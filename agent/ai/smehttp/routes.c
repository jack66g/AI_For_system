/* SPDX-License-Identifier: GPL-2.0 */
/*
 * routes.c - T4b SME HTTP 路由 handler + Pydantic v2 校验形状
 *
 * 逐条对齐 REF-PY e72bc75 `sme/api/server.py`（T4B-DESIGN.md §3）：
 *
 *   GET  /health               {"status":"ok","memories":len(eng.memories)}
 *   GET  /stats                engine_stats
 *   POST /memories             AddMemoryRequest → memory.to_dict(embedding)
 *   POST /memories/batch       BatchRequest → {"added","dropped","total"}
 *   POST /memories/search      SearchRequest → {"query","count","results"}
 *   GET  /memories/{id}        memory.to_dict(embedding) 或 404
 *   POST /memories/{id}/hit    reinforce 结果或 404
 *   GET  /export               {memories, graph, stats}
 *   GET  /regions              {"count","regions"}
 *   POST /import               ImportRequest → {"imported":n}
 *
 * 校验错误体沿用 FastAPI/Pydantic v2 形状：
 *   {"detail":[{"type","loc","msg","input"[,"ctx"]}, ...]}
 * loc 从 ["body", ...] 起，batch 项追加 "memories",<i>，字段按模型声明顺序
 * 收集（AddMemoryRequest: text, metadata, tags, importance, source, link_to,
 * link_kind, ns, conversation_id；SearchRequest: text, top_k, top_regions,
 * metadata_filters, tags, region_retrieval, include_archived, graph_expand,
 * ns, conversation_id, include_history；BatchRequest: memories）。
 *
 * 本轮实现的 type：missing / string_type / dict_type / list_type / int_type /
 * float_type / bool_type / value_error / json_invalid。Pydantic 的 lax 强制
 * 转换（数值字符串、bool→int、非整 float 的 int_from_float 等）不在本轮
 * 契约内（见 T4B-DESIGN §6）。
 *
 * 引擎失败（非校验）统一 500 {"detail":"Internal Server Error"}；batch 中途
 * 失败返回参考的详细 detail（error/failed_index/committed_ids/...）。
 */
#define _POSIX_C_SOURCE 200809L

#include "smehttp/http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Pydantic v2 的 msg 原文 */
#define V_MSG_MISSING	"Field required"
#define V_MSG_STRING	"Input should be a valid string"
#define V_MSG_DICT	"Input should be a valid dictionary"
#define V_MSG_LIST	"Input should be a valid list"
#define V_MSG_INT	"Input should be a valid integer"
#define V_MSG_FLOAT	"Input should be a valid number"
#define V_MSG_BOOL	"Input should be a valid boolean"
#define V_MSG_BLANK	"Value error, text must not be blank"

/* ------------------------------------------------------------------ */
/* JSON 构造助手（失败只置 bad，不中断流程；所有权：成功即转移）        */
/* ------------------------------------------------------------------ */
static aik_json *jb_obj(int *bad)
{
	aik_json *v = aik_json_new_obj();

	if (!v)
		*bad = 1;
	return v;
}

static aik_json *jb_arr(int *bad)
{
	aik_json *v = aik_json_new_arr();

	if (!v)
		*bad = 1;
	return v;
}

static aik_json *jb_str(const char *s, int *bad)
{
	aik_json *v = aik_json_new_str(s ? s : "");

	if (!v)
		*bad = 1;
	return v;
}

static aik_json *jb_int(long long i, int *bad)
{
	aik_json *v = aik_json_new_int(i);

	if (!v)
		*bad = 1;
	return v;
}

static aik_json *jb_bool(int b, int *bad)
{
	aik_json *v = aik_json_new_bool(b ? 1 : 0);

	if (!v)
		*bad = 1;
	return v;
}

static void jb_put(aik_json *obj, const char *key, aik_json *v, int *bad)
{
	if (!v) {
		*bad = 1;
		return;
	}
	if (!obj || aik_json_obj_put(obj, key, v) != 0) {
		*bad = 1;
		aik_json_free(v);
	}
}

static void jb_push(aik_json *arr, aik_json *v, int *bad)
{
	if (!v) {
		*bad = 1;
		return;
	}
	if (!arr || aik_json_arr_push(arr, v) != 0) {
		*bad = 1;
		aik_json_free(v);
	}
}

/* 深拷贝（请求 DOM 借用，错误体的 input 需要自有副本） */
static aik_json *jclone(const aik_json *v, int *bad)
{
	aik_json *out = NULL;

	if (!v) {
		*bad = 1;
		return NULL;
	}
	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		out = aik_json_new_null();
		break;
	case AIK_JSON_BOOL:
		out = aik_json_new_bool(aik_json_bool(v));
		break;
	case AIK_JSON_INT:
		out = aik_json_new_int(aik_json_int(v));
		break;
	case AIK_JSON_NUM:
		out = aik_json_new_num(aik_json_num(v));
		break;
	case AIK_JSON_STR:
		out = aik_json_new_str(aik_json_str(v));
		break;
	case AIK_JSON_ARR: {
		size_t i;
		size_t n;

		out = aik_json_new_arr();
		if (!out) {
			*bad = 1;
			return NULL;
		}
		n = aik_json_count(v);
		for (i = 0; i < n; i++) {
			aik_json *c = jclone(aik_json_at(v, i), bad);

			if (!c) {
				aik_json_free(out);
				return NULL;
			}
			if (aik_json_arr_push(out, c) != 0) {
				aik_json_free(c);
				aik_json_free(out);
				*bad = 1;
				return NULL;
			}
		}
		return out;
	}
	case AIK_JSON_OBJ: {
		size_t i;
		size_t n;

		out = aik_json_new_obj();
		if (!out) {
			*bad = 1;
			return NULL;
		}
		n = aik_json_count(v);
		for (i = 0; i < n; i++) {
			const char *k = aik_json_key_at(v, i);
			aik_json *c = jclone(aik_json_val_at(v, i), bad);

			if (!c || !k) {
				aik_json_free(c);
				aik_json_free(out);
				*bad = 1;
				return NULL;
			}
			if (aik_json_obj_put(out, k, c) != 0) {
				aik_json_free(c);
				aik_json_free(out);
				*bad = 1;
				return NULL;
			}
		}
		return out;
	}
	}
	if (!out)
		*bad = 1;
	return out;
}

/* ------------------------------------------------------------------ */
/* 校验上下文与 422 构造                                              */
/* ------------------------------------------------------------------ */
typedef struct {
	aik_json *errors;	/* ARR（每个元素是一条 Pydantic error） */
	int oom;
} vctx;

typedef struct {
	int in_item;		/* 1 = batch 项：loc 追加 memories,<item> */
	size_t item;
	const char *field;	/* NULL 表示不追加字段 */
	long long elem;		/* >=0 表示追加数组下标 */
} vloc;

static int v_add(vctx *v, const char *type, const char *msg,
		 const aik_json *input, const vloc *loc, int with_ctx)
{
	int bad = 0;
	aik_json *item = jb_obj(&bad);
	aik_json *l = jb_arr(&bad);

	jb_push(l, jb_str("body", &bad), &bad);
	if (loc->in_item) {
		jb_push(l, jb_str("memories", &bad), &bad);
		jb_push(l, jb_int((long long)loc->item, &bad), &bad);
	}
	if (loc->field)
		jb_push(l, jb_str(loc->field, &bad), &bad);
	if (loc->elem >= 0)
		jb_push(l, jb_int(loc->elem, &bad), &bad);
	jb_put(item, "type", jb_str(type, &bad), &bad);
	jb_put(item, "loc", l, &bad);
	jb_put(item, "msg", jb_str(msg, &bad), &bad);
	jb_put(item, "input", jclone(input, &bad), &bad);
	if (with_ctx) {
		aik_json *ctx = jb_obj(&bad);

		jb_put(ctx, "error", jb_obj(&bad), &bad);
		jb_put(item, "ctx", ctx, &bad);
	}
	if (bad || !v->errors) {
		aik_json_free(item);
		v->oom = 1;
		return -1;
	}
	if (aik_json_arr_push(v->errors, item) != 0) {
		aik_json_free(item);
		v->oom = 1;
		return -1;
	}
	return 0;
}

static void respond_validation(aik_http_response *resp, vctx *v)
{
	aik_json *top;

	if (v->oom || !v->errors) {
		aik_json_free(v->errors);
		v->errors = NULL;
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	top = aik_json_new_obj();
	if (!top || aik_json_obj_put(top, "detail", v->errors) != 0) {
		aik_json_free(v->errors);
		aik_json_free(top);
		v->errors = NULL;
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	v->errors = NULL;
	aik_http_response_json(resp, 422, top);
}

/* JSON 解析失败：DESIGN §3 的 json_invalid 形状（尽力而为） */
static void respond_json_invalid(aik_http_response *resp, const char *msg)
{
	int bad = 0;
	aik_json *top = jb_obj(&bad);
	aik_json *arr = jb_arr(&bad);
	aik_json *item = jb_obj(&bad);
	aik_json *loc = jb_arr(&bad);
	aik_json *ctx = jb_obj(&bad);

	jb_push(loc, jb_str("body", &bad), &bad);
	jb_push(loc, jb_int(0, &bad), &bad);
	jb_put(item, "type", jb_str("json_invalid", &bad), &bad);
	jb_put(item, "loc", loc, &bad);
	jb_put(item, "msg", jb_str("JSON decode error", &bad), &bad);
	jb_put(item, "input", jb_obj(&bad), &bad);
	jb_put(ctx, "error", jb_str(msg, &bad), &bad);
	jb_put(item, "ctx", ctx, &bad);
	jb_push(arr, item, &bad);
	jb_put(top, "detail", arr, &bad);
	if (bad) {
		aik_json_free(top);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_http_response_json(resp, 422, top);
}

/* 解析请求体；失败时已写响应并返回 NULL */
static aik_json *parse_body(const aik_http_request *req, vctx *v,
			    aik_http_response *resp)
{
	char err[256];
	aik_json *body;

	v->errors = aik_json_new_arr();
	if (!v->errors) {
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return NULL;
	}
	body = aik_json_parse(req->body, req->body_len, err, sizeof(err));
	if (!body) {
		respond_json_invalid(resp, err);
		aik_json_free(v->errors);
		v->errors = NULL;
		return NULL;
	}
	return body;
}

/* ------------------------------------------------------------------ */
/* 基础判定                                                           */
/* ------------------------------------------------------------------ */
static unsigned int utf8_decode(const unsigned char *p, int *len)
{
	unsigned int c = p[0];
	unsigned int cp;
	int n;
	int i;

	*len = 1;
	if (c < 0x80)
		return c;
	if ((c & 0xe0) == 0xc0) {
		cp = c & 0x1fu;
		n = 2;
	} else if ((c & 0xf0) == 0xe0) {
		cp = c & 0x0fu;
		n = 3;
	} else if ((c & 0xf8) == 0xf0) {
		cp = c & 0x07u;
		n = 4;
	} else {
		*len = -1;
		return 0;
	}
	for (i = 1; i < n; i++) {
		if ((p[i] & 0xc0) != 0x80) {
			*len = -1;
			return 0;
		}
		cp = (cp << 6) | (p[i] & 0x3fu);
	}
	if ((n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) ||
	    (n == 4 && cp < 0x10000) || (cp >= 0xd800 && cp <= 0xdfff) ||
	    cp > 0x10ffff) {
		*len = -1;
		return 0;
	}
	*len = n;
	return cp;
}

static int cp_is_space(unsigned int cp)
{
	if (cp >= 0x09 && cp <= 0x0d)
		return 1;
	if (cp >= 0x1c && cp <= 0x20)
		return 1;
	switch (cp) {
	case 0x85:
	case 0xa0:
	case 0x1680:
	case 0x2028:
	case 0x2029:
	case 0x202f:
	case 0x205f:
	case 0x3000:
		return 1;
	default:
		return cp >= 0x2000 && cp <= 0x200a;
	}
}

/*
 * text_is_blank - NULL/空/Unicode 全空白 → 1（Python str.strip() 的空白集）
 *
 * 与 engine memory.c 的 aik_text__is_blank 同一语义：非法 UTF-8 视为非空白
 * （fail open，只拒绝确定可判定的空白串）。
 */
static int text_is_blank(const char *utf8)
{
	const unsigned char *p = (const unsigned char *)(utf8 ? utf8 : "");

	if (!*p)
		return 1;
	while (*p) {
		int len = 0;
		unsigned int cp = utf8_decode(p, &len);

		if (len < 0 || !cp_is_space(cp))
			return 0;
		p += len;
	}
	return 1;
}

/* INT 或整数值的 NUM（Pydantic lax 接受 10.0）；失败 -1 */
static int json_as_int(const aik_json *j, long long *out)
{
	aik_json_type t = aik_json_typeof(j);

	if (t == AIK_JSON_INT) {
		*out = aik_json_int(j);
		return 0;
	}
	if (t == AIK_JSON_NUM) {
		double d = aik_json_num(j);
		long long v;

		if (!(d >= -9.0e18 && d <= 9.0e18))
			return -1;
		v = (long long)d;
		if ((double)v != d)
			return -1;
		*out = v;
		return 0;
	}
	return -1;
}

static int clamp_int(long long v)
{
	if (v > 2147483647LL)
		return 2147483647;
	if (v < (-2147483647LL - 1))
		return -2147483647 - 1;
	return (int)v;
}

/* ------------------------------------------------------------------ */
/* 字段级校验                                                         */
/* ------------------------------------------------------------------ */
/* Optional[str]：缺失或 null → NULL；非字符串 → string_type */
static void v_opt_str(vctx *v, const aik_json *obj, const char *field,
		      const vloc *base, const char **out)
{
	const aik_json *j = aik_json_get(obj, field);
	vloc loc = *base;

	loc.field = field;
	loc.elem = -1;
	*out = NULL;
	if (!j || aik_json_typeof(j) == AIK_JSON_NULL)
		return;
	if (aik_json_typeof(j) != AIK_JSON_STR) {
		v_add(v, "string_type", V_MSG_STRING, j, &loc, 0);
		return;
	}
	*out = aik_json_str(j);
}

/* 必填 str（Nullable 由调用方另行处理） */
static void v_str(vctx *v, const aik_json *obj, const char *field,
		  const vloc *base, const char *dflt, const char **out)
{
	const aik_json *j = aik_json_get(obj, field);
	vloc loc = *base;

	*out = dflt;
	loc.field = field;
	loc.elem = -1;
	if (!j) {
		if (dflt)
			return;
		v_add(v, "missing", V_MSG_MISSING, obj, &loc, 0);
		return;
	}
	if (aik_json_typeof(j) != AIK_JSON_STR) {
		v_add(v, "string_type", V_MSG_STRING, j, &loc, 0);
		return;
	}
	*out = aik_json_str(j);
}

static void v_int(vctx *v, const aik_json *obj, const char *field,
		  const vloc *base, int dflt, int *out)
{
	const aik_json *j = aik_json_get(obj, field);
	vloc loc = *base;
	long long val;

	*out = dflt;
	loc.field = field;
	loc.elem = -1;
	if (!j)
		return;
	if (json_as_int(j, &val) != 0) {
		v_add(v, "int_type", V_MSG_INT, j, &loc, 0);
		return;
	}
	*out = clamp_int(val);
}

static void v_bool(vctx *v, const aik_json *obj, const char *field,
		   const vloc *base, int dflt, int *out)
{
	const aik_json *j = aik_json_get(obj, field);
	vloc loc = *base;

	*out = dflt;
	loc.field = field;
	loc.elem = -1;
	if (!j)
		return;
	if (aik_json_typeof(j) != AIK_JSON_BOOL) {
		v_add(v, "bool_type", V_MSG_BOOL, j, &loc, 0);
		return;
	}
	*out = aik_json_bool(j);
}

/* list[str]；allow_null 对应 Optional[list[str]] */
static void v_str_list(vctx *v, const aik_json *obj, const char *field,
		       const vloc *base, int allow_null, const char *const **out,
		       size_t *n_out)
{
	const aik_json *j = aik_json_get(obj, field);
	vloc loc = *base;

	*out = NULL;
	*n_out = 0;
	loc.field = field;
	loc.elem = -1;
	if (!j)
		return;
	if (aik_json_typeof(j) == AIK_JSON_NULL && allow_null)
		return;
	if (aik_json_typeof(j) != AIK_JSON_ARR) {
		v_add(v, "list_type", V_MSG_LIST, j, &loc, 0);
		return;
	}
	{
		size_t i;
		size_t n = aik_json_count(j);

		for (i = 0; i < n; i++) {
			const aik_json *el = aik_json_at(j, i);

			if (aik_json_typeof(el) != AIK_JSON_STR) {
				vloc eloc = loc;

				eloc.elem = (long long)i;
				v_add(v, "string_type", V_MSG_STRING, el,
				      &eloc, 0);
			}
		}
	}
}

/* ------------------------------------------------------------------ */
/* AddMemoryRequest                                                   */
/* ------------------------------------------------------------------ */
typedef struct {
	const char *text;
	const aik_json *metadata;
	const char *const *tags;
	size_t n_tags;
	double importance;
	const char *source;
	const char *link_to;
	const char *link_kind;
	const char *ns;
	const char *conversation_id;
} add_args;

static void free_add_args(add_args *args, size_t n)
{
	size_t i;

	if (!args)
		return;
	for (i = 0; i < n; i++)
		free((void *)args[i].tags);
	free(args);
}

/*
 * 校验 AddMemoryRequest（模型字段声明顺序）；成功时填 out（tags 数组
 * malloc，调用方 free_add_args）。返回 0 合法，-1 有错误/OOM。
 */
static int validate_add(vctx *v, const aik_json *obj, const vloc *base,
			add_args *out)
{
	size_t before = v->errors ? aik_json_count(v->errors) : 0;
	const aik_json *j;
	vloc loc;
	size_t n;
	size_t i;

	memset(out, 0, sizeof(*out));

	/* text: 必填 str + 非空白 */
	loc = *base;
	loc.field = "text";
	loc.elem = -1;
	j = aik_json_get(obj, "text");
	if (!j) {
		v_add(v, "missing", V_MSG_MISSING, obj, &loc, 0);
	} else if (aik_json_typeof(j) != AIK_JSON_STR) {
		v_add(v, "string_type", V_MSG_STRING, j, &loc, 0);
	} else if (text_is_blank(aik_json_str(j))) {
		v_add(v, "value_error", V_MSG_BLANK, j, &loc, 1);
	} else {
		out->text = aik_json_str(j);
	}

	/* metadata: dict[str, Any]（默认 {}；null 也是 dict_type） */
	loc = *base;
	loc.field = "metadata";
	loc.elem = -1;
	j = aik_json_get(obj, "metadata");
	if (j) {
		if (aik_json_typeof(j) != AIK_JSON_OBJ)
			v_add(v, "dict_type", V_MSG_DICT, j, &loc, 0);
		else
			out->metadata = j;
	}

	/* tags: list[str]（默认 []） */
	{
		const char *const *tags = NULL;
		size_t n_tags = 0;

		v_str_list(v, obj, "tags", base, 0, &tags, &n_tags);
		(void)tags;
		(void)n_tags;
	}

	/* importance: float（默认 0.5；INT/NUM 均接受） */
	loc = *base;
	loc.field = "importance";
	loc.elem = -1;
	out->importance = 0.5;
	j = aik_json_get(obj, "importance");
	if (j) {
		if (aik_json_typeof(j) == AIK_JSON_INT)
			out->importance = (double)aik_json_int(j);
		else if (aik_json_typeof(j) == AIK_JSON_NUM)
			out->importance = aik_json_num(j);
		else
			v_add(v, "float_type", V_MSG_FLOAT, j, &loc, 0);
	}

	/* source: str（默认 "user"） */
	v_str(v, obj, "source", base, "user", &out->source);
	/* link_to: Optional[str] */
	v_opt_str(v, obj, "link_to", base, &out->link_to);
	/* link_kind: str（默认 "reference"） */
	v_str(v, obj, "link_kind", base, "reference", &out->link_kind);
	/* ns / conversation_id: Optional[str] */
	v_opt_str(v, obj, "ns", base, &out->ns);
	v_opt_str(v, obj, "conversation_id", base, &out->conversation_id);

	if (v->oom)
		return -1;
	if (v->errors && aik_json_count(v->errors) != before)
		return -1;
	/* 类型全部合法后才分配 tags 指针数组（借用 DOM 字符串） */
	j = aik_json_get(obj, "tags");
	n = j ? aik_json_count(j) : 0;
	if (n > 0) {
		const char **tags = calloc(n, sizeof(*tags));

		if (!tags) {
			v->oom = 1;
			return -1;
		}
		for (i = 0; i < n; i++)
			tags[i] = aik_json_str(aik_json_at(j, i));
		out->tags = tags;
		out->n_tags = n;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* SearchRequest                                                      */
/* ------------------------------------------------------------------ */
typedef struct {
	const char *text;
	int top_k;
	int top_regions;	/* -1 = 未指定（回退 region_retrieval/配置） */
	const aik_json *metadata_filters;
	const char *const *tags;
	size_t n_tags;
	int graph_expand;
	int include_archived;
	const char *ns;
} search_args;

/*
 * region_retrieval 解析（Python: int(str.replace("top", ""))，失败 = 未指定）。
 * 成功 0；非整数 -1。
 */
static int parse_top_n(const char *s, long long *out)
{
	char buf[64];
	size_t n = 0;
	const char *p = s;
	char *end = NULL;
	long long v;

	while (*p) {
		if (p[0] == 't' && p[1] == 'o' && p[2] == 'p') {
			p += 3;
			continue;
		}
		if (n + 1 >= sizeof(buf))
			return -1;
		buf[n++] = *p++;
	}
	buf[n] = '\0';
	p = buf;
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' ||
	       *p == '\f' || *p == '\v')
		p++;
	v = strtoll(p, &end, 10);
	if (end == p)
		return -1;
	while (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r' ||
	       *end == '\f' || *end == '\v')
		end++;
	if (*end != '\0')
		return -1;
	*out = v;
	return 0;
}

static int validate_search(vctx *v, const aik_json *obj, const vloc *base,
			   search_args *out)
{
	size_t before = v->errors ? aik_json_count(v->errors) : 0;
	const aik_json *j;
	vloc loc;
	const char *region_retrieval = NULL;
	long long n64;

	memset(out, 0, sizeof(*out));
	out->top_k = 10;
	out->top_regions = -1;

	/* text（SearchRequest 无非空白校验） */
	loc = *base;
	loc.field = "text";
	loc.elem = -1;
	j = aik_json_get(obj, "text");
	if (!j)
		v_add(v, "missing", V_MSG_MISSING, obj, &loc, 0);
	else if (aik_json_typeof(j) != AIK_JSON_STR)
		v_add(v, "string_type", V_MSG_STRING, j, &loc, 0);
	else
		out->text = aik_json_str(j);

	/* top_k: int（默认 10） */
	v_int(v, obj, "top_k", base, 10, &out->top_k);

	/* top_regions: Optional[int] */
	loc = *base;
	loc.field = "top_regions";
	loc.elem = -1;
	j = aik_json_get(obj, "top_regions");
	if (j && aik_json_typeof(j) != AIK_JSON_NULL) {
		if (json_as_int(j, &n64) != 0)
			v_add(v, "int_type", V_MSG_INT, j, &loc, 0);
		else
			out->top_regions = clamp_int(n64);
	}

	/* metadata_filters: dict[str, Any]（默认 {}；null = dict_type） */
	loc = *base;
	loc.field = "metadata_filters";
	loc.elem = -1;
	j = aik_json_get(obj, "metadata_filters");
	if (j) {
		if (aik_json_typeof(j) != AIK_JSON_OBJ)
			v_add(v, "dict_type", V_MSG_DICT, j, &loc, 0);
		else
			out->metadata_filters = j;
	}

	/* tags: Optional[list[str]] */
	v_str_list(v, obj, "tags", base, 1, &out->tags, &out->n_tags);

	/* region_retrieval: Optional[str] */
	v_opt_str(v, obj, "region_retrieval", base, &region_retrieval);

	/* include_archived: bool（默认 False） */
	v_bool(v, obj, "include_archived", base, 0, &out->include_archived);

	/* graph_expand: int（默认 0） */
	v_int(v, obj, "graph_expand", base, 0, &out->graph_expand);

	/* ns / conversation_id: Optional[str] */
	v_opt_str(v, obj, "ns", base, &out->ns);
	{
		const char *conversation_id = NULL;

		v_opt_str(v, obj, "conversation_id", base, &conversation_id);
	}

	/* include_history: bool（默认 False） */
	{
		int include_history = 0;

		v_bool(v, obj, "include_history", base, 0, &include_history);
	}

	/* 显式 top_regions 优先；否则 region_retrieval 折算（Python k_regions） */
	if (out->top_regions < 0 && region_retrieval &&
	    parse_top_n(region_retrieval, &n64) == 0)
		out->top_regions = clamp_int(n64);

	if (v->oom)
		return -1;
	if (v->errors && aik_json_count(v->errors) != before)
		return -1;
	/* tags 指针数组（借用 DOM） */
	j = aik_json_get(obj, "tags");
	if (j && aik_json_typeof(j) == AIK_JSON_ARR) {
		size_t n = aik_json_count(j);
		size_t i;
		const char **tags;

		if (n == 0)
			return 0;
		tags = calloc(n, sizeof(*tags));
		if (!tags) {
			v->oom = 1;
			return -1;
		}
		for (i = 0; i < n; i++)
			tags[i] = aik_json_str(aik_json_at(j, i));
		out->tags = tags;
		out->n_tags = n;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* 路由：health / stats / export / regions                            */
/* ------------------------------------------------------------------ */
void aik_http_route_health(aik_http_server *s, const aik_http_request *req,
			   aik_http_response *resp)
{
	int bad = 0;
	aik_json *o = jb_obj(&bad);
	long long count = (long long)aik_engine_memory_count(
		aik_http_server_engine(s));

	(void)req;
	jb_put(o, "status", jb_str("ok", &bad), &bad);
	jb_put(o, "memories", jb_int(count, &bad), &bad);
	if (bad) {
		aik_json_free(o);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_http_response_json(resp, 200, o);
}

typedef int (*engine_obj_fn)(aik_engine *, aik_json **, char *, size_t);

static void respond_engine_obj(aik_http_server *s, aik_http_request const *req,
			       aik_http_response *resp, engine_obj_fn fn)
{
	char err[256];
	aik_json *dom = NULL;

	(void)req;
	if (fn(aik_http_server_engine(s), &dom, err, sizeof(err)) != 0 || !dom) {
		aik_json_free(dom);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_http_response_json(resp, 200, dom);
}

void aik_http_route_stats(aik_http_server *s, const aik_http_request *req,
			  aik_http_response *resp)
{
	respond_engine_obj(s, req, resp, aik_engine_stats);
}

void aik_http_route_export(aik_http_server *s, const aik_http_request *req,
			   aik_http_response *resp)
{
	respond_engine_obj(s, req, resp, aik_engine_export);
}

void aik_http_route_regions(aik_http_server *s, const aik_http_request *req,
			    aik_http_response *resp)
{
	respond_engine_obj(s, req, resp, aik_engine_regions);
}

/* ------------------------------------------------------------------ */
/* 路由：POST /memories                                               */
/* ------------------------------------------------------------------ */
void aik_http_route_add_memory(aik_http_server *s,
			       const aik_http_request *req,
			       aik_http_response *resp)
{
	vctx v;
	vloc base;
	add_args a;
	aik_json *body;
	aik_memory *m;
	aik_json *dom;
	char err[256];

	memset(&v, 0, sizeof(v));
	memset(&base, 0, sizeof(base));
	base.elem = -1;
	body = parse_body(req, &v, resp);
	if (!body)
		return;
	if (aik_json_typeof(body) != AIK_JSON_OBJ) {
		v_add(&v, "dict_type", V_MSG_DICT, body, &base, 0);
		respond_validation(resp, &v);
		aik_json_free(body);
		return;
	}
	if (validate_add(&v, body, &base, &a) != 0) {
		respond_validation(resp, &v);
		aik_json_free(body);
		return;
	}
	aik_json_free(v.errors);
	v.errors = NULL;
	m = aik_engine_add(aik_http_server_engine(s), a.text, a.metadata, a.tags,
			   a.n_tags, a.importance, a.source, a.link_to,
			   a.link_kind, a.ns, a.conversation_id, err, sizeof(err));
	free((void *)a.tags);
	aik_json_free(body);
	if (!m) {
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	dom = aik_memory_to_json(m, 1);
	if (!dom) {
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_http_response_json(resp, 200, dom);
}

/* ------------------------------------------------------------------ */
/* 路由：POST /memories/batch                                         */
/* ------------------------------------------------------------------ */
void aik_http_route_add_batch(aik_http_server *s, const aik_http_request *req,
			      aik_http_response *resp)
{
	vctx v;
	vloc base;
	aik_json *body;
	const aik_json *mems;
	add_args *args = NULL;
	const char **ids = NULL;
	size_t n = 0;
	size_t i;
	long long added = 0;
	char err[256];

	memset(&v, 0, sizeof(v));
	memset(&base, 0, sizeof(base));
	base.elem = -1;
	body = parse_body(req, &v, resp);
	if (!body)
		return;
	if (aik_json_typeof(body) != AIK_JSON_OBJ) {
		v_add(&v, "dict_type", V_MSG_DICT, body, &base, 0);
		respond_validation(resp, &v);
		aik_json_free(body);
		return;
	}
	mems = aik_json_get(body, "memories");
	base.field = "memories";
	if (!mems) {
		v_add(&v, "missing", V_MSG_MISSING, body, &base, 0);
	} else if (aik_json_typeof(mems) != AIK_JSON_ARR) {
		v_add(&v, "list_type", V_MSG_LIST, mems, &base, 0);
	} else {
		n = aik_json_count(mems);
		args = calloc(n ? n : 1, sizeof(*args));
		if (!args) {
			v.oom = 1;
		} else {
			for (i = 0; i < n; i++) {
				const aik_json *item = aik_json_at(mems, i);
				vloc ib = base;

				ib.in_item = 1;
				ib.item = i;
				ib.field = NULL;
				if (aik_json_typeof(item) != AIK_JSON_OBJ) {
					v_add(&v, "dict_type", V_MSG_DICT,
					      item, &ib, 0);
					continue;
				}
				(void)validate_add(&v, item, &ib, &args[i]);
			}
		}
	}
	if (v.oom) {
		free_add_args(args, n);
		aik_json_free(v.errors);
		v.errors = NULL;
		aik_json_free(body);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	if (v.errors && aik_json_count(v.errors) > 0) {
		free_add_args(args, n);
		respond_validation(resp, &v);
		aik_json_free(body);
		return;
	}
	aik_json_free(v.errors);
	v.errors = NULL;
	ids = calloc(n ? n : 1, sizeof(*ids));
	if (!ids) {
		free_add_args(args, n);
		aik_json_free(v.errors);
		v.errors = NULL;
		aik_json_free(body);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	for (i = 0; i < n; i++) {
		aik_memory *m = aik_engine_add(
			aik_http_server_engine(s), args[i].text,
			args[i].metadata, args[i].tags, args[i].n_tags,
			args[i].importance, args[i].source, args[i].link_to,
			args[i].link_kind, args[i].ns, args[i].conversation_id,
			err, sizeof(err));

		if (!m)
			break;
		ids[added] = m->id;
		added++;
	}
	free_add_args(args, n);
	aik_json_free(body);
	if (i < n) {
		int bad = 0;
		aik_json *o = jb_obj(&bad);
		aik_json *committed = jb_arr(&bad);
		size_t k;

		for (k = 0; k < (size_t)added; k++)
			jb_push(committed, jb_str(ids[k], &bad), &bad);
		jb_put(o, "error", jb_str("batch execution failed", &bad),
		       &bad);
		jb_put(o, "failed_index", jb_int((long long)i, &bad), &bad);
		jb_put(o, "committed_ids", committed, &bad);
		jb_put(o, "committed_count", jb_int(added, &bad), &bad);
		jb_put(o, "recovery_required", jb_bool(0, &bad), &bad);
		jb_put(o, "failed_item_status",
		       jb_str("not_committed", &bad), &bad);
		free(ids);
		if (bad) {
			aik_json_free(o);
			aik_http_response_detail(resp, 500,
						 "Internal Server Error");
			return;
		}
		aik_http_response_json(resp, 500, o);
		return;
	}
	free(ids);
	{
		int bad = 0;
		aik_json *o = jb_obj(&bad);

		jb_put(o, "added", jb_int(added, &bad), &bad);
		jb_put(o, "dropped", jb_int((long long)n - added, &bad), &bad);
		jb_put(o, "total", jb_int((long long)n, &bad), &bad);
		if (bad) {
			aik_json_free(o);
			aik_http_response_detail(resp, 500,
						 "Internal Server Error");
			return;
		}
		aik_http_response_json(resp, 200, o);
	}
}

/* ------------------------------------------------------------------ */
/* 路由：POST /memories/search                                        */
/* ------------------------------------------------------------------ */
void aik_http_route_search(aik_http_server *s, const aik_http_request *req,
			   aik_http_response *resp)
{
	vctx v;
	vloc base;
	search_args a;
	aik_json *body;
	aik_json *mf = NULL;
	int mf_bad = 0;
	aik_search_query q;
	aik_search_hit *hits = NULL;
	size_t n_hits = 0;
	char err[256];
	int rc;
	int bad = 0;
	aik_json *out;
	aik_json *results;
	size_t i;

	memset(&v, 0, sizeof(v));
	memset(&base, 0, sizeof(base));
	base.elem = -1;
	body = parse_body(req, &v, resp);
	if (!body)
		return;
	if (aik_json_typeof(body) != AIK_JSON_OBJ) {
		v_add(&v, "dict_type", V_MSG_DICT, body, &base, 0);
		respond_validation(resp, &v);
		aik_json_free(body);
		return;
	}
	if (validate_search(&v, body, &base, &a) != 0) {
		respond_validation(resp, &v);
		aik_json_free(body);
		return;
	}
	aik_json_free(v.errors);
	v.errors = NULL;
	/* ns 合并进 metadata_filters（engine.search(ns=...) 的等价物） */
	if (a.ns) {
		mf = a.metadata_filters ? jclone(a.metadata_filters, &mf_bad)
					: aik_json_new_obj();
		if (mf) {
			aik_json *nv = aik_json_new_str(a.ns);

			if (!nv || aik_json_obj_set(mf, "ns", nv) != 0) {
				aik_json_free(nv);
				aik_json_free(mf);
				mf = NULL;
				mf_bad = 1;
			}
		} else {
			mf_bad = 1;
		}
	}
	if (mf_bad) {
		free((void *)a.tags);
		aik_json_free(body);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	memset(&q, 0, sizeof(q));
	q.text = a.text;
	q.top_k = a.top_k;
	q.top_regions = a.top_regions;
	q.metadata_filters = mf ? mf : a.metadata_filters;
	q.tags = a.tags;
	q.n_tags = a.n_tags;
	q.region_retrieval = 0;
	q.graph_expand = a.graph_expand;
	q.include_archived = a.include_archived;
	rc = aik_engine_search(aik_http_server_engine(s), &q, &hits, &n_hits,
			       err, sizeof(err));
	free((void *)a.tags);
	aik_json_free(mf);
	if (rc != 0) {
		aik_search_hits_free(hits, n_hits);
		aik_json_free(body);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	out = jb_obj(&bad);
	results = jb_arr(&bad);
	jb_put(out, "query", jb_str(a.text ? a.text : "", &bad), &bad);
	jb_put(out, "count", jb_int((long long)n_hits, &bad), &bad);
	for (i = 0; i < n_hits; i++) {
		aik_json *hit = aik_search_hit_to_json(
			aik_http_server_engine(s), &hits[i]);

		if (!hit) {
			bad = 1;
			break;
		}
		jb_push(results, hit, &bad);
	}
	aik_search_hits_free(hits, n_hits);
	aik_json_free(body);
	jb_put(out, "results", results, &bad);
	if (bad) {
		aik_json_free(out);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_http_response_json(resp, 200, out);
}

/* ------------------------------------------------------------------ */
/* 路由：GET /memories/{id} 与 POST /memories/{id}/hit                */
/* ------------------------------------------------------------------ */
void aik_http_route_memory_get(aik_http_server *s, const aik_http_request *req,
			       const char *memory_id,
			       aik_http_response *resp)
{
	aik_memory *m;
	aik_json *dom;

	(void)req;
	m = aik_engine_get(aik_http_server_engine(s), memory_id);
	if (!m) {
		aik_http_response_detail(resp, 404, "memory not found");
		return;
	}
	dom = aik_memory_to_json(m, 1);
	if (!dom) {
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_http_response_json(resp, 200, dom);
}

void aik_http_route_memory_hit(aik_http_server *s, const aik_http_request *req,
			       const char *memory_id,
			       aik_http_response *resp)
{
	aik_json *result = NULL;
	char err[256];
	int rc;

	(void)req;
	rc = aik_engine_reinforce(aik_http_server_engine(s), memory_id, &result,
				  err, sizeof(err));
	if (rc == 1) {
		aik_http_response_detail(resp, 404, "memory not found");
		return;
	}
	if (rc != 0 || !result) {
		aik_json_free(result);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_http_response_json(resp, 200, result);
}

/* ------------------------------------------------------------------ */
/* 路由：POST /import                                                 */
/* ------------------------------------------------------------------ */
void aik_http_route_import(aik_http_server *s, const aik_http_request *req,
			   aik_http_response *resp)
{
	vctx v;
	vloc base;
	aik_json *body;
	const aik_json *mems;
	long long count = 0;
	char err[256];

	memset(&v, 0, sizeof(v));
	memset(&base, 0, sizeof(base));
	base.elem = -1;
	body = parse_body(req, &v, resp);
	if (!body)
		return;
	if (aik_json_typeof(body) != AIK_JSON_OBJ) {
		v_add(&v, "dict_type", V_MSG_DICT, body, &base, 0);
		respond_validation(resp, &v);
		aik_json_free(body);
		return;
	}
	mems = aik_json_get(body, "memories");
	base.field = "memories";
	if (!mems) {
		v_add(&v, "missing", V_MSG_MISSING, body, &base, 0);
	} else if (aik_json_typeof(mems) != AIK_JSON_ARR) {
		v_add(&v, "list_type", V_MSG_LIST, mems, &base, 0);
	} else {
		size_t i;
		size_t n = aik_json_count(mems);

		for (i = 0; i < n; i++) {
			const aik_json *item = aik_json_at(mems, i);
			vloc ib = base;

			if (aik_json_typeof(item) == AIK_JSON_OBJ)
				continue;
			ib.in_item = 1;
			ib.item = i;
			ib.field = NULL;
			v_add(&v, "dict_type", V_MSG_DICT, item, &ib, 0);
		}
	}
	if (v.oom) {
		aik_json_free(v.errors);
		v.errors = NULL;
		aik_json_free(body);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	if (v.errors && aik_json_count(v.errors) > 0) {
		respond_validation(resp, &v);
		aik_json_free(body);
		return;
	}
	if (aik_engine_import(aik_http_server_engine(s), mems, &count, err,
			      sizeof(err)) != 0) {
		aik_json_free(v.errors);
		v.errors = NULL;
		aik_json_free(body);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_json_free(v.errors);
	v.errors = NULL;
	aik_json_free(body);
	{
		int bad = 0;
		aik_json *o = jb_obj(&bad);

		jb_put(o, "imported", jb_int(count, &bad), &bad);
		if (bad) {
			aik_json_free(o);
			aik_http_response_detail(resp, 500,
						 "Internal Server Error");
			return;
		}
		aik_http_response_json(resp, 200, o);
	}
}
