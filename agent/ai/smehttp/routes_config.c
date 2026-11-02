/* SPDX-License-Identifier: GPL-2.0 */
/*
 * routes_config.c - T4e 配置中心 + consolidation/compression 路由
 *
 * 对齐 REF-PY e72bc75 `sme/api/server.py` 的配置中心段：
 *
 *   GET  /config          {config_file, source, groups, presets}
 *   PUT  /config          ConfigPutRequest{values={}, save=false}
 *   POST /config/preset   PresetRequest{key, save=true}
 *   POST /config/check    ConfigCheckRequest{ping=false}
 *   POST /config/reset    无请求体：删配置文件 + 默认配置 + env 重放
 *   POST /consolidate     {"created":[...]}（engine.consolidate）
 *   POST /compress        {"created":[...]}（engine.compress）
 *
 * 关键语义（T4E-DESIGN §1/§2 与 E2-C 任务书）：
 *   - PUT 的 values 值可为字符串（走 aik_config_item_parse）或原生 JSON
 *     （走 aik_config_item_validate）；值对象键序 = 请求键序；
 *   - 以 api_key 结尾的项收到 "******" 或 "" 视为"不修改"（GET /config
 *     只回显掩码，回传掩码不能覆盖真实密钥）；
 *   - 任一错误 → 200 {"ok":false,"errors":{path:msg}}，引擎不动；
 *   - 全部合法且非空 → 当前配置 DOM 深拷贝 → 逐项 set →
 *     aik_config_from_json → aik_engine_rebuild → swap → 释放旧引擎 →
 *     save 时落盘（落盘失败不回滚已生效配置，source 不变）；
 *   - /config/check 的 llm/embedding 探测只做本地判定：C 版本没有内置
 *     LLM HTTP 客户端，ping=true 时明确返回"请求失败：C 版本未内置 LLM
 *     HTTP 客户端"，不伪造连通；
 *   - /config/reset 的默认配置后重放 SME_LLM_* / SME_API_AUTH_TOKEN /
 *     SME_EMBEDDING_*（与 main.c 的 apply_env_overrides 同序同语义）。
 *
 * 422 错误体沿用 routes.c 的 Pydantic v2 形状：
 *   {"detail":[{"type","loc","msg","input"}]}；body 非法 JSON 走
 *   json_invalid（loc ["body",0] + ctx.error）。本文件自带一份精简的
 *   构造助手（routes.c 的助手是 static，不能跨文件复用）。
 */
#define _POSIX_C_SOURCE 200809L

#include "smehttp/http.h"

#include "smeconfig/config_items.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Pydantic v2 的 msg 原文（与 routes.c 一致） */
#define V_MSG_MISSING	"Field required"
#define V_MSG_STRING	"Input should be a valid string"
#define V_MSG_DICT	"Input should be a valid dictionary"
#define V_MSG_BOOL	"Input should be a valid boolean"

/* llm.base_url 的注册表/SMEConfig 默认值（server.py::_LLM_DEFAULT_BASE_URL） */
#define LLM_DEFAULT_BASE_URL	"https://api.openai.com/v1"

/* ------------------------------------------------------------------ */
/* JSON 构造助手（失败只置 bad，成功即转移所有权）                     */
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

/* 深拷贝（错误体的 input 需要自有副本） */
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
/* 校验错误收集（Pydantic v2 形状）                                    */
/* ------------------------------------------------------------------ */
typedef struct {
	aik_json *arr;		/* ARR（每个元素是一条 Pydantic error） */
	int oom;
} err_list;

/*
 * el_add - 追加一条错误；loc = ["body"] + segs[0..nsegs)
 * input 借用（内部深拷贝）；input 为 NULL 时写 {}。
 */
static void el_add(err_list *el, const char *type, const char *msg,
		   const aik_json *input, const char *const *segs,
		   size_t nsegs)
{
	int bad = 0;
	aik_json *item = jb_obj(&bad);
	aik_json *loc = jb_arr(&bad);
	size_t i;

	jb_push(loc, jb_str("body", &bad), &bad);
	for (i = 0; i < nsegs; i++)
		jb_push(loc, jb_str(segs[i], &bad), &bad);
	jb_put(item, "type", jb_str(type, &bad), &bad);
	jb_put(item, "loc", loc, &bad);
	jb_put(item, "msg", jb_str(msg, &bad), &bad);
	jb_put(item, "input",
	       input ? jclone(input, &bad) : jb_obj(&bad), &bad);
	if (bad || !el->arr) {
		aik_json_free(item);
		el->oom = 1;
		return;
	}
	if (aik_json_arr_push(el->arr, item) != 0) {
		aik_json_free(item);
		el->oom = 1;
	}
}

static void el_add_field(err_list *el, const char *type, const char *msg,
			 const aik_json *input, const char *field)
{
	const char *segs[1];

	segs[0] = field;
	el_add(el, type, msg, input, segs, 1);
}

static void respond_422(err_list *el, aik_http_response *resp)
{
	aik_json *top;

	if (el->oom || !el->arr) {
		aik_json_free(el->arr);
		el->arr = NULL;
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	top = aik_json_new_obj();
	if (!top || aik_json_obj_put(top, "detail", el->arr) != 0) {
		aik_json_free(el->arr);
		aik_json_free(top);
		el->arr = NULL;
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	el->arr = NULL;
	aik_http_response_json(resp, 422, top);
}

/* JSON 解析失败：routes.c::respond_json_invalid 的等价形状 */
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
static aik_json *parse_body(const aik_http_request *req, err_list *el,
			    aik_http_response *resp)
{
	char err[256];
	aik_json *body;

	el->arr = aik_json_new_arr();
	if (!el->arr) {
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return NULL;
	}
	body = aik_json_parse(req->body, req->body_len, err, sizeof(err));
	if (!body) {
		respond_json_invalid(resp, err);
		aik_json_free(el->arr);
		el->arr = NULL;
		return NULL;
	}
	return body;
}

/* 顶层必须是对象（Pydantic 模型的 body） */
static int require_obj(aik_json *body, err_list *el, aik_http_response *resp)
{
	if (aik_json_typeof(body) == AIK_JSON_OBJ)
		return 0;
	el_add(el, "dict_type", V_MSG_DICT, body, NULL, 0);
	respond_422(el, resp);
	return -1;
}

/* ------------------------------------------------------------------ */
/* 响应助手                                                           */
/* ------------------------------------------------------------------ */
static void respond_global_error(aik_http_response *resp, const char *msg)
{
	int bad = 0;
	aik_json *out = jb_obj(&bad);
	aik_json *errors = jb_obj(&bad);

	jb_put(errors, "_global", jb_str(msg, &bad), &bad);
	jb_put(out, "ok", jb_bool(0, &bad), &bad);
	jb_put(out, "errors", errors, &bad);
	if (bad) {
		aik_json_free(out);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_http_response_json(resp, 200, out);
}

static void respond_errors(aik_json *errors, aik_http_response *resp)
{
	int bad = 0;
	aik_json *out = jb_obj(&bad);

	jb_put(out, "ok", jb_bool(0, &bad), &bad);
	jb_put(out, "errors", errors, &bad);
	if (bad) {
		aik_json_free(out);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_http_response_json(resp, 200, out);
}

static void respond_applied_count(long long n, const char *config_file,
				  aik_http_response *resp)
{
	int bad = 0;
	aik_json *out = jb_obj(&bad);

	jb_put(out, "ok", jb_bool(1, &bad), &bad);
	jb_put(out, "applied", jb_int(n, &bad), &bad);
	jb_put(out, "config_file", jb_str(config_file, &bad), &bad);
	if (bad) {
		aik_json_free(out);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_http_response_json(resp, 200, out);
}

/* sizeof 前缀的格式化分配（vsnprintf 两次） */
static char *fmt_alloc(const char *fmt, ...)
{
	va_list ap;
	va_list ap2;
	int n;
	char *buf;

	va_start(ap, fmt);
	va_copy(ap2, ap);
	n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (n < 0) {
		va_end(ap2);
		return NULL;
	}
	buf = malloc((size_t)n + 1);
	if (!buf) {
		va_end(ap2);
		return NULL;
	}
	if (vsnprintf(buf, (size_t)n + 1, fmt, ap2) != n) {
		va_end(ap2);
		free(buf);
		return NULL;
	}
	va_end(ap2);
	return buf;
}

/* ------------------------------------------------------------------ */
/* 配置 DOM 助手                                                      */
/* ------------------------------------------------------------------ */
static const char *source_name(int source)
{
	switch (source) {
	case AIK_HTTP_SOURCE_FILE:
		return "file";
	case AIK_HTTP_SOURCE_ENV:
		return "env";
	default:
		return "defaults";
	}
}

/* 深拷贝配置 DOM（dump + parse，与任务书一致） */
static aik_json *copy_config_dom(const aik_config *cfg, char *err,
				 size_t errlen)
{
	const aik_json *dom = aik_config_dom(cfg);
	char *text = NULL;
	size_t len = 0;
	aik_json *out;

	if (!dom)
		return NULL;
	if (aik_json_dump(dom, &text, &len) != 0 || !text) {
		free(text);
		return NULL;
	}
	out = aik_json_parse(text, len, err, errlen);
	free(text);
	return out;
}

/*
 * apply_config_dom - 引擎热重建 + swap + 可选落盘
 *
 * new_dom 借用（调用者释放）。成功 0（引擎已替换、source 已按需更新）；
 * 失败 -1 且响应已写（ok:false errors._global 或 500）。
 */
static int apply_config_dom(aik_http_server *s, aik_json *new_dom, int save,
			    aik_http_response *resp)
{
	char err[512];
	aik_config *cfg;
	aik_engine *old;
	aik_engine *neu = NULL;
	const char *config_file;
	int rc;

	cfg = aik_config_from_json(new_dom, err, sizeof(err));
	if (!cfg) {
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return -1;
	}
	old = aik_http_server_engine(s);
	rc = aik_engine_rebuild(old, cfg, &neu, err, sizeof(err));
	if (rc == 1) {
		/* embedding 身份闸门：err 是可直接展示的中文提示 */
		respond_global_error(resp, err);
		return -1;
	}
	if (rc != 0) {
		char *msg = fmt_alloc("应用配置失败，引擎保持原配置：%s", err);

		respond_global_error(resp, msg ? msg : err);
		free(msg);
		return -1;
	}
	/* 新引擎接管；server 只借用，旧引擎由本路由释放 */
	aik_http_server_set_engine(s, neu);
	aik_engine_free(old);
	if (!save)
		return 0;
	config_file = aik_http_server_config_file(s);
	if (aik_config_save_file(config_file, new_dom, err, sizeof(err)) != 0) {
		char *msg = fmt_alloc("配置已生效，但写入 %s 失败：%s",
				      config_file, err);

		respond_global_error(resp, msg ? msg : err);
		free(msg);
		return -1;
	}
	aik_http_server_set_source(s, AIK_HTTP_SOURCE_FILE);
	return 0;
}

/* ------------------------------------------------------------------ */
/* GET /config                                                        */
/* ------------------------------------------------------------------ */
void aik_http_route_config_get(aik_http_server *s,
			       const aik_http_request *req,
			       aik_http_response *resp)
{
	aik_engine *eng = aik_http_server_engine(s);
	aik_config *cfg;
	aik_json *display;
	aik_json *groups;
	aik_json *presets;
	aik_json *out;
	int bad = 0;

	(void)req;
	cfg = aik_engine_config(eng);
	if (!cfg) {
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	display = aik_config_display(aik_config_dom(cfg));
	if (!display) {
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	groups = aik_config_groups_build(display);
	aik_json_free(display);
	presets = aik_config_presets_build();
	if (!groups || !presets) {
		aik_json_free(groups);
		aik_json_free(presets);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	out = jb_obj(&bad);
	jb_put(out, "config_file",
	       jb_str(aik_http_server_config_file(s), &bad), &bad);
	jb_put(out, "source",
	       jb_str(source_name(aik_http_server_source(s)), &bad), &bad);
	jb_put(out, "groups", groups, &bad);
	jb_put(out, "presets", presets, &bad);
	if (bad) {
		aik_json_free(out);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_http_response_json(resp, 200, out);
}

/* ------------------------------------------------------------------ */
/* PUT /config                                                        */
/* ------------------------------------------------------------------ */
typedef struct {
	const aik_config_item *item;
	const aik_json *value;	/* 借用（原值在 body 或 owned 里） */
	aik_json *owned;	/* parse 出来的自有值；native 为 NULL */
} parsed_item;

static int path_ends_with(const char *path, const char *suffix)
{
	size_t pl;
	size_t sl;

	if (!path || !suffix)
		return 0;
	pl = strlen(path);
	sl = strlen(suffix);
	if (sl > pl)
		return 0;
	return strcmp(path + (pl - sl), suffix) == 0;
}

void aik_http_route_config_put(aik_http_server *s,
			       const aik_http_request *req,
			       aik_http_response *resp)
{
	err_list el;
	aik_json *body;
	const aik_json *values;
	const aik_json *savev;
	aik_json *errors;
	parsed_item *parsed = NULL;
	size_t n_values = 0;
	size_t n_parsed = 0;
	int save = 0;
	int rc = -1;
	size_t i;

	memset(&el, 0, sizeof(el));
	body = parse_body(req, &el, resp);
	if (!body)
		return;
	if (require_obj(body, &el, resp) != 0) {
		aik_json_free(body);
		return;
	}
	/* values: dict[str, Any] = {}（null 也是 dict_type） */
	values = aik_json_get(body, "values");
	if (values && aik_json_typeof(values) != AIK_JSON_OBJ)
		el_add_field(&el, "dict_type", V_MSG_DICT, values, "values");
	/* save: bool = False */
	savev = aik_json_get(body, "save");
	if (savev) {
		if (aik_json_typeof(savev) != AIK_JSON_BOOL)
			el_add_field(&el, "bool_type", V_MSG_BOOL, savev,
				     "save");
		else
			save = aik_json_bool(savev);
	}
	if (el.oom || (el.arr && aik_json_count(el.arr) > 0)) {
		respond_422(&el, resp);
		aik_json_free(body);
		return;
	}
	aik_json_free(el.arr);
	el.arr = NULL;

	n_values = aik_json_count(values);
	if (n_values > 0) {
		parsed = calloc(n_values, sizeof(*parsed));
		if (!parsed) {
			aik_json_free(el.arr);
			aik_json_free(body);
			aik_http_response_detail(resp, 500,
						 "Internal Server Error");
			return;
		}
	}
	errors = aik_json_new_obj();
	if (!errors) {
		free(parsed);
		aik_json_free(el.arr);
		aik_json_free(body);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}

	for (i = 0; i < n_values; i++) {
		const char *path = aik_json_key_at(values, i);
		const aik_json *raw = aik_json_val_at(values, i);
		const aik_config_item *item;
		char perr[256];
		aik_json *errv;

		if (!path || !raw)
			continue;
		item = aik_config_item_find(path);
		if (!item) {
			errv = aik_json_new_str("未知的配置项");
			if (!errv ||
			    aik_json_obj_set(errors, path, errv) != 0) {
				aik_json_free(errv);
				el.oom = 1;
				break;
			}
			continue;
		}
		/* 掩码回显值 / 空串 = 不修改该项（仅对字符串成立） */
		if (path_ends_with(item->path, "api_key") &&
		    aik_json_typeof(raw) == AIK_JSON_STR) {
			const char *rs = aik_json_str(raw);

			if (!rs || !*rs || strcmp(rs, "******") == 0)
				continue;
		}
		if (aik_json_typeof(raw) == AIK_JSON_STR) {
			aik_json *out = NULL;

			perr[0] = '\0';
			if (aik_config_item_parse(item, aik_json_str(raw), &out,
						  perr, sizeof(perr)) != 0) {
				aik_json_free(out);
				errv = aik_json_new_str(perr);
				if (!errv ||
				    aik_json_obj_set(errors, path, errv) != 0) {
					aik_json_free(errv);
					el.oom = 1;
					break;
				}
				continue;
			}
			parsed[n_parsed].item = item;
			parsed[n_parsed].value = out;
			parsed[n_parsed].owned = out;
			n_parsed++;
		} else {
			int vrc;

			perr[0] = '\0';
			vrc = aik_config_item_validate(item, raw, perr,
						       sizeof(perr));
			if (vrc == -2) {
				el.oom = 1;
				break;
			}
			if (vrc != 0) {
				errv = aik_json_new_str(perr);
				if (!errv ||
				    aik_json_obj_set(errors, path, errv) != 0) {
					aik_json_free(errv);
					el.oom = 1;
					break;
				}
				continue;
			}
			parsed[n_parsed].item = item;
			parsed[n_parsed].value = raw;
			parsed[n_parsed].owned = NULL;
			n_parsed++;
		}
	}

	if (!el.oom && aik_json_count(errors) > 0) {
		aik_json_free(el.arr);
		el.arr = NULL;
		for (i = 0; i < n_parsed; i++)
			aik_json_free(parsed[i].owned);
		free(parsed);
		aik_json_free(body);
		respond_errors(errors, resp);
		return;
	}
	aik_json_free(errors);
	aik_json_free(el.arr);
	el.arr = NULL;
	if (el.oom) {
		for (i = 0; i < n_parsed; i++)
			aik_json_free(parsed[i].owned);
		free(parsed);
		aik_json_free(body);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	if (n_parsed == 0) {
		long long applied = 0;

		free(parsed);
		aik_json_free(body);
		respond_applied_count(applied,
				      aik_http_server_config_file(s), resp);
		return;
	}

	{
		char err[256];
		aik_json *new_dom =
			copy_config_dom(aik_engine_config(
						aik_http_server_engine(s)),
					err, sizeof(err));

		if (!new_dom) {
			for (i = 0; i < n_parsed; i++)
				aik_json_free(parsed[i].owned);
			free(parsed);
			aik_json_free(body);
			aik_http_response_detail(resp, 500,
						 "Internal Server Error");
			return;
		}
		for (i = 0; i < n_parsed; i++) {
			if (aik_config_item_set(new_dom, parsed[i].item,
						parsed[i].value) != 0) {
				aik_json_free(new_dom);
				for (i = 0; i < n_parsed; i++)
					aik_json_free(parsed[i].owned);
				free(parsed);
				aik_json_free(body);
				aik_http_response_detail(
					resp, 500, "Internal Server Error");
				return;
			}
		}
		rc = apply_config_dom(s, new_dom, save, resp);
		aik_json_free(new_dom);
	}
	{
		long long applied = (long long)n_parsed;

		for (i = 0; i < n_parsed; i++)
			aik_json_free(parsed[i].owned);
		free(parsed);
		aik_json_free(body);
		if (rc == 0)
			respond_applied_count(applied,
					      aik_http_server_config_file(s),
					      resp);
	}
}

/* ------------------------------------------------------------------ */
/* POST /config/preset                                                */
/* ------------------------------------------------------------------ */
void aik_http_route_config_preset(aik_http_server *s,
				  const aik_http_request *req,
				  aik_http_response *resp)
{
	err_list el;
	aik_json *body;
	const aik_json *keyv;
	const aik_json *savev;
	const char *key = NULL;
	const aik_config_preset *preset;
	aik_json *errors;
	aik_json **domes = NULL;
	aik_json *new_dom = NULL;
	aik_json *applied = NULL;
	int save = 1;
	int bad = 0;
	size_t i;

	memset(&el, 0, sizeof(el));
	body = parse_body(req, &el, resp);
	if (!body)
		return;
	if (require_obj(body, &el, resp) != 0) {
		aik_json_free(body);
		return;
	}
	/* key: str（必填） */
	keyv = aik_json_get(body, "key");
	if (!keyv)
		el_add_field(&el, "missing", V_MSG_MISSING, body, "key");
	else if (aik_json_typeof(keyv) != AIK_JSON_STR)
		el_add_field(&el, "string_type", V_MSG_STRING, keyv, "key");
	else
		key = aik_json_str(keyv);
	/* save: bool = True */
	savev = aik_json_get(body, "save");
	if (savev) {
		if (aik_json_typeof(savev) != AIK_JSON_BOOL)
			el_add_field(&el, "bool_type", V_MSG_BOOL, savev,
				     "save");
		else
			save = aik_json_bool(savev);
	}
	if (el.oom || (el.arr && aik_json_count(el.arr) > 0)) {
		if (el.arr && aik_json_count(el.arr) > 0) {
			respond_422(&el, resp);
		} else {
			aik_json_free(el.arr);
			el.arr = NULL;
			aik_http_response_detail(resp, 500,
						 "Internal Server Error");
		}
		aik_json_free(body);
		return;
	}
	aik_json_free(el.arr);
	el.arr = NULL;

	preset = aik_config_preset_find(key);
	if (!preset) {
		char list[256];
		size_t off = 0;
		char *msg;

		list[0] = '\0';
		for (i = 0; i < aik_config_preset_count; i++) {
			int n = snprintf(list + off, sizeof(list) - off,
					 "%s%s", off ? "、" : "",
					 aik_config_presets[i].key);

			if (n < 0 || (size_t)n >= sizeof(list) - off)
				break;
			off += (size_t)n;
		}
		msg = fmt_alloc("未知预设 key：%s（可选：%s）", key, list);
		aik_http_response_detail(resp, 400,
					 msg ? msg : "未知预设 key");
		free(msg);
		aik_json_free(body);
		return;
	}

	errors = aik_json_new_obj();
	if (!errors) {
		aik_json_free(body);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	if (preset->n_values > 0) {
		domes = calloc(preset->n_values, sizeof(*domes));
		if (!domes) {
			aik_json_free(errors);
			aik_json_free(body);
			aik_http_response_detail(resp, 500,
						 "Internal Server Error");
			return;
		}
	}
	for (i = 0; i < preset->n_values; i++) {
		const aik_config_preset_value *pv = &preset->values[i];
		const aik_config_item *item =
			aik_config_item_find(pv->path);
		char perr[256];
		aik_json *v;
		int vrc;

		if (!item) {
			aik_json_free(errors);
			for (i = 0; i < preset->n_values; i++)
				aik_json_free(domes[i]);
			free(domes);
			aik_json_free(body);
			aik_http_response_detail(resp, 500,
						 "Internal Server Error");
			return;
		}
		perr[0] = '\0';
		v = aik_json_parse(pv->value_json, strlen(pv->value_json),
				   perr, sizeof(perr));
		if (!v) {
			aik_json_free(errors);
			for (i = 0; i < preset->n_values; i++)
				aik_json_free(domes[i]);
			free(domes);
			aik_json_free(body);
			aik_http_response_detail(resp, 500,
						 "Internal Server Error");
			return;
		}
		domes[i] = v;
		vrc = aik_config_item_validate(item, v, perr, sizeof(perr));
		if (vrc != 0) {
			aik_json *errv = aik_json_new_str(
				vrc == -2 ? "值非法" : perr);

			if (!errv || aik_json_obj_set(errors, pv->path,
						      errv) != 0) {
				aik_json_free(errv);
				aik_json_free(errors);
				for (i = 0; i < preset->n_values; i++)
					aik_json_free(domes[i]);
				free(domes);
				aik_json_free(body);
				aik_http_response_detail(
					resp, 500, "Internal Server Error");
				return;
			}
		}
	}
	if (aik_json_count(errors) > 0) {
		for (i = 0; i < preset->n_values; i++)
			aik_json_free(domes[i]);
		free(domes);
		aik_json_free(body);
		respond_errors(errors, resp);
		return;
	}

	{
		char perr[256];

		new_dom = copy_config_dom(
			aik_engine_config(aik_http_server_engine(s)), perr,
			sizeof(perr));
	}
	if (!new_dom) {
		aik_json_free(errors);
		for (i = 0; i < preset->n_values; i++)
			aik_json_free(domes[i]);
		free(domes);
		aik_json_free(body);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	for (i = 0; i < preset->n_values; i++) {
		const aik_config_item *item =
			aik_config_item_find(preset->values[i].path);

		if (!item || aik_config_item_set(new_dom, item, domes[i]) != 0) {
			aik_json_free(new_dom);
			aik_json_free(errors);
			for (i = 0; i < preset->n_values; i++)
				aik_json_free(domes[i]);
			free(domes);
			aik_json_free(body);
			aik_http_response_detail(resp, 500,
						 "Internal Server Error");
			return;
		}
	}
	for (i = 0; i < preset->n_values; i++)
		aik_json_free(domes[i]);
	free(domes);
	domes = NULL;

	applied = jb_arr(&bad);
	for (i = 0; i < preset->n_values; i++)
		jb_push(applied, jb_str(preset->values[i].path, &bad), &bad);
	if (bad) {
		aik_json_free(applied);
		aik_json_free(new_dom);
		aik_json_free(errors);
		aik_json_free(body);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	if (apply_config_dom(s, new_dom, save, resp) == 0) {
		aik_json *out = jb_obj(&bad);

		jb_put(out, "ok", jb_bool(1, &bad), &bad);
		jb_put(out, "applied", applied, &bad);
		applied = NULL;
		if (bad) {
			aik_json_free(out);
			aik_http_response_detail(resp, 500,
						 "Internal Server Error");
		} else {
			aik_http_response_json(resp, 200, out);
		}
	}
	aik_json_free(applied);
	aik_json_free(errors);
	aik_json_free(new_dom);
	aik_json_free(body);
}

/* ------------------------------------------------------------------ */
/* POST /config/check                                                 */
/* ------------------------------------------------------------------ */
/* 组装一个 probe 对象：{configured, ok, detail} */
static aik_json *probe_obj(int configured, int ok, const char *detail,
			   int *bad)
{
	aik_json *o = jb_obj(bad);

	jb_put(o, "configured", jb_bool(configured, bad), bad);
	jb_put(o, "ok", jb_bool(ok, bad), bad);
	jb_put(o, "detail", jb_str(detail ? detail : "", bad), bad);
	return o;
}

void aik_http_route_config_check(aik_http_server *s,
				 const aik_http_request *req,
				 aik_http_response *resp)
{
	err_list el;
	aik_json *body;
	const aik_json *pingv;
	aik_engine *eng = aik_http_server_engine(s);
	aik_config *cfg;
	aik_json *display = NULL;
	aik_json *warnings = NULL;
	aik_json *out = NULL;
	aik_json *llm = NULL;
	aik_json *emb = NULL;
	aik_json *trial_dom = NULL;
	aik_config *trial_cfg = NULL;
	aik_engine *trial = NULL;
	char err[512];
	char *llm_detail = NULL;
	char *emb_detail = NULL;
	int ping = 0;
	int build_ok = 0;
	int config_valid;
	int bad = 0;

	memset(&el, 0, sizeof(el));
	body = parse_body(req, &el, resp);
	if (!body)
		return;
	if (require_obj(body, &el, resp) != 0) {
		aik_json_free(body);
		return;
	}
	/* ping: bool = False */
	pingv = aik_json_get(body, "ping");
	if (pingv) {
		if (aik_json_typeof(pingv) != AIK_JSON_BOOL)
			el_add_field(&el, "bool_type", V_MSG_BOOL, pingv,
				     "ping");
		else
			ping = aik_json_bool(pingv);
	}
	if (el.oom || (el.arr && aik_json_count(el.arr) > 0)) {
		if (el.arr && aik_json_count(el.arr) > 0) {
			respond_422(&el, resp);
		} else {
			aik_json_free(el.arr);
			el.arr = NULL;
			aik_http_response_detail(resp, 500,
						 "Internal Server Error");
		}
		aik_json_free(body);
		return;
	}
	aik_json_free(el.arr);
	el.arr = NULL;
	aik_json_free(body);

	cfg = aik_engine_config(eng);
	if (!cfg)
		goto oom;

	/* 1) 值合法性（display 视图，null 叶子剔除） */
	display = aik_config_display(aik_config_dom(cfg));
	if (!display)
		goto oom;
	err[0] = '\0';
	warnings = aik_config_validate_all(display, err, sizeof(err));
	aik_json_free(display);
	display = NULL;
	if (!warnings)
		goto oom;
	config_valid = aik_json_count(warnings) == 0;

	/* 2) 引擎试建（当前配置副本；失败即为 config_valid 之外的硬错误） */
	trial_dom = copy_config_dom(cfg, err, sizeof(err));
	if (!trial_dom)
		goto oom;
	trial_cfg = aik_config_from_json(trial_dom, err, sizeof(err));
	if (!trial_cfg)
		goto oom;
	trial = aik_engine_new(trial_cfg, 1, NULL, NULL, NULL, NULL, err,
			       sizeof(err));
	trial_cfg = NULL;	/* 成功/失败都由引擎接管或释放 */
	aik_json_free(trial_dom);
	trial_dom = NULL;

	if (!trial) {
		char *line = fmt_alloc("引擎构建失败：%s", err);
		aik_json *w;

		if (!line)
			goto oom;
		w = aik_json_new_str(line);
		if (!w || aik_json_arr_push(warnings, w) != 0) {
			aik_json_free(w);
			free(line);
			goto oom;
		}
		llm = probe_obj(0, 0, line, &bad);
		emb = probe_obj(0, 0, line, &bad);
		free(line);
		if (bad)
			goto oom;
	} else {
		const char *base;
		const char *key;
		const char *model;
		const char *provider;
		long long dim = 64;
		long long window = 3;
		int llm_configured;

		aik_engine_free(trial);
		trial = NULL;
		build_ok = 1;

		base = aik_config_get_str(cfg, "llm.base_url");
		key = aik_config_get_str(cfg, "llm.api_key");
		model = aik_config_get_str(cfg, "llm.model");
		llm_configured =
			base && *base &&
			!(strcmp(base, LLM_DEFAULT_BASE_URL) == 0 &&
			  (!key || !*key));
		if (llm_configured) {
			int llm_ok = 1;

			llm_detail = fmt_alloc(
				"LLM 已配置：%s model=%s key=%s", base,
				model ? model : "",
				(key && *key)
					? "已填"
					: "空（无鉴权头，多数服务会 401）");
			if (!llm_detail)
				goto oom;
			if (ping) {
				char *d2 = fmt_alloc(
					"%s；请求失败：C 版本未内置 LLM HTTP "
					"客户端",
					llm_detail);

				if (!d2)
					goto oom;
				free(llm_detail);
				llm_detail = d2;
				llm_ok = 0;
			}
			llm = probe_obj(1, llm_ok, llm_detail, &bad);
		} else {
			llm = probe_obj(
				0, 1,
				"LLM 未配置（llm.base_url 为空 → 纯离线可用）",
				&bad);
		}

		/*
		 * embedding：能走到这里说明引擎试建成功，provider 必为
		 * hashing（engine 只支持 hashing）。文案按参考的
		 * emb.name / emb.model_name 形态：hashing 的 model_name 是
		 * "hashing-d<dim>-w<max(1,window)>"。
		 */
		provider = aik_config_get_str(cfg, "embedding.provider");
		(void)aik_config_get_i64(cfg, "embedding.dim", &dim);
		(void)aik_config_get_i64(cfg, "embedding.hash_window",
					 &window);
		if (window < 1)
			window = 1;
		if (provider && strcmp(provider, "hashing") == 0) {
			char *name = fmt_alloc("hashing-d%lld-w%lld", dim,
					       window);

			if (!name)
				goto oom;
			emb_detail = fmt_alloc(
				"embedding=hashing（%s，无需网络）", name);
			free(name);
			if (!emb_detail)
				goto oom;
			emb = probe_obj(0, 1, emb_detail, &bad);
		} else {
			const char *emodel =
				aik_config_get_str(cfg, "embedding.model");

			emb_detail = fmt_alloc(
				"embedding=%s（%s，无需网络）",
				provider ? provider : "",
				emodel ? emodel : "");
			if (!emb_detail)
				goto oom;
			emb = probe_obj(1, 1, emb_detail, &bad);
		}
		if (bad)
			goto oom;
	}

	out = jb_obj(&bad);
	jb_put(out, "config_valid", jb_bool(config_valid, &bad), &bad);
	jb_put(out, "errors", warnings, &bad);
	warnings = NULL;
	jb_put(out, "engine_build_ok", jb_bool(build_ok, &bad), &bad);
	jb_put(out, "llm", llm, &bad);
	llm = NULL;
	jb_put(out, "embedding", emb, &bad);
	emb = NULL;
	free(llm_detail);
	free(emb_detail);
	if (bad) {
		aik_json_free(out);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_http_response_json(resp, 200, out);
	return;

oom:
	aik_engine_free(trial);
	aik_json_free(trial_dom);
	aik_json_free(display);
	aik_json_free(warnings);
	aik_json_free(llm);
	aik_json_free(emb);
	aik_json_free(out);
	free(llm_detail);
	free(emb_detail);
	aik_http_response_detail(resp, 500, "Internal Server Error");
}

/* ------------------------------------------------------------------ */
/* POST /config/reset                                                 */
/* ------------------------------------------------------------------ */
static int env_set_str(aik_config *cfg, const char *path, const char *value)
{
	aik_json *v;
	int rc;

	if (!value)
		return 0;
	v = aik_json_new_str(value);
	if (!v)
		return -1;
	rc = aik_config_set_dotted(cfg, path, v);
	aik_json_free(v);
	return rc;
}

static int env_set_int(aik_config *cfg, const char *path, long long value)
{
	aik_json *v = aik_json_new_int(value);
	int rc;

	if (!v)
		return -1;
	rc = aik_config_set_dotted(cfg, path, v);
	aik_json_free(v);
	return rc;
}

/*
 * apply_env_overrides - 与 main.c::apply_env_overrides 同序同语义
 *
 * SME_LLM_BASE_URL / SME_LLM_API_KEY / SME_LLM_MODEL、
 * SME_API_AUTH_TOKEN、SME_EMBEDDING_PROVIDER / MODEL / DIM / BASE_URL /
 * API_KEY。SME_EMBEDDING_DIM 非法返回 -1（Python int() 抛错）。
 */
static int apply_env_overrides(aik_config *cfg, int *from_env)
{
	const char *base_url = getenv("SME_LLM_BASE_URL");
	const char *token = getenv("SME_API_AUTH_TOKEN");
	const char *provider = getenv("SME_EMBEDDING_PROVIDER");

	*from_env = 0;
	if (base_url && *base_url) {
		const char *key = getenv("SME_LLM_API_KEY");
		const char *model = getenv("SME_LLM_MODEL");

		if (env_set_str(cfg, "llm.base_url", base_url) != 0 ||
		    env_set_str(cfg, "llm.api_key", key ? key : "") != 0 ||
		    env_set_str(cfg, "llm.model",
				model ? model : "gpt-4o-mini") != 0)
			return -1;
		*from_env = 1;
	}
	if (token && *token) {
		if (env_set_str(cfg, "api.auth_token", token) != 0)
			return -1;
		*from_env = 1;
	}
	if (provider && *provider) {
		const char *model = getenv("SME_EMBEDDING_MODEL");
		const char *dim_s = getenv("SME_EMBEDDING_DIM");
		const char *emb_url = getenv("SME_EMBEDDING_BASE_URL");
		const char *emb_key = getenv("SME_EMBEDDING_API_KEY");
		long long dim = 64;

		if (dim_s && *dim_s) {
			char *end = NULL;

			dim = strtoll(dim_s, &end, 10);
			if (end == dim_s || *end != '\0')
				return -1;
		}
		if (env_set_str(cfg, "embedding.provider", provider) != 0 ||
		    env_set_str(cfg, "embedding.model",
				model ? model : "text-embedding-3-small") != 0 ||
		    env_set_int(cfg, "embedding.dim", dim) != 0 ||
		    env_set_str(cfg, "embedding.base_url",
				emb_url ? emb_url : "") != 0 ||
		    env_set_str(cfg, "embedding.api_key",
				emb_key ? emb_key : "") != 0)
			return -1;
		*from_env = 1;
	}
	return 0;
}

void aik_http_route_config_reset(aik_http_server *s,
				 const aik_http_request *req,
				 aik_http_response *resp)
{
	const char *path = aik_http_server_config_file(s);
	char err[512];
	aik_config *cfg;
	aik_engine *old;
	aik_engine *neu = NULL;
	int from_env = 0;
	int rc;
	int bad = 0;
	aik_json *out;

	(void)req;
	if (path && *path && access(path, F_OK) == 0) {
		if (unlink(path) != 0) {
			char *msg = fmt_alloc("删除配置文件 %s 失败：%s", path,
					      strerror(errno));

			respond_global_error(resp, msg ? msg : strerror(errno));
			free(msg);
			return;
		}
	}
	err[0] = '\0';
	cfg = aik_config_defaults(err, sizeof(err));
	if (!cfg) {
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	/* reset = 内置默认 + 环境变量重放（不能把 env 弄丢） */
	if (apply_env_overrides(cfg, &from_env) != 0) {
		aik_config_free(cfg);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	old = aik_http_server_engine(s);
	rc = aik_engine_rebuild(old, cfg, &neu, err, sizeof(err));
	if (rc == 1) {
		respond_global_error(resp, err);
		return;
	}
	if (rc != 0) {
		char *msg = fmt_alloc("应用配置失败，引擎保持原配置：%s", err);

		respond_global_error(resp, msg ? msg : err);
		free(msg);
		return;
	}
	aik_http_server_set_engine(s, neu);
	aik_engine_free(old);
	/* 与参考一致：reset 后 source 恒为 "defaults"（env 值只进配置） */
	(void)from_env;
	aik_http_server_set_source(s, AIK_HTTP_SOURCE_DEFAULTS);

	out = jb_obj(&bad);
	jb_put(out, "ok", jb_bool(1, &bad), &bad);
	if (bad) {
		aik_json_free(out);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_http_response_json(resp, 200, out);
}

/* ------------------------------------------------------------------ */
/* POST /consolidate 与 POST /compress                                */
/* ------------------------------------------------------------------ */
static void respond_created(aik_http_server *s, aik_http_response *resp,
			    int compress)
{
	aik_engine *eng = aik_http_server_engine(s);
	aik_json *created = NULL;
	aik_json *out;
	char err[256];
	int rc;
	int bad = 0;

	if (compress)
		rc = aik_engine_compress(eng, &created, err, sizeof(err));
	else
		rc = aik_engine_consolidate(eng, &created, err, sizeof(err));
	if (rc != 0 || !created) {
		aik_json_free(created);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	out = jb_obj(&bad);
	jb_put(out, "created", created, &bad);
	if (bad) {
		aik_json_free(out);
		aik_http_response_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_http_response_json(resp, 200, out);
}

void aik_http_route_consolidate(aik_http_server *s,
				const aik_http_request *req,
				aik_http_response *resp)
{
	(void)req;
	respond_created(s, resp, 0);
}

void aik_http_route_compress(aik_http_server *s, const aik_http_request *req,
			     aik_http_response *resp)
{
	(void)req;
	respond_created(s, resp, 1);
}
