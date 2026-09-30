// SPDX-License-Identifier: GPL-2.0
/*
 * ai_chat_proto.c - OpenAI Chat Completions 消息/工具调用协议层实现
 *
 * 请求构造与响应解析的唯二入口（local/cloud 两条传输通道共用）：
 *   - ai_chat_build_request_json：messages 数组 + 可选 tools 数组；
 *   - ai_chat_parse_response：choices[0].message{content,tool_calls}，
 *     使用 ai_json_util 的区间扫描，字符串转义正确处理；
 *   - ai_chat_parse_text_toolcall：降级协议（模型不支持 tools 字段时，
 *     以纯文本 JSON 约定工具调用）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_types.h"
#include "ai_json_util.h"
#include "ai_chat.h"

/* ---- 可增长字符串缓冲 ---- */

struct sbuf {
	char *s;
	size_t len;
	size_t cap;
};

static int sbuf_reserve(struct sbuf *b, size_t extra)
{
	size_t need = b->len + extra + 1;

	if (need <= b->cap)
		return 0;
	{
		size_t ncap = b->cap ? b->cap : 1024;

		while (ncap < need)
			ncap *= 2;
		{
			char *ns = realloc(b->s, ncap);

			if (!ns)
				return -1;
			b->s = ns;
			b->cap = ncap;
		}
	}
	return 0;
}

/* 追加任意长度文本 */
static void sbuf_append(struct sbuf *b, const char *s, size_t n)
{
	if (sbuf_reserve(b, n) != 0)
		return;
	memcpy(b->s + b->len, s, n);
	b->len += n;
	b->s[b->len] = '\0';
}

static void sbuf_append_str(struct sbuf *b, const char *s)
{
	sbuf_append(b, s, strlen(s));
}

/* 追加 JSON 字符串字面量（内部转义） */
static void sbuf_append_json_str(struct sbuf *b, const char *s)
{
	char *esc = ai_json_escape(s ? s : "");

	if (!esc)
		return;
	sbuf_append_str(b, "\"");
	sbuf_append_str(b, esc);
	sbuf_append_str(b, "\"");
	free(esc);
}

static void sbuf_append_num(struct sbuf *b, long long v)
{
	char tmp[32];

	snprintf(tmp, sizeof(tmp), "%lld", v);
	sbuf_append_str(b, tmp);
}

/* ---- 请求构造 ---- */

/* 单条消息 → JSON 对象文本 */
static void append_message_json(struct sbuf *b, const struct ai_chat_msg *m)
{
	sbuf_append_str(b, "{\"role\":");
	sbuf_append_json_str(b, m->role);

	if (m->tool_calls_json && m->tool_calls_json[0]) {
		/* assistant 发起工具调用：content 允许为 null */
		if (m->content && m->content[0]) {
			sbuf_append_str(b, ",\"content\":");
			sbuf_append_json_str(b, m->content);
		} else {
			sbuf_append_str(b, ",\"content\":null");
		}
		sbuf_append_str(b, ",\"tool_calls\":");
		sbuf_append_str(b, m->tool_calls_json);
	} else if (m->tool_call_id && m->tool_call_id[0]) {
		/* role:tool 工具结果消息 */
		sbuf_append_str(b, ",\"tool_call_id\":");
		sbuf_append_json_str(b, m->tool_call_id);
		sbuf_append_str(b, ",\"content\":");
		sbuf_append_json_str(b, m->content ? m->content : "");
	} else {
		sbuf_append_str(b, ",\"content\":");
		sbuf_append_json_str(b, m->content ? m->content : "");
	}

	sbuf_append_str(b, "}");
}

char *ai_chat_build_request_json_ex(const char *model_name,
				    const struct ai_chat_msg *msgs,
				    int nmsgs, const char *tools_json,
				    double temperature, int max_tokens,
				    int stream)
{
	struct sbuf b = { NULL, 0, 0 };
	char head[128];
	int i;

	if (!model_name || !msgs || nmsgs <= 0)
		return NULL;

	snprintf(head, sizeof(head), "{\"model\":");
	sbuf_append_str(&b, head);
	sbuf_append_json_str(&b, model_name);
	sbuf_append_str(&b, ",\"messages\":[");

	for (i = 0; i < nmsgs; i++) {
		if (i > 0)
			sbuf_append_str(&b, ",");
		append_message_json(&b, &msgs[i]);
	}
	sbuf_append_str(&b, "]");

	/* tools 数组原样嵌入（由注册表生成，已保证为合法 JSON 数组） */
	if (tools_json && tools_json[0]) {
		sbuf_append_str(&b, ",\"tools\":");
		sbuf_append_str(&b, tools_json);
		sbuf_append_str(&b, ",\"tool_choice\":\"auto\"");
	}

	/* 流式开关：SSE + include_usage（末帧回传 usage 真值） */
	if (stream)
		sbuf_append_str(&b, ",\"stream\":true,\"stream_options\":"
				     "{\"include_usage\":true}");
	else
		sbuf_append_str(&b, ",\"stream\":false");

	sbuf_append_str(&b, ",\"temperature\":");
	{
		char tmp[32];

		snprintf(tmp, sizeof(tmp), "%.2f", temperature);
		sbuf_append_str(&b, tmp);
	}
	sbuf_append_str(&b, ",\"max_tokens\":");
	sbuf_append_num(&b, max_tokens);
	sbuf_append_str(&b, "}");

	return b.s;
}

char *ai_chat_build_request_json(const char *model_name,
				 const struct ai_chat_msg *msgs, int nmsgs,
				 const char *tools_json,
				 double temperature, int max_tokens)
{
	return ai_chat_build_request_json_ex(model_name, msgs, nmsgs,
					     tools_json, temperature,
					     max_tokens, 0);
}

/* ---- 响应解析 ---- */

void ai_chat_result_free(struct ai_chat_result *r)
{
	int i;

	if (!r)
		return;
	free(r->content);
	free(r->finish_reason);
	for (i = 0; i < r->tool_call_count; i++) {
		free(r->tool_calls[i].id);
		free(r->tool_calls[i].name);
		free(r->tool_calls[i].arguments);
	}
	free(r->tool_calls);
	memset(r, 0, sizeof(*r));
}

/* 从 tool_calls 数组 token 解析全部元素 */
static int parse_tool_calls(const char *tok, size_t tlen,
			    struct ai_chat_result *out)
{
	const char *p = tok;
	const char *end = tok + tlen;
	int idx = 0;

	p = ai_json_skip_ws(p + 1, end);        /* 跳过 '[' */

	out->tool_calls = NULL;
	out->tool_call_count = 0;

	while (p < end && *p != ']') {
		const char *etok;
		size_t elen;
		int etype;
		const char *fv;
		size_t fvl;
		int ftype;
		struct ai_tool_call tc;
		struct ai_tool_call *nt;

		if (ai_json_scan_value(&p, end, &etok, &elen, &etype) != 0)
			return AI_ERR_PARSE;

		memset(&tc, 0, sizeof(tc));

		if (etype == AI_JSON_OBJ) {
			/* id / type / function{name,arguments} */
			if (ai_json_obj_get(etok, elen, "id", &fv, &fvl,
					    &ftype) == 1 &&
			    ftype == AI_JSON_STR)
				tc.id = ai_json_strdup_str(fv, fvl);
			if (ai_json_obj_get(etok, elen, "function", &fv,
					    &fvl, &ftype) == 1 &&
			    ftype == AI_JSON_OBJ) {
				const char *nv, *av;
				size_t nl, al;
				int nt_, at;

				if (ai_json_obj_get(fv, fvl, "name", &nv,
						    &nl, &nt_) == 1 &&
				    nt_ == AI_JSON_STR)
					tc.name = ai_json_strdup_str(nv, nl);
				if (ai_json_obj_get(fv, fvl, "arguments",
						    &av, &al, &at) == 1 &&
				    at == AI_JSON_STR)
					tc.arguments =
						ai_json_strdup_str(av, al);
			}
		}

		nt = realloc(out->tool_calls,
			     sizeof(*nt) * (size_t)(out->tool_call_count + 1));
		if (!nt) {
			free(tc.id);
			free(tc.name);
			free(tc.arguments);
			return AI_ERR_MEMORY;
		}
		out->tool_calls = nt;
		out->tool_calls[out->tool_call_count++] = tc;

		idx++;
		p = ai_json_skip_ws(p, end);
		if (p < end && *p == ',') {
			p++;
			continue;
		}
		break;
	}

	(void)idx;
	return AI_OK;
}

int ai_chat_parse_response(const char *http_body, struct ai_chat_result *out)
{
	const char *body;
	size_t blen;
	const char *root_tok = NULL;
	size_t root_len = 0;
	int root_type = AI_JSON_NONE;
	const char *v;
	size_t vl;
	int vt;
	int ret;

	if (!http_body || !out)
		return AI_ERR_INVALID_ARG;

	memset(out, 0, sizeof(*out));
	body = http_body;
	blen = strlen(body);

	/* 根对象 */
	{
		const char *p = body;

		if (ai_json_scan_value(&p, body + blen, &root_tok,
				       &root_len, &root_type) != 0 ||
		    root_type != AI_JSON_OBJ)
			return AI_ERR_PARSE;
	}

	/* 业务错误对象：{"error":{"message":..}} */
	if (ai_json_obj_get(root_tok, root_len, "error", &v, &vl, &vt) == 1 &&
	    (vt == AI_JSON_OBJ || vt == AI_JSON_STR)) {
		char *msg = NULL;

		if (vt == AI_JSON_OBJ &&
		    ai_json_obj_get(v, vl, "message", &v, &vl, &vt) == 1 &&
		    vt == AI_JSON_STR)
			msg = ai_json_strdup_str(v, vl);
		out->finish_reason = msg;       /* 借用字段携带错误摘要 */
		return AI_ERR_API;
	}

	/* choices[0].message */
	if (ai_json_obj_get(root_tok, root_len, "choices", &v, &vl, &vt) != 1 ||
	    vt != AI_JSON_ARR)
		return AI_ERR_PARSE;
	if (ai_json_arr_get(v, vl, 0, &v, &vl, &vt) != 1 || vt != AI_JSON_OBJ)
		return AI_ERR_PARSE;

	/* finish_reason */
	if (ai_json_obj_get(v, vl, "finish_reason", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_STR)
		out->finish_reason = ai_json_strdup_str(v, vl);

	/* 回到 choices[0] 对象取 message */
	if (ai_json_obj_get(root_tok, root_len, "choices", &v, &vl, &vt) != 1 ||
	    vt != AI_JSON_ARR)
		return AI_ERR_PARSE;
	if (ai_json_arr_get(v, vl, 0, &v, &vl, &vt) != 1 || vt != AI_JSON_OBJ)
		return AI_ERR_PARSE;
	if (ai_json_obj_get(v, vl, "message", &v, &vl, &vt) != 1 ||
	    vt != AI_JSON_OBJ)
		return AI_ERR_PARSE;
	{
		const char *msg_tok = v;
		size_t msg_len = vl;

		/* content（可为 null/缺失） */
		if (ai_json_obj_get(msg_tok, msg_len, "content", &v, &vl,
				    &vt) == 1 && vt == AI_JSON_STR)
			out->content = ai_json_strdup_str(v, vl);

		/* tool_calls（可缺失） */
		if (ai_json_obj_get(msg_tok, msg_len, "tool_calls", &v, &vl,
				    &vt) == 1 && vt == AI_JSON_ARR) {
			ret = parse_tool_calls(v, vl, out);
			if (ret != AI_OK)
				return ret;
		}
	}

	/* usage 真值（prompt_tokens/completion_tokens；缺失保持 0） */
	if (ai_json_obj_get(root_tok, root_len, "usage", &v, &vl,
			    &vt) == 1 && vt == AI_JSON_OBJ) {
		const char *uv = v;
		size_t ul = vl;

		if (ai_json_obj_get(uv, ul, "prompt_tokens", &v, &vl,
				    &vt) == 1 && vt == AI_JSON_NUM)
			out->prompt_tokens = (int)ai_json_ll(v, vl);
		if (ai_json_obj_get(uv, ul, "completion_tokens", &v, &vl,
				    &vt) == 1 && vt == AI_JSON_NUM)
			out->completion_tokens = (int)ai_json_ll(v, vl);
	}

	return AI_OK;
}

/* ---- 降级协议：文本 JSON 工具调用 ---- */

/*
 * find_balanced_object - 从 text 中找到第一个完整的 {...} 对象
 * 正确处理字符串转义；返回对象 token 区间，找不到返回 -1。
 */
static int find_balanced_object(const char *text, const char **tok,
				size_t *tlen)
{
	const char *start = NULL;
	const char *p = text;
	int depth = 0;
	int in_str = 0;

	while (*p) {
		if (in_str) {
			if (*p == '\\')
				p++;            /* 跳过被转义字符 */
			else if (*p == '"')
				in_str = 0;
		} else if (*p == '"') {
			in_str = 1;
		} else if (*p == '{') {
			if (depth == 0)
				start = p;      /* 记录最外层 '{' */
			depth++;
		} else if (*p == '}') {
			depth--;
			if (depth == 0 && start) {
				*tok = start;
				*tlen = (size_t)(p - start + 1);
				return 0;
			}
			if (depth < 0)
				break;          /* 括号失衡 */
		}
		p++;
	}
	return -1;
}

int ai_chat_parse_text_toolcall(const char *content,
				struct ai_tool_call *tc, char **answer)
{
	const char *tok;
	size_t tlen;
	const char *v;
	size_t vl;
	int vt;
	char *name = NULL;
	char *args = NULL;

	if (answer)
		*answer = NULL;
	if (!content || !tc)
		return -1;

	/* 快速排除：没有 '{' 直接按纯文本处理 */
	if (!strchr(content, '{'))
		return AI_TEXT_TOOL_NONE;

	if (find_balanced_object(content, &tok, &tlen) != 0)
		return AI_TEXT_TOOL_NONE;

	/* {"tool"/"name": "...", "arguments": {...}} */
	{
		const char *nm = NULL;
		size_t nml = 0;

		if (ai_json_obj_get(tok, tlen, "tool", &v, &vl, &vt) == 1 &&
		    vt == AI_JSON_STR) {
			nm = v;
			nml = vl;
		} else if (ai_json_obj_get(tok, tlen, "name", &v, &vl,
					   &vt) == 1 && vt == AI_JSON_STR) {
			nm = v;
			nml = vl;
		}

		if (nm) {
			name = ai_json_strdup_str(nm, nml);
			/* arguments 可为对象（原样截取）或字符串（二次编码） */
			if (ai_json_obj_get(tok, tlen, "arguments", &v, &vl,
					    &vt) == 1) {
				if (vt == AI_JSON_OBJ) {
					args = malloc(vl + 1);
					if (args) {
						memcpy(args, v, vl);
						args[vl] = '\0';
					}
				} else if (vt == AI_JSON_STR) {
					args = ai_json_strdup_str(v, vl);
				}
			} else {
				/* 无参数工具：补空对象 */
				args = strdup("{}");
			}
		}
	}

	if (name && args) {
		memset(tc, 0, sizeof(*tc));
		tc->id = strdup("text-1");
		tc->name = name;
		tc->arguments = args;
		return AI_TEXT_TOOL_CALL;
	}
	free(name);
	free(args);

	/* {"answer": "..."} 形式 */
	if (ai_json_obj_get(tok, tlen, "answer", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_STR) {
		if (answer) {
			*answer = ai_json_strdup_str(v, vl);
			if (!*answer)
				*answer = strdup(content);
		}
		return AI_TEXT_TOOL_NONE;
	}

	/* JSON 不是工具调用也不是 answer：按纯文本处理 */
	return AI_TEXT_TOOL_NONE;
}

char *ai_chat_render_tool_calls(const struct ai_tool_call *tcs, int n)
{
	struct sbuf b = { NULL, 0, 0 };
	int i;

	if (!tcs || n <= 0)
		return NULL;

	sbuf_append_str(&b, "[");
	for (i = 0; i < n; i++) {
		if (i > 0)
			sbuf_append_str(&b, ",");
		sbuf_append_str(&b, "{\"id\":");
		sbuf_append_json_str(&b, tcs[i].id ? tcs[i].id : "");
		sbuf_append_str(&b, ",\"type\":\"function\",\"function\":{"
				     "\"name\":");
		sbuf_append_json_str(&b, tcs[i].name ? tcs[i].name : "");
		sbuf_append_str(&b, ",\"arguments\":");
		/* arguments 是 JSON 对象字符串 → 二次编码为字符串字面量 */
		sbuf_append_json_str(&b, tcs[i].arguments ? tcs[i].arguments
							  : "{}");
		sbuf_append_str(&b, "}}");
	}
	sbuf_append_str(&b, "]");

	return b.s;
}
