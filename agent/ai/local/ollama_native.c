// SPDX-License-Identifier: GPL-2.0
/*
 * ollama_native.c - Ollama 原生 /api/chat 通道实现
 *
 * 见 ollama_native.h。与 OpenAI 兼容路径（local_chat.c）的差异：
 *   - 请求：options.num_ctx / options.num_predict（/v1 不支持 num_ctx）；
 *   - assistant.tool_calls：原生格式 arguments 是 JSON 对象（/v1 是
 *     二次编码的字符串），role:tool 消息无需 tool_call_id；
 *   - 响应：message.tool_calls 同为对象参数；token 计数字段为
 *     prompt_eval_count / eval_count；结束标志 done_reason（非
 *     finish_reason）。
 * 消息数组的转换与解析全部走 ai_json_util 区间扫描（无 JSON 库依赖），
 * HTTP 传输复用 local/ 的 local_http_post。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "ai_types.h"
#include "ai_json_util.h"
#include "ai_chat.h"
#include "local_http.h"
#include "local_chat.h"
#include "ollama_native.h"

/* ---- 可增长字符串缓冲（与 ai_chat_proto.c 同风格的最小实现） ---- */

struct nb {
	char *s;
	size_t len, cap;
};

static int nb_reserve(struct nb *b, size_t extra)
{
	size_t need = b->len + extra + 1;

	if (need <= b->cap)
		return 0;
	{
		size_t ncap = b->cap ? b->cap : 512;
		char *ns;

		while (ncap < need)
			ncap *= 2;
		ns = realloc(b->s, ncap);
		if (!ns)
			return -1;
		b->s = ns;
		b->cap = ncap;
	}
	return 0;
}

static void nb_append(struct nb *b, const char *s, size_t n)
{
	if (nb_reserve(b, n) != 0)
		return;
	memcpy(b->s + b->len, s, n);
	b->len += n;
	b->s[b->len] = '\0';
}

static void nb_append_str(struct nb *b, const char *s)
{
	nb_append(b, s, strlen(s));
}

static void nb_append_json_str(struct nb *b, const char *s)
{
	char *esc = ai_json_escape(s ? s : "");

	if (!esc)
		return;
	nb_append_str(b, "\"");
	nb_append_str(b, esc);
	nb_append_str(b, "\"");
	free(esc);
}

static void nb_append_num(struct nb *b, long long v)
{
	char tmp[32];

	snprintf(tmp, sizeof(tmp), "%lld", v);
	nb_append_str(b, tmp);
}

/* ---- base_url 工具 ---- */

void ollama_native_strip_v1(const char *base_url, char *out, size_t len)
{
	size_t n;

	if (!base_url || !out || len == 0)
		return;
	n = strlen(base_url);
	while (n > 0 && base_url[n - 1] == '/')
		n--;
	if (n >= 3 && strncmp(base_url + n - 3, "/v1", 3) == 0)
		n -= 3;
	if (n >= len)
		n = len - 1;
	memcpy(out, base_url, n);
	out[n] = '\0';
}

/* ---- 上下文窗口上限探测（进程内缓存） ---- */

static pthread_mutex_t g_cap_mu = PTHREAD_MUTEX_INITIALIZER;
static char g_cap_base[256];
static char g_cap_model[128];
static int g_cap_value;         /* <=0 未缓存 */

int ollama_native_ctx_cap(const char *base_url, const char *model,
			  char **error)
{
	char root[512];
	char url[600];
	char body[256];
	char *resp = NULL;
	char *err = NULL;
	int cap = -1;
	int status = 0;

	if (error)
		*error = NULL;
	if (!base_url || !model)
		return -1;

	pthread_mutex_lock(&g_cap_mu);
	if (g_cap_value > 0 &&
	    strncmp(g_cap_base, base_url, sizeof(g_cap_base) - 1) == 0 &&
	    strncmp(g_cap_model, model, sizeof(g_cap_model) - 1) == 0) {
		int cached = g_cap_value;

		pthread_mutex_unlock(&g_cap_mu);
		return cached;
	}
	pthread_mutex_unlock(&g_cap_mu);

	ollama_native_strip_v1(base_url, root, sizeof(root));
	snprintf(url, sizeof(url), "%s/api/show", root);
	snprintf(body, sizeof(body), "{\"model\":\"%s\"}", model);

	{
		int t = local_chat_get_timeout();

		if (local_http_post(url, NULL, body,
				    t > 0 ? t : 3000, &resp, &err,
				    &status) != AI_OK) {
			if (error)
				*error = err ? err :
					strdup("POST /api/show failed");
			else
				free(err);
			return -1;
		}
	}

	/* 形如 "model_info":{"qwen2.context_length":32768,...}：
	 * 直接搜 context_length 键（首个命中即模型窗口上限） */
	{
		const char *key = strstr(resp, "context_length");

		if (key) {
			const char *colon = strchr(key + strlen("context_length"),
						   ':');
			const char *p = colon;

			if (p) {
				cap = (int)strtol(p + 1, NULL, 10);
				if (cap <= 0)
					cap = -1;
			}
		}
	}

	/* 兜底：根对象 context_length（极老版本无 model_info 包裹），
	 * 与上一分支同为文本扫描，无需额外处理 */

	if (cap > 0) {
		pthread_mutex_lock(&g_cap_mu);
		snprintf(g_cap_base, sizeof(g_cap_base), "%s", base_url);
		snprintf(g_cap_model, sizeof(g_cap_model), "%s", model);
		g_cap_value = cap;
		pthread_mutex_unlock(&g_cap_mu);
	}
	free(resp);
	return cap;
}

int ollama_native_clamp_ctx(const char *base_url, const char *model, int want)
{
	int cap = ollama_native_ctx_cap(base_url, model, NULL);

	if (cap > 0 && want > cap)
		return cap;
	return want;
}

/* ---- 消息数组 → 原生格式 ---- */

/*
 * 把 OpenAI 风格 tool_calls JSON 数组（ai_chat_render_tool_calls 产物，
 * arguments 为二次编码字符串）转换为原生数组（arguments 为裸对象）。
 */
static void nb_append_native_tool_calls(struct nb *b,
					const char *tc_json)
{
	const char *p = tc_json;
	const char *end;
	const char *tok;
	size_t tlen;
	int ttype;

	end = tc_json + strlen(tc_json);
	p = ai_json_skip_ws(p, end);
	if (ai_json_scan_value(&p, end, &tok, &tlen, &ttype) != 0 ||
	    ttype != AI_JSON_ARR) {
		nb_append_str(b, "[]");
		return;
	}

	nb_append_str(b, "[");
	p = ai_json_skip_ws(tok + 1, end);
	{
		int first = 1;

		while (p < end && *p != ']') {
			const char *etok, *fv;
			size_t elen, fvl;
			int etype, ftype;

			if (ai_json_scan_value(&p, end, &etok, &elen,
					       &etype) != 0)
				break;
			if (etype == AI_JSON_OBJ &&
			    ai_json_obj_get(etok, elen, "function", &fv, &fvl,
					    &ftype) == 1 &&
			    ftype == AI_JSON_OBJ) {
				const char *nv, *av;
				size_t nl, al;
				int nt_, at;

				if (ai_json_obj_get(fv, fvl, "name", &nv, &nl,
						    &nt_) == 1 &&
				    nt_ == AI_JSON_STR) {
					char *name =
						ai_json_strdup_str(nv, nl);
					char *args = NULL;

					/* arguments：字符串 → 解出对象原文 */
					if (ai_json_obj_get(fv, fvl,
							    "arguments", &av,
							    &al, &at) == 1 &&
					    at == AI_JSON_STR)
						args = ai_json_strdup_str(av,
									  al);

					if (!first)
						nb_append_str(b, ",");
					first = 0;
					nb_append_str(b,
						"{\"function\":{\"name\":");
					nb_append_json_str(b,
						name ? name : "");
					nb_append_str(b, ",\"arguments\":");
					nb_append_str(b,
						(args && args[0]) ? args : "{}");
					nb_append_str(b, "}}");
					free(name);
					free(args);
				}
			}
			p = ai_json_skip_ws(p, end);
			if (p < end && *p == ',') {
				p++;
				continue;
			}
			break;
		}
	}
	nb_append_str(b, "]");
}

/* 单条消息 → 原生 JSON 对象 */
static void nb_append_message(struct nb *b, const struct ai_chat_msg *m)
{
	nb_append_str(b, "{\"role\":");
	nb_append_json_str(b, m->role);

	if (m->tool_calls_json && m->tool_calls_json[0]) {
		if (m->content && m->content[0]) {
			nb_append_str(b, ",\"content\":");
			nb_append_json_str(b, m->content);
		}
		nb_append_str(b, ",\"tool_calls\":");
		nb_append_native_tool_calls(b, m->tool_calls_json);
	} else {
		nb_append_str(b, ",\"content\":");
		nb_append_json_str(b, m->content ? m->content : "");
	}
	/* 原生协议 tool 结果需要 tool_name（按名与调用配对；
	 * tool_call_id 是 OpenAI 概念，原生端不识别） */
	if (m->tool_call_id && m->tool_call_id[0] &&
	    m->tool_name && m->tool_name[0]) {
		nb_append_str(b, ",\"tool_name\":");
		nb_append_json_str(b, m->tool_name);
	}
	nb_append_str(b, "}");
}

/* ---- 请求体构造 ---- */

char *ollama_native_build_body(const char *model_name,
			       const struct ai_chat_msg *msgs, int nmsgs,
			       const char *tools_json,
			       int max_tokens, int num_ctx, int stream)
{
	struct nb b = { NULL, 0, 0 };
	int i;

	if (!model_name || !msgs || nmsgs <= 0)
		return NULL;

	/* 请求体：{"model","messages","stream":?,"options":{...}} */
	nb_append_str(&b, "{\"model\":");
	nb_append_json_str(&b, model_name);
	nb_append_str(&b, ",\"messages\":[");
	for (i = 0; i < nmsgs; i++) {
		if (i > 0)
			nb_append_str(&b, ",");
		nb_append_message(&b, &msgs[i]);
	}
	nb_append_str(&b, "]");

	if (tools_json && tools_json[0]) {
		nb_append_str(&b, ",\"tools\":");
		nb_append_str(&b, tools_json);
	}

	/* options：num_ctx（调用方已按模型上限钳制）/ num_predict */
	nb_append_str(&b, ",\"options\":{");
	{
		int first = 1;

		if (num_ctx > 0) {
			nb_append_str(&b, "\"num_ctx\":");
			nb_append_num(&b, num_ctx);
			first = 0;
		}
		if (max_tokens > 0) {
			if (!first)
				nb_append_str(&b, ",");
			nb_append_str(&b, "\"num_predict\":");
			nb_append_num(&b, max_tokens);
		}
	}
	nb_append_str(&b, "},\"stream\":");
	nb_append_str(&b, stream ? "true}" : "false}");

	return b.s;
}

/* ---- 非流式请求 ---- */

int ollama_native_chat(const char *base_url, const char *model_name,
		       const char *api_key,
		       const struct ai_chat_msg *msgs, int nmsgs,
		       const char *tools_json,
		       int max_tokens, int num_ctx,
		       struct ai_chat_result **result,
		       char **error_message, int *http_status)
{
	char root[512];
	char url[600];
	char *body = NULL;
	char *http_resp = NULL;
	char *err = NULL;
	int ret;

	if (result)
		*result = NULL;
	if (error_message)
		*error_message = NULL;
	if (http_status)
		*http_status = 0;

	if (!base_url || !model_name || !msgs || nmsgs <= 0 || !result ||
	    !error_message)
		return AI_ERR_INVALID_ARG;

	ollama_native_strip_v1(base_url, root, sizeof(root));
	snprintf(url, sizeof(url), "%s/api/chat", root);

	/* num_ctx 按模型实际上限钳制（/api/show 结果进程内缓存） */
	if (num_ctx > 0) {
		int cap = ollama_native_ctx_cap(base_url, model_name, NULL);

		if (cap > 0 && num_ctx > cap)
			num_ctx = cap;
	}

	body = ollama_native_build_body(model_name, msgs, nmsgs, tools_json,
					max_tokens, num_ctx, 0);
	if (!body)
		return AI_ERR_MEMORY;

	ret = local_http_post(url, api_key, body,
			      local_chat_get_timeout(), &http_resp, &err,
			      http_status);
	free(body);

	if (ret != AI_OK) {
		*error_message = err ? err :
			strdup("POST /api/chat failed");
		return ret;
	}

	/* HTTP 层错误 */
	if (http_status && *http_status >= 400) {
		char *detail = NULL;

		{
			const char *em = strstr(http_resp, "\"error\"");
			const char *end = http_resp + strlen(http_resp);
			const char *p = em ? strchr(em + 7, ':') : NULL;
			const char *tok, *v;
			size_t tl, vl;
			int ttype, vt;

			if (p) {
				p = ai_json_skip_ws(p + 1, end);
				if (ai_json_scan_value(&p, end, &tok, &tl,
						       &ttype) == 0 &&
				    ttype == AI_JSON_OBJ &&
				    ai_json_obj_get(tok, tl, "message", &v,
						    &vl, &vt) == 1 &&
				    vt == AI_JSON_STR)
					detail = ai_json_strdup_str(v, vl);
			}
		}
		{
			char prefix[96];

			snprintf(prefix, sizeof(prefix),
				 "Ollama native API HTTP %d", *http_status);
			if (detail) {
				char *m = malloc(strlen(prefix) +
						 strlen(detail) + 4);

				if (m) {
					snprintf(m, strlen(prefix) +
						 strlen(detail) + 4,
						 "%s (%s)", prefix, detail);
					*error_message = m;
				} else {
					*error_message = strdup(prefix);
				}
				free(detail);
			} else {
				*error_message = strdup(prefix);
			}
		}
		free(http_resp);
		return AI_ERR_API;
	}

	/* 解析响应 */
	*result = calloc(1, sizeof(**result));
	if (!*result) {
		free(http_resp);
		return AI_ERR_MEMORY;
	}
	{
		const char *resp = http_resp;
		size_t rlen = strlen(resp);
		const char *root_tok = NULL, *v;
		size_t root_len = 0, vl;
		int root_type = AI_JSON_NONE, vt;
		const char *p = resp;

		if (ai_json_scan_value(&p, resp + rlen, &root_tok, &root_len,
				       &root_type) != 0 ||
		    root_type != AI_JSON_OBJ) {
			free(http_resp);
			ai_chat_result_free(*result);
			free(*result);
			*result = NULL;
			*error_message = strdup("Malformed /api/chat response");
			return AI_ERR_PARSE;
		}

		/* message.content */
		if (ai_json_obj_get(root_tok, root_len, "message", &v, &vl,
				    &vt) == 1 && vt == AI_JSON_OBJ) {
			const char *mv = v;
			size_t ml = vl;
			const char *cv;
			size_t cl;
			int ct;

			if (ai_json_obj_get(mv, ml, "content", &cv, &cl,
					    &ct) == 1 && ct == AI_JSON_STR)
				(*result)->content =
					ai_json_strdup_str(cv, cl);

			/* message.tool_calls（原生：arguments 为对象） */
			if (ai_json_obj_get(mv, ml, "tool_calls", &cv, &cl,
					    &ct) == 1 && ct == AI_JSON_ARR) {
				const char *q = cv;
				const char *qe = cv + cl;
				const char *etok;
				size_t elen;
				int etype;

				q = ai_json_skip_ws(q + 1, qe);
				while (q < qe && *q != ']') {
					if (ai_json_scan_value(&q, qe, &etok,
							       &elen,
							       &etype) != 0)
						break;
					if (etype == AI_JSON_OBJ) {
						const char *fv, *nv, *av;
						size_t fl, nl, al;
						int ft, nt_, at;
						struct ai_tool_call *nt;

						if (ai_json_obj_get(etok,
							elen, "function",
							&fv, &fl, &ft) == 1 &&
						    ft == AI_JSON_OBJ) {
							nt = realloc(
						  (*result)->tool_calls,
						  sizeof(*nt) *
						  (size_t)
						  ((*result)->tool_call_count +
						   1));
							if (!nt)
								break;
							(*result)->tool_calls =
								nt;
							memset(&nt[(*result)->
						  tool_call_count], 0,
						  sizeof(*nt));
							if (ai_json_obj_get(
							  fv, fl, "name",
							  &nv, &nl,
							  &nt_) == 1 &&
							  nt_ == AI_JSON_STR)
							nt[(*result)->
						   tool_call_count].name =
							ai_json_strdup_str(nv,
									   nl);
							if (ai_json_obj_get(
							  fv, fl, "arguments",
							  &av, &al,
							  &at) == 1) {
								if (at ==
							    AI_JSON_OBJ) {
							nt[(*result)->
						   tool_call_count].arguments =
							malloc(al + 1);
							if (nt[(*result)->
						   tool_call_count].arguments) {
							memcpy(nt[(*result)->
						   tool_call_count].arguments,
						       av, al);
							nt[(*result)->
						   tool_call_count].
						   arguments[al] = '\0';
							}
								} else if (at ==
								AI_JSON_STR) {
							nt[(*result)->
						   tool_call_count].arguments =
							ai_json_strdup_str(av,
									   al);
								}
							}
							(*result)->
							tool_call_count++;
						}
					}
					q = ai_json_skip_ws(q, qe);
					if (q < qe && *q == ',') {
						q++;
						continue;
					}
					break;
				}
			}
		}

		/* done_reason → finish_reason */
		if (ai_json_obj_get(root_tok, root_len, "done_reason", &v,
				    &vl, &vt) == 1 && vt == AI_JSON_STR)
			(*result)->finish_reason =
				ai_json_strdup_str(v, vl);

		/* usage：原生 prompt_eval_count/eval_count（兼容
		 * OpenAI 风格 prompt_tokens/completion_tokens） */
		{
			const char *nv;
			size_t nl;
			int nt_;

			if (ai_json_obj_get(root_tok, root_len,
					    "prompt_eval_count", &nv, &nl,
					    &nt_) == 1 && nt_ == AI_JSON_NUM)
				(*result)->prompt_tokens =
					(int)ai_json_ll(nv, nl);
			if (ai_json_obj_get(root_tok, root_len, "eval_count",
					    &nv, &nl, &nt_) == 1 &&
			    nt_ == AI_JSON_NUM)
				(*result)->completion_tokens =
					(int)ai_json_ll(nv, nl);
			if (ai_json_obj_get(root_tok, root_len,
					    "prompt_tokens", &nv, &nl,
					    &nt_) == 1 && nt_ == AI_JSON_NUM)
				(*result)->prompt_tokens =
					(int)ai_json_ll(nv, nl);
			if (ai_json_obj_get(root_tok, root_len,
					    "completion_tokens", &nv, &nl,
					    &nt_) == 1 && nt_ == AI_JSON_NUM)
				(*result)->completion_tokens =
					(int)ai_json_ll(nv, nl);
		}
	}
	free(http_resp);
	return AI_OK;
}
