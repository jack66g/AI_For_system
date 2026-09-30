// SPDX-License-Identifier: GPL-2.0
/*
 * local_chat.c - 本地 AI 聊天客户端实现（OpenAI Chat Completions 兼容）
 *
 * 请求体 JSON 构造与响应解析与 cloud/provider_openai_compatible.c 对齐
 * （同样的字段、同样的简易 JSON 值提取器、同样的错误处理风格）。
 * 差异点：
 *   - prompt 转义额外覆盖 \r 等全部 ASCII 控制字符（\u00XX），
 *     云端构造器未处理的控制字符在这里保证输出仍是合法 JSON；
 *   - 通过 HTTP 状态码区分 401/403（认证）与 404（端点/模型不存在）。
 * 流式说明：本文件只承载非流式路径；流式统一走 local_stream.c
 * （local_chat_stream_messages，SSE / Ollama NDJSON 双协议真增量），
 * provider 层（provider_local.c ops.stream）与 Communication 层
 * （local_backend.c）共用该实现，无第二套流式代码。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_types.h"
#include "ai_json_util.h"
#include "local_http.h"
#include "local_chat.h"

/* 默认请求超时（毫秒），与 [local].timeout_ms 默认值一致 */
#define LOCAL_CHAT_DEFAULT_TIMEOUT_MS  60000

/* 探测专用超时（毫秒）：回环地址上连接拒绝/成功都是立即返回 */
#define LOCAL_CHAT_PROBE_TIMEOUT_MS    3000

static int g_timeout_ms = LOCAL_CHAT_DEFAULT_TIMEOUT_MS;

void local_chat_set_timeout(int timeout_ms)
{
	if (timeout_ms > 0)
		g_timeout_ms = timeout_ms;
}

int local_chat_get_timeout(void)
{
	return g_timeout_ms;
}

/* ---- JSON 工具（与云端 provider 风格一致） ---- */

/*
 * json_escape - 将字符串转义为可嵌入 JSON 字符串字面量的形式
 * T2 问题 1：此函数曾是 ai_json_escape 的重复实现（双源漂移）。
 * 现转调 runtime 层唯一实现——那里额外做非法 UTF-8 清洗（U+FFFD 替换），
 * 保证进入请求体的内容必为合法 UTF-8（含中文/emoji 的工具结果回传
 * 不再触发服务端 UnicodeDecodeError）。
 * 返回: malloc 的转义串（调用者需 free），失败返回 NULL。
 */
static char *json_escape(const char *src)
{
	return ai_json_escape(src);
}

/*
 * json_get_str - 从 JSON 中提取 key 对应的字符串值
 * 与 cloud/provider_openai_compatible.c 的同名提取器保持一致。
 * 返回提取的值（需 free），失败返回 NULL。
 */
static char *json_get_str(const char *json, const char *key)
{
	char search[128];
	const char *p;
	int klen;
	char *result;
	int len = 0, cap = 256;

	klen = snprintf(search, sizeof(search), "\"%s\":\"", key);
	if (klen < 0 || klen >= (int)sizeof(search))
		return NULL;

	p = strstr(json, search);
	if (!p)
		return NULL;

	p += klen;

	result = malloc(cap);
	if (!result)
		return NULL;

	while (*p && *p != '"') {
		char c;
		if (*p == '\\' && *(p + 1)) {
			char next = *(p + 1);

			if (next == 'n')      c = '\n';
			else if (next == 't') c = '\t';
			else if (next == '"') c = '"';
			else if (next == '\\') c = '\\';
			else { c = '\\'; result[len++] = c; c = next; }
			p += 2;
		} else {
			c = *p++;
		}
		if (len + 1 >= cap) {
			char *tmp;

			cap *= 2;
			tmp = realloc(result, cap);
			if (!tmp) {
				free(result);
				return NULL;
			}
			result = tmp;
		}
		result[len++] = c;
	}
	result[len] = '\0';

	return result;
}

/*
 * build_request_json - 构造 OpenAI Chat Completions 请求体
 * 字段与云端 provider 一致：model/messages/stream:false/temperature 0.7；
 * max_tokens 来自 [ui] 配置（请求级参数，<=0 取默认 4096）。
 */
static char *build_request_json(const char *model_name, const char *prompt,
				int max_tokens)
{
	char mt[32];
	const char *tmpl =
		"{"
		"\"model\":\"%s\","
		"\"messages\":["
		"{\"role\":\"user\",\"content\":\"%s\"}"
		"],"
		"\"stream\":false,"
		"\"temperature\":0.7,"
		"\"max_tokens\":%s"
		"}";

	char *esc_model, *esc_prompt, *json;
	size_t len;

	if (max_tokens <= 0)
		max_tokens = LOCAL_CHAT_DEFAULT_MAX_TOKENS;
	snprintf(mt, sizeof(mt), "%d", max_tokens);

	esc_model = json_escape(model_name);
	esc_prompt = json_escape(prompt);
	if (!esc_model || !esc_prompt) {
		free(esc_model);
		free(esc_prompt);
		return NULL;
	}

	len = strlen(tmpl) + strlen(esc_model) + strlen(esc_prompt) +
	      strlen(mt) + 1;
	json = malloc(len);
	if (json)
		snprintf(json, len, tmpl, esc_model, esc_prompt, mt);

	free(esc_model);
	free(esc_prompt);
	return json;
}

/*
 * compose_error - 拼接 "前缀 (细节)" 形式的错误消息
 * 返回 malloc 字符串（调用者需 free），失败返回 NULL。
 */
static char *compose_error(const char *prefix, const char *detail)
{
	size_t need;
	char *msg;

	if (!detail || !detail[0])
		return strdup(prefix);

	need = strlen(prefix) + strlen(detail) + 4;
	msg = malloc(need);
	if (msg)
		snprintf(msg, need, "%s (%s)", prefix, detail);
	return msg;
}

/* 连接类失败统一附上可操作提示（简报要求的固定提示语） */
static char *compose_unreachable(const char *raw_msg)
{
	static const char *hint =
		"本地服务未启动（Ollama/llama.cpp/LM Studio）或 base_url 配置错误";
	size_t need;
	char *msg;

	if (!raw_msg || !raw_msg[0])
		return strdup(hint);

	need = strlen(raw_msg) + strlen(hint) + 4;
	msg = malloc(need);
	if (msg)
		snprintf(msg, need, "%s. %s", raw_msg, hint);
	return msg;
}

/* ---- 对外接口 ---- */

int local_chat_complete(const char *base_url, const char *model_name,
			const char *api_key, const char *prompt,
			int max_tokens,
			char **response, char **error_message,
			int *http_status)
{
	char full_url[1024];
	char *json_body = NULL;
	char *http_resp = NULL;
	char *raw_err = NULL;
	size_t base_len;
	int ret;

	if (response)
		*response = NULL;
	if (error_message)
		*error_message = NULL;
	if (http_status)
		*http_status = 0;

	if (!base_url || !model_name || !prompt || !response || !error_message)
		return AI_ERR_INVALID_ARG;

	if (!base_url[0] || !model_name[0]) {
		*error_message = strdup("local.base_url / local.model is not "
					"configured");
		return AI_ERR_CONFIG;
	}

	/* 拼接完整端点 URL，容忍 base_url 末尾多余的 '/' */
	base_len = strlen(base_url);
	while (base_len > 0 && base_url[base_len - 1] == '/')
		base_len--;

	snprintf(full_url, sizeof(full_url), "%.*s/chat/completions",
		 (int)base_len, base_url);

	json_body = build_request_json(model_name, prompt, max_tokens);
	if (!json_body)
		return AI_ERR_MEMORY;

	ret = local_http_post(full_url, api_key, json_body, g_timeout_ms,
			      &http_resp, &raw_err, http_status);
	free(json_body);

	if (ret != AI_OK) {
		if (ret == AI_ERR_NETWORK) {
			/* 连接类失败：附上"本地服务未启动"提示 */
			*error_message = compose_unreachable(raw_err);
		} else {
			*error_message = raw_err;
			raw_err = NULL;
		}
		free(raw_err);
		return ret;
	}

	/* HTTP 层错误状态码 */
	if (http_status && *http_status >= 400) {
		char *detail = NULL;

		if (strstr(http_resp, "\"error\"") &&
		    strstr(http_resp, "\"message\""))
			detail = json_get_str(http_resp, "message");

		if (*http_status == 401 || *http_status == 403) {
			*error_message = detail ? detail :
				strdup("Authentication failed");
			ret = AI_ERR_AUTH;
		} else if (*http_status == 404) {
			*error_message = compose_error(
				"Endpoint or model not found (404); check "
				"that local.base_url includes /v1 and the "
				"model name is correct", detail);
			free(detail);
			ret = AI_ERR_API;
		} else {
			char prefix[96];

			snprintf(prefix, sizeof(prefix),
				 "Local service returned HTTP %d",
				 *http_status);
			*error_message = compose_error(prefix, detail);
			free(detail);
			ret = AI_ERR_API;
		}
		free(http_resp);
		return ret;
	}

	/* 200 响应中的业务错误对象（与云端 provider 判定方式一致） */
	if (strstr(http_resp, "\"error\"") && strstr(http_resp, "\"message\"")) {
		char *detail = json_get_str(http_resp, "message");
		int is_auth_err = strstr(http_resp, "401") != NULL ||
				  strstr(http_resp, "auth") != NULL;

		if (detail)
			*error_message = compose_error(
				is_auth_err ? "Authentication failed" :
					      "Local API error", detail);
		else
			*error_message = strdup(is_auth_err ?
				"Authentication failed" : "Local API error");
		free(detail);
		free(http_resp);
		return is_auth_err ? AI_ERR_AUTH : AI_ERR_API;
	}

	/* 提取回复正文（choices[0].message.content） */
	*response = json_get_str(http_resp, "content");
	free(http_resp);

	if (!*response) {
		*error_message = strdup("No 'content' found in response "
					"(not a chat/completions response?)");
		return AI_ERR_API;
	}

	return AI_OK;
}

int local_chat_probe_endpoint(const char *base_url, char **error_message)
{
	int ret;

	ret = local_http_probe(base_url, LOCAL_CHAT_PROBE_TIMEOUT_MS,
			       error_message);
	if (ret == AI_ERR_NETWORK) {
		char *raw = *error_message;

		*error_message = compose_unreachable(raw);
		free(raw);
	}
	return ret;
}

/*
 * local_chat_messages_complete - messages 数组模式请求
 * 请求体构造与响应解析统一走 ai_chat_proto（与 cloud backend 同一实现，
 * 避免双份协议代码漂移）；错误处理风格与 local_chat_complete 一致。
 */
int local_chat_messages_complete(const char *base_url, const char *model_name,
				 const char *api_key,
				 const struct ai_chat_msg *msgs, int nmsgs,
				 const char *tools_json,
				 int max_tokens,
				 struct ai_chat_result **result,
				 char **error_message, int *http_status)
{
	char full_url[1024];
	char *json_body = NULL;
	char *http_resp = NULL;
	char *raw_err = NULL;
	size_t base_len;
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

	if (!base_url[0] || !model_name[0]) {
		*error_message = strdup("local.base_url / local.model is not "
					"configured");
		return AI_ERR_CONFIG;
	}

	/* 拼接完整端点 URL，容忍 base_url 末尾多余的 '/' */
	base_len = strlen(base_url);
	while (base_len > 0 && base_url[base_len - 1] == '/')
		base_len--;

	snprintf(full_url, sizeof(full_url), "%.*s/chat/completions",
		 (int)base_len, base_url);

	json_body = ai_chat_build_request_json(model_name, msgs, nmsgs,
					       tools_json, 0.7,
					       max_tokens > 0 ?
					       max_tokens :
					       LOCAL_CHAT_DEFAULT_MAX_TOKENS);
	if (!json_body)
		return AI_ERR_MEMORY;

	ret = local_http_post(full_url, api_key, json_body, g_timeout_ms,
			      &http_resp, &raw_err, http_status);
	free(json_body);

	if (ret != AI_OK) {
		if (ret == AI_ERR_NETWORK) {
			*error_message = compose_unreachable(raw_err);
		} else {
			*error_message = raw_err;
			raw_err = NULL;
		}
		free(raw_err);
		return ret;
	}

	/* HTTP 层错误状态码（与 local_chat_complete 一致） */
	if (http_status && *http_status >= 400) {
		char *detail = NULL;

		if (strstr(http_resp, "\"error\"") &&
		    strstr(http_resp, "\"message\""))
			detail = json_get_str(http_resp, "message");

		if (*http_status == 401 || *http_status == 403) {
			*error_message = detail ? detail :
				strdup("Authentication failed");
			ret = AI_ERR_AUTH;
		} else if (*http_status == 404) {
			*error_message = compose_error(
				"Endpoint or model not found (404); check "
				"that local.base_url includes /v1 and the "
				"model name is correct", detail);
			free(detail);
			ret = AI_ERR_API;
		} else {
			char prefix[96];

			snprintf(prefix, sizeof(prefix),
				 "Local service returned HTTP %d",
				 *http_status);
			*error_message = compose_error(prefix, detail);
			free(detail);
			ret = AI_ERR_API;
		}
		free(http_resp);
		return ret;
	}

	*result = malloc(sizeof(**result));
	if (!*result) {
		free(http_resp);
		return AI_ERR_MEMORY;
	}
	memset(*result, 0, sizeof(**result));
	ret = ai_chat_parse_response(http_resp, *result);
	if (ret != AI_OK) {
		if ((*result)->finish_reason && !*error_message) {
			*error_message = (*result)->finish_reason;
			(*result)->finish_reason = NULL;
		}
		ai_chat_result_free(*result);
		free(*result);
		*result = NULL;
	}
	free(http_resp);
	return ret;
}
