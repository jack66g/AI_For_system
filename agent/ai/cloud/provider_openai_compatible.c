/*
 * provider_openai_compatible.c - OpenAI Compatible Provider 实现
 *
 * 实现 OpenAI Chat Completions API (v1) 协议。
 * 支持所有兼容该协议的服务商（DeepSeek、OpenAI、Qwen 等）。
 *
 * Phase 3: 使用自研 HTTPS Client (mbedTLS) 替代 curl/popen。
 * JSON 解析使用内嵌的简易解析器。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "ai_provider.h"
#include "ai_config.h"
#include "ai_stream.h"
#include "http/http_client.h"

/* ---- 内部类型 ---- */

struct openai_data {
	struct ai_config *config;
	char *model_name;
	char *base_url;
	char *api_key;
	int connected;
};

/* ---- 简易 JSON 值提取器 ---- */

/*
 * json_get_str - 从 JSON 中提取 key 对应的字符串值
 *
 * 直接查找 "\"key\":\"value\"" 模式。
 * 返回提取的值（需 free），失败返回 NULL。
 */
static char *json_get_str(const char *json, const char *key)
{
	char search[128];
	const char *p;
	int klen;

	klen = snprintf(search, sizeof(search), "\"%s\":\"", key);
	if (klen < 0 || klen >= (int)sizeof(search))
		return NULL;

	p = strstr(json, search);
	if (!p)
		return NULL;

	p += klen;

	/* 提取 value（处理转义） */
	char *result;
	int len = 0, cap = 256;

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
			cap *= 2;
			char *tmp = realloc(result, cap);
			if (!tmp) { free(result); return NULL; }
			result = tmp;
		}
		result[len++] = c;
	}
	result[len] = '\0';

	return result;
}

/* ---- HTTPS 通信（自研 mbedTLS 客户端） ---- */

static char *https_api_call(const char *base_url, const char *api_key,
			    const char *json_body, int *out_error)
{
	char full_url[1024];
	char *response = NULL;
	char *error_msg = NULL;
	int ret;

	snprintf(full_url, sizeof(full_url), "%s/chat/completions", base_url);

	ret = https_post(full_url, api_key, json_body, &response, &error_msg);

	if (ret != 0) {
		if (out_error) {
			if (error_msg) {
				if (strstr(error_msg, "TLS"))
					*out_error = AI_ERR_NETWORK;
				else if (strstr(error_msg, "Network"))
					*out_error = AI_ERR_NETWORK;
				else
					*out_error = AI_ERR_NETWORK;
			} else {
				*out_error = AI_ERR_NETWORK;
			}
		}
		if (error_msg)
			printf("Error: %s\n", error_msg);
		free(error_msg);
		return NULL;
	}

	return response;
}

/* ---- OpenAI Compatible Provider 接口实现 ---- */

static int openai_init(void *instance, struct ai_config *cfg)
{
	struct openai_data *data = instance;

	if (!data || !cfg)
		return AI_ERR_INVALID_ARG;

	data->config = cfg;
	/* Phase 4: Communication Layer 统一管理 https_init，此处不再调用 */
	return AI_OK;
}

static int openai_connect(void *instance)
{
	struct openai_data *data = instance;

	if (!data)
		return AI_ERR_INVALID_ARG;

	if (!data->base_url || !data->api_key || !data->model_name)
		return AI_ERR_CONFIG;

	data->connected = 1;
	return AI_OK;
}

static char *build_request_json_ex(const char *model_name, const char *prompt,
				   int stream)
{
	char *json;
	size_t len;
	const char *template =
		"{"
		"\"model\":\"%s\","
		"\"messages\":["
		"{\"role\":\"user\",\"content\":\"%s\"}"
		"],"
		"\"stream\":%s,"
		"\"temperature\":0.7,"
		"\"max_tokens\":2048"
		"}";

	size_t prompt_len = strlen(prompt);
	char *escaped = malloc(prompt_len * 2 + 1);
	char *d, *s;

	if (!escaped)
		return NULL;

	d = escaped;
	for (s = (char *)prompt; *s; s++) {
		switch (*s) {
		case '"':  *d++ = '\\'; *d++ = '"'; break;
		case '\\': *d++ = '\\'; *d++ = '\\'; break;
		case '\n': *d++ = '\\'; *d++ = 'n'; break;
		case '\t': *d++ = '\\'; *d++ = 't'; break;
		default:   *d++ = *s; break;
		}
	}
	*d = '\0';

	len = strlen(template) + strlen(model_name) + strlen(escaped) + 8;
	json = malloc(len);
	if (json)
		snprintf(json, len, template, model_name, escaped,
			 stream ? "true" : "false");

	free(escaped);
	return json;
}

static char *build_request_json(const char *model_name, const char *prompt)
{
	return build_request_json_ex(model_name, prompt, 0);
}

static int openai_chat(void *instance, const char *prompt, char **response)
{
	struct openai_data *data = instance;
	char *json_body, *http_resp;
	int err_code = 0;

	if (!data || !prompt || !response)
		return AI_ERR_INVALID_ARG;

	if (!data->connected)
		return AI_ERR_NO_PROVIDER;

	json_body = build_request_json(data->model_name, prompt);
	if (!json_body)
		return AI_ERR_MEMORY;

	http_resp = https_api_call(data->base_url, data->api_key,
				   json_body, &err_code);
	free(json_body);

	if (!http_resp)
		return err_code ? err_code : AI_ERR_NETWORK;

	if (strstr(http_resp, "\"error\"") && strstr(http_resp, "\"message\"")) {
		char *err_msg = json_get_str(http_resp, "message");
		if (err_msg) {
			printf("API Error: %s\n", err_msg);
			free(err_msg);
		}

		int is_auth_err = (strstr(http_resp, "401") ||
				   strstr(http_resp, "auth"));
		int ret = is_auth_err ? AI_ERR_AUTH : AI_ERR_API;
		free(http_resp);
		return ret;
	}

	*response = json_get_str(http_resp, "content");

	free(http_resp);

	if (!*response)
		return AI_ERR_API;

	return AI_OK;
}

/* ---- 真增量流式（SSE） ----
 * 受 CONFIG_AI_STREAM_MODE 编译开关门控（Kconfig AIKERNEL_STREAM_MODE）：
 * 未编入流式时 ops.stream 为 NULL、capabilities 不标 CAP_STREAM，
 * 绝不虚标。 */

#ifdef CONFIG_AI_STREAM_MODE

/*
 * openai_stream 内部上下文：
 * https_post_stream 逐段交付（chunked 解码后）→ agg 行缓冲/SSE 解析
 * → delta.content 一到即包装为 NUL 结尾串回调 on_token（真增量：
 * 收到一个 delta 就回调一次，不等整个响应）。
 */
struct openai_stream_ctx {
	struct ai_stream_agg *agg;
	void (*on_token)(const char *token, void *user_data);
	void *user_data;
};

/* agg 的 content 增量回调 → on_token（NUL 结尾串约定） */
static void openai_stream_on_delta(void *ud, const char *delta, size_t len)
{
	struct openai_stream_ctx *c = ud;
	char *tok;

	tok = malloc(len + 1);
	if (!tok)
		return;
	memcpy(tok, delta, len);
	tok[len] = '\0';
	c->on_token(tok, c->user_data);
	free(tok);
}

/* https_post_stream body 段 → 流式聚合器（内部即时回调 on_token） */
static void openai_stream_on_data(void *ud, const char *data, size_t len)
{
	struct openai_stream_ctx *c = ud;

	ai_stream_agg_feed(c->agg, data, len, openai_stream_on_delta, c);
}

static int openai_stream(void *instance, const char *prompt,
			 void (*on_token)(const char *token, void *user_data),
			 void *user_data)
{
	struct openai_data *data = instance;
	struct openai_stream_ctx ctx;
	struct ai_stream_agg *agg = NULL;
	char *json_body = NULL;
	char *full_url = NULL;
	int status = 0;
	char *error_msg = NULL;
	size_t url_len;
	int ret;

	if (!data || !prompt || !on_token)
		return AI_ERR_INVALID_ARG;

	if (!data->connected)
		return AI_ERR_NO_PROVIDER;
	if (!data->base_url || !data->model_name)
		return AI_ERR_CONFIG;

	agg = ai_stream_agg_create();
	if (!agg)
		return AI_ERR_MEMORY;

	json_body = build_request_json_ex(data->model_name, prompt, 1);
	if (!json_body) {
		ai_stream_agg_free(agg);
		return AI_ERR_MEMORY;
	}

	url_len = strlen(data->base_url) + strlen("/chat/completions") + 1;
	full_url = malloc(url_len);
	if (!full_url) {
		free(json_body);
		ai_stream_agg_free(agg);
		return AI_ERR_MEMORY;
	}
	snprintf(full_url, url_len, "%s/chat/completions", data->base_url);

	ctx.agg = agg;
	ctx.on_token = on_token;
	ctx.user_data = user_data;

	ret = https_post_stream(full_url, data->api_key, json_body,
				openai_stream_on_data, &ctx,
				&status, &error_msg);
	free(full_url);
	free(json_body);

	if (ret != 0) {
		free(error_msg);
		ai_stream_agg_free(agg);
		return AI_ERR_NETWORK;
	}
	free(error_msg);

	if (status >= 400) {
		ai_stream_agg_free(agg);
		return (status == 401 || status == 403) ?
			AI_ERR_AUTH : AI_ERR_API;
	}

	/* 导出聚合结果并释放（content/tool_calls 调用方无需保留——
	 * 内容已经通过 on_token 增量交付） */
	{
		struct ai_chat_result result;

		memset(&result, 0, sizeof(result));
		ret = ai_stream_agg_finish(agg, &result);
		ai_chat_result_free(&result);
	}
	ai_stream_agg_free(agg);
	return ret;
}

#endif /* CONFIG_AI_STREAM_MODE */

static int openai_status(void *instance)
{
	struct openai_data *data = instance;

	if (!data)
		return AI_PROVIDER_UNINITIALIZED;

	return data->connected ?
		AI_PROVIDER_READY : AI_PROVIDER_DISCONNECTED;
}

static void openai_close(void *instance)
{
	struct openai_data *data = instance;

	if (!data)
		return;

	data->connected = 0;
	free(data->model_name);
	free(data->base_url);
	free(data->api_key);
	data->model_name = NULL;
	data->base_url = NULL;
	data->api_key = NULL;
}

/* ---- Provider 工厂函数 ---- */

struct ai_provider *openai_compatible_provider_create(void)
{
	struct ai_provider *provider;
	struct openai_data *data;

	provider = calloc(1, sizeof(*provider));
	if (!provider)
		return NULL;

	data = calloc(1, sizeof(*data));
	if (!data) {
		free(provider);
		return NULL;
	}

	provider->name = "openai_compatible";
	provider->display_name = "OpenAI Compatible Provider";
	provider->type = AI_PROVIDER_CLOUD;
#ifdef CONFIG_AI_STREAM_MODE
	/* CAP_STREAM 名副其实：openai_stream 经 https_post_stream 真增量
	 * （SSE + chunked 解码，delta 一到即回调） */
	provider->capabilities = AI_PROVIDER_CAP_CHAT | AI_PROVIDER_CAP_STREAM;
#else
	/* 编译开关关掉流式：如实只标 CHAT，ops.stream 为 NULL */
	provider->capabilities = AI_PROVIDER_CAP_CHAT;
#endif
	provider->instance = data;
	provider->state = AI_PROVIDER_UNINITIALIZED;

	provider->ops.init = openai_init;
	provider->ops.connect = openai_connect;
	provider->ops.chat = openai_chat;
#ifdef CONFIG_AI_STREAM_MODE
	provider->ops.stream = openai_stream;
#else
	provider->ops.stream = NULL;    /* 流式未编入，绝不虚标 */
#endif
	provider->ops.status = openai_status;
	provider->ops.close = openai_close;

	return provider;
}

void openai_provider_configure(struct ai_provider *provider,
			       const char *model_name,
			       const char *base_url,
			       const char *api_key)
{
	struct openai_data *data;

	if (!provider || !provider->instance)
		return;

	data = provider->instance;

	free(data->model_name);
	free(data->base_url);
	free(data->api_key);

	data->model_name = model_name ? strdup(model_name) : NULL;
	data->base_url = base_url ? strdup(base_url) : NULL;
	data->api_key = api_key ? strdup(api_key) : NULL;
}
