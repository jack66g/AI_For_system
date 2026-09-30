// SPDX-License-Identifier: GPL-2.0
/*
 * provider_local.c - Local AI Provider 实现
 *
 * 取代原 provider_local_stub.c 桩（其全部方法返回 AI_ERR_NOT_IMPLEMENTED）。
 * 方案：OpenAI 兼容本地端点客户端 —— POST {base_url}/chat/completions
 * （base_url 默认已含 /v1），纯 HTTP 不带 TLS（本地回环），
 * 兼容 Ollama(11434)/llama.cpp server(8080)/LM Studio(1234)。
 *
 * 两层分工（与云端 provider/backend 一致）：
 *   - 本文件：Provider 注册中心层的生命周期（init/connect/status/close），
 *     ops.chat 通过 local_chat 模块实现（Phase 4 后由 Communication 层
 *     接管数据路径，此实现作为直连兜底）；
 *   - runtime/communication/backend/local_backend.c：Communication 层
 *     的实际数据路径，同样复用 local_chat 模块。
 *
 * 配置来源：model.toml 的 [local] 段（见 ai_config.h 的
 * struct ai_local_config），运行时由 `model use local` 应用。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_provider.h"
#include "ai_config.h"
#include "ai_stream.h"
#include "local_chat.h"

/* 默认请求超时（毫秒），与 config_manager.c 中 [local] 默认值一致 */
#define LOCAL_PROVIDER_DEFAULT_TIMEOUT_MS  60000

/* ---- Local Provider 实例数据 ---- */

struct local_provider_data {
	struct ai_config *config;   /* 配置管理器（读取 [local] 段） */
	char *base_url;             /* 本地服务 Base URL（含 /v1） */
	char *model_name;           /* 模型名 */
	char *api_key;              /* 可选 API Key（空则不发认证头） */
	int   timeout_ms;           /* 请求超时（毫秒） */
	int   connected;            /* 是否已"连接"（配置就绪） */
};

/* ---- 接口实现 ---- */

static int local_init(void *instance, struct ai_config *cfg)
{
	struct local_provider_data *data = instance;

	if (!data || !cfg)
		return AI_ERR_INVALID_ARG;

	data->config = cfg;

	/* 首次初始化：从 [local] 段载入参数并应用超时 */
	if (cfg->local.base_url && !data->base_url)
		data->base_url = strdup(cfg->local.base_url);
	if (cfg->local.model && !data->model_name)
		data->model_name = strdup(cfg->local.model);
	if (cfg->local.api_key && !data->api_key)
		data->api_key = strdup(cfg->local.api_key);
	if (cfg->local.timeout_ms > 0) {
		data->timeout_ms = cfg->local.timeout_ms;
		local_chat_set_timeout(cfg->local.timeout_ms);
	} else {
		data->timeout_ms = LOCAL_PROVIDER_DEFAULT_TIMEOUT_MS;
	}

	return AI_OK;
}

static int local_connect(void *instance)
{
	struct local_provider_data *data = instance;

	if (!data)
		return AI_ERR_INVALID_ARG;

	/*
	 * 这里只做配置校验，不做 TCP 探测：
	 * 本地服务可能尚未启动（Ollama/llama.cpp 按需启动），
	 * 若在 connect 阶段探测失败会把 provider 置为 ERROR 态，
	 * 之后即使服务拉起也无法恢复。可达性由
	 * `model test local` 与聊天时的明确报错负责。
	 */
	if (!data->base_url || !data->base_url[0] ||
	    !data->model_name || !data->model_name[0])
		return AI_ERR_CONFIG;

	data->connected = 1;
	return AI_OK;
}

static int local_chat(void *instance, const char *prompt, char **response)
{
	struct local_provider_data *data = instance;
	char *err_msg = NULL;
	int ret;

	if (!data || !prompt || !response)
		return AI_ERR_INVALID_ARG;

	if (!data->connected)
		return AI_ERR_NO_PROVIDER;

	ret = local_chat_complete(data->base_url, data->model_name,
				  data->api_key, prompt,
				  0,  /* max_tokens：走默认（[ui].max_tokens
				       * 由 Communication 层请求级参数传递，
				       * 此 Provider 遗留路径用默认 4096） */
				  response, &err_msg, NULL);
	if (ret != AI_OK) {
		/* 与云端 openai_chat 一致：在此打印错误细节 */
		if (err_msg) {
			printf("Error: %s\n", err_msg);
			free(err_msg);
		}
		return ret;
	}

	return AI_OK;
}

/* ---- 真流式（与 local_stream.c 同一实现，无双轨桩） ----
 * 受 CONFIG_AI_STREAM_MODE 门控：未编入流式时 ops.stream 为 NULL、
 * capabilities 不标 CAP_STREAM（local_stream.c 不参与链接）。 */

#ifdef CONFIG_AI_STREAM_MODE

/*
 * local_stream_ctx - on_token(NUL 结尾串约定) 适配上下文
 * local_chat_stream_messages 的增量回调是 (ud, delta, len)，
 * provider ops.stream 的回调约定是 (token, ud)，此处包装。
 */
struct local_stream_ctx {
	void (*on_token)(const char *token, void *user_data);
	void *user_data;
};

static void local_stream_on_delta(void *ud, const char *delta, size_t len)
{
	struct local_stream_ctx *c = ud;
	char *tok;

	tok = malloc(len + 1);
	if (!tok)
		return;
	memcpy(tok, delta, len);
	tok[len] = '\0';
	c->on_token(tok, c->user_data);
	free(tok);
}

/*
 * local_stream - 单 prompt 流式聊天（真实现）
 * 接到 local_chat_stream_messages（Ollama NDJSON / OpenAI SSE 双协议，
 * 与 Communication 层 local_backend 走的是同一条真流式路径），
 * 原 AI_ERR_NOT_IMPLEMENTED 死桩已删除。
 */
static int local_stream(void *instance, const char *prompt,
			void (*on_token)(const char *token, void *user_data),
			void *user_data)
{
	struct local_provider_data *data = instance;
	struct local_stream_ctx ctx;
	struct ai_chat_msg msg;
	struct ai_chat_result *result = NULL;
	char *err_msg = NULL;
	int ret;

	if (!data || !prompt || !on_token)
		return AI_ERR_INVALID_ARG;

	if (!data->connected)
		return AI_ERR_NO_PROVIDER;
	if (!data->base_url || !data->model_name)
		return AI_ERR_CONFIG;

	memset(&msg, 0, sizeof(msg));
	msg.role = "user";
	msg.content = prompt;

	ctx.on_token = on_token;
	ctx.user_data = user_data;

	/* tools_json=NULL、max_tokens<=0（默认）、num_ctx=0（不传）、
	 * native=0（OpenAI 兼容 /v1，本 Provider 的协议约定） */
	ret = local_chat_stream_messages(data->base_url, data->model_name,
					 data->api_key, &msg, 1, NULL,
					 0, 0, 0,
					 local_stream_on_delta, &ctx,
					 &result, &err_msg, NULL);
	if (err_msg) {
		/* 与 local_chat 直连兜底路径一致：打印错误细节 */
		printf("Error: %s\n", err_msg);
		free(err_msg);
	}
	if (result)
		ai_chat_result_free(result);
	return ret;
}

#endif /* CONFIG_AI_STREAM_MODE */

static int local_status(void *instance)
{
	struct local_provider_data *data = instance;

	if (!data)
		return AI_PROVIDER_UNINITIALIZED;

	return data->connected ?
		AI_PROVIDER_READY : AI_PROVIDER_DISCONNECTED;
}

static void local_close(void *instance)
{
	struct local_provider_data *data = instance;

	if (!data)
		return;

	data->connected = 0;
	free(data->base_url);
	free(data->model_name);
	free(data->api_key);
	data->base_url = NULL;
	data->model_name = NULL;
	data->api_key = NULL;
	/* 注意：data 本身由注册中心 free（见 provider_core.c） */
}

/* ---- Provider 工厂函数 ---- */

struct ai_provider *local_provider_create(void)
{
	struct ai_provider *provider;
	struct local_provider_data *data;

	provider = calloc(1, sizeof(*provider));
	if (!provider)
		return NULL;

	data = calloc(1, sizeof(*data));
	if (!data) {
		free(provider);
		return NULL;
	}
	data->timeout_ms = LOCAL_PROVIDER_DEFAULT_TIMEOUT_MS;

	provider->name = "local";
	provider->display_name = "Local AI Provider (OpenAI Compatible)";
	provider->type = AI_PROVIDER_LOCAL;
#ifdef CONFIG_AI_STREAM_MODE
	/* CAP_STREAM 名副其实：local_stream 经 local_chat_stream_messages
	 * 真流式（与 local_backend 同一实现），原死桩已删除 */
	provider->capabilities = AI_PROVIDER_CAP_CHAT | AI_PROVIDER_CAP_STREAM;
#else
	provider->capabilities = AI_PROVIDER_CAP_CHAT;
#endif
	provider->instance = data;
	provider->state = AI_PROVIDER_UNINITIALIZED;

#ifdef CONFIG_AI_STREAM_MODE
	/* ops 每个函数指针均为真实现（流式经 local_stream.c 双协议路径） */
	provider->ops.stream = local_stream;
#else
	provider->ops.stream = NULL;    /* 流式未编入，绝不虚标 */
#endif
	provider->ops.init = local_init;
	provider->ops.connect = local_connect;
	provider->ops.chat = local_chat;
	provider->ops.status = local_status;
	provider->ops.close = local_close;

	return provider;
}

/*
 * local_provider_configure - 配置本地 Provider 的运行参数
 *
 * 与 openai_provider_configure 同为"名称约定"配置入口
 * （不是 ops 虚接口），由 `model use local` 在切换时调用，
 * 保证 [local] 段的最新值立即生效。
 */
void local_provider_configure(struct ai_provider *provider,
			      const char *model_name,
			      const char *base_url,
			      const char *api_key,
			      int timeout_ms)
{
	struct local_provider_data *data;

	if (!provider || !provider->instance)
		return;

	data = provider->instance;

	free(data->model_name);
	free(data->base_url);
	free(data->api_key);

	data->model_name = model_name ? strdup(model_name) : NULL;
	data->base_url = base_url ? strdup(base_url) : NULL;
	data->api_key = api_key ? strdup(api_key) : NULL;

	if (timeout_ms > 0) {
		data->timeout_ms = timeout_ms;
		local_chat_set_timeout(timeout_ms);
	} else {
		data->timeout_ms = LOCAL_PROVIDER_DEFAULT_TIMEOUT_MS;
		local_chat_set_timeout(LOCAL_PROVIDER_DEFAULT_TIMEOUT_MS);
	}
}
