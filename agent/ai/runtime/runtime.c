/*
 * runtime.c - AI Runtime 核心实现
 *
 * 负责 Session 管理、Provider 调度、聊天流程控制。
 * 不直接依赖任何具体 Provider 实现。
 *
 * Phase 4: chat 请求通过 Communication Layer 发送，
 * 不再直接调用 Provider->ops.chat()。
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_runtime.h"
#include "ai_config.h"
#include "communication/communication.h"

/* 前向声明 cloud provider 的配置函数（保留用于 Provider 注册） */
struct ai_provider *openai_compatible_provider_create(void);
void openai_provider_configure(struct ai_provider *provider,
			       const char *model_name,
			       const char *base_url,
			       const char *api_key);

int ai_runtime_init(struct ai_runtime *rt, struct ai_config *cfg,
		    struct ai_provider_registry *reg)
{
	if (!rt || !cfg)
		return AI_ERR_INVALID_ARG;

	rt->state = AI_SESSION_IDLE;
	rt->config = cfg;
	rt->registry = reg;
	rt->provider = NULL;
	rt->current_model = NULL;
	rt->model_provider_type = NULL;
	rt->model_name = NULL;
	rt->model_base_url = NULL;
	rt->model_api_key = NULL;
	rt->token_used = 0;
	rt->token_limit = 0;
	rt->token_last_in = 0;
	rt->token_last_out = 0;
	rt->token_session_in = 0;
	rt->token_session_out = 0;
	rt->usage_is_real = 0;

	/* 初始化通信层 */
	communication_init();

	return AI_OK;
}

int ai_runtime_set_model(struct ai_runtime *rt, const char *model_name)
{
	char *provider_type = NULL;
	char *api_model_name = NULL;
	char *base_url = NULL;
	char *api_key = NULL;
	int ret;

	if (!rt || !model_name)
		return AI_ERR_INVALID_ARG;

	/* 从配置获取模型信息 */
	ret = ai_config_get_model(rt->config, model_name,
				  &provider_type, &api_model_name,
				  &base_url, &api_key);
	if (ret != AI_OK)
		return ret;

	/* 查找对应的 Provider */
	struct ai_provider *provider = ai_provider_find(rt->registry,
							provider_type);
	if (!provider) {
		ret = AI_ERR_NO_PROVIDER;
		goto out;
	}

	/* 初始化 Provider 实例（如果尚未初始化） */
	if (provider->state == AI_PROVIDER_UNINITIALIZED) {
		ret = provider->ops.init(provider->instance, rt->config);
		if (ret != AI_OK)
			goto out;
		provider->state = AI_PROVIDER_DISCONNECTED;
	}

	/*
	 * 配置 Provider 的模型参数。
	 * 通过名称约定调用 configure 函数（不是 Provider 虚接口）。
	 * 云 provider 未编入时无此 configure 入口（注册表里也没有
	 * openai_compatible，find 已在上一步失败）。
	 */
	if (strcmp(provider_type, "openai_compatible") == 0) {
#ifdef CONFIG_AI_CLOUD_PROVIDER
		openai_provider_configure(provider, api_model_name,
					  base_url, api_key);
#endif
	}

	/* 建立连接 */
	ret = provider->ops.connect(provider->instance);
	if (ret != AI_OK) {
		provider->state = AI_PROVIDER_ERROR;
		goto out;
	}
	provider->state = AI_PROVIDER_READY;

	/* 更新 Runtime 状态 */
	free(rt->current_model);
	rt->current_model = strdup(model_name);
	rt->provider = provider;

	/* Phase 4: 缓存模型配置供 Communication Layer 使用 */
	free(rt->model_provider_type);
	free(rt->model_name);
	free(rt->model_base_url);
	free(rt->model_api_key);
	rt->model_provider_type = strdup(provider_type);
	rt->model_name = strdup(api_model_name);
	rt->model_base_url = strdup(base_url);
	rt->model_api_key = strdup(api_key);

	ret = AI_OK;

out:
	free(provider_type);
	free(api_model_name);
	free(base_url);
	free(api_key);
	return ret;
}

enum ai_session_state ai_runtime_get_state(struct ai_runtime *rt)
{
	if (!rt)
		return AI_SESSION_ERROR;
	return rt->state;
}

int ai_runtime_chat(struct ai_runtime *rt, const char *message,
		    char **response)
{
	int ret;

	if (!rt || !message || !response)
		return AI_ERR_INVALID_ARG;

	if (!rt->provider) {
		const char *default_model;

		/* 尝试使用默认模型 */
		default_model = ai_config_get_default_model(rt->config);
		if (!default_model)
			return AI_ERR_NO_MODEL;

		ret = ai_runtime_set_model(rt, default_model);
		if (ret != AI_OK)
			return ret;
	}

	if (rt->provider->state != AI_PROVIDER_READY)
		return AI_ERR_NO_PROVIDER;

	/* Phase 4: 通过 Communication Layer 发送请求 */
	{
		struct comm_request req;
		struct comm_response resp;

		memset(&req, 0, sizeof(req));
		memset(&resp, 0, sizeof(resp));

		req.provider_type = rt->model_provider_type;
		req.model_name    = rt->model_name;
		req.base_url      = rt->model_base_url;
		req.api_key       = rt->model_api_key;
		req.prompt        = message;
		/* UI Phase：请求级参数（命令行 > 环境变量 > TOML 的最终权值）；
		 * stream 同样受 CONFIG_AI_STREAM_MODE 门控 */
		req.max_tokens    = rt->config->ui.max_tokens;
		req.num_ctx       = rt->config->ui.ctx_len;
#ifdef CONFIG_AI_STREAM_MODE
		req.stream        = rt->config->ui.stream;
#else
		req.stream        = 0;
#endif
		req.local_native  = rt->config->ui.local_native;

		rt->state = AI_SESSION_CHATTING;
		ret = communication_send(&req, &resp);
		rt->state = AI_SESSION_IDLE;

		if (ret == AI_OK && resp.body) {
			*response = resp.body;
		} else {
			*response = NULL;
			if (resp.error_message) {
				printf("Error: %s\n", resp.error_message);
				free(resp.error_message);
			}
		}
	}

	if (ret == AI_OK && *response) {
		/* usage 未知（单消息模式响应未解析 usage）→ 4 字符/token 粗估 */
		rt->token_last_in = strlen(message) / 4;
		rt->token_last_out = strlen(*response) / 4;
		rt->usage_is_real = 0;
		rt->token_used += rt->token_last_in + rt->token_last_out;
		rt->token_session_in += rt->token_last_in;
		rt->token_session_out += rt->token_last_out;
	}

	return ret;
}

int ai_runtime_chat_ex(struct ai_runtime *rt,
		       const struct ai_chat_msg *msgs, int nmsgs,
		       const char *tools_json,
		       ai_stream_delta_cb on_delta, void *on_delta_ud,
		       struct ai_chat_result **result)
{
	int ret;

	if (!rt || !msgs || nmsgs <= 0 || !result)
		return AI_ERR_INVALID_ARG;
	*result = NULL;

	if (!rt->provider) {
		const char *default_model;

		default_model = ai_config_get_default_model(rt->config);
		if (!default_model)
			return AI_ERR_NO_MODEL;

		ret = ai_runtime_set_model(rt, default_model);
		if (ret != AI_OK)
			return ret;
	}

	if (rt->provider->state != AI_PROVIDER_READY)
		return AI_ERR_NO_PROVIDER;

	/* 通过 Communication Layer 发送（messages 模式） */
	{
		struct comm_request req;
		struct comm_response resp;

		memset(&req, 0, sizeof(req));
		memset(&resp, 0, sizeof(resp));

		req.provider_type = rt->model_provider_type;
		req.model_name    = rt->model_name;
		req.base_url      = rt->model_base_url;
		req.api_key       = rt->model_api_key;
		req.messages      = msgs;
		req.msg_count     = nmsgs;
		req.tools_json    = tools_json;
		/* UI Phase：请求级参数（max_tokens/num_ctx/stream/协议开关）；
		 * stream 受 CONFIG_AI_STREAM_MODE 编译开关门控（Kconfig
		 * AIKERNEL_STREAM_MODE，见 agent/ai/Makefile）：未编入流式
		 * 时强制非流式，配置值不越权 */
		req.max_tokens    = rt->config->ui.max_tokens;
		req.num_ctx       = rt->config->ui.ctx_len;
#ifdef CONFIG_AI_STREAM_MODE
		req.stream        = rt->config->ui.stream;
#else
		req.stream        = 0;
#endif
		req.local_native  = rt->config->ui.local_native;
		req.on_delta      = on_delta;
		req.on_delta_ud   = on_delta_ud;

		rt->state = AI_SESSION_CHATTING;
		ret = communication_send(&req, &resp);
		rt->state = AI_SESSION_IDLE;

		if (ret == AI_OK && resp.chat) {
			*result = resp.chat;
		} else {
			if (resp.error_message) {
				printf("Error: %s\n", resp.error_message);
				free(resp.error_message);
			}
		}
	}

	if (ret == AI_OK && *result) {
		/* usage 真值优先（响应 usage 字段），缺失时按消息+回答
		 * 字符数 /4 粗估兜底；两者都进会话累计与预算显示 */
		int in = (*result)->prompt_tokens;
		int out = (*result)->completion_tokens;

		if (in <= 0 || out <= 0) {
			size_t chars = 0;
			int i;

			for (i = 0; i < nmsgs; i++)
				chars += msgs[i].content ?
					 strlen(msgs[i].content) : 0;
			if ((*result)->content)
				chars += strlen((*result)->content);
			if (in <= 0)
				in = (int)(chars / 4);
			if (out <= 0)
				out = (*result)->content ?
				      (int)(strlen((*result)->content) / 4) : 0;
			rt->usage_is_real = 0;
		} else {
			rt->usage_is_real = 1;
		}
		rt->token_last_in = in;
		rt->token_last_out = out;
		rt->token_used += in + out;
		rt->token_session_in += in;
		rt->token_session_out += out;
	}

	return ret;
}

int ai_runtime_get_token_usage(struct ai_runtime *rt, int *used, int *limit)
{
	if (!rt)
		return AI_ERR_INVALID_ARG;

	if (used)
		*used = rt->token_used;
	if (limit)
		*limit = rt->token_limit;

	return AI_OK;
}

void ai_runtime_destroy(struct ai_runtime *rt)
{
	if (!rt)
		return;

	free(rt->current_model);
	free(rt->model_provider_type);
	free(rt->model_name);
	free(rt->model_base_url);
	free(rt->model_api_key);
	rt->current_model = NULL;
	rt->model_provider_type = NULL;
	rt->model_name = NULL;
	rt->model_base_url = NULL;
	rt->model_api_key = NULL;
	rt->provider = NULL;
	rt->config = NULL;
	rt->registry = NULL;
	rt->state = AI_SESSION_IDLE;
}
