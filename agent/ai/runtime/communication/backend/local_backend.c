// SPDX-License-Identifier: GPL-2.0
/*
 * local_backend.c - Local Backend 实现
 *
 * 取代原桩实现（其 send 返回 AI_ERR_NOT_IMPLEMENTED）。
 * Communication Layer 根据 provider_type == "local" 路由到本 Backend，
 * 是 `ai_runtime_chat()` 在本地模式下的实际数据路径
 * （Provider 层的 local provider 只负责注册中心生命周期管理）。
 *
 * UI Phase 双协议（[ui].local_api 请求级开关，Runtime 填充）：
 *   native（默认）：Ollama 原生 /api/chat —— 唯一支持 options.num_ctx
 *     的通道（长上下文不静默截断），见 local/ollama_native.c；
 *   v1：OpenAI 兼容 {base_url}/chat/completions（base_url 已含 /v1），
 *     兼容 llama.cpp server / LM Studio 等非 Ollama 服务。
 *   纯 HTTP 不带 TLS；max_tokens / num_ctx 均为请求级参数。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "backend.h"
#include "communication/communication.h"
#include "local/local_chat.h"
#include "local/ollama_native.h"

/* ---- Local Backend 接口 ---- */

static int local_backend_send(const struct comm_request *req,
                  struct comm_response *resp)
{
    int ret;

    if (!req || !resp)
        return AI_ERR_INVALID_ARG;

    memset(resp, 0, sizeof(*resp));

    /* 本地服务无需认证：api_key 为空是合法的（不发 Authorization） */
    /* 环境变量覆盖（测试/mock 场景）：AIKERNEL_LLM_URL 优先于 model.toml。
     * req 为 const，覆盖仅作用于本函数局部副本指针。 */
    char url_buf[512];
    struct comm_request local_req;
    const char *env_url = getenv("AIKERNEL_LLM_URL");
    if (env_url && env_url[0] && req->base_url &&
        strlen(env_url) < sizeof(url_buf)) {
        snprintf(url_buf, sizeof(url_buf), "%s", env_url);
        local_req = *req;           /* 值拷贝，解除 const 限制 */
        local_req.base_url = url_buf;
        req = &local_req;
    }
    if (!req->base_url || !req->model_name) {
        resp->error = AI_ERR_CONFIG;
        resp->error_message = strdup("local.base_url / local.model "
                         "is not configured");
        return AI_ERR_CONFIG;
    }

    /* Ask 工具调用闭环：messages 模式（优先），响应解析出
     * content + tool_calls，供 cmd_ask 执行器消费 */
    if (req->messages && req->msg_count > 0) {
        /* 流式优先（UI Phase）：delta.content 逐段回调交付；
         * 流式请求失败（连接/HTTP 4xx/5xx）时自动回退非流式，
         * 保持既有逻辑为兜底（[ui].stream=off 直接走非流式）。
         * 流式受 CONFIG_AI_STREAM_MODE 编译开关门控（Kconfig
         * AIKERNEL_STREAM_MODE，见 Makefile）：未编入时恒走非流式 */
#ifdef CONFIG_AI_STREAM_MODE
        if (req->stream && req->on_delta) {
            ret = local_chat_stream_messages(req->base_url,
                          req->model_name, req->api_key,
                          req->messages, req->msg_count,
                          req->tools_json,
                          req->max_tokens, req->num_ctx,
                          req->local_native,
                          req->on_delta, req->on_delta_ud,
                          &resp->chat, &resp->error_message,
                          &resp->status_code);
            if (ret == AI_OK && resp->chat) {
                resp->error = AI_OK;
                return AI_OK;
            }
            /* 回退：清理流式尝试的残留 */
            free(resp->error_message);
            resp->error_message = NULL;
            resp->status_code = 0;
        }
#endif

        if (req->local_native) {
            /* 原生 /api/chat：带 options.num_ctx（内部按模型上限钳制） */
            ret = ollama_native_chat(req->base_url, req->model_name,
                         req->api_key,
                         req->messages, req->msg_count,
                         req->tools_json,
                         req->max_tokens, req->num_ctx,
                         &resp->chat, &resp->error_message,
                         &resp->status_code);
        } else {
            ret = local_chat_messages_complete(req->base_url,
                           req->model_name, req->api_key,
                           req->messages, req->msg_count,
                           req->tools_json,
                           req->max_tokens,
                           &resp->chat, &resp->error_message,
                           &resp->status_code);
        }
        resp->error = (ret == AI_OK) ? AI_OK : ret;
        return ret;
    }

    if (!req->prompt) {
        resp->error = AI_ERR_INVALID_ARG;
        return AI_ERR_INVALID_ARG;
    }

    ret = local_chat_complete(req->base_url, req->model_name,
                  req->api_key, req->prompt,
                  req->max_tokens,
                  &resp->body, &resp->error_message,
                  &resp->status_code);

    resp->error = (ret == AI_OK) ? AI_OK : ret;
    return ret;
}

static int local_backend_test(const char *host)
{
    char *err = NULL;
    int ret;

    if (!host)
        return AI_ERR_INVALID_ARG;

    /* 与 cloud_backend_test 一致：只返回结果，不打印细节 */
    ret = local_chat_probe_endpoint(host, &err);
    free(err);
    return ret;
}

static int local_backend_init(void)
{
    /* local_chat 模块按需建连，无全局上下文需要初始化 */
    return AI_OK;
}

static void local_backend_cleanup(void)
{
}

static const struct backend_ops g_local_backend = {
    .init    = local_backend_init,
    .send    = local_backend_send,
    .test    = local_backend_test,
    .cleanup = local_backend_cleanup,
    .name    = "local",
};

void local_backend_register(void)
{
    extern void backend_register(const struct backend_ops *ops);

    backend_register(&g_local_backend);
}
