/*
 * communication.c - Communication Layer 核心实现
 *
 * 统一 AI 通信入口。Runtime 只调用 communication_send()。
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "communication.h"
#include "backend/backend.h"

static int g_initialized = 0;

int communication_init(void)
{
    if (g_initialized)
        return AI_OK;

    backend_register_all();
    g_initialized = 1;
    return AI_OK;
}

int communication_send(const struct comm_request *req,
                       struct comm_response *resp)
{
    const struct backend_ops *backend;

    if (!req || !resp)
        return AI_ERR_INVALID_ARG;

    memset(resp, 0, sizeof(*resp));

    if (!g_initialized) {
        resp->error = AI_ERR_NO_PROVIDER;
        return AI_ERR_NO_PROVIDER;
    }

    /* 根据 provider_type 路由到对应 Backend */
    backend = backend_find(req->provider_type);
    if (!backend) {
        resp->error = AI_ERR_NO_PROVIDER;
        resp->error_message = strdup("Unknown provider type");
        return AI_ERR_NO_PROVIDER;
    }

    /* 通过 Backend 发送 */
    return backend->send(req, resp);
}

int communication_test(const char *host)
{
    const struct backend_ops *backend;

    if (!host)
        return AI_ERR_INVALID_ARG;

    if (!g_initialized)
        return AI_ERR_NO_PROVIDER;

    /* 使用 cloud backend 进行网络测试 */
    backend = backend_find("openai_compatible");
    if (!backend || !backend->test)
        return AI_ERR_NO_PROVIDER;

    return backend->test(host);
}

void communication_cleanup(void)
{
    if (!g_initialized)
        return;

    g_initialized = 0;
}
