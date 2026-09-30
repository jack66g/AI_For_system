/*
 * cloud_backend.c - Cloud Backend 实现
 *
 * 负责：
 *   - 通过 HTTPS Client 发送 API 请求
 *   - 构建 OpenAI Compatible 格式的 JSON 请求体
 *   - 解析 JSON 响应提取 content
 *   - 统一错误处理
 *
 * 不直接暴露 HTTP 细节给 Runtime。
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "backend.h"
#include "communication/communication.h"
#include "http/http_client.h"
#include "ai_types.h"
#include "ai_stream.h"

/* max_tokens 缺省值（请求级参数 <=0 时使用；实际值来自 [ui].max_tokens） */
#define LOCAL_DEFAULT_MAX_TOKENS  4096

/* ---- 简易 JSON 值提取器 ---- */

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

/* ---- 构建 OpenAI Compatible 请求 ---- */

static char *build_request_json(const char *model_name, const char *prompt)
{
    const char *tmpl =
        "{"
        "\"model\":\"%s\","
        "\"messages\":["
        "{\"role\":\"user\",\"content\":\"%s\"}"
        "],"
        "\"stream\":false,"
        "\"temperature\":0.7,"
        "\"max_tokens\":4096"
        "}";

    size_t plen = strlen(prompt);
    char *escaped = malloc(plen * 2 + 1);
    char *d;
    const char *s;

    if (!escaped)
        return NULL;

    d = escaped;
    for (s = prompt; *s; s++) {
        switch (*s) {
        case '"':  *d++ = '\\'; *d++ = '"'; break;
        case '\\': *d++ = '\\'; *d++ = '\\'; break;
        case '\n': *d++ = '\\'; *d++ = 'n'; break;
        case '\t': *d++ = '\\'; *d++ = 't'; break;
        default:   *d++ = *s; break;
        }
    }
    *d = '\0';

    size_t tlen = strlen(tmpl) + strlen(model_name) + strlen(escaped) + 1;
    char *json = malloc(tlen);
    if (json)
        snprintf(json, tlen, tmpl, model_name, escaped);

    free(escaped);
    return json;
}

/* ---- Cloud Backend 接口 ---- */

#ifdef CONFIG_AI_STREAM_MODE
/*
 * SSE 真增量流式上下文：
 * https_post_stream 每收到一段（chunked 解码后的）响应体就回调
 * sse_stream_on_data 一次 → 立即喂给流式聚合器（delta.content 一到
 * 就经 req->on_delta 交付输出，不等整个响应收完）；
 * 同时保留全量缓冲，用于：服务器忽略 stream:true 时的非流式兜底
 * 解析、HTTP 错误响应的错误信息提取。
 */
struct sse_stream_ctx {
    struct ai_stream_agg *agg;
    ai_stream_delta_cb cb;
    void *ud;
    char *body;
    size_t body_len;
    size_t body_cap;
};

static void sse_stream_on_data(void *ud, const char *data, size_t len)
{
    struct sse_stream_ctx *c = ud;

    if (c->body) {
        if (c->body_len + len + 1 > c->body_cap) {
            size_t ncap = c->body_cap ? c->body_cap : 8192;
            char *nb;

            while (ncap < c->body_len + len + 1)
                ncap *= 2;
            nb = realloc(c->body, ncap);
            if (!nb) {
                free(c->body);
                c->body = NULL;     /* 缓冲失败不影响增量交付 */
            } else {
                c->body = nb;
                c->body_cap = ncap;
            }
        }
        if (c->body) {
            memcpy(c->body + c->body_len, data, len);
            c->body_len += len;
            c->body[c->body_len] = '\0';
        }
    }
    if (c->agg)
        ai_stream_agg_feed(c->agg, data, len, c->cb, c->ud);
}

static void sse_ctx_free(struct sse_stream_ctx *c)
{
    if (c->agg)
        ai_stream_agg_free(c->agg);
    free(c->body);
    memset(c, 0, sizeof(*c));
}
#else  /* !CONFIG_AI_STREAM_MODE：无流式机制，sctx 恒空，释放为空操作 */
struct sse_stream_ctx {
    char unused_;
};

static void sse_ctx_free(struct sse_stream_ctx *c)
{
    (void)c;
}
#endif /* CONFIG_AI_STREAM_MODE */

static int cloud_backend_send(const struct comm_request *req,
                              struct comm_response *resp)
{
    char full_url[1024];
    char *json_body = NULL;
    char *http_resp = NULL;
    char *error_msg = NULL;
    struct sse_stream_ctx sctx;
    int used_stream = 0;
    int http_status = 0;
    int stream_mode;
    int ret;

    if (!req || !resp)
        return AI_ERR_INVALID_ARG;

    memset(resp, 0, sizeof(*resp));
    memset(&sctx, 0, sizeof(sctx));

    if (!req->base_url || !req->api_key || !req->model_name) {
        resp->error = AI_ERR_CONFIG;
        return AI_ERR_CONFIG;
    }

    /* UI Phase：stream=1 且带增量回调时请求 SSE 流
     * （https_post_stream 逐段交付，delta 到达即回调——真增量流式；
     *   流式受 CONFIG_AI_STREAM_MODE 编译开关门控，未编入时恒走
     *   整体缓冲非流式） */
#ifdef CONFIG_AI_STREAM_MODE
    stream_mode = req->stream && req->on_delta && req->messages &&
                  req->msg_count > 0;
#else
    stream_mode = 0;
#endif

    if (req->messages && req->msg_count > 0) {
        /* Ask 工具调用闭环：messages 数组模式（与 local backend 同一
         * 构造器/解析器 ai_chat_proto，保证两条通道行为一致）。
         * max_tokens 来自 [ui] 配置（请求级参数，<=0 取默认 4096） */
        json_body = ai_chat_build_request_json_ex(req->model_name,
                                               req->messages,
                                               req->msg_count,
                                               req->tools_json,
                                               0.7,
                                               req->max_tokens > 0 ?
                                               req->max_tokens :
                                               LOCAL_DEFAULT_MAX_TOKENS,
                                               stream_mode);
    } else {
        if (!req->prompt) {
            resp->error = AI_ERR_INVALID_ARG;
            return AI_ERR_INVALID_ARG;
        }
        json_body = build_request_json(req->model_name, req->prompt);
    }
    if (!json_body) {
        resp->error = AI_ERR_MEMORY;
        return AI_ERR_MEMORY;
    }

    /* 构建完整 URL */
    snprintf(full_url, sizeof(full_url), "%s/chat/completions",
             req->base_url);

    /* 通过 HTTPS Client 发送：流式走增量读取，非流式整体缓冲 */
#ifdef CONFIG_AI_STREAM_MODE
    if (stream_mode) {
        sctx.agg = ai_stream_agg_create();
        sctx.cb = req->on_delta;
        sctx.ud = req->on_delta_ud;
        sctx.body_cap = 16384;
        sctx.body = malloc(sctx.body_cap);
        if (sctx.body)
            sctx.body[0] = '\0';
        if (!sctx.agg) {
            free(json_body);
            sse_ctx_free(&sctx);
            resp->error = AI_ERR_MEMORY;
            return AI_ERR_MEMORY;
        }
        ret = https_post_stream(full_url, req->api_key, json_body,
                                sse_stream_on_data, &sctx,
                                &http_status, &error_msg);
        used_stream = 1;
    } else
#endif
    {
        ret = https_post(full_url, req->api_key, json_body,
                         &http_resp, &error_msg);
    }
    free(json_body);

    if (ret != 0) {
        resp->error = AI_ERR_NETWORK;
        if (error_msg) {
            resp->error_message = strdup(error_msg);
            free(error_msg);
        }
        sse_ctx_free(&sctx);
        return AI_ERR_NETWORK;
    }

    /* 响应体统一视图：非流式 = http_resp；流式 = sctx.body（全量缓冲，
     * 仅用于错误诊断与非流式兜底，增量输出已在接收过程中完成） */
    {
#ifdef CONFIG_AI_STREAM_MODE
        const char *resp_body = used_stream ?
                                (sctx.body ? sctx.body : "") :
                                (http_resp ? http_resp : "");
#else
        const char *resp_body = http_resp ? http_resp : "";
#endif

        /* 解析响应：API 错误（流式叠加 HTTP 状态码检查） */
        if ((strstr(resp_body, "\"error\"") &&
             strstr(resp_body, "\"message\"")) ||
            (used_stream && http_status >= 400)) {
            char *err_msg = json_get_str(resp_body, "message");

            if (err_msg) {
                resp->error_message = err_msg;
            } else if (used_stream && http_status >= 400) {
                char buf[64];

                snprintf(buf, sizeof(buf), "HTTP status %d", http_status);
                resp->error_message = strdup(buf);
            }

            {
                int is_auth = (strstr(resp_body, "401") ||
                               strstr(resp_body, "auth") ||
                               strstr(resp_body, "Authentication"));

                resp->error = is_auth ? AI_ERR_AUTH : AI_ERR_API;
            }
            free(http_resp);
            sse_ctx_free(&sctx);
            return resp->error;
        }

        if (req->messages && req->msg_count > 0) {
            /* messages 模式：解析出 content + tool_calls */
            resp->chat = malloc(sizeof(*resp->chat));
            if (!resp->chat) {
                free(http_resp);
                sse_ctx_free(&sctx);
                resp->error = AI_ERR_MEMORY;
                return AI_ERR_MEMORY;
            }
            memset(resp->chat, 0, sizeof(*resp->chat));

            if (used_stream) {
#ifdef CONFIG_AI_STREAM_MODE
                if (strstr(resp_body, "data:")) {
                    /* SSE 流：增量已实时交付，此处导出聚合结果 */
                    ret = ai_stream_agg_finish(sctx.agg, resp->chat);
                } else {
                    /* 服务器忽略 stream:true 返回整体 JSON → 按非流式解析 */
                    ret = ai_chat_parse_response(resp_body, resp->chat);
                }
#endif
            } else {
                ret = ai_chat_parse_response(http_resp, resp->chat);
            }
            if (ret != AI_OK) {
                if (resp->chat->finish_reason && !resp->error_message) {
                    resp->error_message = resp->chat->finish_reason;
                    resp->chat->finish_reason = NULL;
                }
                ai_chat_result_free(resp->chat);
                free(resp->chat);
                resp->chat = NULL;
                resp->error = ret;
            }
            free(http_resp);
            sse_ctx_free(&sctx);
            return ret;
        }

        resp->body = json_get_str(resp_body, "content");
        free(http_resp);
        sse_ctx_free(&sctx);

        if (!resp->body) {
            resp->error = AI_ERR_API;
            return AI_ERR_API;
        }

        resp->error = AI_OK;
        return AI_OK;
    }
}

static int cloud_backend_test(const char *host)
{
    char *resp = NULL;
    char *err = NULL;
    char url[512];
    int ret;

    if (!host)
        return AI_ERR_INVALID_ARG;

    snprintf(url, sizeof(url), "https://%s/", host);

    ret = https_get(url, &resp, &err);
    free(resp);
    free(err);

    return (ret == 0) ? AI_OK : AI_ERR_NETWORK;
}

static int cloud_backend_init(void)
{
    https_init();
    return AI_OK;
}

static void cloud_backend_cleanup(void)
{
    https_cleanup();
}

static const struct backend_ops g_cloud_backend = {
    .init    = cloud_backend_init,
    .send    = cloud_backend_send,
    .test    = cloud_backend_test,
    .cleanup = cloud_backend_cleanup,
    .name    = "cloud",
};

void cloud_backend_register(void)
{
    extern void backend_register(const struct backend_ops *ops);
    backend_register(&g_cloud_backend);
}
