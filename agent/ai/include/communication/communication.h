/*
 * communication.h - AIKernel Communication Layer 统一接口
 *
 * Runtime 永远只调用 communication_send()，不直接调用 Cloud Provider。
 * Communication Layer 负责：
 *   - 根据 Provider 类型路由到对应 Backend
 *   - 统一错误处理
 *   - 请求/响应格式标准化
 *
 * 架构：
 *   AI Shell → Runtime → communication_send() → Backend → HTTPS Client → mbedTLS → Socket → Kernel TCP/IP
 */

#ifndef _AI_COMMUNICATION_H
#define _AI_COMMUNICATION_H

#include "ai_types.h"
#include "ai_chat.h"

/* ---- 通信请求 ---- */

struct comm_request {
    const char *provider_type;   /* 如 "openai_compatible", "local" */
    const char *model_name;      /* 模型名 */
    const char *base_url;        /* API Base URL */
    const char *api_key;         /* API Key */
    const char *prompt;          /* 用户输入（单消息模式） */
    /* ---- Ask 工具调用闭环扩展（messages 模式，与 prompt 二选一） ----
     * messages 非空时优先走 messages 路径：请求体带完整消息数组，
     * 可选携带 tools 数组，响应解析出 content + tool_calls。 */
    const struct ai_chat_msg *messages;  /* 消息数组 */
    int msg_count;                       /* 消息条数 */
    const char *tools_json;              /* OpenAI tools 数组 JSON（可 NULL） */
    /* ---- UI Phase：请求级参数（来自 model.toml [ui]，Runtime 填充） ----
     * max_tokens：单次生成上限（<=0 时后端用内置默认 4096）；
     * num_ctx：上下文 token 预算（本地原生通道 options.num_ctx）；
     * stream：1=请求流式输出；
     * local_native：1=Ollama 原生 /api/chat，0=OpenAI 兼容 /v1。 */
    int max_tokens;
    int num_ctx;
    int stream;
    int local_native;
    /* ---- 流式增量回调（stream=1 时后端逐段交付 delta.content） ----
     * on_delta 为空时即使 stream=1 也走一次性返回路径。 */
    void (*on_delta)(void *ud, const char *delta, size_t len);
    void *on_delta_ud;
};

/* ---- 通信响应 ---- */

struct comm_response {
    char *body;                  /* 响应体（单消息模式，调用者需 free） */
    int status_code;             /* HTTP 状态码 */
    int error;                   /* ai_error 错误码 */
    char *error_message;         /* 错误信息（调用者需 free） */
    /* ---- messages 模式响应 ---- */
    struct ai_chat_result *chat; /* 解析结果（调用者 ai_chat_result_free） */
};

/*
 * communication_init - 初始化通信层
 * 包括 TLS 全局上下文、证书管理器等。
 * 返回: AI_OK 成功
 */
int communication_init(void);

/*
 * communication_send - 发送 AI 请求
 * @req: 请求参数
 * @resp: 输出参数，响应数据（调用者需处理）
 * 返回: AI_OK 成功，AI_ERR_* 失败
 *
 * 这是 Runtime 唯一应该调用的通信接口。
 */
int communication_send(const struct comm_request *req, struct comm_response *resp);

/*
 * communication_test - 网络连通性测试
 * @host: 目标主机（如 "api.deepseek.com"）
 * 返回: AI_OK 成功，AI_ERR_NETWORK 失败
 */
int communication_test(const char *host);

/*
 * communication_cleanup - 清理通信层资源
 */
void communication_cleanup(void);

#endif /* _AI_COMMUNICATION_H */
