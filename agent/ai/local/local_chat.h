// SPDX-License-Identifier: GPL-2.0
/*
 * local_chat.h - 本地 AI 聊天客户端接口（OpenAI Chat Completions 兼容）
 *
 * 供两层共用（与 cloud 侧 provider/backend 的分工对齐）：
 *   - agent/ai/local/provider_local.c     （Provider 注册中心层 ops.chat）
 *   - runtime/communication/backend/local_backend.c（Communication 层数据路径）
 *
 * 端点协议：POST {base_url}/chat/completions
 *   base_url 默认已含 /v1（如 http://127.0.0.1:11434/v1），
 *   兼容 Ollama(11434)/llama.cpp server(8080)/LM Studio(1234) 等。
 */
#ifndef _AI_LOCAL_CHAT_H
#define _AI_LOCAL_CHAT_H

#include "ai_chat.h"
#include "ai_stream.h"

/* max_tokens 缺省值（请求级参数 <=0 时使用；实际值来自 [ui].max_tokens） */
#define LOCAL_CHAT_DEFAULT_MAX_TOKENS  4096

/*
 * local_chat_stream_messages - 流式 messages 模式聊天（SSE/NDJSON）
 * @native: 1=Ollama 原生 /api/chat（NDJSON），0=OpenAI 兼容 /v1（SSE）
 * @cb/ud:  delta.content 逐段回调（实时打印；必填）
 * @result: 输出，聚合完成的完整结果（与非流式同构）
 * 返回: AI_OK 成功；AI_ERR_* 失败（未产生输出，调用方可回退非流式）
 */
int local_chat_stream_messages(const char *base_url, const char *model_name,
			       const char *api_key,
			       const struct ai_chat_msg *msgs, int nmsgs,
			       const char *tools_json,
			       int max_tokens, int num_ctx, int native,
			       ai_stream_delta_cb cb, void *ud,
			       struct ai_chat_result **result,
			       char **error_message, int *http_status);

/*
 * local_chat_complete - 发送一次非流式聊天请求
 * @base_url:      本地服务 Base URL（如 http://127.0.0.1:11434/v1）
 * @model_name:    模型名（如 llama3）
 * @api_key:       可选 Bearer 令牌；NULL 或空串时不发送 Authorization
 * @prompt:        用户输入（内部做 JSON 转义）
 * @max_tokens:    单次生成上限（<=0 取 LOCAL_CHAT_DEFAULT_MAX_TOKENS）
 * @response:      输出参数，AI 回复文本（调用者需 free）
 * @error_message: 输出参数，失败原因（调用者需 free），成功时为 NULL
 * @http_status:   输出参数，HTTP 状态码（可为 NULL）
 * 返回: AI_OK 成功，AI_ERR_* 失败
 */
int local_chat_complete(const char *base_url, const char *model_name,
			const char *api_key, const char *prompt,
			int max_tokens,
			char **response, char **error_message,
			int *http_status);

/*
 * local_chat_messages_complete - 发送一次 messages 数组模式的聊天请求
 * （Ask 工具调用闭环使用：请求体含完整消息数组与可选 tools 数组，
 * 响应解析出 content + tool_calls，见 include/ai_chat.h）
 * @base_url:      本地服务 Base URL（如 http://127.0.0.1:11434/v1）
 * @model_name:    模型名
 * @api_key:       可选 Bearer 令牌
 * @msgs:          消息数组（system/user/assistant/tool）
 * @nmsgs:         消息条数
 * @tools_json:    OpenAI tools 数组 JSON（可 NULL）
 * @max_tokens:    单次生成上限（<=0 取默认）
 * @result:        输出参数，解析结果（调用者 ai_chat_result_free）
 * @error_message: 输出参数，失败原因（调用者需 free），成功时为 NULL
 * @http_status:   输出参数，HTTP 状态码（可为 NULL）
 * 返回: AI_OK 成功，AI_ERR_* 失败
 */
int local_chat_messages_complete(const char *base_url, const char *model_name,
				 const char *api_key,
				 const struct ai_chat_msg *msgs, int nmsgs,
				 const char *tools_json,
				 int max_tokens,
				 struct ai_chat_result **result,
				 char **error_message, int *http_status);

/*
 * local_chat_probe_endpoint - 探测本地服务 TCP 可达性
 * @base_url:      http://host:port/... 或裸 host[:port]
 * @error_message: 输出参数，失败原因（含可操作提示，调用者需 free）
 * 返回: AI_OK 可达，AI_ERR_NETWORK 不可达
 */
int local_chat_probe_endpoint(const char *base_url, char **error_message);

/*
 * local_chat_set_timeout - 设置请求超时（毫秒）
 * 供 provider init 与 `model use local` 切换时应用 [local].timeout_ms。
 */
void local_chat_set_timeout(int timeout_ms);

/* local_chat_get_timeout - 读取当前超时（毫秒） */
int local_chat_get_timeout(void);

#endif /* _AI_LOCAL_CHAT_H */
