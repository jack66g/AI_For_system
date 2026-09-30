// SPDX-License-Identifier: GPL-2.0
/*
 * ollama_native.h - Ollama 原生 /api/chat 通道（num_ctx 上下文窗口治理）
 *
 * 为什么需要原生通道：Ollama 的 OpenAI 兼容端点（/v1）不认识
 * options.num_ctx，模型按编译期默认窗口（qwen2.5:1.5b 约 2k）静默
 * 截断长上下文；原生 /api/chat 才接受 options.num_ctx（按 GGUF
 * context_length 上限钳制）。UI Phase 起本地默认走本通道，
 * [ui].local_api = "v1" 可切回 OpenAI 兼容路径（local_chat.c）。
 *
 * 能力探测：POST /api/show {"model":...} → model_info."<arch>.
 * context_length"（如 qwen2.context_length: 32768）。探测结果按
 * (base_url, model) 缓存于进程内，num_ctx 与 config set ctx_len
 * 的钳制共用同一缓存。
 */
#ifndef _AI_OLLAMA_NATIVE_H
#define _AI_OLLAMA_NATIVE_H

#include "ai_chat.h"

/*
 * ollama_native_strip_v1 - 剥离 base_url 末尾的 "/v1"，得到服务根
 * （"http://127.0.0.1:11434/v1" -> "http://127.0.0.1:11434"）
 * @base_url: 输入（容忍末尾多余 '/'）
 * @out/len:  输出缓冲
 */
void ollama_native_strip_v1(const char *base_url, char *out, size_t len);

/*
 * ollama_native_ctx_cap - 查询模型上下文窗口上限（/api/show，带缓存）
 * @base_url: 服务根或含 /v1 的 base_url（内部先剥离）
 * @model:    模型名
 * @error:    输出参数，失败原因（调用者需 free，可为 NULL）
 * 返回: >0 上限 token 数；<=0 探测失败（调用方按"不钳制"处理）
 */
int ollama_native_ctx_cap(const char *base_url, const char *model,
			  char **error);

/*
 * ollama_native_build_body - 构造原生 /api/chat 请求体
 * @stream: 1=NDJSON 流式（"stream":true），0=一次性返回
 * 返回: malloc JSON（调用者需 free）；失败返回 NULL
 */
char *ollama_native_build_body(const char *model_name,
			       const struct ai_chat_msg *msgs, int nmsgs,
			       const char *tools_json,
			       int max_tokens, int num_ctx, int stream);

/*
 * ollama_native_chat - 原生 /api/chat 非流式请求（tools + num_ctx）
 * @base_url:   本地服务 base_url（含 /v1 亦可，内部剥离）
 * @model_name: 模型名
 * @api_key:    可选 Bearer（本机 Ollama 通常为空）
 * @msgs/nmsgs: 消息数组（ai_chat 通用结构，内部转原生格式）
 * @tools_json: OpenAI 风格 tools 数组（Ollama 原生同构，原样嵌入）
 * @max_tokens: 生成上限（原生 options.num_predict；<=0 不带）
 * @num_ctx:    上下文窗口（options.num_ctx；<=0 不带；超上限自动钳制）
 * @result:     输出结果（调用者 ai_chat_result_free）
 * @error_message: 输出参数，失败原因（调用者需 free）
 * @http_status:   输出参数，HTTP 状态码（可为 NULL）
 * 返回: AI_OK 成功，AI_ERR_* 失败
 */
int ollama_native_chat(const char *base_url, const char *model_name,
		       const char *api_key,
		       const struct ai_chat_msg *msgs, int nmsgs,
		       const char *tools_json,
		       int max_tokens, int num_ctx,
		       struct ai_chat_result **result,
		       char **error_message, int *http_status);

/*
 * ollama_native_clamp_ctx - 把用户目标 ctx 钳制到模型上限
 * 返回: 生效值（探测失败时原样返回 want）
 */
int ollama_native_clamp_ctx(const char *base_url, const char *model,
			    int want);

#endif /* _AI_OLLAMA_NATIVE_H */
