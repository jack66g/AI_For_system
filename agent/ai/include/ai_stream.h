/*
 * ai_stream.h - 流式响应增量解析器（SSE data: 帧 + Ollama NDJSON 统一）
 *
 * 覆盖三种线上格式，调用方只管喂字节：
 *   1. OpenAI 兼容 SSE（chat/completions stream:true）：
 *        data: {"choices":[{"delta":{"content":"..."},"finish_reason":null}], ...}
 *        data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}
 *        data: {"usage":{...}}   （stream_options.include_usage）
 *        data: [DONE]
 *   2. Ollama 原生 /api/chat 流（NDJSON，每行一个完整 JSON）：
 *        {"message":{"content":"..."},"done":false}
 *        {"message":{"tool_calls":[...]},...}
 *        {"done":true,"done_reason":"stop","prompt_eval_count":N,"eval_count":M}
 *   3. 整体缓冲的 SSE 文本（云端 HTTPS 通道收完再解析）——同样按行喂入。
 *
 * 解析器职责：
 *   - 行缓冲拼接（跨 feed 的半行）、容忍 \r\n、跳过空行与 SSE 注释
 *     （": keepalive"）、[DONE] 终止；
 *   - delta.content 逐段经回调交付（调用方实时打印）；
 *   - delta.tool_calls 按 index 聚合 arguments 碎片，还原完整调用
 *     （id/name 取首个出现值，arguments 顺序拼接）；
 *   - Ollama 原生 message.tool_calls 为一次性完整对象（arguments 是
 *     JSON 对象而非字符串），原样截取；
 *   - usage/done_reason/done 聚合，finish() 时填充 ai_chat_result
 *     （与非流式路径同一结构，cmd_ask 下游无感）。
 */
#ifndef _AI_STREAM_H
#define _AI_STREAM_H

#include <stddef.h>
#include "ai_chat.h"

/* 流式聚合器（不透明） */
struct ai_stream_agg;

/*
 * ai_stream_delta_cb - content 增量回调
 * @ud:  调用方上下文
 * @delta: 本段文本（UTF-8 片段，非零结尾，长度 @len）
 */
typedef void (*ai_stream_delta_cb)(void *ud, const char *delta, size_t len);

/*
 * ai_stream_agg_create - 创建流式聚合器
 * 返回: 聚合器指针；分配失败返回 NULL
 */
struct ai_stream_agg *ai_stream_agg_create(void);

/*
 * ai_stream_agg_feed - 喂入一段（可能任意切分的）流数据
 * @ag: 聚合器
 * @data: 字节流片段
 * @len:  片段长度
 * @cb:   content 增量回调（可 NULL = 不需要实时交付）
 * @ud:   回调上下文
 */
void ai_stream_agg_feed(struct ai_stream_agg *ag, const char *data,
			size_t len, ai_stream_delta_cb cb, void *ud);

/*
 * ai_stream_agg_finish - 结束流并导出聚合结果
 * @ag:  聚合器
 * @out: 输出结果（content/tool_calls/finish_reason/usage 字段被填充，
 *       所有权移交调用者，ai_chat_result_free 释放；只填充字段，
 *       不负责 out 本身的分配——调用方先 memset）
 * 返回: AI_OK 正常结束；AI_ERR_PARSE 流中出现不可解析帧（尽力而为，
 *       已收内容仍写入 out）；AI_ERR_API 流内携带 error 对象
 */
int ai_stream_agg_finish(struct ai_stream_agg *ag, struct ai_chat_result *out);

/*
 * ai_stream_agg_free - 释放聚合器（finish 之后调用）
 */
void ai_stream_agg_free(struct ai_stream_agg *ag);

#endif /* _AI_STREAM_H */
