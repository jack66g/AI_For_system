// SPDX-License-Identifier: GPL-2.0
/*
 * local_http.h - 本地推理服务极简 HTTP/1.1 客户端接口
 *
 * 面向本地回环（127.0.0.1 等）的纯 HTTP 客户端，不带 TLS：
 *   - 基于 POSIX socket，不依赖 mbedTLS/curl；
 *   - Content-Length 必带，循环读取响应直到对端关闭；
 *   - 支持 chunked transfer-encoding 解码（与 cloud/http_client.c 对齐）；
 *   - 区分 DNS 失败/连接拒绝等错误，便于给出可操作提示。
 */
#ifndef _AI_LOCAL_HTTP_H
#define _AI_LOCAL_HTTP_H

/* 单个响应的最大字节数（防止失控服务端耗尽内存） */
#define LOCAL_HTTP_MAX_RESPONSE  (16 * 1024 * 1024)

/*
 * local_http_body_cb - 流式响应体回调
 * @data: 本段已解码的 body 字节（含 SSE data: 行或 NDJSON 行，
 *        可能任意切分，调用方用行缓冲拼接）
 */
typedef void (*local_http_body_cb)(void *ud, const char *data, size_t len);

/*
 * local_http_post - 向本地 HTTP 服务发送 POST 请求
 * @url:           完整 URL（必须为 http:// 形式，如
 *                 http://127.0.0.1:11434/v1/chat/completions）
 * @api_key:       Bearer 令牌，NULL 或空串时不发送 Authorization 头
 * @json_body:     请求体（原样发送，不做转义）
 * @timeout_ms:    收发超时（毫秒），<=0 时取默认值 60000
 * @response:      输出参数，响应 body（已解码 chunked，调用者需 free）
 * @error_message: 输出参数，失败原因（调用者需 free），成功时为 NULL
 * @status_code:   输出参数，HTTP 状态码（可为 NULL）
 * 返回: AI_OK 成功，AI_ERR_* 失败
 */
int local_http_post(const char *url, const char *api_key,
		    const char *json_body, int timeout_ms,
		    char **response, char **error_message, int *status_code);

/*
 * local_http_post_stream - POST 并以回调方式增量交付响应体（流式）
 * 与 local_http_post 同一条建连/发送路径，但收到 body 字节即经
 * @body_cb 交付（不等收完）。增量解码 chunked transfer-encoding。
 * 仅当状态码为 2xx 才回调 body；4xx/5xx 读全量后返回 AI_ERR_API
 * （@response 带回完整 body 供解析错误信息，调用者需 free）。
 * @response:      输出参数，可 NULL（不关心非 2xx 的错误体）
 * 返回: AI_OK 流正常结束；AI_ERR_API HTTP 错误状态；AI_ERR_* 失败
 */
int local_http_post_stream(const char *url, const char *api_key,
			   const char *json_body, int timeout_ms,
			   local_http_body_cb body_cb, void *ud,
			   char **response, char **error_message,
			   int *status_code);

/*
 * local_http_get - 向本地 HTTP 服务发送 GET 请求
 * 复用 local_http_post 的连接/接收/解码路径（SME REST 客户端的
 * /health /stats 等只读端点使用）。
 * @url:           完整 URL（必须为 http:// 形式）
 * @timeout_ms:    收发超时（毫秒），<=0 时取默认值
 * @response:      输出参数，响应 body（已解码 chunked，调用者需 free）
 * @error_message: 输出参数，失败原因（调用者需 free），成功时为 NULL
 * @status_code:   输出参数，HTTP 状态码（可为 NULL）
 * 返回: AI_OK 成功，AI_ERR_* 失败
 */
int local_http_get(const char *url, int timeout_ms,
		   char **response, char **error_message, int *status_code);

/*
 * local_http_probe - TCP 连通性探测（不做 HTTP 语义交互）
 * @url:           http://host:port/... 或裸 host[:port]
 * @timeout_ms:    连接超时（毫秒）
 * @error_message: 输出参数，失败原因（调用者需 free）
 * 返回: AI_OK 可达，AI_ERR_NETWORK 不可达，AI_ERR_* 参数错误
 */
int local_http_probe(const char *url, int timeout_ms, char **error_message);

#endif /* _AI_LOCAL_HTTP_H */
