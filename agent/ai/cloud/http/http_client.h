/*
 * http_client.h - AIKernel HTTPS Client 接口
 *
 * 基于 mbedTLS 的自有 HTTPS 客户端。
 * 不依赖 curl/wget 等外部命令。
 *
 * Phase 4: 增强 GET 支持、Timeout、KeepAlive 预留。
 */

#ifndef _AI_HTTP_CLIENT_H
#define _AI_HTTP_CLIENT_H

#include <stddef.h>

/* ---- HTTPS POST ---- */

/*
 * https_post - HTTPS POST 请求
 * @url:        完整的 API URL
 * @api_key:    API 认证密钥（可为 NULL）
 * @json_body:  JSON 请求体
 * @response:   输出参数，响应内容（调用者需 free）
 * @error_msg:  输出参数，错误信息（调用者需 free），成功时为 NULL
 * 返回: 0 成功，负值失败
 */
int https_post(const char *url,
	       const char *api_key,
	       const char *json_body,
	       char **response,
	       char **error_msg);

/* ---- HTTPS GET ---- */

/*
 * https_get - HTTPS GET 请求
 * @url:        完整的 URL
 * @response:   输出参数，响应内容（调用者需 free）
 * @error_msg:  输出参数，错误信息（调用者需 free），成功时为 NULL
 * 返回: 0 成功，负值失败
 */
int https_get(const char *url,
	      char **response,
	      char **error_msg);

/* ---- HTTPS POST 增量流式读取（SSE/chunked） ---- */

/*
 * http_data_cb - 响应体增量回调
 * @ud:   调用方上下文
 * @data: 本段响应体（已做 chunked 解码的原始字节，非 NUL 结尾）
 * @len:  本段长度
 *
 * 每从网络收到一段响应体就回调一次（真增量：段间存在真实网络等待，
 * 不等整个响应收完）。
 */
typedef void (*http_data_cb)(void *ud, const char *data, size_t len);

/*
 * https_post_stream - HTTPS POST 请求，响应体增量交付
 * @url:         完整的 API URL
 * @api_key:     API 认证密钥（可为 NULL/空串，不发 Authorization）
 * @json_body:   JSON 请求体
 * @on_data:     响应体增量回调（必填）；chunked 传输时回调的是
 *               已解码的 payload（chunk 大小行不混入）
 * @ud:          回调上下文
 * @status_code: 输出参数，HTTP 状态码（可 NULL）
 * @error_msg:   输出参数，错误信息（调用者需 free），成功时为 NULL
 * 返回: 0 成功（对端关闭/终止块结束），负值失败
 *
 * 支持明文 HTTP 与 TLS；Content-Length 与 chunked 两种响应均支持。
 * 供 SSE 流式通道使用（云通道真增量流式的传输底座）。
 */
int https_post_stream(const char *url,
		      const char *api_key,
		      const char *json_body,
		      http_data_cb on_data, void *ud,
		      int *status_code,
		      char **error_msg);

/* ---- Timeout ---- */

/*
 * https_set_timeout - 设置连接超时
 * @connect_timeout: 连接超时秒数（0=默认30秒）
 * @read_timeout:    读取超时秒数（0=默认30秒）
 */
void https_set_timeout(int connect_timeout, int read_timeout);

/* ---- 生命周期 ---- */

/* 全局初始化 mbedTLS（程序启动时调用一次） */
void https_init(void);

/* 全局清理 mbedTLS（程序退出时调用一次） */
void https_cleanup(void);

#endif /* _AI_HTTP_CLIENT_H */
