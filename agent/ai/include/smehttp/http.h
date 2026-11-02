/* SPDX-License-Identifier: GPL-2.0 */
/*
 * http.h - T4b SME HTTP 服务（单线程 POSIX HTTP/1.1 + 路由分派）
 *
 * 依据 T4B-DESIGN.md §2/§4，对齐 REF-PY e72bc75 `sme/api/server.py` 的
 * 传输层语义：
 *   - 单线程、127.0.0.1、SO_REUSEADDR；port=0 由内核选端口；
 *   - 请求行 + 大小写不敏感 header + Content-Length 请求体（8 MiB 上限，
 *     header 64 KiB 上限，单请求读超时 10s）；
 *   - 每个响应固定 `Content-Type: application/json` + `Connection: close`，
 *     写完即关闭连接（不支持 keep-alive / chunked / TLS）；
 *   - 鉴权中间件：api.auth_token 非空才启用，放行 /health、/docs、/redoc、
 *     /openapi.json、/ 与 /static*，其余必须 `Authorization: Bearer <token>`
 *     完全相等，否则 401 {"detail":"unauthorized"}；
 *   - 未知路径 404 {"detail":"Not Found"}，已知路径方法不符 405。
 *
 * 路由 handler 在 routes.c 实现；http.c 负责解析/鉴权/路径分派/响应。
 * 响应体统一走 store_json 的 aik_json_dump（紧凑 JSON，ensure_ascii=False
 * 等价），与 FastAPI 的字节形态一致。
 *
 * 生命周期：aik_http_server 借用 engine 与 config，二者必须比 server 活得
 * 久（main.c 里先建后毁）。单线程使用，无内部加锁。
 */
#ifndef _AIK_SMEHTTP_HTTP_H
#define _AIK_SMEHTTP_HTTP_H

#include <stddef.h>

#include "engine/engine.h"
#include "smeconfig/config.h"
#include "store/store_json.h"

/* 请求体上限（8 MiB）与 header 上限（64 KiB） */
#define AIK_HTTP_MAX_BODY		(8u * 1024u * 1024u)
#define AIK_HTTP_MAX_HEADER		(64u * 1024u)

/* 单请求读/写超时（毫秒）；serve_one 的 timeout_ms<=0 时取该默认值 */
#define AIK_HTTP_DEFAULT_TIMEOUT_MS	10000

typedef struct aik_http_server aik_http_server;

/*
 * 一次请求的只读视图
 *
 * 所有指针借用 http.c 的栈/请求缓冲，handler 返回后失效。
 *   method        - 原样大写方法（"GET"/"POST"）
 *   path          - 不含 query 的路径（以 '/' 开头）
 *   query         - '?' 之后的原文（无 query 时为空串）
 *   authorization - Authorization 头原值；缺失为 NULL
 *   content_type  - Content-Type 头原值；缺失为 NULL
 *   body          - Content-Length 长度的请求体，额外补 NUL（可含 NUL 字节）
 */
typedef struct {
	const char *method;
	const char *path;
	const char *query;
	const char *authorization;
	const char *content_type;
	const char *body;
	size_t body_len;
} aik_http_request;

/* 响应：body 为 malloc 的 NUL 结尾缓冲（body_len 不含 NUL） */
typedef struct {
	int status;
	char *body;
	size_t body_len;
} aik_http_response;

/*
 * aik_http_server_new - 建监听 socket（bind + listen）
 *
 * host 为数字地址或可解析主机名（NULL/空串 → "127.0.0.1"）；port=0 时由
 * 内核分配，实际端口用 aik_http_server_port 取。失败返回 NULL 并写 err。
 */
aik_http_server *aik_http_server_new(aik_engine *engine, aik_config *config,
				     const char *host, int port,
				     char *err, size_t errlen);
void aik_http_server_free(aik_http_server *s);

/* 实际监听端口 / 绑定主机（借用，随 server 失效） */
int aik_http_server_port(const aik_http_server *s);
const char *aik_http_server_host(const aik_http_server *s);

/*
 * aik_http_server_serve_one - 处理一次连接（accept → 解析 → 鉴权 → 分派
 * → 响应 → 关闭）
 *
 * 返回 0 表示处理完一次连接；1 表示 accept 被信号中断（调用方检查退出
 * 标志）；-1 表示致命错误（errno 已置，调用方可读 errno）。
 */
int aik_http_server_serve_one(aik_http_server *s, int timeout_ms);

/* 访问器（routes.c 使用） */
aik_engine *aik_http_server_engine(const aik_http_server *s);
aik_config *aik_http_server_config(const aik_http_server *s);

/*
 * 响应构造辅助
 *
 * aik_http_response_json 接管 dom 的所有权（dump 后释放）；dump 失败按
 * 500 处理。aik_http_response_detail 生成 {"detail":"<detail>"}。
 * aik_http_response_free 释放 body 并清零（可重复调用）。
 */
void aik_http_response_json(aik_http_response *resp, int status, aik_json *dom);
void aik_http_response_detail(aik_http_response *resp, int status,
			      const char *detail);
void aik_http_response_free(aik_http_response *resp);

/* ------------------------------------------------------------------ */
/* 路由 handler（routes.c 实现，http.c 按路径表分派）                  */
/* ------------------------------------------------------------------ */
void aik_http_route_health(aik_http_server *s, const aik_http_request *req,
			   aik_http_response *resp);
void aik_http_route_stats(aik_http_server *s, const aik_http_request *req,
			  aik_http_response *resp);
void aik_http_route_add_memory(aik_http_server *s,
			       const aik_http_request *req,
			       aik_http_response *resp);
void aik_http_route_add_batch(aik_http_server *s, const aik_http_request *req,
			      aik_http_response *resp);
void aik_http_route_search(aik_http_server *s, const aik_http_request *req,
			   aik_http_response *resp);
void aik_http_route_export(aik_http_server *s, const aik_http_request *req,
			   aik_http_response *resp);
void aik_http_route_regions(aik_http_server *s, const aik_http_request *req,
			    aik_http_response *resp);
void aik_http_route_import(aik_http_server *s, const aik_http_request *req,
			   aik_http_response *resp);
void aik_http_route_memory_get(aik_http_server *s, const aik_http_request *req,
			       const char *memory_id,
			       aik_http_response *resp);
void aik_http_route_memory_hit(aik_http_server *s, const aik_http_request *req,
			       const char *memory_id,
			       aik_http_response *resp);

#endif /* _AIK_SMEHTTP_HTTP_H */
