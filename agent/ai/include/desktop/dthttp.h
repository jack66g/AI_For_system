/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dthttp.h - HTTP 壳(acserv.c 的 ac_http_server 模式,不链 smehttp):
 * 自有 listen/accept、每连接线程、HTTP/1.1 keep-alive、恒 Content-Length、
 * 头序 Server→Date→Content-Type→Content-Length→Cache-Control、
 * 501 模板(py3.10.12 逐字节)、处理互斥。
 */
#ifndef _AIK_DESKTOP_DTHTTP_H
#define _AIK_DESKTOP_DTHTTP_H

#include <stddef.h>

#include "store/store_json.h"

struct dt_req {
	const char *method;
	const char *path;    /* 已去掉 query,保留原始(未解码)形式 */
	const char *query;   /* 无则指向 "" */
	char *body;          /* Content-Length 原始字节(NUL 结尾便于解析) */
	size_t body_len;
	aik_json *json;      /* _body_json:失败 → NULL(empty obj 语义) */
	int non_object_body; /* 体解析为非对象(路由层按未捕获异常关连接) */
};

struct dt_resp {
	int status;
	char *body;          /* malloc,所有权归响应写出方 */
	size_t body_len;
	char ctype[128];
	int cache_public;    /* 0 → no-store;1 → public, max-age=300 */
};

/* dt_dispatch 返回 0 → 正常写 resp;返回 -1 → 未捕获异常等价:直接关连接 */
int dt_dispatch(struct dt_req *req, struct dt_resp *resp);

/* 便捷响应构造(在 desktopd.c 提供) */
void dt_resp_json(struct dt_resp *r, int status, const aik_json *body);
void dt_resp_json404(struct dt_resp *r);
void dt_resp_static(struct dt_resp *r, char *body, size_t n,
		    const char *ctype);

/* 服务:listen 与 accept 循环(main 在两者之间打 listening 日志/LISTENING) */
int dt_http_listen(const char *host, int port);
int dt_http_accept_loop(void);
int dt_http_serve(const char *host, int port);

#endif /* _AIK_DESKTOP_DTHTTP_H */
