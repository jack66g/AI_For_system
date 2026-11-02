/* SPDX-License-Identifier: GPL-2.0 */
/*
 * http.c - T4b SME HTTP/1.1 传输层（单线程 POSIX + 路由分派）
 *
 * 流程（T4B-DESIGN.md §2）：
 *   accept → SO_RCVTIMEO/SO_SNDTIMEO → 读 header（上限 64 KiB）→ 解析
 *   请求行/header → 拒绝 chunked（411）→ 读 Content-Length 请求体（上限
 *   8 MiB，超出 413）→ 鉴权中间件（api.auth_token 每请求现读）→ 路径表
 *   分派到 routes.c → aik_json_dump 写紧凑 JSON → 关闭连接。
 *
 * 只做传输与分派：不解析 query（路由无 query 参数）、不做百分号解码
 * （本轮 id 均为 [A-Za-z0-9_]）、不实现 TLS/keep-alive/chunked。
 * 响应头固定 Content-Type: application/json（与参考无 charset 一致）。
 */
#define _POSIX_C_SOURCE 200809L

#include "smehttp/http.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

struct aik_http_server {
	int fd;
	int port;
	char host[128];
	aik_engine *engine;		/* 借用 */
	aik_config *config;		/* 借用（auth_token 每请求现读） */
};

/* ------------------------------------------------------------------ */
/* 小工具                                                             */
/* ------------------------------------------------------------------ */
static char *dup_str(const char *s)
{
	size_t n;
	char *p;

	if (!s)
		s = "";
	n = strlen(s) + 1;
	p = malloc(n);
	if (p)
		memcpy(p, s, n);
	return p;
}

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || errlen == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

/* 大小写不敏感子串（用于 Transfer-Encoding / Expect 判断） */
static int ci_contains(const char *hay, const char *needle)
{
	size_t nl;
	const char *p;

	if (!hay || !needle)
		return 0;
	nl = strlen(needle);
	if (nl == 0)
		return 1;
	for (p = hay; *p; p++) {
		size_t i;

		for (i = 0; i < nl; i++) {
			unsigned char a = (unsigned char)p[i];
			unsigned char b = (unsigned char)needle[i];

			if (a >= 'A' && a <= 'Z')
				a = (unsigned char)(a - 'A' + 'a');
			if (a != (unsigned char)b)
				break;
		}
		if (i == nl)
			return 1;
		if (!p[1])
			break;
	}
	return 0;
}

static void set_socket_timeout(int fd, int ms)
{
	struct timeval tv;

	if (ms <= 0)
		ms = AIK_HTTP_DEFAULT_TIMEOUT_MS;
	tv.tv_sec = ms / 1000;
	tv.tv_usec = (suseconds_t)((ms % 1000) * 1000);
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static void write_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	size_t off = 0;

	while (off < len) {
		ssize_t n = send(fd, p + off, len - off, 0);

		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		break;
	}
}

static const char *reason_phrase(int status)
{
	switch (status) {
	case 200:
		return "OK";
	case 400:
		return "Bad Request";
	case 401:
		return "Unauthorized";
	case 404:
		return "Not Found";
	case 405:
		return "Method Not Allowed";
	case 411:
		return "Length Required";
	case 413:
		return "Payload Too Large";
	case 422:
		return "Unprocessable Entity";
	case 431:
		return "Request Header Fields Too Large";
	case 500:
		return "Internal Server Error";
	default:
		return "OK";
	}
}

static void write_response(int fd, const aik_http_response *r)
{
	char head[256];
	int n;

	n = snprintf(head, sizeof(head),
		     "HTTP/1.1 %d %s\r\n"
		     "Content-Type: application/json\r\n"
		     "Content-Length: %zu\r\n"
		     "Connection: close\r\n"
		     "\r\n",
		     r->status, reason_phrase(r->status), r->body_len);
	if (n > 0)
		write_all(fd, head, (size_t)n);
	if (r->body && r->body_len > 0)
		write_all(fd, r->body, r->body_len);
}

/* ------------------------------------------------------------------ */
/* 响应构造                                                           */
/* ------------------------------------------------------------------ */
void aik_http_response_json(aik_http_response *resp, int status, aik_json *dom)
{
	char *buf = NULL;
	size_t len = 0;

	if (!resp)
		return;
	if (!dom) {
		resp->status = 500;
		free(resp->body);
		resp->body = NULL;
		resp->body_len = 0;
		return;
	}
	if (aik_json_dump(dom, &buf, &len) != 0 || !buf) {
		aik_json_free(dom);
		free(buf);
		resp->status = 500;
		free(resp->body);
		resp->body = NULL;
		resp->body_len = 0;
		return;
	}
	aik_json_free(dom);
	free(resp->body);
	resp->status = status;
	resp->body = buf;
	resp->body_len = len;
}

void aik_http_response_detail(aik_http_response *resp, int status,
			      const char *detail)
{
	aik_json *obj = aik_json_new_obj();
	aik_json *val = aik_json_new_str(detail ? detail : "");

	if (obj && val && aik_json_obj_put(obj, "detail", val) == 0)
		aik_http_response_json(resp, status, obj);
	else {
		aik_json_free(val);
		aik_json_free(obj);
		if (!resp)
			return;
		resp->status = 500;
		free(resp->body);
		resp->body = NULL;
		resp->body_len = 0;
	}
}

void aik_http_response_free(aik_http_response *resp)
{
	if (!resp)
		return;
	free(resp->body);
	resp->body = NULL;
	resp->body_len = 0;
	resp->status = 0;
}

/* ------------------------------------------------------------------ */
/* server 生命周期                                                    */
/* ------------------------------------------------------------------ */
aik_http_server *aik_http_server_new(aik_engine *engine, aik_config *config,
				     const char *host, int port,
				     char *err, size_t errlen)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	struct sockaddr_in sa;
	socklen_t salen = sizeof(sa);
	char portstr[16];
	int fd = -1;

	if (!engine) {
		set_err(err, errlen, "http: engine is NULL");
		return NULL;
	}
	if (!host || !*host)
		host = "127.0.0.1";
	if (port < 0 || port > 65535) {
		set_err(err, errlen, "http: port %d out of range", port);
		return NULL;
	}
	snprintf(portstr, sizeof(portstr), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, portstr, &hints, &res) != 0) {
		set_err(err, errlen, "http: cannot resolve host '%s'", host);
		return NULL;
	}
	for (ai = res; ai; ai = ai->ai_next) {
		int one = 1;

		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;
		(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one,
				 sizeof(one));
		if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 &&
		    listen(fd, 64) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0) {
		set_err(err, errlen, "http: cannot bind %s:%d: %s", host, port,
			strerror(errno));
		return NULL;
	}
	{
		aik_http_server *s = calloc(1, sizeof(*s));
		size_t hl;

		if (!s) {
			close(fd);
			set_err(err, errlen, "http: out of memory");
			return NULL;
		}
		s->fd = fd;
		s->port = port;
		s->engine = engine;
		s->config = config;
		if (getsockname(fd, (struct sockaddr *)&sa, &salen) == 0)
			s->port = (int)ntohs(sa.sin_port);
		hl = strlen(host);
		if (hl >= sizeof(s->host))
			hl = sizeof(s->host) - 1;
		memcpy(s->host, host, hl);
		s->host[hl] = '\0';
		/* 客户端提前关闭时不因 SIGPIPE 终止进程 */
		(void)signal(SIGPIPE, SIG_IGN);
		return s;
	}
}

void aik_http_server_free(aik_http_server *s)
{
	if (!s)
		return;
	if (s->fd >= 0)
		close(s->fd);
	free(s);
}

int aik_http_server_port(const aik_http_server *s)
{
	return s ? s->port : 0;
}

const char *aik_http_server_host(const aik_http_server *s)
{
	return s ? s->host : "";
}

aik_engine *aik_http_server_engine(const aik_http_server *s)
{
	return s ? s->engine : NULL;
}

aik_config *aik_http_server_config(const aik_http_server *s)
{
	return s ? s->config : NULL;
}

/* ------------------------------------------------------------------ */
/* 请求解析                                                           */
/* ------------------------------------------------------------------ */
/*
 * 读到 header 结束（"\r\n\r\n"）。
 * 返回 1=找到（*out_total 为已读字节数，*out_head 为 header 结束位置），
 * 0=对端关闭，-1=读错误/超时，-2=header 超限。
 */
static int read_head(int fd, char *buf, size_t cap, size_t *out_total,
		     size_t *out_head)
{
	size_t len = 0;
	size_t scanned = 0;

	for (;;) {
		size_t i;

		for (i = scanned; i + 4 <= len; i++) {
			if (buf[i] == '\r' && buf[i + 1] == '\n' &&
			    buf[i + 2] == '\r' && buf[i + 3] == '\n') {
				*out_total = len;
				*out_head = i + 4;
				return 1;
			}
		}
		scanned = len >= 3 ? len - 3 : 0;
		if (len >= cap)
			return -2;
		{
			ssize_t n = recv(fd, buf + len, cap - len, 0);

			if (n == 0)
				return 0;
			if (n < 0) {
				if (errno == EINTR)
					continue;
				return -1;
			}
			len += (size_t)n;
		}
	}
}

static int parse_size(const char *s, size_t *out)
{
	unsigned long long v = 0;
	const char *p = s;

	if (!p || !*p)
		return -1;
	for (; *p; p++) {
		if (*p < '0' || *p > '9')
			return -1;
		v = v * 10ULL + (unsigned long long)(*p - '0');
		if (v > (1ULL << 40))
			return -1;
	}
	*out = (size_t)v;
	return 0;
}

typedef struct {
	char *method;
	char *path;
	char *query;
	char *authorization;
	char *content_type;
	int has_content_length;
	size_t content_length;
	int chunked;
	int expect_continue;
	int bad;
} parsed_head;

static char *trim_left(char *s)
{
	while (*s == ' ' || *s == '\t')
		s++;
	return s;
}

static void trim_right(char *s)
{
	size_t n = strlen(s);

	while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
		s[--n] = '\0';
}

/*
 * 解析 header（原地改写缓冲）。head 必须以 NUL 结尾且空间足够。
 * 成功 0；请求行/版本/Content-Length 非法时置 h->bad 并返回 -1。
 */
static int parse_head(char *head, size_t head_len, parsed_head *h)
{
	char *p = head;
	char *end = head + head_len;
	char *line;

	memset(h, 0, sizeof(*h));
	/* CR/LF 全部换成 NUL，按行扫描（空行直接跳过） */
	{
		size_t i;

		for (i = 0; i < head_len; i++)
			if (head[i] == '\r' || head[i] == '\n')
				head[i] = '\0';
	}
	line = p;
	while (p < end && *p)
		p++;
	if (p >= end) {
		h->bad = 1;
		return -1;
	}
	/* 请求行：METHOD SP target SP HTTP/1.x */
	{
		char *sp1 = strchr(line, ' ');
		char *sp2;
		char *target;
		char *ver;
		char *q;

		if (!sp1) {
			h->bad = 1;
			return -1;
		}
		*sp1 = '\0';
		h->method = line;
		target = sp1 + 1;
		sp2 = strchr(target, ' ');
		if (!sp2) {
			h->bad = 1;
			return -1;
		}
		*sp2 = '\0';
		ver = sp2 + 1;
		if (strncmp(ver, "HTTP/1.", 7) != 0) {
			h->bad = 1;
			return -1;
		}
		q = strchr(target, '?');
		if (q) {
			*q = '\0';
			h->query = q + 1;
		} else {
			h->query = target + strlen(target);
		}
		if (target[0] != '/') {
			h->bad = 1;
			return -1;
		}
		h->path = target;
	}
	p = line + strlen(line) + 1;
	for (; p < end; p++) {
		char *colon;
		char *key;
		char *val;

		if (*p == '\0')
			continue;
		line = p;
		while (p < end && *p)
			p++;
		colon = strchr(line, ':');
		if (!colon)
			continue;	/* 畸形 header 行忽略 */
		*colon = '\0';
		key = line;
		val = colon + 1;
		trim_right(key);
		val = trim_left(val);
		trim_right(val);
		if (strcasecmp(key, "content-length") == 0) {
			size_t cl;

			if (parse_size(val, &cl) != 0) {
				h->bad = 1;
				return -1;
			}
			h->has_content_length = 1;
			h->content_length = cl;
		} else if (strcasecmp(key, "transfer-encoding") == 0) {
			if (ci_contains(val, "chunked"))
				h->chunked = 1;
		} else if (strcasecmp(key, "authorization") == 0) {
			if (!h->authorization)
				h->authorization = val;
		} else if (strcasecmp(key, "content-type") == 0) {
			if (!h->content_type)
				h->content_type = val;
		} else if (strcasecmp(key, "expect") == 0) {
			if (ci_contains(val, "100-continue"))
				h->expect_continue = 1;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* 鉴权（server.py 的 _auth_middleware 等价）                          */
/* ------------------------------------------------------------------ */
static int is_open_path(const char *path)
{
	static const char *const open_paths[] = {
		"/health", "/docs", "/redoc", "/openapi.json", "/",
	};
	size_t i;

	for (i = 0; i < sizeof(open_paths) / sizeof(open_paths[0]); i++) {
		if (strcmp(path, open_paths[i]) == 0)
			return 1;
	}
	if (strncmp(path, "/static", 7) == 0)
		return 1;
	return 0;
}

static int authorized(aik_http_server *s, const aik_http_request *req)
{
	const char *token = aik_config_get_str(s->config, "api.auth_token");
	size_t n;

	if (!token || !*token)
		return 1;
	if (is_open_path(req->path))
		return 1;
	if (!req->authorization)
		return 0;
	n = strlen(token);
	if (strlen(req->authorization) != 7 + n)
		return 0;
	if (strncmp(req->authorization, "Bearer ", 7) != 0)
		return 0;
	return strcmp(req->authorization + 7, token) == 0;
}

/* ------------------------------------------------------------------ */
/* 路由分派                                                           */
/* ------------------------------------------------------------------ */
typedef void (*route_fn)(aik_http_server *, const aik_http_request *,
			 aik_http_response *);

static void dispatch(aik_http_server *s, const aik_http_request *req,
		     aik_http_response *resp)
{
	static const struct {
		const char *path;
		const char *method;
		route_fn fn;
	} exact[] = {
		{ "/health", "GET", aik_http_route_health },
		{ "/memories", "POST", aik_http_route_add_memory },
		{ "/memories/batch", "POST", aik_http_route_add_batch },
		{ "/memories/search", "POST", aik_http_route_search },
		{ "/regions", "GET", aik_http_route_regions },
		{ "/stats", "GET", aik_http_route_stats },
		{ "/export", "GET", aik_http_route_export },
		{ "/import", "POST", aik_http_route_import },
	};
	size_t i;
	int partial = 0;

	for (i = 0; i < sizeof(exact) / sizeof(exact[0]); i++) {
		if (strcmp(req->path, exact[i].path) != 0)
			continue;
		if (strcmp(req->method, exact[i].method) == 0) {
			exact[i].fn(s, req, resp);
			return;
		}
		partial = 1;
	}
	/* /memories/{id} 与 /memories/{id}/hit（id 为一个非空路径段） */
	if (strncmp(req->path, "/memories/", 10) == 0) {
		const char *id = req->path + 10;
		const char *slash = strchr(id, '/');

		if (!slash) {
			if (*id) {
				if (strcmp(req->method, "GET") == 0) {
					char *copy = dup_str(id);

					if (!copy) {
						aik_http_response_detail(
							resp, 500,
							"Internal Server Error");
						return;
					}
					aik_http_route_memory_get(s, req,
								  copy, resp);
					free(copy);
					return;
				}
				partial = 1;
			}
		} else if (strcmp(slash, "/hit") == 0 && slash != id) {
			if (strcmp(req->method, "POST") == 0) {
				size_t n = (size_t)(slash - id);
				char *copy = malloc(n + 1);

				if (!copy) {
					aik_http_response_detail(
						resp, 500,
						"Internal Server Error");
					return;
				}
				memcpy(copy, id, n);
				copy[n] = '\0';
				aik_http_route_memory_hit(s, req, copy, resp);
				free(copy);
				return;
			}
			partial = 1;
		}
	}
	if (partial)
		aik_http_response_detail(resp, 405, "Method Not Allowed");
	else
		aik_http_response_detail(resp, 404, "Not Found");
}

/* ------------------------------------------------------------------ */
/* 单连接处理                                                         */
/* ------------------------------------------------------------------ */
static void handle_connection(aik_http_server *s, int fd)
{
	char *buf = NULL;
	size_t total = 0;
	size_t head_len = 0;
	parsed_head ph;
	char *body = NULL;
	size_t body_len = 0;
	aik_http_request req;
	aik_http_response resp;
	int rc;

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	buf = malloc((size_t)AIK_HTTP_MAX_HEADER + 1);
	if (!buf)
		return;
	rc = read_head(fd, buf, (size_t)AIK_HTTP_MAX_HEADER, &total, &head_len);
	if (rc == 0 || rc == -1) {
		free(buf);
		return;		/* 对端空闲/关闭：直接断开 */
	}
	if (rc == -2) {
		free(buf);
		aik_http_response_detail(&resp, 431,
					 "Request Header Fields Too Large");
		write_response(fd, &resp);
		aik_http_response_free(&resp);
		return;
	}
	/*
	 * 注意：不能在这里写 buf[head_len]='\0'——head_len 之后的字节可能
	 * 已经是内核一并读出的请求体首字节。parse_head 只在 [0,head_len)
	 * 内原地改写 CR/LF，不需要额外结尾 NUL。
	 */
	if (parse_head(buf, head_len, &ph) != 0 || ph.bad) {
		free(buf);
		aik_http_response_detail(&resp, 400, "Bad Request");
		write_response(fd, &resp);
		aik_http_response_free(&resp);
		return;
	}
	/* chunked 请求体不支持（411）；Content-Length 超限 413 */
	if (ph.chunked) {
		free(buf);
		aik_http_response_detail(&resp, 411, "Length Required");
		write_response(fd, &resp);
		aik_http_response_free(&resp);
		return;
	}
	if (ph.has_content_length &&
	    ph.content_length > (size_t)AIK_HTTP_MAX_BODY) {
		free(buf);
		aik_http_response_detail(&resp, 413, "Payload Too Large");
		write_response(fd, &resp);
		aik_http_response_free(&resp);
		return;
	}
	body_len = ph.has_content_length ? ph.content_length : 0;
	if (ph.expect_continue && body_len > 0) {
		static const char cont[] = "HTTP/1.1 100 Continue\r\n\r\n";

		/* 客户端在收到 100 之前不会发请求体：必须先行应答 */
		write_all(fd, cont, sizeof(cont) - 1);
	}
	body = malloc(body_len + 1);
	if (!body) {
		free(buf);
		aik_http_response_detail(&resp, 500, "Internal Server Error");
		write_response(fd, &resp);
		aik_http_response_free(&resp);
		return;
	}
	{
		size_t have = total - head_len;

		if (have > body_len)
			have = body_len;
		if (have > 0)
			memcpy(body, buf + head_len, have);
		while (have < body_len) {
			ssize_t n = recv(fd, body + have, body_len - have, 0);

			if (n == 0)
				break;
			if (n < 0) {
				if (errno == EINTR)
					continue;
				break;
			}
			have += (size_t)n;
		}
		body[have] = '\0';
		if (have < body_len) {
			free(body);
			free(buf);
			aik_http_response_detail(&resp, 400, "Bad Request");
			write_response(fd, &resp);
			aik_http_response_free(&resp);
			return;
		}
		body_len = have;
	}

	req.method = ph.method;
	req.path = ph.path;
	req.query = ph.query;
	req.authorization = ph.authorization;
	req.content_type = ph.content_type;
	req.body = body;
	req.body_len = body_len;

	if (!authorized(s, &req)) {
		aik_http_response_detail(&resp, 401, "unauthorized");
	} else {
		dispatch(s, &req, &resp);
		if (resp.status == 0)
			aik_http_response_detail(&resp, 500,
						 "Internal Server Error");
	}
	write_response(fd, &resp);
	aik_http_response_free(&resp);
	free(body);
	free(buf);
}

int aik_http_server_serve_one(aik_http_server *s, int timeout_ms)
{
	int cfd;

	if (!s || s->fd < 0)
		return -1;
	cfd = accept(s->fd, NULL, NULL);
	if (cfd < 0) {
		if (errno == EINTR)
			return 1;
		return -1;
	}
	set_socket_timeout(cfd, timeout_ms);
	handle_connection(s, cfd);
	close(cfd);
	return 0;
}
