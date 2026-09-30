// SPDX-License-Identifier: GPL-2.0
/*
 * local_http.c - 本地推理服务极简 HTTP/1.1 客户端实现
 *
 * 为什么不复用 cloud/http_client.c：
 *   1. 其非 TLS 分支只做一次 read()，本地大模型的响应体通常跨越多个
 *      TCP 段，会被截断（TLS 分支才有循环读取）；
 *   2. 无论 key 是否为空都强制发送 "Authorization: Bearer %s"，
 *      key 为 NULL 时是未定义行为，而本地服务通常无需认证；
 *   3. 丢失 HTTP 状态码且无法区分"连接拒绝"，无法给出
 *      "本地服务未启动"这类可操作提示。
 * 因此按方案要求用 POSIX socket 自实现（cloud/ 目录只读复用，不改动）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>

#include "local_http.h"
#include "ai_types.h"

/* 收发超时默认值（毫秒），与 [local] timeout_ms 默认值一致 */
#define LOCAL_HTTP_DEFAULT_TIMEOUT_MS  60000

/* ---- URL 解析 ---- */

struct local_url {
	char host[256];     /* 主机名/IP（不含端口） */
	char path[512];     /* 请求路径（以 '/' 开头） */
	int  port;          /* 端口 */
};

/*
 * parse_local_url - 解析 http:// URL
 * 返回: 0 成功；-1 格式错误；-2 为 https URL（本地不支持 TLS）
 */
static int parse_local_url(const char *url, struct local_url *u)
{
	const char *p;
	const char *slash;
	const char *colon;
	size_t len;

	memset(u, 0, sizeof(*u));

	if (strncmp(url, "https://", 8) == 0)
		return -2;
	if (strncmp(url, "http://", 7) != 0)
		return -1;

	p = url + 7;
	u->port = 80;

	slash = strchr(p, '/');
	colon = strchr(p, ':');
	if (colon && (!slash || colon < slash)) {
		long port;

		len = (size_t)(colon - p);
		if (len >= sizeof(u->host))
			len = sizeof(u->host) - 1;
		memcpy(u->host, p, len);
		u->host[len] = '\0';

		port = strtol(colon + 1, NULL, 10);
		if (port <= 0 || port > 65535)
			return -1;
		u->port = (int)port;
	} else if (slash) {
		len = (size_t)(slash - p);
		if (len >= sizeof(u->host))
			len = sizeof(u->host) - 1;
		memcpy(u->host, p, len);
		u->host[len] = '\0';
	} else {
		len = strlen(p);
		if (len >= sizeof(u->host))
			len = sizeof(u->host) - 1;
		memcpy(u->host, p, len);
		u->host[len] = '\0';
	}

	if (u->host[0] == '\0')
		return -1;

	if (slash)
		snprintf(u->path, sizeof(u->path), "%s", slash);
	else
		snprintf(u->path, sizeof(u->path), "/");

	return 0;
}

/* ---- TCP 连接 ---- */

/*
 * tcp_connect_ex - 解析并连接 host:port
 * @timeout_ms: 建连后设置 SO_RCVTIMEO/SO_SNDTIMEO
 * @saved_errno: 输出 connect() 的 errno（判断 ECONNREFUSED）
 * 返回: >=0 socket fd；-1 DNS 解析失败；-2 连接失败
 */
static int tcp_connect_ex(const char *host, int port, int timeout_ms,
			  int *saved_errno)
{
	struct addrinfo hints, *res, *rp;
	char port_str[16];
	int sock = -1;
	struct timeval tv;

	if (saved_errno)
		*saved_errno = 0;

	snprintf(port_str, sizeof(port_str), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;      /* 与 cloud/http_client.c 保持一致 */
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, port_str, &hints, &res) != 0)
		return -1;

	for (rp = res; rp; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock < 0)
			continue;
		if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		if (saved_errno)
			*saved_errno = errno;
		close(sock);
		sock = -1;
	}
	freeaddrinfo(res);

	if (sock < 0)
		return -2;

	/* 收发超时（毫秒精度） */
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	return sock;
}

/* ---- 请求构建与发送 ---- */

/*
 * build_post_request - 构建完整 HTTP/1.1 POST 报文
 * Content-Length 必带；api_key 为空时不发送 Authorization 头。
 */
static char *build_post_request(const char *host, const char *path,
				const char *api_key, const char *json_body,
				size_t *req_len)
{
	size_t key_len = (api_key && api_key[0]) ? strlen(api_key) : 0;
	size_t cap = strlen(json_body) + strlen(host) + strlen(path)
		     + key_len + 1024;
	char *req;
	int n;

	req = malloc(cap);
	if (!req)
		return NULL;

	if (key_len > 0)
		n = snprintf(req, cap,
			     "POST %s HTTP/1.1\r\n"
			     "Host: %s\r\n"
			     "Content-Type: application/json\r\n"
			     "Authorization: Bearer %s\r\n"
			     "Content-Length: %zu\r\n"
			     "Connection: close\r\n"
			     "\r\n"
			     "%s",
			     path, host, api_key, strlen(json_body), json_body);
	else
		n = snprintf(req, cap,
			     "POST %s HTTP/1.1\r\n"
			     "Host: %s\r\n"
			     "Content-Type: application/json\r\n"
			     "Content-Length: %zu\r\n"
			     "Connection: close\r\n"
			     "\r\n"
			     "%s",
			     path, host, strlen(json_body), json_body);

	if (n < 0 || (size_t)n >= cap) {
		free(req);
		return NULL;
	}
	*req_len = (size_t)n;
	return req;
}

/* 循环发送，处理部分发送与 EINTR；返回 0 成功 */
static int send_all(int sock, const char *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = send(sock, buf + off, len - off, 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		off += (size_t)n;
	}
	return 0;
}

/* ---- 响应接收与解码 ---- */

/*
 * recv_all - 循环接收直到对端关闭（Connection: close）
 * 读超时（EAGAIN）时若已有部分数据则按现有数据继续解析，
 * 否则报网络错误。输出缓冲区调用者需 free。
 */
static int recv_all(int sock, char **out)
{
	size_t cap = 65536, len = 0;
	char *buf;

	buf = malloc(cap);
	if (!buf)
		return AI_ERR_MEMORY;

	for (;;) {
		char tmp[8192];
		ssize_t r = recv(sock, tmp, sizeof(tmp), 0);

		if (r == 0)
			break;                  /* 对端正常关闭 */
		if (r < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;          /* 读超时：使用已有数据 */
			free(buf);
			return AI_ERR_NETWORK;
		}

		if (len + (size_t)r + 1 > cap) {
			size_t need = len + (size_t)r + 1;
			size_t ncap = cap * 2;
			char *nb;

			if (need > LOCAL_HTTP_MAX_RESPONSE) {
				free(buf);
				return AI_ERR_MEMORY;   /* 响应超出上限 */
			}
			if (ncap < need)
				ncap = need;
			if (ncap > LOCAL_HTTP_MAX_RESPONSE)
				ncap = LOCAL_HTTP_MAX_RESPONSE;
			nb = realloc(buf, ncap);
			if (!nb) {
				free(buf);
				return AI_ERR_MEMORY;
			}
			buf = nb;
			cap = ncap;
		}

		memcpy(buf + len, tmp, (size_t)r);
		len += (size_t)r;
		buf[len] = '\0';
	}

	if (len == 0) {
		free(buf);
		return AI_ERR_NETWORK;  /* 空响应 */
	}

	*out = buf;
	return AI_OK;
}

/*
 * strip_chunked - 解码 chunked transfer-encoding（与 cloud/http_client.c
 * 的同名实现保持一致）：格式 <hex-size>\r\n<data>\r\n... 0\r\n\r\n，
 * 原地合并，返回干净数据起始指针。
 */
static char *strip_chunked(char *body)
{
	char *src = body, *dst = body;

	while (*src) {
		unsigned long chunk_size = 0;

		/* 解析 hex 大小 */
		while (*src && *src != '\r' && *src != '\n') {
			char c = *src;

			if (c >= '0' && c <= '9')
				chunk_size = chunk_size * 16 +
					     (unsigned long)(c - '0');
			else if (c >= 'a' && c <= 'f')
				chunk_size = chunk_size * 16 +
					     (unsigned long)(c - 'a' + 10);
			else if (c >= 'A' && c <= 'F')
				chunk_size = chunk_size * 16 +
					     (unsigned long)(c - 'A' + 10);
			else
				break;
			src++;
		}
		/* 跳过 chunk 扩展（";ext=..."）与行尾 CRLF */
		while (*src && *src != '\r' && *src != '\n')
			src++;
		while (*src == '\r' || *src == '\n')
			src++;

		if (chunk_size == 0)
			break;

		memmove(dst, src, chunk_size);
		dst += chunk_size;
		src += chunk_size;
		while (*src == '\r' || *src == '\n')
			src++;
	}
	*dst = '\0';
	return body;
}

/* 解析状态行 "HTTP/1.1 200 OK" 中的状态码，失败返回 0 */
static int parse_status_code(const char *header)
{
	const char *p = strchr(header, ' ');

	if (!p)
		return 0;
	while (*p == ' ')
		p++;
	return (int)strtol(p, NULL, 10);
}

/* 头部是否声明 chunked 传输编码 */
static int is_chunked(const char *header)
{
	return strcasestr(header, "transfer-encoding") != NULL &&
	       strcasestr(header, "chunked") != NULL;
}

/* ---- 对外接口 ---- */

int local_http_post(const char *url, const char *api_key,
		    const char *json_body, int timeout_ms,
		    char **response, char **error_message, int *status_code)
{
	struct local_url uinfo;
	char *req = NULL;
	char *raw = NULL;
	char *header_end, *body;
	size_t req_len = 0;
	int sock = -1;
	int ret = AI_ERR_NETWORK;
	int code = 0;
	int attempt;

	if (response)
		*response = NULL;
	if (error_message)
		*error_message = NULL;
	if (status_code)
		*status_code = 0;

	if (!url || !json_body || !response || !error_message)
		return AI_ERR_INVALID_ARG;

	{
		int pr = parse_local_url(url, &uinfo);

		if (pr == -2) {
			*error_message = strdup("https:// is not supported for "
				"local provider; use http:// (e.g. "
				"http://127.0.0.1:11434/v1)");
			return AI_ERR_INVALID_ARG;
		}
		if (pr != 0) {
			*error_message = strdup("Invalid URL format (expect "
				"http://host:port/path)");
			return AI_ERR_INVALID_ARG;
		}
	}

	if (timeout_ms <= 0)
		timeout_ms = LOCAL_HTTP_DEFAULT_TIMEOUT_MS;

	req = build_post_request(uinfo.host, uinfo.path, api_key, json_body,
				 &req_len);
	if (!req) {
		*error_message = strdup("Out of memory while building request");
		return AI_ERR_MEMORY;
	}

	/*
	 * 连接级失败重试（T2 问题 3）：服务端异常关连接（如进程重启、
	 * 异常分支未回包直接 close/RST）时，客户端会拿到空响应或发送
	 * 失败。本协议每请求新连接（Connection: close）、请求体幂等
	 * （chat 请求只读），关闭坏连接后重建重试一次是安全的。
	 */
	for (attempt = 0; attempt < 2; attempt++) {
		int saved_errno = 0;
		int rrc;

		sock = tcp_connect_ex(uinfo.host, uinfo.port, timeout_ms,
				      &saved_errno);
		if (sock < 0) {
			char msg[320];

			if (sock == -1) {
				snprintf(msg, sizeof(msg),
					 "Cannot resolve host %s",
					 uinfo.host);
			} else if (saved_errno == ECONNREFUSED) {
				snprintf(msg, sizeof(msg),
					 "Connection refused by %s:%d",
					 uinfo.host, uinfo.port);
			} else if (saved_errno != 0) {
				snprintf(msg, sizeof(msg),
					 "Cannot connect to %s:%d (%s)",
					 uinfo.host, uinfo.port,
					 strerror(saved_errno));
			} else {
				snprintf(msg, sizeof(msg),
					 "Cannot create socket for %s:%d",
					 uinfo.host, uinfo.port);
			}
			*error_message = strdup(msg);
			ret = AI_ERR_NETWORK;
			goto out;   /* 建连失败重试无意义 */
		}

		if (send_all(sock, req, req_len) != 0) {
			close(sock);
			sock = -1;
			ret = AI_ERR_NETWORK;
			if (attempt == 0)
				continue;   /* 重建连接重试 */
			*error_message = strdup("Failed to send request to "
						"local service");
			goto out;
		}

		rrc = recv_all(sock, &raw);
		close(sock);
		sock = -1;

		if (rrc == AI_OK)
			break;      /* 收包成功，跳出重试循环 */
		ret = rrc;
		if (rrc == AI_ERR_NETWORK && attempt == 0)
			continue;   /* 空响应/连接丢失：重建连接重试 */
		if (rrc == AI_ERR_MEMORY)
			*error_message = strdup("Response too large or out of "
						"memory while reading response");
		else
			*error_message = strdup("No response from local service "
						"(timeout or connection lost)");
		goto out;
	}

	/* 拆分头部与 body，解析状态码 */
	header_end = strstr(raw, "\r\n\r\n");
	if (!header_end) {
		*error_message = strdup("Malformed HTTP response (missing "
					"header terminator)");
		ret = AI_ERR_PARSE;
		goto out;
	}

	code = parse_status_code(raw);
	if (status_code)
		*status_code = code;

	/* chunked 判定仅针对头部块（body 可能合法含有 "chunked" 字样） */
	{
		char hdr[8192];
		size_t hlen = (size_t)(header_end - raw);

		if (hlen >= sizeof(hdr))
			hlen = sizeof(hdr) - 1;
		memcpy(hdr, raw, hlen);
		hdr[hlen] = '\0';

		body = header_end + 4;
		if (is_chunked(hdr))
			body = strip_chunked(body);
	}

	*response = strdup(body);
	if (!*response) {
		*error_message = strdup("Out of memory while copying response");
		ret = AI_ERR_MEMORY;
		goto out;
	}
	ret = AI_OK;

out:
	free(raw);
	free(req);
	if (sock >= 0)
		close(sock);
	return ret;
}

/* ---- 流式 POST（增量交付响应体） ---- */

/* chunked 增量解码器状态 */
enum chunk_state {
	CHUNK_SIZE,     /* 读 chunk 大小行（hex，可能跨 read 切分） */
	CHUNK_DATA,     /* 读 chunk 数据（remaining 字节） */
	CHUNK_CRLF,     /* chunk 数据后的 \r\n */
	CHUNK_DONE,     /* 收到 0 chunk（尾随行忽略） */
};

/* 流式读取器：跟踪 chunked 状态与 body 已消费偏移 */
struct stream_reader {
	int chunked;
	enum chunk_state st;
	size_t remaining;
	char szbuf[32];
	size_t szlen;
	size_t body_off;        /* 相对 body 起点的已消费字节数 */
};

/*
 * sr_consume - 消费 body[off..len) 并交付解码字节
 * 返回: 新的 off（调用方保存，下轮续传）
 */
static size_t sr_consume(struct stream_reader *r, const char *body,
			 size_t off, size_t len,
			 local_http_body_cb cb, void *ud)
{
	while (off < len && r->st != CHUNK_DONE) {
		if (!r->chunked) {
			/* 非 chunked：全部交付 */
			if (len > off)
				cb(ud, body + off, len - off);
			return len;
		}
		switch (r->st) {
		case CHUNK_SIZE: {
			char c = body[off];

			off++;
			if (c == '\n') {
				unsigned long sz;

				r->szbuf[r->szlen] = '\0';
				sz = strtoul(r->szbuf, NULL, 16);
				r->szlen = 0;
				if (sz == 0) {
					r->st = CHUNK_DONE;
				} else {
					r->remaining = (size_t)sz;
					r->st = CHUNK_DATA;
				}
			} else if (c != '\r') {
				if (r->szlen < sizeof(r->szbuf) - 1)
					r->szbuf[r->szlen++] = c;
			}
			break;
		}
		case CHUNK_DATA: {
			size_t avail = len - off;
			size_t take = avail < r->remaining ? avail
							   : r->remaining;

			if (take > 0)
				cb(ud, body + off, take);
			off += take;
			r->remaining -= take;
			if (r->remaining == 0)
				r->st = CHUNK_CRLF;
			break;
		}
		case CHUNK_CRLF: {
			char c = body[off];

			off++;
			if (c == '\n')
				r->st = CHUNK_SIZE;
			/* '\r' 或多余字节直接忽略，等待 '\n' */
			break;
		}
		default:
			return len;
		}
	}
	return off;
}

int local_http_post_stream(const char *url, const char *api_key,
			   const char *json_body, int timeout_ms,
			   local_http_body_cb body_cb, void *ud,
			   char **response, char **error_message,
			   int *status_code)
{
	struct local_url uinfo;
	struct stream_reader sr;
	char *req = NULL;
	char *raw = NULL;
	size_t req_len = 0;
	size_t raw_cap = 65536, raw_len = 0;
	int sock = -1;
	int ret = AI_ERR_NETWORK;
	int code = 0;
	int have_header = 0;
	size_t body_start = 0;

	memset(&sr, 0, sizeof(sr));

	if (response)
		*response = NULL;
	if (error_message)
		*error_message = NULL;
	if (status_code)
		*status_code = 0;

	if (!url || !json_body || !error_message || !body_cb)
		return AI_ERR_INVALID_ARG;

	{
		int pr = parse_local_url(url, &uinfo);

		if (pr != 0) {
			*error_message = strdup(pr == -2 ?
				"https:// is not supported for local "
				"provider; use http://" :
				"Invalid URL format");
			return AI_ERR_INVALID_ARG;
		}
	}

	if (timeout_ms <= 0)
		timeout_ms = LOCAL_HTTP_DEFAULT_TIMEOUT_MS;

	{
		int saved_errno = 0;

		sock = tcp_connect_ex(uinfo.host, uinfo.port, timeout_ms,
				      &saved_errno);
		if (sock < 0) {
			char msg[320];

			if (saved_errno == ECONNREFUSED)
				snprintf(msg, sizeof(msg),
					 "Connection refused by %s:%d",
					 uinfo.host, uinfo.port);
			else
				snprintf(msg, sizeof(msg),
					 "Cannot connect to %s:%d",
					 uinfo.host, uinfo.port);
			*error_message = strdup(msg);
			return AI_ERR_NETWORK;
		}
	}

	req = build_post_request(uinfo.host, uinfo.path, api_key, json_body,
				 &req_len);
	if (!req) {
		*error_message = strdup("Out of memory while building request");
		ret = AI_ERR_MEMORY;
		goto out;
	}
	if (send_all(sock, req, req_len) != 0) {
		*error_message = strdup("Failed to send request");
		ret = AI_ERR_NETWORK;
		goto out;
	}

	raw = malloc(raw_cap);
	if (!raw) {
		*error_message = strdup("Out of memory");
		ret = AI_ERR_MEMORY;
		goto out;
	}

	for (;;) {
		char tmp[8192];
		ssize_t r = recv(sock, tmp, sizeof(tmp), 0);

		if (r <= 0) {
			if (r < 0 && errno == EINTR)
				continue;
			break;   /* 对端关闭或读超时 */
		}

		if (raw_len + (size_t)r + 1 > raw_cap) {
			size_t ncap = raw_cap * 2;
			char *nb;

			while (ncap < raw_len + (size_t)r + 1)
				ncap *= 2;
			if (ncap > LOCAL_HTTP_MAX_RESPONSE)
				ncap = LOCAL_HTTP_MAX_RESPONSE;
			nb = realloc(raw, ncap);
			if (!nb) {
				*error_message = strdup("Out of memory");
				ret = AI_ERR_MEMORY;
				goto out;
			}
			raw = nb;
			raw_cap = ncap;
		}
		memcpy(raw + raw_len, tmp, (size_t)r);
		raw_len += (size_t)r;
		raw[raw_len] = '\0';

		if (!have_header) {
			char *hb = memmem(raw, raw_len, "\r\n\r\n", 4);
			char hdr[8192];
			size_t hlen;

			if (!hb)
				continue;
			have_header = 1;
			code = parse_status_code(raw);
			if (status_code)
				*status_code = code;
			body_start = (size_t)(hb - raw) + 4;

			hlen = (size_t)(hb - raw);
			if (hlen >= sizeof(hdr))
				hlen = sizeof(hdr) - 1;
			memcpy(hdr, raw, hlen);
			hdr[hlen] = '\0';
			sr.chunked = is_chunked(hdr);

			if (code >= 400)
				break;   /* 错误体走全量读取路径 */
		}

		/* 头部之后的 body 增量解码交付 */
		if (raw_len > body_start && code < 400)
			sr.body_off = sr_consume(&sr, raw + body_start,
						 sr.body_off,
						 raw_len - body_start,
						 body_cb, ud);
	}

	if (code >= 400) {
		/* 读全量错误体交回调用方解析 */
		for (;;) {
			char tmp[8192];
			ssize_t r = recv(sock, tmp, sizeof(tmp), 0);

			if (r <= 0) {
				if (r < 0 && errno == EINTR)
					continue;
				break;
			}
			if (raw_len + (size_t)r + 1 > raw_cap) {
				size_t ncap = raw_cap * 2;
				char *nb = realloc(raw, ncap);

				if (!nb)
					break;
				raw = nb;
				raw_cap = ncap;
			}
			memcpy(raw + raw_len, tmp, (size_t)r);
			raw_len += (size_t)r;
			raw[raw_len] = '\0';
		}
		if (response) {
			const char *hb = memmem(raw, raw_len, "\r\n\r\n", 4);

			*response = strdup(hb ? hb + 4 : "");
		}
		*error_message = strdup("HTTP error status (stream)");
		ret = AI_ERR_API;
		goto out;
	}

	if (!code) {
		*error_message = strdup("No response from local service "
					"(timeout or connection lost)");
		ret = AI_ERR_NETWORK;
		goto out;
	}

	ret = AI_OK;

out:
	free(raw);
	free(req);
	if (sock >= 0)
		close(sock);
	return ret;
}

int local_http_probe(const char *url, int timeout_ms, char **error_message)
{	struct local_url uinfo;
	int sock;
	int saved_errno = 0;

	if (error_message)
		*error_message = NULL;

	if (!url || !error_message)
		return AI_ERR_INVALID_ARG;

	if (strncmp(url, "http://", 7) == 0 ||
	    strncmp(url, "https://", 8) == 0) {
		if (parse_local_url(url, &uinfo) != 0) {
			*error_message = strdup("Invalid URL format (expect "
						"http://host:port/...)");
			return AI_ERR_INVALID_ARG;
		}
	} else {
		/* 裸 host[:port] 形式 */
		const char *colon = strchr(url, ':');
		size_t len = colon ? (size_t)(colon - url) : strlen(url);

		memset(&uinfo, 0, sizeof(uinfo));
		if (len == 0 || len >= sizeof(uinfo.host)) {
			*error_message = strdup("Invalid host format");
			return AI_ERR_INVALID_ARG;
		}
		memcpy(uinfo.host, url, len);
		uinfo.host[len] = '\0';
		uinfo.port = colon ? atoi(colon + 1) : 80;
		if (uinfo.port <= 0 || uinfo.port > 65535) {
			*error_message = strdup("Invalid port number");
			return AI_ERR_INVALID_ARG;
		}
		snprintf(uinfo.path, sizeof(uinfo.path), "/");
	}

	if (timeout_ms <= 0)
		timeout_ms = LOCAL_HTTP_DEFAULT_TIMEOUT_MS;

	sock = tcp_connect_ex(uinfo.host, uinfo.port, timeout_ms, &saved_errno);
	if (sock < 0) {
		char msg[320];

		if (sock == -1) {
			snprintf(msg, sizeof(msg), "Cannot resolve host %s",
				 uinfo.host);
		} else if (saved_errno == ECONNREFUSED) {
			snprintf(msg, sizeof(msg),
				 "Connection refused by %s:%d",
				 uinfo.host, uinfo.port);
		} else if (saved_errno != 0) {
			snprintf(msg, sizeof(msg),
				 "Cannot connect to %s:%d (%s)",
				 uinfo.host, uinfo.port,
				 strerror(saved_errno));
		} else {
			snprintf(msg, sizeof(msg),
				 "Cannot create socket for %s:%d",
				 uinfo.host, uinfo.port);
		}
		*error_message = strdup(msg);
		return AI_ERR_NETWORK;
	}

	close(sock);
	return AI_OK;
}

/*
 * local_http_get - GET 请求（SME REST 客户端等只读端点使用）
 * 复用上面的 URL 解析/TCP 建连/收包/chunked 解码路径；
 * 无请求体，不带认证头（SME 本地服务无认证）。
 */
int local_http_get(const char *url, int timeout_ms,
		   char **response, char **error_message, int *status_code)
{
	struct local_url uinfo;
	char *raw = NULL;
	char *header_end, *body;
	size_t req_len;
	char *req = NULL;
	int sock = -1;
	int ret = AI_ERR_NETWORK;
	int code = 0;

	if (response)
		*response = NULL;
	if (error_message)
		*error_message = NULL;
	if (status_code)
		*status_code = 0;

	if (!url || !response || !error_message)
		return AI_ERR_INVALID_ARG;

	{
		int pr = parse_local_url(url, &uinfo);

		if (pr == -2) {
			*error_message = strdup("https:// is not supported; "
				"use http://");
			return AI_ERR_INVALID_ARG;
		}
		if (pr != 0) {
			*error_message = strdup("Invalid URL format (expect "
				"http://host:port/path)");
			return AI_ERR_INVALID_ARG;
		}
	}

	if (timeout_ms <= 0)
		timeout_ms = LOCAL_HTTP_DEFAULT_TIMEOUT_MS;

	{
		int saved_errno = 0;

		sock = tcp_connect_ex(uinfo.host, uinfo.port, timeout_ms,
				      &saved_errno);
		if (sock < 0) {
			char msg[320];

			if (sock == -1)
				snprintf(msg, sizeof(msg),
					 "Cannot resolve host %s",
					 uinfo.host);
			else if (saved_errno == ECONNREFUSED)
				snprintf(msg, sizeof(msg),
					 "Connection refused by %s:%d",
					 uinfo.host, uinfo.port);
			else if (saved_errno != 0)
				snprintf(msg, sizeof(msg),
					 "Cannot connect to %s:%d (%s)",
					 uinfo.host, uinfo.port,
					 strerror(saved_errno));
			else
				snprintf(msg, sizeof(msg),
					 "Cannot create socket for %s:%d",
					 uinfo.host, uinfo.port);
			*error_message = strdup(msg);
			return AI_ERR_NETWORK;
		}
	}

	/* 构造 GET 报文 */
	{
		size_t cap = strlen(uinfo.host) + strlen(uinfo.path) + 256;

		req = malloc(cap);
		if (!req) {
			*error_message = strdup("Out of memory");
			ret = AI_ERR_MEMORY;
			goto out;
		}
		req_len = (size_t)snprintf(req, cap,
					   "GET %s HTTP/1.1\r\n"
					   "Host: %s\r\n"
					   "Accept: application/json\r\n"
					   "Connection: close\r\n"
					   "\r\n",
					   uinfo.path, uinfo.host);
	}

	if (send_all(sock, req, req_len) != 0) {
		*error_message = strdup("Failed to send request to local service");
		ret = AI_ERR_NETWORK;
		goto out;
	}

	ret = recv_all(sock, &raw);
	if (ret != AI_OK) {
		*error_message = strdup(ret == AI_ERR_MEMORY ?
			"Response too large or out of memory" :
			"No response from local service (timeout or "
			"connection lost)");
		goto out;
	}

	header_end = strstr(raw, "\r\n\r\n");
	if (!header_end) {
		*error_message = strdup("Malformed HTTP response");
		ret = AI_ERR_PARSE;
		goto out;
	}

	code = parse_status_code(raw);
	if (status_code)
		*status_code = code;

	{
		char hdr[8192];
		size_t hlen = (size_t)(header_end - raw);

		if (hlen >= sizeof(hdr))
			hlen = sizeof(hdr) - 1;
		memcpy(hdr, raw, hlen);
		hdr[hlen] = '\0';

		body = header_end + 4;
		if (is_chunked(hdr))
			body = strip_chunked(body);
	}

	*response = strdup(body);
	if (!*response) {
		*error_message = strdup("Out of memory while copying response");
		ret = AI_ERR_MEMORY;
		goto out;
	}
	ret = AI_OK;

out:
	free(raw);
	free(req);
	if (sock >= 0)
		close(sock);
	return ret;
}
