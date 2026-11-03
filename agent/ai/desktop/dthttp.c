// SPDX-License-Identifier: GPL-2.0
/*
 * dthttp.c - HTTP 壳(照 acserv.c 的 ac_http_server 模式,不链 smehttp):
 * 自有 listen/accept、每连接 detached 线程、HTTP/1.1 keep-alive、
 * 恒 Content-Length、头序 Server→Date→(Connection)→Content-Type→
 * Content-Length→(Cache-Control)、501 模板 py3.10.12 逐字节、
 * 未捕获异常等价=直接关连接(dt_dispatch 返回 -1)。
 */
#define _POSIX_C_SOURCE 200809L

#include "desktop/dthttp.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "desktop/dtcore.h"
#include "desktop/dtjson.h"

#define DT_MAX_HEADER (64 * 1024)
#define DT_MAX_BODY (8 * 1024 * 1024)
#define DT_RECV_TIMEOUT_MS 10000
#define DT_KEEPALIVE_TIMEOUT_MS 15000

/* ---------------- 响应便捷构造 ---------------- */

void dt_resp_json(struct dt_resp *r, int status, const aik_json *body)
{
	r->status = status;
	snprintf(r->ctype, sizeof(r->ctype), "application/json; charset=utf-8");
	free(r->body);
	r->body = body ? dt_json_dump_default(body) : NULL;
	r->body_len = r->body ? strlen(r->body) : 0;
	r->cache_public = 0;
}

void dt_resp_json404(struct dt_resp *r)
{
	aik_json *o = dt_new_obj();

	dt_put_str(o, "error", "not found");
	dt_resp_json(r, 404, o);
	aik_json_free(o);
}

void dt_resp_static(struct dt_resp *r, char *body, size_t n, const char *ctype)
{
	r->status = 200;
	snprintf(r->ctype, sizeof(r->ctype), "%s", ctype);
	free(r->body);
	r->body = body;
	r->body_len = n;
	r->cache_public = 1;
}

static volatile sig_atomic_t g_stop = 0;
static int g_listen_fd = -1;

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
	if (g_listen_fd >= 0) {
		shutdown(g_listen_fd, SHUT_RDWR);
	}
}

static void set_socket_timeout(int fd, int ms)
{
	struct timeval tv;

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
		ssize_t n = send(fd, p + off, len - off, MSG_NOSIGNAL);

		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		break; /* EPIPE/ECONNRESET 吞掉(参考 wfile.write except) */
	}
}

static const char *reason_phrase(int status)
{
	switch (status) {
	case 200:
		return "OK";
	case 400:
		return "Bad Request";
	case 403:
		return "Forbidden";
	case 404:
		return "Not Found";
	case 409:
		return "Conflict";
	case 411:
		return "Length Required";
	case 413:
		return "Payload Too Large";
	case 431:
		return "Request Header Fields Too Large";
	case 500:
		return "Internal Server Error";
	case 501:
		return "Not Implemented";
	case 503:
		return "Service Unavailable";
	default:
		return "OK";
	}
}

/* RFC 1123 GMT(Date 头,C 自产;差分归一白名单) */
static void http_date(char *buf, size_t cap)
{
	time_t t = time(NULL);
	struct tm tm;
	static const char *MO[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
				     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

	gmtime_r(&t, &tm);
	snprintf(buf, cap, "%02d %3s %04d %02d:%02d:%02d GMT", tm.tm_mday,
		 MO[tm.tm_mon], tm.tm_year + 1900, tm.tm_hour, tm.tm_min,
		 tm.tm_sec);
}

static void send_response(int fd, int status, const char *ctype,
			  const void *body, size_t body_len, int cache_public)
{
	char date[64];
	char head[512];
	int n;

	http_date(date, sizeof(date));
	n = snprintf(head, sizeof(head),
		     "HTTP/1.1 %d %s\r\n"
		     "Server: AIKernel-IMG1/1.0\r\n"
		     "Date: %s\r\n"
		     "Content-Type: %s\r\n"
		     "Content-Length: %zu\r\n"
		     "Cache-Control: %s\r\n"
		     "\r\n",
		     status, reason_phrase(status), date, ctype, body_len,
		     cache_public ? "public, max-age=300" : "no-store");
	if (n > 0)
		write_all(fd, head, (size_t)n);
	if (body && body_len)
		write_all(fd, body, body_len);
}

/* py3.10.12 send_error(501) 逐字节模板(method 代入) */
static void send_501(int fd, const char *method)
{
	char date[64];
	struct dt_sbuf sb;
	char *body;
	size_t body_len;

	http_date(date, sizeof(date));
	dt_sb_init(&sb);
	dt_sb_printf(&sb,
		     "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\n"
		     "        \"http://www.w3.org/TR/html4/strict.dtd\">\n"
		     "<html>\n    <head>\n        <meta "
		     "http-equiv=\"Content-Type\" "
		     "content=\"text/html;charset=utf-8\">\n"
		     "        <title>Error response</title>\n    </head>\n"
		     "    <body>\n        <h1>Error response</h1>\n"
		     "        <p>Error code: 501</p>\n"
		     "        <p>Message: Unsupported method ('%s').</p>\n"
		     "        <p>Error code explanation: "
		     "HTTPStatus.NOT_IMPLEMENTED - Server does not support "
		     "this operation.</p>\n    </body>\n</html>\n",
		     method);
	body = dt_sb_finish(&sb);
	body_len = body ? strlen(body) : 0;
	{
		char head[512];
		int n = snprintf(head, sizeof(head),
				 "HTTP/1.1 501 %s\r\n"
				 "Server: AIKernel-IMG1/1.0\r\n"
				 "Date: %s\r\n"
				 "Connection: close\r\n"
				 "Content-Type: text/html;charset=utf-8\r\n"
				 "Content-Length: %zu\r\n"
				 "\r\n",
				 reason_phrase(501), date, body_len);

		if (n > 0)
			write_all(fd, head, (size_t)n);
		if (body)
			write_all(fd, body, body_len);
	}
	free(body);
}

/* ---------------- 请求解析(acserv.c 模式) ---------------- */

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
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return 0; /* keep-alive 空闲超时 */
				return -1;
			}
			len += (size_t)n;
		}
	}
}

static int parse_size(const char *str, size_t *out)
{
	unsigned long long v = 0;
	const char *p = str;

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

struct parsed_head {
	char *method;
	char *path;
	char *query;
	int has_content_length;
	size_t content_length;
	int http11;
	char *connection;
	int bad;
};

static char *trim_left(char *str)
{
	while (*str == ' ' || *str == '\t')
		str++;
	return str;
}

static void trim_right(char *str)
{
	size_t n = strlen(str);

	while (n > 0 && (str[n - 1] == ' ' || str[n - 1] == '\t'))
		str[--n] = '\0';
}

static int parse_head(char *head, size_t head_len, struct parsed_head *h)
{
	char *p = head;
	char *end = head + head_len;
	char *line;

	memset(h, 0, sizeof(*h));
	for (size_t i = 0; i < head_len; i++)
		if (head[i] == '\r' || head[i] == '\n')
			head[i] = '\0';
	line = p;
	while (p < end && *p)
		p++;
	if (p >= end) {
		h->bad = 1;
		return -1;
	}
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
		h->http11 = strcmp(ver, "HTTP/1.1") == 0;
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
			continue;
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
		} else if (strcasecmp(key, "connection") == 0) {
			if (!h->connection)
				h->connection = val;
		}
	}
	return 0;
}

/* ---------------- 单请求处理 ---------------- */

static int handle_one_request(int fd)
{
	char *buf = NULL;
	size_t total = 0, head_len = 0;
	struct parsed_head ph;
	struct dt_req req;
	struct dt_resp resp;
	int rc;
	int keep_alive;

	memset(&ph, 0, sizeof(ph));
	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));
	resp.status = 200;
	snprintf(resp.ctype, sizeof(resp.ctype),
		 "application/json; charset=utf-8");

	buf = malloc(DT_MAX_HEADER + 1);
	if (!buf)
		return -1;
	rc = read_head(fd, buf, DT_MAX_HEADER, &total, &head_len);
	if (rc <= 0) {
		free(buf);
		return 0; /* 对端关闭/空闲超时 */
	}
	if (rc == -2) {
		free(buf);
		{
			static const char e[] = "{\"error\": \"header too large\"}";

			send_response(fd, 431, "application/json; charset=utf-8",
				      e, sizeof(e) - 1, 0);
		}
		return -1;
	}
	if (parse_head(buf, head_len, &ph) != 0 || ph.bad) {
		free(buf);
		{
			static const char e[] = "{\"error\": \"bad request\"}";

			send_response(fd, 400, "application/json; charset=utf-8",
				      e, sizeof(e) - 1, 0);
		}
		return -1;
	}
	keep_alive = ph.http11
			     ? (!ph.connection ||
				strcasecmp(ph.connection, "close") != 0)
			     : (ph.connection &&
				strcasecmp(ph.connection, "keep-alive") == 0);

	/* 未覆写方法 → py3.10.12 501 模板(方法名区分大小写,与
	 * BaseHTTPRequestHandler 的属性分发一致) */
	if (strcmp(ph.method, "GET") != 0 && strcmp(ph.method, "POST") != 0) {
		send_501(fd, ph.method);
		free(buf);
		return -1; /* Connection: close 语义 */
	}

	req.body_len = ph.has_content_length ? ph.content_length : 0;
	if (req.body_len > DT_MAX_BODY) {
		free(buf);
		{
			static const char e[] = "{\"error\": \"payload too large\"}";

			send_response(fd, 413, "application/json; charset=utf-8",
				      e, sizeof(e) - 1, 0);
		}
		return -1;
	}
	req.body = malloc(req.body_len + 1);
	if (!req.body) {
		free(buf);
		return -1;
	}
	{
		size_t have = total - head_len;

		if (have > req.body_len)
			have = req.body_len;
		if (have > 0)
			memcpy(req.body, buf + head_len, have);
		while (have < req.body_len) {
			ssize_t n = recv(fd, req.body + have,
					 req.body_len - have, 0);

			if (n == 0)
				break;
			if (n < 0) {
				if (errno == EINTR)
					continue;
				break;
			}
			have += (size_t)n;
		}
		req.body[have] = '\0';
		if (have < req.body_len) {
			free(req.body);
			free(buf);
			return 0; /* 半请求:对端断,直接结束连接 */
		}
		req.body_len = have;
	}
	req.method = ph.method;
	req.path = ph.path;
	req.query = ph.query;

	/* _body_json:失败/缺省静默 {}(json=NULL 语义) */
	req.json = aik_json_parse(req.body, req.body_len, NULL, 0);
	if (req.json && aik_json_typeof(req.json) != AIK_JSON_OBJ) {
		aik_json_free(req.json);
		req.json = NULL; /* 非对象体:标记(路由层关连接) */
		req.non_object_body = 1;
	}

	rc = dt_dispatch(&req, &resp);
	free(req.body);
	aik_json_free(req.json);
	free(buf);
	if (rc != 0) {
		/* 未捕获异常等价:无响应,直接关连接 */
		free(resp.body);
		return -1;
	}
	send_response(fd, resp.status, resp.ctype, resp.body, resp.body_len,
		      resp.cache_public);
	free(resp.body);
	return keep_alive ? 1 : -1;
}

static void *conn_main(void *arg)
{
	int fd = (int)(intptr_t)arg;

	set_socket_timeout(fd, DT_RECV_TIMEOUT_MS);
	for (;;) {
		int rc = handle_one_request(fd);

		if (rc <= 0)
			break;
		set_socket_timeout(fd, DT_KEEPALIVE_TIMEOUT_MS);
	}
	close(fd);
	return NULL;
}

/* ---------------- listen / accept ---------------- */

int dt_http_listen(const char *host, int port)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	char portstr[16];
	int fd = -1;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	snprintf(portstr, sizeof(portstr), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res)
		return -1;
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
	if (fd < 0)
		return -1;
	g_listen_fd = fd;
	return 0;
}

int dt_http_accept_loop(void)
{
	int fd = g_listen_fd;

	if (fd < 0)
		return -1;
	while (!g_stop) {
		struct pollfd pfd;
		int cfd;
		pthread_t tid;

		pfd.fd = fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, 200) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			/* shutdown() 唤醒:退出 */
			break;
		}
		if (!(pfd.revents & POLLIN))
			continue;
		cfd = accept(fd, NULL, NULL);
		if (cfd < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			break;
		}
		if (pthread_create(&tid, NULL, conn_main,
				   (void *)(intptr_t)cfd) == 0) {
			pthread_detach(tid);
			continue;
		}
		close(cfd);
	}
	close(fd);
	g_listen_fd = -1;
	return 0;
}

int dt_http_serve(const char *host, int port)
{
	if (dt_http_listen(host, port) != 0)
		return -1;
	return dt_http_accept_loop();
}
