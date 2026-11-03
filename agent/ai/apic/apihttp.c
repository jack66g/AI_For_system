/* SPDX-License-Identifier: GPL-2.0 */
/*
 * apihttp.c - T7b HTTP/1.1 壳(拷贝改编自 T6 dthttp.c,差异点见报告):
 *   - 头序 Server→Date→Content-Type→Content-Length(无 Cache-Control);
 *   - 恒 Content-Length;JSON 响应不带 Connection(keep-alive 由请求定);
 *   - send_error 模板(py3.10.12 逐字节):501(未覆写方法,HEAD 无体)/
 *     414(请求行 >65536)/400(坏请求行/坏版本),均 Connection: close;
 *   - 请求行按 Python str.split() 任意空白切词,词数 2..3;
 *   - 头行 >65536 → 静默关连接(py HTTPException 未捕获等价);
 *   - 请求体由端点自读(CL>1MiB 的 400 不排空 → desync 语义照录);
 *   - 未捕获异常等价 = 无响应直接关连接(api_dispatch 返回 -1)。
 */
#define _POSIX_C_SOURCE 200809L

#include "apic/api.h"

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

#define AH_MAXLINE (64 * 1024)	/* py readline(65537) 上限语义 */
#define AH_MAXHEADER (64 * 1024)
#define AH_RECV_TIMEOUT_MS 10000
#define AH_KEEPALIVE_TIMEOUT_MS 15000
#define AH_MAX_BODY_MEM (8 * 1024 * 1024)

/* ---------------- 连接缓冲读(py rfile 语义) ---------------- */
struct conn_reader {
	int fd;
	unsigned char buf[AH_MAXLINE + AH_MAXHEADER];
	size_t len;		/* 缓冲现存 */
	size_t pos;		/* 已消费 */
	int eof;
};

static int cr_fill(struct conn_reader *cr)
{
	ssize_t n;

	if (cr->pos > 0) {
		memmove(cr->buf, cr->buf + cr->pos, cr->len - cr->pos);
		cr->len -= cr->pos;
		cr->pos = 0;
	}
	if (cr->len >= sizeof(cr->buf))
		return -1;
	{
		size_t want = sizeof(cr->buf) - cr->len;

		if (want > 8192)	/* py rbufsize 8KB 等价节奏 */
			want = 8192;
		n = recv(cr->fd, cr->buf + cr->len, want, 0);
	}
	if (n > 0) {
		cr->len += (size_t)n;
		return 1;
	}
	if (n == 0) {
		cr->eof = 1;
		return 0;
	}
	if (errno == EINTR)
		return 1;
	cr->eof = 1;
	return 0;
}

/*
 * 读一行(到 \n,含;超 max 字节无 \n → 返回 -2 = py readline 超 65536)。
 * 返回 malloc 行(含换行,*out_len 含);EOF 无数据 → NULL(*eof=1)。
 */
static char *cr_readline(struct conn_reader *cr, size_t max, size_t *out_len,
			 int *eof, int *too_long)
{
	struct dt_sbuf sb;

	dt_sb_init(&sb);
	*eof = 0;
	*too_long = 0;
	for (;;) {
		size_t i;

		for (i = cr->pos; i < cr->len; i++) {
			if (cr->buf[i] == '\n')
				break;
		}
		if (i < cr->len) {
			size_t n = i - cr->pos + 1;

			dt_sb_puts(&sb, (const char *)cr->buf + cr->pos, n);
			cr->pos = i + 1;
			*out_len = n;
			return dt_sb_finish(&sb);
		}
		/* 无换行:先吐已有 */
		dt_sb_puts(&sb, (const char *)cr->buf + cr->pos,
			   cr->len - cr->pos);
		cr->pos = cr->len;
		if (sb.n > max) {
			*too_long = 1;
			*out_len = 0;
			free(dt_sb_finish(&sb));
			return NULL;
		}
		if (cr_fill(cr) <= 0) {
			*eof = 1;
			*out_len = sb.n;
			return dt_sb_finish(&sb);
		}
	}
}

/* ---------------- 响应写出 ---------------- */
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
		break;		/* EPIPE/ECONNRESET 吞掉(py wfile 同) */
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
	case 403:
		return "Forbidden";
	case 404:
		return "Not Found";
	case 405:
		return "Method Not Allowed";
	case 409:
		return "Conflict";
	case 410:
		return "Gone";
	case 414:
		return "Request-URI Too Long";
	case 500:
		return "Internal Server Error";
	case 501:
		return "Not Implemented";
	case 502:
		return "Bad Gateway";
	case 503:
		return "Service Unavailable";
	case 504:
		return "Gateway Timeout";
	default:
		return "OK";
	}
}

/* RFC 1123 GMT(Date 头;差分归一白名单) */
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

struct req_log_ctx {
	const char *raw_line;
	const char *client_ip;
};

/* py log_error:"code %d, message %s" */
static void log_error_line(const struct req_log_ctx *lc, int code,
			   const char *message)
{
	printf("[aikernel-api] %s code %d, message %s\n",
	       lc && lc->client_ip ? lc->client_ip : "-",
	       code, message ? message : "-");
	fflush(stdout);
}

/* py log_request:'"%s" %s %s'(size 恒 '-') */
static void log_request_line(const struct req_log_ctx *lc, int code)
{
	printf("[aikernel-api] %s \"%s\" %d -\n",
	       lc && lc->client_ip ? lc->client_ip : "-",
	       lc && lc->raw_line ? lc->raw_line : "-", code);
	fflush(stdout);
}

/* JSON/常规响应:Server→Date→Content-Type→Content-Length(无 Connection) */
static void send_response(int fd, int status, const char *ctype,
			  const void *body, size_t body_len,
			  const struct req_log_ctx *lc)
{
	char date[64];
	char head[512];
	int n;

	http_date(date, sizeof(date));
	n = snprintf(head, sizeof(head),
		     "HTTP/1.1 %d %s\r\n"
		     "Server: %s\r\n"
		     "Date: %s\r\n"
		     "Content-Type: %s\r\n"
		     "Content-Length: %zu\r\n"
		     "\r\n",
		     status, reason_phrase(status), API_SERVER_HDR, date,
		     ctype, body_len);
	if (n > 0)
		write_all(fd, head, (size_t)n);
	if (body && body_len)
		write_all(fd, body, body_len);
	log_request_line(lc, status);
}

/* html.escape(msg, quote=False):& < > 转义 */
static void html_escape_into(struct dt_sbuf *sb, const char *s)
{
	for (; *s; s++) {
		if (*s == '&') {
			dt_sb_putstr(sb, "&amp;");
		} else if (*s == '<') {
			dt_sb_putstr(sb, "&lt;");
		} else if (*s == '>') {
			dt_sb_putstr(sb, "&gt;");
		} else {
			dt_sb_putc(sb, *s);
		}
	}
}

/*
 * py3.10.12 BaseHTTPRequestHandler.send_error 逐字节模板。
 * code_msg:状态行消息(NULL=短语);explain:解释段。no_body=HEAD。
 */
static void send_error_tmpl(int fd, int code, const char *code_msg,
			    const char *explain, const char *method,
			    int no_body, const struct req_log_ctx *lc)
{
	char date[64];
	struct dt_sbuf sb;
	char *body;
	size_t body_len;
	const char *phrase = reason_phrase(code);
	const char *msg = code_msg ? code_msg : phrase;

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
		     "        <p>Error code: %d</p>\n"
		     "        <p>Message: ", code);
	html_escape_into(&sb, msg);
	dt_sb_putstr(&sb, ".</p>\n        <p>Error code explanation: ");
	html_escape_into(&sb, explain);
	dt_sb_putstr(&sb, ".</p>\n    </body>\n</html>\n");
	body = dt_sb_finish(&sb);
	body_len = body ? strlen(body) : 0;
	{
		char head[640];
		char msgline[256];
		char *esc;
		struct dt_sbuf eb;
		int n;

		/* 状态行消息需 latin-1 转义(py 对非 latin-1 报错;模板消息
		 * 均为 ASCII,%r 含引号——按 py %r 语义:单引号包裹+原样) */
		dt_sb_init(&eb);
		dt_sb_putstr(&eb, msg);
		esc = dt_sb_finish(&eb);
		snprintf(msgline, sizeof(msgline), "%d %s", code, esc ? esc : "");
		free(esc);
		n = snprintf(head, sizeof(head),
			     "HTTP/1.1 %s\r\n"
			     "Server: %s\r\n"
			     "Date: %s\r\n"
			     "Connection: close\r\n"
			     "Content-Type: text/html;charset=utf-8\r\n"
			     "Content-Length: %zu\r\n"
			     "\r\n",
			     msgline, API_SERVER_HDR, date, body_len);
		if (n > 0)
			write_all(fd, head, (size_t)n);
	}
	if (!no_body && body)
		write_all(fd, body, body_len);
	free(body);
	log_error_line(lc, code, msg);
	(void)method;
}

/* ---------------- 请求解析 ---------------- */
struct parsed_req {
	char *method;
	char *target;	/* self.path 等价(// 折叠后,含 query) */
	char *path;	/* '?' 前部分(未解码) */
	char *query;	/* '?' 后部分(未解码;无则 "") */
	char *authorization;
	char *content_length;
	char *raw_line;	/* 原始请求行(日志用) */
	char client_ip[64];
	int http11;
	int conn_close;
	int conn_keepalive;
};

static char *trim_ws(char *s)
{
	char *end;

	while (*s == ' ' || *s == '\t')
		s++;
	end = s + strlen(s);
	while (end > s) {
		char c = end[-1];

		if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
			*--end = '\0';
		else
			break;
	}
	return s;
}

/* py str.split():任意空白(空格/\t/\v/\f)切词 */
static int split_words(char *line, char *words[], int max_words)
{
	int n = 0;
	char *p = line;

	while (*p) {
		while (*p == ' ' || *p == '\t' || *p == '\v' || *p == '\f')
			p++;
		if (!*p)
			break;
		if (n < max_words)
			words[n] = p;
		n++;
		while (*p && *p != ' ' && *p != '\t' && *p != '\v' &&
		       *p != '\f')
			p++;
		if (*p)
			*p++ = '\0';
	}
	return n;
}

/* py 请求行解析(3.10.12):返回 0 ok;-1 bad syntax;-2 bad version;
 * -3 HTTP/2+(505);-4 两词非 GET(0.9 形态)
 * gh-87389:path 以 // 开头 → 折叠为单 /(self.path 语义)
 * target_buf 归调用者(线程静态);path/query 由调用方派生 */
static int parse_request_line(char *line, struct parsed_req *h,
			      char *target_buf, size_t target_cap)
{
	char *words[8];
	int n = split_words(line, words, 8);
	const char *version = NULL;

	if (n == 0)
		return -1;
	if (n >= 3) {
		const char *v = words[n - 1];
		const char *num = v + 5;
		const char *dot;
		int comps = 1, bad = 0;

		if (strncmp(v, "HTTP/", 5) != 0)
			return -2;
		dot = num;
		while (*dot) {
			if (*dot == '.')
				comps++;
			else if (*dot < '0' || *dot > '9')
				bad = 1;
			dot++;
		}
		if (bad || comps != 2)	/* 3.10.12:恰两组数字 */
			return -2;
		{
			int maj = atoi(num);

			if (maj >= 2)
				return -3;
		}
		version = v;
	}
	if (n < 2 || n > 3)
		return -1;
	if (n == 2) {
		h->conn_close = 1;	/* HTTP/0.9 形态:立即关 */
		if (strcmp(words[0], "GET") != 0)
			return -4;
	}
	h->method = words[0];
	/* self.path:target 原样拷贝;gh-87389 // 折叠 */
	snprintf(target_buf, target_cap, "%s", words[1]);
	if (target_buf[0] == '/' && target_buf[1] == '/') {
		size_t lead = 0;

		while (target_buf[lead] == '/')
			lead++;
		memmove(target_buf + 1, target_buf + lead,
			strlen(target_buf + lead) + 1);
	}
	h->target = target_buf;
	h->path = target_buf;
	h->query = target_buf + strlen(target_buf);
	h->http11 = version && strcmp(version, "HTTP/1.1") == 0;
	/* close_connection 初值:1.1 → False(除非 Connection: close);
	 * 1.0/0.9 → True(除非 keep-alive)。头阶段再修正。 */
	if (!h->conn_close)
		h->conn_close = !h->http11;
	h->conn_keepalive = 0;
	return 0;
}

/* 请求头解析(email 解析器近似:名: 值;首个同名头生效;值 strdup 归 mh) */
static int parse_header_line(char *line, struct parsed_req *h)
{
	char *colon = strchr(line, ':');
	char *key;
	char *val;

	if (!colon)
		return 0;	/* 无冒号行忽略(email 宽容) */
	*colon = '\0';
	key = trim_ws(line);
	val = trim_ws(colon + 1);
	if (strcasecmp(key, "authorization") == 0) {
		if (!h->authorization)
			h->authorization = strdup(val);
	} else if (strcasecmp(key, "content-length") == 0) {
		if (!h->content_length)
			h->content_length = strdup(val);
	} else if (strcasecmp(key, "connection") == 0) {
		if (strcasecmp(val, "close") == 0)
			h->conn_close = 1;
		else if (strcasecmp(val, "keep-alive") == 0)
			h->conn_keepalive = 1;
	}
	return 0;
}

/* ---------------- 单请求处理 ---------------- */
struct api_http_req_impl {
	struct api_http_req pub;
	struct conn_reader *cr;
};

char *api_http_read_body(struct api_http_req *req, size_t *out_len, int *rc)
{
	struct api_http_req_impl *impl = (struct api_http_req_impl *)req;
	struct conn_reader *cr = impl->cr;
	const char *cl = impl->pub.content_length;
	long long n = 0;
	char *buf;

	*out_len = 0;
	if (!cl || !*cl) {
		*rc = 0;
		buf = malloc(3);
		if (!buf) {
			*rc = -3;
			return NULL;
		}
		memcpy(buf, "{}", 2);
		buf[2] = '\0';
		*out_len = 2;
		return buf;
	}
	if (!api_py_int(cl, &n)) {
		*rc = -1;	/* int() ValueError → "invalid json" */
		return NULL;
	}
	if (n > API_MAX_BODY) {
		*rc = -2;	/* 不读体(py rfile.read 前返回) */
		return NULL;
	}
	if (n < 0)
		n = 0;		/* 未录分支:负 CL 按 0(见报告已知限制) */
	if (n > AH_MAX_BODY_MEM) {
		*rc = -3;
		return NULL;
	}
	buf = malloc((size_t)n + 1);
	if (!buf) {
		*rc = -3;
		return NULL;
	}
	{
		size_t have = 0;

		while (have < (size_t)n) {
			size_t avail = cr->len - cr->pos;
			size_t take;

			if (avail == 0) {
				if (cr_fill(cr) <= 0)
					break;	/* 对端断:短读 */
				continue;
			}
			take = avail;
			if (take > (size_t)n - have)
				take = (size_t)n - have;
			memcpy(buf + have, cr->buf + cr->pos, take);
			cr->pos += take;
			have += take;
		}
		buf[have] = '\0';
		if (have < (size_t)n) {
			*rc = -3;	/* 短读:py 读到 EOF 再 json.loads */
			*out_len = have;
			return buf;
		}
		*out_len = (size_t)n;
	}
	*rc = 0;
	return buf;
}

static int handle_one_request(int fd, struct conn_reader *cr)
{
	char *line = NULL;
	size_t line_len = 0;
	int eof = 0, too_long = 0;
	struct parsed_req ph;
	struct api_http_req_impl req;
	struct api_http_resp resp;
	int rc;
	int keep_alive;
	char *raw_line = NULL;
	static __thread char target_buf[8192];
	static __thread char path_buf[8192];
	struct req_log_ctx lc;

	memset(&ph, 0, sizeof(ph));
	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));
	memset(&lc, 0, sizeof(lc));
	{
		struct sockaddr_storage ss;
		socklen_t sl = sizeof(ss);

		if (getpeername(fd, (struct sockaddr *)&ss, &sl) == 0 &&
		    ss.ss_family == AF_INET) {
			const struct sockaddr_in *sin =
				(const struct sockaddr_in *)&ss;
			const unsigned char *b =
				(const unsigned char *)&sin->sin_addr;

			snprintf(ph.client_ip, sizeof(ph.client_ip),
				 "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
		} else {
			snprintf(ph.client_ip, sizeof(ph.client_ip), "-");
		}
	}
	lc.client_ip = ph.client_ip;

	line = cr_readline(cr, AH_MAXLINE, &line_len, &eof, &too_long);
	if (eof && line_len == 0) {
		free(line);
		return 0;	/* 对端关闭/空闲 */
	}
	if (too_long || line_len > AH_MAXLINE) {
		free(line);
		lc.raw_line = "";
		send_error_tmpl(fd, 414, NULL,
				"HTTPStatus.REQUEST_URI_TOO_LONG - URI is too long",
				NULL, 0, &lc);
		return -1;	/* Connection: close 语义 */
	}
	{
		char *rline = strdup(line);

		free(line);
		line = rline;
	}
	/* py: requestline = raw.rstrip('\n')(日志用原文) */
	raw_line = strdup(line);
	{
		size_t n = strlen(line);

		while (n > 0 && (line[n - 1] == '\r' || line[n - 1] == '\n'))
			line[--n] = '\0';
		n = strlen(raw_line);
		while (n > 0 && (raw_line[n - 1] == '\r' ||
				 raw_line[n - 1] == '\n'))
			raw_line[--n] = '\0';
	}
	lc.raw_line = raw_line;
	rc = parse_request_line(line, &ph, target_buf, sizeof(target_buf));
	if (rc == -2) {
		char msg[300];
		char *v = strrchr(line, ' ');

		snprintf(msg, sizeof(msg), "Bad request version ('%s')",
			 v ? v + 1 : line);
		send_error_tmpl(fd, 400, msg,
				"HTTPStatus.BAD_REQUEST - Bad request syntax", NULL, 0,
				&lc);
		goto fail;
	}
	if (rc == -3) {
		char msg[200];
		char *v = strrchr(line, ' ');
		char base[32];

		snprintf(base, sizeof(base), "%s", v ? v + 1 : line);
		if (strncmp(base, "HTTP/", 5) == 0)
			memmove(base, base + 5, strlen(base + 5) + 1);
		snprintf(msg, sizeof(msg), "Invalid HTTP version (%s)",
			 base);
		send_error_tmpl(fd, 505, msg,
				"HTTPStatus.HTTP_VERSION_NOT_SUPPORTED - Request "
				"version not supported",
				NULL, 0, &lc);
		goto fail;
	}
	if (rc == -4) {
		char msg[200];

		snprintf(msg, sizeof(msg),
			 "Bad HTTP/0.9 request type ('%s')", line);
		send_error_tmpl(fd, 400, msg,
				"HTTPStatus.BAD_REQUEST - Bad request syntax", NULL, 0,
				&lc);
		goto fail;
	}
	if (rc != 0) {
		char msg[300];

		snprintf(msg, sizeof(msg), "Bad request syntax ('%s')",
			 line);
		send_error_tmpl(fd, 400, msg,
				"HTTPStatus.BAD_REQUEST - Bad request syntax", NULL, 0,
				&lc);
		goto fail;
	}

	/* 头行(py parse_headers:空行结束;超长行 → 未捕获 → 关连接) */
	for (;;) {
		char *hline;
		size_t hlen;

		hline = cr_readline(cr, AH_MAXLINE, &hlen, &eof, &too_long);
		if (too_long) {
			free(hline);
			goto fail_silent;	/* 静默关(py HTTPException) */
		}
		if (!hline && eof) {
			free(hline);
			goto fail_silent_zero;
		}
		{
			size_t n = strlen(hline);

			while (n > 0 && (hline[n - 1] == '\r' ||
					 hline[n - 1] == '\n'))
				hline[--n] = '\0';
			if (n == 0) {
				free(hline);
				break;
			}
			parse_header_line(hline, &ph);
			free(hline);
		}
	}

	keep_alive = ph.http11 ? !ph.conn_close : ph.conn_keepalive;

	/* 未覆写方法 → 501(方法名区分大小写,HEAD 无体) */
	if (strcmp(ph.method, "GET") != 0 && strcmp(ph.method, "POST") != 0) {
		char msg[160];

		snprintf(msg, sizeof(msg), "Unsupported method ('%s')",
			 ph.method);
		send_error_tmpl(fd, 501, msg,
				"HTTPStatus.NOT_IMPLEMENTED - Server does "
				"not support this operation",
				NULL, strcmp(ph.method, "HEAD") == 0, &lc);
		goto fail;
	}

	/* GET 路由 path('?' 前);target 为折叠后原文(py self.path) */
	{
		char *q = strchr(target_buf, '?');

		if (q) {
			size_t n = (size_t)(q - target_buf);

			if (n >= sizeof(path_buf))
				n = sizeof(path_buf) - 1;
			memcpy(path_buf, target_buf, n);
			path_buf[n] = 0;
			ph.query = q + 1;
		} else {
			snprintf(path_buf, sizeof(path_buf), "%s",
				 target_buf);
			ph.query = target_buf + strlen(target_buf);
		}
	}
	ph.path = path_buf;
	req.pub.method = ph.method;
	req.pub.target = ph.target;	/* 折叠后含 query(py self.path) */
	req.pub.path = ph.path;
	req.pub.query = ph.query;
	req.pub.authorization = ph.authorization;
	req.pub.content_length = ph.content_length;
	req.pub.conn = cr;
	req.cr = cr;

	rc = api_dispatch(&req.pub, &resp);
	if (rc != 0) {
		free(resp.body);
		goto fail_silent;	/* 未捕获异常等价:关连接 */
	}
	send_response(fd, resp.status, "application/json; charset=utf-8",
		      resp.body, resp.body_len, &lc);
	free(resp.body);
	free(line);
	free(raw_line);
	free(ph.authorization);
	free(ph.content_length);
	return keep_alive ? 1 : -1;
fail:
	free(line);
	free(raw_line);
	free(ph.authorization);
	free(ph.content_length);
	return -1;
fail_silent:
	free(line);
	free(raw_line);
	free(ph.authorization);
	free(ph.content_length);
	return -1;
fail_silent_zero:
	free(line);
	free(raw_line);
	free(ph.authorization);
	free(ph.content_length);
	return 0;
}

static void *conn_main(void *arg)
{
	int fd = (int)(intptr_t)arg;
	struct conn_reader cr;
	struct timeval tv;

	memset(&cr, 0, sizeof(cr));
	cr.fd = fd;
	tv.tv_sec = AH_RECV_TIMEOUT_MS / 1000;
	tv.tv_usec = (suseconds_t)((AH_RECV_TIMEOUT_MS % 1000) * 1000);
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	for (;;) {
		int rc = handle_one_request(fd, &cr);

		if (rc <= 0)
			break;
		tv.tv_sec = AH_KEEPALIVE_TIMEOUT_MS / 1000;
		tv.tv_usec = (suseconds_t)((AH_KEEPALIVE_TIMEOUT_MS % 1000) *
					   1000);
		(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv,
				 sizeof(tv));
	}
	close(fd);
	return NULL;
}

/* ---------------- listen / accept ---------------- */
static volatile sig_atomic_t g_stop = 0;
static int g_listen_fd = -1;

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
	if (g_listen_fd >= 0)
		shutdown(g_listen_fd, SHUT_RDWR);
}

int api_http_listen(const char *host, int port)
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

int api_http_accept_loop(void)
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
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
			break;
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

int api_http_serve(const char *host, int port)
{
	if (api_http_listen(host, port) != 0)
		return -1;
	return api_http_accept_loop();
}
