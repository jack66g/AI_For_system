/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tlsgwserv.c - T7c 服务端单请求/连接处理(py BaseHTTPRequestHandler 语义)
 *
 * 规格冻结(T7C-PROGRESS.md §A2/A3):
 *   - 请求行/头解析、414/400/505/501/431 模板(枚举前缀)、Expect:100-continue、
 *     keep-alive 判定、0.9(两词 GET)体-only 响应 —— py3.10.12 亲读;
 *   - /healthz 本地 200;请求体 CL/chunked 双解码(64MiB 上限 → 400);
 *   - 转发头(剥逐跳+Host,注入四头)、后端请求字节序;
 *   - 502/400 JSON(json.dumps 默认参数);relay(状态行无 Server/Date,
 *     CL 原样流转发/无 CL 重分块);
 *   - 日志:仅 send_response 路径(stderr;cn=对端证书 CN)。
 */
#define _POSIX_C_SOURCE 200809L

#include "tlsgw/tlsgw.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "desktop/dtcore.h"

/* ---------------- 输出小工具 ---------------- */

static char *trim(char *s)
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

static int io_write(struct gw_serve *sv, const void *buf, size_t len)
{
	return sv->io->write(sv->io->ctx, buf, len);
}

static void log_line(struct gw_serve *sv, const char *fmt, ...)
{
	va_list ap;

	if (!sv->log)
		return;
	fprintf(sv->log, "[aik-tls-gateway] %s cn=%s ", sv->peer_ip,
		sv->cn ? sv->cn : "");
	va_start(ap, fmt);
	vfprintf(sv->log, fmt, ap);
	va_end(ap);
	fputc('\n', sv->log);
	fflush(sv->log);
}

/* html.escape(msg, quote=False) */
static void html_escape(struct dt_sbuf *sb, const char *s)
{
	for (; *s; s++) {
		if (*s == '&')
			dt_sb_putstr(sb, "&amp;");
		else if (*s == '<')
			dt_sb_putstr(sb, "&lt;");
		else if (*s == '>')
			dt_sb_putstr(sb, "&gt;");
		else
			dt_sb_putc(sb, *s);
	}
}

static const char *httpstatus_name(int code)	/* py %(code)s 枚举名 */
{
	switch (code) {
	case 400:
		return "HTTPStatus.BAD_REQUEST";
	case 414:
		return "HTTPStatus.REQUEST_URI_TOO_LONG";
	case 431:
		return "HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE";
	case 501:
		return "HTTPStatus.NOT_IMPLEMENTED";
	case 505:
		return "HTTPStatus.HTTP_VERSION_NOT_SUPPORTED";
	default:
		return "HTTPStatus.?";
	}
}

static const char *httpstatus_desc(int code)
{
	switch (code) {
	case 400:
		return "Bad request syntax or unsupported method";
	case 414:
		return "URI is too long";
	case 431:
		return "The server is unwilling to process the request because its header fields are too large";
	case 501:
		return "Server does not support this operation";
	case 505:
		return "Cannot fulfill request";
	default:
		return "?";
	}
}

/*
 * py3.10.12 send_error 逐字节:
 *   模板 "%(code)s" = HTTPStatus 枚举名;0.9 → 无状态行/头仅体;
 *   HEAD → 无体(头仍带 CL);错误日志行先于请求日志行。
 */
static int send_error_tmpl(struct gw_serve *sv, int code, const char *msg,
			   const char *explain_override, int version_09,
			   const char *raw_line, const char *method)
{
	char date[64];
	struct dt_sbuf sb, body;
	char *b;
	size_t blen;
	const char *phrase = gw_reason_phrase(code);
	const char *msg_s = msg ? msg : phrase;
	int no_body = (method && strcmp(method, "HEAD") == 0);

	gw_http_date(date, sizeof(date));
	log_line(sv, "code %d, message %s", code, msg_s);

	dt_sb_init(&body);
	dt_sb_printf(&body,
		     "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"\n"
		     "        \"http://www.w3.org/TR/html4/strict.dtd\">\n"
		     "<html>\n    <head>\n        <meta "
		     "http-equiv=\"Content-Type\" "
		     "content=\"text/html;charset=utf-8\">\n"
		     "        <title>Error response</title>\n    </head>\n"
		     "    <body>\n        <h1>Error response</h1>\n"
		     "        <p>Error code: %d</p>\n"
		     "        <p>Message: ", code);
	html_escape(&body, msg_s);
	dt_sb_putstr(&body, ".</p>\n        <p>Error code explanation: ");
	dt_sb_putstr(&body, httpstatus_name(code));
	dt_sb_putstr(&body, " - ");
	html_escape(&body, explain_override ? explain_override
					    : httpstatus_desc(code));
	dt_sb_putstr(&body, ".</p>\n    </body>\n</html>\n");
	b = dt_sb_finish(&body);
	blen = b ? strlen(b) : 0;

	dt_sb_init(&sb);
	if (!version_09) {
		dt_sb_printf(&sb, "HTTP/1.1 %d %s\r\n", code, msg_s);
		dt_sb_printf(&sb, "Server: %s\r\n", GW_SERVER_HDR);
		dt_sb_printf(&sb, "Date: %s\r\n", date);
		dt_sb_putstr(&sb, "Connection: close\r\n");
		dt_sb_putstr(&sb,
			     "Content-Type: text/html;charset=utf-8\r\n");
		dt_sb_printf(&sb, "Content-Length: %zu\r\n", blen);
		dt_sb_putstr(&sb, "\r\n");
	}
	{
		char *head = dt_sb_finish(&sb);

		if (head) {
			io_write(sv, head, strlen(head));
			free(head);
		}
	}
	if (!no_body && b && blen)
		io_write(sv, b, blen);
	free(b);
	log_line(sv, "\"%s\" %d -", raw_line ? raw_line : "", code);
	return 0;
}

/* py send_response+send_json:Server→Date→Content-Type→Content-Length */
static int send_json(struct gw_serve *sv, int code, const char *v1,
		     const char *v2, int version_09, const char *raw_line)
{
	char date[64];
	struct dt_sbuf sb;
	char *body;
	size_t body_len = 0;
	char *head;

	gw_http_date(date, sizeof(date));
	if (code == 200)
		body = gw_json_kv2("status", v1, "gateway", v2, &body_len);
	else
		body = gw_json_kv2("error", v1, "detail", v2, &body_len);
	if (!body)
		return -1;

	log_line(sv, "\"%s\" %d -", raw_line ? raw_line : "", code);

	dt_sb_init(&sb);
	if (!version_09) {
		dt_sb_printf(&sb, "HTTP/1.1 %d %s\r\n", code,
			     gw_reason_phrase(code));
		dt_sb_printf(&sb, "Server: %s\r\n", GW_SERVER_HDR);
		dt_sb_printf(&sb, "Date: %s\r\n", date);
		dt_sb_putstr(&sb, "Content-Type: application/json\r\n");
		dt_sb_printf(&sb, "Content-Length: %zu\r\n", body_len);
		dt_sb_putstr(&sb, "\r\n");
	}
	head = dt_sb_finish(&sb);
	if (head) {
		io_write(sv, head, strlen(head));
		free(head);
	}
	io_write(sv, body, body_len);
	free(body);
	return 0;
}

/* ---------------- 请求体读取(py read_body) ---------------- */

/* py int(str):全串数字(±/空白宽);失败 → errmsg(py ValueError str) */
static int py_int10(const char *s, long long *out, char *errmsg, size_t cap)
{
	const char *p = s;
	char *end = NULL;
	long long v;

	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' ||
	       *p == '\v' || *p == '\f')
		p++;
	if (!*p) {		/* 空串:py or 0 → 0(调用方已挡) */
		*out = 0;
		return 0;
	}
	v = strtoll(p, &end, 10);
	while (end && (*end == ' ' || *end == '\t' || *end == '\n' ||
		       *end == '\r' || *end == '\v' || *end == '\f'))
		end++;
	if (!end || *end != '\0') {
		struct dt_sbuf sb;
		char *em;

		dt_sb_init(&sb);
		gw_int10_errmsg(&sb, s);
		em = dt_sb_finish(&sb);
		if (em)
			snprintf(errmsg, cap, "%s", em);
		free(em);
		return -1;
	}
	*out = v;
	return 0;
}

/*
 * 返回 0=ok(*out malloc 体);-1=400(*errmsg = py str(exc));
 * -2=内存失败(未捕获等价)。
 */
static int read_request_body(struct gw_serve *sv, struct gw_hlist *hdrs,
			     unsigned char **out, size_t *out_len,
			     char *errmsg, size_t cap)
{
	const char *te = gw_hlist_get_ci(hdrs, "transfer-encoding");
	struct dt_sbuf sb;

	*out = NULL;
	*out_len = 0;
	if (te && strstr(te, "chunked") != NULL) {
		long long total = 0;
		int done = 0;

		dt_sb_init(&sb);
		while (!done) {
			long long size = 0;
			char em[200];
			char *line;
			size_t len = 0;
			int eof = 0;
			unsigned char *chunk;

			line = gw_reader_readline(&sv->rd, 64, &len, &eof);
			if (!line)
				break;	/* EOF:py 下一轮 b""→0 → 终止 */
			if (gw_chunk_parse_line(line, &size, em,
						sizeof(em)) != 0) {
				free(line);
				snprintf(errmsg, cap, "%s", em);
				free(dt_sb_finish(&sb));
				return -1;
			}
			if (size == 0) {	/* 终止:吞一行 */
				char *t;
				size_t tl = 0;
				int te2 = 0;

				free(line);
				t = gw_reader_readline(&sv->rd,
						       GW_MAXLINE + 1,
						       &tl, &te2);
				free(t);
				break;
			}
			free(line);
			total += size;
			if (total > GW_MAX_BODY) {
				snprintf(errmsg, cap, "请求体超限");
				free(dt_sb_finish(&sb));
				return -1;
			}
			chunk = malloc(size > 0 ? (size_t)size : 1);
			if (!chunk) {
				free(dt_sb_finish(&sb));
				return -2;
			}
			{
				int got = gw_reader_read_exact(&sv->rd, chunk,
							       (size_t)size);

				dt_sb_puts(&sb, (const char *)chunk,
					   (size_t)got);
				free(chunk);
				if (got < 0 || (size_t)got < (size_t)size)
					break;	/* EOF 短读:终止 */
			}
			{
				char *t;
				size_t tl = 0;
				int te2 = 0;

				t = gw_reader_readline(&sv->rd,
						       GW_MAXLINE + 1,
						       &tl, &te2);
				free(t);	/* 块尾 CRLF */
			}
		}
		*out_len = sb.n;
		*out = (unsigned char *)dt_sb_finish(&sb);
		return *out ? 0 : -2;
	}
	{
		const char *cl = gw_hlist_get_ci(hdrs, "content-length");
		long long n = 0;
		unsigned char *buf;

		if (!cl || !*cl) {
			*out = malloc(1);
			if (!*out)
				return -2;
			(*out)[0] = '\0';
			*out_len = 0;
			return 0;
		}
		if (py_int10(cl, &n, errmsg, cap) != 0)
			return -1;
		if (n < 0 || n > GW_MAX_BODY) {
			snprintf(errmsg, cap, "请求体超限");
			return -1;
		}
		buf = malloc(n > 0 ? (size_t)n + 1 : 1);
		if (!buf)
			return -2;
		{
			int got = gw_reader_read_exact(&sv->rd, buf,
						       (size_t)n);

			*out_len = (size_t)got;
			buf[got > 0 ? (size_t)got : 0] = '\0';
		}
		*out = buf;
		return 0;
	}
}

/* ---------------- 响应转发(py relay_response) ---------------- */

static int relay_response(struct gw_serve *sv, struct gw_be *be,
			  int version_09)
{
	struct dt_sbuf sb;
	char *head;
	size_t i;
	int have_cl = 0;
	long long out_cl = 0;

	dt_sb_init(&sb);
	if (!version_09)
		dt_sb_printf(&sb, "HTTP/1.1 %d %s\r\n", be->status,
			     be->reason);
	for (i = 0; i < be->hdrs.n; i++) {
		const char *nm = be->hdrs.names[i];

		if (gw_is_hop_by_hop(nm))
			continue;
		if (strcasecmp(nm, "content-length") == 0) {
			const char *v = be->hdrs.vals[i];
			char *end = NULL;
			long long n = strtoll(v, &end, 10);
			int ok = end && (*end == '\0' ||
					 isspace((unsigned char)*end));

			if (!ok) {	/* py int() ValueError → 未捕获 */
				free(dt_sb_finish(&sb));
				return -1;
			}
			out_cl = n;
			have_cl = 1;
		}
		if (!version_09)
			dt_sb_printf(&sb, "%s: %s\r\n", nm, be->hdrs.vals[i]);
	}
	(void)out_cl;
	if (!version_09) {
		if (!have_cl)
			dt_sb_putstr(&sb, "Transfer-Encoding: chunked\r\n");
		dt_sb_putstr(&sb, "\r\n");
	}
	head = dt_sb_finish(&sb);
	if (head) {
		io_write(sv, head, strlen(head));
		free(head);
	}
	{
		unsigned char buf[65536];
		int rc;

		for (;;) {
			rc = gw_be_read_body(be, buf, sizeof(buf));
			if (rc < 0)
				return -1;	/* 未捕获等价 */
			if (rc == 0)
				break;
			if (have_cl) {
				if (io_write(sv, buf, (size_t)rc) != 0)
					return -1;
			} else {
				char sz[32];
				int n = snprintf(sz, sizeof(sz), "%x\r\n",
						 rc);

				if (io_write(sv, sz, (size_t)n) != 0 ||
				    io_write(sv, buf, (size_t)rc) != 0 ||
				    io_write(sv, "\r\n", 2) != 0)
					return -1;
			}
		}
		if (!have_cl) {	/* 0.9 亦带分块尾帧(仅头被抑制) */
			if (io_write(sv, "0\r\n\r\n", 5) != 0)
				return -1;
		}
	}
	return 0;
}

/* ---------------- 代理主流程(py proxy) ---------------- */

static int do_proxy(struct gw_serve *sv, const struct gw_reqline *h,
		    struct gw_hlist *hdrs, int version_09)
{
	unsigned char *body = NULL;
	size_t body_len = 0;
	char errmsg[512];
	struct gw_hlist fwd;
	struct gw_be be;
	char *reqbytes = NULL;
	size_t reqlen = 0;
	int rc = -1;	/* 默认未捕获等价 */
	int keep = h->close_conn ? -1 : 1;

	if (gw_healthz_target(h->target)) {
		if (send_json(sv, 200, "ok", GW_VERSION, version_09,
			      h->rawline) != 0)
			return -1;
		return keep;
	}

	rc = read_request_body(sv, hdrs, &body, &body_len, errmsg,
			       sizeof(errmsg));
	if (rc == -1) {		/* 400(ValueError/OverflowError → str) */
		send_json(sv, 400, "bad_request", errmsg, version_09,
			  h->rawline);
		free(body);
		return keep;
	}
	if (rc == -2) {
		log_line(sv, "uncaught exception equivalent: body oom");
		free(body);
		return -1;
	}

	gw_hlist_init(&fwd);
	if (gw_build_forward(hdrs, &fwd, sv->cfg->backend, sv->peer_ip,
			     sv->cn) != 0) {
		log_line(sv, "uncaught exception equivalent: header oom");
		goto out;
	}
	reqbytes = gw_build_backend_request(h->method, h->target, &fwd, body,
					    body_len, &reqlen);
	if (!reqbytes) {
		log_line(sv, "uncaught exception equivalent: build oom");
		goto out;
	}

	if (gw_be_connect(&be, sv->backend_host, sv->backend_port,
			  GW_BACKEND_TIMEOUT_SEC, errmsg,
			  sizeof(errmsg)) != 0) {
		char detail[1024];

		snprintf(detail, sizeof(detail), "%s: %s", sv->cfg->backend,
			 errmsg);
		send_json(sv, 502, "bad_gateway", detail, version_09,
			  h->rawline);
		rc = keep;
		goto out;
	}
	if (gw_be_send_request(&be, reqbytes, reqlen, errmsg,
			       sizeof(errmsg)) != 0) {
		char detail[1024];

		gw_be_close(&be);
		snprintf(detail, sizeof(detail), "%s: %s", sv->cfg->backend,
			 errmsg);
		send_json(sv, 502, "bad_gateway", detail, version_09,
			  h->rawline);
		rc = keep;
		goto out;
	}
	{
		int hrc = gw_be_read_head(&be, errmsg, sizeof(errmsg));

		if (hrc == -2) {
			gw_be_close(&be);
			log_line(sv, "uncaught exception equivalent: %s",
				 "BadStatusLine");
			rc = -1;
			goto out;
		}
		if (hrc != 0) {
			char detail[1024];

			gw_be_close(&be);
			snprintf(detail, sizeof(detail), "%s: %s",
				 sv->cfg->backend, errmsg);
			send_json(sv, 502, "bad_gateway", detail, version_09,
				  h->rawline);
			rc = keep;
			goto out;
		}
	}
	if (relay_response(sv, &be, version_09) != 0) {
		gw_be_close(&be);
		log_line(sv, "uncaught exception equivalent: relay");
		rc = -1;
		goto out;
	}
	gw_be_close(&be);
	rc = keep;
out:
	gw_hlist_free(&fwd);
	free(reqbytes);
	free(body);
	return rc;
}

/* ---------------- 单连接循环 ---------------- */

int gw_serve_conn(struct gw_serve *sv)
{
	char *line = NULL;
	size_t len = 0;
	int eof = 0;
	struct gw_reqline h;
	struct gw_hlist hdrs;
	int rc;
	int nconn_keepalive;
	int version_09;

	if (sv->rd.buf == NULL)
		gw_reader_init(&sv->rd, sv->io, sv->rdbuf, sizeof(sv->rdbuf));

	line = gw_reader_readline(&sv->rd, GW_MAXLINE + 1, &len, &eof);
	if (!line)
		return 0;	/* EOF:py close_connection → 断 */
	if (len > GW_MAXLINE) {	/* py len>65536 → 414(requestline='') */
		free(line);
		send_error_tmpl(sv, 414, NULL, NULL, 0, "", NULL);
		return -1;
	}
	{
		size_t n = len;

		while (n > 0 && (line[n - 1] == '\r' || line[n - 1] == '\n'))
			line[--n] = '\0';
	}
	rc = gw_parse_request_line(line, &h);
	if (rc == GW_PARSE_BLANK) {	/* py:静默关 */
		free(line);
		return -1;
	}
	if (rc == GW_PARSE_BAD_VERSION || rc == GW_PARSE_HTTP2 ||
	    rc == GW_PARSE_NOT_GET09) {
		char *msg = malloc(strlen(h.rawline) + strlen(h.last_word) + 64);
		int code;
		const char *base = h.last_word;

		if (!msg) {
			free(line);
			return -1;
		}
		if (rc == GW_PARSE_BAD_VERSION) {
			code = 400;
			sprintf(msg, "Bad request version ('%s')", h.last_word);
		} else if (rc == GW_PARSE_HTTP2) {
			code = 505;
			if (strncmp(base, "HTTP/", 5) == 0)
				base += 5;
			sprintf(msg, "Invalid HTTP version (%s)", base);
		} else {
			code = 400;
			sprintf(msg, "Bad HTTP/0.9 request type ('%s')",
				h.last_word);
		}
		/* py:此类错误时 request_version 仍是默认 "HTTP/0.9"
		 * → 响应仅体(无状态行/头;send_header 全跳过) */
		send_error_tmpl(sv, code, msg, NULL, 1, h.rawline, h.method);
		free(msg);
		free(line);
		return -1;
	}
	if (rc != GW_PARSE_OK) {
		char *msg = malloc(strlen(h.rawline) + 64);

		if (!msg) {
			free(line);
			return -1;
		}
		sprintf(msg, "Bad request syntax ('%s')", h.rawline);
		/* py:版本未解析 → 0.9 默认 → 仅体 */
		send_error_tmpl(sv, 400, msg, NULL, 1, h.rawline, h.method);
		free(msg);
		free(line);
		return -1;
	}
	free(line);
	line = NULL;
	version_09 = h.version_09;

	/* ---- 头部(py parse_headers) ---- */
	gw_hlist_init(&hdrs);
	{
		int count = 0;

		for (;;) {
			char *hl;
			size_t hl_len = 0;
			int hl_eof = 0;
			char *colon;

			hl = gw_reader_readline(&sv->rd, GW_MAXLINE + 1,
						&hl_len, &hl_eof);
			if (!hl && hl_eof)
				break;	/* EOF 终结头段 */
			if (!hl)
				continue;
			if (hl_len > GW_MAXLINE) {
				free(hl);
				send_error_tmpl(sv, 431, "Line too long",
						"got more than 65536 bytes "
						"when reading header line",
						1, h.rawline,
						h.method);	/* py 0.9 默认 */
				gw_hlist_free(&hdrs);
				return -1;
			}
			count++;
			if (count > GW_MAXHEADERS) {
				free(hl);
				send_error_tmpl(sv, 431, "Too many headers",
						"got more than 100 headers",
						1, h.rawline,
						h.method);	/* py 0.9 默认 */
				gw_hlist_free(&hdrs);
				return -1;
			}
			{
				size_t n = hl_len;

				while (n > 0 && (hl[n - 1] == '\r' ||
						 hl[n - 1] == '\n'))
					hl[--n] = '\0';
				if (n == 0) {
					free(hl);
					break;	/* 空行:头结束 */
				}
			}
			colon = strchr(hl, ':');
			if (colon) {
				*colon = '\0';
				{
					char *nm = trim(hl);
					char *val = trim(colon + 1);

					if (*nm)
						gw_hlist_set(&hdrs, nm, val);
				}
			}
			free(hl);
		}
	}

	/* Connection 头(首个,py 精确匹配) */
	{
		const char *conn = gw_hlist_get_ci(&hdrs, "connection");

		if (conn) {
			if (strcasecmp(conn, "close") == 0)
				h.close_conn = 1;
			else if (strcasecmp(conn, "keep-alive") == 0)
				h.close_conn = 0;
		}
	}
	/* Expect: 100-continue(py handle_expect_100:一律 100) */
	{
		const char *expect = gw_hlist_get_ci(&hdrs, "expect");

		if (expect && h.version_11 && !version_09 &&
		    strcasecmp(expect, "100-continue") == 0) {
			static const char CONT[] =
				"HTTP/1.1 100 Continue\r\n\r\n";

			io_write(sv, CONT, sizeof(CONT) - 1);
		}
	}
	nconn_keepalive = !h.close_conn;

	/* 方法覆写表(py do_*:GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS) */
	if (strcmp(h.method, "GET") != 0 && strcmp(h.method, "POST") != 0 &&
	    strcmp(h.method, "PUT") != 0 && strcmp(h.method, "DELETE") != 0 &&
	    strcmp(h.method, "PATCH") != 0 && strcmp(h.method, "HEAD") != 0 &&
	    strcmp(h.method, "OPTIONS") != 0) {
		char msg[160];

		snprintf(msg, sizeof(msg), "Unsupported method ('%s')",
			 h.method);
		send_error_tmpl(sv, 501, msg, NULL, version_09, h.rawline,
				h.method);
		gw_hlist_free(&hdrs);
		return -1;
	}

	rc = do_proxy(sv, &h, &hdrs, version_09);
	gw_hlist_free(&hdrs);
	if (rc == 1 && !nconn_keepalive)
		rc = -1;
	return rc;
}
