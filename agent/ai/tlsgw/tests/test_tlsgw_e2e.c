/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_tlsgw_e2e.c - T7c 端到端:
 *   ① 缺证书启动:rc=1 + stderr 逐字(对齐参考 die 文案)
 *   ② 内存流直连 gw_serve_conn:healthz/400/502/转发字节/keep-alive/模板
 *      (mock 后端 = 环回 TCP 线程,记录原始请求字节)
 *   ③ 真 TLS:spawn ./aik-tls-gateway(沙箱证书) + mbedtls 客户端:
 *      有效 mTLS → /healthz 200 + 转发;无证书/野 CA → 握手拒;SIGTERM rc=0
 * 用法: test_tlsgw_e2e <certs_dir> [gateway_binary]
 */
#define _GNU_SOURCE

#include "tlsgw/tlsgw.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "desktop/dtcore.h"

#include "mbedtls/build_info.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

static int g_fail;

static void pass(const char *name) { printf("PASS %s\n", name); }
static void fail(const char *name, const char *why)
{
	printf("FAIL %s: %s\n", name, why);
	g_fail++;
}
static void ok(const char *name, int cond, const char *why)
{
	if (cond)
		pass(name);
	else
		fail(name, why ? why : "");
}

static void *accept_close_main(void *arg);
static int cli_rng(void *ctx, unsigned char *buf, size_t len);

/* ================= mock 后端(环回;记请求字节;脚本响应) ================= */

struct mock_be {
	int lfd;
	int port;
	volatile int stop;
	const char *resp;
	size_t resp_len;
	unsigned char *seen;
	size_t seen_len;
	size_t seen_cap;
	volatile int conns_done;
};

static void be_record(struct mock_be *m, const unsigned char *buf, size_t n)
{
	if (m->seen_len + n > m->seen_cap) {
		size_t cap = m->seen_cap ? m->seen_cap * 2 : 4096;

		while (cap < m->seen_len + n)
			cap *= 2;
		m->seen = realloc(m->seen, cap);
		m->seen_cap = cap;
	}
	memcpy(m->seen + m->seen_len, buf, n);
	m->seen_len += n;
}

static void *mock_be_main(void *arg)
{
	struct mock_be *m = arg;

	while (!m->stop) {
		struct pollfd pfd;
		int cfd;

		pfd.fd = m->lfd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, 100) <= 0)
			continue;
		cfd = accept(m->lfd, NULL, NULL);
		if (cfd < 0)
			continue;
		for (;;) {	/* 读到静默 250ms(网关一次写完) */
			unsigned char buf[8192];
			struct pollfd cp;
			ssize_t n;

			cp.fd = cfd;
			cp.events = POLLIN;
			cp.revents = 0;
			if (poll(&cp, 1, 250) <= 0)
				break;
			n = recv(cfd, buf, sizeof(buf), 0);
			if (n <= 0)
				break;
			be_record(m, buf, (size_t)n);
		}
		if (m->resp_len) {
			size_t off = 0;

			while (off < m->resp_len) {
				ssize_t n = send(cfd, m->resp + off,
						 m->resp_len - off,
						 MSG_NOSIGNAL);

				if (n <= 0)
					break;
				off += (size_t)n;
			}
		}
		close(cfd);
		m->conns_done++;
	}
	return NULL;
}

static void mock_be_start(struct mock_be *m)
{
	struct sockaddr_in sa;
	socklen_t sl;
	int one = 1;
	pthread_t tid;

	memset(m, 0, sizeof(*m));
	m->lfd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(m->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	bind(m->lfd, (struct sockaddr *)&sa, sizeof(sa));
	listen(m->lfd, 8);
	sl = sizeof(sa);
	getsockname(m->lfd, (struct sockaddr *)&sa, &sl);
	m->port = ntohs(sa.sin_port);
	pthread_create(&tid, NULL, mock_be_main, m);
	pthread_detach(tid);
}

static void mock_be_reset(struct mock_be *m, const char *resp,
			  size_t resp_len)
{
	m->seen_len = 0;
	m->resp = resp;
	m->resp_len = resp_len;
}

static void mock_be_stop(struct mock_be *m)
{
	m->stop = 1;
	usleep(250000);
	close(m->lfd);
	free(m->seen);
}

/* 等第 n 个后端连接完成(mock 串行化;3s 超时) */
static int be_wait(struct mock_be *be, int expect)
{
	int i;

	for (i = 0; i < 3000; i++) {
		if (be->conns_done >= expect)
			return 1;
		usleep(1000);
	}
	return be->conns_done >= expect;
}

/* ================= 内存流直连 gw_serve_conn ================= */

struct memsrc {
	const unsigned char *data;
	size_t len;
	size_t pos;
};

struct memsink {
	unsigned char buf[262144];
	size_t len;
};

struct rw_ctx {
	struct memsrc *src;
	struct memsink *sink;
};

static int rw_read(void *ctx, unsigned char *buf, size_t n)
{
	struct rw_ctx *c = ctx;
	size_t avail = c->src->len - c->src->pos;

	if (avail == 0)
		return 0;
	if (n > avail)
		n = avail;
	memcpy(buf, c->src->data + c->src->pos, n);
	c->src->pos += n;
	return (int)n;
}

static int rw_write(void *ctx, const unsigned char *buf, size_t n)
{
	struct rw_ctx *c = ctx;

	if (c->sink->len + n > sizeof(c->sink->buf))
		return -1;
	memcpy(c->sink->buf + c->sink->len, buf, n);
	c->sink->len += n;
	return 0;
}

static struct gw_cfg g_tcfg;

static void serve_setup(struct gw_serve *sv, struct gw_stream *io,
			struct rw_ctx *ctx, struct memsrc *src,
			struct memsink *sink, int backend_port)
{
	io->ctx = ctx;
	io->read = rw_read;
	io->write = rw_write;
	ctx->src = src;
	ctx->sink = sink;
	memset(sv, 0, sizeof(*sv));
	sv->io = io;
	sv->cfg = &g_tcfg;
	snprintf(sv->backend_host, sizeof(sv->backend_host), "127.0.0.1");
	sv->backend_port = backend_port;
	/* Host 头与 502 detail 均取 BACKEND 串(与连接端口一致,py 同源) */
	snprintf(g_tcfg.backend, sizeof(g_tcfg.backend), "127.0.0.1:%d",
		 backend_port);
	sv->peer_ip = "127.0.0.1";
	sv->cn = "gw-test-client";
	sv->log = NULL;
}

/* 返回 gw_serve_conn rc(1=keep);响应字节在 out;req 长度一律 strlen */
static int serve_once(const char *req, struct memsink *out, int backend_port)
{
	struct memsrc src = { (const unsigned char *)req, strlen(req), 0 };
	struct rw_ctx ctx;
	struct gw_stream io;
	struct gw_serve sv;

	memset(out, 0, sizeof(*out));
	serve_setup(&sv, &io, &ctx, &src, out, backend_port);
	return gw_serve_conn(&sv);
}

static int serve_all(const char *req, struct memsink *out, int backend_port)
{
	struct memsrc src = { (const unsigned char *)req, strlen(req), 0 };
	struct rw_ctx ctx;
	struct gw_stream io;
	struct gw_serve sv;

	memset(out, 0, sizeof(*out));
	serve_setup(&sv, &io, &ctx, &src, out, backend_port);
	while (gw_serve_conn(&sv) > 0)
		;
	return (int)out->len;
}

static void eq_bytes(const char *name, const void *got, size_t got_len,
		     const char *want, size_t want_len)
{
	if (got_len == want_len && memcmp(got, want, want_len) == 0) {
		pass(name);
	} else {
		char tmp[128];
		size_t i;

		snprintf(tmp, sizeof(tmp), "len %zu vs %zu", got_len,
			 want_len);
		fail(name, tmp);
		for (i = 0; i < got_len && i < want_len && i < 200; i++) {
			if (((const unsigned char *)got)[i] !=
			    (unsigned char)want[i]) {
				printf("     first diff @%zu: got 0x%02x want 0x%02x\n",
				       i, ((const unsigned char *)got)[i],
				       (unsigned char)want[i]);
				break;
			}
		}
	}
}

/* Date 值归一(T6 先例白名单;头名/序仍比) */
static void eq_norm_date(const char *name, const char *got, size_t got_len,
			 const char *want, size_t want_len)
{
	char g2[131072], w2[131072];
	size_t gl = 0, wl = 0;
	const char *p;
	int bad = 0;

	for (p = got; p < got + got_len && !bad;) {
		const char *nl = memchr(p, '\n', (size_t)(got + got_len - p));
		size_t ln = nl ? (size_t)(nl - p) + 1
			       : (size_t)(got + got_len - p);

		if (strncmp(p, "Date: ", 6) == 0) {
			if (gl + 9 > sizeof(g2)) { bad = 1; break; }
			memcpy(g2 + gl, "Date: X\r\n", 9);
			gl += 9;
		} else {
			if (gl + ln > sizeof(g2)) { bad = 1; break; }
			memcpy(g2 + gl, p, ln);
			gl += ln;
		}
		if (!nl)
			break;
		p = nl + 1;
	}
	for (p = want; p < want + want_len && !bad;) {
		const char *nl = memchr(p, '\n', (size_t)(want + want_len - p));
		size_t ln = nl ? (size_t)(nl - p) + 1
			       : (size_t)(want + want_len - p);

		if (strncmp(p, "Date: ", 6) == 0) {
			if (wl + 9 > sizeof(w2)) { bad = 1; break; }
			memcpy(w2 + wl, "Date: X\r\n", 9);
			wl += 9;
		} else {
			if (wl + ln > sizeof(w2)) { bad = 1; break; }
			memcpy(w2 + wl, p, ln);
			wl += ln;
		}
		if (!nl)
			break;
		p = nl + 1;
	}
	if (!bad && gl == wl && memcmp(g2, w2, gl) == 0) {
		pass(name);
	} else {
		char tmp[96];

		snprintf(tmp, sizeof(tmp), "norm len %zu vs %zu (bad=%d)",
			 gl, wl, bad);
		fail(name, tmp);
	}
}

static void dump160(const char *tag, const void *buf, size_t len)
{
	if (!getenv("AIK_T7C_DEBUG"))
		return;
	const unsigned char *b = buf;
	size_t i;

	fprintf(stderr, "@DUMP %s len=%zu: ", tag, len);
	for (i = 0; i < len && i < 760; i++)
		fprintf(stderr, "%02x ", b[i]);
	fprintf(stderr, "\n");
}

/* 网关自产 JSON 响应构造(Server 值为 C 侧值;Date 归一) */
static int build_json_resp(char *out, size_t cap, int code, const char *phrase,
			   const char *body)
{
	return snprintf(out, cap,
			"HTTP/1.1 %d %s\r\n"
			"Server: %s\r\n"
			"Date: X\r\n"
			"Content-Type: application/json\r\n"
			"Content-Length: %zu\r\n"
			"\r\n"
			"%s",
			code, phrase, GW_SERVER_HDR, strlen(body), body);
}

static int has(const unsigned char *hay, size_t n, const char *needle)
{
	return memmem(hay, n, needle, strlen(needle)) != NULL;
}

/* ---- ② 内存流场景 ---- */

/* mock 后端响应与期望输出(尺寸一律 sizeof-1,杜绝手数) */
#define R_CT "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" \
	     "Content-Length: 2\r\n\r\nhi"
#define R_BYE "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbye"
#define R_204 "HTTP/1.1 204 No Content\r\n\r\n"
#define R_A "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA"
#define R_Z "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nZ"
#define R_SSE "HTTP/1.1 200 OK\r\nX-Sse: yes\r\n\r\ndata: a\ndata: b\n"
#define R_CHUNKED "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" \
		  "3\r\nabc\r\n0\r\n\r\n"
#define R_CL0 "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
#define E_SSE_RECHUNK "HTTP/1.1 200 OK\r\nX-Sse: yes\r\n" \
		      "Transfer-Encoding: chunked\r\n\r\n" \
		      "10\r\ndata: a\ndata: b\n\r\n0\r\n\r\n"

static void case_serve_plain(struct mock_be *be)
{
	struct memsink out;
	int r;
	char want[4096];
	int n;
	char be_str[64];

	snprintf(be_str, sizeof(be_str), "127.0.0.1:%d", be->port);

	/* healthz */
	r = serve_once("GET /healthz HTTP/1.1\r\n\r\n", &out, be->port);
	ok("pl.healthz.keepalive", r == 1, "keep-alive rc");
	n = build_json_resp(want, sizeof(want), 200, "OK",
			     "{\"status\": \"ok\", \"gateway\": "
			     "\"aik-tls-gateway 1.0 (W78)\"}");
	eq_norm_date("pl.healthz", (char *)out.buf, out.len, want,
		     (size_t)n);

	/* 转发:GET + Bearer → mock 收到 py 形状字节(黄金) */
	mock_be_reset(be, R_CT, sizeof(R_CT) - 1);
	serve_once("GET /v1/tools?x=1 HTTP/1.1\r\n"
		   "Authorization: Bearer t123\r\n"
		   "\r\n", &out, be->port);
	n = snprintf(want, sizeof(want),
		     "GET /v1/tools?x=1 HTTP/1.1\r\n"
		     "Accept-Encoding: identity\r\n"
		     "Content-Length: 0\r\n"
		     "Authorization: Bearer t123\r\n"
		     "Host: %s\r\n"
		     "X-Forwarded-For: 127.0.0.1\r\n"
		     "X-Forwarded-Proto: tls\r\n"
		     "X-Client-Cert-CN: gw-test-client\r\n"
		     "\r\n", be_str);
	ok("pl.fwd.sync", be_wait(be, 1), "mock conn 1");
	eq_bytes("pl.fwd.request_bytes", be->seen, be->seen_len, want,
		 (size_t)n);
	/* relay 字节原样回客户端 */
	eq_bytes("pl.relay.bytes", out.buf, out.len, R_CT, sizeof(R_CT) - 1);

	/* POST 体 + CL 透传(体恰 10 字节,CL=10) */
	mock_be_reset(be, R_BYE, sizeof(R_BYE) - 1);
	serve_once("POST /v1/ask HTTP/1.1\r\n"
		   "Content-Length: 10\r\n"
		   "Content-Type: application/json\r\n"
		   "\r\n"
		   "{\"q\":\"hi\"}", &out, be->port);
	ok("pl.post.sync", be_wait(be, 2), "mock conn 2");
	ok("pl.post.fwd",
	   be->seen_len > 66 &&
	   memcmp(be->seen, "POST /v1/ask HTTP/1.1\r\n", 23) == 0 &&
	   has(be->seen, be->seen_len, "Content-Length: 10\r\n") &&
	   be->seen_len >= 10 &&
	   memcmp(be->seen + be->seen_len - 10, "{\"q\":\"hi\"}", 10) == 0,
	   "体与 CL 透传");

	/* chunked 请求体 → 解码 + 自动 CL + TE 剥除 */
	mock_be_reset(be, R_204, sizeof(R_204) - 1);
	serve_once("POST /c HTTP/1.1\r\n"
		   "Transfer-Encoding: chunked\r\n"
		   "\r\n"
		   "5\r\nhello\r\n"
		   "6\r\n world\r\n"
		   "0\r\n\r\n", &out, be->port);
	ok("pl.chunked.sync", be_wait(be, 3), "mock conn 3");
	ok("pl.chunked.decode",
	   has(be->seen, be->seen_len, "Content-Length: 11\r\n") &&
	   be->seen_len >= 11 &&
	   memcmp(be->seen + be->seen_len - 11, "hello world", 11) == 0 &&
	   !has(be->seen, be->seen_len, "Transfer-Encoding"),
	   "去块解码+自动 CL");
	eq_bytes("pl.relay.204", out.buf, out.len,
		 "HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		 25 + 28 + 2 + 5);  /* py: 无 CL(含204)一律重分块 */

	/* 502 refused(端口 1 无人听) */
	serve_once("GET /x HTTP/1.1\r\n\r\n", &out, 1);
	n = build_json_resp(want, sizeof(want), 502, "Bad Gateway",
			     "{\"error\": \"bad_gateway\", \"detail\": "
			     "\"127.0.0.1:1: [Errno 111] Connection "
			     "refused\"}");
	eq_norm_date("pl.502.refused", (char *)out.buf, out.len, want,
		     (size_t)n);

	/* 400:CL 非法 */
	serve_once("POST /b HTTP/1.1\r\n"
		   "Content-Length: abc\r\n"
		   "\r\n", &out, be->port);
	n = build_json_resp(want, sizeof(want), 400, "Bad Request",
			     "{\"error\": \"bad_request\", \"detail\": "
			     "\"invalid literal for int() with base 10: "
			     "'abc'\"}");
	eq_norm_date("pl.400.cl", (char *)out.buf, out.len, want, (size_t)n);

	/* 400:chunked 坏 hex */
	serve_once("POST /c HTTP/1.1\r\n"
		   "Transfer-Encoding: chunked\r\n"
		   "\r\n"
		   "zz\r\n", &out, be->port);
	n = build_json_resp(want, sizeof(want), 400, "Bad Request",
			     "{\"error\": \"bad_request\", \"detail\": "
			     "\"invalid literal for int() with base 16: "
			     "b'zz'\"}");
	eq_norm_date("pl.400.chunk", (char *)out.buf, out.len, want,
		     (size_t)n);

	/* 400:体超限(中文转义) */
	serve_once("POST /c HTTP/1.1\r\n"
		   "Content-Length: 67108865\r\n"
		   "\r\n", &out, be->port);
	n = build_json_resp(want, sizeof(want), 400, "Bad Request",
			     "{\"error\": \"bad_request\", \"detail\": "
			     "\"\\u8bf7\\u6c42\\u4f53\\u8d85\\u9650\"}");
	eq_norm_date("pl.400.overflow", (char *)out.buf, out.len, want,
		     (size_t)n);

	/* 501 未覆写方法(HEAD 无体语义由模板参数承担) */
	r = serve_once("FOOBAR / HTTP/1.1\r\n\r\n", &out, be->port);
	ok("pl.501",
	   r < 0 &&
	   memcmp(out.buf,
		  "HTTP/1.1 501 Unsupported method ('FOOBAR')\r\n",
		  sizeof("HTTP/1.1 501 Unsupported method ('FOOBAR')\r\n") - 1)
	       == 0 &&
	   has(out.buf, out.len, "Connection: close\r\n") &&
	   has(out.buf, out.len, "Unsupported method ('FOOBAR')") &&
	   has(out.buf, out.len,
	       "Error code explanation: HTTPStatus.NOT_IMPLEMENTED - "
	       "Server does not support this operation") &&
	   has(out.buf, out.len, "Content-Type: text/html;charset=utf-8"),
	   "");
	dump160("p501-out", out.buf, out.len);

	/* 400 坏语法模板(HTML 体) */
	serve_once("GARBAGE\r\n\r\n", &out, be->port);
	ok("pl.400.syntax",
	   out.len > 40 &&
	   memcmp(out.buf, "<!DOCTYPE HTML PUBLIC", 21) == 0 &&
	   !has(out.buf, out.len, "HTTP/1.1 400") &&
	   has(out.buf, out.len, "Bad request syntax ('GARBAGE')") &&
	   has(out.buf, out.len,
	       "Error code explanation: HTTPStatus.BAD_REQUEST - "
	       "Bad request syntax or unsupported method"),
	   "");

	/* 505 */
	serve_once("GET / HTTP/2.0\r\n\r\n", &out, be->port);
	ok("pl.505",
	   memcmp(out.buf, "<!DOCTYPE HTML PUBLIC", 21) == 0 &&
	   !has(out.buf, out.len, "HTTP/1.1 505") &&
	   has(out.buf, out.len, "Invalid HTTP version (2.0)") &&
	   has(out.buf, out.len,
	       "Error code explanation: "
	       "HTTPStatus.HTTP_VERSION_NOT_SUPPORTED - "
	       "Cannot fulfill request"),
	   "");

	/* 414(>65536 请求行) */
	{
		char *big = malloc(70000);
		struct memsrc src;
		struct rw_ctx ctx;
		struct gw_stream io;
		struct gw_serve sv;

		memset(big, 'A', 70000);
		memcpy(big, "GET /", 5);
		src.data = (const unsigned char *)big;
		src.len = 70000;
		src.pos = 0;
		memset(&out, 0, sizeof(out));
		serve_setup(&sv, &io, &ctx, &src, &out, be->port);
		ok("pl.414",
		   gw_serve_conn(&sv) < 0 &&
		   memcmp(out.buf,
			  "HTTP/1.1 414 Request-URI Too Long\r\n",
			  33) == 0,
		   "");
		free(big);
	}

	/* 431:头行 >65536 */
	{
		char *big = malloc(70000);
		struct memsrc src;
		struct rw_ctx ctx;
		struct gw_stream io;
		struct gw_serve sv;

		memcpy(big, "GET / HTTP/1.1\r\nX-Big: ", 23);
		memset(big + 23, 'A', 70000 - 23);
		src.data = (const unsigned char *)big;
		src.len = 70000;
		src.pos = 0;
		memset(&out, 0, sizeof(out));
		serve_setup(&sv, &io, &ctx, &src, &out, be->port);
		ok("pl.431",
	   gw_serve_conn(&sv) < 0 &&
	   memcmp(out.buf, "<!DOCTYPE HTML PUBLIC", 21) == 0 &&
	   !has(out.buf, out.len, "HTTP/1.1 431") &&
	   has(out.buf, out.len,
	       "Error code explanation: "
	       "HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE - "
	       "got more than 65536 bytes when reading header "
	       "line."),
	   "");
		free(big);
	}

	/* keep-alive 两请求同流 */
	mock_be_reset(be, R_A, sizeof(R_A) - 1);
	r = serve_all("GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n",
		      &out, be->port);
	be_wait(be, 5);
	ok("pl.keepalive.two",
	   r == 2 * (int)(sizeof(R_A) - 1) &&
	   memcmp(out.buf, R_A, sizeof(R_A) - 1) == 0 &&
	   memcmp(out.buf + sizeof(R_A) - 1, R_A, sizeof(R_A) - 1) == 0,
	   "");

	/* Connection: close → 响应后断 */
	r = serve_once("GET /a HTTP/1.1\r\nConnection: close\r\n\r\n",
		       &out, be->port);
	ok("pl.close", r < 0 && out.len == sizeof(R_A) - 1, "");
	be_wait(be, 6);

	/* 后端无 CL(EOF 体) → 重分块 */
	mock_be_reset(be, R_SSE, sizeof(R_SSE) - 1);
	serve_once("GET /s HTTP/1.1\r\n\r\n", &out, be->port);
	ok("pl.rechunk.sync", be_wait(be, 7), "mock conn 7");
	eq_bytes("pl.rechunk", out.buf, out.len, E_SSE_RECHUNK,
		 sizeof(E_SSE_RECHUNK) - 1);
	dump160("rechunk-out", out.buf, out.len);

	/* 后端 chunked 响应 → TE 剥,体去块,无 CL → 重分块 */
	mock_be_reset(be, R_CHUNKED, sizeof(R_CHUNKED) - 1);
	serve_once("GET /s HTTP/1.1\r\n\r\n", &out, be->port);
	ok("pl.bechunked.sync", be_wait(be, 8), "mock conn 8");
	eq_bytes("pl.be_chunked", out.buf, out.len, R_CHUNKED,
		 sizeof(R_CHUNKED) - 1);

	/* Expect: 100-continue(interim + Expect 剥除 + 体转发) */
	mock_be_reset(be, R_CL0, sizeof(R_CL0) - 1);
	serve_once("POST /e HTTP/1.1\r\n"
		   "Expect: 100-continue\r\n"
		   "Content-Length: 2\r\n"
		   "\r\nhi", &out, be->port);
	ok("pl.expect100",
	   memcmp(out.buf, "HTTP/1.1 100 Continue\r\n\r\n", 25) == 0,
	   "interim 100");
	ok("pl.expect100.sync", be_wait(be, 9), "mock conn 9");
	dump160("expect100-seen", be->seen, be->seen_len);
	ok("pl.expect100.fwd",
	   has(be->seen, be->seen_len, "Expect: 100-continue\r\n") &&
	   be->seen_len >= 2 &&
	   memcmp(be->seen + be->seen_len - 2, "hi", 2) == 0,
	   "Expect 非逐跳头按 py 语义原样转发+体");

	/* 后端收下连接即断无响应 → 502 RemoteDisconnected */
	{
		pthread_t tid;
		pthread_attr_t at;
		struct sockaddr_in sa;
		socklen_t sl;
		int port2;
		static int lfd;
		int one = 1;
		char jbody[512];

		lfd = socket(AF_INET, SOCK_STREAM, 0);
		setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sa.sin_port = 0;
		bind(lfd, (struct sockaddr *)&sa, sizeof(sa));
		listen(lfd, 1);
		sl = sizeof(sa);
		getsockname(lfd, (struct sockaddr *)&sa, &sl);
		port2 = ntohs(sa.sin_port);
		pthread_attr_init(&at);
		pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
		pthread_create(&tid, &at, accept_close_main, &lfd);
		pthread_attr_destroy(&at);
		serve_once("GET /d HTTP/1.1\r\n\r\n", &out, port2);
		snprintf(jbody, sizeof(jbody),
			 "{\"error\": \"bad_gateway\", \"detail\": "
			 "\"127.0.0.1:%d: Remote end closed connection "
			 "without response\"}", port2);
		n = build_json_resp(want, sizeof(want), 502, "Bad Gateway",
				    jbody);
		eq_norm_date("pl.502.remote_disc", (char *)out.buf, out.len,
			     want, (size_t)n);
	}
}

static void *accept_close_main(void *arg)
{
	int lfd = *(int *)arg;
	int cfd = accept(lfd, NULL, NULL);

	if (cfd >= 0)
		close(cfd);	/* 收下即断,无响应 */
	close(lfd);
	return NULL;
}

/* ================= ① 缺证书启动(rc+stderr 逐字) ================= */

static void case_missing_cert(const char *gwbin)
{
	char dir[256];
	char cmd[8192];
	char out[4096];
	int rc;
	FILE *f;
	size_t n = 0;

	snprintf(dir, sizeof(dir), "/tmp/aik-t7c-nonexist-%ld",
		 (long)getpid());
	snprintf(cmd, sizeof(cmd),
		 "rm -rf %s; mkdir -p %s; "
		 "AIK_TLS_DIR=%s AIK_TLS_GATEWAY_LISTEN=127.0.0.1:0 "
		 "%s 2>/tmp/aik-t7c-t1.err", dir, dir, dir, gwbin);
	rc = WEXITSTATUS(system(cmd));
	f = fopen("/tmp/aik-t7c-t1.err", "r");
	out[0] = '\0';
	if (f) {
		n = fread(out, 1, sizeof(out) - 1, f);
		out[n] = '\0';
		fclose(f);
	}
	{
		char want[512];

		snprintf(want, sizeof(want),
			 "aik-tls-gateway: 缺少证书文件 %s/server.crt"
			 "（不自动生成；生成方法见 "
			 "/usr/local/share/doc/aik-tls-gateway/README.md）\n",
			 dir);
		ok("t1.rc", rc == 1, "rc != 1");
		eq_bytes("t1.stderr", out, strlen(out), want, strlen(want));
	}
}

/* ================= ③ 真 TLS(spawn 网关 + mbedtls 客户端) ================= */

static int cli_rng(void *ctx, unsigned char *buf, size_t len)
{
	FILE *f;

	(void)ctx;
	f = fopen("/dev/urandom", "r");
	if (!f)
		return -1;
	if (fread(buf, 1, len, f) != len) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

struct tls_cli {
	char ca[512];
	char crt[512];
	char key[512];		/* 空 = 不带客户端证书 */
};

static int tls_client_run(const struct tls_cli *c, int port,
			  unsigned char *resp, size_t resp_cap,
			  size_t *resp_len, const char *req, size_t req_len)
{
	mbedtls_net_context net;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt ca, own;
	mbedtls_pk_context key;
	char portstr[8];
	int rc = -1;

	mbedtls_net_init(&net);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&ca);
	mbedtls_x509_crt_init(&own);
	mbedtls_pk_init(&key);
	snprintf(portstr, sizeof(portstr), "%d", port);

	if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT) != 0)
		goto out;
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	mbedtls_ssl_conf_rng(&conf, cli_rng, NULL);
	if (mbedtls_x509_crt_parse_file(&ca, c->ca) != 0)
		goto out;
	mbedtls_ssl_conf_ca_chain(&conf, &ca, NULL);
	if (c->key[0]) {
		if (mbedtls_x509_crt_parse_file(&own, c->crt) != 0 ||
		    mbedtls_pk_parse_keyfile(&key, c->key, NULL, cli_rng,
					     NULL) != 0 ||
		    mbedtls_ssl_conf_own_cert(&conf, &own, &key) != 0)
			goto out;
	}
	if (mbedtls_ssl_setup(&ssl, &conf) != 0)
		goto out;
	mbedtls_ssl_set_hostname(&ssl, "127.0.0.1");
	if (mbedtls_net_connect(&net, "127.0.0.1", portstr,
				MBEDTLS_NET_PROTO_TCP) != 0)
		goto out;
	mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv,
			    NULL);
	{
		int hrc = mbedtls_ssl_handshake(&ssl);

		if (hrc != 0) {
			fprintf(stderr, "@cli hs-fail rc=%d\n", hrc);
			goto out;
		}
	}
	rc = 0;
	if (req && req_len) {
		size_t off = 0;

		while (off < req_len) {
			int w = mbedtls_ssl_write(&ssl,
						  (const unsigned char *)
						   req + off,
						  req_len - off);

			if (w <= 0) {
				fprintf(stderr, "@cli write-fail w=%d\n", w);
				rc = -1;	/* "成功"握手后写失败=被拒 */
				goto out;
			}
			off += (size_t)w;
		}
	}
	{
		size_t got = 0;
		unsigned char scratch[512];

		/* 一律读一次:被拒(alert/EOF)在此显形 */
		for (;;) {
			unsigned char *dst = resp ? resp + got : scratch;
			size_t room = resp ? resp_cap - got : sizeof(scratch);
			int rd = mbedtls_ssl_read(&ssl, dst, room);

			if (rd < 0)
				fprintf(stderr, "@cli read-rc=%d\n", rd);
			if (rd <= 0) {
				if (rd < 0 && got == 0)
					rc = -1;	/* 0 字节即错 = 被拒 */
				break;
			}
			got += (size_t)rd;
			if (resp && got >= resp_cap)
				break;
			if (!resp)
				break;	/* 负例只验一读 */
		}
		if (resp)
			*resp_len = got;
	}
out:
	mbedtls_ssl_free(&ssl);
	mbedtls_net_free(&net);
	mbedtls_ssl_config_free(&conf);
	mbedtls_x509_crt_free(&ca);
	mbedtls_x509_crt_free(&own);
	mbedtls_pk_free(&key);
	return rc;
}

static int spawn_gateway(const char *gwbin, const char *certs, int backend,
			 pid_t *pid, int *port, char *errbuf, size_t errcap)
{
	int pfd[2];
	char be[64];
	FILE *f;
	char line[256];

	if (pipe(pfd) != 0)
		return -1;
	*pid = fork();
	if (*pid == 0) {
		close(pfd[0]);
		dup2(pfd[1], 1);
		close(pfd[1]);
		snprintf(be, sizeof(be), "127.0.0.1:%d", backend);
		setenv("AIK_TLS_GATEWAY_LISTEN", "127.0.0.1:0", 1);
		setenv("AIK_TLS_GATEWAY_BACKEND", be, 1);
		setenv("AIK_TLS_DIR", certs, 1);
		execl(gwbin, gwbin, (char *)NULL);
		_exit(127);
	}
	close(pfd[1]);
	f = fdopen(pfd[0], "r");
	*port = -1;
	line[0] = '\0';
	if (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "LISTENING ", 10) == 0) {
			/* 端口 = "LISTENING host:port -> ..." 中
			 * 第一个 " -> " 之前的最后一个冒号 */
			char *sp = strstr(line, " -> ");
			char *colon = NULL;
			char *p;

			for (p = line + 10; p < sp && sp; p++)
				if (*p == ':')
					colon = p;
			if (colon && sp)
				*port = atoi(colon + 1);
		}
	}
	fclose(f);
	if (*port <= 0) {
		int st;

		if (errbuf)
			snprintf(errbuf, errcap, "spawn: %s", line);
		waitpid(*pid, &st, 0);
		return -1;
	}
	return 0;
}

static void case_tls(const char *gwbin, const char *certs, struct mock_be *be)
{
	pid_t pid;
	int port;
	unsigned char resp[8192];
	size_t resp_len = 0;
	char err[256];
	struct tls_cli valid, nocert, rogue;
	/* Connection: close → 服务端答完即关,客户端读到 EOF(否则死等) */
	static const char HEALTHZ_REQ[] =
		"GET /healthz HTTP/1.1\r\nConnection: close\r\n\r\n";

	snprintf(valid.ca, sizeof(valid.ca), "%s/ca.crt", certs);
	snprintf(valid.crt, sizeof(valid.crt), "%s/client.crt", certs);
	snprintf(valid.key, sizeof(valid.key), "%s/client.key", certs);
	snprintf(nocert.ca, sizeof(nocert.ca), "%s/ca.crt", certs);
	nocert.crt[0] = nocert.key[0] = '\0';
	snprintf(rogue.ca, sizeof(rogue.ca), "%s/ca.crt", certs);
	snprintf(rogue.crt, sizeof(rogue.crt), "%s/rogue-client.crt", certs);
	snprintf(rogue.key, sizeof(rogue.key), "%s/rogue-client.key", certs);

	if (spawn_gateway(gwbin, certs, be->port, &pid, &port, err,
			  sizeof(err)) != 0) {
		fail("tls.spawn", err);
		return;
	}
	pass("tls.spawn.LISTENING");
	mock_be_reset(be, R_Z, sizeof(R_Z) - 1);

	/* 有效 mTLS → healthz 200(JSON 精确) */
	if (tls_client_run(&valid, port, resp, sizeof(resp), &resp_len,
			   HEALTHZ_REQ, sizeof(HEALTHZ_REQ) - 1) != 0) {
		fail("tls.valid.handshake", "handshake failed");
	} else {
		pass("tls.valid.handshake");
			/* 拆解断言:逐条定位 */
	ok("hz.len", resp_len == 210, "len");
	ok("hz.prefix",
	   memcmp(resp, "HTTP/1.1 200 OK\r\nServer: ",
		  sizeof("HTTP/1.1 200 OK\r\nServer: ") - 1) == 0, "");
	ok("hz.hdrterm", has(resp, resp_len, "\r\n\r\n"), "");
	ok("hz.tail56", resp_len >= 56 &&
		memcmp(resp + resp_len - 56, "{\"status\": \"ok\", \"gateway\": \"aik-tls-gateway 1.0 (W78)\"}", 56) == 0, "");
	ok("hz.needle", has(resp, resp_len, "\r\n\r\n{\"status\": \"ok\", \"gateway\": \"aik-tls-gateway 1.0 (W78)\"}"), "");
		dump160("healthz-resp", resp, resp_len);
	}

	/* 无客户端证书 → 握手拒 */
	ok("tls.nocert.reject",
	   tls_client_run(&nocert, port, NULL, 0, NULL,
			  HEALTHZ_REQ, sizeof(HEALTHZ_REQ) - 1) != 0, "");

	/* 野 CA 客户端证书 → 握手拒 */
	ok("tls.rogue.reject",
	   tls_client_run(&rogue, port, NULL, 0, NULL,
			  HEALTHZ_REQ, sizeof(HEALTHZ_REQ) - 1) != 0, "");

	/* 有效 mTLS → 转发(经真 TLS 通道;注入头到 mock 后端) */
	resp_len = 0;
	{
		static const char PROXY_REQ[] =
			"GET /v1/tools HTTP/1.1\r\n"
			"Authorization: Bearer zz\r\n"
			"Connection: close\r\n\r\n";

		if (tls_client_run(&valid, port, resp, sizeof(resp),
				   &resp_len, PROXY_REQ,
				   sizeof(PROXY_REQ) - 1) == 0) {
			ok("tls.proxy.relay",
			   resp_len == sizeof(R_Z) - 1 &&
			   memcmp(resp, R_Z, sizeof(R_Z) - 1) == 0,
			   "relay 字节");
			ok("tls.proxy.seen",
			   has(be->seen, be->seen_len,
			       "GET /v1/tools HTTP/1.1") &&
			   has(be->seen, be->seen_len,
			       "X-Client-Cert-CN: gw-test-client\r\n"),
			   "注入头");
			ok("tls.proxy.sync", be_wait(be, 10), "mock conn 10");
		} else {
			fail("tls.proxy.relay", "handshake");
		}
	}

	kill(pid, SIGTERM);
	{
		int st;

		usleep(300000);	/* 等 EXIT/收尾 */
		waitpid(pid, &st, 0);
		ok("tls.sigterm.rc0",
		   WIFEXITED(st) && WEXITSTATUS(st) == 0, "");
	}
	fprintf(stderr, "@case_tls done\n");
}

int main(int argc, char **argv)
{
	const char *certs = argc > 1 ? argv[1] : "/tmp/aik-t7c-certs";
	const char *gwbin = argc > 2 ? argv[2] : "./aik-tls-gateway";
	struct mock_be be;

	signal(SIGPIPE, SIG_IGN);
	{
		static const unsigned char H[] = "hello world";

		ok("canary.has", has(H, 11, "world"), "memmem canary");
		ok("canary.has.at_end", has(H, 11, "rld"), "");
		ok("canary.has.miss", !has(H, 11, "xyz"), "");
	}

	printf("== T7c tlsgw e2e 单测(certs=%s bin=%s) ==\n", certs, gwbin);

	memset(&g_tcfg, 0, sizeof(g_tcfg));
	snprintf(g_tcfg.listen, sizeof(g_tcfg.listen), "127.0.0.1:0");
	snprintf(g_tcfg.backend, sizeof(g_tcfg.backend), "127.0.0.1:1");

	mock_be_start(&be);
	case_serve_plain(&be);
	case_missing_cert(gwbin);
	case_tls(gwbin, certs, &be);
	mock_be_stop(&be);

	printf("\n%s (fail=%d)\n",
	       g_fail ? "RESULT: FAIL" : "RESULT: ALL PASS", g_fail);
	return g_fail ? 1 : 0;
}
