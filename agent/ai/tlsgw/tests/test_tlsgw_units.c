/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_tlsgw_units.c - T7c 纯逻辑单测(黄金值对照 T7C-PROGRESS.md §A 规格)
 */
#define _POSIX_C_SOURCE 200809L

#include "tlsgw/tlsgw.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "desktop/dtcore.h"

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

static void eq_str(const char *name, const char *got, const char *want)
{
	if (got && strcmp(got, want) == 0) {
		pass(name);
	} else {
		char buf[512];

		snprintf(buf, sizeof(buf), "got=[%s] want=[%s]",
			 got ? got : "(null)", want);
		fail(name, buf);
	}
}

/* ---------------- 内存流 ---------------- */

struct memsrc {
	const unsigned char *data;
	size_t len;
	size_t pos;
	int eof_reached;
};

static int mem_read(void *ctx, unsigned char *buf, size_t n)
{
	struct memsrc *m = ctx;
	size_t avail = m->len - m->pos;

	if (avail == 0) {
		m->eof_reached = 1;
		return 0;
	}
	if (n > avail)
		n = avail;
	memcpy(buf, m->data + m->pos, n);
	m->pos += n;
	return (int)n;
}

/* ================= 配置/die ================= */

static const char *fake_env(void *ctx, const char *name)
{
	static char port64[32];
	const char *prefix = ctx;

	if (strcmp(name, "AIK_TLS_GATEWAY_BACKEND") == 0)
		return "127.0.0.1:18761";
	if (strcmp(name, "AIK_TLS_DIR") == 0)
		return "/tmp/aik-t7c";
	if (strcmp(name, "AIK_TLS_GATEWAY_LISTEN") == 0) {
		if (prefix && strcmp(prefix, "novalue") == 0)
			return NULL;
		snprintf(port64, sizeof(port64), "%s", "127.0.0.1:0");
		return port64;
	}
	return NULL;
}

static void case_cfg(void)
{
	struct gw_cfg c;
	char host[64];
	int port = -1;

	gw_cfg_from_env(&c, NULL, NULL);
	eq_str("cfg.default.listen", c.listen, "127.0.0.1:8443");
	eq_str("cfg.default.backend", c.backend, "127.0.0.1:8761");
	eq_str("cfg.default.tlsdir", c.tls_dir, "/etc/aikernel/tls");
	eq_str("cfg.default.crt", c.server_crt, "/etc/aikernel/tls/server.crt");
	eq_str("cfg.default.key", c.server_key, "/etc/aikernel/tls/server.key");
	eq_str("cfg.default.ca", c.ca_crt, "/etc/aikernel/tls/ca.crt");

	gw_cfg_from_env(&c, fake_env, "novalue");
	eq_str("cfg.env.backend", c.backend, "127.0.0.1:18761");
	eq_str("cfg.env.tlsdir", c.tls_dir, "/tmp/aik-t7c");
	eq_str("cfg.env.crt", c.server_crt, "/tmp/aik-t7c/server.crt");

	ok("listen.parse.ok", gw_parse_listen("127.0.0.1:8443", host,
					      sizeof(host), &port) == 0 &&
	   strcmp(host, "127.0.0.1") == 0 && port == 8443, "");
	ok("listen.parse.port0", gw_parse_listen("0.0.0.0:0", host,
						 sizeof(host), &port) == 0 &&
	   port == 0, "");
	{
		struct { const char *v; int ok; } cases[] = {
			{ "localhost", 0 }, { "1.2.3.4:x", 0 },
			{ "1.2.3.4:", 0 }, { "1.2.3.4:99999", 0 },
			{ "1.2.3.4:-1", 0 }, { "a:b:c", 0 },
			{ "[::1]:8443", 1 },
		};
		int i;
		int allok = 1;

		for (i = 0; i < 7; i++) {
			int r = gw_parse_listen(cases[i].v, host, sizeof(host),
						&port);

			if ((r == 0) != cases[i].ok)
				allok = 0;
		}
		ok("listen.parse.neg", allok, "负例集");
		{
			char h[64];
			int p;

			gw_parse_listen("[::1]:8443", h, sizeof(h), &p);
			ok("listen.parse.ipv6ish",
			   strcmp(h, "[::1]") == 0 && p == 8443, "");
		}
	}
	{
		char msg[512];

		gw_listen_bad_msg("localhost", msg, sizeof(msg));
		eq_str("listen.bad.msg", msg,
		       "AIK_TLS_GATEWAY_LISTEN 格式应为 host:port，当前 'localhost'");
		gw_listen_fail_msg("127.0.0.1:8443", EADDRINUSE, msg,
				   sizeof(msg));
		eq_str("listen.fail.msg", msg,
		       "监听 127.0.0.1:8443 失败: [Errno 98] Address already in use");
	}
	{
		FILE *f = fopen("/dev/null", "w");

		gw_die_msg(f, "boom");
		fclose(f);
		pass("die.msg.written");
	}
}

/* ================= py 工具 ================= */

static char *repr_str(const char *s)
{
	struct dt_sbuf sb;

	dt_sb_init(&sb);
	gw_py_repr_str(&sb, s);
	return dt_sb_finish(&sb);
}

static char *repr_bytes(const unsigned char *b, size_t n)
{
	struct dt_sbuf sb;

	dt_sb_init(&sb);
	gw_py_repr_bytes(&sb, b, n);
	return dt_sb_finish(&sb);
}

static void case_pytools(void)
{
	char *s;

	s = repr_str("abc");
	eq_str("repr.str.plain", s, "'abc'");
	free(s);
	s = repr_str("a'b");
	eq_str("repr.str.dquote", s, "\"a'b\"");
	free(s);
	s = repr_str("a\"b'c");
	eq_str("repr.str.sq_with_dq", s, "'a\"b\\'c'");
	free(s);
	s = repr_str("x\ty\nz");
	eq_str("repr.str.ctrl", s, "'x\\ty\\nz'");
	free(s);
	s = repr_str("\x01\x7f");
	eq_str("repr.str.hex", s, "'\\x01\\x7f'");
	free(s);
	s = repr_bytes((const unsigned char *)"zz", 2);
	eq_str("repr.bytes.zz", s, "b'zz'");
	free(s);
	{
		struct dt_sbuf sb;

		dt_sb_init(&sb);
		gw_int10_errmsg(&sb, "abc");
		s = dt_sb_finish(&sb);
		eq_str("int10.err", s,
		       "invalid literal for int() with base 10: 'abc'");
		free(s);
		dt_sb_init(&sb);
		gw_int16_errmsg(&sb, (const unsigned char *)"zz", 2);
		s = dt_sb_finish(&sb);
		eq_str("int16.err", s,
		       "invalid literal for int() with base 16: b'zz'");
		free(s);
	}
	eq_str("oserr.refused", gw_oserr_detail(ECONNREFUSED),
	       "[Errno 111] Connection refused");
	eq_str("oserr.timeout", gw_oserr_detail(ETIMEDOUT), "timed out");
	eq_str("oserr.reset", gw_oserr_detail(ECONNRESET),
	       "[Errno 104] Connection reset by peer");
	eq_str("oserr.pipe", gw_oserr_detail(EPIPE),
	       "[Errno 32] Broken pipe");
	eq_str("oserr.remote_disc", gw_remote_disconnected(),
	       "Remote end closed connection without response");
	eq_str("reason.200", gw_reason_phrase(200), "OK");
	eq_str("reason.414", gw_reason_phrase(414), "Request-URI Too Long");
	eq_str("reason.431", gw_reason_phrase(431),
	       "Request Header Fields Too Large");
	eq_str("reason.501", gw_reason_phrase(501), "Not Implemented");
	eq_str("reason.502", gw_reason_phrase(502), "Bad Gateway");
	{
		char d[64];
		size_t n;

		gw_http_date(d, sizeof(d));
		n = strlen(d);
		ok("date.suffix", n >= 5 && strcmp(d + n - 3, "GMT") == 0,
		   d);
		ok("date.shape", n == 29 && d[3] == ',' && d[4] == ' ' &&
		   d[5] >= '0' && d[5] <= '9' && d[6] >= '0' && d[6] <= '9' &&
		   d[7] == ' ' && d[8] >= 'A' && d[8] <= 'Z' && d[11] == ' ' &&
		   d[12] >= '0' && d[12] <= '9' && d[16] == ' ' &&
		   d[17] >= '0' && d[17] <= '9' && d[19] == ':' &&
		   d[22] == ':', d);
	}
}

/* ================= 请求行 ================= */

static void case_reqline(void)
{
	struct gw_reqline h;
	char buf[512];

	snprintf(buf, sizeof(buf), "GET /x?a=1 HTTP/1.1");
	ok("rl.basic", gw_parse_request_line(buf, &h) == GW_PARSE_OK &&
	   strcmp(h.method, "GET") == 0 && strcmp(h.target, "/x?a=1") == 0 &&
	   h.close_conn == 0 && h.version_11 == 1 && h.version_09 == 0, "");

	snprintf(buf, sizeof(buf), "GET //healthz  ");
	/* 两词 0.9 GET(尾随空白由 split 吃掉) */
	ok("rl.09get", gw_parse_request_line(buf, &h) == GW_PARSE_OK &&
	   h.version_09 == 1 && h.close_conn == 1 &&
	   strcmp(h.target, "/healthz") == 0, "");

	snprintf(buf, sizeof(buf), "GET //a//b HTTP/1.0");
	ok("rl.fold", gw_parse_request_line(buf, &h) == GW_PARSE_OK &&
	   strcmp(h.target, "/a//b") == 0 && h.close_conn == 1 &&
	   h.version_11 == 0, "");

	snprintf(buf, sizeof(buf), "GET / HTTP/2.0");
	ok("rl.http2", gw_parse_request_line(buf, &h) == GW_PARSE_HTTP2 &&
	   strcmp(h.last_word, "HTTP/2.0") == 0, "");

	snprintf(buf, sizeof(buf), "GET / HTTP/x.y");
	ok("rl.badver", gw_parse_request_line(buf, &h) ==
	   GW_PARSE_BAD_VERSION, "");

	snprintf(buf, sizeof(buf), "GET / HTTP/1");
	ok("rl.badver1", gw_parse_request_line(buf, &h) ==
	   GW_PARSE_BAD_VERSION, "");

	snprintf(buf, sizeof(buf), "GARBAGE");
	ok("rl.onesyntax", gw_parse_request_line(buf, &h) ==
	   GW_PARSE_BAD_SYNTAX, "");

	snprintf(buf, sizeof(buf), "a b c d");
	ok("rl.fourwords", gw_parse_request_line(buf, &h) ==
	   GW_PARSE_BAD_VERSION, "py:words>=3 末词非 HTTP/ → 坏版本");

	snprintf(buf, sizeof(buf), "POST /x");
	ok("rl.09post", gw_parse_request_line(buf, &h) ==
	   GW_PARSE_NOT_GET09 && strcmp(h.last_word, "POST") == 0, "");

	snprintf(buf, sizeof(buf), "   ");
	ok("rl.blank", gw_parse_request_line(buf, &h) == GW_PARSE_BLANK, "");

	snprintf(buf, sizeof(buf), "  GET   /y   HTTP/1.1  ");
	ok("rl.multispace", gw_parse_request_line(buf, &h) == GW_PARSE_OK &&
	   strcmp(h.target, "/y") == 0, "");

	snprintf(buf, sizeof(buf), "GET / HTTP/1.2");
	ok("rl.12keepalive", gw_parse_request_line(buf, &h) == GW_PARSE_OK &&
	   h.close_conn == 0 && h.version_11 == 1, "");
}

/* ================= 头列表/转发构造 ================= */

static void case_hlist(void)
{
	struct gw_hlist h;

	gw_hlist_init(&h);
	gw_hlist_set(&h, "A", "1");
	gw_hlist_set(&h, "B", "2");
	gw_hlist_set(&h, "A", "3");	/* 同形覆盖保位 */
	ok("hl.order", h.n == 2 && strcmp(h.names[0], "A") == 0 &&
	   strcmp(h.vals[0], "3") == 0 && strcmp(h.names[1], "B") == 0, "");
	eq_str("hl.get_ci", gw_hlist_get_ci(&h, "a"), "3");
	ok("hl.has_ci", gw_hlist_has_ci(&h, "B"), "");
	ok("hl.miss", !gw_hlist_has_ci(&h, "C"), "");
	gw_hlist_free(&h);

	ok("hop.connection", gw_is_hop_by_hop("Connection"), "");
	ok("hop.te", gw_is_hop_by_hop("TE"), "");
	ok("hop.trailers", gw_is_hop_by_hop("Trailers"), "");
	ok("hop.upgrade", gw_is_hop_by_hop("upgrade"), "");
	ok("hop.transfer_encoding", gw_is_hop_by_hop("Transfer-Encoding"), "");
	ok("hop.proxy_conn", gw_is_hop_by_hop("Proxy-Connection"), "");
	ok("hop.keepalive_neg", !gw_is_hop_by_hop("Keepalive"), "");
	ok("hop.auth_neg", !gw_is_hop_by_hop("Authorization"), "");
	ok("hop.host_neg", !gw_is_hop_by_hop("Host"), "");
}

static void case_forward(void)
{
	struct gw_hlist client, out;
	char *req;
	size_t len;

	gw_hlist_init(&client);
	gw_hlist_init(&out);
	gw_hlist_set(&client, "Authorization", "Bearer t");
	gw_hlist_set(&client, "Content-Type", "application/json");
	gw_hlist_set(&client, "Connection", "keep-alive");
	gw_hlist_set(&client, "Transfer-Encoding", "chunked");
	gw_hlist_set(&client, "Host", "evil");
	gw_hlist_set(&client, "X-Forwarded-For", "evil");
	gw_hlist_set(&client, "X-Client-Cert-CN", "evil");

	ok("fwd.build", gw_build_forward(&client, &out, "127.0.0.1:8761",
					 "10.0.0.9", "cli-1") == 0, "");
	ok("fwd.count", out.n == 6, "");
	eq_str("fwd.host", gw_hlist_get_ci(&out, "host"), "127.0.0.1:8761");
	eq_str("fwd.xff", gw_hlist_get_ci(&out, "x-forwarded-for"), "10.0.0.9");
	eq_str("fwd.xfp", gw_hlist_get_ci(&out, "x-forwarded-proto"), "tls");
	eq_str("fwd.xccn", gw_hlist_get_ci(&out, "x-client-cert-cn"), "cli-1");
	ok("fwd.no_hop", !gw_hlist_has_ci(&out, "connection") &&
	   !gw_hlist_has_ci(&out, "transfer-encoding"), "");
	/* XFF/XCCN 原位覆盖(客户端同形头 → 值被注入值替换,保位;
	 * 顺序 = Authorization, Content-Type, XFF, XCCN, Host, XFP) */
	ok("fwd.xff_inplace", out.n == 6 &&
	   strcmp(out.names[2], "X-Forwarded-For") == 0 &&
	   strcmp(out.vals[2], "10.0.0.9") == 0 &&
	   strcmp(out.names[3], "X-Client-Cert-CN") == 0 &&
	   strcmp(out.vals[3], "cli-1") == 0 &&
	   strcmp(out.names[4], "Host") == 0 &&
	   strcmp(out.names[5], "X-Forwarded-Proto") == 0, "");

	req = gw_build_backend_request("GET", "/v1/tools?x=1", &out,
				       (const unsigned char *)"", 0, &len);
	eq_str("req.golden", req,
	       "GET /v1/tools?x=1 HTTP/1.1\r\n"
	       "Accept-Encoding: identity\r\n"
	       "Content-Length: 0\r\n"
	       "Authorization: Bearer t\r\n"
	       "Content-Type: application/json\r\n"
	       "X-Forwarded-For: 10.0.0.9\r\n"
	       "X-Client-Cert-CN: cli-1\r\n"
	       "Host: 127.0.0.1:8761\r\n"
	       "X-Forwarded-Proto: tls\r\n"
	       "\r\n");
	free(req);
	gw_hlist_free(&out);

	/* 客户端带 CL → 不自动补;带 AE → 不补 identity */
	gw_hlist_init(&out);
	gw_hlist_set(&out, "Content-Length", "5");
	gw_hlist_set(&out, "Accept-Encoding", "gzip");
	req = gw_build_backend_request("POST", "/a", &out,
				       (const unsigned char *)"hello", 5,
				       &len);
	eq_str("req.no_auto", req,
	       "POST /a HTTP/1.1\r\n"
	       "Content-Length: 5\r\n"
	       "Accept-Encoding: gzip\r\n"
	       "\r\n"
	       "hello");
	free(req);
	gw_hlist_free(&out);

	/* 小写 content-length 也挡自动补(ci) */
	gw_hlist_init(&out);
	gw_hlist_set(&out, "content-length", "2");
	req = gw_build_backend_request("POST", "/a", &out,
				       (const unsigned char *)"hi", 2, &len);
	ok("req.no_auto_ci", strstr(req, "Content-Length") == NULL &&
	   strstr(req, "content-length: 2") != NULL, req ? req : "");
	free(req);
	gw_hlist_free(&out);
	gw_hlist_free(&client);
}

/* ================= JSON / healthz ================= */

static void case_json(void)
{
	size_t n;
	char *s;

	s = gw_json_kv2("status", "ok", "gateway",
			"aik-tls-gateway 1.0 (W78)", &n);
	eq_str("json.healthz", s,
	       "{\"status\": \"ok\", \"gateway\": \"aik-tls-gateway 1.0 (W78)\"}");
	ok("json.healthz.len", n == strlen(s), "");
	free(s);
	s = gw_json_kv2("error", "bad_request", "detail", "请求体超限", &n);
	eq_str("json.zh", s,
	       "{\"error\": \"bad_request\", \"detail\": \"\\u8bf7\\u6c42\\u4f53\\u8d85\\u9650\"}");
	free(s);
	s = gw_json_kv2("a", "q\"b\\c", "d", "\x01", &n);
	eq_str("json.esc", s, "{\"a\": \"q\\\"b\\\\c\", \"d\": \"\\u0001\"}");
	free(s);
	s = gw_json_kv2("a", "\xf0\x9f\x98\x80", "b", "x", &n);
	eq_str("json.surrogate", s, "{\"a\": \"\\ud83d\\ude00\", \"b\": \"x\"}");
	free(s);
	s = gw_json_kv2("a", "\xe4\xb8\xad", "b", "\xff\xfe bad", &n);
	eq_str("json.bad_utf8", s,
	       "{\"a\": \"\\u4e2d\", \"b\": \"\\ufffd\\ufffd bad\"}");
	free(s);
	ok("hz.hit", gw_healthz_target("/healthz"), "");
	ok("hz.query_miss", !gw_healthz_target("/healthz?x"), "");
	ok("hz.sub_miss", !gw_healthz_target("/healthz/"), "");
}

/* ================= chunk 尺寸行 ================= */

static void case_chunk(void)
{
	long long sz;
	char em[128];

	ok("ck.5", gw_chunk_parse_line("5\r\n", &sz, em, sizeof(em)) == 0 &&
	   sz == 5, "");
	ok("ck.ext", gw_chunk_parse_line("5;name=v\r\n", &sz, em,
					 sizeof(em)) == 0 && sz == 5, "");
	ok("ck.hexA", gw_chunk_parse_line("A\r\n", &sz, em, sizeof(em)) == 0 &&
	   sz == 10, "");
	ok("ck.zero", gw_chunk_parse_line("0\r\n", &sz, em, sizeof(em)) == 0 &&
	   sz == 0, "");
	ok("ck.blank", gw_chunk_parse_line("\r\n", &sz, em, sizeof(em)) == 0 &&
	   sz == 0, "");
	ok("ck.spaces", gw_chunk_parse_line("  7  \r\n", &sz, em,
					    sizeof(em)) == 0 && sz == 7, "");
	ok("ck.0x", gw_chunk_parse_line("0x10\r\n", &sz, em, sizeof(em)) == 0 &&
	   sz == 16, "");
	ok("ck.bad", gw_chunk_parse_line("zz\r\n", &sz, em, sizeof(em)) == -1,
	   "");
	eq_str("ck.bad.msg", em, "invalid literal for int() with base 16: b'zz'");
	ok("ck.inner_space", gw_chunk_parse_line("5 5\r\n", &sz, em,
						 sizeof(em)) == -1, "");
	eq_str("ck.inner.msg", em,
	       "invalid literal for int() with base 16: b'5 5'");
	ok("ck.empty", gw_chunk_parse_line("", &sz, em, sizeof(em)) == 0 &&
	   sz == 0, "");
}

/* ================= 读缓冲(py readline 语义) ================= */

static void case_reader(void)
{
	static const unsigned char data[] = "line1\nAAAA\r\nBBBB\nCCCC";
	struct memsrc src = { data, sizeof(data) - 1, 0, 0 };
	struct gw_stream st = { &src, mem_read, NULL };
	struct gw_reader r;
	unsigned char buf[64];
	char *line;
	size_t len;
	int eof;

	gw_reader_init(&r, &st, buf, sizeof(buf));
	line = gw_reader_readline(&r, 65537, &len, &eof);
	ok("rd.line1", line && strcmp(line, "line1\n") == 0 && len == 6, "");
	free(line);
	line = gw_reader_readline(&r, 65537, &len, &eof);
	ok("rd.line2", line && strcmp(line, "AAAA\r\n") == 0, "");
	free(line);
	/* cap 语义:cap=3 → 'BBB'(py readline(3)) */
	line = gw_reader_readline(&r, 3, &len, &eof);
	ok("rd.cap", line && len == 3 && strncmp(line, "BBB", 3) == 0, "");
	free(line);
	/* 余 'B\nCCCC' → 'B\n' */
	line = gw_reader_readline(&r, 65537, &len, &eof);
	ok("rd.rest1", line && strcmp(line, "B\n") == 0, "");
	free(line);
	/* EOF 短行 'CCCC'(无换行) */
	line = gw_reader_readline(&r, 65537, &len, &eof);
	ok("rd.partial", line && strcmp(line, "CCCC") == 0 && len == 4 &&
	   eof == 1, "");
	free(line);
	/* EOF 后:NULL */
	line = gw_reader_readline(&r, 65537, &len, &eof);
	ok("rd.eof_null", line == NULL && eof == 1, "");
	free(line);
	{
		unsigned char out[8];
		int got;

		/* read_exact 短读 */
		struct memsrc s2 = { (const unsigned char *)"ab", 2, 0, 0 };
		struct gw_stream st2 = { &s2, mem_read, NULL };

		gw_reader_init(&r, &st2, buf, sizeof(buf));
		got = gw_reader_read_exact(&r, out, 5);
		ok("rd.short", got == 2 && out[0] == 'a' && out[1] == 'b',
		   "");
	}
	{
		/* 长行 65537:readline(65537) 返回恰 65537 字节 */
		unsigned char *big = malloc(70000);
		struct memsrc s3;
		struct gw_stream st3;

		memset(big, 'A', 70000);
		s3.data = big;
		s3.len = 70000;
		s3.pos = 0;
		st3.ctx = &s3;
		st3.read = mem_read;
		st3.write = NULL;
		gw_reader_init(&r, &st3, buf, sizeof(buf));
		line = gw_reader_readline(&r, 65537, &len, &eof);
		ok("rd.long_65537", line && len == 65537, "");
		free(line);
		free(big);
	}
}

int main(void)
{
	printf("== T7c tlsgw 纯逻辑单测 ==\n");
	case_cfg();
	case_pytools();
	case_reqline();
	case_hlist();
	case_forward();
	case_json();
	case_chunk();
	case_reader();
	printf("\n%s (fail=%d)\n", g_fail ? "RESULT: FAIL" : "RESULT: ALL PASS",
	       g_fail);
	return g_fail ? 1 : 0;
}
