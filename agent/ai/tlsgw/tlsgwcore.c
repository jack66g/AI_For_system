/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tlsgwcore.c - T7c aik-tls-gateway 纯逻辑 + 后端明文 TCP 客户端
 *
 * 规格来源(全部亲读,冻结于 T7C-PROGRESS.md §A):
 *   - 参考 agent/ai/cloud/tls_gateway/aik_tls_gateway.py(257 行)
 *   - /usr/lib/python3.10/http/server.py(BaseHTTPRequestHandler 3.10.12)
 *   - /usr/lib/python3.10/http/client.py(putrequest/_send_request/
 *     _read_headers/_read_status;reason=strip() 亲测)
 * 服务端请求行解析改编自 T7b apihttp.c(同 py 版本已差分证明)。
 */
#define _POSIX_C_SOURCE 200809L

#include "tlsgw/tlsgw.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "desktop/dtcore.h"

/* ================= 配置 / die 文案 ================= */

static const char *env_or(gw_getenv_fn fn, void *ctx, const char *name,
			  const char *dflt)
{
	const char *v = fn ? fn(ctx, name) : NULL;

	return (v && *v) ? v : dflt;
}

void gw_cfg_from_env(struct gw_cfg *c, gw_getenv_fn fn, void *ctx)
{
	memset(c, 0, sizeof(*c));
	snprintf(c->listen, sizeof(c->listen), "%s",
		 env_or(fn, ctx, "AIK_TLS_GATEWAY_LISTEN", "127.0.0.1:8443"));
	snprintf(c->backend, sizeof(c->backend), "%s",
		 env_or(fn, ctx, "AIK_TLS_GATEWAY_BACKEND", "127.0.0.1:8761"));
	snprintf(c->tls_dir, sizeof(c->tls_dir), "%s",
		 env_or(fn, ctx, "AIK_TLS_DIR", "/etc/aikernel/tls"));
	snprintf(c->server_crt, sizeof(c->server_crt), "%s/server.crt",
		 c->tls_dir);
	snprintf(c->server_key, sizeof(c->server_key), "%s/server.key",
		 c->tls_dir);
	snprintf(c->ca_crt, sizeof(c->ca_crt), "%s/ca.crt", c->tls_dir);
}

int gw_parse_listen(const char *listen, char *host, size_t cap, int *port)
{
	const char *colon = strrchr(listen, ':');
	char *end = NULL;
	long v;
	size_t hl;

	if (!colon || colon == listen)
		return -1;	/* rsplit(":",1) 无冒号 → ValueError */
	hl = (size_t)(colon - listen);
	if (hl == 0 || hl >= cap || colon[1] == '\0')
		return -1;
	v = strtol(colon + 1, &end, 10);
	if (!end || *end != '\0' || v < 0 || v > 65535)
		return -1;	/* int() ValueError */
	memcpy(host, listen, hl);
	host[hl] = '\0';
	*port = (int)v;
	return 0;
}

void gw_die_msg(FILE *out, const char *msg)
{
	fprintf(out, "aik-tls-gateway: %s\n", msg);
}

static int file_exists(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int gw_first_missing_cert(const struct gw_cfg *c, char *out, size_t cap)
{
	if (!file_exists(c->server_crt)) {
		snprintf(out, cap, "%s", c->server_crt);
		return 1;
	}
	if (!file_exists(c->server_key)) {
		snprintf(out, cap, "%s", c->server_key);
		return 2;
	}
	if (!file_exists(c->ca_crt)) {
		snprintf(out, cap, "%s", c->ca_crt);
		return 3;
	}
	return 0;
}

void gw_missing_cert_msg(const char *path, char *out, size_t cap)
{
	snprintf(out, cap,
		 "缺少证书文件 %s（不自动生成；生成方法见 "
		 "/usr/local/share/doc/aik-tls-gateway/README.md）", path);
}

void gw_listen_bad_msg(const char *val, char *out, size_t cap)
{
	/* py %r:默认单引号;含单引号且不含双引号 → 双引号 */
	if (strchr(val, '\'') && !strchr(val, '"'))
		snprintf(out, cap,
			 "AIK_TLS_GATEWAY_LISTEN 格式应为 host:port，当前 \"%s\"",
			 val);
	else
		snprintf(out, cap,
			 "AIK_TLS_GATEWAY_LISTEN 格式应为 host:port，当前 '%s'",
			 val);
}

void gw_listen_fail_msg(const char *listen, int err, char *out, size_t cap)
{
	snprintf(out, cap, "监听 %s 失败: [Errno %d] %s", listen, err,
		 strerror(err));
}

/* ================= py 语义小工具 ================= */

static void py_repr_core(struct dt_sbuf *sb, const unsigned char *s, size_t n)
{
	int has_sq = 0, has_dq = 0;
	size_t i;
	char q;

	for (i = 0; i < n; i++) {
		if (s[i] == '\'')
			has_sq = 1;
		else if (s[i] == '"')
			has_dq = 1;
	}
	q = (has_sq && !has_dq) ? '"' : '\'';
	dt_sb_putc(sb, q);
	for (i = 0; i < n; i++) {
		unsigned char c = s[i];

		if (c == (unsigned char)q || c == '\\') {
			dt_sb_putc(sb, '\\');
			dt_sb_putc(sb, (char)c);
		} else if (c == '\n') {
			dt_sb_putstr(sb, "\\n");
		} else if (c == '\r') {
			dt_sb_putstr(sb, "\\r");
		} else if (c == '\t') {
			dt_sb_putstr(sb, "\\t");
		} else if (c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0)) {
			dt_sb_printf(sb, "\\x%02x", c);
		} else {
			dt_sb_putc(sb, (char)c);
		}
	}
	dt_sb_putc(sb, q);
}

void gw_py_repr_str(struct dt_sbuf *sb, const char *s)
{
	py_repr_core(sb, (const unsigned char *)s, strlen(s));
}

void gw_py_repr_bytes(struct dt_sbuf *sb, const unsigned char *b, size_t n)
{
	dt_sb_putc(sb, 'b');
	py_repr_core(sb, b, n);
}

void gw_int10_errmsg(struct dt_sbuf *sb, const char *literal)
{
	dt_sb_putstr(sb, "invalid literal for int() with base 10: ");
	gw_py_repr_str(sb, literal);
}

void gw_int16_errmsg(struct dt_sbuf *sb, const unsigned char *lit, size_t n)
{
	dt_sb_putstr(sb, "invalid literal for int() with base 16: ");
	gw_py_repr_bytes(sb, lit, n);
}

const char *gw_remote_disconnected(void)
{
	return "Remote end closed connection without response";
}

const char *gw_oserr_detail(int err)
{
	static __thread char buf[128];

	if (err == 0)
		return "Unknown error";
	if (err == ETIMEDOUT)
		return "timed out";	/* py socket.timeout str */
	snprintf(buf, sizeof(buf), "[Errno %d] %s", err, strerror(err));
	return buf;
}

const char *gw_reason_phrase(int code)
{
	switch (code) {
	case 100:
		return "Continue";
	case 200:
		return "OK";
	case 400:
		return "Bad Request";
	case 414:
		return "Request-URI Too Long";
	case 431:
		return "Request Header Fields Too Large";
	case 501:
		return "Not Implemented";
	case 502:
		return "Bad Gateway";
	case 505:
		return "HTTP Version Not Supported";
	default:
		return "???";
	}
}

void gw_http_date(char *buf, size_t cap)
{
	time_t t = time(NULL);
	struct tm tm;
	static const char *WD[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri",
				    "Sat" };
	static const char *MO[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
				    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

	gmtime_r(&t, &tm);
	snprintf(buf, cap, "%s, %02d %3s %04d %02d:%02d:%02d GMT",
		 WD[tm.tm_wday], tm.tm_mday, MO[tm.tm_mon],
		 tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* ================= 请求行解析(py3.10.12 parse_request) ================= */

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

int gw_parse_request_line(char *line, struct gw_reqline *h)
{
	char *words[16];
	int n;

	/* rawline 必须先取(split_words 会以 NUL 切词破坏原行) */
	snprintf(h->rawline, sizeof(h->rawline), "%s", line);
	n = split_words(line, words, 16);
	memset(h->target, 0, sizeof(h->target));
	h->close_conn = 1;	/* py parse_request 顶部置 True */
	h->version_11 = 0;
	h->version_09 = 0;
	h->method[0] = h->last_word[0] = '\0';

	if (n == 0)
		return GW_PARSE_BLANK;

	if (n >= 3) {
		const char *v = words[n - 1];
		const char *num;
		const char *dot;
		int comps = 1, bad = 0;

		snprintf(h->last_word, sizeof(h->last_word), "%s", v);
		if (strncmp(v, "HTTP/", 5) != 0)
			return GW_PARSE_BAD_VERSION;
		num = v + 5;
		dot = num;
		while (*dot) {
			if (*dot == '.')
				comps++;
			else if (*dot < '0' || *dot > '9')
				bad = 1;
			dot++;
		}
		if (bad || comps != 2)
			return GW_PARSE_BAD_VERSION;
		{
			int maj = atoi(num);
			int mino = atoi(strchr(num, '.') + 1);

			if (maj > 1 || (maj == 1 && mino >= 1))
				h->close_conn = 0;
			/* py Expect 门:self.request_version >= "HTTP/1.1"
			 * (串比较;HTTP/1.2 亦真) */
			h->version_11 = strcmp(v, "HTTP/1.1") >= 0;
			if (maj >= 2)
				return GW_PARSE_HTTP2;
		}
	}
	if (n < 2 || n > 3)
		return GW_PARSE_BAD_SYNTAX;
	if (n == 2) {
		h->close_conn = 1;	/* HTTP/0.9 形态 */
		snprintf(h->last_word, sizeof(h->last_word), "%s", words[0]);
		if (strcmp(words[0], "GET") != 0)
			return GW_PARSE_NOT_GET09;
		h->version_09 = 1;
	}
	snprintf(h->method, sizeof(h->method), "%s", words[0]);
	snprintf(h->target, sizeof(h->target), "%s", words[1]);
	/* gh-87389: '//' 开头 → '/' + lstrip('/') */
	if (h->target[0] == '/' && h->target[1] == '/') {
		size_t lead = 0;

		while (h->target[lead] == '/')
			lead++;
		memmove(h->target + 1, h->target + lead,
			strlen(h->target + lead) + 1);
	}
	return GW_PARSE_OK;
}

/* ================= 头列表 ================= */

void gw_hlist_init(struct gw_hlist *h)
{
	memset(h, 0, sizeof(*h));
}

void gw_hlist_free(struct gw_hlist *h)
{
	size_t i;

	for (i = 0; i < h->n; i++) {
		free(h->names[i]);
		free(h->vals[i]);
	}
	free(h->names);
	free(h->vals);
	gw_hlist_init(h);
}

int gw_hlist_set(struct gw_hlist *h, const char *name, const char *val)
{
	size_t i;

	for (i = 0; i < h->n; i++) {
		if (strcmp(h->names[i], name) == 0) {	/* 同形同名:保位换值 */
			free(h->vals[i]);
			h->vals[i] = strdup(val);
			return h->vals[i] ? 0 : -1;
		}
	}
	if (h->n == h->cap) {
		size_t cap = h->cap ? h->cap * 2 : 16;
		char **nn = realloc(h->names, cap * sizeof(char *));
		char **nv = realloc(h->vals, cap * sizeof(char *));

		if (!nn || !nv) {
			free(nn);
			free(nv);
			return -1;
		}
		h->names = nn;
		h->vals = nv;
		h->cap = cap;
	}
	h->names[h->n] = strdup(name);
	h->vals[h->n] = strdup(val);
	if (!h->names[h->n] || !h->vals[h->n]) {
		free(h->names[h->n]);
		free(h->vals[h->n]);
		return -1;
	}
	h->n++;
	return 0;
}

const char *gw_hlist_get_ci(const struct gw_hlist *h, const char *name)
{
	size_t i;

	for (i = 0; i < h->n; i++) {
		if (strcasecmp(h->names[i], name) == 0)
			return h->vals[i];
	}
	return NULL;
}

int gw_hlist_has_ci(const struct gw_hlist *h, const char *name)
{
	return gw_hlist_get_ci(h, name) != NULL;
}

int gw_is_hop_by_hop(const char *name)
{
	static const char *HOP[] = {
		"connection", "keep-alive", "proxy-authenticate",
		"proxy-authorization", "proxy-connection", "te", "trailer",
		"trailers", "transfer-encoding", "upgrade", NULL
	};
	int i;

	for (i = 0; HOP[i]; i++)
		if (strcasecmp(name, HOP[i]) == 0)
			return 1;
	return 0;
}

int gw_build_forward(const struct gw_hlist *client, struct gw_hlist *out,
		     const char *backend_str, const char *peer_ip,
		     const char *cn)
{
	size_t i;

	for (i = 0; i < client->n; i++) {
		const char *nm = client->names[i];

		if (gw_is_hop_by_hop(nm) || strcasecmp(nm, "host") == 0)
			continue;
		if (gw_hlist_set(out, nm, client->vals[i]) != 0)
			return -1;
	}
	if (gw_hlist_set(out, "Host", backend_str) != 0)
		return -1;
	if (gw_hlist_set(out, "X-Forwarded-For", peer_ip) != 0)
		return -1;
	if (gw_hlist_set(out, "X-Forwarded-Proto", "tls") != 0)
		return -1;
	if (gw_hlist_set(out, "X-Client-Cert-CN", cn ? cn : "") != 0)
		return -1;
	return 0;
}

char *gw_build_backend_request(const char *method, const char *target,
			       const struct gw_hlist *fwd,
			       const unsigned char *body, size_t blen,
			       size_t *out_len)
{
	struct dt_sbuf sb;

	dt_sb_init(&sb);
	dt_sb_printf(&sb, "%s %s HTTP/1.1\r\n", method, target);
	if (!gw_hlist_has_ci(fwd, "accept-encoding"))
		dt_sb_putstr(&sb, "Accept-Encoding: identity\r\n");
	if (!gw_hlist_has_ci(fwd, "content-length"))
		dt_sb_printf(&sb, "Content-Length: %zu\r\n", blen);
	{
		size_t i;

		for (i = 0; i < fwd->n; i++)
			dt_sb_printf(&sb, "%s: %s\r\n", fwd->names[i],
				     fwd->vals[i]);
	}
	dt_sb_putstr(&sb, "\r\n");
	if (body && blen)
		dt_sb_puts(&sb, (const char *)body, blen);
	*out_len = sb.n;
	return dt_sb_finish(&sb);
}

/* ================= JSON(json.dumps 默认参数) ================= */

static void json_escape(struct dt_sbuf *sb, const char *s)
{
	static const char HEXD[] = "0123456789abcdef";
	const unsigned char *p = (const unsigned char *)s;

	dt_sb_putc(sb, '"');
	while (*p) {
		unsigned char c = *p;

		if (c == '"') {
			dt_sb_putstr(sb, "\\\"");
			p++;
		} else if (c == '\\') {
			dt_sb_putstr(sb, "\\\\");
			p++;
		} else if (c < 0x20) {
			char esc[7];

			esc[0] = '\\';
			esc[1] = 'u';
			esc[2] = '0';
			esc[3] = '0';
			esc[4] = HEXD[c >> 4];
			esc[5] = HEXD[c & 0xF];
			esc[6] = '\0';
			dt_sb_putstr(sb, esc);
			p++;
		} else if (c < 0x80) {
			dt_sb_putc(sb, (char)c);
			p++;
		} else {
			/* UTF-8 解码 → \uXXXX(增补平面 → 代理对) */
			unsigned cp = 0;
			int extra = 0;
			int bad = 0;
			int k;

			if ((c & 0xE0) == 0xC0 && (c & 0xFE) != 0xC0) {
				cp = c & 0x1F;
				extra = 1;
			} else if ((c & 0xF0) == 0xE0) {
				cp = c & 0x0F;
				extra = 2;
			} else if ((c & 0xF8) == 0xF0) {
				cp = c & 0x07;
				extra = 3;
			} else {
				bad = 1;
			}
			for (k = 0; !bad && k < extra; k++) {
				unsigned char cc = p[1 + (size_t)k];

				if ((cc & 0xC0) != 0x80)
					bad = 1;
				else
					cp = (cp << 6) | (cc & 0x3F);
			}
			if (bad) {
				dt_sb_putstr(sb, "\\ufffd");
				p++;
				continue;
			}
			if (cp > 0xFFFF) {	/* 代理对 */
				unsigned v = cp - 0x10000;
				char esc[16];

				snprintf(esc, sizeof(esc), "\\u%04x",
					 0xD800 + (v >> 10));
				dt_sb_putstr(sb, esc);
				snprintf(esc, sizeof(esc), "\\u%04x",
					 0xDC00 + (v & 0x3FF));
				dt_sb_putstr(sb, esc);
			} else if (cp >= 0xD800 && cp <= 0xDFFF) {
				dt_sb_putstr(sb, "\\ufffd"); /* 孤代理 */
			} else {
				char esc[16];

				snprintf(esc, sizeof(esc), "\\u%04x", cp);
				dt_sb_putstr(sb, esc);
			}
			p += 1 + (size_t)extra;
		}
	}
	dt_sb_putc(sb, '"');
}

char *gw_json_kv2(const char *k1, const char *v1, const char *k2,
		  const char *v2, size_t *out_len)
{
	struct dt_sbuf sb;

	dt_sb_init(&sb);
	dt_sb_putc(&sb, '{');
	json_escape(&sb, k1);
	dt_sb_putstr(&sb, ": ");
	json_escape(&sb, v1);
	dt_sb_putstr(&sb, ", ");
	json_escape(&sb, k2);
	dt_sb_putstr(&sb, ": ");
	json_escape(&sb, v2);
	dt_sb_putc(&sb, '}');
	*out_len = sb.n;
	return dt_sb_finish(&sb);
}

int gw_healthz_target(const char *target)
{
	return strcmp(target, "/healthz") == 0;
}

/* ================= 读缓冲(py rfile 语义) ================= */

void gw_reader_init(struct gw_reader *r, struct gw_stream *s,
		    unsigned char *buf, size_t cap)
{
	memset(r, 0, sizeof(*r));
	if (s)
		r->s = *s;
	r->buf = buf;
	r->cap = cap;
}

int gw_reader_fill(struct gw_reader *r)
{
	int n;

	if (r->pos > 0) {
		memmove(r->buf, r->buf + r->pos, r->len - r->pos);
		r->len -= r->pos;
		r->pos = 0;
	}
	if (r->len >= r->cap)
		return -1;
	{
		size_t want = r->cap - r->len;

		if (want > 8192)	/* py rbufsize 8KB 节奏 */
			want = 8192;
		n = r->s.read(r->s.ctx, r->buf + r->len, want);
	}
	if (n > 0) {
		r->len += (size_t)n;
		return 1;
	}
	r->eof = 1;
	return 0;
}

char *gw_reader_readline(struct gw_reader *r, size_t cap, size_t *out_len,
			 int *eof)
{
	struct dt_sbuf sb;

	dt_sb_init(&sb);
	*eof = 0;
	*out_len = 0;
	for (;;) {
		size_t i;
		size_t avail = r->len - r->pos;
		size_t room = (sb.n < cap) ? cap - sb.n : 0;

		if (avail == 0) {
			if (gw_reader_fill(r) <= 0) {
				*eof = 1;
				*out_len = sb.n;
				if (sb.n == 0) {
					free(dt_sb_finish(&sb));
					return NULL;
				}
				return dt_sb_finish(&sb);
			}
			continue;
		}
		/* 在可拷窗口内找 \n */
		{
			size_t scan = avail < room ? avail : room;

			for (i = 0; i < scan; i++) {
				if (r->buf[r->pos + i] == '\n')
					break;
			}
			if (i < scan) {
				size_t n = i + 1;

				dt_sb_puts(&sb, (const char *)r->buf + r->pos,
					   n);
				r->pos += n;
				*out_len = sb.n;
				return dt_sb_finish(&sb);
			}
			/* 无 \n:拷满 room(py readline 到 size 即止) */
			dt_sb_puts(&sb, (const char *)r->buf + r->pos, scan);
			r->pos += scan;
			if (sb.n >= cap) {	/* 满 cap */
				*out_len = sb.n;
				return dt_sb_finish(&sb);
			}
		}
	}
}

int gw_reader_read_exact(struct gw_reader *r, unsigned char *out, size_t n)
{
	size_t have = 0;

	while (have < n) {
		size_t avail = r->len - r->pos;
		size_t take;

		if (avail == 0) {
			if (gw_reader_fill(r) <= 0)
				break;	/* EOF 短读 */
			continue;
		}
		take = avail;
		if (take > n - have)
			take = n - have;
		memcpy(out + have, r->buf + r->pos, take);
		r->pos += take;
		have += take;
	}
	return (int)have;
}

/* ================= 后端明文 TCP 客户端 ================= */

static int be_raw_read(void *ctx, unsigned char *buf, size_t n)
{
	int fd = *(int *)ctx;
	ssize_t r;

	for (;;) {
		r = recv(fd, buf, n, 0);
		if (r > 0)
			return (int)r;
		if (r == 0)
			return 0;
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return -1;	/* SO_RCVTIMEO 超时 */
		return -2;
	}
}

static int be_write_all(int fd, const char *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);

		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

int gw_be_connect(struct gw_be *be, const char *host, int port, int timeout,
		  char *errmsg, size_t errcap)
{
	struct addrinfo hints, *res = NULL, *ai;
	char portstr[16];
	int fd = -1;
	int last_err = ECONNREFUSED;
	int gai_rc;

	memset(be, 0, sizeof(*be));
	be->fd = -1;
	be->content_length = -1;
	snprintf(portstr, sizeof(portstr), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	/* py socket.create_connection:逐 addrinfo 试连 */
	gai_rc = getaddrinfo(host, portstr, &hints, &res);
	if (gai_rc != 0 || !res) {
		snprintf(errmsg, errcap, "[Errno %d] %s", gai_rc,
			 gai_strerror(gai_rc));
		return -1;
	}
	for (ai = res; ai; ai = ai->ai_next) {
		int flags;

		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0) {
			last_err = errno;
			continue;
		}
		flags = fcntl(fd, F_GETFL, 0);
		if (flags >= 0)
			(void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
			break;
		if (errno == EINPROGRESS) {
			struct pollfd pfd;

			pfd.fd = fd;
			pfd.events = POLLOUT;
			pfd.revents = 0;
			if (poll(&pfd, 1, timeout * 1000) > 0) {
				int soerr = 0;
				socklen_t sl = sizeof(soerr);

				if (getsockopt(fd, SOL_SOCKET, SO_ERROR,
					       &soerr, &sl) == 0 && soerr == 0)
					break;
				last_err = soerr ? soerr : ETIMEDOUT;
			} else {
				last_err = ETIMEDOUT;
			}
		} else {
			last_err = errno;
		}
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0) {
		snprintf(errmsg, errcap, "%s", gw_oserr_detail(last_err));
		return -1;
	}
	{
		int flags = fcntl(fd, F_GETFL, 0);

		if (flags >= 0)
			(void)fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
	}
	{
		struct timeval tv;

		tv.tv_sec = timeout;
		tv.tv_usec = 0;
		(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv,
				 sizeof(tv));
		(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv,
				 sizeof(tv));
	}
	be->fd = fd;
	be->st.ctx = &be->fd;
	be->st.read = be_raw_read;
	be->st.write = NULL;
	gw_reader_init(&be->rd, &be->st, be->rdbuf, sizeof(be->rdbuf));
	return 0;
}

int gw_be_send_request(struct gw_be *be, const char *bytes, size_t len,
		       char *errmsg, size_t errcap)
{
	if (be->fd < 0 || be_write_all(be->fd, bytes, len) != 0) {
		int e = errno ? errno : EPIPE;

		snprintf(errmsg, errcap, "%s", gw_oserr_detail(e));
		return -1;
	}
	return 0;
}

int gw_be_read_head(struct gw_be *be, char *errmsg, size_t errcap)
{
	char *line = NULL;
	size_t len = 0;
	int eof = 0;

	be->status = 0;
	be->reason[0] = '\0';
	gw_hlist_init(&be->hdrs);

	for (;;) {
		line = gw_reader_readline(&be->rd, GW_MAXLINE + 1, &len,
					  &eof);
		if (!line && eof)
			break;		/* EOF */
		if (!line)
			continue;
		if (len > 0 && (line[len - 1] == '\n' ||
				line[len - 1] == '\r')) {
			/* 行尾剥离后再判空行 */
			size_t n = len;

			while (n > 0 && (line[n - 1] == '\r' ||
					 line[n - 1] == '\n'))
				line[--n] = '\0';
			if (n == 0 && be->status != 0)
				break;	/* 空行:头结束 */
			if (n == 0) {
				/* 状态行前空行:py 严格 → BadStatusLine;
				 * 极端分支,按未捕获处理 */
				free(line);
				snprintf(errmsg, errcap, "%s", "BADSTATUS");
				return -2;
			}
		}
		if (be->status == 0) {	/* 状态行(py _read_status) */
			char *w1 = line;
			char *sp1 = strchr(line, ' ');
			char *w2 = NULL;
			char *reason = NULL;

			if (sp1) {
				*sp1 = '\0';
				w2 = sp1 + 1;
			}
			if (strncmp(w1, "HTTP/", 5) != 0 || !w2) {
				free(line);
				snprintf(errmsg, errcap, "%s", "BADSTATUS");
				return -2;
			}
			{
				char *sp2 = strchr(w2, ' ');

				if (sp2) {
					*sp2 = '\0';
					reason = sp2 + 1;
				}
			}
			{
				char *end = NULL;
				long v = strtol(w2, &end, 10);

				if (!end || *end != '\0' || v < 100 ||
				    v > 999) {
					free(line);
					snprintf(errmsg, errcap, "%s",
						 "BADSTATUS");
					return -2;
				}
				be->status = (int)v;
				if (reason) {
					char *rp = trim_ws(reason);

					snprintf(be->reason,
						 sizeof(be->reason), "%s",
						 rp);	/* py strip() */
				}
			}
		} else {		/* 响应头 */
			char *colon = strchr(line, ':');

			if (colon) {
				*colon = '\0';
				{
					char *nm = trim_ws(line);
					char *val = trim_ws(colon + 1);

					if (*nm)
						gw_hlist_set(&be->hdrs, nm,
							     val);
				}
			}
		}
		free(line);
		line = NULL;
	}
	free(line);
	if (be->status == 0) {
		/* EOF 无状态行 → py RemoteDisconnected */
		snprintf(errmsg, errcap, "%s", gw_remote_disconnected());
		return -1;
	}
	/* 体模式判定(py HTTPResponse:chunked 优先;CL 前者) */
	{
		const char *te;

		te = gw_hlist_get_ci(&be->hdrs, "transfer-encoding");
		be->chunked = te && strstr(te, "chunked") != NULL;
	}
	if (!be->chunked) {
		const char *cl;

		cl = gw_hlist_get_ci(&be->hdrs, "content-length");
		if (cl && *cl) {
			char *end = NULL;
			long long v = strtoll(cl, &end, 10);

			if (end && (*end == '\0' ||
				    isspace((unsigned char)*end)))
				be->content_length = v;
		}
	}
	be->chunk_rem = 0;
	be->consumed = 0;
	be->body_done = 0;
	be->saw_last_chunk = 0;
	return 0;
}

/* chunk 尺寸行(py:readline(64) + int(split(b";")[0].strip() or b"0", 16))。
 * 行内空白只剥两端(内部空白保留 → int 必败,消息带原文 token)。 */
int gw_chunk_parse_line(const char *line, long long *size, char *errmsg,
			size_t cap)
{
	unsigned char tok[96];
	size_t n = 0;
	size_t i = 0;
	size_t s;

	while (line[i] && line[i] != ';')
		i++;
	/* 收集 [0,i) 再剥两端空白(空格/\t/\r/\n/\v/\f) */
	s = 0;
	while (s < i && (line[s] == ' ' || line[s] == '\t' ||
			 line[s] == '\r' || line[s] == '\n' ||
			 line[s] == '\v' || line[s] == '\f'))
		s++;
	while (i > s && (line[i - 1] == ' ' || line[i - 1] == '\t' ||
			 line[i - 1] == '\r' || line[i - 1] == '\n' ||
			 line[i - 1] == '\v' || line[i - 1] == '\f'))
		i--;
	for (; s < i; s++) {
		unsigned char c = (unsigned char)line[s];

		if (n < sizeof(tok))
			tok[n++] = c;	/* 内部空白保留(py strip 只剥两端) */
	}
	tok[n] = '\0';
	if (n == 0) {		/* b"" → or b"0" → 0(终止) */
		*size = 0;
		return 0;
	}
	{
		size_t off = 0;
		int bad = 0;
		unsigned long long v = 0;

		if (n >= 2 && tok[0] == '0' && (tok[1] == 'x' ||
						tok[1] == 'X'))
			off = 2;
		for (; off < n; off++) {
			unsigned char c = tok[off];
			unsigned d;

			if (c >= '0' && c <= '9')
				d = c - '0';
			else if (c >= 'a' && c <= 'f')
				d = c - 'a' + 10;
			else if (c >= 'A' && c <= 'F')
				d = c - 'A' + 10;
			else {
				bad = 1;
				break;
			}
			v = v * 16 + d;
		}
		if (bad) {
			struct dt_sbuf sb;
			char *em;

			dt_sb_init(&sb);
			gw_int16_errmsg(&sb, tok, n);
			em = dt_sb_finish(&sb);
			if (em)
				snprintf(errmsg, cap, "%s", em);
			free(em);
			return -1;
		}
		*size = (long long)v;
	}
	return 0;
}

/* 后端 chunk 尺寸行读取(EOF → 视作终止,等价 py 下一轮 b"" → 0) */
static int be_chunk_size(struct gw_be *be, long long *size, char *errmsg,
			 size_t errcap)
{
	char *line;
	size_t len = 0;
	int eof = 0;
	int rc;

	line = gw_reader_readline(&be->rd, 64, &len, &eof);
	if (!line) {
		*size = 0;		/* EOF:视作终止 */
		return 0;
	}
	rc = gw_chunk_parse_line(line, size, errmsg, errcap);
	free(line);
	return rc;
}

static void be_read_line_swallow(struct gw_be *be)
{
	char *line;
	size_t len = 0;
	int eof = 0;

	line = gw_reader_readline(&be->rd, GW_MAXLINE + 1, &len, &eof);
	free(line);
}

int gw_be_read_body(struct gw_be *be, unsigned char *out, size_t want)
{
	size_t got = 0;

	if (want == 0)
		return 0;
	if (be->body_done)
		return 0;
	if (be->chunked) {
		while (got < want) {
			size_t avail;
			size_t take;

			if (be->chunk_rem == 0) {
				long long sz = 0;
				char em[200];

				if (be->saw_last_chunk)
					break;
				if (be_chunk_size(be, &sz, em,
						  sizeof(em)) != 0) {
					be->body_done = 1;
					return -1;
				}
				if (sz == 0) {
					be->saw_last_chunk = 1;
					be_read_line_swallow(be);
					be->body_done = 1;
					break;
				}
				be->chunk_rem = sz;
				continue;
			}
			avail = be->rd.len - be->rd.pos;
			if (avail == 0) {
				if (gw_reader_fill(&be->rd) <= 0) {
					be->body_done = 1;
					break;	/* EOF:短读即止 */
				}
				continue;
			}
			take = avail;
			if (take > want - got)
				take = want - got;
			if ((long long)take > be->chunk_rem)
				take = (size_t)be->chunk_rem;
			memcpy(out + got, be->rd.buf + be->rd.pos, take);
			be->rd.pos += take;
			got += take;
			be->chunk_rem -= (long long)take;
			if (be->chunk_rem == 0)
				be_read_line_swallow(be);	/* 块尾 CRLF */
		}
		return (int)got;
	}
	if (be->content_length >= 0) {
		long long rem = be->content_length - be->consumed;

		if (rem <= 0) {
			be->body_done = 1;
			return 0;
		}
		while (got < want && rem > 0) {
			size_t avail;
			size_t take;

			avail = be->rd.len - be->rd.pos;
			if (avail == 0) {
				if (gw_reader_fill(&be->rd) <= 0) {
					be->body_done = 1;
					break;
				}
				continue;
			}
			take = avail;
			if (take > want - got)
				take = want - got;
			if ((long long)take > rem)
				take = (size_t)rem;
			memcpy(out + got, be->rd.buf + be->rd.pos, take);
			be->rd.pos += take;
			got += take;
			rem -= (long long)take;
		}
		be->consumed += (long long)got;
		if (be->consumed >= be->content_length)
			be->body_done = 1;
		return (int)got;
	}
	/* 无 CL 无 TE:读到 EOF */
	while (got < want) {
		size_t avail = be->rd.len - be->rd.pos;
		size_t take;

		if (avail == 0) {
			if (gw_reader_fill(&be->rd) <= 0) {
				be->body_done = 1;
				break;
			}
			continue;
		}
		take = avail;
		if (take > want - got)
			take = want - got;
		memcpy(out + got, be->rd.buf + be->rd.pos, take);
		be->rd.pos += take;
		got += take;
	}
	return (int)got;
}

void gw_be_close(struct gw_be *be)
{
	if (be->fd >= 0)
		close(be->fd);
	be->fd = -1;
	gw_hlist_free(&be->hdrs);
}
