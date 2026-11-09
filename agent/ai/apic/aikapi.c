/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aikapi.c - T7b 主程序与路由分发(参考 aikernel-api main/do_GET/do_POST/
 * _auth_error/ai_env/audit_line/parse_api_section/parse_control 等)。
 *
 * 旗标:--frozen-now EPOCH / --frozen-random(T5/T6 先例;本参考无 random,
 * --frozen-* 启用 secrets 定序计数器)/ --probe-netlink(重放器 fn 对拍)。
 * 启动:参考 listening 行(逐字节)+ "LISTENING <port>"(重放器取口)。
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "apic/api.h"
#include "desktop/dtcore.h"
#include "desktop/dtjson.h"

struct api_cfg g_api;

/* ---------------- 冻结时钟 / secrets ---------------- */
long long api_time(void)
{
	if (g_api.frozen)
		return g_api.frozen_epoch;
	return (long long)time(NULL);
}

void api_token_hex16(char out[33])
{
	static unsigned long long counter = 0;
	unsigned char rnd[16];
	size_t i;

	if (g_api.frozen) {
		unsigned long long n = ++counter;

		snprintf(out, 33, "%032llx", n);
		return;
	}
	if (getenv("AIK_DISABLE_URANDOM")) { /* 单测辅助 */
		snprintf(out, 33, "%032llx", ++counter);
		return;
	}
	{
		int fd = open("/dev/urandom", O_RDONLY);

		if (fd < 0 || read(fd, rnd, 16) != 16) {
			if (fd >= 0)
				close(fd);
			snprintf(out, 33, "%032llx", ++counter);
			return;
		}
		close(fd);
	}
	for (i = 0; i < 16; i++)
		snprintf(out + i * 2, 3, "%02x", rnd[i]);
}

/* ---------------- python int() 语义 ---------------- */
static int is_ws_c(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
	       c == '\v' || c == '\f';
}

int api_py_int(const char *s, long long *out)
{
	const char *p = s;
	const char *d0;
	int neg = 0;
	unsigned long long v = 0;

	if (!s)
		return 0;
	while (*p && is_ws_c(*p))
		p++;
	if (*p == '+' || *p == '-') {
		neg = (*p == '-');
		p++;
	}
	if (!*p)
		return 0;
	d0 = p;
	for (; *p && !is_ws_c(*p); p++) {
		if (*p == '_') {
			if (p == d0 || *(p + 1) == '\0' ||
			    is_ws_c(*(p + 1)))
				return 0; /* py 下划线须在数字间 */
			continue;
		}
		if (*p < '0' || *p > '9')
			return 0;
		if (v > (0x7FFFFFFFFFFFFFFFULL - 9) / 10)
			return 0; /* py 溢出抛 ValueError */
		v = v * 10 + (unsigned long long)(*p - '0');
	}
	while (*p && is_ws_c(*p))
		p++;
	if (*p)
		return 0;	/* 数字后有非空白垃圾 */
	*out = neg ? -(long long)v : (long long)v;
	return 1;
}

int api_py_int0(const char *s, long long *out)
{
	const char *p = s;
	int neg = 0, base = 10, ndigits = 0;
	unsigned long long v = 0;

	if (!s)
		return 0;
	while (*p && is_ws_c(*p))
		p++;
	if (*p == '+' || *p == '-') {
		neg = (*p == '-');
		p++;
	}
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
		base = 16;
		p += 2;
	} else if (p[0] == '0' && (p[1] == 'o' || p[1] == 'O')) {
		base = 8;
		p += 2;
	} else if (p[0] == '0' && (p[1] == 'b' || p[1] == 'B')) {
		base = 2;
		p += 2;
	}
	for (; *p && !is_ws_c(*p); p++) {
		int d;

		if (*p == '_') {
			if (!ndigits)
				return 0;
			continue;
		}
		if (*p >= '0' && *p <= '9')
			d = *p - '0';
		else if (*p >= 'a' && *p <= 'z')
			d = *p - 'a' + 10;
		else if (*p >= 'A' && *p <= 'Z')
			d = *p - 'A' + 10;
		else
			return 0;
		if (d >= base)
			return 0;
		if (v > (0x7FFFFFFFFFFFFFFFULL - 35) / (unsigned)base)
			return 0;
		v = v * (unsigned)base + (unsigned long long)d;
		ndigits++;
	}
	while (*p && is_ws_c(*p))
		p++;
	if (*p)
		return 0;
	if (!ndigits)
		return 0;
	*out = neg ? -(long long)v : (long long)v;
	return 1;
}

/* ---------------- UTF-8 解码(errors="replace") ---------------- */
static int utf8_valid_len(const unsigned char *p, size_t n)
{
	/* 返回起始有效序列字节数;0=非法起始 */
	unsigned char c = p[0];
	size_t need;

	if (c < 0x80)
		return 1;
	if ((c & 0xE0) == 0xC0)
		need = 2;
	else if ((c & 0xF0) == 0xE0)
		need = 3;
	else if ((c & 0xF8) == 0xF0)
		need = 4;
	else
		return 0;
	if (n < need)
		return 0; /* 截断(py: unexpected end of data) */
	{
		size_t i;

		for (i = 1; i < need; i++) {
			if ((p[i] & 0xC0) != 0x80)
				return 0;
		}
	}
	return (int)need;
}

int api_utf8_decode_replace(const char *in, size_t n, char **out,
			    size_t *out_len)
{
	struct dt_sbuf sb;
	size_t i = 0;

	dt_sb_init(&sb);
	while (i < n) {
		int k = utf8_valid_len((const unsigned char *)in + i, n - i);

		if (k > 0) {
			dt_sb_puts(&sb, in + i, (size_t)k);
			i += (size_t)k;
		} else {
			dt_sb_putstr(&sb, "\xEF\xBF\xBD"); /* U+FFFD */
			i += 1;
		}
	}
	*out = dt_sb_finish(&sb);
	*out_len = sb.n;
	return 0;
}

/* python UnicodeDecodeError 消息(取首个错误) */
int api_utf8_errmsg(const char *in, size_t n, char *buf, size_t cap)
{
	size_t i = 0;

	while (i < n) {
		unsigned char c = (unsigned char)in[i];
		int k = utf8_valid_len((const unsigned char *)in + i, n - i);
		const char *reason;

		if (k > 0) {
			i += (size_t)k;
			continue;
		}
		if ((c & 0xC0) == 0x80 || c >= 0xF8)
			reason = "invalid start byte";
		else if (n - i < 2 && (c & 0xE0) == 0xC0)
			reason = "unexpected end of data";
		else if (n - i < 3 && (c & 0xF0) == 0xE0)
			reason = "unexpected end of data";
		else if (n - i < 4 && (c & 0xF8) == 0xF0)
			reason = "unexpected end of data";
		else
			reason = "invalid continuation byte";
		snprintf(buf, cap,
			 "'utf-8' codec can't decode byte 0x%02x in "
			 "position %zu: %s", c, i, reason);
		return 1;
	}
	snprintf(buf, cap, "'utf-8' codec can't decode: input ok");
	return 0;
}

/* ---------------- 正则等价 ---------------- */
static int re_token_ok(const char *s, size_t maxlen)
{
	size_t n = 0;

	if (!s)
		return 0;
	for (; s[n]; n++) {
		char c = s[n];

		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		      c == '-'))
			return 0;
	}
	return n >= 1 && n <= maxlen;
}

int api_valid_session(const char *s)
{
	return s && strncmp(s, API_SESSION_PREFIX, 4) == 0 &&
	       re_token_ok(s + 4, API_SESSION_MAX);
}

int api_valid_nonce(const char *s)
{
	return s && strncmp(s, "cq-", 3) == 0 &&
	       re_token_ok(s + 3, API_NONCE_MAX);
}

/* ---------------- TOML [api](最小解析,键序=出现序) ---------------- */
aik_json *api_parse_toml_section(const char *text)
{
	aik_json *out = dt_new_obj();
	const char *p = text;
	int in_api = 0;

	while (p && *p) {
		const char *eol = strchr(p, '\n');
		size_t linelen = eol ? (size_t)(eol - p) : strlen(p);
		char *line = malloc(linelen + 1);
		char *t;
		char *eq;

		if (!line)
			break;
		memcpy(line, p, linelen);
		line[linelen] = '\0';
		t = dt_strip(line);
		if (!*t || *t == '#') {
			free(line);
			p = eol ? eol + 1 : NULL;
			continue;
		}
		if (*t == '[') {
			char *close = strchr(t, ']');

			if (close) {
				char saved = *close;
				char *sec;

				*close = '\0';
				sec = dt_strip(t + 1);
				in_api = strcmp(sec, "api") == 0;
				*close = saved;
			} else {
				in_api = 0;
			}
			free(line);
			p = eol ? eol + 1 : NULL;
			continue;
		}
		eq = strchr(t, '=');
		if (!in_api || !eq) {
			free(line);
			p = eol ? eol + 1 : NULL;
			continue;
		}
		{
			char *key;
			char *val;
			char *kend = eq;

			*eq = '\0';
			key = dt_strip(t);
			while (kend > t && kend[-1] == ' ')
				kend--;
			val = dt_strip(eq + 1);
			if (*key) {
				size_t vlen = strlen(val);

				if (vlen >= 2 && val[0] == '"' &&
				    val[vlen - 1] == '"') {
					val[vlen - 1] = '\0';
					dt_put_str(out, key, val + 1);
				} else if (strcmp(val, "true") == 0) {
					dt_put_bool(out, key, 1);
				} else if (strcmp(val, "false") == 0) {
					dt_put_bool(out, key, 0);
				} else {
					long long iv;

					if (api_py_int0(val, &iv))
						dt_put_int(out, key, iv);
					else
						dt_put_str(out, key, val);
				}
			}
		}
		free(line);
		p = eol ? eol + 1 : NULL;
	}
	return out;
}

aik_json *api_load_config(void)
{
	size_t n = 0;
	char *text = api_read_file(g_api.toml_file, &n, NULL);

	if (!text)
		return dt_new_obj();
	{
		aik_json *o = api_parse_toml_section(text);

		free(text);
		return o;
	}
}

char *api_effective_token(void)
{
	aik_json *cfg = api_load_config();
	const char *s = aik_json_str(dt_get(cfg, "token"));
	char *cand = NULL;

	if (s) {
		cand = dt_strip(s);
		if (!*cand) {
			free(cand);
			cand = NULL;
		}
	}
	aik_json_free(cfg);
	if (cand)
		return cand;
	{
		size_t n = 0;
		char *text = api_read_file(API_TOKEN_FILE, &n, NULL);

		if (!text)
			return NULL;
		{
			char *t = dt_strip(text);

			free(text);
			if (!*t) {
				free(t);
				return NULL;
			}
			return t;
		}
	}
}

/* ---------------- 文件工具 ---------------- */
char *api_read_file(const char *path, size_t *out_len, int *os_errno)
{
	int fd = open(path, O_RDONLY);
	struct stat st;
	struct dt_sbuf sb;

	if (os_errno)
		*os_errno = 0;
	if (fd < 0) {
		if (os_errno)
			*os_errno = errno;
		return NULL;
	}
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		close(fd);
		if (os_errno)
			*os_errno = EINVAL;
		errno = EINVAL;
		return NULL;
	}
	dt_sb_init(&sb);
	for (;;) {
		char chunk[65536];
		ssize_t n = read(fd, chunk, sizeof(chunk));

		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			if (os_errno)
				*os_errno = errno;
			free(dt_sb_finish(&sb));
			return NULL;
		}
		if (n == 0)
			break;
		dt_sb_puts(&sb, chunk, (size_t)n);
	}
	close(fd);
	if (out_len)
		*out_len = sb.n;
	return dt_sb_finish(&sb);
}

/* "[Errno %d] %s: '%s'"(python OSError str) */
void api_oserr_str(char *buf, size_t cap, int e, const char *path)
{
	snprintf(buf, cap, "[Errno %d] %s: '%s'", e, strerror(e), path);
}

/* ---------------- /proc/ai/control 解析 ---------------- */
/* "^(\S+)\s+domain=(\d+)\s+\[real\]\s+min=(-?\d+)\s+max=(-?\d+)
 *  \s+current=(-?\d+)\s+default=(-?\d+)\s*$"(行先两端 strip) */
int api_parse_control_line(const char *line, char *name, size_t name_cap,
			   long long *domain, long long *lo, long long *hi,
			   long long *cur, long long *def)
{
	char *t = dt_strip(line);
	const char *p = t;
	const char *q;
	size_t nlen;
	static const char *labels[4] = { "min=", "max=", "current=",
					 "default=" };
	long long vals[4];
	int i;

	q = p;
	while (*q && *q != ' ' && *q != '\t' && *q != '\v' && *q != '\f')
		q++;
	if (q == p)
		goto fail;
	nlen = (size_t)(q - p);
	p = q;
	/* \s+ 至少一个空白 */
	if (!(*p == ' ' || *p == '\t' || *p == '\v' || *p == '\f'))
		goto fail;
	while (*p == ' ' || *p == '\t' || *p == '\v' || *p == '\f')
		p++;
	if (strncmp(p, "domain=", 7) != 0)
		goto fail;
	p += 7;
	if (*p < '0' || *p > '9')
		goto fail;	/* \d+:无符号 */
	{
		char *end;

		*domain = strtoll(p, &end, 10);
		p = end;
	}
	if (!(*p == ' ' || *p == '\t' || *p == '\v' || *p == '\f'))
		goto fail;
	while (*p == ' ' || *p == '\t' || *p == '\v' || *p == '\f')
		p++;
	if (strncmp(p, "[real]", 6) != 0)
		goto fail;
	p += 6;
	for (i = 0; i < 4; i++) {
		if (!(*p == ' ' || *p == '\t' || *p == '\v' || *p == '\f'))
			goto fail;
		while (*p == ' ' || *p == '\t' || *p == '\v' || *p == '\f')
			p++;
		if (strncmp(p, labels[i], strlen(labels[i])) != 0)
			goto fail;
		p += strlen(labels[i]);
		if (!(*p == '-' || (*p >= '0' && *p <= '9')))
			goto fail;
		{
			char *end;

			vals[i] = strtoll(p, &end, 10);
			p = end;
		}
	}
	while (*p == ' ' || *p == '\t' || *p == '\v' || *p == '\f')
		p++;
	if (*p != '\0')
		goto fail;
	if (nlen >= name_cap)
		goto fail;
	memcpy(name, t, nlen);
	name[nlen] = '\0';
	*lo = vals[0];
	*hi = vals[1];
	*cur = vals[2];
	*def = vals[3];
	free(t);
	return 0;
fail:
	free(t);
	return -1;
}

int api_is_task_param(const char *name)
{
	/* U66/T2（K66-REPORT §1-T2）：内核侧 sec.ws_label 为
	 * AI_CTRL_F_TASK（ai_lsm.c:1858），白名单缺名使 /act 走
	 * api_nl_pack_act(..., value, 0) → data=[value,0] 把 value 当
	 * pid（F16 §2-3 实证）。think 5 字段通道与 v2 定向 netlink 不受
	 * 影响（仅 /act 面）。A7（BLLM-REPORT §1-A7）：io.priority 内核
	 * 侧同为 AI_CTRL_F_TASK（ai_block.c:627，CONFIG_BLOCK 时
	 * REAL|TASK），同构补入白名单，主会话已裁。 */
	static const char *tp[] = { "sched.nice", "sched.affinity",
				    "sched.oom_score", "proc.signal",
				    "proc.freeze", "proc.rlimit",
				    "sec.ws_label", "io.priority" };
	size_t i;

	for (i = 0; i < sizeof(tp) / sizeof(tp[0]); i++) {
		if (strcmp(tp[i], name) == 0)
			return 1;
	}
	return 0;
}

/* ---------------- 审计 ---------------- */
void api_audit_line(const char *tool, const aik_json *args,
		    const char *result)
{
	time_t t = (time_t)api_time();
	struct tm tm;
	char ts[40];
	char *args_json;
	int fd;

	gmtime_r(&t, &tm);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S+0000", &tm);
	args_json = args ? dt_json_dump_default(args) : strdup("{}");
	if (!args_json)
		args_json = strdup("{}");
	fd = open(API_AUDIT_LOG, O_WRONLY | O_APPEND | O_CREAT, 0600);
	if (fd >= 0) {
		char header[160];
		int n;

		n = snprintf(header, sizeof(header),
			     "%s uid=%d user=root mode=api tool=%s args=",
			     ts, (int)getuid(), tool);
		if (n > 0) {
			(void)api_write_discard(fd, header, (size_t)n);
			(void)api_write_discard(fd, args_json,
						strlen(args_json));
			n = snprintf(header, sizeof(header), " result=%s\n",
				     result);
			if (n > 0)
				(void)api_write_discard(fd, header,
							(size_t)n);
		}
		close(fd);
	}
	free(args_json);
}

/* ---------------- 响应构造 ---------------- */
void api_resp_json(struct api_http_resp *r, int status, const aik_json *body)
{
	r->status = status;
	free(r->body);
	r->body = body ? dt_json_dump_default(body) : NULL;
	r->body_len = r->body ? strlen(r->body) : 0;
}

struct aik_json *api_err_body(const char *err, const char *message)
{
	aik_json *o = dt_new_obj();

	dt_put_str(o, "error", err);
	dt_put_str(o, "message", message);
	return o;
}

/* ---------------- query(parse_qs 语义) ---------------- */
static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

char *api_query_get(const char *query, const char *key)
{
	const char *p = query;

	if (!p)
		return NULL;
	while (*p) {
		const char *amp = strchr(p, '&');
		const char *seg_end = amp ? amp : p + strlen(p);
		const char *eq = memchr(p, '=', (size_t)(seg_end - p));
		struct dt_sbuf kb, vb;

		dt_sb_init(&kb);
		dt_sb_init(&vb);
		{
			const char *s = p;
			const char *send = eq ? eq : seg_end;

			while (s < send) {
				if (*s == '+') {
					dt_sb_putc(&kb, ' ');
					s++;
				} else if (*s == '%' && send - s >= 3 &&
					   hexval(s[1]) >= 0 &&
					   hexval(s[2]) >= 0) {
					dt_sb_putc(&kb,
						   (char)(hexval(s[1]) * 16 +
							  hexval(s[2])));
					s += 3;
				} else {
					dt_sb_putc(&kb, *s);
					s++;
				}
			}
		}
		if (eq) {
			const char *s = eq + 1;

			while (s < seg_end) {
				if (*s == '+') {
					dt_sb_putc(&vb, ' ');
					s++;
				} else if (*s == '%' && seg_end - s >= 3 &&
					   hexval(s[1]) >= 0 &&
					   hexval(s[2]) >= 0) {
					dt_sb_putc(&vb,
						   (char)(hexval(s[1]) * 16 +
							  hexval(s[2])));
					s += 3;
				} else {
					dt_sb_putc(&vb, *s);
					s++;
				}
			}
		}
		{
			char *kstr = dt_sb_finish(&kb);
			char *vstr = dt_sb_finish(&vb);
			int hit = kstr && strcmp(kstr, key) == 0;

			free(kstr);
			if (hit && eq && vstr && *vstr) {
				/* keep_blank_values=False:空值丢弃;首值胜 */
				return vstr;
			}
			free(vstr);
		}
		p = amp ? amp + 1 : p + strlen(p);
	}
	return NULL;
}

/* ---------------- 鉴权 ---------------- */
/* 0=通过;1=已写响应(401/403) */
int api_auth_check(struct api_http_req *req, struct api_http_resp *resp)
{
	const char *hdr = req->authorization;
	char *tok;
	char *bearer_tok;

	if (hdr && strncmp(hdr, "Bearer ", 7) == 0) {
		bearer_tok = dt_strip(hdr + 7);
		if (*bearer_tok) {
			tok = api_effective_token();
			if (tok && strcmp(bearer_tok, tok) == 0) {
				free(tok);
				free(bearer_tok);
				return 0;
			}
			free(tok);
			free(bearer_tok);
			{
				aik_json *args = dt_new_obj();
				aik_json *body;

				dt_put_str(args, "path", req->target);
				dt_put_str(args, "op", req->method);
				api_audit_line("api_auth", args,
					       "DENY_BAD_TOKEN");
				aik_json_free(args);
				body = api_err_body(
					"forbidden",
					"Bearer token 不正确或已轮换失效");
				api_resp_json(resp, 403, body);
				aik_json_free(body);
			}
			return 1;
		}
		free(bearer_tok);
	}
	{
		aik_json *args = dt_new_obj();
		aik_json *body;

		dt_put_str(args, "path", req->target);
		dt_put_str(args, "op", req->method);
		api_audit_line("api_auth", args, "DENY_NO_TOKEN");
		aik_json_free(args);
		body = api_err_body("unauthorized",
				    "缺少 Bearer token（GET /health 探活"
				    "除外亦需鉴权）");
		api_resp_json(resp, 401, body);
		aik_json_free(body);
	}
	return 1;
}

#define AUTH_GUARD do { \
	if (api_auth_check(req, resp) != 0) \
		return 0; \
} while (0)

/* ---------------- do_GET ---------------- */
static int do_GET(struct api_http_req *req, struct api_http_resp *resp)
{
	const char *path = req->path;
	const char *query = req->query;

	if (strcmp(path, "/health") == 0) {
		AUTH_GUARD;
		return api_do_health(req, resp);
	}
	if (strcmp(path, "/tools") == 0) {
		char *channel;
		char *risk;

		AUTH_GUARD;
		channel = api_query_get(query, "channel");
		risk = api_query_get(query, "risk");
		return api_do_tools(req, resp, channel, risk);
	}
	if (strcmp(path, "/params") == 0) {
		char *name;

		AUTH_GUARD;
		name = api_query_get(query, "name");
		return api_do_params(req, resp, name);
	}
	if (strcmp(path, "/sense") == 0) {
		char *what;
		char *limit;

		AUTH_GUARD;
		what = api_query_get(query, "what");
		limit = api_query_get(query, "limit");
		return api_do_sense(req, resp, what, limit);
	}
	{
		static const char *known[][2] = { { "/ask", "POST" },
						  { "/act", "POST" },
						  { "/clarify", "POST" } };
		size_t i;

		for (i = 0; i < 3; i++) {
			if (strcmp(path, known[i][0]) == 0) {
				char msg[128];
				aik_json *body;

				snprintf(msg, sizeof(msg), "%s 只支持 %s",
					 known[i][0], known[i][1]);
				body = api_err_body("method_not_allowed", msg);
				api_resp_json(resp, 405, body);
				aik_json_free(body);
				return 0;
			}
		}
	}
	{
		aik_json *body = api_err_body(
			"not found",
			"未知端点（可用：/health /tools /params /sense "
			"/ask /clarify /act）");

		api_resp_json(resp, 404, body);
		aik_json_free(body);
		return 0;
	}
}

/* ---------------- do_POST(原始 target 比较,含 query) ---------------- */
static int do_POST(struct api_http_req *req, struct api_http_resp *resp)
{
	const char *raw = req->target;

	if (strcmp(raw, "/ask") == 0)
		return api_do_ask(req, resp);
	if (strcmp(raw, "/clarify") == 0)
		return api_do_clarify(req, resp);
	if (strcmp(raw, "/act") == 0)
		return api_do_act(req, resp);
	{
		static const char *known[][2] = { { "/health", "GET" },
						  { "/tools", "GET" },
						  { "/params", "GET" },
						  { "/sense", "GET" } };
		size_t i;

		for (i = 0; i < 4; i++) {
			if (strcmp(raw, known[i][0]) == 0) {
				char msg[128];
				aik_json *body;

				snprintf(msg, sizeof(msg), "%s 只支持 %s",
					 known[i][0], known[i][1]);
				body = api_err_body("method_not_allowed", msg);
				api_resp_json(resp, 405, body);
				aik_json_free(body);
				return 0;
			}
		}
	}
	{
		aik_json *body = api_err_body(
			"not found",
			"未知端点（可用：/health /tools /params /sense "
			"/ask /clarify /act）");

		api_resp_json(resp, 404, body);
		aik_json_free(body);
		return 0;
	}
}

int api_dispatch(struct api_http_req *req, struct api_http_resp *resp)
{
	if (strcmp(req->method, "GET") == 0)
		return do_GET(req, resp);
	return do_POST(req, resp);
}
