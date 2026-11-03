// SPDX-License-Identifier: GPL-2.0
/*
 * dtcore.c - 共享基础实现(路径/冻结时钟/随机/日志/UTF-8/文件/哈希)。
 */
#define _POSIX_C_SOURCE 200809L

#include "desktop/dtcore.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int read_urandom_byte(unsigned char *out);

struct dt_cfg g_cfg;

pthread_mutex_t g_lock_desktop = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_lock_theme = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_lock_chat = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_lock_apps = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_lock_zh = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_lock_screenshot = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_lock_vm = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_lock_log = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_lock_stats = PTHREAD_MUTEX_INITIALIZER;

/* ---------------------------------------------------------------- 冻结 */

static long long g_frozen_epoch = -1;   /* -1 = 真时钟 */
static int g_frozen_random = 0;
static long long g_ns_counter = 0;
static long long g_rand_counter = 0;
static pthread_mutex_t g_freeze_lock = PTHREAD_MUTEX_INITIALIZER;

static const double RAND_SEQ[10] = { 0.042, 0.123, 0.314, 0.5, 0.618,
				     0.7, 0.777, 0.85, 0.913, 0.966 };

void dt_freeze_set(long long epoch, int frozen_random)
{
	g_frozen_epoch = epoch;
	g_frozen_random = frozen_random;
}

int dt_frozen(void)
{
	return g_frozen_epoch >= 0;
}

long long dt_time(void)
{
	if (g_frozen_epoch >= 0)
		return g_frozen_epoch;
	return (long long)time(NULL);
}

long long dt_time_ns(void)
{
	if (g_frozen_epoch >= 0) {
		long long n;

		pthread_mutex_lock(&g_freeze_lock);
		g_ns_counter++;
		n = g_ns_counter;
		pthread_mutex_unlock(&g_freeze_lock);
		return g_frozen_epoch * 1000000000LL + n * 1000000LL;
	}
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

size_t dt_strftime(char *buf, size_t cap, const char *fmt)
{
	time_t t = (time_t)dt_time();
	struct tm tm;

	localtime_r(&t, &tm);
	return strftime(buf, cap, fmt, &tm);
}

double dt_random(void)
{
	if (g_frozen_random) {
		double v;

		pthread_mutex_lock(&g_freeze_lock);
		v = RAND_SEQ[g_rand_counter % 10];
		g_rand_counter++;
		pthread_mutex_unlock(&g_freeze_lock);
		return v;
	}
	unsigned char raw[8];
	long long acc = 0;

	for (size_t i = 0; i < sizeof(raw); i++) {
		if (read_urandom_byte(&raw[i]) != 0)
			raw[i] = (unsigned char)(dt_time_ns() & 0xFF);
	}
	for (size_t i = 0; i < sizeof(raw); i++)
		acc = (acc << 8) | raw[i];
	return (double)((acc >> 11) * (1.0 / 9007199254740992.0));
}

static int read_urandom_byte(unsigned char *out)
{
	static int fd = -2;
	static pthread_mutex_t ur_lock = PTHREAD_MUTEX_INITIALIZER;
	ssize_t r = 0;

	if (fd == -2) {
		pthread_mutex_lock(&ur_lock);
		if (fd == -2)
			fd = open("/dev/urandom", 0 /* O_RDONLY */);
		pthread_mutex_unlock(&ur_lock);
	}
	if (fd < 0)
		return -1;
	do {
		r = read(fd, out, 1);
	} while (r < 0 && errno == EINTR);
	return r == 1 ? 0 : -1;
}

/* ---------------------------------------------------------------- 日志 */

void dt_log(const char *fmt, ...)
{
	char tbuf[16];
	va_list ap;

	dt_strftime(tbuf, sizeof(tbuf), "%H:%M:%S");
	pthread_mutex_lock(&g_lock_log);
	fputs("[", stdout);
	fputs(tbuf, stdout);
	fputs("] ", stdout);
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	fputc('\n', stdout);
	fflush(stdout);
	pthread_mutex_unlock(&g_lock_log);
}

/* ---------------------------------------------------------------- sbuf */

void dt_sb_init(struct dt_sbuf *b)
{
	memset(b, 0, sizeof(*b));
}

static int sb_grow(struct dt_sbuf *b, size_t need)
{
	if (b->bad)
		return -1;
	if (b->n + need + 1 > b->cap) {
		size_t cap = b->cap ? b->cap : 256;
		char *q;

		while (cap < b->n + need + 1)
			cap *= 2;
		q = realloc(b->p, cap);
		if (!q) {
			b->bad = 1;
			return -1;
		}
		b->p = q;
		b->cap = cap;
	}
	return 0;
}

void dt_sb_putc(struct dt_sbuf *b, char c)
{
	if (sb_grow(b, 1) == 0)
		b->p[b->n++] = c;
}

void dt_sb_puts(struct dt_sbuf *b, const char *s, size_t n)
{
	if (sb_grow(b, n) == 0) {
		memcpy(b->p + b->n, s, n);
		b->n += n;
	}
}

void dt_sb_putstr(struct dt_sbuf *b, const char *s)
{
	dt_sb_puts(b, s, strlen(s));
}

int dt_sb_printf(struct dt_sbuf *b, const char *fmt, ...)
{
	char tmp[1024];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (n < 0)
		return -1;
	dt_sb_puts(b, tmp, (size_t)n);
	return 0;
}

char *dt_sb_finish(struct dt_sbuf *b)
{
	if (b->bad || sb_grow(b, 1) != 0) {
		free(b->p);
		return NULL;
	}
	b->p[b->n] = '\0';
	return b->p;
}

/* ---------------------------------------------------------------- UTF-8 */

size_t dt_utf8_cplen(const char *s, size_t bytes)
{
	size_t cp = 0, i = 0;

	while (i < bytes) {
		unsigned char c = (unsigned char)s[i];

		if (c < 0x80) {
			i += 1;
		} else if ((c & 0xE0) == 0xC0) {
			i += 2;
		} else if ((c & 0xF0) == 0xE0) {
			i += 3;
		} else if ((c & 0xF8) == 0xF0) {
			i += 4;
		} else {
			i += 1; /* 非法字节按 1 码点(输入恒为合法 UTF-8) */
		}
		cp++;
	}
	return cp;
}

size_t dt_cp_offset(const char *s, size_t bytes, size_t cp)
{
	size_t i = 0, n = 0;

	while (i < bytes && n < cp) {
		unsigned char c = (unsigned char)s[i];

		if (c < 0x80) {
			i += 1;
		} else if ((c & 0xE0) == 0xC0) {
			i += 2;
		} else if ((c & 0xF0) == 0xE0) {
			i += 3;
		} else if ((c & 0xF8) == 0xF0) {
			i += 4;
		} else {
			i += 1;
		}
		n++;
	}
	return i;
}

static char *slice_range(const char *s, size_t start, size_t end)
{
	size_t n = end - start;
	char *out = malloc(n + 1);

	if (!out)
		return NULL;
	memcpy(out, s + start, n);
	out[n] = '\0';
	return out;
}

char *dt_utf8_head(const char *s, size_t n)
{
	size_t bytes = strlen(s);
	size_t cp = dt_utf8_cplen(s, bytes);

	if (cp <= n)
		return strdup(s);
	return slice_range(s, 0, dt_cp_offset(s, bytes, n));
}

char *dt_utf8_tail(const char *s, size_t n)
{
	size_t bytes = strlen(s);
	size_t cp = dt_utf8_cplen(s, bytes);

	if (cp <= n)
		return strdup(s);
	return slice_range(s, dt_cp_offset(s, bytes, cp - n), bytes);
}

char *dt_utf8_chop_last(const char *s)
{
	size_t bytes = strlen(s);
	size_t cp = dt_utf8_cplen(s, bytes);

	if (cp == 0)
		return strdup(s);
	return slice_range(s, 0, dt_cp_offset(s, bytes, cp - 1));
}

/* ---------------------------------------------------------------- 值语义 */

int dt_truthy(const aik_json *v)
{
	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		return 0;
	case AIK_JSON_BOOL:
		return aik_json_bool(v);
	case AIK_JSON_INT: {
		long long i = aik_json_int(v);

		return i != 0;
	}
	case AIK_JSON_NUM:
		return aik_json_num(v) != 0.0;
	case AIK_JSON_STR:
		return aik_json_strlen(v) > 0;
	case AIK_JSON_ARR:
	case AIK_JSON_OBJ:
		return aik_json_count(v) > 0;
	default:
		return 0;
	}
}

/* python repr(str) 简化:单引号 + \\ \' 转义(容器内使用) */
static void repr_str(struct dt_sbuf *b, const char *s, size_t n)
{
	dt_sb_putc(b, '\'');
	for (size_t i = 0; i < n; i++) {
		char c = s[i];

		if (c == '\'' || c == '\\')
			dt_sb_putc(b, '\\');
		dt_sb_putc(b, c);
	}
	dt_sb_putc(b, '\'');
}

static void pyrepr(struct dt_sbuf *b, const aik_json *v)
{
	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		dt_sb_putstr(b, "None");
		break;
	case AIK_JSON_BOOL:
		dt_sb_putstr(b, aik_json_bool(v) ? "True" : "False");
		break;
	case AIK_JSON_STR:
		repr_str(b, aik_json_str(v), aik_json_strlen(v));
		break;
	case AIK_JSON_INT: {
		char tmp[32];

		snprintf(tmp, sizeof(tmp), "%lld", aik_json_int(v));
		dt_sb_putstr(b, tmp);
		break;
	}
	case AIK_JSON_NUM: {
		char tmp[40];

		aik_json_dtoa(aik_json_num(v), tmp, sizeof(tmp));
		dt_sb_putstr(b, tmp);
		break;
	}
	case AIK_JSON_ARR: {
		size_t n = aik_json_count(v);

		dt_sb_putc(b, '[');
		for (size_t i = 0; i < n; i++) {
			if (i)
				dt_sb_puts(b, ", ", 2);
			pyrepr(b, aik_json_at(v, i));
		}
		dt_sb_putc(b, ']');
		break;
	}
	case AIK_JSON_OBJ: {
		size_t n = aik_json_count(v);

		dt_sb_putc(b, '{');
		for (size_t i = 0; i < n; i++) {
			if (i)
				dt_sb_puts(b, ", ", 2);
			repr_str(b, aik_json_key_at(v, i),
				 strlen(aik_json_key_at(v, i)));
			dt_sb_puts(b, ": ", 2);
			pyrepr(b, aik_json_val_at(v, i));
		}
		dt_sb_putc(b, '}');
		break;
	}
	}
}

char *dt_pystr(const aik_json *v)
{
	struct dt_sbuf b;

	dt_sb_init(&b);
	switch (aik_json_typeof(v)) {
	case AIK_JSON_STR: {
		const char *s = aik_json_str(v);
		size_t n = aik_json_strlen(v);
		char *out = malloc(n + 1);

		if (!out)
			return NULL;
		memcpy(out, s, n);
		out[n] = '\0';
		return out;
	}
	default:
		pyrepr(&b, v);
		return dt_sb_finish(&b);
	}
}

static int py_ws(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
	       c == '\v' || c == '\f' || (c >= 0x1c && c <= 0x1f);
}

char *dt_strip(const char *s)
{
	size_t n = strlen(s);
	size_t b = 0, e = n;

	while (b < e && py_ws(s[b]))
		b++;
	while (e > b && py_ws(s[e - 1]))
		e--;
	return slice_range(s, b, e);
}

/* ---------------------------------------------------------------- 文件 */

char *dt_read_file(const char *path, size_t *out_len)
{
	FILE *fh = fopen(path, "rb");
	char *buf = NULL;
	size_t cap = 8192, n = 0;

	if (!fh)
		return NULL;
	buf = malloc(cap);
	if (!buf) {
		fclose(fh);
		return NULL;
	}
	for (;;) {
		size_t r;

		if (n == cap) {
			char *q;

			cap *= 2;
			q = realloc(buf, cap);
			if (!q)
				goto fail;
			buf = q;
		}
		r = fread(buf + n, 1, cap - n, fh);
		if (r == 0)
			break;
		n += r;
	}
	if (ferror(fh))
		goto fail;
	fclose(fh);
	{
		char *q = realloc(buf, n + 1);

		if (!q) {
			free(buf);
			return NULL;
		}
		buf = q;
		buf[n] = '\0';
	}
	if (out_len)
		*out_len = n;
	return buf;
fail:
	fclose(fh);
	free(buf);
	return NULL;
}

int dt_write_file(const char *path, const void *buf, size_t n)
{
	FILE *fh = fopen(path, "wb");

	if (!fh)
		return -1;
	if (n && fwrite(buf, 1, n, fh) != n) {
		fclose(fh);
		return -1;
	}
	if (fclose(fh) != 0)
		return -1;
	return 0;
}

int dt_mkdir_p(const char *path, int mode)
{
	size_t n = strlen(path);
	char tmp[DT_PATH_MAX];

	if (n + 1 > sizeof(tmp))
		return -1;
	memcpy(tmp, path, n + 1);
	for (size_t i = 1; i < n; i++) {
		if (tmp[i] == '/') {
			tmp[i] = '\0';
			if (mkdir(tmp, mode) != 0 && errno != EEXIST)
				return -1;
			tmp[i] = '/';
		}
	}
	if (mkdir(tmp, mode) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

int dt_mkdir_if_absent(const char *path, int mode)
{
	struct stat st;

	if (stat(path, &st) == 0)
		return S_ISDIR(st.st_mode) ? 0 : -1;
	if (mkdir(path, mode) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

void dt_chmod600(const char *path)
{
	chmod(path, 0600);
}

/* POSIX os.path.normpath(词法归一,不解析符号链接) */
static void normpath(char *out, size_t cap, const char *in)
{
	int absolute = in[0] == '/';
	size_t n = strlen(in);
	const char *comps[1024];
	size_t comp_len[1024];
	size_t nc = 0;
	size_t i = 0;
	size_t outn = 0;

	while (i < n) {
		size_t start, len;

		while (i < n && in[i] == '/')
			i++;
		start = i;
		while (i < n && in[i] != '/')
			i++;
		if (i == start)
			break;
		len = i - start;
		if (len == 1 && in[start] == '.')
			continue;
		if (len == 2 && in[start] == '.' && in[start + 1] == '.') {
			if (nc > 0 && !(comp_len[nc - 1] == 2 &&
					comps[nc - 1][0] == '.' &&
					comps[nc - 1][1] == '.')) {
				nc--;    /* 弹掉前一个普通分量 */
			} else if (!absolute && nc < 1024) {
				comps[nc] = in + start;    /* 相对路径保留 .. */
				comp_len[nc] = len;
				nc++;
			}
			/* 绝对路径根上的 .. 丢弃 */
			continue;
		}
		if (nc < 1024) {
			comps[nc] = in + start;
			comp_len[nc] = len;
			nc++;
		}
	}

	if (absolute)
		out[outn++] = '/';
	if (nc == 0) {
		if (!absolute)
			out[outn++] = '.';
		out[outn] = '\0';
		return;
	}
	for (size_t k = 0; k < nc; k++) {
		if (k)
			out[outn++] = '/';
		if (outn + comp_len[k] + 1 > cap) {
			out[0] = '\0';
			return;
		}
		memcpy(out + outn, comps[k], comp_len[k]);
		outn += comp_len[k];
	}
	out[outn] = '\0';
}

void dt_normpath_join(char *out, size_t cap, const char *root,
		      const char *rel)
{
	char joined[DT_PATH_MAX * 2];

	if (rel[0] == '/')
		snprintf(joined, sizeof(joined), "%s", rel);
	else
		snprintf(joined, sizeof(joined), "%s/%s", root, rel);
	normpath(out, cap, joined);
}

void dt_abspath(char *out, size_t cap, const char *in)
{
	if (in[0] == '/') {
		normpath(out, cap, in);
	} else {
		char cwd[DT_PATH_MAX];
		char joined[DT_PATH_MAX * 2];

		if (!getcwd(cwd, sizeof(cwd)))
			cwd[0] = '\0';
		snprintf(joined, sizeof(joined), "%s/%s", cwd, in);
		normpath(out, cap, joined);
	}
}

char *dt_unquote(const char *s)
{
	struct dt_sbuf b;
	size_t n = strlen(s);
	size_t i = 0;

	dt_sb_init(&b);
	while (i < n) {
		if (s[i] == '%' && i + 2 < n) {
			int hi = -1, lo = -1;
			char h = s[i + 1], l = s[i + 2];

			if (h >= '0' && h <= '9')
				hi = h - '0';
			else if (h >= 'a' && h <= 'f')
				hi = h - 'a' + 10;
			else if (h >= 'A' && h <= 'F')
				hi = h - 'A' + 10;
			if (l >= '0' && l <= '9')
				lo = l - '0';
			else if (l >= 'a' && l <= 'f')
				lo = l - 'a' + 10;
			else if (l >= 'A' && l <= 'F')
				lo = l - 'A' + 10;
			if (hi >= 0 && lo >= 0) {
				dt_sb_putc(&b, (char)((hi << 4) | lo));
				i += 3;
				continue;
			}
		}
		dt_sb_putc(&b, s[i]);
		i++;
	}
	return dt_sb_finish(&b);
}

int dt_is_file(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int dt_is_dir(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* ---------------------------------------------------------------- MD5 */

struct md5_ctx {
	uint32_t a, b, c, d;
	uint64_t len;
	unsigned char buf[64];
	size_t fill;
};

static uint32_t rol32(uint32_t v, int s)
{
	return (v << s) | (v >> (32 - s));
}

/* SHA-2 用右旋(MD5 是左旋) */
static uint32_t rotr32(uint32_t v, int s)
{
	return (v >> s) | (v << (32 - s));
}

static void md5_block(struct md5_ctx *c, const unsigned char *p)
{
	static const uint32_t K[64] = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
	};
	static const int S[64] = {
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
	};
	uint32_t m[16];
	uint32_t a = c->a, b = c->b, cc = c->c, d = c->d;

	for (int i = 0; i < 16; i++)
		m[i] = (uint32_t)p[i * 4] | ((uint32_t)p[i * 4 + 1] << 8) |
		       ((uint32_t)p[i * 4 + 2] << 16) |
		       ((uint32_t)p[i * 4 + 3] << 24);
	for (int i = 0; i < 64; i++) {
		uint32_t f, g;

		if (i < 16) {
			f = (b & cc) | (~b & d);
			g = i;
		} else if (i < 32) {
			f = (d & b) | (~d & cc);
			g = (5 * i + 1) % 16;
		} else if (i < 48) {
			f = b ^ cc ^ d;
			g = (3 * i + 5) % 16;
		} else {
			f = cc ^ (b | ~d);
			g = (7 * i) % 16;
		}
		f = f + a + K[i] + m[g];
		a = d;
		d = cc;
		cc = b;
		b = b + rol32(f, S[i]);
	}
	c->a += a;
	c->b += b;
	c->c += cc;
	c->d += d;
}

static void md5_init(struct md5_ctx *c)
{
	c->a = 0x67452301;
	c->b = 0xefcdab89;
	c->c = 0x98badcfe;
	c->d = 0x10325476;
	c->len = 0;
	c->fill = 0;
}

static void md5_update(struct md5_ctx *c, const void *data, size_t n)
{
	const unsigned char *p = data;

	c->len += n;
	while (n > 0) {
		size_t take = 64 - c->fill;

		if (take > n)
			take = n;
		memcpy(c->buf + c->fill, p, take);
		c->fill += take;
		p += take;
		n -= take;
		if (c->fill == 64) {
			md5_block(c, c->buf);
			c->fill = 0;
		}
	}
}

static void md5_final(struct md5_ctx *c, unsigned char out[16])
{
	uint64_t bits = c->len * 8;
	unsigned char pad = 0x80;

	md5_update(c, &pad, 1);
	pad = 0;
	while (c->fill != 56)
		md5_update(c, &pad, 1);
	unsigned char lenb[8];

	for (int i = 0; i < 8; i++)
		lenb[i] = (unsigned char)(bits >> (8 * i));
	md5_update(c, lenb, 8);
	uint32_t vals[4] = { c->a, c->b, c->c, c->d };

	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			out[i * 4 + j] = (unsigned char)(vals[i] >> (8 * j));
}

void dt_md5_hex(const void *data, size_t n, char out[33])
{
	struct md5_ctx c;
	unsigned char d[16];
	static const char HEX[] = "0123456789abcdef";

	md5_init(&c);
	md5_update(&c, data, n);
	md5_final(&c, d);
	for (int i = 0; i < 16; i++) {
		out[i * 2] = HEX[d[i] >> 4];
		out[i * 2 + 1] = HEX[d[i] & 0xF];
	}
	out[32] = '\0';
}

/* ---------------------------------------------------------------- SHA256 */

struct sha256_ctx {
	uint32_t h[8];
	uint64_t len;
	unsigned char buf[64];
	size_t fill;
};

static const uint32_t SHA256_K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static void sha256_block(struct sha256_ctx *c, const unsigned char *p)
{
	uint32_t w[64];
	uint32_t h0 = c->h[0], h1 = c->h[1], h2 = c->h[2], h3 = c->h[3];
	uint32_t h4 = c->h[4], h5 = c->h[5], h6 = c->h[6], h7 = c->h[7];

	for (int i = 0; i < 16; i++)
		w[i] = ((uint32_t)p[i * 4] << 24) |
		       ((uint32_t)p[i * 4 + 1] << 16) |
		       ((uint32_t)p[i * 4 + 2] << 8) |
		       (uint32_t)p[i * 4 + 3];
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
			      (w[i - 15] >> 3);
		uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
			      (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	for (int i = 0; i < 64; i++) {
		uint32_t S1 = rotr32(h4, 6) ^ rotr32(h4, 11) ^ rotr32(h4, 25);
		uint32_t ch = (h4 & h5) ^ (~h4 & h6);
		uint32_t t1 = h7 + S1 + ch + SHA256_K[i] + w[i];
		uint32_t S0 = rotr32(h0, 2) ^ rotr32(h0, 13) ^ rotr32(h0, 22);
		uint32_t maj = (h0 & h1) ^ (h0 & h2) ^ (h1 & h2);
		uint32_t t2 = S0 + maj;

		h7 = h6;
		h6 = h5;
		h5 = h4;
		h4 = h3 + t1;
		h3 = h2;
		h2 = h1;
		h1 = h0;
		h0 = t1 + t2;
	}
	c->h[0] += h0;
	c->h[1] += h1;
	c->h[2] += h2;
	c->h[3] += h3;
	c->h[4] += h4;
	c->h[5] += h5;
	c->h[6] += h6;
	c->h[7] += h7;
}

static void sha256_init(struct sha256_ctx *c)
{
	static const uint32_t H[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372,
				       0xa54ff53a, 0x510e527f, 0x9b05688c,
				       0x1f83d9ab, 0x5be0cd19 };
	for (int i = 0; i < 8; i++)
		c->h[i] = H[i];
	c->len = 0;
	c->fill = 0;
}

static void sha256_update(struct sha256_ctx *c, const void *data, size_t n)
{
	const unsigned char *p = data;

	c->len += n;
	while (n > 0) {
		size_t take = 64 - c->fill;

		if (take > n)
			take = n;
		memcpy(c->buf + c->fill, p, take);
		c->fill += take;
		p += take;
		n -= take;
		if (c->fill == 64) {
			sha256_block(c, c->buf);
			c->fill = 0;
		}
	}
}

static void sha256_final(struct sha256_ctx *c, unsigned char out[32])
{
	uint64_t bits = c->len * 8;
	unsigned char pad = 0x80;

	sha256_update(c, &pad, 1);
	pad = 0;
	while (c->fill != 56)
		sha256_update(c, &pad, 1);
	unsigned char lenb[8];

	for (int i = 0; i < 8; i++)
		lenb[i] = (unsigned char)(bits >> (8 * (7 - i)));
	sha256_update(c, lenb, 8);
	for (int i = 0; i < 8; i++) {
		out[i * 4] = (unsigned char)(c->h[i] >> 24);
		out[i * 4 + 1] = (unsigned char)(c->h[i] >> 16);
		out[i * 4 + 2] = (unsigned char)(c->h[i] >> 8);
		out[i * 4 + 3] = (unsigned char)c->h[i];
	}
}

void dt_sha256_hex(const void *data, size_t n, char out[65])
{
	struct sha256_ctx c;
	unsigned char d[32];
	static const char HEX[] = "0123456789abcdef";

	sha256_init(&c);
	sha256_update(&c, data, n);
	sha256_final(&c, d);
	for (int i = 0; i < 32; i++) {
		out[i * 2] = HEX[d[i] >> 4];
		out[i * 2 + 1] = HEX[d[i] & 0xF];
	}
	out[64] = '\0';
}

/* ---------------------------------------------------------------- 正则 */

int dt_regex_session(const char *sid)
{
	size_t n = strlen(sid);
	size_t k = n;

	/* Python $ 允许单个尾随 '\n' */
	if (k > 0 && sid[k - 1] == '\n')
		k--;
	if (k < 1 || k > 64)
		return 0;
	for (size_t i = 0; i < k; i++) {
		char c = sid[i];

		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		      (c >= '0' && c <= '9') || c == '_' || c == '-'))
			return 0;
	}
	return 1;
}

int dt_regex_win_id(const char *wid)
{
	size_t n = strlen(wid);

	if (n < 6 || n > 11)
		return 0;
	if (wid[0] != 'w' || wid[1] != '-')
		return 0;
	for (size_t i = 2; i < n; i++)
		if (wid[i] < '0' || wid[i] > '9')
			return 0;
	return 1;
}

int dt_regex_app_id(const char *aid)
{
	size_t n = strlen(aid);

	if (n < 1 || n > 128)
		return 0;
	{
		char c = aid[0];

		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		      (c >= '0' && c <= '9')))
			return 0;
	}
	for (size_t i = 1; i < n; i++) {
		char c = aid[i];

		if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		      c == '@' || c == '+' || c == '-'))
			return 0;
	}
	return 1;
}

int dt_regex_hex6(const char *hex)
{
	size_t n = strlen(hex);

	if (n != 7 || hex[0] != '#')
		return 0;
	for (size_t i = 1; i < 7; i++) {
		char c = hex[i];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
		      (c >= 'A' && c <= 'F')))
			return 0;
	}
	return 1;
}

int dt_regex_pin(const char *pin)
{
	size_t n = strlen(pin);

	if (n < 4 || n > 8)
		return 0;
	for (size_t i = 0; i < n; i++)
		if (pin[i] < '0' || pin[i] > '9')
			return 0;
	return 1;
}

/* ---------------------------------------------------------------- env */

static const int RESERVED_PORTS[] = { 8000, 8080, 8761, 9443, 9999, 11434 };
#define N_RESERVED 6

static const char *env_or(const char *name, const char *dflt)
{
	const char *v = getenv(name);

	return (v && *v) ? v : dflt;
}

/* Python int(s) 的字符串语义:前后空白、可选符号、纯数字 */
static int py_int_parse(const char *s, long long *out)
{
	size_t i = 0, n = strlen(s);
	int neg = 0, any = 0;
	long long v = 0;

	while (i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' ||
			 s[i] == '\r' || s[i] == '\v' || s[i] == '\f'))
		i++;
	if (i < n && (s[i] == '+' || s[i] == '-')) {
		neg = s[i] == '-';
		i++;
	}
	while (i < n && s[i] >= '0' && s[i] <= '9') {
		v = v * 10 + (s[i] - '0');
		any = 1;
		i++;
	}
	while (i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' ||
			 s[i] == '\r' || s[i] == '\v' || s[i] == '\f'))
		i++;
	if (!any || i != n)
		return -1;
	*out = neg ? -v : v;
	return 0;
}

static void die(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

void dt_env_port_or_die(void)
{
	const char *s = env_or("AIK_DESKTOP_PORT", "8091");
	long long port;

	if (py_int_parse(s, &port) != 0)
		die("AIK_DESKTOP_PORT 必须是整数");
	if (!(1 <= port && port <= 65535)) {
		char msg[128];

		snprintf(msg, sizeof(msg), "AIK_DESKTOP_PORT 越界: %lld", port);
		die(msg);
	}
	for (int i = 0; i < N_RESERVED; i++) {
		if (port == RESERVED_PORTS[i]) {
			char msg[128];

			snprintf(msg, sizeof(msg),
				 "AIK_DESKTOP_PORT=%lld 与 AIKernel 既有端口冲突",
				 port);
			die(msg);
		}
	}
	g_cfg.port = (int)port;
}

void dt_env_bind_or_die(void)
{
	char raw[256];
	const char *s = env_or("AIK_DESKTOP_BIND", "127.0.0.1");
	size_t b = 0, e = strlen(s);

	while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\n' ||
			 s[b] == '\r' || s[b] == '\v' || s[b] == '\f'))
		b++;
	while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' ||
			 s[e - 1] == '\n' || s[e - 1] == '\r' ||
			 s[e - 1] == '\v' || s[e - 1] == '\f'))
		e--;
	if (e - b >= sizeof(raw))
		die("AIK_DESKTOP_BIND 只允许 loopback: ''");
	memcpy(raw, s + b, e - b);
	raw[e - b] = '\0';
	if (strcmp(raw, "127.0.0.1") != 0 && strcmp(raw, "localhost") != 0 &&
	    strcmp(raw, "::1") != 0) {
		char msg[512];

		/* Python %r:字符串加单引号 */
		snprintf(msg, sizeof(msg),
			 "AIK_DESKTOP_BIND 只允许 loopback: '%s'", raw);
		die(msg);
	}
	snprintf(g_cfg.bind_host, sizeof(g_cfg.bind_host), "%.*s",
		 (int)(sizeof(g_cfg.bind_host) - 1), raw);
}

void dt_path_join(char *out, size_t cap, const char *a, const char *b)
{
	size_t la = strlen(a), lb = strlen(b);
	int slash = la > 0 && lb > 0 && a[la - 1] != '/' && b[0] != '/';

	if (la + lb + 2 > cap) {
		out[0] = '\0';
		return;
	}
	memcpy(out, a, la);
	if (slash)
		out[la++] = '/';
	memcpy(out + la, b, lb);
	out[la + lb] = '\0';
}

int dt_paths_init(void)
{
	const char *base_env = getenv("AIK_DESKTOP_BASE");

	if (base_env && *base_env) {
		dt_abspath(g_cfg.base_dir, sizeof(g_cfg.base_dir), base_env);
	} else {
		ssize_t n = readlink("/proc/self/exe", g_cfg.base_dir,
				     sizeof(g_cfg.base_dir) - 1);
		char exe[DT_PATH_MAX];

		if (n <= 0) {
			if (!getcwd(exe, sizeof(exe)))
				return -1;
			snprintf(g_cfg.base_dir, sizeof(g_cfg.base_dir), "%.*s",
				 (int)(sizeof(exe) - 1), exe);
		} else {
			char tmp[DT_PATH_MAX];

			g_cfg.base_dir[n] = '\0';
			snprintf(tmp, sizeof(tmp), "%.*s", (int)(sizeof(tmp) - 1), g_cfg.base_dir);
			dt_abspath(g_cfg.base_dir, sizeof(g_cfg.base_dir), tmp);
			/* dirname */
			{
				char *slash = strrchr(g_cfg.base_dir, '/');

				if (slash && slash != g_cfg.base_dir)
					*slash = '\0';
				else if (slash)
					g_cfg.base_dir[1] = '\0';
			}
		}
	}

	dt_path_join(g_cfg.static_dir, sizeof(g_cfg.static_dir), g_cfg.base_dir,
		  "static");

	{
		const char *root = getenv("AIK_DESKTOP_ROOT");
		char trimmed[DT_PATH_MAX];
		size_t n, b = 0, e;

		if (!root)
			root = "";
		e = n = strlen(root);
		while (b < e && (root[b] == ' ' || root[b] == '\t' ||
				 root[b] == '\n' || root[b] == '\r'))
			b++;
		while (e > b && (root[e - 1] == ' ' || root[e - 1] == '\t' ||
				 root[e - 1] == '\n' || root[e - 1] == '\r'))
			e--;
		if (b == e)
			dt_path_join(trimmed, sizeof(trimmed), g_cfg.base_dir,
				  "data");
		else {
			memcpy(trimmed, root + b, e - b);
			trimmed[e - b] = '\0';
		}
		dt_abspath(g_cfg.state_root, sizeof(g_cfg.state_root), trimmed);
	}

	dt_path_join(g_cfg.theme_file, sizeof(g_cfg.theme_file), g_cfg.state_root,
		  "theme.json");
	dt_path_join(g_cfg.theme_seed, sizeof(g_cfg.theme_seed), g_cfg.base_dir,
		  "theme.json");
	dt_path_join(g_cfg.locale_file, sizeof(g_cfg.locale_file), g_cfg.base_dir,
		  "locales/zh_CN.json");
	dt_path_join(g_cfg.wallpaper_dir, sizeof(g_cfg.wallpaper_dir),
		  g_cfg.static_dir, "wallpapers");
	dt_path_join(g_cfg.chat_dir, sizeof(g_cfg.chat_dir), g_cfg.state_root,
		  "chats");
	dt_path_join(g_cfg.pin_file, sizeof(g_cfg.pin_file), g_cfg.state_root,
		  "pin.json");
	dt_path_join(g_cfg.notif_file, sizeof(g_cfg.notif_file), g_cfg.state_root,
		  "notifs.json");
	dt_path_join(g_cfg.desktop_file, sizeof(g_cfg.desktop_file),
		  g_cfg.state_root, "desktop.json");
	dt_path_join(g_cfg.screenshot_dir, sizeof(g_cfg.screenshot_dir),
		  g_cfg.state_root, "screenshots");
	dt_path_join(g_cfg.icon_root, sizeof(g_cfg.icon_root), g_cfg.state_root,
		  "icons");
	dt_path_join(g_cfg.icon_out_dir, sizeof(g_cfg.icon_out_dir),
		  g_cfg.icon_root, "apps");
	dt_path_join(g_cfg.gen_icon_dir, sizeof(g_cfg.gen_icon_dir),
		  g_cfg.static_dir, "icons/gen");
	dt_path_join(g_cfg.catalog_file, sizeof(g_cfg.catalog_file),
		  g_cfg.base_dir, "data/apps-catalog.json");
	dt_path_join(g_cfg.seed_notifs, sizeof(g_cfg.seed_notifs),
		  g_cfg.base_dir, "data/notifs.json");
	dt_path_join(g_cfg.seed_desktop, sizeof(g_cfg.seed_desktop),
		  g_cfg.base_dir, "data/desktop.json");
	dt_path_join(g_cfg.seed_pin, sizeof(g_cfg.seed_pin), g_cfg.base_dir,
		  "data/pin.json");

	{
		const char *apps = env_or("AIK_DESKTOP_APPS_DIR",
					  "/usr/share/applications");
		size_t n = strlen(apps), b = 0, e = n;

		while (b < e && (apps[b] == ' ' || apps[b] == '\t' ||
				 apps[b] == '\n' || apps[b] == '\r'))
			b++;
		while (e > b && (apps[e - 1] == ' ' || apps[e - 1] == '\t' ||
				 apps[e - 1] == '\n' || apps[e - 1] == '\r'))
			e--;
		if (e - b >= sizeof(g_cfg.apps_dir))
			return -1;
		memcpy(g_cfg.apps_dir, apps + b, e - b);
		g_cfg.apps_dir[e - b] = '\0';
	}

	{
		const char *vm = env_or("AIK_DESKTOP_VM", "0");
		char low[64];
		size_t n = strlen(vm), b = 0, e = n;

		while (b < e && (vm[b] == ' ' || vm[b] == '\t' || vm[b] == '\n' ||
				 vm[b] == '\r'))
			b++;
		while (e > b && (vm[e - 1] == ' ' || vm[e - 1] == '\t' ||
				 vm[e - 1] == '\n' || vm[e - 1] == '\r'))
			e--;
		if (e - b >= sizeof(low))
			return -1;
		for (size_t i = 0; b + i < e; i++) {
			char c = vm[b + i];

			low[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a')
							: c;
		}
		low[e - b] = '\0';
		g_cfg.vm_enabled = !(strcmp(low, "0") == 0 ||
				     strcmp(low, "false") == 0 ||
				     strcmp(low, "no") == 0 ||
				     strcmp(low, "off") == 0 ||
				     strcmp(low, "disabled") == 0);
	}

	{
		const char *sc = env_or("AIK_DESKTOP_SCREENSHOT", "auto");
		char low[64];
		size_t n = strlen(sc), b = 0, e = n;

		while (b < e && (sc[b] == ' ' || sc[b] == '\t' || sc[b] == '\n' ||
				 sc[b] == '\r'))
			b++;
		while (e > b && (sc[e - 1] == ' ' || sc[e - 1] == '\t' ||
				 sc[e - 1] == '\n' || sc[e - 1] == '\r'))
			e--;
		if (e - b >= sizeof(low))
			return -1;
		for (size_t i = 0; b + i < e; i++) {
			char c = sc[b + i];

			low[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a')
							: c;
		}
		low[e - b] = '\0';
		snprintf(g_cfg.screenshot_mode, sizeof(g_cfg.screenshot_mode),
			 "%s", low);
	}

	{
		const char *home = env_or("HOME", "");

		if (*home)
			dt_path_join(g_cfg.model_toml, sizeof(g_cfg.model_toml),
				  home, ".aikernel/model.toml");
		else
			snprintf(g_cfg.model_toml, sizeof(g_cfg.model_toml),
				 ".aikernel/model.toml");
	}

	{
		/* VM_CONF = ~/.aikernel/vm138.conf(T6c:dtvm 凭据) */
		const char *home = env_or("HOME", "");

		if (*home)
			dt_path_join(g_cfg.vm_conf, sizeof(g_cfg.vm_conf),
				  home, ".aikernel/vm138.conf");
		else
			snprintf(g_cfg.vm_conf, sizeof(g_cfg.vm_conf),
				 ".aikernel/vm138.conf");
	}

	snprintf(g_cfg.version, sizeof(g_cfg.version), "IMG-7-W76b");
	dt_strftime(g_cfg.start_ts, sizeof(g_cfg.start_ts),
		    "%Y-%m-%d %H:%M:%S");
	return 0;
}
