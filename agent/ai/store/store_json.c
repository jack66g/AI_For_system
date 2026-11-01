/* SPDX-License-Identifier: GPL-2.0 */
/*
 * store_json.c - 存储层 JSON DOM / CPython repr 等价 dtoa / 紧凑序列化
 *
 * 设计依据 T2-DESIGN.md §2。整体是手写递归下降解析器：不建 token 表，
 * 直接产出 DOM；错误路径统一走 perr()，只报首个错误并以
 * "offset=N: reason" 形式落在调用者缓冲里，树在失败时整棵释放，绝不
 * 部分成功。
 *
 * 数字：词法无 '.'/'e'/'E' → 走 int64 累加（溢出则退回 double）；其余
 * 走 strtod。整个过程包在 LC_NUMERIC=C 的 uselocale 里，与进程 locale
 * 无关（风险 S2）。
 *
 * dtoa：p=1..17 依次 snprintf("%.*e") 再 strtod 回读，首个按位往返成功
 * 者即最短表示；随后按 CPython 规则排版（decpt<=-4 或 >16 科学计数、
 * 指数至少两位、定点整数补 ".0"）。同样包在 C locale 里，风险 S1/S2。
 *
 * 序列化：ensure_ascii=False 等价——只转义 '"'、'\\' 与 <0x20，其余
 * 字节（含 >=0x80 的 UTF-8）原样写出；对象保持插入序。
 */
#define _GNU_SOURCE 1

#include "store/store_json.h"

#include <limits.h>
#include <locale.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 解析深度上限：防护恶意/损坏输入的栈溢出（快照实测深度 5） */
#define AIK_JSON_MAX_DEPTH 512

/* ------------------------------------------------------------------ */
/* DOM 节点                                                            */
/* ------------------------------------------------------------------ */

struct aik_json {
	aik_json_type type;
	union {
		int b;
		long long i;
		double d;
		struct {
			char *p;	/* NUL 结尾，可含内嵌 NUL（由 n 界定） */
			size_t n;
		} s;
		struct {
			aik_json **v;
			size_t n;
			size_t cap;
		} a;
		struct {
			char **k;
			size_t *kl;
			aik_json **v;
			size_t n;
			size_t cap;
		} o;
	} u;
};

static void *aik_malloc(size_t n)
{
	return malloc(n ? n : 1);
}

static void *aik_realloc(void *p, size_t n)
{
	return realloc(p, n ? n : 1);
}

static aik_json *node_new(aik_json_type t)
{
	aik_json *v = calloc(1, sizeof(*v));

	if (!v)
		return NULL;
	v->type = t;
	return v;
}

aik_json *aik_json_new_null(void)
{
	return node_new(AIK_JSON_NULL);
}

aik_json *aik_json_new_bool(int b)
{
	aik_json *v = node_new(AIK_JSON_BOOL);

	if (v)
		v->u.b = b ? 1 : 0;
	return v;
}

aik_json *aik_json_new_int(long long i)
{
	aik_json *v = node_new(AIK_JSON_INT);

	if (v)
		v->u.i = i;
	return v;
}

aik_json *aik_json_new_num(double d)
{
	aik_json *v = node_new(AIK_JSON_NUM);

	if (v)
		v->u.d = d;
	return v;
}

aik_json *aik_json_new_str(const char *utf8)
{
	aik_json *v;
	size_t n;

	if (!utf8)
		return NULL;
	n = strlen(utf8);
	v = node_new(AIK_JSON_STR);
	if (!v)
		return NULL;
	v->u.s.p = aik_malloc(n + 1);
	if (!v->u.s.p) {
		free(v);
		return NULL;
	}
	memcpy(v->u.s.p, utf8, n + 1);
	v->u.s.n = n;
	return v;
}

aik_json *aik_json_new_arr(void)
{
	return node_new(AIK_JSON_ARR);
}

aik_json *aik_json_new_obj(void)
{
	return node_new(AIK_JSON_OBJ);
}

void aik_json_free(aik_json *v)
{
	size_t i;

	if (!v)
		return;
	switch (v->type) {
	case AIK_JSON_STR:
		free(v->u.s.p);
		break;
	case AIK_JSON_ARR:
		for (i = 0; i < v->u.a.n; i++)
			aik_json_free(v->u.a.v[i]);
		free(v->u.a.v);
		break;
	case AIK_JSON_OBJ:
		for (i = 0; i < v->u.o.n; i++) {
			free(v->u.o.k[i]);
			aik_json_free(v->u.o.v[i]);
		}
		free(v->u.o.k);
		free(v->u.o.kl);
		free(v->u.o.v);
		break;
	default:
		break;
	}
	free(v);
}

/* ------------------------------------------------------------------ */
/* 访问器                                                              */
/* ------------------------------------------------------------------ */

aik_json_type aik_json_typeof(const aik_json *v)
{
	return v ? v->type : AIK_JSON_NULL;
}

int aik_json_bool(const aik_json *v)
{
	return (v && v->type == AIK_JSON_BOOL) ? v->u.b : 0;
}

long long aik_json_int(const aik_json *v)
{
	if (!v)
		return 0;
	if (v->type == AIK_JSON_INT)
		return v->u.i;
	if (v->type == AIK_JSON_NUM)
		return (long long)v->u.d;
	return 0;
}

double aik_json_num(const aik_json *v)
{
	if (!v)
		return 0.0;
	if (v->type == AIK_JSON_NUM)
		return v->u.d;
	if (v->type == AIK_JSON_INT)
		return (double)v->u.i;
	return 0.0;
}

const char *aik_json_str(const aik_json *v)
{
	return (v && v->type == AIK_JSON_STR) ? v->u.s.p : NULL;
}

size_t aik_json_strlen(const aik_json *v)
{
	return (v && v->type == AIK_JSON_STR) ? v->u.s.n : 0;
}

size_t aik_json_count(const aik_json *v)
{
	if (!v)
		return 0;
	if (v->type == AIK_JSON_ARR)
		return v->u.a.n;
	if (v->type == AIK_JSON_OBJ)
		return v->u.o.n;
	return 0;
}

const aik_json *aik_json_at(const aik_json *v, size_t i)
{
	if (!v || v->type != AIK_JSON_ARR || i >= v->u.a.n)
		return NULL;
	return v->u.a.v[i];
}

const char *aik_json_key_at(const aik_json *v, size_t i)
{
	if (!v || v->type != AIK_JSON_OBJ || i >= v->u.o.n)
		return NULL;
	return v->u.o.k[i];
}

const aik_json *aik_json_val_at(const aik_json *v, size_t i)
{
	if (!v || v->type != AIK_JSON_OBJ || i >= v->u.o.n)
		return NULL;
	return v->u.o.v[i];
}

const aik_json *aik_json_get(const aik_json *v, const char *key)
{
	size_t i, n;

	if (!v || v->type != AIK_JSON_OBJ || !key)
		return NULL;
	n = strlen(key);
	for (i = 0; i < v->u.o.n; i++) {
		if (v->u.o.kl[i] == n && memcmp(v->u.o.k[i], key, n) == 0)
			return v->u.o.v[i];	/* 首次出现 */
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/* 构造器                                                              */
/* ------------------------------------------------------------------ */

int aik_json_arr_push(aik_json *arr, aik_json *v)
{
	aik_json **nv;
	size_t cap;

	if (!arr || arr->type != AIK_JSON_ARR || !v)
		return -1;
	if (arr->u.a.n == arr->u.a.cap) {
		cap = arr->u.a.cap ? arr->u.a.cap * 2 : 8;
		nv = aik_realloc(arr->u.a.v, cap * sizeof(*nv));
		if (!nv)
			return -1;
		arr->u.a.v = nv;
		arr->u.a.cap = cap;
	}
	arr->u.a.v[arr->u.a.n++] = v;
	return 0;
}

static int obj_grow(aik_json *o)
{
	size_t cap = o->u.o.cap ? o->u.o.cap * 2 : 8;
	char **k;
	size_t *kl;
	aik_json **v;

	k = aik_realloc(o->u.o.k, cap * sizeof(*k));
	if (!k)
		return -1;
	o->u.o.k = k;
	kl = aik_realloc(o->u.o.kl, cap * sizeof(*kl));
	if (!kl)
		return -1;
	o->u.o.kl = kl;
	v = aik_realloc(o->u.o.v, cap * sizeof(*v));
	if (!v)
		return -1;
	o->u.o.v = v;
	o->u.o.cap = cap;
	return 0;
}

/*
 * obj_put_len - 追加或替换键值
 *
 * replace=1 时：已存在同字节键则释放旧值、保留原位置（Python dict 语义）；
 * replace=0 时无条件追加（显式构造重复键）。
 */
static int obj_put_len(aik_json *o, const char *key, size_t klen,
		       aik_json *v, int replace)
{
	size_t i;
	char *kc;

	if (!o || o->type != AIK_JSON_OBJ || !key || !v)
		return -1;
	if (replace) {
		for (i = 0; i < o->u.o.n; i++) {
			if (o->u.o.kl[i] == klen &&
			    memcmp(o->u.o.k[i], key, klen) == 0) {
				aik_json_free(o->u.o.v[i]);
				o->u.o.v[i] = v;
				return 0;
			}
		}
	}
	if (o->u.o.n == o->u.o.cap && obj_grow(o) != 0)
		return -1;
	kc = aik_malloc(klen + 1);
	if (!kc)
		return -1;
	memcpy(kc, key, klen);
	kc[klen] = '\0';
	o->u.o.k[o->u.o.n] = kc;
	o->u.o.kl[o->u.o.n] = klen;
	o->u.o.v[o->u.o.n] = v;
	o->u.o.n++;
	return 0;
}

int aik_json_obj_put(aik_json *obj, const char *key, aik_json *v)
{
	if (!key)
		return -1;
	return obj_put_len(obj, key, strlen(key), v, 0);
}

int aik_json_obj_set(aik_json *obj, const char *key, aik_json *v)
{
	if (!key)
		return -1;
	return obj_put_len(obj, key, strlen(key), v, 1);
}

/* ------------------------------------------------------------------ */
/* locale：把数字解析/格式化钉在 C locale                              */
/* ------------------------------------------------------------------ */

static locale_t aik_c_locale(void)
{
	static locale_t cached;

	if (cached)
		return cached;
	/*
	 * 进程单线程地建立一次；测试程序与存储读路径都是单线程使用，
	 * 因此不做加锁（避免引入 -pthread 依赖）。
	 */
	cached = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
	return cached;
}

/* ------------------------------------------------------------------ */
/* 解析器                                                              */
/* ------------------------------------------------------------------ */

struct pctx {
	const char *buf;
	size_t len;
	size_t pos;
	int depth;
	int failed;
	char *err;
	size_t errlen;
};

static void perr(struct pctx *p, const char *reason)
{
	if (p->failed)
		return;
	p->failed = 1;
	if (p->err && p->errlen)
		(void)snprintf(p->err, p->errlen, "offset=%zu: %s", p->pos,
			       reason);
}

static void skip_ws(struct pctx *p)
{
	while (p->pos < p->len) {
		char c = p->buf[p->pos];

		if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
			break;
		p->pos++;
	}
}

static int is_digit(int c)
{
	return c >= '0' && c <= '9';
}

static int hexval(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* 简单可增长字节缓冲（字符串解码与 dump 共用思路） */
struct sbuf {
	char *p;
	size_t n;
	size_t cap;
};

static int sb_reserve(struct sbuf *b, size_t extra)
{
	size_t cap = b->cap ? b->cap : 16;
	char *np;

	if (b->n + extra + 1 <= b->cap)
		return 0;
	while (cap < b->n + extra + 1) {
		if (cap > (SIZE_MAX >> 2))
			return -1;
		cap *= 2;
	}
	np = aik_realloc(b->p, cap);
	if (!np)
		return -1;
	b->p = np;
	b->cap = cap;
	return 0;
}

static int sb_putc(struct sbuf *b, char c)
{
	if (sb_reserve(b, 1) != 0)
		return -1;
	b->p[b->n++] = c;
	return 0;
}

static int sb_putn(struct sbuf *b, const char *s, size_t n)
{
	if (sb_reserve(b, n) != 0)
		return -1;
	memcpy(b->p + b->n, s, n);
	b->n += n;
	return 0;
}

/* Unicode 码点 → UTF-8（孤立代理按 WTF-8 三字节编码，与 Python 字符串
 * 允许孤立代理的行为对齐） */
static size_t utf8_put(unsigned cp, char *out)
{
	if (cp < 0x80) {
		out[0] = (char)cp;
		return 1;
	}
	if (cp < 0x800) {
		out[0] = (char)(0xC0 | (cp >> 6));
		out[1] = (char)(0x80 | (cp & 0x3F));
		return 2;
	}
	if (cp < 0x10000) {
		out[0] = (char)(0xE0 | (cp >> 12));
		out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
		out[2] = (char)(0x80 | (cp & 0x3F));
		return 3;
	}
	out[0] = (char)(0xF0 | (cp >> 18));
	out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
	out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
	out[3] = (char)(0x80 | (cp & 0x3F));
	return 4;
}

static int read_hex4(struct pctx *p, unsigned *out)
{
	unsigned v = 0;
	int i;

	if (p->len - p->pos < 4) {
		perr(p, "invalid \\u escape");
		return -1;
	}
	for (i = 0; i < 4; i++) {
		int h = hexval((unsigned char)p->buf[p->pos + i]);

		if (h < 0) {
			perr(p, "invalid \\u escape");
			return -1;
		}
		v = (v << 4) | (unsigned)h;
	}
	p->pos += 4;
	*out = v;
	return 0;
}

/*
 * parse_string_raw - 解析一个带引号的 JSON 字符串
 *
 * 成功置 *out 为 malloc 的 NUL 结尾缓冲、*outlen 为字节长度。
 */
static int parse_string_raw(struct pctx *p, char **out, size_t *outlen)
{
	struct sbuf sb = { NULL, 0, 0 };

	if (p->pos >= p->len || p->buf[p->pos] != '"') {
		perr(p, "expected string");
		return -1;
	}
	p->pos++;
	for (;;) {
		unsigned char c;
		int e;

		if (p->pos >= p->len) {
			perr(p, "unexpected end of input in string");
			goto fail;
		}
		c = (unsigned char)p->buf[p->pos++];
		if (c == '"')
			break;
		if (c < 0x20) {
			perr(p, "control character in string");
			goto fail;
		}
		if (c != '\\') {
			if (sb_putc(&sb, (char)c) != 0) {
				perr(p, "out of memory");
				goto fail;
			}
			continue;
		}
		if (p->pos >= p->len) {
			perr(p, "unexpected end of input in string");
			goto fail;
		}
		e = (unsigned char)p->buf[p->pos++];
		switch (e) {
		case '"':
			if (sb_putc(&sb, '"') != 0)
				goto oom;
			break;
		case '\\':
			if (sb_putc(&sb, '\\') != 0)
				goto oom;
			break;
		case '/':
			if (sb_putc(&sb, '/') != 0)
				goto oom;
			break;
		case 'b':
			if (sb_putc(&sb, '\b') != 0)
				goto oom;
			break;
		case 'f':
			if (sb_putc(&sb, '\f') != 0)
				goto oom;
			break;
		case 'n':
			if (sb_putc(&sb, '\n') != 0)
				goto oom;
			break;
		case 'r':
			if (sb_putc(&sb, '\r') != 0)
				goto oom;
			break;
		case 't':
			if (sb_putc(&sb, '\t') != 0)
				goto oom;
			break;
		case 'u': {
			unsigned cp;
			char tmp[4];
			size_t n;

			if (read_hex4(p, &cp) != 0)
				goto fail;
			if (cp >= 0xD800 && cp <= 0xDBFF &&
			    p->pos + 6 <= p->len && p->buf[p->pos] == '\\' &&
			    p->buf[p->pos + 1] == 'u') {
				size_t save = p->pos;
				unsigned lo;

				p->pos += 2;
				if (read_hex4(p, &lo) != 0)
					goto fail;
				if (lo >= 0xDC00 && lo <= 0xDFFF)
					cp = 0x10000 + ((cp - 0xD800) << 10) +
					     (lo - 0xDC00);
				else
					p->pos = save;	/* 孤立高代理 */
			}
			n = utf8_put(cp, tmp);
			if (sb_putn(&sb, tmp, n) != 0)
				goto oom;
			break;
		}
		default:
			perr(p, "invalid escape");
			goto fail;
		}
	}
	if (sb_putc(&sb, '\0') != 0)
		goto oom;
	*outlen = sb.n - 1;
	*out = sb.p;
	return 0;
oom:
	perr(p, "out of memory");
fail:
	free(sb.p);
	return -1;
}

static int expect_lit(struct pctx *p, const char *lit)
{
	size_t n = strlen(lit);

	if (p->len - p->pos < n || memcmp(p->buf + p->pos, lit, n) != 0) {
		perr(p, "invalid literal");
		return -1;
	}
	p->pos += n;
	return 0;
}

/* 整数词法 → int64，溢出返回 -1 */
static int lex_i64(const char *s, size_t n, long long *out)
{
	size_t i = 0;
	int neg = 0;
	unsigned long long acc = 0;
	unsigned long long limit;

	if (i < n && s[i] == '-') {
		neg = 1;
		i++;
	}
	if (i >= n)
		return -1;
	limit = neg ? 9223372036854775808ULL : 9223372036854775807ULL;
	for (; i < n; i++) {
		unsigned d;

		if (!is_digit((unsigned char)s[i]))
			return -1;
		d = (unsigned)(s[i] - '0');
		if (acc > (limit - d) / 10)
			return -1;
		acc = acc * 10 + d;
	}
	if (neg) {
		if (acc == 9223372036854775808ULL)
			*out = LLONG_MIN;
		else
			*out = -(long long)acc;
	} else {
		*out = (long long)acc;
	}
	return 0;
}

/* 浮点词法 → double；调用时已处于 C locale */
static int lex_f64(const char *s, size_t n, double *out)
{
	char tmp[64];
	char *heap = NULL;
	char *p = tmp;
	char *end = NULL;
	double d;

	if (n + 1 > sizeof(tmp)) {
		heap = aik_malloc(n + 1);
		if (!heap)
			return -1;
		p = heap;
	}
	memcpy(p, s, n);
	p[n] = '\0';
	d = strtod(p, &end);
	if (!end || (size_t)(end - p) != n) {
		free(heap);
		return -1;
	}
	free(heap);
	*out = d;
	return 0;
}

static aik_json *parse_value(struct pctx *p);

static aik_json *parse_number(struct pctx *p)
{
	size_t start = p->pos;
	int is_float = 0;
	aik_json *v;

	if (p->pos < p->len && p->buf[p->pos] == '-')
		p->pos++;
	if (p->pos >= p->len) {
		perr(p, "invalid number");
		return NULL;
	}
	if (p->buf[p->pos] == '0') {
		p->pos++;
		if (p->pos < p->len && is_digit((unsigned char)p->buf[p->pos])) {
			perr(p, "invalid number (leading zero)");
			return NULL;
		}
	} else if (p->buf[p->pos] >= '1' && p->buf[p->pos] <= '9') {
		while (p->pos < p->len && is_digit((unsigned char)p->buf[p->pos]))
			p->pos++;
	} else {
		perr(p, "invalid number");
		return NULL;
	}
	if (p->pos < p->len && p->buf[p->pos] == '.') {
		is_float = 1;
		p->pos++;
		if (p->pos >= p->len || !is_digit((unsigned char)p->buf[p->pos])) {
			perr(p, "invalid number");
			return NULL;
		}
		while (p->pos < p->len && is_digit((unsigned char)p->buf[p->pos]))
			p->pos++;
	}
	if (p->pos < p->len &&
	    (p->buf[p->pos] == 'e' || p->buf[p->pos] == 'E')) {
		is_float = 1;
		p->pos++;
		if (p->pos < p->len &&
		    (p->buf[p->pos] == '+' || p->buf[p->pos] == '-'))
			p->pos++;
		if (p->pos >= p->len || !is_digit((unsigned char)p->buf[p->pos])) {
			perr(p, "invalid number");
			return NULL;
		}
		while (p->pos < p->len && is_digit((unsigned char)p->buf[p->pos]))
			p->pos++;
	}
	if (!is_float) {
		long long i;

		if (lex_i64(p->buf + start, p->pos - start, &i) == 0) {
			v = aik_json_new_int(i);
			if (!v)
				perr(p, "out of memory");
			return v;
		}
		/* int64 之外的整数按 NUM 处理（设计 §2 的取值约定） */
	}
	{
		double d;

		if (lex_f64(p->buf + start, p->pos - start, &d) != 0) {
			perr(p, "invalid number");
			return NULL;
		}
		v = aik_json_new_num(d);
		if (!v)
			perr(p, "out of memory");
		return v;
	}
}

static aik_json *parse_object(struct pctx *p)
{
	aik_json *obj, *val;
	char *key;
	size_t klen;

	if (p->depth >= AIK_JSON_MAX_DEPTH) {
		perr(p, "nesting too deep");
		return NULL;
	}
	obj = aik_json_new_obj();
	if (!obj) {
		perr(p, "out of memory");
		return NULL;
	}
	p->pos++;	/* '{' */
	p->depth++;
	skip_ws(p);
	if (p->pos < p->len && p->buf[p->pos] == '}') {
		p->pos++;
		p->depth--;
		return obj;
	}
	for (;;) {
		skip_ws(p);
		if (parse_string_raw(p, &key, &klen) != 0)
			goto fail;
		skip_ws(p);
		if (p->pos >= p->len || p->buf[p->pos] != ':') {
			perr(p, "expected ':'");
			free(key);
			goto fail;
		}
		p->pos++;
		val = parse_value(p);
		if (!val) {
			free(key);
			goto fail;
		}
		if (obj_put_len(obj, key, klen, val, 1) != 0) {
			perr(p, "out of memory");
			free(key);
			aik_json_free(val);
			goto fail;
		}
		free(key);
		skip_ws(p);
		if (p->pos >= p->len) {
			perr(p, "unexpected end of input");
			goto fail;
		}
		if (p->buf[p->pos] == ',') {
			p->pos++;
			continue;
		}
		if (p->buf[p->pos] == '}') {
			p->pos++;
			break;
		}
		perr(p, "expected ',' or '}'");
		goto fail;
	}
	p->depth--;
	return obj;
fail:
	aik_json_free(obj);
	p->depth--;
	return NULL;
}

static aik_json *parse_array(struct pctx *p)
{
	aik_json *arr, *val;

	if (p->depth >= AIK_JSON_MAX_DEPTH) {
		perr(p, "nesting too deep");
		return NULL;
	}
	arr = aik_json_new_arr();
	if (!arr) {
		perr(p, "out of memory");
		return NULL;
	}
	p->pos++;	/* '[' */
	p->depth++;
	skip_ws(p);
	if (p->pos < p->len && p->buf[p->pos] == ']') {
		p->pos++;
		p->depth--;
		return arr;
	}
	for (;;) {
		val = parse_value(p);
		if (!val)
			goto fail;
		if (aik_json_arr_push(arr, val) != 0) {
			perr(p, "out of memory");
			aik_json_free(val);
			goto fail;
		}
		skip_ws(p);
		if (p->pos >= p->len) {
			perr(p, "unexpected end of input");
			goto fail;
		}
		if (p->buf[p->pos] == ',') {
			p->pos++;
			continue;
		}
		if (p->buf[p->pos] == ']') {
			p->pos++;
			break;
		}
		perr(p, "expected ',' or ']'");
		goto fail;
	}
	p->depth--;
	return arr;
fail:
	aik_json_free(arr);
	p->depth--;
	return NULL;
}

static aik_json *parse_value(struct pctx *p)
{
	aik_json *v;

	skip_ws(p);
	if (p->pos >= p->len) {
		perr(p, "unexpected end of input");
		return NULL;
	}
	switch (p->buf[p->pos]) {
	case '{':
		return parse_object(p);
	case '[':
		return parse_array(p);
	case '"': {
		char *s;
		size_t n;

		if (parse_string_raw(p, &s, &n) != 0)
			return NULL;
		v = node_new(AIK_JSON_STR);
		if (!v) {
			free(s);
			perr(p, "out of memory");
			return NULL;
		}
		v->u.s.p = s;
		v->u.s.n = n;
		return v;
	}
	case 't':
		if (expect_lit(p, "true") != 0)
			return NULL;
		return aik_json_new_bool(1);
	case 'f':
		if (expect_lit(p, "false") != 0)
			return NULL;
		return aik_json_new_bool(0);
	case 'n':
		if (expect_lit(p, "null") != 0)
			return NULL;
		return aik_json_new_null();
	default:
		return parse_number(p);
	}
}

aik_json *aik_json_parse(const char *buf, size_t len, char *err, size_t errlen)
{
	struct pctx p;
	aik_json *v = NULL;
	locale_t loc, old = (locale_t)0;

	if (err && errlen)
		err[0] = '\0';
	if (!buf) {
		if (err && errlen)
			(void)snprintf(err, errlen, "offset=0: null buffer");
		return NULL;
	}
	memset(&p, 0, sizeof(p));
	p.buf = buf;
	p.len = len;
	p.err = err;
	p.errlen = errlen;

	/* 整个解析过程钉在 C locale，保证 strtod 的 '.' 语义（风险 S2） */
	loc = aik_c_locale();
	if (loc)
		old = uselocale(loc);

	skip_ws(&p);
	if (p.pos >= p.len) {
		perr(&p, "unexpected end of input");
	} else {
		v = parse_value(&p);
		if (v) {
			skip_ws(&p);
			if (p.pos != p.len) {
				perr(&p, "trailing data");
				aik_json_free(v);
				v = NULL;
			}
		}
	}

	if (old)
		(void)uselocale(old);
	if (!v && err && errlen && err[0] == '\0')
		(void)snprintf(err, errlen, "offset=%zu: parse failed", p.pos);
	return v;
}

/* ------------------------------------------------------------------ */
/* dtoa：最短往返 + CPython repr 排版                                  */
/* ------------------------------------------------------------------ */

static int put_ch(char *buf, size_t buflen, size_t *n, char c)
{
	if (*n + 1 >= buflen)
		return -1;
	buf[(*n)++] = c;
	return 0;
}

static int put_digits(char *buf, size_t buflen, size_t *n, const char *d,
		      size_t from, size_t to)
{
	size_t i;

	for (i = from; i < to; i++)
		if (put_ch(buf, buflen, n, d[i]) != 0)
			return -1;
	return 0;
}

/*
 * repr_format - 按 CPython float_repr 规则排版
 *
 * digits/nd 为最短往返的有效数字，decpt 为小数点相对首位数字的位置
 * （即 10 的指数 + 1）。decpt<=-4 或 decpt>16 用科学计数，指数至少两位；
 * 定点时整数补 ".0"。
 */
static int repr_format(char *buf, size_t buflen, int neg, const char *digits,
		       size_t nd, int decpt)
{
	size_t n = 0;
	int i;

	if (neg && put_ch(buf, buflen, &n, '-') != 0)
		return -1;

	if (decpt <= -4 || decpt > 16) {
		int e = decpt - 1;
		unsigned ae;

		if (put_ch(buf, buflen, &n, digits[0]) != 0)
			return -1;
		if (nd > 1) {
			if (put_ch(buf, buflen, &n, '.') != 0 ||
			    put_digits(buf, buflen, &n, digits, 1, nd) != 0)
				return -1;
		}
		if (put_ch(buf, buflen, &n, 'e') != 0)
			return -1;
		ae = (unsigned)(e < 0 ? -e : e);
		if (put_ch(buf, buflen, &n, e < 0 ? '-' : '+') != 0)
			return -1;
		if (ae >= 100) {
			if (put_ch(buf, buflen, &n, (char)('0' + ae / 100)) != 0 ||
			    put_ch(buf, buflen, &n, (char)('0' + (ae / 10) % 10)) != 0 ||
			    put_ch(buf, buflen, &n, (char)('0' + ae % 10)) != 0)
				return -1;
		} else {
			if (put_ch(buf, buflen, &n, (char)('0' + ae / 10)) != 0 ||
			    put_ch(buf, buflen, &n, (char)('0' + ae % 10)) != 0)
				return -1;
		}
	} else if (decpt <= 0) {
		if (put_ch(buf, buflen, &n, '0') != 0 ||
		    put_ch(buf, buflen, &n, '.') != 0)
			return -1;
		for (i = 0; i < -decpt; i++)
			if (put_ch(buf, buflen, &n, '0') != 0)
				return -1;
		if (put_digits(buf, buflen, &n, digits, 0, nd) != 0)
			return -1;
	} else if ((size_t)decpt >= nd) {
		if (put_digits(buf, buflen, &n, digits, 0, nd) != 0)
			return -1;
		for (i = 0; i < decpt - (int)nd; i++)
			if (put_ch(buf, buflen, &n, '0') != 0)
				return -1;
		if (put_ch(buf, buflen, &n, '.') != 0 ||
		    put_ch(buf, buflen, &n, '0') != 0)
			return -1;
	} else {
		if (put_digits(buf, buflen, &n, digits, 0, (size_t)decpt) != 0 ||
		    put_ch(buf, buflen, &n, '.') != 0 ||
		    put_digits(buf, buflen, &n, digits, (size_t)decpt, nd) != 0)
			return -1;
	}
	if (n >= buflen)
		return -1;
	buf[n] = '\0';
	return (int)n;
}

int aik_json_dtoa(double v, char *buf, size_t buflen)
{
	char tmp[64];
	char digits[24];
	size_t nd;
	int p, i, neg = 0, decpt = 0, exp10 = 0;
	locale_t loc, old = (locale_t)0;

	if (!buf || buflen == 0)
		return -1;

	if (isnan(v)) {
		if (buflen < 4)
			return -1;
		memcpy(buf, "NaN", 4);
		return 3;
	}
	if (isinf(v)) {
		const char *s = v < 0 ? "-Infinity" : "Infinity";
		size_t n = strlen(s);

		if (buflen < n + 1)
			return -1;
		memcpy(buf, s, n + 1);
		return (int)n;
	}

	/* 整个尝试循环只在一次 uselocale 内完成（风险 S2） */
	loc = aik_c_locale();
	if (loc)
		old = uselocale(loc);

	for (p = 1; p <= 17; p++) {
		double back;
		int r;

		r = snprintf(tmp, sizeof(tmp), "%.*e", p - 1, v);
		if (r < 0 || (size_t)r >= sizeof(tmp))
			break;
		back = strtod(tmp, NULL);
		if (memcmp(&back, &v, sizeof(back)) == 0)
			break;	/* p 最小 → 最短往返表示 */
	}
	if (old)
		(void)uselocale(old);
	if (p > 17)
		p = 17;

	i = 0;
	if (tmp[i] == '-') {
		neg = 1;
		i++;
	}
	nd = 0;
	while (tmp[i] && tmp[i] != 'e' && tmp[i] != 'E') {
		if (tmp[i] >= '0' && tmp[i] <= '9') {
			if (nd + 1 >= sizeof(digits))
				return -1;
			digits[nd++] = tmp[i];
		}
		i++;
	}
	if (nd == 0)
		return -1;
	if (tmp[i] == 'e' || tmp[i] == 'E') {
		int eneg = 0;

		i++;
		if (tmp[i] == '+' || tmp[i] == '-') {
			eneg = tmp[i] == '-';
			i++;
		}
		while (tmp[i] >= '0' && tmp[i] <= '9') {
			exp10 = exp10 * 10 + (tmp[i] - '0');
			i++;
		}
		if (eneg)
			exp10 = -exp10;
	}
	decpt = exp10 + 1;
	return repr_format(buf, buflen, neg, digits, nd, decpt);
}

/* ------------------------------------------------------------------ */
/* 序列化                                                              */
/* ------------------------------------------------------------------ */

static const char aik_hexd[] = "0123456789abcdef";

static int dump_buf_grow(struct sbuf *b, size_t need)
{
	size_t cap = b->cap ? b->cap : 256;
	char *np;

	if (b->n + need + 1 <= b->cap)
		return 0;
	while (cap < b->n + need + 1) {
		if (cap > (SIZE_MAX >> 2))
			return -1;
		cap *= 2;
	}
	np = aik_realloc(b->p, cap);
	if (!np)
		return -1;
	b->p = np;
	b->cap = cap;
	return 0;
}

static int dump_puts(struct sbuf *b, const char *s, size_t n)
{
	if (dump_buf_grow(b, n) != 0)
		return -1;
	memcpy(b->p + b->n, s, n);
	b->n += n;
	return 0;
}

static int dump_putc(struct sbuf *b, char c)
{
	if (dump_buf_grow(b, 1) != 0)
		return -1;
	b->p[b->n++] = c;
	return 0;
}

/* ensure_ascii=False 等价转义 */
static int dump_str(struct sbuf *b, const char *s, size_t n)
{
	size_t i;

	if (dump_putc(b, '"') != 0)
		return -1;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];

		switch (c) {
		case '"':
			if (dump_puts(b, "\\\"", 2) != 0)
				return -1;
			break;
		case '\\':
			if (dump_puts(b, "\\\\", 2) != 0)
				return -1;
			break;
		case '\b':
			if (dump_puts(b, "\\b", 2) != 0)
				return -1;
			break;
		case '\f':
			if (dump_puts(b, "\\f", 2) != 0)
				return -1;
			break;
		case '\n':
			if (dump_puts(b, "\\n", 2) != 0)
				return -1;
			break;
		case '\r':
			if (dump_puts(b, "\\r", 2) != 0)
				return -1;
			break;
		case '\t':
			if (dump_puts(b, "\\t", 2) != 0)
				return -1;
			break;
		default:
			if (c < 0x20) {
				char esc[6];

				esc[0] = '\\';
				esc[1] = 'u';
				esc[2] = '0';
				esc[3] = '0';
				esc[4] = aik_hexd[c >> 4];
				esc[5] = aik_hexd[c & 0x0F];
				if (dump_puts(b, esc, sizeof(esc)) != 0)
					return -1;
			} else if (dump_putc(b, (char)c) != 0) {
				return -1;
			}
			break;
		}
	}
	return dump_putc(b, '"');
}

static int dump_value(struct sbuf *b, const aik_json *v)
{
	size_t i;

	if (!v)
		return dump_puts(b, "null", 4);
	switch (v->type) {
	case AIK_JSON_NULL:
		return dump_puts(b, "null", 4);
	case AIK_JSON_BOOL:
		return v->u.b ? dump_puts(b, "true", 4)
			      : dump_puts(b, "false", 5);
	case AIK_JSON_INT: {
		char tmp[32];
		int n = snprintf(tmp, sizeof(tmp), "%lld", v->u.i);

		if (n < 0 || (size_t)n >= sizeof(tmp))
			return -1;
		return dump_puts(b, tmp, (size_t)n);
	}
	case AIK_JSON_NUM: {
		char tmp[64];
		int n = aik_json_dtoa(v->u.d, tmp, sizeof(tmp));

		if (n < 0)
			return -1;
		return dump_puts(b, tmp, (size_t)n);
	}
	case AIK_JSON_STR:
		return dump_str(b, v->u.s.p, v->u.s.n);
	case AIK_JSON_ARR:
		if (dump_putc(b, '[') != 0)
			return -1;
		for (i = 0; i < v->u.a.n; i++) {
			if (i && dump_putc(b, ',') != 0)
				return -1;
			if (dump_value(b, v->u.a.v[i]) != 0)
				return -1;
		}
		return dump_putc(b, ']');
	case AIK_JSON_OBJ:
		if (dump_putc(b, '{') != 0)
			return -1;
		for (i = 0; i < v->u.o.n; i++) {
			if (i && dump_putc(b, ',') != 0)
				return -1;
			if (dump_str(b, v->u.o.k[i], v->u.o.kl[i]) != 0 ||
			    dump_putc(b, ':') != 0 ||
			    dump_value(b, v->u.o.v[i]) != 0)
				return -1;
		}
		return dump_putc(b, '}');
	}
	return -1;
}

int aik_json_dump(const aik_json *v, char **out, size_t *outlen)
{
	struct sbuf b = { NULL, 0, 0 };

	if (!out || !outlen)
		return -1;
	*out = NULL;
	*outlen = 0;
	if (dump_value(&b, v) != 0) {
		free(b.p);
		return -1;
	}
	if (dump_buf_grow(&b, 0) != 0) {
		free(b.p);
		return -1;
	}
	b.p[b.n] = '\0';
	*out = b.p;
	*outlen = b.n;
	return 0;
}
