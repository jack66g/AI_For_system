/* SPDX-License-Identifier: GPL-2.0 */
/*
 * net_intent.c - W81 V3.1 网络意图 ↔ nft 规则双向编译实现（四件）
 *
 * 正向（自然语言 → nft）：
 *   ni_parse_intent  封闭语法解析（端口/协议/方向/默认策略；不猜测、不吞错）
 *   ni_compile       解析结果格式化成 nft 规则集文本（不做字符串拼接注入）
 *   ni_diff          与现网表做行级 LCS 差异（- 现网 / + 目标）作为下发预览
 *   nft_intent_apply 预检(nft -c -f) → 快照 → 应用(nft -f) → 抽查 → 挂自动回滚
 *
 * 反向（现网规则 → 人话）：
 *   ni_summarize  nft -j list ruleset 的 JSON 走本地 mini-DOM 解析后，按
 *                 「默认策略 / 允许 / 拒绝 / 其他」分段输出；空规则集、
 *                 截断、畸形 JSON、非对象数组元素一律明说，绝不崩。
 *
 * 链路复用：预检/应用/抽查调用 net_admin.c 导出的 ai_nft_run_file() /
 * ai_nft_list_args()——与 W78 nft_txn 同一有界 fork/execv + 超时实现。
 *
 * 安全边界（硬约束写进代码）：
 *   - 只处理自己的一张表（默认 inet aik_intent），绝不 flush ruleset；
 *   - 默认拒绝且未放行 22/tcp 时 apply 拒绝（除非 allow_lockout=true）；
 *   - apply 后 setsid 看门狗：arm_seconds 内无确认决定 → 自动回滚；
 *   - 本模块不做任何降级闸门的动作；D3 判定在 policy/ai_lease.c。
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "tool_registry.h"
#include "net_admin.h"
#include "net_intent.h"

/* ======================================================================
 * 0) 小工具
 * ====================================================================== */

struct sbuf {
	char *p;
	size_t cap;
	size_t used;
	int trunc;
};

static void sb_init(struct sbuf *b, char *p, size_t cap)
{
	b->p = p;
	b->cap = cap;
	b->used = 0;
	b->trunc = 0;
	if (cap)
		p[0] = '\0';
}

static void sb_printf(struct sbuf *b, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (b->trunc || b->cap == 0 || b->used + 1 >= b->cap)
		return;
	va_start(ap, fmt);
	n = vsnprintf(b->p + b->used, b->cap - b->used, fmt, ap);
	va_end(ap);
	if (n < 0) {
		b->trunc = 1;
		return;
	}
	if ((size_t)n >= b->cap - b->used) {
		b->used = b->cap - 1;
		b->trunc = 1;
		return;
	}
	b->used += (size_t)n;
}

/* 动态增长缓冲（反向摘要内部用；最终拷进调用者定长 buf） */
struct dbuf {
	char *p;
	size_t cap;
	size_t used;
	int oom;
};

static void db_init(struct dbuf *b)
{
	b->cap = 4096;
	b->p = malloc(b->cap);
	b->used = 0;
	b->oom = b->p ? 0 : 1;
	if (b->p)
		b->p[0] = '\0';
}

static void db_free(struct dbuf *b)
{
	free(b->p);
	b->p = NULL;
}

static int db_reserve(struct dbuf *b, size_t need)
{
	char *np;
	size_t nc;

	if (b->oom)
		return -1;
	if (b->used + need + 1 <= b->cap)
		return 0;
	nc = b->cap;
	while (nc < b->used + need + 1)
		nc *= 2;
	np = realloc(b->p, nc);
	if (!np) {
		b->oom = 1;
		return -1;
	}
	b->p = np;
	b->cap = nc;
	return 0;
}

static void db_printf(struct dbuf *b, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (db_reserve(b, 256) != 0)
		return;
	va_start(ap, fmt);
	n = vsnprintf(b->p + b->used, b->cap - b->used, fmt, ap);
	va_end(ap);
	if (n < 0) {
		b->oom = 1;
		return;
	}
	if ((size_t)n >= b->cap - b->used) {
		if (db_reserve(b, (size_t)n) != 0)
			return;
		va_start(ap, fmt);
		n = vsnprintf(b->p + b->used, b->cap - b->used, fmt, ap);
		va_end(ap);
		if (n < 0 || (size_t)n >= b->cap - b->used) {
			b->oom = 1;
			return;
		}
	}
	b->used += (size_t)n;
}

/* JSON 字符串参数（支持 \\ \" \/ \n \t \r；\uXXXX 拒绝——意图文本不需要） */
static int ni_arg_str(const char *json, const char *key, char *out, size_t cap)
{
	char pat[64];
	const char *p;
	size_t used = 0;

	if (!json || !key || !out || cap == 0)
		return -1;
	snprintf(pat, sizeof(pat), "\"%s\":", key);
	p = strstr(json, pat);
	if (!p)
		return -1;
	p += strlen(pat);
	while (*p == ' ' || *p == '\t' || *p == '\n')
		p++;
	if (*p != '"')
		return -1;
	p++;
	while (*p && *p != '"') {
		char c = *p;

		if (c == '\\') {
			p++;
			switch (*p) {
			case '"': c = '"'; break;
			case '\\': c = '\\'; break;
			case '/': c = '/'; break;
			case 'n': c = '\n'; break;
			case 't': c = '\t'; break;
			case 'r': c = '\r'; break;
			default:
				return -1;
			}
		}
		if (used + 1 >= cap)
			return -1;
		out[used++] = c;
		p++;
	}
	if (*p != '"')
		return -1;
	out[used] = '\0';
	return 0;
}

static int ni_arg_bool(const char *json, const char *key, int dflt)
{
	char pat[64];
	const char *p;

	snprintf(pat, sizeof(pat), "\"%s\":", key);
	p = strstr(json, pat);
	if (!p)
		return dflt;
	p += strlen(pat);
	while (*p == ' ' || *p == '\t')
		p++;
	if (strncmp(p, "true", 4) == 0)
		return 1;
	if (strncmp(p, "false", 5) == 0)
		return 0;
	return dflt;
}

static long ni_arg_int(const char *json, const char *key, long dflt)
{
	char pat[64];
	const char *p;
	char *end;
	long v;

	snprintf(pat, sizeof(pat), "\"%s\":", key);
	p = strstr(json, pat);
	if (!p)
		return dflt;
	p += strlen(pat);
	while (*p == ' ' || *p == '\t')
		p++;
	v = strtol(p, &end, 10);
	if (end == p)
		return dflt;
	return v;
}

int ni_valid_table(const char *name)
{
	size_t i, n;

	if (!name || !*name)
		return 0;
	n = strlen(name);
	if (n > NI_TABLE_LEN - 1)
		return 0;
	if (!(name[0] >= 'a' && name[0] <= 'z') && name[0] != '_')
		return 0;
	for (i = 0; i < n; i++) {
		char c = name[i];

		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		      c == '_'))
			return 0;
	}
	return 1;
}

void ni_digest(const char *text, char out[17])
{
	unsigned long long h = 1469598103934665603ULL;
	const unsigned char *p = (const unsigned char *)text;

	while (p && *p) {
		h ^= *p++;
		h *= 1099511628211ULL;
	}
	snprintf(out, 17, "%016llx", h);
}

/* ======================================================================
 * 1) mini JSON DOM（只为本模块服务：深度/节点双上限，失败即报错）
 * ====================================================================== */

enum jv_type { JV_NULL = 0, JV_BOOL, JV_NUM, JV_STR, JV_ARR, JV_OBJ };

struct jv {
	unsigned char t;
	char *s;		/* JV_STR 解码后文本；JV_NUM/JV_BOOL 原文 */
	struct jv **val;	/* 数组元素 / 对象值 */
	char **key;		/* 对象键（数组为 NULL） */
	int n;
};

struct jp {
	const char *p;
	const char *end;
	int depth;
	int nodes;
	int err;
};

#define JP_MAX_DEPTH	64
#define JP_MAX_NODES	50000

static void jv_free(struct jv *v)
{
	int i;

	if (!v)
		return;
	for (i = 0; i < v->n; i++) {
		jv_free(v->val[i]);
		if (v->key)
			free(v->key[i]);
	}
	free(v->val);
	free(v->key);
	free(v->s);
	free(v);
}

static struct jv *jv_new(enum jv_type t)
{
	struct jv *v = calloc(1, sizeof(*v));

	if (v)
		v->t = (unsigned char)t;
	return v;
}

static void jp_ws(struct jp *c)
{
	while (c->p < c->end && (*c->p == ' ' || *c->p == '\t' ||
				 *c->p == '\n' || *c->p == '\r'))
		c->p++;
}

static int jp_hex4(struct jp *c, unsigned int *out)
{
	unsigned int v = 0;
	int i;

	if (c->end - c->p < 4)
		return -1;
	for (i = 0; i < 4; i++) {
		char ch = c->p[i];

		v <<= 4;
		if (ch >= '0' && ch <= '9')
			v |= (unsigned int)(ch - '0');
		else if (ch >= 'a' && ch <= 'f')
			v |= (unsigned int)(ch - 'a' + 10);
		else if (ch >= 'A' && ch <= 'F')
			v |= (unsigned int)(ch - 'A' + 10);
		else
			return -1;
	}
	c->p += 4;
	*out = v;
	return 0;
}

static int jp_utf8(unsigned int cp, char *out, size_t cap)
{
	if (cap < 4)
		return -1;
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

/* 解析字符串（c->p 指向开引号）；返回 malloc 文本 */
static char *jp_string(struct jp *c)
{
	const char *start;
	char *out;
	size_t used = 0;
	size_t cap;

	if (c->p >= c->end || *c->p != '"') {
		c->err = 1;
		return NULL;
	}
	c->p++;
	start = c->p;
	cap = (size_t)(c->end - start) + 1;
	out = malloc(cap);
	if (!out) {
		c->err = 1;
		return NULL;
	}
	while (c->p < c->end && *c->p != '"') {
		char ch = *c->p;

		if (ch == '\\') {
			c->p++;
			if (c->p >= c->end) {
				free(out);
				c->err = 1;
				return NULL;
			}
			switch (*c->p) {
			case '"': out[used++] = '"'; c->p++; break;
			case '\\': out[used++] = '\\'; c->p++; break;
			case '/': out[used++] = '/'; c->p++; break;
			case 'b': out[used++] = '\b'; c->p++; break;
			case 'f': out[used++] = '\f'; c->p++; break;
			case 'n': out[used++] = '\n'; c->p++; break;
			case 'r': out[used++] = '\r'; c->p++; break;
			case 't': out[used++] = '\t'; c->p++; break;
			case 'u': {
				unsigned int cp, lo;
				int k;

				c->p++;
				if (jp_hex4(c, &cp) != 0) {
					free(out);
					c->err = 1;
					return NULL;
				}
				if (cp >= 0xD800 && cp <= 0xDBFF &&
				    c->end - c->p >= 6 && c->p[0] == '\\' &&
				    c->p[1] == 'u') {
					c->p += 2;
					if (jp_hex4(c, &lo) != 0) {
						free(out);
						c->err = 1;
						return NULL;
					}
					if (lo >= 0xDC00 && lo <= 0xDFFF)
						cp = 0x10000 +
						     ((cp - 0xD800) << 10) +
						     (lo - 0xDC00);
					else
						cp = 0xFFFD;
				}
				k = jp_utf8(cp, out + used, cap - used);
				if (k < 0) {
					free(out);
					c->err = 1;
					return NULL;
				}
				used += (size_t)k;
				break;
			}
			default:
				free(out);
				c->err = 1;
				return NULL;
			}
			continue;
		}
		if ((unsigned char)ch < 0x20) {
			free(out);
			c->err = 1;
			return NULL;
		}
		out[used++] = ch;
		c->p++;
	}
	if (c->p >= c->end || *c->p != '"') {
		free(out);
		c->err = 1;
		return NULL;
	}
	c->p++;
	out[used] = '\0';
	return out;
}

static struct jv *jp_value(struct jp *c);

static struct jv *jp_number(struct jp *c)
{
	const char *s = c->p;
	struct jv *v;

	if (c->p < c->end && (*c->p == '-' || *c->p == '+'))
		c->p++;
	if (c->p < c->end && *c->p == '0') {
		c->p++;
	} else {
		if (c->p >= c->end || !isdigit((unsigned char)*c->p)) {
			c->err = 1;
			return NULL;
		}
		while (c->p < c->end && isdigit((unsigned char)*c->p))
			c->p++;
	}
	if (c->p < c->end && *c->p == '.') {
		c->p++;
		if (c->p >= c->end || !isdigit((unsigned char)*c->p)) {
			c->err = 1;
			return NULL;
		}
		while (c->p < c->end && isdigit((unsigned char)*c->p))
			c->p++;
	}
	if (c->p < c->end && (*c->p == 'e' || *c->p == 'E')) {
		c->p++;
		if (c->p < c->end && (*c->p == '-' || *c->p == '+'))
			c->p++;
		if (c->p >= c->end || !isdigit((unsigned char)*c->p)) {
			c->err = 1;
			return NULL;
		}
		while (c->p < c->end && isdigit((unsigned char)*c->p))
			c->p++;
	}
	v = jv_new(JV_NUM);
	if (!v) {
		c->err = 1;
		return NULL;
	}
	v->s = strndup(s, (size_t)(c->p - s));
	if (!v->s) {
		jv_free(v);
		c->err = 1;
		return NULL;
	}
	return v;
}

static struct jv *jp_array(struct jp *c)
{
	struct jv *v = jv_new(JV_ARR);

	if (!v) {
		c->err = 1;
		return NULL;
	}
	c->p++;			/* '[' */
	for (;;) {
		struct jv *e;
		struct jv **nv;

		jp_ws(c);
		if (c->p >= c->end) {
			jv_free(v);
			c->err = 1;
			return NULL;
		}
		if (*c->p == ']') {
			c->p++;
			return v;
		}
		e = jp_value(c);
		if (!e) {
			jv_free(v);
			return NULL;
		}
		nv = realloc(v->val, sizeof(*nv) * (size_t)(v->n + 1));
		if (!nv) {
			jv_free(e);
			jv_free(v);
			c->err = 1;
			return NULL;
		}
		v->val = nv;
		v->val[v->n++] = e;
		jp_ws(c);
		if (c->p < c->end && *c->p == ',') {
			c->p++;
			continue;
		}
		if (c->p < c->end && *c->p == ']') {
			c->p++;
			return v;
		}
		jv_free(v);
		c->err = 1;
		return NULL;
	}
}

static struct jv *jp_object(struct jp *c)
{
	struct jv *v = jv_new(JV_OBJ);

	if (!v) {
		c->err = 1;
		return NULL;
	}
	c->p++;			/* '{' */
	for (;;) {
		char *k;
		struct jv *e;
		struct jv **nv;
		char **nk;

		jp_ws(c);
		if (c->p >= c->end) {
			jv_free(v);
			c->err = 1;
			return NULL;
		}
		if (*c->p == '}') {
			c->p++;
			return v;
		}
		k = jp_string(c);
		if (!k) {
			jv_free(v);
			return NULL;
		}
		jp_ws(c);
		if (c->p >= c->end || *c->p != ':') {
			free(k);
			jv_free(v);
			c->err = 1;
			return NULL;
		}
		c->p++;
		e = jp_value(c);
		if (!e) {
			free(k);
			jv_free(v);
			return NULL;
		}
		nv = realloc(v->val, sizeof(*nv) * (size_t)(v->n + 1));
		nk = realloc(v->key, sizeof(*nk) * (size_t)(v->n + 1));
		if (!nv || !nk) {
			free(k);
			jv_free(e);
			if (nv)
				v->val = nv;
			if (nk)
				v->key = nk;
			jv_free(v);
			c->err = 1;
			return NULL;
		}
		v->val = nv;
		v->key = nk;
		v->key[v->n] = k;
		v->val[v->n] = e;
		v->n++;
		jp_ws(c);
		if (c->p < c->end && *c->p == ',') {
			c->p++;
			continue;
		}
		if (c->p < c->end && *c->p == '}') {
			c->p++;
			return v;
		}
		jv_free(v);
		c->err = 1;
		return NULL;
	}
}

static struct jv *jp_value(struct jp *c)
{
	struct jv *v;

	if (c->err)
		return NULL;
	if (++c->nodes > JP_MAX_NODES) {
		c->err = 1;
		return NULL;
	}
	if (++c->depth > JP_MAX_DEPTH) {
		c->err = 1;
		return NULL;
	}
	jp_ws(c);
	if (c->p >= c->end) {
		c->err = 1;
		return NULL;
	}
	switch (*c->p) {
	case '{':
		v = jp_object(c);
		break;
	case '[':
		v = jp_array(c);
		break;
	case '"': {
		char *s = jp_string(c);

		if (!s)
			return NULL;
		v = jv_new(JV_STR);
		if (!v) {
			free(s);
			c->err = 1;
		} else {
			v->s = s;
		}
		break;
	}
	case 't':
		if (c->end - c->p >= 4 && strncmp(c->p, "true", 4) == 0) {
			c->p += 4;
			v = jv_new(JV_BOOL);
			if (v)
				v->s = strdup("true");
		} else {
			c->err = 1;
			return NULL;
		}
		break;
	case 'f':
		if (c->end - c->p >= 5 && strncmp(c->p, "false", 5) == 0) {
			c->p += 5;
			v = jv_new(JV_BOOL);
			if (v)
				v->s = strdup("false");
		} else {
			c->err = 1;
			return NULL;
		}
		break;
	case 'n':
		if (c->end - c->p >= 4 && strncmp(c->p, "null", 4) == 0) {
			c->p += 4;
			v = jv_new(JV_NULL);
		} else {
			c->err = 1;
			return NULL;
		}
		break;
	default:
		v = jp_number(c);
		break;
	}
	c->depth--;
	if (!v)
		c->err = 1;
	return v;
}

/* 根值解析：必须整串消费（尾随空白除外） */
static struct jv *jp_root(const char *text, size_t len, char *err,
			  size_t errcap)
{
	struct jp c;
	struct jv *v;

	memset(&c, 0, sizeof(c));
	c.p = text;
	c.end = text + len;
	v = jp_value(&c);
	if (!v) {
		snprintf(err, errcap, "JSON 解析失败（偏移 %ld，原因：%s）",
			 (long)(c.p - text),
			 c.nodes > JP_MAX_NODES ? "节点数超限" :
			 c.depth > JP_MAX_DEPTH ? "嵌套过深" : "语法非法");
		return NULL;
	}
	jp_ws(&c);
	if (c.p != c.end) {
		snprintf(err, errcap, "JSON 解析失败（偏移 %ld 处有多余内容）",
			 (long)(c.p - text));
		jv_free(v);
		return NULL;
	}
	return v;
}

static struct jv *jv_get(const struct jv *o, const char *key)
{
	int i;

	if (!o || o->t != JV_OBJ || !key)
		return NULL;
	for (i = 0; i < o->n; i++)
		if (o->key[i] && strcmp(o->key[i], key) == 0)
			return o->val[i];
	return NULL;
}

/* 对象里唯一的键（nft -j 的表达式元素形如 {"match":{...}}） */
static const char *jv_single_key(const struct jv *o)
{
	if (!o || o->t != JV_OBJ || o->n != 1)
		return NULL;
	return o->key[0];
}

static struct jv *jv_single_val(const struct jv *o)
{
	if (!o || o->t != JV_OBJ || o->n != 1)
		return NULL;
	return o->val[0];
}

static const char *jv_str(const struct jv *o, const char *key)
{
	struct jv *v = jv_get(o, key);

	if (!v || v->t != JV_STR || !v->s)
		return NULL;
	return v->s;
}

static long long jv_int(const struct jv *o, const char *key, long long dflt)
{
	struct jv *v = jv_get(o, key);

	if (!v || v->t != JV_NUM || !v->s)
		return dflt;
	return strtoll(v->s, NULL, 10);
}

/* 紧凑 JSON 回显（未知表达式用） */
static void jv_dump(const struct jv *v, char *out, size_t cap, size_t *used)
{
	int i;

	if (!v || *used + 1 >= cap)
		return;
	switch (v->t) {
	case JV_NULL:
		*used += (size_t)snprintf(out + *used, cap - *used, "null");
		break;
	case JV_BOOL:
	case JV_NUM:
		*used += (size_t)snprintf(out + *used, cap - *used, "%s",
					  v->s ? v->s : "?");
		break;
	case JV_STR:
		*used += (size_t)snprintf(out + *used, cap - *used, "\"%s\"",
					  v->s ? v->s : "");
		break;
	case JV_ARR:
		*used += (size_t)snprintf(out + *used, cap - *used, "[");
		for (i = 0; i < v->n && *used + 1 < cap; i++) {
			if (i)
				*used += (size_t)snprintf(out + *used,
							  cap - *used, ",");
			jv_dump(v->val[i], out, cap, used);
		}
		if (*used + 1 < cap)
			*used += (size_t)snprintf(out + *used, cap - *used,
						  "]");
		break;
	case JV_OBJ:
		*used += (size_t)snprintf(out + *used, cap - *used, "{");
		for (i = 0; i < v->n && *used + 1 < cap; i++) {
			if (i)
				*used += (size_t)snprintf(out + *used,
							  cap - *used, ",");
			*used += (size_t)snprintf(out + *used, cap - *used,
						  "\"%s\":", v->key[i]);
			jv_dump(v->val[i], out, cap, used);
		}
		if (*used + 1 < cap)
			*used += (size_t)snprintf(out + *used, cap - *used,
						  "}");
		break;
	}
	if (*used >= cap)
		*used = cap - 1;
	out[*used] = '\0';
}

/* ======================================================================
 * 2) 反向：表达式 → 人话
 * ====================================================================== */

static const char *proto_word(const char *p)
{
	if (!p)
		return "";
	if (strcmp(p, "tcp") == 0)
		return "TCP ";
	if (strcmp(p, "udp") == 0)
		return "UDP ";
	if (strcmp(p, "ip") == 0)
		return "IPv4 ";
	if (strcmp(p, "ip6") == 0)
		return "IPv6 ";
	if (strcmp(p, "icmp") == 0)
		return "ICMP ";
	if (strcmp(p, "icmpv6") == 0)
		return "ICMPv6 ";
	if (strcmp(p, "sctp") == 0)
		return "SCTP ";
	return p;
}

static const char *field_word(const char *f)
{
	if (!f)
		return "";
	if (strcmp(f, "dport") == 0)
		return "目的端口";
	if (strcmp(f, "sport") == 0)
		return "源端口";
	if (strcmp(f, "saddr") == 0)
		return "源地址";
	if (strcmp(f, "daddr") == 0)
		return "目的地址";
	if (strcmp(f, "dscp") == 0)
		return "DSCP";
	if (strcmp(f, "length") == 0)
		return "长度";
	return f;
}

static const char *ct_word(const char *k)
{
	if (!k)
		return "连接跟踪";
	if (strcmp(k, "state") == 0)
		return "连接状态";
	if (strcmp(k, "direction") == 0)
		return "连接方向";
	if (strcmp(k, "status") == 0)
		return "连接状态字";
	if (strcmp(k, "mark") == 0)
		return "连接标记";
	if (strcmp(k, "expiration") == 0)
		return "连接过期";
	return k;
}

static const char *meta_word(const char *k)
{
	if (!k)
		return "元数据";
	if (strcmp(k, "iif") == 0)
		return "入接口";
	if (strcmp(k, "oif") == 0)
		return "出接口";
	if (strcmp(k, "iifname") == 0)
		return "入接口名";
	if (strcmp(k, "oifname") == 0)
		return "出接口名";
	if (strcmp(k, "l4proto") == 0)
		return "传输协议";
	if (strcmp(k, "nfproto") == 0)
		return "协议族";
	if (strcmp(k, "mark") == 0)
		return "标记";
	if (strcmp(k, "skuid") == 0)
		return "套接字 UID";
	if (strcmp(k, "skgid") == 0)
		return "套接字 GID";
	if (strcmp(k, "protocol") == 0)
		return "以太类型";
	return k;
}

/* 右侧值：字符串/数字/prefix/range/set/数组 */
static void render_right(const struct jv *v, char *out, size_t cap)
{
	size_t used = 0;

	if (!v) {
		snprintf(out, cap, "?");
		return;
	}
	if (v->t == JV_STR) {
		snprintf(out, cap, "\"%s\"", v->s ? v->s : "");
		return;
	}
	if (v->t == JV_NUM || v->t == JV_BOOL) {
		snprintf(out, cap, "%s", v->s ? v->s : "?");
		return;
	}
	if (v->t == JV_ARR) {
		struct sbuf b;
		int i;

		sb_init(&b, out, cap);
		sb_printf(&b, "{");
		for (i = 0; i < v->n; i++) {
			char one[160];

			if (i)
				sb_printf(&b, ", ");
			if (v->val[i]->t == JV_STR)
				snprintf(one, sizeof(one), "%s",
					 v->val[i]->s);
			else
				render_right(v->val[i], one, sizeof(one));
			sb_printf(&b, "%s", one);
		}
		sb_printf(&b, "}");
		return;
	}
	if (v->t == JV_OBJ) {
		struct jv *prefix = jv_get(v, "prefix");
		struct jv *range = jv_get(v, "range");
		struct jv *set = jv_get(v, "set");

		if (prefix) {
			const char *addr = jv_str(prefix, "addr");

			snprintf(out, cap, "%s/%lld", addr ? addr : "?",
				 jv_int(prefix, "len", -1));
			return;
		}
		if (range && range->t == JV_ARR && range->n == 2) {
			snprintf(out, cap, "%s-%s",
				 range->val[0]->s ? range->val[0]->s : "?",
				 range->val[1]->s ? range->val[1]->s : "?");
			return;
		}
		if (set)
			render_right(set, out, cap);
		else
			jv_dump(v, out, cap, &used);
		return;
	}
	snprintf(out, cap, "?");
}

/* 左侧表达式：payload/meta/ct/其他 */
static void render_left(const struct jv *v, char *out, size_t cap)
{
	struct jv *payload, *meta, *ct;
	size_t used = 0;

	if (!v) {
		snprintf(out, cap, "?");
		return;
	}
	if (v->t != JV_OBJ) {
		jv_dump(v, out, cap, &used);
		return;
	}
	payload = jv_get(v, "payload");
	meta = jv_get(v, "meta");
	ct = jv_get(v, "ct");
	if (payload) {
		const char *proto = jv_str(payload, "protocol");
		const char *field = jv_str(payload, "field");

		snprintf(out, cap, "%s%s", proto_word(proto),
			 field_word(field));
		return;
	}
	if (meta) {
		snprintf(out, cap, "%s", meta_word(jv_str(meta, "key")));
		return;
	}
	if (ct) {
		snprintf(out, cap, "%s", ct_word(jv_str(ct, "key")));
		return;
	}
	jv_dump(v, out, cap, &used);
}

/* 一条 match 表达式 → 人话 */
static void render_match(const struct jv *m, char *out, size_t cap)
{
	const char *op = jv_str(m, "op");
	struct jv *left = jv_get(m, "left");
	struct jv *right = jv_get(m, "right");
	char ltxt[192], rtxt[192];
	struct sbuf b;

	render_left(left, ltxt, sizeof(ltxt));
	render_right(right, rtxt, sizeof(rtxt));
	sb_init(&b, out, cap);
	if (!op || strcmp(op, "==") == 0)
		sb_printf(&b, "%s %s", ltxt, rtxt);
	else if (strcmp(op, "!=") == 0)
		sb_printf(&b, "%s != %s", ltxt, rtxt);
	else if (strcmp(op, "in") == 0)
		sb_printf(&b, "%s 属于 %s", ltxt, rtxt);
	else if (strcmp(op, "not in") == 0)
		sb_printf(&b, "%s 不属于 %s", ltxt, rtxt);
	else
		sb_printf(&b, "%s %s %s", ltxt, op, rtxt);
}

/* 规则 → 动作分类 + 人话动作 */
enum ni_rule_kind { NI_R_ALLOW = 0, NI_R_DENY, NI_R_OTHER };

static int render_action(const struct jv *expr, char *out, size_t cap)
{
	const char *k = jv_single_key(expr);

	if (!k) {
		snprintf(out, cap, "未知表达式");
		return NI_R_OTHER;
	}
	if (strcmp(k, "accept") == 0) {
		snprintf(out, cap, "允许");
		return NI_R_ALLOW;
	}
	if (strcmp(k, "drop") == 0) {
		snprintf(out, cap, "拒绝并丢弃");
		return NI_R_DENY;
	}
	if (strcmp(k, "reject") == 0) {
		snprintf(out, cap, "拒绝并回错误");
		return NI_R_DENY;
	}
	if (strcmp(k, "jump") == 0) {
		struct jv *v = jv_single_val(expr);
		const char *t = v && v->t == JV_OBJ ?
			jv_str(v, "target") : NULL;

		snprintf(out, cap, "跳转到链 %s", t ? t : "?");
		return NI_R_OTHER;
	}
	if (strcmp(k, "goto") == 0) {
		struct jv *v = jv_single_val(expr);
		const char *t = v && v->t == JV_OBJ ?
			jv_str(v, "target") : NULL;

		snprintf(out, cap, "转到链 %s", t ? t : "?");
		return NI_R_OTHER;
	}
	if (strcmp(k, "return") == 0) {
		snprintf(out, cap, "返回上层链");
		return NI_R_OTHER;
	}
	if (strcmp(k, "masquerade") == 0) {
		snprintf(out, cap, "SNAT 伪装");
		return NI_R_OTHER;
	}
	if (strcmp(k, "snat") == 0) {
		snprintf(out, cap, "源地址转换");
		return NI_R_OTHER;
	}
	if (strcmp(k, "dnat") == 0) {
		snprintf(out, cap, "目的地址转换");
		return NI_R_OTHER;
	}
	if (strcmp(k, "redirect") == 0) {
		snprintf(out, cap, "端口重定向");
		return NI_R_OTHER;
	}
	if (strcmp(k, "queue") == 0) {
		snprintf(out, cap, "送用户态队列");
		return NI_R_OTHER;
	}
	if (strcmp(k, "log") == 0) {
		snprintf(out, cap, "记录日志");
		return NI_R_OTHER;
	}
	if (strcmp(k, "counter") == 0) {
		snprintf(out, cap, "计数");
		return NI_R_OTHER;
	}
	snprintf(out, cap, "动作 %s", k);
	return NI_R_OTHER;
}

/* ======================================================================
 * 3) 反向摘要
 * ====================================================================== */

int ni_summarize(const char *json, const char *only_table, char *buf,
		 size_t cap, char *err, size_t errcap)
{
	struct jv *root, *arr;
	struct dbuf out, allow, deny, other;
	int i, table_n = 0, chain_n = 0, rule_n = 0, allow_n = 0, deny_n = 0,
	    other_n = 0, skipped = 0;
	int matched_table = 0;

	if (err && errcap)
		err[0] = '\0';
	if (!json || !buf || cap == 0)
		return -1;
	if (!*json) {
		if (err)
			snprintf(err, errcap, "nft -j 输出为空");
		return -1;
	}
	root = jp_root(json, strlen(json), err, errcap);
	if (!root)
		return -1;
	arr = jv_get(root, "nftables");
	if (!arr || arr->t != JV_ARR) {
		if (err)
			snprintf(err, errcap,
				 "nft -j 输出缺少 nftables 数组（不是 nft JSON 输出）");
		jv_free(root);
		return -1;
	}

	db_init(&out);
	db_init(&allow);
	db_init(&deny);
	db_init(&other);
	if (out.oom || allow.oom || deny.oom || other.oom) {
		if (err)
			snprintf(err, errcap, "内存不足");
		jv_free(root);
		db_free(&out);
		db_free(&allow);
		db_free(&deny);
		db_free(&other);
		return -1;
	}

	db_printf(&out, "nft 规则集反向摘要（来源: nft -j list ruleset）\n");
	db_printf(&out, "== 默认策略 ==\n");

	/* 第一遍：表 + 链（默认策略） */
	for (i = 0; i < arr->n; i++) {
		struct jv *e = arr->val[i];
		struct jv *t = jv_get(e, "table");
		struct jv *ch = jv_get(e, "chain");

		if (e->t != JV_OBJ) {
			skipped++;
			continue;
		}
		if (t) {
			const char *name = jv_str(t, "name");
			const char *fam = jv_str(t, "family");

			if (only_table && *only_table && name &&
			    strcmp(only_table, name) != 0)
				continue;
			matched_table = 1;
			table_n++;
			db_printf(&out, "  [%s %s] 表（handle %lld）\n",
				  fam ? fam : "?", name ? name : "?",
				  jv_int(t, "handle", -1));
			continue;
		}
		if (ch) {
			const char *name = jv_str(ch, "name");
			const char *tab = jv_str(ch, "table");
			const char *fam = jv_str(ch, "family");
			const char *hook = jv_str(ch, "hook");
			const char *pol = jv_str(ch, "policy");
			const char *type = jv_str(ch, "type");
			long long prio = jv_int(ch, "prio", 0);

			if (only_table && *only_table && tab &&
			    strcmp(only_table, tab) != 0)
				continue;
			chain_n++;
			if (hook) {
				db_printf(&out,
					  "  [%s %s] 链 %s：hook=%s, type=%s, "
					  "priority=%lld, policy=%s",
					  fam ? fam : "?", tab ? tab : "?",
					  name ? name : "?", hook,
					  type ? type : "?",
					  (int)prio, pol ? pol : "?");
				if (pol && strcmp(pol, "drop") == 0)
					db_printf(&out, " —— 未匹配流量一律丢弃");
				else if (pol && strcmp(pol, "accept") == 0)
					db_printf(&out, " —— 未匹配流量一律放行");
				db_printf(&out, "\n");
			} else {
				db_printf(&out,
					  "  [%s %s] 链 %s：普通链（无 hook，"
					  "只被 jump/goto 调用）\n",
					  fam ? fam : "?", tab ? tab : "?",
					  name ? name : "?");
			}
			continue;
		}
	}
	if (table_n == 0) {
		db_printf(&out, "  （无）\n");
		if (only_table && *only_table && !matched_table)
			db_printf(&out, "  指定表 %s 不存在。\n",
				  only_table);
	}

	/* 第二遍：规则 → 三档 */
	for (i = 0; i < arr->n; i++) {
		struct jv *e = arr->val[i];
		struct jv *r = jv_get(e, "rule");
		const char *fam, *tab, *chn;
		struct jv *exprs;
		char act[256] = "未知";
		char cond[1024];
		struct sbuf cb;
		char counter[96];
		int kind = NI_R_OTHER, j;

		if (!r || r->t != JV_OBJ)
			continue;
		fam = jv_str(r, "family");
		tab = jv_str(r, "table");
		chn = jv_str(r, "chain");
		if (only_table && *only_table && tab &&
		    strcmp(only_table, tab) != 0)
			continue;
		exprs = jv_get(r, "expr");
		if (!exprs || exprs->t != JV_ARR)
			continue;
		rule_n++;
		sb_init(&cb, cond, sizeof(cond));
		counter[0] = '\0';
		for (j = 0; j < exprs->n; j++) {
			struct jv *x = exprs->val[j];
			const char *k = jv_single_key(x);
			char one[768];

			if (!k)
				continue;
			if (strcmp(k, "match") == 0 || strcmp(k, "cmp") == 0) {
				struct jv *m = jv_single_val(x);

				render_match(m, one, sizeof(one));
				sb_printf(&cb, "%s%s",
					  cb.used ? " 且 " : "", one);
				continue;
			}
			if (strcmp(k, "counter") == 0) {
				struct jv *c = jv_single_val(x);

				snprintf(counter, sizeof(counter),
					 "（计数 %lld 包/%lld 字节）",
					 jv_int(c, "packets", 0),
					 jv_int(c, "bytes", 0));
				continue;
			}
			if (strcmp(k, "log") == 0)
				continue;
			if (strcmp(k, "meta") == 0 || strcmp(k, "payload") == 0 ||
			    strcmp(k, "ct") == 0) {
				jv_dump(x, one, sizeof(one), &(size_t){0});
				sb_printf(&cb, "%s%s",
					  cb.used ? " 且 " : "", one);
				continue;
			}
			{
				int kd = render_action(x, act, sizeof(act));

				if (kd != NI_R_OTHER || kind == NI_R_OTHER)
					kind = kd;
			}
		}
		switch (kind) {
		case NI_R_ALLOW:
			allow_n++;
			db_printf(&allow, "  [%s %s] %s #%lld: %s%s → %s\n",
				  fam ? fam : "?", tab ? tab : "?",
				  chn ? chn : "?", jv_int(r, "handle", -1),
				  cb.used ? cond : "（无条件）", counter, act);
			break;
		case NI_R_DENY:
			deny_n++;
			db_printf(&deny, "  [%s %s] %s #%lld: %s%s → %s\n",
				  fam ? fam : "?", tab ? tab : "?",
				  chn ? chn : "?", jv_int(r, "handle", -1),
				  cb.used ? cond : "（无条件）", counter, act);
			break;
		default:
			other_n++;
			db_printf(&other, "  [%s %s] %s #%lld: %s%s → %s\n",
				  fam ? fam : "?", tab ? tab : "?",
				  chn ? chn : "?", jv_int(r, "handle", -1),
				  cb.used ? cond : "（无条件）", counter, act);
			break;
		}
	}

	db_printf(&out, "\n== 允许（accept）==\n");
	db_printf(&out, "%s", allow.used ? allow.p : "  （无）\n");
	db_printf(&out, "\n== 拒绝（drop/reject）==\n");
	db_printf(&out, "%s", deny.used ? deny.p : "  （无）\n");
	db_printf(&out, "\n== 其他动作（跳转/NAT/日志等）==\n");
	db_printf(&out, "%s", other.used ? other.p : "  （无）\n");

	if (table_n == 0) {
		db_printf(&out,
			  "\n小结：规则集为空——没有任何表、链或规则，"
			  "当前内核不做任何 nft 过滤。\n");
	} else {
		db_printf(&out,
			  "\n小结：%d 表 / %d 链 / %d 规则；允许 %d 条，"
			  "拒绝 %d 条，其他 %d 条。\n",
			  table_n, chain_n, rule_n, allow_n, deny_n, other_n);
	}
	if (skipped)
		db_printf(&out, "（跳过 %d 个非对象数组元素）\n", skipped);
	if (out.oom)
		db_printf(&out, "（摘要缓冲不足，输出已截断）\n");

	{
		size_t len = out.p ? strlen(out.p) : 0;

		if (len >= cap) {
			/* 截断时保留尾部提示（不破坏 NUL） */
			snprintf(buf, cap, "%.*s\n（输出超过 %zu 字节被截断）\n",
				 (int)(cap > 64 ? cap - 64 : 0),
				 out.p ? out.p : "", cap);
		} else {
			snprintf(buf, cap, "%s", out.p ? out.p : "");
		}
	}

	jv_free(root);
	db_free(&out);
	db_free(&allow);
	db_free(&deny);
	db_free(&other);
	return 0;
}

/* ======================================================================
 * 4) 正向：意图解析
 * ====================================================================== */

struct kw {
	const char *w;
	int len;
};

static int kw_match(const char *p, const char *kw, int *len)
{
	size_t i, n = strlen(kw);

	for (i = 0; i < n; i++) {
		unsigned char a = (unsigned char)p[i];
		unsigned char b = (unsigned char)kw[i];

		if (!a)
			return 0;
		if (b >= 'A' && b <= 'Z')
			b = (unsigned char)(b - 'A' + 'a');
		if (a >= 'A' && a <= 'Z')
			a = (unsigned char)(a - 'A' + 'a');
		if (a != b)
			return 0;
	}
	*len = (int)n;
	return 1;
}

static int kw_any(const char *p, const char *const *list, int *len)
{
	int i;

	for (i = 0; list[i]; i++)
		if (kw_match(p, list[i], len))
			return 1;
	return 0;
}

static const char *const KW_ALLOW[] = {
	"允许", "放行", "开放", "许可", "准入",
	"allow", "accept", "permit", NULL
};
static const char *const KW_DENY[] = {
	"拒绝", "禁止", "阻断", "拦截", "屏蔽", "丢弃",
	"deny", "drop", "block", "reject", NULL
};
static const char *const KW_DEF_DROP[] = {
	"其他全", "其余全", "其他全部", "其余全部", "全部拒绝",
	"默认拒绝", "默认丢弃", "默认拒", "default deny", "default drop",
	NULL
};
static const char *const KW_DEF_ACCEPT[] = {
	"默认允许", "默认放行", "default accept", "default allow", NULL
};
static const char *const KW_DIR_IN[] = {
	"进来", "入站", "传入", "进站", "inbound", "ingress", NULL
};
static const char *const KW_DIR_OUT[] = {
	"出去", "出站", "外发", "出站口", "outbound", "egress", NULL
};

static int add_rule(struct ni_intent *in, enum ni_action act,
		    enum ni_proto proto, int lo, int hi)
{
	int i;

	if (in->rule_n >= NI_MAX_RULES)
		return -1;
	if (proto == NI_PROTO_ICMP) {
		if (act == NI_ALLOW)
			in->has_icmp = 1;
		lo = 0;
		hi = 0;
	} else if (lo < NI_PORT_MIN || hi > NI_PORT_MAX || lo > hi) {
		return -1;
	}
	for (i = 0; i < in->rule_n; i++) {
		struct ni_rule *r = &in->rule[i];

		if (r->act == act && r->proto == proto &&
		    r->lo == lo && r->hi == hi)
			return 0;	/* 去重 */
	}
	in->rule[in->rule_n].act = act;
	in->rule[in->rule_n].proto = proto;
	in->rule[in->rule_n].lo = lo;
	in->rule[in->rule_n].hi = hi;
	in->rule_n++;
	return 0;
}

/* 读一个端口/区间：返回消耗字节数，0=不是端口 */
static int parse_port_at(const char *p, int *lo, int *hi, int *explicit_proto,
			 int *err)
{
	const char *s = p;
	long a, b;
	int proto = -1;
	int digits = 0;

	*err = 0;
	if (!isdigit((unsigned char)*s))
		return 0;
	while (isdigit((unsigned char)*s)) {
		s++;
		digits++;
		if (digits > 6)
			break;
	}
	a = strtol(p, NULL, 10);
	b = a;
	if (*s == '-' && isdigit((unsigned char)s[1])) {
		const char *q = s + 1;

		b = strtol(q, NULL, 10);
		s = q;
		while (isdigit((unsigned char)*s))
			s++;
	} else if ((*s == '~' && isdigit((unsigned char)s[1]))) {
		const char *q = s + 1;

		b = strtol(q, NULL, 10);
		s = q;
		while (isdigit((unsigned char)*s))
			s++;
	} else if (strncmp(s, "至", 3) == 0 || strncmp(s, "到", 3) == 0) {
		size_t adv = (strncmp(s, "至", 3) == 0) ? 3 : 3;
		const char *q = s + adv;

		while (*q == ' ')
			q++;
		if (!isdigit((unsigned char)*q))
			return (int)(s - p);
		b = strtol(q, NULL, 10);
		s = q;
		while (isdigit((unsigned char)*s))
			s++;
	}
	/* 协议后缀：/tcp /udp /icmp（也接受紧邻的 tcp/udp） */
	if (*s == '/') {
		if (kw_match(s + 1, "tcp", &digits))
			proto = NI_PROTO_TCP;
		else if (kw_match(s + 1, "udp", &digits))
			proto = NI_PROTO_UDP;
		else if (kw_match(s + 1, "icmp", &digits))
			proto = NI_PROTO_ICMP;
		else {
			*err = 1;
			return (int)(s - p) + 1;
		}
		s += 1 + digits;
	}
	if (a < NI_PORT_MIN || a > NI_PORT_MAX ||
	    b < NI_PORT_MIN || b > NI_PORT_MAX || a > b) {
		*err = 1;
		return (int)(s - p);
	}
	*lo = (int)a;
	*hi = (int)b;
	*explicit_proto = proto;
	return (int)(s - p);
}

/* 端口串分隔符：ASCII 空白/逗号/分号 + UTF-8 的 ，、； 返回消耗字节数 */
static int port_sep_len(const char *s)
{
	if (*s == ' ' || *s == '\t' || *s == ',' || *s == ';')
		return 1;
	if ((unsigned char)s[0] == 0xEF && (unsigned char)s[1] == 0xBC &&
	    (unsigned char)s[2] == 0x82)	/* ，U+FF0C */
		return 3;
	if ((unsigned char)s[0] == 0xE3 && (unsigned char)s[1] == 0x80 &&
	    (unsigned char)s[2] == 0x81)	/* 、U+3001 */
		return 3;
	if ((unsigned char)s[0] == 0xEF && (unsigned char)s[1] == 0xBC &&
	    (unsigned char)s[2] == 0x9B)	/* ；U+FF1B */
		return 3;
	return 0;
}

/* 逗号/顿号/空格 分隔的端口串（结构化参数用） */
static int parse_port_list(const char *s, enum ni_action act,
			   enum ni_proto dflt, struct ni_intent *in, char *err,
			   size_t errcap)
{
	while (s && *s) {
		int lo, hi, ep, perr, used, sep;

		while ((sep = port_sep_len(s)) != 0)
			s += sep;
		if (!*s)
			break;
		if (strncmp(s, "和", 3) == 0 || strncmp(s, "与", 3) == 0) {
			s += 3;
			continue;
		}
		used = parse_port_at(s, &lo, &hi, &ep, &perr);
		if (used <= 0 || perr) {
			snprintf(err, errcap, "端口片段非法: %.32s", s);
			return -1;
		}
		if (add_rule(in, act, ep < 0 ? dflt : (enum ni_proto)ep,
			     lo, hi) != 0) {
			snprintf(err, errcap,
				 "规则过多（上限 %d）或端口越界: %d-%d",
				 NI_MAX_RULES, lo, hi);
			return -1;
		}
		s += used;
	}
	return 0;
}

int ni_parse_intent(const char *intent, const char *allow_ports,
		    const char *deny_ports, const char *default_policy,
		    const char *proto, const char *dir, const char *table,
		    struct ni_intent *out, char *err, size_t errcap)
{
	const char *p;
	enum ni_action act = NI_ALLOW;
	int saw_act = 0;
	enum ni_proto cur_proto = NI_PROTO_TCP, dflt_proto = NI_PROTO_TCP;
	int len, lo, hi, ep, perr, used;

	if (!out)
		return -1;
	memset(out, 0, sizeof(*out));
	out->dir = NI_DIR_IN;
	snprintf(out->table, sizeof(out->table), "%s",
		 (table && *table) ? table : "aik_intent");
	if (!ni_valid_table(out->table)) {
		snprintf(err, errcap,
			 "表名非法（只允许 [a-z_][a-z0-9_]{0,14}）: %.32s",
			 out->table);
		return -1;
	}

	/* 默认协议（结构化参数） */
	if (proto && *proto) {
		if (strcasecmp(proto, "tcp") == 0)
			dflt_proto = NI_PROTO_TCP;
		else if (strcasecmp(proto, "udp") == 0)
			dflt_proto = NI_PROTO_UDP;
		else if (strcasecmp(proto, "icmp") == 0)
			dflt_proto = NI_PROTO_ICMP;
		else if (strcasecmp(proto, "both") == 0)
			dflt_proto = NI_PROTO_TCP;	/* both 由逐条后缀表达 */
		else {
			snprintf(err, errcap,
				 "proto 只接受 tcp/udp/icmp/both: %.32s", proto);
			return -1;
		}
		cur_proto = dflt_proto;
	}
	if (dir && *dir) {
		if (strcasecmp(dir, "in") == 0 ||
		    strcasecmp(dir, "input") == 0)
			out->dir = NI_DIR_IN;
		else if (strcasecmp(dir, "out") == 0 ||
			 strcasecmp(dir, "output") == 0)
			out->dir = NI_DIR_OUT;
		else {
			snprintf(err, errcap,
				 "dir 只接受 in/input/out/output: %.32s", dir);
			return -1;
		}
	}

	/* 自然语言意图 */
	p = intent ? intent : "";
	while (*p) {
		if (kw_any(p, KW_DEF_DROP, &len)) {
			out->policy = NI_POLICY_DROP;
			out->has_policy = 1;
			p += len;
			continue;
		}
		if (kw_any(p, KW_DEF_ACCEPT, &len)) {
			out->policy = NI_POLICY_ACCEPT;
			out->has_policy = 1;
			p += len;
			continue;
		}
		if (kw_any(p, KW_ALLOW, &len)) {
			act = NI_ALLOW;
			saw_act = 1;
			p += len;
			continue;
		}
		if (kw_any(p, KW_DENY, &len)) {
			act = NI_DENY;
			saw_act = 1;
			p += len;
			continue;
		}
		if (kw_any(p, KW_DIR_IN, &len)) {
			out->dir = NI_DIR_IN;
			p += len;
			continue;
		}
		if (kw_any(p, KW_DIR_OUT, &len)) {
			out->dir = NI_DIR_OUT;
			p += len;
			continue;
		}
		if (kw_match(p, "icmp", &len)) {
			cur_proto = NI_PROTO_ICMP;
			p += len;
			if (add_rule(out, act, NI_PROTO_ICMP, 0, 0) != 0) {
				snprintf(err, errcap, "规则过多（上限 %d）",
					 NI_MAX_RULES);
				return -1;
			}
			continue;
		}
		if (kw_match(p, "tcp", &len)) {
			cur_proto = NI_PROTO_TCP;
			p += len;
			continue;
		}
		if (kw_match(p, "udp", &len)) {
			cur_proto = NI_PROTO_UDP;
			p += len;
			continue;
		}
		if (isdigit((unsigned char)*p)) {
			used = parse_port_at(p, &lo, &hi, &ep, &perr);
			if (perr) {
				snprintf(err, errcap,
					 "端口片段非法（越界或区间倒置）: %.32s",
					 p);
				return -1;
			}
			if (used > 0) {
				if (!saw_act) {
					out->implicit_allow = 1;
					act = NI_ALLOW;
				}
				if (add_rule(out, act,
					     ep < 0 ? cur_proto :
					     (enum ni_proto)ep, lo, hi) != 0) {
					snprintf(err, errcap,
						 "规则过多（上限 %d）或端口越界",
						 NI_MAX_RULES);
					return -1;
				}
				p += used;
				continue;
			}
		}
		/* UTF-8 安全跳过：续字节 >=0x80 不会命中任何 ASCII 关键字 */
		p++;
	}

	/* 结构化覆盖（意图没给时补位；给了就叠加） */
	if (allow_ports && *allow_ports &&
	    parse_port_list(allow_ports, NI_ALLOW, dflt_proto, out, err,
			    errcap) != 0)
		return -1;
	if (deny_ports && *deny_ports &&
	    parse_port_list(deny_ports, NI_DENY, dflt_proto, out, err,
			    errcap) != 0)
		return -1;
	if (default_policy && *default_policy) {
		if (strcasecmp(default_policy, "drop") == 0 ||
		    strcasecmp(default_policy, "deny") == 0 ||
		    strcasecmp(default_policy, "reject") == 0) {
			out->policy = NI_POLICY_DROP;
			out->has_policy = 1;
		} else if (strcasecmp(default_policy, "accept") == 0 ||
			   strcasecmp(default_policy, "allow") == 0) {
			out->policy = NI_POLICY_ACCEPT;
			out->has_policy = 1;
		} else {
			snprintf(err, errcap,
				 "default_policy 只接受 drop/accept: %.32s",
				 default_policy);
			return -1;
		}
	}

	if (out->rule_n == 0 &&
	    (!intent || !*intent) && (!allow_ports || !*allow_ports) &&
	    (!deny_ports || !*deny_ports)) {
		snprintf(err, errcap,
			 "意图为空：需要 intent 文本或 allow_ports/deny_ports。"
			 "支持示例「只允许 22 端口进来，其他全拒」"
			 "「放行 80,443 拒绝 8080」「allow 53/udp default deny」");
		return -1;
	}
	if (out->rule_n == 0) {
		snprintf(err, errcap,
			 "意图里没有解析出任何端口/协议规则"
			 "（支持：允许/放行/拒绝 + 端口或端口区间 + tcp/udp/icmp）");
		return -1;
	}

	/* 未显式给默认策略时按语义推导：
	 *   只有放行 → 白名单语义 → drop
	 *   只有拒绝 → 黑名单语义 → accept
	 *   两者都有 → 显式黑名单 → accept（拒绝规则才有意义）
	 */
	if (!out->has_policy) {
		int has_allow = 0, has_deny = 0, i;

		for (i = 0; i < out->rule_n; i++) {
			if (out->rule[i].act == NI_ALLOW)
				has_allow = 1;
			else
				has_deny = 1;
		}
		if (has_allow && !has_deny)
			out->policy = NI_POLICY_DROP;
		else
			out->policy = NI_POLICY_ACCEPT;
	}
	return 0;
}

int ni_compile(const struct ni_intent *in, char *buf, size_t cap)
{
	struct sbuf b;
	const char *chain = in->dir == NI_DIR_IN ? "input" : "output";
	const char *hook = in->dir == NI_DIR_IN ? "input" : "output";
	const char *iface = in->dir == NI_DIR_IN ? "iif" : "oif";
	int i;

	sb_init(&b, buf, cap);
	sb_printf(&b, "table inet %s {\n", in->table);
	sb_printf(&b, "\tchain %s {\n", chain);
	sb_printf(&b, "\t\ttype filter hook %s priority filter; policy %s;\n",
		  hook, in->policy == NI_POLICY_DROP ? "drop" : "accept");
	sb_printf(&b, "\t\tct state established,related accept\n");
	sb_printf(&b, "\t\t%s \"lo\" accept\n", iface);
	for (i = 0; i < in->rule_n; i++) {
		const struct ni_rule *r = &in->rule[i];
		const char *verdict = r->act == NI_ALLOW ? "accept" : "drop";

		if (r->proto == NI_PROTO_ICMP) {
			sb_printf(&b, "\t\ticmp type echo-request %s\n",
				  verdict);
			continue;
		}
		if (r->lo == r->hi)
			sb_printf(&b, "\t\t%s dport %d %s\n",
				  r->proto == NI_PROTO_TCP ? "tcp" : "udp",
				  r->lo, verdict);
		else
			sb_printf(&b, "\t\t%s dport %d-%d %s\n",
				  r->proto == NI_PROTO_TCP ? "tcp" : "udp",
				  r->lo, r->hi, verdict);
	}
	if (in->policy == NI_POLICY_DROP)
		sb_printf(&b, "\t\tcounter drop\n");
	sb_printf(&b, "\t}\n}\n");
	return b.trunc ? -1 : 0;
}

/* ======================================================================
 * 5) 行级 LCS 差异
 * ====================================================================== */

static char *trim_dup(const char *s, size_t n)
{
	char *o = malloc(n + 1);

	if (!o)
		return NULL;
	memcpy(o, s, n);
	o[n] = '\0';
	return o;
}

/* 对比用的规范化：压缩空白 + 去掉 counter 的 packets/bytes 计数 */
static void norm_line(const char *in, char *out, size_t cap)
{
	struct sbuf b;
	const char *p = in;

	sb_init(&b, out, cap);
	while (*p) {
		/* nft list 会把 counter 规范化成 "packets N bytes M"；
		 * 差异对比要忽略实时计数，否则每次 diff 都多一行噪声。 */
		if (strncmp(p, "packets ", 8) == 0) {
			const char *q = p + 8;
			const char *num = q;
			const char *r, *num2;

			while (*q >= '0' && *q <= '9')
				q++;
			if (q > num && *q == ' ' &&
			    strncmp(q + 1, "bytes ", 6) == 0) {
				r = q + 1 + 6;
				num2 = r;
				while (*r >= '0' && *r <= '9')
					r++;
				if (r > num2 && (*r == ' ' || *r == '\0')) {
					p = (*r == ' ') ? r + 1 : r;
					continue;
				}
			}
		}
		sb_printf(&b, "%c", *p);
		p++;
	}
	/* 收敛连续空白 + 首尾空白 */
	{
		size_t i, j = 0;
		int prev_sp = 0;

		for (i = 0; out[i]; i++) {
			int sp = (out[i] == ' ' || out[i] == '\t' ||
				  out[i] == '\n');

			if (sp) {
				if (!prev_sp && j)
					out[j++] = ' ';
			} else {
				out[j++] = out[i];
			}
			prev_sp = sp;
		}
		while (j && out[j - 1] == ' ')
			j--;
		out[j] = '\0';
	}
}

struct line_set {
	char **line;
	char **norm;
	int n;
	char *blob;
};

static void lines_free(struct line_set *ls)
{
	int i;

	for (i = 0; i < ls->n; i++) {
		free(ls->line[i]);
		free(ls->norm[i]);
	}
	free(ls->line);
	free(ls->norm);
	free(ls->blob);
	memset(ls, 0, sizeof(*ls));
}

static int lines_split(const char *text, struct line_set *ls)
{
	size_t n = strlen(text);
	const char *p = text;
	int cap = 32;

	memset(ls, 0, sizeof(*ls));
	ls->blob = trim_dup(text, n);
	if (!ls->blob)
		return -1;
	ls->line = calloc((size_t)cap, sizeof(char *));
	ls->norm = calloc((size_t)cap, sizeof(char *));
	if (!ls->line || !ls->norm) {
		lines_free(ls);
		return -1;
	}
	while (p && *p) {
		const char *e = strchr(p, '\n');
		size_t len = e ? (size_t)(e - p) : strlen(p);

		if (len && p[len - 1] == '\r')
			len--;
		if (ls->n >= cap) {
			char **a, **b;

			cap *= 2;
			a = realloc(ls->line, sizeof(char *) * (size_t)cap);
			b = realloc(ls->norm, sizeof(char *) * (size_t)cap);
			if (!a || !b) {
				if (a)
					ls->line = a;
				if (b)
					ls->norm = b;
				lines_free(ls);
				return -1;
			}
			ls->line = a;
			ls->norm = b;
		}
		ls->line[ls->n] = trim_dup(p, len);
		if (!ls->line[ls->n]) {
			lines_free(ls);
			return -1;
		}
		ls->norm[ls->n] = malloc(len * 2 + 8);
		if (!ls->norm[ls->n]) {
			lines_free(ls);
			return -1;
		}
		norm_line(ls->line[ls->n], ls->norm[ls->n], len * 2 + 8);
		ls->n++;
		p = e ? e + 1 : NULL;
		if (e && !*p)
			break;
	}
	return 0;
}

#define NI_DIFF_MAX_LINES 240

int ni_diff(const char *old_text, const char *new_text, char *buf, size_t cap)
{
	struct line_set a, b;
	struct sbuf o;
	unsigned short *dp;
	int i, j, n, m, big = 0;

	sb_init(&o, buf, cap);
	if (lines_split(old_text ? old_text : "", &a) != 0) {
		snprintf(buf, cap, "（差异计算失败：内存不足）\n");
		return -1;
	}
	if (lines_split(new_text ? new_text : "", &b) != 0) {
		lines_free(&a);
		snprintf(buf, cap, "（差异计算失败：内存不足）\n");
		return -1;
	}
	n = a.n;
	m = b.n;
	if (n > NI_DIFF_MAX_LINES || m > NI_DIFF_MAX_LINES)
		big = 1;

	sb_printf(&o, "--- 现网表（%d 行）\n+++ 目标规则集（%d 行）\n", n, m);
	if (big) {
		for (i = 0; i < n; i++)
			sb_printf(&o, "- %s\n", a.line[i]);
		for (i = 0; i < m; i++)
			sb_printf(&o, "+ %s\n", b.line[i]);
		sb_printf(&o, "（行数超 %d，退化为全量对照）\n",
			  NI_DIFF_MAX_LINES);
		lines_free(&a);
		lines_free(&b);
		return 0;
	}

	dp = calloc((size_t)(n + 1) * (size_t)(m + 1), sizeof(*dp));
	if (!dp) {
		snprintf(buf, cap, "（差异计算失败：内存不足）\n");
		lines_free(&a);
		lines_free(&b);
		return -1;
	}
	for (i = n - 1; i >= 0; i--) {
		for (j = m - 1; j >= 0; j--) {
			if (strcmp(a.norm[i], b.norm[j]) == 0)
				dp[(size_t)i * (m + 1) + j] =
					(unsigned short)(dp[(size_t)(i + 1) * (m + 1) + j + 1] + 1);
			else {
				unsigned short x = dp[(size_t)(i + 1) * (m + 1) + j];
				unsigned short y = dp[(size_t)i * (m + 1) + j + 1];

				dp[(size_t)i * (m + 1) + j] = x > y ? x : y;
			}
		}
	}
	i = 0;
	j = 0;
	while (i < n && j < m) {
		if (strcmp(a.norm[i], b.norm[j]) == 0) {
			sb_printf(&o, "  %s\n", a.line[i]);
			i++;
			j++;
		} else if (dp[(size_t)(i + 1) * (m + 1) + j] >=
			   dp[(size_t)i * (m + 1) + j + 1]) {
			sb_printf(&o, "- %s\n", a.line[i]);
			i++;
		} else {
			sb_printf(&o, "+ %s\n", b.line[j]);
			j++;
		}
	}
	while (i < n)
		sb_printf(&o, "- %s\n", a.line[i++]);
	while (j < m)
		sb_printf(&o, "+ %s\n", b.line[j++]);
	if (n == m && n == 0)
		sb_printf(&o, "（两侧都为空）\n");

	free(dp);
	lines_free(&a);
	lines_free(&b);
	return 0;
}

/* ======================================================================
 * 6) 会话状态 + 回滚
 * ====================================================================== */

struct ni_session {
	char table[NI_TABLE_LEN];
	char dir[512];
	char def[600];
	char applyf[600];
	char snap[600];
	char rollback_del[600];
	char rollback_add[600];
	char decision[600];
	char state[600];
	char lock[600];
	char log[600];
	char meta[600];
	int snapshot_existed;
};

static int mkdir_p0700(const char *path)
{
	struct stat st;

	if (mkdir(path, 0700) == 0)
		return 0;
	if (errno != EEXIST)
		return -1;
	if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
		return -1;
	return 0;
}

static int ni_state_dir(char *out, size_t cap)
{
	const char *env = getenv("AIKERNEL_NFT_INTENT_DIR");

	if (env && *env)
		snprintf(out, cap, "%s", env);
	else if (geteuid() == 0)
		snprintf(out, cap, "/run/aik-nft-intent");
	else
		snprintf(out, cap, "/tmp/aik-nft-intent-%u",
			 (unsigned)geteuid());
	return mkdir_p0700(out);
}

static void ni_session_init(struct ni_session *s, const char *table)
{
	char root[512];

	memset(s, 0, sizeof(*s));
	snprintf(s->table, sizeof(s->table), "%s", table);
	if (ni_state_dir(root, sizeof(root)) != 0)
		root[0] = '\0';
	snprintf(s->dir, sizeof(s->dir), "%s/t-%s", root, table);
	snprintf(s->def, sizeof(s->def), "%s/desired.nft", s->dir);
	snprintf(s->applyf, sizeof(s->applyf), "%s/apply.nft", s->dir);
	snprintf(s->snap, sizeof(s->snap), "%s/snapshot.nft", s->dir);
	snprintf(s->rollback_del, sizeof(s->rollback_del), "%s/rb-del.nft",
		 s->dir);
	snprintf(s->rollback_add, sizeof(s->rollback_add), "%s/rb-add.nft",
		 s->dir);
	snprintf(s->decision, sizeof(s->decision), "%s/decision", s->dir);
	snprintf(s->state, sizeof(s->state), "%s/state", s->dir);
	snprintf(s->lock, sizeof(s->lock), "%s/lock", s->dir);
	snprintf(s->log, sizeof(s->log), "%s/rollback.log", s->dir);
	snprintf(s->meta, sizeof(s->meta), "%s/meta", s->dir);
}

static void ni_slog(const char *logpath, const char *fmt, ...)
{
	char line[1024];
	char ts[64];
	time_t now = time(NULL);
	struct tm tmv;
	va_list ap;
	int n, fd;

	localtime_r(&now, &tmv);
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);
	n = snprintf(line, sizeof(line), "[%s] ", ts);
	va_start(ap, fmt);
	vsnprintf(line + n, sizeof(line) - (size_t)n, fmt, ap);
	va_end(ap);
	n = (int)strlen(line);
	if (n < (int)sizeof(line) - 1) {
		line[n++] = '\n';
		line[n] = '\0';
	}
	fd = open(logpath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	if (write(fd, line, (size_t)n) < 0) {
		/* 日志写失败不掩盖主流程结果 */
	}
	close(fd);
}

static int write_file0600(const char *path, const char *data)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	size_t len = strlen(data);
	size_t off = 0;

	if (fd < 0)
		return -1;
	while (off < len) {
		ssize_t w = write(fd, data + off, len - off);

		if (w <= 0) {
			close(fd);
			return -1;
		}
		off += (size_t)w;
	}
	close(fd);
	return 0;
}

static int read_file_text(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	size_t used = 0;

	if (fd < 0)
		return -1;
	while (used + 1 < cap) {
		ssize_t r = read(fd, buf + used, cap - used - 1);

		if (r <= 0)
			break;
		used += (size_t)r;
	}
	close(fd);
	buf[used] = '\0';
	return 0;
}

static void ni_state_write(const struct ni_session *s, const char *state)
{
	write_file0600(s->state, state);
}

static void ni_state_read(const struct ni_session *s, char *out, size_t cap)
{
	if (read_file_text(s->state, out, cap) != 0)
		snprintf(out, cap, "unknown");
}

/* 日志尾部（最多 1500 字节，按行边界对齐） */
static void ni_session_log_tail(const struct ni_session *s, char *out,
				size_t cap)
{
	char *buf;
	size_t n = 0;
	int fd;

	if (!out || cap == 0)
		return;
	out[0] = '\0';
	buf = malloc(16384);
	if (!buf)
		return;
	fd = open(s->log, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		ssize_t r = read(fd, buf, 16383);

		close(fd);
		if (r > 0)
			n = (size_t)r;
	}
	buf[n] = '\0';
	if (n == 0) {
		snprintf(out, cap, "（日志为空）\n");
		free(buf);
		return;
	}
	{
		size_t keep = 1400;
		char *start = buf;

		if (n > keep) {
			start = buf + (n - keep);
			while (*start && *start != '\n')
				start++;
			if (*start == '\n')
				start++;
		}
		snprintf(out, cap, "%s", start);
	}
	free(buf);
}

/* 删表 + 恢复快照（幂等；flock 串行化并发回滚） */
static int ni_do_rollback(const struct ni_session *s, char *msg, size_t cap)
{
	char buf[2048];
	char state[64];
	int rc, lfd;

	lfd = open(s->lock, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
	if (lfd >= 0)
		flock(lfd, LOCK_EX);

	ni_state_read(s, state, sizeof(state));
	if (strncmp(state, "rolled_back", 11) == 0) {
		snprintf(msg, cap, "已是 rolled_back 状态（重复回滚无副作用）");
		if (lfd >= 0)
			close(lfd);
		return 0;
	}

	memset(buf, 0, sizeof(buf));
	rc = ai_nft_run_file(s->rollback_del, 0, 10, buf, sizeof(buf));
	if (rc == 0) {
		ni_slog(s->log, "回滚: delete table inet %s 成功", s->table);
	} else {
		ni_slog(s->log,
			"回滚: delete table inet %s 失败/已不存在（rc=%d）: %.200s",
			s->table, rc, buf);
	}
	snprintf(msg, cap, "delete table rc=%d（表已删或本就不存在）", rc);

	if (s->snapshot_existed) {
		memset(buf, 0, sizeof(buf));
		rc = ai_nft_run_file(s->rollback_add, 0, 10, buf, sizeof(buf));
		if (rc == 0) {
			ni_slog(s->log, "回滚: 快照表 inet %s 已恢复",
				s->table);
			snprintf(msg, cap,
				 "delete table rc=%d，快照恢复成功", 0);
		} else {
			ni_slog(s->log,
				"回滚: 快照恢复失败（rc=%d）: %.200s", rc, buf);
			snprintf(msg, cap,
				 "delete 已尝试，但快照恢复失败（rc=%d）: %.120s",
				 rc, buf);
			ni_state_write(s, "rollback_failed");
			if (lfd >= 0)
				close(lfd);
			return -1;
		}
	}
	ni_state_write(s, "rolled_back");
	if (lfd >= 0)
		close(lfd);
	return 0;
}

/* 看门狗子进程：只做 sleep/poll/exec，不依赖父进程任何运行期状态 */
static void ni_watchdog_child(const struct ni_session *s, int arm)
{
	int i, dn, dfd;
	char line[512];
	char msg[512];

	dn = open("/dev/null", O_RDWR);
	if (dn >= 0) {
		dup2(dn, 0);
		dup2(dn, 1);
		dup2(dn, 2);
		if (dn > 2)
			close(dn);
	}
	setsid();
	for (i = 0; i < arm; i++) {
		if (access(s->decision, F_OK) == 0) {
			ni_slog(s->log, "看门狗: 已看到操作者决定，退出（不回滚）");
			_exit(0);
		}
		sleep(1);
	}
	dfd = open(s->decision, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
		   0600);
	if (dfd < 0) {
		ni_slog(s->log, "看门狗: 决定文件已被抢占，退出（不回滚）");
		_exit(0);
	}
	(void)!write(dfd, "auto-rollback\n", 14);
	close(dfd);
	snprintf(line, sizeof(line),
		 "看门狗: 窗口 %d 秒内无确认，执行自动回滚（防止把自己关在门外）",
		 arm);
	ni_slog(s->log, "%s", line);
	if (ni_do_rollback(s, msg, sizeof(msg)) == 0)
		ni_slog(s->log, "看门狗: 自动回滚完成（%s）", msg);
	else
		ni_slog(s->log, "看门狗: 自动回滚失败（%s）", msg);
	_exit(0);
}

/* ======================================================================
 * 7) 工具实现
 * ====================================================================== */

enum { NI_TBL_ABSENT = 0, NI_TBL_PRESENT = 1, NI_TBL_DENIED = 2,
       NI_TBL_ERR = 3 };

static int ni_read_table(const char *table, char *buf, size_t cap)
{
	const char *const argv[] = { "list", "table", "inet", table, NULL };
	int rc;

	if (buf && cap)
		buf[0] = '\0';
	rc = ai_nft_list_args(argv, buf, cap);
	if (rc == 0)
		return NI_TBL_PRESENT;
	if (strstr(buf, "No such file or directory") ||
	    strstr(buf, "No such file") || strstr(buf, "does not exist"))
		return NI_TBL_ABSENT;
	if (strstr(buf, "Operation not permitted") ||
	    strstr(buf, "Permission denied") || strstr(buf, "EPERM"))
		return NI_TBL_DENIED;
	return NI_TBL_ERR;
}

static const char *proto_name(enum ni_proto p)
{
	return p == NI_PROTO_TCP ? "tcp" : p == NI_PROTO_UDP ? "udp" : "icmp";
}

/* 解析 + 编译的公共前半段；成功返回 0 */
static int ni_prepare(const char *args, struct ni_intent *in, char *def,
		      size_t defcap, char *dg, char *err, size_t errcap)
{
	char intent[2048], ap[512], dp[512], pol[32], proto[16], dir[16];
	char table[NI_TABLE_LEN * 2];

	if (ni_arg_str(args, "intent", intent, sizeof(intent)) != 0)
		intent[0] = '\0';
	if (ni_arg_str(args, "allow_ports", ap, sizeof(ap)) != 0)
		ap[0] = '\0';
	if (ni_arg_str(args, "deny_ports", dp, sizeof(dp)) != 0)
		dp[0] = '\0';
	if (ni_arg_str(args, "default_policy", pol, sizeof(pol)) != 0)
		pol[0] = '\0';
	if (ni_arg_str(args, "proto", proto, sizeof(proto)) != 0)
		proto[0] = '\0';
	if (ni_arg_str(args, "dir", dir, sizeof(dir)) != 0)
		dir[0] = '\0';
	if (ni_arg_str(args, "table", table, sizeof(table)) != 0)
		table[0] = '\0';
	if (ni_parse_intent(intent, ap, dp, pol, proto, dir, table, in,
			    err, errcap) != 0)
		return -1;
	if (ni_compile(in, def, defcap) != 0) {
		snprintf(err, errcap, "规则集生成失败（缓冲不足）");
		return -1;
	}
	ni_digest(def, dg);
	return 0;
}

/* 意图的人类可读预览（放行/拒绝/默认策略/作用域/风险） */
static void ni_preview(const struct ni_intent *in, char *buf, size_t cap)
{
	struct sbuf b;
	int i, allow_n = 0, deny_n = 0;
	int ssh_ok = 0;

	sb_init(&b, buf, cap);
	sb_printf(&b, "解析结果（意图 → 规则）：\n");	for (i = 0; i < in->rule_n; i++) {
		const struct ni_rule *r = &in->rule[i];

		if (r->act == NI_ALLOW)
			allow_n++;
		else
			deny_n++;
		if (r->proto == NI_PROTO_ICMP)
			sb_printf(&b, "  [%s] icmp echo-request\n",
				  r->act == NI_ALLOW ? "允许" : "拒绝");
		else if (r->lo == r->hi)
			sb_printf(&b, "  [%s] %s 端口 %d\n",
				  r->act == NI_ALLOW ? "允许" : "拒绝",
				  proto_name(r->proto), r->lo);
		else
			sb_printf(&b, "  [%s] %s 端口 %d-%d\n",
				  r->act == NI_ALLOW ? "允许" : "拒绝",
				  proto_name(r->proto), r->lo, r->hi);
		if (r->act == NI_ALLOW && r->proto == NI_PROTO_TCP &&
		    r->lo <= 22 && r->hi >= 22)
			ssh_ok = 1;
	}
	if (in->implicit_allow)
		sb_printf(&b,
			  "  （意图未显式给出动作的端口按「允许」处理，"
			  "建议在 intent 里写清允许/拒绝）\n");
	sb_printf(&b, "默认策略：%s%s\n",
		  in->policy == NI_POLICY_DROP ? "drop（未匹配一律丢弃）" :
		  "accept（未匹配一律放行）",
		  in->has_policy ? "" : "（由意图语义推导，未显式给出）");
	sb_printf(&b, "影响预览：\n");
	sb_printf(&b, "  - 作用域：仅 inet %s 的 %s 链（hook %s）；"
		  "不 flush ruleset、不动其他表/其他 hook\n",
		  in->table, in->dir == NI_DIR_IN ? "input" : "output",
		  in->dir == NI_DIR_IN ? "input" : "output");
	sb_printf(&b, "  - 固定放行：已建立/相关连接（ct state "
		  "established,related）与回环接口 %s \"lo\"\n",
		  in->dir == NI_DIR_IN ? "iif" : "oif");
	sb_printf(&b, "  - 放行 %d 条，拒绝 %d 条，默认策略兜底其余流量\n",
		  allow_n, deny_n);
	if (in->dir == NI_DIR_IN && in->policy == NI_POLICY_DROP && !ssh_ok)
		sb_printf(&b,
			  "  - ⚠ 危险：默认拒绝且未放行 22/tcp —— 若本机 SSH "
			  "监听 22，apply 后立即失联（apply 需 allow_lockout=true "
			  "显式认账才放行）\n");
	else if (in->dir == NI_DIR_IN && ssh_ok)
		sb_printf(&b, "  - SSH 22/tcp 已放行（不会把自己关在门外）\n");
	if (in->dir == NI_DIR_OUT)
		sb_printf(&b, "  - 注意：out 链影响本机主动出站流量\n");
}

static int ni_tool_compile(const char *args, char **out)
{
	struct ni_intent in;
	char err[512] = "";
	char def[NI_TEXT_MAX], dg[17], preview[4096], diff[NI_TEXT_MAX];
	char old[NI_TEXT_MAX], pre[4096];
	char applyf[NI_TEXT_MAX + 256];
	char tmpl[] = "/tmp/aik-nft-intent-XXXXXX";
	char table_state[64];
	int tstate, rc, fd;
	struct sbuf b;
	char *buf;

	if (ni_prepare(args, &in, def, sizeof(def), dg, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 意图解析失败：%s", err) < 0)
			*out = NULL;
		return -1;
	}
	ni_preview(&in, preview, sizeof(preview));

	/* 现网表（只读；非 root 只报不可读） */
	old[0] = '\0';
	tstate = ni_read_table(in.table, old, sizeof(old));
	if (tstate == NI_TBL_PRESENT)
		snprintf(table_state, sizeof(table_state), "存在");
	else if (tstate == NI_TBL_ABSENT)
		snprintf(table_state, sizeof(table_state), "不存在（将新建）");
	else if (tstate == NI_TBL_DENIED)
		snprintf(table_state, sizeof(table_state),
			 "不可读（无 root/CAP_NET_ADMIN）");
	else
		snprintf(table_state, sizeof(table_state), "读取失败");

	if (tstate == NI_TBL_PRESENT)
		ni_diff(old, def, diff, sizeof(diff));
	else
		ni_diff("", def, diff, sizeof(diff));

	/* 语法预检：把 apply 文件（含条件 delete）落临时文件后 nft -c -f */
	if (tstate == NI_TBL_PRESENT)
		snprintf(applyf, sizeof(applyf),
			 "delete table inet %s\n%s", in.table, def);
	else
		snprintf(applyf, sizeof(applyf), "%s", def);
	fd = mkstemp(tmpl);
	if (fd >= 0) {
		size_t len = strlen(applyf), off = 0;

		while (off < len) {
			ssize_t w = write(fd, applyf + off, len - off);

			if (w <= 0)
				break;
			off += (size_t)w;
		}
		close(fd);
		chmod(tmpl, 0600);
		pre[0] = '\0';
		rc = ai_nft_run_file(tmpl, 1, 15, pre, sizeof(pre));
		unlink(tmpl);
	} else {
		pre[0] = '\0';
		rc = -1;
	}

	buf = malloc(32768);
	if (!buf) {
		*out = strdup("ERROR: 内存不足");
		return -1;
	}
	sb_init(&b, buf, 32768);
	sb_printf(&b,
		  "nft 意图编译（V3.1 只读：未下发任何规则）\n"
		  "表 inet %s / 链 %s / digest=%s\n\n",
		  in.table, in.dir == NI_DIR_IN ? "input" : "output",
		  dg);
	sb_printf(&b, "%s\n", preview);
	sb_printf(&b, "现网表状态：%s\n", table_state);
	if (rc == 0)
		sb_printf(&b, "语法预检：通过（nft -c -f，未生效）\n");
	else if (rc == -99)
		sb_printf(&b, "语法预检：超时（15s）——未生效\n");
	else if (tstate == NI_TBL_DENIED)
		sb_printf(&b,
			  "语法预检：不可用（无 root/CAP_NET_ADMIN，"
			  "%.200s）\n", pre);
	else
		sb_printf(&b, "语法预检：失败（rc=%d）：%.500s\n",
			  rc, pre);
	sb_printf(&b, "\n目标规则集：\n%s\n", def);
	sb_printf(&b, "与现网的差异（- 现网 / + 目标 / 空格 相同）：\n%s",
		  diff);
	sb_printf(&b,
		  "\n下一步：确认无误后调用 nft_intent_apply"
		  "（W2/D3，需显式授权；apply 会再跑一次语法校验并"
		  "在 %d 秒内未确认时自动回滚）。"
		  "如需防止预览被掉包，可把 digest=%s 传给 apply 的 "
		  "expect_digest。\n",
		  NI_ARM_DEFAULT, dg);
	*out = buf;
	return 0;
}

static int ni_tool_apply(const char *args, char **out)
{
	struct ni_intent in;
	char err[512] = "";
	char def[NI_TEXT_MAX], dg[17], preview[4096], diff[NI_TEXT_MAX];
	char old[NI_TEXT_MAX], pre[4096], applyf[NI_TEXT_MAX + 256];
	char expect[64], state[64], tline[64];
	char buf[2048];
	int tstate, rc, arm, allow_lockout, pid;
	long deadline;
	struct ni_session s;
	struct sbuf b;
	char *obuf;

	if (ni_prepare(args, &in, def, sizeof(def), dg, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 意图解析失败：%s", err) < 0)
			*out = NULL;
		return -1;
	}
	expect[0] = '\0';
	(void)ni_arg_str(args, "expect_digest", expect, sizeof(expect));
	if (expect[0] && strcmp(expect, dg) != 0) {
		if (asprintf(out,
			     "ERROR: expect_digest 不匹配（预览 digest=%s，"
			     "本次编译 digest=%s）——参数变了或预览被掉包，"
			     "拒绝下发；请重新 nft_intent_compile",
			     expect, dg) < 0)
			*out = NULL;
		return -1;
	}
	if (geteuid() != 0) {
		*out = strdup("ERROR: nft 下发需要 root/CAP_NET_ADMIN"
			      "（当前非 root）——零副作用退出");
		return -1;
	}
	arm = (int)ni_arg_int(args, "arm_seconds", NI_ARM_DEFAULT);
	if (arm < NI_ARM_MIN) {
		if (asprintf(out,
			     "ERROR: arm_seconds=%d 低于下限 %d（不允许关闭"
			     "自动回滚保护窗）", arm, NI_ARM_MIN) < 0)
			*out = NULL;
		return -1;
	}
	if (arm > NI_ARM_MAX)
		arm = NI_ARM_MAX;
	allow_lockout = ni_arg_bool(args, "allow_lockout", 0);

	/* 安全闸 1：SSH 锁死 */
	{
		int ssh_ok = 0, i;

		for (i = 0; i < in.rule_n; i++)
			if (in.rule[i].act == NI_ALLOW &&
			    in.rule[i].proto == NI_PROTO_TCP &&
			    in.rule[i].lo <= 22 && in.rule[i].hi >= 22)
				ssh_ok = 1;
		if (in.dir == NI_DIR_IN && in.policy == NI_POLICY_DROP &&
		    !ssh_ok && !allow_lockout) {
			*out = strdup(
				"ERROR: 拒绝下发——默认拒绝且未放行 22/tcp，"
				"可能把操作者关在门外。确需如此请显式传 "
				"allow_lockout=true（并确认有带外通道），"
				"否则把 22 加进 allow_ports。零副作用退出");
			return -1;
		}
	}

	/* 会话目录 + 未决会话检查 */
	ni_session_init(&s, in.table);
	if (mkdir_p0700(s.dir) != 0) {
		if (asprintf(out, "ERROR: 状态目录不可写 %s: %s",
			     s.dir, strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	ni_state_read(&s, state, sizeof(state));
	if (strncmp(state, "armed", 5) == 0) {
		if (asprintf(out,
			     "ERROR: 表 inet %s 已有未决下发会话（状态 armed）。"
			     "先用 nft_intent_confirm 决定 confirm 或 rollback，"
			     "再重新 apply（避免两次下发互相覆盖回滚凭据）",
			     in.table) < 0)
			*out = NULL;
		return -1;
	}

	/* 快照 + 生成 apply/rollback 文件 */
	old[0] = '\0';
	tstate = ni_read_table(in.table, old, sizeof(old));
	s.snapshot_existed = 0;
	if (tstate == NI_TBL_PRESENT) {
		if (write_file0600(s.snap, old) != 0 ||
		    write_file0600(s.rollback_add, old) != 0) {
			if (asprintf(out, "ERROR: 快照写入失败 %s: %s",
				     s.snap, strerror(errno)) < 0)
				*out = NULL;
			return -1;
		}
		s.snapshot_existed = 1;
	} else if (tstate == NI_TBL_ABSENT) {
		unlink(s.snap);
		unlink(s.rollback_add);
	} else {
		if (asprintf(out,
			     "ERROR: 现网表 inet %s 状态无法确定（%s），"
			     "拒绝下发（无法留可靠回滚凭据）：%.300s",
			     in.table,
			     tstate == NI_TBL_DENIED ? "权限不足" : "读取失败",
			     old) < 0)
			*out = NULL;
		return -1;
	}
	if (tstate == NI_TBL_PRESENT)
		snprintf(applyf, sizeof(applyf),
			 "delete table inet %s\n%s", in.table, def);
	else
		snprintf(applyf, sizeof(applyf), "%s", def);

	snprintf(tline, sizeof(tline), "delete table inet %s\n", in.table);
	if (write_file0600(s.rollback_del, tline) != 0 ||
	    write_file0600(s.def, def) != 0 ||
	    write_file0600(s.applyf, applyf) != 0) {
		if (asprintf(out, "ERROR: 规则文件写入失败 %s: %s", s.dir,
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}

	/* 安全闸 2：语法校验（硬失败，未生效） */
	pre[0] = '\0';
	rc = ai_nft_run_file(s.applyf, 1, 15, pre, sizeof(pre));
	if (rc != 0) {
		if (asprintf(out,
			     "ERROR: 语法预检失败（nft -c -f，rc=%d），"
			     "未应用任何变更：\n%.1000s", rc, pre) < 0)
			*out = NULL;
		return -1;
	}

	/* 应用（单批次） */
	buf[0] = '\0';
	rc = ai_nft_run_file(s.applyf, 0, 15, buf, sizeof(buf));
	if (rc != 0) {
		ni_slog(s.log, "应用失败 rc=%d: %.300s", rc, buf);
		if (asprintf(out,
			     "ERROR: 应用失败（nft -f，rc=%d）；nft -f 单批次"
			     "提交，内核拒绝则整体不生效：\n%.1000s", rc, buf) < 0)
			*out = NULL;
		return -1;
	}

	/* 抽查（与 nft_txn 同款：list 回读关键串） */
	{
		char now_tbl[NI_TEXT_MAX];
		int hits = 0, total = 0;

		now_tbl[0] = '\0';
		(void)ni_read_table(in.table, now_tbl, sizeof(now_tbl));
		for (int i = 0; i < in.rule_n; i++) {
			char key[96];

			total++;
			if (in.rule[i].proto == NI_PROTO_ICMP)
				snprintf(key, sizeof(key),
					 "icmp type echo-request %s",
					 in.rule[i].act == NI_ALLOW ?
					 "accept" : "drop");
			else if (in.rule[i].lo == in.rule[i].hi)
				snprintf(key, sizeof(key), "%s dport %d %s",
					 proto_name(in.rule[i].proto),
					 in.rule[i].lo,
					 in.rule[i].act == NI_ALLOW ?
					 "accept" : "drop");
			else
				snprintf(key, sizeof(key),
					 "%s dport %d-%d %s",
					 proto_name(in.rule[i].proto),
					 in.rule[i].lo, in.rule[i].hi,
					 in.rule[i].act == NI_ALLOW ?
					 "accept" : "drop");
			if (strstr(now_tbl, key))
				hits++;
		}
		ni_slog(s.log, "应用成功；抽查 %d/%d 条规则命中", hits, total);
	}

	/* 元数据 + 看门狗 */
	deadline = (long)time(NULL) + arm;
	{
		char meta[512];

		snprintf(meta, sizeof(meta),
			 "table=%s\narm_seconds=%d\ndeadline=%ld\n"
			 "digest=%s\nsnapshot=%d\npolicy=%s\ndir=%s\n",
			 in.table, arm, deadline, dg, s.snapshot_existed,
			 in.policy == NI_POLICY_DROP ? "drop" : "accept",
			 in.dir == NI_DIR_IN ? "input" : "output");
		write_file0600(s.meta, meta);
	}
	unlink(s.decision);
	ni_state_write(&s, "armed");
	ni_slog(s.log, "已下发 inet %s（digest=%s, 窗口=%d 秒）",
		in.table, dg, arm);

	pid = fork();
	if (pid == 0) {
		struct ni_session child = s;

		ni_watchdog_child(&child, arm);
		_exit(0);
	}
	if (pid < 0)
		ni_slog(s.log, "看门狗 fork 失败: %s（需人工确认/回滚）",
			strerror(errno));

	ni_preview(&in, preview, sizeof(preview));
	if (tstate == NI_TBL_PRESENT)
		ni_diff(old, def, diff, sizeof(diff));
	else
		ni_diff("", def, diff, sizeof(diff));

	obuf = malloc(32768);
	if (!obuf) {
		*out = strdup("ERROR: 内存不足");
		return -1;
	}
	sb_init(&b, obuf, 32768);
	sb_printf(&b,
		  "nft 意图下发（V3.1）\n"
		  "表 inet %s / digest=%s / 状态=armed\n\n",
		  in.table, dg);
	sb_printf(&b, "%s\n", preview);
	sb_printf(&b, "语法预检：通过（nft -c -f）\n");
	sb_printf(&b, "应用：成功（nft -f 单批次，rc=0）\n");
	sb_printf(&b,
		  "回滚凭据：快照=%s（apply 前该表%s）\n"
		  "回滚脚本：%s / %s\n",
		  s.snapshot_existed ? "已保存" : "无（表原本不存在）",
		  s.snapshot_existed ? "存在，已存快照" : "不存在",
		  s.rollback_del, s.rollback_add);
	sb_printf(&b, "日志：%s\n", s.log);
	{
		char ts[64];
		time_t dl = (time_t)deadline;
		struct tm tmv;

		localtime_r(&dl, &tmv);
		strftime(ts, sizeof(ts), "%H:%M:%S", &tmv);
		sb_printf(&b,
			  "自动回滚：看门狗 PID=%d，%d 秒内（截止 %s）"
			  "未确认则自动回滚\n", pid, arm, ts);
	}
	sb_printf(&b,
		  "下一步：核对后立即调用 nft_intent_confirm "
		  "action=confirm（保留规则）或 action=rollback（立即回滚）。"
		  "超时自动回滚是防锁死的硬闸，不能用 arm_seconds=0 关闭。\n");
	sb_printf(&b, "\n与下发前的差异（- 旧 / + 新）：\n%s", diff);
	*out = obuf;
	return 0;
}

static int ni_find_session(const char *table, struct ni_session *s,
			   char *err, size_t errcap)
{
	char root[512];
	DIR *d;
	struct dirent *de;
	int found = 0;

	if (table && *table) {
		if (!ni_valid_table(table)) {
			snprintf(err, errcap, "表名非法: %.32s", table);
			return -1;
		}
		ni_session_init(s, table);
		return 0;
	}
	if (ni_state_dir(root, sizeof(root)) != 0) {
		snprintf(err, errcap, "状态目录不可用: %s", strerror(errno));
		return -1;
	}
	d = opendir(root);
	if (!d) {
		snprintf(err, errcap, "状态目录不可读: %.200s", root);
		return -1;
	}
	while ((de = readdir(d)) != NULL) {
		char state[64];
		struct ni_session t;

		if (strncmp(de->d_name, "t-", 2) != 0)
			continue;
		ni_session_init(&t, de->d_name + 2);
		ni_state_read(&t, state, sizeof(state));
		if (strncmp(state, "armed", 5) != 0)
			continue;
		if (found == 0)
			*s = t;
		found++;
	}
	closedir(d);
	if (found == 0) {
		snprintf(err, errcap,
			 "没有处于 armed 状态的未决会话（可能已确认/已回滚/"
			 "超时）；用 table 参数可指定具体表");
		return -1;
	}
	if (found > 1) {
		snprintf(err, errcap,
			 "有 %d 个未决会话，请显式指定 table 参数", found);
		return -1;
	}
	return 0;
}

static int ni_tool_confirm(const char *args, char **out)
{
	char action[32], table[NI_TABLE_LEN * 2], err[512];
	struct ni_session s;
	char state[64], msg[512], decision[64], logtxt[4096];
	int fd;
	long deadline = 0;
	char *obuf;
	struct sbuf b;

	action[0] = '\0';
	table[0] = '\0';
	if (ni_arg_str(args, "action", action, sizeof(action)) != 0 ||
	    !action[0]) {
		*out = strdup("ERROR: 需要 action（confirm 或 rollback）");
		return -1;
	}
	if (strcmp(action, "confirm") != 0 && strcmp(action, "rollback") != 0) {
		*out = strdup("ERROR: action 只接受 confirm 或 rollback");
		return -1;
	}
	(void)ni_arg_str(args, "table", table, sizeof(table));
	if (ni_find_session(table, &s, err, sizeof(err)) != 0) {
		*out = asprintf(&obuf, "ERROR: %s", err) < 0 ? NULL : obuf;
		return -1;
	}
	/* 读 deadline */
	{
		char meta[1024];
		char *p;

		if (read_file_text(s.meta, meta, sizeof(meta)) == 0) {
			p = strstr(meta, "deadline=");

			if (p)
				deadline = strtol(p + 9, NULL, 10);
		}
	}
	ni_state_read(&s, state, sizeof(state));
	if (strncmp(state, "armed", 5) != 0 && strcmp(action, "rollback") != 0) {
		ni_session_log_tail(&s, logtxt, sizeof(logtxt));
		obuf = NULL;
		if (asprintf(&obuf,
			     "ERROR: 表 inet %s 会话状态为 %s（不是 armed），"
			     "无需确认。日志尾部：\n%s",
			     s.table, state, logtxt) < 0)
			obuf = NULL;
		*out = obuf;
		return -1;
	}

	if (strcmp(action, "confirm") == 0) {
		fd = open(s.decision,
			  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
		if (fd >= 0) {
			(void)!write(fd, "confirmed\n", 10);
			close(fd);
			ni_state_write(&s, "confirmed");
			ni_slog(s.log,
				"操作者确认（窗口关闭，自动回滚已取消）");
			ni_session_log_tail(&s, logtxt, sizeof(logtxt));
			{
				long now = (long)time(NULL);
				long left = deadline > now ? deadline - now : 0;

				if (asprintf(&obuf,
					     "已确认：表 inet %s 保留，自动回滚已取消"
					     "（窗口剩余 %ld 秒时确认）。\n"
					     "查看人话摘要：nft_ruleset_summarize"
					     "（table=%s）；原始回读：nft list "
					     "table inet %s\n日志：%s\n%s",
					     s.table, left, s.table, s.table,
					     s.log, logtxt) < 0)
					obuf = NULL;
			}
			*out = obuf;
			return 0;
		}
		if (errno == EEXIST) {
			decision[0] = '\0';
			(void)read_file_text(s.decision, decision,
					     sizeof(decision));
			ni_session_log_tail(&s, logtxt, sizeof(logtxt));
			if (asprintf(&obuf,
				     "ERROR: 决定已由其它路径落定（%s）——"
				     "不能再确认。\n日志：%s\n%s",
				     decision[0] ? decision : "?",
				     s.log, logtxt) < 0)
				obuf = NULL;
			*out = obuf;
			return -1;
		}
		if (asprintf(&obuf, "ERROR: 确认失败 %s: %s", s.decision,
			     strerror(errno)) < 0)
			obuf = NULL;
		*out = obuf;
		return -1;
	}

	if (strcmp(action, "rollback") == 0) {
		fd = open(s.decision,
			  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
		if (fd >= 0) {
			(void)!write(fd, "manual-rollback\n", 16);
			close(fd);
		}
		if (ni_do_rollback(&s, msg, sizeof(msg)) == 0) {
			ni_slog(s.log, "操作者手动回滚：%s", msg);
			ni_state_write(&s, "rolled_back");
		} else {
			ni_slog(s.log, "操作者手动回滚失败：%s", msg);
		}
		ni_session_log_tail(&s, logtxt, sizeof(logtxt));
		obuf = malloc(16384);
		if (!obuf) {
			*out = strdup("ERROR: 内存不足");
			return -1;
		}
		sb_init(&b, obuf, 16384);
		sb_printf(&b,
			  "回滚：表 inet %s\n结果：%s\n回滚脚本：%s / %s\n"
			  "日志：%s\n日志尾部：\n%s\n",
			  s.table, msg, s.rollback_del, s.rollback_add, s.log,
			  logtxt);
		*out = obuf;
		return 0;
	}
	return -1;
}

static int ni_tool_summarize(const char *args, char **out)
{
	char table[NI_TABLE_LEN * 2], err[512];
	char *json;
	char *txt;
	int rc;
	size_t cap = 262144;
	struct sbuf b;
	char *obuf;

	table[0] = '\0';
	(void)ni_arg_str(args, "table", table, sizeof(table));
	if (table[0] && !ni_valid_table(table)) {
		*out = strdup("ERROR: table 参数非法（只允许 "
			      "[a-z_][a-z0-9_]{0,14}）");
		return -1;
	}
	json = malloc(cap);
	txt = malloc(65536);
	if (!json || !txt) {
		free(json);
		free(txt);
		*out = strdup("ERROR: 内存不足");
		return -1;
	}
	{
		const char *const argv[] = { "-j", "list", "ruleset", NULL };

		json[0] = '\0';
		rc = ai_nft_list_args(argv, json, cap);
	}
	if (rc != 0) {
		if (asprintf(out,
			     "ERROR: nft -j list ruleset 失败（rc=%d）：%.600s",
			     rc, json) < 0)
			*out = NULL;
		free(json);
		free(txt);
		return -1;
	}
	if (strlen(json) >= cap - 1) {
		if (asprintf(out,
			     "ERROR: nft -j 输出超过 %zu 字节被截断，"
			     "拒绝解析半截 JSON（请改用 table 参数缩小范围，"
			     "或直接 nft list ruleset）", cap) < 0)
			*out = NULL;
		free(json);
		free(txt);
		return -1;
	}
	if (ni_summarize(json, table[0] ? table : NULL, txt, 65536, err,
			 sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 规则集摘要失败：%s", err) < 0)
			*out = NULL;
		free(json);
		free(txt);
		return -1;
	}
	obuf = malloc(65536);
	if (!obuf) {
		free(json);
		free(txt);
		*out = strdup("ERROR: 内存不足");
		return -1;
	}
	sb_init(&b, obuf, 65536);
	sb_printf(&b, "%s", txt);
	sb_printf(&b, "（只读：本工具不做任何规则改动）\n");
	*out = obuf;
	free(json);
	free(txt);
	return 0;
}

/* ======================================================================
 * 8) 分发
 * ====================================================================== */

int exec_net_intent_channel(const void *tool_v, const char *args_json,
			    char **out)
{
	const struct ai_tool *tool = tool_v;

	*out = NULL;
	if (!tool || !tool->name || !args_json)
		return -1;
	if (strcmp(tool->name, "nft_intent_compile") == 0)
		return ni_tool_compile(args_json, out);
	if (strcmp(tool->name, "nft_intent_apply") == 0)
		return ni_tool_apply(args_json, out);
	if (strcmp(tool->name, "nft_intent_confirm") == 0)
		return ni_tool_confirm(args_json, out);
	if (strcmp(tool->name, "nft_ruleset_summarize") == 0)
		return ni_tool_summarize(args_json, out);
	if (asprintf(out, "ERROR: 未知 netintent 工具（注册表异常）") < 0)
		*out = NULL;
	return -1;
}
