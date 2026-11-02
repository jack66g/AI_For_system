/* SPDX-License-Identifier: GPL-2.0 */
/*
 * config_items.c - T4e 配置注册表（101 可调项 / 5 预设 / 10 分组）
 *
 * 语义逐条对齐 REF-PY e72bc75：
 *   - sme/config_items.py：parse_value / _parse_number / validate_value /
 *     defaults_config / complete_config / load_config / save_config /
 *     build_help / validate_config / _required_warnings
 *   - sme/api/server.py：_display_dict / _item_payload / _config_groups /
 *     presets 摘要
 *
 * 数据表来自生成文件 config_items_data.h（只读）。本文件只提供行为；错误
 * 文案、值域判定、分组 payload 形状与参考实现逐字一致。
 *
 * 落盘格式 = Python `json.dump(cfg, fh, ensure_ascii=False, indent=2)`：
 * 两空格缩进、空容器写 `[]`/`{}`、元素之间 `,\n`、键值 `": "`、文件无结尾
 * 换行、非 ASCII 原样（UTF-8）。注意换行用 **LF**：冻结向量
 * `config_file.expected.txt` 里的 CRLF 是 Windows 文本模式录制产物（与
 * T2 WAL 同源的结论，见 work/refactor/T2-LOG.md），产品目标 Linux 与
 * Python 在 Linux 上写出的 json.dump 文本一致。
 *
 * 本文件零第三方依赖，C11，构建串行（见 Makefile）。
 */
#define _POSIX_C_SOURCE 200809L

#include "../include/smeconfig/config_items.h"

#include "config_items_data.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* sme/config_items.py: OFF_PERIOD（填 off 关闭的哨兵值） */
#define OFF_PERIOD 1000000000LL

#define HELP_KEY "_help"

/* ------------------------------------------------------------------ */
/* 小工具                                                             */
/* ------------------------------------------------------------------ */
static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || errlen == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

/* 可增长字符串（错误文案 / 序列化缓冲） */
struct sbuf {
	char *p;
	size_t n;
	size_t cap;
};

static int sb_grow(struct sbuf *b, size_t need)
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
	np = realloc(b->p, cap);
	if (!np)
		return -1;
	b->p = np;
	b->cap = cap;
	return 0;
}

static int sb_mem(struct sbuf *b, const char *s, size_t n)
{
	if (sb_grow(b, n) != 0)
		return -1;
	if (n)
		memcpy(b->p + b->n, s, n);
	b->n += n;
	b->p[b->n] = '\0';
	return 0;
}

static int sb_str(struct sbuf *b, const char *s)
{
	return sb_mem(b, s ? s : "", s ? strlen(s) : 0);
}

static int sb_chr(struct sbuf *b, char c)
{
	return sb_mem(b, &c, 1);
}

static int sb_i64(struct sbuf *b, long long v)
{
	char tmp[32];
	int n = snprintf(tmp, sizeof(tmp), "%lld", v);

	if (n < 0 || (size_t)n >= sizeof(tmp))
		return -1;
	return sb_mem(b, tmp, (size_t)n);
}

/* 深拷贝（类型/键序/元素序原样；OOM 返回 NULL） */
static aik_json *json_clone(const aik_json *v)
{
	aik_json *out;
	size_t i, n;

	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		return aik_json_new_null();
	case AIK_JSON_BOOL:
		return aik_json_new_bool(aik_json_bool(v));
	case AIK_JSON_INT:
		return aik_json_new_int(aik_json_int(v));
	case AIK_JSON_NUM:
		return aik_json_new_num(aik_json_num(v));
	case AIK_JSON_STR:
		return aik_json_new_str(aik_json_str(v));
	case AIK_JSON_ARR:
		out = aik_json_new_arr();
		if (!out)
			return NULL;
		n = aik_json_count(v);
		for (i = 0; i < n; i++) {
			aik_json *item = json_clone(aik_json_at(v, i));

			if (!item || aik_json_arr_push(out, item) != 0) {
				aik_json_free(item);
				aik_json_free(out);
				return NULL;
			}
		}
		return out;
	case AIK_JSON_OBJ:
		out = aik_json_new_obj();
		if (!out)
			return NULL;
		n = aik_json_count(v);
		for (i = 0; i < n; i++) {
			const char *key = aik_json_key_at(v, i);
			aik_json *item = json_clone(aik_json_val_at(v, i));

			if (!key || !item || aik_json_obj_put(out, key, item) != 0) {
				aik_json_free(item);
				aik_json_free(out);
				return NULL;
			}
		}
		return out;
	}
	return NULL;
}

/* dump+parse 深拷贝（config_item_set 用；保证与源节点无别名） */
static aik_json *json_dup(const aik_json *v)
{
	char *text = NULL;
	size_t len = 0;
	aik_json *copy;

	if (!v)
		return NULL;
	if (aik_json_dump(v, &text, &len) != 0)
		return NULL;
	copy = aik_json_parse(text, len, NULL, 0);
	free(text);
	return copy;
}

/* 注册表里的 JSON 数字字面量 -> double（字面量由生成器保证合法） */
static int lit_to_double(const char *lit, double *out)
{
	char *end = NULL;
	double d;

	if (!lit || !*lit)
		return -1;
	errno = 0;
	d = strtod(lit, &end);
	if (!end || *end != '\0')
		return -1;
	*out = d;
	return 0;
}

/* Python f"{v:g}" 等价（C locale，%g 默认 6 位有效数字） */
static void fmt_g(char *buf, size_t buflen, double v)
{
	snprintf(buf, buflen, "%g", v);
}

/* ASCII 大小写不敏感比较（Python str.lower() 对键表足够：键全是 ASCII
 * 或中文，中文不需要大小写折叠） */
static int ascii_casecmp(const char *a, const char *b)
{
	while (*a && *b) {
		unsigned char ca = (unsigned char)*a;
		unsigned char cb = (unsigned char)*b;

		if (ca < 0x80)
			ca = (unsigned char)tolower(ca);
		if (cb < 0x80)
			cb = (unsigned char)tolower(cb);
		if (ca != cb)
			return (int)ca - (int)cb;
		a++;
		b++;
	}
	return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

/* ------------------------------------------------------------------ */
/* Unicode strip（Python str.strip() 的空白集合）                      */
/* ------------------------------------------------------------------ */
static int py_isspace(unsigned long cp)
{
	if (cp == 0x20 || (cp >= 0x09 && cp <= 0x0D))
		return 1;
	if (cp >= 0x1C && cp <= 0x1F)
		return 1;
	if (cp >= 0x2000 && cp <= 0x200A)
		return 1;
	switch (cp) {
	case 0x85:
	case 0xA0:
	case 0x1680:
	case 0x2028:
	case 0x2029:
	case 0x202F:
	case 0x205F:
	case 0x3000:
		return 1;
	}
	return 0;
}

/* 解码一个 UTF-8 码点；非法/截断序列按单字节处理（cp = 该字节） */
static size_t utf8_decode(const unsigned char *p, unsigned long *cp)
{
	if (p[0] < 0x80) {
		*cp = p[0];
		return 1;
	}
	if ((p[0] & 0xE0) == 0xC0 && p[1] && (p[1] & 0xC0) == 0x80) {
		*cp = ((unsigned long)(p[0] & 0x1F) << 6) |
		      (unsigned long)(p[1] & 0x3F);
		return 2;
	}
	if ((p[0] & 0xF0) == 0xE0 && p[1] && p[2] &&
	    (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
		*cp = ((unsigned long)(p[0] & 0x0F) << 12) |
		      ((unsigned long)(p[1] & 0x3F) << 6) |
		      (unsigned long)(p[2] & 0x3F);
		return 3;
	}
	if ((p[0] & 0xF8) == 0xF0 && p[1] && p[2] && p[3] &&
	    (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 &&
	    (p[3] & 0xC0) == 0x80) {
		*cp = ((unsigned long)(p[0] & 0x07) << 18) |
		      ((unsigned long)(p[1] & 0x3F) << 12) |
		      ((unsigned long)(p[2] & 0x3F) << 6) |
		      (unsigned long)(p[3] & 0x3F);
		return 4;
	}
	*cp = p[0];
	return 1;
}

/* malloc 版 strip；OOM 返回 NULL */
static char *py_strip(const char *s)
{
	const unsigned char *p = (const unsigned char *)(s ? s : "");
	const unsigned char *first = NULL;
	size_t end = 0, i = 0, start, len;
	char *out;

	while (p[i]) {
		unsigned long cp;
		size_t n = utf8_decode(p + i, &cp);

		if (!py_isspace(cp)) {
			if (!first)
				first = p + i;
			end = i + n;
		}
		i += n;
	}
	if (!first) {
		out = malloc(1);
		if (out)
			out[0] = '\0';
		return out;
	}
	start = (size_t)(first - p);
	len = end - start;
	out = malloc(len + 1);
	if (!out)
		return NULL;
	memcpy(out, p + start, len);
	out[len] = '\0';
	return out;
}

/* ------------------------------------------------------------------ */
/* Python int() / float() 子集                                        */
/* ------------------------------------------------------------------ */
static int is_digit_ch(char c)
{
	return c >= '0' && c <= '9';
}

/* 允许 Python 下划线分隔：数字之间单个 '_'，首尾/连续不合法 */
static int consume_digits(const char **pp, size_t *count)
{
	const char *p = *pp;
	size_t n = 0;

	if (!is_digit_ch(*p))
		return -1;
	while (*p) {
		if (*p == '_') {
			if (!n || !is_digit_ch(p[1]))
				return -1;
			p++;
			continue;
		}
		if (!is_digit_ch(*p))
			break;
		n++;
		p++;
	}
	*pp = p;
	*count += n;
	return 0;
}

static int parse_py_int(const char *s, long long *out)
{
	const char *p = s;
	int neg = 0, overflow = 0;
	unsigned long long uv = 0, limit;
	size_t ndig = 0;

	if (*p == '+' || *p == '-') {
		neg = (*p == '-');
		p++;
	}
	if (!*p)
		return -1;
	while (*p) {
		if (*p == '_') {
			if (!ndig || !is_digit_ch(p[1]))
				return -1;
			p++;
			continue;
		}
		if (!is_digit_ch(*p))
			return -1;
		{
			unsigned d = (unsigned)(*p - '0');

			if (uv > (ULLONG_MAX - d) / 10) {
				overflow = 1;
			} else {
				uv = uv * 10 + d;
			}
		}
		ndig++;
		p++;
	}
	if (ndig == 0)
		return -1;
	limit = neg ? 9223372036854775808ULL : 9223372036854775807ULL;
	if (!overflow && uv > limit)
		overflow = 1;
	if (overflow) {
		/* Python 是任意精度；超出 int64 时饱和（调用方随后的 min/max
		 * 检查几乎总会拒绝这种值），行为在报告里标注 */
		*out = neg ? LLONG_MIN : LLONG_MAX;
		return 0;
	}
	if (neg) {
		if (uv == 9223372036854775808ULL)
			*out = LLONG_MIN;
		else
			*out = -(long long)uv;
	} else {
		*out = (long long)uv;
	}
	return 0;
}

static int ci_prefix(const char *s, const char *word)
{
	while (*word) {
		unsigned char a = (unsigned char)*s;
		unsigned char b = (unsigned char)*word;

		if (a < 0x80)
			a = (unsigned char)tolower(a);
		if (a != b)
			return 0;
		s++;
		word++;
	}
	return 1;
}

static int parse_py_float(const char *s, double *out)
{
	const char *p = s;
	char *clean, *end = NULL;
	size_t i, n = 0;
	int neg = 0;
	double d;

	if (!s || !*s)
		return -1;
	if (*p == '+' || *p == '-') {
		neg = (*p == '-');
		p++;
	}
	if (!*p)
		return -1;
	if (ci_prefix(p, "inf")) {
		p += 3;
		if (ci_prefix(p, "inity"))
			p += 5;
		if (*p)
			return -1;
		*out = neg ? -INFINITY : INFINITY;
		return 0;
	}
	if (ci_prefix(p, "nan")) {
		p += 3;
		if (*p)
			return -1;
		*out = NAN;
		return 0;
	}
	if (consume_digits(&p, &n) != 0) {
		/* 允许 ".5"：小数点开头但必须有数字 */
		if (*p != '.')
			return -1;
	}
	if (*p == '.') {
		p++;
		/* Python 接受 "5."（小数点后无数字）与 ".5"（前无数字），
		 * 但 "." 不合法 */
		if (consume_digits(&p, &n) != 0 && n == 0)
			return -1;
	}
	if (n == 0)
		return -1;
	if (*p == 'e' || *p == 'E') {
		p++;
		if (*p == '+' || *p == '-')
			p++;
		n = 0;
		if (consume_digits(&p, &n) != 0)
			return -1;
	}
	if (*p)
		return -1;

	clean = malloc(strlen(s) + 1);
	if (!clean)
		return -1;
	{
		char *q = clean;

		for (i = 0; s[i]; i++)
			if (s[i] != '_')
				*q++ = s[i];
		*q = '\0';
	}
	errno = 0;
	d = strtod(clean, &end);
	if (!end || *end != '\0') {
		free(clean);
		return -1;
	}
	free(clean);
	*out = d;	/* 溢出得到 ±inf：留待有限性检查报错 */
	return 0;
}

/* ------------------------------------------------------------------ */
/* 查找                                                               */
/* ------------------------------------------------------------------ */
const aik_config_item *aik_config_item_find(const char *path)
{
	size_t i;

	if (!path)
		return NULL;
	for (i = 0; i < aik_config_item_count; i++)
		if (strcmp(aik_config_items[i].path, path) == 0)
			return &aik_config_items[i];
	return NULL;
}

const aik_config_preset *aik_config_preset_find(const char *key)
{
	size_t i;

	if (!key)
		return NULL;
	for (i = 0; i < aik_config_preset_count; i++)
		if (strcmp(aik_config_presets[i].key, key) == 0)
			return &aik_config_presets[i];
	return NULL;
}

/* ------------------------------------------------------------------ */
/* dotted path 读 / 写                                                */
/* ------------------------------------------------------------------ */
const aik_json *aik_config_item_get(const aik_json *cfg,
				    const aik_config_item *it)
{
	const aik_json *cur;
	const char *p;

	if (!cfg || !it || !it->path || !*it->path)
		return NULL;
	if (aik_json_typeof(cfg) != AIK_JSON_OBJ)
		return NULL;
	cur = cfg;
	p = it->path;
	for (;;) {
		const char *dot = strchr(p, '.');
		size_t len = dot ? (size_t)(dot - p) : strlen(p);
		const aik_json *hit;
		char *key;

		key = malloc(len + 1);
		if (!key)
			return NULL;
		memcpy(key, p, len);
		key[len] = '\0';
		hit = aik_json_get(cur, key);
		free(key);
		if (!hit)
			return NULL;
		cur = hit;
		if (!dot)
			break;
		p = dot + 1;
		if (aik_json_typeof(cur) != AIK_JSON_OBJ)
			return NULL;
	}
	return cur;
}

int aik_config_item_has(const aik_json *cfg, const aik_config_item *it)
{
	return aik_config_item_get(cfg, it) != NULL;
}

aik_json *aik_config_item_default(const aik_config_item *it)
{
	if (!it || !it->default_json)
		return NULL;
	return aik_json_parse(it->default_json, strlen(it->default_json),
			      NULL, 0);
}

int aik_config_item_set(aik_json *cfg, const aik_config_item *it,
			const aik_json *value)
{
	aik_json *cur, *copy;
	const char *p;

	if (!cfg || !it || !it->path || !*it->path || !value)
		return -1;
	if (aik_json_typeof(cfg) != AIK_JSON_OBJ)
		return -1;
	copy = json_dup(value);
	if (!copy)
		return -1;
	cur = cfg;
	p = it->path;
	for (;;) {
		const char *dot = strchr(p, '.');
		size_t len = dot ? (size_t)(dot - p) : strlen(p);
		char *key = malloc(len + 1);

		if (!key) {
			aik_json_free(copy);
			return -1;
		}
		memcpy(key, p, len);
		key[len] = '\0';
		if (!dot) {
			int rc = aik_json_obj_set(cur, key, copy);

			free(key);
			if (rc != 0) {
				aik_json_free(copy);
				return -1;
			}
			return 0;
		}
		{
			const aik_json *child = aik_json_get(cur, key);
			aik_json *obj;

			if (child && aik_json_typeof(child) == AIK_JSON_OBJ) {
				obj = (aik_json *)child;
			} else {
				obj = aik_json_new_obj();
				if (!obj) {
					free(key);
					aik_json_free(copy);
					return -1;
				}
				if (aik_json_obj_set(cur, key, obj) != 0) {
					free(key);
					aik_json_free(obj);
					aik_json_free(copy);
					return -1;
				}
			}
			free(key);
			cur = obj;
		}
		p = dot + 1;
	}
}

/* ------------------------------------------------------------------ */
/* parse_value                                                        */
/* ------------------------------------------------------------------ */
static int bool_lookup(const char *s, int *out)
{
	static const struct {
		const char *word;
		int value;
	} TABLE[] = {
		{ "1", 1 },   { "0", 0 },     { "true", 1 }, { "false", 0 },
		{ "yes", 1 }, { "no", 0 },    { "on", 1 },   { "off", 0 },
		{ "y", 1 },   { "n", 0 },     { "开", 1 },   { "关", 0 },
		{ "是", 1 },  { "否", 0 },
	};
	size_t i;

	for (i = 0; i < sizeof(TABLE) / sizeof(TABLE[0]); i++)
		if (ascii_casecmp(TABLE[i].word, s) == 0) {
			*out = TABLE[i].value;
			return 0;
		}
	return -1;
}

/* Python f"可选值：{' / '.join(c or '空' for c in choices)}" */
static void set_enum_parse_err(char *err, size_t errlen,
			       const aik_config_item *it)
{
	struct sbuf b = { 0 };
	size_t i;

	sb_str(&b, "可选值：");
	for (i = 0; i < it->n_choices; i++) {
		const char *c = it->choices[i];

		if (i)
			sb_str(&b, " / ");
		sb_str(&b, (c && *c) ? c : "空");
	}
	set_err(err, errlen, "%s", b.p ? b.p : "可选值：");
	free(b.p);
}

/* Python f"可选值：{' / '.join(choices)}"（validate_value 不替换空串） */
static void set_enum_validate_err(char *err, size_t errlen,
				  const aik_config_item *it)
{
	struct sbuf b = { 0 };
	size_t i;

	sb_str(&b, "可选值：");
	for (i = 0; i < it->n_choices; i++) {
		if (i)
			sb_str(&b, " / ");
		sb_str(&b, it->choices[i] ? it->choices[i] : "");
	}
	set_err(err, errlen, "%s", b.p ? b.p : "可选值：");
	free(b.p);
}

/* 区间检查：v < minimum / v > maximum；命中写入 err 并返回 -1 */
static int check_range(const aik_config_item *it, double v,
		       const char *prefix, char *err, size_t errlen)
{
	double bound;
	char num[64];

	if (it->minimum && lit_to_double(it->minimum, &bound) == 0 &&
	    v < bound) {
		fmt_g(num, sizeof(num), bound);
		if (prefix)
			set_err(err, errlen, "%s 不能小于 %s", prefix, num);
		else
			set_err(err, errlen, "不能小于 %s", num);
		return -1;
	}
	if (it->maximum && lit_to_double(it->maximum, &bound) == 0 &&
	    v > bound) {
		fmt_g(num, sizeof(num), bound);
		if (prefix)
			set_err(err, errlen, "%s 不能大于 %s", prefix, num);
		else
			set_err(err, errlen, "不能大于 %s", num);
		return -1;
	}
	return 0;
}

int aik_config_item_parse(const aik_config_item *it, const char *raw,
			  aik_json **out, char *err, size_t errlen)
{
	char *s;
	int rc = -1;

	if (out)
		*out = NULL;
	if (!it || !out)
		return -1;
	s = py_strip(raw);
	if (!s) {
		set_err(err, errlen, "内存不足");
		return -1;
	}
	if (it->required && s[0] == '\0') {
		set_err(err, errlen, "%s 不能为空，请输入一个值", it->name);
		goto done;
	}
	switch (it->kind) {
	case AIK_CFG_KIND_BOOL: {
		int flag = 0;

		if (bool_lookup(s, &flag) != 0) {
			set_err(err, errlen,
				"请输入 开/关（或 1/0 / true/false / on/off）");
			goto done;
		}
		*out = aik_json_new_bool(flag);
		break;
	}
	case AIK_CFG_KIND_ENUM: {
		size_t i;
		int hit = 0;

		if (s[0] == '\0') {
			*out = aik_json_new_str("");
			break;
		}
		for (i = 0; i < it->n_choices; i++) {
			if (ascii_casecmp(it->choices[i], s) == 0) {
				*out = aik_json_new_str(it->choices[i]);
				hit = 1;
				break;
			}
		}
		if (!hit) {
			set_enum_parse_err(err, errlen, it);
			goto done;
		}
		break;
	}
	case AIK_CFG_KIND_INTERVAL: {
		long long ll;

		if (ascii_casecmp(s, "off") == 0 ||
		    ascii_casecmp(s, "none") == 0 ||
		    ascii_casecmp(s, "关") == 0 ||
		    ascii_casecmp(s, "关闭") == 0) {
			*out = aik_json_new_int(OFF_PERIOD);
			break;
		}
		if (parse_py_int(s, &ll) != 0) {
			set_err(err, errlen, "%s 必须是整数", it->name);
			goto done;
		}
		if (check_range(it, (double)ll, it->name, err, errlen) != 0)
			goto done;
		*out = aik_json_new_int(ll);
		break;
	}
	case AIK_CFG_KIND_INT: {
		long long ll;

		if (parse_py_int(s, &ll) != 0) {
			set_err(err, errlen, "%s 必须是整数", it->name);
			goto done;
		}
		if (check_range(it, (double)ll, it->name, err, errlen) != 0)
			goto done;
		*out = aik_json_new_int(ll);
		break;
	}
	case AIK_CFG_KIND_FLOAT: {
		double d;

		if (parse_py_float(s, &d) != 0) {
			set_err(err, errlen, "%s 必须是数字", it->name);
			goto done;
		}
		if (!isfinite(d)) {
			set_err(err, errlen, "%s 必须是有限数字", it->name);
			goto done;
		}
		if (check_range(it, d, it->name, err, errlen) != 0)
			goto done;
		*out = aik_json_new_num(d);
		break;
	}
	case AIK_CFG_KIND_STR:
	default:
		*out = aik_json_new_str(s);
		break;
	}
	if (!*out) {
		set_err(err, errlen, "内存不足");
		goto done;
	}
	rc = 0;
done:
	free(s);
	return rc;
}

/* ------------------------------------------------------------------ */
/* validate_value                                                     */
/* ------------------------------------------------------------------ */
int aik_config_item_validate(const aik_config_item *it, const aik_json *value,
			     char *err, size_t errlen)
{
	aik_json_type t;

	if (!it)
		return -2;
	t = aik_json_typeof(value);
	if (!value || t == AIK_JSON_NULL) {
		set_err(err, errlen, "值为空");
		return -1;
	}
	switch (it->kind) {
	case AIK_CFG_KIND_BOOL:
		if (t != AIK_JSON_BOOL) {
			set_err(err, errlen, "应为 开/关（true/false）");
			return -1;
		}
		return 0;
	case AIK_CFG_KIND_INT:
	case AIK_CFG_KIND_INTERVAL:
		if (t != AIK_JSON_INT) {
			set_err(err, errlen, "应为整数");
			return -1;
		}
		return check_range(it, (double)aik_json_int(value), NULL, err,
				   errlen);
	case AIK_CFG_KIND_FLOAT: {
		double d;

		if (t != AIK_JSON_INT && t != AIK_JSON_NUM) {
			set_err(err, errlen, "应为数字");
			return -1;
		}
		d = t == AIK_JSON_INT ? (double)aik_json_int(value)
				      : aik_json_num(value);
		if (!isfinite(d)) {
			set_err(err, errlen, "必须是有限数字");
			return -1;
		}
		return check_range(it, d, NULL, err, errlen);
	}
	case AIK_CFG_KIND_ENUM: {
		size_t i;

		if (t == AIK_JSON_STR && aik_json_strlen(value) == 0)
			return 0;
		if (t == AIK_JSON_STR) {
			const char *s = aik_json_str(value);

			for (i = 0; i < it->n_choices; i++)
				if (strcmp(it->choices[i], s) == 0)
					return 0;
		}
		set_enum_validate_err(err, errlen, it);
		return -1;
	}
	case AIK_CFG_KIND_STR:
	default:
		if (t != AIK_JSON_STR) {
			set_err(err, errlen, "应为字符串");
			return -1;
		}
		return 0;
	}
}

/* ------------------------------------------------------------------ */
/* defaults / complete                                                */
/* ------------------------------------------------------------------ */
aik_json *aik_config_defaults_build(void)
{
	aik_json *cfg = aik_json_new_obj();
	size_t i;

	if (!cfg)
		return NULL;
	for (i = 0; i < aik_config_item_count; i++) {
		aik_json *def = aik_config_item_default(&aik_config_items[i]);

		if (!def || aik_config_item_set(cfg, &aik_config_items[i],
						def) != 0) {
			aik_json_free(def);
			aik_json_free(cfg);
			return NULL;
		}
		aik_json_free(def);
	}
	return cfg;
}

int aik_config_complete(aik_json *cfg)
{
	size_t i;

	if (!cfg || aik_json_typeof(cfg) != AIK_JSON_OBJ)
		return -1;
	for (i = 0; i < aik_config_item_count; i++) {
		aik_json *def;

		if (aik_config_item_has(cfg, &aik_config_items[i]))
			continue;
		def = aik_config_item_default(&aik_config_items[i]);
		if (!def)
			return -1;
		if (aik_config_item_set(cfg, &aik_config_items[i], def) != 0) {
			aik_json_free(def);
			return -1;
		}
		aik_json_free(def);
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* 文件读                                                             */
/* ------------------------------------------------------------------ */
static char *read_file_all(const char *path, size_t *len)
{
	FILE *f;
	char *buf;
	long n;
	size_t got;

	f = fopen(path, "rb");
	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 ||
	    fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return NULL;
	}
	buf = malloc((size_t)n + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	got = fread(buf, 1, (size_t)n, f);
	fclose(f);
	if (got != (size_t)n) {
		free(buf);
		return NULL;
	}
	buf[n] = '\0';
	*len = (size_t)n;
	return buf;
}

aik_json *aik_config_load_file(const char *path, char *err, size_t errlen)
{
	aik_json *dom = NULL;
	char *buf;
	size_t len = 0, off = 0;

	if (err && errlen)
		err[0] = '\0';
	/* 文件不存在 / 路径为空 -> defaults_config()（参考 load_config） */
	if (!path || !*path)
		return aik_config_defaults_build();
	buf = read_file_all(path, &len);
	if (!buf)
		return aik_config_defaults_build();
	/* encoding="utf-8-sig"：允许起始 BOM */
	if (len >= 3 && (unsigned char)buf[0] == 0xEF &&
	    (unsigned char)buf[1] == 0xBB && (unsigned char)buf[2] == 0xBF)
		off = 3;
	dom = aik_json_parse(buf + off, len - off, NULL, 0);
	free(buf);
	if (!dom || aik_json_typeof(dom) != AIK_JSON_OBJ) {
		aik_json_free(dom);
		return aik_config_defaults_build();
	}
	return dom;
}

/* ------------------------------------------------------------------ */
/* 缩进序列化（= json.dump(indent=2)）                                */
/* ------------------------------------------------------------------ */
static const char HEXD[] = "0123456789abcdef";

static int pretty_str(struct sbuf *b, const char *s, size_t n)
{
	size_t i;

	if (sb_chr(b, '"') != 0)
		return -1;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];

		switch (c) {
		case '"':
			if (sb_mem(b, "\\\"", 2) != 0)
				return -1;
			break;
		case '\\':
			if (sb_mem(b, "\\\\", 2) != 0)
				return -1;
			break;
		case '\b':
			if (sb_mem(b, "\\b", 2) != 0)
				return -1;
			break;
		case '\f':
			if (sb_mem(b, "\\f", 2) != 0)
				return -1;
			break;
		case '\n':
			if (sb_mem(b, "\\n", 2) != 0)
				return -1;
			break;
		case '\r':
			if (sb_mem(b, "\\r", 2) != 0)
				return -1;
			break;
		case '\t':
			if (sb_mem(b, "\\t", 2) != 0)
				return -1;
			break;
		default:
			if (c < 0x20) {
				char esc[6];

				esc[0] = '\\';
				esc[1] = 'u';
				esc[2] = '0';
				esc[3] = '0';
				esc[4] = HEXD[c >> 4];
				esc[5] = HEXD[c & 0x0F];
				if (sb_mem(b, esc, sizeof(esc)) != 0)
					return -1;
			} else if (sb_chr(b, (char)c) != 0) {
				return -1;
			}
			break;
		}
	}
	return sb_chr(b, '"');
}

static int pretty_indent(struct sbuf *b, int level)
{
	int i;

	for (i = 0; i < level * 2; i++)
		if (sb_chr(b, ' ') != 0)
			return -1;
	return 0;
}

static int pretty_value(struct sbuf *b, const aik_json *v, int level)
{
	size_t i, n;

	if (!v)
		return sb_mem(b, "null", 4);
	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		return sb_mem(b, "null", 4);
	case AIK_JSON_BOOL:
		return aik_json_bool(v) ? sb_mem(b, "true", 4)
					: sb_mem(b, "false", 5);
	case AIK_JSON_INT:
		return sb_i64(b, aik_json_int(v));
	case AIK_JSON_NUM: {
		char tmp[64];
		int len = aik_json_dtoa(aik_json_num(v), tmp, sizeof(tmp));

		if (len < 0)
			return -1;
		return sb_mem(b, tmp, (size_t)len);
	}
	case AIK_JSON_STR:
		return pretty_str(b, aik_json_str(v), aik_json_strlen(v));
	case AIK_JSON_ARR:
		n = aik_json_count(v);
		if (n == 0)
			return sb_mem(b, "[]", 2);
		if (sb_mem(b, "[\n", 2) != 0)
			return -1;
		for (i = 0; i < n; i++) {
			if (pretty_indent(b, level + 1) != 0 ||
			    pretty_value(b, aik_json_at(v, i), level + 1) != 0)
				return -1;
			if (i + 1 < n && sb_chr(b, ',') != 0)
				return -1;
			if (sb_chr(b, '\n') != 0)
				return -1;
		}
		if (pretty_indent(b, level) != 0)
			return -1;
		return sb_chr(b, ']');
	case AIK_JSON_OBJ:
		n = aik_json_count(v);
		if (n == 0)
			return sb_mem(b, "{}", 2);
		if (sb_mem(b, "{\n", 2) != 0)
			return -1;
		for (i = 0; i < n; i++) {
			const char *key = aik_json_key_at(v, i);

			if (pretty_indent(b, level + 1) != 0 ||
			    pretty_str(b, key, key ? strlen(key) : 0) != 0 ||
			    sb_mem(b, ": ", 2) != 0 ||
			    pretty_value(b, aik_json_val_at(v, i),
					 level + 1) != 0)
				return -1;
			if (i + 1 < n && sb_chr(b, ',') != 0)
				return -1;
			if (sb_chr(b, '\n') != 0)
				return -1;
		}
		if (pretty_indent(b, level) != 0)
			return -1;
		return sb_chr(b, '}');
	}
	return -1;
}

/* ------------------------------------------------------------------ */
/* 原子写                                                             */
/* ------------------------------------------------------------------ */
static char *path_dirname(const char *path)
{
	const char *slash = strrchr(path, '/');
	size_t len;
	char *dir;

	if (!slash) {
		dir = malloc(2);
		if (!dir)
			return NULL;
		memcpy(dir, ".", 2);
		return dir;
	}
	len = (size_t)(slash - path);
	if (len == 0)
		len = 1;	/* 根目录 "/" */
	dir = malloc(len + 1);
	if (!dir)
		return NULL;
	memcpy(dir, path, len);
	dir[len] = '\0';
	return dir;
}

/* mkdir -p；已存在视为成功 */
static int ensure_dir(const char *dir)
{
	char *buf;
	size_t i, n;
	int rc = 0;

	if (!dir || !*dir)
		return 0;
	buf = malloc(strlen(dir) + 1);
	if (!buf)
		return -1;
	strcpy(buf, dir);
	n = strlen(buf);
	for (i = 1; i <= n; i++) {
		if (buf[i] == '/' || buf[i] == '\0') {
			char saved = buf[i];

			buf[i] = '\0';
			if (mkdir(buf, 0777) != 0 && errno != EEXIST) {
				rc = -1;
				buf[i] = saved;
				break;
			}
			buf[i] = saved;
		}
	}
	free(buf);
	return rc;
}

static int write_atomic(const char *path, const char *data, size_t len,
			char *err, size_t errlen)
{
	char *dir = path_dirname(path);
	char *tmp = NULL;
	size_t dlen, i;
	int fd = -1, dfd = -1, rc = -1;

	if (!dir) {
		set_err(err, errlen, "内存不足");
		return -1;
	}
	dlen = strlen(dir);
	tmp = malloc(dlen + 32);
	if (!tmp) {
		free(dir);
		set_err(err, errlen, "内存不足");
		return -1;
	}
	snprintf(tmp, dlen + 32, "%s/.sme-config-XXXXXX", dir);
	if (ensure_dir(dir) != 0) {
		set_err(err, errlen, "无法创建目录 %s: %s", dir, strerror(errno));
		goto out;
	}
	fd = mkstemp(tmp);
	if (fd < 0) {
		set_err(err, errlen, "无法创建临时文件 %s: %s", tmp,
			strerror(errno));
		goto out;
	}
	i = 0;
	while (i < len) {
		ssize_t n = write(fd, data + i, len - i);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			set_err(err, errlen, "写入 %s 失败: %s", tmp,
				strerror(errno));
			goto out;
		}
		i += (size_t)n;
	}
	if (fsync(fd) != 0) {
		set_err(err, errlen, "fsync %s 失败: %s", tmp, strerror(errno));
		goto out;
	}
	if (close(fd) != 0) {
		fd = -1;
		set_err(err, errlen, "关闭 %s 失败: %s", tmp, strerror(errno));
		goto out;
	}
	fd = -1;
	if (rename(tmp, path) != 0) {
		set_err(err, errlen, "重命名 %s 失败: %s", path, strerror(errno));
		goto out;
	}
	/* 目录 fsync：保证 rename 落盘 */
	dfd = open(dir, O_RDONLY);
	if (dfd >= 0) {
		(void)fsync(dfd);
		close(dfd);
		dfd = -1;
	}
	rc = 0;
out:
	if (fd >= 0)
		close(fd);
	if (rc != 0 && tmp)
		unlink(tmp);
	free(tmp);
	free(dir);
	return rc;
}

int aik_config_save_file(const char *path, const aik_json *cfg,
			 char *err, size_t errlen)
{
	aik_json *copy, *help;
	struct sbuf b = { 0 };
	size_t i;
	int rc = -1;

	if (err && errlen)
		err[0] = '\0';
	if (!path || !*path) {
		set_err(err, errlen, "配置路径为空");
		return -1;
	}
	if (!cfg || aik_json_typeof(cfg) != AIK_JSON_OBJ) {
		set_err(err, errlen, "配置必须是 JSON 对象");
		return -1;
	}
	copy = json_clone(cfg);
	if (!copy) {
		set_err(err, errlen, "内存不足");
		return -1;
	}
	if (aik_config_complete(copy) != 0) {
		set_err(err, errlen, "内存不足");
		goto out;
	}
	help = aik_json_new_obj();
	if (!help) {
		set_err(err, errlen, "内存不足");
		goto out;
	}
	for (i = 0; i < aik_config_item_count; i++) {
		aik_json *desc = aik_json_new_str(aik_config_items[i].desc);

		if (!desc || aik_json_obj_set(help, aik_config_items[i].path,
					      desc) != 0) {
			aik_json_free(desc);
			aik_json_free(help);
			set_err(err, errlen, "内存不足");
			goto out;
		}
	}
	if (aik_json_obj_set(copy, HELP_KEY, help) != 0) {
		aik_json_free(help);
		set_err(err, errlen, "内存不足");
		goto out;
	}
	if (pretty_value(&b, copy, 0) != 0 || !b.p) {
		set_err(err, errlen, "序列化失败");
		goto out;
	}
	rc = write_atomic(path, b.p, b.n, err, errlen);
out:
	free(b.p);
	aik_json_free(copy);
	return rc;
}

/* ------------------------------------------------------------------ */
/* 展示视图                                                           */
/* ------------------------------------------------------------------ */
aik_json *aik_config_display(const aik_json *cfg)
{
	aik_json *out;
	size_t i, n;

	if (!cfg || aik_json_typeof(cfg) != AIK_JSON_OBJ)
		return NULL;
	out = aik_json_new_obj();
	if (!out)
		return NULL;
	n = aik_json_count(cfg);
	for (i = 0; i < n; i++) {
		const char *key = aik_json_key_at(cfg, i);
		const aik_json *val = aik_json_val_at(cfg, i);
		aik_json *copy;

		if (!key)
			continue;
		if (val && aik_json_typeof(val) == AIK_JSON_OBJ) {
			size_t j, m = aik_json_count(val);

			copy = aik_json_new_obj();
			if (!copy)
				goto oom;
			for (j = 0; j < m; j++) {
				const aik_json *leaf = aik_json_val_at(val, j);
				const char *lkey = aik_json_key_at(val, j);
				aik_json *dup;

				if (!lkey || !leaf ||
				    aik_json_typeof(leaf) == AIK_JSON_NULL)
					continue;
				dup = json_clone(leaf);
				if (!dup || aik_json_obj_put(copy, lkey, dup) != 0) {
					aik_json_free(dup);
					aik_json_free(copy);
					goto oom;
				}
			}
		} else {
			copy = json_clone(val);
			if (!copy)
				goto oom;
		}
		if (aik_json_obj_put(out, key, copy) != 0) {
			aik_json_free(copy);
			goto oom;
		}
	}
	return out;
oom:
	aik_json_free(out);
	return NULL;
}

/* ------------------------------------------------------------------ */
/* Python == 语义                                                     */
/* ------------------------------------------------------------------ */
static int is_number_type(aik_json_type t)
{
	return t == AIK_JSON_BOOL || t == AIK_JSON_INT || t == AIK_JSON_NUM;
}

static double node_number(const aik_json *v)
{
	switch (aik_json_typeof(v)) {
	case AIK_JSON_BOOL:
		return aik_json_bool(v) ? 1.0 : 0.0;
	case AIK_JSON_INT:
		return (double)aik_json_int(v);
	case AIK_JSON_NUM:
		return aik_json_num(v);
	default:
		return 0.0;
	}
}

int aik_config_value_equal(const aik_json *a, const aik_json *b)
{
	aik_json_type ta = aik_json_typeof(a);
	aik_json_type tb = aik_json_typeof(b);
	size_t i, n;

	if (ta == AIK_JSON_NULL || tb == AIK_JSON_NULL)
		return ta == AIK_JSON_NULL && tb == AIK_JSON_NULL;
	/* True == 1 / False == 0 / 1 == 1.0 */
	if (is_number_type(ta) && is_number_type(tb))
		return node_number(a) == node_number(b);
	if (ta != tb)
		return 0;
	switch (ta) {
	case AIK_JSON_STR: {
		const char *sa = aik_json_str(a);
		const char *sb = aik_json_str(b);

		if (!sa || !sb)
			return sa == sb;
		return aik_json_strlen(a) == aik_json_strlen(b) &&
		       memcmp(sa, sb, aik_json_strlen(a)) == 0;
	}
	case AIK_JSON_ARR:
		n = aik_json_count(a);
		if (n != aik_json_count(b))
			return 0;
		for (i = 0; i < n; i++)
			if (!aik_config_value_equal(aik_json_at(a, i),
						    aik_json_at(b, i)))
				return 0;
		return 1;
	case AIK_JSON_OBJ:
		/* Python dict ==：键集合相同且逐键值相等（与顺序无关） */
		n = aik_json_count(a);
		if (n != aik_json_count(b))
			return 0;
		for (i = 0; i < n; i++) {
			const char *key = aik_json_key_at(a, i);
			const aik_json *other;

			if (!key)
				return 0;
			other = aik_json_get(b, key);
			if (!other ||
			    !aik_config_value_equal(aik_json_val_at(a, i),
						    other))
				return 0;
		}
		return 1;
	default:
		return 0;
	}
}

/* Python bool(value) */
static int py_truthy(const aik_json *v)
{
	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		return 0;
	case AIK_JSON_BOOL:
		return aik_json_bool(v);
	case AIK_JSON_INT:
		return aik_json_int(v) != 0;
	case AIK_JSON_NUM:
		return aik_json_num(v) != 0.0;
	case AIK_JSON_STR:
		return aik_json_strlen(v) != 0;
	case AIK_JSON_ARR:
	case AIK_JSON_OBJ:
		return aik_json_count(v) != 0;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* GET /config groups                                                 */
/* ------------------------------------------------------------------ */
static int path_ends_with(const char *s, const char *suffix)
{
	size_t a = strlen(s), b = strlen(suffix);

	return a >= b && memcmp(s + a - b, suffix, b) == 0;
}

static aik_json *payload_choices(const aik_config_item *it)
{
	aik_json *arr = aik_json_new_arr();
	size_t i;

	if (!arr)
		return NULL;
	if (it->kind != AIK_CFG_KIND_ENUM)
		return arr;
	for (i = 0; i < it->n_choices; i++) {
		aik_json *s = aik_json_new_str(it->choices[i]);

		if (!s || aik_json_arr_push(arr, s) != 0) {
			aik_json_free(s);
			aik_json_free(arr);
			return NULL;
		}
	}
	return arr;
}

/* minimum / maximum：JSON 字面量原样解析（NULL 字面量 -> null 节点） */
static aik_json *payload_bound(const char *lit)
{
	if (!lit)
		return aik_json_new_null();
	return aik_json_parse(lit, strlen(lit), NULL, 0);
}

/* ConfigItem.kind 的字符串形态（payload 的 "type"） */
static const char *kind_name(aik_config_kind kind)
{
	switch (kind) {
	case AIK_CFG_KIND_STR:
		return "str";
	case AIK_CFG_KIND_INT:
		return "int";
	case AIK_CFG_KIND_FLOAT:
		return "float";
	case AIK_CFG_KIND_BOOL:
		return "bool";
	case AIK_CFG_KIND_ENUM:
		return "enum";
	case AIK_CFG_KIND_INTERVAL:
		return "interval";
	}
	return "str";
}

static aik_json *item_payload(const aik_config_item *it,
			      const aik_json *cfg)
{
	aik_json *def;
	const aik_json *value;
	aik_json *arr, *payload;
	int modified, masked = 0, secret = 0;

	def = aik_config_item_default(it);
	if (!def)
		return NULL;
	value = aik_config_item_get(cfg, it);
	if (!value)
		value = def;
	modified = !aik_config_value_equal(value, def);
	/* 密钥类配置只下发掩码（空值照常下发空串） */
	secret = path_ends_with(it->path, "api_key");
	if (secret)
		masked = py_truthy(value);

	payload = aik_json_new_obj();
	arr = payload_choices(it);
	if (!payload || !arr)
		goto oom;
	if (aik_json_obj_put(payload, "path", aik_json_new_str(it->path)) != 0)
		goto oom;
	if (aik_json_obj_put(payload, "name", aik_json_new_str(it->name)) != 0)
		goto oom;
	if (masked) {
		if (aik_json_obj_put(payload, "value",
				     aik_json_new_str("******")) != 0)
			goto oom;
	} else if (aik_json_obj_put(payload, "value", json_clone(value)) != 0) {
		goto oom;
	}
	if (aik_json_obj_put(payload, "default", json_clone(def)) != 0)
		goto oom;
	if (aik_json_obj_put(payload, "help",
			     aik_json_new_str(it->desc)) != 0)
		goto oom;
	if (aik_json_obj_put(payload, "type",
			     aik_json_new_str(kind_name(it->kind))) != 0)
		goto oom;
	if (aik_json_obj_put(payload, "choices", arr) != 0)
		goto oom;
	arr = NULL;
	if (aik_json_obj_put(payload, "minimum",
			     payload_bound(it->minimum)) != 0)
		goto oom;
	if (aik_json_obj_put(payload, "maximum",
			     payload_bound(it->maximum)) != 0)
		goto oom;
	if (aik_json_obj_put(payload, "modified",
			     aik_json_new_bool(modified)) != 0)
		goto oom;
	if (secret && aik_json_obj_put(payload, "set",
				       aik_json_new_bool(masked)) != 0)
		goto oom;
	aik_json_free(def);
	return payload;
oom:
	aik_json_free(arr);
	aik_json_free(payload);
	aik_json_free(def);
	return NULL;
}

aik_json *aik_config_groups_build(const aik_json *display_cfg)
{
	aik_json *out = aik_json_new_arr();
	size_t gi;

	if (!out)
		return NULL;
	for (gi = 0; gi < aik_config_group_count; gi++) {
		const aik_config_group *g = &aik_config_groups[gi];
		aik_json *items = aik_json_new_arr();
		aik_json *group;
		size_t i, count = 0;

		if (!items)
			goto oom;
		for (i = 0; i < aik_config_item_count; i++) {
			const aik_config_item *it = &aik_config_items[i];
			aik_json *payload;

			if (!it->group || strcmp(it->group, g->key) != 0)
				continue;
			payload = item_payload(it, display_cfg);
			if (!payload || aik_json_arr_push(items, payload) != 0) {
				aik_json_free(payload);
				aik_json_free(items);
				goto oom;
			}
			count++;
		}
		if (count == 0) {	/* 空分组不下发 */
			aik_json_free(items);
			continue;
		}
		group = aik_json_new_obj();
		if (!group ||
		    aik_json_obj_put(group, "key", aik_json_new_str(g->key)) != 0 ||
		    aik_json_obj_put(group, "name",
				     aik_json_new_str(g->name)) != 0 ||
		    aik_json_obj_put(group, "description",
				     aik_json_new_str(g->description)) != 0 ||
		    aik_json_obj_put(group, "items", items) != 0) {
			aik_json_free(group);
			aik_json_free(items);
			goto oom;
		}
		if (aik_json_arr_push(out, group) != 0) {
			aik_json_free(group);
			goto oom;
		}
	}
	return out;
oom:
	aik_json_free(out);
	return NULL;
}

aik_json *aik_config_presets_build(void)
{
	aik_json *out = aik_json_new_arr();
	size_t i;

	if (!out)
		return NULL;
	for (i = 0; i < aik_config_preset_count; i++) {
		const aik_config_preset *p = &aik_config_presets[i];
		aik_json *obj = aik_json_new_obj();

		if (!obj ||
		    aik_json_obj_put(obj, "key",
				     aik_json_new_str(p->key)) != 0 ||
		    aik_json_obj_put(obj, "name",
				     aik_json_new_str(p->name)) != 0 ||
		    aik_json_obj_put(obj, "description",
				     aik_json_new_str(p->desc)) != 0 ||
		    aik_json_obj_put(obj, "count",
				     aik_json_new_int((long long)p->n_values)) != 0 ||
		    aik_json_arr_push(out, obj) != 0) {
			aik_json_free(obj);
			aik_json_free(out);
			return NULL;
		}
	}
	return out;
}

/* ------------------------------------------------------------------ */
/* validate_config                                                    */
/* ------------------------------------------------------------------ */
static int is_blank_value(const aik_json *v)
{
	const char *s;
	char *stripped;
	int blank;

	if (!v || aik_json_typeof(v) == AIK_JSON_NULL)
		return 1;
	if (aik_json_typeof(v) != AIK_JSON_STR)
		return 0;
	s = aik_json_str(v);
	if (!s)
		return 1;
	stripped = py_strip(s);
	if (!stripped)
		return 1;
	blank = stripped[0] == '\0';
	free(stripped);
	return blank;
}

/* Python repr(v)：字符串单引号（必要时双引号）、True/False/None、数字 */
static int sb_repr_str(struct sbuf *b, const char *s, size_t n)
{
	char quote = '\'';
	size_t i;
	int has_sq = 0, has_dq = 0;

	for (i = 0; i < n; i++) {
		if (s[i] == '\'')
			has_sq = 1;
		else if (s[i] == '"')
			has_dq = 1;
	}
	/* CPython 的 PyUnicode_Repr：含单引号且不含双引号时改用双引号 */
	if (has_sq && !has_dq)
		quote = '"';
	if (sb_chr(b, quote) != 0)
		return -1;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];

		switch (c) {
		case '\\':
			if (sb_mem(b, "\\\\", 2) != 0)
				return -1;
			break;
		case '\t':
			if (sb_mem(b, "\\t", 2) != 0)
				return -1;
			break;
		case '\n':
			if (sb_mem(b, "\\n", 2) != 0)
				return -1;
			break;
		case '\r':
			if (sb_mem(b, "\\r", 2) != 0)
				return -1;
			break;
		default:
			if (c == (unsigned char)quote) {
				if (sb_chr(b, '\\') != 0 ||
				    sb_chr(b, (char)c) != 0)
					return -1;
			} else if (c < 0x20 || c == 0x7F) {
				char esc[5];

				esc[0] = '\\';
				esc[1] = 'x';
				esc[2] = HEXD[c >> 4];
				esc[3] = HEXD[c & 0x0F];
				esc[4] = '\0';
				if (sb_mem(b, esc, 4) != 0)
					return -1;
			} else if (sb_chr(b, (char)c) != 0) {
				return -1;
			}
			break;
		}
	}
	return sb_chr(b, quote);
}

static int sb_repr(struct sbuf *b, const aik_json *v)
{
	size_t i, n;

	if (!v)
		return sb_str(b, "None");
	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		return sb_str(b, "None");
	case AIK_JSON_BOOL:
		return sb_str(b, aik_json_bool(v) ? "True" : "False");
	case AIK_JSON_INT:
		return sb_i64(b, aik_json_int(v));
	case AIK_JSON_NUM: {
		char tmp[64];
		int len = aik_json_dtoa(aik_json_num(v), tmp, sizeof(tmp));

		if (len < 0)
			return -1;
		return sb_mem(b, tmp, (size_t)len);
	}
	case AIK_JSON_STR:
		return sb_repr_str(b, aik_json_str(v), aik_json_strlen(v));
	case AIK_JSON_ARR:
		n = aik_json_count(v);
		if (sb_chr(b, '[') != 0)
			return -1;
		for (i = 0; i < n; i++) {
			if (i && sb_str(b, ", ") != 0)
				return -1;
			if (sb_repr(b, aik_json_at(v, i)) != 0)
				return -1;
		}
		return sb_chr(b, ']');
	case AIK_JSON_OBJ:
		n = aik_json_count(v);
		if (sb_chr(b, '{') != 0)
			return -1;
		for (i = 0; i < n; i++) {
			const char *key = aik_json_key_at(v, i);

			if (i && sb_str(b, ", ") != 0)
				return -1;
			if (sb_repr_str(b, key, key ? strlen(key) : 0) != 0 ||
			    sb_str(b, ": ") != 0 ||
			    sb_repr(b, aik_json_val_at(v, i)) != 0)
				return -1;
		}
		return sb_chr(b, '}');
	}
	return -1;
}

/* 取值（缺失时回退 item.default，与 get_value 同） */
static const aik_json *value_or_default(const aik_json *cfg,
					const aik_config_item *it,
					aik_json **owned)
{
	const aik_json *v = aik_config_item_get(cfg, it);

	*owned = NULL;
	if (v)
		return v;
	*owned = aik_config_item_default(it);
	return *owned;
}

static const char *LLM_DEFAULT_BASE_URL = "https://api.openai.com/v1";

static int append_required_warnings(aik_json *arr, const aik_json *cfg)
{
	const aik_config_item *base_item = aik_config_item_find("llm.base_url");
	const aik_config_item *key_item = aik_config_item_find("llm.api_key");
	const aik_config_item *model_item = aik_config_item_find("llm.model");
	const aik_config_item *emb_base =
		aik_config_item_find("embedding.base_url");
	const aik_config_item *emb_key =
		aik_config_item_find("embedding.api_key");
	aik_json *owned = NULL;
	const aik_json *v;
	int llm_configured = 0;

	if (!base_item || !key_item || !model_item || !emb_base || !emb_key)
		return 0;
	v = value_or_default(cfg, base_item, &owned);
	if (!is_blank_value(v)) {
		const char *base = aik_json_typeof(v) == AIK_JSON_STR
					   ? aik_json_str(v) : NULL;
		aik_json *owned_key = NULL;
		const aik_json *key = value_or_default(cfg, key_item,
						       &owned_key);

		if (!(base && strcmp(base, LLM_DEFAULT_BASE_URL) == 0 &&
		      is_blank_value(key)))
			llm_configured = 1;
		aik_json_free(owned_key);
	}
	aik_json_free(owned);
	owned = NULL;

	if (llm_configured) {
		const aik_config_item *targets[2] = { model_item, key_item };
		size_t i;

		for (i = 0; i < 2; i++) {
			aik_json *own = NULL;
			const aik_json *cur = value_or_default(cfg, targets[i],
							       &own);
			struct sbuf b = { 0 };

			if (is_blank_value(cur)) {
				sb_str(&b, "[");
				sb_str(&b, targets[i]->path);
				sb_str(&b, "]：LLM 已配置（llm.base_url）时 ");
				sb_str(&b, targets[i]->name);
				sb_str(&b, " 必填");
				if (!b.p || aik_json_arr_push(
						    arr, aik_json_new_str(b.p)) != 0) {
					free(b.p);
					aik_json_free(own);
					return -1;
				}
			}
			free(b.p);
			aik_json_free(own);
		}
	}
	{
		aik_json *own = NULL;
		const aik_json *cur = value_or_default(cfg, emb_base, &own);
		int emb_configured = !is_blank_value(cur);

		aik_json_free(own);
		own = NULL;
		if (emb_configured) {
			const aik_json *key = value_or_default(cfg, emb_key,
							       &own);

			if (is_blank_value(key)) {
				struct sbuf b = { 0 };

				sb_str(&b, "[");
				sb_str(&b, emb_key->path);
				sb_str(&b, "]：已配置 embedding.base_url 时 ");
				sb_str(&b, emb_key->name);
				sb_str(&b, " 必填");
				if (!b.p || aik_json_arr_push(
						    arr, aik_json_new_str(b.p)) != 0) {
					free(b.p);
					aik_json_free(own);
					return -1;
				}
				free(b.p);
			}
			aik_json_free(own);
		}
	}
	return 0;
}

aik_json *aik_config_validate_all(const aik_json *cfg, char *err,
				  size_t errlen)
{
	aik_json *arr = aik_json_new_arr();
	size_t i;

	if (err && errlen)
		err[0] = '\0';
	if (!arr) {
		set_err(err, errlen, "内存不足");
		return NULL;
	}
	for (i = 0; i < aik_config_item_count; i++) {
		const aik_config_item *it = &aik_config_items[i];
		const aik_json *v;
		struct sbuf b = { 0 };
		char reason[256];
		int rc;

		if (!aik_config_item_has(cfg, it))
			continue;
		v = aik_config_item_get(cfg, it);
		reason[0] = '\0';
		rc = aik_config_item_validate(it, v, reason, sizeof(reason));
		if (rc == -2 || (rc != 0 && reason[0] == '\0')) {
			free(b.p);
			aik_json_free(arr);
			set_err(err, errlen, "内存不足");
			return NULL;
		}
		if (rc == 0)
			continue;
		sb_str(&b, "[");
		sb_str(&b, it->path);
		sb_str(&b, "] = ");
		if (sb_repr(&b, v) != 0)
			goto oom;
		sb_str(&b, "：");
		sb_str(&b, reason);
		{
			aik_json *line = aik_json_new_str(b.p ? b.p : "");

			if (!line || aik_json_arr_push(arr, line) != 0) {
				aik_json_free(line);
				goto oom;
			}
		}
		free(b.p);
	}
	if (append_required_warnings(arr, cfg) != 0)
		goto oom;
	return arr;
oom:
	aik_json_free(arr);
	set_err(err, errlen, "内存不足");
	return NULL;
}
