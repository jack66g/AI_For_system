// SPDX-License-Identifier: GPL-2.0
/*
 * dtjson.c - JSON 三模式序列化 + DOM 构造工具。
 *
 * dump_default = json.dumps(v, ensure_ascii=False)(默认分隔符 ", " / ": ")
 * dump_indent2 = json.dumps(v, ensure_ascii=False, indent=2)(无尾换行)
 * 转义/浮点语义对齐 aik_json_dump(ensure_ascii=False、aik_json_dtoa)。
 */
#define _POSIX_C_SOURCE 200809L

#include "desktop/dtjson.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "desktop/dtcore.h"

/* ---------------------------------------------------------------- sbuf 复用
 * (dtcore 的 dt_sbuf 对外不可见构造细节,这里自带一套等价小缓冲) */

struct jsb {
	char *p;
	size_t n;
	size_t cap;
	int bad;
};

static void jsb_init(struct jsb *b)
{
	memset(b, 0, sizeof(*b));
}

static int jsb_grow(struct jsb *b, size_t need)
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

static void jsb_putc(struct jsb *b, char c)
{
	if (jsb_grow(b, 1) == 0)
		b->p[b->n++] = c;
}

static void jsb_puts(struct jsb *b, const char *s, size_t n)
{
	if (jsb_grow(b, n) == 0) {
		memcpy(b->p + b->n, s, n);
		b->n += n;
	}
}

static void jsb_pad(struct jsb *b, int depth)
{
	for (int i = 0; i < depth * 2; i++)
		jsb_putc(b, ' ');
}

static char *jsb_finish(struct jsb *b)
{
	if (b->bad || jsb_grow(b, 1) != 0) {
		free(b->p);
		return NULL;
	}
	b->p[b->n] = '\0';
	return b->p;
}

static const char HEXD[] = "0123456789abcdef";

/* ensure_ascii=False 转义(与 store_json dump 同规则) */
static void put_str(struct jsb *b, const char *s, size_t n)
{
	jsb_putc(b, '"');
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];

		switch (c) {
		case '"':
			jsb_puts(b, "\\\"", 2);
			break;
		case '\\':
			jsb_puts(b, "\\\\", 2);
			break;
		case '\b':
			jsb_puts(b, "\\b", 2);
			break;
		case '\f':
			jsb_puts(b, "\\f", 2);
			break;
		case '\n':
			jsb_puts(b, "\\n", 2);
			break;
		case '\r':
			jsb_puts(b, "\\r", 2);
			break;
		case '\t':
			jsb_puts(b, "\\t", 2);
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
				jsb_puts(b, esc, 6);
			} else {
				jsb_putc(b, (char)c);
			}
			break;
		}
	}
	jsb_putc(b, '"');
}

static void put_num(struct jsb *b, const aik_json *v)
{
	char tmp[40];

	switch (aik_json_typeof(v)) {
	case AIK_JSON_INT:
		snprintf(tmp, sizeof(tmp), "%lld", aik_json_int(v));
		jsb_puts(b, tmp, strlen(tmp));
		break;
	case AIK_JSON_NUM: {
		int n = aik_json_dtoa(aik_json_num(v), tmp, sizeof(tmp));

		if (n < 0) {
			b->bad = 1;
			break;
		}
		jsb_puts(b, tmp, (size_t)n);
		break;
	}
	default:
		b->bad = 1;
		break;
	}
}

/*
 * dump_value 两种形态:
 *   indent=0 → json.dumps(v, ensure_ascii=False)      (", " / ": ")
 *   indent>0 → json.dumps(v, ensure_ascii=False, indent=2)("," 换行缩进)
 */
static void dump_value(struct jsb *b, const aik_json *v, int indent, int depth)
{
	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		jsb_puts(b, "null", 4);
		break;
	case AIK_JSON_BOOL:
		if (aik_json_bool(v))
			jsb_puts(b, "true", 4);
		else
			jsb_puts(b, "false", 5);
		break;
	case AIK_JSON_INT:
	case AIK_JSON_NUM:
		put_num(b, v);
		break;
	case AIK_JSON_STR:
		put_str(b, aik_json_str(v), aik_json_strlen(v));
		break;
	case AIK_JSON_ARR: {
		size_t n = aik_json_count(v);

		if (n == 0) {
			jsb_puts(b, "[]", 2);
			break;
		}
		jsb_putc(b, '[');
		for (size_t i = 0; i < n; i++) {
			if (i) {
				jsb_putc(b, ',');
				if (indent == 0)
					jsb_putc(b, ' ');
			}
			if (indent > 0) {
				jsb_putc(b, '\n');
				jsb_pad(b, depth + 1);
			}
			dump_value(b, aik_json_at(v, i), indent, depth + 1);
		}
		if (indent > 0) {
			jsb_putc(b, '\n');
			jsb_pad(b, depth);
		}
		jsb_putc(b, ']');
		break;
	}
	case AIK_JSON_OBJ: {
		size_t n = aik_json_count(v);

		if (n == 0) {
			jsb_puts(b, "{}", 2);
			break;
		}
		jsb_putc(b, '{');
		for (size_t i = 0; i < n; i++) {
			const char *k = aik_json_key_at(v, i);

			if (i) {
				jsb_putc(b, ',');
				if (indent == 0)
					jsb_putc(b, ' ');
			}
			if (indent > 0) {
				jsb_putc(b, '\n');
				jsb_pad(b, depth + 1);
			}
			put_str(b, k, strlen(k));
			jsb_puts(b, ": ", 2);
			dump_value(b, aik_json_val_at(v, i), indent,
				   depth + 1);
		}
		if (indent > 0) {
			jsb_putc(b, '\n');
			jsb_pad(b, depth);
		}
		jsb_putc(b, '}');
		break;
	}
	}
}

char *dt_json_dump_default(const aik_json *v)
{
	struct jsb b;

	jsb_init(&b);
	dump_value(&b, v, 0, 0);
	return jsb_finish(&b);
}

char *dt_json_dump_indent2(const aik_json *v)
{
	struct jsb b;

	jsb_init(&b);
	dump_value(&b, v, 2, 0);
	return jsb_finish(&b);
}

/* ---------------------------------------------------------------- 构造 */

aik_json *dt_new_str(const char *s)
{
	if (!s)
		return aik_json_new_null();
	return aik_json_new_str(s);
}

aik_json *dt_new_strn(const char *s, size_t n)
{
	if (!s)
		return aik_json_new_null();
	/* aik_json_new_str 只吃 NUL 结尾串;此处自拷贝 */
	char *tmp = malloc(n + 1);
	aik_json *v;

	if (!tmp)
		return NULL;
	memcpy(tmp, s, n);
	tmp[n] = '\0';
	v = aik_json_new_str(tmp);
	free(tmp);
	return v;
}

aik_json *dt_new_int(long long i)
{
	return aik_json_new_int(i);
}

aik_json *dt_new_num(double d)
{
	return aik_json_new_num(d);
}

aik_json *dt_new_bool(int b)
{
	return aik_json_new_bool(b);
}

aik_json *dt_new_null(void)
{
	return aik_json_new_null();
}

aik_json *dt_new_arr(void)
{
	return aik_json_new_arr();
}

aik_json *dt_new_obj(void)
{
	return aik_json_new_obj();
}

aik_json *dt_copy(const aik_json *v)
{
	switch (aik_json_typeof(v)) {
	case AIK_JSON_ARR: {
		aik_json *a = aik_json_new_arr();
		size_t n = aik_json_count(v);

		if (!a)
			return NULL;
		for (size_t i = 0; i < n; i++) {
			aik_json *c = dt_copy(aik_json_at(v, i));

			if (!c || aik_json_arr_push(a, c) != 0) {
				aik_json_free(c);
				aik_json_free(a);
				return NULL;
			}
		}
		return a;
	}
	case AIK_JSON_OBJ: {
		aik_json *o = aik_json_new_obj();
		size_t n = aik_json_count(v);

		if (!o)
			return NULL;
		for (size_t i = 0; i < n; i++) {
			aik_json *c = dt_copy(aik_json_val_at(v, i));

			if (!c || aik_json_obj_put(o, aik_json_key_at(v, i),
						   c) != 0) {
				aik_json_free(c);
				aik_json_free(o);
				return NULL;
			}
		}
		return o;
	}
	default:
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
		default:
			return NULL;
		}
	}
}

int dt_put_str(aik_json *o, const char *k, const char *v)
{
	aik_json *n = dt_new_str(v);

	if (!n)
		return -1;
	return aik_json_obj_put(o, k, n);
}

int dt_put_int(aik_json *o, const char *k, long long v)
{
	aik_json *n = aik_json_new_int(v);

	if (!n)
		return -1;
	return aik_json_obj_put(o, k, n);
}

int dt_put_bool(aik_json *o, const char *k, int v)
{
	aik_json *n = aik_json_new_bool(v);

	if (!n)
		return -1;
	return aik_json_obj_put(o, k, n);
}

int dt_put_null(aik_json *o, const char *k)
{
	aik_json *n = aik_json_new_null();

	if (!n)
		return -1;
	return aik_json_obj_put(o, k, n);
}

int dt_put_num(aik_json *o, const char *k, double v)
{
	aik_json *n = aik_json_new_num(v);

	if (!n)
		return -1;
	return aik_json_obj_put(o, k, n);
}

int dt_put_copy(aik_json *o, const char *k, const aik_json *v)
{
	aik_json *c = dt_copy(v);

	if (!c)
		return -1;
	return aik_json_obj_put(o, k, c);
}

int dt_arr_push_str(aik_json *a, const char *v)
{
	aik_json *n = dt_new_str(v);

	if (!n)
		return -1;
	return aik_json_arr_push(a, n);
}

int dt_arr_push_int(aik_json *a, long long v)
{
	aik_json *n = aik_json_new_int(v);

	if (!n)
		return -1;
	return aik_json_arr_push(a, n);
}

int dt_arr_push_copy(aik_json *a, const aik_json *v)
{
	aik_json *c = dt_copy(v);

	if (!c)
		return -1;
	return aik_json_arr_push(a, c);
}

const aik_json *dt_get(const aik_json *o, const char *k)
{
	return aik_json_get(o, k);
}

aik_json *dt_get_mut(aik_json *o, const char *k)
{
	return (aik_json *)(uintptr_t)aik_json_get(o, k);
}

aik_json *dt_obj_setdefault(aik_json *o, const char *k, aik_json *v)
{
	const aik_json *cur = aik_json_get(o, k);

	if (cur) {
		aik_json_free(v);
		return (aik_json *)(uintptr_t)cur;
	}
	if (aik_json_obj_put(o, k, v) != 0) {
		aik_json_free(v);
		return NULL;
	}
	return v;
}

aik_json *dt_obj_setdefault_str(aik_json *o, const char *k, const char *v)
{
	aik_json *n = dt_new_str(v);

	if (!n)
		return NULL;
	return dt_obj_setdefault(o, k, n);
}

aik_json *dt_obj_setdefault_int(aik_json *o, const char *k, long long v)
{
	aik_json *n = aik_json_new_int(v);

	if (!n)
		return NULL;
	return dt_obj_setdefault(o, k, n);
}

aik_json *dt_read_json(const char *path)
{
	size_t len = 0;
	char *buf = dt_read_file(path, &len);
	aik_json *v;

	if (!buf)
		return NULL;
	v = aik_json_parse(buf, len, NULL, 0);
	free(buf);
	return v;
}

static int write_atomic(const char *path, const char *text, size_t n)
{
	char tmp[DT_PATH_MAX];
	FILE *fh;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
		return -1;
	fh = fopen(tmp, "wb");
	if (!fh)
		return -1;
	if (n && fwrite(text, 1, n, fh) != n) {
		fclose(fh);
		return -1;
	}
	if (fclose(fh) != 0)
		return -1;
	chmod(tmp, 0600); /* 先 fchmod 再 rename(write_state_json 语义) */
	if (rename(tmp, path) != 0)
		return -1;
	return 0;
}

int dt_write_json_indent2_atomic(const char *path, const aik_json *v)
{
	char *text = dt_json_dump_indent2(v);
	int rc;

	if (!text)
		return -1;
	rc = write_atomic(path, text, strlen(text));
	free(text);
	return rc;
}

int dt_write_json_default_atomic(const char *path, const aik_json *v)
{
	char *text = dt_json_dump_default(v);
	int rc;

	if (!text)
		return -1;
	rc = write_atomic(path, text, strlen(text));
	free(text);
	return rc;
}

aik_json *dt_parse(const char *buf, size_t len)
{
	return aik_json_parse(buf, len, NULL, 0);
}
