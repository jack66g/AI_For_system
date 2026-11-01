/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_store_json.c - store_json 自测（T2a 门禁）
 *
 * 覆盖：
 *   1) 内置 fixture：嵌套容器 / 全部转义 / 代理对 / 重复键 / int64 边界；
 *   2) 非法输入必须失败且 err 带 offset（截断、尾随垃圾、坏转义、未闭合、
 *      前导零、缺分隔符等），并保证不部分成功；
 *   3) dtoa 向量表（$AIK_STORE_VECTORS/dtoa.vectors.tsv，默认
 *      $HOME/aikernel-longterm/parity/vectors/storage）逐行 0 失配；
 *      另在 setlocale(LC_ALL, "") 之后再跑一遍，证明 locale 无关；
 *   4) snapshot.canonical.json（6.9 MB）parse → dump 逐字节相等；
 *      失败打印首个差异 offset / 行号 / 前后 40 字节。
 *
 * 输出末行统一为 "SUMMARY checked=... mismatch=... bytes=..."，有失配
 * 时退出码非 0。AIK_TEST_LOCALE_OFF=1 可跳过 locale 复跑。
 */
#define _GNU_SOURCE 1

#include "store/store_json.h"

#include <locale.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checked;
static int g_mismatch;
static size_t g_bytes;

/* ------------------------------------------------------------------ */
/* 诊断                                                                */
/* ------------------------------------------------------------------ */

static void report_plain(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "FAIL: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

static void report_mismatch(const char *fmt, ...)
{
	va_list ap;

	g_mismatch++;
	va_start(ap, fmt);
	fprintf(stderr, "FAIL: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

#define CHECK(cond) do {						\
	g_checked++;							\
	if (!(cond))							\
		report_mismatch("%s:%d: CHECK(%s)", __FILE__, __LINE__,	\
				#cond);					\
} while (0)

/* ------------------------------------------------------------------ */
/* 文件与路径                                                          */
/* ------------------------------------------------------------------ */

static const char *vectors_dir(void)
{
	const char *d = getenv("AIK_STORE_VECTORS");
	static char buf[8192];

	if (d && *d)
		return d;
	(void)snprintf(buf, sizeof(buf), "%s/aikernel-longterm/parity/vectors/storage",
		       getenv("HOME") ? getenv("HOME") : ".");
	return buf;
}

static char *vpath_alloc(const char *name)
{
	const char *dir = vectors_dir();
	size_t dl = strlen(dir), nl = strlen(name);
	char *p = malloc(dl + 1 + nl + 1);

	if (!p)
		return NULL;
	memcpy(p, dir, dl);
	p[dl] = '/';
	memcpy(p + dl + 1, name, nl + 1);
	return p;
}

static char *read_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	long sz;
	char *buf;

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return NULL;
	}
	sz = ftell(f);
	if (sz < 0) {
		fclose(f);
		return NULL;
	}
	rewind(f);
	buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf);
		fclose(f);
		return NULL;
	}
	buf[sz] = '\0';
	*len = (size_t)sz;
	fclose(f);
	return buf;
}

static void print_rss(void)
{
	FILE *f = fopen("/proc/self/status", "r");
	char line[256];
	unsigned long cur = 0, peak = 0;

	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "VmRSS:", 6) == 0)
			cur = strtoul(line + 6, NULL, 10);
		else if (strncmp(line, "VmHWM:", 6) == 0)
			peak = strtoul(line + 6, NULL, 10);
	}
	fclose(f);
	printf("RSS: current=%lu kB peak=%lu kB\n", cur, peak);
}

/* ------------------------------------------------------------------ */
/* fixture                                                             */
/* ------------------------------------------------------------------ */

static aik_json *parse_ok(const char *src, int line)
{
	char err[256];
	aik_json *v;

	g_checked++;
	err[0] = '\0';
	v = aik_json_parse(src, strlen(src), err, sizeof(err));
	if (!v)
		report_mismatch("line %d: parse failed: %s", line, err);
	return v;
}

static int dump_eq(const aik_json *v, const char *expect, int line)
{
	char *out = NULL;
	size_t n = 0;
	int ok = 1;

	if (aik_json_dump(v, &out, &n) != 0) {
		report_mismatch("line %d: dump failed", line);
		return 0;
	}
	if (n != strlen(expect) || memcmp(out, expect, n) != 0) {
		report_mismatch("line %d: dump mismatch\n  got: %.*s\n  exp: %s",
				line, (int)n, out, expect);
		ok = 0;
	}
	free(out);
	return ok;
}

static void test_nested(void)
{
	/* 注意 "-0" 词法无 '.'/'e' → INT，dump 为 "0"（与 Python 一致） */
	const char *src =
		"{\"a\":[1,2.5,true,false,null,\"x\"],\"b\":{\"c\":-0}}";
	const char *canon =
		"{\"a\":[1,2.5,true,false,null,\"x\"],\"b\":{\"c\":0}}";
	aik_json *v = parse_ok(src, __LINE__);
	const aik_json *a, *b, *c;

	if (!v)
		return;
	CHECK(aik_json_typeof(v) == AIK_JSON_OBJ);
	CHECK(aik_json_count(v) == 2);
	CHECK(strcmp(aik_json_key_at(v, 0), "a") == 0);
	CHECK(strcmp(aik_json_key_at(v, 1), "b") == 0);
	a = aik_json_get(v, "a");
	CHECK(a != NULL && aik_json_typeof(a) == AIK_JSON_ARR);
	if (a) {
		CHECK(aik_json_count(a) == 6);
		CHECK(aik_json_typeof(aik_json_at(a, 0)) == AIK_JSON_INT);
		CHECK(aik_json_int(aik_json_at(a, 0)) == 1);
		CHECK(aik_json_num(aik_json_at(a, 0)) == 1.0);
		CHECK(aik_json_typeof(aik_json_at(a, 1)) == AIK_JSON_NUM);
		CHECK(aik_json_num(aik_json_at(a, 1)) == 2.5);
		CHECK(aik_json_typeof(aik_json_at(a, 2)) == AIK_JSON_BOOL);
		CHECK(aik_json_bool(aik_json_at(a, 2)) == 1);
		CHECK(aik_json_bool(aik_json_at(a, 3)) == 0);
		CHECK(aik_json_typeof(aik_json_at(a, 4)) == AIK_JSON_NULL);
		CHECK(strcmp(aik_json_str(aik_json_at(a, 5)), "x") == 0);
		CHECK(aik_json_strlen(aik_json_at(a, 5)) == 1);
		CHECK(aik_json_at(a, 6) == NULL);
	}
	b = aik_json_get(v, "b");
	CHECK(b != NULL && aik_json_typeof(b) == AIK_JSON_OBJ);
	c = b ? aik_json_get(b, "c") : NULL;
	CHECK(c != NULL && aik_json_typeof(c) == AIK_JSON_INT);
	CHECK(aik_json_int(c) == 0);
	CHECK(aik_json_get(v, "zzz") == NULL);
	CHECK(aik_json_at(v, 0) == NULL);	/* OBJ 不能当 ARR 用 */
	dump_eq(v, canon, __LINE__);
	aik_json_free(v);
}

static void test_escapes(void)
{
	/* 每个数组元素只测一种转义；最后一个是 \u 全家桶 */
	const char *src =
		"[\"\\\"\",\"\\\\\",\"\\/\",\"\\b\",\"\\f\",\"\\n\",\"\\r\","
		"\"\\t\",\"\\u0041\\u00e9\\u4e2d\\ud83d\\ude00\\u0001\"]";
	const char *expect =
		"[\"\\\"\",\"\\\\\",\"/\",\"\\b\",\"\\f\",\"\\n\",\"\\r\","
		"\"\\t\",\"A\xc3\xa9\xe4\xb8\xad\xf0\x9f\x98\x80\\u0001\"]";
	static const char *plain[] = { "\"", "\\", "/", "\b", "\f", "\n",
				       "\r", "\t" };
	aik_json *v = parse_ok(src, __LINE__);
	const aik_json *e;
	size_t i;

	if (!v)
		return;
	CHECK(aik_json_count(v) == 9);
	for (i = 0; i < 8; i++) {
		e = aik_json_at(v, i);
		CHECK(e != NULL && aik_json_typeof(e) == AIK_JSON_STR);
		if (!e)
			continue;
		CHECK(aik_json_strlen(e) == 1);
		CHECK(strcmp(aik_json_str(e), plain[i]) == 0);
	}
	e = aik_json_at(v, 8);
	if (e) {
		/* A + é(2) + 中(3) + 😀(4) + \x01 */
		static const char want[] = "A\xc3\xa9\xe4\xb8\xad\xf0\x9f\x98\x80\x01";
		CHECK(aik_json_strlen(e) == sizeof(want) - 1);
		CHECK(aik_json_strlen(e) == 11);
		CHECK(memcmp(aik_json_str(e), want, sizeof(want) - 1) == 0);
	}
	dump_eq(v, expect, __LINE__);
	aik_json_free(v);
}

static void test_dup_keys(void)
{
	const char *src = "{\"a\":1,\"b\":2,\"a\":3}";
	aik_json *v = parse_ok(src, __LINE__);
	aik_json *o;

	if (v) {
		CHECK(aik_json_count(v) == 2);
		CHECK(strcmp(aik_json_key_at(v, 0), "a") == 0);
		CHECK(strcmp(aik_json_key_at(v, 1), "b") == 0);
		CHECK(aik_json_int(aik_json_get(v, "a")) == 3);
		CHECK(aik_json_typeof(aik_json_val_at(v, 0)) == AIK_JSON_INT);
		dump_eq(v, "{\"a\":3,\"b\":2}", __LINE__);
		aik_json_free(v);
	}
	/* 构造 API：put 允许重复键，set 替换且保持首次位置 */
	o = aik_json_new_obj();
	CHECK(o != NULL);
	if (!o)
		return;
	CHECK(aik_json_obj_put(o, "a", aik_json_new_int(1)) == 0);
	CHECK(aik_json_obj_put(o, "b", aik_json_new_int(2)) == 0);
	CHECK(aik_json_obj_set(o, "a", aik_json_new_int(9)) == 0);
	CHECK(aik_json_count(o) == 2);
	CHECK(strcmp(aik_json_key_at(o, 0), "a") == 0);
	CHECK(strcmp(aik_json_key_at(o, 1), "b") == 0);
	CHECK(aik_json_int(aik_json_get(o, "a")) == 9);
	dump_eq(o, "{\"a\":9,\"b\":2}", __LINE__);
	CHECK(aik_json_obj_put(o, "a", aik_json_new_int(7)) == 0);
	CHECK(aik_json_count(o) == 3);
	CHECK(aik_json_int(aik_json_get(o, "a")) == 9);	/* 首次出现 */
	dump_eq(o, "{\"a\":9,\"b\":2,\"a\":7}", __LINE__);
	aik_json_free(o);
}

static void test_numbers(void)
{
	static const struct {
		const char *src;
		aik_json_type type;
		const char *dump;
		long long ival;
	} cases[] = {
		{ "9223372036854775807", AIK_JSON_INT, "9223372036854775807", 9223372036854775807LL },
		{ "-9223372036854775808", AIK_JSON_INT, "-9223372036854775808", (-9223372036854775807LL - 1) },
		{ "9223372036854775808", AIK_JSON_NUM, "9.223372036854776e+18", 0 },
		{ "-9223372036854775809", AIK_JSON_NUM, "-9.223372036854776e+18", 0 },
		{ "0", AIK_JSON_INT, "0", 0 },
		{ "-0", AIK_JSON_INT, "0", 0 },
		{ "1.0", AIK_JSON_NUM, "1.0", 0 },
		{ "1e2", AIK_JSON_NUM, "100.0", 0 },
		{ "-1E-5", AIK_JSON_NUM, "-1e-05", 0 },
		{ "0.0001", AIK_JSON_NUM, "0.0001", 0 },
		{ "5e-324", AIK_JSON_NUM, "5e-324", 0 },
		{ "1.7976931348623157e308", AIK_JSON_NUM,
		  "1.7976931348623157e+308", 0 },
		{ "1e16", AIK_JSON_NUM, "1e+16", 0 },
		{ "1e15", AIK_JSON_NUM, "1000000000000000.0", 0 },
		{ "1234567890123456.0", AIK_JSON_NUM, "1234567890123456.0", 0 },
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		aik_json *v = parse_ok(cases[i].src, __LINE__);

		if (!v)
			continue;
		g_checked++;
		if (aik_json_typeof(v) != cases[i].type) {
			report_mismatch("%s: type %d != %d", cases[i].src,
					(int)aik_json_typeof(v),
					(int)cases[i].type);
		} else if (cases[i].type == AIK_JSON_INT) {
			g_checked++;
			if (aik_json_int(v) != cases[i].ival)
				report_mismatch("%s: int %lld != %lld",
						cases[i].src, aik_json_int(v),
						cases[i].ival);
		}
		CHECK(dump_eq(v, cases[i].dump, __LINE__) == 1);
		aik_json_free(v);
	}
}

/* 非法输入：必须 NULL，err 以 "offset=N: " 开头，且 N <= 输入长度 */
static void test_invalid(void)
{
	static const char *bad[] = {
		"",
		"   ",
		"{",
		"{\"a\":",
		"{\"a\":1",
		"[1,",
		"[1,]",
		"{\"a\":1,}",
		"{\"a\" 1}",
		"{} x",
		"[1 2]",
		"tru",
		"nullx",
		"\"\\q\"",
		"\"\\u12\"",
		"\"\\u00g0\"",
		"\"abc",
		"\"\x01\"",
		"01",
		"-",
		"1.",
		"1e",
		"+1",
		"nan",
		"{'a':1}",
		"[1,2",
		"{\"a\"::1}",
		"{\"a\":1}{\"b\":2}",
	};
	size_t i;

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		char err[256];
		aik_json *v;
		unsigned long off = 0;

		g_checked++;
		err[0] = '\0';
		v = aik_json_parse(bad[i], strlen(bad[i]), err, sizeof(err));
		if (v) {
			report_mismatch("invalid input %.40s parsed OK", bad[i]);
			aik_json_free(v);
			continue;
		}
		if (strncmp(err, "offset=", 7) != 0) {
			report_mismatch("invalid input %.40s: bad err \"%s\"",
					bad[i], err);
			continue;
		}
		off = strtoul(err + 7, NULL, 10);
		if (off > strlen(bad[i]))
			report_mismatch("invalid input %.40s: offset %lu > len %zu",
					bad[i], off, strlen(bad[i]));
	}
}

/* ------------------------------------------------------------------ */
/* dtoa 向量表                                                         */
/* ------------------------------------------------------------------ */

static void dtoa_pass(const char *path, const char *label)
{
	FILE *f = fopen(path, "r");
	char line[512];
	char got[64];
	int lines = 0, mism = 0;

	if (!f) {
		report_mismatch("%s: cannot open %s", label, path);
		return;
	}
	while (fgets(line, sizeof(line), f)) {
		char *tab = strchr(line, '\t');
		char *repr;
		size_t rl;
		unsigned long long bits;
		double d;
		int n;

		if (!tab)
			continue;
		*tab = '\0';
		repr = tab + 1;
		rl = strlen(repr);
		while (rl && (repr[rl - 1] == '\n' || repr[rl - 1] == '\r'))
			repr[--rl] = '\0';
		if (rl == 0 || strlen(line) != 16)
			continue;
		bits = strtoull(line, NULL, 16);
		memcpy(&d, &bits, sizeof(d));
		n = aik_json_dtoa(d, got, sizeof(got));
		lines++;
		if (n < 0 || (size_t)n != rl || memcmp(got, repr, rl) != 0) {
			mism++;
			if (mism <= 5) {
				report_plain(
					"%s: bits=%s got=%s exp=%s", label,
					line, n < 0 ? "<err>" : got, repr);
			}
		}
	}
	fclose(f);
	g_checked += lines;
	g_mismatch += mism;
	printf("%s: checked=%d mismatch=%d (%s)\n", label, lines, mism,
	       path);
}

/* ------------------------------------------------------------------ */
/* canonical 逐字节比对                                                */
/* ------------------------------------------------------------------ */

static void print_ctx(const char *tag, const char *p, size_t n, size_t center)
{
	size_t start = center > 40 ? center - 40 : 0;
	size_t end = center + 40 < n ? center + 40 : n;
	size_t i;

	printf("  %s hex [%zu..%zu): ", tag, start, end);
	for (i = start; i < end; i++)
		printf("%02x", (unsigned char)p[i]);
	printf("\n  %s txt:           ", tag);
	for (i = start; i < end; i++) {
		unsigned char c = (unsigned char)p[i];

		putchar(c >= 0x20 && c < 0x7f ? (int)c : '.');
	}
	putchar('\n');
}

static void test_canonical(void)
{
	char *path;
	size_t len = 0;
	char *src;
	char err[256];
	aik_json *v;
	char *out = NULL;
	size_t outlen = 0, diff = 0, line = 1, i;
	int eq;

	g_checked++;
	path = vpath_alloc("snapshot.canonical.json");
	if (!path) {
		report_mismatch("canonical: out of memory");
		return;
	}
	src = read_file(path, &len);
	if (!src) {
		report_mismatch("canonical: cannot read %s", path);
		free(path);
		return;
	}
	free(path);
	err[0] = '\0';
	v = aik_json_parse(src, len, err, sizeof(err));
	if (!v) {
		report_mismatch("canonical: parse failed: %s", err);
		free(src);
		return;
	}
	if (aik_json_dump(v, &out, &outlen) != 0) {
		report_mismatch("canonical: dump failed");
		aik_json_free(v);
		free(src);
		return;
	}
	g_bytes = outlen;
	eq = (outlen == len) && memcmp(out, src, len) == 0;
	if (!eq) {
		if (outlen != len) {
			report_mismatch("canonical: length %zu != %zu", outlen,
					len);
		} else {
			while (diff < len && out[diff] == src[diff])
				diff++;
			for (i = 0; i < diff; i++)
				if (src[i] == '\n')
					line++;
			report_mismatch(
				"canonical: first diff at offset=%zu line=%zu",
				diff, line);
			print_ctx("src", src, len, diff);
			print_ctx("out", out, outlen, diff);
		}
	} else {
		printf("canonical: %zu bytes identical\n", len);
	}
	free(out);
	aik_json_free(v);
	free(src);
	print_rss();
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
	char *path;
	const char *loc;
	const char *off;

	test_nested();
	test_escapes();
	test_dup_keys();
	test_numbers();
	test_invalid();

	path = vpath_alloc("dtoa.vectors.tsv");
	if (!path) {
		report_mismatch("dtoa: out of memory");
		path = NULL;
	}

	/* 进程 locale = C（或环境默认）时先跑一遍基线 */
	if (path)
		dtoa_pass(path, "dtoa[baseline]");

	off = getenv("AIK_TEST_LOCALE_OFF");
	if (!path) {
		/* 已在上面报过 OOM */
	} else if (!off || !*off || strcmp(off, "0") == 0) {
		loc = setlocale(LC_ALL, "");
		printf("locale pass: setlocale(LC_ALL,\"\") -> %s (decpt=\"%s\")\n",
		       loc ? loc : "(failed)",
		       localeconv()->decimal_point ? localeconv()->decimal_point : "?");
		dtoa_pass(path, "dtoa[setlocale]");
		/* 若能切到逗号小数点 locale，再来一轮（更强的 locale 反证） */
		if ((loc = setlocale(LC_ALL, "de_DE.UTF-8")) != NULL) {
			printf("locale pass: de_DE.UTF-8 ok (decpt=\"%s\")\n",
			       localeconv()->decimal_point);
			dtoa_pass(path, "dtoa[de_DE]");
			{
				char err[128];
				aik_json *v = aik_json_parse("1.5", 3, err,
							     sizeof(err));
				g_checked++;
				if (!v || aik_json_num(v) != 1.5) {
					report_mismatch(
						"de_DE: parse \"1.5\" failed: %s",
						v ? "wrong value" : err);
				} else {
					dump_eq(v, "1.5", __LINE__);
				}
				aik_json_free(v);
			}
			(void)setlocale(LC_ALL, "");
		} else {
			printf("locale pass: de_DE.UTF-8 unavailable, skipped\n");
		}
	} else {
		printf("locale pass: skipped (AIK_TEST_LOCALE_OFF=%s)\n", off);
	}

	test_canonical();

	free(path);
	printf("SUMMARY checked=%d mismatch=%d bytes=%zu\n", g_checked,
	       g_mismatch, g_bytes);
	return g_mismatch ? 1 : 0;
}
