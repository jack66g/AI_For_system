/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ac_vec.h - T5b 测试共享：差分向量加载与计数输出（仅 tests/test_ac*.c 内嵌）
 *
 * 使用方必须在本文件之前 `#define _AC_TEST_C11 1` 之外再自行定义
 * `_DEFAULT_SOURCE`（mkdtemp/localtime_r 等 POSIX/GNU 接口）。
 *
 * 向量根：$AIK_PARITY_VECTORS，默认 $HOME/aikernel-longterm/parity/vectors。
 * 输出行格式："test_ac<N>: X checks, Y failed"，失配时退出码非 0。
 */
#ifndef _AIK_AUTOCONDENSE_TESTS_AC_VEC_H
#define _AIK_AUTOCONDENSE_TESTS_AC_VEC_H

#include "store/store_json.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_ac_checks;
static int g_ac_failed;

__attribute__((format(printf, 1, 2)))
static void ac_fail(const char *fmt, ...)
{
	va_list ap;

	g_ac_failed++;
	fprintf(stderr, "FAIL: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

/* 非致命计数断言 */
#define AC_COUNT(cond, name) do {					\
	g_ac_checks++;							\
	if (!(cond))							\
		ac_fail("%s", (name));					\
} while (0)

static void ac_summary(const char *name)
{
	printf("%s: %d checks, %d failed\n", name, g_ac_checks, g_ac_failed);
}

static const char *ac_vectors_root(void)
{
	const char *d = getenv("AIK_PARITY_VECTORS");

	if (d && *d)
		return d;
	static char buf[512];
	const char *home = getenv("HOME");

	snprintf(buf, sizeof(buf), "%s/aikernel-longterm/parity/vectors",
		 home && *home ? home : ".");
	return buf;
}

/* 读整个文件（malloc + NUL）；失败 NULL */
static char *ac_slurp(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return NULL;
	}
	long sz = ftell(f);

	if (sz < 0 || fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return NULL;
	}
	char *buf = malloc((size_t)sz + 1);

	if (!buf || (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz)) {
		fclose(f);
		free(buf);
		return NULL;
	}
	fclose(f);
	buf[sz] = '\0';
	if (len)
		*len = (size_t)sz;
	return buf;
}

/* 读 <root>/<rel> 并解析；失败打印错误并返回 NULL */
static aik_json *ac_load_vector(const char *rel)
{
	static char path[1024];

	snprintf(path, sizeof(path), "%s/%s", ac_vectors_root(), rel);
	size_t sz = 0;
	char *buf = ac_slurp(path, &sz);

	if (!buf) {
		fprintf(stderr, "FATAL: cannot open %s\n", path);
		return NULL;
	}
	char err[128];
	aik_json *v = aik_json_parse(buf, sz, err, sizeof(err));

	free(buf);
	if (!v)
		fprintf(stderr, "FATAL: parse %s: %s\n", path, err);
	return v;
}

/* 紧凑序列化（malloc，调用者 free）；失败返回 NULL */
static char *ac_dump(const aik_json *v)
{
	char *out = NULL;
	size_t n = 0;

	if (aik_json_dump(v, &out, &n) != 0)
		return NULL;
	return out;
}

/* mkdtemp 包装（prefix 形如 "/tmp/ac-state-"）；失败返回 NULL */
static char *ac_mkdtemp(const char *prefix)
{
	char *tpl = malloc(strlen(prefix) + 7);

	if (!tpl)
		return NULL;
	sprintf(tpl, "%sXXXXXX", prefix);
	if (!mkdtemp(tpl)) {
		free(tpl);
		return NULL;
	}
	return tpl;
}

#endif /* _AIK_AUTOCONDENSE_TESTS_AC_VEC_H */
