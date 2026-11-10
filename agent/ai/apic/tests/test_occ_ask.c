/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_occ_ask.c - LT-BUG-007 回归钉：/ask 的 occ 入口。
 *
 * 覆盖（全部本地假 occ，绝不真调模型）：
 *   1) 缺省入口 = /usr/local/bin/occ（出厂口径，防回退到 ai）；
 *   2) occ 不存在 → 502 人话（错误体 error/message 结构不变，message
 *      含 "<path> 不存在" 与查法提示）；
 *   3) 假 occ 脚本 → argv 恰为 {"<occ>", "-p", question}，stdout 原样
 *      透传；question 内的 shell 元字符不被解释（注入面为零）；
 *   4) 假 occ 非 0 退出 → 502 + detail=stderr 尾部（UTF-8 安全）。
 */
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../apiocc.h"
#include "apic/api.h"
#include "desktop/dtcore.h"
#include "desktop/dtjson.h"

static int g_fails = 0;
static int g_checks = 0;

#define CHECK(cond) do { \
	g_checks++; \
	if (!(cond)) { \
		g_fails++; \
		printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
	} \
} while (0)

#define CHECK_STR(got, want) do { \
	const char *g_ = (got); \
	g_checks++; \
	if (!g_ || strcmp(g_, (want)) != 0) { \
		g_fails++; \
		printf("FAIL %s:%d: got %s want %s\n", __FILE__, __LINE__, \
		       g_ ? g_ : "(null)", (want)); \
	} \
} while (0)

/* 假 occ：严格校验 argv，stdout 回显 question 原文，stderr 走元数据行
 * （模拟真 occ 的 `occ: session=...` 输出，不得被 answer 吸收） */
static const char FAKE_OK[] =
	"#!/bin/sh\n"
	"if [ \"$1\" != \"-p\" ] || [ \"$#\" -ne 2 ]; then\n"
	"  printf 'bad argv (#=%s a1=%s)\\n' \"$#\" \"$1\" >&2\n"
	"  exit 9\n"
	"fi\n"
	"printf 'fake-occ-answer:%s\\n' \"$2\"\n"
	"printf 'occ: session=fake msg=m1 tokens=0 finish=stop\\n' >&2\n"
	"exit 0\n";

/* 假 occ：非 0 退出 + 中文 stderr（验证 detail 的 UTF-8 安全尾部） */
static const char FAKE_FAIL[] =
	"#!/bin/sh\n"
	"printf 'boom-中文\\nlast line\\n' >&2\n"
	"exit 3\n";

static char g_base[512];

static int write_script(const char *name, const char *body, char *out,
			size_t cap)
{
	int fd;

	snprintf(out, cap, "%s/%s", g_base, name);
	fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (fd < 0)
		return -1;
	(void)api_write_discard(fd, body, strlen(body));
	close(fd);
	(void)chmod(out, 0755);
	return 0;
}

static void test_default_path(void)
{
	unsetenv(API_OCC_BIN_ENV);
	memset(g_api.ai_bin, 0, sizeof(g_api.ai_bin));
	CHECK_STR(api_occ_bin(), "/usr/local/bin/occ");
}

static void test_missing(void)
{
	char missing[600];
	char *out = NULL, *err = NULL, *dump = NULL;
	size_t outlen = 0, errlen = 0;
	int rc_out = 0, st = 0;
	aik_json *body = NULL;
	int rc;

	snprintf(missing, sizeof(missing), "%s/no-such-occ", g_base);
	setenv(API_OCC_BIN_ENV, missing, 1);
	rc = api_run_occ("1+1=?", 5, &out, &outlen, &err, &errlen, &rc_out,
			 &st, &body);
	CHECK(rc == 1);
	CHECK(st == 502);
	CHECK(body != NULL);
	CHECK(out == NULL && err == NULL);
	if (body) {
		dump = dt_json_dump_default(body);
		/* 机器码保持既有口径，message 换成人话（结构兼容） */
		CHECK(dump && strstr(dump, "\"error\": \"ai binary missing\""));
		CHECK(dump && strstr(dump, "不存在"));
		CHECK(dump && strstr(dump, "查法"));
		CHECK(dump && strstr(dump, "ls -l"));
		CHECK(dump && strstr(dump, missing));
	}
	free(dump);
	aik_json_free(body);
	free(out);
	free(err);
	unsetenv(API_OCC_BIN_ENV);
}

static void test_fake_occ(void)
{
	char script[600];
	char pwned[600];
	char q[2048];
	char want[2400];
	char *out = NULL, *err = NULL, *dump = NULL;
	size_t outlen = 0, errlen = 0;
	int rc_out = 0, st = 0;
	aik_json *body = NULL;
	int rc;

	snprintf(pwned, sizeof(pwned), "%s/pwned", g_base);
	snprintf(q, sizeof(q),
		 "多行问题\nhello; touch %.500s; $(id) `id` | cat > %.500s.x",
		 pwned, pwned);
	snprintf(want, sizeof(want), "fake-occ-answer:%s\n", q);
	CHECK(write_script("fake-occ-ok", FAKE_OK, script,
			   sizeof(script)) == 0);
	setenv(API_OCC_BIN_ENV, script, 1);
	rc = api_run_occ(q, 10, &out, &outlen, &err, &errlen, &rc_out, &st,
			 &body);
	CHECK(rc == 0);
	CHECK(rc_out == 0);
	CHECK(st == 0 && body == NULL);
	/* answer = stdout 原样（handler 再 strip）；stderr 元数据不混入 */
	CHECK(out && outlen == strlen(want) && memcmp(out, want, outlen) == 0);
	CHECK(err && strstr(err, "occ: session=fake"));
	CHECK(access(pwned, F_OK) != 0);
	free(out);
	out = NULL;
	free(err);
	err = NULL;
	outlen = 0;
	errlen = 0;

	CHECK(write_script("fake-occ-fail", FAKE_FAIL, script,
			   sizeof(script)) == 0);
	setenv(API_OCC_BIN_ENV, script, 1);
	rc = api_run_occ("boom", 10, &out, &outlen, &err, &errlen, &rc_out,
			 &st, &body);
	CHECK(rc == 1);
	CHECK(st == 502);
	CHECK(body != NULL);
	if (body) {
		dump = dt_json_dump_default(body);
		CHECK(dump && strstr(dump, "\"error\": \"ai failed\""));
		CHECK(dump && strstr(dump, "occ rc=3"));
		CHECK(dump && strstr(dump, "boom-中文"));
	}
	free(dump);
	aik_json_free(body);
	free(out);
	free(err);
	unsetenv(API_OCC_BIN_ENV);
}

int main(void)
{
	char tmpl[] = "/tmp/test_occ_ask.XXXXXX";

	if (!mkdtemp(tmpl)) {
		printf("FAIL mkdtemp %s\n", tmpl);
		return 1;
	}
	snprintf(g_base, sizeof(g_base), "%s", tmpl);
	memset(&g_api, 0, sizeof(g_api));
	test_default_path();
	test_missing();
	test_fake_occ();
	{
		char cmd[600];
		int rc_;

		snprintf(cmd, sizeof(cmd), "rm -rf %s", g_base);
		rc_ = system(cmd);
		(void)rc_;
	}
	printf("test_occ_ask: %d checks, %d failures\n", g_checks, g_fails);
	return g_fails ? 1 : 0;
}
