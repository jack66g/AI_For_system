/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_tokens.c - occ_core/tokens 单测（T9a3）
 *
 * 覆盖：五项账本（input/output±cache/total）、真实 usage 覆盖式入账、
 * len/4 估算兜底（ASCII/中文/空/NULL）、est 标志（估算置位、真实
 * 回传清除）、格式化 ~ 前缀。
 */
#include <stdio.h>
#include <string.h>

#include "occ_core/occ_tokens.h"

static int n_fail;
static int n_ok;

#define OK(cond, name) do { \
	if (cond) { n_ok++; printf("ok %s\n", name); } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

int main(void)
{
	occ_tokens t;
	occ_usage u;
	char buf[64];

	/* 五项入账 */
	occ_tokens_reset(&t);
	memset(&u, 0, sizeof(u));
	u.present = 1;
	u.input = 100;
	u.output = 40;
	u.cache_read = 60;
	u.cache_write = 5;
	occ_tokens_set_usage(&t, &u);
	OK(t.input == 100 && t.output == 40 && t.cache_read == 60 &&
	   t.cache_write == 5, "usage-five-fields");
	OK(t.total == 140, "total=in+out");
	OK(t.est == 0, "real-usage-not-est");

	/* 覆盖式：第二次 usage 覆盖（SSE 流末最终值） */
	u.input = 120;
	u.output = 50;
	occ_tokens_set_usage(&t, &u);
	OK(t.input == 120 && t.output == 50 && t.total == 170,
	   "usage-overwrite");

	/* present=0 不入账 */
	memset(&u, 0, sizeof(u));
	occ_tokens_set_usage(&t, &u);
	OK(t.input == 120, "absent-usage-ignored");

	/* len/4 估算（任务书口径） */
	OK(occ_tokens_estimate_len("abcd") == 1, "est-ascii-4b");
	OK(occ_tokens_estimate_len("ab") == 0, "est-ascii-2b-floor");
	OK(occ_tokens_estimate_len("你好") == 1, "est-utf8-6b");  /* 6/4=1 */
	OK(occ_tokens_estimate_len("") == 0, "est-empty");
	OK(occ_tokens_estimate_len(NULL) == 0, "est-null");
	OK(occ_tokens_estimate_output("abcdefghijkl") == 3, "est-output");

	/* 估算后真实回传清除 est：loop 场景（估算 → usage 事件到达） */
	occ_tokens_reset(&t);
	t.est = 1;
	t.output = occ_tokens_estimate_output("abcdefgh");
	u.present = 1;
	u.input = 10;
	u.output = 2;
	occ_tokens_set_usage(&t, &u);
	OK(t.est == 0 && t.output == 2, "est-cleared-by-real-usage");

	/* 格式化 */
	occ_tokens_reset(&t);
	t.total = 1234;
	t.est = 0;
	OK(!strcmp(occ_tokens_fmt(&t, buf, sizeof(buf)), "1234"), "fmt-plain");
	t.est = 1;
	OK(!strcmp(occ_tokens_fmt(&t, buf, sizeof(buf)), "~1234"), "fmt-est");

	printf("test_tokens: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
