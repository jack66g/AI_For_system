/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_quota.c - 配额单测（速率/日限/每路日限；时间注入逐事件断言）
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "as_quota.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

int main(void)
{
	struct as_quota q;
	/* 锚定本地正午（跨时区稳定：+1h 仍在同一天，日限断言不翻页） */
	time_t base = 1762300000;
	struct tm tm;
	long long t;

	localtime_r(&base, &tm);
	tm.tm_hour = 12;
	tm.tm_min = 0;
	tm.tm_sec = 0;
	t = (long long)mktime(&tm) * 1000;

	/* ---- 1) 速率：60/min，第 61 条同时刻拒绝，61s 后放行 ---- */
	CHECK(as_quota_init(&q, 60, 5000, 1000) == 0, "init");

	for (int i = 0; i < 60; i++) {
		CHECK(as_quota_check(&q, 1, t) == AS_Q_ALLOW, "rate allow");
		as_quota_commit(&q, 1, t);
	}
	CHECK(as_quota_check(&q, 1, t) == AS_Q_DENY_RATE,
	      "61st in window denied");
	CHECK(as_quota_check(&q, 2, t + 61000) == AS_Q_ALLOW,
	      "after window expiry allowed");
	as_quota_commit(&q, 2, t + 61000);

	/* ---- 2) 滑窗语义：把 60 条摊到 59s 内后新条仍拒（窗口满）；
	 * 摊开后 t+61s 只剩 1 条在窗内 → 放行 ---- */
	as_quota_free(&q);
	CHECK(as_quota_init(&q, 60, 5000, 1000) == 0, "init2");
	for (int i = 0; i < 60; i++) {
		as_quota_commit(&q, 1, t + i * 1000);	/* 每 1s 一条 ×60 */
	}
	CHECK(as_quota_check(&q, 1, t + 59000) == AS_Q_DENY_RATE,
	      "sliding window full at 59s");
	CHECK(as_quota_check(&q, 1, t + 61500) == AS_Q_ALLOW,
	      "oldest expired at 61.5s");
	as_quota_commit(&q, 1, t + 61500);

	/* ---- 3) 全局日上限 ---- */
	as_quota_free(&q);
	CHECK(as_quota_init(&q, 1000000, 5, 1000) == 0, "init3");
	for (int i = 0; i < 5; i++) {
		CHECK(as_quota_check(&q, 0, t) == AS_Q_ALLOW, "daily allow");
		as_quota_commit(&q, 0, t);
	}
	CHECK(as_quota_check(&q, 1, t) == AS_Q_DENY_DAILY, "daily cap");
	/* 同日跨小时仍拒 */
	CHECK(as_quota_check(&q, 1, t + 3600000) == AS_Q_DENY_DAILY,
	      "daily cap same day");

	/* ---- 4) 每路日上限 ---- */
	as_quota_free(&q);
	CHECK(as_quota_init(&q, 1000000, 5000, 3) == 0, "init4");
	for (int i = 0; i < 3; i++) {
		as_quota_commit(&q, 2, t);
	}
	CHECK(as_quota_check(&q, 2, t) == AS_Q_DENY_STREAM,
	      "stream daily cap");
	CHECK(as_quota_check(&q, 3, t) == AS_Q_ALLOW,
	      "other stream unaffected");
	as_quota_commit(&q, 3, t);

	/* ---- 5) 原因文本 ---- */
	CHECK(strcmp(as_quota_reason(AS_Q_DENY_RATE),
		     "rate_per_min exceeded") == 0, "reason rate");

	as_quota_free(&q);
	if (fails) {
		printf("test_quota: %d failures\n", fails);
		return 1;
	}
	printf("test_quota: OK\n");
	return 0;
}
