/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_net_timeout.c - O-27：connect 超时前置于 connect() 的有界失败
 *
 * 真身（T-2 B8 真机实证，11-20）：旧 tcp_connect 把 SO_SNDTIMEO/
 * SO_RCVTIMEO 设在 connect() 之后——黑洞地址的阻塞 connect 吃内核
 * SYN 重试 ~127s+ 才 ETIMEDOUT，g_connect_timeout 形同虚设；headless
 * occ -p 断网三分钟静默。修=超时先于 connect 设（Linux 语义 connect
 * 同受 SO_SNDTIMEO 管）。
 *
 * 断言：TEST-NET-1（RFC 5737 保留，不可路由）地址在 1s 连接超时下
 * 必须失败且有界（≤5s）——无论宿主网络对它超时还是直接 RST。
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cloud/http/http_client.h"

static int fails, checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

static double el_s(const struct timespec *t0)
{
	struct timespec t1;

	clock_gettime(CLOCK_MONOTONIC, &t1);
	return (double)(t1.tv_sec - t0->tv_sec) +
	       (double)(t1.tv_nsec - t0->tv_nsec) / 1e9;
}

int main(void)
{
	struct timespec t0;
	char *resp = NULL, *err = NULL;
	double el;
	int rc;

	/* 1) 黑洞地址：1s 连接超时——失败且有界 */
	https_init();
	https_set_timeout(1, 1);
	clock_gettime(CLOCK_MONOTONIC, &t0);
	rc = https_post("http://192.0.2.1:81/v1/x", "", "{}", &resp, &err);
	el = el_s(&t0);
	CHECK(rc != 0, "blackhole POST fails");
	CHECK(el < 5.0, "blackhole fail bounded (<5s)");
	printf("  blackhole: rc=%d elapsed=%.2fs err=%s\n",
	       rc, el, (err && err[0]) ? err : "(none)");
	free(resp); resp = NULL;
	free(err); err = NULL;

	/* 2) 语法坏 URL：快速失败（sanity——不涉网络） */
	clock_gettime(CLOCK_MONOTONIC, &t0);
	rc = https_post("not-a-url", "", "{}", &resp, &err);
	el = el_s(&t0);
	CHECK(rc != 0, "bad-url POST fails");
	CHECK(el < 2.0, "bad-url fail fast (<2s)");
	free(resp);
	free(err);

	printf("test_net_timeout: %d checks, %d failures\n", checks, fails);
	return fails ? 1 : 0;
}
