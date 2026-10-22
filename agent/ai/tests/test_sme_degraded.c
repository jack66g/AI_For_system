// SPDX-License-Identifier: GPL-2.0
/*
 * test_sme_degraded.c - W43 SME 失忆降级回归（无 SME 服务环境，L1 天然）
 *
 * 断言：
 *   1. 连接失败快速返回 AI_ERR_NETWORK（实测 <5s，无挂死——本机拒绝
 *      应即时；非阻塞 connect 修复后黑洞地址也被 connect 超时兜底）
 *   2. out 含人可读错误说明（SME 服务不可达）
 *   3. 结构化降级原因码 sme_degrade_reason_of：NETWORK→UNAVAILABLE、
 *      AI_OK→NONE、API→HTTP
 *   4. sme_health 探测不可达（/session 显示用）
 *   5. 导出路径白名单先行：合法路径在 SME 不可达时降级为网络错误，
 *      且不产生落盘文件
 */
#define _GNU_SOURCE             /* setenv/clock_gettime/CLOCK_MONOTONIC */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ai_types.h"
#include "memory/sme_client.h"

static int g_fail;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		g_fail++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

static double now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(void)
{
	char out[SME_OUT_BUF_MIN * 2];
	int rc;
	double t0, t1;

	/* 端口 1 保留端口：本机必然立即拒绝（无需任何服务） */
	setenv("SME_URL", "http://127.0.0.1:1", 1);

	/* ---- 1. sme_search 不可达：快速返回 + 结构化标记 ---- */
	memset(out, 0, sizeof(out));
	t0 = now_s();
	rc = sme_search("w43 degraded probe", 3, out, sizeof(out));
	t1 = now_s();
	CHECK(rc == AI_ERR_NETWORK, "sme_search 连接失败返回 AI_ERR_NETWORK");
	CHECK((t1 - t0) < 5.0, "连接失败快速返回（<5s，不挂死）");
	CHECK(strstr(out, "SME") != NULL, "out 含人可读错误说明");

	CHECK(sme_degrade_reason_of(rc) == SME_DEGRADED_UNAVAILABLE,
	      "原因码映射 NETWORK→SME_DEGRADED_UNAVAILABLE");
	CHECK(sme_degrade_reason_of(AI_OK) == SME_DEGRADED_NONE,
	      "原因码映射 AI_OK→SME_DEGRADED_NONE");
	CHECK(sme_degrade_reason_of(AI_ERR_API) == SME_DEGRADED_HTTP,
	      "原因码映射 AI_ERR_API→SME_DEGRADED_HTTP");

	/* ---- 2. 健康探测（/session 显示数据源） ---- */
	rc = sme_health(out, sizeof(out));
	CHECK(rc == AI_ERR_NETWORK, "sme_health 探测不可达返回网络错误");

	/* ---- 3. 合法导出路径：白名单通过 → 网络段失败 → 不落盘 ---- */
	unlink("/tmp/aik-w43-export-test.json");
	rc = sme_export("/tmp/aik-w43-export-test.json", out, sizeof(out));
	CHECK(rc == AI_ERR_NETWORK,
	      "合法路径在 SME 不可达时降级为网络错误（白名单先行通过）");
	{
		FILE *fp = fopen("/tmp/aik-w43-export-test.json", "rb");

		CHECK(!fp, "SME 不可达时不产生导出文件");
		if (fp)
			fclose(fp);
	}

	printf("\n%s\n", g_fail ? "test_sme_degraded: FAIL" :
			  "test_sme_degraded: ALL PASS");
	return g_fail ? 1 : 0;
}
