/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_retry.c - T9b2 自动重试单测（OCD §7.2 数值）
 *
 * 覆盖：
 *   1) occ_llm_retry_class 分级矩阵——408/429/409/5xx 常规或超时、
 *      其余 4xx 不可重试、传输错误文案（timeout/connect/truncated→超时类；
 *      bad json/provider报错/其余→常规）、流提前终止→超时类
 *   2) 参数族 occ_llm_retry_params：缺省（10/3/2000/10000）→ env 覆盖
 *      → 旋钮优先 → 非法 env 回缺省 → cap<base 归一
 *   3) 退避曲线 occ_llm_retry_backoff_ms：指数封顶
 *   4) 中断旗标初始 0（进程级，单测直接置位模拟的契约）
 *
 * 纯计算层（retry.c 不引 http_client）——无网络、毫秒级。
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "occ_llm/occ_llm.h"

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; printf("ok %s\n", name); } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

static void unset_all(void)
{
	unsetenv("OCC_LLM_RETRY_MAX");
	unsetenv("OCC_LLM_RETRY_TIMEOUT_MAX");
	unsetenv("OCC_LLM_RETRY_BASE_MS");
	unsetenv("OCC_LLM_RETRY_CAP_MS");
}

int main(void)
{
	occ_retry_params rp;

	unset_all();
	occ_llm_set_retry_knobs(-1, -1, -1, -1);

	/* ---- 1) 分级矩阵 ---- */
	OK(occ_llm_retry_class(408, NULL, 0) == 2, "cls-408-timeout");
	OK(occ_llm_retry_class(429, NULL, 0) == 1, "cls-429-regular");
	OK(occ_llm_retry_class(409, NULL, 0) == 1, "cls-409-regular");
	OK(occ_llm_retry_class(500, NULL, 0) == 1, "cls-500-regular");
	OK(occ_llm_retry_class(502, NULL, 0) == 1, "cls-502-regular");
	OK(occ_llm_retry_class(503, NULL, 0) == 1, "cls-503-regular");
	OK(occ_llm_retry_class(504, NULL, 0) == 1, "cls-504-regular");
	OK(occ_llm_retry_class(503, NULL, 0) ==
	   occ_llm_retry_class(599, NULL, 0), "cls-5xx-same");
	OK(occ_llm_retry_class(400, NULL, 0) == 0, "cls-400-no");
	OK(occ_llm_retry_class(401, NULL, 0) == 0, "cls-401-no");
	OK(occ_llm_retry_class(403, NULL, 0) == 0, "cls-403-no");
	OK(occ_llm_retry_class(404, NULL, 0) == 0, "cls-404-no");
	OK(occ_llm_retry_class(422, NULL, 0) == 0, "cls-422-no");
	/* 传输错误文案分级（大小写不敏感） */
	OK(occ_llm_retry_class(0, "Connection timed out", 0) == 2,
	   "cls-err-timeout");
	OK(occ_llm_retry_class(0, "read timeout after 60s", 0) == 2,
	   "cls-err-readtimeout");
	OK(occ_llm_retry_class(0, "connect: connection refused", 0) == 2,
	   "cls-err-connect");
	OK(occ_llm_retry_class(0,
	"truncated final SSE block (unterminated event)", 0) == 2,
	   "cls-err-truncated");
	OK(occ_llm_retry_class(0, "bad json block: offset=3: parse err", 0) == 1,
	   "cls-err-badjson");
	OK(occ_llm_retry_class(0,
			      "Provider reported an error (finish_reason)", 0)
	   == 1, "cls-err-provider");
	OK(occ_llm_retry_class(0, "broken pipe", 0) == 1, "cls-err-pipe");
	OK(occ_llm_retry_class(0, NULL, 1) == 2, "cls-incomplete-timeout");
	OK(occ_llm_retry_class(0, NULL, 0) == 0, "cls-clean-no");
	/* 传输错优先于 incomplete 标志（两级同传时按文案判） */
	OK(occ_llm_retry_class(0, "bad json block", 1) == 1,
	   "cls-err-beats-incomplete");

	/* ---- 2) 参数族 ---- */
	occ_llm_retry_params(&rp);
	OK(rp.max_attempts == 10 && rp.timeout_max == 3 &&
	   rp.base_ms == 2000 && rp.cap_ms == 10000, "params-default");

	setenv("OCC_LLM_RETRY_MAX", "4", 1);
	setenv("OCC_LLM_RETRY_TIMEOUT_MAX", "2", 1);
	setenv("OCC_LLM_RETRY_BASE_MS", "50", 1);
	setenv("OCC_LLM_RETRY_CAP_MS", "200", 1);
	occ_llm_retry_params(&rp);
	OK(rp.max_attempts == 4 && rp.timeout_max == 2 &&
	   rp.base_ms == 50 && rp.cap_ms == 200, "params-env");

	/* 旋钮优先于 env（-1=该键回缺省→env） */
	occ_llm_set_retry_knobs(7, 5, 10, 40);
	occ_llm_retry_params(&rp);
	OK(rp.max_attempts == 7 && rp.timeout_max == 5 &&
	   rp.base_ms == 10 && rp.cap_ms == 40, "knob-beats-env");
	occ_llm_set_retry_knobs(-1, -1, -1, -1);
	occ_llm_retry_params(&rp);
	OK(rp.max_attempts == 4 && rp.base_ms == 50, "knob-reset-to-env");

	/* 非法 env（垃圾/负数）→ 该键回缺省 */
	setenv("OCC_LLM_RETRY_MAX", "abc", 1);
	setenv("OCC_LLM_RETRY_BASE_MS", "-5", 1);
	occ_llm_retry_params(&rp);
	OK(rp.max_attempts == 10, "env-garbage-to-default");
	OK(rp.base_ms == 2000, "env-negative-to-default");

	/* cap < base → 归一为 base */
	setenv("OCC_LLM_RETRY_BASE_MS", "50", 1);
	setenv("OCC_LLM_RETRY_CAP_MS", "10", 1);
	occ_llm_retry_params(&rp);
	OK(rp.cap_ms == rp.base_ms && rp.cap_ms == 50,
	   "cap-ge-base-normalized");

	/* 旋钮 0 = 回缺省（env 已清） */
	unset_all();
	occ_llm_set_retry_knobs(0, 0, 0, 0);
	occ_llm_retry_params(&rp);
	OK(rp.max_attempts == 10 && rp.timeout_max == 3 &&
	   rp.base_ms == 2000 && rp.cap_ms == 10000, "knob-zero-to-default");

	/* ---- 3) 退避曲线（env 毫秒级参数） ---- */
	occ_llm_set_retry_knobs(-1, -1, -1, -1);
	setenv("OCC_LLM_RETRY_BASE_MS", "50", 1);
	setenv("OCC_LLM_RETRY_CAP_MS", "200", 1);
	OK(occ_llm_retry_backoff_ms(1) == 50, "backoff-1");
	OK(occ_llm_retry_backoff_ms(2) == 100, "backoff-2");
	OK(occ_llm_retry_backoff_ms(3) == 200, "backoff-3-capped");
	OK(occ_llm_retry_backoff_ms(4) == 200, "backoff-4-capped");
	OK(occ_llm_retry_backoff_ms(99) == 200, "backoff-99-capped");
	OK(occ_llm_retry_backoff_ms(0) == 50, "backoff-attempt0-normalized");
	/* 缺省曲线抽查（env 清后） */
	unset_all();
	OK(occ_llm_retry_backoff_ms(1) == 2000, "backoff-default-1");
	OK(occ_llm_retry_backoff_ms(3) == 8000, "backoff-default-3");
	OK(occ_llm_retry_backoff_ms(4) == 10000, "backoff-default-4-cap");

	/* ---- 4) 中断旗标契约（单测直接置位模拟，不经信号） ---- */
	OK(occ_interrupt_flag == 0, "flag-initial-zero");
	occ_interrupt_flag = 1;
	OK(occ_interrupt_flag == 1, "flag-set");
	occ_interrupt_flag = 0;
	OK(occ_interrupt_flag == 0, "flag-clear");

	/* ---- 5) B4：Retry-After 解析（occ_llm_retry_after_ms） ---- */
	/* 合法 delta-seconds → 毫秒 */
	OK(occ_llm_retry_after_ms("0", 10000) == 0, "ra-zero");
	OK(occ_llm_retry_after_ms("1", 10000) == 1000, "ra-1s");
	OK(occ_llm_retry_after_ms("30", 60000) == 30000, "ra-30s");
	OK(occ_llm_retry_after_ms(" 2 ", 10000) == 2000, "ra-ows");
	/* 畸形 → -1（回指数退避） */
	OK(occ_llm_retry_after_ms(NULL, 10000) == -1, "ra-null");
	OK(occ_llm_retry_after_ms("", 10000) == -1, "ra-empty");
	OK(occ_llm_retry_after_ms("abc", 10000) == -1, "ra-garbage");
	OK(occ_llm_retry_after_ms("-3", 10000) == -1, "ra-negative");
	OK(occ_llm_retry_after_ms("1.5", 10000) == -1, "ra-float");
	OK(occ_llm_retry_after_ms("12x", 10000) == -1, "ra-trailing-junk");
	OK(occ_llm_retry_after_ms("Wed, 21 Oct 2026 07:28:00 GMT",
				  10000) == -1, "ra-http-date-unsupported");
	/* 过大值钳制（上限保护） */
	OK(occ_llm_retry_after_ms("3600", 10000) == 10000, "ra-clamped-cap");
	OK(occ_llm_retry_after_ms("999999999999", 10000) == 10000,
	   "ra-overflow-clamped");
	OK(occ_llm_retry_after_ms("999999999", 0) == 999999999000LL,
	   "ra-nocap-huge");		/* cap<=0=不钳制（测试专用面） */
	OK(occ_llm_retry_after_ms("2", 1500) == 1500, "ra-clamp-1500");
	OK(occ_llm_retry_after_ms("1", 1500) == 1000, "ra-under-cap");

	printf("test_retry: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
