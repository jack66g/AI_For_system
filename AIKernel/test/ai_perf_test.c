// SPDX-License-Identifier: GPL-2.0
/*
 * ai_perf_test.c - K9 性能预算 KUnit 套（KERNEL-K9-DESIGN §2 D2）
 *
 * 内核确定性层：四个微基准各打印机读 PERF 行（k9_perf.py 解析判红绿）。
 * 口径双层：ci_bound=任何环境直接判的 CI 宽界；KTB HW 预算存证于
 * AIKernel/test/perf/budgets.json（tcg 直测 HW 界无意义，不冒充）。
 * 手法同源 ai_policy_test.c:804-841（N 次直调+ktime 逐次+sort 分位）。
 */

#include <kunit/test.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sort.h>
#include <linux/string.h>

#include "../core/ai_policy.h"
#include "../core/ai_telemetry.h"
#include "../core/ai_decision.h"
#include "../security/ai_chain.h"

static int perf_u64_cmp(const void *x, const void *y)
{
	const u64 a = *(const u64 *)x, b = *(const u64 *)y;

	return (a > b) - (a < b);
}

static u64 perf_pct(u64 *lat, unsigned int n, unsigned int pct)
{
	return lat[n * pct / 100];
}

/* 通用跑表：fn 逐次夹逼，输出 PERF 行并按 ci_bound 判定 */
static void perf_run(struct kunit *test, const char *name, unsigned int n,
		     u64 ci_bound,
		     void (*fn)(void *arg), void *arg)
{
	u64 *lat, t0, t1;
	unsigned int i;

	lat = kvmalloc_array(n, sizeof(*lat), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, lat);
	for (i = 0; i < n; i++) {
		t0 = ktime_get_ns();
		fn(arg);
		t1 = ktime_get_ns();
		lat[i] = t1 - t0;
	}
	sort(lat, n, sizeof(lat[0]), perf_u64_cmp, NULL);
	pr_info("AIKernel KUnit: PERF name=%s n=%u p50=%llu p99=%llu p999=%llu ci_bound_ns=%llu verdict=%s\n",
		name, n, perf_pct(lat, n, 50), perf_pct(lat, n, 99),
		lat[n * 999 / 1000], ci_bound,
		perf_pct(lat, n, 99) < ci_bound ? "PASS" : "FAIL");
	KUNIT_EXPECT_LT(test, perf_pct(lat, n, 99), ci_bound);
	kvfree(lat);
}

#ifdef CONFIG_AIKERNEL_RUNTIME
static void perf_fn_record_write(void *arg)
{
	ai_policy_test_record_write((struct ai_decision_record *)arg);
}

static void perf_record_write_test(struct kunit *test)
{
	struct ai_decision_record rec = { 0 };

	rec.trigger_ts = ktime_get_ns();
	rec.decision_ts = rec.trigger_ts + 1000;
	rec.execute_ts = rec.trigger_ts + 2000;
	rec.decision_id = 0x66000099ULL;
	rec.executed = 1;
	perf_run(test, "record_write", 100000, 5000ULL,
		 perf_fn_record_write, &rec);
}

static void perf_fn_decision_query(void *arg)
{
	struct ai_hook_ctx *ctx = arg;

	ai_decision_query(AI_HOOK_SCHED_VRUNTIME, ctx);
}

static void perf_decision_query_test(struct kunit *test)
{
	struct ai_hook_ctx ctx = { .pid = 0 };

	perf_run(test, "decision_query", 100000, 10000ULL,
		 perf_fn_decision_query, &ctx);
}
#else
static void perf_record_write_test(struct kunit *test)
{ kunit_skip(test, "需要 CONFIG_AIKERNEL_RUNTIME"); }
static void perf_decision_query_test(struct kunit *test)
{ kunit_skip(test, "需要 CONFIG_AIKERNEL_RUNTIME"); }
#endif

#ifdef CONFIG_AIKERNEL_SECURITY
static void perf_fn_chain_append(void *arg)
{
	ai_chain_append(AI_CHAIN_KIND_DECISION_NEW, NULL, 0);
}

static void perf_chain_append_test(struct kunit *test)
{
	/* 复位+压锚：纯链路径（KUnit autorun 复位口径见 ai_chain_test 头注） */
	ai_chain_test_reset();
	ai_chain_period_set(0xffffffffU);
	perf_run(test, "chain_append", 100000, 5000ULL,
		 perf_fn_chain_append, NULL);
	ai_chain_period_set(AI_CHAIN_DEFAULT_PERIOD);
}
#else
static void perf_chain_append_test(struct kunit *test)
{ kunit_skip(test, "需要 CONFIG_AIKERNEL_SECURITY"); }
#endif

#ifdef CONFIG_AIKERNEL_TELEMETRY
static void perf_fn_telemetry_emit(void *arg)
{
	ai_telemetry_emit(AI_CAT_AI, AI_EV_AI_OUTCOME, AI_SEV_NORMAL,
			  arg, 16);
}

static void perf_telemetry_emit_test(struct kunit *test)
{
	u8 payload[16] = {};

	/* p99 口径（K7 平均口径升级）；环满丢新计数为诚实观测面 */
	perf_run(test, "telemetry_emit", 100000, 100000ULL,
		 perf_fn_telemetry_emit, payload);
}
#else
static void perf_telemetry_emit_test(struct kunit *test)
{ kunit_skip(test, "需要 CONFIG_AIKERNEL_TELEMETRY"); }
#endif

static struct kunit_case ai_perf_test_cases[] = {
	KUNIT_CASE(perf_record_write_test),
	KUNIT_CASE(perf_chain_append_test),
	KUNIT_CASE(perf_telemetry_emit_test),
	KUNIT_CASE(perf_decision_query_test),
	{}
};

static struct kunit_suite ai_perf_suite = {
	.name = "ai_perf",
	.test_cases = ai_perf_test_cases,
};

kunit_test_suite(ai_perf_suite);
