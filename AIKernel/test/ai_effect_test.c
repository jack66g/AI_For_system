// SPDX-License-Identifier: GPL-2.0
/*
 * ai_effect_test.c - K4.0 效果归因环 KUnit 套件
 *
 * 覆盖：
 *   - 开窗语义：ai_effect_open 字段逐一对值（aux/open_ns/used，脏字段
 *     整体复位），越界 hook 静默忽略；
 *   - 结算回填：open → record_heuristic（内部 bind）→ close(good) 后
 *     ring 条目 outcome/outcome_ts/metric_delta 真改（按 id 读回比对）；
 *   - 超时路径：测试内回拨 open_ns 越过窗长 → ai_effect_tick 按
 *     到期 outcome（默认 timeout，OOM/wakeup 覆盖为 good）关窗
 *     并回填 ring；0 秒纯事件窗（reclaim）tick 永不超时；
 *   - K4 纯判定函数：OOM re-OOM（窗龄/开窗序）、readahead 命中率
 *     （阈值/0 除/metric）、wakeup 误抢占方向与 vruntime 水位方向；
 *   - stats 累计：good/bad/timeout 计数与 last_metric 逐次累加；
 *   - ENOENT 路径：ai_policy_fill_outcome 不存在的 id → -ENOENT、
 *     id=0 → -EINVAL；未绑定窗 close 只走统计不触 ring；
 *   - 分类槽 wakeups 预留字段：新插槽清零（K4.0 只落字段，自增点
 *     后续挂点波接入）。
 * 退出还原：ai_effect_test_reset() 清窗与累计。
 */
#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ktime.h>

#include "../core/ai_types.h"
#include "../core/ai_proc.h"
#include "../core/ai_policy.h"
#include "../core/ai_effect.h"
#include "../mm/ai_mm.h"
#include "../sched/ai_sched.h"

#ifdef CONFIG_AIKERNEL_RUNTIME

/* 读回全量 ring 快照（模式照抄 ai_policy_test.c 的 policy_ring_read；
 * KUnit 套件内串行，末条=最近） */
static struct ai_decision_record *ring_read(struct kunit *test, u32 *count)
{
	struct ai_decision_record *buf;

	buf = kunit_kzalloc(test, AI_POLICY_DECISION_RING_SIZE * sizeof(*buf),
			    GFP_KERNEL);
	if (!buf)
		return NULL;
	if (ai_policy_decision_read(buf, AI_POLICY_DECISION_RING_SIZE *
				    sizeof(*buf), count, NULL) != AI_OK)
		return NULL;
	return buf;
}

/* 按 id 线扫 ring（测试侧全量读回后本地找；找不到返回 NULL） */
static const struct ai_decision_record *ring_find(struct kunit *test, u64 id)
{
	struct ai_decision_record *recs;
	u32 count = 0, i;

	recs = ring_read(test, &count);
	if (!recs)
		return NULL;
	for (i = 0; i < count; i++) {
		if (recs[i].decision_id == id)
			return &recs[i];
	}
	return NULL;
}

/* ---- 开窗语义：字段逐一对值 + 脏字段复位 + 越界 hook 忽略 ---- */
static void effect_open_fields_test(struct kunit *test)
{
	struct ai_effect_win *w = ai_effect_test_win(AI_HOOK_MM_READAHEAD);

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, w);
	ai_effect_test_reset();

	/* 预置脏字段（上一窗结算残留）：开窗必须整体复位 */
	ai_effect_close(AI_HOOK_MM_READAHEAD, AI_EFFECT_OUTCOME_BAD, 99);
	KUNIT_EXPECT_EQ(test, w->used, (u8)0);

	ai_effect_open(AI_HOOK_MM_READAHEAD, 11, 22);
	KUNIT_EXPECT_EQ(test, w->used, (u8)1);
	KUNIT_EXPECT_EQ(test, w->decision_id, (u32)0);
	KUNIT_EXPECT_EQ(test, w->aux0, 11L);
	KUNIT_EXPECT_EQ(test, w->aux1, 22L);
	KUNIT_EXPECT_EQ(test, w->outcome, (u8)AI_EFFECT_OUTCOME_NONE);
	KUNIT_EXPECT_EQ(test, w->metric, 0L);
	KUNIT_EXPECT_EQ(test, w->close_ns, (u64)0);
	KUNIT_EXPECT_GT(test, w->open_ns, (u64)0);

	/* 越界 hook：静默忽略（不越界写数组） */
	ai_effect_open(AI_HOOK_NR, 1, 1);
	ai_effect_close((enum ai_hook_id)99, AI_EFFECT_OUTCOME_GOOD, 0);
	ai_effect_bind((enum ai_hook_id)99, 1);
}

/* ---- 结算回填：bind 绑定最近 pending 窗，close 真改 ring 条目 ---- */
static void effect_settle_ring_fill_test(struct kunit *test)
{
	struct ai_decision_record *recs;
	struct ai_effect_win *w = ai_effect_test_win(AI_HOOK_SCHED_VRUNTIME);
	const struct ai_decision_record *r;
	u64 id;
	u32 count = 0;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, w);
	ai_effect_test_reset();

	/* 开窗 → 铸一条启发式决策记录（record_heuristic 内部把 id 绑到
	 * 最近 pending 窗=本窗）→ 绑定一致性 */
	ai_effect_open(AI_HOOK_SCHED_VRUNTIME, 100, 200);
	KUNIT_EXPECT_EQ(test,
			ai_policy_record_heuristic(AI_POLICY_DOMAIN_SCHED, 1,
						   -100, 100, 200),
			AI_OK);
	recs = ring_read(test, &count);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, recs);
	KUNIT_ASSERT_GE(test, count, 1u);
	id = recs[count - 1].decision_id;
	KUNIT_EXPECT_NE(test, id, (u64)0);
	KUNIT_EXPECT_EQ(test, w->decision_id, (u32)id);

	/* 结算 GOOD+metric → 按 id 读回：ring 条目真被改写 */
	ai_effect_close(AI_HOOK_SCHED_VRUNTIME, AI_EFFECT_OUTCOME_GOOD, -7);
	KUNIT_EXPECT_EQ(test, w->used, (u8)0);
	KUNIT_EXPECT_EQ(test, w->outcome, (u8)AI_EFFECT_OUTCOME_GOOD);
	KUNIT_EXPECT_EQ(test, w->metric, -7L);
	KUNIT_EXPECT_GT(test, w->close_ns, (u64)0);
	r = ring_find(test, id);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, r);
	KUNIT_EXPECT_EQ(test, r->outcome, (u8)AI_EFFECT_OUTCOME_GOOD);
	KUNIT_EXPECT_GT(test, r->outcome_ts, (u64)0);
	KUNIT_EXPECT_EQ(test, r->metric_delta, (s64)-7);

	/* 窗口已关：重复 close 幂等（不重复计数、不重复回填） */
	ai_effect_close(AI_HOOK_SCHED_VRUNTIME, AI_EFFECT_OUTCOME_GOOD, -7);
	KUNIT_EXPECT_EQ(test, w->outcome, (u8)AI_EFFECT_OUTCOME_GOOD);
}

/* ---- 超时路径：回拨 open_ns 越过窗长 → tick 按 timeout 关窗回填 ---- */
static void effect_timeout_test(struct kunit *test)
{
	struct ai_decision_record *recs;
	struct ai_effect_stats st[AI_HOOK_NR];
	struct ai_effect_win *w = ai_effect_test_win(AI_HOOK_MM_READAHEAD);
	const struct ai_decision_record *r;
	u64 id, before;
	u32 count = 0;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, w);
	ai_effect_test_reset();

	/* 开窗+绑定一条记录，回拨 open_ns 越过 5s 窗长（readahead） */
	ai_effect_open(AI_HOOK_MM_READAHEAD, 1, 2);
	KUNIT_EXPECT_EQ(test,
			ai_policy_record_heuristic(AI_POLICY_DOMAIN_MM, 3,
						   1, 1, 2),
			AI_OK);
	recs = ring_read(test, &count);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, recs);
	id = recs[count - 1].decision_id;
	KUNIT_EXPECT_EQ(test, w->decision_id, (u32)id);

	ai_effect_stats_get(st);
	before = atomic64_read(&st[AI_HOOK_MM_READAHEAD].timeout);

	/* 测试内回拨开窗时刻（真实 1Hz tick 与本调用谁先结算均可：
	 * 终态一致，timeout 至多计一次） */
	w->open_ns -= 6ULL * NSEC_PER_SEC;
	ai_effect_tick();

	KUNIT_EXPECT_EQ(test, w->used, (u8)0);
	KUNIT_EXPECT_EQ(test, w->outcome, (u8)AI_EFFECT_OUTCOME_TIMEOUT);
	KUNIT_EXPECT_EQ(test, w->metric, 0L);
	r = ring_find(test, id);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, r);
	KUNIT_EXPECT_EQ(test, r->outcome, (u8)AI_EFFECT_OUTCOME_TIMEOUT);
	KUNIT_EXPECT_GT(test, r->outcome_ts, (u64)0);

	ai_effect_stats_get(st);
	KUNIT_EXPECT_EQ(test,
			atomic64_read(&st[AI_HOOK_MM_READAHEAD].timeout) - before,
			1ULL);
}

/* ---- 0 秒纯事件窗：tick 永不超时（结算器负责关窗）；
 * wakeup（K4.3 窗长 0→1s）到期改判 GOOD ---- */
static void effect_zero_deadline_test(struct kunit *test)
{
	struct ai_effect_win *w = ai_effect_test_win(AI_HOOK_MM_RECLAIM);

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, w);
	ai_effect_test_reset();

	/* reclaim 窗（时长 0）：回拨 1 小时，tick 仍不结算 */
	ai_effect_open(AI_HOOK_MM_RECLAIM, 0, 0);
	w->open_ns -= 3600ULL * NSEC_PER_SEC;
	ai_effect_tick();
	KUNIT_EXPECT_EQ(test, w->used, (u8)1);

	/* wakeup 窗（K4.3 起时长 1s）：到期 tick 按 GOOD 兜底
	 * （1 秒未被抢回必然没有误抢占；见 ai_effect.c 覆盖表） */
	ai_effect_open(AI_HOOK_SCHED_WAKEUP, 42, 0);
	w = ai_effect_test_win(AI_HOOK_SCHED_WAKEUP);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, w);
	w->open_ns -= 2ULL * NSEC_PER_SEC;
	ai_effect_tick();
	KUNIT_EXPECT_EQ(test, w->used, (u8)0);
	KUNIT_EXPECT_EQ(test, w->outcome, (u8)AI_EFFECT_OUTCOME_GOOD);
}

/* ---- stats 累计：good/bad/timeout 计数与 last_metric ---- */
static void effect_stats_test(struct kunit *test)
{
	struct ai_effect_stats st[AI_HOOK_NR];

	ai_effect_test_reset();

	ai_effect_open(AI_HOOK_SCHED_VRUNTIME, 0, 0);
	ai_effect_close(AI_HOOK_SCHED_VRUNTIME, AI_EFFECT_OUTCOME_GOOD, -3);
	ai_effect_open(AI_HOOK_SCHED_VRUNTIME, 0, 0);
	ai_effect_close(AI_HOOK_SCHED_VRUNTIME, AI_EFFECT_OUTCOME_BAD, 4);
	ai_effect_open(AI_HOOK_SCHED_VRUNTIME, 0, 0);
	ai_effect_close(AI_HOOK_SCHED_VRUNTIME, AI_EFFECT_OUTCOME_TIMEOUT, 0);

	ai_effect_stats_get(st);
	KUNIT_EXPECT_EQ(test,
			atomic64_read(&st[AI_HOOK_SCHED_VRUNTIME].good), 1LL);
	KUNIT_EXPECT_EQ(test,
			atomic64_read(&st[AI_HOOK_SCHED_VRUNTIME].bad), 1LL);
	KUNIT_EXPECT_EQ(test,
			atomic64_read(&st[AI_HOOK_SCHED_VRUNTIME].timeout), 1LL);
	KUNIT_EXPECT_EQ(test, st[AI_HOOK_SCHED_VRUNTIME].last_metric, 0L);

	/* 未结算窗（在途）不计数 */
	ai_effect_open(AI_HOOK_SCHED_VRUNTIME, 0, 0);
	ai_effect_stats_get(st);
	KUNIT_EXPECT_EQ(test,
			atomic64_read(&st[AI_HOOK_SCHED_VRUNTIME].good), 1LL);

	/* last_metric 跟随最近一次结算 */
	ai_effect_close(AI_HOOK_SCHED_VRUNTIME, AI_EFFECT_OUTCOME_GOOD, 55);
	ai_effect_stats_get(st);
	KUNIT_EXPECT_EQ(test, st[AI_HOOK_SCHED_VRUNTIME].last_metric, 55L);
	KUNIT_EXPECT_EQ(test,
			atomic64_read(&st[AI_HOOK_SCHED_VRUNTIME].good), 2LL);
}

/* ---- ENOENT 路径：fill_outcome 找不到/非法 id + 未绑定窗不触 ring ---- */
static void effect_fill_outcome_api_test(struct kunit *test)
{
	struct ai_decision_record *recs;
	struct ai_effect_stats st[AI_HOOK_NR];
	struct ai_effect_win *w = ai_effect_test_win(AI_HOOK_MM_RECLAIM);
	const struct ai_decision_record *r;
	u64 id;
	u32 count = 0;

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, w);
	ai_effect_test_reset();

	/* 直调 API 正路径：先铸一条记录再 fill 再读回比对 */
	KUNIT_EXPECT_EQ(test,
			ai_policy_record_heuristic(AI_POLICY_DOMAIN_MM, 4,
						   -1, 5, 6),
			AI_OK);
	recs = ring_read(test, &count);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, recs);
	id = recs[count - 1].decision_id;
	KUNIT_EXPECT_EQ(test, ai_policy_fill_outcome((u32)id,
						     AI_EFFECT_OUTCOME_GOOD,
						     42), 0);
	r = ring_find(test, id);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, r);
	KUNIT_EXPECT_EQ(test, r->outcome, (u8)AI_EFFECT_OUTCOME_GOOD);
	KUNIT_EXPECT_EQ(test, r->metric_delta, (s64)42);

	/* ring 里不存在的 id → -ENOENT（被覆盖/未铸造） */
	KUNIT_EXPECT_EQ(test,
			ai_policy_fill_outcome(0x7FFFFFFFU,
					       AI_EFFECT_OUTCOME_GOOD, 0),
			-ENOENT);
	/* id=0 → -EINVAL */
	KUNIT_EXPECT_EQ(test,
			ai_policy_fill_outcome(0, AI_EFFECT_OUTCOME_GOOD, 0),
			-EINVAL);

	/* 未绑定窗（decision_id=0）close：只结算统计，不触 ring 回填 */
	ai_effect_open(AI_HOOK_MM_RECLAIM, 5, 6);
	KUNIT_EXPECT_EQ(test, w->decision_id, (u32)0);
	ai_effect_close(AI_HOOK_MM_RECLAIM, AI_EFFECT_OUTCOME_BAD, 9);
	ai_effect_stats_get(st);
	KUNIT_EXPECT_EQ(test,
			atomic64_read(&st[AI_HOOK_MM_RECLAIM].bad), 1LL);
	KUNIT_EXPECT_EQ(test, st[AI_HOOK_MM_RECLAIM].last_metric, 9L);
	KUNIT_EXPECT_EQ(test, w->used, (u8)0);
}

#ifdef CONFIG_AIKERNEL_MM
/* ---- K4.1 re-OOM 判定纯函数：窗龄 / 开窗序 / 无窗三态 ---- */
static void k4_oom_reoom_judge_test(struct kunit *test)
{
	u64 now = 100ULL * NSEC_PER_SEC;
	u64 open = now - 30ULL * NSEC_PER_SEC;
	u64 last = now - 5ULL * NSEC_PER_SEC;

	/* 在途窗（开于上次 OOM 之前）+ 窗龄 30s <60s → re-OOM */
	KUNIT_EXPECT_TRUE(test, ai_mm_k4_oom_is_reoom(now, open, last));
	/* 窗龄 ≥60s → 非 re-OOM（交 tick 按 GOOD 兜底） */
	KUNIT_EXPECT_FALSE(test,
			   ai_mm_k4_oom_is_reoom(now, now - 61ULL * NSEC_PER_SEC, last));
	/* 窗开于上次 OOM 之后（本周期 badness 评分刚开）→ 非 re-OOM */
	KUNIT_EXPECT_FALSE(test,
			   ai_mm_k4_oom_is_reoom(now, now - NSEC_PER_MSEC, last));
	/* 无在途窗 / 首次 OOM（last=0）→ 非 re-OOM */
	KUNIT_EXPECT_FALSE(test, ai_mm_k4_oom_is_reoom(now, 0, last));
	KUNIT_EXPECT_FALSE(test, ai_mm_k4_oom_is_reoom(now, open, 0));
}

/* ---- K4.4 命中率判定纯函数：阈值 / 0 除 / 百分点 metric ---- */
static void k4_readahead_ratio_judge_test(struct kunit *test)
{
	long metric = 99;

	/* 50% 整 → GOOD，metric=0 */
	KUNIT_EXPECT_EQ(test,
			ai_mm_k4_readahead_outcome(50, 50, &metric),
			(u8)AI_EFFECT_OUTCOME_GOOD);
	KUNIT_EXPECT_EQ(test, metric, 0L);
	/* 49% → BAD，metric=-1 */
	KUNIT_EXPECT_EQ(test,
			ai_mm_k4_readahead_outcome(49, 51, &metric),
			(u8)AI_EFFECT_OUTCOME_BAD);
	KUNIT_EXPECT_EQ(test, metric, -1L);
	/* 全命中 → GOOD，metric=+50 */
	KUNIT_EXPECT_EQ(test,
			ai_mm_k4_readahead_outcome(8, 0, &metric),
			(u8)AI_EFFECT_OUTCOME_GOOD);
	KUNIT_EXPECT_EQ(test, metric, 50L);
	/* 0/0 防 0 除 → 中性 GOOD，metric=0 */
	KUNIT_EXPECT_EQ(test,
			ai_mm_k4_readahead_outcome(0, 0, &metric),
			(u8)AI_EFFECT_OUTCOME_GOOD);
	KUNIT_EXPECT_EQ(test, metric, 0L);
}
#endif /* CONFIG_AIKERNEL_MM */

#ifdef CONFIG_AIKERNEL_SCHED
/* ---- K4.3/K4.2 判定纯函数：误抢占方向 + 延迟水位方向 ---- */
static void k4_sched_judge_test(struct kunit *test)
{
	long metric = 99;

	/* wakee 1ms 内被切出 → BAD；≥1ms 任意 switch → GOOD；
	 * 1ms 内他人被切出 → NONE（继续观测） */
	KUNIT_EXPECT_EQ(test,
			ai_k4_wakeup_switch_outcome(42, 42, 500UL * NSEC_PER_USEC),
			(u8)AI_EFFECT_OUTCOME_BAD);
	KUNIT_EXPECT_EQ(test,
			ai_k4_wakeup_switch_outcome(7, 42, NSEC_PER_MSEC),
			(u8)AI_EFFECT_OUTCOME_GOOD);
	KUNIT_EXPECT_EQ(test,
			ai_k4_wakeup_switch_outcome(7, 42, NSEC_PER_USEC),
			(u8)AI_EFFECT_OUTCOME_NONE);

	/* 延迟水位：升→BAD（+10%），降→GOOD（-50%），无基线→中性 */
	KUNIT_EXPECT_EQ(test,
			ai_k4_vruntime_outcome(1000, 1100, &metric),
			(u8)AI_EFFECT_OUTCOME_BAD);
	KUNIT_EXPECT_EQ(test, metric, 10L);
	KUNIT_EXPECT_EQ(test,
			ai_k4_vruntime_outcome(1000, 500, &metric),
			(u8)AI_EFFECT_OUTCOME_GOOD);
	KUNIT_EXPECT_EQ(test, metric, -50L);
	KUNIT_EXPECT_EQ(test,
			ai_k4_vruntime_outcome(0, 500, &metric),
			(u8)AI_EFFECT_OUTCOME_GOOD);
	KUNIT_EXPECT_EQ(test, metric, 0L);
}
#endif /* CONFIG_AIKERNEL_SCHED */

/* ---- 分类槽 wakeups 预留字段：新插槽清零（本波不接自增点） ---- */
static void slot_wakeups_field_test(struct kunit *test)
{
	struct ai_proc_slot slot;
	int rc;

	/* 经 exec 路径真实插槽（模式同 ai_decision_test.c 的 mark_self） */
	ai_proc_exec_hook(current, "/bin/sh");
	rc = ai_proc_slot_get(task_pid_nr(current), &slot);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	if (rc == AI_OK)
		KUNIT_EXPECT_EQ(test, slot.wakeups, (u32)0);

	ai_proc_slot_remove(task_pid_nr(current));
}

static int effect_suite_init(struct kunit *test)
{
	ai_effect_test_reset();
	return 0;
}

static void effect_suite_exit(struct kunit *test)
{
	ai_effect_test_reset();
	ai_proc_slot_remove(task_pid_nr(current));
}

static struct kunit_case ai_effect_test_cases[] = {
	KUNIT_CASE(effect_open_fields_test),
	KUNIT_CASE(effect_settle_ring_fill_test),
	KUNIT_CASE(effect_timeout_test),
	KUNIT_CASE(effect_zero_deadline_test),
	KUNIT_CASE(effect_stats_test),
	KUNIT_CASE(effect_fill_outcome_api_test),
#ifdef CONFIG_AIKERNEL_MM
	KUNIT_CASE(k4_oom_reoom_judge_test),
	KUNIT_CASE(k4_readahead_ratio_judge_test),
#endif
#ifdef CONFIG_AIKERNEL_SCHED
	KUNIT_CASE(k4_sched_judge_test),
#endif
	KUNIT_CASE(slot_wakeups_field_test),
	{}
};

static struct kunit_suite ai_effect_test_suite = {
	.name = "ai_effect",
	.init = effect_suite_init,
	.exit = effect_suite_exit,
	.test_cases = ai_effect_test_cases,
};

kunit_test_suite(ai_effect_test_suite);
MODULE_LICENSE("GPL v2");

#endif /* CONFIG_AIKERNEL_RUNTIME */
