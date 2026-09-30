// SPDX-License-Identifier: GPL-2.0
/*
 * ai_decision_test.c - W3 决策注入查询层 KUnit 套件
 *
 * 覆盖：
 *   - 三层开关默认关：master=0 / per-hook=0 时 query 恒 0（原生行为）；
 *   - 挂点语义与符号：OOM ±200、vruntime ∓100‰、wakeup 0/1、
 *     readahead ±1、reclaim ±1（按分类槽 INTERACTIVE/BATCH）；
 *   - 值域硬钳制：外部决策源返回越界值被查询层封顶（第二阶段模型边界）；
 *   - 异常回退：分类槽 miss → 0 + fallback 计数；
 *   - 全量记账：queries/injected/effects 计数与 decisions ring 采样
 *     （source=AI_DEC_SRC_HEURISTIC）；
 *   - ACT 参数族 ai.decision_*（REAL，默认 0）注册存在性。
 * 退出还原：master=0、per-hook=0、决策源=启发式、清理 current 槽位。
 */
#include <kunit/test.h>
#include <linux/sched.h>

#include "../core/ai_types.h"
#include "../core/ai_proc.h"
#include "../core/ai_control.h"
#include "../core/ai_policy.h"
#include "../core/ai_decision.h"

#ifdef CONFIG_AIKERNEL_RUNTIME

static pid_t self_pid(void)
{
	return task_pid_nr(current);
}

/* 经 exec 路径启发式给 current 打分类标（真实公共接口，无测试旁路）。
 * 路径必须命中 exec_hook 的模式表：/usr/bin/grep→BATCH、/bin/sh→INTERACTIVE
 * （/bin/grep 不在表内：未命中模式会保留原分类，kunit 线程=KERNEL）。 */
static void mark_self(struct kunit *test, enum ai_proc_class cls)
{
	if (cls == AI_PROC_CLASS_INTERACTIVE)
		ai_proc_exec_hook(current, "/bin/sh");
	else
		ai_proc_exec_hook(current, "/usr/bin/grep");
	KUNIT_ASSERT_TRUE(test, ai_proc_class_peek(self_pid()) == (int)cls);
}

static void enable_all(u8 on)
{
	enum ai_hook_id h;

	ai_decision_set_master(on);
	for (h = AI_HOOK_OOM_BADNESS; h < AI_HOOK_NR; h++)
		ai_decision_set_hook_enable(h, on);
}

/* ---- 默认关：master=0 / per-hook=0 → 恒 0 ---- */
static void decision_default_off_test(struct kunit *test)
{
	struct ai_hook_ctx ctx = { .pid = self_pid() };

	KUNIT_EXPECT_EQ(test, (int)ai_decision_get_master(), 0);
	KUNIT_EXPECT_EQ(test,
			(int)ai_decision_get_hook_enable(AI_HOOK_OOM_BADNESS), 0);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_OOM_BADNESS, &ctx), 0);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_SCHED_VRUNTIME, &ctx), 0);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_MM_READAHEAD, &ctx), 0);
}

/* ---- 挂点语义：OOM ±200（钳制值）与开关还原 ---- */
static void decision_oom_bias_test(struct kunit *test)
{
	struct ai_hook_ctx ctx = { .pid = self_pid() };

	enable_all(1);

	mark_self(test, AI_PROC_CLASS_BATCH);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_OOM_BADNESS, &ctx),
			AI_DEC_OOM_BIAS_MAX);

	mark_self(test, AI_PROC_CLASS_INTERACTIVE);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_OOM_BADNESS, &ctx),
			-AI_DEC_OOM_BIAS_MAX);

	/* per-hook 关闭即回 0（第二层开关独立生效） */
	ai_decision_set_hook_enable(AI_HOOK_OOM_BADNESS, 0);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_OOM_BADNESS, &ctx), 0);

	enable_all(0);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_OOM_BADNESS, &ctx), 0);
}

/* ---- 挂点语义：调度两挂点（vruntime ∓100‰ / wakeup 0/1） ---- */
static void decision_sched_bias_test(struct kunit *test)
{
	struct ai_hook_ctx ctx = { .pid = self_pid() };

	enable_all(1);

	mark_self(test, AI_PROC_CLASS_INTERACTIVE);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_SCHED_VRUNTIME, &ctx),
			-AI_DEC_SCHED_PCT_MAX);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_SCHED_WAKEUP, &ctx),
			AI_DEC_WAKEUP_BOOST_MAX);

	mark_self(test, AI_PROC_CLASS_BATCH);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_SCHED_VRUNTIME, &ctx),
			AI_DEC_SCHED_PCT_MAX);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_SCHED_WAKEUP, &ctx), 0);

	enable_all(0);
}

/* ---- 挂点语义：mm 两挂点（readahead ±1 / reclaim ±1） ---- */
static void decision_mm_bias_test(struct kunit *test)
{
	struct ai_hook_ctx ctx = { .pid = self_pid() };

	enable_all(1);

	mark_self(test, AI_PROC_CLASS_INTERACTIVE);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_MM_READAHEAD, &ctx),
			AI_DEC_RA_SHIFT_MAX);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_MM_RECLAIM, &ctx),
			AI_DEC_RECLAIM_PRIO_MAX);

	mark_self(test, AI_PROC_CLASS_BATCH);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_MM_READAHEAD, &ctx),
			-AI_DEC_RA_SHIFT_MAX);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_MM_RECLAIM, &ctx),
			-AI_DEC_RECLAIM_PRIO_MAX);

	enable_all(0);
}

/* ---- 异常回退：分类槽 miss → 0 + fallback 计数 ---- */
static void decision_fallback_test(struct kunit *test)
{
	struct ai_decision_stats st0, st1;
	struct ai_hook_ctx ctx = { .pid = 1234567 };   /* 不存在的 pid */

	enable_all(1);
	ai_decision_stats_get(&st0);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_OOM_BADNESS, &ctx), 0);
	ai_decision_stats_get(&st1);
	KUNIT_EXPECT_EQ(test, (int)(st1.hook[AI_HOOK_OOM_BADNESS].fallback -
				    st0.hook[AI_HOOK_OOM_BADNESS].fallback), 1);
	KUNIT_EXPECT_EQ(test, (int)(st1.hook[AI_HOOK_OOM_BADNESS].queries -
				    st0.hook[AI_HOOK_OOM_BADNESS].queries), 1);

	enable_all(0);
}

/* ---- 值域硬钳制 + 决策源替换（第二阶段模型接入点） ---- */
static s32 oversize_source(enum ai_hook_id hook, const struct ai_hook_ctx *ctx)
{
	return (hook == AI_HOOK_MM_RECLAIM) ? -9999 : 9999;
}

static void decision_source_clamp_test(struct kunit *test)
{
	struct ai_hook_ctx ctx = { .pid = self_pid() };

	enable_all(1);
	KUNIT_EXPECT_EQ(test, ai_decision_set_source(oversize_source), AI_OK);

	/* 越界正负值一律被编译期常量封顶（模型决策的硬安全边界） */
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_OOM_BADNESS, &ctx),
			AI_DEC_OOM_BIAS_MAX);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_MM_RECLAIM, &ctx),
			-AI_DEC_RECLAIM_PRIO_MAX);

	/* NULL = 恢复内置启发式 */
	KUNIT_EXPECT_EQ(test, ai_decision_set_source(NULL), AI_OK);
	mark_self(test, AI_PROC_CLASS_BATCH);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_OOM_BADNESS, &ctx),
			AI_DEC_OOM_BIAS_MAX);

	enable_all(0);
}

/* ---- 全量记账：queries/injected/effects + decisions ring 采样 ---- */
static void decision_accounting_test(struct kunit *test)
{
	struct ai_decision_stats st0, st1;
	struct ai_hook_ctx ctx = { .pid = self_pid() };
	struct ai_policy_stats ps0, ps1;

	enable_all(1);
	mark_self(test, AI_PROC_CLASS_BATCH);

	ai_decision_stats_get(&st0);
	KUNIT_EXPECT_EQ(test, ai_policy_stats_get(&ps0), AI_OK);
	KUNIT_EXPECT_EQ(test, ai_decision_query(AI_HOOK_OOM_BADNESS, &ctx),
			AI_DEC_OOM_BIAS_MAX);
	ai_decision_note_effect(AI_HOOK_OOM_BADNESS, 500, 700);
	ai_decision_stats_get(&st1);
	KUNIT_EXPECT_EQ(test, (int)(st1.hook[AI_HOOK_OOM_BADNESS].queries -
				    st0.hook[AI_HOOK_OOM_BADNESS].queries), 1);
	KUNIT_EXPECT_EQ(test, (int)(st1.hook[AI_HOOK_OOM_BADNESS].injected -
				    st0.hook[AI_HOOK_OOM_BADNESS].injected), 1);
	KUNIT_EXPECT_EQ(test, (int)(st1.hook[AI_HOOK_OOM_BADNESS].effects -
				    st0.hook[AI_HOOK_OOM_BADNESS].effects), 1);
	KUNIT_EXPECT_EQ(test, st1.hook[AI_HOOK_OOM_BADNESS].last_bias,
			AI_DEC_OOM_BIAS_MAX);
	KUNIT_EXPECT_EQ(test, st1.hook[AI_HOOK_OOM_BADNESS].last_aux1, 700);

	/* 首次 note_effect 必然穿透节流（last_ring_j 初值 0）→ decisions
	 * ring 出现 source=AI_DEC_SRC_HEURISTIC 采样，decisions_total 增长 */
	KUNIT_EXPECT_EQ(test, ai_policy_stats_get(&ps1), AI_OK);
	KUNIT_EXPECT_GE(test, (int)(ps1.decisions_total - ps0.decisions_total), 1);

	enable_all(0);
}

/* ---- ACT 参数族存在性：REAL 标志 + 默认 0 ---- */
static void decision_act_params_test(struct kunit *test)
{
	static const char *const names[] = {
		"ai.decision_inject", "ai.decision_oom",
		"ai.decision_sched", "ai.decision_mm",
	};
	struct ai_control_param p;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		int idx = ai_control_find(names[i]);

		KUNIT_EXPECT_GE(test, idx, 0);
		if (idx < 0)
			continue;
		KUNIT_EXPECT_EQ(test, ai_control_query((u32)idx, &p), AI_OK);
		KUNIT_EXPECT_NE(test, (u32)(p.flags & AI_CTRL_F_REAL), 0U);
		KUNIT_EXPECT_EQ(test, (int)p.default_val, 0);
	}
}

static int decision_suite_init(struct kunit *test)
{
	/* 启动上下文里测试可能把 master 留 1（前序套件扰动）→ 先归零 */
	enable_all(0);
	return 0;
}

static void decision_suite_exit(struct kunit *test)
{
	enable_all(0);
	ai_decision_set_source(NULL);
	ai_proc_slot_remove(task_pid_nr(current));
}

static struct kunit_case ai_decision_test_cases[] = {
	KUNIT_CASE(decision_default_off_test),
	KUNIT_CASE(decision_oom_bias_test),
	KUNIT_CASE(decision_sched_bias_test),
	KUNIT_CASE(decision_mm_bias_test),
	KUNIT_CASE(decision_fallback_test),
	KUNIT_CASE(decision_source_clamp_test),
	KUNIT_CASE(decision_accounting_test),
	KUNIT_CASE(decision_act_params_test),
	{}
};

static struct kunit_suite ai_decision_test_suite = {
	.name = "ai_decision",
	.init = decision_suite_init,
	.exit = decision_suite_exit,
	.test_cases = ai_decision_test_cases,
};

kunit_test_suite(ai_decision_test_suite);
MODULE_LICENSE("GPL v2");

#endif /* CONFIG_AIKERNEL_RUNTIME */
