// SPDX-License-Identifier: GPL-2.0
/*
 * ai_effect.c - AIKernel 效果归因环（K4.0）
 *
 * 职责一句话：给每个 AI 注入动作开 per-hook 单槽「效果窗口」，
 * 窗口结算后把 outcome 回填到决策 ring（ai_policy_fill_outcome），
 * 让启发式注入从"只记账"升级为"效果可归因"。
 *
 * 三笔账：
 *   1. 开窗/绑定（写侧=钩子原子上下文，rq 锁内）：note_effect 开窗
 *      （纯字段写+时间戳），record_heuristic 铸完 id 绑到最近
 *      pending 窗；
 *   2. 结算（ai_effect_close，结算器=后续挂点波的真实观测点）：关窗
 *      + 回填 ring + per-hook good/bad/timeout 累计 + last_metric
 *      （mispreempt 等指标语义由结算器定义，本层只存）；
 *   3. 1Hz tick（ai_sched 采样 kthread 尾部）：到 per-hook 窗长
 *      未结算 → outcome=TIMEOUT 兜底关窗回填（0 秒纯事件窗不超时）。
 *
 * 并发模型：全字段 WRITE_ONCE/READ_ONCE，无锁无分配（开窗路径零睡眠
 * 零自旋）；单槽 pending 竞态容忍=最后写赢（新窗覆盖未结算旧窗=放弃
 * 旧窗，不计数）。tick 与结算器并发关同一窗时字段以交错写为准，统计
 * 至多多计一次——观测面近似，可接受（与 ai_decision.c 记账同级语义）。
 */

#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/string.h>
#include <linux/errno.h>
#include "ai_types.h"
#include "ai_policy.h"
#include "ai_effect.h"

/* ---- per-hook 单槽 pending 窗 + 结算累计（全部静态零初始化） ---- */

static struct ai_effect_win ai_effect_wins[AI_HOOK_NR];
static struct ai_effect_stats ai_effect_acc[AI_HOOK_NR];

/* 窗口时长（秒→ns；与 enum ai_hook_id 一一对应，0=tick 不超时结算） */
static const u64 ai_effect_win_ns[AI_HOOK_NR] = {
	[AI_HOOK_OOM_BADNESS]    = (u64)AI_EFFECT_WIN_SEC_OOM * NSEC_PER_SEC,
	[AI_HOOK_SCHED_VRUNTIME] = (u64)AI_EFFECT_WIN_SEC_VRUNTIME * NSEC_PER_SEC,
	[AI_HOOK_SCHED_WAKEUP]   = (u64)AI_EFFECT_WIN_SEC_WAKEUP * NSEC_PER_SEC,
	[AI_HOOK_MM_READAHEAD]   = (u64)AI_EFFECT_WIN_SEC_READAHEAD * NSEC_PER_SEC,
	[AI_HOOK_MM_RECLAIM]     = (u64)AI_EFFECT_WIN_SEC_RECLAIM * NSEC_PER_SEC,
};

/* K4 结算器约定：per-hook 到期 outcome 覆盖表（tick 兜底用，默认
 * TIMEOUT=到期未见观测点，非效果为正）。OOM（K4.1）：60s 无 re-OOM =
 * 偏置方向正确 → GOOD；wakeup（K4.3）：1s 未被抢回 = 无误抢占 →
 * GOOD。 */
static const u8 ai_effect_tick_outcome[AI_HOOK_NR] = {
	/* q17 后真机 KUnit 勘误：指定初始化器未列项默认 0=NONE——到期窗
	 * 被静默结算成 NONE（不计数/ring 回填 0）。显式全表： */
	[AI_HOOK_OOM_BADNESS]    = AI_EFFECT_OUTCOME_GOOD,
	[AI_HOOK_SCHED_VRUNTIME] = AI_EFFECT_OUTCOME_TIMEOUT,
	[AI_HOOK_SCHED_WAKEUP]   = AI_EFFECT_OUTCOME_GOOD,
	[AI_HOOK_MM_READAHEAD]   = AI_EFFECT_OUTCOME_TIMEOUT,
	[AI_HOOK_MM_RECLAIM]     = AI_EFFECT_OUTCOME_TIMEOUT,
};

void ai_effect_open(enum ai_hook_id hook, long aux0, long aux1)
{
	struct ai_effect_win *w;

	if (unlikely((unsigned int)hook >= AI_HOOK_NR))
		return;
	w = &ai_effect_wins[hook];
	/* 先写载荷后发布 used（读者按 used=1 视为在途；撕裂容忍）；
	 * 单槽覆盖=放弃未结算旧窗（不计数，K4.0 采样近似语义） */
	WRITE_ONCE(w->decision_id, 0);
	WRITE_ONCE(w->close_ns, 0);
	WRITE_ONCE(w->outcome, AI_EFFECT_OUTCOME_NONE);
	WRITE_ONCE(w->metric, 0);
	WRITE_ONCE(w->aux0, aux0);
	WRITE_ONCE(w->aux1, aux1);
	WRITE_ONCE(w->open_ns, ktime_get_ns());
	WRITE_ONCE(w->used, 1);
}
EXPORT_SYMBOL_GPL(ai_effect_open);

void ai_effect_bind(enum ai_hook_id hook, u32 decision_id)
{
	struct ai_effect_win *w;

	if (unlikely((unsigned int)hook >= AI_HOOK_NR))
		return;
	w = &ai_effect_wins[hook];
	if (!READ_ONCE(w->used))
		return;   /* 无在途窗（开窗前铸记录）：丢弃，等下一窗 */
	WRITE_ONCE(w->decision_id, decision_id);
}
EXPORT_SYMBOL_GPL(ai_effect_bind);

/* 关窗结算公共路径：写字段 → 回填 ring → 累计统计 */
static void ai_effect_settle(unsigned int hook, struct ai_effect_win *w,
			     u8 outcome, long metric)
{
	u32 id;

	/* 先收 used 再取 id：与并发 open 的竞态=最后写赢（容忍） */
	WRITE_ONCE(w->used, 0);
	WRITE_ONCE(w->outcome, outcome);
	WRITE_ONCE(w->metric, metric);
	WRITE_ONCE(w->close_ns, ktime_get_ns());

	id = READ_ONCE(w->decision_id);
	if (id) {
		/* 回填决策 ring；被覆盖滚出 ring（-ENOENT）静默容忍：
		 * 效果观测晚于记录回收是归因环的正常损耗 */
		ai_policy_fill_outcome(id, outcome, metric);
	}

	if (outcome == AI_EFFECT_OUTCOME_GOOD)
		atomic64_inc(&ai_effect_acc[hook].good);
	else if (outcome == AI_EFFECT_OUTCOME_BAD)
		atomic64_inc(&ai_effect_acc[hook].bad);
	else if (outcome == AI_EFFECT_OUTCOME_TIMEOUT)
		atomic64_inc(&ai_effect_acc[hook].timeout);
	WRITE_ONCE(ai_effect_acc[hook].last_metric, metric);
}

void ai_effect_close(enum ai_hook_id hook, u8 outcome, long metric)
{
	struct ai_effect_win *w;

	if (unlikely((unsigned int)hook >= AI_HOOK_NR))
		return;
	w = &ai_effect_wins[hook];
	if (!READ_ONCE(w->used))
		return;   /* 无在途窗：幂等空转（不重复计数） */
	ai_effect_settle((unsigned int)hook, w, outcome, metric);
}
EXPORT_SYMBOL_GPL(ai_effect_close);

bool ai_effect_win_peek(enum ai_hook_id hook, struct ai_effect_win *out)
{
	struct ai_effect_win *w;

	if (unlikely((unsigned int)hook >= AI_HOOK_NR))
		return false;
	w = &ai_effect_wins[hook];
	if (!READ_ONCE(w->used))
		return false;   /* 无在途窗 */
	if (out)
		memcpy(out, w, sizeof(*out));
	return true;
}
EXPORT_SYMBOL_GPL(ai_effect_win_peek);

void ai_effect_tick(void)
{
	enum ai_hook_id hook;
	u64 now = ktime_get_ns();

	for (hook = AI_HOOK_OOM_BADNESS; hook < AI_HOOK_NR; hook++) {
		struct ai_effect_win *w = &ai_effect_wins[hook];
		u64 deadline = ai_effect_win_ns[hook];
		u64 open_ns;

		if (!deadline || !READ_ONCE(w->used))
			continue;   /* 纯事件窗 / 无在途窗 */
		open_ns = READ_ONCE(w->open_ns);
		if (likely(now >= open_ns) && now - open_ns >= deadline)
			ai_effect_settle((unsigned int)hook, w,
					 ai_effect_tick_outcome[hook], 0);
	}
}
EXPORT_SYMBOL_GPL(ai_effect_tick);

void ai_effect_stats_get(struct ai_effect_stats out[AI_HOOK_NR])
{
	if (!out)
		return;
	/* 无锁近似一致快照（观测面用；跨字段允许轻微撕裂） */
	memcpy(out, ai_effect_acc, sizeof(ai_effect_acc));
}
EXPORT_SYMBOL_GPL(ai_effect_stats_get);

#ifdef CONFIG_AIKERNEL_KUNIT_TEST
/* K4.0 测试钩子（ai_effect_test.c / ai_decision_test.c）：窗口槽直读
 * （断言字段 / 测试内回拨 open_ns 强制超时）与整体复位；不进生产链 */
struct ai_effect_win *ai_effect_test_win(enum ai_hook_id hook)
{
	if ((unsigned int)hook >= AI_HOOK_NR)
		return NULL;
	return &ai_effect_wins[hook];
}

void ai_effect_test_reset(void)
{
	memset(ai_effect_wins, 0, sizeof(ai_effect_wins));
	memset(ai_effect_acc, 0, sizeof(ai_effect_acc));
}
#endif /* CONFIG_AIKERNEL_KUNIT_TEST */
