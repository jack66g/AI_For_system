// SPDX-License-Identifier: GPL-2.0
/*
 * ai_policy_safety.c - AIKernel 决策安全边界（all-ai 的安全带，Prompt 13）
 *
 * 三件套：
 *   1. global_enable：决策执行全局开关（/sys/kernel/ai/policy/global_enable）；
 *      execute() 首行 READ_ONCE 单分支检查，关闭时拒绝一切执行且不记录；
 *   2. max_impact_pct：最大影响幅度限制——参数变更幅度 > 范围×pct% 时
 *      clamp 到允许幅度并打 clamped 标记（决策全量记录 outcome=2）；
 *   3. 决策快照：已生效决策保存 (param_index, pid, pre_value)（64 槽环，
 *      满淘汰最旧），支持按 decision_id 回滚 / 全部回滚（测试还原/失控恢复）。
 *
 * 接口见 ai_policy_safety.h；门控 CONFIG_AIKERNEL_RUNTIME（n 配置 stub）。
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include "ai_policy_safety.h"

/* ---- 全局状态 ---- */

static int ai_safety_enabled = AI_SAFETY_DEFAULT_ENABLE;
static u32 ai_safety_max_impact = AI_SAFETY_DEFAULT_MAX_IMPACT;
static u64 ai_safety_rejected;   /* 被限制/拒绝的决策累计 */

/* ---- 决策快照环（slot 序 = 插入序） ---- */

static struct ai_safety_snapshot ai_safety_snap[AI_SAFETY_SNAPSHOT_MAX]
					____cacheline_aligned_in_smp;
static unsigned int ai_safety_snap_head;
static unsigned int ai_safety_snap_count;
static DEFINE_SPINLOCK(ai_safety_lock);

int ai_policy_safety_get_enabled(void)
{
	return READ_ONCE(ai_safety_enabled);
}
EXPORT_SYMBOL_GPL(ai_policy_safety_get_enabled);

int ai_policy_safety_set_enabled(int enable)
{
	WRITE_ONCE(ai_safety_enabled, enable ? 1 : 0);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_policy_safety_set_enabled);

u32 ai_policy_safety_get_max_impact(void)
{
	return READ_ONCE(ai_safety_max_impact);
}
EXPORT_SYMBOL_GPL(ai_policy_safety_get_max_impact);

int ai_policy_safety_set_max_impact(u32 pct)
{
	if (pct > 100)
		return AI_ERR_INVALID_ARG;
	WRITE_ONCE(ai_safety_max_impact, pct);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_policy_safety_set_max_impact);

int ai_policy_safety_limit_value(s64 param_min, s64 param_max,
				 s64 cur, s64 *requested, u8 *clamped)
{
	s64 req, allowed, lo, hi;
	u32 pct;

	if (!requested)
		return AI_ERR_INVALID_ARG;

	req = *requested;
	if (clamped)
		*clamped = 0;

	/* ① 硬范围 clamp */
	if (req < param_min || req > param_max) {
		req = clamp(req, param_min, param_max);
		if (clamped)
			*clamped = 1;
	}

	/* ② 最大影响幅度限制 */
	pct = READ_ONCE(ai_safety_max_impact);
	if (pct < 100) {
		allowed = (param_max - param_min) * (s64)pct / 100;
		lo = cur - allowed;
		hi = cur + allowed;
		if (req < lo || req > hi) {
			req = clamp(req, lo, hi);
			if (clamped)
				*clamped = 1;
		}
	}

	*requested = req;
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_policy_safety_limit_value);

/* ---- 决策快照 ---- */

static struct ai_safety_snapshot *ai_safety_slot(unsigned int idx)
{
	return &ai_safety_snap[idx & (AI_SAFETY_SNAPSHOT_MAX - 1)];
}

int ai_policy_safety_snapshot_save(u64 decision_id, u32 param_index,
				   s32 pid, s64 pre_value)
{
	unsigned long flags;
	struct ai_safety_snapshot *s;
	unsigned int i;
	u8 n;

	if (!decision_id)
		return AI_ERR_INVALID_ARG;

	spin_lock_irqsave(&ai_safety_lock, flags);

	/* 找该决策的既有快照（有效槽 = [head-count, head-1]，最旧在前） */
	for (i = 0; i < ai_safety_snap_count; i++) {
		s = ai_safety_slot(ai_safety_snap_head - ai_safety_snap_count
				   + i);
		if (s->decision_id == decision_id) {
			/* 去重：同参数已保存则覆盖 */
			for (n = 0; n < s->n; n++) {
				if (s->params[n].param_index == param_index &&
				    s->params[n].pid == pid) {
					s->params[n].pre_value = pre_value;
					spin_unlock_irqrestore(&ai_safety_lock,
							       flags);
					return AI_OK;
				}
			}
			if (s->n < AI_SAFETY_SNAPSHOT_PARAMS) {
				s->params[s->n].param_index = param_index;
				s->params[s->n].pid = pid;
				s->params[s->n].pre_value = pre_value;
				s->n++;
			}
			spin_unlock_irqrestore(&ai_safety_lock, flags);
			return AI_OK;
		}
	}

	/* 新决策：占新槽（满则淘汰最旧，slot 序 = 插入序） */
	s = ai_safety_slot(ai_safety_snap_head);
	memset(s, 0, sizeof(*s));
	s->decision_id = decision_id;
	s->ts = ktime_get_ns();
	s->params[0].param_index = param_index;
	s->params[0].pid = pid;
	s->params[0].pre_value = pre_value;
	s->n = 1;
	if (ai_safety_snap_count < AI_SAFETY_SNAPSHOT_MAX)
		ai_safety_snap_count++;
	ai_safety_snap_head = (ai_safety_snap_head + 1) &
			      (AI_SAFETY_SNAPSHOT_MAX - 1);

	spin_unlock_irqrestore(&ai_safety_lock, flags);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_policy_safety_snapshot_save);

int ai_policy_safety_rollback_decision(u64 decision_id,
				       ai_safety_restore_t restore)
{
	unsigned long flags;
	struct ai_safety_snapshot *s = NULL;
	unsigned int i;
	u8 k;

	if (!decision_id)
		return AI_ERR_INVALID_ARG;

	spin_lock_irqsave(&ai_safety_lock, flags);
	for (i = 0; i < ai_safety_snap_count; i++) {
		s = ai_safety_slot(ai_safety_snap_head - ai_safety_snap_count
				   + i);
		if (s->decision_id == decision_id)
			break;
	}
	if (i == ai_safety_snap_count) {
		spin_unlock_irqrestore(&ai_safety_lock, flags);
		return AI_OK;   /* 无快照 = 无可回滚 */
	}

	if (restore) {
		for (k = 0; k < s->n; k++)
			restore(s->params[k].param_index,
				s->params[k].pid, s->params[k].pre_value);
	}
	s->decision_id = 0;
	ai_safety_snap_count--;
	spin_unlock_irqrestore(&ai_safety_lock, flags);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_policy_safety_rollback_decision);

int ai_policy_safety_rollback_all(ai_safety_restore_t restore)
{
	unsigned long flags;
	unsigned int i, n;

	if (restore) {
		/* 逆序恢复（最新决策先回滚：有效槽 [head-count, head-1]） */
		spin_lock_irqsave(&ai_safety_lock, flags);
		n = ai_safety_snap_count;
		for (i = 0; i < n; i++) {
			struct ai_safety_snapshot *s =
				ai_safety_slot(ai_safety_snap_head - 1 - i);
			u8 k;

			for (k = 0; k < s->n; k++)
				restore(s->params[k].param_index,
					s->params[k].pid,
					s->params[k].pre_value);
		}
		spin_unlock_irqrestore(&ai_safety_lock, flags);
	}

	spin_lock_irqsave(&ai_safety_lock, flags);
	memset(ai_safety_snap, 0, sizeof(ai_safety_snap));
	ai_safety_snap_head = 0;
	ai_safety_snap_count = 0;
	spin_unlock_irqrestore(&ai_safety_lock, flags);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_policy_safety_rollback_all);

int ai_policy_safety_stats(u32 *snapshots, u64 *rejected)
{
	unsigned long flags;

	spin_lock_irqsave(&ai_safety_lock, flags);
	if (snapshots)
		*snapshots = ai_safety_snap_count;
	if (rejected)
		*rejected = ai_safety_rejected;
	spin_unlock_irqrestore(&ai_safety_lock, flags);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_policy_safety_stats);

/* 供 ai_control 应用路径累计被限制决策数（模块内符号，非公共接口） */
void ai_policy_safety_note_rejected(void)
{
	WRITE_ONCE(ai_safety_rejected, READ_ONCE(ai_safety_rejected) + 1);
}
