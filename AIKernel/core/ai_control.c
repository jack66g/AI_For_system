// SPDX-License-Identifier: GPL-2.0
/*
 * ai_control.c - AIKernel 可控制参数表（数据计划 20.3，Prompt 13）
 *
 * 数据计划 20.3 落地：每条可控制参数 = 一个策略接口。
 *   - 参数表（64 槽，spinlock）：name/domain/flags/min/max/current/default/apply；
 *   - ai_control_register() → 自动 ai_policy_register()（动作名 = 参数名）；
 *   - 统一策略处理器 ai_control_policy_handler()：
 *       值提取（全局 data[0] / task data[0]=pid data[1]=值）→ 安全边界限幅
 *       （ai_policy_safety_limit_value：硬范围 + max_impact 幅度）→ 决策前值
 *       快照（ai_policy_safety_snapshot_save）→ apply（失败 → 内部回退旧值，
 *       返回错误 → execute 记录 outcome=3）→ current 更新；
 *   - 内置立即生效参数（ai_control_init 注册）：sched.nice/affinity/oom_score
 *     （均经公共头符号 find_get_task_by_vpid/set_user_nice/set_cpus_allowed_ptr，
 *     task_lock 保护；AIKernel 全部 built-in 链接，无需新 EXPORT）；
 *   - mm.swappiness 由 mm/ai_mm.c 注册（经 mm/vmscan.c 门控访问器）；
 *   - 其余域参数由各子系统模块 init 注册（接口预留：仅 clamp+快照+记录）。
 *
 * 门控 CONFIG_AIKERNEL_RUNTIME（n 配置 stub，零开销零回归）。
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/sched/rt.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include "ai_control.h"
#include "ai_policy_safety.h"

#define AI_CONTROL_POLICY_PRIORITY  100

static struct ai_control_param ai_ctrl_tab[AI_CONTROL_MAX_PARAMS];
static unsigned int ai_ctrl_count;
static DEFINE_SPINLOCK(ai_ctrl_lock);

static int ai_control_index(const struct ai_control_param *p)
{
	return (int)(p - ai_ctrl_tab);
}

static struct ai_control_param *ai_control_find_locked(const char *name)
{
	unsigned int i;

	for (i = 0; i < ai_ctrl_count; i++)
		if (strcmp(ai_ctrl_tab[i].name, name) == 0)
			return &ai_ctrl_tab[i];
	return NULL;
}

int ai_control_find(const char *name)
{
	struct ai_control_param *p;
	unsigned long flags;
	int rc = AI_ERR_NOT_FOUND;

	if (!name)
		return AI_ERR_INVALID_ARG;

	spin_lock_irqsave(&ai_ctrl_lock, flags);
	p = ai_control_find_locked(name);
	if (p)
		rc = ai_control_index(p);
	spin_unlock_irqrestore(&ai_ctrl_lock, flags);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_control_find);

int ai_control_query(u32 index, struct ai_control_param *out)
{
	unsigned long flags;
	int rc = AI_ERR_NOT_FOUND;

	if (!out)
		return AI_ERR_INVALID_ARG;

	spin_lock_irqsave(&ai_ctrl_lock, flags);
	if (index < ai_ctrl_count) {
		memcpy(out, &ai_ctrl_tab[index], sizeof(*out));
		rc = AI_OK;
	}
	spin_unlock_irqrestore(&ai_ctrl_lock, flags);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_control_query);

int ai_control_get_value(const char *name, s64 *value)
{
	struct ai_control_param *p;
	unsigned long flags;
	int rc = AI_ERR_NOT_FOUND;

	if (!name || !value)
		return AI_ERR_INVALID_ARG;

	spin_lock_irqsave(&ai_ctrl_lock, flags);
	p = ai_control_find_locked(name);
	if (p) {
		*value = p->cur;
		rc = AI_OK;
	}
	spin_unlock_irqrestore(&ai_ctrl_lock, flags);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_control_get_value);

/* ---- 统一策略处理器（动作名 = 参数名，priority=100） ---- */

static int ai_control_apply_param(struct ai_control_param *p, s32 pid,
				  s64 value, const s64 *data)
{
	s64 eff = value;
	int rc = AI_OK;

	if (p->apply_ex)
		rc = p->apply_ex(p, pid, value, &eff, data);
	else if (p->apply)
		rc = p->apply(p, pid, value, &eff);
	if (rc != AI_OK)
		return rc;
	WRITE_ONCE(p->cur, eff);
	return AI_OK;
}

static int ai_control_policy_handler(const struct ai_policy_ctx *ctx,
				     void *arg)
{
	struct ai_control_param *p = arg;
	s64 requested, cur_val, pre;
	u8 clamped = 0;
	s32 pid = 0;
	int rc;

	if (!p || !ctx)
		return AI_ERR_INVALID_ARG;

	/*
	 * T2 问题 6 根因修复：v1 广播（param 为空）跳过 reserved 参数。
	 * 广播的 decision_data[0] 对 TASK 参数解释为 pid、对全局参数解释
	 * 为值（既定 v1 语义）；reserved 参数（无 AI_CTRL_F_REAL，无 apply，
	 * 仅接口预留）在广播里拿到的是无关值——T2 实测 mock 广播
	 * {"pid":1,"value":3} 时 sched.timeslice 把 data[0]=pid(1) 当值
	 * 写入，current 20→1。reserved 参数无真实内核效果，被灌值纯属
	 * 参数表污染，故广播直接跳过。v2 定向（param 非空）不受影响。
	 */
	if (!ctx->param[0] && !(p->flags & AI_CTRL_F_REAL))
		return AI_ERR_NOT_FOUND;

	if (p->flags & AI_CTRL_F_TASK) {
		pid = (s32)ctx->decision_data[0];
		if (pid <= 0)
			return AI_ERR_INVALID_ARG;
		requested = (s64)ctx->decision_data[1];
	} else {
		requested = (s64)ctx->decision_data[0];
	}

	/* 当前值：s64 对齐读原子（x86_64），快路径免锁 */
	cur_val = READ_ONCE(p->cur);
	pre = cur_val;

	/* 安全边界限幅（硬范围 + 最大影响幅度） */
	rc = ai_policy_safety_limit_value(p->min, p->max, cur_val,
					  &requested, &clamped);
	if (rc != AI_OK)
		return rc;
	if (clamped)
		ai_policy_safety_note_rejected();

	/* 快路径：值无变化 → 无副作用，免快照免应用（恒等决策 ≈15ns）；
	 * 事件型参数（AI_CTRL_F_EVENT，如 proc.signal）重复同值仍执行 */
	if (requested == cur_val && !(p->flags & AI_CTRL_F_EVENT))
		return clamped ? AI_POLICY_RC_CLAMPED : AI_OK;

	/* 决策前值快照（回滚依据） */
	ai_policy_safety_snapshot_save(ctx->decision_id,
				       (u32)ai_control_index(p), pid, pre);

	rc = ai_control_apply_param(p, pid, requested,
				    (const s64 *)ctx->decision_data);
	if (rc != AI_OK) {
		/* 决策回退：恢复决策前值（best-effort） */
		ai_control_apply_param(p, pid, pre, NULL);
		return rc;
	}

	/* 被安全边界 clamp：返回特殊码（已生效，outcome=部分成功+clamped 标记） */
	return clamped ? AI_POLICY_RC_CLAMPED : AI_OK;
}

int ai_control_register_ex(const char *name, u8 domain, u32 flags,
			   s64 min, s64 max, s64 default_val,
			   int (*apply)(struct ai_control_param *p, s32 pid,
					s64 value, s64 *eff),
			   int (*apply_ex)(struct ai_control_param *p, s32 pid,
					   s64 value, s64 *eff,
					   const s64 *data))
{
	struct ai_control_param *p;
	unsigned long flags_l;
	int rc;

	if (!name || !name[0] || min > max)
		return AI_ERR_INVALID_ARG;

	spin_lock_irqsave(&ai_ctrl_lock, flags_l);
	if (ai_ctrl_count >= AI_CONTROL_MAX_PARAMS) {
		spin_unlock_irqrestore(&ai_ctrl_lock, flags_l);
		return AI_ERR_BUSY;
	}
	if (ai_control_find_locked(name)) {
		spin_unlock_irqrestore(&ai_ctrl_lock, flags_l);
		return AI_ERR_INVALID_ARG;   /* 重名 */
	}

	p = &ai_ctrl_tab[ai_ctrl_count];
	memset(p, 0, sizeof(*p));
	strscpy(p->name, name, sizeof(p->name));
	p->domain = domain;
	p->flags = flags;
	p->min = min;
	p->max = max;
	p->cur = default_val;
	p->default_val = default_val;
	p->apply = apply;
	p->apply_ex = apply_ex;
	ai_ctrl_count++;
	spin_unlock_irqrestore(&ai_ctrl_lock, flags_l);

	/* 策略注册表登记同名动作（优先级 100，回退回调 = NULL：
	 * 处理器失败时已内部恢复决策前值） */
	rc = ai_policy_register(domain, name, ai_control_policy_handler,
				NULL, p);
	if (rc != AI_OK) {
		spin_lock_irqsave(&ai_ctrl_lock, flags_l);
		if (ai_ctrl_count > 0)
			ai_ctrl_count--;
		spin_unlock_irqrestore(&ai_ctrl_lock, flags_l);
		return rc;
	}

	pr_info("AIKernel: control param '%s' registered (domain=%u %s)\n",
		name, domain, (flags & AI_CTRL_F_REAL) ? "[real]" : "[reserved]");
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_control_register_ex);

int ai_control_register(const char *name, u8 domain, u32 flags,
			s64 min, s64 max, s64 default_val,
			int (*apply)(struct ai_control_param *p, s32 pid,
				     s64 value, s64 *eff))
{
	return ai_control_register_ex(name, domain, flags, min, max,
				      default_val, apply, NULL);
}
EXPORT_SYMBOL_GPL(ai_control_register);

int ai_control_restore_value(u32 param_index, s32 pid, s64 value)
{
	struct ai_control_param *p;

	if (param_index >= ai_ctrl_count)
		return AI_ERR_NOT_FOUND;
	p = &ai_ctrl_tab[param_index];
	return ai_control_apply_param(p, pid, value, NULL);
}
EXPORT_SYMBOL_GPL(ai_control_restore_value);

/* ---- 内置立即生效参数（task_struct 字段，公共头符号） ---- */

static int ai_ctl_task_get(struct ai_control_param *p, s32 pid,
			   struct task_struct **out)
{
	struct task_struct *task;

	if (pid <= 0)
		return AI_ERR_INVALID_ARG;
	task = find_get_task_by_vpid(pid);
	if (!task)
		return AI_ERR_NOT_FOUND;
	*out = task;
	return AI_OK;
}

static int ai_ctl_sched_nice_apply(struct ai_control_param *p, s32 pid,
				   s64 value, s64 *eff)
{
	struct task_struct *task;
	int rc;

	rc = ai_ctl_task_get(p, pid, &task);
	if (rc != AI_OK)
		return rc;
	if (rt_task(task)) {
		put_task_struct(task);
		return AI_ERR_INVALID_ARG;   /* RT 任务不可调 nice → 回退 */
	}
	set_user_nice(task, (long)value);
	put_task_struct(task);
	*eff = value;
	return AI_OK;
}

static int ai_ctl_sched_affinity_apply(struct ai_control_param *p, s32 pid,
				       s64 value, s64 *eff)
{
	struct task_struct *task;
	cpumask_var_t mask;
	int rc;

	if (value < 0 || value >= nr_cpu_ids)
		return AI_ERR_INVALID_ARG;

	rc = ai_ctl_task_get(p, pid, &task);
	if (rc != AI_OK)
		return rc;

	if (!zalloc_cpumask_var(&mask, GFP_KERNEL)) {
		put_task_struct(task);
		return AI_ERR_MEMORY;
	}
	cpumask_set_cpu((unsigned int)value, mask);
	rc = set_cpus_allowed_ptr(task, mask);
	free_cpumask_var(mask);
	put_task_struct(task);
	if (rc)
		return AI_ERR_GENERIC;
	*eff = value;
	return AI_OK;
}

static int ai_ctl_sched_oom_apply(struct ai_control_param *p, s32 pid,
				  s64 value, s64 *eff)
{
	struct task_struct *task;
	int rc;

	rc = ai_ctl_task_get(p, pid, &task);
	if (rc != AI_OK)
		return rc;

	task_lock(task);
	if (task->signal)
		task->signal->oom_score_adj = (s16)value;
	task_unlock(task);
	put_task_struct(task);
	*eff = value;
	return AI_OK;
}

static int __init ai_control_init(void)
{
	ai_control_register("sched.nice", AI_POLICY_DOMAIN_SCHED,
			    AI_CTRL_F_REAL | AI_CTRL_F_TASK,
			    -20, 19, 0, ai_ctl_sched_nice_apply);
	ai_control_register("sched.affinity", AI_POLICY_DOMAIN_SCHED,
			    AI_CTRL_F_REAL | AI_CTRL_F_TASK,
			    0, nr_cpu_ids - 1, 0, ai_ctl_sched_affinity_apply);
	ai_control_register("sched.oom_score", AI_POLICY_DOMAIN_SCHED,
			    AI_CTRL_F_REAL | AI_CTRL_F_TASK,
			    -1000, 1000, 0, ai_ctl_sched_oom_apply);

	pr_info("AIKernel: control table ready (core params)\n");
	return 0;
}
late_initcall(ai_control_init);
