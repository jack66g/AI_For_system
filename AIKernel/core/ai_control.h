// SPDX-License-Identifier: GPL-2.0
/*
 * ai_control.h - AIKernel 可控制参数表（数据计划 20.3，Prompt 13）
 *
 * 落地数据计划 20.3：AI 可控制的系统参数，每条 = 一个策略接口。
 * 各子系统初始化时把本域的"可执行动作"注册进来（ai_control_register →
 * 自动在策略注册表登记同名动作，执行器命中时走统一处理器：
 * 安全边界 clamp → 决策前值快照 → apply → current 更新；失败 → 回退）。
 *
 * 立即生效参数（内核行为实际修改）：
 *   sched.nice / sched.affinity / sched.oom_score（task_struct 字段）、
 *   mm.swappiness（vm_swappiness）。
 * 接口预留参数（注册/安全/记录全量生效，内核行为接线在对应子系统步骤）：
 *   sched.timeslice、mm.readahead/thp/reclaim_prio、io.priority/bandwidth、
 *   net.cwnd/rto/qdisc/nftables、sec.lsm_override/seccomp/audit、
 *   power.freq/cstate/wakeup、proc.signal/freeze/rlimit。
 *
 * 值传递约定（决策 data）：全局参数 decision_data[0]=值；
 * task 作用域参数（AI_CTRL_F_TASK）decision_data[0]=pid、data[1]=值。
 */

#ifndef _AIKERNEL_AI_CONTROL_H
#define _AIKERNEL_AI_CONTROL_H

#include "ai_types.h"
#include "ai_policy.h"
#include <linux/types.h>

#define AI_CONTROL_MAX_PARAMS  64   /* 参数表容量 */

/* ---- 参数标志 ---- */

#define AI_CTRL_F_REAL    (1U << 0)   /* 立即生效（真实修改内核行为） */
#define AI_CTRL_F_TASK    (1U << 1)   /* task 作用域（data[0]=pid, data[1]=值） */
#define AI_CTRL_F_EVENT   (1U << 2)   /* 事件型参数：重复同值仍执行（如信号投递） */

/* ---- 参数描述符 ---- */

struct ai_control_param {
	char   name[AI_MAX_NAME_LEN];   /* "mm.swappiness"（策略动作名，全表唯一） */
	u8     domain;                  /* 决策域 */
	u32    flags;                   /* AI_CTRL_F_* */
	s64    min;                     /* 参数范围下限 */
	s64    max;                     /* 参数范围上限 */
	s64    cur;                     /* 当前生效值（预留参数=记录值） */
	s64    default_val;             /* 默认值 */
	int    (*apply)(struct ai_control_param *p, s32 pid,
			s64 value, s64 *eff);   /* 可 NULL（预留：仅记录） */
	/* 扩展应用回调（可 NULL）：data=决策参数全量（decision_data[0..7]），
	 * 供需 >1 个辅助输入的参数使用（如 proc.rlimit 的 data[2]=资源号）；
	 * 设置时优先于 apply 调用 */
	int    (*apply_ex)(struct ai_control_param *p, s32 pid,
			   s64 value, s64 *eff, const s64 *data);
};

/* ---- 接口（实现于 ai_control.c） ---- */

#ifdef CONFIG_AIKERNEL_RUNTIME

/**
 * ai_control_register() - 注册一个可控制参数（= 一个策略接口）
 * @name: 参数名（如 "mm.swappiness"；同域内唯一）
 * @domain: 决策域
 * @flags: AI_CTRL_F_*（REAL=立即生效 TASK=pid 作用域）
 * @min/@max: 参数范围（安全 clamp 边界）
 * @default_val: 默认值
 * @apply: 应用回调（可 NULL=接口预留，仅 clamp+记录）
 *
 * 注册参数表项 + 自动在策略注册表登记同名动作（优先级 100）。
 * 各子系统 init 调用（"各子系统把可执行动作注册进来"）。
 * 返回 AI_OK 或负错误码。
 */
int ai_control_register(const char *name, u8 domain, u32 flags,
			s64 min, s64 max, s64 default_val,
			int (*apply)(struct ai_control_param *p, s32 pid,
				     s64 value, s64 *eff));

/**
 * ai_control_register_ex() - 注册可控制参数（扩展版）
 * 与 ai_control_register() 相同，另支持：
 * @apply_ex: 扩展应用回调（可 NULL）：能读到决策参数全量 data[0..7]，
 *            供需 >1 个辅助输入的参数（如 proc.rlimit data[2]=资源号）
 */
int ai_control_register_ex(const char *name, u8 domain, u32 flags,
			   s64 min, s64 max, s64 default_val,
			   int (*apply)(struct ai_control_param *p, s32 pid,
					s64 value, s64 *eff),
			   int (*apply_ex)(struct ai_control_param *p, s32 pid,
					   s64 value, s64 *eff,
					   const s64 *data));

/**
 * ai_control_query() - 按索引读参数描述符
 * @index: 0 起的索引
 * @out: 输出参数快照
 *
 * 返回 AI_OK 或 AI_ERR_NOT_FOUND。
 */
int ai_control_query(u32 index, struct ai_control_param *out);

/**
 * ai_control_find() - 按名查参数索引
 * @name: 参数名
 *
 * 返回索引（>=0）或负错误码。
 */
int ai_control_find(const char *name);

/**
 * ai_control_get_value() - 读参数当前值
 * @name: 参数名
 * @value: 输出当前值
 *
 * 返回 AI_OK 或负错误码。
 */
int ai_control_get_value(const char *name, s64 *value);

/**
 * ai_control_restore_value() - 回滚恢复（安全层 restore 回调）
 * @param_index: 参数表索引
 * @pid: task 作用域目标 pid（0=全局）
 * @value: 决策前值
 *
 * 供 ai_policy_safety_rollback_* 调用；task 参数回找 pid 重放，进程已退出
 * 则仅更新记录值（best-effort，决策全量记录）。返回 AI_OK。
 */
int ai_control_restore_value(u32 param_index, s32 pid, s64 value);

#else /* !CONFIG_AIKERNEL_RUNTIME */

static inline int ai_control_register(const char *name, u8 domain, u32 flags,
				      s64 min, s64 max, s64 default_val,
				      int (*apply)(struct ai_control_param *p,
						   s32 pid, s64 value,
						   s64 *eff))
{
	return AI_OK;
}
static inline int ai_control_register_ex(const char *name, u8 domain,
					 u32 flags, s64 min, s64 max,
					 s64 default_val,
					 int (*apply)(struct ai_control_param *p,
						      s32 pid, s64 value,
						      s64 *eff),
					 int (*apply_ex)(struct ai_control_param *p,
							 s32 pid, s64 value,
							 s64 *eff,
							 const s64 *data))
{
	return AI_OK;
}
static inline int ai_control_query(u32 index, struct ai_control_param *out)
{
	return AI_ERR_NOT_FOUND;
}
static inline int ai_control_find(const char *name) { return AI_ERR_NOT_FOUND; }
static inline int ai_control_get_value(const char *name, s64 *value)
{
	return AI_ERR_NOT_FOUND;
}
static inline int ai_control_restore_value(u32 param_index, s32 pid,
					   s64 value)
{
	return AI_OK;
}

#endif /* CONFIG_AIKERNEL_RUNTIME */

#endif /* _AIKERNEL_AI_CONTROL_H */
