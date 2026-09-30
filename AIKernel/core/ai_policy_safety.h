// SPDX-License-Identifier: GPL-2.0
/*
 * ai_policy_safety.h - AIKernel 决策安全边界（all-ai 的安全带，Prompt 13）
 *
 * 防止 AI 失控的三件套：
 *   1. 全局开关：/sys/kernel/ai/policy/global_enable（一键关闭 AI 决策执行）；
 *   2. 最大影响幅度：max_impact_pct（超幅决策 clamp 到 ±幅度并记录）；
 *   3. 决策快照回滚：每个已生效决策保存 (参数, 决策前值[, pid])，可按
 *      decision_id 回滚或全部回滚（测试/失控恢复）。
 *
 * ai_policy_execute() 首行检查全局开关（单分支 ≈2ns）；参数幅度限制由
 * ai_control 应用参数时经 ai_policy_safety_limit_value() 执行。
 */

#ifndef _AIKERNEL_AI_POLICY_SAFETY_H
#define _AIKERNEL_AI_POLICY_SAFETY_H

#include "ai_types.h"
#include <linux/types.h>

/* ---- 默认值 ---- */

#define AI_SAFETY_DEFAULT_ENABLE      1     /* 全局开关默认开启 */
#define AI_SAFETY_DEFAULT_MAX_IMPACT  50    /* 最大影响幅度默认 50% */
#define AI_SAFETY_SNAPSHOT_MAX        64    /* 决策快照环容量 */
#define AI_SAFETY_SNAPSHOT_PARAMS     8     /* 单决策最多快照参数数 */

/* ---- 决策快照 ---- */

struct ai_safety_snapshot {
	u64 decision_id;                 /* 0 = 槽空闲 */
	u64 ts;                          /* 决策时间 */
	u8  n;                           /* 快照参数数 */
	struct {
		u32 param_index;         /* ai_control 参数表索引 */
		s32 pid;                 /* 0=全局参数；>0=task 作用域 */
		s64 pre_value;           /* 决策前值 */
	} params[AI_SAFETY_SNAPSHOT_PARAMS];
};

/* ---- 安全边界接口（实现于 ai_policy_safety.c） ---- */

#ifdef CONFIG_AIKERNEL_RUNTIME

/**
 * ai_policy_safety_get_enabled() - 读取决策执行全局开关
 *
 * 返回 1=执行 0=关闭。
 */
int ai_policy_safety_get_enabled(void);

/**
 * ai_policy_safety_set_enabled() - 设置决策执行全局开关
 * @enable: 1=开启 0=关闭（关闭后 execute 首行拒绝，不记录）
 *
 * 返回 AI_OK。
 */
int ai_policy_safety_set_enabled(int enable);

/**
 * ai_policy_safety_get_max_impact() - 读取最大影响幅度（%）
 *
 * 返回 0~100。
 */
u32 ai_policy_safety_get_max_impact(void);

/**
 * ai_policy_safety_set_max_impact() - 设置最大影响幅度
 * @pct: 0~100（0=禁止一切参数变更）
 *
 * 返回 AI_OK 或 AI_ERR_INVALID_ARG。
 */
int ai_policy_safety_set_max_impact(u32 pct);

/**
 * ai_policy_safety_limit_value() - 安全边界参数限幅
 * @param_min: 参数范围下限
 * @param_max: 参数范围上限
 * @current:  参数当前值
 * @requested: AI 请求值（入/出：出参为 clamp 后的有效值）
 * @clamped:  输出 1=被限制（越界或超幅），0=原样通过
 *
 * 规则：① 硬范围 clamp 到 [param_min, param_max]；
 *       ② 幅度限制 |requested-current| ≤ (max-min)*max_impact_pct/100。
 * 返回 AI_OK。
 */
int ai_policy_safety_limit_value(s64 param_min, s64 param_max,
				 s64 cur, s64 *requested, u8 *clamped);

/**
 * ai_policy_safety_snapshot_save() - 保存决策前参数值（决策快照）
 * @decision_id: 当前决策 ID
 * @param_index: ai_control 参数表索引
 * @pid: task 作用域参数的目标 pid（全局参数传 0）
 * @pre_value:  决策前值
 *
 * 同一次决策重复保存同一参数去重；快照环满淘汰最旧决策。返回 AI_OK。
 */
int ai_policy_safety_snapshot_save(u64 decision_id, u32 param_index,
				   s32 pid, s64 pre_value);

/**
 * ai_policy_safety_rollback_decision() - 按决策 ID 回滚
 * @decision_id: 目标决策
 * @restore: 恢复回调（参数表提供，恢复 param_index 对应参数）
 *
 * 返回 AI_OK（含无快照=无可回滚）或负错误码。
 */
typedef int (*ai_safety_restore_t)(u32 param_index, s32 pid, s64 value);
int ai_policy_safety_rollback_decision(u64 decision_id,
				       ai_safety_restore_t restore);

/**
 * ai_policy_safety_rollback_all() - 回滚全部已生效决策
 * @restore: 恢复回调（同上）
 *
 * 逆序恢复全部快照后清空快照环。返回 AI_OK。
 */
int ai_policy_safety_rollback_all(ai_safety_restore_t restore);

/**
 * ai_policy_safety_stats() - 读取安全边界统计
 * @snapshots: 输出当前快照占用数（可 NULL）
 * @rejected:  输出被安全边界拒绝/限制的决策累计数（可 NULL）
 *
 * 返回 AI_OK。
 */
int ai_policy_safety_stats(u32 *snapshots, u64 *rejected);

#else /* !CONFIG_AIKERNEL_RUNTIME */

static inline int ai_policy_safety_get_enabled(void) { return 1; }
static inline int ai_policy_safety_set_enabled(int enable) { return AI_OK; }
static inline u32 ai_policy_safety_get_max_impact(void) { return 50; }
static inline int ai_policy_safety_set_max_impact(u32 pct) { return AI_OK; }
static inline int ai_policy_safety_limit_value(s64 min, s64 max, s64 cur,
					       s64 *req, u8 *clamped)
{
	if (clamped)
		*clamped = 0;
	return AI_OK;
}
static inline int ai_policy_safety_snapshot_save(u64 id, u32 idx, s32 pid,
						 s64 pre)
{
	return AI_OK;
}
typedef int (*ai_safety_restore_t)(u32 param_index, s32 pid, s64 value);
static inline int ai_policy_safety_rollback_decision(
				u64 id, ai_safety_restore_t restore)
{
	return AI_OK;
}
static inline int ai_policy_safety_rollback_all(ai_safety_restore_t restore)
{
	return AI_OK;
}
static inline int ai_policy_safety_stats(u32 *snapshots, u64 *rejected)
{
	if (snapshots)
		*snapshots = 0;
	if (rejected)
		*rejected = 0;
	return AI_OK;
}

#endif /* CONFIG_AIKERNEL_RUNTIME */

/* 供 ai_control 应用路径累计被限制决策数（模块内符号，非公共接口；
 * n 配置时无调用方，声明仅存在于 RUNTIME 分支） */
#ifdef CONFIG_AIKERNEL_RUNTIME
void ai_policy_safety_note_rejected(void);
#endif

#endif /* _AIKERNEL_AI_POLICY_SAFETY_H */
