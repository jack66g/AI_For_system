// SPDX-License-Identifier: GPL-2.0
/*
 * ai_decision.h - AIKernel 决策注入查询接口（W3 决策消费者阶段）
 *
 * 架构（第二阶段留口）：
 *   挂点（oom_kill/fair/vmscan/readahead/ai_mm）--调用--> ai_decision_query()
 *                                                        |
 *                                          决策源函数指针（可替换）
 *                                                        |
 *                     v1 = 确定性启发式（per-task 分类槽 + 遥测计数）
 *                     v2 = 训练好的微模型（ai_decision_set_source() 注入，
 *                          消费侧与安全边界零改动）
 *
 * 开关三层（默认全部关闭 = 所有挂点行为与原生内核逐位一致）：
 *   ①全局总开关 ai_dec_master（/sys/kernel/ai/decision_inject，默认 0）；
 *   ②每挂点独立使能 ai_dec_hook_en[]（/sys/kernel/ai/decision/<hook>，默认 0）；
 *   ③值域硬钳制：返回偏置按每挂点编译期常量封顶（本头文件 AI_DEC_*_MAX），
 *     决策源（含第二阶段模型）返回越界值也会被查询层 clamp。
 *
 * 异常回退：决策源错误/越界/分类槽无效（含槽表 trylock 失败）→ 一律按 0
 * （原生行为）处理，计一次 fallback 计数（/sys/kernel/ai/decision/stats 可见）。
 *
 * 热路径预算：总开关关 = 一次 READ_ONCE 分支即返回（不计数零写入）；
 * 开 = trylock 分类槽（争用即回退 0）+ 常量时间查表，无分配无睡眠。
 *
 * 记账：注入偏置≠0 时逐次计入 per-hook 计数（queries/injected/effects/
 * fallback 全量精确）；decisions ring（/proc/ai/decisions，source=
 * AI_DEC_SRC_HEURISTIC）按每挂点 1s 节流采样写入，避免淹没 AI Runtime
 * 自身的策略决策流。
 */

#ifndef _AIKERNEL_AI_DECISION_H
#define _AIKERNEL_AI_DECISION_H

#include "ai_types.h"
#include <linux/types.h>
#include <linux/string.h>

/* ---- 挂点 ID（决策源与消费侧的稳定契约；枚举只追加不重排） ---- */

enum ai_hook_id {
	AI_HOOK_OOM_BADNESS    = 0,  /* OOM badness 偏置（mm/oom_kill.c oom_badness） */
	AI_HOOK_SCHED_VRUNTIME = 1,  /* 入队 vruntime 加权（kernel/sched/fair.c place_entity） */
	AI_HOOK_SCHED_WAKEUP   = 2,  /* 唤醒抢占提示（fair.c check_preempt_wakeup_fair） */
	AI_HOOK_MM_READAHEAD   = 3,  /* 预读窗口调整（mm/readahead.c→ai_mm_readahead_hook） */
	AI_HOOK_MM_RECLAIM     = 4,  /* 回收扫描优先级提示（mm/vmscan.c shrink_lruvec） */
	AI_HOOK_NR
};

/* ---- 每挂点偏置值域硬钳制（编译期常量，查询层强制执行） ----
 * 单位与语义（正=加重/推迟/放大，负=减免/提前/缩小）：
 *   OOM_BADNESS   : badness 加减分，oom_score 量纲（0..1000）
 *                   内核内换算 points += bias * totalpages/1000
 *   SCHED_VRUNTIME: vruntime 平移千分比（‰），基准 = |v - V|（V=加权均值）
 *                   ±100‰ = ±10%，且永不跨越 V（无饥饿）
 *   SCHED_WAKEUP  : 抢占增益布尔提示（0/1）
 *   MM_READAHEAD  : 预读窗口 2 的幂档位（+1=×2，-1=÷2，下限 1 页）
 *   MM_RECLAIM    : get_scan_count 扫描优先级档位（±1，每档 ~10% 扫描量） */
#define AI_DEC_OOM_BIAS_MAX       200
#define AI_DEC_SCHED_PCT_MAX      100
#define AI_DEC_WAKEUP_BOOST_MAX   1
#define AI_DEC_RA_SHIFT_MAX       1
#define AI_DEC_RECLAIM_PRIO_MAX   1

/* ---- 决策 ring 采样节流（每挂点，jiffies） ---- */
#define AI_DEC_RING_JIFFIES       ((unsigned long)HZ)

/* ---- 查询上下文（挂点 → 决策源；pid=0 表示取 current） ---- */

struct ai_hook_ctx {
	pid_t pid;   /* 目标任务 pid（0=当前任务） */
};

/* ---- per-hook 决策记账（/sys/kernel/ai/decision/stats 数据源） ---- */

struct ai_hook_stats {
	u64 queries;      /* 查询次数（总开关开时才累计） */
	u64 injected;     /* 偏置非零次数 */
	u64 effects;      /* 消费侧确认实际生效次数（note_effect） */
	u64 fallback;     /* 决策源错误/槽无效回退 0 次数 */
	u64 ring;         /* decisions ring 采样写入次数 */
	s32 last_bias;    /* 最近一次偏置值 */
	s64 last_aux0;    /* 最近生效前后观测（挂点自定义，如 points 前/后） */
	s64 last_aux1;
	unsigned long last_ring_j;  /* ring 节流时间戳（jiffies） */
};

struct ai_decision_stats {
	u8  master;                        /* 全局总开关当前值 */
	u8  hook_en[AI_HOOK_NR];           /* 每挂点使能当前值 */
	u64 fallback_pad;                  /* 枚举外 hook 记账（理论不可达） */
	struct ai_hook_stats hook[AI_HOOK_NR];
};

/* ---- 决策源函数原型（第二阶段模型接入点） ----
 * 返回该挂点语义下的有界偏置（越界由查询层 clamp）；模型加载失败/暂时
 * 不可用应返回 0（不干预）或负值（查询层按 0 处理）。 */
typedef s32 (*ai_decision_source_fn)(enum ai_hook_id hook,
				     const struct ai_hook_ctx *ctx);

#ifdef CONFIG_AIKERNEL_RUNTIME

/**
 * ai_decision_query() - 挂点决策查询（热路径安全，最坏返回 0=不干预）
 * @hook: 挂点 ID
 * @ctx:  查询上下文（可 NULL，等价 pid=0）
 *
 * 总开关关 / 挂点未使能 → 直接返回 0；否则调当前决策源并按编译期常量
 * clamp。挂点为 fair.c/oom_kill.c/vmscan.c/ai_mm.c 的消费点，可在持
 * rq 锁/task 锁等原子上下文调用（内部仅 trylock + WRITE_ONCE 计数）。
 */
s32 ai_decision_query(enum ai_hook_id hook, const struct ai_hook_ctx *ctx);

/**
 * ai_decision_note_effect() - 消费侧确认偏置实际生效（记账 + ring 采样）
 * @hook: 挂点 ID
 * @aux0/aux1: 生效观测（挂点自定义：如 vruntime 前值/后值、points 前/后）
 *
 * 仅在消费侧真实改变内核状态后调用；节流采样推入 decisions ring
 * （source=AI_DEC_SRC_HEURISTIC）。开关关时不会到达（query 先返回 0）。
 */
void ai_decision_note_effect(enum ai_hook_id hook, s64 aux0, s64 aux1);

/**
 * ai_decision_set_source() - 替换决策源（第二阶段模型接入点）
 * @fn: 新决策源函数；NULL = 恢复内置启发式 v1
 *
 * 返回 AI_OK；模型决策只需经此注入实现，消费挂点与开关/钳制/记账零改动。
 */
int ai_decision_set_source(ai_decision_source_fn fn);

/* ---- 开关读写（sysfs 与 ACT 参数共用） ---- */

int ai_decision_set_master(u8 on);
u8  ai_decision_get_master(void);
int ai_decision_set_hook_enable(enum ai_hook_id hook, u8 on);
u8  ai_decision_get_hook_enable(enum ai_hook_id hook);

/**
 * ai_decision_stats_get() - 读取决策记账快照（无锁近似一致，观测面用）
 */
void ai_decision_stats_get(struct ai_decision_stats *out);

/* 挂点名（sysfs/日志用；与 enum ai_hook_id 顺序一致） */
const char *ai_decision_hook_name(enum ai_hook_id hook);

#else /* !CONFIG_AIKERNEL_RUNTIME */

static inline s32 ai_decision_query(enum ai_hook_id hook,
				    const struct ai_hook_ctx *ctx)
{
	return 0;   /* 决策注入未编译：恒原生行为 */
}
static inline void ai_decision_note_effect(enum ai_hook_id hook, s64 a0, s64 a1)
{
}
static inline int ai_decision_set_source(ai_decision_source_fn fn)
{
	return AI_ERR_NOT_IMPLEMENTED;
}
static inline int ai_decision_set_master(u8 on) { return AI_ERR_DISABLED; }
static inline u8  ai_decision_get_master(void) { return 0; }
static inline int ai_decision_set_hook_enable(enum ai_hook_id hook, u8 on)
{
	return AI_ERR_DISABLED;
}
static inline u8  ai_decision_get_hook_enable(enum ai_hook_id hook) { return 0; }
static inline void ai_decision_stats_get(struct ai_decision_stats *out)
{
	if (out)
		memset(out, 0, sizeof(*out));
}
static inline const char *ai_decision_hook_name(enum ai_hook_id hook)
{
	return "?";
}

#endif /* CONFIG_AIKERNEL_RUNTIME */

#endif /* _AIKERNEL_AI_DECISION_H */
