// SPDX-License-Identifier: GPL-2.0
/*
 * ai_time.h - AIKernel 时间管理子系统统一接口头（Prompt 09）
 *
 * 本文件是 kernel/time/ 全部 AI 埋点的唯一接入点：
 *   A 轨（控制）：ai_time_*_hook() 系列 —— 让 AI 参与时间管理决策，
 *                 空实现 = 原样放行（返回值不改变内核默认行为）；
 *   B 轨（感知）：第11类 时间与定时器感知的 payload 结构 + 发射辅助，
 *                 全量原始零脱敏。
 *
 * 零回归策略：
 *   - CONFIG_AIKERNEL_TIME=n：本头文件不参与任何编译（调用点条件剔除）；
 *   - CONFIG_AIKERNEL_TELEMETRY=n：ai_telemetry_* 退化为 static inline
 *     空函数（ai_telemetry.h 内置兜底），Hook 本身只计数不发射。
 *
 * 中断上下文安全：hrtimer/timer 埋点全部在中断上下文内发射，零锁零分配；
 * timer_base 为 timer.c 私有类型 → Hook 传标量。
 */

#ifndef _AIKERNEL_TIME_AI_TIME_H
#define _AIKERNEL_TIME_AI_TIME_H

#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"
#include <linux/types.h>
#include <linux/ktime.h>

/* 内核类型前向声明（本头只传指针） */
struct hrtimer_cpu_base;
struct clocksource;

/* ==================================================================
 * B 轨：第11类 时间与定时器感知 payload（事件编号对齐 enum ai_event_type
 * 11.01~11.04；首字节 type 区分计划内子事件）
 * ==================================================================
 */

enum ai_time_sub_event {
	AI_TIME_TICK_STOP		= 1,	/* tick_mode_switch：停止周期 tick */
	AI_TIME_TICK_RESTART,			/* tick_mode_switch：恢复周期 tick */
	AI_TIME_TIMER_EXPIRE,			/* timer_expire（批量） */
	AI_TIME_HRTIMER_LATENCY,		/* hrtimer_latency */
	AI_TIME_CLOCKSOURCE_SWITCH,		/* clocksource_switch */
};

struct ai_time_tick_payload {
	u8 type;			/* AI_TIME_TICK_STOP / RESTART */
	u8 cpu;
	u8 do_timer_last;		/* 本 CPU 是否曾承担 do_timer 职责 */
	u64 next_expires_ns;		/* stop 型：下个到期点；restart 型：0 */
};

struct ai_time_timer_payload {
	u8 type;			/* AI_TIME_TIMER_EXPIRE */
	u8 cpu;
	u32 batch_count;		/* 本轮过期的定时器总数 */
	u64 processed_ns;		/* 批次处理总时长 */
};

struct ai_time_hrtimer_payload {
	u8 type;			/* AI_TIME_HRTIMER_LATENCY */
	u32 pid;
	u64 timer_addr;
	u64 latency_ns;			/* now - softexpires */
	u8 restart;			/* 回调是否要求重启 */
};

struct ai_time_clocksource_payload {
	u8 type;			/* AI_TIME_CLOCKSOURCE_SWITCH */
	u32 rating;			/* 新时钟源评分 */
	char old_name[32];
	char new_name[32];
};

/* ---- 决策统计 ---- */

struct ai_time_stats {
	u64 tick_hook_calls, tick_hook_adjusted;
	u64 timer_hook_calls;
	u64 hrtimer_hook_calls;
	u64 cs_hook_calls;
	u64 emit_tick, emit_timer, emit_hrtimer, emit_cs;
};

#ifdef CONFIG_AIKERNEL_TIME

/* ---- A 轨 Hook（实现见 ai_time.c；空实现 = 原样放行） ---- */

/**
 * ai_time_tick_hook() - AI 决定 NOHZ vs 周期 tick
 * @cpu: 当前 CPU
 * @expires: 出参/入参；下一个到期时间（AI 置 0=保留周期 tick，其他=调整睡眠长度）
 *
 * 由 tick_nohz_idle_stop_tick() 到期时间算出后调用。空实现不改。
 */
void ai_time_tick_hook(int cpu, ktime_t *expires);

/**
 * ai_time_timer_hook() - AI 预测定时器到期，优化级联
 * @cpu: 当前 CPU
 * @clk: 当前 jiffies
 * @next_expiry: 出参/入参；下个到期 jiffies（AI 可调整）
 *
 * 由 __run_timers() 入口调用。空实现不改。
 */
void ai_time_timer_hook(int cpu, unsigned long clk, unsigned long *next_expiry);

/**
 * ai_time_hrtimer_hook() - AI 合并相邻定时器建议
 * @cpu_base: 当前 CPU 的 hrtimer 基
 * @now: 当前时间
 *
 * 由 __hrtimer_run_queues() 入口调用。空实现无操作（soft 到期机制已保证
 * 零新增唤醒，AI 合并建议在此预留）。
 */
void ai_time_hrtimer_hook(struct hrtimer_cpu_base *cpu_base, ktime_t now);

/**
 * ai_time_clocksource_hook() - AI 评估时钟源质量，动态切换
 * @best: 本次选中的最优时钟源
 * @cur: 当前时钟源
 *
 * 由 __clocksource_select() found: 前调用。空实现无操作。
 */
void ai_time_clocksource_hook(struct clocksource *best,
			      struct clocksource *cur);

/* ---- 第11类发射辅助（实现见 ai_time.c；全部 sample_take + emit_direct） ---- */

void ai_telemetry_tick_mode(u8 type, u8 do_timer_last, u64 next_expires_ns);
void ai_telemetry_timer_expire(u32 batch_count, u64 processed_ns);
void ai_telemetry_hrtimer_latency(u64 timer_addr, u64 latency_ns, u8 restart);
void ai_telemetry_clocksource_switch(struct clocksource *old_cs,
				     struct clocksource *new_cs);

/* ---- 决策框架 ---- */

void ai_time_stats_read(struct ai_time_stats *st);
bool ai_time_sample_take(u32 rate);

#else /* !CONFIG_AIKERNEL_TIME */

/* 空函数兜底：CONFIG_AIKERNEL_TIME=n 时调用点不编译，
 * 此处兜底仅供 AIKernel/ 内部其他模块引用时保持可编译。 */
static inline void ai_time_tick_hook(int cpu, ktime_t *expires) { }
static inline void ai_time_timer_hook(int cpu, unsigned long clk,
				      unsigned long *next_expiry) { }
static inline void ai_time_hrtimer_hook(struct hrtimer_cpu_base *cpu_base,
					ktime_t now) { }
static inline void ai_time_clocksource_hook(struct clocksource *best,
					    struct clocksource *cur) { }
static inline void ai_telemetry_tick_mode(u8 type, u8 do_timer_last,
					  u64 next_expires_ns)
{ }
static inline void ai_telemetry_timer_expire(u32 batch_count,
					     u64 processed_ns)
{ }
static inline void ai_telemetry_hrtimer_latency(u64 timer_addr,
						u64 latency_ns, u8 restart)
{ }
static inline void ai_telemetry_clocksource_switch(struct clocksource *old_cs,
						   struct clocksource *new_cs)
{ }
static inline void ai_time_stats_read(struct ai_time_stats *st)
{ if (st) memset(st, 0, sizeof(*st)); }
static inline bool ai_time_sample_take(u32 rate)
{ return false; }

#endif /* CONFIG_AIKERNEL_TIME */

#endif /* _AIKERNEL_TIME_AI_TIME_H */
