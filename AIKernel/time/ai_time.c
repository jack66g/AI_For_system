// SPDX-License-Identifier: GPL-2.0
/*
 * ai_time.c - AIKernel 时间管理核心（Prompt 09，重构计划 模块10）
 *
 * A 轨：4 个 ai_time_*_hook()（空实现 = 原样放行，决策表待 AI 填充）；
 * B 轨：第11类 时间与定时器感知（11.01~11.04）发射辅助，全部
 *       sample_take 采样判定 + 栈上 payload + emit_direct 直写。
 *
 * 中断上下文安全：timer/hrtimer 埋点在中断上下文内发射，零锁零分配
 * 零 printk；时间戳 ktime_get_ns()（IRQ 安全）。
 */

#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/hrtimer.h>
#include <linux/clocksource.h>
#include <linux/sched.h>
#include <linux/pid.h>

#include "ai_time.h"

/* ---- 决策统计（per-CPU 近似，汇总读取） ---- */

static DEFINE_PER_CPU(struct ai_time_stats, ai_time_pcpu_stats);

/* ---- per-CPU 采样计数器（无锁） ---- */

struct ai_time_percpu {
	u32 timer_samples;		/* timer 批次采样计数器 */
	u32 hrtimer_samples;		/* hrtimer 延迟采样计数器 */
};

static DEFINE_PER_CPU(struct ai_time_percpu, ai_time_percpu);

static bool ai_time_sample_take_pcpu(u32 rate)
{
	u32 c = __this_cpu_inc_return(ai_time_percpu.timer_samples) - 1;

	return (rate <= 1) || ((c % rate) == 0);
}

bool ai_time_sample_take(u32 rate)
{
	return ai_time_sample_take_pcpu(rate);
}

static bool ai_time_hrtimer_sample_take(void)
{
	u32 c = __this_cpu_inc_return(ai_time_percpu.hrtimer_samples) - 1;

	return (c % 64) == 0;
}

void ai_time_stats_read(struct ai_time_stats *st)
{
	int cpu;

	if (!st)
		return;
	memset(st, 0, sizeof(*st));
	for_each_possible_cpu(cpu) {
		const struct ai_time_stats *p = per_cpu_ptr(&ai_time_pcpu_stats,
							   cpu);

		st->tick_hook_calls += p->tick_hook_calls;
		st->tick_hook_adjusted += p->tick_hook_adjusted;
		st->timer_hook_calls += p->timer_hook_calls;
		st->hrtimer_hook_calls += p->hrtimer_hook_calls;
		st->cs_hook_calls += p->cs_hook_calls;
		st->emit_tick += p->emit_tick;
		st->emit_timer += p->emit_timer;
		st->emit_hrtimer += p->emit_hrtimer;
		st->emit_cs += p->emit_cs;
	}
}
EXPORT_SYMBOL_GPL(ai_time_stats_read);

/* ==================================================================
 * A 轨：AI 时间管理 Hook（空实现 = 原样放行）
 * ==================================================================
 */

void ai_time_tick_hook(int cpu, ktime_t *expires)
{
	this_cpu_inc(ai_time_pcpu_stats.tick_hook_calls);
	/* AI 决定 NOHZ vs 周期 tick：可改 *expires（0=保留周期 tick） */
	if (expires && ktime_to_ns(*expires) == 0)
		this_cpu_inc(ai_time_pcpu_stats.tick_hook_adjusted);
}
EXPORT_SYMBOL_GPL(ai_time_tick_hook);

void ai_time_timer_hook(int cpu, unsigned long clk, unsigned long *next_expiry)
{
	this_cpu_inc(ai_time_pcpu_stats.timer_hook_calls);
	/* AI 预测定时器到期，优化级联：可改 *next_expiry */
}
EXPORT_SYMBOL_GPL(ai_time_timer_hook);

void ai_time_hrtimer_hook(struct hrtimer_cpu_base *cpu_base, ktime_t now)
{
	this_cpu_inc(ai_time_pcpu_stats.hrtimer_hook_calls);
	/* AI 合并相邻定时器建议（soft 到期机制已保证零新增唤醒） */
}
EXPORT_SYMBOL_GPL(ai_time_hrtimer_hook);

void ai_time_clocksource_hook(struct clocksource *best,
			      struct clocksource *cur)
{
	this_cpu_inc(ai_time_pcpu_stats.cs_hook_calls);
	/* AI 评估时钟源质量动态切换：决策表就绪后在此评估 */
}
EXPORT_SYMBOL_GPL(ai_time_clocksource_hook);

/* ==================================================================
 * B 轨：第11类 时间与定时器感知发射辅助
 * ==================================================================
 */

void ai_telemetry_tick_mode(u8 type, u8 do_timer_last, u64 next_expires_ns)
{
	struct ai_time_tick_payload p;

	if (!ai_time_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = type;
	p.cpu = smp_processor_id();
	p.do_timer_last = do_timer_last;
	p.next_expires_ns = next_expires_ns;
	this_cpu_inc(ai_time_pcpu_stats.emit_tick);
	ai_telemetry_emit_direct(AI_CAT_TIME, AI_EV_TIMER, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_tick_mode);

void ai_telemetry_timer_expire(u32 batch_count, u64 processed_ns)
{
	struct ai_time_timer_payload p;

	if (!ai_time_sample_take_pcpu(32))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_TIME_TIMER_EXPIRE;
	p.cpu = smp_processor_id();
	p.batch_count = batch_count;
	p.processed_ns = processed_ns;
	this_cpu_inc(ai_time_pcpu_stats.emit_timer);
	ai_telemetry_emit_direct(AI_CAT_TIME, AI_EV_TIMER, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_timer_expire);

void ai_telemetry_hrtimer_latency(u64 timer_addr, u64 latency_ns, u8 restart)
{
	struct ai_time_hrtimer_payload p;

	if (!ai_time_hrtimer_sample_take())
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_TIME_HRTIMER_LATENCY;
	p.pid = task_pid_nr(current);
	p.timer_addr = timer_addr;
	p.latency_ns = latency_ns;
	p.restart = restart;
	this_cpu_inc(ai_time_pcpu_stats.emit_hrtimer);
	ai_telemetry_emit_direct(AI_CAT_TIME, AI_EV_HRTIMER, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_hrtimer_latency);

void ai_telemetry_clocksource_switch(struct clocksource *old_cs,
				     struct clocksource *new_cs)
{
	struct ai_time_clocksource_payload p;

	if (!ai_time_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_TIME_CLOCKSOURCE_SWITCH;
	if (new_cs) {
		p.rating = new_cs->rating;
		strscpy(p.new_name, new_cs->name, sizeof(p.new_name));
	}
	strscpy(p.old_name, old_cs ? old_cs->name : "", sizeof(p.old_name));
	this_cpu_inc(ai_time_pcpu_stats.emit_cs);
	ai_telemetry_emit_direct(AI_CAT_TIME, AI_EV_CLOCKSOURCE,
				 AI_SEV_IMPORTANT, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_clocksource_switch);
