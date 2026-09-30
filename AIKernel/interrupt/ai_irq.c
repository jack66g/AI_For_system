// SPDX-License-Identifier: GPL-2.0
/*
 * ai_irq.c - AIKernel 中断管理核心（Prompt 09，重构计划 模块8）
 *
 * A 轨：5 个 ai_irq_*_hook()（空实现 = 原样放行，决策表待 AI 填充）；
 * B 轨：第9类 中断与异常感知（09.01~09.05）发射辅助，全部
 *       sample_take 采样判定 + 栈上 payload + emit_direct 直写。
 *
 * 中断上下文安全性（本模块核心铁律）：
 *   - per-CPU 预分配槽位（softirq 起止时间戳 10 槽、softirq 采样计数、
 *     spin 采样计数与时间戳槽——spin 槽给 ai_lock 用，本文件保留定义），
 *     零运行时分配、零锁、零 printk；
 *   - 时间戳 ktime_get_ns()（monotonic，IRQ 安全）；
 *   - comm 拷贝直接读 current->comm（先例：watchdog NMI 路径）。
 *
 * 遥测函数铁律：不阻塞、不分配（无 GFP_KERNEL）、无锁。
 */

#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/cpumask.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/kernel_stat.h>
#include <linux/pid.h>

#include "ai_irq.h"
#include "../../kernel/workqueue_internal.h"

/* ---- 决策统计（per-CPU 近似，汇总读取） ---- */

static DEFINE_PER_CPU(struct ai_irq_stats, ai_irq_pcpu_stats);

/* ---- per-CPU 预分配槽位（无锁无分配） ---- */

#define AI_IRQ_SOFTIRQ_SAMPLE_RATE	64

struct ai_irq_percpu {
	u64 softirq_start[NR_SOFTIRQS];	/* softirq 向量起止时间戳槽 */
	u32 softirq_count[NR_SOFTIRQS];	/* 各向量 kstat 快照（差值累计） */
	u32 softirq_samples;		/* softirq 采样计数器 */
};

static DEFINE_PER_CPU(struct ai_irq_percpu, ai_irq_percpu);

bool ai_irq_sample_take(u32 rate)
{
	u32 c = __this_cpu_inc_return(ai_irq_percpu.softirq_samples) - 1;

	return (rate <= 1) || (c % rate) == 0;
}

void ai_irq_stats_read(struct ai_irq_stats *st)
{
	int cpu;

	if (!st)
		return;
	memset(st, 0, sizeof(*st));
	for_each_possible_cpu(cpu) {
		const struct ai_irq_stats *p = per_cpu_ptr(&ai_irq_pcpu_stats, cpu);

		st->affinity_hook_calls += p->affinity_hook_calls;
		st->affinity_hook_changed += p->affinity_hook_changed;
		st->thread_hook_calls += p->thread_hook_calls;
		st->thread_hook_skipped += p->thread_hook_skipped;
		st->softirq_hook_calls += p->softirq_hook_calls;
		st->wq_hook_calls += p->wq_hook_calls;
		st->watchdog_hook_calls += p->watchdog_hook_calls;
		st->watchdog_threshold_adjusted += p->watchdog_threshold_adjusted;
		st->emit_affinity += p->emit_affinity;
		st->emit_thread += p->emit_thread;
		st->emit_softirq += p->emit_softirq;
		st->emit_wq += p->emit_wq;
		st->emit_watchdog += p->emit_watchdog;
	}
}
EXPORT_SYMBOL_GPL(ai_irq_stats_read);

/* ==================================================================
 * A 轨：AI 中断管理 Hook（空实现 = 原样放行）
 * ==================================================================
 */

int ai_irq_affinity_hook(unsigned int nvecs, struct irq_affinity *affd,
			 struct irq_affinity_desc *masks)
{
	this_cpu_inc(ai_irq_pcpu_stats.affinity_hook_calls);
	/* AI 按 CPU 负载优化分发：决策表就绪后在此调整 masks 并置 changed */
	return 0;
}
EXPORT_SYMBOL_GPL(ai_irq_affinity_hook);

bool ai_irq_thread_hook(unsigned int irq, struct irqaction *new)
{
	this_cpu_inc(ai_irq_pcpu_stats.thread_hook_calls);
	/* AI 决定哪些中断线程化：返回 false 跳过线程化（仅非强制路径） */
	return true;
}
EXPORT_SYMBOL_GPL(ai_irq_thread_hook);

void ai_irq_softirq_hook(u32 *pending, unsigned int *max_restart)
{
	this_cpu_inc(ai_irq_pcpu_stats.softirq_hook_calls);
	/* AI 调整 softirq 顺序/批次：可改 pending 位图与 max_restart */
}
EXPORT_SYMBOL_GPL(ai_irq_softirq_hook);

void ai_irq_wq_hook(struct worker_pool *pool, bool *create_worker)
{
	this_cpu_inc(ai_irq_pcpu_stats.wq_hook_calls);
	/* AI 预测 worker 需求：可改 *create_worker 阻止/促成 worker 创建 */
}
EXPORT_SYMBOL_GPL(ai_irq_wq_hook);

int ai_irq_watchdog_hook(unsigned long duration, unsigned long *threshold)
{
	this_cpu_inc(ai_irq_pcpu_stats.watchdog_hook_calls);
	/* AI 自适应 lockup 阈值：可改 *threshold（本步近事件判定用默认值） */
	return 0;
}
EXPORT_SYMBOL_GPL(ai_irq_watchdog_hook);

/* ==================================================================
 * B 轨：第9类 中断与异常感知发射辅助
 * ==================================================================
 */

void ai_telemetry_irq_affinity_create(unsigned int nvecs,
				      struct irq_affinity *affd)
{
	struct ai_irq_affinity_payload p;

	if (!ai_irq_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_IRQ_AFFINITY_CREATE;
	p.nvecs = nvecs;
	if (affd) {
		p.pre_vectors = affd->pre_vectors;
		p.post_vectors = affd->post_vectors;
		p.nr_sets = affd->nr_sets;
	}
	this_cpu_inc(ai_irq_pcpu_stats.emit_affinity);
	ai_telemetry_emit_direct(AI_CAT_INTERRUPT, AI_EV_IRQ_BALANCE,
				 AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_irq_affinity_create);

void ai_telemetry_irq_affinity_set(u32 irq, const struct cpumask *mask,
				   bool force)
{
	struct ai_irq_affinity_payload p;
	unsigned int words = BITS_TO_LONGS(NR_CPUS);

	if (!ai_irq_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_IRQ_AFFINITY_SET;
	p.irq = irq;
	p.force = force;
	if (mask) {
		unsigned int i, words = BITS_TO_LONGS(nr_cpu_ids);

		/* 全位图拷贝：nr_cpu_ids 有效字 + 高位清零 */
		for (i = 0; i < BITS_TO_LONGS(NR_CPUS); i++)
			p.mask_words[i] = (i < words) ? cpumask_bits(mask)[i]
						      : 0;
	}
	p.nr_cpus = mask ? cpumask_weight(mask) : 0;
	this_cpu_inc(ai_irq_pcpu_stats.emit_affinity);
	ai_telemetry_emit_direct(AI_CAT_INTERRUPT, AI_EV_IRQ_BALANCE,
				 AI_SEV_NORMAL, &p,
				 offsetof(struct ai_irq_affinity_payload,
					  mask_words) + words * sizeof(long));
}
EXPORT_SYMBOL_GPL(ai_telemetry_irq_affinity_set);

void ai_telemetry_irq_thread(u32 irq, u32 thread_pid, const char *thread_name,
			     u8 secondary, u8 forced)
{
	struct ai_irq_thread_payload p;

	if (!ai_irq_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_IRQ_THREAD;
	p.irq = irq;
	p.thread_pid = thread_pid;
	p.secondary = secondary;
	p.forced = forced;
	strscpy(p.thread_name, thread_name ? thread_name : "",
		sizeof(p.thread_name));
	this_cpu_inc(ai_irq_pcpu_stats.emit_thread);
	ai_telemetry_emit_direct(AI_CAT_INTERRUPT, AI_EV_IRQ,
				 AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_irq_thread);

void ai_telemetry_softirq_entry(u8 vec_nr)
{
	struct ai_irq_percpu *pc = this_cpu_ptr(&ai_irq_percpu);

	if (!ai_irq_sample_take(AI_IRQ_SOFTIRQ_SAMPLE_RATE))
		return;
	if (vec_nr < NR_SOFTIRQS)
		pc->softirq_start[vec_nr] = ktime_get_ns();
}
EXPORT_SYMBOL_GPL(ai_telemetry_softirq_entry);

void ai_telemetry_softirq_exit(u8 vec_nr)
{
	struct ai_irq_percpu *pc = this_cpu_ptr(&ai_irq_percpu);
	struct ai_irq_softirq_payload p;
	u64 start;

	if (vec_nr >= NR_SOFTIRQS)
		return;
	start = pc->softirq_start[vec_nr];
	if (!start)
		return;
	pc->softirq_start[vec_nr] = 0;

	memset(&p, 0, sizeof(p));
	p.type = AI_IRQ_SOFTIRQ_EXIT;
	p.vec_nr = vec_nr;
	p.latency_ns = ktime_get_ns() - start;
	p.count = kstat_softirqs_cpu(vec_nr, smp_processor_id()) -
		  pc->softirq_count[vec_nr];
	pc->softirq_count[vec_nr] = kstat_softirqs_cpu(vec_nr,
						       smp_processor_id());

	this_cpu_inc(ai_irq_pcpu_stats.emit_softirq);
	ai_telemetry_emit_direct(AI_CAT_INTERRUPT, AI_EV_SOFTIRQ,
				 AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_softirq_exit);

void ai_telemetry_workqueue_launch(u32 pool_id, u32 cpu, s32 nice,
				   u32 nr_workers, u32 nr_idle,
				   u32 nr_running, u8 create)
{
	struct ai_irq_workqueue_payload p;

	if (!ai_irq_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = create ? AI_IRQ_WORKQUEUE_CREATE : AI_IRQ_WORKQUEUE_DESTROY;
	p.pool_id = pool_id;
	p.cpu = cpu;
	p.nice = nice;
	p.nr_workers = nr_workers;
	p.nr_idle = nr_idle;
	p.nr_running = nr_running;
	this_cpu_inc(ai_irq_pcpu_stats.emit_wq);
	ai_telemetry_emit_direct(AI_CAT_INTERRUPT, AI_EV_IRQ,
				 AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_workqueue_launch);

void ai_telemetry_watchdog_lockup(u8 type, unsigned long duration,
				  unsigned long threshold)
{
	struct ai_irq_watchdog_payload p;

	if (!ai_irq_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = type;
	p.cpu = smp_processor_id();
	p.duration_s = duration;
	p.threshold_s = threshold;
	p.pid = task_pid_nr(current);
	strscpy(p.comm, current->comm, sizeof(p.comm));
	this_cpu_inc(ai_irq_pcpu_stats.emit_watchdog);
	ai_telemetry_emit_direct(AI_CAT_INTERRUPT, AI_EV_NMI_WATCHDOG,
				 (type == AI_IRQ_WATCHDOG_LOCKUP) ?
					AI_SEV_CRITICAL : AI_SEV_IMPORTANT,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_watchdog_lockup);
