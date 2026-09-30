// SPDX-License-Identifier: GPL-2.0
/*
 * ai_lock.c - AIKernel 同步与锁优化核心（Prompt 09，重构计划 模块9）
 *
 * A 轨：5 个 ai_lock_*_hook()（空实现 = 原样放行，决策表待 AI 填充）；
 * B 轨：第10类 锁竞争与同步感知（10.01~10.04）发射辅助，全部
 *       sample_take 采样判定 + 栈上 payload + emit_direct 直写。
 *
 * 中断上下文安全：spin 争用埋点 1/256 采样（每次仅 1 次 per-CPU
 * inc_return+分支），采样命中才取时间戳（per-CPU 槽位），发射零锁
 * 零分配；comm 拷贝直接读 current->comm。
 *
 * mutex 等待时长：waiter 入队点记栈变量 start（同函数栈帧，跨 schedule()
 * 存活），获锁点结算——零全局表零锁。
 */

#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/pid.h>

#include "ai_lock.h"

/* ---- 决策统计（per-CPU 近似，汇总读取） ---- */

static DEFINE_PER_CPU(struct ai_lock_stats, ai_lock_pcpu_stats);

/* ---- per-CPU 预分配槽位（无锁无分配） ---- */

#define AI_LOCK_SPIN_SAMPLE_RATE	256

struct ai_lock_percpu {
	u64 spin_t0;			/* spin 采样窗口起始时间戳槽 */
	u64 spin_t0_lock;		/* 采样的锁地址 */
	u32 spin_samples;		/* spin 采样计数器 */
};

static DEFINE_PER_CPU(struct ai_lock_percpu, ai_lock_percpu);

bool ai_lock_sample_take(u32 rate)
{
	u32 c = __this_cpu_inc_return(ai_lock_percpu.spin_samples) - 1;

	return (rate <= 1) || (c % rate) == 0;
}

void ai_lock_stats_read(struct ai_lock_stats *st)
{
	int cpu;

	if (!st)
		return;
	memset(st, 0, sizeof(*st));
	for_each_possible_cpu(cpu) {
		const struct ai_lock_stats *p = per_cpu_ptr(&ai_lock_pcpu_stats,
							   cpu);

		st->spin_hook_calls += p->spin_hook_calls;
		st->spin_sampled += p->spin_sampled;
		st->mutex_hook_calls += p->mutex_hook_calls;
		st->mutex_hook_skip_spin += p->mutex_hook_skip_spin;
		st->rwsem_hook_calls += p->rwsem_hook_calls;
		st->rcu_hook_calls += p->rcu_hook_calls;
		st->rcu_hook_expedite += p->rcu_hook_expedite;
		st->lockdep_hook_calls += p->lockdep_hook_calls;
		st->emit_contention += p->emit_contention;
		st->emit_spin += p->emit_spin;
		st->emit_rwsem += p->emit_rwsem;
		st->emit_rcu += p->emit_rcu;
		st->emit_deadlock += p->emit_deadlock;
	}
}
EXPORT_SYMBOL_GPL(ai_lock_stats_read);

/* ==================================================================
 * A 轨：AI 同步与锁 Hook（空实现 = 原样放行）
 * ==================================================================
 */

void ai_lock_spin_hook(raw_spinlock_t *lock)
{
	struct ai_lock_percpu *pc = this_cpu_ptr(&ai_lock_percpu);

	this_cpu_inc(ai_lock_pcpu_stats.spin_hook_calls);
	/*
	 * 早期启动（timekeeping_init 前）禁用采样路径：ktime_get_ns()
	 * 在时钟源就绪前调用会导致启动即崩溃（QEMU 实测定位）。mutex/
	 * rwsem 路径最早在 initcall 期使用（timekeeping 已就绪），无需此闸。
	 */
	if (unlikely(system_state < SYSTEM_SCHEDULING))
		return;
	if (!ai_lock_sample_take(AI_LOCK_SPIN_SAMPLE_RATE))
		return;
	/* 采样窗口：锁后由 ai_lock_spin_hook_done() 结算争用时长 */
	pc->spin_t0 = ktime_get_ns();
	pc->spin_t0_lock = (unsigned long)lock;
	this_cpu_inc(ai_lock_pcpu_stats.spin_sampled);
}
EXPORT_SYMBOL_GPL(ai_lock_spin_hook);

void ai_lock_spin_hook_done(raw_spinlock_t *lock)
{
	struct ai_lock_percpu *pc = this_cpu_ptr(&ai_lock_percpu);
	u64 t0 = pc->spin_t0;

	if (!t0 || pc->spin_t0_lock != (unsigned long)lock)
		return;
	pc->spin_t0 = 0;
	ai_telemetry_lock_spin((unsigned long)lock, ktime_get_ns() - t0);
}
EXPORT_SYMBOL_GPL(ai_lock_spin_hook_done);

bool ai_lock_mutex_hook(struct mutex *lock, bool *try_spin)
{
	this_cpu_inc(ai_lock_pcpu_stats.mutex_hook_calls);
	/* AI 竞争预测：改 *try_spin=false 跳过乐观自旋直接入队（悲观路径） */
	return true;
}
EXPORT_SYMBOL_GPL(ai_lock_mutex_hook);

void ai_lock_rwsem_hook(struct rw_semaphore *sem, int kind)
{
	this_cpu_inc(ai_lock_pcpu_stats.rwsem_hook_calls);
	/* AI 读写偏向：后续可在此调整 reader/writer 优先级 */
}
EXPORT_SYMBOL_GPL(ai_lock_rwsem_hook);

void ai_lock_rcu_hook(int n, bool *expedite)
{
	this_cpu_inc(ai_lock_pcpu_stats.rcu_hook_calls);
	/* AI 预测回调压力：置 *expedite=true 建议 expedited 宽限期 */
	if (expedite && *expedite)
		this_cpu_inc(ai_lock_pcpu_stats.rcu_hook_expedite);
}
EXPORT_SYMBOL_GPL(ai_lock_rcu_hook);

void ai_lock_lockdep_hook(struct task_struct *curr, int depth)
{
	this_cpu_inc(ai_lock_pcpu_stats.lockdep_hook_calls);
	/* AI 分析锁依赖图预测死锁：决策表就绪后在此分析 */
}
EXPORT_SYMBOL_GPL(ai_lock_lockdep_hook);

/* ==================================================================
 * B 轨：第10类 锁竞争与同步感知发射辅助
 * ==================================================================
 */

void ai_telemetry_lock_contention(u64 lock_addr, u32 waiter_count)
{
	struct ai_lock_contention_payload p;

	if (!ai_lock_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_LOCK_CONTENTION_WAIT;
	p.pid = task_pid_nr(current);
	p.lock_addr = lock_addr;
	p.waiter_count = waiter_count;
	strscpy(p.comm, current->comm, sizeof(p.comm));
	this_cpu_inc(ai_lock_pcpu_stats.emit_contention);
	ai_telemetry_emit_direct(AI_CAT_LOCK, AI_EV_MUTEX, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_lock_contention);

void ai_telemetry_lock_contention_done(u64 lock_addr, u32 waiter_count,
				       u64 wait_ns)
{
	struct ai_lock_contention_payload p;

	if (!ai_lock_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_LOCK_CONTENTION_ACQUIRED;
	p.pid = task_pid_nr(current);
	p.lock_addr = lock_addr;
	p.waiter_count = waiter_count;
	p.wait_ns = wait_ns;
	strscpy(p.comm, current->comm, sizeof(p.comm));
	this_cpu_inc(ai_lock_pcpu_stats.emit_contention);
	ai_telemetry_emit_direct(AI_CAT_LOCK, AI_EV_MUTEX, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_lock_contention_done);

void ai_telemetry_lock_spin(u64 lock_addr, u64 wait_ns)
{
	struct ai_lock_spin_payload p;

	if (!ai_lock_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_LOCK_SPIN_CONTENTION;
	p.pid = task_pid_nr(current);
	p.lock_addr = lock_addr;
	p.wait_ns = wait_ns;
	strscpy(p.comm, current->comm, sizeof(p.comm));
	this_cpu_inc(ai_lock_pcpu_stats.emit_spin);
	ai_telemetry_emit_direct(AI_CAT_LOCK, AI_EV_SPINLOCK, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_lock_spin);

void ai_telemetry_rwsem_bias(u64 lock_addr, int kind, u32 waiters_read,
			     u32 waiters_write)
{
	struct ai_lock_rwsem_payload p;

	if (!ai_lock_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = (kind == 2) ? AI_LOCK_RWSEM_WRITE : AI_LOCK_RWSEM_READ;
	p.pid = task_pid_nr(current);
	p.lock_addr = lock_addr;
	p.waiters_read = waiters_read;
	p.waiters_write = waiters_write;
	strscpy(p.comm, current->comm, sizeof(p.comm));
	this_cpu_inc(ai_lock_pcpu_stats.emit_rwsem);
	ai_telemetry_emit_direct(AI_CAT_LOCK, AI_EV_RWSEM, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_rwsem_bias);

void ai_telemetry_rcu_gp(int n, bool expedited, u64 wait_ns)
{
	struct ai_lock_rcu_payload p;

	if (!ai_lock_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_LOCK_RCU_GP;
	p.pid = task_pid_nr(current);
	p.n = n;
	p.expedited = expedited;
	p.wait_ns = wait_ns;
	strscpy(p.comm, current->comm, sizeof(p.comm));
	this_cpu_inc(ai_lock_pcpu_stats.emit_rcu);
	ai_telemetry_emit_direct(AI_CAT_LOCK, AI_EV_RTMUTEX, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_rcu_gp);

void ai_telemetry_lockdep_deadlock(u8 type, u64 prev_class, u64 next_class,
				   u32 depth)
{
	struct ai_lock_lockdep_payload p;

	if (!ai_lock_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = type;
	p.pid = task_pid_nr(current);
	p.prev_class = prev_class;
	p.next_class = next_class;
	p.depth = depth;
	strscpy(p.comm, current->comm, sizeof(p.comm));
	this_cpu_inc(ai_lock_pcpu_stats.emit_deadlock);
	ai_telemetry_emit_direct(AI_CAT_LOCK, AI_EV_RTMUTEX, AI_SEV_CRITICAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_lockdep_deadlock);
