// SPDX-License-Identifier: GPL-2.0
/*
 * ai_cpufreq.c - AI cpufreq governor "aiguard"（Prompt 10，重构计划 模块11 任务 11.2）
 *
 * 可插拔注册（与 ai_cca、AI I/O 调度器同模式）：
 *   - CONFIG_AIKERNEL_POWER=n 或 CONFIG_CPU_FREQ=n 时本文件不构建 → 不注册 →
 *     不出现在 scaling_available_governors，系统默认 governor 行为零影响；
 *   - 仅当用户显式 echo "aiguard" 写入 cpufreq 的 scaling_governor 属性才生效；
 *     测试后必须还原（echo schedutil 或 userspace）。
 *
 * 基础版（空实现回退 schedutil 行为）：
 *   1. rate-limit：与 schedutil 同源（cpufreq_policy_transition_delay_us）；
 *   2. util：busy-time 法（get_cpu_idle_time 两次采样差，导出接口无锁）；
 *   3. 参考频率：arch_scale_freq_invariant ? max_freq : cur + cur>>2
 *      （= schedutil get_capacity_ref_freq 在本树的等价形式，arch_scale_freq_ref
 *       为弱实现返回 0，走的正是此分支）；
 *   4. freq = map_util_freq(util, ref, arch_scale_cpu_capacity(cpu))；
 *   5. AI 决策接口 ai_power_cpufreq_hook()：空实现不改 → 原样；
 *   6. cpufreq_driver_resolve_freq() 收敛；fast-switch 直写或 irq_work+kthread 慢路径
 *      （schedutil 同款机制，自包含实现）。
 *
 * 与 schedutil 的差异（基础版如实声明）：util 用 busy-time 近似而非 PELT+headroom
 * （effective_cpu_util 未导出）；无 iowait boost / hold_freq 启发式。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/irq_work.h>
#include <linux/kthread.h>
#include <linux/cpufreq.h>
#include <linux/sched/cpufreq.h>
#include <linux/math64.h>
#include <linux/sched/topology.h>
#include <uapi/linux/sched/types.h>

#include "ai_power.h"

#ifdef CONFIG_CPU_FREQ

struct aiguard_policy {
	struct cpufreq_policy	*policy;

	raw_spinlock_t		update_lock;
	u64			last_freq_update_time;
	s64			freq_update_delay_ns;
	unsigned int		next_freq;
	unsigned int		cached_raw_freq;

	/* The next fields are only needed if fast switch cannot be used: */
	struct			irq_work irq_work;
	struct			kthread_work work;
	struct			mutex work_lock;
	struct			kthread_worker worker;
	struct task_struct	*thread;
	bool			work_in_progress;

	bool			limits_changed;
	bool			need_freq_update;
};

struct aiguard_cpu {
	struct update_util_data	update_util;
	struct aiguard_policy	*sg_policy;
	unsigned int		cpu;

	u64			prev_wall;
	u64			prev_idle;
};

static DEFINE_PER_CPU(struct aiguard_cpu, aiguard_cpu);

/************************ Governor internals ***********************/

static bool aiguard_should_update_freq(struct aiguard_policy *sg_policy, u64 time)
{
	s64 delta_ns;

	/*
	 * cpufreq_this_cpu_can_update() 未导出，这里取其第一分支等价：
	 * 本 CPU 属于该 policy 的 cpus 才允许更新。
	 */
	if (!cpumask_test_cpu(smp_processor_id(), sg_policy->policy->cpus))
		return false;

	if (unlikely(READ_ONCE(sg_policy->limits_changed))) {
		WRITE_ONCE(sg_policy->limits_changed, false);
		sg_policy->need_freq_update = true;
		smp_mb();
		return true;
	} else if (sg_policy->need_freq_update) {
		return true;
	}

	delta_ns = time - sg_policy->last_freq_update_time;
	return delta_ns >= sg_policy->freq_update_delay_ns;
}

static bool aiguard_update_next_freq(struct aiguard_policy *sg_policy, u64 time,
				     unsigned int next_freq)
{
	if (sg_policy->need_freq_update) {
		sg_policy->need_freq_update = false;
		if (sg_policy->next_freq == next_freq &&
		    !cpufreq_driver_test_flags(CPUFREQ_NEED_UPDATE_LIMITS))
			return false;
	} else if (sg_policy->next_freq == next_freq) {
		return false;
	}

	sg_policy->next_freq = next_freq;
	sg_policy->last_freq_update_time = time;

	return true;
}

static void aiguard_deferred_update(struct aiguard_policy *sg_policy)
{
	if (!sg_policy->work_in_progress) {
		sg_policy->work_in_progress = true;
		irq_work_queue(&sg_policy->irq_work);
	}
}

/*
 * busy-time util 估算：两次采样差 (wall_delta - idle_delta) / wall_delta，
 * 输出 0 ~ SCHED_CAPACITY_SCALE。
 */
static unsigned long aiguard_get_util(struct aiguard_cpu *sg_cpu)
{
	u64 wall = 0, idle;
	u64 delta_wall, delta_idle;
	unsigned long util = 0;

	idle = get_cpu_idle_time(sg_cpu->cpu, &wall, 0);
	delta_wall = wall - sg_cpu->prev_wall;
	delta_idle = idle - sg_cpu->prev_idle;
	sg_cpu->prev_wall = wall;
	sg_cpu->prev_idle = idle;

	if (delta_wall > 0) {
		if (delta_idle < delta_wall) {
			u64 busy = delta_wall - delta_idle;

			util = (busy * SCHED_CAPACITY_SCALE) / delta_wall;
		}
	}

	return util;
}

/*
 * 频率计算：schedutil 同款公式 + AI 决策接口。
 * AI 空实现不改 freq → 与 schedutil 行为一致。
 */
/* ---- power.freq 立即生效参数（aiguard 频率上限，万分比 0..10000） ----
 * value=目标频率上限万分比（10000=100% 不受限）；aiguard governor 每次
 * 频率计算真实钳制目标频率（cpufreq 环境下经 cpufreq_driver_resolve_freq
 * 收敛生效；QEMU 等无 cpufreq 虚拟化环境经请求/钳制计数观测面证明链路
 * 真实，虚拟化限制如实）。per-CPU 计数（util update 热路径无锁）。 */
static unsigned int aiguard_freq_max_pct;
static DEFINE_PER_CPU(u64, aiguard_freq_reqs);
static DEFINE_PER_CPU(u64, aiguard_freq_clamps);

unsigned int ai_aiguard_freq_max_pct_get(void)
{
	return READ_ONCE(aiguard_freq_max_pct);
}
EXPORT_SYMBOL_GPL(ai_aiguard_freq_max_pct_get);

void ai_aiguard_freq_max_pct_set(unsigned int pct)
{
	WRITE_ONCE(aiguard_freq_max_pct, pct);
}
EXPORT_SYMBOL_GPL(ai_aiguard_freq_max_pct_set);

void ai_aiguard_freq_stats_read(u64 *requests, u64 *clamped)
{
	u64 r = 0, c = 0;
	int i;

	for_each_possible_cpu(i) {
		r += per_cpu(aiguard_freq_reqs, i);
		c += per_cpu(aiguard_freq_clamps, i);
	}
	if (requests)
		*requests = r;
	if (clamped)
		*clamped = c;
}
EXPORT_SYMBOL_GPL(ai_aiguard_freq_stats_read);

static unsigned int aiguard_get_next_freq(struct aiguard_policy *sg_policy,
					  unsigned long util, u64 time)
{
	struct cpufreq_policy *policy = sg_policy->policy;
	unsigned long max = arch_scale_cpu_capacity(sg_policy->policy->cpu);
	unsigned int freq;
	unsigned long ref;
	unsigned int pct;

	if (arch_scale_freq_invariant())
		ref = policy->cpuinfo.max_freq;
	else
		ref = policy->cur + (policy->cur >> 2);

	freq = map_util_freq(util, ref, max);

	/* power.freq AI 上限钳制：真实作用于本 policy 目标频率计算 */
	pct = READ_ONCE(aiguard_freq_max_pct);
	this_cpu_inc(aiguard_freq_reqs);
	if (pct && pct < 10000) {
		unsigned int cap =
			(unsigned int)div_u64((u64)policy->cpuinfo.max_freq *
						      pct, 10000);

		if (freq > cap) {
			freq = cap;
			this_cpu_inc(aiguard_freq_clamps);
		}
	}

	if (freq == sg_policy->cached_raw_freq && !sg_policy->need_freq_update)
		return sg_policy->next_freq;

	ai_power_cpufreq_hook(policy, time, util, max, &freq);

	sg_policy->cached_raw_freq = freq;
	return cpufreq_driver_resolve_freq(policy, freq);
}

static void aiguard_update_single_freq(struct update_util_data *hook, u64 time,
				       unsigned int flags)
{
	struct aiguard_cpu *sg_cpu = container_of(hook, struct aiguard_cpu,
						  update_util);
	struct aiguard_policy *sg_policy = sg_cpu->sg_policy;
	unsigned int next_f;

	if (!aiguard_should_update_freq(sg_policy, time))
		return;

	next_f = aiguard_get_next_freq(sg_policy, aiguard_get_util(sg_cpu), time);

	if (!aiguard_update_next_freq(sg_policy, time, next_f))
		return;

	if (sg_policy->policy->fast_switch_enabled) {
		cpufreq_driver_fast_switch(sg_policy->policy, next_f);
	} else {
		raw_spin_lock(&sg_policy->update_lock);
		aiguard_deferred_update(sg_policy);
		raw_spin_unlock(&sg_policy->update_lock);
	}
}

static unsigned int aiguard_next_freq_shared(struct aiguard_policy *sg_policy,
					     u64 time)
{
	struct cpufreq_policy *policy = sg_policy->policy;
	unsigned long util = 0;
	unsigned int j;

	for_each_cpu(j, policy->cpus) {
		struct aiguard_cpu *j_sg_cpu = &per_cpu(aiguard_cpu, j);

		util = max(aiguard_get_util(j_sg_cpu), util);
	}

	return aiguard_get_next_freq(sg_policy, util, time);
}

static void aiguard_update_shared(struct update_util_data *hook, u64 time,
				  unsigned int flags)
{
	struct aiguard_cpu *sg_cpu = container_of(hook, struct aiguard_cpu,
						  update_util);
	struct aiguard_policy *sg_policy = sg_cpu->sg_policy;
	unsigned int next_f;

	raw_spin_lock(&sg_policy->update_lock);

	if (aiguard_should_update_freq(sg_policy, time)) {
		next_f = aiguard_next_freq_shared(sg_policy, time);

		if (!aiguard_update_next_freq(sg_policy, time, next_f))
			goto unlock;

		if (sg_policy->policy->fast_switch_enabled)
			cpufreq_driver_fast_switch(sg_policy->policy, next_f);
		else
			aiguard_deferred_update(sg_policy);
	}
unlock:
	raw_spin_unlock(&sg_policy->update_lock);
}

static void aiguard_work(struct kthread_work *work)
{
	struct aiguard_policy *sg_policy = container_of(work,
							struct aiguard_policy,
							work);
	unsigned int freq;
	unsigned long flags;

	raw_spin_lock_irqsave(&sg_policy->update_lock, flags);
	freq = sg_policy->next_freq;
	sg_policy->work_in_progress = false;
	raw_spin_unlock_irqrestore(&sg_policy->update_lock, flags);

	mutex_lock(&sg_policy->work_lock);
	__cpufreq_driver_target(sg_policy->policy, freq, CPUFREQ_RELATION_L);
	mutex_unlock(&sg_policy->work_lock);
}

static void aiguard_irq_work(struct irq_work *irq_work)
{
	struct aiguard_policy *sg_policy;

	sg_policy = container_of(irq_work, struct aiguard_policy, irq_work);

	kthread_queue_work(&sg_policy->worker, &sg_policy->work);
}

/********************** cpufreq governor interface *********************/

static int aiguard_init(struct cpufreq_policy *policy)
{
	struct aiguard_policy *sg_policy;
	int ret = 0;

	if (policy->governor_data)
		return -EBUSY;

	cpufreq_enable_fast_switch(policy);

	sg_policy = kzalloc(sizeof(*sg_policy), GFP_KERNEL);
	if (!sg_policy) {
		cpufreq_disable_fast_switch(policy);
		return -ENOMEM;
	}

	sg_policy->policy = policy;
	raw_spin_lock_init(&sg_policy->update_lock);
	policy->governor_data = sg_policy;

	if (!policy->fast_switch_enabled) {
		kthread_init_work(&sg_policy->work, aiguard_work);
		kthread_init_worker(&sg_policy->worker);
		sg_policy->thread = kthread_create(kthread_worker_fn,
						   &sg_policy->worker,
						   "aiguard:%d",
						   cpumask_first(policy->related_cpus));
		if (IS_ERR(sg_policy->thread)) {
			ret = PTR_ERR(sg_policy->thread);
			pr_err("failed to create aiguard thread: %d\n", ret);
			goto fail;
		}
		kthread_bind_mask(sg_policy->thread, policy->related_cpus);
		init_irq_work(&sg_policy->irq_work, aiguard_irq_work);
		mutex_init(&sg_policy->work_lock);
		wake_up_process(sg_policy->thread);
	}

	return 0;

fail:
	policy->governor_data = NULL;
	kfree(sg_policy);
	cpufreq_disable_fast_switch(policy);
	return ret;
}

static void aiguard_exit(struct cpufreq_policy *policy)
{
	struct aiguard_policy *sg_policy = policy->governor_data;

	if (!sg_policy)
		return;

	if (!policy->fast_switch_enabled) {
		kthread_flush_worker(&sg_policy->worker);
		kthread_stop(sg_policy->thread);
		mutex_destroy(&sg_policy->work_lock);
	}

	policy->governor_data = NULL;
	kfree(sg_policy);
	cpufreq_disable_fast_switch(policy);
}

static int aiguard_start(struct cpufreq_policy *policy)
{
	struct aiguard_policy *sg_policy = policy->governor_data;
	void (*uu)(struct update_util_data *data, u64 time, unsigned int flags);
	unsigned int cpu;

	sg_policy->freq_update_delay_ns = cpufreq_policy_transition_delay_us(policy)
					  * NSEC_PER_USEC;
	sg_policy->last_freq_update_time = 0;
	sg_policy->next_freq = 0;
	sg_policy->work_in_progress = false;
	sg_policy->limits_changed = false;
	sg_policy->cached_raw_freq = 0;
	sg_policy->need_freq_update =
		cpufreq_driver_test_flags(CPUFREQ_NEED_UPDATE_LIMITS);

	if (policy_is_shared(policy))
		uu = aiguard_update_shared;
	else
		uu = aiguard_update_single_freq;

	for_each_cpu(cpu, policy->cpus) {
		struct aiguard_cpu *sg_cpu = &per_cpu(aiguard_cpu, cpu);

		memset(sg_cpu, 0, sizeof(*sg_cpu));
		sg_cpu->cpu = cpu;
		sg_cpu->sg_policy = sg_policy;
		/* busy-time 采样基线（冷启动防一采样异常） */
		sg_cpu->prev_idle = get_cpu_idle_time(cpu, &sg_cpu->prev_wall, 0);
		cpufreq_add_update_util_hook(cpu, &sg_cpu->update_util, uu);
	}
	return 0;
}

static void aiguard_stop(struct cpufreq_policy *policy)
{
	struct aiguard_policy *sg_policy = policy->governor_data;
	unsigned int cpu;

	for_each_cpu(cpu, policy->cpus)
		cpufreq_remove_update_util_hook(cpu);

	synchronize_rcu();

	if (!policy->fast_switch_enabled) {
		irq_work_sync(&sg_policy->irq_work);
		kthread_cancel_work_sync(&sg_policy->work);
	}
}

static void aiguard_limits(struct cpufreq_policy *policy)
{
	struct aiguard_policy *sg_policy = policy->governor_data;

	if (!policy->fast_switch_enabled) {
		mutex_lock(&sg_policy->work_lock);
		cpufreq_policy_apply_limits(policy);
		mutex_unlock(&sg_policy->work_lock);
	}

	smp_wmb();
	WRITE_ONCE(sg_policy->limits_changed, true);
}

static struct cpufreq_governor aiguard_gov = {
	.name			= "aiguard",
	.owner			= THIS_MODULE,
	.flags			= CPUFREQ_GOV_DYNAMIC_SWITCHING,
	.init			= aiguard_init,
	.exit			= aiguard_exit,
	.start			= aiguard_start,
	.stop			= aiguard_stop,
	.limits			= aiguard_limits,
};

cpufreq_governor_init(aiguard_gov);

#endif /* CONFIG_CPU_FREQ */
