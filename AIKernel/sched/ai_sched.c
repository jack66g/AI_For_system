// SPDX-License-Identifier: GPL-2.0
/*
 * ai_sched.c - AIKernel 调度子系统核心（Prompt 03）
 *
 * A 轨：AI 调度决策框架。
 *   - 进程分类（AI负载/交互式/批处理）与时间片预测（占位启发式，
 *     后续步骤由 AI Runtime 推理策略替换）；
 *   - 全部 ai_sched_*_hook() 空实现 = 原样放行（返回值不改变内核默认行为），
 *     本步只负责签名落地 + 决策计数 + 遥测采集。
 *
 * B 轨：第1类 CPU 与调度感知。
 *   - 每秒采样器 ai_sched_metrics_sampler()：cpu_load（avenrun）、
 *     cpu_utilization（kernel_cpustat 差分）、cpu_frequency（cpufreq）、
 *     cpu_cstate（cpuidle）、cpu_temperature（thermal）、rq_depth、psi；
 *   - cpu_hotplug：kernel/cpu.c 的 CPU hotplug 通知链（cpuhp 回调）；
 *   - sched_domain：启动时采集一次（rcu 读锁遍历 rq->sd 链）。
 *
 * 铁律：遥测路径不阻塞、不分配（无 GFP_KERNEL）、无锁；
 * CONFIG_AIKERNEL_TELEMETRY=n 时本文件只保留计数与空 Hook。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/cpumask.h>
#include <linux/atomic.h>
#include <linux/string.h>
#include <linux/cpu.h>
#include <linux/pid.h>
#include <linux/math64.h>
#include <linux/sched.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/rt.h>
#include <linux/sched/isolation.h>
#include <linux/kernel_stat.h>
#include <linux/cpufreq.h>
#include <linux/cpuidle.h>
#include <linux/thermal.h>
#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"
#include "../core/ai_control.h"
#include <linux/ai_accessors.h>
#include "ai_sched.h"

/* 调度子系统内部类型（cpu_rq()/struct rq/struct cfs_rq 等）——
 * AIKernel/sched/ 属调度子系统，允许依赖 kernel/sched/sched.h。 */
#include "../../kernel/sched/sched.h"

/* ==================================================================
 * 决策统计（/proc/ai/sched/stats 数据源；近似计数，非精确账目）
 * ================================================================== */

static struct ai_sched_stats ai_sched_stats;

void ai_sched_stats_read(struct ai_sched_stats *st)
{
	if (!st)
		return;
	*st = ai_sched_stats;
}
EXPORT_SYMBOL_GPL(ai_sched_stats_read);

/* ==================================================================
 * A 轨：决策框架（占位启发式 + 默认放行 Hook）
 * ================================================================== */

int ai_sched_classify_task(struct task_struct *p)
{
	int cls = AI_SCHED_CLASS_BATCH;

	if (!p)
		return cls;

	/* 系统关键类（RT/DL）恒为 AI 负载 */
	if (rt_task(p) || dl_task(p)) {
		cls = AI_SCHED_CLASS_AI_LOAD;
		goto out;
	}

	/* CFS：util_avg >= 512（约 50% 算力）→ AI 负载 */
	if (p->se.avg.util_avg >= 512) {
		cls = AI_SCHED_CLASS_AI_LOAD;
		goto out;
	}

	/* 低利用率 + 多次运行 → 交互式（占位启发式） */
#ifdef CONFIG_SCHED_INFO
	if (p->se.avg.util_avg <= 256 && p->sched_info.pcount > 100)
		cls = AI_SCHED_CLASS_INTERACTIVE;
#endif

out:
	WRITE_ONCE(ai_sched_stats.classify[cls],
		   READ_ONCE(ai_sched_stats.classify[cls]) + 1);
	return cls;
}
EXPORT_SYMBOL_GPL(ai_sched_classify_task);

u64 ai_sched_predict_timeslice(struct task_struct *p)
{
	if (!p)
		return 0;

	if (rt_task(p))
		return (u64)p->rt.time_slice * NSEC_PER_USEC;

	return p->se.slice;
}
EXPORT_SYMBOL_GPL(ai_sched_predict_timeslice);

/* ---- Hook：空实现 = 原样放行 ---- */

void ai_sched_pick_next_hook(struct task_struct **prev, struct task_struct **next)
{
	WRITE_ONCE(ai_sched_stats.pick_next_calls,
		   READ_ONCE(ai_sched_stats.pick_next_calls) + 1);
	/* AI 推理占位：本步不修改 prev/next */
}
EXPORT_SYMBOL_GPL(ai_sched_pick_next_hook);

struct task_struct *ai_cfs_pick_next_hook(struct task_struct *prev,
					  struct task_struct *next)
{
	WRITE_ONCE(ai_sched_stats.cfs_pick_calls,
		   READ_ONCE(ai_sched_stats.cfs_pick_calls) + 1);
	return next;   /* 原样返回 */
}
EXPORT_SYMBOL_GPL(ai_cfs_pick_next_hook);

int ai_load_balance_hook(int src_cpu, int dst_cpu, unsigned long imbalance,
			 bool *proceed)
{
	WRITE_ONCE(ai_sched_stats.lb_calls,
		   READ_ONCE(ai_sched_stats.lb_calls) + 1);
	if (proceed)
		*proceed = true;   /* 默认继续迁移 */
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_load_balance_hook);

u64 ai_pelt_adjust_hook(u64 delta, unsigned long load)
{
	WRITE_ONCE(ai_sched_stats.pelt_adjust_calls,
		   READ_ONCE(ai_sched_stats.pelt_adjust_calls) + 1);
	return delta;   /* 原样返回 */
}
EXPORT_SYMBOL_GPL(ai_pelt_adjust_hook);

void ai_sched_context_switch_hook(struct task_struct *prev,
				  struct task_struct *next, int cpu)
{
	WRITE_ONCE(ai_sched_stats.context_switch_calls,
		   READ_ONCE(ai_sched_stats.context_switch_calls) + 1);
}
EXPORT_SYMBOL_GPL(ai_sched_context_switch_hook);

int ai_sched_rt_admission_hook(struct task_struct *p)
{
	/* 区分 RT/DL 调用来源（按任务策略判定） */
	if (dl_task(p))
		WRITE_ONCE(ai_sched_stats.dl_admission_calls,
			   READ_ONCE(ai_sched_stats.dl_admission_calls) + 1);
	else
		WRITE_ONCE(ai_sched_stats.rt_admission_calls,
			   READ_ONCE(ai_sched_stats.rt_admission_calls) + 1);
	return 1;   /* 本步允许全部；AI 准入决策后续步骤接通 */
}
EXPORT_SYMBOL_GPL(ai_sched_rt_admission_hook);

void ai_sched_isolate_hook(const struct cpumask *isolated, unsigned long hk_type)
{
	WRITE_ONCE(ai_sched_stats.isolate_hook_calls,
		   READ_ONCE(ai_sched_stats.isolate_hook_calls) + 1);
	/* 本步不修改隔离配置；AI 动态隔离建议后续步骤落地 */
}
EXPORT_SYMBOL_GPL(ai_sched_isolate_hook);

int ai_sched_query(u32 query_id, const void *in, size_t in_len,
		   void *out, size_t out_len)
{
	WRITE_ONCE(ai_sched_stats.query_calls,
		   READ_ONCE(ai_sched_stats.query_calls) + 1);

	switch (query_id) {
	case AI_SCHED_QUERY_SCX_READY:
		/* sched_ext 启用探测：AI 辅助可用 */
		return AI_OK;
	case AI_SCHED_QUERY_CLASSIFY: {
		struct task_struct *p;
		int pid, cls;

		if (!in || in_len < sizeof(int) || !out || out_len < sizeof(int))
			return AI_ERR_INVALID_ARG;
		pid = *(const int *)in;
		rcu_read_lock();
		p = find_task_by_vpid(pid);
		cls = p ? ai_sched_classify_task(p) : AI_SCHED_CLASS_BATCH;
		rcu_read_unlock();
		*(int *)out = cls;
		return AI_OK;
	}
	case AI_SCHED_QUERY_TIMESLICE: {
		struct task_struct *p;
		u64 slice;
		int pid;

		if (!in || in_len < sizeof(int) || !out || out_len < sizeof(u64))
			return AI_ERR_INVALID_ARG;
		pid = *(const int *)in;
		rcu_read_lock();
		p = find_task_by_vpid(pid);
		slice = p ? ai_sched_predict_timeslice(p) : 0;
		rcu_read_unlock();
		*(u64 *)out = slice;
		return AI_OK;
	}
	default:
		return AI_ERR_INVALID_ARG;
	}
}
EXPORT_SYMBOL_GPL(ai_sched_query);

/* ==================================================================
 * B 轨：遥测采集
 * ================================================================== */

#ifdef CONFIG_AIKERNEL_TELEMETRY

/* update_curr 热路径 PELT 采样（每 64 次发射 1 次，per-CPU 计数器） */
static DEFINE_PER_CPU(u32, ai_pelt_sample_cnt);

void ai_telemetry_pelt_se_sample(struct sched_entity *se, struct cfs_rq *cfs_rq)
{
	u32 cnt = this_cpu_inc_return(ai_pelt_sample_cnt);
	struct ai_pelt_cfs_payload cfs;
	struct task_struct *p;

	if ((cnt & 0x3F) != 0)
		return;

	cfs.type = AI_PELT_CFS;
	cfs.cpu = (u16)smp_processor_id();
	cfs.util_avg = (u32)cfs_rq->avg.util_avg;
	cfs.load_avg = (u32)cfs_rq->avg.load_avg;
	cfs.runnable_avg = (u32)cfs_rq->avg.runnable_avg;
	ai_telemetry_pelt(AI_SEV_DEBUG, &cfs, sizeof(cfs));

	if (se && entity_is_task(se)) {
		struct ai_pelt_se_payload sev;

		p = task_of(se);
		sev.type = AI_PELT_SE;
		sev.pid = task_pid_nr(p);
		sev.util_avg = (u32)se->avg.util_avg;
		sev.load_avg = (u32)se->avg.load_avg;
		sev.runnable_avg = (u32)se->avg.runnable_avg;
		strscpy(sev.comm, p->comm, TASK_COMM_LEN);
		ai_telemetry_pelt(AI_SEV_DEBUG, &sev, sizeof(sev));
	}
}
EXPORT_SYMBOL_GPL(ai_telemetry_pelt_se_sample);

/* ---- 每秒采样器 ---- */

/* 上一采样周期 kernel_cpustat 快照（固定数组，无运行时分配） */
static u64 ai_sched_cpustat_prev[NR_CPUS][NR_STATS];

static void ai_sched_sample_cpu_load(void)
{
	struct ai_cpu_load_payload ld;

	/* avenrun 为全系统负载（定点值，实际负载 = 值/2048） */
	ld.type = AI_CPU_LOAD;
	ld.cpu = 0;
	ld.load_1min = (u32)READ_ONCE(avenrun[0]);
	ld.load_5min = (u32)READ_ONCE(avenrun[1]);
	ld.load_15min = (u32)READ_ONCE(avenrun[2]);
	ai_telemetry_cpu_load(AI_SEV_NORMAL, &ld, sizeof(ld));
}

static void ai_sched_sample_cpu_utilization(void)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct ai_cpu_utilization_payload ut;
		u64 cur[NR_STATS], delta[NR_STATS], total = 0;
		int s;

		for (s = 0; s < NR_STATS; s++) {
			cur[s] = kcpustat_cpu(cpu).cpustat[s];
			delta[s] = cur[s] - ai_sched_cpustat_prev[cpu][s];
			ai_sched_cpustat_prev[cpu][s] = cur[s];
			total += delta[s];
		}

		ut.type = AI_CPU_UTILIZATION;
		ut.cpu = cpu;
		/* sys 含 IRQ+SOFTIRQ，softirq 另行单列（与计划字段对齐） */
		ut.user_pct = total ? div64_u64((delta[CPUTIME_USER] +
				delta[CPUTIME_NICE] + delta[CPUTIME_GUEST] +
				delta[CPUTIME_GUEST_NICE]) * 100, total) : 0;
		ut.sys_pct = total ? div64_u64((delta[CPUTIME_SYSTEM] +
				delta[CPUTIME_IRQ] + delta[CPUTIME_SOFTIRQ]) *
				100, total) : 0;
		ut.iowait_pct = total ? div64_u64(delta[CPUTIME_IOWAIT] * 100,
						  total) : 0;
		ut.idle_pct = total ? div64_u64(delta[CPUTIME_IDLE] * 100,
						total) : 0;
		ut.steal_pct = total ? div64_u64(delta[CPUTIME_STEAL] * 100,
						 total) : 0;
		ut.softirq_pct = total ? div64_u64(delta[CPUTIME_SOFTIRQ] * 100,
						   total) : 0;
		ai_telemetry_cpu_load(AI_SEV_DEBUG, &ut, sizeof(ut));
	}
}

static void ai_sched_sample_cpu_frequency(void)
{
#ifdef CONFIG_CPU_FREQ
	int cpu;

	for_each_online_cpu(cpu) {
		struct ai_cpu_frequency_payload fq;
		struct cpufreq_policy *pol;
		unsigned int cur, max;

		cur = cpufreq_quick_get(cpu);
		max = cpufreq_quick_get_max(cpu);
		pol = cpufreq_cpu_get(cpu);
		fq.type = AI_CPU_FREQUENCY;
		fq.cpu = cpu;
		fq.cur_freq_khz = cur;
		fq.max_freq_khz = max;
		strscpy(fq.governor,
			(pol && pol->governor) ? pol->governor->name : "none",
			sizeof(fq.governor));
		if (pol)
			cpufreq_cpu_put(pol);
		ai_telemetry_cpu_load(AI_SEV_DEBUG, &fq, sizeof(fq));
	}
#endif
}

static void ai_sched_sample_cpu_cstate(void)
{
#ifdef CONFIG_CPU_IDLE
	int cpu;

	for_each_online_cpu(cpu) {
		struct ai_cpu_cstate_payload cs;
		struct cpuidle_device *dev;
		struct cpuidle_driver *drv;

		dev = per_cpu(cpuidle_devices, cpu);
		drv = dev ? cpuidle_get_cpu_driver(dev) : NULL;

		cs.type = AI_CPU_CSTATE;
		cs.cpu = cpu;
		cs.state_idx = dev ? dev->last_state_idx : 0;
		/* last_residency_ns 为纳秒驻留 → 转 us 存储 */
		cs.residency_us = dev ? div_u64(dev->last_residency_ns, 1000) : 0;
		if (drv && cs.state_idx < drv->state_count)
			strscpy(cs.state_name, drv->states[cs.state_idx].name,
				sizeof(cs.state_name));
		else
			strscpy(cs.state_name, "none", sizeof(cs.state_name));
		ai_telemetry_cpu_load(AI_SEV_DEBUG, &cs, sizeof(cs));
	}
#endif
}

static void ai_sched_sample_cpu_temperature(void)
{
#ifdef CONFIG_THERMAL
	/* x86 常见 CPU 热区名（coretemp 提供）；未找到则跳过（不发射零值） */
	static const char * const ai_thermal_zones[] = {
		"cpu", "x86_pkg_temp",
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(ai_thermal_zones); i++) {
		struct ai_cpu_temperature_payload tp;
		struct thermal_zone_device *tz;
		int temp = 0;

		tz = thermal_zone_get_zone_by_name(ai_thermal_zones[i]);
		if (IS_ERR(tz))
			continue;
		if (thermal_zone_get_temp(tz, &temp))
			continue;

		tp.type = AI_CPU_TEMPERATURE;
		tp.cpu = 0;
		tp.temp_millicelsius = temp;
		tp.trip_point = 0;
		strscpy(tp.zone_name, ai_thermal_zones[i], sizeof(tp.zone_name));
		ai_telemetry_cpu_load(AI_SEV_NORMAL, &tp, sizeof(tp));
	}
#endif
}

static void ai_sched_sample_rq_depth(void)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct ai_rq_depth_payload rq;
		struct rq *r = cpu_rq(cpu);

		rq.type = AI_RQ_DEPTH;
		rq.cpu = cpu;
		rq.nr_running = READ_ONCE(r->nr_running);
		/* per-CPU 近似（全局和才精确；事件注释说明） */
		rq.nr_uninterruptible = (u32)READ_ONCE(r->nr_uninterruptible);
		rq.nr_iowait = (u32)atomic_read(&r->nr_iowait);
		ai_telemetry_rq_depth(AI_SEV_DEBUG, &rq, sizeof(rq));
	}
}

static void ai_sched_sample_psi(void)
{
#ifdef CONFIG_PSI
	unsigned long some[3], full[3];
	u8 res;

	for (res = PSI_CPU; res <= PSI_IO; res++) {
		struct ai_psi_payload ps;

		if (ai_psi_read(res, some, full) != AI_OK)
			continue;

		ps.type = AI_PSI;
		ps.resource = res;
		/* avg[] 为定点值（FIXED_1=2048，百分比 = 值*100/2048） */
		ps.some_avg10 = (u32)some[0];
		ps.some_avg60 = (u32)some[1];
		ps.some_avg300 = (u32)some[2];
		ps.full_avg10 = (u32)full[0];
		ps.full_avg60 = (u32)full[1];
		ps.full_avg300 = (u32)full[2];
		ai_telemetry_psi(AI_SEV_NORMAL, &ps, sizeof(ps));
	}
#endif
}

static void ai_sched_metrics_sample_once(void)
{
	ai_sched_sample_cpu_load();
	ai_sched_sample_cpu_utilization();
	ai_sched_sample_cpu_frequency();
	ai_sched_sample_cpu_cstate();
	ai_sched_sample_cpu_temperature();
	ai_sched_sample_rq_depth();
	ai_sched_sample_psi();
}

static int ai_sched_metrics_sampler(void *unused)
{
	while (!kthread_should_stop()) {
		ai_sched_metrics_sample_once();
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ);
	}
	return 0;
}

/* ---- cpu_hotplug（kernel/cpu.c 通知链回调） ---- */

static int ai_sched_cpu_online(unsigned int cpu)
{
	struct ai_cpu_hotplug_payload hp;

	hp.type = AI_SCHED_HOTPLUG;
	hp.cpu = cpu;
	hp.online = 1;
	ai_telemetry_cpu_hotplug(AI_SEV_IMPORTANT, &hp, sizeof(hp));
	return 0;
}

static int ai_sched_cpu_offline(unsigned int cpu)
{
	struct ai_cpu_hotplug_payload hp;

	hp.type = AI_SCHED_HOTPLUG;
	hp.cpu = cpu;
	hp.online = 0;
	ai_telemetry_cpu_hotplug(AI_SEV_IMPORTANT, &hp, sizeof(hp));
	return 0;
}

/* ---- 调度域拓扑（启动采集一次） ---- */

static void ai_sched_domain_emit_once(void)
{
	int cpu;

	rcu_read_lock();
	for_each_online_cpu(cpu) {
		struct sched_domain *sd;

		for (sd = rcu_dereference(cpu_rq(cpu)->sd); sd;
		     sd = rcu_dereference(sd->parent)) {
			struct ai_sched_domain_payload d;
			unsigned int i, n;

			n = min_t(unsigned int, BITS_TO_LONGS(NR_CPUS),
				  BITS_TO_LONGS(nr_cpu_ids));
			d.type = AI_SCHED_DOMAIN;
			d.cpu = cpu;
			d.level = sd->level;
			d.flags = sd->flags;
			for (i = 0; i < n; i++)
				d.span_bits[i] =
					cpumask_bits(sched_domain_span(sd))[i];
			for (; i < BITS_TO_LONGS(NR_CPUS); i++)
				d.span_bits[i] = 0;
			strscpy(d.name, sd->name ? sd->name : "?",
				sizeof(d.name));
			ai_telemetry_sched_domain(AI_SEV_NORMAL, &d, sizeof(d));
		}
	}
	rcu_read_unlock();
}

/* ---- 初始化 ---- */

static struct task_struct *ai_sched_sampler_task;
static int ai_sched_cpuhp_state;


/* ---- sched.timeslice 立即生效参数（EEVDF base slice 门控访问器） ----
 * EEVDF 无静态 timeslice：value（0.1ms 单位）映射 sysctl_sched_base_slice
 * （ns），20 → 2ms；注册默认不主动改写系统启动值（700us），AI 下发才生效。 */
static int ai_sched_timeslice_apply(struct ai_control_param *p, s32 pid,
				    s64 value, s64 *eff)
{
	int rc;

	if (value < 1 || value > 1000)
		return AI_ERR_INVALID_ARG;
	rc = ai_sched_base_slice_set_ns((u64)value * 100000);
	if (rc)
		return AI_ERR_GENERIC;
	*eff = value;
	pr_info("AIKernel: sched.timeslice %lld (0.1ms) -> base_slice %llu ns\n",
		value, (u64)value * 100000);
	return AI_OK;
}

static int __init ai_sched_init(void)
{
	/* 幂等：CONFIG_AIKERNEL_RUNTIME 已在 start_kernel 调用过则无操作 */
	ai_telemetry_init();

	/* 热路径事件默认采样率（其余事件全量）：
	 * sched_latency 1/32、pelt 1/64——控制性能预算同时保留统计意义 */
	ai_telemetry_set_sample_rate(AI_CAT_SCHED, AI_EV_SCHED_LATENCY, 32);
	ai_telemetry_set_sample_rate(AI_CAT_SCHED, AI_EV_PELT, 64);

	/* 可控制参数表（数据计划 20.3 调度域）：sched.timeslice 立即生效
	 * （EEVDF base slice 门控访问器，value 单位 0.1ms） */
	ai_control_register("sched.timeslice", AI_POLICY_DOMAIN_SCHED,
			    AI_CTRL_F_REAL, 1, 1000, 20,
			    ai_sched_timeslice_apply);

	ai_sched_domain_emit_once();

	ai_sched_sampler_task = kthread_run(ai_sched_metrics_sampler, NULL,
					    "ai_sched_metrics");
	if (IS_ERR(ai_sched_sampler_task)) {
		ai_sched_sampler_task = NULL;
		pr_warn("AIKernel: sched metrics sampler start failed\n");
	}

	ai_sched_cpuhp_state = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
					"aikernel/sched:online",
					ai_sched_cpu_online, ai_sched_cpu_offline);
	if (ai_sched_cpuhp_state < 0)
		pr_warn("AIKernel: sched cpuhp state registration failed (%d)\n",
			ai_sched_cpuhp_state);

	pr_info("AIKernel: sched subsystem ready (AI hooks + telemetry)\n");
	return 0;
}
late_initcall(ai_sched_init);

#endif /* CONFIG_AIKERNEL_TELEMETRY */
