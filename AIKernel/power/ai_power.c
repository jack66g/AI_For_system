// SPDX-License-Identifier: GPL-2.0
/*
 * ai_power.c - AIKernel 电源管理核心（Prompt 10，重构计划 模块11）
 *
 * A 轨：6 个 ai_power_*_hook()（空实现 = 原样放行，决策表待 AI 填充）；
 * B 轨：第12类 电源管理感知（12.01~12.05）发射辅助，全部
 *       sample_take 采样判定 + 栈上 payload + emit_direct 直写。
 *
 * 热路径安全性：
 *   - cpuidle Hook（idle 决策热路径）只做 per-CPU inc + 分支，零锁零分配零 printk；
 *   - 全部发射辅助 < 100ns 预算（per-CPU ring 无锁写，满则丢）；
 *   - per-CPU 计数器直接对符号操作（Prompt 09 早期启动崩溃先例）。
 *
 * 跨目录类型隔离：本文件不 include 任何内核电源/热管理私有头，Hook 全标量参数。
 */

#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/pm_qos.h>
#ifdef CONFIG_TRACEPOINTS
#include <linux/tracepoint.h>
#include <trace/events/sched.h>
#endif

#include "ai_power.h"
#include "../core/ai_control.h"

/* ---- 决策统计（per-CPU 近似，汇总读取） ---- */

static DEFINE_PER_CPU(struct ai_power_stats, ai_power_pcpu_stats);

/* ---- per-CPU 采样计数器（无锁） ---- */

struct ai_power_percpu {
	u32 cpuidle_samples;		/* C-state 驻留采样计数器 */
	u32 thermal_samples;		/* 温度趋势采样计数器 */
	u32 idle_samples;		/* 通用采样计数器 */
};

static DEFINE_PER_CPU(struct ai_power_percpu, ai_power_percpu);

bool ai_power_sample_take(u32 rate)
{
	u32 c = __this_cpu_inc_return(ai_power_percpu.idle_samples) - 1;

	return (rate <= 1) || ((c % rate) == 0);
}
EXPORT_SYMBOL_GPL(ai_power_sample_take);

static bool ai_power_cpuidle_sample_take(void)
{
	u32 c = __this_cpu_inc_return(ai_power_percpu.cpuidle_samples) - 1;

	return (c % 64) == 0;
}

static bool ai_power_thermal_sample_take(void)
{
	u32 c = __this_cpu_inc_return(ai_power_percpu.thermal_samples) - 1;

	return (c % 16) == 0;
}

void ai_power_stats_read(struct ai_power_stats *st)
{
	int cpu;

	if (!st)
		return;
	memset(st, 0, sizeof(*st));
	for_each_possible_cpu(cpu) {
		const struct ai_power_stats *p = per_cpu_ptr(&ai_power_pcpu_stats,
							    cpu);

		st->cpufreq_hook_calls += p->cpufreq_hook_calls;
		st->cpufreq_hook_adjusted += p->cpufreq_hook_adjusted;
		st->cpuidle_hook_calls += p->cpuidle_hook_calls;
		st->cpuidle_hook_adjusted += p->cpuidle_hook_adjusted;
		st->em_hook_calls += p->em_hook_calls;
		st->thermal_hook_calls += p->thermal_hook_calls;
		st->qos_hook_calls += p->qos_hook_calls;
		st->wakelock_hook_calls += p->wakelock_hook_calls;
		st->emit_cpufreq += p->emit_cpufreq;
		st->emit_cpuidle += p->emit_cpuidle;
		st->emit_em += p->emit_em;
		st->emit_thermal += p->emit_thermal;
		st->emit_qos += p->emit_qos;
		st->emit_wakelock += p->emit_wakelock;
	}
}
EXPORT_SYMBOL_GPL(ai_power_stats_read);

/* ==================================================================
 * A 轨：AI 电源管理 Hook（空实现 = 原样放行）
 * ==================================================================
 */

void ai_power_cpufreq_hook(struct cpufreq_policy *policy, u64 time,
			   unsigned long util, unsigned long max,
			   unsigned int *freq)
{
	this_cpu_inc(ai_power_pcpu_stats.cpufreq_hook_calls);
	/* AI 频率决策：可改写 *freq（aiguard 空实现 = schedutil 同款公式原样） */
	if (freq && *freq == 0)
		this_cpu_inc(ai_power_pcpu_stats.cpufreq_hook_adjusted);
}
EXPORT_SYMBOL_GPL(ai_power_cpufreq_hook);

void ai_power_cpuidle_hook(int cpu, int state_count, u64 latency_req_ns,
			   u64 *predicted_ns, int *idx)
{
	this_cpu_inc(ai_power_pcpu_stats.cpuidle_hook_calls);
	/* AI 预测空闲时长选 C-state：可改 *predicted_ns / *idx（调用点钳制边界） */
	if (idx && *idx < 0)
		this_cpu_inc(ai_power_pcpu_stats.cpuidle_hook_adjusted);
}
EXPORT_SYMBOL_GPL(ai_power_cpuidle_hook);

void ai_power_em_hook(struct device *dev, struct em_perf_table *table)
{
	this_cpu_inc(ai_power_pcpu_stats.em_hook_calls);
	/* AI 实时更新能耗模型参数：可调整 table->state[]（空实现不改） */
}
EXPORT_SYMBOL_GPL(ai_power_em_hook);

void ai_power_thermal_hook(const char *zone, int temperature,
			   int last_temperature, int *target_temp)
{
	this_cpu_inc(ai_power_pcpu_stats.thermal_hook_calls);
	/* AI 预测温度趋势提前降频：可改 *target_temp（空实现不改） */
}
EXPORT_SYMBOL_GPL(ai_power_thermal_hook);

void ai_power_qos_hook(int qos_type, int action, int prev_value,
		       int *curr_value)
{
	this_cpu_inc(ai_power_pcpu_stats.qos_hook_calls);
	/* AI 评估 QoS 约束合理性：可改 *curr_value（空实现不改） */
}
EXPORT_SYMBOL_GPL(ai_power_qos_hook);

void ai_power_wakelock_hook(const char *name, size_t len, u64 timeout_ns,
			    u8 action)
{
	this_cpu_inc(ai_power_pcpu_stats.wakelock_hook_calls);
	/* AI 预测 wakeup 事件预唤醒：决策表就绪后在此评估 */
}
EXPORT_SYMBOL_GPL(ai_power_wakelock_hook);

/* ==================================================================
 * B 轨：第12类 电源管理感知发射辅助
 * ==================================================================
 */

void ai_telemetry_cpufreq_change(u16 cpu, u32 old_freq, u32 new_freq,
				 u8 relation, const char *governor)
{
	struct ai_power_cpufreq_payload p;

	if (!ai_power_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_POWER_CPUFREQ_CHANGE;
	p.cpu = cpu;
	p.old_freq_khz = old_freq;
	p.new_freq_khz = new_freq;
	p.relation = relation;
	strscpy(p.governor, governor ? governor : "none", sizeof(p.governor));
	this_cpu_inc(ai_power_pcpu_stats.emit_cpufreq);
	ai_telemetry_emit_direct(AI_CAT_POWER, AI_EV_CPUFREQ, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_cpufreq_change);

void ai_telemetry_cpuidle_state(u16 cpu, u32 state_idx, u64 residency_ns,
				const char *state_name)
{
	struct ai_power_cpuidle_payload p;

	if (!ai_power_cpuidle_sample_take())
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_POWER_CPUIDLE_STATE;
	p.cpu = cpu;
	p.state_idx = state_idx;
	p.residency_ns = residency_ns;
	strscpy(p.state_name, state_name ? state_name : "none",
		sizeof(p.state_name));
	this_cpu_inc(ai_power_pcpu_stats.emit_cpuidle);
	ai_telemetry_emit_direct(AI_CAT_POWER, AI_EV_CPUIDLE, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_cpuidle_state);

void ai_telemetry_energy_model(const char *dev_name, u32 nr_states,
			       const u32 *freq_khz, const u32 *power_mw)
{
	struct ai_power_energy_model_payload p;
	u32 n;

	if (!ai_power_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_POWER_ENERGY_MODEL_UPDATE;
	n = min_t(u32, nr_states, ARRAY_SIZE(p.freq_khz));
	p.nr_states = n;
	for (u32 i = 0; i < n; i++) {
		p.freq_khz[i] = freq_khz[i];
		p.power_mw[i] = power_mw[i];
	}
	strscpy(p.device_name, dev_name ? dev_name : "none",
		sizeof(p.device_name));
	this_cpu_inc(ai_power_pcpu_stats.emit_em);
	ai_telemetry_emit_direct(AI_CAT_POWER, AI_EV_CPUFREQ,
				 AI_SEV_IMPORTANT, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_energy_model);

void ai_telemetry_thermal_trend(const char *zone, s32 temperature,
				s32 last_temperature)
{
	struct ai_power_thermal_payload p;

	if (!ai_power_thermal_sample_take())
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_POWER_THERMAL_TREND;
	p.temperature = temperature;
	p.last_temperature = last_temperature;
	p.trend = temperature - last_temperature;
	strscpy(p.zone_name, zone ? zone : "none", sizeof(p.zone_name));
	this_cpu_inc(ai_power_pcpu_stats.emit_thermal);
	ai_telemetry_emit_direct(AI_CAT_POWER, AI_EV_THERMAL, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_thermal_trend);

void ai_telemetry_qos_constraint(u8 qos_type, u8 action, s32 prev_value,
				 s32 curr_value)
{
	struct ai_power_qos_payload p;

	if (!ai_power_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_POWER_QOS_CONSTRAINT;
	p.qos_type = qos_type;
	p.action = action;
	p.prev_value = prev_value;
	p.curr_value = curr_value;
	this_cpu_inc(ai_power_pcpu_stats.emit_qos);
	ai_telemetry_emit_direct(AI_CAT_POWER, AI_EV_RUNTIME_PM,
				 AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_qos_constraint);

void ai_telemetry_wakelock_event(u8 action, u64 timeout_ns, const char *name,
				 size_t len)
{
	struct ai_power_wakelock_payload p;
	size_t n;

	if (!ai_power_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_POWER_WAKELOCK_EVENT;
	p.action = action;
	p.pid = task_pid_nr(current);
	p.timeout_ns = timeout_ns;
	n = min(len, sizeof(p.name) - 1);
	memcpy(p.name, name ? name : "", n);
	p.name[n] = '\0';
	this_cpu_inc(ai_power_pcpu_stats.emit_wakelock);
	ai_telemetry_emit_direct(AI_CAT_POWER, AI_EV_SUSPEND, AI_SEV_IMPORTANT,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_wakelock_event);

/* ==================================================================
 * power.freq / power.cstate / power.wakeup 立即生效参数
 *   freq   → aiguard 频率上限万分比（ai_cpufreq.c 访问器，每次频率计算
 *            真实钳制；无 cpufreq 虚拟化环境经请求/钳制计数观测）；
 *   cstate → PM QoS cpu_dma_latency 档位（value*100us 退出延迟上限，
 *            与 /dev/cpu_dma_latency 同源，0=移除请求）；
 *   wakeup → sched_wakeup tracepoint 唤醒事件采集门控（真实事件源 =
 *            进程唤醒，注册/摘除探针 + per-CPU 计数，真开关真效果）。
 * ================================================================== */

static DEFINE_MUTEX(ai_cstate_qos_lock);
static struct pm_qos_request ai_cstate_qos_req;
static bool ai_cstate_qos_active;

static int ai_power_cstate_apply(struct ai_control_param *p, s32 pid,
				 s64 value, s64 *eff)
{
	int lat_us = 0;

	if (value < 0 || value > 10)
		return AI_ERR_INVALID_ARG;

	lat_us = (int)value * 100;   /* 档位 → C-state 退出延迟上限（us） */
	mutex_lock(&ai_cstate_qos_lock);
	if (value == 0) {
		if (ai_cstate_qos_active) {
			cpu_latency_qos_remove_request(&ai_cstate_qos_req);
			ai_cstate_qos_active = false;
		}
	} else if (!ai_cstate_qos_active) {
			cpu_latency_qos_add_request(&ai_cstate_qos_req, lat_us);
		ai_cstate_qos_active = true;
	} else {
		cpu_latency_qos_update_request(&ai_cstate_qos_req, lat_us);
	}
	mutex_unlock(&ai_cstate_qos_lock);

	*eff = value;
	pr_info("AIKernel: power.cstate %lld -> PM QoS cpu_dma_latency %d us%s\n",
		value, value ? lat_us : 0, value ? "" : " (removed)");
	return AI_OK;
}

static bool ai_wakeup_capture = true;   /* 默认采集（保持现状） */
static bool ai_wakeup_probe_registered;
static DEFINE_MUTEX(ai_wakeup_lock);
static DEFINE_PER_CPU(u64, ai_wakeup_pcpu_events);

bool ai_power_wakeup_capture_is_enabled(void)
{
	return READ_ONCE(ai_wakeup_capture);
}
EXPORT_SYMBOL_GPL(ai_power_wakeup_capture_is_enabled);

void ai_power_wakeup_stats_read(bool *on, u64 *events)
{
	u64 sum = 0;
	int c;

	for_each_possible_cpu(c)
		sum += per_cpu(ai_wakeup_pcpu_events, c);
	if (on)
		*on = READ_ONCE(ai_wakeup_capture);
	if (events)
		*events = sum;
}
EXPORT_SYMBOL_GPL(ai_power_wakeup_stats_read);

#ifdef CONFIG_TRACEPOINTS
static void ai_wakeup_probe(void *data, struct task_struct *tsk)
{
	if (READ_ONCE(ai_wakeup_capture))
		this_cpu_inc(ai_wakeup_pcpu_events);
}

static int ai_power_wakeup_apply(struct ai_control_param *p, s32 pid,
				 s64 value, s64 *eff)
{
	int rc = 0;

	if (value != 0 && value != 1)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_wakeup_lock);
	if (value == 1) {
		WRITE_ONCE(ai_wakeup_capture, true);
		if (!ai_wakeup_probe_registered) {
			rc = tracepoint_probe_register(
				&__tracepoint_sched_wakeup,
				ai_wakeup_probe, NULL);
			if (!rc)
				ai_wakeup_probe_registered = true;
		}
	} else {
		WRITE_ONCE(ai_wakeup_capture, false);
		if (ai_wakeup_probe_registered) {
			tracepoint_probe_unregister(
				&__tracepoint_sched_wakeup,
				ai_wakeup_probe, NULL);
			ai_wakeup_probe_registered = false;
		}
	}
	mutex_unlock(&ai_wakeup_lock);
	if (rc)
		return AI_ERR_GENERIC;
	*eff = value;
	pr_info("AIKernel: power.wakeup %lld (sched_wakeup capture %s)\n",
		value, value ? "on" : "off");
	return AI_OK;
}
#endif /* CONFIG_TRACEPOINTS */

static int ai_power_freq_apply(struct ai_control_param *p, s32 pid,
			       s64 value, s64 *eff)
{
	if (value < 0 || value > 10000)
		return AI_ERR_INVALID_ARG;
	ai_aiguard_freq_max_pct_set((unsigned int)value);
	*eff = value;
	pr_info("AIKernel: power.freq %lld -> aiguard cap %lld/10000\n",
		value, value);
	return AI_OK;
}

static int __init ai_power_init(void)
{
	ai_control_register("power.freq", AI_POLICY_DOMAIN_POWER,
			    AI_CTRL_F_REAL, 0, 10000, 0, ai_power_freq_apply);
	ai_control_register("power.cstate", AI_POLICY_DOMAIN_POWER,
			    AI_CTRL_F_REAL, 0, 10, 0, ai_power_cstate_apply);
#ifdef CONFIG_TRACEPOINTS
	ai_control_register("power.wakeup", AI_POLICY_DOMAIN_POWER,
			    AI_CTRL_F_REAL, 0, 1, 1, ai_power_wakeup_apply);
#else
	ai_control_register("power.wakeup", AI_POLICY_DOMAIN_POWER, 0,
			    0, 1, 1, NULL);
#endif

	pr_info("AIKernel: power subsystem ready (AI hooks + telemetry)\n");
	return 0;
}
late_initcall(ai_power_init);
