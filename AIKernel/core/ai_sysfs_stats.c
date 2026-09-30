// SPDX-License-Identifier: GPL-2.0
/*
 * ai_sysfs_stats.c - AIKernel /sys/kernel/ai/stats/ 只读统计视图（自 ai_sysfs.c 拆分）
 *
 * 职责一句话：telemetry emitted/dropped/sampled_skip（全 CPU 合计）、
 * decisions total/hit/hitrate、runtime state 七个只读属性的 attribute_group。
 *
 * 拆分说明：函数体自原 ai_sysfs.c（670 行）逐字搬移；ai_stats_group 原
 * static 提升为非 static（声明见 ai_sysfs_internal.h），由 ai_sysfs.c 的
 * ai_sysfs_init() 装配。门控：随 ai_sysfs.o 在 CONFIG_AIKERNEL_USRIFACE 下
 * 构建（与拆分前一致）。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/string.h>
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include "ai_types.h"
#include "ai_startup.h"
#include "ai_runtime.h"
#include "ai_model.h"
#include "ai_telemetry.h"
#include "ai_policy.h"
#include "ai_policy_safety.h"
#include "ai_causal.h"
#include "ai_sysfs_internal.h"

/* ---- stats/ 目录 ---- */

static void ai_sysfs_telemetry_totals(u64 *emitted, u64 *dropped, u64 *skipped)
{
	int cpu;
	u64 e = 0, d = 0, s = 0;

	for_each_possible_cpu(cpu) {
		struct ai_telemetry_cpu_stats st;

		if (ai_telemetry_stats(cpu, &st) == AI_OK) {
			e += st.emitted;
			d += st.dropped;
			s += st.sampled_skip;
		}
	}
	*emitted = e;
	*dropped = d;
	*skipped = s;
}

#define AI_STATS_RO(name, fn) \
static ssize_t name##_show(struct kobject *kobj, \
			   struct kobj_attribute *attr, char *buf) \
{ return fn(buf); } \
static struct kobj_attribute name##_attr = __ATTR_RO(name)

static ssize_t ai_stats_telemetry_emitted_show_fn(char *buf)
{
	u64 e, d, s;

	ai_sysfs_telemetry_totals(&e, &d, &s);
	return sysfs_emit(buf, "%llu\n", e);
}
AI_STATS_RO(telemetry_emitted, ai_stats_telemetry_emitted_show_fn);

static ssize_t ai_stats_telemetry_dropped_show_fn(char *buf)
{
	u64 e, d, s;

	ai_sysfs_telemetry_totals(&e, &d, &s);
	return sysfs_emit(buf, "%llu\n", d);
}
AI_STATS_RO(telemetry_dropped, ai_stats_telemetry_dropped_show_fn);

static ssize_t ai_stats_telemetry_sampled_skip_show_fn(char *buf)
{
	u64 e, d, s;

	ai_sysfs_telemetry_totals(&e, &d, &s);
	return sysfs_emit(buf, "%llu\n", s);
}
AI_STATS_RO(telemetry_sampled_skip, ai_stats_telemetry_sampled_skip_show_fn);

static ssize_t ai_stats_decisions_total_show_fn(char *buf)
{
	struct ai_policy_stats st;

	ai_policy_stats_get(&st);
	return sysfs_emit(buf, "%llu\n", st.decisions_total);
}
AI_STATS_RO(decisions_total, ai_stats_decisions_total_show_fn);

static ssize_t ai_stats_decisions_hit_show_fn(char *buf)
{
	struct ai_policy_stats st;

	ai_policy_stats_get(&st);
	return sysfs_emit(buf, "%llu\n", st.hits);
}
AI_STATS_RO(decisions_hit, ai_stats_decisions_hit_show_fn);

static ssize_t ai_stats_decisions_hitrate_show_fn(char *buf)
{
	struct ai_policy_stats st;
	u64 permille = 0;

	ai_policy_stats_get(&st);
	if (st.attempts)
		permille = st.hits * 1000 / st.attempts;
	return sysfs_emit(buf, "%llu\n", permille);
}
AI_STATS_RO(decisions_hitrate_permille, ai_stats_decisions_hitrate_show_fn);

static ssize_t ai_stats_runtime_state_show_fn(char *buf)
{
	return sysfs_emit(buf, "%d\n", ai_runtime_get_state());
}
AI_STATS_RO(runtime_state, ai_stats_runtime_state_show_fn);

/* ---- ai_actions：16 个可控参数真实效果聚合观测面 ----
 * （钳制命中/采集计数/开关状态/访问器读回——与 /proc/ai/control 的
 *   current 值互为双证据） */
#include <linux/ai_accessors.h>
#include "../net/ai_net.h"
#include "../power/ai_power.h"
#include "../security/ai_audit.h"
#include "../security/ai_lsm.h"

static ssize_t ai_stats_ai_actions_show_fn(char *buf)
{
	u64 reqs = 0, clamps = 0, wk_ev = 0, nf_p = 0, nf_b = 0;
	bool wk_on = false, nf_on = false;

	ai_aiguard_freq_stats_read(&reqs, &clamps);
	ai_power_wakeup_stats_read(&wk_on, &wk_ev);
	ai_netfilter_stats_read(&nf_on, &nf_p, &nf_b);
	return sysfs_emit(buf,
			  "cwnd_clamp_hits: %llu\n"
			  "aiguard_freq_requests: %llu\n"
			  "aiguard_freq_clamped: %llu\n"
			  "aiguard_freq_cap_pct: %u\n"
			  "wakeup_capture: %d\n"
			  "wakeup_events: %llu\n"
			  "netfilter_hook: %d\n"
			  "netfilter_pkts: %llu\n"
			  "netfilter_bytes: %llu\n"
			  "audit_capture: %d\n"
			  "audit_gate_drops: %llu\n"
			  "lsm_enforce: %d\n"
			  "lsm_rules: %u\n"
			  "sched_base_slice_ns: %llu\n"
			  "vfs_cache_pressure: %d\n",
			  ai_cca_clamp_hits_read(), reqs, clamps,
			  ai_aiguard_freq_max_pct_get(), (int)wk_on, wk_ev,
			  (int)nf_on, nf_p, nf_b,
			  (int)ai_audit_capture_is_enabled(),
			  ai_audit_gate_drops_read(),
			  (int)ai_lsm_enforce_get(), ai_lsm_rule_count(),
			  ai_sched_base_slice_get(),
			  ai_vfs_cache_pressure_get());
}
AI_STATS_RO(ai_actions, ai_stats_ai_actions_show_fn);

static struct attribute *ai_stats_attrs[] = {
	&telemetry_emitted_attr.attr,
	&telemetry_dropped_attr.attr,
	&telemetry_sampled_skip_attr.attr,
	&decisions_total_attr.attr,
	&decisions_hit_attr.attr,
	&decisions_hitrate_permille_attr.attr,
	&runtime_state_attr.attr,
	&ai_actions_attr.attr,
	NULL,
};

const struct attribute_group ai_stats_group = {
	.attrs = ai_stats_attrs,
};
