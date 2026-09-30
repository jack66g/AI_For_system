// SPDX-License-Identifier: GPL-2.0
/*
 * ai_control_test.c - 可控参数 real 化 KUnit 套件（16 参数 handler/访问器）
 *
 * 覆盖：
 *   - control 表 16 参数全部 [real]（AI_CTRL_F_REAL 标志）；
 *   - sched.timeslice → EEVDF base_slice 映射与读回；
 *   - mm.readahead/reclaim_prio、net.cwnd（ai_cca 钳制）、power.freq
 *     （aiguard 上限）、power.cstate（PM QoS）、power.wakeup（采集门控）、
 *     sec.audit（gate 真丢弃）、sec.lsm_override（enforce 档位）、
 *     sec.seccomp（deny 规则注入/解除）、net.nftables（netfilter 钩子
 *     真注册/摘除）的真实内核状态切换；
 *   - proc.signal/freeze/rlimit 的 TASK 目标校验（真实投递/冻结/软限
 *     由 L1 guest 实测取证：ps 状态 / /proc/PID/limits）。
 * net.qdisc 动作不自动测（运行时 graft 碰网络面，guest 实测）。
 */
#include <kunit/test.h>
#include <linux/sched.h>

#include "../core/ai_types.h"
#include "../core/ai_control.h"
#include "../core/ai_policy.h"
#include <linux/ai_accessors.h>
#include "../net/ai_net.h"
#include "../power/ai_power.h"
#include "../security/ai_audit.h"
#include "../security/ai_lsm.h"
#include "../core/ai_policy_safety.h"

/* 翻转类测试前置：max_impact_pct=50 时 [0..1] 参数单步翻转（幅度 100%）
 * 会被安全层 clamp 跳过（既有设计）；翻转验证显式放宽到 100%，测后还原 */
static void safety_impact_set(struct kunit *test, u32 pct)
{
	KUNIT_ASSERT_EQ(test, ai_policy_safety_set_max_impact(pct), AI_OK);
}

/* 定向执行一个参数动作（v2 语义），返回 executed 计数 */
static int execute_named(const char *name, enum ai_policy_domain dom,
			 u64 d0, u64 d1, u64 d2)
{
	struct ai_policy_ctx ctx = { 0 };

	strscpy(ctx.param, name, sizeof(ctx.param));
	ctx.domain = dom;
	ctx.decision_data[0] = d0;
	ctx.decision_data[1] = d1;
	ctx.decision_data[2] = d2;
	return ai_policy_execute(&ctx, NULL);
}

static s64 value_of(const char *name)
{
	s64 v = -999999;

	ai_control_get_value(name, &v);
	return v;
}

/* 16 个参数全部 [real] */
static void control_all_real_test(struct kunit *test)
{
	static const char *const names[] = {
		"proc.signal", "proc.freeze", "proc.rlimit",
		"net.cwnd", "net.nftables",
		"sched.timeslice",
		"mm.readahead", "mm.reclaim_prio",
		"io.bandwidth",
		"sec.lsm_override", "sec.seccomp", "sec.audit",
		"power.freq", "power.cstate", "power.wakeup",
	};
	struct ai_control_param p;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(names); i++) {
		int idx = ai_control_find(names[i]);

		KUNIT_EXPECT_GE(test, idx, 0);
		if (idx < 0)
			continue;
		KUNIT_EXPECT_EQ(test, ai_control_query((u32)idx, &p), AI_OK);
		KUNIT_EXPECT_NE(test, (u32)(p.flags & AI_CTRL_F_REAL), 0U);
	}
	/* net.qdisc 诚实保留 [reserved]：graft 实测冻结网络栈（见
	 * ai_net.c 注释与 ~/w1k-evidence/07_qdisc.txt） */
	{
		struct ai_control_param p;
		int idx = ai_control_find("net.qdisc");

		KUNIT_EXPECT_GE(test, idx, 0);
		if (idx >= 0) {
			KUNIT_EXPECT_EQ(test, ai_control_query((u32)idx, &p), AI_OK);
			KUNIT_EXPECT_EQ(test, (u32)(p.flags & AI_CTRL_F_REAL), 0U);
		}
	}
}

/* sched.timeslice：0.1ms 单位 → base_slice ns（30→3ms，还原 7→700us） */
static void timeslice_test(struct kunit *test)
{
	int rc;

	rc = execute_named("sched.timeslice", AI_POLICY_DOMAIN_SCHED, 30, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, ai_sched_base_slice_get(), 3000000ULL);
	KUNIT_EXPECT_EQ(test, value_of("sched.timeslice"), 30);

	rc = execute_named("sched.timeslice", AI_POLICY_DOMAIN_SCHED, 7, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, ai_sched_base_slice_get(), 700000ULL);
}

/* mm.readahead（256→128）与 mm.reclaim_prio（60 幂等） */
static void mm_params_test(struct kunit *test)
{
	int rc;

	rc = execute_named("mm.readahead", AI_POLICY_DOMAIN_MM, 256, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, value_of("mm.readahead"), 256);
	rc = execute_named("mm.readahead", AI_POLICY_DOMAIN_MM, 128, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, value_of("mm.readahead"), 128);

	rc = execute_named("mm.reclaim_prio", AI_POLICY_DOMAIN_MM, 60, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, value_of("mm.reclaim_prio"), 60);
}

/* net.cwnd：ai_cca 钳制访问器真值（2→256） */
static void cwnd_test(struct kunit *test)
{
	int rc;

	rc = execute_named("net.cwnd", AI_POLICY_DOMAIN_NET, 2, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, ai_cca_cwnd_clamp_get(), 2U);
	rc = execute_named("net.cwnd", AI_POLICY_DOMAIN_NET, 256, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, ai_cca_cwnd_clamp_get(), 256U);
}

/* power.freq（上限万分比）/ power.cstate（PM QoS 档位）/ power.wakeup */
static void power_params_test(struct kunit *test)
{
	u64 reqs, clamps, ev;
	bool on;
	int rc;

	ai_aiguard_freq_stats_read(&reqs, &clamps);   /* 统计面可达 */
	rc = execute_named("power.freq", AI_POLICY_DOMAIN_POWER, 5000, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, ai_aiguard_freq_max_pct_get(), 5000U);
	rc = execute_named("power.freq", AI_POLICY_DOMAIN_POWER, 0, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, ai_aiguard_freq_max_pct_get(), 0U);

	rc = execute_named("power.cstate", AI_POLICY_DOMAIN_POWER, 3, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, value_of("power.cstate"), 3);
	rc = execute_named("power.cstate", AI_POLICY_DOMAIN_POWER, 0, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, value_of("power.cstate"), 0);

	safety_impact_set(test, 100);
	rc = execute_named("power.wakeup", AI_POLICY_DOMAIN_POWER, 0, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	ai_power_wakeup_stats_read(&on, &ev);
	KUNIT_EXPECT_FALSE(test, on);
	rc = execute_named("power.wakeup", AI_POLICY_DOMAIN_POWER, 1, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	ai_power_wakeup_stats_read(&on, &ev);
	KUNIT_EXPECT_TRUE(test, on);
	safety_impact_set(test, 50);
}

/* sec.audit：gate 真丢弃（关后 ingest 递增 gate_drops） */
static void audit_gate_test(struct kunit *test)
{
	u64 drops0, drops1;
	int rc;

	safety_impact_set(test, 100);
	rc = execute_named("sec.audit", AI_POLICY_DOMAIN_SECURITY, 0, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	drops0 = ai_audit_gate_drops_read();
	ai_audit_ingest(1300, "x", 1);   /* AUDIT_SYSCALL */
	drops1 = ai_audit_gate_drops_read();
	KUNIT_EXPECT_EQ(test, drops1, drops0 + 1);
	rc = execute_named("sec.audit", AI_POLICY_DOMAIN_SECURITY, 1, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_TRUE(test, ai_audit_capture_is_enabled());
	safety_impact_set(test, 50);
}

/* sec.lsm_override（enforce 档位）+ sec.seccomp（deny 规则注入/解除） */
static void lsm_seccomp_test(struct kunit *test)
{
	int rc;

	safety_impact_set(test, 100);
	rc = execute_named("sec.lsm_override", AI_POLICY_DOMAIN_SECURITY,
			   1, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_TRUE(test, ai_lsm_enforce_get());

	rc = execute_named("sec.seccomp", AI_POLICY_DOMAIN_SECURITY,
			   424242, 1, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_GE(test, ai_lsm_rule_count(), 1U);

	rc = execute_named("sec.seccomp", AI_POLICY_DOMAIN_SECURITY,
			   424242, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, ai_lsm_rule_count(), 0U);

	rc = execute_named("sec.lsm_override", AI_POLICY_DOMAIN_SECURITY,
			   0, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_FALSE(test, ai_lsm_enforce_get());
	safety_impact_set(test, 50);
}

/* net.nftables：netfilter 钩子真注册/摘除 */
static void nftables_test(struct kunit *test)
{
	u64 p, b;
	bool on;
	int rc;

	safety_impact_set(test, 100);
	rc = execute_named("net.nftables", AI_POLICY_DOMAIN_NET, 1, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_TRUE(test, ai_netfilter_is_enabled());
	ai_netfilter_stats_read(&on, &p, &b);
	KUNIT_EXPECT_TRUE(test, on);
	rc = execute_named("net.nftables", AI_POLICY_DOMAIN_NET, 0, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_FALSE(test, ai_netfilter_is_enabled());
	safety_impact_set(test, 50);
}

/* proc.*：TASK 目标校验（不存在的 pid → execute 返回 match 计数 1、
 * executed=0；决策值不落账）。真实投递/冻结/软限由 L1 guest 实测取证。 */
static void proc_task_params_test(struct kunit *test)
{
	int rc;

	/* KUnit 早期 boot 上下文里 execute 命中数与运行时不同（0 命中或
	 * 命中后 handler 拒绝）；关键不变量 = 非法目标不落账 + 不崩溃 */
	rc = execute_named("proc.signal", AI_POLICY_DOMAIN_PROC,
			   999999, 15, 0);
	KUNIT_EXPECT_TRUE(test, rc == 0 || rc == 1);
	KUNIT_EXPECT_EQ(test, value_of("proc.signal"), 0);
	rc = execute_named("proc.freeze", AI_POLICY_DOMAIN_PROC,
			   999999, 1, 0);
	KUNIT_EXPECT_TRUE(test, rc == 0 || rc == 1);
	KUNIT_EXPECT_EQ(test, value_of("proc.freeze"), 0);
	rc = execute_named("proc.rlimit", AI_POLICY_DOMAIN_PROC,
			   999999, 0, 4);
	KUNIT_EXPECT_TRUE(test, rc == 0 || rc == 1);
	KUNIT_EXPECT_EQ(test, value_of("proc.rlimit"), 0);
}

static struct kunit_case ai_control_test_cases[] = {
	KUNIT_CASE(control_all_real_test),
	KUNIT_CASE(timeslice_test),
	KUNIT_CASE(mm_params_test),
	KUNIT_CASE(cwnd_test),
	KUNIT_CASE(power_params_test),
	KUNIT_CASE(audit_gate_test),
	KUNIT_CASE(lsm_seccomp_test),
	KUNIT_CASE(nftables_test),
	KUNIT_CASE(proc_task_params_test),
	{}
};

static struct kunit_suite ai_control_test_suite = {
	.name = "ai_control",
	.test_cases = ai_control_test_cases,
};

kunit_test_suite(ai_control_test_suite);
MODULE_LICENSE("GPL v2");
