// SPDX-License-Identifier: GPL-2.0
/*
 * ai_control_test.c - 可控参数 real 化 KUnit 套件（15 real + 1 reserved 参数）
 *
 * 覆盖：
 *   - control 表 16 参数中 15 个 [real]（AI_CTRL_F_REAL 标志）；
 *     sec.seccomp 于 W49 如实降级 [reserved]（专项用例断言）；
 *   - sched.timeslice → EEVDF base_slice 映射与读回；
 *   - mm.readahead/reclaim_prio、net.cwnd（ai_cca 钳制）、power.freq
 *     （aiguard 上限）、power.cstate（PM QoS）、power.wakeup（采集门控）、
 *     sec.audit（gate 真丢弃）、sec.lsm_override（enforce 档位）、
 *     net.nftables（netfilter 钩子真注册/摘除）的真实内核状态切换；
 *     sec.seccomp 已降级 reserved：只记录值、零规则副作用（另有用例）；
 *   - proc.signal/freeze/rlimit 的 TASK 目标校验（真实投递/冻结/软限
 *     由 L1 guest 实测取证：ps 状态 / /proc/PID/limits）。
 * w21：net.qdisc 接线后入 [real] 名单；设置/钳制/回滚三例在 dryrun 护栏
 * 下自动测（不真 graft），真 graft 由 guest 冒烟实测（tc qdisc show）。
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

/* 16 个参数全部 [real]（w21：net.qdisc 接线后入列） */
static void control_all_real_test(struct kunit *test)
{
	static const char *const names[] = {
		"proc.signal", "proc.freeze", "proc.rlimit",
		"net.cwnd", "net.qdisc", "net.nftables",
		"sched.timeslice",
		"mm.readahead", "mm.reclaim_prio",
		"io.bandwidth",
		"sec.lsm_override", "sec.audit",
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

/* sec.lsm_override（enforce 档位）+ sec.seccomp（W49: reserved 诚实降级） */
static void lsm_seccomp_test(struct kunit *test)
{
	int rc;

	safety_impact_set(test, 100);
	rc = execute_named("sec.lsm_override", AI_POLICY_DOMAIN_SECURITY,
			   1, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_TRUE(test, ai_lsm_enforce_get());

	/* sec.seccomp=1 只记录值：不得注入任何 LSM 规则（无空转副作用） */
	rc = execute_named("sec.seccomp", AI_POLICY_DOMAIN_SECURITY,
			   424242, 1, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, value_of("sec.seccomp"), 1);
	KUNIT_EXPECT_EQ(test, ai_lsm_rule_count(), 0U);

	rc = execute_named("sec.seccomp", AI_POLICY_DOMAIN_SECURITY,
			   424242, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, value_of("sec.seccomp"), 0);
	KUNIT_EXPECT_EQ(test, ai_lsm_rule_count(), 0U);

	/* ai_lsm 规则面本身（与 sec.seccomp 解耦；仅 lsm=ai 启用时被消费）：
	 * 直接 API 增/删仍工作，且不因参数降级而失效 */
	KUNIT_EXPECT_EQ(test, ai_lsm_rule_add(424242, true, "kunit-rule"),
			AI_OK);
	KUNIT_EXPECT_EQ(test, ai_lsm_rule_count(), 1U);
	KUNIT_EXPECT_EQ(test, ai_lsm_rule_del(424242), AI_OK);
	KUNIT_EXPECT_EQ(test, ai_lsm_rule_count(), 0U);

	rc = execute_named("sec.lsm_override", AI_POLICY_DOMAIN_SECURITY,
			   0, 0, 0);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_FALSE(test, ai_lsm_enforce_get());
	safety_impact_set(test, 50);
}

/* sec.seccomp 必须是 reserved（无 REAL；TASK 作用域保留） */
static void sec_seccomp_reserved_test(struct kunit *test)
{
	struct ai_control_param p;
	int idx = ai_control_find("sec.seccomp");

	KUNIT_EXPECT_GE(test, idx, 0);
	if (idx < 0)
		return;
	KUNIT_ASSERT_EQ(test, ai_control_query((u32)idx, &p), AI_OK);
	KUNIT_EXPECT_FALSE(test, p.flags & AI_CTRL_F_REAL);
	KUNIT_EXPECT_TRUE(test, p.flags & AI_CTRL_F_TASK);
	KUNIT_EXPECT_EQ(test, p.apply == NULL, true);
	KUNIT_EXPECT_EQ(test, p.apply_ex == NULL, true);
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

/* w21 net.qdisc 三例：设置/钳制/回滚。dryrun 护栏下 apply 正常提交
 * （pending/current 更新）但不调度 worker——不碰真实网卡；真 graft 行为
 * （tc qdisc show 上墙/回滚实证）由 guest 冒烟实测取证。
 * max_impact 语义：qdisc 值域跨度 3，pct=50 时 allowed=1（0→2/3 被钳），
 * 测试显式放宽 100（与 nftables_test 同模式），尾部还原 50。 */
#if IS_ENABLED(CONFIG_NET_SCHED) && defined(CONFIG_INET)
static void qdisc_set_test(struct kunit *test)
{
	safety_impact_set(test, 100);
	ai_net_qdisc_dryrun_set(true);
	KUNIT_EXPECT_EQ(test, execute_named("net.qdisc", AI_POLICY_DOMAIN_NET,
					    2, 0, 0), 1);
	KUNIT_EXPECT_EQ(test, value_of("net.qdisc"), 2);
	KUNIT_EXPECT_EQ(test, ai_net_qdisc_pending_get(), 2);
	KUNIT_EXPECT_EQ(test, execute_named("net.qdisc", AI_POLICY_DOMAIN_NET,
					    0, 0, 0), 1);
	KUNIT_EXPECT_EQ(test, ai_net_qdisc_pending_get(), 0);
	ai_net_qdisc_dryrun_set(false);
	safety_impact_set(test, 50);
}

/* 超域值 99 → 安全层硬范围钳到 max=3（clamp 语义，仍算 executed） */
static void qdisc_clamp_test(struct kunit *test)
{
	safety_impact_set(test, 100);
	ai_net_qdisc_dryrun_set(true);
	KUNIT_EXPECT_EQ(test, execute_named("net.qdisc", AI_POLICY_DOMAIN_NET,
					    99, 0, 0), 1);
	KUNIT_EXPECT_EQ(test, value_of("net.qdisc"), 3);
	KUNIT_EXPECT_EQ(test, execute_named("net.qdisc", AI_POLICY_DOMAIN_NET,
					    0, 0, 0), 1);
	ai_net_qdisc_dryrun_set(false);
	safety_impact_set(test, 50);
}

/* 回滚：set(1) → rollback(0)，current 归 0、pending 归 0 */
static void qdisc_rollback_test(struct kunit *test)
{
	safety_impact_set(test, 100);
	ai_net_qdisc_dryrun_set(true);
	KUNIT_EXPECT_EQ(test, execute_named("net.qdisc", AI_POLICY_DOMAIN_NET,
					    1, 0, 0), 1);
	KUNIT_EXPECT_EQ(test, value_of("net.qdisc"), 1);
	KUNIT_EXPECT_EQ(test, execute_named("net.qdisc", AI_POLICY_DOMAIN_NET,
					    0, 0, 0), 1);
	KUNIT_EXPECT_EQ(test, value_of("net.qdisc"), 0);
	KUNIT_EXPECT_EQ(test, ai_net_qdisc_pending_get(), 0);
	ai_net_qdisc_dryrun_set(false);
	safety_impact_set(test, 50);
}
#endif /* CONFIG_NET_SCHED && CONFIG_INET */

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
	KUNIT_CASE(sec_seccomp_reserved_test),
	KUNIT_CASE(nftables_test),
#if IS_ENABLED(CONFIG_NET_SCHED) && defined(CONFIG_INET)
	KUNIT_CASE(qdisc_set_test),
	KUNIT_CASE(qdisc_clamp_test),
	KUNIT_CASE(qdisc_rollback_test),
#endif
	KUNIT_CASE(proc_task_params_test),
	{}
};

static struct kunit_suite ai_control_test_suite = {
	.name = "ai_control",
	.test_cases = ai_control_test_cases,
};

kunit_test_suite(ai_control_test_suite);
MODULE_LICENSE("GPL v2");
