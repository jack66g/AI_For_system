// SPDX-License-Identifier: GPL-2.0
/*
 * ai_policy_test.c - AI 策略引擎 KUnit 测试（A 轨 模块15.6）
 *
 * 覆盖：域+动作注册、execute 命中/未命中、安全边界 clamp、outcome 回写、
 * rollback 回滚、决策记录 ring、性能实测。
 *
 * 测试鲁棒性设计：系统已有各子域注册的真实动作（mm.swappiness 等），
 * 因此测试动作注册在 GENERAL 域（无系统动作），精确断言命中数。
 *
 * CONFIG_AIKERNEL=n 时不参与编译（Makefile 门控）→ 无操作；
 * CONFIG_AIKERNEL_RUNTIME=n 时编译为空套件。
 */

#include <kunit/test.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include "../core/ai_types.h"
#include "../core/ai_policy.h"
#include "../core/ai_policy_safety.h"
#include "../core/ai_control.h"
#include "../core/ai_runtime.h"
#include "../core/ai_telemetry.h"

#ifdef CONFIG_AIKERNEL_RUNTIME

/* 测试动作状态 */
static long test_param;          /* 示例参数 */
static long test_saved;          /* 快照 */
static int  test_applied;

/* 回调：记录参数（模拟 mm.swappiness 风格全局参数；>100 拒绝→回滚路径） */
static int test_action_cb(const struct ai_policy_ctx *ctx, void *arg)
{
	long v = (long)ctx->decision_data[0];

	if (v < 0 || v > 100)
		return AI_ERR_INVALID_ARG;   /* 触发内核自动回滚 */
	test_saved = test_param;
	test_param = v;
	test_applied = 1;
	return AI_OK;
}

/* 回滚：恢复快照 */
static int test_action_rb(const struct ai_policy_ctx *ctx, void *arg)
{
	test_param = test_saved;
	test_applied = 0;
	return AI_OK;
}

/* 失败回调：返回错误触发回滚路径 */
static int test_fail_cb(const struct ai_policy_ctx *ctx, void *arg)
{
	return AI_ERR_GENERIC;
}

/* 读出最新决策记录（ring 最旧在前，末条 = 最近） */
static u64 policy_last_decision_id(struct kunit *test)
{
	struct ai_decision_record *buf;
	u32 count = 0;
	int rc;

	buf = kunit_kzalloc(test, AI_POLICY_DECISION_RING_SIZE * sizeof(*buf),
			    GFP_KERNEL);
	if (!buf)
		return 0;
	rc = ai_policy_decision_read(buf,
				     AI_POLICY_DECISION_RING_SIZE *
				     sizeof(*buf),
				     &count, NULL);
	if (rc != AI_OK || count == 0)
		return 0;
	return buf[count - 1].decision_id;
}

static void policy_register_execute_test(struct kunit *test)
{
	struct ai_policy_ctx ctx = { 0 };
	int rc;

	/* 清理残留（多次运行幂等） */
	ai_policy_unregister("kunit.test.param");

	rc = ai_policy_register(AI_POLICY_DOMAIN_GENERAL, "kunit.test.param",
				test_action_cb, test_action_rb, NULL);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	/* GENERAL 域无系统动作：命中精确 = 1（本测试动作） */
	test_param = 60;
	memset(&ctx, 0, sizeof(ctx));
	ctx.domain = AI_POLICY_DOMAIN_GENERAL;
	ctx.decision_type = 1;
	ctx.decision_data[0] = 30;
	ctx.confidence = 100;
	ctx.model_version = 1;
	ctx.trigger_ts = ktime_get_ns();

	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 1);          /* 1 个动作执行成功 */
	KUNIT_EXPECT_EQ(test, test_param, 30L); /* 参数已生效 */
	KUNIT_EXPECT_GE(test, policy_last_decision_id(test), 1ULL);

	/* 域不匹配（VIRT 域无动作）→ 无命中 */
	memset(&ctx, 0, sizeof(ctx));
	ctx.domain = AI_POLICY_DOMAIN_VIRT;
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 0);          /* 0 命中 */
}

static void policy_param_target_test(struct kunit *test)
{
	struct ai_policy_ctx ctx = { 0 };
	int rc;

	/* 依赖 policy_register_execute_test 已注册 kunit.test.param */

	/* 定向（v2）：param=动作全名 → 精确执行该条（GENERAL 域仅此动作） */
	memset(&ctx, 0, sizeof(ctx));
	ctx.domain = AI_POLICY_DOMAIN_GENERAL;
	ctx.decision_type = 1;
	ctx.decision_data[0] = 35;
	strscpy(ctx.param, "kunit.test.param", sizeof(ctx.param));
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, test_param, 35L);

	/* 定向短名：末段匹配（"param" 命中 "kunit.test.param"） */
	memset(&ctx, 0, sizeof(ctx));
	ctx.domain = AI_POLICY_DOMAIN_GENERAL;
	ctx.decision_data[0] = 40;
	strscpy(ctx.param, "param", sizeof(ctx.param));
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, test_param, 40L);

	/* 定向未命中：param 无匹配动作 → 0 命中，且不污染其它参数 */
	memset(&ctx, 0, sizeof(ctx));
	ctx.domain = AI_POLICY_DOMAIN_GENERAL;
	ctx.decision_data[0] = 45;
	strscpy(ctx.param, "no.such.param", sizeof(ctx.param));
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, test_param, 40L);
}

static void policy_outcome_test(struct kunit *test)
{
	struct ai_policy_ctx ctx = { 0 };
	u64 id;
	int rc;

	ctx.domain = AI_POLICY_DOMAIN_GENERAL;
	ctx.decision_type = 1;
	ctx.decision_data[0] = 40;
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 1);

	id = policy_last_decision_id(test);
	KUNIT_EXPECT_GE(test, id, 1ULL);

	/* outcome 回写（闭环第 4 步） */
	rc = ai_policy_outcome_update(id, AI_OUTCOME_SUCCESS,
				      5 /* metric_delta */);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	/* 不存在的 decision_id → 找不到 */
	rc = ai_policy_outcome_update(0xDEAD, AI_OUTCOME_SUCCESS, 0);
	KUNIT_EXPECT_EQ(test, rc, AI_ERR_NOT_FOUND);
}

static void policy_rollback_test(struct kunit *test)
{
	long before = test_param;

	/* rollback 恢复决策前值 */
	{
		int rc = ai_policy_rollback_all();

		KUNIT_EXPECT_EQ(test, rc, AI_OK);
	}
	KUNIT_EXPECT_EQ(test, test_param, before);
}

static void policy_safety_clamp_test(struct kunit *test)
{
	struct ai_policy_ctx ctx = { 0 };
	u32 saved_max;
	int rc;

	/* 记录并关闭 global_enable → execute 应拒绝 */
	saved_max = ai_policy_safety_get_max_impact();
	ai_policy_safety_set_enabled(0);

	memset(&ctx, 0, sizeof(ctx));
	ctx.domain = AI_POLICY_DOMAIN_GENERAL;
	ctx.decision_data[0] = 55;
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, AI_ERR_DISABLED);

	/* 还原 global_enable + max_impact */
	ai_policy_safety_set_enabled(1);
	ai_policy_safety_set_max_impact(saved_max);

	/* 超界参数（>100）→ 回调拒绝 → 内核自动调 rollback：
	 * 先成功执行 70（快照 55），再执行 999（拒绝）→ 恢复 55 */
	test_param = 55;
	memset(&ctx, 0, sizeof(ctx));
	ctx.domain = AI_POLICY_DOMAIN_GENERAL;
	ctx.decision_data[0] = 70;
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, test_param, 70L);

	memset(&ctx, 0, sizeof(ctx));
	ctx.domain = AI_POLICY_DOMAIN_GENERAL;
	ctx.decision_data[0] = 999;
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 0);          /* 执行失败（0 成功） */
	KUNIT_EXPECT_EQ(test, test_param, 55L); /* 已回滚到决策前值 */
}

/* K65（I8-DATA-REPORT §3.3）：小 span 幅度限幅整数截断回归测试。
 * 修复前 allowed=(max-min)*pct/100 在 span=1、pct=50 时 =0，任意请求被
 * 钳回当前值（sched.affinity 2 CPU 台架读回 0/18=0%）；修复后保底 1。 */
static void policy_safety_span1_test(struct kunit *test)
{
	u32 saved = ai_policy_safety_get_max_impact();
	s64 v;
	u8 clamped;

	KUNIT_ASSERT_EQ(test, ai_policy_safety_set_max_impact(50), AI_OK);

	/* span=1（0..1，2 CPU sched.affinity 同构）：单步翻转须放行 */
	v = 1; clamped = 0;
	KUNIT_EXPECT_EQ(test,
		ai_policy_safety_limit_value(0, 1, 0, &v, &clamped), AI_OK);
	KUNIT_EXPECT_EQ(test, v, 1);
	KUNIT_EXPECT_EQ(test, clamped, 0);

	/* span=1 反向：1→0 同样单步可动 */
	v = 0; clamped = 0;
	KUNIT_EXPECT_EQ(test,
		ai_policy_safety_limit_value(0, 1, 1, &v, &clamped), AI_OK);
	KUNIT_EXPECT_EQ(test, v, 0);
	KUNIT_EXPECT_EQ(test, clamped, 0);

	/* span=39（nice -20..19）pct=50 → allowed=19：大步仍钳（限幅语义保持，
	 * I-8 台架 10→-15 被钳 -9 同款） */
	v = -20; clamped = 0;
	KUNIT_EXPECT_EQ(test,
		ai_policy_safety_limit_value(-20, 19, 0, &v, &clamped), AI_OK);
	KUNIT_EXPECT_EQ(test, v, -19);
	KUNIT_EXPECT_EQ(test, clamped, 1);

	/* pct=100 门不变：全幅直达（不进幅度分支） */
	KUNIT_ASSERT_EQ(test, ai_policy_safety_set_max_impact(100), AI_OK);
	v = -20; clamped = 0;
	KUNIT_EXPECT_EQ(test,
		ai_policy_safety_limit_value(-20, 19, 0, &v, &clamped), AI_OK);
	KUNIT_EXPECT_EQ(test, v, -20);
	KUNIT_EXPECT_EQ(test, clamped, 0);

	/* 还原全局幅度 */
	KUNIT_EXPECT_EQ(test, ai_policy_safety_set_max_impact(saved), AI_OK);
}

static void policy_fail_rollback_test(struct kunit *test)
{
	long before;
	int rc;

	/* 注册一个必然失败的动作：失败 → 内核调 rollback（GENERAL 域）。
	 * 先注销 kunit.test.param，保证 GENERAL 域只有失败动作（命中=0） */
	ai_policy_unregister("kunit.test.param");
	ai_policy_unregister("kunit.test.fail");
	rc = ai_policy_register(AI_POLICY_DOMAIN_GENERAL, "kunit.test.fail",
				test_fail_cb, test_action_rb, NULL);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	before = test_param;
	{
		struct ai_policy_ctx ctx = { 0 };

		ctx.domain = AI_POLICY_DOMAIN_GENERAL;
		rc = ai_policy_execute(&ctx, NULL);
		KUNIT_EXPECT_EQ(test, rc, 0);   /* 0 成功（全败） */
	}
	KUNIT_EXPECT_EQ(test, test_param, before);

	ai_policy_unregister("kunit.test.fail");

	/* 恢复：重新注册 kunit.test.param（后续用例依赖） */
	ai_policy_register(AI_POLICY_DOMAIN_GENERAL, "kunit.test.param",
			   test_action_cb, test_action_rb, NULL);
}

static void policy_stats_test(struct kunit *test)
{
	struct ai_policy_stats st = { 0 };

	ai_policy_stats_get(&st);
	KUNIT_EXPECT_GE(test, st.attempts, 1ULL);
	KUNIT_EXPECT_GE(test, st.decisions_total, 1ULL);
}

static void policy_execute_latency_test(struct kunit *test)
{
	/*
	 * 性能实测（Prompt 15 验证标准：决策执行 < 200ns 目标、AI hook
	 * < 5µs 目标；TCG 下记录实测）：循环执行 ai_policy_execute() 与
	 * ai_runtime_think_execute()（AI hook 路径 = 感知→推理→决策→执行）。
	 */
	struct ai_policy_ctx ctx = { 0 };
	struct ai_sense_input sense = { 0 };
	struct ai_think_result res = { 0 };
	u64 t0, t1, avg;
	unsigned int i;
	int rc;

	/* 决策执行（GENERAL 域，kunit.test.param 已注册） */
	memset(&ctx, 0, sizeof(ctx));
	ctx.domain = AI_POLICY_DOMAIN_GENERAL;
	ctx.decision_type = 1;
	ctx.decision_data[0] = 60;
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 1);

	t0 = ktime_get_raw_ns();
	for (i = 0; i < 256; i++) {
		memset(&ctx, 0, sizeof(ctx));
		ctx.domain = AI_POLICY_DOMAIN_GENERAL;
		ctx.decision_type = 1;
		ctx.decision_data[0] = 60;   /* 恒等决策快路径 */
		ai_policy_execute(&ctx, NULL);
	}
	t1 = ktime_get_raw_ns();
	avg = (t1 - t0) / 256;
	pr_info("AIKernel KUnit: policy_execute latency avg=%llu ns (%u calls)\n",
		avg, 256);
	KUNIT_EXPECT_LT(test, avg, 1000000ULL);

	/* AI hook（think_execute：感知→推理→决策→执行全链） */
	memset(&sense, 0, sizeof(sense));
	sense.ts = ktime_get_ns();
	sense.event_id = AI_EVENT_ID(AI_CAT_MM, AI_EV_RECLAIM);
	{
		struct ai_sense_decision d = { 0 };

		d.domain = AI_POLICY_DOMAIN_GENERAL;
		d.decision_type = 1;
		d.confidence = 100;
		d.value = 60;
		memcpy(sense.data, &d, sizeof(d));
		sense.data_len = sizeof(d);
	}
	t0 = ktime_get_raw_ns();
	for (i = 0; i < 128; i++) {
		memset(&sense, 0, sizeof(sense));
		sense.ts = ktime_get_ns();
		sense.event_id = AI_EVENT_ID(AI_CAT_MM, AI_EV_RECLAIM);
		{
			struct ai_sense_decision d = { 0 };

			d.domain = AI_POLICY_DOMAIN_GENERAL;
			d.decision_type = 1;
			d.confidence = 100;
			d.value = 60;
			memcpy(sense.data, &d, sizeof(d));
			sense.data_len = sizeof(d);
		}
		ai_runtime_think_execute(&sense, &res);
	}
	t1 = ktime_get_raw_ns();
	avg = (t1 - t0) / 128;
	pr_info("AIKernel KUnit: think_execute (AI hook) latency avg=%llu ns "
		"(%u calls)\n", avg, 128);
	KUNIT_EXPECT_LT(test, avg, 10000000ULL);
}

/* K66 T1（A2/F16-PROGRESS §2-2）恒等快路径回归：
 * ① per-task 读 NOT_FOUND（多 CPU 掩码，sched.affinity 真值无法单值
 *    忠实表出）时，请求值==全局 cur 必须真应用——修复前同值快路径
 *    静默 no-op（executed=1 实未迁移）；
 * ② per-task 真值==请求值时，同值快路径合法（免快照免应用）。
 * 同时覆盖 K66 T3 快照查询：真应用决策 pre 可查、快路径决策无快照。 */
static void policy_affinity_idem_fastpath_test(struct kunit *test)
{
	struct ai_policy_ctx ctx = { 0 };
	s64 pre_vals[AI_SAFETY_SNAPSHOT_PARAMS];
	s64 gcur = -1;
	u8 n = AI_SAFETY_SNAPSHOT_PARAMS;
	int rc;

	if (num_online_cpus() < 2) {
		kunit_mark_skipped(test, "needs SMP, online=%u",
				   num_online_cpus());
		return;
	}

	/* 步骤 1：真实应用 pin 本线程到 CPU1 → 全局 cur=1 */
	memset(&ctx, 0, sizeof(ctx));
	strscpy(ctx.param, "sched.affinity", sizeof(ctx.param));
	ctx.domain = AI_POLICY_DOMAIN_SCHED;
	ctx.decision_type = 90;
	ctx.decision_id = 0x66000001ULL;
	ctx.decision_data[0] = (u64)current->pid;
	ctx.decision_data[1] = 1;
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, cpumask_weight(current->cpus_ptr), 1);
	KUNIT_EXPECT_EQ(test, cpumask_first(current->cpus_ptr), 1);
	KUNIT_EXPECT_EQ(test, ai_control_get_value("sched.affinity", &gcur),
			AI_OK);
	KUNIT_EXPECT_EQ(test, gcur, 1);

	/* 步骤 2：人工恢复全 CPU 掩码（真值≠全局 cur 的多掩码态），
	 * 再注入与全局 cur 相同的值 1——修复前此处被同值快路径静默
	 * no-op（I-10 会话 7 连 miss 形态）；修复后必须真迁移。 */
	rc = set_cpus_allowed_ptr(current, cpu_online_mask);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, cpumask_weight(current->cpus_ptr),
			num_online_cpus());

	memset(&ctx, 0, sizeof(ctx));
	strscpy(ctx.param, "sched.affinity", sizeof(ctx.param));
	ctx.domain = AI_POLICY_DOMAIN_SCHED;
	ctx.decision_type = 90;
	ctx.decision_id = 0x66000002ULL;
	ctx.decision_data[0] = (u64)current->pid;
	ctx.decision_data[1] = 1;   /* == 全局 cur，真值是全 CPU 掩码 */
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, cpumask_weight(current->cpus_ptr), 1);
	KUNIT_EXPECT_EQ(test, cpumask_first(current->cpus_ptr), 1);

	/* T3：真应用决策有 pre 快照（读失败分支 pre=全局表值 1） */
	n = AI_SAFETY_SNAPSHOT_PARAMS;
	KUNIT_EXPECT_EQ(test,
			ai_policy_safety_snapshot_lookup(0x66000002ULL,
							 pre_vals, &n),
			AI_OK);
	KUNIT_EXPECT_EQ(test, n, 1);
	KUNIT_EXPECT_EQ(test, pre_vals[0], 1);

	/* 步骤 3：真值==请求值 → 同值快路径合法（无快照、不应用） */
	memset(&ctx, 0, sizeof(ctx));
	strscpy(ctx.param, "sched.affinity", sizeof(ctx.param));
	ctx.domain = AI_POLICY_DOMAIN_SCHED;
	ctx.decision_type = 90;
	ctx.decision_id = 0x66000003ULL;
	ctx.decision_data[0] = (u64)current->pid;
	ctx.decision_data[1] = 1;
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 1);
	KUNIT_EXPECT_EQ(test, cpumask_first(current->cpus_ptr), 1);
	n = AI_SAFETY_SNAPSHOT_PARAMS;
	KUNIT_EXPECT_EQ(test,
			ai_policy_safety_snapshot_lookup(0x66000003ULL,
							 pre_vals, &n),
			AI_ERR_NOT_FOUND);

	/* 还原 KUnit 线程亲和，避免影响后续套件 */
	set_cpus_allowed_ptr(current, cpu_online_mask);
}

/* K66 T3：决策前值快照查询 API（/proc/ai/decisions pre= 的取数入口） */
static void policy_snapshot_pre_lookup_test(struct kunit *test)
{
	s64 pre_vals[AI_SAFETY_SNAPSHOT_PARAMS];
	u8 n = AI_SAFETY_SNAPSHOT_PARAMS;
	int rc;

	/* 保存（负值覆盖 sched.nice 域）→ 查询回读 */
	KUNIT_EXPECT_EQ(test,
			ai_policy_safety_snapshot_save(0x66000011ULL, 0, 1,
						       -5), AI_OK);
	n = AI_SAFETY_SNAPSHOT_PARAMS;
	rc = ai_policy_safety_snapshot_lookup(0x66000011ULL, pre_vals, &n);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, n, 1);
	KUNIT_EXPECT_EQ(test, pre_vals[0], -5);

	/* 同决策同参数覆盖 → 新值 */
	KUNIT_EXPECT_EQ(test,
			ai_policy_safety_snapshot_save(0x66000011ULL, 0, 1,
						       -7), AI_OK);
	n = AI_SAFETY_SNAPSHOT_PARAMS;
	KUNIT_EXPECT_EQ(test,
			ai_policy_safety_snapshot_lookup(0x66000011ULL,
							 pre_vals, &n),
			AI_OK);
	KUNIT_EXPECT_EQ(test, n, 1);
	KUNIT_EXPECT_EQ(test, pre_vals[0], -7);

	/* 同决策第二参数 → 保存序两条 */
	KUNIT_EXPECT_EQ(test,
			ai_policy_safety_snapshot_save(0x66000011ULL, 3, 2,
						       42), AI_OK);
	n = AI_SAFETY_SNAPSHOT_PARAMS;
	KUNIT_EXPECT_EQ(test,
			ai_policy_safety_snapshot_lookup(0x66000011ULL,
							 pre_vals, &n),
			AI_OK);
	KUNIT_EXPECT_EQ(test, n, 2);
	KUNIT_EXPECT_EQ(test, pre_vals[0], -7);
	KUNIT_EXPECT_EQ(test, pre_vals[1], 42);

	/* 小容量数组：拷贝截断到容量，出参 n=实际条数 */
	n = 1;
	KUNIT_EXPECT_EQ(test,
			ai_policy_safety_snapshot_lookup(0x66000011ULL,
							 pre_vals, &n),
			AI_OK);
	KUNIT_EXPECT_EQ(test, n, 2);
	KUNIT_EXPECT_EQ(test, pre_vals[0], -7);

	/* 未知决策 → NOT_FOUND */
	n = AI_SAFETY_SNAPSHOT_PARAMS;
	KUNIT_EXPECT_EQ(test,
			ai_policy_safety_snapshot_lookup(0x66000099ULL,
							 pre_vals, &n),
			AI_ERR_NOT_FOUND);

	/* rollback 消费快照（restore=NULL 不执行恢复）→ 再查 NOT_FOUND */
	KUNIT_EXPECT_EQ(test,
			ai_policy_safety_rollback_decision(0x66000011ULL,
							   NULL), AI_OK);
	n = AI_SAFETY_SNAPSHOT_PARAMS;
	KUNIT_EXPECT_EQ(test,
			ai_policy_safety_snapshot_lookup(0x66000011ULL,
							 pre_vals, &n),
			AI_ERR_NOT_FOUND);
}

static struct kunit_case policy_test_cases[] = {
	KUNIT_CASE(policy_register_execute_test),
	KUNIT_CASE(policy_param_target_test),
	KUNIT_CASE(policy_outcome_test),
	KUNIT_CASE(policy_rollback_test),
	KUNIT_CASE(policy_safety_clamp_test),
	KUNIT_CASE(policy_safety_span1_test),
	KUNIT_CASE(policy_fail_rollback_test),
	KUNIT_CASE(policy_stats_test),
	KUNIT_CASE(policy_execute_latency_test),
	KUNIT_CASE(policy_affinity_idem_fastpath_test),
	KUNIT_CASE(policy_snapshot_pre_lookup_test),
	{}
};

static struct kunit_suite policy_test_suite = {
	.name = "ai_policy",
	.test_cases = policy_test_cases,
};

#else /* !CONFIG_AIKERNEL_RUNTIME */

static struct kunit_suite policy_test_suite = {
	.name = "ai_policy",
	.test_cases = {},
};

#endif

kunit_test_suite(policy_test_suite);
MODULE_LICENSE("GPL v2");
