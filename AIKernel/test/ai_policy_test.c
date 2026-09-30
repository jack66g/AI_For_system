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
#include "../core/ai_types.h"
#include "../core/ai_policy.h"
#include "../core/ai_policy_safety.h"
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

static struct kunit_case policy_test_cases[] = {
	KUNIT_CASE(policy_register_execute_test),
	KUNIT_CASE(policy_param_target_test),
	KUNIT_CASE(policy_outcome_test),
	KUNIT_CASE(policy_rollback_test),
	KUNIT_CASE(policy_safety_clamp_test),
	KUNIT_CASE(policy_fail_rollback_test),
	KUNIT_CASE(policy_stats_test),
	KUNIT_CASE(policy_execute_latency_test),
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
