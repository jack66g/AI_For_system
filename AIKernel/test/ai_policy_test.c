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
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/ai_netlink.h>
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

/* ---- K1：统一 trace 与决策环扩展（KERNEL-K1-DESIGN D2/D3/D5/D6） ---- */

/* 读出全量 ring 快照（KUnit 套件内串行，末条=最近；失败返回 NULL
 * 由调用方 ASSERT 兜底——非 void 帮手不用 KUNIT_ASSERT 宏） */
static struct ai_decision_record *policy_ring_read(struct kunit *test,
						   u32 *count)
{
	struct ai_decision_record *buf;

	buf = kunit_kzalloc(test, AI_POLICY_DECISION_RING_SIZE * sizeof(*buf),
			    GFP_KERNEL);
	if (!buf)
		return NULL;
	if (ai_policy_decision_read(buf, AI_POLICY_DECISION_RING_SIZE *
				    sizeof(*buf), count, NULL) != AI_OK)
		return NULL;
	return buf;
}

/* K1 D2：v1 零进零铸 → 每条决策 trace 恒非零，hi==boot_cookie、
 * lo==decision_id；连发 3 次验证唯一性（lo 单调递增）。 */
static void policy_trace_mint_test(struct kunit *test)
{
	struct ai_decision_record *recs;
	struct ai_policy_ctx ctx;
	u64 last_lo = 0;
	u32 count = 0, i;
	int rc;

	/* 依赖 policy_register_execute_test 已注册 kunit.test.param
	 * （套件按声明序串行；防御性重注册幂等） */
	ai_policy_unregister("kunit.test.param");
	KUNIT_EXPECT_EQ(test,
			ai_policy_register(AI_POLICY_DOMAIN_GENERAL,
					    "kunit.test.param", test_action_cb,
					    test_action_rb, NULL),
			AI_OK);

	recs = policy_ring_read(test, &count);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, recs);

	for (i = 0; i < 3; i++) {
		const struct ai_decision_record *r;

		memset(&ctx, 0, sizeof(ctx));
		ctx.domain = AI_POLICY_DOMAIN_GENERAL;
		ctx.decision_data[0] = 60;
		rc = ai_policy_execute(&ctx, NULL);
		KUNIT_ASSERT_EQ(test, rc, 1);

		KUNIT_ASSERT_EQ(test,
				ai_policy_decision_read(
					recs,
					AI_POLICY_DECISION_RING_SIZE *
					sizeof(*recs),
					&count, NULL),
				AI_OK);
		KUNIT_ASSERT_GE(test, count, 1u);
		r = &recs[count - 1];
		KUNIT_EXPECT_NE(test, r->decision_id, 0ULL);
		KUNIT_EXPECT_NE(test, r->trace_hi, 0ULL);
		KUNIT_EXPECT_NE(test, r->trace_lo, 0ULL);
		KUNIT_EXPECT_EQ(test, r->trace_lo, r->decision_id);
		KUNIT_EXPECT_EQ(test, r->trace_hi, ai_trace_boot_cookie);
		KUNIT_EXPECT_GT(test, r->trace_lo, last_lo);   /* 唯一性 */
		last_lo = r->trace_lo;
	}
}

/* K1 D3/D8：ACT2 全链（ctx 直调 execute_trace → ring 回读）8 新字段
 * 逐一对值；显式 trace（hi/lo 任一非零）采用不改写，ctx 出参带回。 */
static void policy_record_ext_fields_test(struct kunit *test)
{
	struct ai_decision_record *recs;
	struct ai_policy_ctx ctx;
	u32 count = 0;
	int rc;

	memset(&ctx, 0, sizeof(ctx));
	ctx.domain = AI_POLICY_DOMAIN_GENERAL;
	ctx.decision_type = 1;
	ctx.decision_data[0] = 60;
	ctx.confidence = 100;
	ctx.model_version = 7;
	ctx.trigger_ts = ktime_get_ns() - 1000000;   /* 1ms 前：cost 确定性 */
	ctx.trace_hi = 0x00deadbeefcafe01ULL;   /* 显式携带（ACT2 语义） */
	ctx.trace_lo = 0x0000000000000042ULL;
	ctx.intent_id = 0xab;
	ctx.parent_id = 0;
	ctx.agent_id = AI_AGENT_OCC_AI;
	ctx.expected = -1500000;
	rc = ai_policy_execute_trace(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 1);

	/* ctx 出参回读：id 补铸 + 显式 trace 原样带回（ACT2 ack 同源） */
	KUNIT_EXPECT_NE(test, ctx.decision_id, 0ULL);
	KUNIT_EXPECT_EQ(test, ctx.trace_hi, 0x00deadbeefcafe01ULL);
	KUNIT_EXPECT_EQ(test, ctx.trace_lo, 0x0000000000000042ULL);

	recs = policy_ring_read(test, &count);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, recs);
	KUNIT_ASSERT_GE(test, count, 1u);
	{
		const struct ai_decision_record *r = &recs[count - 1];

		KUNIT_EXPECT_EQ(test, r->decision_id, ctx.decision_id);
		KUNIT_EXPECT_EQ(test, r->trace_hi, 0x00deadbeefcafe01ULL);
		KUNIT_EXPECT_EQ(test, r->trace_lo, 0x0000000000000042ULL);
		KUNIT_EXPECT_EQ(test, r->intent_id, 0xabULL);
		KUNIT_EXPECT_EQ(test, r->parent_id, 0ULL);
		KUNIT_EXPECT_EQ(test, r->agent_id, (u32)AI_AGENT_OCC_AI);
		KUNIT_EXPECT_EQ(test, r->expected, -1500000LL);
		KUNIT_EXPECT_EQ(test, r->side_effect_mask,
				(u32)AI_SE_PARAM_WRITTEN);
		/* executed 形态：cost = exec_ts-trig_ts（trigger 提前 1ms） */
		KUNIT_EXPECT_GE(test, r->cost_ns, 900000ULL);
		KUNIT_EXPECT_EQ(test, r->cost_ns,
				r->execute_ts - r->trigger_ts);
	}
}

/* K1 D5：cost_ns 两形态——executed>0 → exec_ts-trig_ts；未命中 →
 * dec_ts-trig_ts（VIRT 域无动作）。trigger 置 1ms 前使断言确定性。 */
static void policy_cost_ns_test(struct kunit *test)
{
	struct ai_decision_record *recs;
	struct ai_policy_ctx ctx;
	u32 count = 0;
	int rc;

	/* 形态 1：executed>0（kunit.test.param 命中） */
	memset(&ctx, 0, sizeof(ctx));
	ctx.domain = AI_POLICY_DOMAIN_GENERAL;
	ctx.decision_data[0] = 60;
	ctx.trigger_ts = ktime_get_ns() - 1000000;
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 1);
	recs = policy_ring_read(test, &count);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, recs);
	KUNIT_ASSERT_GE(test, count, 1u);
	KUNIT_EXPECT_EQ(test, recs[count - 1].executed, 1);
	KUNIT_EXPECT_GE(test, recs[count - 1].cost_ns, 900000ULL);
	KUNIT_EXPECT_EQ(test, recs[count - 1].cost_ns,
			recs[count - 1].execute_ts -
			recs[count - 1].trigger_ts);

	/* 形态 2：executed=0（VIRT 域无动作）→ dec_ts-trig_ts */
	memset(&ctx, 0, sizeof(ctx));
	ctx.domain = AI_POLICY_DOMAIN_VIRT;
	ctx.trigger_ts = ktime_get_ns() - 1000000;
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 0);
	recs = policy_ring_read(test, &count);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, recs);
	KUNIT_ASSERT_GE(test, count, 1u);
	KUNIT_EXPECT_EQ(test, recs[count - 1].executed, 0);
	KUNIT_EXPECT_GE(test, recs[count - 1].cost_ns, 900000ULL);
	KUNIT_EXPECT_EQ(test, recs[count - 1].cost_ns,
			recs[count - 1].decision_ts -
			recs[count - 1].trigger_ts);
}

/* K1 D6 se 位情形 2 用：返回 clamp 语义（executed++/clamped++） */
static int test_clamp_cb(const struct ai_policy_ctx *ctx, void *arg)
{
	return AI_POLICY_RC_CLAMPED;
}

/* K1 D6：se 位三情形——成功写参数 / clamp / 失败回退（单点位聚合，
 * 位组合精确断言，不重复置位） */
static void policy_side_effect_mask_test(struct kunit *test)
{
	struct ai_decision_record *recs;
	struct ai_policy_ctx ctx;
	u32 count = 0;
	int rc;

	/* 情形 1：成功执行（kunit.test.param）→ 仅 PARAM_WRITTEN */
	memset(&ctx, 0, sizeof(ctx));
	ctx.domain = AI_POLICY_DOMAIN_GENERAL;
	ctx.decision_data[0] = 60;
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 1);
	recs = policy_ring_read(test, &count);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, recs);
	KUNIT_EXPECT_EQ(test, recs[count - 1].side_effect_mask,
			(u32)AI_SE_PARAM_WRITTEN);

	/* 情形 2：handler 返回 RC_CLAMPED → +SAFETY_CLAMPED（定向执行） */
	ai_policy_unregister("kunit.test.clamp");
	KUNIT_EXPECT_EQ(test,
			ai_policy_register(AI_POLICY_DOMAIN_GENERAL,
					    "kunit.test.clamp", test_clamp_cb,
					    NULL, NULL),
			AI_OK);
	memset(&ctx, 0, sizeof(ctx));
	strscpy(ctx.param, "kunit.test.clamp", sizeof(ctx.param));
	ctx.domain = AI_POLICY_DOMAIN_GENERAL;
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 1);
	recs = policy_ring_read(test, &count);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, recs);
	KUNIT_EXPECT_EQ(test, recs[count - 1].safety_clamped, 1);
	KUNIT_EXPECT_EQ(test, recs[count - 1].side_effect_mask,
			(u32)(AI_SE_PARAM_WRITTEN |
			       AI_SE_SAFETY_CLAMPED));
	ai_policy_unregister("kunit.test.clamp");

	/* 情形 3：失败 + rollback 回调 → 仅 ROLLED_BACK（无 PARAM_WRITTEN） */
	ai_policy_unregister("kunit.test.param");
	ai_policy_unregister("kunit.test.fail");
	KUNIT_EXPECT_EQ(test,
			ai_policy_register(AI_POLICY_DOMAIN_GENERAL,
					    "kunit.test.fail", test_fail_cb,
					    test_action_rb, NULL),
			AI_OK);
	memset(&ctx, 0, sizeof(ctx));
	ctx.domain = AI_POLICY_DOMAIN_GENERAL;
	rc = ai_policy_execute(&ctx, NULL);
	KUNIT_EXPECT_EQ(test, rc, 0);
	recs = policy_ring_read(test, &count);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, recs);
	KUNIT_EXPECT_EQ(test, recs[count - 1].side_effect_mask,
			(u32)AI_SE_ROLLED_BACK);
	ai_policy_unregister("kunit.test.fail");

	/* 恢复：后续套件依赖 kunit.test.param（latency 等用例） */
	ai_policy_register(AI_POLICY_DOMAIN_GENERAL, "kunit.test.param",
			   test_action_cb, test_action_rb, NULL);
}

/* K1 D2：heuristic 入口同理铸 trace（零进零铸第二条路径） */
static void policy_heuristic_trace_test(struct kunit *test)
{
	struct ai_decision_record *recs;
	u32 count = 0;

	KUNIT_EXPECT_EQ(test,
			ai_policy_record_heuristic(AI_POLICY_DOMAIN_MM,
						  3, 10, 1, 2),
			AI_OK);
	recs = policy_ring_read(test, &count);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, recs);
	KUNIT_ASSERT_GE(test, count, 1u);
	KUNIT_EXPECT_NE(test, recs[count - 1].decision_id, 0ULL);
	KUNIT_EXPECT_EQ(test, recs[count - 1].trace_hi,
			ai_trace_boot_cookie);
	KUNIT_EXPECT_EQ(test, recs[count - 1].trace_lo,
			recs[count - 1].decision_id);
	KUNIT_EXPECT_EQ(test, recs[count - 1].source,
			(u8)AI_DEC_SRC_HEURISTIC);
}

static int policy_u64_cmp(const void *a, const void *b)
{
	u64 x = *(const u64 *)a, y = *(const u64 *)b;

	return (x > y) - (x < y);
}

/* K1（KERNEL-K1-DESIGN §5 验收门）：record_write p99 微基准。
 * N=100000 次直调内部 record_write（KUnit 钩子，183B 整条落笔），
 * 逐次 ktime_get_ns 计时，p50/p99/p999 实测值 pr_info 输出（K1c
 * 真机取数，真值 ~1µs 级）；断言 p99 < 5000ns（CI 宽限防噪声）。 */
static void policy_record_write_p99_test(struct kunit *test)
{
	struct ai_decision_record rec = { 0 };
	u64 *lat, t0, t1, p50, p99, p999;
	unsigned int i, n = 100000;

	lat = kvmalloc_array(n, sizeof(*lat), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, lat);

	rec.trigger_ts = ktime_get_ns();
	rec.decision_ts = rec.trigger_ts + 1000;
	rec.execute_ts = rec.trigger_ts + 2000;
	rec.decision_id = 0x66000099ULL;
	rec.executed = 1;

	for (i = 0; i < n; i++) {
		t0 = ktime_get_ns();
		ai_policy_test_record_write(&rec);
		t1 = ktime_get_ns();
		lat[i] = t1 - t0;
	}
	sort(lat, n, sizeof(lat[0]), policy_u64_cmp, NULL);

	p50 = lat[n * 50 / 100];
	p99 = lat[n * 99 / 100];
	p999 = lat[n * 999 / 1000];
	pr_info("AIKernel KUnit: rec_write n=%u p50=%llu p99=%llu p999=%llu ns\n",
		n, p50, p99, p999);
	KUNIT_EXPECT_LT(test, p99, 5000ULL);
	kvfree(lat);
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
	/* K1：统一 trace 与决策环扩展（仅追加，既有用例零删改） */
	KUNIT_CASE(policy_trace_mint_test),
	KUNIT_CASE(policy_record_ext_fields_test),
	KUNIT_CASE(policy_cost_ns_test),
	KUNIT_CASE(policy_side_effect_mask_test),
	KUNIT_CASE(policy_heuristic_trace_test),
	KUNIT_CASE(policy_record_write_p99_test),
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
