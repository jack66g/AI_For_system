// SPDX-License-Identifier: GPL-2.0
/*
 * ai_causal_test.c - AI 决策因果链 KUnit 测试（A 轨 模块15.6）
 *
 * 覆盖：chain push/read 完整性（trigger→decision→outcome 首尾一致）、
 * ring 512 满覆盖（最旧丢弃）。
 *
 * CONFIG_AIKERNEL=n 时不参与编译（Makefile 门控）→ 无操作；
 * CONFIG_AIKERNEL_RUNTIME=n 时编译为空套件。
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include "../core/ai_types.h"
#include "../core/ai_policy.h"
#include "../core/ai_causal.h"
#include "../core/ai_telemetry.h"

#ifdef CONFIG_AIKERNEL_RUNTIME

static void causal_chain_integrity_test(struct kunit *test)
{
	struct ai_decision_record rec = { 0 };
	struct ai_decision_record *buf;
	u32 count = 0;
	size_t bytes = 0;
	int rc;

	ai_causal_flush();   /* 关闭文件句柄：测试不写 CSV（目录可能不存在） */

	/* 构造完整因果链：trigger → decision → outcome */
	rec.trigger_ts = 1000;
	rec.trigger_event_id = AI_EVENT_ID(AI_CAT_MM, AI_EV_RECLAIM);
	rec.decision_ts = 2000;
	rec.decision_type = 7;
	rec.decision_data[0] = 42;
	rec.execute_ts = 3000;
	rec.outcome_ts = 4000;
	rec.outcome = AI_OUTCOME_SUCCESS;
	rec.metric_delta = -12;
	rec.model_version = 3;
	rec.confidence = 95;
	rec.decision_id = 12345;

	rc = ai_causal_chain_push(&rec);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	buf = kzalloc(sizeof(rec) * 8, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	rc = ai_causal_chain_read(buf, sizeof(rec) * 8, &count, &bytes);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_GE(test, count, 1u);

	if (count >= 1) {
		/* 最后一条应为刚 push 的完整链（首尾字段一致） */
		struct ai_decision_record *last = &buf[count - 1];

		KUNIT_EXPECT_EQ(test, last->decision_id, 12345ULL);
		KUNIT_EXPECT_EQ(test, last->trigger_event_id,
				AI_EVENT_ID(AI_CAT_MM, AI_EV_RECLAIM));
		KUNIT_EXPECT_EQ(test, last->outcome, (u8)AI_OUTCOME_SUCCESS);
		KUNIT_EXPECT_EQ(test, last->metric_delta, -12LL);
		KUNIT_EXPECT_EQ(test, last->decision_data[0], 42ULL);
		KUNIT_EXPECT_EQ(test, last->confidence, 95);
	}
	kfree(buf);
}

static void causal_ring_overflow_test(struct kunit *test)
{
	struct ai_decision_record *buf;
	u32 count = 0;
	size_t bytes = 0;
	unsigned int i;
	int rc;

	ai_causal_flush();

	/* 压满 ring（512 条）+ 溢出 32 条：满覆盖最旧 */
	for (i = 0; i < AI_CAUSAL_RING_SIZE + 32; i++) {
		struct ai_decision_record rec = { 0 };

		rec.decision_id = 100000 + i;
		rec.outcome = AI_OUTCOME_UNKNOWN;
		rc = ai_causal_chain_push(&rec);
		KUNIT_EXPECT_EQ(test, rc, AI_OK);
	}

	buf = kzalloc(sizeof(*buf) * (AI_CAUSAL_RING_SIZE + 8), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	rc = ai_causal_chain_read(buf, sizeof(*buf) * (AI_CAUSAL_RING_SIZE + 8),
				  &count, &bytes);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, count, (u32)AI_CAUSAL_RING_SIZE);   /* 满容量 */

	if (count == AI_CAUSAL_RING_SIZE) {
		/* 最旧应已被覆盖：第一条为 100000+32 */
		KUNIT_EXPECT_EQ(test, buf[0].decision_id, 100032ULL);
		/* 最后一条为最新 */
		KUNIT_EXPECT_EQ(test, buf[count - 1].decision_id,
				100000ULL + AI_CAUSAL_RING_SIZE + 31);
	}
	kfree(buf);
}

static struct kunit_case causal_test_cases[] = {
	KUNIT_CASE(causal_chain_integrity_test),
	KUNIT_CASE(causal_ring_overflow_test),
	{}
};

static struct kunit_suite causal_test_suite = {
	.name = "ai_causal",
	.test_cases = causal_test_cases,
};

#else /* !CONFIG_AIKERNEL_RUNTIME */

static struct kunit_suite causal_test_suite = {
	.name = "ai_causal",
	.test_cases = {},
};

#endif

kunit_test_suite(causal_test_suite);
MODULE_LICENSE("GPL v2");
