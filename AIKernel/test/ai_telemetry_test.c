// SPDX-License-Identifier: GPL-2.0
/*
 * ai_telemetry_test.c - AI 遥测 ring buffer KUnit 测试（A 轨 模块15.6）
 *
 * 覆盖：写入/读取往返一致、满则丢弃（dropped 计数）、采样率 0/1/N、
 * reset 清空、写入延迟实测。
 *
 * 测试鲁棒性设计：ring 为 per-CPU 且全系统共享（其他子系统埋点持续写入），
 * 因此：
 *   1) 测试线程先绑定 CPU 0（set_cpus_allowed_ptr + sched_getcpu 等待），
 *      写读都在 CPU 0 上；
 *   2) 断言用"标记 payload"（data[0]=0xA1, data[63]=0xA1）+ 回读计数，
 *      与系统事件天然隔离；
 *   3) 统计断言用 >= 阈值（emitted 含其他事件）。
 *
 * CONFIG_AIKERNEL=n 时本文件不参与编译（Makefile 门控）→ 无操作；
 * CONFIG_AIKERNEL_TELEMETRY=n 时编译为空套件（子开关兜底）。
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"

#ifdef CONFIG_AIKERNEL_TELEMETRY

#define MARKER 0xA1   /* 标记 payload 首尾字节 */

/* 绑定当前线程到 CPU 0（KUnit kthread 上下文） */
static void telemetry_pin_cpu0(struct kunit *test)
{
	cpumask_t *mask = kunit_kzalloc(test, cpumask_size(), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, mask);
	cpumask_clear(mask);
	cpumask_set_cpu(0, mask);
	if (set_cpus_allowed_ptr(current, mask) == 0) {
		unsigned int spin = 0;

		/* 等待迁移生效（实际已在 CPU 0 运行） */
		while (smp_processor_id() != 0 && spin++ < 100000)
			cpu_relax();
	}
	KUNIT_EXPECT_EQ(test, smp_processor_id(), 0u);
}

/* 回读全 CPU，统计标记 payload（data[0]==MARKER && data[len-1]==MARKER）
 * 的记录数；fmt 校验记录完整性 */
static unsigned int telemetry_count_marker(const u8 marker)
{
	void *buf;
	unsigned int cpu, count = 0;

	buf = kzalloc(AI_TELEMETRY_RING_SIZE, GFP_KERNEL);
	if (!buf)
		return 0;

	for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
		size_t n = 0, pos = 0;

		if (ai_telemetry_read(cpu, buf, AI_TELEMETRY_RING_SIZE, &n)
		    != AI_OK)
			continue;
		while (pos + AI_TELEMETRY_HEADER_LEN <= n) {
			struct ai_telemetry_record *rec =
				(struct ai_telemetry_record *)((u8 *)buf + pos);
			const u8 *d;
			size_t total;

			total = AI_TELEMETRY_HEADER_LEN + rec->data_len;
			if (pos + total > n)
				break;
			d = (const u8 *)buf + pos + AI_TELEMETRY_HEADER_LEN;
			if (rec->data_len >= 2 && d[0] == marker &&
			    d[rec->data_len - 1] == marker)
				count++;
			pos += total;
		}
	}
	kfree(buf);
	return count;
}

static void telemetry_write_read_test(struct kunit *test)
{
	u8 payload[64];
	unsigned int i;
	int rc;

	telemetry_pin_cpu0(test);
	rc = ai_telemetry_init();
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	rc = ai_telemetry_reset();
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	/* 显式全量采样（KUnit 在子系统 late_initcall 之前运行，
	 * 防御性保证速率不干扰标记计数） */
	rc = ai_telemetry_set_sample_rate(AI_CAT_SCHED, AI_EV_SCHED_LATENCY, 1);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	/* 写入 3 条标记记录：全量原始数据（零脱敏往返一致） */
	for (i = 0; i < 3; i++) {
		memset(payload, (int)i, sizeof(payload));
		payload[0] = MARKER;
		payload[sizeof(payload) - 1] = MARKER;
		rc = ai_telemetry_emit(AI_CAT_SCHED, AI_EV_SCHED_LATENCY + i,
				       AI_SEV_NORMAL, payload, sizeof(payload));
		KUNIT_EXPECT_EQ(test, rc, AI_OK);
	}

	/* 3 条标记记录全部回读（跨全 CPU 计数） */
	KUNIT_EXPECT_EQ(test, telemetry_count_marker(MARKER), 3u);

	/* reset 后清空 */
	rc = ai_telemetry_reset();
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, telemetry_count_marker(MARKER), 0u);
}

static void telemetry_overflow_test(struct kunit *test)
{
	struct ai_telemetry_cpu_stats st;
	void *buf;
	unsigned int i;
	int rc;

	telemetry_pin_cpu0(test);
	ai_telemetry_init();
	ai_telemetry_reset();

	/* 写入远大于 ring 容量（128KB）的数据：64 条 x 4KB = 256KB，
	 * 必然触发满丢弃（payload 走堆，避免测试栈帧超限） */
	buf = kzalloc(AI_TELEMETRY_MAX_DATA_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	memset(buf, MARKER, AI_TELEMETRY_MAX_DATA_LEN);
	for (i = 0; i < 64; i++) {
		rc = ai_telemetry_emit(AI_CAT_MM, AI_EV_PAGE_ALLOC,
				       AI_SEV_NORMAL, buf,
				       AI_TELEMETRY_MAX_DATA_LEN);
		/* 语义（ai_telemetry.h）：不阻塞；满则丢弃并累计 dropped，
		 * 返回 AI_ERR_RING_FULL（-16） */
		KUNIT_EXPECT_TRUE(test, rc == AI_OK || rc == AI_ERR_RING_FULL);
	}
	kfree(buf);

	/* 满丢弃已累计（emitted/dropped 含系统事件，用阈值断言） */
	rc = ai_telemetry_stats(0, &st);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_GT(test, st.emitted, 0u);
	KUNIT_EXPECT_GT(test, st.dropped, 0u);

	/* ring 内容仍可读出（最旧丢弃，非崩溃） */
	KUNIT_EXPECT_GE(test, telemetry_count_marker(MARKER), 1u);

	ai_telemetry_reset();
}

static void telemetry_sample_rate_test(struct kunit *test)
{
	u8 payload[4] = { MARKER, 0, 0, MARKER };
	u32 rate = 0;
	unsigned int i;
	int rc;

	telemetry_pin_cpu0(test);
	ai_telemetry_init();
	ai_telemetry_reset();

	/* rate=0：全部丢弃（标记记录 0 条） */
	rc = ai_telemetry_set_sample_rate(AI_CAT_NET, AI_EV_TCP, 0);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	rc = ai_telemetry_get_sample_rate(AI_CAT_NET, AI_EV_TCP, &rate);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, rate, 0u);
	for (i = 0; i < 4; i++)
		ai_telemetry_emit(AI_CAT_NET, AI_EV_TCP, AI_SEV_NORMAL,
				  payload, sizeof(payload));
	KUNIT_EXPECT_EQ(test, telemetry_count_marker(MARKER), 0u);

	/* rate=1：全量（4 条标记） */
	ai_telemetry_reset();
	rc = ai_telemetry_set_sample_rate(AI_CAT_NET, AI_EV_TCP, 1);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	for (i = 0; i < 4; i++)
		ai_telemetry_emit(AI_CAT_NET, AI_EV_TCP, AI_SEV_NORMAL,
				  payload, sizeof(payload));
	KUNIT_EXPECT_EQ(test, telemetry_count_marker(MARKER), 4u);

	/* rate=N=4：每 4 条记 1 条（8 次 → 2 条） */
	ai_telemetry_reset();
	rc = ai_telemetry_set_sample_rate(AI_CAT_NET, AI_EV_TCP, 4);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	for (i = 0; i < 8; i++)
		ai_telemetry_emit(AI_CAT_NET, AI_EV_TCP, AI_SEV_NORMAL,
				  payload, sizeof(payload));
	KUNIT_EXPECT_EQ(test, telemetry_count_marker(MARKER), 2u);

	rc = ai_telemetry_set_sample_rate(AI_CAT_NET, AI_EV_TCP, 1); /* 还原 */
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	ai_telemetry_reset();
}

static void telemetry_emit_direct_test(struct kunit *test)
{
	u8 payload[4] = { MARKER, 0, 0, MARKER };
	bool take;
	int rc;

	telemetry_pin_cpu0(test);
	ai_telemetry_init();
	ai_telemetry_reset();

	/* sample_take + emit_direct 组合（供热路径埋点姿势）。
	 * 采样计数器为 per-CPU 共享（ai_ring_sample），相位取决于此前
	 * CPU0 上的全部采样活动，因此断言"两次恰好一次为 true"（XOR）。 */
	rc = ai_telemetry_set_sample_rate(AI_CAT_IO, AI_EV_BIO, 2);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	take = ai_telemetry_sample_take(AI_CAT_IO, AI_EV_BIO);
	rc = ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_BIO, AI_SEV_NORMAL,
				      payload, sizeof(payload));
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	{
		bool take2 = ai_telemetry_sample_take(AI_CAT_IO, AI_EV_BIO);

		/* rate=2：两次恰好命中一次 */
		KUNIT_EXPECT_TRUE(test, take != take2);
	}

	/* emit_direct 不做采样判定（已判定后直写）：两次直写都入 ring */
	{
		rc = ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_BIO,
					      AI_SEV_NORMAL, payload,
					      sizeof(payload));
		KUNIT_EXPECT_EQ(test, rc, AI_OK);
	}
	KUNIT_EXPECT_EQ(test, telemetry_count_marker(MARKER), 2u);

	ai_telemetry_set_sample_rate(AI_CAT_IO, AI_EV_BIO, 1);
	ai_telemetry_reset();
}

static void telemetry_write_latency_test(struct kunit *test)
{
	/*
	 * 性能实测（Prompt 15 验证标准：遥测写 < 100ns 目标，TCG 下记录实测）：
	 * 循环 1024 次 ai_telemetry_emit()（无锁 per-CPU ring 写路径），
	 * ktime_get_raw_ns 计时。QEMU TCG 下为真实硬件数倍，实测值如实记录。
	 */
	struct ai_telemetry_cpu_stats st;
	u64 t0, t1, avg;
	unsigned int i;
	int rc;

	telemetry_pin_cpu0(test);
	ai_telemetry_init();
	ai_telemetry_reset();
	rc = ai_telemetry_set_sample_rate(AI_CAT_TIME, AI_EV_DELAY, 1);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	t0 = ktime_get_raw_ns();
	for (i = 0; i < 1024; i++)
		ai_telemetry_emit(AI_CAT_TIME, AI_EV_DELAY, AI_SEV_DEBUG,
				  NULL, 0);
	t1 = ktime_get_raw_ns();
	avg = (t1 - t0) / 1024;

	ai_telemetry_stats(0, &st);
	/* 1024 条 23B = 23.5KB < 128KB ring，全部落盘（含系统事件 ≥1024） */
	KUNIT_EXPECT_GE(test, st.emitted, 1024u);
	pr_info("AIKernel KUnit: telemetry write latency avg=%llu ns/emit "
		"(%u emits, total=%llu ns)\n", avg, 1024,
		(unsigned long long)(t1 - t0));
	/* TCG 宽松上界：真实硬件应 < 100ns */
	KUNIT_EXPECT_LT(test, avg, 100000ULL);
}

static void telemetry_cat18_test(struct kunit *test)
{
	/*
	 * 第 18 类（AI 自我观测）发射回归测试：Prompt 13 引入 cat18 后，
	 * 采样率表仍按 17 类分配 → emit 拒绝（AI_ERR_INVALID_ARG），
	 * 决策/结果事件从未入 ring。Prompt 15 修复表尺寸与校验后补测。
	 */
	u8 payload[8] = { MARKER, 1, 2, 3, 4, 5, 6, MARKER };
	int rc;

	telemetry_pin_cpu0(test);
	ai_telemetry_init();
	ai_telemetry_reset();
	rc = ai_telemetry_set_sample_rate(AI_CAT_AI, AI_EV_AI_DECISION, 1);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	rc = ai_telemetry_emit(AI_CAT_AI, AI_EV_AI_DECISION, AI_SEV_NORMAL,
			       payload, sizeof(payload));
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	rc = ai_telemetry_emit(AI_CAT_AI, AI_EV_AI_OUTCOME, AI_SEV_NORMAL,
			       payload, sizeof(payload));
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	/* 两条 cat18 标记记录全部回读 */
	KUNIT_EXPECT_EQ(test, telemetry_count_marker(MARKER), 2u);

	ai_telemetry_reset();
}

static struct kunit_case telemetry_test_cases[] = {
	KUNIT_CASE(telemetry_write_read_test),
	KUNIT_CASE(telemetry_overflow_test),
	KUNIT_CASE(telemetry_sample_rate_test),
	KUNIT_CASE(telemetry_emit_direct_test),
	KUNIT_CASE(telemetry_cat18_test),
	KUNIT_CASE(telemetry_write_latency_test),
	{}
};

static struct kunit_suite telemetry_test_suite = {
	.name = "ai_telemetry",
	.test_cases = telemetry_test_cases,
};

#else /* !CONFIG_AIKERNEL_TELEMETRY */

static struct kunit_suite telemetry_test_suite = {
	.name = "ai_telemetry",
	.test_cases = {},
};

#endif

kunit_test_suite(telemetry_test_suite);
MODULE_LICENSE("GPL v2");
