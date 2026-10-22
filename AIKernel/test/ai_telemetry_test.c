// SPDX-License-Identifier: GPL-2.0
/*
 * ai_telemetry_test.c - AI 遥测 ring buffer KUnit 测试（A 轨 模块15.6）
 *
 * 覆盖：写入/读取往返一致、满则丢弃（dropped 计数）、采样率 0/1/N、
 * reset 清空、写入延迟实测；w24 新增：后台排空（drain_all 读空 + consumed
 * 计额）、积压自适应降采样（积压越高位水位 → 位移抬起/sampled_skip 计额/
 * IMPORTANT 旁路 → 排空后位移衰减恢复）。
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
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/bitmap.h>
#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"

#ifdef CONFIG_AIKERNEL_TELEMETRY

#define MARKER 0xA1   /* 标记 payload 首尾字节 */

/* w58 测试隔离：暂停 250ms 后台排空线程，避免其在"灌环→回读"断言窗口
 * 内并发消费标记记录（W57 无 initrd 直启下 write_read/overflow 偶发失败
 * 的根因）。用 kunit_add_action 保证异常路径也会恢复。 */
static void telemetry_drain_restart_action(void *unused)
{
	ai_telemetry_drain_start();
}

static void telemetry_test_quiesce(struct kunit *test)
{
	if (!ai_telemetry_drain_running())
		return;
	ai_telemetry_drain_stop();
	kunit_add_action(test, telemetry_drain_restart_action, NULL);
}

/* w63：predrain 用例结束恢复"消费者就绪"闩锁（异常路径同样生效） */
static void telemetry_consumer_ready_restore(void *unused)
{
	ai_telemetry_test_set_consumer_ready(true);
}

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
	telemetry_test_quiesce(test);
	rc = ai_telemetry_reset();
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	/* 显式全量采样：SCHED 子系统 initcall 会把 LATENCY 设成 1/32、
	 * PELT 设成 1/64，本用例用到 LATENCY..PELT 三个事件，必须逐个
	 * 置 1，否则标记记录会被 rate 采样静默跳过（W57 偶发失败的根因）。 */
	for (i = 0; i < 3; i++) {
		rc = ai_telemetry_set_sample_rate(AI_CAT_SCHED,
						  AI_EV_SCHED_LATENCY + i, 1);
		KUNIT_EXPECT_EQ(test, rc, AI_OK);
	}

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
	telemetry_test_quiesce(test);
	ai_telemetry_reset();
	/* mm 子系统 initcall 把 PAGE_ALLOC 设为 1/32；本用例按"条"灌满
	 * ring 验证 dropped，必须显式全量，否则 64 次 emit 只剩 2 条入环。 */
	rc = ai_telemetry_set_sample_rate(AI_CAT_MM, AI_EV_PAGE_ALLOC, 1);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	/*
	 * Part A：环满真丢弃语义（dropped）。
	 * w24 起 NORMAL 级在积压超水位时会被自适应降采样跳过（不再进环），
	 * 故本用例改用 IMPORTANT 级灌环（旁路自适应层，保证写入路径被压满）：
	 * 64 条 x 4KB = 256KB > 环容量-1，必然触发满丢弃。payload 走堆。
	 */
	buf = kzalloc(AI_TELEMETRY_MAX_DATA_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	memset(buf, MARKER, AI_TELEMETRY_MAX_DATA_LEN);
	for (i = 0; i < 64; i++) {
		rc = ai_telemetry_emit(AI_CAT_MM, AI_EV_PAGE_ALLOC,
				       AI_SEV_IMPORTANT, buf,
				       AI_TELEMETRY_MAX_DATA_LEN);
		/* 语义（ai_telemetry.h）：不阻塞；满则丢弃并累计 dropped，
		 * 返回 AI_ERR_RING_FULL（-16） */
		KUNIT_EXPECT_TRUE(test, rc == AI_OK || rc == AI_ERR_RING_FULL);
	}

	/* 满丢弃已累计（emitted/dropped 含系统事件，用阈值断言） */
	rc = ai_telemetry_stats(0, &st);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_GT(test, st.emitted, 0u);
	KUNIT_EXPECT_GT(test, st.dropped, 0u);

	/* ring 内容仍可读出（最旧丢弃，非崩溃） */
	KUNIT_EXPECT_GE(test, telemetry_count_marker(MARKER), 1u);

	/*
	 * Part B（w24）：积压超水位时 NORMAL 级被自适应降采样"跳过"而非
	 * "丢弃"——skipped 计额走 sampled_skip/adapt_skipped，dropped 不变。
	 */
	for (i = 0; i < 8; i++)
		rc = ai_telemetry_emit(AI_CAT_MM, AI_EV_PAGE_ALLOC,
				       AI_SEV_NORMAL, buf, 64);
	rc = ai_telemetry_stats(0, &st);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_GT(test, st.adapt_skipped, (u64)0);
	KUNIT_EXPECT_GT(test, st.sampled_skip, 0u);

	kfree(buf);
	ai_telemetry_reset();
}

/* w24：后台排空——drain_all 把各 CPU ring 读空，consumed 计额、dropped 恒 0 */
static void telemetry_drain_test(struct kunit *test)
{
	struct ai_telemetry_cpu_stats st;
	u8 payload[32];
	unsigned int i;
	int rc;

	telemetry_pin_cpu0(test);
	ai_telemetry_init();
	telemetry_test_quiesce(test);
	ai_telemetry_reset();
	rc = ai_telemetry_set_sample_rate(AI_CAT_PROCESS, AI_EV_PROCESS_STATE,
					  1);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	/* 100 条标记记录入环（71B/条 << 环深，全部成功）。
	 * 标记 payload 首尾都打标（count_marker 校验首尾两字节） */
	payload[0] = MARKER;
	payload[sizeof(payload) - 1] = MARKER;
	for (i = 0; i < 100; i++) {
		payload[1] = (u8)i;
		rc = ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_PROCESS_STATE,
				       AI_SEV_NORMAL, payload, sizeof(payload));
		KUNIT_EXPECT_EQ(test, rc, AI_OK);
	}

	/* 排空前：backlog > 0 且 consumed == 0 */
	rc = ai_telemetry_stats(0, &st);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_GT(test, st.head - st.tail, 0u);
	KUNIT_EXPECT_EQ(test, st.consumed, (u64)0);

	/* 排空（多轮：覆盖 >64KB 的满环场景），允许系统事件少量再入环 */
	for (i = 0; i < 5; i++)
		ai_telemetry_drain_all();

	rc = ai_telemetry_stats(0, &st);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	/* backlog 近 0（残余仅为本断言窗口内落进的系统事件） */
	KUNIT_EXPECT_LT(test, st.head - st.tail, 8192u);
	KUNIT_EXPECT_GT(test, st.consumed, (u64)0);
	KUNIT_EXPECT_EQ(test, st.dropped, 0u);
	KUNIT_EXPECT_EQ(test, telemetry_count_marker(MARKER), 0u);

	ai_telemetry_reset();
}

/* w63：排空线程启动后首轮立即消费（不再等 AI_TEL_DRAIN_PERIOD_MS=250ms）。
 * 回归点：早期版本 kthread 先 schedule_timeout(250ms) 才第一次 drain，
 * 启动期高事件速率下 ring 可能在首轮前就已填充。 */
static void telemetry_drain_immediate_test(struct kunit *test)
{
	struct ai_telemetry_cpu_stats st;
	u8 payload[32];
	u64 t0, elapsed = 0;
	unsigned int i;
	int rc;

	telemetry_pin_cpu0(test);
	ai_telemetry_init();
	telemetry_test_quiesce(test);   /* 停掉后台 drain，确保 consumed 归零后可控 */
	rc = ai_telemetry_reset();
	KUNIT_ASSERT_EQ(test, rc, AI_OK);
	rc = ai_telemetry_set_sample_rate(AI_CAT_PROCESS,
					  AI_EV_PROCESS_STATE, 1);
	KUNIT_ASSERT_EQ(test, rc, AI_OK);

	payload[0] = MARKER;
	payload[sizeof(payload) - 1] = MARKER;
	for (i = 0; i < 100; i++) {
		payload[1] = (u8)i;
		rc = ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_PROCESS_STATE,
				       AI_SEV_NORMAL, payload, sizeof(payload));
		KUNIT_EXPECT_EQ(test, rc, AI_OK);
	}

	rc = ai_telemetry_stats(0, &st);
	KUNIT_ASSERT_EQ(test, rc, AI_OK);
	KUNIT_ASSERT_EQ(test, st.consumed, (u64)0);

	/* 启动排空线程，等待 consumed 变正（不直接调用 drain_all） */
	t0 = ktime_get_ns();
	rc = ai_telemetry_drain_start();
	KUNIT_ASSERT_EQ(test, rc, AI_OK);

	for (i = 0; i < 100; i++) {
		rc = ai_telemetry_stats(0, &st);
		KUNIT_ASSERT_EQ(test, rc, AI_OK);
		if (st.consumed > 0) {
			elapsed = ktime_get_ns() - t0;
			break;
		}
		usleep_range(1000, 2000);
	}

	KUNIT_EXPECT_GT(test, st.consumed, (u64)0);
	/* 首轮立即排空：远早于旧的 250ms 初始延迟 */
	KUNIT_EXPECT_LT(test, elapsed, (u64)200000000);
}

/* w63：消费者就绪前的环满丢弃计入 sampled_skip + predrain_dropped，
 * dropped 保持 0（启动窗口与稳态背压分离；M9 稳态口径）。 */
static void telemetry_predrain_accounting_test(struct kunit *test)
{
	struct ai_telemetry_cpu_stats st;
	void *buf;
	unsigned int i;
	int rc;

	/* 用例结束恢复闩锁（LIFO：先恢复 true，再重启 drain） */
	kunit_add_action(test, telemetry_consumer_ready_restore, NULL);
	telemetry_pin_cpu0(test);
	ai_telemetry_init();
	telemetry_test_quiesce(test);

	ai_telemetry_test_set_consumer_ready(false);   /* 模拟启动窗口 */
	rc = ai_telemetry_reset();
	KUNIT_ASSERT_EQ(test, rc, AI_OK);
	rc = ai_telemetry_set_sample_rate(AI_CAT_MM, AI_EV_PAGE_ALLOC, 1);
	KUNIT_ASSERT_EQ(test, rc, AI_OK);

	buf = kzalloc(AI_TELEMETRY_MAX_DATA_LEN, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	memset(buf, MARKER, AI_TELEMETRY_MAX_DATA_LEN);

	/* 80 x 4KB > 256KB：必然经历环满 */
	for (i = 0; i < 80; i++) {
		rc = ai_telemetry_emit(AI_CAT_MM, AI_EV_PAGE_ALLOC,
				       AI_SEV_IMPORTANT, buf,
				       AI_TELEMETRY_MAX_DATA_LEN);
		KUNIT_EXPECT_TRUE(test,
				  rc == AI_OK || rc == AI_ERR_RING_FULL);
	}

	rc = ai_telemetry_stats(0, &st);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_GT(test, st.predrain_dropped, (u64)0);
	KUNIT_EXPECT_EQ(test, st.dropped, 0u);
	KUNIT_EXPECT_GT(test, st.sampled_skip, 0u);

	kfree(buf);
	ai_telemetry_reset();

	/* 立即恢复就绪态（action 兜底异常路径） */
	ai_telemetry_test_set_consumer_ready(true);
}

/* w24：积压 → 自适应降采样 → 排空后恢复（任务书要求的闭环用例） */
static void telemetry_adaptive_test(struct kunit *test)
{
	struct ai_telemetry_cpu_stats st;
	u8 payload[48];
	unsigned int i;
	int rc;

	telemetry_pin_cpu0(test);
	ai_telemetry_init();
	telemetry_test_quiesce(test);
	ai_telemetry_reset();
	rc = ai_telemetry_set_sample_rate(AI_CAT_LOCK, AI_EV_MUTEX, 1);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	/* 阶段1：无人消费持续灌环 → 积压越高位水位 → 位移抬起、跳过计额。
	 * 标记 payload 首尾都打标（count_marker 校验首尾两字节） */
	payload[0] = MARKER;
	payload[sizeof(payload) - 1] = MARKER;
	for (i = 0; i < 6000; i++) {
		payload[1] = (u8)i;
		ai_telemetry_emit(AI_CAT_LOCK, AI_EV_MUTEX, AI_SEV_NORMAL,
				  payload, sizeof(payload));
		if ((i & 0x3f) == 0) {
			ai_telemetry_stats(0, &st);
			if (st.adapt_shift > 0)
				break;
		}
	}
	rc = ai_telemetry_stats(0, &st);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_GT(test, st.adapt_shift, 0u);
	KUNIT_EXPECT_GT(test, st.adapt_skipped, (u64)0);
	/* 跳过计额走 sampled_skip（采样跳过语义），dropped 保持真实丢弃 */
	KUNIT_EXPECT_GT(test, st.sampled_skip, 0u);

	/* 阶段2：IMPORTANT 级旁路自适应降采样 → 照常入环 */
	payload[1] = 0xEE;
	rc = ai_telemetry_emit(AI_CAT_LOCK, AI_EV_MUTEX, AI_SEV_IMPORTANT,
			       payload, sizeof(payload));
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	/* 阶段3：排空至低位水位以下 → 位移逐次衰减回 0 → 恢复原采样密度 */
	for (i = 0; i < 100; i++)
		ai_telemetry_drain_all();
	for (i = 0; i < 512; i++) {
		payload[1] = (u8)(i + 1);
		rc = ai_telemetry_emit(AI_CAT_LOCK, AI_EV_MUTEX,
				       AI_SEV_NORMAL, payload, sizeof(payload));
		KUNIT_EXPECT_EQ(test, rc, AI_OK);
		ai_telemetry_stats(0, &st);
		if (st.adapt_shift == 0)
			break;
	}
	KUNIT_EXPECT_EQ(test, st.adapt_shift, 0u);
	/* 恢复后新 emit 可入环（写读往返） */
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
	telemetry_test_quiesce(test);
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

/* w21：rate_cmd 解析（/proc/ai/telemetry 写 "rate=cat:ev:N" 的内核侧）。
 * 语法/边界非法拒、越界 cat/ev 拒、N>65535 钳 65535、成功落表读回。 */
static void telemetry_rate_cmd_test(struct kunit *test)
{
	u32 rate = 0;

	telemetry_pin_cpu0(test);
	ai_telemetry_init();

	/* 合法：cat=2 ev=10 → 8 */
	KUNIT_EXPECT_EQ(test, ai_telemetry_rate_cmd("2:10:8"), AI_OK);
	KUNIT_EXPECT_EQ(test, ai_telemetry_get_sample_rate(2, 10, &rate), AI_OK);
	KUNIT_EXPECT_EQ(test, rate, 8u);

	/* 语法非法 */
	KUNIT_EXPECT_NE(test, ai_telemetry_rate_cmd("2:10"), AI_OK);
	KUNIT_EXPECT_NE(test, ai_telemetry_rate_cmd("a:b:c"), AI_OK);
	KUNIT_EXPECT_NE(test, ai_telemetry_rate_cmd("2:10:8x"), AI_OK);
	KUNIT_EXPECT_NE(test, ai_telemetry_rate_cmd(""), AI_OK);
	KUNIT_EXPECT_NE(test, ai_telemetry_rate_cmd(NULL), AI_OK);

	/* 边界非法（unsigned long 域先检查，防 (u8) 截断绕过） */
	KUNIT_EXPECT_NE(test, ai_telemetry_rate_cmd("0:10:8"), AI_OK);
	KUNIT_EXPECT_NE(test, ai_telemetry_rate_cmd("99:10:8"), AI_OK);
	KUNIT_EXPECT_NE(test, ai_telemetry_rate_cmd("2:0:8"), AI_OK);
	KUNIT_EXPECT_NE(test, ai_telemetry_rate_cmd("2:999:8"), AI_OK);

	/* N 钳制：99999999 → 65535 */
	KUNIT_EXPECT_EQ(test, ai_telemetry_rate_cmd("2:10:99999999"), AI_OK);
	KUNIT_EXPECT_EQ(test, ai_telemetry_get_sample_rate(2, 10, &rate), AI_OK);
	KUNIT_EXPECT_EQ(test, rate, 65535u);

	/* 还原全量 */
	KUNIT_EXPECT_EQ(test, ai_telemetry_rate_cmd("2:10:1"), AI_OK);
	KUNIT_EXPECT_EQ(test, ai_telemetry_get_sample_rate(2, 10, &rate), AI_OK);
	KUNIT_EXPECT_EQ(test, rate, 1u);
}

static void telemetry_emit_direct_test(struct kunit *test)
{
	u8 payload[4] = { MARKER, 0, 0, MARKER };
	bool take;
	int rc;

	telemetry_pin_cpu0(test);
	ai_telemetry_init();
	telemetry_test_quiesce(test);
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
	telemetry_test_quiesce(test);
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

/* ---- w58：多读者并发一致性（1 生产者 + 3 读者） ----
 *
 * 复现 W57 读侧缺陷的最小闭环：生产者绑 CPU0 连续写带序列号的标记记录，
 * 3 个 kthread 同时对 CPU0 ring 调 ai_telemetry_read()，结束后再由测试
 * 线程做最终排空。断言：
 *   - 所有记录头合法（data_len ≤ 4096、不跨缓冲尾）→ 无撕裂/错位；
 *   - 每条标记记录恰好被读走一次（位图无重复、无缺失）→ 序列完整；
 *   - resyncs/dropped 无新增 → 无 bad_len/resync；
 *   - kthread_stop 全部返回 → 无死锁（配合 KUnit 300s 超时）。
 */
#define TEL_CONC_READERS  3
#define TEL_CONC_RECORDS  1800
#define TEL_CONC_DATA_LEN 64
#define TEL_CONC_RD_BUF   (64 * 1024)
#define TEL_CONC_TAG0     0x5A
#define TEL_CONC_TAG1     0xC3

struct telemetry_conc_ctx {
	unsigned long *seen;   /* 序列号位图（1..total） */
	u32 total;
	atomic_t errors;
	atomic_t reads;
};

static void telemetry_conc_scan(struct telemetry_conc_ctx *ctx,
				const u8 *buf, size_t n)
{
	size_t pos = 0;

	while (pos + AI_TELEMETRY_HEADER_LEN <= n) {
		const struct ai_telemetry_record *rec =
			(const struct ai_telemetry_record *)(buf + pos);
		const u8 *d = buf + pos + AI_TELEMETRY_HEADER_LEN;
		size_t total = AI_TELEMETRY_HEADER_LEN + rec->data_len;

		if (rec->data_len > AI_TELEMETRY_MAX_DATA_LEN ||
		    total > n - pos) {
			atomic_inc(&ctx->errors);
			return;
		}
		if (rec->category == AI_CAT_SCHED &&
		    rec->event_type == AI_EV_SCHED_LATENCY &&
		    rec->data_len == TEL_CONC_DATA_LEN &&
		    d[0] == MARKER && d[1] == TEL_CONC_TAG0 &&
		    d[2] == TEL_CONC_TAG1) {
			u32 seq;

			memcpy(&seq, d + 4, sizeof(seq));
			if (seq < 1 || seq > ctx->total ||
			    test_and_set_bit(seq - 1, ctx->seen))
				atomic_inc(&ctx->errors);
		}
		pos += total;
	}
	if (pos != n)
		atomic_inc(&ctx->errors);
}

static int telemetry_conc_reader_fn(void *data)
{
	struct telemetry_conc_ctx *ctx = data;
	u8 *buf;

	buf = kmalloc(TEL_CONC_RD_BUF, GFP_KERNEL);
	if (!buf) {
		atomic_inc(&ctx->errors);
		return 0;
	}

	while (!kthread_should_stop()) {
		size_t n = 0;

		if (ai_telemetry_read(0, buf, TEL_CONC_RD_BUF, &n) != AI_OK) {
			atomic_inc(&ctx->errors);
			break;
		}
		atomic_inc(&ctx->reads);
		telemetry_conc_scan(ctx, buf, n);
		if (!n)
			usleep_range(50, 100);
		else
			cond_resched();
	}
	kfree(buf);
	return 0;
}

static void telemetry_concurrent_readers_test(struct kunit *test)
{
	struct telemetry_conc_ctx ctx;
	struct task_struct *tasks[TEL_CONC_READERS];
	struct ai_telemetry_cpu_stats after;
	u8 *payload, *buf;
	unsigned int i, seq;
	int rc;

	telemetry_pin_cpu0(test);
	rc = ai_telemetry_init();
	KUNIT_ASSERT_EQ(test, rc, AI_OK);
	telemetry_test_quiesce(test);   /* 去掉后台 drain，读者只剩本用例 3 个 */
	rc = ai_telemetry_reset();
	KUNIT_ASSERT_EQ(test, rc, AI_OK);
	rc = ai_telemetry_set_sample_rate(AI_CAT_SCHED, AI_EV_SCHED_LATENCY, 1);
	KUNIT_ASSERT_EQ(test, rc, AI_OK);

	memset(&ctx, 0, sizeof(ctx));
	atomic_set(&ctx.errors, 0);
	atomic_set(&ctx.reads, 0);
	ctx.total = TEL_CONC_RECORDS;
	ctx.seen = kunit_kzalloc(test,
				 BITS_TO_LONGS(TEL_CONC_RECORDS) * sizeof(long),
				 GFP_KERNEL);
	payload = kunit_kzalloc(test, TEL_CONC_DATA_LEN, GFP_KERNEL);
	buf = kunit_kzalloc(test, TEL_CONC_RD_BUF, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx.seen);
	KUNIT_ASSERT_NOT_NULL(test, payload);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	payload[0] = MARKER;
	payload[1] = TEL_CONC_TAG0;
	payload[2] = TEL_CONC_TAG1;
	payload[3] = 0;
	payload[TEL_CONC_DATA_LEN - 1] = MARKER;

	for (i = 0; i < TEL_CONC_READERS; i++) {
		tasks[i] = kthread_run(telemetry_conc_reader_fn, &ctx,
				       "tel_rd%u", i);
		if (IS_ERR(tasks[i])) {
			unsigned int j;

			for (j = 0; j < i; j++)
				kthread_stop(tasks[j]);
			KUNIT_FAIL(test, "reader kthread create failed");
			return;
		}
	}

	/* 生产者：IMPORTANT 旁路自适应降采样；总量 1800 x 87B ≈ 153KB，
	 * 低于环深，且读者持续消费 → 不应出现环满丢弃。 */
	for (seq = 1; seq <= TEL_CONC_RECORDS; seq++) {
		memcpy(payload + 4, &seq, sizeof(seq));
		rc = ai_telemetry_emit(AI_CAT_SCHED, AI_EV_SCHED_LATENCY,
				       AI_SEV_IMPORTANT, payload,
				       TEL_CONC_DATA_LEN);
		if (rc != AI_OK)
			atomic_inc(&ctx.errors);
		if ((seq & 0x1f) == 0)
			cond_resched();
	}

	for (i = 0; i < TEL_CONC_READERS; i++) {
		if (!IS_ERR_OR_NULL(tasks[i]))
			kthread_stop(tasks[i]);
		tasks[i] = NULL;
	}

	/* 最终排空：读者退出后把余量读进测试线程并校验完整性 */
	for (i = 0; i < 64; i++) {
		size_t n = 0;

		rc = ai_telemetry_read(0, buf, TEL_CONC_RD_BUF, &n);
		KUNIT_ASSERT_EQ(test, rc, AI_OK);
		if (!n)
			break;
		telemetry_conc_scan(&ctx, buf, n);
	}

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx.errors), 0);
	KUNIT_EXPECT_GT(test, atomic_read(&ctx.reads), 0);
	for (i = 0; i < TEL_CONC_RECORDS; i++)
		if (!test_bit(i, ctx.seen))
			break;
	KUNIT_EXPECT_EQ(test, i, (unsigned int)TEL_CONC_RECORDS);

	/* reset 后 resyncs/dropped 均从 0 起：本用例期间不应有新增 */
	rc = ai_telemetry_stats(0, &after);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, after.resyncs, 0u);
	KUNIT_EXPECT_EQ(test, after.dropped, 0u);
	KUNIT_EXPECT_EQ(test, after.adapt_peak_shift, 0u);
	KUNIT_EXPECT_EQ(test, after.adapt_episodes, (u64)0);

	ai_telemetry_reset();
}

static struct kunit_case telemetry_test_cases[] = {
	KUNIT_CASE(telemetry_write_read_test),
	KUNIT_CASE(telemetry_overflow_test),
	KUNIT_CASE(telemetry_sample_rate_test),
	KUNIT_CASE(telemetry_rate_cmd_test),
	KUNIT_CASE(telemetry_emit_direct_test),
	KUNIT_CASE(telemetry_cat18_test),
	KUNIT_CASE(telemetry_drain_test),
	KUNIT_CASE(telemetry_drain_immediate_test),
	KUNIT_CASE(telemetry_predrain_accounting_test),
	KUNIT_CASE(telemetry_adaptive_test),
	KUNIT_CASE(telemetry_write_latency_test),
	KUNIT_CASE(telemetry_concurrent_readers_test),
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
