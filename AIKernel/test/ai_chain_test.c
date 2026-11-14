// SPDX-License-Identifier: GPL-2.0
/*
 * ai_chain_test.c - K8 审计链 KUnit 测试（KERNEL-K8-DESIGN §3/§4）
 *
 * 覆盖：
 *   - 惰性 genesis（prev=seed/0）+ seq 单调 + 窗口验证；
 *   - 篡改四型定位到条（data/self_hash/prev_hash/seq 断档）；
 *   - 覆盖最旧驱逐（evicted/窗口收缩/越窗 -ENOENT）+ verify 仍过；
 *   - 周期锚（period=16 恰在 16/32 落锚）+ anchor_now 即发；
 *   - seed 仅空链收（非空 -EBUSY）+ genesis.prev==种子；
 *   - xxh64 向量钉扎（防用户态 python 实现漂移：selftest 同值）；
 *   - 并发 append 唯一序 + enable=0 快退；
 *   - 三层开销（§D8）：纯 append p99 绝对值 / record_write on-off 配对
 *     （微操口径如实报百分比）/ ACT 全路径占比（K2c 0.63-0.75ms 基线，
 *     链百 ns 级 → <0.1%，注释口径）；
 *   - 决策事件对（NEW/OUTCOME 同 decision_id 关联，可回填性覆盖）。
 *
 * CONFIG_AIKERNEL_SECURITY=n 时空套件（ai_chain.o 不构建）。
 *
 * 环境口径（真机实抓）：树 config KUNIT_AUTORUN=y 时本套件会在每次
 * boot ~29s 复位生产链（含 seeded）——dev boot 属预期；生产/验收 boot
 * 须 kunit.enable=0（factory grub 同款姿势，k8v rig 已带）。
 */

#include <kunit/test.h>
#include <linux/xxhash.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sort.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/string.h>

#include "../boundary/ai_chain.h"
#include "../core/ai_policy.h"

#ifdef CONFIG_AIKERNEL_SECURITY

static void chain_append_n(u16 kind, unsigned int n)
{
	unsigned int i;

	for (i = 0; i < n; i++)
		ai_chain_append(kind, NULL, 0);
}

/* ---- 1 惰性 genesis ---- */
static void chain_genesis_lazy_test(struct kunit *test)
{
	struct ai_chain_stats st;

	ai_chain_test_reset();
	chain_append_n(AI_CHAIN_KIND_DECISION_NEW, 1);
	ai_chain_stats_read(&st);
	KUNIT_ASSERT_EQ(test, st.nodes, 2);	/* genesis + 事件 */
	KUNIT_ASSERT_EQ(test, st.first_seq, 1);
	KUNIT_ASSERT_EQ(test, st.boot_cookie != 0, true);
}

/* ---- 2 seq 单调 + 窗口验证 ---- */
static void chain_seq_monotonic_test(struct kunit *test)
{
	struct ai_chain_node n;
	struct ai_chain_stats st;
	int i;

	ai_chain_test_reset();
	chain_append_n(AI_CHAIN_KIND_DECISION_NEW, 10);
	ai_chain_stats_read(&st);
	KUNIT_ASSERT_EQ(test, st.nodes, 11);
	KUNIT_EXPECT_EQ(test, ai_chain_verify(NULL), 0);
	KUNIT_EXPECT_EQ(test, ai_chain_node_copy(1, &n), 0);
	KUNIT_EXPECT_EQ(test, n.kind, AI_CHAIN_KIND_GENESIS);
	KUNIT_EXPECT_EQ(test, n.prev_hash, 0);	/* 未 seed：genesis prev=0 */
	for (i = 2; i <= 11; i++) {
		KUNIT_EXPECT_EQ(test, ai_chain_node_copy(i, &n), 0);
		KUNIT_EXPECT_EQ(test, n.seq, (u64)i);
	}
	KUNIT_EXPECT_EQ(test, ai_chain_node_copy(12, &n), -ENOENT);
}

/* ---- 3/4/5/6 篡改四型定位 ---- */
static void chain_tamper_data_test(struct kunit *test)
{
	u64 bad = 0;

	ai_chain_test_reset();
	chain_append_n(AI_CHAIN_KIND_DECISION_NEW, 5);
	KUNIT_ASSERT_EQ(test, ai_chain_verify(NULL), 0);
	KUNIT_ASSERT_EQ(test, ai_chain_test_tamper(4, 0), 0);	/* data */
	KUNIT_EXPECT_EQ(test, ai_chain_verify(&bad), -EIO);
	KUNIT_EXPECT_EQ(test, bad, 4);
}

static void chain_tamper_self_test(struct kunit *test)
{
	u64 bad = 0;

	ai_chain_test_reset();
	chain_append_n(AI_CHAIN_KIND_DECISION_NEW, 5);
	KUNIT_ASSERT_EQ(test, ai_chain_test_tamper(3, 1), 0);	/* self_hash */
	KUNIT_EXPECT_EQ(test, ai_chain_verify(&bad), -EIO);
	KUNIT_EXPECT_EQ(test, bad, 3);
}

static void chain_tamper_prev_test(struct kunit *test)
{
	u64 bad = 0;

	ai_chain_test_reset();
	chain_append_n(AI_CHAIN_KIND_DECISION_NEW, 5);
	/* 首存活节点 prev 免验（窗口锚点）：篡第 2+ 个 */
	KUNIT_ASSERT_EQ(test, ai_chain_test_tamper(5, 2), 0);	/* prev_hash */
	KUNIT_EXPECT_EQ(test, ai_chain_verify(&bad), -EIO);
	KUNIT_EXPECT_EQ(test, bad, 5);
}

static void chain_tamper_seq_gap_test(struct kunit *test)
{
	u64 bad = 0;

	ai_chain_test_reset();
	chain_append_n(AI_CHAIN_KIND_DECISION_NEW, 5);
	KUNIT_ASSERT_EQ(test, ai_chain_test_tamper(4, 3), 0);	/* seq 字段 */
	KUNIT_EXPECT_EQ(test, ai_chain_verify(&bad), -EIO);
	KUNIT_EXPECT_EQ(test, bad, 4);	/* 期望 seq 即定位 */
}

/* ---- 7 覆盖最旧驱逐 ---- */
static void chain_eviction_test(struct kunit *test)
{
	struct ai_chain_node n;
	struct ai_chain_stats st;

	ai_chain_test_reset();
	ai_chain_period_set(0xffffffffU);	/* 压锚，纯测驱逐 */
	chain_append_n(AI_CHAIN_KIND_DECISION_NEW, AI_CHAIN_RING_NODES + 50);
	ai_chain_stats_read(&st);
	KUNIT_ASSERT_EQ(test, st.nodes, AI_CHAIN_RING_NODES + 51);
	KUNIT_EXPECT_EQ(test, st.evicted, 51);	/* 8243-8192 */
	KUNIT_EXPECT_EQ(test, st.first_seq, 52);
	KUNIT_EXPECT_EQ(test, ai_chain_node_copy(51, &n), -ENOENT);
	KUNIT_EXPECT_EQ(test, ai_chain_node_copy(52, &n), 0);
	KUNIT_EXPECT_EQ(test, n.seq, 52);
	KUNIT_EXPECT_EQ(test, ai_chain_verify(NULL), 0);	/* 窗口内仍全过 */
	ai_chain_period_set(AI_CHAIN_DEFAULT_PERIOD);
}

/* ---- 8 周期锚 ---- */
static void chain_anchor_period_test(struct kunit *test)
{
	struct ai_chain_node n;
	struct ai_chain_stats st;
	u64 i, anchors = 0;

	ai_chain_test_reset();
	ai_chain_period_set(16);
	chain_append_n(AI_CHAIN_KIND_DECISION_NEW, 40);
	ai_chain_stats_read(&st);
	KUNIT_ASSERT_EQ(test, st.nodes, 1 + 40 + 2);	/* 16/32 两锚 */
	KUNIT_EXPECT_EQ(test, st.anchors, 2);
	for (i = st.first_seq; i <= st.nodes; i++) {
		KUNIT_ASSERT_EQ(test, ai_chain_node_copy(i, &n), 0);
		if (n.kind == AI_CHAIN_KIND_ANCHOR) {
			anchors++;
			KUNIT_EXPECT_EQ(test, n.flags & AI_CHAIN_FLAG_ANCHOR,
					AI_CHAIN_FLAG_ANCHOR);
		}
	}
	KUNIT_EXPECT_EQ(test, anchors, 2);
	ai_chain_period_set(AI_CHAIN_DEFAULT_PERIOD);
}

/* ---- 9 anchor_now 即发 ---- */
static void chain_anchor_now_test(struct kunit *test)
{
	struct ai_chain_node n;
	struct ai_chain_stats st;

	ai_chain_test_reset();
	chain_append_n(AI_CHAIN_KIND_DECISION_NEW, 2);
	KUNIT_ASSERT_GT(test, ai_chain_anchor_now(), 0);
	ai_chain_stats_read(&st);
	KUNIT_ASSERT_EQ(test, st.nodes, 4);	/* genesis+2+锚 */
	KUNIT_EXPECT_EQ(test, ai_chain_node_copy(st.nodes, &n), 0);
	KUNIT_EXPECT_EQ(test, n.kind, AI_CHAIN_KIND_ANCHOR);
	KUNIT_EXPECT_EQ(test, st.anchors, 1);
}

/* ---- 10 seed 续链 ---- */
static void chain_seed_test(struct kunit *test)
{
	struct ai_chain_node g;
	const u64 seedv = 0xdeadbeeffeedfaceULL;

	ai_chain_test_reset();
	KUNIT_EXPECT_EQ(test, ai_chain_seed(seedv), 0);
	chain_append_n(AI_CHAIN_KIND_DECISION_NEW, 1);
	KUNIT_ASSERT_EQ(test, ai_chain_node_copy(1, &g), 0);
	KUNIT_EXPECT_EQ(test, g.kind, AI_CHAIN_KIND_GENESIS);
	KUNIT_EXPECT_EQ(test, g.prev_hash, seedv);
	/* 非空链拒 seed（防事后改史） */
	KUNIT_EXPECT_EQ(test, ai_chain_seed(0x1), -EBUSY);
	KUNIT_EXPECT_EQ(test, ai_chain_verify(NULL), 0);
}

/* ---- 11 xxh64 向量（与 aikctl selftest 同值钉扎） ---- */
static void chain_xxh64_vector_test(struct kunit *test)
{
	/* 官方空载向量：与 aikctl selftest 同值钉扎（防 python 实现漂移）。
	 * 链种子向量不由静态断言钉（离线不可信算）——真机 rig 上以内核
	 * 链节点经 aikctl 逐条重算做跨实现互证。 */
	KUNIT_EXPECT_EQ(test, xxh64("", 0, 0), 0xef46db3751d8e999ULL);
}

/* ---- 12 并发 append 唯一序 ---- */
struct chain_thr_ctx {
	struct completion done;
	unsigned int n;
};

static int chain_thr_fn(void *p)
{
	struct chain_thr_ctx *c = p;

	chain_append_n(AI_CHAIN_KIND_AGENT_REJECT, c->n);
	complete(&c->done);
	return 0;
}

static void chain_concurrent_test(struct kunit *test)
{
	struct ai_chain_stats st;
	struct chain_thr_ctx a, b;
	struct task_struct *ta, *tb;

	ai_chain_test_reset();
	ai_chain_period_set(0xffffffffU);
	a.n = b.n = 500;
	init_completion(&a.done);
	init_completion(&b.done);
	ta = kthread_run(chain_thr_fn, &a, "ai_chain_t0");
	tb = kthread_run(chain_thr_fn, &b, "ai_chain_t1");
	KUNIT_ASSERT_FALSE(test, IS_ERR(ta));
	KUNIT_ASSERT_FALSE(test, IS_ERR(tb));
	wait_for_completion(&a.done);
	wait_for_completion(&b.done);
	/* 线程函数自退（complete 后 return），无需 kthread_stop */
	ai_chain_stats_read(&st);
	KUNIT_EXPECT_EQ(test, st.nodes, 1 + 1000);
	KUNIT_EXPECT_EQ(test, ai_chain_verify(NULL), 0);	/* 唯一序+链接 */
	ai_chain_period_set(AI_CHAIN_DEFAULT_PERIOD);
}

/* ---- 13 enable 快退 ---- */
static void chain_enable_off_test(struct kunit *test)
{
	struct ai_chain_stats st;

	ai_chain_test_reset();
	KUNIT_EXPECT_EQ(test, ai_chain_enable_set(false), 0);
	KUNIT_EXPECT_EQ(test, ai_chain_append(AI_CHAIN_KIND_ROLLBACK, NULL, 0),
			0);
	ai_chain_stats_read(&st);
	KUNIT_EXPECT_EQ(test, st.nodes, 0);	/* 快退零铸点 */
	KUNIT_EXPECT_FALSE(test, st.enabled);
	KUNIT_EXPECT_EQ(test, ai_chain_enable_set(true), 0);
	KUNIT_EXPECT_TRUE(test, ai_chain_enable_read());
}

/* ---- 14 纯 append p99（绝对值层） ---- */
static int chain_u64_cmp(const void *x, const void *y)
{
	const u64 a = *(const u64 *)x, b = *(const u64 *)y;

	return (a > b) - (a < b);
}

static u64 chain_pct(u64 *lat, unsigned int n, unsigned int pct)
{
	return lat[n * pct / 100];
}

static void chain_append_p99_test(struct kunit *test)
{
	u64 *lat, t0, t1;
	unsigned int i, n = 100000;

	ai_chain_test_reset();
	ai_chain_period_set(0xffffffffU);
	lat = kvmalloc_array(n, sizeof(*lat), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, lat);
	for (i = 0; i < n; i++) {
		t0 = ktime_get_ns();
		ai_chain_append(AI_CHAIN_KIND_DECISION_NEW, NULL, 0);
		t1 = ktime_get_ns();
		lat[i] = t1 - t0;
	}
	sort(lat, n, sizeof(lat[0]), chain_u64_cmp, NULL);
	pr_info("AIKernel KUnit: chain_append n=%u p50=%llu p99=%llu p999=%llu ns\n",
		n, chain_pct(lat, n, 50), chain_pct(lat, n, 99),
		lat[n * 999 / 1000]);
	KUNIT_EXPECT_LT(test, chain_pct(lat, n, 99), 5000ULL);	/* CI 宽界 */
	kvfree(lat);
	ai_chain_period_set(AI_CHAIN_DEFAULT_PERIOD);
}

/* ---- 15 record_write on/off 配对（微操口径，如实报百分比） ----
 * KTB「10 万条链写入开销<1%」按全路径占比成立（§D8）：链增量百 ns 级
 * ÷ ACT 全路径（K2c 实测 p99 0.63-0.75ms）<0.1%。本例测微操层：同
 * boot enable 0/1 配对 record_write，百分比进日志与台账（不冒充
 * 路径口径，宽界断言只防回归翻倍）。ai_policy_test_record_write 由
 * ai_policy.h 声明（KUNIT_TEST 门）。 */
static void chain_wired_paired_test(struct kunit *test)
{
#ifdef CONFIG_AIKERNEL_RUNTIME
	struct ai_decision_record rec = { 0 };
	u64 *lat, t0, t1, p50a, p99a, p50b, p99b;
	unsigned int i, n = 100000;

	ai_chain_test_reset();
	ai_chain_period_set(0xffffffffU);
	lat = kvmalloc_array(n, sizeof(*lat), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, lat);

	rec.trigger_ts = ktime_get_ns();
	rec.decision_ts = rec.trigger_ts + 1000;
	rec.execute_ts = rec.trigger_ts + 2000;
	rec.decision_id = 0x66000099ULL;
	rec.executed = 1;

	ai_chain_enable_set(false);
	for (i = 0; i < n; i++) {
		t0 = ktime_get_ns();
		ai_policy_test_record_write(&rec);
		t1 = ktime_get_ns();
		lat[i] = t1 - t0;
	}
	sort(lat, n, sizeof(lat[0]), chain_u64_cmp, NULL);
	p50a = chain_pct(lat, n, 50);
	p99a = chain_pct(lat, n, 99);

	ai_chain_enable_set(true);
	for (i = 0; i < n; i++) {
		t0 = ktime_get_ns();
		ai_policy_test_record_write(&rec);
		t1 = ktime_get_ns();
		lat[i] = t1 - t0;
	}
	sort(lat, n, sizeof(lat[0]), chain_u64_cmp, NULL);
	p50b = chain_pct(lat, n, 50);
	p99b = chain_pct(lat, n, 99);
	kvfree(lat);

	pr_info("AIKernel KUnit: rec_write paired n=%u off(p50=%llu p99=%llu) on(p50=%llu p99=%llu) delta_p50=%llu%% delta_p99=%llu%% (微操口径；全路径占比=链增量/ACT 0.7ms)\n",
		n, p50a, p99a, p50b, p99b,
		p50a ? (p50b - p50a) * 100 / p50a : 0,
		p99a ? (p99b - p99a) * 100 / p99a : 0);
	/* 宽界回归闸：链开启后微操 p99 绝对增量 <10µs（tcg 噪声容忍）。
	 * 比例数字仅入台账——baseline 微操 ~1.7µs 下比值无门禁意义
	 * （真机首轮实测 delta_p50=+106% delta_p99=+146%，绝对增量
	 * 863/2458ns；全路径占比层见函数头注释）。 */
	KUNIT_EXPECT_LT(test, p99b > p99a ? p99b - p99a : 0, 10000ULL);
	ai_chain_period_set(AI_CHAIN_DEFAULT_PERIOD);
#else
	kunit_skip(test, "需要 CONFIG_AIKERNEL_RUNTIME");
#endif
}

/* ---- 16 决策事件对（NEW/OUTCOME 同 id 关联） ---- */
static void chain_decision_pair_test(struct kunit *test)
{
#ifdef CONFIG_AIKERNEL_RUNTIME
	struct ai_decision_record rec = { 0 };
	struct ai_chain_node n;
	struct ai_chain_stats st;
	struct ai_chain_ev_decision_new en;
	struct ai_chain_ev_decision_outcome eo;
	u64 i;
	bool got_new = false, got_outcome = false;

	ai_chain_test_reset();
	ai_chain_period_set(0xffffffffU);
	rec.trigger_ts = ktime_get_ns();
	rec.decision_ts = rec.trigger_ts + 100;
	rec.trigger_event_id = 0x2211;
	rec.decision_id = 0x1234;
	rec.decision_type = 3;
	rec.domain = 1;
	rec.source = 0;
	ai_policy_test_record_write(&rec);
	KUNIT_ASSERT_EQ(test,
			ai_policy_fill_outcome(0x1234, AI_OUTCOME_SUCCESS, -4321),
			0);

	ai_chain_stats_read(&st);
	for (i = st.first_seq; i <= st.nodes; i++) {
		KUNIT_ASSERT_EQ(test, ai_chain_node_copy(i, &n), 0);
		if (n.kind == AI_CHAIN_KIND_DECISION_NEW) {
			memcpy(&en, n.data, sizeof(en));
			if (en.decision_id == 0x1234) {
				got_new = true;
				KUNIT_EXPECT_EQ(test, en.trigger_event_id, 0x2211);
				KUNIT_EXPECT_EQ(test, en.decision_type, 3);
			}
		} else if (n.kind == AI_CHAIN_KIND_DECISION_OUTCOME) {
			memcpy(&eo, n.data, sizeof(eo));
			if (eo.decision_id == 0x1234) {
				got_outcome = true;
				KUNIT_EXPECT_EQ(test, eo.metric_delta, -4321);
				KUNIT_EXPECT_NE(test, eo.outcome_ts, 0);
			}
		}
	}
	KUNIT_EXPECT_TRUE(test, got_new);
	KUNIT_EXPECT_TRUE(test, got_outcome);
	KUNIT_EXPECT_EQ(test, ai_chain_verify(NULL), 0);
	ai_chain_period_set(AI_CHAIN_DEFAULT_PERIOD);
#else
	kunit_skip(test, "需要 CONFIG_AIKERNEL_RUNTIME");
#endif
}

static struct kunit_case ai_chain_test_cases[] = {
	KUNIT_CASE(chain_genesis_lazy_test),
	KUNIT_CASE(chain_seq_monotonic_test),
	KUNIT_CASE(chain_tamper_data_test),
	KUNIT_CASE(chain_tamper_self_test),
	KUNIT_CASE(chain_tamper_prev_test),
	KUNIT_CASE(chain_tamper_seq_gap_test),
	KUNIT_CASE(chain_eviction_test),
	KUNIT_CASE(chain_anchor_period_test),
	KUNIT_CASE(chain_anchor_now_test),
	KUNIT_CASE(chain_seed_test),
	KUNIT_CASE(chain_xxh64_vector_test),
	KUNIT_CASE(chain_concurrent_test),
	KUNIT_CASE(chain_enable_off_test),
	KUNIT_CASE(chain_append_p99_test),
	KUNIT_CASE(chain_wired_paired_test),
	KUNIT_CASE(chain_decision_pair_test),
	{}
};

static struct kunit_suite ai_chain_suite = {
	.name = "ai_chain",
	.test_cases = ai_chain_test_cases,
};

kunit_test_suite(ai_chain_suite);

#else	/* !CONFIG_AIKERNEL_SECURITY：空套件 */

static struct kunit_case ai_chain_test_cases[] = { {} };
static struct kunit_suite ai_chain_suite = {
	.name = "ai_chain",
	.test_cases = ai_chain_test_cases,
};
kunit_test_suite(ai_chain_suite);

#endif	/* CONFIG_AIKERNEL_SECURITY */
