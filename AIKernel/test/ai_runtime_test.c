// SPDX-License-Identifier: GPL-2.0
/*
 * ai_runtime_test.c - AI Runtime 生命周期 KUnit 测试（A 轨 模块15.6）
 *
 * 覆盖：init/destroy 幂等、状态迁移、模型 load/unload/find/enumerate、
 * chat 无模型时报 AI_ERR_NO_MODEL；W49 追加模型生命周期并发契约：
 *   - load 期间模型对读者不可见（LOADING），ops->load 返回后才发布 LOADED；
 *   - load 失败回滚干净（无残留注册表项、state=ERROR）；
 *   - 重名拒绝；
 *   - 在途 infer 持引用时 unload 阻塞，引用释放后才调 ops->unload；
 *   - destroy 逐模型执行 unload（K2）。
 *
 * K6（KERNEL-K6-DESIGN D2/D4）追加：决策模型 A/B 切换（arm/confirm/
 * 冒烟失败拒切/-ETIME 回退 builtin 启发式）；「首个 think 模型」旧语义
 * 对齐「active 指针默认=builtin decide」新语义（既有用例只对齐不删）。
 * 对施工 A 的接口形态假设（switch 三 API/budget 全局 helper/enumerate
 * 扩展出参/ops->infer 增 budget_ns 形参）见各段注释与施工报告契约清单。
 *
 * CONFIG_AIKERNEL=n 时本文件不参与编译（Makefile 门控 obj-$(CONFIG_
 * AIKERNEL_KUNIT_TEST)，该开关 depends on AIKERNEL）→ 无操作零产物；
 * 本文件内部再按 CONFIG_AIKERNEL_RUNTIME 兜底，保证子开关关闭时
 * 编译为空套件。
 */

#include <kunit/test.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ktime.h>
#include <linux/unaligned.h>
#include "../core/ai_types.h"
#include "../core/ai_model.h"
#include "../core/ai_runtime.h"

#ifdef CONFIG_AIKERNEL_RUNTIME

/* 枚举扫描上限（仅测试用；运行时注册表容量 16） */
#define TEST_ENUM_SCAN_MAX 64

static void runtime_init_destroy_test(struct kunit *test)
{
	int rc;

	/* 先 destroy 再 init：验证 init 幂等（boot 时已初始化过） */
	ai_runtime_destroy();
	rc = ai_runtime_init();
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	/* 二次 init 幂等 */
	rc = ai_runtime_init();
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	/* destroy 幂等 */
	ai_runtime_destroy();
	ai_runtime_destroy();

	/* 恢复：重新 init，保证后续 boot 流程（sysfs/procfs 创建）正常 */
	rc = ai_runtime_init();
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
}

static void runtime_state_test(struct kunit *test)
{
	int st;

	ai_runtime_init();
	st = ai_runtime_get_state();
	KUNIT_EXPECT_EQ(test, st, AI_RT_STATE_READY);
	ai_runtime_destroy();
	st = ai_runtime_get_state();
	KUNIT_EXPECT_EQ(test, st, AI_RT_STATE_DOWN);
	ai_runtime_init();   /* 恢复 */
}

static void model_load_unload_test(struct kunit *test)
{
	static struct ai_model m;
	static const struct ai_model_ops ops = {
		.load   = NULL,   /* 无加载动作（仅注册） */
		.unload = NULL,
		.infer  = NULL,
		.think  = NULL,
	};
	int id, rc;

	memset(&m, 0, sizeof(m));
	strscpy(m.name, "kunit-test-model", sizeof(m.name));
	m.version = 1;
	m.source = 0;
	m.ops = &ops;

	rc = ai_model_load(&m);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_GE(test, (int)m.id, 1);
	KUNIT_EXPECT_EQ(test, (int)m.state, AI_MODEL_STATE_LOADED);

	id = ai_model_find("kunit-test-model");
	KUNIT_EXPECT_GE(test, id, 1);
	KUNIT_EXPECT_EQ(test, id, (int)m.id);

	/* enumerate 应能枚举到该模型（K6：出参扩展六项，此处不取传 NULL） */
	{
		char name[AI_MAX_NAME_LEN];
		u32 ver = 0, src = 0, st = 0;

		rc = ai_model_enumerate(0, name, &ver, &src, &st,
					NULL, NULL, NULL, NULL, NULL, NULL);
		KUNIT_EXPECT_EQ(test, rc, AI_OK);
	}

	rc = ai_model_unload(&m);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	/* 卸载后 find 应失败 */
	id = ai_model_find("kunit-test-model");
	KUNIT_EXPECT_LT(test, id, 0);
}

static void chat_no_model_test(struct kunit *test)
{
	struct ai_inference_request req = { 0 };
	struct ai_inference_result res = { 0 };
	char out[32];
	int rc;

	/* 卸载全部测试模型后，chat 应报 AI_ERR_NO_MODEL */
	ai_model_unload_by_name("kunit-test-model");

	req.model_id = 0xDEAD;   /* 不存在的模型句柄 */
	req.input = "hello";
	req.input_len = 5;
	req.output = out;
	req.output_len = sizeof(out);

	rc = ai_runtime_chat(&req, &res);
	KUNIT_EXPECT_EQ(test, rc, AI_ERR_NO_MODEL);
}

/* ---- W49：load 可见性（K3） ---- */

static bool vis_find_seen;
static bool vis_enumerate_seen;
static int vis_infer_rc;

static int vis_load(struct ai_model *model)
{
	char name[AI_MAX_NAME_LEN];
	char dummy_in[4] = { 0 };
	char dummy_out[4];
	size_t out_len = sizeof(dummy_out);
	u32 ver, src, st;
	unsigned int i;

	vis_find_seen = ai_model_find(model->name) >= 1;

	vis_enumerate_seen = false;
	for (i = 0; i < TEST_ENUM_SCAN_MAX; i++) {
		if (ai_model_enumerate(i, name, &ver, &src, &st,
				       NULL, NULL, NULL, NULL, NULL,
				       NULL) != AI_OK)
			break;
		if (strcmp(name, model->name) == 0) {
			vis_enumerate_seen = true;
			break;
		}
	}

	vis_infer_rc = ai_runtime_model_infer_by_name(model->name,
						      dummy_in, sizeof(dummy_in),
						      dummy_out, &out_len,
						      NULL, 0);
	return AI_OK;
}

static void model_load_visibility_test(struct kunit *test)
{
	static struct ai_model m;
	static const struct ai_model_ops ops = {
		.load = vis_load,
	};
	int rc;

	memset(&m, 0, sizeof(m));
	strscpy(m.name, "kunit-vis-model", sizeof(m.name));
	m.version = 1;
	m.ops = &ops;

	vis_find_seen = true;
	vis_enumerate_seen = true;
	vis_infer_rc = AI_OK;

	rc = ai_model_load(&m);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	/* ops->load 执行期间：LOADING 不入读侧视图 */
	KUNIT_EXPECT_FALSE(test, vis_find_seen);
	KUNIT_EXPECT_FALSE(test, vis_enumerate_seen);
	KUNIT_EXPECT_EQ(test, vis_infer_rc, AI_ERR_NOT_FOUND);

	/* ops->load 返回后：发布 LOADED，读者可见 */
	KUNIT_EXPECT_EQ(test, (int)m.state, AI_MODEL_STATE_LOADED);
	KUNIT_EXPECT_GE(test, ai_model_find("kunit-vis-model"), 1);

	KUNIT_EXPECT_EQ(test, ai_model_unload(&m), AI_OK);
	KUNIT_EXPECT_LT(test, ai_model_find("kunit-vis-model"), 0);
}

/* ---- W49：load 失败回滚 ---- */

static int fail_load(struct ai_model *model)
{
	return AI_ERR_GENERIC;
}

static bool enumerate_has_name(const char *want)
{
	char name[AI_MAX_NAME_LEN];
	unsigned int i;

	for (i = 0; i < 64; i++) {
		u32 ver, src, st;

		if (ai_model_enumerate(i, name, &ver, &src, &st,
				       NULL, NULL, NULL, NULL, NULL,
				       NULL) != AI_OK)
			break;
		if (strcmp(name, want) == 0)
			return true;
	}
	return false;
}

static void model_load_failure_test(struct kunit *test)
{
	static struct ai_model m;
	static const struct ai_model_ops ops = {
		.load = fail_load,
	};
	int rc;

	memset(&m, 0, sizeof(m));
	strscpy(m.name, "kunit-fail-model", sizeof(m.name));
	m.version = 1;
	m.ops = &ops;

	rc = ai_model_load(&m);
	KUNIT_EXPECT_EQ(test, rc, AI_ERR_GENERIC);

	/* 失败后：注册表无残留、状态 ERROR、读者不可见 */
	KUNIT_EXPECT_LT(test, ai_model_find("kunit-fail-model"), 0);
	KUNIT_EXPECT_FALSE(test, enumerate_has_name("kunit-fail-model"));
	KUNIT_EXPECT_EQ(test, (int)m.state, AI_MODEL_STATE_ERROR);

	/* 失败后可修正并重新装载（同一描述符） */
	m.ops = NULL;
	rc = ai_model_load(&m);
	KUNIT_EXPECT_EQ(test, rc, AI_ERR_INVALID_ARG);   /* ops 必填校验 */
}

/* ---- W49：重名 ---- */

static void model_duplicate_name_test(struct kunit *test)
{
	static struct ai_model m1, m2;
	static const struct ai_model_ops ops = { .load = NULL };
	int rc;

	memset(&m1, 0, sizeof(m1));
	memset(&m2, 0, sizeof(m2));
	strscpy(m1.name, "kunit-dup-model", sizeof(m1.name));
	strscpy(m2.name, "kunit-dup-model", sizeof(m2.name));
	m1.version = 1;
	m2.version = 2;
	m1.ops = &ops;
	m2.ops = &ops;

	KUNIT_EXPECT_EQ(test, ai_model_load(&m1), AI_OK);
	rc = ai_model_load(&m2);
	KUNIT_EXPECT_EQ(test, rc, AI_ERR_INVALID_ARG);

	/* 首模型不受影响 */
	KUNIT_EXPECT_EQ(test, ai_model_find("kunit-dup-model"), (int)m1.id);

	KUNIT_EXPECT_EQ(test, ai_model_unload(&m1), AI_OK);

	/* 名字释放后可重新装载 */
	KUNIT_EXPECT_EQ(test, ai_model_load(&m2), AI_OK);
	KUNIT_EXPECT_EQ(test, ai_model_find("kunit-dup-model"), (int)m2.id);
	KUNIT_EXPECT_EQ(test, ai_model_unload(&m2), AI_OK);
}

/* ---- W49：在途推理引用 vs unload 阻塞（K4/K5） ---- */

static struct completion ref_infer_entered;
static struct completion ref_infer_gate;
static struct completion ref_infer_done;
static struct completion ref_unload_done;
static atomic_t ref_unload_calls;
static atomic_t ref_infer_rc;

/* K6 集成勘误：A 冻结 ops->infer 6 参签名（预算走 trampoline 读全局），
 * mock 回落 6 参（不消费预算） */
static int ref_infer(struct ai_model *model, const void *input, size_t in_len,
		     void *output, size_t *out_len, u64 *latency_ns)
{
	complete(&ref_infer_entered);
	wait_for_completion(&ref_infer_gate);
	memcpy(output, "ok", 2);
	*out_len = 2;
	return AI_OK;
}

static int ref_unload(struct ai_model *model)
{
	atomic_inc(&ref_unload_calls);
	return AI_OK;
}

struct ref_thread_arg {
	struct ai_model *model;
};

static int ref_infer_thread(void *arg)
{
	struct ref_thread_arg *a = arg;
	struct ai_inference_request req = { 0 };
	struct ai_inference_result res;
	char out[8];
	int rc;

	req.id = 0x55;
	req.model_id = a->model->id;
	req.input = "in";
	req.input_len = 2;
	req.output = out;
	req.output_len = sizeof(out);
	rc = ai_runtime_chat(&req, &res);
	atomic_set(&ref_infer_rc, rc);
	complete(&ref_infer_done);
	return 0;
}

static int ref_unload_thread(void *arg)
{
	struct ref_thread_arg *a = arg;

	ai_model_unload(a->model);
	complete(&ref_unload_done);
	return 0;
}

static void model_refcount_unload_test(struct kunit *test)
{
	static struct ai_model m;
	static const struct ai_model_ops ops = {
		.infer  = ref_infer,
		.unload = ref_unload,
	};
	static struct ref_thread_arg arg;
	struct task_struct *t1, *t2;
	unsigned long left;

	memset(&m, 0, sizeof(m));
	strscpy(m.name, "kunit-ref-model", sizeof(m.name));
	m.version = 1;
	m.ops = &ops;

	init_completion(&ref_infer_entered);
	init_completion(&ref_infer_gate);
	init_completion(&ref_infer_done);
	init_completion(&ref_unload_done);
	atomic_set(&ref_unload_calls, 0);
	atomic_set(&ref_infer_rc, AI_ERR_GENERIC);

	KUNIT_ASSERT_EQ(test, ai_model_load(&m), AI_OK);
	arg.model = &m;

	/* 读者进入 infer 并持引用（infer 内阻塞） */
	t1 = kthread_run(ref_infer_thread, &arg, "kunit-ref-infer");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, t1);
	left = wait_for_completion_timeout(&ref_infer_entered, HZ);
	KUNIT_ASSERT_GT(test, left, 0UL);

	/* unload：先退册（find 立即不可见），但在途引用未归零前必须阻塞 */
	t2 = kthread_run(ref_unload_thread, &arg, "kunit-ref-unload");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, t2);

	/* 等 unload 线程完成退册（find 变 NOT_FOUND）再断言其阻塞在引用上；
	 * 不能假设 kthread_run 返回后线程已运行。 */
	{
		unsigned int i;

		for (i = 0; i < 200; i++) {
			if (ai_model_find("kunit-ref-model") < 0)
				break;
			msleep(1);
		}
	}
	KUNIT_EXPECT_LT(test, ai_model_find("kunit-ref-model"), 0);
	KUNIT_EXPECT_EQ(test, wait_for_completion_timeout(&ref_unload_done,
							  msecs_to_jiffies(100)),
			0UL);
	KUNIT_EXPECT_EQ(test, atomic_read(&ref_unload_calls), 0);

	/* 释放读者：unload 完成，ops->unload 恰好调用一次 */
	complete(&ref_infer_gate);
	left = wait_for_completion_timeout(&ref_infer_done, HZ);
	KUNIT_EXPECT_GT(test, left, 0UL);
	left = wait_for_completion_timeout(&ref_unload_done, HZ);
	KUNIT_EXPECT_GT(test, left, 0UL);
	KUNIT_EXPECT_EQ(test, atomic_read(&ref_unload_calls), 1);
	KUNIT_EXPECT_EQ(test, atomic_read(&ref_infer_rc), AI_OK);
	KUNIT_EXPECT_EQ(test, (int)m.state, AI_MODEL_STATE_UNLOADED);
}

/* ---- W63：callback unregister 等待在途回调（SRCU，priv 释放安全） ---- */

static struct completion cb_entered;
static struct completion cb_gate;
static struct completion cb_unreg_done;
static int cb_unreg_rc;
static atomic_t cb_calls;

static int cb_infer(struct ai_model *model, const void *input, size_t in_len,
		    void *output, size_t *out_len, u64 *latency_ns)
{
	/* 立即返回：回调在 infer 返回后执行并阻塞在 cb_gate */
	memcpy(output, "ok", 2);
	*out_len = 2;
	return AI_OK;
}

static void kunit_runtime_cb(struct ai_inference_result *res, void *priv)
{
	atomic_inc(&cb_calls);
	complete(&cb_entered);
	wait_for_completion(&cb_gate);
}

static int cb_unreg_thread(void *arg)
{
	cb_unreg_rc = ai_runtime_callback_unregister(kunit_runtime_cb);
	complete(&cb_unreg_done);
	return 0;
}

static void cb_cleanup_action(void *unused)
{
	/* 异常路径兜底：放行回调，再注销（幂等） */
	complete(&cb_gate);
	complete(&ref_infer_gate);
	ai_runtime_callback_unregister(kunit_runtime_cb);
}

static void callback_unregister_sync_test(struct kunit *test)
{
	static struct ai_model m;
	static const struct ai_model_ops ops = {
		.infer = cb_infer,
	};
	static struct ref_thread_arg arg;
	struct task_struct *t1, *t2;

	ai_runtime_init();
	kunit_add_action(test, cb_cleanup_action, NULL);

	memset(&m, 0, sizeof(m));
	strscpy(m.name, "kunit-cb-model", sizeof(m.name));
	m.version = 1;
	m.ops = &ops;

	init_completion(&ref_infer_entered);
	init_completion(&ref_infer_gate);
	init_completion(&ref_infer_done);
	init_completion(&cb_entered);
	init_completion(&cb_gate);
	init_completion(&cb_unreg_done);
	atomic_set(&cb_calls, 0);
	atomic_set(&ref_infer_rc, AI_ERR_GENERIC);
	cb_unreg_rc = AI_ERR_GENERIC;

	KUNIT_ASSERT_EQ(test,
			ai_runtime_callback_register(kunit_runtime_cb, NULL),
			AI_OK);
	KUNIT_ASSERT_EQ(test, ai_model_load(&m), AI_OK);
	arg.model = &m;

	/* chat 线程进入 infer → 返回后执行回调并阻塞在 cb_gate */
	t1 = kthread_run(ref_infer_thread, &arg, "kunit-cb-chat");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, t1);
	KUNIT_ASSERT_GT(test,
			wait_for_completion_timeout(&cb_entered, HZ), 0UL);

	/* 回调在途：unregister 必须阻塞（synchronize_srcu），100ms 不返回 */
	t2 = kthread_run(cb_unreg_thread, NULL, "kunit-cb-unreg");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, t2);
	KUNIT_EXPECT_EQ(test,
			wait_for_completion_timeout(&cb_unreg_done,
						    msecs_to_jiffies(100)),
			0UL);

	/* 放行回调 → unregister 返回，chat 完成 */
	complete(&cb_gate);
	KUNIT_ASSERT_GT(test,
			wait_for_completion_timeout(&cb_unreg_done, HZ), 0UL);
	KUNIT_EXPECT_EQ(test, cb_unreg_rc, AI_OK);
	KUNIT_ASSERT_GT(test,
			wait_for_completion_timeout(&ref_infer_done, HZ), 0UL);
	KUNIT_EXPECT_EQ(test, atomic_read(&cb_calls), 1);
	KUNIT_EXPECT_EQ(test, atomic_read(&ref_infer_rc), AI_OK);

	/* 已注销：再次推理不再触发回调（ref_infer 的 gate 已放行） */
	init_completion(&ref_infer_gate);
	complete(&ref_infer_gate);
	{
		struct ai_inference_request req = { 0 };
		struct ai_inference_result res;
		char out[8];

		req.model_id = m.id;
		req.input = "in";
		req.input_len = 2;
		req.output = out;
		req.output_len = sizeof(out);
		KUNIT_EXPECT_EQ(test, ai_runtime_chat(&req, &res), AI_OK);
	}
	KUNIT_EXPECT_EQ(test, atomic_read(&cb_calls), 1);

	KUNIT_EXPECT_EQ(test, ai_model_unload(&m), AI_OK);
}

/* ---- W49：destroy 逐模型 unload（K2） ---- */

static atomic_t destroy_unload_calls;

static int destroy_unload(struct ai_model *model)
{
	atomic_inc(&destroy_unload_calls);
	return AI_OK;
}

static void runtime_destroy_unloads_models_test(struct kunit *test)
{
	static struct ai_model m;
	static const struct ai_model_ops ops = {
		.unload = destroy_unload,
	};
	int rc;

	memset(&m, 0, sizeof(m));
	strscpy(m.name, "kunit-destroy-model", sizeof(m.name));
	m.version = 1;
	m.ops = &ops;

	atomic_set(&destroy_unload_calls, 0);
	KUNIT_ASSERT_EQ(test, ai_model_load(&m), AI_OK);

	ai_runtime_destroy();

	/* 模型资源被逐个卸载（含内置 decide 模型），注册表清空 */
	KUNIT_EXPECT_EQ(test, atomic_read(&destroy_unload_calls), 1);
	KUNIT_EXPECT_LT(test, ai_model_find("kunit-destroy-model"), 0);
	KUNIT_EXPECT_EQ(test, ai_runtime_get_state(), AI_RT_STATE_DOWN);

	/* 恢复 Runtime，后续 boot 流程依赖 READY */
	rc = ai_runtime_init();
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_GE(test, ai_model_find("decide"), 1);

	/* K6 对齐（只增不删）：active 指针新语义下重 init 后 active 默认
	 * =builtin decide（旧「首个 think 模型」语义的默认态等价物），
	 * think 立即可用（decide 直通：sense 载荷原样透传 domain/value）。 */
	{
		struct ai_sense_input sense;
		struct ai_think_result res;
		struct ai_sense_decision d;

		memset(&sense, 0, sizeof(sense));
		sense.ts = ktime_get_ns();
		memset(&d, 0, sizeof(d));
		d.domain = 1;
		d.decision_type = 1;
		d.confidence = 100;
		d.value = 42;
		memcpy(sense.data, &d, sizeof(d));
		sense.data_len = sizeof(d);
		rc = ai_runtime_think(&sense, &res);
		KUNIT_EXPECT_EQ(test, rc, AI_OK);
		KUNIT_EXPECT_EQ(test, res.decision_data[0], 42ULL);
		/* model_version 跟随 active（=builtin decide，出厂 v1） */
		KUNIT_EXPECT_EQ(test, res.model_version, 1u);
	}
}

/* ---- K6（KERNEL-K6-DESIGN D4）：决策模型 A/B 切换 ---- */

/*
 * 契约（施工 A 接口形态；对不齐处以集成期契约为准并记施工报告）：
 *   int ai_runtime_model_switch_arm(const char *name, u64 *token);
 *     目标必须 LOADED 且冒烟推理（固定微输入）过 → arm 单槽切换窗，
 *     成功回填非零 token；armed 再 arm → 负错误（K2c 单槽诚实拒）；
 *   int ai_runtime_model_switch_confirm(u64 token);
 *     失配/过期 token → 负错误且 active 不动；成功 → active 指针翻转
 *     （RCU 发布），旧模型 refcount 观察窗保活；
 *   int ai_runtime_switch_observe(unsigned int n);
 *     观察窗记账/健康评估入口，空窗/窗内均返回 AI_OK。
 * enumerate 扩展出参 slot 语义：0=无槽，1=A（active），2=B（arm 待切）。
 */

/* 测试用最小 AIKWMDL1 模型字节流（单层 in_dim→1，线性，W[0][0]=0.5，
 * 其余权重/偏置全 0——Q31 精确合法；构造手法同 ai_mlp_test.c） */
static u8 *sw_build_tiny_model(u32 in_dim, size_t *out_len)
{
	size_t len = 24 + ((size_t)in_dim + 1) * 4;
	u8 *buf = kmalloc(len, GFP_KERNEL);

	if (!buf)
		return NULL;
	memcpy(buf, "AIKWMDL1", 8);
	put_unaligned_le32(1, buf + 8);          /* n_layers */
	put_unaligned_le32(in_dim, buf + 12);
	put_unaligned_le32(1, buf + 16);         /* out_dim=1 */
	put_unaligned_le32(0, buf + 20);         /* act=linear */
	memset(buf + 24, 0, len - 24);
	put_unaligned_le32(0x3F000000u, buf + 24);   /* W[0][0]=0.5 */
	*out_len = len;
	return buf;
}

static int sw_find_slot(const char *want, u32 *slot)
{
	char name[AI_MAX_NAME_LEN];
	unsigned int i;

	for (i = 0; i < 64; i++) {
		u32 ver, src, st, s;
		u64 h, by, in_n, lat, to;

		if (ai_model_enumerate(i, name, &ver, &src, &st,
				       &h, &by, &in_n, &lat, &to,
				       &s) != AI_OK)
			break;
		if (strcmp(name, want) == 0) {
			*slot = s;
			return 0;
		}
	}
	return -1;
}

/* 切换全链：未知模型拒/单槽拒/失配 confirm 拒且不生效/正确 token 生效
 * （slot 翻转）/观察窗入口冒烟/卸载曾 active 模型后 think 不悬空 */
static void runtime_model_switch_test(struct kunit *test)
{
	u8 *buf;
	size_t len;
	u64 tok = 0, tok2 = 0;
	u32 slot = 0xFFFFFFFFu;
	struct ai_sense_input sense;
	struct ai_think_result res;
	struct ai_sense_decision d;
	int rc;

	KUNIT_ASSERT_EQ(test, ai_runtime_init(), AI_OK);

	buf = sw_build_tiny_model(1, &len);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buf);
	KUNIT_ASSERT_GE(test,
			ai_mlp_model_create("kunit-sw-a", buf, len), 1);

	/* 未知模型 arm 拒 */
	rc = ai_runtime_model_switch_arm("no-such-model", &tok2);
	KUNIT_EXPECT_LT(test, rc, 0);

	/* 合法模型 arm：token 非零 */
	tok = 0;
	rc = ai_runtime_model_switch_arm("kunit-sw-a", &tok);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_NE(test, tok, 0ULL);

	/* 单槽：armed 再 arm 拒（照 K2c blast token 模式） */
	rc = ai_runtime_model_switch_arm("kunit-sw-a", &tok2);
	KUNIT_EXPECT_LT(test, rc, 0);

	/* 无 confirm 不生效：目标模型仍无槽 */
	rc = sw_find_slot("kunit-sw-a", &slot);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, slot, 0u);

	/* 失配 token confirm 拒 */
	tok2 = tok ^ 1;
	rc = ai_runtime_model_switch_confirm(tok2);
	KUNIT_EXPECT_LT(test, rc, 0);

	/* 正确 token confirm：active 翻转（A 槽让位 builtin decide） */
	rc = ai_runtime_model_switch_confirm(tok);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	rc = sw_find_slot("kunit-sw-a", &slot);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, slot, 1u);
	rc = sw_find_slot("decide", &slot);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_NE(test, slot, 1u);

	/* 观察窗记账入口冒烟（窗口内不炸、AI_OK） */
	rc = ai_runtime_switch_observe(10);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	/* 卸载曾 active 的模型：决策面不得悬空（think 走 builtin 兜底） */
	KUNIT_EXPECT_EQ(test, ai_model_unload_by_name("kunit-sw-a"),
			AI_OK);
	memset(&sense, 0, sizeof(sense));
	sense.ts = ktime_get_ns();
	memset(&d, 0, sizeof(d));
	d.confidence = 100;
	memcpy(sense.data, &d, sizeof(d));
	sense.data_len = sizeof(d);
	rc = ai_runtime_think(&sense, &res);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);

	kfree(buf);
}

/* 冒烟失败拒切：in_dim=1024 的合法模型对任何固定微输入（<4KB）过不了
 * 维度检查 → arm 拒（-ETIME 同族路径同走此拒），active 不动 */
static void runtime_model_switch_smoke_fail_test(struct kunit *test)
{
	u8 *buf;
	size_t len;
	u64 tok = 999;
	u32 slot = 0xFFFFFFFFu;
	int rc;

	KUNIT_ASSERT_EQ(test, ai_runtime_init(), AI_OK);

	buf = sw_build_tiny_model(1024, &len);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buf);
	KUNIT_ASSERT_GE(test,
			ai_mlp_model_create("kunit-sw-fail", buf, len), 1);

	rc = ai_runtime_model_switch_arm("kunit-sw-fail", &tok);
	KUNIT_EXPECT_LT(test, rc, 0);
	KUNIT_EXPECT_EQ(test, tok, 999ULL);   /* 拒切不回填 token */

	/* active 不动：失败模型无槽 */
	rc = sw_find_slot("kunit-sw-fail", &slot);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, slot, 0u);

	KUNIT_EXPECT_EQ(test, ai_model_unload_by_name("kunit-sw-fail"),
			AI_OK);
	kfree(buf);
}

/* D2：-ETIME 回退——active=测试模型 + 全局预算压 1ns，think 不得把
 * -ETIME 透给调用方（回退 builtin 启发式路径），预算原值恢复 */
static void runtime_model_switch_etime_fallback_test(struct kunit *test)
{
	u8 *buf;
	size_t len;
	u64 tok = 0, old_budget;
	struct ai_sense_input sense;
	struct ai_think_result res;
	struct ai_sense_decision d;
	int rc;

	KUNIT_ASSERT_EQ(test, ai_runtime_init(), AI_OK);

	buf = sw_build_tiny_model(1, &len);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buf);
	KUNIT_ASSERT_GE(test,
			ai_mlp_model_create("kunit-sw-et", buf, len), 1);

	rc = ai_runtime_model_switch_arm("kunit-sw-et", &tok);
	KUNIT_ASSERT_EQ(test, rc, AI_OK);
	rc = ai_runtime_model_switch_confirm(tok);
	KUNIT_ASSERT_EQ(test, rc, AI_OK);

	/* 全局预算 1ns：模型侧推理（含冒烟/think 内 infer）必 -ETIME，
	 * runtime think 侧按 D2 回退 builtin 启发式 → 调用方见 AI_OK */
	old_budget = ai_model_infer_budget_ns_get();
	ai_model_infer_budget_ns_set(1);

	memset(&sense, 0, sizeof(sense));
	sense.ts = ktime_get_ns();
	memset(&d, 0, sizeof(d));
	d.confidence = 100;
	memcpy(sense.data, &d, sizeof(d));
	sense.data_len = sizeof(d);
	rc = ai_runtime_think(&sense, &res);
	KUNIT_EXPECT_EQ(test, rc, AI_OK);
	KUNIT_EXPECT_EQ(test, res.status, AI_OK);

	/* 预算原值恢复（对生产面/后续用例零污染） */
	ai_model_infer_budget_ns_set(old_budget);

	KUNIT_EXPECT_EQ(test, ai_model_unload_by_name("kunit-sw-et"),
			AI_OK);
	kfree(buf);
}

static struct kunit_case runtime_test_cases[] = {
	KUNIT_CASE(runtime_init_destroy_test),
	KUNIT_CASE(runtime_state_test),
	KUNIT_CASE(model_load_unload_test),
	KUNIT_CASE(chat_no_model_test),
	KUNIT_CASE(model_load_visibility_test),
	KUNIT_CASE(model_load_failure_test),
	KUNIT_CASE(model_duplicate_name_test),
	KUNIT_CASE(model_refcount_unload_test),
	KUNIT_CASE(callback_unregister_sync_test),
	KUNIT_CASE(runtime_destroy_unloads_models_test),
	/* K6：A/B 切换置于既有用例后（destroy/init 循环把 active 复位为
	 * 默认 builtin decide，K6 用例从干净态起测） */
	KUNIT_CASE(runtime_model_switch_test),
	KUNIT_CASE(runtime_model_switch_smoke_fail_test),
	KUNIT_CASE(runtime_model_switch_etime_fallback_test),
	{}
};

static struct kunit_suite runtime_test_suite = {
	.name = "ai_runtime",
	.test_cases = runtime_test_cases,
};

#else /* !CONFIG_AIKERNEL_RUNTIME */

static struct kunit_suite runtime_test_suite = {
	.name = "ai_runtime",
	.test_cases = {},
};

#endif

kunit_test_suite(runtime_test_suite);
MODULE_LICENSE("GPL v2");
