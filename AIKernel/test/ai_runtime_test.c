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

	/* enumerate 应能枚举到该模型 */
	{
		char name[AI_MAX_NAME_LEN];
		u32 ver = 0, src = 0, st = 0;

		rc = ai_model_enumerate(0, name, &ver, &src, &st);
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
		if (ai_model_enumerate(i, name, &ver, &src, &st) != AI_OK)
			break;
		if (strcmp(name, model->name) == 0) {
			vis_enumerate_seen = true;
			break;
		}
	}

	vis_infer_rc = ai_runtime_model_infer_by_name(model->name,
						     dummy_in, sizeof(dummy_in),
						     dummy_out, &out_len, NULL);
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

		if (ai_model_enumerate(i, name, &ver, &src, &st) != AI_OK)
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
