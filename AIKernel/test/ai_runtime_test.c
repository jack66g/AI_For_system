// SPDX-License-Identifier: GPL-2.0
/*
 * ai_runtime_test.c - AI Runtime 生命周期 KUnit 测试（A 轨 模块15.6）
 *
 * 覆盖：init/destroy 幂等、状态迁移、模型 load/unload/find/enumerate、
 * chat 无模型时报 AI_ERR_NO_MODEL。
 *
 * CONFIG_AIKERNEL=n 时本文件不参与编译（Makefile 门控 obj-$(CONFIG_
 * AIKERNEL_KUNIT_TEST)，该开关 depends on AIKERNEL）→ 无操作零产物；
 * 本文件内部再按 CONFIG_AIKERNEL_RUNTIME 兜底，保证子开关关闭时
 * 编译为空套件。
 */

#include <kunit/test.h>
#include "../core/ai_types.h"
#include "../core/ai_model.h"
#include "../core/ai_runtime.h"

#ifdef CONFIG_AIKERNEL_RUNTIME

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
	KUNIT_EXPECT_GE(test, st, AI_RT_STATE_INIT);
	KUNIT_EXPECT_LE(test, st, AI_RT_STATE_READY);
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

static struct kunit_case runtime_test_cases[] = {
	KUNIT_CASE(runtime_init_destroy_test),
	KUNIT_CASE(runtime_state_test),
	KUNIT_CASE(model_load_unload_test),
	KUNIT_CASE(chat_no_model_test),
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
