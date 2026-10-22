// SPDX-License-Identifier: GPL-2.0
/*
 * ai_netlink_test.c - NETLINK_AI 订阅生命周期 KUnit 测试（W63）
 *
 * 覆盖 ai_netlink.c 的登记表生命周期修复点：
 *   - AI_CMD_REG 登记表 add 幂等、容量上限（32）、del 幂等；
 *   - NETLINK_URELEASE 通知按 (protocol, netns) 过滤自动摘除死槽
 *     （W63 修复：此前只能靠下一次 push 失败惰性摘除，存在死槽占用
 *      与 portid 复用误投）；
 *   - 空表 push 快速路径不分配 skb、不崩溃。
 *
 * 真实 socket 往返（REG → 内核事件 → UNREG/close → 不再投递）由 qemu
 * 用户态冒烟覆盖（证据：fix-w63/netlink-lifecycle.log）。
 *
 * CONFIG_AIKERNEL_NETLINK=n 时编译为空套件（与 core 测试目录的
 * CONFIG_AIKERNEL_KUNIT_TEST 门控叠加，不产生链接依赖）。
 */

#include <kunit/test.h>
#include <linux/netlink.h>
#include <net/net_namespace.h>
#include "../core/ai_types.h"
#include "../net/ai_netlink.h"

#ifdef CONFIG_AIKERNEL_NETLINK

#define NL_TEST_MAX 32   /* 与 ai_netlink.c 的 AI_NL_REG_MAX 一致 */

static void netlink_registry_test(struct kunit *test)
{
	unsigned int i;

	ai_netlink_test_reg_clear();
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_count(), 0u);

	/* 幂等 add */
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_add(0x1000), AI_OK);
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_add(0x1000), AI_OK);
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_count(), 1u);

	/* 填满 32 槽 */
	for (i = 1; i < NL_TEST_MAX; i++)
		KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_add(0x1000 + i),
				AI_OK);
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_count(),
			(unsigned int)NL_TEST_MAX);

	/* 第 33 个 → BUSY，计数不变 */
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_add(0x2000), AI_ERR_BUSY);
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_count(),
			(unsigned int)NL_TEST_MAX);

	/* 删除中间项；重复删除无副作用 */
	ai_netlink_test_reg_del(0x1005);
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_count(),
			(unsigned int)(NL_TEST_MAX - 1));
	ai_netlink_test_reg_del(0x1005);
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_count(),
			(unsigned int)(NL_TEST_MAX - 1));

	ai_netlink_test_reg_clear();
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_count(), 0u);
}

static void netlink_urelease_cleanup_test(struct kunit *test)
{
	ai_netlink_test_reg_clear();
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_add(0x3000), AI_OK);
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_add(0x3001), AI_OK);

	/* 协议不符：不摘除 */
	ai_netlink_test_urelease(0x3000, NETLINK_USERSOCK, &init_net);
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_count(), 2u);

	/* netns 不符：不摘除 */
	ai_netlink_test_urelease(0x3000, NETLINK_AI, NULL);
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_count(), 2u);

	/* (NETLINK_AI, init_net)：摘除对应 portid，其它保留 */
	ai_netlink_test_urelease(0x3000, NETLINK_AI, &init_net);
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_count(), 1u);

	ai_netlink_test_urelease(0x3001, NETLINK_AI, &init_net);
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_count(), 0u);

	/* 重复通知（socket 已摘除）无副作用 */
	ai_netlink_test_urelease(0x3001, NETLINK_AI, &init_net);
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_count(), 0u);
}

static void netlink_push_empty_test(struct kunit *test)
{
	int rc;

	ai_netlink_test_reg_clear();
	/* 无注册者：只做空表检查，不分配 skb；协议族已创建 → AI_OK。
	 * ai.enabled=0 启动时协议族不存在 → AI_ERR_DISABLED 亦为合法。 */
	rc = ai_netlink_push_event(1, 0, 1, 0, NULL);
	KUNIT_EXPECT_TRUE(test, rc == AI_OK || rc == AI_ERR_DISABLED);
	KUNIT_EXPECT_EQ(test, ai_netlink_test_reg_count(), 0u);
}

static struct kunit_case netlink_test_cases[] = {
	KUNIT_CASE(netlink_registry_test),
	KUNIT_CASE(netlink_urelease_cleanup_test),
	KUNIT_CASE(netlink_push_empty_test),
	{}
};

static struct kunit_suite netlink_test_suite = {
	.name = "ai_netlink",
	.test_cases = netlink_test_cases,
};

#else /* !CONFIG_AIKERNEL_NETLINK */

static struct kunit_suite netlink_test_suite = {
	.name = "ai_netlink",
	.test_cases = {},
};

#endif

kunit_test_suite(netlink_test_suite);
MODULE_LICENSE("GPL v2");
