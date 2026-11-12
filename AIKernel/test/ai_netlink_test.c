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
#include <linux/string.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include "../core/ai_types.h"
#include "../core/ai_policy.h"
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

/* ---- K1：ACT2 nlattr 载荷解析（KERNEL-K1-DESIGN §3/D1；手搓 nlattr
 * 缓冲，NLA_HDRLEN 对齐，无真实 socket 依赖） ---- */

/* 追加一个 attr（payload 定长拷贝；缓冲预清零故 NLA_ALIGN pad 恒 0） */
static u8 *act2_put_attr(u8 *p, int attr, const void *data, int len)
{
	struct nlattr *nla = (struct nlattr *)p;
	int total = NLA_HDRLEN + len;

	nla->nla_type = (u16)attr;
	nla->nla_len = (u16)total;
	memcpy((u8 *)nla + NLA_HDRLEN, data, len);
	return p + NLA_ALIGN(total);
}

/* 全参有效 → ctx 逐字段对值（含 u64 负值 s64/字符串/64B 二进制） */
static void netlink_act2_parse_full_test(struct kunit *test)
{
	u8 buf[512] __aligned(NLA_ALIGNTO);
	u8 *p = buf;
	struct ai_policy_ctx ctx;
	u64 data64[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	u64 u64v;
	u32 u32v;
	s64 s64v;
	u8 u8v;
	int rem, err, ok = 1;
	unsigned int k;

	memset(buf, 0, sizeof(buf));
	u8v = AI_POLICY_DOMAIN_SCHED;
	p = act2_put_attr(p, AI_DEC_ATTR_DOMAIN, &u8v, sizeof(u8v));
	u32v = 2;
	p = act2_put_attr(p, AI_DEC_ATTR_TYPE, &u32v, sizeof(u32v));
	p = act2_put_attr(p, AI_DEC_ATTR_PARAM, "kunit.test.param",
			  sizeof("kunit.test.param"));   /* 含 NUL=17 */
	p = act2_put_attr(p, AI_DEC_ATTR_DATA, data64, sizeof(data64));
	u8v = 100;
	p = act2_put_attr(p, AI_DEC_ATTR_CONFIDENCE, &u8v, sizeof(u8v));
	u32v = 7;
	p = act2_put_attr(p, AI_DEC_ATTR_MODEL_VER, &u32v, sizeof(u32v));
	u64v = 0x0102;
	p = act2_put_attr(p, AI_DEC_ATTR_TRIG_EVID, &u64v, sizeof(u64v));
	u64v = 0x00deadbeefcafe01ULL;
	p = act2_put_attr(p, AI_DEC_ATTR_TRACE_HI, &u64v, sizeof(u64v));
	u64v = 42;
	p = act2_put_attr(p, AI_DEC_ATTR_TRACE_LO, &u64v, sizeof(u64v));
	u64v = 0xab;
	p = act2_put_attr(p, AI_DEC_ATTR_INTENT, &u64v, sizeof(u64v));
	u64v = 77;
	p = act2_put_attr(p, AI_DEC_ATTR_PARENT, &u64v, sizeof(u64v));
	u32v = AI_AGENT_OCC_AI;
	p = act2_put_attr(p, AI_DEC_ATTR_AGENT, &u32v, sizeof(u32v));
	s64v = -1500000;
	p = act2_put_attr(p, AI_DEC_ATTR_EXPECTED, &s64v, sizeof(s64v));
	rem = (int)(p - buf);

	err = ai_nl_act2_parse((struct nlattr *)buf, rem, &ctx);
	KUNIT_EXPECT_EQ(test, err, 0);

	KUNIT_EXPECT_EQ(test, ctx.domain, AI_POLICY_DOMAIN_SCHED);
	KUNIT_EXPECT_EQ(test, (u32)ctx.decision_type, 2u);
	KUNIT_EXPECT_STREQ(test, ctx.param, "kunit.test.param");
	for (k = 0; k < 8; k++)
		if (ctx.decision_data[k] != data64[k])
			ok = 0;
	KUNIT_EXPECT_TRUE(test, ok);
	KUNIT_EXPECT_EQ(test, (u32)ctx.confidence, 100u);
	KUNIT_EXPECT_EQ(test, ctx.model_version, 7u);
	KUNIT_EXPECT_EQ(test, (u32)ctx.trigger_event_id, 0x0102u);
	KUNIT_EXPECT_EQ(test, ctx.trace_hi, 0x00deadbeefcafe01ULL);
	KUNIT_EXPECT_EQ(test, ctx.trace_lo, 42ULL);
	KUNIT_EXPECT_EQ(test, ctx.intent_id, 0xabULL);
	KUNIT_EXPECT_EQ(test, ctx.parent_id, 77ULL);
	KUNIT_EXPECT_EQ(test, ctx.agent_id, (u32)AI_AGENT_OCC_AI);
	KUNIT_EXPECT_EQ(test, ctx.expected, -1500000LL);
	/* 解析器不碰运行时字段（trigger_ts/source 由处理器补） */
	KUNIT_EXPECT_EQ(test, ctx.trigger_ts, 0ULL);
	KUNIT_EXPECT_EQ(test, (u32)ctx.source, 0u);
}

/* 缺必备（无 PARAM / 空载荷）→ -EINVAL */
static void netlink_act2_parse_missing_test(struct kunit *test)
{
	u8 buf[128] __aligned(NLA_ALIGNTO);
	u8 *p = buf;
	struct ai_policy_ctx ctx;
	u32 u32v = 2;
	u8 u8v = 1;
	int rem;

	memset(buf, 0, sizeof(buf));
	p = act2_put_attr(p, AI_DEC_ATTR_DOMAIN, &u8v, sizeof(u8v));
	p = act2_put_attr(p, AI_DEC_ATTR_TYPE, &u32v, sizeof(u32v));
	rem = (int)(p - buf);   /* 缺 PARAM */
	KUNIT_EXPECT_EQ(test,
			ai_nl_act2_parse((struct nlattr *)buf, rem, &ctx),
			-EINVAL);

	/* 空载荷（rem=0）：同样缺必备 → -EINVAL */
	KUNIT_EXPECT_EQ(test, ai_nl_act2_parse(NULL, 0, &ctx), -EINVAL);
}

/* PARAM 超长 / CONFIDENCE=101 / 坏类型（DOMAIN 4B）/ DATA ≠64B
 * → policy 表全拒（负错误码；范围/长度违规具体码归 nlattr.c） */
static void netlink_act2_parse_invalid_test(struct kunit *test)
{
	u8 buf[128] __aligned(NLA_ALIGNTO);
	u8 *p;
	struct ai_policy_ctx ctx;
	u32 u32v = 2;
	u8 u8v = 1, conf101 = 101;
	u64 u64v = 0;
	int rem, err;

	/* PARAM 超长：24 字符 + NUL = 25 > 24（含 NUL 上限） */
	memset(buf, 0, sizeof(buf));
	p = act2_put_attr(buf, AI_DEC_ATTR_DOMAIN, &u8v, sizeof(u8v));
	p = act2_put_attr(p, AI_DEC_ATTR_TYPE, &u32v, sizeof(u32v));
	p = act2_put_attr(p, AI_DEC_ATTR_PARAM,
			  "aaaaaaaaaaaaaaaaaaaaaaaa"/* 24 chars */, 25);
	rem = (int)(p - buf);
	err = ai_nl_act2_parse((struct nlattr *)buf, rem, &ctx);
	KUNIT_EXPECT_LT(test, err, 0);

	/* CONFIDENCE=101（RANGE 0-100 外）→ 拒 */
	memset(buf, 0, sizeof(buf));
	p = act2_put_attr(buf, AI_DEC_ATTR_DOMAIN, &u8v, sizeof(u8v));
	p = act2_put_attr(p, AI_DEC_ATTR_TYPE, &u32v, sizeof(u32v));
	p = act2_put_attr(p, AI_DEC_ATTR_PARAM, "x", 2);
	p = act2_put_attr(p, AI_DEC_ATTR_CONFIDENCE, &conf101,
			  sizeof(conf101));
	rem = (int)(p - buf);
	err = ai_nl_act2_parse((struct nlattr *)buf, rem, &ctx);
	KUNIT_EXPECT_LT(test, err, 0);

	/* 坏类型：DOMAIN 携带 4B 载荷（NLA_U8 期望 1B）→ 拒 */
	memset(buf, 0, sizeof(buf));
	p = act2_put_attr(buf, AI_DEC_ATTR_DOMAIN, &u32v, sizeof(u32v));
	p = act2_put_attr(p, AI_DEC_ATTR_TYPE, &u32v, sizeof(u32v));
	p = act2_put_attr(p, AI_DEC_ATTR_PARAM, "x", 2);
	rem = (int)(p - buf);
	err = ai_nl_act2_parse((struct nlattr *)buf, rem, &ctx);
	KUNIT_EXPECT_LT(test, err, 0);

	/* DATA 长度 ≠64（8B）→ EXACT_LEN 拒 */
	memset(buf, 0, sizeof(buf));
	p = act2_put_attr(buf, AI_DEC_ATTR_DOMAIN, &u8v, sizeof(u8v));
	p = act2_put_attr(p, AI_DEC_ATTR_TYPE, &u32v, sizeof(u32v));
	p = act2_put_attr(p, AI_DEC_ATTR_PARAM, "x", 2);
	p = act2_put_attr(p, AI_DEC_ATTR_DATA, &u64v, sizeof(u64v));
	rem = (int)(p - buf);
	err = ai_nl_act2_parse((struct nlattr *)buf, rem, &ctx);
	KUNIT_EXPECT_LT(test, err, 0);
}

static struct kunit_case netlink_test_cases[] = {
	KUNIT_CASE(netlink_registry_test),
	KUNIT_CASE(netlink_urelease_cleanup_test),
	KUNIT_CASE(netlink_push_empty_test),
	/* K1：ACT2 nlattr 解析（仅追加，既有用例零删改） */
	KUNIT_CASE(netlink_act2_parse_full_test),
	KUNIT_CASE(netlink_act2_parse_missing_test),
	KUNIT_CASE(netlink_act2_parse_invalid_test),
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
