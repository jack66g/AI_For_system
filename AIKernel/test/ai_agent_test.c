// SPDX-License-Identifier: GPL-2.0
/*
 * ai_agent_test.c - agent 角色注册表/配额准入 KUnit 测试（K3，
 * KERNEL-K3-DESIGN §2/D6）
 *
 * 覆盖：
 *   - 绑定/改绑/一角色一 socket（-EBUSY）/白名单外与 KERNEL=0 拒绑；
 *   - 解绑幂等 + 记账保留（URELEASE 路径同函数 ai_agent_unbind）；
 *   - admit 角色判定三档：绑定命中＞白名单后自报＞0=system 直通；
 *   - 未绑定自报非零：记 actions_total 不耗 win_used（防投毒分离计数）；
 *   - 配额 N/N（超额 100% -EAGAIN）+ failures 计数 + 窗滚动 + 0=不限；
 *   - degraded（cgroup 路径无效）：显式可见 + 仅记账不限制；
 *   - note_cost 归集 / 视图快照（/proc/ai/agents 数据源）/配额 knob
 *     （sysfs 数据源）读写回环。
 *
 * admit 直调真实导出函数：nlmsg_new 构造 skb + 手填 NETLINK_CB.portid
 * （cb 为消息暂存区，无真实 socket 依赖——K1 act2_parse 先例同思路）。
 * CONFIG_AIKERNEL_RUNTIME=n 时编译为空套件（ai_agent.o 不构建）。
 */

#include <kunit/test.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/ai_netlink.h>
#include "../actuators/ai_agent.h"

#ifdef CONFIG_AIKERNEL_RUNTIME

static struct ai_agent_view view_of(struct kunit *test, u32 agent_id)
{
	struct ai_agent_view a;
	unsigned int i;

	for (i = 0; ai_agent_view_get(i, &a) == 0; i++) {
		if (a.id == agent_id)
			return a;
	}
	KUNIT_FAIL(test, "agent id %u 不在视图表中", agent_id);
	memset(&a, 0, sizeof(a));
	return a;
}

static struct sk_buff *agent_test_skb(struct kunit *test, u32 portid)
{
	struct sk_buff *skb = nlmsg_new(64, GFP_KERNEL);

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, skb);
	NETLINK_CB(skb).portid = portid;   /* cb 暂存区直填（无 socket） */
	return skb;
}

static int admit_as(struct kunit *test, u32 portid, u32 msg_agent,
		    u32 *role_out)
{
	struct sk_buff *skb = agent_test_skb(test, portid);
	int rc = ai_agent_admit(skb, msg_agent, role_out);

	kfree_skb(skb);
	return rc;
}

/* ---- 绑定/改绑/占位/拒绑 ---- */

static void agent_bind_rebind_test(struct kunit *test)
{
	ai_agent_test_reset();

	/* 基本绑定 */
	KUNIT_EXPECT_EQ(test, ai_agent_bind(0x5001, AI_AGENT_OCC_CLI, NULL),
			0);
	KUNIT_EXPECT_EQ(test, (u32)view_of(test, AI_AGENT_OCC_CLI).bound, 1u);

	/* 同 socket 同角色重复 REG：幂等（改绑语义退化解旧+占同槽） */
	KUNIT_EXPECT_EQ(test, ai_agent_bind(0x5001, AI_AGENT_OCC_CLI, NULL),
			0);
	KUNIT_EXPECT_EQ(test, (u32)view_of(test, AI_AGENT_OCC_CLI).bound, 1u);

	/* 一角色一 socket：他 portid 占用 → -EBUSY */
	KUNIT_EXPECT_EQ(test, ai_agent_bind(0x5002, AI_AGENT_OCC_CLI, NULL),
			-EBUSY);

	/* 改绑：旧槽让出、新槽占位 */
	KUNIT_EXPECT_EQ(test, ai_agent_bind(0x5001, AI_AGENT_TOOL, NULL), 0);
	KUNIT_EXPECT_EQ(test, (u32)view_of(test, AI_AGENT_OCC_CLI).bound, 0u);
	KUNIT_EXPECT_EQ(test, (u32)view_of(test, AI_AGENT_TOOL).bound, 1u);

	/* 改绑后原角色可被其它 socket 绑定 */
	KUNIT_EXPECT_EQ(test, ai_agent_bind(0x5002, AI_AGENT_OCC_CLI, NULL),
			0);

	/* 拒绑：白名单外 / KERNEL=0（内核自身，防 0 逃逸）/ portid 0 */
	KUNIT_EXPECT_EQ(test, ai_agent_bind(0x5003, 6, NULL), -EINVAL);
	KUNIT_EXPECT_EQ(test, ai_agent_bind(0x5003, 254, NULL), -EINVAL);
	KUNIT_EXPECT_EQ(test, ai_agent_bind(0x5003, 256, NULL), -EINVAL);
	KUNIT_EXPECT_EQ(test, ai_agent_bind(0x5003, AI_AGENT_KERNEL, NULL),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, ai_agent_bind(0, AI_AGENT_TOOL, NULL), -EINVAL);

	/* OTHER=255 合法（逃生舱，如实记账） */
	KUNIT_EXPECT_EQ(test, ai_agent_bind(0x5003, AI_AGENT_OTHER, NULL), 0);
	KUNIT_EXPECT_EQ(test, (u32)view_of(test, AI_AGENT_OTHER).bound, 1u);
}

/* ---- 解绑（UNREG/URELEASE 同路径）+ 记账保留 ---- */

static void agent_unbind_test(struct kunit *test)
{
	struct ai_agent_view a;
	u32 role = 0;

	ai_agent_test_reset();
	KUNIT_EXPECT_EQ(test, ai_agent_bind(0x5101, AI_AGENT_OCC_AI, NULL),
			0);

	/* 绑定期间产生一次记账 */
	KUNIT_EXPECT_EQ(test, admit_as(test, 0x5101, AI_AGENT_KERNEL, &role),
			0);
	KUNIT_EXPECT_EQ(test, role, (u32)AI_AGENT_OCC_AI);   /* 绑定覆盖 */
	KUNIT_EXPECT_EQ(test, view_of(test, AI_AGENT_OCC_AI).actions, 1ULL);

	/* 解绑（幂等）：bound 清零、计数保留（D1 v1：记账至 reboot） */
	ai_agent_unbind(0x5101);
	ai_agent_unbind(0x5101);
	a = view_of(test, AI_AGENT_OCC_AI);
	KUNIT_EXPECT_EQ(test, (u32)a.bound, 0u);
	KUNIT_EXPECT_EQ(test, a.actions, 1ULL);
	KUNIT_EXPECT_STREQ(test, a.cgroup, "");

	/* 解绑后可再绑（槽回收） */
	KUNIT_EXPECT_EQ(test, ai_agent_bind(0x5102, AI_AGENT_OCC_AI, NULL),
			0);
}

/* ---- admit 白名单与 system(0) 旁路 ---- */

static void agent_admit_whitelist_test(struct kunit *test)
{
	u32 role = 99;

	ai_agent_test_reset();

	/* 未绑定+自报 0：system 直通（零记账） */
	KUNIT_EXPECT_EQ(test, admit_as(test, 0x5201, AI_AGENT_KERNEL, &role),
			0);
	KUNIT_EXPECT_EQ(test, role, (u32)AI_AGENT_KERNEL);
	KUNIT_EXPECT_EQ(test, view_of(test, AI_AGENT_KERNEL).actions, 0ULL);

	/* 未绑定自报合法非零：放行+记账（OTHER=255 逃生舱同样合法） */
	KUNIT_EXPECT_EQ(test, admit_as(test, 0x5201, AI_AGENT_APIC, &role),
			0);
	KUNIT_EXPECT_EQ(test, role, (u32)AI_AGENT_APIC);
	KUNIT_EXPECT_EQ(test, admit_as(test, 0x5201, AI_AGENT_OTHER, &role),
			0);
	KUNIT_EXPECT_EQ(test, view_of(test, AI_AGENT_APIC).actions, 1ULL);
	KUNIT_EXPECT_EQ(test, view_of(test, AI_AGENT_OTHER).actions, 1ULL);

	/* 未绑定自报越界：-EINVAL（值域 {0..5,255} 外全拒） */
	KUNIT_EXPECT_EQ(test, admit_as(test, 0x5201, 6, &role), -EINVAL);
	KUNIT_EXPECT_EQ(test, admit_as(test, 0x5201, 254, &role), -EINVAL);
	KUNIT_EXPECT_EQ(test, admit_as(test, 0x5201, 256, &role), -EINVAL);
	KUNIT_EXPECT_EQ(test,
			admit_as(test, 0x5201, 0xFFFFFFFFu, &role), -EINVAL);
}

/* ---- 未绑定自报：记账不耗窗（D1 分离计数防投毒） ---- */

static void agent_unbound_no_window_test(struct kunit *test)
{
	ai_agent_test_reset();
	KUNIT_EXPECT_EQ(test,
			ai_agent_set_actions_per_win(AI_AGENT_OCC_AI, 2), 0);

	/* 未绑定流量 ×5：全放行（配额仅对绑定 socket 执行） */
	{
		unsigned int i;

		for (i = 0; i < 5; i++)
			KUNIT_EXPECT_EQ(test,
				admit_as(test, 0x5300 + i, AI_AGENT_OCC_AI,
					 NULL), 0);
	}
	/* actions_total 记满 5（诚实），win_used 恒 0（不耗绑定方窗） */
	KUNIT_EXPECT_EQ(test, view_of(test, AI_AGENT_OCC_AI).actions, 5ULL);
	KUNIT_EXPECT_EQ(test, view_of(test, AI_AGENT_OCC_AI).win_used, 0ULL);
	KUNIT_EXPECT_EQ(test, view_of(test, AI_AGENT_OCC_AI).failures, 0ULL);
}

/* ---- 配额 N/N（storm 判据内核侧镜像） ---- */

static void agent_quota_admit_test(struct kunit *test)
{
	u32 role = 0;
	int i;

	ai_agent_test_reset();
	KUNIT_EXPECT_EQ(test, ai_agent_bind(0x5401, AI_AGENT_TOOL, NULL), 0);
	KUNIT_EXPECT_EQ(test, ai_agent_set_actions_per_win(AI_AGENT_TOOL, 3),
			0);
	KUNIT_EXPECT_EQ(test, ai_agent_set_win_ms(AI_AGENT_TOOL, 60000), 0);

	/* 3 发放行；自报被绑定角色覆盖 */
	for (i = 0; i < 3; i++) {
		KUNIT_EXPECT_EQ(test,
			admit_as(test, 0x5401, AI_AGENT_APIC, &role), 0);
		KUNIT_EXPECT_EQ(test, role, (u32)AI_AGENT_TOOL);
	}

	/* 第 4 起 100% -EAGAIN（N/N）；含自报 0 的逃逸尝试同样拦 */
	KUNIT_EXPECT_EQ(test,
		admit_as(test, 0x5401, AI_AGENT_KERNEL, &role), -EAGAIN);
	KUNIT_EXPECT_EQ(test, role, (u32)AI_AGENT_TOOL);
	for (i = 0; i < 3; i++)
		KUNIT_EXPECT_EQ(test,
			admit_as(test, 0x5401, AI_AGENT_TOOL, &role),
			-EAGAIN);

	/* 三方一致判据（k3bench storm 同口径）：win_used==limit==actions，
	 * failures==N */
	KUNIT_EXPECT_EQ(test, view_of(test, AI_AGENT_TOOL).win_used, 3ULL);
	KUNIT_EXPECT_EQ(test, view_of(test, AI_AGENT_TOOL).actions, 3ULL);
	KUNIT_EXPECT_EQ(test, view_of(test, AI_AGENT_TOOL).failures, 4ULL);

	/* 0=不限：写回后立即放行 */
	KUNIT_EXPECT_EQ(test, ai_agent_set_actions_per_win(AI_AGENT_TOOL, 0),
			0);
	KUNIT_EXPECT_EQ(test,
		admit_as(test, 0x5401, AI_AGENT_TOOL, &role), 0);
}

/* ---- 滚动窗：不滚（长窗拒）与滚（短窗过窗放行） ---- */

static void agent_window_roll_test(struct kunit *test)
{
	ai_agent_test_reset();
	KUNIT_EXPECT_EQ(test, ai_agent_bind(0x5501, AI_AGENT_APIC, NULL), 0);

	/* 长窗：apw=1，第 2 发在同窗内 → -EAGAIN（确定性） */
	KUNIT_EXPECT_EQ(test, ai_agent_set_actions_per_win(AI_AGENT_APIC, 1),
			0);
	KUNIT_EXPECT_EQ(test, ai_agent_set_win_ms(AI_AGENT_APIC, 60000), 0);
	KUNIT_EXPECT_EQ(test, admit_as(test, 0x5501, AI_AGENT_APIC, NULL), 0);
	KUNIT_EXPECT_EQ(test, admit_as(test, 0x5501, AI_AGENT_APIC, NULL),
			-EAGAIN);

	/* 短窗：apw=1/win_ms=1，>1ms 后过窗重置 → 放行（确定性） */
	KUNIT_EXPECT_EQ(test, ai_agent_set_win_ms(AI_AGENT_APIC, 1), 0);
	msleep(10);
	KUNIT_EXPECT_EQ(test, admit_as(test, 0x5501, AI_AGENT_APIC, NULL), 0);

	/* win_ms=0=不滚窗（等效不限） */
	KUNIT_EXPECT_EQ(test, ai_agent_set_win_ms(AI_AGENT_APIC, 0), 0);
	KUNIT_EXPECT_EQ(test, admit_as(test, 0x5501, AI_AGENT_APIC, NULL), 0);
}

/* ---- degraded：路径无效=显式可见+仅记账不限制 ---- */

static void agent_degraded_test(struct kunit *test)
{
	struct ai_agent_view a;

	ai_agent_test_reset();
	KUNIT_EXPECT_EQ(test,
		ai_agent_bind(0x5601, AI_AGENT_AISTREAMD,
			      "/no/such/ai/cgroup"), 0);

	a = view_of(test, AI_AGENT_AISTREAMD);
	KUNIT_EXPECT_EQ(test, (u32)a.degraded, 1u);
	KUNIT_EXPECT_STREQ(test, a.cgroup, "/no/such/ai/cgroup");

	/* 仅记账不限制：apw=1 连发 2 发全放行、failures 恒 0 */
	KUNIT_EXPECT_EQ(test,
		ai_agent_set_actions_per_win(AI_AGENT_AISTREAMD, 1), 0);
	KUNIT_EXPECT_EQ(test,
		admit_as(test, 0x5601, AI_AGENT_AISTREAMD, NULL), 0);
	KUNIT_EXPECT_EQ(test,
		admit_as(test, 0x5601, AI_AGENT_AISTREAMD, NULL), 0);
	a = view_of(test, AI_AGENT_AISTREAMD);
	KUNIT_EXPECT_EQ(test, a.actions, 2ULL);
	KUNIT_EXPECT_EQ(test, a.failures, 0ULL);
}

/* ---- note_cost 归集 ---- */

static void agent_note_cost_test(struct kunit *test)
{
	ai_agent_test_reset();

	ai_agent_note_cost(AI_AGENT_OCC_CLI, 1000);
	ai_agent_note_cost(AI_AGENT_OCC_CLI, 234);
	KUNIT_EXPECT_EQ(test, view_of(test, AI_AGENT_OCC_CLI).cost_ns,
			1234ULL);

	/* KERNEL=0 归 kernel 槽（内核自身决策成本如实记） */
	ai_agent_note_cost(AI_AGENT_KERNEL, 7);
	KUNIT_EXPECT_EQ(test, view_of(test, AI_AGENT_KERNEL).cost_ns, 7ULL);

	/* 白名单外静默忽略；零成本不记（不产生假条目） */
	ai_agent_note_cost(6, 100);
	ai_agent_note_cost(AI_AGENT_OTHER, 0);
	KUNIT_EXPECT_EQ(test, view_of(test, AI_AGENT_OTHER).cost_ns, 0ULL);
}

/* ---- 视图/枚举（/proc/ai/agents 数据源）+ 配额 knob（sysfs 数据源） ---- */

static void agent_view_and_quota_test(struct kunit *test)
{
	struct ai_agent_view a;
	u32 id = 0, apw = 7, win = 8;
	const char *name = NULL;
	static const u32 ids[] = { 0, 1, 2, 3, 4, 5, 255 };
	static const char * const names[] = {
		"kernel", "occ_cli", "occ_ai", "aistreamd", "apic",
		"tool", "other",
	};
	unsigned int i;

	ai_agent_test_reset();

	/* 枚举顺序与内置名表（7 角色；槽 7 保留不枚举） */
	for (i = 0; i < ARRAY_SIZE(ids); i++) {
		KUNIT_EXPECT_EQ(test, ai_agent_enumerate(i, &id, &name), 0);
		KUNIT_EXPECT_EQ(test, id, ids[i]);
		KUNIT_EXPECT_STREQ(test, name, names[i]);
	}
	KUNIT_EXPECT_EQ(test, ai_agent_enumerate(ARRAY_SIZE(ids), &id, &name),
			-ENOENT);

	/* 快照默认值：0=不限、win_ms 默认 60000、全零计数 */
	KUNIT_EXPECT_EQ(test, ai_agent_view_get(1, &a), 0);
	KUNIT_EXPECT_EQ(test, a.actions_per_win, 0u);
	KUNIT_EXPECT_EQ(test, a.win_ms, 60000u);
	KUNIT_EXPECT_EQ(test, a.actions, 0ULL);

	/* 配额 knob 读写回环（sysfs show/store 的数据后端） */
	KUNIT_EXPECT_EQ(test,
		ai_agent_set_actions_per_win(AI_AGENT_OCC_AI, 7), 0);
	KUNIT_EXPECT_EQ(test, ai_agent_set_win_ms(AI_AGENT_OCC_AI, 8000), 0);
	KUNIT_EXPECT_EQ(test,
		ai_agent_quota_get(AI_AGENT_OCC_AI, &apw, &win), 0);
	KUNIT_EXPECT_EQ(test, apw, 7u);
	KUNIT_EXPECT_EQ(test, win, 8000u);
	a = view_of(test, AI_AGENT_OCC_AI);
	KUNIT_EXPECT_EQ(test, a.actions_per_win, 7u);
	KUNIT_EXPECT_EQ(test, a.win_ms, 8000u);

	/* 越界 id：get -ENOENT / set -EINVAL */
	KUNIT_EXPECT_EQ(test, ai_agent_quota_get(6, &apw, &win), -ENOENT);
	KUNIT_EXPECT_EQ(test, ai_agent_set_win_ms(254, 100), -EINVAL);
}

static struct kunit_case agent_test_cases[] = {
	KUNIT_CASE(agent_bind_rebind_test),
	KUNIT_CASE(agent_unbind_test),
	KUNIT_CASE(agent_admit_whitelist_test),
	KUNIT_CASE(agent_unbound_no_window_test),
	KUNIT_CASE(agent_quota_admit_test),
	KUNIT_CASE(agent_window_roll_test),
	KUNIT_CASE(agent_degraded_test),
	KUNIT_CASE(agent_note_cost_test),
	KUNIT_CASE(agent_view_and_quota_test),
	{}
};

static struct kunit_suite agent_test_suite = {
	.name = "ai_agent",
	.test_cases = agent_test_cases,
};

#else /* !CONFIG_AIKERNEL_RUNTIME */

static struct kunit_suite agent_test_suite = {
	.name = "ai_agent",
	.test_cases = {},
};

#endif

kunit_test_suite(agent_test_suite);
MODULE_LICENSE("GPL v2");
