/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ai_agent.h - AIKernel agent 角色注册表与配额准入（K3，KERNEL-K3-DESIGN §2）
 *
 * D1 静态槽注册表（core/ai_agent.c）：身份空间=既有 enum ai_agent_id
 * （uapi 冻结零改），零 kmalloc；绑定=AI_CMD_REG 追加 AGENT/CGROUP
 * 属性（一 socket 一角色，重复 REG=改绑，URELEASE/UNREG 解绑）。
 *
 * D3 配额准入：三个 ACT 命令入口统一 ai_agent_admit()（dispatch 内、
 * execute 之前）；角色判定=绑定 portid 命中＞消息属性（白名单后）＞
 * 0=system 直通；超额=-EAGAIN+failures+++limit_hit 遥测（零 ring 写入）。
 *
 * D4/D5 记账面：view_get 供 /proc/ai/agents；quota_* 供
 * /sys/kernel/ai/agents/<name>/{actions_per_win,win_ms}（默认 0=不限，
 * 出厂零行为变化——记账全量开）。
 */

#ifndef _AIKERNEL_AI_AGENT_H
#define _AIKERNEL_AI_AGENT_H

#include <linux/types.h>

struct sk_buff;

/* 角色名/cgroup 路径存储容量（内置枚举名 ≤15+NUL；路径超长拒收不截断
 * ——审计上下文静默变形比拒绝更糟） */
#define AI_AGENT_NAME_LEN	16
#define AI_AGENT_CG_LEN		256

/* /proc/ai/agents 与测试共用的单槽只读快照（D4：全静态原子读，seq_file
 * 单次快照允许极小撕裂，v1 口径） */
struct ai_agent_view {
	u32  id;			/* enum ai_agent_id */
	char name[AI_AGENT_NAME_LEN];	/* 内置枚举名 */
	u8   bound;			/* 1=有 socket 绑定 */
	u8   degraded;			/* 1=cgroup 无效=仅记账不限制 */
	u32  actions_per_win;		/* 0=不限（默认） */
	u32  win_ms;			/* 滚动窗（默认 60000） */
	u64  actions;			/* actions_total（绑定+未绑定自报） */
	u64  cost_ns;			/* 决策+执行耗时累计（note_cost） */
	u64  failures;			/* 超限拒绝次数 */
	u64  win_used;			/* 当前窗动作数（仅绑定方递增） */
	char cgroup[AI_AGENT_CG_LEN];	/* 绑定时申报路径（可空） */
};

#ifdef CONFIG_AIKERNEL_RUNTIME

/**
 * ai_agent_admit() - ACT 命令入口配额准入（D3，热路径零分配零阻塞）
 * @skb: 请求消息（取 NETLINK_CB portid 判绑定）
 * @msg_agent: 消息自报 enum ai_agent_id（v1 ACT 无字段恒 0）
 * @role_out: 出参——生效角色（绑定槽命中＞白名单后自报＞0=system）；
 *   可与 msg_agent 同址（先读后写，绑定角色覆盖自报值）；NULL=不关心
 *
 * 返回 0=放行；-EINVAL=自报值白名单外（未绑定时）；-EAGAIN=超额
 * （failures++ 已计、limit_hit 遥测已发、零 ring 写入——与 blast
 * 拒绝同语义）。未绑定+自报 0=system 快速旁路零记账。
 */
int ai_agent_admit(struct sk_buff *skb, u32 msg_agent, u32 *role_out);

/**
 * ai_agent_bind() - 角色绑定/改绑（REG 慢路径）
 * @portid: 发起方 netlink socket portid（0=内核自身，拒收）
 * @agent_id: 目标角色（enum ai_agent_id 白名单；KERNEL=0 不可绑）
 * @cgroup: 角色申报 cgroup 路径（可 NULL/空=不校验不降级；只读校验
 *   存在性，无效 → degraded=记账不限制，D2）
 *
 * 重复 REG=改绑（先解本 socket 旧角色）；角色被其它 socket 占用
 * -EBUSY；白名单外/KERNEL/portid 0 → -EINVAL。
 */
int ai_agent_bind(u32 portid, u32 agent_id, const char *cgroup);

/* 解绑（UNREG/URELEASE 路径；幂等；记账保留至 reboot，D1 v1） */
void ai_agent_unbind(u32 portid);

/* 落账点成本归集（D3：admit 记数、record 记成本；白名单外静默忽略） */
void ai_agent_note_cost(u32 agent_id, u64 cost_ns);

/* 槽表枚举与快照（procfs/sysfs/测试数据源） */
int ai_agent_view_get(unsigned int index, struct ai_agent_view *out);
int ai_agent_enumerate(unsigned int index, u32 *agent_id,
		       const char **name);
int ai_agent_quota_get(u32 agent_id, u32 *actions_per_win, u32 *win_ms);
int ai_agent_set_actions_per_win(u32 agent_id, u32 val);
int ai_agent_set_win_ms(u32 agent_id, u32 val);

#else /* !CONFIG_AIKERNEL_RUNTIME */

/* 桩（调用方均依赖 RUNTIME，防御性自洽——ai_policy.h 同款口径）：
 * admit 直通、role 原样透传；bind 记 -EINVAL；视图枚举空表。 */
static inline int ai_agent_admit(struct sk_buff *skb, u32 msg_agent,
				 u32 *role_out)
{
	if (role_out)
		*role_out = msg_agent;
	return 0;
}
static inline int ai_agent_bind(u32 portid, u32 agent_id, const char *cg)
{
	return -EINVAL;
}
static inline void ai_agent_unbind(u32 portid) {}
static inline void ai_agent_note_cost(u32 agent_id, u64 cost_ns) {}
static inline int ai_agent_view_get(unsigned int index,
				    struct ai_agent_view *out)
{
	return -ENOENT;
}
static inline int ai_agent_enumerate(unsigned int index, u32 *agent_id,
				     const char **name)
{
	return -ENOENT;
}
static inline int ai_agent_quota_get(u32 agent_id, u32 *actions_per_win,
				     u32 *win_ms)
{
	return -ENOENT;
}
static inline int ai_agent_set_actions_per_win(u32 agent_id, u32 val)
{
	return -EINVAL;
}
static inline int ai_agent_set_win_ms(u32 agent_id, u32 val)
{
	return -EINVAL;
}

#endif /* CONFIG_AIKERNEL_RUNTIME */

#ifdef CONFIG_AIKERNEL_KUNIT_TEST
/* KUnit 钩子（实现于 ai_agent.c；测试：test/ai_agent_test.c）——
 * 槽表复位（仅清运行态；锁/内置名/win_ms 默认值保持 init 状态） */
void ai_agent_test_reset(void);
#endif

#endif /* _AIKERNEL_AI_AGENT_H */
