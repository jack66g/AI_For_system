// SPDX-License-Identifier: GPL-2.0
/*
 * ai_netlink.h - NETLINK_AI 内核内部事件推送接口（W49 ai-6/7）
 *
 * ai_netlink_push_event() 由内核侧事件源（策略执行、模型生命周期等）调用，
 * 向所有通过 AI_CMD_REG 注册的 portid 单播 AI_CMD_EVENT 消息。无注册者时
 * 仅做一次空表检查即返回，不分配 skb。
 *
 * 上下文：可在原子上下文调用（GFP_ATOMIC 分配 + MSG_DONTWAIT 单播），
 * 不睡眠、不持调用方锁等待。注册表本身由 spinlock 保护。
 *
 * w63 生命周期：登记表由 NETLINK_URELEASE 通知清理（socket 关闭/进程退出
 * 自动摘除，防死槽与 portid 复用误投）；push/reply 持 socket 引用发送，
 * 与 ai_netlink_exit() 的 release 无竞争。
 */

#ifndef _AIKERNEL_NET_AI_NETLINK_H
#define _AIKERNEL_NET_AI_NETLINK_H

#include <linux/types.h>
#include <linux/ai_netlink.h>
#include "../core/ai_types.h"

struct net;

/**
 * ai_netlink_push_event() - 向已注册 portid 推送一条异步事件
 * @category: AI_NL_EV_*（1=策略，2=模型）
 * @severity: AI_NL_EV_SEV_*（0/1/2）
 * @event_id: 事件 ID（策略=decision_id，模型=model id）
 * @code: 事件结果（策略=executed 数，模型=1 装载/0 卸载）
 * @param: 参数名/模型名（可 NULL；NUL 结尾，超长截断）
 *
 * 返回 AI_OK（已尝试推送，至少一个注册者或空表均算正常）、
 * AI_ERR_DISABLED（协议族未创建/ai.enabled=0）或负错误码。
 */
#ifdef CONFIG_AIKERNEL_NETLINK
int ai_netlink_push_event(u32 category, u32 severity, u64 event_id,
			  s32 code, const char *param);
#else
static inline int ai_netlink_push_event(u32 category, u32 severity,
					u64 event_id, s32 code, const char *param)
{
	return AI_ERR_DISABLED;
}
#endif

#ifdef CONFIG_AIKERNEL_KUNIT_TEST
/* w63 KUnit 钩子（实现于 ai_netlink.c；测试：ai_netlink_test.c） */
int ai_netlink_test_reg_add(u32 portid);
void ai_netlink_test_reg_del(u32 portid);
unsigned int ai_netlink_test_reg_count(void);
void ai_netlink_test_reg_clear(void);
void ai_netlink_test_urelease(u32 portid, int protocol, struct net *net);
#endif

#endif /* _AIKERNEL_NET_AI_NETLINK_H */
