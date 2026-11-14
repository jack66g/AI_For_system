// SPDX-License-Identifier: GPL-2.0
/*
 * ai_net_internal.h - AIKernel net/ai_net*.c 拆分后模块内部共享声明
 *
 * 仅限 net/ai_net*.c 各实现文件之间共享的符号：原 ai_net.c 内 static 的
 * 地址解析辅助（拆分后提升为非 static，定义在 ai_net_telemetry.c）。
 * 对外接口仍以 ai_net.h 为准；本头文件禁止被 ai_net*.c 实现文件之外的
 * 文件 include。
 *
 * 注：payload 采样开关 ai_net_payload_sampling（module_param）仅由
 * ai_net.c 内 ai_net_sample_take() 消费，仍为该文件 static，无需共享。
 */

#ifndef _AIKERNEL_AI_NET_INTERNAL_H
#define _AIKERNEL_AI_NET_INTERNAL_H

struct sock;

#ifdef CONFIG_INET
/*
 * ai_net_sock_addr4() - IPv4 socket 五元组提取（saddr/daddr/sport/dport，可 NULL 跳过）
 * （定义在 ai_net_telemetry.c；原 ai_net.c 内 static，拆分后
 *   由 ai_net_telemetry.c 与 ai_net_scan.c 共享）
 */
void ai_net_sock_addr4(const struct sock *sk, u32 *saddr, u32 *daddr,
		       u16 *sport, u16 *dport);
#endif

#endif /* _AIKERNEL_AI_NET_INTERNAL_H */
