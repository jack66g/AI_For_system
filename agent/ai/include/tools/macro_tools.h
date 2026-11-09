/* SPDX-License-Identifier: GPL-2.0 */
/*
 * macro_tools.h - W78 宏工具：高频组合升格的一等工具（13 件）
 *
 * 分级：R 7 件（psi_snapshot/kernel_ai_healthcheck/disk_hogs/
 *       service_doctor/baseline_diff/sysctl_snapshot/schedule_list）
 *       W1 2 件（model_verify/schedule_remove）
 *       W2 4 件（schedule_create/ip_ban_verified/process_quarantine/
 *               sysctl_restore）
 * 通道：TOOL_CH_MACRO；执行器入口 exec_macro_channel()。
 * 组合复用既有闸门语义：W1/W2 风险照常过 lease D0-D4，写动作走
 * executor 既有实现（exec_netlink_act / exec_sysctl_write / exec_sysfs_dyn）。
 */
#ifndef _AI_MACRO_TOOLS_H
#define _AI_MACRO_TOOLS_H

#include <stddef.h>

/* 纯函数（导出供单测） */
int ai_macro_valid_unit(const char *s);        /* systemd unit 名：[A-Za-z0-9_.@-]{1,64} */
int ai_macro_valid_ip(const char *s);          /* IPv4/IPv6 字面量 */
int ai_macro_valid_cal(const char *s);         /* OnCalendar 表达式（保守字符集） */

/* 执行器入口（executor.c 的 TOOL_CH_MACRO 分发调用） */
int exec_macro_channel(const void *tool, const char *args_json, char **out);

#endif /* _AI_MACRO_TOOLS_H */
