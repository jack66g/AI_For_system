// SPDX-License-Identifier: GPL-2.0
/*
 * ai_sysfs_internal.h - AIKernel core/ai_sysfs*.c 拆分后模块内部共享声明
 *
 * 仅限 core/ai_sysfs*.c 各实现文件之间共享的符号：原 ai_sysfs.c 内 static 的
 * stats 属性组（拆分后提升为非 static，定义在 ai_sysfs_stats.c，由
 * ai_sysfs.c 的初始化装配到 /sys/kernel/ai/stats/）。
 * 对外接口仍以各子系统公共头为准；本头文件禁止被 ai_sysfs*.c 实现文件
 * 之外的文件 include。
 */

#ifndef _AIKERNEL_AI_SYSFS_INTERNAL_H
#define _AIKERNEL_AI_SYSFS_INTERNAL_H

#include <linux/kobject.h>
#include <linux/sysfs.h>

/* stats/ 目录属性组（定义在 ai_sysfs_stats.c；原 ai_sysfs.c 内 static） */
extern const struct attribute_group ai_stats_group;

#endif /* _AIKERNEL_AI_SYSFS_INTERNAL_H */
