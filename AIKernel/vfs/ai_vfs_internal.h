// SPDX-License-Identifier: GPL-2.0
/*
 * ai_vfs_internal.h - AIKernel vfs/ai_vfs*.c 拆分后模块内部共享声明
 *
 * 仅限 vfs/ai_vfs*.c 各实现文件之间共享的符号：原 ai_vfs.c 内 static 的
 * per-CPU 统计变量（拆分后提升为非 static + DECLARE_PER_CPU）与路径填充/
 * 发射计数工具函数。对外接口仍以 ai_vfs.h 为准；本头文件禁止被
 * ai_vfs*.c 实现文件之外的文件 include。
 */

#ifndef _AIKERNEL_AI_VFS_INTERNAL_H
#define _AIKERNEL_AI_VFS_INTERNAL_H

#include <linux/percpu.h>
#include <linux/path.h>
#include <linux/types.h>
#include "ai_vfs.h"

/* 决策统计 per-CPU 变量（ai_vfs.c 定义，ai_vfs_stats_read 汇总；
 * 命中/溢出计数由 ai_vfs_telemetry*.c 发射路径累计） */
DECLARE_PER_CPU(u64, ai_vfs_dentry_hit);
DECLARE_PER_CPU(u64, ai_vfs_dentry_miss);
DECLARE_PER_CPU(u64, ai_vfs_inode_hit);
DECLARE_PER_CPU(u64, ai_vfs_inode_miss);
DECLARE_PER_CPU(u64, ai_vfs_inode_veto);
DECLARE_PER_CPU(u64, ai_vfs_path_overflow);
DECLARE_PER_CPU(u64, ai_vfs_emitted[AI_VFS_SUB_MAX]);

/*
 * ai_vfs_path_fill() - d_path 全量路径填充（右对齐字符串 memmove 到头部）
 * 返回 false 表示超长/无效（调用方丢弃事件并累计 path_overflow）。
 * noinline：防止被内联进各发射辅助导致 frame-larger-than。
 * （定义在 ai_vfs_telemetry.c；原 ai_vfs.c 内 static，拆分后共享）
 */
bool ai_vfs_path_fill(const struct path *p, char *dst, size_t size);

/* 发射计数（per-CPU ai_vfs_emitted 自增；定义在 ai_vfs_telemetry.c） */
void ai_vfs_emit_done(u16 sub);

#endif /* _AIKERNEL_AI_VFS_INTERNAL_H */
