// SPDX-License-Identifier: GPL-2.0
/*
 * ai_proc_internal.h - AIKernel core/ai_proc_* 拆分后模块内部共享声明
 *
 * 仅限 core/ai_proc_*.c 各实现文件之间共享的符号：原 ai_proc.c 内 static 的
 * per-CPU 变量与宏，拆分后提升为模块内部可见（非 static + DECLARE_PER_CPU）。
 * 对外接口仍以 ai_proc.h 为准；本头文件禁止被 ai_proc_* 实现文件之外include。
 */

#ifndef _AIKERNEL_AI_PROC_INTERNAL_H
#define _AIKERNEL_AI_PROC_INTERNAL_H

#include <linux/percpu.h>
#include <linux/types.h>
#include "ai_proc.h"

#ifdef CONFIG_AIKERNEL_TELEMETRY
#include "ai_telemetry.h"
#endif

/* syscall 频率/序列 per-CPU 状态（ai_proc_syscall.c 定义，ai_proc_sampler.c 汇总清零） */
#define AI_SYSCALL_NR_MAX  512

DECLARE_PER_CPU(u32[AI_SYSCALL_NR_MAX], ai_syscall_freq);
DECLARE_PER_CPU(u32[64], ai_syscall_seq);
DECLARE_PER_CPU(u16, ai_syscall_seq_n);

/* 大 payload（tty/exec/script 原始数据）per-CPU 暂存区（ai_proc_telemetry.c 定义，
 * ai_proc_input.c / ai_proc_syscall.c / ai_proc_telemetry.c / ai_proc_user.c 共用） */
DECLARE_PER_CPU(u8[AI_TELEMETRY_MAX_DATA_LEN + 128], ai_payload_stage);

#endif /* _AIKERNEL_AI_PROC_INTERNAL_H */
