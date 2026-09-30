// SPDX-License-Identifier: GPL-2.0
/*
 * ai_proc.c - AIKernel 进程/线程管理 A 轨：分类槽表 + Hook（Prompt 12）
 *
 * 本文件由原 ai_proc.c（1907 行）拆分而来，函数体逐字保留。
 * 职责一句话：4096 槽进程分类槽表（pid 哈希线性探测，spinlock）与
 * ai_proc_*_hook 空实现（fork 分类 / exec 预测 / futex / 信号，原样放行 +
 * 计数）以及 ai_proc_query/ai_proc_stats 查询接口。
 *
 * B 轨（第5/6/15类遥测）已拆分至：ai_proc_input.c（用户输入）、
 * ai_proc_syscall.c（syscall 遥测）、ai_proc_telemetry.c（exec/进程/信号）、
 * ai_proc_user.c（用户行为）、ai_proc_sampler.c（周期采样器 + init）；
 * 模块内部共享符号见 ai_proc_internal.h；对外接口 ai_proc.h 保持不变。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/cgroup.h>
#include <linux/sort.h>
#include <linux/sched/deadline.h>
#include <linux/input-event-codes.h>
#include "ai_types.h"
#include "ai_proc.h"
#include "ai_control.h"

#ifdef CONFIG_AIKERNEL_TELEMETRY
#include "ai_telemetry.h"
#endif

/* ==================================================================
 * A 轨：进程分类槽表
 * ================================================================== */

#ifdef CONFIG_AIKERNEL_RUNTIME

#define AI_PROC_SLOT_NR  4096

static struct ai_proc_slot ai_proc_slots[AI_PROC_SLOT_NR];
static DEFINE_SPINLOCK(ai_proc_slot_lock);
static u32 ai_proc_slot_gen;

static struct ai_proc_stats ai_proc_stats_core;

static inline int ai_slot_hash(int pid)
{
	return ((unsigned int)pid) & (AI_PROC_SLOT_NR - 1);
}

/* 查找（调用方持锁）：返回槽索引或 -1 */
static int ai_slot_find_locked(int pid)
{
	int i, idx = ai_slot_hash(pid);

	for (i = 0; i < AI_PROC_SLOT_NR; i++) {
		struct ai_proc_slot *s = &ai_proc_slots[(idx + i) & (AI_PROC_SLOT_NR - 1)];

		if (!s->alive)
			continue;
		if (s->pid == pid)
			return (idx + i) & (AI_PROC_SLOT_NR - 1);
	}
	return -1;
}

void ai_proc_slot_remove(int pid)
{
	unsigned long flags;
	int idx;

	spin_lock_irqsave(&ai_proc_slot_lock, flags);
	idx = ai_slot_find_locked(pid);
	if (idx >= 0) {
		ai_proc_slots[idx].alive = 0;
		ai_proc_slots[idx].pid = 0;
		ai_proc_stats_core.slot_remove++;
	}
	spin_unlock_irqrestore(&ai_proc_slot_lock, flags);
}
EXPORT_SYMBOL_GPL(ai_proc_slot_remove);

int ai_proc_slot_get(int pid, struct ai_proc_slot *out)
{
	unsigned long flags;
	int idx, rc = AI_ERR_NOT_FOUND;

	if (!out)
		return AI_ERR_INVALID_ARG;
	spin_lock_irqsave(&ai_proc_slot_lock, flags);
	idx = ai_slot_find_locked(pid);
	if (idx >= 0) {
		*out = ai_proc_slots[idx];
		rc = AI_OK;
	}
	spin_unlock_irqrestore(&ai_proc_slot_lock, flags);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_proc_slot_get);

int ai_proc_class_peek(int pid)
{
	unsigned long flags;
	int idx, cls = -2;   /* -2 = 槽未找到（调用方按槽无效回退） */

	/* W3 决策注入热路径专用：trylock 争用即让路（-1），只读 class 单
	 * 字段，临界区远短于 ai_proc_slot_get 的整槽拷贝 */
	if (!spin_trylock_irqsave(&ai_proc_slot_lock, flags))
		return -1;
	idx = ai_slot_find_locked(pid);
	if (idx >= 0 && ai_proc_slots[idx].alive)
		cls = ai_proc_slots[idx].class;
	spin_unlock_irqrestore(&ai_proc_slot_lock, flags);
	return cls;
}
EXPORT_SYMBOL_GPL(ai_proc_class_peek);

/* 插入/更新槽位：更新 app 记录并返回 class */
static u8 ai_slot_put(int pid, u8 cls, bool update_app, const char *path)
{
	unsigned long flags;
	int i, idx, victim = -1;
	u32 best_gen = U32_MAX;
	struct ai_proc_slot *s;
	u64 now = ktime_get_ns();
	u64 now_boot = ktime_get_boottime_ns();

	spin_lock_irqsave(&ai_proc_slot_lock, flags);
	idx = ai_slot_find_locked(pid);
	if (idx >= 0) {
		s = &ai_proc_slots[idx];
		if (update_app) {
			s->app_start_ns = now;
			s->app_start_boot_ns = now_boot;
		}
		if (path)
			strscpy(s->app_path, path, sizeof(s->app_path));
		s->class = cls;
		s->alive = 1;
		s->pid = pid;
		ai_proc_stats_core.slot_update++;
		goto out;
	}

	idx = ai_slot_hash(pid);
	for (i = 0; i < AI_PROC_SLOT_NR; i++) {
		s = &ai_proc_slots[(idx + i) & (AI_PROC_SLOT_NR - 1)];
		if (!s->alive) {
			victim = (idx + i) & (AI_PROC_SLOT_NR - 1);
			break;
		}
		if (s->gen < best_gen) {
			best_gen = s->gen;
			victim = (idx + i) & (AI_PROC_SLOT_NR - 1);
		}
	}
	s = &ai_proc_slots[victim];
	memset(s, 0, sizeof(*s));
	s->pid = pid;
	s->class = cls;
	s->alive = 1;
	s->app_start_ns = now;
	s->app_start_boot_ns = now_boot;
	if (path)
		strscpy(s->app_path, path, sizeof(s->app_path));
	ai_proc_stats_core.slot_insert++;
out:
	s = &ai_proc_slots[(idx >= 0) ? idx : victim];
	s->gen = ++ai_proc_slot_gen;
	spin_unlock_irqrestore(&ai_proc_slot_lock, flags);
	return cls;
}

/* ---- A 轨 Hook（空实现 = 原样放行） ---- */

u8 ai_proc_classify_hook(struct task_struct *p,
			 struct kernel_clone_args *args)
{
	u8 cls = AI_PROC_CLASS_BATCH;
	struct ai_proc_slot parent;

	if (!p)
		return AI_PROC_CLASS_BATCH;
	ai_proc_stats_core.classify_count++;

	if ((args && (args->kthread || args->io_thread)) ||
	    (p->flags & PF_KTHREAD)) {
		cls = AI_PROC_CLASS_KERNEL;
	} else if (ai_proc_slot_get(task_pid_nr(current), &parent) == AI_OK &&
		   parent.alive &&
		   parent.class == AI_PROC_CLASS_INTERACTIVE) {
		/* 交互式父进程 → 子进程继承交互式（用户前台工具树） */
		cls = AI_PROC_CLASS_INTERACTIVE;
	} else if (rt_task(p) || dl_task(p)) {
		cls = AI_PROC_CLASS_AI_LOAD;
	}
	/* 其余 = 批处理（占位启发式，AI 预测后续 Prompt 替换） */

	/* 继承父进程的 app 路径（fork 子进程 = 同一应用实例，app_crash/lifetime 用） */
	return ai_slot_put(task_pid_nr(p), cls, false,
			   parent.alive ? parent.app_path : NULL);
}

void ai_proc_exec_hook(struct task_struct *p, const char *path)
{
	struct ai_proc_slot slot;
	u8 cls;

	if (!p)
		return;
	ai_proc_stats_core.exec_count++;

	if (ai_proc_slot_get(task_pid_nr(p), &slot) == AI_OK)
		cls = slot.class;
	else
		cls = AI_PROC_CLASS_BATCH;

	/* AI 预测：按新程序路径特征微调行为模式（占位启发式） */
	if (path) {
		if (strstr(path, "/bin/sh") || strstr(path, "/bin/bash") ||
		    strstr(path, "/bin/zsh") || strstr(path, "/bin/dash") ||
		    strstr(path, "/usr/bin/vi") || strstr(path, "/usr/bin/top") ||
		    strstr(path, "/usr/bin/less") || strstr(path, "ssh") ||
		    strstr(path, "/usr/bin/env")) {
			cls = AI_PROC_CLASS_INTERACTIVE;
		} else if (strstr(path, "/bin/make") ||
			   strstr(path, "gcc") || strstr(path, "clang") ||
			   strstr(path, "/bin/ld") || strstr(path, "gzip") ||
			   strstr(path, "/usr/bin/find") ||
			   strstr(path, "/usr/bin/grep")) {
			cls = AI_PROC_CLASS_BATCH;
		} else if (strstr(path, "/llm") || strstr(path, "/infer") ||
			   strstr(path, "/tensorrt") || strstr(path, "torch")) {
			cls = AI_PROC_CLASS_AI_LOAD;
		}
	}
	/* 更新槽表并刷新 app 启动记录 */
	ai_slot_put(task_pid_nr(p), cls, true, path);
}

int ai_proc_futex_hook(struct task_struct *p, u32 addr, u32 val)
{
	ai_proc_stats_core.futex_count++;
	return 0;   /* 原逻辑放行；AI 优先级调整决策表后续 Prompt 填充 */
}

int ai_proc_signal_hook(int sig, struct task_struct *target,
			struct kernel_siginfo *info)
{
	ai_proc_stats_core.signal_count++;
	return 0;   /* 原逻辑放行；AI 信号过滤/降权决策表后续 Prompt 填充 */
}

int ai_proc_query(int pid, struct ai_proc_info *out)
{
	struct ai_proc_slot slot;
	int rc;

	if (!out)
		return AI_ERR_INVALID_ARG;
	ai_proc_stats_core.query_count++;
	rc = ai_proc_slot_get(pid, &slot);
	if (rc != AI_OK)
		return rc;
	out->class = slot.class;
	out->app_start_ns = slot.app_start_ns;
	out->app_start_boot_ns = slot.app_start_boot_ns;
	strscpy(out->app_path, slot.app_path, sizeof(out->app_path));
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_proc_query);

int ai_proc_stats(struct ai_proc_stats *out)
{
	unsigned long flags;

	if (!out)
		return AI_ERR_INVALID_ARG;
	spin_lock_irqsave(&ai_proc_slot_lock, flags);
	*out = ai_proc_stats_core;
	spin_unlock_irqrestore(&ai_proc_slot_lock, flags);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_proc_stats);

#endif /* CONFIG_AIKERNEL_RUNTIME */
