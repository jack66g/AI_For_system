/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ai_accessors.h - AIKernel 门控访问器声明（host 侧最小侵入点）
 *
 * AIKernel 可控参数对内核真实状态的唯一写入口：各 host 文件
 * （kernel/sys.c / kernel/sched/fair.c / mm/backing-dev.c）提供
 * ai_*_get/set 访问器，CONFIG_AIKERNEL_RUNTIME=n 时全部内联为
 * -ENOTSUPP 空桩（零开销零回归）。范式先例：mm/vmscan.c
 * ai_vmscan_swappiness_get/set。
 */

#ifndef _LINUX_AI_ACCESSORS_H
#define _LINUX_AI_ACCESSORS_H

#include <linux/types.h>

struct task_struct;

#ifdef CONFIG_AIKERNEL_RUNTIME

int ai_sys_prlimit_set(struct task_struct *tsk, unsigned int resource,
		       unsigned long cur);
u64 ai_sched_base_slice_get(void);
int ai_sched_base_slice_set_ns(u64 ns);
int ai_bdi_ra_pages_set(unsigned long read_ahead_kb, unsigned long *out_kb);
int ai_bdi_max_ratio_set(unsigned int pct, unsigned int *out_pct);
int ai_vfs_cache_pressure_get(void);
int ai_vfs_cache_pressure_set(int val);

#else /* !CONFIG_AIKERNEL_RUNTIME */

static inline int ai_sys_prlimit_set(struct task_struct *tsk,
				     unsigned int resource, unsigned long cur)
{
	return -ENOTSUPP;
}
static inline u64 ai_sched_base_slice_get(void) { return 0; }
static inline int ai_sched_base_slice_set_ns(u64 ns) { return -ENOTSUPP; }
static inline int ai_bdi_ra_pages_set(unsigned long read_ahead_kb,
				      unsigned long *out_kb)
{
	return -ENOTSUPP;
}
static inline int ai_bdi_max_ratio_set(unsigned int pct,
				       unsigned int *out_pct)
{
	return -ENOTSUPP;
}
static inline int ai_vfs_cache_pressure_get(void) { return 100; }
static inline int ai_vfs_cache_pressure_set(int val) { return -ENOTSUPP; }

#endif /* CONFIG_AIKERNEL_RUNTIME */

#endif /* _LINUX_AI_ACCESSORS_H */
