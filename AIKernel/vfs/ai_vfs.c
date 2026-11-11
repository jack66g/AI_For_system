// SPDX-License-Identifier: GPL-2.0
/*
 * ai_vfs.c - AIKernel VFS 子系统核心（Prompt 08）
 *
 * A 轨：8 个 AI Hook 空实现（原样放行，不改变内核默认行为）+ 决策框架
 *       （dentry 复用预测占位启发式 + 子事件采样率表 + 统计）。
 * B 轨：第7类 文件系统感知 6 子类 24 个发射辅助：
 *       全部 = ai_vfs_sample_take() 采样判定 → 栈上构建 payload（含完整路径）
 *       → ai_telemetry_emit_direct() 直写；路径构建只在采样命中时进行。
 *
 * 铁律（与 ai_block/ai_mm/ai_net 一致）：
 *   - 遥测函数不阻塞、不分配（无 GFP_KERNEL）、无锁（per-CPU ring 直写）；
 *   - CONFIG_AIKERNEL_TELEMETRY=n 时 emit_direct 自动退化为空函数（零开销）；
 *   - 路径 ≥ AI_VFS_PATH_MAX（1024）整条丢弃 + path_overflow 计数（丢弃≠截断）。
 *
 * per-file 读写字节表（vfs_close 的 bytes_read/written 数据源）：
 *   固定 256 槽无分配；open 注册 / read/write 原子累计 / close 取出注销。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/fcntl.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/mount.h>
#include <linux/units.h>
#include <uapi/linux/mount.h>	/* MS_* / MNT_FORCE 常量 */
#include "ai_vfs.h"
#include "ai_vfs_internal.h"

/* ==================================================================
 * 子事件采样率表（定稿，/proc/ai/vfs/rates 可查，ai_vfs_set_sub_rate 可改）
 * ================================================================== */

static u32 ai_vfs_sub_rates[AI_VFS_SUB_MAX] = {
	[AI_VFS_SUB_OPEN]		= 1,	/* 全量 */
	[AI_VFS_SUB_CLOSE]		= 1,	/* 全量 */
	[AI_VFS_SUB_READ]		= 256,	/* 1/256 */
	[AI_VFS_SUB_WRITE]		= 128,	/* 1/128 */
	[AI_VFS_SUB_STAT]		= 64,	/* 1/64 */
	[AI_VFS_SUB_MKDIR]		= 1,	/* 全量 */
	[AI_VFS_SUB_UNLINK]		= 1,	/* 全量 */
	[AI_VFS_SUB_RENAME]		= 1,	/* 全量 */
	[AI_VFS_SUB_SYMLINK]		= 1,	/* 全量 */
	[AI_VFS_SUB_CHMOD]		= 1,	/* 全量 */
	[AI_VFS_SUB_CHOWN]		= 1,	/* 全量 */
	[AI_VFS_SUB_WRITEBACK]		= 32,	/* 1/32 */
	[AI_VFS_SUB_PATH_LOOKUP]	= 64,	/* 1/64 */
	[AI_VFS_SUB_PATH_LOOKUP_CACHE]	= 32,	/* 1/32 */
	[AI_VFS_SUB_MOUNT]		= 1,	/* 全量 */
	[AI_VFS_SUB_UMOUNT]		= 1,	/* 全量 */
	[AI_VFS_SUB_FILE_LOCK_SET]	= 1,	/* 全量 */
	[AI_VFS_SUB_FILE_LOCK_CONFLICT]	= 1,	/* 全量 */
	[AI_VFS_SUB_EPOLL_CREATE]	= 1,	/* 全量 */
	[AI_VFS_SUB_EPOLL_CTL]		= 1,	/* 全量 */
	[AI_VFS_SUB_EPOLL_WAIT]		= 64,	/* 1/64 */
	[AI_VFS_SUB_INOTIFY_EVENT]	= 1,	/* 全量 */
	[AI_VFS_SUB_FS_ERROR]		= 1,	/* 全量 */
	[AI_VFS_SUB_FS_CORRUPTION]	= 1,	/* 全量 */
};

static DEFINE_PER_CPU(u32, ai_vfs_sub_cnt[AI_VFS_SUB_MAX]);

/* ==================================================================
 * 决策统计（per-CPU，ai_vfs_stats_read 汇总）
 * ================================================================== */

DEFINE_PER_CPU(u64, ai_vfs_dentry_hit);
DEFINE_PER_CPU(u64, ai_vfs_dentry_miss);
DEFINE_PER_CPU(u64, ai_vfs_inode_hit);
DEFINE_PER_CPU(u64, ai_vfs_inode_miss);
DEFINE_PER_CPU(u64, ai_vfs_path_overflow);
DEFINE_PER_CPU(u64, ai_vfs_emitted[AI_VFS_SUB_MAX]);

void ai_vfs_stats_read(struct ai_vfs_stats *st)
{
	int cpu, i;

	memset(st, 0, sizeof(*st));
	for_each_possible_cpu(cpu) {
		st->dentry_hit += per_cpu(ai_vfs_dentry_hit, cpu);
		st->dentry_miss += per_cpu(ai_vfs_dentry_miss, cpu);
		st->inode_hit += per_cpu(ai_vfs_inode_hit, cpu);
		st->inode_miss += per_cpu(ai_vfs_inode_miss, cpu);
		st->path_overflow += per_cpu(ai_vfs_path_overflow, cpu);
		for (i = 0; i < AI_VFS_SUB_MAX; i++)
			st->emitted[i] += per_cpu(ai_vfs_emitted[i], cpu);
	}
}
EXPORT_SYMBOL_GPL(ai_vfs_stats_read);

bool ai_vfs_sample_take(u16 sub)
{
	u32 rate;

	if (sub <= 0 || sub >= AI_VFS_SUB_MAX)
		return false;
	rate = READ_ONCE(ai_vfs_sub_rates[sub]);
	if (rate <= 1)
		return rate == 1;
	{
		u32 *cnt = this_cpu_ptr(ai_vfs_sub_cnt);

		cnt[sub]++;
		return (cnt[sub] % rate) == 1;
	}
}
EXPORT_SYMBOL_GPL(ai_vfs_sample_take);

int ai_vfs_set_sub_rate(u16 sub, u32 rate)
{
	if (sub <= 0 || sub >= AI_VFS_SUB_MAX)
		return AI_ERR_INVALID_ARG;
	WRITE_ONCE(ai_vfs_sub_rates[sub], rate);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_vfs_set_sub_rate);

int ai_vfs_get_sub_rate(u16 sub, u32 *rate)
{
	if (sub <= 0 || sub >= AI_VFS_SUB_MAX || !rate)
		return AI_ERR_INVALID_ARG;
	*rate = READ_ONCE(ai_vfs_sub_rates[sub]);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_vfs_get_sub_rate);
