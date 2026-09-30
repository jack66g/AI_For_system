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

enum ai_vfs_hook_id {
	AI_VFS_HOOK_DCACHE = 0,
	AI_VFS_HOOK_INODE,
	AI_VFS_HOOK_PATH,
	AI_VFS_HOOK_WB,
	AI_VFS_HOOK_EPOLL,
	AI_VFS_HOOK_AIO,
	AI_VFS_HOOK_DAX,
	AI_VFS_HOOK_RW,
	AI_VFS_HOOK_MAX,
};

static DEFINE_PER_CPU(u64, ai_vfs_hook_cnt[AI_VFS_HOOK_MAX]);
static DEFINE_PER_CPU(u64, ai_vfs_dcache_veto);
/* ai_vfs_inode_veto_note()（拆分至 ai_vfs_telemetry.c）递增本变量，须跨文件可见 */
DEFINE_PER_CPU(u64, ai_vfs_inode_veto);
static DEFINE_PER_CPU(u64, ai_vfs_wb_adjusted);
DEFINE_PER_CPU(u64, ai_vfs_dentry_hit);
DEFINE_PER_CPU(u64, ai_vfs_dentry_miss);
DEFINE_PER_CPU(u64, ai_vfs_inode_hit);
DEFINE_PER_CPU(u64, ai_vfs_inode_miss);
DEFINE_PER_CPU(u64, ai_vfs_path_overflow);
DEFINE_PER_CPU(u64, ai_vfs_emitted[AI_VFS_SUB_MAX]);

/* ==================================================================
 * dentry 复用预测表（64 槽，d_name 哈希，EWMA 访问记录）
 * ================================================================== */

#define AI_VFS_REUSE_SZ	64

struct ai_vfs_reuse_ent {
	u32 hash;
	u32 count;			/* 近窗访问次数（封顶 10） */
	u64 last_ms;			/* 最近访问时间戳（ms） */
};

static struct ai_vfs_reuse_ent ai_vfs_reuse_tab[AI_VFS_REUSE_SZ];

static void ai_vfs_reuse_note(struct dentry *dentry)
{
	u32 h = full_name_hash(dentry, dentry->d_name.name,
			       dentry->d_name.len);
	struct ai_vfs_reuse_ent *e = &ai_vfs_reuse_tab[h % AI_VFS_REUSE_SZ];
	u64 now = ktime_get_boot_fast_ns() / NSEC_PER_MSEC;

	if (e->hash != h) {
		e->hash = h;
		e->count = 1;
	} else if (now - e->last_ms > 60000) {
		e->count = 1;		/* 超过 60s 窗口重置 */
	} else if (e->count < 10) {
		e->count++;
	}
	e->last_ms = now;
}

/* ==================================================================
 * A 轨：AI Hook（空实现 = 原样放行）
 * ================================================================== */

bool ai_vfs_dcache_hook(struct dentry *dentry, int op)
{
	this_cpu_inc(ai_vfs_hook_cnt[AI_VFS_HOOK_DCACHE]);
	ai_vfs_reuse_note(dentry);
	/* AI 决策表本步为空：默认允许驱逐（不改变 LRU 顺序/驱逐行为）。
	 * AI 后续经预测分/决策表返回 false 时，调用方走 retain 路径。 */
	return true;
}
EXPORT_SYMBOL_GPL(ai_vfs_dcache_hook);

bool ai_vfs_inode_hook(struct inode *inode)
{
	this_cpu_inc(ai_vfs_hook_cnt[AI_VFS_HOOK_INODE]);
	return true;
}
EXPORT_SYMBOL_GPL(ai_vfs_inode_hook);

int ai_vfs_path_hook(struct dentry *parent, const struct qstr *last,
		     unsigned int flags)
{
	this_cpu_inc(ai_vfs_hook_cnt[AI_VFS_HOOK_PATH]);
	return 0;
}
EXPORT_SYMBOL_GPL(ai_vfs_path_hook);

void ai_vfs_writeback_hook(struct bdi_writeback *wb, long *nr_pages,
			   int reason)
{
	this_cpu_inc(ai_vfs_hook_cnt[AI_VFS_HOOK_WB]);
	/* AI 决策：本步空实现不改 nr_pages */
}
EXPORT_SYMBOL_GPL(ai_vfs_writeback_hook);

int ai_vfs_epoll_hook(struct eventpoll *ep, int maxevents)
{
	this_cpu_inc(ai_vfs_hook_cnt[AI_VFS_HOOK_EPOLL]);
	return 0;
}
EXPORT_SYMBOL_GPL(ai_vfs_epoll_hook);

int ai_vfs_aio_hook(struct kioctx *ctx, const struct iocb *iocb,
			   int rw)
{
	this_cpu_inc(ai_vfs_hook_cnt[AI_VFS_HOOK_AIO]);
	return 0;
}
EXPORT_SYMBOL_GPL(ai_vfs_aio_hook);

void ai_vfs_dax_hook(struct kiocb *iocb, struct iov_iter *iter,
		     bool *prefetch)
{
	this_cpu_inc(ai_vfs_hook_cnt[AI_VFS_HOOK_DAX]);
}
EXPORT_SYMBOL_GPL(ai_vfs_dax_hook);

bool ai_vfs_rw_hook(struct file *file, int rw, loff_t offset, size_t *count)
{
	this_cpu_inc(ai_vfs_hook_cnt[AI_VFS_HOOK_RW]);
	return true;
}
EXPORT_SYMBOL_GPL(ai_vfs_rw_hook);

void ai_vfs_exec_command_hook(struct linux_binprm *bprm)
{
	/* B 轨第5类 exec_command（完整命令行）预留钩子：
	 * 本步空实现，fs/exec.c 接入由后续 Prompt 落地。 */
}
EXPORT_SYMBOL_GPL(ai_vfs_exec_command_hook);

/* ---- 决策框架 ---- */

int ai_vfs_predict_dentry_reuse(struct dentry *dentry, u8 *out_score)
{
	u32 h;
	struct ai_vfs_reuse_ent *e;
	u64 age;
	u8 score;

	if (!out_score)
		return AI_ERR_INVALID_ARG;

	h = full_name_hash(dentry, dentry->d_name.name, dentry->d_name.len);
	e = &ai_vfs_reuse_tab[h % AI_VFS_REUSE_SZ];
	age = ktime_get_boot_fast_ns() / NSEC_PER_MSEC - e->last_ms;

	if (e->hash == h && e->count) {
		/* 占位启发式：近 10s 访问 ≥3 次 → 高复用概率 */
		if (age < 10000 && e->count >= 3)
			score = 80 + min(20u, e->count * 4);
		else if (age < 60000)
			score = 40 + min(40u, e->count * 8);
		else
			score = 5;
	} else {
		score = 5;
	}
	*out_score = score;
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_vfs_predict_dentry_reuse);

void ai_vfs_stats_read(struct ai_vfs_stats *st)
{
	int cpu, i;

	memset(st, 0, sizeof(*st));
	for_each_possible_cpu(cpu) {
		st->dcache_hook_calls += per_cpu(ai_vfs_hook_cnt[0], cpu);
		st->inode_hook_calls += per_cpu(ai_vfs_hook_cnt[1], cpu);
		st->path_hook_calls += per_cpu(ai_vfs_hook_cnt[2], cpu);
		st->writeback_hook_calls += per_cpu(ai_vfs_hook_cnt[3], cpu);
		st->epoll_hook_calls += per_cpu(ai_vfs_hook_cnt[4], cpu);
		st->aio_hook_calls += per_cpu(ai_vfs_hook_cnt[5], cpu);
		st->dax_hook_calls += per_cpu(ai_vfs_hook_cnt[6], cpu);
		st->rw_hook_calls += per_cpu(ai_vfs_hook_cnt[7], cpu);
		st->dcache_ai_veto += per_cpu(ai_vfs_dcache_veto, cpu);
		st->inode_ai_veto += per_cpu(ai_vfs_inode_veto, cpu);
		st->writeback_ai_adjusted += per_cpu(ai_vfs_wb_adjusted, cpu);
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
