// SPDX-License-Identifier: GPL-2.0
/*
 * ai_vfs_procfs.c - AIKernel /proc/ai/vfs/ VFS 决策统计（Prompt 08）
 *
 * 接口：
 *   stats      R   全部 AI VFS Hook 决策计数 + 缓存命中/未命中 + path_overflow
 *   rates      R   24 个子事件采样率表（0=丢弃 1=全量 N=每 N 条记 1 条）
 *
 * 门控 CONFIG_AIKERNEL_VFS。节点挂载到 /proc/ai/ 根（ai_procfs.c 导出），
 * ai.enabled=0 启动时与既有接口一致不创建（零回归）。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/init.h>
#include "../core/ai_types.h"
#include "ai_vfs.h"

#ifdef CONFIG_AIKERNEL_RUNTIME
#include "../core/ai_startup.h"
#endif

/* ai_procfs.c（CONFIG_AIKERNEL_USRIFACE）导出的 /proc/ai 根节点 */
#ifdef CONFIG_AIKERNEL_USRIFACE
extern struct proc_dir_entry *ai_procfs_get_root(void);
#endif

static const char *ai_vfs_sub_name(int sub)
{
	switch (sub) {
	case AI_VFS_SUB_OPEN:		return "vfs_open";
	case AI_VFS_SUB_CLOSE:		return "vfs_close";
	case AI_VFS_SUB_READ:		return "vfs_read";
	case AI_VFS_SUB_WRITE:		return "vfs_write";
	case AI_VFS_SUB_STAT:		return "vfs_stat";
	case AI_VFS_SUB_MKDIR:		return "vfs_mkdir";
	case AI_VFS_SUB_UNLINK:		return "vfs_unlink";
	case AI_VFS_SUB_RENAME:		return "vfs_rename";
	case AI_VFS_SUB_SYMLINK:	return "vfs_symlink";
	case AI_VFS_SUB_CHMOD:		return "vfs_chmod";
	case AI_VFS_SUB_CHOWN:		return "vfs_chown";
	case AI_VFS_SUB_WRITEBACK:	return "writeback";
	case AI_VFS_SUB_PATH_LOOKUP:	return "path_lookup";
	case AI_VFS_SUB_PATH_LOOKUP_CACHE: return "path_lookup_cache";
	case AI_VFS_SUB_MOUNT:		return "mount";
	case AI_VFS_SUB_UMOUNT:		return "umount";
	case AI_VFS_SUB_FILE_LOCK_SET:	return "file_lock_set";
	case AI_VFS_SUB_FILE_LOCK_CONFLICT: return "file_lock_conflict";
	case AI_VFS_SUB_EPOLL_CREATE:	return "epoll_create";
	case AI_VFS_SUB_EPOLL_CTL:	return "epoll_ctl";
	case AI_VFS_SUB_EPOLL_WAIT:	return "epoll_wait";
	case AI_VFS_SUB_INOTIFY_EVENT:	return "inotify_event";
	case AI_VFS_SUB_FS_ERROR:	return "fs_error";
	case AI_VFS_SUB_FS_CORRUPTION:	return "fs_corruption";
	default:			return "unknown";
	}
}

static int ai_vfs_stats_show(struct seq_file *m, void *v)
{
	struct ai_vfs_stats st;
	u64 total;
	int i;

	ai_vfs_stats_read(&st);

	seq_printf(m, "dcache_hook_calls=%llu\n", st.dcache_hook_calls);
	seq_printf(m, "dcache_ai_veto=%llu\n", st.dcache_ai_veto);
	seq_printf(m, "inode_hook_calls=%llu\n", st.inode_hook_calls);
	seq_printf(m, "inode_ai_veto=%llu\n", st.inode_ai_veto);
	seq_printf(m, "path_hook_calls=%llu\n", st.path_hook_calls);
	seq_printf(m, "writeback_hook_calls=%llu\n", st.writeback_hook_calls);
	seq_printf(m, "writeback_ai_adjusted=%llu\n", st.writeback_ai_adjusted);
	seq_printf(m, "epoll_hook_calls=%llu\n", st.epoll_hook_calls);
	seq_printf(m, "aio_hook_calls=%llu\n", st.aio_hook_calls);
	seq_printf(m, "dax_hook_calls=%llu\n", st.dax_hook_calls);
	seq_printf(m, "rw_hook_calls=%llu\n", st.rw_hook_calls);
	seq_printf(m, "dentry_hit=%llu\n", st.dentry_hit);
	seq_printf(m, "dentry_miss=%llu\n", st.dentry_miss);
	total = st.dentry_hit + st.dentry_miss;
	seq_printf(m, "dentry_hitrate=%u\n",
		   total ? (u32)div_u64(st.dentry_hit * 1000, total) : 0);
	seq_printf(m, "inode_hit=%llu\n", st.inode_hit);
	seq_printf(m, "inode_miss=%llu\n", st.inode_miss);
	total = st.inode_hit + st.inode_miss;
	seq_printf(m, "inode_hitrate=%u\n",
		   total ? (u32)div_u64(st.inode_hit * 1000, total) : 0);
	seq_printf(m, "path_overflow=%llu\n", st.path_overflow);
	seq_printf(m, "emitted:\n");
	for (i = 1; i < AI_VFS_SUB_MAX; i++) {
		if (st.emitted[i])
			seq_printf(m, "  %s=%llu\n", ai_vfs_sub_name(i),
				   st.emitted[i]);
	}
	return 0;
}

static int ai_vfs_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, ai_vfs_stats_show, NULL);
}

static const struct proc_ops ai_vfs_stats_ops = {
	.proc_open    = ai_vfs_stats_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int ai_vfs_rates_show(struct seq_file *m, void *v)
{
	int i;

	for (i = 1; i < AI_VFS_SUB_MAX; i++) {
		u32 rate;

		ai_vfs_get_sub_rate(i, &rate);
		seq_printf(m, "%2d %-22s %u\n", i, ai_vfs_sub_name(i), rate);
	}
	return 0;
}

static int ai_vfs_rates_open(struct inode *inode, struct file *file)
{
	return single_open(file, ai_vfs_rates_show, NULL);
}

static const struct proc_ops ai_vfs_rates_ops = {
	.proc_open    = ai_vfs_rates_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ---- 初始化 ---- */

static struct proc_dir_entry *ai_proc_vfs_dir;

static int __init ai_vfs_procfs_init(void)
{
	struct proc_dir_entry *root = NULL;

#ifdef CONFIG_AIKERNEL_RUNTIME
	if (!ai_startup_get_enabled())
		return 0;   /* ai.enabled=0 启动：节点不创建（零回归） */
#endif

#ifdef CONFIG_AIKERNEL_USRIFACE
	root = ai_procfs_get_root();
#endif
	if (!root)
		root = proc_mkdir("ai", NULL);   /* USRIFACE 未开时自建 /proc/ai */
	if (!root)
		return -ENOMEM;

	ai_proc_vfs_dir = proc_mkdir("vfs", root);
	if (!ai_proc_vfs_dir)
		return -ENOMEM;

	proc_create("stats", 0444, ai_proc_vfs_dir, &ai_vfs_stats_ops);
	proc_create("rates", 0444, ai_proc_vfs_dir, &ai_vfs_rates_ops);

	pr_info("AIKernel: /proc/ai/vfs/ ready\n");
	return 0;
}
subsys_initcall(ai_vfs_procfs_init);

static void __exit ai_vfs_procfs_exit(void)
{
	proc_remove(ai_proc_vfs_dir);
	ai_proc_vfs_dir = NULL;
}
module_exit(ai_vfs_procfs_exit);
