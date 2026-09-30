// SPDX-License-Identifier: GPL-2.0
/*
 * ai_vfs_telemetry_fs.c - AIKernel B 轨第7类挂载/文件锁/poll/错误遥测（自 ai_vfs.c 拆分）
 *
 * 职责一句话：mount/umount、file_lock_set/conflict、epoll_create/ctl/wait、
 * inotify_event、fs_error/fs_corruption 的发射辅助（采样判定 → 全量路径或
 * 设备名 payload → emit_direct 直写）。
 *
 * 拆分说明：函数体自原 ai_vfs.c（1222 行）逐字搬移；mount_flags_str/
 * lock_path/sb_devname 仅本文件使用，保持 static；路径填充与发射计数经
 * ai_vfs_internal.h 共享。门控：随 ai_vfs.o 在 CONFIG_AIKERNEL_VFS 下构建
 * （与拆分前一致）。
 */

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

/* ---- 07.03 挂载 ---- */

static void ai_vfs_mount_flags_str(char *buf, size_t size, unsigned long flags)
{
	static const struct {
		unsigned long bit;
		const char *name;
	} bits[] = {
		{ MS_RDONLY, "RDONLY" }, { MS_NOSUID, "NOSUID" },
		{ MS_NODEV, "NODEV" }, { MS_NOEXEC, "NOEXEC" },
		{ MS_SYNCHRONOUS, "SYNCHRONOUS" }, { MS_REMOUNT, "REMOUNT" },
		{ MS_MANDLOCK, "MANDLOCK" }, { MS_DIRSYNC, "DIRSYNC" },
		{ MS_NOSYMFOLLOW, "NOSYMFOLLOW" }, { MS_NOATIME, "NOATIME" },
		{ MS_NODIRATIME, "NODIRATIME" }, { MS_BIND, "BIND" },
		{ MS_MOVE, "MOVE" }, { MS_REC, "REC" }, { MS_SILENT, "SILENT" },
		{ MS_POSIXACL, "POSIXACL" }, { MS_UNBINDABLE, "UNBINDABLE" },
		{ MS_PRIVATE, "PRIVATE" }, { MS_SLAVE, "SLAVE" },
		{ MS_SHARED, "SHARED" }, { MS_RELATIME, "RELATIME" },
		{ MS_KERNMOUNT, "KERNMOUNT" }, { MS_I_VERSION, "I_VERSION" },
		{ MS_STRICTATIME, "STRICTATIME" }, { MS_LAZYTIME, "LAZYTIME" },
	};
	size_t off = 0;
	int i;

	buf[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(bits); i++) {
		size_t n;

		if (!(flags & bits[i].bit))
			continue;
		if (off) {
			n = snprintf(buf + off, size - off, "|%s", bits[i].name);
			if (n >= size - off)
				break;
			off += n;
		} else {
			n = snprintf(buf + off, size - off, "%s", bits[i].name);
			if (n >= size - off)
				break;
			off += n;
		}
	}
}

void ai_telemetry_mount(const char *dev_name, const struct path *mnt_point,
			const char *fs_type, unsigned long flags,
			const char *options)
{
	struct ai_vfs_mount_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_mount_payload, mount_point);
	u16 len;

	if (!ai_vfs_sample_take(AI_VFS_SUB_MOUNT))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_MOUNT;
	pl.flags = flags;
	strscpy(pl.dev_name, dev_name ? dev_name : "", sizeof(pl.dev_name));
	strscpy(pl.fs_type, fs_type ? fs_type : "", sizeof(pl.fs_type));
	ai_vfs_mount_flags_str(pl.flags_str, sizeof(pl.flags_str), flags);
	strscpy(pl.options, options ? options : "", sizeof(pl.options));
	if (!ai_vfs_path_fill(mnt_point, pl.mount_point,
			      sizeof(pl.mount_point))) {
		this_cpu_inc(ai_vfs_path_overflow);
		return;
	}
	len = fixoff + strlen(pl.mount_point) + 1;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_MOUNT, AI_SEV_NORMAL,
				 &pl, len);
	ai_vfs_emit_done(AI_VFS_SUB_MOUNT);
}
EXPORT_SYMBOL_GPL(ai_telemetry_mount);

void ai_telemetry_umount(const struct path *path, int flags)
{
	struct ai_vfs_umount_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_umount_payload, mount_point);
	u16 len;

	if (!ai_vfs_sample_take(AI_VFS_SUB_UMOUNT))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_UMOUNT;
	pl.force = !!(flags & MNT_FORCE);
	if (!ai_vfs_path_fill(path, pl.mount_point, sizeof(pl.mount_point))) {
		this_cpu_inc(ai_vfs_path_overflow);
		return;
	}
	len = fixoff + strlen(pl.mount_point) + 1;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_MOUNT, AI_SEV_NORMAL,
				 &pl, len);
	ai_vfs_emit_done(AI_VFS_SUB_UMOUNT);
}
EXPORT_SYMBOL_GPL(ai_telemetry_umount);

/* ---- 07.04 文件锁 ---- */

static void ai_vfs_lock_path(struct file *file, char *buf, size_t size)
{
	ai_vfs_path_fill(&file->f_path, buf, size);
}

void ai_telemetry_file_lock_set(struct file *file, int type, u64 start,
				u64 len, bool blocking)
{
	struct ai_vfs_file_lock_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_file_lock_payload, full_path);
	u16 plen;

	if (!ai_vfs_sample_take(AI_VFS_SUB_FILE_LOCK_SET))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_FILE_LOCK_SET;
	pl.pid = current->pid;
	get_task_comm(pl.comm, current);
	pl.start = start;
	pl.len = len;
	pl.lock_type = (u8)type;
	pl.blocking = blocking ? 1 : 0;
	ai_vfs_lock_path(file, pl.full_path, sizeof(pl.full_path));
	plen = strlen(pl.full_path);
	if (!plen) {
		this_cpu_inc(ai_vfs_path_overflow);
		return;
	}
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_FILE_LOCK, AI_SEV_NORMAL,
				 &pl, fixoff + plen + 1);
	ai_vfs_emit_done(AI_VFS_SUB_FILE_LOCK_SET);
}
EXPORT_SYMBOL_GPL(ai_telemetry_file_lock_set);

void ai_telemetry_file_lock_conflict(struct file *file, pid_t holder_pid,
				     int type)
{
	struct ai_vfs_file_lock_conflict_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_file_lock_conflict_payload,
			      full_path);
	u16 plen;

	if (!ai_vfs_sample_take(AI_VFS_SUB_FILE_LOCK_CONFLICT))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_FILE_LOCK_CONFLICT;
	pl.pid = current->pid;
	get_task_comm(pl.comm, current);
	pl.holder_pid = holder_pid;
	pl.lock_type = (u8)type;
	ai_vfs_lock_path(file, pl.full_path, sizeof(pl.full_path));
	plen = strlen(pl.full_path);
	if (!plen) {
		this_cpu_inc(ai_vfs_path_overflow);
		return;
	}
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_FILE_LOCK,
				 AI_SEV_IMPORTANT, &pl, fixoff + plen + 1);
	ai_vfs_emit_done(AI_VFS_SUB_FILE_LOCK_CONFLICT);
}
EXPORT_SYMBOL_GPL(ai_telemetry_file_lock_conflict);

/* ---- 07.05 epoll/事件通知 ---- */

void ai_telemetry_epoll_create(int flags)
{
	struct ai_vfs_epoll_create_payload pl;

	if (!ai_vfs_sample_take(AI_VFS_SUB_EPOLL_CREATE))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_VFS_SUB_EPOLL_CREATE;
	pl.pid = current->pid;
	get_task_comm(pl.comm, current);
	pl.flags = flags;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_EPOLL, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
	ai_vfs_emit_done(AI_VFS_SUB_EPOLL_CREATE);
}
EXPORT_SYMBOL_GPL(ai_telemetry_epoll_create);

void ai_telemetry_epoll_ctl(int epfd, int op, int fd, u32 events)
{
	struct ai_vfs_epoll_ctl_payload pl;

	if (!ai_vfs_sample_take(AI_VFS_SUB_EPOLL_CTL))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_VFS_SUB_EPOLL_CTL;
	pl.pid = current->pid;
	pl.epfd = epfd;
	pl.op = op;
	pl.fd = fd;
	pl.events = events;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_EPOLL, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
	ai_vfs_emit_done(AI_VFS_SUB_EPOLL_CTL);
}
EXPORT_SYMBOL_GPL(ai_telemetry_epoll_ctl);

void ai_telemetry_epoll_wait(int epfd, int ready_count, u64 wait_duration_us)
{
	struct ai_vfs_epoll_wait_payload pl;

	if (!ai_vfs_sample_take(AI_VFS_SUB_EPOLL_WAIT))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_VFS_SUB_EPOLL_WAIT;
	pl.pid = current->pid;
	pl.epfd = epfd;
	pl.ready_count = ready_count;
	pl.wait_duration_us = wait_duration_us;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_EPOLL, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
	ai_vfs_emit_done(AI_VFS_SUB_EPOLL_WAIT);
}
EXPORT_SYMBOL_GPL(ai_telemetry_epoll_wait);

void ai_telemetry_inotify_event(struct inode *inode, struct inode *dir,
				const struct qstr *name, int wd, u32 mask)
{
	struct ai_vfs_inotify_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_inotify_payload, full_path);
	struct dentry *dentry = NULL;
	u16 len;

	if (!ai_vfs_sample_take(AI_VFS_SUB_INOTIFY_EVENT))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_INOTIFY_EVENT;
	pl.pid = current->pid;
	pl.wd = wd;
	pl.mask = mask;

	/* 目录监视：dir+name 组装完整路径；文件监视：文件自身路径。
	 * dentry_path_raw 相对文件系统根（inotify 事件语义内完整）。 */
	if (name && name->name && dir)
		dentry = d_find_alias(dir);
	if (!dentry && inode)
		dentry = d_find_alias(inode);
	if (dentry) {
		char *res = dentry_path_raw(dentry, pl.full_path,
					    sizeof(pl.full_path));
		size_t plen;

		if (!IS_ERR(res)) {
			memmove(pl.full_path, res, strlen(res) + 1);
			plen = strlen(pl.full_path);
			if (name && name->name && name->len &&
			    plen + 1 + name->len + 1 <= sizeof(pl.full_path)) {
				if (plen == 1 && pl.full_path[0] == '/')
					plen = 0;	/* 根目录去掉 '/' */
				if (plen && pl.full_path[plen - 1] != '/')
					pl.full_path[plen++] = '/';
				memcpy(pl.full_path + plen, name->name,
				       name->len);
				pl.full_path[plen + name->len] = '\0';
				plen += name->len;
			}
			len = fixoff + plen + 1;
			ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_EPOLL,
						 AI_SEV_NORMAL, &pl, len);
			ai_vfs_emit_done(AI_VFS_SUB_INOTIFY_EVENT);
		} else {
			this_cpu_inc(ai_vfs_path_overflow);
		}
		dput(dentry);
	} else {
		this_cpu_inc(ai_vfs_path_overflow);
	}
}
EXPORT_SYMBOL_GPL(ai_telemetry_inotify_event);

/* ---- 07.06 文件系统错误 ---- */

static void ai_vfs_sb_devname(struct super_block *sb, char *buf, size_t size)
{
	struct gendisk *disk;

	if (sb && sb->s_bdev) {
		disk = sb->s_bdev->bd_disk;
		if (disk)
			snprintf(buf, size, "%s", disk->disk_name);
		else
			snprintf(buf, size, "%u:%u",
				 MAJOR(sb->s_bdev->bd_dev),
				 MINOR(sb->s_bdev->bd_dev));
	} else {
		snprintf(buf, size, "%s", "n/a");
	}
}

void ai_telemetry_fs_error(struct super_block *sb, u8 error_type,
			   int error_code, u64 ino)
{
	struct ai_vfs_fs_error_payload pl;
	struct dentry *dentry = NULL;
	struct inode *inode = NULL;
	u16 fixoff = offsetof(struct ai_vfs_fs_error_payload, full_path);
	u16 len;
	size_t plen = 0;

	if (!ai_vfs_sample_take(AI_VFS_SUB_FS_ERROR))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_FS_ERROR;
	pl.error_code = error_code;
	pl.error_type = error_type;
	pl.ino = ino;
	if (sb) {
		strscpy(pl.fs_type, sb->s_type->name, sizeof(pl.fs_type));
		ai_vfs_sb_devname(sb, pl.dev, sizeof(pl.dev));
	}
	/* 尽力而为的路径：有 inode 对象时取其 dentry 相对根路径 */
	if (sb && ino)
		inode = ilookup(sb, ino);
	if (inode)
		dentry = d_find_alias(inode);
	if (dentry) {
		char *res = dentry_path_raw(dentry, pl.full_path,
					    sizeof(pl.full_path));

		if (!IS_ERR(res)) {
			memmove(pl.full_path, res, strlen(res) + 1);
			plen = strlen(pl.full_path);
		}
		dput(dentry);
	}
	if (inode)
		iput(inode);
	len = fixoff + plen + 1;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_FS_ERROR,
				 AI_SEV_IMPORTANT, &pl, len);
	ai_vfs_emit_done(AI_VFS_SUB_FS_ERROR);
}
EXPORT_SYMBOL_GPL(ai_telemetry_fs_error);

void ai_telemetry_fs_corruption(struct super_block *sb, u64 ino,
				u8 error_type)
{
	struct ai_vfs_fs_corruption_payload pl;

	if (!ai_vfs_sample_take(AI_VFS_SUB_FS_CORRUPTION))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_VFS_SUB_FS_CORRUPTION;
	pl.ino = ino;
	pl.error_type = error_type;
	if (sb) {
		strscpy(pl.fs_type, sb->s_type->name, sizeof(pl.fs_type));
		ai_vfs_sb_devname(sb, pl.dev, sizeof(pl.dev));
	}
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_FS_ERROR,
				 AI_SEV_CRITICAL, &pl, sizeof(pl));
	ai_vfs_emit_done(AI_VFS_SUB_FS_CORRUPTION);
}
EXPORT_SYMBOL_GPL(ai_telemetry_fs_corruption);
