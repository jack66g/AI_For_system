// SPDX-License-Identifier: GPL-2.0
/*
 * ai_vfs_telemetry.c - AIKernel B 轨第7类文件/目录/路径操作遥测（自 ai_vfs.c 拆分）
 *
 * 职责一句话：open/close/read/write/stat/mkdir/unlink/rename/symlink/chmod/
 * chown/writeback/path_lookup 及 dcache/inode 缓存命中统计的发射辅助
 * （采样判定 → 栈上 payload 含全量路径 → emit_direct 直写）。
 *
 * 拆分说明：函数体自原 ai_vfs.c（1222 行）逐字搬移；per-file 读写字节表、
 * flags_str 等仅本文件使用的辅助保持 static；ai_vfs_path_fill/
 * ai_vfs_emit_done 提升为模块内部共享（声明见 ai_vfs_internal.h，定义在本
 * 文件）。门控：随 ai_vfs.o 在 CONFIG_AIKERNEL_VFS 下构建（与拆分前一致）。
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


/* ==================================================================
 * 工具：全量路径填充 + 发射计数
 * ================================================================== */

/*
 * ai_vfs_path_fill() - d_path 全量路径填充（右对齐字符串 memmove 到头部）
 * 返回 false 表示超长/无效（调用方丢弃事件并累计 path_overflow）。
 * noinline：防止被内联进各发射辅助导致 frame-larger-than。
 */
noinline bool ai_vfs_path_fill(const struct path *p, char *dst,
				      size_t size)
{
	char *res;

	if (!p || !p->dentry || !p->mnt)
		return false;
	/* d_path 依赖 current->fs（get_fs_root_rcu）：
	 * 内核线程/退出中任务（do_exit 已 __exit_fs）fs==NULL，
	 * __fput 路径（含 kthread fput）必须防御（QEMU 实测崩溃修复）。 */
	if (!current->fs)
		return false;
	res = d_path(p, dst, size);
	if (IS_ERR(res))
		return false;
	memmove(dst, res, strlen(res) + 1);
	return true;
}

void ai_vfs_emit_done(u16 sub)
{
	this_cpu_inc(ai_vfs_emitted[sub]);
}

/* ==================================================================
 * per-file 读写字节累计表（vfs_close 数据源）
 * ================================================================== */

#define AI_VFS_FILE_TAB_SZ	256

struct ai_vfs_file_ent {
	struct file *file;
	atomic64_t rbytes;
	atomic64_t wbytes;
};

static struct ai_vfs_file_ent ai_vfs_file_tab[AI_VFS_FILE_TAB_SZ];
static DEFINE_SPINLOCK(ai_vfs_file_tab_lock);

static inline u32 ai_vfs_file_hash(struct file *f)
{
	return ((unsigned long)f >> 4) & (AI_VFS_FILE_TAB_SZ - 1);
}

static void ai_vfs_file_enter(struct file *f)
{
	struct ai_vfs_file_ent *e = &ai_vfs_file_tab[ai_vfs_file_hash(f)];

	spin_lock(&ai_vfs_file_tab_lock);
	if (!e->file) {
		e->file = f;
		atomic64_set(&e->rbytes, 0);
		atomic64_set(&e->wbytes, 0);
	}
	spin_unlock(&ai_vfs_file_tab_lock);
}

static void ai_vfs_file_bytes_add(struct file *f, int rw, u64 bytes)
{
	struct ai_vfs_file_ent *e = &ai_vfs_file_tab[ai_vfs_file_hash(f)];

	if (READ_ONCE(e->file) != f)
		return;
	if (rw)
		atomic64_add(bytes, &e->wbytes);
	else
		atomic64_add(bytes, &e->rbytes);
}

static void ai_vfs_file_leave(struct file *f, u64 *rb, u64 *wb)
{
	struct ai_vfs_file_ent *e = &ai_vfs_file_tab[ai_vfs_file_hash(f)];

	spin_lock(&ai_vfs_file_tab_lock);
	if (e->file == f) {
		*rb = atomic64_read(&e->rbytes);
		*wb = atomic64_read(&e->wbytes);
		e->file = NULL;
	} else {
		*rb = 0;
		*wb = 0;
	}
	spin_unlock(&ai_vfs_file_tab_lock);
}

/* ==================================================================
 * 工具：open flags 紧凑字符串
 * ================================================================== */

static void ai_vfs_flags_str(char *buf, size_t size, unsigned int flags)
{
	static const struct {
		unsigned int bit;
		const char *name;
	} bits[] = {
		{ O_RDONLY,	"RDONLY" },
		{ O_WRONLY,	"WRONLY" },
		{ O_RDWR,	"RDWR" },
		{ O_CREAT,	"CREAT" },
		{ O_EXCL,	"EXCL" },
		{ O_TRUNC,	"TRUNC" },
		{ O_APPEND,	"APPEND" },
		{ O_NONBLOCK,	"NONBLOCK" },
		{ O_SYNC,	"SYNC" },
		{ O_DSYNC,	"DSYNC" },
		{ O_DIRECT,	"DIRECT" },
		{ O_LARGEFILE,	"LARGEFILE" },
		{ O_DIRECTORY,	"DIRECTORY" },
		{ O_NOFOLLOW,	"NOFOLLOW" },
		{ O_CLOEXEC,	"CLOEXEC" },
		{ O_TMPFILE,	"TMPFILE" },
		{ O_PATH,	"PATH" },
		{ O_NOATIME,	"NOATIME" },
	};
	int i;
	size_t off = 0;

	buf[0] = '\0';
	for (i = 0; i < ARRAY_SIZE(bits); i++) {
		size_t n;

		if (!(flags & bits[i].bit) || bits[i].bit == O_RDONLY)
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

/* ==================================================================
 * B 轨：第7类 6 子类 24 个发射辅助
 * ================================================================== */

/* ---- 07.01 VFS 操作 ---- */

void ai_telemetry_vfs_open(struct file *file)
{
	struct ai_vfs_open_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_open_payload, full_path);
	u16 len;

	if (!ai_vfs_sample_take(AI_VFS_SUB_OPEN))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_OPEN;
	pl.pid = current->pid;
	get_task_comm(pl.comm, current);
	pl.mode = file->f_flags;
	ai_vfs_flags_str(pl.flags_str, sizeof(pl.flags_str), file->f_flags);
	ai_vfs_file_enter(file);
	if (!ai_vfs_path_fill(&file->f_path, pl.full_path,
			     sizeof(pl.full_path))) {
		this_cpu_inc(ai_vfs_path_overflow);
		return;
	}
	len = fixoff + strlen(pl.full_path) + 1;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_VFS, AI_SEV_NORMAL,
				 &pl, len);
	ai_vfs_emit_done(AI_VFS_SUB_OPEN);
}
EXPORT_SYMBOL_GPL(ai_telemetry_vfs_open);

void ai_telemetry_vfs_close(struct file *file)
{
	struct ai_vfs_close_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_close_payload, full_path);
	u16 len;
	u64 rb = 0, wb = 0;

	if (!ai_vfs_sample_take(AI_VFS_SUB_CLOSE))
		goto out;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_CLOSE;
	pl.pid = current->pid;
	ai_vfs_file_leave(file, &rb, &wb);
	pl.bytes_read = rb;
	pl.bytes_written = wb;
	if (!ai_vfs_path_fill(&file->f_path, pl.full_path,
			     sizeof(pl.full_path))) {
		this_cpu_inc(ai_vfs_path_overflow);
		return;
	}
	len = fixoff + strlen(pl.full_path) + 1;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_VFS, AI_SEV_NORMAL,
				 &pl, len);
	ai_vfs_emit_done(AI_VFS_SUB_CLOSE);
	return;
out:
	ai_vfs_file_leave(file, &rb, &wb);
}
EXPORT_SYMBOL_GPL(ai_telemetry_vfs_close);

void ai_telemetry_vfs_read(struct file *file, loff_t offset, size_t bytes)
{
	struct ai_vfs_rw_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_rw_payload, full_path);
	u16 len;

	ai_vfs_file_bytes_add(file, 0, bytes);
	if (!ai_vfs_sample_take(AI_VFS_SUB_READ))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_READ;
	pl.pid = current->pid;
	get_task_comm(pl.comm, current);
	pl.offset = offset;
	pl.bytes = bytes;
	if (!ai_vfs_path_fill(&file->f_path, pl.full_path,
			     sizeof(pl.full_path))) {
		this_cpu_inc(ai_vfs_path_overflow);
		return;
	}
	len = fixoff + strlen(pl.full_path) + 1;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_VFS, AI_SEV_NORMAL,
				 &pl, len);
	ai_vfs_emit_done(AI_VFS_SUB_READ);
}
EXPORT_SYMBOL_GPL(ai_telemetry_vfs_read);

void ai_telemetry_vfs_write(struct file *file, loff_t offset, size_t bytes)
{
	struct ai_vfs_rw_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_rw_payload, full_path);
	u16 len;

	ai_vfs_file_bytes_add(file, 1, bytes);
	if (!ai_vfs_sample_take(AI_VFS_SUB_WRITE))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_WRITE;
	pl.pid = current->pid;
	get_task_comm(pl.comm, current);
	pl.offset = offset;
	pl.bytes = bytes;
	if (!ai_vfs_path_fill(&file->f_path, pl.full_path,
			     sizeof(pl.full_path))) {
		this_cpu_inc(ai_vfs_path_overflow);
		return;
	}
	len = fixoff + strlen(pl.full_path) + 1;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_VFS, AI_SEV_NORMAL,
				 &pl, len);
	ai_vfs_emit_done(AI_VFS_SUB_WRITE);
}
EXPORT_SYMBOL_GPL(ai_telemetry_vfs_write);

void ai_telemetry_vfs_stat(const struct path *path)
{
	struct ai_vfs_stat_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_stat_payload, full_path);
	u16 len;

	if (!ai_vfs_sample_take(AI_VFS_SUB_STAT))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_STAT;
	pl.pid = current->pid;
	get_task_comm(pl.comm, current);
	if (!ai_vfs_path_fill(path, pl.full_path, sizeof(pl.full_path))) {
		this_cpu_inc(ai_vfs_path_overflow);
		return;
	}
	len = fixoff + strlen(pl.full_path) + 1;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_VFS, AI_SEV_NORMAL,
				 &pl, len);
	ai_vfs_emit_done(AI_VFS_SUB_STAT);
}
EXPORT_SYMBOL_GPL(ai_telemetry_vfs_stat);

void ai_telemetry_vfs_mkdir(const struct path *parent, const char *name,
			    umode_t mode)
{
	struct ai_vfs_mkdir_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_mkdir_payload, parent_path);
	u16 len;

	if (!ai_vfs_sample_take(AI_VFS_SUB_MKDIR))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_MKDIR;
	pl.pid = current->pid;
	get_task_comm(pl.comm, current);
	pl.mode = mode;
	strscpy(pl.dir_name, name, sizeof(pl.dir_name));
	if (!ai_vfs_path_fill(parent, pl.parent_path,
			      sizeof(pl.parent_path))) {
		this_cpu_inc(ai_vfs_path_overflow);
		return;
	}
	len = fixoff + strlen(pl.parent_path) + 1;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_VFS, AI_SEV_NORMAL,
				 &pl, len);
	ai_vfs_emit_done(AI_VFS_SUB_MKDIR);
}
EXPORT_SYMBOL_GPL(ai_telemetry_vfs_mkdir);

void ai_telemetry_vfs_unlink(const struct path *path)
{
	struct ai_vfs_unlink_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_unlink_payload, full_path);
	u16 len;

	if (!ai_vfs_sample_take(AI_VFS_SUB_UNLINK))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_UNLINK;
	pl.pid = current->pid;
	get_task_comm(pl.comm, current);
	if (!ai_vfs_path_fill(path, pl.full_path, sizeof(pl.full_path))) {
		this_cpu_inc(ai_vfs_path_overflow);
		return;
	}
	len = fixoff + strlen(pl.full_path) + 1;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_VFS, AI_SEV_NORMAL,
				 &pl, len);
	ai_vfs_emit_done(AI_VFS_SUB_UNLINK);
}
EXPORT_SYMBOL_GPL(ai_telemetry_vfs_unlink);

void ai_telemetry_vfs_rename(const struct path *old_path,
			     const struct path *new_path)
{
	struct ai_vfs_rename_payload *pl;
	u16 fixoff = offsetof(struct ai_vfs_rename_payload, old_path);
	u16 olen, nlen;

	if (!ai_vfs_sample_take(AI_VFS_SUB_RENAME))
		return;
	/* 双 1024B 路径使 payload 超 2KB 栈帧预算：改用 kmalloc
	 * （rename 为可睡眠系统调用路径，同 Prompt 07 seccomp 修复先例） */
	pl = kzalloc(sizeof(*pl), GFP_KERNEL);
	if (!pl)
		return;
	pl->type = AI_VFS_SUB_RENAME;
	pl->pid = current->pid;
	get_task_comm(pl->comm, current);
	if (!ai_vfs_path_fill(old_path, pl->old_path, sizeof(pl->old_path)) ||
	    !ai_vfs_path_fill(new_path, pl->new_path, sizeof(pl->new_path))) {
		this_cpu_inc(ai_vfs_path_overflow);
		kfree(pl);
		return;
	}
	olen = strlen(pl->old_path) + 1;
	nlen = strlen(pl->new_path) + 1;
	if (fixoff + olen + nlen > AI_TELEMETRY_MAX_DATA_LEN) {
		this_cpu_inc(ai_vfs_path_overflow);
		kfree(pl);
		return;
	}
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_VFS, AI_SEV_NORMAL,
				 pl, fixoff + olen + nlen);
	ai_vfs_emit_done(AI_VFS_SUB_RENAME);
	kfree(pl);
}
EXPORT_SYMBOL_GPL(ai_telemetry_vfs_rename);

void ai_telemetry_vfs_symlink(const char *target, const struct path *link_path)
{
	struct ai_vfs_symlink_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_symlink_payload, link_path);
	u16 len;

	if (!ai_vfs_sample_take(AI_VFS_SUB_SYMLINK))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_SYMLINK;
	pl.pid = current->pid;
	get_task_comm(pl.comm, current);
	strscpy(pl.target_path, target, sizeof(pl.target_path));
	if (!ai_vfs_path_fill(link_path, pl.link_path,
			      sizeof(pl.link_path))) {
		this_cpu_inc(ai_vfs_path_overflow);
		return;
	}
	len = fixoff + strlen(pl.link_path) + 1;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_VFS, AI_SEV_NORMAL,
				 &pl, len);
	ai_vfs_emit_done(AI_VFS_SUB_SYMLINK);
}
EXPORT_SYMBOL_GPL(ai_telemetry_vfs_symlink);

void ai_telemetry_vfs_chmod(const struct path *path, umode_t old_mode,
			    umode_t new_mode)
{
	struct ai_vfs_chmod_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_chmod_payload, full_path);
	u16 len;

	if (!ai_vfs_sample_take(AI_VFS_SUB_CHMOD))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_CHMOD;
	pl.pid = current->pid;
	get_task_comm(pl.comm, current);
	pl.old_mode = old_mode;
	pl.new_mode = new_mode;
	if (!ai_vfs_path_fill(path, pl.full_path, sizeof(pl.full_path))) {
		this_cpu_inc(ai_vfs_path_overflow);
		return;
	}
	len = fixoff + strlen(pl.full_path) + 1;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_VFS, AI_SEV_NORMAL,
				 &pl, len);
	ai_vfs_emit_done(AI_VFS_SUB_CHMOD);
}
EXPORT_SYMBOL_GPL(ai_telemetry_vfs_chmod);

void ai_telemetry_vfs_chown(const struct path *path, uid_t old_uid,
			    uid_t new_uid)
{
	struct ai_vfs_chown_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_chown_payload, full_path);
	u16 len;

	if (!ai_vfs_sample_take(AI_VFS_SUB_CHOWN))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_CHOWN;
	pl.pid = current->pid;
	get_task_comm(pl.comm, current);
	pl.old_uid = old_uid;
	pl.new_uid = new_uid;
	if (!ai_vfs_path_fill(path, pl.full_path, sizeof(pl.full_path))) {
		this_cpu_inc(ai_vfs_path_overflow);
		return;
	}
	len = fixoff + strlen(pl.full_path) + 1;
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_VFS, AI_SEV_NORMAL,
				 &pl, len);
	ai_vfs_emit_done(AI_VFS_SUB_CHOWN);
}
EXPORT_SYMBOL_GPL(ai_telemetry_vfs_chown);

void ai_telemetry_writeback(struct bdi_writeback *wb, long nr_pages,
			    int reason)
{
	struct ai_vfs_writeback_payload pl;

	if (!ai_vfs_sample_take(AI_VFS_SUB_WRITEBACK))
		return;
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_VFS_SUB_WRITEBACK;
	pl.reason = (u8)reason;
	pl.nr_pages = nr_pages;
	strscpy(pl.dev, bdi_dev_name(wb->bdi), sizeof(pl.dev));
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_VFS, AI_SEV_NORMAL,
				 &pl, sizeof(pl));
	ai_vfs_emit_done(AI_VFS_SUB_WRITEBACK);
}
EXPORT_SYMBOL_GPL(ai_telemetry_writeback);

/* ---- 07.02 路径解析 ---- */

void ai_telemetry_path_lookup(const struct path *path, const struct qstr *last,
			      u32 depth, u32 symlinks, u32 mounts,
			      u64 latency_ns)
{
	struct ai_vfs_path_lookup_payload pl;
	u16 fixoff = offsetof(struct ai_vfs_path_lookup_payload, full_path);
	u16 len;

	if (!ai_vfs_sample_take(AI_VFS_SUB_PATH_LOOKUP))
		return;
	memset(&pl, 0, fixoff + 1);
	pl.type = AI_VFS_SUB_PATH_LOOKUP;
	pl.pid = current->pid;
	get_task_comm(pl.comm, current);
	pl.depth = depth;
	pl.symlink_count = symlinks;
	pl.mount_crossings = mounts;
	pl.latency_ns = latency_ns;
	if (!ai_vfs_path_fill(path, pl.full_path, sizeof(pl.full_path))) {
		this_cpu_inc(ai_vfs_path_overflow);
		return;
	}
	len = fixoff + strlen(pl.full_path) + 1;
	if (last && last->name && last->len) {
		size_t plen = strlen(pl.full_path);

		if (plen + 1 + last->len + 1 <= sizeof(pl.full_path)) {
			if (pl.full_path[plen - 1] != '/')
				pl.full_path[plen++] = '/';
			memcpy(pl.full_path + plen, last->name, last->len);
			pl.full_path[plen + last->len] = '\0';
			len = fixoff + plen + last->len + 1;
		}
	}
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_PATH_LOOKUP,
				 AI_SEV_NORMAL, &pl, len);
	ai_vfs_emit_done(AI_VFS_SUB_PATH_LOOKUP);
}
EXPORT_SYMBOL_GPL(ai_telemetry_path_lookup);

/*
 * 热路径采样计数方案（性能优化，QEMU/TCG 实测定位）：
 * 每次查找仅 1 次 per-CPU inc_return + 分支；命中/未命中计数按
 * AI_VFS_CACHE_SAMPLE_RATE（32）采样累计（命中率统计为近似值，
 * 采样计数 ≈ 全量/32，比率语义不变）。
 */
#define AI_VFS_CACHE_SAMPLE_RATE	32

static DEFINE_PER_CPU(u32, ai_vfs_cache_samp_cnt);

void ai_vfs_dcache_lookup(bool hit)
{
	u32 n = this_cpu_inc_return(ai_vfs_cache_samp_cnt);

	if (unlikely((n % AI_VFS_CACHE_SAMPLE_RATE) == 0)) {
		if (hit)
			this_cpu_inc(ai_vfs_dentry_hit);
		else
			this_cpu_inc(ai_vfs_dentry_miss);
		ai_telemetry_path_lookup_cache();
	}
}
EXPORT_SYMBOL_GPL(ai_vfs_dcache_lookup);

void ai_vfs_inode_lookup(bool hit)
{
	if (hit)
		this_cpu_inc(ai_vfs_inode_hit);
	else
		this_cpu_inc(ai_vfs_inode_miss);
}
EXPORT_SYMBOL_GPL(ai_vfs_inode_lookup);

void ai_vfs_inode_veto_note(void)
{
	this_cpu_inc(ai_vfs_inode_veto);
}
EXPORT_SYMBOL_GPL(ai_vfs_inode_veto_note);

void ai_telemetry_path_lookup_cache(void)
{
	struct ai_vfs_path_lookup_cache_payload pl;

	/* 采样判定已在 ai_vfs_dcache_lookup 完成（AI_VFS_CACHE_SAMPLE_RATE） */
	memset(&pl, 0, sizeof(pl));
	pl.type = AI_VFS_SUB_PATH_LOOKUP_CACHE;
	{
		int cpu;

		for_each_possible_cpu(cpu) {
			pl.dentry_hit += per_cpu(ai_vfs_dentry_hit, cpu);
			pl.dentry_miss += per_cpu(ai_vfs_dentry_miss, cpu);
			pl.inode_hit += per_cpu(ai_vfs_inode_hit, cpu);
			pl.inode_miss += per_cpu(ai_vfs_inode_miss, cpu);
		}
	}
	ai_telemetry_emit_direct(AI_CAT_FS, AI_EV_PATH_LOOKUP,
				 AI_SEV_NORMAL, &pl, sizeof(pl));
	ai_vfs_emit_done(AI_VFS_SUB_PATH_LOOKUP_CACHE);
}
EXPORT_SYMBOL_GPL(ai_telemetry_path_lookup_cache);
