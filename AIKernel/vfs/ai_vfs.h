// SPDX-License-Identifier: GPL-2.0
/*
 * ai_vfs.h - AIKernel VFS 子系统统一接口头（Prompt 08）
 *
 * 本文件是 fs/ 全部 AI 埋点的唯一接入点：
 *   A 轨（控制）：ai_vfs_*_hook() 系列 —— 让 AI 参与 VFS 决策
 *                 （dentry/inode 缓存驱逐、路径预取、回写时机/批量、
 *                  epoll 事件优先级、AIO 聚合、DAX 预取、读写控制通道），
 *                  空实现 = 原样放行（不改变内核默认行为，不扰动 LRU 顺序）；
 *   B 轨（感知）：第7类 文件系统感知 6 子类的 payload 结构 + 发射辅助，
 *                 全量原始零脱敏（完整路径/pid/comm/偏移/字节全保留）。
 *
 * 零回归策略：
 *   - CONFIG_AIKERNEL_VFS=n：本头文件不参与任何编译（fs/ 下各 .c 的
 *     条件 include 一并剔除），预处理产物与基线一致；
 *   - CONFIG_AIKERNEL_TELEMETRY=n：ai_telemetry_emit_direct() 退化为
 *     static inline 空函数（ai_telemetry.h 内置兜底），Hook 本身只计数不发射。
 *
 * 遥测函数铁律：不阻塞、不分配（无 GFP_KERNEL）、无锁，仅供快速路径
 * （vfs_read/vfs_write/路径解析可能在 RCU 或中断上下文调用 —— 全部走
 * per-CPU ring buffer 直写；采样判定在前，路径构建只在采样命中时进行）。
 *
 * 事件体系：第7类 文件系统感知 6 个子类（AI_CAT_FS）：
 *   07.01 VFS 操作 / 07.02 路径解析 / 07.03 挂载 / 07.04 文件锁 /
 *   07.05 epoll 与事件通知 / 07.06 文件系统错误
 * 子事件编号（payload 首字节 type）全局唯一（1~24，对齐 ai_net 模式）。
 *
 * 全量路径上限：AI_VFS_PATH_MAX=1024。路径 ≥1024 字符时整条事件丢弃并累计
 * path_overflow 计数（丢弃 ≠ 截断，保证"零截断"语义；计数见 /proc/ai/vfs/stats）。
 */

#ifndef _AIKERNEL_VFS_AI_VFS_H
#define _AIKERNEL_VFS_AI_VFS_H

#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/uio.h>
#include <linux/backing-dev.h>
#include <linux/binfmts.h>
#include <linux/aio_abi.h>
#include <linux/sched.h>
#include <linux/string.h>

/* ---- 常量 ---- */

#define AI_VFS_PATH_MAX		1024	/* 完整路径上限（超限整条丢弃不截断） */
#define AI_VFS_TARGET_MAX	256	/* symlink 目标路径上限 */

/* ---- 子事件编号（payload 首字节 type，全局唯一 1~24） ---- */

enum ai_vfs_sub_event {
	/* 07.01 VFS 操作（AI_EV_VFS） */
	AI_VFS_SUB_OPEN		= 1,	/* 文件打开（全量路径） */
	AI_VFS_SUB_CLOSE,		/* 文件关闭 */
	AI_VFS_SUB_READ,		/* 文件读取 */
	AI_VFS_SUB_WRITE,		/* 文件写入 */
	AI_VFS_SUB_STAT,		/* 文件查询 */
	AI_VFS_SUB_MKDIR,		/* 创建目录 */
	AI_VFS_SUB_UNLINK,		/* 删除文件 */
	AI_VFS_SUB_RENAME,		/* 重命名 */
	AI_VFS_SUB_SYMLINK,		/* 创建符号链接 */
	AI_VFS_SUB_CHMOD,		/* 权限变更 */
	AI_VFS_SUB_CHOWN,		/* 所有者变更 */
	AI_VFS_SUB_WRITEBACK,		/* 回写（nr_pages/reason） */

	/* 07.02 路径解析（AI_EV_PATH_LOOKUP） */
	AI_VFS_SUB_PATH_LOOKUP	= 13,	/* 路径解析详情（含延迟） */
	AI_VFS_SUB_PATH_LOOKUP_CACHE,	/* 缓存命中/未命中统计 */

	/* 07.03 文件系统挂载（AI_EV_MOUNT） */
	AI_VFS_SUB_MOUNT	= 15,	/* 挂载 */
	AI_VFS_SUB_UMOUNT,		/* 卸载 */

	/* 07.04 文件锁（AI_EV_FILE_LOCK） */
	AI_VFS_SUB_FILE_LOCK_SET = 17,	/* 锁设置 */
	AI_VFS_SUB_FILE_LOCK_CONFLICT,	/* 锁冲突 */

	/* 07.05 epoll/事件通知（AI_EV_EPOLL） */
	AI_VFS_SUB_EPOLL_CREATE	= 19,	/* epoll 创建 */
	AI_VFS_SUB_EPOLL_CTL,		/* epoll 控制 */
	AI_VFS_SUB_EPOLL_WAIT,		/* epoll 等待 */
	AI_VFS_SUB_INOTIFY_EVENT,	/* inotify 事件 */

	/* 07.06 文件系统错误（AI_EV_FS_ERROR） */
	AI_VFS_SUB_FS_ERROR	= 23,	/* 文件系统错误 */
	AI_VFS_SUB_FS_CORRUPTION,	/* 文件系统损坏 */

	AI_VFS_SUB_MAX,
};

/* ---- 驱逐路径操作类型（ai_vfs_dcache_hook op 参数） ---- */

enum ai_vfs_evict_op {
	AI_VFS_EVICT_DENTRY = 1,	/* dput() 引用计数归零驱逐（可干预） */
	AI_VFS_EVICT_LRU,		/* shrink 路径 LRU 驱逐（本步观察点，输出仅记录） */
};

/* ---- fs 错误类型（ai_telemetry_fs_error error_type 参数） ---- */

enum ai_vfs_fs_err_type {
	AI_VFS_FS_ERR_GENERIC = 1,	/* 通用错误 */
	AI_VFS_FS_ERR_EMERGENCY_REMOUNT,/* 紧急只读重挂载（VFS 通用收敛点） */
	AI_VFS_FS_ERR_EXT4,		/* ext4 错误上报 */
	AI_VFS_FS_ERR_CORRUPTION,	/* 元数据损坏 */
};

/* ==================================================================
 * B 轨：第7类 文件系统感知 payload（事件编号对齐 enum ai_vfs_sub_event）
 * ==================================================================
 * 每个 payload 首字节为 u8 type，区分计划内的子事件。
 * 全量原始零脱敏：完整路径 / pid / comm / 偏移 / 字节数全保留。
 */

/* 07.01 open（vfs_open + chrdev_open 共用） */
struct ai_vfs_open_payload {
	u8 type;			/* AI_VFS_SUB_OPEN */
	u32 pid;
	char comm[TASK_COMM_LEN];
	char flags_str[24];		/* O_RDONLY|O_CREAT|... 紧凑字符串 */
	umode_t mode;
	char full_path[AI_VFS_PATH_MAX]; /* 完整路径（零截断，超限整条丢弃） */
};

struct ai_vfs_close_payload {
	u8 type;			/* AI_VFS_SUB_CLOSE */
	u32 pid;
	u64 bytes_read;			/* per-file 累计读取字节 */
	u64 bytes_written;		/* per-file 累计写入字节 */
	char full_path[AI_VFS_PATH_MAX];
};

/* read/write 共用（type 区分） */
struct ai_vfs_rw_payload {
	u8 type;			/* AI_VFS_SUB_READ / AI_VFS_SUB_WRITE */
	u32 pid;
	char comm[TASK_COMM_LEN];
	u64 offset;
	u64 bytes;
	char full_path[AI_VFS_PATH_MAX];
};

struct ai_vfs_stat_payload {
	u8 type;			/* AI_VFS_SUB_STAT */
	u32 pid;
	char comm[TASK_COMM_LEN];
	char full_path[AI_VFS_PATH_MAX];
};

struct ai_vfs_mkdir_payload {
	u8 type;			/* AI_VFS_SUB_MKDIR */
	u32 pid;
	char comm[TASK_COMM_LEN];
	umode_t mode;
	char dir_name[256];
	char parent_path[AI_VFS_PATH_MAX];
};

struct ai_vfs_unlink_payload {
	u8 type;			/* AI_VFS_SUB_UNLINK */
	u32 pid;
	char comm[TASK_COMM_LEN];
	char full_path[AI_VFS_PATH_MAX];
};

struct ai_vfs_rename_payload {
	u8 type;			/* AI_VFS_SUB_RENAME */
	u32 pid;
	char comm[TASK_COMM_LEN];
	char old_path[AI_VFS_PATH_MAX];
	char new_path[AI_VFS_PATH_MAX];
};

struct ai_vfs_symlink_payload {
	u8 type;			/* AI_VFS_SUB_SYMLINK */
	u32 pid;
	char comm[TASK_COMM_LEN];
	char target_path[AI_VFS_TARGET_MAX];
	char link_path[AI_VFS_PATH_MAX];
};

struct ai_vfs_chmod_payload {
	u8 type;			/* AI_VFS_SUB_CHMOD */
	u32 pid;
	char comm[TASK_COMM_LEN];
	umode_t old_mode;
	umode_t new_mode;
	char full_path[AI_VFS_PATH_MAX];
};

struct ai_vfs_chown_payload {
	u8 type;			/* AI_VFS_SUB_CHOWN */
	u32 pid;
	char comm[TASK_COMM_LEN];
	uid_t old_uid;
	uid_t new_uid;
	char full_path[AI_VFS_PATH_MAX];
};

struct ai_vfs_writeback_payload {
	u8 type;			/* AI_VFS_SUB_WRITEBACK */
	u8 reason;			/* enum wb_reason */
	u8 pad[2];
	long nr_pages;
	char dev[32];
};

/* 07.02 路径解析 */
struct ai_vfs_path_lookup_payload {
	u8 type;			/* AI_VFS_SUB_PATH_LOOKUP */
	u32 pid;
	char comm[TASK_COMM_LEN];
	u32 depth;			/* 组件深度（nd->depth 近似） */
	u32 symlink_count;		/* nd->total_link_count */
	u32 mount_crossings;		/* ND_JUMPED 近似（0/1） */
	u64 latency_ns;
	char full_path[AI_VFS_PATH_MAX];
};

struct ai_vfs_path_lookup_cache_payload {
	u8 type;			/* AI_VFS_SUB_PATH_LOOKUP_CACHE */
	u64 dentry_hit;
	u64 dentry_miss;
	u64 inode_hit;
	u64 inode_miss;
};

/* 07.03 挂载 */
struct ai_vfs_mount_payload {
	u8 type;			/* AI_VFS_SUB_MOUNT */
	u64 flags;
	char dev_name[64];
	char fs_type[32];
	char flags_str[64];
	char options[64];
	char mount_point[AI_VFS_PATH_MAX];
};

struct ai_vfs_umount_payload {
	u8 type;			/* AI_VFS_SUB_UMOUNT */
	u8 force;			/* MNT_FORCE 位 */
	char mount_point[AI_VFS_PATH_MAX];
};

/* 07.04 文件锁 */
struct ai_vfs_file_lock_payload {
	u8 type;			/* AI_VFS_SUB_FILE_LOCK_SET */
	u32 pid;
	char comm[TASK_COMM_LEN];
	u64 start;
	u64 len;
	u8 lock_type;			/* F_RDLCK/F_WRLCK/F_UNLCK */
	u8 blocking;			/* FL_SLEEP */
	char full_path[AI_VFS_PATH_MAX];
};

struct ai_vfs_file_lock_conflict_payload {
	u8 type;			/* AI_VFS_SUB_FILE_LOCK_CONFLICT */
	u32 pid;
	char comm[TASK_COMM_LEN];
	u32 holder_pid;			/* 冲突锁持有者 */
	u8 lock_type;			/* 请求的锁类型 */
	u8 pad[3];
	char full_path[AI_VFS_PATH_MAX];
};

/* 07.05 epoll/事件通知 */
struct ai_vfs_epoll_create_payload {
	u8 type;			/* AI_VFS_SUB_EPOLL_CREATE */
	u32 pid;
	char comm[TASK_COMM_LEN];
	u32 flags;
};

struct ai_vfs_epoll_ctl_payload {
	u8 type;			/* AI_VFS_SUB_EPOLL_CTL */
	u32 pid;
	int epfd;
	u32 op;				/* EPOLL_CTL_ADD/DEL/MOD */
	int fd;
	u32 events;
};

struct ai_vfs_epoll_wait_payload {
	u8 type;			/* AI_VFS_SUB_EPOLL_WAIT */
	u32 pid;
	int epfd;
	u32 ready_count;
	u64 wait_duration_us;
};

struct ai_vfs_inotify_payload {
	u8 type;			/* AI_VFS_SUB_INOTIFY_EVENT */
	u32 pid;
	int wd;
	u32 mask;
	char full_path[AI_VFS_PATH_MAX];
};

/* 07.06 文件系统错误 */
struct ai_vfs_fs_error_payload {
	u8 type;			/* AI_VFS_SUB_FS_ERROR */
	u32 error_code;
	u8 error_type;			/* enum ai_vfs_fs_err_type */
	u8 pad[3];
	u64 ino;
	char fs_type[32];
	char dev[32];
	char full_path[AI_VFS_PATH_MAX]; /* 尽力而为：无对象上下文时为空 */
};

struct ai_vfs_fs_corruption_payload {
	u8 type;			/* AI_VFS_SUB_FS_CORRUPTION */
	u64 ino;
	u8 error_type;			/* enum ai_vfs_fs_err_type */
	u8 pad[7];
	char fs_type[32];
	char dev[32];
};

/* ==================================================================
 * 决策统计
 * ================================================================== */

struct ai_vfs_stats {
	u64 dcache_hook_calls;
	u64 dcache_ai_veto;		/* AI 保留 dentry 次数 */
	u64 inode_hook_calls;
	u64 inode_ai_veto;
	u64 path_hook_calls;
	u64 writeback_hook_calls;
	u64 writeback_ai_adjusted;
	u64 epoll_hook_calls;
	u64 aio_hook_calls;
	u64 dax_hook_calls;
	u64 rw_hook_calls;
	u64 dentry_hit, dentry_miss;	/* dcache 查找命中/未命中 */
	u64 inode_hit, inode_miss;	/* inode 哈希查找命中/未命中 */
	u64 path_overflow;		/* 超长路径整条丢弃计数 */
	u64 emitted[AI_VFS_SUB_MAX];	/* 各子事件成功发射计数 */
};

#ifdef CONFIG_AIKERNEL_VFS

/* ---- A 轨：推理/控制 Hook（ai_vfs.c 实现，全部 EXPORT_SYMBOL_GPL） ---- */

/**
 * ai_vfs_dcache_hook() - AI 决定 dentry 缓存驱逐
 * @dentry: 待驱逐的 dentry
 * @op:     驱逐路径（AI_VFS_EVICT_DENTRY=dput 引用归零，可干预；
 *          AI_VFS_EVICT_LRU=shrink LRU 驱逐，本步仅观察记录不干预）
 *
 * 返回 true=允许驱逐（默认，原逻辑）；false=保留（仅 DENTRY 路径生效：
 * 走 retain 路径放回 LRU 并置 DCACHE_REFERENCED，不改变 LRU 顺序语义；
 * 若条目本身不可保留（DONTCACHE/submount）则仍按原逻辑回收，防止死循环）。
 */
bool ai_vfs_dcache_hook(struct dentry *dentry, int op);

/**
 * ai_vfs_inode_hook() - AI 决定 inode 缓存驱逐
 * @inode: 待回收的 inode
 *
 * 返回 true=继续回收（默认，原逻辑）；false=保留（走 LRU 缓存路径，
 * 本步为决策点框架：实际保留动作由 iput_final 的 LRU 分支承载，AI 后续填充）。
 */
bool ai_vfs_inode_hook(struct inode *inode);

/**
 * ai_vfs_path_hook() - AI 预测下一步路径（预取建议）
 * @parent: 当前组件父 dentry
 * @last:   当前组件名
 * @flags:  解析标志（LOOKUP_*）
 *
 * 返回 0=不改（默认）；AI 预取/路径预测建议预留位。
 */
int ai_vfs_path_hook(struct dentry *parent, const struct qstr *last,
		     unsigned int flags);

/**
 * ai_vfs_writeback_hook() - AI 决定回写时机/批量
 * @wb:        bdi 回写单元
 * @nr_pages:  本轮计划回写页数（AI 可改：0=本轮跳过，N=批量上限）
 * @reason:    回写原因（enum wb_reason）
 *
 * 空实现不改（原逻辑）。
 */
void ai_vfs_writeback_hook(struct bdi_writeback *wb, long *nr_pages,
			   int reason);

struct eventpoll;	/* fs/eventpoll.c 私有类型，前向声明 */

/**
 * ai_vfs_epoll_hook() - AI 重排 epoll 就绪事件优先级
 * @ep:        eventpoll 实例
 * @maxevents: 本轮最大事件数（AI 可改）
 *
 * 返回 0=默认遍历（原逻辑）；AI 重排建议预留位。
 */
int ai_vfs_epoll_hook(struct eventpoll *ep, int maxevents);

struct kioctx;		/* fs/aio.c 私有类型，前向声明 */

/**
 * ai_vfs_aio_hook() - AI 聚合 AIO 异步 I/O 请求
 * @ctx:  kioctx 上下文
 * @iocb: 待提交请求（调用点 const）
 * @rw:   1=写 0=读
 *
 * 返回 0=放行（默认）；AI 批处理建议预留位。
 */
int ai_vfs_aio_hook(struct kioctx *ctx, const struct iocb *iocb, int rw);

/**
 * ai_vfs_dax_hook() - AI 预测 PMEM 访问模式
 * @iocb:     DAX I/O 控制块
 * @iter:     I/O 迭代器
 * @prefetch: 预取建议输出（AI 可置 true 建议预取）
 *
 * 空实现不改（原逻辑）。
 */
void ai_vfs_dax_hook(struct kiocb *iocb, struct iov_iter *iter,
		     bool *prefetch);

/**
 * ai_vfs_rw_hook() - AI 读写控制通道（预留）
 * @file:   目标文件
 * @rw:     1=写 0=读
 * @offset: 当前偏移
 * @count:  请求字节数（AI 可改）
 *
 * 返回 true=放行（默认）；false=本次拒绝（返回 -EPERM 语义由调用方处理）。
 */
bool ai_vfs_rw_hook(struct file *file, int rw, loff_t offset,
		    size_t *count);

/**
 * ai_vfs_exec_command_hook() - exec 命令行感知钩子（预留）
 * @bprm: exec 二进制参数块（含完整 argv/envp）
 *
 * B 轨第5类 exec_command（完整命令行）的预留钩子：本步仅声明+空实现，
 * 实际接入 fs/exec.c 与命令行采集由后续 Prompt 落地。
 */
void ai_vfs_exec_command_hook(struct linux_binprm *bprm);

/* ---- 决策框架（占位启发式，AI 推理后续步骤替换） ---- */

/**
 * ai_vfs_predict_dentry_reuse() - dentry 未来访问概率预测
 * @dentry:    目标 dentry
 * @out_score: 输出 0~100 访问概率分
 *
 * 占位启发式：按 d_name 哈希访问频次表（64 槽 EWMA）。
 */
int ai_vfs_predict_dentry_reuse(struct dentry *dentry, u8 *out_score);

/**
 * ai_vfs_stats_read() - 决策统计读取
 * @st: 统计输出
 */
void ai_vfs_stats_read(struct ai_vfs_stats *st);

/**
 * ai_vfs_sample_take() - 子事件采样判定（per-CPU 无锁）
 * @sub: 子事件编号（1~AI_VFS_SUB_MAX-1）
 *
 * rate==0 → false（关闭）；rate==1 → true（全量）；rate==N → 每 N 次记 1 条。
 */
bool ai_vfs_sample_take(u16 sub);

/**
 * ai_vfs_set_sub_rate() - 覆盖子事件采样率
 * @sub:  子事件编号
 * @rate: 0=丢弃 1=全量 N=每 N 条记 1 条
 */
int ai_vfs_set_sub_rate(u16 sub, u32 rate);

/**
 * ai_vfs_get_sub_rate() - 读取子事件采样率
 * @sub:  子事件编号
 * @rate: 输出当前采样率
 */
int ai_vfs_get_sub_rate(u16 sub, u32 *rate);

/* ---- B 轨：发射辅助（ai_vfs.c 实现，全部 EXPORT_SYMBOL_GPL） ---- */

void ai_telemetry_vfs_open(struct file *file);
void ai_telemetry_vfs_close(struct file *file);
void ai_telemetry_vfs_read(struct file *file, loff_t offset, size_t bytes);
void ai_telemetry_vfs_write(struct file *file, loff_t offset, size_t bytes);
void ai_telemetry_vfs_stat(const struct path *path);
void ai_telemetry_vfs_mkdir(const struct path *parent, const char *name,
			    umode_t mode);
void ai_telemetry_vfs_unlink(const struct path *path);
void ai_telemetry_vfs_rename(const struct path *old_path,
			     const struct path *new_path);
void ai_telemetry_vfs_symlink(const char *target, const struct path *link_path);
void ai_telemetry_vfs_chmod(const struct path *path, umode_t old_mode,
			    umode_t new_mode);
void ai_telemetry_vfs_chown(const struct path *path, uid_t old_uid,
			    uid_t new_uid);
void ai_telemetry_writeback(struct bdi_writeback *wb, long nr_pages,
			    int reason);
void ai_telemetry_path_lookup(const struct path *path, const struct qstr *last,
			      u32 depth, u32 symlinks, u32 mounts,
			      u64 latency_ns);
/* path_lookup_cache 事件：采样判定由 ai_vfs_dcache_lookup 完成，
 * 本函数为已判定直发（携带累计 hit/miss 快照）。 */
void ai_telemetry_path_lookup_cache(void);

/**
 * ai_vfs_dcache_lookup() - dcache 查找命中/未命中计数（热路径优化：采样）
 * @hit: true=命中 false=未命中
 *
 * 由 fs/dcache.c __d_lookup_rcu()/__d_lookup() 每次查找调用。
 * 性能设计：每次查找仅 1 次 per-CPU 计数 + 分支；命中/未命中按 1/32
 * 采样累计（比率语义不变，近似统计），每 32 次查找发射一次
 * path_lookup_cache 事件（累计快照）。
 */
void ai_vfs_dcache_lookup(bool hit);

/**
 * ai_vfs_inode_lookup() - inode 哈希查找命中/未命中计数（全量，非采样）
 * @hit: true=命中 false=未命中
 *
 * 由 fs/inode.c find_inode()/find_inode_fast() 每次查找调用。
 */
void ai_vfs_inode_lookup(bool hit);

/**
 * ai_vfs_inode_veto_note() - 记录一次不可执行的 inode 保留决策
 *
 * AI 建议保留但 superblock 已不活跃（保留不可行）时由 fs/inode.c 调用。
 */
void ai_vfs_inode_veto_note(void);
void ai_telemetry_mount(const char *dev_name, const struct path *mnt_point,
			const char *fs_type, unsigned long flags,
			const char *options);
void ai_telemetry_umount(const struct path *path, int flags);
void ai_telemetry_file_lock_set(struct file *file, int type, u64 start,
				u64 len, bool blocking);
void ai_telemetry_file_lock_conflict(struct file *file, pid_t holder_pid,
				     int type);
void ai_telemetry_epoll_create(int flags);
void ai_telemetry_epoll_ctl(int epfd, int op, int fd, u32 events);
void ai_telemetry_epoll_wait(int epfd, int ready_count, u64 wait_duration_us);
void ai_telemetry_inotify_event(struct inode *inode, struct inode *dir,
				const struct qstr *name, int wd, u32 mask);
void ai_telemetry_fs_error(struct super_block *sb, u8 error_type,
			   int error_code, u64 ino);
void ai_telemetry_fs_corruption(struct super_block *sb, u64 ino,
				u8 error_type);

#else /* !CONFIG_AIKERNEL_VFS */

/* 空函数兜底：CONFIG_AIKERNEL_VFS=n 时 fs/ 不包含本头文件，
 * 此处兜底仅防御性提供（保证任何遗留引用编译通过且零开销）。 */

static inline bool ai_vfs_dcache_hook(struct dentry *dentry, int op)
{ return true; }
static inline bool ai_vfs_inode_hook(struct inode *inode) { return true; }
static inline int ai_vfs_path_hook(struct dentry *parent,
				   const struct qstr *last,
				   unsigned int flags) { return 0; }
static inline void ai_vfs_writeback_hook(struct bdi_writeback *wb,
					 long *nr_pages, int reason) { }
static inline int ai_vfs_epoll_hook(struct eventpoll *ep, int maxevents)
{ return 0; }
static inline int ai_vfs_aio_hook(struct kioctx *ctx,
				  const struct iocb *iocb, int rw) { return 0; }
static inline void ai_vfs_dax_hook(struct kiocb *iocb, struct iov_iter *iter,
				   bool *prefetch) { }
static inline bool ai_vfs_rw_hook(struct file *file, int rw, loff_t offset,
				  size_t *count) { return true; }
static inline void ai_vfs_exec_command_hook(struct linux_binprm *bprm) { }
static inline int ai_vfs_predict_dentry_reuse(struct dentry *dentry,
					      u8 *out_score)
{ if (out_score) *out_score = 50; return AI_OK; }
static inline void ai_vfs_stats_read(struct ai_vfs_stats *st)
{ if (st) memset(st, 0, sizeof(*st)); }
static inline bool ai_vfs_sample_take(u16 sub) { return false; }
static inline int ai_vfs_set_sub_rate(u16 sub, u32 rate) { return AI_OK; }
static inline int ai_vfs_get_sub_rate(u16 sub, u32 *rate)
{ if (rate) *rate = 1; return AI_OK; }
static inline void ai_telemetry_vfs_open(struct file *file) { }
static inline void ai_telemetry_vfs_close(struct file *file) { }
static inline void ai_telemetry_vfs_read(struct file *file, loff_t offset,
					 size_t bytes) { }
static inline void ai_telemetry_vfs_write(struct file *file, loff_t offset,
					  size_t bytes) { }
static inline void ai_telemetry_vfs_stat(const struct path *path) { }
static inline void ai_telemetry_vfs_mkdir(const struct path *parent,
					  const char *name, umode_t mode) { }
static inline void ai_telemetry_vfs_unlink(const struct path *path) { }
static inline void ai_telemetry_vfs_rename(const struct path *old_path,
					   const struct path *new_path) { }
static inline void ai_telemetry_vfs_symlink(const char *target,
					    const struct path *link_path) { }
static inline void ai_telemetry_vfs_chmod(const struct path *path,
					  umode_t old_mode, umode_t new_mode) { }
static inline void ai_telemetry_vfs_chown(const struct path *path,
					  uid_t old_uid, uid_t new_uid) { }
static inline void ai_telemetry_writeback(struct bdi_writeback *wb,
					  long nr_pages, int reason) { }
static inline void ai_telemetry_path_lookup(const struct path *path,
					    const struct qstr *last,
					    u32 depth, u32 symlinks,
					    u32 mounts, u64 latency_ns) { }
static inline void ai_telemetry_path_lookup_cache(void) { }
static inline void ai_vfs_dcache_lookup(bool hit) { }
static inline void ai_vfs_inode_lookup(bool hit) { }
static inline void ai_vfs_inode_veto_note(void) { }
static inline void ai_telemetry_mount(const char *dev_name,
				      const struct path *mnt_point,
				      const char *fs_type, unsigned long flags,
				      const char *options) { }
static inline void ai_telemetry_umount(const struct path *path, int flags) { }
static inline void ai_telemetry_file_lock_set(struct file *file, int type,
					      u64 start, u64 len,
					      bool blocking) { }
static inline void ai_telemetry_file_lock_conflict(struct file *file,
						   pid_t holder_pid,
						   int type) { }
static inline void ai_telemetry_epoll_create(int flags) { }
static inline void ai_telemetry_epoll_ctl(int epfd, int op, int fd,
					  u32 events) { }
static inline void ai_telemetry_epoll_wait(int epfd, int ready_count,
					   u64 wait_duration_us) { }
static inline void ai_telemetry_inotify_event(struct inode *inode,
					      struct inode *dir,
					      const struct qstr *name, int wd,
					      u32 mask) { }
static inline void ai_telemetry_fs_error(struct super_block *sb,
					 u8 error_type, int error_code,
					 u64 ino) { }
static inline void ai_telemetry_fs_corruption(struct super_block *sb,
					      u64 ino, u8 error_type) { }

#endif /* CONFIG_AIKERNEL_VFS */

#endif /* _AIKERNEL_VFS_AI_VFS_H */
