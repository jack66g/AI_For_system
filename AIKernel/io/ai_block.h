// SPDX-License-Identifier: GPL-2.0
/*
 * ai_block.h - AIKernel I/O 子系统统一接口头（Prompt 05）
 *
 * 本文件是 block/ 全部 AI 埋点的唯一接入点：
 *   A 轨（控制）：ai_io_*_hook() 系列 —— 让 AI 参与块层决策
 *                 （请求分发顺序/合并预测/写回节流/IO 限制/AI 调度器），
 *                 空实现 = 原样放行（返回值不改变内核默认行为）；
 *   B 轨（感知）：第3类 I/O 与存储感知的 payload 结构 + 发射辅助，
 *                 全量原始零脱敏（dev 名/sector/pid/comm 全保留）。
 *
 * 零回归策略：
 *   - CONFIG_AIKERNEL_IO=n：本头文件不参与任何编译（block/ 下各 .c 文件的
 *     条件 include 一并剔除），预处理产物与基线一致；
 *   - CONFIG_AIKERNEL_TELEMETRY=n：ai_telemetry_* 包装退化为 static inline
 *     空函数（ai_telemetry.h 内置兜底），Hook 本身只计数不发射。
 *
 * 遥测函数铁律：不阻塞、不分配（无 GFP_KERNEL）、无锁，仅供快速路径
 * （bio_endio / blk_mq_complete_request / blk_update_request 可能在硬中断
 *  上下文调用 —— 全部走 per-CPU ring buffer 直写）。
 *
 * 事件体系：第3类 I/O 与存储感知 6 个子类（AI_CAT_IO）：
 *   03.01 BIO / 03.02 blk-mq / 03.03 I/O 调度器 / 03.04 节流与 QoS /
 *   03.05 块设备状态（周期）/ 03.06 字符设备（字符设备事件见 ai_char.h）。
 */

#ifndef _AIKERNEL_IO_AI_BLOCK_H
#define _AIKERNEL_IO_AI_BLOCK_H

#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/part_stat.h>
#include <linux/ktime.h>
#include <linux/string.h>

/* ==================================================================
 * B 轨：第3类 I/O 与存储感知 payload（事件编号对齐 enum ai_event_type）
 * ==================================================================
 * 每个 payload 首字节为 u8 type，区分计划内的子事件。
 * 全量原始零脱敏：dev 名 / sector / pid / comm 全保留。
 */

/* 03.01 块层 BIO */
enum ai_bio_type {
	AI_BIO_QUEUE		= 1,	/* BIO 创建/入队（alloc 时 sector/nr_sectors=0） */
	AI_BIO_COMPLETE,		/* BIO 完成（含 latency_ns） */
	AI_BIO_MERGE,			/* BIO 合并 */
	AI_BIO_SPLIT,			/* BIO 拆分 */
};

struct ai_bio_queue_payload {
	u8 type;			/* AI_BIO_QUEUE */
	char dev[16];
	u64 sector;			/* alloc 时尚未设置，恒 0（语义见头注释） */
	u32 nr_sectors;			/* 同上 */
	u8 rw;				/* 1=写 0=读 */
	u32 pid;
	char comm[TASK_COMM_LEN];
};

struct ai_bio_complete_payload {
	u8 type;			/* AI_BIO_COMPLETE */
	char dev[16];
	u64 sector;			/* 完整位置信息 */
	u32 nr_sectors;
	u64 latency_ns;			/* alloc→endio（bio->issue_time_ns 记录起点） */
	u32 error;			/* bi_status */
};

struct ai_bio_merge_payload {
	u8 type;			/* AI_BIO_MERGE */
	char dev[16];
	u32 front_sectors;		/* 前向合并的 bio 扇区数 */
	u32 back_sectors;		/* 后向合并的 bio 扇区数 */
};

struct ai_bio_split_payload {
	u8 type;			/* AI_BIO_SPLIT */
	char dev[16];
	u32 nr_sectors;			/* 切出部分的扇区数 */
	u8 reason;			/* 保留（0） */
};

/* 03.02 blk-mq */
enum ai_blk_mq_type {
	AI_BLK_MQ_QUEUE_RQ	= 1,	/* 请求入硬件队列 */
	AI_BLK_MQ_COMPLETE_RQ,		/* 请求完成（含 latency_ns） */
};

struct ai_blk_mq_queue_rq_payload {
	u8 type;			/* AI_BLK_MQ_QUEUE_RQ */
	char dev[16];
	u16 hctx_idx;
	u16 cpu;
	u16 nr_pending;			/* 本批次剩余请求数近似 */
};

struct ai_blk_mq_complete_rq_payload {
	u8 type;			/* AI_BLK_MQ_COMPLETE_RQ */
	char dev[16];
	u16 hctx_idx;
	u64 latency_ns;			/* io_start_time_ns 起点（QUEUE_FLAG_STATS 时有效） */
};

/* 03.03 I/O 调度器 */
enum ai_io_sched_type {
	AI_IO_SCHED_INSERT	= 1,	/* 插入调度器 */
	AI_IO_SCHED_DISPATCH,		/* 分发 */
	AI_IO_SCHED_LATENCY,		/* 调度器平均延迟 */
	AI_IO_SCHED_SWITCH,		/* 调度器切换（elevator.c） */
};

struct ai_io_sched_insert_payload {
	u8 type;			/* AI_IO_SCHED_INSERT */
	char dev[16];
	char scheduler_name[16];
	u8 direction;			/* 1=写 0=读 */
};

struct ai_io_sched_dispatch_payload {
	u8 type;			/* AI_IO_SCHED_DISPATCH */
	char dev[16];
	char scheduler_name[16];
	u32 nr_dispatched;
};

struct ai_io_sched_latency_payload {
	u8 type;			/* AI_IO_SCHED_LATENCY */
	char dev[16];
	u64 avg_read_lat_ns;
	u64 avg_write_lat_ns;
};

struct ai_io_sched_switch_payload {
	u8 type;			/* AI_IO_SCHED_SWITCH */
	char dev[16];
	char old_sched[16];
	char new_sched[16];
	u32 pid;
	char comm[TASK_COMM_LEN];
};

/* 03.04 I/O 节流与 QoS */
enum ai_io_qos_type {
	AI_WBT_LATENCY		= 1,	/* 写回节流延迟 */
	AI_BLK_THROTTLE,		/* cgroup I/O 限制 */
	AI_BLK_IOCOST,			/* I/O 成本模型 */
};

struct ai_wbt_latency_payload {
	u8 type;			/* AI_WBT_LATENCY */
	char dev[16];
	u64 read_lat_ns;
	u64 write_lat_ns;
};

struct ai_blk_throttle_payload {
	u8 type;			/* AI_BLK_THROTTLE */
	char dev[16];
	char cgroup_path[64];
	u64 bytes_allowed;
	u64 bytes_used;
};

struct ai_blk_iocost_payload {
	u8 type;			/* AI_BLK_IOCOST */
	char dev[16];
	u64 vrate;
};

/* 03.05 块设备状态（周期性 + 错误） */
enum ai_disk_stats_type {
	AI_DISK_STATS		= 1,	/* 每秒完整磁盘统计 */
	AI_DISK_ERROR,			/* 磁盘 IO 错误（blk-mq 请求完成路径） */
	AI_DISK_EVENT,			/* 磁盘级状态事件（genhd.c disk_uevent） */
};

struct ai_disk_stats_payload {
	u8 type;			/* AI_DISK_STATS */
	char dev[16];
	u64 rd_ios;
	u64 rd_sectors;
	u64 wr_ios;
	u64 wr_sectors;
	u64 io_ticks;
	u32 avg_queue_depth;		/* in_flight EWMA 平滑 */
	u64 avg_wait_ns;		/* 累积平均等待 = nsecs/ios */
};

struct ai_disk_error_payload {
	u8 type;			/* AI_DISK_ERROR */
	char dev[16];
	u64 sector;
	u8 error_type;			/* req_op */
	u8 error_code;			/* blk_status_t */
};

struct ai_disk_event_payload {
	u8 type;			/* AI_DISK_EVENT */
	char dev[16];
	u8 action;			/* kobject_action */
};

/* 03.06 字符设备：见 AIKernel/io/ai_char.h */

/* ==================================================================
 * 决策统计
 * ================================================================== */

struct ai_io_stats {
	u64 dispatch_hook_calls;
	u64 merge_hook_calls;
	u64 wbt_hook_calls;
	u64 throttle_hook_calls;
	u64 sched_hook_calls;
	u64 entropy_hook_calls;
	u64 tty_hook_calls;
	u64 disk_stats_emitted;
	u64 disk_errors_emitted;
};

#ifdef CONFIG_AIKERNEL_IO

/* ---- A 轨：推理/控制 Hook（ai_block.c 实现，全部 EXPORT_SYMBOL_GPL） ---- */

/**
 * ai_io_dispatch_hook() - AI 优化请求分发顺序
 * @hctx: 硬件队列
 * @rq:   待分发请求
 *
 * 返回 false 则本次不分发该请求（留在列表等待下轮）；空实现返回 true 放行。
 */
bool ai_io_dispatch_hook(struct blk_mq_hw_ctx *hctx, struct request *rq);

/**
 * ai_io_merge_hook() - AI 判断请求是否合并
 * @req:  目标请求
 * @bio:  待合并 bio
 * @back: 1=后向合并 0=前向合并
 *
 * 返回 false 则阻止合并；空实现返回 true（放行内核物理检查结果）。
 */
bool ai_io_merge_hook(struct request *req, struct bio *bio, int back);

struct rq_wb;	/* block/blk-wbt.h 内部类型，前向声明 */

/**
 * ai_io_wbt_hook() - AI 调整写回节流决策
 * @rwb:    wbt 状态
 * @status: 当前 latency 判定（LAT_OK/EXCEEDED/UNKNOWN*）
 *
 * 返回替换后的 status；空实现返回原值。
 */
int ai_io_wbt_hook(struct rq_wb *rwb, int status);

struct throtl_grp;	/* block/blk-throttle.h 内部类型，前向声明 */

/**
 * ai_io_throttle_hook() - AI 动态调整 I/O 限制
 * @tg:         cgroup 节流组
 * @bio:        当前 bio
 * @bps_limit:  字节限制（AI 可修改）
 * @iops_limit: IOPS 限制（AI 可修改）
 *
 * 空实现不改（返回原值）。
 */
void ai_io_throttle_hook(struct throtl_grp *tg, struct bio *bio,
			 u64 *bps_limit, unsigned long *iops_limit);

/**
 * ai_io_sched_hook() - AI I/O 调度器决策接口
 * @hctx: 硬件队列
 * @dir:  建议的下一个分发方向（0=读 1=写）
 *
 * 返回 0 表示不改（按 deadline 默认决策）；返回非 0 表示采纳建议方向。
 */
int ai_io_sched_hook(struct blk_mq_hw_ctx *hctx, int *dir);

/* ---- 决策框架（占位启发式，AI 推理后续步骤替换） ---- */

/**
 * ai_io_predict_merge() - 合并收益预测
 *
 * 占位启发式：同方向且物理相邻 → 建议合并。
 */
bool ai_io_predict_merge(struct bio *bio, struct request *req, int back);

/**
 * ai_io_adjust_wbt() - 写回阈值建议
 *
 * 占位启发式：按 write 延迟滑动平均建议 scale 方向。
 */
int ai_io_adjust_wbt(struct rq_wb *rwb, int status);

/**
 * ai_io_stats_read() - 决策统计读取
 * @st: 统计输出
 */
void ai_io_stats_read(struct ai_io_stats *st);

/* ---- B 轨：发射辅助（ai_block.c 实现，全部 EXPORT_SYMBOL_GPL） ---- */

void ai_io_emit_bio_queue(struct bio *bio, struct block_device *bdev,
			  blk_opf_t opf);
void ai_io_emit_bio_complete(struct bio *bio);
void ai_io_emit_bio_merge(struct request *req, struct bio *bio, int back);
void ai_io_emit_bio_split(struct bio *bio, int sectors);
void ai_io_emit_blk_mq_queue_rq(struct blk_mq_hw_ctx *hctx, u16 nr_pending);
void ai_io_emit_blk_mq_complete_rq(struct request *rq);
void ai_io_emit_io_sched_insert(const char *dev, const char *sched_name,
				u8 direction);
void ai_io_emit_io_sched_dispatch(const char *dev, const char *sched_name,
				  u32 nr_dispatched);
void ai_io_emit_io_sched_latency(const char *dev,
				 u64 avg_read_lat_ns, u64 avg_write_lat_ns);
void ai_io_emit_io_sched_switch(const char *dev, const char *old_name,
				const char *new_name);
void ai_io_emit_wbt_latency(const char *dev, u64 read_lat_ns,
			    u64 write_lat_ns);
void ai_io_emit_blk_throttle(const char *dev, const char *cgroup_path,
			     u64 bytes_allowed, u64 bytes_used);
void ai_io_emit_blk_iocost(const char *dev, u64 vrate);
void ai_io_emit_disk_stats(void);
void ai_io_emit_disk_error(struct request *rq, blk_status_t error);
void ai_io_emit_disk_event(struct gendisk *disk, int action);

/* ---- 周期采样器 ---- */

/**
 * ai_io_metrics_sampler() - 每秒块设备状态采样 kthread 主体
 *
 * 遍历 block_class 全部磁盘，发射 disk_stats（全量不采样）。
 */
int ai_io_metrics_sampler(void *unused);

#else /* !CONFIG_AIKERNEL_IO */

/* 空函数兜底：CONFIG_AIKERNEL_IO=n 时 block/ 不包含本头文件，
 * 此处兜底仅防御性提供（保证任何遗留引用编译通过且零开销）。 */

static inline bool ai_io_dispatch_hook(struct blk_mq_hw_ctx *hctx,
				       struct request *rq) { return true; }
static inline bool ai_io_merge_hook(struct request *req, struct bio *bio,
				    int back) { return true; }
static inline int ai_io_wbt_hook(struct rq_wb *rwb, int status)
{ return status; }
static inline void ai_io_throttle_hook(struct throtl_grp *tg, struct bio *bio,
				       u64 *bps_limit, unsigned long *iops_limit)
{ }
static inline int ai_io_sched_hook(struct blk_mq_hw_ctx *hctx, int *dir)
{ return 0; }
static inline bool ai_io_predict_merge(struct bio *bio, struct request *req,
				       int back) { return true; }
static inline int ai_io_adjust_wbt(struct rq_wb *rwb, int status)
{ return status; }
static inline void ai_io_stats_read(struct ai_io_stats *st)
{ if (st) memset(st, 0, sizeof(*st)); }
static inline void ai_io_emit_bio_queue(struct bio *bio,
					struct block_device *bdev,
					blk_opf_t opf) { }
static inline void ai_io_emit_bio_complete(struct bio *bio) { }
static inline void ai_io_emit_bio_merge(struct request *req, struct bio *bio,
					int back) { }
static inline void ai_io_emit_bio_split(struct bio *bio, int sectors) { }
static inline void ai_io_emit_blk_mq_queue_rq(struct blk_mq_hw_ctx *hctx,
					      u16 nr_pending) { }
static inline void ai_io_emit_blk_mq_complete_rq(struct request *rq) { }
static inline void ai_io_emit_io_sched_insert(const char *dev,
					      const char *sched_name,
					      u8 direction) { }
static inline void ai_io_emit_io_sched_dispatch(const char *dev,
						const char *sched_name,
						u32 nr_dispatched) { }
static inline void ai_io_emit_io_sched_latency(const char *dev,
					       u64 avg_read_lat_ns,
					       u64 avg_write_lat_ns) { }
static inline void ai_io_emit_io_sched_switch(const char *dev,
					      const char *old_name,
					      const char *new_name) { }
static inline void ai_io_emit_wbt_latency(const char *dev, u64 read_lat_ns,
					  u64 write_lat_ns) { }
static inline void ai_io_emit_blk_throttle(const char *dev,
					   const char *cgroup_path,
					   u64 bytes_allowed,
					   u64 bytes_used) { }
static inline void ai_io_emit_blk_iocost(const char *dev, u64 vrate) { }
static inline void ai_io_emit_disk_stats(void) { }
static inline void ai_io_emit_disk_error(struct request *rq,
					 blk_status_t error) { }
static inline void ai_io_emit_disk_event(struct gendisk *disk, int action) { }
static inline int ai_io_metrics_sampler(void *unused) { return 0; }

#endif /* CONFIG_AIKERNEL_IO */

#endif /* _AIKERNEL_IO_AI_BLOCK_H */
