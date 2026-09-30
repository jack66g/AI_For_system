// SPDX-License-Identifier: GPL-2.0
/*
 * ai_block.c - AIKernel I/O 子系统核心（Prompt 05）
 *
 * A 轨：块层 Hook 空实现（= 原样放行）+ 决策框架占位启发式 + 决策计数。
 * B 轨：第3类 I/O 与存储感知发射辅助（sample_take + emit_direct 直写）
 *       + 每秒磁盘统计采样器。
 *
 * 门控：CONFIG_AIKERNEL_IO。CONFIG_AIKERNEL_TELEMETRY=n 时本文件仍编译
 * （Hook 计数 + 空放行），发射辅助退化为无操作（emit_direct stub）。
 *
 * 铁律：
 *   - 全部发射路径无锁、无分配（GFP_KERNEL）、不睡眠 —— bio_endio /
 *     blk_mq_complete_request / blk_update_request 可能在硬中断上下文；
 *   - 全部 Hook 空实现 = 原样放行（返回值不改变内核默认行为）；
 *   - 感知数据全量原始零脱敏（dev 名 / sector / pid / comm 全保留）。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/device.h>
#include <linux/blkdev.h>
#include <linux/part_stat.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/ioprio.h>
#include <linux/delay.h>

#include "ai_block.h"
#include "../core/ai_control.h"
#include <linux/ai_accessors.h>

/* ==================================================================
 * A 轨：Hook 空实现（= 原样放行）+ 决策计数
 * ================================================================== */

static DEFINE_PER_CPU(struct ai_io_stats, ai_io_cnt);

/* ai_char.c 提供的字符设备 Hook 计数（熵源/TTY） */
extern void ai_io_char_stats_read(u64 *entropy_calls, u64 *tty_calls);

bool ai_io_dispatch_hook(struct blk_mq_hw_ctx *hctx, struct request *rq)
{
	this_cpu_inc(ai_io_cnt.dispatch_hook_calls);
	return true;
}
EXPORT_SYMBOL_GPL(ai_io_dispatch_hook);

bool ai_io_merge_hook(struct request *req, struct bio *bio, int back)
{
	this_cpu_inc(ai_io_cnt.merge_hook_calls);
	return true;
}
EXPORT_SYMBOL_GPL(ai_io_merge_hook);

int ai_io_wbt_hook(struct rq_wb *rwb, int status)
{
	this_cpu_inc(ai_io_cnt.wbt_hook_calls);
	return status;
}
EXPORT_SYMBOL_GPL(ai_io_wbt_hook);

void ai_io_throttle_hook(struct throtl_grp *tg, struct bio *bio,
			 u64 *bps_limit, unsigned long *iops_limit)
{
	this_cpu_inc(ai_io_cnt.throttle_hook_calls);
}
EXPORT_SYMBOL_GPL(ai_io_throttle_hook);

int ai_io_sched_hook(struct blk_mq_hw_ctx *hctx, int *dir)
{
	this_cpu_inc(ai_io_cnt.sched_hook_calls);
	return 0;
}
EXPORT_SYMBOL_GPL(ai_io_sched_hook);

/* ---- 决策框架（占位启发式，AI 推理后续步骤替换） ---- */

bool ai_io_predict_merge(struct bio *bio, struct request *req, int back)
{
	if (!bio || !req)
		return false;
	/* 占位：同方向（rq_data_dir）且物理相邻 → 建议合并 */
	if (rq_data_dir(req) == bio_data_dir(bio) &&
	    bio_sectors(bio) > 0) {
		if (back && blk_rq_pos(req) + blk_rq_sectors(req) ==
		    bio->bi_iter.bi_sector)
			return true;
		if (!back && bio->bi_iter.bi_sector + bio_sectors(bio) ==
		    blk_rq_pos(req))
			return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(ai_io_predict_merge);

int ai_io_adjust_wbt(struct rq_wb *rwb, int status)
{
	/* 占位：当前不做调整，返回原判定 */
	return status;
}
EXPORT_SYMBOL_GPL(ai_io_adjust_wbt);

void ai_io_stats_read(struct ai_io_stats *st)
{
	u64 entropy_calls = 0, tty_calls = 0;
	int cpu;

	memset(st, 0, sizeof(*st));
	for_each_possible_cpu(cpu) {
		const struct ai_io_stats *c = per_cpu_ptr(&ai_io_cnt, cpu);

		st->dispatch_hook_calls += c->dispatch_hook_calls;
		st->merge_hook_calls += c->merge_hook_calls;
		st->wbt_hook_calls += c->wbt_hook_calls;
		st->throttle_hook_calls += c->throttle_hook_calls;
		st->sched_hook_calls += c->sched_hook_calls;
		st->disk_stats_emitted += c->disk_stats_emitted;
		st->disk_errors_emitted += c->disk_errors_emitted;
	}
	ai_io_char_stats_read(&entropy_calls, &tty_calls);
	st->entropy_hook_calls = entropy_calls;
	st->tty_hook_calls = tty_calls;
}
EXPORT_SYMBOL_GPL(ai_io_stats_read);

/* ==================================================================
 * B 轨：发射辅助（sample_take 采样判定 → 构建 payload → emit_direct）
 * ================================================================== */

static void ai_io_dev_from_bdev(struct block_device *bdev, char *out,
				size_t size)
{
	struct gendisk *disk;

	if (!bdev) {
		strscpy(out, "?", size);
		return;
	}
	disk = bdev->bd_disk;
	if (disk)
		strscpy(out, disk->disk_name, size);
	else
		strscpy(out, "?", size);
}

static void ai_io_dev_from_req(struct request *rq, char *out, size_t size)
{
	struct gendisk *disk = rq->q ? rq->q->disk : NULL;

	if (disk)
		strscpy(out, disk->disk_name, size);
	else
		strscpy(out, "?", size);
}

void ai_io_emit_bio_queue(struct bio *bio, struct block_device *bdev,
			  blk_opf_t opf)
{
	struct ai_bio_queue_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_BIO))
		return;

	p.type = AI_BIO_QUEUE;
	ai_io_dev_from_bdev(bdev, p.dev, sizeof(p.dev));
	p.sector = 0;
	p.nr_sectors = 0;
	p.rw = op_is_write(opf) ? 1 : 0;
	p.pid = task_pid_nr(current);
	strscpy(p.comm, current->comm, TASK_COMM_LEN);
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_BIO, AI_SEV_DEBUG, &p, sizeof(p));

	/* 记录 BIO 生命周期起点（bio_complete 的 latency_ns 数据源）。
	 * 仅 CONFIG_BLK_CGROUP=y 时该字段存在；bio_init 每次分配归零。
	 * 与 blk-iolatency 共用同一字段（其语义 = 延迟起点，此处起点更早
	 * 仅使双功能同时启用时 iolatency 统计含排队时间，语义仍正确）。 */
#ifdef CONFIG_BLK_CGROUP
	if (bio)
		bio->issue_time_ns = ktime_get_ns();
#endif
}
EXPORT_SYMBOL_GPL(ai_io_emit_bio_queue);

void ai_io_emit_bio_complete(struct bio *bio)
{
	struct ai_bio_complete_payload p;
	u64 issued = 0;

	if (!bio || !ai_telemetry_sample_take(AI_CAT_IO, AI_EV_BIO))
		return;

#ifdef CONFIG_BLK_CGROUP
	issued = bio->issue_time_ns;
#endif
	p.type = AI_BIO_COMPLETE;
	ai_io_dev_from_bdev(bio->bi_bdev, p.dev, sizeof(p.dev));
	p.sector = bio->bi_iter.bi_sector;
	p.nr_sectors = bio_sectors(bio);
	p.latency_ns = issued ? ktime_get_ns() - issued : 0;
	p.error = bio->bi_status;
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_BIO, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_bio_complete);

void ai_io_emit_bio_merge(struct request *req, struct bio *bio, int back)
{
	struct ai_bio_merge_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_BIO))
		return;

	p.type = AI_BIO_MERGE;
	ai_io_dev_from_req(req, p.dev, sizeof(p.dev));
	p.front_sectors = back ? 0 : bio_sectors(bio);
	p.back_sectors = back ? bio_sectors(bio) : 0;
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_BIO, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_bio_merge);

void ai_io_emit_bio_split(struct bio *bio, int sectors)
{
	struct ai_bio_split_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_BIO))
		return;

	p.type = AI_BIO_SPLIT;
	ai_io_dev_from_bdev(bio->bi_bdev, p.dev, sizeof(p.dev));
	p.nr_sectors = sectors;
	p.reason = 0;
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_BIO, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_bio_split);

void ai_io_emit_blk_mq_queue_rq(struct blk_mq_hw_ctx *hctx, u16 nr_pending)
{
	struct ai_blk_mq_queue_rq_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_BLK_MQ))
		return;

	p.type = AI_BLK_MQ_QUEUE_RQ;
	{
		struct gendisk *disk = hctx->queue->disk;

		if (disk)
			strscpy(p.dev, disk->disk_name, sizeof(p.dev));
		else
			strscpy(p.dev, "?", sizeof(p.dev));
	}
	p.hctx_idx = hctx->queue_num;
	p.cpu = smp_processor_id();
	p.nr_pending = nr_pending;
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_BLK_MQ, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_blk_mq_queue_rq);

void ai_io_emit_blk_mq_complete_rq(struct request *rq)
{
	struct ai_blk_mq_complete_rq_payload p;
	u64 started = rq->io_start_time_ns;

	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_BLK_MQ))
		return;

	p.type = AI_BLK_MQ_COMPLETE_RQ;
	ai_io_dev_from_req(rq, p.dev, sizeof(p.dev));
	p.hctx_idx = rq->mq_hctx ? rq->mq_hctx->queue_num : 0;
	p.latency_ns = started ? ktime_get_ns() - started : 0;
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_BLK_MQ, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_blk_mq_complete_rq);

void ai_io_emit_io_sched_insert(const char *dev, const char *sched_name,
				u8 direction)
{
	struct ai_io_sched_insert_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_IO_SCHED))
		return;

	p.type = AI_IO_SCHED_INSERT;
	strscpy(p.dev, dev, sizeof(p.dev));
	strscpy(p.scheduler_name, sched_name, sizeof(p.scheduler_name));
	p.direction = direction;
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_IO_SCHED, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_io_sched_insert);

void ai_io_emit_io_sched_dispatch(const char *dev, const char *sched_name,
				  u32 nr_dispatched)
{
	struct ai_io_sched_dispatch_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_IO_SCHED))
		return;

	p.type = AI_IO_SCHED_DISPATCH;
	strscpy(p.dev, dev, sizeof(p.dev));
	strscpy(p.scheduler_name, sched_name, sizeof(p.scheduler_name));
	p.nr_dispatched = nr_dispatched;
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_IO_SCHED, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_io_sched_dispatch);

void ai_io_emit_io_sched_latency(const char *dev, u64 avg_read_lat_ns,
				 u64 avg_write_lat_ns)
{
	struct ai_io_sched_latency_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_IO_SCHED))
		return;

	p.type = AI_IO_SCHED_LATENCY;
	strscpy(p.dev, dev, sizeof(p.dev));
	p.avg_read_lat_ns = avg_read_lat_ns;
	p.avg_write_lat_ns = avg_write_lat_ns;
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_IO_SCHED, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_io_sched_latency);

void ai_io_emit_io_sched_switch(const char *dev, const char *old_name,
				const char *new_name)
{
	struct ai_io_sched_switch_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_IO_SCHED))
		return;

	p.type = AI_IO_SCHED_SWITCH;
	strscpy(p.dev, dev, sizeof(p.dev));
	strscpy(p.old_sched, old_name ? old_name : "none",
		sizeof(p.old_sched));
	strscpy(p.new_sched, new_name ? new_name : "none",
		sizeof(p.new_sched));
	p.pid = task_pid_nr(current);
	strscpy(p.comm, current->comm, TASK_COMM_LEN);
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_IO_SCHED, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_io_sched_switch);

void ai_io_emit_wbt_latency(const char *dev, u64 read_lat_ns,
			    u64 write_lat_ns)
{
	struct ai_wbt_latency_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_IO_QOS))
		return;

	p.type = AI_WBT_LATENCY;
	strscpy(p.dev, dev, sizeof(p.dev));
	p.read_lat_ns = read_lat_ns;
	p.write_lat_ns = write_lat_ns;
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_IO_QOS, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_wbt_latency);

void ai_io_emit_blk_throttle(const char *dev, const char *cgroup_path,
			     u64 bytes_allowed, u64 bytes_used)
{
	struct ai_blk_throttle_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_IO_QOS))
		return;

	p.type = AI_BLK_THROTTLE;
	strscpy(p.dev, dev, sizeof(p.dev));
	strscpy(p.cgroup_path, cgroup_path ? cgroup_path : "unknown",
		sizeof(p.cgroup_path));
	p.bytes_allowed = bytes_allowed;
	p.bytes_used = bytes_used;
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_IO_QOS, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_blk_throttle);

void ai_io_emit_blk_iocost(const char *dev, u64 vrate)
{
	struct ai_blk_iocost_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_IO, AI_EV_IO_QOS))
		return;

	p.type = AI_BLK_IOCOST;
	strscpy(p.dev, dev, sizeof(p.dev));
	p.vrate = vrate;
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_IO_QOS, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_blk_iocost);

void ai_io_emit_disk_error(struct request *rq, blk_status_t error)
{
	struct ai_disk_error_payload p;

	/* 错误事件全量直写（不采样）：低频但重要，severity=IMPORTANT */
	if (ai_telemetry_sample_take(AI_CAT_IO, AI_EV_DISK_STATS) == false)
		return;

	p.type = AI_DISK_ERROR;
	ai_io_dev_from_req(rq, p.dev, sizeof(p.dev));
	p.sector = blk_rq_pos(rq);
	p.error_type = req_op(rq);
	p.error_code = (u8)error;
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_DISK_STATS, AI_SEV_IMPORTANT, &p, sizeof(p));
	this_cpu_inc(ai_io_cnt.disk_errors_emitted);
}
EXPORT_SYMBOL_GPL(ai_io_emit_disk_error);

void ai_io_emit_disk_event(struct gendisk *disk, int action)
{
	struct ai_disk_event_payload p;

	if (!disk || !ai_telemetry_sample_take(AI_CAT_IO, AI_EV_DISK_STATS))
		return;

	p.type = AI_DISK_EVENT;
	strscpy(p.dev, disk->disk_name, sizeof(p.dev));
	p.action = (u8)action;
	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_DISK_STATS, AI_SEV_IMPORTANT, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_io_emit_disk_event);

/* ==================================================================
 * 每秒磁盘统计采样器（ai_io_metrics_sampler）
 * ================================================================== */

/* per-disk EWMA 平滑状态（磁盘数上限 32，单写者线程，无锁） */
#define AI_IO_MAX_DISKS 32

struct ai_io_disk_state {
	const struct gendisk *disk;
	u32 avg_queue_depth;
	u64 last_seen;			/* jiffies（清理用） */
};

static struct ai_io_disk_state ai_io_disk_state[AI_IO_MAX_DISKS];

static struct ai_io_disk_state *ai_io_disk_lookup(struct gendisk *disk,
						  bool create)
{
	struct ai_io_disk_state *st = NULL, *free = NULL;
	int i;

	for (i = 0; i < AI_IO_MAX_DISKS; i++) {
		if (ai_io_disk_state[i].disk == disk) {
			st = &ai_io_disk_state[i];
			break;
		}
		if (!free && !ai_io_disk_state[i].disk)
			free = &ai_io_disk_state[i];
	}
	if (!st && create && free) {
		st = free;
		st->disk = disk;
		st->avg_queue_depth = 0;
		st->last_seen = jiffies;
	}
	if (st)
		st->last_seen = jiffies;
	return st;
}

static void ai_io_sample_disk(struct gendisk *disk)
{
	struct ai_disk_stats_payload p;
	struct block_device *part = disk->part0;
	struct ai_io_disk_state *st;
	u64 rd_ios, wr_ios, rd_nsecs, wr_nsecs, wait;
	u32 inflight;

	if (!part || !part->bd_stats)
		return;

	p.type = AI_DISK_STATS;
	strscpy(p.dev, disk->disk_name, sizeof(p.dev));
	p.rd_ios = part_stat_read(part, ios[STAT_READ]);
	p.rd_sectors = part_stat_read(part, sectors[STAT_READ]);
	p.wr_ios = part_stat_read(part, ios[STAT_WRITE]);
	p.wr_sectors = part_stat_read(part, sectors[STAT_WRITE]);
	p.io_ticks = part_stat_read(part, io_ticks);

	rd_nsecs = part_stat_read(part, nsecs[STAT_READ]);
	wr_nsecs = part_stat_read(part, nsecs[STAT_WRITE]);
	rd_ios = p.rd_ios;
	wr_ios = p.wr_ios;
	wait = rd_ios + wr_ios ? (rd_nsecs + wr_nsecs) / (rd_ios + wr_ios) : 0;
	p.avg_wait_ns = wait;

	inflight = part_stat_local_read(part, in_flight[0]) +
		   part_stat_local_read(part, in_flight[1]);

	st = ai_io_disk_lookup(disk, true);
	if (st) {
		if (st->avg_queue_depth == 0)
			st->avg_queue_depth = inflight;
		else
			st->avg_queue_depth = (st->avg_queue_depth * 3 +
					       inflight) / 4;
		p.avg_queue_depth = st->avg_queue_depth;
	} else {
		p.avg_queue_depth = inflight;
	}

	ai_telemetry_emit_direct(AI_CAT_IO, AI_EV_DISK_STATS, AI_SEV_NORMAL, &p, sizeof(p));
	this_cpu_inc(ai_io_cnt.disk_stats_emitted);
}

int ai_io_metrics_sampler(void *unused)
{
	while (!kthread_should_stop()) {
		struct class_dev_iter it;
		struct device *dev;

		class_dev_iter_init(&it, &block_class, NULL, NULL);
		while ((dev = class_dev_iter_next(&it)))
			ai_io_sample_disk(dev_to_disk(dev));
		class_dev_iter_exit(&it);

		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ);
	}
	return 0;
}

/* ==================================================================
 * 初始化
 * ================================================================== */

/* ---- io.priority 立即生效参数（task 作用域，block/blk-ioc.c 导出符号） ----
 * 值语义：0~7 = IOPRIO_CLASS_BE 内 level（0 最高、7 最低，与 ionice(1) 一致，
 * 默认 4 = IOPRIO_NORM）。与 sched.nice apply 拒绝 RT 任务同源的安全边界：
 * 刻意不暴露 IOPRIO_CLASS_RT/IDLE，AI 决策只在 BE 类内调权（零特权提升）。
 * CONFIG_BLOCK=n 时本函数剔除，注册退回接口预留（NULL）。 */
#ifdef CONFIG_BLOCK
static int ai_block_ioprio_apply(struct ai_control_param *p, s32 pid,
				 s64 value, s64 *eff)
{
	struct task_struct *task;

	if (pid <= 0)
		return AI_ERR_INVALID_ARG;
	if (value < 0 || value > 7)
		return AI_ERR_INVALID_ARG;
	task = find_get_task_by_vpid(pid);
	if (!task)
		return AI_ERR_NOT_FOUND;
	set_task_ioprio(task, IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, (int)value));
	put_task_struct(task);
	if (eff)
		*eff = value;
	pr_info("AIKernel: io.priority (BE) %lld -> %lld (pid=%d)\n",
		p ? p->cur : -1, value, pid);
	return AI_OK;
}
#endif /* CONFIG_BLOCK */

static struct task_struct *ai_io_sampler_task;


/* ---- io.bandwidth 立即生效参数（bdi 写回带宽分摊比） ----
 * value=写回带宽上限百分比，经 mm/backing-dev.c 门控访问器写全部已
 * 注册 bdi 的 max_ratio（/sys/class/bdi/<dev> 下 max_ratio 节点同源，bdi_set_max_ratio
 * 上游导出接口）；value=0 语义映射恢复无限制（100%）。 */
static int ai_block_bandwidth_apply(struct ai_control_param *p, s32 pid,
				    s64 value, s64 *eff)
{
	unsigned int pct = 0;
	int rc;

	if (value < 0 || value > 100)
		return AI_ERR_INVALID_ARG;
	rc = ai_bdi_max_ratio_set((unsigned int)value, &pct);
	if (rc)
		return AI_ERR_GENERIC;
	*eff = pct;
	pr_info("AIKernel: io.bandwidth %lld -> bdi max_ratio %u%%\n",
		value, pct);
	return AI_OK;
}

static int __init ai_io_init(void)
{
	/* 幂等：CONFIG_AIKERNEL_RUNTIME 已在 start_kernel 调用过则无操作 */
	ai_telemetry_init();

	/* 热路径事件默认采样率（其余事件全量）：
	 * BIO=1/32、BLK_MQ=1/32、IO_SCHED=1/16、CHAR_DEV=1/32（ai_char.c 同设）、
	 * IO_QOS/DISK_STATS 全量（低频/每秒一次）。 */
	ai_telemetry_set_sample_rate(AI_CAT_IO, AI_EV_BIO, 32);
	ai_telemetry_set_sample_rate(AI_CAT_IO, AI_EV_BLK_MQ, 32);
	ai_telemetry_set_sample_rate(AI_CAT_IO, AI_EV_IO_SCHED, 16);

	/* 可控制参数表（数据计划 20.3 I/O 域）：io.priority 立即生效
	 * （task 作用域，经 block/blk-ioc.c set_task_ioprio 导出符号），
	 * io.bandwidth 接口预留（安全/记录全量生效，内核行为接线在后续步骤） */
#ifdef CONFIG_BLOCK
	ai_control_register("io.priority", AI_POLICY_DOMAIN_IO,
			    AI_CTRL_F_REAL | AI_CTRL_F_TASK,
			    0, 7, 4, ai_block_ioprio_apply);
#else
	ai_control_register("io.priority", AI_POLICY_DOMAIN_IO, 0,
			    0, 7, 4, NULL);
#endif
	ai_control_register("io.bandwidth", AI_POLICY_DOMAIN_IO,
			    AI_CTRL_F_REAL, 0, 100, 100,
			    ai_block_bandwidth_apply);

	ai_io_sampler_task = kthread_run(ai_io_metrics_sampler, NULL,
					 "ai-io-metrics");
	if (IS_ERR(ai_io_sampler_task)) {
		pr_warn("AIKernel: failed to start io metrics sampler\n");
		ai_io_sampler_task = NULL;
	}

	pr_info("AIKernel: io subsystem ready (AI hooks + telemetry)\n");
	return 0;
}

late_initcall(ai_io_init);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AIKernel I/O subsystem: block hooks + class-3 telemetry");
