// SPDX-License-Identifier: GPL-2.0
/*
 * ai_bfq.c - AIKernel AI I/O 调度器类（Prompt 05）
 *
 * 注册为独立调度器 `ai`（elevator 注册表 elv_list）：
 *   echo ai > /sys/block/<dev>/queue/scheduler
 *
 * 设计（基础版）：
 *   - 数据结构 = 简化 deadline（mq-deadline 语义族）：
 *     每个队列一个 ai_sched_data（elevator_data），sort_list[2] 两棵按
 *     期限（rq->fifo_time）排序的 rb 树 + fifo_list[2] + dispatch 链表；
 *   - AI 决策接口 ai_io_sched_hook()：可建议下一次分发方向；
 *     空实现（AI 无推理/未启用）→ 按 deadline 默认决策
 *     （读优先 + writes_starved 写饥饿保护 + 期限过期优先 + fifo 批），
 *     与 mq-deadline 行为同族 —— 即"回退 mq-deadline 行为"；
 *   - 零回归：CONFIG_AIKERNEL_IO=n 时本文件不参与构建 → 不注册 → 默认
 *     调度器仍为原生 mq-deadline；AI 关闭时该调度器不可见。
 *
 * 遥测：io_sched_insert / io_sched_dispatch / io_sched_latency
 * （第3类 3.3 I/O 调度器，经 AIKernel/io/ai_block.h 发射辅助）。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <linux/math64.h>
#include <linux/ktime.h>

#include "../../block/elevator.h"
#include "../../block/blk-mq.h"
#include "../../block/blk-mq-sched.h"
#include "../../block/blk.h"

#include "ai_block.h"

/* 与 mq-deadline 同族参数（简化版固定值） */
#define AI_READ_EXPIRE		(HZ / 2)	/* 读期限 500ms（SOFT） */
#define AI_WRITE_EXPIRE		(5 * HZ)	/* 写期限 5s（SOFT） */
#define AI_WRITES_STARVED	2		/* 读最多饿死写的次数 */
#define AI_FIFO_BATCH		16		/* 同向连续分发批大小 */
#define AI_LAT_SAMPLE_HZ	1		/* 平均延迟每秒发射一次 */

struct ai_sched_data {
	struct rb_root sort_list[2];	/* 按 rq->fifo_time 排序 */
	struct list_head fifo_list[2];	/* 同向 FIFO（顺序 = 插入序） */
	struct list_head dispatch;	/* BLK_MQ_INSERT_AT_HEAD 直接分发 */
	spinlock_t lock;

	unsigned int starved;		/* 读方向连续分发计数 */
	unsigned int batching;		/* 当前批内已分发数 */
	unsigned int last_dir;		/* 上一批方向 */

	u64 r_lat_sum, w_lat_sum;	/* 平均延迟累计 */
	u32 r_lat_n, w_lat_n;
	unsigned long last_lat_emit;	/* jiffies */
};

/* ---- rb/fifo 辅助（简化 deadline） ---- */

static struct request *ai_sched_fifo_request(struct ai_sched_data *asd,
					     int dir)
{
	struct request *rq;

	if (list_empty(&asd->fifo_list[dir]))
		return NULL;
	rq = list_first_entry(&asd->fifo_list[dir], struct request, queuelist);
	/* fifo_time 为 u64（6.18），jiffies 为 unsigned long —— 显式转换比较 */
	if (time_before((unsigned long)rq->fifo_time, jiffies))
		return rq;		/* 期限已过 */
	return NULL;
}

static struct request *ai_sched_oldest_request(struct ai_sched_data *asd,
					       int dir)
{
	struct rb_node *node = rb_first(&asd->sort_list[dir]);

	return node ? rb_entry_rq(node) : NULL;
}

static void ai_sched_add_rq(struct ai_sched_data *asd, struct request *rq)
{
	const int dir = rq_data_dir(rq);

	rq->fifo_time = jiffies +
		(dir == READ ? AI_READ_EXPIRE : AI_WRITE_EXPIRE);
	elv_rb_add(&asd->sort_list[dir], rq);
	list_add_tail(&rq->queuelist, &asd->fifo_list[dir]);
}

static void ai_sched_move_request(struct ai_sched_data *asd,
				  struct request *rq)
{
	const int dir = rq_data_dir(rq);
	struct request_queue *q = rq->q;

	elv_rb_del(&asd->sort_list[dir], rq);
	list_del_init(&rq->queuelist);
	/* dispatch 出队：从 rqhash 摘除并清理 last_merge（同 mq-deadline
	 * dd_start_request）。缺失此步 → hash 残留已完成/已释放请求，
	 * elv_attempt_insert_merge 的 hash 循环与 last_merge 命中后 UAF 崩溃。 */
	elv_rqhash_del(q, rq);
	if (q->last_merge == rq)
		q->last_merge = NULL;
}

/* ---- 分发决策（锁内调用；AI hook 仅咨询不持锁） ---- */

static struct request *ai_sched_pick(struct blk_mq_hw_ctx *hctx,
				     struct ai_sched_data *asd)
{
	struct request *rq;
	int dir = -1;

	/* 1. AI 决策接口：AI 可建议下一次分发方向（空实现不改 dir） */
	if (ai_io_sched_hook(hctx, &dir) && (dir == READ || dir == WRITE)) {
		rq = ai_sched_oldest_request(asd, dir);
		if (rq)
			goto pick;
	}

	/* 2. 回退 = deadline 默认决策（AI 空实现时行为与 mq-deadline 同族） */
	if (!list_empty(&asd->dispatch)) {
		rq = list_first_entry(&asd->dispatch, struct request,
				      queuelist);
		list_del_init(&rq->queuelist);
		asd->batching = 0;
		return rq;
	}

	/* 批内延续：上一方向仍有请求且未达批上限 */
	rq = ai_sched_oldest_request(asd, asd->last_dir);
	if (rq && asd->batching < AI_FIFO_BATCH)
		goto pick;

	/* 选方向：读优先，写饥饿保护 */
	if (!list_empty(&asd->fifo_list[READ])) {
		if (ai_sched_fifo_request(asd, WRITE) &&
		    asd->starved++ >= AI_WRITES_STARVED)
			goto pick_write;
		dir = READ;
		goto find;
	}
	if (!list_empty(&asd->fifo_list[WRITE])) {
pick_write:
		asd->starved = 0;
		dir = WRITE;
		goto find;
	}
	return NULL;

find:
	/* 期限已过 → 取 FIFO 头；否则取最早期限请求 */
	rq = ai_sched_fifo_request(asd, dir);
	if (!rq)
		rq = ai_sched_oldest_request(asd, dir);
	if (!rq)
		return NULL;
	asd->last_dir = dir;
	asd->batching = 0;

pick:
	asd->batching++;
	ai_sched_move_request(asd, rq);
	return rq;
}

static void ai_sched_emit_dispatch(struct request_queue *q, u32 nr)
{
	const char *dev = q->disk ? q->disk->disk_name : "?";

	if (nr)
		ai_io_emit_io_sched_dispatch(dev, "ai", nr);
}

/* ---- elevator_mq_ops ---- */

static int ai_sched_init_sched(struct request_queue *q,
			       struct elevator_queue *e)
{
	struct ai_sched_data *asd;

	asd = kzalloc(sizeof(*asd), GFP_KERNEL);
	if (!asd)
		return -ENOMEM;

	spin_lock_init(&asd->lock);
	asd->sort_list[READ] = RB_ROOT;
	asd->sort_list[WRITE] = RB_ROOT;
	INIT_LIST_HEAD(&asd->fifo_list[READ]);
	INIT_LIST_HEAD(&asd->fifo_list[WRITE]);
	INIT_LIST_HEAD(&asd->dispatch);
	asd->last_lat_emit = jiffies;
	e->elevator_data = asd;
	/* 与 mq-deadline/kyber 一致：调度器自身负责挂载 elevator_queue */
	q->elevator = e;
	return 0;
}

static void ai_sched_exit_sched(struct elevator_queue *e)
{
	struct ai_sched_data *asd = e->elevator_data;

	if (asd) {
		/* 队列冻结中，链表应为空；防御性清空 */
		WARN_ON_ONCE(!list_empty(&asd->dispatch) ||
			     !list_empty(&asd->fifo_list[READ]) ||
			     !list_empty(&asd->fifo_list[WRITE]));
		kfree(asd);
		e->elevator_data = NULL;
	}
}

static void ai_sched_insert_requests(struct blk_mq_hw_ctx *hctx,
				     struct list_head *list,
				     blk_insert_t flags)
{
	struct request_queue *q = hctx->queue;
	struct ai_sched_data *asd = q->elevator->elevator_data;
	const char *dev = q->disk ? q->disk->disk_name : "?";
	LIST_HEAD(free);

	spin_lock(&asd->lock);
	while (!list_empty(list)) {
		struct request *rq;

		rq = list_first_entry(list, struct request, queuelist);
		list_del_init(&rq->queuelist);

		if (blk_mq_sched_try_insert_merge(q, rq, &free))
			continue;

		if (flags & BLK_MQ_INSERT_AT_HEAD) {
			list_add(&rq->queuelist, &asd->dispatch);
			rq->fifo_time = jiffies;
		} else {
			ai_sched_add_rq(asd, rq);
			if (rq_mergeable(rq)) {
				elv_rqhash_add(q, rq);
				if (!q->last_merge)
					q->last_merge = rq;
			}
		}
		ai_io_emit_io_sched_insert(dev, "ai", rq_data_dir(rq));
	}
	spin_unlock(&asd->lock);

	blk_mq_free_requests(&free);
}

static struct request *ai_sched_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct ai_sched_data *asd = q->elevator->elevator_data;
	struct request *rq;

	spin_lock(&asd->lock);
	rq = ai_sched_pick(hctx, asd);
	spin_unlock(&asd->lock);

	if (rq)
		ai_sched_emit_dispatch(q, 1);
	return rq;
}

static void ai_sched_completed_request(struct request *rq, u64 now_ns)
{
	struct request_queue *q = rq->q;
	struct ai_sched_data *asd = q->elevator->elevator_data;
	unsigned long now = jiffies;
	u64 lat;

	(void)now_ns;
	if (!rq->io_start_time_ns)
		return;

	lat = ktime_get_ns() - rq->io_start_time_ns;
	if (rq_data_dir(rq) == READ) {
		asd->r_lat_sum += lat;
		asd->r_lat_n++;
	} else {
		asd->w_lat_sum += lat;
		asd->w_lat_n++;
	}

	/* 每秒发射一次平均延迟 */
	if (time_after_eq(now, asd->last_lat_emit + AI_LAT_SAMPLE_HZ * HZ)) {
		const char *dev = q->disk ? q->disk->disk_name : "?";
		u64 ravg = asd->r_lat_n ? div_u64(asd->r_lat_sum,
						  asd->r_lat_n) : 0;
		u64 wavg = asd->w_lat_n ? div_u64(asd->w_lat_sum,
						  asd->w_lat_n) : 0;

		asd->last_lat_emit = now;
		asd->r_lat_sum = asd->w_lat_sum = 0;
		asd->r_lat_n = asd->w_lat_n = 0;
		ai_io_emit_io_sched_latency(dev, ravg, wavg);
	}
}

static void ai_sched_finish_request(struct request *rq)
{
	/* 基础版：无需统计（io_sched_latency 由 completed_request 提供） */
}

static void ai_sched_requeue_request(struct request *rq)
{
	/* 驱动要求重排的请求：从 rqhash 摘除（请求将重新 insert）。
	 * 缺失此步会导致 hash 残留已完成/被释放的请求 → merge 路径崩溃。 */
	struct request_queue *q = rq->q;

	elv_rqhash_del(q, rq);
	if (q->last_merge == rq)
		q->last_merge = NULL;
}

static void ai_sched_request_merged(struct request_queue *q,
				    struct request *req, enum elv_merge type)
{
	/* 合并后请求首扇区变化：重定位 hash，保持可合并性 */
	if (type == ELEVATOR_BACK_MERGE)
		elv_rqhash_reposition(q, req);
}

static bool ai_sched_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct ai_sched_data *asd = hctx->queue->elevator->elevator_data;

	return !list_empty_careful(&asd->dispatch) ||
	       !list_empty_careful(&asd->fifo_list[READ]) ||
	       !list_empty_careful(&asd->fifo_list[WRITE]);
}

static bool ai_sched_allow_merge(struct request_queue *q, struct request *rq,
				 struct bio *bio)
{
	/* 精确合并判断由电梯核心 rqhash 完成，此处一律放行 */
	return true;
}

/* ---- 注册 ---- */

static struct elevator_type ai_iosched = {
	.ops = {
		.init_sched		= ai_sched_init_sched,
		.exit_sched		= ai_sched_exit_sched,
		.insert_requests	= ai_sched_insert_requests,
		.dispatch_request	= ai_sched_dispatch_request,
		.has_work		= ai_sched_has_work,
		.completed_request	= ai_sched_completed_request,
		.finish_request		= ai_sched_finish_request,
		.requeue_request	= ai_sched_requeue_request,
		.request_merged		= ai_sched_request_merged,
		.allow_merge		= ai_sched_allow_merge,
	},
	.elevator_name	= "ai",
	.elevator_owner	= THIS_MODULE,
};
MODULE_ALIAS("ai-iosched");

static int __init ai_sched_init(void)
{
	return elv_register(&ai_iosched);
}

late_initcall(ai_sched_init);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AIKernel AI IO scheduler (deadline-family, AI-decidable)");
