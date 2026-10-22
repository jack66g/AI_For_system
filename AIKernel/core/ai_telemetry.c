// SPDX-License-Identifier: GPL-2.0
/*
 * ai_telemetry.c - AIKernel 遥测采集核心（per-CPU ring buffer）
 *
 * 设计：
 *   - 每 CPU 256KB 环形缓冲（w24 由 128KB 扩容，64 CPU 共 16MB），
 *     alloc_percpu 动态分配控制块 + 每 CPU 独立 vmalloc 数据区，无锁写入；
 *   - 生产者 = 属主 CPU（preempt_disable 保证同一 CPU 内完成写入），
 *     单写 head（smp_store_release 发布）；
 *   - 消费者 = AI Runtime / 后台排空线程 / NETLINK SENSE 多读者；w58 起
 *     每 CPU 一把读者 mutex，串行化"复制记录 + 推进 tail"临界区（三个
 *     读者均为可睡眠进程上下文）；tail 仍用 cmpxchg 推进，以兼容生产者
 *     CRITICAL 驱逐。w24 起另驻后台排空线程（250ms 周期读空各 CPU ring
 *     并释放），消除"无人拉取 → 环常满 → 全部写入 dropped"的常驻积压
 *     （实测空闲 dropped 15278 条/s、积压恒 13.1 万字节）；
 *   - 满则丢弃并累计 dropped（不覆盖未读数据、不阻塞）；w58 起
 *     dropped 按"真实丢失记录条数"计（满丢弃/CRITICAL 驱逐/resync 弃
 *     积压逐条计入，不再一次 resync 只计 1）；
 *   - 采样：per (category,event) 采样率表，rate=0 丢弃 / 1 全量 / N 每 N 条记 1 条；
 *   - w63 启动期消费者时序：遥测在 start_kernel 内即就绪并接收 sched/mm/vfs
 *     事件，而排空线程原先只在 late_initcall(ai_proc_init) 启动（8 vCPU
 *     qemu 引导实测 0.29s 就绪 / 2.03s 才启动，cpu1 环满 dropped=3641）。
 *     现于 early_initcall（kthreadd 可用后的最早安全点）启动排空线程，
 *     且线程首轮立即排空（不再等 250ms）。若仍有消费者就绪前的环满丢弃，
 *     计入 sampled_skip + predrain_dropped（dropped 只表示消费者就绪后的
 *     真实背压丢失）——启动窗口不再与稳态丢包混为一谈，损失仍可观测。
 *     排空周期自适应：上一轮单 CPU 排空量达环深 1/4 时缩短为 10ms，
 *     回落即恢复 250ms，吸收引导期突发（避免就绪后首个 250ms 窗口溢出）。
 *   - w24 积压自适应降采样：积压超高位水位时按 per-CPU 位移抬高跳过
 *     粒度（跳过计额走 sampled_skip——丢的是采样密度，不是已发生事件
 *     计数；dropped 语义保持"环满真实丢弃"），IMPORTANT 及以上事件
 *     旁路；积压回落低位水位以下逐次衰减位移自动恢复；
 *   - 性能预算：单次写入 < 100ns（ktime_get_ns + 两段 memcpy，无锁无原子 RMW）。
 *
 * 数据原则（all-ai）：24B 定长头 + 原始数据，不脱敏、不哈希、不截断。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/timekeeping.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/smp.h>
#include "ai_telemetry.h"

/*
 * per-CPU ring buffer 布局：
 *   - 控制结构（head/tail/计数）为小尺寸 DEFINE_PER_CPU（几十字节/CPU）；
 *   - 256KB 数据缓冲为每 CPU 独立的 vmalloc 区域（指针存于控制结构中）。
 * 原因：alloc_percpu() 无法分配 >= PCPU_MIN_UNIT_SIZE(32KB, x86) 的对象，
 * 而每 CPU 256KB 数据区必须按设计预算独立可寻址、无锁写。
 */

struct ai_ring_cpu {
	struct mutex read_lock;/* w58：per-CPU 读者互斥（复制+tail 推进同一临界区） */
	u32 head;              /* 写位置（仅属主 CPU 写，release 发布） */
	atomic_t tail;         /* 读位置（读者/生产者驱逐原子推进） */
	u32 emitted;           /* 成功写入条数 */
	atomic_t dropped;      /* 真实丢弃条数（生产者与 resync 读者并发递增） */
	atomic_t resyncs;      /* w58：环错位 resync 次数（诊断，正常恒 0） */
	u32 sampled_skip;      /* 采样跳过条数 */
	u32 sample_counter;    /* 采样计数器（per-CPU 全局） */
	u8 *data;              /* 256KB 环形数据缓冲（vmalloc，page 对齐） */
	/* ---- w24：积压自适应降采样 + 消费观测 ---- */
	u32 adapt_counter;     /* 自适应降采样计数器（独立于 rate 采样相位） */
	u8  adapt_shift;       /* 当前降档级（瞬时；是否降过档看 adapt_skipped/episodes） */
	u8  adapt_peak_shift;  /* w58：历史最高降档级 */
	u64 consumed;          /* 已被读者/排空线程消费（读出并释放）字节数 */
	u64 adapt_skipped;     /* 被自适应降采样跳过的条数（含于 sampled_skip） */
	u64 adapt_episodes;    /* w58：进入降档（shift 0→>0）的次数 */
	u64 predrain_dropped;  /* w63：消费者就绪前环满丢弃条数（含于 sampled_skip） */
} ____cacheline_aligned_in_smp;

static DEFINE_PER_CPU(struct ai_ring_cpu, ai_ring_cpus);
static bool ai_telemetry_ready;

/*
 * w63：消费者就绪闩锁（一次性，置 true 后不回退）。
 *
 * 排空线程/排空 API 首次成为消费者前为 false；就绪前的环满丢弃计入
 * sampled_skip + predrain_dropped（启动窗口无消费者可等待，按"采样跳过"
 * 语义计额；predrain_dropped 保留真实损失观测），就绪后的环满丢弃才计入
 * dropped（真实背压）。闩锁不回退，保证消费者已运行过之后的背压丢失
 * 永远不会被误计为启动窗口跳过（KUnit 暂停/恢复排空线程的隔离场景依赖
 * 这一语义）。
 */
static bool ai_tel_consumer_ready;

/* w24 后台排空状态（实现见"后台排空"节；exit 必须先停线程再释放 ring）。
 * start 仅在 late_initcall、stop 仅在 shutdown/KUnit 路径，天然串行。 */
static u8 *ai_tel_drain_buf;                 /* 排空暂存缓冲（kvfree 释放） */
static struct task_struct *ai_tel_drain_task;/* 排空线程（NULL=未启动） */
static DEFINE_MUTEX(ai_tel_drain_buf_lock);  /* 暂存缓冲懒分配锁 */

/* w24 积压自适应降采样水位与上限位移（按环容量比例取值）：
 *   - backlog > 3/4 环深 → 位移步进（跳过粒度翻倍，上限 1/64）；
 *   - backlog < 1/4 环深 → 位移逐步衰减（自动恢复原采样密度）；
 *   - IMPORTANT 及以上事件旁路（稀缺高值事件不受降采样影响）。 */
#define AI_TEL_ADAPT_HIGH       (AI_TELEMETRY_RING_SIZE / 4 * 3)
#define AI_TEL_ADAPT_LOW        (AI_TELEMETRY_RING_SIZE / 4)
#define AI_TEL_ADAPT_MAX_SHIFT  6u

/* 第 16/17 类类型化发射默认采样率（Prompt 15）：
 * 硬件错误/NMI/模块/配置变更全量；设备/DMA/platform/sysctl 限频 */
#define AI_TEL_DEVICE_SAMPLE     16
#define AI_TEL_DMA_SAMPLE        64
#define AI_TEL_PLATFORM_SAMPLE   16
#define AI_TEL_SYSCTL_SAMPLE     16

static u16 ai_telemetry_sample_rate[AI_CAT_AI][AI_EV_MAX - 1]
		____cacheline_aligned_in_smp;

#define AI_RING_MASK  (AI_TELEMETRY_RING_SIZE - 1)

static inline u32 ai_ring_free(struct ai_ring_cpu *r, u32 head, u32 tail)
{
	return AI_TELEMETRY_RING_SIZE - 1 - (head - tail);
}

/* 环形缓冲写入（处理回绕），pos 为绝对位置 */
static void ai_ring_copy_in(struct ai_ring_cpu *r, u32 pos,
			    const void *src, size_t len)
{
	u32 off = pos & AI_RING_MASK;
	size_t first = min_t(size_t, len, AI_TELEMETRY_RING_SIZE - off);

	if (!len)
		return;
	memcpy(r->data + off, src, first);
	if (first < len)
		memcpy(r->data, (const u8 *)src + first, len - first);
}

/* 环形缓冲读出（处理回绕），pos 为绝对位置 */
static void ai_ring_copy_out(struct ai_ring_cpu *r, u32 pos,
			     void *dst, size_t len)
{
	u32 off = pos & AI_RING_MASK;
	size_t first = min_t(size_t, len, AI_TELEMETRY_RING_SIZE - off);

	if (!len)
		return;
	memcpy(dst, r->data + off, first);
	if (first < len)
		memcpy((u8 *)dst + first, r->data, len - first);
}

/* 前向声明：write 路径的 resync 复用按条计账助手（定义见读路径前） */
static u32 ai_ring_discard_backlog(struct ai_ring_cpu *r, u32 tail, u32 head,
				   const char *reason, u32 bad_len);

/* 写一条记录（属主 CPU 上下文，preempt 已禁用） */
static int ai_ring_write(struct ai_ring_cpu *r,
			 const struct ai_telemetry_record *rec,
			 const void *data)
{
	u32 head = r->head;
	u32 tail = (u32)atomic_read(&r->tail);
	size_t total = AI_TELEMETRY_HEADER_LEN + rec->data_len;

	if (total > AI_TELEMETRY_RING_SIZE - 1)
		return AI_ERR_RING_FULL;   /* 防御（max 4120 << 128KB） */

	/* w24 防御：环位置不可能态（积压超环深，含 tail 越过 head 的回绕
	 * 表现）。放任会让 free 计算回绕成"无限空间"而越界覆盖未读数据。
	 * 处置：tail 重同步到 head（放弃错位积压，按条计 dropped）后继续。
	 * w58：若读者已推进 tail（cmpxchg 失败），重新读取实际值再判断，
	 * 不把 "tail = head" 当作已生效（旧代码会用陈旧乐观值算 free）。 */
	while ((u32)(head - tail) > AI_TELEMETRY_RING_SIZE - 1) {
		u32 new_tail = (u32)atomic_read(&r->tail);

		if (new_tail != tail) {
			tail = new_tail;
			continue;
		}
		ai_ring_discard_backlog(r, tail, head, "write", 0);
		tail = head;
	}

	/*
	 * 关键事件（OOM/内存错误/KASAN 等训练金矿）：ring 满时逐出最旧记录
	 * 腾出空间，保证关键事件不被高频事件淹没。读者间由 read_lock 互斥，
	 * 生产者与读者之间仍用 tail cmpxchg 推进；非关键事件保持"满则丢弃"。
	 */
	if (rec->severity >= AI_SEV_CRITICAL) {
		while (ai_ring_free(r, head, tail) < total) {
			struct ai_telemetry_record old;
			u32 old_tail = tail;
			size_t old_total;

			ai_ring_copy_out(r, tail, &old,
					 AI_TELEMETRY_HEADER_LEN);
			old_total = AI_TELEMETRY_HEADER_LEN + old.data_len;
			/* w24 防御：尾记录头非法（data_len 超发射上限，或长度
			 * 越过 head——并发驱逐/消费竞争下可能的环错位）。
			 * 若照抄 old_total 推进 tail 会让环永久错位卡死
			 * （实测 cpu4：tail 恰好多跳 23+65535 字节后停摆）。
			 * 处置：把 tail 重同步到 head（放弃全部积压，按
			 * 可解析条数计 dropped），本次关键事件退化为满丢弃。 */
			if (old.data_len > AI_TELEMETRY_MAX_DATA_LEN ||
			    old_total > (u32)(head - old_tail)) {
				ai_ring_discard_backlog(r, old_tail, head,
							"evict", old.data_len);
				return AI_ERR_RING_FULL;
			}
			if (old_total > AI_TELEMETRY_RING_SIZE - 1)
				return AI_ERR_RING_FULL;
			if (atomic_cmpxchg(&r->tail, old_tail,
					   old_tail + old_total) != old_tail) {
				/* 读者并发推进：从新 tail 重读 */
				tail = (u32)atomic_read(&r->tail);
				continue;
			}
			atomic_inc(&r->dropped);   /* 被逐出的旧记录计为丢弃 */
			tail = old_tail + old_total;
		}
	}

	if (ai_ring_free(r, head, tail) < total)
		return AI_ERR_RING_FULL;

	ai_ring_copy_in(r, head, rec, AI_TELEMETRY_HEADER_LEN);
	ai_ring_copy_in(r, head + AI_TELEMETRY_HEADER_LEN, data, rec->data_len);
	smp_store_release(&r->head, head + total);
	return AI_OK;
}

/*
 * w58：丢弃 [tail, head) 区间积压并按"条"计账（替代旧的"一次 resync
 * 只 dropped++ 一次"）。先尽力按记录头遍历统计可解析条数（遇到坏头即
 * 停，宁可少计不越界），再 cmpxchg 把 tail 重同步到 head。cmpxchg 失败
 * 说明他方已推进 tail（生产者 CRITICAL 驱逐），本次不计账。
 * 坏头/残记录本身无法确定边界，按 1 条计并在日志标注 lower-bound，
 * 同时打印丢弃总字节，保证损失可观测。
 * 仅 memcpy/原子操作，可在 preempt-disabled 生产者上下文调用。
 * 返回实际计入 dropped 的记录条数。
 */
static u32 ai_ring_discard_backlog(struct ai_ring_cpu *r, u32 tail, u32 head,
				   const char *reason, u32 bad_len)
{
	u32 n = 0, pos = tail;
	bool corrupt = false;

	while ((u32)(head - pos) >= AI_TELEMETRY_HEADER_LEN) {
		struct ai_telemetry_record rec;
		size_t total;

		ai_ring_copy_out(r, pos, &rec, AI_TELEMETRY_HEADER_LEN);
		total = AI_TELEMETRY_HEADER_LEN + rec.data_len;
		if (rec.data_len > AI_TELEMETRY_MAX_DATA_LEN ||
		    total > (u32)(head - pos))
			break;
		pos += total;
		n++;
	}
	if (pos != head)
		corrupt = true;   /* 尾部坏头/残记录：至少再丢 1 条 */

	if (atomic_cmpxchg(&r->tail, tail, head) != tail)
		return 0;

	if (n)
		atomic_add(n, &r->dropped);
	if (corrupt)
		atomic_inc(&r->dropped);
	atomic_inc(&r->resyncs);
	/* 坏头之后无法逐条解析：报告可解析条数 + 总字节，并标注下界 */
	pr_warn_ratelimited(
		"AIKernel: telemetry ring resync on %s (cpu=%d tail=%u head=%u bad_len=%u dropped_records=%u%s bytes=%u)\n",
		reason, smp_processor_id(), tail, head, bad_len,
		n + (corrupt ? 1 : 0), corrupt ? "(lower-bound)" : "",
		(u32)(head - tail));
	return n + (corrupt ? 1 : 0);
}

/* 读出记录（多读者由 per-CPU read_lock 串行化；cap 不足时保留整条记录） */
static int ai_ring_read_from(struct ai_ring_cpu *r, void *buf, size_t cap,
			     size_t *out_bytes)
{
	size_t copied = 0;

	/*
	 * w58 读侧并发修复：每 CPU 读者互斥，临界区覆盖"复制一条记录 +
	 * cmpxchg 推进 tail"整体。三个读者均为可睡眠进程上下文：
	 *   - 排空 kthread：kthread 上下文；
	 *   - /proc/ai/telemetry read：read(2) 系统调用上下文（kmalloc
	 *     GFP_KERNEL 已隐含此前提）；
	 *   - NETLINK SENSE：netlink_unicast_kernel() 在发送方进程上下文
	 *     直接调用 .input 回调（net/netlink/af_netlink.c），无自旋锁；
	 * 故用 mutex 而非 spinlock。生产者不取此锁（CRITICAL 驱逐仍用
	 * tail cmpxchg），不存在读者锁与生产者锁的嵌套/死锁。
	 * 互斥保证任一时刻只有一个读者推进 tail：生产者只有看到已发布的
	 * tail 后才可能回绕覆盖，慢读者正在复制的记录不会被快读者“消费
	 * 后释放”。
	 */
	mutex_lock(&r->read_lock);
	/*
	 * w63 退出竞争：ai_telemetry_exit() 先把 ready 置 false，再逐个
	 * 获取/释放本 CPU 的 read_lock（等待在途读者退出）后才 vfree ring。
	 * 读者必须在锁内复查：若在"外层 ready 检查通过"与"拿到锁"之间
	 * 发生 exit，则看到 false 后直接返回，绝不触碰已释放的 ring。
	 */
	if (!READ_ONCE(ai_telemetry_ready)) {
		mutex_unlock(&r->read_lock);
		if (out_bytes)
			*out_bytes = 0;
		return AI_ERR_DISABLED;
	}
	for (;;) {
		struct ai_telemetry_record rec;
		size_t total;
		u32 tail, head;

		tail = (u32)atomic_read(&r->tail);
		head = smp_load_acquire(&r->head);
		if (tail == head)
			break;

		/* w24 防御：环位置不可能态（积压超环深，含 tail 越过 head）
		 * → 重同步到 head 后退出，防继续按错位解析。 */
		if ((u32)(head - tail) > AI_TELEMETRY_RING_SIZE - 1) {
			ai_ring_discard_backlog(r, tail, head, "read", 0);
			break;
		}

		ai_ring_copy_out(r, tail, &rec, AI_TELEMETRY_HEADER_LEN);
		total = AI_TELEMETRY_HEADER_LEN + rec.data_len;

		/* w24 防御：记录头非法（data_len 超发射上限）说明环已错位/
		 * 被踩踏，继续等只会永久卡死读者。处置：把 tail 重同步到
		 * head（放弃积压中无法解析的部分，按条计 dropped）并退出。 */
		if (rec.data_len > AI_TELEMETRY_MAX_DATA_LEN) {
			ai_ring_discard_backlog(r, tail, head, "read",
						rec.data_len);
			break;
		}

		/* 记录未写完（head 尚未发布到完整记录尾）或头部非法：停止 */
		if ((u32)(head - tail) < total)
			break;
		if (copied + total > cap)
			break;

		memcpy((u8 *)buf + copied, &rec, AI_TELEMETRY_HEADER_LEN);
		ai_ring_copy_out(r, tail + AI_TELEMETRY_HEADER_LEN,
				 (u8 *)buf + copied + AI_TELEMETRY_HEADER_LEN,
				 rec.data_len);

		if (atomic_cmpxchg(&r->tail, tail, tail + total) != tail) {
			copied = 0;   /* 生产者驱逐推进了 tail：从新位置重读 */
			continue;
		}
		copied += total;
	}
	mutex_unlock(&r->read_lock);

	if (out_bytes)
		*out_bytes = copied;
	return AI_OK;
}

/* ---- 生命周期 ---- */

int ai_telemetry_init(void)
{
	int cpu;

	if (ai_telemetry_ready)
		return AI_OK;   /* 幂等 */

	for_each_possible_cpu(cpu) {
		struct ai_ring_cpu *r = per_cpu_ptr(&ai_ring_cpus, cpu);

		if (!r->data) {
			r->data = vmalloc(AI_TELEMETRY_RING_SIZE);
			if (!r->data) {
				int c;

				for (c = 0; c < cpu; c++)
					vfree(per_cpu_ptr(&ai_ring_cpus, c)->data);
				for (c = 0; c < nr_cpu_ids; c++)
					per_cpu_ptr(&ai_ring_cpus, c)->data = NULL;
				return AI_ERR_MEMORY;
			}
		}
		mutex_init(&r->read_lock);   /* w58：每 CPU 读者互斥 */
		memset(r->data, 0, AI_TELEMETRY_RING_SIZE);
		r->head = 0;
		atomic_set(&r->tail, 0);
		r->emitted = 0;
		atomic_set(&r->dropped, 0);
		atomic_set(&r->resyncs, 0);
		r->sampled_skip = 0;
		r->sample_counter = 0;
		r->adapt_counter = 0;
		r->adapt_shift = 0;
		r->adapt_peak_shift = 0;
		r->consumed = 0;
		r->adapt_skipped = 0;
		r->adapt_episodes = 0;
		r->predrain_dropped = 0;
	}
	/* 采样率默认全量（1），per (category,event) 覆盖 */
	{
		u8 c, e;

		for (c = 0; c < AI_CAT_AI; c++)
			for (e = 0; e < AI_EV_MAX - 1; e++)
				ai_telemetry_sample_rate[c][e] = 1;
	}

	/* 第 16/17 类类型化发射默认采样率（Prompt 15）：
	 * 硬件错误/NMI/模块/配置变更全量；设备/DMA/platform/sysctl 限频 */
	ai_telemetry_sample_rate[AI_CAT_HW - 1][AI_EV_DEVICE - 1] =
		AI_TEL_DEVICE_SAMPLE;
	ai_telemetry_sample_rate[AI_CAT_HW - 1][AI_EV_DMA - 1] =
		AI_TEL_DMA_SAMPLE;
	ai_telemetry_sample_rate[AI_CAT_KCONFIG - 1][AI_EV_SYSCTL - 1] =
		AI_TEL_SYSCTL_SAMPLE;

	ai_telemetry_ready = true;
	WRITE_ONCE(ai_tel_consumer_ready, false);   /* w63：新生命周期从无消费者开始 */
	pr_info("AIKernel: telemetry ready (%u CPU x %dKB ring buffers)\n",
		nr_cpu_ids, AI_TELEMETRY_RING_SIZE / 1024);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_telemetry_init);

/* w63：退出屏障 IPI 处理体（空）。见 ai_telemetry_exit() 的时序说明。 */
static void ai_tel_exit_sync(void *unused)
{
}

void ai_telemetry_exit(void)
{
	int cpu;

	if (!ai_telemetry_ready)
		return;

	/*
	 * w24：先停后台排空线程（kthread_stop 等待其退出，保证不再触碰
	 * ring），再关闸门、释放 ring。vfree() 会触发子系统感知埋点
	 * （如 mm 的 __free_pages → ai_mm_emit_page_free），若 ready 仍为
	 * true，emit 会在已释放/未映射的 ring 上写入 → 内核崩溃
	 * （KUnit ai_runtime 套件实测捕获）。先关闸门保证释放路径安全。
	 * w63：关闸门与 vfree 之间补生产者/读者退出屏障（见下），关闭
	 * "已通过 ready 检查、尚未触碰 ring" 的残留 UAF 窗口。
	 */
	ai_telemetry_drain_stop();
	kvfree(ai_tel_drain_buf);
	ai_tel_drain_buf = NULL;
	WRITE_ONCE(ai_tel_consumer_ready, false);
	WRITE_ONCE(ai_telemetry_ready, false);

	/*
	 * w63 退出屏障：关闸门后等两类在途访问退出再 vfree。
	 *   1) 生产者：emit 在 local_irq_save() 之后复查 ready。已进入临界区
	 *      的生产者先完成写序列并恢复中断，IPI 才被投递；on_each_cpu()
	 *      返回即表示各 CPU 的在途写序列均已结束。此后开始的生产者读到
	 *      ready=false 直接返回，不会触碰 ring。
	 *   2) 读者（procfs/NETLINK SENSE）：ai_ring_read_from() 在 read_lock
	 *      内复查 ready；逐个获取/释放 read_lock 等待在途读者退出，之后
	 *      进入者看到 false 立即返回。
	 * NMI 生产者不可被 IRQ/IPI 屏蔽（W58 已知残留），本屏障不覆盖。
	 */
	on_each_cpu(ai_tel_exit_sync, NULL, 1);
	for_each_possible_cpu(cpu) {
		struct ai_ring_cpu *r = per_cpu_ptr(&ai_ring_cpus, cpu);

		mutex_lock(&r->read_lock);
		mutex_unlock(&r->read_lock);
	}

	for_each_possible_cpu(cpu) {
		struct ai_ring_cpu *r = per_cpu_ptr(&ai_ring_cpus, cpu);

		vfree(r->data);
		r->data = NULL;
	}
	pr_info("AIKernel: telemetry shutdown\n");
}
EXPORT_SYMBOL_GPL(ai_telemetry_exit);

/* ---- 写入入口（全系统唯一） ---- */

/* 采样判定（供 sample_take 与 emit 共用；preempt 已禁用） */
static bool ai_ring_sample(struct ai_ring_cpu *r, u16 rate)
{
	if (rate <= 1)
		return rate == 1;

	r->sample_counter++;
	if ((r->sample_counter % rate) != 0) {
		r->sampled_skip++;
		return false;
	}
	return true;
}

static int ai_telemetry_emit_common(u8 category, u8 event_type, u8 severity,
				    const void *data, u16 data_len,
				    bool sampling_done)
{
	struct ai_ring_cpu *r;
	struct ai_telemetry_record rec;
	unsigned long flags;
	u16 rate;
	int rc;

	if (!ai_telemetry_ready)
		return AI_ERR_DISABLED;
	if (category < 1 || category > AI_CAT_AI)
		return AI_ERR_INVALID_ARG;
	if (event_type < 1 || event_type >= AI_EV_MAX)
		return AI_ERR_INVALID_ARG;
	if (data_len > AI_TELEMETRY_MAX_DATA_LEN)
		return AI_ERR_INVALID_ARG;   /* 不截断：保全量 */

	rate = READ_ONCE(ai_telemetry_sample_rate[category - 1][event_type - 1]);
	if (!sampling_done) {
		if (rate == 0)
			return AI_OK;   /* 该事件被采样关闭 */
	}

	/*
	 * w58：单写者语义要求"读 head→写记录→发布 head"在属主 CPU 上
	 * 不可被同 CPU 的另一生产者嵌套。preempt_disable() 只防抢占，不防
	 * 硬中断：timer/irq 上下文的遥测埋点（如 ai_telemetry_tick_mode）
	 * 可在写序列中间插入，用同一 head 再写一条并以不同长度发布，
	 * 造成环内记录错位（KUnit 并发用例已复现 bad_len）。改用
	 * local_irq_save()：本 CPU 关中断覆盖整个写临界区（含采样/自适应
	 * 计数），NMI 入口在 x86 上 IF 已清，save/restore 语义安全。
	 * 读者侧不受影响（读者是睡眠上下文，不与此临界区嵌套）。
	 */
	local_irq_save(flags);
	/*
	 * w63 退出竞争：ai_telemetry_exit() 置 ready=false 后调用
	 * on_each_cpu() 作屏障；本检查位于 IRQ 关闭区间内，因此已读到 true
	 * 的生产者一定先完成写序列、恢复中断后 IPI 才被投递，exit 的屏障
	 * 返回后才会 vfree。此处复查把 "外层检查通过 → 被抢占/中断" 的
	 * 窗口闭合（外层检查保留为无锁快速路径）。
	 */
	if (!READ_ONCE(ai_telemetry_ready)) {
		local_irq_restore(flags);
		return AI_ERR_DISABLED;
	}
	r = per_cpu_ptr(&ai_ring_cpus, smp_processor_id());

	if (!sampling_done && !ai_ring_sample(r, rate)) {
		local_irq_restore(flags);
		return AI_OK;
	}

	/*
	 * w24 积压自适应降采样：消费跟不上生产时（积压超高位水位）按
	 * per-CPU 位移抬高跳过粒度，积压回落后逐次衰减自动恢复。
	 *   - 跳过计额走 sampled_skip（采样跳过语义），不进 dropped；
	 *     dropped 语义保持"真实丢失（满/驱逐/resync 逐条）"；
	 *   - IMPORTANT 及以上事件旁路（稀缺高值事件不降采样）；
	 *   - adapt_counter 独立计数，不干扰 rate 采样表相位。
	 */
	{
		u32 bk_head = READ_ONCE(r->head);
		u32 backlog = bk_head - (u32)atomic_read(&r->tail);

		if (backlog > AI_TEL_ADAPT_HIGH) {
			if (r->adapt_shift < AI_TEL_ADAPT_MAX_SHIFT) {
				if (!r->adapt_shift)
					r->adapt_episodes++;
				r->adapt_shift++;
				if (r->adapt_shift > r->adapt_peak_shift)
					r->adapt_peak_shift = r->adapt_shift;
			}
		} else if (backlog < AI_TEL_ADAPT_LOW && r->adapt_shift) {
			r->adapt_shift--;
		}

		if (r->adapt_shift && severity < AI_SEV_IMPORTANT) {
			r->adapt_counter++;
			if ((r->adapt_counter & ((1u << r->adapt_shift) - 1))) {
				r->sampled_skip++;
				r->adapt_skipped++;
				local_irq_restore(flags);
				return AI_OK;
			}
		}
	}

	rec.timestamp_ns = ktime_get_ns();
	if (current) {
		rec.pid = current->pid;
		rec.tgid = current->tgid;
	} else {
		rec.pid = 0;
		rec.tgid = 0;
	}
	rec.cpu = (u16)smp_processor_id();
	rec.category = category;
	rec.event_type = event_type;
	rec.severity = severity;
	rec.data_len = data_len;

	rc = ai_ring_write(r, &rec, data);
	if (rc == AI_OK) {
		r->emitted++;
	} else if (rc == AI_ERR_RING_FULL &&
		   !READ_ONCE(ai_tel_consumer_ready)) {
		/*
		 * w63 启动窗口：排空线程尚未成为消费者，环满没有可等待的
		 * 消费端。按"采样跳过"语义计额（sampled_skip），并单独累计
		 * predrain_dropped 保留真实损失观测；dropped 只统计消费者
		 * 就绪后的真实背压丢失，避免把启动期无消费者与稳态丢包
		 * 混为一个指标（M9 稳态口径）。
		 */
		r->sampled_skip++;
		r->predrain_dropped++;
	} else {
		atomic_inc(&r->dropped);
	}
	local_irq_restore(flags);

	return rc;
}

int ai_telemetry_emit(u8 category, u8 event_type, u8 severity,
		      const void *data, u16 data_len)
{
	return ai_telemetry_emit_common(category, event_type, severity,
					data, data_len, false);
}
EXPORT_SYMBOL_GPL(ai_telemetry_emit);

bool ai_telemetry_sample_take(u8 category, u8 event_type)
{
	u16 rate;
	bool ok;

	if (!ai_telemetry_ready)
		return false;
	if (category < 1 || category > AI_CAT_AI)
		return false;
	if (event_type < 1 || event_type >= AI_EV_MAX)
		return false;

	rate = READ_ONCE(ai_telemetry_sample_rate[category - 1][event_type - 1]);
	if (rate == 0)
		return false;

	preempt_disable();
	ok = ai_ring_sample(per_cpu_ptr(&ai_ring_cpus, smp_processor_id()),
			    rate);
	preempt_enable();
	return ok;
}
EXPORT_SYMBOL_GPL(ai_telemetry_sample_take);

int ai_telemetry_emit_direct(u8 category, u8 event_type, u8 severity,
			     const void *data, u16 data_len)
{
	return ai_telemetry_emit_common(category, event_type, severity,
					data, data_len, true);
}
EXPORT_SYMBOL_GPL(ai_telemetry_emit_direct);

/* ---- 读取（供 AI Runtime） ---- */

int ai_telemetry_read(u32 cpu, void *buf, size_t len, size_t *out_bytes)
{
	struct ai_ring_cpu *r;

	if (!ai_telemetry_ready)
		return AI_ERR_DISABLED;
	if (cpu >= nr_cpu_ids || !buf)
		return AI_ERR_INVALID_ARG;

	r = per_cpu_ptr(&ai_ring_cpus, cpu);
	return ai_ring_read_from(r, buf, len, out_bytes);
}
EXPORT_SYMBOL_GPL(ai_telemetry_read);

/* ---- 采样开关 ---- */

int ai_telemetry_set_sample_rate(u8 category, u8 event_type, u32 rate)
{
	if (category < 1 || category > AI_CAT_AI)
		return AI_ERR_INVALID_ARG;
	if (event_type < 1 || event_type >= AI_EV_MAX)
		return AI_ERR_INVALID_ARG;

	WRITE_ONCE(ai_telemetry_sample_rate[category - 1][event_type - 1],
		   (u16)min_t(u32, rate, 65535));
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_telemetry_set_sample_rate);

int ai_telemetry_get_sample_rate(u8 category, u8 event_type, u32 *rate)
{
	if (category < 1 || category > AI_CAT_AI)
		return AI_ERR_INVALID_ARG;
	if (event_type < 1 || event_type >= AI_EV_MAX)
		return AI_ERR_INVALID_ARG;
	if (!rate)
		return AI_ERR_INVALID_ARG;

	*rate = READ_ONCE(ai_telemetry_sample_rate[category - 1][event_type - 1]);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_telemetry_get_sample_rate);

/* ---- 采样率用户态命令（w21：/proc/ai/telemetry 写 "rate=cat:ev:N"） ----
 * 语法 NUL 结尾 "cat:ev:N"；cat∈[1,AI_CAT_AI]、ev∈[1,AI_EV_MAX)，
 * N∈[0,65535]（>65535 钳 65535）；0=丢弃全部 1=全量 N=每 N 条记 1 条。
 * 在 unsigned long 域先做边界检查再窄化（防 (u8) 截断绕过）。
 * 供 ai_procfs.c 写路径（CAP_SYS_ADMIN 门控在那里）与 KUnit 直接调用。 */
int ai_telemetry_rate_cmd(const char *s)
{
	unsigned long cat, ev, rate;
	char *end;

	if (!s)
		return AI_ERR_INVALID_ARG;

	cat = simple_strtoul(s, &end, 10);
	if (end == s || *end != ':')
		return AI_ERR_INVALID_ARG;
	s = end + 1;
	ev = simple_strtoul(s, &end, 10);
	if (end == s || *end != ':')
		return AI_ERR_INVALID_ARG;
	s = end + 1;
	rate = simple_strtoul(s, &end, 10);
	if (end == s || *end != '\0')
		return AI_ERR_INVALID_ARG;
	if (cat < 1 || cat > AI_CAT_AI || ev < 1 || ev >= AI_EV_MAX)
		return AI_ERR_INVALID_ARG;

	rate = min_t(unsigned long, rate, 65535);
	if (ai_telemetry_set_sample_rate((u8)cat, (u8)ev, (u32)rate) != AI_OK)
		return AI_ERR_INVALID_ARG;
	pr_info("AIKernel: telemetry sample rate cat=%lu ev=%lu -> %lu\n",
		cat, ev, rate);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_telemetry_rate_cmd);

/* ---- 清空（感知数据清空） ---- */

int ai_telemetry_reset(void)
{
	int cpu;

	if (!ai_telemetry_ready)
		return AI_ERR_DISABLED;

	for_each_possible_cpu(cpu) {
		struct ai_ring_cpu *r = per_cpu_ptr(&ai_ring_cpus, cpu);

		/* w58：与读者串行化，避免 memset/位置重置被读到半状态 */
		mutex_lock(&r->read_lock);
		/* w63：退出竞争下不再触碰即将释放的 ring（见 exit 屏障） */
		if (!READ_ONCE(ai_telemetry_ready)) {
			mutex_unlock(&r->read_lock);
			continue;
		}
		memset(r->data, 0, AI_TELEMETRY_RING_SIZE);
		r->head = 0;
		atomic_set(&r->tail, 0);
		r->emitted = 0;
		atomic_set(&r->dropped, 0);
		atomic_set(&r->resyncs, 0);
		r->sampled_skip = 0;
		r->sample_counter = 0;
		r->adapt_counter = 0;
		r->adapt_shift = 0;
		r->adapt_peak_shift = 0;
		r->consumed = 0;
		r->adapt_skipped = 0;
		r->adapt_episodes = 0;
		r->predrain_dropped = 0;
		mutex_unlock(&r->read_lock);
	}
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_telemetry_reset);

/* ---- 统计 ---- */

int ai_telemetry_stats(u32 cpu, struct ai_telemetry_cpu_stats *st)
{
	struct ai_ring_cpu *r;

	if (!ai_telemetry_ready)
		return AI_ERR_DISABLED;
	if (cpu >= nr_cpu_ids || !st)
		return AI_ERR_INVALID_ARG;

	r = per_cpu_ptr(&ai_ring_cpus, cpu);
	st->emitted = r->emitted;
	st->dropped = (u32)atomic_read(&r->dropped);
	st->sampled_skip = r->sampled_skip;
	st->ring_size = AI_TELEMETRY_RING_SIZE;
	st->head = r->head;
	st->tail = (u32)atomic_read(&r->tail);
	st->consumed = r->consumed;
	st->resyncs = (u32)atomic_read(&r->resyncs);
	st->adapt_shift = r->adapt_shift;
	st->adapt_peak_shift = r->adapt_peak_shift;
	st->adapt_skipped = r->adapt_skipped;
	st->adapt_episodes = r->adapt_episodes;
	st->predrain_dropped = r->predrain_dropped;
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_telemetry_stats);

/* ---- w24：后台排空（消费者常驻化） ----
 * 此前唯一消费者是被动拉取（/proc/ai/telemetry 读 / NETLINK SENSE 拉），
 * 无人拉取时环常满、全部写入 dropped（实测空闲 dropped 15278 条/s、
 * 积压恒 13.1 万字节）。本线程以固定周期把各 CPU ring 读空并释放：
 * 读出内容计入 consumed 后丢弃——与环满丢弃同损益，但事件先入环、
 * 在排空周期窗口内仍可被被动读者捕获（时延上界=排空周期）。
 * 250ms 周期 x 每 CPU 至多整环 256KB = 每 CPU >=1MB/s 排空能力，覆盖
 * 实测峰值；突发超出部分由积压自适应降采样兜底。与被动读者并发时
 * 由每 CPU read_lock 串行化（w58）；tail cmpxchg 仅用于兼容生产者
 * CRITICAL 驱逐。 */

#define AI_TEL_DRAIN_CHUNK  (64 * 1024)

/*
 * w63/w66：排空节奏自适应。固定 250ms 周期在引导突发期不足以吸收
 * "每 CPU 每秒数百 KB" 的写入：两轮之间仍可填满 256KB ring
 * （8 vCPU qemu 实测消费者就绪后的 250ms 窗口内仍 dropped=2009）。
 * #56 生产 VM 实测：启动 5s 内 10ms 快周期仍让 cpu0 丢掉 8781 条，
 * 原因是引导期单 CPU 事件速率可达数十 MB/s，10ms 窗口足以填满 256KB。
 * 策略：
 *   - 排空线程启动后的前 5 秒（引导突发期）无条件用 2ms 快周期；
 *   - 之后任意 CPU 环占用 ≥1/4 时用 2ms；≥1/16 时用 10ms；
 *   - 或上一轮单 CPU 排空字节数达环深 1/8 时用 10ms；
 *   - 全部回落后恢复 250ms。
 * #57 生产实测：仅按“上一轮排空量”判断时，重负载突发（sandbox 编译/OOM
 * 测试）仍可在 250ms 窗口内填满 256KB 环，累计 dropped 24829。改为直接
 * 读各 CPU 环占用（head-tail），在环未满前就提速，避免“先丢再降”。
 */
#define AI_TEL_DRAIN_FAST_PERIOD_MS  2
#define AI_TEL_DRAIN_MID_PERIOD_MS   10
#define AI_TEL_DRAIN_FAST_THRESHOLD  (AI_TELEMETRY_RING_SIZE / 8)
#define AI_TEL_DRAIN_BOOT_FAST_NS    (5ULL * NSEC_PER_SEC)

/* 上一轮排空：单 CPU 读出字节数峰值（排空线程单写；读者可无锁读） */
static u32 ai_tel_drain_last_max;
/* 排空线程本次启动时刻（boottime ns；前 5 秒用快周期） */
static u64 ai_tel_drain_started_ns;

/* 任一 CPU 环的已用字节数达到阈值（无锁快照，排空线程决策用） */
static bool ai_tel_ring_used_at_least(u32 threshold)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct ai_ring_cpu *r = per_cpu_ptr(&ai_ring_cpus, cpu);
		u32 head = READ_ONCE(r->head);
		u32 tail = (u32)atomic_read(&r->tail);

		if ((u32)(head - tail) >= threshold)
			return true;
	}
	return false;
}

static unsigned int ai_tel_drain_period_ms(void)
{
	if (ktime_get_boottime_ns() - READ_ONCE(ai_tel_drain_started_ns) <
	    AI_TEL_DRAIN_BOOT_FAST_NS)
		return AI_TEL_DRAIN_FAST_PERIOD_MS;
	if (ai_tel_ring_used_at_least(AI_TELEMETRY_RING_SIZE / 4))
		return AI_TEL_DRAIN_FAST_PERIOD_MS;
	if (ai_tel_ring_used_at_least(AI_TELEMETRY_RING_SIZE / 16))
		return AI_TEL_DRAIN_MID_PERIOD_MS;
	if (READ_ONCE(ai_tel_drain_last_max) >= AI_TEL_DRAIN_FAST_THRESHOLD)
		return AI_TEL_DRAIN_MID_PERIOD_MS;
	return AI_TEL_DRAIN_PERIOD_MS;
}

int ai_telemetry_drain_all(void)
{
	int cpu;
	u32 max_bytes = 0;

	if (!ai_telemetry_ready)
		return AI_ERR_DISABLED;

	/* 本函数就是消费者：此后环满丢弃按稳态 dropped 计额（w63） */
	WRITE_ONCE(ai_tel_consumer_ready, true);

	/* 暂存缓冲懒分配（进程上下文；KUnit 亦可直接调用本函数） */
	mutex_lock(&ai_tel_drain_buf_lock);
	if (!ai_tel_drain_buf) {
		ai_tel_drain_buf = kzalloc(AI_TEL_DRAIN_CHUNK, GFP_KERNEL);
		if (!ai_tel_drain_buf)
			ai_tel_drain_buf = vzalloc(AI_TEL_DRAIN_CHUNK);
	}
	mutex_unlock(&ai_tel_drain_buf_lock);
	if (!ai_tel_drain_buf)
		return AI_ERR_MEMORY;

	for_each_possible_cpu(cpu) {
		struct ai_ring_cpu *r = per_cpu_ptr(&ai_ring_cpus, cpu);
		u32 this_cpu = 0;

		for (;;) {
			size_t n = 0;

			if (ai_ring_read_from(r, ai_tel_drain_buf,
					      AI_TEL_DRAIN_CHUNK, &n) != AI_OK)
				break;
			if (!n)
				break;   /* 本 CPU 环已空 */
			r->consumed += n;
			this_cpu += n;
			if (n < AI_TEL_DRAIN_CHUNK)
				break;   /* 不足一块：也已读空 */
		}
		if (this_cpu > max_bytes)
			max_bytes = this_cpu;
	}
	WRITE_ONCE(ai_tel_drain_last_max, max_bytes);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_telemetry_drain_all);

static int ai_tel_drain_fn(void *arg)
{
	/*
	 * w63：首轮立即排空，不再先睡 250ms。原来 kthread_run 后第一次
	 * 消费要等到一个周期之后；启动期事件速率高，这段初始延迟本身
	 * 就可能让 256KB ring 填满（与 late_initcall 晚启动叠加）。
	 */
	ai_telemetry_drain_all();

	while (!kthread_should_stop()) {
		unsigned int period = ai_tel_drain_period_ms();

		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(period));
		if (kthread_should_stop())
			break;
		ai_telemetry_drain_all();
	}
	return 0;
}

int ai_telemetry_drain_start(void)
{
	if (!ai_telemetry_ready)
		return AI_ERR_DISABLED;
	if (ai_tel_drain_task)
		return AI_OK;   /* 幂等 */

	/* 预分配暂存缓冲（失败则拒绝启动，保持被动消费旧路径不劣化） */
	mutex_lock(&ai_tel_drain_buf_lock);
	if (!ai_tel_drain_buf) {
		ai_tel_drain_buf = kzalloc(AI_TEL_DRAIN_CHUNK, GFP_KERNEL);
		if (!ai_tel_drain_buf)
			ai_tel_drain_buf = vzalloc(AI_TEL_DRAIN_CHUNK);
	}
	mutex_unlock(&ai_tel_drain_buf_lock);
	if (!ai_tel_drain_buf)
		return AI_ERR_MEMORY;

	ai_tel_drain_task = kthread_run(ai_tel_drain_fn, NULL, "ai_tel_drain");
	if (IS_ERR(ai_tel_drain_task)) {
		ai_tel_drain_task = NULL;
		return AI_ERR_GENERIC;
	}
	/* 消费者已就绪（线程首轮会立即排空）；闩锁一次性置位 */
	WRITE_ONCE(ai_tel_consumer_ready, true);
	WRITE_ONCE(ai_tel_drain_started_ns, ktime_get_boottime_ns());
	pr_info("AIKernel: telemetry drainer started (period=%dms)\n",
		AI_TEL_DRAIN_PERIOD_MS);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_telemetry_drain_start);

void ai_telemetry_drain_stop(void)
{
	struct task_struct *t = ai_tel_drain_task;

	if (!t)
		return;   /* 幂等 */
	ai_tel_drain_task = NULL;
	kthread_stop(t);   /* 唤醒并等待退出（保证 vfree 前不再触碰 ring） */
}
EXPORT_SYMBOL_GPL(ai_telemetry_drain_stop);

bool ai_telemetry_drain_running(void)
{
	return ai_tel_drain_task != NULL;
}
EXPORT_SYMBOL_GPL(ai_telemetry_drain_running);

/*
 * w63：尽早启动排空线程。
 *
 * 遥测在 start_kernel() 内（AI Runtime 初始化）即就绪，此后 sched/mm/vfs
 * 的核内埋点立即开始写入 per-CPU ring；而排空线程原先只在
 * late_initcall(ai_proc_init) 启动。实测 8 vCPU qemu 引导：
 *   telemetry ready 0.29s → drainer started 2.03s，
 *   cpu1 在该窗口内环满 dropped=3641（随后稳态 0 增长）。
 * early_initcall 是 kthreadd 可用后的最早安全点（rest_init 先创建 kthreadd，
 * 之后才运行 initcalls），把无消费者窗口从 ~1.7s 缩短到 initcall 之前的
 * 数百毫秒；配合线程首轮立即排空，窗口内积压通常不再触顶。
 * 失败时保持旧路径：late_initcall(ai_proc_init) 会再调用一次（幂等重试），
 * 此前的环满丢弃按 predrain 口径计额。
 */
static int __init ai_telemetry_drain_early_init(void)
{
	int rc;

	if (!READ_ONCE(ai_telemetry_ready))
		return 0;   /* ai.enabled=0 / 遥测未启用 */

	rc = ai_telemetry_drain_start();
	if (rc != AI_OK)
		pr_warn("AIKernel: early telemetry drainer start failed (%d)\n",
			rc);
	return 0;
}
early_initcall(ai_telemetry_drain_early_init);

#ifdef CONFIG_AIKERNEL_KUNIT_TEST
/*
 * w63 KUnit 钩子：复位/置位消费者就绪闩锁。仅供测试验证"消费者就绪前
 * 环满丢弃计入 sampled_skip + predrain_dropped、dropped 保持 0"。
 */
void ai_telemetry_test_set_consumer_ready(bool ready)
{
	WRITE_ONCE(ai_tel_consumer_ready, ready);
}
#endif

/* ---- 第 16/17 类类型化发射（Prompt 15，全量原始零脱敏） ---- */

int ai_telemetry_hw_error(const struct ai_hw_error_payload *p, u8 severity)
{
	if (!p)
		return AI_ERR_INVALID_ARG;
	/* 硬件错误不采样：全量直写；CRITICAL 级驱逐保证关键错误不丢 */
	return ai_telemetry_emit_direct(AI_CAT_HW, AI_EV_HW_ERROR, severity,
					p, sizeof(*p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_hw_error);

int ai_telemetry_device_evt(u8 action, const char *dev, const char *drv)
{
	struct ai_device_payload p;

	if (!dev)
		return AI_ERR_INVALID_ARG;
	memset(&p, 0, sizeof(p));
	p.action = action;
	strscpy(p.dev, dev, sizeof(p.dev));
	if (drv)
		strscpy(p.drv, drv, sizeof(p.drv));
	/* 采样走采样率表（默认 1/16，ai_telemetry_init 设置） */
	return ai_telemetry_emit(AI_CAT_HW, AI_EV_DEVICE,
				 AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_device_evt);

int ai_telemetry_dma_evt(u8 dir, const char *dev, u64 dma_addr, u32 size)
{
	struct ai_dma_payload p;

	if (!dev)
		return AI_ERR_INVALID_ARG;
	memset(&p, 0, sizeof(p));
	p.dir = dir;
	p.dma_addr = dma_addr;
	p.size = size;
	strscpy(p.dev, dev, sizeof(p.dev));
	/* 采样走采样率表（默认 1/64，ai_telemetry_init 设置） */
	return ai_telemetry_emit(AI_CAT_HW, AI_EV_DMA, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_dma_evt);

int ai_telemetry_nmi_evt(u8 reason, u64 ip, const char *msg)
{
	struct ai_nmi_payload p;

	memset(&p, 0, sizeof(p));
	p.reason = reason;
	p.ip = ip;
	if (msg)
		strscpy(p.msg, msg, sizeof(p.msg));
	return ai_telemetry_emit_direct(AI_CAT_HW, AI_EV_HW_ERROR,
					AI_SEV_IMPORTANT, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_nmi_evt);

int ai_telemetry_platform_evt(const char *name, s32 id, u32 nres)
{
	struct ai_platform_payload p;

	if (!name)
		return AI_ERR_INVALID_ARG;
	memset(&p, 0, sizeof(p));
	strscpy(p.name, name, sizeof(p.name));
	p.id = id;
	p.nres = nres;
	/* 采样走采样率表（默认 1/16，ai_telemetry_init 设置） */
	return ai_telemetry_emit(AI_CAT_HW, AI_EV_DEVICE,
				 AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_platform_evt);

int ai_telemetry_config_change_evt(const struct ai_kconfig_payload *p)
{
	if (!p)
		return AI_ERR_INVALID_ARG;
	/* 启动采集一次：全量直写 */
	return ai_telemetry_emit_direct(AI_CAT_KCONFIG, AI_EV_CONFIG_CHANGE,
					AI_SEV_NORMAL, p, sizeof(*p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_config_change_evt);

int ai_telemetry_module_evt(u8 action, const char *name)
{
	struct ai_module_payload p;

	if (!name)
		return AI_ERR_INVALID_ARG;
	memset(&p, 0, sizeof(p));
	p.action = action;
	strscpy(p.name, name, sizeof(p.name));
	return ai_telemetry_emit_direct(AI_CAT_KCONFIG, AI_EV_CONFIG_CHANGE,
					AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_module_evt);

int ai_telemetry_sysctl_evt(const char *name, const char *old_val,
			    const char *new_val)
{
	struct ai_sysctl_payload p;

	if (!name)
		return AI_ERR_INVALID_ARG;
	memset(&p, 0, sizeof(p));
	strscpy(p.name, name, sizeof(p.name));
	if (old_val)
		strscpy(p.old_val, old_val, sizeof(p.old_val));
	if (new_val)
		strscpy(p.new_val, new_val, sizeof(p.new_val));
	/* 采样走采样率表（默认 1/16，ai_telemetry_init 设置） */
	return ai_telemetry_emit(AI_CAT_KCONFIG, AI_EV_SYSCTL,
				 AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_sysctl_evt);
