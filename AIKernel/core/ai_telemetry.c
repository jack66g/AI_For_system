// SPDX-License-Identifier: GPL-2.0
/*
 * ai_telemetry.c - AIKernel 遥测采集核心（per-CPU ring buffer）
 *
 * 设计：
 *   - 每 CPU 128KB 环形缓冲（alloc_percpu 动态分配），无锁写入；
 *   - 生产者 = 属主 CPU（preempt_disable 保证同一 CPU 内完成写入），
 *     单写 head（smp_store_release 发布）；
 *   - 消费者 = AI Runtime（单读者语义），原子推进 tail；
 *   - 满则丢弃并累计 dropped（不覆盖未读数据、不阻塞）；
 *   - 采样：per (category,event) 采样率表，rate=0 丢弃 / 1 全量 / N 每 N 条记 1 条；
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
#include "ai_telemetry.h"

/*
 * per-CPU ring buffer 布局：
 *   - 控制结构（head/tail/计数）为小尺寸 DEFINE_PER_CPU（几字节/CPU）；
 *   - 128KB 数据缓冲为每 CPU 独立的 vmalloc 区域（指针存于控制结构中）。
 * 原因：alloc_percpu() 无法分配 >= PCPU_MIN_UNIT_SIZE(32KB, x86) 的对象，
 * 而每 CPU 128KB 数据区必须按设计预算独立可寻址、无锁写。
 */

struct ai_ring_cpu {
	u32 head;              /* 写位置（仅属主 CPU 写，release 发布） */
	atomic_t tail;         /* 读位置（消费者原子推进） */
	u32 emitted;           /* 成功写入条数 */
	u32 dropped;           /* 满丢弃条数 */
	u32 sampled_skip;      /* 采样跳过条数 */
	u32 sample_counter;    /* 采样计数器（per-CPU 全局） */
	u8 *data;              /* 128KB 环形数据缓冲（vmalloc，page 对齐） */
} ____cacheline_aligned_in_smp;

static DEFINE_PER_CPU(struct ai_ring_cpu, ai_ring_cpus);
static bool ai_telemetry_ready;

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

	/*
	 * 关键事件（OOM/内存错误/KASAN 等训练金矿）：ring 满时逐出最旧记录
	 * 腾出空间，保证关键事件不被高频事件淹没。与读者共用 tail 的
	 * cmpxchg 推进（单读者语义不受破坏）；非关键事件保持"满则丢弃"。
	 */
	if (rec->severity >= AI_SEV_CRITICAL) {
		while (ai_ring_free(r, head, tail) < total) {
			struct ai_telemetry_record old;
			u32 old_tail = tail;
			size_t old_total;

			ai_ring_copy_out(r, tail, &old,
					 AI_TELEMETRY_HEADER_LEN);
			old_total = AI_TELEMETRY_HEADER_LEN + old.data_len;
			if (old_total > AI_TELEMETRY_RING_SIZE - 1)
				return AI_ERR_RING_FULL;
			if (atomic_cmpxchg(&r->tail, old_tail,
					   old_tail + old_total) != old_tail) {
				/* 读者并发推进：从新 tail 重读 */
				tail = (u32)atomic_read(&r->tail);
				continue;
			}
			r->dropped++;   /* 被逐出的旧记录计为丢弃 */
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

/* 读出记录（单读者语义；cap 不足时保留整条记录） */
static int ai_ring_read_from(struct ai_ring_cpu *r, void *buf, size_t cap,
			     size_t *out_bytes)
{
	size_t copied = 0;

	for (;;) {
		struct ai_telemetry_record rec;
		size_t total;
		u32 tail, head;

		tail = (u32)atomic_read(&r->tail);
		head = smp_load_acquire(&r->head);
		if (tail == head)
			break;

		ai_ring_copy_out(r, tail, &rec, AI_TELEMETRY_HEADER_LEN);
		total = AI_TELEMETRY_HEADER_LEN + rec.data_len;

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
			copied = 0;   /* 其他读者推进了 tail：从新位置重读 */
			continue;
		}
		copied += total;
	}

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
		memset(r->data, 0, AI_TELEMETRY_RING_SIZE);
		r->head = 0;
		atomic_set(&r->tail, 0);
		r->emitted = r->dropped = r->sampled_skip = 0;
		r->sample_counter = 0;
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
	pr_info("AIKernel: telemetry ready (%u CPU x %dKB ring buffers)\n",
		nr_cpu_ids, AI_TELEMETRY_RING_SIZE / 1024);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_telemetry_init);

void ai_telemetry_exit(void)
{
	int cpu;

	if (!ai_telemetry_ready)
		return;

	/*
	 * 先置 ready=false 再释放 ring：vfree() 会触发子系统感知埋点
	 * （如 mm 的 __free_pages → ai_mm_emit_page_free），若 ready 仍为
	 * true，emit 会在已释放/未映射的 ring 上写入 → 内核崩溃
	 * （KUnit ai_runtime 套件实测捕获）。先关闸门保证释放路径安全。
	 */
	ai_telemetry_ready = false;

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

	preempt_disable();
	r = per_cpu_ptr(&ai_ring_cpus, smp_processor_id());

	if (!sampling_done && !ai_ring_sample(r, rate)) {
		preempt_enable();
		return AI_OK;
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
	if (rc == AI_OK)
		r->emitted++;
	else
		r->dropped++;
	preempt_enable();

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

/* ---- 清空（感知数据清空） ---- */

int ai_telemetry_reset(void)
{
	int cpu;

	if (!ai_telemetry_ready)
		return AI_ERR_DISABLED;

	for_each_possible_cpu(cpu) {
		struct ai_ring_cpu *r = per_cpu_ptr(&ai_ring_cpus, cpu);

		memset(r->data, 0, AI_TELEMETRY_RING_SIZE);
		r->head = 0;
		atomic_set(&r->tail, 0);
		r->emitted = r->dropped = r->sampled_skip = 0;
		r->sample_counter = 0;
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
	st->dropped = r->dropped;
	st->sampled_skip = r->sampled_skip;
	st->ring_size = AI_TELEMETRY_RING_SIZE;
	st->head = r->head;
	st->tail = (u32)atomic_read(&r->tail);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_telemetry_stats);

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
