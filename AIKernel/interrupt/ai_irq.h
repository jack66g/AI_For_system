// SPDX-License-Identifier: GPL-2.0
/*
 * ai_irq.h - AIKernel 中断子系统统一接口头（Prompt 09）
 *
 * 本文件是 kernel/irq/ + kernel/softirq.c + kernel/workqueue.c +
 * kernel/watchdog.c 全部 AI 埋点的唯一接入点：
 *   A 轨（控制）：ai_irq_*_hook() 系列 —— 让 AI 参与中断管理决策，
 *                 空实现 = 原样放行（返回值不改变内核默认行为）；
 *   B 轨（感知）：第9类 中断与异常感知的 payload 结构 + 发射辅助，
 *                 全量原始零脱敏（irq 号/全位图/worker 统计全保留）。
 *
 * 零回归策略：
 *   - CONFIG_AIKERNEL_INTERRUPT=n：本头文件不参与任何编译（调用点条件剔除），
 *     预处理产物与基线一致；
 *   - CONFIG_AIKERNEL_TELEMETRY=n：ai_telemetry_* 退化为 static inline 空函数
 *     （ai_telemetry.h 内置兜底），Hook 本身只计数不发射。
 *
 * 中断上下文埋点铁律（本模块核心）：可重入、原子写、零锁、零分配、
 * 零 printk；时间戳一律 ktime_get_ns()（IRQ 安全）；per-CPU 槽位预分配。
 */

#ifndef _AIKERNEL_INTERRUPT_AI_IRQ_H
#define _AIKERNEL_INTERRUPT_AI_IRQ_H

#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"
#include <linux/types.h>
#include <linux/bitmap.h>

/* 内核类型前向声明（本头只传指针，不拉内核内部头） */
struct irq_affinity;
struct irq_affinity_desc;
struct irqaction;
struct worker_pool;
struct cpumask;

/* ==================================================================
 * B 轨：第9类 中断与异常感知 payload（事件编号对齐 enum ai_event_type
 * 09.01~09.05；首字节 type 区分计划内子事件）
 * ==================================================================
 */

enum ai_irq_sub_event {
	AI_IRQ_AFFINITY_CREATE	= 1,	/* irq_affinity_change：多队列掩码生成 */
	AI_IRQ_AFFINITY_SET,		/* irq_affinity_change：动态亲和性设置 */
	AI_IRQ_THREAD,			/* irq_thread：线程化决策 */
	AI_IRQ_SOFTIRQ_ENTRY,		/* softirq_entry */
	AI_IRQ_SOFTIRQ_EXIT,		/* softirq_exit（含延迟） */
	AI_IRQ_WORKQUEUE_CREATE,	/* workqueue_launch：worker 增加 */
	AI_IRQ_WORKQUEUE_DESTROY,	/* workqueue_launch：worker 减少 */
	AI_IRQ_WATCHDOG_NEAR,		/* watchdog_lockup：近事件（阈值一半） */
	AI_IRQ_WATCHDOG_LOCKUP,		/* watchdog_lockup：实际触发 */
};

struct ai_irq_affinity_payload {
	u8 type;			/* AI_IRQ_AFFINITY_CREATE / AI_IRQ_AFFINITY_SET */
	u32 irq;			/* set 型：irq 号；create 型：0 */
	u32 force;			/* set 型：force 标志 */
	u32 nvecs;			/* create 型：总向量数 */
	u32 pre_vectors, post_vectors;	/* create 型：前后保留向量 */
	u32 nr_sets;			/* create 型：集合数 */
	u16 nr_cpus;			/* mask 有效 CPU 数 */
	unsigned long mask_words[BITS_TO_LONGS(NR_CPUS)];	/* set 型：全位图 */
};

struct ai_irq_thread_payload {
	u8 type;			/* AI_IRQ_THREAD */
	u32 irq;
	u32 thread_pid;			/* 线程化 kthread 的 pid */
	u8 secondary;			/* 共享中断次级线程 */
	u8 forced;			/* 强制线程化（IRQF_FORCE_THREAD 路径） */
	char thread_name[TASK_COMM_LEN];
};

struct ai_irq_softirq_payload {
	u8 type;			/* AI_IRQ_SOFTIRQ_ENTRY / AI_IRQ_SOFTIRQ_EXIT */
	u8 vec_nr;			/* softirq 向量号 */
	u32 count;			/* exit 型：kstat 差值（该向量累计次数） */
	u64 latency_ns;			/* exit 型：向量处理时长 */
};

struct ai_irq_workqueue_payload {
	u8 type;			/* AI_IRQ_WORKQUEUE_CREATE / DESTROY */
	u32 pool_id;			/* worker_pool->id */
	u32 cpu;			/* WORK_CPU_UNBOUND 表示非绑定池 */
	s32 nice;			/* 池 nice 值 */
	u32 nr_workers;			/* 池内 worker 总数 */
	u32 nr_idle;			/* 空闲 worker 数 */
	u32 nr_running;			/* 池内运行中任务近似 */
};

struct ai_irq_watchdog_payload {
	u8 type;			/* AI_IRQ_WATCHDOG_NEAR / AI_IRQ_WATCHDOG_LOCKUP */
	u8 cpu;
	u32 duration_s;			/* 本次超时秒数 */
	u32 threshold_s;		/* 当前生效阈值秒数（AI 可调后实际值） */
	u32 pid;
	char comm[TASK_COMM_LEN];
};

/* ---- 决策统计（/proc 数据源预留；本步经 ai_irq_stats_read 读取） ---- */

struct ai_irq_stats {
	u64 affinity_hook_calls, affinity_hook_changed;
	u64 thread_hook_calls, thread_hook_skipped;
	u64 softirq_hook_calls;
	u64 wq_hook_calls;
	u64 watchdog_hook_calls, watchdog_threshold_adjusted;
	u64 emit_affinity, emit_thread, emit_softirq, emit_wq, emit_watchdog;
};

#ifdef CONFIG_AIKERNEL_INTERRUPT

/* ---- A 轨 Hook（实现见 ai_irq.c；空实现 = 原样放行） ---- */

/**
 * ai_irq_affinity_hook() - AI 参与多队列中断亲和性掩码生成
 * @nvecs: 总向量数
 * @affd:  亲和性需求描述
 * @masks: 已填充的亲和性掩码数组（AI 可调整）
 *
 * 由 irq_create_affinity_masks() 掩码填充后调用。空实现不改掩码。
 * 返回 0（预留：AI 返回非 0 表示已调整）。
 */
int ai_irq_affinity_hook(unsigned int nvecs, struct irq_affinity *affd,
			 struct irq_affinity_desc *masks);

/**
 * ai_irq_thread_hook() - AI 决定中断是否线程化
 * @irq: 中断号
 * @new: 待注册的 irqaction
 *
 * 由 __setup_irq() 在创建 handler 线程前调用。空实现返回 true=按原逻辑
 * 创建线程；返回 false=AI 建议跳过线程化（仅非强制路径，IRQF_FORCE_THREAD
 * 与嵌套线程不受影响）。
 */
bool ai_irq_thread_hook(unsigned int irq, struct irqaction *new);

/**
 * ai_irq_softirq_hook() - AI 调整 softirq 处理顺序/批次
 * @pending: 待处理软中断位图（AI 可调整处理顺序）
 * @max_restart: 最大重启次数（AI 可调整批次大小）
 *
 * 由 handle_softirqs() 入口调用。空实现不改任何值。
 */
void ai_irq_softirq_hook(u32 *pending, unsigned int *max_restart);

/**
 * ai_irq_wq_hook() - AI 预测 worker 需求
 * @pool: 目标 worker 池
 * @create_worker: 出参；true=继续按原逻辑创建 worker（默认）
 *
 * 由 manage_workers() 在 maybe_create_worker() 前调用。空实现不改。
 */
void ai_irq_wq_hook(struct worker_pool *pool, bool *create_worker);

/**
 * ai_irq_watchdog_hook() - AI 自适应 lockup 检测阈值
 * @duration: 本次计算的超时时长（秒）
 * @threshold: 出参；当前生效阈值（AI 可调，空实现不改）
 *
 * 由 watchdog_timer_fn() 判定后调用。空实现不改阈值。
 * 返回 0。
 */
int ai_irq_watchdog_hook(unsigned long duration, unsigned long *threshold);

/* ---- 第9类发射辅助（实现见 ai_irq.c；全部 sample_take + emit_direct） ---- */

void ai_telemetry_irq_affinity_create(unsigned int nvecs,
				      struct irq_affinity *affd);
void ai_telemetry_irq_affinity_set(u32 irq, const struct cpumask *mask,
				   bool force);
void ai_telemetry_irq_thread(u32 irq, u32 thread_pid, const char *thread_name,
			     u8 secondary, u8 forced);
void ai_telemetry_softirq_entry(u8 vec_nr);
void ai_telemetry_softirq_exit(u8 vec_nr);
void ai_telemetry_workqueue_launch(u32 pool_id, u32 cpu, s32 nice,
				   u32 nr_workers, u32 nr_idle,
				   u32 nr_running, u8 create);
void ai_telemetry_watchdog_lockup(u8 type, unsigned long duration,
				  unsigned long threshold);

/* ---- 决策框架 ---- */

void ai_irq_stats_read(struct ai_irq_stats *st);
bool ai_irq_sample_take(u32 rate);

#else /* !CONFIG_AIKERNEL_INTERRUPT */

/* 空函数兜底：CONFIG_AIKERNEL_INTERRUPT=n 时调用点不编译，
 * 此处兜底仅供 AIKernel/ 内部其他模块引用时保持可编译。 */
static inline int ai_irq_affinity_hook(unsigned int nvecs,
				       struct irq_affinity *affd,
				       struct irq_affinity_desc *masks)
{ return 0; }
static inline bool ai_irq_thread_hook(unsigned int irq,
				      struct irqaction *new)
{ return true; }
static inline void ai_irq_softirq_hook(u32 *pending,
				       unsigned int *max_restart) { }
static inline void ai_irq_wq_hook(struct worker_pool *pool,
				  bool *create_worker) { }
static inline int ai_irq_watchdog_hook(unsigned long duration,
				       unsigned long *threshold)
{ return 0; }
static inline void ai_telemetry_irq_affinity_create(unsigned int nvecs,
						    struct irq_affinity *affd)
{ }
static inline void ai_telemetry_irq_affinity_set(u32 irq,
						 const struct cpumask *mask,
						 bool force)
{ }
static inline void ai_telemetry_irq_thread(u32 irq, u32 thread_pid,
					   const char *thread_name,
					   u8 secondary, u8 forced)
{ }
static inline void ai_telemetry_softirq_entry(u8 vec_nr) { }
static inline void ai_telemetry_softirq_exit(u8 vec_nr) { }
static inline void ai_telemetry_workqueue_launch(u32 pool_id, u32 cpu,
						 s32 nice, u32 nr_workers,
						 u32 nr_idle, u32 nr_running,
						 u8 create)
{ }
static inline void ai_telemetry_watchdog_lockup(u8 type, unsigned long duration,
						unsigned long threshold)
{ }
static inline void ai_irq_stats_read(struct ai_irq_stats *st)
{ if (st) memset(st, 0, sizeof(*st)); }
static inline bool ai_irq_sample_take(u32 rate)
{ return false; }

#endif /* CONFIG_AIKERNEL_INTERRUPT */

#endif /* _AIKERNEL_INTERRUPT_AI_IRQ_H */
