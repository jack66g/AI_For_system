// SPDX-License-Identifier: GPL-2.0
/*
 * ai_lock.h - AIKernel 同步与锁子系统统一接口头（Prompt 09）
 *
 * 本文件是 kernel/locking/ + kernel/rcu/update.c 全部 AI 埋点的唯一接入点：
 *   A 轨（控制）：ai_lock_*_hook() 系列 —— 让 AI 参与锁策略决策，
 *                 空实现 = 原样放行（返回值不改变内核默认行为）；
 *   B 轨（感知）：第10类 锁竞争与同步感知的 payload 结构 + 发射辅助，
 *                 全量原始零脱敏（pid/锁地址/等待时长/waiter 数全保留）。
 *
 * 零回归策略：
 *   - CONFIG_AIKERNEL_LOCK=n：本头文件不参与任何编译（调用点条件剔除）；
 *   - CONFIG_AIKERNEL_TELEMETRY=n：ai_telemetry_* 退化为 static inline
 *     空函数（ai_telemetry.h 内置兜底），Hook 本身只计数不发射。
 *
 * 中断上下文安全：spin 路径埋点只在采样命中时取时间戳（per-CPU 槽位），
 * 发射零锁零分配；comm 拷贝直接读 current->comm。
 */

#ifndef _AIKERNEL_LOCK_AI_LOCK_H
#define _AIKERNEL_LOCK_AI_LOCK_H

#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"
#include <linux/types.h>
#include <linux/spinlock_types.h>

/* 内核类型前向声明（本头只传指针） */
struct mutex;
struct rw_semaphore;
struct task_struct;

/* ==================================================================
 * B 轨：第10类 锁竞争与同步感知 payload（事件编号对齐 enum ai_event_type
 * 10.01~10.04；首字节 type 区分计划内子事件）
 * ==================================================================
 */

enum ai_lock_sub_event {
	AI_LOCK_CONTENTION_WAIT		= 1,	/* lock_contention：入队 */
	AI_LOCK_CONTENTION_ACQUIRED,		/* lock_contention：获锁（含等待时长） */
	AI_LOCK_SPIN_CONTENTION,		/* spin_contention */
	AI_LOCK_RWSEM_READ,			/* rwsem_bias：读慢路径 */
	AI_LOCK_RWSEM_WRITE,			/* rwsem_bias：写慢路径 */
	AI_LOCK_RCU_GP,				/* rcu_gp */
	AI_LOCK_LOCKDEP_RECURSIVE,		/* lockdep_deadlock：递归 */
	AI_LOCK_LOCKDEP_CIRCULAR,		/* lockdep_deadlock：循环 */
	AI_LOCK_LOCKDEP_IRQ_INVERSION,		/* lockdep_deadlock：irq 反转 */
};

struct ai_lock_contention_payload {
	u8 type;			/* WAIT / ACQUIRED */
	u32 pid;
	u64 lock_addr;			/* 锁地址（零脱敏） */
	u32 waiter_count;		/* 入队时 waiter 数快照 */
	u64 wait_ns;			/* ACQUIRED 型：等待时长 */
	char comm[TASK_COMM_LEN];
};

struct ai_lock_spin_payload {
	u8 type;			/* AI_LOCK_SPIN_CONTENTION */
	u32 pid;
	u64 lock_addr;
	u64 wait_ns;			/* 争用等待时长（采样） */
	char comm[TASK_COMM_LEN];
};

struct ai_lock_rwsem_payload {
	u8 type;			/* AI_LOCK_RWSEM_READ / WRITE */
	u32 pid;
	u64 lock_addr;
	u32 waiters_read;		/* 读 waiter 数 */
	u32 waiters_write;		/* 写 waiter 数 */
	char comm[TASK_COMM_LEN];
};

struct ai_lock_rcu_payload {
	u8 type;			/* AI_LOCK_RCU_GP */
	u32 pid;
	u8 n;				/* 本次等待的宽限期数量 */
	u8 expedited;			/* 是否走 expedited 建议 */
	u64 wait_ns;			/* 全程等待时长 */
	char comm[TASK_COMM_LEN];
};

struct ai_lock_lockdep_payload {
	u8 type;			/* RECURSIVE / CIRCULAR / IRQ_INVERSION */
	u32 pid;
	u64 prev_class;			/* 已持锁类地址 */
	u64 next_class;			/* 待获取锁类地址 */
	u32 depth;			/* 当前锁深度 */
	char comm[TASK_COMM_LEN];
};

/* ---- 决策统计 ---- */

struct ai_lock_stats {
	u64 spin_hook_calls, spin_sampled;
	u64 mutex_hook_calls, mutex_hook_skip_spin;
	u64 rwsem_hook_calls;
	u64 rcu_hook_calls, rcu_hook_expedite;
	u64 lockdep_hook_calls;
	u64 emit_contention, emit_spin, emit_rwsem, emit_rcu, emit_deadlock;
};

#ifdef CONFIG_AIKERNEL_LOCK

/* ---- A 轨 Hook（实现见 ai_lock.c；空实现 = 原样放行） ---- */

/**
 * ai_lock_spin_hook() - AI 自适应 spin 策略（采样窗口开始）
 * @lock: 目标自旋锁
 *
 * 由 _raw_spin_lock 家族在锁前调用。空实现不干预 spin；内部按 1/256
 * 采样窗口在锁后由 ai_lock_spin_hook_done() 结算争用时长。
 */
void ai_lock_spin_hook(raw_spinlock_t *lock);

/**
 * ai_lock_spin_hook_done() - 采样窗口结束
 * @lock: 目标自旋锁
 *
 * 由 _raw_spin_lock 家族在锁后调用。空实现无操作。
 */
void ai_lock_spin_hook_done(raw_spinlock_t *lock);

/**
 * ai_lock_mutex_hook() - AI 竞争预测，乐观/悲观路径选择
 * @lock: 目标 mutex
 * @try_spin: 出参；true=继续尝试乐观自旋（默认），false=AI 建议直接入队
 *
 * 由 __mutex_lock_common() 入口调用。空实现不改 *try_spin。
 * 返回 true=放行继续（默认）。
 */
bool ai_lock_mutex_hook(struct mutex *lock, bool *try_spin);

/**
 * ai_lock_rwsem_hook() - AI 动态调整 reader/writer 偏向
 * @sem: 目标读写信号量
 * @kind: 1=读慢路径入口 2=写慢路径入口
 *
 * 由 rwsem_down_read_slowpath()/rwsem_down_write_slowpath() 入口调用。
 * 空实现无操作（AI 偏向决策预留位）。
 */
void ai_lock_rwsem_hook(struct rw_semaphore *sem, int kind);

/**
 * ai_lock_rcu_hook() - AI 预测回调压力，调整宽限期
 * @n: 本次等待的宽限期数量
 * @expedite: 出参；true=建议 expedited 宽限期（默认 false=正常路径）
 *
 * 由 __wait_rcu_gp() 入口调用。空实现不改 *expedite。
 */
void ai_lock_rcu_hook(int n, bool *expedite);

/**
 * ai_lock_lockdep_hook() - AI 分析锁依赖图，预测死锁
 * @curr: 当前任务
 * @depth: 当前锁深度
 *
 * 由 __lock_acquire() 链校验通过后调用。空实现无操作。
 */
void ai_lock_lockdep_hook(struct task_struct *curr, int depth);

/* ---- 第10类发射辅助（实现见 ai_lock.c；全部 sample_take + emit_direct） ---- */

void ai_telemetry_lock_contention(u64 lock_addr, u32 waiter_count);
void ai_telemetry_lock_contention_done(u64 lock_addr, u32 waiter_count,
				       u64 wait_ns);
void ai_telemetry_lock_spin(u64 lock_addr, u64 wait_ns);
void ai_telemetry_rwsem_bias(u64 lock_addr, int kind, u32 waiters_read,
			     u32 waiters_write);
void ai_telemetry_rcu_gp(int n, bool expedited, u64 wait_ns);
void ai_telemetry_lockdep_deadlock(u8 type, u64 prev_class, u64 next_class,
				   u32 depth);

/* ---- 决策框架 ---- */

void ai_lock_stats_read(struct ai_lock_stats *st);
bool ai_lock_sample_take(u32 rate);

#else /* !CONFIG_AIKERNEL_LOCK */

/* 空函数兜底：CONFIG_AIKERNEL_LOCK=n 时调用点不编译，
 * 此处兜底仅供 AIKernel/ 内部其他模块引用时保持可编译。 */
static inline void ai_lock_spin_hook(raw_spinlock_t *lock) { }
static inline void ai_lock_spin_hook_done(raw_spinlock_t *lock) { }
static inline bool ai_lock_mutex_hook(struct mutex *lock, bool *try_spin)
{ return true; }
static inline void ai_lock_rwsem_hook(struct rw_semaphore *sem, int kind) { }
static inline void ai_lock_rcu_hook(int n, bool *expedite) { }
static inline void ai_lock_lockdep_hook(struct task_struct *curr, int depth)
{ }
static inline void ai_telemetry_lock_contention(u64 lock_addr,
						u32 waiter_count)
{ }
static inline void ai_telemetry_lock_contention_done(u64 lock_addr,
						     u32 waiter_count,
						     u64 wait_ns)
{ }
static inline void ai_telemetry_lock_spin(u64 lock_addr, u64 wait_ns)
{ }
static inline void ai_telemetry_rwsem_bias(u64 lock_addr, int kind,
					   u32 waiters_read, u32 waiters_write)
{ }
static inline void ai_telemetry_rcu_gp(int n, bool expedited, u64 wait_ns)
{ }
static inline void ai_telemetry_lockdep_deadlock(u8 type, u64 prev_class,
						 u64 next_class, u32 depth)
{ }
static inline void ai_lock_stats_read(struct ai_lock_stats *st)
{ if (st) memset(st, 0, sizeof(*st)); }
static inline bool ai_lock_sample_take(u32 rate)
{ return false; }

#endif /* CONFIG_AIKERNEL_LOCK */

#endif /* _AIKERNEL_LOCK_AI_LOCK_H */
