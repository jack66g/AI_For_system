// SPDX-License-Identifier: GPL-2.0
/*
 * ai_sched.h - AIKernel 调度子系统统一接口头（Prompt 03）
 *
 * 本文件是 kernel/sched/ 全部 AI 埋点的唯一接入点：
 *   A 轨（控制）：ai_sched_*_hook() 系列 —— 让 AI 参与调度决策，
 *                 空实现 = 原样放行（返回值不改变内核默认行为）；
 *   B 轨（感知）：第1类 CPU 与调度感知的 payload 结构 + 事件包装，
 *                 全量原始零脱敏（pid/comm/prio/掩码全保留）。
 *
 * 零回归策略：
 *   - CONFIG_AIKERNEL_SCHED=n：本头文件不参与任何编译（kernel/sched 下
 *     各 .c 文件的条件 include 一并剔除），预处理产物与基线一致；
 *   - CONFIG_AIKERNEL_TELEMETRY=n：ai_telemetry_* 包装退化为 static inline
 *     空函数（ai_telemetry.h 内置兜底），Hook 本身只计数不发射。
 *
 * 遥测函数铁律：不阻塞、不分配（无 GFP_KERNEL）、无锁，仅供快速路径。
 */

#ifndef _AIKERNEL_SCHED_AI_SCHED_H
#define _AIKERNEL_SCHED_AI_SCHED_H

#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/string.h>
#include <linux/bitmap.h>

/* ==================================================================
 * B 轨：第1类 CPU 与调度感知 payload（事件编号对齐 enum ai_event_type）
 * ==================================================================
 * 每个 payload 首字节为 u8 type，区分计划内的子事件
 * （1.1 的 switch/wakeup/wakeup_new/migrate 共用 AI_EV_SCHED_CTX_SWITCH）。
 */

/* 01.01 上下文切换子事件 */
enum ai_sched_ctx_type {
	AI_SCHED_CTX_SWITCH	= 1,
	AI_SCHED_CTX_WAKEUP,
	AI_SCHED_CTX_WAKEUP_NEW,
	AI_SCHED_CTX_MIGRATE,
};

struct ai_sched_switch_payload {
	u8 type;			/* AI_SCHED_CTX_SWITCH */
	u32 prev_pid, next_pid;
	s32 prev_prio, next_prio;
	u32 prev_state;			/* 切换前任务状态位 */
	u16 cpu;
	char prev_comm[TASK_COMM_LEN];
	char next_comm[TASK_COMM_LEN];
};

struct ai_sched_wakeup_payload {
	u8 type;			/* AI_SCHED_CTX_WAKEUP */
	u32 pid;
	s32 prio;
	s32 target_cpu;
	u8 success;
	char comm[TASK_COMM_LEN];
};

struct ai_sched_wakeup_new_payload {
	u8 type;			/* AI_SCHED_CTX_WAKEUP_NEW */
	u32 pid;
	s32 prio;
	s32 target_cpu;
	char comm[TASK_COMM_LEN];
};

struct ai_sched_migrate_payload {
	u8 type;			/* AI_SCHED_CTX_MIGRATE */
	u32 pid;
	s32 orig_cpu;
	s32 dest_cpu;
	char comm[TASK_COMM_LEN];
};

/* 01.02 调度延迟子事件 */
enum ai_sched_latency_type {
	AI_SCHED_LATENCY	= 1,
	AI_SCHED_BLOCK,
};

struct ai_sched_latency_payload {
	u8 type;			/* AI_SCHED_LATENCY / AI_SCHED_BLOCK */
	u32 pid;
	u64 run_delay_ns;		/* sched_info.run_delay（CONFIG_SCHED_INFO 关闭为 0） */
	u64 wait_delay_ns;		/* se.statistics.wait_sum（CONFIG_SCHEDSTATS 关闭为 0） */
	u32 block_reason;		/* 阻塞子事件：任务状态位 */
	u64 wchan;			/* 阻塞子事件：wchan 符号地址（本步恒 0，符号解析后续步骤） */
	char comm[TASK_COMM_LEN];
};

/* 01.03 CPU 负载（周期）子事件 */
enum ai_sched_cpu_load_type {
	AI_CPU_LOAD		= 1,
	AI_CPU_UTILIZATION,
	AI_CPU_FREQUENCY,
	AI_CPU_CSTATE,
	AI_CPU_TEMPERATURE,
};

struct ai_cpu_load_payload {
	u8 type;			/* AI_CPU_LOAD */
	u16 cpu;
	u32 load_1min, load_5min, load_15min;	/* avenrun 定点值（实际负载 = 值/2048） */
};

struct ai_cpu_utilization_payload {
	u8 type;			/* AI_CPU_UTILIZATION */
	u16 cpu;
	u32 user_pct, sys_pct, iowait_pct, idle_pct, steal_pct, softirq_pct;
};

struct ai_cpu_frequency_payload {
	u8 type;			/* AI_CPU_FREQUENCY */
	u16 cpu;
	u32 cur_freq_khz;
	u32 max_freq_khz;
	char governor[24];
};

struct ai_cpu_cstate_payload {
	u8 type;			/* AI_CPU_CSTATE */
	u16 cpu;
	u32 state_idx;
	u64 residency_us;
	char state_name[24];
};

struct ai_cpu_temperature_payload {
	u8 type;			/* AI_CPU_TEMPERATURE */
	u16 cpu;
	s32 temp_millicelsius;
	s32 trip_point;
	char zone_name[32];
};

/* 01.04 PELT 子事件 */
enum ai_sched_pelt_type {
	AI_PELT_SE	= 1,
	AI_PELT_CFS,
};

struct ai_pelt_se_payload {
	u8 type;			/* AI_PELT_SE */
	u32 pid;
	u32 util_avg, load_avg, runnable_avg;
	char comm[TASK_COMM_LEN];
};

struct ai_pelt_cfs_payload {
	u8 type;			/* AI_PELT_CFS */
	u16 cpu;
	u32 util_avg, load_avg, runnable_avg;
};

/* 01.05 运行队列状态子事件 */
enum ai_sched_rq_type {
	AI_RQ_DEPTH	= 1,
	AI_RQ_LOAD_BALANCE,
};

struct ai_rq_depth_payload {
	u8 type;			/* AI_RQ_DEPTH */
	u16 cpu;
	u32 nr_running;
	u32 nr_uninterruptible;		/* per-CPU 近似（全局和才精确，注释说明） */
	u32 nr_iowait;
};

struct ai_load_balance_payload {
	u8 type;			/* AI_RQ_LOAD_BALANCE */
	s32 src_cpu;
	s32 dst_cpu;
	s32 imbalance_pct;
	s32 moved_tasks;
	u8 failed;
};

/* 01.06 PSI 压力 */
enum ai_sched_psi_type {
	AI_PSI	= 1,
};

struct ai_psi_payload {
	u8 type;			/* AI_PSI */
	u8 resource;			/* 0=cpu 1=memory 2=io */
	u32 some_avg10, some_avg60, some_avg300;
	u32 full_avg10, full_avg60, full_avg300;
};

/* 01.07 CPU 隔离与热插拔子事件 */
enum ai_sched_cpu_hotplug_type {
	AI_SCHED_AFFINITY_CHANGE	= 1,
	AI_SCHED_HOTPLUG,
};

struct ai_sched_affinity_payload {
	u8 type;			/* AI_SCHED_AFFINITY_CHANGE */
	u32 pid;
	unsigned long old_mask[BITS_TO_LONGS(NR_CPUS)];
	unsigned long new_mask[BITS_TO_LONGS(NR_CPUS)];
	char comm[TASK_COMM_LEN];
};

struct ai_cpu_hotplug_payload {
	u8 type;			/* AI_SCHED_HOTPLUG */
	u16 cpu;
	u8 online;
};

/* 01.08 调度域拓扑 */
enum ai_sched_domain_type {
	AI_SCHED_DOMAIN	= 1,
};

struct ai_sched_domain_payload {
	u8 type;			/* AI_SCHED_DOMAIN */
	u16 cpu;
	u16 level;
	u32 flags;
	unsigned long span_bits[BITS_TO_LONGS(NR_CPUS)];
	char name[16];
};

/* ==================================================================
 * A 轨：AI 调度决策框架
 * ==================================================================
 */

/* 进程分类 */
enum ai_sched_class {
	AI_SCHED_CLASS_AI_LOAD		= 0,	/* AI 负载（计算密集/系统关键） */
	AI_SCHED_CLASS_INTERACTIVE,		/* 交互式（睡眠多、片小） */
	AI_SCHED_CLASS_BATCH,			/* 批处理 */
	AI_SCHED_CLASS_MAX,
};

/* ai_sched_query() 查询编号（sched_ext/BPF 调度器可调用） */
enum ai_sched_query_id {
	AI_SCHED_QUERY_SCX_READY	= 1,	/* sched_ext 启用时探测 AI 辅助可用性 */
	AI_SCHED_QUERY_CLASSIFY,		/* in=int pid; out=enum ai_sched_class */
	AI_SCHED_QUERY_TIMESLICE,		/* in=int pid; out=u64 预测时间片(ns) */
};

/* 决策统计（/proc/ai/sched/stats 数据源） */
struct ai_sched_stats {
	u64 pick_next_calls, pick_next_ai_changed;
	u64 cfs_pick_calls, cfs_pick_ai_changed;
	u64 lb_calls, lb_ai_veto;
	u64 pelt_adjust_calls;
	u64 context_switch_calls;
	u64 rt_admission_calls, dl_admission_calls, admission_rejected;
	u64 isolate_hook_calls;
	u64 query_calls;
	u64 classify[AI_SCHED_CLASS_MAX];
};

#ifdef CONFIG_AIKERNEL_SCHED

/* ---- A 轨 Hook（实现见 ai_sched.c；空实现 = 原样放行） ---- */

/**
 * ai_sched_pick_next_hook() - AI 参与选下一个运行任务
 * @prev: 出参/入参，当前任务指针（AI 可替换）
 * @next: 出参/入参，候选任务指针（AI 可替换，必须为可运行任务）
 *
 * 由 __schedule() 在 pick_next_task() 之后调用。空实现不修改任何值。
 */
void ai_sched_pick_next_hook(struct task_struct **prev, struct task_struct **next);

/**
 * ai_cfs_pick_next_hook() - AI 辅助 CFS 候选排序
 * @prev: 当前任务
 * @next: CFS 选中的下一个任务
 *
 * 返回 AI 调整后的候选（空实现原样返回 @next）。
 */
struct task_struct *ai_cfs_pick_next_hook(struct task_struct *prev,
					  struct task_struct *next);

/**
 * ai_load_balance_hook() - AI 建议任务是否迁移
 * @src_cpu: 源（最忙）CPU
 * @dst_cpu: 目标 CPU
 * @imbalance: 失衡量（环境中的 env.imbalance）
 * @proceed: 出参；true=继续迁移（默认），false=AI 建议跳过本次迁移
 *
 * 由 sched_balance_rq()（=6.18 的 load_balance()）找到最忙队列后调用。
 * 空实现恒置 *proceed = true。
 */
int ai_load_balance_hook(int src_cpu, int dst_cpu, unsigned long imbalance,
			 bool *proceed);

/**
 * ai_pelt_adjust_hook() - AI 修正 PELT 衰减因子
 * @delta: 距上次更新的原始时间差（ns，已除 1024 前）
 * @load: 本次负载（load/runnable/running 综合）
 *
 * 返回调整后的 delta（空实现原样返回）。返回 0 表示 AI 要求本次不更新。
 */
u64 ai_pelt_adjust_hook(u64 delta, unsigned long load);

/**
 * ai_sched_context_switch_hook() - 上下文切换观察点
 * @prev: 切换出的任务
 * @next: 切换入的任务
 * @cpu: 当前 CPU
 */
void ai_sched_context_switch_hook(struct task_struct *prev,
				  struct task_struct *next, int cpu);

/**
 * ai_sched_rt_admission_hook() - RT/DL 任务准入控制
 * @p: 入队任务
 *
 * 由 enqueue_task_rt()/enqueue_task_dl() 入口调用。本步只计数不拦截
 * （返回值 1=允许，为后续 AI 准入决策预留的默认值）。
 */
int ai_sched_rt_admission_hook(struct task_struct *p);

/**
 * ai_sched_isolate_hook() - AI 动态 CPU 隔离建议
 * @isolated: 当前隔离 CPU 掩码
 * @hk_type: housekeeping 类型（HK_TYPE_*）
 *
 * 由 housekeeping_init() 调用；空实现只计数/采样，不修改隔离配置。
 */
void ai_sched_isolate_hook(const struct cpumask *isolated, unsigned long hk_type);

/**
 * ai_sched_query() - sched_ext 可调用的 AI 辅助函数
 * @query_id: enum ai_sched_query_id
 * @in/@in_len: 入参缓冲；@out/@out_len: 出参缓冲
 *
 * 空实现返回 AI_ERR_NOT_IMPLEMENTED（scx_enable 探测时记录计数）。
 */
int ai_sched_query(u32 query_id, const void *in, size_t in_len,
		   void *out, size_t out_len);

/* ---- 决策框架（实现见 ai_sched.c） ---- */

/**
 * ai_sched_classify_task() - 进程分类（AI负载/交互式/批处理）
 * @p: 任务
 *
 * 返回 enum ai_sched_class。本步为确定性占位启发式，AI 推理后续步骤替换。
 */
int ai_sched_classify_task(struct task_struct *p);

/**
 * ai_sched_predict_timeslice() - 时间片预测（框架默认值）
 * @p: 任务
 *
 * CFS 返回 p->se.slice，RT 返回 p->rt.time_slice，其余 0。
 */
u64 ai_sched_predict_timeslice(struct task_struct *p);

/**
 * ai_telemetry_pelt_se_sample() - update_curr 热路径 PELT 采样（内部限频 1/64）
 * @se: 当前 CFS 调度实体（可能为组实体，组实体只采 cfs_rq）
 * @cfs_rq: 当前 CFS 队列
 *
 * 每 64 次调用发射一次 pelt_se + pelt_cfs 事件。
 */
void ai_telemetry_pelt_se_sample(struct sched_entity *se, struct cfs_rq *cfs_rq);

/**
 * ai_sched_stats_read() - 决策统计读取
 * @st: 输出统计
 */
void ai_sched_stats_read(struct ai_sched_stats *st);

#else /* !CONFIG_AIKERNEL_SCHED */

/* 空函数兜底：CONFIG_AIKERNEL_SCHED=n 时 kernel/sched 不包含本头文件，
 * 此处兜底仅供 AIKernel/ 内部其他模块引用时保持可编译。 */
static inline void ai_sched_pick_next_hook(struct task_struct **prev,
					   struct task_struct **next) { }
static inline struct task_struct *ai_cfs_pick_next_hook(struct task_struct *prev,
							struct task_struct *next)
{ return next; }
static inline int ai_load_balance_hook(int src_cpu, int dst_cpu,
				       unsigned long imbalance, bool *proceed)
{ if (proceed) *proceed = true; return AI_OK; }
static inline u64 ai_pelt_adjust_hook(u64 delta, unsigned long load)
{ return delta; }
static inline void ai_sched_context_switch_hook(struct task_struct *prev,
						struct task_struct *next, int cpu) { }
static inline int ai_sched_rt_admission_hook(struct task_struct *p) { return 1; }
static inline void ai_sched_isolate_hook(const struct cpumask *isolated,
					 unsigned long hk_type) { }
static inline int ai_sched_query(u32 query_id, const void *in, size_t in_len,
				 void *out, size_t out_len)
{ return AI_ERR_NOT_IMPLEMENTED; }
static inline int ai_sched_classify_task(struct task_struct *p)
{ return AI_SCHED_CLASS_BATCH; }
static inline u64 ai_sched_predict_timeslice(struct task_struct *p) { return 0; }
static inline void ai_telemetry_pelt_se_sample(struct sched_entity *se,
					       struct cfs_rq *cfs_rq) { }
static inline void ai_sched_stats_read(struct ai_sched_stats *st)
{ if (st) memset(st, 0, sizeof(*st)); }

#endif /* CONFIG_AIKERNEL_SCHED */

#endif /* _AIKERNEL_SCHED_AI_SCHED_H */
