// SPDX-License-Identifier: GPL-2.0
/*
 * ai_bpf.h - AIKernel BPF/Tracing/Perf 子系统统一接口头（Prompt 11，重构计划 模块13）
 *
 * 本文件是 kernel/bpf/、kernel/trace/、kernel/events/、kernel/kprobes.c
 * 全部 AI 埋点的唯一接入点：
 *   A 轨（控制）：ai_bpf_*_hook() 系列 —— AI 观察/建议 BPF 与 Tracing 行为，
 *                 空实现 = 原样放行（不修改任何入参/出参/返回值）；
 *   A 轨（执行载体）：ai_bpf_query()/ai_bpf_telemetry()/BPF_MAP_TYPE_AI_MODEL
 *                 —— BPF 程序调 AI 推理、发遥测、存模型参数（helper 包装在
 *                 kernel/bpf/helpers.c，核心逻辑在本模块）；
 *   B 轨（感知）：第14类 BPF/Tracing/Perf 感知的 payload 结构 + 发射辅助，
 *                 全量原始零脱敏。
 *
 * 零回归策略：
 *   - CONFIG_AIKERNEL_BPF=n：本头文件不参与任何编译（kernel/ 调用点 #ifdef 剔除）；
 *   - CONFIG_AIKERNEL_TELEMETRY=n：ai_telemetry_* 退化为 static inline
 *     空函数（ai_telemetry.h 内置兜底），Hook 本身只计数不发射。
 *
 * 热路径安全性（BPF 执行/ftrace/kprobe/过滤匹配）：
 *   - 全部发射 = sample_take + 栈上 payload + emit_direct 直写（无锁无分配）；
 *   - per-CPU 计数器一律直接对符号操作（Prompt 09 早期启动崩溃先例）；
 *   - AI PMU 发射 = static_key 门控（无 perf 监听时单分支 ≈1ns）。
 *
 * 跨目录类型隔离：Hook 全部传标量/void*（filter 指针/op 指针），不引入
 * struct bpf_prog、struct event_filter、struct kprobe、struct ftrace_ops
 * 等类型依赖，ai_bpf.c 在任意 CONFIG 组合可编译。
 */

#ifndef _AIKERNEL_BPF_AI_BPF_H
#define _AIKERNEL_BPF_AI_BPF_H

#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"
#include <linux/string.h>
#include <linux/types.h>

/* ==================================================================
 * B 轨：第14类 BPF/Tracing/Perf 感知 payload（事件编号对齐 enum
 * ai_event_type 14.01~14.04；首字节 type 区分计划内子事件）
 * ==================================================================
 */

enum ai_bpf_sub_event {
	AI_BPF_PROG_LOAD		= 1,	/* 14.01 BPF 程序加载 */
	AI_BPF_PROG_RUN,			/* 14.01 BPF 程序执行 */
	AI_BPF_AI_QUERY,			/* 14.01 AI 推理调用记录（AI 自我观测） */
	AI_BPF_MAP_CREATE,			/* 14.02 BPF Map 创建 */
	AI_BPF_TRACE_EVENT_OPEN,		/* 14.03 trace 事件文件打开 */
	AI_BPF_TRACE_FILTER_CHANGE,		/* 14.03 trace 过滤器变更 */
	AI_BPF_FTRACE_FUNCTION,			/* 14.03 ftrace 函数采样 */
	AI_BPF_PERF_EVENT_OPEN,			/* 14.04 perf 事件打开 */
	AI_BPF_PMU_SAMPLE,			/* 14.04 AI PMU 采样 */
	AI_BPF_KPROBE_REGISTER,			/* 14.03 kprobe 注册 */
	AI_BPF_KPROBE_HIT,			/* 14.03 kprobe 命中 */
	AI_BPF_VERIFIER_DECISION,		/* 14.01 验证器判定 */
};

struct ai_bpf_prog_load_payload {
	u8 type;			/* AI_BPF_PROG_LOAD */
	u32 prog_type;			/* enum bpf_prog_type */
	u32 insn_cnt;			/* 指令数 */
	s32 result;			/* 0=成功 负=失败 errno */
	char prog_name[16];		/* BPF 程序名（bpf_obj_name_cpy 上限 15+1） */
};

struct ai_bpf_prog_run_payload {
	u8 type;			/* AI_BPF_PROG_RUN */
	u32 prog_type;			/* enum bpf_prog_type */
	u64 run_count;			/* per-CPU 累计执行次数 */
};

struct ai_bpf_ai_query_payload {
	u8 type;			/* AI_BPF_AI_QUERY */
	u32 model_id;			/* 目标模型句柄 */
	u32 input_len;			/* 输入长度 */
	u32 output_len;			/* 实际输出长度 */
	s32 result;			/* 0=成功 负=失败 errno */
	u64 latency_ns;			/* 推理耗时（AI PMU 同步采集） */
	u64 calls;			/* per-CPU 累计调用次数 */
};

struct ai_bpf_map_create_payload {
	u8 type;			/* AI_BPF_MAP_CREATE */
	u32 map_type;			/* enum bpf_map_type（AI_MODEL=34） */
	u32 max_entries;
	u32 key_size;
	u32 value_size;
	u64 mem_bytes;			/* 内存用量 */
	char map_name[16];		/* map 名 */
};

struct ai_bpf_trace_event_payload {
	u8 type;			/* AI_BPF_TRACE_EVENT_OPEN */
	u32 event_id;			/* trace 事件 id */
	u32 mode;			/* file->f_mode 读写模式位 */
	char event_name[64];		/* 事件名全量 */
};

struct ai_bpf_trace_filter_payload {
	u8 type;			/* AI_BPF_TRACE_FILTER_CHANGE */
	u32 event_id;			/* trace 事件 id（子系统=0） */
	s32 result;			/* 0=成功 负=失败 errno */
	char system[32];		/* 子系统名 */
	char filter[512];		/* 过滤器串全量（超长截断，长度上限 512） */
};

struct ai_bpf_ftrace_payload {
	u8 type;			/* AI_BPF_FTRACE_FUNCTION */
	unsigned long ip;		/* 当前函数地址 */
	unsigned long parent_ip;	/* 调用方地址 */
};

struct ai_bpf_perf_open_payload {
	u8 type;			/* AI_BPF_PERF_EVENT_OPEN */
	u32 pid;
	s32 cpu;
	u32 attr_type;			/* attr.type（PERF_TYPE_*） */
	u64 config;			/* attr.config（事件 id） */
	u32 flags;			/* 用户 flags */
};

struct ai_bpf_pmu_payload {
	u8 type;			/* AI_BPF_PMU_SAMPLE */
	u32 event_id;			/* 1=inference 2=decision 3=telemetry_write */
	u64 nr;				/* 本次增量 */
	u64 latency_ns;			/* 推理耗时/决策延迟 */
	u64 total;			/* per-CPU 累计计数 */
};

struct ai_bpf_kprobe_register_payload {
	u8 type;			/* AI_BPF_KPROBE_REGISTER */
	unsigned long offset;
	unsigned long addr;		/* 解析后的插桩地址 */
	s32 result;			/* 0=成功 负=失败 errno */
	char symbol[128];		/* 符号名全量 */
};

struct ai_bpf_kprobe_hit_payload {
	u8 type;			/* AI_BPF_KPROBE_HIT */
	unsigned long addr;		/* kprobe 地址 */
	u64 hits;			/* per-CPU 累计命中 */
	char symbol[128];		/* 符号名（无则空串） */
};

struct ai_bpf_verifier_payload {
	u8 type;			/* AI_BPF_VERIFIER_DECISION */
	u32 prog_type;			/* enum bpf_prog_type */
	u32 insn_cnt;
	u32 subprog_cnt;
	s32 verdict;			/* 0=通过 负=拒绝 errno */
	u64 verification_ns;		/* 验证耗时 */
};

/* ---- 决策统计 ---- */

struct ai_bpf_stats {
	u64 trace_filter_hook_calls, trace_filter_hook_adjusted;
	u64 ftrace_hook_calls;
	u64 kprobe_hook_calls;
	u64 kprobe_hit_calls;
	u64 verifier_hook_calls;
	u64 query_calls, query_ok, query_fail;
	u64 telemetry_calls, telemetry_ok;
	u64 prog_run_counts;
	u64 emit_prog_load, emit_prog_run, emit_ai_query, emit_map_create,
	    emit_trace_open, emit_filter_change, emit_ftrace, emit_perf_open,
	    emit_pmu_sample, emit_kprobe_reg, emit_kprobe_hit,
	    emit_verifier_decision;
};

/* ---- AI PMU 事件常量（PERF_TYPE_AI=6 PMU 的 attr.config 取值） ---- */

#define AI_PMU_EVENT_MAX		4	/* 数组上界（1..3 有效） */
#define AI_PMU_EVENT_INFERENCE		1
#define AI_PMU_EVENT_DECISION		2
#define AI_PMU_EVENT_TELEMETRY_WRITE	3

#ifdef CONFIG_AIKERNEL_BPF

/* ==================================================================
 * A 轨：AI 观察 Hook（实现见 ai_bpf.c；空实现 = 原样放行）
 * ==================================================================
 */

/**
 * ai_bpf_trace_filter() - AI 辅助过滤 trace 事件，聚焦异常
 * @filter: 事件过滤器（opaque，调用点类型）
 * @match: 出参/入参；当前匹配结果（AI 可改写，空实现不改）
 *
 * 由 kernel/trace/trace_events_filter.c filter_match_preds() 返回前调用。
 * 注意：本 Hook 在事件过滤热路径上，实现必须零锁零分配零 printk。
 */
void ai_bpf_trace_filter(const void *filter, bool *match);

/**
 * ai_bpf_ftrace_hook() - AI 分析函数调用图，发现性能热点
 * @ip: 当前函数地址
 * @parent_ip: 调用方地址
 * @op: ftrace_ops（opaque，调用点类型）
 *
 * 由 kernel/trace/trace_functions.c function_trace_call() 入口调用。
 * 空实现无操作（+ ftrace_function 遥测 1/64 采样）。
 */
void ai_bpf_ftrace_hook(unsigned long ip, unsigned long parent_ip,
			const void *op);

/**
 * ai_bpf_kprobe_hook() - AI 建议关键函数的插桩位置
 * @symbol: 符号名
 * @offset: 符号内偏移
 * @addr: 解析后的地址
 *
 * 由 kernel/kprobes.c register_kprobe() 入口调用。空实现无操作。
 */
void ai_bpf_kprobe_hook(const char *symbol, unsigned long offset,
			unsigned long addr);

/**
 * ai_bpf_verifier_hook() - AI 辅助路径分析，减少误报
 * @prog_type: 程序类型（enum bpf_prog_type）
 * @insn_cnt: 指令数
 * @subprog_cnt: 子程序数
 * @verdict: 验证判定（0=通过 负=拒绝）
 * @verification_ns: 验证耗时
 *
 * 由 kernel/bpf/verifier.c bpf_check() 验证统计后调用。
 * 空实现不改 verdict（验证器判定权威性零影响）；verifier_decision 遥测全量。
 */
void ai_bpf_verifier_hook(u32 prog_type, u32 insn_cnt, u32 subprog_cnt,
			  int verdict, u64 verification_ns);

/* ==================================================================
 * A 轨：BPF 协同核心（实现见 ai_bpf.c；helper 包装见 kernel/bpf/helpers.c）
 * ==================================================================
 */

/**
 * ai_bpf_query() - BPF helper bpf_ai_query 的核心实现（BPF 程序调 AI 推理）
 * @model_id: 目标模型句柄（ai_model_load 回填的 id，1 起）
 * @input: 输入数据指针（BPF 程序内存，验证器已保证可读 input_len 字节）
 * @input_len: 输入长度（0~4096）
 * @output: 输出缓冲指针（验证器已保证可写 output_len 字节）
 * @output_len: 输出缓冲容量（0~4096）
 *
 * 上下文安全：原子/中断上下文返回 -EBUSY 不阻塞；进程上下文走
 * ai_runtime_chat() 同步推理。成功后发射 AI 自我观测遥测
 * （ai_telemetry_ai_query，全量）并计数 AI PMU ai_inference（含耗时）。
 * 返回：>=0 = 成功（写入 output 的实际字节数）；负 errno = 失败。
 */
long ai_bpf_query(u64 model_id, const void *input, u32 input_len,
		  void *output, u32 output_len);

/**
 * ai_bpf_telemetry() - BPF helper bpf_ai_telemetry 的核心实现（BPF 发遥测）
 * @category: 大类（1~17，对齐 enum ai_category）
 * @event_type: 子类（1~101，对齐 enum ai_event_type）
 * @data: 原始数据指针（验证器保证可读 len 字节；len=0 可 NULL）
 * @len: 数据长度（0~4096）
 *
 * 走全系统唯一写入入口 ai_telemetry_emit()（<100ns，无锁，满则丢弃）。
 * 成功后计数 AI PMU ai_telemetry_write。返回 0 或负 errno。
 */
long ai_bpf_telemetry(u32 category, u32 event_type, const void *data,
		      u32 len);

/**
 * ai_bpf_prog_run_count() - BPF 程序执行计数（B 轨 bpf_prog_run）
 * @prog_type: 程序类型（enum bpf_prog_type，标量）
 *
 * 由 include/linux/filter.h __bpf_prog_run() 每次执行调用（CONFIG_AIKERNEL_BPF）。
 * per-CPU 计数器 + 1/64 采样遥测。零锁零分配零 printk。
 */
void ai_bpf_prog_run_count(u32 prog_type);

/* ==================================================================
 * B 轨：第14类发射辅助（实现见 ai_bpf.c；全部 sample_take + emit_direct）
 * ==================================================================
 */

void ai_telemetry_bpf_prog_load(u32 prog_type, u32 insn_cnt, s32 result,
				const char *prog_name);
void ai_telemetry_bpf_prog_run(u32 prog_type);
void ai_telemetry_ai_query(u32 model_id, u32 input_len, u32 output_len,
			   s32 result, u64 latency_ns);
void ai_telemetry_ai_map_create(u32 map_type, u32 max_entries, u32 key_size,
				u32 value_size, u64 mem_bytes,
				const char *map_name);
void ai_telemetry_trace_event_open(u32 event_id, u32 mode,
				   const char *event_name);
void ai_telemetry_trace_filter_change(u32 event_id, s32 result,
				      const char *system,
				      const char *filter_str);
void ai_telemetry_ftrace_function(unsigned long ip, unsigned long parent_ip);
void ai_telemetry_perf_event_open(u32 pid, s32 cpu, u32 attr_type, u64 config,
				  u32 flags);
void ai_telemetry_perf_ai(u32 event_id, u64 nr, u64 latency_ns);
void ai_telemetry_kprobe_register(const char *symbol, unsigned long offset,
				  unsigned long addr, s32 result);
void ai_telemetry_kprobe_hit(unsigned long addr, const char *symbol);
void ai_telemetry_verifier_decision(u32 prog_type, u32 insn_cnt,
				    u32 subprog_cnt, int verdict,
				    u64 verification_ns);

/* ---- 决策框架 ---- */

void ai_bpf_stats_read(struct ai_bpf_stats *st);
bool ai_bpf_sample_take(u32 rate);

/* ---- 初始化（late_initcall：BPF 计数器与采样器注册） ---- */

int ai_bpf_init(void);

#else /* !CONFIG_AIKERNEL_BPF */

/* 空函数兜底：CONFIG_AIKERNEL_BPF=n 时 kernel/ 调用点不编译，
 * 此处兜底仅供 AIKernel/ 内部其他模块引用时保持可编译。 */
static inline void ai_bpf_trace_filter(const void *filter, bool *match)
{ }
static inline void ai_bpf_ftrace_hook(unsigned long ip, unsigned long parent_ip,
				      const void *op)
{ }
static inline void ai_bpf_kprobe_hook(const char *symbol,
				      unsigned long offset, unsigned long addr)
{ }
static inline void ai_bpf_verifier_hook(u32 prog_type, u32 insn_cnt,
					u32 subprog_cnt, int verdict,
					u64 verification_ns)
{ }
static inline long ai_bpf_query(u64 model_id, const void *input,
				u32 input_len, void *output, u32 output_len)
{ return -ENOSYS; }
static inline long ai_bpf_telemetry(u32 category, u32 event_type,
				    const void *data, u32 len)
{ return -ENOSYS; }
static inline void ai_bpf_prog_run_count(u32 prog_type)
{ }
static inline void ai_telemetry_bpf_prog_load(u32 prog_type, u32 insn_cnt,
					      s32 result, const char *prog_name)
{ }
static inline void ai_telemetry_bpf_prog_run(u32 prog_type)
{ }
static inline void ai_telemetry_ai_query(u32 model_id, u32 input_len,
					 u32 output_len, s32 result,
					 u64 latency_ns)
{ }
static inline void ai_telemetry_ai_map_create(u32 map_type, u32 max_entries,
					      u32 key_size, u32 value_size,
					      u64 mem_bytes,
					      const char *map_name)
{ }
static inline void ai_telemetry_trace_event_open(u32 event_id, u32 mode,
						 const char *event_name)
{ }
static inline void ai_telemetry_trace_filter_change(u32 event_id, s32 result,
						    const char *system,
						    const char *filter_str)
{ }
static inline void ai_telemetry_ftrace_function(unsigned long ip,
						unsigned long parent_ip)
{ }
static inline void ai_telemetry_perf_event_open(u32 pid, s32 cpu, u32 attr_type,
						u64 config, u32 flags)
{ }
static inline void ai_telemetry_perf_ai(u32 event_id, u64 nr, u64 latency_ns)
{ }
static inline void ai_telemetry_kprobe_register(const char *symbol,
						unsigned long offset,
						unsigned long addr, s32 result)
{ }
static inline void ai_telemetry_kprobe_hit(unsigned long addr,
					   const char *symbol)
{ }
static inline void ai_telemetry_verifier_decision(u32 prog_type, u32 insn_cnt,
						  u32 subprog_cnt, int verdict,
						  u64 verification_ns)
{ }
static inline void ai_bpf_stats_read(struct ai_bpf_stats *st)
{ if (st) memset(st, 0, sizeof(*st)); }
static inline bool ai_bpf_sample_take(u32 rate)
{ return false; }
static inline int ai_bpf_init(void)
{ return AI_OK; }

#endif /* CONFIG_AIKERNEL_BPF */

#endif /* _AIKERNEL_BPF_AI_BPF_H */
