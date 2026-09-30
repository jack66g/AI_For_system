// SPDX-License-Identifier: GPL-2.0
/*
 * ai_bpf.c - AIKernel BPF/Tracing/Perf 协同核心（Prompt 11，重构计划 模块13）
 *
 * A 轨：AI 观察 Hook（ai_bpf_trace_filter/ftrace/kprobe/verifier，
 *       空实现 = 原样放行，决策表待 AI 填充）+ BPF 协同核心
 *       （ai_bpf_query：BPF 调 AI 推理；ai_bpf_telemetry：BPF 发遥测；
 *       ai_bpf_prog_run_count：BPF 执行计数）。
 * B 轨：第14类 BPF/Tracing/Perf 感知（14.01~14.04）发射辅助，全部
 *       sample_take 采样判定 + 栈上 payload + emit_direct 直写。
 *
 * 热路径安全性：
 *   - __bpf_prog_run / function_trace_call / 过滤匹配 / kprobe 命中：
 *     仅 per-CPU inc + 分支（采样命中才构建 payload），零锁零分配零 printk；
 *   - per-CPU 计数器直接对符号操作（Prompt 09 早期启动崩溃先例）；
 *   - AI PMU 发射走 static_key 门控（无 perf 监听时单分支 ≈1ns）。
 *
 * 跨目录类型隔离：本文件只 include 公共内核头 + AIKernel 头，Hook 全标量/void*。
 * 上下文安全：ai_bpf_query 在原子/中断上下文返回 -EBUSY 绝不阻塞。
 */

#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/ktime.h>
#include <linux/preempt.h>
#include <linux/hardirq.h>
#include <linux/irqflags.h>
#include <linux/sched.h>

#include "ai_bpf.h"
#include "../core/ai_runtime.h"

#define AI_BPF_QUERY_MAX_LEN	4096   /* helper 输入/输出载荷上限（对齐遥测 4096） */

/* ---- 决策统计（per-CPU 近似，汇总读取） ---- */

static DEFINE_PER_CPU(struct ai_bpf_stats, ai_bpf_pcpu_stats);

/* ---- per-CPU 采样计数器（无锁） ---- */

struct ai_bpf_percpu {
	u32 prog_run_samples;		/* bpf_prog_run 采样计数器 */
	u32 ftrace_samples;		/* ftrace_function 采样计数器 */
	u32 kprobe_hit_samples;		/* kprobe_hit 采样计数器 */
	u32 generic_samples;		/* 通用采样计数器（全量事件占位） */
};

static DEFINE_PER_CPU(struct ai_bpf_percpu, ai_bpf_percpu);

bool ai_bpf_sample_take(u32 rate)
{
	u32 c = __this_cpu_inc_return(ai_bpf_percpu.generic_samples) - 1;

	return (rate <= 1) || ((c % rate) == 0);
}
EXPORT_SYMBOL_GPL(ai_bpf_sample_take);

static bool ai_bpf_prog_run_sample_take(void)
{
	u32 c = __this_cpu_inc_return(ai_bpf_percpu.prog_run_samples) - 1;

	return (c % 64) == 0;
}

static bool ai_bpf_ftrace_sample_take(void)
{
	u32 c = __this_cpu_inc_return(ai_bpf_percpu.ftrace_samples) - 1;

	return (c % 64) == 0;
}

static bool ai_bpf_kprobe_hit_sample_take(void)
{
	u32 c = __this_cpu_inc_return(ai_bpf_percpu.kprobe_hit_samples) - 1;

	return (c % 64) == 0;
}

void ai_bpf_stats_read(struct ai_bpf_stats *st)
{
	int cpu;

	if (!st)
		return;
	memset(st, 0, sizeof(*st));
	for_each_possible_cpu(cpu) {
		const struct ai_bpf_stats *p = per_cpu_ptr(&ai_bpf_pcpu_stats,
							   cpu);

		st->trace_filter_hook_calls += p->trace_filter_hook_calls;
		st->trace_filter_hook_adjusted += p->trace_filter_hook_adjusted;
		st->ftrace_hook_calls += p->ftrace_hook_calls;
		st->kprobe_hook_calls += p->kprobe_hook_calls;
		st->kprobe_hit_calls += p->kprobe_hit_calls;
		st->verifier_hook_calls += p->verifier_hook_calls;
		st->query_calls += p->query_calls;
		st->query_ok += p->query_ok;
		st->query_fail += p->query_fail;
		st->telemetry_calls += p->telemetry_calls;
		st->telemetry_ok += p->telemetry_ok;
		st->prog_run_counts += p->prog_run_counts;
		st->emit_prog_load += p->emit_prog_load;
		st->emit_prog_run += p->emit_prog_run;
		st->emit_ai_query += p->emit_ai_query;
		st->emit_map_create += p->emit_map_create;
		st->emit_trace_open += p->emit_trace_open;
		st->emit_filter_change += p->emit_filter_change;
		st->emit_ftrace += p->emit_ftrace;
		st->emit_perf_open += p->emit_perf_open;
		st->emit_pmu_sample += p->emit_pmu_sample;
		st->emit_kprobe_reg += p->emit_kprobe_reg;
		st->emit_kprobe_hit += p->emit_kprobe_hit;
		st->emit_verifier_decision += p->emit_verifier_decision;
	}
}
EXPORT_SYMBOL_GPL(ai_bpf_stats_read);

/* ==================================================================
 * A 轨：AI 观察 Hook（空实现 = 原样放行）
 * ==================================================================
 */

void ai_bpf_trace_filter(const void *filter, bool *match)
{
	this_cpu_inc(ai_bpf_pcpu_stats.trace_filter_hook_calls);
	/* AI 聚焦异常 trace 事件：可改 *match（空实现不改）；决策表就绪后评估 */
	if (match && !*match)
		this_cpu_inc(ai_bpf_pcpu_stats.trace_filter_hook_adjusted);
	ai_telemetry_perf_ai(AI_PMU_EVENT_DECISION, 1, 0);
}
EXPORT_SYMBOL_GPL(ai_bpf_trace_filter);

void ai_bpf_ftrace_hook(unsigned long ip, unsigned long parent_ip,
			const void *op)
{
	this_cpu_inc(ai_bpf_pcpu_stats.ftrace_hook_calls);
	/* AI 分析函数调用图发现性能热点：决策表就绪后在此评估 */
	ai_telemetry_perf_ai(AI_PMU_EVENT_DECISION, 1, 0);
}
EXPORT_SYMBOL_GPL(ai_bpf_ftrace_hook);

void ai_bpf_kprobe_hook(const char *symbol, unsigned long offset,
			unsigned long addr)
{
	this_cpu_inc(ai_bpf_pcpu_stats.kprobe_hook_calls);
	/* AI 建议关键函数的插桩位置：决策表就绪后在此评估 */
	ai_telemetry_perf_ai(AI_PMU_EVENT_DECISION, 1, 0);
}
EXPORT_SYMBOL_GPL(ai_bpf_kprobe_hook);

void ai_bpf_verifier_hook(u32 prog_type, u32 insn_cnt, u32 subprog_cnt,
			  int verdict, u64 verification_ns)
{
	this_cpu_inc(ai_bpf_pcpu_stats.verifier_hook_calls);
	/* AI 辅助路径分析减少误报：可影响后续重验（本步不改 verdict） */
	ai_telemetry_perf_ai(AI_PMU_EVENT_DECISION, 1, verification_ns);
	ai_telemetry_verifier_decision(prog_type, insn_cnt, subprog_cnt,
				       verdict, verification_ns);
}
EXPORT_SYMBOL_GPL(ai_bpf_verifier_hook);

/* ==================================================================
 * A 轨：BPF 协同核心
 * ==================================================================
 */

long ai_bpf_query(u64 model_id, const void *input, u32 input_len,
		  void *output, u32 output_len)
{
	struct ai_inference_request req;
	struct ai_inference_result res;
	u64 t0, latency;
	int rc;

	if (!input || !output || input_len > AI_BPF_QUERY_MAX_LEN ||
	    output_len == 0 || output_len > AI_BPF_QUERY_MAX_LEN ||
	    model_id == 0)
		return -EINVAL;
	/*
	 * 上下文安全：hardirq/softirq/NMI/BH 关闭或本地 IRQ 关闭时拒绝（-EBUSY，
	 * 绝不阻塞）。进程上下文（含 BPF 执行的标准 migrate_disable 环境）允许
	 * 同步推理——此时 mutex 路径可调度；严格 lockdep 内核的收紧由后续
	 * Prompt 在 ai_runtime 提供无锁注册表读取后实施（见设计文档 2.3 风险）。
	 */
	if (in_interrupt() || irqs_disabled())
		return -EBUSY;
	if (ai_runtime_get_state() != AI_RT_STATE_READY)
		return -EPERM;   /* AI_ERR_DISABLED */

	memset(&req, 0, sizeof(req));
	memset(&res, 0, sizeof(res));
	req.model_id = (u32)model_id;
	req.input = input;
	req.input_len = input_len;
	req.output = output;
	req.output_len = output_len;
	req.timeout_ns = 0;

	this_cpu_inc(ai_bpf_pcpu_stats.query_calls);
	t0 = ktime_get_ns();
	rc = ai_runtime_chat(&req, &res);
	latency = ktime_get_ns() - t0;

	if (rc == AI_OK)
		this_cpu_inc(ai_bpf_pcpu_stats.query_ok);
	else
		this_cpu_inc(ai_bpf_pcpu_stats.query_fail);

	ai_telemetry_perf_ai(AI_PMU_EVENT_INFERENCE, 1, latency);
	ai_telemetry_ai_query((u32)model_id, input_len, (u32)res.output_len,
			      rc, latency);

	return rc ? ai_error_to_errno(rc) : (long)res.output_len;
}
EXPORT_SYMBOL_GPL(ai_bpf_query);

long ai_bpf_telemetry(u32 category, u32 event_type, const void *data, u32 len)
{
	int rc;

	if (category < 1 || category > AI_CAT_KCONFIG)
		return -EINVAL;
	if (event_type < 1 || event_type >= AI_EV_MAX)
		return -EINVAL;
	if (len > AI_TELEMETRY_MAX_DATA_LEN || (len > 0 && !data))
		return -EINVAL;

	this_cpu_inc(ai_bpf_pcpu_stats.telemetry_calls);
	rc = ai_telemetry_emit((u8)category, (u8)event_type, AI_SEV_NORMAL,
			       data, (u16)len);
	if (rc == AI_OK)
		this_cpu_inc(ai_bpf_pcpu_stats.telemetry_ok);

	ai_telemetry_perf_ai(AI_PMU_EVENT_TELEMETRY_WRITE, 1, 0);
	return rc ? ai_error_to_errno(rc) : 0;
}
EXPORT_SYMBOL_GPL(ai_bpf_telemetry);

void ai_bpf_prog_run_count(u32 prog_type)
{
	this_cpu_inc(ai_bpf_pcpu_stats.prog_run_counts);
	if (!ai_bpf_prog_run_sample_take())
		return;
	ai_telemetry_bpf_prog_run(prog_type);
}
EXPORT_SYMBOL_GPL(ai_bpf_prog_run_count);

/* ==================================================================
 * B 轨：第14类 BPF/Tracing/Perf 感知发射辅助
 * ==================================================================
 */

void ai_telemetry_bpf_prog_load(u32 prog_type, u32 insn_cnt, s32 result,
				const char *prog_name)
{
	struct ai_bpf_prog_load_payload p;

	if (!ai_bpf_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_BPF_PROG_LOAD;
	p.prog_type = prog_type;
	p.insn_cnt = insn_cnt;
	p.result = result;
	strscpy(p.prog_name, prog_name ? prog_name : "none",
		sizeof(p.prog_name));
	this_cpu_inc(ai_bpf_pcpu_stats.emit_prog_load);
	ai_telemetry_emit_direct(AI_CAT_BPF, AI_EV_BPF_PROG, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_bpf_prog_load);

void ai_telemetry_bpf_prog_run(u32 prog_type)
{
	struct ai_bpf_prog_run_payload p;

	if (!ai_bpf_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_BPF_PROG_RUN;
	p.prog_type = prog_type;
	p.run_count = this_cpu_read(ai_bpf_pcpu_stats.prog_run_counts);
	this_cpu_inc(ai_bpf_pcpu_stats.emit_prog_run);
	ai_telemetry_emit_direct(AI_CAT_BPF, AI_EV_BPF_PROG, AI_SEV_DEBUG,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_bpf_prog_run);

void ai_telemetry_ai_query(u32 model_id, u32 input_len, u32 output_len,
			   s32 result, u64 latency_ns)
{
	struct ai_bpf_ai_query_payload p;

	if (!ai_bpf_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_BPF_AI_QUERY;
	p.model_id = model_id;
	p.input_len = input_len;
	p.output_len = output_len;
	p.result = result;
	p.latency_ns = latency_ns;
	p.calls = this_cpu_read(ai_bpf_pcpu_stats.query_calls);
	this_cpu_inc(ai_bpf_pcpu_stats.emit_ai_query);
	ai_telemetry_emit_direct(AI_CAT_BPF, AI_EV_BPF_PROG, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_ai_query);

void ai_telemetry_ai_map_create(u32 map_type, u32 max_entries, u32 key_size,
				u32 value_size, u64 mem_bytes,
				const char *map_name)
{
	struct ai_bpf_map_create_payload p;

	if (!ai_bpf_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_BPF_MAP_CREATE;
	p.map_type = map_type;
	p.max_entries = max_entries;
	p.key_size = key_size;
	p.value_size = value_size;
	p.mem_bytes = mem_bytes;
	strscpy(p.map_name, map_name ? map_name : "none", sizeof(p.map_name));
	this_cpu_inc(ai_bpf_pcpu_stats.emit_map_create);
	ai_telemetry_emit_direct(AI_CAT_BPF, AI_EV_BPF_MAP, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_ai_map_create);

void ai_telemetry_trace_event_open(u32 event_id, u32 mode,
				   const char *event_name)
{
	struct ai_bpf_trace_event_payload p;

	if (!ai_bpf_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_BPF_TRACE_EVENT_OPEN;
	p.event_id = event_id;
	p.mode = mode;
	strscpy(p.event_name, event_name ? event_name : "none",
		sizeof(p.event_name));
	this_cpu_inc(ai_bpf_pcpu_stats.emit_trace_open);
	ai_telemetry_emit_direct(AI_CAT_BPF, AI_EV_TRACING, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_trace_event_open);

void ai_telemetry_trace_filter_change(u32 event_id, s32 result,
				      const char *system,
				      const char *filter_str)
{
	struct ai_bpf_trace_filter_payload p;
	size_t n;

	if (!ai_bpf_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_BPF_TRACE_FILTER_CHANGE;
	p.event_id = event_id;
	p.result = result;
	strscpy(p.system, system ? system : "none", sizeof(p.system));
	n = strlen(filter_str ? filter_str : "");
	if (n > sizeof(p.filter) - 1)
		n = sizeof(p.filter) - 1;
	memcpy(p.filter, filter_str ? filter_str : "", n);
	p.filter[n] = '\0';
	this_cpu_inc(ai_bpf_pcpu_stats.emit_filter_change);
	ai_telemetry_emit_direct(AI_CAT_BPF, AI_EV_TRACING, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_trace_filter_change);

void ai_telemetry_ftrace_function(unsigned long ip, unsigned long parent_ip)
{
	struct ai_bpf_ftrace_payload p;

	if (!ai_bpf_ftrace_sample_take())
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_BPF_FTRACE_FUNCTION;
	p.ip = ip;
	p.parent_ip = parent_ip;
	this_cpu_inc(ai_bpf_pcpu_stats.emit_ftrace);
	ai_telemetry_emit_direct(AI_CAT_BPF, AI_EV_TRACING, AI_SEV_DEBUG,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_ftrace_function);

void ai_telemetry_perf_event_open(u32 pid, s32 cpu, u32 attr_type, u64 config,
				  u32 flags)
{
	struct ai_bpf_perf_open_payload p;

	if (!ai_bpf_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_BPF_PERF_EVENT_OPEN;
	p.pid = pid;
	p.cpu = cpu;
	p.attr_type = attr_type;
	p.config = config;
	p.flags = flags;
	this_cpu_inc(ai_bpf_pcpu_stats.emit_perf_open);
	ai_telemetry_emit_direct(AI_CAT_BPF, AI_EV_PERF, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_perf_event_open);

void ai_telemetry_kprobe_register(const char *symbol, unsigned long offset,
				  unsigned long addr, s32 result)
{
	struct ai_bpf_kprobe_register_payload p;

	if (!ai_bpf_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_BPF_KPROBE_REGISTER;
	p.offset = offset;
	p.addr = addr;
	p.result = result;
	strscpy(p.symbol, symbol ? symbol : "none", sizeof(p.symbol));
	this_cpu_inc(ai_bpf_pcpu_stats.emit_kprobe_reg);
	ai_telemetry_emit_direct(AI_CAT_BPF, AI_EV_TRACING, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_kprobe_register);

void ai_telemetry_kprobe_hit(unsigned long addr, const char *symbol)
{
	struct ai_bpf_kprobe_hit_payload p;

	this_cpu_inc(ai_bpf_pcpu_stats.kprobe_hit_calls);
	if (!ai_bpf_kprobe_hit_sample_take())
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_BPF_KPROBE_HIT;
	p.addr = addr;
	p.hits = this_cpu_read(ai_bpf_pcpu_stats.kprobe_hit_calls);
	strscpy(p.symbol, symbol ? symbol : "", sizeof(p.symbol));
	this_cpu_inc(ai_bpf_pcpu_stats.emit_kprobe_hit);
	ai_telemetry_emit_direct(AI_CAT_BPF, AI_EV_TRACING, AI_SEV_DEBUG,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_kprobe_hit);

void ai_telemetry_verifier_decision(u32 prog_type, u32 insn_cnt,
				    u32 subprog_cnt, int verdict,
				    u64 verification_ns)
{
	struct ai_bpf_verifier_payload p;

	if (!ai_bpf_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_BPF_VERIFIER_DECISION;
	p.prog_type = prog_type;
	p.insn_cnt = insn_cnt;
	p.subprog_cnt = subprog_cnt;
	p.verdict = verdict;
	p.verification_ns = verification_ns;
	this_cpu_inc(ai_bpf_pcpu_stats.emit_verifier_decision);
	ai_telemetry_emit_direct(AI_CAT_BPF, AI_EV_BPF_PROG,
				 AI_SEV_IMPORTANT, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_verifier_decision);

/* ==================================================================
 * 初始化
 * ==================================================================
 */

int __init ai_bpf_init(void)
{
	pr_info("AIKernel: BPF/Tracing/Perf 协同核心就绪（AI PMU: ai/*）\n");
	return AI_OK;
}
late_initcall(ai_bpf_init);
