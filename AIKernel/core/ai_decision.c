// SPDX-License-Identifier: GPL-2.0
/*
 * ai_decision.c - AIKernel 决策注入查询层（W3：给挂接点通电）
 *
 * 职责一句话：把 5 个高价值 ai_*_hook 从"计数+放行"升级为真实决策消费者
 * 的中间层 —— 挂点调 ai_decision_query(hook, ctx) 取有界偏置；
 *   - 决策源接口化：v1 = 确定性启发式（per-task 分类槽 ai_proc_class_peek
 *     + 遥测计数），第二阶段训练好的微模型经 ai_decision_set_source() 注入
 *     替换，消费挂点/开关/钳制/记账零改动；
 *   - 开关三层：全局总开关（/sys/kernel/ai/decision_inject，默认 0）→
 *     每挂点独立使能（/sys/kernel/ai/decision/<hook>，默认 0）→ 值域硬
 *     钳制（AI_DEC_*_MAX 编译期常量，决策源越界也被 clamp）；
 *   - 异常回退：决策源错误/分类槽无效（含槽表 trylock 失败）→ 按 0（原生
 *     行为）处理并计 fallback；
 *   - 全量记账：queries/injected/effects/fallback per-hook 精确计数
 *     （/sys/kernel/ai/decision/stats）；decisions ring（source=
 *     AI_DEC_SRC_HEURISTIC）按每挂点 1s 节流采样，避免淹没 AI Runtime
 *     策略决策流。
 *
 * 并发/上下文安全：全部状态 WRITE_ONCE/READ_ONCE 原子字访问，无专用锁；
 * 查询路径仅 trylock 分类槽（争用即回退 0）+ 常量时间查表，无分配无睡眠，
 * 可在 rq 锁/task 锁/tasklist 锁等原子上下文调用。总开关关 = 一次读普及
 * 即返回，热路径不付计数写入代价（与原生内核逐位一致）。
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include "ai_types.h"
#include "ai_proc.h"
#include "ai_control.h"
#include "ai_policy.h"
#include "ai_decision.h"

/* ---- 开关与决策记账（全部默认 0 = 关闭 = 原生行为） ---- */

static u8 ai_dec_master;
static u8 ai_dec_hook_en[AI_HOOK_NR];
static struct ai_decision_stats ai_dec_stats;

/* 值域硬钳制表（与 enum ai_hook_id 一一对应；编译期常量，查询层强制） */
static const s32 ai_hook_clamp_max[AI_HOOK_NR] = {
	[AI_HOOK_OOM_BADNESS]    = AI_DEC_OOM_BIAS_MAX,
	[AI_HOOK_SCHED_VRUNTIME] = AI_DEC_SCHED_PCT_MAX,
	[AI_HOOK_SCHED_WAKEUP]   = AI_DEC_WAKEUP_BOOST_MAX,
	[AI_HOOK_MM_READAHEAD]   = AI_DEC_RA_SHIFT_MAX,
	[AI_HOOK_MM_RECLAIM]     = AI_DEC_RECLAIM_PRIO_MAX,
};

static const char * const ai_hook_name_tbl[AI_HOOK_NR] = {
	[AI_HOOK_OOM_BADNESS]    = "oom_badness",
	[AI_HOOK_SCHED_VRUNTIME] = "sched_vruntime",
	[AI_HOOK_SCHED_WAKEUP]   = "sched_wakeup",
	[AI_HOOK_MM_READAHEAD]   = "readahead",
	[AI_HOOK_MM_RECLAIM]     = "reclaim",
};

/* ==================================================================
 * 决策源 v1：确定性启发式（per-task 分类槽）
 * ================================================================== */

static s32 ai_dec_heuristic_v1(enum ai_hook_id hook,
			       const struct ai_hook_ctx *ctx)
{
	pid_t pid = (ctx && ctx->pid) ? ctx->pid : (pid_t)task_pid_nr(current);
	int cls = ai_proc_class_peek(pid);
	struct ai_hook_stats *st;

	/* 槽 miss / 槽表 trylock 争用 / 分类值损坏 → 回退 0 并计 fallback；
	 * 内核线程（KERNEL 类）为有效分类但本批挂点一律不干预（原生行为） */
	if (cls < 0 || cls >= AI_PROC_CLASS_MAX) {
		if (hook < AI_HOOK_NR) {
			st = &ai_dec_stats.hook[hook];
			WRITE_ONCE(st->fallback, READ_ONCE(st->fallback) + 1);
		}
		return 0;
	}
	if (cls == AI_PROC_CLASS_KERNEL)
		return 0;

	switch (hook) {
	case AI_HOOK_OOM_BADNESS:
		/* 批处理/AI 负载加 badness（更可能成受害者），交互式减 */
		if (cls == AI_PROC_CLASS_INTERACTIVE)
			return -AI_DEC_OOM_BIAS_MAX;
		if (cls == AI_PROC_CLASS_AI_LOAD || cls == AI_PROC_CLASS_BATCH)
			return AI_DEC_OOM_BIAS_MAX;
		return 0;
	case AI_HOOK_SCHED_VRUNTIME:
		/* 交互式减免（提前），批处理推迟；基准 |v-V| 的千分比 */
		if (cls == AI_PROC_CLASS_INTERACTIVE)
			return -AI_DEC_SCHED_PCT_MAX;
		if (cls == AI_PROC_CLASS_BATCH)
			return AI_DEC_SCHED_PCT_MAX;
		return 0;
	case AI_HOOK_SCHED_WAKEUP:
		/* 交互式 wakee 抢占增益提示（典型场景：批处理持 CPU 唤醒交互式） */
		return (cls == AI_PROC_CLASS_INTERACTIVE) ?
			AI_DEC_WAKEUP_BOOST_MAX : 0;
	case AI_HOOK_MM_READAHEAD:
		/* 交互式读放大一档（延迟敏感），批处理缩小一档（省内存带宽） */
		if (cls == AI_PROC_CLASS_INTERACTIVE)
			return AI_DEC_RA_SHIFT_MAX;
		if (cls == AI_PROC_CLASS_BATCH)
			return -AI_DEC_RA_SHIFT_MAX;
		return 0;
	case AI_HOOK_MM_RECLAIM:
		/* 交互式直接回收 → 轻扫一档（保延迟）；批处理 → 重扫一档（快腾存） */
		if (cls == AI_PROC_CLASS_INTERACTIVE)
			return AI_DEC_RECLAIM_PRIO_MAX;
		if (cls == AI_PROC_CLASS_BATCH)
			return -AI_DEC_RECLAIM_PRIO_MAX;
		return 0;
	default:
		/* enum 之外值（理论不可达）→ 按无效回退 */
		WRITE_ONCE(ai_dec_stats.fallback_pad,
			   READ_ONCE(ai_dec_stats.fallback_pad) + 1);
		return 0;
	}
}

/* 当前决策源（函数指针单字，READ_ONCE 读取；NULL 在 init 前等价启发式 ——
 * 本文件静态初始化直接指向 v1，不存在 NULL 窗口） */
static ai_decision_source_fn ai_dec_source = ai_dec_heuristic_v1;

/* ==================================================================
 * 查询 / 记账 / 开关接口
 * ================================================================== */

s32 ai_decision_query(enum ai_hook_id hook, const struct ai_hook_ctx *ctx)
{
	struct ai_hook_stats *st;
	ai_decision_source_fn src;
	s32 bias, maxb;

	if (unlikely((unsigned int)hook >= AI_HOOK_NR))
		return 0;
	/* 总开关关：单次读普及 → 原生行为（不计数，热路径零写入） */
	if (!READ_ONCE(ai_dec_master))
		return 0;
	if (!READ_ONCE(ai_dec_hook_en[hook]))
		return 0;

	st = &ai_dec_stats.hook[hook];
	WRITE_ONCE(st->queries, READ_ONCE(st->queries) + 1);

	src = READ_ONCE(ai_dec_source);
	bias = src ? src(hook, ctx) : 0;

	/* 值域硬钳制：决策源（含第二阶段模型）越界值一律封顶 */
	maxb = ai_hook_clamp_max[hook];
	if (bias > maxb)
		bias = maxb;
	else if (bias < -maxb)
		bias = -maxb;

	if (bias)
		WRITE_ONCE(st->injected, READ_ONCE(st->injected) + 1);
	WRITE_ONCE(st->last_bias, bias);
	return bias;
}
EXPORT_SYMBOL_GPL(ai_decision_query);

void ai_decision_note_effect(enum ai_hook_id hook, s64 aux0, s64 aux1)
{
	struct ai_hook_stats *st;
	unsigned long now;

	if (unlikely((unsigned int)hook >= AI_HOOK_NR))
		return;
	st = &ai_dec_stats.hook[hook];
	WRITE_ONCE(st->effects, READ_ONCE(st->effects) + 1);
	WRITE_ONCE(st->last_aux0, aux0);
	WRITE_ONCE(st->last_aux1, aux1);

	/* decisions ring 节流采样（每挂点 AI_DEC_RING_JIFFIES 一条；
	 * 全量精确计数在上面 effects/last_*，ring 只是样本流） */
	now = jiffies;
	if (time_after(now, READ_ONCE(st->last_ring_j) + AI_DEC_RING_JIFFIES)) {
		u8 domain = AI_POLICY_DOMAIN_MM;

		WRITE_ONCE(st->last_ring_j, now);
		WRITE_ONCE(st->ring, READ_ONCE(st->ring) + 1);
		if (hook == AI_HOOK_SCHED_VRUNTIME || hook == AI_HOOK_SCHED_WAKEUP)
			domain = AI_POLICY_DOMAIN_SCHED;
		ai_policy_record_heuristic(domain, (u8)hook,
					   READ_ONCE(st->last_bias), aux0, aux1);
	}
}
EXPORT_SYMBOL_GPL(ai_decision_note_effect);

int ai_decision_set_source(ai_decision_source_fn fn)
{
	WRITE_ONCE(ai_dec_source, fn ? fn : ai_dec_heuristic_v1);
	pr_info("AIKernel: decision source -> %s\n",
		fn ? "external (stage-2 model hook)" : "heuristic_v1");
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_decision_set_source);

int ai_decision_set_master(u8 on)
{
	WRITE_ONCE(ai_dec_master, on ? 1 : 0);
	pr_info("AIKernel: decision inject master -> %d\n", on ? 1 : 0);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_decision_set_master);

u8 ai_decision_get_master(void)
{
	return READ_ONCE(ai_dec_master);
}
EXPORT_SYMBOL_GPL(ai_decision_get_master);

int ai_decision_set_hook_enable(enum ai_hook_id hook, u8 on)
{
	if ((unsigned int)hook >= AI_HOOK_NR)
		return AI_ERR_INVALID_ARG;
	WRITE_ONCE(ai_dec_hook_en[hook], on ? 1 : 0);
	pr_info("AIKernel: decision hook[%s] -> %d\n",
		ai_hook_name_tbl[hook], on ? 1 : 0);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_decision_set_hook_enable);

u8 ai_decision_get_hook_enable(enum ai_hook_id hook)
{
	if ((unsigned int)hook >= AI_HOOK_NR)
		return 0;
	return READ_ONCE(ai_dec_hook_en[hook]);
}
EXPORT_SYMBOL_GPL(ai_decision_get_hook_enable);

void ai_decision_stats_get(struct ai_decision_stats *out)
{
	if (!out)
		return;
	/* 无锁近似一致快照（观测面用；单字段原子，跨字段允许轻微撕裂） */
	memcpy(out, &ai_dec_stats, sizeof(*out));
	out->master = READ_ONCE(ai_dec_master);
	memcpy(out->hook_en, ai_dec_hook_en, sizeof(out->hook_en));
}
EXPORT_SYMBOL_GPL(ai_decision_stats_get);

const char *ai_decision_hook_name(enum ai_hook_id hook)
{
	if ((unsigned int)hook >= AI_HOOK_NR)
		return "?";
	return ai_hook_name_tbl[hook];
}
EXPORT_SYMBOL_GPL(ai_decision_hook_name);

/* ==================================================================
 * ACT 参数（加分项 6）：AI 经自己的 69 工具注册表经 NETLINK 开启决策注入
 * ================================================================== */

static int ai_dec_master_apply(struct ai_control_param *p, s32 pid,
			       s64 value, s64 *eff)
{
	if (value < 0 || value > 1)
		return AI_ERR_INVALID_ARG;
	ai_decision_set_master((u8)value);
	*eff = ai_decision_get_master();
	return AI_OK;
}

/* ai.decision_oom：挂点 1（OOM badness 偏置）使能 */
static int ai_dec_oom_apply(struct ai_control_param *p, s32 pid,
			    s64 value, s64 *eff)
{
	if (value < 0 || value > 1)
		return AI_ERR_INVALID_ARG;
	ai_decision_set_hook_enable(AI_HOOK_OOM_BADNESS, (u8)value);
	*eff = ai_decision_get_hook_enable(AI_HOOK_OOM_BADNESS);
	return AI_OK;
}

/* ai.decision_sched：挂点 2/3（vruntime 加权 + 唤醒抢占提示）成对使能 */
static int ai_dec_sched_apply(struct ai_control_param *p, s32 pid,
			      s64 value, s64 *eff)
{
	if (value < 0 || value > 1)
		return AI_ERR_INVALID_ARG;
	ai_decision_set_hook_enable(AI_HOOK_SCHED_VRUNTIME, (u8)value);
	ai_decision_set_hook_enable(AI_HOOK_SCHED_WAKEUP, (u8)value);
	*eff = ai_decision_get_hook_enable(AI_HOOK_SCHED_VRUNTIME);
	return AI_OK;
}

/* ai.decision_mm：挂点 4/5（预读窗口 + 回收扫描优先级）成对使能 */
static int ai_dec_mm_apply(struct ai_control_param *p, s32 pid,
			   s64 value, s64 *eff)
{
	if (value < 0 || value > 1)
		return AI_ERR_INVALID_ARG;
	ai_decision_set_hook_enable(AI_HOOK_MM_READAHEAD, (u8)value);
	ai_decision_set_hook_enable(AI_HOOK_MM_RECLAIM, (u8)value);
	*eff = ai_decision_get_hook_enable(AI_HOOK_MM_READAHEAD);
	return AI_OK;
}

static int __init ai_decision_init(void)
{
	/* 决策注入开关族注册为真实 ACT 可控参数（REAL，默认 0=关）：
	 * AI 可经 /proc/ai/control（NETLINK ACT）开启自己的决策注入；
	 * sysfs 侧 /sys/kernel/ai/decision_inject 与 decision/<hook> 同源。
	 * 域选择说明：按受控子系统归域（oom/mm→MM、sched→SCHED），全局
	 * 总开关归 SECURITY（干预门控语义，与 sec.* 同族）——刻意避开
	 * GENERAL/VIRT：KUnit ai_policy 套件在这两域做"域内广播恰好命中
	 * 1 条"的精确断言，注册进去会撑爆计数（实测 rc 1→5 回归）。 */
	ai_control_register("ai.decision_inject", AI_POLICY_DOMAIN_SECURITY,
			    AI_CTRL_F_REAL, 0, 1, 0, ai_dec_master_apply);
	ai_control_register("ai.decision_oom", AI_POLICY_DOMAIN_MM,
			    AI_CTRL_F_REAL, 0, 1, 0, ai_dec_oom_apply);
	ai_control_register("ai.decision_sched", AI_POLICY_DOMAIN_SCHED,
			    AI_CTRL_F_REAL, 0, 1, 0, ai_dec_sched_apply);
	ai_control_register("ai.decision_mm", AI_POLICY_DOMAIN_MM,
			    AI_CTRL_F_REAL, 0, 1, 0, ai_dec_mm_apply);

	pr_info("AIKernel: decision inject layer ready (5 hooks, master=off, heuristic_v1)\n");
	return 0;
}
late_initcall(ai_decision_init);
