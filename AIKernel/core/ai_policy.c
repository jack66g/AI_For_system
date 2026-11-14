// SPDX-License-Identifier: GPL-2.0
/*
 * ai_policy.c - AIKernel 决策策略引擎（Prompt 13 强化）
 *
 * 注册表：静态数组（最多 AI_POLICY_MAX_COUNT 个动作），
 * ai_policy_register(domain, action, callback, rollback, priv) 注册；
 * ai_policy_execute() 按决策域匹配、按优先级降序执行已启用动作：
 *   - 首行安全边界闸门（global_enable=0 → AI_ERR_DISABLED 单分支）；
 *   - 分配 decision_id（全局单调）；逐动作收集结果（失败 → 调该动作 rollback
 *     回退内核默认行为）；outcome 聚合（全成=1 部分=2 全败=3 无匹配=0）；
 *   - 决策记录（struct ai_decision_record，数据计划 23.2+因果链扩展）写入
 *     4096 条 ring（spinlock 保护，满覆盖最旧）+ AI_DECISION 遥测（cat18）
 *     + attempts/hits/latency 统计（/proc/ai/latency、hitrate 数据源）。
 * 闭环：ai_policy_outcome_update() 回填 outcome/outcome_ts/metric_delta →
 * AI_OUTCOME 遥测 → 完整因果链记录推入 ai_causal（数据计划 20.1 五步）。
 * 回退：ai_policy_rollback_decision/all → 安全层快照恢复（ai_control 参数表）。
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/sort.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/random.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/hrtimer.h>
#include <linux/workqueue.h>
#include <linux/sched/stat.h>	/* nr_threads（D6 radius） */
#include <linux/types.h>
#include "ai_policy.h"
#include "../actuators/ai_policy_safety.h"
#include "../actuators/ai_control.h"
#include "../actuators/ai_agent.h"
#include "ai_telemetry.h"
#include "ai_causal.h"
#include "ai_effect.h"
#include "../senses/ai_netlink.h"
#include "../boundary/ai_chain.h"

/* K1 D3/D8：决策记录尾部扩 8 字段，127→183B packed（drift 即编译
 * 失败；字段与 struct ai_policy_ctx 尾部一一对应，注释锚见 .h） */
_Static_assert(sizeof(struct ai_decision_record) == 183,
	       "ai_decision_record 必须为 183B（K1 D3）");

#define AI_POLICY_MAX_COUNT  64   /* 注册表容量 */

static struct ai_policy *ai_policy_table[AI_POLICY_MAX_COUNT];
static unsigned int ai_policy_count;
static DEFINE_MUTEX(ai_policy_lock);

/* K2a（KERNEL-K2-DESIGN D5/D6）：自动回滚单槽 + blast 阈值（状态定义
 * 在前——ai_policy_trace_init 引用；机制函数见 execute_trace 之后的
 * ACT_BATCH 一节） */
/* K2 勘误（K2c 真机实证）：64 在常态机（nr_threads>100）即拦所有
 * 全局参数单发——默认抬到 1024（sysfs 可调 0=off）。 */
static u32 ai_batch_blast_threshold = 1024;	/* sysfs 0644，0=关 */
static struct hrtimer ai_batch_ar_timer;
static struct work_struct ai_batch_ar_work;
static struct {
	u64 decision_id;	/* pending 待回滚决策 */
	u64 trace_hi;		/* 事件推送用 trace（从决策记录铸链取） */
	u64 trace_lo;
	bool armed;		/* v1 单槽：同刻仅一个 pending 自动回滚 */
} ai_batch_ar;

static void ai_batch_ar_work_fn(struct work_struct *work);

static atomic64_t ai_decision_seq = ATOMIC64_INIT(0);

/* K1 D2：统一 trace per-boot 随机 cookie——init 一次 get_random_u64()
 * （非零保证），跨 boot 由 hi 区分；lo=decision_id 同 boot 单调。 */
u64 ai_trace_boot_cookie;

/* K2 D5：自动回滚定时器回调（定义见 ai_batch_ar_work 段） */
static enum hrtimer_restart ai_batch_ar_timer_fn(struct hrtimer *timer);

static int __init ai_policy_trace_init(void)
{
	do {
		ai_trace_boot_cookie = get_random_u64();
	} while (!ai_trace_boot_cookie);   /* 退化 0（2^-64）重摇 */
	/* K2a D5：自动回滚定时器 + work 跳板初始化（单槽） */
	/* K2 勘误（主会话构建门抓获）：6.18 树 hrtimer_init 已移除
	 * （6.15+ 改名），换 hrtimer_setup。 */
	hrtimer_setup(&ai_batch_ar_timer, ai_batch_ar_timer_fn,
		      CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	INIT_WORK(&ai_batch_ar_work, ai_batch_ar_work_fn);
	return 0;
}
subsys_initcall(ai_policy_trace_init);

/* K1 D2：trace 铸造——hi/lo 任一非零 = 显式携带（ACT2），不改写；
 * 双零（v1 ACT/think/heuristic 零进）→ 铸 {hi: boot cookie,
 * lo: decision_id}，全决策恒非零（lo 单调 ≥1）。 */
static void ai_trace_mint(u64 decision_id, u64 *hi, u64 *lo)
{
	if (!*hi && !*lo) {
		*hi = ai_trace_boot_cookie;
		*lo = decision_id;
	}
}

/* ---- 决策记录 ring + ID 定位缓存 ---- */

static struct ai_decision_record ai_dec_ring[AI_POLICY_DECISION_RING_SIZE]
					____cacheline_aligned_in_smp;
static unsigned int ai_dec_head;   /* 下一个写入位置 */
static u64 ai_dec_total;           /* 累计写入条数 */
static struct ai_policy_stats ai_pstat;
static DEFINE_SPINLOCK(ai_dec_lock);

#define AI_DEC_MASK  (AI_POLICY_DECISION_RING_SIZE - 1)

/* 最近决策 ID → ring 位置缓存（outcome_update 快速定位，未命中线性扫） */
#define AI_DEC_ID_CACHE_SIZE  64

struct ai_dec_id_cache_entry {
	u64 decision_id;
	unsigned int ring_index;
};

static struct ai_dec_id_cache_entry ai_dec_id_cache[AI_DEC_ID_CACHE_SIZE]
					____cacheline_aligned_in_smp;
static unsigned int ai_dec_id_cache_pos;

u64 ai_policy_next_decision_id(void)
{
	return (u64)atomic64_inc_return(&ai_decision_seq);
}
EXPORT_SYMBOL_GPL(ai_policy_next_decision_id);

int ai_policy_register(enum ai_policy_domain domain, const char *action,
		       ai_policy_handler_t callback,
		       ai_policy_rollback_t rollback, void *priv)
{
	struct ai_policy *pol;
	unsigned int i;
	int rc;

	if (!action || !action[0] || !callback)
		return AI_ERR_INVALID_ARG;
	if (strlen(action) >= AI_MAX_NAME_LEN)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_policy_lock);

	if (ai_policy_count >= AI_POLICY_MAX_COUNT) {
		mutex_unlock(&ai_policy_lock);
		return AI_ERR_BUSY;
	}
	for (i = 0; i < ai_policy_count; i++) {
		if (strcmp(ai_policy_table[i]->name, action) == 0) {
			mutex_unlock(&ai_policy_lock);
			return AI_ERR_INVALID_ARG;   /* 动作名重复 */
		}
	}

	pol = kzalloc(sizeof(*pol), GFP_KERNEL);
	if (!pol) {
		mutex_unlock(&ai_policy_lock);
		return AI_ERR_MEMORY;
	}
	strscpy(pol->name, action, sizeof(pol->name));
	pol->domain = domain;
	pol->priority = 100;      /* 默认优先级（子模块可自行调整） */
	pol->enabled = 1;         /* 注册即启用 */
	pol->handler = callback;
	pol->rollback = rollback;
	pol->private_data = priv;

	ai_policy_table[ai_policy_count++] = pol;
	rc = AI_OK;

	mutex_unlock(&ai_policy_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_policy_register);

int ai_policy_unregister(const char *action)
{
	unsigned int i;
	int rc = AI_ERR_NOT_FOUND;

	if (!action)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_policy_lock);
	for (i = 0; i < ai_policy_count; i++) {
		if (strcmp(ai_policy_table[i]->name, action) == 0)
			break;
	}
	if (i < ai_policy_count) {
		kfree(ai_policy_table[i]);
		memmove(&ai_policy_table[i], &ai_policy_table[i + 1],
			(ai_policy_count - i - 1) * sizeof(struct ai_policy *));
		ai_policy_count--;
		rc = AI_OK;
	}
	mutex_unlock(&ai_policy_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_policy_unregister);

/* 按优先级降序排序（qsort 比较器） */
static int ai_policy_cmp(const void *a, const void *b)
{
	const struct ai_policy *pa = *(const struct ai_policy * const *)a;
	const struct ai_policy *pb = *(const struct ai_policy * const *)b;

	return (pb->priority > pa->priority) - (pb->priority < pa->priority);
}

/* 决策记录写入 ring + 统计累计（同一临界区；调用方不得持 ai_policy_lock 之外锁）。
 * K1 D5：cost_ns 统一在本函数算定（唯一落笔点，execute/heuristic
 * 两入口共用）：executed>0 ? exec_ts-trig_ts : dec_ts-trig_ts；
 * 时间戳异常（时钟同拍/乱序）退 0，防御恒非负。 */
static void ai_policy_record_write(struct ai_decision_record *rec, u64 lat)
{
	unsigned long flags;
	unsigned int slot;

	if (rec->executed > 0 && rec->execute_ts > rec->trigger_ts)
		rec->cost_ns = rec->execute_ts - rec->trigger_ts;
	else if (rec->decision_ts > rec->trigger_ts)
		rec->cost_ns = rec->decision_ts - rec->trigger_ts;
	else
		rec->cost_ns = 0;
	spin_lock_irqsave(&ai_dec_lock, flags);
	slot = ai_dec_head & AI_DEC_MASK;
	ai_dec_ring[slot] = *rec;
	ai_dec_head++;
	ai_dec_total++;
	ai_pstat.decisions_total++;
	ai_dec_id_cache[ai_dec_id_cache_pos & (AI_DEC_ID_CACHE_SIZE - 1)] =
		(struct ai_dec_id_cache_entry) {
			.decision_id = rec->decision_id,
			.ring_index = slot,
		};
	ai_dec_id_cache_pos++;
	ai_pstat.attempts++;
	if (rec->executed > 0)
		ai_pstat.hits++;
	ai_pstat.latency_sum += lat;
	if (ai_pstat.latency_min == 0 || lat < ai_pstat.latency_min)
		ai_pstat.latency_min = lat;
	if (lat > ai_pstat.latency_max)
		ai_pstat.latency_max = lat;
	spin_unlock_irqrestore(&ai_dec_lock, flags);

	/* K8：决策入环即铸链（fire-and-forget，链永不阻断业务路径） */
	{
		struct ai_chain_ev_decision_new ev = {
			.decision_id = rec->decision_id,
			.trigger_event_id = rec->trigger_event_id,
			.decision_type = rec->decision_type,
			.domain = rec->domain,
			.source = rec->source,
		};

		ai_chain_append(AI_CHAIN_KIND_DECISION_NEW, &ev, sizeof(ev));
	}
}

/*
 * 启发式决策注入记账（W3）：ai_decision.c 的节流采样入口。与 execute
 * 路径共用 ring 与统计（source=AI_DEC_SRC_HEURISTIC 可在 /proc/ai/
 * decisions 区分），decision_id 与既有计数器同源单调。
 */
int ai_policy_record_heuristic(u8 domain, u8 hook_id,
			       s64 bias, s64 aux0, s64 aux1)
{
	struct ai_decision_record rec = { 0 };
	u64 now = ktime_get_ns();

	rec.trigger_ts = now;
	/* trigger_event_id 高 16 位伪事件族标记 + 低 8 位挂点 ID */
	rec.trigger_event_id = (0xA1DEu << 16) | hook_id;
	rec.decision_ts = now;
	rec.execute_ts = now;
	rec.decision_type = 2;   /* 2 = 注入型决策（启发式偏置） */
	rec.decision_data[0] = hook_id;
	rec.decision_data[1] = (u64)bias;
	rec.decision_data[2] = (u64)aux0;
	rec.decision_data[3] = (u64)aux1;
	rec.model_version = 0;   /* 非模型：内置确定性启发式 */
	rec.confidence = 100;    /* 确定性规则无置信度概念，记满 */
	rec.decision_id = (u64)atomic64_inc_return(&ai_decision_seq);
	rec.domain = domain;
	rec.source = AI_DEC_SRC_HEURISTIC;
	rec.executed = 1;
	/* K1 D2：heuristic 入口同理铸 trace（零进零铸，id 已取号） */
	ai_trace_mint(rec.decision_id, &rec.trace_hi, &rec.trace_lo);
	/* K4.0 效果归因环：铸完 id 即绑定该挂点最近 pending 效果窗
	 * （note_effect 在采样前已开窗）；窗口结算时按 id 回填本记录
	 * 的 outcome/outcome_ts/metric_delta。id 截 u32 与效果窗字段
	 * 同宽（计数器 64 位、实际远不到回绕） */
	ai_effect_bind((enum ai_hook_id)hook_id, (u32)rec.decision_id);
	ai_policy_record_write(&rec, 0);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_policy_record_heuristic);

/*
 * 定向匹配（v2）：param 为空 → 匹配域内全部已启用动作（v1 广播语义不变）；
 * 非空 → 动作名全等，或动作名末段（最后一个 '.' 之后）与之相等
 * （允许客户端只传短名，如 "swappiness" 命中 "mm.swappiness"；
 * 同域内动作名唯一，末段匹配无歧义）。
 */
static bool ai_policy_param_match(const char *action, const char *param)
{
	const char *last_dot;

	if (!param[0])
		return true;
	if (strcmp(action, param) == 0)
		return true;
	last_dot = strrchr(action, '.');
	return last_dot && strcmp(last_dot + 1, param) == 0;
}

static int __ai_policy_execute(struct ai_policy_ctx *ctx, void *arg)
{
	struct ai_policy *match[AI_POLICY_MAX_COUNT];
	struct ai_decision_record rec;
	struct ai_tp_decision tp;
	unsigned int i, n = 0;
	int executed = 0;
	int failed = 0;
	int clamped = 0;
	int rolled_back = 0;        /* K1 D6：AI_SE_ROLLED_BACK 登记源 */
	u32  side_effect_mask = 0; /* K1 D6：AI_SE_* 聚合 */
	u64 t0, t1, lat;

	if (!ctx)
		return AI_ERR_INVALID_ARG;

	/* 安全边界闸门：全局关闭 → 单分支拒绝（零记录零执行） */
	if (!ai_policy_safety_get_enabled())
		return AI_ERR_DISABLED;

	/* K2b 修复（nice 回滚立项，K2-LOG 登记）：decision_id 必须在
	 * handler 运行前就绪。ai_control_policy_handler 用 ctx->decision_id
	 * 落决策快照（ai_policy_safety_snapshot_save 拒绝 id=0），原实现
	 * id 在全部 handler 之后才分配、且 ctx 为 const 无法回填 → 快照
	 * 从未真正保存，rollback 恒空转（abnice A/B 实测：rollback all 后
	 * sched.nice 停 5 不回 0、affinity 原样不动、rc=0）。K1 起核心
	 * __ai_policy_execute 直吃可写 ctx（const 壳/trace 壳见文件尾），
	 * id 预分配语义不变；接口签名与全部调用方不变，id 序列仍与
	 * ai_decision_seq 同源单调（每决策一次自增不变）。 */
	if (!ctx->decision_id)
		ctx->decision_id = ai_policy_next_decision_id();
	/* K1 D2：统一 trace 铸造（双零 → 铸；ACT2 显式携带不改写）。
	 * ACT2 ack 经 ai_policy_execute_trace 从调用方 ctx 回读结果 */
	ai_trace_mint(ctx->decision_id, &ctx->trace_hi, &ctx->trace_lo);

	t0 = ktime_get_ns();
	mutex_lock(&ai_policy_lock);
	for (i = 0; i < ai_policy_count; i++) {
		if (ai_policy_table[i]->enabled &&
		    ai_policy_table[i]->domain == ctx->domain &&
		    ai_policy_param_match(ai_policy_table[i]->name,
					  ctx->param))
			match[n++] = ai_policy_table[i];
	}
	if (n > 1) {
		/* 同优先级（注册默认全部 100）时无需排序 */
		if (match[0]->priority != match[n - 1]->priority)
			sort(match, n, sizeof(match[0]), ai_policy_cmp, NULL);
		else if (n > 2) {
			unsigned int k;

			for (k = 1; k < n; k++)
				if (match[k]->priority != match[0]->priority)
					break;
			if (k < n)
				sort(match, n, sizeof(match[0]),
				     ai_policy_cmp, NULL);
		}
	}

	for (i = 0; i < n; i++) {
		struct ai_policy *pol = match[i];
		int rc;

		rc = pol->handler(ctx, arg ? arg : pol->private_data);
		if (rc == AI_POLICY_RC_CLAMPED) {
			executed++;
			clamped++;
		} else if (rc == 0) {
			executed++;
		} else {
			failed++;
			if (pol->rollback) {
				pol->rollback(ctx, arg ? arg : pol->private_data);
				rolled_back++;   /* K1 D6：SE_ROLLED_BACK 登记锚 */
			}
		}

		/*
		 * T2 问题 5：ACT 执行此前无 dmesg 痕迹（审计仅 procfs
		 * decisions ring，重启即失）。按动作逐条打执行结果日志：
		 * 匹配过滤（ai_policy_param_match）之后，故定向只打命中
		 * 的那一条、广播打每一条，executed 数各自可见。
		 * rate-limited 防广播风暴刷屏；成功与失败都留痕。
		 */
		pr_info_ratelimited("AIKernel: policy act '%s' domain=%u "
				    "param='%s' data0=%lld data1=%lld "
				    "executed=%d failed=%d%s\n",
				    pol->name, ctx->domain,
				    ctx->param[0] ? ctx->param : "(broadcast)",
				    (long long)ctx->decision_data[0],
				    (long long)ctx->decision_data[1],
				    executed, failed,
				    rc == AI_POLICY_RC_CLAMPED ?
					    " clamped" :
				    rc == 0 ? "" : " (handler fail)");
	}

	t1 = ktime_get_ns();
	lat = t1 - t0;

	/* 决策记录（全量零脱敏：参数/时间戳/结果全记） */
	memset(&rec, 0, sizeof(rec));
	rec.trigger_ts = ctx->trigger_ts ? ctx->trigger_ts : t0;
	rec.trigger_event_id = ctx->trigger_event_id;
	rec.decision_ts = t0;
	rec.decision_type = ctx->decision_type;
	memcpy(rec.decision_data, ctx->decision_data, sizeof(rec.decision_data));
	rec.execute_ts = t1;
	rec.decision_id = ctx->decision_id;   /* K2b：handler 前已就绪 */
	rec.domain = (u8)ctx->domain;
	rec.source = ctx->source;
	rec.executed = (u8)min_t(unsigned int, executed, U8_MAX);
	rec.safety_clamped = clamped ? 1 : 0;
	rec.confidence = ctx->confidence;
	rec.model_version = ctx->model_version;
	/* K1 D3/D6：新 8 字段 ctx→rec 透传（cost_ns 由 record_write
	 * 统一算定）；副作用三位单点位聚合（executed>0 写参数 / clamp /
	 * 失败回退），互斥清晰不重复置位 */
	if (executed > 0)
		side_effect_mask |= AI_SE_PARAM_WRITTEN;
	if (clamped)
		side_effect_mask |= AI_SE_SAFETY_CLAMPED;
	if (rolled_back)
		side_effect_mask |= AI_SE_ROLLED_BACK;
	rec.trace_hi = ctx->trace_hi;
	rec.trace_lo = ctx->trace_lo;
	rec.intent_id = ctx->intent_id;
	rec.parent_id = ctx->parent_id;
	rec.agent_id = ctx->agent_id;
	rec.expected = ctx->expected;
	rec.side_effect_mask = side_effect_mask;
	if (executed == 0)
		rec.outcome = AI_OUTCOME_UNKNOWN;
	else if (failed == 0)
		rec.outcome = clamped ? AI_OUTCOME_PARTIAL : AI_OUTCOME_SUCCESS;
	else
		rec.outcome = (executed - clamped) > 0 ? AI_OUTCOME_PARTIAL
						       : AI_OUTCOME_FAILED;

	ai_policy_record_write(&rec, lat);
	ai_agent_note_cost(rec.agent_id, rec.cost_ns);   /* K3：agent 成本归集 */

	/* AI 自我观测遥测（cat18：决策事件） */
	memset(&tp, 0, sizeof(tp));
	tp.type = 1;
	tp.decision_id = rec.decision_id;
	tp.trigger_ts = rec.trigger_ts;
	tp.trigger_event_id = rec.trigger_event_id;
	tp.decision_type = rec.decision_type;
	tp.domain = rec.domain;
	tp.confidence = rec.confidence;
	tp.model_version = rec.model_version;
	tp.executed = rec.executed;
	tp.safety_clamped = rec.safety_clamped;
	/* K7 D1：决策上下文对包段——cat18 决策事件头携带 trace/agent
	 * （trace_lo=decision_id：链内判别键；hi 为 per-boot 常量 cookie） */
	ai_telemetry_ctx_set(rec.trace_lo, rec.agent_id);
	ai_telemetry_emit(AI_CAT_AI, AI_EV_AI_DECISION, AI_SEV_NORMAL,
			  &tp, sizeof(tp));
	ai_telemetry_ctx_clear();

	mutex_unlock(&ai_policy_lock);

	/* W49 ai-6/7：决策结果异步推送（已注册 NETLINK_AI 的 AI 主体免轮询）。
	 * 协议族未创建/无注册者时为廉价空操作；GFP_ATOMIC 路径不睡眠。 */
	ai_netlink_push_event_trace(AI_NL_EV_POLICY,
		rec.outcome == AI_OUTCOME_FAILED ? AI_NL_EV_SEV_ERROR :
		rec.outcome == AI_OUTCOME_PARTIAL ? AI_NL_EV_SEV_WARN :
		AI_NL_EV_SEV_INFO,
		rec.decision_id, executed,
		ctx->param[0] ? ctx->param : NULL,
		rec.trace_hi, rec.trace_lo);   /* K1 D7：72B 带 trace 尾 */

	return executed;
}

/* K1 D2：const 壳（v1 调用方行为/ABI 不变；零进零铸语义同旧）。 */
int ai_policy_execute(const struct ai_policy_ctx *ctx, void *arg)
{
	struct ai_policy_ctx ctx_v;

	if (!ctx)
		return AI_ERR_INVALID_ARG;
	ctx_v = *ctx;
	return __ai_policy_execute(&ctx_v, arg);
}
EXPORT_SYMBOL_GPL(ai_policy_execute);

/**
 * ai_policy_execute_trace() - 同 ai_policy_execute，但 ctx 可写：
 * decision_id 补铸与统一 trace 铸造（K1 D2）结果回写调用方 ctx，
 * 供 ACT2 ack 回读决策关联键（decision_id/trace_hi/trace_lo）。
 * 显式携带（hi/lo 任一非零）原样带回，内核不改写。
 */
int ai_policy_execute_trace(struct ai_policy_ctx *ctx, void *arg)
{
	if (!ctx)
		return AI_ERR_INVALID_ARG;
	return __ai_policy_execute(ctx, arg);
}
EXPORT_SYMBOL_GPL(ai_policy_execute_trace);

/* ---- K2a（KERNEL-K2-DESIGN D2/D3/D5/D6）：ACT_BATCH 批量事务 ---- */

/*
 * 无状态 confirm token 派生（D6）：FNV64a——offset basis
 * 0xcbf29ce484222325、prime 0x100000001b3（仓内同款口径：用户态
 * as_util.c:45 / executor.c:1305 的 intent/session 混合即此参数组）；
 * u64 字段按小端 8 字节展开逐字节 xor-mul。
 * token = FNV64a(升序 (param_idx, pid, clamped_value) 序列 + radius)
 * ——无状态可重算；radius 或任一元组变化 → token 自然失配（重试即重验）。
 */
#define AI_BATCH_FNV_OFFSET	0xcbf29ce484222325ULL
#define AI_BATCH_FNV_PRIME	0x100000001b3ULL

static u64 ai_batch_fnv64a_mix(u64 h, u64 v)
{
	u8 k;

	for (k = 0; k < 8; k++) {
		h ^= (u8)v;
		h *= AI_BATCH_FNV_PRIME;
		v >>= 8;
	}
	return h;
}

/* Pass1 dry-run 逐项产物（栈上 ≤ AI_BATCH_MAX_OPS 项；不驻留
 * ai_control 参数结构体，控内核栈占用） */
struct ai_batch_item {
	struct ai_policy *pol;	/* 精确同名且 enabled 的策略项（持锁稳定） */
	u32 pidx;		/* ai_control 参数表索引 */
	u32 pflags;		/* AI_CTRL_F_* */
	u8  domain;		/* 参数域（记录/ctx 用） */
	u8  clamped_flag;	/* 1=被幅度限幅 */
	s64 clamped;		/* 钳后值（token 派生与 Pass2 请求值） */
	u32 radius;		/* D6：pid 定向=1，全局=nr_threads */
};

/* D5 自动回滚：hrtimer 回调只 queue_work（ai_net.c:402 qdisc 范式——
 * restore 链含 GFP_KERNEL/mutex 级睡眠，硬中断直调必炸）；work 持
 * ai_policy_lock 回滚（锁序收编后与 execute/batch 同锁串行）。 */
static enum hrtimer_restart ai_batch_ar_timer_fn(struct hrtimer *timer)
{
	queue_work(system_wq, &ai_batch_ar_work);
	return HRTIMER_NORESTART;
}

static void ai_batch_ar_work_fn(struct work_struct *work)
{
	u64 id, thi, tlo;

	mutex_lock(&ai_policy_lock);
	if (!ai_batch_ar.armed) {
		mutex_unlock(&ai_policy_lock);
		return;	/* confirm 已取消 / 幂等残留触发 */
	}
	id = ai_batch_ar.decision_id;
	thi = ai_batch_ar.trace_hi;
	tlo = ai_batch_ar.trace_lo;
	ai_batch_ar.armed = false;
	/* 已持 ai_policy_lock：直调 safety 层（public 包装同锁，勿嵌套） */
	ai_policy_safety_rollback_decision(id, ai_control_restore_value);
	mutex_unlock(&ai_policy_lock);
	pr_info("AIKernel: batch auto-rollback decision=%llu (values restored)\n",
		id);
	/* code=0：与常规 policy 事件（code=executed）区分——as_outcome tap
	 * 以 category==policy && executed>0 建 job（rows-b §3），回滚通知
	 * 若带 executed 会误触 outcome 管线（K2a 判决；设计册 D5 原文
	 * code=executed，差异登记 K2a 报告） */
	ai_netlink_push_event_trace(AI_NL_EV_POLICY, AI_NL_EV_SEV_WARN,
				    id, 0, "auto_rollback", thi, tlo);
}

/* 成功批 arm（持 ai_policy_lock 调用）；v1 单槽：armed 再 arm → -EBUSY */
static int ai_batch_ar_arm(u64 id, u32 ms, u64 thi, u64 tlo)
{
	if (READ_ONCE(ai_batch_ar.armed))
		return -EBUSY;	/* 诚实拒：多槽需求登记 K4 前 */
	ai_batch_ar.armed = true;
	ai_batch_ar.decision_id = id;
	ai_batch_ar.trace_hi = thi;
	ai_batch_ar.trace_lo = tlo;
	hrtimer_start(&ai_batch_ar_timer, ms_to_ktime(ms),
		      HRTIMER_MODE_REL);
	return 0;
}

int ai_policy_batch_confirm(u64 decision_id)
{
	if (!decision_id)
		return -EINVAL;

	mutex_lock(&ai_policy_lock);
	if (!ai_batch_ar.armed || ai_batch_ar.decision_id != decision_id) {
		mutex_unlock(&ai_policy_lock);
		return -ENOENT;	/* 未 arm / 已回滚（work 消费）/ id 不符 */
	}
	ai_batch_ar.armed = false;
	/* 锁外 cancel：work 本体也取 ai_policy_lock，持锁 cancel_work_sync
	 * 会自等死锁（armed 已清，残留 work/timer 动作幂等空转） */
	mutex_unlock(&ai_policy_lock);
	hrtimer_cancel(&ai_batch_ar_timer);
	cancel_work_sync(&ai_batch_ar_work);
	return 0;
}
EXPORT_SYMBOL_GPL(ai_policy_batch_confirm);

u32 ai_policy_blast_threshold_get(void)
{
	return READ_ONCE(ai_batch_blast_threshold);
}
EXPORT_SYMBOL_GPL(ai_policy_blast_threshold_get);

int ai_policy_blast_threshold_set(u32 val)
{
	WRITE_ONCE(ai_batch_blast_threshold, val);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_policy_blast_threshold_set);

int ai_policy_execute_batch(const struct ai_batch_op *ops, u32 n_ops,
			    const struct ai_batch_opts *opts,
			    struct ai_nl_batch_ack *ack)
{
	struct ai_batch_item items[AI_BATCH_MAX_OPS];
	struct ai_decision_record rec;
	struct ai_policy_ctx ictx;
	struct ai_tp_decision tp;
	u64 t0, t1, lat, radius = 0, token = 0;
	u32 threshold, i, j;
	int executed = 0, clamped = 0;
	int first_fail = -1;
	int rc;

	if (!ack)
		return -EINVAL;
	memset(ack, 0, sizeof(*ack));
	ack->first_fail_idx = -1;
	if (!ops || !opts)
		return -EINVAL;
	if (n_ops == 0 || n_ops > AI_BATCH_MAX_OPS) {
		ack->ai_err = -EINVAL;
		return -EINVAL;	/* 计数检查先于逐项（28 项直接拒） */
	}
	if (!ai_policy_safety_get_enabled()) {
		ack->ai_err = AI_ERR_DISABLED;
		return AI_ERR_DISABLED;
	}

	t0 = ktime_get_ns();
	mutex_lock(&ai_policy_lock);

	/* ---- Pass1 dry-run：查表+硬范围+重复名+pid+限幅（零副作用） ---- */
	for (i = 0; i < n_ops; i++) {
		struct ai_control_param p;
		int idx = ai_control_find(ops[i].param);
		s64 cur, v;
		u8 cf = 0;

		memset(&p, 0, sizeof(p));
		if (!ops[i].param || !ops[i].param[0] || idx < 0 ||
		    ai_control_query((u32)idx, &p) != AI_OK) {
			first_fail = (s32)i;	/* 参数名不存在（精确全名） */
			break;
		}
		if (!(p.flags & AI_CTRL_F_REAL)) {
			first_fail = (s32)i;	/* reserved 参数拒收（D2） */
			break;
		}
		for (j = 0; j < i; j++) {
			if (strcmp(ops[j].param, ops[i].param) == 0) {
				first_fail = (s32)i;	/* 重复名拒（D1） */
				break;
			}
		}
		if (first_fail >= 0)
			break;
		if ((p.flags & AI_CTRL_F_TASK) && (s32)ops[i].pid <= 0) {
			first_fail = (s32)i;	/* TASK 参数必须定向 pid */
			break;
		}
		/* 硬范围：批量显式拒（单发 ACT 为静默硬钳；批量新契约=拒收，
		 * D10①「超范围值→-EINVAL」验收口径，K2a 报告登记差异） */
		if ((s64)ops[i].value < p.min || (s64)ops[i].value > p.max) {
			first_fail = (s32)i;
			break;
		}
		/* 限幅基准镜像 handler：read 真值优先（K2a D7 后全局参数亦有
		 * read），失败退影子 cur */
		cur = p.cur;
		if (p.read && p.read(&p, (s32)ops[i].pid, &cur) != AI_OK)
			cur = p.cur;
		v = (s64)ops[i].value;
		if (ai_policy_safety_limit_value(p.min, p.max, cur, &v,
						 &cf) != AI_OK) {
			first_fail = (s32)i;
			break;
		}
		items[i].clamped = v;
		items[i].clamped_flag = cf;
		items[i].pidx = (u32)idx;
		items[i].pflags = p.flags;
		items[i].domain = p.domain;
		/* radius：pid 定向=1；全局参数=全系统任务面 nr_threads（D6，
		 * v1 诚实粗估——cgroup/netns/文件维度不冒充，登记 K4/K6） */
		items[i].radius = ops[i].pid ? 1 : (u32)nr_threads;
		if (items[i].radius > radius)
			radius = items[i].radius;
		/* 策略表精确同名 + enabled（Pass2 handler 级复用入口） */
		items[i].pol = NULL;
		for (j = 0; j < ai_policy_count; j++) {
			if (ai_policy_table[j]->enabled &&
			    strcmp(ai_policy_table[j]->name,
				   ops[i].param) == 0) {
				items[i].pol = ai_policy_table[j];
				break;
			}
		}
		if (!items[i].pol) {
			first_fail = (s32)i;	/* 策略缺失/停用 */
			break;
		}
	}
	if (first_fail >= 0) {
		mutex_unlock(&ai_policy_lock);
		ack->ai_err = -EINVAL;
		ack->first_fail_idx = first_fail;
		return -EINVAL;	/* 零副作用：无 id 无记录无取值 */
	}

	/* ---- D6 blast gate：超阈且 token 缺失/失配 → -EAGAIN ---- */
	threshold = ai_policy_blast_threshold_get();
	if (threshold && radius > threshold) {
		u64 h = AI_BATCH_FNV_OFFSET;

		for (i = 0; i < n_ops; i++) {
			h = ai_batch_fnv64a_mix(h, items[i].pidx);
			h = ai_batch_fnv64a_mix(h, ops[i].pid);
			h = ai_batch_fnv64a_mix(h, (u64)items[i].clamped);
		}
		h = ai_batch_fnv64a_mix(h, radius);
		if (opts->token != h) {
			mutex_unlock(&ai_policy_lock);
			ack->ai_err = -EAGAIN;
			ack->blast_radius = (u32)radius;
			ack->token = h;	/* 无状态派生，重试重算匹配 */
			return -EAGAIN;	/* 零副作用：无 id 无记录 */
		}
		token = h;	/* 过闸 token 回显（未触发=0） */
	}

	/* ---- 取号+铸 trace（K1 链：双零→铸；显式携带不改写） ---- */
	ack->decision_id = ai_policy_next_decision_id();
	ack->trace_hi = opts->trace_hi;
	ack->trace_lo = opts->trace_lo;
	ai_trace_mint(ack->decision_id, &ack->trace_hi, &ack->trace_lo);

	/* ---- Pass2：逐项 snapshot_save+apply（复用 ai_control 既有链） ----
	 * 每项构造定向 ctx（TASK: data[0]=pid data[1]=值；全局: data[0]=值）
	 * 直接调策略 handler（=ai_control_policy_handler，priv=ctrl 表项）：
	 * 限幅→恒等快路径→快照→apply→失败 handler 内自恢复，全部语义与
	 * 单发 execute 一致（同 decision_id 落快照，槽序=子项序号）。 */
	for (i = 0; i < n_ops; i++) {
		memset(&ictx, 0, sizeof(ictx));
		ictx.decision_id = ack->decision_id;
		ictx.trigger_ts = t0;
		ictx.domain = (enum ai_policy_domain)items[i].domain;
		ictx.source = AI_DEC_SRC_NETLINK;
		ictx.trace_hi = ack->trace_hi;
		ictx.trace_lo = ack->trace_lo;
		ictx.intent_id = opts->intent_id;
		ictx.agent_id = opts->agent_id;
		strscpy(ictx.param, ops[i].param, sizeof(ictx.param));
		if (items[i].pflags & AI_CTRL_F_TASK) {
			ictx.decision_data[0] = ops[i].pid;
			ictx.decision_data[1] = (u64)items[i].clamped;
		} else {
			ictx.decision_data[0] = (u64)items[i].clamped;
		}
		rc = items[i].pol->handler(&ictx, items[i].pol->private_data);
		if (rc == AI_POLICY_RC_CLAMPED) {
			executed++;
			clamped++;
		} else if (rc == 0) {
			executed++;
		} else {
			first_fail = (s32)i;	/* handler 内已自恢复本项 */
			break;
		}
		/* D3 post 回填：重复名已拒 → pidx 唯一；恒等快路径项无快照
		 * → NOT_FOUND 静默（post 保持 0=未回填） */
		ai_policy_safety_snapshot_post(ack->decision_id,
					       items[i].pidx,
					       items[i].clamped);
	}

	if (first_fail >= 0) {
		/* 全退已应用项（快照消费即毁）；已持锁 → 直调 safety 层
		 * （public 包装 ai_policy_rollback_decision 同锁勿嵌套） */
		ai_policy_safety_rollback_decision(ack->decision_id,
						  ai_control_restore_value);
	}

	t1 = ktime_get_ns();
	lat = t1 - t0;

	/* 决策记录（D3：data[0]=子项数、data[1]=first_fail；executed=成功
	 * 子项数（失败全退时=失败前成功数，审计留痕）；se 三位复用） */
	memset(&rec, 0, sizeof(rec));
	rec.trigger_ts = t0;
	rec.decision_ts = t0;
	rec.execute_ts = t1;
	rec.decision_data[0] = n_ops;
	rec.decision_data[1] = first_fail >= 0 ? (u64)first_fail : 0;
	rec.decision_id = ack->decision_id;
	rec.domain = items[0].domain;	/* 首元组域（跨域批的代表性记账） */
	rec.source = AI_DEC_SRC_NETLINK;
	rec.executed = (u8)min_t(int, executed, U8_MAX);
	rec.safety_clamped = clamped ? 1 : 0;
	rec.trace_hi = ack->trace_hi;
	rec.trace_lo = ack->trace_lo;
	rec.intent_id = opts->intent_id;
	rec.agent_id = opts->agent_id;
	if (executed > 0)	/* 位语义对齐 __ai_policy_execute */
		rec.side_effect_mask |= AI_SE_PARAM_WRITTEN;
	if (clamped)
		rec.side_effect_mask |= AI_SE_SAFETY_CLAMPED;
	if (first_fail >= 0)
		rec.side_effect_mask |= AI_SE_ROLLED_BACK;
	if (first_fail >= 0)
		rec.outcome = AI_OUTCOME_FAILED;	/* 失败全退 */
	else if (clamped)
		rec.outcome = AI_OUTCOME_PARTIAL;	/* 任一钳=PARTIAL */
	else
		rec.outcome = AI_OUTCOME_SUCCESS;

	ai_policy_record_write(&rec, lat);
	ai_agent_note_cost(rec.agent_id, rec.cost_ns);   /* K3：agent 成本归集 */

	/* cat18 遥测（K1 链照旧） */
	memset(&tp, 0, sizeof(tp));
	tp.type = 1;
	tp.decision_id = rec.decision_id;
	tp.trigger_ts = rec.trigger_ts;
	tp.decision_type = rec.decision_type;
	tp.domain = rec.domain;
	tp.executed = rec.executed;
	tp.safety_clamped = rec.safety_clamped;
	/* K7 D1：决策上下文对包段（同 __ai_policy_execute） */
	ai_telemetry_ctx_set(rec.trace_lo, rec.agent_id);
	ai_telemetry_emit(AI_CAT_AI, AI_EV_AI_DECISION, AI_SEV_NORMAL,
			  &tp, sizeof(tp));
	ai_telemetry_ctx_clear();

	mutex_unlock(&ai_policy_lock);

	ack->executed = rec.executed;
	ack->hit = (first_fail < 0 && executed > 0) ? 1 : 0;
	ack->ai_err = first_fail >= 0 ? -EIO : AI_OK;
	ack->first_fail_idx = first_fail;
	ack->blast_radius = (u32)radius;
	ack->token = token;

	pr_info_ratelimited("AIKernel: policy batch items=%u executed=%d "
			    "clamped=%d first_fail=%d radius=%llu "
			    "decision=%llu%s\n",
			    n_ops, executed, clamped, first_fail, radius,
			    ack->decision_id,
			    first_fail >= 0 ? " (rolled back)" : "");

	/* W49 形态：决策结果异步推送（param="batch"） */
	ai_netlink_push_event_trace(AI_NL_EV_POLICY,
		first_fail >= 0 ? AI_NL_EV_SEV_ERROR :
		clamped ? AI_NL_EV_SEV_WARN : AI_NL_EV_SEV_INFO,
		ack->decision_id, executed, "batch",
		ack->trace_hi, ack->trace_lo);

	/* D5：成功且请求 arm → 单槽定时器（占用中 -EBUSY 记入 ack；
	 * 批已生效，arm 拒不是批失败） */
	if (first_fail < 0 && opts->auto_rollback_ms &&
	    ai_batch_ar_arm(ack->decision_id, opts->auto_rollback_ms,
			    ack->trace_hi, ack->trace_lo))
		ack->ai_err = -EBUSY;

	return first_fail >= 0 ? -EIO : executed;
}
EXPORT_SYMBOL_GPL(ai_policy_execute_batch);

/* 按 decision_id 定位 ring 槽（先查缓存，未命中线性扫；持 ai_dec_lock 调用） */
static struct ai_decision_record *ai_policy_ring_find_locked(u64 decision_id)
{
	unsigned int i;

	for (i = 0; i < AI_DEC_ID_CACHE_SIZE; i++) {
		const struct ai_dec_id_cache_entry *e =
			&ai_dec_id_cache[i];

		if (e->decision_id == decision_id) {
			struct ai_decision_record *r =
				&ai_dec_ring[e->ring_index & AI_DEC_MASK];

			if (r->decision_id == decision_id)
				return r;
		}
	}
	{
		u64 total = ai_dec_total;
		unsigned int start, n = min_t(u64, total,
					       AI_POLICY_DECISION_RING_SIZE);

		start = ai_dec_head - n;
		for (i = 0; i < n; i++) {
			struct ai_decision_record *r =
				&ai_dec_ring[(start + i) & AI_DEC_MASK];

			if (r->decision_id == decision_id)
				return r;
		}
	}
	return NULL;
}

int ai_policy_outcome_update(u64 decision_id, u8 outcome, s64 metric_delta)
{
	struct ai_decision_record *r;
	struct ai_decision_record chain_rec;
	struct ai_tp_outcome tp;
	unsigned long flags;

	if (!decision_id || outcome > AI_OUTCOME_WORSE)
		return AI_ERR_INVALID_ARG;

	/* ring 定位（缓存加速+线性兜底）；单临界区完成回填与因果链取数 */
	spin_lock_irqsave(&ai_dec_lock, flags);
	r = ai_policy_ring_find_locked(decision_id);
	if (!r) {
		spin_unlock_irqrestore(&ai_dec_lock, flags);
		return AI_ERR_NOT_FOUND;
	}
	r->outcome_ts = ktime_get_ns();
	r->outcome = outcome;
	r->metric_delta = metric_delta;
	chain_rec = *r;   /* 完整因果链记录（trigger→decision→outcome） */
	spin_unlock_irqrestore(&ai_dec_lock, flags);

	/* AI 自我观测遥测（cat18：结果事件写回 ring buffer）。
	 * K7 D1：决策上下文对包段——结果事件头携带原决策的 trace/agent
	 * （因果链回读值，与决策事件同键可关联） */
	memset(&tp, 0, sizeof(tp));
	tp.type = 2;
	tp.decision_id = decision_id;
	tp.outcome = outcome;
	tp.metric_delta = metric_delta;
	ai_telemetry_ctx_set(chain_rec.trace_lo, chain_rec.agent_id);
	ai_telemetry_emit(AI_CAT_AI, AI_EV_AI_OUTCOME, AI_SEV_NORMAL,
			  &tp, sizeof(tp));
	ai_telemetry_ctx_clear();

	/* 因果链落链（ring + CSV 导出） */
	ai_causal_chain_push(&chain_rec);

	/* K8：结果回填铸链（OUTCOME 半事件对，decision_id 关联） */
	{
		struct ai_chain_ev_decision_outcome ev = {
			.decision_id = decision_id,
			.outcome = outcome,
			.metric_delta = metric_delta,
			.outcome_ts = chain_rec.outcome_ts,
		};

		ai_chain_append(AI_CHAIN_KIND_DECISION_OUTCOME, &ev,
					 sizeof(ev));
	}

	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_policy_outcome_update);

/*
 * 效果归因环回填（K4.0）：ai_effect.c 窗口结算的定向落笔。与
 * ai_policy_outcome_update 的差异——只改 ring 条目的
 * outcome_ts/outcome/metric_delta，不发遥测、不落因果链（效果窗结算
 * 频率高，逐条 cat18/causal 会淹没 AI Runtime 决策流）。定位复用
 * ai_policy_ring_find_locked（id 缓存 + 线扫兜底）；找不到（被覆盖
 * 滚出 ring）返回 -ENOENT，调用方静默容忍。
 */
int ai_policy_fill_outcome(u32 decision_id, u8 outcome, long delta)
{
	struct ai_decision_record *r;
	unsigned long flags;
	u64 ots;

	if (!decision_id)
		return -EINVAL;

	spin_lock_irqsave(&ai_dec_lock, flags);
	r = ai_policy_ring_find_locked((u64)decision_id);
	if (!r) {
		spin_unlock_irqrestore(&ai_dec_lock, flags);
		return -ENOENT;
	}
	r->outcome_ts = ktime_get_ns();
	ots = r->outcome_ts;
	r->outcome = outcome;
	r->metric_delta = (s64)delta;
	spin_unlock_irqrestore(&ai_dec_lock, flags);

	/* K8：效果结算回填同铸 OUTCOME（与 outcome_update 同构半事件对） */
	{
		struct ai_chain_ev_decision_outcome ev = {
			.decision_id = decision_id,
			.outcome = outcome,
			.metric_delta = (s64)delta,
			.outcome_ts = ots,
		};

		ai_chain_append(AI_CHAIN_KIND_DECISION_OUTCOME, &ev,
					 sizeof(ev));
	}
	return 0;
}
EXPORT_SYMBOL_GPL(ai_policy_fill_outcome);

int ai_policy_rollback_decision(u64 decision_id)
{
	int rc;

	/* K2a D5 锁序收编：rollback 与 execute/batch 同锁串行（原实现不持
	 * ai_policy_lock——定时器回滚 vs 在途 execute 交错未定义，rows-a
	 * §5）。调用者全为进程上下文（sysfs/测试/batch 内部走 safety 层
	 * 直调），grep 清单见 K2a 报告。 */
	mutex_lock(&ai_policy_lock);
	rc = ai_policy_safety_rollback_decision(decision_id,
					       ai_control_restore_value);
	mutex_unlock(&ai_policy_lock);
	/* K8：回滚执行铸链（仅成功路径） */
	if (rc == 0) {
		struct ai_chain_ev_rollback ev = {
			.decision_id = decision_id,
			.count = 1,
		};

		ai_chain_append(AI_CHAIN_KIND_ROLLBACK, &ev, sizeof(ev));
	}
	return rc;
}
EXPORT_SYMBOL_GPL(ai_policy_rollback_decision);

int ai_policy_rollback_all(void)
{
	int rc;

	/* K2a D5 锁序收编（同 ai_policy_rollback_decision） */
	mutex_lock(&ai_policy_lock);
	rc = ai_policy_safety_rollback_all(ai_control_restore_value);
	mutex_unlock(&ai_policy_lock);
	/* K8：全量回滚铸链（count=实回滚数，rc<0 不铸） */
	if (rc >= 0) {
		struct ai_chain_ev_rollback ev = {
			.decision_id = 0,
			.count = (u32)rc,
		};

		ai_chain_append(AI_CHAIN_KIND_ROLLBACK, &ev, sizeof(ev));
	}
	return rc;
}
EXPORT_SYMBOL_GPL(ai_policy_rollback_all);

int ai_policy_set_enabled(const char *action, u8 enable)
{
	unsigned int i;
	int rc = AI_ERR_NOT_FOUND;

	if (!action)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_policy_lock);
	for (i = 0; i < ai_policy_count; i++) {
		if (strcmp(ai_policy_table[i]->name, action) == 0) {
			ai_policy_table[i]->enabled = enable ? 1 : 0;
			rc = AI_OK;
			break;
		}
	}
	mutex_unlock(&ai_policy_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_policy_set_enabled);

int ai_policy_get_name(unsigned int index, char *name, u8 *enabled)
{
	int rc = AI_ERR_NOT_FOUND;

	if (!name)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_policy_lock);
	if (index < ai_policy_count) {
		strscpy(name, ai_policy_table[index]->name, AI_MAX_NAME_LEN);
		if (enabled)
			*enabled = ai_policy_table[index]->enabled;
		rc = AI_OK;
	}
	mutex_unlock(&ai_policy_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_policy_get_name);

int ai_policy_lookup(const char *action, u8 *enabled)
{
	unsigned int i;
	int rc = AI_ERR_NOT_FOUND;

	if (!action)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_policy_lock);
	for (i = 0; i < ai_policy_count; i++) {
		if (strcmp(ai_policy_table[i]->name, action) == 0) {
			if (enabled)
				*enabled = ai_policy_table[i]->enabled;
			rc = AI_OK;
			break;
		}
	}
	mutex_unlock(&ai_policy_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_policy_lookup);

int ai_policy_stats_get(struct ai_policy_stats *st)
{
	unsigned long flags;

	if (!st)
		return AI_ERR_INVALID_ARG;

	/* K2b 修复 K1B-21：读侧锁型与写侧（spin_lock_irqsave）对齐，
	 * 拆除"未来任何 hardirq 写者即死锁"的锁型不对称埋雷 */
	spin_lock_irqsave(&ai_dec_lock, flags);
	*st = ai_pstat;
	spin_unlock_irqrestore(&ai_dec_lock, flags);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_policy_stats_get);

int ai_policy_decision_read(void *buf, size_t cap,
			    u32 *out_count, size_t *out_bytes)
{
	unsigned int start, n, i;
	unsigned long flags;   /* K2b（K1B-21）：锁型与写侧对齐 */
	size_t copied = 0;
	u32 count = 0;

	if (!buf || !out_count)
		return AI_ERR_INVALID_ARG;

	spin_lock_irqsave(&ai_dec_lock, flags);
	n = min_t(unsigned int, ai_dec_total, AI_POLICY_DECISION_RING_SIZE);
	/* 最旧在前：start = head - n（回绕由数组线性化处理） */
	start = ai_dec_head - n;

	for (i = 0; i < n; i++) {
		const struct ai_decision_record *e =
			&ai_dec_ring[(start + i) & AI_DEC_MASK];

		if (copied + sizeof(*e) > cap)
			break;
		memcpy((u8 *)buf + copied, e, sizeof(*e));
		copied += sizeof(*e);
		count++;
	}
	spin_unlock_irqrestore(&ai_dec_lock, flags);

	*out_count = count;
	if (out_bytes)
		*out_bytes = copied;
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_policy_decision_read);

#ifdef CONFIG_AIKERNEL_KUNIT_TEST
/* K1 p99 微基准钩子（测试：ai_policy_test.c）：直调内部
 * ai_policy_record_write（cost_ns 就地算定）；纯测试面，
 * 不进任何生产调用链。 */
void ai_policy_test_record_write(struct ai_decision_record *rec)
{
	if (!rec)
		return;
	ai_policy_record_write(rec, 0);
}
#endif /* CONFIG_AIKERNEL_KUNIT_TEST */
