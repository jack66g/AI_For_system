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
#include <linux/slab.h>
#include <linux/types.h>
#include "ai_policy.h"
#include "ai_policy_safety.h"
#include "ai_control.h"
#include "ai_telemetry.h"
#include "ai_causal.h"

#define AI_POLICY_MAX_COUNT  64   /* 注册表容量 */

static struct ai_policy *ai_policy_table[AI_POLICY_MAX_COUNT];
static unsigned int ai_policy_count;
static DEFINE_MUTEX(ai_policy_lock);

static atomic64_t ai_decision_seq = ATOMIC64_INIT(0);

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

/* 决策记录写入 ring + 统计累计（同一临界区；调用方不得持 ai_policy_lock 之外锁） */
static void ai_policy_record_write(const struct ai_decision_record *rec,
				   u64 lat)
{
	unsigned long flags;
	unsigned int slot;

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

int ai_policy_execute(const struct ai_policy_ctx *ctx, void *arg)
{
	struct ai_policy *match[AI_POLICY_MAX_COUNT];
	struct ai_decision_record rec;
	struct ai_tp_decision tp;
	unsigned int i, n = 0;
	int executed = 0;
	int failed = 0;
	int clamped = 0;
	u64 t0, t1, lat;

	if (!ctx)
		return AI_ERR_INVALID_ARG;

	/* 安全边界闸门：全局关闭 → 单分支拒绝（零记录零执行） */
	if (!ai_policy_safety_get_enabled())
		return AI_ERR_DISABLED;

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
			if (pol->rollback)
				pol->rollback(ctx, arg ? arg : pol->private_data);
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
	rec.decision_id = ctx->decision_id ? ctx->decision_id :
					    ai_policy_next_decision_id();
	rec.domain = (u8)ctx->domain;
	rec.source = ctx->source;
	rec.executed = (u8)min_t(unsigned int, executed, U8_MAX);
	rec.safety_clamped = clamped ? 1 : 0;
	rec.confidence = ctx->confidence;
	rec.model_version = ctx->model_version;
	if (executed == 0)
		rec.outcome = AI_OUTCOME_UNKNOWN;
	else if (failed == 0)
		rec.outcome = clamped ? AI_OUTCOME_PARTIAL : AI_OUTCOME_SUCCESS;
	else
		rec.outcome = (executed - clamped) > 0 ? AI_OUTCOME_PARTIAL
						       : AI_OUTCOME_FAILED;

	ai_policy_record_write(&rec, lat);

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
	ai_telemetry_emit(AI_CAT_AI, AI_EV_AI_DECISION, AI_SEV_NORMAL,
			  &tp, sizeof(tp));

	mutex_unlock(&ai_policy_lock);
	return executed;
}
EXPORT_SYMBOL_GPL(ai_policy_execute);

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

	/* AI 自我观测遥测（cat18：结果事件写回 ring buffer） */
	memset(&tp, 0, sizeof(tp));
	tp.type = 2;
	tp.decision_id = decision_id;
	tp.outcome = outcome;
	tp.metric_delta = metric_delta;
	ai_telemetry_emit(AI_CAT_AI, AI_EV_AI_OUTCOME, AI_SEV_NORMAL,
			  &tp, sizeof(tp));

	/* 因果链落链（ring + CSV 导出） */
	ai_causal_chain_push(&chain_rec);

	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_policy_outcome_update);

int ai_policy_rollback_decision(u64 decision_id)
{
	return ai_policy_safety_rollback_decision(decision_id,
						  ai_control_restore_value);
}
EXPORT_SYMBOL_GPL(ai_policy_rollback_decision);

int ai_policy_rollback_all(void)
{
	return ai_policy_safety_rollback_all(ai_control_restore_value);
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
	if (!st)
		return AI_ERR_INVALID_ARG;

	spin_lock(&ai_dec_lock);
	*st = ai_pstat;
	spin_unlock(&ai_dec_lock);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_policy_stats_get);

int ai_policy_decision_read(void *buf, size_t cap,
			    u32 *out_count, size_t *out_bytes)
{
	unsigned int start, n, i;
	size_t copied = 0;
	u32 count = 0;

	if (!buf || !out_count)
		return AI_ERR_INVALID_ARG;

	spin_lock(&ai_dec_lock);
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
	spin_unlock(&ai_dec_lock);

	*out_count = count;
	if (out_bytes)
		*out_bytes = copied;
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_policy_decision_read);
