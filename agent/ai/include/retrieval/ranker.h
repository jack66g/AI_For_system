/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ranker.h - T3b 记忆打分（8 信号加权 + breakdown）
 *
 * 逐条对齐 REF-PY（SME 1.3.0, e72bc75）：
 *   sme/retrieval/ranking.py:63-132、sme/dynamics/decay.py、
 *   sme/utils.py:age_days/clamp/exponential_decay。
 *
 *   age        = max(0, (reference - last_hit) / 86400)
 *   factor(f)  = decay 关闭 ? 1.0
 *              : age < 1e-6 ? 1.0
 *              : f + (1-f) * exp(-ln2 * age / max(half_life, 1e-9))
 *   importance = memory.importance * factor(1 - max_importance_decay)
 *   freshness  = memory.freshness / (1 + age / max(half_life, 1e-9))
 *   eff_weight = memory.weight * factor(1 - max_weight_decay)
 *   weight     = eff_weight / (1 + eff_weight)
 *   decay      = factor(1 - max_weight_decay)
 *   hit_count  = hc / (1 + hc)
 *   recency    = 1 / (1 + age / 7)
 *   region     = region_score
 *   final      = Σ wᵢ·signalᵢ（调用方保证 8 个权重之和为 1）
 *
 * detailed=1：每个信号先 clamp 到 [0,1]，再按 Python round(x,4) 舍入；
 *             final 单独 round(final,4)（final 不 clamp）。
 * detailed=0：只写 final=round(final,4)，其余信号字段一律 0。
 * aik_rank_score 的 out->score 是**未舍入**的 final。
 *
 * 舍入复刻 CPython round(x, 4) 的「正确舍入 + 半偶」：实现用
 * snprintf("%.4f") + strtod（glibc printf 对被打印的二进制值做正确
 * 舍入，FE_TONEAREST），不用 floor(x*1e4+0.5)（后者在 0.00035 这类
 * 二进制略小于十进制半值的输入上会错）。
 *
 * 无全局状态；纯函数，可并发调用。
 */
#ifndef _AIK_RETRIEVAL_RANKER_H
#define _AIK_RETRIEVAL_RANKER_H

#include <stddef.h>

#include "store/store_json.h"

/* 参与打分的记忆视图（全部借引用，ranker 不拥有任何指针） */
typedef struct {
	const char *id;
	const char *text;
	const aik_json *metadata;	/* store_json DOM, borrowed */
	const char *const *tags;
	size_t n_tags;
	double importance;
	double weight;
	double freshness;
	int hit_count;
	double last_hit;
	const char *source;
	int archived;
	const double *embedding;
	int dim;
} aik_memory_view;

/* 8 信号权重（RankingConfig，默认 0.40/0.12/0.10/0.10/0.08/0.08/0.06/0.06） */
typedef struct {
	double semantic;
	double importance;
	double freshness;
	double weight;
	double decay;
	double hit_count;
	double recency;
	double region;
} aik_ranking_weights;

/* DecayConfig + enabled（引擎策略 decay_enabled） */
typedef struct {
	double half_life_days;		/* 默认 30.0 */
	double max_weight_decay;	/* 默认 0.85 → floor 0.15 */
	double max_importance_decay;	/* 默认 0.85 → floor 0.15 */
	int enabled;
} aik_decay_config;

/* 打分明细：detailed=0 时除 final 外全 0 */
typedef struct {
	double semantic;
	double importance;
	double freshness;
	double weight;
	double decay;
	double hit_count;
	double recency;
	double region;
	double final;
} aik_score_breakdown;

typedef struct {
	double score;			/* 未舍入的 final */
	aik_score_breakdown breakdown;
} aik_rank_result;

/*
 * aik_rank_score - 计算一条记忆的最终分数
 *
 * w/d/mem/out 不可为 NULL。region_score 由调用方给出（阶段 1 / 图扩展的
 * dampening）。reference 是打分基准时刻（unix 秒）。has_semantic=1 时
 * semantic 由调用方预算（hybrid 或 (cos+1)/2），=0 时该信号取 0.0。
 * detailed=1 填满 breakdown；=0 只填 breakdown.final。
 *
 * 返回 0；参数非法返回 -1（out 不被写）。
 */
int aik_rank_score(const aik_ranking_weights *w, const aik_decay_config *d,
		   const aik_memory_view *mem, double region_score,
		   double reference, int has_semantic, double semantic,
		   int detailed, aik_rank_result *out);

/* 导出给测试：CPython round(value, 4) 等价（正确舍入、半偶） */
double aik_round_half_even4(double value);

#endif /* _AIK_RETRIEVAL_RANKER_H */
