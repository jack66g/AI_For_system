/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ranker.c - T3b 记忆打分：8 信号加权 + breakdown（纯 C11，无第三方依赖）
 *
 * 语义与参考实现见 ranker.h 顶部注释；本文件逐表达式复刻
 * sme/retrieval/ranking.py:80-132 与 sme/dynamics/decay.py:34-52 的
 * 运算顺序（左结合、先乘后加），使 final 与 Python 逐位一致。
 */
#include "retrieval/ranker.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Python math.log(2.0) 的 double 值（与 libm 的 M_LN2 相同，避免
 * -std=c11 严格模式下 M_LN2 不可见） */
#define AIK_LN2 0.693147180559945309417232121458176568

/*
 * age_days - sme/utils.py:24-27
 *
 * max(0.0, (ref - then) / 86400.0)；NaN 归一为 0（与 Python max 的
 * 比较语义一致）。
 */
static double age_days(double then, double reference)
{
	double age = (reference - then) / 86400.0;

	return age > 0.0 ? age : 0.0;
}

/*
 * decay_factor - sme/dynamics/decay.py:_factor
 *
 * enabled=0 → 1.0；age<1e-6 → 1.0（刚命中不衰减）；
 * 否则 floor + (1-floor)*exp(-ln2*age/max(half_life,1e-9))。
 */
static double decay_factor(double age, int enabled, double half_life,
			   double floor_v)
{
	double hl = half_life > 1e-9 ? half_life : 1e-9;
	double retention;

	if (!enabled)
		return 1.0;
	if (age < 1e-6)
		return 1.0;
	/* sme/utils.py:exponential_decay：age<=0 返回 1.0 */
	retention = age <= 0.0 ? 1.0
			       : exp(-AIK_LN2 * age / hl);
	return floor_v + (1.0 - floor_v) * retention;
}

/*
 * clamp01 - sme/utils.py:clamp（lo=0, hi=1）
 *
 * 写成 Python min/max 的比较形式：NaN 结果与 CPython 一致（返回 1.0）。
 */
static double clamp01(double v)
{
	double m = v < 1.0 ? v : 1.0;	/* min(1.0, v) */
	return m > 0.0 ? m : 0.0;	/* max(0.0, m) */
}

double aik_round_half_even4(double value)
{
	char buf[512];
	char *end = NULL;
	char *p;
	int n;
	double rounded;

	/*
	 * glibc 的 printf 对二进制 double 的精确十进制展开做正确舍入，
	 * 默认 FE_TONEAREST 即 ties-to-even —— 与 CPython round(x, 4)
	 * 的语义相同；而 floor(x*1e4+0.5) 会先把 x 放大再取整，二次
	 * 舍入会让 0.00035 之类的输入得到错误结果。
	 */
	n = snprintf(buf, sizeof buf, "%.4f", value);
	if (n < 0 || (size_t)n >= sizeof buf)
		return value;		/* 不可达：double 最长 ~316 字节 */
	/* 防 LC_NUMERIC 非 C locale 时输出 ','（库不修改进程 locale） */
	for (p = buf; *p != '\0'; p++) {
		if (*p == ',')
			*p = '.';
	}
	rounded = strtod(buf, &end);
	if (end == buf)
		return value;
	return rounded;
}

int aik_rank_score(const aik_ranking_weights *w, const aik_decay_config *d,
		   const aik_memory_view *mem, double region_score,
		   double reference, int has_semantic, double semantic,
		   int detailed, aik_rank_result *out)
{
	double half_life;
	double age;
	double decay_floor_weight;
	double factor_importance;
	double factor_weight;
	double importance;
	double freshness;
	double eff_weight;
	double weight;
	double decay;
	double hit_count;
	double recency;
	double sem;
	double final;

	if (!w || !d || !mem || !out)
		return -1;

	half_life = d->half_life_days > 1e-9 ? d->half_life_days : 1e-9;
	age = age_days(mem->last_hit, reference);

	/* ranking.py:90-102，注意每个信号各自的 floor */
	decay_floor_weight = 1.0 - d->max_weight_decay;
	factor_importance = decay_factor(age, d->enabled, d->half_life_days,
					 1.0 - d->max_importance_decay);
	factor_weight = decay_factor(age, d->enabled, d->half_life_days,
				     decay_floor_weight);

	importance = mem->importance * factor_importance;
	freshness = mem->freshness / (1.0 + age / half_life);
	eff_weight = mem->weight * factor_weight;
	weight = eff_weight / (1.0 + eff_weight);
	decay = factor_weight;
	hit_count = (double)mem->hit_count / (1.0 + (double)mem->hit_count);
	recency = 1.0 / (1.0 + age / 7.0);
	sem = has_semantic ? semantic : 0.0;

	/* ranking.py:105-114：左结合求和，权重由调用方保证和为 1 */
	final = w->semantic * sem
	      + w->importance * importance
	      + w->freshness * freshness
	      + w->weight * weight
	      + w->decay * decay
	      + w->hit_count * hit_count
	      + w->recency * recency
	      + w->region * region_score;

	out->score = final;
	memset(&out->breakdown, 0, sizeof out->breakdown);
	if (detailed) {
		out->breakdown.semantic = aik_round_half_even4(clamp01(sem));
		out->breakdown.importance =
			aik_round_half_even4(clamp01(importance));
		out->breakdown.freshness =
			aik_round_half_even4(clamp01(freshness));
		out->breakdown.weight = aik_round_half_even4(clamp01(weight));
		out->breakdown.decay = aik_round_half_even4(clamp01(decay));
		out->breakdown.hit_count =
			aik_round_half_even4(clamp01(hit_count));
		out->breakdown.recency = aik_round_half_even4(clamp01(recency));
		out->breakdown.region =
			aik_round_half_even4(clamp01(region_score));
		out->breakdown.final = aik_round_half_even4(final);
	} else {
		/* ranking.py:118-119：快速通道只舍入 final */
		out->breakdown.final = aik_round_half_even4(final);
	}
	return 0;
}
