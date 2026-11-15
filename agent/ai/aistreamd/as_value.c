/* SPDX-License-Identifier: GPL-2.0
 *
 * as_value.c - L1 棒①：价值评分器实现（纯函数核心 + 接线层；
 * 规格与归一基准见 as_value.h 文件头）
 *
 * 纯叶子模块：无日志/IO——失败经返回值与计数上报（as_parquet.c 可
 * 直链本对象，pq_dump 差分驱动同）。
 */
#include <string.h>

#include "as_value.h"

/* ---- 进程级策略快照（缺省=as_conf.h 默认——直接库调用确定性） ---- */

static struct {
	struct as_value_w w;
	int curated;
	long long curated_rows;
	long long curated_fails;
} P = {
	{ AS_VALUE_W1_DEF, AS_VALUE_W2_DEF, AS_VALUE_W3_DEF,
	  AS_VALUE_W4_DEF, AS_VALUE_W5_DEF, AS_VALUE_W6_DEF,
	  AS_VALUE_PROMOTE_MIN_DEF, AS_VALUE_PROMOTE_MAX_DEF },
	1, 0, 0,
};

void as_value_conf_init(const struct as_conf *c)
{
	if (!c)
		return;
	P.w.w1 = c->value_w[0];
	P.w.w2 = c->value_w[1];
	P.w.w3 = c->value_w[2];
	P.w.w4 = c->value_w[3];
	P.w.w5 = c->value_w[4];
	P.w.w6 = c->value_w[5];
	P.w.promote_min = c->value_promote_min;
	P.w.promote_max = c->value_promote_max;
	P.curated = c->curated_enabled ? 1 : 0;
}

const struct as_value_w *as_value_weights(void)
{
	return &P.w;
}

int as_value_promoted(double value)
{
	return value >= P.w.promote_min && value <= P.w.promote_max;
}

int as_value_curated_enabled(void)
{
	return P.curated;
}

void as_value_curated_counts(long long *rows, long long *fails)
{
	if (rows)
		*rows = P.curated_rows;
	if (fails)
		*fails = P.curated_fails;
}

/* writer 层镜像记账（as_parquet.c curated 路回调） */
void as_value_note_curated(int ok, long long nrows)
{
	if (ok)
		P.curated_rows += nrows;
	else
		P.curated_fails++;
}

/* ================= 纯函数核心 ================= */

static double clamp01(double x)
{
	if (x < 0.0)
		return 0.0;
	if (x > 1.0)
		return 1.0;
	return x;
}

static double dabs(double x)
{
	return x < 0.0 ? -x : x;
}

void as_value_score(const struct as_value_w *w,
		    const struct as_value_ev_mat *ev,
		    const struct as_value_dec_mat *dm,
		    const struct as_value_state *st,
		    struct as_value_out *out)
{
	double nov = 0.0, div = 0.0, cost = 0.0, rare = 0.0, rep = 0.0;
	int64_t f = 0;

	if (!out)
		return;
	memset(out, 0, sizeof(*out));

	/* novelty：digest 首见 1 + severity 抬升（封顶 1）；已见=仅抬升 */
	if (ev && ev->digest != 0) {
		double boost = ev->severity == 2 ? 0.25 :
			       ev->severity == 1 ? 0.125 : 0.0;

		nov = clamp01((st && st->digest_seen ? 0.0 : 1.0) + boost);
	} else {
		f |= AS_VF_MISS_NOVELTY;
	}

	/* 反差/代价（decisions 原料；confidence 调制反差） */
	if (dm && dm->has) {
		double d = dabs((double)(dm->outcome - dm->expected));
		double conf = (double)dm->confidence;

		if (conf < 0.0)
			conf = 0.0;
		if (conf > 100.0)
			conf = 100.0;
		div = d / (d + 64.0) * (conf / 100.0);
		cost = (double)dm->cost_ns / ((double)dm->cost_ns + 10000000.0);
	} else {
		f |= AS_VF_MISS_DIVERGENCE | AS_VF_MISS_COST |
		     AS_VF_MISS_CONFIDENCE;
	}

	/* 纠正：occ 侧信号未接入（尾池）——v0 恒 0 贡献+缺失位如实 */
	f |= AS_VF_MISS_CORRECTION;

	/* 稀有：事件路=流计数，decisions 路=agent 计数（口径见头注）；
	 * 稀有态不可用（writer 路）=0 贡献+缺失位 */
	if (st && st->rarity_known) {
		if (dm && dm->has)
			rare = 1.0 / (1.0 + (double)st->agent_count);
		else if (ev && ev->stream_idx >= 0 && ev->stream_idx < 6)
			rare = 1.0 / (1.0 + (double)st->stream_count);
		else
			f |= AS_VF_MISS_RARITY;
	} else {
		f |= AS_VF_MISS_RARITY;
	}

	/* 重复罚：repeats=窗口被合并条数（聚合行 merged_count−1） */
	if (ev) {
		int repeats = ev->merged_count > 1 ? ev->merged_count - 1 : 0;

		rep = (double)repeats / 16.0;
		if (rep > 1.0)
			rep = 1.0;
	}

	out->value = clamp01(w->w1 * nov + w->w2 * div + w->w3 * 0.0 +
			     w->w4 * cost + w->w5 * rare - w->w6 * rep);
	if (out->value >= w->promote_min && out->value <= w->promote_max)
		f |= AS_VF_PROMOTED;
	out->flags = f;
}

double as_value_dec_row_score(const struct pq_dec_row *r)
{
	struct as_value_dec_mat dm;
	struct as_value_state st;
	struct as_value_out o;

	if (!r)
		return 0.0;
	memset(&dm, 0, sizeof(dm));
	memset(&st, 0, sizeof(st));
	dm.has = 1;
	dm.outcome = (long long)r->outcome;
	dm.expected = r->expected;
	dm.cost_ns = (unsigned long long)r->cost_ns;
	dm.confidence = (int)r->confidence;
	dm.agent_id = (int)r->agent_id;
	st.rarity_known = 0;		/* 行内无稀有态（口径见头注） */
	as_value_score(&P.w, NULL, &dm, &st, &o);
	return o.value;
}

/* ================= 接线层 ================= */

void as_value_ctx_init(struct as_value_ctx *c)
{
	memset(c, 0, sizeof(*c));
}

static int sev_num(const char *s)
{
	if (s && strcmp(s, "error") == 0)
		return 2;
	if (s && strcmp(s, "warn") == 0)
		return 1;
	return 0;
}

/* digest 在近窗口（有界环形集）中？ */
static int digest_seen(const struct as_value_ctx *c, uint64_t digest)
{
	for (size_t i = 0; i < c->dig_n; i++)
		if (c->digests[i] == digest)
			return 1;
	return 0;
}

static void digest_insert(struct as_value_ctx *c, uint64_t digest)
{
	c->digests[c->dig_idx] = digest;
	c->dig_idx = (c->dig_idx + 1) % AS_VALUE_NOVELTY_SLOTS;
	if (c->dig_n < AS_VALUE_NOVELTY_SLOTS)
		c->dig_n++;
}

/*
 * 挂点公共体：评分（用前置状态）→ 回填 ev → 推进状态。
 * dec!=NULL=decisions 路（v3 尾巴原料 + AS_VF_DEC_PATH）。
 */
static int hook_common(struct as_value_ctx *c, struct as_event *ev,
		       const struct as_value_dec_mat *dec)
{
	struct as_value_ev_mat em;
	struct as_value_state st;
	struct as_value_out o;

	if (!c || !ev)
		return 0;
	memset(&em, 0, sizeof(em));
	memset(&st, 0, sizeof(st));
	em.digest = ev->digest;
	em.severity = sev_num(ev->severity);
	em.stream_idx = ev->stream_idx;
	em.merged_count = ev->merged_count;
	st.digest_seen = digest_seen(c, ev->digest);
	st.rarity_known = 1;
	if (dec) {
		st.agent_count = dec->agent_id >= 0 ?
			c->agent_counts[dec->agent_id % AS_VALUE_AGENT_BUCKETS] : 0;
	} else if (ev->stream_idx >= 0 && ev->stream_idx < 6) {
		st.stream_count = c->stream_counts[ev->stream_idx];
	}
	as_value_score(as_value_weights(), &em, dec, &st, &o);
	if (dec)
		o.flags |= AS_VF_DEC_PATH;
	ev->value = o.value;
	ev->vflags = o.flags;
	/* 状态推进（评分用前置值——先算后记） */
	digest_insert(c, ev->digest);
	if (dec) {
		if (dec->agent_id >= 0)
			c->agent_counts[dec->agent_id %
					AS_VALUE_AGENT_BUCKETS]++;
	} else if (ev->stream_idx >= 0 && ev->stream_idx < 6) {
		c->stream_counts[ev->stream_idx]++;
	}
	c->scored++;
	if (o.flags & AS_VF_PROMOTED)
		c->promoted++;
	return (o.flags & AS_VF_PROMOTED) ? 1 : 0;
}

int as_value_hook_event(struct as_value_ctx *c, struct as_event *ev)
{
	return hook_common(c, ev, NULL);
}

int as_value_hook_decision(struct as_value_ctx *c, struct as_event *ev)
{
	struct as_value_dec_mat dm;

	if (!ev || !ev->dec_material)
		return 0;
	memset(&dm, 0, sizeof(dm));
	dm.has = 1;
	dm.outcome = (long long)ev->dec_outcome;
	dm.expected = ev->dec_expected;
	dm.cost_ns = ev->dec_cost_ns;
	dm.confidence = ev->dec_confidence;
	dm.agent_id = ev->dec_agent_id;
	return hook_common(c, ev, &dm);
}
