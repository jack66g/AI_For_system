/* SPDX-License-Identifier: GPL-2.0 */
/*
 * retriever.c - T3b 两阶段检索（候选池 + 双通道 + hybrid + 图扩展）
 *
 * 逐条对齐 REF-PY sme/retrieval/retriever.py（SME 1.3.0, e72bc75）：
 *   search                304-498
 *   _graph_expand_bfs     524-636
 *   _graph_expand_ppr     639-780
 *   _ppr_subgraph         784-815
 *   _channel_weights      881-905
 *   _vector_scores        938-962
 *   _keyword_scores       964-978
 *   _metadata_matches     989-998
 *   _tags_match           1000-1004
 *
 * 数值约定：通道余弦与 BM25 完全复用 L1 的 aik_bm25_*；ranked final 由
 * aik_rank_score 给出（未舍入）。Python 的 round(x,4) 由
 * aik_round_half_even4 复刻。所有中间集合按「有序数组 + 去重」维护；
 * 最终同分用 (score desc, memory_id asc) 作为 C 的稳定 tie-break
 * （允许差异见 T3B-DESIGN.md §5）。
 */
#include "../include/retrieval/retriever.h"

#include "../include/retrieval/bm25.h"
#include "../include/retrieval/ppr.h"
#include "../include/retrieval/text.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* retriever.py:66-68 */
#define AIK_PPR_NODE_CAP 500
#define AIK_PPR_MIN_EDGES 5

struct aik_retriever {
	aik_retrieval_config cfg;
	aik_bm25 *bm25;
};

struct hit_ref {
	aik_search_hit *h;
};

/* ------------------------------------------------------------------ */
/* 基础工具                                                            */
/* ------------------------------------------------------------------ */
static void set_err(char *err, size_t errlen, const char *msg)
{
	if (err && errlen)
		snprintf(err, errlen, "%s", msg);
}

static char *dup_str(const char *s)
{
	size_t n;
	char *p;

	if (!s)
		return NULL;
	n = strlen(s) + 1;
	p = malloc(n);
	if (p)
		memcpy(p, s, n);
	return p;
}

static double vec_norm(const double *v, int dim)
{
	double s = 0.0;
	int i;

	for (i = 0; i < dim; i++)
		s += v[i] * v[i];
	return sqrt(s);
}

/* 拥有字符串的有序去重集合 */
struct str_vec {
	char **items;
	size_t n;
	size_t cap;
};

static void str_vec_free(struct str_vec *v)
{
	size_t i;

	if (!v)
		return;
	for (i = 0; i < v->n; i++)
		free(v->items[i]);
	free(v->items);
	v->items = NULL;
	v->n = 0;
	v->cap = 0;
}

static int str_vec_contains(const struct str_vec *v, const char *s)
{
	size_t i;

	for (i = 0; i < v->n; i++)
		if (strcmp(v->items[i], s) == 0)
			return 1;
	return 0;
}

static int str_vec_push(struct str_vec *v, const char *s)
{
	char **grown;
	char *copy;

	if (str_vec_contains(v, s))
		return 0;
	if (v->n == v->cap) {
		size_t cap = v->cap ? v->cap * 2 : 16;

		grown = realloc(v->items, cap * sizeof(*grown));
		if (!grown)
			return -1;
		v->items = grown;
		v->cap = cap;
	}
	copy = dup_str(s);
	if (!copy)
		return -1;
	v->items[v->n++] = copy;
	return 0;
}

/* 借用字符串的有序去重集合 */
struct cstr_vec {
	const char **items;
	size_t n;
	size_t cap;
};

static void cstr_vec_free(struct cstr_vec *v)
{
	if (!v)
		return;
	free(v->items);
	v->items = NULL;
	v->n = 0;
	v->cap = 0;
}

static int cstr_vec_contains(const struct cstr_vec *v, const char *s)
{
	size_t i;

	for (i = 0; i < v->n; i++)
		if (strcmp(v->items[i], s) == 0)
			return 1;
	return 0;
}

static int cstr_vec_push(struct cstr_vec *v, const char *s)
{
	const char **grown;

	if (cstr_vec_contains(v, s))
		return 0;
	if (v->n == v->cap) {
		size_t cap = v->cap ? v->cap * 2 : 16;

		grown = realloc(v->items, cap * sizeof(*grown));
		if (!grown)
			return -1;
		v->items = grown;
		v->cap = cap;
	}
	v->items[v->n++] = s;
	return 0;
}

static int cstr_vec_copy(struct cstr_vec *dst, const struct cstr_vec *src)
{
	size_t i;

	memset(dst, 0, sizeof(*dst));
	for (i = 0; i < src->n; i++)
		if (cstr_vec_push(dst, src->items[i]) != 0) {
			cstr_vec_free(dst);
			return -1;
		}
	return 0;
}

static size_t cstr_vec_index(const struct cstr_vec *v, const char *s)
{
	size_t i;

	for (i = 0; i < v->n; i++)
		if (strcmp(v->items[i], s) == 0)
			return i;
	return (size_t)-1;
}

static int cmp_cstr(const void *pa, const void *pb)
{
	const char *const *a = pa;
	const char *const *b = pb;

	return strcmp(*a, *b);
}

/* region_id -> region 分数（Python dict，setdefault 语义） */
struct rs_entry {
	char *id;
	double score;
};

struct rs_map {
	struct rs_entry *items;
	size_t n;
	size_t cap;
};

static void rs_free(struct rs_map *m)
{
	size_t i;

	if (!m)
		return;
	for (i = 0; i < m->n; i++)
		free(m->items[i].id);
	free(m->items);
	m->items = NULL;
	m->n = 0;
	m->cap = 0;
}

static int rs_setdefault(struct rs_map *m, const char *id, double score)
{
	struct rs_entry *grown;
	char *copy;
	size_t i;

	for (i = 0; i < m->n; i++)
		if (strcmp(m->items[i].id, id) == 0)
			return 0;
	if (m->n == m->cap) {
		size_t cap = m->cap ? m->cap * 2 : 8;

		grown = realloc(m->items, cap * sizeof(*grown));
		if (!grown)
			return -1;
		m->items = grown;
		m->cap = cap;
	}
	copy = dup_str(id);
	if (!copy)
		return -1;
	m->items[m->n].id = copy;
	m->items[m->n].score = score;
	m->n++;
	return 0;
}

/* 1=存在；0=不存在 */
static int rs_get(const struct rs_map *m, const char *id, double *out)
{
	size_t i;

	for (i = 0; i < m->n; i++)
		if (strcmp(m->items[i].id, id) == 0) {
			*out = m->items[i].score;
			return 1;
		}
	return 0;
}

/* 按 id 排序的记忆视图索引（`memories` 的插入序另由原数组保留） */
struct mem_index {
	const aik_memory_view **items;
	size_t n;
};

static int cmp_mem_ptr(const void *pa, const void *pb)
{
	const aik_memory_view *const *a = pa;
	const aik_memory_view *const *b = pb;

	return strcmp((*a)->id, (*b)->id);
}

static int mem_index_build(struct mem_index *mi, const aik_memory_view *mems,
			   size_t n, char *err, size_t errlen)
{
	size_t i;

	memset(mi, 0, sizeof(*mi));
	if (n == 0)
		return 0;
	mi->items = malloc(n * sizeof(*mi->items));
	if (!mi->items) {
		set_err(err, errlen, "out of memory");
		return -1;
	}
	for (i = 0; i < n; i++)
		mi->items[i] = &mems[i];
	qsort(mi->items, n, sizeof(*mi->items), cmp_mem_ptr);
	mi->n = n;
	return 0;
}

static void mem_index_free(struct mem_index *mi)
{
	free(mi->items);
	mi->items = NULL;
	mi->n = 0;
}

static const aik_memory_view *mem_find(const struct mem_index *mi,
				       const char *id)
{
	size_t lo = 0;
	size_t hi = mi->n;

	if (!id)
		return NULL;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		int c = strcmp(mi->items[mid]->id, id);

		if (c == 0)
			return mi->items[mid];
		if (c < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/* 过滤（retriever.py:989-1004）                                       */
/* ------------------------------------------------------------------ */
/*
 * Python 的 bool 是 int 子类：True == 1、False == 0，且与 float 也比较
 * 相等。返回 1 表示 v 属于数值类（BOOL/INT/NUM）并写入 out。
 */
static int json_number_value(const aik_json *v, double *out)
{
	switch (aik_json_typeof(v)) {
	case AIK_JSON_BOOL:
		*out = aik_json_bool(v) ? 1.0 : 0.0;
		return 1;
	case AIK_JSON_INT:
	case AIK_JSON_NUM:
		*out = aik_json_num(v);
		return 1;
	default:
		return 0;
	}
}

/* Python 的 == 语义：数值跨 bool/int/float 比较，容器深比较（dict 无序） */
static int json_value_equal(const aik_json *a, const aik_json *b)
{
	aik_json_type ta = aik_json_typeof(a);
	aik_json_type tb = aik_json_typeof(b);
	double na;
	double nb;
	size_t i;
	size_t n;

	/* int 与 int 保持精确比较（大整数不被 double 截断） */
	if (ta == AIK_JSON_INT && tb == AIK_JSON_INT)
		return aik_json_int(a) == aik_json_int(b);
	/* bool/int/num 混比：True == 1 == 1.0、False == 0 == 0.0 */
	if (json_number_value(a, &na) && json_number_value(b, &nb))
		return na == nb;
	if (ta != tb)
		return 0;
	switch (ta) {
	case AIK_JSON_NULL:
		return 1;
	case AIK_JSON_BOOL:
		return aik_json_bool(a) == aik_json_bool(b);
	case AIK_JSON_INT:
		return aik_json_int(a) == aik_json_int(b);
	case AIK_JSON_NUM:
		return aik_json_num(a) == aik_json_num(b);
	case AIK_JSON_STR: {
		const char *sa = aik_json_str(a);
		const char *sb = aik_json_str(b);

		return sa && sb && strcmp(sa, sb) == 0;
	}
	case AIK_JSON_ARR:
		n = aik_json_count(a);
		if (n != aik_json_count(b))
			return 0;
		for (i = 0; i < n; i++)
			if (!json_value_equal(aik_json_at(a, i),
					      aik_json_at(b, i)))
				return 0;
		return 1;
	case AIK_JSON_OBJ:
		n = aik_json_count(a);
		if (n != aik_json_count(b))
			return 0;
		for (i = 0; i < n; i++) {
			const char *key = aik_json_key_at(a, i);
			const aik_json *bv;

			if (!key)
				return 0;
			bv = aik_json_get(b, key);
			if (!bv || !json_value_equal(aik_json_val_at(a, i), bv))
				return 0;
		}
		return 1;
	}
	return 0;
}

static int metadata_matches(const aik_memory_view *m, const aik_json *filters)
{
	size_t i;
	size_t n;

	if (!filters || aik_json_typeof(filters) != AIK_JSON_OBJ)
		return 1;
	n = aik_json_count(filters);
	for (i = 0; i < n; i++) {
		const char *key = aik_json_key_at(filters, i);
		const aik_json *want = aik_json_val_at(filters, i);
		const aik_json *have;

		if (!key)
			continue;
		have = aik_json_get(m->metadata, key);
		if (!have)
			return 0;
		if (aik_json_typeof(want) == AIK_JSON_ARR) {
			size_t k;
			size_t nv = aik_json_count(want);
			int hit = 0;

			for (k = 0; k < nv; k++)
				if (json_value_equal(aik_json_at(want, k), have)) {
					hit = 1;
					break;
				}
			if (!hit)
				return 0;
		} else if (!json_value_equal(have, want)) {
			return 0;
		}
	}
	return 1;
}

static int tags_match(const aik_memory_view *m, const char *const *tags,
		      size_t n_tags)
{
	size_t i;
	size_t j;

	if (!tags || n_tags == 0)
		return 1;
	for (i = 0; i < n_tags; i++) {
		if (!tags[i])
			continue;
		for (j = 0; j < m->n_tags; j++)
			if (m->tags[j] && strcmp(tags[i], m->tags[j]) == 0)
				return 1;
	}
	return 0;
}

/* engine.policy.allows_retrieval（archived 恒 False） */
static int policy_allows(const aik_search_ctx *ctx,
			 const aik_memory_view *m)
{
	if (m->archived)
		return 0;
	if (ctx->policy_full_memory)
		return 1;
	return m->importance >= ctx->policy_importance_threshold;
}

/* retriever.visible：archived/policy/metadata/tags */
static int visible(const aik_search_ctx *ctx, const aik_search_query *q,
		   const aik_memory_view *m)
{
	if (m->archived && !q->include_archived)
		return 0;
	if (!policy_allows(ctx, m) && !q->include_archived)
		return 0;
	return metadata_matches(m, q->metadata_filters) &&
	       tags_match(m, q->tags, q->n_tags);
}

/* ------------------------------------------------------------------ */
/* 通道分数（retriever.py:881-978）                                    */
/* ------------------------------------------------------------------ */
static void channel_weights(const aik_retrieval_config *cfg, double *vw,
			    double *kw, double *mw)
{
	if (cfg->fusion == AIK_FUSION_MINMAX) {
		double total = cfg->vector_weight + cfg->keyword_weight;

		if (total > 0.0) {
			*vw = cfg->vector_weight / total;
			*kw = cfg->keyword_weight / total;
			*mw = 0.0;
			return;
		}
		*vw = 1.0;
		*kw = 0.0;
		*mw = 0.0;
		return;
	}
	*vw = cfg->vector_weight;
	*kw = cfg->keyword_weight;
	*mw = cfg->metadata_weight;
}

/*
 * _vector_scores：mat 行归一化、query 归一化，逐元素相除后按维度顺序累加。
 * minmax 在候选池内归一（全等 0.5）；weighted 用 clip((cos+1)/2,0,1)。
 */
static int compute_vector_scores(const aik_search_ctx *ctx,
				 const aik_retrieval_config *cfg,
				 const aik_memory_view **cands, size_t n,
				 double *out, char *err, size_t errlen)
{
	double *sims;
	double qn;
	double qd;
	size_t i;
	size_t n_emb = 0;
	int have_range = 0;
	double lo = 0.0;
	double hi = 0.0;

	memset(out, 0, n * sizeof(*out));
	if (n == 0)
		return 0;
	sims = malloc(n * sizeof(*sims));
	if (!sims) {
		set_err(err, errlen, "out of memory");
		return -1;
	}
	qn = vec_norm(ctx->query_vector, ctx->dim);
	qd = qn > 1e-12 ? qn : 1e-12;
	for (i = 0; i < n; i++) {
		const aik_memory_view *m = cands[i];
		double en;
		double ed;
		double s = 0.0;
		int j;

		if (!m->embedding)
			continue;
		en = vec_norm(m->embedding, ctx->dim);
		ed = en > 1e-12 ? en : 1e-12;
		for (j = 0; j < ctx->dim; j++)
			s += (m->embedding[j] / ed) *
			     (ctx->query_vector[j] / qd);
		sims[i] = s;
		n_emb++;
	}
	if (n_emb == 0) {
		free(sims);
		return 0;
	}
	if (cfg->fusion == AIK_FUSION_MINMAX) {
		for (i = 0; i < n; i++) {
			if (!cands[i]->embedding)
				continue;
			if (!have_range) {
				lo = sims[i];
				hi = sims[i];
				have_range = 1;
				continue;
			}
			if (sims[i] < lo)
				lo = sims[i];
			if (sims[i] > hi)
				hi = sims[i];
		}
		if (hi <= lo) {
			for (i = 0; i < n; i++)
				if (cands[i]->embedding)
					out[i] = 0.5;
		} else {
			double span = hi - lo;

			for (i = 0; i < n; i++)
				if (cands[i]->embedding)
					out[i] = (sims[i] - lo) / span;
		}
	} else {
		for (i = 0; i < n; i++) {
			double s;

			if (!cands[i]->embedding)
				continue;
			s = (sims[i] + 1.0) / 2.0;
			if (s < 0.0)
				s = 0.0;
			if (s > 1.0)
				s = 1.0;
			out[i] = s;
		}
	}
	free(sims);
	return 0;
}

/*
 * _keyword_scores：query token 必须与索引同方案（aik_tokenize cjk_bigram）。
 * minmax 只对 raw>0 的子集归一（其余保持 0）；weighted 用池峰值归一。
 */
static int compute_keyword_scores(struct aik_retriever *r,
				  const aik_retrieval_config *cfg,
				  const char *text,
				  const aik_memory_view **cands, size_t n,
				  double *out, char *err, size_t errlen)
{
	aik_token_list toks;
	const char **ids = NULL;
	double *raw = NULL;
	size_t i;
	int rc = -1;

	memset(out, 0, n * sizeof(*out));
	if (n == 0)
		return 0;
	if (!r->bm25)
		return 0;
	memset(&toks, 0, sizeof(toks));
	if (aik_tokenize(text ? text : "", r->cfg.cjk_bigram, &toks, err,
			 errlen) != 0)
		return -1;
	if (toks.count == 0) {
		aik_token_list_free(&toks);
		return 0;
	}
	ids = malloc(n * sizeof(*ids));
	if (!ids) {
		set_err(err, errlen, "out of memory");
		goto done;
	}
	for (i = 0; i < n; i++)
		ids[i] = cands[i]->id;
	if (cfg->fusion == AIK_FUSION_MINMAX) {
		size_t matched = 0;
		double lo = 0.0;
		double hi = 0.0;

		raw = malloc(n * sizeof(*raw));
		if (!raw) {
			set_err(err, errlen, "out of memory");
			goto done;
		}
		if (aik_bm25_scores(r->bm25, &toks, ids, n, 0, raw, err,
				    errlen) != 0)
			goto done;
		for (i = 0; i < n; i++) {
			if (!(raw[i] > 0.0))
				continue;
			if (matched == 0) {
				lo = raw[i];
				hi = raw[i];
			} else {
				if (raw[i] < lo)
					lo = raw[i];
				if (raw[i] > hi)
					hi = raw[i];
			}
			matched++;
		}
		if (matched > 0) {
			if (hi <= lo) {
				for (i = 0; i < n; i++)
					if (raw[i] > 0.0)
						out[i] = 0.5;
			} else {
				double span = hi - lo;

				for (i = 0; i < n; i++)
					if (raw[i] > 0.0)
						out[i] = (raw[i] - lo) / span;
			}
		}
	} else if (aik_bm25_scores(r->bm25, &toks, ids, n, 1, out, err,
				   errlen) != 0) {
		goto done;
	}
	rc = 0;
done:
	free(raw);
	free(ids);
	aik_token_list_free(&toks);
	return rc;
}

/* ------------------------------------------------------------------ */
/* 命中构造 / 排序                                                      */
/* ------------------------------------------------------------------ */
static int init_hit(aik_search_hit *hit, const aik_memory_view *m,
		    double score, const char *region_id, double region_score,
		    double keyword_score, double vector_score, int meta)
{
	memset(hit, 0, sizeof(*hit));
	hit->memory_id = dup_str(m->id);
	hit->region_id = dup_str(region_id ? region_id : "");
	if (!hit->memory_id || !hit->region_id) {
		free(hit->memory_id);
		free(hit->region_id);
		hit->memory_id = NULL;
		hit->region_id = NULL;
		return -1;
	}
	hit->score = score;
	hit->region_score = region_score;
	hit->keyword_score = aik_round_half_even4(keyword_score);
	hit->vector_score = aik_round_half_even4(vector_score);
	hit->metadata_match = meta;
	return 0;
}

static void free_hit(aik_search_hit *hit)
{
	if (!hit)
		return;
	free(hit->memory_id);
	free(hit->region_id);
	hit->memory_id = NULL;
	hit->region_id = NULL;
}

static int cmp_hit_score(const void *pa, const void *pb)
{
	const aik_search_hit *a = pa;
	const aik_search_hit *b = pb;

	if (a->score > b->score)
		return -1;
	if (a->score < b->score)
		return 1;
	return strcmp(a->memory_id, b->memory_id);
}

static int cmp_hit_ref(const void *pa, const void *pb)
{
	const struct hit_ref *a = pa;
	const struct hit_ref *b = pb;

	return cmp_hit_score(a->h, b->h);
}

static int copy_refs(const struct hit_ref *src, size_t n,
		     struct hit_ref **out)
{
	struct hit_ref *p = NULL;

	if (n > 0) {
		p = malloc(n * sizeof(*p));
		if (!p)
			return -1;
		memcpy(p, src, n * sizeof(*p));
	}
	*out = p;
	return 0;
}

/* ------------------------------------------------------------------ */
/* PPR 图扩展（retriever.py:784-872）                                  */
/* ------------------------------------------------------------------ */
struct nbr_list {
	const char **ids;
	size_t n;
	size_t cap;
};

static void nbr_list_free(struct nbr_list *l)
{
	free(l->ids);
	l->ids = NULL;
	l->n = 0;
	l->cap = 0;
}

static int nbr_list_add(struct nbr_list *l, const char *id)
{
	const char **grown;
	size_t i;

	for (i = 0; i < l->n; i++)
		if (strcmp(l->ids[i], id) == 0)
			return 0;
	if (l->n == l->cap) {
		size_t cap = l->cap ? l->cap * 2 : 8;

		grown = realloc(l->ids, cap * sizeof(*grown));
		if (!grown)
			return -1;
		l->ids = grown;
		l->cap = cap;
	}
	l->ids[l->n++] = id;
	return 0;
}

/*
 * graph.neighbors_of 的无向等价：遍历 edges（插入序）收集对端并去重。
 * sort=1 按 memory_id 升序（PPR 子图用）；sort=0 保持边序（BFS 退化路，
 * Python 侧是 set 迭代序，仅影响节点发现顺序，不影响集合与分数）。
 */
static int neighbors_collect(const aik_search_ctx *ctx, const char *mid,
			     int sort, struct nbr_list *out, char *err,
			     size_t errlen)
{
	size_t i;

	memset(out, 0, sizeof(*out));
	for (i = 0; i < ctx->n_edges; i++) {
		const aik_graph_edge *e = &ctx->edges[i];
		const char *other = NULL;

		if (!e->source || !e->target)
			continue;
		if (strcmp(e->source, mid) == 0)
			other = e->target;
		else if (strcmp(e->target, mid) == 0)
			other = e->source;
		if (!other)
			continue;
		if (nbr_list_add(out, other) != 0) {
			set_err(err, errlen, "out of memory");
			nbr_list_free(out);
			return -1;
		}
	}
	if (sort && out->n > 1)
		qsort(out->ids, out->n, sizeof(*out->ids), cmp_cstr);
	return 0;
}

/*
 * _ppr_subgraph：从 seeds（已按权重降序）出发 BFS graph_expand 跳，
 * archived 不出现也不中继，节点上限 500。
 */
static int ppr_subgraph(const aik_search_ctx *ctx, const aik_search_query *q,
			const struct cstr_vec *seeds,
			const struct mem_index *mi, struct cstr_vec *out,
			char *err, size_t errlen)
{
	struct cstr_vec seen;
	struct cstr_vec frontier;
	int depth_r;
	int rc = -1;

	memset(out, 0, sizeof(*out));
	memset(&seen, 0, sizeof(seen));
	memset(&frontier, 0, sizeof(frontier));
	if (cstr_vec_copy(&seen, seeds) != 0 ||
	    cstr_vec_copy(&frontier, seeds) != 0 ||
	    cstr_vec_copy(out, seeds) != 0)
		goto oom;
	for (depth_r = 1; depth_r <= q->graph_expand; depth_r++) {
		struct cstr_vec nxt;
		size_t i;

		memset(&nxt, 0, sizeof(nxt));
		for (i = 0; i < frontier.n; i++) {
			struct nbr_list nbrs;
			size_t j;

			if (neighbors_collect(ctx, frontier.items[i], 1, &nbrs,
					      err, errlen) != 0) {
				cstr_vec_free(&nxt);
				goto done;
			}
			for (j = 0; j < nbrs.n; j++) {
				const char *nb = nbrs.ids[j];
				const aik_memory_view *m;

				if (cstr_vec_contains(&seen, nb))
					continue;
				m = mem_find(mi, nb);
				if (!m)
					continue;
				if (out->n >= AIK_PPR_NODE_CAP)
					break;
				if (m->archived && !q->include_archived) {
					/* archived 只进 seen：不出现、不中继 */
					if (cstr_vec_push(&seen, nb) != 0) {
						nbr_list_free(&nbrs);
						cstr_vec_free(&nxt);
						goto oom;
					}
					continue;
				}
				if (cstr_vec_push(&seen, nb) != 0 ||
				    cstr_vec_push(out, nb) != 0 ||
				    cstr_vec_push(&nxt, nb) != 0) {
					nbr_list_free(&nbrs);
					cstr_vec_free(&nxt);
					goto oom;
				}
			}
			nbr_list_free(&nbrs);
			if (out->n >= AIK_PPR_NODE_CAP)
				break;
		}
		cstr_vec_free(&frontier);
		frontier = nxt;
		if (frontier.n == 0)
			break;
	}
	rc = 0;
	goto done;
oom:
	set_err(err, errlen, "out of memory");
done:
	cstr_vec_free(&seen);
	cstr_vec_free(&frontier);
	if (rc != 0)
		cstr_vec_free(out);
	return rc;
}

/* 加权无向邻接（同一对节点的平行边累加；插入序保留） */
struct adj_nbr {
	const char *id;
	double w;
};

struct adj_node {
	const char *id;
	struct adj_nbr *nbrs;
	size_t n;
	size_t cap;
};

struct adj_graph {
	struct adj_node *nodes;
	size_t n;
};

static void adj_graph_free(struct adj_graph *g)
{
	size_t i;

	if (!g)
		return;
	for (i = 0; i < g->n; i++)
		free(g->nodes[i].nbrs);
	free(g->nodes);
	g->nodes = NULL;
	g->n = 0;
}

static size_t adj_find(const struct adj_graph *g, const char *id)
{
	size_t i;

	for (i = 0; i < g->n; i++)
		if (strcmp(g->nodes[i].id, id) == 0)
			return i;
	return (size_t)-1;
}

static int adj_add(struct adj_node *node, const char *id, double w)
{
	struct adj_nbr *grown;
	size_t i;

	for (i = 0; i < node->n; i++)
		if (strcmp(node->nbrs[i].id, id) == 0) {
			node->nbrs[i].w += w;
			return 0;
		}
	if (node->n == node->cap) {
		size_t cap = node->cap ? node->cap * 2 : 8;

		grown = realloc(node->nbrs, cap * sizeof(*grown));
		if (!grown)
			return -1;
		node->nbrs = grown;
		node->cap = cap;
	}
	node->nbrs[node->n].id = id;
	node->nbrs[node->n].w = w;
	node->n++;
	return 0;
}

struct exp_item {
	const aik_memory_view *m;
	double factor;
};

struct dep_entry {
	const char *id;
	int depth;
};

struct dep_list {
	struct dep_entry *items;
	size_t n;
	size_t cap;
};

static void dep_list_free(struct dep_list *l)
{
	free(l->items);
	l->items = NULL;
	l->n = 0;
	l->cap = 0;
}

static int dep_list_push(struct dep_list *l, const char *id, int depth)
{
	struct dep_entry *grown;

	if (l->n == l->cap) {
		size_t cap = l->cap ? l->cap * 2 : 16;

		grown = realloc(l->items, cap * sizeof(*grown));
		if (!grown)
			return -1;
		l->items = grown;
		l->cap = cap;
	}
	l->items[l->n].id = id;
	l->items[l->n].depth = depth;
	l->n++;
	return 0;
}

/*
 * 扩展候选统一走同一套 hybrid + ranker 管线；factor 是路径衰减
 * （PPR: 0.5*ppr/peak；BFS: 0.5**depth），summary 惩罚再乘。
 */
static int build_expanded_hits(struct aik_retriever *r,
			       const aik_search_ctx *ctx,
			       const aik_retrieval_config *cfg,
			       const aik_search_query *q,
			       const struct rs_map *rs,
			       const struct exp_item *items, size_t n,
			       aik_search_hit **out, char *err, size_t errlen)
{
	const aik_memory_view **mems = NULL;
	double *vs = NULL;
	double *ks = NULL;
	unsigned char *mm = NULL;
	aik_search_hit *hits = NULL;
	double vw, kw, mw;
	size_t i;
	int rc = -1;

	*out = NULL;
	if (n == 0)
		return 0;
	mems = malloc(n * sizeof(*mems));
	vs = malloc(n * sizeof(*vs));
	ks = malloc(n * sizeof(*ks));
	mm = malloc(n);
	hits = calloc(n, sizeof(*hits));
	if (!mems || !vs || !ks || !mm || !hits) {
		set_err(err, errlen, "out of memory");
		goto done;
	}
	for (i = 0; i < n; i++)
		mems[i] = items[i].m;
	if (compute_vector_scores(ctx, cfg, mems, n, vs, err, errlen) != 0)
		goto done;
	if (compute_keyword_scores(r, cfg, q->text, mems, n, ks, err,
				   errlen) != 0)
		goto done;
	channel_weights(cfg, &vw, &kw, &mw);
	for (i = 0; i < n; i++) {
		const aik_memory_view *m = mems[i];
		const char *rid =
			ctx->space ? aik_space_region_for(ctx->space, m->id) :
				     NULL;
		double region_score = cfg->region_dampening;
		double meta = metadata_matches(m, q->metadata_filters) ? 1.0 :
									0.0;
		double hybrid = vw * vs[i] + kw * ks[i] + mw * meta;
		aik_rank_result rr;
		double final;

		(void)rs_get(rs, rid ? rid : "", &region_score);
		if (aik_rank_score(ctx->weights, ctx->decay, m, region_score,
				   ctx->reference, 1, hybrid, 0, &rr) != 0) {
			set_err(err, errlen, "aik_rank_score failed");
			goto done;
		}
		final = rr.score * items[i].factor;
		if (m->source && strcmp(m->source, "summary") == 0)
			final *= cfg->summary_penalty;
		if (init_hit(&hits[i], m, final, rid, region_score, ks[i],
			     vs[i], meta > 0.0) != 0) {
			size_t k;

			for (k = 0; k < i; k++)
				free_hit(&hits[k]);
			set_err(err, errlen, "out of memory");
			goto done;
		}
	}
	qsort(hits, n, sizeof(*hits), cmp_hit_score);
	*out = hits;
	hits = NULL;
	rc = 0;
done:
	if (hits) {
		for (i = 0; i < n; i++)
			free_hit(&hits[i]);
	}
	free(hits);
	free(mems);
	free(vs);
	free(ks);
	free(mm);
	return rc;
}

/* BFS 退化路径（retriever.py:524-636） */
static int bfs_expand(struct aik_retriever *r, const aik_search_ctx *ctx,
		      const aik_search_query *q,
		      const aik_retrieval_config *cfg,
		      aik_search_hit *scored, size_t n_scored,
		      const struct hit_ref *top, size_t n_top,
		      const struct mem_index *mi, const struct rs_map *rs,
		      struct hit_ref **out_refs, size_t *out_n_refs,
		      aik_search_hit **out_exp, size_t *out_n_exp,
		      char *err, size_t errlen)
{
	struct cstr_vec included;
	struct cstr_vec seen;
	struct cstr_vec frontier;
	struct dep_list expanded;
	struct exp_item *items = NULL;
	aik_search_hit *hits = NULL;
	struct hit_ref *refs = NULL;
	size_t n_hits = 0;
	size_t cap;
	int depth_r;
	int rc = -1;

	*out_refs = NULL;
	*out_n_refs = 0;
	*out_exp = NULL;
	*out_n_exp = 0;
	memset(&included, 0, sizeof(included));
	memset(&seen, 0, sizeof(seen));
	memset(&frontier, 0, sizeof(frontier));
	memset(&expanded, 0, sizeof(expanded));
	cap = q->top_k > 0 ? (size_t)q->top_k * 6 : 30;
	if (cap < 30)
		cap = 30;
	for (size_t i = 0; i < n_top; i++) {
		if (cstr_vec_push(&included, top[i].h->memory_id) != 0)
			goto oom;
	}
	if (cstr_vec_copy(&seen, &included) != 0 ||
	    cstr_vec_copy(&frontier, &included) != 0)
		goto oom;
	for (depth_r = 1; depth_r <= q->graph_expand; depth_r++) {
		struct cstr_vec nxt;
		size_t i;

		memset(&nxt, 0, sizeof(nxt));
		if (expanded.n >= cap) {
			cstr_vec_free(&nxt);
			break;
		}
		for (i = 0; i < frontier.n; i++) {
			struct nbr_list nbrs;
			size_t j;

			if (neighbors_collect(ctx, frontier.items[i], 0, &nbrs,
					      err, errlen) != 0) {
				cstr_vec_free(&nxt);
				goto done;
			}
			for (j = 0; j < nbrs.n; j++) {
				const char *nb = nbrs.ids[j];
				const aik_memory_view *m;

				if (cstr_vec_contains(&seen, nb))
					continue;
				m = mem_find(mi, nb);
				if (!m)
					continue;
				if (m->archived && !q->include_archived) {
					/* archived 只进 seen：不出现、不中继 */
					if (cstr_vec_push(&seen, nb) != 0) {
						nbr_list_free(&nbrs);
						cstr_vec_free(&nxt);
						goto oom;
					}
					continue;
				}
				if (cstr_vec_push(&seen, nb) != 0 ||
				    dep_list_push(&expanded, nb, depth_r) != 0 ||
				    cstr_vec_push(&nxt, nb) != 0) {
					nbr_list_free(&nbrs);
					cstr_vec_free(&nxt);
					goto oom;
				}
				if (expanded.n >= cap)
					break;
			}
			nbr_list_free(&nbrs);
			if (expanded.n >= cap)
				break;
		}
		cstr_vec_free(&frontier);
		frontier = nxt;
		if (frontier.n == 0)
			break;
	}
	if (expanded.n > 0) {
		size_t i;
		size_t n_new = 0;

		items = malloc(expanded.n * sizeof(*items));
		if (!items)
			goto oom;
		for (i = 0; i < expanded.n; i++) {
			const aik_memory_view *m = mem_find(mi,
							    expanded.items[i].id);

			if (!m || !visible(ctx, q, m))
				continue;
			items[n_new].m = m;
			items[n_new].factor = pow(0.5, (double)expanded.items[i].depth);
			n_new++;
		}
		if (n_new > 0) {
			if (build_expanded_hits(r, ctx, cfg, q, rs, items,
						n_new, &hits, err, errlen) != 0)
				goto done;
			n_hits = n_new;
		}
	}
	if (n_hits == 0) {
		/* Python: if not hits: return scored[:top_k] */
		rc = copy_refs(top, n_top, &refs);
		if (rc != 0) {
			set_err(err, errlen, "out of memory");
			goto done;
		}
		*out_refs = refs;
		*out_n_refs = n_top;
		refs = NULL;
		rc = 0;
		goto done;
	}
	{
		size_t reserved = (size_t)(q->top_k / 5);
		size_t prefix;
		size_t merged_n = 0;
		size_t i;

		if (reserved < 1)
			reserved = 1;
		{
			size_t max_reserved =
				q->top_k > 0 ? (size_t)(q->top_k - 1) : 0;

			if (reserved > max_reserved)
				reserved = max_reserved;
		}
		prefix = (size_t)q->top_k - reserved;
		if (prefix > n_scored)
			prefix = n_scored;
		merged_n = prefix;
		if (reserved > n_hits)
			reserved = n_hits;
		merged_n += reserved;
		refs = malloc(merged_n * sizeof(*refs));
		if (merged_n > 0 && !refs)
			goto oom;
		for (i = 0; i < prefix; i++)
			refs[i].h = &scored[i];
		for (i = 0; i < reserved; i++)
			refs[prefix + i].h = &hits[i];
		if (merged_n > 1)
			qsort(refs, merged_n, sizeof(*refs), cmp_hit_ref);
		*out_refs = refs;
		*out_n_refs = merged_n > (size_t)q->top_k ?
				      (size_t)q->top_k :
				      merged_n;
		refs = NULL;
	}
	*out_exp = hits;
	*out_n_exp = n_hits;
	hits = NULL;
	rc = 0;
	goto done;
oom:
	set_err(err, errlen, "out of memory");
done:
	free(items);
	if (hits) {
		size_t i;

		for (i = 0; i < n_hits; i++)
			free_hit(&hits[i]);
		free(hits);
	}
	free(refs);
	cstr_vec_free(&included);
	cstr_vec_free(&seen);
	cstr_vec_free(&frontier);
	dep_list_free(&expanded);
	return rc;
}

/* PPR 主路（retriever.py:639-780） */
static int ppr_expand(struct aik_retriever *r, const aik_search_ctx *ctx,
		      const aik_search_query *q,
		      const aik_retrieval_config *cfg,
		      aik_search_hit *scored, size_t n_scored,
		      const struct hit_ref *top, size_t n_top,
		      const struct mem_index *mi, const struct rs_map *rs,
		      struct hit_ref **out_refs, size_t *out_n_refs,
		      aik_search_hit **out_exp, size_t *out_n_exp,
		      char *err, size_t errlen)
{
	struct cstr_vec seeds;
	struct cstr_vec nodes;
	struct cstr_vec included;
	struct cstr_vec cand;
	struct adj_graph adj;
	struct exp_item *items = NULL;
	aik_search_hit *hits = NULL;
	struct hit_ref *refs = NULL;
	double *seed_w = NULL;
	double *p = NULL;
	double *ppr = NULL;
	size_t *src = NULL;
	size_t *dst = NULL;
	double *prob = NULL;
	size_t n_hits = 0;
	size_t n_trans = 0;
	size_t n_used = 0;
	size_t total = 0;
	size_t i;
	int rc = -1;

	*out_refs = NULL;
	*out_n_refs = 0;
	*out_exp = NULL;
	*out_n_exp = 0;
	memset(&seeds, 0, sizeof(seeds));
	memset(&nodes, 0, sizeof(nodes));
	memset(&included, 0, sizeof(included));
	memset(&cand, 0, sizeof(cand));
	memset(&adj, 0, sizeof(adj));

	if (n_top == 0) {
		rc = copy_refs(top, n_top, &refs);
		if (rc != 0) {
			set_err(err, errlen, "out of memory");
			goto done;
		}
		*out_refs = refs;
		refs = NULL;
		*out_n_refs = n_top;
		rc = 0;
		goto done;
	}
	/* seed 权重 = direct hit 的 hybrid（hit 里通道分是 round 4 后的值） */
	seed_w = calloc(n_top, sizeof(*seed_w));
	if (!seed_w)
		goto oom;
	for (i = 0; i < n_top; i++) {
		const aik_search_hit *h = top[i].h;
		double vw, kw, mw;
		double hybrid;

		channel_weights(cfg, &vw, &kw, &mw);
		hybrid = vw * h->vector_score + kw * h->keyword_score +
			 mw * (h->metadata_match ? 1.0 : 0.0);
		if (hybrid < 0.0)
			hybrid = 0.0;
		seed_w[i] = hybrid;
		total += hybrid;
	}
	if (total <= 0.0) {
		for (i = 0; i < n_top; i++)
			seed_w[i] = 1.0;
		total = n_top;
	}
	/* seeds 顺序：(weight desc, memory_id asc)。设计 §3.5 约定 */
	{
		size_t *order = malloc(n_top * sizeof(*order));

		if (!order)
			goto oom;
		for (i = 0; i < n_top; i++)
			order[i] = i;
		/* 插入排序：n_top <= top_k，规模很小 */
		for (i = 1; i < n_top; i++) {
			size_t key = order[i];
			size_t j = i;

			while (j > 0) {
				size_t prev = order[j - 1];
				int less;

				if (seed_w[key] > seed_w[prev])
					less = 1;
				else if (seed_w[key] < seed_w[prev])
					less = 0;
				else
					less = strcmp(top[key].h->memory_id,
						       top[prev].h->memory_id) < 0;
				if (!less)
					break;
				order[j] = prev;
				j--;
			}
			order[j] = key;
		}
		for (i = 0; i < n_top; i++) {
			if (cstr_vec_push(&seeds,
					  top[order[i]].h->memory_id) != 0) {
				free(order);
				goto oom;
			}
		}
		free(order);
	}
	if (ppr_subgraph(ctx, q, &seeds, mi, &nodes, err, errlen) != 0)
		goto done;
	if (nodes.n == 0) {
		rc = copy_refs(top, n_top, &refs);
		if (rc != 0) {
			set_err(err, errlen, "out of memory");
			goto done;
		}
		*out_refs = refs;
		refs = NULL;
		*out_n_refs = n_top;
		rc = 0;
		goto done;
	}
	/* 子图邻接：按 edges 数组顺序双向累加，n_edges 是边对象数 */
	adj.nodes = calloc(nodes.n, sizeof(*adj.nodes));
	if (!adj.nodes)
		goto oom;
	adj.n = nodes.n;
	for (i = 0; i < nodes.n; i++)
		adj.nodes[i].id = nodes.items[i];
	for (i = 0; i < ctx->n_edges; i++) {
		const aik_graph_edge *e = &ctx->edges[i];
		size_t si;
		size_t di;
		double w;

		if (!e->source || !e->target)
			continue;
		si = adj_find(&adj, e->source);
		di = adj_find(&adj, e->target);
		if (si == (size_t)-1 || di == (size_t)-1)
			continue;
		w = e->weight > 0.0 ? e->weight : 0.0;
		if (adj_add(&adj.nodes[si], e->target, w) != 0 ||
		    adj_add(&adj.nodes[di], e->source, w) != 0)
			goto oom;
		n_used++;
	}
	if (n_used < AIK_PPR_MIN_EDGES) {
		int brc;

		brc = bfs_expand(r, ctx, q, cfg, scored, n_scored, top, n_top,
				 mi, rs, out_refs, out_n_refs, out_exp,
				 out_n_exp, err, errlen);
		rc = brc;
		goto done;
	}
	p = calloc(nodes.n, sizeof(*p));
	if (!p)
		goto oom;
	for (i = 0; i < n_top; i++) {
		size_t idx = cstr_vec_index(&nodes, top[i].h->memory_id);

		if (idx != (size_t)-1)
			p[idx] += seed_w[i] / (double)total;
	}
	for (i = 0; i < adj.n; i++)
		n_trans += adj.nodes[i].n;
	src = malloc(n_trans * sizeof(*src));
	dst = malloc(n_trans * sizeof(*dst));
	prob = malloc(n_trans * sizeof(*prob));
	ppr = malloc(nodes.n * sizeof(*ppr));
	if ((n_trans > 0 && (!src || !dst || !prob)) || !ppr)
		goto oom;
	n_trans = 0;
	for (i = 0; i < adj.n; i++) {
		const struct adj_node *node = &adj.nodes[i];
		double wsum = 0.0;
		size_t j;

		if (node->n == 0)
			continue;
		for (j = 0; j < node->n; j++)
			wsum += node->nbrs[j].w;
		for (j = 0; j < node->n; j++) {
			size_t di = adj_find(&adj, node->nbrs[j].id);

			src[n_trans] = i;
			dst[n_trans] = di;
			prob[n_trans] = wsum > 0.0 ?
						node->nbrs[j].w / wsum :
						1.0 / (double)node->n;
			n_trans++;
		}
	}
	if (aik_ppr_rank(nodes.n, p, src, dst, prob, n_trans, ppr) != 0) {
		set_err(err, errlen, "aik_ppr_rank failed");
		goto done;
	}
	/* 扩展候选 = 子图内不在 direct top 且 ppr>0 的可见记忆 */
	for (i = 0; i < n_top; i++)
		if (cstr_vec_push(&included, top[i].h->memory_id) != 0)
			goto oom;
	for (i = 0; i < nodes.n; i++)
		if (!cstr_vec_contains(&included, nodes.items[i]) &&
		    ppr[i] > 0.0)
			if (cstr_vec_push(&cand, nodes.items[i]) != 0)
				goto oom;
	{
		size_t n_new = 0;
		double peak = 0.0;

		items = malloc(cand.n * sizeof(*items));
		if (cand.n > 0 && !items)
			goto oom;
		for (i = 0; i < cand.n; i++) {
			const aik_memory_view *m = mem_find(mi, cand.items[i]);
			size_t idx;

			if (!m || !visible(ctx, q, m))
				continue;
			idx = cstr_vec_index(&nodes, cand.items[i]);
			if (idx == (size_t)-1)
				continue;
			items[n_new].m = m;
			items[n_new].factor = ppr[idx];
			if (ppr[idx] > peak)
				peak = ppr[idx];
			n_new++;
		}
		if (n_new == 0) {
			rc = copy_refs(top, n_top, &refs);
			if (rc != 0) {
				set_err(err, errlen, "out of memory");
				goto done;
			}
			*out_refs = refs;
			refs = NULL;
			*out_n_refs = n_top;
			rc = 0;
			goto done;
		}
		for (i = 0; i < n_new; i++)
			items[i].factor = 0.5 * items[i].factor / peak;
		if (build_expanded_hits(r, ctx, cfg, q, rs, items, n_new,
					&hits, err, errlen) != 0)
			goto done;
		n_hits = n_new;
	}
	{
		size_t reserved = (size_t)(q->top_k / 5);
		size_t prefix;
		size_t merged_n = 0;

		if (reserved < 1)
			reserved = 1;
		{
			size_t max_reserved =
				q->top_k > 0 ? (size_t)(q->top_k - 1) : 0;

			if (reserved > max_reserved)
				reserved = max_reserved;
		}
		prefix = (size_t)q->top_k - reserved;
		if (prefix > n_scored)
			prefix = n_scored;
		merged_n = prefix;
		if (reserved > n_hits)
			reserved = n_hits;
		merged_n += reserved;
		refs = malloc(merged_n * sizeof(*refs));
		if (merged_n > 0 && !refs)
			goto oom;
		for (i = 0; i < prefix; i++)
			refs[i].h = &scored[i];
		for (i = 0; i < reserved; i++)
			refs[prefix + i].h = &hits[i];
		if (merged_n > 1)
			qsort(refs, merged_n, sizeof(*refs), cmp_hit_ref);
		*out_refs = refs;
		*out_n_refs = merged_n > (size_t)q->top_k ?
				      (size_t)q->top_k :
				      merged_n;
		refs = NULL;
	}
	*out_exp = hits;
	*out_n_exp = n_hits;
	hits = NULL;
	rc = 0;
	goto done;
oom:
	set_err(err, errlen, "out of memory");
done:
	free(seed_w);
	free(p);
	free(ppr);
	free(src);
	free(dst);
	free(prob);
	free(items);
	if (hits) {
		for (i = 0; i < n_hits; i++)
			free_hit(&hits[i]);
		free(hits);
	}
	free(refs);
	adj_graph_free(&adj);
	cstr_vec_free(&seeds);
	cstr_vec_free(&nodes);
	cstr_vec_free(&included);
	cstr_vec_free(&cand);
	return rc;
}

/* ------------------------------------------------------------------ */
/* 配置                                                                */
/* ------------------------------------------------------------------ */
static void config_defaults(aik_retrieval_config *c)
{
	c->top_regions = 3;
	c->top_k = 10;
	c->vector_weight = 0.60;
	c->keyword_weight = 0.30;
	c->metadata_weight = 0.10;
	c->region_dampening = 0.10;
	c->summary_penalty = 0.5;
	c->cjk_bigram = 1;
	c->candidate_window = 20;
	c->fusion = AIK_FUSION_MINMAX;
	c->keyword_candidates = 0;
}

aik_retriever *aik_retriever_new(const aik_retrieval_config *cfg, char *err,
				 size_t errlen)
{
	aik_retriever *r;

	r = calloc(1, sizeof(*r));
	if (!r) {
		set_err(err, errlen, "out of memory");
		return NULL;
	}
	if (cfg)
		r->cfg = *cfg;
	else
		config_defaults(&r->cfg);
	r->bm25 = aik_bm25_new(1.5, 0.75, r->cfg.cjk_bigram, err, errlen);
	if (!r->bm25) {
		free(r);
		return NULL;
	}
	return r;
}

void aik_retriever_free(aik_retriever *r)
{
	if (!r)
		return;
	aik_bm25_free(r->bm25);
	free(r);
}

int aik_retriever_index(aik_retriever *r, const aik_memory_view *mems,
			size_t n, char *err, size_t errlen)
{
	aik_bm25 *ix;
	size_t i;

	if (!r) {
		set_err(err, errlen, "aik_retriever_index: retriever is NULL");
		return -1;
	}
	ix = aik_bm25_new(1.5, 0.75, r->cfg.cjk_bigram, err, errlen);
	if (!ix)
		return -1;
	for (i = 0; i < n; i++) {
		if (mems[i].archived)
			continue;
		if (!mems[i].id)
			continue;
		if (aik_bm25_add(ix, mems[i].id,
				 mems[i].text ? mems[i].text : "", err,
				 errlen) != 0) {
			aik_bm25_free(ix);
			return -1;
		}
	}
	aik_bm25_free(r->bm25);
	r->bm25 = ix;
	return 0;
}

void aik_search_hits_free(aik_search_hit *hits, size_t n)
{
	size_t i;

	if (!hits)
		return;
	for (i = 0; i < n; i++)
		free_hit(&hits[i]);
	free(hits);
}

/* ------------------------------------------------------------------ */
/* 主检索（retriever.py:304-498）                                      */
/* ------------------------------------------------------------------ */
int aik_retriever_search(aik_retriever *r, const aik_search_ctx *ctx,
			 const aik_search_query *q, aik_search_hit **out,
			 size_t *n_out, char *err, size_t errlen)
{
	const aik_retrieval_config *cfg;
	struct mem_index mi;
	struct rs_map rs;
	struct str_vec cand;
	const aik_memory_view **cands = NULL;
	double *vscore = NULL;
	double *kscore = NULL;
	unsigned char *mmeta = NULL;
	aik_search_hit *scored = NULL;
	struct hit_ref *top = NULL;
	struct hit_ref *merged = NULL;
	aik_search_hit *expanded = NULL;
	size_t n_expanded = 0;
	size_t n_cands = 0;
	size_t n_scored = 0;
	size_t n_top = 0;
	size_t n_merged;
	aik_region_hit *rhits = NULL;
	size_t n_rhits = 0;
	int has_filters;
	int k_regions;
	int rc = -1;
	size_t i;
	size_t j;

	if (out)
		*out = NULL;
	if (n_out)
		*n_out = 0;
	if (!r || !ctx || !q || !out || !n_out || !ctx->query_vector ||
	    !ctx->weights || !ctx->decay) {
		set_err(err, errlen, "aik_retriever_search: invalid argument");
		return -1;
	}
	cfg = ctx->cfg ? ctx->cfg : &r->cfg;
	if (q->top_k <= 0)
		return 0;
	if (ctx->dim <= 0) {
		set_err(err, errlen, "aik_retriever_search: invalid dim");
		return -1;
	}
	if (mem_index_build(&mi, ctx->memories, ctx->n_memories, err,
			    errlen) != 0)
		return -1;
	memset(&rs, 0, sizeof(rs));
	memset(&cand, 0, sizeof(cand));

	/* 阶段 1：显式 query 值 > region_retrieval > config */
	if (q->top_regions >= 0)
		k_regions = q->top_regions;
	else if (q->region_retrieval > 0)
		k_regions = q->region_retrieval;
	else
		k_regions = cfg->top_regions;
	has_filters = (q->metadata_filters &&
		       aik_json_typeof(q->metadata_filters) == AIK_JSON_OBJ &&
		       aik_json_count(q->metadata_filters) > 0) ||
		      (q->tags && q->n_tags > 0);
	if (ctx->space) {
		if (aik_space_query_regions(ctx->space, ctx->query_vector,
					    k_regions, &rhits, &n_rhits, err,
					    errlen) != 0)
			goto done;
	}
	for (i = 0; i < n_rhits; i++) {
		const aik_region *reg = rhits[i].region;
		const char *rid = aik_region_id(reg);

		if (!rid)
			continue;
		if (rs_setdefault(&rs, rid, rhits[i].score) != 0)
			goto oom;
	}
	for (i = 0; i < n_rhits; i++) {
		const aik_region *reg = rhits[i].region;
		size_t nm = aik_region_size(reg);

		for (j = 0; j < nm; j++) {
			const char *mid = aik_region_member(reg, j);

			if (!mid)
				continue;
			if (has_filters) {
				const aik_memory_view *m = mem_find(&mi, mid);

				if (!m)
					continue;
				if (!metadata_matches(m, q->metadata_filters))
					continue;
				if (!tags_match(m, q->tags, q->n_tags))
					continue;
			}
			if (str_vec_push(&cand, mid) != 0)
				goto oom;
		}
	}

	/* 全局补池：pool_target = max(top_k*2, candidate_window) */
	{
		int pool_target = q->top_k * 2;

		if (cfg->candidate_window > pool_target)
			pool_target = cfg->candidate_window;
		if (pool_target > 0 && cand.n < (size_t)pool_target) {
			size_t budget = (size_t)pool_target - cand.n;
			const aik_memory_view **pool = NULL;
			double *sims = NULL;
			struct {
				double sim;
				size_t idx;
			} *order = NULL;
			size_t np = 0;
			size_t taken = 0;

			if (ctx->n_memories > 0) {
				pool = malloc(ctx->n_memories *
					      sizeof(*pool));
				if (!pool)
					goto oom;
			}
			for (i = 0; i < ctx->n_memories; i++) {
				const aik_memory_view *m = &ctx->memories[i];

				if (!m->id)
					continue;
				if (str_vec_contains(&cand, m->id))
					continue;
				if (m->archived && !q->include_archived)
					continue;
				if (!policy_allows(ctx, m) &&
				    !q->include_archived)
					continue;
				if (!m->embedding)
					continue;
				if (has_filters &&
				    (!metadata_matches(m,
						       q->metadata_filters) ||
				     !tags_match(m, q->tags, q->n_tags)))
					continue;
				pool[np++] = m;
			}
			if (np > 0) {
				sims = malloc(np * sizeof(*sims));
				order = malloc(np * sizeof(*order));
				if (!sims || !order) {
					free(pool);
					free(sims);
					free(order);
					goto oom;
				}
				/* 补池 mat 行归一、query 原样（retriever.py:386-388） */
				for (i = 0; i < np; i++) {
					double en = vec_norm(pool[i]->embedding,
							     ctx->dim);
					double ed = en > 1e-12 ? en : 1e-12;
					double s = 0.0;
					int k;

					for (k = 0; k < ctx->dim; k++)
						s += (pool[i]->embedding[k] /
						      ed) *
						     ctx->query_vector[k];
					sims[i] = s;
					order[i].sim = s;
					order[i].idx = i;
				}
				/* stable (sim asc, index asc) 后反向遍历；
				 * 插入排序保证同分按池内出现序（后者优先）
				 */
				for (i = 1; i < np; i++) {
					double key_sim = sims[i];
					size_t key_idx = i;
					size_t k = i;

					while (k > 0) {
						double ps = order[k - 1].sim;
						int less;

						if (key_sim < ps)
							less = 1;
						else if (key_sim > ps)
							less = 0;
						else
							less = key_idx <
							     order[k - 1].idx;
						if (!less)
							break;
						order[k] = order[k - 1];
						k--;
					}
					order[k].sim = key_sim;
					order[k].idx = key_idx;
				}
				for (i = np; i > 0 && taken < budget; i--) {
					const aik_memory_view *m =
						pool[order[i - 1].idx];
					const char *rid = ctx->space ?
						aik_space_region_for(
							ctx->space, m->id) :
						NULL;

					if (str_vec_push(&cand, m->id) != 0)
						goto oom;
					if (rs_setdefault(&rs, rid ? rid : "",
							  cfg->region_dampening) !=
					    0)
						goto oom;
					taken++;
				}
			}
			free(pool);
			free(sims);
			free(order);
		}
	}

	/* BM25 全局召回 */
	if (cfg->keyword_candidates > 0 && cfg->keyword_weight > 0.0 &&
	    r->bm25) {
		const char **allowed = NULL;
		size_t n_allowed = 0;
		char **top_ids = NULL;
		size_t n_top_ids = 0;

		if (ctx->n_memories > 0) {
			allowed = malloc(ctx->n_memories *
					 sizeof(*allowed));
			if (!allowed)
				goto oom;
		}
		for (i = 0; i < ctx->n_memories; i++) {
			const aik_memory_view *m = &ctx->memories[i];

			if (!m->id)
				continue;
			if (!visible(ctx, q, m))
				continue;
			allowed[n_allowed++] = m->id;
		}
		if (n_allowed > 0) {
			if (aik_bm25_top(r->bm25, q->text ? q->text : "",
					 (size_t)cfg->keyword_candidates,
					 allowed, n_allowed, &top_ids,
					 &n_top_ids, err, errlen) != 0) {
				free(allowed);
				goto done;
			}
		}
		for (i = 0; i < n_top_ids; i++) {
			const char *mid = top_ids[i];
			const char *rid = ctx->space ?
				aik_space_region_for(ctx->space, mid) : NULL;

			if (str_vec_push(&cand, mid) != 0) {
				free(top_ids);
				free(allowed);
				goto oom;
			}
			if (rs_setdefault(&rs, rid ? rid : "",
					  cfg->region_dampening) != 0) {
				free(top_ids);
				free(allowed);
				goto oom;
			}
		}
		free(top_ids);
		free(allowed);
	}

	if (cand.n == 0)
		goto empty;

	/* 候选过滤：archived/policy -> metadata/tags */
	cands = malloc(cand.n * sizeof(*cands));
	vscore = calloc(cand.n, sizeof(*vscore));
	kscore = calloc(cand.n, sizeof(*kscore));
	mmeta = calloc(cand.n, sizeof(*mmeta));
	if (!cands || !vscore || !kscore || !mmeta)
		goto oom;
	for (i = 0; i < cand.n; i++) {
		const aik_memory_view *m = mem_find(&mi, cand.items[i]);

		if (!m)
			continue;
		if (!visible(ctx, q, m))
			continue;
		cands[n_cands++] = m;
	}
	if (n_cands == 0)
		goto empty;
	if (compute_vector_scores(ctx, cfg, cands, n_cands, vscore, err,
				  errlen) != 0)
		goto done;
	if (compute_keyword_scores(r, cfg, q->text, cands, n_cands, kscore,
				   err, errlen) != 0)
		goto done;
	for (i = 0; i < n_cands; i++)
		mmeta[i] = metadata_matches(cands[i], q->metadata_filters) ? 1 :
									 0;

	/* hybrid -> ranker(detailed=0)；summary 惩罚作用在 score 上 */
	scored = calloc(n_cands, sizeof(*scored));
	if (!scored)
		goto oom;
	{
		double vw, kw, mw;

		channel_weights(cfg, &vw, &kw, &mw);
		for (i = 0; i < n_cands; i++) {
			const aik_memory_view *m = cands[i];
			const char *rid = ctx->space ?
				aik_space_region_for(ctx->space, m->id) : NULL;
			double region_score = 0.0;
			double meta = mmeta[i] ? 1.0 : 0.0;
			double hybrid;
			aik_rank_result rr;
			double final;

			(void)rs_get(&rs, rid ? rid : "", &region_score);
			hybrid = vw * vscore[i] + kw * kscore[i] + mw * meta;
			if (aik_rank_score(ctx->weights, ctx->decay, m,
					   region_score, ctx->reference, 1,
					   hybrid, 0, &rr) != 0) {
				set_err(err, errlen, "aik_rank_score failed");
				goto done;
			}
			final = rr.score;
			if (m->source && strcmp(m->source, "summary") == 0)
				final *= cfg->summary_penalty;
			if (init_hit(&scored[i], m, final, rid, region_score,
				     kscore[i], vscore[i], mmeta[i]) != 0)
				goto oom;
			n_scored++;
		}
	}
	qsort(scored, n_scored, sizeof(*scored), cmp_hit_score);
	n_top = n_scored < (size_t)q->top_k ? n_scored : (size_t)q->top_k;
	top = malloc(n_top * sizeof(*top));
	if (n_top > 0 && !top)
		goto oom;
	for (i = 0; i < n_top; i++)
		top[i].h = &scored[i];
	n_merged = n_top;
	merged = top;
	top = NULL;

	/* 图扩展 */
	if (q->graph_expand > 0 && ctx->n_edges > 0 && n_merged > 0) {
		struct hit_ref *new_refs = NULL;
		size_t new_n = 0;

		if (ppr_expand(r, ctx, q, cfg, scored, n_scored, merged,
			       n_merged, &mi, &rs, &new_refs, &new_n,
			       &expanded, &n_expanded, err, errlen) != 0) {
			free(merged);
			merged = NULL;
			goto done;
		}
		free(merged);
		merged = new_refs;
		n_merged = new_n;
	}

	if (n_merged == 0)
		goto empty;

	/* 仅最终 top-k 重算 detailed breakdown */
	{
		double vw, kw, mw;

		channel_weights(cfg, &vw, &kw, &mw);
		for (i = 0; i < n_merged; i++) {
			aik_search_hit *h = merged[i].h;
			const aik_memory_view *m = mem_find(&mi, h->memory_id);
			double meta = h->metadata_match ? 1.0 : 0.0;
			double hybrid;
			aik_rank_result rr;

			if (!m) {
				set_err(err, errlen, "internal: hit memory lost");
				goto done;
			}
			hybrid = vw * h->vector_score + kw * h->keyword_score +
				 mw * meta;
			if (aik_rank_score(ctx->weights, ctx->decay, m,
					   h->region_score, ctx->reference, 1,
					   hybrid, 1, &rr) != 0) {
				set_err(err, errlen, "aik_rank_score failed");
				goto done;
			}
			h->breakdown = rr.breakdown;
			if (m->source && strcmp(m->source, "summary") == 0)
				h->breakdown.final *= cfg->summary_penalty;
		}
	}
	{
		aik_search_hit *outarr = calloc(n_merged, sizeof(*outarr));

		if (!outarr)
			goto oom;
		for (i = 0; i < n_merged; i++) {
			outarr[i] = *merged[i].h;
			merged[i].h->memory_id = NULL;
			merged[i].h->region_id = NULL;
		}
		*out = outarr;
		*n_out = n_merged;
	}
	rc = 0;
	goto done;
empty:
	rc = 0;
	goto done;
oom:
	set_err(err, errlen, "out of memory");
done:
	if (scored) {
		for (i = 0; i < n_cands; i++)
			free_hit(&scored[i]);
	}
	free(scored);
	if (expanded) {
		for (i = 0; i < n_expanded; i++)
			free_hit(&expanded[i]);
	}
	free(expanded);
	free(merged);
	free(top);
	free(cands);
	free(vscore);
	free(kscore);
	free(mmeta);
	free(rhits);
	str_vec_free(&cand);
	rs_free(&rs);
	mem_index_free(&mi);
	return rc;
}
