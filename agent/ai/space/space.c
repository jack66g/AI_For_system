/* SPDX-License-Identifier: GPL-2.0 */
/*
 * space.c - Spatial Memory Space 生命周期（对齐 sme/space/space.py 与
 * sme/space/region_manager.py，REF-PY e72bc75 / SME 1.3.0）
 *
 * 语义要点（逐条见 T3B-DESIGN.md §2.1-2.7）：
 *   - Region 按创建序保存（dict 语义），成员按加入序保存；
 *   - insert 幂等 guard：已有向量且 membership 指向存活 Region 时只刷新向量；
 *   - 加入成员走增量质心 + mark_stale，消费方 sync_geometry 才全量重算；
 *   - split 5/3（相等取 A）、merge keeper=较大者、close 边合并与 _merge_ops
 *     滞后窗口（write_ops - merge_ops >= 4*evolve_interval）；
 *   - update_edges_for 先 sync，再删两端涉事旧边，最后逐 Region 重算；
 *   - 所有 id 都是本 space 自增生成，无全局状态。
 *
 * 一致性：除 history_push 失败这种 OOM 情形外，所有函数在失败时尽量保持
 * 结构可继续使用；错误一律写 err（可为 NULL）。
 */
#include "../include/space/space.h"

#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* region.c 内部构造/几何 + 本文件对 space_load.c 暴露的最小内部接口 */
#include "space_internal.h"

/* ------------------------------------------------------------------ */
/* 常量与内部类型                                                     */
/* ------------------------------------------------------------------ */
#define AIK_HISTORY_CAP 500
#define AIK_MAX_EVOLVE_ACTIONS 8
#define AIK_FULL_TABLE 0xffffffffffffffffULL

typedef struct {
	char *id;		/* NULL = 空槽 */
	double *vec;
	const char *region_id;	/* 借用 Region 的 id 字符串，可为 NULL */
	size_t hash;
	int used;
	int tomb;
} aik_vec_slot;

typedef struct {
	char *a;		/* 无向存储，保留写入方向 */
	char *b;
	double distance;
} aik_edge;

typedef struct {
	char *a;
	char *b;
} aik_close_key;

typedef struct {
	char *region_id;
	int write_ops;
} aik_merge_op;

struct aik_space {
	aik_region_config cfg;
	int dim;

	aik_vec_slot *vtab;
	size_t vcap;
	size_t vused;
	size_t vtomb;

	aik_region **regions;
	size_t n_regions;
	size_t cap_regions;

	char **split_cands;
	size_t n_split;
	size_t cap_split;
	char **small_cands;
	size_t n_small;
	size_t cap_small;

	aik_edge *edges;
	size_t n_edges;
	size_t cap_edges;
	aik_close_key *close_keys;
	size_t n_close;
	size_t cap_close;

	aik_merge_op *merge_ops;
	size_t n_merge_ops;
	size_t cap_merge_ops;

	aik_space_event *history;
	size_t n_history;
	size_t cap_history;

	size_t region_seq;
	int write_ops;
	int split_count;
	int merge_count;

	/* T4a：批量写入抑制演化（aik_space_set_bulk） */
	int bulk;
	/* T4a：新建 Region 的 id 生成钩子（aik_space_set_id_fn） */
	int (*id_fn)(void *ud, const char *prefix, char out[16]);
	void *id_fn_ud;
	/* T4a：Region 时间源（aik_space_set_clock）；NULL → time(NULL) */
	double (*now_fn)(void *ud);
	void *now_ud;
};

/* ------------------------------------------------------------------ */
/* 小工具                                                             */
/* ------------------------------------------------------------------ */
static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || errlen == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

static char *dup_str(const char *s)
{
	size_t n;
	char *p;

	if (!s)
		return NULL;
	n = strlen(s) + 1;
	p = malloc(n);
	if (!p)
		return NULL;
	memcpy(p, s, n);
	return p;
}

static double aik_now(void)
{
	return (double)time(NULL);
}

/* 注入时钟优先，否则墙钟（T4a；未设置时与原行为一致） */
static double space_now(const aik_space *sp)
{
	return sp && sp->now_fn ? sp->now_fn(sp->now_ud) : aik_now();
}

static void free_str_array(char **arr, size_t n)
{
	size_t i;

	if (!arr)
		return;
	for (i = 0; i < n; i++)
		free(arr[i]);
	free(arr);
}

static void config_defaults(aik_region_config *c)
{
	c->min_region_size = 3;
	c->min_join_cosine = 0.70;
	c->split_threshold = 48;
	c->max_density = 120.0;
	c->merge_distance = 0.12;
	c->neighbor_factor = 1.8;
	c->auto_evolve = 1;
	c->evolve_interval = 40;
}

static uint64_t hash_str(const char *s)
{
	uint64_t h = 1469598103934665603ULL;

	while (*s) {
		h ^= (unsigned char)*s++;
		h *= 1099511628211ULL;
	}
	return h;
}

/* ------------------------------------------------------------------ */
/* 向量表（memory_id -> 向量 + membership）                           */
/* ------------------------------------------------------------------ */
static int vec_rehash(aik_space *sp, size_t newcap)
{
	aik_vec_slot *old = sp->vtab;
	size_t oldcap = sp->vcap;
	aik_vec_slot *tab;
	size_t i;

	tab = calloc(newcap, sizeof(*tab));
	if (!tab)
		return -1;
	for (i = 0; i < oldcap; i++) {
		size_t j;

		if (!old[i].used)
			continue;
		j = (size_t)(old[i].hash & (uint64_t)(newcap - 1));
		while (tab[j].used)
			j = (j + 1) & (newcap - 1);
		tab[j] = old[i];
	}
	free(old);
	sp->vtab = tab;
	sp->vcap = newcap;
	sp->vtomb = 0;
	return 0;
}

static aik_vec_slot *vec_lookup(const aik_space *sp, const char *id)
{
	uint64_t h;
	size_t mask;
	size_t start;
	size_t i;

	if (!sp || !sp->vcap || !id)
		return NULL;
	h = hash_str(id);
	mask = sp->vcap - 1;
	start = (size_t)(h & (uint64_t)mask);
	i = start;
	for (;;) {
		aik_vec_slot *s = &sp->vtab[i];

		if (!s->used && !s->tomb)
			return NULL;
		if (s->used && s->hash == h && s->id && strcmp(s->id, id) == 0)
			return s;
		i = (i + 1) & mask;
		if (i == start)
			return NULL;
	}
}

static int vec_insert(aik_space *sp, const char *id, const double *vec,
		      char *err, size_t errlen)
{
	uint64_t h;
	size_t mask;
	size_t i;
	aik_vec_slot *slot;
	double *copy;

	if ((sp->vused + sp->vtomb + 1) * 10 >= sp->vcap * 7) {
		size_t next = sp->vcap ? sp->vcap * 2 : 16;

		if (vec_rehash(sp, next) < 0) {
			set_err(err, errlen, "aik_space: out of memory");
			return -1;
		}
	}
	copy = malloc((size_t)sp->dim * sizeof(double));
	if (!copy) {
		set_err(err, errlen, "aik_space: out of memory");
		return -1;
	}
	memcpy(copy, vec, (size_t)sp->dim * sizeof(double));
	h = hash_str(id);
	mask = sp->vcap - 1;
	i = (size_t)(h & (uint64_t)mask);
	for (;;) {
		slot = &sp->vtab[i];
		if (!slot->used && !slot->tomb)
			break;
		i = (i + 1) & mask;
	}
	slot->id = dup_str(id);
	if (!slot->id) {
		free(copy);
		set_err(err, errlen, "aik_space: out of memory");
		return -1;
	}
	slot->vec = copy;
	slot->region_id = NULL;
	slot->hash = h;
	slot->used = 1;
	slot->tomb = 0;
	sp->vused++;
	return 0;
}

static void vec_erase(aik_space *sp, const char *id)
{
	aik_vec_slot *s = vec_lookup(sp, id);

	if (!s)
		return;
	free(s->id);
	free(s->vec);
	s->id = NULL;
	s->vec = NULL;
	s->region_id = NULL;
	s->used = 0;
	s->tomb = 1;
	sp->vused--;
	sp->vtomb++;
}

static const double *space_lookup_vec(void *ctx, const char *memory_id)
{
	aik_space *sp = ctx;
	aik_vec_slot *s = vec_lookup(sp, memory_id);

	return s ? s->vec : NULL;
}

/* ------------------------------------------------------------------ */
/* 向量数学（long double 累加）                                       */
/* ------------------------------------------------------------------ */
static long double ld_sqnorm(const double *v, int dim)
{
	long double acc = 0.0L;
	int j;

	for (j = 0; j < dim; j++)
		acc += (long double)v[j] * (long double)v[j];
	return acc;
}

static long double ld_dot(const double *a, const double *b, int dim)
{
	long double acc = 0.0L;
	int j;

	for (j = 0; j < dim; j++)
		acc += (long double)a[j] * (long double)b[j];
	return acc;
}

static long double ld_distance(const double *a, const double *b, int dim)
{
	long double acc = 0.0L;
	int j;

	for (j = 0; j < dim; j++) {
		long double d = (long double)a[j] - (long double)b[j];

		acc += d * d;
	}
	return sqrtl(acc);
}

/* sme/utils.py cosine_similarity */
static long double ld_cosine(const double *a, const double *b, int dim)
{
	long double na = sqrtl(ld_sqnorm(a, dim));
	long double nb = sqrtl(ld_sqnorm(b, dim));
	long double dot;

	if (na < 1e-12L || nb < 1e-12L)
		return 0.0L;
	dot = ld_dot(a, b, dim);
	return dot / (na * nb);
}

/* region_manager.evolution_pass 小 Region 合并用的余弦（分母 +1e-12） */
static long double ld_cosine_eps(const double *a, const double *b, int dim)
{
	long double na = sqrtl(ld_sqnorm(a, dim));
	long double nb = sqrtl(ld_sqnorm(b, dim));
	long double dot = ld_dot(a, b, dim);

	return dot / (na * nb + 1e-12L);
}

/* ------------------------------------------------------------------ */
/* Region 数组                                                        */
/* ------------------------------------------------------------------ */
static size_t region_index(const aik_space *sp, const char *region_id)
{
	size_t i;

	if (!sp || !region_id)
		return AIK_FULL_TABLE;
	for (i = 0; i < sp->n_regions; i++) {
		if (strcmp(aik_region_id(sp->regions[i]), region_id) == 0)
			return i;
	}
	return AIK_FULL_TABLE;
}

static aik_region *region_find(const aik_space *sp, const char *region_id)
{
	size_t i = region_index(sp, region_id);

	return i == AIK_FULL_TABLE ? NULL : sp->regions[i];
}

static int region_add(aik_space *sp, aik_region *r)
{
	if (sp->n_regions == sp->cap_regions) {
		size_t cap = sp->cap_regions ? sp->cap_regions * 2 : 8;
		aik_region **grown =
			realloc(sp->regions, cap * sizeof(*grown));

		if (!grown)
			return -1;
		sp->regions = grown;
		sp->cap_regions = cap;
	}
	sp->regions[sp->n_regions++] = r;
	return 0;
}

static void region_remove_at(aik_space *sp, size_t idx)
{
	aik_region__free(sp->regions[idx]);
	memmove(&sp->regions[idx], &sp->regions[idx + 1],
		(sp->n_regions - idx - 1) * sizeof(*sp->regions));
	sp->n_regions--;
}

static void next_region_id(aik_space *sp, char *buf, size_t buflen)
{
	/* 调用方装了生成器就优先用它；失败/空串回退默认格式（T4a） */
	if (sp->id_fn) {
		char tmp[16];

		tmp[0] = '\0';
		if (sp->id_fn(sp->id_fn_ud, "r", tmp) == 0 && tmp[0] != '\0') {
			snprintf(buf, buflen, "%s", tmp);
			return;
		}
	}
	sp->region_seq++;
	snprintf(buf, buflen, "r%06zu", sp->region_seq);
}

/* ------------------------------------------------------------------ */
/* 演化候选（split / small）                                          */
/* ------------------------------------------------------------------ */
static int cand_add(char ***arr, size_t *n, size_t *cap, const char *id)
{
	size_t i;
	char *copy;

	for (i = 0; i < *n; i++) {
		if (strcmp((*arr)[i], id) == 0)
			return 0;
	}
	if (*n == *cap) {
		size_t next = *cap ? *cap * 2 : 8;
		char **grown = realloc(*arr, next * sizeof(*grown));

		if (!grown)
			return -1;
		*arr = grown;
		*cap = next;
	}
	copy = dup_str(id);
	if (!copy)
		return -1;
	(*arr)[(*n)++] = copy;
	return 0;
}

static void cand_remove(char ***arr, size_t *n, const char *id)
{
	size_t i;

	for (i = 0; i < *n; i++) {
		if (strcmp((*arr)[i], id) == 0) {
			free((*arr)[i]);
			memmove(&(*arr)[i], &(*arr)[i + 1],
				(*n - i - 1) * sizeof(char *));
			(*n)--;
			return;
		}
	}
}

static char **cand_take(char ***arr, size_t *n, size_t *cap, size_t *out_n)
{
	char **out = *arr;

	*out_n = *n;
	*arr = NULL;
	*n = 0;
	*cap = 0;
	return out;
}

/* ------------------------------------------------------------------ */
/* 边与 close 集合                                                    */
/* ------------------------------------------------------------------ */
static int edge_pair_equal(const char *a1, const char *b1, const char *a2,
			   const char *b2)
{
	return (strcmp(a1, a2) == 0 && strcmp(b1, b2) == 0) ||
	       (strcmp(a1, b2) == 0 && strcmp(b1, a2) == 0);
}

static size_t edge_index(const aik_space *sp, const char *a, const char *b)
{
	size_t i;

	for (i = 0; i < sp->n_edges; i++) {
		if (edge_pair_equal(sp->edges[i].a, sp->edges[i].b, a, b))
			return i;
	}
	return AIK_FULL_TABLE;
}

static int edge_set(aik_space *sp, const char *src, const char *tgt,
		    double distance)
{
	size_t idx = edge_index(sp, src, tgt);
	char *ca;
	char *cb;

	ca = dup_str(src);
	cb = dup_str(tgt);
	if (!ca || !cb) {
		free(ca);
		free(cb);
		return -1;
	}
	if (idx != AIK_FULL_TABLE) {
		free(sp->edges[idx].a);
		free(sp->edges[idx].b);
		sp->edges[idx].a = ca;
		sp->edges[idx].b = cb;
		sp->edges[idx].distance = distance;
		return 0;
	}
	if (sp->n_edges == sp->cap_edges) {
		size_t cap = sp->cap_edges ? sp->cap_edges * 2 : 8;
		aik_edge *grown = realloc(sp->edges, cap * sizeof(*grown));

		if (!grown) {
			free(ca);
			free(cb);
			return -1;
		}
		sp->edges = grown;
		sp->cap_edges = cap;
	}
	sp->edges[sp->n_edges].a = ca;
	sp->edges[sp->n_edges].b = cb;
	sp->edges[sp->n_edges].distance = distance;
	sp->n_edges++;
	return 0;
}

static void edge_remove_at(aik_space *sp, size_t idx)
{
	free(sp->edges[idx].a);
	free(sp->edges[idx].b);
	memmove(&sp->edges[idx], &sp->edges[idx + 1],
		(sp->n_edges - idx - 1) * sizeof(*sp->edges));
	sp->n_edges--;
}

static void edge_remove(aik_space *sp, const char *a, const char *b)
{
	size_t idx = edge_index(sp, a, b);

	if (idx != AIK_FULL_TABLE)
		edge_remove_at(sp, idx);
}

static int close_has(const aik_space *sp, const char *a, const char *b)
{
	size_t i;

	for (i = 0; i < sp->n_close; i++) {
		if (edge_pair_equal(sp->close_keys[i].a, sp->close_keys[i].b, a,
				    b))
			return 1;
	}
	return 0;
}

static int close_add(aik_space *sp, const char *a, const char *b)
{
	char *ca;
	char *cb;

	if (close_has(sp, a, b))
		return 0;
	ca = dup_str(a);
	cb = dup_str(b);
	if (!ca || !cb) {
		free(ca);
		free(cb);
		return -1;
	}
	if (sp->n_close == sp->cap_close) {
		size_t cap = sp->cap_close ? sp->cap_close * 2 : 8;
		aik_close_key *grown =
			realloc(sp->close_keys, cap * sizeof(*grown));

		if (!grown) {
			free(ca);
			free(cb);
			return -1;
		}
		sp->close_keys = grown;
		sp->cap_close = cap;
	}
	sp->close_keys[sp->n_close].a = ca;
	sp->close_keys[sp->n_close].b = cb;
	sp->n_close++;
	return 0;
}

static void close_remove_at(aik_space *sp, size_t idx)
{
	free(sp->close_keys[idx].a);
	free(sp->close_keys[idx].b);
	memmove(&sp->close_keys[idx], &sp->close_keys[idx + 1],
		(sp->n_close - idx - 1) * sizeof(*sp->close_keys));
	sp->n_close--;
}

static void close_remove(aik_space *sp, const char *a, const char *b)
{
	size_t i;

	for (i = 0; i < sp->n_close; i++) {
		if (edge_pair_equal(sp->close_keys[i].a, sp->close_keys[i].b, a,
				    b)) {
			close_remove_at(sp, i);
			return;
		}
	}
}

static void close_prune_for(aik_space *sp, const char *id)
{
	size_t i = sp->n_close;

	while (i-- > 0) {
		if (strcmp(sp->close_keys[i].a, id) == 0 ||
		    strcmp(sp->close_keys[i].b, id) == 0)
			close_remove_at(sp, i);
	}
}

/* ------------------------------------------------------------------ */
/* _merge_ops 滞后表                                                  */
/* ------------------------------------------------------------------ */
static int merge_ops_get(const aik_space *sp, const char *region_id,
			 int fallback)
{
	size_t i;

	for (i = 0; i < sp->n_merge_ops; i++) {
		if (strcmp(sp->merge_ops[i].region_id, region_id) == 0)
			return sp->merge_ops[i].write_ops;
	}
	return fallback;
}

static int merge_ops_set(aik_space *sp, const char *region_id, int value)
{
	size_t i;
	char *copy;

	for (i = 0; i < sp->n_merge_ops; i++) {
		if (strcmp(sp->merge_ops[i].region_id, region_id) == 0) {
			sp->merge_ops[i].write_ops = value;
			return 0;
		}
	}
	if (sp->n_merge_ops == sp->cap_merge_ops) {
		size_t cap = sp->cap_merge_ops ? sp->cap_merge_ops * 2 : 8;
		aik_merge_op *grown =
			realloc(sp->merge_ops, cap * sizeof(*grown));

		if (!grown)
			return -1;
		sp->merge_ops = grown;
		sp->cap_merge_ops = cap;
	}
	copy = dup_str(region_id);
	if (!copy)
		return -1;
	sp->merge_ops[sp->n_merge_ops].region_id = copy;
	sp->merge_ops[sp->n_merge_ops].write_ops = value;
	sp->n_merge_ops++;
	return 0;
}

static void merge_ops_prune(aik_space *sp, int cutoff)
{
	size_t i = 0;

	while (i < sp->n_merge_ops) {
		if (sp->merge_ops[i].write_ops >= cutoff) {
			i++;
			continue;
		}
		free(sp->merge_ops[i].region_id);
		memmove(&sp->merge_ops[i], &sp->merge_ops[i + 1],
			(sp->n_merge_ops - i - 1) * sizeof(*sp->merge_ops));
		sp->n_merge_ops--;
	}
}

/* ------------------------------------------------------------------ */
/* 事件                                                               */
/* ------------------------------------------------------------------ */
static void event_dispose(aik_space_event *e)
{
	if (!e)
		return;
	free(e->kind);
	free(e->region_id);
	free(e->other_id);
	free_str_array(e->region_members, e->n_region_members);
	free_str_array(e->other_members, e->n_other_members);
	memset(e, 0, sizeof(*e));
}

static int copy_str_array(char ***dst, size_t *dst_n, char *const *src,
			  size_t n)
{
	size_t i;
	char **out = NULL;

	if (n == 0) {
		*dst = NULL;
		*dst_n = 0;
		return 0;
	}
	out = calloc(n, sizeof(*out));
	if (!out)
		return -1;
	for (i = 0; i < n; i++) {
		out[i] = dup_str(src[i]);
		if (!out[i]) {
			free_str_array(out, i);
			return -1;
		}
	}
	*dst = out;
	*dst_n = n;
	return 0;
}

static int event_fill(aik_space_event *e, const char *kind,
		      const char *region_id, const char *other_id,
		      char *const *members, size_t n_members,
		      char *const *other_members, size_t n_other,
		      double density)
{
	memset(e, 0, sizeof(*e));
	e->kind = dup_str(kind);
	e->region_id = dup_str(region_id);
	e->other_id = other_id ? dup_str(other_id) : NULL;
	e->density = density;
	if (!e->kind || !e->region_id ||
	    (other_id && !e->other_id) ||
	    copy_str_array(&e->region_members, &e->n_region_members, members,
			   n_members) < 0 ||
	    copy_str_array(&e->other_members, &e->n_other_members,
			   other_members, n_other) < 0) {
		event_dispose(e);
		return -1;
	}
	return 0;
}

static int event_clone(aik_space_event *dst, const aik_space_event *src)
{
	return event_fill(dst, src->kind, src->region_id, src->other_id,
			  src->region_members, src->n_region_members,
			  src->other_members, src->n_other_members,
			  src->density);
}

static int history_push(aik_space *sp, const char *kind,
			const char *region_id, const char *other_id,
			char *const *members, size_t n_members,
			char *const *other_members, size_t n_other,
			double density, char *err, size_t errlen)
{
	aik_space_event e;

	if (event_fill(&e, kind, region_id, other_id, members, n_members,
		       other_members, n_other, density) < 0) {
		set_err(err, errlen, "aik_space: out of memory");
		return -1;
	}
	if (sp->n_history == sp->cap_history) {
		size_t cap = sp->cap_history ? sp->cap_history * 2 : 16;
		aik_space_event *grown =
			realloc(sp->history, cap * sizeof(*grown));

		if (!grown) {
			event_dispose(&e);
			set_err(err, errlen, "aik_space: out of memory");
			return -1;
		}
		sp->history = grown;
		sp->cap_history = cap;
	}
	sp->history[sp->n_history++] = e;
	if (sp->n_history > AIK_HISTORY_CAP) {
		event_dispose(&sp->history[0]);
		memmove(&sp->history[0], &sp->history[1],
			(sp->n_history - 1) * sizeof(*sp->history));
		sp->n_history--;
	}
	return 0;
}

void aik_space_events_free(aik_space_event *events, size_t n)
{
	size_t i;

	if (!events)
		return;
	for (i = 0; i < n; i++)
		event_dispose(&events[i]);
	free(events);
}

static int collect_last_event(aik_space *sp, aik_space_event **arr,
			      size_t *n, size_t *cap, char *err, size_t errlen)
{
	if (sp->n_history == 0)
		return -1;
	if (*n == *cap) {
		size_t next = *cap ? *cap * 2 : 4;
		aik_space_event *grown = realloc(*arr, next * sizeof(*grown));

		if (!grown) {
			set_err(err, errlen, "aik_space: out of memory");
			return -1;
		}
		*arr = grown;
		*cap = next;
	}
	if (event_clone(&(*arr)[*n], &sp->history[sp->n_history - 1]) < 0) {
		set_err(err, errlen, "aik_space: out of memory");
		return -1;
	}
	(*n)++;
	return 0;
}

/* ------------------------------------------------------------------ */
/* 几何                                                               */
/* ------------------------------------------------------------------ */
static void region_full_refresh(aik_space *sp, aik_region *r)
{
	aik_region__refresh_geometry(r, space_lookup_vec, sp);
}

void aik_space_sync_geometry(aik_space *sp)
{
	size_t i;

	if (!sp)
		return;
	for (i = 0; i < sp->n_regions; i++) {
		if (aik_region__stale(sp->regions[i]))
			region_full_refresh(sp, sp->regions[i]);
	}
}

/* ------------------------------------------------------------------ */
/* 候选登记（region_manager.note_region）                             */
/* ------------------------------------------------------------------ */
static void note_region(aik_space *sp, const char *region_id)
{
	aik_region *r = region_find(sp, region_id);

	if (!r) {
		cand_remove(&sp->split_cands, &sp->n_split, region_id);
		cand_remove(&sp->small_cands, &sp->n_small, region_id);
		return;
	}
	if ((int)aik_region_size(r) >= sp->cfg.split_threshold)
		(void)cand_add(&sp->split_cands, &sp->n_split, &sp->cap_split,
			       region_id);
	else
		cand_remove(&sp->split_cands, &sp->n_split, region_id);
	if ((int)aik_region_size(r) < sp->cfg.min_region_size)
		(void)cand_add(&sp->small_cands, &sp->n_small, &sp->cap_small,
			       region_id);
	else
		cand_remove(&sp->small_cands, &sp->n_small, region_id);
}

/* ------------------------------------------------------------------ */
/* 创建 / 删除 / 刷新                                                 */
/* ------------------------------------------------------------------ */
static aik_region *create_region(aik_space *sp, const char *member_id,
				 char *err, size_t errlen)
{
	char idbuf[32];
	aik_region *r;
	char *members[1];

	next_region_id(sp, idbuf, sizeof(idbuf));
	r = aik_region__new(sp->dim, idbuf, NULL, 1, space_now(sp), err, errlen);
	if (!r)
		return NULL;
	aik_region__set_clock(r, sp->now_fn, sp->now_ud);
	if (aik_region__append_member(r, member_id) < 0) {
		aik_region__free(r);
		set_err(err, errlen, "aik_space: out of memory");
		return NULL;
	}
	region_full_refresh(sp, r);
	if (region_add(sp, r) < 0) {
		aik_region__free(r);
		set_err(err, errlen, "aik_space: out of memory");
		return NULL;
	}
	note_region(sp, aik_region_id(r));
	members[0] = (char *)member_id;
	if (history_push(sp, "region_created", aik_region_id(r), NULL, members,
			 1, NULL, 0, 0.0, err, errlen) < 0) {
		region_remove_at(sp, sp->n_regions - 1);
		return NULL;
	}
	return r;
}

/* 取 Region 成员的深拷贝（供事件在释放前快照） */
static char **snapshot_members(const aik_region *r, size_t *n_out)
{
	char **out;
	size_t i;
	size_t n = aik_region_size(r);

	*n_out = 0;
	if (n == 0)
		return NULL;
	out = calloc(n, sizeof(*out));
	if (!out)
		return NULL;
	for (i = 0; i < n; i++) {
		out[i] = dup_str(aik_region_member(r, i));
		if (!out[i]) {
			free_str_array(out, i);
			return NULL;
		}
	}
	*n_out = n;
	return out;
}

static int delete_region(aik_space *sp, const char *region_id,
			 char *err, size_t errlen)
{
	size_t idx = region_index(sp, region_id);
	aik_region *r;
	char **members;
	size_t n_members = 0;
	char *saved_id;
	size_t i;

	if (idx == AIK_FULL_TABLE)
		return 0;
	r = sp->regions[idx];
	members = snapshot_members(r, &n_members);
	if (n_members > 0 && !members) {
		set_err(err, errlen, "aik_space: out of memory");
		return -1;
	}
	saved_id = dup_str(region_id);
	if (!saved_id) {
		free_str_array(members, n_members);
		set_err(err, errlen, "aik_space: out of memory");
		return -1;
	}
	for (i = 0; i < sp->vcap; i++) {
		if (sp->vtab[i].used && sp->vtab[i].region_id &&
		    strcmp(sp->vtab[i].region_id, region_id) == 0)
			sp->vtab[i].region_id = NULL;
	}
	for (i = sp->n_edges; i-- > 0;) {
		if (strcmp(sp->edges[i].a, region_id) == 0 ||
		    strcmp(sp->edges[i].b, region_id) == 0) {
			close_remove(sp, sp->edges[i].a, sp->edges[i].b);
			edge_remove_at(sp, i);
		}
	}
	close_prune_for(sp, region_id);
	region_remove_at(sp, idx);
	note_region(sp, saved_id);
	if (history_push(sp, "region_deleted", saved_id, NULL, members,
			 n_members, NULL, 0, 0.0, err, errlen) < 0) {
		free_str_array(members, n_members);
		free(saved_id);
		return -1;
	}
	free_str_array(members, n_members);
	free(saved_id);
	return 0;
}

static void refresh_geometry_one(aik_space *sp, aik_region *r)
{
	region_full_refresh(sp, r);
	note_region(sp, aik_region_id(r));
}

/* ------------------------------------------------------------------ */
/* 最邻近 / 吸收                                                      */
/* ------------------------------------------------------------------ */
static aik_region *nearest_region(aik_space *sp, const double *vec,
				  long double *out_dist)
{
	aik_region *best = NULL;
	long double best_dist = 0.0L;
	size_t i;

	for (i = 0; i < sp->n_regions; i++) {
		aik_region *r = sp->regions[i];
		const double *c = aik_region_centroid(r);
		long double d;

		if (!c)
			continue;
		d = ld_distance(vec, c, sp->dim);
		if (!best || d < best_dist) {
			best = r;
			best_dist = d;
		}
	}
	if (out_dist)
		*out_dist = best ? best_dist : 0.0L;
	return best;
}

static aik_region *absorb_member(aik_space *sp, const char *memory_id,
				 const double *vec, char *err, size_t errlen)
{
	aik_region *best;
	const double *centroid;

	if (sp->n_regions == 0)
		return create_region(sp, memory_id, err, errlen);
	best = nearest_region(sp, vec, NULL);
	if (best) {
		centroid = aik_region_centroid(best);
		if (centroid &&
		    ld_cosine(vec, centroid, sp->dim) >=
			    (long double)sp->cfg.min_join_cosine) {
			if (aik_region__append_member(best, memory_id) < 0) {
				set_err(err, errlen, "aik_space: out of memory");
				return NULL;
			}
			aik_region__incremental_centroid(best, vec);
			aik_region__mark_stale(best);
			note_region(sp, aik_region_id(best));
			return best;
		}
	}
	return create_region(sp, memory_id, err, errlen);
}

/* ------------------------------------------------------------------ */
/* 图边                                                               */
/* ------------------------------------------------------------------ */
static int recompute_edges(aik_space *sp, const char *region_id)
{
	aik_region *a = region_find(sp, region_id);
	size_t i;

	if (!a || !aik_region_centroid(a))
		return 0;
	for (i = 0; i < sp->n_regions; i++) {
		aik_region *other = sp->regions[i];
		long double dist;
		long double threshold;
		double dist_d;

		if (other == a || !aik_region_centroid(other))
			continue;
		dist = ld_distance(aik_region_centroid(a),
				   aik_region_centroid(other), sp->dim);
		threshold = ((long double)aik_region_radius(a) +
			     (long double)aik_region_radius(other)) *
			    (long double)sp->cfg.neighbor_factor;
		dist_d = (double)dist;
		if (dist <= threshold) {
			if (edge_set(sp, region_id, aik_region_id(other),
				     dist_d) < 0)
				return -1;
			if (dist_d < sp->cfg.merge_distance) {
				if (close_add(sp, region_id,
					      aik_region_id(other)) < 0)
					return -1;
			} else {
				close_remove(sp, region_id,
					     aik_region_id(other));
			}
		} else {
			edge_remove(sp, region_id, aik_region_id(other));
			close_remove(sp, region_id, aik_region_id(other));
		}
	}
	return 0;
}

static int update_edges_for(aik_space *sp, const char *const *ids, size_t n,
			    char *err, size_t errlen)
{
	size_t i;
	size_t j;

	aik_space_sync_geometry(sp);
	for (i = sp->n_edges; i-- > 0;) {
		int hit = 0;

		for (j = 0; j < n; j++) {
			if (strcmp(sp->edges[i].a, ids[j]) == 0 ||
			    strcmp(sp->edges[i].b, ids[j]) == 0) {
				hit = 1;
				break;
			}
		}
		if (!hit)
			continue;
		close_remove(sp, sp->edges[i].a, sp->edges[i].b);
		edge_remove_at(sp, i);
	}
	for (j = 0; j < n; j++) {
		if (recompute_edges(sp, ids[j]) < 0) {
			set_err(err, errlen, "aik_space: out of memory");
			return -1;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* split                                                              */
/* ------------------------------------------------------------------ */
static int split_region(aik_space *sp, const char *region_id,
			char **keep_out, char **new_out,
			char *err, size_t errlen)
{
	size_t idx = region_index(sp, region_id);
	aik_region *r;
	size_t n_mem;
	size_t i;
	size_t seed_a = AIK_FULL_TABLE;
	size_t seed_b = AIK_FULL_TABLE;
	long double best;
	const double *va;
	const double *vb;
	char **part_a = NULL;
	char **part_b = NULL;
	size_t na = 0;
	size_t nb = 0;
	char **keep_part;
	char **other_part;
	size_t n_keep;
	size_t n_other;
	char new_id[32];
	aik_region *child;
	int old_generation;
	double pre_density;
	char *saved_id = NULL;

	if (idx == AIK_FULL_TABLE)
		return 1;
	r = sp->regions[idx];
	if (aik_region_size(r) < 4 || !aik_region_centroid(r))
		return 1;
	n_mem = aik_region_size(r);

	best = -1.0L;
	for (i = 0; i < n_mem; i++) {
		const double *v = space_lookup_vec(sp, aik_region_member(r, i));
		long double d;

		if (!v)
			continue;
		d = ld_distance(v, aik_region_centroid(r), sp->dim);
		if (d > best) {
			best = d;
			seed_a = i;
		}
	}
	if (seed_a == AIK_FULL_TABLE)
		return 1;
	va = space_lookup_vec(sp, aik_region_member(r, seed_a));
	best = -1.0L;
	for (i = 0; i < n_mem; i++) {
		const double *v = space_lookup_vec(sp, aik_region_member(r, i));
		long double d;

		if (!v)
			continue;
		d = ld_distance(v, va, sp->dim);
		if (d > best) {
			best = d;
			seed_b = i;
		}
	}
	if (seed_b == AIK_FULL_TABLE ||
	    strcmp(aik_region_member(r, seed_a), aik_region_member(r, seed_b)) ==
		    0)
		return 1;
	vb = space_lookup_vec(sp, aik_region_member(r, seed_b));

	part_a = calloc(n_mem, sizeof(*part_a));
	part_b = calloc(n_mem, sizeof(*part_b));
	if (!part_a || !part_b) {
		free(part_a);
		free(part_b);
		set_err(err, errlen, "aik_space: out of memory");
		return -1;
	}
	for (i = 0; i < n_mem; i++) {
		const char *mid = aik_region_member(r, i);
		char *copy = NULL;
		int to_a;

		if (strcmp(mid, aik_region_member(r, seed_a)) == 0) {
			to_a = 1;
		} else if (strcmp(mid, aik_region_member(r, seed_b)) == 0) {
			to_a = 0;
		} else {
			const double *v = space_lookup_vec(sp, mid);
			long double d_a;
			long double d_b;

			if (!v) {
				to_a = 1;
			} else {
				d_a = ld_distance(v, va, sp->dim);
				d_b = ld_distance(v, vb, sp->dim);
				to_a = (d_a <= d_b);
			}
		}
		copy = dup_str(mid);
		if (!copy) {
			free_str_array(part_a, na);
			free_str_array(part_b, nb);
			set_err(err, errlen, "aik_space: out of memory");
			return -1;
		}
		if (to_a)
			part_a[na++] = copy;
		else
			part_b[nb++] = copy;
	}
	if (na == 0 || nb == 0) {
		free_str_array(part_a, na);
		free_str_array(part_b, nb);
		return 1;
	}
	if (na >= nb) {
		keep_part = part_a;
		other_part = part_b;
		n_keep = na;
		n_other = nb;
	} else {
		keep_part = part_b;
		other_part = part_a;
		n_keep = nb;
		n_other = na;
	}

	next_region_id(sp, new_id, sizeof(new_id));
	old_generation = aik_region_generation(r);
	pre_density = aik_region_density(r);
	child = aik_region__new(sp->dim, new_id, region_id,
				old_generation + 1, space_now(sp), err, errlen);
	if (!child) {
		free_str_array(part_a, na);
		free_str_array(part_b, nb);
		return -1;
	}
	aik_region__set_clock(child, sp->now_fn, sp->now_ud);
	/* keeper 保留原 id / created_at / parent，generation+1 */
	aik_region__set_members(r, keep_part, n_keep);
	aik_region__set_generation(r, old_generation + 1);
	aik_region__set_members(child, other_part, n_other);
	region_full_refresh(sp, r);
	region_full_refresh(sp, child);
	/* r 仍在原位置；child 追加到末尾（Python dict 语义） */
	if (region_add(sp, child) < 0) {
		aik_region__free(child);
		set_err(err, errlen, "aik_space: out of memory");
		return -1;
	}
	saved_id = dup_str(region_id);
	if (!saved_id) {
		set_err(err, errlen, "aik_space: out of memory");
		return -1;
	}
	for (i = 0; i < n_other; i++) {
		aik_vec_slot *slot = vec_lookup(sp, other_part[i]);

		if (slot)
			slot->region_id = aik_region_id(child);
	}
	note_region(sp, saved_id);
	note_region(sp, new_id);
	{
		const char *ids[2];

		ids[0] = saved_id;
		ids[1] = new_id;
		if (update_edges_for(sp, ids, 2, err, errlen) < 0) {
			free(saved_id);
			return -1;
		}
	}
	sp->split_count++;
	if (history_push(sp, "split", saved_id, new_id, keep_part, n_keep,
			 other_part, n_other, pre_density, err, errlen) < 0) {
		free(saved_id);
		return -1;
	}
	if (keep_out) {
		*keep_out = dup_str(saved_id);
		if (!*keep_out) {
			free(saved_id);
			set_err(err, errlen, "aik_space: out of memory");
			return -1;
		}
	}
	if (new_out) {
		*new_out = dup_str(aik_region_id(child));
		if (!*new_out) {
			free(saved_id);
			set_err(err, errlen, "aik_space: out of memory");
			return -1;
		}
	}
	free(saved_id);
	return 0;
}

/* ------------------------------------------------------------------ */
/* merge                                                              */
/* ------------------------------------------------------------------ */
static int merge_regions(aik_space *sp, const char *a_id, const char *b_id,
			 char **keeper_out, char *err, size_t errlen)
{
	size_t ia = region_index(sp, a_id);
	size_t ib = region_index(sp, b_id);
	aik_region *a;
	aik_region *b;
	aik_region *keeper;
	aik_region *absorbed;
	size_t absorbed_idx;
	size_t keeper_n;
	size_t absorbed_n;
	char **union_members = NULL;
	char **absorbed_members = NULL;
	size_t n_union = 0;
	size_t i;
	char *absorbed_id = NULL;
	char *keeper_id_copy = NULL;
	int transferred = 0;

	if (ia == AIK_FULL_TABLE || ib == AIK_FULL_TABLE || ia == ib)
		return 1;
	a = sp->regions[ia];
	b = sp->regions[ib];
	if (aik_region_size(a) >= aik_region_size(b)) {
		keeper = a;
		absorbed = b;
	} else {
		keeper = b;
		absorbed = a;
	}
	absorbed_idx = (absorbed == a) ? ia : ib;
	keeper_n = aik_region_size(keeper);
	absorbed_n = aik_region_size(absorbed);
	absorbed_id = dup_str(aik_region_id(absorbed));
	keeper_id_copy = dup_str(aik_region_id(keeper));
	if (!absorbed_id || !keeper_id_copy) {
		free(absorbed_id);
		free(keeper_id_copy);
		set_err(err, errlen, "aik_space: out of memory");
		return -1;
	}
	union_members = calloc((keeper_n + absorbed_n) ? keeper_n + absorbed_n : 1,
			       sizeof(*union_members));
	absorbed_members = calloc(absorbed_n ? absorbed_n : 1,
				  sizeof(*absorbed_members));
	if (!union_members || !absorbed_members) {
		free(union_members);
		free(absorbed_members);
		free(absorbed_id);
		free(keeper_id_copy);
		set_err(err, errlen, "aik_space: out of memory");
		return -1;
	}
	for (i = 0; i < keeper_n; i++) {
		union_members[n_union] = dup_str(aik_region_member(keeper, i));
		if (!union_members[n_union])
			goto oom;
		n_union++;
	}
	for (i = 0; i < absorbed_n; i++) {
		char *copy = dup_str(aik_region_member(absorbed, i));

		if (!copy)
			goto oom;
		absorbed_members[i] = copy;
		union_members[n_union++] = dup_str(copy);
		if (!union_members[n_union - 1])
			goto oom;
	}
	aik_region__set_members(keeper, union_members, n_union);
	transferred = 1;
	region_full_refresh(sp, keeper);
	for (i = 0; i < absorbed_n; i++) {
		aik_vec_slot *slot = vec_lookup(sp, absorbed_members[i]);

		if (slot)
			slot->region_id = aik_region_id(keeper);
	}
	region_remove_at(sp, absorbed_idx);
	note_region(sp, keeper_id_copy);
	note_region(sp, absorbed_id);
	{
		const char *ids[1];

		ids[0] = keeper_id_copy;
		if (update_edges_for(sp, ids, 1, err, errlen) < 0) {
			free_str_array(absorbed_members, absorbed_n);
			free(absorbed_id);
			free(keeper_id_copy);
			return -1;
		}
	}
	if (merge_ops_set(sp, keeper_id_copy, sp->write_ops) < 0) {
		set_err(err, errlen, "aik_space: out of memory");
		free_str_array(absorbed_members, absorbed_n);
		free(absorbed_id);
		free(keeper_id_copy);
		return -1;
	}
	sp->merge_count++;
	if (history_push(sp, "merge", keeper_id_copy, absorbed_id,
			 union_members, n_union, absorbed_members, absorbed_n,
			 0.0, err, errlen) < 0) {
		free_str_array(absorbed_members, absorbed_n);
		free(absorbed_id);
		free(keeper_id_copy);
		return -1;
	}
	if (keeper_out) {
		*keeper_out = dup_str(keeper_id_copy);
		if (!*keeper_out) {
			set_err(err, errlen, "aik_space: out of memory");
			free_str_array(absorbed_members, absorbed_n);
			free(absorbed_id);
			free(keeper_id_copy);
			return -1;
		}
	}
	free_str_array(absorbed_members, absorbed_n);
	free(absorbed_id);
	free(keeper_id_copy);
	return 0;

oom:
	set_err(err, errlen, "aik_space: out of memory");
	if (!transferred)
		free_str_array(union_members, n_union);
	free_str_array(absorbed_members, absorbed_n);
	free(absorbed_id);
	free(keeper_id_copy);
	return -1;
}

/* ------------------------------------------------------------------ */
/* 演化                                                               */
/* ------------------------------------------------------------------ */
static aik_region *closest_region(aik_space *sp, const char *region_id)
{
	aik_region *region = region_find(sp, region_id);
	aik_region *best = NULL;
	long double best_dist = 0.0L;
	size_t i;

	if (!region || !aik_region_centroid(region))
		return NULL;
	for (i = 0; i < sp->n_regions; i++) {
		aik_region *other = sp->regions[i];
		long double d;

		if (other == region || !aik_region_centroid(other))
			continue;
		d = ld_distance(aik_region_centroid(region),
				aik_region_centroid(other), sp->dim);
		if (!best || d < best_dist) {
			best = other;
			best_dist = d;
		}
	}
	return best;
}

static int evolution_pass(aik_space *sp, aik_space_event **events_out,
			  size_t *n_out, char *err, size_t errlen)
{
	aik_space_event *collected = NULL;
	size_t n_collected = 0;
	size_t cap_collected = 0;
	char **snap;
	size_t n_snap;
	size_t i;
	int splits = 0;
	int merges = 0;
	int rc = 0;
	int interval = sp->cfg.evolve_interval;

	aik_space_sync_geometry(sp);

	/* 1) 密度拆分 */
	snap = cand_take(&sp->split_cands, &sp->n_split, &sp->cap_split,
			 &n_snap);
	for (i = 0; i < n_snap && splits < AIK_MAX_EVOLVE_ACTIONS; i++) {
		aik_region *r = region_find(sp, snap[i]);
		int merge_ops;
		int allow;

		if (!r)
			continue;
		merge_ops = merge_ops_get(sp, snap[i], -(interval * 4));
		allow = sp->write_ops - merge_ops >= interval * 4;
		if ((int)aik_region_size(r) >= sp->cfg.split_threshold &&
		    aik_region_density(r) >= sp->cfg.max_density && allow) {
			int src = split_region(sp, snap[i], NULL, NULL, err,
					       errlen);

			if (src < 0) {
				rc = -1;
				goto done;
			}
			if (src == 0) {
				splits++;
				if (collect_last_event(sp, &collected, &n_collected,
						       &cap_collected, err,
						       errlen) < 0) {
					rc = -1;
					goto done;
				}
			}
		}
	}
	free_str_array(snap, n_snap);
	{
		size_t extra = 0;
		char **leftover = cand_take(&sp->split_cands, &sp->n_split,
					    &sp->cap_split, &extra);

		free_str_array(leftover, extra);
	}

	/* 2) 小 Region 并入最近邻（质心余弦门槛） */
	snap = cand_take(&sp->small_cands, &sp->n_small, &sp->cap_small,
			 &n_snap);
	for (i = 0; i < n_snap && merges < AIK_MAX_EVOLVE_ACTIONS; i++) {
		aik_region *r = region_find(sp, snap[i]);
		aik_region *neighbor;

		if (!r || (int)aik_region_size(r) >= sp->cfg.min_region_size)
			continue;
		neighbor = closest_region(sp, snap[i]);
		if (!neighbor || strcmp(aik_region_id(neighbor), snap[i]) == 0)
			continue;
		if (!aik_region_centroid(r) ||
		    !aik_region_centroid(neighbor))
			continue;
		if (ld_cosine_eps(aik_region_centroid(r),
				  aik_region_centroid(neighbor),
				  sp->dim) <
		    (long double)sp->cfg.min_join_cosine)
			continue;
		{
			int mrc = merge_regions(sp, snap[i],
						aik_region_id(neighbor), NULL, err,
						errlen);

			if (mrc < 0) {
				rc = -1;
				goto done;
			}
			if (mrc == 0) {
				merges++;
				if (collect_last_event(sp, &collected,
						       &n_collected,
						       &cap_collected, err,
						       errlen) < 0) {
					rc = -1;
					goto done;
				}
			}
		}
	}
	free_str_array(snap, n_snap);
	{
		size_t extra = 0;
		char **leftover = cand_take(&sp->small_cands, &sp->n_small,
					    &sp->cap_small, &extra);

		free_str_array(leftover, extra);
	}

	/* 3) close 边合并 */
	{
		aik_close_key *close_snapshot = NULL;
		size_t n_close_snapshot = sp->n_close;
		size_t j;

		if (n_close_snapshot) {
			close_snapshot = calloc(n_close_snapshot,
						sizeof(*close_snapshot));
			if (!close_snapshot) {
				set_err(err, errlen, "aik_space: out of memory");
				rc = -1;
				goto done;
			}
			for (j = 0; j < n_close_snapshot; j++) {
				close_snapshot[j].a =
					dup_str(sp->close_keys[j].a);
				close_snapshot[j].b =
					dup_str(sp->close_keys[j].b);
				if (!close_snapshot[j].a ||
				    !close_snapshot[j].b) {
					set_err(err, errlen,
						"aik_space: out of memory");
					for (; j < n_close_snapshot; j++) {
						close_snapshot[j].a = NULL;
						close_snapshot[j].b = NULL;
					}
					for (j = 0; j < n_close_snapshot; j++) {
						free(close_snapshot[j].a);
						free(close_snapshot[j].b);
					}
					free(close_snapshot);
					rc = -1;
					goto done;
				}
			}
		}
		for (j = 0; j < n_close_snapshot &&
			    merges < AIK_MAX_EVOLVE_ACTIONS;
		     j++) {
			aik_edge *edge;
			size_t eidx;
			aik_region *ra;
			aik_region *rb;
			int combined;

			eidx = edge_index(sp, close_snapshot[j].a,
					  close_snapshot[j].b);
			if (eidx == AIK_FULL_TABLE) {
				close_remove(sp, close_snapshot[j].a,
					     close_snapshot[j].b);
				continue;
			}
			edge = &sp->edges[eidx];
			ra = region_find(sp, edge->a);
			rb = region_find(sp, edge->b);			if (!ra || !rb) {
				close_remove(sp, close_snapshot[j].a,
					     close_snapshot[j].b);
				continue;
			}
			combined = (int)aik_region_size(ra) +
				   (int)aik_region_size(rb);
			if (combined >= sp->cfg.min_region_size &&
			    combined <= sp->cfg.split_threshold * 2) {
				char *ea = dup_str(sp->edges[eidx].a);
				char *eb = dup_str(sp->edges[eidx].b);

				if (!ea || !eb) {
					free(ea);
					free(eb);
					set_err(err, errlen,
						"aik_space: out of memory");
					rc = -1;
					break;
				}
				{
					int mrc = merge_regions(sp, ea, eb, NULL,
								err, errlen);

					if (mrc < 0)
						rc = -1;
					else if (mrc == 0) {
						merges++;
						if (collect_last_event(
							    sp, &collected,
							    &n_collected,
							    &cap_collected, err,
							    errlen) < 0)
							rc = -1;
					}
				}
				free(ea);
				free(eb);
			}
			if (rc < 0)
				break;
		}
		for (j = 0; j < n_close_snapshot; j++) {
			free(close_snapshot[j].a);
			free(close_snapshot[j].b);
		}
		free(close_snapshot);
		if (rc < 0)
			goto done;
	}

	/* _merge_ops 有界化 */
	if (sp->n_merge_ops > 64)
		merge_ops_prune(sp, sp->write_ops - interval * 8);

done:
	if (rc == 0) {
		if (events_out) {
			*events_out = collected;
			*n_out = n_collected;
			collected = NULL;
			n_collected = 0;
		}
	}
	if (collected)
		aik_space_events_free(collected, n_collected);
	return rc;
}

static int maybe_evolve(aik_space *sp, char *err, size_t errlen)
{
	/* 顺序同 Python _maybe_evolve：bulk 优先于 auto_evolve（T4a） */
	if (sp->bulk)
		return 0;
	if (!sp->cfg.auto_evolve)
		return 0;
	if (sp->cfg.evolve_interval <= 0)
		return 0;
	if (sp->write_ops % sp->cfg.evolve_interval != 0)
		return 0;
	return evolution_pass(sp, NULL, NULL, err, errlen);
}

/* ------------------------------------------------------------------ */
/* 生命周期公开 API                                                   */
/* ------------------------------------------------------------------ */
aik_space *aik_space_new(const aik_region_config *cfg, int dim,
			 char *err, size_t errlen)
{
	aik_space *sp;

	if (dim <= 0) {
		set_err(err, errlen, "aik_space_new: dim must be > 0");
		return NULL;
	}
	sp = calloc(1, sizeof(*sp));
	if (!sp) {
		set_err(err, errlen, "aik_space_new: out of memory");
		return NULL;
	}
	if (cfg)
		sp->cfg = *cfg;
	else
		config_defaults(&sp->cfg);
	sp->dim = dim;
	if (vec_rehash(sp, 16) < 0) {
		free(sp);
		set_err(err, errlen, "aik_space_new: out of memory");
		return NULL;
	}
	return sp;
}

void aik_space_free(aik_space *sp)
{
	size_t i;

	if (!sp)
		return;
	for (i = 0; i < sp->vcap; i++) {
		free(sp->vtab[i].id);
		free(sp->vtab[i].vec);
	}
	free(sp->vtab);
	for (i = 0; i < sp->n_regions; i++)
		aik_region__free(sp->regions[i]);
	free(sp->regions);
	free_str_array(sp->split_cands, sp->n_split);
	free_str_array(sp->small_cands, sp->n_small);
	for (i = 0; i < sp->n_edges; i++) {
		free(sp->edges[i].a);
		free(sp->edges[i].b);
	}
	free(sp->edges);
	for (i = 0; i < sp->n_close; i++) {
		free(sp->close_keys[i].a);
		free(sp->close_keys[i].b);
	}
	free(sp->close_keys);
	for (i = 0; i < sp->n_merge_ops; i++)
		free(sp->merge_ops[i].region_id);
	free(sp->merge_ops);
	aik_space_events_free(sp->history, sp->n_history);
	free(sp);
}

int aik_space_insert(aik_space *sp, const char *memory_id,
		     const double *vec, char *err, size_t errlen)
{
	aik_vec_slot *slot;
	aik_region *region;

	if (!sp || !memory_id || !vec) {
		set_err(err, errlen, "aik_space_insert: invalid argument");
		return -1;
	}
	slot = vec_lookup(sp, memory_id);
	if (slot) {
		memcpy(slot->vec, vec, (size_t)sp->dim * sizeof(double));
		if (slot->region_id && region_find(sp, slot->region_id))
			return 0;	/* 幂等：只刷新向量 */
		slot->region_id = NULL;
	} else if (vec_insert(sp, memory_id, vec, err, errlen) < 0) {
		return -1;
	}
	region = absorb_member(sp, memory_id, vec, err, errlen);
	if (!region)
		return -1;
	slot = vec_lookup(sp, memory_id);
	if (!slot) {
		set_err(err, errlen, "aik_space_insert: internal");
		return -1;
	}
	slot->region_id = aik_region_id(region);
	sp->write_ops++;
	return maybe_evolve(sp, err, errlen);
}

int aik_space_remove(aik_space *sp, const char *memory_id)
{
	aik_vec_slot *slot;
	const char *region_id;
	aik_region *region;
	char *saved = NULL;

	if (!sp || !memory_id)
		return -1;
	slot = vec_lookup(sp, memory_id);
	if (!slot)
		return 0;
	region_id = slot->region_id;
	slot->region_id = NULL;
	vec_erase(sp, memory_id);
	if (!region_id)
		return 0;
	region = region_find(sp, region_id);
	if (!region)
		return 0;
	saved = dup_str(region_id);
	if (!saved)
		return -1;
	aik_region__drop_member(region, memory_id);
	if (aik_region_size(region) == 0) {
		int rc = delete_region(sp, saved, NULL, 0);

		free(saved);
		return rc;
	}
	refresh_geometry_one(sp, region);
	free(saved);
	return maybe_evolve(sp, NULL, 0);
}

/* ------------------------------------------------------------------ */
/* 查询与统计                                                         */
/* ------------------------------------------------------------------ */
static void stable_sort_hits(aik_region_hit *arr, size_t n,
			     aik_region_hit *tmp)
{
	size_t width;

	for (width = 1; width < n; width *= 2) {
		size_t i;

		for (i = 0; i < n; i += width * 2) {
			size_t left = i;
			size_t mid = i + width < n ? i + width : n;
			size_t right = i + width * 2 < n ? i + width * 2 : n;
			size_t l = left;
			size_t r = mid;
			size_t k = left;

			while (l < mid && r < right) {
				if (arr[l].score >= arr[r].score)
					tmp[k++] = arr[l++];
				else
					tmp[k++] = arr[r++];
			}
			while (l < mid)
				tmp[k++] = arr[l++];
			while (r < right)
				tmp[k++] = arr[r++];
		}
		for (i = 0; i < n; i++)
			arr[i] = tmp[i];
	}
}

int aik_space_query_regions(const aik_space *sp, const double *query,
			    int top_k, aik_region_hit **out, size_t *n_out,
			    char *err, size_t errlen)
{
	double *qhat = NULL;
	aik_region_hit *coarse = NULL;
	aik_region_hit *refined = NULL;
	aik_region_hit *tmp = NULL;
	aik_region_hit *result = NULL;
	size_t n_coarse = 0;
	size_t n_refine;
	size_t i;
	size_t j;
	long double sq = 0.0L;
	double divisor;

	if (!sp || !query || !out || !n_out) {
		set_err(err, errlen, "aik_space_query_regions: invalid argument");
		return -1;
	}
	*out = NULL;
	*n_out = 0;
	if (top_k <= 0 || sp->n_regions == 0)
		return 0;
	qhat = calloc((size_t)sp->dim, sizeof(double));
	coarse = calloc(sp->n_regions, sizeof(*coarse));
	if (!qhat || !coarse)
		goto oom;
	for (j = 0; j < (size_t)sp->dim; j++)
		sq += (long double)query[j] * (long double)query[j];
	divisor = (double)sqrtl(sq);
	if (!(divisor > 1e-12))
		divisor = 1e-12;
	for (j = 0; j < (size_t)sp->dim; j++)
		qhat[j] = query[j] / divisor;
	for (i = 0; i < sp->n_regions; i++) {
		const aik_region *r = sp->regions[i];
		const double *c = aik_region_centroid(r);
		long double cos;
		long double distance;
		long double denom;
		long double score;

		if (!c || aik_region_size(r) == 0)
			continue;
		denom = sqrtl(ld_sqnorm(c, sp->dim)) *
			sqrtl(ld_sqnorm(qhat, sp->dim));
		if (denom < 1e-12L)
			denom = 1e-12L;
		cos = ld_dot(c, qhat, sp->dim) / denom;
		distance = ld_distance(query, c, sp->dim);
		score = 0.6L * (cos + 1.0L) / 2.0L +
			0.4L * (1.0L / (1.0L + distance));
		coarse[n_coarse].region = r;
		coarse[n_coarse].score = (double)score;
		coarse[n_coarse].distance = (double)distance;
		n_coarse++;
	}
	tmp = calloc(n_coarse ? n_coarse : 1, sizeof(*tmp));
	if (!tmp)
		goto oom;
	stable_sort_hits(coarse, n_coarse, tmp);

	n_refine = (size_t)(top_k > 0 ? top_k : 0) * 4;
	if (n_refine < 12)
		n_refine = 12;
	if (n_refine > n_coarse)
		n_refine = n_coarse;
	refined = calloc(n_refine ? n_refine : 1, sizeof(*refined));
	if (!refined)
		goto oom;
	for (i = 0; i < n_refine; i++) {
		const aik_region *r = coarse[i].region;
		size_t n_mem = aik_region_size(r);
		double max_cos = coarse[i].score;
		int any = 0;

		for (j = 0; j < n_mem; j++) {
			const double *v = space_lookup_vec((void *)sp,
							   aik_region_member(r, j));
			long double nv;
			long double divisor2;
			long double dot;
			long double cs;

			if (!v)
				continue;
			nv = sqrtl(ld_sqnorm(v, sp->dim));
			divisor2 = nv < 1e-12L ? 1e-12L : nv;
			dot = 0.0L;
			{
				int k;

				for (k = 0; k < sp->dim; k++)
					dot += ((long double)v[k] /
						divisor2) *
					       (long double)qhat[k];
			}
			cs = dot;
			if (!any || cs > (long double)max_cos)
				max_cos = (double)cs;
			any = 1;
		}
		refined[i].region = r;
		refined[i].score =
			0.4 * coarse[i].score + 0.6 * max_cos;
		refined[i].distance = coarse[i].distance;
	}
	stable_sort_hits(refined, n_refine, tmp);
	if (n_refine > (size_t)top_k)
		n_refine = (size_t)top_k;
	if (n_refine == 0) {
		free(qhat);
		free(coarse);
		free(refined);
		free(tmp);
		return 0;
	}
	result = malloc(n_refine * sizeof(*result));
	if (!result)
		goto oom;
	for (i = 0; i < n_refine; i++)
		result[i] = refined[i];
	free(qhat);
	free(coarse);
	free(refined);
	free(tmp);
	*out = result;
	*n_out = n_refine;
	return 0;

oom:
	set_err(err, errlen, "aik_space_query_regions: out of memory");
	free(qhat);
	free(coarse);
	free(refined);
	free(tmp);
	return -1;
}

int aik_space_region_stats(const aik_space *sp, aik_region_stats *out)
{
	aik_space *mutable_sp = (aik_space *)sp;
	double sum_size = 0.0;
	double sum_density = 0.0;
	double sum_radius = 0.0;
	double sum_neighbors = 0.0;
	size_t i;

	if (!sp || !out)
		return -1;
	memset(out, 0, sizeof(*out));
	aik_space_sync_geometry(mutable_sp);
	out->count = (int)sp->n_regions;
	if (sp->n_regions == 0)
		return 0;
	out->max_size = (int)aik_region_size(sp->regions[0]);
	out->min_size = out->max_size;
	for (i = 0; i < sp->n_regions; i++) {
		const aik_region *r = sp->regions[i];
		int size = (int)aik_region_size(r);
		double neighbors = 0.0;
		size_t k;

		sum_size += (double)size;
		sum_density += aik_region_density(r);
		sum_radius += aik_region_radius(r);
		if (size > out->max_size)
			out->max_size = size;
		if (size < out->min_size)
			out->min_size = size;
		for (k = 0; k < sp->n_edges; k++) {
			if (strcmp(sp->edges[k].a, aik_region_id(r)) == 0 ||
			    strcmp(sp->edges[k].b, aik_region_id(r)) == 0)
				neighbors += 1.0;
		}
		sum_neighbors += neighbors;
	}
	out->avg_size = sum_size / (double)sp->n_regions;
	out->avg_density = sum_density / (double)sp->n_regions;
	out->avg_radius = sum_radius / (double)sp->n_regions;
	out->avg_neighbors = sum_neighbors / (double)sp->n_regions;
	out->edge_count = (int)sp->n_edges;
	out->split_count = sp->split_count;
	out->merge_count = sp->merge_count;
	return 0;
}

/* ------------------------------------------------------------------ */
/* 访问器                                                             */
/* ------------------------------------------------------------------ */
const char *aik_space_region_for(const aik_space *sp, const char *memory_id)
{
	aik_vec_slot *slot;

	if (!sp || !memory_id)
		return NULL;
	slot = vec_lookup(sp, memory_id);
	return slot ? slot->region_id : NULL;
}

size_t aik_space_region_count(const aik_space *sp)
{
	return sp ? sp->n_regions : 0;
}

const aik_region *aik_space_region_at(const aik_space *sp, size_t i)
{
	if (!sp || i >= sp->n_regions)
		return NULL;
	return sp->regions[i];
}

const aik_region *aik_space_region(const aik_space *sp, const char *region_id)
{
	return region_find(sp, region_id);
}

size_t aik_space_edge_count(const aik_space *sp)
{
	return sp ? sp->n_edges : 0;
}

int aik_space_edge_at(const aik_space *sp, size_t i, const char **a,
		      const char **b, double *distance)
{
	if (!sp || i >= sp->n_edges)
		return -1;
	if (a)
		*a = sp->edges[i].a;
	if (b)
		*b = sp->edges[i].b;
	if (distance)
		*distance = sp->edges[i].distance;
	return 0;
}

int aik_space_evolution_pass(aik_space *sp, aik_space_event **events,
			     size_t *n_events, char *err, size_t errlen)
{
	if (!sp || !events || !n_events) {
		set_err(err, errlen, "aik_space_evolution_pass: invalid argument");
		return -1;
	}
	*events = NULL;
	*n_events = 0;
	return evolution_pass(sp, events, n_events, err, errlen);
}

int aik_space_split(aik_space *sp, const char *region_id, char **keep_id,
		    char **new_id, char *err, size_t errlen)
{
	if (!sp || !region_id) {
		set_err(err, errlen, "aik_space_split: invalid argument");
		return -1;
	}
	if (keep_id)
		*keep_id = NULL;
	if (new_id)
		*new_id = NULL;
	return split_region(sp, region_id, keep_id, new_id, err, errlen);
}

int aik_space_merge(aik_space *sp, const char *a, const char *b,
		    char **keeper_id, char *err, size_t errlen)
{
	if (!sp || !a || !b) {
		set_err(err, errlen, "aik_space_merge: invalid argument");
		return -1;
	}
	if (keeper_id)
		*keeper_id = NULL;
	return merge_regions(sp, a, b, keeper_id, err, errlen);
}

int aik_space_write_ops(const aik_space *sp)
{
	return sp ? sp->write_ops : 0;
}

size_t aik_space_history_count(const aik_space *sp)
{
	return sp ? sp->n_history : 0;
}

const aik_space_event *aik_space_history_at(const aik_space *sp, size_t i)
{
	if (!sp || i >= sp->n_history)
		return NULL;
	return &sp->history[i];
}

/* ------------------------------------------------------------------ */
/* T4a：bulk 抑制 / id 生成钩子                                       */
/* ------------------------------------------------------------------ */
void aik_space_set_bulk(aik_space *sp, int bulk)
{
	if (sp)
		sp->bulk = bulk != 0;
}

void aik_space_set_id_fn(aik_space *sp,
			 int (*fn)(void *ud, const char *prefix, char out[16]),
			 void *ud)
{
	if (!sp)
		return;
	sp->id_fn = fn;
	sp->id_fn_ud = ud;
}

void aik_space_set_clock(aik_space *sp, aik_space_now_fn fn, void *ud)
{
	size_t i;

	if (!sp)
		return;
	sp->now_fn = fn;
	sp->now_ud = ud;
	/* 已有 Region 继承新时钟：之后的 mark_stale / 几何重算生效，
	 * 已写入的 created_at 不变 */
	for (i = 0; i < sp->n_regions; i++)
		aik_region__set_clock(sp->regions[i], fn, ud);
}

/* ------------------------------------------------------------------ */
/* T4a：快照恢复所需的最小内部访问（space_load.c 使用）               */
/* ------------------------------------------------------------------ */
void aik_space__reset(aik_space *sp)
{
	size_t i;

	if (!sp)
		return;
	for (i = 0; i < sp->vcap; i++) {
		free(sp->vtab[i].id);
		free(sp->vtab[i].vec);
		sp->vtab[i].id = NULL;
		sp->vtab[i].vec = NULL;
		sp->vtab[i].region_id = NULL;
		sp->vtab[i].hash = 0;
		sp->vtab[i].used = 0;
		sp->vtab[i].tomb = 0;
	}
	sp->vused = 0;
	sp->vtomb = 0;
	for (i = 0; i < sp->n_regions; i++)
		aik_region__free(sp->regions[i]);
	sp->n_regions = 0;
	free_str_array(sp->split_cands, sp->n_split);
	sp->split_cands = NULL;
	sp->n_split = 0;
	sp->cap_split = 0;
	free_str_array(sp->small_cands, sp->n_small);
	sp->small_cands = NULL;
	sp->n_small = 0;
	sp->cap_small = 0;
	for (i = 0; i < sp->n_edges; i++) {
		free(sp->edges[i].a);
		free(sp->edges[i].b);
	}
	sp->n_edges = 0;
	for (i = 0; i < sp->n_close; i++) {
		free(sp->close_keys[i].a);
		free(sp->close_keys[i].b);
	}
	sp->n_close = 0;
	for (i = 0; i < sp->n_merge_ops; i++)
		free(sp->merge_ops[i].region_id);
	sp->n_merge_ops = 0;
	aik_space_events_free(sp->history, sp->n_history);
	sp->history = NULL;
	sp->n_history = 0;
	sp->cap_history = 0;
	sp->write_ops = 0;
	sp->region_seq = 0;
}

void aik_space__set_dim(aik_space *sp, int dim)
{
	if (sp && dim > 0)
		sp->dim = dim;
}

aik_region *aik_space__new_region(aik_space *sp, const char *id,
				  const char *parent_id, int generation,
				  double created_at, char *err, size_t errlen)
{
	aik_region *r;

	if (!sp)
		return NULL;
	r = aik_region__new(sp->dim, id, parent_id, generation, created_at,
			    err, errlen);
	if (!r)
		return NULL;
	/* load 恢复的 Region 也继承注入时钟：重算几何后 last_updated=时钟 */
	aik_region__set_clock(r, sp->now_fn, sp->now_ud);
	return r;
}

int aik_space__load_vector(aik_space *sp, const char *memory_id,
			   const double *vec, char *err, size_t errlen)
{
	aik_vec_slot *slot;

	if (!sp || !memory_id || !vec) {
		set_err(err, errlen, "aik_space: invalid vector");
		return -1;
	}
	slot = vec_lookup(sp, memory_id);
	if (slot) {
		memcpy(slot->vec, vec, (size_t)sp->dim * sizeof(double));
		return 0;
	}
	return vec_insert(sp, memory_id, vec, err, errlen);
}

int aik_space__has_vector(const aik_space *sp, const char *memory_id)
{
	return sp && memory_id && vec_lookup(sp, memory_id) ? 1 : 0;
}

int aik_space__region_exists(const aik_space *sp, const char *region_id)
{
	return sp && region_id && region_find(sp, region_id) ? 1 : 0;
}

int aik_space__adopt_region(aik_space *sp, aik_region *r)
{
	size_t idx;

	if (!sp || !r)
		return -1;
	/* Python dict 语义：同 id 后者替换、保持首次插入位置 */
	idx = region_index(sp, aik_region_id(r));
	if (idx != AIK_FULL_TABLE) {
		aik_region__free(sp->regions[idx]);
		sp->regions[idx] = r;
		return 0;
	}
	return region_add(sp, r);
}

void aik_space__refresh_region(aik_space *sp, aik_region *r)
{
	if (sp && r)
		region_full_refresh(sp, r);
}

int aik_space__set_membership(aik_space *sp, const char *memory_id,
			      const aik_region *region)
{
	aik_vec_slot *slot;

	if (!sp || !memory_id)
		return -1;
	slot = vec_lookup(sp, memory_id);
	if (!slot)
		return -1;
	slot->region_id = region ? aik_region_id(region) : NULL;
	return 0;
}

int aik_space__adopt_edge(aik_space *sp, const char *a, const char *b,
			  double distance)
{
	if (!sp || !a || !b)
		return -1;
	return edge_set(sp, a, b, distance);
}

void aik_space__set_write_ops(aik_space *sp, int write_ops)
{
	if (sp)
		sp->write_ops = write_ops;
}

double aik_space__now(const aik_space *sp)
{
	return space_now(sp);
}

void aik_space__reserve_region_seq(aik_space *sp, size_t seq)
{
	if (sp && seq > sp->region_seq)
		sp->region_seq = seq;
}

