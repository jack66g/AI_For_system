/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bm25.c - 增量 BM25 关键词索引（T3a）
 *
 * 数据结构：
 *   docs[]   ：文档槽（删除后留 id=NULL 的墓碑，供 postings 下标复用）
 *   terms[]  ：token 槽，带 df 与 postings（文档下标数组）
 *   term_slots/doc_slots：开放寻址哈希表（0 = 空，存 下标+1）
 *
 * 语义对齐 REF-PY BM25Index 见 bm25.h。注意 query 中的重复 token 会重复
 * 累加（REF-PY 的 `for qt in query_tokens` 不去重）。
 *
 * 内存分配失败时函数返回 -1；索引可能处于部分更新状态（调用方应视为
 * 致命错误，不要在失败后继续查询）。
 */
#include "retrieval/bm25.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct aik_bm25_doc {
	char *id;
	char **toks;
	size_t n_toks;
};

struct aik_bm25_term {
	char *tok;
	size_t df;
	size_t *docs;
	size_t n_docs;
	size_t cap;
};

struct aik_bm25 {
	double k1;
	double b;
	int cjk_bigram;

	struct aik_bm25_doc *docs;
	size_t docs_len;	/* 已用槽数（含墓碑） */
	size_t docs_cap;
	size_t n_docs;		/* 存活文档数（Python _n_docs） */
	size_t sum_len;

	struct aik_bm25_term *terms;
	size_t n_terms;
	size_t terms_cap;

	size_t *term_slots;
	size_t term_slots_cap;

	size_t *doc_slots;
	size_t doc_slots_cap;

	size_t *marks;
	size_t marks_cap;
	size_t mark_gen;
};

static void set_err(char *err, size_t errlen, const char *msg)
{
	if (err && errlen)
		snprintf(err, errlen, "%s", msg);
}

static uint64_t str_hash(const char *s)
{
	uint64_t h = 14695981039346656037ULL;

	while (*s) {
		h ^= (unsigned char)*s++;
		h *= 1099511628211ULL;
	}
	return h;
}

static char *xstrdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = malloc(n);

	if (p)
		memcpy(p, s, n);
	return p;
}

static int cmp_str_ptr(const void *a, const void *b)
{
	const char *const *pa = (const char *const *)a;
	const char *const *pb = (const char *const *)b;

	return strcmp(*pa, *pb);
}

static char **sorted_copy(char *const *toks, size_t n)
{
	char **s = malloc((n ? n : 1) * sizeof(*s));

	if (!s)
		return NULL;
	if (n)
		memcpy(s, toks, n * sizeof(*s));
	if (n > 1)
		qsort(s, n, sizeof(*s), cmp_str_ptr);
	return s;
}

static void free_tokens(char **toks, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		free(toks[i]);
	free(toks);
}

/* ------------------------------------------------------------------ */
/* 文档表                                                              */
/* ------------------------------------------------------------------ */

static size_t doc_find(const aik_bm25 *ix, const char *id)
{
	size_t mask, i;

	if (!ix->doc_slots_cap)
		return SIZE_MAX;
	mask = ix->doc_slots_cap - 1;
	i = (size_t)str_hash(id) & mask;
	while (ix->doc_slots[i]) {
		size_t idx = ix->doc_slots[i] - 1;

		if (ix->docs[idx].id && strcmp(ix->docs[idx].id, id) == 0)
			return idx;
		i = (i + 1) & mask;
	}
	return SIZE_MAX;
}

static void doc_map_insert_raw(aik_bm25 *ix, size_t idx)
{
	size_t mask = ix->doc_slots_cap - 1;
	size_t i = (size_t)str_hash(ix->docs[idx].id) & mask;

	while (ix->doc_slots[i])
		i = (i + 1) & mask;
	ix->doc_slots[i] = idx + 1;
}

static int doc_map_reserve(aik_bm25 *ix, size_t need)
{
	size_t cap = ix->doc_slots_cap ? ix->doc_slots_cap : 16;
	size_t i;

	if (ix->doc_slots && cap >= need * 2)
		return 0;
	while (cap < need * 2)
		cap <<= 1;
	free(ix->doc_slots);
	ix->doc_slots = calloc(cap, sizeof(*ix->doc_slots));
	if (!ix->doc_slots) {
		ix->doc_slots_cap = 0;
		return -1;
	}
	ix->doc_slots_cap = cap;
	for (i = 0; i < ix->docs_len; i++)
		if (ix->docs[i].id)
			doc_map_insert_raw(ix, i);
	return 0;
}

static void doc_map_rebuild(aik_bm25 *ix)
{
	size_t i;

	if (!ix->doc_slots)
		return;
	memset(ix->doc_slots, 0, ix->doc_slots_cap * sizeof(*ix->doc_slots));
	for (i = 0; i < ix->docs_len; i++)
		if (ix->docs[i].id)
			doc_map_insert_raw(ix, i);
}

static size_t doc_slot_alloc(aik_bm25 *ix)
{
	size_t i;

	for (i = 0; i < ix->docs_len; i++)
		if (!ix->docs[i].id)
			return i;
	if (ix->docs_len == ix->docs_cap) {
		size_t cap = ix->docs_cap ? ix->docs_cap * 2 : 16;
		struct aik_bm25_doc *d = realloc(ix->docs, cap * sizeof(*d));

		if (!d)
			return SIZE_MAX;
		ix->docs = d;
		ix->docs_cap = cap;
	}
	i = ix->docs_len++;
	memset(&ix->docs[i], 0, sizeof(ix->docs[i]));
	return i;
}

/* ------------------------------------------------------------------ */
/* token 表 / postings                                                 */
/* ------------------------------------------------------------------ */

static size_t term_find(const aik_bm25 *ix, const char *tok)
{
	size_t mask, i;

	if (!ix->term_slots_cap)
		return SIZE_MAX;
	mask = ix->term_slots_cap - 1;
	i = (size_t)str_hash(tok) & mask;
	while (ix->term_slots[i]) {
		size_t idx = ix->term_slots[i] - 1;

		if (strcmp(ix->terms[idx].tok, tok) == 0)
			return idx;
		i = (i + 1) & mask;
	}
	return SIZE_MAX;
}

static int term_map_rehash(aik_bm25 *ix, size_t cap)
{
	size_t *slots = calloc(cap, sizeof(*slots));
	size_t i, mask = cap - 1;

	if (!slots)
		return -1;
	for (i = 0; i < ix->n_terms; i++) {
		size_t j = (size_t)str_hash(ix->terms[i].tok) & mask;

		while (slots[j])
			j = (j + 1) & mask;
		slots[j] = i + 1;
	}
	free(ix->term_slots);
	ix->term_slots = slots;
	ix->term_slots_cap = cap;
	return 0;
}

static int term_add(aik_bm25 *ix, const char *tok, size_t *out_idx,
		    char *err, size_t errlen)
{
	size_t idx, mask, j;

	if (ix->n_terms == ix->terms_cap) {
		size_t cap = ix->terms_cap ? ix->terms_cap * 2 : 32;
		struct aik_bm25_term *t = realloc(ix->terms,
						  cap * sizeof(*t));

		if (!t) {
			set_err(err, errlen, "out of memory");
			return -1;
		}
		ix->terms = t;
		ix->terms_cap = cap;
	}
	if (!ix->term_slots_cap || (ix->n_terms + 1) * 2 > ix->term_slots_cap) {
		size_t cap = ix->term_slots_cap ? ix->term_slots_cap : 32;

		while (cap < (ix->n_terms + 1) * 2)
			cap <<= 1;
		if (term_map_rehash(ix, cap) != 0) {
			set_err(err, errlen, "out of memory");
			return -1;
		}
	}

	idx = ix->n_terms;
	ix->terms[idx].tok = xstrdup(tok);
	if (!ix->terms[idx].tok) {
		set_err(err, errlen, "out of memory");
		return -1;
	}
	ix->terms[idx].df = 0;
	ix->terms[idx].docs = NULL;
	ix->terms[idx].n_docs = 0;
	ix->terms[idx].cap = 0;

	mask = ix->term_slots_cap - 1;
	j = (size_t)str_hash(tok) & mask;
	while (ix->term_slots[j])
		j = (j + 1) & mask;
	ix->term_slots[j] = idx + 1;
	ix->n_terms++;
	*out_idx = idx;
	return 0;
}

static int posting_add(struct aik_bm25_term *t, size_t doc)
{
	if (t->n_docs == t->cap) {
		size_t cap = t->cap ? t->cap * 2 : 4;
		size_t *d = realloc(t->docs, cap * sizeof(*d));

		if (!d)
			return -1;
		t->docs = d;
		t->cap = cap;
	}
	t->docs[t->n_docs++] = doc;
	return 0;
}

static void posting_remove(struct aik_bm25_term *t, size_t doc)
{
	size_t i;

	for (i = 0; i < t->n_docs; i++) {
		if (t->docs[i] == doc) {
			t->docs[i] = t->docs[--t->n_docs];
			return;
		}
	}
}

static void remove_doc_terms(aik_bm25 *ix, size_t idx)
{
	struct aik_bm25_doc *d = &ix->docs[idx];
	char **sorted;
	size_t i;

	if (d->n_toks == 0)
		return;
	sorted = sorted_copy(d->toks, d->n_toks);
	if (!sorted)
		return;
	for (i = 0; i < d->n_toks; i++) {
		size_t t;

		if (i > 0 && strcmp(sorted[i], sorted[i - 1]) == 0)
			continue;
		t = term_find(ix, sorted[i]);
		if (t == SIZE_MAX)
			continue;
		if (ix->terms[t].df > 0)
			ix->terms[t].df--;
		posting_remove(&ix->terms[t], idx);
	}
	free(sorted);
}

/* ------------------------------------------------------------------ */
/* 公开 API                                                            */
/* ------------------------------------------------------------------ */

aik_bm25 *aik_bm25_new(double k1, double b, int cjk_bigram,
		       char *err, size_t errlen)
{
	aik_bm25 *ix = calloc(1, sizeof(*ix));

	if (!ix) {
		set_err(err, errlen, "out of memory");
		return NULL;
	}
	ix->k1 = k1;
	ix->b = b;
	ix->cjk_bigram = cjk_bigram ? 1 : 0;
	return ix;
}

void aik_bm25_free(aik_bm25 *ix)
{
	size_t i;

	if (!ix)
		return;
	for (i = 0; i < ix->docs_len; i++) {
		free(ix->docs[i].id);
		free_tokens(ix->docs[i].toks, ix->docs[i].n_toks);
	}
	for (i = 0; i < ix->n_terms; i++) {
		free(ix->terms[i].tok);
		free(ix->terms[i].docs);
	}
	free(ix->docs);
	free(ix->terms);
	free(ix->term_slots);
	free(ix->doc_slots);
	free(ix->marks);
	free(ix);
}

int aik_bm25_add(aik_bm25 *ix, const char *id, const char *text,
		 char *err, size_t errlen)
{
	aik_token_list tl;
	char **sorted = NULL;
	size_t idx, i, n_toks;
	int existed;

	if (!ix || !id) {
		set_err(err, errlen, "index/id is NULL");
		return -1;
	}
	memset(&tl, 0, sizeof(tl));
	if (aik_tokenize(text ? text : "", ix->cjk_bigram, &tl,
			 err, errlen) != 0)
		return -1;
	n_toks = tl.count;

	idx = doc_find(ix, id);
	existed = idx != SIZE_MAX;
	if (existed) {
		remove_doc_terms(ix, idx);
		ix->sum_len -= ix->docs[idx].n_toks;
		free_tokens(ix->docs[idx].toks, ix->docs[idx].n_toks);
		free(ix->docs[idx].id);
		memset(&ix->docs[idx], 0, sizeof(ix->docs[idx]));
	} else {
		idx = doc_slot_alloc(ix);
		if (idx == SIZE_MAX) {
			aik_token_list_free(&tl);
			set_err(err, errlen, "out of memory");
			return -1;
		}
		/* 先扩容映射（此时新槽 id 仍为 NULL，不会被 rehash 收录） */
		if (doc_map_reserve(ix, ix->n_docs + 1) != 0) {
			aik_token_list_free(&tl);
			set_err(err, errlen, "out of memory");
			return -1;
		}
		ix->n_docs++;
	}

	ix->docs[idx].id = xstrdup(id);
	if (!ix->docs[idx].id) {
		aik_token_list_free(&tl);
		set_err(err, errlen, "out of memory");
		return -1;
	}
	ix->docs[idx].toks = tl.items;
	ix->docs[idx].n_toks = n_toks;
	ix->sum_len += n_toks;

	if (!existed)
		doc_map_insert_raw(ix, idx);

	sorted = sorted_copy(ix->docs[idx].toks, n_toks);
	if (!sorted && n_toks > 0) {
		set_err(err, errlen, "out of memory");
		return -1;
	}
	for (i = 0; i < n_toks; i++) {
		size_t t;

		if (i > 0 && strcmp(sorted[i], sorted[i - 1]) == 0)
			continue;
		t = term_find(ix, sorted[i]);
		if (t == SIZE_MAX) {
			if (term_add(ix, sorted[i], &t, err, errlen) != 0) {
				free(sorted);
				return -1;
			}
		}
		ix->terms[t].df++;
		if (posting_add(&ix->terms[t], idx) != 0) {
			free(sorted);
			set_err(err, errlen, "out of memory");
			return -1;
		}
	}
	free(sorted);
	return 0;
}

int aik_bm25_remove(aik_bm25 *ix, const char *id)
{
	size_t idx;

	if (!ix || !id)
		return -1;
	idx = doc_find(ix, id);
	if (idx == SIZE_MAX)
		return 0;
	remove_doc_terms(ix, idx);
	ix->sum_len -= ix->docs[idx].n_toks;
	free_tokens(ix->docs[idx].toks, ix->docs[idx].n_toks);
	free(ix->docs[idx].id);
	memset(&ix->docs[idx], 0, sizeof(ix->docs[idx]));
	ix->n_docs--;
	doc_map_rebuild(ix);
	return 0;
}

size_t aik_bm25_n_docs(const aik_bm25 *ix)
{
	return ix ? ix->n_docs : 0;
}

static double avg_len(const aik_bm25 *ix)
{
	size_t denom = ix->n_docs ? ix->n_docs : 1;

	return (double)ix->sum_len / (double)denom;
}

static double score_doc(const aik_bm25 *ix, const struct aik_bm25_doc *d,
			const aik_token_list *q, double avg)
{
	double dl = (double)d->n_toks;
	double denom_base = ix->k1 * (1.0 - ix->b +
			      ix->b * dl / (avg > 1.0 ? avg : 1.0));
	double score = 0.0;
	size_t i, t;

	for (i = 0; i < q->count; i++) {
		const char *qt = q->items[i];
		size_t f = 0, ti = term_find(ix, qt);
		double df, idf;

		for (t = 0; t < d->n_toks; t++)
			if (strcmp(d->toks[t], qt) == 0)
				f++;
		if (f == 0)
			continue;
		df = (ti == SIZE_MAX) ? 0.0 : (double)ix->terms[ti].df;
		idf = log(1.0 + ((double)ix->n_docs - df + 0.5) / (df + 0.5));
		score += idf * ((double)f * (ix->k1 + 1.0)) /
			 fmax((double)f + denom_base, 1e-9);
	}
	return score;
}

int aik_bm25_scores(aik_bm25 *ix, const aik_token_list *query,
		    const char *const *ids, size_t n_ids, int normalize,
		    double *out, char *err, size_t errlen)
{
	size_t i;
	double peak = 0.0;

	if (!ix || (!out && n_ids > 0) || (!ids && n_ids > 0)) {
		set_err(err, errlen, "invalid arguments");
		return -1;
	}
	for (i = 0; i < n_ids; i++)
		out[i] = 0.0;
	if (!query || query->count == 0 || n_ids == 0)
		return 0;
	{
		double avg = avg_len(ix);

		for (i = 0; i < n_ids; i++) {
			size_t idx = doc_find(ix, ids[i]);

			if (idx == SIZE_MAX)
				continue;
			out[i] = score_doc(ix, &ix->docs[idx], query, avg);
			if (out[i] > peak)
				peak = out[i];
		}
	}
	if (normalize && peak > 0.0) {
		for (i = 0; i < n_ids; i++)
			out[i] /= peak;
	}
	return 0;
}

struct hit {
	const char *id;
	double score;
};

static int hit_cmp(const void *pa, const void *pb)
{
	const struct hit *a = pa;
	const struct hit *b = pb;

	if (a->score > b->score)
		return -1;
	if (a->score < b->score)
		return 1;
	return strcmp(a->id, b->id);
}

struct strset {
	const char **slots;
	size_t cap;
};

static int strset_build(struct strset *s, const char *const *items, size_t n)
{
	size_t cap = 16, i;

	while (cap < n * 2)
		cap <<= 1;
	s->slots = calloc(cap, sizeof(*s->slots));
	if (!s->slots) {
		s->cap = 0;
		return -1;
	}
	s->cap = cap;
	for (i = 0; i < n; i++) {
		size_t j = (size_t)str_hash(items[i]) & (cap - 1);

		while (s->slots[j])
			j = (j + 1) & (cap - 1);
		s->slots[j] = items[i];
	}
	return 0;
}

static int strset_has(const struct strset *s, const char *k)
{
	size_t j;

	if (!s->cap)
		return 0;
	j = (size_t)str_hash(k) & (s->cap - 1);
	while (s->slots[j]) {
		if (strcmp(s->slots[j], k) == 0)
			return 1;
		j = (j + 1) & (s->cap - 1);
	}
	return 0;
}

static int marks_reserve(aik_bm25 *ix, size_t n)
{
	size_t cap, i;
	size_t *m;

	if (ix->marks_cap >= n)
		return 0;
	cap = ix->marks_cap ? ix->marks_cap : 16;
	while (cap < n)
		cap <<= 1;
	m = realloc(ix->marks, cap * sizeof(*m));
	if (!m)
		return -1;
	for (i = ix->marks_cap; i < cap; i++)
		m[i] = 0;
	ix->marks = m;
	ix->marks_cap = cap;
	return 0;
}

int aik_bm25_top(aik_bm25 *ix, const char *query_text, size_t limit,
		 const char *const *allowed, size_t n_allowed,
		 char ***out_ids, size_t *out_n, char *err, size_t errlen)
{
	aik_token_list q;
	struct strset set;
	struct hit *hits = NULL;
	size_t n_hits = 0, hits_cap = 0;
	size_t *cands = NULL;
	size_t n_cands = 0;
	double avg;
	size_t i, j, take, total;
	char **block;

	if (!out_ids || !out_n) {
		set_err(err, errlen, "out_ids/out_n is NULL");
		return -1;
	}
	*out_ids = NULL;
	*out_n = 0;
	if (!ix) {
		set_err(err, errlen, "index is NULL");
		return -1;
	}
	memset(&q, 0, sizeof(q));
	memset(&set, 0, sizeof(set));
	if (aik_tokenize(query_text ? query_text : "", ix->cjk_bigram, &q,
			 err, errlen) != 0)
		return -1;

	if (q.count == 0 || ix->n_docs == 0 || limit == 0)
		goto done;

	if (marks_reserve(ix, ix->docs_len) != 0) {
		set_err(err, errlen, "out of memory");
		goto fail;
	}
	ix->mark_gen++;
	if (ix->mark_gen == 0) {
		for (i = 0; i < ix->marks_cap; i++)
			ix->marks[i] = 0;
		ix->mark_gen = 1;
	}
	cands = malloc((ix->n_docs ? ix->n_docs : 1) * sizeof(*cands));
	if (!cands) {
		set_err(err, errlen, "out of memory");
		goto fail;
	}
	for (i = 0; i < q.count; i++) {
		size_t t = term_find(ix, q.items[i]);

		if (t == SIZE_MAX)
			continue;
		for (j = 0; j < ix->terms[t].n_docs; j++) {
			size_t d = ix->terms[t].docs[j];

			if (ix->marks[d] == ix->mark_gen)
				continue;
			ix->marks[d] = ix->mark_gen;
			cands[n_cands++] = d;
		}
	}

	if (allowed && strset_build(&set, allowed, n_allowed) != 0) {
		set_err(err, errlen, "out of memory");
		goto fail;
	}
	avg = avg_len(ix);
	for (i = 0; i < n_cands; i++) {
		struct aik_bm25_doc *d = &ix->docs[cands[i]];
		double s;

		if (!d->id)
			continue;
		if (allowed && !strset_has(&set, d->id))
			continue;
		s = score_doc(ix, d, &q, avg);
		if (!(s > 0.0))
			continue;
		if (n_hits == hits_cap) {
			size_t cap = hits_cap ? hits_cap * 2 : 16;
			struct hit *h = realloc(hits, cap * sizeof(*h));

			if (!h) {
				set_err(err, errlen, "out of memory");
				goto fail;
			}
			hits = h;
			hits_cap = cap;
		}
		hits[n_hits].id = d->id;
		hits[n_hits].score = s;
		n_hits++;
	}
	if (n_hits > 1)
		qsort(hits, n_hits, sizeof(*hits), hit_cmp);

	take = n_hits < limit ? n_hits : limit;
	if (take == 0)
		goto done;
	total = (size_t)take * sizeof(char *);
	for (i = 0; i < take; i++) {
		size_t len = strlen(hits[i].id) + 1;

		if (total > (size_t)-1 - len) {
			set_err(err, errlen, "result too large");
			goto fail;
		}
		total += len;
	}
	block = malloc(total);
	if (!block) {
		set_err(err, errlen, "out of memory");
		goto fail;
	}
	{
		char *p = (char *)(block + take);

		for (i = 0; i < take; i++) {
			size_t len = strlen(hits[i].id) + 1;

			block[i] = p;
			memcpy(p, hits[i].id, len);
			p += len;
		}
	}
	*out_ids = block;
	*out_n = take;

done:
	free(hits);
	free(cands);
	free(set.slots);
	aik_token_list_free(&q);
	return 0;

fail:
	free(hits);
	free(cands);
	free(set.slots);
	aik_token_list_free(&q);
	return -1;
}
