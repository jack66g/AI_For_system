/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bm25.h - 增量 BM25 关键词索引（T3a）
 *
 * 对齐 REF-PY sme/retrieval/retriever.py::BM25Index：
 *   df / postings / sum_len / n_docs 增量维护，add 覆盖同 id（先撤旧 token），
 *   remove 对未知 id 静默返回 0；
 *   idf(t) = ln(1 + (N - df + 0.5) / (df + 0.5))；
 *   score(d) = Σ_t idf(t) * f*(k1+1) / max(f + k1*(1-b+b*dl/max(avg,1)), 1e-9)，
 *   只累加 f>0 的 query token（query 中的重复 token 重复累加，与 REF-PY 一致）；
 *   normalize=true 时除以候选池峰值（峰值 0 则不动）；
 *   top 只保留至少命中一个 query token 的文档，按 (-score, id) 排序取前 limit。
 */
#ifndef _AIK_BM25_H
#define _AIK_BM25_H

#include <stddef.h>

#include "text.h"

typedef struct aik_bm25 aik_bm25;

/* 新建索引；k1/b 与 REF-PY 默认 1.5/0.75 一致。失败 NULL 并写 err */
aik_bm25 *aik_bm25_new(double k1, double b, int cjk_bigram,
		       char *err, size_t errlen);

/* 释放索引（NULL 安全） */
void aik_bm25_free(aik_bm25 *ix);

/* 新增/覆盖文档；成功 0，失败 -1 并写 err */
int aik_bm25_add(aik_bm25 *ix, const char *id, const char *text,
		 char *err, size_t errlen);

/* 删除文档（不存在时也返回 0） */
int aik_bm25_remove(aik_bm25 *ix, const char *id);

/* 当前文档数 */
size_t aik_bm25_n_docs(const aik_bm25 *ix);

/*
 * aik_bm25_scores - 按调用方 ids 顺序输出分数
 *
 * query 里出现的 token 才参与打分；out 需有 n_ids 项。
 * 成功 0，参数非法 -1。
 */
int aik_bm25_scores(aik_bm25 *ix, const aik_token_list *query,
		    const char *const *ids, size_t n_ids, int normalize,
		    double *out, char *err, size_t errlen);

/*
 * aik_bm25_top - 词法召回 top-N
 *
 * allowed 为 NULL 时不过滤，否则只保留其中 id。返回的 *out_ids 是一整块
 * malloc 内存（指针数组 + 字符串本体连续存放），free(*out_ids) 即全部释放；
 * 无结果时 *out_ids=NULL、*out_n=0。成功 0，失败 -1。
 */
int aik_bm25_top(aik_bm25 *ix, const char *query_text, size_t limit,
		 const char *const *allowed, size_t n_allowed,
		 char ***out_ids, size_t *out_n, char *err, size_t errlen);

#endif /* _AIK_BM25_H */
