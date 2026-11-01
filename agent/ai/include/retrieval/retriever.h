/* SPDX-License-Identifier: GPL-2.0 */
/*
 * retriever.h - T3b 两阶段检索（候选池 + 双通道 + hybrid + 图扩展）
 *
 * 逐条对齐 REF-PY sme/retrieval/retriever.py（SME 1.3.0, e72bc75）：
 *
 *   阶段 1：aik_space_query_regions(query_vec, top_regions) 得 Region 命中；
 *   阶段 2：top-N Region 成员 + 全局余弦补池（pool_target =
 *           max(top_k*2, candidate_window)）+ 可选 BM25 全局召回，
 *           组成候选集，过滤后按 fusion 模式计算 vector/keyword 通道分，
 *           hybrid 作为 semantic 交给 aik_rank_score()；
 *   可选图扩展：graph_expand>0 且存在边时，PPR 主路 / 小图 BFS 退化。
 *
 * 语义要点（T3B-DESIGN.md §2.9-2.10）：
 *   - 全局补池按余弦 stable 升序 argsort 后反向取 budget（同分后出现者
 *     优先）；补池与 BM25 召回的 region_score 用
 *     region_scores.setdefault(region_id or "", region_dampening)；
 *   - minmax：vector 在候选池内 min-max（全等 0.5），keyword 只在 raw>0
 *     子集内 min-max，metadata 权重的比例折算进 v/k；
 *     weighted：vector 用 (cos+1)/2 裁剪、keyword 除以池峰值、metadata
 *     常量权重；
 *   - 排序 (score desc, memory_id asc)（Python 同分是 set 迭代序）；
 *     仅最终 top-k 重算 detailed breakdown；summary 惩罚先作用于 score，
 *     再作用于 breakdown.final（先 round 后乘）；
 *   - 图扩展的扩展候选在**扩展子集内**重新归一化通道分；
 *     PPR 边 < 5 退化 BFS；合并 reserved = max(1, top_k//5) 且
 *     min(reserved, max(0, top_k-1))。
 *
 * 无全局状态；所有错误写 err 并返回 -1。
 */
#ifndef _AIK_RETRIEVAL_RETRIEVER_H
#define _AIK_RETRIEVAL_RETRIEVER_H

#include <stddef.h>

#include "retrieval/ranker.h"
#include "space/space.h"
#include "store/store_json.h"

/* 通道归一化模式：weighted=0（legacy）、minmax=1（默认） */
typedef enum {
	AIK_FUSION_WEIGHTED = 0,
	AIK_FUSION_MINMAX = 1
} aik_fusion;

/* RetrievalConfig（sme/config.py:53-79）；summary_penalty 默认 0.5 */
typedef struct {
	int top_regions;
	int top_k;
	double vector_weight;
	double keyword_weight;
	double metadata_weight;
	double region_dampening;
	double summary_penalty;
	int cjk_bigram;
	int candidate_window;
	aik_fusion fusion;
	int keyword_candidates;
} aik_retrieval_config;

/* 记忆图边（借用，与 engine.graph.edges 的插入序一致） */
typedef struct {
	const char *source;
	const char *target;
	const char *kind;
	double weight;
} aik_graph_edge;

/*
 * 检索请求（SearchQuery）
 *
 * top_regions: >=0 为显式覆盖；-1 表示回退 region_retrieval / config。
 * region_retrieval: 0=off，1..5=topN（Python "top1"/"top3"/"top5"）。
 * metadata_filters: store_json OBJ 或 NULL；tags: 任一命中即可。
 */
typedef struct {
	const char *text;
	int top_k;
	int top_regions;
	const aik_json *metadata_filters;
	const char *const *tags;
	size_t n_tags;
	int region_retrieval;
	int graph_expand;
	int include_archived;
} aik_search_query;

/* 命中（memory_id/region_id 均为 malloc，调用者用 aik_search_hits_free） */
typedef struct {
	char *memory_id;
	double score;
	char *region_id;
	double region_score;
	double keyword_score;
	double vector_score;
	int metadata_match;
	aik_score_breakdown breakdown;
} aik_search_hit;

/*
 * 一次检索的只读上下文
 *
 * space 用于阶段 1 与 region 归属；memories 按引擎 dict 插入序给出（全局
 * 补池的 tie 语义依赖该顺序）；edges 按 graph.edges 插入序；query_vector
 * 由调用方生成（测试用 aik_hash_embed_one 复算）；policy 三字段等价于
 * engine.policy（archived 恒不允许，除非 include_archived）。
 */
typedef struct {
	aik_space *space;
	const aik_memory_view *memories;
	size_t n_memories;
	const aik_graph_edge *edges;
	size_t n_edges;
	const double *query_vector;
	int dim;
	const aik_retrieval_config *cfg;
	const aik_ranking_weights *weights;
	const aik_decay_config *decay;
	int policy_full_memory;
	double policy_importance_threshold;
	double reference;
} aik_search_ctx;

typedef struct aik_retriever aik_retriever;

/* 创建检索器（cfg 为 NULL 时用 RetrievalConfig 默认值） */
aik_retriever *aik_retriever_new(const aik_retrieval_config *cfg,
				 char *err, size_t errlen);
void aik_retriever_free(aik_retriever *r);

/* 重建 BM25 索引：只索引 !archived 的记忆；重复调用会整体替换旧索引 */
int aik_retriever_index(aik_retriever *r, const aik_memory_view *mems,
			size_t n, char *err, size_t errlen);

/*
 * aik_retriever_search - 两阶段检索
 *
 * 成功 0，*out 为单块 malloc 的命中数组（按返回顺序），*n_out 为条数；
 * top_k<=0 或无候选时 *out=NULL、*n_out=0。失败 -1 并写 err。
 */
int aik_retriever_search(aik_retriever *r, const aik_search_ctx *ctx,
			 const aik_search_query *q,
			 aik_search_hit **out, size_t *n_out,
			 char *err, size_t errlen);
void aik_search_hits_free(aik_search_hit *hits, size_t n);

#endif /* _AIK_RETRIEVAL_RETRIEVER_H */
