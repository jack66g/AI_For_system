/* SPDX-License-Identifier: GPL-2.0 */
/*
 * engine.h - T4a SpatialMemoryEngine 核心（进程内 facade）
 *
 * 对齐 REF-PY e72bc75（SME 1.3.0）：
 *   - sme/engine.py::SpatialMemoryEngine（add / search / reinforce /
 *     archive / restore / stats / export / import / load）
 *   - sme/memory_manager.py（add_memory / _register / archive / restore /
 *     reinforce / stats）
 *   - sme/models.py（Memory / Region / SearchHit / ScoreBreakdown /
 *     MemoryStats / RegionStats 的 to_dict 键序）
 *
 * 本接口是**进程内**契约：没有 HTTP 传输、没有路由层校验（T4b）、没有
 * WAL（T4c）与后台线程。所有子系统沿用 L1 既有实现：
 *   smeconfig（配置）/ space（Region + 空间）/ retrieval（两阶段检索）/
 *   store（JSON DOM + 快照 + NPZ）/ memory（hashing 嵌入）。
 *
 * 生命周期与所有权：
 *   - aik_engine_new 接管 cfg（take_ownership 非 0）或借用（=0）；cfg 为
 *     NULL 时内部构造默认配置并拥有它。
 *   - aik_engine_load 成功后引擎配置整体换成快照里的 config（与 Python
 *     _load_locked 一致），原借用配置不被释放。
 *   - 所有返回 aik_memory* 的接口都是**借用**，随引擎失效；调用者不得
 *     free。返回的 aik_json* 由调用者 aik_json_free。
 *   - 引擎无全局状态；单线程使用（T4b 再包锁）。
 *
 * 错误约定：返回 -1 表示失败且 err 已写原因（err 可为 NULL/errlen=0）；
 * reinforce/archive/restore 用 0=成功、1=不存在或状态不符、-1=错误。
 */
#ifndef _AIK_ENGINE_ENGINE_H
#define _AIK_ENGINE_ENGINE_H

#include <stddef.h>

#include "retrieval/retriever.h"
#include "smeconfig/config.h"
#include "store/store_json.h"

/* 时钟：返回 unix 秒。NULL 时引擎退回 time(NULL) */
typedef double (*aik_now_fn)(void *ud);

/*
 * id 生成器：prefix 为 "m"（记忆）或 "r"（Region），成功时把
 * "<prefix>_" + 12 位小写十六进制 + NUL 写进 out[16]（共 15 字节）并
 * 返回 0。NULL 时引擎使用内置自增生成器（"m_%012llx"）。
 */
typedef int (*aik_id_fn)(void *ud, const char *prefix, char out[16]);

typedef struct aik_engine aik_engine;

/*
 * 一条记忆记录。字段与 sme/models.py::Memory 一一对应，字符串与数组
 * 全部归引擎所有；aik_memory_to_json 只读。
 */
typedef struct aik_memory {
	char *id;
	char *text;
	aik_json *metadata;		/* 自有 OBJ（永不为 NULL） */
	double created_at;
	double last_hit;
	long long hit_count;
	double weight;
	double importance;
	double freshness;
	double decay_factor;
	char *region_id;		/* 自有，可为 NULL */
	char **neighbors;		/* 自有字符串数组（to_json 时排序） */
	size_t n_neighbors;
	char **tags;
	size_t n_tags;
	char *summary;			/* 可为 NULL */
	long long version;
	char *parent_id;		/* 可为 NULL */
	char **children;
	size_t n_children;
	int archived;
	char *source;
	double *embedding;		/* 自有，可为 NULL */
	int dim;
} aik_memory;

/*
 * aik_engine_new - 创建引擎
 *
 * 解析配置（embedding/region/retrieval/ranking/decay/policy…），建 space
 * 与 retriever，并做 §3.6 的 region.min_join_cosine 校准。失败返回 NULL。
 *
 * 明确拒绝的配置（fail closed，不静默降级）：
 *   - embedding.provider != "hashing"：T4a 只有 hashing 本地嵌入；
 *   - persistence.enabled 为真：WAL 尚未接线（T4c）。
 */
aik_engine *aik_engine_new(aik_config *cfg, int take_ownership,
			   aik_now_fn now, void *now_ud,
			   aik_id_fn id, void *id_ud,
			   char *err, size_t errlen);
void aik_engine_free(aik_engine *e);

/*
 * aik_engine_load - 读 T2 快照（engine.json.gz/明文 + NPZ sidecar）
 *
 * 对齐 sme/engine.py::_load_locked：
 *   - 快照 config 覆盖当前配置（随后重建 space 的 region 参数与维度）；
 *   - memories 按快照插入序恢复（Memory.from_dict 语义）；
 *   - NPZ sidecar 按快照 embedding_file（basename，必须与快照同目录且
 *     存在）读取，embedding_generation 与 NPZ generation 校验；
 *   - space 用 aik_space_load_state 恢复 regions/region_edges（只传
 *     非 archived 向量），**不重新聚类**；archived 的 region_id 置 NULL；
 *   - memory_edges 原样恢复；counters（splits/merges/consolidations/
 *     compressions）恢复（Python 把 splits/merges 写回 region_manager）。
 * 成功 0，失败 -1 且引擎保持调用前状态。
 */
int aik_engine_load(aik_engine *e, const char *path, char *err, size_t errlen);

/*
 * aik_engine_import - 批量导入 export 形状的记忆（引擎 §3.2）
 *
 * 空 text 跳过且不计数；缺省字段按 Memory.from_dict 补齐；已有向量逐位
 * 保留（缺失才用当前 provider 重编码）；archived 只进 memories + 冷存档。
 * 整批 space.set_bulk(True) 抑制逐条演化，结束后若 auto_evolve 且
 * write_ops>0 调一次 evolution_pass。成功 0，*out_count 为导入条数。
 */
int aik_engine_import(aik_engine *e, const aik_json *items,
		      long long *out_count, char *err, size_t errlen);

/*
 * aik_engine_add - 新增一条记忆（sme/memory_manager.py::add_memory）
 *
 * text 为 NULL/空/Unicode 全空白 → -1。metadata 借用（NULL 视为 {}），
 * 内部深拷贝后若 ns 非 NULL 追加 metadata["ns"]。importance 先 clamp 到
 * [0,1]。source 为 NULL 时取 "user"。link_to 非 NULL 时在 graph 里加一条
 * new -> link_to / link_kind / weight=1 / note="" 的边。
 */
aik_memory *aik_engine_add(aik_engine *e, const char *text,
			   const aik_json *metadata,
			   const char *const *tags, size_t n_tags,
			   double importance, const char *source,
			   const char *link_to, const char *link_kind,
			   const char *ns, const char *conversation_id,
			   char *err, size_t errlen);

aik_memory *aik_engine_get(aik_engine *e, const char *id);
size_t aik_engine_memory_count(const aik_engine *e);
aik_memory *aik_engine_memory_at(const aik_engine *e, size_t i);

/*
 * aik_engine_reinforce - Ebbinghaus 强化（sme/dynamics/reinforcement.py）
 *
 * retention = age<=0 ? 1 : 1/(1+(age/max(half_life,1e-9))^max(power,0.1))；
 * weight/importance 按 delta*retention 增加并 clamp，last_hit=now、
 * freshness=1、version+1。*out_result 为 4 个 round(x,4) + hit_count 的
 * OBJ（键序 memory_id,retention,weight_delta,importance_delta,hit_count）。
 */
int aik_engine_reinforce(aik_engine *e, const char *id,
			 aik_json **out_result, char *err, size_t errlen);

/* archive：移出 space、archived=1、进冷存档；已归档/不存在返回 1 */
int aik_engine_archive(aik_engine *e, const char *id);
/* restore：重新插入 space、archived=0、移出冷存档；未归档/不存在返回 1 */
int aik_engine_restore(aik_engine *e, const char *id);

/*
 * aik_engine_search - 两阶段检索（sme/engine.py::_search_locked）
 *
 * views 含活跃 + archived（可见性由 retriever 判）；query 向量用同一
 * hashing provider 复算。min_similarity > -1 时按原始余弦过滤后截断
 * requested_k。ns 由调用方先合并进 q->metadata_filters["ns"]（本层没有
 * ns 参数，与 T4b 路由层一致）。
 * 成功 0，*out 为单块 malloc（aik_search_hits_free 释放）；q->top_k<=0
 * 时 *out=NULL、*n_out=0。
 */
int aik_engine_search(aik_engine *e, const aik_search_query *q,
		      aik_search_hit **out, size_t *n_out,
		      char *err, size_t errlen);

/* memory_stats + region_stats + engine_stats（键序 = Python to_dict） */
int aik_engine_stats(aik_engine *e, aik_json **out, char *err, size_t errlen);

/* /export 形状：{memories:[to_dict(include_embedding=true)], graph, stats} */
int aik_engine_export(aik_engine *e, aik_json **out, char *err, size_t errlen);

/* /regions 形状：{count, regions:[Region.to_dict…]}（Region 插入序） */
int aik_engine_regions(aik_engine *e, aik_json **out, char *err, size_t errlen);

/*
 * aik_engine_save - T4c 才实现（NPZ 写侧）
 *
 * 一律返回 -1 并写「save 未启用（NPZ 写侧 T4c）」，绝不写半成品。
 */
int aik_engine_save(aik_engine *e, const char *path, char *err, size_t errlen);

/*
 * aik_memory_to_json - Memory.to_dict 的逐键逐序复刻
 *
 * id,text,metadata,created_at,last_hit,hit_count,weight,importance,
 * freshness,decay_factor,region_id,neighbors(sorted),tags,summary,version,
 * parent_id,children,archived,source[,embedding]。返回新 DOM（调用者
 * aik_json_free）。include_embedding 且 embedding 非 NULL 时才带向量。
 */
aik_json *aik_memory_to_json(const aik_memory *m, int include_embedding);

/*
 * aik_search_hit_to_json - SearchHit.to_dict（memory 19 键无向量）
 *
 * memory.to_dict(include_embedding=0) 之后按 Python dict 赋值语义追加：
 * score、breakdown（9 键）、region_id（原位覆盖）、region_score、
 * keyword_score、vector_score、metadata_match。memory_id 必须仍存在。
 */
aik_json *aik_search_hit_to_json(aik_engine *e, const aik_search_hit *hit);

#endif /* _AIK_ENGINE_ENGINE_H */
