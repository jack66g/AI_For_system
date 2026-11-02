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
 * 后台线程。WAL（T4e-D）只接 file backend + sync_mode=fsync（懒打开，
 * 单线程内同步 write+fsync）；sqlite/grouped 明确拒绝。
 * 所有子系统沿用 L1 既有实现：
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
 *   - persistence.enabled 且 storage.backend=sqlite：sqlite WAL 未接线
 *     （T4e-D 只接 file backend）；
 *   - persistence.enabled 且 persistence.sync_mode != "fsync"：grouped
 *     （后台组提交线程）等模式未接线。
 * persistence.enabled + storage.backend=json + sync_mode=fsync 已真实可用：
 * WAL 路径 = persistence.wal_path（非空）否则 storage.path + ".wal"；
 * WAL 懒打开（首次 append 才建文件），每条记录一次 write + fsync。
 */
aik_engine *aik_engine_new(aik_config *cfg, int take_ownership,
			   aik_now_fn now, void *now_ud,
			   aik_id_fn id, void *id_ud,
			   char *err, size_t errlen);
void aik_engine_free(aik_engine *e);

/* 借用当前配置（只读语义；路由 / 启动期覆盖使用） */
aik_config *aik_engine_config(aik_engine *e);

/*
 * aik_engine_rebuild - 配置热重建（PUT /config 的 export→new→import→swap）
 *
 * 对齐 sme/api/server.py::rebuild_engine_with：
 *   1) 旧库非空且 embedding 身份变化 → 拒绝（返回 1，err 为可直接展示的
 *      中文提示）。身份 = provider/model/dim **加** mrl_dim/revision/
 *      hash_factors/hash_seed（TASK-BOOK §7.3 的有意修正；上游只比前三项）；
 *   2) 旧引擎 export（memories 含向量 + graph）→ 新引擎 import →
 *      原样恢复图边与计数器（splits/merges/consolidations/compressions）；
 *   3) 成功返回 0，*out 为新引擎（**接管 new_cfg 所有权**，调用者负责
 *      free 旧引擎与释放旧配置的所有权关系）；失败返回 -1，err 为
 *      "应用配置失败，引擎保持原配置：..." 或具体原因；**new_cfg 一律被
 *      接管/释放**（调用方不要 free）。
 * 任何失败都不修改旧引擎。
 */
int aik_engine_rebuild(aik_engine *old, aik_config *new_cfg,
		       aik_engine **out, char *err, size_t errlen);

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
 *     compressions）恢复（Python 把 splits/merges 写回 region_manager）；
 *   - WAL（T4e-D）：快照 wal_sequence 作为 checkpoint，replay 跳过
 *     seq<=checkpoint（seq=0 总是重放），按参考 wal._apply 应用
 *     add/transaction（不重复写 WAL、不触发 autosave）；重放条数 >0 时
 *     立即 checkpoint（save）。replay 失败返回 -1，err 含
 *     "WAL replay failed at record N; log retained"，日志文件原样保留。
 * 成功 0，失败 -1 且引擎保持调用前状态（提交后的 WAL 重放失败除外：
 * 引擎已载入快照，与参考 load() 抛 WALRecoveryError 的状态一致）。
 */
int aik_engine_load(aik_engine *e, const char *path, char *err, size_t errlen);

/*
 * aik_engine_import - 批量导入 export 形状的记忆（引擎 §3.2）
 *
 * 空 text 跳过且不计数；缺省字段按 Memory.from_dict 补齐；已有向量逐位
 * 保留（缺失才用当前 provider 重编码）；archived 只进 memories + 冷存档。
 * 整批 space.set_bulk(True) 抑制逐条演化，结束后若 auto_evolve 且
 * write_ops>0 调一次 evolution_pass。成功 0，*out_count 为导入条数。
 *
 * WAL（T4e-D）：bulk import 不逐条写 WAL（参考同）；persistence.enabled
 * 时导入完成立即 checkpoint（aik_engine_save → storage.path），否则走
 * 非 WAL 的 autosave 计数。
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
 * aik_engine_update - 记忆 PATCH（sme/memory_manager.py::update_memory）
 *
 * patch 为 JSON 对象（借用；NULL 视为 {}）。可含 text / metadata / tags /
 * importance / weight / summary；键缺失或值为 null 表示"不改"。语义逐条
 * 对齐参考：
 *   - text：仅当 `patch.text.strip() != memory.text` 才算变化（落盘文本仍
 *     是 patch 原文）；变化时重编码 → space.remove + space.insert → 更新
 *     text / embedding / region_id；
 *   - metadata：整字典替换，但 patch 不带 "ns" 时保留旧 metadata["ns"]；
 *     metadata-only 变化不 touched；
 *   - tags 整列表替换；importance clamp 到 [0,1]；weight 下限 0；
 *     summary 允许置 ""（与 NULL 不同）。
 * 有实质变化才 touched（last_hit=now、freshness=1、version+1）；实质变化
 * 或 metadata 变化都会重建 BM25 索引。
 *
 * 返回 0=成功（用 aik_engine_get 取更新后的记忆）、1=id 不存在、-1=错误。
 * 类型不符（tags 非字符串数组等）按 -1 处理（route 层已做 422 校验）。
 */
int aik_engine_update(aik_engine *e, const char *id, const aik_json *patch,
		      char *err, size_t errlen);

/*
 * aik_engine_delete - 删除记忆（含派生摘要级联）
 *
 * 对齐 sme/memory_manager.py::delete_memory：
 *   - 先删 source=="summary" 且（目标 id 在其 children 或 metadata.covers
 *     包含目标 id）的派生记忆（递归级联）；
 *   - space.remove、删除所有涉及该 id 的 graph 边；
 *   - 其他记忆的 neighbors/children 去掉该 id，parent_id 指向它时置 NULL；
 *   - 重建 BM25 索引（Python 的 retriever.drop_memory 的全量等价）。
 * 返回 0=删除、1=id 不存在、-1=错误（err 已写）。
 */
int aik_engine_delete(aik_engine *e, const char *id, char *err, size_t errlen);

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

/*
 * aik_engine_search_regions - 仅 Region 阶段（engine.search_regions）
 *
 * hashing 编码查询文本后调 aik_space_query_regions（分数/排序/取整一致）。
 * *out 为**单块 malloc**（调用者 free()），其中 aik_region_hit.region 借用
 * 引擎内部 Region（在下一次修改 space 前有效）；top_k<=0 或没有 Region 时
 * *out=NULL、*n_out=0。成功 0，-1 错误。
 */
int aik_engine_search_regions(aik_engine *e, const char *text, int top_k,
			      aik_region_hit **out, size_t *n_out,
			      char *err, size_t errlen);

/* memory_stats + region_stats + engine_stats（键序 = Python to_dict） */
int aik_engine_stats(aik_engine *e, aik_json **out, char *err, size_t errlen);

/* /export 形状：{memories:[to_dict(include_embedding=true)], graph, stats} */
int aik_engine_export(aik_engine *e, aik_json **out, char *err, size_t errlen);

/* /regions 形状：{count, regions:[Region.to_dict…]}（Region 插入序） */
int aik_engine_regions(aik_engine *e, aik_json **out, char *err, size_t errlen);

/*
 * aik_engine_evolve - 一次演化（/regions/evolve）
 *
 * 调 aik_space_evolution_pass；返回 {"events":[{"kind","region_id",
 * "detail"}]}，detail 用 Python 原格式：
 *   split        "{keep} -> {other} members (density %.1f)"（density 为拆分前）
 *   merge        "absorbed {absorbed_id} ({n} members)"
 *   region_created "{n} members"
 *   region_deleted ""
 * region_id 是真实 Region id。*out 由调用者 aik_json_free；成功 0。
 */
int aik_engine_evolve(aik_engine *e, aik_json **out, char *err, size_t errlen);

/*
 * aik_engine_graph - 记忆图（MemoryEdge.to_dict 键序）
 *
 * {"edges":[{source,target,kind,weight,note}...]}，顺序即边插入序。
 */
int aik_engine_graph(aik_engine *e, aik_json **out, char *err, size_t errlen);

/*
 * aik_engine_link - 建一条记忆图边（sme/memory_manager.py::link）
 *
 * kind 为 NULL 时取 "reference"，note 为 NULL 时取 ""。kind=="cause" 时
 * 额外加反向边 b -> a / "conversation" / weight=1 / note="timeline"。
 * 不修改 Memory.neighbors。返回 0=成功、1=a 或 b 不存在、-1=错误
 * （a==b 自环也按 -1 处理，Python 抛 ValueError）。
 */
int aik_engine_link(aik_engine *e, const char *a, const char *b,
		    const char *kind, double weight, const char *note,
		    char *err, size_t errlen);

/*
 * aik_engine_save - 写快照（JSON[.gz] + NPZ sidecar）
 *
 * 对齐 sme/engine.py::_save_locked + sme/storage/snapshot.py::save_snapshot：
 *   1) space.sync_geometry()；config 副本的 embedding.revision_stamp =
 *      embedding_revision(config)（provider|model|dim[|mrlN][|seedN][|rev]）；
 *   2) 快照键序 schema_version,counters,config,memories(无向量),regions,
 *      region_edges,memory_edges,module_state,wal_sequence,
 *      [embedding_file,embedding_generation]；
 *   3) 有向量时写 "<embedding_base>.<32hex>.npz"（见 store_npz_write.h），
 *      JSON 追加两个 embedding_* 键（basename / 代次）；
 *   4) path 以 .gz 结尾或（storage.compress && 以 .json 结尾）时 gzip；
 *      .json 且 compress 时自动补 .gz（与 Python 一致）；父目录 mkdir -p；
 *      aik_snapshot_save 原子写（tmp → fsync → rename → dir fsync）；
 *   5) 成功后删除同前缀 "<stem>.embeddings.<32hex>.npz" 中未被当前明文/
 *      gzip 清单引用的旧代次（失败不影响保存成功）。
 *
 * path 为 NULL/空时用 config.storage.path。成功 0 并把 autosave 计数器
 * 清零；失败 -1（err 已写，绝不留下半成品 JSON；本次新 NPZ 会尽力删除）。
 * 空库（没有向量）不写 NPZ、不写 embedding_* 键。
 *
 * WAL（T4e-D）：快照 wal_sequence = 当前 WAL 序号（未启用时为 0，字节与
 * 旧版快照一致）。仅当保存路径与 config.storage.path 等价（abspath 归一
 * 后去掉 ".json.gz"）且 WAL 启用时 checkpoint：checkpoint_sequence = seq、
 * autosave 计数清零、checkpointed++、WAL 截断（seq 保留）。保存到其他
 * 路径（export）不截断 WAL。WAL 截断失败 → 保存返回 -1（日志保留）。
 */
int aik_engine_save(aik_engine *e, const char *path, char *err, size_t errlen);

/*
 * aik_engine_wal_stats - WAL 运行状态（只读快照）
 *
 * 键序：enabled, path, sync_mode, sequence, checkpoint_sequence,
 * pending_ops, replayed, checkpointed。未启用 WAL 时 enabled=false、
 * path=""、sequence/checkpoint_sequence=0。用于自测与后续 HTTP 观测；
 * 成功 0，*out 由调用者 aik_json_free。
 */
int aik_engine_wal_stats(const aik_engine *e, aik_json **out,
			 char *err, size_t errlen);

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

/*
 * aik_engine_consolidate - 记忆融合（sme/dynamics/consolidation.py）
 *
 * 按 space.regions 插入序找组（每组 <= consolidation.max_group_size）：
 *   - Region 成员（member_ids 序）过滤 archived / source=="summary"；
 *   - 按 metadata["ns"] 的 str() 分桶，桶内 importance 降序后贪心聚类
 *     （余弦 >= consolidation.similarity_threshold），簇 >= 3 才成组；
 *   - 小桶（<= max_group_size）覆盖率 < 0.6 且整体连贯时整桶融合；
 *   - 最多 20 组；已有 summary 的 covers 集合相同的组跳过（幂等）。
 * 每组生成一条 summary 记忆（source="summary"、tags=["summary"]、
 * importance=0.75，走正常 add 管线：嵌入/space/id/时钟），把成员挂为
 * children 并加 parent/summary 图边；metadata 追加 covers(sorted)、
 * consolidated_at，组内唯一非空 ns 时写 ns。template 摘要文本与参考
 * _template_summary/_common_tokens 逐字一致（本阶段无 LLM，summary_source
 * =="llm" 时同样走 template）。
 *
 * 成功 0，*out_created 为 {"created":[...]} 形状的 ARR（创建序，元素为
 * memory.to_dict(include_embedding=1)），调用者 aik_json_free；失败 -1
 * （err 已写）。结束后 e->consolidations 自增并执行一次 autosave（与
 * Python consolidate() 的单次 _autosave 一致）。
 */
int aik_engine_consolidate(aik_engine *e, aik_json **out_created,
			   char *err, size_t errlen);

/*
 * aik_engine_compress - 长期压缩（sme/dynamics/compression.py）
 *
 * 遍历 Region（插入序）：size >= compression.min_region_compact、
 * 尚未被本 Region 的 summary 压缩（metadata.compresses_region）时，取
 * member_ids 序中未 archived、非 summary、age_days(last_hit) >=
 * compression.age_days_threshold 的记忆，按 ns 分桶，桶 >= 阈值才成为
 * 一个候选组；最多 10 组。每组生成一条 summary 记忆（importance=0.7），
 * metadata 追加 compresses_region / compressed_at / cover_count /
 * covers(sorted) / 可选 ns；模板文本与参考 _summarize 逐字一致。
 *
 * 成功 0，*out_created 同 aik_engine_consolidate；结束时
 * e->compressions 自增并执行一次 autosave。
 */
int aik_engine_compress(aik_engine *e, aik_json **out_created,
			char *err, size_t errlen);

#endif /* _AIK_ENGINE_ENGINE_H */
