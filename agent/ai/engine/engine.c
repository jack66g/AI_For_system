/* SPDX-License-Identifier: GPL-2.0 */
/*
 * engine.c - T4a SME Engine 核心（进程内 facade）
 *
 * 逐条对齐 REF-PY e72bc75：
 *   sme/engine.py               __init__/_calibrate_region_threshold/add/
 *                               import_memories/load/_load_locked/search/
 *                               _search_locked/reinforce/archive/restore/
 *                               memory_stats/region_stats/engine_stats/export
 *   sme/memory_manager.py       add_memory/_register/archive_memory/
 *                               restore_memory/reinforce/stats
 *   sme/dynamics/reinforcement.py  Ebbinghaus on_hit
 *   sme/models.py               Memory/Region/SearchHit/MemoryStats/
 *                               RegionStats/ScoreBreakdown to_dict
 *
 * 依赖全部来自 L1：smeconfig（配置）/ space（Region + 空间）/
 * retrieval（两阶段检索 + BM25 + ranker）/ store（JSON/快照/NPZ）/
 * memory（hashing 嵌入）。本文件不改动任何既有模块。
 *
 * T4c 已接线的部分（写路径）：
 *   - update / delete（派生摘要级联）/ search_regions / evolve / graph /
 *     link（cause 反向 conversation 边）；
 *   - save()：JSON[.gz] 快照 + NPZ sidecar（store_npz_write）+ 旧代次清理；
 *   - autosave：非 WAL 模式每 storage.autosave_interval 次写操作存一次，
 *     保存失败 fail closed（写操作返回 -1/NULL，err 已写）。
 *
 * T4e-D 已接线的部分（WAL）：
 *   - persistence.enabled + storage.backend=json + sync_mode=fsync 真实可用
 *     （file backend，每条 append 一次 write+fsync）；sqlite/grouped 拒绝；
 *   - 写路径按参考 wal.append 逐字节记录 add / transaction；
 *   - save 写快照 wal_sequence 并在配置路径上 checkpoint（截断 WAL）；
 *   - load 按快照 wal_sequence 跳过已 checkpoint 的记录并重放，重放后
 *     checkpoint；失败保留日志并让 load 失败。
 *
 * 仍然 fail closed 的部分：
 *   - embedding.provider != "hashing" → aik_engine_new 报错（T5 接 openai）；
 *   - maintenance/observability/namespaces/v2 模块 → engine_stats 不出现
 *     对应键（与 Python 关闭时一致），本轮也不实现其开启语义。
 *
 * Region 时间源：space 通过 aik_space_set_clock 注入引擎时钟（与 Python 的
 * sme.utils.now() 同一来源），新建/刷新 Region 的 created_at/last_updated
 * 都取引擎时钟；load 时 created_at 取快照值、last_updated 取引擎时钟
 * （与 Python update_geometry 的 now() 一致）。
 *
 * engine_stats.provider 复刻 Python 的 embeddings.model_name：hashing 时
 * 派生 "hashing-d{dim}-w{max(1,hash_window)}"（与 config.model 无关），
 * 其它 provider 用 config.model（T4a 只支持 hashing，见 new 的拒绝）。
 *
 * 单线程；无全局状态。错误一律写 err 并返回 -1。
 */
#define _POSIX_C_SOURCE 200809L

#include "../include/engine/engine.h"

#include "../include/memory/embed_hash.h"
#include "../include/retrieval/ranker.h"
#include "../include/retrieval/retriever.h"
#include "../include/retrieval/text.h"
#include "../include/space/space.h"
#include "../include/store/store_npz.h"
#include "../include/store/store_npz_write.h"
#include "../include/store/store_snapshot.h"
#include "../include/store/store_wal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* memory.c 的内部符号（不属于 engine.h 公开契约） */
char *aik_engine__dup(const char *s);
aik_json *aik_json__clone(const aik_json *v);
int aik_text__is_blank(const char *utf8);
aik_memory *aik_memory__new(void);
void aik_memory__free(aik_memory *m);
int aik_json__str_array(const aik_json *arr, char ***out, size_t *n_out);
void aik_str_array_free(char **arr, size_t n);

/* 前向声明：更新/归档后重建 BM25（定义在检索段） */
static int engine_refresh_index(aik_engine *e, char *err, size_t errlen);
/* 前向声明：WAL 用到的后面定义的辅助（快照/图/目录） */
struct aik_edge;	/* 参数列表里先出现的 tag 是 prototype scope，先声明 */
static int put_new(aik_json *obj, const char *key, aik_json *v);
static int put_slot(aik_json **slot, aik_json *obj, const char *key);
static aik_json *edge_json(const struct aik_edge *e);
static int ensure_parent_dir(const char *path, char *err, size_t errlen);
static int ci_ends_with(const char *s, const char *suffix);
/* 前向声明：WAL replay 需要级联删除（定义在 delete 段） */
static int engine_delete_impl(aik_engine *e, const char *id, char *err,
			      size_t errlen);
/* 前向声明：WAL 捕获/提交（定义在注册段之后，写路径先用到） */
static int wal_guard(const aik_engine *e, char *err, size_t errlen);
static int wal_dirty_add(aik_engine *e, const char *id);
static int wal_deleted_add(aik_engine *e, const char *id);
static int wal_edge_add(aik_engine *e, const char *source,
			const char *target, const char *kind, double weight,
			const char *note);
static void wal_begin(aik_engine *e);
static void wal_abort(aik_engine *e);
static int wal_commit(aik_engine *e, int vectors, char *err, size_t errlen);
static int wal_record_add(aik_engine *e, const aik_memory *m, char *err,
			  size_t errlen);
static int wal_record_add_transaction(aik_engine *e, char *err, size_t errlen);

/* ------------------------------------------------------------------ */
/* 数据结构                                                           */
/* ------------------------------------------------------------------ */
struct aik_edge {
	char *source;
	char *target;
	char *kind;
	double weight;
	char *note;
};

/* 一次 mutation 内累积的 WAL 变更（对齐 Python _mutation 的
 * _wal_dirty/_wal_deleted/_wal_edges：三个集合按"首次出现"序，写出前排序） */
struct wal_capture {
	char **dirty;		/* 需要写 patches/memories 的记忆 id */
	size_t n_dirty, cap_dirty;
	char **deleted;		/* 被删除的记忆 id */
	size_t n_deleted, cap_deleted;
	struct aik_edge *edges;	/* 图变更（dict 语义：同 source/target/kind 覆盖） */
	size_t n_edges, cap_edges;
};

/* 从配置解析出的一组运行参数（load 先在临时结构上解析，成功才提交） */
struct resolved {
	aik_hash_params emb;
	int dim;
	aik_region_config region;
	aik_retrieval_config rcfg;
	aik_ranking_weights weights;
	aik_decay_config decay;
	int policy_full;
	double policy_threshold;
	int auto_evolve;
	int autosave;
	double autosave_interval;
	/* T4e-D WAL */
	int wal_enabled;
	int wal_fsync;
	char *wal_path;		/* 自有；未启用时 NULL */
	long long checkpoint_every;
};

struct aik_engine {
	aik_config *cfg;
	int owns_cfg;
	aik_now_fn now;
	void *now_ud;
	aik_id_fn id_fn;
	void *id_ud;
	long long id_seq;
	aik_space *space;
	aik_retriever *ret;
	aik_memory **mem;
	size_t n_mem;
	size_t cap_mem;
	struct aik_edge *edges;
	size_t n_edges;
	size_t cap_edges;
	/* 快照恢复的累计计数器（Python 把它们写回 region_manager） */
	long long splits_base;
	long long merges_base;
	long long consolidations;
	long long compressions;
	struct resolved r;
	long long autosave_ops;
	/* ---- T4e-D WAL（file backend / fsync） ---- */
	aik_wal *wal;		/* 懒打开句柄 */
	long long wal_seq;	/* 已追加的最后序号 */
	long long wal_checkpoint_seq;	/* 最近一次快照覆盖到的序号 */
	long long wal_ops;	/* 自上次 checkpoint 以来的 append 数 */
	long long wal_replayed;	/* load 累计重放条数 */
	long long wal_checkpointed;	/* save 触发的 checkpoint 次数 */
	char wal_recovery_error[192];	/* "" = 正常；否则 fail closed 原因 */
	int wal_depth;		/* mutation 嵌套深度（>0 时捕获变更） */
	struct wal_capture wcap;
};

/* ------------------------------------------------------------------ */
/* 基础工具                                                           */
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

static double default_now(void *ud)
{
	(void)ud;
	return (double)time(NULL);
}

static int cfg_i64(const aik_config *c, const char *key, long long def)
{
	long long v = 0;

	if (aik_config_get_i64(c, key, &v) == 0)
		return v;
	return def;
}

static double cfg_num(const aik_config *c, const char *key, double def)
{
	double v = 0.0;

	if (aik_config_get_num(c, key, &v) == 0)
		return v;
	return def;
}

static int cfg_bool(const aik_config *c, const char *key, int def)
{
	int v = 0;

	if (aik_config_get_bool(c, key, &v) == 0)
		return v ? 1 : 0;
	return def;
}

static const char *cfg_str(const aik_config *c, const char *key,
			   const char *def)
{
	const char *s = aik_config_get_str(c, key);

	return s ? s : def;
}

static double clampd(double v, double lo, double hi)
{
	if (v < lo)
		return lo;
	if (v > hi)
		return hi;
	return v;
}

static int cmp_cstr(const void *a, const void *b)
{
	const char *const *x = a;
	const char *const *y = b;

	return strcmp(*x, *y);
}

/* ------------------------------------------------------------------ */
/* id 生成                                                            */
/* ------------------------------------------------------------------ */
static int default_id(aik_engine *e, const char *prefix, char out[16])
{
	const char *p = (prefix && prefix[0] && !prefix[1]) ? prefix : "x";

	e->id_seq++;
	snprintf(out, 16, "%s_%012llx", p, (unsigned long long)e->id_seq);
	return 0;
}

static int id_apply(aik_engine *e, const char *prefix, char out[16])
{
	out[0] = '\0';
	out[15] = '\0';
	if (e->id_fn && e->id_fn(e->id_ud, prefix, out) == 0 && out[0]) {
		out[15] = '\0';
		return 0;
	}
	return default_id(e, prefix, out);
}

static int space_id_trampoline(void *ud, const char *prefix, char out[16])
{
	return id_apply(ud, prefix, out);
}

/* ------------------------------------------------------------------ */
/* 配置解析                                                           */
/* ------------------------------------------------------------------ */
static int resolve_into(const aik_config *cfg, struct resolved *r,
			char *err, size_t errlen)
{
	const char *provider;
	const char *fusion;
	long long seed;

	memset(r, 0, sizeof(*r));
	provider = cfg_str(cfg, "embedding.provider", "hashing");
	r->emb.dim = (int)cfg_i64(cfg, "embedding.dim", 64);
	r->emb.factors = (int)cfg_i64(cfg, "embedding.hash_factors", 3);
	r->emb.window = (int)cfg_i64(cfg, "embedding.hash_window", 3);
	seed = cfg_i64(cfg, "embedding.hash_seed", 0);
	r->emb.seed = seed == 0 ? 42u : (unsigned long long)seed;
	r->emb.normalize_output = cfg_bool(cfg, "embedding.normalize", 1);
	r->emb.mrl_dim = (int)cfg_i64(cfg, "embedding.mrl_dim", 0);
	r->dim = aik_hash_effective_dim(&r->emb);
	if (r->dim <= 0) {
		set_err(err, errlen,
			"engine: invalid embedding params (dim=%d mrl_dim=%d)",
			r->emb.dim, r->emb.mrl_dim);
		return -1;
	}

	r->region.min_region_size =
		(int)cfg_i64(cfg, "region.min_region_size", 3);
	r->region.min_join_cosine =
		cfg_num(cfg, "region.min_join_cosine", 0.70);
	r->region.split_threshold =
		(int)cfg_i64(cfg, "region.split_threshold", 48);
	r->region.max_density = cfg_num(cfg, "region.max_density", 120.0);
	r->region.merge_distance =
		cfg_num(cfg, "region.merge_distance", 0.12);
	r->region.neighbor_factor =
		cfg_num(cfg, "region.neighbor_factor", 1.8);
	r->region.auto_evolve = cfg_bool(cfg, "region.auto_evolve", 1);
	r->region.evolve_interval =
		(int)cfg_i64(cfg, "region.evolve_interval", 40);
	if (r->region.evolve_interval <= 0)
		r->region.evolve_interval = 40;

	/*
	 * §3.6 校准：只有 region.min_join_cosine 非显式、值仍是 0.70、且
	 * provider 不是 hashing 时才放宽到 0.55（真实嵌入模型短句余弦偏低）。
	 * T4a 只支持 hashing，因此这里实际是 no-op；逻辑保留，T5 接真实
	 * provider 后自动生效。
	 */
	if (!aik_config_is_explicit(cfg, "region.min_join_cosine") &&
	    r->region.min_join_cosine == 0.70 &&
	    strcmp(provider, "hashing") != 0)
		r->region.min_join_cosine = 0.55;

	r->rcfg.top_regions = (int)cfg_i64(cfg, "retrieval.top_regions", 3);
	r->rcfg.top_k = (int)cfg_i64(cfg, "retrieval.top_k", 10);
	r->rcfg.vector_weight = cfg_num(cfg, "retrieval.vector_weight", 0.6);
	r->rcfg.keyword_weight =
		cfg_num(cfg, "retrieval.keyword_weight", 0.3);
	r->rcfg.metadata_weight =
		cfg_num(cfg, "retrieval.metadata_weight", 0.1);
	r->rcfg.region_dampening =
		cfg_num(cfg, "retrieval.region_dampening", 0.1);
	r->rcfg.summary_penalty =
		cfg_num(cfg, "retrieval.summary_penalty", 0.5);
	r->rcfg.cjk_bigram = cfg_bool(cfg, "retrieval.cjk_bigram", 1);
	r->rcfg.candidate_window =
		(int)cfg_i64(cfg, "retrieval.candidate_window", 20);
	fusion = cfg_str(cfg, "retrieval.fusion", "minmax");
	r->rcfg.fusion = strcmp(fusion, "minmax") == 0 ? AIK_FUSION_MINMAX
						      : AIK_FUSION_WEIGHTED;
	r->rcfg.keyword_candidates =
		(int)cfg_i64(cfg, "retrieval.keyword_candidates", 0);

	r->weights.semantic = cfg_num(cfg, "ranking.semantic", 0.40);
	r->weights.importance = cfg_num(cfg, "ranking.importance", 0.12);
	r->weights.freshness = cfg_num(cfg, "ranking.freshness", 0.10);
	r->weights.weight = cfg_num(cfg, "ranking.weight", 0.10);
	r->weights.decay = cfg_num(cfg, "ranking.decay", 0.08);
	r->weights.hit_count = cfg_num(cfg, "ranking.hit_count", 0.08);
	r->weights.recency = cfg_num(cfg, "ranking.recency", 0.06);
	r->weights.region = cfg_num(cfg, "ranking.region", 0.06);

	r->decay.half_life_days = cfg_num(cfg, "decay.half_life_days", 30.0);
	r->decay.max_weight_decay = cfg_num(cfg, "decay.max_weight_decay", 0.85);
	r->decay.max_importance_decay =
		cfg_num(cfg, "decay.max_importance_decay", 0.85);
	r->decay.enabled = cfg_bool(cfg, "policy.decay_enabled", 1);

	r->policy_full = cfg_bool(cfg, "policy.full_memory", 1);
	r->policy_threshold =
		cfg_num(cfg, "policy.importance_threshold", 0.25);
	r->auto_evolve = r->region.auto_evolve;
	r->autosave = cfg_bool(cfg, "storage.autosave", 0);
	r->autosave_interval =
		cfg_num(cfg, "storage.autosave_interval", 100.0);

	if (strcmp(provider, "hashing") != 0) {
		set_err(err, errlen,
			"engine: embedding.provider '%s' 未支持（T4a 只支持 hashing）",
			provider);
		return -1;
	}
	if (cfg_bool(cfg, "persistence.enabled", 0)) {
		const char *backend = cfg_str(cfg, "storage.backend", "json");
		const char *sync = cfg_str(cfg, "persistence.sync_mode", "fsync");
		const char *wal_path = cfg_str(cfg, "persistence.wal_path", "");
		const char *storage_path = cfg_str(cfg, "storage.path", "");
		size_t need;

		if (strcmp(backend, "sqlite") == 0) {
			set_err(err, errlen,
				"engine: persistence.enabled + storage.backend=sqlite 未接线（T4e-D 仅 file backend）");
			return -1;
		}
		if (strcmp(sync, "fsync") != 0) {
			set_err(err, errlen,
				"engine: persistence.sync_mode=%s 未接线（T4e-D 仅 fsync）",
				sync);
			return -1;
		}
		need = strlen(wal_path[0] ? wal_path : storage_path) + 5;
		r->wal_path = calloc(need, 1);
		if (!r->wal_path) {
			set_err(err, errlen, "engine: out of memory (wal path)");
			return -1;
		}
		if (*wal_path)
			memcpy(r->wal_path, wal_path, strlen(wal_path));
		else
			snprintf(r->wal_path, need, "%s.wal", storage_path);
		r->wal_enabled = 1;
		r->wal_fsync = 1;
		r->checkpoint_every =
			cfg_i64(cfg, "persistence.checkpoint_every", 10);
	}
	return 0;
}

/* 释放 resolved 自己持有的资源（wal_path） */
static void resolved_free(struct resolved *r)
{
	if (!r)
		return;
	free(r->wal_path);
	r->wal_path = NULL;
}

/* ------------------------------------------------------------------ */
/* 记忆表                                                             */
/* ------------------------------------------------------------------ */
static aik_memory *find_mem(const aik_engine *e, const char *id)
{
	size_t i;

	if (!e || !id)
		return NULL;
	for (i = 0; i < e->n_mem; i++) {
		if (e->mem[i]->id && strcmp(e->mem[i]->id, id) == 0)
			return e->mem[i];
	}
	return NULL;
}

/* Python dict 语义：同 id 覆盖（保持首次位置），否则追加 */
static int engine_put(aik_engine *e, aik_memory *m)
{
	size_t i;

	for (i = 0; i < e->n_mem; i++) {
		if (e->mem[i]->id && m->id && strcmp(e->mem[i]->id, m->id) == 0) {
			aik_memory__free(e->mem[i]);
			e->mem[i] = m;
			return 0;
		}
	}
	if (e->n_mem == e->cap_mem) {
		size_t next = e->cap_mem ? e->cap_mem * 2 : 16;
		aik_memory **grown = realloc(e->mem, next * sizeof(*grown));

		if (!grown)
			return -1;
		e->mem = grown;
		e->cap_mem = next;
	}
	e->mem[e->n_mem++] = m;
	return 0;
}

static void engine_clear_memories(aik_engine *e)
{
	size_t i;

	for (i = 0; i < e->n_mem; i++)
		aik_memory__free(e->mem[i]);
	free(e->mem);
	e->mem = NULL;
	e->n_mem = 0;
	e->cap_mem = 0;
}

/* ------------------------------------------------------------------ */
/* 图边                                                               */
/* ------------------------------------------------------------------ */
static void edge_free(struct aik_edge *e)
{
	if (!e)
		return;
	free(e->source);
	free(e->target);
	free(e->kind);
	free(e->note);
	memset(e, 0, sizeof(*e));
}

static void engine_clear_edges(aik_engine *e)
{
	size_t i;

	for (i = 0; i < e->n_edges; i++)
		edge_free(&e->edges[i]);
	free(e->edges);
	e->edges = NULL;
	e->n_edges = 0;
	e->cap_edges = 0;
}

/*
 * MemoryGraph.add_edge：同 (source,target,kind) 只保留一条，后写覆盖
 * weight，note 非空时覆盖（note or existing.note）。
 */
static int engine_add_edge(aik_engine *e, const char *source,
			   const char *target, const char *kind, double weight,
			   const char *note)
{
	size_t i;
	struct aik_edge *edge;

	for (i = 0; i < e->n_edges; i++) {
		struct aik_edge *x = &e->edges[i];

		if (strcmp(x->source, source) == 0 &&
		    strcmp(x->target, target) == 0 &&
		    strcmp(x->kind, kind) == 0) {
			x->weight = weight;
			if (note && *note) {
				char *copy = aik_engine__dup(note);

				if (!copy)
					return -1;
				free(x->note);
				x->note = copy;
			}
			return 0;
		}
	}
	if (e->n_edges == e->cap_edges) {
		size_t next = e->cap_edges ? e->cap_edges * 2 : 8;
		struct aik_edge *grown =
			realloc(e->edges, next * sizeof(*grown));

		if (!grown)
			return -1;
		e->edges = grown;
		e->cap_edges = next;
	}
	edge = &e->edges[e->n_edges];
	memset(edge, 0, sizeof(*edge));
	edge->source = aik_engine__dup(source);
	edge->target = aik_engine__dup(target);
	edge->kind = aik_engine__dup(kind);
	edge->note = aik_engine__dup(note ? note : "");
	edge->weight = weight;
	if (!edge->source || !edge->target || !edge->kind || !edge->note) {
		edge_free(edge);
		return -1;
	}
	e->n_edges++;
	if (wal_edge_add(e, source, target, kind, weight, note) != 0)
		return -1;	/* 边已加入；WAL 捕获 OOM 已是不可恢复错误 */
	return 0;
}

/* ------------------------------------------------------------------ */
/* 嵌入                                                               */
/* ------------------------------------------------------------------ */
static double *engine_embed(aik_engine *e, const char *text, int *out_dim,
			    char *err, size_t errlen)
{
	double *buf;
	int got;

	if (e->r.emb.dim <= 0) {
		set_err(err, errlen, "engine: embedding dim 非法");
		return NULL;
	}
	buf = malloc((size_t)e->r.emb.dim * sizeof(double));
	if (!buf) {
		set_err(err, errlen, "engine: out of memory (embedding)");
		return NULL;
	}
	got = aik_hash_embed_one(&e->r.emb, text ? text : "", buf,
				 (size_t)e->r.emb.dim, err, errlen);
	if (got <= 0) {
		free(buf);
		return NULL;
	}
	if (out_dim)
		*out_dim = got;
	return buf;
}

/* ------------------------------------------------------------------ */
/* Memory.from_dict 语义                                              */
/* ------------------------------------------------------------------ */
static int json_is_num(const aik_json *v)
{
	aik_json_type t = aik_json_typeof(v);

	return t == AIK_JSON_NUM || t == AIK_JSON_INT;
}

static double json_num_or(const aik_json *obj, const char *key, double def)
{
	const aik_json *v = aik_json_get(obj, key);

	return json_is_num(v) ? aik_json_num(v) : def;
}

static long long json_int_or(const aik_json *obj, const char *key,
			     long long def)
{
	const aik_json *v = aik_json_get(obj, key);

	return json_is_num(v) ? aik_json_int(v) : def;
}

static char *json_str_or_null(const aik_json *obj, const char *key)
{
	const char *s = aik_json_str(aik_json_get(obj, key));

	return s ? aik_engine__dup(s) : NULL;
}

/* archived：Python data.get("archived", False)（非 bool 按真值判定） */
static int json_archived(const aik_json *obj)
{
	const aik_json *v = aik_json_get(obj, "archived");

	switch (aik_json_typeof(v)) {
	case AIK_JSON_BOOL:
		return aik_json_bool(v) ? 1 : 0;
	case AIK_JSON_INT:
		return aik_json_int(v) != 0;
	case AIK_JSON_NUM:
		return aik_json_num(v) != 0.0;
	default:
		return 0;
	}
}

/* 取出条目里的 embedding 数组（拷贝）；没有或非数值数组返回 NULL */
static double *json_embedding(const aik_json *obj, int *out_dim)
{
	const aik_json *arr = aik_json_get(obj, "embedding");
	double *v;
	size_t n;
	size_t i;

	*out_dim = 0;
	if (aik_json_typeof(arr) != AIK_JSON_ARR)
		return NULL;
	n = aik_json_count(arr);
	if (n == 0 || n > (1u << 20))
		return NULL;
	v = malloc(n * sizeof(double));
	if (!v)
		return NULL;
	for (i = 0; i < n; i++) {
		const aik_json *x = aik_json_at(arr, i);

		if (!json_is_num(x)) {
			free(v);
			return NULL;
		}
		v[i] = aik_json_num(x);
	}
	*out_dim = (int)n;
	return v;
}

/*
 * memory_from_json - Memory.from_dict 等价（embedding 由调用方给出）
 *
 * 接管 emb（失败时一并释放）。缺省：id 用 id_fn，created_at/last_hit 用
 * now，hit_count=0, weight=1.0, importance=0.5, freshness=1.0,
 * decay_factor=1.0, version=1, archived=false, source="user"。
 */
static aik_memory *memory_from_json(aik_engine *e, const aik_json *obj,
				    double *emb, int emb_dim, char *err,
				    size_t errlen)
{
	aik_memory *m;
	const aik_json *j;
	const char *s;
	double ref;
	char idbuf[16];

	if (aik_json_typeof(obj) != AIK_JSON_OBJ) {
		set_err(err, errlen, "engine: memory item is not an object");
		free(emb);
		return NULL;
	}
	m = aik_memory__new();
	if (!m) {
		set_err(err, errlen, "engine: out of memory");
		free(emb);
		return NULL;
	}
	ref = e->now(e->now_ud);

	s = aik_json_str(aik_json_get(obj, "id"));
	if (s) {
		m->id = aik_engine__dup(s);
	} else {
		id_apply(e, "m", idbuf);
		m->id = aik_engine__dup(idbuf);
	}
	s = aik_json_str(aik_json_get(obj, "text"));
	m->text = aik_engine__dup(s ? s : "");

	j = aik_json_get(obj, "metadata");
	aik_json_free(m->metadata);
	m->metadata = aik_json_typeof(j) == AIK_JSON_OBJ ? aik_json__clone(j)
							 : aik_json_new_obj();

	m->created_at = json_num_or(obj, "created_at", ref);
	m->last_hit = json_num_or(obj, "last_hit", ref);
	m->hit_count = json_int_or(obj, "hit_count", 0);
	m->weight = json_num_or(obj, "weight", 1.0);
	m->importance = json_num_or(obj, "importance", 0.5);
	m->freshness = json_num_or(obj, "freshness", 1.0);
	m->decay_factor = json_num_or(obj, "decay_factor", 1.0);
	m->version = json_int_or(obj, "version", 1);
	m->archived = json_archived(obj);
	m->summary = json_str_or_null(obj, "summary");
	m->parent_id = json_str_or_null(obj, "parent_id");
	s = aik_json_str(aik_json_get(obj, "source"));
	free(m->source);
	m->source = aik_engine__dup(s ? s : "user");
	m->embedding = emb;
	m->dim = emb ? emb_dim : 0;

	if (!m->id || !m->text || !m->metadata || !m->source ||
	    aik_json__str_array(aik_json_get(obj, "neighbors"),
				&m->neighbors, &m->n_neighbors) != 0 ||
	    aik_json__str_array(aik_json_get(obj, "tags"), &m->tags,
				&m->n_tags) != 0 ||
	    aik_json__str_array(aik_json_get(obj, "children"), &m->children,
				&m->n_children) != 0) {
		set_err(err, errlen, "engine: out of memory (memory item)");
		aik_memory__free(m);
		return NULL;
	}
	return m;
}

/* ------------------------------------------------------------------ */
/* 注册（MemoryManager._register）                                    */
/* ------------------------------------------------------------------ */
static int engine_register(aik_engine *e, aik_memory *m, char *err,
			   size_t errlen)
{
	const char *rid;

	if (!m->embedding || m->dim <= 0) {
		set_err(err, errlen, "engine: memory '%s' has no embedding",
			m->id ? m->id : "?");
		return -1;
	}
	if (m->dim != e->r.dim) {
		set_err(err, errlen,
			"engine: memory '%s' embedding dim %d != space dim %d",
			m->id ? m->id : "?", m->dim, e->r.dim);
		return -1;
	}
	if (aik_space_insert(e->space, m->id, m->embedding, err, errlen) != 0)
		return -1;
	rid = aik_space_region_for(e->space, m->id);
	free(m->region_id);
	m->region_id = rid ? aik_engine__dup(rid) : NULL;
	if (engine_put(e, m) != 0) {
		set_err(err, errlen, "engine: out of memory (memory table)");
		return -1;
	}
	/* MemoryManager.on_upsert → _index_memory：mutation 内登记 dirty */
	if (wal_dirty_add(e, m->id) != 0) {
		set_err(err, errlen, "engine: out of memory (wal dirty)");
		return -1;
	}
	return 0;
}

/* ================================================================== */
/* T4e-D：WAL（file backend / fsync / 恢复 / checkpoint）              */
/*                                                                    */
/* 逐条对齐 REF-PY e72bc75：                                          */
/*   sme/storage/wal.py     append/reset/replay/_apply/stats          */
/*   sme/engine.py          _record_write/_autosave/_save_locked/      */
/*                          load/_recover_wal/_mutation/               */
/*                          _apply_write_transaction                   */
/*                                                                    */
/* 记录格式（aik_json_dump 紧凑 + LF，与 json.dumps(separators=(",", */
/* ":")) 逐字节一致，键序 = Python dict 插入序）：                     */
/*   add          op,mid,text,source,metadata,tags,importance,state    */
/*   transaction  op,memories,patches,deleted,edges,counters           */
/*   add+link_to  op,memories,graph（参考 add 的事务形态，无 counters）*/
/* seq 由 wal_append_op 最后追加，从 1 单调递增。                      */
/* ================================================================== */

/* 错误前置检查（参考每一处 self.wal.recovery_error 的 fail-closed 语义） */
static int wal_guard(const aik_engine *e, char *err, size_t errlen)
{
	if (e && e->wal_recovery_error[0]) {
		set_err(err, errlen, "%s", e->wal_recovery_error);
		return -1;
	}
	return 0;
}

static void wal_set_recovery_error(aik_engine *e, const char *msg)
{
	set_err(e->wal_recovery_error, sizeof(e->wal_recovery_error), "%s", msg);
}

static void wal_capture_clear(struct wal_capture *c)
{
	size_t i;

	for (i = 0; i < c->n_dirty; i++)
		free(c->dirty[i]);
	free(c->dirty);
	for (i = 0; i < c->n_deleted; i++)
		free(c->deleted[i]);
	free(c->deleted);
	for (i = 0; i < c->n_edges; i++)
		edge_free(&c->edges[i]);
	free(c->edges);
	memset(c, 0, sizeof(*c));
}

static int wal_str_push(char ***arr, size_t *n, size_t *cap, const char *s)
{
	char **grown;
	char *copy;
	size_t next;

	if (*n == *cap) {
		next = *cap ? *cap * 2 : 8;
		grown = realloc(*arr, next * sizeof(*grown));
		if (!grown)
			return -1;
		*arr = grown;
		*cap = next;
	}
	copy = aik_engine__dup(s);
	if (!copy)
		return -1;
	(*arr)[(*n)++] = copy;
	return 0;
}

/* MemoryManager._register / on_upsert 的 _wal_dirty.add（仅 mutation 内） */
static int wal_dirty_add(aik_engine *e, const char *id)
{
	size_t i;

	if (!e->r.wal_enabled || e->wal_depth <= 0 || !id)
		return 0;
	for (i = 0; i < e->wcap.n_dirty; i++)
		if (strcmp(e->wcap.dirty[i], id) == 0)
			return 0;
	return wal_str_push(&e->wcap.dirty, &e->wcap.n_dirty,
			    &e->wcap.cap_dirty, id);
}

/* on_delete 的 _wal_deleted.add（仅 mutation 内） */
static int wal_deleted_add(aik_engine *e, const char *id)
{
	size_t i;

	if (!e->r.wal_enabled || e->wal_depth <= 0 || !id)
		return 0;
	for (i = 0; i < e->wcap.n_deleted; i++)
		if (strcmp(e->wcap.deleted[i], id) == 0)
			return 0;
	return wal_str_push(&e->wcap.deleted, &e->wcap.n_deleted,
			    &e->wcap.cap_deleted, id);
}

/* MemoryGraph.on_change → _wal_edges[(source,target,kind)] = edge.to_dict() */
static int wal_edge_add(aik_engine *e, const char *source, const char *target,
			const char *kind, double weight, const char *note)
{
	struct wal_capture *c;
	struct aik_edge *x;
	size_t i;

	if (!e->r.wal_enabled || e->wal_depth <= 0)
		return 0;
	c = &e->wcap;
	for (i = 0; i < c->n_edges; i++) {
		x = &c->edges[i];
		if (strcmp(x->source, source) == 0 &&
		    strcmp(x->target, target) == 0 &&
		    strcmp(x->kind, kind) == 0) {
			x->weight = weight;
			if (note && *note) {
				char *copy = aik_engine__dup(note);

				if (!copy)
					return -1;
				free(x->note);
				x->note = copy;
			}
			return 0;
		}
	}
	if (c->n_edges == c->cap_edges) {
		size_t next = c->cap_edges ? c->cap_edges * 2 : 8;
		struct aik_edge *grown =
			realloc(c->edges, next * sizeof(*grown));

		if (!grown)
			return -1;
		c->edges = grown;
		c->cap_edges = next;
	}
	x = &c->edges[c->n_edges];
	memset(x, 0, sizeof(*x));
	x->source = aik_engine__dup(source);
	x->target = aik_engine__dup(target);
	x->kind = aik_engine__dup(kind);
	x->note = aik_engine__dup(note ? note : "");
	x->weight = weight;
	if (!x->source || !x->target || !x->kind || !x->note) {
		edge_free(x);
		return -1;
	}
	c->n_edges++;
	return 0;
}

static void wal_begin(aik_engine *e)
{
	if (!e->r.wal_enabled)
		return;
	if (e->wal_depth == 0)
		wal_capture_clear(&e->wcap);
	e->wal_depth++;
}

/*
 * wal_abort - 失败退出 mutation（参考 _mutation 的 except 分支）
 *
 * 已有部分变更被捕获时置 recovery_error（与参考
 * "Uncommitted mutation; reload before saving or writing" 一致），
 * 否则静默丢弃捕获。
 */
static void wal_abort(aik_engine *e)
{
	if (!e->r.wal_enabled)
		return;
	if (e->wal_depth > 0)
		e->wal_depth--;
	if (e->wal_depth > 0)
		return;
	if (e->wcap.n_dirty || e->wcap.n_deleted || e->wcap.n_edges)
		wal_set_recovery_error(
			e, "Uncommitted mutation; reload before saving or writing");
	wal_capture_clear(&e->wcap);
}

static int wal_open(aik_engine *e, char *err, size_t errlen)
{
	if (e->wal)
		return 0;
	if (!e->r.wal_path || !*e->r.wal_path) {
		set_err(err, errlen, "engine: WAL 路径为空");
		return -1;
	}
	if (ensure_parent_dir(e->r.wal_path, err, errlen) != 0)
		return -1;
	e->wal = aik_wal_open(e->r.wal_path, e->r.wal_fsync, err, errlen);
	return e->wal ? 0 : -1;
}

/* 追加一条记录：seq 最后追加；成功后推进 wal_seq/ops */
static int wal_append_op(aik_engine *e, aik_json *op, char *err, size_t errlen)
{
	long long seq = e->wal_seq + 1;
	aik_json *v = aik_json_new_int(seq);

	if (!v || aik_json_obj_put(op, "seq", v) != 0) {
		aik_json_free(v);
		set_err(err, errlen, "engine: out of memory (wal seq)");
		return -1;
	}
	if (wal_open(e, err, errlen) != 0)
		return -1;
	if (aik_wal_append(e->wal, op, err, errlen) != 0) {
		wal_set_recovery_error(
			e, "WAL write failed; reload before saving or writing");
		return -1;
	}
	e->wal_seq = seq;
	e->wal_ops++;
	return 0;
}

/* op["add"]：参考 add() 的非事务分支（state 无 embedding） */
static int wal_record_add(aik_engine *e, const aik_memory *m, char *err,
			  size_t errlen)
{
	aik_json *op = NULL;
	aik_json *tags = NULL;
	aik_json *state = NULL;
	size_t i;
	int rc = -1;

	if (!e->r.wal_enabled)
		return 0;
	op = aik_json_new_obj();
	tags = aik_json_new_arr();
	state = aik_memory_to_json(m, 0);
	if (!op || !tags || !state)
		goto oom;
	for (i = 0; i < m->n_tags; i++) {
		aik_json *t = aik_json_new_str(m->tags[i] ? m->tags[i] : "");

		if (!t || aik_json_arr_push(tags, t) != 0) {
			aik_json_free(t);
			goto oom;
		}
	}
	if (put_new(op, "op", aik_json_new_str("add")) != 0 ||
	    put_new(op, "mid", aik_json_new_str(m->id)) != 0 ||
	    put_new(op, "text", aik_json_new_str(m->text)) != 0 ||
	    put_new(op, "source", aik_json_new_str(m->source)) != 0 ||
	    put_new(op, "metadata", aik_json__clone(m->metadata)) != 0 ||
	    put_slot(&tags, op, "tags") != 0 ||
	    put_new(op, "importance", aik_json_new_num(m->importance)) != 0 ||
	    put_slot(&state, op, "state") != 0)
		goto oom;
	rc = wal_append_op(e, op, err, errlen);
	goto done;

oom:
	set_err(err, errlen, "engine: out of memory (wal add)");
done:
	aik_json_free(tags);
	aik_json_free(state);
	aik_json_free(op);
	return rc;
}

/* 排序一份 id 数组（Python sorted(set)；字符串按字节序 = 码点序） */
static char **wal_sorted_copy(char *const *ids, size_t n)
{
	char **copy;
	size_t i;

	copy = malloc((n ? n : 1) * sizeof(*copy));
	if (!copy)
		return NULL;
	for (i = 0; i < n; i++)
		copy[i] = ids[i];
	qsort(copy, n, sizeof(*copy), cmp_cstr);
	return copy;
}

/*
 * wal_commit - 结束 mutation 并写出 transaction 记录
 *
 * 对齐参考 _mutation 的 op 形状：
 *   op,memories,patches,deleted,edges,counters（+seq）
 * vectors 为真时变更记录进 memories（含向量），否则进 patches（无向量）。
 * 三个集合都为空时不写记录（参考 any(op[k]) 判定）。
 */
static int wal_commit(aik_engine *e, int vectors, char *err, size_t errlen)
{
	struct wal_capture *c = &e->wcap;
	aik_json *op = NULL;
	aik_json *memories = NULL;
	aik_json *patches = NULL;
	aik_json *deleted = NULL;
	aik_json *edges = NULL;
	aik_json *counters = NULL;
	char **sorted = NULL;
	size_t i;
	int rc = -1;

	if (!e->r.wal_enabled)
		return 0;
	if (e->wal_depth > 0)
		e->wal_depth--;
	if (e->wal_depth > 0)
		return 0;
	if (!c->n_dirty && !c->n_deleted && !c->n_edges) {
		wal_capture_clear(c);
		return 0;
	}
	if (c->n_dirty) {
		sorted = wal_sorted_copy(c->dirty, c->n_dirty);
		if (!sorted)
			goto oom;
	}
	op = aik_json_new_obj();
	memories = aik_json_new_arr();
	patches = aik_json_new_arr();
	deleted = aik_json_new_arr();
	edges = aik_json_new_arr();
	counters = aik_json_new_obj();
	if (!op || !memories || !patches || !deleted || !edges || !counters)
		goto oom;
	for (i = 0; i < c->n_dirty; i++) {
		aik_memory *m = find_mem(e, sorted[i]);
		aik_json *d;

		if (!m)
			continue;	/* 参考 if mid in self.memories */
		d = aik_memory_to_json(m, vectors);
		if (!d || aik_json_arr_push(vectors ? memories : patches, d) != 0) {
			aik_json_free(d);
			goto oom;
		}
	}
	free(sorted);
	sorted = NULL;
	if (c->n_deleted) {
		sorted = wal_sorted_copy(c->deleted, c->n_deleted);
		if (!sorted)
			goto oom;
		for (i = 0; i < c->n_deleted; i++) {
			aik_json *v = aik_json_new_str(sorted[i]);

			if (!v || aik_json_arr_push(deleted, v) != 0) {
				aik_json_free(v);
				goto oom;
			}
		}
		free(sorted);
		sorted = NULL;
	}
	for (i = 0; i < c->n_edges; i++) {
		aik_json *x = edge_json(&c->edges[i]);

		if (!x || aik_json_arr_push(edges, x) != 0) {
			aik_json_free(x);
			goto oom;
		}
	}
	if (put_new(counters, "consolidations",
		    aik_json_new_int(e->consolidations)) != 0 ||
	    put_new(counters, "compressions",
		    aik_json_new_int(e->compressions)) != 0)
		goto oom;
	if (put_new(op, "op", aik_json_new_str("transaction")) != 0 ||
	    put_slot(&memories, op, "memories") != 0 ||
	    put_slot(&patches, op, "patches") != 0 ||
	    put_slot(&deleted, op, "deleted") != 0 ||
	    put_slot(&edges, op, "edges") != 0 ||
	    put_slot(&counters, op, "counters") != 0)
		goto oom;
	rc = wal_append_op(e, op, err, errlen);
	goto done;

oom:
	set_err(err, errlen, "engine: out of memory (wal transaction)");
done:
	free(sorted);
	aik_json_free(op);
	aik_json_free(memories);
	aik_json_free(patches);
	aik_json_free(deleted);
	aik_json_free(edges);
	aik_json_free(counters);
	wal_capture_clear(c);
	return rc;
}

/* add(link_to=...) 的事务形态：op,memories(含向量),graph,seq（参考 add） */
static int wal_record_add_transaction(aik_engine *e, char *err, size_t errlen)
{
	struct wal_capture *c = &e->wcap;
	aik_json *op = NULL;
	aik_json *memories = NULL;
	aik_json *graph = NULL;
	aik_json *edge_arr = NULL;
	char **sorted = NULL;
	size_t i;
	int rc = -1;

	if (!e->r.wal_enabled)
		return 0;
	if (e->wal_depth > 0)
		e->wal_depth--;
	if (!c->n_dirty) {
		wal_capture_clear(c);
		return 0;
	}
	sorted = wal_sorted_copy(c->dirty, c->n_dirty);
	if (!sorted)
		goto oom;
	op = aik_json_new_obj();
	memories = aik_json_new_arr();
	graph = aik_json_new_obj();
	edge_arr = aik_json_new_arr();
	if (!op || !memories || !graph || !edge_arr)
		goto oom;
	for (i = 0; i < c->n_dirty; i++) {
		aik_memory *m = find_mem(e, sorted[i]);
		aik_json *d;

		if (!m)
			continue;
		d = aik_memory_to_json(m, 1);
		if (!d || aik_json_arr_push(memories, d) != 0) {
			aik_json_free(d);
			goto oom;
		}
	}
	for (i = 0; i < e->n_edges; i++) {
		aik_json *x = edge_json(&e->edges[i]);

		if (!x || aik_json_arr_push(edge_arr, x) != 0) {
			aik_json_free(x);
			goto oom;
		}
	}
	if (put_slot(&edge_arr, graph, "edges") != 0)
		goto oom;
	if (put_new(op, "op", aik_json_new_str("transaction")) != 0 ||
	    put_slot(&memories, op, "memories") != 0 ||
	    put_slot(&graph, op, "graph") != 0)
		goto oom;
	rc = wal_append_op(e, op, err, errlen);
	goto done;

oom:
	set_err(err, errlen, "engine: out of memory (wal add transaction)");
done:
	free(sorted);
	aik_json_free(op);
	aik_json_free(memories);
	aik_json_free(graph);
	aik_json_free(edge_arr);
	wal_capture_clear(c);
	return rc;
}

/* ------------------------------------------------------------------ */
/* WAL replay（load）                                                  */
/* ------------------------------------------------------------------ */

/*
 * 应用一条记录（对齐 wal._apply / _apply_write_transaction）：
 * 不重新写 WAL（wal_depth 为 0）、不触发 autosave、不重编码 transaction
 * 内的向量（memories/patches 直接带/继承旧向量）；仅 add 的 state 缺
 * 向量时按当前 provider 重编码（参考同样重编码，否则无法进 space）。
 */
static int wal_apply_record(aik_engine *e, aik_memory *m, char *err,
			    size_t errlen)
{
	aik_memory *old;

	if (!m || !m->id) {
		aik_memory__free(m);
		set_err(err, errlen, "WAL memory record has no id");
		return -1;
	}
	old = find_mem(e, m->id);
	if (old && !old->archived)
		aik_space_remove(e->space, m->id);
	if (m->archived) {
		free(m->region_id);
		m->region_id = NULL;
		if (engine_put(e, m) != 0) {
			aik_memory__free(m);
			set_err(err, errlen,
				"engine: out of memory (wal archive)");
			return -1;
		}
		return 0;
	}
	if (!m->embedding) {
		aik_memory__free(m);
		set_err(err, errlen, "WAL memory record has no embedding");
		return -1;
	}
	if (engine_register(e, m, err, errlen) != 0) {
		aik_memory__free(m);
		return -1;
	}
	return 0;
}

/* 旧式 add（无 state）：mm.add_memory(..., memory_id=mid) */
static int wal_apply_legacy_add(aik_engine *e, const aik_json *op,
				const char *mid, char *err, size_t errlen)
{
	aik_json *obj = NULL;
	aik_json *meta = NULL;
	aik_json *tags = NULL;
	const aik_json *src_meta = aik_json_get(op, "metadata");
	const aik_json *src_tags = aik_json_get(op, "tags");
	const char *text = aik_json_str(aik_json_get(op, "text"));
	const char *source = aik_json_str(aik_json_get(op, "source"));
	double *emb = NULL;
	int dim = 0;
	aik_memory *m = NULL;
	size_t i;
	int rc = -1;

	obj = aik_json_new_obj();
	meta = aik_json_typeof(src_meta) == AIK_JSON_OBJ
		       ? aik_json__clone(src_meta)
		       : aik_json_new_obj();
	tags = aik_json_new_arr();
	if (!obj || !meta || !tags)
		goto oom;
	if (aik_json_typeof(src_tags) == AIK_JSON_ARR) {
		for (i = 0; i < aik_json_count(src_tags); i++) {
			const char *s = aik_json_str(aik_json_at(src_tags, i));
			aik_json *t = aik_json_new_str(s ? s : "");

			if (!t || aik_json_arr_push(tags, t) != 0) {
				aik_json_free(t);
				goto oom;
			}
		}
	}
	if (put_new(obj, "id", aik_json_new_str(mid)) != 0 ||
	    put_new(obj, "text", aik_json_new_str(text ? text : "")) != 0 ||
	    put_slot(&meta, obj, "metadata") != 0 ||
	    put_slot(&tags, obj, "tags") != 0 ||
	    put_new(obj, "importance",
		    aik_json_new_num(json_num_or(op, "importance", 0.5))) != 0 ||
	    put_new(obj, "source",
		    aik_json_new_str(source ? source : "user")) != 0)
		goto oom;
	emb = engine_embed(e, text ? text : "", &dim, err, errlen);
	if (!emb)
		goto done;
	m = memory_from_json(e, obj, emb, dim, err, errlen);
	emb = NULL;
	if (!m)
		goto done;
	rc = wal_apply_record(e, m, err, errlen);
	goto done;

oom:
	set_err(err, errlen, "engine: out of memory (wal add)");
done:
	free(emb);
	aik_json_free(obj);
	aik_json_free(meta);
	aik_json_free(tags);
	return rc;
}

static int wal_apply_add(aik_engine *e, const aik_json *op, char *err,
			 size_t errlen)
{
	const char *mid = aik_json_str(aik_json_get(op, "mid"));
	const aik_json *state = aik_json_get(op, "state");
	double *emb = NULL;
	int dim = 0;
	aik_memory *m;

	/* 幂等：该 add 已在快照/先前重放中落库 */
	if (mid && find_mem(e, mid))
		return 0;
	if (aik_json_typeof(state) != AIK_JSON_OBJ)
		return wal_apply_legacy_add(e, op, mid, err, errlen);
	emb = json_embedding(state, &dim);
	if (!emb) {
		const char *text = aik_json_str(aik_json_get(state, "text"));

		if (!text)
			text = aik_json_str(aik_json_get(op, "text"));
		emb = engine_embed(e, text ? text : "", &dim, err, errlen);
		if (!emb)
			return -1;
	}
	if (dim != e->r.dim) {
		free(emb);
		set_err(err, errlen,
			"WAL add embedding dim %d != engine dim %d", dim, e->r.dim);
		return -1;
	}
	m = memory_from_json(e, state, emb, dim, err, errlen);
	if (!m)
		return -1;
	return wal_apply_record(e, m, err, errlen);
}

/* patches：Memory.from_dict({**previous.to_dict(), **patch}) */
static int wal_apply_patch(aik_engine *e, const aik_json *patch, char *err,
			   size_t errlen)
{
	const char *id = aik_json_str(aik_json_get(patch, "id"));
	aik_memory *prev;
	aik_json *merged = NULL;
	double *emb = NULL;
	int dim = 0;
	aik_memory *m;
	size_t i, n;
	int rc = -1;

	if (!id) {
		set_err(err, errlen, "WAL patch has no id");
		return -1;
	}
	prev = find_mem(e, id);
	if (!prev) {
		set_err(err, errlen, "WAL patch source is missing: %s", id);
		return -1;
	}
	if (!prev->embedding) {
		set_err(err, errlen, "WAL patch source has no embedding: %s", id);
		return -1;
	}
	merged = aik_memory_to_json(prev, 1);
	if (!merged)
		goto oom;
	n = aik_json_count(patch);
	for (i = 0; i < n; i++) {
		const char *key = aik_json_key_at(patch, i);
		aik_json *v;

		if (!key)
			continue;
		v = aik_json__clone(aik_json_val_at(patch, i));
		if (!v || aik_json_obj_set(merged, key, v) != 0) {
			aik_json_free(v);
			goto oom;
		}
	}
	emb = json_embedding(merged, &dim);
	if (!emb) {
		set_err(err, errlen, "WAL patch merged record has no embedding");
		goto done;
	}
	m = memory_from_json(e, merged, emb, dim, err, errlen);
	emb = NULL;
	if (!m)
		goto done;
	rc = wal_apply_record(e, m, err, errlen);
	goto done;

oom:
	set_err(err, errlen, "engine: out of memory (wal patch)");
done:
	free(emb);
	aik_json_free(merged);
	return rc;
}

static int wal_apply_graph(aik_engine *e, const aik_json *graph, char *err,
			   size_t errlen)
{
	const aik_json *edges = aik_json_get(graph, "edges");
	size_t i;

	if (aik_json_typeof(edges) != AIK_JSON_ARR)
		return 0;
	engine_clear_edges(e);
	for (i = 0; i < aik_json_count(edges); i++) {
		const aik_json *x = aik_json_at(edges, i);
		const char *source = aik_json_str(aik_json_get(x, "source"));
		const char *target = aik_json_str(aik_json_get(x, "target"));
		const char *kind = aik_json_str(aik_json_get(x, "kind"));
		const char *note = aik_json_str(aik_json_get(x, "note"));

		if (!source || !target) {
			set_err(err, errlen,
				"WAL graph edge %zu lacks source/target", i);
			return -1;
		}
		if (engine_add_edge(e, source, target,
				    kind ? kind : "reference",
				    json_num_or(x, "weight", 1.0),
				    note ? note : "") != 0) {
			set_err(err, errlen,
				"engine: out of memory (wal graph)");
			return -1;
		}
	}
	return 0;
}

static int wal_apply_transaction(aik_engine *e, const aik_json *op, char *err,
				 size_t errlen)
{
	const aik_json *deleted = aik_json_get(op, "deleted");
	const aik_json *memories = aik_json_get(op, "memories");
	const aik_json *patches = aik_json_get(op, "patches");
	const aik_json *edges = aik_json_get(op, "edges");
	const aik_json *graph = aik_json_get(op, "graph");
	const aik_json *counters = aik_json_get(op, "counters");
	size_t i;

	if (aik_json_typeof(deleted) == AIK_JSON_ARR) {
		for (i = 0; i < aik_json_count(deleted); i++) {
			const char *mid = aik_json_str(aik_json_at(deleted, i));

			if (!mid)
				continue;
			if (engine_delete_impl(e, mid, err, errlen) == -1)
				return -1;
		}
	}
	if (aik_json_typeof(memories) == AIK_JSON_ARR) {
		for (i = 0; i < aik_json_count(memories); i++) {
			const aik_json *d = aik_json_at(memories, i);
			double *emb;
			int dim = 0;
			aik_memory *m;

			emb = json_embedding(d, &dim);
			if (!emb) {
				set_err(err, errlen,
					"WAL memory record has no embedding");
				return -1;
			}
			if (dim != e->r.dim) {
				free(emb);
				set_err(err, errlen,
					"WAL memory embedding dim %d != engine dim %d",
					dim, e->r.dim);
				return -1;
			}
			m = memory_from_json(e, d, emb, dim, err, errlen);
			if (!m)
				return -1;
			if (wal_apply_record(e, m, err, errlen) != 0)
				return -1;
		}
	}
	if (aik_json_typeof(patches) == AIK_JSON_ARR) {
		for (i = 0; i < aik_json_count(patches); i++)
			if (wal_apply_patch(e, aik_json_at(patches, i), err,
					    errlen) != 0)
				return -1;
	}
	if (aik_json_typeof(graph) == AIK_JSON_OBJ)
		if (wal_apply_graph(e, graph, err, errlen) != 0)
			return -1;
	if (aik_json_typeof(edges) == AIK_JSON_ARR) {
		for (i = 0; i < aik_json_count(edges); i++) {
			const aik_json *x = aik_json_at(edges, i);
			const char *source = aik_json_str(aik_json_get(x, "source"));
			const char *target = aik_json_str(aik_json_get(x, "target"));
			const char *kind = aik_json_str(aik_json_get(x, "kind"));
			const char *note = aik_json_str(aik_json_get(x, "note"));

			if (!source || !target) {
				set_err(err, errlen,
					"WAL edge %zu lacks source/target", i);
				return -1;
			}
			if (engine_add_edge(e, source, target,
					    kind ? kind : "reference",
					    json_num_or(x, "weight", 1.0),
					    note ? note : "") != 0) {
				set_err(err, errlen,
					"engine: out of memory (wal edges)");
				return -1;
			}
		}
	}
	if (aik_json_typeof(counters) == AIK_JSON_OBJ) {
		if (json_is_num(aik_json_get(counters, "consolidations")))
			e->consolidations = json_int_or(counters, "consolidations",
							e->consolidations);
		if (json_is_num(aik_json_get(counters, "compressions")))
			e->compressions = json_int_or(counters, "compressions",
						      e->compressions);
	}
	return 0;
}

static int wal_apply_op(void *ctx, const aik_json *op, char *err, size_t errlen)
{
	aik_engine *e = ctx;
	const char *kind = aik_json_str(aik_json_get(op, "op"));

	if (!kind) {
		set_err(err, errlen, "WAL record has no op");
		return -1;
	}
	if (strcmp(kind, "transaction") == 0)
		return wal_apply_transaction(e, op, err, errlen);
	if (strcmp(kind, "add") == 0)
		return wal_apply_add(e, op, err, errlen);
	set_err(err, errlen, "unsupported WAL operation: '%s'", kind);
	return -1;
}

/* 从 store 的 "wal: record N: detail" 剥出 detail（load 的错误文案用） */
static const char *wal_detail(const char *msg, long long rec)
{
	char prefix[64];
	size_t n;

	if (!msg || !msg[0])
		return "replay failed";
	n = (size_t)snprintf(prefix, sizeof(prefix), "wal: record %lld: ", rec);
	if (n < sizeof(prefix) && strncmp(msg, prefix, n) == 0)
		return msg + n;
	return msg;
}

/* ------------------------------------------------------------------ */
/* WAL 路径等价判定（Python _save_locked 的 recovery_path）            */
/* ------------------------------------------------------------------ */

/* os.path.abspath 等价：相对路径拼 getcwd，再按 normpath 规则折叠 */
static char *path_abspath(const char *path)
{
	const char *p;
	const char *s;
	char *joined = NULL;
	char *out;
	size_t o = 0;

	if (!path || !*path)
		return NULL;
	if (path[0] == '/') {
		p = path;
	} else {
		char *cwd = getcwd(NULL, 0);
		size_t n;

		if (!cwd)
			return NULL;
		n = strlen(cwd) + strlen(path) + 2;
		joined = malloc(n);
		if (!joined) {
			free(cwd);
			return NULL;
		}
		snprintf(joined, n, "%s/%s", cwd, path);
		free(cwd);
		p = joined;
	}
	out = malloc(strlen(p) + 2);
	if (!out) {
		free(joined);
		return NULL;
	}
	out[o++] = '/';
	s = p;
	while (*s) {
		const char *seg;
		size_t len;

		while (*s == '/')
			s++;
		seg = s;
		while (*s && *s != '/')
			s++;
		len = (size_t)(s - seg);
		if (len == 0 || (len == 1 && seg[0] == '.'))
			continue;
		if (len == 2 && seg[0] == '.' && seg[1] == '.') {
			while (o > 1 && out[o - 1] != '/')
				o--;
			if (o > 1)
				o--;
			continue;
		}
		if (o > 1)
			out[o++] = '/';
		memcpy(out + o, seg, len);
		o += len;
	}
	if (o == 0)
		out[o++] = '/';
	out[o] = '\0';
	free(joined);
	return out;
}

/* 去掉 ".json.gz"（参考 recovery_path：仅该后缀被剥离，大小写不敏感） */
static void path_strip_json_gz(char *p)
{
	size_t n = strlen(p);

	if (ci_ends_with(p, ".json.gz"))
		p[n - 3] = '\0';
}

/* 保存路径是否等价于配置的 recovery 路径（= storage.path） */
static int wal_path_is_recovery(const aik_engine *e, const char *path)
{
	const char *storage = cfg_str(e->cfg, "storage.path", NULL);
	char *a;
	char *b;
	int same = 0;

	if (!path || !*path || !storage || !*storage)
		return 0;
	a = path_abspath(path);
	b = path_abspath(storage);
	if (a && b) {
		path_strip_json_gz(a);
		path_strip_json_gz(b);
		same = strcmp(a, b) == 0;
	}
	free(a);
	free(b);
	return same;
}

/*
 * autosave（storage.autosave，Python engine._autosave）
 *
 * 非 WAL 模式：每次成功写操作计数 +1，达到 storage.autosave_interval 时
 * 调 aik_engine_save(storage.path)。保存失败即 fail closed：错误写 err，
 * 写操作返回 -1/NULL（内存里已完成的改动不回滚，与 Python 抛异常一致）。
 * 成功的 save 会把计数器清零（aik_engine_save 内做）。
 *
 * WAL 模式（T4e-D）：不数 interval，改看 ops_since_checkpoint() >=
 * persistence.checkpoint_every 时 checkpoint（save）；与参考 _autosave
 * 一致（storage.autosave=false 时 WAL 也不自动 checkpoint）。
 */
static int engine_autosave(aik_engine *e, char *err, size_t errlen)
{
	const char *path;

	if (!e->r.autosave)
		return 0;
	if (e->r.wal_enabled) {
		if (e->wal_ops < e->r.checkpoint_every)
			return 0;
		return aik_engine_save(e, NULL, err, errlen);
	}
	e->autosave_ops++;
	if ((double)e->autosave_ops < e->r.autosave_interval)
		return 0;
	path = cfg_str(e->cfg, "storage.path", NULL);
	if (!path || !*path) {
		set_err(err, errlen,
			"engine: storage.autosave 开启但 storage.path 为空");
		return -1;
	}
	if (aik_engine_save(e, path, err, errlen) != 0)
		return -1;
	e->autosave_ops = 0;
	return 0;
}

/* ------------------------------------------------------------------ */
/* 公开接口：创建 / 释放                                              */
/* ------------------------------------------------------------------ */
aik_engine *aik_engine_new(aik_config *cfg, int take_ownership,
			   aik_now_fn now, void *now_ud,
			   aik_id_fn id, void *id_ud,
			   char *err, size_t errlen)
{
	aik_engine *e;

	if (!cfg) {
		cfg = aik_config_defaults(err, errlen);
		if (!cfg)
			return NULL;
		take_ownership = 1;
	}
	e = calloc(1, sizeof(*e));
	if (!e) {
		if (take_ownership)
			aik_config_free(cfg);
		set_err(err, errlen, "engine: out of memory");
		return NULL;
	}
	e->cfg = cfg;
	e->owns_cfg = take_ownership ? 1 : 0;
	e->now = now ? now : default_now;
	e->now_ud = now_ud;
	e->id_fn = id;
	e->id_ud = id_ud;
	if (resolve_into(e->cfg, &e->r, err, errlen) != 0)
		goto fail;
	e->space = aik_space_new(&e->r.region, e->r.dim, err, errlen);
	if (!e->space)
		goto fail;
	aik_space_set_id_fn(e->space, space_id_trampoline, e);
	/* Region 时间源 = 引擎时钟（Python sme.utils.now() 的等价物） */
	aik_space_set_clock(e->space, e->now, e->now_ud);
	e->ret = aik_retriever_new(&e->r.rcfg, err, errlen);
	if (!e->ret)
		goto fail;
	return e;

fail:
	aik_engine_free(e);
	return NULL;
}

void aik_engine_free(aik_engine *e)
{
	if (!e)
		return;
	engine_clear_memories(e);
	engine_clear_edges(e);
	if (e->wal) {
		(void)aik_wal_close(e->wal);
		e->wal = NULL;
	}
	wal_capture_clear(&e->wcap);
	resolved_free(&e->r);
	aik_space_free(e->space);
	aik_retriever_free(e->ret);
	if (e->owns_cfg)
		aik_config_free(e->cfg);
	free(e);
}

aik_config *aik_engine_config(aik_engine *e)
{
	return e ? e->cfg : NULL;
}

/* ------------------------------------------------------------------ */
/* 公开接口：写                                                       */
/* ------------------------------------------------------------------ */
/*
 * engine_add_core - add_memory 管线（不含 autosave）
 *
 * 与 aik_engine_add 的行为逐条一致（id/时钟/嵌入/space 注册/BM25/可选
 * link_to 边），唯一区别是**不**调 engine_autosave。consolidate/compress
 * 在内部批量创建 summary 记忆后只调用一次 autosave（与 Python
 * consolidate()/compress() 的单次 _autosave 一致）。
 */
static aik_memory *engine_add_core(aik_engine *e, const char *text,
				   const aik_json *metadata,
				   const char *const *tags, size_t n_tags,
				   double importance, const char *source,
				   const char *link_to, const char *link_kind,
				   const char *ns, char *err, size_t errlen)
{
	aik_memory *m;
	const aik_json *j;
	char idbuf[16];
	size_t i;

	if (!e) {
		set_err(err, errlen, "engine: engine is NULL");
		return NULL;
	}
	if (aik_text__is_blank(text)) {
		set_err(err, errlen, "memory text must not be blank");
		return NULL;
	}
	m = aik_memory__new();
	if (!m)
		goto oom;
	id_apply(e, "m", idbuf);
	m->id = aik_engine__dup(idbuf);
	m->text = aik_engine__dup(text);
	aik_json_free(m->metadata);
	j = aik_json_typeof(metadata) == AIK_JSON_OBJ ? metadata : NULL;
	m->metadata = j ? aik_json__clone(j) : aik_json_new_obj();
	if (!m->id || !m->text || !m->metadata)
		goto fail;
	if (ns != NULL) {
		aik_json *v = aik_json_new_str(ns);

		if (!v || aik_json_obj_set(m->metadata, "ns", v) != 0) {
			aik_json_free(v);
			goto fail;
		}
	}
	if (n_tags > 0) {
		m->tags = calloc(n_tags, sizeof(*m->tags));
		if (!m->tags)
			goto fail;
		for (i = 0; i < n_tags; i++) {
			m->tags[i] = aik_engine__dup(tags[i] ? tags[i] : "");
			if (!m->tags[i])
				goto fail;
			m->n_tags = i + 1;
		}
	}
	m->created_at = e->now(e->now_ud);
	m->last_hit = m->created_at;
	m->hit_count = 0;
	m->weight = 1.0;
	m->importance = clampd(importance, 0.0, 1.0);
	m->freshness = 1.0;
	m->decay_factor = 1.0;
	m->version = 1;
	m->archived = 0;
	free(m->source);
	m->source = aik_engine__dup(source ? source : "user");
	if (!m->source)
		goto fail;
	m->embedding = engine_embed(e, text, &m->dim, err, errlen);
	if (!m->embedding)
		goto fail;
	if (engine_register(e, m, err, errlen) != 0)
		goto fail;
	if (link_to != NULL &&
	    engine_add_edge(e, m->id, link_to,
			    link_kind ? link_kind : "reference", 1.0,
			    "") != 0) {
		/* 记忆已注册：绝不回滚（Python 同样保留），只报告边未建 */
		set_err(err, errlen, "engine: out of memory (graph edge)");
		return NULL;
	}
	return m;

oom:
	set_err(err, errlen, "engine: out of memory");
	return NULL;
fail:
	aik_memory__free(m);
	return NULL;
}

aik_memory *aik_engine_add(aik_engine *e, const char *text,
			   const aik_json *metadata,
			   const char *const *tags, size_t n_tags,
			   double importance, const char *source,
			   const char *link_to, const char *link_kind,
			   const char *ns, const char *conversation_id,
			   char *err, size_t errlen)
{
	aik_memory *m;

	(void)conversation_id;	/* v2 pipeline 专用，T4a 无副作用 */
	if (wal_guard(e, err, errlen) != 0)
		return NULL;
	if (e && e->r.wal_enabled && link_to != NULL) {
		/*
		 * 参考 add()：wal 开启且带 link_to 时走事务形态
		 * （op,memories,graph）——模块在 C 端为空，不写 modules。
		 */
		wal_begin(e);
		m = engine_add_core(e, text, metadata, tags, n_tags, importance,
				    source, link_to, link_kind, ns, err, errlen);
		if (!m) {
			wal_abort(e);
			return NULL;
		}
		if (wal_record_add_transaction(e, err, errlen) != 0)
			return NULL;
	} else {
		m = engine_add_core(e, text, metadata, tags, n_tags, importance,
				    source, link_to, link_kind, ns, err, errlen);
		if (!m)
			return NULL;
		if (e && wal_record_add(e, m, err, errlen) != 0)
			return NULL;
	}
	if (engine_autosave(e, err, errlen) != 0)
		return NULL;
	return m;
}

int aik_engine_import(aik_engine *e, const aik_json *items,
		      long long *out_count, char *err, size_t errlen)
{
	size_t n;
	size_t i;
	long long count = 0;
	int rc = -1;

	if (out_count)
		*out_count = 0;
	if (!e || aik_json_typeof(items) != AIK_JSON_ARR) {
		set_err(err, errlen, "engine: import items is not an array");
		return -1;
	}
	n = aik_json_count(items);
	aik_space_set_bulk(e->space, 1);
	for (i = 0; i < n; i++) {
		const aik_json *item = aik_json_at(items, i);
		const char *text = aik_json_str(aik_json_get(item, "text"));
		aik_memory *m;
		double *emb;
		int emb_dim = 0;

		if (!text || !*text)
			continue;	/* Python: if not item.get("text") */
		emb = json_embedding(item, &emb_dim);
		m = memory_from_json(e, item, emb, emb_dim, err, errlen);
		if (!m)
			goto out;
		if (!m->embedding) {
			m->embedding = engine_embed(e, m->text, &m->dim, err,
						    errlen);
			if (!m->embedding) {
				aik_memory__free(m);
				goto out;
			}
		}
		if (m->archived) {
			/* 归档记忆：不进空间/检索索引，只登记 memories + 冷存档 */
			free(m->region_id);
			m->region_id = NULL;
			if (engine_put(e, m) != 0) {
				aik_memory__free(m);
				set_err(err, errlen,
					"engine: out of memory (memory table)");
				goto out;
			}
		} else if (engine_register(e, m, err, errlen) != 0) {
			aik_memory__free(m);
			goto out;
		}
		count++;
	}
	rc = 0;
out:
	aik_space_set_bulk(e->space, 0);
	if (rc == 0 && e->r.auto_evolve && aik_space_write_ops(e->space) > 0) {
		aik_space_event *events = NULL;
		size_t n_events = 0;

		if (aik_space_evolution_pass(e->space, &events, &n_events, err,
					     errlen) != 0) {
			rc = -1;
			goto done;
		}
		aik_space_events_free(events, n_events);
	}
done:
	if (out_count)
		*out_count = count;
	if (rc == 0) {
		/*
		 * 参考 import_memories：bulk import 不逐条写 WAL；WAL 开启时
		 * 立即 checkpoint（save），否则走非 WAL 的 autosave 计数。
		 */
		if (e->r.wal_enabled) {
			if (aik_engine_save(e, NULL, err, errlen) != 0)
				rc = -1;
		} else if (engine_autosave(e, err, errlen) != 0) {
			rc = -1;
		}
	}
	return rc;
}

aik_memory *aik_engine_get(aik_engine *e, const char *id)
{
	return find_mem(e, id);
}

size_t aik_engine_memory_count(const aik_engine *e)
{
	return e ? e->n_mem : 0;
}

aik_memory *aik_engine_memory_at(const aik_engine *e, size_t i)
{
	if (!e || i >= e->n_mem)
		return NULL;
	return e->mem[i];
}

/* ------------------------------------------------------------------ */
/* 快照读取                                                           */
/* ------------------------------------------------------------------ */
static int file_exists(const char *path)
{
	FILE *f = fopen(path, "rb");

	if (!f)
		return 0;
	fclose(f);
	return 1;
}

static char *path_join(const char *dir, const char *name)
{
	size_t dl = strlen(dir);
	size_t nl = strlen(name);
	char *p = malloc(dl + nl + 2);

	if (!p)
		return NULL;
	memcpy(p, dir, dl);
	if (dl > 0 && dir[dl - 1] != '/')
		p[dl++] = '/';
	memcpy(p + dl, name, nl + 1);
	return p;
}

static int safe_basename(const char *name)
{
	if (!name || !*name)
		return 0;
	if (strchr(name, '/') || strchr(name, '\\') || strstr(name, ".."))
		return 0;
	return 1;
}

/* 读 NPZ 的 ids/matrix/generation；成功 0 */
static int load_npz(const char *npz_path, const aik_json *root,
		    char ***out_ids, size_t *out_n_ids, double **out_matrix,
		    int *out_dim, char *err, size_t errlen)
{
	aik_npz *z = NULL;
	unsigned char *ids_buf = NULL;
	unsigned char *mat_buf = NULL;
	size_t ids_len = 0;
	size_t mat_len = 0;
	aik_npy ids_npy;
	aik_npy mat_npy;
	char **ids = NULL;
	double *matrix = NULL;
	size_t n_ids = 0;
	size_t i;
	int dim;
	int rc = -1;

	*out_ids = NULL;
	*out_n_ids = 0;
	*out_matrix = NULL;
	*out_dim = 0;

	z = aik_npz_open(npz_path, err, errlen);
	if (!z)
		return -1;
	if (!aik_npz_has(z, "ids") || !aik_npz_has(z, "matrix")) {
		set_err(err, errlen, "engine: npz lacks ids/matrix entries");
		goto done;
	}
	if (aik_npz_read(z, "ids", &ids_buf, &ids_len, err, errlen) != 0 ||
	    aik_npz_read(z, "matrix", &mat_buf, &mat_len, err, errlen) != 0)
		goto done;
	if (aik_npy_parse(ids_buf, ids_len, &ids_npy, err, errlen) != 0 ||
	    aik_npy_parse(mat_buf, mat_len, &mat_npy, err, errlen) != 0)
		goto done;
	if (ids_npy.descr[0] != '<' || ids_npy.descr[1] != 'U') {
		set_err(err, errlen, "engine: npz ids dtype %s unsupported",
			ids_npy.descr);
		goto done;
	}
	n_ids = aik_npy_nelem(&ids_npy);
	if (mat_npy.ndim != 2 || mat_npy.shape[0] < 0 ||
	    (size_t)mat_npy.shape[0] != n_ids) {
		set_err(err, errlen, "engine: npz ids/matrix shape mismatch");
		goto done;
	}
	dim = (int)mat_npy.shape[1];
	if (dim <= 0) {
		set_err(err, errlen, "engine: npz matrix has no columns");
		goto done;
	}
	ids = calloc(n_ids ? n_ids : 1, sizeof(*ids));
	matrix = malloc((n_ids ? n_ids : 1) * (size_t)dim * sizeof(double));
	if (!ids || !matrix) {
		set_err(err, errlen, "engine: out of memory (npz)");
		goto done;
	}
	for (i = 0; i < n_ids * (size_t)dim; i++) {
		if (aik_npy_get_f8(&mat_npy, i, &matrix[i]) != 0) {
			set_err(err, errlen, "engine: npz matrix element %zu",
				i);
			goto done;
		}
	}
	for (i = 0; i < n_ids; i++) {
		char name[128];
		size_t k;
		char *copy;

		if (aik_npy_get_ustr(&ids_npy, i, name, sizeof(name)) < 0) {
			set_err(err, errlen, "engine: npz ids element %zu", i);
			goto done;
		}
		copy = aik_engine__dup(name);
		if (!copy) {
			set_err(err, errlen, "engine: out of memory (npz ids)");
			goto done;
		}
		for (k = 0; k < i; k++) {
			if (strcmp(ids[k], copy) == 0) {
				set_err(err, errlen,
					"engine: duplicate npz id '%s'", copy);
				free(copy);
				goto done;
			}
		}
		ids[i] = copy;
	}
	/* embedding_generation 校验 */
	{
		const char *want =
			aik_json_str(aik_json_get(root, "embedding_generation"));

		if (want && *want) {
			unsigned char *gen_buf = NULL;
			size_t gen_len = 0;
			aik_npy gen_npy;
			char got[128];
			int bad;

			if (!aik_npz_has(z, "generation")) {
				set_err(err, errlen,
					"engine: npz lacks generation entry");
				goto done;
			}
			if (aik_npz_read(z, "generation", &gen_buf, &gen_len,
					 err, errlen) != 0) {
				free(gen_buf);
				goto done;
			}
			bad = aik_npy_parse(gen_buf, gen_len, &gen_npy, err,
					    errlen) != 0 ||
			      aik_npy_get_ustr(&gen_npy, 0, got,
					       sizeof(got)) < 0;
			free(gen_buf);
			if (bad)
				goto done;
			if (strcmp(got, want) != 0) {
				set_err(err, errlen,
					"engine: embedding_generation mismatch "
					"(snapshot=%s npz=%s)",
					want, got);
				goto done;
			}
		}
	}
	*out_ids = ids;
	*out_n_ids = n_ids;
	*out_matrix = matrix;
	*out_dim = dim;
	ids = NULL;
	matrix = NULL;
	rc = 0;
done:
	if (ids) {
		for (i = 0; i < n_ids; i++)
			free(ids[i]);
		free(ids);
	}
	free(matrix);
	free(ids_buf);
	free(mat_buf);
	aik_npz_close(z);
	return rc;
}

/* 快照记忆按 id 取 NPZ 行（拷贝） */
static double *npz_row(char *const *ids, size_t n_ids, const double *matrix,
		       int dim, const char *id, int *out_dim)
{
	size_t i;

	*out_dim = 0;
	if (!id)
		return NULL;
	for (i = 0; i < n_ids; i++) {
		double *row;

		if (strcmp(ids[i], id) != 0)
			continue;
		row = malloc((size_t)dim * sizeof(double));
		if (!row)
			return NULL;
		memcpy(row, matrix + i * (size_t)dim,
		       (size_t)dim * sizeof(double));
		*out_dim = dim;
		return row;
	}
	return NULL;
}

int aik_engine_load(aik_engine *e, const char *path, char *err, size_t errlen)
{
	aik_snapshot snap;
	aik_config *newcfg = NULL;
	struct resolved rnew;
	aik_space *sp_new = NULL;
	aik_retriever *ret_new = NULL;
	aik_memory **mem_new = NULL;
	size_t n_mem_new = 0;
	size_t cap_mem_new = 0;
	struct aik_edge *edges_new = NULL;
	size_t n_edges_new = 0;
	size_t cap_edges_new = 0;
	aik_space_vector *vecs = NULL;
	size_t n_vecs = 0;
	char **npz_ids = NULL;
	size_t n_npz_ids = 0;
	double *matrix = NULL;
	int npz_dim = 0;
	const aik_json *root;
	const aik_json *jmem;
	const aik_json *jregions;
	const aik_json *jregion_edges;
	const aik_json *jm_edges;
	const char *embedding_file;
	char *npz_path = NULL;
	char *dir = NULL;
	long long snap_wal_seq = 0;
	size_t i;
	int rc = -1;

	if (!e || !path) {
		set_err(err, errlen, "engine: invalid argument to load");
		return -1;
	}
	memset(&snap, 0, sizeof(snap));
	if (aik_snapshot_load(path, &snap, err, errlen) != 0)
		return -1;
	if (aik_snapshot_validate(&snap, err, errlen) != 0)
		goto done;
	root = snap.root;
	snap_wal_seq = json_int_or(root, "wal_sequence", 0);

	newcfg = aik_config_from_json(aik_json_get(root, "config"), err,
				      errlen);
	if (!newcfg) {
		if (!err || !err[0])
			set_err(err, errlen, "engine: invalid snapshot config");
		goto done;
	}
	if (resolve_into(newcfg, &rnew, err, errlen) != 0)
		goto done;

	embedding_file = aik_json_str(aik_json_get(root, "embedding_file"));
	if (!safe_basename(embedding_file)) {
		set_err(err, errlen,
			"engine: snapshot embedding_file is missing/unsafe");
		goto done;
	}
	dir = aik_engine__dup(path);
	if (!dir)
		goto oom;
	{
		char *slash = strrchr(dir, '/');

		if (slash) {
			*slash = '\0';
		} else {
			dir[0] = '.';
			dir[1] = '\0';
		}
	}
	npz_path = path_join(dir, embedding_file);
	if (!npz_path)
		goto oom;
	if (!file_exists(npz_path)) {
		set_err(err, errlen, "engine: embedding sidecar not found: %s",
			npz_path);
		goto done;
	}
	if (load_npz(npz_path, root, &npz_ids, &n_npz_ids, &matrix, &npz_dim,
		     err, errlen) != 0)
		goto done;
	if (npz_dim != rnew.dim) {
		set_err(err, errlen,
			"engine: npz dim %d != config effective dim %d",
			npz_dim, rnew.dim);
		goto done;
	}

	jmem = aik_json_get(root, "memories");
	jregions = aik_json_get(root, "regions");
	jregion_edges = aik_json_get(root, "region_edges");
	jm_edges = aik_json_get(root, "memory_edges");
	if (aik_json_typeof(jmem) != AIK_JSON_ARR) {
		set_err(err, errlen, "engine: snapshot memories is not an array");
		goto done;
	}

	mem_new = calloc(aik_json_count(jmem) ? aik_json_count(jmem) : 1,
			 sizeof(*mem_new));
	vecs = calloc(aik_json_count(jmem) ? aik_json_count(jmem) : 1,
		      sizeof(*vecs));
	if (!mem_new || !vecs)
		goto oom;

	for (i = 0; i < aik_json_count(jmem); i++) {
		const aik_json *item = aik_json_at(jmem, i);
		const char *id = aik_json_str(aik_json_get(item, "id"));
		double *emb;
		int emb_dim = 0;
		aik_memory *m;

		emb = npz_row(npz_ids, n_npz_ids, matrix, npz_dim, id,
			      &emb_dim);
		m = memory_from_json(e, item, emb, emb_dim, err, errlen);
		if (!m)
			goto done;
		if (m->archived) {
			free(m->region_id);
			m->region_id = NULL;
		} else if (m->embedding) {
			vecs[n_vecs].id = m->id;
			vecs[n_vecs].vector = m->embedding;
			vecs[n_vecs].dim = m->dim;
			n_vecs++;
		}
		if (n_mem_new == cap_mem_new) {
			size_t next = cap_mem_new ? cap_mem_new * 2 : 16;
			aik_memory **grown =
				realloc(mem_new, next * sizeof(*grown));

			if (!grown) {
				aik_memory__free(m);
				goto oom;
			}
			mem_new = grown;
			cap_mem_new = next;
		}
		mem_new[n_mem_new++] = m;
	}

	sp_new = aik_space_new(&rnew.region, rnew.dim, err, errlen);
	if (!sp_new)
		goto done;
	aik_space_set_id_fn(sp_new, space_id_trampoline, e);
	/* load 时 last_updated 取引擎时钟（created_at 仍取快照值） */
	aik_space_set_clock(sp_new, e->now, e->now_ud);
	if (aik_space_load_state(sp_new, rnew.dim, vecs, n_vecs, jregions,
				 jregion_edges, err, errlen) != 0)
		goto done;

	for (i = 0; i < n_mem_new; i++) {
		aik_memory *m = mem_new[i];
		const char *rid;

		if (m->archived)
			continue;
		rid = aik_space_region_for(sp_new, m->id);
		free(m->region_id);
		m->region_id = rid ? aik_engine__dup(rid) : NULL;
	}

	if (aik_json_typeof(jm_edges) == AIK_JSON_ARR) {
		for (i = 0; i < aik_json_count(jm_edges); i++) {
			const aik_json *x = aik_json_at(jm_edges, i);
			const char *source;
			const char *target;
			const char *kind;
			const char *note;

			if (aik_json_typeof(x) != AIK_JSON_OBJ) {
				set_err(err, errlen,
					"engine: memory_edges[%zu] is not an object",
					i);
				goto done;
			}
			source = aik_json_str(aik_json_get(x, "source"));
			target = aik_json_str(aik_json_get(x, "target"));
			kind = aik_json_str(aik_json_get(x, "kind"));
			note = aik_json_str(aik_json_get(x, "note"));
			if (!source || !target) {
				set_err(err, errlen,
					"engine: memory_edges[%zu] lacks source/target",
					i);
				goto done;
			}
			if (n_edges_new == cap_edges_new) {
				size_t next =
					cap_edges_new ? cap_edges_new * 2 : 8;
				struct aik_edge *grown = realloc(
					edges_new, next * sizeof(*grown));

				if (!grown)
					goto oom;
				edges_new = grown;
				cap_edges_new = next;
			}
			memset(&edges_new[n_edges_new], 0,
			       sizeof(*edges_new));
			edges_new[n_edges_new].source =
				aik_engine__dup(source);
			edges_new[n_edges_new].target =
				aik_engine__dup(target);
			edges_new[n_edges_new].kind =
				aik_engine__dup(kind ? kind : "reference");
			edges_new[n_edges_new].note =
				aik_engine__dup(note ? note : "");
			edges_new[n_edges_new].weight =
				json_num_or(x, "weight", 1.0);
			if (!edges_new[n_edges_new].source ||
			    !edges_new[n_edges_new].target ||
			    !edges_new[n_edges_new].kind ||
			    !edges_new[n_edges_new].note) {
				edge_free(&edges_new[n_edges_new]);
				goto oom;
			}
			n_edges_new++;
		}
	}

	ret_new = aik_retriever_new(&rnew.rcfg, err, errlen);
	if (!ret_new)
		goto done;

	/* ---- 提交：此后不再失败（WAL 重放失败除外，见下） ---- */
	engine_clear_memories(e);
	engine_clear_edges(e);
	aik_space_free(e->space);
	aik_retriever_free(e->ret);
	if (e->owns_cfg)
		aik_config_free(e->cfg);
	/* 快照可能换了 storage/persistence 配置：旧 WAL 句柄与旧路径一起换掉 */
	if (e->wal) {
		(void)aik_wal_close(e->wal);
		e->wal = NULL;
	}
	wal_capture_clear(&e->wcap);
	resolved_free(&e->r);
	e->cfg = newcfg;
	e->owns_cfg = 1;
	newcfg = NULL;
	e->r = rnew;
	rnew.wal_path = NULL;	/* 所有权转移给 e->r */
	e->space = sp_new;
	sp_new = NULL;
	e->ret = ret_new;
	ret_new = NULL;
	e->mem = mem_new;
	e->n_mem = n_mem_new;
	e->cap_mem = cap_mem_new;
	mem_new = NULL;
	e->edges = edges_new;
	e->n_edges = n_edges_new;
	e->cap_edges = cap_edges_new;
	edges_new = NULL;
	e->splits_base =
		json_int_or(aik_json_get(root, "counters"), "splits", 0);
	e->merges_base =
		json_int_or(aik_json_get(root, "counters"), "merges", 0);
	e->consolidations =
		json_int_or(aik_json_get(root, "counters"), "consolidations", 0);
	e->compressions =
		json_int_or(aik_json_get(root, "counters"), "compressions", 0);
	e->autosave_ops = 0;
	e->wal_seq = snap_wal_seq;
	e->wal_checkpoint_seq = snap_wal_seq;
	e->wal_ops = 0;
	e->wal_recovery_error[0] = '\0';
	rc = 0;

	/*
	 * T4e-D：快照 + WAL 恢复。seq<=checkpoint 的记录由 store 跳过；
	 * 重放 >0 条即 checkpoint（参考 _recover_wal 的 save），失败保留日志。
	 */
	if (e->r.wal_enabled) {
		char werr[512];
		long long rec = 0, last_seq = 0;
		int n;

		werr[0] = '\0';
		n = aik_wal_replay_ex(e->r.wal_path, e->wal_checkpoint_seq,
				      wal_apply_op, e, &rec, &last_seq, werr,
				      sizeof(werr));
		if (n < 0) {
			set_err(err, errlen,
				"WAL replay failed at record %lld; log retained: %s",
				rec, wal_detail(werr, rec));
			rc = -1;
			goto done;
		}
		/* 参考 replay()：sequence = max(sequence, 扫描到的最大 seq) */
		if (last_seq > e->wal_seq)
			e->wal_seq = last_seq;
		e->wal_replayed += n;
		e->wal_ops = n;
		if (n > 0 && aik_engine_save(e, NULL, err, errlen) != 0) {
			char detail[512];

			snprintf(detail, sizeof(detail), "%s",
				 (err && err[0]) ? err : "save failed");
			set_err(err, errlen,
				"WAL recovery checkpoint failed; log retained: %s",
				detail);
			rc = -1;
			goto done;
		}
	}
	goto done;

oom:
	set_err(err, errlen, "engine: out of memory");
done:
	if (mem_new) {
		for (i = 0; i < n_mem_new; i++)
			aik_memory__free(mem_new[i]);
		free(mem_new);
	}
	if (edges_new) {
		for (i = 0; i < n_edges_new; i++)
			edge_free(&edges_new[i]);
		free(edges_new);
	}
	aik_space_free(sp_new);
	aik_retriever_free(ret_new);
	if (newcfg)
		aik_config_free(newcfg);
	if (npz_ids) {
		for (i = 0; i < n_npz_ids; i++)
			free(npz_ids[i]);
		free(npz_ids);
	}
	free(matrix);
	free(vecs);
	free(npz_path);
	free(dir);
	resolved_free(&rnew);
	aik_snapshot_free(&snap);
	return rc;
}

/* ------------------------------------------------------------------ */
/* 强化 / 归档 / 恢复                                                 */
/* ------------------------------------------------------------------ */
static double retention_of(const aik_engine *e, double last_hit,
			   double reference)
{
	double age = (reference - last_hit) / 86400.0;
	double half = cfg_num(e->cfg, "reinforcement.ebbinghaus_half_life_days",
			      7.0);
	double power =
		cfg_num(e->cfg, "reinforcement.ebbinghaus_power", 1.2);

	if (age <= 0.0)
		return 1.0;
	if (half < 1e-9)
		half = 1e-9;
	if (power < 0.1)
		power = 0.1;
	return 1.0 / (1.0 + pow(age / half, power));
}

int aik_engine_reinforce(aik_engine *e, const char *id,
			 aik_json **out_result, char *err, size_t errlen)
{
	aik_memory *m;
	aik_json *out;
	double reference;
	double retention;
	double weight_delta;
	double importance_delta;
	double max_weight;
	double max_importance;
	double min_importance;

	if (out_result)
		*out_result = NULL;
	if (!e) {
		set_err(err, errlen, "engine: engine is NULL");
		return -1;
	}
	if (wal_guard(e, err, errlen) != 0)
		return -1;
	m = find_mem(e, id);
	if (!m || m->archived)
		return 1;
	wal_begin(e);
	reference = e->now(e->now_ud);
	retention = retention_of(e, m->last_hit, reference);
	weight_delta = cfg_num(e->cfg, "reinforcement.hit_weight_delta", 0.10) *
		       retention;
	importance_delta =
		cfg_num(e->cfg, "reinforcement.hit_importance_delta", 0.05) *
		retention;
	max_weight = cfg_num(e->cfg, "reinforcement.max_weight", 5.0);
	max_importance = cfg_num(e->cfg, "reinforcement.max_importance", 1.0);
	min_importance = cfg_num(e->cfg, "reinforcement.min_importance", 0.0);

	m->hit_count += 1;
	m->weight = clampd(m->weight + weight_delta, 0.0, max_weight);
	m->importance = clampd(m->importance + importance_delta,
			       min_importance, max_importance);
	m->last_hit = reference;
	m->freshness = 1.0;
	m->version += 1;

	out = aik_json_new_obj();
	if (!out ||
	    aik_json_obj_put(out, "memory_id",
			     aik_json_new_str(m->id ? m->id : "")) != 0 ||
	    aik_json_obj_put(
		    out, "retention",
		    aik_json_new_num(aik_round_half_even4(retention))) != 0 ||
	    aik_json_obj_put(
		    out, "weight_delta",
		    aik_json_new_num(aik_round_half_even4(weight_delta))) != 0 ||
	    aik_json_obj_put(out, "importance_delta",
			     aik_json_new_num(
				     aik_round_half_even4(importance_delta))) !=
		    0 ||
	    aik_json_obj_put(out, "hit_count",
			     aik_json_new_int(m->hit_count)) != 0) {
		aik_json_free(out);
		set_err(err, errlen, "engine: out of memory (reinforce)");
		wal_abort(e);
		return -1;
	}
	/* 参考 reinforce()：_mutation 结束后显式把 memory_id 加入 dirty */
	if (wal_dirty_add(e, m->id) != 0 || wal_commit(e, 0, err, errlen) != 0) {
		aik_json_free(out);
		return -1;
	}
	if (engine_autosave(e, err, errlen) != 0) {
		aik_json_free(out);
		return -1;
	}
	if (out_result)
		*out_result = out;
	else
		aik_json_free(out);
	return 0;
}

int aik_engine_archive(aik_engine *e, const char *id)
{
	aik_memory *m;

	if (!e)
		return -1;
	if (wal_guard(e, NULL, 0) != 0)
		return -1;
	m = find_mem(e, id);
	if (!m || m->archived)
		return 1;
	wal_begin(e);
	aik_space_remove(e->space, m->id);
	free(m->region_id);
	m->region_id = NULL;
	m->archived = 1;
	if (engine_refresh_index(e, NULL, 0) != 0) {
		wal_abort(e);
		return -1;
	}
	/* 参考 _drop_memory：归档记忆仍在 memories 里 → dirty（patches） */
	if (wal_dirty_add(e, m->id) != 0 || wal_commit(e, 0, NULL, 0) != 0)
		return -1;
	if (engine_autosave(e, NULL, 0) != 0)
		return -1;
	return 0;
}

int aik_engine_restore(aik_engine *e, const char *id)
{
	aik_memory *m;
	const char *rid;

	if (!e)
		return -1;
	if (wal_guard(e, NULL, 0) != 0)
		return -1;
	m = find_mem(e, id);
	if (!m || !m->archived)
		return 1;
	if (!m->embedding || m->dim <= 0)
		return -1;
	wal_begin(e);
	if (aik_space_insert(e->space, m->id, m->embedding, NULL, 0) != 0) {
		wal_abort(e);
		return -1;
	}
	rid = aik_space_region_for(e->space, m->id);
	free(m->region_id);
	m->region_id = rid ? aik_engine__dup(rid) : NULL;
	m->archived = 0;
	if (engine_refresh_index(e, NULL, 0) != 0) {
		wal_abort(e);
		return -1;
	}
	if (wal_dirty_add(e, m->id) != 0 || wal_commit(e, 0, NULL, 0) != 0)
		return -1;
	if (engine_autosave(e, NULL, 0) != 0)
		return -1;
	return 0;
}

/* ------------------------------------------------------------------ */
/* 写路径工具：Python 白空格 / dict 相等 / 字符串数组                 */
/* ------------------------------------------------------------------ */
static int cp_is_space(unsigned int cp)
{
	if (cp >= 0x09 && cp <= 0x0d)
		return 1;
	if (cp >= 0x1c && cp <= 0x20)
		return 1;
	switch (cp) {
	case 0x85:
	case 0xa0:
	case 0x1680:
	case 0x2028:
	case 0x2029:
	case 0x202f:
	case 0x205f:
	case 0x3000:
		return 1;
	default:
		return cp >= 0x2000 && cp <= 0x200a;
	}
}

/* 同 memory.c 的严格 UTF-8 解码：成功返回字节数并写 *cp，非法返回 -1 */
static int utf8_next_cp(const unsigned char *p, unsigned int *cp)
{
	unsigned int c = p[0];
	int len;
	int i;

	if (c < 0x80) {
		*cp = c;
		return 1;
	}
	if ((c & 0xe0) == 0xc0) {
		*cp = c & 0x1fu;
		len = 2;
	} else if ((c & 0xf0) == 0xe0) {
		*cp = c & 0x0fu;
		len = 3;
	} else if ((c & 0xf8) == 0xf0) {
		*cp = c & 0x07u;
		len = 4;
	} else {
		return -1;
	}
	for (i = 1; i < len; i++) {
		if ((p[i] & 0xc0) != 0x80)
			return -1;
		*cp = (*cp << 6) | (p[i] & 0x3fu);
	}
	if ((len == 2 && *cp < 0x80) || (len == 3 && *cp < 0x800) ||
	    (len == 4 && *cp < 0x10000))
		return -1;
	if (*cp >= 0xd800 && *cp <= 0xdfff)
		return -1;
	if (*cp > 0x10ffff)
		return -1;
	return len;
}

/*
 * text_strip_equals - Python `text.strip() == stored`
 *
 * 非法 UTF-8 字节按非空白处理（与 aik_text__is_blank 的 fail-open 一致）。
 */
static int text_strip_equals(const char *patch, const char *stored)
{
	const char *p = patch ? patch : "";
	size_t off = 0;
	size_t start = 0;
	size_t end = 0;
	int seen = 0;
	size_t have;

	while (p[off]) {
		unsigned int cp = 0;
		int len = utf8_next_cp((const unsigned char *)p + off, &cp);
		size_t step = len < 0 ? 1 : (size_t)len;

		if (!(len > 0 && cp_is_space(cp))) {
			if (!seen) {
				start = off;
				seen = 1;
			}
			end = off + step;
		}
		off += step;
	}
	have = seen ? end - start : 0;
	return strlen(stored) == have && memcmp(p + start, stored, have) == 0;
}

/* Python 数值等价：int/float/bool 同值相等（True == 1） */
static int json_is_numeric(const aik_json *v)
{
	aik_json_type t = aik_json_typeof(v);

	return t == AIK_JSON_INT || t == AIK_JSON_NUM || t == AIK_JSON_BOOL;
}

static double json_numeric(const aik_json *v)
{
	switch (aik_json_typeof(v)) {
	case AIK_JSON_BOOL:
		return aik_json_bool(v) ? 1.0 : 0.0;
	case AIK_JSON_INT:
		return (double)aik_json_int(v);
	case AIK_JSON_NUM:
		return aik_json_num(v);
	default:
		return 0.0;
	}
}

/* Python dict/list 深比较（对象键序无关，数值跨类型按值比较） */
static int json_equal(const aik_json *a, const aik_json *b)
{
	aik_json_type ta = aik_json_typeof(a);
	aik_json_type tb = aik_json_typeof(b);
	size_t i;
	size_t n;

	if (json_is_numeric(a) && json_is_numeric(b))
		return json_numeric(a) == json_numeric(b);
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
	case AIK_JSON_STR:
		return strcmp(aik_json_str(a), aik_json_str(b)) == 0;
	case AIK_JSON_ARR:
		n = aik_json_count(a);
		if (n != aik_json_count(b))
			return 0;
		for (i = 0; i < n; i++) {
			if (!json_equal(aik_json_at(a, i), aik_json_at(b, i)))
				return 0;
		}
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
			if (!bv || !json_equal(aik_json_val_at(a, i), bv))
				return 0;
		}
		return 1;
	}
	return 0;
}

static int str_array_equal(char *const *a, size_t na, char *const *b, size_t nb)
{
	size_t i;

	if (na != nb)
		return 0;
	for (i = 0; i < na; i++) {
		if (strcmp(a[i] ? a[i] : "", b[i] ? b[i] : "") != 0)
			return 0;
	}
	return 1;
}

static int str_array_has(char *const *arr, size_t n, const char *id)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (arr[i] && strcmp(arr[i], id) == 0)
			return 1;
	}
	return 0;
}

/* Python set/list.remove 语义：删除所有等于 id 的元素并压缩数组 */
static void str_array_remove(char **arr, size_t *n, const char *id)
{
	size_t i;
	size_t w = 0;

	if (!arr || !n)
		return;
	for (i = 0; i < *n; i++) {
		if (arr[i] && strcmp(arr[i], id) == 0) {
			free(arr[i]);
			continue;
		}
		arr[w++] = arr[i];
	}
	*n = w;
}

/*
 * json_string_list - PATCH 里的 list[str]（route 层已校验；这里 fail closed）
 */
static int json_string_list(const aik_json *arr, char ***out, size_t *n_out,
			    char *err, size_t errlen)
{
	char **items = NULL;
	size_t n = 0;
	size_t cap = 0;
	size_t i;

	*out = NULL;
	*n_out = 0;
	if (aik_json_typeof(arr) != AIK_JSON_ARR) {
		set_err(err, errlen, "engine: tags must be an array of strings");
		return -1;
	}
	for (i = 0; i < aik_json_count(arr); i++) {
		const char *s = aik_json_str(aik_json_at(arr, i));
		char *copy;

		if (!s) {
			set_err(err, errlen,
				"engine: tags[%zu] is not a string", i);
			goto fail;
		}
		if (n == cap) {
			size_t next = cap ? cap * 2 : 8;
			char **grown = realloc(items, next * sizeof(*grown));

			if (!grown) {
				set_err(err, errlen, "engine: out of memory");
				goto fail;
			}
			items = grown;
			cap = next;
		}
		copy = aik_engine__dup(s);
		if (!copy) {
			set_err(err, errlen, "engine: out of memory");
			goto fail;
		}
		items[n++] = copy;
	}
	*out = items;
	*n_out = n;
	return 0;

fail:
	aik_str_array_free(items, n);
	return -1;
}

/* metadata PATCH：整字典替换，但 patch 没带 ns 时保留旧 ns */
static aik_json *metadata_patch(const aik_json *patch, const aik_json *old,
				char *err, size_t errlen)
{
	aik_json *merged = aik_json__clone(patch);
	const aik_json *old_ns;

	if (!merged) {
		set_err(err, errlen, "engine: out of memory (metadata)");
		return NULL;
	}
	old_ns = aik_json_get(old, "ns");
	if (!aik_json_get(merged, "ns") && old_ns) {
		aik_json *copy = aik_json__clone(old_ns);

		if (!copy || aik_json_obj_put(merged, "ns", copy) != 0) {
			aik_json_free(copy);
			aik_json_free(merged);
			set_err(err, errlen, "engine: out of memory (metadata ns)");
			return NULL;
		}
	}
	return merged;
}

/* ------------------------------------------------------------------ */
/* update（sme/memory_manager.py::update_memory）                     */
/* ------------------------------------------------------------------ */
int aik_engine_update(aik_engine *e, const char *id, const aik_json *patch,
		      char *err, size_t errlen)
{
	aik_memory *m;
	const aik_json *j;
	char *new_text = NULL;
	char *new_summary = NULL;
	char **new_tags = NULL;
	size_t n_new_tags = 0;
	aik_json *new_meta = NULL;
	double *new_emb = NULL;
	int has_meta = 0;
	int has_tags = 0;
	int has_importance = 0;
	int has_weight = 0;
	int has_summary = 0;
	int has_text_param = 0;
	int changed = 0;
	int index_change = 0;
	int committed = 0;
	int rc = -1;

	if (!e) {
		set_err(err, errlen, "engine: engine is NULL");
		return -1;
	}
	if (wal_guard(e, err, errlen) != 0)
		return -1;
	m = find_mem(e, id);
	if (!m)
		return 1;
	if (patch && aik_json_typeof(patch) != AIK_JSON_OBJ) {
		set_err(err, errlen, "engine: update patch is not an object");
		return -1;
	}
	/* 参考 _mutation(vectors=text is not None)：patch 带文本键即用 memories */
	has_text_param =
		aik_json_typeof(aik_json_get(patch, "text")) == AIK_JSON_STR;

	/* ---- 暂存并校验所有字段（任何失败都不改记忆） ---- */
	j = aik_json_get(patch, "text");
	if (aik_json_typeof(j) == AIK_JSON_STR) {
		const char *text = aik_json_str(j);

		if (!text_strip_equals(text, m->text)) {
			new_text = aik_engine__dup(text);
			if (!new_text) {
				set_err(err, errlen, "engine: out of memory");
				goto out;
			}
			new_emb = engine_embed(e, text, NULL, err, errlen);
			if (!new_emb)
				goto out;
		}
	} else if (j && aik_json_typeof(j) != AIK_JSON_NULL) {
		set_err(err, errlen, "engine: text must be a string");
		goto out;
	}

	j = aik_json_get(patch, "metadata");
	if (aik_json_typeof(j) == AIK_JSON_OBJ) {
		has_meta = 1;
		new_meta = metadata_patch(j, m->metadata, err, errlen);
		if (!new_meta)
			goto out;
		if (json_equal(j, m->metadata)) {
			aik_json_free(new_meta);
			new_meta = NULL;
			has_meta = 0;
		}
	} else if (j && aik_json_typeof(j) != AIK_JSON_NULL) {
		set_err(err, errlen, "engine: metadata must be an object");
		goto out;
	}

	j = aik_json_get(patch, "tags");
	if (aik_json_typeof(j) == AIK_JSON_ARR) {
		has_tags = 1;
		if (json_string_list(j, &new_tags, &n_new_tags, err, errlen) != 0)
			goto out;
		if (str_array_equal(new_tags, n_new_tags, m->tags, m->n_tags)) {
			aik_str_array_free(new_tags, n_new_tags);
			new_tags = NULL;
			n_new_tags = 0;
			has_tags = 0;
		}
	} else if (j && aik_json_typeof(j) != AIK_JSON_NULL) {
		set_err(err, errlen, "engine: tags must be an array of strings");
		goto out;
	}

	j = aik_json_get(patch, "importance");
	if (json_is_numeric(j)) {
		has_importance = 1;
	} else if (j && aik_json_typeof(j) != AIK_JSON_NULL) {
		set_err(err, errlen, "engine: importance must be a number");
		goto out;
	}

	j = aik_json_get(patch, "weight");
	if (json_is_numeric(j)) {
		has_weight = 1;
	} else if (j && aik_json_typeof(j) != AIK_JSON_NULL) {
		set_err(err, errlen, "engine: weight must be a number");
		goto out;
	}

	j = aik_json_get(patch, "summary");
	if (aik_json_typeof(j) == AIK_JSON_STR) {
		has_summary = 1;
		new_summary = aik_engine__dup(aik_json_str(j));
		if (!new_summary) {
			set_err(err, errlen, "engine: out of memory");
			goto out;
		}
	} else if (j && aik_json_typeof(j) != AIK_JSON_NULL) {
		set_err(err, errlen, "engine: summary must be a string");
		goto out;
	}

	/* ---- text：重编码 → space.remove/insert → text/embedding ---- */
	wal_begin(e);
	if (new_text) {
		const char *rid;
		char *new_rid;

		aik_space_remove(e->space, m->id);
		if (aik_space_insert(e->space, m->id, new_emb, err, errlen) != 0) {
			/* 尽力恢复旧向量，保持空间可用 */
			(void)aik_space_insert(e->space, m->id, m->embedding, NULL,
					       0);
			goto out;
		}
		rid = aik_space_region_for(e->space, m->id);
		new_rid = rid ? aik_engine__dup(rid) : NULL;
		if (rid && !new_rid) {
			set_err(err, errlen, "engine: out of memory (region id)");
			goto out;
		}
		free(m->text);
		m->text = new_text;
		new_text = NULL;
		free(m->embedding);
		m->embedding = new_emb;
		new_emb = NULL;
		m->dim = e->r.dim;
		free(m->region_id);
		m->region_id = new_rid;
		changed = 1;
	}

	if (has_meta) {
		aik_json_free(m->metadata);
		m->metadata = new_meta;
		new_meta = NULL;
		index_change = 1;
	}
	if (has_tags) {
		aik_str_array_free(m->tags, m->n_tags);
		m->tags = new_tags;
		m->n_tags = n_new_tags;
		new_tags = NULL;
		n_new_tags = 0;
		changed = 1;
	}
	if (has_importance) {
		j = aik_json_get(patch, "importance");
		if (json_numeric(j) != m->importance) {
			m->importance = clampd(json_numeric(j), 0.0, 1.0);
			changed = 1;
		}
	}
	if (has_weight) {
		j = aik_json_get(patch, "weight");
		if (json_numeric(j) != m->weight) {
			double w = json_numeric(j);

			m->weight = w < 0.0 ? 0.0 : w;
			changed = 1;
		}
	}
	if (has_summary &&
	    (!m->summary || strcmp(new_summary, m->summary) != 0)) {
		free(m->summary);
		m->summary = new_summary;
		new_summary = NULL;
		changed = 1;
	}

	if (changed) {
		m->last_hit = e->now(e->now_ud);
		m->freshness = 1.0;
		m->version += 1;
	}
	/* 参考 on_upsert：实质变化或 metadata-only 变化都登记 dirty */
	if ((changed || has_meta) && wal_dirty_add(e, m->id) != 0) {
		set_err(err, errlen, "engine: out of memory (wal dirty)");
		goto out;
	}
	if ((changed || index_change) &&
	    engine_refresh_index(e, err, errlen) != 0)
		goto out;
	if (wal_commit(e, has_text_param, err, errlen) != 0)
		goto out;
	committed = 1;
	if (engine_autosave(e, err, errlen) != 0)
		goto out;
	rc = 0;

out:
	if (!committed)
		wal_abort(e);
	free(new_text);
	free(new_summary);
	free(new_emb);
	aik_json_free(new_meta);
	aik_str_array_free(new_tags, n_new_tags);
	return rc;
}

/* ------------------------------------------------------------------ */
/* delete（sme/memory_manager.py::delete_memory + 级联）              */
/* ------------------------------------------------------------------ */
static int memory_covers(const aik_memory *m, const char *id)
{
	const aik_json *covers = aik_json_get(m->metadata, "covers");
	size_t i;

	if (aik_json_typeof(covers) == AIK_JSON_ARR) {
		for (i = 0; i < aik_json_count(covers); i++) {
			const char *s = aik_json_str(aik_json_at(covers, i));

			if (s && strcmp(s, id) == 0)
				return 1;
		}
		return 0;
	}
	if (aik_json_typeof(covers) == AIK_JSON_STR)
		return strstr(aik_json_str(covers), id) != NULL;
	return 0;
}

static int collect_derived(aik_engine *e, const char *id, char ***out,
			   size_t *n_out, char *err, size_t errlen)
{
	char **ids = NULL;
	size_t n = 0;
	size_t cap = 0;
	size_t i;

	*out = NULL;
	*n_out = 0;
	for (i = 0; i < e->n_mem; i++) {
		const aik_memory *other = e->mem[i];

		if (strcmp(other->source ? other->source : "", "summary") != 0)
			continue;
		if (!str_array_has(other->children, other->n_children, id) &&
		    !memory_covers(other, id))
			continue;
		if (n == cap) {
			size_t next = cap ? cap * 2 : 4;
			char **grown = realloc(ids, next * sizeof(*grown));

			if (!grown) {
				set_err(err, errlen, "engine: out of memory");
				aik_str_array_free(ids, n);
				return -1;
			}
			ids = grown;
			cap = next;
		}
		ids[n] = aik_engine__dup(other->id);
		if (!ids[n]) {
			set_err(err, errlen, "engine: out of memory");
			aik_str_array_free(ids, n);
			return -1;
		}
		n++;
	}
	*out = ids;
	*n_out = n;
	return 0;
}

static int engine_delete_impl(aik_engine *e, const char *id, char *err,
			      size_t errlen)
{
	aik_memory *m;
	char **derived = NULL;
	size_t n_derived = 0;
	size_t idx;
	size_t i;
	int rc = 0;

	for (idx = 0; idx < e->n_mem; idx++) {
		if (strcmp(e->mem[idx]->id, id) == 0)
			break;
	}
	if (idx == e->n_mem)
		return 1;
	m = e->mem[idx];
	memmove(&e->mem[idx], &e->mem[idx + 1],
		(e->n_mem - idx - 1) * sizeof(*e->mem));
	e->n_mem--;
	/* 参考 _drop_memory：不在 memories 里 → _wal_deleted.add */
	if (wal_deleted_add(e, m->id) != 0)
		rc = -1;

	/* 派生摘要（source=="summary" 且 id 在 children/covers 里）递归删除 */
	if (collect_derived(e, id, &derived, &n_derived, err, errlen) != 0)
		rc = -1;
	for (i = 0; i < n_derived; i++) {
		if (engine_delete_impl(e, derived[i], err, errlen) == -1)
			rc = -1;
	}
	aik_str_array_free(derived, n_derived);

	aik_space_remove(e->space, m->id);

	for (i = e->n_edges; i-- > 0;) {
		if (strcmp(e->edges[i].source, m->id) == 0 ||
		    strcmp(e->edges[i].target, m->id) == 0) {
			edge_free(&e->edges[i]);
			memmove(&e->edges[i], &e->edges[i + 1],
				(e->n_edges - i - 1) * sizeof(*e->edges));
			e->n_edges--;
		}
	}
	for (i = 0; i < e->n_mem; i++) {
		aik_memory *other = e->mem[i];
		int affected = 0;

		if (other->parent_id && strcmp(other->parent_id, id) == 0)
			affected = 1;
		if (str_array_has(other->neighbors, other->n_neighbors, id))
			affected = 1;
		if (str_array_has(other->children, other->n_children, id))
			affected = 1;
		str_array_remove(other->neighbors, &other->n_neighbors, id);
		str_array_remove(other->children, &other->n_children, id);
		if (other->parent_id && strcmp(other->parent_id, id) == 0) {
			free(other->parent_id);
			other->parent_id = NULL;
		}
		/* 参考 delete_memory：受影响的其他记忆 on_upsert → dirty */
		if (affected && wal_dirty_add(e, other->id) != 0)
			rc = -1;
	}
	aik_memory__free(m);
	return rc;
}

int aik_engine_delete(aik_engine *e, const char *id, char *err, size_t errlen)
{
	int rc;

	if (!e || !id) {
		set_err(err, errlen, "engine: invalid argument to delete");
		return -1;
	}
	if (wal_guard(e, err, errlen) != 0)
		return -1;
	wal_begin(e);
	rc = engine_delete_impl(e, id, err, errlen);
	if (rc != 0) {
		wal_abort(e);
		return rc;
	}
	if (engine_refresh_index(e, err, errlen) != 0) {
		wal_abort(e);
		return -1;
	}
	if (wal_commit(e, 0, err, errlen) != 0)
		return -1;
	if (engine_autosave(e, err, errlen) != 0)
		return -1;
	return 0;
}

/* ------------------------------------------------------------------ */
/* 检索                                                               */
/* ------------------------------------------------------------------ */
static double cos_sim(const double *a, const double *b, int dim)
{
	double dot = 0.0;
	double na = 0.0;
	double nb = 0.0;
	int i;

	if (!a || !b || dim <= 0)
		return 0.0;
	for (i = 0; i < dim; i++) {
		dot += a[i] * b[i];
		na += a[i] * a[i];
		nb += b[i] * b[i];
	}
	na = sqrt(na);
	nb = sqrt(nb);
	if (na < 1e-12 || nb < 1e-12)
		return 0.0;
	return dot / (na * nb);
}

/* 检索视图（BM25/两阶段检索共用；views 容量必须 >= e->n_mem） */
static void fill_views(const aik_engine *e, aik_memory_view *views)
{
	size_t i;

	for (i = 0; i < e->n_mem; i++) {
		const aik_memory *m = e->mem[i];

		views[i].id = m->id;
		views[i].text = m->text;
		views[i].metadata = m->metadata;
		views[i].tags = (const char *const *)m->tags;
		views[i].n_tags = m->n_tags;
		views[i].importance = m->importance;
		views[i].weight = m->weight;
		views[i].freshness = m->freshness;
		views[i].hit_count = (int)m->hit_count;
		views[i].last_hit = m->last_hit;
		views[i].source = m->source;
		views[i].archived = m->archived;
		views[i].embedding = m->embedding;
		views[i].dim = m->dim;
	}
}

/* 写路径后重建 BM25（Python retriever.index_memory/drop_memory 的全量等价） */
static int engine_refresh_index(aik_engine *e, char *err, size_t errlen)
{
	aik_memory_view *views = NULL;

	if (e->n_mem > 0) {
		views = calloc(e->n_mem, sizeof(*views));
		if (!views) {
			set_err(err, errlen, "engine: out of memory (views)");
			return -1;
		}
		fill_views(e, views);
	}
	if (aik_retriever_index(e->ret, views, e->n_mem, err, errlen) != 0) {
		free(views);
		return -1;
	}
	free(views);
	return 0;
}

int aik_engine_search(aik_engine *e, const aik_search_query *q,
		      aik_search_hit **out, size_t *n_out,
		      char *err, size_t errlen)
{
	aik_memory_view *views = NULL;
	aik_graph_edge *edges = NULL;
	double *qv = NULL;
	aik_search_ctx ctx;
	size_t i;
	size_t n;
	size_t raw;
	size_t kept;
	double floor_sim;
	int rc = -1;

	if (out)
		*out = NULL;
	if (n_out)
		*n_out = 0;
	if (!e || !q || !out || !n_out) {
		set_err(err, errlen, "engine: invalid argument to search");
		return -1;
	}
	if (q->top_k <= 0)
		return 0;	/* Python: top_k<=0 直接返回 []（不编码 query） */
	n = e->n_mem;
	if (n > 0) {
		views = calloc(n, sizeof(*views));
		if (!views) {
			set_err(err, errlen, "engine: out of memory (views)");
			return -1;
		}
		fill_views(e, views);
	}
	if (aik_retriever_index(e->ret, views, n, err, errlen) != 0)
		goto done;
	qv = engine_embed(e, q->text, NULL, err, errlen);
	if (!qv)
		goto done;
	if (e->n_edges > 0) {
		edges = calloc(e->n_edges, sizeof(*edges));
		if (!edges) {
			set_err(err, errlen, "engine: out of memory (edges)");
			goto done;
		}
		for (i = 0; i < e->n_edges; i++) {
			edges[i].source = e->edges[i].source;
			edges[i].target = e->edges[i].target;
			edges[i].kind = e->edges[i].kind;
			edges[i].weight = e->edges[i].weight;
		}
	}
	memset(&ctx, 0, sizeof(ctx));
	ctx.space = e->space;
	ctx.memories = views;
	ctx.n_memories = n;
	ctx.edges = edges;
	ctx.n_edges = edges ? e->n_edges : 0;
	ctx.query_vector = qv;
	ctx.dim = e->r.dim;
	ctx.cfg = &e->r.rcfg;
	ctx.weights = &e->r.weights;
	ctx.decay = &e->r.decay;
	ctx.policy_full_memory = e->r.policy_full;
	ctx.policy_importance_threshold = e->r.policy_threshold;
	ctx.reference = e->now(e->now_ud);
	if (aik_retriever_search(e->ret, &ctx, q, out, n_out, err, errlen) != 0)
		goto done;

	/* min_similarity 过滤（engine._search_locked 的 floor 分支） */
	floor_sim = cfg_num(e->cfg, "retrieval.min_similarity", -1.0);
	if (floor_sim > -1.0 && *out) {
		raw = *n_out;
		kept = 0;
		for (i = 0; i < raw; i++) {
			aik_search_hit *h = &(*out)[i];
			aik_memory *m = find_mem(e, h->memory_id);
			int keep = m && m->embedding &&
				   cos_sim(qv, m->embedding, e->r.dim) >=
					   floor_sim;

			if (!keep) {
				free(h->memory_id);
				free(h->region_id);
				h->memory_id = NULL;
				h->region_id = NULL;
				continue;
			}
			if (kept != i) {
				(*out)[kept] = *h;
				h->memory_id = NULL;
				h->region_id = NULL;
			}
			kept++;
		}
		*n_out = kept;
	}
	/* 截断 requested_k */
	if (*out && *n_out > (size_t)q->top_k) {
		for (i = (size_t)q->top_k; i < *n_out; i++) {
			free((*out)[i].memory_id);
			free((*out)[i].region_id);
			(*out)[i].memory_id = NULL;
			(*out)[i].region_id = NULL;
		}
		*n_out = (size_t)q->top_k;
	}
	rc = 0;
done:
	free(views);
	free(edges);
	free(qv);
	return rc;
}

int aik_engine_search_regions(aik_engine *e, const char *text, int top_k,
			      aik_region_hit **out, size_t *n_out,
			      char *err, size_t errlen)
{
	double *qv;
	int rc;

	if (out)
		*out = NULL;
	if (n_out)
		*n_out = 0;
	if (!e || !out || !n_out) {
		set_err(err, errlen,
			"engine: invalid argument to search_regions");
		return -1;
	}
	if (top_k <= 0)
		return 0;	/* 与 space.query_regions 的 top_k<=0 短路一致 */
	qv = engine_embed(e, text ? text : "", NULL, err, errlen);
	if (!qv)
		return -1;
	rc = aik_space_query_regions(e->space, qv, top_k, out, n_out, err,
				     errlen);
	free(qv);
	return rc;
}

aik_json *aik_search_hit_to_json(aik_engine *e, const aik_search_hit *hit)
{
	aik_memory *m;
	aik_json *d;
	aik_json *bd;
	const aik_score_breakdown *b;

	if (!e || !hit || !hit->memory_id)
		return NULL;
	m = find_mem(e, hit->memory_id);
	if (!m)
		return NULL;
	d = aik_memory_to_json(m, 0);
	if (!d)
		return NULL;
	b = &hit->breakdown;
	bd = aik_json_new_obj();
	if (!bd ||
	    aik_json_obj_put(bd, "semantic",
			     aik_json_new_num(b->semantic)) != 0 ||
	    aik_json_obj_put(bd, "importance",
			     aik_json_new_num(b->importance)) != 0 ||
	    aik_json_obj_put(bd, "freshness",
			     aik_json_new_num(b->freshness)) != 0 ||
	    aik_json_obj_put(bd, "weight", aik_json_new_num(b->weight)) != 0 ||
	    aik_json_obj_put(bd, "decay", aik_json_new_num(b->decay)) != 0 ||
	    aik_json_obj_put(bd, "hit_count",
			     aik_json_new_num(b->hit_count)) != 0 ||
	    aik_json_obj_put(bd, "recency",
			     aik_json_new_num(b->recency)) != 0 ||
	    aik_json_obj_put(bd, "region", aik_json_new_num(b->region)) != 0 ||
	    aik_json_obj_put(bd, "final", aik_json_new_num(b->final)) != 0) {
		aik_json_free(bd);
		aik_json_free(d);
		return NULL;
	}
	if (aik_json_obj_put(d, "score", aik_json_new_num(hit->score)) != 0 ||
	    aik_json_obj_put(d, "breakdown", bd) != 0) {
		aik_json_free(d);
		return NULL;
	}
	{
		aik_json *rid = hit->region_id
					? aik_json_new_str(hit->region_id)
					: aik_json_new_null();

		if (!rid || aik_json_obj_set(d, "region_id", rid) != 0) {
			aik_json_free(rid);
			aik_json_free(d);
			return NULL;
		}
	}
	if (aik_json_obj_put(d, "region_score",
			     aik_json_new_num(hit->region_score)) != 0 ||
	    aik_json_obj_put(d, "keyword_score",
			     aik_json_new_num(hit->keyword_score)) != 0 ||
	    aik_json_obj_put(d, "vector_score",
			     aik_json_new_num(hit->vector_score)) != 0 ||
	    aik_json_obj_put(d, "metadata_match",
			     aik_json_new_bool(hit->metadata_match ? 1 : 0)) !=
		    0) {
		aik_json_free(d);
		return NULL;
	}
	return d;
}

/* ------------------------------------------------------------------ */
/* 统计 / 导出 / regions                                              */
/* ------------------------------------------------------------------ */
/* 所有权安全的 put：成功后 *slot 置 NULL；失败时 v 已被 put 释放 */
static int put_slot(aik_json **slot, aik_json *obj, const char *key)
{
	aik_json *v = *slot;

	if (!v)
		return -1;
	*slot = NULL;
	if (aik_json_obj_put(obj, key, v) != 0) {
		aik_json_free(v);
		return -1;
	}
	return 0;
}

/* 新建一个标量并放入；失败时 free（节点未被转移） */
static int put_new(aik_json *obj, const char *key, aik_json *v)
{
	if (!v)
		return -1;
	if (aik_json_obj_put(obj, key, v) != 0) {
		aik_json_free(v);
		return -1;
	}
	return 0;
}

/*
 * provider_name - Python embeddings.model_name 的等价物
 *
 * hashing：HashingEmbeddingProvider.model_name = "hashing-d{dim}-w{window}"，
 * 其中 window 已 max(1, ...)、dim 是配置原生维度（不是 mrl 后的有效维）。
 * 其它 provider（T4a 不可达）：用 config.embedding.model。
 */
static void provider_name(const aik_engine *e, char *buf, size_t buflen)
{
	const char *provider = cfg_str(e->cfg, "embedding.provider", "hashing");

	if (strcmp(provider, "hashing") == 0) {
		int window = e->r.emb.window;

		if (window < 1)
			window = 1;
		snprintf(buf, buflen, "hashing-d%d-w%d", e->r.emb.dim,
			 window);
		return;
	}
	snprintf(buf, buflen, "%s", cfg_str(e->cfg, "embedding.model", ""));
}

static aik_json *memory_stats_json(aik_engine *e)
{
	aik_json *out;
	long long total = 0;
	long long active = 0;
	long long archived = 0;
	long long summarized = 0;
	long long total_hits = 0;
	long long active_hits = 0;
	double sum_weight = 0.0;
	double sum_importance = 0.0;
	double min_created = 0.0;
	int have_created = 0;
	size_t i;

	for (i = 0; i < e->n_mem; i++) {
		const aik_memory *m = e->mem[i];

		total++;
		total_hits += m->hit_count;
		if (m->summary)
			summarized++;
		if (m->archived) {
			archived++;
			continue;
		}
		active++;
		active_hits += m->hit_count;
		sum_weight += m->weight;
		sum_importance += m->importance;
		if (!have_created || m->created_at < min_created) {
			min_created = m->created_at;
			have_created = 1;
		}
	}

	out = aik_json_new_obj();
	if (!out)
		return NULL;
	if (put_new(out, "total", aik_json_new_int(total)) != 0 ||
	    put_new(out, "active", aik_json_new_int(active)) != 0 ||
	    put_new(out, "archived", aik_json_new_int(archived)) != 0 ||
	    put_new(out, "summarized", aik_json_new_int(summarized)) != 0 ||
	    put_new(out, "total_hits", aik_json_new_int(total_hits)) != 0 ||
	    put_new(out, "avg_weight",
		    aik_json_new_num(active ? sum_weight / (double)active
					    : 0.0)) != 0 ||
	    put_new(out, "avg_importance",
		    aik_json_new_num(active ? sum_importance / (double)active
					    : 0.0)) != 0 ||
	    put_new(out, "avg_hit_count",
		    aik_json_new_num(active
					     ? (double)active_hits / (double)active
					     : 0.0)) != 0 ||
	    put_new(out, "oldest_age_days",
		    aik_json_new_num(have_created
					     ? (e->now(e->now_ud) - min_created) /
						       86400.0
					     : 0.0)) != 0) {
		aik_json_free(out);
		return NULL;
	}
	return out;
}

static aik_json *region_stats_json(aik_engine *e, long long *out_splits,
				   long long *out_merges)
{
	aik_region_stats st;
	aik_json *out;
	long long splits;
	long long merges;

	if (aik_space_region_stats(e->space, &st) != 0)
		return NULL;
	splits = e->splits_base + st.split_count;
	merges = e->merges_base + st.merge_count;
	if (out_splits)
		*out_splits = splits;
	if (out_merges)
		*out_merges = merges;
	out = aik_json_new_obj();
	if (!out)
		return NULL;
	if (put_new(out, "count", aik_json_new_int(st.count)) != 0 ||
	    put_new(out, "avg_size",
		    aik_json_new_num(st.count ? st.avg_size : 0.0)) != 0 ||
	    put_new(out, "avg_density",
		    aik_json_new_num(st.count ? st.avg_density : 0.0)) != 0 ||
	    put_new(out, "max_size", aik_json_new_int(st.max_size)) != 0 ||
	    put_new(out, "min_size", aik_json_new_int(st.min_size)) != 0 ||
	    put_new(out, "avg_radius",
		    aik_json_new_num(st.count ? st.avg_radius : 0.0)) != 0 ||
	    put_new(out, "edge_count", aik_json_new_int(st.edge_count)) != 0 ||
	    put_new(out, "avg_neighbors",
		    aik_json_new_num(st.count ? st.avg_neighbors : 0.0)) != 0 ||
	    put_new(out, "split_count", aik_json_new_int(splits)) != 0 ||
	    put_new(out, "merge_count", aik_json_new_int(merges)) != 0) {
		aik_json_free(out);
		return NULL;
	}
	return out;
}

int aik_engine_stats(aik_engine *e, aik_json **out, char *err, size_t errlen)
{
	aik_json *root = NULL;
	aik_json *memstats = NULL;
	aik_json *regstats = NULL;
	aik_json *policy = NULL;
	long long splits = 0;
	long long merges = 0;
	char provider[160];

	if (out)
		*out = NULL;
	if (!e || !out) {
		set_err(err, errlen, "engine: invalid argument to stats");
		return -1;
	}
	memstats = memory_stats_json(e);
	regstats = region_stats_json(e, &splits, &merges);
	policy = aik_json_new_obj();
	root = aik_json_new_obj();
	if (!memstats || !regstats || !policy || !root)
		goto oom;
	provider_name(e, provider, sizeof(provider));
	if (put_new(policy, "full_memory",
		    aik_json_new_bool(e->r.policy_full ? 1 : 0)) != 0 ||
	    put_new(policy, "importance_threshold",
		    aik_json_new_num(e->r.policy_threshold)) != 0 ||
	    put_new(policy, "decay_enabled",
		    aik_json_new_bool(e->r.decay.enabled ? 1 : 0)) != 0)
		goto oom;
	if (put_slot(&memstats, root, "memories") != 0 ||
	    put_slot(&regstats, root, "regions") != 0 ||
	    put_new(root, "splits", aik_json_new_int(splits)) != 0 ||
	    put_new(root, "merges", aik_json_new_int(merges)) != 0 ||
	    put_new(root, "consolidations",
		    aik_json_new_int(e->consolidations)) != 0 ||
	    put_new(root, "compressions",
		    aik_json_new_int(e->compressions)) != 0 ||
	    put_new(root, "graph_edges",
		    aik_json_new_int((long long)e->n_edges)) != 0 ||
	    put_new(root, "provider", aik_json_new_str(provider)) != 0 ||
	    put_slot(&policy, root, "policy") != 0)
		goto oom;
	*out = root;
	return 0;

oom:
	aik_json_free(memstats);
	aik_json_free(regstats);
	aik_json_free(policy);
	aik_json_free(root);
	set_err(err, errlen, "engine: out of memory (stats)");
	return -1;
}

static aik_json *edge_json(const struct aik_edge *e)
{
	aik_json *x = aik_json_new_obj();

	if (!x)
		return NULL;
	if (put_new(x, "source", aik_json_new_str(e->source)) != 0 ||
	    put_new(x, "target", aik_json_new_str(e->target)) != 0 ||
	    put_new(x, "kind", aik_json_new_str(e->kind)) != 0 ||
	    put_new(x, "weight", aik_json_new_num(e->weight)) != 0 ||
	    put_new(x, "note", aik_json_new_str(e->note)) != 0) {
		aik_json_free(x);
		return NULL;
	}
	return x;
}

/* ------------------------------------------------------------------ */
/* 图：/graph 与 /graph/link                                          */
/* ------------------------------------------------------------------ */
int aik_engine_graph(aik_engine *e, aik_json **out, char *err, size_t errlen)
{
	aik_json *root = NULL;
	aik_json *arr = NULL;
	size_t i;

	if (out)
		*out = NULL;
	if (!e || !out) {
		set_err(err, errlen, "engine: invalid argument to graph");
		return -1;
	}
	root = aik_json_new_obj();
	arr = aik_json_new_arr();
	if (!root || !arr)
		goto oom;
	for (i = 0; i < e->n_edges; i++) {
		aik_json *x = edge_json(&e->edges[i]);

		if (!x || aik_json_arr_push(arr, x) != 0) {
			aik_json_free(x);
			goto oom;
		}
	}
	if (put_slot(&arr, root, "edges") != 0)
		goto oom;
	*out = root;
	return 0;

oom:
	aik_json_free(arr);
	aik_json_free(root);
	set_err(err, errlen, "engine: out of memory (graph)");
	return -1;
}

int aik_engine_link(aik_engine *e, const char *a, const char *b,
		    const char *kind, double weight, const char *note,
		    char *err, size_t errlen)
{
	const char *k;

	if (!e || !a || !b) {
		set_err(err, errlen, "engine: invalid argument to link");
		return -1;
	}
	if (wal_guard(e, err, errlen) != 0)
		return -1;
	k = kind ? kind : "reference";
	if (strcmp(a, b) == 0) {
		/* Python MemoryGraph.add_edge 对自环抛 ValueError */
		set_err(err, errlen,
			"engine: self-loops are not allowed in the memory graph");
		return -1;
	}
	if (!find_mem(e, a) || !find_mem(e, b))
		return 1;
	wal_begin(e);
	if (engine_add_edge(e, a, b, k, weight, note ? note : "") != 0) {
		set_err(err, errlen, "engine: out of memory (graph edge)");
		wal_abort(e);
		return -1;
	}
	if (strcmp(k, "cause") == 0 &&
	    engine_add_edge(e, b, a, "conversation", 1.0, "timeline") != 0) {
		set_err(err, errlen, "engine: out of memory (graph edge)");
		wal_abort(e);
		return -1;
	}
	/* 不改 Memory.neighbors（与 memory_manager.link 一致） */
	if (wal_commit(e, 0, err, errlen) != 0)
		return -1;
	if (engine_autosave(e, err, errlen) != 0)
		return -1;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Region 演化（/regions/evolve）                                     */
/* ------------------------------------------------------------------ */
static char *evolution_detail(const aik_space_event *ev)
{
	const char *kind = ev->kind ? ev->kind : "";
	char *detail;

	if (strcmp(kind, "split") == 0) {
		size_t need = 128 + strlen(ev->region_id ? ev->region_id : "");

		detail = malloc(need);
		if (!detail)
			return NULL;
		snprintf(detail, need, "%zu -> %zu members (density %.1f)",
			 ev->n_region_members, ev->n_other_members, ev->density);
		return detail;
	}
	if (strcmp(kind, "merge") == 0) {
		const char *absorbed = ev->other_id ? ev->other_id : "";
		size_t need = strlen(absorbed) + 64;

		detail = malloc(need);
		if (!detail)
			return NULL;
		snprintf(detail, need, "absorbed %s (%zu members)", absorbed,
			 ev->n_other_members);
		return detail;
	}
	if (strcmp(kind, "region_created") == 0) {
		char buf[64];

		snprintf(buf, sizeof(buf), "%zu members", ev->n_region_members);
		return aik_engine__dup(buf);
	}
	/* region_deleted 及未知类型：Python detail 默认 "" */
	return aik_engine__dup("");
}

int aik_engine_evolve(aik_engine *e, aik_json **out, char *err, size_t errlen)
{
	aik_space_event *events = NULL;
	size_t n_events = 0;
	aik_json *root = NULL;
	aik_json *arr = NULL;
	size_t i;

	if (out)
		*out = NULL;
	if (!e || !out) {
		set_err(err, errlen, "engine: invalid argument to evolve");
		return -1;
	}
	if (aik_space_evolution_pass(e->space, &events, &n_events, err, errlen) !=
	    0)
		return -1;
	root = aik_json_new_obj();
	arr = aik_json_new_arr();
	if (!root || !arr)
		goto oom;
	for (i = 0; i < n_events; i++) {
		const aik_space_event *ev = &events[i];
		aik_json *x = aik_json_new_obj();
		char *detail = evolution_detail(ev);

		if (!x || !detail ||
		    put_new(x, "kind",
			    aik_json_new_str(ev->kind ? ev->kind : "")) != 0 ||
		    put_new(x, "region_id",
			    aik_json_new_str(ev->region_id ? ev->region_id : "")) !=
			    0 ||
		    put_new(x, "detail", aik_json_new_str(detail)) != 0 ||
		    aik_json_arr_push(arr, x) != 0) {
			free(detail);
			aik_json_free(x);
			goto oom;
		}
		free(detail);
	}
	if (put_slot(&arr, root, "events") != 0)
		goto oom;
	aik_space_events_free(events, n_events);
	*out = root;
	return 0;

oom:
	aik_space_events_free(events, n_events);
	aik_json_free(arr);
	aik_json_free(root);
	set_err(err, errlen, "engine: out of memory (evolve)");
	return -1;
}

int aik_engine_export(aik_engine *e, aik_json **out, char *err, size_t errlen)
{
	aik_json *root = NULL;
	aik_json *memories = NULL;
	aik_json *graph = NULL;
	aik_json *edges = NULL;
	aik_json *stats = NULL;
	size_t i;

	if (out)
		*out = NULL;
	if (!e || !out) {
		set_err(err, errlen, "engine: invalid argument to export");
		return -1;
	}
	memories = aik_json_new_arr();
	graph = aik_json_new_obj();
	edges = aik_json_new_arr();
	root = aik_json_new_obj();
	if (!memories || !graph || !edges || !root)
		goto oom;
	for (i = 0; i < e->n_mem; i++) {
		aik_json *d = aik_memory_to_json(e->mem[i], 1);

		if (!d || aik_json_arr_push(memories, d) != 0) {
			aik_json_free(d);
			goto oom;
		}
	}
	for (i = 0; i < e->n_edges; i++) {
		aik_json *x = edge_json(&e->edges[i]);

		if (!x || aik_json_arr_push(edges, x) != 0) {
			aik_json_free(x);
			goto oom;
		}
	}
	if (put_slot(&edges, graph, "edges") != 0)
		goto oom;
	if (aik_engine_stats(e, &stats, err, errlen) != 0)
		goto oom;
	if (put_slot(&memories, root, "memories") != 0 ||
	    put_slot(&graph, root, "graph") != 0 ||
	    put_slot(&stats, root, "stats") != 0)
		goto oom;
	*out = root;
	return 0;

oom:
	aik_json_free(memories);
	aik_json_free(edges);
	aik_json_free(graph);
	aik_json_free(stats);
	aik_json_free(root);
	set_err(err, errlen, "engine: out of memory (export)");
	return -1;
}

/* ------------------------------------------------------------------ */
/* 配置热重建（PUT /config）                                          */
/* ------------------------------------------------------------------ */
struct emb_identity {
	const char *provider;
	const char *model;
	const char *revision;
	long long dim;
	long long mrl_dim;
	long long hash_factors;
	long long hash_seed;
};

static void emb_identity(const aik_config *c, struct emb_identity *id)
{
	id->provider = cfg_str(c, "embedding.provider", "hashing");
	id->model = cfg_str(c, "embedding.model", "text-embedding-3-small");
	id->revision = cfg_str(c, "embedding.revision", "");
	id->dim = cfg_i64(c, "embedding.dim", 64);
	id->mrl_dim = cfg_i64(c, "embedding.mrl_dim", 0);
	id->hash_factors = cfg_i64(c, "embedding.hash_factors", 3);
	id->hash_seed = cfg_i64(c, "embedding.hash_seed", 0);
}

static int emb_append(char *buf, size_t cap, size_t *off, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (*off >= cap)
		return -1;
	va_start(ap, fmt);
	n = vsnprintf(buf + *off, cap - *off, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= cap - *off)
		return -1;
	*off += (size_t)n;
	return 0;
}

/*
 * embedding_identity_changed - 身份变化判定 + 中文提示
 *
 * 返回 1 表示变化（msg 已写），0 表示未变。基础三元组（provider/model/
 * dim）的提示文案与参考逐字一致；额外四项（mrl_dim/revision/hash_factors/
 * hash_seed）是 TASK-BOOK §7.3 的有意闸门修正，追加在箭头之后。
 */
static int embedding_identity_changed(const aik_config *a,
				      const aik_config *b,
				      char *msg, size_t msglen)
{
	struct emb_identity o, n;
	char extra[384];
	size_t off = 0;
	int changed = 0;

	emb_identity(a, &o);
	emb_identity(b, &n);
	extra[0] = '\0';
	if (o.mrl_dim != n.mrl_dim) {
		if (emb_append(extra, sizeof(extra), &off,
			       "%smrl_dim %lld→%lld", off ? "，" : "",
			       o.mrl_dim, n.mrl_dim) != 0)
			return 0;
		changed = 1;
	}
	if (strcmp(o.revision, n.revision) != 0) {
		if (emb_append(extra, sizeof(extra), &off,
			       "%srevision \"%s\"→\"%s\"", off ? "，" : "",
			       o.revision, n.revision) != 0)
			return 0;
		changed = 1;
	}
	if (o.hash_factors != n.hash_factors) {
		if (emb_append(extra, sizeof(extra), &off,
			       "%shash_factors %lld→%lld", off ? "，" : "",
			       o.hash_factors, n.hash_factors) != 0)
			return 0;
		changed = 1;
	}
	if (o.hash_seed != n.hash_seed) {
		if (emb_append(extra, sizeof(extra), &off,
			       "%shash_seed %lld→%lld", off ? "，" : "",
			       o.hash_seed, n.hash_seed) != 0)
			return 0;
		changed = 1;
	}
	if (strcmp(o.provider, n.provider) != 0 ||
	    strcmp(o.model, n.model) != 0 || o.dim != n.dim)
		changed = 1;
	if (!changed)
		return 0;
	if (extra[0]) {
		snprintf(msg, msglen,
			 "embedding 配置变更（%s/%s/%lld → %s/%s/%lld；%s）"
			 "会使现有记忆的向量维度与新配置不一致，需要新库或清空"
			 "现有记忆后重启服务；请先导出记忆并清空，再修改 "
			 "embedding 配置",
			 o.provider, o.model, o.dim, n.provider, n.model, n.dim,
			 extra);
	} else {
		snprintf(msg, msglen,
			 "embedding 配置变更（%s/%s/%lld → %s/%s/%lld）"
			 "会使现有记忆的向量维度与新配置不一致，需要新库或清空"
			 "现有记忆后重启服务；请先导出记忆并清空，再修改 "
			 "embedding 配置",
			 o.provider, o.model, o.dim, n.provider, n.model, n.dim);
	}
	return 1;
}

int aik_engine_rebuild(aik_engine *old, aik_config *new_cfg,
		       aik_engine **out, char *err, size_t errlen)
{
	aik_json *ex = NULL;
	const aik_json *edges;
	aik_engine *neu = NULL;
	aik_region_stats st;
	size_t i, n;
	int rc = -1;

	if (out)
		*out = NULL;
	if (!old || !new_cfg || !out) {
		set_err(err, errlen, "engine: invalid argument to rebuild");
		if (new_cfg)
			aik_config_free(new_cfg);
		return -1;
	}
	if (old->n_mem > 0) {
		char msg[768];

		if (embedding_identity_changed(old->cfg, new_cfg, msg,
					       sizeof(msg))) {
			set_err(err, errlen, "%s", msg);
			aik_config_free(new_cfg);
			return 1;
		}
	}
	if (aik_engine_export(old, &ex, err, errlen) != 0) {
		aik_config_free(new_cfg);
		return -1;
	}
	neu = aik_engine_new(new_cfg, 1, old->now, old->now_ud, old->id_fn,
			     old->id_ud, err, errlen);
	if (!neu) {
		aik_json_free(ex);
		return -1;
	}
	new_cfg = NULL;		/* 所有权已交给 neu */
	if (aik_engine_import(neu, aik_json_get(ex, "memories"), NULL, err,
			      errlen) != 0)
		goto done;
	edges = aik_json_get(aik_json_get(ex, "graph"), "edges");
	n = edges ? aik_json_count(edges) : 0;
	for (i = 0; i < n; i++) {
		const aik_json *x = aik_json_at(edges, i);
		const char *src = aik_json_str(aik_json_get(x, "source"));
		const char *tgt = aik_json_str(aik_json_get(x, "target"));
		const char *kind = aik_json_str(aik_json_get(x, "kind"));
		const char *note = aik_json_str(aik_json_get(x, "note"));
		double w = json_num_or(x, "weight", 1.0);

		if (!src || !tgt)
			continue;
		if (engine_add_edge(neu, src, tgt,
				    kind ? kind : "reference", w,
				    note ? note : "") != 0) {
			set_err(err, errlen,
				"engine: out of memory (rebuild graph)");
			goto done;
		}
	}
	/*
	 * 计数器口径与 Python rebuild_engine_with 一致：参考在 import 之后
	 * 用旧引擎计数**整体覆盖**新引擎计数器（import 期间自动演化产生的
	 * 增量被丢弃）。C 的统计口径是 base + space 实时计数，因此把 base
	 * 反解成 old_total - new_space_count，使可观察总量等于旧值。
	 */
	if (aik_space_region_stats(old->space, &st) == 0) {
		long long old_splits =
			old->splits_base + (long long)st.split_count;
		long long old_merges =
			old->merges_base + (long long)st.merge_count;
		aik_region_stats nst;

		if (aik_space_region_stats(neu->space, &nst) == 0) {
			neu->splits_base =
				old_splits - (long long)nst.split_count;
			neu->merges_base =
				old_merges - (long long)nst.merge_count;
		} else {
			neu->splits_base = old_splits;
			neu->merges_base = old_merges;
		}
	}
	neu->consolidations = old->consolidations;
	neu->compressions = old->compressions;
	/*
	 * WAL 序号延续（参考 export_json 携带 wal_sequence，import_json 取
	 * max 后继续追加）：新引擎在同一 WAL 文件上从旧 seq 之后写，避免
	 * 序号回绕导致 checkpoint 跳过错判。wal_ops（自上次 checkpoint 的
	 * 追加数）按参考从 0 起算。
	 */
	neu->wal_seq = old->wal_seq;
	neu->wal_checkpoint_seq = old->wal_checkpoint_seq;
	*out = neu;
	neu = NULL;
	rc = 0;
done:
	aik_engine_free(neu);
	aik_json_free(ex);
	return rc;
}

static aik_json *double_array_json(const double *v, int dim)
{
	aik_json *arr;
	int i;

	if (!v || dim <= 0)
		return NULL;
	arr = aik_json_new_arr();
	if (!arr)
		return NULL;
	for (i = 0; i < dim; i++) {
		aik_json *x = aik_json_new_num(v[i]);

		if (!x || aik_json_arr_push(arr, x) != 0) {
			aik_json_free(x);
			aik_json_free(arr);
			return NULL;
		}
	}
	return arr;
}

static aik_json *region_to_json(aik_engine *e, const aik_region *r)
{
	aik_json *obj;
	aik_json *arr = NULL;
	const char **order = NULL;
	size_t n;
	size_t i;

	obj = aik_json_new_obj();
	if (!obj)
		return NULL;
	arr = aik_json_new_arr();
	if (!arr)
		goto fail;
	n = aik_region_size(r);
	if (n > 1) {
		order = malloc(n * sizeof(*order));
		if (!order)
			goto fail;
		for (i = 0; i < n; i++)
			order[i] = aik_region_member(r, i);
		qsort(order, n, sizeof(*order), cmp_cstr);
	}
	for (i = 0; i < n; i++) {
		const char *mid = order ? order[i] : aik_region_member(r, i);
		aik_json *v = aik_json_new_str(mid ? mid : "");

		if (!v || aik_json_arr_push(arr, v) != 0) {
			aik_json_free(v);
			goto fail;
		}
	}
	free(order);
	order = NULL;
	/* 键序 = sme/models.py Region.to_dict：id, member_ids, radius, ... */
	if (put_new(obj, "id", aik_json_new_str(aik_region_id(r))) != 0 ||
	    put_slot(&arr, obj, "member_ids") != 0 ||
	    put_new(obj, "radius",
		    aik_json_new_num(aik_region_radius(r))) != 0 ||
	    put_new(obj, "density",
		    aik_json_new_num(aik_region_density(r))) != 0 ||
	    put_new(obj, "created_at",
		    aik_json_new_num(aik_region_created_at(r))) != 0 ||
	    put_new(obj, "last_updated",
		    aik_json_new_num(aik_region_last_updated(r))) != 0)
		goto fail;
	if (put_new(obj, "parent_region",
		    aik_region_parent(r)
			    ? aik_json_new_str(aik_region_parent(r))
			    : aik_json_new_null()) != 0 ||
	    put_new(obj, "generation",
		    aik_json_new_int(aik_region_generation(r))) != 0)
		goto fail;
	arr = double_array_json(aik_region_centroid(r), e->r.dim);
	if (put_slot(&arr, obj, "centroid") != 0)
		goto fail;
	arr = double_array_json(aik_region_bbox_min(r), e->r.dim);
	if (put_slot(&arr, obj, "bbox_min") != 0)
		goto fail;
	arr = double_array_json(aik_region_bbox_max(r), e->r.dim);
	if (put_slot(&arr, obj, "bbox_max") != 0)
		goto fail;
	return obj;

fail:
	free(order);
	aik_json_free(arr);
	aik_json_free(obj);
	return NULL;
}

int aik_engine_regions(aik_engine *e, aik_json **out, char *err, size_t errlen)
{
	aik_json *root = NULL;
	aik_json *regions = NULL;
	size_t n;
	size_t i;

	if (out)
		*out = NULL;
	if (!e || !out) {
		set_err(err, errlen, "engine: invalid argument to regions");
		return -1;
	}
	n = aik_space_region_count(e->space);
	regions = aik_json_new_arr();
	root = aik_json_new_obj();
	if (!regions || !root)
		goto oom;
	for (i = 0; i < n; i++) {
		aik_json *r = region_to_json(e, aik_space_region_at(e->space, i));

		if (!r || aik_json_arr_push(regions, r) != 0) {
			aik_json_free(r);
			goto oom;
		}
	}
	if (put_new(root, "count", aik_json_new_int((long long)n)) != 0 ||
	    put_slot(&regions, root, "regions") != 0)
		goto oom;
	*out = root;
	return 0;

oom:
	aik_json_free(regions);
	aik_json_free(root);
	set_err(err, errlen, "engine: out of memory (regions)");
	return -1;
}

/* ------------------------------------------------------------------ */
/* 保存（sme/storage/snapshot.py::save_snapshot + engine._save_locked）*/
/* ------------------------------------------------------------------ */
static int ci_ends_with(const char *s, const char *suffix)
{
	size_t sl = strlen(s);
	size_t fl = strlen(suffix);
	size_t i;

	if (sl < fl)
		return 0;
	for (i = 0; i < fl; i++) {
		char a = s[sl - fl + i];
		char b = suffix[i];

		if (a >= 'A' && a <= 'Z')
			a = (char)(a - 'A' + 'a');
		if (b >= 'A' && b <= 'Z')
			b = (char)(b - 'A' + 'a');
		if (a != b)
			return 0;
	}
	return 1;
}

/* Python str.strip() 的 C 版（返回 malloc 字符串） */
static char *strip_dup(const char *s)
{
	const unsigned char *p = (const unsigned char *)(s ? s : "");
	size_t off = 0;
	size_t start = 0;
	size_t end = 0;
	int seen = 0;
	char *out;

	while (p[off]) {
		unsigned int cp = 0;
		int len = utf8_next_cp(p + off, &cp);
		size_t step = len < 0 ? 1 : (size_t)len;

		if (!(len > 0 && cp_is_space(cp))) {
			if (!seen) {
				start = off;
				seen = 1;
			}
			end = off + step;
		}
		off += step;
	}
	if (!seen)
		return aik_engine__dup("");
	out = malloc(end - start + 1);
	if (!out)
		return NULL;
	memcpy(out, p + start, end - start);
	out[end - start] = '\0';
	return out;
}

/*
 * revision_stamp - Python engine.embedding_revision
 *
 * provider|model|dim[|mrlN][|seedN][|revision]，model 用配置原值，
 * revision 先 strip。
 */
static char *revision_stamp(const aik_config *cfg, char *err, size_t errlen)
{
	const char *provider = aik_config_get_str(cfg, "embedding.provider");
	const char *model = aik_config_get_str(cfg, "embedding.model");
	const char *rev = aik_config_get_str(cfg, "embedding.revision");
	long long dim = cfg_i64(cfg, "embedding.dim", 64);
	long long mrl = cfg_i64(cfg, "embedding.mrl_dim", 0);
	long long seed = cfg_i64(cfg, "embedding.hash_seed", 0);
	char *revbuf = NULL;
	char out[1024];
	size_t off = 0;
	int n;

	if (!provider || !*provider)
		provider = "hashing";
	if (!model)
		model = "";
	revbuf = strip_dup(rev ? rev : "");
	if (!revbuf) {
		set_err(err, errlen, "engine: out of memory (revision)");
		return NULL;
	}
	n = snprintf(out + off, sizeof(out) - off, "%s|%s|%lld", provider, model,
		     dim);
	if (n < 0 || (size_t)n >= sizeof(out) - off)
		goto overflow;
	off += (size_t)n;
	if (mrl > 0) {
		n = snprintf(out + off, sizeof(out) - off, "|mrl%lld", mrl);
		if (n < 0 || (size_t)n >= sizeof(out) - off)
			goto overflow;
		off += (size_t)n;
	}
	if (seed != 0) {
		n = snprintf(out + off, sizeof(out) - off, "|seed%lld", seed);
		if (n < 0 || (size_t)n >= sizeof(out) - off)
			goto overflow;
		off += (size_t)n;
	}
	if (revbuf[0]) {
		n = snprintf(out + off, sizeof(out) - off, "|%s", revbuf);
		if (n < 0 || (size_t)n >= sizeof(out) - off)
			goto overflow;
		off += (size_t)n;
	}
	free(revbuf);
	return aik_engine__dup(out);

overflow:
	free(revbuf);
	set_err(err, errlen, "engine: embedding revision stamp too long");
	return NULL;
}

/* 32 位小写十六进制代次（uuid4().hex 的 C 版；优先 /dev/urandom） */
static void make_generation(char out[33])
{
	static const char hex[] = "0123456789abcdef";
	unsigned char raw[16];
	int fd;
	int ok = 0;
	size_t i;

	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		if (read(fd, raw, sizeof(raw)) == (ssize_t)sizeof(raw))
			ok = 1;
		(void)close(fd);
	}
	if (!ok) {
		uint64_t x = (uint64_t)time(NULL) ^
			     ((uint64_t)getpid() << 32) ^ (uintptr_t)out;

		for (i = 0; i < sizeof(raw); i++) {
			x ^= x << 13;
			x ^= x >> 7;
			x ^= x << 17;
			raw[i] = (unsigned char)(x >> 24);
		}
	}
	for (i = 0; i < sizeof(raw); i++) {
		out[i * 2] = hex[raw[i] >> 4];
		out[i * 2 + 1] = hex[raw[i] & 0x0f];
	}
	out[32] = '\0';
}

static char *basename_dup(const char *path)
{
	const char *slash = strrchr(path, '/');

	return aik_engine__dup(slash ? slash + 1 : path);
}

static char *dirname_dup(const char *path)
{
	char *copy = aik_engine__dup(path);
	char *slash;

	if (!copy)
		return NULL;
	slash = strrchr(copy, '/');
	if (!slash) {
		free(copy);
		return aik_engine__dup(".");
	}
	if (slash == copy) {
		slash[1] = '\0';
		return copy;
	}
	*slash = '\0';
	return copy;
}

/* mkdir -p（path 的父目录；已存在的同名普通文件按失败处理） */
static int mkdir_one(const char *dir, char *err, size_t errlen)
{
	struct stat st;

	if (mkdir(dir, 0777) == 0)
		return 0;
	if (errno != EEXIST) {
		set_err(err, errlen, "engine: mkdir %s failed: %s", dir,
			strerror(errno));
		return -1;
	}
	if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
		set_err(err, errlen, "engine: %s is not a directory", dir);
		return -1;
	}
	return 0;
}

static int mkdir_p(const char *dir, char *err, size_t errlen)
{
	char *copy;
	size_t i;

	if (!dir || !*dir || strcmp(dir, ".") == 0)
		return 0;
	copy = aik_engine__dup(dir);
	if (!copy) {
		set_err(err, errlen, "engine: out of memory (mkdir)");
		return -1;
	}
	for (i = 1; copy[i]; i++) {
		if (copy[i] != '/')
			continue;
		copy[i] = '\0';
		if (mkdir_one(copy, err, errlen) != 0) {
			free(copy);
			return -1;
		}
		copy[i] = '/';
	}
	if (mkdir_one(copy, err, errlen) != 0) {
		free(copy);
		return -1;
	}
	free(copy);
	return 0;
}

static int ensure_parent_dir(const char *path, char *err, size_t errlen)
{
	char *dir = dirname_dup(path);
	int rc;

	if (!dir) {
		set_err(err, errlen, "engine: out of memory (dirname)");
		return -1;
	}
	rc = mkdir_p(dir, err, errlen);
	free(dir);
	return rc;
}

/* embedding_path(path)：去 .gz/.json 后加 ".embeddings.npz" */
static char *embedding_base_path(const char *path)
{
	static const char suffix[] = ".embeddings.npz";
	char *base = aik_engine__dup(path);
	size_t len;
	char *out;

	if (!base)
		return NULL;
	len = strlen(base);
	if (len >= 3 && ci_ends_with(base, ".gz")) {
		base[len - 3] = '\0';
		len -= 3;
	}
	if (len >= 5 && ci_ends_with(base, ".json")) {
		base[len - 5] = '\0';
		len -= 5;
	}
	out = malloc(len + sizeof(suffix));
	if (out) {
		memcpy(out, base, len);
		memcpy(out + len, suffix, sizeof(suffix));
	}
	free(base);
	return out;
}

/* emb_base[:-4] + "." + generation + ".npz" */
static char *generation_npz_path(const char *emb_base, const char *gen)
{
	size_t len = strlen(emb_base);
	size_t glen = strlen(gen);
	char *out;

	if (len < 4 || strcmp(emb_base + len - 4, ".npz") != 0)
		return NULL;
	out = malloc(len - 4 + 1 + glen + 4 + 1);
	if (!out)
		return NULL;
	memcpy(out, emb_base, len - 4);
	out[len - 4] = '.';
	memcpy(out + len - 3, gen, glen);
	memcpy(out + len - 3 + glen, ".npz", 5);
	return out;
}

/* <stem>.embeddings.<32 位小写 hex>.npz */
static int match_generation_name(const char *name, const char *prefix)
{
	size_t pl = strlen(prefix);
	size_t i;
	size_t len = strlen(name);

	if (len != pl + 1 + 32 + 4 || strncmp(name, prefix, pl) != 0 ||
	    name[pl] != '.')
		return 0;
	for (i = 0; i < 32; i++) {
		char c = name[pl + 1 + i];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
			return 0;
	}
	return strcmp(name + pl + 33, ".npz") == 0;
}

/*
 * cleanup_embeddings - 删除未被当前快照引用的旧代次
 *
 * 只匹配 "<stem>.embeddings.<32 hex>.npz"；引用来自保存路径的明文与
 * .gz 清单（Python _cleanup_embeddings 同口径）。失败静默（不改变已成功
 * 的保存结果）。
 */
static void cleanup_embeddings(const char *snap_path, const char *emb_base)
{
	char refs[2][256];
	size_t n_refs = 0;
	char *base = aik_engine__dup(snap_path);
	char *dir = NULL;
	char *prefix = NULL;
	DIR *d;
	struct dirent *de;
	size_t k;
	size_t plen;
	int manifests_ok = 1;

	if (!base || !emb_base)
		goto out;
	if (ci_ends_with(base, ".gz"))
		base[strlen(base) - 3] = '\0';
	for (k = 0; k < 2; k++) {
		char *manifest = NULL;
		aik_snapshot snap;
		const char *file;

		if (k == 0) {
			manifest = aik_engine__dup(base);
		} else {
			manifest = malloc(strlen(base) + 4);
			if (manifest)
				sprintf(manifest, "%s.gz", base);
		}
		if (!manifest)
			continue;
		memset(&snap, 0, sizeof(snap));
		if (file_exists(manifest)) {
			if (aik_snapshot_load(manifest, &snap, NULL, 0) != 0)
				manifests_ok = 0;
			file = aik_json_str(
				aik_json_get(snap.root, "embedding_file"));
			if (file && strlen(file) < sizeof(refs[0]) &&
			    n_refs < 2)
				snprintf(refs[n_refs++], sizeof(refs[0]), "%s",
					 file);
		}
		aik_snapshot_free(&snap);
		free(manifest);
	}
	/* 清单读失败时绝不动磁盘（Python 同样整块跳过） */
	if (!manifests_ok)
		goto out;
	dir = dirname_dup(emb_base);
	prefix = basename_dup(emb_base);
	if (!dir || !prefix)
		goto out;
	plen = strlen(prefix);
	if (plen > 4 && strcmp(prefix + plen - 4, ".npz") == 0)
		prefix[plen - 4] = '\0';
	d = opendir(dir);
	if (!d)
		goto out;
	while ((de = readdir(d)) != NULL) {
		size_t i;
		int referenced = 0;
		char *full;

		if (!match_generation_name(de->d_name, prefix))
			continue;
		for (i = 0; i < n_refs; i++) {
			if (strcmp(refs[i], de->d_name) == 0) {
				referenced = 1;
				break;
			}
		}
		if (referenced)
			continue;
		full = malloc(strlen(dir) + strlen(de->d_name) + 2);
		if (!full)
			continue;
		sprintf(full, "%s/%s", dir, de->d_name);
		(void)unlink(full);
		free(full);
	}
	(void)closedir(d);

out:
	free(base);
	free(dir);
	free(prefix);
}

/* 固定 module_state（v2 全关时的 Python _module_state 形状） */
static aik_json *module_state_json(void)
{
	aik_json *state = aik_json_new_obj();
	aik_json *qapair = aik_json_new_obj();
	aik_json *pairs = aik_json_new_arr();
	aik_json *factgraph = aik_json_new_obj();
	aik_json *entities = aik_json_new_arr();
	aik_json *relations = aik_json_new_arr();
	aik_json *profile = aik_json_new_obj();
	aik_json *facts = aik_json_new_arr();
	aik_json *snapshots = aik_json_new_obj();
	aik_json *pending = aik_json_new_arr();

	if (!state || !qapair || !pairs || !factgraph || !entities ||
	    !relations || !profile || !facts || !snapshots || !pending)
		goto oom;
	if (put_slot(&pairs, qapair, "pairs") != 0 ||
	    put_slot(&qapair, state, "qapair") != 0 ||
	    put_slot(&entities, factgraph, "entities") != 0 ||
	    put_slot(&relations, factgraph, "relations") != 0 ||
	    put_slot(&factgraph, state, "factgraph") != 0 ||
	    put_slot(&facts, profile, "profile_facts") != 0 ||
	    put_slot(&snapshots, profile, "snapshots") != 0 ||
	    put_new(profile, "write_count", aik_json_new_int(0)) != 0 ||
	    put_slot(&profile, state, "profile") != 0 ||
	    put_slot(&pending, state, "pending_questions") != 0)
		goto oom;
	return state;

oom:
	aik_json_free(pairs);
	aik_json_free(qapair);
	aik_json_free(entities);
	aik_json_free(relations);
	aik_json_free(factgraph);
	aik_json_free(facts);
	aik_json_free(snapshots);
	aik_json_free(profile);
	aik_json_free(pending);
	aik_json_free(state);
	return NULL;
}

/* region_edges：[{source,target,distance,kind:"neighbor"}]（RegionEdge.to_dict） */
static aik_json *region_edges_json(aik_engine *e)
{
	aik_json *arr = aik_json_new_arr();
	size_t n = aik_space_edge_count(e->space);
	size_t i;

	if (!arr)
		return NULL;
	for (i = 0; i < n; i++) {
		const char *a = NULL;
		const char *b = NULL;
		double dist = 0.0;
		aik_json *x;

		if (aik_space_edge_at(e->space, i, &a, &b, &dist) != 0)
			goto fail;
		x = aik_json_new_obj();
		if (!x || put_new(x, "source", aik_json_new_str(a)) != 0 ||
		    put_new(x, "target", aik_json_new_str(b)) != 0 ||
		    put_new(x, "distance", aik_json_new_num(dist)) != 0 ||
		    put_new(x, "kind", aik_json_new_str("neighbor")) != 0 ||
		    aik_json_arr_push(arr, x) != 0) {
			aik_json_free(x);
			goto fail;
		}
	}
	return arr;

fail:
	aik_json_free(arr);
	return NULL;
}

static aik_json *counters_json(aik_engine *e)
{
	aik_region_stats st;
	long long splits = e->splits_base;
	long long merges = e->merges_base;
	aik_json *obj = aik_json_new_obj();

	if (!obj)
		return NULL;
	if (aik_space_region_stats(e->space, &st) == 0) {
		splits += st.split_count;
		merges += st.merge_count;
	}
	if (put_new(obj, "splits", aik_json_new_int(splits)) != 0 ||
	    put_new(obj, "merges", aik_json_new_int(merges)) != 0 ||
	    put_new(obj, "consolidations",
		    aik_json_new_int(e->consolidations)) != 0 ||
	    put_new(obj, "compressions", aik_json_new_int(e->compressions)) !=
		    0) {
		aik_json_free(obj);
		return NULL;
	}
	return obj;
}

int aik_engine_save(aik_engine *e, const char *path, char *err, size_t errlen)
{
	const char *path_in;
	char *snap_path = NULL;
	char *emb_base = NULL;
	char *npz_path = NULL;
	char *stamp = NULL;
	char *base_name = NULL;
	char *grown;
	char gen[33];
	const aik_json *cfg_dom;
	aik_json *config = NULL;
	aik_json *emb = NULL;
	aik_json *counters = NULL;
	aik_json *memories = NULL;
	aik_json *regions = NULL;
	aik_json *region_edges = NULL;
	aik_json *memory_edges = NULL;
	aik_json *module_state = NULL;
	aik_json *root = NULL;
	aik_json *v;
	const char **ids = NULL;
	double *matrix = NULL;
	size_t n_emb = 0;
	size_t n_mem;
	size_t dim;
	size_t i;
	size_t k;
	int use_gzip = 0;
	int wrote_npz = 0;
	int rc = -1;

	if (!e) {
		set_err(err, errlen, "engine: engine is NULL");
		return -1;
	}
	if (wal_guard(e, err, errlen) != 0)
		return -1;
	path_in = (path && *path) ? path : cfg_str(e->cfg, "storage.path", NULL);
	if (!path_in || !*path_in) {
		set_err(err, errlen, "engine: save path is empty");
		return -1;
	}
	if (e->r.dim <= 0) {
		set_err(err, errlen, "engine: invalid embedding dim");
		return -1;
	}

	/* 1. 快照携带精确几何；config.embedding.revision_stamp 随快照落盘 */
	aik_space_sync_geometry(e->space);
	stamp = revision_stamp(e->cfg, err, errlen);
	if (!stamp)
		return -1;

	/* 2. 目标路径：compress 且以 .json 结尾时补 .gz（Python 同） */
	snap_path = aik_engine__dup(path_in);
	if (!snap_path) {
		set_err(err, errlen, "engine: out of memory");
		goto done;
	}
	if (ci_ends_with(snap_path, ".gz")) {
		use_gzip = 1;
	} else if (cfg_bool(e->cfg, "storage.compress", 1) &&
		   ci_ends_with(snap_path, ".json")) {
		grown = malloc(strlen(snap_path) + 4);
		if (!grown) {
			set_err(err, errlen, "engine: out of memory");
			goto done;
		}
		sprintf(grown, "%s.gz", snap_path);
		free(snap_path);
		snap_path = grown;
		use_gzip = 1;
	}

	/* 3. 快照 DOM */
	cfg_dom = aik_config_dom(e->cfg);
	if (!cfg_dom) {
		set_err(err, errlen, "engine: config DOM is NULL");
		goto done;
	}
	config = aik_json__clone(cfg_dom);
	if (!config) {
		set_err(err, errlen, "engine: out of memory (config)");
		goto done;
	}
	emb = (aik_json *)aik_json_get(config, "embedding");
	if (!emb || aik_json_typeof(emb) != AIK_JSON_OBJ) {
		set_err(err, errlen, "engine: config.embedding is not an object");
		goto done;
	}
	v = aik_json_new_str(stamp);
	if (!v || aik_json_obj_set(emb, "revision_stamp", v) != 0) {
		aik_json_free(v);
		set_err(err, errlen, "engine: out of memory (revision_stamp)");
		goto done;
	}

	n_mem = e->n_mem;
	memories = aik_json_new_arr();
	if (!memories) {
		set_err(err, errlen, "engine: out of memory (memories)");
		goto done;
	}
	for (i = 0; i < n_mem; i++) {
		aik_json *d = aik_memory_to_json(e->mem[i], 0);

		if (!d || aik_json_arr_push(memories, d) != 0) {
			aik_json_free(d);
			set_err(err, errlen, "engine: out of memory (memories)");
			goto done;
		}
		if (e->mem[i]->embedding)
			n_emb++;
	}

	regions = aik_json_new_arr();
	if (!regions) {
		set_err(err, errlen, "engine: out of memory (regions)");
		goto done;
	}
	for (i = 0; i < aik_space_region_count(e->space); i++) {
		aik_json *r = region_to_json(e, aik_space_region_at(e->space, i));

		if (!r || aik_json_arr_push(regions, r) != 0) {
			aik_json_free(r);
			set_err(err, errlen, "engine: out of memory (regions)");
			goto done;
		}
	}

	region_edges = region_edges_json(e);
	if (!region_edges) {
		set_err(err, errlen, "engine: out of memory (region_edges)");
		goto done;
	}
	memory_edges = aik_json_new_arr();
	if (!memory_edges) {
		set_err(err, errlen, "engine: out of memory (memory_edges)");
		goto done;
	}
	for (i = 0; i < e->n_edges; i++) {
		aik_json *x = edge_json(&e->edges[i]);

		if (!x || aik_json_arr_push(memory_edges, x) != 0) {
			aik_json_free(x);
			set_err(err, errlen,
				"engine: out of memory (memory_edges)");
			goto done;
		}
	}
	module_state = module_state_json();
	if (!module_state) {
		set_err(err, errlen, "engine: out of memory (module_state)");
		goto done;
	}
	counters = counters_json(e);
	if (!counters) {
		set_err(err, errlen, "engine: out of memory (counters)");
		goto done;
	}

	root = aik_json_new_obj();
	if (!root) {
		set_err(err, errlen, "engine: out of memory (snapshot)");
		goto done;
	}
	if (put_new(root, "schema_version", aik_json_new_int(2)) != 0 ||
	    put_slot(&counters, root, "counters") != 0 ||
	    put_slot(&config, root, "config") != 0 ||
	    put_slot(&memories, root, "memories") != 0 ||
	    put_slot(&regions, root, "regions") != 0 ||
	    put_slot(&region_edges, root, "region_edges") != 0 ||
	    put_slot(&memory_edges, root, "memory_edges") != 0 ||
	    put_slot(&module_state, root, "module_state") != 0 ||
	    put_new(root, "wal_sequence", aik_json_new_int(e->wal_seq)) != 0) {
		set_err(err, errlen, "engine: out of memory (snapshot)");
		goto done;
	}

	/* 4. 向量 sidecar（有向量才写；无向量时 JSON 不带 embedding_* 键） */
	if (n_emb > 0) {
		dim = (size_t)e->r.dim;
		if (n_emb > SIZE_MAX / dim ||
		    n_emb * dim > SIZE_MAX / sizeof(double)) {
			set_err(err, errlen, "engine: embedding matrix too large");
			goto done;
		}
		ids = calloc(n_emb, sizeof(*ids));
		matrix = malloc(n_emb * dim * sizeof(double));
		if (!ids || !matrix) {
			set_err(err, errlen,
				"engine: out of memory (embedding matrix)");
			goto done;
		}
		k = 0;
		for (i = 0; i < n_mem; i++) {
			aik_memory *m = e->mem[i];

			if (!m->embedding)
				continue;
			if (m->dim != e->r.dim) {
				set_err(err, errlen,
					"engine: memory '%s' dim %d != %d",
					m->id ? m->id : "?", m->dim, e->r.dim);
				goto done;
			}
			ids[k] = m->id;
			memcpy(matrix + k * dim, m->embedding,
			       dim * sizeof(double));
			k++;
		}
		make_generation(gen);
		emb_base = embedding_base_path(snap_path);
		if (emb_base)
			npz_path = generation_npz_path(emb_base, gen);
		if (!emb_base || !npz_path) {
			set_err(err, errlen, "engine: out of memory (npz path)");
			goto done;
		}
		if (ensure_parent_dir(npz_path, err, errlen) != 0)
			goto done;
		if (aik_npz_write_embeddings(npz_path, gen,
					     (const char *const *)ids, n_emb,
					     matrix, e->r.dim, err, errlen) != 0)
			goto done;
		wrote_npz = 1;
		base_name = basename_dup(npz_path);
		if (!base_name) {
			set_err(err, errlen, "engine: out of memory (basename)");
			goto done;
		}
		if (put_new(root, "embedding_file",
			    aik_json_new_str(base_name)) != 0 ||
		    put_new(root, "embedding_generation",
			    aik_json_new_str(gen)) != 0) {
			set_err(err, errlen, "engine: out of memory (snapshot)");
			goto done;
		}
	}

	/* 5. 原子写快照（compress → gzip），成功后清理旧代次 */
	if (ensure_parent_dir(snap_path, err, errlen) != 0)
		goto done;
	if (aik_snapshot_save(root, snap_path, use_gzip, err, errlen) != 0)
		goto done;
	if (wrote_npz)
		cleanup_embeddings(snap_path, emb_base);
	e->autosave_ops = 0;
	/*
	 * 参考 _save_locked：只有保存到 recovery 路径（storage.path 等价）才算
	 * checkpoint；export 到别处不截断 WAL。截断失败 → 保存失败（日志保留），
	 * 绝不报告已落盘。
	 */
	if (e->r.wal_enabled && wal_path_is_recovery(e, path_in)) {
		e->wal_checkpoint_seq = e->wal_seq;
		e->wal_checkpointed++;
		/* 参考 wal.reset：文件存在才截断（不存在时保持不存在） */
		if (file_exists(e->r.wal_path)) {
			if (wal_open(e, err, errlen) != 0)
				goto done;
			if (aik_wal_reset(e->wal, err, errlen) != 0)
				goto done;
		}
		e->wal_ops = 0;
	}
	rc = 0;

done:
	if (rc != 0 && wrote_npz && npz_path)
		(void)unlink(npz_path);
	free(snap_path);
	free(emb_base);
	free(npz_path);
	free(stamp);
	free(base_name);
	free(ids);
	free(matrix);
	aik_json_free(config);
	aik_json_free(counters);
	aik_json_free(memories);
	aik_json_free(regions);
	aik_json_free(region_edges);
	aik_json_free(memory_edges);
	aik_json_free(module_state);
	aik_json_free(root);
	return rc;
}

int aik_engine_wal_stats(const aik_engine *e, aik_json **out,
			 char *err, size_t errlen)
{
	aik_json *obj;

	if (out)
		*out = NULL;
	if (!e || !out) {
		set_err(err, errlen, "engine: invalid argument to wal_stats");
		return -1;
	}
	obj = aik_json_new_obj();
	if (!obj)
		goto oom;
	if (put_new(obj, "enabled", aik_json_new_bool(e->r.wal_enabled)) != 0 ||
	    put_new(obj, "path",
		    aik_json_new_str(e->r.wal_path ? e->r.wal_path : "")) != 0 ||
	    put_new(obj, "sync_mode", aik_json_new_str("fsync")) != 0 ||
	    put_new(obj, "sequence", aik_json_new_int(e->wal_seq)) != 0 ||
	    put_new(obj, "checkpoint_sequence",
		    aik_json_new_int(e->wal_checkpoint_seq)) != 0 ||
	    put_new(obj, "pending_ops", aik_json_new_int(e->wal_ops)) != 0 ||
	    put_new(obj, "replayed", aik_json_new_int(e->wal_replayed)) != 0 ||
	    put_new(obj, "checkpointed",
		    aik_json_new_int(e->wal_checkpointed)) != 0) {
		aik_json_free(obj);
		goto oom;
	}
	*out = obj;
	return 0;

oom:
	set_err(err, errlen, "engine: out of memory (wal stats)");
	return -1;
}

/* ================================================================== */
/* T4e-E1-B：consolidation / compression                              */
/*                                                                    */
/* 逐条对齐 REF-PY e72bc75：                                          */
/*   sme/dynamics/consolidation.py  ConsolidationEngine               */
/*                                  find_groups/_find_groups_in_members/ */
/*                                  _greedy_clusters/_region_coherent/ */
/*                                  consolidate/_template_summary/    */
/*                                  _common_tokens/_already_consolidated */
/*   sme/dynamics/compression.py    CompressionEngine                  */
/*                                  find_compressible/compress/       */
/*                                  _summarize/_region_compressed     */
/*   sme/memory_manager.py          summary_memory / set_parent       */
/*   sme/engine.py                  consolidate()/compress()（单次    */
/*                                  _autosave + 计数器自增）           */
/*                                                                    */
/* LLM 摘要：本阶段 C 无 LLM（aik_engine_new 只接受 hashing），       */
/* summary_source=="llm" 时仍走 template（与参考在 llm 不可用时的    */
/* 行为一致：Python 里 self.llm is None 也走 template）。             */
/* ================================================================== */
#define DYN_MIN_GROUP_SIZE 3	/* ConsolidationConfig.min_group_size */
#define DYN_MAX_GROUPS 20	/* find_groups(max_groups=20) */
#define DYN_MAX_REGIONS 10	/* find_compressible(max_regions=10) */

struct dyn_group {
	aik_memory **items;
	size_t n;
};

struct dyn_groups {
	struct dyn_group *v;
	size_t n;
	size_t cap;
};

struct dyn_bucket {
	char *key;
	aik_memory **items;
	size_t n;
	size_t cap;
};

struct dyn_buf {
	char *s;
	size_t n;
	size_t cap;
};

struct dyn_cand {
	const char *tok;
	long long score;
};

struct dyn_tokcnt {
	char *tok;
	size_t cnt;
};

static void dyn_groups_reset(struct dyn_groups *gs)
{
	size_t i;

	for (i = 0; i < gs->n; i++)
		free(gs->v[i].items);
	free(gs->v);
	gs->v = NULL;
	gs->n = 0;
	gs->cap = 0;
}

static int dyn_groups_push(struct dyn_groups *gs, aik_memory *const *items,
			   size_t n)
{
	struct dyn_group *g;

	if (gs->n == gs->cap) {
		size_t next = gs->cap ? gs->cap * 2 : 8;
		struct dyn_group *grown = realloc(gs->v, next * sizeof(*grown));

		if (!grown)
			return -1;
		gs->v = grown;
		gs->cap = next;
	}
	g = &gs->v[gs->n];
	g->items = NULL;
	g->n = 0;
	if (n > 0) {
		g->items = malloc(n * sizeof(*g->items));
		if (!g->items)
			return -1;
		memcpy(g->items, items, n * sizeof(*g->items));
	}
	g->n = n;
	gs->n++;
	return 0;
}

/* ---------------- 字符串缓冲 ---------------- */
static int dyn_buf_addn(struct dyn_buf *b, const char *s, size_t n)
{
	size_t cap;
	char *p;

	if (b->n + n + 1 > b->cap) {
		cap = b->cap ? b->cap : 64;
		while (cap < b->n + n + 1)
			cap *= 2;
		p = realloc(b->s, cap);
		if (!p)
			return -1;
		b->s = p;
		b->cap = cap;
	}
	if (n > 0 && s)
		memcpy(b->s + b->n, s, n);
	b->n += n;
	b->s[b->n] = '\0';
	return 0;
}

static int dyn_buf_add(struct dyn_buf *b, const char *s)
{
	return dyn_buf_addn(b, s ? s : "", s ? strlen(s) : 0);
}

static char *dyn_buf_take(struct dyn_buf *b)
{
	char *s = b->s;

	if (!s)
		s = aik_engine__dup("");
	b->s = NULL;
	b->n = 0;
	b->cap = 0;
	return s;
}

/* UTF-8 码点个数（Python len(str)） */
static size_t dyn_utf8_len(const char *s)
{
	const unsigned char *p = (const unsigned char *)(s ? s : "");
	size_t n = 0;

	while (*p) {
		if ((*p & 0xc0) != 0x80)
			n++;
		p++;
	}
	return n;
}

/* ---------------- Python 真值与 str(metadata.get("ns", "")) --------- */
static int dyn_json_truthy(const aik_json *v)
{
	switch (aik_json_typeof(v)) {
	case AIK_JSON_BOOL:
		return aik_json_bool(v) ? 1 : 0;
	case AIK_JSON_INT:
		return aik_json_int(v) != 0;
	case AIK_JSON_NUM:
		return aik_json_num(v) != 0.0;
	case AIK_JSON_STR:
		return aik_json_str(v) && aik_json_str(v)[0] != '\0';
	case AIK_JSON_ARR:
	case AIK_JSON_OBJ:
		return aik_json_count(v) > 0;
	case AIK_JSON_NULL:
	default:
		return 0;
	}
}

/*
 * ns 分桶键：str(m.metadata.get(NS_KEY, ""))
 *
 * 缺键 → ""；None → "None"；bool → "True"/"False"；数字走 CPython repr。
 * 数组/对象分支参考实现不存在（str(list/dict)），这里退化为 "" 并在
 * T4E-E1-B.md 记为已知差异。
 */
static char *dyn_ns_key(const aik_json *metadata)
{
	const aik_json *v = aik_json_get(metadata, "ns");
	char buf[64];

	if (!v)
		return aik_engine__dup("");
	switch (aik_json_typeof(v)) {
	case AIK_JSON_STR:
		return aik_engine__dup(aik_json_str(v));
	case AIK_JSON_NULL:
		return aik_engine__dup("None");
	case AIK_JSON_BOOL:
		return aik_engine__dup(aik_json_bool(v) ? "True" : "False");
	case AIK_JSON_INT:
		snprintf(buf, sizeof(buf), "%lld", aik_json_int(v));
		return aik_engine__dup(buf);
	case AIK_JSON_NUM:
		if (aik_json_dtoa(aik_json_num(v), buf, sizeof(buf)) < 0)
			return NULL;
		return aik_engine__dup(buf);
	default:
		return aik_engine__dup("");
	}
}

/* ---------------- 成员枚举 / 排序 / 分桶 ---------------- */

/*
 * Region 成员（member_ids 顺序）∩ memories，过滤 archived 与
 * source=="summary"（consolidation.py::find_groups 的 members_all）。
 */
/* sorted(member_ids)：Region.member_ids 在参考里是 set，迭代序随机；
 * C 侧统一按 id 升序（= 快照数组序 = 设计稿 §2.3/§2.4 的确定性口径）。 */
static int dyn_cmp_mem_id(const void *pa, const void *pb)
{
	aik_memory *const *a = pa;
	aik_memory *const *b = pb;

	if (!*a || !*b)
		return 0;
	return strcmp((*a)->id, (*b)->id);
}

static int dyn_region_members(aik_engine *e, const aik_region *r,
			      aik_memory ***out, size_t *out_n)
{
	size_t cnt = aik_region_size(r);
	aik_memory **arr;
	size_t n = 0;
	size_t i;

	*out = NULL;
	*out_n = 0;
	arr = malloc((cnt ? cnt : 1) * sizeof(*arr));
	if (!arr)
		return -1;
	for (i = 0; i < cnt; i++) {
		const char *mid = aik_region_member(r, i);
		aik_memory *m;

		if (!mid)
			continue;
		m = find_mem(e, mid);
		if (!m || m->archived)
			continue;
		if (m->source && strcmp(m->source, "summary") == 0)
			continue;
		arr[n++] = m;
	}
	qsort(arr, n, sizeof(*arr), dyn_cmp_mem_id);
	*out = arr;
	*out_n = n;
	return 0;
}

/* Python list.sort(key=importance, reverse=True)：稳定（等值保持原序） */
static void dyn_sort_by_importance(aik_memory **m, size_t n)
{
	size_t i;
	size_t j;

	for (i = 1; i < n; i++) {
		aik_memory *cur = m[i];

		j = i;
		while (j > 0 && m[j - 1]->importance < cur->importance) {
			m[j] = m[j - 1];
			j--;
		}
		m[j] = cur;
	}
}

static void dyn_buckets_free(struct dyn_bucket *bs, size_t nb)
{
	size_t i;

	for (i = 0; i < nb; i++) {
		free(bs[i].key);
		free(bs[i].items);
	}
	free(bs);
}

static int dyn_bucket_append(struct dyn_bucket *b, aik_memory *m)
{
	if (b->n == b->cap) {
		size_t next = b->cap ? b->cap * 2 : 8;
		aik_memory **grown = realloc(b->items, next * sizeof(*grown));

		if (!grown)
			return -1;
		b->items = grown;
		b->cap = next;
	}
	b->items[b->n++] = m;
	return 0;
}

/* 按 ns 分桶；桶顺序 = 成员首次出现序（Python dict 语义） */
static int dyn_build_buckets(aik_memory *const *members, size_t n,
			     struct dyn_bucket **out, size_t *out_nb)
{
	struct dyn_bucket *bs = NULL;
	size_t nb = 0;
	size_t cap = 0;
	size_t i;
	size_t j;

	*out = NULL;
	*out_nb = 0;
	for (i = 0; i < n; i++) {
		char *key = dyn_ns_key(members[i]->metadata);

		if (!key)
			goto fail;
		for (j = 0; j < nb; j++) {
			if (strcmp(bs[j].key, key) == 0)
				break;
		}
		if (j == nb) {
			if (nb == cap) {
				size_t next = cap ? cap * 2 : 4;
				struct dyn_bucket *grown =
					realloc(bs, next * sizeof(*grown));

				if (!grown) {
					free(key);
					goto fail;
				}
				bs = grown;
				cap = next;
			}
			memset(&bs[nb], 0, sizeof(bs[nb]));
			bs[nb].key = key;
			nb++;
		} else {
			free(key);
		}
		if (dyn_bucket_append(&bs[j], members[i]) != 0)
			goto fail;
	}
	*out = bs;
	*out_nb = nb;
	return 0;
fail:
	dyn_buckets_free(bs, nb);
	return -1;
}

/* ---------------- 聚类 ---------------- */

/* 贪心簇：anchor 未用时对每个未用 other 算余弦，>= threshold 入簇 */
static int dyn_greedy_clusters(aik_memory **members, size_t n,
			       double threshold, struct dyn_groups *out)
{
	char *used;
	size_t *cluster;
	size_t ai;
	size_t oi;
	int rc = -1;

	used = calloc(n ? n : 1, 1);
	cluster = malloc((n ? n : 1) * sizeof(*cluster));
	if (!used || !cluster)
		goto done;
	for (ai = 0; ai < n; ai++) {
		size_t cn = 0;

		if (used[ai])
			continue;
		cluster[cn++] = ai;
		for (oi = 0; oi < n; oi++) {
			aik_memory *a = members[ai];
			aik_memory *b = members[oi];

			if (used[oi] || oi == ai)
				continue;
			if (!a->embedding || !b->embedding)
				continue;
			if (a->dim != b->dim)
				continue;
			if (cos_sim(a->embedding, b->embedding, a->dim) >=
			    threshold)
				cluster[cn++] = oi;
		}
		if (cn >= 2) {
			aik_memory **items = malloc(cn * sizeof(*items));
			size_t k;

			if (!items)
				goto done;
			for (k = 0; k < cn; k++) {
				items[k] = members[cluster[k]];
				used[cluster[k]] = 1;
			}
			if (dyn_groups_push(out, items, cn) != 0) {
				free(items);
				goto done;
			}
			free(items);
		}
	}
	rc = 0;
done:
	free(used);
	free(cluster);
	return rc;
}

/* 前 30 个成员的两两余弦均值（最多 200 对，break 只退内层，同参考） */
static int dyn_region_coherent(aik_memory **members, size_t n,
			       double threshold)
{
	size_t sample = n < 30 ? n : 30;
	double total = 0.0;
	int pairs = 0;
	size_t i;
	size_t j;

	if (sample < 2)
		return 0;
	for (i = 0; i < sample; i++) {
		for (j = i + 1; j < sample; j++) {
			aik_memory *a = members[i];
			aik_memory *b = members[j];

			if (!a->embedding || !b->embedding)
				continue;
			if (a->dim != b->dim)
				continue;
			total += cos_sim(a->embedding, b->embedding, a->dim);
			pairs++;
			if (pairs >= 200)
				break;
		}
	}
	if (pairs == 0)
		return 0;
	return (total / (double)pairs) >= threshold * 0.6;
}

/*
 * _find_groups_in_members：桶内贪心簇 + 整区连贯回退
 *
 * 返回 1 表示 groups 已达到 max_groups（调用方应立即收尾）。
 */
static int dyn_groups_in_members(aik_memory **members, size_t n,
				 double threshold, int max_group,
				 struct dyn_groups *groups)
{
	struct dyn_groups clusters;
	const char **covered = NULL;
	size_t n_covered = 0;
	size_t cap_covered = 0;
	size_t ci;
	size_t i;
	int rc = -1;

	memset(&clusters, 0, sizeof(clusters));
	dyn_sort_by_importance(members, n);
	if (dyn_greedy_clusters(members, n, threshold, &clusters) != 0)
		goto done;
	for (ci = 0; ci < clusters.n; ci++) {
		struct dyn_group *cl = &clusters.v[ci];
		size_t take;

		if (cl->n < DYN_MIN_GROUP_SIZE)
			continue;
		take = cl->n > (size_t)max_group ? (size_t)max_group : cl->n;
		if (dyn_groups_push(groups, cl->items, take) != 0)
			goto done;
		for (i = 0; i < take; i++) {
			const char *id = cl->items[i]->id;
			size_t k;
			int seen = 0;

			for (k = 0; k < n_covered; k++) {
				if (strcmp(covered[k], id) == 0) {
					seen = 1;
					break;
				}
			}
			if (seen)
				continue;
			if (n_covered == cap_covered) {
				size_t next = cap_covered ? cap_covered * 2 : 16;
				const char **grown =
					realloc(covered, next * sizeof(*grown));

				if (!grown)
					goto done;
				covered = grown;
				cap_covered = next;
			}
			covered[n_covered++] = id;
		}
		if (groups->n >= DYN_MAX_GROUPS) {
			rc = 1;
			goto done;
		}
	}
	if (n <= (size_t)max_group && n > 0) {
		double coverage = (double)n_covered / (double)n;

		if (coverage >= 0.6) {
			rc = 0;
			goto done;
		}
		if (dyn_region_coherent(members, n, threshold)) {
			if (dyn_groups_push(groups, members, n) != 0)
				goto done;
		}
	}
	rc = 0;
done:
	dyn_groups_reset(&clusters);
	free(covered);
	return rc;
}

/* find_groups(max_groups=20)：Region 插入序 → ns 桶 → 桶内聚合 */
static int dyn_find_groups(aik_engine *e, struct dyn_groups *groups,
			   char *err, size_t errlen)
{
	double threshold =
		cfg_num(e->cfg, "consolidation.similarity_threshold", 0.5);
	long long max_group =
		cfg_i64(e->cfg, "consolidation.max_group_size", 12);
	size_t nreg = aik_space_region_count(e->space);
	size_t ri;
	size_t bi;

	if (max_group < 1)
		max_group = 1;
	for (ri = 0; ri < nreg; ri++) {
		const aik_region *r = aik_space_region_at(e->space, ri);
		aik_memory **members = NULL;
		size_t nm = 0;
		struct dyn_bucket *bs = NULL;
		size_t nb = 0;
		int hit;

		if (!r)
			continue;
		if (dyn_region_members(e, r, &members, &nm) != 0)
			goto oom;
		if (nm < DYN_MIN_GROUP_SIZE) {
			free(members);
			continue;
		}
		if (dyn_build_buckets(members, nm, &bs, &nb) != 0) {
			free(members);
			goto oom;
		}
		hit = 0;
		for (bi = 0; bi < nb; bi++) {
			int rc;

			if (bs[bi].n < DYN_MIN_GROUP_SIZE)
				continue;
			rc = dyn_groups_in_members(bs[bi].items, bs[bi].n,
						   threshold, (int)max_group,
						   groups);
			if (rc < 0) {
				dyn_buckets_free(bs, nb);
				free(members);
				goto oom;
			}
			if (rc == 1 || groups->n >= DYN_MAX_GROUPS) {
				hit = 1;
				break;
			}
		}
		dyn_buckets_free(bs, nb);
		free(members);
		if (hit)
			return 0;
	}
	return 0;
oom:
	set_err(err, errlen, "engine: out of memory (consolidation groups)");
	return -1;
}

/* ---------------- summary_memory / set_parent ---------------- */
static int dyn_set_parent(aik_engine *e, const char *child_id,
			  const char *parent_id)
{
	aik_memory *child = find_mem(e, child_id);
	aik_memory *parent = find_mem(e, parent_id);
	size_t i;

	if (!child || !parent)
		return 1;
	free(child->parent_id);
	child->parent_id = aik_engine__dup(parent_id);
	if (!child->parent_id)
		return -1;
	for (i = 0; i < parent->n_children; i++) {
		if (parent->children[i] &&
		    strcmp(parent->children[i], child_id) == 0)
			break;
	}
	if (i == parent->n_children) {
		char **grown = realloc(parent->children,
				       (parent->n_children + 1) * sizeof(*grown));

		if (!grown)
			return -1;
		parent->children = grown;
		parent->children[parent->n_children] =
			aik_engine__dup(child_id);
		if (!parent->children[parent->n_children])
			return -1;
		parent->n_children++;
	}
	if (engine_add_edge(e, child_id, parent_id, "parent", 1.0, "child") != 0)
		return -1;
	/* 参考 set_parent 的 on_upsert(child)/on_upsert(parent) */
	if (wal_dirty_add(e, child_id) != 0 || wal_dirty_add(e, parent_id) != 0)
		return -1;
	return 0;
}

/*
 * summary_memory(text, member_ids, importance)
 *
 * 正常 add 管线（嵌入、space、id/时钟），然后 summary=text，再对每个成员
 * set_parent(mid, summary.id) 并追加 summary→mid / kind=summary /
 * weight=1 / note="covers" 边。**不** autosave（由调用方统一调用一次）。
 */
static aik_memory *dyn_summary_memory(aik_engine *e, const char *text,
				      char *const *ids, size_t n_ids,
				      double importance, char *err,
				      size_t errlen)
{
	static const char *tags[] = { "summary" };
	aik_memory *s;
	size_t i;

	s = engine_add_core(e, text, NULL, tags, 1, importance, "summary",
			    NULL, NULL, NULL, err, errlen);
	if (!s)
		return NULL;
	free(s->summary);
	s->summary = aik_engine__dup(text);
	if (!s->summary) {
		set_err(err, errlen, "engine: out of memory (summary text)");
		return NULL;
	}
	for (i = 0; i < n_ids; i++) {
		int rc = dyn_set_parent(e, ids[i], s->id);

		if (rc < 0) {
			set_err(err, errlen,
				"engine: out of memory (parent link)");
			return NULL;
		}
		if (engine_add_edge(e, s->id, ids[i], "summary", 1.0,
				    "covers") != 0) {
			set_err(err, errlen,
				"engine: out of memory (summary edge)");
			return NULL;
		}
	}
	return s;
}

/* ---------------- 摘要文本 ---------------- */

static int dyn_cmp_cand(const void *pa, const void *pb)
{
	const struct dyn_cand *a = pa;
	const struct dyn_cand *b = pb;

	if (a->score != b->score)
		return a->score > b->score ? -1 : 1;
	return strcmp(a->tok, b->tok);
}

/*
 * _common_tokens：每条记忆 tokenize(set) 计数；候选 cnt>=2 且码点长度>=4；
 * 排序 (-cnt*len^2, tok)，取前 4，用 "、" 连接。
 */
static int dyn_common_tokens(aik_memory *const *group, size_t n, char **out,
			     char *err, size_t errlen)
{
	struct dyn_tokcnt *arr = NULL;
	size_t na = 0;
	size_t cap = 0;
	struct dyn_cand *cands = NULL;
	size_t nc = 0;
	struct dyn_buf b;
	size_t gi;
	size_t i;
	size_t j;
	int rc = -1;

	*out = NULL;
	memset(&b, 0, sizeof(b));
	for (gi = 0; gi < n; gi++) {
		aik_token_list tl;

		if (aik_tokenize(group[gi]->text, 0, &tl, err, errlen) != 0)
			goto done;
		for (i = 0; i < tl.count; i++) {
			const char *tok = tl.items[i];
			int dup_seen = 0;

			if (!tok)
				continue;
			for (j = 0; j < i; j++) {
				if (tl.items[j] && strcmp(tl.items[j], tok) == 0) {
					dup_seen = 1;
					break;
				}
			}
			if (dup_seen)
				continue;
			for (j = 0; j < na; j++) {
				if (strcmp(arr[j].tok, tok) == 0) {
					arr[j].cnt++;
					break;
				}
			}
			if (j < na)
				continue;
			if (na == cap) {
				size_t next = cap ? cap * 2 : 16;
				struct dyn_tokcnt *grown =
					realloc(arr, next * sizeof(*grown));

				if (!grown) {
					aik_token_list_free(&tl);
					goto done;
				}
				arr = grown;
				cap = next;
			}
			arr[na].tok = aik_engine__dup(tok);
			if (!arr[na].tok) {
				aik_token_list_free(&tl);
				goto done;
			}
			arr[na].cnt = 1;
			na++;
		}
		aik_token_list_free(&tl);
	}
	cands = malloc((na ? na : 1) * sizeof(*cands));
	if (!cands)
		goto done;
	for (i = 0; i < na; i++) {
		size_t chars = dyn_utf8_len(arr[i].tok);

		if (arr[i].cnt >= 2 && chars >= 4) {
			cands[nc].tok = arr[i].tok;
			cands[nc].score = (long long)arr[i].cnt *
					  (long long)chars * (long long)chars;
			nc++;
		}
	}
	qsort(cands, nc, sizeof(*cands), dyn_cmp_cand);
	for (i = 0; i < nc && i < 4; i++) {
		if (i > 0 && dyn_buf_add(&b, "、") != 0)
			goto done;
		if (dyn_buf_add(&b, cands[i].tok) != 0)
			goto done;
	}
	*out = dyn_buf_take(&b);
	if (!*out)
		goto done;
	rc = 0;
done:
	free(b.s);
	free(cands);
	for (j = 0; j < na; j++)
		free(arr[j].tok);
	free(arr);
	if (rc != 0)
		set_err(err, errlen, "engine: out of memory (common tokens)");
	return rc;
}

/* _template_summary */
static int dyn_template_summary(aik_memory *const *group, size_t n, char **out,
				char *err, size_t errlen)
{
	struct dyn_buf b;
	char *topics = NULL;
	char num[32];
	size_t i;
	size_t preview_n;
	int rc = -1;

	*out = NULL;
	memset(&b, 0, sizeof(b));
	if (dyn_common_tokens(group, n, &topics, err, errlen) != 0)
		goto done;
	snprintf(num, sizeof(num), "%zu", n);
	if (topics && topics[0]) {
		if (dyn_buf_add(&b, "关于「") != 0 ||
		    dyn_buf_add(&b, topics) != 0 ||
		    dyn_buf_add(&b, "」的 ") != 0 ||
		    dyn_buf_add(&b, num) != 0 ||
		    dyn_buf_add(&b, " 条相关记忆") != 0)
			goto done;
	} else {
		if (dyn_buf_add(&b, num) != 0 ||
		    dyn_buf_add(&b, " 条相关记忆") != 0)
			goto done;
	}
	if (n > 3) {
		char more[48];

		snprintf(more, sizeof(more), "，共%zu条", n);
		if (dyn_buf_add(&b, more) != 0)
			goto done;
	}
	if (dyn_buf_add(&b, "：") != 0)
		goto done;
	preview_n = n < 3 ? n : 3;
	for (i = 0; i < preview_n; i++) {
		if (i > 0 && dyn_buf_add(&b, "；") != 0)
			goto done;
		if (dyn_buf_add(&b, group[i]->text) != 0)
			goto done;
	}
	*out = dyn_buf_take(&b);
	if (!*out)
		goto done;
	rc = 0;
done:
	free(b.s);
	free(topics);
	if (rc != 0)
		set_err(err, errlen, "engine: out of memory (template summary)");
	return rc;
}

/* compression.py::_summarize（template 分支） */
static int dyn_compression_text(aik_memory *const *cands, size_t n, char **out,
				char *err, size_t errlen)
{
	struct dyn_buf b;
	char num[32];
	size_t i;
	size_t preview_n;
	int rc = -1;

	*out = NULL;
	memset(&b, 0, sizeof(b));
	snprintf(num, sizeof(num), "%zu", n);
	if (dyn_buf_add(&b, "长期记忆摘要（") != 0 || dyn_buf_add(&b, num) != 0 ||
	    dyn_buf_add(&b, "条）") != 0)
		goto done;
	if (n > 5) {
		char more[48];

		snprintf(more, sizeof(more), " 等%zu条", n);
		if (dyn_buf_add(&b, more) != 0)
			goto done;
	}
	if (dyn_buf_add(&b, "：") != 0)
		goto done;
	preview_n = n < 5 ? n : 5;
	for (i = 0; i < preview_n; i++) {
		if (i > 0 && dyn_buf_add(&b, "；") != 0)
			goto done;
		if (dyn_buf_add(&b, cands[i]->text) != 0)
			goto done;
	}
	*out = dyn_buf_take(&b);
	if (!*out)
		goto done;
	rc = 0;
done:
	free(b.s);
	if (rc != 0)
		set_err(err, errlen, "engine: out of memory (compression summary)");
	return rc;
}

/* ---------------- 幂等判定 / metadata ---------------- */

static size_t dyn_unique_count(char *const *ids, size_t n)
{
	size_t i;
	size_t j;
	size_t uniq = 0;

	for (i = 0; i < n; i++) {
		for (j = 0; j < i; j++) {
			if (strcmp(ids[j], ids[i]) == 0)
				break;
		}
		if (j == i)
			uniq++;
	}
	return uniq;
}

static int dyn_has_id(char *const *ids, size_t n, const char *id)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (strcmp(ids[i], id) == 0)
			return 1;
	}
	return 0;
}

/* set(metadata["covers"]) == set(ids)（元素必须是 id 字符串） */
static int dyn_covers_matches(const aik_json *covers, char *const *ids,
			      size_t n)
{
	size_t nc;
	size_t i;
	size_t j;
	size_t uniq_c = 0;

	if (aik_json_typeof(covers) != AIK_JSON_ARR)
		return 0;
	nc = aik_json_count(covers);
	for (i = 0; i < nc; i++) {
		if (!aik_json_str(aik_json_at(covers, i)))
			return 0;
	}
	for (i = 0; i < nc; i++) {
		const char *a = aik_json_str(aik_json_at(covers, i));

		for (j = 0; j < i; j++) {
			if (strcmp(aik_json_str(aik_json_at(covers, j)), a) == 0)
				break;
		}
		if (j == i)
			uniq_c++;
	}
	if (uniq_c != dyn_unique_count(ids, n))
		return 0;
	for (i = 0; i < nc; i++) {
		const char *a = aik_json_str(aik_json_at(covers, i));

		for (j = 0; j < i; j++) {
			if (strcmp(aik_json_str(aik_json_at(covers, j)), a) == 0)
				break;
		}
		if (j != i)
			continue;
		if (!dyn_has_id(ids, n, a))
			return 0;
	}
	return 1;
}

/* _already_consolidated：已有 summary 且 covers 集合 == ids 集合 */
static int dyn_already_consolidated(aik_engine *e, char *const *ids, size_t n)
{
	size_t i;

	for (i = 0; i < e->n_mem; i++) {
		const aik_memory *m = e->mem[i];
		const aik_json *covers;

		if (!m->source || strcmp(m->source, "summary") != 0)
			continue;
		covers = aik_json_get(m->metadata, "covers");
		if (!dyn_json_truthy(covers))
			continue;
		if (dyn_covers_matches(covers, ids, n))
			return 1;
	}
	return 0;
}

/* _region_compressed：source=="summary" 且 compresses_region == region.id */
static int dyn_region_compressed(aik_engine *e, const char *region_id)
{
	size_t i;

	if (!region_id)
		return 0;
	for (i = 0; i < e->n_mem; i++) {
		const aik_memory *m = e->mem[i];
		const aik_json *v;

		if (!m->source || strcmp(m->source, "summary") != 0)
			continue;
		v = aik_json_get(m->metadata, "compresses_region");
		if (aik_json_typeof(v) == AIK_JSON_STR &&
		    strcmp(aik_json_str(v), region_id) == 0)
			return 1;
	}
	return 0;
}

/* sorted(ids) 的 JSON 数组（strcmp 序 = Python 码点序，UTF-8） */
static aik_json *dyn_sorted_ids_json(char *const *ids, size_t n)
{
	aik_json *arr = aik_json_new_arr();
	char **copy = NULL;
	size_t i;

	if (!arr)
		return NULL;
	if (n > 0) {
		copy = malloc(n * sizeof(*copy));
		if (!copy)
			goto fail;
		memcpy(copy, ids, n * sizeof(*copy));
		qsort(copy, n, sizeof(*copy), cmp_cstr);
	}
	for (i = 0; i < n; i++) {
		aik_json *v = aik_json_new_str(copy[i]);

		if (!v || aik_json_arr_push(arr, v) != 0) {
			aik_json_free(v);
			goto fail;
		}
	}
	free(copy);
	return arr;
fail:
	free(copy);
	aik_json_free(arr);
	return NULL;
}

/*
 * Python: ns_values = {m.metadata.get("ns") for m in group
 *                      if m.metadata.get("ns")}；len==1 时写入摘要。
 * 返回唯一值指针（借用）；多个不同值或没有 → *out_found=0。
 */
static const aik_json *dyn_group_ns(aik_memory *const *group, size_t n,
				    int *out_found)
{
	const aik_json *ns = NULL;
	int found = 0;
	size_t i;

	for (i = 0; i < n; i++) {
		const aik_json *v = aik_json_get(group[i]->metadata, "ns");

		if (!dyn_json_truthy(v))
			continue;
		if (!found) {
			ns = v;
			found = 1;
		} else if (!json_equal(ns, v)) {
			*out_found = 0;
			return NULL;
		}
	}
	*out_found = found;
	return ns;
}

static int dyn_created_push(aik_memory ***arr, size_t *n, size_t *cap,
			    aik_memory *m)
{
	if (*n == *cap) {
		size_t next = *cap ? *cap * 2 : 16;
		aik_memory **grown = realloc(*arr, next * sizeof(*grown));

		if (!grown)
			return -1;
		*arr = grown;
		*cap = next;
	}
	(*arr)[(*n)++] = m;
	return 0;
}

static aik_json *dyn_created_json(aik_memory *const *created, size_t n)
{
	aik_json *arr = aik_json_new_arr();
	size_t i;

	if (!arr)
		return NULL;
	for (i = 0; i < n; i++) {
		aik_json *row = aik_memory_to_json(created[i], 1);

		if (!row || aik_json_arr_push(arr, row) != 0) {
			aik_json_free(row);
			aik_json_free(arr);
			return NULL;
		}
	}
	return arr;
}

/* ---------------- 公开接口 ---------------- */

int aik_engine_consolidate(aik_engine *e, aik_json **out_created, char *err,
			   size_t errlen)
{
	struct dyn_groups groups;
	aik_memory **created = NULL;
	size_t n_created = 0;
	size_t cap_created = 0;
	aik_json *arr = NULL;
	double now;
	size_t gi;
	int committed = 0;
	int rc = -1;

	memset(&groups, 0, sizeof(groups));
	if (out_created)
		*out_created = NULL;
	if (!e || !out_created) {
		set_err(err, errlen, "engine: invalid argument to consolidate");
		return -1;
	}
	if (wal_guard(e, err, errlen) != 0)
		return -1;
	wal_begin(e);
	if (dyn_find_groups(e, &groups, err, errlen) != 0)
		goto done;
	now = e->now(e->now_ud);
	for (gi = 0; gi < groups.n; gi++) {
		struct dyn_group *g = &groups.v[gi];
		char **ids;
		char *text = NULL;
		aik_memory *s;
		const aik_json *ns;
		aik_json *v;
		int ns_found = 0;
		size_t i;

		ids = malloc(g->n * sizeof(*ids));
		if (!ids) {
			set_err(err, errlen, "engine: out of memory (covers)");
			goto done;
		}
		for (i = 0; i < g->n; i++)
			ids[i] = g->items[i]->id;
		if (dyn_already_consolidated(e, ids, g->n)) {
			free(ids);
			continue;
		}
		if (dyn_template_summary(g->items, g->n, &text, err, errlen) !=
		    0) {
			free(ids);
			goto done;
		}
		s = dyn_summary_memory(e, text, ids, g->n, 0.75, err, errlen);
		free(text);
		if (!s) {
			free(ids);
			goto done;
		}
		v = dyn_sorted_ids_json(ids, g->n);
		if (!v || aik_json_obj_set(s->metadata, "covers", v) != 0) {
			aik_json_free(v);
			free(ids);
			set_err(err, errlen, "engine: out of memory (covers)");
			goto done;
		}
		v = aik_json_new_num(now);
		if (!v || aik_json_obj_set(s->metadata, "consolidated_at", v) !=
				  0) {
			aik_json_free(v);
			free(ids);
			set_err(err, errlen,
				"engine: out of memory (consolidated_at)");
			goto done;
		}
		ns = dyn_group_ns(g->items, g->n, &ns_found);
		if (ns_found && ns) {
			v = aik_json__clone(ns);
			if (!v ||
			    aik_json_obj_set(s->metadata, "ns", v) != 0) {
				aik_json_free(v);
				free(ids);
				set_err(err, errlen,
					"engine: out of memory (ns)");
				goto done;
			}
		}
		if (dyn_created_push(&created, &n_created, &cap_created, s) != 0) {
			free(ids);
			set_err(err, errlen,
				"engine: out of memory (created list)");
			goto done;
		}
		e->consolidations++;
		free(ids);
	}
	/* consolidation.last_run_at = now()（仅引擎内部状态，无外部字段） */
	if (wal_commit(e, 1, err, errlen) != 0)
		goto done;
	committed = 1;
	if (engine_autosave(e, err, errlen) != 0)
		goto done;
	arr = dyn_created_json(created, n_created);
	if (!arr) {
		set_err(err, errlen, "engine: out of memory (created JSON)");
		goto done;
	}
	*out_created = arr;
	arr = NULL;
	rc = 0;
done:
	if (!committed)
		wal_abort(e);
	aik_json_free(arr);
	free(created);
	dyn_groups_reset(&groups);
	return rc;
}

/* find_compressible(max_regions=10) */
static int dyn_find_compressible(aik_engine *e, struct dyn_groups *out,
				 double now, char *err, size_t errlen)
{
	double age_threshold =
		cfg_num(e->cfg, "compression.age_days_threshold", 3.0);
	long long min_compact =
		cfg_i64(e->cfg, "compression.min_region_compact", 8);
	size_t nreg = aik_space_region_count(e->space);
	size_t ri;

	if (min_compact < 1)
		min_compact = 1;
	for (ri = 0; ri < nreg; ri++) {
		const aik_region *r = aik_space_region_at(e->space, ri);
		size_t cnt;
		aik_memory **cands = NULL;
		size_t nc = 0;
		struct dyn_bucket *bs = NULL;
		size_t nb = 0;
		size_t i;
		size_t bi;
		int stop = 0;

		if (!r)
			continue;
		cnt = aik_region_size(r);
		if (cnt < (size_t)min_compact)
			continue;
		if (dyn_region_compressed(e, aik_region_id(r)))
			continue;
		cands = malloc((cnt ? cnt : 1) * sizeof(*cands));
		if (!cands)
			goto oom;
		for (i = 0; i < cnt; i++) {
			const char *mid = aik_region_member(r, i);
			aik_memory *m;
			double age;

			if (!mid)
				continue;
			m = find_mem(e, mid);
			if (!m || m->archived)
				continue;
			if (m->source && strcmp(m->source, "summary") == 0)
				continue;
			age = (now - m->last_hit) / 86400.0;
			if (age < 0.0)
				age = 0.0;	/* age_days: max(0, ...) */
			if (age < age_threshold)
				continue;
			cands[nc++] = m;
		}
		qsort(cands, nc, sizeof(*cands), dyn_cmp_mem_id);
		if (nc > 0 &&
		    dyn_build_buckets(cands, nc, &bs, &nb) != 0) {
			free(cands);
			goto oom;
		}
		for (bi = 0; bi < nb; bi++) {
			if (bs[bi].n < (size_t)min_compact)
				continue;
			if (dyn_groups_push(out, bs[bi].items, bs[bi].n) != 0) {
				dyn_buckets_free(bs, nb);
				free(cands);
				goto oom;
			}
		}
		dyn_buckets_free(bs, nb);
		free(cands);
		if (out->n >= DYN_MAX_REGIONS)
			stop = 1;
		if (stop)
			break;
	}
	return 0;
oom:
	set_err(err, errlen, "engine: out of memory (compressible regions)");
	return -1;
}

int aik_engine_compress(aik_engine *e, aik_json **out_created, char *err,
			size_t errlen)
{
	struct dyn_groups lists;
	aik_memory **created = NULL;
	size_t n_created = 0;
	size_t cap_created = 0;
	aik_json *arr = NULL;
	double now;
	size_t gi;
	int committed = 0;
	int rc = -1;

	memset(&lists, 0, sizeof(lists));
	if (out_created)
		*out_created = NULL;
	if (!e || !out_created) {
		set_err(err, errlen, "engine: invalid argument to compress");
		return -1;
	}
	if (wal_guard(e, err, errlen) != 0)
		return -1;
	wal_begin(e);
	now = e->now(e->now_ud);
	if (dyn_find_compressible(e, &lists, now, err, errlen) != 0)
		goto done;
	for (gi = 0; gi < lists.n; gi++) {
		struct dyn_group *g = &lists.v[gi];
		const char *rid;
		char *rid_copy;
		char *text = NULL;
		char **ids;
		aik_memory *s;
		const aik_json *ns;
		aik_json *v;
		int ns_found = 0;
		size_t i;

		if (g->n == 0)
			continue;
		rid = aik_space_region_for(e->space, g->items[0]->id);
		rid_copy = rid ? aik_engine__dup(rid) : NULL;
		if (rid && !rid_copy) {
			set_err(err, errlen, "engine: out of memory (region id)");
			goto done;
		}
		ids = malloc(g->n * sizeof(*ids));
		if (!ids) {
			free(rid_copy);
			set_err(err, errlen, "engine: out of memory (covers)");
			goto done;
		}
		for (i = 0; i < g->n; i++)
			ids[i] = g->items[i]->id;
		if (dyn_compression_text(g->items, g->n, &text, err, errlen) !=
		    0) {
			free(ids);
			free(rid_copy);
			goto done;
		}
		s = dyn_summary_memory(e, text, ids, g->n, 0.7, err, errlen);
		free(text);
		if (!s) {
			free(ids);
			free(rid_copy);
			goto done;
		}
		v = rid_copy ? aik_json_new_str(rid_copy) : aik_json_new_null();
		free(rid_copy);
		if (!v || aik_json_obj_set(s->metadata, "compresses_region", v) !=
				  0) {
			aik_json_free(v);
			free(ids);
			set_err(err, errlen,
				"engine: out of memory (compresses_region)");
			goto done;
		}
		v = aik_json_new_num(now);
		if (!v ||
		    aik_json_obj_set(s->metadata, "compressed_at", v) != 0) {
			aik_json_free(v);
			free(ids);
			set_err(err, errlen,
				"engine: out of memory (compressed_at)");
			goto done;
		}
		v = aik_json_new_int((long long)g->n);
		if (!v || aik_json_obj_set(s->metadata, "cover_count", v) != 0) {
			aik_json_free(v);
			free(ids);
			set_err(err, errlen,
				"engine: out of memory (cover_count)");
			goto done;
		}
		v = dyn_sorted_ids_json(ids, g->n);
		if (!v || aik_json_obj_set(s->metadata, "covers", v) != 0) {
			aik_json_free(v);
			free(ids);
			set_err(err, errlen, "engine: out of memory (covers)");
			goto done;
		}
		ns = dyn_group_ns(g->items, g->n, &ns_found);
		if (ns_found && ns) {
			v = aik_json__clone(ns);
			if (!v ||
			    aik_json_obj_set(s->metadata, "ns", v) != 0) {
				aik_json_free(v);
				free(ids);
				set_err(err, errlen,
					"engine: out of memory (ns)");
				goto done;
			}
		}
		if (dyn_created_push(&created, &n_created, &cap_created, s) != 0) {
			free(ids);
			set_err(err, errlen,
				"engine: out of memory (created list)");
			goto done;
		}
		e->compressions++;
		free(ids);
	}
	if (wal_commit(e, 1, err, errlen) != 0)
		goto done;
	committed = 1;
	if (engine_autosave(e, err, errlen) != 0)
		goto done;
	arr = dyn_created_json(created, n_created);
	if (!arr) {
		set_err(err, errlen, "engine: out of memory (created JSON)");
		goto done;
	}
	*out_created = arr;
	arr = NULL;
	rc = 0;
done:
	if (!committed)
		wal_abort(e);
	aik_json_free(arr);
	free(created);
	dyn_groups_reset(&lists);
	return rc;
}
