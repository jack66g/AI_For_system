/* SPDX-License-Identifier: GPL-2.0 */
/*
 * space.h - T3b Spatial Memory Space（region 生命周期 + 两阶段 Region 检索）
 *
 * 对齐 REF-PY `sme/space/space.py` 与 `sme/space/region_manager.py`：
 *   - Region 存储保持插入序（dict 语义）；成员按加入序保存；
 *   - 向量按 memory_id 存储，重复 insert 只刷新向量与幂等 guard；
 *   - 写入路径质心走增量 (n*c+v)/(n+1) 并置 stale，消费方 sync 后全量重算；
 *   - split / merge / evolution_pass 的判定、keeper 规则、事件与
 *     `_merge_ops` 滞后窗口逐条对齐（T3B-DESIGN.md §2.1-2.7）。
 *
 * 错误约定：返回 -1 表示失败且 err 已写入原因（err 可为 NULL/errlen=0）。
 * 所有内存均由调用者显式释放，库里没有全局状态。
 *
 * 追加接口（契约外，供 parity 测试取演化历史）：
 *   aik_space_history_count / aik_space_history_at —— 只读借用内部事件
 *   数组，指针在下次修改 space 前有效。
 */
#ifndef _AIK_SPACE_SPACE_H
#define _AIK_SPACE_SPACE_H

#include <stddef.h>

#include "space/region.h"

typedef struct aik_space aik_space;

/*
 * 演化事件：members 均为深拷贝（malloc 的字符串数组），随事件数组一起
 * 由 aik_space_events_free 释放。kind 取值：
 *   region_created | split | merge | region_deleted
 * other_id：split 为新生子 Region，merge 为被吸收 Region，其余 NULL。
 * density：split 为拆分前密度，其余 0。
 */
typedef struct {
	char *kind;
	char *region_id;
	char *other_id;
	char **region_members;
	size_t n_region_members;
	char **other_members;
	size_t n_other_members;
	double density;
} aik_space_event;

/* 阶段 1 命中：region 借用 space 内部指针 */
typedef struct {
	const aik_region *region;
	double score;
	double distance;
} aik_region_hit;

typedef struct {
	int count;
	double avg_size;
	double avg_density;
	double avg_radius;
	double avg_neighbors;
	int max_size;
	int min_size;
	int edge_count;
	int split_count;
	int merge_count;
} aik_region_stats;

/*
 * aik_space_new - 创建空间
 *
 * cfg 为 NULL 时使用 RegionConfig 默认值；dim 必须 > 0。
 */
aik_space *aik_space_new(const aik_region_config *cfg, int dim,
			 char *err, size_t errlen);
void aik_space_free(aik_space *sp);

/*
 * aik_space_insert - 写入一条记忆向量，返回 0
 *
 * 幂等：memory_id 已有向量且 membership 指向仍存在的 Region 时只刷新向量
 * （不累加质心、不增加 write_ops、不触发演化）。孤儿记忆走完整吸收路径。
 * 每次真正吸收后 write_ops++，并按 evolve_interval 触发自动演化。
 */
int aik_space_insert(aik_space *sp, const char *memory_id,
		     const double *vec, char *err, size_t errlen);

/* 删除一条记忆；不存在时静默返回 0。空 Region 会被删除，否则全量刷新几何 */
int aik_space_remove(aik_space *sp, const char *memory_id);

/* 对所有 stale Region 做全量几何重算（清 stale 位） */
void aik_space_sync_geometry(aik_space *sp);

/* memory_id 当前所属 Region id（借用），不在任何 Region 时为 NULL */
const char *aik_space_region_for(const aik_space *sp, const char *memory_id);

size_t aik_space_region_count(const aik_space *sp);
const aik_region *aik_space_region_at(const aik_space *sp, size_t i);
const aik_region *aik_space_region(const aik_space *sp, const char *region_id);

size_t aik_space_edge_count(const aik_space *sp);
/* 边按无向存储但保留写入方向；成功 0，越界 -1。a/b/distance 均可为 NULL */
int aik_space_edge_at(const aik_space *sp, size_t i,
		      const char **a, const char **b, double *distance);

/*
 * aik_space_query_regions - 两阶段 Region 检索（T3B-DESIGN.md §2.7）
 *
 * *out 为单块 malloc（调用者 free）；top_k<=0 或没有可用 Region 时 *out=NULL,
 * *n_out=0。稳定排序：分数降序、同分保持 Region 插入序。
 */
int aik_space_query_regions(const aik_space *sp, const double *query, int top_k,
			    aik_region_hit **out, size_t *n_out,
			    char *err, size_t errlen);

/*
 * aik_space_evolution_pass - 一次演化（split -> small merge -> close merge）
 *
 * *events 为本次演化产生的事件数组（深拷贝，单块 malloc），无事件时为 NULL；
 * 调用者用 aik_space_events_free 释放。同一批事件也已追加到内部 history。
 */
int aik_space_evolution_pass(aik_space *sp, aik_space_event **events,
			     size_t *n_events, char *err, size_t errlen);
void aik_space_events_free(aik_space_event *events, size_t n);

/*
 * aik_space_split / aik_space_merge - 显式拆分/合并
 *
 * 返回 0 表示执行成功（keep_id / new_id / keeper_id 指向 malloc 字符串，
 * 调用者 free）；1 表示前置条件不满足（Region 不存在、成员数不足、种子
 * 相同等）；-1 表示错误（err 已写）。
 */
int aik_space_split(aik_space *sp, const char *region_id,
		    char **keep_id, char **new_id, char *err, size_t errlen);
int aik_space_merge(aik_space *sp, const char *a, const char *b,
		    char **keeper_id, char *err, size_t errlen);

/* 统计；内部会 sync_geometry 以保证 radius/density 精确 */
int aik_space_region_stats(const aik_space *sp, aik_region_stats *out);

int aik_space_write_ops(const aik_space *sp);

/* 追加接口：内部演化历史（只读借用） */
size_t aik_space_history_count(const aik_space *sp);
const aik_space_event *aik_space_history_at(const aik_space *sp, size_t i);

#endif /* _AIK_SPACE_SPACE_H */
