/* SPDX-License-Identifier: GPL-2.0 */
/*
 * space_internal.h - space.c / space_load.c 之间的内部接口
 *
 * 只暴露快照恢复（T4a）与 region.c 内部构造所需的最小符号。这些符号
 * 不属于 T3 公共契约，不承诺 ABI/语义稳定，space/ 之外的模块不得使用。
 *
 * 约定：
 *   - 所有 aik_space__* 函数对 NULL 安全（无操作/返回 -1）；
 *   - 所有权：Region 对象一旦被 aik_space__adopt_region 采纳即归 space，
 *     reset/free 时统一释放；成员 id 数组由 aik_region__set_members 接管。
 */
#ifndef _AIK_SPACE_SPACE_INTERNAL_H
#define _AIK_SPACE_SPACE_INTERNAL_H

#include <stddef.h>

#include "space/space.h"

/* ------------------------------------------------------------------ */
/* region.c 内部构造 / 几何（实现在 region.c）                        */
/* ------------------------------------------------------------------ */
typedef const double *(*aik_region_lookup_fn)(void *ctx,
					      const char *memory_id);

aik_region *aik_region__new(int dim, const char *id, const char *parent_id,
			    int generation, double created_at,
			    char *err, size_t errlen);
void aik_region__free(aik_region *r);
int aik_region__append_member(aik_region *r, const char *memory_id);
int aik_region__drop_member(aik_region *r, const char *memory_id);
/* 接管 members（外部分配的字符串数组）；旧成员数组被释放 */
void aik_region__set_members(aik_region *r, char **members, size_t n);
void aik_region__set_generation(aik_region *r, int generation);
/* 注入 Region 时间源（mark_stale / refresh_geometry 的 last_updated）；
 * fn 为 NULL 时回退 time(NULL)。space 层负责在创建/重置时传播。 */
void aik_region__set_clock(aik_region *r, double (*fn)(void *ud), void *ud);
void aik_region__mark_stale(aik_region *r);
void aik_region__incremental_centroid(aik_region *r, const double *vec);
int aik_region__stale(const aik_region *r);
void aik_region__refresh_geometry(aik_region *r, aik_region_lookup_fn lookup,
				  void *ctx);

/* ------------------------------------------------------------------ */
/* space.c 内部（实现在 space.c，供 space_load.c 使用）               */
/* ------------------------------------------------------------------ */

/*
 * aik_space__reset - 清空全部运行态
 *
 * 释放向量表内容、全部 Region、Region 边、演化候选、close 集合、
 * merge_ops 与事件历史；write_ops/region_seq 归零。保留 cfg、dim、bulk、
 * id_fn、时钟（now_fn/now_ud）与各表容量（容量复用），可反复调用。
 */
void aik_space__reset(aik_space *sp);

/* 设置维度（load 前调用）；dim<=0 时忽略 */
void aik_space__set_dim(aik_space *sp, int dim);

/* 以 sp->dim 构造一个 Region（load 用；created_at/generation 原样保留） */
aik_region *aik_space__new_region(aik_space *sp, const char *id,
				  const char *parent_id, int generation,
				  double created_at, char *err, size_t errlen);

/*
 * aik_space__load_vector - 注册一条向量
 *
 * 重复 id 只覆盖向量内容（保持原槽位与 membership）；不吸收成员、
 * 不增加 write_ops、不触发演化。成功 0，OOM 返回 -1 并写 err。
 */
int aik_space__load_vector(aik_space *sp, const char *memory_id,
			   const double *vec, char *err, size_t errlen);

/* memory_id 是否已有向量：1/0 */
int aik_space__has_vector(const aik_space *sp, const char *memory_id);

/* Region id 是否存活：1/0 */
int aik_space__region_exists(const aik_space *sp, const char *region_id);

/*
 * aik_space__adopt_region - 采纳一个 Region
 *
 * 追加到插入序末尾；同 id 已存在时释放旧对象并在原位置替换（Python
 * dict 语义）。成功后 Region 归 space 所有（即便返回 -1 以外的失败，
 * 调用者仅需在返回 -1 时自行释放 r）。
 */
int aik_space__adopt_region(aik_space *sp, aik_region *r);

/* 用 sp 的向量表全量重算几何（Region 不必已加入 Region 列表） */
void aik_space__refresh_region(aik_space *sp, aik_region *r);

/* 绑定 membership：region 为 NULL 表示解除；memory_id 无向量返回 -1 */
int aik_space__set_membership(aik_space *sp, const char *memory_id,
			      const aik_region *region);

/* 追加/替换一条无向边（同对保持首次位置，distance 取最后一次） */
int aik_space__adopt_edge(aik_space *sp, const char *a, const char *b,
			  double distance);

/* write_ops 直接赋值（load 置 0） */
void aik_space__set_write_ops(aik_space *sp, int write_ops);

/* 当前注入时钟（未设置时 time(NULL)）；load 补默认 created_at 用 */
double aik_space__now(const aik_space *sp);

/* 预留默认 id 自增序号（仅当 seq > 当前 region_seq 时生效） */
void aik_space__reserve_region_seq(aik_space *sp, size_t seq);

#endif /* _AIK_SPACE_SPACE_INTERNAL_H */
