/* SPDX-License-Identifier: GPL-2.0 */
/*
 * region.h - T3b Region 几何（纯 C11）
 *
 * 对齐 REF-PY `sme/models.py` Region 与 `sme/utils.py` vector_mean/bbox_of/
 * euclidean_distance：
 *   - centroid = 成员向量均值；radius = 成员到质心距离的最大值；
 *   - bbox = 逐轴 min/max，跨度 < 1e-6 的轴两侧各扩 1e-6；
 *   - density = size / (1 + 平均质心距离)；无成员时 centroid=0、radius=0、
 *     density=0（bbox 保持不变，与 Python update_geometry 的空分支一致）。
 *
 * Region 成员保持加入序（调用者通过 aik_region_member 按序遍历）。几何量
 * 由 space 层驱动刷新：写入路径只做增量质心并置 stale 位，消费方调用
 * aik_space_sync_geometry 才做全量重算（见 T3B-DESIGN.md §2.1）。
 *
 * 本文件只暴露只读访问器；构造/销毁/更新由 space.c 内部调用
 * （内部符号 aik_region__*，声明见 space.c 顶部）。
 */
#ifndef _AIK_SPACE_REGION_H
#define _AIK_SPACE_REGION_H

#include <stddef.h>

/* Region 演化参数（默认值同 sme.config.RegionConfig） */
typedef struct {
	int min_region_size;	/* 3：小于它的 Region 进 small 候选 */
	double min_join_cosine;	/* 0.70：加入/合并的质心余弦门槛 */
	int split_threshold;	/* 48：达到它的 Region 进 split 候选 */
	double max_density;	/* 120.0：拆分所需的最小密度 */
	double merge_distance;	/* 0.12：质心距离小于它记入 close 集合 */
	double neighbor_factor;	/* 1.8：建边阈值 (r1+r2)*factor */
	int auto_evolve;	/* 非 0：insert/remove 触发自动演化 */
	int evolve_interval;	/* 40：每 N 次 write_ops 一次演化 */
} aik_region_config;

typedef struct aik_region aik_region;

/* 全部访问器对 NULL 安全：返回 NULL 或 0 */
const char *aik_region_id(const aik_region *r);
size_t aik_region_size(const aik_region *r);
const char *aik_region_member(const aik_region *r, size_t i);
const double *aik_region_centroid(const aik_region *r);
double aik_region_radius(const aik_region *r);
double aik_region_density(const aik_region *r);
const double *aik_region_bbox_min(const aik_region *r);
const double *aik_region_bbox_max(const aik_region *r);
int aik_region_generation(const aik_region *r);
const char *aik_region_parent(const aik_region *r);	/* 可为 NULL */
double aik_region_created_at(const aik_region *r);
double aik_region_last_updated(const aik_region *r);

#endif /* _AIK_SPACE_REGION_H */
