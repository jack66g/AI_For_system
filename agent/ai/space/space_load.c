/* SPDX-License-Identifier: GPL-2.0 */
/*
 * space_load.c - T4a 快照状态恢复（纯 C11）
 *
 * 对齐 REF-PY e72bc75：
 *   sme/engine.py::_load_locked（约 1010-1065 行）——space.load_state 之后用
 *   snapshot.regions 的 member_ids ∩ 向量重建成员、全量重算几何、剪空
 *   Region、删悬挂边、反建 membership；
 *   sme/space/space.py::load_state —— 清空运行态，regions 按列表顺序装入
 *   dict，region_edges 按无向对去重。
 *
 * 与 Python 的对应关系：
 *   - Python `vectors` 只含非 archived 且有 embedding 的记忆，本接口的
 *     vectors 数组由调用方按同一规则提供；
 *   - Python update_geometry 只对「与向量集有交集」的 Region 调用；本实现
 *     先过滤成员再对非空 Region 全量重算，结果等价；
 *   - Python `region.member_ids &= vector_ids` 之后空 Region 从 dict 删除；
 *     空的 Region 不进入插入序（与 pop 后的 dict 顺序一致）；
 *   - Python 最后 `region_edges` 保留两端都在 regions 里的边；本实现同；
 *   - created_at 取快照值（缺字段时用注入时钟）；存活 Region 重算几何后
 *     last_updated = 注入时钟（aik_space_set_clock，默认 time(NULL)），
 *     与 Python update_geometry 里的 now() 一致；快照 last_updated 不采用；
 *   - write_ops 置 0（Python 传 {"write_ops": 0}）。
 *
 * 失败返回 -1 并写 err：sp/dim/数组类型/向量维度等参数校验在动 state 之前
 * 完成，失败时空间保持原状；进入恢复流程后的失败（OOM/数据不合法）整块
 * 回滚（aik_space__reset），不留半成品。
 */
#include "space_internal.h"

#include "store/store_json.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void free_member_array(char **arr, size_t n)
{
	size_t i;

	if (!arr)
		return;
	for (i = 0; i < n; i++)
		free(arr[i]);
	free(arr);
}

static int json_is_num(const aik_json *v)
{
	aik_json_type jt = aik_json_typeof(v);

	return jt == AIK_JSON_NUM || jt == AIK_JSON_INT;
}

/* ------------------------------------------------------------------ */
/* 成员过滤：member_ids ∩ 向量 id（保持 JSON 顺序、去重）             */
/* ------------------------------------------------------------------ */
static int collect_members(const aik_space *sp, const aik_json *arr,
			   char ***out, size_t *n_out, char *err, size_t errlen)
{
	char **members = NULL;
	size_t n = 0;
	size_t cap = 0;
	size_t i;

	*out = NULL;
	*n_out = 0;
	if (!arr)
		return 0;
	if (aik_json_typeof(arr) != AIK_JSON_ARR) {
		set_err(err, errlen,
			"space_load: region member_ids is not an array");
		return -1;
	}
	for (i = 0; i < aik_json_count(arr); i++) {
		const char *mid = aik_json_str(aik_json_at(arr, i));
		size_t j;
		int seen = 0;
		char *copy;

		if (!mid) {
			set_err(err, errlen,
				"space_load: region member id is not a string");
			goto fail;
		}
		if (!aik_space__has_vector(sp, mid))
			continue;	/* 向量缺失（archived 等）→ 不是成员 */
		for (j = 0; j < n; j++) {
			if (strcmp(members[j], mid) == 0) {
				seen = 1;
				break;
			}
		}
		if (seen)
			continue;
		if (n == cap) {
			size_t next = cap ? cap * 2 : 8;
			char **grown = realloc(members, next * sizeof(*grown));

			if (!grown) {
				set_err(err, errlen, "space_load: out of memory");
				goto fail;
			}
			members = grown;
			cap = next;
		}
		copy = dup_str(mid);
		if (!copy) {
			set_err(err, errlen, "space_load: out of memory");
			goto fail;
		}
		members[n++] = copy;
	}
	*out = members;
	*n_out = n;
	return 0;
fail:
	free_member_array(members, n);
	return -1;
}

/* ------------------------------------------------------------------ */
/* Region 恢复                                                        */
/* ------------------------------------------------------------------ */
static aik_region *build_region(aik_space *sp, const aik_json *obj, size_t idx,
				char *err, size_t errlen, int *skip)
{
	const aik_json *j;
	const char *id;
	const char *parent = NULL;
	int generation = 1;
	double created_at;
	char **members = NULL;
	size_t n_members = 0;
	aik_region *r;

	*skip = 0;
	if (aik_json_typeof(obj) != AIK_JSON_OBJ) {
		set_err(err, errlen, "space_load: regions[%zu] is not an object",
			idx);
		return NULL;
	}
	id = aik_json_str(aik_json_get(obj, "id"));
	if (!id || !*id) {
		set_err(err, errlen, "space_load: regions[%zu] has no id", idx);
		return NULL;
	}
	j = aik_json_get(obj, "parent_region");
	if (j && aik_json_typeof(j) != AIK_JSON_NULL) {
		parent = aik_json_str(j);
		if (!parent) {
			set_err(err, errlen,
				"space_load: regions[%zu].parent_region is not a string",
				idx);
			return NULL;
		}
	}
	j = aik_json_get(obj, "generation");
	if (j) {
		if (!json_is_num(j)) {
			set_err(err, errlen,
				"space_load: regions[%zu].generation is not a number",
				idx);
			return NULL;
		}
		generation = (int)aik_json_int(j);
	}
	j = aik_json_get(obj, "created_at");
	if (j && !json_is_num(j)) {
		set_err(err, errlen,
			"space_load: regions[%zu].created_at is not a number",
			idx);
		return NULL;
	}
	created_at = j ? aik_json_num(j) : aik_space__now(sp);

	if (collect_members(sp, aik_json_get(obj, "member_ids"), &members,
			    &n_members, err, errlen) < 0)
		return NULL;
	if (n_members == 0) {
		/* Python：member_ids ∩ vectors 为空 → 该 Region 被剪掉 */
		free_member_array(members, n_members);
		*skip = 1;
		return NULL;
	}

	r = aik_space__new_region(sp, id, parent, generation > 0 ? generation : 1,
				  created_at, err, errlen);
	if (!r) {
		free_member_array(members, n_members);
		return NULL;
	}
	/* 原样保留 generation（Python from_dict 不再做 >0 归一） */
	aik_region__set_generation(r, generation);
	aik_region__set_members(r, members, n_members);
	/* 全量重算 centroid/radius/bbox/density（long double 累加） */
	aik_space__refresh_region(sp, r);
	return r;
}

/* ------------------------------------------------------------------ */
/* 默认 id 序号预留：避免新 Region 与已加载的 "r%06zu" 撞名           */
/* ------------------------------------------------------------------ */
static void reserve_region_seq(aik_space *sp, const aik_json *regions)
{
	size_t i;

	for (i = 0; i < aik_json_count(regions); i++) {
		const char *id =
			aik_json_str(aik_json_get(aik_json_at(regions, i), "id"));
		const char *p;
		unsigned long long seq;

		if (!id || id[0] != 'r' || id[1] == '\0')
			continue;
		for (p = id + 1; *p; p++) {
			if (*p < '0' || *p > '9')
				break;
		}
		if (*p != '\0')
			continue;	/* 非纯数字后缀（uuid 风格）不参与 */
		errno = 0;
		seq = strtoull(id + 1, NULL, 10);
		if (errno == 0 && seq <= (unsigned long long)SIZE_MAX)
			aik_space__reserve_region_seq(sp, (size_t)seq);
	}
}

/* ------------------------------------------------------------------ */
/* 公开接口                                                           */
/* ------------------------------------------------------------------ */
int aik_space_load_state(aik_space *sp, int dim,
			 const aik_space_vector *vectors, size_t n_vectors,
			 const aik_json *regions, const aik_json *region_edges,
			 char *err, size_t errlen)
{
	size_t i;

	if (!sp || dim <= 0) {
		set_err(err, errlen,
			"space_load: invalid space or dim (%d)", dim);
		return -1;
	}
	if (n_vectors > 0 && !vectors) {
		set_err(err, errlen, "space_load: vectors is NULL");
		return -1;
	}
	if (aik_json_typeof(regions) != AIK_JSON_ARR) {
		set_err(err, errlen, "space_load: regions is not an array");
		return -1;
	}
	if (region_edges && aik_json_typeof(region_edges) != AIK_JSON_ARR) {
		set_err(err, errlen, "space_load: region_edges is not an array");
		return -1;
	}
	for (i = 0; i < n_vectors; i++) {
		if (!vectors[i].id || !*vectors[i].id ||
		    !vectors[i].vector) {
			set_err(err, errlen,
				"space_load: vectors[%zu] is missing id/vector",
				i);
			return -1;
		}
		if (vectors[i].dim != dim) {
			set_err(err, errlen,
				"space_load: vectors[%zu] dim %d != %d", i,
				vectors[i].dim, dim);
			return -1;
		}
	}

	aik_space__reset(sp);
	aik_space__set_dim(sp, dim);

	/* 1) 向量（只注册，不吸收、不演化） */
	for (i = 0; i < n_vectors; i++) {
		if (aik_space__load_vector(sp, vectors[i].id, vectors[i].vector,
					   err, errlen) < 0)
			goto fail;
	}

	/* 2) Region：插入序、成员过滤、空 Region 丢弃、几何全量重算 */
	for (i = 0; i < aik_json_count(regions); i++) {
		aik_region *r;
		int skip = 0;

		r = build_region(sp, aik_json_at(regions, i), i, err, errlen,
				 &skip);
		if (!r) {
			if (skip)
				continue;
			goto fail;
		}
		if (aik_space__adopt_region(sp, r) < 0) {
			aik_region__free(r);
			set_err(err, errlen, "space_load: out of memory");
			goto fail;
		}
	}

	/* 3) membership 由成员表反建（Python 的 _membership） */
	for (i = 0; i < aik_space_region_count(sp); i++) {
		const aik_region *r = aik_space_region_at(sp, i);
		size_t m;
		size_t n = aik_region_size(r);

		for (m = 0; m < n; m++) {
			const char *mid = aik_region_member(r, m);

			if (aik_space__set_membership(sp, mid, r) < 0) {
				set_err(err, errlen,
					"space_load: membership rebuild failed for '%s'",
					mid);
				goto fail;
			}
		}
	}

	/* 4) 边：只保留两端都存活的边（无向去重，距离沿用快照） */
	for (i = 0; region_edges && i < aik_json_count(region_edges); i++) {
		const aik_json *e = aik_json_at(region_edges, i);
		const aik_json *jd;
		const char *a;
		const char *b;

		if (aik_json_typeof(e) != AIK_JSON_OBJ) {
			set_err(err, errlen,
				"space_load: region_edges[%zu] is not an object",
				i);
			goto fail;
		}
		a = aik_json_str(aik_json_get(e, "source"));
		b = aik_json_str(aik_json_get(e, "target"));
		jd = aik_json_get(e, "distance");
		if (!a || !b || !json_is_num(jd)) {
			set_err(err, errlen,
				"space_load: region_edges[%zu] has no source/target/distance",
				i);
			goto fail;
		}
		if (!aik_space__region_exists(sp, a) ||
		    !aik_space__region_exists(sp, b))
			continue;	/* 悬挂边 */
		if (aik_space__adopt_edge(sp, a, b, aik_json_num(jd)) < 0) {
			set_err(err, errlen, "space_load: out of memory");
			goto fail;
		}
	}

	aik_space__set_write_ops(sp, 0);
	reserve_region_seq(sp, regions);
	return 0;

fail:
	aik_space__reset(sp);
	return -1;
}
