/* SPDX-License-Identifier: GPL-2.0 */
/*
 * region.c - Region 几何（对齐 sme/models.py Region + sme/utils.py）
 *
 * 几何用 long double 累加再落回 double：
 *   - Python 的 np.mean 按成员集合的迭代序逐项相加，末位随哈希序漂移；
 *   - 扩展精度累加得到正确舍入的均值，把「同一 Region 几何」的末位误差
 *     压到 <=1 ulp（远小于 1e-9 的验收门槛），同时在 split 种子选择的
 *     近似平局上给出稳定、可复现的结果（见交付报告的语义偏差一节）。
 * 增量质心 (n*c+v)/(n+1) 同样在 long double 中计算后存 double。
 */
#include "../include/space/region.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* 小维度（<=128）的质心累加走栈缓冲，避免几何刷新引入分配失败点 */
#define AIK_REGION_STACK_DIM 128
#define AIK_REGION_BBOX_EPS 1e-6

struct aik_region {
	char *id;
	char **members;
	size_t n_members;
	size_t cap_members;
	int dim;
	double *centroid;
	double *bbox_min;
	double *bbox_max;
	double radius;
	double density;
	int generation;
	char *parent_id;
	double created_at;
	double last_updated;
	int stale;
};

/* ------------------------------------------------------------------ */
/* 内部辅助                                                           */
/* ------------------------------------------------------------------ */
static double aik_now(void)
{
	return (double)time(NULL);
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

/* ------------------------------------------------------------------ */
/* 构造 / 销毁（space.c 内部使用）                                    */
/* ------------------------------------------------------------------ */
aik_region *aik_region__new(int dim, const char *id, const char *parent_id,
			    int generation, double created_at,
			    char *err, size_t errlen);

void aik_region__free(aik_region *r);

int aik_region__append_member(aik_region *r, const char *memory_id);
int aik_region__drop_member(aik_region *r, const char *memory_id);
void aik_region__set_members(aik_region *r, char **members, size_t n);
void aik_region__set_generation(aik_region *r, int generation);
void aik_region__mark_stale(aik_region *r);
void aik_region__incremental_centroid(aik_region *r, const double *vec);
int aik_region__stale(const aik_region *r);

typedef const double *(*aik_region_lookup_fn)(void *ctx, const char *memory_id);

void aik_region__refresh_geometry(aik_region *r, aik_region_lookup_fn lookup,
				  void *ctx);

static void set_err(char *err, size_t errlen, const char *msg)
{
	if (err && errlen)
		snprintf(err, errlen, "%s", msg);
}

aik_region *aik_region__new(int dim, const char *id, const char *parent_id,
			    int generation, double created_at,
			    char *err, size_t errlen)
{
	aik_region *r;

	if (dim <= 0 || !id) {
		set_err(err, errlen, "aik_region_new: invalid argument");
		return NULL;
	}
	r = calloc(1, sizeof(*r));
	if (!r) {
		set_err(err, errlen, "aik_region_new: out of memory");
		return NULL;
	}
	r->id = dup_str(id);
	r->parent_id = parent_id ? dup_str(parent_id) : NULL;
	r->dim = dim;
	r->centroid = calloc((size_t)dim, sizeof(double));
	r->bbox_min = calloc((size_t)dim, sizeof(double));
	r->bbox_max = calloc((size_t)dim, sizeof(double));
	if (!r->id || (parent_id && !r->parent_id) || !r->centroid ||
	    !r->bbox_min || !r->bbox_max) {
		aik_region__free(r);
		set_err(err, errlen, "aik_region_new: out of memory");
		return NULL;
	}
	r->generation = generation > 0 ? generation : 1;
	r->created_at = created_at;
	r->last_updated = created_at;
	r->radius = 0.0;
	r->density = 0.0;
	r->stale = 0;
	return r;
}

void aik_region__free(aik_region *r)
{
	if (!r)
		return;
	free(r->id);
	free(r->parent_id);
	free_member_array(r->members, r->n_members);
	free(r->centroid);
	free(r->bbox_min);
	free(r->bbox_max);
	free(r);
}

int aik_region__append_member(aik_region *r, const char *memory_id)
{
	char **grown;
	size_t cap;
	char *copy;

	if (!r || !memory_id)
		return -1;
	if (r->n_members == r->cap_members) {
		cap = r->cap_members ? r->cap_members * 2 : 4;
		grown = realloc(r->members, cap * sizeof(char *));
		if (!grown)
			return -1;
		r->members = grown;
		r->cap_members = cap;
	}
	copy = dup_str(memory_id);
	if (!copy)
		return -1;
	r->members[r->n_members++] = copy;
	return 0;
}

int aik_region__drop_member(aik_region *r, const char *memory_id)
{
	size_t i;

	if (!r || !memory_id)
		return -1;
	for (i = 0; i < r->n_members; i++) {
		if (strcmp(r->members[i], memory_id) == 0) {
			free(r->members[i]);
			memmove(&r->members[i], &r->members[i + 1],
				(r->n_members - i - 1) * sizeof(char *));
			r->n_members--;
			return 0;
		}
	}
	return 0;
}

void aik_region__set_members(aik_region *r, char **members, size_t n)
{
	if (!r)
		return;
	free_member_array(r->members, r->n_members);
	r->members = members;
	r->n_members = n;
	r->cap_members = n;
}

void aik_region__set_generation(aik_region *r, int generation)
{
	if (r)
		r->generation = generation;
}

void aik_region__mark_stale(aik_region *r)
{
	if (!r)
		return;
	r->stale = 1;
	r->last_updated = aik_now();
}

int aik_region__stale(const aik_region *r)
{
	return r ? r->stale : 0;
}

void aik_region__incremental_centroid(aik_region *r, const double *vec)
{
	size_t j;
	size_t n;

	if (!r || !vec || !r->centroid)
		return;
	n = r->n_members;
	if (n == 0)
		return;
	for (j = 0; j < (size_t)r->dim; j++) {
		long double v = ((long double)(n - 1) *
				 (long double)r->centroid[j] +
				 (long double)vec[j]) / (long double)n;
		r->centroid[j] = (double)v;
	}
}

void aik_region__refresh_geometry(aik_region *r, aik_region_lookup_fn lookup,
				  void *ctx)
{
	long double stack_sum[AIK_REGION_STACK_DIM];
	long double *sum = stack_sum;
	size_t count = 0;
	size_t i, j;
	long double maxd = 0.0L;
	long double sumd = 0.0L;
	int first = 1;

	if (!r || !lookup)
		return;
	if (r->dim > AIK_REGION_STACK_DIM) {
		sum = calloc((size_t)r->dim, sizeof(*sum));
		if (!sum)
			return;	/* 保底：保持旧几何，stale 位不清 */
	}
	memset(sum, 0, (size_t)r->dim * sizeof(*sum));
	for (i = 0; i < r->n_members; i++) {
		const double *v = lookup(ctx, r->members[i]);

		if (!v)
			continue;
		for (j = 0; j < (size_t)r->dim; j++)
			sum[j] += (long double)v[j];
		count++;
	}
	if (count == 0) {
		memset(r->centroid, 0, (size_t)r->dim * sizeof(double));
		r->radius = 0.0;
		r->density = 0.0;
		if (sum != stack_sum)
			free(sum);
		return;
	}
	for (j = 0; j < (size_t)r->dim; j++)
		r->centroid[j] = (double)(sum[j] / (long double)count);
	if (sum != stack_sum)
		free(sum);
	for (i = 0; i < r->n_members; i++) {
		const double *v = lookup(ctx, r->members[i]);
		long double d2 = 0.0L;
		long double d;

		if (!v)
			continue;
		for (j = 0; j < (size_t)r->dim; j++) {
			long double diff =
				(long double)v[j] - (long double)r->centroid[j];
			d2 += diff * diff;
		}
		d = sqrtl(d2);
		if (d > maxd)
			maxd = d;
		sumd += d;
		if (first) {
			for (j = 0; j < (size_t)r->dim; j++) {
				r->bbox_min[j] = v[j];
				r->bbox_max[j] = v[j];
			}
			first = 0;
		} else {
			for (j = 0; j < (size_t)r->dim; j++) {
				if (v[j] < r->bbox_min[j])
					r->bbox_min[j] = v[j];
				if (v[j] > r->bbox_max[j])
					r->bbox_max[j] = v[j];
			}
		}
	}
	r->radius = (double)maxd;
	r->density = (double)((long double)count /
			      (1.0L + sumd / (long double)count));
	for (j = 0; j < (size_t)r->dim; j++) {
		if (r->bbox_max[j] - r->bbox_min[j] < AIK_REGION_BBOX_EPS) {
			r->bbox_min[j] -= AIK_REGION_BBOX_EPS;
			r->bbox_max[j] += AIK_REGION_BBOX_EPS;
		}
	}
	r->stale = 0;
	r->last_updated = aik_now();
}

/* ------------------------------------------------------------------ */
/* 只读访问器                                                         */
/* ------------------------------------------------------------------ */
const char *aik_region_id(const aik_region *r)
{
	return r ? r->id : NULL;
}

size_t aik_region_size(const aik_region *r)
{
	return r ? r->n_members : 0;
}

const char *aik_region_member(const aik_region *r, size_t i)
{
	if (!r || i >= r->n_members)
		return NULL;
	return r->members[i];
}

const double *aik_region_centroid(const aik_region *r)
{
	return r ? r->centroid : NULL;
}

double aik_region_radius(const aik_region *r)
{
	return r ? r->radius : 0.0;
}

double aik_region_density(const aik_region *r)
{
	return r ? r->density : 0.0;
}

const double *aik_region_bbox_min(const aik_region *r)
{
	return r ? r->bbox_min : NULL;
}

const double *aik_region_bbox_max(const aik_region *r)
{
	return r ? r->bbox_max : NULL;
}

int aik_region_generation(const aik_region *r)
{
	return r ? r->generation : 0;
}

const char *aik_region_parent(const aik_region *r)
{
	return r ? r->parent_id : NULL;
}

double aik_region_created_at(const aik_region *r)
{
	return r ? r->created_at : 0.0;
}

double aik_region_last_updated(const aik_region *r)
{
	return r ? r->last_updated : 0.0;
}
