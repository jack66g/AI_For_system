/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_space.c - T3b Region 几何 + Space 生命周期向量自测
 *
 * 数据：$AIK_PARITY_VECTORS/retrieval/space.vectors.json（默认
 * $HOME/aikernel-longterm/parity/vectors）。按 ops 顺序重放 38 个操作，
 * 每步 sync_geometry 后与 states[i] 比较：
 *   - Region 集合按 canonical key（成员升序以 '+' 连接）匹配；
 *   - centroid/radius/density/bbox 相对误差 <= 1e-9（|exp|<=1 时退化为
 *     绝对误差 1e-9，见 close_enough）；
 *   - generation/parent_key 精确，边按无向 canonical 对匹配，distance
 *     <= 1e-9；write_ops/region_count 精确。
 * 全部操作结束后比较 history 的 kind/region_key/detail（merge detail 用
 * `absorbed [key] (N members)`），以及 6 组 query_regions 与 region_stats。
 *
 * 输出最后一行：checks=<N> mismatches=<M>；有失配 exit 1 并打印路径。
 * 读向量失败 / 字段缺失同样 exit 1 并说明。
 */
#include "../../include/space/space.h"
#include "../../include/store/store_json.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checks;
static size_t mismatches;

/* ------------------------------------------------------------------ */
/* 输入                                                                */
/* ------------------------------------------------------------------ */
static const char *vectors_dir(void)
{
	static char buf[1024];
	const char *d = getenv("AIK_PARITY_VECTORS");
	const char *home = getenv("HOME");

	if (d && *d)
		return d;
	snprintf(buf, sizeof(buf), "%s/aikernel-longterm/parity/vectors",
		 home && *home ? home : ".");
	return buf;
}

static char *read_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	char *buf;
	long n;
	size_t got;

	if (!f) {
		fprintf(stderr, "cannot open %s\n", path);
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 ||
	    fseek(f, 0, SEEK_SET) != 0) {
		fprintf(stderr, "cannot seek %s\n", path);
		fclose(f);
		return NULL;
	}
	buf = malloc((size_t)n + 1);
	if (!buf) {
		fclose(f);
		fprintf(stderr, "out of memory reading %s\n", path);
		return NULL;
	}
	got = fread(buf, 1, (size_t)n, f);
	fclose(f);
	if (got != (size_t)n) {
		free(buf);
		fprintf(stderr, "short read on %s\n", path);
		return NULL;
	}
	buf[got] = '\0';
	*len = got;
	return buf;
}

static char *local_strdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = malloc(n);

	if (p)
		memcpy(p, s, n);
	return p;
}

static void die(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "ERROR: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

static const aik_json *need(const aik_json *obj, const char *key,
			    const char *where)
{
	const aik_json *v = aik_json_get(obj, key);

	if (!v)
		die("%s: missing field '%s'", where, key);
	return v;
}

static const aik_json *at(const aik_json *arr, size_t i, const char *where)
{
	const aik_json *v = aik_json_at(arr, i);

	if (!v)
		die("%s: missing index %zu", where, i);
	return v;
}

static const char *need_str(const aik_json *obj, const char *key,
			    const char *where)
{
	const char *s = aik_json_str(need(obj, key, where));

	if (!s)
		die("%s: field '%s' is not a string", where, key);
	return s;
}

static const char *arr_str(const aik_json *arr, size_t i, const char *where)
{
	const char *s = aik_json_str(at(arr, i, where));

	if (!s)
		die("%s[%zu]: not a string", where, i);
	return s;
}

static double need_num(const aik_json *obj, const char *key,
		       const char *where)
{
	const aik_json *v = need(obj, key, where);

	if (aik_json_typeof(v) != AIK_JSON_NUM &&
	    aik_json_typeof(v) != AIK_JSON_INT)
		die("%s: field '%s' is not a number", where, key);
	return aik_json_num(v);
}

static int need_int(const aik_json *obj, const char *key, const char *where)
{
	return (int)aik_json_int(need(obj, key, where));
}

/* ------------------------------------------------------------------ */
/* 比较                                                                */
/* ------------------------------------------------------------------ */
/* 相对误差 <= 1e-9；|exp|<=1 时退化为绝对误差 1e-9 */
static int close_enough(double got, double exp)
{
	double scale = fabs(exp) > 1.0 ? fabs(exp) : 1.0;

	return fabs(got - exp) <= 1e-9 * scale;
}

static void check_num(const char *path, double got, double exp)
{
	checks++;
	if (!close_enough(got, exp)) {
		fprintf(stderr,
			"MISMATCH %s: got %.17g expected %.17g\n", path, got,
			exp);
		mismatches++;
	}
}

static void check_int(const char *path, long long got, long long exp)
{
	checks++;
	if (got != exp) {
		fprintf(stderr, "MISMATCH %s: got %lld expected %lld\n", path,
			got, exp);
		mismatches++;
	}
}

static void check_str(const char *path, const char *got, const char *exp)
{
	checks++;
	if (!got || strcmp(got, exp) != 0) {
		fprintf(stderr, "MISMATCH %s: got '%s' expected '%s'\n", path,
			got ? got : "(null)", exp);
		mismatches++;
	}
}

/* ------------------------------------------------------------------ */
/* canonical key                                                      */
/* ------------------------------------------------------------------ */
static int cmp_str_ptr(const void *a, const void *b)
{
	const char *sa = *(const char *const *)a;
	const char *sb = *(const char *const *)b;

	return strcmp(sa, sb);
}

static char *canon_join(char *const *ids, size_t n)
{
	char **sorted;
	char *out;
	size_t len = 0;
	size_t i;

	if (n == 0) {
		out = malloc(1);
		if (out)
			out[0] = '\0';
		return out;
	}
	sorted = malloc(n * sizeof(*sorted));
	if (!sorted)
		return NULL;
	for (i = 0; i < n; i++)
		sorted[i] = ids[i];
	qsort(sorted, n, sizeof(*sorted), cmp_str_ptr);
	for (i = 0; i < n; i++)
		len += strlen(sorted[i]);
	len += n - 1;
	out = malloc(len + 1);
	if (out) {
		size_t pos = 0;

		for (i = 0; i < n; i++) {
			size_t l = strlen(sorted[i]);

			memcpy(out + pos, sorted[i], l);
			pos += l;
			if (i + 1 < n)
				out[pos++] = '+';
		}
		out[pos] = '\0';
	}
	free(sorted);
	return out;
}

static char *canon_region(const aik_region *r)
{
	size_t n = aik_region_size(r);
	char **ids;
	char *out;
	size_t i;

	if (n == 0)
		return canon_join(NULL, 0);
	ids = malloc(n * sizeof(*ids));
	if (!ids)
		return NULL;
	for (i = 0; i < n; i++)
		ids[i] = (char *)aik_region_member(r, i);
	out = canon_join(ids, n);
	free(ids);
	return out;
}

static const aik_region *find_region_by_key(const aik_space *sp,
					    const char *key)
{
	size_t i;
	size_t n = aik_space_region_count(sp);

	for (i = 0; i < n; i++) {
		const aik_region *r = aik_space_region_at(sp, i);
		char *ck = canon_region(r);
		int hit = ck && strcmp(ck, key) == 0;

		free(ck);
		if (hit)
			return r;
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/* 事件历史比较用的 region id -> canonical key 映射                   */
/* ------------------------------------------------------------------ */
typedef struct {
	char *rid;
	char *key;
} seen_entry;

typedef struct {
	seen_entry *v;
	size_t n;
	size_t cap;
} seen_map;

static const char *seen_get(const seen_map *m, const char *rid)
{
	size_t i;

	for (i = 0; i < m->n; i++) {
		if (strcmp(m->v[i].rid, rid) == 0)
			return m->v[i].key;
	}
	return NULL;
}

static void seen_put(seen_map *m, const char *rid, const char *key)
{
	size_t i;
	char *rid_copy;
	char *key_copy;

	for (i = 0; i < m->n; i++) {
		if (strcmp(m->v[i].rid, rid) == 0) {
			key_copy = local_strdup(key);
			if (!key_copy)
				die("out of memory");
			free(m->v[i].key);
			m->v[i].key = key_copy;
			return;
		}
	}
	if (m->n == m->cap) {
		size_t next = m->cap ? m->cap * 2 : 8;
		seen_entry *grown = realloc(m->v, next * sizeof(*grown));

		if (!grown)
			die("out of memory");
		m->v = grown;
		m->cap = next;
	}
	rid_copy = local_strdup(rid);
	key_copy = local_strdup(key);
	if (!rid_copy || !key_copy)
		die("out of memory");
	m->v[m->n].rid = rid_copy;
	m->v[m->n].key = key_copy;
	m->n++;
}

static void seen_free(seen_map *m)
{
	size_t i;

	for (i = 0; i < m->n; i++) {
		free(m->v[i].rid);
		free(m->v[i].key);
	}
	free(m->v);
	m->v = NULL;
	m->n = 0;
	m->cap = 0;
}

/* ------------------------------------------------------------------ */
/* 状态比较                                                            */
/* ------------------------------------------------------------------ */
static void compare_region(const aik_space *sp, const aik_region *cr,
			   const aik_json *exp, size_t step, int dim)
{
	char path[512];
	const char *key = need_str(exp, "key", "states[].regions[]");
	int j;

	snprintf(path, sizeof(path), "states[%zu].regions[%s].size", step, key);
	check_int(path, (long long)aik_region_size(cr),
		  (long long)need_int(exp, "size", "region"));

	snprintf(path, sizeof(path),
		 "states[%zu].regions[%s].generation", step, key);
	check_int(path, (long long)aik_region_generation(cr),
		  (long long)need_int(exp, "generation", "region"));

	{
		const aik_json *centroid = need(exp, "centroid", "region");
		const double *got = aik_region_centroid(cr);

		if (aik_json_count(centroid) != (size_t)dim || !got)
			die("region %s: bad centroid", key);
		for (j = 0; j < dim; j++) {
			snprintf(path, sizeof(path),
				 "states[%zu].regions[%s].centroid[%d]", step,
				 key, j);
			check_num(path, got[j], aik_json_num(at(centroid,
								 (size_t)j,
								 "centroid")));
		}
	}
	snprintf(path, sizeof(path), "states[%zu].regions[%s].radius", step, key);
	check_num(path, aik_region_radius(cr), need_num(exp, "radius", "region"));
	snprintf(path, sizeof(path), "states[%zu].regions[%s].density", step,
		 key);
	check_num(path, aik_region_density(cr),
		  need_num(exp, "density", "region"));
	{
		const aik_json *bmin = need(exp, "bbox_min", "region");
		const aik_json *bmax = need(exp, "bbox_max", "region");
		const double *gmin = aik_region_bbox_min(cr);
		const double *gmax = aik_region_bbox_max(cr);

		if (aik_json_count(bmin) != (size_t)dim ||
		    aik_json_count(bmax) != (size_t)dim || !gmin || !gmax)
			die("region %s: bad bbox", key);
		for (j = 0; j < dim; j++) {
			snprintf(path, sizeof(path),
				 "states[%zu].regions[%s].bbox_min[%d]", step,
				 key, j);
			check_num(path, gmin[j],
				  aik_json_num(at(bmin, (size_t)j, "bbox_min")));
			snprintf(path, sizeof(path),
				 "states[%zu].regions[%s].bbox_max[%d]", step,
				 key, j);
			check_num(path, gmax[j],
				  aik_json_num(at(bmax, (size_t)j, "bbox_max")));
		}
	}
	{
		const aik_json *parent = aik_json_get(exp, "parent_key");
		const char *got_parent = aik_region_parent(cr);
		char actual[512];

		snprintf(path, sizeof(path),
			 "states[%zu].regions[%s].parent_key", step, key);
		if (!parent || aik_json_typeof(parent) == AIK_JSON_NULL) {
			checks++;
			if (got_parent) {
				fprintf(stderr,
					"MISMATCH %s: got '%s' expected null\n",
					path, got_parent);
				mismatches++;
			}
		} else {
			const char *exp_parent = aik_json_str(parent);
			const aik_region *pr;

			if (!got_parent) {
				checks++;
				fprintf(stderr,
					"MISMATCH %s: got null expected '%s'\n",
					path, exp_parent ? exp_parent : "?");
				mismatches++;
				return;
			}
			pr = aik_space_region(sp, got_parent);
			if (!pr) {
				snprintf(actual, sizeof(actual), "<deleted>");
			} else {
				char *ck = canon_region(pr);

				if (!ck)
					die("out of memory");
				snprintf(actual, sizeof(actual), "%s", ck);
				free(ck);
			}
			check_str(path, actual, exp_parent ? exp_parent : "");
		}
	}
}

static void compare_state(const aik_space *sp, const aik_json *st, size_t step,
			  int dim)
{
	char path[512];
	const aik_json *regions = need(st, "regions", "state");
	const aik_json *edges = need(st, "edges", "state");
	size_t n_exp = aik_json_count(regions);
	size_t n_edges_exp = aik_json_count(edges);
	size_t n_edges_got = aik_space_edge_count(sp);
	size_t i;
	size_t j;
	unsigned char *edge_used = NULL;

	snprintf(path, sizeof(path), "states[%zu].write_ops", step);
	check_int(path, (long long)aik_space_write_ops(sp),
		  (long long)need_int(st, "write_ops", "state"));
	snprintf(path, sizeof(path), "states[%zu].region_count", step);
	check_int(path, (long long)aik_space_region_count(sp),
		  (long long)need_int(st, "region_count", "state"));
	if (n_exp != aik_space_region_count(sp)) {
		snprintf(path, sizeof(path), "states[%zu].regions", step);
		fprintf(stderr, "MISMATCH %s: got %zu regions expected %zu\n",
			path, aik_space_region_count(sp), n_exp);
		mismatches++;
	}
	for (i = 0; i < n_exp; i++) {
		const aik_json *er = at(regions, i, "states[].regions");
		const char *key = need_str(er, "key", "states[].regions[]");
		const aik_region *cr = find_region_by_key(sp, key);

		snprintf(path, sizeof(path), "states[%zu].regions[%s]", step, key);
		if (!cr) {
			fprintf(stderr, "MISMATCH %s: region missing\n", path);
			mismatches++;
			continue;
		}
		compare_region(sp, cr, er, step, dim);
	}
	if (n_edges_exp != n_edges_got) {
		snprintf(path, sizeof(path), "states[%zu].edges", step);
		fprintf(stderr, "MISMATCH %s: got %zu edges expected %zu\n",
			path, n_edges_got, n_edges_exp);
		mismatches++;
	}
	edge_used = calloc(n_edges_got ? n_edges_got : 1, 1);
	if (!edge_used)
		die("out of memory");
	for (i = 0; i < n_edges_exp; i++) {
		const aik_json *ee = at(edges, i, "states[].edges");
		const char *ea = need_str(ee, "a", "states[].edges[]");
		const char *eb = need_str(ee, "b", "states[].edges[]");
		double dist = need_num(ee, "distance", "states[].edges[]");
		double got = 0.0;
		int found = 0;

		for (j = 0; j < n_edges_got; j++) {
			const char *ga;
			const char *gb;
			double gd;
			const aik_region *gra;
			const aik_region *grb;
			char *gka;
			char *gkb;
			int match;

			if (edge_used[j])
				continue;
			if (aik_space_edge_at(sp, j, &ga, &gb, &gd) != 0)
				continue;
			gra = aik_space_region(sp, ga);
			grb = aik_space_region(sp, gb);
			gka = gra ? canon_region(gra) :
				    local_strdup("<deleted>");
			gkb = grb ? canon_region(grb) :
				    local_strdup("<deleted>");
			if (!gka || !gkb)
				die("out of memory");
			match = ((strcmp(gka, ea) == 0 && strcmp(gkb, eb) == 0) ||
				 (strcmp(gka, eb) == 0 && strcmp(gkb, ea) == 0)) &&
				close_enough(gd, dist);
			free(gka);
			free(gkb);
			if (match) {
				edge_used[j] = 1;
				got = gd;
				found = 1;
				break;
			}
		}
		snprintf(path, sizeof(path), "states[%zu].edges[%s|%s].distance",
			 step, ea, eb);
		checks++;
		if (!found) {
			fprintf(stderr, "MISMATCH %s: edge missing\n", path);
			mismatches++;
		} else {
			check_num(path, got, dist);
		}
	}
	free(edge_used);
}

/* ------------------------------------------------------------------ */
/* query_regions                                                      */
/* ------------------------------------------------------------------ */
static void compare_query(const aik_space *sp, const aik_json *spec, int dim)
{
	const char *id = need_str(spec, "id", "query_regions[]");
	const aik_json *vec = need(spec, "vector", "query_regions[]");
	const aik_json *hits_json = need(spec, "hits", "query_regions[]");
	int top_k = need_int(spec, "top_k", "query_regions[]");
	size_t n_exp = aik_json_count(hits_json);
	aik_region_hit *hits = NULL;
	size_t n_got = 0;
	char path[512];
	size_t i;
	size_t j;
	unsigned char *used = NULL;
	double *query;

	if (!sp)
		die("query %s: null space", id);
	if ((int)aik_json_count(vec) != dim)
		die("query %s: vector has %zu components, dim=%d", id,
		    aik_json_count(vec), dim);
	query = malloc((size_t)dim * sizeof(*query));
	if (!query)
		die("out of memory");
	for (j = 0; j < (size_t)dim; j++)
		query[j] = aik_json_num(at(vec, j, "query vector"));
	if (aik_space_query_regions(sp, query, top_k, &hits, &n_got, NULL, 0) !=
	    0)
		die("query %s: aik_space_query_regions failed", id);
	snprintf(path, sizeof(path), "query_regions[%s].count", id);
	checks++;
	if (n_got != n_exp) {
		fprintf(stderr, "MISMATCH %s: got %zu expected %zu\n", path,
			n_got, n_exp);
		mismatches++;
	}
	/* 结果必须按分数降序（同分允许任意顺序） */
	for (i = 1; i < n_got; i++) {
		if (hits[i].score > hits[i - 1].score + 1e-12) {
			fprintf(stderr,
				"MISMATCH query_regions[%s].order: %.17g before %.17g\n",
				id, hits[i].score, hits[i - 1].score);
			mismatches++;
			break;
		}
		checks++;
	}
	used = calloc(n_got ? n_got : 1, 1);
	if (!used)
		die("out of memory");
	for (i = 0; i < n_exp; i++) {
		const aik_json *eh = at(hits_json, i, "query hits");
		const char *key = need_str(eh, "region", "query hit");
		double exp_score = need_num(eh, "score", "query hit");
		double exp_dist = need_num(eh, "distance", "query hit");
		int found = 0;

		for (j = 0; j < n_got; j++) {
			char *ck;

			if (used[j])
				continue;
			ck = canon_region(hits[j].region);
			if (ck && strcmp(ck, key) == 0 &&
			    close_enough(hits[j].score, exp_score) &&
			    close_enough(hits[j].distance, exp_dist)) {
				free(ck);
				used[j] = 1;
				found = 1;
				break;
			}
			free(ck);
		}
		snprintf(path, sizeof(path), "query_regions[%s].hits[%s]", id,
			 key);
		checks++;
		if (!found) {
			fprintf(stderr, "MISMATCH %s: hit missing\n", path);
			mismatches++;
		}
	}
	free(used);
	free(hits);
	free(query);
}

/* ------------------------------------------------------------------ */
/* region_stats                                                       */
/* ------------------------------------------------------------------ */
static void compare_stats(const aik_space *sp, const aik_json *exp,
			  const char *prefix)
{
	aik_region_stats st;
	char path[512];

	if (aik_space_region_stats(sp, &st) != 0)
		die("%s: aik_space_region_stats failed", prefix);
	snprintf(path, sizeof(path), "%s.count", prefix);
	check_int(path, st.count, need_int(exp, "count", prefix));
	snprintf(path, sizeof(path), "%s.avg_size", prefix);
	check_num(path, st.avg_size, need_num(exp, "avg_size", prefix));
	snprintf(path, sizeof(path), "%s.avg_density", prefix);
	check_num(path, st.avg_density, need_num(exp, "avg_density", prefix));
	snprintf(path, sizeof(path), "%s.avg_radius", prefix);
	check_num(path, st.avg_radius, need_num(exp, "avg_radius", prefix));
	snprintf(path, sizeof(path), "%s.avg_neighbors", prefix);
	check_num(path, st.avg_neighbors,
		  need_num(exp, "avg_neighbors", prefix));
	snprintf(path, sizeof(path), "%s.max_size", prefix);
	check_int(path, st.max_size, need_int(exp, "max_size", prefix));
	snprintf(path, sizeof(path), "%s.min_size", prefix);
	check_int(path, st.min_size, need_int(exp, "min_size", prefix));
	snprintf(path, sizeof(path), "%s.edge_count", prefix);
	check_int(path, st.edge_count, need_int(exp, "edge_count", prefix));
	snprintf(path, sizeof(path), "%s.split_count", prefix);
	check_int(path, st.split_count, need_int(exp, "split_count", prefix));
	snprintf(path, sizeof(path), "%s.merge_count", prefix);
	check_int(path, st.merge_count, need_int(exp, "merge_count", prefix));
}

/* ------------------------------------------------------------------ */
/* history                                                            */
/* ------------------------------------------------------------------ */
/* 由事件字段构造 recorded detail（merge 用 absorbed [key] (n members)） */
static char *event_detail(const aik_space_event *e)
{
	char *out = NULL;

	if (strcmp(e->kind, "split") == 0) {
		out = malloc(128);
		if (!out)
			die("out of memory");
		snprintf(out, 128, "%zu -> %zu members (density %.1f)",
			 e->n_region_members, e->n_other_members, e->density);
	} else if (strcmp(e->kind, "merge") == 0) {
		char *other = canon_join(e->other_members, e->n_other_members);
		size_t len;

		if (!other)
			die("out of memory");
		len = strlen(other) + 96;
		out = malloc(len);
		if (!out)
			die("out of memory");
		snprintf(out, len, "absorbed [%s] (%zu members)", other,
			 e->n_other_members);
		free(other);
	} else if (strcmp(e->kind, "region_created") == 0) {
		out = malloc(64);
		if (!out)
			die("out of memory");
		snprintf(out, 64, "%zu members", e->n_region_members);
	} else {
		out = local_strdup("");
		if (!out)
			die("out of memory");
	}
	return out;
}

static void compare_history(const aik_space *sp, const aik_json *hist)
{
	size_t n_got = aik_space_history_count(sp);
	size_t n_exp = aik_json_count(hist);
	seen_map seen = {0};
	char path[512];
	size_t i;

	snprintf(path, sizeof(path), "history");
	checks++;
	if (n_got != n_exp) {
		fprintf(stderr, "MISMATCH %s: got %zu events expected %zu\n",
			path, n_got, n_exp);
		mismatches++;
	}
	for (i = 0; i < n_got && i < n_exp; i++) {
		const aik_space_event *e = aik_space_history_at(sp, i);
		const aik_json *ee = at(hist, i, "history");
		const char *kind = need_str(ee, "kind", "history[]");
		const char *region_key = need_str(ee, "region_key", "history[]");
		const char *detail = need_str(ee, "detail", "history[]");
		char *key;
		char *want_detail = NULL;

		if (e->n_region_members > 0) {
			key = canon_join(e->region_members, e->n_region_members);
		} else {
			const char *last = e->region_id ?
						   seen_get(&seen, e->region_id) :
						   NULL;

			if (!last)
				last = "<unknown>";
			key = local_strdup(last);
		}
		if (!key)
			die("out of memory");
		if (e->region_id) {
			const char *last = seen_get(&seen, e->region_id);

			if (!last || strcmp(last, key) != 0)
				seen_put(&seen, e->region_id, key);
		}
		want_detail = event_detail(e);
		snprintf(path, sizeof(path), "history[%zu].kind", i);
		check_str(path, e->kind, kind);
		snprintf(path, sizeof(path), "history[%zu].region_key", i);
		check_str(path, key, region_key);
		snprintf(path, sizeof(path), "history[%zu].detail", i);
		check_str(path, want_detail, detail);
		free(key);
		free(want_detail);
	}
	seen_free(&seen);
}

/* ------------------------------------------------------------------ */
/* 操作重放                                                           */
/* ------------------------------------------------------------------ */
static const aik_json *find_query_spec(const aik_json *root, const char *id)
{
	const aik_json *queries = need(root, "query_regions", "root");
	size_t i;
	size_t n = aik_json_count(queries);

	for (i = 0; i < n; i++) {
		const aik_json *q = at(queries, i, "query_regions");

		if (strcmp(need_str(q, "id", "query_regions[]"), id) == 0)
			return q;
	}
	die("query spec '%s' not found", id);
	return NULL;
}

static void read_vector(const aik_json *o, const char *key, double *out,
			size_t dim, const char *where)
{
	const aik_json *vec = need(o, key, where);
	size_t i;

	if (aik_json_count(vec) != dim)
		die("%s.%s: expected %zu components, got %zu", where, key, dim,
		    aik_json_count(vec));
	for (i = 0; i < dim; i++)
		out[i] = aik_json_num(at(vec, i, key));
}

static void replay(aik_space *sp, const aik_json *root, int dim)
{
	const aik_json *ops = need(root, "ops", "root");
	const aik_json *states = need(root, "states", "root");
	size_t n_ops = aik_json_count(ops);
	size_t n_states = aik_json_count(states);
	double *vec = malloc((size_t)dim * sizeof(*vec));
	size_t i;
	char err[256];
	char path[512];

	if (!vec)
		die("out of memory");
	if (n_ops != n_states)
		die("ops/states length mismatch: %zu vs %zu", n_ops, n_states);
	for (i = 0; i < n_ops; i++) {
		const aik_json *op = at(ops, i, "ops");
		const char *kind = need_str(op, "op", "ops[]");
		int rc = 0;

		memset(err, 0, sizeof(err));
		if (strcmp(kind, "insert") == 0) {
			const char *mid = need_str(op, "id", "insert op");

			read_vector(op, "vector", vec, (size_t)dim, "insert op");
			rc = aik_space_insert(sp, mid, vec, err, sizeof(err));
			if (rc != 0)
				die("ops[%zu] insert %s failed: %s", i, mid,
				    err);
		} else if (strcmp(kind, "split") == 0 ||
			   strcmp(kind, "split_b") == 0 ||
			   strcmp(kind, "split_c") == 0) {
			const char *key = need_str(op, "region", "split op");
			const aik_json *children =
				need(op, "children", "split op");
			const aik_region *r = find_region_by_key(sp, key);
			char *keep = NULL;
			char *created = NULL;
			int expected = aik_json_bool(
				need(op, "result", "split op"));

			snprintf(path, sizeof(path), "ops[%zu].%s", i, kind);
			checks++;
			if (!r) {
				fprintf(stderr,
					"MISMATCH %s: region %s not found\n",
					path, key);
				mismatches++;
				continue;
			}
			rc = aik_space_split(sp, aik_region_id(r), &keep,
					     &created, err, sizeof(err));
			if (expected) {
				if (rc != 0) {
					fprintf(stderr,
						"MISMATCH %s.result: rc=%d (%s)\n",
						path, rc, err);
					mismatches++;
				} else {
					const aik_region *kr =
						aik_space_region(sp, keep);
					const aik_region *nr =
						aik_space_region(sp, created);
					char *kk = kr ? canon_region(kr) : NULL;
					char *nk = nr ? canon_region(nr) : NULL;

					snprintf(path, sizeof(path),
						 "ops[%zu].%s.children[0]", i,
						 kind);
					check_str(path, kk,
						  arr_str(children, 0,
							  "children"));
					snprintf(path, sizeof(path),
						 "ops[%zu].%s.children[1]", i,
						 kind);
					check_str(path, nk,
						  arr_str(children, 1,
							  "children"));
					free(kk);
					free(nk);
				}
			} else if (rc == 0) {
				fprintf(stderr, "MISMATCH %s.result: expected failure\n",
					path);
				mismatches++;
			}
			free(keep);
			free(created);
		} else if (strcmp(kind, "merge") == 0 ||
			   strcmp(kind, "merge_b") == 0 ||
			   strcmp(kind, "merge_c") == 0) {
			const char *ka = need_str(op, "a", "merge op");
			const char *kb = need_str(op, "b", "merge op");
			const aik_region *ra = find_region_by_key(sp, ka);
			const aik_region *rb = find_region_by_key(sp, kb);
			char *keeper = NULL;
			int expected = aik_json_bool(
				need(op, "result", "merge op"));

			snprintf(path, sizeof(path), "ops[%zu].%s", i, kind);
			checks++;
			if (!ra || !rb) {
				fprintf(stderr,
					"MISMATCH %s: regions %s / %s not found\n",
					path, ka, kb);
				mismatches++;
				continue;
			}
			rc = aik_space_merge(sp, aik_region_id(ra),
					     aik_region_id(rb), &keeper, err,
					     sizeof(err));
			if (expected && rc != 0) {
				fprintf(stderr,
					"MISMATCH %s.result: rc=%d (%s)\n",
					path, rc, err);
				mismatches++;
			} else if (!expected && rc == 0) {
				fprintf(stderr, "MISMATCH %s.result: expected failure\n",
					path);
				mismatches++;
			}
			free(keeper);
		} else if (strcmp(kind, "evolution_pass") == 0) {
			aik_space_event *events = NULL;
			size_t n_events = 0;
			const aik_json *exp_events =
				need(op, "events", "evolution op");
			size_t n_exp = aik_json_count(exp_events);
			size_t k;

			rc = aik_space_evolution_pass(sp, &events, &n_events,
						      err, sizeof(err));
			if (rc != 0)
				die("ops[%zu] evolution_pass failed: %s", i,
				    err);
			snprintf(path, sizeof(path), "ops[%zu].events", i);
			checks++;
			if (n_events != n_exp) {
				fprintf(stderr,
					"MISMATCH %s: got %zu expected %zu\n",
					path, n_events, n_exp);
				mismatches++;
			}
			for (k = 0; k < n_events && k < n_exp; k++) {
				const aik_json *ee =
					at(exp_events, k, "evolution events");

				snprintf(path, sizeof(path),
					 "ops[%zu].events[%zu].kind", i, k);
				check_str(path, events[k].kind,
					  need_str(ee, "kind", "event"));
				{
					char *dd = event_detail(&events[k]);

					snprintf(path, sizeof(path),
						 "ops[%zu].events[%zu].detail", i,
						 k);
					check_str(path, dd,
						  need_str(ee, "detail",
							   "event"));
					free(dd);
				}
			}
			aik_space_events_free(events, n_events);
		} else if (strcmp(kind, "query_regions") == 0) {
			const char *qid = need_str(op, "id", "query op");

			compare_query(sp, find_query_spec(root, qid), dim);
		} else if (strcmp(kind, "remove") == 0) {
			const char *mid = need_str(op, "id", "remove op");

			rc = aik_space_remove(sp, mid);
			if (rc != 0)
				die("ops[%zu] remove %s failed", i, mid);
		} else if (strcmp(kind, "region_stats") == 0) {
			compare_stats(sp, need(root, "region_stats", "root"),
				      "region_stats");
		} else {
			die("ops[%zu]: unknown op '%s'", i, kind);
		}
		aik_space_sync_geometry(sp);
		compare_state(sp, at(states, i, "states"), i, dim);
	}
	free(vec);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */
int main(void)
{
	char path[2048];
	char *buf;
	size_t len = 0;
	aik_json *root;
	const aik_json *cfg_json;
	aik_region_config cfg;
	aik_space *sp;
	char err[256];
	int dim;

	snprintf(path, sizeof(path), "%s/retrieval/space.vectors.json",
		 vectors_dir());
	buf = read_file(path, &len);
	if (!buf)
		return 1;
	root = aik_json_parse(buf, len, err, sizeof(err));
	free(buf);
	if (!root) {
		fprintf(stderr, "ERROR: %s: invalid JSON: %s\n", path, err);
		return 1;
	}
	dim = need_int(root, "dim", "root");
	cfg_json = need(root, "region_config", "root");
	memset(&cfg, 0, sizeof(cfg));
	cfg.min_region_size = need_int(cfg_json, "min_region_size", "config");
	cfg.min_join_cosine = need_num(cfg_json, "min_join_cosine", "config");
	cfg.split_threshold = need_int(cfg_json, "split_threshold", "config");
	cfg.max_density = need_num(cfg_json, "max_density", "config");
	cfg.merge_distance = need_num(cfg_json, "merge_distance", "config");
	cfg.neighbor_factor = need_num(cfg_json, "neighbor_factor", "config");
	cfg.auto_evolve =
		aik_json_bool(need(cfg_json, "auto_evolve", "config"));
	cfg.evolve_interval = need_int(cfg_json, "evolve_interval", "config");

	memset(err, 0, sizeof(err));
	sp = aik_space_new(&cfg, dim, err, sizeof(err));
	if (!sp) {
		fprintf(stderr, "ERROR: aik_space_new failed: %s\n", err);
		aik_json_free(root);
		return 1;
	}
	replay(sp, root, dim);
	compare_history(sp, need(root, "history", "root"));
	compare_stats(sp, need(root, "region_stats", "root"), "region_stats");
	aik_space_free(sp);
	aik_json_free(root);
	printf("checks=%zu mismatches=%zu\n", checks, mismatches);
	return mismatches == 0 ? 0 : 1;
}
