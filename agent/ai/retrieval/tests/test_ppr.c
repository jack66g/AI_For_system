/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_ppr.c - T3b Personalized PageRank 向量自测
 *
 * 数据：$AIK_PARITY_VECTORS/retrieval/search.vectors.json 的 ppr_cases
 * （3 组，12 个节点质量，含 dangling 节点与零质量节点）。
 *
 * 每个用例按 nodes 顺序构造转移表：adj 的每个三元组 [u, v, w] 属于 u
 * 这一行，prob = w / 行内权重和（行和为 0 时 1/出度）；无出边的节点是
 * dangling。personalization = seeds[i].weight / total，按 seeds 顺序用
 * `+=` 累加（与 Python 一致）。比较每个节点 PPR 值，相对误差 <= 1e-9。
 *
 * 输出：SUMMARY ppr checks=<n> mismatches=<m>；有失配 exit 1。
 */
#include "retrieval/ppr.h"
#include "store/store_json.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checked;
static size_t mismatched;

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
		fclose(f);
		return NULL;
	}
	buf = malloc((size_t)n + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	got = fread(buf, 1, (size_t)n, f);
	fclose(f);
	if (got != (size_t)n) {
		free(buf);
		return NULL;
	}
	buf[got] = '\0';
	*len = got;
	return buf;
}

static int close_enough(double got, double exp)
{
	double scale = fabs(exp) > 1.0 ? fabs(exp) : 1.0;

	return fabs(got - exp) <= 1e-9 * scale;
}

static void check_num(const char *what, double got, double exp)
{
	checked++;
	if (!close_enough(got, exp)) {
		mismatched++;
		printf("MISMATCH %s got=%.17g exp=%.17g\n", what, got, exp);
	}
}

static double num_or(const aik_json *obj, const char *key, double def)
{
	const aik_json *v = aik_json_get(obj, key);

	return v ? aik_json_num(v) : def;
}

static long node_index(const char *const *nodes, size_t n, const char *name)
{
	size_t i;

	if (!name)
		return -1;
	for (i = 0; i < n; i++) {
		if (strcmp(nodes[i], name) == 0)
			return (long)i;
	}
	return -1;
}

/* 处理一个 ppr_case；返回 0 表示结构完好（数值失配单独计数） */
static int run_case(const aik_json *cs)
{
	const aik_json *jn = aik_json_get(cs, "nodes");
	const aik_json *ja = aik_json_get(cs, "adj");
	const aik_json *jseeds = aik_json_get(cs, "seeds");
	const aik_json *jvals = aik_json_get(cs, "values");
	const char *id = aik_json_str(aik_json_get(cs, "id"));
	const char *name = id && *id ? id : "?";
	size_t n = aik_json_count(jn);
	size_t m = aik_json_count(ja);
	size_t n_seeds = aik_json_count(jseeds);
	size_t n_vals = aik_json_count(jvals);
	const char **nodes = NULL;
	const char **eu = NULL;
	const char **ev = NULL;
	double *ew = NULL;
	size_t *src = NULL;
	size_t *dst = NULL;
	double *prob = NULL;
	double *p = NULL;
	double *out = NULL;
	char what[256];
	double total;
	size_t i;
	size_t e;
	size_t k;
	size_t s;
	size_t v;
	int rc = -1;

	nodes = calloc(n ? n : 1, sizeof *nodes);
	eu = calloc(m ? m : 1, sizeof *eu);
	ev = calloc(m ? m : 1, sizeof *ev);
	ew = calloc(m ? m : 1, sizeof *ew);
	src = calloc(m ? m : 1, sizeof *src);
	dst = calloc(m ? m : 1, sizeof *dst);
	prob = calloc(m ? m : 1, sizeof *prob);
	p = calloc(n ? n : 1, sizeof *p);
	out = calloc(n ? n : 1, sizeof *out);
	if (!nodes || !eu || !ev || !ew || !src || !dst || !prob || !p || !out)
		goto done;

	for (i = 0; i < n; i++)
		nodes[i] = aik_json_str(aik_json_at(jn, i));
	for (e = 0; e < m; e++) {
		const aik_json *t = aik_json_at(ja, e);

		eu[e] = aik_json_str(aik_json_at(t, 0));
		ev[e] = aik_json_str(aik_json_at(t, 1));
		ew[e] = aik_json_num(aik_json_at(t, 2));
		if (!eu[e] || !ev[e])
			goto done;
	}

	/* 按 nodes 顺序逐行构造（行内保持 adj 出现顺序） */
	k = 0;
	for (i = 0; i < n; i++) {
		double wsum = 0.0;
		size_t cnt = 0;

		for (e = 0; e < m; e++) {
			if (strcmp(eu[e], nodes[i]) == 0) {
				wsum += ew[e];
				cnt++;
			}
		}
		for (e = 0; e < m; e++) {
			long j;

			if (strcmp(eu[e], nodes[i]) != 0)
				continue;
			j = node_index(nodes, n, ev[e]);
			if (j < 0)
				goto done;
			src[k] = i;
			dst[k] = (size_t)j;
			prob[k] = wsum > 0.0 ? ew[e] / wsum
					     : 1.0 / (double)cnt;
			k++;
		}
	}
	if (k != m)
		goto done;

	total = num_or(cs, "total", 1.0);
	if (total == 0.0)
		total = 1.0;
	for (s = 0; s < n_seeds; s++) {
		const aik_json *sd = aik_json_at(jseeds, s);
		long idx = node_index(nodes, n,
				      aik_json_str(aik_json_get(sd, "node")));

		if (idx < 0)
			goto done;
		p[idx] += num_or(sd, "weight", 0.0) / total;
	}

	if (aik_ppr_rank(n, p, src, dst, prob, m, out) != 0) {
		mismatched++;
		printf("MISMATCH ppr[%s].rc\n", name);
		rc = 0;
		goto done;
	}

	for (v = 0; v < n_vals; v++) {
		const aik_json *val = aik_json_at(jvals, v);
		const char *node = aik_json_str(aik_json_get(val, "node"));
		long idx = node_index(nodes, n, node);

		if (idx < 0) {
			mismatched++;
			printf("MISMATCH ppr[%s].%s unknown node\n", name,
			       node ? node : "?");
			continue;
		}
		snprintf(what, sizeof(what), "ppr[%s].%s", name, node);
		check_num(what, out[idx], num_or(val, "value", 0.0));
	}
	rc = 0;
done:
	free(nodes);
	free(eu);
	free(ev);
	free(ew);
	free(src);
	free(dst);
	free(prob);
	free(p);
	free(out);
	return rc;
}

int main(void)
{
	char file[4096];
	char err[256];
	char *buf;
	size_t len = 0;
	aik_json *root;
	const aik_json *cases;
	size_t n_cases;
	size_t i;

	snprintf(file, sizeof(file), "%s/retrieval/search.vectors.json",
		 vectors_dir());
	buf = read_file(file, &len);
	if (!buf)
		return 2;
	root = aik_json_parse(buf, len, err, sizeof(err));
	free(buf);
	if (!root) {
		fprintf(stderr, "parse %s failed: %s\n", file, err);
		return 2;
	}

	cases = aik_json_get(root, "ppr_cases");
	n_cases = aik_json_count(cases);
	if (n_cases == 0) {
		printf("SUMMARY ppr checks=0 mismatches=1\n");
		printf("MISMATCH ppr_cases missing/empty\n");
		aik_json_free(root);
		return 1;
	}
	for (i = 0; i < n_cases; i++) {
		if (run_case(aik_json_at(cases, i)) != 0) {
			mismatched++;
			printf("MISMATCH ppr_cases[%zu] malformed case\n", i);
		}
	}

	aik_json_free(root);
	printf("SUMMARY ppr checks=%zu mismatches=%zu\n", checked, mismatched);
	return mismatched ? 1 : 0;
}
