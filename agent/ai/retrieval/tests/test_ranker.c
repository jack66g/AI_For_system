/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_ranker.c - T3b ranker 向量自测
 *
 * 数据：$AIK_PARITY_VECTORS/retrieval/search.vectors.json 的 ranker_cases
 * （10 组，含 detailed=false 与 decay_enabled=false）。
 *
 *   1. 用 input 的 importance/weight/freshness/hit_count/last_hit 填
 *      aik_memory_view；decay 配置取 config.decay，enabled 取
 *      input.decay_enabled；reference = 文件里的 frozen_now；
 *      has_semantic=1，semantic=input.semantic；
 *      region_score=input.region_score、detailed=input.detailed。
 *   2. 比较 out->score（未舍入 final）与 ranker_cases[i].final，
 *      以及 9 个 breakdown 字段，相对误差 <= 1e-9。
 *   3. detailed=0 的用例额外断言 8 个信号字段精确为 0。
 *   4. 直接验证 aik_round_half_even4：期望值由 CPython
 *      round(x, 4) 实测得到（不是任务书里的三个假设值，见下方注释）。
 *
 * 输出：SUMMARY ranker checks=<n> mismatches=<m>；有失配 exit 1。
 */
#include "../../include/retrieval/ranker.h"
#include "../../include/store/store_json.h"

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

/* 相对误差 <= 1e-9（|exp|<=1 时退化为绝对误差 1e-9） */
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

static void check_exact(const char *what, double got, double exp)
{
	checked++;
	if (got != exp) {
		mismatched++;
		printf("MISMATCH %s got=%.17g exp=%.17g\n", what, got, exp);
	}
}

/*
 * aik_round_half_even4 与 CPython round(x,4) 的对齐表。
 *
 * 期望值全部由 CPython 3 实测（round(x,4)，正确舍入 + 半偶），括号里是
 * 该输入 double 的精确十进制展开：
 *   0.12345  = 0.12345000000000000417... → 0.1235（略大于半值，进位）
 *   0.12355  = 0.12354999999999999316... → 0.1235（略小于半值，舍去）
 *   2.675    = 2.67499999999999982236... → 2.675
 * 注意：任务书里「0.12345→0.1234、0.12355→0.1236」的假设与 CPython
 * 实测不符，按二进制精确展开取值。
 *
 * 0.00035 = 0.00034999999999999999... → 0.0003：这里
 * floor(x*1e4+0.5) 会因二次舍入得到 0.0004，正是选 printf 的动机。
 */
static const struct {
	double in;
	double out;
} round_cases[] = {
	{ 0.12345, 0.1235 },
	{ 0.12355, 0.1235 },
	{ 2.675, 2.675 },
	{ 0.00035, 0.0003 },
	{ 0.00045, 0.0004 },
	{ 1.00005, 1.0001 },
	{ 0.99995, 1.0 },
	{ 123456.78905, 123456.7891 },
	{ -0.12345, -0.1235 },
	{ 0.30272695164869046, 0.3027 },
};

static void run_round_cases(void)
{
	char what[128];
	size_t i;

	for (i = 0; i < sizeof(round_cases) / sizeof(round_cases[0]); i++) {
		snprintf(what, sizeof(what), "round_half_even4[%.17g]",
			 round_cases[i].in);
		checked++;
		if (aik_round_half_even4(round_cases[i].in) !=
		    round_cases[i].out) {
			mismatched++;
			printf("MISMATCH %s got=%a exp=%a\n", what,
			       aik_round_half_even4(round_cases[i].in),
			       round_cases[i].out);
		}
	}
}

static double num_or(const aik_json *obj, const char *key, double def)
{
	const aik_json *v = aik_json_get(obj, key);

	return v ? aik_json_num(v) : def;
}

int main(void)
{
	char file[4096];
	char err[256];
	char what[512];
	char *buf;
	size_t len = 0;
	aik_json *root;
	const aik_json *cases;
	const aik_json *jcfg;
	const aik_json *jrank;
	const aik_json *jdecay;
	aik_ranking_weights w;
	aik_decay_config dc;
	double reference;
	size_t n_cases;
	size_t i;
	int j;

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

	jcfg = aik_json_get(root, "config");
	jrank = jcfg ? aik_json_get(jcfg, "ranking") : NULL;
	jdecay = jcfg ? aik_json_get(jcfg, "decay") : NULL;

	w.semantic = num_or(jrank, "semantic", 0.40);
	w.importance = num_or(jrank, "importance", 0.12);
	w.freshness = num_or(jrank, "freshness", 0.10);
	w.weight = num_or(jrank, "weight", 0.10);
	w.decay = num_or(jrank, "decay", 0.08);
	w.hit_count = num_or(jrank, "hit_count", 0.08);
	w.recency = num_or(jrank, "recency", 0.06);
	w.region = num_or(jrank, "region", 0.06);

	dc.half_life_days = num_or(jdecay, "half_life_days", 30.0);
	dc.max_weight_decay = num_or(jdecay, "max_weight_decay", 0.85);
	dc.max_importance_decay = num_or(jdecay, "max_importance_decay", 0.85);
	dc.enabled = 1;

	reference = num_or(root, "frozen_now", 0.0);
	cases = aik_json_get(root, "ranker_cases");
	n_cases = aik_json_count(cases);
	if (n_cases == 0) {
		printf("SUMMARY ranker checks=0 mismatches=1\n");
		printf("MISMATCH ranker_cases missing/empty\n");
		aik_json_free(root);
		return 1;
	}

	for (i = 0; i < n_cases; i++) {
		const aik_json *cs = aik_json_at(cases, i);
		const aik_json *in = aik_json_get(cs, "input");
		const aik_json *eb = aik_json_get(cs, "breakdown");
		const char *id = aik_json_str(aik_json_get(cs, "id"));
		const char *name = id && *id ? id : "?";
		aik_memory_view mem;
		aik_rank_result res;
		int detailed;
		int rc;
		static const char *const names[9] = {
			"semantic", "importance", "freshness", "weight",
			"decay", "hit_count", "recency", "region", "final",
		};
		double got[9];
		double exp[9];

		memset(&mem, 0, sizeof(mem));
		memset(&res, 0, sizeof(res));
		mem.id = name;
		mem.text = "";
		mem.source = "parity";
		mem.importance = num_or(in, "importance", 0.0);
		mem.weight = num_or(in, "weight", 0.0);
		mem.freshness = num_or(in, "freshness", 0.0);
		mem.hit_count = (int)aik_json_int(aik_json_get(in, "hit_count"));
		mem.last_hit = num_or(in, "last_hit", 0.0);

		dc.enabled = aik_json_bool(aik_json_get(in, "decay_enabled"));
		detailed = aik_json_bool(aik_json_get(in, "detailed"));

		rc = aik_rank_score(&w, &dc, &mem,
				    num_or(in, "region_score", 0.0), reference, 1,
				    num_or(in, "semantic", 0.0), detailed, &res);
		if (rc != 0) {
			mismatched++;
			snprintf(what, sizeof(what), "rank_cases[%s].rc", name);
			printf("MISMATCH %s rc=%d\n", what, rc);
			continue;
		}

		snprintf(what, sizeof(what), "rank_cases[%s].score", name);
		check_num(what, res.score, num_or(cs, "final", 0.0));

		got[0] = res.breakdown.semantic;
		got[1] = res.breakdown.importance;
		got[2] = res.breakdown.freshness;
		got[3] = res.breakdown.weight;
		got[4] = res.breakdown.decay;
		got[5] = res.breakdown.hit_count;
		got[6] = res.breakdown.recency;
		got[7] = res.breakdown.region;
		got[8] = res.breakdown.final;
		for (j = 0; j < 9; j++) {
			exp[j] = num_or(eb, names[j], 0.0);
			snprintf(what, sizeof(what),
				 "rank_cases[%s].breakdown.%s", name, names[j]);
			check_num(what, got[j], exp[j]);
		}

		/* detailed=0：信号字段必须精确为 0（只写 final） */
		if (!detailed) {
			for (j = 0; j < 8; j++) {
				snprintf(what, sizeof(what),
					 "rank_cases[%s].breakdown.%s.zero",
					 name, names[j]);
				check_exact(what, got[j], 0.0);
			}
		}
	}

	run_round_cases();

	aik_json_free(root);
	printf("SUMMARY ranker checks=%zu mismatches=%zu\n", checked,
	       mismatched);
	return mismatched ? 1 : 0;
}
