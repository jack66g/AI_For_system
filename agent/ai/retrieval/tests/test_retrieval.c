/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_retrieval.c - T3b 两阶段检索向量自测
 *
 * 数据：$AIK_PARITY_VECTORS/retrieval/search.vectors.json（默认
 * $HOME/aikernel-longterm/parity/vectors）。
 *
 *   1. 按 config.region 建 aik_space；按 memories 顺序**全部**插入录制
 *      embedding（含 m21），再对 archived 列表 aik_space_remove 并标记
 *      archived；随后 aik_retriever_index（只索引非 archived）；按 graph
 *      数组顺序建边。
 *   2. 每个 search query：
 *      - config.embedding 参数调用 aik_hash_embed_one 复算 query 向量；
 *      - cfg 覆盖来自 params（top_regions/top_k/fusion/keyword_candidates/
 *        candidate_window/region_dampening），weights/decay 来自 config，
 *        reference=frozen_now，policy 三字段来自 config.policy；
 *      - metadata_filters 解析为 store_json DOM，tags 数组；
 *      - 调 aik_retriever_search，比较 count、同分区间按集合比较命中，
 *        每条比较 score/region_score/keyword_score/vector_score、
 *        breakdown 9 字段（相对 1e-9）、region canonical key、metadata_match。
 *   3. kind=="regions" 的 query 走 aik_space_query_regions，比较 score/
 *      distance（1e-9，同分集合）。
 *   4. AIK_PARITY_DUMP=<path> 时写 TSV：
 *        S <qid> <memory_key> <score> <breakdown.final> <region_score>
 *          <keyword_score> <vector_score>
 *        R <qid> <region_key> <score> <distance>
 *      数字 %.17g，每 hit 一行，按返回顺序。
 *
 * 输出：SUMMARY retrieval checks=N mismatches=M；有失配 exit 1。
 */
#include "../../include/memory/embed_hash.h"
#include "../../include/retrieval/ranker.h"
#include "../../include/retrieval/retriever.h"
#include "../../include/space/space.h"
#include "../../include/store/store_json.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checks;
static size_t mismatches;
static FILE *dump_fp;

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

static int need_bool(const aik_json *obj, const char *key, const char *where)
{
	return aik_json_bool(need(obj, key, where));
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

/* 同分判定（TASK-BOOK §7.1：score 容差 1e-12 归组） */
static int same_score(double a, double b)
{
	double scale = fabs(b) > 1.0 ? fabs(b) : 1.0;

	return fabs(a - b) <= 1e-12 * scale;
}

static void check_num(const char *path, double got, double exp)
{
	checks++;
	if (!close_enough(got, exp)) {
		mismatches++;
		printf("MISMATCH %s got=%.17g exp=%.17g\n", path, got, exp);
	}
}

static void check_int(const char *path, long long got, long long exp)
{
	checks++;
	if (got != exp) {
		mismatches++;
		printf("MISMATCH %s got=%lld exp=%lld\n", path, got, exp);
	}
}

static void check_str(const char *path, const char *got, const char *exp)
{
	checks++;
	if (!got)
		got = "";
	if (!exp)
		exp = "";
	if (strcmp(got, exp) != 0) {
		mismatches++;
		printf("MISMATCH %s got='%s' exp='%s'\n", path, got, exp);
	}
}

static void check_bool(const char *path, int got, int exp)
{
	checks++;
	if ((got != 0) != (exp != 0)) {
		mismatches++;
		printf("MISMATCH %s got=%d exp=%d\n", path, got, exp);
	}
}

static int cmp_str(const void *pa, const void *pb)
{
	const char *const *a = pa;
	const char *const *b = pb;

	return strcmp(*a ? *a : "", *b ? *b : "");
}

/*
 * 把 region id 映射成 canonical key：成员 memory_id 升序以 '+' 连接。
 * region_id 为空 -> ""（Python key_of_region(None) -> None）。
 */
static void canonical_region(const aik_space *sp, const char *rid, char *buf,
			     size_t buflen)
{
	const aik_region *reg;
	const char **members;
	size_t n;
	size_t i;
	size_t off = 0;

	if (!rid || !rid[0]) {
		if (buflen)
			buf[0] = '\0';
		return;
	}
	reg = aik_space_region(sp, rid);
	if (!reg) {
		snprintf(buf, buflen, "<deleted>");
		return;
	}
	n = aik_region_size(reg);
	if (n == 0) {
		if (buflen)
			buf[0] = '\0';
		return;
	}
	members = malloc(n * sizeof(*members));
	if (!members)
		die("out of memory");
	for (i = 0; i < n; i++)
		members[i] = aik_region_member(reg, i);
	qsort(members, n, sizeof(*members), cmp_str);
	if (buflen)
		buf[0] = '\0';
	for (i = 0; i < n; i++) {
		int wrote;

		if (!members[i])
			continue;
		wrote = snprintf(buf + off, buflen > off ? buflen - off : 0,
				 "%s%s", off > 0 ? "+" : "", members[i]);
		if (wrote < 0)
			break;
		off += (size_t)wrote;
		if (off >= buflen)
			break;
	}
	free(members);
}

/* ------------------------------------------------------------------ */
/* 记忆 / 配置装载                                                     */
/* ------------------------------------------------------------------ */
struct mem_rec {
	aik_memory_view view;
	double *embedding;
	const char **tags;
};

static void free_memories(struct mem_rec *mems, size_t n)
{
	size_t i;
	size_t j;

	if (!mems)
		return;
	for (i = 0; i < n; i++) {
		free(mems[i].embedding);
		if (mems[i].tags) {
			for (j = 0; j < mems[i].view.n_tags; j++)
				free((void *)mems[i].tags[j]);
		}
		free(mems[i].tags);
	}
	free(mems);
}

/* ------------------------------------------------------------------ */
/* 结果比较                                                            */
/* ------------------------------------------------------------------ */
/*
 * 同分跨 top-k 截断时 Python 用 set 迭代序选人（UUID 随机），C 用
 * (score desc, memory_id asc)。允许差异的前提是两条记录除 memory_id
 * 以外逐字段等价（例如 m23/m24 这种完全相同的孪生记忆）。只要任一
 * 字段不同，仍然按 key set mismatch 报错。
 */
static int hit_record_matches(const aik_json *item, const aik_search_hit *h,
			      aik_space *sp, const char *qid)
{
	const aik_json *bd = need(item, "breakdown", qid);
	const aik_json *rk = need(item, "region_key", qid);
	const char *exp_region =
		aik_json_typeof(rk) == AIK_JSON_NULL ? "" : aik_json_str(rk);
	char rbuf[4096];

	canonical_region(sp, h->region_id, rbuf, sizeof(rbuf));
	if (!exp_region)
		exp_region = "";
	return close_enough(h->score, need_num(item, "score", qid)) &&
	       close_enough(h->region_score,
			    need_num(item, "region_score", qid)) &&
	       close_enough(h->keyword_score,
			    need_num(item, "keyword_score", qid)) &&
	       close_enough(h->vector_score,
			    need_num(item, "vector_score", qid)) &&
	       (h->metadata_match != 0) ==
		       (need_bool(item, "metadata_match", qid) != 0) &&
	       strcmp(rbuf, exp_region) == 0 &&
	       close_enough(h->breakdown.semantic,
			    need_num(bd, "semantic", qid)) &&
	       close_enough(h->breakdown.importance,
			    need_num(bd, "importance", qid)) &&
	       close_enough(h->breakdown.freshness,
			    need_num(bd, "freshness", qid)) &&
	       close_enough(h->breakdown.weight,
			    need_num(bd, "weight", qid)) &&
	       close_enough(h->breakdown.decay,
			    need_num(bd, "decay", qid)) &&
	       close_enough(h->breakdown.hit_count,
			    need_num(bd, "hit_count", qid)) &&
	       close_enough(h->breakdown.recency,
			    need_num(bd, "recency", qid)) &&
	       close_enough(h->breakdown.region,
			    need_num(bd, "region", qid)) &&
	       close_enough(h->breakdown.final,
			    need_num(bd, "final", qid));
}

static void compare_search_group(const char *qid, const aik_json *exp_arr,
				 size_t start, size_t len,
				 const aik_search_hit *got, size_t got_start,
				 size_t n_got, aik_space *sp)
{
	char **ek;
	char **gk;
	unsigned char *used;
	size_t i;
	size_t k;
	char path[512];
	const char *ekey;
	char rbuf[4096];

	if (got_start + len > n_got) {
		checks++;
		mismatches++;
		printf("MISMATCH queries[%s].results.tie-group: got %zu of %zu "
		       "entries\n", qid, n_got - got_start, len);
		return;
	}
	ek = malloc(len * sizeof(*ek));
	gk = malloc(len * sizeof(*gk));
	used = calloc(len, 1);
	if (!ek || !gk || !used)
		die("out of memory");
	for (i = 0; i < len; i++) {
		const aik_json *item = at(exp_arr, start + i, qid);

		ekey = aik_json_str(need(item, "memory", qid));
		ek[i] = (char *)(ekey ? ekey : "");
		gk[i] = got[got_start + i].memory_id;
	}
	size_t *pair;
	int keyset_ok = 1;

	qsort(ek, len, sizeof(*ek), cmp_str);
	qsort(gk, len, sizeof(*gk), cmp_str);
	checks++;
	for (i = 0; i < len; i++)
		if (strcmp(ek[i], gk[i]) != 0) {
			keyset_ok = 0;
			break;
		}
	pair = malloc(len * sizeof(*pair));
	if (!pair)
		die("out of memory");
	for (i = 0; i < len; i++)
		pair[i] = (size_t)-1;
	/* 先按 memory key 配对 */
	for (i = 0; i < len; i++) {
		const char *want_key =
			aik_json_str(need(at(exp_arr, start + i, qid),
					  "memory", qid));

		if (!want_key)
			want_key = "";
		for (k = 0; k < len; k++) {
			if (used[k])
				continue;
			if (strcmp(got[got_start + k].memory_id,
				   want_key) == 0) {
				pair[i] = k;
				used[k] = 1;
				break;
			}
		}
	}
	/* key set 不同：仅当未配对条目与同分未用条目逐字段等价时放行 */
	if (!keyset_ok) {
		int ok = 1;

		for (i = 0; i < len && ok; i++) {
			const aik_json *item;

			if (pair[i] != (size_t)-1)
				continue;
			item = at(exp_arr, start + i, qid);
			ok = 0;
			for (k = 0; k < len; k++) {
				if (used[k])
					continue;
				if (hit_record_matches(item,
						       &got[got_start + k], sp,
						       qid)) {
					pair[i] = k;
					used[k] = 1;
					ok = 1;
					break;
				}
			}
		}
		if (!ok) {
			mismatches++;
			printf("MISMATCH queries[%s].results.tie-group: key set "
			       "differs\n", qid);
		}
	}
	for (i = 0; i < len; i++) {
		const aik_json *item = at(exp_arr, start + i, qid);
		const aik_json *bd;
		const char *want_key = aik_json_str(need(item, "memory", qid));
		const aik_json *rk;
		const aik_search_hit *h = pair[i] == (size_t)-1 ?
						  NULL :
						  &got[got_start + pair[i]];

		if (!want_key)
			want_key = "";
		if (!h)
			continue;
		snprintf(path, sizeof(path), "queries[%s].results[%s].score",
			 qid, want_key);
		check_num(path, h->score, need_num(item, "score", qid));
		snprintf(path, sizeof(path),
			 "queries[%s].results[%s].region_score", qid, want_key);
		check_num(path, h->region_score,
			  need_num(item, "region_score", qid));
		snprintf(path, sizeof(path),
			 "queries[%s].results[%s].keyword_score", qid, want_key);
		check_num(path, h->keyword_score,
			  need_num(item, "keyword_score", qid));
		snprintf(path, sizeof(path),
			 "queries[%s].results[%s].vector_score", qid, want_key);
		check_num(path, h->vector_score,
			  need_num(item, "vector_score", qid));
		snprintf(path, sizeof(path),
			 "queries[%s].results[%s].metadata_match", qid,
			 want_key);
		check_bool(path, h->metadata_match,
			   need_bool(item, "metadata_match", qid));
		rk = need(item, "region_key", qid);
		canonical_region(sp, h->region_id, rbuf, sizeof(rbuf));
		snprintf(path, sizeof(path),
			 "queries[%s].results[%s].region_key", qid, want_key);
		check_str(path, rbuf,
			  aik_json_typeof(rk) == AIK_JSON_NULL ?
				  "" :
				  aik_json_str(rk));
		bd = need(item, "breakdown", qid);
		snprintf(path, sizeof(path),
			 "queries[%s].results[%s].breakdown.semantic", qid,
			 want_key);
		check_num(path, h->breakdown.semantic,
			  need_num(bd, "semantic", qid));
		snprintf(path, sizeof(path),
			 "queries[%s].results[%s].breakdown.importance", qid,
			 want_key);
		check_num(path, h->breakdown.importance,
			  need_num(bd, "importance", qid));
		snprintf(path, sizeof(path),
			 "queries[%s].results[%s].breakdown.freshness", qid,
			 want_key);
		check_num(path, h->breakdown.freshness,
			  need_num(bd, "freshness", qid));
		snprintf(path, sizeof(path),
			 "queries[%s].results[%s].breakdown.weight", qid,
			 want_key);
		check_num(path, h->breakdown.weight,
			  need_num(bd, "weight", qid));
		snprintf(path, sizeof(path),
			 "queries[%s].results[%s].breakdown.decay", qid,
			 want_key);
		check_num(path, h->breakdown.decay,
			  need_num(bd, "decay", qid));
		snprintf(path, sizeof(path),
			 "queries[%s].results[%s].breakdown.hit_count", qid,
			 want_key);
		check_num(path, h->breakdown.hit_count,
			  need_num(bd, "hit_count", qid));
		snprintf(path, sizeof(path),
			 "queries[%s].results[%s].breakdown.recency", qid,
			 want_key);
		check_num(path, h->breakdown.recency,
			  need_num(bd, "recency", qid));
		snprintf(path, sizeof(path),
			 "queries[%s].results[%s].breakdown.region", qid,
			 want_key);
		check_num(path, h->breakdown.region,
			  need_num(bd, "region", qid));
		snprintf(path, sizeof(path),
			 "queries[%s].results[%s].breakdown.final", qid,
			 want_key);
		check_num(path, h->breakdown.final,
			  need_num(bd, "final", qid));
	}
	free(pair);
	free(ek);
	free(gk);
	free(used);
}

static void compare_search_results(const char *qid, const aik_json *exp_arr,
				   const aik_search_hit *got, size_t n_got,
				   aik_space *sp)
{
	size_t n_exp = aik_json_count(exp_arr);
	size_t i = 0;
	size_t j = 0;
	char path[256];

	snprintf(path, sizeof(path), "queries[%s].count", qid);
	check_int(path, (long long)n_got, (long long)n_exp);
	while (i < n_exp) {
		double base = need_num(at(exp_arr, i, qid), "score", qid);
		size_t end = i + 1;

		while (end < n_exp &&
		       same_score(need_num(at(exp_arr, end, qid), "score", qid),
				  base))
			end++;
		compare_search_group(qid, exp_arr, i, end - i, got, j, n_got,
				     sp);
		j += end - i;
		i = end;
	}
	if (j != n_got) {
		checks++;
		mismatches++;
		printf("MISMATCH queries[%s].results.extra: %zu unexpected "
		       "entries\n", qid, n_got - (j < n_got ? j : n_got));
	}
}

static void dump_search(const char *qid, const aik_search_hit *hits,
			size_t n)
{
	size_t i;

	if (!dump_fp)
		return;
	for (i = 0; i < n; i++)
		fprintf(dump_fp, "S\t%s\t%s\t%.17g\t%.17g\t%.17g\t%.17g\t%.17g\n",
			qid, hits[i].memory_id ? hits[i].memory_id : "",
			hits[i].score, hits[i].breakdown.final,
			hits[i].region_score, hits[i].keyword_score,
			hits[i].vector_score);
}

static void compare_region_results(const char *qid, const aik_json *exp_arr,
				   const aik_region_hit *got, size_t n_got,
				   const aik_space *sp)
{
	size_t n_exp = aik_json_count(exp_arr);
	size_t i = 0;
	size_t j = 0;
	char path[256];

	snprintf(path, sizeof(path), "queries[%s].count", qid);
	check_int(path, (long long)n_got, (long long)n_exp);
	while (i < n_exp) {
		double base = need_num(at(exp_arr, i, qid), "score", qid);
		size_t end = i + 1;
		size_t len;
		char **ek;
		char **gk;
		unsigned char *used;
		size_t k;

		while (end < n_exp &&
		       same_score(need_num(at(exp_arr, end, qid), "score", qid),
				  base))
			end++;
		len = end - i;
		if (j + len > n_got) {
			checks++;
			mismatches++;
			printf("MISMATCH queries[%s].results.tie-group: got %zu "
			       "of %zu entries\n", qid, n_got - j, len);
			j += len;
			i = end;
			continue;
		}
		ek = malloc(len * sizeof(*ek));
		gk = malloc(len * sizeof(*gk));
		used = calloc(len, 1);
		if (!ek || !gk || !used)
			die("out of memory");
		for (k = 0; k < len; k++) {
			const aik_json *item = at(exp_arr, i + k, qid);
			const char *s = aik_json_str(need(item, "region", qid));

			ek[k] = (char *)(s ? s : "");
			gk[k] = malloc(4096);
			if (!gk[k])
				die("out of memory");
			canonical_region(sp, aik_region_id(got[j + k].region),
					 gk[k], 4096);
		}
		{
			char **sorted_ek = malloc(len * sizeof(*sorted_ek));
			char **sorted_gk = malloc(len * sizeof(*sorted_gk));

			if (!sorted_ek || !sorted_gk)
				die("out of memory");
			for (k = 0; k < len; k++) {
				sorted_ek[k] = ek[k];
				sorted_gk[k] = gk[k];
			}
			qsort(sorted_ek, len, sizeof(*sorted_ek), cmp_str);
			qsort(sorted_gk, len, sizeof(*sorted_gk), cmp_str);
			checks++;
			for (k = 0; k < len; k++) {
				if (strcmp(sorted_ek[k], sorted_gk[k]) != 0) {
					mismatches++;
					printf("MISMATCH queries[%s].results."
					       "tie-group: key set differs\n",
					       qid);
					break;
				}
			}
			free(sorted_ek);
			free(sorted_gk);
		}
		for (k = 0; k < len; k++) {
			const aik_json *item = at(exp_arr, i + k, qid);
			const char *want = aik_json_str(need(item, "region", qid));
			size_t m;
			size_t idx = (size_t)-1;

			if (!want)
				want = "";
			for (m = 0; m < len; m++) {
				if (used[m])
					continue;
				if (strcmp(gk[m], want) == 0) {
					idx = m;
					used[m] = 1;
					break;
				}
			}
			if (idx == (size_t)-1)
				continue;
			snprintf(path, sizeof(path),
				 "queries[%s].results[%s].score", qid, want);
			check_num(path, got[j + idx].score,
				  need_num(item, "score", qid));
			snprintf(path, sizeof(path),
				 "queries[%s].results[%s].distance", qid, want);
			check_num(path, got[j + idx].distance,
				  need_num(item, "distance", qid));
		}
		for (k = 0; k < len; k++)
			free(gk[k]);
		free(ek);
		free(gk);
		free(used);
		j += len;
		i = end;
	}
	if (j != n_got) {
		checks++;
		mismatches++;
		printf("MISMATCH queries[%s].results.extra: %zu unexpected "
		       "entries\n", qid,
		       n_got - (j < n_got ? j : n_got));
	}
}

static void dump_regions(const char *qid, const aik_space *sp,
			 const aik_region_hit *hits, size_t n)
{
	size_t i;
	char key[4096];

	if (!dump_fp)
		return;
	for (i = 0; i < n; i++) {
		canonical_region(sp, aik_region_id(hits[i].region), key,
				 sizeof(key));
		fprintf(dump_fp, "R\t%s\t%s\t%.17g\t%.17g\n", qid, key,
			hits[i].score, hits[i].distance);
	}
}

/* ------------------------------------------------------------------ */
/* 合成回归：archived 节点不得中继图扩展                                */
/* ------------------------------------------------------------------ */
/*
 * 向量集无法区分该行为（archived 桥对端在 PPR 子图里孤立、ppr=0），
 * 因此单独构造最小用例：
 *   - S(active) 是唯一 direct hit；B(archived) 是 S 与 T 的唯一桥；
 *   - T(active) 故意不给 memory embedding：REF-PY 的全局补池要求
 *     m.embedding is not None，因此 T 不会成为直接候选，只能经图扩展
 *     出现（T 在 space 里仍有正交向量，保证与 S 分属不同 Region）；
 *   - 正确语义：BFS 到 B 即止（B 只进 seen），T 永不出现；若 archived
 *     分支把 B 放进 frontier，T 会在 depth=2 被拉进结果。
 */
static void run_synthetic_relay_test(void)
{
	enum { DIM = 4 };
	aik_region_config rcfg;
	aik_retrieval_config cfg;
	aik_ranking_weights weights;
	aik_decay_config decay;
	aik_memory_view mems[3];
	aik_graph_edge edges[2];
	aik_space *space;
	aik_retriever *retr;
	aik_search_query q;
	aik_search_ctx ctx;
	aik_search_hit *hits = NULL;
	size_t n_hits = 0;
	double svec[DIM] = {1.0, 0.0, 0.0, 0.0};
	double bvec[DIM] = {0.0, 0.0, 1.0, 0.0};
	double tvec[DIM] = {0.0, 1.0, 0.0, 0.0};
	double qvec[DIM] = {1.0, 0.0, 0.0, 0.0};
	char err[256];
	size_t i;
	int t_surfaced = 0;

	memset(err, 0, sizeof(err));
	memset(mems, 0, sizeof(mems));
	mems[0].id = "synthetic-seed";
	mems[0].text = "synthetic relay seed";
	mems[0].importance = 0.80;
	mems[0].weight = 1.0;
	mems[0].freshness = 1.0;
	mems[0].hit_count = 0;
	mems[0].last_hit = 1000000.0;
	mems[0].source = "user";
	mems[0].archived = 0;
	mems[0].embedding = svec;
	mems[0].dim = DIM;

	mems[1].id = "synthetic-bridge";
	mems[1].text = "synthetic archived bridge";
	mems[1].importance = 0.80;
	mems[1].weight = 1.0;
	mems[1].freshness = 1.0;
	mems[1].hit_count = 0;
	mems[1].last_hit = 1000000.0;
	mems[1].source = "user";
	mems[1].archived = 1;
	mems[1].embedding = bvec;
	mems[1].dim = DIM;

	mems[2].id = "synthetic-target";
	mems[2].text = "synthetic target only";
	mems[2].importance = 0.80;
	mems[2].weight = 1.0;
	mems[2].freshness = 1.0;
	mems[2].hit_count = 0;
	mems[2].last_hit = 1000000.0;
	mems[2].source = "user";
	mems[2].archived = 0;
	/* 无 memory embedding：不被全局补池召回，只能经图扩展出现 */
	mems[2].embedding = NULL;
	mems[2].dim = DIM;

	rcfg.min_region_size = 3;
	rcfg.min_join_cosine = 0.70;
	rcfg.split_threshold = 48;
	rcfg.max_density = 120.0;
	rcfg.merge_distance = 0.12;
	rcfg.neighbor_factor = 1.8;
	rcfg.auto_evolve = 0;
	rcfg.evolve_interval = 40;

	space = aik_space_new(&rcfg, DIM, err, sizeof(err));
	if (!space)
		die("synthetic: aik_space_new: %s", err);
	/* 小 space 只含 S 与 T；两者正交 -> 各自成 Region */
	if (aik_space_insert(space, mems[0].id, svec, err, sizeof(err)) != 0)
		die("synthetic: insert S: %s", err);
	if (aik_space_insert(space, mems[2].id, tvec, err, sizeof(err)) != 0)
		die("synthetic: insert T: %s", err);

	memset(&cfg, 0, sizeof(cfg));
	cfg.top_regions = 1;
	cfg.top_k = 2;
	cfg.vector_weight = 0.60;
	cfg.keyword_weight = 0.30;
	cfg.metadata_weight = 0.10;
	cfg.region_dampening = 0.10;
	cfg.summary_penalty = 0.5;
	cfg.cjk_bigram = 1;
	cfg.candidate_window = 20;
	cfg.fusion = AIK_FUSION_MINMAX;
	cfg.keyword_candidates = 0;

	memset(&weights, 0, sizeof(weights));
	weights.semantic = 0.40;
	weights.importance = 0.12;
	weights.freshness = 0.10;
	weights.weight = 0.10;
	weights.decay = 0.08;
	weights.hit_count = 0.08;
	weights.recency = 0.06;
	weights.region = 0.06;

	memset(&decay, 0, sizeof(decay));
	decay.half_life_days = 30.0;
	decay.max_weight_decay = 0.85;
	decay.max_importance_decay = 0.85;
	decay.enabled = 1;

	retr = aik_retriever_new(&cfg, err, sizeof(err));
	if (!retr)
		die("synthetic: aik_retriever_new: %s", err);
	if (aik_retriever_index(retr, mems, 3, err, sizeof(err)) != 0)
		die("synthetic: aik_retriever_index: %s", err);

	edges[0].source = mems[0].id;
	edges[0].target = mems[1].id;
	edges[0].kind = "reference";
	edges[0].weight = 1.0;
	edges[1].source = mems[1].id;
	edges[1].target = mems[2].id;
	edges[1].kind = "reference";
	edges[1].weight = 1.0;

	memset(&q, 0, sizeof(q));
	q.text = "synthetic relay seed";
	q.top_k = 2;
	q.top_regions = 1;
	q.region_retrieval = 0;
	q.graph_expand = 2;
	q.include_archived = 0;

	memset(&ctx, 0, sizeof(ctx));
	ctx.space = space;
	ctx.memories = mems;
	ctx.n_memories = 3;
	ctx.edges = edges;
	ctx.n_edges = 2;
	ctx.query_vector = qvec;
	ctx.dim = DIM;
	ctx.cfg = &cfg;
	ctx.weights = &weights;
	ctx.decay = &decay;
	ctx.policy_full_memory = 1;
	ctx.policy_importance_threshold = 0.25;
	ctx.reference = 1000000.0;

	if (aik_retriever_search(retr, &ctx, &q, &hits, &n_hits, err,
				 sizeof(err)) != 0)
		die("synthetic: search: %s", err);

	/* 正确语义：只有 S；T 绝不经 archived B 中继出现 */
	check_int("synthetic.relay.count", (long long)n_hits, 1);
	check_str("synthetic.relay.result0",
		  n_hits > 0 ? hits[0].memory_id : NULL, mems[0].id);
	for (i = 0; i < n_hits; i++)
		if (strcmp(hits[i].memory_id, mems[2].id) == 0)
			t_surfaced = 1;
	check_bool("synthetic.relay.archived_not_relayed", !t_surfaced, 1);
	aik_search_hits_free(hits, n_hits);
	aik_retriever_free(retr);
	aik_space_free(space);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(void)
{
	char path[1100];
	char err[512];
	char *raw;
	size_t rawlen = 0;
	aik_json *root;
	const aik_json *config;
	const aik_json *jcfg;
	const aik_json *memories;
	const aik_json *archived;
	const aik_json *graph;
	const aik_json *queries;
	const aik_json *ranking;
	const aik_json *decay_cfg;
	const aik_json *policy;
	const aik_json *embed;
	struct mem_rec *mems = NULL;
	aik_memory_view *views = NULL;
	size_t n_mems;
	aik_region_config rcfg;
	aik_space *space = NULL;
	aik_retrieval_config base;
	aik_retriever *retriever = NULL;
	aik_ranking_weights weights;
	aik_decay_config decay;
	aik_graph_edge *edges = NULL;
	size_t n_edges = 0;
	aik_hash_params hp;
	const char *dump_path = getenv("AIK_PARITY_DUMP");
	double frozen_now;
	size_t dim;
	size_t i;
	size_t qi;
	int rc = 1;

	snprintf(path, sizeof(path), "%s/retrieval/search.vectors.json",
		 vectors_dir());
	raw = read_file(path, &rawlen);
	if (!raw)
		die("cannot read %s", path);
	root = aik_json_parse(raw, rawlen, err, sizeof(err));
	if (!root)
		die("parse %s: %s", path, err);
	config = need(root, "config", "root");
	jcfg = need(config, "region", "config");
	rcfg.min_region_size = need_int(jcfg, "min_region_size", "region");
	rcfg.min_join_cosine = need_num(jcfg, "min_join_cosine", "region");
	rcfg.split_threshold = need_int(jcfg, "split_threshold", "region");
	rcfg.max_density = need_num(jcfg, "max_density", "region");
	rcfg.merge_distance = need_num(jcfg, "merge_distance", "region");
	rcfg.neighbor_factor = need_num(jcfg, "neighbor_factor", "region");
	rcfg.auto_evolve = need_bool(jcfg, "auto_evolve", "region");
	rcfg.evolve_interval = need_int(jcfg, "evolve_interval", "region");
	embed = need(config, "embedding", "config");
	dim = (size_t)need_int(embed, "dim", "embedding");
	hp.dim = (int)dim;
	hp.factors = need_int(embed, "hash_factors", "embedding");
	hp.window = need_int(embed, "hash_window", "embedding");
	hp.seed = (unsigned long long)need_num(embed, "hash_seed", "embedding");
	hp.normalize_output = need_bool(embed, "normalize", "embedding");
	hp.mrl_dim = need_int(embed, "mrl_dim", "embedding");
	frozen_now = need_num(root, "frozen_now", "root");

	memories = need(root, "memories", "root");
	n_mems = aik_json_count(memories);
	mems = calloc(n_mems ? n_mems : 1, sizeof(*mems));
	if (!mems)
		die("out of memory");
	for (i = 0; i < n_mems; i++) {
		const aik_json *rec = at(memories, i, "memories");
		const aik_json *tags;
		const aik_json *emb;
		size_t n_tags;
		size_t k;
		const char *where = "memory";

		mems[i].view.id = need_str(rec, "key", where);
		mems[i].view.text = need_str(rec, "text", where);
		mems[i].view.metadata = need(rec, "metadata", where);
		mems[i].view.importance = need_num(rec, "importance", where);
		mems[i].view.weight = need_num(rec, "weight", where);
		mems[i].view.freshness = need_num(rec, "freshness", where);
		mems[i].view.hit_count = need_int(rec, "hit_count", where);
		mems[i].view.last_hit = need_num(rec, "last_hit", where);
		mems[i].view.source = need_str(rec, "source", where);
		mems[i].view.archived = need_bool(rec, "archived", where);
		tags = need(rec, "tags", where);
		n_tags = aik_json_count(tags);
		mems[i].tags = calloc(n_tags ? n_tags : 1,
				      sizeof(*mems[i].tags));
		if (!mems[i].tags)
			die("out of memory");
		for (k = 0; k < n_tags; k++) {
			const char *s = arr_str(tags, k, "tags");
			size_t len = strlen(s) + 1;
			char *copy = malloc(len);

			if (!copy)
				die("out of memory");
			memcpy(copy, s, len);
			mems[i].tags[k] = copy;
		}
		mems[i].view.tags = mems[i].tags;
		mems[i].view.n_tags = n_tags;
		emb = need(rec, "embedding", where);
		if (aik_json_count(emb) != dim)
			die("memory %s: embedding dim mismatch", mems[i].view.id);
		mems[i].embedding = malloc(dim * sizeof(*mems[i].embedding));
		if (!mems[i].embedding)
			die("out of memory");
		for (k = 0; k < dim; k++)
			mems[i].embedding[k] = aik_json_num(aik_json_at(emb, k));
		mems[i].view.embedding = mems[i].embedding;
		mems[i].view.dim = (int)dim;
	}

	space = aik_space_new(&rcfg, (int)dim, err, sizeof(err));
	if (!space)
		die("aik_space_new: %s", err);
	for (i = 0; i < n_mems; i++)
		if (aik_space_insert(space, mems[i].view.id,
				     mems[i].embedding, err, sizeof(err)) != 0)
			die("aik_space_insert(%s): %s", mems[i].view.id, err);
	archived = need(root, "archived", "root");
	for (i = 0; i < aik_json_count(archived); i++) {
		const char *key = arr_str(archived, i, "archived");
		size_t k;

		if (aik_space_remove(space, key) != 0)
			die("aik_space_remove(%s) failed", key);
		for (k = 0; k < n_mems; k++)
			if (strcmp(mems[k].view.id, key) == 0)
				mems[k].view.archived = 1;
	}
	/* aik_memory_view 必须是连续数组（ctx->memories 按插入序索引） */
	views = malloc(n_mems ? n_mems * sizeof(*views) : 1);
	if (!views)
		die("out of memory");
	for (i = 0; i < n_mems; i++)
		views[i] = mems[i].view;

	/* 基础 RetrievalConfig：文件 config 中存在的字段 + Python 默认值 */
	memset(&base, 0, sizeof(base));
	base.top_regions = 3;
	base.top_k = 10;
	base.vector_weight = 0.60;
	base.keyword_weight = 0.30;
	base.metadata_weight = 0.10;
	base.region_dampening = 0.10;
	base.summary_penalty = 0.5;
	base.cjk_bigram = 1;
	base.candidate_window = 20;
	base.fusion = AIK_FUSION_MINMAX;
	base.keyword_candidates = 0;
	{
		const aik_json *retr = need(config, "retrieval", "config");

		base.top_regions = need_int(retr, "top_regions", "retrieval");
		base.top_k = need_int(retr, "top_k", "retrieval");
		base.candidate_window =
			need_int(retr, "candidate_window", "retrieval");
		base.keyword_candidates =
			need_int(retr, "keyword_candidates", "retrieval");
		if (strcmp(need_str(retr, "fusion", "retrieval"), "weighted") ==
		    0)
			base.fusion = AIK_FUSION_WEIGHTED;
	}
	retriever = aik_retriever_new(&base, err, sizeof(err));
	if (!retriever)
		die("aik_retriever_new: %s", err);
	if (aik_retriever_index(retriever, views, n_mems, err,
				sizeof(err)) != 0)
		die("aik_retriever_index: %s", err);

	ranking = need(config, "ranking", "config");
	weights.semantic = need_num(ranking, "semantic", "ranking");
	weights.importance = need_num(ranking, "importance", "ranking");
	weights.freshness = need_num(ranking, "freshness", "ranking");
	weights.weight = need_num(ranking, "weight", "ranking");
	weights.decay = need_num(ranking, "decay", "ranking");
	weights.hit_count = need_num(ranking, "hit_count", "ranking");
	weights.recency = need_num(ranking, "recency", "ranking");
	weights.region = need_num(ranking, "region", "ranking");
	decay_cfg = need(config, "decay", "config");
	decay.half_life_days = need_num(decay_cfg, "half_life_days", "decay");
	decay.max_weight_decay =
		need_num(decay_cfg, "max_weight_decay", "decay");
	decay.max_importance_decay =
		need_num(decay_cfg, "max_importance_decay", "decay");
	policy = need(config, "policy", "config");
	decay.enabled = need_bool(policy, "decay_enabled", "policy");

	graph = need(root, "graph", "root");
	n_edges = aik_json_count(graph);
	edges = calloc(n_edges ? n_edges : 1, sizeof(*edges));
	if (!edges)
		die("out of memory");
	for (i = 0; i < n_edges; i++) {
		const aik_json *e = at(graph, i, "graph");

		edges[i].source = need_str(e, "source", "graph");
		edges[i].target = need_str(e, "target", "graph");
		edges[i].kind = need_str(e, "kind", "graph");
		edges[i].weight = need_num(e, "weight", "graph");
	}

	if (dump_path && *dump_path) {
		dump_fp = fopen(dump_path, "w");
		if (!dump_fp)
			die("cannot open dump %s", dump_path);
	}

	queries = need(root, "queries", "root");
	for (qi = 0; qi < aik_json_count(queries); qi++) {
		const aik_json *q = at(queries, qi, "queries");
		const char *qid = need_str(q, "id", "query");
		const char *kind = need_str(q, "kind", "query");
		const char *text = need_str(q, "text", "query");
		double *qv = malloc(dim * sizeof(*qv));
		int got_dim;

		if (!qv)
			die("out of memory");
		got_dim = aik_hash_embed_one(&hp, text, qv, dim, err,
					     sizeof(err));
		if (got_dim != (int)dim)
			die("aik_hash_embed_one(%s): %s", qid, err);
		if (strcmp(kind, "regions") == 0) {
			int top_k = need_int(q, "top_k", qid);
			aik_region_hit *hits = NULL;
			size_t n_hits = 0;

			if (aik_space_query_regions(space, qv, top_k, &hits,
						    &n_hits, err,
						    sizeof(err)) != 0)
				die("query_regions(%s): %s", qid, err);
			compare_region_results(qid, need(q, "results", qid),
					       hits, n_hits, space);
			dump_regions(qid, space, hits, n_hits);
			free(hits);
			free(qv);
			continue;
		}
		{
			const aik_json *params = need(q, "params", qid);
			const aik_json *tv;
			const aik_json *mf;
			const aik_json *tg;
			const aik_json *rr;
			aik_retrieval_config cfg = base;
			aik_search_query sq;
			aik_search_ctx ctx;
			aik_search_hit *hits = NULL;
			size_t n_hits = 0;
			size_t k;
			int rc2;

			tv = aik_json_get(params, "top_regions");
			cfg.top_k = need_int(params, "top_k", qid);
			cfg.keyword_candidates =
				need_int(params, "keyword_candidates", qid);
			cfg.candidate_window =
				need_int(params, "candidate_window", qid);
			cfg.region_dampening =
				need_num(params, "region_dampening", qid);
			cfg.top_regions = tv &&
						  aik_json_typeof(tv) !=
							  AIK_JSON_NULL ?
						 (int)aik_json_int(tv) :
						 base.top_regions;
			if (strcmp(need_str(params, "fusion", qid),
				   "weighted") == 0)
				cfg.fusion = AIK_FUSION_WEIGHTED;
			else
				cfg.fusion = AIK_FUSION_MINMAX;

			memset(&sq, 0, sizeof(sq));
			sq.text = text;
			sq.top_k = cfg.top_k;
			sq.top_regions =
				(tv && aik_json_typeof(tv) != AIK_JSON_NULL) ?
					(int)aik_json_int(tv) :
					-1;
			mf = aik_json_get(params, "metadata_filters");
			if (mf && aik_json_typeof(mf) == AIK_JSON_OBJ)
				sq.metadata_filters = mf;
			tg = aik_json_get(params, "tags");
			if (tg && aik_json_typeof(tg) == AIK_JSON_ARR) {
				size_t n_tags = aik_json_count(tg);
				const char **tags = calloc(
					n_tags ? n_tags : 1, sizeof(*tags));

				if (!tags)
					die("out of memory");
				for (k = 0; k < n_tags; k++)
					tags[k] = arr_str(tg, k, "tags");
				sq.tags = tags;
				sq.n_tags = n_tags;
			} else {
				sq.tags = NULL;
				sq.n_tags = 0;
			}
			rr = aik_json_get(params, "region_retrieval");
			if (rr && aik_json_str(rr)) {
				int n = 0;

				if (sscanf(aik_json_str(rr), "top%d", &n) == 1)
					sq.region_retrieval = n;
			}
			sq.graph_expand = need_int(params, "graph_expand", qid);
			sq.include_archived =
				need_bool(params, "include_archived", qid);

			memset(&ctx, 0, sizeof(ctx));
			ctx.space = space;
			ctx.memories = views;
			ctx.n_memories = n_mems;
			ctx.edges = edges;
			ctx.n_edges = n_edges;
			ctx.query_vector = qv;
			ctx.dim = (int)dim;
			ctx.cfg = &cfg;
			ctx.weights = &weights;
			ctx.decay = &decay;
			ctx.policy_full_memory =
				need_bool(policy, "full_memory", "policy");
			ctx.policy_importance_threshold = need_num(
				policy, "importance_threshold", "policy");
			ctx.reference = frozen_now;

			rc2 = aik_retriever_search(retriever, &ctx, &sq, &hits,
						   &n_hits, err,
						   sizeof(err));
			free((void *)sq.tags);
			if (rc2 != 0)
				die("search(%s): %s", qid, err);
			compare_search_results(qid, need(q, "results", qid),
					       hits, n_hits, space);
			dump_search(qid, hits, n_hits);
			aik_search_hits_free(hits, n_hits);
		}
		free(qv);
	}

	/* 独立合成回归：archived 桥不得中继（不依赖 search.vectors.json） */
	run_synthetic_relay_test();

	printf("SUMMARY retrieval checks=%zu mismatches=%zu\n", checks,
	       mismatches);
	if (dump_fp)
		fclose(dump_fp);
	free(edges);
	aik_retriever_free(retriever);
	aik_space_free(space);
	free(views);
	free_memories(mems, n_mems);
	aik_json_free(root);
	free(raw);
	if (mismatches == 0)
		rc = 0;
	return rc;
}
