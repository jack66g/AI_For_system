/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_dynamics.c - T4e-E1-B consolidation / compression 差分测试
 *
 * 数据（$AIK_PARITY_VECTORS，默认 $HOME/aikernel-longterm/parity/vectors）：
 *   dynamics/dynamics.vectors.json（or $AIK_DYNAMICS_VECTORS 指定的同 schema 文件）
 *   storage/engine.json.gz + storage/engine.embeddings.npz
 *
 * 期望值来源：向量自带的 before / consolidate.after / compress.after /
 * idempotent 段（缺失的键回退上一阶段；idempotent 缺失时按设计稿 0/0 与
 * 上一阶段计数）。$AIK_DYNAMICS_DUMP=<dir> 会把本次 created JSON 落盘供
 * 人工比对。
 *
 * 已知契约缺陷（见 ~/aikernel-longterm/T4E-E1-B.md）：参考实现
 * sme/models.py:147 的 Region.member_ids 是 set，加载后迭代顺序取决于
 * CPython 字符串哈希（每进程随机），因此冻结向量里的 children 顺序与部分
 * 分组本身不可复现；C 侧按快照/排序后的成员序确定执行。严格比对冻结向量
 * 会有失配，属预期。
 *
 * 流程：
 *   1. 临时目录复制快照，NPZ 按快照 embedding_file 改名后 aik_engine_load
 *      （默认配置 + 冻结时钟 vectors.now + 确定性 id 生成器）；
 *   2. 断言 before：549 memories / 226 regions / merges=8；
 *   3. aik_engine_consolidate → created 数 = 20，逐条比对
 *      dynamics.vectors.json 的 consolidate.created：
 *        text/summary/tags/source/importance/created_at/last_hit/version/
 *        freshness/weight/hit_count/decay_factor/archived 精确；
 *        children_texts 保序、neighbors 保序；
 *        metadata.covers 按文本多重集、consolidated_at 精确、ns 存在性；
 *        嵌入只比维度（hashing 逐位一致，见 T4E-E1-B.md）；
 *      再断言 after：569 memories / 226 regions / consolidations=20；
 *   4. aik_engine_compress → created 数 = 10，同法比对 compress.created
 *      （额外比 compresses_region / compressed_at / cover_count）；
 *      断言 579 memories / compressions=10 / merges 不变；
 *   5. 二次调用幂等：consolidate → 0、compress → 0；
 *   6. 空库边界：新引擎空库调用两 API → 0，不崩溃；
 *   7. --negate：把期望值故意改错（字符串加 "!"、数字 +1），必须产生
 *      失配并以非 0 退出（证明比较器真的在比）。
 *
 * 末行 "test_dynamics: N checks, M failed"；有失配退出码 1。
 */
#define _POSIX_C_SOURCE 200809L

#include "../../include/engine/engine.h"
#include "../../include/store/store_json.h"
#include "../../include/store/store_snapshot.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static size_t checks;
static size_t mismatches;
static int g_negate;

/* ------------------------------------------------------------------ */
/* 基础工具                                                           */
/* ------------------------------------------------------------------ */
static void die(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "test_dynamics: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}

/* 负向对照：故意把期望改错（正常运行不生效） */
static const char *exp_str(const char *s)
{
	static char buf[16384];

	if (!g_negate)
		return s;
	snprintf(buf, sizeof(buf), "%s!", s ? s : "");
	return buf;
}

static double exp_num(double v)
{
	return g_negate ? v + 1.0 : v;
}

static void check_int(const char *path, long long got, long long exp)
{
	checks++;
	if (got != exp) {
		mismatches++;
		printf("MISMATCH %s: got %lld expected %lld\n", path, got, exp);
	}
}

static void check_num(const char *path, double got, double exp)
{
	checks++;
	if (!(got == exp)) {
		mismatches++;
		printf("MISMATCH %s: got %.17g expected %.17g\n", path, got,
		       exp);
	}
}

static void check_str(const char *path, const char *got, const char *exp)
{
	checks++;
	if (!got)
		got = "(null)";
	if (!exp)
		exp = "(null)";
	if (strcmp(got, exp) != 0) {
		mismatches++;
		printf("MISMATCH %s: got '%s' expected '%s'\n", path, got, exp);
	}
}

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

static char *make_tmpdir(void)
{
	const char *base = getenv("TMPDIR");
	char tmpl[1024];
	char *p;

	snprintf(tmpl, sizeof(tmpl), "%s/aik-dynamics-XXXXXX",
		 base && *base ? base : "/tmp");
	p = mkdtemp(tmpl);
	if (!p)
		die("mkdtemp failed");
	return strdup(p);
}

static int copy_file(const char *src, const char *dst)
{
	FILE *in = fopen(src, "rb");
	FILE *out;
	char buf[65536];
	size_t n;

	if (!in) {
		fprintf(stderr, "cannot open %s\n", src);
		return -1;
	}
	out = fopen(dst, "wb");
	if (!out) {
		fclose(in);
		fprintf(stderr, "cannot create %s\n", dst);
		return -1;
	}
	while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
		if (fwrite(buf, 1, n, out) != n) {
			fclose(in);
			fclose(out);
			return -1;
		}
	}
	fclose(in);
	return fclose(out) == 0 ? 0 : -1;
}

static aik_json *load_json(const char *path)
{
	FILE *f = fopen(path, "rb");
	long len;
	char *buf;
	aik_json *v;
	char err[512];

	if (!f)
		die("cannot open %s", path);
	if (fseek(f, 0, SEEK_END) != 0)
		die("fseek %s", path);
	len = ftell(f);
	if (len < 0)
		die("ftell %s", path);
	rewind(f);
	buf = malloc((size_t)len + 1);
	if (!buf)
		die("out of memory reading %s", path);
	if (fread(buf, 1, (size_t)len, f) != (size_t)len)
		die("short read %s", path);
	fclose(f);
	buf[len] = '\0';
	v = aik_json_parse(buf, (size_t)len, err, sizeof(err));
	if (!v)
		die("parse %s: %s", path, err);
	free(buf);
	return v;
}

/* JSON 数字（INT/NUM 都读成 double） */
static double jnum(const aik_json *obj, const char *key)
{
	const aik_json *v = aik_json_get(obj, key);

	if (aik_json_typeof(v) == AIK_JSON_INT)
		return (double)aik_json_int(v);
	return aik_json_num(v);
}

static long long jint(const aik_json *obj, const char *key)
{
	const aik_json *v = aik_json_get(obj, key);

	if (aik_json_typeof(v) == AIK_JSON_INT)
		return aik_json_int(v);
	return (long long)aik_json_num(v);
}

/* JSON bool → 0/1（INT 也接受，与 Python 真值一致） */
static long long jbool(const aik_json *obj, const char *key)
{
	const aik_json *v = aik_json_get(obj, key);

	if (aik_json_typeof(v) == AIK_JSON_BOOL)
		return aik_json_bool(v) ? 1 : 0;
	if (aik_json_typeof(v) == AIK_JSON_INT)
		return aik_json_int(v) != 0 ? 1 : 0;
	return 0;
}

static const char *jstr(const aik_json *obj, const char *key)
{
	return aik_json_str(aik_json_get(obj, key));
}

/* 诊断用：$AIK_DYNAMICS_DUMP/<tag>.json 写入创建结果（不设则无副作用） */
static void maybe_dump(const char *tag, const aik_json *v)
{
	const char *dir = getenv("AIK_DYNAMICS_DUMP");
	char *path;
	char *text = NULL;
	size_t len = 0;
	FILE *f;

	if (!dir || !*dir || !v)
		return;
	path = path_join(dir, tag);
	if (!path)
		return;
	{
		char *full = malloc(strlen(path) + 6);

		if (!full) {
			free(path);
			return;
		}
		sprintf(full, "%s.json", path);
		free(path);
		path = full;
	}
	if (aik_json_dump(v, &text, &len) != 0) {
		free(path);
		return;
	}
	f = fopen(path, "wb");
	if (f) {
		if (len > 0)
			fwrite(text, 1, len, f);
		fclose(f);
	}
	free(text);
	free(path);
}

/* ------------------------------------------------------------------ */
/* 冻结时钟 / 确定性 id                                               */
/* ------------------------------------------------------------------ */
static double g_now;

static double clock_now(void *ud)
{
	(void)ud;
	return g_now;
}

static unsigned long long g_id_seq = 0x1000;

static int id_gen(void *ud, const char *prefix, char out[16])
{
	(void)ud;
	(void)prefix;
	g_id_seq++;
	/* 15 字节以内；与快照里的 m_* / r_* 不冲突 */
	snprintf(out, 16, "s_%012llx", g_id_seq);
	return 0;
}

/* ------------------------------------------------------------------ */
/* 从 id 取正文                                                       */
/* ------------------------------------------------------------------ */
static const char *text_of(aik_engine *e, const char *id)
{
	aik_memory *m = aik_engine_get(e, id);

	return m && m->text ? m->text : "<missing>";
}

static int cmp_str_ptr(const void *a, const void *b)
{
	const char *const *x = a;
	const char *const *y = b;

	return strcmp(*x, *y);
}

/* ------------------------------------------------------------------ */
/* 比对                                                               */
/* ------------------------------------------------------------------ */
static void check_str_array_in_order(const char *path, aik_engine *e,
				     const aik_json *got,
				     const aik_json *exp_texts)
{
	size_t ng = aik_json_typeof(got) == AIK_JSON_ARR ? aik_json_count(got)
							 : 0;
	size_t ne = aik_json_typeof(exp_texts) == AIK_JSON_ARR
			    ? aik_json_count(exp_texts)
			    : 0;
	size_t i;
	char item[1024];

	check_int(path, (long long)ng, (long long)ne);
	for (i = 0; i < ng && i < ne; i++) {
		const char *id = aik_json_str(aik_json_at(got, i));
		const char *want = aik_json_str(aik_json_at(exp_texts, i));

		snprintf(item, sizeof(item), "%.512s[%zu]", path, i);
		check_str(item, id ? text_of(e, id) : "(null)",
			  exp_str(want));
	}
}

/* metadata.covers 按文本多重集比较（元素是 id，映射成 text 后排序） */
static void check_covers_multiset(const char *path, aik_engine *e,
				  const aik_json *got, const aik_json *exp)
{
	size_t ng = aik_json_typeof(got) == AIK_JSON_ARR ? aik_json_count(got)
							 : 0;
	size_t ne = aik_json_typeof(exp) == AIK_JSON_ARR ? aik_json_count(exp)
							 : 0;
	char **gv = NULL;
	char **ev = NULL;
	size_t i;
	char item[1024];

	check_int(path, (long long)ng, (long long)ne);
	gv = calloc(ng ? ng : 1, sizeof(*gv));
	ev = calloc(ne ? ne : 1, sizeof(*ev));
	if (!gv || !ev)
		die("out of memory (covers)");
	for (i = 0; i < ng; i++) {
		const char *id = aik_json_str(aik_json_at(got, i));

		gv[i] = strdup(id ? text_of(e, id) : "<missing>");
		if (!gv[i])
			die("out of memory (covers)");
	}
	for (i = 0; i < ne; i++) {
		const char *s = aik_json_str(aik_json_at(exp, i));

		ev[i] = strdup(exp_str(s ? s : ""));
		if (!ev[i])
			die("out of memory (covers)");
	}
	qsort(gv, ng, sizeof(*gv), cmp_str_ptr);
	qsort(ev, ne, sizeof(*ev), cmp_str_ptr);
	for (i = 0; i < ng && i < ne; i++) {
		snprintf(item, sizeof(item), "%.512s[%zu]", path, i);
		check_str(item, gv[i], ev[i]);
	}
	for (i = 0; i < ng; i++)
		free(gv[i]);
	for (i = 0; i < ne; i++)
		free(ev[i]);
	free(gv);
	free(ev);
}

static void check_metadata(const char *prefix, aik_engine *e,
			   const aik_json *got, const aik_json *exp)
{
	char path[1024];

	snprintf(path, sizeof(path), "%.512s.covers", prefix);
	check_covers_multiset(path, e, aik_json_get(got, "covers"),
			      aik_json_get(exp, "covers"));

	/* 时间戳精确 */
	if (aik_json_get(exp, "consolidated_at")) {
		snprintf(path, sizeof(path), "%.512s.consolidated_at", prefix);
		check_num(path, jnum(got, "consolidated_at"),
			  exp_num(jnum(exp, "consolidated_at")));
	}
	if (aik_json_get(exp, "compressed_at")) {
		snprintf(path, sizeof(path), "%.512s.compressed_at", prefix);
		check_num(path, jnum(got, "compressed_at"),
			  exp_num(jnum(exp, "compressed_at")));
	}
	if (aik_json_get(exp, "compresses_region")) {
		snprintf(path, sizeof(path), "%.512s.compresses_region", prefix);
		check_str(path, jstr(got, "compresses_region"),
			  exp_str(jstr(exp, "compresses_region")));
	}
	if (aik_json_get(exp, "cover_count")) {
		snprintf(path, sizeof(path), "%.512s.cover_count", prefix);
		check_int(path, jint(got, "cover_count"),
			  (long long)exp_num((double)jint(exp, "cover_count")));
	}
	/* ns 存在性 + 值 */
	{
		const aik_json *en = aik_json_get(exp, "ns");
		const aik_json *gn = aik_json_get(got, "ns");

		snprintf(path, sizeof(path), "%.512s.ns.present", prefix);
		check_int(path, gn ? 1 : 0, en ? 1 : 0);
		if (gn && en) {
			snprintf(path, sizeof(path), "%.512s.ns", prefix);
			check_str(path, aik_json_str(gn),
				  exp_str(aik_json_str(en)));
		}
	}
	/* 不多不少：键数一致 */
	snprintf(path, sizeof(path), "%.512s.keys", prefix);
	check_int(path, (long long)aik_json_count(got),
		  (long long)aik_json_count(exp));
}

static void check_row(const char *prefix, aik_engine *e, const aik_json *got,
		      const aik_json *exp)
{
	char path[1024];
	const aik_json *gtags;
	const aik_json *etags;
	size_t i;

	snprintf(path, sizeof(path), "%.512s.text", prefix);
	check_str(path, jstr(got, "text"), exp_str(jstr(exp, "text")));
	snprintf(path, sizeof(path), "%.512s.summary", prefix);
	check_str(path, jstr(got, "summary"), exp_str(jstr(exp, "summary")));
	snprintf(path, sizeof(path), "%.512s.source", prefix);
	check_str(path, jstr(got, "source"), exp_str(jstr(exp, "source")));

	gtags = aik_json_get(got, "tags");
	etags = aik_json_get(exp, "tags");
	snprintf(path, sizeof(path), "%.512s.tags.count", prefix);
	check_int(path, (long long)aik_json_count(gtags),
		  (long long)aik_json_count(etags));
	for (i = 0; i < aik_json_count(gtags) && i < aik_json_count(etags);
	     i++) {
		snprintf(path, sizeof(path), "%.512s.tags[%zu]", prefix, i);
		check_str(path, aik_json_str(aik_json_at(gtags, i)),
			  exp_str(aik_json_str(aik_json_at(etags, i))));
	}

#define NUM_FIELD(field)                                                     \
	do {                                                                   \
		snprintf(path, sizeof(path), "%.512s." field, prefix);             \
		check_num(path, jnum(got, field), exp_num(jnum(exp, field)));  \
	} while (0)
#define INT_FIELD(field)                                                     \
	do {                                                                   \
		snprintf(path, sizeof(path), "%.512s." field, prefix);             \
		check_int(path, jint(got, field),                              \
			  (long long)exp_num((double)jint(exp, field)));       \
	} while (0)

	NUM_FIELD("created_at");
	NUM_FIELD("last_hit");
	NUM_FIELD("weight");
	NUM_FIELD("importance");
	NUM_FIELD("freshness");
	NUM_FIELD("decay_factor");
	INT_FIELD("hit_count");
	INT_FIELD("version");
	snprintf(path, sizeof(path), "%.512s.archived", prefix);
	check_int(path, jbool(got, "archived"),
		  (long long)exp_num((double)jbool(exp, "archived")));

	snprintf(path, sizeof(path), "%.512s.children", prefix);
	check_str_array_in_order(path, e, aik_json_get(got, "children"),
				 aik_json_get(exp, "children_texts"));
	snprintf(path, sizeof(path), "%.512s.neighbors", prefix);
	check_str_array_in_order(path, e, aik_json_get(got, "neighbors"),
				 aik_json_get(exp, "neighbors"));

	snprintf(path, sizeof(path), "%.512s.metadata", prefix);
	check_metadata(path, e, aik_json_get(got, "metadata"),
		       aik_json_get(exp, "metadata"));

	/* 嵌入只比维度（hashing 同实现，逐位一致未在 C 端复算） */
	{
		const aik_json *emb = aik_json_get(got, "embedding");

		snprintf(path, sizeof(path), "%.512s.embedding_dim", prefix);
		check_int(path,
			  (long long)(aik_json_typeof(emb) == AIK_JSON_ARR
					      ? aik_json_count(emb)
					      : 0),
			  1024);
	}
#undef NUM_FIELD
#undef INT_FIELD
}

static aik_json *jstat(const aik_json *stats, const char *key)
{
	return (aik_json *)aik_json_get(stats, key);
}

static void check_stats(const char *prefix, aik_engine *e, long long memories,
			long long regions, long long splits, long long merges,
			long long cons, long long comp)
{
	aik_json *stats = NULL;
	char err[512];
	char path[1024];

	if (aik_engine_stats(e, &stats, err, sizeof(err)) != 0)
		die("stats: %s", err);
	snprintf(path, sizeof(path), "%.512s.memories", prefix);
	check_int(path, jint(jstat(stats, "memories"), "total"), memories);
	snprintf(path, sizeof(path), "%.512s.regions", prefix);
	check_int(path, jint(jstat(stats, "regions"), "count"), regions);
	snprintf(path, sizeof(path), "%.512s.splits", prefix);
	check_int(path, jint(stats, "splits"), splits);
	snprintf(path, sizeof(path), "%.512s.merges", prefix);
	check_int(path, jint(stats, "merges"), merges);
	snprintf(path, sizeof(path), "%.512s.consolidations", prefix);
	check_int(path, jint(stats, "consolidations"), cons);
	snprintf(path, sizeof(path), "%.512s.compressions", prefix);
	check_int(path, jint(stats, "compressions"), comp);
	aik_json_free(stats);
}

/* 取 spec[key]，缺失时用 fallback 的 key（before 段提供 splits/merges 等） */
static long long spec_int(const aik_json *spec, const aik_json *fallback,
			  const char *key)
{
	if (aik_json_get(spec, key))
		return jint(spec, key);
	if (fallback && aik_json_get(fallback, key))
		return jint(fallback, key);
	return 0;
}

/* 期望来自向量自身的 before/after/idempotent 段（缺失键回退上一阶段） */
static void check_stats_spec(const char *prefix, aik_engine *e,
			     const aik_json *spec, const aik_json *fallback)
{
	check_stats(prefix, e, spec_int(spec, fallback, "memories"),
		    spec_int(spec, fallback, "regions"),
		    spec_int(spec, fallback, "splits"),
		    spec_int(spec, fallback, "merges"),
		    spec_int(spec, fallback, "consolidations"),
		    spec_int(spec, fallback, "compressions"));
}

/* ------------------------------------------------------------------ */
/* 场景                                                               */
/* ------------------------------------------------------------------ */
static void run_dynamics(aik_json *vec)
{
	const char *vdir = vectors_dir();
	char err[1024];
	char *snap_src;
	char *npz_src;
	char *tmpdir;
	char *snap_tmp;
	char *npz_tmp = NULL;
	aik_snapshot snap;
	const char *embedding_file;
	aik_engine *e = NULL;
	aik_json *created = NULL;
	const aik_json *jcons;
	const aik_json *jcomp;
	const aik_json *arr;
	size_t i;
	long long n;

	snap_src = path_join(vdir, "storage/engine.json.gz");
	npz_src = path_join(vdir, "storage/engine.embeddings.npz");
	if (!snap_src || !npz_src)
		die("out of memory");
	tmpdir = make_tmpdir();
	snap_tmp = path_join(tmpdir, "engine.json.gz");
	if (!snap_tmp)
		die("out of memory");
	if (copy_file(snap_src, snap_tmp) != 0)
		die("cannot copy %s", snap_src);

	memset(&snap, 0, sizeof(snap));
	if (aik_snapshot_load(snap_tmp, &snap, err, sizeof(err)) != 0)
		die("snapshot load: %s", err);
	embedding_file = aik_json_str(aik_json_get(snap.root, "embedding_file"));
	if (!embedding_file || !*embedding_file)
		die("snapshot has no embedding_file");
	npz_tmp = path_join(tmpdir, embedding_file);
	if (!npz_tmp)
		die("out of memory");
	aik_snapshot_free(&snap);
	if (copy_file(npz_src, npz_tmp) != 0)
		die("cannot copy %s", npz_src);

	g_now = jnum(vec, "now");
	e = aik_engine_new(NULL, 0, clock_now, NULL, id_gen, NULL, err,
			   sizeof(err));
	if (!e)
		die("aik_engine_new: %s", err);
	if (aik_engine_load(e, snap_tmp, err, sizeof(err)) != 0)
		die("aik_engine_load: %s", err);

	/* before */
	check_stats_spec("before", e, aik_json_get(vec, "before"), NULL);

	/* ---- consolidate ---- */
	created = NULL;
	if (aik_engine_consolidate(e, &created, err, sizeof(err)) != 0)
		die("consolidate: %s", err);
	jcons = aik_json_get(vec, "consolidate");
	arr = aik_json_get(jcons, "created");
	check_int("consolidate.created.count", (long long)aik_json_count(created),
		  (long long)aik_json_count(arr));
	n = (long long)aik_json_count(arr);
	for (i = 0; i < (size_t)n && i < aik_json_count(created); i++) {
		char prefix[64];

		snprintf(prefix, sizeof(prefix), "consolidate.created[%zu]", i);
		check_row(prefix, e, aik_json_at(created, i),
			  aik_json_at(arr, i));
	}
	maybe_dump("consolidate.created", created);
	aik_json_free(created);
	created = NULL;
	check_stats_spec("consolidate.after", e, aik_json_get(jcons, "after"),
			 aik_json_get(vec, "before"));

	/* ---- compress ---- */
	if (aik_engine_compress(e, &created, err, sizeof(err)) != 0)
		die("compress: %s", err);
	jcomp = aik_json_get(vec, "compress");
	arr = aik_json_get(jcomp, "created");
	check_int("compress.created.count", (long long)aik_json_count(created),
		  (long long)aik_json_count(arr));
	n = (long long)aik_json_count(arr);
	for (i = 0; i < (size_t)n && i < aik_json_count(created); i++) {
		char prefix[64];

		snprintf(prefix, sizeof(prefix), "compress.created[%zu]", i);
		check_row(prefix, e, aik_json_at(created, i),
			  aik_json_at(arr, i));
	}
	maybe_dump("compress.created", created);
	aik_json_free(created);
	created = NULL;
	check_stats_spec("compress.after", e, aik_json_get(jcomp, "after"),
			 aik_json_get(vec, "before"));

	/* ---- 幂等：二次调用 ---- */
	if (aik_engine_consolidate(e, &created, err, sizeof(err)) != 0)
		die("consolidate#2: %s", err);
	check_int("idempotent.consolidate.created",
		  (long long)aik_json_count(created),
		  spec_int(aik_json_get(vec, "idempotent"), NULL,
			   "again_consolidate"));
	aik_json_free(created);
	created = NULL;
	if (aik_engine_compress(e, &created, err, sizeof(err)) != 0)
		die("compress#2: %s", err);
	check_int("idempotent.compress.created",
		  (long long)aik_json_count(created),
		  spec_int(aik_json_get(vec, "idempotent"), NULL,
			   "again_compress"));
	aik_json_free(created);
	created = NULL;
	{
		const aik_json *idle = aik_json_get(vec, "idempotent");
		const aik_json *caf = aik_json_get(jcomp, "after");

		if (idle)
			check_stats_spec("idempotent.after", e, idle, caf);
		else
			check_stats_spec("idempotent.after", e, caf,
					 aik_json_get(vec, "before"));
	}

	aik_engine_free(e);
	free(npz_tmp);
	free(snap_tmp);
	free(tmpdir);
	free(npz_src);
	free(snap_src);
}

static void run_empty(void)
{
	char err[512];
	aik_engine *e;
	aik_json *created = NULL;

	e = aik_engine_new(NULL, 0, clock_now, NULL, id_gen, NULL, err,
			   sizeof(err));
	if (!e)
		die("aik_engine_new (empty): %s", err);
	if (aik_engine_consolidate(e, &created, err, sizeof(err)) != 0)
		die("empty consolidate: %s", err);
	check_int("empty.consolidate.created",
		  (long long)aik_json_count(created), 0);
	aik_json_free(created);
	created = NULL;
	if (aik_engine_compress(e, &created, err, sizeof(err)) != 0)
		die("empty compress: %s", err);
	check_int("empty.compress.created", (long long)aik_json_count(created),
		  0);
	aik_json_free(created);
	aik_engine_free(e);
}

int main(int argc, char **argv)
{
	const char *vdir = vectors_dir();
	const char *voverride = getenv("AIK_DYNAMICS_VECTORS");
	char *vec_path;
	aik_json *vec;

	if (argc > 1 && strcmp(argv[1], "--negate") == 0)
		g_negate = 1;
	else if (argc > 1)
		die("unknown argument '%s' (only --negate)", argv[1]);

	if (voverride && *voverride)
		vec_path = strdup(voverride);
	else
		vec_path = path_join(vdir, "dynamics/dynamics.vectors.json");
	if (!vec_path)
		die("out of memory");
	vec = load_json(vec_path);
	run_dynamics(vec);
	run_empty();
	aik_json_free(vec);
	free(vec_path);

	if (g_negate) {
		printf("NEGATIVE CONTROL: mismatches=%zu (must be > 0)\n",
		       mismatches);
		printf("test_dynamics: %zu checks, %zu failed\n", checks,
		       mismatches);
		return mismatches > 0 ? 1 : 0;
	}
	printf("test_dynamics: %zu checks, %zu failed\n", checks, mismatches);
	return mismatches == 0 ? 0 : 1;
}
