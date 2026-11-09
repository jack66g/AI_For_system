/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_space_load.c - T4a 快照状态恢复 + bulk 抑制 + id/时钟钩子自测
 *
 * 用例（数据目录 $AIK_PARITY_VECTORS/storage，默认
 * $HOME/aikernel-longterm/parity/vectors/storage）：
 *
 * 1) 真快照恢复（对齐 sme/engine.py::_load_locked 的空间部分）：
 *    - 临时目录复制 engine.json.gz；按快照 embedding_file（缺省回退
 *      snapshot.meta.json）把 engine.embeddings.npz 复制成该 generation
 *      文件名；aik_snapshot_load + aik_npz_* 读出 549 条记忆的 embedding；
 *    - 跳过 archived（10 条）构造 aik_space_vector[539]；
 *    - 以快照 regions/region_edges 调 aik_space_load_state(dim=1024)，
 *      注入冻结时钟 1767225600.0；
 *    - 与 space_load.expected.json 比较：Region 数 226、id/成员集合/
 *      generation/parent_region/created_at 精确，centroid/radius/density
 *      相对 1e-9；边 1461 条（无向 canonical 对）distance 1e-9；
 *      membership：549 条记忆逐条映射一致（539 条归属、10 条 archived
 *      为 NULL）；write_ops=0；每个 Region 的 last_updated == 注入时钟。
 * 2) bulk：dim=4、auto_evolve=1、evolve_interval=2、split_threshold=2、
 *    max_density=1；bulk on 插 4 条 → 无演化事件；bulk off + 显式
 *    evolution_pass → 出现 split 事件。
 * 3) id_fn：生成器返回 r_00000000000a / ...0b；两个不相似向量建两个
 *    Region 且 id 正确；再插相似向量复用第一个 Region（生成器不再调用）。
 * 4) 时钟：注入 1767225600.0 后新建 Region 的 created_at==last_updated==
 *    该值；换时钟后已有 Region 刷新跟随新时钟且 created_at 不变。
 * 5) 合成剪枝/悬挂边/重载/错误路径；Region JSON 自带与时钟不同的
 *    created_at(111/333) 与 last_updated(999.5)，验证 load 取快照 created_at、
 *    last_updated 用注入时钟。
 *
 * 末行 "SUMMARY space_load checks=N mismatches=M"；有失配退出码非 0 并
 * 打印路径。
 */
#define _POSIX_C_SOURCE 200809L

#include "space/space.h"
#include "store/store_json.h"
#include "store/store_npz.h"
#include "store/store_snapshot.h"

#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static size_t checks;
static size_t mismatches;

/* ------------------------------------------------------------------ */
/* 冻结时钟（T4a clock 注入）                                         */
/* ------------------------------------------------------------------ */
struct clock_state {
	double now;
};

static double frozen_now(void *ud)
{
	return ((const struct clock_state *)ud)->now;
}

/* ------------------------------------------------------------------ */
/* 输入与基础工具                                                     */
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

/* dir + "/" + name（malloc，调用者 free；不设长度上限，避免截断告警） */
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

static double need_num(const aik_json *obj, const char *key, const char *where)
{
	const aik_json *v = need(obj, key, where);
	aik_json_type jt = aik_json_typeof(v);

	if (jt != AIK_JSON_NUM && jt != AIK_JSON_INT)
		die("%s: field '%s' is not a number", where, key);
	return aik_json_num(v);
}

static int need_int(const aik_json *obj, const char *key, const char *where)
{
	return (int)aik_json_int(need(obj, key, where));
}

/* ------------------------------------------------------------------ */
/* 比较                                                               */
/* ------------------------------------------------------------------ */
/* 相对误差 <= 1e-9；|exp|<=1 时退化为绝对误差 1e-9 */
static int close_enough(double got, double exp)
{
	double scale = fabs(exp) > 1.0 ? fabs(exp) : 1.0;

	return fabs(got - exp) <= 1e-9 * scale;
}

static void mismatch(const char *path, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "MISMATCH %s: ", path);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
	mismatches++;
}

static void check_num(const char *path, double got, double exp)
{
	checks++;
	if (!close_enough(got, exp))
		mismatch(path, "got %.17g expected %.17g", got, exp);
}

static void check_exact(const char *path, double got, double exp)
{
	checks++;
	if (got != exp)
		mismatch(path, "got %.17g expected %.17g (exact)", got, exp);
}

static void check_int(const char *path, long long got, long long exp)
{
	checks++;
	if (got != exp)
		mismatch(path, "got %lld expected %lld", got, exp);
}

static void check_str(const char *path, const char *got, const char *exp)
{
	checks++;
	if (!got || !exp || strcmp(got, exp) != 0)
		mismatch(path, "got '%s' expected '%s'", got ? got : "(null)",
			 exp ? exp : "(null)");
}

/* expected 是 JSON 字符串或 null（缺字段按 null） */
static void check_opt_str(const char *path, const char *got,
			  const aik_json *expv)
{
	const char *want = NULL;

	if (expv && aik_json_typeof(expv) != AIK_JSON_NULL) {
		want = aik_json_str(expv);
		if (!want)
			die("%s: expected value is not a string", path);
	}
	checks++;
	if ((!got && !want) || (got && want && strcmp(got, want) == 0))
		return;
	mismatch(path, "got '%s' expected '%s'", got ? got : "(null)",
		 want ? want : "(null)");
}

static int cmp_str_ptr(const void *a, const void *b)
{
	const char *sa = *(const char *const *)a;
	const char *sb = *(const char *const *)b;

	return strcmp(sa, sb);
}

/* 成员集合比较（Python 侧是 set：顺序无关） */
static void check_members(const char *path, const aik_region *r,
			  const aik_json *exp)
{
	size_t n_got = aik_region_size(r);
	size_t n_exp = aik_json_count(exp);
	const char **got;
	const char **want;
	char buf[512];
	size_t i;
	int ok = 1;

	checks++;
	if (n_got != n_exp) {
		mismatch(path, "member count got %zu expected %zu", n_got, n_exp);
		return;
	}
	if (n_exp == 0)
		return;
	got = malloc(n_got * sizeof(*got));
	want = malloc(n_exp * sizeof(*want));
	if (!got || !want)
		die("%s: out of memory", path);
	for (i = 0; i < n_got; i++)
		got[i] = aik_region_member(r, i);
	for (i = 0; i < n_exp; i++)
		want[i] = arr_str(exp, i, "expected region members");
	qsort(got, n_got, sizeof(*got), cmp_str_ptr);
	qsort(want, n_exp, sizeof(*want), cmp_str_ptr);
	for (i = 0; i < n_got; i++) {
		if (strcmp(got[i], want[i]) != 0) {
			snprintf(buf, sizeof(buf),
				 "member[%zu] got '%s' expected '%s'", i,
				 got[i], want[i]);
			mismatch(path, "%s", buf);
			ok = 0;
			break;
		}
	}
	if (!ok) {
		/* 打印缺失/多余项，便于定位（不计入 checks） */
		for (i = 0; i < n_got; i++) {
			size_t j;
			int found = 0;

			for (j = 0; j < n_exp; j++) {
				if (strcmp(got[i], want[j]) == 0) {
					found = 1;
					break;
				}
			}
			if (!found)
				fprintf(stderr, "  extra member '%s'\n", got[i]);
		}
		for (i = 0; i < n_exp; i++) {
			size_t j;
			int found = 0;

			for (j = 0; j < n_got; j++) {
				if (strcmp(want[i], got[j]) == 0) {
					found = 1;
					break;
				}
			}
			if (!found)
				fprintf(stderr, "  missing member '%s'\n",
					want[i]);
		}
	}
	free(got);
	free(want);
}

/* 质心逐维比较，整体算一次 check；失配打印首个超差轴 */
static void check_centroid(const char *path, const aik_region *r,
			   const aik_json *exp, int dim)
{
	const double *got = aik_region_centroid(r);
	size_t n = aik_json_count(exp);
	int bad = -1;
	size_t i;

	checks++;
	if (!got) {
		mismatch(path, "no centroid");
		return;
	}
	if ((int)n != dim) {
		mismatch(path, "expected dim %zu != %d", n, dim);
		return;
	}
	for (i = 0; i < (size_t)dim; i++) {
		double want = aik_json_num(aik_json_at(exp, i));

		if (!close_enough(got[i], want)) {
			bad = (int)i;
			break;
		}
	}
	if (bad >= 0)
		mismatch(path, "axis[%d] got %.17g expected %.17g", bad,
			 got[bad], aik_json_num(aik_json_at(exp, (size_t)bad)));
}

/* ------------------------------------------------------------------ */
/* 无向边 canonical key                                               */
/* ------------------------------------------------------------------ */
typedef struct {
	char *key;
	const char *a;
	const char *b;
	double distance;
} exp_edge;

static char *pair_key(const char *a, const char *b)
{
	const char *lo = strcmp(a, b) <= 0 ? a : b;
	const char *hi = lo == a ? b : a;
	size_t n = strlen(lo) + strlen(hi) + 2;
	char *k = malloc(n);

	if (!k)
		return NULL;
	snprintf(k, n, "%s\x01%s", lo, hi);
	return k;
}

static int cmp_edge_key(const void *x, const void *y)
{
	const exp_edge *e1 = x;
	const exp_edge *e2 = y;

	return strcmp(e1->key, e2->key);
}

static void compare_edges(const aik_space *sp, const aik_json *exp)
{
	size_t n_exp = aik_json_count(exp);
	size_t n_got = aik_space_edge_count(sp);
	exp_edge *table;
	size_t i;
	size_t matched = 0;
	char path[1024];

	table = calloc(n_exp ? n_exp : 1, sizeof(*table));
	if (!table)
		die("out of memory");
	for (i = 0; i < n_exp; i++) {
		const aik_json *e = at(exp, i, "expected.region_edges");

		table[i].a = need_str(e, "source", "expected.region_edges");
		table[i].b = need_str(e, "target", "expected.region_edges");
		table[i].distance =
			need_num(e, "distance", "expected.region_edges");
		table[i].key = pair_key(table[i].a, table[i].b);
		if (!table[i].key)
			die("out of memory");
	}
	qsort(table, n_exp, sizeof(*table), cmp_edge_key);

	check_int("edges.count", (long long)n_got, (long long)n_exp);
	for (i = 0; i < n_got; i++) {
		const char *a;
		const char *b;
		double d;
		exp_edge needle;
		exp_edge *hit;
		char *k;

		if (aik_space_edge_at(sp, i, &a, &b, &d) != 0)
			die("edge_at(%zu) failed", i);
		k = pair_key(a, b);
		if (!k)
			die("out of memory");
		needle.key = k;
		hit = bsearch(&needle, table, n_exp, sizeof(*table),
			      cmp_edge_key);
		if (!hit) {
			snprintf(path, sizeof(path), "edges.got[%zu]", i);
			checks++;
			mismatch(path, "unexpected edge '%s' -- '%s'", a, b);
		} else {
			matched++;
			snprintf(path, sizeof(path), "edges[%s|%s].distance",
				 hit->a, hit->b);
			check_num(path, d, hit->distance);
		}
		free(k);
	}
	check_int("edges.matched", (long long)matched, (long long)n_exp);

	for (i = 0; i < n_exp; i++)
		free(table[i].key);
	free(table);
}

/* ------------------------------------------------------------------ */
/* Region / membership 比较                                           */
/* ------------------------------------------------------------------ */
static void compare_regions(aik_space *sp, const aik_json *exp, int dim)
{
	size_t n_exp = aik_json_count(exp);
	size_t n_got = aik_space_region_count(sp);
	size_t i;
	char path[256];

	check_int("regions.count", (long long)n_got, (long long)n_exp);
	for (i = 0; i < n_exp && i < n_got; i++) {
		const aik_json *er = at(exp, i, "expected.regions");
		const aik_region *r = aik_space_region_at(sp, i);
		const char *eid = need_str(er, "id", "expected.regions");

		/* regions 数组顺序 = Region 插入序 */
		snprintf(path, sizeof(path), "regions[%zu].id", i);
		check_str(path, aik_region_id(r), eid);
		snprintf(path, sizeof(path), "regions[%zu].members", i);
		check_members(path, r, need(er, "members", "expected.regions"));
		snprintf(path, sizeof(path), "regions[%zu].generation", i);
		check_int(path, aik_region_generation(r),
			  need_int(er, "generation", "expected.regions"));
		snprintf(path, sizeof(path), "regions[%zu].parent_region", i);
		check_opt_str(path, aik_region_parent(r),
			      aik_json_get(er, "parent_region"));
		snprintf(path, sizeof(path), "regions[%zu].created_at", i);
		check_exact(path, aik_region_created_at(r),
			    need_num(er, "created_at", "expected.regions"));
		snprintf(path, sizeof(path), "regions[%zu].centroid", i);
		check_centroid(path, r, need(er, "centroid", "expected.regions"),
			       dim);
		snprintf(path, sizeof(path), "regions[%zu].radius", i);
		check_num(path, aik_region_radius(r),
			  need_num(er, "radius", "expected.regions"));
		snprintf(path, sizeof(path), "regions[%zu].density", i);
		check_num(path, aik_region_density(r),
			  need_num(er, "density", "expected.regions"));
	}
}

/*
 * membership：逐条记忆检查（549 条）。archived 记忆不在空间里（NULL），
 * 其余必须与期望 Region id 一致；另外核对期望表条数 = 非 archived 数。
 */
static void compare_membership(aik_space *sp, const aik_json *exp,
			       const char **mem_ids,
			       const unsigned char *archived, size_t n_mem)
{
	size_t non_archived = 0;
	size_t i;

	for (i = 0; i < n_mem; i++)
		if (!archived[i])
			non_archived++;
	check_int("membership.count", (long long)aik_json_count(exp),
		  (long long)non_archived);
	for (i = 0; i < n_mem; i++) {
		const char *got = aik_space_region_for(sp, mem_ids[i]);
		const char *want = NULL;
		char path[256];

		if (!archived[i]) {
			want = aik_json_str(aik_json_get(exp, mem_ids[i]));
			if (!want)
				die("expected.membership: missing '%s'",
				    mem_ids[i]);
		}
		snprintf(path, sizeof(path), "membership[%s]", mem_ids[i]);
		checks++;
		if ((!got && !want) || (got && want && strcmp(got, want) == 0))
			continue;
		mismatch(path, "got '%s' expected '%s'", got ? got : "(null)",
			 want ? want : "(null)");
	}
}

/* ------------------------------------------------------------------ */
/* 临时目录 / 文件复制                                                */
/* ------------------------------------------------------------------ */
static char *make_tmpdir(void)
{
	const char *base = getenv("TMPDIR");
	char tmpl[2048];

	if (!base || !*base)
		base = "/tmp";
	if (snprintf(tmpl, sizeof(tmpl), "%s/aikspaceload.XXXXXX", base) >=
	    (int)sizeof(tmpl))
		return NULL;
	if (!mkdtemp(tmpl))
		return NULL;
	return local_strdup(tmpl);
}

static int copy_file(const char *src, const char *dst)
{
	FILE *in = fopen(src, "rb");
	FILE *out;
	char buf[65536];
	size_t n;

	if (!in)
		return -1;
	out = fopen(dst, "wb");
	if (!out) {
		fclose(in);
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

/* snapshot.meta.json 的 snapshot.embedding_file（快照缺该键时回退） */
static const char *meta_embedding_file(const char *storage)
{
	static char out[512];
	char *path;
	char *buf;
	size_t len = 0;
	aik_json *m;
	const char *s;
	int ok = 0;

	path = path_join(storage, "snapshot.meta.json");
	if (!path)
		return NULL;
	buf = read_file(path, &len);
	free(path);
	if (!buf)
		return NULL;
	m = aik_json_parse(buf, len, NULL, 0);
	free(buf);
	if (!m)
		return NULL;
	s = aik_json_str(aik_json_get(aik_json_get(m, "snapshot"),
				     "embedding_file"));
	if (s && *s && strlen(s) < sizeof(out)) {
		snprintf(out, sizeof(out), "%s", s);
		ok = 1;
	}
	aik_json_free(m);
	return ok ? out : NULL;
}

static int is_archived_id(const char **mem_ids, const unsigned char *archived,
			  size_t n_mem, const char *id)
{
	size_t i;

	for (i = 0; i < n_mem; i++) {
		if (archived[i] && strcmp(mem_ids[i], id) == 0)
			return 1;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* 用例 1：真快照恢复                                                 */
/* ------------------------------------------------------------------ */
static void run_parity(const char *storage)
{
	char *snap_src;
	char *npz_src;
	char *exp_src;
	char *tmpdir;
	char *snap_tmp;
	char *npz_tmp;
	char err[512];
	aik_snapshot snap;
	aik_npz *z = NULL;
	aik_json *expected = NULL;
	const aik_json *root;
	const aik_json *jmem;
	const aik_json *jregions;
	const aik_json *jregion_edges;
	char *exp_buf;
	size_t exp_len = 0;
	unsigned char *ids_buf = NULL;
	unsigned char *mat_buf = NULL;
	size_t ids_len = 0;
	size_t mat_len = 0;
	aik_npy ids_npy;
	aik_npy mat_npy;
	char **vec_ids = NULL;
	double *matrix = NULL;
	aik_space_vector *vectors = NULL;
	const char **mem_ids = NULL;
	unsigned char *archived = NULL;
	size_t n_mem;
	size_t n_ids;
	size_t n_vectors = 0;
	size_t n_archived = 0;
	size_t i;
	int dim;
	const char *embedding_file;
	aik_space *sp;
	struct clock_state clk = { 1767225600.0 };

	snap_src = path_join(storage, "engine.json.gz");
	npz_src = path_join(storage, "engine.embeddings.npz");
	exp_src = path_join(storage, "space_load.expected.json");
	if (!snap_src || !npz_src || !exp_src)
		die("out of memory");

	tmpdir = make_tmpdir();
	if (!tmpdir)
		die("mkdtemp failed");
	snap_tmp = path_join(tmpdir, "engine.json.gz");
	if (!snap_tmp)
		die("out of memory");
	if (copy_file(snap_src, snap_tmp) != 0)
		die("cannot copy %s", snap_src);

	memset(&snap, 0, sizeof(snap));
	if (aik_snapshot_load(snap_tmp, &snap, err, sizeof(err)) != 0)
		die("aik_snapshot_load(%s): %s", snap_tmp, err);
	if (aik_snapshot_validate(&snap, err, sizeof(err)) != 0)
		die("aik_snapshot_validate: %s", err);
	root = snap.root;

	/* 快照的 embedding_file（generation 文件名），缺省读 meta */
	embedding_file = aik_json_str(aik_json_get(root, "embedding_file"));
	if (!embedding_file || !*embedding_file)
		embedding_file = meta_embedding_file(storage);
	if (!embedding_file || !*embedding_file)
		die("snapshot has no embedding_file");
	npz_tmp = path_join(tmpdir, embedding_file);
	if (!npz_tmp)
		die("out of memory");
	if (copy_file(npz_src, npz_tmp) != 0)
		die("cannot copy %s -> %s", npz_src, npz_tmp);

	z = aik_npz_open(npz_tmp, err, sizeof(err));
	if (!z)
		die("aik_npz_open(%s): %s", npz_tmp, err);
	if (aik_npz_read(z, "ids", &ids_buf, &ids_len, err, sizeof(err)) != 0)
		die("npz ids: %s", err);
	if (aik_npz_read(z, "matrix", &mat_buf, &mat_len, err, sizeof(err)) != 0)
		die("npz matrix: %s", err);
	if (aik_npy_parse(ids_buf, ids_len, &ids_npy, err, sizeof(err)) != 0)
		die("npy ids: %s", err);
	if (aik_npy_parse(mat_buf, mat_len, &mat_npy, err, sizeof(err)) != 0)
		die("npy matrix: %s", err);
	n_ids = aik_npy_nelem(&ids_npy);
	if (mat_npy.ndim != 2)
		die("npz matrix is not 2-D");
	if ((size_t)mat_npy.shape[0] != n_ids)
		die("npz ids/matrix rows mismatch: %zu vs %lld", n_ids,
		    mat_npy.shape[0]);
	dim = (int)mat_npy.shape[1];

	/* 期望结果 */
	exp_buf = read_file(exp_src, &exp_len);
	if (!exp_buf)
		die("missing %s", exp_src);
	expected = aik_json_parse(exp_buf, exp_len, err, sizeof(err));
	free(exp_buf);
	if (!expected)
		die("invalid JSON %s: %s", exp_src, err);
	if (need_int(expected, "dim", "expected") != dim)
		die("expected.dim %d != npz dim %d",
		    need_int(expected, "dim", "expected"), dim);
	check_int("npz.dim", dim, need_int(expected, "dim", "expected"));

	/* 记忆 id / archived 位（顺序同快照） */
	jmem = need(root, "memories", "snapshot");
	if (aik_json_typeof(jmem) != AIK_JSON_ARR)
		die("snapshot.memories is not an array");
	n_mem = aik_json_count(jmem);
	mem_ids = calloc(n_mem ? n_mem : 1, sizeof(*mem_ids));
	archived = calloc(n_mem ? n_mem : 1, 1);
	if (!mem_ids || !archived)
		die("out of memory");
	for (i = 0; i < n_mem; i++) {
		const aik_json *m = at(jmem, i, "snapshot.memories");

		mem_ids[i] = need_str(m, "id", "snapshot.memories");
		archived[i] = (unsigned char)aik_json_bool(
			aik_json_get(m, "archived"));
		if (archived[i])
			n_archived++;
	}

	/* 向量矩阵（逐元素拷贝，避免 NPY 数据段对齐问题） */
	matrix = malloc(n_ids * (size_t)dim * sizeof(double));
	vec_ids = calloc(n_ids ? n_ids : 1, sizeof(*vec_ids));
	vectors = calloc(n_ids ? n_ids : 1, sizeof(*vectors));
	if (!matrix || !vec_ids || !vectors)
		die("out of memory");
	for (i = 0; i < n_ids * (size_t)dim; i++) {
		if (aik_npy_get_f8(&mat_npy, i, &matrix[i]) != 0)
			die("npy matrix element %zu unreadable", i);
	}
	for (i = 0; i < n_ids; i++) {
		char name[128];

		if (aik_npy_get_ustr(&ids_npy, i, name, sizeof(name)) < 0)
			die("npy ids element %zu unreadable", i);
		vec_ids[i] = local_strdup(name);
		if (!vec_ids[i])
			die("out of memory");
	}
	check_int("npz.ids.count", (long long)n_ids, (long long)n_mem);
	{
		size_t unknown = 0;
		size_t k;

		for (i = 0; i < n_ids; i++) {
			int found = 0;

			for (k = 0; k < n_mem; k++) {
				if (strcmp(mem_ids[k], vec_ids[i]) == 0) {
					found = 1;
					break;
				}
			}
			if (!found)
				unknown++;
		}
		check_int("npz.ids.unknown", (long long)unknown, 0);
	}
	/* archived 记忆不进入空间（sme/engine.py 的 vectors 过滤） */
	for (i = 0; i < n_ids; i++) {
		if (is_archived_id(mem_ids, archived, n_mem, vec_ids[i]))
			continue;
		vectors[n_vectors].id = vec_ids[i];
		vectors[n_vectors].vector = matrix + i * (size_t)dim;
		vectors[n_vectors].dim = dim;
		n_vectors++;
	}

	check_int("memories.count", (long long)n_mem, 549);
	check_int("vectors.count", (long long)n_vectors,
		  (long long)(n_mem - n_archived));
	check_int("vectors.archived", (long long)n_archived, 10);

	jregions = need(root, "regions", "snapshot");
	jregion_edges = aik_json_get(root, "region_edges");

	sp = aik_space_new(NULL, dim, err, sizeof(err));
	if (!sp)
		die("aik_space_new: %s", err);
	aik_space_set_clock(sp, frozen_now, &clk);
	if (aik_space_load_state(sp, dim, vectors, n_vectors, jregions,
				 jregion_edges, err, sizeof(err)) != 0)
		die("aik_space_load_state: %s", err);

	check_int("space.write_ops", aik_space_write_ops(sp),
		  need_int(expected, "write_ops", "expected"));
	compare_regions(sp, need(expected, "regions", "expected"), dim);
	compare_edges(sp, need(expected, "region_edges", "expected"));
	compare_membership(sp, need(expected, "membership", "expected"),
			   mem_ids, archived, n_mem);
	{
		/*
		 * load 的 last_updated = 注入时钟（Python update_geometry 的
		 * now()），不是快照值；created_at 保持快照值（compare_regions
		 * 已逐条比对）。
		 */
		size_t nreg = aik_space_region_count(sp);

		for (i = 0; i < nreg; i++) {
			const aik_region *r = aik_space_region_at(sp, i);
			char path[128];

			snprintf(path, sizeof(path),
				 "regions[%zu].last_updated", i);
			check_exact(path, aik_region_last_updated(r), clk.now);
		}
	}

	printf("parity: memories=%zu vectors=%zu archived=%zu regions=%zu "
	       "edges=%zu\n",
	       n_mem, n_vectors, n_archived, aik_space_region_count(sp),
	       aik_space_edge_count(sp));

	aik_space_free(sp);
	for (i = 0; i < n_ids; i++)
		free(vec_ids[i]);
	free(vec_ids);
	free(vectors);
	free(matrix);
	free(mem_ids);
	free(archived);
	aik_npz_close(z);
	free(ids_buf);
	free(mat_buf);
	aik_json_free(expected);
	aik_snapshot_free(&snap);
	unlink(snap_tmp);
	unlink(npz_tmp);
	rmdir(tmpdir);
	free(snap_src);
	free(npz_src);
	free(exp_src);
	free(snap_tmp);
	free(npz_tmp);
	free(tmpdir);
}

/* ------------------------------------------------------------------ */
/* 用例 2：bulk 抑制演化                                              */
/* ------------------------------------------------------------------ */
static void run_bulk(void)
{
	aik_region_config cfg;
	aik_space *sp;
	char err[256];
	/* 4 个共线且相邻的点：全部并入同一 Region，密度 > 1 */
	const double vec[4][4] = {
		{ 1.0, 0.0, 0.0, 0.0 },
		{ 1.0, 0.2, 0.0, 0.0 },
		{ 1.0, 0.4, 0.0, 0.0 },
		{ 1.0, 0.6, 0.0, 0.0 },
	};
	const char *ids[4] = { "b1", "b2", "b3", "b4" };
	aik_space_event *events = NULL;
	size_t n_events = 0;
	size_t i;
	int found_split = 0;
	int rc;

	memset(&cfg, 0, sizeof(cfg));
	cfg.min_region_size = 3;
	cfg.min_join_cosine = 0.70;
	cfg.split_threshold = 2;
	cfg.max_density = 1.0;
	cfg.merge_distance = 0.12;
	cfg.neighbor_factor = 1.8;
	cfg.auto_evolve = 1;
	cfg.evolve_interval = 2;	/* write_ops=2/4 都会触发（若不抑制） */

	sp = aik_space_new(&cfg, 4, err, sizeof(err));
	if (!sp)
		die("bulk: aik_space_new: %s", err);

	aik_space_set_bulk(sp, 1);
	for (i = 0; i < 4; i++) {
		if (aik_space_insert(sp, ids[i], vec[i], err, sizeof(err)) != 0)
			die("bulk: insert %s: %s", ids[i], err);
	}
	check_int("bulk.regions", (long long)aik_space_region_count(sp), 1);
	check_int("bulk.write_ops", aik_space_write_ops(sp), 4);
	{
		/*
		 * bulk 期间不应有演化事件：history 只允许首个 Region 的
		 * region_created（吸收/建 Region 不经过 maybe_evolve）。
		 */
		int no_split_merge = 1;
		int only_created = 1;

		for (i = 0; i < aik_space_history_count(sp); i++) {
			const aik_space_event *e = aik_space_history_at(sp, i);

			if (!e->kind)
				continue;
			if (strcmp(e->kind, "split") == 0 ||
			    strcmp(e->kind, "merge") == 0)
				no_split_merge = 0;
			if (strcmp(e->kind, "region_created") != 0)
				only_created = 0;
		}
		checks++;
		if (!no_split_merge)
			mismatch("bulk.no_evolution", "split/merge in history");
		checks++;
		if (!only_created)
			mismatch("bulk.history",
				 "unexpected event beyond region_created");
	}

	aik_space_set_bulk(sp, 0);
	rc = aik_space_evolution_pass(sp, &events, &n_events, err, sizeof(err));
	check_int("bulk.evolution.rc", rc, 0);
	checks++;
	if (n_events == 0) {
		mismatch("bulk.evolution.events", "expected > 0 events");
	} else {
		for (i = 0; i < n_events; i++) {
			if (events[i].kind && strcmp(events[i].kind, "split") == 0)
				found_split = 1;
		}
	}
	checks++;
	if (!found_split)
		mismatch("bulk.evolution.split",
			 "no split event after bulk off (events=%zu)",
			 n_events);
	printf("bulk: events=%zu split=%d\n", n_events, found_split);
	aik_space_events_free(events, n_events);
	aik_space_free(sp);
}

/* ------------------------------------------------------------------ */
/* 用例 3：Region id 生成钩子                                         */
/* ------------------------------------------------------------------ */
struct id_state {
	int calls;
};

static int test_id_fn(void *ud, const char *prefix, char out[16])
{
	struct id_state *st = ud;

	if (!prefix || strcmp(prefix, "r") != 0)
		return -1;
	st->calls++;
	/* 10 → r_00000000000a，11 → r_00000000000b ... */
	snprintf(out, 16, "r_%012x", 10 + st->calls - 1);
	return 0;
}

static void run_id_fn(void)
{
	aik_region_config cfg;
	struct id_state st;
	aik_space *sp;
	char err[256];
	const double v1[4] = { 1.0, 0.0, 0.0, 0.0 };
	const double v2[4] = { 0.0, 1.0, 0.0, 0.0 };
	const double v3[4] = { 1.0, 0.1, 0.0, 0.0 };
	const char *r0;
	const char *r1;

	memset(&cfg, 0, sizeof(cfg));
	cfg.min_region_size = 3;
	cfg.min_join_cosine = 0.70;
	cfg.split_threshold = 48;
	cfg.max_density = 120.0;
	cfg.merge_distance = 0.12;
	cfg.neighbor_factor = 1.8;
	cfg.auto_evolve = 0;	/* id 用例不参与演化 */
	cfg.evolve_interval = 40;
	memset(&st, 0, sizeof(st));

	sp = aik_space_new(&cfg, 4, err, sizeof(err));
	if (!sp)
		die("id_fn: aik_space_new: %s", err);
	aik_space_set_id_fn(sp, test_id_fn, &st);

	if (aik_space_insert(sp, "i1", v1, err, sizeof(err)) != 0)
		die("id_fn: insert i1: %s", err);
	if (aik_space_insert(sp, "i2", v2, err, sizeof(err)) != 0)
		die("id_fn: insert i2: %s", err);
	check_int("id_fn.regions.after_two",
		  (long long)aik_space_region_count(sp), 2);
	check_int("id_fn.calls.after_two", st.calls, 2);
	r0 = aik_space_region_for(sp, "i1");
	r1 = aik_space_region_for(sp, "i2");
	check_str("id_fn.region0", r0, "r_00000000000a");
	check_str("id_fn.region1", r1, "r_00000000000b");
	check_str("id_fn.region_at0", aik_region_id(aik_space_region_at(sp, 0)),
		  "r_00000000000a");
	check_str("id_fn.region_at1", aik_region_id(aik_space_region_at(sp, 1)),
		  "r_00000000000b");

	/* 与 i1 相似 → 复用原 Region，不新建、不再调生成器 */
	if (aik_space_insert(sp, "i3", v3, err, sizeof(err)) != 0)
		die("id_fn: insert i3: %s", err);
	check_int("id_fn.regions.after_three",
		  (long long)aik_space_region_count(sp), 2);
	check_int("id_fn.calls.after_three", st.calls, 2);
	check_str("id_fn.reuse", aik_space_region_for(sp, "i3"),
		  "r_00000000000a");
	printf("id_fn: ids=%s,%s calls=%d\n", r0 ? r0 : "(null)",
	       r1 ? r1 : "(null)", st.calls);
	aik_space_free(sp);
}

/* ------------------------------------------------------------------ */
/* 用例 4：合成剪枝 / 悬挂边 / 重载 / 错误路径                        */
/* ------------------------------------------------------------------ */
static void jpush(aik_json *arr, aik_json *v)
{
	if (aik_json_arr_push(arr, v) != 0) {
		aik_json_free(v);
		die("json arr push failed");
	}
}

static void jput(aik_json *obj, const char *key, aik_json *v)
{
	if (aik_json_obj_put(obj, key, v) != 0) {
		aik_json_free(v);
		die("json obj put failed");
	}
}

static aik_json *mk_region(const char *id, const char *m1, const char *m2,
			   const char *m3, int generation, const char *parent,
			   double created_at)
{
	aik_json *obj = aik_json_new_obj();
	aik_json *members = aik_json_new_arr();

	if (!obj || !members)
		die("out of memory");
	jput(obj, "id", aik_json_new_str(id));
	jpush(members, aik_json_new_str(m1));
	if (m2)
		jpush(members, aik_json_new_str(m2));
	if (m3)
		jpush(members, aik_json_new_str(m3));
	jput(obj, "member_ids", members);
	jput(obj, "generation", aik_json_new_int(generation));
	jput(obj, "parent_region", parent ? aik_json_new_str(parent)
					  : aik_json_new_null());
	jput(obj, "created_at", aik_json_new_num(created_at));
	/* 快照里的 last_updated 不应被采用（load 后 = 注入时钟） */
	jput(obj, "last_updated", aik_json_new_num(999.5));
	return obj;
}

static aik_json *mk_edge(const char *a, const char *b, double distance)
{
	aik_json *obj = aik_json_new_obj();

	if (!obj)
		die("out of memory");
	jput(obj, "source", aik_json_new_str(a));
	jput(obj, "target", aik_json_new_str(b));
	jput(obj, "distance", aik_json_new_num(distance));
	return obj;
}

static void run_synthetic(void)
{
	aik_json *regions = aik_json_new_arr();
	aik_json *edges = aik_json_new_arr();
	aik_space *sp;
	aik_space_vector vec[2];
	double va[3] = { 1.0, 0.0, 0.0 };
	double vb[3] = { 0.0, 1.0, 0.0 };
	char err[256];
	const aik_region *r0;
	const aik_region *r1;
	/* 与快照 created_at（111/333）刻意不同的冻结时钟 */
	struct clock_state clk = { 1700000000.0 };
	int rc;

	if (!regions || !edges)
		die("out of memory");
	/* r2 的成员全不在向量集 → 剪枝；r3 保留 {a,b}（ghost 过滤） */
	jpush(regions, mk_region("r1", "a", NULL, NULL, 2, NULL, 111.0));
	jpush(regions, mk_region("r2", "ghost", "x", NULL, 3, "r1", 222.0));
	jpush(regions, mk_region("r3", "a", "b", "ghost", 1, "r1", 333.0));
	/* 悬挂边（一端被剪）丢弃；r3->r1 与 r1->r3 是无向同对，去重 */
	jpush(edges, mk_edge("r1", "r2", 0.5));
	jpush(edges, mk_edge("r2", "r3", 0.75));
	jpush(edges, mk_edge("r1", "r3", 0.25));
	jpush(edges, mk_edge("r3", "r1", 0.25));

	vec[0].id = "a";
	vec[0].vector = va;
	vec[0].dim = 3;
	vec[1].id = "b";
	vec[1].vector = vb;
	vec[1].dim = 3;

	sp = aik_space_new(NULL, 3, err, sizeof(err));
	if (!sp)
		die("synthetic: aik_space_new: %s", err);
	aik_space_set_clock(sp, frozen_now, &clk);
	rc = aik_space_load_state(sp, 3, vec, 2, regions, edges, err,
				  sizeof(err));
	check_int("synthetic.load.rc", rc, 0);
	check_int("synthetic.regions", (long long)aik_space_region_count(sp),
		  2);
	check_int("synthetic.write_ops", aik_space_write_ops(sp), 0);
	check_int("synthetic.edges", (long long)aik_space_edge_count(sp), 1);
	check_str("synthetic.region0.id",
		  aik_region_id(aik_space_region_at(sp, 0)), "r1");
	check_str("synthetic.region1.id",
		  aik_region_id(aik_space_region_at(sp, 1)), "r3");
	check_int("synthetic.region0.generation",
		  aik_region_generation(aik_space_region_at(sp, 0)), 2);
	check_int("synthetic.region1.generation",
		  aik_region_generation(aik_space_region_at(sp, 1)), 1);
	check_opt_str("synthetic.region0.parent",
		      aik_region_parent(aik_space_region_at(sp, 0)), NULL);
	check_str("synthetic.region1.parent",
		  aik_region_parent(aik_space_region_at(sp, 1)), "r1");
	check_exact("synthetic.region0.created_at",
		    aik_region_created_at(aik_space_region_at(sp, 0)), 111.0);
	check_exact("synthetic.region1.created_at",
		    aik_region_created_at(aik_space_region_at(sp, 1)), 333.0);
	/* created_at 取快照值；last_updated 取注入时钟（JSON 里的 999.5 被忽略） */
	check_exact("synthetic.region0.last_updated",
		    aik_region_last_updated(aik_space_region_at(sp, 0)),
		    clk.now);
	check_exact("synthetic.region1.last_updated",
		    aik_region_last_updated(aik_space_region_at(sp, 1)),
		    clk.now);
	check_int("synthetic.region1.size",
		  (long long)aik_region_size(aik_space_region_at(sp, 1)), 2);
	check_str("synthetic.region1.member0",
		  aik_region_member(aik_space_region_at(sp, 1), 0), "a");
	check_str("synthetic.region1.member1",
		  aik_region_member(aik_space_region_at(sp, 1), 1), "b");
	r1 = aik_space_region_at(sp, 1);
	check_num("synthetic.region1.radius", aik_region_radius(r1),
		  sqrt(0.5));
	check_num("synthetic.region1.density", aik_region_density(r1),
		  2.0 / (1.0 + sqrt(0.5)));
	check_num("synthetic.region1.centroid0",
		  aik_region_centroid(r1) ? aik_region_centroid(r1)[0] : -1.0,
		  0.5);
	check_num("synthetic.region1.centroid1",
		  aik_region_centroid(r1) ? aik_region_centroid(r1)[1] : -1.0,
		  0.5);
	/* membership 成员表反建：同一条记忆出现在两个 Region 时后者覆盖
	 * （Python 按 regions 迭代序赋值，与这里一致） */
	check_str("synthetic.membership.a", aik_space_region_for(sp, "a"),
		  "r3");
	check_str("synthetic.membership.b", aik_space_region_for(sp, "b"),
		  "r3");
	check_opt_str("synthetic.membership.ghost",
		      aik_space_region_for(sp, "ghost"), NULL);
	check_opt_str("synthetic.membership.x",
		      aik_space_region_for(sp, "x"), NULL);
	{
		const char *a;
		const char *b;
		double d = 0.0;

		if (aik_space_edge_at(sp, 0, &a, &b, &d) != 0)
			die("synthetic: edge_at failed");
		/* Python dict 去重保留最后一次写入的方向（r3 → r1） */
		check_str("synthetic.edge.a_end", a, "r3");
		check_str("synthetic.edge.b_end", b, "r1");
		check_num("synthetic.edge.distance", d, 0.25);
	}

	/* 重载：aik_space_load_state 替换既有状态 */
	rc = aik_space_load_state(sp, 3, vec, 2, regions, edges, err,
				  sizeof(err));
	check_int("synthetic.reload.rc", rc, 0);
	check_int("synthetic.reload.regions",
		  (long long)aik_space_region_count(sp), 2);
	check_int("synthetic.reload.edges", (long long)aik_space_edge_count(sp),
		  1);
	r0 = aik_space_region_at(sp, 0);
	check_exact("synthetic.reload.region0.created_at",
		    aik_region_created_at(r0), 111.0);
	check_exact("synthetic.reload.region0.last_updated",
		    aik_region_last_updated(r0), clk.now);

	/* 错误路径：向量维度不符 → -1；参数校验不动既有状态 */
	vec[1].dim = 4;
	rc = aik_space_load_state(sp, 3, vec, 2, regions, edges, err,
				  sizeof(err));
	check_int("synthetic.bad_dim.rc", rc, -1);
	check_int("synthetic.bad_dim.regions",
		  (long long)aik_space_region_count(sp), 2);
	check_int("synthetic.bad_dim.edges", (long long)aik_space_edge_count(sp),
		  1);
	vec[1].dim = 3;
	rc = aik_space_load_state(sp, 3, vec, 2, regions, edges, err,
				  sizeof(err));
	check_int("synthetic.recover.rc", rc, 0);
	r0 = aik_space_region_at(sp, 0);
	check_str("synthetic.recover.region0", aik_region_id(r0), "r1");
	check_str("synthetic.recover.membership.a",
		  aik_space_region_for(sp, "a"), "r3");

	aik_space_free(sp);
	aik_json_free(regions);
	aik_json_free(edges);
}

/* ------------------------------------------------------------------ */
/* 用例 5：时钟注入（created_at / last_updated）                      */
/* ------------------------------------------------------------------ */
static void run_clock(void)
{
	aik_region_config cfg;
	struct clock_state clk = { 1767225600.0 };
	aik_space *sp;
	char err[256];
	const double v1[4] = { 1.0, 0.0, 0.0, 0.0 };
	const double v2[4] = { 0.0, 1.0, 0.0, 0.0 };
	const double v3[4] = { 1.0, 0.1, 0.0, 0.0 };
	const char *rid0;

	memset(&cfg, 0, sizeof(cfg));
	cfg.min_region_size = 3;
	cfg.min_join_cosine = 0.70;
	cfg.split_threshold = 48;
	cfg.max_density = 120.0;
	cfg.merge_distance = 0.12;
	cfg.neighbor_factor = 1.8;
	cfg.auto_evolve = 0;
	cfg.evolve_interval = 40;

	sp = aik_space_new(&cfg, 4, err, sizeof(err));
	if (!sp)
		die("clock: aik_space_new: %s", err);
	aik_space_set_clock(sp, frozen_now, &clk);

	/* 设时钟后新建两个不相似 Region → created_at == last_updated == 冻结值 */
	if (aik_space_insert(sp, "k1", v1, err, sizeof(err)) != 0)
		die("clock: insert k1: %s", err);
	if (aik_space_insert(sp, "k2", v2, err, sizeof(err)) != 0)
		die("clock: insert k2: %s", err);
	check_int("clock.regions", (long long)aik_space_region_count(sp), 2);
	check_exact("clock.region0.created_at",
		    aik_region_created_at(aik_space_region_at(sp, 0)), clk.now);
	check_exact("clock.region0.last_updated",
		    aik_region_last_updated(aik_space_region_at(sp, 0)),
		    clk.now);
	check_exact("clock.region1.created_at",
		    aik_region_created_at(aik_space_region_at(sp, 1)), clk.now);
	check_exact("clock.region1.last_updated",
		    aik_region_last_updated(aik_space_region_at(sp, 1)),
		    clk.now);
	rid0 = aik_region_id(aik_space_region_at(sp, 0));

	/* 换时钟：已有 Region 之后的刷新跟随新时钟，created_at 不变 */
	clk.now = 1700000000.0;
	if (aik_space_insert(sp, "k3", v3, err, sizeof(err)) != 0)
		die("clock: insert k3: %s", err);
	aik_space_sync_geometry(sp);
	check_int("clock.regions.after",
		  (long long)aik_space_region_count(sp), 2);
	check_str("clock.reuse", aik_space_region_for(sp, "k3"), rid0);
	check_exact("clock.region0.created_at.after",
		    aik_region_created_at(aik_space_region_at(sp, 0)),
		    1767225600.0);
	check_exact("clock.region0.last_updated.after",
		    aik_region_last_updated(aik_space_region_at(sp, 0)),
		    clk.now);
	check_exact("clock.region1.last_updated.untouched",
		    aik_region_last_updated(aik_space_region_at(sp, 1)),
		    1767225600.0);

	aik_space_free(sp);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */
int main(void)
{
	char *storage = path_join(vectors_dir(), "storage");

	if (!storage)
		die("out of memory");
	run_parity(storage);
	free(storage);
	run_bulk();
	run_id_fn();
	run_clock();
	run_synthetic();
	printf("SUMMARY space_load checks=%zu mismatches=%zu\n", checks,
	       mismatches);
	return mismatches == 0 ? 0 : 1;
}
