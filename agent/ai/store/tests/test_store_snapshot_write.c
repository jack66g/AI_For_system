/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_store_snapshot_write.c - 快照写 + WAL 重放状态机自测（T2b-1）
 *
 * 覆盖：
 *   1) $AIK_STORE_VECTORS/engine.json.gz → aik_snapshot_save 为
 *      /tmp/t2b-out/snapshot.json.gz（gzip=1）与 snapshot.json（明文）；
 *      两者再 load → dump 都必须与 snapshot.canonical.json 逐字节相等
 *      （明文文件本身也必须等于 canonical）；
 *   2) 重放状态机（本测试内实现，不入库）：以
 *      $AIK_PARITY_VECTORS/wal/engine.json.gz 的 memories/memory_edges
 *      为初始状态，依次应用 wal.vectors.json 的 parsed 记录（add /
 *      transaction 的 memories、patches、deleted、graph 整体替换；兼容
 *      update/delete/archive/restore），导出
 *      {"memories":[按 id 升序],"graph":{"edges":[按 source,target,
 *      kind,weight,note 排序]}}（丢弃 embedding 与 region_id），与
 *      wal/expected_state.canonical.json 逐字节相等，失败打印首个差异
 *      offset；
 *   3) 崩溃恢复：fork 子进程 open WAL(fsync_each=1) → append 两条 →
 *      _exit(9)；父进程 waitpid 后 replay(checkpoint=7) 必须成功回调
 *      两次（seq 8/9）；crash.wal 逐字节等于 engine.json.wal.lf（纯 LF，
 *      不含 CR）。
 *
 * 末行 "SUMMARY snapshot_write checked=... mismatch=... bytes=..."。
 */
#define _POSIX_C_SOURCE 200809L

#include "store/store_json.h"
#include "store/store_snapshot.h"
#include "store/store_wal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define OUT_DIR "/tmp/t2b-out"

static int g_checked;
static int g_mismatch;
static size_t g_bytes;

static void report(const char *fmt, ...)
{
	va_list ap;

	g_mismatch++;
	va_start(ap, fmt);
	fprintf(stderr, "FAIL: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

#define CHECK(cond) do {						\
	g_checked++;							\
	if (!(cond))							\
		report("%s:%d: CHECK(%s)", __FILE__, __LINE__, #cond);	\
} while (0)

/* ------------------------------------------------------------------ */
/* 路径与文件                                                          */
/* ------------------------------------------------------------------ */

static const char *store_dir(void)
{
	const char *d = getenv("AIK_STORE_VECTORS");
	static char buf[8192];

	if (d && *d)
		return d;
	(void)snprintf(buf, sizeof(buf),
		       "%s/aikernel-longterm/parity/vectors/storage",
		       getenv("HOME") ? getenv("HOME") : ".");
	return buf;
}

static const char *parity_dir(void)
{
	const char *d = getenv("AIK_PARITY_VECTORS");
	static char buf[8192];

	if (d && *d)
		return d;
	(void)snprintf(buf, sizeof(buf),
		       "%s/aikernel-longterm/parity/vectors",
		       getenv("HOME") ? getenv("HOME") : ".");
	return buf;
}

static char *path_in(const char *dir, const char *name)
{
	size_t dl = strlen(dir), nl = strlen(name);
	char *p = malloc(dl + 1 + nl + 1);

	if (!p)
		return NULL;
	memcpy(p, dir, dl);
	p[dl] = '/';
	memcpy(p + dl + 1, name, nl + 1);
	return p;
}

static unsigned char *read_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	long sz;
	unsigned char *buf;

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return NULL;
	}
	sz = ftell(f);
	if (sz < 0) {
		fclose(f);
		return NULL;
	}
	rewind(f);
	buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf);
		fclose(f);
		return NULL;
	}
	buf[sz] = '\0';
	fclose(f);
	*len = (size_t)sz;
	return buf;
}

static int ensure_out_dir(void)
{
	struct stat st;

	if (mkdir(OUT_DIR, 0755) == 0)
		return 0;
	if (errno != EEXIST)
		return -1;
	if (stat(OUT_DIR, &st) != 0 || !S_ISDIR(st.st_mode))
		return -1;
	return 0;
}

static void report_diff(const char *label, const unsigned char *got, size_t gn,
			const unsigned char *want, size_t wn)
{
	size_t i, n = gn < wn ? gn : wn, from, to;

	for (i = 0; i < n; i++) {
		if (got[i] != want[i])
			break;
	}
	if (i == n && gn == wn)
		return;
	report("%s mismatch at offset %zu (got %zu bytes, want %zu)",
	       label, i, gn, wn);
	from = i > 40 ? i - 40 : 0;
	to = i + 40 < gn ? i + 40 : gn;
	fprintf(stderr, "  got[%zu..%zu]:  ", from, to);
	if (to > from)
		(void)fwrite(got + from, 1, to - from, stderr);
	fprintf(stderr, "\n");
	to = i + 40 < wn ? i + 40 : wn;
	fprintf(stderr, "  want[%zu..%zu]: ", from, to);
	if (to > from)
		(void)fwrite(want + from, 1, to - from, stderr);
	fprintf(stderr, "\n");
}

/* ------------------------------------------------------------------ */
/* DOM 深拷贝（状态机只读参考快照，构造自己的副本）                     */
/* ------------------------------------------------------------------ */

static aik_json *jclone(const aik_json *v)
{
	aik_json *out;
	size_t i, n;

	if (!v)
		return NULL;
	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		return aik_json_new_null();
	case AIK_JSON_BOOL:
		return aik_json_new_bool(aik_json_bool(v));
	case AIK_JSON_INT:
		return aik_json_new_int(aik_json_int(v));
	case AIK_JSON_NUM:
		return aik_json_new_num(aik_json_num(v));
	case AIK_JSON_STR: {
		const char *s = aik_json_str(v);

		return s ? aik_json_new_str(s) : NULL;
	}
	case AIK_JSON_ARR:
		out = aik_json_new_arr();
		if (!out)
			return NULL;
		n = aik_json_count(v);
		for (i = 0; i < n; i++) {
			aik_json *c = jclone(aik_json_at(v, i));

			if (!c || aik_json_arr_push(out, c) != 0) {
				aik_json_free(c);
				aik_json_free(out);
				return NULL;
			}
		}
		return out;
	case AIK_JSON_OBJ:
		out = aik_json_new_obj();
		if (!out)
			return NULL;
		n = aik_json_count(v);
		for (i = 0; i < n; i++) {
			const char *k = aik_json_key_at(v, i);
			aik_json *c = jclone(aik_json_val_at(v, i));

			if (!c || !k || aik_json_obj_put(out, k, c) != 0) {
				aik_json_free(c);
				aik_json_free(out);
				return NULL;
			}
		}
		return out;
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/* 最小状态机                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
	aik_json *memories;	/* OBJ：id -> memory DOM（插入序） */
	aik_json *edges;	/* ARR：edge DOM */
} sm_state;

static const char *op_id(const aik_json *op)
{
	const char *id = aik_json_str(aik_json_get(op, "mid"));

	if (id)
		return id;
	return aik_json_str(aik_json_get(op, "id"));
}

static int sm_insert(sm_state *st, const aik_json *mem)
{
	const char *id;
	aik_json *c;

	if (aik_json_typeof(mem) != AIK_JSON_OBJ)
		return -1;
	id = aik_json_str(aik_json_get(mem, "id"));
	if (!id)
		return -1;
	c = jclone(mem);
	if (!c)
		return -1;
	if (aik_json_obj_set(st->memories, id, c) != 0) {
		aik_json_free(c);
		return -1;
	}
	return 0;
}

/* 无删除 API：重建映射，保持其余键的原有顺序 */
static int sm_remove(sm_state *st, const char *id)
{
	aik_json *neu = aik_json_new_obj();
	size_t i, n = aik_json_count(st->memories);

	if (!neu)
		return -1;
	for (i = 0; i < n; i++) {
		const char *k = aik_json_key_at(st->memories, i);
		aik_json *c;

		if (strcmp(k, id) == 0)
			continue;
		c = jclone(aik_json_val_at(st->memories, i));
		if (!c || aik_json_obj_put(neu, k, c) != 0) {
			aik_json_free(c);
			aik_json_free(neu);
			return -1;
		}
	}
	aik_json_free(st->memories);
	st->memories = neu;
	return 0;
}

static int sm_merge_obj(aik_json *target, const aik_json *patch)
{
	size_t i, n;

	if (aik_json_typeof(patch) != AIK_JSON_OBJ)
		return -1;
	n = aik_json_count(patch);
	for (i = 0; i < n; i++) {
		const char *k = aik_json_key_at(patch, i);
		aik_json *c = jclone(aik_json_val_at(patch, i));

		if (!c || aik_json_obj_set(target, k, c) != 0) {
			aik_json_free(c);
			return -1;
		}
	}
	return 0;
}

static int sm_set_graph(sm_state *st, const aik_json *graph)
{
	const aik_json *edges = aik_json_get(graph, "edges");
	aik_json *neu;
	size_t i, n;

	if (aik_json_typeof(graph) != AIK_JSON_OBJ ||
	    aik_json_typeof(edges) != AIK_JSON_ARR)
		return -1;
	neu = aik_json_new_arr();
	if (!neu)
		return -1;
	n = aik_json_count(edges);
	for (i = 0; i < n; i++) {
		aik_json *c = jclone(aik_json_at(edges, i));

		if (!c || aik_json_arr_push(neu, c) != 0) {
			aik_json_free(c);
			aik_json_free(neu);
			return -1;
		}
	}
	aik_json_free(st->edges);
	st->edges = neu;
	return 0;
}

static int sm_apply(sm_state *st, const aik_json *op)
{
	const char *name;

	if (aik_json_typeof(op) != AIK_JSON_OBJ)
		return -1;
	name = aik_json_str(aik_json_get(op, "op"));
	if (!name)
		return -1;

	if (strcmp(name, "add") == 0) {
		const aik_json *state = aik_json_get(op, "state");

		if (aik_json_typeof(state) == AIK_JSON_OBJ)
			return sm_insert(st, state);
		return 0;
	}

	if (strcmp(name, "transaction") == 0) {
		const aik_json *mems = aik_json_get(op, "memories");
		const aik_json *patches = aik_json_get(op, "patches");
		const aik_json *deleted = aik_json_get(op, "deleted");
		const aik_json *graph = aik_json_get(op, "graph");
		size_t i, n;

		n = aik_json_count(mems);
		for (i = 0; i < n; i++)
			if (sm_insert(st, aik_json_at(mems, i)) != 0)
				return -1;

		n = aik_json_count(patches);
		for (i = 0; i < n; i++) {
			const char *id = aik_json_key_at(patches, i);
			aik_json *target =
				(aik_json *)aik_json_get(st->memories, id);

			if (target &&
			    sm_merge_obj(target, aik_json_val_at(patches, i)) != 0)
				return -1;
		}

		n = aik_json_count(deleted);
		for (i = 0; i < n; i++) {
			const char *id = aik_json_str(aik_json_at(deleted, i));

			if (id && sm_remove(st, id) != 0)
				return -1;
		}

		if (graph && sm_set_graph(st, graph) != 0)
			return -1;
		return 0;
	}

	if (strcmp(name, "update") == 0) {
		const aik_json *state = aik_json_get(op, "state");
		const aik_json *patch = aik_json_get(op, "patch");
		const char *id;
		aik_json *target;

		if (aik_json_typeof(state) == AIK_JSON_OBJ)
			return sm_insert(st, state);
		id = op_id(op);
		target = id ? (aik_json *)aik_json_get(st->memories, id) : NULL;
		if (!target)
			return 0;
		if (patch && sm_merge_obj(target, patch) != 0)
			return -1;
		{
			static const char *skip[] = {
				"op", "mid", "id", "seq", "patch", "state",
				"memories", "graph", "deleted", "patches"
			};
			size_t i, j, ns = sizeof(skip) / sizeof(skip[0]);
			size_t n = aik_json_count(op);

			for (i = 0; i < n; i++) {
				const char *k = aik_json_key_at(op, i);
				aik_json *c;
				int skip_it = 0;

				for (j = 0; j < ns; j++) {
					if (strcmp(k, skip[j]) == 0) {
						skip_it = 1;
						break;
					}
				}
				if (skip_it)
					continue;
				c = jclone(aik_json_val_at(op, i));
				if (!c || aik_json_obj_set(target, k, c) != 0) {
					aik_json_free(c);
					return -1;
				}
			}
		}
		return 0;
	}

	if (strcmp(name, "delete") == 0) {
		const char *id = op_id(op);

		return id ? sm_remove(st, id) : -1;
	}

	if (strcmp(name, "archive") == 0 || strcmp(name, "restore") == 0) {
		const char *id = op_id(op);
		aik_json *target = id ? (aik_json *)aik_json_get(st->memories, id)
				      : NULL;
		aik_json *b;

		if (!target)
			return 0;
		b = aik_json_new_bool(strcmp(name, "archive") == 0);
		if (!b || aik_json_obj_set(target, "archived", b) != 0) {
			aik_json_free(b);
			return -1;
		}
		return 0;
	}

	/* 未知 op 视为数据漂移，让门禁失败 */
	return -1;
}

static int sm_init(sm_state *st, const aik_json *root)
{
	const aik_json *mems = aik_json_get(root, "memories");
	const aik_json *edges = aik_json_get(root, "memory_edges");
	size_t i, n;

	st->memories = aik_json_new_obj();
	st->edges = aik_json_new_arr();
	if (!st->memories || !st->edges)
		return -1;

	n = aik_json_count(mems);
	for (i = 0; i < n; i++) {
		const aik_json *m = aik_json_at(mems, i);
		const char *id = aik_json_str(aik_json_get(m, "id"));
		aik_json *c = jclone(m);

		if (!id || !c || aik_json_obj_put(st->memories, id, c) != 0) {
			aik_json_free(c);
			return -1;
		}
	}

	n = aik_json_count(edges);
	for (i = 0; i < n; i++) {
		aik_json *c = jclone(aik_json_at(edges, i));

		if (!c || aik_json_arr_push(st->edges, c) != 0) {
			aik_json_free(c);
			return -1;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* 导出投影                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
	const char *id;
	const aik_json *mem;
} mem_item;

static int cmp_mem(const void *pa, const void *pb)
{
	const mem_item *a = pa;
	const mem_item *b = pb;

	return strcmp(a->id, b->id);
}

static const char *estr(const aik_json *o, const char *k)
{
	const char *s = aik_json_str(aik_json_get(o, k));

	return s ? s : "";
}

static int cmp_edge(const void *pa, const void *pb)
{
	const aik_json *a = *(const aik_json * const *)pa;
	const aik_json *b = *(const aik_json * const *)pb;
	int r = strcmp(estr(a, "source"), estr(b, "source"));
	double wa, wb;

	if (r)
		return r;
	r = strcmp(estr(a, "target"), estr(b, "target"));
	if (r)
		return r;
	r = strcmp(estr(a, "kind"), estr(b, "kind"));
	if (r)
		return r;
	wa = aik_json_num(aik_json_get(a, "weight"));
	wb = aik_json_num(aik_json_get(b, "weight"));
	if (wa < wb)
		return -1;
	if (wa > wb)
		return 1;
	return strcmp(estr(a, "note"), estr(b, "note"));
}

static aik_json *filter_memory(const aik_json *m)
{
	aik_json *o = aik_json_new_obj();
	size_t i, n = aik_json_count(m);

	if (!o)
		return NULL;
	for (i = 0; i < n; i++) {
		const char *k = aik_json_key_at(m, i);
		aik_json *c;

		if (strcmp(k, "embedding") == 0 || strcmp(k, "region_id") == 0)
			continue;
		c = jclone(aik_json_val_at(m, i));
		if (!c || aik_json_obj_put(o, k, c) != 0) {
			aik_json_free(c);
			aik_json_free(o);
			return NULL;
		}
	}
	return o;
}

static aik_json *export_state(const sm_state *st)
{
	aik_json *root = NULL, *marr = NULL, *graph = NULL, *earr = NULL;
	mem_item *items = NULL;
	const aik_json **edges = NULL;
	size_t i, n;

	root = aik_json_new_obj();
	marr = aik_json_new_arr();
	if (!root || !marr)
		goto fail;

	n = aik_json_count(st->memories);
	items = malloc((n ? n : 1) * sizeof(*items));
	if (!items)
		goto fail;
	for (i = 0; i < n; i++) {
		items[i].id = aik_json_key_at(st->memories, i);
		items[i].mem = aik_json_val_at(st->memories, i);
	}
	qsort(items, n, sizeof(*items), cmp_mem);
	for (i = 0; i < n; i++) {
		aik_json *f = filter_memory(items[i].mem);

		if (!f || aik_json_arr_push(marr, f) != 0) {
			aik_json_free(f);
			goto fail;
		}
	}
	free(items);
	items = NULL;

	n = aik_json_count(st->edges);
	edges = malloc((n ? n : 1) * sizeof(*edges));
	if (!edges)
		goto fail;
	for (i = 0; i < n; i++)
		edges[i] = aik_json_at(st->edges, i);
	qsort(edges, n, sizeof(*edges), cmp_edge);
	earr = aik_json_new_arr();
	if (!earr)
		goto fail;
	for (i = 0; i < n; i++) {
		aik_json *c = jclone(edges[i]);

		if (!c || aik_json_arr_push(earr, c) != 0) {
			aik_json_free(c);
			goto fail;
		}
	}
	free(edges);
	edges = NULL;

	graph = aik_json_new_obj();
	if (!graph || aik_json_obj_put(graph, "edges", earr) != 0)
		goto fail;
	earr = NULL;
	if (aik_json_obj_put(root, "memories", marr) != 0)
		goto fail;
	marr = NULL;
	if (aik_json_obj_put(root, "graph", graph) != 0)
		goto fail;
	return root;

fail:
	free(items);
	free(edges);
	aik_json_free(earr);
	aik_json_free(graph);
	aik_json_free(marr);
	aik_json_free(root);
	return NULL;
}

/* ------------------------------------------------------------------ */
/* 1) 快照原子写                                                       */
/* ------------------------------------------------------------------ */

static void compare_dump(const char *label, const aik_json *root,
			 const unsigned char *want, size_t wn)
{
	char *got = NULL;
	size_t gn = 0;

	if (aik_json_dump(root, &got, &gn) != 0) {
		report("%s: dump failed", label);
		return;
	}
	g_bytes += gn;
	{
		int same = gn == wn && memcmp(got, want, wn) == 0;

		CHECK(same);
		if (!same)
			report_diff(label, (const unsigned char *)got, gn, want,
				    wn);
	}
	free(got);
}

static void test_snapshot_write(void)
{
	char err[256] = "";
	char *src = path_in(store_dir(), "engine.json.gz");
	char *canon = path_in(store_dir(), "snapshot.canonical.json");
	char *gzout = path_in(OUT_DIR, "snapshot.json.gz");
	char *jsout = path_in(OUT_DIR, "snapshot.json");
	unsigned char *want = NULL, *plain = NULL;
	size_t wn = 0, pn = 0;
	aik_snapshot s;

	memset(&s, 0, sizeof(s));
	printf("snapshot: out dir %s\n", OUT_DIR);
	if (!src || !canon || !gzout || !jsout) {
		report("out of memory");
		goto out;
	}
	if (ensure_out_dir() != 0) {
		report("cannot create %s: %s", OUT_DIR, strerror(errno));
		goto out;
	}
	if (aik_snapshot_load(src, &s, err, sizeof(err)) != 0) {
		report("load %s: %s", src, err);
		goto out;
	}

	/* gzip 写 */
	g_checked++;
	if (aik_snapshot_save(s.root, gzout, 1, err, sizeof(err)) != 0)
		report("save %s: %s", gzout, err);
	/* 明文写 */
	g_checked++;
	if (aik_snapshot_save(s.root, jsout, 0, err, sizeof(err)) != 0)
		report("save %s: %s", jsout, err);

	want = read_file(canon, &wn);
	CHECK(want != NULL);
	if (!want)
		goto out;

	/* gzip 往返：load → dump == canonical */
	{
		aik_snapshot r;

		memset(&r, 0, sizeof(r));
		if (aik_snapshot_load(gzout, &r, err, sizeof(err)) != 0) {
			report("load %s: %s", gzout, err);
		} else {
			compare_dump("snapshot.json.gz roundtrip", r.root, want,
				     wn);
			aik_snapshot_free(&r);
		}
	}

	/* 明文往返：load → dump == canonical */
	{
		aik_snapshot r;

		memset(&r, 0, sizeof(r));
		if (aik_snapshot_load(jsout, &r, err, sizeof(err)) != 0) {
			report("load %s: %s", jsout, err);
		} else {
			compare_dump("snapshot.json roundtrip", r.root, want,
				     wn);
			aik_snapshot_free(&r);
		}
	}

	/* 明文文件本身逐字节等于 canonical；gzip 头 magic 正确 */
	plain = read_file(jsout, &pn);
	CHECK(plain != NULL);
	if (plain) {
		CHECK(pn == wn && memcmp(plain, want, wn) == 0);
		if (!(pn == wn && memcmp(plain, want, wn) == 0))
			report_diff("snapshot.json file", plain, pn, want, wn);
	}
	{
		size_t gn = 0;
		unsigned char *g = read_file(gzout, &gn);

		CHECK(g != NULL && gn > 2 && g[0] == 0x1f && g[1] == 0x8b);
		free(g);
	}

out:
	aik_snapshot_free(&s);
	free(want);
	free(plain);
	free(src);
	free(canon);
	free(gzout);
	free(jsout);
}

/* ------------------------------------------------------------------ */
/* 2) WAL 重放状态机                                                   */
/* ------------------------------------------------------------------ */

static void test_replay_state(const aik_json *vectors)
{
	char err[256] = "";
	char *snap_path = path_in(parity_dir(), "wal/engine.json.gz");
	char *exp_path = path_in(parity_dir(), "wal/expected_state.canonical.json");
	aik_snapshot snap;
	sm_state st;
	const aik_json *lines;
	unsigned char *want = NULL;
	size_t wn = 0, i, n;
	aik_json *out = NULL;

	memset(&snap, 0, sizeof(snap));
	memset(&st, 0, sizeof(st));
	if (!snap_path || !exp_path) {
		report("out of memory");
		goto out;
	}
	if (aik_snapshot_load(snap_path, &snap, err, sizeof(err)) != 0) {
		report("load %s: %s", snap_path, err);
		goto out;
	}
	if (sm_init(&st, snap.root) != 0) {
		report("cannot initialize state machine");
		goto out;
	}

	lines = aik_json_get(aik_json_get(vectors, "wal"), "lines");
	n = aik_json_count(lines);
	for (i = 0; i < n; i++) {
		const aik_json *op = aik_json_get(aik_json_at(lines, i), "parsed");

		g_checked++;
		if (sm_apply(&st, op) != 0) {
			report("cannot apply WAL record %zu", i + 1);
			goto out;
		}
	}

	out = export_state(&st);
	CHECK(out != NULL);
	want = read_file(exp_path, &wn);
	CHECK(want != NULL);
	if (out && want)
		compare_dump("expected_state", out, want, wn);

out:
	aik_json_free(out);
	free(want);
	aik_json_free(st.memories);
	aik_json_free(st.edges);
	aik_snapshot_free(&snap);
	free(snap_path);
	free(exp_path);
}

/* ------------------------------------------------------------------ */
/* 3) 崩溃恢复                                                         */
/* ------------------------------------------------------------------ */

struct crash_ctx {
	int count;
	long long seqs[8];
};

static int crash_cb(void *ctx, const aik_json *op, char *err, size_t errlen)
{
	struct crash_ctx *c = ctx;
	const aik_json *seq = aik_json_get(op, "seq");

	if (!seq || aik_json_typeof(seq) != AIK_JSON_INT) {
		(void)snprintf(err, errlen, "callback: bad seq");
		return -1;
	}
	if (c->count >= 8) {
		(void)snprintf(err, errlen, "callback: too many records");
		return -1;
	}
	c->seqs[c->count++] = aik_json_int(seq);
	return 0;
}

static void test_crash_recovery(const aik_json *vectors)
{
	char err[256] = "";
	char *path = path_in(OUT_DIR, "crash.wal");
	const aik_json *lines;
	size_t n, i;
	pid_t pid;
	int status;

	if (!path) {
		report("out of memory");
		return;
	}
	lines = aik_json_get(aik_json_get(vectors, "wal"), "lines");
	n = aik_json_count(lines);
	(void)unlink(path);

	pid = fork();
	if (pid < 0) {
		report("fork failed: %s", strerror(errno));
		free(path);
		return;
	}
	if (pid == 0) {
		aik_wal *w = aik_wal_open(path, 1, err, sizeof(err));

		if (!w)
			_exit(10);
		for (i = 0; i < n; i++) {
			const aik_json *op =
				aik_json_get(aik_json_at(lines, i), "parsed");

			if (aik_wal_append(w, op, err, sizeof(err)) != 0)
				_exit(11);
		}
		(void)aik_wal_close(w);
		_exit(9);
	}

	if (waitpid(pid, &status, 0) != pid) {
		report("waitpid failed: %s", strerror(errno));
	} else {
		g_checked++;
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 9)
			report("child status=0x%x, want exit 9", status);
	}
	{
		struct crash_ctx c;
		int rc;

		memset(&c, 0, sizeof(c));
		rc = aik_wal_replay(path, 7, crash_cb, &c, err, sizeof(err));
		g_checked++;
		if (rc != 2)
			report("crash replay rc=%d, want 2 (%s)", rc, err);
		g_checked++;
		if (c.count != 2)
			report("crash replay callbacks=%d, want 2", c.count);
		CHECK(c.count < 1 || c.seqs[0] == 8);
		CHECK(c.count < 2 || c.seqs[1] == 9);
	}

	/* crash.wal 必须是纯 LF，且与 LF 基准逐字节相同 */
	{
		char *lfp = path_in(parity_dir(), "wal/engine.json.wal.lf");
		unsigned char *cb = NULL, *lb = NULL;
		size_t cn = 0, ln = 0, j;
		int cr = 0;

		if (!lfp) {
			report("out of memory");
		} else {
			cb = read_file(path, &cn);
			lb = read_file(lfp, &ln);
			CHECK(cb != NULL && lb != NULL);
			if (cb && lb) {
				g_checked++;
				if (cn != ln || memcmp(cb, lb, cn) != 0)
					report("crash.wal != engine.json.wal.lf (%zu vs %zu bytes)",
					       cn, ln);
				for (j = 0; j < cn; j++) {
					if (cb[j] == '\r')
						cr++;
				}
				g_checked++;
				if (cr != 0)
					report("crash.wal contains %d CR bytes",
					       cr);
			}
			free(cb);
			free(lb);
			free(lfp);
		}
	}
	free(path);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
	char err[256] = "";
	char *vpath;
	unsigned char *vbuf = NULL;
	size_t vlen = 0;
	aik_json *vectors = NULL;

	printf("parity vectors: %s\n", parity_dir());
	printf("store vectors:  %s\n", store_dir());

	vpath = path_in(parity_dir(), "wal/wal.vectors.json");
	if (!vpath) {
		report("out of memory");
		goto summary;
	}
	vbuf = read_file(vpath, &vlen);
	if (!vbuf) {
		report("cannot read %s", vpath);
		goto summary;
	}
	vectors = aik_json_parse((const char *)vbuf, vlen, err, sizeof(err));
	if (!vectors) {
		report("parse %s: %s", vpath, err);
		goto summary;
	}

	test_snapshot_write();
	test_replay_state(vectors);
	test_crash_recovery(vectors);

summary:
	aik_json_free(vectors);
	free(vbuf);
	free(vpath);
	printf("SUMMARY snapshot_write checked=%d mismatch=%d bytes=%zu\n",
	       g_checked, g_mismatch, g_bytes);
	return g_mismatch ? 1 : 0;
}
