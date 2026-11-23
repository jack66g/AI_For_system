/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_rebuild.c - T4e 配置热重建（aik_engine_rebuild）
 *
 * 覆盖：
 *   1) 有记忆时 embedding 身份变化 → 拒绝（返回 1，中文提示），旧引擎不变；
 *      身份包含 mrl_dim/revision/hash_factors/hash_seed（有意修正）；
 *   2) 普通配置变化 → 新引擎保留全部记忆字段/图边/计数器；
 *   3) 空库 → 身份变化也允许重建；
 *   4) 549 条 T2 快照 → 重建后计数（splits/merges/consolidations/
 *      compressions/graph_edges）与 archived 数不变，抽样记忆逐字段一致。
 *   5) MEM-02a（上游 ed5378a P3-14）→ 新配置 persistence.enabled=false 的
 *      热重建立即 checkpoint 到 storage.path：重建前无快照、重建后有，
 *      新引擎从该快照 load 回全部记忆；落盘失败 → 返回 2、旧引擎原封
 *      不动；persistence 开着（WAL）→ 重建成功且状态已落盘。
 *      自 MEM-02a 起重建会写 storage.path，各用例改用自己的临时目录。
 *
 * 数据目录：$AIK_PARITY_VECTORS（缺省 $HOME/aikernel-longterm/parity/vectors）。
 * 输出：test_rebuild: N checks, 0 failed（失败行 MISMATCH ...）。
 */
#define _POSIX_C_SOURCE 200809L

#include "engine/engine.h"
#include "smeconfig/config.h"
#include "store/store_snapshot.h"

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_checks;
static int g_failed;

static void check(int ok, const char *fmt, ...)
{
	va_list ap;

	g_checks++;
	if (ok)
		return;
	g_failed++;
	fputs("MISMATCH ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static void check_ll(const char *name, long long got, long long want)
{
	check(got == want, "%s: got %lld expected %lld", name, got, want);
}

static void check_has(const char *name, const char *hay, const char *needle)
{
	check(hay && strstr(hay, needle) != NULL, "%s: '%s' not in '%s'",
	      name, needle ? needle : "(null)", hay ? hay : "(null)");
}

/* ------------------------------------------------------------------ */
/* 固定时钟 / 顺序 id                                                 */
/* ------------------------------------------------------------------ */
static double fixed_now(void *ud)
{
	(void)ud;
	return 1775000000.0;
}

static unsigned long long g_id_seq;

static int seq_id(void *ud, const char *prefix, char out[16])
{
	(void)ud;
	g_id_seq++;
	snprintf(out, 16, "%c_%012llx", prefix ? prefix[0] : 'x', g_id_seq);
	return 0;
}

static const char *vector_root(void)
{
	static char buf[1024];
	const char *env = getenv("AIK_PARITY_VECTORS");
	const char *home;

	if (env && *env) {
		snprintf(buf, sizeof(buf), "%s", env);
		return buf;
	}
	home = getenv("HOME");
	snprintf(buf, sizeof(buf), "%s/aikernel-longterm/parity/vectors",
		 home ? home : ".");
	return buf;
}

static char *path_join(const char *a, const char *b)
{
	size_t al = strlen(a);
	size_t bl = strlen(b);
	char *p = malloc(al + bl + 2);

	if (!p)
		return NULL;
	memcpy(p, a, al);
	p[al] = '/';
	memcpy(p + al + 1, b, bl + 1);
	return p;
}

static int copy_file(const char *src, const char *dst)
{
	FILE *in = fopen(src, "rb");
	FILE *out;

	if (!in)
		return -1;
	out = fopen(dst, "wb");
	if (!out) {
		fclose(in);
		return -1;
	}
	for (;;) {
		char buf[65536];
		size_t n = fread(buf, 1, sizeof(buf), in);

		if (n && fwrite(buf, 1, n, out) != n) {
			fclose(in);
			fclose(out);
			return -1;
		}
		if (n < sizeof(buf))
			break;
	}
	fclose(in);
	if (fclose(out) != 0)
		return -1;
	return 0;
}

/* ------------------------------------------------------------------ */
/* JSON 比较                                                          */
/* ------------------------------------------------------------------ */
static char *dump_json(const aik_json *v)
{
	char *text = NULL;
	size_t len = 0;

	if (!v || aik_json_dump(v, &text, &len) != 0)
		return NULL;
	return text;
}

static char *memory_canon(const aik_memory *m)
{
	aik_json *d = aik_memory_to_json(m, 1);
	aik_json *nullv = aik_json_new_null();
	char *text;

	if (!d || !nullv ||
	    aik_json_obj_set(d, "region_id", nullv) != 0) {
		aik_json_free(d);
		aik_json_free(nullv);
		return NULL;
	}
	text = dump_json(d);
	aik_json_free(d);
	return text;
}

/* ------------------------------------------------------------------ */
/* 构造小库                                                           */
/* ------------------------------------------------------------------ */
static aik_config *default_cfg(void)
{
	return aik_config_defaults(NULL, 0);
}

static aik_engine *new_engine(aik_config *cfg)
{
	return aik_engine_new(cfg, 1, fixed_now, NULL, seq_id, NULL, NULL, 0);
}

static void small_library(aik_engine *e, char ids[3][16])
{
	aik_json *meta = aik_json_new_obj();
	aik_json *ns = aik_json_new_str("n1");
	aik_memory *m;
	const char *tags[] = { "t1", "t2" };

	aik_json_obj_set(meta, "kind", aik_json_new_str("k1"));
	aik_json_obj_set(meta, "n", aik_json_new_int(7));
	aik_json_obj_set(meta, "ns", ns);
	m = aik_engine_add(e, "alpha memory one", meta, tags, 2, 0.4, NULL,
			   NULL, NULL, NULL, NULL, NULL, 0);
	snprintf(ids[0], 16, "%s", m ? m->id : "");
	m = aik_engine_add(e, "beta memory two", NULL, NULL, 0, 0.9, "seed",
			   ids[0], "reference", NULL, NULL, NULL, 0);
	snprintf(ids[1], 16, "%s", m ? m->id : "");
	m = aik_engine_add(e, "gamma memory three", NULL, NULL, 0, 0.2, NULL,
			   NULL, NULL, NULL, NULL, NULL, 0);
	snprintf(ids[2], 16, "%s", m ? m->id : "");
	aik_json_free(meta);
	if (ids[2][0])
		(void)aik_engine_archive(e, ids[2]);
}

static void set_num(aik_config *c, const char *path, double v)
{
	aik_json *x = aik_json_new_num(v);

	if (x) {
		(void)aik_config_set_dotted(c, path, x);
		aik_json_free(x);
	}
}

static void set_str(aik_config *c, const char *path, const char *v)
{
	aik_json *x = aik_json_new_str(v);

	if (x) {
		(void)aik_config_set_dotted(c, path, x);
		aik_json_free(x);
	}
}

static void set_int(aik_config *c, const char *path, long long v)
{
	aik_json *x = aik_json_new_int(v);

	if (x) {
		(void)aik_config_set_dotted(c, path, x);
		aik_json_free(x);
	}
}

static void disable_autosave(aik_config *c, const char *path)
{
	aik_json *x = aik_json_new_bool(0);

	if (x) {
		(void)aik_config_set_dotted(c, "storage.autosave", x);
		aik_json_free(x);
	}
	set_str(c, "storage.path", path);
}

/*
 * MEM-02a 起，新配置 persistence.enabled=false 的热重建会把迁移后的完整
 * 状态立即 checkpoint 到 storage.path（上游 ed5378a P3-14）。此前本文件的
 * cfg2 指向 /tmp/aik-rebuild-never.json、快照用例沿用向量里的 <TMP>/...，
 * 都默认「重建不落盘」；现在每个用例用自己的临时目录，并在结束时删除。
 */
static char *rebuild_tmpdir(const char *tag)
{
	char tmpl[128];
	char *p;

	snprintf(tmpl, sizeof(tmpl), "/tmp/aik-rebuild-%s-XXXXXX", tag);
	p = mkdtemp(tmpl);
	return p ? strdup(p) : NULL;	/* mkdtemp 返回的是栈上 tmpl，必须拷走 */
}

/* 递归删除本测试自建的临时目录（失败静默，不影响断言） */
static void rm_rf(const char *path)
{
	DIR *d = opendir(path);
	struct dirent *ent;

	if (!d) {
		rmdir(path);
		return;
	}
	while ((ent = readdir(d)) != NULL) {
		char *sub;

		if (strcmp(ent->d_name, ".") == 0 ||
		    strcmp(ent->d_name, "..") == 0)
			continue;
		sub = path_join(path, ent->d_name);
		if (!sub)
			continue;
		if (unlink(sub) != 0)
			rm_rf(sub);
		free(sub);
	}
	closedir(d);
	rmdir(path);
}

static void set_bool(aik_config *c, const char *path, int v)
{
	aik_json *x = aik_json_new_bool(v);

	if (x) {
		(void)aik_config_set_dotted(c, path, x);
		aik_json_free(x);
	}
}

/* ------------------------------------------------------------------ */
/* 1) 小库重建 + 2) 闸门                                              */
/* ------------------------------------------------------------------ */
static void test_small(void)
{
	aik_config *cfg = default_cfg();
	aik_engine *e = new_engine(cfg);
	char ids[3][16] = { { 0 } };
	char *m0, *m1, *m2, *graph;
	aik_json *stats, *graph_dom = NULL;
	aik_json *g = NULL;
	long long splits0, merges0, cons0, comp0, edges0;
	aik_config *cfg2;
	aik_engine *e2 = NULL;
	char *dir;
	char *state = NULL;
	char *state_gz = NULL;
	int rc;

	dir = rebuild_tmpdir("small");
	if (dir) {
		state = path_join(dir, "state.json");
		state_gz = path_join(dir, "state.json.gz");
	}
	check(state && state_gz, "rebuild small: tmpdir");
	if (!state || !state_gz) {
		free(state_gz);
		free(state);
		free(dir);
		aik_engine_free(e);
		return;
	}
	small_library(e, ids);
	m0 = memory_canon(aik_engine_get(e, ids[0]));
	m1 = memory_canon(aik_engine_get(e, ids[1]));
	m2 = memory_canon(aik_engine_get(e, ids[2]));
	(void)aik_engine_graph(e, &graph_dom, NULL, 0);
	graph = dump_json(graph_dom);
	(void)aik_engine_stats(e, &stats, NULL, 0);
	splits0 = aik_json_int(aik_json_get(stats, "splits"));
	merges0 = aik_json_int(aik_json_get(stats, "merges"));
	cons0 = aik_json_int(aik_json_get(stats, "consolidations"));
	comp0 = aik_json_int(aik_json_get(stats, "compressions"));
	edges0 = aik_json_int(aik_json_get(stats, "graph_edges"));
	aik_json_free(stats);

	cfg2 = default_cfg();
	set_num(cfg2, "region.min_join_cosine", 0.5);
	set_str(cfg2, "retrieval.fusion", "weighted");
	set_num(cfg2, "ranking.semantic", 0.5);
	disable_autosave(cfg2, state);
	check(access(state_gz, F_OK) != 0, "rebuild small: snapshot before");
	rc = aik_engine_rebuild(e, cfg2, &e2, NULL, 0);
	check(rc == 0 && e2 != NULL, "rebuild small: rc=%d", rc);
	/*
	 * MEM-02a：新配置 persistence 关闭 → 重建后立即 checkpoint
	 * （storage.compress=true 且路径以 .json 结尾 → 落成 .json.gz）。
	 */
	check(access(state_gz, F_OK) == 0,
	      "rebuild small: MEM-02a checkpoint missing");
	if (e2) {
		char *n0 = memory_canon(aik_engine_get(e2, ids[0]));
		char *n1 = memory_canon(aik_engine_get(e2, ids[1]));
		char *n2 = memory_canon(aik_engine_get(e2, ids[2]));
		char *ngraph = NULL;
		aik_json *nstats = NULL;

		check_ll("small.memories", aik_engine_memory_count(e2), 3);
		check(n0 && m0 && strcmp(n0, m0) == 0, "rebuild m0 changed");
		check(n1 && m1 && strcmp(n1, m1) == 0, "rebuild m1 changed");
		check(n2 && m2 && strcmp(n2, m2) == 0, "rebuild m2 changed");
		(void)aik_engine_graph(e2, &g, NULL, 0);
		ngraph = dump_json(g);
		check(graph && ngraph && strcmp(graph, ngraph) == 0,
		      "rebuild graph changed");
		(void)aik_engine_stats(e2, &nstats, NULL, 0);
		check_ll("small.splits",
			 aik_json_int(aik_json_get(nstats, "splits")),
			 splits0);
		check_ll("small.merges",
			 aik_json_int(aik_json_get(nstats, "merges")),
			 merges0);
		check_ll("small.consolidations",
			 aik_json_int(aik_json_get(nstats, "consolidations")),
			 cons0);
		check_ll("small.compressions",
			 aik_json_int(aik_json_get(nstats, "compressions")),
			 comp0);
		check_ll("small.graph_edges",
			 aik_json_int(aik_json_get(nstats, "graph_edges")),
			 edges0);
		free(n0);
		free(n1);
		free(n2);
		free(ngraph);
		aik_json_free(g);
		aik_json_free(nstats);
	}
	free(m0);
	free(m1);
	free(m2);
	free(graph);
	aik_json_free(graph_dom);

	/* 闸门：mrl_dim 变化（有意修正） */
	{
		aik_config *gate = default_cfg();
		aik_engine *never = NULL;
		char err[768] = { 0 };

		set_int(gate, "embedding.mrl_dim", 512);
		rc = aik_engine_rebuild(e2, gate, &never, err, sizeof(err));
		check(rc == 1, "gate mrl_dim: rc=%d", rc);
		check(never == NULL, "gate mrl_dim: engine not NULL");
		check_has("gate mrl_dim", err, "mrl_dim 0→512");
		check_has("gate mrl_dim", err,
			  "会使现有记忆的向量维度与新配置不一致");
		check_ll("gate mrl_dim.old_intact",
			 (long long)aik_engine_memory_count(e2), 3);
	}

	/* 闸门：provider 变化（基础三元组文案与参考一致） */
	{
		aik_config *gate = default_cfg();
		aik_engine *never = NULL;
		char err[768] = { 0 };

		set_str(gate, "embedding.provider", "openai");
		rc = aik_engine_rebuild(e2, gate, &never, err, sizeof(err));
		check(rc == 1, "gate provider: rc=%d", rc);
		check_has("gate provider", err,
			  "embedding 配置变更（hashing/text-embedding-3-small/64 → openai/text-embedding-3-small/64）");
	}

	/* 闸门：revision / hash_factors / hash_seed */
	{
		aik_config *gate = default_cfg();
		aik_engine *never = NULL;
		char err[768] = { 0 };

		set_str(gate, "embedding.revision", "v2");
		set_int(gate, "embedding.hash_factors", 5);
		set_int(gate, "embedding.hash_seed", 9);
		rc = aik_engine_rebuild(e2, gate, &never, err, sizeof(err));
		check(rc == 1, "gate extra: rc=%d", rc);
		check_has("gate extra", err, "revision \"\"→\"v2\"");
		check_has("gate extra", err, "hash_factors 3→5");
		check_has("gate extra", err, "hash_seed 0→9");
	}

	aik_engine_free(e2);
	aik_engine_free(e);
	rm_rf(dir);
	free(state_gz);
	free(state);
	free(dir);
}

/* ------------------------------------------------------------------ */
/* 3) 空库允许身份变化                                                */
/* ------------------------------------------------------------------ */
static void test_empty(void)
{
	aik_config *cfg = default_cfg();
	aik_engine *e = new_engine(cfg);
	aik_config *cfg2 = default_cfg();
	aik_engine *e2 = NULL;
	char *dir;
	char *state = NULL;
	char *state_gz = NULL;
	long long mrl = -1;
	int rc;

	set_int(cfg2, "embedding.mrl_dim", 512);
	dir = rebuild_tmpdir("empty");
	if (dir) {
		state = path_join(dir, "state.json");
		state_gz = path_join(dir, "state.json.gz");
	}
	check(state && state_gz, "empty rebuild: tmpdir");
	if (!state || !state_gz) {
		free(state_gz);
		free(state);
		free(dir);
		aik_engine_free(e);
		return;
	}
	disable_autosave(cfg2, state);
	rc = aik_engine_rebuild(e, cfg2, &e2, NULL, 0);
	check(rc == 0 && e2 != NULL, "empty rebuild: rc=%d", rc);
	if (e2) {
		check_ll("empty.memories", aik_engine_memory_count(e2), 0);
		(void)aik_config_get_i64(aik_engine_config(e2),
					 "embedding.mrl_dim", &mrl);
		check_ll("empty.mrl_dim", mrl, 512);
	}
	/* MEM-02a：空库同样 checkpoint（只写 JSON 快照，不写 NPZ） */
	check(access(state_gz, F_OK) == 0,
	      "empty rebuild: MEM-02a checkpoint missing");
	aik_engine_free(e2);
	aik_engine_free(e);
	rm_rf(dir);
	free(state_gz);
	free(state);
	free(dir);
}

/* ------------------------------------------------------------------ */
/* 4) 549 条快照：计数器 / archived / 抽样记忆                         */
/* ------------------------------------------------------------------ */
static void test_snapshot(void)
{
	char tmpl[] = "/tmp/aik-rebuild-XXXXXX";
	char *dir = mkdtemp(tmpl);
	char *snap_src, *npz_src, *snap_dst;
	char *npz_dst = NULL;
	char *rebuilt_path = NULL;
	char *rebuilt_gz = NULL;
	aik_snapshot snap;
	const char *emb_name;
	aik_config *cfg;
	aik_engine *e = NULL;
	aik_json *s0 = NULL;
	long long splits0, merges0, cons0, comp0, edges0, archived0;
	char ids[5][16] = { { 0 } };
	char *canon0[5] = { 0 };
	aik_config *cfg2;
	aik_engine *e2 = NULL;
	int rc;
	size_t i;

	memset(&snap, 0, sizeof(snap));
	if (!dir) {
		check(0, "snapshot: mkdtemp failed");
		return;
	}
	snap_src = path_join(vector_root(), "storage/engine.json.gz");
	npz_src = path_join(vector_root(), "storage/engine.embeddings.npz");
	snap_dst = path_join(dir, "engine.json.gz");
	rebuilt_path = path_join(dir, "rebuilt.json");
	rebuilt_gz = path_join(dir, "rebuilt.json.gz");
	check(snap_src && npz_src && snap_dst && rebuilt_path && rebuilt_gz,
	      "snapshot: path join failed");
	if (!snap_src || !npz_src || !snap_dst || !rebuilt_path || !rebuilt_gz)
		goto out;
	memset(&snap, 0, sizeof(snap));
	check(aik_snapshot_load(snap_src, &snap, NULL, 0) == 0,
	      "snapshot: cannot load fixture");
	emb_name = aik_json_str(aik_json_get(snap.root, "embedding_file"));
	check(emb_name != NULL, "snapshot: no embedding_file");
	if (!emb_name) {
		aik_snapshot_free(&snap);
		goto out;
	}
	npz_dst = path_join(dir, emb_name);
	check(npz_dst != NULL, "snapshot: npz path join failed");
	if (!npz_dst) {
		aik_snapshot_free(&snap);
		goto out;
	}
	check(copy_file(snap_src, snap_dst) == 0, "snapshot: copy json failed");
	check(copy_file(npz_src, npz_dst) == 0, "snapshot: copy npz failed");

	cfg = default_cfg();
	e = new_engine(cfg);
	check(aik_engine_load(e, snap_dst, NULL, 0) == 0, "snapshot: load failed");
	(void)aik_engine_stats(e, &s0, NULL, 0);
	splits0 = aik_json_int(aik_json_get(s0, "splits"));
	merges0 = aik_json_int(aik_json_get(s0, "merges"));
	cons0 = aik_json_int(aik_json_get(s0, "consolidations"));
	comp0 = aik_json_int(aik_json_get(s0, "compressions"));
	edges0 = aik_json_int(aik_json_get(s0, "graph_edges"));
	archived0 = aik_json_int(
		aik_json_get(aik_json_get(s0, "memories"), "archived"));
	for (i = 0; i < 5; i++) {
		const aik_memory *m = aik_engine_memory_at(e, i);

		if (!m)
			break;
		snprintf(ids[i], 16, "%s", m->id);
		canon0[i] = memory_canon(m);
	}

	/*
	 * 用当前配置副本 + 无害改动重建。storage.path 指回本用例的临时目录：
	 * MEM-02a 起重建会落盘，不能沿用快照内嵌配置里的 <TMP>/... 路径。
	 */
	cfg2 = aik_config_from_json(aik_config_dom(aik_engine_config(e)), NULL, 0);
	check(cfg2 != NULL, "snapshot: config clone failed");
	if (cfg2) {
		aik_json *noauto = aik_json_new_bool(0);

		set_num(cfg2, "region.min_join_cosine", 0.5);
		set_str(cfg2, "storage.path", rebuilt_path);
		if (noauto) {
			(void)aik_config_set_dotted(cfg2, "storage.autosave",
						    noauto);
			aik_json_free(noauto);
		}
		rc = aik_engine_rebuild(e, cfg2, &e2, NULL, 0);
		check(rc == 0 && e2 != NULL, "snapshot rebuild: rc=%d", rc);
		check(access(rebuilt_gz, F_OK) == 0,
		      "snapshot rebuild: MEM-02a checkpoint missing");
	}
	if (e2) {
		aik_json *s1 = NULL;
		long long archived1;

		check_ll("snapshot.memories", aik_engine_memory_count(e2),
			 549);
		(void)aik_engine_stats(e2, &s1, NULL, 0);
		check_ll("snapshot.splits",
			 aik_json_int(aik_json_get(s1, "splits")), splits0);
		check_ll("snapshot.merges",
			 aik_json_int(aik_json_get(s1, "merges")), merges0);
		check_ll("snapshot.consolidations",
			 aik_json_int(aik_json_get(s1, "consolidations")),
			 cons0);
		check_ll("snapshot.compressions",
			 aik_json_int(aik_json_get(s1, "compressions")),
			 comp0);
		check_ll("snapshot.graph_edges",
			 aik_json_int(aik_json_get(s1, "graph_edges")),
			 edges0);
		archived1 = aik_json_int(
			aik_json_get(aik_json_get(s1, "memories"), "archived"));
		check_ll("snapshot.archived", archived1, archived0);
		check_ll("snapshot.archived", archived1, 10);
		for (i = 0; i < 5; i++) {
			char *now;

			if (!ids[i][0])
				break;
			now = memory_canon(aik_engine_get(e2, ids[i]));
			check(now && canon0[i] &&
				      strcmp(now, canon0[i]) == 0,
			      "snapshot memory[%zu] changed", i);
			free(now);
		}
		aik_json_free(s1);
	}
out:
	for (i = 0; i < 5; i++)
		free(canon0[i]);
	aik_json_free(s0);
	aik_engine_free(e2);
	aik_engine_free(e);
	aik_snapshot_free(&snap);
	free(npz_dst);
	free(rebuilt_gz);
	free(rebuilt_path);
	free(snap_dst);
	free(npz_src);
	free(snap_src);
	rm_rf(dir);	/* dir 指向栈上的 tmpl，不能 free */
}

/* ------------------------------------------------------------------ */
/* 5) MEM-02a：热重建后持久化关闭 → 立即 checkpoint                     */
/* ------------------------------------------------------------------ */

/*
 * 上游 ed5378a sme/api/server.py::rebuild_engine_with（P3-14）：迁移
 * （export → new → import）之后，若**新配置** persistence.enabled 为假，
 * 立即 new_engine.save()；落盘失败则整体失败、旧引擎保持原配置。对应
 * 上游回归 experiment/regression/test_fix_round2_20261120.py::
 * test_rebuild_persistence_off_checkpoints_to_disk（persistence True→False，
 * PUT /config 之后磁盘上的恢复存储必须含全部记忆）。
 *
 * C 版语义：persistence.enabled=false 时重启后不重放 WAL（aik_engine_load
 * 只在启用时 replay），自上次 checkpoint 以来的写入只在内存里；热重建换
 * 进来的新引擎 autosave 计数从 0 起，这段未落盘的写入要多等一个完整的
 * autosave 间隔才有机会落盘。重建即 checkpoint 关掉这个窗口。
 * persistence.enabled=true 时与上游一致：不额外 save（WAL 续写，bulk
 * import 自带 checkpoint）。
 */
static void test_mem02a_checkpoint(void)
{
	char *dir = rebuild_tmpdir("m02a");
	char *state = NULL;
	char *state_gz = NULL;
	char *wal_state = NULL;
	char *wal_gz = NULL;
	char *blocked = NULL;
	aik_config *cfg;
	aik_engine *e;
	aik_engine *e2 = NULL;
	char ids[3][16] = { { 0 } };
	char *texts[3] = { NULL, NULL, NULL };
	char err[768];
	int rc;
	size_t i;

	if (!dir) {
		check(0, "mem02a: mkdtemp failed");
		return;
	}
	state = path_join(dir, "state.json");
	state_gz = path_join(dir, "state.json.gz");
	wal_state = path_join(dir, "wal.json");
	wal_gz = path_join(dir, "wal.json.gz");
	blocked = path_join(dir, "blocked");
	check(state && state_gz && wal_state && wal_gz && blocked,
	      "mem02a: path join failed");
	if (!state || !state_gz || !wal_state || !wal_gz || !blocked)
		goto out;

	/* a) persistence 一直关（出厂默认）：重建前无快照，重建后立即有 */
	cfg = default_cfg();
	disable_autosave(cfg, state);
	e = new_engine(cfg);
	small_library(e, ids);
	for (i = 0; i < 3; i++) {
		const aik_memory *m = aik_engine_get(e, ids[i]);

		if (m && m->text)
			texts[i] = strdup(m->text);
	}
	check(access(state_gz, F_OK) != 0, "mem02a: snapshot before rebuild");
	{
		aik_config *cfg2 = default_cfg();
		aik_config *cfg3 = default_cfg();
		aik_engine *fresh;
		int same = 1;

		set_num(cfg2, "region.min_join_cosine", 0.5);
		disable_autosave(cfg2, state);
		err[0] = '\0';
		rc = aik_engine_rebuild(e, cfg2, &e2, err, sizeof(err));
		check(rc == 0 && e2 != NULL, "mem02a: rebuild rc=%d err=%s", rc,
		      err);
		check(access(state_gz, F_OK) == 0,
		      "mem02a: checkpoint after rebuild missing");
		/* 重启等价：新引擎从恢复存储路径 load，记忆一条不少 */
		disable_autosave(cfg3, state);
		fresh = new_engine(cfg3);
		if (!fresh) {
			check(0, "mem02a: fresh engine");
		} else {
			err[0] = '\0';
			rc = aik_engine_load(fresh, state_gz, err, sizeof(err));
			check(rc == 0, "mem02a: load checkpoint rc=%d err=%s", rc,
			      err);
			check_ll("mem02a: reloaded memories",
				 (long long)aik_engine_memory_count(fresh), 3);
			for (i = 0; i < 3; i++) {
				const aik_memory *m = aik_engine_get(fresh, ids[i]);

				if (!m || !m->text || !texts[i] ||
				    strcmp(m->text, texts[i]) != 0)
					same = 0;
			}
			check(same, "mem02a: reloaded memories differ");
			aik_engine_free(fresh);
		}
	}
	aik_engine_free(e2);
	e2 = NULL;
	aik_engine_free(e);
	for (i = 0; i < 3; i++) {
		free(texts[i]);
		texts[i] = NULL;
	}

	/* b) 落盘失败（父路径被普通文件占住）→ 整体失败、旧引擎原封不动 */
	cfg = default_cfg();
	disable_autosave(cfg, state);
	e = new_engine(cfg);
	small_library(e, ids);
	{
		FILE *f = fopen(blocked, "wb");

		check(f != NULL, "mem02a: cannot create blocker");
		if (f)
			fclose(f);
	}
	if (access(blocked, F_OK) == 0) {
		aik_config *cfg2 = default_cfg();
		char *bad = path_join(blocked, "engine.json");

		disable_autosave(cfg2, bad);
		err[0] = '\0';
		rc = aik_engine_rebuild(e, cfg2, &e2, err, sizeof(err));
		check(rc == 2, "mem02a(blocked): rc=%d exp 2", rc);
		check(e2 == NULL, "mem02a(blocked): out must be NULL");
		/* 文案与上游 ConfigApplyError 一致，且不再套「应用配置失败」前缀 */
		check_has("mem02a(blocked)", err,
			  "persistence 关闭模式下 checkpoint 落盘失败，引擎保持原配置：");
		check(err[0] != '\0' &&
			  strncmp(err, "应用配置失败", strlen("应用配置失败")) != 0,
		      "mem02a(blocked): err must not use the generic prefix");
		check_ll("mem02a(blocked): old engine intact",
			 (long long)aik_engine_memory_count(e), 3);
		for (i = 0; i < 3; i++)
			check(aik_engine_get(e, ids[i]) != NULL,
			      "mem02a(blocked): old memory[%zu] lost", i);
		free(bad);
	}
	aik_engine_free(e);

	/* c) persistence 开着（file backend / fsync WAL）：重建成功且状态已落盘
	 *    （bulk import 的 checkpoint，不是本项新增的 save） */
	cfg = default_cfg();
	disable_autosave(cfg, wal_state);
	set_bool(cfg, "persistence.enabled", 1);
	e = new_engine(cfg);
	small_library(e, ids);
	check(access(wal_gz, F_OK) != 0, "mem02a(wal): snapshot before rebuild");
	{
		aik_config *cfg2 = default_cfg();

		set_bool(cfg2, "persistence.enabled", 1);
		disable_autosave(cfg2, wal_state);
		set_num(cfg2, "region.min_join_cosine", 0.5);
		err[0] = '\0';
		rc = aik_engine_rebuild(e, cfg2, &e2, err, sizeof(err));
		check(rc == 0 && e2 != NULL, "mem02a(wal): rebuild rc=%d err=%s",
		      rc, err);
		check(access(wal_gz, F_OK) == 0,
		      "mem02a(wal): snapshot after rebuild missing");
	}
	aik_engine_free(e2);
	aik_engine_free(e);

out:
	for (i = 0; i < 3; i++)
		free(texts[i]);
	unlink(blocked);
	free(blocked);
	free(wal_gz);
	free(wal_state);
	free(state_gz);
	free(state);
	rm_rf(dir);
	free(dir);
}

int main(void)
{
	test_small();
	test_empty();
	test_snapshot();
	test_mem02a_checkpoint();
	printf("test_rebuild: %d checks, %d failed\n", g_checks, g_failed);
	return g_failed ? 1 : 0;
}
