/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_store_snapshot.c - store_snapshot 自测（T2a 门禁）
 *
 * 覆盖（真读 parity 向量，AIK_STORE_VECTORS 默认
 * $HOME/aikernel-longterm/parity/vectors/storage）：
 *   1) engine.json.gz：load → validate 通过；
 *   2) aik_json_dump(root) 与 snapshot.canonical.json 逐字节相等
 *      （6,897,081 字节），失败打印首个差异 offset 与前后 40 字节；
 *   3) memories/regions/region_edges/memory_edges 计数、schema_version、
 *      embedding_file 与 snapshot.meta.json 一致（含绝对值断言）；
 *   4) 负向：$TMPDIR 下截断 gz → load 失败；embedding_file 改成
 *      "../escape.npz" 等路径形态 → validate 失败（合法 basename 仍通过）；
 *      缺字段 / 类型错 / schema_version!=2 → validate 失败；
 *   5) aik_gzip_deflate → aik_gzip_inflate 往返等于原文本，且 gzip 头
 *      第 4..7 字节为 0（mtime=0）。
 *
 * 末行 "SUMMARY snapshot checked=... mismatch=... bytes=..."，有失配退出
 * 码非 0。
 */
#define _GNU_SOURCE 1

#include "store/store_gzip.h"
#include "store/store_json.h"
#include "store/store_snapshot.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static const char *vectors_dir(void)
{
	const char *d = getenv("AIK_STORE_VECTORS");
	static char buf[8192];

	if (d && *d)
		return d;
	(void)snprintf(buf, sizeof(buf), "%s/aikernel-longterm/parity/vectors/storage",
		       getenv("HOME") ? getenv("HOME") : ".");
	return buf;
}

static char *vpath_alloc(const char *name)
{
	const char *dir = vectors_dir();
	size_t dl = strlen(dir), nl = strlen(name);
	char *p = malloc(dl + 1 + nl + 1);

	if (!p)
		return NULL;
	memcpy(p, dir, dl);
	p[dl] = '/';
	memcpy(p + dl + 1, name, nl + 1);
	return p;
}

static char *join_path(const char *dir, const char *name)
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

static int write_file(const char *path, const void *data, size_t len)
{
	FILE *f = fopen(path, "wb");
	int ok;

	if (!f)
		return -1;
	ok = fwrite(data, 1, len, f) == len;
	fclose(f);
	return ok ? 0 : -1;
}

static char *make_tmpdir(void)
{
	const char *base = getenv("TMPDIR");
	char tmpl[8192];
	size_t n;

	if (!base || !*base)
		base = "/tmp";
	n = (size_t)snprintf(tmpl, sizeof(tmpl), "%s/aiksnap.XXXXXX", base);
	if (n >= sizeof(tmpl))
		return NULL;
	if (!mkdtemp(tmpl))
		return NULL;
	return strdup(tmpl);
}

static void print_rss(void)
{
	FILE *f = fopen("/proc/self/status", "r");
	char line[256];
	unsigned long cur = 0, peak = 0;

	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "VmRSS:", 6) == 0)
			cur = strtoul(line + 6, NULL, 10);
		else if (strncmp(line, "VmHWM:", 6) == 0)
			peak = strtoul(line + 6, NULL, 10);
	}
	fclose(f);
	printf("RSS: current=%lu kB peak=%lu kB\n", cur, peak);
}

/* ------------------------------------------------------------------ */
/* meta 读取小工具                                                     */
/* ------------------------------------------------------------------ */

static const char *jstr(const aik_json *o, const char *k)
{
	const char *s = aik_json_str(aik_json_get(o, k));

	return s ? s : "";
}

static long long jint(const aik_json *o, const char *k)
{
	return aik_json_int(aik_json_get(o, k));
}

/* ------------------------------------------------------------------ */
/* 差异定位                                                            */
/* ------------------------------------------------------------------ */

static void report_diff(const unsigned char *got, size_t gn,
			const unsigned char *want, size_t wn)
{
	size_t i, n = gn < wn ? gn : wn;
	size_t from, to;

	for (i = 0; i < n; i++) {
		if (got[i] != want[i])
			break;
	}
	if (i == n && gn == wn)
		return;
	report("canonical mismatch at offset %zu (dump %zu bytes, canonical %zu)",
	       i, gn, wn);
	from = i > 40 ? i - 40 : 0;
	to = i + 40 < gn ? i + 40 : gn;
	fprintf(stderr, "  dump[%zu..%zu]: ", from, to);
	if (to > from)
		(void)fwrite(got + from, 1, to - from, stderr);
	fprintf(stderr, "\n");
	to = i + 40 < wn ? i + 40 : wn;
	fprintf(stderr, "  canon[%zu..%zu]: ", from, to);
	if (to > from)
		(void)fwrite(want + from, 1, to - from, stderr);
	fprintf(stderr, "\n");
}

/* ------------------------------------------------------------------ */
/* 临时快照构造                                                        */
/* ------------------------------------------------------------------ */

/*
 * 生成一个结构最小但齐全的快照 JSON：embedding_file 可控、schema_version
 * 可控、regions 可故意写成 null（类型错）。
 */
static void build_snap(char *buf, size_t buflen, const char *emb, int ver,
		       int regions_ok)
{
	(void)snprintf(buf, buflen,
		       "{\"schema_version\":%d,\"counters\":{},"
		       "\"config\":{\"x\":1},\"memories\":[],"
		       "\"regions\":%s,\"region_edges\":[],"
		       "\"memory_edges\":[],\"module_state\":{},"
		       "\"wal_sequence\":0,\"embedding_file\":\"%s\","
		       "\"embedding_generation\":\"g\"}",
		       ver, regions_ok ? "[]" : "null", emb);
}

/* ------------------------------------------------------------------ */
/* 正向检查                                                            */
/* ------------------------------------------------------------------ */

static void check_top_keys(const aik_snapshot *s, const aik_json *meta)
{
	const aik_json *keys = aik_json_get(meta, "top_level_keys");
	size_t n = aik_json_count(keys), i;

	CHECK(n == 11);
	CHECK(aik_json_count(s->root) == n);
	for (i = 0; i < n; i++) {
		const char *want = aik_json_str(aik_json_at(keys, i));
		const char *got = aik_json_key_at(s->root, i);

		if (!want || !got || strcmp(want, got) != 0)
			report("top_level_keys[%zu]: %s != %s", i,
			       got ? got : "(null)", want ? want : "(null)");
		else
			CHECK(1);
	}
}

static void check_counts(const aik_snapshot *s, const aik_json *meta)
{
	const aik_json *counts = aik_json_get(meta, "counts");
	const aik_json *root = s->root;
	const aik_json *emb;
	const char *name;
	long long n_mem, n_reg, n_re, n_me;

	n_mem = (long long)aik_json_count(aik_json_get(root, "memories"));
	n_reg = (long long)aik_json_count(aik_json_get(root, "regions"));
	n_re = (long long)aik_json_count(aik_json_get(root, "region_edges"));
	n_me = (long long)aik_json_count(aik_json_get(root, "memory_edges"));

	/* 绝对值（meta 若被篡改也能发现） */
	CHECK(n_mem == 549);
	CHECK(n_reg == 226);
	CHECK(n_re == 1487);
	CHECK(n_me == 0);
	/* 与 meta 一致 */
	CHECK(n_mem == jint(counts, "memories"));
	CHECK(n_reg == jint(counts, "regions"));
	CHECK(n_re == jint(counts, "region_edges"));
	CHECK(n_me == jint(counts, "memory_edges"));
	CHECK(aik_json_int(aik_json_get(root, "schema_version")) == 2);
	CHECK(aik_json_int(aik_json_get(root, "schema_version")) ==
	      jint(meta, "schema_version"));

	emb = aik_json_get(root, "embedding_file");
	name = aik_json_str(emb);
	CHECK(name != NULL);
	if (name) {
		CHECK(strcmp(name, jstr(meta, "embedding_file")) == 0);
		CHECK(strchr(name, '/') == NULL);
		CHECK(strchr(name, 0x5c) == NULL);
		CHECK(strstr(name, "..") == NULL);
		printf("embedding_file: %s\n", name);
	}
	printf("counts: memories=%lld regions=%lld region_edges=%lld memory_edges=%lld\n",
	       n_mem, n_reg, n_re, n_me);
}

static void test_positive(const char *gzpath, const char *canonpath,
			  const aik_json *meta)
{
	aik_snapshot s;
	char err[256] = "";
	unsigned char *canon = NULL;
	char *out = NULL;
	size_t outlen = 0, cn = 0;
	int rc;

	printf("load: %s\n", gzpath);
	rc = aik_snapshot_load(gzpath, &s, err, sizeof(err));
	CHECK(rc == 0);
	if (rc != 0) {
		report("load failed: %s", err);
		return;
	}
	CHECK(s.json_len > 0);
	CHECK(s.json != NULL && s.json[s.json_len] == '\0');
	CHECK(s.root != NULL);

	rc = aik_snapshot_validate(&s, err, sizeof(err));
	CHECK(rc == 0);
	if (rc != 0)
		report("validate failed: %s", err);
	else
		printf("validate: ok (json %zu bytes)\n", s.json_len);

	CHECK(aik_json_dump(s.root, &out, &outlen) == 0);
	if (!out) {
		report("dump failed");
		aik_snapshot_free(&s);
		return;
	}
	g_bytes = outlen;

	canon = read_file(canonpath, &cn);
	CHECK(canon != NULL);
	if (canon) {
		CHECK((size_t)jint(meta, "canonical_bytes") == cn);
		CHECK(cn == 6897081);
		if (outlen != cn || memcmp(out, canon, cn) != 0)
			report_diff((const unsigned char *)out, outlen, canon, cn);
		else
			CHECK(1);
		printf("canonical: %zu bytes, dump %zu bytes, byte-identical=%s\n",
		       cn, outlen, (outlen == cn && memcmp(out, canon, cn) == 0) ?
		       "yes" : "no");
	}

	check_top_keys(&s, meta);
	check_counts(&s, meta);

	free(out);
	free(canon);
	aik_snapshot_free(&s);
}

/* ------------------------------------------------------------------ */
/* gzip 往返                                                           */
/* ------------------------------------------------------------------ */

static void test_roundtrip(const aik_snapshot *s)
{
	const char *small = "hello gzip multi member\n";
	unsigned char *gz = NULL, *g2 = NULL, *back = NULL, *cat = NULL;
	size_t gzn = 0, g2n = 0, backn = 0;
	char err[256] = "";

	CHECK(aik_gzip_deflate(s->json, s->json_len, 9, &gz, &gzn,
			       err, sizeof(err)) == 0);
	if (!gz) {
		report("deflate failed: %s", err);
		return;
	}
	CHECK(gzn > 18);
	CHECK(gz[0] == 0x1f && gz[1] == 0x8b);
	CHECK(gz[2] == 8);
	CHECK(gz[3] == 0);	/* 无 FNAME */
	CHECK(gz[4] == 0 && gz[5] == 0 && gz[6] == 0 && gz[7] == 0);
	printf("gzip: deflate %zu -> %zu bytes, header %02x %02x %02x %02x %02x %02x %02x %02x\n",
	       s->json_len, gzn, gz[0], gz[1], gz[2], gz[3], gz[4], gz[5],
	       gz[6], gz[7]);

	CHECK(aik_gzip_inflate(gz, gzn, &back, &backn, err, sizeof(err)) == 0);
	CHECK(backn == s->json_len);
	CHECK(back != NULL && memcmp(back, s->json, s->json_len) == 0);
	CHECK(aik_gzip_inflate(NULL, 0, &back, &backn, err, sizeof(err)) != 0);
	free(back);
	back = NULL;
	free(gz);
	gz = NULL;

	/* 多 member：两个独立 gzip 串联后一次解压 */
	CHECK(aik_gzip_deflate(small, strlen(small), 9, &gz, &gzn,
			       err, sizeof(err)) == 0);
	CHECK(aik_gzip_deflate(small, strlen(small), 9, &g2, &g2n,
			       err, sizeof(err)) == 0);
	if (gz && g2) {
		cat = malloc(gzn + g2n);
		CHECK(cat != NULL);
		if (cat) {
			memcpy(cat, gz, gzn);
			memcpy(cat + gzn, g2, g2n);
			CHECK(aik_gzip_inflate(cat, gzn + g2n, &back, &backn,
					       err, sizeof(err)) == 0);
			CHECK(backn == 2 * strlen(small));
			CHECK(back && memcmp(back, small, strlen(small)) == 0);
			printf("gzip: multi-member %zu+%zu -> %zu bytes ok\n",
			       gzn, g2n, backn);
		}
	}
	free(cat);
	free(back);
	free(gz);
	free(g2);
}

/* ------------------------------------------------------------------ */
/* 负向检查                                                            */
/* ------------------------------------------------------------------ */

static void test_negative_gz(const char *gzpath, const char *dir)
{
	aik_snapshot s;
	char err[256] = "";
	unsigned char *orig;
	size_t olen = 0;
	char *p = join_path(dir, "truncated.json.gz");
	int rc;

	orig = read_file(gzpath, &olen);
	CHECK(orig != NULL);
	CHECK(p != NULL);
	if (!orig || !p) {
		free(orig);
		free(p);
		return;
	}
	CHECK(olen > 200);
	CHECK(write_file(p, orig, olen - 100) == 0);
	memset(&s, 0, sizeof(s));
	rc = aik_snapshot_load(p, &s, err, sizeof(err));
	CHECK(rc != 0);
	printf("negative: truncated gz -> %d (%s)\n", rc,
	       rc ? err : "loaded!");
	aik_snapshot_free(&s);
	(void)unlink(p);

	CHECK(write_file(p, "not a gzip at all", 17) == 0);
	memset(&s, 0, sizeof(s));
	rc = aik_snapshot_load(p, &s, err, sizeof(err));
	CHECK(rc != 0);
	printf("negative: non-gzip .gz -> %d (%s)\n", rc, rc ? err : "loaded!");
	aik_snapshot_free(&s);
	(void)unlink(p);

	/* 明文 JSON 路径：坏语法必须失败 */
	{
		char *q = join_path(dir, "broken.json");
		const char *bad = "{\"schema_version\":2,";

		CHECK(write_file(q, bad, strlen(bad)) == 0);
		memset(&s, 0, sizeof(s));
		rc = aik_snapshot_load(q, &s, err, sizeof(err));
		CHECK(rc != 0);
		printf("negative: broken json -> %d (%s)\n", rc,
		       rc ? err : "loaded!");
		aik_snapshot_free(&s);
		(void)unlink(q);
		free(q);
	}
	free(orig);
	free(p);
}

static void expect_validate(const char *dir, const char *tag, const char *emb,
			    int ver, int regions_ok, int want_ok)
{
	char *p = join_path(dir, "snap.json");
	char buf[2048];
	aik_snapshot s;
	char err[256] = "";
	int rc;

	if (!p) {
		report("out of memory");
		return;
	}
	build_snap(buf, sizeof(buf), emb, ver, regions_ok);
	CHECK(write_file(p, buf, strlen(buf)) == 0);
	memset(&s, 0, sizeof(s));
	rc = aik_snapshot_load(p, &s, err, sizeof(err));
	CHECK(rc == 0);
	if (rc != 0) {
		report("%s: load failed: %s", tag, err);
		free(p);
		return;
	}
	rc = aik_snapshot_validate(&s, err, sizeof(err));
	CHECK(want_ok ? (rc == 0) : (rc != 0));
	if (want_ok && rc != 0)
		report("%s: validate should pass but: %s", tag, err);
	if (!want_ok && rc == 0)
		report("%s: validate should fail but passed", tag);
	printf("negative: %-14s validate=%d (%s)\n", tag, rc,
	       rc ? err : "ok");
	aik_snapshot_free(&s);
	(void)unlink(p);
	free(p);
}

static void test_negative_json(const char *dir)
{
	char bs[32];

	CHECK((size_t)snprintf(bs, sizeof(bs), "a%cb.npz", 0x5c) < sizeof(bs));
	expect_validate(dir, "control", "engine.npz", 2, 1, 1);
	expect_validate(dir, "traversal", "../escape.npz", 2, 1, 0);
	expect_validate(dir, "dotdot", "..", 2, 1, 0);
	expect_validate(dir, "subdir", "sub/escape.npz", 2, 1, 0);
	expect_validate(dir, "backslash", bs, 2, 1, 0);
	expect_validate(dir, "empty", "", 2, 1, 0);
	expect_validate(dir, "schema", "engine.npz", 3, 1, 0);
	expect_validate(dir, "regions", "engine.npz", 2, 0, 0);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
	char *gzpath = vpath_alloc("engine.json.gz");
	char *canonpath = vpath_alloc("snapshot.canonical.json");
	char *metapath = vpath_alloc("snapshot.meta.json");
	unsigned char *mbuf;
	size_t mlen = 0;
	char err[256] = "";
	aik_json *meta;
	const aik_json *snap;
	aik_snapshot s;
	char *dir;

	printf("vectors: %s\n", vectors_dir());
	if (!gzpath || !canonpath || !metapath) {
		report("out of memory");
		return 1;
	}
	mbuf = read_file(metapath, &mlen);
	if (!mbuf) {
		report("cannot read %s", metapath);
		free(gzpath);
		free(canonpath);
		free(metapath);
		return 1;
	}
	meta = aik_json_parse((const char *)mbuf, mlen, err, sizeof(err));
	free(mbuf);
	if (!meta) {
		report("meta parse failed: %s", err);
		free(gzpath);
		free(canonpath);
		free(metapath);
		return 1;
	}
	snap = aik_json_get(meta, "snapshot");
	CHECK(snap != NULL);

	test_positive(gzpath, canonpath, snap);

	/* roundtrip 需要一份解压后的文本，单独再 load 一次 */
	memset(&s, 0, sizeof(s));
	if (aik_snapshot_load(gzpath, &s, err, sizeof(err)) == 0) {
		test_roundtrip(&s);
		aik_snapshot_free(&s);
	} else {
		report("reload for roundtrip failed: %s", err);
	}

	dir = make_tmpdir();
	if (!dir) {
		report("cannot create tmpdir");
	} else {
		printf("negative: tmpdir %s\n", dir);
		test_negative_gz(gzpath, dir);
		test_negative_json(dir);
		(void)rmdir(dir);
		free(dir);
	}

	print_rss();
	printf("SUMMARY snapshot checked=%d mismatch=%d bytes=%zu\n",
	       g_checked, g_mismatch, g_bytes);

	aik_json_free(meta);
	free(gzpath);
	free(canonpath);
	free(metapath);
	return g_mismatch ? 1 : 0;
}
