/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_store_wal.c - store_wal 自测（T2b-1 门禁）
 *
 * 覆盖（真读 parity 向量，AIK_PARITY_VECTORS 默认
 * $HOME/aikernel-longterm/parity/vectors）：
 *   1) wal.vectors.json 每行 parsed → aik_wal_append（fsync_each=1）到
 *      临时文件，整文件与 wal/engine.json.wal.lf 逐字节相等（2,347 B），
 *      sha256 与向量 wal.sha256_lf 相等；顺带核对 dump(parsed) 与向量
 *      raw 一致；
 *   2) replay：checkpoint=7 → 两次回调（seq 8/9，顺序 add/transaction）；
 *      checkpoint=9 → 0 次；checkpoint=8 → 1 次；另对原始 CRLF 的
 *      engine.json.wal 跑 replay，必须接受并恢复 2 条（读取兼容）；
 *   3) 边界语义（对齐参考 replay）：空行/纯空白行跳过；缺失 seq 视为
 *      0 且不被 checkpoint 跳过；文件不存在返回 0、不写 err；
 *   4) 损坏：截断最后一行 → replay -1 且文件大小不变；把首行
 *      "seq":8 改成 "seq":-1 → replay -1（同样不落盘任何修改）。
 *
 * 末行 "SUMMARY wal checked=... mismatch=... bytes=..."，有失配退出码非 0。
 */
#define _POSIX_C_SOURCE 200809L

#include "store/store_json.h"
#include "store/store_wal.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

static int write_file(const char *path, const void *data, size_t len)
{
	FILE *f = fopen(path, "wb");
	int ok;

	if (!f)
		return -1;
	ok = fwrite(data, 1, len, f) == len;
	if (fclose(f) != 0)
		ok = 0;
	return ok ? 0 : -1;
}

static char *make_tmpdir(void)
{
	const char *base = getenv("TMPDIR");
	char tmpl[8192];
	size_t n;

	if (!base || !*base)
		base = "/tmp";
	n = (size_t)snprintf(tmpl, sizeof(tmpl), "%s/aikwal.XXXXXX", base);
	if (n >= sizeof(tmpl))
		return NULL;
	if (!mkdtemp(tmpl))
		return NULL;
	return strdup(tmpl);
}

static long find_bytes(const unsigned char *hay, size_t hn,
		       const unsigned char *needle, size_t nn)
{
	size_t i;

	if (nn == 0 || hn < nn)
		return -1;
	for (i = 0; i + nn <= hn; i++) {
		if (hay[i] == needle[0] && memcmp(hay + i, needle, nn) == 0)
			return (long)i;
	}
	return -1;
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
/* SHA-256（仅测试用，避免给库引入额外依赖）                            */
/* ------------------------------------------------------------------ */

struct sha256_ctx {
	uint32_t h[8];
	uint64_t total;
	unsigned char buf[64];
	size_t used;
};

static const uint32_t sha_k[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
	0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
	0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
	0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
	0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
	0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
	0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
	0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
	0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
	0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
	0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
	0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
	0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
	0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
	0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
	0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(struct sha256_ctx *c, const unsigned char *p)
{
	uint32_t w[64], a, b, cc, d, e, f, g, h, t1, t2;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = ((uint32_t)p[4 * i] << 24) |
		       ((uint32_t)p[4 * i + 1] << 16) |
		       ((uint32_t)p[4 * i + 2] << 8) |
		       (uint32_t)p[4 * i + 3];
	for (i = 16; i < 64; i++) {
		uint32_t s0 = ROR32(w[i - 15], 7) ^ ROR32(w[i - 15], 18) ^
			      (w[i - 15] >> 3);
		uint32_t s1 = ROR32(w[i - 2], 17) ^ ROR32(w[i - 2], 19) ^
			      (w[i - 2] >> 10);

		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
	e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
	for (i = 0; i < 64; i++) {
		uint32_t s1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t s0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
		uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);

		t1 = h + s1 + ch + sha_k[i] + w[i];
		t2 = s0 + maj;
		h = g; g = f; f = e; e = d + t1;
		d = cc; cc = b; b = a; a = t1 + t2;
	}
	c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
	c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(struct sha256_ctx *c)
{
	static const uint32_t iv[8] = {
		0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
		0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
	};

	memcpy(c->h, iv, sizeof(iv));
	c->total = 0;
	c->used = 0;
}

static void sha256_update(struct sha256_ctx *c, const void *data, size_t len)
{
	const unsigned char *p = data;

	c->total += len;
	while (len > 0) {
		size_t n = 64 - c->used;

		if (n > len)
			n = len;
		memcpy(c->buf + c->used, p, n);
		c->used += n;
		p += n;
		len -= n;
		if (c->used == 64) {
			sha256_block(c, c->buf);
			c->used = 0;
		}
	}
}

static void sha256_final(struct sha256_ctx *c, unsigned char out[32])
{
	uint64_t bits = c->total * 8;
	unsigned char pad[72];
	unsigned char lenbe[8];
	size_t padlen;
	int i;

	memset(pad, 0, sizeof(pad));
	pad[0] = 0x80;
	padlen = (c->used < 56) ? (56 - c->used) : (120 - c->used);
	sha256_update(c, pad, padlen);
	for (i = 0; i < 8; i++)
		lenbe[i] = (unsigned char)(bits >> (56 - 8 * i));
	sha256_update(c, lenbe, 8);
	for (i = 0; i < 8; i++) {
		out[4 * i] = (unsigned char)(c->h[i] >> 24);
		out[4 * i + 1] = (unsigned char)(c->h[i] >> 16);
		out[4 * i + 2] = (unsigned char)(c->h[i] >> 8);
		out[4 * i + 3] = (unsigned char)c->h[i];
	}
}

static void sha256_hex(const void *data, size_t len, char out[65])
{
	struct sha256_ctx c;
	unsigned char d[32];
	int i;

	sha256_init(&c);
	sha256_update(&c, data, len);
	sha256_final(&c, d);
	for (i = 0; i < 32; i++)
		(void)snprintf(out + 2 * i, 3, "%02x", d[i]);
}

/* ------------------------------------------------------------------ */
/* replay 回调                                                         */
/* ------------------------------------------------------------------ */

struct replay_ctx {
	int count;
	long long seqs[16];
	char ops[16][32];
};

static int replay_cb(void *ctx, const aik_json *op, char *err, size_t errlen)
{
	struct replay_ctx *c = ctx;
	const aik_json *seq = aik_json_get(op, "seq");
	const char *name = aik_json_str(aik_json_get(op, "op"));
	long long v = 0;

	if (seq) {
		if (aik_json_typeof(seq) != AIK_JSON_INT) {
			(void)snprintf(err, errlen, "callback: bad seq");
			return -1;
		}
		v = aik_json_int(seq);
		if (v < 0) {
			(void)snprintf(err, errlen, "callback: negative seq");
			return -1;
		}
	}
	if (c->count >= 16) {
		(void)snprintf(err, errlen, "callback: too many records");
		return -1;
	}
	c->seqs[c->count] = v;
	(void)snprintf(c->ops[c->count], sizeof(c->ops[0]), "%s",
		       name ? name : "");
	c->count++;
	return 0;
}

static void expect_replay(const char *path, long long checkpoint,
			  int want_rc, int want_count, long long want_first)
{
	struct replay_ctx c;
	char err[256] = "";
	int rc;

	memset(&c, 0, sizeof(c));
	rc = aik_wal_replay(path, checkpoint, replay_cb, &c, err, sizeof(err));
	g_checked++;
	if (rc != want_rc)
		report("replay(%s, %lld) rc=%d, want %d (%s)", path, checkpoint,
		       rc, want_rc, err);
	g_checked++;
	if (c.count != want_count)
		report("replay(%s, %lld) callbacks=%d, want %d", path,
		       checkpoint, c.count, want_count);
	if (want_count > 0) {
		g_checked++;
		if (c.seqs[0] != want_first)
			report("replay(%s, %lld) first seq=%lld, want %lld", path,
			       checkpoint, c.seqs[0], want_first);
	}
}

/* replay 必须失败，并且绝不改动文件 */
static void expect_replay_fail(const char *path, long long checkpoint)
{
	struct replay_ctx c;
	struct stat before, after;
	char err[256] = "";
	int rc;

	memset(&c, 0, sizeof(c));
	if (stat(path, &before) != 0) {
		report("stat(%s) failed", path);
		return;
	}
	rc = aik_wal_replay(path, checkpoint, replay_cb, &c, err, sizeof(err));
	g_checked++;
	if (rc != -1)
		report("replay(%s) rc=%d, want -1", path, rc);
	g_checked++;
	if (!strstr(err, "wal: record"))
		report("replay(%s) err \"%s\" lacks \"wal: record\"", path, err);
	g_checked++;
	if (stat(path, &after) != 0 || before.st_size != after.st_size)
		report("replay(%s) changed file size", path);
}

/* ------------------------------------------------------------------ */
/* T4e-D 新增 API：reset / ops / replay_ex                             */
/* ------------------------------------------------------------------ */
static void test_new_api(const char *dir)
{
	static const char *const rec1 = "{\"op\":\"add\",\"seq\":1}\n";
	static const char *const rec2 = "{\"op\":\"transaction\",\"seq\":2}\n";
	char err[256] = "";
	char *p = path_in(dir, "api.wal");
	char *bad = path_in(dir, "api-bad.wal");
	struct stat st;
	aik_json *op = NULL;
	aik_wal *w = NULL;
	int n = 0;
	long long record = -1, last_seq = -1;

	if (!p || !bad) {
		report("out of memory");
		free(p);
		free(bad);
		return;
	}
	(void)unlink(p);
	(void)unlink(bad);

	w = aik_wal_open(p, 1, err, sizeof(err));
	CHECK(w != NULL);
	CHECK(aik_wal_ops(w) == 0);
	op = aik_json_parse("{\"op\":\"add\",\"seq\":1}", 20, err, sizeof(err));
	CHECK(op != NULL);
	if (op)
		CHECK(aik_wal_append(w, op, err, sizeof(err)) == 0);
	aik_json_free(op);
	op = aik_json_parse("{\"op\":\"transaction\",\"seq\":2}", 28, err,
			    sizeof(err));
	CHECK(op != NULL);
	if (op)
		CHECK(aik_wal_append(w, op, err, sizeof(err)) == 0);
	aik_json_free(op);
	CHECK(aik_wal_ops(w) == 2);
	CHECK(stat(p, &st) == 0 &&
	      st.st_size == (off_t)(strlen(rec1) + strlen(rec2)));
	/* reset：截断 + 计数清零，seq 由调用方（引擎）保留 */
	CHECK(aik_wal_reset(w, err, sizeof(err)) == 0);
	CHECK(aik_wal_ops(w) == 0);
	CHECK(stat(p, &st) == 0 && st.st_size == 0);
	op = aik_json_parse("{\"op\":\"add\",\"seq\":3}", 20, err, sizeof(err));
	CHECK(op != NULL);
	if (op)
		CHECK(aik_wal_append(w, op, err, sizeof(err)) == 0);
	aik_json_free(op);
	CHECK(aik_wal_ops(w) == 1);
	CHECK(aik_wal_close(w) == 0);
	w = NULL;
	CHECK(aik_wal_ops(NULL) == 0);
	CHECK(aik_wal_reset(NULL, err, sizeof(err)) == -1);

	/* replay_ex：行号与最大 seq */
	CHECK(aik_wal_replay_ex(p, 0, replay_cb, &n, &record, &last_seq, err,
				sizeof(err)) == 1);
	CHECK(record == 1);
	CHECK(last_seq == 3);
	CHECK(n == 1);

	/* 坏行：失败并回传出错行号，文件不改 */
	CHECK(write_file(bad, "not-json\n", 9) == 0);
	record = -1;
	last_seq = -1;
	CHECK(aik_wal_replay_ex(bad, 0, replay_cb, &n, &record, &last_seq, err,
				sizeof(err)) == -1);
	CHECK(record == 1);
	CHECK(last_seq == 0);
	CHECK(stat(bad, &st) == 0 && st.st_size == 9);

	(void)unlink(p);
	(void)unlink(bad);
	free(p);
	free(bad);
}

/* ------------------------------------------------------------------ */
/* 主测试                                                              */
/* ------------------------------------------------------------------ */

int main(void)
{
	char err[256] = "";
	char *vpath, *lfpath = NULL, *crlfpath = NULL;
	char *built = NULL, *truncp = NULL, *badp = NULL;
	char *blankp = NULL, *wsp = NULL, *noseqp = NULL;
	char *dir = NULL;
	unsigned char *vbuf = NULL, *bb = NULL, *eb = NULL;
	size_t vlen = 0, bn = 0, en = 0;
	aik_json *doc = NULL;
	const aik_json *wal, *lines;
	size_t nlines, i;

	printf("vectors: %s\n", parity_dir());
	vpath = path_in(parity_dir(), "wal/wal.vectors.json");
	lfpath = path_in(parity_dir(), "wal/engine.json.wal.lf");
	crlfpath = path_in(parity_dir(), "wal/engine.json.wal");
	if (!vpath || !lfpath || !crlfpath) {
		report("out of memory");
		free(vpath);
		free(lfpath);
		free(crlfpath);
		printf("SUMMARY wal checked=%d mismatch=%d bytes=%zu\n",
		       g_checked, g_mismatch, g_bytes);
		return 1;
	}
	vbuf = read_file(vpath, &vlen);
	if (!vbuf) {
		report("cannot read %s", vpath);
		goto out;
	}
	doc = aik_json_parse((const char *)vbuf, vlen, err, sizeof(err));
	if (!doc) {
		report("parse %s: %s", vpath, err);
		goto out;
	}

	wal = aik_json_get(doc, "wal");
	lines = aik_json_get(wal, "lines");
	CHECK(aik_json_typeof(wal) == AIK_JSON_OBJ);
	CHECK(aik_json_typeof(lines) == AIK_JSON_ARR);
	nlines = aik_json_count(lines);
	CHECK(nlines == 2);

	dir = make_tmpdir();
	CHECK(dir != NULL);
	if (!dir || nlines == 0)
		goto out;
	built = path_in(dir, "built.wal");
	truncp = path_in(dir, "trunc.wal");
	badp = path_in(dir, "badseq.wal");
	blankp = path_in(dir, "blank.wal");
	wsp = path_in(dir, "ws.wal");
	noseqp = path_in(dir, "noseq.wal");
	if (!built || !truncp || !badp || !blankp || !wsp || !noseqp) {
		report("out of memory");
		goto out;
	}

	/* 1) 逐条 append，记录必须与引擎 WAL 逐字节相同 */
	{
		aik_wal *w = aik_wal_open(built, 1, err, sizeof(err));

		CHECK(w != NULL);
		if (w) {
			for (i = 0; i < nlines; i++) {
				const aik_json *line = aik_json_at(lines, i);
				const aik_json *parsed =
					aik_json_get(line, "parsed");
				const char *raw =
					aik_json_str(aik_json_get(line, "raw"));
				char *dump = NULL;
				size_t dlen = 0;

				CHECK(aik_json_typeof(parsed) == AIK_JSON_OBJ);
				if (aik_json_dump(parsed, &dump, &dlen) == 0) {
					size_t rlen = raw ? strlen(raw) : 0;

					g_checked++;
					if (!raw || dlen != rlen ||
					    memcmp(dump, raw, dlen) != 0)
						report("record %zu: dump(parsed) != raw (dump %zu, raw %zu)",
						       i + 1, dlen, rlen);
					free(dump);
				} else {
					CHECK(0);
				}
				g_checked++;
				if (aik_wal_append(w, parsed, err, sizeof(err)) != 0)
					report("append record %zu: %s", i + 1,
					       err);
			}
			CHECK(aik_wal_close(w) == 0);
		}
	}

	/* 整文件字节 + sha256 + 字节数（LF 基准） */
	bb = read_file(built, &bn);
	eb = read_file(lfpath, &en);
	CHECK(bb != NULL && eb != NULL);
	if (bb && eb) {
		const char *want_sha =
			aik_json_str(aik_json_get(wal, "sha256_lf"));
		long long want_bytes =
			aik_json_int(aik_json_get(wal, "bytes_lf"));
		char hex[65];
		int same;

		g_bytes += bn;
		same = bn == en && memcmp(bb, eb, bn) == 0;
		CHECK(same);
		if (!same)
			report_diff("engine.json.wal.lf", bb, bn, eb, en);
		CHECK(want_sha != NULL);
		sha256_hex(bb, bn, hex);
		if (want_sha)
			CHECK(strcmp(hex, want_sha) == 0);
		CHECK(want_bytes >= 0 && (unsigned long long)want_bytes == bn);
		CHECK(want_bytes == 2347);
		printf("wal: %zu bytes sha256=%s\n", bn, hex);
	}

	/* 2) 重放（LF 产物） */
	expect_replay(built, 7, 2, 2, 8);
	expect_replay(built, 9, 0, 0, 0);
	expect_replay(built, 8, 1, 1, 9);

	/* 原始 CRLF 录制件只用于读取兼容：replay 必须恢复两条 */
	{
		struct stat st;

		g_checked++;
		if (stat(crlfpath, &st) != 0 ||
		    (unsigned long long)st.st_size !=
			    (unsigned long long)aik_json_int(
				    aik_json_get(wal, "bytes")))
			report("CRLF engine.json.wal size mismatch");
		expect_replay(crlfpath, 7, 2, 2, 8);
	}

	/* 3) 边界语义（对齐参考 sme/storage/wal.py replay） */
	if (bb && bn > 0) {
		char missing[128];
		size_t p1 = 0, n1, n2;
		unsigned char *b1 = NULL, *b2 = NULL;
		static const char noseq[] =
			"{\"op\":\"add\",\"mid\":\"m_noseq\",\"text\":\"no seq\"}\n";
		struct replay_ctx c;
		int rc;

		while (p1 < bn && bb[p1] != '\n')
			p1++;
		if (p1 >= bn) {
			report("built WAL has no newline");
		} else {
			/* rec1 \n + 空行 + rec2 \n + 末尾空行 */
			n1 = bn + 2;
			b1 = malloc(n1);
			if (!b1) {
				report("out of memory");
			} else {
				memcpy(b1, bb, p1 + 1);
				b1[p1 + 1] = '\n';
				memcpy(b1 + p1 + 2, bb + p1 + 1, bn - p1 - 1);
				b1[n1 - 1] = '\n';
				g_checked++;
				if (write_file(blankp, b1, n1) != 0)
					report("cannot write %s", blankp);
				else
					expect_replay(blankp, 7, 2, 2, 8);
				free(b1);
			}
			/* rec1 \n + 纯空白行 " \t\r" + rec2 \n */
			n2 = bn + 4;
			b2 = malloc(n2);
			if (!b2) {
				report("out of memory");
			} else {
				memcpy(b2, bb, p1 + 1);
				memcpy(b2 + p1 + 1, " \t\r\n", 4);
				memcpy(b2 + p1 + 5, bb + p1 + 1, bn - p1 - 1);
				g_checked++;
				if (write_file(wsp, b2, n2) != 0)
					report("cannot write %s", wsp);
				else
					expect_replay(wsp, 7, 2, 2, 8);
				free(b2);
			}
		}

		/* 无 seq 的合法 op：seq=0，checkpoint 再大也不跳过 */
		g_checked++;
		if (write_file(noseqp, noseq, sizeof(noseq) - 1) != 0) {
			report("cannot write %s", noseqp);
		} else {
			expect_replay(noseqp, 7, 1, 1, 0);
			expect_replay(noseqp, 1000000, 1, 1, 0);
		}

		/* 文件不存在：返回 0，不写 err */
		(void)snprintf(missing, sizeof(missing),
			       "/tmp/does-not-exist-%ld.wal", (long)getpid());
		(void)unlink(missing);
		memset(&c, 0, sizeof(c));
		memset(err, 0x7f, sizeof(err));
		rc = aik_wal_replay(missing, 7, replay_cb, &c, err, sizeof(err));
		g_checked++;
		if (rc != 0)
			report("missing file replay rc=%d, want 0 (%s)", rc, err);
		g_checked++;
		if (c.count != 0)
			report("missing file callbacks=%d, want 0", c.count);
		g_checked++;
		if (err[0] != '\0')
			report("missing file wrote err: %s", err);
	}

	/* 4) 损坏：截断最后一行；seq 改成负数 */
	if (bb) {
		size_t cut = bn > 10 ? bn - 10 : bn / 2;

		g_checked++;
		if (write_file(truncp, bb, cut) != 0)
			report("cannot write %s", truncp);
		else
			expect_replay_fail(truncp, 7);

		{
			static const unsigned char needle[] = "\"seq\":8";
			static const unsigned char repl[] = "\"seq\":-1";
			size_t nlen = sizeof(needle) - 1;
			size_t rlen = sizeof(repl) - 1;
			long pos = find_bytes(bb, bn, needle, nlen);

			g_checked++;
			if (pos < 0) {
					report("cannot find %s in engine.json.wal.lf",
					       (const char *)needle);
			} else {
				unsigned char *nb = malloc(bn - nlen + rlen + 1);
				size_t nn = bn - nlen + rlen;

				if (!nb) {
					report("out of memory");
				} else {
					memcpy(nb, bb, (size_t)pos);
					memcpy(nb + pos, repl, rlen);
					memcpy(nb + pos + rlen,
					       bb + pos + nlen, bn - (size_t)pos - nlen);
					g_checked++;
					if (write_file(badp, nb, nn) != 0)
						report("cannot write %s", badp);
					else
						expect_replay_fail(badp, 7);
					free(nb);
				}
			}
		}
	}

	/* T4e-D：reset / ops / replay_ex（引擎 WAL 接线所需的最小 API） */
	test_new_api(dir);

out:
	if (dir) {
		if (built)
			(void)unlink(built);
		if (truncp)
			(void)unlink(truncp);
		if (badp)
			(void)unlink(badp);
		if (blankp)
			(void)unlink(blankp);
		if (wsp)
			(void)unlink(wsp);
		if (noseqp)
			(void)unlink(noseqp);
		(void)rmdir(dir);
	}
	aik_json_free(doc);
	free(vbuf);
	free(bb);
	free(eb);
	free(vpath);
	free(lfpath);
	free(crlfpath);
	free(built);
	free(truncp);
	free(badp);
	free(blankp);
	free(wsp);
	free(noseqp);
	free(dir);
	printf("SUMMARY wal checked=%d mismatch=%d bytes=%zu\n",
	       g_checked, g_mismatch, g_bytes);
	return g_mismatch ? 1 : 0;
}
