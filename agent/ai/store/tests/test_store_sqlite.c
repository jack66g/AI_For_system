/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_store_sqlite.c - store_sqlite 自测（T2b-2 门禁）
 *
 * 覆盖（真读 parity 向量，AIK_SQLITE_VECTORS 默认
 * $HOME/aikernel-longterm/parity/vectors/sqlite）：
 *   1) 参考 engine.db：表名集合 = snapshots/vectors/wal_ops/sqlite_sequence；
 *      打开后 busy_timeout 查询 == 5000（默认值 + PRAGMA 读回 + 设置器）；
 *   2) 最新 snapshot：payload 原文 sha256 == payload_raw_sha256，parse→dump
 *      紧凑文本与 payload_canonical 逐字节相等，字节数一致；saved_at
 *      精确等于 1767225600.0；payload 内 memories/regions/region_edges/
 *      memory_edges 计数与记录一致；
 *   3) vectors：2 行；每行长度 == dim*8，sha256_le 与记录一致，
 *      first8_hex 的 Python float.hex 文本按位还原后与 blob 前 8 个
 *      小端 double 逐字节相同；
 *   4) wal_ops：2 行，表内 seq 8/9，op 原文与记录 raw 逐字节相等，
 *      parse→dump 也等于 raw；wal_replay(checkpoint=7) → 2 次回调，
 *      checkpoint=8 → 1 次、9 → 0 次；
 *   5) 重放状态：payload memories + memory_edges 初始化，套用 wal_ops，
 *      输出 {"memories":[按 id 排序],"graph":{"edges":[排序]}}（丢
 *      embedding/region_id），与 expected_state.canonical.json 逐字节
 *      相等（sha256/字节数同记录）；
 *   6) 写路径：/tmp/t2b-sqlite-out/engine.db 新建库（create=1），写同一
 *      payload 原文 + 2 条向量 + 2 条 op；重开校验并打印路径供 Python
 *      SqliteBackend 读回；
 *   7) 负向：DROP TABLE vectors 后 load/for_each_vector/put_vector/save
 *      全部报错；截断库文件后 open 或查询报错；payload 改成非法 JSON 后
 *      load 仍返回原文（aik_json_parse 失败）；坏 wal 行 replay → -1 且
 *      不删行；wal_clear 不清 sqlite_sequence；缺库 create=0 打不开；
 *      内嵌 seq 缺失按 0 永不跳过、seq 为负/非整数 → -1 且行保留。
 *
 * 末行 "SUMMARY sqlite checked=... mismatch=..."，有失配退出码非 0。
 */
#define _POSIX_C_SOURCE 200809L

#include "store/store_json.h"
#include "store/store_sqlite.h"
#include "store/store_wal.h"

#include "sqlite3.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OUT_DIR "/tmp/t2b-sqlite-out"
#define OUT_DB OUT_DIR "/engine.db"

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

static void report_diff(const char *label, const unsigned char *got,
			size_t gn, const unsigned char *want, size_t wn)
{
	size_t i, lim = gn < wn ? gn : wn;

	for (i = 0; i < lim; i++) {
		if (got[i] != want[i])
			break;
	}
	report("%s: first diff at %zu (got %zu B, want %zu B)", label, i, gn,
	       wn);
	if (i < gn && i < wn)
		report("  got: %.40s", (const char *)got + (i > 20 ? i - 20 : 0));
	if (i < wn)
		report("  want: %.40s",
		       (const char *)want + (i > 20 ? i - 20 : 0));
}

/* ------------------------------------------------------------------ */
/* 路径与文件                                                          */
/* ------------------------------------------------------------------ */

static const char *vectors_dir(void)
{
	const char *d = getenv("AIK_SQLITE_VECTORS");
	static char buf[8192];

	if (d && *d)
		return d;
	(void)snprintf(buf, sizeof(buf),
		       "%s/aikernel-longterm/parity/vectors/sqlite",
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
	if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
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
	ok = len == 0 || fwrite(data, 1, len, f) == len;
	if (fclose(f) != 0)
		ok = 0;
	return ok ? 0 : -1;
}

static int copy_file(const char *src, const char *dst)
{
	unsigned char *buf;
	size_t n = 0;
	int rc;

	buf = read_file(src, &n);
	if (!buf)
		return -1;
	rc = write_file(dst, buf, n);
	free(buf);
	return rc;
}

static char *make_tmpdir(void)
{
	const char *base = getenv("TMPDIR");
	char tmpl[8192];
	size_t n;

	if (!base || !*base)
		base = "/tmp";
	n = (size_t)snprintf(tmpl, sizeof(tmpl), "%s/t2bsql.XXXXXX", base);
	if (n >= sizeof(tmpl))
		return NULL;
	if (!mkdtemp(tmpl))
		return NULL;
	return strdup(tmpl);
}

static int ensure_dir(const char *path)
{
	if (mkdir(path, 0777) == 0 || errno == EEXIST)
		return 0;
	return -1;
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
	size_t padlen;
	int i;

	memset(pad, 0, sizeof(pad));
	pad[0] = 0x80;
	padlen = (c->used < 56) ? (56 - c->used) : (120 - c->used);
	sha256_update(c, pad, padlen);
	{
		unsigned char lenbe[8];

		for (i = 0; i < 8; i++)
			lenbe[i] = (unsigned char)(bits >> (56 - 8 * i));
		sha256_update(c, lenbe, 8);
	}
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
/* 裸 sqlite 访问（仅测试用于校验/造坏库）                              */
/* ------------------------------------------------------------------ */

static int raw_exec(void *h, const char *sql)
{
	char *msg = NULL;
	int rc = sqlite3_exec((sqlite3 *)h, sql, NULL, NULL, &msg);

	sqlite3_free(msg);
	return rc == SQLITE_OK ? 0 : -1;
}

static int raw_ll(void *h, const char *sql, long long *out)
{
	sqlite3_stmt *st = NULL;
	int ok = 0;

	if (sqlite3_prepare_v2((sqlite3 *)h, sql, -1, &st, NULL) != SQLITE_OK)
		return -1;
	if (sqlite3_step(st) == SQLITE_ROW) {
		*out = sqlite3_column_int64(st, 0);
		ok = 1;
	}
	(void)sqlite3_finalize(st);
	return ok ? 0 : -1;
}

/* SELECT 单行单列的文本（malloc）；无行返回 NULL */
static char *raw_text(void *h, const char *sql)
{
	sqlite3_stmt *st = NULL;
	char *out = NULL;

	if (sqlite3_prepare_v2((sqlite3 *)h, sql, -1, &st, NULL) != SQLITE_OK)
		return NULL;
	if (sqlite3_step(st) == SQLITE_ROW) {
		const unsigned char *t = sqlite3_column_text(st, 0);
		int n = sqlite3_column_bytes(st, 0);

		out = malloc((size_t)(n > 0 ? n : 0) + 1);
		if (out) {
			if (t && n > 0)
				memcpy(out, t, (size_t)n);
			out[n > 0 ? n : 0] = '\0';
		}
	}
	(void)sqlite3_finalize(st);
	return out;
}

/* ------------------------------------------------------------------ */
/* DOM 深拷贝 + 最小状态机（与 T2b-1 相同的语义）                       */
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
/* 1) 参考库：表名 + busy_timeout                                      */
/* ------------------------------------------------------------------ */

static void test_tables(aik_sqlite *db)
{
	void *h = aik_sqlite_handle(db);
	sqlite3_stmt *st = NULL;
	long long cnt = -1;
	int n = 0, ok = 1;

	CHECK(h != NULL);
	if (!h)
		return;
	CHECK(sqlite3_prepare_v2((sqlite3 *)h,
				 "SELECT name FROM sqlite_master"
				 " WHERE type = 'table' ORDER BY name",
				 -1, &st, NULL) == SQLITE_OK);
	if (!st)
		return;
	while (sqlite3_step(st) == SQLITE_ROW) {
		const char *name = (const char *)sqlite3_column_text(st, 0);

		if (!name) {
			ok = 0;
			continue;
		}
		printf("table: %s\n", name);
		n++;
		if (strcmp(name, "snapshots") != 0 &&
		    strcmp(name, "vectors") != 0 &&
		    strcmp(name, "wal_ops") != 0 &&
		    strcmp(name, "sqlite_sequence") != 0) {
			report("unexpected table %s", name);
			ok = 0;
		}
	}
	(void)sqlite3_finalize(st);
	CHECK(ok);
	CHECK(n == 4);
	CHECK(raw_ll(h,
		     "SELECT count(*) FROM sqlite_master WHERE type = 'table'"
		     " AND name IN ('snapshots','vectors','wal_ops')",
		     &cnt) == 0);
	CHECK(cnt == 3);
}

static void test_busy_timeout(aik_sqlite *db)
{
	char err[256] = "";
	int ms = -1;
	long long rms = -1;

	CHECK(aik_sqlite_busy_timeout_get(db, &ms, err, sizeof(err)) == 0);
	CHECK(ms == 5000);
	err[0] = '\0';
	CHECK(raw_ll(aik_sqlite_handle(db), "PRAGMA busy_timeout", &rms) == 0);
	CHECK(rms == 5000);
	printf("busy_timeout: get=%d pragma=%lld\n", ms, rms);

	/* 设置器往返 */
	err[0] = '\0';
	CHECK(aik_sqlite_busy_timeout(db, 1234, err, sizeof(err)) == 0);
	ms = -1;
	CHECK(aik_sqlite_busy_timeout_get(db, &ms, err, sizeof(err)) == 0);
	CHECK(ms == 1234);
	err[0] = '\0';
	CHECK(aik_sqlite_busy_timeout(db, 5000, err, sizeof(err)) == 0);
	ms = -1;
	CHECK(aik_sqlite_busy_timeout_get(db, &ms, err, sizeof(err)) == 0);
	CHECK(ms == 5000);
}

/* ------------------------------------------------------------------ */
/* 2) 最新 snapshot                                                    */
/* ------------------------------------------------------------------ */

static void test_snapshot(aik_sqlite *db, const aik_json *v,
			  char **payload_out)
{
	char err[256] = "";
	char *payload = NULL;
	double saved_at = -1.0;
	const aik_json *snap = aik_json_get(v, "snapshot");
	const char *want = aik_json_str(aik_json_get(snap, "payload_canonical"));
	const char *want_raw_sha =
		aik_json_str(aik_json_get(snap, "payload_raw_sha256"));
	const aik_json *counts = aik_json_get(snap, "counts");
	aik_json *dom;
	char *dump = NULL;
	size_t dlen = 0;
	char hex[65];

	*payload_out = NULL;
	CHECK(aik_sqlite_load_snapshot(db, &payload, &saved_at, err,
				       sizeof(err)) == 0);
	if (!payload) {
		report("load_snapshot returned no payload: %s", err);
		return;
	}
	g_bytes += strlen(payload);
	sha256_hex(payload, strlen(payload), hex);
	CHECK(want_raw_sha != NULL && strcmp(hex, want_raw_sha) == 0);
	printf("snapshot: %zu bytes raw, saved_at=%.1f\n", strlen(payload),
	       saved_at);

	CHECK(saved_at == 1767225600.0);
	CHECK(saved_at == aik_json_num(aik_json_get(snap, "saved_at")));

	dom = aik_json_parse(payload, strlen(payload), err, sizeof(err));
	CHECK(dom != NULL);
	if (dom) {
		CHECK(aik_json_dump(dom, &dump, &dlen) == 0);
		if (dump && want) {
			size_t wn = strlen(want);

			g_bytes += dlen;
			CHECK(dlen == wn && memcmp(dump, want, wn) == 0);
			if (!(dlen == wn && memcmp(dump, want, wn) == 0))
				report_diff("payload_canonical", (unsigned char *)dump,
					    dlen, (const unsigned char *)want, wn);
			CHECK((long long)wn ==
			      aik_json_int(aik_json_get(snap,
							"payload_canonical_bytes")));
		} else {
			CHECK(0);
		}
		/* 计数 */
		CHECK((long long)aik_json_count(aik_json_get(dom, "memories")) ==
		      aik_json_int(aik_json_get(counts, "memories")));
		CHECK((long long)aik_json_count(aik_json_get(dom, "regions")) ==
		      aik_json_int(aik_json_get(counts, "regions")));
		CHECK((long long)aik_json_count(
			      aik_json_get(dom, "region_edges")) ==
		      aik_json_int(aik_json_get(counts, "region_edges")));
		CHECK((long long)aik_json_count(
			      aik_json_get(dom, "memory_edges")) ==
		      aik_json_int(aik_json_get(counts, "memory_edges")));
		printf("snapshot: memories=%zu regions=%zu region_edges=%zu memory_edges=%zu\n",
		       aik_json_count(aik_json_get(dom, "memories")),
		       aik_json_count(aik_json_get(dom, "regions")),
		       aik_json_count(aik_json_get(dom, "region_edges")),
		       aik_json_count(aik_json_get(dom, "memory_edges")));
		aik_json_free(dom);
	}
	free(dump);
	*payload_out = payload;
}

/* ------------------------------------------------------------------ */
/* 3) vectors                                                          */
/* ------------------------------------------------------------------ */

struct vec_row {
	char id[64];
	unsigned char *blob;
	size_t len;
};

struct vec_ctx {
	struct vec_row rows[8];
	int n;
	int fail;
};

static void vec_ctx_free(struct vec_ctx *c)
{
	int i;

	for (i = 0; i < c->n; i++)
		free(c->rows[i].blob);
	memset(c, 0, sizeof(*c));
}

static int vec_cb(void *ctx, const char *memory_id, const void *blob,
		  size_t len, char *err, size_t errlen)
{
	struct vec_ctx *c = ctx;
	struct vec_row *r;

	if (c->n >= 8) {
		(void)snprintf(err, errlen, "too many vector rows");
		c->fail = 1;
		return -1;
	}
	r = &c->rows[c->n];
	(void)snprintf(r->id, sizeof(r->id), "%s", memory_id);
	r->blob = malloc(len ? len : 1);
	if (!r->blob) {
		(void)snprintf(err, errlen, "out of memory");
		c->fail = 1;
		return -1;
	}
	if (len)
		memcpy(r->blob, blob, len);
	r->len = len;
	c->n++;
	return 0;
}

static const aik_json *find_record(const aik_json *arr, const char *id)
{
	size_t i, n = aik_json_count(arr);

	for (i = 0; i < n; i++) {
		const aik_json *r = aik_json_at(arr, i);
		const char *rid = aik_json_str(aik_json_get(r, "memory_id"));

		if (rid && strcmp(rid, id) == 0)
			return r;
	}
	return NULL;
}

static void test_vectors(aik_sqlite *db, const aik_json *v, struct vec_ctx *out)
{
	char err[256] = "";
	const aik_json *recs = aik_json_get(v, "vectors");
	long long dim = aik_json_int(aik_json_get(aik_json_get(v, "meta"),
						  "embed_dim"));
	int i;

	memset(out, 0, sizeof(*out));
	CHECK(aik_sqlite_for_each_vector(db, vec_cb, out, err, sizeof(err)) ==
	      0);
	printf("vectors: n=%d (record %zu, dim=%lld)\n", out->n,
	       aik_json_count(recs), dim);
	CHECK(out->n == 2);
	CHECK((size_t)out->n == aik_json_count(recs));
	CHECK(dim == 64);
	for (i = 0; i < out->n; i++) {
		struct vec_row *row = &out->rows[i];
		const aik_json *rec = find_record(recs, row->id);
		char hex[65];

		CHECK(rec != NULL);
		if (!rec)
			continue;
		CHECK(row->len == (size_t)dim * 8);
		sha256_hex(row->blob, row->len, hex);
		printf("vector: %s len=%zu sha256_le=%s\n", row->id, row->len,
		       hex);
		CHECK(strcmp(hex, aik_json_str(aik_json_get(rec, "sha256_le"))) ==
		      0);
		/* first8_hex: Python float.hex() 文本 → 按位还原 */
		{
			const aik_json *f8 = aik_json_get(rec, "first8_hex");
			size_t k;

			CHECK(aik_json_typeof(f8) == AIK_JSON_ARR);
			CHECK(aik_json_count(f8) == 8);
			for (k = 0; k < 8 && k < aik_json_count(f8); k++) {
				const char *hs =
					aik_json_str(aik_json_at(f8, k));
				char *end = NULL;
				double d;
				unsigned char bits[8];

				CHECK(hs != NULL);
				if (!hs)
					continue;
				d = strtod(hs, &end);
				CHECK(end && *end == '\0');
				memcpy(bits, &d, sizeof(bits));
				g_checked++;
				if (row->len < (k + 1) * 8 ||
				    memcmp(bits, row->blob + k * 8, 8) != 0)
					report("vector %s first8[%zu] (%s) bits mismatch",
					       row->id, k, hs);
			}
		}
	}
}

/* ------------------------------------------------------------------ */
/* 4) wal_ops 行 + replay                                              */
/* ------------------------------------------------------------------ */

struct op_ctx {
	aik_json *ops[8];
	int n;
	int fail;
};

static void op_ctx_free(struct op_ctx *c)
{
	int i;

	for (i = 0; i < c->n; i++)
		aik_json_free(c->ops[i]);
	memset(c, 0, sizeof(*c));
}

static int op_cb(void *ctx, const aik_json *op, char *err, size_t errlen)
{
	struct op_ctx *c = ctx;
	aik_json *copy;

	if (c->n >= 8) {
		(void)snprintf(err, errlen, "too many records");
		c->fail = 1;
		return -1;
	}
	copy = jclone(op);
	if (!copy) {
		(void)snprintf(err, errlen, "out of memory");
		c->fail = 1;
		return -1;
	}
	c->ops[c->n] = copy;
	c->n++;
	return 0;
}

static void expect_replay(aik_sqlite *db, long long checkpoint, int want,
			  struct op_ctx *out)
{
	char err[256] = "";
	struct op_ctx local;
	struct op_ctx *c = out ? out : &local;
	int rc;

	memset(c, 0, sizeof(*c));
	rc = aik_sqlite_wal_replay(db, checkpoint, op_cb, c, err, sizeof(err));
	g_checked++;
	if (rc != want)
		report("wal_replay(%lld) rc=%d, want %d (%s)", checkpoint, rc,
		       want, err);
	if (!out)
		op_ctx_free(&local);
}

static void test_wal(aik_sqlite *db, const aik_json *v)
{
	char err[256] = "";
	const aik_json *wal = aik_json_get(v, "wal");
	const aik_json *rows = aik_json_get(wal, "rows");
	void *h = aik_sqlite_handle(db);
	sqlite3_stmt *st = NULL;
	size_t n = aik_json_count(rows), i;
	int rc;

	CHECK(aik_json_int(aik_json_get(wal, "row_count")) == 2);
	CHECK(n == 2);
	CHECK(sqlite3_prepare_v2((sqlite3 *)h,
				 "SELECT seq, op FROM wal_ops ORDER BY seq",
				 -1, &st, NULL) == SQLITE_OK);
	if (!st)
		return;
	for (i = 0; i < n; i++) {
		const aik_json *r = aik_json_at(rows, i);
		const char *raw = aik_json_str(aik_json_get(r, "raw"));
		long long want_seq = aik_json_int(aik_json_get(r, "seq"));
		const char *op;
		int olen;
		aik_json *parsed;
		char *dump = NULL;
		size_t dlen = 0;

		rc = sqlite3_step(st);
		CHECK(rc == SQLITE_ROW);
		if (rc != SQLITE_ROW)
			break;
		CHECK(sqlite3_column_int64(st, 0) == want_seq);
		op = (const char *)sqlite3_column_text(st, 1);
		olen = sqlite3_column_bytes(st, 1);
		g_checked++;
		if (!raw || !op || (size_t)olen != strlen(raw) ||
		    memcmp(op, raw, (size_t)olen) != 0)
			report("wal row %zu: op text != record raw", i + 1);
		parsed = raw ? aik_json_parse(raw, strlen(raw), err,
					      sizeof(err))
			     : NULL;
		CHECK(parsed != NULL);
		if (parsed) {
			CHECK(aik_json_dump(parsed, &dump, &dlen) == 0);
			g_checked++;
			if (!dump || dlen != (raw ? strlen(raw) : 0) ||
			    memcmp(dump, raw, dlen) != 0)
				report("wal row %zu: dump(parse(raw)) != raw",
				       i + 1);
			free(dump);
			aik_json_free(parsed);
		}
	}
	CHECK(sqlite3_step(st) == SQLITE_DONE);
	(void)sqlite3_finalize(st);

	/* checkpoint 语义 */
	{
		struct op_ctx c;

		memset(&c, 0, sizeof(c));
		expect_replay(db, 7, 2, &c);
		CHECK(c.n == 2);
		if (c.n == 2) {
			CHECK(strcmp(aik_json_str(aik_json_get(c.ops[0], "op")),
				     "add") == 0);
			CHECK(strcmp(aik_json_str(aik_json_get(c.ops[1], "op")),
				     "transaction") == 0);
		}
		op_ctx_free(&c);
	}
	expect_replay(db, 9, 0, NULL);
	expect_replay(db, 8, 1, NULL);
	expect_replay(db, -1, 2, NULL);
	printf("wal: 2 rows seq 8/9; replay(7)=2 replay(8)=1 replay(9)=0\n");
}

/* ------------------------------------------------------------------ */
/* 5) 重放状态                                                         */
/* ------------------------------------------------------------------ */

static void test_replay_state(aik_sqlite *db, const aik_json *v,
			      const char *exp_path, const char *payload)
{
	char err[256] = "";
	aik_json *dom = NULL;
	sm_state st;
	struct op_ctx ops;
	aik_json *out = NULL;
	unsigned char *want = NULL;
	size_t wn = 0;
	char hex[65];
	int i;

	memset(&st, 0, sizeof(st));
	memset(&ops, 0, sizeof(ops));
	dom = aik_json_parse(payload, strlen(payload), err, sizeof(err));
	CHECK(dom != NULL);
	if (!dom)
		goto out;
	if (sm_init(&st, dom) != 0) {
		report("cannot initialize state machine");
		goto out;
	}
	(void)aik_sqlite_wal_replay(db, 7, op_cb, &ops, err, sizeof(err));
	CHECK(ops.n == 2);
	for (i = 0; i < ops.n; i++) {
		g_checked++;
		if (sm_apply(&st, ops.ops[i]) != 0) {
			report("cannot apply WAL record %d", i + 1);
			goto out;
		}
	}
	out = export_state(&st);
	CHECK(out != NULL);
	want = read_file(exp_path, &wn);
	CHECK(want != NULL);
	if (out && want) {
		char *dump = NULL;
		size_t dlen = 0;

		CHECK(aik_json_dump(out, &dump, &dlen) == 0);
		if (dump) {
			g_bytes += dlen;
			CHECK(dlen == wn && memcmp(dump, want, wn) == 0);
			if (!(dlen == wn && memcmp(dump, want, wn) == 0))
				report_diff("expected_state", (unsigned char *)dump,
					    dlen, want, wn);
			sha256_hex(dump, dlen, hex);
			free(dump);
		}
		CHECK(strcmp(hex, aik_json_str(aik_json_get(v,
							   "expected_state_sha256"))) == 0);
		CHECK((long long)wn ==
		      aik_json_int(aik_json_get(v, "expected_state_bytes")));
		printf("state: %zu bytes sha256=%s\n", wn, hex);
	}

out:
	aik_json_free(out);
	aik_json_free(st.memories);
	aik_json_free(st.edges);
	op_ctx_free(&ops);
	aik_json_free(dom);
	free(want);
}

/* ------------------------------------------------------------------ */
/* 6) 写路径                                                           */
/* ------------------------------------------------------------------ */

static void test_write_path(const char *payload, const aik_json *v,
			    const struct vec_ctx *vecs)
{
	char err[256] = "";
	const aik_json *wal = aik_json_get(v, "wal");
	const aik_json *rows = aik_json_get(wal, "rows");
	aik_sqlite *db;
	char *got = NULL;
	double saved_at = 0.0;
	int i;

	CHECK(ensure_dir(OUT_DIR) == 0);
	(void)unlink(OUT_DB);
	(void)unlink(OUT_DB "-journal");

	db = aik_sqlite_open(OUT_DB, 1, err, sizeof(err));
	CHECK(db != NULL);
	if (!db) {
		report("cannot create %s: %s", OUT_DB, err);
		return;
	}
	err[0] = '\0';
	CHECK(aik_sqlite_save_snapshot(db, payload, 1767225600.0, err,
				       sizeof(err)) == 0);
	for (i = 0; i < vecs->n; i++) {
		err[0] = '\0';
		CHECK(aik_sqlite_put_vector(db, vecs->rows[i].id,
					    vecs->rows[i].blob,
					    vecs->rows[i].len, err,
					    sizeof(err)) == 0);
	}
	for (i = 0; i < (int)aik_json_count(rows); i++) {
		const char *raw =
			aik_json_str(aik_json_get(aik_json_at(rows, i), "raw"));
		long long seq = -1;

		err[0] = '\0';
		CHECK(aik_sqlite_wal_append(db, raw, &seq, err,
					    sizeof(err)) == 0);
		CHECK(seq == i + 1);
	}
	aik_sqlite_close(db);

	/* 重开校验 */
	err[0] = '\0';
	db = aik_sqlite_open(OUT_DB, 0, err, sizeof(err));
	CHECK(db != NULL);
	if (!db) {
		report("cannot reopen %s: %s", OUT_DB, err);
		return;
	}
	{
		int ms = -1;

		CHECK(aik_sqlite_busy_timeout_get(db, &ms, err, sizeof(err)) ==
		      0);
		CHECK(ms == 5000);
	}
	CHECK(aik_sqlite_load_snapshot(db, &got, &saved_at, err,
				       sizeof(err)) == 0);
	g_checked++;
	if (!got || strcmp(got, payload) != 0)
		report("written snapshot payload differs");
	CHECK(saved_at == 1767225600.0);

	{
		struct vec_ctx back;
		char hex[65];

		memset(&back, 0, sizeof(back));
		CHECK(aik_sqlite_for_each_vector(db, vec_cb, &back, err,
						 sizeof(err)) == 0);
		CHECK(back.n == vecs->n);
		for (i = 0; i < back.n && i < vecs->n; i++) {
			sha256_hex(back.rows[i].blob, back.rows[i].len, hex);
			CHECK(back.rows[i].len == vecs->rows[i].len &&
			      memcmp(back.rows[i].blob, vecs->rows[i].blob,
				     back.rows[i].len) == 0);
			CHECK(strcmp(back.rows[i].id, vecs->rows[i].id) == 0);
		}
		vec_ctx_free(&back);
	}

	{
		long long cnt = -1;
		char *op0, *op1;

		CHECK(raw_ll(aik_sqlite_handle(db),
			     "SELECT count(*) FROM wal_ops", &cnt) == 0);
		CHECK(cnt == 2);
		op0 = raw_text(aik_sqlite_handle(db),
			       "SELECT op FROM wal_ops ORDER BY seq LIMIT 1");
		op1 = raw_text(aik_sqlite_handle(db),
			       "SELECT op FROM wal_ops ORDER BY seq LIMIT 1 OFFSET 1");
		g_checked++;
		if (!op0 ||
		    strcmp(op0, aik_json_str(aik_json_get(aik_json_at(rows, 0),
							  "raw"))) != 0)
			report("written wal row 1 differs");
		g_checked++;
		if (!op1 ||
		    strcmp(op1, aik_json_str(aik_json_get(aik_json_at(rows, 1),
							  "raw"))) != 0)
			report("written wal row 2 differs");
		free(op0);
		free(op1);
	}
	/*
	 * 回归点：写出的库表内 seq 是 1/2（AUTOINCREMENT 新表），而 op 内嵌
	 * seq 仍是 8/9。checkpoint 判定必须用内嵌 seq：
	 *   replay(7) -> 2（不是 0），replay(9) -> 0。
	 */
	expect_replay(db, 0, 2, NULL);
	expect_replay(db, 7, 2, NULL);
	expect_replay(db, 8, 1, NULL);
	expect_replay(db, 9, 0, NULL);
	printf("written replay: table seq 1/2, op seq 8/9 -> ckpt7=2 ckpt8=1 ckpt9=0\n");
	printf("wrote: %s\n", OUT_DB);
	free(got);
	aik_sqlite_close(db);
}

/* ------------------------------------------------------------------ */
/* 7) 负向                                                             */
/* ------------------------------------------------------------------ */

static void test_negative(const char *ref_db, const char *payload)
{
	char err[256] = "";
	char *dir = make_tmpdir();
	char *p_drop = dir ? path_in(dir, "drop.db") : NULL;
	char *p_trunc = dir ? path_in(dir, "trunc.db") : NULL;
	char *p_badjson = dir ? path_in(dir, "badjson.db") : NULL;
	char *p_badwal = dir ? path_in(dir, "badwal.db") : NULL;
	char *p_noseq = dir ? path_in(dir, "noseq.db") : NULL;
	char *p_seqbad = dir ? path_in(dir, "seqbad.db") : NULL;
	char *p_save = dir ? path_in(dir, "save.db") : NULL;
	char *p_missing = dir ? path_in(dir, "nope.db") : NULL;

	CHECK(dir != NULL);
	if (!dir)
		return;

	/* a) DROP TABLE vectors：load / for_each_vector / put_vector / save 全失败 */
	if (copy_file(ref_db, p_drop) == 0) {
		aik_sqlite *db = aik_sqlite_open(p_drop, 0, err, sizeof(err));

		CHECK(db != NULL);
		if (db) {
			char *pay = NULL;
			double sat = 0.0;
			struct vec_ctx vc;

			CHECK(raw_exec(aik_sqlite_handle(db),
				       "DROP TABLE vectors") == 0);
			err[0] = '\0';
			g_checked++;
			if (aik_sqlite_load_snapshot(db, &pay, &sat, err,
						     sizeof(err)) != -1)
				report("load after DROP vectors did not fail");
			g_checked++;
			if (!strstr(err, "sqlite: "))
				report("load after DROP vectors: err \"%s\" lacks prefix",
				       err);
			free(pay);
			memset(&vc, 0, sizeof(vc));
			err[0] = '\0';
			g_checked++;
			if (aik_sqlite_for_each_vector(db, vec_cb, &vc, err,
						       sizeof(err)) != -1)
				report("for_each_vector after DROP vectors did not fail");
			g_checked++;
			if (!strstr(err, "sqlite: "))
				report("for_each_vector err \"%s\" lacks prefix",
				       err);
			err[0] = '\0';
			g_checked++;
			if (aik_sqlite_put_vector(db, "x", "\0\0\0\0\0\0\0\0",
						  8, err, sizeof(err)) != -1)
				report("put_vector after DROP vectors did not fail");
			err[0] = '\0';
			g_checked++;
			if (aik_sqlite_save_snapshot(db, payload, 1.0, err,
						     sizeof(err)) != -1)
				report("save_snapshot after DROP vectors did not fail");
			/* 读 snapshot 也不允许（schema 校验） */
			err[0] = '\0';
			g_checked++;
			if (aik_sqlite_load_snapshot(db, &pay, &sat, err,
						     sizeof(err)) != -1)
				report("load after DROP vectors (2nd) did not fail");
			aik_sqlite_close(db);
			printf("negative: DROP vectors -> errors ok\n");
		}
	} else {
		report("cannot copy reference db to %s", p_drop);
	}

	/* b) 截断库文件：open 或查询必须报错 */
	{
		unsigned char *buf;
		size_t n = 0;

		buf = read_file(ref_db, &n);
		CHECK(buf != NULL);
		if (buf && n > 4096) {
			CHECK(write_file(p_trunc, buf, 4096) == 0);
			err[0] = '\0';
			{
				aik_sqlite *db =
					aik_sqlite_open(p_trunc, 0, err,
							sizeof(err));

				if (!db) {
					printf("negative: trunc open failed: %s\n",
					       err);
					CHECK(strstr(err, "sqlite: ") != NULL);
				} else {
					char *pay = NULL;
					double sat = 0.0;
					int rc;

					rc = aik_sqlite_load_snapshot(
						db, &pay, &sat, err,
						sizeof(err));
					g_checked++;
					if (rc != -1)
						report("truncated db: load rc=%d, want -1",
						       rc);
					g_checked++;
					if (!strstr(err, "sqlite: "))
						report("truncated db err \"%s\" lacks prefix",
						       err);
					free(pay);
					aik_sqlite_close(db);
					printf("negative: trunc query failed: %s\n",
					       err);
				}
			}
		}
		free(buf);
	}

	/* c) payload 非法 JSON：load 仍返回原文，aik_json_parse 失败 */
	if (copy_file(ref_db, p_badjson) == 0) {
		aik_sqlite *db =
			aik_sqlite_open(p_badjson, 0, err, sizeof(err));

		CHECK(db != NULL);
		if (db) {
			char *got = NULL;
			double sat = 0.0;
			aik_json *dom = NULL;

			CHECK(raw_exec(aik_sqlite_handle(db),
				       "UPDATE snapshots SET payload = '{not json'") ==
			      0);
			err[0] = '\0';
			CHECK(aik_sqlite_load_snapshot(db, &got, &sat, err,
						       sizeof(err)) == 0);
			CHECK(got != NULL && strcmp(got, "{not json") == 0);
			dom = got ? aik_json_parse(got, strlen(got), err,
						   sizeof(err))
				  : NULL;
			CHECK(dom == NULL);
			aik_json_free(dom);
			free(got);
			aik_sqlite_close(db);
			printf("negative: invalid payload passthrough ok\n");
		}
	}

	/* d) 坏 wal 行 replay → -1 且不删行；clear 不清 sqlite_sequence */
	if (copy_file(ref_db, p_badwal) == 0) {
		aik_sqlite *db =
			aik_sqlite_open(p_badwal, 0, err, sizeof(err));

		CHECK(db != NULL);
		if (db) {
			long long seq = 0, cnt = -1;

			CHECK(aik_sqlite_wal_append(db, "{broken", &seq, err,
						    sizeof(err)) == 0);
			CHECK(seq == 10);
			err[0] = '\0';
			{
				struct op_ctx oc;

				memset(&oc, 0, sizeof(oc));
				g_checked++;
				if (aik_sqlite_wal_replay(db, 9, op_cb, &oc,
							  err,
							  sizeof(err)) != -1)
					report("replay with broken row did not fail");
				op_ctx_free(&oc);
			}
			g_checked++;
			if (!strstr(err, "sqlite: wal record 3"))
				report("broken wal err \"%s\" lacks record index", err);
			CHECK(raw_ll(aik_sqlite_handle(db),
				     "SELECT count(*) FROM wal_ops", &cnt) == 0);
			CHECK(cnt == 3);

			CHECK(aik_sqlite_wal_clear(db, err, sizeof(err)) == 0);
			CHECK(raw_ll(aik_sqlite_handle(db),
				     "SELECT count(*) FROM wal_ops", &cnt) == 0);
			CHECK(cnt == 0);
			CHECK(raw_ll(aik_sqlite_handle(db),
				     "SELECT seq FROM sqlite_sequence WHERE name='wal_ops'",
				     &cnt) == 0);
			CHECK(cnt == 10);
			seq = 0;
			CHECK(aik_sqlite_wal_append(db, "{\"op\":\"x\"}", &seq,
						    err, sizeof(err)) == 0);
			CHECK(seq == 11);
			aik_sqlite_close(db);
			printf("negative: broken wal retained; clear keeps sequence (next seq=11)\n");
		}
	}

	/* e) save_snapshot 全量替换：旧向量被清空 */
	if (copy_file(ref_db, p_save) == 0) {
		aik_sqlite *db = aik_sqlite_open(p_save, 0, err, sizeof(err));

		CHECK(db != NULL);
		if (db) {
			long long cnt = -1;

			CHECK(aik_sqlite_save_snapshot(db, payload, 1767225600.0,
						       err, sizeof(err)) == 0);
			CHECK(raw_ll(aik_sqlite_handle(db),
				     "SELECT count(*) FROM vectors", &cnt) == 0);
			CHECK(cnt == 0);
			CHECK(raw_ll(aik_sqlite_handle(db),
				     "SELECT count(*) FROM snapshots", &cnt) == 0);
			CHECK(cnt == 1);
			aik_sqlite_close(db);
			printf("negative: save clears vectors (full replace) ok\n");
		}
	}

	/* f) 内嵌 seq 缺失 → 0，永不因 checkpoint 跳过（哪怕表 seq 很大） */
	if (copy_file(ref_db, p_noseq) == 0) {
		aik_sqlite *db = aik_sqlite_open(p_noseq, 0, err, sizeof(err));

		CHECK(db != NULL);
		if (db) {
			long long seq = -1, cnt = -1;

			CHECK(aik_sqlite_wal_append(db,
						    "{\"op\":\"add\",\"mid\":\"m_noseq\"}",
						    &seq, err, sizeof(err)) == 0);
			CHECK(seq == 10);
			{
				struct op_ctx oc;

				memset(&oc, 0, sizeof(oc));
				CHECK(aik_sqlite_wal_replay(db, 7, op_cb, &oc,
							    err, sizeof(err)) == 3);
				CHECK(oc.n == 3);
				op_ctx_free(&oc);
			}
			/* checkpoint 9：8/9 跳过，无 seq 的一条仍回调 */
			expect_replay(db, 9, 1, NULL);
			CHECK(raw_ll(aik_sqlite_handle(db),
				     "SELECT count(*) FROM wal_ops", &cnt) == 0);
			CHECK(cnt == 3);
			aik_sqlite_close(db);
			printf("negative: missing seq=0 never skipped (ckpt7=3 ckpt9=1)\n");
		}
	}

	/* g) 内嵌 seq 为负 / 非整数 → -1 且行保留 */
	if (copy_file(ref_db, p_seqbad) == 0) {
		aik_sqlite *db = aik_sqlite_open(p_seqbad, 0, err, sizeof(err));

		CHECK(db != NULL);
		if (db) {
			long long seq = -1, cnt = -1;

			CHECK(aik_sqlite_wal_append(db,
						    "{\"op\":\"add\",\"seq\":-1}",
						    &seq, err, sizeof(err)) == 0);
			CHECK(seq == 10);
			err[0] = '\0';
			{
				struct op_ctx oc;

				memset(&oc, 0, sizeof(oc));
				g_checked++;
				if (aik_sqlite_wal_replay(db, 7, op_cb, &oc, err,
							  sizeof(err)) != -1)
					report("replay with seq=-1 did not fail");
				op_ctx_free(&oc);
			}
			g_checked++;
			if (!strstr(err, "sqlite: wal record 3") ||
			    !strstr(err, "invalid WAL sequence"))
				report("seq=-1 err \"%s\" wrong", err);
			CHECK(raw_ll(aik_sqlite_handle(db),
				     "SELECT count(*) FROM wal_ops", &cnt) == 0);
			CHECK(cnt == 3);

			/* 非整数（JSON 字符串）同样非法；先清表让它是第 1 条 */
			CHECK(aik_sqlite_wal_clear(db, err, sizeof(err)) == 0);
			CHECK(aik_sqlite_wal_append(db,
						    "{\"op\":\"add\",\"seq\":\"8\"}",
						    &seq, err, sizeof(err)) == 0);
			CHECK(seq == 11);
			err[0] = '\0';
			{
				struct op_ctx oc;

				memset(&oc, 0, sizeof(oc));
				g_checked++;
				if (aik_sqlite_wal_replay(db, 7, op_cb, &oc, err,
							  sizeof(err)) != -1)
					report("replay with string seq did not fail");
				op_ctx_free(&oc);
			}
			g_checked++;
			if (!strstr(err, "sqlite: wal record 1") ||
			    !strstr(err, "invalid WAL sequence"))
				report("string seq err \"%s\" wrong", err);
			CHECK(raw_ll(aik_sqlite_handle(db),
				     "SELECT count(*) FROM wal_ops", &cnt) == 0);
			CHECK(cnt == 1);
			aik_sqlite_close(db);
			printf("negative: seq=-1 / seq=\"8\" -> -1, rows retained\n");
		}
	}

	/* h) create=0 打开不存在的库必须失败 */
	err[0] = '\0';
	{
		aik_sqlite *db = aik_sqlite_open(p_missing, 0, err, sizeof(err));

		CHECK(db == NULL);
		CHECK(strstr(err, "sqlite: ") != NULL);
		aik_sqlite_close(db);
	}

	/* i) 非法参数 */
	err[0] = '\0';
	CHECK(aik_sqlite_open("", 0, err, sizeof(err)) == NULL);

	(void)unlink(p_drop);
	(void)unlink(p_trunc);
	(void)unlink(p_badjson);
	(void)unlink(p_badwal);
	(void)unlink(p_noseq);
	(void)unlink(p_seqbad);
	(void)unlink(p_save);
	(void)rmdir(dir);
	free(p_drop);
	free(p_trunc);
	free(p_badjson);
	free(p_badwal);
	free(p_noseq);
	free(p_seqbad);
	free(p_save);
	free(p_missing);
	free(dir);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
	char err[256] = "";
	const char *dir = vectors_dir();
	char *vpath = path_in(dir, "sqlite.vectors.json");
	char *dbpath = path_in(dir, "engine.db");
	char *exp_path = path_in(dir, "expected_state.canonical.json");
	unsigned char *vbuf = NULL, *ref_before = NULL, *ref_after = NULL;
	size_t vlen = 0, ref_bn = 0, ref_an = 0;
	aik_json *v = NULL;
	aik_sqlite *db = NULL;
	char *payload = NULL;
	struct vec_ctx vecs;
	char sha_before[65] = "", sha_after[65] = "";

	memset(&vecs, 0, sizeof(vecs));
	printf("vectors: %s\n", dir);
	if (!vpath || !dbpath || !exp_path) {
		report("out of memory");
		goto out;
	}
	vbuf = read_file(vpath, &vlen);
	if (!vbuf) {
		report("cannot read %s", vpath);
		goto out;
	}
	v = aik_json_parse((const char *)vbuf, vlen, err, sizeof(err));
	if (!v) {
		report("parse %s: %s", vpath, err);
		goto out;
	}
	ref_before = read_file(dbpath, &ref_bn);
	if (!ref_before) {
		report("cannot read %s", dbpath);
		goto out;
	}
	sha256_hex(ref_before, ref_bn, sha_before);
	printf("reference db: %zu bytes sha256=%s\n", ref_bn, sha_before);

	db = aik_sqlite_open(dbpath, 0, err, sizeof(err));
	CHECK(db != NULL);
	if (!db) {
		report("open %s: %s", dbpath, err);
		goto out;
	}
	test_tables(db);
	test_busy_timeout(db);
	test_snapshot(db, v, &payload);
	test_vectors(db, v, &vecs);
	test_wal(db, v);
	if (payload)
		test_replay_state(db, v, exp_path, payload);
	aik_sqlite_close(db);
	db = NULL;

	if (payload) {
		test_write_path(payload, v, &vecs);
		test_negative(dbpath, payload);
	} else {
		report("no payload, write/negative tests skipped");
	}

	/* 参考库必须逐字节未变 */
	ref_after = read_file(dbpath, &ref_an);
	CHECK(ref_after != NULL);
	if (ref_after) {
		sha256_hex(ref_after, ref_an, sha_after);
		CHECK(ref_bn == ref_an && memcmp(ref_before, ref_after, ref_bn) == 0);
		CHECK(strcmp(sha_before, sha_after) == 0);
		if (strcmp(sha_before, sha_after) != 0)
			report("reference db changed: %s -> %s", sha_before,
			       sha_after);
	}

out:
	aik_sqlite_close(db);
	vec_ctx_free(&vecs);
	free(payload);
	aik_json_free(v);
	free(vbuf);
	free(ref_before);
	free(ref_after);
	free(vpath);
	free(dbpath);
	free(exp_path);
	printf("SUMMARY sqlite checked=%d mismatch=%d\n", g_checked,
	       g_mismatch);
	return g_mismatch ? 1 : 0;
}
