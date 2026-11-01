/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_store_npz.c - store_npz 自测（T2a 门禁）
 *
 * 覆盖（真读 parity 向量，AIK_STORE_VECTORS 默认
 * $HOME/aikernel-longterm/parity/vectors/storage）：
 *   1) engine.embeddings.npz 的条目恰为 generation/ids/matrix；
 *   2) ids：<U14、(549,)、首尾字符串与 snapshot.meta.json 一致、
 *      原始字节 sha256 == meta.npz.ids.sha256；
 *   3) matrix：<f8、(549,1024)、fortran_order=false、
 *      LE 字节 sha256 == meta.npz.matrix.sha256_le、row0/row_last 前 8 个
 *      double 的 Python float.hex 文本与 meta 一致；
 *   4) generation：<U32、shape ()、值 == meta；
 *   5) 负向（$TMPDIR 下副本）：改 1 字节 → 读失败；截断 → 打开失败；
 *      把 ids.npy 的 descr 改成 <U13（同长度替换，重算 CRC）→ 解析失败；
 *      另加路径穿越与重复条目 → 打开失败。
 *
 * 末行 "SUMMARY npz checked=... mismatch=..."，有失配退出码非 0。
 */
#define _GNU_SOURCE 1

#include "store/store_json.h"
#include "store/store_npz.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static int g_checked;
static int g_mismatch;

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
	n = (size_t)snprintf(tmpl, sizeof(tmpl), "%s/aiknpz.XXXXXX", base);
	if (n >= sizeof(tmpl))
		return NULL;
	if (!mkdtemp(tmpl))
		return NULL;
	return strdup(tmpl);
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
/* Python float.hex() 等价文本（13 位十六进制尾数）                     */
/* ------------------------------------------------------------------ */

static void py_float_hex(double v, char *out, size_t outlen)
{
	uint64_t bits;
	uint32_t sign, exp;
	uint64_t frac;

	memcpy(&bits, &v, sizeof(bits));
	sign = (uint32_t)(bits >> 63);
	exp = (uint32_t)((bits >> 52) & 0x7ffu);
	frac = bits & 0xfffffffffffffULL;
	if (exp == 0x7ffu) {
		(void)snprintf(out, outlen, "%s%s", sign ? "-" : "",
			       frac ? "nan" : "inf");
		return;
	}
	if (exp == 0 && frac == 0) {
		(void)snprintf(out, outlen, "%s0x0.0p+0", sign ? "-" : "");
		return;
	}
	if (exp == 0) {
		(void)snprintf(out, outlen, "%s0x0.%013llxp-1022",
			       sign ? "-" : "",
			       (unsigned long long)frac);
		return;
	}
	(void)snprintf(out, outlen, "%s0x1.%013llxp%+d", sign ? "-" : "",
		       (unsigned long long)frac, (int)exp - 1023);
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
/* 正向检查                                                            */
/* ------------------------------------------------------------------ */

static void test_entries(aik_npz *z, const aik_json *npz)
{
	const aik_json *ents = aik_json_get(npz, "entries");
	size_t i, n = aik_json_count(ents);

	CHECK(aik_npz_count(z) == 3);
	CHECK(n == 3);
	for (i = 0; i < n; i++) {
		const char *nm = aik_json_str(aik_json_at(ents, i));

		CHECK(nm != NULL && aik_npz_has(z, nm));
	}
	CHECK(!aik_npz_has(z, "nope"));
	for (i = 0; i < aik_npz_count(z); i++) {
		const char *nm = aik_npz_name_at(z, i);

		CHECK(nm && (strcmp(nm, "generation") == 0 ||
			     strcmp(nm, "ids") == 0 ||
			     strcmp(nm, "matrix") == 0));
		if (nm)
			printf("entry[%zu] = %s\n", i, nm);
	}
	CHECK(aik_npz_name_at(z, 3) == NULL);
}

static void test_ids(aik_npz *z, const aik_json *npz)
{
	const aik_json *im = aik_json_get(npz, "ids");
	const aik_json *shape = aik_json_get(im, "shape");
	unsigned char *buf = NULL;
	size_t len = 0;
	char err[256] = "";
	aik_npy npy;
	char hex[65], u[256];
	size_t nelem;

	CHECK(aik_npz_read(z, "ids", &buf, &len, err, sizeof(err)) == 0);
	if (!buf) {
		report("ids: read failed: %s", err);
		return;
	}
	memset(&npy, 0, sizeof(npy));
	CHECK(aik_npy_parse(buf, len, &npy, err, sizeof(err)) == 0);
	if (!npy.data) {
		report("ids: parse failed: %s", err);
		free(buf);
		return;
	}
	CHECK(strcmp(npy.descr, jstr(im, "dtype")) == 0);
	CHECK(npy.ndim == 1);
	CHECK(aik_json_count(shape) == 1);
	CHECK(npy.shape[0] == aik_json_int(aik_json_at(shape, 0)));
	CHECK(npy.fortran_order == 0);
	nelem = aik_npy_nelem(&npy);
	CHECK(nelem == (size_t)jint(im, "count"));
	CHECK(npy.data_len == nelem * 14u * 4u);

	sha256_hex(npy.data, npy.data_len, hex);
	if (strcmp(hex, jstr(im, "sha256")) != 0)
		report("ids: sha256 %s != meta %s", hex, jstr(im, "sha256"));
	else
		CHECK(1);

	CHECK(aik_npy_get_ustr(&npy, 0, u, sizeof(u)) >= 0);
	if (strcmp(u, jstr(im, "first")) != 0)
		report("ids: first \"%s\" != meta \"%s\"", u,
		       jstr(im, "first"));
	else
		CHECK(1);
	CHECK(aik_npy_get_ustr(&npy, nelem - 1, u, sizeof(u)) >= 0);
	if (strcmp(u, jstr(im, "last")) != 0)
		report("ids: last \"%s\" != meta \"%s\"", u,
		       jstr(im, "last"));
	else
		CHECK(1);
	printf("ids: n=%zu first=%s last=%s sha256=%s\n", nelem,
	       jstr(im, "first"), jstr(im, "last"), hex);

	/* 越界与短缓冲必须失败 */
	CHECK(aik_npy_get_ustr(&npy, nelem, u, sizeof(u)) == -1);
	CHECK(aik_npy_get_ustr(&npy, 0, u, 3) == -1);
	free(buf);
}

static void test_matrix(aik_npz *z, const aik_json *npz)
{
	const aik_json *mm = aik_json_get(npz, "matrix");
	const aik_json *shape = aik_json_get(mm, "shape");
	unsigned char *buf = NULL;
	size_t len = 0;
	char err[256] = "";
	aik_npy npy;
	char hex[65];
	size_t rows, cols, i;
	static const char *const keys[2] = { "row0_hex", "row_last_hex" };

	CHECK(aik_npz_read(z, "matrix", &buf, &len, err, sizeof(err)) == 0);
	if (!buf) {
		report("matrix: read failed: %s", err);
		return;
	}
	memset(&npy, 0, sizeof(npy));
	CHECK(aik_npy_parse(buf, len, &npy, err, sizeof(err)) == 0);
	if (!npy.data) {
		report("matrix: parse failed: %s", err);
		free(buf);
		return;
	}
	CHECK(strcmp(npy.descr, jstr(mm, "dtype")) == 0);
	CHECK(npy.ndim == 2);
	CHECK(npy.shape[0] == aik_json_int(aik_json_at(shape, 0)));
	CHECK(npy.shape[1] == aik_json_int(aik_json_at(shape, 1)));
	CHECK(npy.fortran_order == (aik_json_bool(aik_json_get(mm,
							       "fortran_order")) ?
				    1 : 0));
	rows = (size_t)npy.shape[0];
	cols = (size_t)npy.shape[1];
	CHECK(aik_npy_nelem(&npy) == rows * cols);
	CHECK(npy.data_len == rows * cols * 8u);

	sha256_hex(npy.data, npy.data_len, hex);
	if (strcmp(hex, jstr(mm, "sha256_le")) != 0)
		report("matrix: sha256_le %s != meta %s", hex,
		       jstr(mm, "sha256_le"));
	else
		CHECK(1);
	printf("matrix: %zux%zu sha256_le=%s\n", rows, cols, hex);

	for (i = 0; i < 2; i++) {
		const aik_json *want = aik_json_get(mm, keys[i]);
		size_t row = (i == 0) ? 0 : rows - 1;
		size_t base = row * cols;
		size_t k;

		CHECK(aik_json_count(want) == 8);
		for (k = 0; k < 8; k++) {
			double d = 0.0;
			const char *exp = aik_json_str(aik_json_at(want, k));

			CHECK(aik_npy_get_f8(&npy, base + k, &d) == 0);
			py_float_hex(d, hex, sizeof(hex));
			if (!exp || strcmp(hex, exp) != 0)
				report("matrix: %s[%zu] %s != meta %s", keys[i],
				       k, hex, exp ? exp : "(null)");
			else
				CHECK(1);
			if (i == 0)
				printf("  row0[%zu] = %s\n", k, hex);
		}
	}
	/* 越界必须失败 */
	{
		double dummy = 0.0;

		CHECK(aik_npy_get_f8(&npy, rows * cols, &dummy) == -1);
	}
	free(buf);
}

static void test_generation(aik_npz *z, const aik_json *npz)
{
	const aik_json *gm = aik_json_get(npz, "generation");
	unsigned char *buf = NULL;
	size_t len = 0;
	char err[256] = "";
	aik_npy npy;
	char u[128];

	CHECK(aik_npz_read(z, "generation", &buf, &len, err, sizeof(err)) == 0);
	if (!buf) {
		report("generation: read failed: %s", err);
		return;
	}
	memset(&npy, 0, sizeof(npy));
	CHECK(aik_npy_parse(buf, len, &npy, err, sizeof(err)) == 0);
	if (!npy.data) {
		report("generation: parse failed: %s", err);
		free(buf);
		return;
	}
	CHECK(strcmp(npy.descr, jstr(gm, "dtype")) == 0);
	CHECK(npy.ndim == 0);
	CHECK(aik_npy_nelem(&npy) == 1);
	CHECK(npy.data_len == 128);
	CHECK(aik_npy_get_ustr(&npy, 0, u, sizeof(u)) >= 0);
	if (strcmp(u, jstr(gm, "value")) != 0)
		report("generation: \"%s\" != meta \"%s\"", u,
		       jstr(gm, "value"));
	else
		CHECK(1);
	CHECK((size_t)aik_npy_get_ustr(&npy, 0, u, sizeof(u)) ==
	      (size_t)jint(gm, "length"));
	printf("generation: %s (len=%zu)\n", u, strlen(u));
	free(buf);
}

/* ------------------------------------------------------------------ */
/* 负向：临时 zip 构造（method 0，便于精确篡改 .npy 头）                */
/* ------------------------------------------------------------------ */

struct zent {
	const char *name;
	const unsigned char *data;
	size_t len;
};

static void put16(unsigned char *p, unsigned int v)
{
	p[0] = (unsigned char)(v & 0xffu);
	p[1] = (unsigned char)((v >> 8) & 0xffu);
}

static void put32(unsigned char *p, unsigned long v)
{
	p[0] = (unsigned char)(v & 0xfful);
	p[1] = (unsigned char)((v >> 8) & 0xfful);
	p[2] = (unsigned char)((v >> 16) & 0xfful);
	p[3] = (unsigned char)((v >> 24) & 0xfful);
}

static int write_store_zip(const char *path, const struct zent *e, size_t n)
{
	FILE *f;
	size_t off[16], crc[16], i, pos = 0, cd_off, cd_size = 0;
	int ok = 1;

	if (n > 16)
		return -1;
	for (i = 0; i < n; i++)
		crc[i] = (size_t)crc32(0L, e[i].data, (uInt)e[i].len);
	f = fopen(path, "wb");
	if (!f)
		return -1;
	for (i = 0; i < n; i++) {
		unsigned char h[30];
		size_t nl = strlen(e[i].name);

		memset(h, 0, sizeof(h));
		put32(h, 0x04034b50ul);
		put16(h + 4, 20);
		put16(h + 8, 0);	/* 无 data descriptor */
		put16(h + 10, 0);	/* method 0 = store */
		put32(h + 14, (unsigned long)crc[i]);
		put32(h + 18, (unsigned long)e[i].len);
		put32(h + 22, (unsigned long)e[i].len);
		put16(h + 26, (unsigned int)nl);
		off[i] = pos;
		if (fwrite(h, 1, sizeof(h), f) != sizeof(h) ||
		    fwrite(e[i].name, 1, nl, f) != nl ||
		    fwrite(e[i].data, 1, e[i].len, f) != e[i].len) {
			ok = 0;
			break;
		}
		pos += sizeof(h) + nl + e[i].len;
	}
	if (!ok) {
		fclose(f);
		return -1;
	}
	cd_off = pos;
	for (i = 0; i < n; i++) {
		unsigned char c[46];
		size_t nl = strlen(e[i].name);

		memset(c, 0, sizeof(c));
		put32(c, 0x02014b50ul);
		put16(c + 4, 20);
		put16(c + 6, 20);
		put16(c + 10, 0);
		put32(c + 16, (unsigned long)crc[i]);
		put32(c + 20, (unsigned long)e[i].len);
		put32(c + 24, (unsigned long)e[i].len);
		put16(c + 28, (unsigned int)nl);
		put32(c + 42, (unsigned long)off[i]);
		if (fwrite(c, 1, sizeof(c), f) != sizeof(c) ||
		    fwrite(e[i].name, 1, nl, f) != nl) {
			ok = 0;
			break;
		}
		cd_size += sizeof(c) + nl;
	}
	if (ok) {
		unsigned char eocd[22];

		memset(eocd, 0, sizeof(eocd));
		put32(eocd, 0x06054b50ul);
		put16(eocd + 8, (unsigned int)n);
		put16(eocd + 10, (unsigned int)n);
		put32(eocd + 12, (unsigned long)cd_size);
		put32(eocd + 16, (unsigned long)cd_off);
		if (fwrite(eocd, 1, sizeof(eocd), f) != sizeof(eocd))
			ok = 0;
	}
	fclose(f);
	return ok ? 0 : -1;
}

static unsigned char *find_bytes(unsigned char *buf, size_t len,
				 const char *pat, size_t plen)
{
	size_t i;

	for (i = 0; i + plen <= len; i++) {
		if (memcmp(buf + i, pat, plen) == 0)
			return buf + i;
	}
	return NULL;
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

static void test_flipped(const char *npzpath, const char *dir)
{
	unsigned char *orig, *copy = NULL;
	size_t olen = 0;
	char *p = join_path(dir, "flipped.npz");
	char err[256] = "";
	aik_npz *z;

	orig = read_file(npzpath, &olen);
	CHECK(orig != NULL);
	if (!orig || !p) {
		free(orig);
		free(p);
		return;
	}
	copy = malloc(olen);
	CHECK(copy != NULL);
	if (copy) {
		memcpy(copy, orig, olen);
		copy[olen / 2] ^= 0x40;	/* 落在 matrix 的 deflate 流里 */
		CHECK(write_file(p, copy, olen) == 0);
		z = aik_npz_open(p, err, sizeof(err));
		if (!z) {
			printf("negative: flipped byte rejected at open: %s\n",
			       err);
			CHECK(1);
		} else {
			unsigned char *d = NULL;
			size_t n = 0;
			int rc = aik_npz_read(z, "matrix", &d, &n, err,
					      sizeof(err));

			CHECK(rc != 0);
			if (rc != 0)
				printf("negative: flipped byte read -> %d (%s)\n",
				       rc, err);
			free(d);
			aik_npz_close(z);
		}
	}
	free(copy);
	free(orig);
	(void)unlink(p);
	free(p);
}

static void test_truncated(const char *npzpath, const char *dir)
{
	unsigned char *orig;
	size_t olen = 0;
	char *p = join_path(dir, "truncated.npz");
	char err[256] = "";
	aik_npz *z;

	orig = read_file(npzpath, &olen);
	CHECK(orig != NULL);
	if (!orig || !p) {
		free(orig);
		free(p);
		return;
	}
	CHECK(olen > 200);
	CHECK(write_file(p, orig, olen - 200) == 0);
	z = aik_npz_open(p, err, sizeof(err));
	CHECK(z == NULL);
	if (z) {
		report("truncated npz still opened");
		aik_npz_close(z);
	} else {
		printf("negative: truncated npz rejected: %s\n", err);
	}
	free(orig);
	(void)unlink(p);
	free(p);
}

static void test_bad_descr(aik_npz *z, const char *dir)
{
	unsigned char *ids = NULL, *gen = NULL;
	size_t idslen = 0, genlen = 0;
	unsigned char *hit;
	char *p = join_path(dir, "baddescr.npz");
	char err[256] = "";
	struct zent ents[2];
	aik_npz *z2;
	aik_npy npy;
	int rc;

	CHECK(p != NULL);
	CHECK(aik_npz_read(z, "ids", &ids, &idslen, err, sizeof(err)) == 0);
	CHECK(aik_npz_read(z, "generation", &gen, &genlen, err,
			   sizeof(err)) == 0);
	if (!p || !ids || !gen) {
		free(ids);
		free(gen);
		free(p);
		return;
	}
	hit = find_bytes(ids, idslen, "<U14", 4);
	CHECK(hit != NULL);
	if (!hit) {
		free(ids);
		free(gen);
		free(p);
		return;
	}
	memcpy(hit, "<U13", 4);	/* 同长度替换：数据段长度与 itemsize 不符 */
	ents[0].name = "ids.npy";
	ents[0].data = ids;
	ents[0].len = idslen;
	ents[1].name = "generation.npy";
	ents[1].data = gen;
	ents[1].len = genlen;
	CHECK(write_store_zip(p, ents, 2) == 0);
	z2 = aik_npz_open(p, err, sizeof(err));
	CHECK(z2 != NULL);
	if (z2) {
		unsigned char *d = NULL;
		size_t n = 0;

		rc = aik_npz_read(z2, "ids", &d, &n, err, sizeof(err));
		CHECK(rc == 0);	/* zip 层合法（CRC 已重算） */
		if (rc == 0) {
			memset(&npy, 0, sizeof(npy));
			rc = aik_npy_parse(d, n, &npy, err, sizeof(err));
			CHECK(rc != 0);
			printf("negative: descr <U13 parse -> %d (%s)\n", rc,
			       err);
		}
		free(d);
		aik_npz_close(z2);
	}
	free(ids);
	free(gen);
	(void)unlink(p);
	free(p);
}

static void test_unsafe_entries(aik_npz *z, const char *dir)
{
	unsigned char *gen = NULL;
	size_t genlen = 0;
	char err[256] = "";
	char *p = join_path(dir, "unsafe.npz");
	struct zent one;
	aik_npz *z2;

	CHECK(p != NULL);
	CHECK(aik_npz_read(z, "generation", &gen, &genlen, err,
			   sizeof(err)) == 0);
	if (!p || !gen) {
		free(gen);
		free(p);
		return;
	}

	/* 路径穿越 */
	one.name = "../escape.npy";
	one.data = gen;
	one.len = genlen;
	CHECK(write_store_zip(p, &one, 1) == 0);
	z2 = aik_npz_open(p, err, sizeof(err));
	CHECK(z2 == NULL);
	if (z2) {
		report("traversal entry accepted");
		aik_npz_close(z2);
	} else {
		printf("negative: traversal entry rejected: %s\n", err);
	}
	(void)unlink(p);

	/* 重复条目 */
	{
		struct zent dup[2];

		dup[0].name = "ids.npy";
		dup[0].data = gen;
		dup[0].len = genlen;
		dup[1].name = "ids.npy";
		dup[1].data = gen;
		dup[1].len = genlen;
		CHECK(write_store_zip(p, dup, 2) == 0);
		z2 = aik_npz_open(p, err, sizeof(err));
		CHECK(z2 == NULL);
		if (z2) {
			report("duplicate entry accepted");
			aik_npz_close(z2);
		} else {
			printf("negative: duplicate entry rejected: %s\n", err);
		}
		(void)unlink(p);
	}
	free(gen);
	free(p);
}

static void test_negatives(aik_npz *z, const char *npzpath)
{
	char *dir = make_tmpdir();
	char err[256] = "";
	unsigned char *d = NULL;
	size_t n = 0;

	if (!dir) {
		report("negative: cannot create tmpdir");
		return;
	}
	printf("negative: tmpdir %s\n", dir);
	CHECK(aik_npz_read(z, "nope", &d, &n, err, sizeof(err)) != 0);
	free(d);
	d = NULL;
	test_flipped(npzpath, dir);
	test_truncated(npzpath, dir);
	test_bad_descr(z, dir);
	test_unsafe_entries(z, dir);
	(void)rmdir(dir);
	free(dir);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
	char *npzpath = vpath_alloc("engine.embeddings.npz");
	char *metapath = vpath_alloc("snapshot.meta.json");
	unsigned char *mbuf;
	size_t mlen = 0;
	aik_json *meta;
	const aik_json *npz;
	aik_npz *z;
	char err[256] = "";

	printf("vectors: %s\n", vectors_dir());
	if (!npzpath || !metapath) {
		report("out of memory");
		free(npzpath);
		free(metapath);
		return 1;
	}
	mbuf = read_file(metapath, &mlen);
	if (!mbuf) {
		report("cannot read %s", metapath);
		free(npzpath);
		free(metapath);
		return 1;
	}
	meta = aik_json_parse((const char *)mbuf, mlen, err, sizeof(err));
	free(mbuf);
	if (!meta) {
		report("meta parse failed: %s", err);
		free(npzpath);
		free(metapath);
		return 1;
	}
	npz = aik_json_get(meta, "npz");
	CHECK(npz != NULL);

	z = aik_npz_open(npzpath, err, sizeof(err));
	if (!z) {
		report("open %s failed: %s", npzpath, err);
	} else {
		test_entries(z, npz);
		test_ids(z, npz);
		test_matrix(z, npz);
		test_generation(z, npz);
		test_negatives(z, npzpath);
		aik_npz_close(z);
	}

	printf("SUMMARY npz checked=%d mismatch=%d\n", g_checked, g_mismatch);
	aik_json_free(meta);
	free(npzpath);
	free(metapath);
	return g_mismatch ? 1 : 0;
}
