/* SPDX-License-Identifier: GPL-2.0 */
/*
 * store_npz_write.c - .npz 写入（ZIP store + NPY 1.0）
 *
 * 设计见 store_npz_write.h。ZIP 只写最保守的子集：method 0（store）、
 * 通用标志 0、无 extra/comment、无 data descriptor。NPY 头按 numpy 1.x
 * 的 ARRAY_ALIGN=64 规则填充（magic+版本+头长+头 = 64 的整数倍），
 * 读侧（store_npz.c 的 aik_npy_parse）与 numpy 均接受。
 *
 * 所有分配失败/参数错误都在写盘前判定；写盘阶段失败会删除临时文件。
 */
#define _POSIX_C_SOURCE 200809L

#include "store/store_npz_write.h"
#include "store/store_npz.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#define NPY_MAGIC_LEN 6
#define NPY_PREFIX_LEN 10	/* magic(6) + version(2) + hlen(2) */
#define NPY_ALIGN 64
#define ZIP_SIG_LOC 0x04034b50u
#define ZIP_SIG_CEN 0x02014b50u
#define ZIP_SIG_EOCD 0x06054b50u
#define ZIP_VERSION 20
#define NPZ_MAX_ENTRIES 3
#define GEN_WIDTH 32
#define ID_MAX_CODEPOINTS 64

static void npz_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || errlen == 0)
		return;
	va_start(ap, fmt);
	(void)vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

/* ------------------------------------------------------------------ */
/* 可增长缓冲                                                         */
/* ------------------------------------------------------------------ */
typedef struct {
	unsigned char *p;
	size_t len;
	size_t cap;
} nbuf;

static int buf_reserve(nbuf *b, size_t extra)
{
	size_t need;
	size_t next;
	unsigned char *grown;

	if (extra > SIZE_MAX - b->len)
		return -1;
	need = b->len + extra;
	if (need <= b->cap)
		return 0;
	next = b->cap ? b->cap : 256;
	while (next < need) {
		if (next > SIZE_MAX / 2)
			return -1;
		next *= 2;
	}
	grown = realloc(b->p, next);
	if (!grown)
		return -1;
	b->p = grown;
	b->cap = next;
	return 0;
}

static int buf_put(nbuf *b, const void *data, size_t n)
{
	if (buf_reserve(b, n) != 0)
		return -1;
	if (n)
		memcpy(b->p + b->len, data, n);
	b->len += n;
	return 0;
}

static int buf_u16(nbuf *b, uint32_t v)
{
	unsigned char x[2];

	x[0] = (unsigned char)(v & 0xffu);
	x[1] = (unsigned char)((v >> 8) & 0xffu);
	return buf_put(b, x, sizeof(x));
}

static int buf_u32(nbuf *b, uint32_t v)
{
	unsigned char x[4];

	x[0] = (unsigned char)(v & 0xffu);
	x[1] = (unsigned char)((v >> 8) & 0xffu);
	x[2] = (unsigned char)((v >> 16) & 0xffu);
	x[3] = (unsigned char)((v >> 24) & 0xffu);
	return buf_put(b, x, sizeof(x));
}

/* ------------------------------------------------------------------ */
/* UTF-8 → UTF-32LE                                                    */
/* ------------------------------------------------------------------ */

/*
 * utf8_to_cps - 严格解码 UTF-8 为码点数组
 *
 * 返回码点数（>=0）；非法序列、过长编码、代理区、> U+10FFFF 返回 -1。
 * *out 为 malloc 数组（调用者 free），空串时可为 NULL。
 */
static long utf8_to_cps(const char *s, uint32_t **out)
{
	const unsigned char *p = (const unsigned char *)s;
	uint32_t *cps;
	size_t n = 0;
	size_t cap;

	*out = NULL;
	if (!s)
		return -1;
	cap = strlen(s) + 1;
	cps = malloc(cap * sizeof(*cps));
	if (!cps)
		return -1;
	while (*p) {
		uint32_t c = p[0];
		uint32_t v;
		int len;
		int i;

		if (c < 0x80) {
			v = c;
			len = 1;
		} else if ((c & 0xe0) == 0xc0) {
			v = c & 0x1fu;
			len = 2;
		} else if ((c & 0xf0) == 0xe0) {
			v = c & 0x0fu;
			len = 3;
		} else if ((c & 0xf8) == 0xf0) {
			v = c & 0x07u;
			len = 4;
		} else {
			free(cps);
			return -1;
		}
		for (i = 1; i < len; i++) {
			if ((p[i] & 0xc0) != 0x80) {
				free(cps);
				return -1;
			}
			v = (v << 6) | (p[i] & 0x3fu);
		}
		if ((len == 2 && v < 0x80) || (len == 3 && v < 0x800) ||
		    (len == 4 && v < 0x10000)) {
			free(cps);
			return -1;
		}
		if (v >= 0xd800 && v <= 0xdfff) {
			free(cps);
			return -1;
		}
		if (v > 0x10ffff) {
			free(cps);
			return -1;
		}
		cps[n++] = v;
		p += len;
	}
	if (n == 0) {
		free(cps);
		return 0;
	}
	*out = cps;
	return (long)n;
}

/* ------------------------------------------------------------------ */
/* NPY 构造                                                           */
/* ------------------------------------------------------------------ */

/*
 * npy_build - 生成完整 .npy 字节（头 + 数据）
 *
 * shape 为 shape 元组文本（如 "(3,)" / "(3, 4)" / "()"）。头部总长按
 * NPY_ALIGN 对齐；hlen 字段 = 头文本长度 + 1 个换行 + 空格填充。
 */
static int npy_build(const char *descr, const char *shape,
		     const unsigned char *data, size_t data_len, nbuf *out,
		     char *err, size_t errlen)
{
	char text[256];
	unsigned char prefix[NPY_PREFIX_LEN];
	size_t text_len;
	size_t hlen;
	size_t padlen;
	size_t total_h;
	int n;

	n = snprintf(text, sizeof(text),
		     "{'descr': '%s', 'fortran_order': False, 'shape': %s, }",
		     descr, shape);
	if (n < 0 || (size_t)n >= sizeof(text)) {
		npz_err(err, errlen, "npz_write: npy header too long");
		return -1;
	}
	text_len = (size_t)n;
	hlen = text_len + 1;	/* 末尾换行 */
	padlen = NPY_ALIGN - ((NPY_PREFIX_LEN + hlen) % NPY_ALIGN);
	total_h = hlen + padlen;
	if (total_h > 0xffffu) {
		npz_err(err, errlen, "npz_write: npy header overflows uint16");
		return -1;
	}
	memcpy(prefix, "\x93NUMPY", NPY_MAGIC_LEN);
	prefix[6] = 1;
	prefix[7] = 0;
	prefix[8] = (unsigned char)(total_h & 0xffu);
	prefix[9] = (unsigned char)((total_h >> 8) & 0xffu);

	if (buf_put(out, prefix, sizeof(prefix)) != 0 ||
	    buf_put(out, text, text_len) != 0) {
		npz_err(err, errlen, "npz_write: out of memory");
		return -1;
	}
	{
		static const char spaces[NPY_ALIGN] = {
			' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
			' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
			' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
			' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
			' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
			' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
			' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
			' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '
		};

		if (buf_put(out, spaces, padlen) != 0 ||
		    buf_put(out, "\n", 1) != 0) {
			npz_err(err, errlen, "npz_write: out of memory");
			return -1;
		}
	}
	if (data_len && buf_put(out, data, data_len) != 0) {
		npz_err(err, errlen, "npz_write: out of memory");
		return -1;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* ZIP 构造                                                           */
/* ------------------------------------------------------------------ */
struct zent {
	const char *name;
	unsigned char *data;
	size_t len;
	uint32_t crc;
	size_t off;
};

static uint32_t crc_of(const unsigned char *data, size_t len)
{
	uLong crc = crc32(0L, Z_NULL, 0);

	while (len > 0) {
		uInt chunk = len > 0x40000000u ? 0x40000000u : (uInt)len;

		crc = crc32(crc, data, chunk);
		data += chunk;
		len -= chunk;
	}
	return (uint32_t)crc;
}

static int zip_local(nbuf *out, struct zent *e)
{
	size_t name_len = strlen(e->name);

	e->off = out->len;
	if (buf_u32(out, ZIP_SIG_LOC) != 0 ||
	    buf_u16(out, ZIP_VERSION) != 0 ||
	    buf_u16(out, 0) != 0 ||	/* flags */
	    buf_u16(out, 0) != 0 ||	/* method: store */
	    buf_u16(out, 0) != 0 ||	/* mod time */
	    buf_u16(out, 0) != 0 ||	/* mod date */
	    buf_u32(out, e->crc) != 0 ||
	    buf_u32(out, (uint32_t)e->len) != 0 ||
	    buf_u32(out, (uint32_t)e->len) != 0 ||
	    buf_u16(out, (uint32_t)name_len) != 0 ||
	    buf_u16(out, 0) != 0 ||	/* extra len */
	    buf_put(out, e->name, name_len) != 0 ||
	    buf_put(out, e->data, e->len) != 0)
		return -1;
	return 0;
}

static int zip_central(nbuf *out, const struct zent *e)
{
	size_t name_len = strlen(e->name);

	if (buf_u32(out, ZIP_SIG_CEN) != 0 ||
	    buf_u16(out, ZIP_VERSION) != 0 ||	/* version made by */
	    buf_u16(out, ZIP_VERSION) != 0 ||	/* version needed */
	    buf_u16(out, 0) != 0 ||		/* flags */
	    buf_u16(out, 0) != 0 ||		/* method */
	    buf_u16(out, 0) != 0 ||		/* mod time */
	    buf_u16(out, 0) != 0 ||		/* mod date */
	    buf_u32(out, e->crc) != 0 ||
	    buf_u32(out, (uint32_t)e->len) != 0 ||
	    buf_u32(out, (uint32_t)e->len) != 0 ||
	    buf_u16(out, (uint32_t)name_len) != 0 ||
	    buf_u16(out, 0) != 0 ||	/* extra len */
	    buf_u16(out, 0) != 0 ||	/* comment len */
	    buf_u16(out, 0) != 0 ||	/* disk start */
	    buf_u16(out, 0) != 0 ||	/* internal attrs */
	    buf_u32(out, 0) != 0 ||	/* external attrs */
	    buf_u32(out, (uint32_t)e->off) != 0 ||
	    buf_put(out, e->name, name_len) != 0)
		return -1;
	return 0;
}

/* ------------------------------------------------------------------ */
/* 原子写                                                             */
/* ------------------------------------------------------------------ */
static int write_all(int fd, const unsigned char *data, size_t len)
{
	while (len > 0) {
		ssize_t n = write(fd, data, len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		data += (size_t)n;
		len -= (size_t)n;
	}
	return 0;
}

static int fsync_dir_of(const char *path, char *err, size_t errlen)
{
	char *copy;
	char *slash;
	int fd;
	int rc = 0;

	copy = strdup(path);
	if (!copy) {
		npz_err(err, errlen, "npz_write: out of memory");
		return -1;
	}
	slash = strrchr(copy, '/');
	if (slash) {
		*slash = '\0';
		if (!copy[0])
			strcpy(copy, "/");
	} else {
		strcpy(copy, ".");
	}
	fd = open(copy, O_RDONLY);
	if (fd < 0) {
		npz_err(err, errlen, "npz_write: cannot open dir %s: %s", copy,
			strerror(errno));
		free(copy);
		return -1;
	}
	if (fsync(fd) != 0) {
		npz_err(err, errlen, "npz_write: fsync dir %s failed: %s", copy,
			strerror(errno));
		rc = -1;
	}
	(void)close(fd);
	free(copy);
	return rc;
}

static int write_atomic(const char *path, const unsigned char *data, size_t len,
			char *err, size_t errlen)
{
	char *tmp;
	size_t tlen = strlen(path);
	int fd = -1;
	int rc = -1;

	tmp = malloc(tlen + 32);
	if (!tmp) {
		npz_err(err, errlen, "npz_write: out of memory");
		return -1;
	}
	(void)snprintf(tmp, tlen + 32, "%s.tmp.%ld", path, (long)getpid());
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		npz_err(err, errlen, "npz_write: cannot create %s: %s", tmp,
			strerror(errno));
		goto out;
	}
	if (write_all(fd, data, len) != 0) {
		npz_err(err, errlen, "npz_write: write failed on %s: %s", tmp,
			strerror(errno));
		goto out;
	}
	if (fsync(fd) != 0) {
		npz_err(err, errlen, "npz_write: fsync failed on %s: %s", tmp,
			strerror(errno));
		goto out;
	}
	if (close(fd) != 0) {
		fd = -1;
		npz_err(err, errlen, "npz_write: close failed on %s: %s", tmp,
			strerror(errno));
		goto out;
	}
	fd = -1;
	if (rename(tmp, path) != 0) {
		npz_err(err, errlen, "npz_write: rename %s -> %s failed: %s",
			tmp, path, strerror(errno));
		goto out;
	}
	if (fsync_dir_of(path, err, errlen) != 0)
		goto out;
	rc = 0;

out:
	if (fd >= 0)
		(void)close(fd);
	if (rc != 0)
		(void)unlink(tmp);
	free(tmp);
	return rc;
}

/* ------------------------------------------------------------------ */
/* 公开接口                                                           */
/* ------------------------------------------------------------------ */
int aik_npz_write_embeddings(const char *path, const char *generation,
			     const char *const *ids, size_t n_ids,
			     const double *matrix, int dim,
			     char *err, size_t errlen)
{
	nbuf ids_npy = { NULL, 0, 0 };
	nbuf mat_npy = { NULL, 0, 0 };
	nbuf gen_npy = { NULL, 0, 0 };
	nbuf zip = { NULL, 0, 0 };
	struct zent ents[NPZ_MAX_ENTRIES];
	uint32_t **id_cps = NULL;
	long *id_len = NULL;
	uint32_t *gen_cps = NULL;
	long gen_len;
	size_t width = 1;
	size_t i;
	size_t k;
	size_t cd_off;
	size_t cd_size;
	char descr[32];
	char shape[64];
	int rc = -1;

	memset(ents, 0, sizeof(ents));
	if (!path || !*path) {
		npz_err(err, errlen, "npz_write: path is NULL/empty");
		return -1;
	}
	if (!generation || !*generation) {
		npz_err(err, errlen, "npz_write: generation is NULL/empty");
		return -1;
	}
	if (!ids || n_ids == 0) {
		npz_err(err, errlen, "npz_write: no embeddings to write (n_ids=0)");
		return -1;
	}
	if (!matrix || dim <= 0) {
		npz_err(err, errlen, "npz_write: invalid matrix/dim");
		return -1;
	}
	if (n_ids > (size_t)INT32_MAX || (size_t)dim > (size_t)INT32_MAX) {
		npz_err(err, errlen, "npz_write: matrix too large");
		return -1;
	}

	/* ids：严格 UTF-8 → 码点；同时求最大宽度 */
	id_cps = calloc(n_ids, sizeof(*id_cps));
	id_len = calloc(n_ids, sizeof(*id_len));
	if (!id_cps || !id_len) {
		npz_err(err, errlen, "npz_write: out of memory");
		goto out;
	}
	for (i = 0; i < n_ids; i++) {
		long n;

		if (!ids[i] || !ids[i][0]) {
			npz_err(err, errlen, "npz_write: ids[%zu] is NULL/empty",
				i);
			goto out;
		}
		n = utf8_to_cps(ids[i], &id_cps[i]);
		if (n < 0) {
			npz_err(err, errlen,
				"npz_write: ids[%zu] is not valid UTF-8", i);
			goto out;
		}
		if ((size_t)n > ID_MAX_CODEPOINTS) {
			npz_err(err, errlen,
				"npz_write: ids[%zu] has %ld codepoints (max %d)",
				i, n, ID_MAX_CODEPOINTS);
			goto out;
		}
		id_len[i] = n;
		if ((size_t)n > width)
			width = (size_t)n;
	}
	gen_len = utf8_to_cps(generation, &gen_cps);
	if (gen_len <= 0) {
		npz_err(err, errlen, "npz_write: generation is empty/invalid");
		goto out;
	}
	if ((size_t)gen_len > GEN_WIDTH) {
		npz_err(err, errlen,
			"npz_write: generation has %ld codepoints (max %d)",
			gen_len, GEN_WIDTH);
		goto out;
	}

	/* ids.npy */
	if (n_ids > AIK_NPZ_MAX_ENTRY / (width * 4)) {
		npz_err(err, errlen, "npz_write: ids array too large");
		goto out;
	}
	{
		size_t bytes = n_ids * width * 4;
		unsigned char *raw = calloc(bytes ? bytes : 1, 1);

		if (!raw) {
			npz_err(err, errlen, "npz_write: out of memory (ids)");
			goto out;
		}
		for (i = 0; i < n_ids; i++) {
			for (k = 0; k < (size_t)id_len[i]; k++) {
				uint32_t cp = id_cps[i][k];
				unsigned char *p =
					raw + (i * width + k) * 4;

				p[0] = (unsigned char)(cp & 0xffu);
				p[1] = (unsigned char)((cp >> 8) & 0xffu);
				p[2] = (unsigned char)((cp >> 16) & 0xffu);
				p[3] = (unsigned char)((cp >> 24) & 0xffu);
			}
		}
		(void)snprintf(descr, sizeof(descr), "<U%zu", width);
		(void)snprintf(shape, sizeof(shape), "(%zu,)", n_ids);
		rc = npy_build(descr, shape, raw, bytes, &ids_npy, err, errlen);
		free(raw);
		if (rc != 0)
			goto out;
	}

	/* matrix.npy */
	if (n_ids > SIZE_MAX / (size_t)dim ||
	    n_ids * (size_t)dim > AIK_NPZ_MAX_ENTRY / 8) {
		npz_err(err, errlen, "npz_write: matrix too large");
		rc = -1;
		goto out;
	}
	{
		size_t nelem = n_ids * (size_t)dim;
		size_t bytes = nelem * 8;
		unsigned char *raw = malloc(bytes);

		if (!raw) {
			npz_err(err, errlen, "npz_write: out of memory (matrix)");
			goto out;
		}
		for (i = 0; i < nelem; i++) {
			uint64_t bits;
			double v = matrix[i];

			memcpy(&bits, &v, sizeof(bits));
			raw[i * 8 + 0] = (unsigned char)(bits & 0xffu);
			raw[i * 8 + 1] = (unsigned char)((bits >> 8) & 0xffu);
			raw[i * 8 + 2] = (unsigned char)((bits >> 16) & 0xffu);
			raw[i * 8 + 3] = (unsigned char)((bits >> 24) & 0xffu);
			raw[i * 8 + 4] = (unsigned char)((bits >> 32) & 0xffu);
			raw[i * 8 + 5] = (unsigned char)((bits >> 40) & 0xffu);
			raw[i * 8 + 6] = (unsigned char)((bits >> 48) & 0xffu);
			raw[i * 8 + 7] = (unsigned char)((bits >> 56) & 0xffu);
		}
		(void)snprintf(shape, sizeof(shape), "(%zu, %d)", n_ids, dim);
		rc = npy_build("<f8", shape, raw, bytes, &mat_npy, err, errlen);
		free(raw);
		if (rc != 0)
			goto out;
	}

	/* generation.npy：0-D 标量，固定 32 码点 */
	{
		unsigned char raw[GEN_WIDTH * 4];
		size_t bytes = sizeof(raw);

		memset(raw, 0, sizeof(raw));
		for (k = 0; k < (size_t)gen_len; k++) {
			uint32_t cp = gen_cps[k];

			raw[k * 4 + 0] = (unsigned char)(cp & 0xffu);
			raw[k * 4 + 1] = (unsigned char)((cp >> 8) & 0xffu);
			raw[k * 4 + 2] = (unsigned char)((cp >> 16) & 0xffu);
			raw[k * 4 + 3] = (unsigned char)((cp >> 24) & 0xffu);
		}
		(void)snprintf(descr, sizeof(descr), "<U%d", GEN_WIDTH);
		rc = npy_build(descr, "()", raw, bytes, &gen_npy, err, errlen);
		if (rc != 0)
			goto out;
	}

	/* 组装 ZIP */
	if (ids_npy.len > AIK_NPZ_MAX_ENTRY || mat_npy.len > AIK_NPZ_MAX_ENTRY ||
	    gen_npy.len > AIK_NPZ_MAX_ENTRY) {
		npz_err(err, errlen, "npz_write: entry exceeds size limit");
		rc = -1;
		goto out;
	}
	ents[0].name = "ids.npy";
	ents[0].data = ids_npy.p;
	ents[0].len = ids_npy.len;
	ents[1].name = "matrix.npy";
	ents[1].data = mat_npy.p;
	ents[1].len = mat_npy.len;
	ents[2].name = "generation.npy";
	ents[2].data = gen_npy.p;
	ents[2].len = gen_npy.len;
	for (i = 0; i < NPZ_MAX_ENTRIES; i++) {
		ents[i].crc = crc_of(ents[i].data, ents[i].len);
		if (zip_local(&zip, &ents[i]) != 0) {
			npz_err(err, errlen, "npz_write: out of memory (zip)");
			rc = -1;
			goto out;
		}
	}
	cd_off = zip.len;
	for (i = 0; i < NPZ_MAX_ENTRIES; i++) {
		if (zip_central(&zip, &ents[i]) != 0) {
			npz_err(err, errlen, "npz_write: out of memory (zip)");
			rc = -1;
			goto out;
		}
	}
	cd_size = zip.len - cd_off;
	if (zip.len > AIK_NPZ_MAX_FILE) {
		npz_err(err, errlen, "npz_write: file exceeds size limit");
		rc = -1;
		goto out;
	}
	if (buf_u32(&zip, ZIP_SIG_EOCD) != 0 ||
	    buf_u16(&zip, 0) != 0 ||
	    buf_u16(&zip, 0) != 0 ||
	    buf_u16(&zip, NPZ_MAX_ENTRIES) != 0 ||
	    buf_u16(&zip, NPZ_MAX_ENTRIES) != 0 ||
	    buf_u32(&zip, (uint32_t)cd_size) != 0 ||
	    buf_u32(&zip, (uint32_t)cd_off) != 0 ||
	    buf_u16(&zip, 0) != 0) {
		npz_err(err, errlen, "npz_write: out of memory (eocd)");
		rc = -1;
		goto out;
	}
	rc = write_atomic(path, zip.p, zip.len, err, errlen);

out:
	if (id_cps) {
		for (i = 0; i < n_ids; i++)
			free(id_cps[i]);
		free(id_cps);
	}
	free(id_len);
	free(gen_cps);
	free(ids_npy.p);
	free(mat_npy.p);
	free(gen_npy.p);
	free(zip.p);
	return rc;
}
