/* SPDX-License-Identifier: GPL-2.0 */
/*
 * store_npz.c - .npz（ZIP + NPY）只读解析
 *
 * 设计依据 T2-DESIGN.md §4。ZIP 侧刻意不实现完整 zip：只从文件尾部 64 KiB
 * 内反查 EOCD，再扫中央目录，最后按 local header 定位压缩数据。压缩数据长
 * 度与 CRC 一律取中央目录的值（local header 在 data descriptor 场景下可能
 * 是 0），local header 只用于定位数据起点与核对文件名。
 *
 * method 8 是 raw deflate（无 gzip/zlib 包装），因此这里自带 static
 * inflate_raw()（inflateInit2(-MAX_WBITS)），不去污染 store_gzip 的公开
 * API。解压长度必须恰好等于中央目录的 usize，随后校验 CRC32。
 *
 * NPY 侧只认 \x93NUMPY 1.0/2.0，descr 只支持 "<f8" 与 "<U<n>"；头里的
 * dict 用子串定位而非完整 Python 字面量解析（numpy 只写这三个键）。
 */
#define _POSIX_C_SOURCE 200809L

#include "store/store_npz.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define ZIP_SIG_EOCD 0x06054b50u
#define ZIP_SIG_CEN  0x02014b50u
#define ZIP_SIG_LOC  0x04034b50u

#define ZIP_EOCD_SIZE  22u
#define ZIP_CEN_SIZE   46u
#define ZIP_LOC_SIZE   30u
#define ZIP_MAX_COMMENT 65535u
#define ZIP_MAX_HDR    65536u

struct npz_entry {
	char *name;		/* 规范名（去 ".npy"），用于查找 */
	char *raw;		/* 中央目录里的原始名 */
	size_t off;		/* local header 偏移 */
	unsigned long crc;
	size_t csize;
	size_t usize;
	int method;
};

struct aik_npz {
	unsigned char *file;
	size_t file_len;
	struct npz_entry *ent;
	size_t n;
};

/* ------------------------------------------------------------------ */
/* 小工具                                                              */
/* ------------------------------------------------------------------ */

static void npz_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || errlen == 0)
		return;
	va_start(ap, fmt);
	(void)vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

static uint32_t rd16(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

static uint32_t rd32(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t rd32le(const unsigned char *p)
{
	return rd32(p);
}

static int read_all(const char *path, unsigned char **out, size_t *len,
		    char *err, size_t errlen)
{
	FILE *f;
	long sz;
	unsigned char *buf;

	f = fopen(path, "rb");
	if (!f) {
		npz_err(err, errlen, "npz: cannot open %s: %s", path,
			strerror(errno));
		return -1;
	}
	if (fseek(f, 0, SEEK_END) != 0) {
		npz_err(err, errlen, "npz: seek failed on %s", path);
		fclose(f);
		return -1;
	}
	sz = ftell(f);
	if (sz < 0) {
		npz_err(err, errlen, "npz: ftell failed on %s", path);
		fclose(f);
		return -1;
	}
	if ((unsigned long)sz > AIK_NPZ_MAX_FILE) {
		npz_err(err, errlen, "npz: file too large (%ld > %u)", sz,
			(unsigned int)AIK_NPZ_MAX_FILE);
		fclose(f);
		return -1;
	}
	rewind(f);
	buf = malloc((size_t)sz + 1);
	if (!buf) {
		npz_err(err, errlen, "npz: out of memory");
		fclose(f);
		return -1;
	}
	if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		npz_err(err, errlen, "npz: short read on %s", path);
		free(buf);
		fclose(f);
		return -1;
	}
	buf[sz] = '\0';
	fclose(f);
	*out = buf;
	*len = (size_t)sz;
	return 0;
}

/*
 * 条目名安全校验：拒绝绝对路径、路径分隔符、任何 ".."、以 '.' 开头的名
 * 字与控制字符。合法名必须是单段 printable ASCII（numpy 的 "xxx.npy"）。
 */
static int entry_name_ok(const unsigned char *nm, size_t n, char *err,
			 size_t errlen)
{
	size_t i;

	if (n == 0 || n > 255) {
		npz_err(err, errlen, "npz: bad entry name length %zu", n);
		return -1;
	}
	if (nm[0] == '.' || nm[0] == '/') {
		npz_err(err, errlen, "npz: unsafe entry name");
		return -1;
	}
	for (i = 0; i < n; i++) {
		unsigned char c = nm[i];

		if (c < 0x20 || c == 0x7f) {
			npz_err(err, errlen, "npz: control char in entry name");
			return -1;
		}
		/* 0x5c 是反斜杠：用数值避免源码里的转义 */
		if (c == 0x2f || c == 0x5c || c == 0x3a) {
			npz_err(err, errlen,
				"npz: path separator in entry name");
			return -1;
		}
		if (c == '.' && i + 1 < n && nm[i + 1] == '.') {
			npz_err(err, errlen, "npz: \"..\" in entry name");
			return -1;
		}
	}
	return 0;
}

/* 规范名：去掉结尾 ".npy"；若不以此结尾则原样 */
static char *canon_name(const char *raw, size_t n)
{
	char *s;
	size_t len = n;

	if (len > 4 && memcmp(raw + len - 4, ".npy", 4) == 0)
		len -= 4;
	s = malloc(len + 1);
	if (!s)
		return NULL;
	memcpy(s, raw, len);
	s[len] = '\0';
	return s;
}

/* ------------------------------------------------------------------ */
/* ZIP 解析                                                            */
/* ------------------------------------------------------------------ */

static int find_eocd(const unsigned char *f, size_t len, size_t *pos,
		     char *err, size_t errlen)
{
	size_t window = ZIP_EOCD_SIZE + ZIP_MAX_COMMENT;
	size_t start, i;

	if (len < ZIP_EOCD_SIZE) {
		npz_err(err, errlen, "npz: file too small (%zu bytes)", len);
		return -1;
	}
	start = len > window ? len - window : 0;
	i = len - ZIP_EOCD_SIZE + 1;
	while (i-- > start) {
		if (rd32(f + i) == ZIP_SIG_EOCD) {
			*pos = i;
			return 0;
		}
	}
	npz_err(err, errlen, "npz: EOCD not found (not a zip/npz)");
	return -1;
}

/*
 * 解析中央目录，填充 z->ent。调用者负责 z->file / z->file_len。
 * 返回 0 成功；失败时已分配条目由 aik_npz_close 释放。
 */
static int parse_central(aik_npz *z, char *err, size_t errlen)
{
	size_t eocd = 0, cd_off, cd_size, cd_end, pos;
	unsigned int nent, i;
	unsigned int disk, cd_disk, ent_disk, ent_total;
	size_t k;

	if (find_eocd(z->file, z->file_len, &eocd, err, errlen) != 0)
		return -1;
	if (eocd + ZIP_EOCD_SIZE > z->file_len) {
		npz_err(err, errlen, "npz: truncated EOCD");
		return -1;
	}

	disk = rd16(z->file + eocd + 4);
	cd_disk = rd16(z->file + eocd + 6);
	ent_disk = rd16(z->file + eocd + 8);
	ent_total = rd16(z->file + eocd + 10);
	cd_size = rd32(z->file + eocd + 12);
	cd_off = rd32(z->file + eocd + 16);

	if (disk != 0 || cd_disk != 0) {
		npz_err(err, errlen, "npz: multi-disk zip not supported");
		return -1;
	}
	if (ent_disk != ent_total) {
		npz_err(err, errlen, "npz: inconsistent entry counts");
		return -1;
	}
	if (ent_total == 0xffffu || cd_off == 0xffffffffu ||
	    cd_size == 0xffffffffu) {
		npz_err(err, errlen, "npz: zip64 not supported");
		return -1;
	}
	if (cd_off > z->file_len || cd_size > z->file_len - cd_off) {
		npz_err(err, errlen, "npz: central directory out of range");
		return -1;
	}
	cd_end = cd_off + cd_size;
	if (cd_end > eocd) {
		npz_err(err, errlen, "npz: central directory overlaps EOCD");
		return -1;
	}

	nent = ent_total;
	z->ent = calloc(nent ? nent : 1, sizeof(*z->ent));
	if (!z->ent) {
		npz_err(err, errlen, "npz: out of memory");
		return -1;
	}

	pos = cd_off;
	for (i = 0; i < nent; i++) {
		const unsigned char *p;
		size_t nlen, elen, clen, loff;
		unsigned int flags, method;
		unsigned long crc, csize, usize;
		struct npz_entry *e = &z->ent[z->n];

		if (pos + ZIP_CEN_SIZE > cd_end) {
			npz_err(err, errlen, "npz: truncated central header");
			return -1;
		}
		p = z->file + pos;
		if (rd32(p) != ZIP_SIG_CEN) {
			npz_err(err, errlen, "npz: bad central header signature");
			return -1;
		}
		flags = rd16(p + 8);
		method = rd16(p + 10);
		crc = rd32(p + 16);
		csize = rd32(p + 20);
		usize = rd32(p + 24);
		nlen = rd16(p + 28);
		elen = rd16(p + 30);
		clen = rd16(p + 32);
		loff = rd32(p + 42);

		if (pos + ZIP_CEN_SIZE + nlen + elen + clen > cd_end) {
			npz_err(err, errlen, "npz: central header overruns");
			return -1;
		}
		if (flags & 0x0001u) {
			npz_err(err, errlen, "npz: encrypted entries refused");
			return -1;
		}
		if (method != 0 && method != 8) {
			npz_err(err, errlen, "npz: unsupported method %u",
				method);
			return -1;
		}
		if (usize > AIK_NPZ_MAX_ENTRY || csize > AIK_NPZ_MAX_ENTRY) {
			npz_err(err, errlen,
				"npz: entry too large (%lu bytes)", usize);
			return -1;
		}
		if (loff + ZIP_LOC_SIZE > z->file_len) {
			npz_err(err, errlen, "npz: local header out of range");
			return -1;
		}
		if (entry_name_ok(p + ZIP_CEN_SIZE, nlen, err, errlen) != 0)
			return -1;

		e->raw = malloc(nlen + 1);
		if (!e->raw) {
			npz_err(err, errlen, "npz: out of memory");
			return -1;
		}
		memcpy(e->raw, p + ZIP_CEN_SIZE, nlen);
		e->raw[nlen] = '\0';
		e->name = canon_name(e->raw, nlen);
		if (!e->name) {
			npz_err(err, errlen, "npz: out of memory");
			return -1;
		}
		for (k = 0; k < z->n; k++) {
			if (strcmp(z->ent[k].name, e->name) == 0 ||
			    strcmp(z->ent[k].raw, e->raw) == 0) {
				npz_err(err, errlen,
					"npz: duplicate entry \"%s\"", e->name);
				return -1;
			}
		}
		e->off = loff;
		e->crc = crc;
		e->csize = (size_t)csize;
		e->usize = (size_t)usize;
		e->method = (int)method;
		z->n++;
		pos += ZIP_CEN_SIZE + nlen + elen + clen;
	}
	return 0;
}

aik_npz *aik_npz_open(const char *path, char *err, size_t errlen)
{
	aik_npz *z;

	if (err && errlen)
		err[0] = '\0';
	if (!path) {
		npz_err(err, errlen, "npz: null path");
		return NULL;
	}
	z = calloc(1, sizeof(*z));
	if (!z) {
		npz_err(err, errlen, "npz: out of memory");
		return NULL;
	}
	if (read_all(path, &z->file, &z->file_len, err, errlen) != 0) {
		free(z);
		return NULL;
	}
	if (parse_central(z, err, errlen) != 0) {
		aik_npz_close(z);
		return NULL;
	}
	return z;
}

void aik_npz_close(aik_npz *z)
{
	size_t i;

	if (!z)
		return;
	for (i = 0; i < z->n; i++) {
		free(z->ent[i].name);
		free(z->ent[i].raw);
	}
	free(z->ent);
	free(z->file);
	free(z);
}

size_t aik_npz_count(const aik_npz *z)
{
	return z ? z->n : 0;
}

const char *aik_npz_name_at(const aik_npz *z, size_t i)
{
	if (!z || i >= z->n)
		return NULL;
	return z->ent[i].name;
}

static const struct npz_entry *find_entry(const aik_npz *z, const char *name)
{
	size_t i;

	if (!z || !name)
		return NULL;
	for (i = 0; i < z->n; i++) {
		if (strcmp(z->ent[i].name, name) == 0 ||
		    strcmp(z->ent[i].raw, name) == 0)
			return &z->ent[i];
	}
	return NULL;
}

int aik_npz_has(const aik_npz *z, const char *name)
{
	return find_entry(z, name) != NULL;
}

/* method 8：raw deflate（无 gzip/zlib 包装），单次解到已知长度 */
static int inflate_raw(const unsigned char *in, size_t inlen,
		       unsigned char *out, size_t outlen, char *err,
		       size_t errlen)
{
	z_stream s;
	int rc;

	if (inlen > 0x7fffffffu || outlen == 0 || outlen > 0x7fffffffu) {
		npz_err(err, errlen, "npz: entry length unsupported");
		return -1;
	}
	memset(&s, 0, sizeof(s));
	rc = inflateInit2(&s, -MAX_WBITS);
	if (rc != Z_OK) {
		npz_err(err, errlen, "npz: inflateInit2 failed (%d)", rc);
		return -1;
	}
	s.next_in = (Bytef *)(uintptr_t)in;
	s.avail_in = (uInt)inlen;
	s.next_out = out;
	s.avail_out = (uInt)outlen;
	rc = inflate(&s, Z_FINISH);
	if (rc != Z_STREAM_END) {
		npz_err(err, errlen, "npz: deflate error %d (%s)", rc,
			s.msg ? s.msg : "?");
		(void)inflateEnd(&s);
		return -1;
	}
	if (s.total_out != (uLong)outlen) {
		npz_err(err, errlen,
			"npz: inflated %lu bytes, expected %zu",
			(unsigned long)s.total_out, outlen);
		(void)inflateEnd(&s);
		return -1;
	}
	(void)inflateEnd(&s);
	return 0;
}

int aik_npz_read(const aik_npz *z, const char *name, unsigned char **data,
		 size_t *len, char *err, size_t errlen)
{
	const struct npz_entry *e;
	unsigned char *buf;
	const unsigned char *lp;
	size_t nlen, elen, data_off;
	unsigned long crc;

	if (!data || !len) {
		npz_err(err, errlen, "npz: null output argument");
		return -1;
	}
	*data = NULL;
	*len = 0;
	e = find_entry(z, name);
	if (!e) {
		npz_err(err, errlen, "npz: no such entry \"%s\"",
			name ? name : "(null)");
		return -1;
	}

	lp = z->file + e->off;
	if (rd32(lp) != ZIP_SIG_LOC) {
		npz_err(err, errlen, "npz: bad local header for \"%s\"", e->raw);
		return -1;
	}
	nlen = rd16(lp + 26);
	elen = rd16(lp + 28);
	/* local header 自带的 sizes 可能是 0（data descriptor），只看名字 */
	if (e->off + ZIP_LOC_SIZE + nlen + elen > z->file_len) {
		npz_err(err, errlen, "npz: local header overruns for \"%s\"",
			e->raw);
		return -1;
	}
	if (nlen != strlen(e->raw) ||
	    memcmp(lp + ZIP_LOC_SIZE, e->raw, nlen) != 0) {
		npz_err(err, errlen, "npz: local/central name mismatch for \"%s\"",
			e->raw);
		return -1;
	}
	data_off = e->off + ZIP_LOC_SIZE + nlen + elen;
	if (e->csize > z->file_len - data_off) {
		npz_err(err, errlen, "npz: compressed data overruns for \"%s\"",
			e->raw);
		return -1;
	}

	buf = malloc(e->usize + 1);
	if (!buf) {
		npz_err(err, errlen, "npz: out of memory");
		return -1;
	}
	if (e->method == 0) {
		if (e->csize != e->usize) {
			npz_err(err, errlen,
				"npz: stored entry size mismatch for \"%s\"",
				e->raw);
			free(buf);
			return -1;
		}
		memcpy(buf, z->file + data_off, e->usize);
	} else {
		if (inflate_raw(z->file + data_off, e->csize, buf, e->usize,
				err, errlen) != 0) {
			free(buf);
			return -1;
		}
	}
	buf[e->usize] = '\0';
	crc = crc32(0L, buf, (uInt)e->usize);
	if (crc != e->crc) {
		npz_err(err, errlen,
			"npz: CRC mismatch for \"%s\" (got %08lx want %08lx)",
			e->raw, crc, e->crc);
		free(buf);
		return -1;
	}
	*data = buf;
	*len = e->usize;
	return 0;
}

/* ------------------------------------------------------------------ */
/* NPY                                                                 */
/* ------------------------------------------------------------------ */

/* "<U<n>" → n（1..64）；其它返回 0 */
static int descr_u_width(const char *descr)
{
	char *end;
	long n;

	if (!descr || descr[0] != '<' || descr[1] != 'U')
		return 0;
	n = strtol(descr + 2, &end, 10);
	if (end == descr + 2 || *end != '\0' || n < 1 || n > 64)
		return 0;
	return (int)n;
}

size_t aik_npy_itemsize(const aik_npy *npy)
{
	int n;

	if (!npy)
		return 0;
	if (strcmp(npy->descr, "<f8") == 0)
		return 8;
	n = descr_u_width(npy->descr);
	if (n <= 0)
		return 0;
	return (size_t)n * 4;
}

size_t aik_npy_nelem(const aik_npy *npy)
{
	size_t total = 1;
	int i;

	if (!npy || npy->ndim < 0 || npy->ndim > 8)
		return 0;
	if (npy->ndim == 0)
		return 1;
	for (i = 0; i < npy->ndim; i++) {
		if (npy->shape[i] < 0)
			return 0;
		if (npy->shape[i] == 0)
			return 0;
		if ((unsigned long long)npy->shape[i] >
		    (unsigned long long)SIZE_MAX / (unsigned long long)total)
			return 0;
		total *= (size_t)npy->shape[i];
	}
	return total;
}

/* 返回 dict 中 "'key'" / "\"key\"" 之后第一个 ':' 之后的位置 */
static const char *field_after(const char *ht, const char *key)
{
	char pat[40];
	const char *p, *c;
	int n;

	n = snprintf(pat, sizeof(pat), "'%s'", key);
	if (n < 0 || (size_t)n >= sizeof(pat))
		return NULL;
	p = strstr(ht, pat);
	if (!p) {
		n = snprintf(pat, sizeof(pat), "\"%s\"", key);
		if (n < 0 || (size_t)n >= sizeof(pat))
			return NULL;
		p = strstr(ht, pat);
	}
	if (!p)
		return NULL;
	c = strchr(p, ':');
	if (!c)
		return NULL;
	return c + 1;
}

static const char *skip_ws(const char *p)
{
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
		p++;
	return p;
}

static int parse_descr(const char *ht, aik_npy *out, char *err, size_t errlen)
{
	const char *p = field_after(ht, "descr");
	const char *e;
	char q;
	size_t n;

	if (!p) {
		npz_err(err, errlen, "npy: no descr in header");
		return -1;
	}
	p = skip_ws(p);
	q = *p;
	if (q != '\'' && q != '"') {
		npz_err(err, errlen, "npy: malformed descr");
		return -1;
	}
	p++;
	e = strchr(p, q);
	if (!e) {
		npz_err(err, errlen, "npy: unterminated descr");
		return -1;
	}
	n = (size_t)(e - p);
	if (n == 0 || n >= sizeof(out->descr)) {
		npz_err(err, errlen, "npy: descr length %zu unsupported", n);
		return -1;
	}
	memcpy(out->descr, p, n);
	out->descr[n] = '\0';
	if (out->descr[0] != '<') {
		npz_err(err, errlen, "npy: only little-endian descr supported (%s)",
			out->descr);
		return -1;
	}
	if (strcmp(out->descr, "<f8") != 0 && descr_u_width(out->descr) <= 0) {
		npz_err(err, errlen, "npy: unsupported descr \"%s\"",
			out->descr);
		return -1;
	}
	return 0;
}

static int parse_fortran(const char *ht, aik_npy *out, char *err, size_t errlen)
{
	const char *p = field_after(ht, "fortran_order");

	if (!p) {
		npz_err(err, errlen, "npy: no fortran_order in header");
		return -1;
	}
	p = skip_ws(p);
	if (strncmp(p, "True", 4) == 0) {
		out->fortran_order = 1;
		return 0;
	}
	if (strncmp(p, "False", 5) == 0) {
		out->fortran_order = 0;
		return 0;
	}
	npz_err(err, errlen, "npy: malformed fortran_order");
	return -1;
}

static int parse_shape(const char *ht, aik_npy *out, char *err, size_t errlen)
{
	const char *p = field_after(ht, "shape");
	char *end;
	long long v;

	if (!p) {
		npz_err(err, errlen, "npy: no shape in header");
		return -1;
	}
	p = skip_ws(p);
	if (*p != '(') {
		npz_err(err, errlen, "npy: malformed shape");
		return -1;
	}
	p++;
	out->ndim = 0;
	for (;;) {
		p = skip_ws(p);
		if (*p == ')') {
			p++;
			break;
		}
		if (!isdigit((unsigned char)*p)) {
			npz_err(err, errlen, "npy: malformed shape element");
			return -1;
		}
		errno = 0;
		v = strtoll(p, &end, 10);
		if (end == p || errno == ERANGE || v < 0) {
			npz_err(err, errlen, "npy: bad shape value");
			return -1;
		}
		if (out->ndim >= 8) {
			npz_err(err, errlen, "npy: more than 8 dimensions");
			return -1;
		}
		out->shape[out->ndim++] = v;
		p = skip_ws(end);
		if (*p == ',') {
			p++;
			continue;
		}
		if (*p == ')') {
			p++;
			break;
		}
		npz_err(err, errlen, "npy: malformed shape list");
		return -1;
	}
	return 0;
}

int aik_npy_parse(const unsigned char *buf, size_t len, aik_npy *out,
		  char *err, size_t errlen)
{
	static const unsigned char magic[6] = { 0x93, 'N', 'U', 'M', 'P', 'Y' };
	char *ht;
	size_t hlen, hstart, hend, itemsize, nelem, expect;
	unsigned int major;
	int rc = -1;

	if (!out) {
		npz_err(err, errlen, "npy: null output");
		return -1;
	}
	memset(out, 0, sizeof(*out));
	if (!buf || len < 10) {
		npz_err(err, errlen, "npy: buffer too small (%zu)", len);
		return -1;
	}
	if (memcmp(buf, magic, sizeof(magic)) != 0) {
		npz_err(err, errlen, "npy: bad magic");
		return -1;
	}
	major = buf[6];
	if (major == 1) {
		hlen = rd16(buf + 8);
		hstart = 10;
	} else if (major == 2) {
		if (len < 12) {
			npz_err(err, errlen, "npy: truncated v2 header");
			return -1;
		}
		hlen = rd32le(buf + 8);
		hstart = 12;
	} else {
		npz_err(err, errlen, "npy: unsupported version %u.%u",
			major, buf[7]);
		return -1;
	}
	if (hlen == 0 || hlen > ZIP_MAX_HDR) {
		npz_err(err, errlen, "npy: bad header length %zu", hlen);
		return -1;
	}
	hend = hstart + hlen;
	if (hend > len) {
		npz_err(err, errlen, "npy: header overruns buffer");
		return -1;
	}

	ht = malloc(hlen + 1);
	if (!ht) {
		npz_err(err, errlen, "npy: out of memory");
		return -1;
	}
	memcpy(ht, buf + hstart, hlen);
	ht[hlen] = '\0';

	if (parse_descr(ht, out, err, errlen) != 0)
		goto out;
	if (parse_fortran(ht, out, err, errlen) != 0)
		goto out;
	if (parse_shape(ht, out, err, errlen) != 0)
		goto out;

	itemsize = aik_npy_itemsize(out);
	nelem = aik_npy_nelem(out);
	if (itemsize == 0) {
		npz_err(err, errlen, "npy: zero itemsize");
		goto out;
	}
	if (nelem == 0) {
		npz_err(err, errlen, "npy: empty array");
		goto out;
	}
	if (nelem > SIZE_MAX / itemsize) {
		npz_err(err, errlen, "npy: element count overflow");
		goto out;
	}
	expect = nelem * itemsize;
	if (expect != len - hend) {
		npz_err(err, errlen,
			"npy: data length %zu != nelem*itemsize %zu (descr=%s)",
			len - hend, expect, out->descr);
		goto out;
	}
	out->data = buf + hend;
	out->data_len = len - hend;
	rc = 0;

out:
	free(ht);
	if (rc != 0)
		memset(out, 0, sizeof(*out));
	return rc;
}

int aik_npy_get_f8(const aik_npy *npy, size_t idx, double *out)
{
	const unsigned char *p;
	uint64_t bits = 0;
	size_t nelem;
	int i;

	if (!npy || !out || !npy->data)
		return -1;
	if (strcmp(npy->descr, "<f8") != 0)
		return -1;
	nelem = aik_npy_nelem(npy);
	if (idx >= nelem)
		return -1;
	p = npy->data + idx * 8;
	for (i = 0; i < 8; i++)
		bits |= (uint64_t)p[i] << (8 * i);
	memcpy(out, &bits, sizeof(*out));
	return 0;
}

static int utf8_put(char *out, size_t outlen, size_t *o, unsigned int cp)
{
	unsigned char b[4];
	int k;

	if (cp < 0x80) {
		b[0] = (unsigned char)cp;
		k = 1;
	} else if (cp < 0x800) {
		b[0] = (unsigned char)(0xc0 | (cp >> 6));
		b[1] = (unsigned char)(0x80 | (cp & 0x3f));
		k = 2;
	} else if (cp < 0x10000) {
		b[0] = (unsigned char)(0xe0 | (cp >> 12));
		b[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3f));
		b[2] = (unsigned char)(0x80 | (cp & 0x3f));
		k = 3;
	} else {
		b[0] = (unsigned char)(0xf0 | (cp >> 18));
		b[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3f));
		b[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3f));
		b[3] = (unsigned char)(0x80 | (cp & 0x3f));
		k = 4;
	}
	if (*o + (size_t)k >= outlen)
		return -1;
	memcpy(out + *o, b, (size_t)k);
	*o += (size_t)k;
	return 0;
}

int aik_npy_get_ustr(const aik_npy *npy, size_t idx, char *out, size_t outlen)
{
	const unsigned char *p;
	size_t nelem, off = 0;
	int width, i;

	if (!npy || !out || !npy->data || outlen == 0)
		return -1;
	width = descr_u_width(npy->descr);
	if (width <= 0)
		return -1;
	nelem = aik_npy_nelem(npy);
	if (idx >= nelem)
		return -1;
	p = npy->data + idx * ((size_t)width * 4);
	for (i = 0; i < width; i++) {
		uint32_t cp = rd32le(p + (size_t)i * 4);

		if (cp == 0)
			break;
		if (cp > 0x10ffffu || (cp >= 0xd800u && cp <= 0xdfffu)) {
			out[0] = '\0';
			return -1;
		}
		if (utf8_put(out, outlen, &off, cp) != 0) {
			out[0] = '\0';
			return -1;
		}
	}
	out[off] = '\0';
	return (int)off;
}
