/* SPDX-License-Identifier: GPL-2.0 */
/*
 * store_gzip.c - gzip 解压/压缩（zlib）
 *
 * 设计依据 T2-DESIGN.md §3。解压用 16+MAX_WBITS 自动识别 gzip 包装，
 * 遇到 Z_STREAM_END 且仍有剩余输入时 inflateReset 继续下一个 member；
 * 输出缓冲从 64 KiB 起倍增，硬上限 AIK_GZIP_MAX_OUTPUT（256 MiB），
 * 防压缩炸弹。
 *
 * 压缩固定 level 9 与 gzip 头 mtime=0（deflateSetHeader），保证同一输入
 * 产出同一字节流；OS 字段固定 3（Unix）。
 */
#define _POSIX_C_SOURCE 200809L

#include "store/store_gzip.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* 输出缓冲起步与每次增量 */
#define GZ_CHUNK (64u * 1024u)

static void gz_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || errlen == 0)
		return;
	va_start(ap, fmt);
	(void)vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

int aik_gzip_inflate(const void *in, size_t inlen, unsigned char **out,
		     size_t *outlen, char *err, size_t errlen)
{
	z_stream s;
	unsigned char *buf = NULL;
	const unsigned char *ip = in;
	size_t left = inlen;
	size_t cap = 0;
	size_t used = 0;
	unsigned int members = 0;
	int rc;

	if (!out || !outlen) {
		gz_err(err, errlen, "inflate: null output argument");
		return -1;
	}
	*out = NULL;
	*outlen = 0;
	if (!in || inlen == 0) {
		gz_err(err, errlen, "inflate: empty input");
		return -1;
	}

	memset(&s, 0, sizeof(s));
	rc = inflateInit2(&s, 16 + MAX_WBITS);
	if (rc != Z_OK) {
		gz_err(err, errlen, "inflate: inflateInit2 failed (%d)", rc);
		return -1;
	}

	for (;;) {
		if (s.avail_in == 0 && left > 0) {
			uInt take = left > 0x7fffffffu ? 0x7fffffffu
						       : (uInt)left;

			s.next_in = (Bytef *)(uintptr_t)ip;
			s.avail_in = take;
			ip += take;
			left -= take;
		}
		if (s.avail_out == 0) {
			size_t ncap;
			unsigned char *nb;

			if (cap == 0) {
				ncap = GZ_CHUNK;
			} else {
				ncap = cap * 2;
				if (ncap < cap)
					ncap = 0;
			}
			if (ncap == 0 || ncap > AIK_GZIP_MAX_OUTPUT) {
				gz_err(err, errlen,
				       "inflate: output exceeds %u bytes",
				       (unsigned int)AIK_GZIP_MAX_OUTPUT);
				goto fail;
			}
			nb = realloc(buf, ncap + 1);
			if (!nb) {
				gz_err(err, errlen, "inflate: out of memory");
				goto fail;
			}
			buf = nb;
			cap = ncap;
			s.next_out = buf + used;
			s.avail_out = (uInt)(cap - used);
		}

		rc = inflate(&s, Z_NO_FLUSH);
		used = (size_t)(cap - s.avail_out);

		if (rc == Z_STREAM_END) {
			members++;
			if (used > AIK_GZIP_MAX_OUTPUT) {
				gz_err(err, errlen,
				       "inflate: output exceeds %u bytes",
				       (unsigned int)AIK_GZIP_MAX_OUTPUT);
				goto fail;
			}
			if (s.avail_in == 0 && left == 0)
				break;	/* 没有后续 member */
			rc = inflateReset(&s);
			if (rc != Z_OK) {
				gz_err(err, errlen,
				       "inflate: inflateReset failed (%d)", rc);
				goto fail;
			}
			continue;
		}
		if (rc == Z_OK)
			continue;
		if (rc == Z_BUF_ERROR) {
			if (s.avail_in == 0 && left == 0) {
				gz_err(err, errlen,
				       "inflate: truncated stream (after %u member, %zu bytes)",
				       members, used);
				goto fail;
			}
			/* 否则是输出窗口满，下一轮扩容继续 */
			continue;
		}
		gz_err(err, errlen, "inflate: zlib error %d (%s)", rc,
		       s.msg ? s.msg : "?");
		goto fail;
	}

	(void)inflateEnd(&s);
	if (!buf) {
		/* 空 member：cap 仍为 0，给一个可 free 的 1 字节缓冲 */
		buf = malloc(1);
		if (!buf) {
			gz_err(err, errlen, "inflate: out of memory");
			return -1;
		}
		cap = 0;
	}
	buf[used] = '\0';
	*out = buf;
	*outlen = used;
	return 0;

fail:
	(void)inflateEnd(&s);
	free(buf);
	return -1;
}

int aik_gzip_deflate(const void *in, size_t inlen, int level,
		     unsigned char **out, size_t *outlen,
		     char *err, size_t errlen)
{
	z_stream s;
	gz_header h;
	unsigned char *buf = NULL;
	uLong bound;
	size_t cap;
	int rc;

	if (!out || !outlen) {
		gz_err(err, errlen, "deflate: null output argument");
		return -1;
	}
	*out = NULL;
	*outlen = 0;
	if (!in && inlen > 0) {
		gz_err(err, errlen, "deflate: null input");
		return -1;
	}
	if (inlen > 0xffffffffu) {
		gz_err(err, errlen, "deflate: input too large (%zu)", inlen);
		return -1;
	}
	if (level < 1 || level > 9)
		level = 9;

	memset(&s, 0, sizeof(s));
	rc = deflateInit2(&s, level, Z_DEFLATED, 16 + MAX_WBITS, 8,
			  Z_DEFAULT_STRATEGY);
	if (rc != Z_OK) {
		gz_err(err, errlen, "deflate: deflateInit2 failed (%d)", rc);
		return -1;
	}

	memset(&h, 0, sizeof(h));
	h.time = 0;	/* mtime=0：字节级可重复 */
	h.os = 3;	/* OS=Unix，固定值 */
	rc = deflateSetHeader(&s, &h);
	if (rc != Z_OK) {
		gz_err(err, errlen, "deflate: deflateSetHeader failed (%d)", rc);
		(void)deflateEnd(&s);
		return -1;
	}

	bound = deflateBound(&s, (uLong)inlen);
	cap = (size_t)bound + 64;
	buf = malloc(cap + 1);
	if (!buf) {
		gz_err(err, errlen, "deflate: out of memory");
		(void)deflateEnd(&s);
		return -1;
	}

	s.next_in = (Bytef *)(uintptr_t)in;
	s.avail_in = (uInt)inlen;
	s.next_out = buf;
	s.avail_out = (uInt)cap;
	rc = deflate(&s, Z_FINISH);
	if (rc != Z_STREAM_END) {
		gz_err(err, errlen, "deflate: unexpected zlib status %d (%s)",
		       rc, s.msg ? s.msg : "?");
		(void)deflateEnd(&s);
		free(buf);
		return -1;
	}
	*outlen = cap - s.avail_out;
	(void)deflateEnd(&s);
	buf[*outlen] = '\0';
	*out = buf;
	return 0;
}
