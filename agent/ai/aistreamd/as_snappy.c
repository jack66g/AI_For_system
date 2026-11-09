/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_snappy.c - snappy 压缩/解压（块格式，T8）
 *
 * 压缩器对齐 canonical snappy（google/snappy）的编码决策：
 *   - 输入按 65536 字节分块独立压缩（copy 偏移恒 < 65536）；
 *   - 4 字节乘法哈希（0x1e35a7bd），1<<14 槽，存 pos+1（0=空）；
 *   - 最小匹配 4 字节，正向贪心扩展；
 *   - emitLiteral：len-1 < 60 一字节 tag，否则 61/62/63/64 + 1..4 字节
 *     小端额外长度（每块 <= 65536，最多 3 字节额外）；
 *   - emitCopy：len >= 68 先拆 64；> 64 拆 60；4..11 且偏移 < 2048 用
 *     一字节偏移形式；其余用二字节偏移形式。
 * 与 canonical 的已知偏差（不影响格式合法性，仅压缩率细节）：
 *   - 匹配查找每位置单候选（无 skip 加速启发式），逐位置插表；
 *   - 无 "len < 4 偏移" 特例（canonical 亦无）。
 */
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include "aistreamd/as_snappy.h"

#define SN_BLOCK	65536
#define SN_HASH_BITS	14
#define SN_HASH_SIZE	(1u << SN_HASH_BITS)
#define SN_MAGIC	0x1e35a7bdu

/* ---- 小端读取（不假设宿主字节序） ---- */

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
	       (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint32_t sn_hash(uint32_t v)
{
	return (v * SN_MAGIC) >> (32 - SN_HASH_BITS);
}

/* ---- 输出缓冲 ---- */

struct sn_out {
	uint8_t *p;
	size_t n;
};

static void emit8(struct sn_out *o, uint8_t b)
{
	o->p[o->n++] = b;
}

static void emit_varint(struct sn_out *o, uint64_t v)
{
	while (v >= 0x80) {
		emit8(o, (uint8_t)(v | 0x80));
		v >>= 7;
	}
	emit8(o, (uint8_t)v);
}

/* literal 段 in[lit .. lit+len) 一次性输出（canonical emitLiteral） */
static void emit_literal(struct sn_out *o, const uint8_t *in, size_t lit,
			 size_t len)
{
	size_t n = len - 1;

	if (len == 0)
		return;
	if (n < 60) {
		emit8(o, (uint8_t)(n << 2));
	} else if (n < (1u << 8)) {
		emit8(o, 60 << 2);
		emit8(o, (uint8_t)n);
	} else if (n < (1u << 16)) {
		emit8(o, 61 << 2);
		emit8(o, (uint8_t)(n & 0xff));
		emit8(o, (uint8_t)((n >> 8) & 0xff));
	} else if (n < (1u << 24)) {
		emit8(o, 62 << 2);
		emit8(o, (uint8_t)(n & 0xff));
		emit8(o, (uint8_t)((n >> 8) & 0xff));
		emit8(o, (uint8_t)((n >> 16) & 0xff));
	} else {
		emit8(o, 63 << 2);
		emit8(o, (uint8_t)(n & 0xff));
		emit8(o, (uint8_t)((n >> 8) & 0xff));
		emit8(o, (uint8_t)((n >> 16) & 0xff));
		emit8(o, (uint8_t)((n >> 24) & 0xff));
	}
	memcpy(o->p + o->n, in + lit, len);
	o->n += len;
}

/* copy：偏移 [1,65535]，长度 >= 4（canonical emitCopy） */
static void emit_copy(struct sn_out *o, uint32_t off, size_t len)
{
	while (len >= 68) {
		emit8(o, (uint8_t)(2 | ((64 - 1) << 2)));
		emit8(o, (uint8_t)(off & 0xff));
		emit8(o, (uint8_t)((off >> 8) & 0xff));
		len -= 64;
	}
	if (len > 64) {
		emit8(o, (uint8_t)(2 | ((60 - 1) << 2)));
		emit8(o, (uint8_t)(off & 0xff));
		emit8(o, (uint8_t)((off >> 8) & 0xff));
		len -= 60;
	}
	if (len < 12 && off < 2048) {
		/* 一字节偏移：len 4..11 编码 (len-4)，偏移高 3 位进 tag */
		emit8(o, (uint8_t)(1 | ((len - 4) << 2) | ((off >> 8) << 5)));
		emit8(o, (uint8_t)(off & 0xff));
	} else {
		emit8(o, (uint8_t)(2 | ((len - 1) << 2)));
		emit8(o, (uint8_t)(off & 0xff));
		emit8(o, (uint8_t)((off >> 8) & 0xff));
	}
}

size_t as_snappy_max_len(size_t n)
{
	return 32 + n + n / 6;
}

int as_snappy_compress(const uint8_t *in, size_t n, uint8_t *out,
		       size_t *out_len)
{
	struct sn_out o;
	uint32_t *table;
	size_t block;

	if (!out_len)
		return -1;
	if (n == 0 || (!in && n)) {
		if (n == 0 && out) {
			out[0] = 0;
			*out_len = 1;
			return 0;
		}
		return -1;
	}
	if (!out)
		return -1;

	table = calloc(SN_HASH_SIZE, sizeof(*table));
	if (!table)
		return -1;

	o.p = out;
	o.n = 0;
	emit_varint(&o, (uint64_t)n);

	for (block = 0; block < n; block += SN_BLOCK) {
		const uint8_t *bp = in + block;
		size_t blen = n - block < SN_BLOCK ? n - block : SN_BLOCK;
		size_t bend = blen < 4 ? 0 : blen - 3; /* pos 上界：pos+4<=end */
		size_t pos = 0, lit = 0;

		memset(table, 0, SN_HASH_SIZE * sizeof(*table));
		while (pos < bend) {
			uint32_t cur = le32(bp + pos);
			uint32_t h = sn_hash(cur);
			uint32_t cand1 = table[h];
			size_t mlen;

			table[h] = (uint32_t)(pos + 1);
			if (cand1 != 0 && cand1 <= pos &&
			    le32(bp + (cand1 - 1)) == cur) {
				size_t cand = cand1 - 1;

				mlen = 4;
				while (pos + mlen < blen &&
				       bp[cand + mlen] == bp[pos + mlen])
					mlen++;
				emit_literal(&o, bp, lit, pos - lit);
				emit_copy(&o, (uint32_t)(pos - cand), mlen);
				pos += mlen;
				lit = pos;
			} else {
				pos++;
			}
		}
		emit_literal(&o, bp, lit, blen - lit);
	}

	free(table);
	*out_len = o.n;
	return 0;
}

/* ---- 解压（canonical 逐元素解释；防越界：所有推进 >= 1） ---- */

static const uint8_t *vd(const uint8_t *p, const uint8_t *end, uint32_t *out)
{
	uint32_t v = 0;
	int shift = 0;

	while (p < end) {
		uint8_t b = *p++;

		v |= (uint32_t)(b & 0x7f) << shift;
		if (!(b & 0x80)) {
			*out = v;
			return p;
		}
		shift += 7;
		if (shift > 28)
			return NULL;
	}
	return NULL;
}

static const uint8_t *copy_out(uint8_t *out, size_t *used, size_t cap,
			       uint32_t off, uint32_t len)
{
	if (off == 0 || off > *used || *used + len > cap)
		return NULL;
	{
		uint8_t *dst = out + *used;
		const uint8_t *src = dst - off;

		for (uint32_t i = 0; i < len; i++)
			dst[i] = src[i];	/* 逐字节：重叠 copy 语义 */
		*used += len;
	}
	return out;
}

int as_snappy_uncompress(const uint8_t *in, size_t n, uint8_t *out,
			 size_t *out_cap)
{
	const uint8_t *p = in, *end = in + n;
	uint32_t total;
	size_t used = 0;

	if (!in || !out || !out_cap || n == 0)
		return -1;
	p = vd(p, end, &total);
	if (!p || total > *out_cap)
		return -1;

	while (p < end) {
		uint8_t tag = *p++;
		uint32_t len, off;

		switch (tag & 3) {
		case 0:
			len = (uint32_t)(tag >> 2) + 1;
			if (len > 60) {
				uint32_t extra = len - 60; /* 1..4 字节 */

				if ((size_t)(end - p) < extra)
					return -1;
				len = 0;
				for (uint32_t i = 0; i < extra; i++)
					len |= (uint32_t)*p++ << (8 * i);
				len += 1;
			}
			if ((size_t)(end - p) < len || used + len > total)
				return -1;
			memcpy(out + used, p, len);
			used += len;
			p += len;
			break;
		case 1:
			if (p >= end)
				return -1;
			len = 4 + ((tag >> 2) & 7);
			off = ((uint32_t)(tag >> 5) << 8) | *p++;
			if (!copy_out(out, &used, total, off, len))
				return -1;
			break;
		case 2:
			if ((size_t)(end - p) < 2)
				return -1;
			len = (uint32_t)(tag >> 2) + 1;
			off = (uint32_t)p[0] | (uint32_t)p[1] << 8;
			p += 2;
			if (!copy_out(out, &used, total, off, len))
				return -1;
			break;
		case 3:
			if ((size_t)(end - p) < 4)
				return -1;
			len = (uint32_t)(tag >> 2) + 1;
			off = le32(p);
			p += 4;
			if (!copy_out(out, &used, total, off, len))
				return -1;
			break;
		}
	}
	if (used != total || p != end)
		return -1;
	*out_cap = used;
	return 0;
}
