/* SPDX-License-Identifier: GPL-2.0 */
/*
 * blake2b.c - RFC 7693 BLAKE2b 内核（T3a）
 *
 * mbedTLS 没有 BLAKE2b，而 REF-PY 的 hashing 嵌入用
 * hashlib.blake2b(..., digest_size=8) 生成特征哈希，所以这里自实现
 * RFC 7693 的 64 位 BLAKE2b（无 key、无 salt、无 personalize）。
 *
 * 参数块按规范折算进 h[0]：h[0] ^= 0x01010000 ^ digest_size。
 * 参数块四字节依次是 digest_length / key_length / fanout / depth；无 key、
 * 单级树即 0x01 0x00 0x01 0x01，按 little-endian 读成 0x01010000。
 *
 * 字节序：BLAKE2b 全程 little-endian（RFC 7693 §2.5）。
 */
#include "blake2b.h"

#include "../include/memory/embed_hash.h"

#include <string.h>

#define B2B_BLOCK	128
#define B2B_ROUNDS	12

static const unsigned long long b2b_iv[8] = {
	0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
	0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
	0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
	0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

static const unsigned char b2b_sigma[B2B_ROUNDS][16] = {
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

struct b2b_ctx {
	unsigned long long h[8];
	unsigned long long t[2];
	unsigned char buf[B2B_BLOCK];
	size_t buflen;
	size_t outlen;
};

static unsigned long long b2b_load64(const unsigned char *p)
{
	return (unsigned long long)p[0] |
	       ((unsigned long long)p[1] << 8) |
	       ((unsigned long long)p[2] << 16) |
	       ((unsigned long long)p[3] << 24) |
	       ((unsigned long long)p[4] << 32) |
	       ((unsigned long long)p[5] << 40) |
	       ((unsigned long long)p[6] << 48) |
	       ((unsigned long long)p[7] << 56);
}

static void b2b_store64(unsigned char *p, unsigned long long v)
{
	int i;

	for (i = 0; i < 8; i++)
		p[i] = (unsigned char)(v >> (8 * i));
}

static unsigned long long b2b_rotr64(unsigned long long x, unsigned int n)
{
	return (x >> n) | (x << (64 - n));
}

static void b2b_g(unsigned long long *v, int a, int b, int c, int d,
		  unsigned long long x, unsigned long long y)
{
	v[a] = v[a] + v[b] + x;
	v[d] = b2b_rotr64(v[d] ^ v[a], 32);
	v[c] = v[c] + v[d];
	v[b] = b2b_rotr64(v[b] ^ v[c], 24);
	v[a] = v[a] + v[b] + y;
	v[d] = b2b_rotr64(v[d] ^ v[a], 16);
	v[c] = v[c] + v[d];
	v[b] = b2b_rotr64(v[b] ^ v[c], 63);
}

static void b2b_compress(struct b2b_ctx *c, const unsigned char *block, int last)
{
	unsigned long long v[16];
	unsigned long long m[16];
	int i, r;

	for (i = 0; i < 16; i++)
		m[i] = b2b_load64(block + 8 * i);
	for (i = 0; i < 8; i++) {
		v[i] = c->h[i];
		v[i + 8] = b2b_iv[i];
	}
	v[12] ^= c->t[0];
	v[13] ^= c->t[1];
	if (last)
		v[14] = ~v[14];

	for (r = 0; r < B2B_ROUNDS; r++) {
		const unsigned char *s = b2b_sigma[r];

		b2b_g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
		b2b_g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
		b2b_g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
		b2b_g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
		b2b_g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
		b2b_g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
		b2b_g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
		b2b_g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
	}

	for (i = 0; i < 8; i++)
		c->h[i] ^= v[i] ^ v[i + 8];
}

static void b2b_init(struct b2b_ctx *c, size_t outlen)
{
	int i;

	memset(c, 0, sizeof(*c));
	for (i = 0; i < 8; i++)
		c->h[i] = b2b_iv[i];
	/* digest_length | key_length<<8 | fanout<<16 | depth<<24 */
	c->h[0] ^= 0x01010000ULL ^ (unsigned long long)outlen;
	c->outlen = outlen;
}

static void b2b_update(struct b2b_ctx *c, const unsigned char *p, size_t len)
{
	while (len > 0) {
		size_t left = B2B_BLOCK - c->buflen;

		if (len > left) {
			memcpy(c->buf + c->buflen, p, left);
			c->buflen = B2B_BLOCK;
			c->t[0] += B2B_BLOCK;
			if (c->t[0] < B2B_BLOCK)
				c->t[1]++;
			b2b_compress(c, c->buf, 0);
			c->buflen = 0;
			p += left;
			len -= left;
		} else {
			memcpy(c->buf + c->buflen, p, len);
			c->buflen += len;
			len = 0;
		}
	}
}

static void b2b_final(struct b2b_ctx *c, unsigned char *out)
{
	unsigned char full[64];
	size_t i;

	c->t[0] += c->buflen;
	if (c->t[0] < c->buflen)
		c->t[1]++;
	memset(c->buf + c->buflen, 0, B2B_BLOCK - c->buflen);
	b2b_compress(c, c->buf, 1);

	for (i = 0; i < 8; i++)
		b2b_store64(full + 8 * i, c->h[i]);
	memcpy(out, full, c->outlen);
}

int aik_blake2b(const void *data, size_t len, void *out, size_t outlen)
{
	struct b2b_ctx c;

	if (!out || outlen == 0 || outlen > 64)
		return -1;
	if (!data && len > 0)
		return -1;
	b2b_init(&c, outlen);
	if (len > 0)
		b2b_update(&c, (const unsigned char *)data, len);
	b2b_final(&c, (unsigned char *)out);
	return 0;
}

int aik_blake2b64(const void *data, size_t len, unsigned char out[8])
{
	return aik_blake2b(data, len, out, 8);
}
