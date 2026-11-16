/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sha256.c - 自含 SHA-256（FIPS 180-4）
 *
 * S-FINDING-01（S-TRACK §5）：occ 快照完整性 sidecar 的摘要源。
 * 刻意不引 mbedtls（trim 配置耦合面）——libc-only 自含实现。
 * "abc" 向量在 test_revert 场景 I 钉正确性。
 */
#include "sha256.h"

#include <string.h>

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(occ_sha256 *c, const unsigned char *p)
{
	uint32_t w[64];
	uint32_t a, b, cc, d, e, f, g, h;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = ((uint32_t)p[i * 4] << 24) |
		       ((uint32_t)p[i * 4 + 1] << 16) |
		       ((uint32_t)p[i * 4 + 2] << 8) |
		       (uint32_t)p[i * 4 + 3];
	for (i = 16; i < 64; i++) {
		uint32_t s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^
			      (w[i - 15] >> 3);
		uint32_t s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^
			      (w[i - 2] >> 10);

		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
	e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
	for (i = 0; i < 64; i++) {
		uint32_t S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
		uint32_t ch = (e & f) ^ (~e & g);
		uint32_t t1 = h + S1 + ch + K[i] + w[i];
		uint32_t S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
		uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);

		h = g; g = f; f = e; e = d + t1;
		d = cc; cc = b; b = a; a = t1 + S0 + mj;
	}
	c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
	c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

void occ_sha256_init(occ_sha256 *c)
{
	c->h[0] = 0x6a09e667; c->h[1] = 0xbb67ae85;
	c->h[2] = 0x3c6ef372; c->h[3] = 0xa54ff53a;
	c->h[4] = 0x510e527f; c->h[5] = 0x9b05688c;
	c->h[6] = 0x1f83d9ab; c->h[7] = 0x5be0cd19;
	c->len = 0;
	c->blen = 0;
}

void occ_sha256_update(occ_sha256 *c, const void *data, size_t len)
{
	const unsigned char *p = data;

	c->len += len;
	while (len) {
		size_t take = 64 - c->blen;

		if (take > len)
			take = len;
		memcpy(c->buf + c->blen, p, take);
		c->blen += take;
		p += take;
		len -= take;
		if (c->blen == 64) {
			sha256_block(c, c->buf);
			c->blen = 0;
		}
	}
}

void occ_sha256_final(occ_sha256 *c, unsigned char out[32])
{
	uint64_t bits = c->len * 8;
	unsigned char pad[8];
	int i;

	c->buf[c->blen++] = 0x80;
	if (c->blen > 56) {
		memset(c->buf + c->blen, 0, 64 - c->blen);
		sha256_block(c, c->buf);
		c->blen = 0;
	}
	memset(c->buf + c->blen, 0, 56 - c->blen);
	memset(pad, 0, sizeof(pad));
	for (i = 0; i < 8; i++)
		pad[i] = (unsigned char)(bits >> (56 - 8 * i));
	memcpy(c->buf + 56, pad, 8);
	sha256_block(c, c->buf);
	for (i = 0; i < 8; i++) {
		out[i * 4] = (unsigned char)(c->h[i] >> 24);
		out[i * 4 + 1] = (unsigned char)(c->h[i] >> 16);
		out[i * 4 + 2] = (unsigned char)(c->h[i] >> 8);
		out[i * 4 + 3] = (unsigned char)c->h[i];
	}
	c->blen = 0;
}

int occ_sha256_hex(const void *data, size_t len,
		   char out[OCC_SHA256_HEX + 1])
{
	occ_sha256 c;
	unsigned char d[32];
	static const char hx[] = "0123456789abcdef";
	int i;

	if (!data || !out)
		return -1;
	occ_sha256_init(&c);
	occ_sha256_update(&c, data, len);
	occ_sha256_final(&c, d);
	for (i = 0; i < 32; i++) {
		out[i * 2] = hx[d[i] >> 4];
		out[i * 2 + 1] = hx[d[i] & 15];
	}
	out[64] = '\0';
	return 0;
}
