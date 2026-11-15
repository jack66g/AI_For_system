/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_table.c - AIPD-M1 内置规则表：MVP 三规则手写最小表（Lane-B
 * 生成器到位后重生成替换；--check 冻结=摘要比对）+ SHA-256 自校验。
 *
 * 表 schema 冻结于 aip_model.h；序列化/摘要合同冻结于 aip_table.h。
 *
 * 阈值定值依据（/proc 常识定值，M1 影子期不追求最优，追求可解释）：
 *   - psi_mem_some（PSI memory some avg10 定点 0..2048，×100/2048=%）：
 *     >409 即 ≈20%——持续两成采样窗内至少一任务因内存停等，属明确
 *     内存压力（桌面常态 <5%=102；20% 已是显著回收信号）→ 建议提升
 *     reclaim 激进度（param=建议 swappiness 目标 100，激进回收档）。
 *   - lat_ewma_ns（sched latency EWMA）：>10ms——交互系统健康态
 *     通常 <1ms，10ms 一个数量级余量=明确调度延迟恶化 → 建议调度
 *     补偿（param=建议补偿量 10，含义=补偿百分比档，M2 冻结精确面）。
 *   - iowait_pct（iowait 百分比 0..100）：>20——两成时间在等 IO，
 *     IO bound 明确 → 建议 readahead 提升（param=建议 readahead
 *     KB 512，桌面默认 128KB 的 4 档）。
 *
 * 全部规则只产影子建议（executed 恒 0，无 ACT 下发路径——设计 §0）。
 */
#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "aip_feat.h"
#include "aip_model.h"
#include "aip_table.h"

/* ================= SHA-256（FIPS 180-4；生成器同算法锚） ================= */

struct sha256_ctx {
	uint32_t h[8];
	uint64_t len;			/* 总比特数 */
	uint8_t buf[64];
	size_t buflen;
};

static const uint32_t sha_k[64] = {
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
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t rotr(uint32_t x, int n)
{
	return (x >> n) | (x << (32 - n));
}

static void sha_init(struct sha256_ctx *c)
{
	c->h[0] = 0x6a09e667; c->h[1] = 0xbb67ae85;
	c->h[2] = 0x3c6ef372; c->h[3] = 0xa54ff53a;
	c->h[4] = 0x510e527f; c->h[5] = 0x9b05688c;
	c->h[6] = 0x1f83d9ab; c->h[7] = 0x5be0cd19;
	c->len = 0;
	c->buflen = 0;
}

static void sha_block(struct sha256_ctx *c, const uint8_t p[64])
{
	uint32_t w[64], a, b, cc, d, e, f, g, h;
	uint32_t t1, t2;

	for (int i = 0; i < 16; i++)
		w[i] = ((uint32_t)p[i * 4] << 24) |
		       ((uint32_t)p[i * 4 + 1] << 16) |
		       ((uint32_t)p[i * 4 + 2] << 8) |
		       (uint32_t)p[i * 4 + 3];
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^
			      (w[i - 15] >> 3);
		uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^
			      (w[i - 2] >> 10);

		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
	e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
	for (int i = 0; i < 64; i++) {
		uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
		uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);

		t1 = h + S1 + ch + sha_k[i] + w[i];
		t2 = S0 + maj;
		h = g; g = f; f = e; e = d + t1;
		d = cc; cc = b; b = a; a = t1 + t2;
	}
	c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
	c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha_update(struct sha256_ctx *c, const uint8_t *p, size_t n)
{
	c->len += (uint64_t)n * 8;
	while (n > 0) {
		size_t take = 64 - c->buflen;

		if (take > n)
			take = n;
		memcpy(c->buf + c->buflen, p, take);
		c->buflen += take;
		p += take;
		n -= take;
		if (c->buflen == 64) {
			sha_block(c, c->buf);
			c->buflen = 0;
		}
	}
}

static void sha_final(struct sha256_ctx *c, uint8_t out[32])
{
	uint64_t bits = c->len;
	uint8_t pad[72];
	size_t padlen;
	int i;

	pad[0] = 0x80;
	memset(pad + 1, 0, sizeof(pad) - 1);
	padlen = (c->buflen < 56) ? (56 - c->buflen) : (120 - c->buflen);
	/* 长度域按大端 8 字节附加 */
	{
		uint8_t lenb[8];

		for (i = 0; i < 8; i++)
			lenb[i] = (uint8_t)(bits >> (56 - 8 * i));
		/* padlen+buflen+8 == 64 的倍数；pad 容量 72 足够 */
		sha_update(c, pad, padlen);
		/* 手动喂长度域（不再累计 len） */
		memcpy(c->buf + c->buflen, lenb, 8);
		sha_block(c, c->buf);
		c->buflen = 0;
	}
	for (i = 0; i < 8; i++) {
		out[i * 4] = (uint8_t)(c->h[i] >> 24);
		out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
		out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
		out[i * 4 + 3] = (uint8_t)c->h[i];
	}
}

void aip_sha256(const uint8_t *data, size_t n, uint8_t out[32])
{
	struct sha256_ctx c;

	sha_init(&c);
	sha_update(&c, data, n);
	sha_final(&c, out);
}

void aip_sha256_hex(const uint8_t digest[32], char out[65])
{
	static const char hexd[] = "0123456789abcdef";

	for (int i = 0; i < 32; i++) {
		out[i * 2] = hexd[digest[i] >> 4];
		out[i * 2 + 1] = hexd[digest[i] & 0xf];
	}
	out[64] = '\0';
}

/* ================= 规则串行化（生成器合同格式） ================= */

static void put_u32(uint8_t *p, uint32_t v)
{
	for (int i = 0; i < 4; i++)
		p[i] = (uint8_t)(v >> (8 * i));
}

static void put_i64(uint8_t *p, int64_t v)
{
	uint64_t u = (uint64_t)v;

	for (int i = 0; i < 8; i++)
		p[i] = (uint8_t)(u >> (8 * i));
}

#define RULE_SER_SZ	(4 + 4 + 8 + 8 + 4 + 4 + AIP_REASON_MAX)

ssize_t aip_table_serialize(const struct ai_rule *rules, size_t n,
			    uint8_t *out, size_t cap)
{
	if ((!rules && n) || (!out && cap))
		return -1;
	if (n > AIP_RULES_MAX)
		return -1;
	if (cap < n * RULE_SER_SZ)
		return -1;
	for (size_t r = 0; r < n; r++) {
		uint8_t *p = out + r * RULE_SER_SZ;

		put_u32(p, rules[r].feat);
		put_u32(p + 4, rules[r].op);
		put_i64(p + 8, rules[r].lo);
		put_i64(p + 16, rules[r].hi);
		put_u32(p + 24, rules[r].action);
		put_u32(p + 28, (uint32_t)rules[r].param);
		memcpy(p + 32, rules[r].reason, AIP_REASON_MAX);
	}
	return (ssize_t)(n * RULE_SER_SZ);
}

/* ================= 表数据 =================
 * 数据（aip_rules/aip_nrules/aip_table_ver/aip_table_sha256）自 M1
 * 整合起由 gen_aip_table.py 生成于 **aip_table_data.c**（勿手改；
 * --check 冻结漂移检）。本文件只保留序列化/sha256/校验函数。 */

/* ================= 加载自校验 ================= */

static int rule_valid(const struct ai_rule *r)
{
	if (r->feat >= AIP_FEAT_MAX)
		return 0;
	if (r->op != AIP_OP_IN_RANGE && r->op != AIP_OP_GT)
		return 0;
	/* 动作建议 id 上界（M1 三动作；生成器扩表须同步升 VER） */
	if (r->action > AIP_ACT_READAHEAD_BOOST)
		return 0;
	if (r->op == AIP_OP_IN_RANGE && r->lo > r->hi)
		return 0;
	return 1;
}

int aip_table_check_rules(const struct ai_rule *rules, size_t n,
			  uint32_t ver, const char *sha256_hex,
			  char *err, size_t errcap)
{
	uint8_t ser[AIP_RULES_MAX * 128];
	uint8_t digest[32];
	char hex[65];
	ssize_t sz;

	if (n > AIP_RULES_MAX) {
		if (err && errcap)
			snprintf(err, errcap, "n=%zu > AIP_RULES_MAX", n);
		return -1;
	}
	if (ver != AIP_TABLE_VER) {
		if (err && errcap)
			snprintf(err, errcap, "ver=%u != AIP_TABLE_VER=%u",
				 ver, AIP_TABLE_VER);
		return -1;
	}
	for (size_t i = 0; i < n; i++) {
		if (!rule_valid(&rules[i])) {
			if (err && errcap)
				snprintf(err, errcap,
					 "rule[%zu] field out of range", i);
			return -1;
		}
	}
	sz = aip_table_serialize(rules, n, ser, sizeof(ser));
	if (sz < 0) {
		if (err && errcap)
			snprintf(err, errcap, "serialize failed");
		return -1;
	}
	aip_sha256(ser, (size_t)sz, digest);
	aip_sha256_hex(digest, hex);
	if (!sha256_hex || strcmp(hex, sha256_hex) != 0) {
		if (err && errcap)
			snprintf(err, errcap, "sha256 mismatch: computed=%s "
				 "constant=%s", hex,
				 sha256_hex ? sha256_hex : "(null)");
		return -1;
	}
	return 0;
}

int aip_table_check(char *err, size_t errcap)
{
	return aip_table_check_rules(aip_rules, aip_nrules, aip_table_ver,
				     aip_table_sha256, err, errcap);
}
