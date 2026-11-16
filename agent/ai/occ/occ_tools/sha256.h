/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sha256.h - 自含 SHA-256（FIPS 180-4；S-FINDING-01 快照完整性用）
 *
 * 无外部依赖（libc-only）；公开域参考实现风格，正确性由
 * test_revert 场景 I 的 "abc" 向量钉死（ba7816bf…）。
 */
#ifndef OCC_TOOLS_SHA256_H
#define OCC_TOOLS_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define OCC_SHA256_HEX 64		/* 十六进制摘要长度（不含 NUL） */

typedef struct {
	uint32_t h[8];
	uint64_t len;			/* 总字节数 */
	unsigned char buf[64];
	size_t blen;			/* 缓冲未消费数 */
} occ_sha256;

void occ_sha256_init(occ_sha256 *c);
void occ_sha256_update(occ_sha256 *c, const void *data, size_t len);
void occ_sha256_final(occ_sha256 *c, unsigned char out[32]);

/* 一次性便利：data 摘要 → 小写 hex（out 长度 ≥65）。0=ok */
int occ_sha256_hex(const void *data, size_t len,
		   char out[OCC_SHA256_HEX + 1]);

#endif /* OCC_TOOLS_SHA256_H */
