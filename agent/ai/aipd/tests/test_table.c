/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_table.c - 表自校验（通过/篡改拒载/SHA-256 已知答案/串行化合同）
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "aip_model.h"
#include "aip_table.h"

static int fails, checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

/* SHA-256("abc") FIPS 180-4 已知答案（实现正确性锚） */
#define SHA_ABC	"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
/* SHA-256("") 已知答案（空表摘要合同锚） */
#define SHA_EMPTY	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

int main(void)
{
	char err[256];
	uint8_t ser[AIP_RULES_MAX * 128];
	uint8_t digest[32];
	char hex[65];
	struct ai_rule tampered[AIP_RULES_MAX];
	ssize_t sz;

	/* ---- 1) 内置表自校验通过 ---- */
	CHECK(aip_table_check(err, sizeof(err)) == 0, "builtin table check");
	CHECK(aip_table_ver == AIP_TABLE_VER && aip_nrules == 3,
	      "ver + 3 rules");

	/* ---- 2) SHA-256 实现已知答案（生成器 hashlib 同算法锚） ---- */
	aip_sha256((const uint8_t *)"abc", 3, digest);
	aip_sha256_hex(digest, hex);
	CHECK(strcmp(hex, SHA_ABC) == 0, "sha256(abc) known answer");
	aip_sha256((const uint8_t *)"", 0, digest);
	aip_sha256_hex(digest, hex);
	CHECK(strcmp(hex, SHA_EMPTY) == 0, "sha256(empty) known answer");

	/* ---- 3) 串行化合同：定长 128B/条 ---- */
	sz = aip_table_serialize(aip_rules, aip_nrules, ser, sizeof(ser));
	CHECK(sz == (ssize_t)(aip_nrules * 128), "serialize 128B/rule");
	/* 容量不足拒绝 */
	CHECK(aip_table_serialize(aip_rules, aip_nrules, ser, 8) == -1,
	      "serialize capacity guard");

	/* ---- 4) 空表合同 ---- */
	CHECK(aip_table_check_rules(NULL, 0, AIP_TABLE_VER, SHA_EMPTY, err,
				    sizeof(err)) == 0,
	      "empty rules + empty digest ok");

	/* ---- 5) 篡改拒载（漂移=--check 拒的同口径） ---- */
	memcpy(tampered, aip_rules, sizeof(tampered));
	tampered[0].param = 60;		/* param 篡改 */
	CHECK(aip_table_check_rules(tampered, aip_nrules, aip_table_ver,
				    aip_table_sha256, err,
				    sizeof(err)) != 0,
	      "tampered param rejected");
	CHECK(strstr(err, "sha256 mismatch") != NULL,
	      "tamper err mentions sha256");
	memcpy(tampered, aip_rules, sizeof(tampered));
	tampered[1].lo = 99999999;	/* 阈值篡改 */
	CHECK(aip_table_check_rules(tampered, aip_nrules, aip_table_ver,
				    aip_table_sha256, err,
				    sizeof(err)) != 0,
	      "tampered threshold rejected");
	memcpy(tampered, aip_rules, sizeof(tampered));
	tampered[2].reason[0] = 'X';	/* 文案篡改（单字节） */
	CHECK(aip_table_check_rules(tampered, aip_nrules, aip_table_ver,
				    aip_table_sha256, err,
				    sizeof(err)) != 0,
	      "tampered reason byte rejected");
	/* 摘要常量本身被换=拒 */
	memcpy(tampered, aip_rules, sizeof(tampered));
	CHECK(aip_table_check_rules(tampered, aip_nrules, aip_table_ver,
				    SHA_ABC, err, sizeof(err)) != 0,
	      "wrong digest constant rejected");

	/* ---- 6) 值域校验（非摘要路） ---- */
	memcpy(tampered, aip_rules, sizeof(tampered));
	tampered[0].feat = AIP_FEAT_MAX;	/* 枚举外 */
	{
		uint8_t d2[32];
		char h2[65];

		/* 重算篡改表摘要（隔离值域校验分支） */
		sz = aip_table_serialize(tampered, aip_nrules, ser,
					 sizeof(ser));
		CHECK(sz > 0, "serialize tampered");
		aip_sha256(ser, (size_t)sz, d2);
		aip_sha256_hex(d2, h2);
		CHECK(aip_table_check_rules(tampered, aip_nrules,
					    aip_table_ver, h2, err,
					    sizeof(err)) != 0,
		      "feat out of enum rejected (value domain)");
		CHECK(strstr(err, "out of range") != NULL,
		      "value domain err mentions range");
	}
	CHECK(aip_table_check_rules(aip_rules, aip_nrules,
				    AIP_TABLE_VER + 1u, aip_table_sha256,
				    err, sizeof(err)) != 0,
	      "version mismatch rejected");
	CHECK(aip_table_check_rules(aip_rules, AIP_RULES_MAX + 1,
				    AIP_TABLE_VER, aip_table_sha256, err,
				    sizeof(err)) != 0,
	      "n over max rejected");

	if (fails) {
		printf("test_table: %d failures (%d checks)\n", fails,
		       checks);
		return 1;
	}
	printf("test_table: OK (%d checks)\n", checks);
	return 0;
}
