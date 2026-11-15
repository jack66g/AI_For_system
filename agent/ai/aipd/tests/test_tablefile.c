/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_tablefile.c - M2 AIPTBL 表文件 B 加载器单测（设计册 §4/B3）：
 * 合法通过 / 篡改体字节拒 / 截断拒 / 坏 magic 拒 / ver/flags/nrules/
 * 尾随字节/reason NUL/大小写 hex 全拒。
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aip_model.h"
#include "aip_table.h"
#include "aip_table_file.h"

static int fails, checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

static char tmpdir[64];

static void put_u16(unsigned char *p, unsigned v)
{
	p[0] = (unsigned char)(v & 0xff);
	p[1] = (unsigned char)((v >> 8) & 0xff);
}

static void put_u32(unsigned char *p, uint32_t v)
{
	for (int i = 0; i < 4; i++)
		p[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

/*
 * mk_table_file - 用规则集出 AIPTBL 文件（生成器镜像：体=串行化字节，
 * 头 sha=体摘要）。返回文件字节数。
 */
static size_t mk_table_file(const char *path, const struct ai_rule *rules,
			    size_t n, unsigned ver, unsigned flags,
			    uint32_t nrules_hdr, const char *sha_hex_override,
			    long truncate_to, int extra_tail_byte)
{
	unsigned char buf[AIPTBL_FILE_MAX + 1];
	unsigned char ser[AIP_RULES_MAX * 128];
	uint8_t digest[32];
	char hex[65];
	ssize_t sz;
	FILE *f;
	size_t total;

	sz = aip_table_serialize(rules, n, ser, sizeof(ser));
	CHECK(sz == (ssize_t)(n * 128), "serialize for file build");
	aip_sha256(ser, (size_t)sz, digest);
	aip_sha256_hex(digest, hex);

	memset(buf, 0, sizeof(buf));
	memcpy(buf, "AIPTBL\0\0", 8);
	put_u16(buf + 8, ver);
	put_u16(buf + 10, flags);
	put_u32(buf + 12, nrules_hdr);
	memcpy(buf + 16, sha_hex_override ? sha_hex_override : hex, 65);
	memcpy(buf + AIPTBL_HDR_SZ, ser, (size_t)sz);
	total = AIPTBL_HDR_SZ + (size_t)sz;
	if (extra_tail_byte) {
		buf[total] = 0xAA;
		total++;
	}
	if (truncate_to >= 0 && (size_t)truncate_to < total)
		total = (size_t)truncate_to;
	f = fopen(path, "wb");
	if (!f) {
		CHECK(f != NULL, "tmp table file open");
		return 0;
	}
	fwrite(buf, 1, total, f);
	fclose(f);
	return total;
}

static char p_ok[128], p_bad[128];

int main(void)
{
	struct aip_table_file tf;
	struct ai_rule variant[AIP_RULES_MAX];
	char err[256];
	uint8_t digest[32];
	char hex[65];
	unsigned char ser[AIP_RULES_MAX * 128];
	ssize_t sz;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/m2a-tbl-%d", (int)getpid());
	{
		char cmd[128];

		snprintf(cmd, sizeof(cmd), "mkdir -p %s", tmpdir);
		if (system(cmd) != 0)
			return 2;
	}
	snprintf(p_ok, sizeof(p_ok), "%s/ok.bin", tmpdir);
	snprintf(p_bad, sizeof(p_bad), "%s/bad.bin", tmpdir);

	/* ---- 1) 合法（builtin 同内容；头 sha=体摘要）→ 通过 ---- */
	mk_table_file(p_ok, aip_rules, aip_nrules, 1, 0,
		      (uint32_t)aip_nrules, NULL, -1, 0);
	CHECK(aip_table_file_load(p_ok, &tf, err, sizeof(err)) == 0,
	      "valid AIPTBL loads");
	CHECK(tf.nrules == aip_nrules && tf.ver == 1 && tf.flags == 0,
	      "header fields");
	CHECK(strcmp(tf.sha256_hex, aip_table_sha256) == 0,
	      "body digest == builtin digest（同内容同摘要）");
	{
		int same = 1;

		for (size_t i = 0; i < aip_nrules; i++)
			if (memcmp(&tf.rules[i], &aip_rules[i],
				   sizeof(struct ai_rule)) != 0)
				same = 0;
		CHECK(same, "rules roundtrip byte-equal");
	}

	/* ---- 2) 篡改规则体 1 字节 → 拒 ---- */
	mk_table_file(p_bad, aip_rules, aip_nrules, 1, 0,
		      (uint32_t)aip_nrules, NULL, -1, 0);
	{
		FILE *f = fopen(p_bad, "r+b");

		CHECK(f != NULL, "tamper open");
		if (f) {
			fseek(f, AIPTBL_HDR_SZ + 32 + 10, SEEK_SET);
			fputc('X', f);		/* rule[0].reason[10] */
			fclose(f);
		}
	}
	CHECK(aip_table_file_load(p_bad, &tf, err, sizeof(err)) != 0,
	      "flipped body byte rejected");
	CHECK(strstr(err, "sha256") != NULL || strstr(err, "rule check") != NULL,
	      "tamper err mentions digest");

	/* ---- 3) 截断（头+少一体）→ 拒 ---- */
	mk_table_file(p_bad, aip_rules, aip_nrules, 1, 0,
		      (uint32_t)aip_nrules, NULL,
		      (long)(AIPTBL_HDR_SZ + 2 * 128), 0);
	CHECK(aip_table_file_load(p_bad, &tf, err, sizeof(err)) != 0,
	      "truncated rejected");
	CHECK(strstr(err, "size") != NULL, "truncation err mentions size");

	/* ---- 4) 坏 magic → 拒 ---- */
	mk_table_file(p_bad, aip_rules, aip_nrules, 1, 0,
		      (uint32_t)aip_nrules, NULL, -1, 0);
	{
		FILE *f = fopen(p_bad, "r+b");

		if (f) {
			fseek(f, 0, SEEK_SET);
			fputs("XIPTBL", f);
			fclose(f);
		}
	}
	CHECK(aip_table_file_load(p_bad, &tf, err, sizeof(err)) != 0,
	      "bad magic rejected");
	CHECK(strstr(err, "magic") != NULL, "magic err mentions magic");

	/* ---- 5) ver=2 → 拒 ---- */
	mk_table_file(p_bad, aip_rules, aip_nrules, 2, 0,
		      (uint32_t)aip_nrules, NULL, -1, 0);
	CHECK(aip_table_file_load(p_bad, &tf, err, sizeof(err)) != 0,
	      "ver=2 rejected");

	/* ---- 6) flags=1 → 拒 ---- */
	mk_table_file(p_bad, aip_rules, aip_nrules, 1, 1,
		      (uint32_t)aip_nrules, NULL, -1, 0);
	CHECK(aip_table_file_load(p_bad, &tf, err, sizeof(err)) != 0,
	      "flags=1 rejected");

	/* ---- 7) nrules=0 → 拒；nrules 头与体数不符 → 拒 ---- */
	mk_table_file(p_bad, aip_rules, aip_nrules, 1, 0, 0, NULL, -1, 0);
	CHECK(aip_table_file_load(p_bad, &tf, err, sizeof(err)) != 0,
	      "nrules=0 rejected");
	mk_table_file(p_bad, aip_rules, aip_nrules, 1, 0, 2, NULL, -1, 0);
	CHECK(aip_table_file_load(p_bad, &tf, err, sizeof(err)) != 0,
	      "header nrules != body count rejected");

	/* ---- 8) 尾随 1 字节 → 拒 ---- */
	mk_table_file(p_bad, aip_rules, aip_nrules, 1, 0,
		      (uint32_t)aip_nrules, NULL, -1, 1);
	CHECK(aip_table_file_load(p_bad, &tf, err, sizeof(err)) != 0,
	      "trailing byte rejected");

	/* ---- 9) 大写 hex / 头 hex 未 NUL 终结 → 拒 ---- */
	mk_table_file(p_bad, aip_rules, aip_nrules, 1, 0,
		      (uint32_t)aip_nrules, NULL, -1, 0);
	{
		FILE *f = fopen(p_bad, "r+b");

		if (f) {
			fseek(f, 16, SEEK_SET);
			fputc('A', f);		/* 首字符大写化 */
			fclose(f);
		}
	}
	CHECK(aip_table_file_load(p_bad, &tf, err, sizeof(err)) != 0,
	      "uppercase hex rejected");
	{
		char upper[65];

		sz = aip_table_serialize(aip_rules, aip_nrules, ser,
					 sizeof(ser));
		aip_sha256(ser, (size_t)sz, digest);
		aip_sha256_hex(digest, hex);
		memcpy(upper, hex, 65);
		for (int i = 0; i < 64; i++)
			if (upper[i] >= 'a' && upper[i] <= 'f')
				upper[i] = (char)(upper[i] - 'a' + 'A');
		mk_table_file(p_bad, aip_rules, aip_nrules, 1, 0,
			      (uint32_t)aip_nrules, upper, -1, 0);
		CHECK(aip_table_file_load(p_bad, &tf, err,
					  sizeof(err)) != 0,
		      "all-uppercase hex rejected (lowercase frozen)");
	}

	/* ---- 10) reason 未 NUL 终结（sha 一致）→ 拒 ---- */
	memcpy(variant, aip_rules, sizeof(variant));
	memset(variant[0].reason, 'R', AIP_REASON_MAX);	/* 无 NUL+文案改 */
	sz = aip_table_serialize(variant, aip_nrules, ser, sizeof(ser));
	aip_sha256(ser, (size_t)sz, digest);
	aip_sha256_hex(digest, hex);
	mk_table_file(p_bad, variant, aip_nrules, 1, 0,
		      (uint32_t)aip_nrules, hex, -1, 0);
	CHECK(aip_table_file_load(p_bad, &tf, err, sizeof(err)) != 0,
	      "reason without NUL rejected");

	/* ---- 11) 规则域越界（action=99，sha 一致）→ 拒 ---- */
	memcpy(variant, aip_rules, sizeof(variant));
	variant[0].action = 99;
	sz = aip_table_serialize(variant, aip_nrules, ser, sizeof(ser));
	aip_sha256(ser, (size_t)sz, digest);
	aip_sha256_hex(digest, hex);
	mk_table_file(p_bad, variant, aip_nrules, 1, 0,
		      (uint32_t)aip_nrules, hex, -1, 0);
	CHECK(aip_table_file_load(p_bad, &tf, err, sizeof(err)) != 0,
	      "action=99 rejected (whitelist-independent rule_valid)");
	CHECK(strstr(err, "out of range") != NULL,
	      "domain err mentions range");

	/* ---- 12) 文件缺失 → 拒 ---- */
	CHECK(aip_table_file_load("/nonexistent/tbl.bin", &tf, err,
				  sizeof(err)) != 0,
	      "missing file rejected");

	{
		char cmd[128];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
		(void)!system(cmd);
	}
	if (fails) {
		printf("test_tablefile: %d failures (%d checks)\n", fails,
		       checks);
		return 1;
	}
	printf("test_tablefile: OK (%d checks)\n", checks);
	return 0;
}
