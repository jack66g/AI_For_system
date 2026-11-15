/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_table_file.c - AIPTBL 表文件 B 加载器（设计册 §4）
 *
 * 全校验 fail-fast 合同：magic/ver/flags/长度/nrules/reason NUL/
 * 逐条值域/摘要重算——任一失配 -1（守护启动 exit 1，与 conf 同级；
 * B3 门「篡改/截断/坏 magic → aipd exit 1」的 C 侧本体）。
 * 摘要校验复用 aip_table_check_rules（值域+sha256 一体），保证 B 表
 * 与 builtin 走同一套冻结校验语义（B 与 builtin 同 schema，§3）。
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aip_table.h"
#include "aip_table_file.h"

static int tf_bad(char *err, size_t cap, const char *msg)
{
	if (err && cap)
		snprintf(err, cap, "%s", msg);
	return -1;
}

static uint16_t get_u16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t get_u32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int64_t get_i64(const uint8_t *p)
{
	uint64_t u = 0;

	for (int i = 7; i >= 0; i--)
		u = (u << 8) | p[i];
	return (int64_t)u;
}

/* 体反序列化（aip_table_serialize 的逆；字节序布局冻结于 aip_table.h） */
static void rule_from_body(const uint8_t *p, struct ai_rule *r)
{
	r->feat = get_u32(p);
	r->op = get_u32(p + 4);
	r->lo = get_i64(p + 8);
	r->hi = get_i64(p + 16);
	r->action = get_u32(p + 24);
	r->param = (int32_t)get_u32(p + 28);
	memcpy(r->reason, p + 32, AIP_REASON_MAX);
}

int aip_table_file_load(const char *path, struct aip_table_file *tf,
			char *err, size_t errcap)
{
	static const uint8_t magic[8] = { 'A', 'I', 'P', 'T', 'B', 'L',
					  0, 0 };
	FILE *f;
	long sz;
	uint8_t *buf = NULL;
	uint32_t nrules;
	size_t want;

	if (!path || !tf) {
		errno = EINVAL;
		return tf_bad(err, errcap, "invalid args");
	}
	memset(tf, 0, sizeof(*tf));
	f = fopen(path, "rb");
	if (!f)
		return tf_bad(err, errcap, "open failed");
	if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 ||
	    fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return tf_bad(err, errcap, "seek failed");
	}
	if (sz < AIPTBL_HDR_SZ || sz > AIPTBL_FILE_MAX) {
		fclose(f);
		return tf_bad(err, errcap, "file size out of bounds "
			      "(truncated or oversized)");
	}
	buf = malloc((size_t)sz);
	if (!buf) {
		fclose(f);
		return tf_bad(err, errcap, "oom");
	}
	if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		fclose(f);
		free(buf);
		return tf_bad(err, errcap, "short read");
	}
	fclose(f);

	if (memcmp(buf, magic, sizeof(magic)) != 0) {
		free(buf);
		return tf_bad(err, errcap, "bad magic (not AIPTBL)");
	}
	tf->ver = get_u16(buf + 8);
	tf->flags = get_u16(buf + 10);
	nrules = get_u32(buf + 12);
	if (tf->ver != 1) {
		free(buf);
		return tf_bad(err, errcap, "ver != 1");
	}
	if (tf->flags != 0) {
		free(buf);
		return tf_bad(err, errcap, "flags != 0");
	}
	if (nrules < 1 || nrules > AIP_RULES_MAX) {
		free(buf);
		return tf_bad(err, errcap, "nrules out of 1..AIP_RULES_MAX");
	}
	want = AIPTBL_HDR_SZ + (size_t)nrules * AIPTBL_RULE_SZ;
	if ((size_t)sz != want) {
		free(buf);
		return tf_bad(err, errcap, "file size != 128+nrules*128 "
			      "(truncated or trailing bytes)");
	}
	/* 头摘要：65B 区必须 64 小写 hex + NUL */
	if (buf[16 + 64] != '\0') {
		free(buf);
		return tf_bad(err, errcap, "sha256_hex not NUL terminated");
	}
	memcpy(tf->sha256_hex, buf + 16, 65);
	for (int i = 0; i < 64; i++) {
		char h = tf->sha256_hex[i];

		if (!((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f'))) {
			free(buf);
			return tf_bad(err, errcap,
				      "sha256_hex not 64 lowercase hex");
		}
	}
	/* 逐条反序列化 + reason NUL 终结（生成器合同=NUL 填充；违例=拒） */
	for (uint32_t i = 0; i < nrules; i++) {
		const uint8_t *body = buf + AIPTBL_HDR_SZ +
				      (size_t)i * AIPTBL_RULE_SZ;

		rule_from_body(body, &tf->rules[i]);
		if (memchr(tf->rules[i].reason, '\0', AIP_REASON_MAX)
		    == NULL) {
			free(buf);
			return tf_bad(err, errcap,
				      "rule reason not NUL terminated");
		}
	}
	tf->nrules = nrules;
	free(buf);

	/* 值域+摘要一体校验（复用 builtin 同套冻结语义；含 sha 重算==头 hex，
	 * 经反序列化→重串行化=体字节等价的传递性） */
	{
		char cerr[256];

		if (aip_table_check_rules(tf->rules, tf->nrules, tf->ver,
					  tf->sha256_hex, cerr,
					  sizeof(cerr)) != 0) {
			if (err && errcap)
				snprintf(err, errcap, "rule check: %s",
					 cerr);
			return -1;
		}
	}
	return 0;
}
