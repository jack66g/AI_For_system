/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_table_file.h - AIPD-M2 表文件 B（AIPTBL 格式，设计册 §4）
 *
 * 布局（128B 头 + N×128B 体；体=aip_table_serialize 同字节序）：
 *   off 0   char[8]   magic "AIPTBL\0\0"
 *   off 8   u16       ver=1（=AIP_TABLE_VER）
 *   off 10  u16       flags=0
 *   off 12  u32       nrules (1..64)
 *   off 16  char[65]  sha256_hex 规则体摘要（64 小写 hex + NUL；
 *                     算法与 builtin 同=对全部规则体字节，无头）
 *   off 81  u8[47]    零填充
 *   off 128 起         nrules × 128B
 *
 * 签名=MVP 诚实面（§4/§9.1）：sha256 完整性+发布台账绑定，非抗 root
 * 篡改的 Authenticity。加载校验（任一失配 → 调用方 exit 1 fail-fast，
 * 与 conf 同级——防 A/B 静默错配）：
 *   magic / ver / flags / 文件长恰=128+nrules*128（无尾随字节）/
 *   nrules 1..AIP_RULES_MAX / 逐条 rule_valid（复用 aip_table.c
 *   aip_table_check_rules 全套=值域+摘要）/ reason 定长区 NUL 终结 /
 *   sha256 重算==头 hex。
 */
#ifndef _AIP_TABLE_FILE_H
#define _AIP_TABLE_FILE_H

#include <stddef.h>
#include <stdint.h>

#include "aip_model.h"

#define AIPTBL_HDR_SZ		128
#define AIPTBL_RULE_SZ		128
#define AIPTBL_FILE_MAX		(AIPTBL_HDR_SZ + AIP_RULES_MAX * \
				 AIPTBL_RULE_SZ)

struct aip_table_file {
	struct ai_rule rules[AIP_RULES_MAX];
	size_t nrules;
	uint16_t ver;
	uint16_t flags;
	char sha256_hex[65];		/* 头声明摘要（已验==重算） */
};

/*
 * aip_table_file_load - 读+全校验。0=通过（*tf 填）；
 * -1=失配（err 收人读原因；fail-fast 由调用方 exit 1 兜）。
 */
int aip_table_file_load(const char *path, struct aip_table_file *tf,
			char *err, size_t errcap);

#endif /* _AIP_TABLE_FILE_H */
