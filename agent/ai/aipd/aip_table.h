/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_table.h - AIPD-M1 内置规则表（手写最小表=生成器合同锚）
 *
 * Lane-B 生成器 gen_aip_table.py（输入 table_spec.json）重新生成
 * 本表时应保持：规则数组语义、AIP_TABLE_VER、sha256 常量串与
 * aip_table_check() 校验语义逐字节一致（--check 漂移拒）。
 *
 * ================== 生成器合同（Lane-B 必读，冻结） ==================
 *
 * 规则集摘要串 = 对规则数组按下述格式逐条串行化后求 SHA-256，
 * 以 64 字符小写 hex 写入产物常量 aip_table_sha256：
 *
 *   每条规则（按数组顺序）依次输出（小端，无填充）：
 *     feat    uint32        （enum aip_feat 值）
 *     op      uint32        （enum aip_op 值）
 *     lo      int64         （二补码位型 8 字节）
 *     hi      int64
 *     action  uint32
 *     param   int32
 *     reason  AIP_REASON_MAX=96 字节（UTF-8 文案，NUL 结尾后补 '\0'
 *             至定长——生成器须与表内文案逐字节一致）
 *
 *   aip_table_sha256 = hex_lowercase(SHA-256(全部规则串行化字节))
 *
 * SHA-256 实现：FIPS 180-4 标准算法（aip_table.c 内手写 aip_sha256）；
 * 生成器用 Python hashlib.sha256 即为同算法。
 * 加载校验（aip_table_check）：运行时对内存中规则表同法串行化求
 * 摘要，与常量串比对；失配=篡改/漂移，拒载（守护启动 exit 1）。
 * ==================================================================
 */
#ifndef _AIP_TABLE_H
#define _AIP_TABLE_H

#include <stddef.h>
#include <stdint.h>

#include "aip_model.h"

/* 内置规则表（M1 手写最小表；Lane-B 生成器到位后重生成替换） */
extern const struct ai_rule aip_rules[AIP_RULES_MAX];
extern const size_t aip_nrules;			/* = 3（M1） */
extern const uint32_t aip_table_ver;		/* = AIP_TABLE_VER */
extern const char aip_table_sha256[65];		/* 64 hex + NUL */

/*
 * aip_table_check - 加载自校验（守护启动/单测）：
 *   1) aip_table_ver == AIP_TABLE_VER；
 *   2) 1 <= aip_nrules <= AIP_RULES_MAX 且规则字段值域合法
 *      （feat/action/op 枚举内；IN_RANGE 要求 lo<=hi）；
 *   3) 规则串行化 SHA-256 == aip_table_sha256。
 * 0=通过；-1=失配（err 收到人读原因，容量 errcap；可 NULL）。
 */
int aip_table_check(char *err, size_t errcap);

/* 同上，但校验任意规则集（单测「篡改拒载」用——对拷贝篡改后应失配）。
 * n==0 或 rules==NULL 也合法（空表摘要是良定义的）。 */
int aip_table_check_rules(const struct ai_rule *rules, size_t n,
			  uint32_t ver, const char *sha256_hex,
			  char *err, size_t errcap);

/*
 * aip_table_serialize - 规则串行化（生成器合同格式；亦供校验内部用）。
 * 写 out（容量 >= n*128）；返回写字节数，-1=参数非法。
 */
ssize_t aip_table_serialize(const struct ai_rule *rules, size_t n,
			    uint8_t *out, size_t cap);

/* SHA-256（FIPS 180-4；生成器同算法锚）。out[32] 二进制摘要。 */
void aip_sha256(const uint8_t *data, size_t n, uint8_t out[32]);

/* 摘要 → 64 字符小写 hex + NUL（out 容量 >= 65） */
void aip_sha256_hex(const uint8_t digest[32], char out[65]);

#endif /* _AIP_TABLE_H */
