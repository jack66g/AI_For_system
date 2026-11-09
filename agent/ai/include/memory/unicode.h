/* SPDX-License-Identifier: GPL-2.0 */
/*
 * unicode.h - UTF-8 解码 / 全量小写 / Python isspace 判定（T3a）
 *
 * 目标：逐条复刻 Python 3.10.6（Unicode 13.0.0）的 str.lower() 与
 * str.isspace()，供 hashing 嵌入和 tokenize 共用。小写映射表来自
 * unicode_lower_table.h（由 parity 向量生成），表外码点原样复制，
 * 非法 UTF-8 一律报错、绝不静默替换。
 */
#ifndef _AIK_UNICODE_H
#define _AIK_UNICODE_H

#include <stddef.h>

/*
 * aik_utf8_decode - 解一个码点（严格 UTF-8：拒绝 overlong、代理区、>U+10FFFF）
 *
 * 成功返回消耗字节数（1..4）并写 *cp；失败返回 0（*cp 不保证被写）。
 */
size_t aik_utf8_decode(const char *s, size_t len, unsigned int *cp);

/* aik_utf8_encode - 编码一个码点，返回字节数（1..4）；非法码点返回 0 */
size_t aik_utf8_encode(unsigned int cp, char out[4]);

/*
 * aik_utf8_decode_all - 把整串解成码点数组（malloc，调用者 free）
 *
 * 成功 0，返回的码点数组与个数写进 out / out_n；失败 -1 且 err 写
 * "invalid UTF-8 at byte N"。
 */
int aik_utf8_decode_all(const char *utf8, size_t len, unsigned int **out,
			size_t *out_n, char *err, size_t errlen);

/*
 * aik_unicode_lower_alloc - str.lower() 等价（malloc，调用者 free）
 *
 * 含希腊词尾 sigma 上下文规则与多字符展开；失败返回 NULL 并写 err。
 */
char *aik_unicode_lower_alloc(const char *utf8, char *err, size_t errlen);

/* Python str.isspace() 的码点集合（Zs + 0x09-0x0D/0x1C-0x1F/0x85/0x2028/0x2029） */
int aik_unicode_is_space(unsigned int cp);

/* Unicode 13.0 Cased / Case_Ignorable（词尾 sigma 判定用） */
int aik_unicode_is_cased(unsigned int cp);
int aik_unicode_is_case_ignorable(unsigned int cp);

#endif /* _AIK_UNICODE_H */
