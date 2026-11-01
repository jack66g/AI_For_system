/* SPDX-License-Identifier: GPL-2.0 */
/*
 * blake2b.h - RFC 7693 BLAKE2b 内核（T3a）
 *
 * 只给 T3a 的 hashing 嵌入用：无 key、纯函数、输出长度可配（1..64 字节）。
 * 对外主入口 aik_blake2b64() 声明在 include/memory/embed_hash.h。
 */
#ifndef _AIK_BLAKE2B_H
#define _AIK_BLAKE2B_H

#include <stddef.h>

/*
 * aik_blake2b - 无 key BLAKE2b
 *
 * data/len: 输入（data 可为 NULL 当且仅当 len == 0）
 * out/outlen: 输出缓冲与摘要长度（字节，1..64）
 * 成功 0；参数非法 -1。输出与 RFC 7693 附录测试向量一致。
 */
int aik_blake2b(const void *data, size_t len, void *out, size_t outlen);

#endif /* _AIK_BLAKE2B_H */
