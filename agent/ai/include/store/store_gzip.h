/* SPDX-License-Identifier: GPL-2.0 */
/*
 * store_gzip.h - gzip 解压/压缩（zlib，T2a 存储层读路径）
 *
 * 设计依据 T2-DESIGN.md §3。inflate 走 16+MAX_WBITS（gzip 包装），支持
 * 多 member 串联；deflate 固定 gzip 头 mtime=0（字节级不要求与 Python
 * 相同，解压后必须相同）。
 *
 * 输出缓冲均由本模块 malloc，调用者 free；成功返回 0，失败返回 -1 并在
 * err[0..errlen) 给出 "inflate: ..." / "deflate: ..." 形式的原因。输出
 * 缓冲末尾额外补一个 NUL（不计入 *outlen），便于直接把文本当 C 字符串用。
 */
#ifndef _AIK_STORE_GZIP_H
#define _AIK_STORE_GZIP_H

#include <stddef.h>

/* 解压输出上限（防压缩炸弹），256 MiB；超过即失败 */
#define AIK_GZIP_MAX_OUTPUT (256u * 1024u * 1024u)

/*
 * aik_gzip_inflate - 解压 gzip（含多 member）
 *
 * 成功返回 0，*out 为 malloc 缓冲（末尾带 NUL，*outlen 为真实长度）。
 * 输入为空、数据损坏、截断、超过 AIK_GZIP_MAX_OUTPUT 均返回 -1。
 */
int aik_gzip_inflate(const void *in, size_t inlen, unsigned char **out,
		     size_t *outlen, char *err, size_t errlen);

/*
 * aik_gzip_deflate - 压缩为 gzip
 *
 * level 取 1..9（越界按 9 处理）；gzip 头 mtime=0、OS=3，保证输出可重复。
 * 成功返回 0，*out 为 malloc 缓冲（末尾带 NUL，*outlen 为真实长度）。
 */
int aik_gzip_deflate(const void *in, size_t inlen, int level,
		     unsigned char **out, size_t *outlen,
		     char *err, size_t errlen);

#endif /* _AIK_STORE_GZIP_H */
