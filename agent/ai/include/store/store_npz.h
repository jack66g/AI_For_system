/* SPDX-License-Identifier: GPL-2.0 */
/*
 * store_npz.h - .npz（ZIP + NPY）只读解析，T2a 存储层读路径
 *
 * 设计依据 T2-DESIGN.md §4。
 *   - ZIP 侧只做读：EOCD（尾部 64 KiB 内反查）+ 中央目录 + local header；
 *     method 0（store）与 8（deflate，raw zlib 流）；sizes/CRC 一律以中央
 *     目录为准；拒绝路径穿越、重复名、加密条目与超过 AIK_NPZ_MAX_ENTRY
 *     的单条目。
 *   - NPY 侧支持 \x93NUMPY 1.0/2.0 头，descr 支持 "<f8" 与 "<U<n>"
 *     （UTF-32LE code point 序列）。
 *
 * 所有错误经 err[0..errlen) 返回 "npz: ..." / "npy: ..."，失败不留半成品。
 */
#ifndef _AIK_STORE_NPZ_H
#define _AIK_STORE_NPZ_H

#include <stddef.h>

/* 单条目解压后上限（防 zip 炸弹） */
#define AIK_NPZ_MAX_ENTRY (64u * 1024u * 1024u)
/* 整个 .npz 文件上限 */
#define AIK_NPZ_MAX_FILE (256u * 1024u * 1024u)

typedef struct aik_npz aik_npz;

/* 打开 .npz：读入整文件并解析中央目录。失败返回 NULL，err 给原因 */
aik_npz *aik_npz_open(const char *path, char *err, size_t errlen);
void aik_npz_close(aik_npz *z);

/* 条目数 / 第 i 个条目名（已去掉 ".npy" 后缀，NUL 结尾） */
size_t aik_npz_count(const aik_npz *z);
const char *aik_npz_name_at(const aik_npz *z, size_t i);

/* 是否存在该条目：name 可写 "ids" 或 "ids.npy"。存在 1，否则 0 */
int aik_npz_has(const aik_npz *z, const char *name);

/*
 * aik_npz_read - 取出并解压指定条目的 .npy 原始字节
 *
 * *data 为 malloc 缓冲（末尾带 NUL，*len 为真实长度），调用者 free。
 * 失败（不存在 / 解压错误 / 长度不符 / CRC 不符）返回 -1。
 */
int aik_npz_read(const aik_npz *z, const char *name, unsigned char **data,
		 size_t *len, char *err, size_t errlen);

/* NPY 头解析结果；data 指向调用者提供的 buf（aik_npz_read 的返回值） */
typedef struct aik_npy {
	char descr[16];		/* "<f8" / "<U14" / "<U32" ... */
	int fortran_order;
	int ndim;
	long long shape[8];
	const unsigned char *data;	/* 数据段（不含头） */
	size_t data_len;
} aik_npy;

/*
 * aik_npy_parse - 解析 .npy 头并校验数据段长度
 *
 * descr 只支持 "<f8" 与 "<U<n>"（n=1..64）；shape 最多 8 维；
 * data_len 必须恰好等于元素数 * itemsize，否则失败。
 */
int aik_npy_parse(const unsigned char *buf, size_t len, aik_npy *out,
		  char *err, size_t errlen);

/* 元素数（shape 连乘；标量 shape () 为 1）；非法返回 0 */
size_t aik_npy_nelem(const aik_npy *npy);

/* 元素字节数：<f8 → 8，<U<n> → 4n；未知 descr 返回 0 */
size_t aik_npy_itemsize(const aik_npy *npy);

/*
 * aik_npy_get_f8 - 取第 idx 个 double（C 序扁平下标；仅 "<f8"）
 *
 * 成功 0；下标越界、类型不符或 npy 为空返回 -1。
 */
int aik_npy_get_f8(const aik_npy *npy, size_t idx, double *out);

/*
 * aik_npy_get_ustr - 取 "<U<n>" 第 idx 个字符串，转 UTF-8
 *
 * UTF-32LE code point 序列，读到 0 或 n 个 code point 为止；输出 NUL 结尾。
 * 成功返回写入字节数（不含 NUL）；下标越界、类型不符、非法 code point
 * 或输出缓冲不足返回 -1。
 */
int aik_npy_get_ustr(const aik_npy *npy, size_t idx, char *out, size_t outlen);

#endif /* _AIK_STORE_NPZ_H */
