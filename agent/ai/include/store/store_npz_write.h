/* SPDX-License-Identifier: GPL-2.0 */
/*
 * store_npz_write.h - .npz 写入（ZIP store + NPY 1.0），T4c 引擎保存路径
 *
 * 对齐 REF-PY e72bc75 `sme/storage/snapshot.py::_save_embeddings` 的磁盘格式：
 *
 *   ids.npy        dtype "<U<width>"，1-D shape (n,)
 *   matrix.npy     dtype "<f8"，2-D shape (n, dim)，C 序
 *   generation.npy dtype "<U32"，0-D 标量 shape ()
 *
 * NPY 1.0 头：\x93NUMPY + 版本 (1,0) + 2 字节小端头长 + 头部文本，
 * 头部文本以空格填充、末尾换行，使 magic+版本+长度+头 的总长按 64 字节
 * 对齐（因此也一定是 16 字节对齐；与 numpy 1.x 的 ARRAY_ALIGN 一致）。
 * "<U<n>" 数据是 UTF-32LE 码点序列，不足补 0 码点；width 取所有 id 的
 * 最大 UTF-8 码点数（至少 1），generation 固定 32 码点。
 *
 * ZIP 侧只写 store（method 0）：local file header + data + central
 * directory + EOCD，通用标志位 0，条目名不带任何路径（"ids.npy" 等）。
 *
 * 原子性：同目录 path.tmp.<pid> → fsync → rename → 目录 fsync；任何失败
 * 都会清理临时文件并返回 -1，绝不留下半成品 .npz。目录必须已存在
 * （引擎保存路径负责 mkdir -p）。
 *
 * 空输入约定（与 Python `_save_embeddings` 一致）：n_ids == 0 时不写文件，
 * 返回 -1 并写 err（T2 读侧的 aik_npy_parse 也把空数组判为非法）。
 *
 * 失败时 err[0..errlen) 写入 "npz_write: ..." 形式的原因（err 可为
 * NULL/errlen=0）。无全局状态，单线程。
 */
#ifndef _AIK_STORE_NPZ_WRITE_H
#define _AIK_STORE_NPZ_WRITE_H

#include <stddef.h>

/*
 * aik_npz_write_embeddings - 写 embeddings sidecar
 *
 *   path       目标 .npz 路径（目录必须存在）
 *   generation 32 位小写十六进制代次字符串（1..32 个码点；引擎传 32 位）
 *   ids        n_ids 个 NUL 结尾 UTF-8 字符串（借用）
 *   n_ids      条目数，必须 > 0
 *   matrix     行优先 n_ids * dim 个 double（借用）
 *   dim        向量维度，必须 > 0
 *
 * 成功返回 0；参数非法、id 过长（> 64 码点）、非法 UTF-8、生成代次为空
 * 或超长、条目超过 AIK_NPZ_MAX_ENTRY / 文件超过 AIK_NPZ_MAX_FILE、
 * I/O 失败均返回 -1 并写 err。
 */
int aik_npz_write_embeddings(const char *path, const char *generation,
			     const char *const *ids, size_t n_ids,
			     const double *matrix, int dim,
			     char *err, size_t errlen);

#endif /* _AIK_STORE_NPZ_WRITE_H */
