/* SPDX-License-Identifier: GPL-2.0 */
/*
 * embed_hash.h - 确定性 hashing 嵌入（T3a）
 *
 * 逐条复刻 REF-PY sme/embedding/hashing.py + base.py 的 _embed_one/_post：
 *   lowered = str.lower(text)，全空白则用 "_empty_"；
 *   对 lowered 的码点做 1..window 长的 n-gram（factors 次独立哈希）；
 *   h = BLAKE2b-64(f"{seed}:{f}:{feat}") 按 little-endian 读成 uint64；
 *   idx = h % dim，sign = ((h >> 8) & 1) ? +1 : -1，v[idx] += sign*(1+0.5*w)；
 *   再按 mrl_dim 截断、pad/truncate 到 effective_dim、可选 L2 归一化。
 *
 * 参数约定：seed 已在上层把 0 折成 42，本层原样使用；window 会按
 * max(1, window) 处理（与 REF-PY 一致）。
 */
#ifndef _AIK_EMBED_HASH_H
#define _AIK_EMBED_HASH_H

#include <stddef.h>

typedef struct {
	int dim;
	int factors;
	int window;
	unsigned long long seed;
	int normalize_output;
	int mrl_dim;
} aik_hash_params;

/* 实际输出维数：0 < mrl_dim < dim 时为 mrl_dim，否则 dim；参数非法返回 0 */
int aik_hash_effective_dim(const aik_hash_params *p);

/*
 * aik_hash_embed_one - 单条文本的嵌入
 *
 * 成功返回有效维数（写入 out 的 double 个数，全部为 0.5 的整数倍或
 * 归一化后的结果）；失败 -1 并写 err。out_cap 小于有效维数时报错。
 */
int aik_hash_embed_one(const aik_hash_params *p, const char *utf8,
		       double *out, size_t out_cap, char *err, size_t errlen);

/*
 * aik_blake2b64 - 无 key BLAKE2b，digest_size=8（RFC 7693）
 *
 * 实现见 memory/blake2b.c；成功 0，参数非法 -1。
 */
int aik_blake2b64(const void *data, size_t len, unsigned char out[8]);

#endif /* _AIK_EMBED_HASH_H */
