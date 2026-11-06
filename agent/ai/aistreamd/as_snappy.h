/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_snappy.h - snappy 原始块格式（raw block）压缩/解压（T8）
 *
 * Parquet 页压缩用（codec=SNAPPY）。实现 snappy 规范的块格式：
 *   [varint uncompressed_length][element ...]
 * element 为 literal（tag 低 2 位=0）或 copy（1/2/3 字节偏移三种）。
 *
 * 压缩器：按 64KB 块独立压缩（对齐 canonical snappy 的分块语义，
 * 保证 copy 偏移 <= 65535，只需 1/2 字节偏移形式）；4 字节最小匹配，
 * 1<<14 槽位哈希表（乘法哈希 0x1e35a7bd，同 canonical）。
 * 单块内退化为 literal-only 输出时格式仍合法（pyarrow 可读）。
 *
 * 解压器仅服务单测与负向校验（writer 不回读数据页——读路径只到
 * footer 统计，见 as_parquet.c）。
 */
#ifndef _AS_SNAPPY_H
#define _AS_SNAPPY_H

#include <stddef.h>
#include <stdint.h>

/* 压缩输出上界（同 canonical MaxCompressedLength） */
size_t as_snappy_max_len(size_t n);

/*
 * as_snappy_compress - 压缩 in[n] 到 out（容量 >= as_snappy_max_len(n)）。
 * 返回 0 成功（*out_len 为输出长度）；-1 参数/内部错误。
 * n==0：输出仅 1 字节 varint 0（合法空块）。
 */
int as_snappy_compress(const uint8_t *in, size_t n, uint8_t *out,
		       size_t *out_len);

/*
 * as_snappy_uncompress - 解压 in[n]（snappy 块）到 out（容量 *out_cap）。
 * 返回 0 成功（*out_cap 改写为实际解压长度）；-1 格式损坏/容量不足。
 */
int as_snappy_uncompress(const uint8_t *in, size_t n, uint8_t *out,
			 size_t *out_cap);

#endif /* _AS_SNAPPY_H */
