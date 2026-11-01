/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ppr.h - Personalized PageRank（topic-sensitive，dangling 回流 seeds）
 *
 * 逐条对齐 REF-PY sme/retrieval/retriever.py:_ppr_rank（SME 1.3.0）：
 *
 *   v <- d * (Mᵀ v + dangling * p) + (1 - d) * p
 *
 *   - M 的每行是「出边权重 / 行内权重和」；无出边的行是 dangling，
 *     其质量按 personalization 回流（保证游走锚定在检索证据上）；
 *   - personalization 由调用方归一（Σ = 1），这里不再缩放；
 *   - damping d = 0.85，最多 20 轮，Σᵢ|vᵢ' - vᵢ| < 1e-6 提前退出
 *     （退出前已把 v 更新为 v'，返回的是最后一轮的 v'）。
 *
 * 转移表按边顺序展平：src[e]→dst[e] 的概率 prob[e]。累加严格按边顺序
 * 进行（与 numpy.bincount 的逐元素累加一致），因此同一组输入在 C 与
 * Python 上得到同一浮点结果，而不只是 1e-9 内接近。
 *
 * 无全局状态；不做分配以外的 I/O，调用者拥有 out。
 */
#ifndef _AIK_RETRIEVAL_PPR_H
#define _AIK_RETRIEVAL_PPR_H

#include <stddef.h>

/*
 * aik_ppr_rank - 幂迭代求 personalization PageRank 向量
 *
 * n_nodes             节点数（0 时直接返回 0，out 可为 NULL）
 * personalization     n_nodes 个，已归一；不可为 NULL
 * src/dst/prob        n_edges 条转移；n_edges=0 时三者可为 NULL
 * out                 n_nodes 个结果，由调用者分配
 *
 * 返回 0；参数非法（空指针、下标越界、分配失败）返回 -1。
 */
int aik_ppr_rank(size_t n_nodes, const double *personalization,
		 const size_t *src, const size_t *dst, const double *prob,
		 size_t n_edges, double *out);

#endif /* _AIK_RETRIEVAL_PPR_H */
