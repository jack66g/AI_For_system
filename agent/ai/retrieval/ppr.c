/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ppr.c - Personalized PageRank（topic-sensitive）
 *
 * 逐行复刻 sme/retrieval/retriever.py:_ppr_rank（820-870 行）：
 *
 *   v = p
 *   for 20 轮:
 *       nxt = (1-d)*p
 *       dangling = Σ_{i 无出边} v[i]
 *       if dangling > 0: nxt += (d*dangling)*p
 *       acc[dst[e]] += (d*v[src[e]])*prob[e]      # 按边顺序累加
 *       nxt += acc
 *       err = Σ|nxt-v|; v = nxt; if err < 1e-6: break
 *
 * 与 Python 的差异仅为 numpy 的 pairwise 求和（误差 ~1e-16，远小于
 * 1e-9 门禁）；累加顺序本身严格一致。
 */
#include "../include/retrieval/ppr.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#define AIK_PPR_DAMPING 0.85
#define AIK_PPR_MAX_ITERS 20
#define AIK_PPR_TOL 1e-6

int aik_ppr_rank(size_t n_nodes, const double *personalization,
		 const size_t *src, const size_t *dst, const double *prob,
		 size_t n_edges, double *out)
{
	double *v;
	double *nxt;
	double *acc;
	unsigned char *dangling;
	size_t i;
	size_t e;
	int iter;
	int rc = -1;

	if (n_nodes == 0)
		return 0;
	if (!personalization || !out)
		return -1;
	if (n_edges > 0 && (!src || !dst || !prob))
		return -1;
	for (e = 0; e < n_edges; e++) {
		if (src[e] >= n_nodes || dst[e] >= n_nodes)
			return -1;
	}

	v = malloc(n_nodes * sizeof *v);
	nxt = malloc(n_nodes * sizeof *nxt);
	acc = malloc(n_nodes * sizeof *acc);
	dangling = malloc(n_nodes * sizeof *dangling);
	if (!v || !nxt || !acc || !dangling)
		goto out;

	for (i = 0; i < n_nodes; i++) {
		v[i] = personalization[i];
		dangling[i] = 1;
	}
	/* retriever.py:858-859：出现在 src 里的节点都有出边 */
	for (e = 0; e < n_edges; e++)
		dangling[src[e]] = 0;

	for (iter = 0; iter < AIK_PPR_MAX_ITERS; iter++) {
		double dang = 0.0;
		double err = 0.0;

		/* np.bincount(dst, weights=d*v[src]*prob)：按边顺序累加 */
		memset(acc, 0, n_nodes * sizeof *acc);
		for (e = 0; e < n_edges; e++)
			acc[dst[e]] += (AIK_PPR_DAMPING * v[src[e]]) * prob[e];
		/* v[dangling_mask].sum()：按节点下标升序 */
		for (i = 0; i < n_nodes; i++) {
			if (dangling[i])
				dang += v[i];
		}
		for (i = 0; i < n_nodes; i++) {
			double x = (1.0 - AIK_PPR_DAMPING) *
				   personalization[i];

			if (dang > 0.0)
				x += (AIK_PPR_DAMPING * dang) *
				     personalization[i];
			nxt[i] = x + acc[i];
		}
		for (i = 0; i < n_nodes; i++) {
			err += fabs(nxt[i] - v[i]);
			v[i] = nxt[i];
		}
		if (err < AIK_PPR_TOL)
			break;
	}

	memcpy(out, v, n_nodes * sizeof *out);
	rc = 0;
out:
	free(v);
	free(nxt);
	free(acc);
	free(dangling);
	return rc;
}
