/* SPDX-License-Identifier: GPL-2.0 */
/*
 * embed_hash.c - 确定性 hashing 嵌入（T3a）
 *
 * 逐行对齐 REF-PY sme/embedding/hashing.py::_embed_one 与
 * sme/embedding/base.py::_post。所有 raw 增量都是 0.5 的整数倍（w=1..window
 * 的权重为 1, 1.5, 2, 2.5...），因此 double 累加无舍入；L2 范数的平方和
 * 也精确可表示，sqrt 按 IEEE 正确舍入，归一化结果与 numpy 逐位相同。
 */
#include "memory/embed_hash.h"

#include "memory/blake2b.h"
#include "memory/unicode.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AIK_HASH_MRL_EPS	1e-12

static void set_err(char *err, size_t errlen, const char *msg)
{
	if (err && errlen)
		snprintf(err, errlen, "%s", msg);
}

int aik_hash_effective_dim(const aik_hash_params *p)
{
	if (!p || p->dim <= 0)
		return 0;
	if (p->mrl_dim > 0 && p->mrl_dim < p->dim)
		return p->mrl_dim;
	return p->dim;
}

static size_t cp_len(unsigned int cp)
{
	if (cp <= 0x7F)
		return 1;
	if (cp <= 0x7FF)
		return 2;
	if (cp <= 0xFFFF)
		return 3;
	return 4;
}

/*
 * decode_with_offsets - 解码点并给出每个码点的字节偏移
 *
 * off 需 n+1 项；off[n] 等于原串字节长度（严格 UTF-8 下编码长度唯一）。
 */
static int decode_with_offsets(const char *text, unsigned int **out_cps,
			       size_t **out_off, size_t *out_n,
			       char *err, size_t errlen)
{
	unsigned int *cps = NULL;
	size_t *off = NULL;
	size_t n = 0, i, len = strlen(text);

	if (aik_utf8_decode_all(text, len, &cps, &n, err, errlen) != 0)
		return -1;
	off = malloc((n + 1) * sizeof(*off));
	if (!off) {
		free(cps);
		set_err(err, errlen, "out of memory");
		return -1;
	}
	off[0] = 0;
	for (i = 0; i < n; i++)
		off[i + 1] = off[i] + cp_len(cps[i]);
	if (off[n] != len) {
		free(cps);
		free(off);
		set_err(err, errlen, "internal UTF-8 length mismatch");
		return -1;
	}
	*out_cps = cps;
	*out_off = off;
	*out_n = n;
	return 0;
}

static int all_space(const unsigned int *cps, size_t n)
{
	size_t i;

	if (n == 0)
		return 1;
	for (i = 0; i < n; i++) {
		if (!aik_unicode_is_space(cps[i]))
			return 0;
	}
	return 1;
}

int aik_hash_embed_one(const aik_hash_params *p, const char *utf8,
		       double *out, size_t out_cap, char *err, size_t errlen)
{
	char *lowered = NULL;
	unsigned int *cps = NULL;
	size_t *off = NULL;
	size_t n = 0, i, featlen, scratch_cap;
	char *scratch = NULL;
	double *v = NULL;
	int dim, factors, window, target, w, f;

	if (!p) {
		set_err(err, errlen, "params is NULL");
		return -1;
	}
	dim = p->dim;
	factors = p->factors;
	window = p->window;
	target = aik_hash_effective_dim(p);
	if (dim <= 0 || target <= 0) {
		set_err(err, errlen, "dim must be positive");
		return -1;
	}
	if (factors < 0) {
		set_err(err, errlen, "factors must be >= 0");
		return -1;
	}
	if (window < 1)
		window = 1;	/* Python: self.window = max(1, window) */
	if (!out || out_cap < (size_t)target) {
		set_err(err, errlen, "out buffer too small");
		return -1;
	}

	lowered = aik_unicode_lower_alloc(utf8, err, errlen);
	if (!lowered)
		return -1;
	if (decode_with_offsets(lowered, &cps, &off, &n, err, errlen) != 0)
		goto fail;
	if (all_space(cps, n)) {
		/* str.strip() 为空 -> 用 "_empty_" 参与特征提取 */
		char *repl = malloc(sizeof("_empty_"));

		if (!repl) {
			set_err(err, errlen, "out of memory");
			goto fail;
		}
		memcpy(repl, "_empty_", sizeof("_empty_"));
		free(cps);
		free(off);
		free(lowered);
		lowered = repl;
		if (decode_with_offsets(lowered, &cps, &off, &n,
					err, errlen) != 0)
			goto fail;
	}

	/* 哈希输入上限："seed:factors:" + 最长 window 个码点（≤4 字节） */
	scratch_cap = 64 + (size_t)window * 4;
	scratch = malloc(scratch_cap);
	v = calloc((size_t)dim, sizeof(*v));
	if (!scratch || !v) {
		set_err(err, errlen, "out of memory");
		goto fail;
	}

	for (i = 0; i < n; i++) {
		for (w = 1; w <= window && i + (size_t)w <= n; w++) {
			unsigned char dg[8];
			unsigned long long h;
			size_t idx, sign_len;
			double sign;

			featlen = off[i + (size_t)w] - off[i];
			for (f = 0; f < factors; f++) {
				int pre = snprintf(scratch, scratch_cap,
						   "%llu:%d:",
						   p->seed, f);

				if (pre < 0 ||
				    (size_t)pre + featlen >= scratch_cap) {
					set_err(err, errlen,
						"feature buffer too small");
					goto fail;
				}
				memcpy(scratch + pre, lowered + off[i],
				       featlen);
				if (aik_blake2b64(scratch,
						  (size_t)pre + featlen,
						  dg) != 0) {
					set_err(err, errlen, "blake2b failed");
					goto fail;
				}
				h = 0;
				for (sign_len = 0; sign_len < 8; sign_len++)
					h |= (unsigned long long)dg[sign_len] <<
					     (8 * sign_len);
				idx = (size_t)(h % (unsigned long long)dim);
				sign = ((h >> 8) & 1ULL) ? 1.0 : -1.0;
				v[idx] += sign * (1.0 + 0.5 * (double)w);
			}
		}
	}

	/*
	 * 后处理（base.py::_post）：先按 mrl_dim 截断，再 pad/truncate 到
	 * effective_dim，最后归一化。mrl 生效时 target == mrl_dim。
	 */
	memset(out, 0, (size_t)target * sizeof(*out));
	memcpy(out, v, (size_t)(target < dim ? target : dim) * sizeof(*out));
	if (p->normalize_output) {
		double norm = 0.0;

		for (i = 0; i < (size_t)target; i++)
			norm += out[i] * out[i];
		norm = sqrt(norm);
		if (norm >= AIK_HASH_MRL_EPS) {
			for (i = 0; i < (size_t)target; i++)
				out[i] /= norm;
		}
	}

	free(v);
	free(scratch);
	free(off);
	free(cps);
	free(lowered);
	return target;

fail:
	free(v);
	free(scratch);
	free(off);
	free(cps);
	free(lowered);
	return -1;
}
