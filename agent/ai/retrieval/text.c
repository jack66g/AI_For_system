/* SPDX-License-Identifier: GPL-2.0 */
/*
 * text.c - 轻量 tokenize（T3a）
 *
 * 与 REF-PY 的对应关系见 text.h 顶部注释。要点：
 *   - 先做全量 Unicode 小写（含 sigma 上下文），再按码点扫 run；
 *   - CJK 判定只看基本区 U+4E00-U+9FFF（与 Python 正则一致）；
 *   - 混合 run（拉丁/CJK 连写，如 "gpt模型"、"abc中文123"）按"长度>1 且
 *     含 CJK"进入切段分支，但**先按书写系统切段**：拉丁/数字段整词
 *     追加，CJK 段逐字 + 段内二元组（bigram 不再跨 ASCII/CJK 边界）。
 *
 * MEM-01a（有意偏离基线）：基线 REF-PY e72bc75 把整个混合 run 逐字符
 * 打散（"c中"、"文1" 这类跨书写系统 bigram），拉丁整词（gpt/iphone）从
 * BM25 索引里消失，纯拉丁查询对这些文档的关键词通道恒为 0。自
 * e72bc75 起在此处有意偏离，依据上游 ed5378a `sme/utils.py::tokenize`
 * （_RUN_SPLIT_RE = r"[a-z0-9]+|[\u4e00-\u9fff]+"，2026-11-20 测试战役
 * P2-1）。纯 CJK run 与纯拉丁 run 的行为与基线逐字节相同。
 *
 * 分词入口只有这一个：BM25 建索引（aik_bm25_add）、查询侧（_keyword_
 * scores / aik_bm25_top）与融合公共 token（engine consolidate）都调
 * aik_tokenize，索引与查询天然同方案。PPR 走记忆图边、8 信号排序不打分
 * 词，均不经分词。
 */
#include "retrieval/text.h"

#include "memory/unicode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_err(char *err, size_t errlen, const char *msg)
{
	if (err && errlen)
		snprintf(err, errlen, "%s", msg);
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

static int is_token_cp(unsigned int cp)
{
	if (cp >= 'a' && cp <= 'z')
		return 1;
	if (cp >= '0' && cp <= '9')
		return 1;
	return cp >= 0x4E00 && cp <= 0x9FFF;
}

static int is_cjk_cp(unsigned int cp)
{
	return cp >= 0x4E00 && cp <= 0x9FFF;
}

static int push_token(aik_token_list *out, size_t *cap, const char *s,
		      size_t len, char *err, size_t errlen)
{
	char *tok;

	if (out->count == *cap) {
		size_t ncap = *cap ? *cap * 2 : 16;
		char **items = realloc(out->items, ncap * sizeof(*items));

		if (!items) {
			set_err(err, errlen, "out of memory");
			return -1;
		}
		out->items = items;
		*cap = ncap;
	}
	tok = malloc(len + 1);
	if (!tok) {
		set_err(err, errlen, "out of memory");
		return -1;
	}
	memcpy(tok, s, len);
	tok[len] = '\0';
	out->items[out->count++] = tok;
	return 0;
}

int aik_tokenize(const char *utf8, int cjk_bigram, aik_token_list *out,
		 char *err, size_t errlen)
{
	char *lowered;
	unsigned int *cps = NULL;
	size_t *off = NULL;
	size_t n = 0, i, k, cap = 0, len;

	if (!out) {
		set_err(err, errlen, "out is NULL");
		return -1;
	}
	out->items = NULL;
	out->count = 0;
	if (!utf8 || utf8[0] == '\0')
		return 0;

	lowered = aik_unicode_lower_alloc(utf8, err, errlen);
	if (!lowered)
		return -1;
	len = strlen(lowered);
	if (aik_utf8_decode_all(lowered, len, &cps, &n, err, errlen) != 0)
		goto fail;
	off = malloc((n + 1) * sizeof(*off));
	if (!off) {
		set_err(err, errlen, "out of memory");
		goto fail;
	}
	off[0] = 0;
	for (i = 0; i < n; i++)
		off[i + 1] = off[i] + cp_len(cps[i]);
	if (off[n] != len) {
		set_err(err, errlen, "internal UTF-8 length mismatch");
		goto fail;
	}

	i = 0;
	while (i < n) {
		size_t j = i;
		int has_cjk = 0;

		if (!is_token_cp(cps[i])) {
			i++;
			continue;
		}
		while (j < n && is_token_cp(cps[j])) {
			if (is_cjk_cp(cps[j]))
				has_cjk = 1;
			j++;
		}
		if (j - i > 1 && has_cjk) {
			/*
			 * 混合 run 按书写系统切成极大段（等价 _RUN_SPLIT_RE.
			 * findall(tok)：run 只含 [a-z0-9] 与基本区 CJK 两类
			 * 码点，两类交替成段）。拉丁/数字段整词追加；CJK 段
			 * 先逐字追加，cjk_bigram 时再追加段内全部相邻二元组。
			 */
			k = i;
			while (k < j) {
				size_t e = k;
				int seg_cjk = is_cjk_cp(cps[k]);

				while (e < j && is_cjk_cp(cps[e]) == seg_cjk)
					e++;
				if (!seg_cjk) {
					if (push_token(out, &cap, lowered + off[k],
						       off[e] - off[k], err,
						       errlen) != 0)
						goto fail;
				} else {
					size_t m;

					for (m = k; m < e; m++) {
						if (push_token(out, &cap,
							       lowered + off[m],
							       off[m + 1] - off[m],
							       err, errlen) != 0)
							goto fail;
					}
					if (cjk_bigram) {
						for (m = k; m + 1 < e; m++) {
							if (push_token(out, &cap,
								       lowered + off[m],
								       off[m + 2] - off[m],
								       err, errlen) != 0)
								goto fail;
						}
					}
				}
				k = e;
			}
		} else {
			if (push_token(out, &cap, lowered + off[i],
				       off[j] - off[i], err, errlen) != 0)
				goto fail;
		}
		i = j;
	}

	free(off);
	free(cps);
	free(lowered);
	return 0;

fail:
	free(off);
	free(cps);
	free(lowered);
	aik_token_list_free(out);
	return -1;
}

void aik_token_list_free(aik_token_list *t)
{
	size_t i;

	if (!t)
		return;
	for (i = 0; i < t->count; i++)
		free(t->items[i]);
	free(t->items);
	t->items = NULL;
	t->count = 0;
}
