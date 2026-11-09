/* SPDX-License-Identifier: GPL-2.0 */
/*
 * text.c - 轻量 tokenize（T3a）
 *
 * 与 REF-PY 的对应关系见 text.h 顶部注释。要点：
 *   - 先做全量 Unicode 小写（含 sigma 上下文），再按码点扫 run；
 *   - CJK 判定只看基本区 U+4E00-U+9FFF（与 Python 正则一致）；
 *   - 混合 run（如 "abc中文123"）也按"长度>1 且含 CJK"走单字 + 二元组，
 *     所以 bigram 会跨 ASCII/CJK 边界（"c中"、"文1"）。
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
	size_t n = 0, i, cap = 0, len;

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
		size_t j = i, k;
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
			for (k = i; k < j; k++) {
				if (push_token(out, &cap, lowered + off[k],
					       off[k + 1] - off[k],
					       err, errlen) != 0)
					goto fail;
			}
			if (cjk_bigram) {
				for (k = i; k + 1 < j; k++) {
					if (push_token(out, &cap,
						       lowered + off[k],
						       off[k + 2] - off[k],
						       err, errlen) != 0)
						goto fail;
				}
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
