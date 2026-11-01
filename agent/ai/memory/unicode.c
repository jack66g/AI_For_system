/* SPDX-License-Identifier: GPL-2.0 */
/*
 * unicode.c - UTF-8 解码 / 全量小写 / Python isspace 判定（T3a）
 *
 * 语义基准是 REF-PY 的 CPython 3.10.6（Unicode 13.0.0）：
 *   - str.lower() 走 Unicode 默认（非土耳其语）小写映射，U+0130 展开成
 *     "i" + U+0307，U+03A3 按上下文取 U+03C3 / U+03C2；
 *   - 词尾 sigma 规则：前向跳过 Case_Ignorable 后存在 Cased，且后向跳过
 *     Case_Ignorable 后不存在 Cased，则输出 U+03C2；
 *   - str.isspace() 的集合为 Zs + 0x09-0x0D + 0x1C-0x1F + 0x85 +
 *     0x2028/0x2029（共 29 个码点）。
 *
 * Cased / Case_Ignorable 区间由 /tmp 生成脚本逐码点对 CPython 实测导出，
 * 存于 unicode_lower_table.h；等价于 DerivedCoreProperties（含
 * Other_Uppercase / Other_Lowercase，例如 U+2160 Ⅰ、U+00AA ª）。
 */
#include "unicode.h"
#include "unicode_lower_table.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_err(char *err, size_t errlen, const char *msg)
{
	if (err && errlen)
		snprintf(err, errlen, "%s", msg);
}

size_t aik_utf8_decode(const char *s, size_t len, unsigned int *cp)
{
	const unsigned char *p = (const unsigned char *)s;
	unsigned int c, min;
	size_t need, i;

	if (len == 0)
		return 0;
	c = p[0];
	if (c < 0x80) {
		*cp = c;
		return 1;
	}
	if ((c & 0xE0) == 0xC0) {
		c &= 0x1F;
		need = 1;
		min = 0x80;
	} else if ((c & 0xF0) == 0xE0) {
		c &= 0x0F;
		need = 2;
		min = 0x800;
	} else if ((c & 0xF8) == 0xF0) {
		c &= 0x07;
		need = 3;
		min = 0x10000;
	} else {
		return 0;
	}
	if (len < need + 1)
		return 0;
	for (i = 1; i <= need; i++) {
		if ((p[i] & 0xC0) != 0x80)
			return 0;
		c = (c << 6) | (p[i] & 0x3F);
	}
	if (c < min || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF))
		return 0;
	*cp = c;
	return need + 1;
}

size_t aik_utf8_encode(unsigned int cp, char out[4])
{
	if (cp <= 0x7F) {
		out[0] = (char)cp;
		return 1;
	}
	if (cp >= 0xD800 && cp <= 0xDFFF)
		return 0;
	if (cp <= 0x7FF) {
		out[0] = (char)(0xC0 | (cp >> 6));
		out[1] = (char)(0x80 | (cp & 0x3F));
		return 2;
	}
	if (cp <= 0xFFFF) {
		out[0] = (char)(0xE0 | (cp >> 12));
		out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
		out[2] = (char)(0x80 | (cp & 0x3F));
		return 3;
	}
	if (cp <= 0x10FFFF) {
		out[0] = (char)(0xF0 | (cp >> 18));
		out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
		out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
		out[3] = (char)(0x80 | (cp & 0x3F));
		return 4;
	}
	return 0;
}

int aik_utf8_decode_all(const char *utf8, size_t len, unsigned int **out,
			size_t *out_n, char *err, size_t errlen)
{
	unsigned int *cps;
	size_t n = 0, i = 0;

	if (!out || !out_n)
		return -1;
	*out = NULL;
	*out_n = 0;
	if (!utf8)
		return -1;
	cps = malloc((len + 1) * sizeof(*cps));
	if (!cps) {
		set_err(err, errlen, "out of memory");
		return -1;
	}
	while (i < len) {
		unsigned int cp;
		size_t used = aik_utf8_decode(utf8 + i, len - i, &cp);

		if (used == 0) {
			if (err && errlen)
				snprintf(err, errlen,
					 "invalid UTF-8 at byte %zu", i);
			free(cps);
			return -1;
		}
		cps[n++] = cp;
		i += used;
	}
	*out = cps;
	*out_n = n;
	return 0;
}

static const struct aik_uni_lower_entry *lower_lookup(unsigned int cp)
{
	size_t lo = 0, hi = AIK_UNI_LOWER_COUNT;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (aik_uni_lower_table[mid].cp < cp)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (lo < AIK_UNI_LOWER_COUNT && aik_uni_lower_table[lo].cp == cp)
		return &aik_uni_lower_table[lo];
	return NULL;
}

static int in_ranges(const struct aik_uni_range *r, size_t n, unsigned int cp)
{
	size_t lo = 0, hi = n;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (r[mid].hi < cp)
			lo = mid + 1;
		else if (r[mid].lo > cp)
			hi = mid;
		else
			return 1;
	}
	return 0;
}

int aik_unicode_is_cased(unsigned int cp)
{
	return in_ranges(aik_uni_cased_ranges, AIK_UNI_CASED_COUNT, cp);
}

int aik_unicode_is_case_ignorable(unsigned int cp)
{
	return in_ranges(aik_uni_case_ignorable_ranges,
			 AIK_UNI_CASE_IGNORABLE_COUNT, cp);
}

int aik_unicode_is_space(unsigned int cp)
{
	switch (cp) {
	case 0x09: case 0x0A: case 0x0B: case 0x0C: case 0x0D:
	case 0x1C: case 0x1D: case 0x1E: case 0x1F:
	case 0x20: case 0x85: case 0xA0: case 0x1680:
	case 0x2028: case 0x2029: case 0x202F: case 0x205F: case 0x3000:
		return 1;
	default:
		break;
	}
	return cp >= 0x2000 && cp <= 0x200A;
}

static int is_final_sigma(const unsigned int *cps, size_t n, size_t i)
{
	size_t j;
	int preceded = 0;

	for (j = i; j > 0; j--) {
		unsigned int prev = cps[j - 1];

		if (aik_unicode_is_cased(prev)) {
			preceded = 1;
			break;
		}
		if (!aik_unicode_is_case_ignorable(prev))
			break;
	}
	if (!preceded)
		return 0;
	for (j = i + 1; j < n; j++) {
		if (aik_unicode_is_cased(cps[j]))
			return 0;
		if (!aik_unicode_is_case_ignorable(cps[j]))
			break;
	}
	return 1;
}

char *aik_unicode_lower_alloc(const char *utf8, char *err, size_t errlen)
{
	unsigned int *cps = NULL;
	size_t n = 0, i, total = 0;
	char *out;

	if (!utf8) {
		set_err(err, errlen, "text is NULL");
		return NULL;
	}
	if (aik_utf8_decode_all(utf8, strlen(utf8), &cps, &n, err, errlen) != 0)
		return NULL;

	for (i = 0; i < n; i++) {
		unsigned int cp = cps[i];
		const struct aik_uni_lower_entry *e;
		size_t add;

		if (cp == 0x03A3) {
			add = 2;
		} else {
			e = lower_lookup(cp);
			if (e)
				add = strlen(e->to);
			else if (cp <= 0x7F)
				add = 1;
			else if (cp <= 0x7FF)
				add = 2;
			else if (cp <= 0xFFFF)
				add = 3;
			else
				add = 4;
		}
		if (total > (size_t)-1 - add)
			goto overflow;
		total += add;
	}

	out = malloc(total + 1);
	if (!out) {
		free(cps);
		set_err(err, errlen, "out of memory");
		return NULL;
	}
	total = 0;
	for (i = 0; i < n; i++) {
		unsigned int cp = cps[i];
		const struct aik_uni_lower_entry *e;
		size_t len;

		if (cp == 0x03A3) {
			unsigned int mapped = is_final_sigma(cps, n, i) ?
					      0x03C2 : 0x03C3;

			len = aik_utf8_encode(mapped, out + total);
			total += len;
			continue;
		}
		e = lower_lookup(cp);
		if (e) {
			len = strlen(e->to);
			memcpy(out + total, e->to, len);
			total += len;
			continue;
		}
		len = aik_utf8_encode(cp, out + total);
		if (len == 0) {
			free(cps);
			free(out);
			set_err(err, errlen, "invalid code point");
			return NULL;
		}
		total += len;
	}
	out[total] = '\0';
	free(cps);
	return out;

overflow:
	free(cps);
	set_err(err, errlen, "input too long");
	return NULL;
}
