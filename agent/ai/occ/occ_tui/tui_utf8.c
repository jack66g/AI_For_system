/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_utf8.c - UTF-8 解码/编码 + 简化 wcwidth 双宽表（T9c1）
 *
 * wcwidth 简化范围（诚实标注，测试矩阵只对本表负责）：
 *   - 宽(2)：CJK 统一表意(4E00-9FFF)、扩展A(3400-4DBF)、兼容(F900-FAFF)、
 *     扩展B+(20000-3FFFD)、假名(3040-30FF)、谚文音节(AC00-D7A3)、
 *     谚文 Jamo(1100-115F)、全角形式(FF01-FF60/FFE0-FFE6)、
 *     CJK符号标点(2E80-303E 内的宽段)、emoji 主区块(1F300-1F64F、
 *     1F680-1F6FF、1F900-1F9FF、1FA00-1FAFF 等)。
 *   - 零宽(0)：C0/C1 控制、组合附加符常用块（0300-036F、0483-0489、
 *     0591-05BD、0610-061A、064B-065F、0900-0903、093A-094D、1AB0-1AFF、
 *     1DC0-1DFF、20D0-20F0、FE00-FE0F 变体选择符、FE20-FE2F 等）、
 *     零宽空格/方向标记(200B-200F、2028-202E、2060-206F)、U+FEFF。
 *   - 不承诺与 glibc wcwidth 全表逐点一致：emoji 变体选择符序列、
 *     East Asian Ambiguous（如 U+00B1、U+2010-201F 等）一律按 1 处理、
 *     罕见组合符块可能漏收（漏收→按 1，不按 0——宁可宽一格不撕行）。
 */
#include "tui_utf8.h"

#include <string.h>

/* ---- 前导字节 → 期望长度 ---- */
int tui_utf8_seqlen(uint8_t lead)
{
	if (lead < 0x80)
		return 1;
	if (lead >= 0xC2 && lead <= 0xDF)
		return 2;
	if (lead >= 0xE0 && lead <= 0xEF)
		return 3;
	if (lead >= 0xF0 && lead <= 0xF4)
		return 4;
	return 0;			/* 连续字节/0xC0-0xC1 过长/0xF5+ 越界 */
}

/* ---- 解码（严格校验：过长编码、代理区、>10FFFF 一律 INVALID） ---- */
tui_u8stat tui_utf8_decode(const uint8_t *p, size_t n, uint32_t *cp, size_t *adv)
{
	int need;
	uint32_t v;
	size_t i;

	*cp = 0;
	*adv = 0;
	if (n == 0)
		return TUI_U8_NEEDMORE;

	need = tui_utf8_seqlen(p[0]);
	if (need == 0) {
		*adv = 1;		/* 坏前导：跳 1 字节吐替换符 */
		return TUI_U8_INVALID;
	}
	if (need == 1) {
		*cp = p[0];
		*adv = 1;
		return TUI_U8_OK;
	}
	if (n < (size_t)need) {
		/* 前缀可能合法也可能已经坏——先查已见部分的约束 */
		if (need == 3 && n >= 2 && (p[1] < 0x80 || p[1] > 0xBF))
			{ *adv = 1; return TUI_U8_INVALID; }
		if (need == 3 && n >= 2 && p[0] == 0xE0 && p[1] < 0xA0)
			{ *adv = 1; return TUI_U8_INVALID; }
		if (need == 4 && n >= 2 && (p[1] < 0x80 || p[1] > 0xBF))
			{ *adv = 1; return TUI_U8_INVALID; }
		if (need == 4 && n >= 2 && p[0] == 0xF0 && p[1] < 0x90)
			{ *adv = 1; return TUI_U8_INVALID; }
		if (need == 4 && n >= 2 && p[0] == 0xF4 && p[1] > 0x8F)
			{ *adv = 1; return TUI_U8_INVALID; }
		*adv = n;
		return TUI_U8_NEEDMORE;
	}
	/* 续字节全查 */
	for (i = 1; i < (size_t)need; i++) {
		if (p[i] < 0x80 || p[i] > 0xBF) {
			*adv = 1;	/* 首字节单独已坏 */
			return TUI_U8_INVALID;
		}
	}
	v = (uint32_t)(p[0] & (0x7F >> need));
	for (i = 1; i < (size_t)need; i++)
		v = (v << 6) | (uint32_t)(p[i] & 0x3F);
	/* 过长/代理/越界 */
	if ((need == 3 && v < 0x800) ||
	    (need == 4 && v < 0x10000) ||
	    (v >= 0xD800 && v <= 0xDFFF) || v > 0x10FFFF) {
		*adv = 1;
		return TUI_U8_INVALID;
	}
	*cp = v;
	*adv = (size_t)need;
	return TUI_U8_OK;
}

/* ---- 编码 ---- */
size_t tui_utf8_encode(uint32_t cp, uint8_t *out)
{
	if (cp < 0x80) {
		out[0] = (uint8_t)cp;
		return 1;
	}
	if (cp < 0x800) {
		out[0] = (uint8_t)(0xC0 | (cp >> 6));
		out[1] = (uint8_t)(0x80 | (cp & 0x3F));
		return 2;
	}
	if (cp >= 0xD800 && cp <= 0xDFFF)
		return 0;		/* 代理码点不编码 */
	if (cp < 0x10000) {
		out[0] = (uint8_t)(0xE0 | (cp >> 12));
		out[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
		out[2] = (uint8_t)(0x80 | (cp & 0x3F));
		return 3;
	}
	if (cp > 0x10FFFF)
		return 0;
	out[0] = (uint8_t)(0xF0 | (cp >> 18));
	out[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
	out[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
	out[3] = (uint8_t)(0x80 | (cp & 0x3F));
	return 4;
}

/* ---- 区间表（闭区间 [lo,hi]，升序，线性扫——表 <80 项，够快） ---- */
struct u32range {
	uint32_t lo, hi;
};

/* 组合/零宽（跟前） */
static const struct u32range comb_tbl[] = {
	{0x0300, 0x036F}, {0x0483, 0x0489}, {0x0591, 0x05BD}, {0x05BF, 0x05BF},
	{0x05C1, 0x05C2}, {0x05C4, 0x05C5}, {0x05C7, 0x05C7}, {0x0610, 0x061A},
	{0x064B, 0x065F}, {0x0670, 0x0670}, {0x06D6, 0x06DC}, {0x06DF, 0x06E4},
	{0x06E7, 0x06E8}, {0x06EA, 0x06ED}, {0x0711, 0x0711}, {0x0730, 0x074A},
	{0x07A6, 0x07B0}, {0x07EB, 0x07F3}, {0x0816, 0x0819}, {0x081B, 0x0823},
	{0x0825, 0x0827}, {0x0829, 0x082D}, {0x0900, 0x0903}, {0x093A, 0x093C},
	{0x093E, 0x094D}, {0x0951, 0x0957}, {0x0962, 0x0963}, {0x0E31, 0x0E31},
	{0x0E34, 0x0E3A}, {0x0E47, 0x0E4E}, {0x1AB0, 0x1AFF}, {0x1DC0, 0x1DFF},
	{0x200B, 0x200F}, {0x2028, 0x202E}, {0x2060, 0x206F}, {0x20D0, 0x20F0},
	{0xFE00, 0xFE0F}, {0xFE20, 0xFE2F}, {0xFEFF, 0xFEFF},
	{0xE0100, 0xE01EF},		/* 变体选择符补充区 */
};

/* 双宽（East Asian Wide/Fullwidth 简化段 + emoji 主区块） */
static const struct u32range wide_tbl[] = {
	{0x1100, 0x115F},		/* 谚文 Jamo */
	{0x2E80, 0x303E},		/* CJK 部首补充~CJK 符号（303F 起为窄） */
	{0x3041, 0x33FF},		/* 假名~CJK 兼容 */
	{0x3400, 0x4DBF},		/* CJK 扩展 A */
	{0x4E00, 0x9FFF},		/* CJK 统一表意 */
	{0xA000, 0xA4CF},		/* 彝文 */
	{0xA960, 0xA97F},		/* 谚文 Jamo 扩展 A */
	{0xAC00, 0xD7A3},		/* 谚文音节 */
	{0xF900, 0xFAFF},		/* CJK 兼容表意 */
	{0xFE10, 0xFE19},		/* 竖排形式 */
	{0xFE30, 0xFE6F},		/* CJK 兼容形式/小写变体 */
	{0xFF00, 0xFF60},		/* 全角形式 */
	{0xFFE0, 0xFFE6},		/* 全角符号 */
	{0x16FE0, 0x16FE4}, {0x17000, 0x187F7}, {0x18800, 0x18AFF},
	{0x1B000, 0x1B2FB},
	{0x1F004, 0x1F004}, {0x1F0CF, 0x1F0CF}, {0x1F18E, 0x1F18E},
	{0x1F191, 0x1F19A},
	{0x1F200, 0x1F320},		/* 围绕字母数字~部分 emoji */
	{0x1F32D, 0x1F335}, {0x1F337, 0x1F37C}, {0x1F37E, 0x1F393},
	{0x1F3A0, 0x1F3CA}, {0x1F3CF, 0x1F3D3}, {0x1F3E0, 0x1F3F0},
	{0x1F3F4, 0x1F3F4}, {0x1F3F8, 0x1F43E}, {0x1F440, 0x1F440},
	{0x1F442, 0x1F4FC}, {0x1F4FF, 0x1F53D}, {0x1F54B, 0x1F54E},
	{0x1F550, 0x1F567}, {0x1F57A, 0x1F57A}, {0x1F595, 0x1F596},
	{0x1F5A4, 0x1F5A4}, {0x1F5FB, 0x1F64F}, {0x1F680, 0x1F6FF},
	{0x1F6D0, 0x1F6D2}, {0x1F6EB, 0x1F6EC}, {0x1F6F4, 0x1F6FC},
	{0x1F7E0, 0x1F7EB},
	{0x1F900, 0x1F9FF},		/* 表情符号补充 */
	{0x1FA00, 0x1FAFF},		/* 符号和扩展 A */
	{0x20000, 0x2FFFD},		/* CJK 扩展 B~F */
	{0x30000, 0x3FFFD},		/* CJK 扩展 G~H */
};

static int in_tbl(uint32_t cp, const struct u32range *t, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		if (cp < t[i].lo)
			return 0;	/* 升序，可早退 */
		if (cp <= t[i].hi)
			return 1;
	}
	return 0;
}

int tui_wcwidth(uint32_t cp)
{
	if (cp == 0)
		return 0;
	if (cp < 0x20 || (cp >= 0x7F && cp < 0xA0))
		return 0;		/* C0/C1 控制 */
	if (in_tbl(cp, comb_tbl, sizeof(comb_tbl) / sizeof(comb_tbl[0])))
		return 0;
	if (in_tbl(cp, wide_tbl, sizeof(wide_tbl) / sizeof(wide_tbl[0])))
		return 2;
	return 1;
}

int tui_is_combining(uint32_t cp)
{
	if (cp < 0x20 || (cp >= 0x7F && cp < 0xA0))
		return 0;		/* 控制符不算组合符 */
	return in_tbl(cp, comb_tbl, sizeof(comb_tbl) / sizeof(comb_tbl[0]));
}

/* ---- LT-BUG-005：显示列安全截断（公共原语；头注见 tui_utf8.h） ---- */

size_t tui_utf8_cols(const char *s)
{
	size_t i = 0, len, w = 0;

	if (!s)
		return 0;
	len = strlen(s);
	while (i < len) {
		uint32_t cp;
		size_t adv = 0;
		int gw;

		if (tui_utf8_decode((const uint8_t *)s + i, len - i, &cp,
				    &adv) != TUI_U8_OK || adv == 0)
			adv = 1;
		gw = tui_wcwidth(cp);
		w += gw > 0 ? (size_t)gw : 1;
		i += adv;
	}
	return w;
}

size_t tui_utf8_clip_cols(const char *src, size_t maxcols, char *dst,
			  size_t dstcap)
{
	size_t i = 0, o = 0, len;
	size_t w = 0;

	if (!dst || dstcap == 0)
		return 0;
	dst[0] = '\0';
	if (!src || maxcols == 0)
		return 0;
	len = strlen(src);
	while (i < len) {
		uint32_t cp;
		size_t adv = 0;
		int gw;

		if (tui_utf8_decode((const uint8_t *)src + i, len - i, &cp,
				    &adv) != TUI_U8_OK || adv == 0)
			adv = 1;
		gw = tui_wcwidth(cp);
		if (gw < 0)
			gw = 0;
		if (w + (size_t)gw > maxcols - 1) {
			/* 留末列给 …（与旧 tv_clip_cols 口径一致）；
			 * cap 放不下 … 时只截正文（仍保证 NUL 结尾） */
			if (o + 4 <= dstcap) {
				memcpy(dst + o, "\xe2\x80\xa6", 3);
				o += 3;
			}
			dst[o] = '\0';
			return o;
		}
		if (o + adv + 1 > dstcap)
			break;
		memcpy(dst + o, src + i, adv);
		o += adv;
		w += (size_t)gw;
		i += adv;
	}
	dst[o] = '\0';
	return o;
}

/* ---- B7：简化 grapheme 续接判定（头注见 tui_utf8.h） ---- */

#define TUI_IS_RI(cp) ((cp) >= 0x1F1E6 && (cp) <= 0x1F1FF)	/* 旗帜 RI */

int tui_graph_feed(tui_gph_st *st, uint32_t cp, int wc)
{
	int act = TUI_GPH_START;

	if (st->join) {
		/* ZWJ 后：下一码点并入（含基字符）；再遇 ZWJ 维持 join */
		st->prev = cp;
		st->join = (cp == 0x200D);
		st->ri = 0;
		return TUI_GPH_EXTEND;
	}
	if (cp == 0x200D) {			/* ZWJ：并入 + 联结下一码点 */
		st->prev = cp;
		st->join = 1;
		st->ri = 0;
		return TUI_GPH_EXTEND;
	}
	if (cp >= 0x1F3FB && cp <= 0x1F3FF) {	/* 肤色修饰符并入 */
		act = TUI_GPH_EXTEND;
	} else if (cp == 0xFE0F) {		/* VS16：emoji 呈现=宽 2 */
		act = TUI_GPH_BUMP;
	} else if (TUI_IS_RI(cp)) {
		/* 旗帜：偶数位 RI 起对（START，单枚按窄字母 1 列），奇数位
		 * 闭合（BUMP：RI 对=终端 2 列——复用 VS16 的 1→2 机制） */
		st->ri++;
		st->prev = cp;
		return (st->ri & 1) ? TUI_GPH_START : TUI_GPH_BUMP;
	} else if (wc == 0 && tui_is_combining(cp)) {
		act = TUI_GPH_EXTEND;		/* 常规组合符并入 */
	}
	st->prev = cp;
	st->ri = 0;
	return act;
}
