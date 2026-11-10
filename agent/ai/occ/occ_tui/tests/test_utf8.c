/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_utf8.c - UTF-8 宽度矩阵 golden 测试（T9c1）
 *
 * 覆盖：中/英/日/emoji/非法序列/组合符六类；解码边界（截断/过长/
 * 代理区/越界）；编码回环；替换符策略。
 */
#include "tui_utf8.h"

#include <stdio.h>
#include <string.h>

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

/* 宽度矩阵：标签、UTF-8 字节、期望宽度 */
struct wcase {
	const char *label;
	const char *utf8;
	int width;
};

static const struct wcase wcases[] = {
	/* 英文/ASCII → 1 */
	{ "ascii-A", "A", 1 },
	{ "ascii-z", "z", 1 },
	{ "ascii-digit", "7", 1 },
	{ "ascii-space", " ", 1 },
	{ "latin1-e-acute-cp", "\xc3\xa9", 1 },	/* é (U+00E9) */
	/* 中文 → 2 */
	{ "cjk-zhong", "\xe4\xb8\xad", 2 },		/* 中 */
	{ "cjk-guo", "\xe5\x9b\xbd", 2 },		/* 国 */
	{ "cjk-fullwidth-excl", "\xef\xbc\x81", 2 },	/* ！U+FF01 */
	/* 日文 → 2 */
	{ "kana-a", "\xe3\x81\x82", 2 },		/* あ */
	{ "kana-ka", "\xe3\x82\xab", 2 },		/* カ */
	{ "kanji-nihon", "\xe6\x97\xa5\xe6\x9c\xac", 2 }, /* 日本（首字） */
	/* 韩文音节 → 2 */
	{ "hangul-han", "\xed\x95\x9c", 2 },		/* 한 */
	/* emoji → 2（主区块，简化表） */
	{ "emoji-grin", "\xf0\x9f\x98\x80", 2 },	/* 😀 U+1F600 */
	{ "emoji-rocket", "\xf0\x9f\x9a\x80", 2 },	/* 🚀 U+1F680 */
	{ "emoji-heart-suit", "\xe2\x9d\xa4", 1 },	/* ❤ U+2764 单码点=1 */
	/* 组合符 → 0 */
	{ "combining-acute", "\xcc\x81", 0 },		/* U+0301 */
	{ "combining-cedilla", "\xcc\xa7", 0 },		/* U+0327 */
	{ "vs16", "\xef\xb8\x8f", 0 },			/* U+FE0F */
	/* 控制符 → 0 */
	{ "ctl-soh", "\x01", 0 },
	{ "ctl-bel", "\x07", 0 },
	{ "ctl-del", "\x7f", 0 },
	/* C1 控制 → 0 */
	{ "c1-0x85", "\xc2\x85", 0 },			/* U+0085 */
	/* 零宽空格/方向标记 → 0 */
	{ "zwsp", "\xe2\x80\x8b", 0 },			/* U+200B */
	{ "lrm", "\xe2\x80\x8e", 0 },			/* U+200E */
	/* 不换行空格 → 1（简化表按普通宽） */
	{ "nbsp", "\xc2\xa0", 1 },
	/* CJK 扩展 A → 2 */
	{ "cjk-extA", "\xe3\x90\x80", 2 },		/* U+3400 */
	/* 全角拉丁 → 2（FF00-FF60 全角形式） */
	{ "fullwidth-A", "\xef\xbc\xa1", 2 },		/* Ａ U+FF21 */
	/* 半角片假名 → 1（FF61-FFDC 半角，不入宽表） */
	{ "halfwidth-katakana", "\xef\xbd\xb1", 1 },	/* ｱ U+FF71 */
};

static int width_of_case(const struct wcase *c)
{
	uint32_t cp;
	size_t adv;
	tui_u8stat st = tui_utf8_decode((const uint8_t *)c->utf8,
					strlen(c->utf8), &cp, &adv);
	if (st != TUI_U8_OK)
		return -1;
	return tui_wcwidth(cp);
}

/* 解码边界用例 */
struct dcase {
	const char *label;
	const char *bytes;
	size_t len;
	tui_u8stat want_st;
	size_t want_adv;
	uint32_t want_cp;	/* 仅 OK 时校验 */
};

static const struct dcase dcases[] = {
	{ "ok-ascii", "A", 1, TUI_U8_OK, 1, 'A' },
	{ "ok-3byte", "\xe4\xb8\xad", 3, TUI_U8_OK, 3, 0x4E2D },
	{ "ok-4byte", "\xf0\x9f\x98\x80", 4, TUI_U8_OK, 4, 0x1F600 },
	{ "ok-2byte", "\xc3\xa9", 2, TUI_U8_OK, 2, 0xE9 },
	{ "trunc-3byte-1b", "\xe4", 1, TUI_U8_NEEDMORE, 1, 0 },
	{ "trunc-3byte-2b", "\xe4\xb8", 2, TUI_U8_NEEDMORE, 2, 0 },
	{ "trunc-4byte-2b", "\xf0\x9f", 2, TUI_U8_NEEDMORE, 2, 0 },
	{ "empty", "", 0, TUI_U8_NEEDMORE, 0, 0 },
	{ "bad-lone-cont", "\x80", 1, TUI_U8_INVALID, 1, 0 },
	{ "bad-cont-first", "\xbf", 1, TUI_U8_INVALID, 1, 0 },
	{ "bad-0xff", "\xff", 1, TUI_U8_INVALID, 1, 0 },
	{ "bad-0xf5", "\xf5\x80\x80\x80", 4, TUI_U8_INVALID, 1, 0 },
	{ "bad-overlong-2", "\xc0\x80", 2, TUI_U8_INVALID, 1, 0 },
	{ "bad-overlong-3", "\xe0\x80\x80", 3, TUI_U8_INVALID, 1, 0 },
	{ "bad-surrogate", "\xed\xa0\x80", 3, TUI_U8_INVALID, 1, 0 },
	{ "bad-too-big", "\xf4\x90\x80\x80", 4, TUI_U8_INVALID, 1, 0 },
	{ "bad-mid-noncont", "\xe4\x28\xad", 3, TUI_U8_INVALID, 1, 0 },
	{ "max-cp", "\xf4\x8f\xbf\xbf", 4, TUI_U8_OK, 4, 0x10FFFF },
};

int main(void)
{
	size_t i;
	uint8_t out[4];

	/* 宽度矩阵 */
	for (i = 0; i < sizeof(wcases) / sizeof(wcases[0]); i++) {
		int w = width_of_case(&wcases[i]);
		char name[96];
		snprintf(name, sizeof(name), "width-%s", wcases[i].label);
		OK(w == wcases[i].width, name);
	}

	/* 解码边界 */
	for (i = 0; i < sizeof(dcases) / sizeof(dcases[0]); i++) {
		const struct dcase *d = &dcases[i];
		uint32_t cp = 0;
		size_t adv = 0;
		tui_u8stat st = tui_utf8_decode((const uint8_t *)d->bytes,
						d->len, &cp, &adv);
		char name[96];
		snprintf(name, sizeof(name), "decode-%s", d->label);
		if (st == TUI_U8_OK && d->want_st == TUI_U8_OK)
			OK(st == d->want_st && adv == d->want_adv &&
			   cp == d->want_cp, name);
		else
			OK(st == d->want_st && adv == d->want_adv, name);
	}

	/* 编码回环 */
	OK(tui_utf8_encode(0x4E2D, out) == 3 &&
	   memcmp(out, "\xe4\xb8\xad", 3) == 0, "encode-zhong");
	OK(tui_utf8_encode('A', out) == 1 && out[0] == 'A', "encode-ascii");
	OK(tui_utf8_encode(0x1F600, out) == 4 &&
	   memcmp(out, "\xf0\x9f\x98\x80", 4) == 0, "encode-emoji");
	OK(tui_utf8_encode(0xD800, out) == 0, "encode-surrogate-rejected");
	OK(tui_utf8_encode(0x110000, out) == 0, "encode-out-of-range");

	/* 解码→编码回环（抽样） */
	{
		uint32_t cp;
		size_t adv;
		OK(tui_utf8_decode((const uint8_t *)"\xe4\xb8\xad", 3, &cp,
				   &adv) == TUI_U8_OK &&
		   tui_utf8_encode(cp, out) == 3 &&
		   memcmp(out, "\xe4\xb8\xad", 3) == 0, "roundtrip-zhong");
	}

	/* 非法序列 → 替换符宽度（U+FFFD 按 1） */
	OK(tui_wcwidth(TUI_REPLACEMENT) == 1, "width-replacement");

	/* seqlen */
	OK(tui_utf8_seqlen('A') == 1, "seqlen-ascii");
	OK(tui_utf8_seqlen(0xE4) == 3, "seqlen-3");
	OK(tui_utf8_seqlen(0xF0) == 4, "seqlen-4");
	OK(tui_utf8_seqlen(0x80) == 0, "seqlen-cont-bad");
	OK(tui_utf8_seqlen(0xF5) == 0, "seqlen-f5-bad");

	/* is_combining */
	OK(tui_is_combining(0x0301) == 1, "combining-yes");
	OK(tui_is_combining(0x4E2D) == 0, "combining-cjk-no");
	OK(tui_is_combining(0x07) == 0, "combining-ctl-no");

	/* ---- B7：grapheme 续接判定（ZWJ/肤色/RI/VS16）----
	 * 现状实测口径：👨‍👩‍👧 逐码点 6 列 vs 终端 2 列（错位撕行）——
	 * EXTEND 收敛为单 grapheme 宽 2；VS16 文本呈现 1 列 vs emoji
	 * 呈现 2 列（反向覆盖）——BUMP 提升前格宽。 */
	{
		tui_gph_st st = {0, 0, 0};

		/* 常规文本：全 START */
		OK(tui_graph_feed(&st, 'a', 1) == TUI_GPH_START, "gph-ascii-start");
		OK(tui_graph_feed(&st, 0x4E2D, 2) == TUI_GPH_START, "gph-cjk-start");
		/* ZWJ → EXTEND + join */
		OK(tui_graph_feed(&st, 0x200D, 0) == TUI_GPH_EXTEND, "gph-zwj-extend");
		/* join 中基字符（👨 1F468）→ EXTEND（宽 0 并入） */
		OK(tui_graph_feed(&st, 0x1F468, 2) == TUI_GPH_EXTEND, "gph-zwj-join-base");
		/* join 后新基字符恢复 START */
		OK(tui_graph_feed(&st, 0x1F469, 2) == TUI_GPH_START, "gph-after-join-start");
		/* 连串 ZWJ：👨 ZWJ 👩 ZWJ 👧 → 全并入首 grapheme */
		{
			tui_gph_st s2 = {0, 0, 0};
			uint32_t fam[] = { 0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467 };
			int exp[] = { TUI_GPH_START, TUI_GPH_EXTEND, TUI_GPH_EXTEND,
				      TUI_GPH_EXTEND, TUI_GPH_EXTEND };
			int i, all = 1;

			for (i = 0; i < 5; i++) {
				int act = tui_graph_feed(&s2, fam[i],
							 tui_wcwidth(fam[i]));
				if (act != exp[i])
					all = 0;
			}
			OK(all, "gph-family-zwj-collapse");
		}
		/* 肤色修饰（1F3FB-1F3FF）→ EXTEND */
		{
			tui_gph_st s3 = {0, 0, 0};

			(void)tui_graph_feed(&s3, 0x1F44B, 2);	/* 👋 */
			OK(tui_graph_feed(&s3, 0x1F3FD, 1) == TUI_GPH_EXTEND,
			   "gph-skin-modifier");
		}
		/* 旗帜对：RI+RI → 第二枚 BUMP（1→2 列）；第三枚起新对 */
		{
			tui_gph_st s4 = {0, 0, 0};

			OK(tui_graph_feed(&s4, 0x1F1E8, 1) == TUI_GPH_START,
			   "gph-flag-first-start");	/* C */
			OK(tui_graph_feed(&s4, 0x1F1F3, 1) == TUI_GPH_BUMP,
			   "gph-flag-ri-pair");		/* N 闭合对 → 提宽 2 */
			OK(tui_graph_feed(&s4, 0x1F1E8, 1) == TUI_GPH_START,
			   "gph-third-ri-start");	/* 新对起点 */
			OK(tui_graph_feed(&s4, 0x1F1F3, 1) == TUI_GPH_BUMP,
			   "gph-fourth-ri-bump");
		}
		/* VS16 → BUMP；前格宽 2 时调用方降级 EXTEND（动作仍 BUMP） */
		{
			tui_gph_st s5 = {0, 0, 0};

			(void)tui_graph_feed(&s5, 0x270C, 1);	/* ✌ */
			OK(tui_graph_feed(&s5, 0xFE0F, 0) == TUI_GPH_BUMP,
			   "gph-vs16-bump");
		}
		/* 常规组合符 → EXTEND（既有行为不变） */
		{
			tui_gph_st s6 = {0, 0, 0};

			(void)tui_graph_feed(&s6, 'e', 1);
			OK(tui_graph_feed(&s6, 0x0301, 0) == TUI_GPH_EXTEND,
			   "gph-combining-extend");
		}
		/* keycap：'1' FE0F 20E3 → VS16 BUMP + 组合 EXTEND（2 列） */
		{
			tui_gph_st s7 = {0, 0, 0};

			(void)tui_graph_feed(&s7, '1', 1);
			OK(tui_graph_feed(&s7, 0xFE0F, 0) == TUI_GPH_BUMP,
			   "gph-keycap-vs16");
			OK(tui_graph_feed(&s7, 0x20E3, 0) == TUI_GPH_EXTEND,
			   "gph-keycap-combining");
		}
	}

	/* ---- T1/LT-BUG-005：显示列安全截断 + 列宽统计 ---- */
	{
		char b[64];
		size_t n;

		OK(tui_utf8_cols("abc") == 3, "clip-cols-ascii");
		OK(tui_utf8_cols("\xe4\xb8\xad\xe6\x96\x87") == 4,
		   "clip-cols-cjk");		/* 中文 = 2×2 */
		OK(tui_utf8_cols(NULL) == 0, "clip-cols-null");

		n = tui_utf8_clip_cols("abcdef", 10, b, sizeof(b));
		OK(n == 6 && strcmp(b, "abcdef") == 0, "clip-fits");
		n = tui_utf8_clip_cols("abcdef", 4, b, sizeof(b));
		OK(n == 6 && strcmp(b, "abc\xe2\x80\xa6") == 0,
		   "clip-ellipsis");		/* abc… */
		/* CJK 双宽：不切半个汉字（3 列只能放 1 个汉字 + …） */
		n = tui_utf8_clip_cols("\xe4\xb8\xad\xe6\x96\x87", 3, b,
				       sizeof(b));
		OK(strcmp(b, "\xe4\xb8\xad\xe2\x80\xa6") == 0, "clip-cjk-safe");
		/* cap 不足以放 … 时只截正文、不越界 */
		n = tui_utf8_clip_cols("abcdef", 4, b, 4);
		OK(n <= 3 && strlen(b) <= 3, "clip-cap-guard");
		OK(tui_utf8_clip_cols("abc", 0, b, sizeof(b)) == 0 &&
		   b[0] == '\0', "clip-zero-cols");
	}

	printf("test_utf8: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
