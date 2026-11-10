/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_glyphwidth.c - E 方案字形白名单宽度探针（防退化钉死）
 *
 * 背景：U+2500 系 box-drawing / U+2580 系半块 / U+00B7 / U+2026 属
 * East Asian Ambiguous（UAX #11 A 类）——个别中文终端按 2 列渲染会让
 * 框线错位。L1 libc wcwidth 实测均为 1 列，本套件把断言钉进测试：
 *   ① 白名单每个字符 tui_utf8_cols()==1（且 tui_wcwidth()>=1）；
 *   ② CJK「你」==2（双宽基准）；
 *   ③ 混排探针：`│你│`==4、块头 `▌你 · 16:20`==12、spinner 帧 ⊂ 白名单。
 * 白名单（DESIGN-ANALYSIS §3' 硬约束）：
 *   ─│┌┐└┘├┤┬┴┼（框线）▌▎█（块/滑块）●○◆（点/菱形）↑↓←→ ×·… + ASCII
 */
#define _DEFAULT_SOURCE 1
#include <stdio.h>
#include <string.h>

#include "tui_theme.h"
#include "tui_utf8.h"

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

/* 白名单：UTF-8 字面 + 期望显示列（全部 1） */
static const struct {
	const char *u8;
	const char *name;
} WL[] = {
	{ "─", "U+2500 box-h" },	{ "│", "U+2502 box-v" },
	{ "┌", "U+250C tl" },		{ "┐", "U+2510 tr" },
	{ "└", "U+2514 bl" },		{ "┘", "U+2518 br" },
	{ "├", "U+251C te" },		{ "┤", "U+2524 tw" },
	{ "┬", "U+252C tn" },		{ "┴", "U+2534 ts" },
	{ "┼", "U+253C cross" },
	{ "▌", "U+258C half-l" },	{ "▎", "U+258E quad-l" },
	{ "█", "U+2588 full" },
	{ "●", "U+25CF dot" },		{ "○", "U+25CB circle" },
	{ "◆", "U+25C6 diamond" },
	{ "↑", "U+2191 up" },		{ "↓", "U+2193 down" },
	{ "←", "U+2190 left" },		{ "→", "U+2192 right" },
	{ "×", "U+00D7 times" },	{ "·", "U+00B7 middot" },
	{ "…", "U+2026 ellipsis" },
	{ "A", "ASCII A" },		{ "1", "ASCII 1" },
	{ " ", "ASCII space" },
};

int main(void)
{
	size_t i;

	/* ① 白名单逐字符：显示列恒 1（含 U+2500 系 A 类宽度钉死） */
	for (i = 0; i < sizeof(WL) / sizeof(WL[0]); i++) {
		char nm[64];

		snprintf(nm, sizeof(nm), "wl1 %s", WL[i].name);
		OK(tui_utf8_cols(WL[i].u8) == 1, nm);
	}

	/* ② CJK 双宽基准 */
	OK(tui_utf8_cols("你") == 2, "cjk-ni-cols2");
	OK(tui_utf8_cols("汉字") == 4, "cjk-two-chars-cols4");

	/* ③ 混排探针（框线+CJK+白名单符号不撕行） */
	OK(tui_utf8_cols("│你│") == 4, "probe-box-cjk-box");
	OK(tui_utf8_cols("▌你 · 16:20") == 11, "probe-user-header");
	OK(tui_utf8_cols("◆ mock-model · 16:20") == 20, "probe-assist-header");
	OK(tui_utf8_cols("  ├─ + bash · ls") == 16, "probe-tool-row");

	/* spinner 帧必须落在白名单半块内（零豆腐前提） */
	OK(strcmp(TUI_THM_SPINNER, "█▌▎") == 0,
	   "spinner-frames-whitelisted");
	{
		const char *f = "█▌▎";
		int k;

		for (k = 0; k < 3; k++) {
			char one[4];

			memcpy(one, f + k * 3, 3);
			one[3] = '\0';
			OK(tui_utf8_cols(one) == 1, "spinner-frame-cols1");
		}
	}

	printf("test_glyphwidth: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
