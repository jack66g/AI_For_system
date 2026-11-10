/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_sidebar.c - occ TUI 会话侧栏实现（T9c2 最小版）
 *
 * 单行文本直接 tui_screen_put（栏宽 22 内，超长由 put 在栏缘截断——
 * 侧栏右缘==栏宽-1，put 的屏幕边缘截断不适用，这里手工截到 w 列）。
 * id 显示：ses_XXXX…（前 8 字符+…）；标题截到剩余宽。
 */
#define _DEFAULT_SOURCE 1
#include "tui_sidebar.h"

#include <stdio.h>
#include <string.h>

#include "tui_utf8.h"

/* 12345 → "12.3k"；≥1e6 → "12.3M" */
static void fmt_tok(long long t, char *buf, size_t cap)
{
	if (t >= 1000000)
		snprintf(buf, cap, "%.1fM", (double)t / 1000000.0);
	else if (t >= 1000)
		snprintf(buf, cap, "%.1fk", (double)t / 1000.0);
	else
		snprintf(buf, cap, "%lld", t);
}

/* 截字符串到 maxw 显示列（超宽末尾加 …）；返回写入字节数（含 NUL） */
static size_t clip_cols(const char *s, int maxw, char *out, size_t cap)
{
	size_t i = 0;
	int w = 0;
	size_t o = 0;

	if (cap == 0)
		return 0;
	out[0] = '\0';
	while (s[i]) {
		uint32_t cp;
		size_t adv = 0;
		int gw;

		if (tui_utf8_decode((const uint8_t *)s + i, strlen(s + i),
				    &cp, &adv) != TUI_U8_OK || adv == 0)
			adv = 1;
		gw = tui_wcwidth(cp);
		if (gw < 0)
			gw = 0;
		if (w + gw > maxw - 1) {	/* 留列给 … */
			if (o + 4 <= cap) {
				memcpy(out + o, "…", 3);
				o += 3;
				out[o] = '\0';
			}
			return o + 1;
		}
		if (o + adv + 1 > cap)
			break;
		memcpy(out + o, s + i, adv);
		o += adv;
		w += gw;
		i += adv;
	}
	out[o] = '\0';
	return o + 1;
}

void tui_sidebar_render(const tui_sb_data *d, tui_screen *s, int rows,
			const tui_theme *th)
{
	tui_theme loc;
	int y = 0;
	int i;
	char line[TUI_SB_WIDTH * 4];
	char tok[24];
	tui_attr a_title, a_cur, a_dim, a_bottom;

	if (!d || !s || rows < 1)
		return;
	if (!th) {
		tui_theme_default(&loc);
		th = &loc;
	}
	a_title = tui_thm_attr(TUI_THM_ACCENT, TUI_THM_BG, TUI_ST_BOLD);
	/* UXAB：当前行=左标条 ▎(accent) + 亮色文字（fg 加粗）——替旧反白 */
	a_cur = tui_thm_attr(TUI_THM_FG, TUI_THM_BG, TUI_ST_BOLD);
	a_dim = tui_thm_attr(TUI_THM_MUTED, TUI_THM_BG, 0);
	a_bottom = tui_thm_attr(TUI_THM_MUTED, TUI_THM_BG, 0);

	/* 标题行 */
	(void)tui_screen_put(s, 0, 0, "sessions", 8, a_title);
	y = 1;

	for (i = 0; i < d->n && y < rows - 1; i++, y++) {
		const tui_sb_row *r = &d->rows[i];
		char id12[16];
		char rest[TUI_SB_WIDTH * 4];
		char title_clip[TUI_SB_WIDTH * 4];
		int avail;
		tui_attr a = r->is_current ? a_cur : a_dim;

		/* UXAB：当前行首列画 ▎ 标条（accent）；正文右移一列 */
		if (r->is_current) {
			(void)tui_screen_put(s, y, 0, "▎", strlen("▎"),
					     tui_thm_attr(TUI_THM_ACCENT,
							  TUI_THM_BG, 0));
		}
		/* id 前 8 字符（ses_XXXX…） */
		snprintf(id12, sizeof(id12), "%.8s", r->id);
		avail = TUI_SB_WIDTH - 1 - (r->is_current ? 2 : 0) -
			(int)strlen(id12) - 1;
		if (avail < 4)
			avail = 4;
		clip_cols(r->title, avail, title_clip, sizeof(title_clip));
		snprintf(rest, sizeof(rest), "%s %s", id12, title_clip);
		(void)tui_screen_put(s, y, r->is_current ? 1 : 0, rest,
				     strlen(rest), a);
	}

	/* 底部 token 水位行（倒数第 1 行；UXAB：` · ` 分隔） */
	if (rows >= 2) {
		char pct[20];

		fmt_tok(d->tokens_total, tok, sizeof(tok));
		if (d->pct >= 0)
			snprintf(pct, sizeof(pct), " · %d%%", d->pct);
		else
			pct[0] = '\0';
		snprintf(line, sizeof(line), "%s%s", tok, pct);
		(void)tui_screen_put(s, rows - 1, 0, line, strlen(line),
				     a_bottom);
	}
}
