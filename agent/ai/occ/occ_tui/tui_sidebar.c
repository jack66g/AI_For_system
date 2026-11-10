/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_sidebar.c - occ TUI 会话侧栏实现（T9c2 最小版 / T1 视觉升级 / E 面板）
 *
 * 单行文本直接 tui_screen_put（栏宽 22；T1 起正文最多占 21 列——
 * 末列（x=21）留给视图层的分隔线/滚动条）。T1 不再显示 ses_ id：
 * 标题占满内容宽（显示列安全裁剪，CJK 不溢出）；status=error 标题用
 * ERROR 色 + 行尾 ×、interrupted 行尾 …；条数溢出时末行
 * `… +N 个（/sessions）`。
 *
 * E 方案（tui_sidebar_render_panel）：会话列表挪进框线面板（C 形态），
 * 零栏目名/零计数（token/计数一职一地归 footer）——只渲会话行本体
 * （样式沿用 T1：▎当前条 / ×错误 / …中断 / … +N 溢出），rect 由
 * tui_view 的框线原语围出。
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

void tui_sidebar_render(const tui_sb_data *d, tui_screen *s, int rows,
			const tui_theme *th)
{
	tui_theme loc;
	int i;
	char line[TUI_SB_WIDTH * 4];
	char rule[TUI_SB_WIDTH * 3];
	char tok[24];
	tui_attr a_title, a_cur, a_dim, a_bottom, a_err;
	int maxw = TUI_SB_WIDTH - 1;	/* 内容宽（末列留给分隔线） */
	int first, avail, show, overflow;

	if (!d || !s || rows < 1)
		return;
	if (!th) {
		tui_theme_default(&loc);
		th = &loc;
	}
	a_title = tui_thm_attr(TUI_THM_ACCENT, TUI_THM_BG, TUI_ST_BOLD);
	/* 当前行=左标条 ▎(accent) + 亮色文字（fg 加粗） */
	a_cur = tui_thm_attr(TUI_THM_FG, TUI_THM_BG, TUI_ST_BOLD);
	a_dim = tui_thm_attr(TUI_THM_MUTED, TUI_THM_BG, 0);
	a_bottom = tui_thm_attr(TUI_THM_MUTED, TUI_THM_BG, 0);
	a_err = tui_thm_attr(TUI_THM_ERROR, TUI_THM_BG, 0);

	/* 标题行 + dim 细线（T1） */
	(void)tui_screen_put(s, 0, 0, "sessions", 8, a_title);
	for (i = 0; i < maxw; i++)
		memcpy(rule + i * 3, "─", 3);
	if (rows > 1)
		(void)tui_screen_put(s, 1, 0, rule, (size_t)maxw * 3, a_dim);

	/* 会话行：y=2 .. rows-2（末行 rows-1 是 tokens 行） */
	first = 2;
	avail = (rows - 1) - first;
	if (avail < 0)
		avail = 0;
	show = d->n < avail ? d->n : avail;
	overflow = d->total > show;
	if (overflow && avail > 0 && show == avail)
		show = avail - 1;	/* 腾出末行给溢出提示 */

	for (i = 0; i < show; i++) {
		const tui_sb_row *r = &d->rows[i];
		char title_clip[TUI_SB_WIDTH * 4];
		const char *mark = NULL;
		tui_attr a = a_dim;
		int x = 0;
		int tw;

		if (r->is_current) {
			/* 当前行首列画 ▎ 标条（accent）；正文右移一列 */
			(void)tui_screen_put(s, first + i, 0, "▎",
					     strlen("▎"),
					     tui_thm_attr(TUI_THM_ACCENT,
							  TUI_THM_BG, 0));
			a = a_cur;
			x = 1;
		}
		if (!strcmp(r->status, "error")) {
			mark = "×";
			a = a_err;
		} else if (!strcmp(r->status, "interrupted")) {
			mark = "…";
		}
		/* 行尾标记占末列；标题只占其左 */
		tw = maxw - x - (mark ? 1 : 0);
		if (tw < 1)
			tw = 1;
		tui_utf8_clip_cols(r->title, (size_t)tw, title_clip,
				   sizeof(title_clip));
		if (title_clip[0])
			(void)tui_screen_put(s, first + i, x, title_clip,
					     strlen(title_clip), a);
		if (mark)
			(void)tui_screen_put(s, first + i, maxw - 1, mark,
					     strlen(mark), a);
	}

	/* 溢出提示（条数超显示位）：`… +N 个（/sessions）` */
	if (overflow && avail > 0) {
		char ovf[96];
		char clip[96];
		int n;

		n = d->total - show;
		snprintf(ovf, sizeof(ovf), "… +%d 个（/sessions）", n);
		tui_utf8_clip_cols(ovf, (size_t)maxw, clip, sizeof(clip));
		(void)tui_screen_put(s, first + show, 0, clip, strlen(clip),
				     a_bottom);
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

/* ---- E 方案：框线面板内的会话列表（rect=框内净区；零栏目名/零计数） ----
 * 样式沿用 T1（▎当前条 / ×error / …interrupted / … +N 溢出），只显标题、
 * 显示列安全裁剪。溢出提示占列表末位（有余量才画）。 */
void tui_sidebar_render_panel(const tui_sb_data *d, tui_screen *s,
			      int x, int y, int w, int h,
			      const tui_theme *th)
{
	tui_theme loc;
	int i;
	tui_attr a_cur, a_dim, a_bottom, a_err;
	int first, avail, show, overflow;

	if (!d || !s || w < 2 || h < 1)
		return;
	if (!th) {
		tui_theme_default(&loc);
		th = &loc;
	}
	(void)th;
	a_cur = tui_thm_attr(TUI_THM_FG, TUI_THM_BG, TUI_ST_BOLD);
	a_dim = tui_thm_attr(TUI_THM_MUTED, TUI_THM_BG, 0);
	a_bottom = tui_thm_attr(TUI_THM_MUTED, TUI_THM_BG, 0);
	a_err = tui_thm_attr(TUI_THM_ERROR, TUI_THM_BG, 0);

	first = y;
	avail = h;
	show = d->n < avail ? d->n : avail;
	overflow = d->total > show;
	if (overflow && avail > 0 && show == avail)
		show = avail - 1;	/* 腾出末行给溢出提示 */

	for (i = 0; i < show; i++) {
		const tui_sb_row *r = &d->rows[i];
		char title_clip[TUI_SB_WIDTH * 4];
		const char *mark = NULL;
		tui_attr a = a_dim;
		int cx = x;
		int tw;

		if (r->is_current) {
			(void)tui_screen_put(s, first + i, x, "▎",
					     strlen("▎"),
					     tui_thm_attr(TUI_THM_ACCENT,
							  TUI_THM_BG, 0));
			a = a_cur;
			cx = x + 1;
		}
		if (!strcmp(r->status, "error")) {
			mark = "×";
			a = a_err;
		} else if (!strcmp(r->status, "interrupted")) {
			mark = "…";
		}
		tw = (x + w) - cx - (mark ? 1 : 0);
		if (tw < 1)
			tw = 1;
		tui_utf8_clip_cols(r->title, (size_t)tw, title_clip,
				   sizeof(title_clip));
		if (title_clip[0])
			(void)tui_screen_put(s, first + i, cx, title_clip,
					     strlen(title_clip), a);
		if (mark)
			(void)tui_screen_put(s, first + i, x + w - 1, mark,
					     strlen(mark), a);
	}
	if (overflow && avail > 0) {
		char ovf[96];
		char clip[96];
		int n;

		n = d->total - show;
		snprintf(ovf, sizeof(ovf), "… +%d 个（/sessions）", n);
		tui_utf8_clip_cols(ovf, (size_t)w, clip, sizeof(clip));
		(void)tui_screen_put(s, first + show, x, clip, strlen(clip),
				     a_bottom);
	}
}
