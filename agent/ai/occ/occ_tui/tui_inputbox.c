/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_inputbox.c - occ TUI 输入框实现（T9c2）
 *
 * 单字节缓冲 + 字节游标；键事件消费见 tui_inputbox.h 头注。
 * 渲染：逻辑行切分 → 含光标尾部窗口 → 光标行横向偏移（grapheme 边界
 * 对齐，保光标列在 [0,w-1]）→ tui_screen_put（区域右缘==屏幕右缘约定，
 * 由 tui_screen_put 在屏幕边缘自然截断；双宽字不撕半格）。
 */
#define _DEFAULT_SOURCE 1
#include "tui_inputbox.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tui_utf8.h"

/* 15 条内置 slash 命令（OPENCODE-PLAN §5；Tab 补全与 /help 同源） */
static const char *const IB_CMDS[] = {
	"/models", "/new", "/sessions", "/rename", "/delete", "/clear", "/help",
	"/exit", "/status", "/tools", "/sandbox", "/trace", "/lease",
	"/compact", "/shell"
};
#define IB_NCMDS ((int)(sizeof(IB_CMDS) / sizeof(IB_CMDS[0])))

struct tui_inputbox {
	tui_theme th;
	char *buf;			/* NUL 结尾 */
	size_t len, cap;
	size_t cur;			/* 字节游标 [0..len] */
	/* 会话级历史 */
	char **hist;
	int nhist, hcap;
	int browse;			/* -1=未浏览；否则 hist 下标 */
	char *draft;			/* 进入浏览时的草稿（heap） */
	size_t draft_len;
	int last_cr;			/* 粘贴中刚插过 \r：下一 \n 跳过（\r\n 归一） */
};

const char *const *tui_inputbox_cmds(int *count)
{
	if (count)
		*count = IB_NCMDS;
	return IB_CMDS;
}

/* ---- 缓冲原语 ---- */

static int ib_reserve(tui_inputbox *ib, size_t need)
{
	if (need + 1 <= ib->cap)
		return 0;
	{
		size_t nc = ib->cap ? ib->cap : 128;
		char *nb;

		while (nc < need + 1)
			nc *= 2;
		nb = realloc(ib->buf, nc);
		if (!nb)
			return -1;
		ib->buf = nb;
		ib->cap = nc;
	}
	return 0;
}

/* 在游标处插入 n 字节（UTF-8 序列）；失败返回 -1 */
static int ib_insert(tui_inputbox *ib, const char *s, size_t n)
{
	if (n == 0)
		return 0;
	if (ib_reserve(ib, ib->len + n) != 0)
		return -1;
	memmove(ib->buf + ib->cur + n, ib->buf + ib->cur,
		ib->len - ib->cur);
	memcpy(ib->buf + ib->cur, s, n);
	ib->cur += n;
	ib->len += n;
	ib->buf[ib->len] = '\0';
	ib->browse = -1;		/* 编辑即脱离历史浏览 */
	return 0;
}

/* 删游标前一个 grapheme（跨行：删 '\n' 连接两行） */
static void ib_backspace(tui_inputbox *ib)
{
	size_t start;

	if (ib->cur == 0)
		return;
	start = ib->cur - 1;
	while (start > 0 && ((unsigned char)ib->buf[start] & 0xC0) == 0x80)
		start--;
	memmove(ib->buf + start, ib->buf + ib->cur, ib->len - ib->cur);
	ib->len -= ib->cur - start;
	ib->cur = start;
	ib->buf[ib->len] = '\0';
	ib->browse = -1;
}

/* 删游标处一个 grapheme */
static void ib_delete(tui_inputbox *ib)
{
	size_t n;

	if (ib->cur >= ib->len)
		return;
	n = tui_utf8_seqlen((uint8_t)ib->buf[ib->cur]);
	if (n <= 0)
		n = 1;
	if (ib->cur + n > ib->len)
		n = ib->len - ib->cur;
	memmove(ib->buf + ib->cur, ib->buf + ib->cur + n,
		ib->len - ib->cur - n);
	ib->len -= n;
	ib->buf[ib->len] = '\0';
	ib->browse = -1;
}

/* ---- 行/列定位 ---- */

static size_t ib_line_start(const tui_inputbox *ib, size_t pos)
{
	while (pos > 0 && ib->buf[pos - 1] != '\n')
		pos--;
	return pos;
}

static size_t ib_line_end(const tui_inputbox *ib, size_t pos)
{
	while (pos < ib->len && ib->buf[pos] != '\n')
		pos++;
	return pos;
}

/* [from,to) 的显示宽度 */
static int ib_width(const tui_inputbox *ib, size_t from, size_t to)
{
	int w = 0;

	while (from < to) {
		uint32_t cp;
		size_t adv = 0;
		int gw;

		if (tui_utf8_decode((const uint8_t *)ib->buf + from,
				    to - from, &cp, &adv) != TUI_U8_OK ||
		    adv == 0)
			adv = 1;
		gw = tui_wcwidth(cp);
		w += (gw > 0) ? gw : 0;
		from += adv;
	}
	return w;
}

/* 游标显示列（所在行内） */
static int ib_cursor_col(const tui_inputbox *ib)
{
	return ib_width(ib, ib_line_start(ib, ib->cur), ib->cur);
}

static int ib_cursor_line(const tui_inputbox *ib)
{
	int ln = 0;
	size_t i;

	for (i = 0; i < ib->cur; i++)
		if (ib->buf[i] == '\n')
			ln++;
	return ln;
}

/* 目标行内走显示列 col（截断到行尾字节偏移） */
static size_t ib_col_to_pos(const tui_inputbox *ib, size_t lstart,
			    size_t lend, int col)
{
	size_t p = lstart;
	int w = 0;

	while (p < lend) {
		uint32_t cp;
		size_t adv = 0;
		int gw;

		if (tui_utf8_decode((const uint8_t *)ib->buf + p,
				    lend - p, &cp, &adv) != TUI_U8_OK ||
		    adv == 0)
			adv = 1;
		gw = tui_wcwidth(cp);
		if (gw <= 0)
			gw = 0;
		if (w + gw > col)
			break;
		w += gw;
		p += adv;
	}
	return p;
}

/* ---- 历史 ---- */

static void ib_hist_push(tui_inputbox *ib)
{
	if (ib->len == 0)
		return;
	if (ib->nhist > 0 && !strcmp(ib->hist[ib->nhist - 1], ib->buf))
		return;			/* 连续重复不入 */
	if (ib->nhist == ib->hcap) {
		int nc = ib->hcap ? ib->hcap * 2 : 16;
		char **nv = realloc(ib->hist, (size_t)nc * sizeof(char *));

		if (!nv)
			return;
		ib->hist = nv;
		ib->hcap = nc;
	}
	ib->hist[ib->nhist] = strdup(ib->buf);
	if (!ib->hist[ib->nhist])
		return;
	ib->nhist++;
}

static void ib_hist_load(tui_inputbox *ib, const char *s)
{
	size_t n = strlen(s);

	if (ib_reserve(ib, n) != 0)
		return;
	memcpy(ib->buf, s, n + 1);
	ib->len = n;
	ib->cur = n;
}

static void ib_hist_up(tui_inputbox *ib)
{
	if (ib->nhist == 0)
		return;
	if (ib->browse < 0) {
		free(ib->draft);
		ib->draft = malloc(ib->len + 1);
		if (!ib->draft)
			return;
		memcpy(ib->draft, ib->buf, ib->len + 1);
		ib->draft_len = ib->len;
		ib->browse = ib->nhist - 1;
	} else if (ib->browse > 0) {
		ib->browse--;
	} else {
		return;
	}
	ib_hist_load(ib, ib->hist[ib->browse]);
}

static void ib_hist_down(tui_inputbox *ib)
{
	if (ib->browse < 0)
		return;
	ib->browse++;
	if (ib->browse >= ib->nhist) {
		ib->browse = -1;
		if (ib->draft)
			ib_hist_load(ib, ib->draft);
		return;
	}
	ib_hist_load(ib, ib->hist[ib->browse]);
}

/* ---- Tab 补全（斜杠首 token 前缀） ---- */

static void ib_complete(tui_inputbox *ib)
{
	size_t tokend;
	const char *prefix;
	size_t plen;
	int i, nmatch = 0;
	int first = -1;
	char common[64];
	size_t clen = 0;

	if (ib->len == 0 || ib->buf[0] != '/')
		return;
	tokend = 0;
	while (tokend < ib->len && ib->buf[tokend] != ' ' &&
	       ib->buf[tokend] != '\n')
		tokend++;
	if (ib->cur > tokend)
		return;			/* 光标已过首 token */
	prefix = ib->buf;
	plen = tokend;
	common[0] = '\0';
	for (i = 0; i < IB_NCMDS; i++) {
		if (strncmp(IB_CMDS[i], prefix, plen) != 0)
			continue;
		if (nmatch == 0) {
			first = i;
			snprintf(common, sizeof(common), "%s", IB_CMDS[i]);
			clen = strlen(common);
		} else {
			size_t k = 0;

			while (k < clen && common[k] == IB_CMDS[i][k])
				k++;
			clen = k;
			common[k] = '\0';
		}
		nmatch++;
	}
	if (nmatch == 0)
		return;
	if (nmatch == 1) {
		const char *m = IB_CMDS[first];
		size_t ml = strlen(m);
		char tmp[80];

		if (ml + 2 > sizeof(tmp))
			return;
		memcpy(tmp, m, ml);
		tmp[ml] = ' ';
		tmp[ml + 1] = '\0';
		/* 替换 [0,tokend) → "cmd " */
		{
			size_t tail = ib->len - tokend;

			if (ib_reserve(ib, ml + 1 + tail) != 0)
				return;
			memmove(ib->buf + ml + 1, ib->buf + tokend, tail + 1);
			memcpy(ib->buf, tmp, ml + 1);
			ib->len = ml + 1 + tail;
			ib->cur = ml + 1;
			ib->buf[ib->len] = '\0';
		}
		return;
	}
	/* 多命中：扩公共前缀（须比现 token 长） */
	if (clen > plen && clen < sizeof(common)) {
		size_t tail = ib->len - tokend;

		if (ib_reserve(ib, clen + tail) != 0)
			return;
		memmove(ib->buf + clen, ib->buf + tokend, tail + 1);
		memcpy(ib->buf, common, clen);
		ib->len = clen + tail;
		ib->cur = clen;
		ib->buf[ib->len] = '\0';
	}
}

/* ---- 构造/析构 ---- */

tui_inputbox *tui_inputbox_create(const tui_theme *th)
{
	tui_inputbox *ib = calloc(1, sizeof(*ib));

	if (!ib)
		return NULL;
	if (th)
		ib->th = *th;
	else
		tui_theme_default(&ib->th);
	ib->browse = -1;
	if (ib_reserve(ib, 128) != 0) {
		free(ib);
		return NULL;
	}
	ib->buf[0] = '\0';
	return ib;
}

void tui_inputbox_destroy(tui_inputbox *ib)
{
	int i;

	if (!ib)
		return;
	for (i = 0; i < ib->nhist; i++)
		free(ib->hist[i]);
	free(ib->hist);
	free(ib->draft);
	free(ib->buf);
	free(ib);
}

const char *tui_inputbox_text(const tui_inputbox *ib, size_t *len_out)
{
	if (len_out)
		*len_out = ib ? ib->len : 0;
	return ib ? ib->buf : "";
}

void tui_inputbox_clear(tui_inputbox *ib)
{
	if (!ib)
		return;
	ib->len = 0;
	ib->cur = 0;
	ib->buf[0] = '\0';
	ib->browse = -1;
}

int tui_inputbox_empty(const tui_inputbox *ib)
{
	return !ib || ib->len == 0;
}

int tui_inputbox_lines(const tui_inputbox *ib)
{
	int n = 1;
	size_t i;

	if (!ib)
		return 1;
	for (i = 0; i < ib->len; i++)
		if (ib->buf[i] == '\n')
			n++;
	return n;
}

/* ---- 键事件 ---- */

int tui_inputbox_key(tui_inputbox *ib, const tui_event *ev)
{
	if (!ib || !ev || ev->type != TUI_EV_KEY)
		return TUI_IN_NONE;

	switch (ev->key) {
	case TUI_KEY_RETURN:
		if (ev->mods & (TUI_MOD_SHIFT | TUI_MOD_CTRL | TUI_MOD_ALT)) {
			(void)ib_insert(ib, "\n", 1);
			return TUI_IN_NONE;
		}
		if (ib->len == 0)
			return TUI_IN_NONE;	/* 空回车忽略 */
		ib_hist_push(ib);
		ib->browse = -1;
		return TUI_IN_SUBMIT;
	case TUI_KEY_BACKSPACE:
		ib_backspace(ib);
		return TUI_IN_NONE;
	case TUI_KEY_DELETE:
		ib_delete(ib);
		return TUI_IN_NONE;
	case TUI_KEY_LEFT:
		if (ib->cur > 0) {
			size_t p = ib->cur - 1;

			while (p > 0 &&
			       ((unsigned char)ib->buf[p] & 0xC0) == 0x80)
				p--;
			ib->cur = p;
		}
		return TUI_IN_NONE;
	case TUI_KEY_RIGHT:
		if (ib->cur < ib->len) {
			int n = tui_utf8_seqlen((uint8_t)ib->buf[ib->cur]);

			if (n <= 0)
				n = 1;
			ib->cur += (size_t)n;
			if (ib->cur > ib->len)
				ib->cur = ib->len;
		}
		return TUI_IN_NONE;
	case TUI_KEY_HOME:
		ib->cur = ib_line_start(ib, ib->cur);
		return TUI_IN_NONE;
	case TUI_KEY_END:
		ib->cur = ib_line_end(ib, ib->cur);
		return TUI_IN_NONE;
	case TUI_KEY_UP:
		if (ib_cursor_line(ib) == 0)
			ib_hist_up(ib);
		else {
			size_t ls = ib_line_start(ib, ib->cur);
			size_t ps, pe;
			int col = ib_cursor_col(ib);

			if (ls == 0)
				return TUI_IN_NONE;
			ps = ib_line_start(ib, ls - 1);
			pe = ls - 1;	/* 前一行不含 '\n' */
			ib->cur = ib_col_to_pos(ib, ps, pe, col);
		}
		return TUI_IN_NONE;
	case TUI_KEY_DOWN: {
		size_t le = ib_line_end(ib, ib->cur);
		int col = ib_cursor_col(ib);

		if (le >= ib->len) {
			/* 末行：历史 next（光标在末行才翻） */
			ib_hist_down(ib);
			return TUI_IN_NONE;
		}
		/* 下一行（跳过 '\n'） */
		{
			size_t ns = le + 1;
			size_t ne = ib_line_end(ib, ns);

			ib->cur = ib_col_to_pos(ib, ns, ne, col);
		}
		return TUI_IN_NONE;
	}
	case TUI_KEY_TAB:
		ib_complete(ib);
		return TUI_IN_NONE;
	case TUI_KEY_PAGEUP:
		return TUI_IN_SCROLL_UP;
	case TUI_KEY_PAGEDOWN:
		return TUI_IN_SCROLL_DOWN;
	case TUI_KEY_CHAR: {
		if (ev->mods & TUI_MOD_CTRL) {
			if (ev->ch == 'c' || ev->ch == 'd') {
				if (ib->len == 0)
					return TUI_IN_EXIT;
				tui_inputbox_clear(ib);
				return TUI_IN_CLEAR;
			}
			if (ev->ch == 'j') {	/* ctrl+j = 换行 */
				(void)ib_insert(ib, "\n", 1);
				return TUI_IN_NONE;
			}
			return TUI_IN_NONE;	/* 其余 ctrl 组合忽略 */
		}
		if (ev->mods & (TUI_MOD_ALT | TUI_MOD_SUPER))
			return TUI_IN_NONE;	/* alt/super 组合：本棒不接 */
		if (ev->paste) {
			/* 原样入缓冲：\r\n→单\n、\t→空格、其余控制字节丢 */
			if (ev->ch == '\r') {
				ib->last_cr = 1;
				return ib_insert(ib, "\n", 1), TUI_IN_NONE;
			}
			if (ev->ch == '\n') {
				if (ib->last_cr) {	/* \r\n 归一 */
					ib->last_cr = 0;
					return TUI_IN_NONE;
				}
				return ib_insert(ib, "\n", 1), TUI_IN_NONE;
			}
			ib->last_cr = 0;
			if (ev->ch == '\t')
				return ib_insert(ib, " ", 1), TUI_IN_NONE;
			if (ev->ch < 0x20 || ev->ch == 0x7f)
				return TUI_IN_NONE;
		}
		{
			uint8_t u[4];
			size_t n = tui_utf8_encode(ev->ch, u);

			if (n == 0)
				return TUI_IN_NONE;
			(void)ib_insert(ib, (const char *)u, n);
		}
		return TUI_IN_NONE;
	}
	default:
		return TUI_IN_NONE;
	}
}

/* ---- 渲染 ---- */

/* 从行首走到显示宽度达到 hoff 的首个 grapheme 边界；返回边界字节偏移，
 * *wout 累计宽度（光标列换算用）。 */
static size_t ib_skip_to_hoff(const tui_inputbox *ib, size_t from, size_t to,
			      int hoff, int *wout)
{
	size_t q = from;
	int rw = 0;

	while (q < to && rw < hoff) {
		uint32_t cp;
		size_t adv = 0;
		int gw;

		if (tui_utf8_decode((const uint8_t *)ib->buf + q, to - q,
				    &cp, &adv) != TUI_U8_OK || adv == 0)
			adv = 1;
		gw = tui_wcwidth(cp);
		rw += (gw > 0) ? gw : 0;
		q += adv;
	}
	if (wout)
		*wout = rw;
	return q;
}

void tui_inputbox_render(const tui_inputbox *ib, tui_screen *s,
			 int x, int y, int w, int h,
			 int *cur_row, int *cur_col)
{
	int nlines, cline, top, i, ccol, hoff, rw = 0;
	size_t p;
	tui_attr a;

	if (!ib || !s || w < 1 || h < 1)
		return;
	a = tui_thm_attr(TUI_THM_FG, TUI_THM_BG, 0);
	nlines = tui_inputbox_lines(ib);
	cline = ib_cursor_line(ib);
	/* 含光标的尾部窗口 */
	top = (cline >= h) ? cline - h + 1 : 0;

	/* 光标行横向偏移：hoff=首个 >= max(0,ccol-(w-1)) 的边界值 */
	ccol = ib_cursor_col(ib);
	hoff = ccol - (w - 1);
	if (hoff < 0)
		hoff = 0;

	/* 逐逻辑行渲染（行右缘由 tui_screen_put 在屏幕边缘截断——
	 * 输入区右缘==屏幕右缘是 tui_view 的布局约定） */
	p = 0;
	for (i = 0; i < nlines; i++) {
		size_t ls = p, le;
		int row = y + (i - top);

		while (p < ib->len && ib->buf[p] != '\n')
			p++;
		le = p;
		if (p < ib->len)
			p++;	/* 跳过 '\n' */
		if (i < top || i - top >= h || row < 0 || row >= s->rows)
			continue;
		if (i == cline) {
			size_t q = ib_skip_to_hoff(ib, ls, le, hoff, NULL);

			if (q < le)
				(void)tui_screen_put(s, row, x, ib->buf + q,
						     le - q, a);
		} else if (le > ls) {
			(void)tui_screen_put(s, row, x, ib->buf + ls,
					     le - ls, a);
		}
	}

	/* 光标绝对坐标（行内横向走到 hoff 边界后按剩余列定位） */
	{
		int crow = y + (cline - top);
		int cpos_x;
		size_t ls = ib_line_start(ib, ib->cur);

		(void)ib_skip_to_hoff(ib, ls, ib->cur, hoff, &rw);
		cpos_x = x + (ccol - rw);
		if (cpos_x < x)
			cpos_x = x;
		if (cpos_x >= x + w)
			cpos_x = x + w - 1;
		if (crow < y)
			crow = y;
		if (crow >= y + h)
			crow = y + h - 1;
		if (cur_row)
			*cur_row = crow;
		if (cur_col)
			*cur_col = cpos_x;
	}
}
