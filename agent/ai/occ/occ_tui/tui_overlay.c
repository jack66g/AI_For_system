/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_overlay.c - 全屏覆盖层实现（T9c3）
 *
 * 可见映射 vis[]：query 空 → 全量；非空 → 去分组头 + text/tag 大小写
 * 不敏感子串（OCD 搜索态去分组语义；fuzzysort 加权取舍见台账裁定 2）。
 * 选择窗在 render 时强制选中可见（top 钳位）；detail/status 行共用
 * （rows-2）：有 status 显示 status，否则显示选中项 detail。
 */
#define _DEFAULT_SOURCE 1
#include "tui_overlay.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "tui_utf8.h"

struct tui_overlay {
	int active;
	int ov_id;
	int is_input;
	int searchable;
	int mask;
	char title[TUI_OV_TITLE_MAX];
	char footer[TUI_OV_FOOTER_MAX];
	char prompt[TUI_OV_PROMPT_MAX];
	char status[TUI_OV_STATUS_MAX];
	int status_err;
	int busy;				/* OCC-DEBT：状态行 spinner 前缀 */
	/* list */
	tui_ov_item *items;
	int nitems, itemscap;
	int *vis;
	int nvis, viscap;
	int sel;		/* vis 下标；-1=无 */
	int top;		/* 窗口首（vis 下标） */
	int body_h;		/* 上次渲染体高（page 步长） */
	/* input / query */
	char text[TUI_OV_INPUT_MAX];
	size_t tlen;
	char query[TUI_OV_QUERY_MAX];
	size_t qlen;
};

/* ---- 小工具 ---- */

static int contains_ci(const char *hay, const char *needle)
{
	size_t nlen = strlen(needle);
	size_t hlen = strlen(hay);
	size_t i, j;

	if (!nlen)
		return 1;
	if (nlen > hlen)
		return 0;
	for (i = 0; i + nlen <= hlen; i++) {
		for (j = 0; j < nlen; j++) {
			if (tolower((unsigned char)hay[i + j]) !=
			    tolower((unsigned char)needle[j]))
				break;
		}
		if (j == nlen)
			return 1;
	}
	return 0;
}

static int ov_width(const char *s)
{
	int w = 0;
	size_t i = 0, len = strlen(s);

	while (i < len) {
		uint32_t cp;
		size_t adv;
		int cw;

		if (tui_utf8_decode((const uint8_t *)s + i, len - i, &cp,
				    &adv) != TUI_U8_OK || adv == 0) {
			adv = 1;
			cp = TUI_REPLACEMENT;
		}
		cw = tui_wcwidth(cp);
		w += cw > 0 ? cw : 0;
		i += adv;
	}
	return w;
}

/* 后缀起点（跳过前缀使后缀宽 ≤ avail）；返回起点字节，*remain_w=后缀宽 */
static size_t ov_scroll_start(const char *s, int avail, int *remain_w)
{
	int total = ov_width(s);
	size_t start = 0;
	size_t len = strlen(s);

	*remain_w = total;
	if (avail < 0)
		avail = 0;
	while (*remain_w > avail && start < len) {
		uint32_t cp;
		size_t adv;
		int cw;

		if (tui_utf8_decode((const uint8_t *)s + start, len - start,
				    &cp, &adv) != TUI_U8_OK || adv == 0) {
			adv = 1;
			cp = TUI_REPLACEMENT;
		}
		cw = tui_wcwidth(cp);
		*remain_w -= cw > 0 ? cw : 0;
		start += adv;
	}
	return start;
}

static int ov_is_header(const tui_overlay *ov, int vi)
{
	return (ov->items[ov->vis[vi]].flags & TUI_OV_HEADER) != 0;
}

/* 从 from 起按 dir 找首个可选 vis 下标；无 → -1 */
static int ov_pick(const tui_overlay *ov, int from, int dir)
{
	int i;

	if (dir >= 0) {
		for (i = from; i < ov->nvis; i++) {
			if (!ov_is_header(ov, i))
				return i;
		}
	} else {
		for (i = from; i >= 0; i--) {
			if (!ov_is_header(ov, i))
				return i;
		}
	}
	return -1;
}

static void ov_rebuild_vis(tui_overlay *ov)
{
	int i;

	ov->nvis = 0;
	if (!ov->searchable || !ov->qlen) {
		for (i = 0; i < ov->nitems; i++) {
			if (ov->nvis >= ov->viscap)
				break;
			ov->vis[ov->nvis++] = i;
		}
	} else {
		for (i = 0; i < ov->nitems; i++) {
			if (ov->items[i].flags & TUI_OV_HEADER)
				continue;	/* 搜索态去分组（OCD） */
			if (!contains_ci(ov->items[i].text, ov->query) &&
			    !contains_ci(ov->items[i].tag, ov->query) &&
			    !contains_ci(ov->items[i].detail, ov->query))
				continue;
			if (ov->nvis >= ov->viscap)
				break;
			ov->vis[ov->nvis++] = i;
		}
	}
	/* 选择复位/钳位到首个可选项 */
	ov->sel = ov_pick(ov, 0, 1);
	ov->top = 0;
}

static int ov_grow(tui_overlay *ov)
{
	tui_ov_item *ni;
	int *nv;
	int nc = ov->itemscap ? ov->itemscap * 2 : 64;

	ni = realloc(ov->items, (size_t)nc * sizeof(*ni));
	if (!ni)
		return -1;
	ov->items = ni;
	nv = realloc(ov->vis, (size_t)nc * sizeof(*nv));
	if (!nv)
		return -1;
	ov->vis = nv;
	ov->itemscap = nc;
	ov->viscap = nc;
	return 0;
}

/* ---- 生命周期 / 装载 ---- */

tui_overlay *tui_overlay_create(void)
{
	tui_overlay *ov = calloc(1, sizeof(*ov));

	if (!ov)
		return NULL;
	ov->sel = -1;
	ov->body_h = 10;
	return ov;
}

void tui_overlay_destroy(tui_overlay *ov)
{
	if (!ov)
		return;
	free(ov->items);
	free(ov->vis);
	free(ov);
}

void tui_overlay_clear(tui_overlay *ov)
{
	if (!ov)
		return;
	ov->active = 0;
	ov->is_input = 0;
	ov->searchable = 0;
	ov->mask = 0;
	ov->nitems = 0;
	ov->nvis = 0;
	ov->sel = -1;
	ov->top = 0;
	ov->status[0] = '\0';
	ov->status_err = 0;
	ov->text[0] = '\0';
	ov->tlen = 0;
	ov->query[0] = '\0';
	ov->qlen = 0;
	ov->title[0] = '\0';
	ov->footer[0] = '\0';
	ov->prompt[0] = '\0';
}

int tui_overlay_set_list(tui_overlay *ov, int ov_id, const char *title,
			 const tui_ov_item *items, int n, int searchable,
			 const char *footer)
{
	if (!ov || n < 0 || (n > 0 && !items))
		return -1;
	tui_overlay_clear(ov);
	while (ov->nitems < n) {
		if (ov->nitems >= ov->itemscap && ov_grow(ov) != 0)
			return -1;
		ov->items[ov->nitems] = items[ov->nitems];
		ov->nitems++;
	}
	snprintf(ov->title, sizeof(ov->title), "%s", title ? title : "");
	snprintf(ov->footer, sizeof(ov->footer), "%s", footer ? footer : "");
	ov->searchable = searchable ? 1 : 0;
	ov->ov_id = ov_id;
	ov->active = 1;
	ov->is_input = 0;
	ov_rebuild_vis(ov);
	return 0;
}

int tui_overlay_set_input(tui_overlay *ov, int ov_id, const char *title,
			  const char *prompt, const char *initial, int mask)
{
	if (!ov)
		return -1;
	tui_overlay_clear(ov);
	snprintf(ov->title, sizeof(ov->title), "%s", title ? title : "");
	snprintf(ov->prompt, sizeof(ov->prompt), "%s", prompt ? prompt : "");
	if (initial) {
		snprintf(ov->text, sizeof(ov->text), "%s", initial);
		ov->tlen = strlen(ov->text);
	}
	ov->mask = mask ? 1 : 0;
	ov->ov_id = ov_id;
	ov->active = 1;
	ov->is_input = 1;
	return 0;
}

/* ---- 观察口 ---- */

int tui_overlay_active(const tui_overlay *ov)
{
	return ov && ov->active;
}

int tui_overlay_id(const tui_overlay *ov)
{
	return ov ? ov->ov_id : 0;
}

int tui_overlay_is_input(const tui_overlay *ov)
{
	return ov && ov->is_input;
}

int tui_overlay_searchable(const tui_overlay *ov)
{
	return ov && ov->searchable;
}

int tui_overlay_nitems(const tui_overlay *ov)
{
	return ov ? ov->nitems : 0;
}

int tui_overlay_sel(const tui_overlay *ov)
{
	return ov ? ov->sel : -1;
}

int tui_overlay_count_selectable(const tui_overlay *ov)
{
	int i, n = 0;

	if (!ov)
		return 0;
	for (i = 0; i < ov->nvis; i++) {
		if (!ov_is_header(ov, i))
			n++;
	}
	return n;
}

int tui_overlay_sel_no(const tui_overlay *ov)
{
	int i, n = 0;

	if (!ov || ov->sel < 0)
		return 0;
	for (i = 0; i <= ov->sel && i < ov->nvis; i++) {
		if (!ov_is_header(ov, i))
			n++;
	}
	return n;
}

const char *tui_overlay_title(const tui_overlay *ov)
{
	return ov ? ov->title : "";
}

const char *tui_overlay_query(const tui_overlay *ov)
{
	return ov ? ov->query : "";
}

const char *tui_overlay_input_text(const tui_overlay *ov, size_t *len)
{
	if (len)
		*len = ov ? ov->tlen : 0;
	return ov ? ov->text : "";
}

const char *tui_overlay_footer(const tui_overlay *ov)
{
	return ov ? ov->footer : "";
}

void tui_overlay_status(tui_overlay *ov, const char *msg, int is_err)
{
	if (!ov)
		return;
	if (!msg) {
		ov->status[0] = '\0';
		ov->status_err = 0;
		return;
	}
	snprintf(ov->status, sizeof(ov->status), "%s", msg);
	ov->status_err = is_err ? 1 : 0;
}

void tui_overlay_busy(tui_overlay *ov, int on)
{
	if (ov)
		ov->busy = on ? 1 : 0;
}

/* ---- 键动作 ---- */

int tui_overlay_nav(tui_overlay *ov, int dir)
{
	int s;

	if (!ov || !ov->active)
		return TUI_OVA_NONE;
	if (ov->is_input)
		return TUI_OVA_HANDLED;	/* 单行输入：方向键无操作（吞） */
	if (dir == 0)
		return TUI_OVA_HANDLED;
	if (ov->sel < 0) {
		s = ov_pick(ov, dir > 0 ? 0 : ov->nvis - 1, dir > 0 ? 1 : -1);
		if (s >= 0)
			ov->sel = s;
		return TUI_OVA_HANDLED;
	}
	s = ov->sel + dir;
	while (s >= 0 && s < ov->nvis && ov_is_header(ov, s))
		s += dir;
	if (s >= 0 && s < ov->nvis)
		ov->sel = s;	/* 越界：保持原位 */
	return TUI_OVA_HANDLED;
}

int tui_overlay_page(tui_overlay *ov, int dir)
{
	int steps;

	if (!ov || !ov->active)
		return TUI_OVA_NONE;
	if (ov->is_input)
		return TUI_OVA_HANDLED;
	steps = ov->body_h > 0 ? ov->body_h : 10;
	while (steps-- > 0)
		(void)tui_overlay_nav(ov, dir > 0 ? 1 : -1);
	return TUI_OVA_HANDLED;
}

int tui_overlay_home(tui_overlay *ov)
{
	int s;

	if (!ov || !ov->active)
		return TUI_OVA_NONE;
	if (ov->is_input)
		return TUI_OVA_HANDLED;
	s = ov_pick(ov, 0, 1);
	if (s >= 0)
		ov->sel = s;
	return TUI_OVA_HANDLED;
}

int tui_overlay_end(tui_overlay *ov)
{
	int s;

	if (!ov || !ov->active)
		return TUI_OVA_NONE;
	if (ov->is_input)
		return TUI_OVA_HANDLED;
	s = ov_pick(ov, ov->nvis - 1, -1);
	if (s >= 0)
		ov->sel = s;
	return TUI_OVA_HANDLED;
}

int tui_overlay_backspace(tui_overlay *ov)
{
	if (!ov || !ov->active)
		return TUI_OVA_NONE;
	if (ov->is_input) {
		size_t i;

		if (!ov->tlen)
			return TUI_OVA_HANDLED;
		i = ov->tlen - 1;
		while (i > 0 && ((unsigned char)ov->text[i] & 0xC0) == 0x80)
			i--;
		ov->tlen = i;
		ov->text[ov->tlen] = '\0';
		return TUI_OVA_HANDLED;
	}
	if (ov->searchable && ov->qlen) {
		size_t i = ov->qlen - 1;

		while (i > 0 && ((unsigned char)ov->query[i] & 0xC0) == 0x80)
			i--;
		ov->qlen = i;
		ov->query[ov->qlen] = '\0';
		ov_rebuild_vis(ov);
		return TUI_OVA_HANDLED;
	}
	return TUI_OVA_NONE;
}

int tui_overlay_type(tui_overlay *ov, const char *utf8, size_t len)
{
	if (!ov || !ov->active || !utf8 || !len)
		return TUI_OVA_NONE;
	if (ov->is_input) {
		if (ov->tlen + len >= sizeof(ov->text))
			return TUI_OVA_HANDLED;
		memcpy(ov->text + ov->tlen, utf8, len);
		ov->tlen += len;
		ov->text[ov->tlen] = '\0';
		return TUI_OVA_HANDLED;
	}
	if (!ov->searchable)
		return TUI_OVA_NONE;
	if (ov->qlen + len >= sizeof(ov->query))
		return TUI_OVA_HANDLED;
	memcpy(ov->query + ov->qlen, utf8, len);
	ov->qlen += len;
	ov->query[ov->qlen] = '\0';
	ov_rebuild_vis(ov);
	return TUI_OVA_HANDLED;
}

int tui_overlay_submit_idx(const tui_overlay *ov)
{
	if (!ov || !ov->active || ov->is_input || ov->sel < 0 ||
	    ov->sel >= ov->nvis)
		return -1;
	return ov->vis[ov->sel];
}

/* ---- 渲染 ---- */

void tui_overlay_render(tui_overlay *ov, tui_screen *s,
			int *cur_row, int *cur_col)
{
	int rows, cols;
	tui_attr a_plain = tui_thm_plain();
	tui_attr a_title = tui_thm_attr(TUI_THM_ACCENT, TUI_THM_BG,
					TUI_ST_BOLD);
	tui_attr a_muted = tui_thm_muted();
	tui_attr a_fg = tui_thm_attr(TUI_THM_FG, TUI_THM_BG, 0);
	tui_attr a_sel = tui_thm_attr(TUI_THM_BG, TUI_THM_ACCENT, 0);
	tui_attr a_err = tui_thm_attr(TUI_THM_ERROR, TUI_THM_BG, 0);
	tui_attr a_status = tui_thm_attr(TUI_THM_ACCENT, TUI_THM_BG, 0);

	if (cur_row)
		*cur_row = -1;
	if (cur_col)
		*cur_col = -1;
	if (!ov || !ov->active || !s)
		return;
	rows = s->rows;
	cols = s->cols;
	if (rows < 1 || cols < 4)
		return;

	/* 整屏填底（全屏覆盖层——底图不透出） */
	tui_screen_fill(s, a_plain);

	/* 标题行 + 右侧计数 */
	if (ov->title[0])
		(void)tui_screen_put(s, 0, 1, ov->title, strlen(ov->title),
				     a_title);
	if (!ov->is_input) {
		char cnt[40];
		int w;

		if (ov->searchable && ov->qlen)
			snprintf(cnt, sizeof(cnt), "[%d/%d] (filter)",
				 tui_overlay_sel_no(ov),
				 tui_overlay_count_selectable(ov));
		else
			snprintf(cnt, sizeof(cnt), "[%d/%d]",
				 tui_overlay_sel_no(ov),
				 tui_overlay_count_selectable(ov));
		w = ov_width(cnt);
		if (cols - 1 - w > 1)
			(void)tui_screen_put(s, 0, cols - 1 - w, cnt,
					     strlen(cnt), a_muted);
	}

	if (ov->is_input) {
		/* 输入态：提示 / 输入行 / status / footer */
		if (rows > 1 && ov->prompt[0])
			(void)tui_screen_put(s, 1, 1, ov->prompt,
					     strlen(ov->prompt), a_muted);
		if (rows > 2) {
			char shown[TUI_OV_INPUT_MAX * 2];
			size_t slen = 0;
			int remain_w = 0;
			size_t start;
			int avail = cols - 2;

			if (ov->mask) {
				/* 每个基 grapheme 一个 '*'（组合符并入） */
				size_t i = 0, len = ov->tlen;

				while (i < len && slen + 1 < sizeof(shown)) {
					uint32_t cp;
					size_t adv;
					int cw;

					if (tui_utf8_decode((const uint8_t *)
							    ov->text + i,
							    len - i, &cp,
							    &adv) !=
					    TUI_U8_OK || adv == 0) {
						adv = 1;
						cp = TUI_REPLACEMENT;
					}
					cw = tui_wcwidth(cp);
					if (cw > 0)
						shown[slen++] = '*';
					i += adv;
				}
				shown[slen] = '\0';
			} else {
				snprintf(shown, sizeof(shown), "%s",
					 ov->text);
				slen = strlen(shown);
			}
			(void)slen;
			start = ov_scroll_start(shown, avail, &remain_w);
			(void)tui_screen_put(s, 2, 1, shown + start,
					     strlen(shown + start), a_fg);
			if (cur_row && cur_col) {
				*cur_row = 2;
				*cur_col = 1 + remain_w;
				if (*cur_col > cols - 1)
					*cur_col = cols - 1;
			}
		}
		if (rows > 3 && ov->status[0]) {
			if (ov->busy) {
				struct timespec ts;
				uint64_t now = 0;
				const char *sp;

				(void)clock_gettime(CLOCK_MONOTONIC, &ts);
				now = (uint64_t)ts.tv_sec * 1000u +
				      (uint64_t)(ts.tv_nsec / 1000000);
				sp = tui_thm_spinner(now);
				(void)tui_screen_put(s, rows - 2, 1, sp,
						     strlen(sp),
						     ov->status_err ? a_err :
						     a_status);
				(void)tui_screen_put(s, rows - 2, 3,
						     ov->status,
						     strlen(ov->status),
						     ov->status_err ? a_err :
						     a_status);
			} else {
				(void)tui_screen_put(s, rows - 2, 1,
						     ov->status,
						     strlen(ov->status),
						     ov->status_err ? a_err :
						     a_status);
			}
		}
		if (ov->footer[0] && rows >= 2)
			(void)tui_screen_put(s, rows - 1, 1, ov->footer,
					     strlen(ov->footer), a_muted);
		return;
	}

	/* 列表态 */
	{
		int body_start = 1;
		int body_h, detail_row, i;

		if (ov->searchable) {
			if (rows > 2) {
				char qrow[TUI_OV_QUERY_MAX + 16];

				snprintf(qrow, sizeof(qrow), "filter: %s",
					 ov->query);
				(void)tui_screen_put(s, 1, 1, qrow,
						     strlen(qrow),
						     ov->qlen ? a_fg :
						     a_muted);
			}
			body_start = 2;
		}
		detail_row = rows - 2;
		body_h = detail_row - body_start;
		if (body_h < 1)
			body_h = 1;
		ov->body_h = body_h;

		/* 选择窗钳位（选中必可见） */
		if (ov->sel >= 0) {
			if (ov->sel < ov->top)
				ov->top = ov->sel;
			if (ov->sel >= ov->top + body_h)
				ov->top = ov->sel - body_h + 1;
		}
		{
			int maxtop = ov->nvis - body_h;

			if (maxtop < 0)
				maxtop = 0;
			if (ov->top > maxtop)
				ov->top = maxtop;
			if (ov->top < 0)
				ov->top = 0;
		}

		for (i = 0; i < body_h; i++) {
			int vi = ov->top + i;
			const tui_ov_item *it;
			tui_attr a;
			int row = body_start + i;
			char line[TUI_OV_TEXT_MAX + 24];

			if (vi >= ov->nvis)
				break;
			it = &ov->items[ov->vis[vi]];
			if (it->flags & TUI_OV_HEADER) {
				a = tui_thm_attr(TUI_THM_MUTED, TUI_THM_BG,
						 TUI_ST_BOLD);
				snprintf(line, sizeof(line), "── %s",
					 it->text);
			} else if (vi == ov->sel) {
				a = a_sel;
				snprintf(line, sizeof(line), "▸ %s",
					 it->text);
			} else if (it->flags & TUI_OV_DIM) {
				a = a_muted;
				snprintf(line, sizeof(line), "  %s",
					 it->text);
			} else {
				a = a_fg;
				snprintf(line, sizeof(line), "  %s",
					 it->text);
			}
			(void)tui_screen_put(s, row, 1, line, strlen(line),
					     a);
			/* tag 右对齐（仅常规行；放得下才画） */
			if (!(it->flags & TUI_OV_HEADER) && it->tag[0]) {
				int tw = ov_width(it->tag);
				int tx = cols - 1 - tw;
				int lw = ov_width(line);

				if (tx > lw + 2)
					(void)tui_screen_put(s, row, tx,
							     it->tag,
							     strlen(it->tag),
							     vi == ov->sel ?
							     a_sel : a_muted);
			}
		}

		/* detail / status 行（rows-2；busy 态前缀 spinner 帧自走） */
		if (detail_row > 0 && detail_row < rows) {
			const char *msg = NULL;
			tui_attr a = a_muted;

			if (ov->status[0]) {
				msg = ov->status;
				a = ov->status_err ? a_err : a_status;
			} else if (ov->sel >= 0 && ov->sel < ov->nvis) {
				const tui_ov_item *it =
					&ov->items[ov->vis[ov->sel]];

				if (it->detail[0])
					msg = it->detail;
			}
			if (msg) {
				if (ov->busy) {
					struct timespec ts;
					uint64_t now = 0;
					const char *sp;

					(void)clock_gettime(CLOCK_MONOTONIC,
							    &ts);
					now = (uint64_t)ts.tv_sec * 1000u +
					      (uint64_t)(ts.tv_nsec / 1000000);
					sp = tui_thm_spinner(now);
					(void)tui_screen_put(s, detail_row, 1,
							     sp, strlen(sp),
							     a);
					(void)tui_screen_put(s, detail_row, 3,
							     msg, strlen(msg),
							     a);
				} else {
					(void)tui_screen_put(s, detail_row, 1,
							     msg, strlen(msg),
							     a);
				}
			}
		}
		if (ov->footer[0])
			(void)tui_screen_put(s, rows - 1, 1, ov->footer,
					     strlen(ov->footer), a_muted);
	}
}
