/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_overlay.c - 全屏覆盖层（T9c3：键导航 / 过滤 / 输入态 / 渲染）
 *
 * 断言面：分组头不可选且导航跳过、query 子串过滤（去分组）、home/end/
 * page、输入态编辑与 mask、submit 下标回映射、渲染字节（标题/选中▸/
 * 头前缀/detail 行/光标位）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tui_overlay.h"

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

/* 屏幕拼文本（行优先；跳过宽字续格） */
static void dump_screen(tui_screen *s, char *buf, size_t cap)
{
	size_t off = 0;
	int r, c;

	for (r = 0; r < s->rows && off + 2 < cap; r++) {
		for (c = 0; c < s->cols && off + 2 < cap; c++) {
			tui_cell *cell = &s->cells[r * s->cols + c];

			if (cell->len > 0 &&
			    off + cell->len + 1 < cap) {
				memcpy(buf + off, cell->utf8, cell->len);
				off += cell->len;
			}
		}
		buf[off++] = '\n';
	}
	buf[off] = '\0';
}

static void mk_items(tui_ov_item *it)
{
	memset(it, 0, 5 * sizeof(*it));
	snprintf(it[0].text, sizeof(it[0].text), "Group A");
	it[0].flags = TUI_OV_HEADER;
	snprintf(it[1].text, sizeof(it[1].text), "alpha");
	snprintf(it[1].tag, sizeof(it[1].tag), "prov-a");
	snprintf(it[1].detail, sizeof(it[1].detail), "alpha detail");
	snprintf(it[2].text, sizeof(it[2].text), "beta");
	snprintf(it[2].tag, sizeof(it[2].tag), "prov-b");
	it[2].flags = TUI_OV_DIM;
	snprintf(it[3].text, sizeof(it[3].text), "Group B");
	it[3].flags = TUI_OV_HEADER;
	snprintf(it[4].text, sizeof(it[4].text), "gamma");
	snprintf(it[4].tag, sizeof(it[4].tag), "prov-c");
}

int main(void)
{
	tui_ov_item it[5];
	tui_overlay *ov;
	tui_screen *s;
	char dump[8192];
	int cr = -2, cc = -2;
	size_t tlen = 0;

	ov = tui_overlay_create();
	OK(ov != NULL, "create");
	mk_items(it);

	/* ---- 列表态装载：头不可选、首可选=alpha ---- */
	OK(tui_overlay_set_list(ov, 7, "models", it, 5, 1,
				"Enter=go") == 0, "set-list");
	OK(tui_overlay_active(ov), "active");
	OK(tui_overlay_id(ov) == 7, "id");
	OK(!tui_overlay_is_input(ov), "not-input");
	OK(tui_overlay_searchable(ov), "searchable");
	OK(tui_overlay_nitems(ov) == 5, "nitems");
	OK(tui_overlay_sel(ov) == 1, "sel-first-selectable");
	OK(tui_overlay_count_selectable(ov) == 3, "count-selectable");
	OK(tui_overlay_sel_no(ov) == 1, "sel-no");

	/* ---- 导航：跳头、边界保持 ---- */
	OK(tui_overlay_nav(ov, 1) == TUI_OVA_HANDLED &&
	   tui_overlay_sel(ov) == 2, "nav-next-beta");
	OK(tui_overlay_nav(ov, 1) == TUI_OVA_HANDLED &&
	   tui_overlay_sel(ov) == 4, "nav-skip-header");
	OK(tui_overlay_nav(ov, 1) == TUI_OVA_HANDLED &&
	   tui_overlay_sel(ov) == 4, "nav-clamp-end");
	OK(tui_overlay_nav(ov, -1) == TUI_OVA_HANDLED &&
	   tui_overlay_sel(ov) == 2, "nav-prev-beta");
	OK(tui_overlay_nav(ov, -1) == TUI_OVA_HANDLED &&
	   tui_overlay_sel(ov) == 1, "nav-prev-alpha");
	OK(tui_overlay_nav(ov, -1) == TUI_OVA_HANDLED &&
	   tui_overlay_sel(ov) == 1, "nav-clamp-start");
	OK(tui_overlay_end(ov) == TUI_OVA_HANDLED &&
	   tui_overlay_sel(ov) == 4, "end");
	OK(tui_overlay_home(ov) == TUI_OVA_HANDLED &&
	   tui_overlay_sel(ov) == 1, "home");
	/* page（body_h 缺省 10 > 列表长 → 到尾） */
	OK(tui_overlay_page(ov, 1) == TUI_OVA_HANDLED &&
	   tui_overlay_sel(ov) == 4, "page-down-end");
	OK(tui_overlay_page(ov, -1) == TUI_OVA_HANDLED &&
	   tui_overlay_sel(ov) == 1, "page-up-home");

	/* ---- submit 下标回映射（原始 items 下标） ---- */
	OK(tui_overlay_submit_idx(ov) == 1, "submit-idx-alpha");
	tui_overlay_nav(ov, 1);
	tui_overlay_nav(ov, 1);
	OK(tui_overlay_submit_idx(ov) == 4, "submit-idx-gamma");

	/* ---- query 过滤：去分组、text+tag 命中、复位选择 ---- */
	OK(tui_overlay_type(ov, "bet", 3) == TUI_OVA_HANDLED, "type-query");
	OK(strcmp(tui_overlay_query(ov), "bet") == 0, "query-value");
	OK(tui_overlay_sel(ov) == 0, "filter-sel-reset");
	OK(tui_overlay_submit_idx(ov) == 2, "filter-idx-beta");
	OK(tui_overlay_count_selectable(ov) == 1, "filter-count");
	/* tag 命中 */
	OK(tui_overlay_backspace(ov) == TUI_OVA_HANDLED &&
	   tui_overlay_backspace(ov) == TUI_OVA_HANDLED &&
	   tui_overlay_backspace(ov) == TUI_OVA_HANDLED, "query-backspace");
	OK(tui_overlay_query(ov)[0] == '\0', "query-cleared");
	OK(tui_overlay_type(ov, "prov-a", 6) == TUI_OVA_HANDLED,
	   "type-tag-query");
	OK(tui_overlay_submit_idx(ov) == 1, "filter-tag-idx");
	/* 无命中 → sel=-1 */
	(void)tui_overlay_backspace(ov);
	OK(tui_overlay_type(ov, "zzz", 3) == TUI_OVA_HANDLED, "type-nohit");
	OK(tui_overlay_sel(ov) == -1, "filter-nohit-sel");
	OK(tui_overlay_submit_idx(ov) == -1, "filter-nohit-submit");
	/* backspace 清空复位 */
	while (tui_overlay_query(ov)[0])
		(void)tui_overlay_backspace(ov);
	OK(tui_overlay_sel(ov) == 1, "query-reset-sel");

	/* ---- 渲染（列表态） ---- */
	s = tui_screen_create(24, 80);
	OK(s != NULL, "screen-create");
	tui_overlay_render(ov, s, &cr, &cc);
	OK(cr == -1 && cc == -1, "list-cursor-hidden");
	dump_screen(s, dump, sizeof(dump));
	OK(strstr(dump, "models") != NULL, "render-title");
	OK(strstr(dump, "── Group A") != NULL, "render-header");
	OK(strstr(dump, "▸ alpha") != NULL, "render-selected");
	OK(strstr(dump, "Enter=go") != NULL, "render-footer");
	OK(strstr(dump, "[1/3]") != NULL, "render-count");
	/* detail 行 = 选中项 detail */
	OK(strstr(dump, "alpha detail") != NULL, "render-detail");
	tui_screen_destroy(s);

	/* ---- 非过滤列表：type 不生效 ---- */
	OK(tui_overlay_set_list(ov, 8, "sessions", it, 5, 0, "f") == 0,
	   "set-list-nosearch");
	OK(tui_overlay_type(ov, "x", 1) == TUI_OVA_NONE,
	   "nosearch-type-none");
	OK(tui_overlay_query(ov)[0] == '\0', "nosearch-query-empty");

	/* ---- 输入态（mask） ---- */
	OK(tui_overlay_set_input(ov, 9, "key", "paste key", NULL, 1) == 0,
	   "set-input");
	OK(tui_overlay_is_input(ov), "is-input");
	OK(tui_overlay_type(ov, "a", 1) == TUI_OVA_HANDLED, "input-type-a");
	OK(tui_overlay_type(ov, "b", 1) == TUI_OVA_HANDLED, "input-type-b");
	OK(tui_overlay_type(ov, "c", 1) == TUI_OVA_HANDLED, "input-type-c");
	OK(strcmp(tui_overlay_input_text(ov, &tlen), "abc") == 0 &&
	   tlen == 3, "input-value");
	OK(tui_overlay_backspace(ov) == TUI_OVA_HANDLED &&
	   strcmp(tui_overlay_input_text(ov, NULL), "ab") == 0,
	   "input-backspace");
	OK(tui_overlay_submit_idx(ov) == -1, "input-no-idx");
	/* 方向键在输入态被吞（HANDLED 但不动） */
	OK(tui_overlay_nav(ov, 1) == TUI_OVA_HANDLED, "input-nav-swallow");

	s = tui_screen_create(24, 80);
	tui_overlay_render(ov, s, &cr, &cc);
	OK(cr == 2, "input-cursor-row");
	OK(cc == 1 + 2, "input-cursor-col");	/* 1 + "ab" 宽 2 */
	dump_screen(s, dump, sizeof(dump));
	OK(strstr(dump, "paste key") != NULL, "input-prompt");
	OK(strstr(dump, "**") != NULL, "input-masked");
	OK(strstr(dump, "ab") == NULL, "input-plaintext-hidden");
	tui_screen_destroy(s);

	/* ---- status 行 ---- */
	tui_overlay_status(ov, "验证中…", 0);
	s = tui_screen_create(24, 80);
	tui_overlay_render(ov, s, &cr, &cc);
	dump_screen(s, dump, sizeof(dump));
	OK(strstr(dump, "验证中") != NULL, "render-status");
	tui_screen_destroy(s);

	/* ---- 关闭 ---- */
	tui_overlay_clear(ov);
	OK(!tui_overlay_active(ov), "cleared");
	tui_overlay_destroy(ov);

	printf("test_overlay: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
