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

	/* ---- E8：/tasks 面板形态（ov_id=6；title 带在跑计数/tag=status
	 * 右对齐/终态 DIM/预算 detail 行/中文标题不炸渲染） ---- */
	{
		tui_ov_item t[3];

		memset(t, 0, sizeof(t));
		snprintf(t[0].text, sizeof(t[0].text), "TASK-ALPHA");
		snprintf(t[0].tag, sizeof(t[0].tag), "in_review");
		snprintf(t[0].detail, sizeof(t[0].detail),
			 "tsk_0000000000000000000000000000aa · rew 1/2 ·"
			 " 12.0k/34.0k tok · $0.045600");
		snprintf(t[1].text, sizeof(t[1].text), "TASK-BETA");
		snprintf(t[1].tag, sizeof(t[1].tag), "done");
		snprintf(t[1].detail, sizeof(t[1].detail),
			 "tsk_0000000000000000000000000000bb · rew 0/2 ·"
			 " 1.0k/2.0k tok");
		t[1].flags = TUI_OV_DIM;
		snprintf(t[2].text, sizeof(t[2].text), "TASK-GAMMA");
		snprintf(t[2].tag, sizeof(t[2].tag), "dispatched");
		snprintf(t[2].detail, sizeof(t[2].detail),
			 "tsk_0000000000000000000000000000cc · rew 0/2 ·"
			 " 0/0 tok");
		OK(tui_overlay_set_list(ov, 6, "tasks · 跑 1", t, 3, 1,
					"Enter=验收提示(in_review) ·"
					" Esc=关闭") == 0, "e8-set-list");
		OK(tui_overlay_id(ov) == 6, "e8-id");
		OK(tui_overlay_sel(ov) == 0, "e8-sel-first");
		OK(tui_overlay_submit_idx(ov) == 0, "e8-submit-idx");
		/* tag 过滤：status 命中（dispatched 唯一） */
		OK(tui_overlay_type(ov, "dispatched", 10) ==
		   TUI_OVA_HANDLED, "e8-type-query");
		OK(tui_overlay_submit_idx(ov) == 2, "e8-filter-tag-idx");
		while (tui_overlay_query(ov)[0])
			(void)tui_overlay_backspace(ov);
		/* 渲染：标题（中文+跑计数）/任务行/status tag/detail 预算段 */
		s = tui_screen_create(24, 80);
		OK(s != NULL, "e8-screen-create");
		tui_overlay_render(ov, s, &cr, &cc);
		dump_screen(s, dump, sizeof(dump));
		OK(strstr(dump, "tasks") != NULL &&
		   strstr(dump, "跑 1") != NULL, "e8-render-title-running");
		OK(strstr(dump, "TASK-ALPHA") != NULL &&
		   strstr(dump, "TASK-BETA") != NULL &&
		   strstr(dump, "TASK-GAMMA") != NULL, "e8-render-rows");
		OK(strstr(dump, "in_review") != NULL &&
		   strstr(dump, "done") != NULL &&
		   strstr(dump, "dispatched") != NULL,
		   "e8-render-status-tags");
		OK(strstr(dump, "rew 1/2") != NULL &&
		   strstr(dump, "$0.045600") != NULL,
		   "e8-render-detail-budget");
		OK(strstr(dump, "验收提示") != NULL, "e8-render-footer");
		tui_screen_destroy(s);
		/* 状态行（面板内验收提示语义——E8 R3） */
		tui_overlay_status(ov, "验收：对模型用 task 工具 return"
				" 提交裁决（面板只读，不代行）", 0);
		s = tui_screen_create(24, 80);
		tui_overlay_render(ov, s, &cr, &cc);
		dump_screen(s, dump, sizeof(dump));
		OK(strstr(dump, "task 工具") != NULL &&
		   strstr(dump, "return") != NULL, "e8-render-verdict-hint");
		tui_screen_destroy(s);
	}

	/* ---- P-42：NOSEL 不可选行（dim 提示）——初始选择跳过落在首个
	 * 可选条目、导航/家端跳过、提交拒绝越位；选中行整行反色条
	 * （首格 attr 含 TUI_ST_INVERSE——fbterm 下确定可见） ---- */
	{
		tui_ov_item n4[4];

		memset(n4, 0, sizeof(n4));
		snprintf(n4[0].text, sizeof(n4[0].text),
			 "catalog 快照未配置，仅显示已配置模型");
		n4[0].flags = TUI_OV_DIM | TUI_OV_NOSEL;
		snprintf(n4[1].text, sizeof(n4[1].text), "alpha");
		snprintf(n4[2].text, sizeof(n4[2].text), "Group");
		n4[2].flags = TUI_OV_HEADER;
		snprintf(n4[3].text, sizeof(n4[3].text), "beta");
		OK(tui_overlay_set_list(ov, 7, "models", n4, 4, 1,
					"Enter=go") == 0, "p42-set-list");
		/* 初始光标=首个可选（NOSEL 提示行与分组头都跳过） */
		OK(tui_overlay_sel(ov) == 1, "p42-sel-skips-nosel");
		OK(tui_overlay_count_selectable(ov) == 2,
		   "p42-count-selectable");
		OK(tui_overlay_submit_idx(ov) == 1, "p42-submit-first-real");
		OK(tui_overlay_nav(ov, 1) == TUI_OVA_HANDLED &&
		   tui_overlay_sel(ov) == 3, "p42-nav-skips-header");
		OK(tui_overlay_nav(ov, -1) == TUI_OVA_HANDLED &&
		   tui_overlay_sel(ov) == 1, "p42-nav-back-skips-nosel");
		OK(tui_overlay_home(ov) == TUI_OVA_HANDLED &&
		   tui_overlay_sel(ov) == 1, "p42-home-skips-nosel");
		OK(tui_overlay_end(ov) == TUI_OVA_HANDLED &&
		   tui_overlay_sel(ov) == 3, "p42-end");
		/* 过滤只命中 NOSEL 行 → 无可选（sel=-1，回车拒绝） */
		OK(tui_overlay_type(ov, "cat", 3) == TUI_OVA_HANDLED,
		   "p42-type-query");
		OK(tui_overlay_sel(ov) == -1, "p42-only-nosel-hit");
		OK(tui_overlay_submit_idx(ov) == -1, "p42-only-nosel-submit");
		while (tui_overlay_query(ov)[0])
			(void)tui_overlay_backspace(ov);
		/* 渲染：提示行 dim 常规形态 + 选中行 ▸ 文本 + 整行反色条
		 *（可过滤列表 body 从第 2 行起：NOSEL=2 行、选中=3 行） */
		s = tui_screen_create(24, 80);
		OK(s != NULL, "p42-screen");
		tui_overlay_render(ov, s, &cr, &cc);
		dump_screen(s, dump, sizeof(dump));
		OK(strstr(dump, "快照未配置") != NULL, "p42-render-note-dim");
		OK(strstr(dump, "▸ alpha") != NULL, "p42-render-selected");
		{
			/* col 1=▸ 标记、col 2=整行条空格——都须带 INVERSE */
			tui_cell *mk = tui_screen_at(s, 3, 1);
			tui_cell *bar = tui_screen_at(s, 3, 2);

			OK(mk && mk->len == 3 &&
			   (mk->attr.style & TUI_ST_INVERSE) != 0,
			   "p42-sel-marker-inverse");
			OK(bar && bar->len == 1 && bar->utf8[0] == ' ' &&
			   (bar->attr.style & TUI_ST_INVERSE) != 0,
			   "p42-sel-row-inverse-bar");
		}
		tui_screen_destroy(s);
	}

	/* ---- 关闭 ---- */
	tui_overlay_clear(ov);
	OK(!tui_overlay_active(ov), "cleared");
	tui_overlay_destroy(ov);

	printf("test_overlay: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
