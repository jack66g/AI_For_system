/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_chat.c - tui_chat 转写区单测（T9c2）
 *
 * 覆盖：消息模型（user/notice/live/收口）、markdown-lite 行为
 * （标题/列表/引用/行内 code/bold/围栏+语法色）、工具行 ✓✗、
 * RESET 截断、dump_text/live_empty 观察口、scrollback 定稿推进。
 * 断言走 dump 文本与屏幕 cell 抽取（golden 文本），不比对 SGR 字节
 * （属性色由 test_render 的 SGR 生成单测覆盖）。
 */
#define _DEFAULT_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tui_chat.h"
#include "tui_core.h"

static int n_fail;
static int n_ok;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

/* ---- 屏幕抽取：把 [x, x+w) 的 cell 拼成串（跳过宽字续格） ---- */

static size_t screen_row(const tui_screen *s, int row, int x, int w,
			 char *buf, size_t cap)
{
	size_t n = 0;
	int k;

	if (row < 0 || row >= s->rows || cap == 0)
		return 0;
	for (k = 0; k < w && x + k < s->cols; k++) {
		const tui_cell *c = &s->cells[(size_t)row * (size_t)s->cols +
					      x + k];
		size_t cl;

		if (c->width == 0)
			continue;		/* 宽字续格 */
		if (c->len == 0)
			continue;		/* 空占位 */
		cl = c->len;
		if (n + cl + 1 > cap)
			break;
		memcpy(buf + n, c->utf8, cl);
		n += cl;
	}
	buf[n] = '\0';
	/* 去尾部空格（未写区域是空白 cell） */
	while (n > 0 && buf[n - 1] == ' ')
		buf[--n] = '\0';
	return n;
}

static tui_screen *render_to(tui_chat *c, int rows, int cols, uint64_t now_ms)
{
	tui_screen *s = tui_screen_create(rows, cols);

	if (!s)
		return NULL;
	tui_screen_fill(s, tui_attr_default());
	tui_chat_render(c, s, 0, 0, cols, rows, now_ms);
	return s;
}

int main(void)
{
	tui_chat *c;
	tui_screen *s;
	char row[512];
	char dump[4096];

	/* ---- 1. user 消息定稿推进 scrollback ---- */
	c = tui_chat_create(NULL);
	OK(c != NULL, "create");
	tui_chat_add_user(c, "hello tui", 9);
	s = render_to(c, 8, 40, 1000);
	OK(s != NULL, "render1");
	OK(screen_row(s, 0, 0, 40, row, sizeof(row)) > 0 &&
	   strstr(row, "you") != NULL, "user-header");
	OK(screen_row(s, 1, 0, 40, row, sizeof(row)) != 0 &&
	   strcmp(row, "hello tui") == 0, "user-text");
	tui_screen_destroy(s);

	/* ---- 2. assistant live：流式中钉底渲染，收口后进 scrollback ---- */
	tui_chat_begin_assistant(c);
	OK(tui_chat_live_empty(c) == 1, "live-empty-on-begin");
	tui_chat_append_text(c, "流式文本", strlen("流式文本"));
	OK(tui_chat_live_empty(c) == 0, "live-nonempty");
	s = render_to(c, 8, 40, 1000);
	{	/* live 钉在转写区底部（h-1），全行扫描不赌列位 */
		int i, found = 0;

		for (i = 0; i < 8; i++) {
			screen_row(s, i, 0, 40, row, sizeof(row));
			if (strstr(row, "流式文本") != NULL)
				found = 1;
		}
		OK(found, "live-rendered");
	}
	tui_screen_destroy(s);
	tui_chat_end_assistant(c, "Agent · model · 1.0s · 20 tok/s");
	s = render_to(c, 8, 40, 1000);
	OK(screen_row(s, 3, 0, 40, row, sizeof(row)) != 0 &&
	   strstr(row, "Agent") != NULL, "footer-in-scrollback");
	tui_screen_destroy(s);

	/* ---- 3. markdown-lite：标题/列表/引用/行内 ---- */
	tui_chat_begin_assistant(c);
	tui_chat_append_text(c,
		"# 标题\n"
		"- 项目一\n"
		"> 引用行\n"
		"行内 `code` 与 **加粗** 结束",
		strlen("# 标题\n- 项目一\n> 引用行\n行内 `code` 与 **加粗** 结束"));
	tui_chat_end_assistant(c, "");
	s = render_to(c, 12, 40, 1000);
	{
		int i, found_h = 0, found_li = 0, found_q = 0, found_ic = 0;

		for (i = 0; i < 12; i++) {
			screen_row(s, i, 0, 40, row, sizeof(row));
			if (strstr(row, "标题") != NULL)
				found_h = 1;
			if (strstr(row, "• 项目一") != NULL)
				found_li = 1;
			if (strstr(row, "引用行") != NULL)
				found_q = 1;
			if (strstr(row, "code") != NULL &&
			    strstr(row, "加粗") != NULL)
				found_ic = 1;
		}
		OK(found_h, "md-heading");
		OK(found_li, "md-list-bullet");
		OK(found_q, "md-quote");
		OK(found_ic, "md-inline");
	}
	tui_screen_destroy(s);

	/* ---- 4. 代码围栏：``` 内容不渲染围栏行，行级语法色 ---- */
	tui_chat_begin_assistant(c);
	tui_chat_append_text(c, "前\n```c\nint x = 1;\n```\n后",
			     strlen("前\n```c\nint x = 1;\n```\n后"));
	tui_chat_end_assistant(c, "");
	s = render_to(c, 12, 40, 1000);
	{
		int i, found_fence = 0, found_code = 0, found_after = 0;

		for (i = 0; i < 12; i++) {
			screen_row(s, i, 0, 40, row, sizeof(row));
			if (strncmp(row, "```", 3) == 0)
				found_fence = 1;
			if (strstr(row, "int x = 1;") != NULL)
				found_code = 1;
			if (strcmp(row, "后") == 0)
				found_after = 1;
		}
		OK(!found_fence, "fence-hidden");
		OK(found_code, "fence-content");
		OK(found_after, "after-fence");
	}
	tui_screen_destroy(s);

	/* ---- 5. 工具行 start→end（running→✓） ---- */
	tui_chat_begin_assistant(c);
	tui_chat_tool_start(c, "bash", "{\"cmd\":\"ls\"}");
	tui_chat_append_text(c, "doing", 5);
	s = render_to(c, 8, 40, 1000);
	{
		int i, found_spin = 0;

		for (i = 0; i < 8; i++) {
			screen_row(s, i, 0, 40, row, sizeof(row));
			if (strstr(row, "bash") != NULL)
				found_spin = 1;
		}
		OK(found_spin, "tool-running-row");
	}
	tui_screen_destroy(s);
	tui_chat_tool_end(c, "bash", "file1\nfile2", 0);
	s = render_to(c, 8, 40, 1000);
	{
		int i, found_ok = 0;

		for (i = 0; i < 8; i++) {
			screen_row(s, i, 0, 40, row, sizeof(row));
			if (strstr(row, "✓") != NULL &&
			    strstr(row, "bash") != NULL)
				found_ok = 1;
		}
		OK(found_ok, "tool-ok-mark");
	}
	tui_screen_destroy(s);
	tui_chat_end_assistant(c, "");

	/* ---- 6. RESET 截断 live 文本（重试语义） ---- */
	tui_chat_begin_assistant(c);
	tui_chat_append_text(c, "GARBAGE-", 9);
	tui_chat_append_text(c, "keep", 4);
	tui_chat_reset_live(c);		/* 应截到首轮增量前（mark=0） */
	tui_chat_append_text(c, "你好", strlen("你好"));
	tui_chat_end_assistant(c, "");
	dump[0] = '\0';
	tui_chat_dump_text(c, dump, sizeof(dump));
	OK(strstr(dump, "你好") != NULL, "reset-replay-present");
	/* mark 语义：首个增量前打点——GARBAGE 属本轮起点后、reset 清掉 */
	OK(strstr(dump, "GARBAGE-") == NULL, "reset-truncated");

	/* ---- 7. notice/error 行 ---- */
	tui_chat_add_notice(c, "重试：第 1/2 次");
	tui_chat_add_error(c, "连接失败");
	s = render_to(c, 12, 40, 1000);
	{
		int i, found_n = 0, found_e = 0;

		for (i = 0; i < 12; i++) {
			screen_row(s, i, 0, 40, row, sizeof(row));
			if (strstr(row, "重试") != NULL)
				found_n = 1;
			if (strstr(row, "连接失败") != NULL)
				found_e = 1;
		}
		OK(found_n, "notice-row");
		OK(found_e, "error-row");
	}
	tui_screen_destroy(s);

	/* ---- 8. clear 后空 ---- */
	tui_chat_clear(c);
	OK(tui_chat_live_empty(c), "clear-empty");
	dump[0] = '\0';
	tui_chat_dump_text(c, dump, sizeof(dump));
	OK(dump[0] == '\0', "clear-dump-empty");

	/* ---- 9. 宽度变化重建（CJK 换行不撕字） ---- */
	tui_chat_add_user(c, "你好世界你好世界你好世界", 36);
	s = render_to(c, 6, 10, 1000);		/* 窄宽强制回绕 */
	OK(s != NULL, "narrow-render");
	{
		int i, rows_used = 0;

		for (i = 0; i < 6; i++) {
			screen_row(s, i, 0, 10, row, sizeof(row));
			if (row[0] != '\0')
				rows_used++;
		}
		OK(rows_used >= 2, "cjk-wrap-multiple-rows");
	}
	tui_screen_destroy(s);
	tui_chat_destroy(c);

	/* ---- 10. B5：推理折叠点击展开/收起（live + 定稿） ---- */
	c = tui_chat_create(NULL);
	tui_chat_begin_assistant(c);
	tui_chat_append_reasoning(c, "思路甲乙丙", strlen("思路甲乙丙"));
	tui_chat_append_text(c, "正文ABC", strlen("正文ABC"));
	/* live：折叠头行渲染（不含正文思路） */
	s = render_to(c, 10, 40, 1000);
	{
		int i, fold = -1, leaked = 0;

		for (i = 0; i < 10; i++) {
			screen_row(s, i, 0, 40, row, sizeof(row));
			if (strstr(row, "thinking…") != NULL)
				fold = i;
			if (strstr(row, "思路甲乙丙") != NULL)
				leaked = 1;
		}
		OK(fold >= 0, "fold-header-rendered");
		OK(!leaked, "fold-collapsed-no-content");
		OK(tui_chat_fold_row(c) == fold, "fold-row-api");
		/* 点击折叠行 → 展开：思路正文渲染 + ⌃ 标记 */
		OK(tui_chat_click(c, fold) == 1, "fold-click-hit");
	}
	tui_screen_destroy(s);
	s = render_to(c, 10, 40, 1000);
	{
		int i, found = 0, marker = 0;

		for (i = 0; i < 10; i++) {
			screen_row(s, i, 0, 40, row, sizeof(row));
			if (strstr(row, "思路甲乙丙") != NULL)
				found = 1;
			if (strstr(row, "\xe2\x8c\x83") != NULL)	/* ⌃ */
				marker = 1;
		}
		OK(found, "fold-expanded-content");
		OK(marker, "fold-open-marker");
		{
			int fr = tui_chat_fold_row(c);

			OK(fr >= 0, "fold-row-after-expand");
			OK(tui_chat_click(c, fr) == 1, "fold-click-collapse");
		}
	}
	tui_screen_destroy(s);
	s = render_to(c, 10, 40, 1000);
	{
		int i, leaked = 0;

		for (i = 0; i < 10; i++) {
			screen_row(s, i, 0, 40, row, sizeof(row));
			if (strstr(row, "思路甲乙丙") != NULL)
				leaked = 1;
		}
		OK(!leaked, "fold-recollapsed");
	}
	/* 未命中行点击 → 0 不误切 */
	OK(tui_chat_click(c, 0) == 0, "fold-click-miss");
	tui_screen_destroy(s);
	/* 收口 → 定稿折叠行点击展开（scrollback 内） */
	tui_chat_end_assistant(c, "");
	s = render_to(c, 10, 40, 1000);
	{
		int i, fold = -1;

		for (i = 0; i < 10; i++) {
			screen_row(s, i, 0, 40, row, sizeof(row));
			if (strstr(row, "thought · ") != NULL)
				fold = i;
		}
		OK(fold >= 0, "final-fold-header");
		OK(tui_chat_click(c, fold) == 1, "final-fold-click");
	}
	tui_screen_destroy(s);
	s = render_to(c, 10, 40, 1000);
	{
		int i, found = 0;

		for (i = 0; i < 10; i++) {
			screen_row(s, i, 0, 40, row, sizeof(row));
			if (strstr(row, "思路甲乙丙") != NULL)
				found = 1;
		}
		OK(found, "final-fold-expanded");
	}
	tui_screen_destroy(s);
	tui_chat_destroy(c);

	/* ---- 11. B7：emoji ZWJ 序列渲染收敛（单 grapheme 宽 2） ---- */
	c = tui_chat_create(NULL);
	tui_chat_add_user(c,
			  "\xf0\x9f\x91\xa8\xe2\x80\x8d\xf0\x9f\x91\xa9"
			  "\xe2\x80\x8d\xf0\x9f\x91\xa7",
			  18);			/* 👨‍👩‍👧 */
	s = render_to(c, 6, 40, 1000);
	OK(s != NULL, "zwj-render");
	{
		int i, found = 0, wide2 = 0;
		const tui_cell *cc = NULL;

		for (i = 0; i < 6; i++) {
			screen_row(s, i, 0, 40, row, sizeof(row));
			if (strstr(row, "\xf0\x9f\x91\xa8") != NULL) {
				int k;

				found = 1;
				for (k = 0; k < 40; k++) {
					const tui_cell *t =
						&s->cells[(size_t)i * 40 + k];

					if (t->len == 18) {
						cc = t;
						break;
					}
				}
			}
		}
		OK(found, "zwj-bytes-in-row");
		if (cc) {
			OK(cc->width == 2, "zwj-single-grapheme-width2");
			wide2 = 1;
		}
		OK(wide2, "zwj-cell-found");
	}
	tui_screen_destroy(s);
	tui_chat_destroy(c);

	printf("test_chat: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
