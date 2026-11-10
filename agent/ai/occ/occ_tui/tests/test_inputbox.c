/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_inputbox.c - 输入框单测（T9c2）：编辑/历史/补全/粘贴/动作码
 *
 * 直接构造 tui_event 喂 tui_inputbox_key（不经 pty——纯逻辑层），
 * 渲染断言走 tui_screen 抽行。
 */
#define _DEFAULT_SOURCE 1
#include <stdio.h>
#include <string.h>

#include "tui_inputbox.h"

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

static tui_event key(uint16_t k, uint32_t ch, uint8_t mods, uint8_t paste)
{
	tui_event e;

	memset(&e, 0, sizeof(e));
	e.type = TUI_EV_KEY;
	e.key = k;
	e.ch = ch;
	e.mods = mods;
	e.paste = paste;
	return e;
}

static void type_str(tui_inputbox *ib, const char *s)
{
	/* 按码点喂（CHAR 事件的 ch 是码点，不是字节） */
	while (*s) {
		unsigned char b = (unsigned char)*s;
		uint32_t cp;
		size_t n = 1;

		if (b < 0x80) {
			cp = b;
		} else if ((b & 0xE0) == 0xC0 && (s[1] & 0xC0) == 0x80) {
			cp = ((uint32_t)(b & 0x1F) << 6) |
			     (uint32_t)(s[1] & 0x3F);
			n = 2;
		} else if ((b & 0xF0) == 0xE0 && (s[1] & 0xC0) == 0x80 &&
			   (s[2] & 0xC0) == 0x80) {
			cp = ((uint32_t)(b & 0x0F) << 12) |
			     ((uint32_t)(s[1] & 0x3F) << 6) |
			     (uint32_t)(s[2] & 0x3F);
			n = 3;
		} else {
			cp = 0xFFFD;
		}
		{
			tui_event e = key(TUI_KEY_CHAR, cp, 0, 0);

			(void)tui_inputbox_key(ib, &e);
		}
		s += n;
	}
}

int main(void)
{
	tui_inputbox *ib;
	tui_event e;
	const char *t;
	size_t len;
	int act;
	int ncmds = 0;
	const char *const *cmds;

	/* ---- 1. 基本编辑：插入/退格/删除/左右 ---- */
	ib = tui_inputbox_create(NULL);
	OK(ib != NULL, "create");
	OK(tui_inputbox_empty(ib), "empty-init");
	type_str(ib, "hello");
	t = tui_inputbox_text(ib, &len);
	OK(len == 5 && strcmp(t, "hello") == 0, "type-hello");
	e = key(TUI_KEY_BACKSPACE, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	OK(strcmp(tui_inputbox_text(ib, NULL), "hell") == 0, "backspace");
	e = key(TUI_KEY_LEFT, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	e = key(TUI_KEY_LEFT, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	e = key(TUI_KEY_DELETE, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	/* "hell" 退格→"hell"，游标 4；左左→2；删 index2='l' → "hel" */
	OK(strcmp(tui_inputbox_text(ib, NULL), "hel") == 0, "left-left-del");
	e = key(TUI_KEY_HOME, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	e = key(TUI_KEY_END, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	OK(strcmp(tui_inputbox_text(ib, NULL), "hel") == 0,
	   "home-end-idempotent");

	/* ---- 2. Enter：空忽略 / 非空提交+入历史 ---- */
	e = key(TUI_KEY_RETURN, 0, 0, 0);
	act = tui_inputbox_key(ib, &e);
	OK(act == TUI_IN_SUBMIT, "enter-submit");
	t = tui_inputbox_text(ib, &len);
	OK(len == 3 && strcmp(t, "hel") == 0, "submit-text-kept");
	tui_inputbox_clear(ib);
	e = key(TUI_KEY_RETURN, 0, 0, 0);
	act = tui_inputbox_key(ib, &e);
	OK(act == TUI_IN_NONE, "enter-empty-ignored");

	/* ---- 3. 历史：↑ 取回、编辑脱离、↓ 回草稿 ---- */
	type_str(ib, "first");
	e = key(TUI_KEY_RETURN, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	tui_inputbox_clear(ib);
	type_str(ib, "second");
	e = key(TUI_KEY_RETURN, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	tui_inputbox_clear(ib);
	e = key(TUI_KEY_UP, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	OK(strcmp(tui_inputbox_text(ib, NULL), "second") == 0, "hist-up-newest");
	e = key(TUI_KEY_UP, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	OK(strcmp(tui_inputbox_text(ib, NULL), "first") == 0, "hist-up-older");
	e = key(TUI_KEY_DOWN, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	OK(strcmp(tui_inputbox_text(ib, NULL), "second") == 0, "hist-down");
	e = key(TUI_KEY_DOWN, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	OK(tui_inputbox_empty(ib), "hist-down-restores-draft");
	/* 多行：光标在中间行 ↑ 走行不走历史 */
	tui_inputbox_clear(ib);
	type_str(ib, "a");
	e = key(TUI_KEY_RETURN, 0, TUI_MOD_SHIFT, 0);	/* shift+enter=换行 */
	act = tui_inputbox_key(ib, &e);
	OK(act == TUI_IN_NONE, "shift-enter-newline");
	type_str(ib, "b");
	OK(tui_inputbox_lines(ib) == 2, "two-lines");
	e = key(TUI_KEY_UP, 0, 0, 0);			/* 光标在第 2 行 → 上移行 */
	(void)tui_inputbox_key(ib, &e);
	OK(strcmp(tui_inputbox_text(ib, NULL), "a\nb") == 0,
	   "up-midline-moves-line-not-hist");

	/* ---- 4. ctrl+c/d 动作码 ---- */
	tui_inputbox_clear(ib);
	e = key(TUI_KEY_CHAR, 'd', TUI_MOD_CTRL, 0);
	act = tui_inputbox_key(ib, &e);
	OK(act == TUI_IN_EXIT, "ctrl+d-empty-exit");
	type_str(ib, "xyz");
	e = key(TUI_KEY_CHAR, 'c', TUI_MOD_CTRL, 0);
	act = tui_inputbox_key(ib, &e);
	OK(act == TUI_IN_CLEAR && tui_inputbox_empty(ib),
	   "ctrl+c-nonempty-clear");
	/* ctrl+j = 换行 */
	type_str(ib, "j1");
	e = key(TUI_KEY_CHAR, 'j', TUI_MOD_CTRL, 0);
	(void)tui_inputbox_key(ib, &e);
	OK(strcmp(tui_inputbox_text(ib, NULL), "j1\n") == 0, "ctrl+j-newline");

	/* ---- 5. Tab 补全：唯一/公共前缀/无命中 ---- */
	tui_inputbox_clear(ib);
	type_str(ib, "/he");
	e = key(TUI_KEY_TAB, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	OK(strcmp(tui_inputbox_text(ib, NULL), "/help ") == 0, "tab-unique");
	tui_inputbox_clear(ib);
	type_str(ib, "/s");
	e = key(TUI_KEY_TAB, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	OK(strcmp(tui_inputbox_text(ib, NULL), "/s") == 0 ||
	   strncmp(tui_inputbox_text(ib, NULL), "/s", 2) == 0,
	   "tab-multi-no-crash");
	{
		const char *tb = tui_inputbox_text(ib, NULL);

		/* /s 多命中（/sessions /shell /status /sandbox）→ 公共前缀 "/s" 不变 */
		OK(strcmp(tb, "/s") == 0, "tab-multi-common-prefix");
	}
	tui_inputbox_clear(ib);
	type_str(ib, "/zzz");
	e = key(TUI_KEY_TAB, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	OK(strcmp(tui_inputbox_text(ib, NULL), "/zzz") == 0, "tab-no-match");
	tui_inputbox_clear(ib);
	type_str(ib, "plain");
	e = key(TUI_KEY_TAB, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	OK(strcmp(tui_inputbox_text(ib, NULL), "plain") == 0,
	   "tab-non-slash-noop");

	/* ---- 6. 命令表：15 条（O-12 增 /delete） ---- */
	cmds = tui_inputbox_cmds(&ncmds);
	OK(ncmds == 15 && cmds != NULL, "cmds-15");
	OK(strcmp(cmds[0], "/models") == 0 && strcmp(cmds[14], "/shell") == 0,
	   "cmds-ends");
	OK(strcmp(cmds[4], "/delete") == 0, "cmds-delete");

	/* ---- 7. 粘贴：原样入缓冲、\r\n 归一、控制字节丢 ---- */
	tui_inputbox_clear(ib);
	e = key(TUI_KEY_CHAR, 'p', 0, 1);
	(void)tui_inputbox_key(ib, &e);
	e = key(TUI_KEY_CHAR, '\r', 0, 1);
	(void)tui_inputbox_key(ib, &e);
	e = key(TUI_KEY_CHAR, '\n', 0, 1);
	(void)tui_inputbox_key(ib, &e);
	e = key(TUI_KEY_CHAR, 'q', 0, 1);
	(void)tui_inputbox_key(ib, &e);
	e = key(TUI_KEY_CHAR, 0x01, 0, 1);	/* 控制字节丢 */
	(void)tui_inputbox_key(ib, &e);
	OK(strcmp(tui_inputbox_text(ib, NULL), "p\nq") == 0,
	   "paste-normalize");

	/* ---- 8. PgUp/PgDn 动作码 ---- */
	e = key(TUI_KEY_PAGEUP, 0, 0, 0);
	act = tui_inputbox_key(ib, &e);
	OK(act == TUI_IN_SCROLL_UP, "pgup-action");
	e = key(TUI_KEY_PAGEDOWN, 0, 0, 0);
	act = tui_inputbox_key(ib, &e);
	OK(act == TUI_IN_SCROLL_DOWN, "pgdn-action");

	/* ---- 9. CJK 编辑：宽字退格整字删 ---- */
	tui_inputbox_clear(ib);
	type_str(ib, "中文");
	OK(strcmp(tui_inputbox_text(ib, NULL), "中文") == 0, "cjk-type");
	e = key(TUI_KEY_BACKSPACE, 0, 0, 0);
	(void)tui_inputbox_key(ib, &e);
	OK(strcmp(tui_inputbox_text(ib, NULL), "中") == 0, "cjk-backspace");

	/* ---- 10. 渲染：光标坐标在区域内 ---- */
	{
		tui_screen *s = tui_screen_create(6, 40);
		int cr = -1, cc = -1;

		tui_inputbox_render(ib, s, 0, 0, 40, 4, &cr, &cc);
		OK(cr >= 0 && cr < 4 && cc >= 0 && cc < 40,
		   "render-cursor-in-region");
		tui_screen_destroy(s);
	}

	tui_inputbox_destroy(ib);
	printf("test_inputbox: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
