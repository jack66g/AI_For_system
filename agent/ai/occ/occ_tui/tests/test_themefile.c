/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_themefile.c - 主题数据文件（T9c3：~/.occ/theme.ini 同形）
 *
 * 出厂缺省 = c2 编译期常量；坏文件（未知键/越界/语法错）→ -1 且
 * **调色板保持加载前状态**（整文件全对才提交）；文件不存在 → 0 静默。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tui_theme.h"

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

static const char *write_tmp(const char *content)
{
	static char path[128];
	FILE *f;

	snprintf(path, sizeof(path), "/tmp/occ-c3-theme-%d.ini",
		 (int)getpid());
	f = fopen(path, "w");
	if (!f)
		return NULL;
	fputs(content, f);
	fclose(f);
	return path;
}

int main(void)
{
	char err[256];
	const char *p;

	/* ---- 出厂缺省（= c2 常量） ---- */
	tui_thm_reset();
	OK(tui_thm_color(TUI_THM_FG) == 252, "def-fg");
	OK(tui_thm_color(TUI_THM_BG) == 235, "def-bg");
	OK(tui_thm_color(TUI_THM_MUTED) == 242, "def-muted");
	OK(tui_thm_color(TUI_THM_ACCENT) == 81, "def-accent");
	OK(tui_thm_color(TUI_THM_ERROR) == 203, "def-error");
	OK(tui_thm_color(TUI_THM_WARN) == 214, "def-warn");
	OK(tui_thm_color(TUI_THM_CODE_FG) == 186, "def-code-fg");
	OK(tui_thm_color(TUI_THM_LINK) == 75, "def-link");
	OK(tui_thm_color(999) == 252, "def-oob-slot-safe");

	/* ---- 槽位名表 ---- */
	OK(tui_thm_slot_by_name("fg") == TUI_THM_FG, "name-fg");
	OK(tui_thm_slot_by_name("assist_bg") == TUI_THM_ASSIST_BG,
	   "name-assist-bg");
	OK(tui_thm_slot_by_name("nope") == -1, "name-unknown");
	OK(strcmp(tui_thm_slot_name(TUI_THM_KW), "kw") == 0, "slot-kw");
	OK(tui_thm_slot_name(-1) == NULL, "slot-oob");

	/* ---- 文件不存在 → 0（静默缺省） ---- */
	err[0] = '\0';
	OK(tui_thm_load("/tmp/occ-c3-no-such-theme.ini", err,
			sizeof(err)) == 0, "load-missing-ok");
	OK(err[0] == '\0', "load-missing-no-err");
	OK(tui_thm_color(TUI_THM_FG) == 252, "load-missing-unchanged");

	/* ---- 正常加载：部分覆盖 + 注释 + 空白 ---- */
	p = write_tmp("# occ theme\nfg = 100\n\n  accent = 196  \nbg=20\n");
	OK(p != NULL, "tmp-written");
	err[0] = '\0';
	OK(tui_thm_load(p, err, sizeof(err)) == 0, "load-good");
	OK(tui_thm_color(TUI_THM_FG) == 100, "good-fg");
	OK(tui_thm_color(TUI_THM_ACCENT) == 196, "good-accent");
	OK(tui_thm_color(TUI_THM_BG) == 20, "good-bg");
	OK(tui_thm_color(TUI_THM_MUTED) == 242, "good-unspecified-kept");
	unlink(p);

	/* ---- 坏文件：整文件拒绝、调色板保持加载前状态 ---- */
	p = write_tmp("fg = 111\nbogus_key = 1\n");
	err[0] = '\0';
	OK(tui_thm_load(p, err, sizeof(err)) == -1, "bad-unknown-key");
	OK(strstr(err, "未知键") != NULL, "bad-unknown-key-msg");
	OK(tui_thm_color(TUI_THM_FG) == 100, "bad-keeps-prior");
	unlink(p);

	p = write_tmp("fg = 111\nbg = 300\n");
	err[0] = '\0';
	OK(tui_thm_load(p, err, sizeof(err)) == -1, "bad-range");
	OK(strstr(err, "0..255") != NULL, "bad-range-msg");
	OK(tui_thm_color(TUI_THM_BG) == 20, "bad-range-keeps-prior");
	unlink(p);

	p = write_tmp("fg 111\n");
	err[0] = '\0';
	OK(tui_thm_load(p, err, sizeof(err)) == -1, "bad-no-eq");
	OK(strstr(err, "line 1") != NULL, "bad-no-eq-lineno");
	unlink(p);

	p = write_tmp("fg = abc\n");
	err[0] = '\0';
	OK(tui_thm_load(p, err, sizeof(err)) == -1, "bad-nonint");
	unlink(p);

	/* ---- 恢复出厂 ---- */
	tui_thm_reset();
	OK(tui_thm_color(TUI_THM_FG) == 252, "reset-fg");
	OK(tui_thm_color(TUI_THM_ACCENT) == 81, "reset-accent");

	printf("test_themefile: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
