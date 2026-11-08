/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_theme.c - occ TUI 调色板运行时（T9c3：主题数据文件）
 *
 * 全局调色板（单实例 TUI，主线程读写——render 与 load 均在主线程）。
 * 出厂缺省 = c2 tui_theme.h 编译期常量逐槽相等；tui_thm_load 先解析进
 * 临时表、整文件全对才提交——坏文件绝不动现有调色板（诚实回落前提）。
 *
 * 文件格式（自定 ini，报告 T9C3-REPORT §主题）：
 *   # 注释行
 *   fg = 252        （键名见 tui_thm_slot_name；值 0..255 整数）
 * 语法：`key = value`，key/value 两侧空白忽略；值必须是纯整数
 * （strtol 全消费）；未知键 / 越界 / 缺 '=' / 空键 → 整文件拒绝。
 */
#define _DEFAULT_SOURCE 1
#include "tui_theme.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 出厂缺省（= c2 编译期常量；顺序与 enum 槽位一致） */
static const int TUI_THM_DEFAULTS[TUI_THM_COUNT] = {
	252,	/* FG */
	235,	/* BG */
	242,	/* MUTED */
	81,	/* ACCENT */
	238,	/* BORDER */
	203,	/* ERROR */
	114,	/* OK */
	214,	/* WARN */
	236,	/* USER_BG */
	234,	/* ASSIST_BG */
	186,	/* CODE_FG */
	236,	/* CODE_BG */
	81,	/* KW */
	114,	/* STR */
	179,	/* NUM */
	244,	/* CMT */
	75	/* LINK */
};

static const char *const TUI_THM_NAMES[TUI_THM_COUNT] = {
	"fg", "bg", "muted", "accent", "border", "error", "ok", "warn",
	"user_bg", "assist_bg", "code_fg", "code_bg", "kw", "str", "num",
	"cmt", "link"
};

static int g_pal[TUI_THM_COUNT];

const char *tui_thm_slot_name(int slot)
{
	if (slot < 0 || slot >= TUI_THM_COUNT)
		return NULL;
	return TUI_THM_NAMES[slot];
}

int tui_thm_slot_by_name(const char *name)
{
	int i;

	if (!name)
		return -1;
	for (i = 0; i < TUI_THM_COUNT; i++) {
		if (!strcmp(name, TUI_THM_NAMES[i]))
			return i;
	}
	return -1;
}

int tui_thm_color(int slot)
{
	if (slot < 0 || slot >= TUI_THM_COUNT)
		return TUI_THM_DEFAULTS[TUI_THM_FG];
	return g_pal[slot];
}

void tui_thm_reset(void)
{
	memcpy(g_pal, TUI_THM_DEFAULTS, sizeof(g_pal));
}

/* 进程启动即缺省（无需显式 init；tui_thm_reset 可重置） */
static void tui_thm_init_once(void) __attribute__((constructor));
static void tui_thm_init_once(void)
{
	memcpy(g_pal, TUI_THM_DEFAULTS, sizeof(g_pal));
}

/* ---- 数据文件加载 ---- */

static char *trim(char *s)
{
	char *e;

	while (*s && isspace((unsigned char)*s))
		s++;
	e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		*--e = '\0';
	return s;
}

int tui_thm_load(const char *path, char *err, size_t errlen)
{
	FILE *f;
	char line[256];
	int tmp[TUI_THM_COUNT];
	int lineno = 0;
	int rc = 0;

	if (err && errlen)
		err[0] = '\0';
	if (!path || !path[0]) {
		if (err)
			snprintf(err, errlen, "theme: empty path");
		return -1;
	}
	f = fopen(path, "r");
	if (!f) {
		if (errno == ENOENT)
			return 0;	/* 出厂缺省静默生效（非错误） */
		if (err)
			snprintf(err, errlen, "theme: cannot open %.160s: %s",
				 path, strerror(errno));
		return -1;
	}
	memcpy(tmp, TUI_THM_DEFAULTS, sizeof(tmp));
	while (fgets(line, sizeof(line), f)) {
		char *s, *eq, *key, *val;
		char *end = NULL;
		long v;
		int slot;

		lineno++;
		s = trim(line);
		if (!*s || *s == '#')
			continue;
		eq = strchr(s, '=');
		if (!eq) {
			if (err)
				snprintf(err, errlen,
					 "theme: line %d: 缺少 '='", lineno);
			rc = -1;
			break;
		}
		*eq = '\0';
		key = trim(s);
		val = trim(eq + 1);
		slot = tui_thm_slot_by_name(key);
		if (slot < 0) {
			if (err)
				snprintf(err, errlen,
					 "theme: line %d: 未知键 `%.40s'",
					 lineno, key);
			rc = -1;
			break;
		}
		if (!*val) {
			if (err)
				snprintf(err, errlen,
					 "theme: line %d: 缺值", lineno);
			rc = -1;
			break;
		}
		errno = 0;
		v = strtol(val, &end, 10);
		if (errno || end == val || *end != '\0' || v < 0 || v > 255) {
			if (err)
				snprintf(err, errlen,
					 "theme: line %d: 值须为 0..255 整数"
					 "（`%.40s`）", lineno, val);
			rc = -1;
			break;
		}
		tmp[slot] = (int)v;
	}
	fclose(f);
	if (rc == 0)
		memcpy(g_pal, tmp, sizeof(g_pal));	/* 整文件全对才提交 */
	return rc;
}
