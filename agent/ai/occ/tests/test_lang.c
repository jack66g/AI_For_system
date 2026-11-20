/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_lang.c - O-20 A 部：语档基建单测
 *
 * 红线断言=zh 档指针恒等（L_ 返回入参本尊——差分/既有断言零扰动的
 * 机制保证）；en 档查表命中/缺键诚实回 zh；OCC_LANG 解析（缺省/非法
 * 回 zh，仅精确 "en" 开 en）。
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "occ_tui/tui_lang.h"

static int fails, checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

int main(void)
{
	const char *zh1 = "新对话";

	/* 1) 缺省 zh：指针恒等（字节+指针双保证） */
	tui_lang_init_env();
	CHECK(tui_lang_is_en() == 0, "default is zh");
	CHECK(L_(zh1) == zh1, "zh returns identical pointer");
	CHECK(strcmp(L_("不在表里的中文"), "不在表里的中文") == 0,
	      "zh unknown key identity");

	/* 2) en：表命中/缺键诚实回 zh */
	tui_lang_set_en(1);
	CHECK(tui_lang_is_en() == 1, "set en");
	CHECK(strcmp(L_("已切中文档"), "Switched to Chinese") == 0,
	      "en table hit (/lang 通知键)");
	CHECK(L_(zh1) == zh1 || strcmp(L_(zh1), zh1) == 0,
	      "en missing key falls back zh");

	/* 3) 回 zh 恒等复归 */
	tui_lang_set_en(0);
	CHECK(L_(zh1) == zh1, "back to zh identity");

	/* 4) OCC_LANG 解析：精确 en 开；空/非法/zh 全回 zh */
	setenv("OCC_LANG", "en", 1);
	tui_lang_init_env();
	CHECK(tui_lang_is_en() == 1, "OCC_LANG=en");
	setenv("OCC_LANG", "en-US", 1);
	tui_lang_init_env();
	CHECK(tui_lang_is_en() == 0, "OCC_LANG=en-US rejected");
	setenv("OCC_LANG", "zh", 1);
	tui_lang_init_env();
	CHECK(tui_lang_is_en() == 0, "OCC_LANG=zh");
	unsetenv("OCC_LANG");
	tui_lang_init_env();
	CHECK(tui_lang_is_en() == 0, "OCC_LANG unset -> zh");

	printf("test_lang: %d checks, %d failures\n", checks, fails);
	return fails ? 1 : 0;
}
