/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_lang.c - 语言档实现（O-20 A 部，LANG-IME-DESIGN §A）
 *
 * OCC_LANG=en|zh（缺省 zh，非法回 zh）+/lang 运行时切换（内存态——
 * 持久化走 env/出厂配置位）。en 双语表=tui_lang_tab.h（收编产物，
 * 由表生成器从收编 JSON 生成；zh=键本身恒等返回，不入表）。
 */
#include <stdlib.h>
#include <string.h>

#include "tui_lang.h"
#include "tui_lang_tab.h"

static int g_lang_en;			/* 零init=zh：测试/差分缺省面恒等 */

int tui_lang_is_en(void)
{
	return g_lang_en;
}

void tui_lang_set_en(int en)
{
	g_lang_en = en ? 1 : 0;
}

void tui_lang_init_env(void)
{
	const char *v = getenv("OCC_LANG");

	/* 精确匹配 "en"；其余（含未设/非法）一律 zh——缺省面字节不变 */
	g_lang_en = (v && v[0] == 'e' && v[1] == 'n' && v[2] == '\0') ?
		    1 : 0;
}

const char *tui_lang_get(const char *zh)
{
	size_t i;

	if (!g_lang_en || zh == NULL)
		return zh;
	for (i = 0; i < sizeof(L_TAB) / sizeof(L_TAB[0]); i++)
		if (strcmp(L_TAB[i].zh, zh) == 0)
			return L_TAB[i].en;
	return zh;	/* en 缺键：诚实降级，中文照显 */
}
