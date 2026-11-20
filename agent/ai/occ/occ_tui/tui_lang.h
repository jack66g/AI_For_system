/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_lang.h - O-20 A 部：语言两档（zh|en）文案面
 *
 * 语档：OCC_LANG=en|zh（缺省 zh，非法回 zh）；/lang 运行时切换。
 * L_(s)——zh 档恒回 s 原字面量（字节恒等：差分门/既有断言零扰动）；
 * en 档查 tui_lang.c 双语表，缺键诚实回中文原文（可见、可补译）。
 * 不引第三方 i18n 库（纯 C 手表，LANG-IME-DESIGN §A）。
 */
#ifndef _TUI_LANG_H
#define _TUI_LANG_H

/* 按当前档取文案：zh=入参恒等；en=查表，缺键回入参（中文照显） */
const char *tui_lang_get(const char *zh);

int tui_lang_is_en(void);
void tui_lang_set_en(int en);		/* /lang 运行时切换（内存态） */
void tui_lang_init_env(void);		/* OCC_LANG 解析（启动一次） */

#define L_(s) tui_lang_get(s)

#endif /* _TUI_LANG_H */
