/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dttheme.h - 主题引擎:load_theme 自愈、_BASE_THEMES 内嵌色板、
 * build_custom_theme 混色派生、壁纸画廊(T6b)。
 */
#ifndef _AIK_DESKTOP_DTTHEME_H
#define _AIK_DESKTOP_DTTHEME_H

#include "store/store_json.h"

/* 内置三主题(_BASE_THEMES 同源;返回新增引用,调用者释放) */
aik_json *dt_base_theme(const char *name);   /* "dark"/"light"/"pink" */

/* load_theme:文件坏 → {current:dark, themes:{}};任何内置主题缺失或
 * 无 bg 键 → 修补(保留 wallpaper_file/display);themes 空 → 整体植入;
 * setdefault wallpaper/current;脏了重写 THEME_FILE(tmp+replace+后 chmod)。 */
aik_json *dt_load_theme(void);

/* save_theme:tmp + 先 chmod 0600 + replace */
int dt_save_theme(aik_json *obj);

/* list_wallpapers:STATIC_DIR/wallpapers 下 .png 且 >10240,sorted 去扩展名 */
aik_json *dt_list_wallpapers(void);

/* build_custom_theme:混色系数 bg .06/bg2 .10/panel_solid .08/
 * bubble_ai .14/bubble_user=accent 混黑 .15/accent2 混白 .35、
 * 三段渐变 wallpaper(用混合后的 bg)、wallpaper_file=null 补尾、
 * display="自定义(<accent>)"。 */
aik_json *dt_build_custom_theme(const char *accent, const char *base);

#endif /* _AIK_DESKTOP_DTTHEME_H */
