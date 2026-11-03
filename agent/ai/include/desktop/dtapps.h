/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dtapps.h - 应用清单:.desktop 扫描、freedesktop 图标链+复制、
 * zh_CN 映射、demo catalog 合并、120s 缓存(T6b)。
 */
#ifndef _AIK_DESKTOP_DTAPPS_H
#define _AIK_DESKTOP_DTAPPS_H

#include "store/store_json.h"

/* collect_apps():键序 id/name/name_en/name_zh/comment/exec/categories/
 * terminal/icon/virtual;真实应用 <5 时合并 catalog(virtual/source 补尾) */
aik_json *dt_collect_apps(void);

/* get_apps(force):120s 缓存(冻结时钟下恒命中) */
aik_json *dt_get_apps(int force);

#endif /* _AIK_DESKTOP_DTAPPS_H */
