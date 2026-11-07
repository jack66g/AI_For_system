/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_tools_priv.h - occ_tools 内部共享件（不外露）
 *
 * obuf：结果文本化缓冲（8KB 截断 + UTF-8 边界安全 + 截断注记）。
 */
#ifndef _OCC_TOOLS_PRIV_H
#define _OCC_TOOLS_PRIV_H

#include <stddef.h>

#include "occ_tools.h"

typedef struct {
	char buf[OCC_TOOL_OUT_MAX + 256];
	size_t len;			/* 已写入字节 */
	size_t total;			/* 截断前累计字节 */
	int truncated;
} occ_obuf;

void occ_ob_put(occ_obuf *o, const char *s, size_t n);
void occ_ob_puts(occ_obuf *o, const char *s);
void occ_ob_printf(occ_obuf *o, const char *fmt, ...);

#endif /* _OCC_TOOLS_PRIV_H */
