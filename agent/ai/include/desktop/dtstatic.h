/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dtstatic.h - 静态资源服务:unquote→normpath 双 root 防穿越、
 * 内建 mimetypes 表(以 L1 录制实测为准)、缓存头(T6b)。
 */
#ifndef _AIK_DESKTOP_DTSTATIC_H
#define _AIK_DESKTOP_DTSTATIC_H

#include <stddef.h>

/* mimetypes.guess_type(path)[0] or "application/octet-stream"
 * (表以 static 向量 20 步为准:.js=text/javascript、.xyz=chemical/x-xyz) */
const char *dt_guess_type(const char *path);

/* _static(rel):命中返回 0 并给出 body/ctype(调用者释放);
 * 未命中返回 -1(回 404)。rel 为已解码路径片段。 */
int dt_static_lookup(const char *rel, char **body, size_t *body_len,
		     const char **ctype);

#endif /* _AIK_DESKTOP_DTSTATIC_H */
