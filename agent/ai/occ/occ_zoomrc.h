/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_zoomrc.h - T4 /zoom：fbterm 字号级表 + ~/.fbtermrc font-size 编辑
 *
 * 纯函数（无终端依赖，tests/test_zoomrc.c 直测）。/zoom 的终端门
 * （FBTERM 环境+isatty）与退出码 70 握手在 occ.c 命令层。
 */
#ifndef OCC_ZOOMRC_H
#define OCC_ZOOMRC_H

#include <stddef.h>

/* 级别表（px，fbterm font-size）；-1 结尾 */
extern const int occ_zoom_sizes[];
extern const char *const occ_zoom_names[];	/* 与 sizes 等长：显示名 */

/* 级别下标 → 字号；idx 越界返回 -1 */
int occ_zoom_size(int idx);
/* 字号 → 级别下标（不在表内=-1） */
int occ_zoom_index(int size);
/* 相对步进：dir=+1 放大/-1 缩小；cur 不在表内按最近档折算；返回新下标 */
int occ_zoom_step(int cur_size, int dir);

/*
 * 编辑 fbtermrc 的 font-size= 行（读写整个文件）：
 *   - 文件不存在：生成最小模板（font-names/font-size/comments）
 *   - 存在：只改 font-size= 行，其余行逐字节保留
 * 返回 0 成功；-1 IO 错误（err 人话）；原子写（tmp+rename）。
 */
int occ_zoom_edit_fbtermrc(const char *path, int size,
			   char *err, size_t errlen);

#endif /* OCC_ZOOMRC_H */
