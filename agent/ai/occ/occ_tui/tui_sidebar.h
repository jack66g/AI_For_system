/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_sidebar.h - occ TUI 会话侧栏（T9c2 最小版）
 *
 * 固定窄栏 22 列（终端宽 <60 隐藏——布局判定在 tui_view）；当前会话
 * 高亮 + 最近 N 条 + 底部 tokens·pct 行。数据由 occ.c 会话列表填充
 * （只读快照，切换/宽度拖拽/Pinned 归 c3）。
 */
#ifndef OCC_TUI_SIDEBAR_H
#define OCC_TUI_SIDEBAR_H

#include "tui_core.h"
#include "tui_theme.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TUI_SB_WIDTH 22		/* 固定栏宽（含边框列） */
#define TUI_SB_MIN_COLS 60	/* 终端宽低于此隐藏侧栏 */
#define TUI_SB_MAX_ROWS 64

/* 侧栏一行会话（id 截短显示：ses_ 前 8 位 + …） */
typedef struct {
	char id[44];			/* OCC_ID_LEN=40 + NUL */
	char title[96];
	long long tokens;
	char status[16];		/* active/running/... */
	int is_current;
} tui_sb_row;

typedef struct tui_sb_data {
	tui_sb_row rows[TUI_SB_MAX_ROWS];
	int n;
	long long tokens_total;		/* 底部 tokens 行 */
	int pct;			/* token 水位 %；<0=未知 */
} tui_sb_data;

/*
 * 渲染侧栏到 [0, 0, TUI_SB_WIDTH, rows)。
 * 高亮当前会话（accent 反白），非当前 dim；底部 `12.3k · 6%` 行。
 */
void tui_sidebar_render(const tui_sb_data *d, tui_screen *s, int rows,
			const tui_theme *th);

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_SIDEBAR_H */
