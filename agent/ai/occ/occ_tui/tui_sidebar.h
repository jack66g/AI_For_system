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

/* 侧栏一行会话（T1：不再显示 id——只显标题；status 决定行尾标记/颜色） */
typedef struct {
	char id[44];			/* OCC_ID_LEN=40 + NUL */
	char title[96];
	long long tokens;
	char status[16];		/* active/running/... */
	int is_current;
} tui_sb_row;

typedef struct tui_sb_data {
	tui_sb_row rows[TUI_SB_MAX_ROWS];
	int n;				/* rows 有效条数（≤ TUI_SB_MAX_ROWS） */
	int total;			/* 会话总数（真值；>n=列表已截断） */
	long long tokens_total;		/* 底部 tokens 行 */
	int pct;			/* token 水位 %；<0=未知 */
} tui_sb_data;

/*
 * 渲染侧栏到 [0, 0, TUI_SB_WIDTH, rows)。
 * 标题行 `sessions` + dim 细线；会话行只显标题（21 列内裁剪，末列留给
 * 视图层分隔线/滚动条）；当前行 `▎`+FG 加粗；status=error 用 ERROR 色
 * + 行尾 ×、interrupted 行尾 …；条数溢出时末行 `… +N 个（/sessions）`。
 * 底部 `12.3k · 6%` 行。
 */
void tui_sidebar_render(const tui_sb_data *d, tui_screen *s, int rows,
			const tui_theme *th);

/*
 * E 方案：框线面板内的会话列表（rect (x,y,w,h)=框内净区，框线由
 * tui_view 原语围出）。零栏目名/零计数——只渲会话行（▎当前条 / ×error /
 * …interrupted / 溢出 `… +N 个（/sessions）`），样式沿用 T1。
 */
void tui_sidebar_render_panel(const tui_sb_data *d, tui_screen *s,
			      int x, int y, int w, int h,
			      const tui_theme *th);

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_SIDEBAR_H */
