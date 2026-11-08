/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_inputbox.h - occ TUI 输入框：多行编辑 + 历史 + Tab 补全（T9c2）
 *
 * 模型：单字节缓冲（UTF-8，可含 '\n'）+ 字节游标。键事件由
 * tui_inputbox_key 消费，编辑类动作内部完成并返回 TUI_IN_NONE；
 * 需要视图层响应的动作返回动作码（提交/退出/清空/翻页）。
 *
 * 取舍（报告复用）：
 *   - Enter=提交；shift/ctrl/alt+return 与 ctrl+j=换行（c1 事件位）；
 *   - ↑↓ 历史：光标在首/末行才翻（OCD 语义）；浏览中编辑即脱离浏览；
 *   - Tab 补全：仅缓冲以 '/' 开头且光标在首 token 内——唯一补全加空格、
 *     多命中扩公共前缀、无命中不动（14 指令内置常量，见 tui_inputbox_cmds）；
 *   - bracketed paste：内容原样入缓冲（\r\n 归一为单换行，\t→空格，
 *     其余控制字节丢弃——不进 cell 防乱移光标）；
 *   - 不折行长行：横向偏移保光标可见（转写区才折行）。
 */
#ifndef OCC_TUI_INPUTBOX_H
#define OCC_TUI_INPUTBOX_H

#include "tui_core.h"
#include "tui_input.h"
#include "tui_theme.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tui_inputbox tui_inputbox;

/* 动作码（视图层消费；编辑类=TUI_IN_NONE） */
enum {
	TUI_IN_NONE = 0,
	TUI_IN_SUBMIT,		/* 缓冲非空提交；text=tui_inputbox_text() */
	TUI_IN_EXIT,		/* 空缓冲 ctrl+c/ctrl+d：请求退出 */
	TUI_IN_CLEAR,		/* 非空 ctrl+c/ctrl+d：缓冲已清空 */
	TUI_IN_SCROLL_UP,	/* PgUp：视图上滚转写区 */
	TUI_IN_SCROLL_DOWN	/* PgDn：视图下滚/回底 */
};

tui_inputbox *tui_inputbox_create(const tui_theme *th);
void tui_inputbox_destroy(tui_inputbox *ib);

/* 喂一个键事件（type!=TUI_EV_KEY 的事件忽略）。返回动作码。 */
int tui_inputbox_key(tui_inputbox *ib, const tui_event *ev);

/* 提交后的文本（NUL 结尾；到下一次缓冲变更前有效）；len_out 可 NULL */
const char *tui_inputbox_text(const tui_inputbox *ib, size_t *len_out);
void tui_inputbox_clear(tui_inputbox *ib);
int tui_inputbox_empty(const tui_inputbox *ib);
/* 逻辑行数（'\n' 数 + 1；视图用它算输入区高度并夹到上限） */
int tui_inputbox_lines(const tui_inputbox *ib);

/*
 * 渲染缓冲到 [x, y, x+w, y+h)：超高中只显示含光标的尾部窗口，
 * 光标行超宽时横向偏移保光标可见。光标绝对坐标写入 cur_row/cur_col
 * 出参（供 tui_renderer_flush 定位）。区域右缘==屏幕右缘约定见 tui_view。
 */
void tui_inputbox_render(const tui_inputbox *ib, tui_screen *s,
			 int x, int y, int w, int h,
			 int *cur_row, int *cur_col);

/* 14 条内置 slash 命令（Tab 补全表；view 的 /help 同源）。返回数组指针。 */
const char *const *tui_inputbox_cmds(int *count);

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_INPUTBOX_H */
