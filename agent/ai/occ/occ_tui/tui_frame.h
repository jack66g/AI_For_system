/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_frame.h - occ_tui 帧节流 + resize 队列化（T9c1）+ E 框线原语
 *
 *   - 30fps 帧节流（PLAN §4.1 有意差异：opencode 60fps → occ 30fps，
 *     编码智能体不需要 60——记录在案）；时钟可注入（单测假时钟）。
 *   - SIGWINCH → 只置 flag（信号处理器内零嵌套安全问题），主循环
 *     tui_frame_winch_take / tui_frame_check_resize 消费后才重绘。
 *   - E 方案框线原语（纯 U+2500 系 box-drawing 文本字符，零外部依赖）：
 *     单线框 + 框内分隔立柱（C 形态面板合体用）。
 */
#ifndef OCC_TUI_FRAME_H
#define OCC_TUI_FRAME_H

#include <stdint.h>

#include "tui_core.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TUI_FRAME_MS 33u	/* 30fps 上限（1000/30 向下取整） */

typedef struct {
	uint64_t last_ms;	/* 上次渲染时刻 */
	uint64_t interval_ms;	/* 帧间隔，默认 TUI_FRAME_MS */
	int inited;		/* 是否已渲染过（首帧立即到期） */
} tui_frame;

void tui_frame_init(tui_frame *f);
void tui_frame_set_interval(tui_frame *f, uint64_t ms);
/* 1=到点该渲染（首帧或距上次渲染 >= interval） */
int tui_frame_due(const tui_frame *f, uint64_t now_ms);
void tui_frame_mark(tui_frame *f, uint64_t now_ms);
/* 距下次可渲染的毫秒数（poll 睡眠提示）；0=现在就可渲染 */
uint64_t tui_frame_wait_ms(const tui_frame *f, uint64_t now_ms);

/* ---- resize：信号只置 flag ---- */
void tui_frame_winch_flag_set(void);	/* SIGWINCH 处理器调（只写 sig_atomic） */
int tui_frame_winch_take(void);		/* 消费：1=有未处理 resize */
/*
 * take + TIOCGWINSZ 一步到位：
 *   1=拿到新尺寸（rows/cols 已写）
 *   0=无 pending resize（未调用 ioctl）
 *  -1=有 resize 但 ioctl 失败（flag 已消费，调用方保留旧尺寸）
 */
int tui_frame_check_resize(int fd, int *rows, int *cols);

/* ---- E 方案框线原语（框线零文字；字形白名单 U+2500 系） ---- */
/*
 * 单线框：┌─┐ / │ │ / └─┘ 画在 (x,y,w,h) 矩形边线上（含边）。
 * w<2 或 h<2 退化为空操作（防御窄屏）。框线属性 a（一般 dim）。
 */
void tui_frame_box(tui_screen *s, int x, int y, int w, int h, tui_attr a);
/*
 * 框内分隔立柱（C 形态：左右面板合体共用框线）：列 x、行 [y, y+h-1]，
 * 上下行顶点用 ┬/┴ 与横线合流，中段 │。调用方保证 x 在框内。
 */
void tui_frame_divider(tui_screen *s, int x, int y, int h, tui_attr a);

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_FRAME_H */
