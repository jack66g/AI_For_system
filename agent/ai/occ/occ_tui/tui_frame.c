/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_frame.c - 帧节流（30fps）+ SIGWINCH flag 队列化（T9c1）
 *             + E 方案框线原语（U+2500 系单线框，零外部依赖）
 */
#include "tui_frame.h"

#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

void tui_frame_init(tui_frame *f)
{
	f->last_ms = 0;
	f->interval_ms = TUI_FRAME_MS;
	f->inited = 0;
}

void tui_frame_set_interval(tui_frame *f, uint64_t ms)
{
	f->interval_ms = ms ? ms : TUI_FRAME_MS;
}

int tui_frame_due(const tui_frame *f, uint64_t now_ms)
{
	if (!f->inited)
		return 1;
	return now_ms - f->last_ms >= f->interval_ms;
}

void tui_frame_mark(tui_frame *f, uint64_t now_ms)
{
	f->last_ms = now_ms;
	f->inited = 1;
}

uint64_t tui_frame_wait_ms(const tui_frame *f, uint64_t now_ms)
{
	if (!f->inited)
		return 0;
	if (now_ms - f->last_ms >= f->interval_ms)
		return 0;
	return f->interval_ms - (now_ms - f->last_ms);
}

/* SIGWINCH 只置 flag：信号处理器内仅写 sig_atomic_t，零嵌套安全问题 */
static volatile sig_atomic_t g_winch;

void tui_frame_winch_flag_set(void)
{
	g_winch = 1;
}

int tui_frame_winch_take(void)
{
	sig_atomic_t v = g_winch;
	g_winch = 0;
	return v ? 1 : 0;
}

int tui_frame_check_resize(int fd, int *rows, int *cols)
{
	struct winsize ws;

	if (!tui_frame_winch_take())
		return 0;
	if (fd < 0 || ioctl(fd, TIOCGWINSZ, &ws) != 0)
		return -1;
	*rows = ws.ws_row;
	if (cols)
		*cols = ws.ws_col;
	return 1;
}

/* ---- E 方案框线原语 ---- */

#define TUI_FRAME_FILL_MAX 340

void tui_frame_box(tui_screen *s, int x, int y, int w, int h, tui_attr a)
{
	char fill[TUI_FRAME_FILL_MAX * 3];
	int i, n;

	if (!s || w < 2 || h < 2)
		return;
	n = w - 2;
	if (n > TUI_FRAME_FILL_MAX)
		n = TUI_FRAME_FILL_MAX;
	for (i = 0; i < n; i++)
		memcpy(fill + i * 3, "─", 3);
	/* 上下横线（先横后角：角字覆盖顶点） */
	if (n > 0) {
		(void)tui_screen_put(s, y, x + 1, fill, (size_t)n * 3, a);
		(void)tui_screen_put(s, y + h - 1, x + 1, fill, (size_t)n * 3,
				     a);
	}
	(void)tui_screen_put(s, y, x, "┌", 3, a);
	(void)tui_screen_put(s, y, x + w - 1, "┐", 3, a);
	(void)tui_screen_put(s, y + h - 1, x, "└", 3, a);
	(void)tui_screen_put(s, y + h - 1, x + w - 1, "┘", 3, a);
	for (i = 1; i < h - 1; i++) {
		(void)tui_screen_put(s, y + i, x, "│", 3, a);
		(void)tui_screen_put(s, y + i, x + w - 1, "│", 3, a);
	}
}

void tui_frame_divider(tui_screen *s, int x, int y, int h, tui_attr a)
{
	int i;

	if (!s || h < 2)
		return;
	(void)tui_screen_put(s, y, x, "┬", 3, a);
	(void)tui_screen_put(s, y + h - 1, x, "┴", 3, a);
	for (i = 1; i < h - 1; i++)
		(void)tui_screen_put(s, y + i, x, "│", 3, a);
}
