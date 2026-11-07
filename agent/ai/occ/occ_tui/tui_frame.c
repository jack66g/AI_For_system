/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_frame.c - 帧节流（30fps）+ SIGWINCH flag 队列化（T9c1）
 */
#include "tui_frame.h"

#include <signal.h>
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
