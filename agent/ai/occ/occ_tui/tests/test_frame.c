/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_frame.c - 帧节流（30fps）+ SIGWINCH flag 测试（T9c1）
 *
 * 时钟可注入（假时钟）断言节流边界；resize flag 只置/只消费一次；
 * check_resize 对坏 fd 返回 -1 且消费 flag。
 */
#include "tui_frame.h"

#include <signal.h>
#include <stdio.h>

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

static void test_throttle(void)
{
	tui_frame f;

	tui_frame_init(&f);
	OK(f.interval_ms == TUI_FRAME_MS, "frame-default-interval");
	OK(TUI_FRAME_MS == 33, "frame-30fps-intentional");	/* PLAN 有意差异 */

	/* 首帧立即到期 */
	OK(tui_frame_due(&f, 0) == 1, "frame-first-due");

	/* mark(100) 后：100+32 不到期，100+33 到期 */
	tui_frame_mark(&f, 100);
	OK(tui_frame_due(&f, 100) == 0, "frame-0ms-not-due");
	OK(tui_frame_due(&f, 132) == 0, "frame-32ms-not-due");
	OK(tui_frame_due(&f, 133) == 1, "frame-33ms-due");
	OK(tui_frame_due(&f, 200) == 1, "frame-late-due");

	/* wait_ms 提示 */
	OK(tui_frame_wait_ms(&f, 100) == 33, "frame-wait-33");
	OK(tui_frame_wait_ms(&f, 110) == 23, "frame-wait-23");
	OK(tui_frame_wait_ms(&f, 133) == 0, "frame-wait-0");

	/* mark 推进基准 */
	tui_frame_mark(&f, 133);
	OK(tui_frame_due(&f, 165) == 0, "frame-remark-32ms");
	OK(tui_frame_due(&f, 166) == 1, "frame-remark-33ms");

	/* 可配间隔 */
	tui_frame_set_interval(&f, 50);
	OK(f.interval_ms == 50, "frame-set-interval");
	OK(tui_frame_due(&f, 182) == 0, "frame-50ms-not-due");
	OK(tui_frame_due(&f, 183) == 1, "frame-50ms-due");

	/* 间隔 0 → 回落默认 */
	tui_frame_set_interval(&f, 0);
	OK(f.interval_ms == TUI_FRAME_MS, "frame-interval-zero-fallback");
}

static void test_winch_flag(void)
{
	int rows = -1, cols = -1;

	/* 清残留 */
	while (tui_frame_winch_take())
		;
	OK(tui_frame_winch_take() == 0, "winch-clear-initial");

	/* 置一次消费一次（幂等置位：两次 set 仍只 take 到 1） */
	tui_frame_winch_flag_set();
	tui_frame_winch_flag_set();
	OK(tui_frame_winch_take() == 1, "winch-take-1");
	OK(tui_frame_winch_take() == 0, "winch-take-0-after");

	/* check_resize：无 flag → 0（不碰 ioctl） */
	OK(tui_frame_check_resize(-1, &rows, &cols) == 0, "winch-check-none");

	/* 有 flag 但坏 fd → -1，flag 已消费 */
	tui_frame_winch_flag_set();
	OK(tui_frame_check_resize(-1, &rows, &cols) == -1, "winch-check-badfd");
	OK(tui_frame_winch_take() == 0, "winch-check-consumed");

	/* 真信号路径：raise(SIGWINCH) → 处理器置 flag（需处理器已装；
	 * 本进程未装 → 默认动作是忽略？ SIGWINCH 默认忽略但不置 flag，
	 * 所以直接验证 flag API + 单独的处理器安装在 pty 集成测试里做） */
	tui_frame_winch_flag_set();
	OK(tui_frame_winch_take() == 1, "winch-flag-api");
}

int main(void)
{
	test_throttle();
	test_winch_flag();
	printf("test_frame: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
