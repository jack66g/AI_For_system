/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_pty.c - 伪终端集成测试：进/退序列字节对拍 + 信号恢复（T9c1）
 *
 * 用 POSIX openpty 三件套（posix_openpt/grantpt/unlockpt+ptsname）自建
 * 伪终端（避免 -lutil 依赖）。覆盖：
 *   A. 正常进出：ENTER_SEQ + "MARK" + LEAVE_SEQ + "RESTORED" 逐字节对拍，
 *      且子进程内断言 raw 生效（ICANON/ECHO 关）与恢复（开）、leave 幂等。
 *   B. SIGTERM：处理器恢复终端（LEAVE 字节可见）后按原信号终止。
 *   C. 非 TTY：rc=2、stdout 零字节、stderr 含 "TTY" 人话报错。
 *   D. SIGWINCH：真实 TIOCSWINSZ → 内核投递 → flag 消费 → 尺寸对拍。
 *   E. atexit：exit(0) 路径同样恢复（LEAVE 字节可见）。
 *   F. get_size：正常尺寸 + 0 尺寸兜底 24x80 + 坏 fd -1。
 */
#define _XOPEN_SOURCE 700	/* posix_openpt/grantpt/unlockpt/ptsname (XSI) */
#define _DEFAULT_SOURCE 1

#include "tui_core.h"
#include "tui_frame.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

/* ---- golden 进/退序列（与 tui_term_enter/leave 独立对照） ---- */
static const char ENTER_SEQ[] =
	"\x1b[?1049h\x1b[0m\x1b[2J\x1b[H\x1b[?25l\x1b[?2004h\x1b[?u";
static const char LEAVE_SEQ[] =
	"\x1b[?2004l\x1b[?25h\x1b[0m\x1b[?1049l";

static void dump_hex(const char *tag, const char *buf, int len)
{
	int i;
	printf("  %s(%d):", tag, len);
	for (i = 0; i < len && i < 160; i++)
		printf(" %02x", (unsigned char)buf[i]);
	printf("%s\n", i < len ? " ..." : "");
}

static void ok_bytes(const char *name, const char *got, int glen,
		     const char *want, int wlen)
{
	if (glen == wlen && memcmp(got, want, (size_t)wlen) == 0) {
		n_ok++;
		return;
	}
	n_fail++;
	printf("FAIL %s (line %d)\n", name, __LINE__);
	dump_hex("want", want, wlen);
	dump_hex("got ", got, glen);
}

/* ---- 伪终端（POSIX 三件套） ---- */
struct pty {
	int master;
	int slave;
};

static int pty_open(struct pty *p)
{
	char *name;

	p->master = posix_openpt(O_RDWR | O_NOCTTY);
	if (p->master < 0)
		return -1;
	if (grantpt(p->master) != 0 || unlockpt(p->master) != 0) {
		close(p->master);
		return -1;
	}
	name = ptsname(p->master);
	if (!name) {
		close(p->master);
		return -1;
	}
	p->slave = open(name, O_RDWR | O_NOCTTY);
	if (p->slave < 0) {
		close(p->master);
		return -1;
	}
	return 0;
}

static void pty_close(struct pty *p)
{
	if (p->slave >= 0)
		close(p->slave);
	if (p->master >= 0)
		close(p->master);
	p->slave = p->master = -1;
}

/* 从 fd 收集输出：直到 EOF（返回1）或超时（返回0）或错误（-1） */
static int read_until_eof(int fd, char *buf, int cap, int *have, int timeout_ms)
{
	while (*have < cap) {
		struct pollfd p;
		int r;

		p.fd = fd;
		p.events = POLLIN;
		p.revents = 0;
		r = poll(&p, 1, timeout_ms);
		if (r == 0)
			return 0;
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		{
			ssize_t n = read(fd, buf + *have, (size_t)(cap - *have));
			if (n > 0) {
				*have += (int)n;
				continue;
			}
			if (n == 0)
				return 1;	/* EOF */
			if (errno == EINTR)
				continue;
			if (errno == EIO)	/* slave 已关 */
				return 1;
			return -1;
		}
	}
	return 1;
}

/* 收集直到出现 need 字节（或 EOF/超时）——凑够即返回，不等 EOF。
 * T9c1 收尾修：旧实现复用 read_until_eof（其合同=读到 EOF 才返回），
 * 导致父进程阻塞到子进程退出（winch 子进程 3s 等 flag 超时 rc=17），
 * read_until_eof 报 EOF 后未先检查 have>=need 就返回失败——三连败瀑布。
 * 新实现自带 poll 循环 + 单调时钟总预算（超时未凑够=-1）。 */
static int read_until_need(int fd, char *buf, int cap, int *have,
			   int need, int timeout_ms)
{
	struct timespec start, now;
	long long remain_ms;

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		return -1;
	while (*have < need && *have < cap) {
		struct pollfd p;
		int r;
		ssize_t n;

		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return -1;
		remain_ms = timeout_ms -
			((now.tv_sec - start.tv_sec) * 1000LL +
			 (now.tv_nsec - start.tv_nsec) / 1000000LL);
		if (remain_ms <= 0)
			return -1;
		p.fd = fd;
		p.events = POLLIN;
		p.revents = 0;
		r = poll(&p, 1, (int)remain_ms);
		if (r == 0)
			return -1;
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		n = read(fd, buf + *have, (size_t)(cap - *have));
		if (n > 0) {
			*have += (int)n;
			continue;
		}
		if (n == 0)
			return *have >= need ? 0 : 1;
		if (errno == EINTR)
			continue;
		if (errno == EIO)
			return *have >= need ? 0 : 1;
		return -1;
	}
	return *have >= need ? 0 : -1;
}

/* ---- 子进程模式 ---- */

static int child_enter_leave(void)
{
	tui_term t;
	struct termios ts;

	tui_term_init(&t, STDOUT_FILENO);
	if (tui_term_enter(&t) != 0)
		return 10;
	/* raw 生效断言 */
	if (tcgetattr(0, &ts) != 0)
		return 11;
	if ((ts.c_lflag & ICANON) || (ts.c_lflag & ECHO))
		return 12;
	if (write(1, "MARK", 4) != 4)
		return 13;
	tui_term_leave(&t);
	/* 恢复断言 */
	if (tcgetattr(0, &ts) != 0)
		return 14;
	if (!(ts.c_lflag & ICANON) || !(ts.c_lflag & ECHO))
		return 15;
	tui_term_leave(&t);		/* 幂等：不再吐字节 */
	if (write(1, "RESTORED", 8) != 8)
		return 16;
	return 0;
}

static int child_signal(void)
{
	tui_term t;
	struct termios ts;

	tui_term_init(&t, STDOUT_FILENO);
	if (tui_term_enter(&t) != 0)
		return 10;
	if (tcgetattr(0, &ts) != 0)
		return 11;
	if ((ts.c_lflag & ICANON) || (ts.c_lflag & ECHO))
		return 12;
	if (write(1, "MARK", 4) != 4)
		return 13;
	for (;;)
		pause();		/* 等父进程信号 */
}

static int child_winch(void)
{
	tui_term t;
	int i;

	tui_term_init(&t, STDOUT_FILENO);
	if (tui_term_enter(&t) != 0)
		return 10;
	if (write(1, "MARK", 4) != 4)
		return 11;
	for (i = 0; i < 300; i++) {	/* 最多等 3s */
		if (tui_frame_winch_take()) {
			int r = -1, c = -1;
			char sz[32];
			int n;

			if (tui_term_get_size(1, &r, &c) != 0)
				return 12;
			n = snprintf(sz, sizeof(sz), "SZ%dx%d", r, c);
			if (n <= 0 || strcmp(sz, "SZ30x100") != 0)
				return 13;
			if (write(1, sz, (size_t)n) != (ssize_t)n)
				return 14;
			tui_term_leave(&t);
			return 0;
		}
		{
			struct timespec ts;
			ts.tv_sec = 0;
			ts.tv_nsec = 10 * 1000 * 1000;
			nanosleep(&ts, NULL);
		}
	}
	return 17;			/* 超时：flag 未达 */
}

static int child_atexit(void)
{
	tui_term t;

	tui_term_init(&t, STDOUT_FILENO);
	if (tui_term_enter(&t) != 0)
		return 10;
	if (write(1, "MARK", 4) != 4)
		return 11;
	exit(0);			/* atexit → leave */
}

static int child_nontty(void)
{
	tui_term t;

	tui_term_init(&t, STDOUT_FILENO);
	return tui_term_enter(&t);	/* 期望 2 */
}

/* B5：鼠标开关字节黄金——enable/disable/幂等/leave 复位 */
static int child_mouse_golden(void)
{
	tui_term t;

	tui_term_init(&t, STDOUT_FILENO);
	setenv("TERM", "xterm-256color", 1);
	/* 未进屏：-1 不发字节 */
	if (tui_mouse_enable(&t, 1) != -1)
		return 20;
	if (tui_mouse_active(&t))
		return 21;
	if (tui_term_enter(&t) != 0)
		return 10;
	if (write(1, "A", 1) != 1)
		return 11;
	if (tui_mouse_enable(&t, 1) != 0)	/* 开：CSI ? 1000;1006 h */
		return 22;
	if (!tui_mouse_active(&t))
		return 23;
	if (tui_mouse_enable(&t, 1) != 0)	/* 幂等：不再发字节 */
		return 24;
	if (write(1, "B", 1) != 1)
		return 12;
	if (tui_mouse_enable(&t, 0) != 0)	/* 关：CSI ? 1000;1006 l */
		return 25;
	if (tui_mouse_enable(&t, 1) != 0)	/* 再开（leave 前挂起） */
		return 26;
	tui_term_leave(&t);			/* mouse_on → 前置鼠标复位 */
	return 0;
}

/* B5：TERM=dumb 诚实降级——enable 拒绝且零字节 */
static int child_mouse_dumb(void)
{
	tui_term t;

	setenv("TERM", "dumb", 1);
	tui_term_init(&t, STDOUT_FILENO);
	if (tui_term_enter(&t) != 0)
		return 10;
	if (tui_mouse_enable(&t, 1) != -1)
		return 27;
	if (tui_mouse_active(&t))
		return 28;
	if (write(1, "D", 1) != 1)
		return 13;
	tui_term_leave(&t);
	return 0;
}

typedef int (*child_fn)(void);

/* fork 一个 pty 子进程：完成 setsid+TIOCSCTTY+stdio 重定向后跑 fn */
static pid_t spawn_pty_child(struct pty *p, child_fn fn)
{
	pid_t pid;

	fflush(NULL);			/* 防 exit() 冲刷父缓冲污染黄金字节 */
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		close(p->master);
		setsid();
		ioctl(p->slave, TIOCSCTTY, 0);
		dup2(p->slave, 0);
		dup2(p->slave, 1);
		dup2(p->slave, 2);
		if (p->slave > 2)
			close(p->slave);
		_exit(fn());
	}
	close(p->slave);
	p->slave = -1;
	return pid;
}

/* ---- 测试 ---- */

static void test_enter_leave_bytes(void)
{
	struct pty p;
	char buf[4096];
	char want[256];
	int have = 0, wlen, st = 0;
	pid_t pid;

	memset(&p, -1, sizeof(p));
	if (pty_open(&p) != 0) {
		n_fail++;
		printf("FAIL pty-open (line %d)\n", __LINE__);
		return;
	}
	pid = spawn_pty_child(&p, child_enter_leave);
	OK(pid > 0, "el-spawn");
	if (pid > 0) {
		int eof = read_until_eof(p.master, buf, sizeof(buf), &have,
					 5000);
		OK(eof == 1, "el-eof");
		waitpid(pid, &st, 0);
		OK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
		   "el-child-exit0");
		if (WIFEXITED(st) && WEXITSTATUS(st) != 0)
			printf("  child rc=%d\n", WEXITSTATUS(st));
		wlen = snprintf(want, sizeof(want), "%sMARK%sRESTORED",
				ENTER_SEQ, LEAVE_SEQ);
		ok_bytes("el-bytes", buf, have, want, wlen);
	}
	pty_close(&p);
}

static void test_signal_restore(void)
{
	struct pty p;
	char buf[4096];
	char want[256];
	int have = 0, wlen, st = 0;
	pid_t pid;

	memset(&p, -1, sizeof(p));
	if (pty_open(&p) != 0) {
		n_fail++;
		printf("FAIL pty-open (line %d)\n", __LINE__);
		return;
	}
	pid = spawn_pty_child(&p, child_signal);
	OK(pid > 0, "sig-spawn");
	if (pid > 0) {
		/* 等 MARK（证明已进 raw） */
		int r = read_until_need(p.master, buf, sizeof(buf), &have,
					(int)strlen(ENTER_SEQ) + 4, 5000);
		OK(r == 0, "sig-got-mark");
		kill(pid, SIGTERM);
		r = read_until_eof(p.master, buf, sizeof(buf), &have, 5000);
		OK(r == 1, "sig-eof");
		waitpid(pid, &st, 0);
		OK(WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM,
		   "sig-died-by-sigterm");
		wlen = snprintf(want, sizeof(want), "%sMARK%s",
				ENTER_SEQ, LEAVE_SEQ);
		ok_bytes("sig-bytes", buf, have, want, wlen);
	}
	pty_close(&p);
}

static void test_nontty(void)
{
	int po[2], pe[2];
	char out[256], err[512];
	int ohave = 0, ehave = 0, st = 0;
	pid_t pid;

	fflush(NULL);
	if (pipe(po) != 0 || pipe(pe) != 0) {
		n_fail++;
		printf("FAIL nontty-pipe (line %d)\n", __LINE__);
		return;
	}
	pid = fork();
	if (pid < 0) {
		n_fail++;
		printf("FAIL nontty-fork (line %d)\n", __LINE__);
		return;
	}
	if (pid == 0) {
		close(po[0]);
		close(pe[0]);
		dup2(po[1], 1);
		dup2(pe[1], 2);
		close(po[1]);
		close(pe[1]);
		_exit(child_nontty());
	}
	close(po[1]);
	close(pe[1]);
	waitpid(pid, &st, 0);
	OK(WIFEXITED(st) && WEXITSTATUS(st) == 2, "nontty-rc2");
	read_until_eof(po[0], out, sizeof(out), &ohave, 2000);
	read_until_eof(pe[0], err, sizeof(err), &ehave, 2000);
	close(po[0]);
	close(pe[0]);
	OK(ohave == 0, "nontty-stdout-empty");
	err[ehave < (int)sizeof(err) ? ehave : (int)sizeof(err) - 1] = '\0';
	OK(strstr(err, "TTY") != NULL, "nontty-msg-tty");
	OK(strstr(err, "occ_tui") != NULL, "nontty-msg-prefix");
}

static void test_winch_real_signal(void)
{
	struct pty p;
	char buf[4096];
	char want[256];
	int have = 0, wlen, st = 0;
	pid_t pid;
	struct winsize ws;

	memset(&p, -1, sizeof(p));
	if (pty_open(&p) != 0) {
		n_fail++;
		printf("FAIL pty-open (line %d)\n", __LINE__);
		return;
	}
	pid = spawn_pty_child(&p, child_winch);
	OK(pid > 0, "winch-spawn");
	if (pid > 0) {
		int r = read_until_need(p.master, buf, sizeof(buf), &have,
					(int)strlen(ENTER_SEQ) + 4, 5000);
		OK(r == 0, "winch-got-mark");
		ws.ws_row = 30;
		ws.ws_col = 100;
		ws.ws_xpixel = 0;
		ws.ws_ypixel = 0;
		OK(ioctl(p.master, TIOCSWINSZ, &ws) == 0, "winch-set-size");
		r = read_until_eof(p.master, buf, sizeof(buf), &have, 5000);
		OK(r == 1, "winch-eof");
		waitpid(pid, &st, 0);
		OK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
		   "winch-child-exit0");
		if (WIFEXITED(st) && WEXITSTATUS(st) != 0)
			printf("  child rc=%d\n", WEXITSTATUS(st));
		wlen = snprintf(want, sizeof(want), "%sMARKSZ30x100%s",
				ENTER_SEQ, LEAVE_SEQ);
		ok_bytes("winch-bytes", buf, have, want, wlen);
	}
	pty_close(&p);
}

static void test_atexit_restore(void)
{
	struct pty p;
	char buf[4096];
	char want[256];
	int have = 0, wlen, st = 0;
	pid_t pid;

	memset(&p, -1, sizeof(p));
	if (pty_open(&p) != 0) {
		n_fail++;
		printf("FAIL pty-open (line %d)\n", __LINE__);
		return;
	}
	pid = spawn_pty_child(&p, child_atexit);
	OK(pid > 0, "atexit-spawn");
	if (pid > 0) {
		int eof = read_until_eof(p.master, buf, sizeof(buf), &have,
					 5000);
		OK(eof == 1, "atexit-eof");
		waitpid(pid, &st, 0);
		OK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
		   "atexit-child-exit0");
		wlen = snprintf(want, sizeof(want), "%sMARK%s",
				ENTER_SEQ, LEAVE_SEQ);
		ok_bytes("atexit-bytes", buf, have, want, wlen);
	}
	pty_close(&p);
}

static void test_get_size(void)
{
	struct pty p;
	struct winsize ws;
	int r = -1, c = -1;

	memset(&p, -1, sizeof(p));
	if (pty_open(&p) != 0) {
		n_fail++;
		printf("FAIL pty-open (line %d)\n", __LINE__);
		return;
	}
	ws.ws_row = 40;
	ws.ws_col = 120;
	ws.ws_xpixel = 0;
	ws.ws_ypixel = 0;
	OK(ioctl(p.master, TIOCSWINSZ, &ws) == 0, "size-set");
	OK(tui_term_get_size(p.master, &r, &c) == 0 && r == 40 && c == 120,
	   "size-get");
	ws.ws_row = 0;
	ws.ws_col = 0;
	OK(ioctl(p.master, TIOCSWINSZ, &ws) == 0, "size-set-zero");
	OK(tui_term_get_size(p.master, &r, &c) == 0 && r == 24 && c == 80,
	   "size-zero-fallback");
	OK(tui_term_get_size(-1, &r, &c) == -1, "size-badfd");
	pty_close(&p);
}

/* B5：鼠标模式字节黄金（TERM=xterm-256color）
 * 期望流 = ENTER + A + MON + B + MOFF + MON + MOFF(leave 前置) + LEAVE */
static void test_mouse_mode_bytes(void)
{
	struct pty p;
	char buf[4096];
	char want[512];
	int have = 0, wlen, st = 0;
	pid_t pid;

	memset(&p, -1, sizeof(p));
	if (pty_open(&p) != 0) {
		n_fail++;
		printf("FAIL pty-open (line %d)\n", __LINE__);
		return;
	}
	pid = spawn_pty_child(&p, child_mouse_golden);
	OK(pid > 0, "mm-spawn");
	if (pid > 0) {
		int eof = read_until_eof(p.master, buf, sizeof(buf), &have,
					 5000);

		OK(eof == 1, "mm-eof");
		waitpid(pid, &st, 0);
		OK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "mm-child-exit0");
		if (WIFEXITED(st) && WEXITSTATUS(st) != 0)
			printf("  child rc=%d\n", WEXITSTATUS(st));
		wlen = snprintf(want, sizeof(want),
				"%sA\x1b[?1000;1006hB\x1b[?1000;1006l"
				"\x1b[?1000;1006h\x1b[?1000;1006l%s",
				ENTER_SEQ, LEAVE_SEQ);
		ok_bytes("mm-bytes", buf, have, want, wlen);
	}
	pty_close(&p);
}

/* B5：TERM=dumb——enable 拒绝、零鼠标字节、leave 与黄金一致 */
static void test_mouse_dumb_degrade(void)
{
	struct pty p;
	char buf[4096];
	char want[256];
	int have = 0, wlen, st = 0;
	pid_t pid;

	memset(&p, -1, sizeof(p));
	if (pty_open(&p) != 0) {
		n_fail++;
		printf("FAIL pty-open (line %d)\n", __LINE__);
		return;
	}
	pid = spawn_pty_child(&p, child_mouse_dumb);
	OK(pid > 0, "md-spawn");
	if (pid > 0) {
		int eof = read_until_eof(p.master, buf, sizeof(buf), &have,
					 5000);

		OK(eof == 1, "md-eof");
		waitpid(pid, &st, 0);
		OK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "md-child-exit0");
		if (WIFEXITED(st) && WEXITSTATUS(st) != 0)
			printf("  child rc=%d\n", WEXITSTATUS(st));
		wlen = snprintf(want, sizeof(want), "%sD%s", ENTER_SEQ,
				LEAVE_SEQ);
		ok_bytes("md-bytes", buf, have, want, wlen);
	}
	pty_close(&p);
}

int main(void)
{
	signal(SIGPIPE, SIG_IGN);
	test_enter_leave_bytes();
	test_signal_restore();
	test_nontty();
	test_winch_real_signal();
	test_atexit_restore();
	test_get_size();
	test_mouse_mode_bytes();
	test_mouse_dumb_degrade();
	printf("test_pty: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
