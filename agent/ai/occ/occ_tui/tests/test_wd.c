/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_wd.c - P-41/P-44 输出看门狗 pty 级回归门
 *
 * wd 超时本身由 test_sinkbuf 在 pipe 单元证明（pty 级造「永不读的假
 * 消费端」不现实——pty 缓冲由内核端排空）。pty 级本套验证回归面：
 *   A. wd 禁用（OCC_TUI_WD_MS=0）时行为与旧版全等——同操作序列在
 *      「直写 fd 汇」（旧版）与「缓冲 fd 汇+wd 禁用+term.bsink」
 *      （新版全链）两子进程产生逐字节相同的输出流（enter/帧/光标
 *      序列/leave——缓冲化只改批次不改字节总序）。
 *   B. wd 缺省（15000）+ 健康消费端（父进程持续读）：不误伤，整流
 *      正常进出、rc=0。
 */
#define _XOPEN_SOURCE 700	/* posix_openpt 三件套（照 test_pty 口径） */
#define _DEFAULT_SOURCE 1

#include "tui_core.h"
#include "tui_view.h"

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

/* ---- 伪终端（照 test_pty 三件套，避免 -lutil） ---- */
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

#define WD_OUT_CAP (256 * 1024)

static uint64_t wd_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* 从 master 收集输出：EOF（子进程退出）返回 1；静默 quiet_ms 返回 0。
 * 纪律：poll 无 POLLIN 绝不 read——阻塞 ptmx 上无数据 read 会死等
 * （心跳静默窗实证：父进程卡死=整套件挂起）。 */
static int collect(int fd, char *buf, int cap, int *have, int quiet_ms)
{
	uint64_t last = wd_now_ms();

	for (;;) {
		struct pollfd p;
		ssize_t n;

		p.fd = fd;
		p.events = POLLIN;
		p.revents = 0;
		if (poll(&p, 1, 200) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!(p.revents & POLLIN)) {
			if (wd_now_ms() - last > (uint64_t)quiet_ms)
				return 0;	/* 静默：先行返回（等收尸定论） */
			continue;
		}
		n = read(fd, buf + *have, (size_t)(cap - *have));
		if (n > 0) {
			*have += (int)n;
			last = wd_now_ms();
			continue;
		}
		if (n == 0 || errno == EIO)
			return 1;		/* EOF（子进程已退） */
		if (errno != EINTR && errno != EAGAIN)
			return -1;
		if (wd_now_ms() - last > (uint64_t)quiet_ms)
			return 0;
		if (*have >= cap)
			return 0;
	}
}

/* 手写子串搜索（memmem 是 GNU 扩展；照 test_view_pty 口径） */
static const char *find_bytes(const char *hay, int haylen,
			      const char *needle)
{
	size_t nlen = strlen(needle);
	int i;

	if (nlen == 0 || haylen < (int)nlen)
		return NULL;
	for (i = 0; i <= haylen - (int)nlen; i++)
		if (memcmp(hay + i, needle, nlen) == 0)
			return hay + i;
	return NULL;
}

/*
 * 子进程：进全屏 → 光标 hide/show（覆盖 bsink 序列路由——buffered 下
 * 进缓冲、直写下直写，字节序一致）→ 画 3 行（SGR/双宽/尾光标 CUP——
 * 覆盖帧字节全谱）→ flush → 退屏 → rc 0。
 * buffered=0：直写 fd 汇（旧版行为）；=1：缓冲 fd 汇+OCC_TUI_WD_MS=0
 * +term.bsink 接 renderer 副本（新版全链）。
 */
static int child_main(int buffered)
{
	tui_term term;
	tui_sink sink;
	tui_renderer *r;
	tui_attr red = tui_attr_default();

	red.fg = tui_color_idx(1);
	red.style = TUI_ST_BOLD;
	tui_term_init(&term, STDOUT_FILENO);
	if (tui_term_enter(&term) != 0)
		return 2;
	if (buffered) {
		/* 新版全链：缓冲 fd 汇（env OCC_TUI_WD_MS 由 run_child
		 * 在 fork 前置位——init 时读取） */
		if (tui_sink_init_fd_buf(&sink, STDOUT_FILENO) != 0)
			return 3;
	} else {
		tui_sink_init_fd(&sink, STDOUT_FILENO);	/* 旧版直写 */
	}
	r = tui_renderer_create(6, 16, sink);
	if (!r)
		return 4;
	if (buffered)
		term.bsink = &r->sink;	/* 光标序列与帧同批 */
	tui_screen_puts(tui_renderer_front(r), 0, 0, "WD-MARK",
			tui_attr_default());
	tui_screen_puts(tui_renderer_front(r), 2, 1,
			"\xe6\xb1\x89\xe5\xad\x97", red);
	tui_screen_puts(tui_renderer_front(r), 4, 3, "tail",
			tui_attr_default());
	tui_term_hide_cursor(&term);
	tui_term_show_cursor(&term);
	if (tui_renderer_flush(r, 5, 8) != 3)
		return 5;
	tui_term_leave(&term);
	tui_renderer_destroy(r);
	return 0;
}

/* 在 pty 上跑一轮子进程，收集全量输出流；返回子进程退出码（异常 -1） */
static int run_child(int buffered, char *out, int *out_len)
{
	struct pty pt;
	pid_t pid;
	int have = 0;
	int st = 0;
	struct winsize ws = { .ws_row = 24, .ws_col = 80 };

	if (pty_open(&pt) != 0)
		return -1;
	(void)ioctl(pt.slave, TIOCSWINSZ, &ws);
	pid = fork();
	if (pid < 0) {
		pty_close(&pt);
		return -1;
	}
	if (pid == 0) {
		close(pt.master);
		if (setsid() < 0)
			_exit(20);
		if (ioctl(pt.slave, TIOCSCTTY, 0) < 0)
			_exit(21);
		if (dup2(pt.slave, STDIN_FILENO) < 0 ||
		    dup2(pt.slave, STDOUT_FILENO) < 0 ||
		    dup2(pt.slave, STDERR_FILENO) < 0)
			_exit(22);
		if (pt.slave > STDERR_FILENO)
			close(pt.slave);
		if (buffered)
			setenv("OCC_TUI_WD_MS", "0", 1);
		_exit(child_main(buffered));
	}
	close(pt.slave);
	pt.slave = -1;
	(void)collect(pt.master, out, WD_OUT_CAP, &have, 400);
	{
		int w;

		for (w = 0; w < 60; w++) {
			if (waitpid(pid, &st, WNOHANG) == pid)
				break;
			usleep(50000);
			(void)collect(pt.master, out, WD_OUT_CAP, &have, 100);
		}
		if (w == 60) {
			kill(pid, SIGKILL);
			waitpid(pid, &st, 0);
			pty_close(&pt);
			return -1;
		}
	}
	pty_close(&pt);
	*out_len = have;
	if (!WIFEXITED(st))
		return -1;
	return WEXITSTATUS(st);
}

/* ---- C. P-41/P-44b 空闲心跳（view 级 pty）---- */

/* 有界收集：dur_ms 内持续读（不看静默——心跳场景要按窗取字节）；
 * 同 collect 纪律：poll 无 POLLIN 绝不 read（防阻塞 ptmx 死等） */
static void collect_for(int fd, char *buf, int cap, int *have, int dur_ms)
{
	uint64_t t0 = wd_now_ms();

	while (wd_now_ms() - t0 < (uint64_t)dur_ms) {
		struct pollfd p;
		ssize_t n;

		p.fd = fd;
		p.events = POLLIN;
		p.revents = 0;
		if (poll(&p, 1, 100) < 0) {
			if (errno == EINTR)
				continue;
			return;
		}
		if (!(p.revents & POLLIN))
			continue;
		n = read(fd, buf + *have, (size_t)(cap - *have));
		if (n > 0) {
			*have += (int)n;
			continue;
		}
		if (n == 0 || errno == EIO)
			return;		/* 子进程已退 */
	}
}

/* 等子串出现（有界）——首帧就绪锚点用 */
static int wait_tok(int fd, char *buf, int cap, int *have, const char *tok,
		    int timeout_ms)
{
	uint64_t t0 = wd_now_ms();

	while (wd_now_ms() - t0 < (uint64_t)timeout_ms) {
		if (find_bytes(buf, *have, tok) != NULL)
			return 0;
		collect_for(fd, buf, cap, have, 200);
	}
	return find_bytes(buf, *have, tok) != NULL ? 0 : -1;
}

/* 校验字节段全是 CUP 序列（\x1b[<r>;<c>H 重复——探针零视觉合同） */
static int is_cup_only(const char *p, int n)
{
	int i = 0;

	while (i < n) {
		int j = i;

		if (p[j] != 0x1b || j + 1 >= n || p[j + 1] != '[')
			return 0;
		j += 2;
		if (j >= n || p[j] < '0' || p[j] > '9')
			return 0;
		while (j < n && p[j] >= '0' && p[j] <= '9')
			j++;
		if (j >= n || p[j] != ';')
			return 0;
		j++;
		if (j >= n || p[j] < '0' || p[j] > '9')
			return 0;
		while (j < n && p[j] >= '0' && p[j] <= '9')
			j++;
		if (j >= n || p[j] != 'H')
			return 0;
		j++;
		i = j;
	}
	return i == n;
}

/* 裸 view 子进程：无 hooks（空态面板）——心跳逻辑与 hooks 无关 */
static int view_child_main(void)
{
	tui_view *v = tui_view_create(NULL);
	int rc;

	if (!v)
		return 10;
	rc = tui_view_run(v);
	tui_view_destroy(v);
	return rc == 0 ? 0 : 11;
}

/*
 * 单轮：spawn 裸 view 子进程（hb_env 非空则置 OCC_TUI_HB_MS）→ 等首帧
 * → 快照 → 空闲 idle_ms 收集 → 校验增量（want_cup：应全为 CUP；否则
 * 应为零）→ /exit → 等 leave → 返回子进程 rc（异常 -1）。*idle_delta
 * 返回空闲增量长度。
 */
static int hb_run(const char *hb_env, int idle_ms, int want_cup,
		  int *idle_delta)
{
	struct pty pt;
	pid_t pid;
	static char out[WD_OUT_CAP];
	int have = 0, snap, st = 0;
	struct winsize ws = { .ws_row = 24, .ws_col = 80 };

	*idle_delta = -1;
	if (pty_open(&pt) != 0)
		return -1;
	(void)ioctl(pt.slave, TIOCSWINSZ, &ws);
	pid = fork();
	if (pid < 0) {
		pty_close(&pt);
		return -1;
	}
	if (pid == 0) {
		close(pt.master);
		if (setsid() < 0)
			_exit(30);
		if (ioctl(pt.slave, TIOCSCTTY, 0) < 0)
			_exit(31);
		if (dup2(pt.slave, STDIN_FILENO) < 0 ||
		    dup2(pt.slave, STDOUT_FILENO) < 0 ||
		    dup2(pt.slave, STDERR_FILENO) < 0)
			_exit(32);
		if (pt.slave > STDERR_FILENO)
			close(pt.slave);
		if (hb_env)
			setenv("OCC_TUI_HB_MS", hb_env, 1);
		else
			unsetenv("OCC_TUI_HB_MS");
		_exit(view_child_main());
	}
	close(pt.slave);
	pt.slave = -1;

	/* 等首帧（空态面板标题）→ 稳定期（首帧批次可能部分写跨 poll 窗，
	 * 等 600ms 静默确保帧完全落地再快照——空闲增量才纯净） */
	if (wait_tok(pt.master, out, WD_OUT_CAP, &have,
		     "AIKernel", 5000) != 0) {
		kill(pid, SIGKILL);
		waitpid(pid, &st, 0);
		pty_close(&pt);
		return -2;
	}
	collect_for(pt.master, out, WD_OUT_CAP, &have, 600);
	snap = have;
	collect_for(pt.master, out, WD_OUT_CAP, &have, idle_ms);
	*idle_delta = have - snap;
	/* 空闲增量校验：心跳开=纯 CUP（≥1 次探针 6 字节；节拍窗内通常
	 * ≥2 次）；心跳关=零字节 */
	if (want_cup)
		OK(*idle_delta >= 6 && is_cup_only(out + snap, *idle_delta),
		   "C1-idle-delta-cup-only");
	else
		OK(*idle_delta == 0, "C2-idle-zero-bytes");

	/* /exit 正常退出（心跳不扰动正常收口） */
	{
		char ex[] = "/exit\r";

		(void)!write(pt.master, ex, sizeof(ex) - 1);
	}
	{
		int w;

		for (w = 0; w < 60; w++) {
			if (waitpid(pid, &st, WNOHANG) == pid)
				break;
			collect_for(pt.master, out, WD_OUT_CAP, &have, 150);
		}
		if (w == 60) {
			kill(pid, SIGKILL);
			waitpid(pid, &st, 0);
			pty_close(&pt);
			return -1;
		}
	}
	pty_close(&pt);
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void hb_scenario(void)
{
	int delta;
	int rc;

	/* C1. HB=1200、空闲 3s：探针到点注入（≥1 次、窗内通常 2-3 次），
	 * 字节全 CUP（零视觉合同） */
	rc = hb_run("1200", 3000, 1, &delta);
	OK(rc == 0, "C1-hb-view-rc0");
	OK(delta >= 6, "C1-hb-injected");

	/* C2. HB=0（禁用）、同窗口：零注入=与无心跳实现输出流逐字节
	 * 全等（回归门——空闲段字节一个不多） */
	rc = hb_run("0", 3000, 0, &delta);
	OK(rc == 0, "C2-hb-off-view-rc0");
	OK(delta == 0, "C2-hb-off-zero-delta");
}

int main(void)
{
	static char out_old[WD_OUT_CAP], out_new[WD_OUT_CAP];
	int old_len = 0, new_len = 0;
	int rc_old, rc_new;

	signal(SIGPIPE, SIG_IGN);	/* EPIPE 以返回值到达（drain 判据同型） */

	/* ---- A. wd 禁用=与旧版全等（回归门） ---- */
	rc_old = run_child(0, out_old, &old_len);
	OK(rc_old == 0, "A-old-child-rc0");
	rc_new = run_child(1, out_new, &new_len);
	OK(rc_new == 0, "A-new-child-rc0");
	if (rc_old == 0 && rc_new == 0) {
		OK(old_len == new_len, "A-stream-length-equal");
		OK(old_len > 0 &&
		   memcmp(out_old, out_new, (size_t)old_len) == 0,
		   "A-stream-bytes-identical");
		OK(find_bytes(out_new, new_len, "WD-MARK") != NULL,
		   "A-frame-content-visible");
		/* 流序健康度：enter 序列开头、leave 序列收尾 */
		OK(new_len > 10 && out_new[0] == 0x1b, "A-enter-first");
		OK(find_bytes(out_new, new_len, "\x1b[?1049l") != NULL,
		   "A-leave-present");
	}

	/* ---- B. wd 缺省（15000）+ 健康消费端：不误伤 ---- */
	unsetenv("OCC_TUI_HB_MS");
	{
		int have = 0;

		rc_new = run_child(1, out_new, &have);
		OK(rc_new == 0, "B-default-wd-rc0");
		OK(find_bytes(out_new, have, "WD-MARK") != NULL,
		   "B-frame-content-visible");
	}

	/* ---- C. P-41/P-44b 空闲心跳（view 级 pty）----
	 * 覆盖真空：wd 只能伴帧输出计时，空闲（零事件/零输出）窗口的
	 * 楔死由心跳探针检出。断言对：
	 *   C1. HB=1200 空闲 3s：注入字节全是 CUP（光标回原位=零视觉）
	 *       且 ≥2 次（节拍到点）；/exit 正常退出 rc=0。
	 *   C2. HB=0（禁用）同窗口：零注入——空闲段输出流与无心跳实现
	 *       逐字节全等（回归门）。 */
	hb_scenario();

	printf("test_wd: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
