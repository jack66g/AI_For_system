/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_gate_pty.c - q17 回归：gate 输入泵端到端（pty 驱动 SETUP/LOGIN）
 *
 * 背景（q17 audit A-1，实机抓获）：gate 只出队（tui_input_next）不进队
 * （无人 read+tui_input_feed）——首屏画完即冻死，掩码/两段确认/3 错冷却
 * 在实机全部不可达。本测试在真 pty 上驱动 tui_gate_enter() 全流：
 *   A. SETUP：短密码 →「至少 6 位」；两次不一致 →「两次不一致」；
 *      正确×2 → tui_gate_enter()==0 + 凭据文件 0600 + admin:$6$ 前缀。
 *      （掩码/错误消息随按键重绘=输入泵活的直接证据。）
 *   B. LOGIN：错误密码×3 →「尝试过多，冷却」（泵+计数+冷却路径）。
 *   C. 双控制台覆写守卫（q17 覆写探针）：SETUP 提交时凭据文件已存在
 *      → 拒写转 LOGIN（「密码已由其他控制台设置」）。
 */
#define _XOPEN_SOURCE 700	/* posix_openpt/grantpt/unlockpt/ptsname */
#define _DEFAULT_SOURCE 1
#define _GNU_SOURCE 1		/* ptsname_r */

#include "tui_gate.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int fails;

#define CHECK(cond) do { \
	if (!(cond)) { fails++; \
		printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

static char acc[65536];
static size_t acc_n;
static char g_last[160];			/* P-2a：last-user 隔离桩路径 */

static int find_tok(const char *tok)
{
	size_t tl = strlen(tok);
	size_t i;

	if (tl == 0 || acc_n < tl)
		return 0;
	for (i = 0; i + tl <= acc_n; i++)
		if (memcmp(acc + i, tok, tl) == 0)
			return 1;
	return 0;
}

static int wait_tok(int mfd, const char *tok, int sec)
{
	time_t t0 = time(NULL);
	struct pollfd p = { .fd = mfd, .events = POLLIN };

	while (time(NULL) - t0 < sec) {
		if (find_tok(tok))
			return 1;
		if (poll(&p, 1, 400) > 0 && (p.revents & POLLIN)) {
			ssize_t n = read(mfd, acc + acc_n, 512);

			if (n <= 0)
				break;
			acc_n += (size_t)n;
			if (acc_n > sizeof(acc) - 1024)
				acc_n = 0;	/* 溢出保护：重accum */
		}
	}
	if (!find_tok(tok)) {
		size_t from = acc_n > 300 ? acc_n - 300 : 0;

		printf("[wait_tok miss %s] tail: %.*s\n", tok,
		       (int)(acc_n - from), acc + from);
	}
	return find_tok(tok);
}

static void feed(int mfd, const char *s)
{
	size_t n = strlen(s);
	char cr = '\r';

	(void)!write(mfd, s, n);
	(void)!write(mfd, &cr, 1);
}

/* P-2a：原样写字节（Tab/退格等控制键——feed 会补 \r 破坏控制流） */
static void feedraw(int mfd, const char *s)
{
	(void)!write(mfd, s, strlen(s));
}

/* 限时等子进程退出（q17 教训：waitpid 第三参是 flags 不是秒——
 * $6$ crypt ~200ms，误传 15=WNOHANG 组会在解锁完成前抢跑断言失败） */
static int wait_exit(pid_t pid, int *status, int sec)
{
	time_t t0 = time(NULL);

	while (time(NULL) - t0 < sec) {
		if (waitpid(pid, status, WNOHANG) == pid)
			return 1;
		usleep(100000);
	}
	return waitpid(pid, status, WNOHANG) == pid;
}

/* 起 gate 子进程：stdin/stdout=pty slave；返回 master fd，*pid 出参 */
static int spawn_gate(const char *path, pid_t *pid)
{
	int m = posix_openpt(O_RDWR | O_NOCTTY);
	char slave[128];
	struct winsize wz = { .ws_row = 24, .ws_col = 80 };

	if (m < 0)
		return -1;
	if (grantpt(m) != 0 || unlockpt(m) != 0) {
		close(m);
		return -1;
	}
	if (ptsname_r(m, slave, sizeof(slave)) != 0) {
		close(m);
		return -1;
	}
	*pid = fork();
	if (*pid < 0) {
		close(m);
		return -1;
	}
	if (*pid == 0) {
		int s = open(slave, O_RDWR);

		if (s < 0)
			_exit(99);
		setsid();
		/* TIOCSCTTY 尽力而为：gate 只按 stdin 是 tty 工作 */
		(void)!ioctl(s, TIOCSCTTY, 0);
		dup2(s, 0);
		dup2(s, 1);
		dup2(s, 2);
		if (s > 2)
			close(s);
		close(m);
		setenv("AIK_CONSOLE_GATE", path, 1);
		setenv("AIK_CONSOLE_GATE_LAST", g_last, 1);
		unsetenv("AIK_CONSOLE_GATE_SKIP");
		_exit(tui_gate_enter() == 0 ? 0 : 42);
	}
	ioctl(m, TIOCSWINSZ, &wz);
	return m;
}

int main(void)
{
	char tmpl[] = "/tmp/q17gate_pty_XXXXXX";
	char path[128];
	struct stat st;
	char head[16];
	int m, status;
	pid_t pid;
	FILE *f;

	alarm(60);	/* gate 冻死类回归=挂起形态，60s 硬杀 */

	/* A: SETUP 全流 */
	{
		int fd = mkstemp(tmpl);

		CHECK(fd >= 0);
		close(fd);
		unlink(tmpl);	/* SETUP 要求凭据文件不存在 */
		snprintf(path, sizeof(path), "%s", tmpl);

		snprintf(g_last, sizeof(g_last), "%s-last", path);
		unlink(g_last);
		acc_n = 0;
		m = spawn_gate(path, &pid);
		CHECK(m >= 0);
		CHECK(wait_tok(m, "AIKernel 初始化", 8));
		feed(m, "abc");
		CHECK(wait_tok(m, "至少 6 位", 8));
		feed(m, "aaa123");
		/* diff 渲染只发变化格：提示行 token（设置密码→确认密码）不连续，
		 * 用整行绘制的状态行 token 断言（q17 实机口径同此）。 */
		CHECK(wait_tok(m, "再输入一次确认", 8));
		feed(m, "bbb123");
		CHECK(wait_tok(m, "两次不一致", 8));
		feed(m, "q17pw1!");
		CHECK(wait_tok(m, "再输入一次确认", 8));
		feed(m, "q17pw1!");
		CHECK(wait_exit(pid, &status, 15));
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		CHECK(stat(path, &st) == 0);
		CHECK((st.st_mode & 0777) == 0600);
		f = fopen(path, "r");
		CHECK(f != NULL);
		if (f) {
			size_t n = fread(head, 1, 9, f);
			fclose(f);
			CHECK(n == 9 && strncmp(head, "admin:$6$", 9) == 0);
		}
		close(m);
		printf("test_gate_pty A (setup flow): %s\n",
		       fails ? "FAIL" : "ok");
	}

	/* B: LOGIN 3 错 → 冷却 */
	{
		printf("[B] gate file: exists=%d mode=%o\n",
		       stat(path, &st) == 0, stat(path, &st) == 0 ?
		       (unsigned)(st.st_mode & 0777) : 0u);
		acc_n = 0;
		m = spawn_gate(path, &pid);
		CHECK(m >= 0);
		CHECK(wait_tok(m, "Enter 登录", 8));
		feed(m, "wrong1");
		CHECK(wait_tok(m, "密码不正确", 8));
		feed(m, "wrong2");
		feed(m, "wrong3");
		CHECK(wait_tok(m, "尝试过多，冷却", 8));
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		close(m);
		printf("test_gate_pty B (login+cooldown): %s\n",
		       fails ? "FAIL" : "ok");
	}

	/* C: 覆写守卫——凭据已在时 SETUP 提交拒绝转 LOGIN */
	{
		acc_n = 0;
		m = spawn_gate(path, &pid);
		CHECK(m >= 0);
		CHECK(wait_tok(m, "Enter 登录", 8));	/* 文件在=LOGIN */
		/* 删文件 + 提交 → 文件消失路径转 SETUP（q17 audit A-8 面） */
		unlink(path);
		feed(m, "zzz999");
		CHECK(wait_tok(m, "首次使用", 8));
		feed(m, "zzz999");
		CHECK(wait_tok(m, "再输入一次确认", 8));
		/* 另一控制台抢先设密（stale-SETUP 覆写探针场景） */
		{
			char h[128];

			CHECK(tui_gate_hash("stolen77", h) == 0);
			CHECK(tui_gate_write(path, h) == 0);
		}
		feed(m, "zzz999");
		CHECK(wait_tok(m, "密码已由其他控制台设置", 8));
		/* stolen77 可登录=未覆写 */
		feed(m, "stolen77");
		CHECK(wait_exit(pid, &status, 15));
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		close(m);
		unlink(path);
		printf("test_gate_pty C (overwrite guard): %s\n",
		       fails ? "FAIL" : "ok");
	}

	/* D: P-2a 双用户登录（用户名框+密码错/对、逐用户独立计数、
	 * 冷却独立、last 预填与落盘）——gate 文件 admin+u1+u2 三条目 */
	{
		char h_admin[128], h_u1[128], h_u2[128], rd[128];
		char lb[64];
		int ff = -1;
		FILE *lf;

		CHECK(tui_gate_hash("adm-p2a-pw", h_admin) == 0);
		CHECK(tui_gate_hash("u1-p2a-pw", h_u1) == 0);
		CHECK(tui_gate_hash("u2-p2a-pw", h_u2) == 0);
		CHECK(tui_gate_write(path, h_admin) == 0);
		CHECK(tui_gate_write_entry(path, "u1", h_u1, 0) == 0);
		CHECK(tui_gate_write_entry(path, "u2", h_u2, 0) == 0);
		unlink(g_last);			/* 无 last → 预填 admin */

		/* D1: u1 错一次——计数只落 u1 行 */
		acc_n = 0;
		m = spawn_gate(path, &pid);
		CHECK(m >= 0);
		CHECK(wait_tok(m, "Enter 登录", 8));
		CHECK(wait_tok(m, "用户", 8));			/* 用户名框在屏 */
		feedraw(m, "\t");				/* Tab→用户名框 */
		feedraw(m, "\x7f\x7f\x7f\x7f\x7f");	/* 退格清预填 admin */
		feed(m, "u1");				/* 用户名+Enter 跳密码 */
		feed(m, "wrong-pw");
		CHECK(wait_tok(m, "密码不正确（1/3）", 8));
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		close(m);
		CHECK(tui_gate_read_user(path, "u1", rd, &ff) == 0 && ff == 1);
		CHECK(tui_gate_read_user(path, "u2", rd, &ff) == 0 && ff == 0);
		CHECK(tui_gate_read_user(path, "admin", rd, &ff) == 0 &&
		      ff == 0);

		/* D2: 预填 admin——不动用户名直接打密码（老习惯兼容）；
		 * admin 计数独立于 u1 */
		acc_n = 0;
		m = spawn_gate(path, &pid);
		CHECK(m >= 0);
		CHECK(wait_tok(m, "Enter 登录", 8));
		feed(m, "wrong-pw");
		CHECK(wait_tok(m, "密码不正确（1/3）", 8));
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		close(m);
		CHECK(tui_gate_read_user(path, "admin", rd, &ff) == 0 &&
		      ff == 1);
		CHECK(tui_gate_read_user(path, "u1", rd, &ff) == 0 && ff == 1);

		/* D3: ghost 拒绝（不枚举用户）→ 改回 u1 成功 + last 落盘 */
		acc_n = 0;
		m = spawn_gate(path, &pid);
		CHECK(m >= 0);
		CHECK(wait_tok(m, "Enter 登录", 8));
		feedraw(m, "\t");
		feedraw(m, "\x7f\x7f\x7f\x7f\x7f");	/* 退格清预填 */
		feed(m, "ghost");
		feed(m, "whatever");
		CHECK(wait_tok(m, "用户名或密码不正确", 8));
		feedraw(m, "\t");			/* 用户名框保留 ghost */
		feedraw(m, "\x7f\x7f\x7f\x7f\x7f");
		feed(m, "u1");
		feed(m, "u1-p2a-pw");
		CHECK(wait_exit(pid, &status, 15));
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		close(m);
		lf = fopen(g_last, "r");
		CHECK(lf != NULL);
		if (lf) {
			CHECK(fgets(lb, sizeof(lb), lf) != NULL &&
			      strcmp(lb, "u1\n") == 0);
			fclose(lf);
		}
		CHECK(tui_gate_read_user(path, "u1", rd, &ff) == 0 &&
		      ff == 0);			/* 成功清零 */

		/* D4: u1（预填）打满 3 错触发冷却——u2 不受牵连可登录
		 * （逐用户独立：非阻塞冷却） */
		acc_n = 0;
		m = spawn_gate(path, &pid);
		CHECK(m >= 0);
		CHECK(wait_tok(m, "Enter 登录", 8));
		feed(m, "w1");
		CHECK(wait_tok(m, "密码不正确（1/3）", 8));
		feed(m, "w2");
		/* 差分渲染只发变化格：1/3→2/3 仅一个数字格变化，字节流
		 * 不再含完整 token——以文件计数为准（写侧同步落盘） */
		usleep(700000);
		CHECK(tui_gate_read_user(path, "u1", rd, &ff) == 0 &&
		      ff == 2);
		feed(m, "w3");
		CHECK(wait_tok(m, "尝试过多，冷却", 8));
		feedraw(m, "\t");			/* 冷却中切用户名 */
		feedraw(m, "\x7f\x7f");			/* 清 "u1" */
		feed(m, "u2");
		feed(m, "u2-p2a-pw");
		CHECK(wait_exit(pid, &status, 15));
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		close(m);
		CHECK(tui_gate_read_user(path, "u1", rd, &ff) == 0 &&
		      ff == 3);			/* u1 计数留痕 */
		CHECK(tui_gate_read_user(path, "u2", rd, &ff) == 0 &&
		      ff == 0);
		printf("test_gate_pty D (multi-user login): %s\n",
		       fails ? "FAIL" : "ok");
	}
	unlink(path);
	unlink(g_last);

	printf("test_gate_pty: %s (%d fails)\n", fails ? "FAIL" : "all ok",
	       fails);
	return fails ? 1 : 0;
}
