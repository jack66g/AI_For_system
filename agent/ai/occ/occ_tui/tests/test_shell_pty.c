/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_shell_pty.c - O-2 /shell 往返端到端（pty 驱动真 occ 二进制）
 *
 * 修向（UX-O：一键切换更顺滑）：/shell 无反馈回屏——收口后无退出码/
 * 无 cwd 注记、无退屏提示行、$SHELL 不认（写死 /bin/bash）、
 * /shell <cmd> 单条形态缺失。本套在真 pty 上 fork+exec ../occ（fixture
 * 隔离、死端口模型——往返不过网）验证全链字节流：
 *   S1 交互往返：/shell → 退屏（alt-screen leave）→ 提示行
 *      「occ: 已退至 shell——exit 返回 occ」→ 子壳=强制 SHELL=/bin/sh
 *      （断言 $SHELL 生效）内 echo 标记 → exit 7 → 回屏（alt-screen
 *      re-enter）→ 侧栏/输入框特征字节全量重绘 → 注记
 *      「shell 退出码 7·cwd=<fixture 目录>」在屏。
 *   S2 带参形态：/shell echo O2CMD_RUN → 退屏 → 命令输出字节 →
 *      回屏 → 注记「shell 退出码 0」（成功态）；全程提示行恰一次
 *      （带参形态命令输出即反馈，不加噪）。
 *   S3 收尾：/exit → 退屏 + 子进程 rc=71（O-1 注销语义在两次往返
 *      重建后不被污染）。
 * 手法 test_su_pty/test_exitmarker 同源；断言以匹配位置为界只认其后
 * 字节（leave 与提示行/首帧常并入同一读块——have 快照会漏帧，位置界
 * 抗合块）；子壳侧输入用 \n 收尾并留呼吸（退屏 TCSAFLUSH 与子壳
 * 首读的竞态）。
 * 前置：../occ 已构建（occ 顶层 make all）；未构建诚实 skip（exit 0）。
 */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

#define OUT_CAP (512 * 1024)

struct pty {
	int master, slave;
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

static const char *find_bytes(const char *hay, int len, const char *needle)
{
	int nl = (int)strlen(needle);
	int i;

	if (nl == 0 || len < nl)
		return NULL;
	for (i = 0; i + nl <= len; i++)
		if (memcmp(hay + i, needle, (size_t)nl) == 0)
			return hay + i;
	return NULL;
}

static int count_bytes(const char *hay, int len, const char *needle)
{
	int n = 0;
	const char *p = hay;
	int left = len;

	for (;;) {
		const char *hit = find_bytes(p, left, needle);

		if (!hit)
			return n;
		n++;
		left -= (int)(hit - p) + (int)strlen(needle);
		p = hit + strlen(needle);
	}
}

/* 只认 from 起字节；命中返回匹配起点（后续断言以它为界——抗读块
 * 合并），超时/错误返回 -1 */
static int wait_new(int fd, char *buf, int cap, int *have, int from,
		    const char *needle, int timeout_ms)
{
	struct timespec start, now;
	const int nlen = (int)strlen(needle);

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		return -1;
	for (;;) {
		struct pollfd p;
		int r;
		ssize_t n;

		if (*have - from >= nlen) {
			const char *hit = find_bytes(buf + from,
						      *have - from, needle);

			if (hit)
				return (int)(hit - buf);
		}
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return -1;
		{
			long long remain = timeout_ms -
				((now.tv_sec - start.tv_sec) * 1000LL +
				 (now.tv_nsec - start.tv_nsec) / 1000000LL);
			int slice;

			if (remain <= 0)
				return -1;
			slice = remain > 200 ? 200 : (int)remain;
			p.fd = fd;
			p.events = POLLIN;
			p.revents = 0;
			r = poll(&p, 1, slice);
			if (r == 0)
				continue;
			if (r < 0) {
				if (errno == EINTR)
					continue;
				return -1;
			}
		}
		n = read(fd, buf + *have, (size_t)(cap - *have));
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		*have += (int)n;
	}
}

static int wait_child(pid_t pid)
{
	int st = 0, w;

	for (w = 0; w < 50; w++) {
		if (waitpid(pid, &st, WNOHANG) == pid)
			return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
		usleep(100000);
	}
	kill(pid, SIGKILL);
	waitpid(pid, &st, 0);
	return -1;
}

static void w_or_die(int fd, const char *s)
{
	if (write(fd, s, strlen(s)) < 0)
		printf("FAIL write %s\n", s);
}

int main(void)
{
	static char out[OUT_CAP];
	int have = 0, pos, enter1, leave1, reenter1, leave2, reenter2;
	char tmpl[] = "/tmp/btui-o2-XXXXXX";
	char *tmp;
	char toml[512], dbp[512], homep[512], cwdneedle[600], occbin[512];
	struct pty pt;
	struct winsize ws = { .ws_row = 24, .ws_col = 80 };
	pid_t pid;
	int rc;

	signal(SIGPIPE, SIG_IGN);

	if (access("../occ", X_OK) != 0) {
		printf("test_shell_pty: SKIP（../occ 未构建——occ 顶层 "
		       "make all 后生效）\n");
		return 0;
	}
	tmp = mkdtemp(tmpl);
	if (!tmp) {
		printf("FAIL mkdtemp\n");
		return 1;
	}
	snprintf(toml, sizeof(toml), "%s/model.toml", tmp);
	snprintf(dbp, sizeof(dbp), "%s/sessions.db", tmp);
	snprintf(homep, sizeof(homep), "%s/home", tmp);
	snprintf(cwdneedle, sizeof(cwdneedle), "cwd=%s", tmp);
	snprintf(occbin, sizeof(occbin), "%s/occ", tmp);
	mkdir(homep, 0700);
	{
		FILE *f = fopen(toml, "w");

		if (!f ||
		    fputs("[models.cloud]\n"
			  "provider_type = \"openai_compatible\"\n"
			  "model_name = \"mock-model\"\n"
			  "base_url = \"http://127.0.0.1:9/v1\"\n"
			  "api_key = \"mock-key-not-real\"\n", f) < 0) {
			printf("FAIL fixture toml\n");
			return 1;
		}
		fclose(f);
	}
	/* occ 拷入 fixture（子进程 chdir(tmp) 后 ../occ 不可达——
	 * 手法 test_su_pty 同源） */
	{
		char cmd[1100];

		snprintf(cmd, sizeof(cmd), "cp ../occ %s", occbin);
		if (system(cmd) != 0 || access(occbin, X_OK) != 0) {
			printf("FAIL fixture occ copy\n");
			return 1;
		}
	}

	if (pty_open(&pt) != 0) {
		printf("FAIL pty_open\n");
		return 1;
	}
	(void)ioctl(pt.slave, TIOCSWINSZ, &ws);
	pid = fork();
	if (pid < 0) {
		printf("FAIL fork\n");
		return 1;
	}
	if (pid == 0) {
		close(pt.master);
		if (setsid() < 0)
			_exit(12);
		if (ioctl(pt.slave, TIOCSCTTY, 0) < 0)
			_exit(13);
		if (dup2(pt.slave, STDIN_FILENO) < 0 ||
		    dup2(pt.slave, STDOUT_FILENO) < 0 ||
		    dup2(pt.slave, STDERR_FILENO) < 0)
			_exit(14);
		if (pt.slave > STDERR_FILENO)
			close(pt.slave);
		if (chdir(tmp) != 0)
			_exit(15);
		setenv("OCC_MODEL_TOML", toml, 1);
		setenv("OCC_DB", dbp, 1);
		setenv("HOME", homep, 1);
		setenv("TERM", "xterm", 1);
		setenv("SHELL", "/bin/sh", 1);	/* 断言 $SHELL 生效 */
		setenv("AIK_CONSOLE_GATE_SKIP", "1", 1);
		execl(occbin, "occ", (char *)NULL);
		_exit(127);
	}
	close(pt.slave);
	pt.slave = -1;

	/* ---- 进屏 ---- */
	enter1 = wait_new(pt.master, out, OUT_CAP, &have, 0,
			  "\x1b[?1049h", 15000);
	OK(enter1 >= 0, "enter-alt-screen");

	/* ---- S1：交互往返（exit 7 → 注记退出码 7 + cwd） ---- */
	w_or_die(pt.master, "/shell\r");
	leave1 = wait_new(pt.master, out, OUT_CAP, &have, enter1,
			  "\x1b[?1049l", 10000);
	OK(leave1 >= 0, "s1-leave-alt-screen");
	/* 提示行在 leave 之后（同一读块也以位置界命中） */
	pos = wait_new(pt.master, out, OUT_CAP, &have, leave1,
		       "已退至 shell", 5000);
	OK(pos >= 0, "s1-pre-shell-hint");

	/* 子壳就绪呼吸（退屏 TCSAFLUSH 与子壳首读的竞态——\n 收尾） */
	usleep(400000);
	w_or_die(pt.master, "echo O2SHELL_IN\n");
	pos = wait_new(pt.master, out, OUT_CAP, &have, have,
		       "O2SHELL_IN", 8000);
	OK(pos >= 0, "s1-child-shell-alive");

	usleep(300000);
	w_or_die(pt.master, "exit 7\n");
	reenter1 = wait_new(pt.master, out, OUT_CAP, &have, have,
			    "\x1b[?1049h", 10000);
	OK(reenter1 >= 0, "s1-reenter-alt-screen");
	/* 注记/重绘锚只认 re-enter 之后字节（首屏同名锚在界前） */
	pos = wait_new(pt.master, out, OUT_CAP, &have, reenter1,
		       "shell 退出码 7", 8000);
	OK(pos >= 0, "s1-note-exit-code-7");
	pos = wait_new(pt.master, out, OUT_CAP, &have, reenter1,
		       cwdneedle, 5000);
	OK(pos >= 0, "s1-note-cwd-fixture");
	pos = wait_new(pt.master, out, OUT_CAP, &have, reenter1,
		       "AIKernel", 5000);
	OK(pos >= 0, "s1-redraw-sidebar-anchor");
	pos = wait_new(pt.master, out, OUT_CAP, &have, reenter1,
		       "输入消息", 5000);
	OK(pos >= 0, "s1-redraw-inputbox-anchor");

	/* ---- S2：带参形态（/shell echo O2CMD_RUN → 注记退出码 0） ---- */
	w_or_die(pt.master, "/shell echo O2CMD_RUN\r");
	leave2 = wait_new(pt.master, out, OUT_CAP, &have, reenter1,
			  "\x1b[?1049l", 10000);
	OK(leave2 >= 0, "s2-leave-alt-screen");
	/* 命令输出在 leave 之后（输入框回显里的 O2CMD_RUN 在界前） */
	pos = wait_new(pt.master, out, OUT_CAP, &have, leave2,
		       "O2CMD_RUN", 8000);
	OK(pos >= 0, "s2-command-output-bytes");
	reenter2 = wait_new(pt.master, out, OUT_CAP, &have, leave2,
			    "\x1b[?1049h", 10000);
	OK(reenter2 >= 0, "s2-reenter-alt-screen");
	pos = wait_new(pt.master, out, OUT_CAP, &have, reenter2,
		       "shell 退出码 0", 8000);
	OK(pos >= 0, "s2-note-exit-code-0");
	/* 提示行全程恰一次：带参形态不加噪 */
	OK(count_bytes(out, have, "已退至 shell") == 1,
	   "s2-hint-once-interactive-only");

	/* ---- S3：/exit → rc=71（往返重建不污染注销语义） ---- */
	usleep(200000);
	w_or_die(pt.master, "/exit\r");
	pos = wait_new(pt.master, out, OUT_CAP, &have, reenter2,
		       "\x1b[?1049l", 8000);
	OK(pos >= 0, "s3-exit-leave");
	rc = wait_child(pid);
	OK(rc == 71, "s3-occ-rc-71");

	/* 清场防污染其它用例 */
	{
		char cmd[600];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp);
		if (system(cmd)) {
			/* 清理失败不影响判定 */
		}
	}
	close(pt.master);
	printf("test_shell_pty: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
