/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_cmd_tailws.c - O-19 回归：slash 命令容行尾空白（真 occ pty 台架）。
 *
 * 实证根因（11-19 T14e）："/models "（尾空格）精确 strcmp 不命中 →
 * unknown command。修复合同（兜底重试式）：
 *   1. "/models " + 回车 → 浮层照常打开（footer「Esc=关闭」字节）；
 *   2. "/models  x"（带参形态，行尾无空白）→ 行为不变：unknown
 *      command 提示（view 层文案），不误开浮层。
 * 手法同 test_models_offline：fork pty 子进程 exec 真 occ（fixture
 * 目录隔离快照搜索链；model.toml 单直填槽位零网络零 key；登录门
 * AIK_CONSOLE_GATE_SKIP 旁路）。前置 ../occ 已构建；未构建诚实 skip。
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

#define OUT_CAP (256 * 1024)

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

static const char *find_bytes(const char *hay, int haylen, const char *needle)
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

/* 累积式等待：buf 追加读到的字节，直到含 needle 或超时 */
static int read_until_contains(int fd, char *buf, int cap, int *have,
			       const char *needle, int timeout_ms)
{
	struct timespec start, now;
	size_t nlen = strlen(needle);

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		return -1;
	for (;;) {
		long long remain;
		struct pollfd p;
		int r;
		ssize_t n;

		if (*have >= (int)nlen && find_bytes(buf, *have, needle))
			return 0;
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return -1;
		remain = timeout_ms -
			 ((now.tv_sec - start.tv_sec) * 1000LL +
			  (now.tv_nsec - start.tv_nsec) / 1000000LL);
		if (remain <= 0)
			return -1;
		if (*have >= cap)
			return -1;
		p.fd = fd;
		p.events = POLLIN;
		p.revents = 0;
		r = poll(&p, 1, (int)remain);
		if (r == 0)
			return -1;
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
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

int main(void)
{
	static char out[OUT_CAP];
	int have = 0;
	char tmpl[] = "/tmp/btui-o19-XXXXXX";
	char *tmp;
	char toml[512], dbp[512], homep[512], occbin[512], catp[512];
	struct pty pt;
	struct winsize ws = { .ws_row = 24, .ws_col = 80 };
	pid_t pid;
	int st = 0, w;

	signal(SIGPIPE, SIG_IGN);

	if (access("../occ", X_OK) != 0) {
		printf("test_cmd_tailws: SKIP（../occ 未构建——occ 顶层 "
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
	snprintf(occbin, sizeof(occbin), "%s/occ", tmp);
	snprintf(catp, sizeof(catp), "%s/none-catalog.json", tmp);
	mkdir(homep, 0700);
	{
		FILE *f = fopen(toml, "w");

		if (!f) {
			printf("FAIL fixture toml\n");
			return 1;
		}
		/* 直填式槽位；闭端口 base_url：零网络（/models 不触发传输） */
		fputs("[models.cloud]\n"
		      "provider_type = \"openai_compatible\"\n"
		      "model_name = \"glm-p35\"\n"
		      "base_url = \"http://127.0.0.1:9/v1\"\n"
		      "api_key = \"mock-key-not-real\"\n", f);
		fclose(f);
	}
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
		setenv("AIK_CONSOLE_GATE_SKIP", "1", 1);
		setenv("OCC_CATALOG", catp, 1);
		execl(occbin, "occ", (char *)NULL);
		_exit(127);
	}
	close(pt.slave);
	pt.slave = -1;

	/* 1. 进屏（alt-screen） */
	OK(read_until_contains(pt.master, out, OUT_CAP, &have,
			       "\x1b[?1049h", 8000) == 0, "enter-alt-screen");

	/* 2. O-19 主案："/models "（尾随空格）→ 浮层照常打开 */
	if (write(pt.master, "/models \r", 9) < 0)
		printf("FAIL write /models-tailws (errno=%d)\n", errno);
	OK(read_until_contains(pt.master, out, OUT_CAP, &have,
			       "Esc=关闭", 15000) == 0, "tailws-overlay-opens");

	/* 3. Esc 关浮层（单字节孤立——25ms 结算窗） */
	if (write(pt.master, "\x1b", 1) < 0)
		printf("FAIL write esc (errno=%d)\n", errno);
	usleep(300000);

	/* 4. O-19 不变量："/models  x"（带参形态）→ 行为不变（unknown） */
	if (write(pt.master, "/models  x\r", 11) < 0)
		printf("FAIL write /models-args (errno=%d)\n", errno);
	OK(read_until_contains(pt.master, out, OUT_CAP, &have,
			       "unknown command", 15000) == 0,
	   "args-form-still-unknown");

	/* 5. /exit 干净收口 */
	if (write(pt.master, "/exit\r", 6) >= 0)
		OK(read_until_contains(pt.master, out, OUT_CAP, &have,
				       "\x1b[?1049l", 8000) == 0,
		   "exit-clean");
	else
		OK(0, "exit-clean");

	for (w = 0; w < 50; w++) {
		pid_t r = waitpid(pid, &st, WNOHANG);

		if (r == pid)
			break;
		usleep(100000);
	}
	if (w == 50) {
		kill(pid, SIGKILL);
		waitpid(pid, &st, 0);
		OK(0, "child-reaped");
	} else {
		OK(1, "child-reaped");
		OK(WIFEXITED(st) &&
		   (WEXITSTATUS(st) == 0 || WEXITSTATUS(st) == 71),
		   "child-exit-code");
	}
	close(pt.master);

	{
		char cmd[600];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp);
		if (system(cmd) != 0) { }	/* 清理尽力而为 */
	}
	printf("test_cmd_tailws: %s (%d ok, %d fail)\n",
	       n_fail ? "FAIL" : "ALL GREEN", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
