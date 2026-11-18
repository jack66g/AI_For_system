/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_exitmarker.c - P-47 退出码出带外 marker：真 occ 二进制 pty 台架
 *
 * 谜底（DEV-LOG（十九）④）：fbterm 转手吞掉子进程退出码——occ TUI 退
 * 71（/exit=注销语义），aik-console 只见 fbterm 的 0，O-1 退出即注销
 * 在 fb 链永不触发。修法=marker 出带外（读后即焚）。本套 exec 真
 * ../occ 全屏 TUI 验证（手法 test_rename_ai 同源；不发消息、无 mock
 * 端点——模型配置指死端口即可，进屏/退屏不过网）：
 *   M1 FBTERM=1（aik-console fb 分支同款 env）+ OCC_EXIT_MARKER 指
 *      /tmp 文件：/exit → 子进程退出码 71 且 marker 内容恰 "71\n"。
 *   M2 对照：无 FBTERM env（serial/ssh 链 rc 直达）→ 退出码仍 71、
 *      marker 文件不存在（门卫=FBTERM 而非 env 路径，精确）。
 *   M3 /zoom（退出码 70）不写 marker——fb 循环内重启非终局退出，写
 *      了会被 aik-console 当本轮退出消费、污染下一轮判定（回归门：
 *      70 一旦出带外即破坏「读后即焚」契约）。
 * 隔离：marker 路径用 OCC_EXIT_MARKER 覆盖指 /tmp（生产不设 env、用
 * 缺省 /run/aik-occ-exit——测试绝不碰 /run）；每场景前清目标文件、
 * 全套结束清场防污染其它用例。
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

static int read_until_contains(int fd, char *buf, int cap, int *have,
			       const char *needle, int timeout_ms)
{
	long long t0 = -1, now_ms = 0;
	size_t nlen = strlen(needle);

	for (;;) {
		struct pollfd p;
		ssize_t n;
		long long remain;

		if (t0 < 0) {
			struct timespec ts;

			clock_gettime(CLOCK_MONOTONIC, &ts);
			t0 = (long long)ts.tv_sec * 1000 +
			     ts.tv_nsec / 1000000;
			now_ms = t0;
		}
		if (*have >= (int)nlen && find_bytes(buf, *have, needle))
			return 0;
		remain = timeout_ms - (now_ms - t0);
		if (remain <= 0)
			return -1;
		if (*have >= cap)
			return -1;
		p.fd = fd;
		p.events = POLLIN;
		p.revents = 0;
		n = poll(&p, 1, (int)(remain > 1000 ? 1000 : remain));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n > 0 && (p.revents & POLLIN)) {
			ssize_t r = read(fd, buf + *have,
					 (size_t)(cap - *have));

			if (r > 0) {
				*have += (int)r;
				continue;
			}
			if (r == 0)
				return 1;
			if (errno != EINTR && errno != EAGAIN)
				return -1;
		}
		{
			struct timespec ts;

			clock_gettime(CLOCK_MONOTONIC, &ts);
			now_ms = (long long)ts.tv_sec * 1000 +
				 ts.tv_nsec / 1000000;
		}
	}
}

/*
 * 在 pty 上跑一轮真 occ TUI：进屏（alt-screen）→ 写 slash 命令 →
 * 等退屏 → 收尸。返回子进程退出码（异常 -1）。fbterm=0 时显式
 * unsetenv FBTERM（serial/ssh 链形态）。
 */
static int run_occ(const char *tmpdir, int fbterm, const char *slash,
		   const char *marker, char *out, int *out_len)
{
	struct pty pt;
	pid_t pid;
	int have = 0;
	int st = 0;
	struct winsize ws = { .ws_row = 24, .ws_col = 80 };
	char toml[512], dbp[512], homep[512];

	snprintf(toml, sizeof(toml), "%s/model.toml", tmpdir);
	{
		FILE *f = fopen(toml, "w");

		if (!f)
			return -1;
		/* 死端口即可：本套不发消息，进屏/退屏不过网 */
		fprintf(f,
			"[models.cloud]\n"
			"provider_type = \"openai_compatible\"\n"
			"model_name = \"mock-model\"\n"
			"base_url = \"http://127.0.0.1:9/v1\"\n"
			"api_key = \"mock-key-not-real\"\n");
		fclose(f);
	}
	snprintf(dbp, sizeof(dbp), "%s/sessions.db", tmpdir);
	snprintf(homep, sizeof(homep), "%s/home", tmpdir);
	mkdir(homep, 0700);

	if (pty_open(&pt) != 0)
		return -1;
	(void)ioctl(pt.slave, TIOCSWINSZ, &ws);
	pid = fork();
	if (pid < 0) {
		close(pt.master);
		close(pt.slave);
		return -1;
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
		setenv("OCC_MODEL_TOML", toml, 1);
		setenv("OCC_DB", dbp, 1);
		setenv("HOME", homep, 1);
		setenv("TERM", "dumb", 1);
		setenv("AIK_CONSOLE_GATE_SKIP", "1", 1);
		setenv("OCC_EXIT_MARKER", marker, 1);
		if (fbterm)
			setenv("FBTERM", "1", 1);
		else
			unsetenv("FBTERM");
		execl("../occ", "occ", (char *)NULL);
		_exit(127);
	}
	close(pt.slave);
	pt.slave = -1;

	/* 等进屏（tcsetattr TCSAFLUSH 冲刷过早输入——先等 alt-screen） */
	if (read_until_contains(pt.master, out, OUT_CAP, &have,
				"\x1b[?1049h", 15000) != 0) {
		kill(pid, SIGKILL);
		waitpid(pid, &st, 0);
		close(pt.master);
		return -1;
	}
	{
		size_t sl = strlen(slash);

		if (write(pt.master, slash, sl) < 0) {
			kill(pid, SIGKILL);
			waitpid(pid, &st, 0);
			close(pt.master);
			return -1;
		}
	}
	if (read_until_contains(pt.master, out, OUT_CAP, &have,
				"\x1b[?1049l", 15000) != 0) {
		kill(pid, SIGKILL);
		waitpid(pid, &st, 0);
		close(pt.master);
		return -1;
	}
	*out_len = have;
	{
		int w;

		for (w = 0; w < 80; w++) {
			if (waitpid(pid, &st, WNOHANG) == pid)
				break;
			usleep(100000);
		}
		if (w == 80) {
			kill(pid, SIGKILL);
			waitpid(pid, &st, 0);
			close(pt.master);
			return -1;
		}
	}
	close(pt.master);
	if (!WIFEXITED(st))
		return -1;
	return WEXITSTATUS(st);
}

/* marker 文件整读（小文件）；返回长度，buf NUL 结尾 */
static int marker_read(const char *path, char *buf, size_t cap)
{
	FILE *f = fopen(path, "rb");
	size_t n;

	if (!f)
		return -1;
	n = fread(buf, 1, cap - 1, f);
	fclose(f);
	buf[n] = '\0';
	return (int)n;
}

int main(void)
{
	static char out[OUT_CAP];
	char tmpl[] = "/tmp/btui-xmk-XXXXXX";
	char marker[300];
	char *tmp;
	int out_len = 0;
	int rc;

	signal(SIGPIPE, SIG_IGN);

	if (access("../occ", X_OK) != 0) {
		printf("test_exitmarker: SKIP（../occ 未构建——occ 顶层 "
		       "make all 后生效）\n");
		return 0;
	}
	tmp = mkdtemp(tmpl);
	if (!tmp) {
		printf("FAIL mkdtemp\n");
		return 1;
	}
	snprintf(marker, sizeof(marker), "%s/marker", tmp);

	/* ---- M1：FBTERM=1 → /exit 退 71 + marker 出带外 ---- */
	unlink(marker);
	rc = run_occ(tmp, 1, "/exit\r", marker, out, &out_len);
	OK(rc == 71, "M1-exit-code-71");
	{
		char buf[64];
		int n = marker_read(marker, buf, sizeof(buf));

		OK(n == 3 && !strcmp(buf, "71\n"), "M1-marker-content-71");
	}

	/* ---- M2 对照：无 FBTERM → 仍 71、marker 不存在（门卫精确） ---- */
	unlink(marker);
	rc = run_occ(tmp, 0, "/exit\r", marker, out, &out_len);
	OK(rc == 71, "M2-exit-code-71");
	OK(access(marker, F_OK) != 0, "M2-no-marker-without-fbterm");

	/* ---- M3：/zoom（70）不写 marker（非终局退出防污染） ---- */
	unlink(marker);
	rc = run_occ(tmp, 1, "/zoom 20\r", marker, out, &out_len);
	OK(rc == 70, "M3-zoom-exit-code-70");
	OK(access(marker, F_OK) != 0, "M3-no-marker-for-zoom-70");

	/* 清场防污染其它用例（marker + 夹具目录 + zoom 写的 .fbtermrc） */
	unlink(marker);
	{
		char cmd[300];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp);
		if (system(cmd)) {
			/* 清理失败不影响判定 */
		}
	}
	printf("test_exitmarker: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
