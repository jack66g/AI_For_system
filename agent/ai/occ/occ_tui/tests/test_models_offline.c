/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_models_offline.c - P-35 回归：/models 浮层离线（无 catalog 快照）
 * 不自退——真 occ 二进制 pty 台架。
 *
 * 手法（test_rename_ai / test_view_pty 同源）：fork pty 子进程 exec 真
 * occ（拷入 fixture 目录——exe 目录搜索链无 models.dev.snapshot.json，
 * OCC_CATALOG 亦指向不存在路径；cwd=fixture 无快照 → catalog 三路全空
 * = 真机离线形态）。model.toml 单直填槽位（glm-p35）零网络零 key。
 * 断言（P-35 修复合同）：
 *   1. /models 后浮层打开（footer「Esc=关闭」字节）——不静默自退；
 *   2. 配置条目直列可选（「glm-p35」进字节流）；
 *   3. 浮层内 dim 提示行（「快照未配置」）——不是 chat notice 退出；
 *   4. 浮层停留窗内进程存活（自退=1s 内退出/回主界面帧）；
 *   5. Esc 关浮层回主界面 → /exit 干净收口（子 rc=0/71）；
 *   6. 全流零「注册表为空」（旧空数据即关文案不复现）；
 *   7. P-42：浮层打开即选中首个可选条目——首回车直接切换成功
 *      （「model → cloud/glm-p35」notice），且全流零「该条目不可用」
 *      （旧：初始光标停 dim 提示行，首回车必报）；选中行反色序列
 *      （SGR 7 + accent 前景）进字节流（fbterm 高亮可见性的字节证据）。
 * 前置：../occ 已构建；未构建诚实 skip（exit 0）。
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
	int have = 0, out_len = 0;
	char tmpl[] = "/tmp/btui-p35-XXXXXX";
	char *tmp;
	char toml[512], dbp[512], homep[512], occbin[512], catp[512];
	struct pty pt;
	struct winsize ws = { .ws_row = 24, .ws_col = 80 };
	pid_t pid;
	int st = 0, w;
	time_t t0;

	signal(SIGPIPE, SIG_IGN);

	if (access("../occ", X_OK) != 0) {
		printf("test_models_offline: SKIP（../occ 未构建——occ 顶层 "
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
		/* 直填式槽位（provider_type 必给——缺省判 malformed）；
		 * base_url 指向闭端口：本测试零网络调用（/models 不触发
		 * 传输；P-35 后空 catalog 也不阻塞） */
		fputs("[models.cloud]\n"
		      "provider_type = \"openai_compatible\"\n"
		      "model_name = \"glm-p35\"\n"
		      "base_url = \"http://127.0.0.1:9/v1\"\n"
		      "api_key = \"mock-key-not-real\"\n", f);
		fclose(f);
	}
	/* occ 拷入 fixture（exe 目录无快照——catalog 三级搜索全空） */
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
		if (chdir(tmp) != 0)		/* cwd 无快照 */
			_exit(15);
		setenv("OCC_MODEL_TOML", toml, 1);
		setenv("OCC_DB", dbp, 1);
		setenv("HOME", homep, 1);
		setenv("TERM", "xterm", 1);
		setenv("AIK_CONSOLE_GATE_SKIP", "1", 1);
		/* P-35 场景旋钮：显式 catalog 指向不存在路径 */
		setenv("OCC_CATALOG", catp, 1);
		execl(occbin, "occ", (char *)NULL);
		_exit(127);
	}
	close(pt.slave);
	pt.slave = -1;

	/* 1. 进屏（alt-screen） */
	OK(read_until_contains(pt.master, out, OUT_CAP, &have,
			       "\x1b[?1049h", 8000) == 0, "enter-alt-screen");

	/* 2. /models → 浮层打开（footer 字节；不自退） */
	if (write(pt.master, "/models\r", 8) < 0)
		printf("FAIL write /models (errno=%d)\n", errno);
	OK(read_until_contains(pt.master, out, OUT_CAP, &have,
			       "Esc=关闭", 15000) == 0, "overlay-opens");

	/* 3. 配置条目直列（model.toml 条目进浮层） */
	OK(read_until_contains(pt.master, out, OUT_CAP, &have,
			       "glm-p35", 15000) == 0, "toml-entry-listed");

	/* 4. dim 提示行（catalog 缺失——浮层内提示而非 chat notice） */
	OK(read_until_contains(pt.master, out, OUT_CAP, &have,
			       "快照未配置", 15000) == 0, "catalog-note-line");

	/* 5. 停留窗存活（自退=1s 内退出；P-35 前空数据即关在打开瞬间） */
	t0 = time(NULL);
	st = 0;
	do {
		pid_t r = waitpid(pid, &st, WNOHANG);

		if (r == pid) {
			printf("  dbg: child exited early (st=%d)\n", st);
			break;
		}
		usleep(100000);
	} while (time(NULL) - t0 < 1);
	OK(waitpid(pid, &st, WNOHANG) == 0, "no-silent-exit");

	/* 6. 零旧文案（「注册表为空」= 空数据即关的 chat notice） */
	OK(find_bytes(out, have, "注册表为空") == NULL,
	   "no-registry-empty-notice");

	/* 7. P-42：打开即选中首个可选条目——首回车直接切换（成功 notice
	 *    字节）；零「该条目不可用」（旧症状：光标停 dim 提示行）；
	 *    选中行 SGR 7 反色 + accent 前景序列在流（fbterm 可见性证据） */
	if (write(pt.master, "\r", 1) < 0)
		printf("FAIL write enter (errno=%d)\n", errno);
	OK(read_until_contains(pt.master, out, OUT_CAP, &have,
			       "model → cloud/glm-p35", 15000) == 0,
	   "p42-enter-switches-model");
	OK(find_bytes(out, have, "该条目不可用") == NULL,
	   "p42-no-unavailable-status");
	OK(find_bytes(out, have, "7;38;5;81m") != NULL,
	   "p42-inverse-sgr-bytes");

	/* 8. Esc 关浮层（单字节孤立——25ms 结算窗）→ /exit 干净收口 */
	if (write(pt.master, "\x1b", 1) >= 0) {
		usleep(100000);
		if (write(pt.master, "/exit\r", 6) >= 0)
			OK(read_until_contains(pt.master, out, OUT_CAP,
					       &have, "\x1b[?1049l", 8000)
			   == 0, "esc-then-exit-clean");
		else
			OK(0, "esc-then-exit-clean");
	} else {
		OK(0, "esc-then-exit-clean");
	}
	out_len = have;

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
		/* occ 主动退出=71（注销语义）；正常 /exit=0 */
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
	(void)out_len;
	printf("test_models_offline: %s (%d ok, %d fail)\n",
	       n_fail ? "FAIL" : "ALL GREEN", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
