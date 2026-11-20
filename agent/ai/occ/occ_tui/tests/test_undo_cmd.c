/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_undo_cmd.c - O-25 回归：TUI /undo /redo 端到端
 * （真 pty 驱动真 occ 二进制 + 本地 mock LLM）
 *
 * 现状痛点：撤销只有 CLI `occ undo/redo --session <id>`；TUI 敲 /undo
 * =unknown command，unstuck 文案却指引 /undo。本刀补 TUI 分发
 * （tui_app_on_command_impl /undo /redo → occ_undo/occ_redo 当前会话）
 * + 结果注记行进聊天流（/delete 同款 notice 通道）+ 被撤输入回填
 * （/rename 预填同款 tui_view_open_input）。
 *
 * 场景（每场景独立子进程跑 occ；AIK_CONSOLE_GATE_SKIP=1；HOME=独立
 * 临时 home（快照树根）；cwd=独立临时 workdir；mock=tests/mock_w2_llm.py
 * 首答回 write toolCall——127.0.0.1 绝无真网）：
 *   S1 全环：write u25.txt 落盘→收口→/undo→注记「已撤销」+ 文件回滚
 *      消失（ABSENT 墓碑→删）+ 回填面板（标题 undo 回填）→Esc 关→
 *      /redo→注记「已恢复」+ 文件与内容复原
 *   S2 无会话：进屏即 /undo→注记「尚无会话」（无可撤的人话面）
 *
 * 骨架复用 test_w2_confirm_pty.c 的 PTY+mock 手法（mock 起法/fixture
 * 隔离/退屏断言同款；write 走 workdir 相对路径=W1，不经 W2 面板——
 * 无需 policy 桩）。
 */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int n_ok, n_fail;
static const char *g_scn = "S0";	/* 当前场景标签（OK 行前缀） */

#define OK(cond, name) do { \
	if (cond) { n_ok++; printf("%s %s OK\n", g_scn, name); } \
	else { n_fail++; printf("FAIL %s %s (line %d)\n", g_scn, name, \
				__LINE__); } \
} while (0)

#define OUT_CAP (2 * 1024 * 1024)

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

static const char *find_bytes(const char *buf, int len, const char *needle)
{
	int nl = (int)strlen(needle);
	int i;

	if (nl == 0 || len < nl)
		return NULL;
	for (i = 0; i + nl <= len; i++)
		if (memcmp(buf + i, needle, (size_t)nl) == 0)
			return buf + i;
	return NULL;
}

static int read_until_contains(int fd, char *buf, int cap, int *have,
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

		if (*have >= nlen && find_bytes(buf, *have, needle))
			return 0;
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return -1;
		{
			long long remain = timeout_ms -
				((now.tv_sec - start.tv_sec) * 1000LL +
				 (now.tv_nsec - start.tv_nsec) / 1000000LL);

			if (remain <= 0)
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

/* 自 from 起等新字节（全缓冲找会命中历史 token——prompt/文案反复
 * 出现的串必须只认 from 后新字节；test_w2_confirm_pty 同款） */
static int wait_new(int fd, char *buf, int cap, int *have, int from,
		    const char *needle, int timeout_ms)
{
	struct timespec start, now;

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		return -1;
	for (;;) {
		struct pollfd p;
		int r;
		ssize_t n;

		if (*have - from >= (int)strlen(needle) &&
		    find_bytes(buf + from, *have - from, needle))
			return 0;
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

/* ---- mock LLM（tests/mock_w2_llm.py；python3 起，127.0.0.1） ---- */

static pid_t mock_start(int port, const char *reqdir)
{
	char pbuf[16];
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		char path[512];

		snprintf(pbuf, sizeof(pbuf), "%d", port);
		/* 相对本测试二进制（occ_tui/ 下运行；test_w2 同款） */
		snprintf(path, sizeof(path), "%s/mock_w2_llm.py",
			 getenv("BTUI_MOCK_DIR") ? getenv("BTUI_MOCK_DIR") :
			 "tests");
		execlp("python3", "python3", path, pbuf, reqdir,
		       (char *)NULL);
		_exit(127);
	}
	return pid;
}

static void mock_wait_up(int port)
{
	int i;

	for (i = 0; i < 100; i++) {
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in sa;

		if (fd >= 0) {
			memset(&sa, 0, sizeof(sa));
			sa.sin_family = AF_INET;
			sa.sin_port = htons((uint16_t)port);
			sa.sin_addr.s_addr = htonl(0x7f000001u);
			if (connect(fd, (struct sockaddr *)&sa, sizeof(sa))
			    == 0) {
				close(fd);
				return;
			}
			close(fd);
		}
		usleep(50000);
	}
}

static void write_ctl(const char *reqdir, const char *kv)
{
	char path[512];
	FILE *f;

	snprintf(path, sizeof(path), "%s/ctl", reqdir);
	f = fopen(path, "w");
	if (f) {
		fputs(kv, f);
		fclose(f);
	}
}

static int wait_child(pid_t pid)
{
	int st = 0, w;

	for (w = 0; w < 80; w++) {
		pid_t r = waitpid(pid, &st, WNOHANG);

		if (r == pid)
			return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
		usleep(100000);
	}
	kill(pid, SIGKILL);
	waitpid(pid, &st, 0);
	return -1;
}

/* 起一个 occ 子进程挂 pty（wd/db/home/toml/occbin 全隔离）；返回 pid */
static pid_t occ_spawn(struct pty *pt, const char *wd, const char *dbp,
		       const char *homep, const char *toml,
		       const char *occbin)
{
	struct winsize ws = { .ws_row = 24, .ws_col = 120 };
	pid_t pid;

	if (pty_open(pt) != 0)
		return -1;
	(void)ioctl(pt->slave, TIOCSWINSZ, &ws);
	pid = fork();
	if (pid < 0) {
		close(pt->master);
		close(pt->slave);
		return -1;
	}
	if (pid == 0) {
		close(pt->master);
		if (setsid() < 0)
			_exit(12);
		if (ioctl(pt->slave, TIOCSCTTY, 0) < 0)
			_exit(13);
		if (dup2(pt->slave, STDIN_FILENO) < 0 ||
		    dup2(pt->slave, STDOUT_FILENO) < 0 ||
		    dup2(pt->slave, STDERR_FILENO) < 0)
			_exit(14);
		if (pt->slave > STDERR_FILENO)
			close(pt->slave);
		if (chdir(wd) != 0)
			_exit(15);
		setenv("OCC_MODEL_TOML", toml, 1);
		setenv("OCC_DB", dbp, 1);
		setenv("HOME", homep, 1);
		setenv("TERM", "xterm", 1);
		setenv("AIK_CONSOLE_GATE_SKIP", "1", 1);
		setenv("OCC_CATALOG", "/tmp/o25-none-catalog.json", 1);
		/* 重试旋钮压到最快（失败路径毫秒级收口；w2 同款） */
		setenv("OCC_LLM_RETRY_MAX", "1", 1);
		setenv("OCC_LLM_RETRY_TIMEOUT_MAX", "1", 1);
		setenv("OCC_LLM_RETRY_BASE_MS", "50", 1);
		setenv("OCC_LLM_RETRY_CAP_MS", "100", 1);
		execl(occbin, "occ", (char *)NULL);
		_exit(127);
	}
	close(pt->slave);
	pt->slave = -1;
	return pid;
}

static int file_content_is(const char *path, const char *want)
{
	FILE *f = fopen(path, "r");
	char buf[64];
	size_t n = 0;

	if (!f)
		return 0;
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	return strcmp(buf, want) == 0;
}

/* ---- S1：write 落盘 → /undo 注记+回滚+回填面板 → Esc → /redo 恢复 ---- */

static int s1_full_loop(const char *root, const char *homep,
			const char *toml, const char *occbin,
			const char *reqdir, int port)
{
	static char out[OUT_CAP];
	char wd[300], dbp[360], fpath[360];
	struct pty pt;
	pid_t pid;
	int have = 0, mark;
	int rc = 0;
	int childrc;
	struct stat st;

	(void)port;
	g_scn = "S1";
	snprintf(wd, sizeof(wd), "%s/S1", root);
	mkdir(wd, 0755);
	snprintf(fpath, sizeof(fpath), "%s/u25.txt", wd);
	snprintf(dbp, sizeof(dbp), "%s/S1/sessions.db", root);
	/* mock 首答回 write toolCall（workdir 相对路径=W1，不经 W2 面板） */
	write_ctl(reqdir, "TOOL=write\n"
		  "ARGS={\"path\":\"u25.txt\",\"content\":\"undo-me\"}\n");

	pid = occ_spawn(&pt, wd, dbp, homep, toml, occbin);
	if (pid < 0) {
		OK(0, "spawn");
		return 1;
	}
	if (read_until_contains(pt.master, out, OUT_CAP, &have,
				"\x1b[?1049h", 8000) != 0) {
		OK(0, "enter-alt-screen");
		rc = 1;
		goto done;
	}
	OK(1, "enter-alt-screen");

	/* 提交提示词 → mock 回 write toolCall → 真落盘 → 工具结果收口 */
	if (write(pt.master, "落盘 u25\r", sizeof("落盘 u25\r") - 1) < 0) {
		OK(0, "submit-prompt");
		rc = 1;
		goto done;
	}
	if (read_until_contains(pt.master, out, OUT_CAP, &have,
				"收到工具结果", 20000) != 0) {
		OK(0, "write-turn-done");
		rc = 1;
		goto done;
	}
	OK(1, "write-turn-done");
	OK(stat(fpath, &st) == 0 && file_content_is(fpath, "undo-me"),
	   "file-written");
	/* 收口结算窗（worker join/status 归位后再 /undo——运行中会被
	 * busy 注记挡回） */
	usleep(800000);

	/* /undo：回填面板（被撤输入预填——/rename 同款 API，标题即证据；
	 * 全屏面板会临时盖住注记行，注记断言放 Esc 关面板后）+ 文件回滚
	 * （ABSENT→删除）。字节序：面板开（标题）→Esc 关（注记行露出）。 */
	mark = have;
	if (write(pt.master, "/undo\r", 6) < 0)
		OK(0, "undo-write");
	OK(wait_new(pt.master, out, OUT_CAP, &have, mark,
		    "undo 回填", 10000) == 0, "recall-overlay-opens");
	OK(stat(fpath, &st) != 0, "file-rolled-back");

	/* Esc 关面板（孤立 Esc 结算窗）→ 盖住的注记行露出：已撤销 N 条
	 * +M 文件回滚+无快照未回滚 K 处与 /redo 指引 */
	usleep(150000);
	if (write(pt.master, "\x1b", 1) < 0)
		OK(0, "esc-write");
	usleep(300000);
	OK(wait_new(pt.master, out, OUT_CAP, &have, mark,
		    "已撤销", 10000) == 0, "undo-notice");
	OK(wait_new(pt.master, out, OUT_CAP, &have, mark,
		    "/redo 可恢复", 10000) == 0, "undo-notice-redo-hint");

	/* /redo → 注记+文件复原 */
	mark = have;
	if (write(pt.master, "/redo\r", 6) < 0)
		OK(0, "redo-write");
	OK(wait_new(pt.master, out, OUT_CAP, &have, mark,
		    "已恢复", 10000) == 0, "redo-notice");
	OK(stat(fpath, &st) == 0 && file_content_is(fpath, "undo-me"),
	   "file-restored");

	/* 收尾 /exit */
	if (write(pt.master, "/exit\r", 6) < 0)
		OK(0, "exit-write");
	if (read_until_contains(pt.master, out, OUT_CAP, &have,
				"\x1b[?1049l", 8000) != 0)
		OK(0, "exit-alt-screen");
	else
		OK(1, "exit-alt-screen");
done:
	childrc = wait_child(pid);
	if (!rc)
		OK(childrc == 71 || childrc == 0, "child-exit-clean");
	close(pt.master);
	return rc;
}

/* ---- S2：无会话 /undo → 注记「尚无会话」（无可撤人话面） ---- */

static int s2_no_session(const char *root, const char *homep,
			 const char *toml, const char *occbin)
{
	static char out[OUT_CAP];
	char wd[300], dbp[360];
	struct pty pt;
	pid_t pid;
	int have = 0, mark;
	int rc = 0;
	int childrc;

	g_scn = "S2";
	snprintf(wd, sizeof(wd), "%s/S2", root);
	mkdir(wd, 0755);
	snprintf(dbp, sizeof(dbp), "%s/S2/sessions.db", root);

	pid = occ_spawn(&pt, wd, dbp, homep, toml, occbin);
	if (pid < 0) {
		OK(0, "spawn");
		return 1;
	}
	if (read_until_contains(pt.master, out, OUT_CAP, &have,
				"\x1b[?1049h", 8000) != 0) {
		OK(0, "enter-alt-screen");
		rc = 1;
		goto done;
	}
	OK(1, "enter-alt-screen");

	mark = have;
	if (write(pt.master, "/undo\r", 6) < 0)
		OK(0, "undo-write");
	OK(wait_new(pt.master, out, OUT_CAP, &have, mark,
		    "尚无会话", 5000) == 0, "undo-no-session-notice");

	if (write(pt.master, "/exit\r", 6) < 0)
		OK(0, "exit-write");
	if (read_until_contains(pt.master, out, OUT_CAP, &have,
				"\x1b[?1049l", 8000) != 0)
		OK(0, "exit-alt-screen");
	else
		OK(1, "exit-alt-screen");
done:
	childrc = wait_child(pid);
	if (!rc)
		OK(childrc == 71 || childrc == 0, "child-exit-clean");
	close(pt.master);
	return rc;
}

int main(void)
{
	char root[128], homep[160], toml[192], occbin[192];
	char reqdir[192];
	pid_t mock;
	int port;

	signal(SIGPIPE, SIG_IGN);

	if (access("../occ", X_OK) != 0) {
		printf("test_undo_cmd: SKIP（../occ 未构建——occ 顶层"
		       " make all 后生效）\n");
		return 0;
	}
	snprintf(root, sizeof(root), "/tmp/btui-o25-%d", (int)getpid());
	snprintf(homep, sizeof(homep), "/tmp/uxo_o25_home_%d", (int)getpid());
	if (mkdir(root, 0755) != 0 || mkdir(homep, 0700) != 0) {
		printf("FAIL fixture root/home\n");
		return 1;
	}
	snprintf(reqdir, sizeof(reqdir), "%s/req", root);
	mkdir(reqdir, 0755);
	port = 20000 + (int)(getpid() % 20000);

	/* model.toml → mock（write 走 workdir=W1，无需 policy 桩） */
	{
		FILE *f;

		snprintf(toml, sizeof(toml), "%s/model.toml", root);
		f = fopen(toml, "w");
		if (!f ||
		    fputs("[models.cloud]\n"
			  "provider_type = \"openai_compatible\"\n"
			  "model_name = \"mock-model\"\n"
			  "base_url = \"http://127.0.0.1:", f) < 0) {
			printf("FAIL fixture toml\n");
			return 1;
		}
		fprintf(f, "%d/v1\"\napi_key = \"mock-key-not-real\"\n", port);
		fclose(f);
	}
	/* occ 拷入 fixture（execl 绝对路径——子进程 chdir 后相对路径失效；
	 * test_w2_confirm_pty 同款） */
	{
		char cmd[512];

		snprintf(occbin, sizeof(occbin), "%s/occ", root);
		snprintf(cmd, sizeof(cmd), "cp ../occ %s", occbin);
		if (system(cmd) != 0 || access(occbin, X_OK) != 0) {
			printf("FAIL fixture occ copy\n");
			return 1;
		}
	}

	mock = mock_start(port, reqdir);
	if (mock <= 0) {
		printf("FAIL mock-start\n");
		return 1;
	}
	mock_wait_up(port);

	s1_full_loop(root, homep, toml, occbin, reqdir, port);
	s2_no_session(root, homep, toml, occbin);

	/* 清理 fixture（root/home；mock 已杀） */
	kill(mock, SIGKILL);
	{
		int st = 0;

		waitpid(mock, &st, 0);
	}
	{
		char cmd[400];

		snprintf(cmd, sizeof(cmd), "rm -rf %s %s", root, homep);
		if (system(cmd) != 0)
			printf("FAIL cleanup\n");
	}

	printf("test_undo_cmd: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
