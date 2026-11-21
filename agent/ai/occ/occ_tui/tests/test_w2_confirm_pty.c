/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_w2_confirm_pty.c - P-52 病①/病②回归：W2 确认面板端到端
 * （真 pty 驱动真 occ 二进制 + 本地 mock LLM）
 *
 * 病①：W2 面板无 y/n 快捷键（字符被 tui_overlay_type 静默丢）——
 *       S1/S2 实证 y 与 Enter 两条提交链；S2 是「Enter 真机/pty 聋」
 *       的裁决样本：若 CR 失败而 y 成功，如实 FAIL 输出现象，不绕断言。
 * 病②：gate 确认放行后 write_guard 照样硬拒越界（「双门」）——S6
 *       特权档确认后 /var/tmp 域外写真落盘（J-7=A w2_confirmed 豁免）。
 *
 * 场景（每场景独立子进程跑 occ；AIK_CONSOLE_GATE_SKIP=1；policy 桩全
 * privileged=特权档；HOME=/tmp/uxo_w52_home_<pid>；cwd=独立临时 workdir；
 * mock LLM=tests/mock_w2_llm.py 首答回 toolCall，127.0.0.1 绝无真网）：
 *   S1 y 快捷键：chmod 666 f.txt（刀1 语义级=W2）→面板→'y'→≤5s 工具
 *      真执行（mock 回投文案到屏）+ stat f.txt mode 含 o+w
 *   S2 Enter：同 S1 但发 '\r'（CR）——成败即「Enter 聋」裁决
 *   S3 n 拒绝：发 'n'→拒绝文案+mode 无 o+w
 *   S4 Esc 拒绝：发 0x1b→同 S3 断言
 *   S5 超时兜底：OCC_W2_TIMEOUT_MS=2000，面板后不发键→2~4s 拒绝文案
 *      +面板收起（/exit 能到达输入框=面板已关的代理断言）
 *   S6 写侧双门：write→/var/tmp/uxo_w52_out_<pid>_a/x.txt（域外、非
 *      ~/.occ）发 'y'→≤5s 真落盘；再跑 '_b' 发 'n'→无文件+拒绝文案
 *
 * 骨架复用 test_view_pty.c / test_su_pty.c 的 PTY+mock 手法（mock 起
 * 法/fixture 隔离/策略桩照 test_su_pty；SSE 参数结构照既有 mock）。
 *
 * 运行面：须以 root 跑（sudo ./tests/test_w2_confirm_pty——bench 生产
 * 面=特权档 root）。S1-S5 的 chmod 走 aik-sandbox（W71 能力裁到
 * CAP_NET_RAW、无 DAC_OVERRIDE/FOWNER）——沙箱内 chmod 需 uid 与文件
 * 属主一致：root 建的 f.txt + root occ=uid 匹配放行；非 root 跑则
 * EPERM（环境语义，非门/面板回归缺陷）。
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

/* 自 from 起等新字节（全缓冲找会命中历史 token——面板项/文案反复
 * 出现的串必须只认 from 后新字节；test_su_pty 同款） */
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
		/* 相对本测试二进制（occ_tui/ 下运行；test_rename_ai 同款） */
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

static int file_has_ow(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && (st.st_mode & S_IWOTH);
}

/* ---- 场景驱动 ---- */

struct scn {
	const char *tag;		/* S1…S6a/S6b（目录名+OK 前缀） */
	const char *tool;		/* mock ctl TOOL */
	char args[640];			/* mock ctl ARGS（JSON 对象文本） */
	const char *key;		/* 面板出现后写的键；NULL=不发 */
	int key_len;
	int esc_settle;			/* 1=单字节 Esc 孤立结算 100ms */
	int w2_timeout_ms;		/* OCC_W2_TIMEOUT_MS；0=缺省 */
	const char *allow_needle;	/* 放行侧新字节（NULL=跳过） */
	const char *deny_needle;	/* 拒绝侧新字节（NULL=跳过） */
	int deny_wait_ms;		/* 拒绝侧等待窗 */
	const char *probe;		/* stat 断言路径 */
	int want_exists;		/* 1=须存在 0=须不存在 */
	int want_ow;			/* 1=须 o+w 0=须无 o+w */
	const char *want_content;	/* 非空=内容精确断言 */
	/* ---- 本波扩展（O-6/O-18 新场景驱动面） ---- */
	const char *cwd_override;	/* O-6：子进程 chdir 目标（NULL=wd） */
	int no_panel;			/* O-6：1=不等 W2 面板（W1 工具直接跑） */
	const char *absent_all;	/* 全程输出不得出现的 needle */
	const char *second_prompt;	/* O-18：非空=两阶段（turn2 再提交） */
	char second_args[512];	/* turn2 mock ctl ARGS */
	const char *second_allow;	/* turn2 放行侧新字节证据 */
	const char *second_absent;	/* turn2 区间不得出现（免问断言） */
};

static int run_scenario(const struct scn *s, const char *root,
			const char *homep, const char *toml,
			const char *polp, const char *occbin,
			const char *reqdir)
{
	static char out[OUT_CAP];
	char wd[300], dbp[360], fpath[360], ctl[900];
	struct pty pt;
	struct winsize ws = { .ws_row = 24, .ws_col = 120 };
	pid_t pid;
	int have = 0, mark;
	int rc = 0;
	int childrc;

	g_scn = s->tag;
	/* 独立 workdir（cwd）+ f.txt 0644（chmod 场景靶件） */
	snprintf(wd, sizeof(wd), "%s/%s", root, s->tag);
	mkdir(wd, 0755);
	snprintf(fpath, sizeof(fpath), "%s/f.txt", wd);
	{
		FILE *f = fopen(fpath, "w");

		if (f) {
			fputs("w52\n", f);
			fclose(f);
		}
		chmod(fpath, 0644);
	}
	/* O-18 S8：turn2 靶件（免问放行后 o+w 断言用） */
	{
		char f2[360];
		FILE *f;

		snprintf(f2, sizeof(f2), "%s/f2.txt", wd);
		f = fopen(f2, "w");
		if (f) {
			fputs("w52\n", f);
			fclose(f);
		}
		chmod(f2, 0644);
	}
	snprintf(dbp, sizeof(dbp), "%s/%s/sessions.db", root, s->tag);
	snprintf(ctl, sizeof(ctl), "TOOL=%s\nARGS=%s\n", s->tool, s->args);
	write_ctl(reqdir, ctl);

	if (pty_open(&pt) != 0) {
		OK(0, "pty-open");
		return 1;
	}
	(void)ioctl(pt.slave, TIOCSWINSZ, &ws);
	pid = fork();
	if (pid < 0) {
		OK(0, "fork");
		close(pt.master);
		close(pt.slave);
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
		if (chdir(s->cwd_override ? s->cwd_override : wd) != 0)
			_exit(15);
		setenv("OCC_MODEL_TOML", toml, 1);
		setenv("OCC_DB", dbp, 1);
		setenv("HOME", homep, 1);
		setenv("TERM", "xterm", 1);
		setenv("AIK_CONSOLE_GATE_SKIP", "1", 1);
		setenv("AIKERNEL_POLICY", polp, 1);
		setenv("OCC_CATALOG", "/tmp/p52-none-catalog.json", 1);
		/* 重试旋钮压到最快（失败路径毫秒级收口；rename_ai 同款） */
		setenv("OCC_LLM_RETRY_MAX", "1", 1);
		setenv("OCC_LLM_RETRY_TIMEOUT_MAX", "1", 1);
		setenv("OCC_LLM_RETRY_BASE_MS", "50", 1);
		setenv("OCC_LLM_RETRY_CAP_MS", "100", 1);
		if (s->w2_timeout_ms > 0) {
			char tb[32];

			snprintf(tb, sizeof(tb), "%d", s->w2_timeout_ms);
			setenv("OCC_W2_TIMEOUT_MS", tb, 1);
		}
		execl(occbin, "occ", (char *)NULL);
		_exit(127);
	}
	close(pt.slave);
	pt.slave = -1;

	/* 进屏 → 提交提示词 → 等 W2 面板 */
	if (read_until_contains(pt.master, out, OUT_CAP, &have,
				"\x1b[?1049h", 8000) != 0) {
		OK(0, "enter-alt-screen");
		rc = 1;
		goto done;
	}
	OK(1, "enter-alt-screen");
	if (write(pt.master, "p52\r", 4) < 0) {
		OK(0, "submit-prompt");
		rc = 1;
		goto done;
	}
	if (s->no_panel) {
		/* O-6：W1 工具直接执行——不等面板 */
		mark = have;
	} else if (read_until_contains(pt.master, out, OUT_CAP, &have,
				     "W2 高危操作确认", 15000) != 0) {
		OK(0, "panel-opens");
		rc = 1;
		goto done;
	} else {
		OK(1, "panel-opens");
	}
	mark = have;

	/* 面板应答（S5 超时场景不发键） */
	if (s->key && s->key_len > 0) {
		if (write(pt.master, s->key, (size_t)s->key_len) < 0)
			OK(0, "key-write");
		/* 单字节裸 Esc：25ms 孤立结算窗（后续字节过早到达会被并成
		 * Alt+键——test_su_pty 同款） */
		if (s->esc_settle)
			usleep(150000);
	}
	/* 放行侧：≤5s 断言工具真执行（mock 回投文案=工具链走通的新字节） */
	if (s->allow_needle)
		OK(wait_new(pt.master, out, OUT_CAP, &have, mark,
			    s->allow_needle, 5000) == 0,
		   "tool-exec-evidence");
	/* 拒绝侧：拒绝文案新字节（S5=超时窗 2~4s） */
	if (s->deny_needle)
		OK(wait_new(pt.master, out, OUT_CAP, &have, mark,
			    s->deny_needle, s->deny_wait_ms) == 0,
		   "deny-text");

	/* O-18 两阶段：turn1 收口后改写 ctl（mock 逐请求重读
	 * ctl）→ 再提交一轮→ turn2 证据/免问断言 */
	if (s->second_prompt) {
		int mark2 = have;

		snprintf(ctl, sizeof(ctl), "TOOL=%s\nARGS=%s\n",
			 s->tool, s->second_args);
		write_ctl(reqdir, ctl);
		if (write(pt.master, s->second_prompt,
			   strlen(s->second_prompt)) < 0)
			OK(0, "second-submit");
		if (s->second_allow)
			OK(wait_new(pt.master, out, OUT_CAP, &have, mark2,
				    s->second_allow, 8000) == 0,
			   "second-turn-evidence");
		if (s->second_absent) {
			const char *seg = out + (mark2 < (int)sizeof(out) ?
						 mark2 : 0);

			OK(strstr(seg, s->second_absent) == NULL,
			   "second-no-panel");
		}
	}

	/* O-6：全程不得出现的 needle（如非法 rw-path 报错特征） */
	if (s->absent_all)
		OK(strstr(out, s->absent_all) == NULL, "absent-all");

	/* 收尾 /exit：面板已关（submit/超时收板）→ /exit 到达输入框 →
	 * occ 退出（71=注销语义/0 均可）。面板若仍开着，/exit 字符会被
	 * 模态面板吞掉——退不出即 FAIL（面板收起的代理断言）。 */
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

	/* 世界态断言（occ 退出后 stat——文件真值） */
	if (s->want_exists == 1) {
		struct stat st;

		OK(stat(s->probe, &st) == 0, "probe-exists");
		if (s->want_content) {
			FILE *f = fopen(s->probe, "r");
			char buf[64];
			size_t n = 0;

			if (f) {
				n = fread(buf, 1, sizeof(buf) - 1, f);
				fclose(f);
				buf[n] = '\0';
			}
			OK(f && strcmp(buf, s->want_content) == 0,
			   "probe-content");
		}
	} else if (s->want_exists == 0) {
		struct stat st;

		OK(stat(s->probe, &st) != 0, "probe-absent");
	}
	if (s->want_ow == 1) {
		/* P-58②：chmod 探针经 aik-sandbox（非 root 经 sudo 组装=
		 * 区内 root 无 DAC_OVERRIDE 对他属主文件必 EPERM）——
		 * root-only 断言，非 root 显式 SKIP 不冒充失败 */
		if (geteuid() == 0)
			OK(file_has_ow(s->probe), "file-o+w-set");
		else
			printf("SKIP file-o+w-set (root-only: "
			       "sandbox uid coupling)\n");
	} else if (s->want_ow == 0 && s->want_exists != 0)
		OK(!file_has_ow(s->probe), "file-no-o+w");
	return rc;
}

int main(void)
{
	char root[128], homep[160], toml[192], polp[192], occbin[192];
	char reqdir[192];
	pid_t mock;
	int port;

	signal(SIGPIPE, SIG_IGN);

	if (access("../occ", X_OK) != 0) {
		printf("test_w2_confirm_pty: SKIP（../occ 未构建——occ 顶层"
		       " make all 后生效）\n");
		return 0;
	}
	snprintf(root, sizeof(root), "/tmp/btui-w52-%d", (int)getpid());
	snprintf(homep, sizeof(homep), "/tmp/uxo_w52_home_%d", (int)getpid());
	if (mkdir(root, 0755) != 0 || mkdir(homep, 0700) != 0) {
		printf("FAIL fixture root/home\n");
		return 1;
	}
	snprintf(reqdir, sizeof(reqdir), "%s/req", root);
	mkdir(reqdir, 0755);
	port = 20000 + (int)(getpid() % 20000);

	/* model.toml → mock；policy 桩全 privileged（tier=特权档，
	 * 与运行 uid 无关——test_su_pty 的 restricted 桩同款手法） */
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
		snprintf(polp, sizeof(polp), "%s/policy.conf", root);
		f = fopen(polp, "w");
		if (!f ||
		    fputs("[root]\nmode = privileged\n"
			  "[wheel]\nmode = privileged\ngroup = p52-nogrp\n"
			  "[default]\nmode = privileged\n", f) < 0) {
			printf("FAIL fixture policy\n");
			return 1;
		}
		fclose(f);
	}
	/* occ 拷入 fixture（execl 绝对路径——子进程 chdir 后相对路径失效；
	 * test_su_pty 同款） */
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

	/* ---- S1 y 快捷键：chmod 666（刀1=W2）→ y → 真执行+o+w ---- */
	{
		struct scn s;
		char args[512], fpath[360];

		snprintf(fpath, sizeof(fpath), "/tmp/btui-w52-%d/S1/f.txt",
			 (int)getpid());
		/* 相对路径 f.txt：沙箱内以 cwd=workdir 执行（rw bind 同绝
		 * 对路径，但相对路径最稳）；外层断言用绝对 fpath stat */
		snprintf(args, sizeof(args),
			 "{\"command\":\"chmod 666 f.txt\"}");
		memset(&s, 0, sizeof(s));
		s.tag = "S1";
		s.tool = "bash";
		snprintf(s.args, sizeof(s.args), "%s", args);
		s.key = "y";
		s.key_len = 1;
		s.allow_needle = "收到工具结果";	/* 工具链走通=回投文案 */
		s.probe = fpath;
		s.want_exists = 1;
		s.want_ow = 1;
		run_scenario(&s, root, homep, toml, polp, occbin, reqdir);
	}
	/* ---- S2 Enter：同 S1 但发 '\r'（CR）——「Enter 聋」裁决样本 ---- */
	{
		struct scn s;
		char args[512], fpath[360];

		snprintf(fpath, sizeof(fpath), "/tmp/btui-w52-%d/S2/f.txt",
			 (int)getpid());
		/* 相对路径 f.txt：沙箱内以 cwd=workdir 执行（rw bind 同绝
		 * 对路径，但相对路径最稳）；外层断言用绝对 fpath stat */
		snprintf(args, sizeof(args),
			 "{\"command\":\"chmod 666 f.txt\"}");
		memset(&s, 0, sizeof(s));
		s.tag = "S2";
		s.tool = "bash";
		snprintf(s.args, sizeof(s.args), "%s", args);
		s.key = "\r";
		s.key_len = 1;
		s.allow_needle = "收到工具结果";
		s.probe = fpath;
		s.want_exists = 1;
		s.want_ow = 1;
		run_scenario(&s, root, homep, toml, polp, occbin, reqdir);
	}
	/* ---- S3 n 拒绝 ---- */
	{
		struct scn s;
		char args[512], fpath[360];

		snprintf(fpath, sizeof(fpath), "/tmp/btui-w52-%d/S3/f.txt",
			 (int)getpid());
		/* 相对路径 f.txt：沙箱内以 cwd=workdir 执行（rw bind 同绝
		 * 对路径，但相对路径最稳）；外层断言用绝对 fpath stat */
		snprintf(args, sizeof(args),
			 "{\"command\":\"chmod 666 f.txt\"}");
		memset(&s, 0, sizeof(s));
		s.tag = "S3";
		s.tool = "bash";
		snprintf(s.args, sizeof(s.args), "%s", args);
		s.key = "n";
		s.key_len = 1;
		s.deny_needle = "W2 拒绝";
		s.deny_wait_ms = 5000;
		s.probe = fpath;
		s.want_exists = 1;
		s.want_ow = 0;
		run_scenario(&s, root, homep, toml, polp, occbin, reqdir);
	}
	/* ---- S4 Esc 拒绝（孤立 Esc 结算窗） ---- */
	{
		struct scn s;
		char args[512], fpath[360];

		snprintf(fpath, sizeof(fpath), "/tmp/btui-w52-%d/S4/f.txt",
			 (int)getpid());
		/* 相对路径 f.txt：沙箱内以 cwd=workdir 执行（rw bind 同绝
		 * 对路径，但相对路径最稳）；外层断言用绝对 fpath stat */
		snprintf(args, sizeof(args),
			 "{\"command\":\"chmod 666 f.txt\"}");
		memset(&s, 0, sizeof(s));
		s.tag = "S4";
		s.tool = "bash";
		snprintf(s.args, sizeof(s.args), "%s", args);
		s.key = "\x1b";
		s.key_len = 1;
		s.esc_settle = 1;
		s.deny_needle = "W2 拒绝";
		s.deny_wait_ms = 5000;
		s.probe = fpath;
		s.want_exists = 1;
		s.want_ow = 0;
		run_scenario(&s, root, homep, toml, polp, occbin, reqdir);
	}
	/* ---- S5 超时兜底：OCC_W2_TIMEOUT_MS=2000，面板后不发键 ---- */
	{
		struct scn s;
		char args[512], fpath[360];

		snprintf(fpath, sizeof(fpath), "/tmp/btui-w52-%d/S5/f.txt",
			 (int)getpid());
		/* 相对路径 f.txt：沙箱内以 cwd=workdir 执行（rw bind 同绝
		 * 对路径，但相对路径最稳）；外层断言用绝对 fpath stat */
		snprintf(args, sizeof(args),
			 "{\"command\":\"chmod 666 f.txt\"}");
		memset(&s, 0, sizeof(s));
		s.tag = "S5";
		s.tool = "bash";
		snprintf(s.args, sizeof(s.args), "%s", args);
		s.key = NULL;
		s.w2_timeout_ms = 2000;
		s.deny_needle = "W2 拒绝";
		s.deny_wait_ms = 4000;		/* 2~4s 窗（超时 2s+余量） */
		s.probe = fpath;
		s.want_exists = 1;
		s.want_ow = 0;
		run_scenario(&s, root, homep, toml, polp, occbin, reqdir);
	}
	/* ---- S6 写侧双门：域外写确认后真落盘（y）／拒绝无文件（n） ---- */
	{
		struct scn s;
		char out_a[360], out_b[360];

		snprintf(out_a, sizeof(out_a),
			 "/var/tmp/uxo_w52_out_%d_a/x.txt", (int)getpid());
		snprintf(out_b, sizeof(out_b),
			 "/var/tmp/uxo_w52_out_%d_b/x.txt", (int)getpid());
		unlink(out_a);
		unlink(out_b);

		memset(&s, 0, sizeof(s));
		s.tag = "S6a";
		s.tool = "write";
		snprintf(s.args, sizeof(s.args),
			 "{\"path\":\"%s\",\"content\":\"p52\"}", out_a);
		s.key = "y";
		s.key_len = 1;
		s.allow_needle = "已写入";	/* write 工具真落盘文案 */
		s.probe = out_a;
		s.want_exists = 1;
		s.want_content = "p52";
		run_scenario(&s, root, homep, toml, polp, occbin, reqdir);

		memset(&s, 0, sizeof(s));
		s.tag = "S6b";
		s.tool = "write";
		snprintf(s.args, sizeof(s.args),
			 "{\"path\":\"%s\",\"content\":\"p52\"}", out_b);
		s.key = "n";
		s.key_len = 1;
		s.deny_needle = "W2 拒绝";
		s.deny_wait_ms = 5000;
		s.probe = out_b;
		s.want_exists = 0;
		run_scenario(&s, root, homep, toml, polp, occbin, reqdir);
	}

	/* ---- S7（O-6）：cwd=/root 起 occ→workdir 回退 /var/ai/work，
	 * ---- 首发 bash pwd 不再非法 rw-path 且输出含回退值（无面板 W1 直接跑）
	 * ---- P-58②：cwd=/root 本身需 root——非 root 显式 SKIP ---- */
	if (geteuid() != 0) {
		printf("SKIP S7 (root-only: cwd=/root premise)\n");
	} else {
		struct scn s;

		memset(&s, 0, sizeof(s));
		s.tag = "S7";
		s.tool = "bash";
		snprintf(s.args, sizeof(s.args),
			 "{\"command\":\"pwd\"}");
		s.cwd_override = "/root";
		s.no_panel = 1;
		s.allow_needle = "/var/ai/work";	/* notice 或 pwd 输出 */
		s.absent_all = "非法";		/* rw-path 拒绝报错特征 */
		run_scenario(&s, root, homep, toml, polp, occbin, reqdir);
	}

	/* ---- S8（O-18）：chmod 666→s 本会话同类放行→第二个
	 * ---- chmod 666 不同路径无面板直接执行（f2.txt o+w 为证） ---- */
	{
		struct scn s;
		char f2[360];

		snprintf(f2, sizeof(f2), "/tmp/btui-w52-%d/S8/f2.txt",
			 (int)getpid());
		memset(&s, 0, sizeof(s));
		s.tag = "S8";
		s.tool = "bash";
		snprintf(s.args, sizeof(s.args),
			 "{\"command\":\"chmod 666 f.txt\"}");
		s.key = "s";
		s.key_len = 1;
		s.allow_needle = "收到工具结果";	/* turn1 收口 */
		s.second_prompt = "p52\r";
		snprintf(s.second_args, sizeof(s.second_args),
			 "{\"command\":\"chmod 666 f2.txt\"}");
		s.second_allow = "收到工具结果";
		s.second_absent = "W2 高危操作确认";
		s.probe = f2;
		s.want_exists = 1;
		s.want_ow = 1;
		run_scenario(&s, root, homep, toml, polp, occbin, reqdir);
	}

	/* 清理 fixture（root/home//var/tmp 产物；mock 已杀） */
	kill(mock, SIGKILL);
	{
		int st = 0;

		waitpid(mock, &st, 0);
	}
	{
		char cmd[600];

		snprintf(cmd, sizeof(cmd),
			 "rm -rf %s %s /var/tmp/uxo_w52_out_%d_a"
			 " /var/tmp/uxo_w52_out_%d_b",
			 root, homep, (int)getpid(), (int)getpid());
		if (system(cmd) != 0)
			printf("FAIL cleanup\n");
	}

	printf("test_w2_confirm_pty: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
