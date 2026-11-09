/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_rename_ai.c - B8 /rename 空题=AI 生成标题：真 occ 二进制 pty 台架
 *
 * 手法（test_view_pty 同源）：fork pty 子进程 exec 真 ../occ（交互 TUI 全
 * 路径——输入覆盖层/on_overlay_input/异步 worker/occ_llm_call），本地
 * mock_title_llm.py 充当端点（127.0.0.1，绝无真网/真 key）。四路径：
 *   R1 成功：首条消息 turn → /rename 空回车 → 「renamed → <题>」进字节
 *      流 + 请求体含首条 user 消息（req 落盘复核）
 *   R2 超长截断：60B 标题 → 恰 48B（ASCII 对拍）真改名
 *   R3 失败降级：mock 500（重试旋钮压到 1 次尝试）→ 诚实错误留步、
 *      「renamed」零出现（空题旧语义=不改名）
 *   R4 取消+不阻塞：mock 挂 30s → busy spinner 帧常刷（主循环活着）
 *      → Esc 取消 → 「已取消」留步、零改名
 * 前置：../occ 已构建（occ 顶层 make all）；未构建则诚实 skip（exit 0）。
 */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
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
	for (i = 0; i <= haylen - (int)nlen; i++) {
		if (memcmp(hay + i, needle, nlen) == 0)
			return hay + i;
	}
	return NULL;
}

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
		if (n > 0) {
			*have += (int)n;
			continue;
		}
		if (n == 0)
			return 1;
		if (errno == EINTR)
			continue;
		if (errno == EIO)
			return 1;
		return -1;
	}
}

/* ---- mock 服务器 ---- */

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
		/* 相对本测试二进制（occ_tui/ 下运行） */
		snprintf(path, sizeof(path), "%s/mock_title_llm.py",
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

/* ---- 场景驱动 ----
 * steps：交替 [写字节, 等needle]；写 NULL=跳过写。返回 0=全过。 */
struct step {
	const char *write_bytes;	/* NULL=不写 */
	size_t write_len;
	const char *needle;		/* 等 pty 流出现（NULL=不等） */
	int esc_split;			/* 1=首字节 Esc 单独写+60ms（裸 Esc 语义） */
};

static int run_occ(const char *tmpdir, int port,
		   const struct step *steps, int nsteps,
		   char *out, int *out_len)
{
	struct pty pt;
	pid_t pid;
	int have = 0;
	int i;
	int rc = 0;
	struct winsize ws = { .ws_row = 24, .ws_col = 80 };
	char toml[512], dbp[512], homep[512];

	snprintf(toml, sizeof(toml), "%s/model.toml", tmpdir);
	{
		FILE *f = fopen(toml, "w");

		if (!f)
			return -1;
		fprintf(f,
			"[models.cloud]\n"
			"provider_type = \"openai_compatible\"\n"
			"model_name = \"mock-model\"\n"
			"base_url = \"http://127.0.0.1:%d/v1\"\n"
			"api_key = \"mock-key-not-real\"\n",
			port);
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
		/* 重试旋钮压到最快（失败路径毫秒级收口） */
		setenv("OCC_LLM_RETRY_MAX", "1", 1);
		setenv("OCC_LLM_RETRY_TIMEOUT_MAX", "1", 1);
		setenv("OCC_LLM_RETRY_BASE_MS", "50", 1);
		setenv("OCC_LLM_RETRY_CAP_MS", "100", 1);
		execl("../occ", "occ", (char *)NULL);
		_exit(127);
	}
	close(pt.slave);
	pt.slave = -1;

	/* 等进屏（tcsetattr TCSAFLUSH 冲刷过早输入——先等 alt-screen） */
	if (read_until_contains(pt.master, out, OUT_CAP, &have,
				"\x1b[?1049h", 8000) != 0)
		rc = -1;
	for (i = 0; i < nsteps && rc == 0; i++) {
		if (steps[i].write_bytes && steps[i].write_len) {
			if (steps[i].esc_split &&
			    (unsigned char)steps[i].write_bytes[0] == 0x1b &&
			    steps[i].write_len > 1) {
				if (write(pt.master, steps[i].write_bytes, 1) < 0)
					rc = -1;
				usleep(60000);
				if (write(pt.master, steps[i].write_bytes + 1,
					  steps[i].write_len - 1) < 0)
					rc = -1;
			} else if (write(pt.master, steps[i].write_bytes,
					 steps[i].write_len) < 0) {
				rc = -1;
			}
			/* 单字节裸 Esc：等 25ms 孤立 Esc 结算窗过后再进行
			 * （后续字节过早到达会被并成 Alt+键——面板关不上） */
			if (steps[i].write_len == 1 &&
			    (unsigned char)steps[i].write_bytes[0] == 0x1b)
				usleep(100000);
		}
		if (rc == 0 && steps[i].needle) {
			if (read_until_contains(pt.master, out, OUT_CAP, &have,
						steps[i].needle, 15000) != 0) {
				printf("  dbg: step %d needle '%s' missing "
				       "(have=%d)\n", i, steps[i].needle,
				       have);
				rc = -1;
			}
		}
	}
	/* 收尾：/exit + 等 leave */
	if (rc == 0) {
		if (write(pt.master, "/exit\r", 6) < 0)
			rc = -1;
		else if (read_until_contains(pt.master, out, OUT_CAP, &have,
					     "\x1b[?1049l", 8000) != 0)
			rc = -1;
	}
	*out_len = have;
	{
		int st = 0;
		int w;

		for (w = 0; w < 50; w++) {
			pid_t r = waitpid(pid, &st, WNOHANG);

			if (r == pid)
				break;
			usleep(100000);
		}
		if (w == 50) {
			kill(pid, SIGKILL);
			waitpid(pid, &st, 0);
			rc = -1;
		} else if (rc == 0 &&
			   (!WIFEXITED(st) || WEXITSTATUS(st) != 0)) {
			printf("  child exit=%d\n",
			       WIFEXITED(st) ? WEXITSTATUS(st) : -1);
			rc = -1;
		}
	}
	close(pt.master);
	return rc;
}

/* 检查 req 落盘文件含 marker（输入=首条 user 消息断言） */
static int reqdir_contains(const char *reqdir, const char *marker, int nmin)
{
	int i;
	char path[512];

	for (i = 1; i <= nmin; i++) {
		FILE *f;
		char buf[65536];
		size_t n;

		snprintf(path, sizeof(path), "%s/req_%d.json", reqdir, i);
		f = fopen(path, "r");
		if (!f)
			continue;
		n = fread(buf, 1, sizeof(buf) - 1, f);
		fclose(f);
		buf[n] = '\0';
		if (strstr(buf, marker))
			return i;
	}
	return 0;
}

/* 写 mock 控制文件（env 在 mock 启动时固化——ctl 才是场景旋钮） */
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

/* 直查 fixture 库最新会话标题（pty 字节会被 wordwrap 折行撕串——
 * 库值才是改名真值的字节级断言位） */
static int db_latest_title(const char *db, char *out, size_t cap)
{
	char cmd[768];
	FILE *p;
	size_t n;

	snprintf(cmd, sizeof(cmd),
		 "python3 -c \"import sqlite3,sys;"
		 "db=sqlite3.connect('%s');"
		 "r=db.execute('select title from occ_session "
		 "order by created desc limit 1').fetchone();"
		 "sys.stdout.write(r[0] if r else '')\"", db);
	p = popen(cmd, "r");
	if (!p)
		return -1;
	n = fread(out, 1, cap - 1, p);
	pclose(p);
	out[n] = '\0';
	while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
		out[--n] = '\0';
	return (int)n;
}

int main(void)
{
	static char out[OUT_CAP];
	int out_len = 0;
	char tmpl[] = "/tmp/btui-ren-XXXXXX";
	char *tmp;
	int port;
	pid_t mock;
	int rc;

	signal(SIGPIPE, SIG_IGN);

	if (access("../occ", X_OK) != 0) {
		printf("test_rename_ai: SKIP（../occ 未构建——occ 顶层 "
		       "make all 后生效）\n");
		return 0;
	}
	tmp = mkdtemp(tmpl);
	if (!tmp) {
		printf("FAIL mkdtemp\n");
		return 1;
	}
	port = 20000 + (int)(getpid() % 20000);
	{
		char reqdir[512];

		snprintf(reqdir, sizeof(reqdir), "%s/req", tmp);
		mock = mock_start(port, reqdir);
		OK(mock > 0, "mock-start");
		if (mock <= 0)
			return 1;
		mock_wait_up(port);

		/* 空回车=AI 生成：rename 面板预填现题——先 120×退格清空
		 * （tui_overlay_backspace 空缓冲安全）再回车才是「空提交」 */
		static char clr_enter[128];
		int ci;

		for (ci = 0; ci < 120; ci++)
			clr_enter[ci] = '\x7f';
		clr_enter[120] = '\r';

		/* ---- R1 成功：AI 生成 → renamed → <题>（CJK 短题） ---- */
		{
			struct step st[] = {
				{ "我的首条消息：内核调度器排障要点\r", 0,
				  "\xe6\x94\xb6\xe5\x88\xb0\xef\xbc\x8c\xe7\xac\xac"
				  "\xe4\xb8\x80\xe6\x9d\xa1\xe6\xb6\x88\xe6\x81\xaf"
				  "\xe5\xb7\xb2\xe8\xae\xb0\xe5\xbd\x95", 0 },
				{ "/rename\r", 0, "AI", 0 },
				{ NULL, 0, "renamed", 0 },
			};
			char dbt[128];
			char dbp[512];

			snprintf(dbp, sizeof(dbp), "%s/sessions.db", tmp);
			st[0].write_len = strlen(st[0].write_bytes);
			st[1].write_len = strlen(st[1].write_bytes);
			st[2].write_bytes = clr_enter;
			st[2].write_len = 121;
			write_ctl(reqdir, "# default\n");
			rc = run_occ(tmp, port, st, 3, out, &out_len);
			OK(rc == 0, "R1-success-flow");
			OK(find_bytes(out, out_len, "renamed \xe2\x86\x92") !=
			   NULL, "R1-renamed-arrow");
			OK(find_bytes(out, out_len,
				      "\xe5\x86\x85\xe6\xa0\xb8\xe8\xb0\x83"
				      "\xe5\xba\xa6\xe5\x99\xa8\xe6\x8e\x92"
				      "\xe9\x9a\x9c") != NULL,
			   "R1-title-cjk-bytes");	/* 内核调度器排障 */
			/* 库值=改名真值（字节级） */
			OK(db_latest_title(dbp, dbt, sizeof(dbt)) > 0 &&
			   !strcmp(dbt, "\xe5\x86\x85\xe6\xa0\xb8\xe8\xb0\x83"
				   "\xe5\xba\xa6\xe5\x99\xa8\xe6\x8e\x92"
				   "\xe9\x9a\x9c"),
			   "R1-db-title-exact");	/* 内核调度器排障 */
			/* 生成请求体含首条 user 消息（req 落盘复核） */
			{
				int hit = reqdir_contains(reqdir,
							  "\xe8\xb0\x83\xe5\xba\xa6"
							  "\xe5\x99\xa8\xe6\x8e\x92"
							  "\xe9\x9a\x9c\xe8\xa6\x81"
							  "\xe7\x82\xb9", 4);

				OK(hit > 0, "R1-req-has-first-user-msg");
			}
		}

		/* ---- R2 超长截断：60B ASCII 标题 → 恰 48B（库值对拍） ---- */
		{
			/* 60 位数字；期望库标题=前 48 位（renamed 行会被
			 * wordwrap 折行——整串断言不可靠，库值才是真值） */
			static const char long60[] =
				"0123456789012345678901234567890123456789"
				"01234567890123456789";		/* 恰 60 */
			char dbt[128];
			char ctl[128];
			char dbp[512];
			struct step st[] = {
				{ "第二条会话消息\r", 0,
				  "\xe6\x94\xb6\xe5\x88\xb0", 0 },
				{ "/rename\r", 0, "AI", 0 },
				{ NULL, 0, "renamed", 0 },
			};

			snprintf(dbp, sizeof(dbp), "%s/sessions.db", tmp);
			st[0].write_len = strlen(st[0].write_bytes);
			st[1].write_len = strlen(st[1].write_bytes);
			st[2].write_bytes = clr_enter;
			st[2].write_len = 121;
			OK(strlen(long60) == 60, "R2-fixture-60B");
			snprintf(ctl, sizeof(ctl), "TEXT=%s\n", long60);
			write_ctl(reqdir, ctl);
			rc = run_occ(tmp, port, st, 3, out, &out_len);
			OK(rc == 0, "R2-long-title-flow");
			OK(db_latest_title(dbp, dbt, sizeof(dbt)) == 48 &&
			   !strncmp(dbt, long60, 48),
			   "R2-db-title-truncated-48B");
			/* 未截断的 52 位长跑不得改名进库 */
			OK(strlen(dbt) == 48, "R2-db-title-not-longer");
			write_ctl(reqdir, "# reset\n");
		}

		/* ---- R3 失败降级：mock 500 → 诚实错误、不改名 ---- */
		{
			struct step st[] = {
				{ "第三条会话消息\r", 0,
				  "\xe6\x94\xb6\xe5\x88\xb0", 0 },
				{ "/rename\r", 0, "AI", 0 },
				{ NULL, 0,
				  "AI \xe7\x94\x9f\xe6\x88\x90\xe6\xa0\x87"
				  "\xe9\xa2\x98\xe5\xa4\xb1\xe8\xb4\xa5", 0 },
				{ "\x1b", 1, NULL, 0 },	/* Esc 关面板（留步后） */
			};

			st[0].write_len = strlen(st[0].write_bytes);
			st[1].write_len = strlen(st[1].write_bytes);
			st[2].write_bytes = clr_enter;
			st[2].write_len = 121;
			st[3].write_len = 1;
			st[3].esc_split = 1;
			write_ctl(reqdir, "FAIL=1\n");
			rc = run_occ(tmp, port, st, 4, out, &out_len);
			OK(rc == 0, "R3-fail-flow");
			OK(find_bytes(out, out_len,
				      "AI \xe7\x94\x9f\xe6\x88\x90\xe6\xa0\x87"
				      "\xe9\xa2\x98\xe5\xa4\xb1\xe8\xb4\xa5") !=
			   NULL, "R3-honest-error");
			OK(find_bytes(out, out_len, "renamed \xe2\x86\x92") ==
			   NULL, "R3-no-rename");
			write_ctl(reqdir, "# reset\n");
		}

		/* ---- R4 取消 + 不阻塞：mock 挂 30s；busy spinner 常刷
		 * （主循环不卡）；Esc → 已取消留步、不改名 ---- */
		{
			struct step st[] = {
				{ "第四条会话消息\r", 0,
				  "\xe6\x94\xb6\xe5\x88\xb0", 0 },
				{ "/rename\r", 0, "AI", 0 },
				{ NULL, 0,
				  "\xe7\x94\x9f\xe6\x88\x90\xe6\xa0\x87"
				  "\xe9\xa2\x98\xe4\xb8\xad", 0 }, /* 生成标题中 */
				{ "\x1b", 1,
				  "\xe5\xb7\xb2\xe5\x8f\x96\xe6\xb6\x88", 0 },
				{ "\x1b", 1, NULL, 0 },	/* Esc 关面板（留步后） */
			};

			st[0].write_len = strlen(st[0].write_bytes);
			st[1].write_len = strlen(st[1].write_bytes);
			st[2].write_bytes = clr_enter;
			st[2].write_len = 121;
			st[3].write_len = 1;
			st[3].esc_split = 1;
			st[4].write_len = 1;
			st[4].esc_split = 1;
			write_ctl(reqdir, "HANG=1\n");
			rc = run_occ(tmp, port, st, 5, out, &out_len);
			OK(rc == 0, "R4-cancel-flow");
			/* busy spinner 帧字节（U+2800 段 braille）=主循环活 */
			OK(find_bytes(out, out_len, "\xe2\xa0") != NULL,
			   "R4-busy-spinner-alive");
			OK(find_bytes(out, out_len,
				      "\xe5\xb7\xb2\xe5\x8f\x96\xe6\xb6\x88") !=
			   NULL, "R4-cancelled-notice");
			OK(find_bytes(out, out_len, "renamed \xe2\x86\x92") ==
			   NULL, "R4-no-rename");
			write_ctl(reqdir, "# reset\n");
		}

		kill(mock, SIGKILL);
		waitpid(mock, NULL, 0);
	}
	printf("test_rename_ai: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
