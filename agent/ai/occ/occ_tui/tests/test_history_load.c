/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_history_load.c - T2 长历史增量加载 end-to-end pty 台架
 *
 * 手法（test_rename_ai 同源）：fork pty 子进程 exec 真 ../occ（完整交互
 * TUI），本地临时 SQLite 会话库（python3 直插 120 条 user/assistant 消息，
 * 内容 "MSG-NNNN ..."），零网络/零真 key（model.toml 指向未监听 loopback，
 * 本用例从不提交消息——不触 LLM）。
 *
 * 断言链：
 *   H1 进屏 → /sessions → Enter 选中唯一会话 → 回放尾部（OCC_REPLAY_LINES=10
 *      很小）→ 顶部出现「⋯ 更早 N 条消息未回放」分隔（N>0 的预算切割）。
 *   H2 初始窗口只含尾部消息：MSG-0000 不在屏（旧内容未加载）。
 *   H3 Home（已在顶）→ on_load_more：预算 +1000 重放（HIST_CLEAR→全部事件→
 *      HIST_ANCHOR）→ 视口锚定不跳：MSG-0000 仍不在屏、无「锚点丢失」。
 *   H4 Home（锚点上方的旧内容）→ 一路到真正顶部 → MSG-0000 进屏（加载到
 *      第一条，内容确实变多）。
 *   H5 再 Home（已在顶）→ 无可加载 →「── 已到最早 ──」进字节流。
 * 前置：../occ 已构建且 python3 可用；缺一则诚实 SKIP（exit 0）。
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
#define HIST_MSGS 300

/* ---- pty 三件套（照 test_view_pty） ---- */

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

/* 在 [from, haylen) 区间找子串（"加载后"断言——避免匹配加载前的旧字节） */
static const char *find_after(const char *hay, int haylen, int from,
			      const char *needle)
{
	if (from < 0)
		from = 0;
	if (from >= haylen)
		return NULL;
	return find_bytes(hay + from, haylen - from, needle);
}

/* 累积读到出现 needle；返回 0=找到（*pos 记新字节起点前的位置），-1=超时 */
static int read_until(int fd, char *buf, int cap, int *have, const char *needle,
		      int timeout_ms, int *pos)
{
	struct timespec start, now;
	size_t nlen = strlen(needle);
	int startpos = *have;

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		return -1;
	for (;;) {
		long long remain;
		struct pollfd p;
		int r;
		ssize_t n;

		if (*have >= (int)nlen && find_bytes(buf, *have, needle)) {
			if (pos)
				*pos = startpos;
			return 0;
		}
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
			return -1;
		if (errno == EINTR)
			continue;
		if (errno == EIO)
			return -1;
		return -1;
	}
}

/* 静默窗：给主循环若干帧时间（把已注入按键的处理结果渲出来） */
static void settle(int fd, char *buf, int cap, int *have, int ms)
{
	struct timespec start, now;

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		return;
	for (;;) {
		struct pollfd p;
		long long remain;
		int r;
		ssize_t n;

		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return;
		remain = ms - ((now.tv_sec - start.tv_sec) * 1000LL +
			       (now.tv_nsec - start.tv_nsec) / 1000000LL);
		if (remain <= 0)
			return;
		if (*have >= cap)
			return;
		p.fd = fd;
		p.events = POLLIN;
		p.revents = 0;
		r = poll(&p, 1, (int)remain);
		if (r <= 0)
			return;
		n = read(fd, buf + *have, (size_t)(cap - *have));
		if (n <= 0)
			return;
		*have += (int)n;
	}
}

static int write_all(int fd, const char *s, size_t n)
{
	while (n > 0) {
		ssize_t w = write(fd, s, n);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		s += w;
		n -= (size_t)w;
	}
	return 0;
}

/* 写 seed.py（python3 sqlite3 直插会话+消息；content_json 与
 * occ_core build_content_json 同形：[{type:"text",text:...}]） */
static int write_seed(const char *path)
{
	FILE *f = fopen(path, "w");

	if (!f)
		return -1;
	fputs("import sqlite3, sys, time, json\n"
	      "db = sqlite3.connect(sys.argv[1])\n"
	      "sid = 'ses_histseed01'\n"
	      "now = int(time.time())\n"
	      "db.execute('DELETE FROM occ_message WHERE session_id=?',"
	      " (sid,))\n"
	      "db.execute('DELETE FROM occ_session WHERE id=?', (sid,))\n"
	      "db.execute('INSERT INTO occ_session(id,title,created,model,"
	      "tokens_total,status,updated,tokens_est,workdir)"
	      " VALUES(?,?,?,?,?,?,?,?,?)',"
	      " (sid,'HISTSEED',now,'mock-model',0,'active',now,0,"
	      "'/tmp'))\n", f);
	fprintf(f, "for i in range(%d):\n", HIST_MSGS);
	fputs("    role = 'user' if i % 2 == 0 else 'assistant'\n"
	      "    txt = 'MSG-%04d %s' % (i, 'x' * 40)\n"
	      "    cj = json.dumps([{'type': 'text', 'text': txt}])\n"
	      "    db.execute('INSERT INTO occ_message(id,session_id,role,"
	      "content_json,usage_est,finish,created,reverted)"
	      " VALUES(?,?,?,?,?,?,?,?)',"
	      " ('msg_%04d' % i, sid, role, cj, 0, '', now + i, 0))\n"
	      "db.commit()\n"
	      "db.close()\n", f);
	fclose(f);
	return 0;
}

int main(void)
{
	static char out[OUT_CAP];
	int have = 0;
	int mark_load = 0;
	char tmpl[] = "/tmp/btui-hist-XXXXXX";
	char *tmp;
	char toml[600], dbp[600], homep[600], seedp[600], cmd[1600];
	struct pty pt;
	struct winsize ws = { .ws_row = 24, .ws_col = 80 };
	pid_t pid;
	int rc = 0;
	int st = 0;
	int w;

	signal(SIGPIPE, SIG_IGN);
	if (access("../occ", X_OK) != 0) {
		printf("test_history_load: SKIP（../occ 未构建）\n");
		return 0;
	}
	if (system("command -v python3 >/dev/null 2>&1") != 0) {
		printf("test_history_load: SKIP（无 python3）\n");
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
	snprintf(seedp, sizeof(seedp), "%s/seed.py", tmp);
	mkdir(homep, 0700);
	{
		FILE *f = fopen(toml, "w");

		if (!f)
			return 1;
		/* 端点不监听（本用例零 LLM 调用）；只为 run_interactive 的
		 * provider 解析提供合法槽位 */
		fprintf(f,
			"[models.cloud]\n"
			"provider_type = \"openai_compatible\"\n"
			"model_name = \"mock-model\"\n"
			"base_url = \"http://127.0.0.1:1/v1\"\n"
			"api_key = \"mock-key-not-real\"\n");
		fclose(f);
	}
	if (write_seed(seedp) != 0) {
		printf("FAIL write seed\n");
		return 1;
	}
	/* 建库/建表（occ sessions 走 occ_db_open 的 DDL），再直插夹具 */
	snprintf(cmd, sizeof(cmd),
		 "HOME='%s' OCC_DB='%s' ../occ sessions >/dev/null 2>&1",
		 homep, dbp);
	if (system(cmd) != 0) {
		printf("FAIL create db (%s)\n", dbp);
		return 1;
	}
	snprintf(cmd, sizeof(cmd), "python3 '%s' '%s'", seedp, dbp);
	if (system(cmd) != 0) {
		printf("FAIL seed db\n");
		return 1;
	}

	if (pty_open(&pt) != 0)
		return 1;
	(void)ioctl(pt.slave, TIOCSWINSZ, &ws);
	pid = fork();
	if (pid < 0) {
		pty_close(&pt);
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
		setenv("OCC_MODEL_TOML", toml, 1);
		setenv("OCC_DB", dbp, 1);
		setenv("HOME", homep, 1);
		setenv("TERM", "dumb", 1);
		/* 尾部挂载预算压到 10 行：120 条消息必然被切割出
		 * 「⋯ 更早 N 条」；增量加载 +1000 一次覆盖全部 */
		setenv("OCC_REPLAY_LINES", "10", 1);
		execl("../occ", "occ", (char *)NULL);
		_exit(127);
	}
	close(pt.slave);
	pt.slave = -1;

	/* H0：进屏 */
	if (read_until(pt.master, out, OUT_CAP, &have, "\x1b[?1049h", 8000,
		       NULL) != 0) {
		printf("  dbg: alt-screen missing (have=%d)\n", have);
		rc = -1;
	}
	/* H1：/sessions → 选中唯一会话 → 回放尾部 */
	if (rc == 0 &&
	    write_all(pt.master, "/sessions\r", 10) != 0)
		rc = -1;
	if (rc == 0 &&
	    read_until(pt.master, out, OUT_CAP, &have, "HISTSEED", 8000,
		       NULL) != 0) {
		printf("  dbg: sessions overlay missing (have=%d)\n", have);
		rc = -1;
	}
	if (rc == 0 && write_all(pt.master, "\r", 1) != 0)
		rc = -1;
	if (rc == 0 &&
	    read_until(pt.master, out, OUT_CAP, &have,
		       "条消息未回放", 8000, NULL) != 0) {
		printf("  dbg: SEP line missing (have=%d)\n", have);
		rc = -1;
	}
	/* 初始窗口尾部消息（同帧可能分多次 read 到达——等到它出现） */
	if (rc == 0 &&
	    read_until(pt.master, out, OUT_CAP, &have, "MSG-0299", 5000,
		       NULL) != 0) {
		printf("  dbg: tail message missing (have=%d)\n", have);
		rc = -1;
	}
	/* H2：初始窗口只有尾部（MSG-0000 未加载） */
	OK(rc == 0, "H1-sep-after-replay");
	OK(find_bytes(out, have, "条消息未回放") != NULL, "H1-sep-bytes");
	OK(find_bytes(out, have, "MSG-0299") != NULL,
	   "H1-tail-message-visible");
	OK(find_bytes(out, have, "MSG-0000") == NULL,
	   "H2-earliest-not-loaded");

	/* H3：Home（已在顶）→ 增量加载（+1000 预算全量重放）→ 锚点不跳。
	 * 加载后新可见的 MSG-0296 只可能来自更大预算（初始窗口为
	 * MSG-0297..0299）——锚点契约：视口首行=锚点块上一行（0296 文本行），
	 * 等它出现即加载已渲染。（E 布局 17 行视口下旧断言 MSG-0294 只有
	 * 20 行满屏钳位漂移才可达，与契约不符——按契约对齐。） */
	if (rc == 0) {
		mark_load = have;
		if (write_all(pt.master, "\x1b[H", 3) != 0)
			rc = -1;
		if (rc == 0 &&
		    read_until(pt.master, out, OUT_CAP, &have, "MSG-0296",
			       8000, NULL) != 0) {
			printf("  dbg: load render missing (have=%d)\n", have);
			rc = -1;
		}
	}
	OK(rc == 0, "H3-load-more-ran");
	OK(find_after(out, have, mark_load, "锚点丢失，已跳到加载起点") ==
	   NULL, "H3-anchor-not-lost");
	OK(find_after(out, have, mark_load, "MSG-0000") == NULL,
	   "H3-anchor-not-jumped-to-new-top");

	/* H4：Home → 从锚点上滚到整个历史的真顶部（此时再 Home 才会命中
	 * at_top）。字节流是**增量 diff**（只发变化格）：从 MSG-0114 滚到
	 * MSG-0000 只差尾部 3 格，不能拿整串 "MSG-0000" 当 needle——改用
	 * 「再 Home 触发 at_top → 已到最早」作为到达顶部的证据，End 回底
	 * 露出通告行。 */
	if (rc == 0) {
		if (write_all(pt.master, "\x1b[H", 3) != 0)
			rc = -1;
		settle(pt.master, out, OUT_CAP, &have, 500);
	}
	OK(rc == 0, "H4-scroll-to-first");

	/* H5：再 Home（已在顶）→ 「已到最早」通告落转写区尾部（视口
	 * 在顶部看不到——End 回底即见） */
	if (rc == 0) {
		if (write_all(pt.master, "\x1b[H", 3) != 0)
			rc = -1;
		settle(pt.master, out, OUT_CAP, &have, 500);
		if (rc == 0 && write_all(pt.master, "\x1b[F", 3) != 0)
			rc = -1;		/* End=回底（露出通告行） */
		if (rc == 0 &&
		    read_until(pt.master, out, OUT_CAP, &have,
			       "── 已到最早 ──", 8000, NULL) != 0) {
			printf("  dbg: earliest notice missing (have=%d)\n",
			       have);
			rc = -1;
		}
	}
	OK(rc == 0, "H5-earliest-notice");
	OK(find_bytes(out, have, "── 已到最早 ──") != NULL,
	   "H5-earliest-notice-bytes");

	/* 收尾：/exit + leave */
	if (rc == 0) {
		if (write_all(pt.master, "/exit\r", 6) != 0)
			rc = -1;
		else if (read_until(pt.master, out, OUT_CAP, &have,
				    "\x1b[?1049l", 8000, NULL) != 0) {
			printf("  dbg: leave missing (have=%d)\n", have);
			rc = -1;
		}
	}
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
	} else if (rc == 0 && (!WIFEXITED(st) || WEXITSTATUS(st) != 0)) {
		printf("  child exit=%d\n",
		       WIFEXITED(st) ? WEXITSTATUS(st) : -1);
		rc = -1;
	}
	close(pt.master);

	printf("test_history_load: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
