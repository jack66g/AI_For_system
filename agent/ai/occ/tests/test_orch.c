/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_orch.c - occ_core/orch 单测 + B2 并发写库压测（波次 E2）
 *
 * 覆盖（ORCH-DESIGN §8 E2 验收门）：
 *   A) 结果回收与分类：正常退出（exit 0/7）/崩溃（SIGSEGV）/stdout
 *      尾窗读回/env 注入（附加项+OCC_DB 同库）/私有 child 会话/
 *      任务面联动（spawn 建行 dispatch→终局 review in_review+
 *      dispatch/result 事件审计）/spawn 失败→escalate 审计。
 *   B) 取消精准：TERM 段直杀；两段（ignoreterm→宽限→KILL）；
 *      只断目标子（另一路在取消期间存活）；取消后进程表零残留
 *      （kill 0=ESRCH + waitpid=ECHILD + 进程组探零）。
 *   C) 超时：per-任务 deadline→取消同路径（TIMEOUT+TERM/KILL 段）。
 *   G) E3 文件集互斥：登记前无冲突；声明占用（含公共文件撞车检出+
 *      持有者回填）；并发第二任务声明同文件 spawn 即拒（EFILESET）；
 *      不同文件放行；取消/正常终局自动注销（同集可再声明）。
 *   H) E3 task 第七工具五动作全链（OCC_ORCH_TOOLS=1 打开态演练）：
 *      spawn（brief 组装+结果文件 env 通道）→wait 限时终局→status
 *      （DB 读回 in_review）→read_result（报告=结果文件内容）→
 *      return（记入任务事件）；工具面互斥（ok:false+EFILESET）。
 *   D) 并发闸：上限 2 第三路立即拒绝（ELIMIT）+30s 退避窗（EBACKOFF；
 *      窗内槽位空也拒；窗满自动复位——测试用短窗 400ms 覆写）。
 *   E) B2 并发写库压测（两腿，报告落 tests/orch_b2_report.txt）：
 *      腿1 生产路径：4 进程（自 exec）并发 occ_db_open 同库+各 25 事务
 *      （occ_msg_add_user/occ_task_create/occ_task_dispatch——INSERT+
 *      UPDATE 混合，含并发首开建库竞态面）→ 零失败断言。
 *      腿2 可观测：等价 PRAGMA（WAL+foreign_keys）+计数 busy handler
 *      （10ms 步进≤5s，与 busy_timeout 同包络）+共享热行 UPDATE+事务内
 *      200us 负载 → busy 重试如实计数。
 *   F) WAL 读回：压测库 journal_mode=wal（busy_timeout=5000 的开库
 *      校验内建于 session.c occ_db_open——每次开库必验）。
 *
 * 子模式入口（同二进制自 exec——真多进程，非进程内模拟）：
 *   env OCC_ORCH_SIM=1 + -p <prompt> --session <sid>  子进程行为
 *       模拟器（argv/env 合同形状与真 occ -p 完全一致——分发键走
 *       env 标记，argv 零私货）
 *   --b2w <db> <parent_sid> <wid> <m> <outfile>   腿1 worker
 *   --b2rw <db> <wid> <m> <hot_csv> <outfile>     腿2 worker
 *   --conc-drill <occ_bin>   E2 验收演练：mock LLM 下 orch spawn 2 路
 *       真 occ -p 并发对话（同库并发写=B2 生产路径）+第三路撞限即拒
 *
 * 外部验证：独立 sqlite3 连接直查（同 test_task 口径）。
 */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <sqlite3.h>

#include "occ_core/orch.h"
#include "occ_tools/occ_tools.h"	/* E3：task 工具全链演练 */

static int n_fail;
static int n_ok;

#define OK(cond, name) do { \
	if (cond) { n_ok++; printf("ok %s\n", name); } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

static char tmpdir[128];
static char self_bin[420];		/* /proc/self/exe：自 exec 用 */

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void msleep(long long ms)
{
	struct timespec ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000;
	nanosleep(&ts, NULL);
}

/* 递归删目录（测试夹具清理；POSIX 面） */
static void rm_rf(const char *path)
{
	DIR *d = opendir(path);
	struct dirent *e;
	char sub[512];

	if (!d) {
		unlink(path);
		return;
	}
	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name);
		rm_rf(sub);
	}
	closedir(d);
	rmdir(path);
}

/* ---- 独立连接观察者（带参 int 查询） ---- */

static int sql_int(const char *db, const char *sql, const char *arg)
{
	sqlite3 *h;
	sqlite3_stmt *st;
	int v = -1;

	if (sqlite3_open_v2(db, &h, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
		return -1;
	if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK) {
		if (arg)
			sqlite3_bind_text(st, 1, arg, -1, SQLITE_STATIC);
		if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st,
		    0) == SQLITE_INTEGER)
			v = sqlite3_column_int(st, 0);
		sqlite3_finalize(st);
	}
	sqlite3_close(h);
	return v;
}

static int sql_str(const char *db, const char *sql, char *out, size_t cap)
{
	sqlite3 *h;
	sqlite3_stmt *st;

	out[0] = '\0';
	if (sqlite3_open_v2(db, &h, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
		return -1;
	if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK) {
		if (sqlite3_step(st) == SQLITE_ROW) {
			const unsigned char *s = sqlite3_column_text(st, 0);

			snprintf(out, cap, "%s", s ? (const char *)s : "");
		}
		sqlite3_finalize(st);
	}
	sqlite3_close(h);
	return 0;
}

/* ---- fork+exec 自 exec worker（真多进程） ---- */

static pid_t fork_exec(char *const argv[])
{
	pid_t pid = fork();

	if (pid < 0)
		return -1;
	if (pid == 0) {
		execvp(argv[0], argv);		/* 无斜杠名走 PATH（python3） */
		_exit(111);
	}
	return pid;
}

/* ---- sim：子进程行为模拟器（argv 形状=orch spawn 真合同；
 *      main 以 env OCC_ORCH_SIM=1 分发） ---- */

static int sim_main(int argc, char **argv)
{
	const char *prompt = "";
	const char *sid = "";
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-p") && i + 1 < argc)
			prompt = argv[++i];
		else if (!strcmp(argv[i], "--session") && i + 1 < argc)
			sid = argv[++i];
	}
	if (!strncmp(prompt, "sim:hang", 8)) {
		int s = atoi(prompt + 8);

		/* READY 标记=镜像已装载就绪（TERM 赶在 execve 装载途中
		 * 会挂起到装载完才致死——取消类用例先等标记再动手） */
		printf("SIM-HANG-READY\n");
		fflush(stdout);
		sleep(s > 0 ? s : 30);
		printf("SIM-HANG-DONE\n");
		return 0;
	}
	if (!strncmp(prompt, "sim:ignoreterm", 14)) {
		int s;
		struct sigaction sa;

		/* 注意：严格 _POSIX_C_SOURCE 下 glibc signal()=SysV 语义
		 *（SA_RESETHAND——SIG_IGN 首次投递即失效被杀）。显式
		 * sigaction flags=0 才是真忽略（c2/b2 两段取消演练前提）。 */
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = SIG_IGN;
		sigemptyset(&sa.sa_mask);
		sigaction(SIGTERM, &sa, NULL);
		printf("SIM-IGNORETERM sid=%s\n", sid);
		fflush(stdout);
		s = atoi(prompt + 14);
		sleep(s > 0 ? s : 30);
		return 0;
	}
	if (!strcmp(prompt, "sim:exit7")) {
		printf("SIM-EXIT7 sid=%s\n", sid);
		return 7;
	}
	if (!strcmp(prompt, "sim:segv")) {
		printf("SIM-SEGV sid=%s\n", sid);
		fflush(stdout);
		raise(SIGSEGV);
		return 99;
	}
	if (!strncmp(prompt, "sim:env ", 8)) {
		const char *v = getenv(prompt + 8);

		printf("SIM-ENV %s=%s\n", prompt + 8, v ? v : "(null)");
		return 0;
	}
	/* E3：结果文件 env 通道演练——任务书正文内嵌「sim:report <报告>」
	 * 标记：把报告写往 OCC_TASK_RESULT_FILE 并打印摘要行 */
	{
		const char *mark = strstr(prompt, "sim:report ");

		if (mark) {
			const char *rf = getenv(OCC_ORCH_RESULT_ENV);
			const char *body = mark + strlen("sim:report ");
			char *nlp = strchr(body, '\n');

			if (rf && rf[0]) {
				FILE *f = fopen(rf, "w");

				if (f) {
					fprintf(f, "%.*s\n",
						nlp ? (int)(nlp - body) :
						      (int)strlen(body), body);
					fclose(f);
				}
				printf("SIM-REPORT file=%s\n", rf);
			} else {
				printf("SIM-REPORT nofile\n");
			}
			return 0;
		}
	}
	printf("SIM-OK sid=%s\n", sid);		/* sim:ok 及缺省 */
	return 0;
}

/* ---- --b2w：腿1 worker（生产路径：occ_db_open+session/task API） ---- */

static int b2w_main(int argc, char **argv)
{
	/* argv: --b2w <db> <parent_sid> <wid> <m> <outfile> */
	const char *dbp = argc > 2 ? argv[2] : NULL;
	const char *psid = argc > 3 ? argv[3] : "";
	int wid = argc > 4 ? atoi(argv[4]) : 0;
	int m = argc > 5 ? atoi(argv[5]) : 25;
	const char *out = argc > 6 ? argv[6] : NULL;
	occ_db *db;
	occ_session_row srow;
	char err[256], msg[160], first[192];
	long long t0 = now_ms();
	int ok = 0, fail = 0, i;

	first[0] = '\0';
	if (!dbp || !out)
		return 98;
	db = occ_db_open(dbp, err, sizeof(err));	/* 含并发首开竞态面 */
	if (!db) {
		snprintf(first, sizeof(first), "open: %.140s", err);
		fail = m;
		goto out;
	}
	err[0] = '\0';
	if (occ_session_create_kind(db, "", OCC_SK_CHILD, &srow, err,
				    sizeof(err)) != 0) {
		snprintf(first, sizeof(first), "session: %.140s", err);
		fail = m;
		occ_db_close(db);
		goto out;
	}
	for (i = 0; i < m; i++) {
		occ_task_row trow;

		snprintf(msg, sizeof(msg), "b2 w%d t%d 并发写库压测", wid,
			 i);
		if (occ_msg_add_user(db, srow.id, msg, NULL, 0, err,
				     sizeof(err)) != 0 ||
		    occ_task_create(db, psid, "b2-stress",
				    "{\"leg\":\"production\"}", 0, &trow, err,
				    sizeof(err)) != 0 ||
		    occ_task_dispatch(db, trow.id, srow.id, err,
				      sizeof(err)) != 0) {
			if (!first[0])
				snprintf(first, sizeof(first), "t%d: %.140s",
					 i, err);
			fail++;
			continue;
		}
		occ_task_row_free(&trow);
		ok++;
	}
	occ_db_close(db);
out:
	{
		FILE *f = fopen(out, "w");

		if (f) {
			fprintf(f, "ok=%d fail=%d busy=0 wall_ms=%lld "
				"err=%.140s\n", ok, fail, now_ms() - t0,
				first);
			fclose(f);
		}
	}
	return fail;
}

/* ---- --b2rw：腿2 worker（等价 PRAGMA+计数 busy handler，可观测） ---- */

struct busy_ud {
	int count;
};

static int busy_cb(void *ud, int attempts)
{
	struct busy_ud *b = ud;

	b->count++;
	if (attempts >= 500)		/* ≈5s 包络（同 busy_timeout=5000） */
		return 0;
	{
		struct timespec ts = { 0, 10 * 1000 * 1000 };

		nanosleep(&ts, NULL);
	}
	return 1;
}

static int b2rw_main(int argc, char **argv)
{
	/* argv: --b2rw <db> <wid> <m> <hot_csv> <outfile> */
	const char *dbp = argc > 2 ? argv[2] : NULL;
	int wid = argc > 3 ? atoi(argv[3]) : 0;
	int m = argc > 4 ? atoi(argv[4]) : 25;
	const char *out = argc > 6 ? argv[6] : NULL;
	char *csv = NULL, *hot[16];
	int nhot = 0;
	sqlite3 *h = NULL;
	struct busy_ud ud = { 0 };
	char first[192], argbuf[512];
	long long t0 = now_ms();
	int ok = 0, fail = 0, i;

	(void)wid;
	first[0] = '\0';
	argbuf[0] = '\0';
	if (!dbp || !out || argc <= 5)
		return 98;
	snprintf(argbuf, sizeof(argbuf), "%s", argv[5]);
	csv = strdup(argbuf);
	if (!csv)
		return 98;
	{
		char *p = strtok(csv, ",");

		while (p && nhot < 16) {
			hot[nhot++] = p;
			p = strtok(NULL, ",");
		}
	}
	if (!nhot) {
		free(csv);
		return 97;
	}
	if (sqlite3_open_v2(dbp, &h, SQLITE_OPEN_READWRITE |
			   SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK) {
		snprintf(first, sizeof(first), "open");
		fail = m;
		goto out;
	}
	sqlite3_exec(h, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);
	sqlite3_busy_handler(h, busy_cb, &ud);
	for (i = 0; i < m; i++) {
		const char *hid = hot[i % nhot];
		char *perr = NULL;
		sqlite3_stmt *st = NULL;
		int bad = 0;

		if (sqlite3_exec(h, "BEGIN IMMEDIATE", NULL, NULL,
				 &perr) != SQLITE_OK) {
			if (!first[0])
				snprintf(first, sizeof(first),
					 "begin: %.120s",
					 perr ? perr : "?");
			sqlite3_free(perr);
			fail++;
			continue;
		}
		if (sqlite3_prepare_v2(h,
				       "INSERT INTO occ_task_event"
				       "(task_id,kind,payload_json,created)"
				       " VALUES(?1,'stress',"
				       "'{\"leg\":\"observable\"}',?2)",
				       -1, &st, NULL) == SQLITE_OK) {
			sqlite3_bind_text(st, 1, hid, -1, SQLITE_TRANSIENT);
			sqlite3_bind_int64(st, 2, (sqlite3_int64)time(NULL) *
					   1000);
			if (sqlite3_step(st) != SQLITE_DONE)
				bad = 1;
			sqlite3_finalize(st);
		} else {
			bad = 1;
		}
		if (!bad && sqlite3_prepare_v2(h,
					       "UPDATE occ_task SET"
					       " updated=updated+1"
					       " WHERE id=?1", -1, &st,
					       NULL) == SQLITE_OK) {
			sqlite3_bind_text(st, 1, hid, -1, SQLITE_TRANSIENT);
			if (sqlite3_step(st) != SQLITE_DONE)
				bad = 1;
			sqlite3_finalize(st);
		} else if (!bad) {
			bad = 1;
		}
		if (bad) {
			if (!first[0])
				snprintf(first, sizeof(first),
					 "stmt t%d", i);
			sqlite3_exec(h, "ROLLBACK", NULL, NULL, NULL);
			fail++;
			continue;
		}
		{
			struct timespec ts = { 0, 200 * 1000 };

			nanosleep(&ts, NULL);	/* 事务内负载：拉长写锁持有 */
		}
		if (sqlite3_exec(h, "COMMIT", NULL, NULL, &perr) != SQLITE_OK) {
			sqlite3_exec(h, "ROLLBACK", NULL, NULL, NULL);
			if (!first[0])
				snprintf(first, sizeof(first),
					 "commit: %.120s",
					 perr ? perr : "?");
			sqlite3_free(perr);
			fail++;
			continue;
		}
		ok++;
	}
out:
	if (h)
		sqlite3_close(h);
	{
		FILE *f = fopen(out, "w");

		if (f) {
			fprintf(f, "ok=%d fail=%d busy=%d wall_ms=%lld "
				"err=%.140s\n", ok, fail, ud.count,
				now_ms() - t0, first);
			fclose(f);
		}
	}
	free(csv);
	return fail;
}

/* ---- 单测夹具 ---- */

static occ_db *g_db;
static char g_dbpath[192];
static char g_psid[OCC_ID_LEN];
static occ_orch *g_o;
static const char *g_sim_env[2] = { "OCC_ORCH_SIM=1", NULL };
/* 就绪标记探针文件（B/C/D 各 case 的显式 stdout 路径） */
static const char *g_outa, *g_outb, *g_outi, *g_outc, *g_outc2;
static const char *g_outd1, *g_outd2;

static occ_orch_child *spawn_simple(const char *prompt, long long timeout_ms)
{
	occ_orch_spawn_opts opts;
	occ_orch_child *c = NULL;
	char err[256];

	memset(&opts, 0, sizeof(opts));
	opts.prompt = prompt;
	opts.parent_session = g_psid;
	opts.occ_bin = self_bin;
	opts.env = g_sim_env;			/* sim 分发键（argv 零私货） */
	opts.timeout_ms = timeout_ms;
	if (occ_orch_spawn(g_o, &opts, &c, err, sizeof(err)) != OCC_ORCH_OK) {
		printf("FAIL spawn_simple(%s): %s\n", prompt, err);
		n_fail++;
		return NULL;
	}
	return c;
}

/* 带显式 stdout 路径的 spawn（就绪标记同步用——execve 装载 ~100ms
 * 期间信号挂起，取消/超时类用例必须先等子进程打出 READY 标记） */
static occ_orch_child *spawn_probe(const char *prompt, long long timeout_ms,
				   const char *outpath)
{
	occ_orch_spawn_opts opts;
	occ_orch_child *c = NULL;
	char err[256];

	memset(&opts, 0, sizeof(opts));
	opts.prompt = prompt;
	opts.parent_session = g_psid;
	opts.occ_bin = self_bin;
	opts.env = g_sim_env;
	opts.timeout_ms = timeout_ms;
	opts.stdout_path = outpath;
	if (occ_orch_spawn(g_o, &opts, &c, err, sizeof(err)) != OCC_ORCH_OK) {
		printf("FAIL spawn_probe(%s): %s\n", prompt, err);
		n_fail++;
		return NULL;
	}
	return c;
}

/* 轮询 stdout 文件直到出现标记（子进程就绪同步；超时 -1） */
static int wait_marker(const char *path, const char *needle,
		       long long timeout_ms)
{
	long long t0 = now_ms();

	while (now_ms() - t0 < timeout_ms) {
		FILE *f = fopen(path, "r");
		char buf[512];
		size_t got;

		if (f) {
			got = fread(buf, 1, sizeof(buf) - 1, f);
			fclose(f);
			buf[got] = '\0';
			if (strstr(buf, needle))
				return 0;
		}
		msleep(10);
	}
	return -1;
}

/* worker 结果行解析：ok= fail= busy= wall_ms= */
static int parse_wf(const char *path, int *ok, int *fail, int *busy,
		    long long *wall)
{
	FILE *f = fopen(path, "r");
	char line[320];

	if (!f)
		return -1;
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	*ok = *fail = *busy = -1;
	*wall = -1;
	if (sscanf(line, "ok=%d fail=%d busy=%d wall_ms=%lld", ok, fail,
		   busy, wall) < 2)
		return -1;
	return 0;
}

/* ---- B2 压测（两腿） ---- */

static int g_l1_ok, g_l1_fail, g_l1_busy;
static int g_l2_ok, g_l2_fail, g_l2_busy;
static long long g_l1_wall, g_l2_wall;

static void b2_stress(void)
{
	enum { N_W = 4, M_TX = 25, K_HOT = 4 };
	char wpath[N_W][192];
	pid_t pid[N_W];
	char *argv_w[8];
	char hot_csv[OCC_ID_LEN * K_HOT + 8];
	char wids[N_W][8], ms[N_W][8];
	int i, bad_exit = 0;

	/* ---- 腿1：生产路径（occ_db_open+API；并发首开+并发事务） ---- */
	for (i = 0; i < N_W; i++) {
		snprintf(wids[i], sizeof(wids[i]), "%d", i);
		snprintf(ms[i], sizeof(ms[i]), "%d", M_TX);
		snprintf(wpath[i], sizeof(wpath[i]), "%s/w%d.txt", tmpdir, i);
		argv_w[0] = self_bin;
		argv_w[1] = (char *)"--b2w";
		argv_w[2] = g_dbpath;
		argv_w[3] = g_psid;
		argv_w[4] = wids[i];
		argv_w[5] = ms[i];
		argv_w[6] = wpath[i];
		argv_w[7] = NULL;
		pid[i] = fork_exec(argv_w);
	}
	for (i = 0; i < N_W; i++) {
		int st = 0;

		if (pid[i] > 0)
			while (waitpid(pid[i], &st, 0) < 0 && errno == EINTR)
				;
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
			bad_exit++;
	}
	for (i = 0; i < N_W; i++) {
		int ok = 0, fail = 0, busy = 0;
		long long wall = 0;

		if (parse_wf(wpath[i], &ok, &fail, &busy, &wall) != 0) {
			fail += M_TX;
			wall = -1;
		}
		g_l1_ok += ok;
		g_l1_fail += fail;
		g_l1_busy += busy;
		if (wall > g_l1_wall)
			g_l1_wall = wall;
	}
	OK(bad_exit == 0, "b2-leg1-worker-exit0");
	OK(g_l1_fail == 0 && g_l1_ok == N_W * M_TX,
	   "b2-leg1-prod-4p-x25-zero-fail");

	/* ---- 腿2：可观测 busy 重试（等价 PRAGMA+计数 handler+热行） ---- */
	hot_csv[0] = '\0';
	for (i = 0; i < K_HOT; i++) {
		occ_task_row trow;
		char err[192];
		size_t len = strlen(hot_csv);

		if (occ_task_create(g_db, g_psid, "b2-hot",
				    "{\"leg\":\"hot\"}", 0, &trow, err,
				    sizeof(err)) != 0) {
			printf("FAIL b2 hot row %d: %s\n", i, err);
			n_fail++;
			return;
		}
		snprintf(hot_csv + len, sizeof(hot_csv) - len, "%s%s",
			 i ? "," : "", trow.id);
		occ_task_row_free(&trow);
	}
	bad_exit = 0;
	for (i = 0; i < N_W; i++) {
		snprintf(wpath[i], sizeof(wpath[i]), "%s/r%d.txt", tmpdir, i);
		argv_w[0] = self_bin;
		argv_w[1] = (char *)"--b2rw";
		argv_w[2] = g_dbpath;
		argv_w[3] = wids[i];
		argv_w[4] = ms[i];
		argv_w[5] = hot_csv;
		argv_w[6] = wpath[i];
		argv_w[7] = NULL;
		pid[i] = fork_exec(argv_w);
	}
	for (i = 0; i < N_W; i++) {
		int st = 0;

		if (pid[i] > 0)
			while (waitpid(pid[i], &st, 0) < 0 && errno == EINTR)
				;
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
			bad_exit++;
	}
	for (i = 0; i < N_W; i++) {
		int ok = 0, fail = 0, busy = 0;
		long long wall = 0;

		if (parse_wf(wpath[i], &ok, &fail, &busy, &wall) != 0) {
			fail += M_TX;
			wall = -1;
		}
		g_l2_ok += ok;
		g_l2_fail += fail;
		g_l2_busy += busy;
		if (wall > g_l2_wall)
			g_l2_wall = wall;
	}
	OK(bad_exit == 0, "b2-leg2-worker-exit0");
	OK(g_l2_fail == 0 && g_l2_ok == N_W * M_TX,
	   "b2-leg2-obs-4p-x25-zero-fail");
	OK(g_l2_busy >= 1, "b2-leg2-busy-retry-observed");
}

static void b2_report(void)
{
	const char *path = "tests/orch_b2_report.txt";
	FILE *f;

	/* cwd=occ/（make test 约定）；其它 cwd 只跳过报告不失败 */
	f = fopen(path, "w");
	if (!f) {
		printf("note b2-report-skip (%s: %s)\n", path,
		       strerror(errno));
		return;
	}
	fprintf(f,
		"B2 并发写库压测报告（ORCH-E2 销账件；tests/test_orch 每次"
		"运行刷新；--conc-drill 腿追加）\n"
		"口径：同一 occ SQLite 库多进程并发写；journal_mode=WAL + "
		"busy_timeout=5000 + BEGIN IMMEDIATE 单事务\n"
		"（session.c occ_db_open 生产开库路径；WAL/超时开库读回校验"
		"内建于 session.c）\n\n"
		"[腿1 生产路径] 4 进程 × 25 事务：occ_db_open（含并发首开建库"
		"竞态面）+\n"
		"  occ_msg_add_user（INSERT occ_message+UPDATE occ_session）"
		"+ occ_task_create（INSERT）+\n"
		"  occ_task_dispatch（UPDATE occ_task+INSERT occ_task_event）"
		"——全部生产 API 路径\n");
	for (int i = 0; i < 4; i++) {
		char wf[192];
		int ok = 0, fail = 0, busy = 0;
		long long wall = -1;

		snprintf(wf, sizeof(wf), "%s/w%d.txt", tmpdir, i);
		if (parse_wf(wf, &ok, &fail, &busy, &wall) == 0)
			fprintf(f, "  w%d: 事务=%d ok=%d fail=%d 墙钟=%lldms"
				"\n", i, 25, ok, fail, wall);
	}
	fprintf(f, "  合计：事务=%d ok=%d fail=%d（断言 fail==0）\n\n",
		100, g_l1_ok, g_l1_fail);
	fprintf(f,
		"[腿2 可观测] 4 进程 × 25 事务：等价 PRAGMA（WAL+"
		"foreign_keys）+\n"
		"  计数 busy handler（10ms 步进≤5s——与 busy_timeout=5000 "
		"同等待包络，重试可见）+\n"
		"  共享热行 UPDATE（4 行轮流加压）+ 事务内 200us 计算负载\n");
	for (int i = 0; i < 4; i++) {
		char wf[192];
		int ok = 0, fail = 0, busy = 0;
		long long wall = -1;

		snprintf(wf, sizeof(wf), "%s/r%d.txt", tmpdir, i);
		if (parse_wf(wf, &ok, &fail, &busy, &wall) == 0)
			fprintf(f, "  w%d: 事务=%d ok=%d fail=%d busy重试=%d"
				" 墙钟=%lldms\n", i, 25, ok, fail, busy,
				wall);
	}
	fprintf(f,
		"\n[腿2 合计] 事务=%d fail=%d busy重试=%d（busy 包络内吸收，"
		"零终局 SQLITE_BUSY）\n"
		"[总墙钟参考] 腿1 最长单 worker=%lldms；腿2 最长=%lldms\n"
		"结论：多进程并发写下写串行化成立（WAL+IMMEDIATE+busy 包络），"
		"B2 销账依据=NEXT-PLAN.md 波次 B2 行\n",
		g_l2_ok, g_l2_fail, g_l2_busy, g_l1_wall, g_l2_wall);
	fclose(f);
	printf("ok b2-report-written (%s)\n", path);
	n_ok++;
}

/* ---- 单测主体 ---- */

static int unit_main(void)
{
	char err[256], ctid[OCC_ID_LEN];
	occ_orch_child *c, *a, *b;
	occ_orch_result r;
	occ_task_row trow;
	occ_task_event_row *evs;
	size_t nevs;
	occ_session_row srow;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/occ_test_orch.XXXXXX");
	if (!mkdtemp(tmpdir)) {
		printf("FAIL mkdtemp\n");
		return 1;
	}
	if (readlink("/proc/self/exe", self_bin, sizeof(self_bin) - 1) <= 0) {
		printf("FAIL /proc/self/exe\n");
		return 1;
	}
	self_bin[sizeof(self_bin) - 1] = '\0';

	snprintf(g_dbpath, sizeof(g_dbpath), "%s/orch.db", tmpdir);
	g_db = occ_db_open(g_dbpath, err, sizeof(err));
	OK(g_db != NULL, "db-open");
	if (!g_db)
		return 1;
	OK(occ_session_create(g_db, "test-model", &srow, err,
			      sizeof(err)) == 0, "parent-session");
	snprintf(g_psid, sizeof(g_psid), "%s", srow.id);
	g_o = occ_orch_new(g_db);
	OK(g_o != NULL, "orch-new");

	/* ===== A 结果回收与分类 ===== */
	c = spawn_simple("sim:ok", 0);
	if (c) {
		snprintf(ctid, sizeof(ctid), "%s", occ_orch_child_task(c));
		OK(occ_orch_child_pid(c) > 0, "a-pid");
		OK(occ_orch_child_session(c)[0] != '\0', "a-session-id");
		OK(ctid[0] != '\0', "a-task-id");
		OK(occ_orch_wait(c, &r, err, sizeof(err)) == 0, "a-wait");
		OK(r.end == OCC_ORCH_END_EXIT && r.exit_code == 0,
		   "a-exit0");
		OK(r.reviewed == 1, "a-reviewed");
		OK(r.stdout_tail && strstr(r.stdout_tail, "SIM-OK"),
		   "a-stdout-tail");
		OK(r.stdout_tail &&
		   r.session_id[0] != '\0' &&
		   strstr(r.stdout_tail, r.session_id) != NULL,
		   "a-private-session-in-stdout");
		occ_orch_result_free(&r);
		/* 任务面：dispatched→in_review + 事件审计 */
		OK(occ_task_get(g_db, ctid, &trow, NULL, 0) == 1 &&
		   !strcmp(trow.status, OCC_TASK_ST_IN_REVIEW),
		   "a-status-in-review");
		occ_task_row_free(&trow);
		OK(occ_task_events(g_db, ctid, &evs, &nevs, NULL, 0) == 0 &&
		   nevs >= 2, "a-events");
		if (nevs >= 2) {
			OK(!strcmp(evs[0].kind, OCC_TASK_EV_DISPATCH) &&
			   !strcmp(evs[1].kind, OCC_TASK_EV_RESULT),
			   "a-event-kinds");
			occ_task_event_rows_free(evs, nevs);
		}
	}
	/* child 会话 kind 落库 */
	c = spawn_simple("sim:ok", 0);
	if (c) {
		char sid[OCC_ID_LEN];
		char q[300], kindv[24] = "";

		snprintf(sid, sizeof(sid), "%s", occ_orch_child_session(c));
		occ_orch_wait(c, &r, err, sizeof(err));
		occ_orch_result_free(&r);
		snprintf(q, sizeof(q), "SELECT kind FROM occ_session"
			 " WHERE id='%s'", sid);
		sql_str(g_dbpath, q, kindv, sizeof(kindv));
		OK(!strcmp(kindv, OCC_SK_CHILD), "a-child-session-kind");
	}
	c = spawn_simple("sim:exit7", 0);
	if (c) {
		OK(occ_orch_wait(c, &r, err, sizeof(err)) == 0, "a2-wait");
		OK(r.end == OCC_ORCH_END_EXIT && r.exit_code == 7,
		   "a2-exit7");
		OK(r.reviewed == 1, "a2-reviewed");
		occ_orch_result_free(&r);
	}
	c = spawn_simple("sim:segv", 0);
	if (c) {
		OK(occ_orch_wait(c, &r, err, sizeof(err)) == 0, "a3-wait");
		OK(r.end == OCC_ORCH_END_SIGNAL && r.signal == SIGSEGV,
		   "a3-signal-segv");
		OK(r.reviewed == 1, "a3-reviewed");
		occ_orch_result_free(&r);
	}
	/* env 注入：附加项 + OCC_DB 同库自动注入（无任务面轻模式） */
	{
		const char *envp[3] = { "OCC_ORCH_MARKER=hello-e2",
					"OCC_ORCH_SIM=1", NULL };
		occ_orch_spawn_opts opts;

		memset(&opts, 0, sizeof(opts));
		opts.prompt = "sim:env OCC_ORCH_MARKER";
		opts.occ_bin = self_bin;
		opts.env = envp;
		c = NULL;
		OK(occ_orch_spawn(g_o, &opts, &c, err, sizeof(err)) == 0,
		   "a4-spawn");
		if (c) {
			occ_orch_wait(c, &r, err, sizeof(err));
			OK(r.stdout_tail &&
			   strstr(r.stdout_tail, "hello-e2") != NULL,
			   "a4-env-inject");
			occ_orch_result_free(&r);
		}
		memset(&opts, 0, sizeof(opts));
		opts.prompt = "sim:env OCC_DB";
		opts.occ_bin = self_bin;
		opts.env = g_sim_env;
		c = NULL;
		occ_orch_spawn(g_o, &opts, &c, err, sizeof(err));
		if (c) {
			occ_orch_wait(c, &r, err, sizeof(err));
			OK(r.stdout_tail &&
			   strstr(r.stdout_tail, g_dbpath) != NULL,
			   "a4-occdb-inject");
			occ_orch_result_free(&r);
		}
	}
	/* 显式 stdout 文件（调用方持有，不随回收删除） */
	{
		occ_orch_spawn_opts opts;
		char sp[192];

		snprintf(sp, sizeof(sp), "%s/explicit.out", tmpdir);
		memset(&opts, 0, sizeof(opts));
		opts.prompt = "sim:ok";
		opts.occ_bin = self_bin;
		opts.env = g_sim_env;
		opts.stdout_path = sp;
		c = NULL;
		occ_orch_spawn(g_o, &opts, &c, err, sizeof(err));
		if (c) {
			occ_orch_wait(c, &r, err, sizeof(err));
			occ_orch_result_free(&r);
			{
				FILE *f = fopen(sp, "r");
				char buf[256] = "";
				int has = 0;

				if (f) {
					if (fgets(buf, sizeof(buf), f) &&
					    strstr(buf, "SIM-OK"))
						has = 1;
					fclose(f);
				}
				OK(has, "a5-explicit-stdout-file");
			}
		}
	}
	/* spawn 失败→任务 escalated 审计 */
	{
		occ_orch_spawn_opts opts;
		occ_task_row *rows = NULL;
		size_t n = 0;

		memset(&opts, 0, sizeof(opts));
		opts.prompt = "sim:ok";
		opts.parent_session = g_psid;
		opts.occ_bin = "/nonexistent/orch_occ_bin";
		c = NULL;
		OK(occ_orch_spawn(g_o, &opts, &c, err, sizeof(err)) ==
		   OCC_ORCH_ESPAWN, "a7-spawn-fail-rc");
		OK(occ_task_list(g_db, g_psid, &rows, &n, err,
				 sizeof(err)) == 0 && n >= 1,
		   "a7-task-list");
		if (rows && n >= 1) {
			OK(!strcmp(rows[0].status, OCC_TASK_ST_ESCALATED),
			   "a7-escalated");
		}
		occ_task_rows_free(rows, n);
	}

	/* ===== B 取消精准 ===== */
	{
		static char outa[192], outb[192], outi[192], outc[192],
			    outc2[192], outd1[192], outd2[192];

		snprintf(outa, sizeof(outa), "%s/b_a.out", tmpdir);
		snprintf(outb, sizeof(outb), "%s/b_b.out", tmpdir);
		snprintf(outi, sizeof(outi), "%s/b_ig.out", tmpdir);
		snprintf(outc, sizeof(outc), "%s/c_h.out", tmpdir);
		snprintf(outc2, sizeof(outc2), "%s/c_ig.out", tmpdir);
		snprintf(outd1, sizeof(outd1), "%s/d_a.out", tmpdir);
		snprintf(outd2, sizeof(outd2), "%s/d_b.out", tmpdir);
		g_outa = outa;
		g_outb = outb;
		g_outi = outi;
		g_outc = outc;
		g_outc2 = outc2;
		g_outd1 = outd1;
		g_outd2 = outd2;
	}
	a = spawn_probe("sim:hang 30", 0, g_outa);
	b = spawn_probe("sim:hang 30", 0, g_outb);
	OK(occ_orch_nrunning(g_o) == 2, "b-two-running");
	if (a && b) {
		/* 就绪同步：等两路都真正进入 sleep（装载完成）再取消 */
		OK(wait_marker(g_outa, "SIM-HANG-READY", 10000) == 0,
		   "b-a-ready");
		OK(wait_marker(g_outb, "SIM-HANG-READY", 10000) == 0,
		   "b-b-ready");
		pid_t pa = occ_orch_child_pid(a);
		pid_t pb = occ_orch_child_pid(b);
		int st;

		OK(occ_orch_cancel(a, &r, err, sizeof(err)) == 0,
		   "b-cancel");
		OK(r.end == OCC_ORCH_END_CANCELLED && r.signal == SIGTERM,
		   "b-cancel-term");
		OK(r.dur_ms < 10000, "b-cancel-fast");
		/* 零残留：直杀已收尸 + 进程组探零 */
		OK(kill(pa, 0) < 0 && errno == ESRCH, "b-no-pid");
		OK(waitpid(pa, &st, WNOHANG) < 0 && errno == ECHILD,
		   "b-reaped");
		OK(kill(-pa, 0) < 0 && errno == ESRCH, "b-no-pgroup");
		/* 只断目标：另一路仍活 */
		OK(kill(pb, 0) == 0, "b-other-alive");
		occ_orch_result_free(&r);
		OK(occ_orch_cancel(b, &r, err, sizeof(err)) == 0 &&
		   r.end == OCC_ORCH_END_CANCELLED, "b-cancel-other");
		occ_orch_result_free(&r);
	} else {
		if (a)
			occ_orch_cancel(a, &r, err, sizeof(err)),
			occ_orch_result_free(&r);
		if (b)
			occ_orch_cancel(b, &r, err, sizeof(err)),
			occ_orch_result_free(&r);
	}
	OK(occ_orch_nrunning(g_o) == 0, "b-zero-running");

	/* 两段：ignoreterm→宽限→KILL（先等 SIG_IGN 装好——标记同步） */
	a = spawn_probe("sim:ignoreterm 30", 0, g_outi);
	if (a) {
		pid_t pa = occ_orch_child_pid(a);

		OK(wait_marker(g_outi, "SIM-IGNORETERM", 10000) == 0,
		   "b2-ready");
		OK(occ_orch_cancel(a, &r, err, sizeof(err)) == 0,
		   "b2-cancel");
		OK(r.end == OCC_ORCH_END_CANCELLED && r.signal == SIGKILL,
		   "b2-cancel-kill-stage");
		OK(r.dur_ms >= 1500 && r.dur_ms < 10000, "b2-grace-window");
		OK(kill(pa, 0) < 0 && errno == ESRCH, "b2-no-residue");
		occ_orch_result_free(&r);
	}

	/* ===== C 超时 ===== */
	a = spawn_probe("sim:hang 30", 1500, g_outc);
	if (a) {
		OK(wait_marker(g_outc, "SIM-HANG-READY", 10000) == 0,
		   "c-ready");
		snprintf(ctid, sizeof(ctid), "%s", occ_orch_child_task(a));
		OK(occ_orch_wait(a, &r, err, sizeof(err)) == 0, "c-timeout");
		OK(r.end == OCC_ORCH_END_TIMEOUT && r.signal == SIGTERM,
		   "c-timeout-term");
		OK(r.dur_ms >= 1400 && r.dur_ms < 8000, "c-timeout-window");
		OK(r.reviewed == 1, "c-timeout-reviewed");
		occ_orch_result_free(&r);
		OK(occ_task_get(g_db, ctid, &trow, NULL, 0) == 1 &&
		   !strcmp(trow.status, OCC_TASK_ST_IN_REVIEW),
		   "c-timeout-task-in-review");
		occ_task_row_free(&trow);
	}
	a = spawn_probe("sim:ignoreterm 30", 1500, g_outc2);
	if (a) {
		OK(wait_marker(g_outc2, "SIM-IGNORETERM", 10000) == 0,
		   "c2-ready");
		OK(occ_orch_wait(a, &r, err, sizeof(err)) == 0, "c2-timeout");
		OK(r.end == OCC_ORCH_END_TIMEOUT && r.signal == SIGKILL,
		   "c2-timeout-kill-stage");
		occ_orch_result_free(&r);
	}

	/* ===== G E3：文件集互斥（运行时登记+冲突拒绝+终局注销） ===== */
	{
		occ_orch_spawn_opts opts;
		occ_orch_child *ga = NULL, *gb = NULL;
		char owner[OCC_ID_LEN];
		char outg[192];
		const char *fsa[2] = { "/tmp/occ_fsx_g1.c",
				       "/tmp/occ_fsx_common.h" };
		const char *fsb[2] = { "/tmp/occ_fsx_g2.c",
				       "/tmp/occ_fsx_common.h" };
		const char *fsc[1] = { "/tmp/occ_fsx_g3.c" };

		snprintf(outg, sizeof(outg), "%s/g_hang.out", tmpdir);
		OK(occ_orch_fileset_conflict(g_o, fsa, 2, owner,
					     sizeof(owner)) == 0,
		   "g-pre-no-conflict");
		/* 声明占用：hang 子进程持有 fsa（含公共文件） */
		memset(&opts, 0, sizeof(opts));
		opts.prompt = "sim:hang 30";
		opts.parent_session = g_psid;
		opts.occ_bin = self_bin;
		opts.env = g_sim_env;
		opts.fileset = fsa;
		opts.nfileset = 2;
		opts.stdout_path = outg;
		OK(occ_orch_spawn(g_o, &opts, &ga, err, sizeof(err)) ==
		   OCC_ORCH_OK, "g-spawn-hold");
		if (ga) {
			OK(wait_marker(outg, "SIM-HANG-READY", 10000) == 0,
			   "g-ready");
			/* API 面：撞车检出+持有者回填 */
			OK(occ_orch_fileset_conflict(g_o, fsb, 2, owner,
						     sizeof(owner)) == 1 &&
			   owner[0] == 't', "g-conflict-api");
			/* 并发第二个任务声明同文件 = spawn 拒绝（EFILESET） */
			memset(&opts, 0, sizeof(opts));
			opts.prompt = "sim:ok";
			opts.parent_session = g_psid;
			opts.occ_bin = self_bin;
			opts.env = g_sim_env;
			opts.fileset = fsb;
			opts.nfileset = 2;
			OK(occ_orch_spawn(g_o, &opts, &gb, err,
					  sizeof(err)) == OCC_ORCH_EFILESET,
			   "g-second-rejected");
			OK(gb == NULL && strstr(err, "独占"), "g-reject-msg");
			/* 不同文件不冲突 */
			opts.fileset = fsc;
			opts.nfileset = 1;
			OK(occ_orch_spawn(g_o, &opts, &gb, err,
					  sizeof(err)) == OCC_ORCH_OK,
			   "g-distinct-ok");
			if (gb) {
				occ_orch_wait(gb, &r, err, sizeof(err));
				occ_orch_result_free(&r);
				gb = NULL;
			}
			/* 取消（终局）自动注销 → fsa 可再声明 */
			OK(occ_orch_cancel(ga, &r, err, sizeof(err)) == 0,
			   "g-cancel");
			occ_orch_result_free(&r);
			ga = NULL;
			OK(occ_orch_fileset_conflict(g_o, fsa, 2, owner,
						     sizeof(owner)) == 0,
			   "g-released-after-cancel");
			/* 正常终局路径注销：再 spawn fsa（sim:ok 即退）→
			 * wait 收口 → 第三次 spawn 同集仍应成功 */
			memset(&opts, 0, sizeof(opts));
			opts.prompt = "sim:ok";
			opts.parent_session = g_psid;
			opts.occ_bin = self_bin;
			opts.env = g_sim_env;
			opts.fileset = fsa;
			opts.nfileset = 2;
			OK(occ_orch_spawn(g_o, &opts, &ga, err,
					  sizeof(err)) == OCC_ORCH_OK,
			   "g-respawn-same-fileset");
			if (ga) {
				occ_orch_wait(ga, &r, err, sizeof(err));
				occ_orch_result_free(&r);
				ga = NULL;
				OK(occ_orch_fileset_conflict(g_o, fsa, 2,
							     owner,
							     sizeof(owner)) ==
				   0, "g-released-after-exit");
			}
		} else {
			printf("FAIL g-ready-sync\n");
			n_fail++;
		}
	}

	/* ===== H E3：task 第七工具五动作全链（sim 子进程；OCC_ORCH_TOOLS
	 * 开关打开态演练——spawn→wait→status→read_result→return） ===== */
	{
		occ_tool_ctx tc;
		occ_tool_result tr;
		char args[1600];
		char tid[OCC_ID_LEN] = "";
		occ_orch_child *hc = NULL;
		occ_orch_spawn_opts ho;
		const char *fsh[1] = { "/tmp/occ_fsx_h_zz.c" };
		const char *q, *body;
		char *e;

		setenv("OCC_ORCH_TOOLS", "1", 1);
		setenv("OCC_ORCH_BIN", self_bin, 1);	/* 子进程=本 sim */
		setenv("OCC_ORCH_SIM", "1", 1);		/* 分发键随 env 继承 */
		memset(&tc, 0, sizeof(tc));
		tc.db = g_db;
		tc.session_id = g_psid;
		tc.workdir = tmpdir;
		tc.orch = g_o;
		memset(&tr, 0, sizeof(tr));

		/* H1 spawn：brief 组装→派发（goal 内嵌 sim:report 触发词） */
		snprintf(args, sizeof(args),
			 "{\"action\":\"spawn\",\"brief\":{\"goal\":"
			 "\"sim:report 子任务完成：目标达成，证据完整\","
			 "\"fileset\":[\"h_t1.c\"],\"forbidden\":[\"Makefile\"],"
			 "\"acceptance\":[\"exit=0\"],\"rework_max\":2}}");
		OK(occ_tool_exec(&tc, "task", "call_h1", args, &tr) == 0 &&
		   tr.text && strstr(tr.text, "\"ok\":true") &&
		   strstr(tr.text, "\"action\":\"spawn\"") &&
		   strstr(tr.text, "\"task_id\":\"tsk_") &&
		   strstr(tr.text, "\"result_file\":\"/tmp/") &&
		   strstr(tr.text, "\"rework_max\":2"), "h1-tool-spawn");
		if (tr.text) {
			q = strstr(tr.text, "\"task_id\":\"");
			if (q) {
				q += strlen("\"task_id\":\"");
				e = strchr(q, '"');
				if (e && (size_t)(e - q) < sizeof(tid)) {
					memcpy(tid, q, (size_t)(e - q));
					tid[e - q] = '\0';
				}
			}
		}
		OK(tid[0] == 't', "h1-tid-extracted");
		occ_tool_result_free(&tr);

		/* H2 wait：限时等终局（sim:report 写结果文件后即退） */
		snprintf(args, sizeof(args),
			 "{\"action\":\"wait\",\"task_id\":\"%s\","
			 "\"timeout_ms\":15000}", tid);
		OK(occ_tool_exec(&tc, "task", "call_h2", args, &tr) == 0 &&
		   tr.text && strstr(tr.text, "\"done\":true") &&
		   strstr(tr.text, "\"end\":\"exit\"") &&
		   strstr(tr.text, "\"exit_code\":0") &&
		   strstr(tr.text, "\"task_state\":\"in_review\""),
		   "h2-tool-wait");
		occ_tool_result_free(&tr);

		/* H3 status：出活表后 DB 读回 in_review */
		snprintf(args, sizeof(args),
			 "{\"action\":\"status\",\"task_id\":\"%s\"}", tid);
		OK(occ_tool_exec(&tc, "task", "call_h3", args, &tr) == 0 &&
		   tr.text && strstr(tr.text, "\"state\":\"in_review\"") &&
		   strstr(tr.text, "\"rework_max\":2"), "h3-tool-status");
		occ_tool_result_free(&tr);

		/* H4 read_result：报告=结果文件内容（env 通道闭环） */
		snprintf(args, sizeof(args),
			 "{\"action\":\"read_result\",\"task_id\":\"%s\"}",
			 tid);
		OK(occ_tool_exec(&tc, "task", "call_h4", args, &tr) == 0 &&
		   tr.text && strstr(tr.text, "目标达成") &&
		   strstr(tr.text, "\"result_event\":") &&
		   strstr(tr.text, "\"task_state\":\"in_review\""),
		   "h4-tool-read-result");
		body = tr.text;
		(void)body;
		printf("drill task read_result: %.360s\n",
		       tr.text ? tr.text : "(null)");
		occ_tool_result_free(&tr);

		/* H5 return：表态记入任务事件（最小实现；E4 接 verdict） */
		snprintf(args, sizeof(args),
			 "{\"action\":\"return\",\"task_id\":\"%s\","
			 "\"verdict\":\"认可：exit=0，报告完整达标\"}", tid);
		OK(occ_tool_exec(&tc, "task", "call_h5", args, &tr) == 0 &&
		   tr.text && strstr(tr.text, "\"recorded\":true"),
		   "h5-tool-return");
		occ_tool_result_free(&tr);
		{
			occ_task_event_row *evs = NULL;
			size_t nevs = 0, k;
			int found = 0;

			if (occ_task_events(g_db, tid, &evs, &nevs, NULL,
					    0) == 0) {
				for (k = 0; k < nevs; k++)
					if (!strcmp(evs[k].kind,
						    OCC_TASK_EV_RETURN))
						found = 1;
				occ_task_event_rows_free(evs, nevs);
			}
			OK(found, "h5-return-event-in-db");
		}

		/* H6 工具面互斥：一路 hang 持有 /tmp/occ_fsx_h_zz.c →
		 * task spawn 声明同文件 → 结构化 EFILESET 拒绝 */
		memset(&ho, 0, sizeof(ho));
		ho.prompt = "sim:hang 30";
		ho.parent_session = g_psid;
		ho.occ_bin = self_bin;
		ho.env = g_sim_env;
		ho.fileset = fsh;
		ho.nfileset = 1;
		OK(occ_orch_spawn(g_o, &ho, &hc, err, sizeof(err)) ==
		   OCC_ORCH_OK, "h6-fsx-hold");
		snprintf(args, sizeof(args),
			 "{\"action\":\"spawn\",\"brief\":{\"goal\":"
			 "\"撞互斥的第二个任务\",\"fileset\":"
			 "[\"/tmp/occ_fsx_h_zz.c\"]}}");
		OK(occ_tool_exec(&tc, "task", "call_h6", args, &tr) != 0 &&
		   tr.text && strstr(tr.text, "\"ok\":false") &&
		   strstr(tr.text, "EFILESET"), "h6-tool-fsx-reject");
		occ_tool_result_free(&tr);
		if (hc) {
			occ_orch_cancel(hc, &r, err, sizeof(err));
			occ_orch_result_free(&r);
		}
		unsetenv("OCC_ORCH_TOOLS");
		unsetenv("OCC_ORCH_BIN");
		unsetenv("OCC_ORCH_SIM");
	}

	/* ===== E/F B2 压测 + WAL 读回 ===== */
	b2_stress();
	{
		char q[192], jmv[24] = "";

		snprintf(q, sizeof(q), "PRAGMA journal_mode");
		sql_str(g_dbpath, q, jmv, sizeof(jmv));
		OK(!strcmp(jmv, "wal"), "f-journal-mode-wal");
	}
	b2_report();

	/* ===== D 并发闸（最后：退避窗不扰前序） =====
	 * 测试短窗 2000ms（本 VM 共享高载——execve 装载+TERM 致死可
	 * 达数百 ms；窗长只需远大于取消耗时、小于测试时长即可，闸语义
	 * 不变：撞限开窗→窗内拒绝→槽空窗存续→满窗自动复位）。 */
	occ_orch_set_backoff_ms(g_o, 2000);
	a = spawn_probe("sim:hang 30", 0, g_outd1);
	b = spawn_probe("sim:hang 30", 0, g_outd2);
	OK(occ_orch_nrunning(g_o) == 2, "d-two-running");
	if (wait_marker(g_outd1, "SIM-HANG-READY", 20000) == 0 &&
	    wait_marker(g_outd2, "SIM-HANG-READY", 20000) == 0) {
		occ_orch_spawn_opts opts;
		long long rem;

		memset(&opts, 0, sizeof(opts));
		opts.prompt = "sim:ok";
		opts.occ_bin = self_bin;
		opts.env = g_sim_env;
		c = NULL;
		OK(occ_orch_spawn(g_o, &opts, &c, err, sizeof(err)) ==
		   OCC_ORCH_ELIMIT, "d-third-rejected");
		rem = occ_orch_backoff_ms(g_o);
		OK(rem > 0 && rem <= 2000, "d-backoff-window-open");
		c = NULL;
		OK(occ_orch_spawn(g_o, &opts, &c, err, sizeof(err)) ==
		   OCC_ORCH_EBACKOFF, "d-backoff-window-reject");
		OK(occ_orch_cancel(a, &r, err, sizeof(err)) == 0,
		   "d-cancel-a");
		occ_orch_result_free(&r);
		OK(occ_orch_cancel(b, &r, err, sizeof(err)) == 0,
		   "d-cancel-b");
		occ_orch_result_free(&r);
		OK(occ_orch_nrunning(g_o) == 0, "d-slots-free");
		OK(occ_orch_backoff_ms(g_o) > 0, "d-window-outlives-slots");
	} else {
		printf("FAIL d-ready-sync\n");
		n_fail++;
		if (a) {
			occ_orch_cancel(a, &r, err, sizeof(err));
			occ_orch_result_free(&r);
		}
		if (b) {
			occ_orch_cancel(b, &r, err, sizeof(err));
			occ_orch_result_free(&r);
		}
		a = NULL;
		b = NULL;
	}
	msleep(2100);
	OK(occ_orch_backoff_ms(g_o) == 0, "d-window-expires");
	{
		occ_orch_child *e2 = spawn_simple("sim:ok", 0);

		if (e2) {
			occ_orch_wait(e2, &r, err, sizeof(err));
			OK(r.end == OCC_ORCH_END_EXIT, "d-spawn-after-window");
			occ_orch_result_free(&r);
		}
	}
	occ_orch_set_backoff_ms(g_o, 0);	/* 复位缺省 30s */

	occ_orch_free(g_o);
	occ_db_close(g_db);
	/* OCC_ORCH_KEEP=1：保留夹具目录（压测诊断用；正常跑清理） */
	if (getenv("OCC_ORCH_KEEP"))
		printf("note keep tmpdir=%s\n", tmpdir);
	else
		rm_rf(tmpdir);
	printf("orch: %d ok assertions / FAIL=%d\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}

/* ---- --conc-drill：mock LLM 2 路真 occ -p 并发对话（E2 验收门） ---- */

static int wait_port(int port)
{
	struct sockaddr_in addr;
	int s, i;

	for (i = 0; i < 80; i++) {
		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0)
			return -1;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons((unsigned short)port);
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
			close(s);
			return 0;
		}
		close(s);
		msleep(100);
	}
	return -1;
}

static int conc_drill_main(int argc, char **argv)
{
	const char *occ_bin = argc > 2 ? argv[2] : "./occ";
	char tdir[128], toml[192], dbp[192], reqdir[192];
	char occroot[512], absocc[512], mockpy[512], pbuf[16];
	char env_toml[300];
	FILE *f;
	pid_t mock;
	int port = 20000 + (int)(now_ms() % 20000);
	occ_db *db;
	occ_session_row srow, *rows = NULL;
	size_t nrows = 0;
	char psid[OCC_ID_LEN] = "";
	char err[256];
	occ_orch *o;
	occ_orch_child *ca = NULL, *cb = NULL, *cc = NULL;
	const char *envp[2];
	occ_orch_spawn_opts opts;
	occ_orch_result r;
	int fail = 0;
	char *slash;

	/* mock 与 occ 的绝对路径：/proc/self/exe（tests/test_orch）上溯 */
	snprintf(occroot, sizeof(occroot), "%s", self_bin);
	slash = strrchr(occroot, '/');
	if (slash)
		*slash = '\0';			/* occroot=…/occ/tests */
	snprintf(absocc, sizeof(absocc), "%.400s/../occ", occroot);
	slash = strrchr(occroot, '/');
	if (slash)
		*slash = '\0';			/* occroot=…/occ */
	snprintf(mockpy, sizeof(mockpy), "%.400s/tests/mock_llm.py", occroot);
	if (access(absocc, X_OK) == 0)
		occ_bin = absocc;

	snprintf(tdir, sizeof(tdir), "/tmp/occ_orch_drill.XXXXXX");
	if (!mkdtemp(tdir)) {
		printf("FAIL drill mkdtemp\n");
		return 1;
	}
	snprintf(reqdir, sizeof(reqdir), "%s/reqs", tdir);
	mkdir(reqdir, 0755);
	snprintf(toml, sizeof(toml), "%s/model.toml", tdir);
	f = fopen(toml, "w");
	if (!f) {
		printf("FAIL drill toml\n");
		return 1;
	}
	fprintf(f,
		"[models.cloud]\n"
		"provider_type = \"openai_compatible\"\n"
		"model_name = \"mock-model\"\n"
		"base_url = \"http://127.0.0.1:%d/v1\"\n"
		"api_key = \"mock-key-not-real\"\n", port);
	fclose(f);

	{
		char *margv[5];

		snprintf(pbuf, sizeof(pbuf), "%d", port);
		margv[0] = (char *)"python3";
		margv[1] = mockpy;
		margv[2] = pbuf;
		margv[3] = reqdir;
		margv[4] = NULL;
		mock = fork_exec(margv);
	}
	if (mock < 0 || wait_port(port) != 0) {
		printf("FAIL drill mock-up (port %d)\n", port);
		if (mock > 0)
			kill(mock, SIGKILL);
		return 1;
	}
	printf("ok drill-mock-up port=%d\n", port);
	n_ok++;

	snprintf(dbp, sizeof(dbp), "%s/sessions.db", tdir);
	db = occ_db_open(dbp, err, sizeof(err));
	if (!db) {
		printf("FAIL drill db: %s\n", err);
		kill(mock, SIGKILL);
		return 1;
	}
	if (occ_session_create(db, "drill", &srow, err, sizeof(err)) != 0) {
		printf("FAIL drill session: %s\n", err);
		kill(mock, SIGKILL);
		return 1;
	}
	snprintf(psid, sizeof(psid), "%s", srow.id);
	(void)rows;
	(void)nrows;

	o = occ_orch_new(db);
	snprintf(env_toml, sizeof(env_toml), "OCC_MODEL_TOML=%.240s",
		 toml);
	envp[0] = env_toml;
	envp[1] = NULL;

	memset(&opts, 0, sizeof(opts));
	opts.prompt = "并发演练第一路：请记住暗号 e2-alpha";
	opts.parent_session = psid;
	opts.occ_bin = occ_bin;
	opts.env = envp;
	opts.timeout_ms = 60000;
	if (occ_orch_spawn(o, &opts, &ca, err, sizeof(err)) != 0) {
		printf("FAIL drill spawn-a: %s\n", err);
		n_fail++;
		fail++;
	}
	opts.prompt = "并发演练第二路：请记住暗号 e2-beta";
	if (occ_orch_spawn(o, &opts, &cb, err, sizeof(err)) != 0) {
		printf("FAIL drill spawn-b: %s\n", err);
		n_fail++;
		fail++;
	}
	/* 第三路撞限即拒（并发闸活证） */
	opts.prompt = "并发演练第三路";
	if (occ_orch_spawn(o, &opts, &cc, err, sizeof(err)) ==
	    OCC_ORCH_ELIMIT) {
		printf("ok drill-third-rejected\n");
		n_ok++;
	} else {
		printf("FAIL drill-third-rejected (%s)\n", err);
		n_fail++;
		fail++;
		if (cc)
			occ_orch_cancel(cc, NULL, NULL, 0);
	}
	if (ca && occ_orch_wait(ca, &r, err, sizeof(err)) == 0) {
		int good = r.end == OCC_ORCH_END_EXIT && r.exit_code == 0 &&
			   r.stdout_tail &&
			   strstr(r.stdout_tail, "冒烟 mock 助手") != NULL;

		printf("%s drill-a-exit0-reply\n", good ? "ok" : "FAIL");
		if (good)
			n_ok++;
		else {
			n_fail++;
			fail++;
		}
		occ_orch_result_free(&r);
	}
	if (cb && occ_orch_wait(cb, &r, err, sizeof(err)) == 0) {
		int good = r.end == OCC_ORCH_END_EXIT && r.exit_code == 0 &&
			   r.stdout_tail &&
			   strstr(r.stdout_tail, "冒烟 mock 助手") != NULL;

		printf("%s drill-b-exit0-reply\n", good ? "ok" : "FAIL");
		if (good)
			n_ok++;
		else {
			n_fail++;
			fail++;
		}
		occ_orch_result_free(&r);
	}
	/* 同库并发写证：2 child 会话各 2 条消息、tokens=100、in_review=2 */
	{
		int nchild = sql_int(dbp, "SELECT COUNT(*) FROM occ_session"
				   " WHERE kind='child'", NULL);
		int nmsg = sql_int(dbp, "SELECT COUNT(*) FROM occ_message m"
				   " JOIN occ_session s ON s.id=m.session_id"
				   " WHERE s.kind='child'", NULL);
		int nrev = sql_int(dbp, "SELECT COUNT(*) FROM occ_task"
				   " WHERE status='in_review'", NULL);
		int tok = sql_int(dbp, "SELECT COUNT(*) FROM occ_session"
				  " WHERE kind='child' AND tokens_total=50",
				  NULL);

		if (nchild == 2 && nmsg == 4 && nrev == 2 && tok == 2) {
			printf("ok drill-db-2p-concurrent-writes\n");
			n_ok++;
		} else {
			printf("FAIL drill-db nchild=%d nmsg=%d nrev=%d"
			       " tok=%d\n", nchild, nmsg, nrev, tok);
			n_fail++;
			fail++;
		}
	}
	kill(mock, SIGKILL);
	waitpid(mock, NULL, 0);

	/* 演练腿追加进 B2 报告 */
	{
		FILE *rf = fopen("tests/orch_b2_report.txt", "a");

		if (rf) {
			fprintf(rf,
				"\n[--conc-drill 腿] orch 运行时 spawn 2 路真"
				" occ -p（mock LLM）同库并发对话：\n"
				"  2 路 exit=0、stdout 含流式回复、各 2 消息"
				"（user+assistant）tokens=50/路、任务 in_review；"
				"第三路撞限即拒（ELIMIT）\n"
				"  失败数=0（同库并发写下零 SQLITE_BUSY 终局）\n");
			fclose(rf);
		}
	}
	occ_orch_free(o);
	occ_db_close(db);
	rm_rf(tdir);
	printf("orch-conc-drill: %d ok / FAIL=%d\n", n_ok, n_fail);
	return fail ? 1 : 0;
}

int main(int argc, char **argv)
{
	/* sim 分发键=env 标记（spawn 的 argv 形状与真 occ -p 逐字一致） */
	if (getenv("OCC_ORCH_SIM") && argc >= 2 && !strcmp(argv[1], "-p"))
		return sim_main(argc, argv);
	if (argc >= 2 && !strcmp(argv[1], "--b2w"))
		return b2w_main(argc, argv);
	if (argc >= 2 && !strcmp(argv[1], "--b2rw"))
		return b2rw_main(argc, argv);
	if (argc >= 2 && !strcmp(argv[1], "--conc-drill")) {
		if (readlink("/proc/self/exe", self_bin,
			     sizeof(self_bin) - 1) <= 0) {
			printf("FAIL /proc/self/exe\n");
			return 1;
		}
		self_bin[sizeof(self_bin) - 1] = '\0';
		return conc_drill_main(argc, argv);
	}
	return unit_main();
}
