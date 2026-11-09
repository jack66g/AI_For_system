/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_session.c - occ_core/session 单测（T9a3）
 *
 * 覆盖：DB open/schema、会话 CRUD、消息落库/读回、五项 usage 列、
 * tokens_total 累计、标题 UTF-8 截断、**崩溃安全事务回滚注入**
 * （fault bit0/1：INSERT 后 COMMIT 前失败 → 库无半条、状态不脏）、
 * 级联删除。库文件用 mkdtemp 临时目录，结束清理。
 *
 * schema 外部验证：测试另开 sqlite3 连接（独立观察者）直查
 * sqlite_master/PRAGMA——证明 occ_db_open 的产物对任何标准工具可见。
 *
 * B2（T9B2 §8-4 → 波次 B）：写锁竞态钉——另一连接持 RESERVED 时
 * occ 单语句写（set_status）必须经 IMMEDIATE+busy_timeout 等待后
 * 成功（修前 deferred 隐式写升级瞬时 SQLITE_BUSY，不进 busy
 * handler）。多进程面由 tests/bllm_conc_drill.sh 压测钉。
 */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <sqlite3.h>

#include "occ_core/occ_session.h"

static int n_fail;
static int n_ok;

#define OK(cond, name) do { \
	if (cond) { n_ok++; printf("ok %s\n", name); } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

static char tmpdir[128];

/* ---- B2 写锁竞态钉 ---- */
static const char *g_b2_path;
static volatile int g_b2_held;

/* ms 睡（nanosleep——POSIX.1-2008 无 usleep 严格面） */
static void b2_msleep(int ms)
{
	struct timespec ts;

	ts.tv_sec = 0;
	ts.tv_nsec = (long)ms * 1000 * 1000;
	nanosleep(&ts, NULL);
}

/* 独立连接持 RESERVED（BEGIN IMMEDIATE+UPDATE 未提交）150ms 后释放 */
static void *b2_hold_reserved_thread(void *unused)
{
	sqlite3 *h = NULL;
	char sql[128];

	(void)unused;
	if (sqlite3_open_v2(g_b2_path, &h, SQLITE_OPEN_READWRITE, NULL)
	    != SQLITE_OK) {
		if (h)
			sqlite3_close(h);
		return NULL;
	}
	sqlite3_exec(h, "PRAGMA busy_timeout=2000;", NULL, NULL, NULL);
	snprintf(sql, sizeof(sql),
		 "BEGIN IMMEDIATE; UPDATE occ_session SET title='b2hold'"
		 " WHERE rowid=1;");
	if (sqlite3_exec(h, sql, NULL, NULL, NULL) == SQLITE_OK)
		g_b2_held = 1;
	b2_msleep(150);
	sqlite3_exec(h, "COMMIT;", NULL, NULL, NULL);
	sqlite3_close(h);
	return NULL;
}

/* 完整 UTF-8 序列校验（leading→continuation 链；孤立续字节=非法） */
static int utf8_valid(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;
	int need = 0;

	if (!s)
		return 0;
	while (*p) {
		if (need) {
			if ((*p & 0xC0) != 0x80)
				return 0;
			need--;
		} else if (*p < 0x80) {
			/* ASCII */
		} else if ((*p & 0xE0) == 0xC0) {
			need = 1;
		} else if ((*p & 0xF0) == 0xE0) {
			need = 2;
		} else if ((*p & 0xF8) == 0xF0) {
			need = 3;
		} else {
			return 0;	/* 孤立续字节/非法 leading */
		}
		p++;
	}
	return need == 0;		/* 截断的多字节尾巴=非法 */
}

static occ_db *g_db;

/* 独立连接查表存在性（外部观察者视角） */
static int table_exists(const char *name)
{
	sqlite3 *h;
	char path[256];
	char sql[128];
	sqlite3_stmt *st;
	int found = 0;

	snprintf(path, sizeof(path), "%s/sessions.db", tmpdir);
	if (sqlite3_open_v2(path, &h, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
		return 0;
	snprintf(sql, sizeof(sql),
		 "SELECT 1 FROM sqlite_master WHERE type='table' AND name='%s'",
		 name);
	if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK) {
		if (sqlite3_step(st) == SQLITE_ROW)
			found = 1;
		sqlite3_finalize(st);
	}
	sqlite3_close(h);
	return found;
}

/* b2：列存在性（PRAGMA table_info；表/列名为测试内固定字面量） */
static int col_exists(const char *table, const char *col)
{
	sqlite3 *h;
	char path[256];
	char sql[160];
	sqlite3_stmt *st;
	int found = 0;

	snprintf(path, sizeof(path), "%s/sessions.db", tmpdir);
	if (sqlite3_open_v2(path, &h, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
		return 0;
	snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
	if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK) {
		while (sqlite3_step(st) == SQLITE_ROW) {
			const unsigned char *name = sqlite3_column_text(st, 1);

			if (name && !strcmp((const char *)name, col)) {
				found = 1;
				break;
			}
		}
		sqlite3_finalize(st);
	}
	sqlite3_close(h);
	return found;
}

static int user_version(void)
{
	sqlite3 *h;
	char path[256];
	sqlite3_stmt *st;
	int v = -1;

	snprintf(path, sizeof(path), "%s/sessions.db", tmpdir);
	if (sqlite3_open_v2(path, &h, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
		return -1;
	if (sqlite3_prepare_v2(h, "PRAGMA user_version", -1, &st, NULL) ==
	    SQLITE_OK) {
		if (sqlite3_step(st) == SQLITE_ROW)
			v = sqlite3_column_int(st, 0);
		sqlite3_finalize(st);
	}
	sqlite3_close(h);
	return v;
}

static int count_msgs(const char *sid)
{
	sqlite3 *h;
	char path[256];
	sqlite3_stmt *st;
	int n = -1;

	snprintf(path, sizeof(path), "%s/sessions.db", tmpdir);
	if (sqlite3_open_v2(path, &h, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
		return -1;
	if (sqlite3_prepare_v2(h, "SELECT COUNT(*) FROM occ_message WHERE"
				 " session_id=?1", -1, &st, NULL) == SQLITE_OK) {
		sqlite3_bind_text(st, 1, sid, -1, SQLITE_TRANSIENT);
		if (sqlite3_step(st) == SQLITE_ROW)
			n = sqlite3_column_int(st, 0);
		sqlite3_finalize(st);
	}
	sqlite3_close(h);
	return n;
}

int main(void)
{
	char err[256] = "";
	char dbpath[256];
	occ_session_row s, s2;
	occ_msg_row *msgs = NULL;
	size_t n = 0;
	occ_usage u;
	char mid[OCC_ID_LEN];

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/occ_sess_t_%d", (int)getpid());
	mkdir(tmpdir, 0755);			/* 已存在则忽略 */
	snprintf(dbpath, sizeof(dbpath), "%s/sessions.db", tmpdir);

	/* ---- open + schema ---- */
	g_db = occ_db_open(dbpath, err, sizeof(err));
	OK(g_db != NULL, "db-open");
	OK(table_exists("occ_session"), "schema-occ_session");
	OK(table_exists("occ_message"), "schema-occ_message");
	OK(table_exists("occ_toolcall"), "schema-occ_toolcall-empty");
	OK(table_exists("occ_window"), "schema-occ_window");
	/* b2 schema v2：user_version 2 + occ_revert 表 + 两处新列 */
	OK(user_version() == 2, "schema-user_version=2");
	OK(table_exists("occ_revert"), "schema-occ_revert");
	OK(col_exists("occ_message", "reverted"), "schema-msg-reverted");
	OK(col_exists("occ_session", "workdir"), "schema-session-workdir");

	/* 重复 open 幂等（DDL IF NOT EXISTS） */
	occ_db_close(g_db);
	g_db = occ_db_open(dbpath, err, sizeof(err));
	OK(g_db != NULL, "db-reopen-idempotent");

	/* ---- 会话 CRUD ---- */
	OK(occ_session_create(g_db, "deepseek-flash", &s, err, sizeof(err)) == 0,
	   "session-create");
	OK(!strncmp(s.id, "ses_", 4), "session-id-prefix");
	OK(!strcmp(s.status, "active"), "session-initial-active");
	OK(occ_session_get(g_db, s.id, &s2, err, sizeof(err)) == 1,
	   "session-get");
	/* b2：workdir 落库/读回（undo 相对路径解析与执行同口径） */
	OK(s2.workdir[0] == '\0', "session-workdir-initial-empty");
	OK(occ_session_set_workdir(g_db, s.id, "/tmp/occ_wd_probe", err,
				   sizeof(err)) == 0, "session-set-workdir");
	OK(occ_session_get(g_db, s.id, &s2, err, sizeof(err)) == 1 &&
	   !strcmp(s2.workdir, "/tmp/occ_wd_probe"), "session-workdir-roundtrip");
	OK(!strcmp(s2.model, "deepseek-flash"), "session-model");
	OK(s2.created > 1700000000000LL, "session-created-ms");

	/* window native 行 */
	{
		sqlite3 *h;
		char path[256];
		sqlite3_stmt *st;
		int nat = 0;

		snprintf(path, sizeof(path), "%s/sessions.db", tmpdir);
		sqlite3_open_v2(path, &h, SQLITE_OPEN_READONLY, NULL);
		if (sqlite3_prepare_v2(h, "SELECT COUNT(*) FROM occ_window"
					 " WHERE session_id=?1 AND"
					 " base_kind='native'", -1, &st,
				       NULL) == SQLITE_OK) {
			sqlite3_bind_text(st, 1, s.id, -1, SQLITE_TRANSIENT);
			if (sqlite3_step(st) == SQLITE_ROW)
				nat = sqlite3_column_int(st, 0);
			sqlite3_finalize(st);
		}
		sqlite3_close(h);
		OK(nat == 1, "window-native-row");
	}

	/* 不存在的会话 */
	OK(occ_session_get(g_db, "ses_nope", &s2, err, sizeof(err)) == 0,
	   "session-get-miss");

	/* ---- 消息落库/读回 ---- */
	OK(occ_msg_add_user(g_db, s.id, "你好，帮我看看这段代码", mid,
			    sizeof(mid), err, sizeof(err)) == 0,
	   "msg-add-user");
	OK(!strncmp(mid, "msg_", 4), "msg-id-prefix");
	OK(occ_session_get(g_db, s.id, &s2, err, sizeof(err)) == 1 &&
	   !strcmp(s2.status, "running"), "user-msg-sets-running");

	memset(&u, 0, sizeof(u));
	u.present = 1;
	u.input = 55;
	u.output = 6;
	u.cache_read = 10;
	u.cache_write = 0;
	OK(occ_msg_add_assistant(g_db, s.id, "好的，我看下。", "思考中…",
				 NULL, 0, &u, 0, "stop", NULL, 0,
				 err, sizeof(err)) == 0,
	   "msg-add-assistant");
	OK(occ_session_get(g_db, s.id, &s2, err, sizeof(err)) == 1 &&
	   !strcmp(s2.status, "active"), "assistant-msg-resets-active");
	OK(s2.tokens_total == 61, "tokens-total-61");

	OK(occ_msg_list(g_db, s.id, &msgs, &n, err, sizeof(err)) == 0 && n == 2,
	   "msg-list-2");
	if (n == 2) {
		OK(!strcmp(msgs[0].role, "user"), "msg0-role-user");
		OK(msgs[0].text && !strcmp(msgs[0].text,
					   "你好，帮我看看这段代码"),
		   "msg0-text");
		OK(!strcmp(msgs[1].role, "assistant"), "msg1-role-assistant");
		OK(msgs[1].text && !strcmp(msgs[1].text, "好的，我看下。"),
		   "msg1-text");
		OK(msgs[1].reasoning && !strcmp(msgs[1].reasoning, "思考中…"),
		   "msg1-reasoning");
		OK(msgs[1].usage_in == 55 && msgs[1].usage_out == 6 &&
		   msgs[1].usage_cache_read == 10,
		   "msg1-usage-cols");
		OK(!strcmp(msgs[1].finish, "stop"), "msg1-finish");
		/* content_json 原文含 opencode 同构 part 键 */
		OK(msgs[1].content_json &&
		   strstr(msgs[1].content_json, "\"type\":\"text\"") &&
		   strstr(msgs[1].content_json, "\"type\":\"reasoning\""),
		   "msg1-parts-shape");
	} else {
		OK(0, "msg0-role-user");
		OK(0, "msg0-text");
		OK(0, "msg1-role-assistant");
		OK(0, "msg1-text");
		OK(0, "msg1-reasoning");
		OK(0, "msg1-usage-cols");
		OK(0, "msg1-finish");
		OK(0, "msg1-parts-shape");
	}
	occ_msg_rows_free(msgs, n);
	msgs = NULL;
	n = 0;

	/* 标题：首条 user 消息截断（中文 UTF-8 不切断） */
	{
		occ_session_row s3;
		size_t tl;

		occ_session_create(g_db, "m", &s3, err, sizeof(err));
		occ_msg_add_user(g_db, s3.id,
				 "这是一个非常非常长的中文标题测试句子"
				 "用来验证UTF8安全截断逻辑不会把多字节"
				 "字符切成两半导致乱码出现"
				 "继续加长继续加长继续加长继续加长",
				 NULL, 0, err, sizeof(err));
		occ_session_get(g_db, s3.id, &s3, err, sizeof(err));
		tl = strlen(s3.title);
		OK(tl > 0 && utf8_valid(s3.title), "title-utf8-safe");
		OK(tl >= 3 && !strncmp(s3.title + tl - 3, "\xE2\x80\xA6", 3),
		   "title-ellipsis");
	}

	/* occ_msg_last */
	{
		occ_msg_row last;

		OK(occ_msg_last(g_db, s.id, &last, err, sizeof(err)) == 1 &&
		   !strcmp(last.role, "assistant"), "msg-last-assistant");
		occ_msg_row_free(&last);
	}

	/* ---- 崩溃安全：事务回滚注入 ---- */
	/* bit0：add_user 的 INSERT 后 COMMIT 前失败 */
	occ_db_test_fault(0x1);
	{
		int before = count_msgs(s.id);

		OK(occ_msg_add_user(g_db, s.id, "这条不该落库", NULL, 0,
				    err, sizeof(err)) != 0,
		   "fault-add-user-fails");
		OK(count_msgs(s.id) == before, "fault-add-user-no-partial");
		/* 事务回滚：session 状态保持注入前的 active（UPDATE 与
		 * INSERT 同事务，一并回滚） */
		occ_session_get(g_db, s.id, &s2, err, sizeof(err));
		OK(!strcmp(s2.status, "active"), "fault-add-user-status-kept");
	}
	occ_db_test_fault(0);
	/* bit1：add_assistant 的 INSERT 后 COMMIT 前失败 */
	occ_db_test_fault(0x2);
	{
		long long tok_before;
		int before = count_msgs(s.id);

		occ_session_get(g_db, s.id, &s2, err, sizeof(err));
		tok_before = s2.tokens_total;
		OK(occ_msg_add_assistant(g_db, s.id, "半条", NULL, NULL, 0,
					 &u, 0, "stop", NULL, 0,
					 err, sizeof(err)) != 0,
		   "fault-add-assistant-fails");
		OK(count_msgs(s.id) == before, "fault-add-assistant-no-partial");
		occ_session_get(g_db, s.id, &s2, err, sizeof(err));
		OK(s2.tokens_total == tok_before,
		   "fault-tokens-unchanged");
	}
	occ_db_test_fault(0);

	/* 重复主键（真实约束失败路径）：直接插同 id user 消息 → 事务拒 */
	{
		occ_session_row s4;

		occ_session_create(g_db, "m", &s4, err, sizeof(err));
		occ_msg_add_user(g_db, s4.id, "one", mid, sizeof(mid), err,
				 sizeof(err));
		/* 同一 msg id 再插：绕过 API 层——用 sqlite 直插模拟并发/竞态
		 * 下 UNIQUE 冲突路径走 ROLLBACK（fault 之外的天然失败） */
		{
			sqlite3 *h;
			char path[256];
			char sql[256];
			char *perr = NULL;

			snprintf(path, sizeof(path), "%s/sessions.db",
				 tmpdir);
			sqlite3_open_v2(path, &h, SQLITE_OPEN_READWRITE, NULL);
			snprintf(sql, sizeof(sql),
				 "INSERT INTO occ_message(id,session_id,role,"
				 "content_json,created) VALUES('%s','%s',"
				 "'user','[]',1)", mid, s4.id);
			/* 注：此直插不在 occ 事务内，预期 SQLITE_CONSTRAINT
			 * 失败（主键冲突）——证明约束真实存在 */
			if (sqlite3_exec(h, sql, NULL, NULL, &perr) !=
			    SQLITE_OK) {
				OK(strstr(perr ? perr : "", "UNIQUE") !=
				   NULL, "pk-constraint-real");
			} else {
				OK(0, "pk-constraint-real");
			}
			sqlite3_free(perr);
			sqlite3_close(h);
		}
	}

	/* ---- set_status / set_title / list ---- */
	OK(occ_session_set_status(g_db, s.id, "error", err, sizeof(err)) == 0 &&
	   occ_session_get(g_db, s.id, &s2, err, sizeof(err)) == 1 &&
	   !strcmp(s2.status, "error"), "set-status");
	OK(occ_session_set_title(g_db, s.id, "title'with\"quotes",
				 err, sizeof(err)) == 0 &&
	   occ_session_get(g_db, s.id, &s2, err, sizeof(err)) == 1 &&
	   !strcmp(s2.title, "title'with\"quotes"), "set-title-quoted");

	{
		occ_session_row *rows = NULL;
		size_t nr = 0;

		OK(occ_session_list(g_db, &rows, &nr, err, sizeof(err)) == 0 &&
		   nr >= 3, "session-list");
		OK(nr >= 2 && strcmp(rows[0].id, rows[nr - 1].id) != 0,
		   "session-list-desc");
		free(rows);
	}

	/* ---- 级联删除（外键生效；FK 是 per-connection PRAGMA——外部
	 * 连接须自开 foreign_keys，occ 自有连接 open 时已开） ---- */
	{
		occ_session_row s5;

		occ_session_create(g_db, "m", &s5, err, sizeof(err));
		occ_msg_add_user(g_db, s5.id, "x", NULL, 0, err, sizeof(err));
		{
			sqlite3 *h;
			char path[256];
			char sql[160];

			snprintf(path, sizeof(path), "%s/sessions.db",
				 tmpdir);
			sqlite3_open_v2(path, &h, SQLITE_OPEN_READWRITE, NULL);
			sqlite3_exec(h, "PRAGMA foreign_keys=ON", NULL, NULL,
				     NULL);
			snprintf(sql, sizeof(sql),
				 "DELETE FROM occ_session WHERE id='%s'",
				 s5.id);
			sqlite3_exec(h, sql, NULL, NULL, NULL);
			sqlite3_close(h);
		}
		OK(count_msgs(s5.id) == 0, "fk-cascade-delete");
	}

	/* ---- B2：写锁竞态钉（RESERVED 持有者 + occ 单语句写） ---- */
	{
		pthread_t th;
		char dbpath[256];
		struct timeval t0, t1;
		long el;
		int rc, spin;

		snprintf(dbpath, sizeof(dbpath), "%s/sessions.db", tmpdir);
		g_b2_path = dbpath;
		if (pthread_create(&th, NULL, b2_hold_reserved_thread, NULL)) {
			OK(0, "b2-thread-create");
		} else {
			/* 等 RESERVED 真正到手（上限 2s） */
			for (spin = 0; spin < 2000 && !g_b2_held; spin++)
				b2_msleep(1);
			OK(g_b2_held, "b2-reserved-held");
			gettimeofday(&t0, NULL);
			rc = occ_session_set_status(g_db, s.id, "running",
						    err, sizeof(err));
			gettimeofday(&t1, NULL);
			pthread_join(th, NULL);
			el = (t1.tv_sec - t0.tv_sec) * 1000 +
			     (t1.tv_usec - t0.tv_usec) / 1000;
			OK(rc == 0, "b2-set-status-waits-and-succeeds");
			OK(el >= 100 && el < 4500,
			   "b2-waited-not-instant-not-timeout");
		}
	}

	/* ---- 收尾：半开事务由 close 回滚（fault 后库仍可用） ---- */
	OK(occ_msg_add_user(g_db, s.id, "fault 后库仍可写", NULL, 0,
			    err, sizeof(err)) == 0, "db-usable-after-fault");

	occ_db_close(g_db);
	{
		char cmd[192];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
		if (system(cmd)) {
			/* 清理失败不影响判定 */
		}
	}

	printf("test_session: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
