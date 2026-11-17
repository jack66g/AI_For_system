/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_task.c - occ_core/task 单测（波次 E1：任务数据面）
 *
 * 覆盖：
 *   A) schema v3：新库两表+kind 列+user_version=3；
 *      v2→v3 老库前向迁移无损（老会话/消息可读、kind 补 'main'）；
 *      v3 库重复打开幂等（零副作用——行数/版本不变）。
 *   B) 任务状态机全路径：pending→dispatched→in_review→done（一过）；
 *      回炉环 verdict 失败×N（≤rework_max → rework→dispatched ↺）；
 *      超限自动 escalated；手动 escalate；distill（done 后审计事件）。
 *   C) 非法迁移拒绝（返回错误不静默；err 含「非法迁移」）：pending
 *      起 review/verdict/escalate/distill、dispatched 起 verdict、
 *      in_review 起 dispatch、done/escalated 起一切。
 *   D) 事件审计：occ_task_event 顺序/种类/payload 与动作序列对齐。
 *   E) 会话 kind：缺省 main / child 建会话回读 / 非法值拒绝。
 *   F) /clear 库面（occ_session_archive）：归档后 status=archived 且
 *      消息可查回（非删除）、occ_window 回 native 空基线（digest_id
 *      置空）、幂等、不存在人话报错。
 *   G) E7 预算记账 API：budget 基线事件（两列不动）/budget_add 单事务
 *      累加（两拍+负 delta 钳 0）/kind='budget' 审计三行（src=
 *      usage/estimated 标注对齐）/独立连接直查/不存在人话报错。
 *
 * 外部验证：另开独立 sqlite3 连接直查（PRAGMA/sqlite_master）——
 * 产物对任何标准工具可见（同 test_session 口径）。
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sqlite3.h>

#include "occ_core/task.h"

static int n_fail;
static int n_ok;

#define OK(cond, name) do { \
	if (cond) { n_ok++; printf("ok %s\n", name); } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

static char tmpdir[128];

/* ---- 独立连接观察者（路径相对 tmpdir） ---- */

static char *dbpath_of(const char *name)
{
	static char buf[192];

	snprintf(buf, sizeof(buf), "%s/%s", tmpdir, name);
	return buf;
}

static int sql_int(const char *db, const char *sql)
{
	sqlite3 *h;
	sqlite3_stmt *st;
	int v = -1;

	if (sqlite3_open_v2(db, &h, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
		return -1;
	if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK) {
		if (sqlite3_step(st) == SQLITE_ROW)
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
	int rc = -1;

	out[0] = '\0';
	if (sqlite3_open_v2(db, &h, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
		return -1;
	if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK) {
		if (sqlite3_step(st) == SQLITE_ROW) {
			const unsigned char *s = sqlite3_column_text(st, 0);

			snprintf(out, cap, "%s", s ? (const char *)s : "");
			rc = 0;
		}
		sqlite3_finalize(st);
	}
	sqlite3_close(h);
	return rc;
}

/* ---- v2 旧库夹具（E1 迁移前夜形态：workdir/reverted/occ_revert 在、
 * kind/occ_task/occ_task_event 不在；user_version=2） ---- */

static const char V2_DDL[] =
	"CREATE TABLE occ_session ("
	"  id TEXT PRIMARY KEY,"
	"  title TEXT NOT NULL DEFAULT '',"
	"  created INTEGER NOT NULL,"
	"  model TEXT NOT NULL DEFAULT '',"
	"  tokens_total INTEGER NOT NULL DEFAULT 0,"
	"  status TEXT NOT NULL DEFAULT 'active',"
	"  updated INTEGER NOT NULL DEFAULT 0,"
	"  tokens_est INTEGER NOT NULL DEFAULT 0,"
	"  workdir TEXT NOT NULL DEFAULT ''"
	");"
	"CREATE TABLE occ_message ("
	"  id TEXT PRIMARY KEY,"
	"  session_id TEXT NOT NULL"
	"    REFERENCES occ_session(id) ON DELETE CASCADE,"
	"  role TEXT NOT NULL,"
	"  content_json TEXT NOT NULL,"
	"  usage_in INTEGER, usage_out INTEGER,"
	"  usage_cache_read INTEGER, usage_cache_write INTEGER,"
	"  usage_est INTEGER NOT NULL DEFAULT 0,"
	"  finish TEXT NOT NULL DEFAULT '',"
	"  created INTEGER NOT NULL,"
	"  reverted INTEGER NOT NULL DEFAULT 0"
	");"
	"CREATE INDEX occ_message_session ON occ_message(session_id, created);"
	"CREATE TABLE occ_toolcall ("
	"  id TEXT PRIMARY KEY,"
	"  message_id TEXT NOT NULL"
	"    REFERENCES occ_message(id) ON DELETE CASCADE,"
	"  tool TEXT NOT NULL,"
	"  args_json TEXT,"
	"  result_json TEXT,"
	"  rc INTEGER,"
	"  dur_ms INTEGER"
	");"
	"CREATE TABLE occ_window ("
	"  session_id TEXT PRIMARY KEY"
	"    REFERENCES occ_session(id) ON DELETE CASCADE,"
	"  base_kind TEXT NOT NULL DEFAULT 'native',"
	"  digest_id TEXT"
	");"
	"CREATE TABLE occ_revert ("
	"  session_id TEXT PRIMARY KEY"
	"    REFERENCES occ_session(id) ON DELETE CASCADE,"
	"  boundary_msg TEXT NOT NULL,"
	"  note_msg TEXT NOT NULL,"
	"  created INTEGER NOT NULL,"
	"  files_json TEXT NOT NULL DEFAULT '',"
	"  hidden_json TEXT NOT NULL DEFAULT ''"
	");"
	"PRAGMA user_version=2;";

static void build_v2_db(const char *path)
{
	sqlite3 *h;

	if (sqlite3_open_v2(path, &h, SQLITE_OPEN_READWRITE |
			    SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
		if (h)
			sqlite3_close(h);
		return;
	}
	sqlite3_exec(h, V2_DDL, NULL, NULL, NULL);
	/* 老数据：一会话两消息 + digest 窗口（迁移后必须原样可读） */
	sqlite3_exec(h,
		     "INSERT INTO occ_session VALUES"
		     " ('ses_v2old','v2 旧会话',1700000000000,'old-model',9,"
		     "'active',1700000000000,0,'/tmp/wd');"
		     "INSERT INTO occ_message VALUES"
		     " ('msg_v2a','ses_v2old','user',"
		     "'[{\"type\":\"text\",\"text\":\"v2 老消息\"}]',"
		     "NULL,NULL,NULL,NULL,0,'',1700000000000,0);"
		     "INSERT INTO occ_message VALUES"
		     " ('msg_v2b','ses_v2old','assistant',"
		     "'[{\"type\":\"text\",\"text\":\"v2 老回复\"}]',"
		     "1,2,NULL,NULL,0,'stop',1700000000001,0);"
		     "INSERT INTO occ_window VALUES"
		     " ('ses_v2old','digest','msg_v2a');",
		     NULL, NULL, NULL);
	sqlite3_close(h);
}

int main(void)
{
	char err[256] = "";
	occ_db *db;
	occ_session_row s, s2;
	occ_task_row t, t2, *tl = NULL;
	occ_task_event_row *evs = NULL;
	occ_msg_row *msgs = NULL;
	size_t n = 0, i;
	char mid[OCC_ID_LEN];

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/occ_task_t_%d", (int)getpid());
	mkdir(tmpdir, 0755);
	db = occ_db_open(dbpath_of("new.db"), err, sizeof(err));

	/* ---- A) 新库 schema v3（P-50 后开库即 v4——迁移链随位对齐） ---- */
	OK(db != NULL, "db-open");
	OK(sql_int(dbpath_of("new.db"), "PRAGMA user_version") == 4,
	   "v3-new-user-version");
	OK(sql_int(dbpath_of("new.db"),
		   "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
		   " AND name='occ_task'") == 1, "v3-new-task-table");
	OK(sql_int(dbpath_of("new.db"),
		   "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
		   " AND name='occ_task_event'") == 1, "v3-new-event-table");
	OK(sql_int(dbpath_of("new.db"),
		   "SELECT COUNT(*) FROM pragma_table_info('occ_session')"
		   " WHERE name='kind'") == 1, "v3-new-session-kind-col");
	OK(db && occ_db_sqlite(db) != NULL, "db-sqlite-handle");

	/* ---- E) 会话 kind ---- */
	OK(occ_session_create(db, "glm-5.3", &s, err, sizeof(err)) == 0,
	   "kind-main-create");
	OK(!strcmp(s.kind, OCC_SK_MAIN), "kind-main-default");
	OK(occ_session_create_kind(db, "glm-5.3", OCC_SK_CHILD, &s2,
				   err, sizeof(err)) == 0, "kind-child-create");
	OK(!strcmp(s2.kind, OCC_SK_CHILD), "kind-child-roundtrip");
	err[0] = '\0';
	OK(occ_session_create_kind(db, "glm-5.3", "bogus", NULL,
				   err, sizeof(err)) == -1 &&
	   strstr(err, "kind") != NULL, "kind-bogus-rejected");

	/* ---- B/C/D) 状态机 ---- */
	/* 建：缺省 rework_max=2（R2） */
	err[0] = '\0';
	OK(occ_task_create(db, s.id, "侦察任务", "{\"goal\":\"扫一处落点\"}",
			   0, &t, err, sizeof(err)) == 0, "task-create");
	OK(!strncmp(t.id, "tsk_", 4), "task-id-prefix");
	OK(!strcmp(t.status, OCC_TASK_ST_PENDING), "task-initial-pending");
	OK(t.rework_max == OCC_TASK_REWORK_MAX_DEF, "task-rework-max-default");
	OK(occ_task_get(db, t.id, &t2, err, sizeof(err)) == 1 &&
	   t2.brief_json && !strcmp(t2.brief_json,
				    "{\"goal\":\"扫一处落点\"}") &&
	   !strcmp(t2.parent_session, s.id), "task-get-roundtrip");
	OK(occ_task_get(db, "tsk_nope", &t2, err, sizeof(err)) == 0,
	   "task-get-miss");
	/* 建失败路径：rework_max 超界（R2 覆写 1-3）+ 主会话不存在 */
	err[0] = '\0';
	OK(occ_task_create(db, s.id, "x", "{}", 4, NULL, err,
			   sizeof(err)) == -1 &&
	   strstr(err, "rework_max") != NULL, "task-create-rm-over");
	OK(occ_task_create(db, s.id, "x", "{}", 3, NULL, NULL, 0) == 0,
	   "task-create-rm3-ok");
	err[0] = '\0';
	OK(occ_task_create(db, "ses_nope", "x", "{}", 0, NULL, err,
			   sizeof(err)) == -1 &&
	   strstr(err, "不存在") != NULL, "task-create-no-parent");

	/* 非法迁移：pending 起 review/verdict/escalate/distill 全拒 */
	err[0] = '\0';
	OK(occ_task_review(db, t.id, NULL, err, sizeof(err)) == -1 &&
	   strstr(err, "非法迁移") != NULL, "illegal-pending-review");
	err[0] = '\0';
	OK(occ_task_verdict(db, t.id, 1, NULL, err, sizeof(err)) == -1 &&
	   strstr(err, "非法迁移") != NULL, "illegal-pending-verdict");
	err[0] = '\0';
	OK(occ_task_escalate(db, t.id, NULL, err, sizeof(err)) == -1 &&
	   strstr(err, "非法迁移") != NULL, "illegal-pending-escalate");
	err[0] = '\0';
	OK(occ_task_distill(db, t.id, NULL, err, sizeof(err)) == -1 &&
	   strstr(err, "非法迁移") != NULL, "illegal-pending-distill");

	/* 派发：pending→dispatched；child_session 填；事件 dispatch */
	OK(occ_task_dispatch(db, t.id, s2.id, err, sizeof(err)) == 0,
	   "dispatch-ok");
	OK(occ_task_get(db, t.id, &t2, err, sizeof(err)) == 1 &&
	   !strcmp(t2.status, OCC_TASK_ST_DISPATCHED) &&
	   !strcmp(t2.child_session, s2.id), "dispatch-state-child");

	/* 非法迁移：dispatched 起 verdict/distill 拒 */
	err[0] = '\0';
	OK(occ_task_verdict(db, t.id, 1, NULL, err, sizeof(err)) == -1 &&
	   strstr(err, "非法迁移") != NULL, "illegal-dispatched-verdict");
	err[0] = '\0';
	OK(occ_task_distill(db, t.id, NULL, err, sizeof(err)) == -1,
	   "illegal-dispatched-distill");

	/* 回炉环（rework_max=2 缺省）：一拒一改一拒→第三次超限升级 */
	OK(occ_task_review(db, t.id, "报告v1", err, sizeof(err)) == 0,
	   "review-1");
	OK(occ_task_get(db, t.id, &t2, err, sizeof(err)) == 1 &&
	   !strcmp(t2.status, OCC_TASK_ST_IN_REVIEW), "review-state");
	/* in_review 起 dispatch 拒 */
	err[0] = '\0';
	OK(occ_task_dispatch(db, t.id, NULL, err, sizeof(err)) == -1 &&
	   strstr(err, "非法迁移") != NULL, "illegal-inreview-dispatch");
	/* 失败 #1：0+1=1 ≤ 2 → rework */
	OK(occ_task_verdict(db, t.id, 0, "{\"gap\":\"少自检输出\"}", err,
			    sizeof(err)) == 0, "verdict-fail-1");
	OK(occ_task_get(db, t.id, &t2, err, sizeof(err)) == 1 &&
	   !strcmp(t2.status, OCC_TASK_ST_REWORK) &&
	   t2.rework_count == 1 && t2.verdict_json &&
	   strstr(t2.verdict_json, "少自检输出") != NULL,
	   "rework-state-count1");
	/* 回炉再派：rework→dispatched；child 不传=沿用 */
	OK(occ_task_dispatch(db, t.id, NULL, err, sizeof(err)) == 0,
	   "redispatch-ok");
	OK(occ_task_get(db, t.id, &t2, err, sizeof(err)) == 1 &&
	   !strcmp(t2.status, OCC_TASK_ST_DISPATCHED) &&
	   !strcmp(t2.child_session, s2.id), "redispatch-child-kept");
	/* 失败 #2：1+1=2 ≤ 2 → rework（最后一次机会） */
	OK(occ_task_review(db, t.id, "报告v2", err, sizeof(err)) == 0 &&
	   occ_task_verdict(db, t.id, 0, "{\"gap\":\"仍差证据\"}", err,
			    sizeof(err)) == 0, "verdict-fail-2");
	OK(occ_task_get(db, t.id, &t2, err, sizeof(err)) == 1 &&
	   !strcmp(t2.status, OCC_TASK_ST_REWORK) &&
	   t2.rework_count == 2, "rework-state-count2");
	/* 失败 #3：2+1=3 > 2 → 自动 escalated（超限上抛） */
	OK(occ_task_dispatch(db, t.id, NULL, err, sizeof(err)) == 0 &&
	   occ_task_review(db, t.id, "报告v3", err, sizeof(err)) == 0 &&
	   occ_task_verdict(db, t.id, 0, "{\"gap\":\"超限\"}", err,
			    sizeof(err)) == 0, "verdict-fail-3");
	OK(occ_task_get(db, t.id, &t2, err, sizeof(err)) == 1 &&
	   !strcmp(t2.status, OCC_TASK_ST_ESCALATED) &&
	   t2.rework_count == 3, "escalated-auto");
	/* 终态起一切拒 */
	err[0] = '\0';
	OK(occ_task_dispatch(db, t.id, NULL, err, sizeof(err)) == -1 &&
	   strstr(err, "非法迁移") != NULL, "illegal-escalated-dispatch");
	err[0] = '\0';
	OK(occ_task_review(db, t.id, NULL, err, sizeof(err)) == -1,
	   "illegal-escalated-review");
	err[0] = '\0';
	OK(occ_task_distill(db, t.id, NULL, err, sizeof(err)) == -1,
	   "illegal-escalated-distill");

	/* 事件审计：与动作序列逐一对应（D）——12 事件：
	 * dispatch,result,verdict,rework, dispatch,result,verdict,rework,
	 * dispatch,result,verdict,escalate（每拒=verdict+rework 双事件，
	 * 超限拒=verdict+escalate；verdict 先、副事件后） */
	OK(occ_task_events(db, t.id, &evs, &n, err, sizeof(err)) == 0 &&
	   n == 12, "events-count-12");
	if (n == 12) {
		static const char *exp[] = {
			"dispatch", "result", "verdict", "rework",
			"dispatch", "result", "verdict", "rework",
			"dispatch", "result", "verdict", "escalate"
		};
		int seq_ok = 1;

		for (i = 0; i < n; i++)
			if (strcmp(evs[i].kind, exp[i])) {
				seq_ok = 0;
				break;
			}
		OK(seq_ok, "events-sequence");
		OK(evs[0].payload_json &&
		   !strcmp(evs[0].payload_json, s2.id),
		   "event-dispatch-payload-child");
		OK(evs[2].payload_json &&
		   strstr(evs[2].payload_json, "少自检输出") != NULL,
		   "event-verdict-payload");
	} else {
		OK(0, "events-sequence");
		OK(0, "event-dispatch-payload-child");
		OK(0, "event-verdict-payload");
	}
	occ_task_event_rows_free(evs, n);
	evs = NULL;

	/* 一过路径 + distill（B） */
	OK(occ_task_create(db, s.id, "文档任务",
			   "{\"goal\":\"写 README 片段\"}", 1, &t2,
			   err, sizeof(err)) == 0 && t2.rework_max == 1,
	   "task2-create-rm1");
	OK(occ_task_dispatch(db, t2.id, s2.id, err, sizeof(err)) == 0 &&
	   occ_task_review(db, t2.id, "报告ok", err, sizeof(err)) == 0 &&
	   occ_task_verdict(db, t2.id, 1, "{\"pass\":true}", err,
			    sizeof(err)) == 0, "task2-once-pass");
	OK(occ_task_get(db, t2.id, &t2, err, sizeof(err)) == 1 &&
	   !strcmp(t2.status, OCC_TASK_ST_DONE) &&
	   t2.rework_count == 0 && t2.verdict_json &&
	   strstr(t2.verdict_json, "\"pass\":true") != NULL, "task2-done");
	/* done 起动作全拒（终态）；distill 例外（审计事件） */
	err[0] = '\0';
	OK(occ_task_review(db, t2.id, NULL, err, sizeof(err)) == -1 &&
	   strstr(err, "非法迁移") != NULL, "illegal-done-review");
	err[0] = '\0';
	OK(occ_task_escalate(db, t2.id, NULL, err, sizeof(err)) == -1,
	   "illegal-done-escalate");
	OK(occ_task_distill(db, t2.id, "返回摘要：3 行", err,
			    sizeof(err)) == 0, "distill-after-done");
	OK(occ_task_get(db, t2.id, &t2, err, sizeof(err)) == 1 &&
	   !strcmp(t2.status, OCC_TASK_ST_DONE), "distill-keeps-done");
	OK(occ_task_events(db, t2.id, &evs, &n, err, sizeof(err)) == 0 &&
	   n == 5 && !strcmp(evs[3].kind, "done") &&
	   !strcmp(evs[4].kind, "distill") &&
	   evs[4].payload_json &&
	   strstr(evs[4].payload_json, "返回摘要") != NULL,
	   "distill-event");
	occ_task_event_rows_free(evs, n);
	evs = NULL;

	/* 手动上抛：dispatched → escalated（裁判可主动放弃） */
	OK(occ_task_create(db, s.id, "放弃任务", "{}", 0, &t2,
			   err, sizeof(err)) == 0 &&
	   occ_task_dispatch(db, t2.id, NULL, err, sizeof(err)) == 0,
	   "task3-create-dispatch");
	OK(occ_task_escalate(db, t2.id, "{\"why\":\"子进程崩溃\"}", err,
			    sizeof(err)) == 0 &&
	   occ_task_get(db, t2.id, &t2, err, sizeof(err)) == 1 &&
	   !strcmp(t2.status, OCC_TASK_ST_ESCALATED), "escalate-manual");

	/* 列表（B） */
	occ_task_rows_free(tl, n);
	tl = NULL;
	n = 0;
	OK(occ_task_list(db, s.id, &tl, &n, err, sizeof(err)) == 0 &&
	   n == 4, "list-by-parent-4");
	occ_task_rows_free(tl, n);
	tl = NULL;
	OK(occ_task_list(db, NULL, &tl, &n, err, sizeof(err)) == 0 &&
	   n == 4, "list-all-4");
	occ_task_rows_free(tl, n);
	tl = NULL;
	OK(occ_task_list(db, s2.id, &tl, &n, err, sizeof(err)) == 0 &&
	   n == 0 && tl == NULL, "list-other-parent-0");
	(void)tl;

	/* 不存在任务的动作：-1 人话 */
	err[0] = '\0';
	OK(occ_task_dispatch(db, "tsk_nope", NULL, err, sizeof(err)) == -1 &&
	   strstr(err, "不存在") != NULL, "dispatch-no-task");

	/* ---- F) /clear 库面：occ_session_archive ---- */
	{
		occ_session_row sc;
		char vbuf[192];
		char wout[64];		/* 独立出参：sqlite3_prepare_v2(-1)
					 * 后语句仍引用 SQL 原文——出参
					 * 不得与 SQL 缓冲别名（探针实证） */

		OK(occ_session_create(db, "glm-5.3", &sc, err,
				      sizeof(err)) == 0, "arc-session-create");
		OK(occ_msg_add_user(db, sc.id, "会被归档的问题", mid,
				    sizeof(mid), err, sizeof(err)) == 0 &&
		   occ_msg_add_assistant(db, sc.id, "会被归档的回答", NULL,
					 NULL, 0, NULL, 0, "stop", NULL, 0,
					 err, sizeof(err)) == 0,
		   "arc-msgs-add");
		/* 先换 digest 窗（T9d）再归档——断言窗口被拉回 native */
		OK(occ_session_set_window_digest(db, sc.id, mid, err,
						 sizeof(err)) == 0,
		   "arc-window-digest");
		snprintf(vbuf, sizeof(vbuf),
			 "SELECT base_kind FROM occ_window WHERE"
			 " session_id='%s'", sc.id);
		OK(sql_str(dbpath_of("new.db"), vbuf, wout,
			   sizeof(wout)) == 0 && !strcmp(wout, "digest"),
		   "arc-window-was-digest");
		OK(occ_session_archive(db, sc.id, err, sizeof(err)) == 0,
		   "archive-ok");
		OK(occ_session_get(db, sc.id, &s2, err, sizeof(err)) == 1 &&
		   !strcmp(s2.status, OCC_ST_ARCHIVED),
		   "archive-status");
		/* 归档≠删除：消息原地可查回 */
		OK(occ_msg_list(db, sc.id, &msgs, &n, err, sizeof(err)) == 0 &&
		   n == 2 && msgs && msgs[0].text &&
		   !strcmp(msgs[0].text, "会被归档的问题"),
		   "archive-msgs-retrievable");
		occ_msg_rows_free(msgs, n);
		msgs = NULL;
		/* 窗口回 native 空基线 */
		snprintf(vbuf, sizeof(vbuf),
			 "SELECT base_kind||'/'||COALESCE(digest_id,'-')"
			 " FROM occ_window WHERE session_id='%s'", sc.id);
		OK(sql_str(dbpath_of("new.db"), vbuf, wout,
			   sizeof(wout)) == 0 && !strcmp(wout, "native/-"),
		   "archive-window-native");
		/* 幂等：重复归档无害 */
		OK(occ_session_archive(db, sc.id, err, sizeof(err)) == 0,
		   "archive-idempotent");
		/* 不存在：-1 人话 */
		err[0] = '\0';
		OK(occ_session_archive(db, "ses_nope", err, sizeof(err)) ==
		   -1 && strstr(err, "不存在") != NULL,
		   "archive-nonexist");
	}

	/* ---- G) E7 预算记账 API：基线事件/单事务累加/审计事件 ---- */
	{
		char vq[320];
		int nbud = 0;

		err[0] = '\0';
		OK(occ_task_create(db, s.id, "记账任务", "{\"goal\":\"E7\"}",
				   0, &t, err, sizeof(err)) == 0,
		   "budget-task-create");
		/* 基线：只落 kind='budget' 事件，任务行两列不动 */
		err[0] = '\0';
		OK(occ_task_budget_baseline(db, t.id, 5000, err,
					    sizeof(err)) == 0,
		   "budget-baseline-ok");
		OK(occ_task_get(db, t.id, &t2, err, sizeof(err)) == 1 &&
		   t2.budget_in == 0 && t2.budget_out == 0,
		   "budget-baseline-cols-zero");
		/* 基线坏参：max_tokens<=0 拒绝 */
		err[0] = '\0';
		OK(occ_task_budget_baseline(db, t.id, 0, err,
					    sizeof(err)) == -1 &&
		   strstr(err, "bad args") != NULL,
		   "budget-baseline-badargs");
		/* 累加两拍：100/200 真值 + 50/0 估算 → 150/200 */
		err[0] = '\0';
		OK(occ_task_budget_add(db, t.id, 100, 200, 0, err,
				       sizeof(err)) == 0, "budget-add-1-ok");
		err[0] = '\0';
		OK(occ_task_budget_add(db, t.id, 50, 0, 1, err,
				       sizeof(err)) == 0, "budget-add-2-ok");
		OK(occ_task_get(db, t.id, &t2, err, sizeof(err)) == 1 &&
		   t2.budget_in == 150 && t2.budget_out == 200,
		   "budget-add-accum-150-200");
		/* 负 delta 钳 0（账本单调） */
		err[0] = '\0';
		OK(occ_task_budget_add(db, t.id, -999, -1, 0, err,
				       sizeof(err)) == 0 &&
		   occ_task_get(db, t.id, &t2, err, sizeof(err)) == 1 &&
		   t2.budget_in == 150 && t2.budget_out == 200,
		   "budget-add-negative-clamped");
		/* 审计：kind='budget' 三行（1 基线+2 记账），src 标注对齐 */
		occ_task_row_free(&t2);
		nbud = 0;
		if (occ_task_events(db, t.id, &evs, &n, NULL, 0) == 0) {
			int nbase = 0, nusage = 0, nest = 0;

			for (i = 0; i < n; i++) {
				if (strcmp(evs[i].kind, OCC_TASK_EV_BUDGET))
					continue;
				nbud++;
				if (strstr(evs[i].payload_json,
					   "\"phase\":\"baseline\"") &&
				    strstr(evs[i].payload_json,
					   "\"max_tokens\":5000"))
					nbase = 1;
				if (strstr(evs[i].payload_json,
					   "\"in\":100") &&
				    strstr(evs[i].payload_json,
					   "\"out\":200") &&
				    strstr(evs[i].payload_json,
					   "\"src\":\"usage\""))
					nusage = 1;
				if (strstr(evs[i].payload_json,
					   "\"in\":50") &&
				    strstr(evs[i].payload_json,
					   "\"src\":\"estimated\""))
					nest = 1;
			}
			occ_task_event_rows_free(evs, n);
			evs = NULL;
			n = 0;
			OK(nbud == 3, "budget-events-count-3");
			OK(nbase, "budget-event-baseline-payload");
			OK(nusage, "budget-event-usage-src");
			OK(nest, "budget-event-estimated-src");
		} else {
			OK(0, "budget-events-read");
		}
		/* 独立连接直查（外部验证口径） */
		snprintf(vq, sizeof(vq),
			 "SELECT budget_in||'/'||budget_out FROM occ_task"
			 " WHERE id='%s'", t.id);
		{
			char vb[48] = "";

			sql_str(dbpath_of("new.db"), vq, vb, sizeof(vb));
			OK(!strcmp(vb, "150/200"), "budget-cols-sqlite-view");
		}
		/* 不存在任务：-1 */
		err[0] = '\0';
		OK(occ_task_budget_add(db, "tsk_nope", 1, 1, 0, err,
				       sizeof(err)) == -1 &&
		   strstr(err, "不存在") != NULL,
		   "budget-add-nonexist");
		err[0] = '\0';
		OK(occ_task_budget_baseline(db, "tsk_nope", 100, err,
					    sizeof(err)) == -1,
		   "budget-baseline-nonexist");
	}

	occ_db_close(db);

	/* ---- A) v2→v3 前向迁移（老库不丢数据） ---- */
	build_v2_db(dbpath_of("v2.db"));
	OK(sql_int(dbpath_of("v2.db"), "PRAGMA user_version") == 2,
	   "v2-fixture-version");
	db = occ_db_open(dbpath_of("v2.db"), err, sizeof(err));
	OK(db != NULL, "v2-migrate-open");
	OK(sql_int(dbpath_of("v2.db"), "PRAGMA user_version") == 4,
	   "v2-migrate-version-4");
	OK(sql_int(dbpath_of("v2.db"),
		   "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
		   " AND name='occ_task'") == 1, "v2-migrate-task-table");
	OK(sql_int(dbpath_of("v2.db"),
		   "SELECT COUNT(*) FROM pragma_table_info('occ_session')"
		   " WHERE name='kind'") == 1, "v2-migrate-kind-col");
	/* 老行无损 + kind 补缺省 'main'（旧值兼容） */
	OK(occ_session_get(db, "ses_v2old", &s2, err, sizeof(err)) == 1 &&
	   !strcmp(s2.title, "v2 旧会话") && s2.tokens_total == 9 &&
	   !strcmp(s2.model, "old-model") &&
	   !strcmp(s2.workdir, "/tmp/wd") &&
	   !strcmp(s2.kind, OCC_SK_MAIN), "v2-migrate-old-session");
	OK(occ_msg_list(db, "ses_v2old", &msgs, &n, err, sizeof(err)) == 0 &&
	   n == 2 && msgs && msgs[1].text &&
	   !strcmp(msgs[1].text, "v2 老回复") && msgs[1].reverted == 0,
	   "v2-migrate-old-msgs");
	occ_msg_rows_free(msgs, n);
	msgs = NULL;
	{
		char kb[32];

		OK(sql_str(dbpath_of("v2.db"),
			   "SELECT kind FROM occ_session WHERE"
			   " id='ses_v2old'", kb, sizeof(kb)) == 0 &&
		   !strcmp(kb, "main"), "v2-migrate-kind-main");
	}
	/* 迁移后老库上任务面可用 */
	OK(occ_task_create(db, "ses_v2old", "迁移后任务", "{}", 0, &t,
			   err, sizeof(err)) == 0 &&
	   occ_task_dispatch(db, t.id, NULL, err, sizeof(err)) == 0,
	   "v2-migrate-task-usable");

	/* ---- A) v3 重复打开幂等（零副作用） ---- */
	{
		int tasks_before = sql_int(dbpath_of("v2.db"),
					   "SELECT COUNT(*) FROM occ_task");
		int evs_before = sql_int(dbpath_of("v2.db"),
					 "SELECT COUNT(*) FROM"
					 " occ_task_event");
		int i2;

		occ_db_close(db);
		for (i2 = 0; i2 < 2; i2++) {
			db = occ_db_open(dbpath_of("v2.db"), err, sizeof(err));
			OK(db != NULL, "v3-reopen-again");
			occ_db_close(db);
		}
		db = occ_db_open(dbpath_of("v2.db"), err, sizeof(err));
		OK(sql_int(dbpath_of("v2.db"), "PRAGMA user_version") == 4,
		   "v3-reopen-version-kept");
		OK(sql_int(dbpath_of("v2.db"),
			   "SELECT COUNT(*) FROM occ_task") == tasks_before,
		   "v3-reopen-tasks-unchanged");
		OK(sql_int(dbpath_of("v2.db"),
			   "SELECT COUNT(*) FROM occ_task_event") ==
		   evs_before, "v3-reopen-events-unchanged");
	}
	occ_db_close(db);

	{
		char cmd[192];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
		if (system(cmd)) {
			/* 清理失败不影响判定 */
		}
	}

	printf("test_task: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
