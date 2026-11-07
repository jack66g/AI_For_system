/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_revert.c - T9b2 /undo 三段式单测（OCD §7.3 headless 形态）
 *
 * 覆盖：
 *   A) schema v1→v2 迁移：旧库（user_version=1、无 reverted/workdir/
 *      occ_revert）经 occ_db_open 无损升级，旧行可读
 *   B) undo 主链：文件回滚（快照）+ 消息隐藏 + 注记落库 + stage 行 +
 *      user 文本回填；redo 还原（文件/解隐藏/删注记/删 stage）；再
 *      undo → commit（stage 清除、消息保持隐藏、redo 不可用）
 *   C) 两步深撤叠加：--step 从现边界再往深处数；undo#2 后 redo 一步
 *      回到首次撤销前现状（_redo 不被叠加覆盖）
 *   D) ABSENT 墓碑：新建文件撤销=删除；redo 恢复
 *   E) status=running 拒绝 undo（不改库）
 *   F) 纯对话轮（无文件快照）拒绝 undo（不改库——设计 §9-2 约束）
 *   G) bash 无快照 → nskipped 如实计数（不谎称全量回滚）
 *   H) 幂等/边界：无 stage 的 commit 无操作；无 stage 的 redo 报错
 *
 * 夹具全在 /tmp/occ_rev_t_*（授权范围）；快照根/trace 经 OCC_SNAPROOT/
 * OCC_TRACE_DIR 重定向；write走真工具链（真快照+真 durable 落库）。
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sqlite3.h>

#include "occ_core/occ_revert.h"
#include "occ_tools/occ_tools.h"

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; printf("ok %s\n", name); } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

static char tmpdir[128];
static char workdir[160];

static char *dbpath_of(const char *name)
{
	static char p[256];

	snprintf(p, sizeof(p), "%s/%s", tmpdir, name);
	return p;
}

static void wfile(const char *path, const char *body)
{
	FILE *f = fopen(path, "wb");

	if (f) {
		fputs(body, f);
		fclose(f);
	}
}

static char *rfile(const char *path)
{
	static char buf[4096];
	FILE *f = fopen(path, "rb");
	size_t n;

	if (!f)
		return NULL;
	n = fread(buf, 1, sizeof(buf) - 1, f);
	buf[n] = '\0';
	fclose(f);
	return buf;
}

static int fexists(const char *path)
{
	return !access(path, F_OK);
}

/* 直连 sqlite 计数（独立连接=外部观察者视角） */
static long long sql_count(const char *dbfile, const char *sql,
			   const char *bind)
{
	sqlite3 *h;
	sqlite3_stmt *st;
	long long v = -1;

	if (sqlite3_open_v2(dbfile, &h, SQLITE_OPEN_READONLY, NULL) !=
	    SQLITE_OK)
		return -1;
	if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK) {
		if (bind)
			sqlite3_bind_text(st, 1, bind, -1, SQLITE_TRANSIENT);
		if (sqlite3_step(st) == SQLITE_ROW)
			v = sqlite3_column_int64(st, 0);
		sqlite3_finalize(st);
	}
	sqlite3_close(h);
	return v;
}

static long long sql_int(const char *dbfile, const char *sql)
{
	return sql_count(dbfile, sql, NULL);
}

/* ---- 会话/回合构造助手 ---- */

/* 一轮：user → assistant(toolCall write) → 真执行 → assistant 收口。
 * 返回 0 成功。 */
static int make_write_turn(occ_db *db, const char *sid, const char *prompt,
			   const char *path, const char *content,
			   char *user_id, char *err, size_t errlen)
{
	occ_tool_ctx tc;
	occ_tool_result tr;
	occ_tool_call call;
	char asst1[OCC_ID_LEN], asst2[OCC_ID_LEN];
	char args[1024];
	char cwd[160];
	int rc = -1;

	if (user_id)
		user_id[0] = '\0';
	if (occ_msg_add_user(db, sid, prompt, user_id, OCC_ID_LEN, err,
			     errlen))
		return -1;
	memset(&call, 0, sizeof(call));
	snprintf(args, sizeof(args),
		 "{\"path\":\"%s\",\"content\":\"%s\"}", path, content);
	call.id = "call_w";
	call.name = "write";
	call.arguments = args;
	if (occ_msg_add_assistant_ex(db, sid, "", NULL, &call, 1, NULL, 0,
				     "tool_calls", 1, asst1, sizeof(asst1),
				     err, errlen))
		return -1;
	memset(&tc, 0, sizeof(tc));
	memset(&tr, 0, sizeof(tr));
	tc.db = db;
	tc.session_id = sid;
	tc.msg_id = asst1;
	snprintf(cwd, sizeof(cwd), "%s", workdir);
	tc.workdir = cwd;
	tc.trace_dir = tmpdir;			/* 静默到 tmp */
	if (occ_tool_exec(&tc, "write", "call_w", args, &tr)) {
		occ_tool_result_free(&tr);
		return -1;
	}
	rc = tr.rc;
	occ_tool_result_free(&tr);
	if (rc)
		return -1;
	if (occ_msg_add_assistant_ex(db, sid, "已写入", NULL, NULL, 0, NULL,
				     0, "stop", 0, asst2, sizeof(asst2),
				     err, errlen))
		return -1;
	return 0;
}

/* ---- A) v1→v2 迁移 ---- */

/* 旧版（a3/b1）schema：无 reverted/workdir/occ_revert，user_version=1 */
static const char V1_DDL[] =
	"CREATE TABLE occ_session ("
	"  id TEXT PRIMARY KEY,"
	"  title TEXT NOT NULL DEFAULT '',"
	"  created INTEGER NOT NULL,"
	"  model TEXT NOT NULL DEFAULT '',"
	"  tokens_total INTEGER NOT NULL DEFAULT 0,"
	"  status TEXT NOT NULL DEFAULT 'active',"
	"  updated INTEGER NOT NULL DEFAULT 0,"
	"  tokens_est INTEGER NOT NULL DEFAULT 0"
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
	"  created INTEGER NOT NULL"
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
	"PRAGMA user_version=1;";

static void test_migration(void)
{
	const char *v1db = dbpath_of("v1.db");
	sqlite3 *h;
	char err[256] = "";
	occ_db *db;
	occ_session_row s;
	occ_msg_row *rows = NULL;
	size_t n = 0;

	if (sqlite3_open_v2(v1db, &h, SQLITE_OPEN_READWRITE |
			    SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
		OK(0, "mig-create-v1db");
		return;
	}
	if (sqlite3_exec(h, V1_DDL, NULL, NULL, NULL) != SQLITE_OK) {
		sqlite3_close(h);
		OK(0, "mig-v1-ddl");
		return;
	}
	sqlite3_exec(h,
		     "INSERT INTO occ_session VALUES"
		     " ('ses_v1old','旧标题',1700000000000,'old-model',7,"
		     "'active',1700000000000,0);"
		     "INSERT INTO occ_message VALUES"
		     " ('msg_v1old','ses_v1old','user',"
		     "'[{\"type\":\"text\",\"text\":\"旧消息\"}]',"
		     "NULL,NULL,NULL,NULL,0,'',1700000000000);",
		     NULL, NULL, NULL);
	sqlite3_close(h);

	db = occ_db_open(v1db, err, sizeof(err));
	OK(db != NULL, "mig-open");
	if (!db)
		return;
	/* 升级证据 */
	OK(sql_int(v1db, "PRAGMA user_version") == 2, "mig-user-version-2");
	OK(sql_count(v1db,
		     "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
		     " AND name='occ_revert'", NULL) == 1, "mig-revert-table");
	OK(sql_count(v1db,
		     "SELECT COUNT(*) FROM pragma_table_info('occ_message')"
		     " WHERE name='reverted'", NULL) == 1, "mig-msg-reverted");
	OK(sql_count(v1db,
		     "SELECT COUNT(*) FROM pragma_table_info('occ_session')"
		     " WHERE name='workdir'", NULL) == 1, "mig-session-workdir");
	/* 旧行无损可读 */
	OK(occ_session_get(db, "ses_v1old", &s, err, sizeof(err)) == 1,
	   "mig-old-session-read");
	OK(!strcmp(s.title, "旧标题") && s.tokens_total == 7 &&
	   !strcmp(s.model, "old-model"), "mig-old-session-fields");
	OK(occ_msg_list(db, "ses_v1old", &rows, &n, err, sizeof(err)) == 0 &&
	   n == 1 && rows && rows[0].text && !strcmp(rows[0].text, "旧消息") &&
	   rows[0].reverted == 0, "mig-old-message-read");
	occ_msg_rows_free(rows, n);
	occ_db_close(db);
}

/* ---- 主测试 ---- */

int main(void)
{
	char err[512] = "";
	occ_db *db;
	occ_session_row s;
	char sid1[OCC_ID_LEN], sid2[OCC_ID_LEN], sid3[OCC_ID_LEN];
	char sid4[OCC_ID_LEN], sid5[OCC_ID_LEN], sid6[OCC_ID_LEN];
	char user1[OCC_ID_LEN];
	occ_undo_result r;
	occ_revert_row st;
	char f1[192], f2[192], f3[192], f6[192];

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/occ_rev_t_%d", (int)getpid());
	snprintf(workdir, sizeof(workdir), "%s/wd", tmpdir);
	mkdir(tmpdir, 0755);
	mkdir(workdir, 0755);
	/* 快照根/trace 重定向（授权夹具范围） */
	setenv("OCC_SNAPROOT", dbpath_of("snapshots"), 1);
	setenv("OCC_TRACE_DIR", tmpdir, 1);

	test_migration();

	db = occ_db_open(dbpath_of("sessions.db"), err, sizeof(err));
	OK(db != NULL, "db-open");
	if (!db)
		goto out;

	/* ---- B) undo 主链 ---- */
	OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0, "s1-create");
	snprintf(sid1, sizeof(sid1), "%s", s.id);
	OK(occ_session_set_workdir(db, sid1, workdir, err, sizeof(err)) == 0,
	   "s1-workdir");
	snprintf(f1, sizeof(f1), "%s/f1.txt", workdir);
	wfile(f1, "V1");
	OK(make_write_turn(db, sid1, "第一步：把 f1 改成 V2", f1, "V2",
			   user1, err, sizeof(err)) == 0, "s1-turn1");
	OK(!strcmp(rfile(f1), "V2"), "s1-after-turn-v2");

	memset(&r, 0, sizeof(r));
	OK(occ_undo(db, sid1, 1, NULL, &r, err, sizeof(err)) == 0,
	   "s1-undo-rc");
	OK(!strcmp(rfile(f1), "V1"), "s1-undo-restored-v1");
	OK(r.nmsgs_reverted == 4, "s1-undo-hidden-4");
	OK(r.nfiles == 1 && r.files[0].action == OCC_UNDO_RESTORE &&
	   !r.files[0].failed && !strcmp(r.files[0].path, f1),
	   "s1-undo-file-entry");
	OK(r.nskipped == 0, "s1-undo-no-skip");
	OK(r.user_text && strstr(r.user_text, "第一步"), "s1-undo-user-text");
	OK(!strncmp(r.boundary_user_msg, "msg_", 4) &&
	   !strcmp(r.boundary_user_msg, user1), "s1-undo-boundary");
	OK(!strncmp(r.note_msg, "msg_", 4), "s1-undo-note-id");
	/* 库态：stage 行 + 注记 + 全隐藏 + 尾态不可见 */
	OK(occ_revert_get(db, sid1, &st, err, sizeof(err)) == 1,
	   "s1-stage-row");
	OK(st.boundary_msg[0] && !strcmp(st.boundary_msg, user1),
	   "s1-stage-boundary");
	occ_revert_row_free(&st);
	OK(sql_count(dbpath_of("sessions.db"),
		     "SELECT COUNT(*) FROM occ_message WHERE session_id=?1"
		     " AND role='system'", sid1) == 1, "s1-note-row");
	{
		occ_msg_row last;
		int has = occ_msg_last(db, sid1, &last, err, sizeof(err));

		/* 被撤消息不可见；唯一可见的允许是 undo 注记（system，
		 * 待下一条 user 折叠） */
		OK(has == 0 || !strcmp(last.role, "system"),
		   "s1-tail-invisible");
		occ_msg_row_free(&last);
	}
	/* 注记人话含撤销语义（下轮模型可读） */
	OK(sql_count(dbpath_of("sessions.db"),
		     "SELECT COUNT(*) FROM occ_message WHERE"
		     " session_id=?1 AND role='system' AND"
		     " content_json LIKE '%撤销%'", sid1) == 1,
	   "s1-note-content");

	/* redo：文件/消息/注记/stage 全还原 */
	memset(&r, 0, sizeof(r));
	OK(occ_redo(db, sid1, NULL, &r, err, sizeof(err)) == 0, "s1-redo-rc");
	OK(!strcmp(rfile(f1), "V2"), "s1-redo-restored-v2");
	OK(occ_revert_get(db, sid1, &st, err, sizeof(err)) == 0,
	   "s1-redo-stage-gone");
	OK(sql_count(dbpath_of("sessions.db"),
		     "SELECT COUNT(*) FROM occ_message WHERE session_id=?1"
		     " AND role='system'", sid1) == 0, "s1-redo-note-gone");
	{
		occ_msg_row last;

		OK(occ_msg_last(db, sid1, &last, err, sizeof(err)) == 1 &&
		   !strcmp(last.role, "assistant"), "s1-redo-tail-visible");
		occ_msg_row_free(&last);
	}
	occ_undo_result_free(&r);

	/* 再 undo → commit（用户重发即认）：stage 清、消息保持隐藏、
	 * 文件保持回滚态、redo 不可用 */
	memset(&r, 0, sizeof(r));
	OK(occ_undo(db, sid1, 1, NULL, &r, err, sizeof(err)) == 0,
	   "s1-undo2-rc");
	OK(!strcmp(rfile(f1), "V1"), "s1-undo2-v1");
	occ_undo_result_free(&r);
	occ_revert_commit(db, sid1, NULL);		/* 幂等路径 */
	OK(occ_revert_get(db, sid1, &st, err, sizeof(err)) == 0,
	   "s1-commit-stage-gone");
	OK(!strcmp(rfile(f1), "V1"), "s1-commit-file-stays-v1");
	{
		occ_msg_row last;
		int has = occ_msg_last(db, sid1, &last, err, sizeof(err));

		OK(has == 0 || !strcmp(last.role, "system"),
		   "s1-commit-hidden-stays");
		occ_msg_row_free(&last);
	}
	memset(&r, 0, sizeof(r));
	OK(occ_redo(db, sid1, NULL, &r, err, sizeof(err)) == -1 &&
	   strstr(err, "stage"), "s1-redo-after-commit-rejected");
	occ_undo_result_free(&r);

	/* ---- C) 两步深撤叠加 + redo 一步回首次撤销前 ---- */
	OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0, "s2-create");
	snprintf(sid2, sizeof(sid2), "%s", s.id);
	occ_session_set_workdir(db, sid2, workdir, err, sizeof(err));
	snprintf(f2, sizeof(f2), "%s/f2.txt", workdir);
	wfile(f2, "A");
	OK(make_write_turn(db, sid2, "回合1：A→B", f2, "B", NULL, err,
			   sizeof(err)) == 0, "s2-turn1");
	OK(make_write_turn(db, sid2, "回合2：B→C", f2, "C", NULL, err,
			   sizeof(err)) == 0, "s2-turn2");
	OK(!strcmp(rfile(f2), "C"), "s2-after-turns-c");

	memset(&r, 0, sizeof(r));
	OK(occ_undo(db, sid2, 1, NULL, &r, err, sizeof(err)) == 0,
	   "s2-undo1");
	OK(!strcmp(rfile(f2), "B"), "s2-undo1-restores-b");
	OK(r.nmsgs_reverted == 4, "s2-undo1-hidden-4");
	occ_undo_result_free(&r);

	memset(&r, 0, sizeof(r));
	OK(occ_undo(db, sid2, 1, NULL, &r, err, sizeof(err)) == 0,
	   "s2-undo2-deeper");
	OK(!strcmp(rfile(f2), "A"), "s2-undo2-restores-a");
	OK(r.nmsgs_reverted == 4, "s2-undo2-newly-hidden-4");
	OK(r.nfiles == 1, "s2-undo2-files-1");
	occ_undo_result_free(&r);
	/* 第三步：无可撤 user（全部隐藏）→ 人话拒绝、不改库 */
	memset(&r, 0, sizeof(r));
	OK(occ_undo(db, sid2, 1, NULL, &r, err, sizeof(err)) == -1 &&
	   strstr(err, "可撤销"), "s2-undo3-nothing");
	occ_undo_result_free(&r);
	/* redo：一步回到首次撤销前（_redo 保留 undo#1 捕获的 C） */
	memset(&r, 0, sizeof(r));
	OK(occ_redo(db, sid2, NULL, &r, err, sizeof(err)) == 0, "s2-redo");
	OK(!strcmp(rfile(f2), "C"), "s2-redo-back-to-c");
	{
		occ_msg_row last;

		OK(occ_msg_last(db, sid2, &last, err, sizeof(err)) == 1,
		   "s2-redo-all-visible");
		occ_msg_row_free(&last);
	}
	occ_undo_result_free(&r);

	/* ---- D) ABSENT 墓碑：新建文件撤销=删除 ---- */
	OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0, "s3-create");
	snprintf(sid3, sizeof(sid3), "%s", s.id);
	occ_session_set_workdir(db, sid3, workdir, err, sizeof(err));
	snprintf(f3, sizeof(f3), "%s/new3.txt", workdir);
	OK(!fexists(f3), "s3-before-absent");
	OK(make_write_turn(db, sid3, "新建 new3.txt", f3, "NEW", NULL, err,
			   sizeof(err)) == 0, "s3-turn");
	OK(fexists(f3), "s3-created");
	memset(&r, 0, sizeof(r));
	OK(occ_undo(db, sid3, 1, NULL, &r, err, sizeof(err)) == 0, "s3-undo");
	OK(!fexists(f3), "s3-undo-deletes");
	OK(r.nfiles == 1 && r.files[0].action == OCC_UNDO_DELETE,
	   "s3-delete-action");
	occ_undo_result_free(&r);
	memset(&r, 0, sizeof(r));
	OK(occ_redo(db, sid3, NULL, &r, err, sizeof(err)) == 0, "s3-redo");
	OK(fexists(f3) && !strcmp(rfile(f3), "NEW"), "s3-redo-recreates");
	occ_undo_result_free(&r);

	/* ---- E) status=running 拒绝（不改库） ---- */
	OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0, "s4-create");
	snprintf(sid4, sizeof(sid4), "%s", s.id);
	OK(occ_msg_add_user(db, sid4, "在跑的回合", NULL, 0, err,
			    sizeof(err)) == 0, "s4-add-user-running");
	memset(&r, 0, sizeof(r));
	OK(occ_undo(db, sid4, 1, NULL, &r, err, sizeof(err)) == -1 &&
	   strstr(err, "running"), "s4-undo-running-rejected");
	OK(occ_revert_get(db, sid4, &st, err, sizeof(err)) == 0,
	   "s4-no-stage-written");
	{
		occ_msg_row last;

		OK(occ_msg_last(db, sid4, &last, err, sizeof(err)) == 1 &&
		   !last.reverted, "s4-not-hidden");
		occ_msg_row_free(&last);
	}
	occ_undo_result_free(&r);

	/* ---- F) 纯对话轮（无文件快照）拒绝（不改库） ---- */
	OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0, "s5-create");
	snprintf(sid5, sizeof(sid5), "%s", s.id);
	OK(occ_msg_add_user(db, sid5, "纯聊天问题", NULL, 0, err,
			    sizeof(err)) == 0, "s5-user");
	{
		char mid[OCC_ID_LEN];

		OK(occ_msg_add_assistant_ex(db, sid5, "纯聊天回答", NULL,
					     NULL, 0, NULL, 0, "stop", 0, mid,
					     sizeof(mid), err,
					     sizeof(err)) == 0, "s5-asst");
	}
	memset(&r, 0, sizeof(r));
	OK(occ_undo(db, sid5, 1, NULL, &r, err, sizeof(err)) == -1 &&
	   strstr(err, "快照"), "s5-pure-chat-rejected");
	{
		occ_msg_row last;

		OK(occ_msg_last(db, sid5, &last, err, sizeof(err)) == 1 &&
		   !last.reverted, "s5-not-hidden");
		occ_msg_row_free(&last);
	}
	occ_undo_result_free(&r);

	/* ---- G) bash 无快照 → nskipped 如实计数 ---- */
	OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0, "s6-create");
	snprintf(sid6, sizeof(sid6), "%s", s.id);
	occ_session_set_workdir(db, sid6, workdir, err, sizeof(err));
	snprintf(f6, sizeof(f6), "%s/f6.txt", workdir);
	wfile(f6, "X");
	{
		/* 手工构造：user + assistant[write, bash] + 执行 write +
		 * 记录 bash + 收口 */
		char uid[OCC_ID_LEN], a1[OCC_ID_LEN], a2[OCC_ID_LEN];
		char args[1024];
		occ_tool_call calls[2];
		occ_tool_ctx tc;
		occ_tool_result tr;

		OK(occ_msg_add_user(db, sid6, "写文件并跑命令", uid,
				    sizeof(uid), err, sizeof(err)) == 0,
		   "s6-user");
		memset(calls, 0, sizeof(calls));
		snprintf(args, sizeof(args),
			 "{\"path\":\"%s\",\"content\":\"Y\"}", f6);
		calls[0].id = "call_w6";
		calls[0].name = "write";
		calls[0].arguments = args;
		calls[1].id = "call_b6";
		calls[1].name = "bash";
		calls[1].arguments = "{\"command\":\"echo hi\"}";
		OK(occ_msg_add_assistant_ex(db, sid6, "", NULL, calls, 2,
					     NULL, 0, "tool_calls", 1, a1,
					     sizeof(a1), err,
					     sizeof(err)) == 0, "s6-asst-calls");
		memset(&tc, 0, sizeof(tc));
		tc.db = db;
		tc.session_id = sid6;
		tc.msg_id = a1;
		tc.workdir = workdir;
		tc.trace_dir = tmpdir;
		OK(occ_tool_exec(&tc, "write", "call_w6", args, &tr) == 0 &&
		   tr.rc == 0, "s6-write-exec");
		occ_tool_result_free(&tr);
		/* bash 行：只落库不真执行（沙箱不进单测） */
		OK(occ_tool_record(db, sid6, a1, "bash",
				   "{\"command\":\"echo hi\"}", "hi\n", 0, 5,
				   "call_b6", NULL, 0, NULL, 0, err,
				   sizeof(err)) == 0, "s6-bash-record");
		OK(occ_msg_add_assistant_ex(db, sid6, "完成", NULL, NULL, 0,
					     NULL, 0, "stop", 0, a2,
					     sizeof(a2), err,
					     sizeof(err)) == 0, "s6-close");
	}
	OK(!strcmp(rfile(f6), "Y"), "s6-after-write-y");
	memset(&r, 0, sizeof(r));
	OK(occ_undo(db, sid6, 1, NULL, &r, err, sizeof(err)) == 0, "s6-undo");
	OK(!strcmp(rfile(f6), "X"), "s6-restored-x");
	OK(r.nskipped == 1, "s6-bash-skipped-counted");
	OK(r.nfiles == 1, "s6-write-file-counted");
	occ_undo_result_free(&r);

	/* ---- H) 无 stage 的 commit/redo 边界 ---- */
	occ_revert_commit(db, sid5, NULL);		/* 无 stage：无操作 */
	OK(1, "h-commit-noop-no-crash");
	memset(&r, 0, sizeof(r));
	OK(occ_redo(db, sid5, NULL, &r, err, sizeof(err)) == -1,
	   "h-redo-no-stage-rejected");
	occ_undo_result_free(&r);
	/* 参数边界 */
	memset(&r, 0, sizeof(r));
	OK(occ_undo(db, sid5, 0, NULL, &r, err, sizeof(err)) == -1,
	   "h-undo-steps0-rejected");
	OK(occ_undo(db, "ses_nope", 1, NULL, &r, err, sizeof(err)) == -1,
	   "h-undo-no-session");
	occ_undo_result_free(&r);

	/* 旧的 v1 迁移库再开一次（幂等） */
	{
		occ_db *db2 = occ_db_open(dbpath_of("v1.db"), err,
					  sizeof(err));

		OK(db2 != NULL && sql_int(dbpath_of("v1.db"),
					  "PRAGMA user_version") == 2,
		   "mig-reopen-idempotent");
		if (db2)
			occ_db_close(db2);
	}

	occ_db_close(db);
out:
	{
		char cmd[256];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
		if (system(cmd)) {
			/* 清理失败不影响判定 */
		}
	}
	printf("test_revert: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
