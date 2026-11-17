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
 *   I) S-FINDING-01 快照完整性（内容篡改拒收/legacy 兼容/redo 同口径）
 *      + P-49：ABSENT 墓碑投毒拒收（I10/I11）、legacy/空墓碑照常
 *      工作（I10b/I10c）
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
#include <dirent.h>

#include <sqlite3.h>

#include "occ_core/occ_revert.h"
#include "occ_tools/occ_tools.h"
#include "occ_tools/sha256.h"			/* S-FINDING-01 场景 I */

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

/* I) 助手：定位 <root>/<ses>/ 下首个真快照（跳过 .ABSENT/.sha256/
 * _redo/隐藏项）——返回 0=找到（out=绝对路径） */
static int find_snap(const char *root, const char *ses, char *out,
		     size_t cap)
{
	char d[340];
	DIR *dd, *md;
	struct dirent *en, *mn;

	snprintf(d, sizeof(d), "%s/%s", root, ses);
	if (!(dd = opendir(d)))
		return -1;
	while ((en = readdir(dd))) {
		char sub[620];

		if (en->d_name[0] == '.' || !strcmp(en->d_name, "_redo"))
			continue;
		snprintf(sub, sizeof(sub), "%s/%s", d, en->d_name);
		if (!(md = opendir(sub)))
			continue;
		while ((mn = readdir(md))) {
			size_t nl = strlen(mn->d_name);

			if (mn->d_name[0] == '.')
				continue;
			if (nl > 7 &&
			    (!strcmp(mn->d_name + nl - 7, ".ABSENT") ||
			     !strcmp(mn->d_name + nl - 7, ".sha256")))
				continue;
			snprintf(out, cap, "%s/%s", sub, mn->d_name);
			closedir(md);
			closedir(dd);
			return 0;
		}
		closedir(md);
	}
	closedir(dd);
	return -1;
}

/* I10 助手：定位 <root>/<ses>/ 下首个 .ABSENT 墓碑（跳过 sidecar/
 * 内容副本/_redo）——返回 0=找到（out=绝对路径） */
static int find_absent(const char *root, const char *ses, char *out,
		       size_t cap)
{
	char d[340];
	DIR *dd, *md;
	struct dirent *en, *mn;

	snprintf(d, sizeof(d), "%s/%s", root, ses);
	if (!(dd = opendir(d)))
		return -1;
	while ((en = readdir(dd))) {
		char sub[620];

		if (en->d_name[0] == '.' || !strcmp(en->d_name, "_redo"))
			continue;
		snprintf(sub, sizeof(sub), "%s/%s", d, en->d_name);
		if (!(md = opendir(sub)))
			continue;
		while ((mn = readdir(md))) {
			size_t nl = strlen(mn->d_name);

			if (mn->d_name[0] == '.')
				continue;
			if (nl > 7 && !strcmp(mn->d_name + nl - 7, ".ABSENT")) {
				snprintf(out, cap, "%s/%s", sub, mn->d_name);
				closedir(md);
				closedir(dd);
				return 0;
			}
		}
		closedir(md);
	}
	closedir(dd);
	return -1;
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
	/* 升级证据（E1：v1 老库直升 v3——v2/v3 迁移链 open 内一次走完；
	 * v3 全量证据面归 test_task，此处只钉版本与 v2 主件不回退） */
	OK(sql_int(v1db, "PRAGMA user_version") == 3, "mig-user-version-3");
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

		/* 旧的 v1 迁移库再开一次（幂等；E1：版本钉 v3 不再动） */
		{
			occ_db *db2 = occ_db_open(dbpath_of("v1.db"), err,
						  sizeof(err));

			OK(db2 != NULL && sql_int(dbpath_of("v1.db"),
						  "PRAGMA user_version") == 3,
			   "mig-reopen-idempotent");
			if (db2)
				occ_db_close(db2);
		}

	/* ---- I) S-FINDING-01：快照完整性（篡改拒恢复+legacy 兼容+
	 *      redo 同口径校验） ---- */
	{
		char sid7[OCC_ID_LEN], sid8[OCC_ID_LEN], sid9[OCC_ID_LEN];
		char sid10[OCC_ID_LEN], sid10b[OCC_ID_LEN], sid10c[OCC_ID_LEN];
		char sid11[OCC_ID_LEN];
		char u7[OCC_ID_LEN], u8[OCC_ID_LEN], u9[OCC_ID_LEN];
		char u10[OCC_ID_LEN], u10b[OCC_ID_LEN], u10c[OCC_ID_LEN];
		char u11[OCC_ID_LEN];
		char f7[192], f8[192], f9[192];
		char f10[192], f10b[192], f10c[192], f11[192];
		char snap[900], side[920], rd[900], absent[900];
		char hex[OCC_SHA256_HEX + 1];

		/* I0：实现正确性向量（"abc"）钉死 */
		OK(occ_sha256_hex("abc", 3, hex) == 0 &&
		   !strcmp(hex,
			    "ba7816bf8f01cfea414140de5dae2223"
			    "b00361a396177a9cb410ff61f20015ad"),
		   "i0-sha256-abc");

		/* I7：篡改快照+sidecar 在场 → 拒绝恢复（fail closed） */
		OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
		   "i7-create");
		snprintf(sid7, sizeof(sid7), "%s", s.id);
		occ_session_set_workdir(db, sid7, workdir, err, sizeof(err));
		snprintf(f7, sizeof(f7), "%s/f7.txt", workdir);
		wfile(f7, "O7");
		OK(make_write_turn(db, sid7, "把 f7 改成 T7", f7, "T7",
				   u7, err, sizeof(err)) == 0, "i7-turn");
		OK(find_snap(dbpath_of("snapshots"), sid7, snap,
			      sizeof(snap)) == 0, "i7-snap-found");
		snprintf(side, sizeof(side), "%s.sha256", snap);
		OK(!access(side, F_OK), "i7-sidecar-written");
		wfile(snap, "POISON7");
		memset(&r, 0, sizeof(r));
		OK(occ_undo(db, sid7, 1, NULL, &r, err, sizeof(err)) == 0,
		   "i7-undo-rc0");
		OK(r.nfiles == 1 && r.files[0].failed == 1,
		   "i7-tamper-refused");
		OK(!strcmp(rfile(f7), "T7"), "i7-target-kept-current");
		occ_undo_result_free(&r);

		/* I8：legacy 快照（无 sidecar）→ 照旧恢复（向后兼容） */
		OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
		   "i8-create");
		snprintf(sid8, sizeof(sid8), "%s", s.id);
		occ_session_set_workdir(db, sid8, workdir, err, sizeof(err));
		snprintf(f8, sizeof(f8), "%s/f8.txt", workdir);
		wfile(f8, "O8");
		OK(make_write_turn(db, sid8, "把 f8 改成 T8", f8, "T8",
				   u8, err, sizeof(err)) == 0, "i8-turn");
		OK(find_snap(dbpath_of("snapshots"), sid8, snap,
			      sizeof(snap)) == 0, "i8-snap-found");
		snprintf(side, sizeof(side), "%s.sha256", snap);
		OK(unlink(side) == 0, "i8-sidecar-removed");
		wfile(snap, "LEGACY8");
		memset(&r, 0, sizeof(r));
		OK(occ_undo(db, sid8, 1, NULL, &r, err, sizeof(err)) == 0,
		   "i8-undo-rc0");
		OK(r.nfiles == 1 && !r.files[0].failed, "i8-legacy-restored");
		OK(!strcmp(rfile(f8), "LEGACY8"), "i8-legacy-content");
		occ_undo_result_free(&r);

		/* I9：_redo 段同口径（篡改 _redo 副本 → redo 拒绝还原） */
		OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
		   "i9-create");
		snprintf(sid9, sizeof(sid9), "%s", s.id);
		occ_session_set_workdir(db, sid9, workdir, err, sizeof(err));
		snprintf(f9, sizeof(f9), "%s/f9.txt", workdir);
		wfile(f9, "O9");
		OK(make_write_turn(db, sid9, "把 f9 改成 T9", f9, "T9",
				   u9, err, sizeof(err)) == 0, "i9-turn");
		memset(&r, 0, sizeof(r));
		OK(occ_undo(db, sid9, 1, NULL, &r, err, sizeof(err)) == 0 &&
		   !strcmp(rfile(f9), "O9"), "i9-undo-ok");
		occ_undo_result_free(&r);
		{
			char rdir[300];
			DIR *dd = NULL;
			struct dirent *mn;

			snprintf(rdir, sizeof(rdir), "%s/%s/_redo",
				  dbpath_of("snapshots"), sid9);
			OK((dd = opendir(rdir)) != NULL, "i9-redo-dir");
			if (dd) {
				while ((mn = readdir(dd))) {
					size_t nl = strlen(mn->d_name);

					if (mn->d_name[0] == '.')
						continue;
					if (nl > 7 && !strcmp(mn->d_name + nl - 7,
								 ".sha256"))
						continue;
					snprintf(rd, sizeof(rd), "%s/%s",
						   rdir, mn->d_name);
					break;
				}
				closedir(dd);
			}
			OK(rd[0] != '\0', "i9-redo-snap-found");
			if (rd[0]) {
				wfile(rd, "POISON9");
				memset(&r, 0, sizeof(r));
				OK(occ_redo(db, sid9, NULL, &r, err,
					      sizeof(err)) == 0,
				   "i9-redo-rc0");
				OK(r.nfiles == 1 && r.files[0].failed == 1,
				   "i9-redo-tamper-refused");
			OK(!strcmp(rfile(f9), "O9"),
			   "i9-redo-kept-undone");
				occ_undo_result_free(&r);
			}
		}

		/* I10：P-49——ABSENT 墓碑投毒：undo 拒按墓碑行事（文件
		 *      保持写后现状、failed 如实上报；与内容快照拒收同款
		 *      语义）。手法=真机实证同款：墓碑 append 毒字节。 */
		OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
		   "i10-create");
		snprintf(sid10, sizeof(sid10), "%s", s.id);
		occ_session_set_workdir(db, sid10, workdir, err, sizeof(err));
		snprintf(f10, sizeof(f10), "%s/new10.txt", workdir);
		OK(!fexists(f10), "i10-before-absent");
		OK(make_write_turn(db, sid10, "新建 new10.txt", f10, "NEW10",
				   u10, err, sizeof(err)) == 0, "i10-turn");
		OK(find_absent(dbpath_of("snapshots"), sid10, absent,
			       sizeof(absent)) == 0, "i10-marker-found");
		snprintf(side, sizeof(side), "%s.sha256", absent);
		OK(!access(side, F_OK), "i10-marker-sidecar-written");
		{
			FILE *f = fopen(absent, "ab");

			OK(f != NULL, "i10-open-marker");
			if (f) {
				fputs("POISON10\n", f);
				fclose(f);
			}
		}
		memset(&r, 0, sizeof(r));
		OK(occ_undo(db, sid10, 1, NULL, &r, err, sizeof(err)) == 0,
		   "i10-undo-rc0");
		OK(r.nfiles == 1 && r.files[0].action == OCC_UNDO_DELETE &&
		   r.files[0].failed == 1, "i10-tamper-refused");
		OK(fexists(f10) && !strcmp(rfile(f10), "NEW10"),
		   "i10-target-kept-current");
		occ_undo_result_free(&r);

		/* I10b：legacy 墓碑（无 sidecar、内容规范 "absent\n"）照常
		 *      工作——向后兼容不破坏合法 undo */
		OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
		   "i10b-create");
		snprintf(sid10b, sizeof(sid10b), "%s", s.id);
		occ_session_set_workdir(db, sid10b, workdir, err, sizeof(err));
		snprintf(f10b, sizeof(f10b), "%s/new10b.txt", workdir);
		OK(make_write_turn(db, sid10b, "新建 new10b.txt", f10b,
				   "NEW10B", u10b, err, sizeof(err)) == 0,
		   "i10b-turn");
		OK(find_absent(dbpath_of("snapshots"), sid10b, absent,
			       sizeof(absent)) == 0, "i10b-marker-found");
		snprintf(side, sizeof(side), "%s.sha256", absent);
		OK(unlink(side) == 0, "i10b-strip-sidecar");
		memset(&r, 0, sizeof(r));
		OK(occ_undo(db, sid10b, 1, NULL, &r, err, sizeof(err)) == 0,
		   "i10b-undo-rc0");
		OK(r.nfiles == 1 && r.files[0].action == OCC_UNDO_DELETE &&
		   !r.files[0].failed && !fexists(f10b),
		   "i10b-legacy-marker-still-deletes");
		occ_undo_result_free(&r);

		/* I10c：空墓碑（0 字节、无 sidecar）照常工作——「空
		 *      ABSENT 标记照常工作」钉死 */
		OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
		   "i10c-create");
		snprintf(sid10c, sizeof(sid10c), "%s", s.id);
		occ_session_set_workdir(db, sid10c, workdir, err, sizeof(err));
		snprintf(f10c, sizeof(f10c), "%s/new10c.txt", workdir);
		OK(make_write_turn(db, sid10c, "新建 new10c.txt", f10c,
				   "NEW10C", u10c, err, sizeof(err)) == 0,
		   "i10c-turn");
		OK(find_absent(dbpath_of("snapshots"), sid10c, absent,
			       sizeof(absent)) == 0, "i10c-marker-found");
		snprintf(side, sizeof(side), "%s.sha256", absent);
		OK(unlink(side) == 0, "i10c-strip-sidecar");
		wfile(absent, "");
		memset(&r, 0, sizeof(r));
		OK(occ_undo(db, sid10c, 1, NULL, &r, err, sizeof(err)) == 0,
		   "i10c-undo-rc0");
		OK(r.nfiles == 1 && r.files[0].action == OCC_UNDO_DELETE &&
		   !r.files[0].failed && !fexists(f10c),
		   "i10c-empty-marker-still-deletes");
		occ_undo_result_free(&r);

		/* I11：P-49——_redo 墓碑投毒：redo 拒按墓碑行事（目标保持
		 *      被撤后状态=不存在，failed 如实上报） */
		OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
		   "i11-create");
		snprintf(sid11, sizeof(sid11), "%s", s.id);
		occ_session_set_workdir(db, sid11, workdir, err, sizeof(err));
		snprintf(f11, sizeof(f11), "%s/new11.txt", workdir);
		OK(make_write_turn(db, sid11, "新建 new11.txt", f11, "NEW11",
				   u11, err, sizeof(err)) == 0, "i11-turn");
		OK(unlink(f11) == 0, "i11-manual-rm");	/* 撤销前现状=不存在 */
		memset(&r, 0, sizeof(r));
		OK(occ_undo(db, sid11, 1, NULL, &r, err, sizeof(err)) == 0,
		   "i11-undo-rc0");	/* 墓碑合法：DELETE 动作 ENOENT 视作成功 */
		occ_undo_result_free(&r);
		{
			char rdir[300];
			DIR *dd = NULL;
			struct dirent *mn;

			snprintf(rdir, sizeof(rdir), "%s/%s/_redo",
				 dbpath_of("snapshots"), sid11);
			OK((dd = opendir(rdir)) != NULL, "i11-redo-dir");
			rd[0] = '\0';
			if (dd) {
				while ((mn = readdir(dd))) {
					size_t nl = strlen(mn->d_name);

					if (mn->d_name[0] == '.')
						continue;
					if (nl > 7 && !strcmp(mn->d_name + nl - 7,
							      ".ABSENT")) {
						snprintf(rd, sizeof(rd), "%s/%s",
							 rdir, mn->d_name);
						break;
					}
				}
				closedir(dd);
			}
			OK(rd[0] != '\0', "i11-redo-tomb-found");
			if (rd[0]) {
				FILE *f = fopen(rd, "ab");

				OK(f != NULL, "i11-open-tomb");
				if (f) {
					fputs("POISON11\n", f);
					fclose(f);
				}
				memset(&r, 0, sizeof(r));
				OK(occ_redo(db, sid11, NULL, &r, err,
					    sizeof(err)) == 0, "i11-redo-rc0");
				OK(r.nfiles == 1 && r.files[0].failed == 1,
				   "i11-redo-tamper-refused");
				OK(!fexists(f11), "i11-target-stays-absent");
				occ_undo_result_free(&r);
			}
		}
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
