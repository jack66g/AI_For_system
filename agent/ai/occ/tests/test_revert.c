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
 *   E) status=running 拒绝 undo（不改库；文案含 unstuck 指引）
 *   U) P-48 解僵链：running 残留 → 归位 interrupted（occ unstuck 的
 *      库原语）→ undo 放行（文件真回滚）
 *   F) 纯对话轮（无文件快照）拒绝 undo（不改库——设计 §9-2 约束）
 *   G) bash 无快照 → nskipped 如实计数（不谎称全量回滚）
 *   H) 幂等/边界：无 stage 的 commit 无操作；无 stage 的 redo 报错
 *   I) S-FINDING-01 快照完整性（内容篡改拒收/legacy 兼容/redo 同口径）
 *      + P-49：ABSENT 墓碑投毒拒收（I10/I11）、legacy/空墓碑照常
 *      工作（I10b/I10c）
 *   J) P-50 manifest 对账（DB 外部锚）：I12 换内容+重造 sidecar 拒收、
 *      I13 墓碑字节/kind 篡改拒收、I14 搬目录拒收、I15 删标记拒、
 *      I16 manifest 清空回 legacy（I9/I10b 语义不变）、I17 redo 锚
 *      （投毒拒收 + 空 redo_json legacy 正路）、I18 E2E（manifest 行
 *      直查+undo/redo 全绿）+ v3→v4 迁移
 *   O) O-24 状态一致性 fail-closed：篡改/搬目录/删标记类校验失败
 *      = undo 整体拒绝（rc=-1、不改文件、不隐藏消息、不建 stage，
 *      人话含「校验未过/未隐藏/可重试」）——I7/I10/I12-I16 断言随新
 *      语义翻转；O24a 一条消息多文件+单快照被外部改动致整体拒绝+
 *      修复后重试成功+redo 可用；O24b 换窗（digest）会话 /undo 人话
 *      提示（无可撤与步数不足两面，native 对照不带）；O24c 回滚
 *      IO 失败→已回滚条目补偿回撤销前现状+整体拒绝
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

/* J) 助手：直连 sqlite 写执行（模拟「DB 侧外部干预」——清 manifest/
 * 造 v3 老库；返回 0=成功） */
static int sql_exec(const char *dbfile, const char *sql)
{
	sqlite3 *h;
	char *perr = NULL;
	int rc = -1;

	if (sqlite3_open_v2(dbfile, &h, SQLITE_OPEN_READWRITE, NULL) !=
	    SQLITE_OK)
		return -1;
	if (sqlite3_exec(h, sql, NULL, NULL, &perr) == SQLITE_OK)
		rc = 0;
	sqlite3_free(perr);
	sqlite3_close(h);
	return rc;
}

/* J) 助手：按目标绝对路径定位 <root>/<ses>/ 下该文件的快照在盘文件
 * （内容或墓碑，mangle 单射比对——不依赖 readdir 顺序；多 msg 目录时
 * 返回首个命中）。返回 0=找到（out=全路径，墓碑含 .ABSENT 后缀）。 */
static int find_snap_of(const char *root, const char *ses,
			const char *want_abs, char *out, size_t cap)
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
			char name[1200], abs[4096];

			if (mn->d_name[0] == '.')
				continue;
			if (nl > 7 &&
			    (!strcmp(mn->d_name + nl - 7, ".sha256")))
				continue;
			if (nl > 7 && !strcmp(mn->d_name + nl - 7, ".ABSENT"))
				nl -= 7;
			if (nl >= sizeof(name))
				continue;
			memcpy(name, mn->d_name, nl);
			name[nl] = '\0';
			if (occ_snap_unmangle(name, abs, sizeof(abs)))
				continue;
			if (strcmp(abs, want_abs))
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

/* J) 助手：按 path 找 result 条目（readdir 序不定——按 path 断言）；
 * 找到返回下标，否则 -1 */
static int result_find(occ_undo_result *r, const char *path)
{
	size_t i;

	for (i = 0; i < r->nfiles; i++)
		if (!strcmp(r->files[i].path, path))
			return (int)i;
	return -1;
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
	/* 升级证据（E1→P-50：v1 老库直升 v4——v2/v3/v4 迁移链 open 内
	 * 一次走完；v3 全量证据面归 test_task，此处只钉版本与 v2/v4 主件） */
	OK(sql_int(v1db, "PRAGMA user_version") == 4, "mig-user-version-4");
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

	/* ---- U) P-48 unstuck 解僵链：running 挡 undo → 归位
	 * interrupted（occ unstuck 的库原语 occ_session_set_status）
	 * → undo 放行（文件真回滚） ---- */
	{
		char sidu[OCC_ID_LEN];
		char fu[192];

		OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
		   "u-create");
		snprintf(sidu, sizeof(sidu), "%s", s.id);
		OK(occ_session_set_workdir(db, sidu, workdir, err,
					   sizeof(err)) == 0, "u-workdir");
		snprintf(fu, sizeof(fu), "%s/f_u.txt", workdir);
		wfile(fu, "U0");
		OK(make_write_turn(db, sidu, "解僵前写一轮", fu, "U1", NULL,
				   err, sizeof(err)) == 0, "u-turn");
		OK(!strcmp(rfile(fu), "U1"), "u-before-stuck");
		/* 楔死/强杀残留形态：环未收口 → status=running 挡 undo */
		OK(occ_session_set_status(db, sidu, OCC_ST_RUNNING, err,
					  sizeof(err)) == 0, "u-set-running");
		memset(&r, 0, sizeof(r));
		OK(occ_undo(db, sidu, 1, NULL, &r, err, sizeof(err)) == -1 &&
		   strstr(err, "running") && strstr(err, "unstuck"),
		   "u-undo-blocked-with-hint");
		occ_undo_result_free(&r);
		/* occ unstuck 的库原语：running→interrupted（上下文原地） */
		OK(occ_session_set_status(db, sidu, OCC_ST_INTERRUPTED, err,
					  sizeof(err)) == 0, "u-unstuck");
		OK(occ_session_get(db, sidu, &s, err, sizeof(err)) == 1 &&
		   !strcmp(s.status, OCC_ST_INTERRUPTED),
		   "u-status-readback");
		memset(&r, 0, sizeof(r));
		OK(occ_undo(db, sidu, 1, NULL, &r, err, sizeof(err)) == 0,
		   "u-undo-after-unstuck");
		OK(!strcmp(rfile(fu), "U0"), "u-file-restored");
		occ_undo_result_free(&r);
	}

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

		/* 旧的 v1 迁移库再开一次（幂等；P-50：版本钉 v4 不再动） */
		{
			occ_db *db2 = occ_db_open(dbpath_of("v1.db"), err,
						  sizeof(err));

			OK(db2 != NULL && sql_int(dbpath_of("v1.db"),
						  "PRAGMA user_version") == 4,
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
		/* O-24：预检 fail-closed——整体拒绝（原 rc=0 部分失败语义
		 * 翻转：任一文件校验未过=不回滚、不隐藏、不建 stage） */
		OK(occ_undo(db, sid7, 1, NULL, &r, err, sizeof(err)) == -1 &&
		   strstr(err, "校验未过") && strstr(err, "未隐藏") &&
		   strstr(err, "可重试"), "i7-undo-refused");
		OK(!strcmp(rfile(f7), "T7"), "i7-target-kept-current");
		OK(occ_revert_get(db, sid7, &st, err, sizeof(err)) == 0,
		   "i7-no-stage");
		{
			occ_msg_row last;

			OK(occ_msg_last(db, sid7, &last, err, sizeof(err)) == 1 &&
			   !last.reverted, "i7-not-hidden");
			occ_msg_row_free(&last);
		}
		occ_undo_result_free(&r);

		/* I8：legacy 快照（无 sidecar 且无 DB manifest 行——P-50 起
		 *      「legacy」=P-49 前的快照两侧证全无）→ 照旧恢复
		 *      （向后兼容） */
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
		{
			char sql[600];

			snprintf(sql, sizeof(sql),
				 "DELETE FROM occ_snap WHERE path='%s';", f8);
			OK(sql_exec(dbpath_of("sessions.db"), sql) == 0,
			   "i8-manifest-row-removed");
		}
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
		OK(occ_undo(db, sid10, 1, NULL, &r, err, sizeof(err)) == -1 &&
		   strstr(err, "校验未过"), "i10-undo-refused");
		OK(fexists(f10) && !strcmp(rfile(f10), "NEW10"),
		   "i10-target-kept-current");
		OK(occ_revert_get(db, sid10, &st, err, sizeof(err)) == 0,
		   "i10-no-stage");
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

		/* ---- J) P-50：manifest 对账（DB 外部锚） ---- */
		{
			char sid12[OCC_ID_LEN], sid13[OCC_ID_LEN];
			char sid13b[OCC_ID_LEN], sid14[OCC_ID_LEN];
			char sid15[OCC_ID_LEN], sid16[OCC_ID_LEN];
			char sid16b[OCC_ID_LEN], sid17[OCC_ID_LEN];
			char sid18[OCC_ID_LEN];
			char f12[192], f13[192], f13b[192], f14a[192];
			char f14b[192], f15[192], f16[192], f16b[192];
			char f17[192], f18[192];
			char snap[900], side[960], tomb[920], hex[OCC_SHA256_HEX + 1];
			char sbuf[128];

			/* I12：anchored 换内容 + sidecar 正确重造——P-49
			 *      抓不住（sidecar 与快照同目录=自证），DB 锚拒收 */
			OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
			   "i12-create");
			snprintf(sid12, sizeof(sid12), "%s", s.id);
			occ_session_set_workdir(db, sid12, workdir, err,
						sizeof(err));
			snprintf(f12, sizeof(f12), "%s/f12.txt", workdir);
			wfile(f12, "O12");
			OK(make_write_turn(db, sid12, "把 f12 改成 T12", f12,
					   "T12", NULL, err, sizeof(err)) == 0,
			   "i12-turn");
			OK(find_snap_of(dbpath_of("snapshots"), sid12, f12,
					snap, sizeof(snap)) == 0, "i12-snap-found");
			wfile(snap, "POISON12");
			OK(occ_sha256_hex("POISON12", 8, hex) == 0, "i12-sha");
			snprintf(side, sizeof(side), "%s.sha256", snap);
			snprintf(sbuf, sizeof(sbuf), "%s\n", hex);
			wfile(side, sbuf);		/* sidecar 一并重造 */
			memset(&r, 0, sizeof(r));
			OK(occ_undo(db, sid12, 1, NULL, &r, err, sizeof(err)) == -1 &&
			   strstr(err, "校验未过"), "i12-undo-refused");
			OK(!strcmp(rfile(f12), "T12"), "i12-target-kept-current");
			OK(occ_revert_get(db, sid12, &st, err, sizeof(err)) == 0,
			   "i12-no-stage");
			occ_undo_result_free(&r);

			/* I13a：anchored 墓碑字节篡改 + sidecar 重造 → 拒 */
			OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
			   "i13a-create");
			snprintf(sid13, sizeof(sid13), "%s", s.id);
			occ_session_set_workdir(db, sid13, workdir, err,
						sizeof(err));
			snprintf(f13, sizeof(f13), "%s/new13.txt", workdir);
			OK(!fexists(f13), "i13a-before-absent");
			OK(make_write_turn(db, sid13, "新建 new13.txt", f13,
					   "NEW13", NULL, err, sizeof(err)) == 0,
			   "i13a-turn");
			OK(find_snap_of(dbpath_of("snapshots"), sid13, f13,
					snap, sizeof(snap)) == 0, "i13a-marker-found");
			OK(strlen(snap) > 7 &&
			   !strcmp(snap + strlen(snap) - 7, ".ABSENT"),
			   "i13a-is-tombstone");
			wfile(snap, "absent-POISON13\n");
			{
				size_t pl = strlen("absent-POISON13\n");

				OK(occ_sha256_hex("absent-POISON13\n", pl,
						  hex) == 0, "i13a-sha");
				snprintf(side, sizeof(side), "%s.sha256", snap);
				snprintf(sbuf, sizeof(sbuf), "%s\n", hex);
				wfile(side, sbuf);
			}
			memset(&r, 0, sizeof(r));
			OK(occ_undo(db, sid13, 1, NULL, &r, err, sizeof(err)) == -1 &&
			   strstr(err, "校验未过"), "i13a-undo-refused");
			OK(fexists(f13) && !strcmp(rfile(f13), "NEW13"),
			   "i13a-target-kept-current");
			OK(occ_revert_get(db, sid13, &st, err, sizeof(err)) == 0,
			   "i13a-no-stage");
			occ_undo_result_free(&r);

			/* I13b：内容快照被换成规范墓碑（kind 不符）→ 拒 */
			OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
			   "i13b-create");
			snprintf(sid13b, sizeof(sid13b), "%s", s.id);
			occ_session_set_workdir(db, sid13b, workdir, err,
						sizeof(err));
			snprintf(f13b, sizeof(f13b), "%s/f13b.txt", workdir);
			wfile(f13b, "O13B");
			OK(make_write_turn(db, sid13b, "把 f13b 改成 T13B", f13b,
					   "T13B", NULL, err, sizeof(err)) == 0,
			   "i13b-turn");
			OK(find_snap_of(dbpath_of("snapshots"), sid13b, f13b,
					snap, sizeof(snap)) == 0, "i13b-snap-found");
			snprintf(side, sizeof(side), "%s.sha256", snap);
			OK(unlink(snap) == 0 && unlink(side) == 0,
			   "i13b-swap-removed");
			snprintf(tomb, sizeof(tomb), "%s.ABSENT", snap);
			wfile(tomb, "absent\n");	/* 规范墓碑形态 */
			OK(occ_sha256_hex("absent\n", 7, hex) == 0, "i13b-sha");
			snprintf(side, sizeof(side), "%s.sha256", tomb);
			snprintf(sbuf, sizeof(sbuf), "%s\n", hex);
			wfile(side, sbuf);
			memset(&r, 0, sizeof(r));
			OK(occ_undo(db, sid13b, 1, NULL, &r, err, sizeof(err)) == -1 &&
			   strstr(err, "校验未过"), "i13b-undo-refused");
			OK(!strcmp(rfile(f13b), "T13B"),
			   "i13b-target-kept-current");
			occ_undo_result_free(&r);

			/* I14：搬目录——f14a 快照从 msg1 挪进 msg2 目录 */
			OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
			   "i14-create");
			snprintf(sid14, sizeof(sid14), "%s", s.id);
			occ_session_set_workdir(db, sid14, workdir, err,
						sizeof(err));
			snprintf(f14a, sizeof(f14a), "%s/f14a.txt", workdir);
			snprintf(f14b, sizeof(f14b), "%s/f14b.txt", workdir);
			wfile(f14a, "A1");
			OK(make_write_turn(db, sid14, "回合1：f14a 改 A2", f14a,
					   "A2", NULL, err, sizeof(err)) == 0,
			   "i14-turn1");
			wfile(f14b, "B1");
			OK(make_write_turn(db, sid14, "回合2：f14b 改 B2", f14b,
					   "B2", NULL, err, sizeof(err)) == 0,
			   "i14-turn2");
			{
				char snapA[900], snapB[900], dirB[900];
				char baseA[900], dst[1900], *slash;

				OK(find_snap_of(dbpath_of("snapshots"), sid14,
						f14a, snapA, sizeof(snapA)) == 0,
				   "i14-snapA-found");
				OK(find_snap_of(dbpath_of("snapshots"), sid14,
						f14b, snapB, sizeof(snapB)) == 0,
				   "i14-snapB-found");
				/* msg 目录不同（两回合两 assistant 消息） */
				{
					char dirA[900];

					snprintf(dirA, sizeof(dirA), "%s", snapA);
					slash = strrchr(dirA, '/');
					if (slash)
						*slash = '\0';
					snprintf(dirB, sizeof(dirB), "%s", snapB);
					slash = strrchr(dirB, '/');
					if (slash)
						*slash = '\0';
					OK(strcmp(dirA, dirB), "i14-distinct-msg-dirs");
				}
				slash = strrchr(snapA, '/');
				snprintf(baseA, sizeof(baseA), "%s", slash ? slash + 1 : snapA);
				snprintf(dst, sizeof(dst), "%s/%s", dirB, baseA);
				OK(rename(snapA, dst) == 0, "i14-moved");
			}
			memset(&r, 0, sizeof(r));
			/* O-24：搬目录条目预检拒 → 整体拒绝：f14b 不再部分
			 * 回滚（消息不隐藏=redo/重试能力保住） */
			OK(occ_undo(db, sid14, 2, NULL, &r, err, sizeof(err)) == -1 &&
			   strstr(err, "校验未过"), "i14-undo-refused");
			OK(!strcmp(rfile(f14a), "A2"), "i14-f14a-kept-current");
			OK(!strcmp(rfile(f14b), "B2"), "i14-f14b-also-kept");
			OK(occ_revert_get(db, sid14, &st, err, sizeof(err)) == 0,
			   "i14-no-stage");
			occ_undo_result_free(&r);

			/* I15：删标记——墓碑+sidecar 全删 → 合成 failed 条目
			 *      （action=DELETE）、目标保留不删、rc=0 */
			OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
			   "i15-create");
			snprintf(sid15, sizeof(sid15), "%s", s.id);
			occ_session_set_workdir(db, sid15, workdir, err,
						sizeof(err));
			snprintf(f15, sizeof(f15), "%s/new15.txt", workdir);
			OK(make_write_turn(db, sid15, "新建 new15.txt", f15,
					   "NEW15", NULL, err, sizeof(err)) == 0,
			   "i15-turn");
			OK(find_snap_of(dbpath_of("snapshots"), sid15, f15,
					snap, sizeof(snap)) == 0, "i15-marker-found");
			snprintf(side, sizeof(side), "%s.sha256", snap);
			OK(unlink(snap) == 0 && unlink(side) == 0,
			   "i15-marker-deleted");
			memset(&r, 0, sizeof(r));
			/* O-24：删标记=快照缺失，预检整体拒绝（原「合成
			 * failed 条目+rc=0+隐藏照常」语义翻转） */
			OK(occ_undo(db, sid15, 1, NULL, &r, err, sizeof(err)) == -1 &&
			   strstr(err, "校验未过"), "i15-undo-refused");
			OK(fexists(f15) && !strcmp(rfile(f15), "NEW15"),
			   "i15-target-kept");
			{
				occ_msg_row last;

				OK(occ_msg_last(db, sid15, &last, err,
						sizeof(err)) == 1 &&
				   !last.reverted, "i15-not-hidden");
				occ_msg_row_free(&last);
			}
			occ_undo_result_free(&r);

			/* I16：manifest 清空（DELETE FROM occ_snap）→ 回纯
			 *      P-49 legacy 世界 */
			OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
			   "i16a-create");
			snprintf(sid16, sizeof(sid16), "%s", s.id);
			occ_session_set_workdir(db, sid16, workdir, err,
						sizeof(err));
			snprintf(f16, sizeof(f16), "%s/f16.txt", workdir);
			wfile(f16, "O16");
			OK(make_write_turn(db, sid16, "把 f16 改成 T16", f16,
					   "T16", NULL, err, sizeof(err)) == 0,
			   "i16a-turn");
			OK(find_snap_of(dbpath_of("snapshots"), sid16, f16,
					snap, sizeof(snap)) == 0, "i16a-snap-found");
			wfile(snap, "POISON16");	/* sidecar 不动（I9 手法） */
			OK(sql_exec(dbpath_of("sessions.db"),
				    "DELETE FROM occ_snap;") == 0, "i16a-manifest-cleared");
			memset(&r, 0, sizeof(r));
			OK(occ_undo(db, sid16, 1, NULL, &r, err, sizeof(err)) == -1 &&
			   strstr(err, "校验未过"), "i16a-undo-refused");
			OK(!strcmp(rfile(f16), "T16"), "i16a-target-kept");
			occ_undo_result_free(&r);

			OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
			   "i16b-create");
			snprintf(sid16b, sizeof(sid16b), "%s", s.id);
			occ_session_set_workdir(db, sid16b, workdir, err,
						sizeof(err));
			snprintf(f16b, sizeof(f16b), "%s/new16b.txt", workdir);
			OK(make_write_turn(db, sid16b, "新建 new16b.txt", f16b,
					   "NEW16B", NULL, err, sizeof(err)) == 0,
			   "i16b-turn");
			OK(find_snap_of(dbpath_of("snapshots"), sid16b, f16b,
					snap, sizeof(snap)) == 0, "i16b-marker-found");
			snprintf(side, sizeof(side), "%s.sha256", snap);
			OK(unlink(side) == 0, "i16b-strip-sidecar");
			OK(sql_exec(dbpath_of("sessions.db"),
				    "DELETE FROM occ_snap;") == 0, "i16b-manifest-cleared");
			memset(&r, 0, sizeof(r));
			OK(occ_undo(db, sid16b, 1, NULL, &r, err, sizeof(err)) == 0,
			   "i16b-undo-rc0");
			OK(r.nfiles == 1 && r.files[0].action == OCC_UNDO_DELETE &&
			   !r.files[0].failed && !fexists(f16b),
			   "i16b-legacy-marker-still-deletes");
			occ_undo_result_free(&r);

			/* I17：redo 锚——_redo 投毒 + sidecar 重造 → redo 拒；
			 *      redo_json 置空（模拟旧 stage）→ legacy 路照常 */
			OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
			   "i17-create");
			snprintf(sid17, sizeof(sid17), "%s", s.id);
			occ_session_set_workdir(db, sid17, workdir, err,
						sizeof(err));
			snprintf(f17, sizeof(f17), "%s/f17.txt", workdir);
			wfile(f17, "O17");
			OK(make_write_turn(db, sid17, "把 f17 改成 T17", f17,
					   "T17", NULL, err, sizeof(err)) == 0,
			   "i17-turn");
			memset(&r, 0, sizeof(r));
			OK(occ_undo(db, sid17, 1, NULL, &r, err, sizeof(err)) == 0 &&
			   !strcmp(rfile(f17), "O17"), "i17-undo-ok");
			occ_undo_result_free(&r);
			{
				char rdir[300];
				DIR *dd = NULL;
				struct dirent *mn;
				char rd[900];

				rd[0] = '\0';
				snprintf(rdir, sizeof(rdir), "%s/%s/_redo",
					 dbpath_of("snapshots"), sid17);
				OK((dd = opendir(rdir)) != NULL, "i17-redo-dir");
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
				OK(rd[0] != '\0', "i17-redo-snap-found");
				if (rd[0]) {
					wfile(rd, "POISON17");
					OK(occ_sha256_hex("POISON17", 8, hex) == 0,
					   "i17-sha");
					snprintf(side, sizeof(side), "%s.sha256", rd);
					snprintf(sbuf, sizeof(sbuf), "%s\n", hex);
					wfile(side, sbuf);
					memset(&r, 0, sizeof(r));
					OK(occ_redo(db, sid17, NULL, &r, err,
						    sizeof(err)) == 0, "i17a-redo-rc0");
					OK(r.nfiles == 1 && r.files[0].failed == 1,
					   "i17a-redo-anchor-refused");
					OK(!strcmp(rfile(f17), "O17"),
					   "i17a-kept-undone");
					occ_undo_result_free(&r);
				}
			}
			/* 旧 stage 模拟：redo_json='' → legacy 照常（不投毒
			 * 正例；新回合新捕获——上一 redo 已清 _redo 段） */
			OK(make_write_turn(db, sid17, "再把 f17 改成 T17B", f17,
					   "T17B", NULL, err, sizeof(err)) == 0,
			   "i17b-turn");
			memset(&r, 0, sizeof(r));
			OK(occ_undo(db, sid17, 1, NULL, &r, err, sizeof(err)) == 0 &&
			   !strcmp(rfile(f17), "O17"), "i17b-undo-ok");
			occ_undo_result_free(&r);
			{
				char sql[256];

				snprintf(sql, sizeof(sql),
					 "UPDATE occ_revert SET redo_json=''"
					 " WHERE session_id='%s';", sid17);
				OK(sql_exec(dbpath_of("sessions.db"), sql) == 0,
				   "i17b-anchor-cleared");
			}
			memset(&r, 0, sizeof(r));
			OK(occ_redo(db, sid17, NULL, &r, err, sizeof(err)) == 0,
			   "i17b-redo-rc0");
			OK(r.nfiles == 1 && !r.files[0].failed,
			   "i17b-legacy-redo-works");
			OK(!strcmp(rfile(f17), "T17B"), "i17b-redo-restored");
			occ_undo_result_free(&r);

			/* I18a：E2E——manifest 行直查（kind/sha 正确）+
			 *      undo/redo 全绿零 failed */
			OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
			   "i18a-create");
			snprintf(sid18, sizeof(sid18), "%s", s.id);
			occ_session_set_workdir(db, sid18, workdir, err,
						sizeof(err));
			snprintf(f18, sizeof(f18), "%s/f18.txt", workdir);
			wfile(f18, "O18");
			OK(make_write_turn(db, sid18, "把 f18 改成 T18", f18,
					   "T18", NULL, err, sizeof(err)) == 0,
			   "i18a-turn");
			OK(occ_sha256_hex("O18", 3, hex) == 0, "i18a-sha");
			{
				char sql[600];

				snprintf(sql, sizeof(sql),
					 "SELECT COUNT(*) FROM occ_snap"
					 " WHERE path='%s' AND kind='snap'"
					 " AND sha256='%s'", f18, hex);
				OK(sql_int(dbpath_of("sessions.db"), sql) == 1,
				   "i18a-manifest-row");
			}
			memset(&r, 0, sizeof(r));
			OK(occ_undo(db, sid18, 1, NULL, &r, err, sizeof(err)) == 0,
			   "i18a-undo-rc0");
			OK(r.nfiles == 1 && !r.files[0].failed &&
			   !strcmp(rfile(f18), "O18"), "i18a-undo-green");
			occ_undo_result_free(&r);
			OK(occ_revert_get(db, sid18, &st, err, sizeof(err)) == 1,
			   "i18a-stage-row");
			{
				/* redo 锚记录的是 _redo 捕获（撤销前现状 T18）
				 * 的摘要——不是快照 O18 的 */
				char hex2[OCC_SHA256_HEX + 1];

				OK(occ_sha256_hex("T18", 3, hex2) == 0,
				   "i18a-redo-sha");
				OK(st.redo_json && strstr(st.redo_json, f18) &&
				   strstr(st.redo_json, hex2),
				   "i18a-redo-json-anchored");
			}
			occ_revert_row_free(&st);
			memset(&r, 0, sizeof(r));
			OK(occ_redo(db, sid18, NULL, &r, err, sizeof(err)) == 0,
			   "i18a-redo-rc0");
			OK(r.nfiles == 1 && !r.files[0].failed &&
			   !strcmp(rfile(f18), "T18"), "i18a-redo-green");
			occ_undo_result_free(&r);

			/* I18b：v3→v4 迁移——老库（无 occ_snap/redo_json）重开
			 *      无损升级、老 stage 行可读（redo_json 补缺省 ''） */
			{
				const char *v3db = dbpath_of("v3mig.db");
				occ_db *dv;
				char sidm[OCC_ID_LEN];

				unlink(v3db);
				dv = occ_db_open(v3db, err, sizeof(err));
				OK(dv != NULL, "i18b-open-fresh");
				if (!dv)
					goto out;
				OK(occ_session_create(dv, "m", &s, err,
						      sizeof(err)) == 0,
				   "i18b-session-create");
				snprintf(sidm, sizeof(sidm), "%s", s.id);
				OK(occ_revert_put(dv, sidm, "msg_b18", "msg_n18",
						  "[]", "[]", NULL, err,
						  sizeof(err)) == 0,
				   "i18b-stage-put");
				occ_db_close(dv);
				/* 降级回 v3 形态：删 manifest 表 + 拆 redo_json 列 */
				OK(sql_exec(v3db, "DROP TABLE occ_snap;") == 0,
				   "i18b-drop-snap");
				OK(sql_exec(v3db, "ALTER TABLE occ_revert"
					    " DROP COLUMN redo_json;") == 0,
				   "i18b-drop-redo-col");
				OK(sql_exec(v3db, "PRAGMA user_version=3;") == 0,
				   "i18b-set-v3");
				OK(sql_int(v3db, "PRAGMA user_version") == 3,
				   "i18b-downgraded-v3");
				OK(sql_count(v3db,
					     "SELECT COUNT(*) FROM sqlite_master"
					     " WHERE type='table' AND"
					     " name='occ_snap'", NULL) == 0,
				   "i18b-snap-gone");
				dv = occ_db_open(v3db, err, sizeof(err));
				OK(dv != NULL, "i18b-reopen");
				if (dv) {
					OK(sql_int(v3db, "PRAGMA user_version") == 4,
					   "i18b-migrated-v4");
					OK(sql_count(v3db,
						     "SELECT COUNT(*) FROM sqlite_master"
						     " WHERE type='table' AND"
						     " name='occ_snap'", NULL) == 1,
					   "i18b-snap-table-back");
					OK(sql_count(v3db,
						     "SELECT COUNT(*) FROM"
						     " pragma_table_info('occ_revert')"
						     " WHERE name='redo_json'",
						     NULL) == 1,
					   "i18b-redo-col-back");
					OK(occ_revert_get(dv, sidm, &st, err,
							  sizeof(err)) == 1 &&
					   !strcmp(st.boundary_msg, "msg_b18"),
					   "i18b-old-stage-readable");
					OK(st.redo_json && st.redo_json[0] == '\0',
					   "i18b-redo-json-default-empty");
					occ_revert_row_free(&st);
					occ_db_close(dv);
				}
			}
		}

		/* ---- O) O-24：状态一致性 fail-closed ---- */
		{
			char s24a[OCC_ID_LEN], s24b[OCC_ID_LEN];
			char s24c[OCC_ID_LEN];
			char f24a[192], f24b[192], f24c[192], f24d[192];
			char snap[900], side[960], hex[OCC_SHA256_HEX + 1];

			/* O24a：一条消息多文件快照+其中一份被外部改动致
			 * 回滚校验拒 → 整体拒绝（分歧窗口关闭）：全部文件
			 * 保持现状、消息未隐藏、无 stage；修复快照后重试
			 * 成功 + redo 可用（拒绝不吞回滚能力） */
			OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
			   "o24a-create");
			snprintf(s24a, sizeof(s24a), "%s", s.id);
			occ_session_set_workdir(db, s24a, workdir, err,
						sizeof(err));
			snprintf(f24a, sizeof(f24a), "%s/f24a.txt", workdir);
			snprintf(f24b, sizeof(f24b), "%s/f24b.txt", workdir);
			wfile(f24a, "O24A");
			wfile(f24b, "O24B");
			{
				/* 单回合两 write（一条消息多文件快照） */
				char uid[OCC_ID_LEN], a1[OCC_ID_LEN];
				char a2[OCC_ID_LEN];
				char args1[512], args2[512];
				occ_tool_call calls[2];
				occ_tool_ctx tc;
				occ_tool_result tr;

				OK(occ_msg_add_user(db, s24a, "改两个文件",
						    uid, sizeof(uid), err,
						    sizeof(err)) == 0,
				   "o24a-user");
				memset(calls, 0, sizeof(calls));
				snprintf(args1, sizeof(args1),
					 "{\"path\":\"%s\",\"content\":\"W24A\"}",
					 f24a);
				snprintf(args2, sizeof(args2),
					 "{\"path\":\"%s\",\"content\":\"W24B\"}",
					 f24b);
				calls[0].id = "call_w24a";
				calls[0].name = "write";
				calls[0].arguments = args1;
				calls[1].id = "call_w24b";
				calls[1].name = "write";
				calls[1].arguments = args2;
				OK(occ_msg_add_assistant_ex(db, s24a, "", NULL,
							     calls, 2, NULL, 0,
							     "tool_calls", 1,
							     a1, sizeof(a1),
							     err,
							     sizeof(err)) == 0,
				   "o24a-asst-calls");
				memset(&tc, 0, sizeof(tc));
				tc.db = db;
				tc.session_id = s24a;
				tc.msg_id = a1;
				tc.workdir = workdir;
				tc.trace_dir = tmpdir;
				OK(occ_tool_exec(&tc, "write", "call_w24a",
						 args1, &tr) == 0 &&
				   tr.rc == 0, "o24a-exec-a");
				occ_tool_result_free(&tr);
				OK(occ_tool_exec(&tc, "write", "call_w24b",
						 args2, &tr) == 0 &&
				   tr.rc == 0, "o24a-exec-b");
				occ_tool_result_free(&tr);
				OK(occ_msg_add_assistant_ex(db, s24a, "完成",
							     NULL, NULL, 0,
							     NULL, 0, "stop",
							     0, a2,
							     sizeof(a2),
							     err,
							     sizeof(err)) == 0,
				   "o24a-close");
			}
			OK(!strcmp(rfile(f24a), "W24A") &&
			   !strcmp(rfile(f24b), "W24B"), "o24a-written");
			/* 外部改动 f24b 的快照（append 毒字节——sidecar
			 * 不动，S-FINDING-01 手法） */
			OK(find_snap_of(dbpath_of("snapshots"), s24a, f24b,
					snap, sizeof(snap)) == 0,
			   "o24a-snap-found");
			{
				FILE *fp = fopen(snap, "ab");

				OK(fp != NULL, "o24a-poison-open");
				if (fp) {
					fputs("POISON24\n", fp);
					fclose(fp);
				}
			}
			memset(&r, 0, sizeof(r));
			OK(occ_undo(db, s24a, 1, NULL, &r, err,
				    sizeof(err)) == -1 &&
			   strstr(err, "校验未过") &&
			   strstr(err, "未隐藏") && strstr(err, "可重试"),
			   "o24a-refused");
			OK(!strcmp(rfile(f24a), "W24A"), "o24a-fa-kept");
			OK(!strcmp(rfile(f24b), "W24B"), "o24a-fb-kept");
			OK(occ_revert_get(db, s24a, &st, err, sizeof(err)) == 0,
			   "o24a-no-stage");
			{
				occ_msg_row last;

				OK(occ_msg_last(db, s24a, &last, err,
						sizeof(err)) == 1 &&
				   !last.reverted &&
				   !strcmp(last.role, "assistant"),
				   "o24a-not-hidden");
				occ_msg_row_free(&last);
			}
			occ_undo_result_free(&r);
			/* 修复快照（写回原内容+sidecar 重造——DB 锚
			 * want_sha=sha("O24B")）→ 重试成功 */
			wfile(snap, "O24B");
			OK(occ_sha256_hex("O24B", 4, hex) == 0, "o24a-fix-sha");
			snprintf(side, sizeof(side), "%s.sha256", snap);
			{
				char sbuf[128];

				snprintf(sbuf, sizeof(sbuf), "%s\n", hex);
				wfile(side, sbuf);
			}
			memset(&r, 0, sizeof(r));
			OK(occ_undo(db, s24a, 1, NULL, &r, err,
				    sizeof(err)) == 0, "o24a-retry-ok");
			OK(!strcmp(rfile(f24a), "O24A") &&
			   !strcmp(rfile(f24b), "O24B"),
			   "o24a-retry-restored");
			{
				int ia = result_find(&r, f24a);
				int ib = result_find(&r, f24b);

				OK(r.nfiles == 2 && ia >= 0 && ib >= 0 &&
				   !r.files[ia].failed &&
				   !r.files[ib].failed, "o24a-retry-green");
			}
			occ_undo_result_free(&r);
			/* redo 可用（_redo 捕获=撤销前现状——被拒的
			 * 第一次 undo 未吞掉回滚能力） */
			memset(&r, 0, sizeof(r));
			OK(occ_redo(db, s24a, NULL, &r, err, sizeof(err)) == 0 &&
			   !strcmp(rfile(f24a), "W24A") &&
			   !strcmp(rfile(f24b), "W24B"), "o24a-redo-green");
			occ_undo_result_free(&r);

			/* O24b：换窗（digest）会话 /undo 人话提示——
			 * 旧窗口消息被压缩折叠（reverted=1）不可撤销 */
			OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
			   "o24b-create");
			snprintf(s24b, sizeof(s24b), "%s", s.id);
			occ_session_set_workdir(db, s24b, workdir, err,
						sizeof(err));
			OK(occ_msg_add_user(db, s24b, "旧窗口消息", NULL, 0,
					    err, sizeof(err)) == 0,
			   "o24b-old-user");
			{
				char mid[OCC_ID_LEN];

				OK(occ_msg_add_assistant_ex(db, s24b,
							     "旧窗口回答",
							     NULL, NULL, 0,
							     NULL, 0, "stop",
							     0, mid,
							     sizeof(mid),
							     err,
							     sizeof(err)) == 0,
				   "o24b-old-asst");
			}
			{
				/* 换窗落库效果：摘要前全部消息置 reverted=1
				 * （occ_ac_apply_digest 同款）+ occ_window
				 * digest 标记 */
				char sql[600];

				snprintf(sql, sizeof(sql),
					 "UPDATE occ_message SET reverted=1"
					 " WHERE session_id='%s';", s24b);
				OK(sql_exec(dbpath_of("sessions.db"), sql) == 0,
				   "o24b-folded");
				snprintf(sql, sizeof(sql),
					 "UPDATE occ_window SET"
					 " base_kind='digest' WHERE"
					 " session_id='%s';", s24b);
				OK(sql_exec(dbpath_of("sessions.db"), sql) == 0,
				   "o24b-window-digest");
			}
			memset(&r, 0, sizeof(r));
			OK(occ_undo(db, s24b, 1, NULL, &r, err,
				    sizeof(err)) == -1 &&
			   strstr(err, "换窗"), "o24b-hint-on-empty");
			occ_undo_result_free(&r);
			/* 换窗后新窗口 1 步、请求 3 步 → 步数不足文案
			 * 也带换窗说明 */
			OK(occ_msg_add_user(db, s24b, "新窗口消息", NULL, 0,
					    err, sizeof(err)) == 0,
			   "o24b-new-user");
			{
				char mid[OCC_ID_LEN];

				OK(occ_msg_add_assistant_ex(db, s24b,
							     "新窗口回答",
							     NULL, NULL, 0,
							     NULL, 0, "stop",
							     0, mid,
							     sizeof(mid),
							     err,
							     sizeof(err)) == 0,
				   "o24b-new-asst");
			}
			memset(&r, 0, sizeof(r));
			OK(occ_undo(db, s24b, 3, NULL, &r, err,
				    sizeof(err)) == -1 &&
			   strstr(err, "步可撤") && strstr(err, "换窗"),
			   "o24b-hint-on-steps");
			occ_undo_result_free(&r);
			/* native 会话对照：步数不足不带换窗字样 */
			memset(&r, 0, sizeof(r));
			OK(occ_undo(db, sid5, 5, NULL, &r, err,
				    sizeof(err)) == -1 &&
			   strstr(err, "步可撤") && !strstr(err, "换窗"),
			   "o24b-native-no-hint");
			occ_undo_result_free(&r);

			/* O24c：回滚 IO 失败（目标位置被换成同名目录——
			 * 预检过、copy_file 打不开）→ 已回滚条目补偿回
			 * 撤销前现状 + 整体拒绝 */
			OK(occ_session_create(db, "m", &s, err, sizeof(err)) == 0,
			   "o24c-create");
			snprintf(s24c, sizeof(s24c), "%s", s.id);
			occ_session_set_workdir(db, s24c, workdir, err,
						sizeof(err));
			snprintf(f24c, sizeof(f24c), "%s/f24c.txt", workdir);
			snprintf(f24d, sizeof(f24d), "%s/f24d.txt", workdir);
			wfile(f24c, "O24C");
			wfile(f24d, "O24D");
			{
				char uid[OCC_ID_LEN], a1[OCC_ID_LEN];
				char a2[OCC_ID_LEN];
				char args1[512], args2[512];
				occ_tool_call calls[2];
				occ_tool_ctx tc;
				occ_tool_result tr;

				OK(occ_msg_add_user(db, s24c, "再改两个文件",
						    uid, sizeof(uid), err,
						    sizeof(err)) == 0,
				   "o24c-user");
				memset(calls, 0, sizeof(calls));
				snprintf(args1, sizeof(args1),
					 "{\"path\":\"%s\",\"content\":\"W24C\"}",
					 f24c);
				snprintf(args2, sizeof(args2),
					 "{\"path\":\"%s\",\"content\":\"W24D\"}",
					 f24d);
				calls[0].id = "call_w24c";
				calls[0].name = "write";
				calls[0].arguments = args1;
				calls[1].id = "call_w24d";
				calls[1].name = "write";
				calls[1].arguments = args2;
				OK(occ_msg_add_assistant_ex(db, s24c, "", NULL,
							     calls, 2, NULL, 0,
							     "tool_calls", 1,
							     a1, sizeof(a1),
							     err,
							     sizeof(err)) == 0,
				   "o24c-asst-calls");
				memset(&tc, 0, sizeof(tc));
				tc.db = db;
				tc.session_id = s24c;
				tc.msg_id = a1;
				tc.workdir = workdir;
				tc.trace_dir = tmpdir;
				OK(occ_tool_exec(&tc, "write", "call_w24c",
						 args1, &tr) == 0 &&
				   tr.rc == 0, "o24c-exec-c");
				occ_tool_result_free(&tr);
				OK(occ_tool_exec(&tc, "write", "call_w24d",
						 args2, &tr) == 0 &&
				   tr.rc == 0, "o24c-exec-d");
				occ_tool_result_free(&tr);
				OK(occ_msg_add_assistant_ex(db, s24c, "完成",
							     NULL, NULL, 0,
							     NULL, 0, "stop",
							     0, a2,
							     sizeof(a2),
							     err,
							     sizeof(err)) == 0,
				   "o24c-close");
			}
			OK(!strcmp(rfile(f24c), "W24C") &&
			   !strcmp(rfile(f24d), "W24D"), "o24c-written");
			/* 外部把 f24c 目标位置换成同名目录 */
			OK(unlink(f24c) == 0 && mkdir(f24c, 0755) == 0,
			   "o24c-target-dir");
			memset(&r, 0, sizeof(r));
			OK(occ_undo(db, s24c, 1, NULL, &r, err,
				    sizeof(err)) == -1 &&
			   strstr(err, "回滚失败") &&
			   strstr(err, "未隐藏") && strstr(err, "可重试"),
			   "o24c-refused");
			/* 已回滚条目补偿回撤销前现状（readdir 序不定：
			 * f24d 或未轮到或已补偿——两序同断言） */
			OK(!strcmp(rfile(f24d), "W24D"), "o24c-fd-compensated");
			OK(occ_revert_get(db, s24c, &st, err, sizeof(err)) == 0,
			   "o24c-no-stage");
			{
				occ_msg_row last;

				OK(occ_msg_last(db, s24c, &last, err,
						sizeof(err)) == 1 &&
				   !last.reverted, "o24c-not-hidden");
				occ_msg_row_free(&last);
			}
			occ_undo_result_free(&r);
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
