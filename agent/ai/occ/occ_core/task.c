/* SPDX-License-Identifier: GPL-2.0 */
/*
 * task.c - occ 编排任务数据面实现（ORCH-DESIGN §2；波次 E1）
 *
 * occ_task/occ_task_event 两表 + 任务状态机 API。DDL 归本文件
 * （occ_task_schema_v3），由 session.c occ_db_open 在建库/迁移事务内
 * 调用（新库与 v2→v3 都经此建表；幂等）。SQL 经 occ_db_sqlite 拿原生
 * 句柄，全部绑参（与 session.c 同风格）；每动作单事务
 * （BEGIN IMMEDIATE…COMMIT，失败 ROLLBACK）。
 *
 * 状态迁移合法性在事务内读现态判定——非法迁移返回错误不静默
 * （迁移表见 task.h 头注）。
 */
#define _POSIX_C_SOURCE 200809L
#include "task.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include <sqlite3.h>

/* ---- 小工具（同 session.c 口径；static 不外溢） ---- */

static long long now_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* /dev/urandom → id（"tsk_" + 16 字节 hex = 32 字符） */
static int gen_id(char *buf, size_t buflen)
{
	static const char prefix[] = "tsk_";
	unsigned char rb[16];
	size_t i;
	int fd;

	if (buflen < sizeof(prefix) - 1 + 32 + 1)
		return -1;
	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return -1;
	if (read(fd, rb, sizeof(rb)) != (ssize_t)sizeof(rb)) {
		close(fd);
		return -1;
	}
	close(fd);
	memcpy(buf, prefix, sizeof(prefix) - 1);
	for (i = 0; i < sizeof(rb); i++) {
		buf[sizeof(prefix) - 1 + i * 2] =
			"0123456789abcdef"[rb[i] >> 4];
		buf[sizeof(prefix) - 1 + i * 2 + 1] =
			"0123456789abcdef"[rb[i] & 0xF];
	}
	buf[sizeof(prefix) - 1 + 32] = '\0';
	return 0;
}

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || !errlen)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

static int tx_begin(occ_db *db, char *err, size_t errlen)
{
	char *perr = NULL;
	sqlite3 *h = occ_db_sqlite(db);

	if (sqlite3_exec(h, "BEGIN IMMEDIATE", NULL, NULL, &perr) !=
	    SQLITE_OK) {
		set_err(err, errlen, "task tx: %s",
			perr ? perr : sqlite3_errmsg(h));
		sqlite3_free(perr);
		return -1;
	}
	return 0;
}

static void tx_rollback(occ_db *db)
{
	sqlite3_exec(occ_db_sqlite(db), "ROLLBACK", NULL, NULL, NULL);
}

static int tx_commit(occ_db *db, char *err, size_t errlen)
{
	char *perr = NULL;
	sqlite3 *h = occ_db_sqlite(db);

	if (sqlite3_exec(h, "COMMIT", NULL, NULL, &perr) != SQLITE_OK) {
		set_err(err, errlen, "task commit: %s",
			perr ? perr : sqlite3_errmsg(h));
		sqlite3_free(perr);
		tx_rollback(db);
		return -1;
	}
	return 0;
}

/* 事务内追加事件行（kind/payload 全绑参；payload NULL→空串） */
static int ev_add(occ_db *db, const char *task_id, const char *kind,
		  const char *payload_json)
{
	static const char *ins =
		"INSERT INTO occ_task_event(task_id,kind,payload_json,created)"
		" VALUES (?1,?2,?3,?4)";
	sqlite3 *h = occ_db_sqlite(db);
	sqlite3_stmt *st = NULL;

	if (sqlite3_prepare_v2(h, ins, -1, &st, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_text(st, 1, task_id, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 2, kind, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 3, payload_json ? payload_json : "", -1,
			  SQLITE_TRANSIENT);
	sqlite3_bind_int64(st, 4, now_ms());
	if (sqlite3_step(st) != SQLITE_DONE) {
		sqlite3_finalize(st);
		return -1;
	}
	sqlite3_finalize(st);
	return 0;
}

/*
 * 事务内读现态（status/rework_count/rework_max）。
 * 返回 1=找到；0=任务不存在；-1=DB 错。调用方统一经 task_state_fail
 * 报错（区分「不存在」人话与 DB 错原文）。
 */
static int task_state(occ_db *db, const char *id, char *status, size_t slen,
		      int *rework_count, int *rework_max)
{
	static const char *sel =
		"SELECT status,rework_count,rework_max FROM occ_task"
		" WHERE id=?1";
	sqlite3 *h = occ_db_sqlite(db);
	sqlite3_stmt *st = NULL;
	int rc;

	if (sqlite3_prepare_v2(h, sel, -1, &st, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
	rc = sqlite3_step(st);
	if (rc == SQLITE_ROW) {
		const unsigned char *s = sqlite3_column_text(st, 0);

		snprintf(status, slen, "%s", s ? (const char *)s : "");
		*rework_count = sqlite3_column_int(st, 1);
		*rework_max = sqlite3_column_int(st, 2);
		rc = 1;
	} else {
		rc = (rc == SQLITE_DONE) ? 0 : -1;
	}
	sqlite3_finalize(st);
	return rc;
}

/* task_state 失败统一报错（0=不存在人话；-1=DB 错原文） */
static int task_state_fail(int rc, const char *id, const char *what,
			   char *err, size_t errlen)
{
	if (rc == 0)
		set_err(err, errlen, "%s: 任务 %s 不存在", what, id);
	else
		set_err(err, errlen, "%s: 读任务态失败", what);
	return -1;
}

/* 事务内改状态（status 单列；updated 同拍） */
static int task_set_status(occ_db *db, const char *id, const char *status)
{
	static const char *upd =
		"UPDATE occ_task SET status=?1, updated=?2 WHERE id=?3";
	sqlite3 *h = occ_db_sqlite(db);
	sqlite3_stmt *st = NULL;

	if (sqlite3_prepare_v2(h, upd, -1, &st, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_text(st, 1, status, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(st, 2, now_ms());
	sqlite3_bind_text(st, 3, id, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(st) != SQLITE_DONE) {
		sqlite3_finalize(st);
		return -1;
	}
	sqlite3_finalize(st);
	return 0;
}

/* ---- schema v3 DDL ---- */

int occ_task_schema_v3(occ_db *db, char *err, size_t errlen)
{
	static const char DDL[] =
		"CREATE TABLE IF NOT EXISTS occ_task ("
		"  id TEXT PRIMARY KEY,"
		"  parent_session TEXT NOT NULL"
		"    REFERENCES occ_session(id) ON DELETE CASCADE,"
		"  child_session TEXT,"
		"  title TEXT NOT NULL DEFAULT '',"
		"  brief_json TEXT NOT NULL DEFAULT '',"
		"  status TEXT NOT NULL DEFAULT 'pending',"
		"  rework_count INTEGER NOT NULL DEFAULT 0,"
		"  rework_max INTEGER NOT NULL DEFAULT 2,"
		"  verdict_json TEXT,"
		"  budget_in INTEGER NOT NULL DEFAULT 0,"
		"  budget_out INTEGER NOT NULL DEFAULT 0,"
		"  created INTEGER NOT NULL DEFAULT 0,"
		"  updated INTEGER NOT NULL DEFAULT 0"
		");"
		"CREATE INDEX IF NOT EXISTS occ_task_parent"
		"  ON occ_task(parent_session, created);"
		"CREATE TABLE IF NOT EXISTS occ_task_event ("
		"  id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"  task_id TEXT NOT NULL"
		"    REFERENCES occ_task(id) ON DELETE CASCADE,"
		"  kind TEXT NOT NULL,"
		"  payload_json TEXT,"
		"  created INTEGER NOT NULL DEFAULT 0"
		");"
		"CREATE INDEX IF NOT EXISTS occ_task_event_task"
		"  ON occ_task_event(task_id, id);";
	char *perr = NULL;
	sqlite3 *h;

	if (!db) {
		set_err(err, errlen, "occ_task_schema_v3: bad args");
		return -1;
	}
	h = occ_db_sqlite(db);
	if (sqlite3_exec(h, DDL, NULL, NULL, &perr) != SQLITE_OK) {
		set_err(err, errlen, "task schema: %s",
			perr ? perr : sqlite3_errmsg(h));
		sqlite3_free(perr);
		return -1;
	}
	return 0;
}

/* ---- 行读取 ---- */

static char *col_strdup(sqlite3_stmt *st, int col)
{
	const unsigned char *s = sqlite3_column_text(st, col);

	if (!s)
		return NULL;
	return strdup((const char *)s);
}

static const char TASK_COLS[] =
	"id,parent_session,child_session,title,brief_json,status,"
	"rework_count,rework_max,verdict_json,budget_in,budget_out,"
	"created,updated";

static int task_fill(occ_task_row *out, sqlite3_stmt *st)
{
	const unsigned char *cs;

	snprintf(out->id, sizeof(out->id), "%s", sqlite3_column_text(st, 0));
	snprintf(out->parent_session, sizeof(out->parent_session), "%s",
		 sqlite3_column_text(st, 1));
	cs = sqlite3_column_text(st, 2);
	snprintf(out->child_session, sizeof(out->child_session), "%s",
		 cs ? (const char *)cs : "");
	snprintf(out->title, sizeof(out->title), "%s",
		 sqlite3_column_text(st, 3));
	out->brief_json = col_strdup(st, 4);
	snprintf(out->status, sizeof(out->status), "%s",
		 sqlite3_column_text(st, 5));
	out->rework_count = sqlite3_column_int(st, 6);
	out->rework_max = sqlite3_column_int(st, 7);
	out->verdict_json = col_strdup(st, 8);
	out->budget_in = sqlite3_column_int64(st, 9);
	out->budget_out = sqlite3_column_int64(st, 10);
	out->created = sqlite3_column_int64(st, 11);
	out->updated = sqlite3_column_int64(st, 12);
	return 1;
}

void occ_task_row_free(occ_task_row *r)
{
	if (!r)
		return;
	free(r->brief_json);
	free(r->verdict_json);
	memset(r, 0, sizeof(*r));
}

void occ_task_rows_free(occ_task_row *rows, size_t n)
{
	size_t i;

	if (!rows)
		return;
	for (i = 0; i < n; i++) {
		free(rows[i].brief_json);
		free(rows[i].verdict_json);
	}
	free(rows);
}

void occ_task_event_rows_free(occ_task_event_row *rows, size_t n)
{
	size_t i;

	if (!rows)
		return;
	for (i = 0; i < n; i++)
		free(rows[i].payload_json);
	free(rows);
}

int occ_task_get(occ_db *db, const char *id, occ_task_row *out,
		 char *err, size_t errlen)
{
	char sql[256];
	sqlite3 *h;
	sqlite3_stmt *st = NULL;
	int rc;

	if (!db || !id || !out) {
		set_err(err, errlen, "occ_task_get: bad args");
		return -1;
	}
	h = occ_db_sqlite(db);
	snprintf(sql, sizeof(sql),
		 "SELECT %s FROM occ_task WHERE id=?1", TASK_COLS);
	if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "prepare: %s", sqlite3_errmsg(h));
		return -1;
	}
	sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
	rc = sqlite3_step(st);
	if (rc == SQLITE_ROW)
		rc = task_fill(out, st);
	else
		rc = 0;
	sqlite3_finalize(st);
	return rc;
}

int occ_task_list(occ_db *db, const char *parent_session,
		  occ_task_row **rows, size_t *n, char *err, size_t errlen)
{
	char sql[256];
	sqlite3 *h;
	sqlite3_stmt *st = NULL;
	occ_task_row *v = NULL;
	size_t cnt = 0, cap = 0;

	if (!db || !rows || !n) {
		set_err(err, errlen, "occ_task_list: bad args");
		return -1;
	}
	*rows = NULL;
	*n = 0;
	h = occ_db_sqlite(db);
	if (parent_session)
		snprintf(sql, sizeof(sql),
			 "SELECT %s FROM occ_task WHERE parent_session=?1"
			 " ORDER BY created DESC", TASK_COLS);
	else
		snprintf(sql, sizeof(sql),
			 "SELECT %s FROM occ_task ORDER BY created DESC",
			 TASK_COLS);
	if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "prepare: %s", sqlite3_errmsg(h));
		return -1;
	}
	if (parent_session)
		sqlite3_bind_text(st, 1, parent_session, -1,
				  SQLITE_TRANSIENT);
	while (sqlite3_step(st) == SQLITE_ROW) {
		if (cnt == cap) {
			occ_task_row *nv;

			cap = cap ? cap * 2 : 8;
			nv = realloc(v, cap * sizeof(*nv));
			if (!nv) {
				free(v);
				sqlite3_finalize(st);
				set_err(err, errlen, "oom");
				return -1;
			}
			v = nv;
		}
		memset(&v[cnt], 0, sizeof(v[cnt]));
		task_fill(&v[cnt], st);
		cnt++;
	}
	sqlite3_finalize(st);
	*rows = v;
	*n = cnt;
	return 0;
}

int occ_task_events(occ_db *db, const char *id,
		    occ_task_event_row **rows, size_t *n,
		    char *err, size_t errlen)
{
	static const char *sel =
		"SELECT id,task_id,kind,payload_json,created"
		" FROM occ_task_event WHERE task_id=?1 ORDER BY id";
	sqlite3 *h;
	sqlite3_stmt *st = NULL;
	occ_task_event_row *v = NULL;
	size_t cnt = 0, cap = 0;

	if (!db || !id || !rows || !n) {
		set_err(err, errlen, "occ_task_events: bad args");
		return -1;
	}
	*rows = NULL;
	*n = 0;
	h = occ_db_sqlite(db);
	if (sqlite3_prepare_v2(h, sel, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "prepare: %s", sqlite3_errmsg(h));
		return -1;
	}
	sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
	while (sqlite3_step(st) == SQLITE_ROW) {
		if (cnt == cap) {
			occ_task_event_row *nv;

			cap = cap ? cap * 2 : 8;
			nv = realloc(v, cap * sizeof(*nv));
			if (!nv) {
				free(v);
				sqlite3_finalize(st);
				set_err(err, errlen, "oom");
				return -1;
			}
			v = nv;
		}
		memset(&v[cnt], 0, sizeof(v[cnt]));
		v[cnt].id = sqlite3_column_int64(st, 0);
		snprintf(v[cnt].task_id, sizeof(v[cnt].task_id), "%s",
			 sqlite3_column_text(st, 1));
		snprintf(v[cnt].kind, sizeof(v[cnt].kind), "%s",
			 sqlite3_column_text(st, 2));
		v[cnt].payload_json = col_strdup(st, 3);
		v[cnt].created = sqlite3_column_int64(st, 4);
		cnt++;
	}
	sqlite3_finalize(st);
	*rows = v;
	*n = cnt;
	return 0;
}

/* ---- 状态机（迁移表见 task.h 头注；非法迁移拒绝不静默） ---- */

int occ_task_create(occ_db *db, const char *parent_session,
		    const char *title, const char *brief_json,
		    int rework_max, occ_task_row *out,
		    char *err, size_t errlen)
{
	static const char *ins =
		"INSERT INTO occ_task"
		"  (id,parent_session,title,brief_json,status,rework_count,"
		"   rework_max,created,updated)"
		"  VALUES (?1,?2,?3,?4,?5,0,?6,?7,?7)";
	static const char *pchk = "SELECT 1 FROM occ_session WHERE id=?1";
	sqlite3 *h;
	sqlite3_stmt *st = NULL;
	long long now = now_ms();
	char id[OCC_ID_LEN];
	int rm = rework_max > 0 ? rework_max : OCC_TASK_REWORK_MAX_DEF;

	if (out)
		memset(out, 0, sizeof(*out));
	if (!db || !parent_session || !title || !brief_json) {
		set_err(err, errlen, "occ_task_create: bad args");
		return -1;
	}
	/* R2：缺省 2；brief 覆写上限 1-3，超界拒绝（不静默钳制） */
	if (rework_max > OCC_TASK_REWORK_MAX_HI) {
		set_err(err, errlen, "occ_task_create: rework_max %d 超界"
			"（覆写上限 1-%d）", rework_max,
			OCC_TASK_REWORK_MAX_HI);
		return -1;
	}
	h = occ_db_sqlite(db);
	/* 主会话必须存在（外键外再给人话错误——BAD 外键报错不友好） */
	if (sqlite3_prepare_v2(h, pchk, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "prepare: %s", sqlite3_errmsg(h));
		return -1;
	}
	sqlite3_bind_text(st, 1, parent_session, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(st) != SQLITE_ROW) {
		sqlite3_finalize(st);
		set_err(err, errlen, "occ_task_create: 主会话 %s 不存在",
			parent_session);
		return -1;
	}
	sqlite3_finalize(st);
	if (gen_id(id, sizeof(id))) {
		set_err(err, errlen, "occ_task_create: urandom");
		return -1;
	}
	if (tx_begin(db, err, errlen))
		return -1;
	if (sqlite3_prepare_v2(h, ins, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "prepare: %s", sqlite3_errmsg(h));
		tx_rollback(db);
		return -1;
	}
	sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 2, parent_session, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 3, title, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 4, brief_json, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 5, OCC_TASK_ST_PENDING, -1, SQLITE_STATIC);
	sqlite3_bind_int(st, 6, rm);
	sqlite3_bind_int64(st, 7, now);
	if (sqlite3_step(st) != SQLITE_DONE) {
		set_err(err, errlen, "step: %s", sqlite3_errmsg(h));
		sqlite3_finalize(st);
		tx_rollback(db);
		return -1;
	}
	sqlite3_finalize(st);
	if (tx_commit(db, err, errlen))
		return -1;
	if (out) {
		snprintf(out->id, sizeof(out->id), "%s", id);
		snprintf(out->parent_session, sizeof(out->parent_session),
			 "%s", parent_session);
		snprintf(out->title, sizeof(out->title), "%s", title);
		out->brief_json = strdup(brief_json);
		snprintf(out->status, sizeof(out->status), "%s",
			 OCC_TASK_ST_PENDING);
		out->rework_count = 0;
		out->rework_max = rm;
		out->created = now;
		out->updated = now;
	}
	return 0;
}

int occ_task_dispatch(occ_db *db, const char *id, const char *child_session,
		      char *err, size_t errlen)
{
	sqlite3 *h;
	sqlite3_stmt *st = NULL;
	char cur[16];
	int rc, rwc, rwm;

	if (!db || !id) {
		set_err(err, errlen, "occ_task_dispatch: bad args");
		return -1;
	}
	h = occ_db_sqlite(db);
	if (tx_begin(db, err, errlen))
		return -1;
	rc = task_state(db, id, cur, sizeof(cur), &rwc, &rwm);
	if (rc != 1) {
		tx_rollback(db);
		return task_state_fail(rc, id, "occ_task_dispatch", err,
				       errlen);
	}
	if (strcmp(cur, OCC_TASK_ST_PENDING) != 0 &&
	    strcmp(cur, OCC_TASK_ST_REWORK) != 0) {
		tx_rollback(db);
		set_err(err, errlen, "occ_task_dispatch: 非法迁移 %s→%s"
			"（dispatch 仅允许 pending/rework）", cur,
			OCC_TASK_ST_DISPATCHED);
		return -1;
	}
	if (task_set_status(db, id, OCC_TASK_ST_DISPATCHED)) {
		tx_rollback(db);
		set_err(err, errlen, "dispatch: %s", sqlite3_errmsg(h));
		return -1;
	}
	/* 子会话 id 派发后填（rework 回炉再派不传=沿用原值） */
	if (child_session && child_session[0]) {
		static const char *upd =
			"UPDATE occ_task SET child_session=?1 WHERE id=?2";

		if (sqlite3_prepare_v2(h, upd, -1, &st, NULL) != SQLITE_OK) {
			tx_rollback(db);
			set_err(err, errlen, "prepare: %s", sqlite3_errmsg(h));
			return -1;
		}
		sqlite3_bind_text(st, 1, child_session, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(st, 2, id, -1, SQLITE_TRANSIENT);
		if (sqlite3_step(st) != SQLITE_DONE) {
			sqlite3_finalize(st);
			tx_rollback(db);
			set_err(err, errlen, "step: %s", sqlite3_errmsg(h));
			return -1;
		}
		sqlite3_finalize(st);
	}
	if (ev_add(db, id, OCC_TASK_EV_DISPATCH, child_session)) {
		tx_rollback(db);
		set_err(err, errlen, "dispatch: 事件落库失败");
		return -1;
	}
	if (tx_commit(db, err, errlen))
		return -1;
	return 0;
}

int occ_task_review(occ_db *db, const char *id, const char *result_json,
		    char *err, size_t errlen)
{
	char cur[16];
	int rc, rwc, rwm;

	if (!db || !id) {
		set_err(err, errlen, "occ_task_review: bad args");
		return -1;
	}
	if (tx_begin(db, err, errlen))
		return -1;
	rc = task_state(db, id, cur, sizeof(cur), &rwc, &rwm);
	if (rc != 1) {
		tx_rollback(db);
		return task_state_fail(rc, id, "occ_task_review", err,
				       errlen);
	}
	if (strcmp(cur, OCC_TASK_ST_DISPATCHED) != 0) {
		tx_rollback(db);
		set_err(err, errlen, "occ_task_review: 非法迁移 %s→%s"
			"（review 仅允许 dispatched）", cur,
			OCC_TASK_ST_IN_REVIEW);
		return -1;
	}
	if (task_set_status(db, id, OCC_TASK_ST_IN_REVIEW) ||
	    ev_add(db, id, OCC_TASK_EV_RESULT, result_json)) {
		tx_rollback(db);
		set_err(err, errlen, "review: %s",
			sqlite3_errmsg(occ_db_sqlite(db)));
		return -1;
	}
	if (tx_commit(db, err, errlen))
		return -1;
	return 0;
}

int occ_task_verdict(occ_db *db, const char *id, int pass,
		     const char *verdict_json, char *err, size_t errlen)
{
	static const char *vput =
		"UPDATE occ_task SET verdict_json=?1, rework_count=?2,"
		" updated=?3 WHERE id=?4";
	sqlite3 *h;
	sqlite3_stmt *st = NULL;
	char cur[16];
	int rc, rwc, rwm, new_count;

	if (!db || !id) {
		set_err(err, errlen, "occ_task_verdict: bad args");
		return -1;
	}
	h = occ_db_sqlite(db);
	if (tx_begin(db, err, errlen))
		return -1;
	rc = task_state(db, id, cur, sizeof(cur), &rwc, &rwm);
	if (rc != 1) {
		tx_rollback(db);
		return task_state_fail(rc, id, "occ_task_verdict", err,
				       errlen);
	}
	if (strcmp(cur, OCC_TASK_ST_IN_REVIEW) != 0) {
		tx_rollback(db);
		set_err(err, errlen, "occ_task_verdict: 非法迁移 %s→裁决"
			"（verdict 仅允许 in_review）", cur);
		return -1;
	}
	new_count = pass ? rwc : rwc + 1;
	/* 裁决原文 + 回炉计数同事务落库（fail 现场可审计） */
	if (sqlite3_prepare_v2(h, vput, -1, &st, NULL) != SQLITE_OK) {
		tx_rollback(db);
		set_err(err, errlen, "prepare: %s", sqlite3_errmsg(h));
		return -1;
	}
	sqlite3_bind_text(st, 1, verdict_json ? verdict_json : "", -1,
			  SQLITE_TRANSIENT);
	sqlite3_bind_int(st, 2, new_count);
	sqlite3_bind_int64(st, 3, now_ms());
	sqlite3_bind_text(st, 4, id, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(st) != SQLITE_DONE) {
		sqlite3_finalize(st);
		tx_rollback(db);
		set_err(err, errlen, "step: %s", sqlite3_errmsg(h));
		return -1;
	}
	sqlite3_finalize(st);
	if (ev_add(db, id, OCC_TASK_EV_VERDICT, verdict_json)) {
		tx_rollback(db);
		set_err(err, errlen, "verdict: 事件落库失败");
		return -1;
	}
	if (pass) {
		if (task_set_status(db, id, OCC_TASK_ST_DONE) ||
		    ev_add(db, id, OCC_TASK_EV_DONE, verdict_json)) {
			tx_rollback(db);
			set_err(err, errlen, "verdict: done 落库失败");
			return -1;
		}
	} else if (new_count <= rwm) {
		if (task_set_status(db, id, OCC_TASK_ST_REWORK) ||
		    ev_add(db, id, OCC_TASK_EV_REWORK, verdict_json)) {
			tx_rollback(db);
			set_err(err, errlen, "verdict: rework 落库失败");
			return -1;
		}
	} else {
		if (task_set_status(db, id, OCC_TASK_ST_ESCALATED) ||
		    ev_add(db, id, OCC_TASK_EV_ESCALATE, verdict_json)) {
			tx_rollback(db);
			set_err(err, errlen, "verdict: escalate 落库失败");
			return -1;
		}
	}
	if (tx_commit(db, err, errlen))
		return -1;
	return 0;
}

int occ_task_escalate(occ_db *db, const char *id, const char *reason_json,
		      char *err, size_t errlen)
{
	char cur[16];
	int rc, rwc, rwm;

	if (!db || !id) {
		set_err(err, errlen, "occ_task_escalate: bad args");
		return -1;
	}
	if (tx_begin(db, err, errlen))
		return -1;
	rc = task_state(db, id, cur, sizeof(cur), &rwc, &rwm);
	if (rc != 1) {
		tx_rollback(db);
		return task_state_fail(rc, id, "occ_task_escalate", err,
				       errlen);
	}
	if (strcmp(cur, OCC_TASK_ST_DISPATCHED) != 0 &&
	    strcmp(cur, OCC_TASK_ST_IN_REVIEW) != 0 &&
	    strcmp(cur, OCC_TASK_ST_REWORK) != 0) {
		tx_rollback(db);
		set_err(err, errlen, "occ_task_escalate: 非法迁移 %s→%s"
			"（escalate 仅允许 dispatched/in_review/rework）",
			cur, OCC_TASK_ST_ESCALATED);
		return -1;
	}
	if (task_set_status(db, id, OCC_TASK_ST_ESCALATED) ||
	    ev_add(db, id, OCC_TASK_EV_ESCALATE, reason_json)) {
		tx_rollback(db);
		set_err(err, errlen, "escalate: %s",
			sqlite3_errmsg(occ_db_sqlite(db)));
		return -1;
	}
	if (tx_commit(db, err, errlen))
		return -1;
	return 0;
}

int occ_task_distill(occ_db *db, const char *id, const char *payload_json,
		     char *err, size_t errlen)
{
	char cur[16];
	int rc, rwc, rwm;

	if (!db || !id) {
		set_err(err, errlen, "occ_task_distill: bad args");
		return -1;
	}
	if (tx_begin(db, err, errlen))
		return -1;
	rc = task_state(db, id, cur, sizeof(cur), &rwc, &rwm);
	if (rc != 1) {
		tx_rollback(db);
		return task_state_fail(rc, id, "occ_task_distill", err,
				       errlen);
	}
	if (strcmp(cur, OCC_TASK_ST_DONE) != 0) {
		tx_rollback(db);
		set_err(err, errlen, "occ_task_distill: 非法迁移 %s→distill"
			"（distill 仅允许 done——未完成/上抛任务无蒸馏）",
			cur);
		return -1;
	}
	if (ev_add(db, id, OCC_TASK_EV_DISTILL, payload_json)) {
		tx_rollback(db);
		set_err(err, errlen, "distill: 事件落库失败");
		return -1;
	}
	if (tx_commit(db, err, errlen))
		return -1;
	return 0;
}
