/* SPDX-License-Identifier: GPL-2.0 */
/*
 * store_sqlite.c - SQLite 单文件存储实现（T2b-2）
 *
 * 设计依据 T2-DESIGN.md §5/§7.1 与 T2b-2 契约；语义对齐参考实现
 * sme/storage/backends.py（SqliteBackend）与 sme/storage/wal.py。
 * 详见 store_sqlite.h 的 API 注释。
 */
#define _POSIX_C_SOURCE 200809L

#include "store/store_sqlite.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sqlite3.h"

struct aik_sqlite {
	sqlite3 *db;
};

/* ------------------------------------------------------------------ */
/* 错误与通用执行                                                      */
/* ------------------------------------------------------------------ */

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || errlen == 0)
		return;
	va_start(ap, fmt);
	(void)vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

/* 以 sqlite3_errmsg 生成 "sqlite: <what>: <msg>"，返回 -1 */
static int fail_db(const aik_sqlite *db, const char *what,
		   char *err, size_t errlen)
{
	const char *msg = (db && db->db) ? sqlite3_errmsg(db->db)
					 : "database is closed";

	set_err(err, errlen, "sqlite: %s: %s", what, msg);
	return -1;
}

static int exec_sql(const aik_sqlite *db, const char *sql)
{
	char *msg = NULL;
	int rc;

	if (!db || !db->db)
		return SQLITE_MISUSE;
	rc = sqlite3_exec(db->db, sql, NULL, NULL, &msg);
	sqlite3_free(msg);
	return rc;
}

/* 1 存在 / 0 不存在 / -1 查询失败（错误留在 db 里） */
static int table_exists(const aik_sqlite *db, const char *name)
{
	static const char sql[] =
		"SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1";
	sqlite3_stmt *st = NULL;
	int rc, found = 0;

	if (!db || !db->db)
		return -1;
	rc = sqlite3_prepare_v2(db->db, sql, -1, &st, NULL);
	if (rc != SQLITE_OK)
		return -1;
	(void)sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
	rc = sqlite3_step(st);
	if (rc == SQLITE_ROW)
		found = 1;
	else if (rc != SQLITE_DONE) {
		(void)sqlite3_finalize(st);
		return -1;
	}
	(void)sqlite3_finalize(st);
	return found;
}

/* 递归建目录（create 路径；已存在视为成功） */
static int mkdir_p(const char *dir)
{
	char buf[4096];
	size_t i, n = strlen(dir);

	if (n == 0 || n >= sizeof(buf))
		return n == 0 ? 0 : -1;
	memcpy(buf, dir, n + 1);
	for (i = 1; i < n; i++) {
		if (buf[i] != '/')
			continue;
		buf[i] = '\0';
		if (mkdir(buf, 0777) != 0 && errno != EEXIST)
			return -1;
		buf[i] = '/';
	}
	if (mkdir(buf, 0777) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

/* 返回 path 的目录部分（malloc，去掉末尾 '/'；无目录时返回 ""） */
static char *dir_of(const char *path)
{
	const char *slash = strrchr(path, '/');
	size_t n;
	char *out;

	if (!slash)
		return strdup("");
	n = (size_t)(slash - path);
	while (n > 1 && path[n - 1] == '/')
		n--;
	out = malloc(n + 1);
	if (!out)
		return NULL;
	memcpy(out, path, n);
	out[n] = '\0';
	return out;
}

/* ------------------------------------------------------------------ */
/* 打开 / 关闭                                                         */
/* ------------------------------------------------------------------ */

static int create_base_schema(aik_sqlite *db)
{
	if (exec_sql(db,
		     "CREATE TABLE IF NOT EXISTS snapshots ("
		     " id INTEGER PRIMARY KEY, payload TEXT, saved_at REAL)") !=
	    SQLITE_OK)
		return -1;
	if (exec_sql(db,
		     "CREATE TABLE IF NOT EXISTS vectors ("
		     " memory_id TEXT PRIMARY KEY, blob BLOB NOT NULL)") !=
	    SQLITE_OK)
		return -1;
	return 0;
}

aik_sqlite *aik_sqlite_open(const char *path, int create,
			    char *err, size_t errlen)
{
	aik_sqlite *db;
	int flags, rc;

	if (!path || !*path) {
		set_err(err, errlen, "sqlite: open: empty path");
		return NULL;
	}
	if (create) {
		char *dir = dir_of(path);

		if (!dir) {
			set_err(err, errlen, "sqlite: open: out of memory");
			return NULL;
		}
		if (*dir && mkdir_p(dir) != 0) {
			set_err(err, errlen, "sqlite: open: cannot create %s: %s",
				dir, strerror(errno));
			free(dir);
			return NULL;
		}
		free(dir);
	}

	db = calloc(1, sizeof(*db));
	if (!db) {
		set_err(err, errlen, "sqlite: open: out of memory");
		return NULL;
	}
	flags = SQLITE_OPEN_READWRITE | (create ? SQLITE_OPEN_CREATE : 0);
	rc = sqlite3_open_v2(path, &db->db, flags, NULL);
	if (rc != SQLITE_OK) {
		set_err(err, errlen, "sqlite: open %s: %s", path,
			db->db ? sqlite3_errmsg(db->db) : sqlite3_errstr(rc));
		if (db->db)
			(void)sqlite3_close(db->db);
		free(db);
		return NULL;
	}
	/* 与参考 _connect() 一致：跨进程文件锁竞争的兜底 */
	(void)sqlite3_busy_timeout(db->db, 5000);
	if (create && create_base_schema(db) != 0) {
		(void)fail_db(db, "open: create tables", err, errlen);
		(void)sqlite3_close(db->db);
		free(db);
		return NULL;
	}
	return db;
}

void aik_sqlite_close(aik_sqlite *db)
{
	if (!db)
		return;
	if (db->db)
		(void)sqlite3_close(db->db);
	free(db);
}

void *aik_sqlite_handle(const aik_sqlite *db)
{
	return db ? db->db : NULL;
}

int aik_sqlite_busy_timeout(aik_sqlite *db, int ms,
			    char *err, size_t errlen)
{
	if (!db || !db->db) {
		set_err(err, errlen, "sqlite: busy_timeout: invalid handle");
		return -1;
	}
	if (sqlite3_busy_timeout(db->db, ms) != SQLITE_OK)
		return fail_db(db, "busy_timeout", err, errlen);
	return 0;
}

int aik_sqlite_busy_timeout_get(aik_sqlite *db, int *ms,
				char *err, size_t errlen)
{
	sqlite3_stmt *st = NULL;
	int rc;

	if (!db || !db->db || !ms) {
		set_err(err, errlen, "sqlite: busy_timeout_get: invalid argument");
		return -1;
	}
	rc = sqlite3_prepare_v2(db->db, "PRAGMA busy_timeout", -1, &st, NULL);
	if (rc != SQLITE_OK)
		return fail_db(db, "busy_timeout_get", err, errlen);
	rc = sqlite3_step(st);
	if (rc != SQLITE_ROW) {
		(void)sqlite3_finalize(st);
		return fail_db(db, "busy_timeout_get", err, errlen);
	}
	*ms = sqlite3_column_int(st, 0);
	(void)sqlite3_finalize(st);
	return 0;
}

/* ------------------------------------------------------------------ */
/* snapshots                                                           */
/* ------------------------------------------------------------------ */

int aik_sqlite_save_snapshot(aik_sqlite *db, const char *payload_json,
			     double saved_at, char *err, size_t errlen)
{
	sqlite3_stmt *st = NULL;

	if (!db || !db->db || !payload_json) {
		set_err(err, errlen, "sqlite: save_snapshot: invalid argument");
		return -1;
	}
	if (exec_sql(db, "BEGIN") != SQLITE_OK)
		return fail_db(db, "save_snapshot: begin", err, errlen);
	if (exec_sql(db, "DELETE FROM snapshots") != SQLITE_OK)
		goto fail;
	/*
	 * 参考 save() 是全量替换：先 DELETE FROM vectors，再逐条
	 * INSERT OR REPLACE。这里清空旧向量，调用者随后用 put_vector
	 * 重写本次快照的向量。
	 */
	if (exec_sql(db, "DELETE FROM vectors") != SQLITE_OK)
		goto fail;
	if (sqlite3_prepare_v2(db->db,
			       "INSERT INTO snapshots (payload, saved_at)"
			       " VALUES (?1, ?2)",
			       -1, &st, NULL) != SQLITE_OK)
		goto fail;
	(void)sqlite3_bind_text(st, 1, payload_json, -1, SQLITE_TRANSIENT);
	(void)sqlite3_bind_double(st, 2, saved_at);
	if (sqlite3_step(st) != SQLITE_DONE)
		goto fail;
	(void)sqlite3_finalize(st);
	st = NULL;
	if (exec_sql(db, "COMMIT") != SQLITE_OK) {
		(void)exec_sql(db, "ROLLBACK");
		return fail_db(db, "save_snapshot: commit", err, errlen);
	}
	return 0;

fail:
	if (st)
		(void)sqlite3_finalize(st);
	(void)exec_sql(db, "ROLLBACK");
	return fail_db(db, "save_snapshot", err, errlen);
}

int aik_sqlite_load_snapshot(aik_sqlite *db, char **payload_json,
			     double *saved_at, char *err, size_t errlen)
{
	sqlite3_stmt *st = NULL;
	int rc, te;

	if (!db || !db->db || !payload_json || !saved_at) {
		set_err(err, errlen, "sqlite: load_snapshot: invalid argument");
		return -1;
	}
	*payload_json = NULL;
	*saved_at = 0.0;

	te = table_exists(db, "snapshots");
	if (te == 0) {
		set_err(err, errlen, "sqlite: load_snapshot: missing table snapshots");
		return -1;
	}
	if (te < 0)
		return fail_db(db, "load_snapshot: schema", err, errlen);
	te = table_exists(db, "vectors");
	if (te == 0) {
		set_err(err, errlen, "sqlite: load_snapshot: missing table vectors");
		return -1;
	}
	if (te < 0)
		return fail_db(db, "load_snapshot: schema", err, errlen);

	rc = sqlite3_prepare_v2(db->db,
				"SELECT payload, saved_at FROM snapshots"
				" ORDER BY id DESC LIMIT 1",
				-1, &st, NULL);
	if (rc != SQLITE_OK)
		return fail_db(db, "load_snapshot: prepare", err, errlen);
	rc = sqlite3_step(st);
	if (rc == SQLITE_DONE) {
		(void)sqlite3_finalize(st);
		return 0;
	}
	if (rc != SQLITE_ROW) {
		(void)sqlite3_finalize(st);
		return fail_db(db, "load_snapshot: select", err, errlen);
	}
	{
		const unsigned char *txt = sqlite3_column_text(st, 0);
		int n = sqlite3_column_bytes(st, 0);
		char *copy = malloc((size_t)(n > 0 ? n : 0) + 1);

		if (!copy) {
			(void)sqlite3_finalize(st);
			set_err(err, errlen, "sqlite: load_snapshot: out of memory");
			return -1;
		}
		if (txt && n > 0)
			memcpy(copy, txt, (size_t)n);
		copy[n > 0 ? n : 0] = '\0';
		*payload_json = copy;
	}
	*saved_at = sqlite3_column_double(st, 1);
	(void)sqlite3_finalize(st);
	return 0;
}

/* ------------------------------------------------------------------ */
/* vectors                                                             */
/* ------------------------------------------------------------------ */

int aik_sqlite_put_vector(aik_sqlite *db, const char *memory_id,
			  const void *blob, size_t len,
			  char *err, size_t errlen)
{
	sqlite3_stmt *st = NULL;

	if (!db || !db->db || !memory_id || (!blob && len != 0) ||
	    len > (size_t)0x7fffffff) {
		set_err(err, errlen, "sqlite: put_vector: invalid argument");
		return -1;
	}
	if (exec_sql(db, "BEGIN") != SQLITE_OK)
		return fail_db(db, "put_vector: begin", err, errlen);
	if (sqlite3_prepare_v2(db->db,
			       "DELETE FROM vectors WHERE memory_id = ?1",
			       -1, &st, NULL) != SQLITE_OK)
		goto fail;
	(void)sqlite3_bind_text(st, 1, memory_id, -1, SQLITE_STATIC);
	if (sqlite3_step(st) != SQLITE_DONE)
		goto fail;
	(void)sqlite3_finalize(st);
	st = NULL;

	if (sqlite3_prepare_v2(db->db,
			       "INSERT OR REPLACE INTO vectors"
			       " (memory_id, blob) VALUES (?1, ?2)",
			       -1, &st, NULL) != SQLITE_OK)
		goto fail;
	(void)sqlite3_bind_text(st, 1, memory_id, -1, SQLITE_STATIC);
	if (len == 0)
		(void)sqlite3_bind_zeroblob(st, 2, 0);
	else
		(void)sqlite3_bind_blob(st, 2, blob, (int)len,
					SQLITE_TRANSIENT);
	if (sqlite3_step(st) != SQLITE_DONE)
		goto fail;
	(void)sqlite3_finalize(st);
	st = NULL;
	if (exec_sql(db, "COMMIT") != SQLITE_OK) {
		(void)exec_sql(db, "ROLLBACK");
		return fail_db(db, "put_vector: commit", err, errlen);
	}
	return 0;

fail:
	if (st)
		(void)sqlite3_finalize(st);
	(void)exec_sql(db, "ROLLBACK");
	return fail_db(db, "put_vector", err, errlen);
}

int aik_sqlite_for_each_vector(aik_sqlite *db, aik_sqlite_vec_visit fn,
			       void *ctx, char *err, size_t errlen)
{
	sqlite3_stmt *st = NULL;
	int rc, te;

	if (!db || !db->db || !fn) {
		set_err(err, errlen, "sqlite: for_each_vector: invalid argument");
		return -1;
	}
	te = table_exists(db, "vectors");
	if (te == 0) {
		set_err(err, errlen, "sqlite: for_each_vector: missing table vectors");
		return -1;
	}
	if (te < 0)
		return fail_db(db, "for_each_vector: schema", err, errlen);

	rc = sqlite3_prepare_v2(db->db,
				"SELECT memory_id, blob FROM vectors ORDER BY rowid",
				-1, &st, NULL);
	if (rc != SQLITE_OK)
		return fail_db(db, "for_each_vector: prepare", err, errlen);
	for (;;) {
		const char *id;
		const void *blob;
		int n;
		char msg[256] = "";

		rc = sqlite3_step(st);
		if (rc == SQLITE_DONE)
			break;
		if (rc != SQLITE_ROW) {
			(void)sqlite3_finalize(st);
			return fail_db(db, "for_each_vector: step", err, errlen);
		}
		id = (const char *)sqlite3_column_text(st, 0);
		if (!id) {
			(void)sqlite3_finalize(st);
			set_err(err, errlen,
				"sqlite: for_each_vector: NULL memory_id");
			return -1;
		}
		blob = sqlite3_column_blob(st, 1);
		n = sqlite3_column_bytes(st, 1);
		if (fn(ctx, id, n > 0 ? blob : "", (size_t)(n > 0 ? n : 0),
		       msg, sizeof(msg)) != 0) {
			(void)sqlite3_finalize(st);
			set_err(err, errlen, "sqlite: vector %s: %s", id,
				msg[0] ? msg : "visitor failed");
			return -1;
		}
	}
	(void)sqlite3_finalize(st);
	return 0;
}

/* ------------------------------------------------------------------ */
/* WAL（sqlite 分支）                                                  */
/* ------------------------------------------------------------------ */

/* 惰性建表；已存在时不执行任何写语句（保证只读打开参考库不改文件） */
static int ensure_wal_table(aik_sqlite *db)
{
	int te = table_exists(db, "wal_ops");

	if (te < 0)
		return -1;
	if (te == 1)
		return 0;
	if (exec_sql(db,
		     "CREATE TABLE IF NOT EXISTS wal_ops ("
		     " seq INTEGER PRIMARY KEY AUTOINCREMENT,"
		     " op TEXT NOT NULL)") != SQLITE_OK)
		return -1;
	return 0;
}

int aik_sqlite_wal_append(aik_sqlite *db, const char *op_json,
			  long long *seq, char *err, size_t errlen)
{
	sqlite3_stmt *st = NULL;

	if (!db || !db->db || !op_json) {
		set_err(err, errlen, "sqlite: wal_append: invalid argument");
		return -1;
	}
	if (ensure_wal_table(db) != 0)
		return fail_db(db, "wal_append: create table", err, errlen);
	if (exec_sql(db, "BEGIN") != SQLITE_OK)
		return fail_db(db, "wal_append: begin", err, errlen);
	if (sqlite3_prepare_v2(db->db,
			       "INSERT INTO wal_ops (op) VALUES (?1)",
			       -1, &st, NULL) != SQLITE_OK)
		goto fail;
	(void)sqlite3_bind_text(st, 1, op_json, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(st) != SQLITE_DONE)
		goto fail;
	(void)sqlite3_finalize(st);
	st = NULL;
	if (seq)
		*seq = sqlite3_last_insert_rowid(db->db);
	if (exec_sql(db, "COMMIT") != SQLITE_OK) {
		(void)exec_sql(db, "ROLLBACK");
		return fail_db(db, "wal_append: commit", err, errlen);
	}
	return 0;

fail:
	if (st)
		(void)sqlite3_finalize(st);
	(void)exec_sql(db, "ROLLBACK");
	return fail_db(db, "wal_append", err, errlen);
}

int aik_sqlite_wal_replay(aik_sqlite *db, long long checkpoint,
			  aik_wal_visit fn, void *ctx,
			  char *err, size_t errlen)
{
	sqlite3_stmt *st = NULL;
	int rc, count = 0;
	long long index = 0;

	if (!db || !db->db) {
		set_err(err, errlen, "sqlite: wal_replay: invalid handle");
		return -1;
	}
	if (ensure_wal_table(db) != 0)
		return fail_db(db, "wal_replay: create table", err, errlen);
	/* 表内 seq 只用于排序；checkpoint 判定用 op 内嵌的 "seq"（参考实现） */
	rc = sqlite3_prepare_v2(db->db,
				"SELECT seq, op FROM wal_ops ORDER BY seq",
				-1, &st, NULL);
	if (rc != SQLITE_OK)
		return fail_db(db, "wal_replay: prepare", err, errlen);
	for (;;) {
		long long table_seq;
		const unsigned char *txt;
		int n;
		aik_json *op;
		const aik_json *jseq;
		long long seq;
		char perr[256] = "";

		rc = sqlite3_step(st);
		if (rc == SQLITE_DONE)
			break;
		if (rc != SQLITE_ROW) {
			(void)sqlite3_finalize(st);
			return fail_db(db, "wal_replay: step", err, errlen);
		}
		index++;
		table_seq = sqlite3_column_int64(st, 0);
		txt = sqlite3_column_text(st, 1);
		n = sqlite3_column_bytes(st, 1);
		if (!txt) {
			(void)sqlite3_finalize(st);
			set_err(err, errlen, "sqlite: wal record %lld: NULL op",
				index);
			return -1;
		}
		op = aik_json_parse((const char *)txt, (size_t)n,
				    perr, sizeof(perr));
		if (!op) {
			(void)sqlite3_finalize(st);
			set_err(err, errlen, "sqlite: wal record %lld: %s", index,
				perr);
			return -1;
		}
		if (aik_json_typeof(op) != AIK_JSON_OBJ) {
			aik_json_free(op);
			(void)sqlite3_finalize(st);
			set_err(err, errlen,
				"sqlite: wal record %lld: WAL record must be an object",
				index);
			return -1;
		}
		/*
		 * 参考 wal.py：
		 *   seq = op.get("seq", 0)
		 *   if not isinstance(seq, int) or seq < 0: raise
		 *   if seq and seq <= checkpoint: continue
		 * 缺失按 0 处理，0 永不因 checkpoint 跳过。
		 */
		jseq = aik_json_get(op, "seq");
		if (!jseq) {
			seq = 0;
		} else if (aik_json_typeof(jseq) != AIK_JSON_INT) {
			aik_json_free(op);
			(void)sqlite3_finalize(st);
			set_err(err, errlen,
				"sqlite: wal record %lld: invalid WAL sequence (table seq %lld)",
				index, table_seq);
			return -1;
		} else {
			seq = aik_json_int(jseq);
			if (seq < 0) {
				aik_json_free(op);
				(void)sqlite3_finalize(st);
				set_err(err, errlen,
					"sqlite: wal record %lld: invalid WAL sequence (table seq %lld)",
					index, table_seq);
				return -1;
			}
		}
		if (seq > 0 && seq <= checkpoint) {
			aik_json_free(op);
			continue;
		}
		if (fn) {
			char cerr[256] = "";

			if (fn(ctx, op, cerr, sizeof(cerr)) != 0) {
				aik_json_free(op);
				(void)sqlite3_finalize(st);
				set_err(err, errlen,
					"sqlite: wal record %lld: %s", index,
					cerr[0] ? cerr : "visitor failed");
				return -1;
			}
		}
		aik_json_free(op);
		count++;
	}
	(void)sqlite3_finalize(st);
	return count;
}

int aik_sqlite_wal_clear(aik_sqlite *db, char *err, size_t errlen)
{
	if (!db || !db->db) {
		set_err(err, errlen, "sqlite: wal_clear: invalid handle");
		return -1;
	}
	if (ensure_wal_table(db) != 0)
		return fail_db(db, "wal_clear: create table", err, errlen);
	if (exec_sql(db, "DELETE FROM wal_ops") != SQLITE_OK)
		return fail_db(db, "wal_clear", err, errlen);
	return 0;
}
