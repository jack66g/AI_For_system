/* SPDX-License-Identifier: GPL-2.0 */
/*
 * session.c - occ 会话生命周期 + SQLite 持久化（T9a3）
 *
 * SQLite 引擎只读复用 T2 store 产出：链接 ../store/libsqlite3.a
 * （amalgamation 编译开关同 store/Makefile SQLITE_CFLAGS：
 *  -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_THREADSAFE=1），本文件经原生
 * sqlite3 C API 管理 occ 自有 schema（schema 详见 occ_session.h 头注）。
 *
 * PRAGMA 对齐 T2 store_sqlite 约定：busy_timeout=5000；另开
 * foreign_keys=ON（CASCADE）与 user_version=1（迁移锚点）。
 * 崩溃安全：每消息单事务（BEGIN IMMEDIATE…COMMIT；任一步失败即
 * ROLLBACK——kill -9 由 SQLite 自身崩溃恢复保证同样语义：未提交事务
 * 回滚，库中只可能出现整条消息，绝不半条）。
 */
#define _POSIX_C_SOURCE 200809L
#include "occ_session.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <sqlite3.h>

#include "store/store_json.h"

struct occ_db {
	sqlite3 *h;
	char path[512];
};

/* 测试注入 mask（bit0=add_user COMMIT 前失败；bit1=add_assistant 同上） */
static int g_test_fault;

int occ_db_test_fault(int mask)
{
	int old = g_test_fault;

	g_test_fault = mask;
	return old;
}

/* ---- 小工具 ---- */

static long long now_ms(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* /dev/urandom → id（"ses_"/"msg_" + 16 字节 hex = 32 字符） */
static int gen_id(char *buf, size_t buflen, const char *prefix)
{
	unsigned char rb[16];
	size_t plen = strlen(prefix);
	size_t i;
	int fd;

	if (buflen < plen + 32 + 1)
		return -1;
	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return -1;
	if (read(fd, rb, sizeof(rb)) != (ssize_t)sizeof(rb)) {
		close(fd);
		return -1;
	}
	close(fd);
	memcpy(buf, prefix, plen);
	for (i = 0; i < sizeof(rb); i++) {
		buf[plen + i * 2] = "0123456789abcdef"[rb[i] >> 4];
		buf[plen + i * 2 + 1] = "0123456789abcdef"[rb[i] & 0xF];
	}
	buf[plen + 32] = '\0';
	return 0;
}

/* UTF-8 安全前缀截断（不切断多字节序列；截短时追加 U+2026） */
static void utf8_prefix(const char *src, char *dst, size_t dstlen)
{
	size_t n = 0, i = 0;

	if (!src)
		src = "";
	while (src[i]) {
		unsigned char c = (unsigned char)src[i];
		size_t len = 1;

		if (c >= 0xF0)
			len = 4;
		else if (c >= 0xE0)
			len = 3;
		else if (c >= 0xC0)
			len = 2;
		if (!src[i + len - 1])		/* 尾部残缺多字节整体丢弃 */
			break;
		if (n + len + 4 > dstlen)	/* 留 "…"(3B) + NUL 余量 */
			break;
		memcpy(dst + n, src + i, len);
		n += len;
		i += len;
	}
	dst[n] = '\0';
	if (src[i]) {
		dst[n++] = (char)0xE2;
		dst[n++] = (char)0x80;
		dst[n++] = (char)0xA6;		/* U+2026 HORIZONTAL ELLIPSIS */
		dst[n] = '\0';
	}
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

/* ---- DB 生命周期 ---- */

static const char OCC_DDL[] =
	"CREATE TABLE IF NOT EXISTS occ_session ("
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
	"CREATE TABLE IF NOT EXISTS occ_message ("
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
	"CREATE INDEX IF NOT EXISTS occ_message_session"
	"  ON occ_message(session_id, created);"
	"CREATE TABLE IF NOT EXISTS occ_toolcall ("
	"  id TEXT PRIMARY KEY,"
	"  message_id TEXT NOT NULL"
	"    REFERENCES occ_message(id) ON DELETE CASCADE,"
	"  tool TEXT NOT NULL,"
	"  args_json TEXT,"
	"  result_json TEXT,"
	"  rc INTEGER,"
	"  dur_ms INTEGER"
	");"
	"CREATE TABLE IF NOT EXISTS occ_window ("
	"  session_id TEXT PRIMARY KEY"
	"    REFERENCES occ_session(id) ON DELETE CASCADE,"
	"  base_kind TEXT NOT NULL DEFAULT 'native',"
	"  digest_id TEXT"
	");"
	"CREATE TABLE IF NOT EXISTS occ_revert ("
	"  session_id TEXT PRIMARY KEY"
	"    REFERENCES occ_session(id) ON DELETE CASCADE,"
	"  boundary_msg TEXT NOT NULL,"
	"  note_msg TEXT NOT NULL,"
	"  created INTEGER NOT NULL,"
	"  files_json TEXT NOT NULL DEFAULT '',"
	"  hidden_json TEXT NOT NULL DEFAULT ''"
	");";

/*
 * schema v1→v2 迁移（T9b2）：occ_message+reverted、新表 occ_revert。
 * 旧库（user_version=1）无损升级：ALTER 容忍重复列（b1/b2 新建库 DDL
 * 已含列，ALTER 报 duplicate column 视为已迁移）。
 */
static int occ_migrate_v2(occ_db *db, char *err, size_t errlen)
{
	sqlite3_stmt *st = NULL;
	int uv = 0;
	char *perr = NULL;

	if (sqlite3_prepare_v2(db->h, "PRAGMA user_version", -1, &st, NULL)
	    != SQLITE_OK) {
		set_err(err, errlen, "migrate: %s", sqlite3_errmsg(db->h));
		return -1;
	}
	if (sqlite3_step(st) == SQLITE_ROW)
		uv = sqlite3_column_int(st, 0);
	sqlite3_finalize(st);
	if (uv >= 2)
		return 0;
	/* duplicate column = 新建库已带列（DDL 先行）——非错误 */
	sqlite3_exec(db->h, "ALTER TABLE occ_message ADD COLUMN reverted"
		    " INTEGER NOT NULL DEFAULT 0;", NULL, NULL, &perr);
	sqlite3_free(perr);
	perr = NULL;
	sqlite3_exec(db->h, "ALTER TABLE occ_session ADD COLUMN workdir"
		    " TEXT NOT NULL DEFAULT '';", NULL, NULL, &perr);
	sqlite3_free(perr);
	perr = NULL;
	if (sqlite3_exec(db->h, "CREATE TABLE IF NOT EXISTS occ_revert ("
			"  session_id TEXT PRIMARY KEY"
			"    REFERENCES occ_session(id) ON DELETE CASCADE,"
			"  boundary_msg TEXT NOT NULL,"
			"  note_msg TEXT NOT NULL,"
			"  created INTEGER NOT NULL,"
			"  files_json TEXT NOT NULL DEFAULT '',"
			"  hidden_json TEXT NOT NULL DEFAULT '');",
			NULL, NULL, &perr) != SQLITE_OK) {
		set_err(err, errlen, "migrate revert: %s",
			perr ? perr : sqlite3_errmsg(db->h));
		sqlite3_free(perr);
		return -1;
	}
	/* b2 中期开发库（无 hidden_json 列）→ 补列 */
	perr = NULL;
	sqlite3_exec(db->h, "ALTER TABLE occ_revert ADD COLUMN hidden_json"
		    " TEXT NOT NULL DEFAULT '';", NULL, NULL, &perr);
	sqlite3_free(perr);
	perr = NULL;
	if (sqlite3_exec(db->h, "PRAGMA user_version=2;", NULL, NULL, &perr)
	    != SQLITE_OK) {
		set_err(err, errlen, "migrate uv: %s",
			perr ? perr : sqlite3_errmsg(db->h));
		sqlite3_free(perr);
		return -1;
	}
	return 0;
}

static int occ_default_db_path(char *buf, size_t buflen)
{
	const char *home = getenv("HOME");

	if (!home)
		return -1;
	if ((size_t)snprintf(buf, buflen, "%s/.occ/sessions.db", home) >= buflen)
		return -1;
	return 0;
}

static int mkdirs(const char *path)
{
	char tmp[512];
	char *p;

	snprintf(tmp, sizeof(tmp), "%s", path);
	for (p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(tmp, 0755) && errno != EEXIST)
				return -1;
			*p = '/';
		}
	}
	/* 最终目录本身（循环只覆盖到倒数第二层） */
	return mkdir(tmp, 0755) && errno != EEXIST ? -1 : 0;
}

occ_db *occ_db_open(const char *path, char *err, size_t errlen)
{
	occ_db *db;
	char dir[512];
	char *slash;
	char *perr = NULL;

	db = calloc(1, sizeof(*db));
	if (!db) {
		set_err(err, errlen, "occ_db_open: oom");
		return NULL;
	}
	if (!path) {
		if (occ_default_db_path(db->path, sizeof(db->path))) {
			set_err(err, errlen, "occ_db_open: no HOME");
			free(db);
			return NULL;
		}
	} else if (snprintf(db->path, sizeof(db->path), "%s", path) >=
		   (int)sizeof(db->path)) {
		set_err(err, errlen, "occ_db_open: path too long");
		free(db);
		return NULL;
	}
	/* 递归建父目录（T2 aik_sqlite_open 同语义） */
	snprintf(dir, sizeof(dir), "%s", db->path);
	slash = strrchr(dir, '/');
	if (slash && slash != dir) {
		*slash = '\0';
		if (mkdirs(dir) && errno != EEXIST) {
			set_err(err, errlen, "occ_db_open: mkdir %s: %s",
				dir, strerror(errno));
			free(db);
			return NULL;
		}
	}
	if (sqlite3_open_v2(db->path, &db->h,
			    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
			    SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK) {
		set_err(err, errlen, "occ_db_open: %s",
			db->h ? sqlite3_errmsg(db->h) : "open failed");
		if (db->h)
			sqlite3_close(db->h);
		free(db);
		return NULL;
	}
	/* 忙等 5s（T2 约定）+ 外键 + schema + v1→v2 迁移 */
	if (sqlite3_exec(db->h, "PRAGMA busy_timeout=5000;"
			"PRAGMA foreign_keys=ON;", NULL, NULL, &perr) != SQLITE_OK ||
	    sqlite3_exec(db->h, OCC_DDL, NULL, NULL, &perr) != SQLITE_OK ||
	    occ_migrate_v2(db, err, errlen)) {
		set_err(err, errlen, "occ_db_open: %s",
			perr ? perr : (err && err[0]) ? err : "init failed");
		sqlite3_free(perr);
		occ_db_close(db);
		return NULL;
	}
	return db;
}

void occ_db_close(occ_db *db)
{
	if (!db)
		return;
	sqlite3_close(db->h);		/* 未提交事务由 sqlite 回滚 */
	free(db);
}

const char *occ_db_path(const occ_db *db)
{
	return db ? db->path : "(null)";
}

/* ---- 事务助手 ---- */

static int tx_begin(occ_db *db, char *err, size_t errlen)
{
	char *perr = NULL;

	if (sqlite3_exec(db->h, "BEGIN IMMEDIATE", NULL, NULL, &perr) !=
	    SQLITE_OK) {
		set_err(err, errlen, "tx_begin: %s",
			perr ? perr : sqlite3_errmsg(db->h));
		sqlite3_free(perr);
		return -1;
	}
	return 0;
}

static void tx_rollback(occ_db *db)
{
	sqlite3_exec(db->h, "ROLLBACK", NULL, NULL, NULL);
}

static int tx_commit(occ_db *db, char *err, size_t errlen)
{
	char *perr = NULL;

	if (sqlite3_exec(db->h, "COMMIT", NULL, NULL, &perr) != SQLITE_OK) {
		set_err(err, errlen, "tx_commit: %s",
			perr ? perr : sqlite3_errmsg(db->h));
		sqlite3_free(perr);
		tx_rollback(db);
		return -1;
	}
	return 0;
}

/* 单串绑定执行（UPDATE 类） */
static int run_s1(occ_db *db, const char *sql, const char *s1,
		  char *err, size_t errlen)
{
	sqlite3_stmt *st = NULL;

	if (sqlite3_prepare_v2(db->h, sql, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "prepare: %s", sqlite3_errmsg(db->h));
		return -1;
	}
	sqlite3_bind_text(st, 1, s1, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(st) != SQLITE_DONE) {
		set_err(err, errlen, "step: %s", sqlite3_errmsg(db->h));
		sqlite3_finalize(st);
		return -1;
	}
	sqlite3_finalize(st);
	return 0;
}

/* ---- content_json 构造/解析 ---- */

/* parts 数组：reasoning? + text? + toolCall*（键名对齐 opencode part） */
static int push_str_part(aik_json *arr, const char *type, const char *text)
{
	aik_json *p = aik_json_new_obj();
	aik_json *t;

	if (!p)
		return -1;
	t = aik_json_new_str(type);
	if (!t || aik_json_obj_put(p, "type", t) < 0) {
		aik_json_free(t);
		aik_json_free(p);
		return -1;
	}
	t = aik_json_new_str(text ? text : "");
	if (!t || aik_json_obj_put(p, "text", t) < 0) {
		aik_json_free(t);
		aik_json_free(p);
		return -1;
	}
	if (aik_json_arr_push(arr, p) < 0) {
		aik_json_free(p);
		return -1;
	}
	return 0;
}

static char *build_content_json(const char *text, const char *reasoning,
				 const occ_tool_call *calls, size_t ncalls)
{
	aik_json *arr = aik_json_new_arr();
	char *out = NULL;
	size_t i;

	if (!arr)
		return NULL;
	if (reasoning && reasoning[0] &&
	    push_str_part(arr, "reasoning", reasoning))
		goto fail;
	if (text && text[0] && push_str_part(arr, "text", text))
		goto fail;
	for (i = 0; i < ncalls; i++) {
		aik_json *p = aik_json_new_obj();
		aik_json *t;

		if (!p)
			goto fail;
		t = aik_json_new_str("toolCall");
		if (!t || aik_json_obj_put(p, "type", t) < 0) {
			aik_json_free(t);
			aik_json_free(p);
			goto fail;
		}
		t = aik_json_new_str(calls[i].id ? calls[i].id : "");
		if (!t || aik_json_obj_put(p, "toolCallID", t) < 0) {
			aik_json_free(t);
			aik_json_free(p);
			goto fail;
		}
		t = aik_json_new_str(calls[i].name ? calls[i].name : "");
		if (!t || aik_json_obj_put(p, "tool", t) < 0) {
			aik_json_free(t);
			aik_json_free(p);
			goto fail;
		}
		t = aik_json_new_str(calls[i].arguments ? calls[i].arguments
						       : "{}");
		if (!t || aik_json_obj_put(p, "arguments", t) < 0) {
			aik_json_free(t);
			aik_json_free(p);
			goto fail;
		}
		if (aik_json_arr_push(arr, p) < 0) {
			aik_json_free(p);
			goto fail;
		}
	}
	{
		/* a1 教训（T9A1-REPORT §5.5）：aik_json_dump 不接受 NULL
		 * outlen——本地 dummy */
		size_t dummy;

		if (aik_json_dump(arr, &out, &dummy) < 0)
			out = NULL;
	}
fail:
	aik_json_free(arr);
	return out;
}

static char *json_strdup(const aik_json *v)
{
	const char *s = aik_json_str(v);

	return s ? strdup(s) : NULL;
}

/* content_json → 便捷视图（text/reasoning/toolCall parts） */
static void parse_content(occ_msg_row *r)
{
	char perr[96];
	aik_json *root;
	size_t n, i;

	if (!r->content_json)
		return;
	root = aik_json_parse(r->content_json, strlen(r->content_json),
			      perr, sizeof(perr));
	if (!root || aik_json_typeof(root) != AIK_JSON_ARR) {
		aik_json_free(root);		/* 视图缺省，原文仍可用 */
		return;
	}
	n = aik_json_count(root);
	for (i = 0; i < n; i++) {
		const aik_json *p = aik_json_at(root, i);
		const aik_json *t;
		const char *ty;

		if (!p || aik_json_typeof(p) != AIK_JSON_OBJ)
			continue;
		t = aik_json_get(p, "type");
		if (!t || aik_json_typeof(t) != AIK_JSON_STR)
			continue;
		ty = aik_json_str(t);
		if (!strcmp(ty, "text") && !r->text) {
			r->text = json_strdup(aik_json_get(p, "text"));
		} else if (!strcmp(ty, "reasoning") && !r->reasoning) {
			r->reasoning = json_strdup(aik_json_get(p, "text"));
		} else if (!strcmp(ty, "toolResult") && !r->tool_call_id) {
			/* T9b1：tool 结果消息——toolCallID 进 tool_call_id，
			 * output 进 text 视图（build_msgs 回灌用） */
			r->tool_call_id = json_strdup(
				aik_json_get(p, "toolCallID"));
			if (!r->text)
				r->text = json_strdup(
					aik_json_get(p, "output"));
		} else if (!strcmp(ty, "toolCall")) {
			occ_toolcall_part *nc = realloc(r->calls,
				(r->ncalls + 1) * sizeof(*nc));

			if (!nc)
				break;
			r->calls = nc;
			memset(&r->calls[r->ncalls], 0, sizeof(*nc));
			r->calls[r->ncalls].id = json_strdup(
				aik_json_get(p, "toolCallID"));
			r->calls[r->ncalls].tool = json_strdup(
				aik_json_get(p, "tool"));
			r->calls[r->ncalls].arguments = json_strdup(
				aik_json_get(p, "arguments"));
			r->ncalls++;
		}
	}
	aik_json_free(root);
}

void occ_msg_row_free(occ_msg_row *r)
{
	size_t i;

	if (!r)
		return;
	free(r->content_json);
	free(r->text);
	free(r->reasoning);
	free(r->tool_call_id);
	for (i = 0; i < r->ncalls; i++) {
		free(r->calls[i].id);
		free(r->calls[i].tool);
		free(r->calls[i].arguments);
	}
	free(r->calls);
	memset(r, 0, sizeof(*r));
}

void occ_msg_rows_free(occ_msg_row *rows, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		occ_msg_row_free(&rows[i]);
	free(rows);
}

/* ---- 会话 ---- */

int occ_session_create(occ_db *db, const char *model,
		       occ_session_row *out, char *err, size_t errlen)
{
	static const char *ins =
		"INSERT INTO occ_session"
		"  (id,title,created,model,tokens_total,status,updated)"
		"  VALUES (?1, '', ?2, ?3, 0, 'active', ?2)";
	static const char *win =
		"INSERT INTO occ_window(session_id,base_kind)"
		"  VALUES (?1, 'native')";
	long long now = now_ms();
	char id[OCC_ID_LEN];
	sqlite3_stmt *st = NULL;

	if (out)
		memset(out, 0, sizeof(*out));
	if (!db || !model) {
		set_err(err, errlen, "occ_session_create: bad args");
		return -1;
	}
	if (gen_id(id, sizeof(id), "ses_")) {
		set_err(err, errlen, "occ_session_create: urandom");
		return -1;
	}
	if (sqlite3_prepare_v2(db->h, ins, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "prepare: %s", sqlite3_errmsg(db->h));
		return -1;
	}
	sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(st, 2, now);
	sqlite3_bind_text(st, 3, model, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(st) != SQLITE_DONE) {
		set_err(err, errlen, "step: %s", sqlite3_errmsg(db->h));
		sqlite3_finalize(st);
		return -1;
	}
	sqlite3_finalize(st);
	/* occ_window：a3 恒 native 单行（窗口裁剪 b 棒 / 换窗 d 棒） */
	if (sqlite3_prepare_v2(db->h, win, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "prepare win: %s", sqlite3_errmsg(db->h));
		return -1;
	}
	sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(st) != SQLITE_DONE) {
		set_err(err, errlen, "step win: %s", sqlite3_errmsg(db->h));
		sqlite3_finalize(st);
		return -1;
	}
	sqlite3_finalize(st);
	if (out) {
		snprintf(out->id, sizeof(out->id), "%s", id);
		snprintf(out->model, sizeof(out->model), "%s", model);
		out->created = now;
		out->updated = now;
		snprintf(out->status, sizeof(out->status), "%s", OCC_ST_ACTIVE);
	}
	return 0;
}

static int session_fill(occ_session_row *out, sqlite3_stmt *st)
{
	snprintf(out->id, sizeof(out->id), "%s", sqlite3_column_text(st, 0));
	snprintf(out->title, sizeof(out->title), "%s",
		 (const char *)sqlite3_column_text(st, 1));
	out->created = sqlite3_column_int64(st, 2);
	snprintf(out->model, sizeof(out->model), "%s",
		 (const char *)sqlite3_column_text(st, 3));
	out->tokens_total = sqlite3_column_int64(st, 4);
	snprintf(out->status, sizeof(out->status), "%s",
		 (const char *)sqlite3_column_text(st, 5));
	out->updated = sqlite3_column_int64(st, 6);
	out->tokens_est = sqlite3_column_int(st, 7);
	{
		const unsigned char *wd = sqlite3_column_text(st, 8);

		snprintf(out->workdir, sizeof(out->workdir), "%s",
			 wd ? (const char *)wd : "");
	}
	return 1;
}

static const char SESSION_COLS[] =
	"id,title,created,model,tokens_total,status,updated,tokens_est,"
	"workdir";

int occ_session_get(occ_db *db, const char *id, occ_session_row *out,
		    char *err, size_t errlen)
{
	char sql[256];
	sqlite3_stmt *st = NULL;
	char idbuf[OCC_ID_LEN];
	int rc;

	if (!db || !id || !out) {
		set_err(err, errlen, "occ_session_get: bad args");
		return -1;
	}
	/* 别名防御：occ_session_get(db, s.id, &s, ...) 模式下 memset out
	 * 会清掉调用方仍在使用的 id——先拷贝再清零 */
	snprintf(idbuf, sizeof(idbuf), "%s", id);
	memset(out, 0, sizeof(*out));
	snprintf(sql, sizeof(sql),
		 "SELECT %s FROM occ_session WHERE id=?1", SESSION_COLS);
	if (sqlite3_prepare_v2(db->h, sql, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "prepare: %s", sqlite3_errmsg(db->h));
		return -1;
	}
	sqlite3_bind_text(st, 1, idbuf, -1, SQLITE_TRANSIENT);
	rc = sqlite3_step(st);
	if (rc == SQLITE_ROW)
		rc = session_fill(out, st);
	else
		rc = 0;
	sqlite3_finalize(st);
	return rc;
}

int occ_session_list(occ_db *db, occ_session_row **rows, size_t *n,
		     char *err, size_t errlen)
{
	char sql[256];
	sqlite3_stmt *st = NULL;
	occ_session_row *v = NULL;
	size_t cnt = 0, cap = 0;

	if (!db || !rows || !n) {
		set_err(err, errlen, "occ_session_list: bad args");
		return -1;
	}
	*rows = NULL;
	*n = 0;
	snprintf(sql, sizeof(sql),
		 "SELECT %s FROM occ_session ORDER BY created DESC",
		 SESSION_COLS);
	if (sqlite3_prepare_v2(db->h, sql, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "prepare: %s", sqlite3_errmsg(db->h));
		return -1;
	}
	while (sqlite3_step(st) == SQLITE_ROW) {
		if (cnt == cap) {
			occ_session_row *nv;

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
		session_fill(&v[cnt], st);
		cnt++;
	}
	sqlite3_finalize(st);
	*rows = v;
	*n = cnt;
	return 0;
}

int occ_session_set_title(occ_db *db, const char *id, const char *title,
			  char *err, size_t errlen)
{
	char sql[128];

	if (!db || !id || !title) {
		set_err(err, errlen, "occ_session_set_title: bad args");
		return -1;
	}
	snprintf(sql, sizeof(sql),
		 "UPDATE occ_session SET title=?1 WHERE id='%s'", id);
	/* id 为内部生成（hex 前缀），无注入面；title 走绑定 */
	return run_s1(db, sql, title, err, errlen);
}

int occ_session_set_status(occ_db *db, const char *id, const char *status,
			   char *err, size_t errlen)
{
	char sql[160];

	if (!db || !id || !status) {
		set_err(err, errlen, "occ_session_set_status: bad args");
		return -1;
	}
	snprintf(sql, sizeof(sql),
		 "UPDATE occ_session SET status='%s', updated=%lld"
		 " WHERE id='%s'", status, now_ms(), id);
	if (sqlite3_exec(db->h, sql, NULL, NULL, NULL) != SQLITE_OK) {
		set_err(err, errlen, "set_status: %s", sqlite3_errmsg(db->h));
		return -1;
	}
	return 0;
}

int occ_session_set_workdir(occ_db *db, const char *id, const char *workdir,
			    char *err, size_t errlen)
{
	char sql[160];

	if (!db || !id) {
		set_err(err, errlen, "occ_session_set_workdir: bad args");
		return -1;
	}
	snprintf(sql, sizeof(sql),
		 "UPDATE occ_session SET workdir=?1 WHERE id='%s'", id);
	return run_s1(db, sql, workdir ? workdir : "", err, errlen);
}

/* ---- 消息（每条单事务；崩溃安全核心） ---- */

static int msg_insert(occ_db *db, const char *msg_id, const char *session_id,
		      const char *role, const char *content_json,
		      const occ_usage *u, int est, const char *finish,
		      long long now, char *err, size_t errlen)
{
	static const char *ins =
		"INSERT INTO occ_message"
		"  (id,session_id,role,content_json,usage_in,usage_out,"
		"   usage_cache_read,usage_cache_write,usage_est,finish,created)"
		"  VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)";
	sqlite3_stmt *st = NULL;

	if (sqlite3_prepare_v2(db->h, ins, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "prepare msg: %s", sqlite3_errmsg(db->h));
		return -1;
	}
	sqlite3_bind_text(st, 1, msg_id, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 2, session_id, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 3, role, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 4, content_json, -1, SQLITE_TRANSIENT);
	if (u && u->present) {
		sqlite3_bind_int64(st, 5, u->input);
		sqlite3_bind_int64(st, 6, u->output);
		sqlite3_bind_int64(st, 7, u->cache_read);
		sqlite3_bind_int64(st, 8, u->cache_write);
	} /* else：四个 usage 列绑定保持 NULL */
	sqlite3_bind_int(st, 9, est);
	sqlite3_bind_text(st, 10, finish ? finish : "", -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(st, 11, now);
	if (sqlite3_step(st) != SQLITE_DONE) {
		set_err(err, errlen, "step msg: %s", sqlite3_errmsg(db->h));
		sqlite3_finalize(st);
		return -1;
	}
	sqlite3_finalize(st);
	return 0;
}

int occ_msg_add_user(occ_db *db, const char *session_id, const char *text,
		     char *msg_id, size_t idlen, char *err, size_t errlen)
{
	char id[OCC_ID_LEN];
	char *content = NULL;
	char title[128];
	char sql[256];
	long long now = now_ms();
	int rc = -1;

	if (!db || !session_id || !text) {
		set_err(err, errlen, "occ_msg_add_user: bad args");
		return -1;
	}
	if (gen_id(id, sizeof(id), "msg_")) {
		set_err(err, errlen, "occ_msg_add_user: urandom");
		return -1;
	}
	content = build_content_json(text, NULL, NULL, 0);
	if (!content) {
		set_err(err, errlen, "occ_msg_add_user: content oom");
		return -1;
	}
	if (tx_begin(db, err, errlen))
		goto out;
	if (msg_insert(db, id, session_id, "user", content, NULL, 0, "",
		       now, err, errlen))
		goto abort;
	if (g_test_fault & 0x1) {
		set_err(err, errlen, "injected fault: add_user pre-commit");
		tx_rollback(db);
		goto out;
	}
	/* title 为空（首条消息）→ UTF-8 截断前缀（a3 标题策略；LLM 生成标题
	 * 留后续棒）。title 来自用户文本——必须参数化绑定（?1）防注入/截断 */
	utf8_prefix(text, title, sizeof(title));
	snprintf(sql, sizeof(sql),
		 "UPDATE occ_session SET status='running', updated=%lld,"
		 " title=CASE WHEN title='' THEN ?1 ELSE title END"
		 " WHERE id='%s'", now, session_id);
	{
		sqlite3_stmt *st = NULL;

		if (sqlite3_prepare_v2(db->h, sql, -1, &st, NULL) !=
		    SQLITE_OK) {
			set_err(err, errlen, "prepare title: %s",
				sqlite3_errmsg(db->h));
			goto abort;
		}
		sqlite3_bind_text(st, 1, title, -1, SQLITE_TRANSIENT);
		if (sqlite3_step(st) != SQLITE_DONE) {
			set_err(err, errlen, "step title: %s",
				sqlite3_errmsg(db->h));
			sqlite3_finalize(st);
			goto abort;
		}
		sqlite3_finalize(st);
	}
	if (tx_commit(db, err, errlen))
		goto out;
	if (msg_id && idlen >= strlen(id) + 1)
		memcpy(msg_id, id, strlen(id) + 1);
	rc = 0;
	goto out2;
abort:
	tx_rollback(db);
out:
	if (msg_id && idlen)
		msg_id[0] = '\0';
out2:
	free(content);
	return rc;
}

int occ_msg_add_assistant_ex(occ_db *db, const char *session_id,
			     const char *text, const char *reasoning,
			     const occ_tool_call *calls, size_t ncalls,
			     const occ_usage *u, int est, const char *finish,
			     int interim, char *msg_id, size_t idlen,
			     char *err, size_t errlen)
{
	char id[OCC_ID_LEN];
	char *content = NULL;
	char sql[320];
	long long now = now_ms();
	long long tin = 0, tout = 0;
	int rc = -1;

	if (!db || !session_id) {
		set_err(err, errlen,
			"occ_msg_add_assistant_ex: bad args");
		return -1;
	}
	if (gen_id(id, sizeof(id), "msg_")) {
		set_err(err, errlen, "occ_msg_add_assistant_ex: urandom");
		return -1;
	}
	content = build_content_json(text, reasoning, calls, ncalls);
	if (!content) {
		set_err(err, errlen,
			"occ_msg_add_assistant_ex: content oom");
		return -1;
	}
	if (u && u->present) {
		tin = u->input;
		tout = u->output;
	} else if (est) {
		/* usage 未回传的估算兜底由调用方（loop.c/tokens.c）算好
		 * 塞进 u——此处只负责落库；此分支不该到达，防御置零 */
	}
	if (tx_begin(db, err, errlen))
		goto out;
	if (msg_insert(db, id, session_id, "assistant", content, u, est,
		       finish ? finish : "", now, err, errlen))
		goto abort;
	if (g_test_fault & 0x2) {
		set_err(err, errlen,
			"injected fault: add_assistant pre-commit");
		tx_rollback(db);
		goto out;
	}
	/* T9b1：interim=1（携带 toolCall、环未收口）→ status='running'；
	 * 收口轮（无 calls）→ 'active'。tokens 累计两种情形都做。 */
	snprintf(sql, sizeof(sql),
		 "UPDATE occ_session SET status='%s', updated=%lld,"
		 " tokens_total=tokens_total+%lld,"
		 " tokens_est=CASE WHEN %d=1 THEN 1 ELSE tokens_est END"
		 " WHERE id='%s'", interim ? "running" : "active",
		 now, tin + tout, est, session_id);
	if (sqlite3_exec(db->h, sql, NULL, NULL, NULL) != SQLITE_OK) {
		set_err(err, errlen, "update session: %s",
			sqlite3_errmsg(db->h));
		goto abort;
	}
	if (tx_commit(db, err, errlen))
		goto out;
	if (msg_id && idlen >= strlen(id) + 1)
		memcpy(msg_id, id, strlen(id) + 1);
	rc = 0;
	goto out2;
abort:
	tx_rollback(db);
out:
	if (msg_id && idlen)
		msg_id[0] = '\0';
out2:
	free(content);
	return rc;
}

int occ_msg_add_assistant(occ_db *db, const char *session_id,
			  const char *text, const char *reasoning,
			  const occ_tool_call *calls, size_t ncalls,
			  const occ_usage *u, int est, const char *finish,
			  char *msg_id, size_t idlen,
			  char *err, size_t errlen)
{
	return occ_msg_add_assistant_ex(db, session_id, text, reasoning,
					calls, ncalls, u, est, finish, 0,
					msg_id, idlen, err, errlen);
}

static occ_msg_row *msg_read(occ_db *db, const char *sql,
			     const char *session_id, size_t *n,
			     char *err, size_t errlen)
{
	sqlite3_stmt *st = NULL;
	occ_msg_row *v = NULL;
	size_t cnt = 0, cap = 0;

	*n = 0;
	if (sqlite3_prepare_v2(db->h, sql, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "prepare msgs: %s", sqlite3_errmsg(db->h));
		return NULL;
	}
	if (session_id)
		sqlite3_bind_text(st, 1, session_id, -1, SQLITE_TRANSIENT);
	while (sqlite3_step(st) == SQLITE_ROW) {
		occ_msg_row r;

		if (cnt == cap) {
			occ_msg_row *nv;

			cap = cap ? cap * 2 : 8;
			nv = realloc(v, cap * sizeof(*nv));
			if (!nv) {
				free(v);
				sqlite3_finalize(st);
				set_err(err, errlen, "oom");
				return NULL;
			}
			v = nv;
		}
		memset(&r, 0, sizeof(r));
		snprintf(r.id, sizeof(r.id), "%s",
			 (const char *)sqlite3_column_text(st, 0));
		snprintf(r.role, sizeof(r.role), "%s",
			 (const char *)sqlite3_column_text(st, 1));
		{
			const unsigned char *cj = sqlite3_column_text(st, 2);

			r.content_json = cj ? strdup((const char *)cj) : NULL;
		}
		r.usage_in = sqlite3_column_type(st, 3) == SQLITE_NULL ?
			     0 : sqlite3_column_int64(st, 3);
		r.usage_out = sqlite3_column_type(st, 4) == SQLITE_NULL ?
			      0 : sqlite3_column_int64(st, 4);
		r.usage_cache_read = sqlite3_column_type(st, 5) == SQLITE_NULL ?
				     0 : sqlite3_column_int64(st, 5);
		r.usage_cache_write = sqlite3_column_type(st, 6) == SQLITE_NULL ?
				      0 : sqlite3_column_int64(st, 6);
		r.usage_est = sqlite3_column_int(st, 7);
		snprintf(r.finish, sizeof(r.finish), "%s",
			 (const char *)sqlite3_column_text(st, 8));
		r.created = sqlite3_column_int64(st, 9);
		r.reverted = sqlite3_column_int(st, 10);
		r.rowid = sqlite3_column_int64(st, 11);
		parse_content(&r);
			v[cnt++] = r;
		}
		sqlite3_finalize(st);
		*n = cnt;
		if (!v) {
			/*
			 * b2：0 行 → 非 NULL 空数组（调用方「成功但空」
			 * 语义——compose_user_text 在首条 user 前查注记、
			 * revert 在空会话判定「无可撤销」都靠它；真错
			 * （prepare/oom）仍在上方带 err 返回 NULL）。
			 */
			v = calloc(1, sizeof(*v));
			if (!v)
				set_err(err, errlen, "msgs: oom");
		}
		return v;
	}

static const char MSG_COLS[] =
	"id,role,content_json,usage_in,usage_out,usage_cache_read,"
	"usage_cache_write,usage_est,finish,created,reverted,rowid";

int occ_msg_list(occ_db *db, const char *session_id,
		 occ_msg_row **rows, size_t *n, char *err, size_t errlen)
{
	char sql[256];

	if (!db || !session_id || !rows || !n) {
		set_err(err, errlen, "occ_msg_list: bad args");
		return -1;
	}
	snprintf(sql, sizeof(sql),
		 "SELECT %s FROM occ_message WHERE session_id=?1"
		 " ORDER BY created ASC, rowid ASC", MSG_COLS);
	*rows = msg_read(db, sql, session_id, n, err, errlen);
	return *rows ? 0 : -1;
}

/* b2：last 是「尾态」视图——被撤（reverted=1）消息对尾态不可见
 * （opencode messagesFromRevert 同语义）；last_user 不跳过 reverted
 * （retry=重发最近 prompt；undo 后最近 user 恰是被撤边界，重发即
 * 落地撤销——OCD「用户重发即认」），但天然跳过 system 注记。 */
static int msg_last_where(occ_db *db, const char *session_id,
			  const char *where_extra, occ_msg_row *out,
			  char *err, size_t errlen)
{
	char sql[320];
	occ_msg_row *v = NULL;
	size_t n = 0;

	memset(out, 0, sizeof(*out));
	snprintf(sql, sizeof(sql),
		 "SELECT %s FROM occ_message WHERE session_id=?1 %s"
		 " ORDER BY created DESC, rowid DESC LIMIT 1",
		 MSG_COLS, where_extra);
	v = msg_read(db, sql, session_id, &n, err, errlen);
	if (!v)
		return -1;
	if (n == 0) {
		free(v);
		return 0;
	}
	*out = v[0];
	free(v);
	return 1;
}

int occ_msg_last(occ_db *db, const char *session_id, occ_msg_row *out,
		 char *err, size_t errlen)
{
	if (!db || !session_id || !out) {
		set_err(err, errlen, "occ_msg_last: bad args");
		return -1;
	}
	return msg_last_where(db, session_id, "AND reverted=0", out, err,
			      errlen);
}

int occ_msg_last_user(occ_db *db, const char *session_id, occ_msg_row *out,
		      char *err, size_t errlen)
{
	if (!db || !session_id || !out) {
		set_err(err, errlen, "occ_msg_last_user: bad args");
		return -1;
	}
	return msg_last_where(db, session_id, "AND role='user'", out, err,
			      errlen);
}

/* ---- T9b1：工具环 durable 扩展 ---- */

/* toolResult content：[{"type":"toolResult","toolCallID":…,"tool":…,
 * "output":…}]（键名对齐 opencode part 形态） */
static char *build_toolresult_json(const char *call_id, const char *tool,
				   const char *output)
{
	aik_json *arr = aik_json_new_arr();
	aik_json *p = aik_json_new_obj();
	char *out = NULL;

	if (!arr || !p)
		goto fail;
	{
		aik_json *t;

		t = aik_json_new_str("toolResult");
		if (!t || aik_json_obj_put(p, "type", t) < 0) {
			aik_json_free(t);
			goto fail;
		}
		t = aik_json_new_str(call_id ? call_id : "");
		if (!t || aik_json_obj_put(p, "toolCallID", t) < 0) {
			aik_json_free(t);
			goto fail;
		}
		t = aik_json_new_str(tool ? tool : "");
		if (!t || aik_json_obj_put(p, "tool", t) < 0) {
			aik_json_free(t);
			goto fail;
		}
		t = aik_json_new_str(output ? output : "");
		if (!t || aik_json_obj_put(p, "output", t) < 0) {
			aik_json_free(t);
			goto fail;
		}
	}
	if (aik_json_arr_push(arr, p) < 0) {
		aik_json_free(p);
		goto fail;
	}
	p = NULL;
	{
		/* a1 教训：aik_json_dump 不接受 NULL outlen——本地 dummy */
		size_t dummy;

		if (aik_json_dump(arr, &out, &dummy) < 0)
			out = NULL;
	}
fail:
	aik_json_free(p);
	aik_json_free(arr);
	return out;
}

int occ_tool_record(occ_db *db, const char *session_id,
		    const char *assistant_msg_id, const char *tool,
		    const char *args_json, const char *result_text,
		    int rc, long long dur_ms, const char *call_id,
		    char *msg_id_out, size_t msg_len,
		    char *tcrow_id_out, size_t tc_len,
		    char *err, size_t errlen)
{
	char mid[OCC_ID_LEN];
	char tcid[OCC_ID_LEN];
	char *content = NULL;
	sqlite3_stmt *st = NULL;
	static const char *ins_tc =
		"INSERT INTO occ_toolcall"
		"  (id,message_id,tool,args_json,result_json,rc,dur_ms)"
		"  VALUES (?1,?2,?3,?4,?5,?6,?7)";
	int ret = -1;

	if (msg_id_out && msg_len)
		msg_id_out[0] = '\0';
	if (tcrow_id_out && tc_len)
		tcrow_id_out[0] = '\0';
	if (!db || !session_id || !assistant_msg_id || !tool) {
		set_err(err, errlen, "occ_tool_record: bad args");
		return -1;
	}
	if (gen_id(mid, sizeof(mid), "msg_") ||
	    gen_id(tcid, sizeof(tcid), "tc_")) {
		set_err(err, errlen, "occ_tool_record: urandom");
		return -1;
	}
	content = build_toolresult_json(call_id, tool, result_text);
	if (!content) {
		set_err(err, errlen, "occ_tool_record: content oom");
		return -1;
	}
	if (tx_begin(db, err, errlen))
		goto out;
	if (sqlite3_prepare_v2(db->h, ins_tc, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "prepare tc: %s",
			sqlite3_errmsg(db->h));
		goto abort;
	}
	sqlite3_bind_text(st, 1, tcid, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 2, assistant_msg_id, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 3, tool, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 4, args_json ? args_json : "{}", -1,
			  SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 5, result_text ? result_text : "", -1,
			  SQLITE_TRANSIENT);
	sqlite3_bind_int(st, 6, rc);
	sqlite3_bind_int64(st, 7, dur_ms);
	if (sqlite3_step(st) != SQLITE_DONE) {
		set_err(err, errlen, "step tc: %s", sqlite3_errmsg(db->h));
		sqlite3_finalize(st);
		goto abort;
	}
	sqlite3_finalize(st);
	st = NULL;
	if (msg_insert(db, mid, session_id, "tool", content, NULL, 0, "",
		       now_ms(), err, errlen))
		goto abort;
	if (tx_commit(db, err, errlen))
		goto out;
	if (msg_id_out && msg_len >= strlen(mid) + 1)
		memcpy(msg_id_out, mid, strlen(mid) + 1);
	if (tcrow_id_out && tc_len >= strlen(tcid) + 1)
		memcpy(tcrow_id_out, tcid, strlen(tcid) + 1);
	ret = 0;
	goto out;
abort:
	tx_rollback(db);
out:
	if (st)
		sqlite3_finalize(st);
	free(content);
	return ret;
}

int occ_msg_pending_calls(occ_db *db, const char *session_id,
			  occ_toolcall_part **calls, size_t *n,
			  char *asst_msg_id, size_t asst_len,
			  char *err, size_t errlen)
{
	occ_msg_row *rows = NULL;
	size_t nmsgs = 0, i, k, np = 0;
	char **answered = NULL;
	size_t nans = 0;
	occ_toolcall_part *out = NULL;
	int ret = -1;

	*calls = NULL;
	*n = 0;
	if (asst_msg_id && asst_len)
		asst_msg_id[0] = '\0';
	if (!db || !session_id || !calls || !n) {
		set_err(err, errlen, "occ_msg_pending_calls: bad args");
		return -1;
	}
	if (occ_msg_list(db, session_id, &rows, &nmsgs, err, errlen))
		return -1;
	/* 自尾向前：tool 行收 toolCallID；首个 assistant 行的 calls 减
	 * 已应答集 = pending。b2：reverted（被撤）行透明——被撤回合的
	 * 调用不再是待办（undo 后模型上下文里它们本就不存在）。 */
	for (i = nmsgs; i > 0; i--) {
		occ_msg_row *r = &rows[i - 1];

		if (r->reverted)
			continue;
		if (!strcmp(r->role, "tool")) {
			if (r->tool_call_id && r->tool_call_id[0]) {
				char **na = realloc(answered,
					(nans + 1) * sizeof(*na));

				if (!na)
					goto oom;
				answered = na;
				answered[nans++] = strdup(r->tool_call_id);
			}
			continue;
		}
		if (!strcmp(r->role, "assistant")) {
			if (asst_msg_id && asst_len >= strlen(r->id) + 1)
				memcpy(asst_msg_id, r->id,
				       strlen(r->id) + 1);
			for (k = 0; k < r->ncalls; k++) {
				const char *cid = r->calls[k].id ?
						  r->calls[k].id : "";
				size_t a;
				int done = 0;

				for (a = 0; a < nans; a++)
					if (!strcmp(answered[a], cid)) {
						done = 1;
						break;
					}
				if (done)
					continue;
				{
					occ_toolcall_part *no = realloc(
						out, (np + 1) * sizeof(*no));

					if (!no)
						goto oom;
					out = no;
					memset(&out[np], 0, sizeof(out[np]));
					out[np].id = strdup(cid);
					out[np].tool = r->calls[k].tool ?
						       strdup(r->calls[k].tool) :
						       NULL;
					out[np].arguments = r->calls[k].arguments ?
							     strdup(r->calls[k].arguments) :
							     NULL;
					np++;
				}
			}
			break;			/* 只看末位 assistant */
		}
		/* user：其后无 assistant——无 pending */
		break;
	}
	*calls = out;
	*n = np;
	ret = (int)np;
oom:
	if (ret < 0) {
		for (k = 0; k < np; k++) {
			free(out[k].id);
			free(out[k].tool);
			free(out[k].arguments);
		}
		free(out);
		set_err(err, errlen, "occ_msg_pending_calls: oom");
	}
	for (k = 0; k < nans; k++)
		free(answered[k]);
	free(answered);
	occ_msg_rows_free(rows, nmsgs);
	return ret;
}

/* ---- T9b2：/undo 三段式支撑 ---- */

int occ_msg_add_note(occ_db *db, const char *session_id, const char *text,
		     char *msg_id, size_t idlen, char *err, size_t errlen)
{
	char id[OCC_ID_LEN];
	char *content = NULL;
	long long now = now_ms();
	int rc = -1;

	if (!db || !session_id || !text) {
		set_err(err, errlen, "occ_msg_add_note: bad args");
		return -1;
	}
	if (gen_id(id, sizeof(id), "msg_")) {
		set_err(err, errlen, "occ_msg_add_note: urandom");
		return -1;
	}
	content = build_content_json(text, NULL, NULL, 0);
	if (!content) {
		set_err(err, errlen, "occ_msg_add_note: content oom");
		return -1;
	}
	if (tx_begin(db, err, errlen))
		goto out;
	if (msg_insert(db, id, session_id, "system", content, NULL, 0, "",
		       now, err, errlen))
		goto abort;
	if (tx_commit(db, err, errlen))
		goto out;
	if (msg_id && idlen >= strlen(id) + 1)
		memcpy(msg_id, id, strlen(id) + 1);
	rc = 0;
	goto out2;
abort:
	tx_rollback(db);
out:
	if (msg_id && idlen)
		msg_id[0] = '\0';
out2:
	free(content);
	return rc;
}

int occ_msg_delete(occ_db *db, const char *msg_id, char *err, size_t errlen)
{
	char sql[128];

	if (!db || !msg_id) {
		set_err(err, errlen, "occ_msg_delete: bad args");
		return -1;
	}
	snprintf(sql, sizeof(sql),
		 "DELETE FROM occ_message WHERE id='%s'", msg_id);
	if (sqlite3_exec(db->h, sql, NULL, NULL, NULL) != SQLITE_OK) {
		set_err(err, errlen, "occ_msg_delete: %s",
			sqlite3_errmsg(db->h));
		return -1;
	}
	return 0;
}

int occ_msgs_set_reverted(occ_db *db, const char *session_id,
			  const char *ids_json, int flag, long long *n_out,
			  char *err, size_t errlen)
{
	char perr[96];
	aik_json *arr;
	size_t n, i;
	long long changed = 0;
	static const char *upd =
		"UPDATE occ_message SET reverted=?1 WHERE id=?2"
		" AND session_id=?3 AND reverted<>?4";

	if (n_out)
		*n_out = 0;
	if (!db || !session_id) {
		set_err(err, errlen, "occ_msgs_set_reverted: bad args");
		return -1;
	}
	if (!ids_json || !ids_json[0] || !strcmp(ids_json, "[]"))
		return 0;			/* 空集合：无操作 */
	arr = aik_json_parse(ids_json, strlen(ids_json), perr, sizeof(perr));
	if (!arr || aik_json_typeof(arr) != AIK_JSON_ARR) {
		aik_json_free(arr);
		set_err(err, errlen, "occ_msgs_set_reverted: ids_json: %s",
			perr);
		return -1;
	}
	n = aik_json_count(arr);
	if (tx_begin(db, err, errlen)) {
		aik_json_free(arr);
		return -1;
	}
	for (i = 0; i < n; i++) {
		const aik_json *e = aik_json_at(arr, i);
		const char *id;
		sqlite3_stmt *st = NULL;

		if (!e || aik_json_typeof(e) != AIK_JSON_STR)
			continue;
		id = aik_json_str(e);
		if (!id || strncmp(id, "msg_", 4))
			continue;		/* 只接受 occ 消息 id 形态 */
		if (sqlite3_prepare_v2(db->h, upd, -1, &st, NULL) != SQLITE_OK)
			goto fail;
		sqlite3_bind_int(st, 1, flag ? 1 : 0);
		sqlite3_bind_text(st, 2, id, -1, SQLITE_TRANSIENT);
		sqlite3_bind_text(st, 3, session_id, -1, SQLITE_TRANSIENT);
		sqlite3_bind_int(st, 4, flag ? 1 : 0);
		if (sqlite3_step(st) != SQLITE_DONE) {
			sqlite3_finalize(st);
			goto fail;
		}
		changed += sqlite3_changes(db->h);
		sqlite3_finalize(st);
	}
	aik_json_free(arr);
	if (tx_commit(db, err, errlen))
		return -1;
	if (n_out)
		*n_out = changed;
	return 0;
fail:
	set_err(err, errlen, "occ_msgs_set_reverted: %s",
		sqlite3_errmsg(db->h));
	tx_rollback(db);
	aik_json_free(arr);
	return -1;
}

void occ_revert_row_free(occ_revert_row *r)
{
	if (!r)
		return;
	free(r->files_json);
	free(r->hidden_json);
	memset(r, 0, sizeof(*r));
}

int occ_revert_get(occ_db *db, const char *session_id, occ_revert_row *out,
		   char *err, size_t errlen)
{
	static const char *sel =
		"SELECT session_id,boundary_msg,note_msg,created,files_json,"
		"hidden_json FROM occ_revert WHERE session_id=?1";
	sqlite3_stmt *st = NULL;
	int rc;

	if (!db || !session_id || !out) {
		set_err(err, errlen, "occ_revert_get: bad args");
		return -1;
	}
	memset(out, 0, sizeof(*out));
	if (sqlite3_prepare_v2(db->h, sel, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "prepare revert: %s",
			sqlite3_errmsg(db->h));
		return -1;
	}
	sqlite3_bind_text(st, 1, session_id, -1, SQLITE_TRANSIENT);
	rc = sqlite3_step(st);
	if (rc == SQLITE_ROW) {
		snprintf(out->session_id, sizeof(out->session_id), "%s",
			 (const char *)sqlite3_column_text(st, 0));
		snprintf(out->boundary_msg, sizeof(out->boundary_msg), "%s",
			 (const char *)sqlite3_column_text(st, 1));
		snprintf(out->note_msg, sizeof(out->note_msg), "%s",
			 (const char *)sqlite3_column_text(st, 2));
		out->created = sqlite3_column_int64(st, 3);
		{
			const unsigned char *fj = sqlite3_column_text(st, 4);
			const unsigned char *hj = sqlite3_column_text(st, 5);

			out->files_json = fj ? strdup((const char *)fj) : NULL;
			out->hidden_json = hj ? strdup((const char *)hj) : NULL;
		}
		rc = 1;
	} else {
		rc = 0;
	}
	sqlite3_finalize(st);
	return rc;
}

int occ_revert_put(occ_db *db, const char *session_id,
		   const char *boundary_msg, const char *note_msg,
		   const char *files_json, const char *hidden_json,
		   char *err, size_t errlen)
{
	static const char *ins =
		"INSERT OR REPLACE INTO occ_revert"
		"  (session_id,boundary_msg,note_msg,created,files_json,"
		"   hidden_json)"
		"  VALUES (?1,?2,?3,?4,?5,?6)";
	sqlite3_stmt *st = NULL;

	if (!db || !session_id || !boundary_msg || !note_msg) {
		set_err(err, errlen, "occ_revert_put: bad args");
		return -1;
	}
	if (sqlite3_prepare_v2(db->h, ins, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "prepare put: %s", sqlite3_errmsg(db->h));
		return -1;
	}
	sqlite3_bind_text(st, 1, session_id, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 2, boundary_msg, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 3, note_msg, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(st, 4, now_ms());
	sqlite3_bind_text(st, 5, files_json ? files_json : "", -1,
			  SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 6, hidden_json ? hidden_json : "", -1,
			  SQLITE_TRANSIENT);
	if (sqlite3_step(st) != SQLITE_DONE) {
		set_err(err, errlen, "step put: %s", sqlite3_errmsg(db->h));
		sqlite3_finalize(st);
		return -1;
	}
	sqlite3_finalize(st);
	return 0;
}

int occ_revert_clear(occ_db *db, const char *session_id,
		     char *err, size_t errlen)
{
	char sql[128];

	if (!db || !session_id) {
		set_err(err, errlen, "occ_revert_clear: bad args");
		return -1;
	}
	snprintf(sql, sizeof(sql),
		 "DELETE FROM occ_revert WHERE session_id='%s'", session_id);
	if (sqlite3_exec(db->h, sql, NULL, NULL, NULL) != SQLITE_OK) {
		set_err(err, errlen, "occ_revert_clear: %s",
			sqlite3_errmsg(db->h));
		return -1;
	}
	return 0;
}

/* ---- b2：undo 范围内工具调用对账 ---- */

void occ_tc_rows_free(occ_tc_row *rows, size_t n)
{
	size_t i;

	if (!rows)
		return;
	for (i = 0; i < n; i++)
		free(rows[i].args_json);
	free(rows);
}

int occ_toolcalls_since(occ_db *db, const char *session_id,
			long long min_rowid, occ_tc_row **rows, size_t *n,
			char *err, size_t errlen)
{
	static const char *sql =
		"SELECT t.tool,t.args_json,t.rc,m.rowid,m.id"
		" FROM occ_toolcall t JOIN occ_message m"
		" ON m.id=t.message_id"
		" WHERE m.session_id=?1 AND m.rowid>=?2"
		" ORDER BY m.rowid ASC,t.rowid ASC";
	occ_tc_row *v = NULL;
	size_t cnt = 0, cap = 0;
	sqlite3_stmt *st = NULL;

	if (rows)
		*rows = NULL;
	if (n)
		*n = 0;
	if (!db || !session_id || !rows || !n) {
		set_err(err, errlen, "occ_toolcalls_since: bad args");
		return -1;
	}
	if (sqlite3_prepare_v2(db->h, sql, -1, &st, NULL) != SQLITE_OK) {
		set_err(err, errlen, "toolcalls_since: %s",
			sqlite3_errmsg(db->h));
		return -1;
	}
	sqlite3_bind_text(st, 1, session_id, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(st, 2, min_rowid);
	while (sqlite3_step(st) == SQLITE_ROW) {
		occ_tc_row r;
		const unsigned char *aj;

		if (cnt == cap) {
			occ_tc_row *nv;

			cap = cap ? cap * 2 : 8;
			nv = realloc(v, cap * sizeof(*nv));
			if (!nv) {
				free(v);
				sqlite3_finalize(st);
				set_err(err, errlen, "toolcalls_since: oom");
				return -1;
			}
			v = nv;
		}
		memset(&r, 0, sizeof(r));
		snprintf(r.tool, sizeof(r.tool), "%s",
			 (const char *)sqlite3_column_text(st, 0));
		aj = sqlite3_column_text(st, 1);
		r.args_json = aj ? strdup((const char *)aj) : NULL;
		r.rc = sqlite3_column_int(st, 2);
		r.msg_rowid = sqlite3_column_int64(st, 3);
		snprintf(r.msg_id, sizeof(r.msg_id), "%s",
			 (const char *)sqlite3_column_text(st, 4));
		v[cnt++] = r;
	}
	sqlite3_finalize(st);
	*rows = v;
	*n = cnt;
	return 0;
}
