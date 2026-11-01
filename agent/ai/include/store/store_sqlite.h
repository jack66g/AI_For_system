/* SPDX-License-Identifier: GPL-2.0 */
/*
 * store_sqlite.h - SQLite 单文件存储（T2b-2）
 *
 * 语义对齐参考实现 sme/storage/backends.py（SqliteBackend）与
 * sme/storage/wal.py（sqlite 分支）。磁盘格式：
 *
 *   snapshots(id INTEGER PRIMARY KEY, payload TEXT, saved_at REAL)
 *   vectors(memory_id TEXT PRIMARY KEY, blob BLOB NOT NULL)
 *   wal_ops(seq INTEGER PRIMARY KEY AUTOINCREMENT, op TEXT NOT NULL)
 *
 * 约定：
 *   - 除注明外，函数返回 0 成功 / -1 失败；失败时 err 以 "sqlite: " 开头。
 *   - 句柄不是线程安全的：同一个 aik_sqlite* 不得跨线程并发使用。
 *   - open 时固定执行 PRAGMA busy_timeout = 5000（与参考实现一致）。
 *   - create 非 0 时建 snapshots 与 vectors 表（不建 sqlite_sequence，由
 *     AUTOINCREMENT 自动产生）；create 为 0 时只打开既有库，缺表即报错，
 *     绝不隐式建表（避免改写参考库）。
 *   - wal_ops 表由 aik_sqlite_wal_append / replay / clear 首次使用时创建
 *     （与参考实现惰性建表一致）。
 *
 * 与参考 save() 的对应关系：参考的一次 save 是一个事务（DELETE snapshots
 * + INSERT + DELETE vectors + 逐条 INSERT OR REPLACE）。本 API 拆成
 * aik_sqlite_save_snapshot（事务内清空 snapshots 与 vectors，写快照行，
 * 见下）与反复调用 aik_sqlite_put_vector（各自事务）——调用顺序约定为
 * 先 save_snapshot 再 put_vector，落盘结果与参考 save 一致。
 */
#ifndef _AIK_STORE_SQLITE_H
#define _AIK_STORE_SQLITE_H

#include <stddef.h>

#include "store/store_wal.h"

/* 不透明句柄 */
typedef struct aik_sqlite aik_sqlite;

/*
 * aik_sqlite_open - 打开（create 非 0 时新建）数据库
 *
 * create 非 0：必要时递归创建父目录，建 snapshots / vectors 表。
 * create 为 0：库不存在或无权限 → NULL + err。
 * 成功返回句柄（调用者 aik_sqlite_close）；失败返回 NULL。
 */
aik_sqlite *aik_sqlite_open(const char *path, int create,
			    char *err, size_t errlen);

/* 关闭并释放句柄；NULL 安全。未提交事务由 sqlite 回滚。 */
void aik_sqlite_close(aik_sqlite *db);

/* 设置 busy_timeout（毫秒）。成功 0 / 失败 -1。 */
int aik_sqlite_busy_timeout(aik_sqlite *db, int ms,
			    char *err, size_t errlen);

/*
 * aik_sqlite_save_snapshot - 全量写快照（单行逻辑）
 *
 * 单个事务内 DELETE FROM snapshots、DELETE FROM vectors、INSERT 一行
 * (payload_json, saved_at)。清空 vectors 与参考 save() 的全量替换语义
 * 一致：调用者随后用 aik_sqlite_put_vector 重写本次快照的向量。
 * payload_json 按原文写入，不做 JSON 校验（校验属上层）。
 * 成功 0 / 失败 -1（回滚）。
 */
int aik_sqlite_save_snapshot(aik_sqlite *db, const char *payload_json,
			     double saved_at, char *err, size_t errlen);

/*
 * aik_sqlite_load_snapshot - 读最新一行
 *
 * SELECT payload, saved_at FROM snapshots ORDER BY id DESC LIMIT 1。
 * 成功返回 0；*payload_json 为 malloc 的原文（调用者 free），
 * *saved_at 为保存时间。表中无行时返回 0 且 *payload_json = NULL、
 * *saved_at = 0.0。payload 为 SQL NULL 时返回空串。
 * 库缺少 snapshots 或 vectors 表 → -1（schema 校验，防止把坏库当空库）。
 */
int aik_sqlite_load_snapshot(aik_sqlite *db, char **payload_json,
			     double *saved_at, char *err, size_t errlen);

/*
 * aik_sqlite_put_vector - 写一条向量（裸字节，语义由调用者解释）
 *
 * 事务内 DELETE FROM vectors WHERE memory_id = ? 后
 * INSERT OR REPLACE INTO vectors(memory_id, blob)。blob 为裸 float64
 * 小端字节（参考实现 np.float64.tobytes()）；len 为字节数，可为 0
 * （写入零长度 BLOB）。成功 0 / 失败 -1。
 */
int aik_sqlite_put_vector(aik_sqlite *db, const char *memory_id,
			  const void *blob, size_t len,
			  char *err, size_t errlen);

/*
 * aik_sqlite_vec_visit - 向量遍历回调
 *
 * memory_id 为 NUL 结尾文本；blob 只在回调期间有效，不得持有。
 * 返回非 0 中止遍历，err 内容会带进 "sqlite: vector <id>: ..."。
 */
typedef int (*aik_sqlite_vec_visit)(void *ctx, const char *memory_id,
				    const void *blob, size_t len,
				    char *err, size_t errlen);

/*
 * aik_sqlite_for_each_vector - 按 rowid（插入）序遍历全部向量
 *
 * 成功返回 0；缺 vectors 表或回调失败返回 -1 并写 err。
 */
int aik_sqlite_for_each_vector(aik_sqlite *db, aik_sqlite_vec_visit fn,
			       void *ctx, char *err, size_t errlen);

/*
 * aik_sqlite_wal_append - 追加一条 op 文本
 *
 * 首次调用建 wal_ops 表。op_json 按原文写入（调用者保证是紧凑 JSON；
 * 参考实现写 json.dumps 结果）。成功 0，*seq（非 NULL 时）收
 * last_insert_rowid()；失败 -1。
 */
int aik_sqlite_wal_append(aik_sqlite *db, const char *op_json,
			  long long *seq, char *err, size_t errlen);

/*
 * aik_sqlite_wal_replay - 只读重放
 *
 * 按表内 seq 升序读取（仅用于排序）；每行 op 文本用 aik_json_parse 解析成
 * 对象后，按 op **内嵌的 "seq"** 决定是否跳过（与参考实现
 * `if seq and seq <= checkpoint` 一致）：
 *   - 缺失 → 0，0 永不因 checkpoint 跳过；
 *   - 非整数（含 JSON 字符串/布尔）或负数 → -1，err 形如
 *     "sqlite: wal record N: invalid WAL sequence"（N 为 1 起的记录序号，
 *     行保留，不删除/不改写）；
 *   - 仅 seq > 0 且 seq <= checkpoint 时跳过。
 * 非法 JSON / 非对象同样返回 -1（err "sqlite: wal record N: ..."）。
 * 返回回调次数（>= 0）。checkpoint 语义与参考一致：序列号 <= checkpoint
 * 的 op 已在快照里。
 */
int aik_sqlite_wal_replay(aik_sqlite *db, long long checkpoint,
			  aik_wal_visit fn, void *ctx,
			  char *err, size_t errlen);

/*
 * aik_sqlite_wal_clear - 清空 wal_ops 行（DELETE FROM wal_ops）
 *
 * 不动 sqlite_sequence（与参考 reset() 一致：后续 append 的 seq 继续
 * 递增，不会复用已 checkpoint 的序号）。首次调用建表。成功 0 / 失败 -1。
 */
int aik_sqlite_wal_clear(aik_sqlite *db, char *err, size_t errlen);

/* ------------------------------------------------------------------ */
/* 只读辅助（T2b-2 为门禁与诊断新增，不属于参考 API）                  */
/* ------------------------------------------------------------------ */

/*
 * aik_sqlite_busy_timeout_get - 查询当前 busy_timeout（PRAGMA 读回）
 * 成功 0 / 失败 -1。
 */
int aik_sqlite_busy_timeout_get(aik_sqlite *db, int *ms,
				char *err, size_t errlen);

/*
 * aik_sqlite_handle - 返回底层 sqlite3*（以 void * 暴露，避免公共头
 * 依赖第三方头文件）。仅供测试/诊断（例如制造坏库的 DROP TABLE）；
 * 正常读写路径必须走本模块 API。db 为 NULL 时返回 NULL。
 */
void *aik_sqlite_handle(const aik_sqlite *db);

#endif /* _AIK_STORE_SQLITE_H */
