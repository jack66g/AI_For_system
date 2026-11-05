/* SPDX-License-Identifier: GPL-2.0 */
/*
 * acstate.h - 会话状态 / 快照 / 事件流水的线程安全存储
 *
 * T5b 逐语义复刻 ref-autocondense/state.py（583 行）：
 *   - sessions-state.json（{"version":1,"saved_at",sessions:{sid:asdict}}，
 *     indent=2 无尾换行，原子写，损坏 quarantine 后清空）；
 *   - sessions.jsonl（每行 {"ts","event","session_id","cwd","data"} 默认
 *     分隔 ", "/": " + "\n"）；
 *   - snapshots/{hash}/index.json（indent=2，按 (ts,file) 字符串降序）；
 *   - snapshots/{hash}/{YYYYmmdd-HHMMSS}-{safe_trigger}[-N].md 快照正文；
 *   - snapshots/{hash}/delta-state.json（{"delta_since_full":N} + "\n"）；
 *   - project_hash = sha1(normcase(normpath(绝对路径)))[:10]。
 *
 * asdict 键序（dataclass 字段序）与 summary() 键序均逐字节对齐向量；
 * 时间全部走 acconfig.h 注入时钟。
 */
#ifndef _AIK_AUTOCONDENSE_ACSTATE_H
#define _AIK_AUTOCONDENSE_ACSTATE_H

#include "autocondense/acconfig.h"

#include <stddef.h>

/* ------------------------------------------------------------------ */
/* SessionState                                                        */
/* ------------------------------------------------------------------ */

typedef struct ac_session {
	char *session_id;
	char *cwd;			/* 缺省 "" */
	char *transcript_path;		/* NULL = None */
	int has_context_tokens;
	long long context_tokens;
	int has_est_tokens;
	long long est_tokens;
	aik_json *token_samples;	/* ARR，元素 {turn,tokens}；缺省空 */
	int has_context_tokens_turn;
	long long context_tokens_turn;
	int has_last_file_turn;
	long long last_file_turn;
	int has_last_fail_turn;
	long long last_fail_turn;
	aik_json *plan_items;		/* ARR，元素 {title,status,first_seen_turn,completed_turn} */
	aik_json *plan_archive;		/* ARR；mark_condensed 清空 */
	long long turns;
	long long turns_since_condense;
	char *last_condense_at;		/* ISO 或 NULL */
	char *cooldown_until;		/* ISO 或 NULL */
	char *last_trigger;		/* 或 NULL */
	int condensing;
	aik_json *last_judge;		/* {turn,ts,verdict,result} 或 NULL */
	int has_defer_until_turn;
	long long defer_until_turn;
	long long defer_streak;
	char *begin_mode;		/* "delta"|"full" 或 NULL */
	char *created_at;		/* ISO */
	char *last_seen;			/* ISO */
} ac_session;

/* 全新会话（session_id 拷贝；时间戳取注入时钟的 now）*/
ac_session *ac_session_new(const char *session_id, const char *cwd);

/* _session_from_dict：非对象 / 缺 session_id → NULL；已知键尽量还原 */
ac_session *ac_session_from_dict(const aik_json *d);

void ac_session_free(ac_session *s);

/* summary()：REST /session/start、/status 等返回的键序（24 键）*/
aik_json *ac_session_summary(const ac_session *s);

/* asdict：sessions-state.json 落盘键序（23 键，dataclass 字段序）*/
aik_json *ac_session_asdict(const ac_session *s);

/* ------------------------------------------------------------------ */
/* 纯工具                                                              */
/* ------------------------------------------------------------------ */

/* sha1(normcase(normpath(abs(cwd))))[:10] → out（11 字节含 NUL）。返回 0 */
int ac_project_hash(const char *cwd, char *out /* [11] */);

/* Path(cwd).name：末段（无则为 ""）；结果写入 out */
int ac_project_name(const char *cwd, char *out, size_t buflen);

/* normalize_status：completed/done→"completed"；
 * in_progress/in-progress/inprogress→"in_progress"；其余→"pending" */
const char *ac_normalize_status(const char *raw);

/* 活动类型（mark_activity kind 参数）*/
enum ac_activity {
	AC_ACTIVITY_FILE = 0,	/* 文件修改类工具 */
	AC_ACTIVITY_FAIL = 1,	/* 工具失败 */
};

/* ------------------------------------------------------------------ */
/* StateStore                                                          */
/* ------------------------------------------------------------------ */

typedef struct ac_store ac_store;

/*
 * ac_store_open - 打开（并加载）data_dir 下的状态
 *
 * cfg 为借引用（须比 store 长寿；mark_condensed 读 cooldown_minutes），
 * NULL 则用默认配置。data_dir 会做去尾斜杠规范化（Path 语义）。
 */
ac_store *ac_store_open(const char *data_dir, const ac_config *cfg);
void ac_store_close(ac_store *st);

/* 借引用读取（store 存续期内有效；操作需外部串行或依赖内部锁瞬间一致性）*/
const ac_config *ac_store_config(const ac_store *st);

/*
 * ac_store_set_psi_state - 设置/清除 sessions-state.json 顶层 "psi" 段
 *
 * K3d-1：psi 为 NULL 时清除该段（文件回到旧格式，逐字节兼容）；否则深
 * 拷贝后立即落盘。旧文件带 "psi" 键时加载器自然忽略（向后兼容）。
 */
int ac_store_set_psi_state(ac_store *st, const aik_json *psi);

/* 会话操作（返回 0 成功；-1 会话不存在等）。Python 可选参数用 has 标志：
 * cwd/transcript_path 传 NULL 表示不设置（Python 空串同样跳过）。*/
int ac_store_upsert(ac_store *st, const char *session_id, const char *cwd,
		    const char *transcript_path,
		    int has_context_tokens, long long context_tokens,
		    int has_est_tokens, long long est_tokens);
int ac_store_mark_activity(ac_store *st, const char *session_id,
			   enum ac_activity kind);
const ac_session *ac_store_get_session(ac_store *st, const char *session_id);

/* all_sessions：按 last_seen 字符串降序；返回 malloc 的指针数组
 * （只释放数组本身，元素归 store），*n 为个数 */
const ac_session **ac_store_all_sessions(ac_store *st, size_t *n);

int ac_store_set_condensing(ac_store *st, const char *session_id, int flag);
int ac_store_set_est_tokens(ac_store *st, const char *session_id,
			    int has_est, long long est);
int ac_store_bump_turn(ac_store *st, const char *session_id);
int ac_store_mark_condensed(ac_store *st, const char *session_id,
			    const char *trigger);

/* verdict 深拷贝；result "APPROVED"|"DEFERRED" */
int ac_store_record_judge(ac_store *st, const char *session_id,
			  const aik_json *verdict, const char *result);
int ac_store_set_defer_until_turn(ac_store *st, const char *session_id,
				  int has_turn, long long turn);
int ac_store_set_defer_streak(ac_store *st, const char *session_id,
			      long long streak);
int ac_store_set_begin_mode(ac_store *st, const char *session_id,
			    const char *mode /* NULL 清空 */);

/* update_plan：以 items（ARR of {title|content,status}）为准合并；
 * 消失的 completed 进 plan_archive；详见 state.py:360-405 */
int ac_store_update_plan(ac_store *st, const char *session_id,
			 const aik_json *items);

/* 只清当前计划里的 completed（被消费的不进 archive）*/
int ac_store_clear_completed_plan_items(ac_store *st, const char *session_id);

/* 事件流水 */
int ac_store_append_event(ac_store *st, const char *event,
			  const char *session_id /* 可 NULL */,
			  const char *cwd /* 可 NULL */,
			  const aik_json *data /* 可 NULL → {} */);
/* recent_events：返回 ARR（最近 n 条；n<=0 或 use_all 非 0 时全量）*/
aik_json *ac_store_recent_events(ac_store *st, size_t n, int use_all);

/* 快照 */
/*
 * ac_store_save_snapshot - 写正文 + 更新 index + 追加 condense 事件
 *
 * 返回索引条目 DOM（file,ts,trigger,session_id,title,char_count,
 * sme_memory_id,delta），*path_out（可 NULL）得到 malloc 的绝对路径；
 * 会话不存在返回 NULL。
 */
aik_json *ac_store_save_snapshot(ac_store *st, const char *digest_md,
				 const char *trigger, const char *session_id,
				 int delta, char **path_out);

/* delta-state：缺失/损坏按 0 */
long long ac_store_read_delta_state(ac_store *st, const char *project_hash_);
int ac_store_write_delta_state(ac_store *st, const char *project_hash_,
			       long long value);

/* 索引条目按 (ts,file) 降序；has_top_n=1 且 top_n>0 时截前 top_n */
aik_json *ac_store_list_snapshots(ac_store *st, const char *project_hash_,
				  int has_top_n, long long top_n);

/* 命中 file 的条目写入 sme_memory_id；返回 1 命中 / 0 未命中 */
int ac_store_set_snapshot_memory_id(ac_store *st, const char *project_hash_,
				    const char *file_path,
				    const char *memory_id);

#endif /* _AIK_AUTOCONDENSE_ACSTATE_H */
