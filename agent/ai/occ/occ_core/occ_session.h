/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_session.h - occ 会话生命周期 + SQLite 持久化（T9a3；T9b2 扩展）
 *
 * OPENCODE-PLAN §6 durable / §11 数据格式：一切状态先落 SQLite 再前进。
 * SQLite 引擎只读复用 T2 store 产出的 libsqlite3.a（sqlite3 amalgamation，
 * agent/ai/third_party/sqlite3，编译开关同 store/Makefile SQLITE_CFLAGS）；
 * occ 自有 schema 经原生 sqlite3 C API 管理（T2 store_sqlite 的
 * snapshots/vectors 语义与 occ 会话表不匹配，不套用）。
 *
 * schema（字段名 PLAN §11，part 键名对齐 opencode v2 message/part）：
 *   occ_session(id, title, created, model, tokens_total, status,
 *               updated, tokens_est, workdir, kind)  时间 epoch ms；
 *               workdir b2：本会话工具工作目录（undo 相对路径解析须与
 *               执行时同口径——每轮 loop 以 opts->workdir 刷新）；
 *               kind E1（ORCH §2）：会话类型——'main' 用户会话 /
 *               'child' 任务子会话（R4 进程隔离派生；老行缺省 'main'）
 *   occ_message(id, session_id, role, content_json, usage_in, usage_out,
 *               usage_cache_read, usage_cache_write, usage_est, finish,
 *               created, reverted)                reverted b2：/undo 隐藏位
 *               （1=不进上下文——opencode messagesFromRevert）
 *   occ_toolcall(id, message_id, tool, args_json, result_json, rc, dur_ms)
 *               （a3 空表先建，b1 工具环启用）
 *   occ_window(session_id, base_kind, digest_id)
 *               （a3 恒 native 单行；窗口裁剪/换窗 d 棒）
 *   occ_revert(session_id, boundary_msg, note_msg, created, files_json,
 *              hidden_json)
 *               （b2：/undo 三段式 stage 态——边界消息/undo 注记消息/
 *               受影响文件 JSON 数组/本 stage 隐藏的消息 id JSON 数组；
 *               commit=删行落地（消息保持隐藏）；redo=删行+按 hidden_json
 *               精确解隐藏——只解本 stage 隐藏的，早期已 commit 的保持隐藏）
 *
 * content_json = parts 数组（opencode part 同构）：
 *   user      [{"type":"text","text":...}]
 *   assistant [{"type":"reasoning","text":...}]? [{"type":"text","text":...}]?
 *             [{"type":"toolCall","toolCallID":..,"tool":..,"arguments":...}]*
 *   system    [{"type":"text","text":...}]（b2：occ 自身注记——undo 记录；
 *             组装上下文时在下一条 user 消息落库前折叠并入其文本，
 *             故请求中不产生连续 user，两协议均安全）
 *
 * 崩溃安全：每消息单事务（BEGIN IMMEDIATE…COMMIT，失败 ROLLBACK）。
 * 环协议：occ_msg_add_user 与 session.status='running' 同事务；
 * occ_msg_add_assistant 与 tokens_total 累计、status='active' 同事务。
 * kill -9 任意时刻：库中只有整条消息（无半条）；occ --recover 按
 * status∈{running,error,interrupted} + 尾消息 role 判定重放（occ.c /
 * loop.c）。b2 status 新值 'interrupted'：SIGINT 安全点停止；停止前
 * 未应答调用一律以「未执行」合成结果闭合（工具应答不变量恒成立）。
 *
 * schema 迁移：user_version 1→2（open 时 ALTER ADD COLUMN reverted +
 * CREATE occ_revert；旧库无损升级，test_revert 覆盖）；
 * 2→3（E1：ALTER occ_session+kind 补缺省 'main' + CREATE occ_task/
 * occ_task_event——DDL 见 task.c；v3 库重复打开零副作用，test_task 覆盖）；
 * 3→4（P-50：occ_revert+redo_json 列（_redo 段 DB 锚，redo 消费侧比对）
 * + 新表 occ_snap——快照 manifest（msg→{path,kind,sha256} 外部锚；
 * 威胁模型：对快照树有 FS 写权的攻击者无 DB 写权，sidecar 与快照同
 * 目录=自证，DB 行才是真锚）。写侧 tools.c occ_snapshot_stage 落行，
 * 消费侧 revert.c undo/redo 对账，test_revert I12-I18 覆盖）。
 *
 * 测试注入（仅单测使用，生产恒 0；occ_db_test_fault）：
 *   bit0：add_user 在 INSERT 后 COMMIT 前失败 → 断言回滚无半条
 *   bit1：add_assistant 同上
 */
#ifndef _OCC_SESSION_H
#define _OCC_SESSION_H

#include <stddef.h>

#include "occ_llm/occ_llm.h"	/* occ_usage */

/* E1：原生句柄出借声明用（前向类型——与 sqlite3.h 的 typedef 同型，
 * C11 允许重复 typedef；不强推 sqlite3.h 给全体消费方） */
typedef struct sqlite3 sqlite3;

#define OCC_ID_LEN 40			/* "ses_"/"msg_" + 32 hex + NUL */

/* 环状态（occ_session.status） */
#define OCC_ST_ACTIVE "active"		/* 无进行中环（正常） */
#define OCC_ST_RUNNING "running"	/* 环进行中（环开始置位） */
#define OCC_ST_ERROR "error"		/* 上次环失败（可续接/重试） */
#define OCC_ST_INTERRUPTED "interrupted"	/* b2：SIGINT 安全点停止
						 * （可 retry/续接/recover） */
const char *occ_sessions_dir(void);	/* E5 迁自 occ_ac.c（occ_sme 依赖；轻量链接不拖 occ_ac.o） */
#define OCC_ST_ARCHIVED "archived"	/* E1：/clear 归档（会话+消息原地
					 * 保留可找回，/sessions 可续聊） */

/* E1（ORCH §2）：会话类型（occ_session.kind） */
#define OCC_SK_MAIN "main"		/* 用户会话（对话用户；缺省值） */
#define OCC_SK_CHILD "child"		/* 任务子会话（子智能体执行载体；
					 * 蒸馏后 archived——E5） */

typedef struct occ_db occ_db;

typedef struct occ_session_row {
	char id[OCC_ID_LEN];
	char title[128];
	char model[96];
	long long created;		/* epoch ms */
	long long updated;		/* epoch ms */
	long long tokens_total;		/* Σ(usage_in+usage_out)（含估算成分时照加） */
	int tokens_est;			/* 1=会话累计含 len/4 估算值（显示 ~） */
	char status[16];
	char workdir[4096];		/* b2：工具工作目录（undo 相对路径
						 * 解析与执行时同口径；空=未设置） */
	char kind[16];			/* E1：main=用户会话 / child=任务
						 * 子会话（老行读回 'main'） */
} occ_session_row;

/*
 * 消息行（读回形态）。content_json 为原文（heap，调用者 free）；
 * text/reasoning/calls* 为解析提取的便捷视图（heap 或 NULL，一并 free，
 * 由 occ_msg_row_free 统一释放——各指针独立 malloc，互不重叠）。
 */
typedef struct occ_toolcall_part {
	char *id;			/* toolCallID */
	char *tool;
	char *arguments;		/* JSON 文本 */
} occ_toolcall_part;

typedef struct occ_msg_row {
	char id[OCC_ID_LEN];
	char role[12];			/* user|assistant|tool|system */
	char *content_json;
	char *text;			/* 首个 text part；role=tool 时=
					 * toolResult 的 output（T9b1） */
	char *reasoning;			/* 首个 reasoning part */
	char *tool_call_id;		/* role=tool：对应 toolCallID（T9b1） */
	occ_toolcall_part *calls;	/* toolCall parts（assistant） */
	size_t ncalls;
	long long usage_in, usage_out;
	long long usage_cache_read, usage_cache_write;
	int usage_est;			/* 1=估算（~） */
	char finish[24];			/* assistant finish；user 为空串 */
	long long created;		/* epoch ms */
	int reverted;			/* b2：1=/undo 已隐藏（不进上下文） */
	long long rowid;		/* b2：插入序锚点（undo 边界判定） */
} occ_msg_row;

void occ_msg_row_free(occ_msg_row *r);
void occ_msg_rows_free(occ_msg_row *rows, size_t n);

/* ---- DB 生命周期 ---- */

/*
 * occ_db_open - 打开（必要时递归建目录+建库）。path NULL = 缺省
 * ~/.occ/sessions.db。PRAGMA busy_timeout=5000（T2 约定）、
 * foreign_keys=ON（CASCADE 生效）、journal_mode=WAL（E2/B2：多进程
 * 读写不互斥；开库处一次性设置+读回校验，非 wal 报错不降级）、
 * user_version=4（P-50；v1/v2/v3 旧库自动链式迁移）。
 */
occ_db *occ_db_open(const char *path, char *err, size_t errlen);
void occ_db_close(occ_db *db);
const char *occ_db_path(const occ_db *db);	/* 诊断/测试 */

/* E1：原生句柄出借（occ_core 内部——task.c 等自有 schema 模块用；
 * 借用方不得改 occ_session 族表结构。外部测试勿依赖） */
sqlite3 *occ_db_sqlite(occ_db *db);

/* 测试注入：置 fault mask（生产勿调用）。返回旧值。 */
int occ_db_test_fault(int mask);

/* ---- 会话 ---- */

/* 新建会话（ses_ id 随机、title 空、status=active、occ_window native 行） */
int occ_session_create(occ_db *db, const char *model,
		       occ_session_row *out, char *err, size_t errlen);

/* E1：kind 版建会话（'main'/'child'，其余值拒绝；NULL/空=main）。
 * occ_session_create ≡ create_kind(main)。 */
int occ_session_create_kind(occ_db *db, const char *model, const char *kind,
			    occ_session_row *out, char *err, size_t errlen);

int occ_session_get(occ_db *db, const char *id, occ_session_row *out,
		    char *err, size_t errlen);

/* 列表：created 降序（新在前）。rows 数组 heap（occ_msg_rows_free 式，
 * 元素为值拷贝、无堆指针——直接 free(*rows) 即可）。 */
int occ_session_list(occ_db *db, occ_session_row **rows, size_t *n,
		     char *err, size_t errlen);

/* title/status 单独更新（status 同时刷新 updated） */
int occ_session_set_title(occ_db *db, const char *id, const char *title,
			  char *err, size_t errlen);
int occ_session_set_status(occ_db *db, const char *id, const char *status,
			   char *err, size_t errlen);

/* b2：工具工作目录落库（loop 每轮以 opts->workdir 刷新；undo 据此以
 * 执行时同口径解析历史 toolcall 的相对路径）。workdir 空=清除。 */
int occ_session_set_workdir(occ_db *db, const char *id, const char *workdir,
			    char *err, size_t errlen);

/* T9d 换窗：token 账本重置为新基线（total=新基线，est=1 含估算成分） */
int occ_session_set_tokens(occ_db *db, const char *id, long long total,
			   int est, char *err, size_t errlen);

/* T9d 换窗：occ_window.base_kind→'digest'（digest_id=摘要注记行 id） */
int occ_session_set_window_digest(occ_db *db, const char *id,
				  const char *digest_id, char *err,
				  size_t errlen);

/*
 * E1（ORCH §2 拍板 6）：/clear 的库面半件——归档+换窗，单事务：
 * status→'archived'（会话+消息原地保留可找回）+ occ_window 回 native
 * 空基线（digest_id 置空——窗口换新而非删历史）。幂等；不存在 -1。
 */
int occ_session_archive(occ_db *db, const char *id, char *err,
			size_t errlen);

/*
 * O-12：删除会话（级联消息+工具调用+窗口+回滚+transcript 文件）。
 * BEGIN IMMEDIATE 单事务：存在性预检（不存在 → 人话错误
 * 「会话 … 不存在」）→ DELETE occ_message（occ_toolcall 随外键
 * CASCADE）→ DELETE occ_window → DELETE occ_revert → DELETE
 * occ_session → 提交前 COUNT 复核为 0。提交后事务外 best-effort
 * 清理会话侧文件 <OCC_SESSIONS_DIR>/<sid>.jsonl（transcript）与
 * <sid>.smeq（配额计数；目录解析口径同 occ_ac.c occ_sessions_dir：
 * OCC_SESSIONS_DIR > $HOME/.occ/sessions——session.o 独立解析，
 * 不链 occ_ac）。文件清理失败不回滚 DB（删除已 durable；残留文件
 * 不复活会话）。
 * 返回 0=成功；-1=不存在或 DB 错。
 *
 * 调用方（O-12 UX 棒接线，库层不做）：occ.c 的 /delete 命令与
 * occ_tui /sessions 面板 d 键。
 */
int occ_session_delete(occ_db *db, const char *session_id,
		       char *err, size_t errlen);

/* ---- 消息（每条单事务） ---- */

/*
 * occ_msg_add_user - 用户消息落库。
 * 同事务：INSERT user 消息 + session.status='running' + updated=now；
 * 若会话 title 为空 → title=首条消息前缀（UTF-8 截断 48 字节）。
 * msg_id 可 NULL；非 NULL 时拷贝生成的 msg_ id（≥OCC_ID_LEN）。
 */
int occ_msg_add_user(occ_db *db, const char *session_id, const char *text,
		     char *msg_id, size_t idlen, char *err, size_t errlen);

/*
 * occ_msg_add_assistant - 完成消息原子落库（崩溃安全核心）。
 * 同事务：INSERT assistant 消息（text/reasoning/calls → parts）+
 * session.tokens_total += usage_in+usage_out（est 传入置 tokens_est=1，
 * 只升不降）+ status='active' + updated=now。
 * u NULL/!present 时 usage 落 NULL（est=1 由调用方估好传入）。
 * finish NULL=""。msg_id 语义同上。
 */
int occ_msg_add_assistant(occ_db *db, const char *session_id,
			  const char *text, const char *reasoning,
			  const occ_tool_call *calls, size_t ncalls,
			  const occ_usage *u, int est, const char *finish,
			  char *msg_id, size_t idlen,
			  char *err, size_t errlen);

/*
 * occ_msg_add_assistant_ex - 同上 + interim 标志（T9b1 工具环）：
 * interim=1（该 assistant 消息携带 toolCall、环未收口）→ 同事务
 * status='running'（而非 'active'），tokens 照累计。崩溃窗口内
 * status=running + 尾消息=assistant(toolCall) 或 tool → --recover
 * 续环（occ_msg_pending_calls 判定未应答调用）。
 */
int occ_msg_add_assistant_ex(occ_db *db, const char *session_id,
			     const char *text, const char *reasoning,
			     const occ_tool_call *calls, size_t ncalls,
			     const occ_usage *u, int est, const char *finish,
			     int interim, char *msg_id, size_t idlen,
			     char *err, size_t errlen);

/*
 * occ_tool_record - 工具执行结果 durable 落库（T9b1，单事务）：
 *   occ_toolcall 行（id=tc_…，message_id=携带该 toolCall 的 assistant
 *   消息，tool/args_json/result_json/rc/dur_ms）
 * + occ_message 行（role='tool'，content=[{"type":"toolResult",
 *   "toolCallID":…,"tool":…,"output":…}]，usage/finish 空）。
 * 不触碰 session.status/tokens（环仍在途）。msg_id_out/tcrow_id_out
 * 可 NULL。先落库再回灌——loop 下轮从库重读（OPENCODE-PLAN §6）。
 */
int occ_tool_record(occ_db *db, const char *session_id,
		    const char *assistant_msg_id, const char *tool,
		    const char *args_json, const char *result_text,
		    int rc, long long dur_ms, const char *call_id,
		    char *msg_id_out, size_t msg_len,
		    char *tcrow_id_out, size_t tc_len,
		    char *err, size_t errlen);

/*
 * occ_msg_pending_calls - 末位 assistant 消息中未被 tool 消息应答的
 * 工具调用（T9b1 recover/续环判定）。*calls heap 拷贝（调用方
 * occ_msg_rows_free 式逐项 free id/tool/arguments 后 free 数组）；
 * asst_msg_id（可 NULL）回填携带消息 id。返回待执行数（0=无）；
 * 错 -1。语义：从尾向前扫，tool 行收集 toolCallID 到已应答集；
 * 首个 assistant 行（自尾向前）的 calls 减去已应答集 = pending；
 * 尾是 user（无 assistant 在后）→ 0。b2：reverted（被撤）行透明——
 * 被撤回合的调用不再是待办。
 */
int occ_msg_pending_calls(occ_db *db, const char *session_id,
			  occ_toolcall_part **calls, size_t *n,
			  char *asst_msg_id, size_t asst_len,
			  char *err, size_t errlen);

/* created 升序全量（窗口裁剪 d 棒；a3 全量=当前窗口）。b2：行含
 * reverted 标志与 rowid（过滤由调用方/revert.c 负责）。 */
int occ_msg_list(occ_db *db, const char *session_id,
		 occ_msg_row **rows, size_t *n, char *err, size_t errlen);

/* 最后一条（无消息 0 且 *out 零填充；有则 1；错 -1）。
 * b2：跳过 reverted=1 行（被撤消息对「尾态」不可见）。 */
int occ_msg_last(occ_db *db, const char *session_id, occ_msg_row *out,
		 char *err, size_t errlen);

/*
 * b2：最后一条真人 user 消息——按 rowid 取最后一条 role='user'，
 * **不跳过 reverted**（retry 语义=重发最近一次 prompt；undo 后最近
 * user 恰是被撤边界消息，重发即落地撤销——OCD「用户重发即认」）。
 * system 注记天然排除（role 过滤）。返回语义同 occ_msg_last。
 */
int occ_msg_last_user(occ_db *db, const char *session_id, occ_msg_row *out,
		      char *err, size_t errlen);

/* ---- b2：/undo 三段式支撑（逻辑主体在 occ_core/revert.c） ---- */

/*
 * occ_msg_add_note - occ 自身注记消息落库（role='system'，单事务）。
 * 与 add_user 的差异：不改 session.status、不更新 title。undo 记录走
 * 这里；下一条 user 消息落库前由 loop 折叠并入其文本（不留连续 user，
 * 两协议安全），折叠时删除该注记行。
 */
int occ_msg_add_note(occ_db *db, const char *session_id, const char *text,
		     char *msg_id, size_t idlen, char *err, size_t errlen);

/* 按 id 删单条消息（redo/undo 叠加时撤旧注记用；occ_toolcall 随外键
 * CASCADE；system 注记无子行，安全） */
int occ_msg_delete(occ_db *db, const char *msg_id, char *err, size_t errlen);

/*
 * occ_msgs_set_reverted - 按 id 列表（JSON 数组文本 ["msg_a",…]）批量
 * 置/清 reverted 标志，单事务。*n_out 可 NULL，回填实际改动行数。
 * undo 传新隐藏集合（flag=1）；redo 传 stage.hidden_json（flag=0）
 * ——只解本 stage 隐藏的，早期已 commit 的保持隐藏。
 */
int occ_msgs_set_reverted(occ_db *db, const char *session_id,
			  const char *ids_json, int flag, long long *n_out,
			  char *err, size_t errlen);

/*
 * occ_revert_row - stage 态（occ_revert 表）。files_json：本 stage
 * 受影响文件绝对路径 JSON 数组（redo 据此查 _redo 段）；hidden_json：
 * 本 stage 隐藏的消息 id JSON 数组（redo 据此精确解隐藏）；redo_json
 * （P-50）：_redo 段在盘文件锚 [{"path":…,"kind":"snap|absent",
 * "sha256":…},…]——undo 捕获时落、redo 消费前比对（空/损=全 legacy
 * 走 sidecar 校验，旧 stage 行兼容）。
 */
typedef struct occ_revert_row {
	char session_id[OCC_ID_LEN];
	char boundary_msg[OCC_ID_LEN];
	char note_msg[OCC_ID_LEN];
	long long created;
	char *files_json;		/* heap；可 NULL（理论不空） */
	char *hidden_json;		/* heap；可 NULL（理论不空） */
	char *redo_json;		/* heap；可 NULL（P-50 redo 锚） */
} occ_revert_row;

void occ_revert_row_free(occ_revert_row *r);

/* 读 stage 态：1=存在（*out 填充）；0=无；错 -1 */
int occ_revert_get(occ_db *db, const char *session_id, occ_revert_row *out,
		   char *err, size_t errlen);

/* 写/替换 stage 态（单事务；files/hidden/redo_json 可 NULL） */
int occ_revert_put(occ_db *db, const char *session_id,
		   const char *boundary_msg, const char *note_msg,
		   const char *files_json, const char *hidden_json,
		   const char *redo_json, char *err, size_t errlen);

/* 删 stage 态（redo/commit；不存在也返回 0） */
int occ_revert_clear(occ_db *db, const char *session_id,
		     char *err, size_t errlen);

/* ---- P-50：快照 manifest（occ_snap 表——DB 外部锚） ---- */

/*
 * occ_snap_row - manifest 行（值拷贝、无堆指针，直接 free 数组即可）。
 * 字段长度与 revert.c snap_ent 对齐：kind "snap"|"absent"、sha256 小写
 * hex（64+NUL）。message_id 形如 "msg_…"（FK occ_message）。
 */
typedef struct occ_snap_row {
	char message_id[OCC_ID_LEN];
	char path[4096];		/* 还原目标绝对路径 */
	char kind[8];			/* "snap" | "absent" */
	char sha256[65];		/* 内容/墓碑字节摘要 */
} occ_snap_row;

void occ_snap_rows_free(occ_snap_row *rows, size_t n);

/* 落/换 manifest 行（INSERT OR REPLACE；快照写入侧用——tools.c） */
int occ_snap_put(occ_db *db, const char *message_id, const char *path,
		 const char *kind, const char *sha256, char *err,
		 size_t errlen);

/*
 * occ_snap_rows_for_msgs - 按 msg id 集合载 manifest 行（undo 对账用）。
 * IN 列表按 64 一段分批查询合并（防 SQLITE_MAX_VARIABLE_NUMBER 上限）。
 * *rows heap（occ_snap_rows_free）；返回行数（0=无，*rows=NULL）；错 -1。
 */
int occ_snap_rows_for_msgs(occ_db *db, const char *const *msg_ids, size_t n,
			   occ_snap_row **rows, size_t *nout, char *err,
			   size_t errlen);

/* ---- b2：undo 范围内工具调用对账（revert.c 判「无快照跳过」用） ---- */

typedef struct occ_tc_row {
	char tool[40];			/* write/edit/bash/… */
	char *args_json;		/* heap（可 NULL） */
	int rc;
	long long msg_rowid;		/* 所属 assistant 消息插入序 */
	char msg_id[OCC_ID_LEN];
} occ_tc_row;

void occ_tc_rows_free(occ_tc_row *rows, size_t n);

/*
 * occ_toolcalls_since - 会话内所属消息 rowid≥min_rowid 的 occ_toolcall 行
 * （JOIN occ_message；按消息 rowid、行插入序升序）。*rows heap，返回行数
 * （0=无，*rows=NULL）；错 -1。
 */
int occ_toolcalls_since(occ_db *db, const char *session_id,
			long long min_rowid, occ_tc_row **rows, size_t *n,
			char *err, size_t errlen);

#endif /* _OCC_SESSION_H */
