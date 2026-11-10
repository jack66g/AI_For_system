/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_ac.h - occ × autocondense 绑定（T9d，OPENCODE-PLAN §9）
 *
 * occ 侧只做三件事（ac 内核 /check→/judge→/begin→digest→/commit 原样，
 * 本模块是**驱动方**不是重写方——等价于把 MCP 那条链在进程内走一遍）：
 *   ① transcript 实时落 <会话侧目录>/<id>.jsonl（ac 兼容行流，
 *      {ts,role,content,tool?,usage?}；ac 的 ac_estimate_transcript_tokens
 *      按行字符计费，格式只要求「一行一条」）；
 *   ② /check 轮询（每轮结束必查 + 轮间 30s 门）上报 token 水位
 *      （POST /session/start 的 context_tokens）+ transcript_path；
 *   ③ 收到 digest → **换窗**：隐藏（reverted=1）摘要前全部历史、落
 *      `〈会话摘要〉` system 注记（下一条 user 消息落库前由既有注记折叠
 *      机制并入其文本——不留连续 user，两协议安全）、token 账本重置为
 *      新基线、occ_window 记 digest。
 *
 * 状态经 NOTICE 上报（occ_tui 禁改，状态展示走事件字符串）：
 *   @ac:idle / @ac:working / @ac:ok / @ac:off
 *
 * 环境开关：
 *   OCC_AC=off             禁用 ac 绑定
 *   OCC_AC_URL             基地址（缺省 http://127.0.0.1:8762——T9d 改号）
 *   AUTOCONDENSE_BASE_URL  同上（ac 生态既有约定，次优先）
 *   OCC_SESSIONS_DIR       会话侧目录（缺省 $HOME/.occ/sessions）
 *   OCC_BIND               绑定总闸 auto|on|off（见 occ_bind_active）
 *   OCC_STATE_NOTICE       状态通告强制开关（headless 缺省不打——见下）
 *
 * 状态通告可见性（与「headless occ -p 输出逐字节不变」铁门的调和）：
 *   TUI（sink 回调在场）恒发；headless 仅当 stderr 是终端、或
 *   OCC_STATE_NOTICE=1 时发（=0 强制关）。重定向/管道=机器在读，保持
 *   字节合同；人跑在终端上照样看得到降级。
 *
 * 线程合同：与 occ_loop_run 同线程（worker）；内部静态状态无锁。
 */
#ifndef _OCC_AC_H
#define _OCC_AC_H

#include <stddef.h>

#include "occ_loop.h"
#include "occ_session.h"

/* 换窗定界（digest 注记文本前缀；折叠进下一条 user 文本） */
#define OCC_DIGEST_PREFIX "〈会话摘要〉\n"

/* ac 侧状态（NOTICE 文本） */
#define OCC_AC_ST_OFF "@ac:off"
#define OCC_AC_ST_IDLE "@ac:idle"
#define OCC_AC_ST_WORKING "@ac:working"
#define OCC_AC_ST_OK "@ac:ok"

/* ---- 绑定总闸（SME/ac 共用） ---- */

/*
 * occ_bind_active - 本轮是否启用外部绑定。
 *   OCC_BIND=on  → 恒启用（单测注入伪传输时用）
 *   OCC_BIND=off  → 恒禁用
 *   缺省 auto     → 仅在**真实传输路径**（opts->llm_call == NULL）启用：
 *                   注入传输 = 回放/单测路径，禁外部 HTTP 副作用——单测
 *                   零触网，也是 test_sink/test_loop 保持零 NOTICE 的原因。
 * opts 可 NULL（=全缺省 → 真实路径 → 启用）。
 */
int occ_bind_active(const occ_loop_opts *opts);

/* ---- ac 绑定 ---- */

int occ_ac_enabled(void);		/* env OCC_AC=off → 0 */
const char *occ_ac_status(void);	/* 见文件头四个宏 */

/* 会话侧目录：OCC_SESSIONS_DIR > $HOME/.occ/sessions（不存在则建）。
 * 失败返回 NULL（调用方降级：transcript 不落盘但不阻塞对话）。 */
const char *occ_sessions_dir(void);

/*
 * occ_ac_transcript - ① 落一行 transcript JSONL（role=user|assistant|
 * tool）。usage 可 NULL。返回 0=写出，-1=目录/IO 失败（不阻塞）。
 */
int occ_ac_transcript(const char *session_id, const char *role,
		      const char *content, const char *tool,
		      const occ_usage *usage);

/*
 * occ_ac_report - ② 上报：POST /session/start {session_id, cwd,
 * transcript_path, context_tokens}（ac_store_upsert 语义：只更新水位与
 * 路径，不重置轮次）。返回 0=可达，-1=不可达（状态转 off）。
 */
int occ_ac_report(const char *session_id, const char *cwd, long long tokens);

/* ② 轮询：GET /check?session_id=…；*should 填 "NO"/"JUDGE"/""（不可达）。
 * 返回 0=可达，-1=不可达。 */
int occ_ac_check(const char *session_id, char *should, size_t n);

/* 一次驱动（②+③）：轮询 →（JUDGE 时）判定 → begin → 摘要 → commit →
 * 换窗。force=1 跳过 check/judge 直接 begin（/compact 手动触发语义）。
 * *compacted 回填 1=本轮完成换窗。返回 0=完成（含「判定不需要压缩」
 * 与 ac 不可达），-1=链上某步失败（err 人话）。 */
typedef struct occ_ac_turn {
	occ_db *db;
	const occ_provider *p;
	occ_llm_call_fn call_fn;	/* NULL=occ_llm_call（单测可注入） */
	void *llm_ud;
	const occ_loop_opts *opts;	/* sink 通知；可 NULL */
	const char *session_id;
	const char *cwd;
	long long tokens;		/* 本轮结束时的 token 水位 */
	const char *context;		/* 收口回复（judge 判影响用，可 NULL） */
	int force;
	long long digest_chars;		/* out：本轮换窗摘要字符数（未换窗 0） */
} occ_ac_turn;

int occ_ac_turn_end(occ_ac_turn *t, int *compacted, char *err,
		    size_t errlen);

/*
 * occ_ac_compact_now - `/compact` 的 C API（命令行/slash 条目归后续棒，
 * 本棒只交付可调用入口；不碰 occ.c / occ_tui）。
 */
int occ_ac_compact_now(occ_ac_turn *t, char *err, size_t errlen);

/*
 * occ_ac_apply_digest - ③ 换窗本体（单测可直测）：
 *   1) 落 `〈会话摘要〉` system 注记（先落——中途崩溃时历史仍在，安全）；
 *   2) 摘要前全部消息置 reverted=1（上下文过滤既有机制，不删行——审计/
 *      undo 留档）；
 *   3) token 账本重置为新基线（system prompt + 摘要的 len/4 估算，
 *      tokens_est=1）；
 *   4) occ_window.base_kind → 'digest'（digest_id=注记行 id）。
 */
int occ_ac_apply_digest(occ_db *db, const char *session_id,
			const char *digest, char *err, size_t errlen);

/* 单测注入 digest/判定生成器（NULL=缺省走 LLM）。返回 0 且 *out=heap。 */
typedef int (*occ_ac_fill_fn)(void *ud, const char *prompt, char **out);
void occ_ac_set_fill(occ_ac_fill_fn fn, void *ud);

/* 单测直置状态（生产勿调用）；返回旧值。0=off 1=idle 2=working 3=ok */
int occ_ac_test_set_state(int v);

#endif /* _OCC_AC_H */
