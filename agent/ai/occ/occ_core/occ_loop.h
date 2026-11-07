/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_loop.h - occ agent 环（T9a3 最小环 + T9b1 工具环）
 *
 * 环语义（b1：六件套工具激活，OPENCODE-PLAN §6/§7）：
 *   输入消息落库（单事务，status=running）
 *   → 环迭代：上下文每轮从库重读（system prompt + 窗口全量 + 六件套
 *     tools 定义）→ occ_llm 流式调用 → assistant 消息落库（携带
 *     toolCall 时 interim：status 保持 running）
 *   → 有未应答 tool_call（新落库的或崩溃残留的）→ 逐个执行（occ_tools：
 *     快照→执行→trace→occ_toolcall 行 + tool 结果消息单事务落库）→
 *     续环（durable：先落库再回灌）
 *   → 直到无工具调用收口 / 步数上限 24 / OutputLimit 续 2 次 /
 *     LLM 失败（status=error）
 *
 * durable：一切状态先落库再前进；kill -9 任意时刻库中无半条消息
 * （session.c 事务保证）。occ --recover 对 status∈{running,error,
 * interrupted} 的会话用 prompt=NULL 重放/续跑：尾=user 重放整环；尾=
 * tool 或 assistant(toolCall 未全应答) 续环（先执行 pending 再 LLM 轮）。
 *
 * b2 中断（OCD §7.1 headless 版）：SIGINT 置 occ_interrupt_flag，安全点
 * 停——每工具后 / 每轮 LLM 前 / LLM 轮失败时检查；LLM 轮已产出 toolCall
 * 时该批仍整体执行以闭合上下文（工具应答不变量），执行中才观察到的
 * 中断对剩余调用合成「未执行」应答；status=interrupted 落库，下一条
 * user 自动附续传注记。新 user 落库前折叠 system 注记（undo 记录）并
 * commit 撤销态（OCD「用户重发即认」）。上下文组装过滤 reverted=1 与
 * system 行（opencode messagesFromRevert 同语义）。
 *
 * 工具意外失败（含未知工具名/沙箱不可用拒绝）：错误文本作为 tool 结果
 * 回灌模型继续环（不崩、不谎报成功）。
 */
#ifndef _OCC_LOOP_H
#define _OCC_LOOP_H

#include <stdio.h>

#include "occ_llm.h"
#include "occ_provider.h"
#include "occ_session.h"
#include "occ_tokens.h"

/* 环返回码 */
#define OCC_LOOP_OK 0
#define OCC_LOOP_EARGS (-1)		/* 参数/会话状态不合法 */
#define OCC_LOOP_ELLM (-2)		/* LLM 调用失败（网络/HTTP/流错） */
#define OCC_LOOP_ETOOLS (-3)		/* 保留（a3 语义位）；b1 起工具
					 * 调用为期望路径，环不再返回 */

/* 可注入传输（默认 occ_llm_call；单测注入 fixture 回放伪传输） */
typedef int (*occ_llm_call_fn)(const occ_provider *p, const occ_llm_req *req,
			       occ_event_cb cb, void *ud, char **err_out);

typedef struct occ_loop_opts {
	const char *prompt;		/* 本轮用户输入；NULL=重放中断环 */
	occ_llm_call_fn llm_call;	/* NULL=默认（含 forwarder→direct） */
	void *llm_ud;			/* 透传注入传输 */
	FILE *stream_out;		/* TEXT_DELTA 流式出口（NULL=静默） */
	FILE *reasoning_out;		/* 思维链出口（NULL=不打印，仍落库） */
	const char *workdir;		/* 工具工作目录（b1；NULL=getcwd）：
					 * glob/grep/bash rw 挂载面 */
} occ_loop_opts;

typedef struct occ_loop_result {
	char session_id[OCC_ID_LEN];
	char assistant_msg_id[OCC_ID_LEN];	/* 收口轮 assistant 消息 */
	char *text;			/* 收口轮回复（heap；loop 内 free 前有效） */
	char *reasoning;		/* 收口轮思维链全文（可 NULL） */
	occ_usage usage;		/* 收口轮回传 usage（present=0 则未回传） */
	int usage_est;			/* 1=估算（len/4，~） */
	occ_tokens tokens;		/* 收口轮五项账本（含 total） */
	char finish[24];		/* stop/length/tool-calls/... */
	int unexpected_toolcalls;	/* 本 turn 执行的工具调用总数（诊断） */
	int llm_error;			/* 1=收到 OCC_EV_ERROR */
	int rounds;			/* 环步数（LLM 轮+执行批） */
	int steps_capped;		/* 1=步数上限截断收口 */
	int interrupted;		/* b2：1=SIGINT 安全点停（status=
					 * interrupted；text/assistant_msg_id
					 * 已清空——本轮不冒充收口产物） */
} occ_loop_result;

void occ_loop_result_free(occ_loop_result *r);

/*
 * occ_loop_run - 跑一轮对话环（含工具环）。
 * session_id NULL → 新建会话（model 取 p->model）；非 NULL → 续接
 * （会话必须存在）。opts NULL = 全缺省（prompt 必须经 opts 给）。
 * res 可 NULL（headless 主路径要拿 assistant_msg_id/session_id）。
 * 成功返回 OCC_LOOP_OK；参数/落库错 EARGS；LLM 失败 ELLM
 * （session.status='error'，已落库消息保留）。
 */
int occ_loop_run(occ_db *db, const occ_provider *p, const char *session_id,
		 const occ_loop_opts *opts, occ_loop_result *res,
		 char *err, size_t errlen);

#endif /* _OCC_LOOP_H */
