/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_replay.h - TUI 历史回放规划器（OCC-DEBT：偿还 T9C2 裁定 2）
 *
 * 纯函数：durable SQLite 读回的 occ_msg_row 升序行 → 回放事件序列。
 * 不触 DB、不触 UI（occ.c 拿计划逐条 tui_view_post；tui_view 把事件
 * 渲染进 scrollback——OCD §1.3 尾部挂载语义的 occ 等价）。
 *
 * 规划规则：
 *   - reverted=1（/undo 隐藏）与 system 注记不回放（opencode
 *     messagesFromRevert 语义；注记本就折进下一条 user）；
 *   - role='tool' 行不单独回放——结果摘要折叠进所属 assistant 调用的
 *     TOOL_END（与 live 渲染同形：工具行挂在 assistant 块内）；
 *   - 连续 [assistant, tool*, assistant, …] 回合组折叠为一个
 *     BEGIN…END 块（live 一个 turn = 一个块，footer 一条）；
 *   - 行预算（max_lines>0 生效）：从尾部往前圈定，新到旧累加估算行数
 *     （72 列口径），超出即止；至少纳入最新一条可见消息（尾部保底）；
 *     预算外更早的可见消息数经 SEP 事件上报（「⋯ 更早 N 条」分隔行）。
 */
#ifndef _OCC_REPLAY_H
#define _OCC_REPLAY_H

#include <stddef.h>

#include "occ_session.h"

typedef enum {
	OCC_RP_SEP = 1,		/* 分隔行；rc=更早可见消息数（text=NULL） */
	OCC_RP_USER,		/* text=user 文本 */
	OCC_RP_BEGIN,		/* assistant 回合组块开始 */
	OCC_RP_REASON,		/* text=思维链（折叠单行渲染） */
	OCC_RP_TEXT,		/* text=正文（markdown-lite） */
	OCC_RP_TOOL_START,	/* text=工具名；arg=参数 JSON */
	OCC_RP_TOOL_END,	/* text=工具名；arg=结果摘要；rc=0 成功 */
	OCC_RP_END,		/* assistant 回合组块收口（footer 调用方定） */
} occ_replay_kind;

typedef struct {
	occ_replay_kind kind;
	const char *text;	/* 指向 rows 内存储（rows 存活期内有效） */
	const char *arg;	/* 同上；SEP 恒 NULL */
	int rc;			/* SEP=更早条数；TOOL_END=0 ok /1 fail */
} occ_replay_item;

/*
 * occ_replay_plan - 产出到 items（heap 数组，调用方 free(*items)）。
 * rows=occ_msg_list 升序输出；tcs=occ_toolcalls_since 全量工具结果
 * （msg_id+tool 定位 rc；两者均可 NULL/0）。max_lines<=0 = 不限。
 * *n_earlier=预算切割掉的更早可见消息数。返回 0；-1=OOM。
 */
int occ_replay_plan(const occ_msg_row *rows, size_t n,
		    const occ_tc_row *tcs, size_t ntc,
		    int max_lines,
		    occ_replay_item **items, size_t *nitems,
		    size_t *n_earlier);

/* 单消息行数估算（72 列口径；单测锚定）：user=1+⌈len/72⌉；
 * assistant=1(footer)+思维链 1+⌈len/72⌉+每调用 1；其余角色 0。 */
int occ_replay_est_lines(const occ_msg_row *r);

#endif /* _OCC_REPLAY_H */
