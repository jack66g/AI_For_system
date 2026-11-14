/* SPDX-License-Identifier: GPL-2.0 */
/*
 * task.h - occ 编排任务数据面（ORCH-DESIGN §2；波次 E1）
 *
 * 任务状态机（§2 拍板 2；非法迁移一律拒绝——返回错误不静默）：
 *
 *   pending → dispatched → in_review → ┬→ done（验收通过；触发压缩/记账
 *                                      │   为 E5/E7 棒，此处只落终态）
 *                                      ├→ rework（≤rework_max）→ dispatched ↺
 *                                      └→ escalated（重试超限：换智能体/
 *                                          拆任务/上抛用户）
 *
 * 迁移表（状态 × 动作 → 新状态；× = 拒绝）：
 *   from        action                to          记事件
 *   pending     dispatch(child)       dispatched  dispatch
 *   rework      dispatch(child?)      dispatched  dispatch（回炉再派）
 *   dispatched  review(result)        in_review   result
 *   in_review   verdict(pass)         done        verdict + done
 *   in_review   verdict(fail) 未超限  rework      verdict + rework
 *   in_review   verdict(fail) 已超限  escalated   verdict + escalate
 *   dispatched  escalate(reason)      escalated   escalate
 *   in_review   escalate(reason)      escalated   escalate
 *   rework      escalate(reason)      escalated   escalate
 *   done        distill(payload)      done(不变)  distill（蒸馏审计）
 *
 * occ_task_event 为迁移审计（trace 精神）：每次动作按上表追加事件行
 * （kind=payload_json 原文可 NULL→空串），created=epoch ms。
 *
 * schema v3（DDL 见 task.c；迁移编排见 session.c occ_db_open）：
 *   occ_task(id, parent_session, child_session, title, brief_json,
 *            status, rework_count, rework_max, verdict_json,
 *            budget_in, budget_out, created, updated)
 *            —— brief_json=§3 任务书全文（goal/fileset/…/rework_max）；
 *               budget_in/out 逐任务记账列（E1 建面；E7 记账管线消费：
 *               occ_task_budget_add/baseline 累加+审计，orch.c 终局回
 *               收从子会话 usage 真值落账——见 orch.h E7 段）
 *   occ_task_event(id AUTOINCREMENT, task_id, kind, payload_json, created)
 *
 * 线程/事务：与 session.c 同口径——每动作单事务（BEGIN IMMEDIATE…
 * COMMIT，失败 ROLLBACK）；SQL 全绑参，无字符串拼接注入面。
 */
#ifndef _OCC_TASK_H
#define _OCC_TASK_H

#include "occ_session.h"

/* 任务状态（occ_task.status；取值集=§2 状态枚举） */
#define OCC_TASK_ST_PENDING	"pending"	/* 已建未派 */
#define OCC_TASK_ST_DISPATCHED	"dispatched"	/* 已派子智能体执行中 */
#define OCC_TASK_ST_IN_REVIEW	"in_review"	/* 子交结果待验收 */
#define OCC_TASK_ST_REWORK	"rework"	/* 验收不通过待回炉 */
#define OCC_TASK_ST_DONE	"done"		/* 验收通过（终态） */
#define OCC_TASK_ST_ESCALATED	"escalated"	/* 回炉超限上抛（终态） */

/* 事件 kind（occ_task_event.kind；§2 枚举） */
#define OCC_TASK_EV_DISPATCH	"dispatch"
#define OCC_TASK_EV_RESULT	"result"
#define OCC_TASK_EV_VERDICT	"verdict"
#define OCC_TASK_EV_REWORK	"rework"
#define OCC_TASK_EV_ESCALATE	"escalate"
#define OCC_TASK_EV_DONE	"done"
#define OCC_TASK_EV_DISTILL	"distill"
#define OCC_TASK_EV_RETURN	"return"	/* E3 追加：主会话 return
						 * 动作表态（不动状态机；
						 * E4 verdict 通道接入前的
						 * 最小承载） */
#define OCC_TASK_EV_BUDGET	"budget"	/* E7 追加：预算记账审计
						 * （不动状态机；payload
						 * 见 occ_task_budget_add/
						 * occ_task_budget_baseline） */

#define OCC_TASK_TITLE_MAX	128		/* title 容量（截断，同 session） */
#define OCC_TASK_REWORK_MAX_DEF	2		/* R2：缺省回炉上限 */
#define OCC_TASK_REWORK_MAX_HI	3		/* R2：brief 覆写上限 1-3 */

typedef struct occ_task_row {
	char id[OCC_ID_LEN];		/* tsk_ + 32 hex */
	char parent_session[OCC_ID_LEN];/* 主会话 id（建任务时钉死） */
	char child_session[OCC_ID_LEN];	/* 子会话 id；空=未派/未填 */
	char title[OCC_TASK_TITLE_MAX];
	char *brief_json;		/* heap；可 NULL（理论非空） */
	char status[16];
	int rework_count;		/* 已用回炉次数 */
	int rework_max;			/* 上限（R2：缺省 2） */
	char *verdict_json;		/* heap；可 NULL=尚无裁决 */
	long long budget_in;		/* 预算记账列（E7 消费；本棒恒 0） */
	long long budget_out;
	long long created;		/* epoch ms */
	long long updated;		/* epoch ms */
} occ_task_row;

typedef struct occ_task_event_row {
	long long id;			/* AUTOINCREMENT 行号（升序锚） */
	char task_id[OCC_ID_LEN];
	char kind[16];
	char *payload_json;		/* heap；可 NULL */
	long long created;		/* epoch ms */
} occ_task_event_row;

void occ_task_row_free(occ_task_row *r);
void occ_task_rows_free(occ_task_row *rows, size_t n);
void occ_task_event_rows_free(occ_task_event_row *rows, size_t n);

/*
 * occ_task_schema_v3 - 任务两表 DDL 落库（CREATE TABLE IF NOT EXISTS，
 * 幂等）。session.c occ_db_open 在建库事务内调用（新库建表 + v2→v3
 * 迁移都走这里；v3 库重复打开零副作用）。不自理事务——必须在调用方
 * 的 IMMEDIATE 事务内执行。
 */
int occ_task_schema_v3(occ_db *db, char *err, size_t errlen);

/*
 * occ_task_create - 建任务（status=pending、rework_count=0）。
 * parent_session 必须存在（人话报错）；rework_max<=0 → 缺省 2（R2），
 * >3 拒绝（覆写上限 1-3）。out 可 NULL；非 NULL 回填生成的 tsk_ 行。
 */
int occ_task_create(occ_db *db, const char *parent_session,
		    const char *title, const char *brief_json,
		    int rework_max, occ_task_row *out,
		    char *err, size_t errlen);

/* 读回：1=存在（*out 填充）；0=无；错 -1 */
int occ_task_get(occ_db *db, const char *id, occ_task_row *out,
		 char *err, size_t errlen);

/*
 * 列表：parent_session NULL=全部任务；非 NULL=该主会话名下。
 * created 降序（新在前）。*rows heap（值拷贝），返回行数；错 -1。
 */
int occ_task_list(occ_db *db, const char *parent_session,
		  occ_task_row **rows, size_t *n, char *err, size_t errlen);

/*
 * occ_task_dispatch - 派发（pending|rework → dispatched；事件 dispatch）。
 * child_session：子会话 id（R4 进程隔离=子会话 id 派发后填）；
 * NULL=保持原值（rework 回炉再派同子）。其余状态拒绝。
 */
int occ_task_dispatch(occ_db *db, const char *id, const char *child_session,
		      char *err, size_t errlen);

/*
 * occ_task_review - 子智能体交结果进验收位（dispatched → in_review；
 * 事件 result，payload=result_json）。result_json 可 NULL。
 */
int occ_task_review(occ_db *db, const char *id, const char *result_json,
		    char *err, size_t errlen);

/*
 * occ_task_verdict - 验收裁决（in_review 起）：
 *   pass=1 → done（事件 verdict + done；verdict_json 落库）
 *   pass=0 且 rework_count+1 ≤ rework_max → rework（verdict + rework）
 *   pass=0 且已超限 → escalated（verdict + escalate）
 * verdict_json=裁决原文（对照哪条/差什么/证据在哪），可 NULL。
 */
int occ_task_verdict(occ_db *db, const char *id, int pass,
		     const char *verdict_json, char *err, size_t errlen);

/*
 * occ_task_escalate - 手动上抛（dispatched|in_review|rework → escalated；
 * 事件 escalate）。reason_json 可 NULL。pending/done/escalated 拒绝。
 */
int occ_task_escalate(occ_db *db, const char *id, const char *reason_json,
		      char *err, size_t errlen);

/*
 * occ_task_distill - 蒸馏审计事件（仅 done 态；状态不变；事件 distill）。
 * payload_json 可 NULL。非 done 拒绝（子完成即蒸馏，未完成任务无蒸馏）。
 */
int occ_task_distill(occ_db *db, const char *id, const char *payload_json,
		     char *err, size_t errlen);

/*
 * occ_task_note - E3 追加（API 阻断缺口：task 工具 return 动作需要
 * 落事件而不动状态机）：任意状态下追加 kind='return' 审计事件行，
 * 状态不变。payload_json 可 NULL。任务不存在/DB 错 → -1 人话。
 * kind 白名单不开放（固定 "return"——E4 verdict 通道接入时再扩面）。
 */
int occ_task_note(occ_db *db, const char *id, const char *payload_json,
		  char *err, size_t errlen);

/*
 * occ_task_budget_baseline - E7 追加（预算记账管线）：spawn 时预算
 * 基线入事件流——kind='budget'、payload={"phase":"baseline",
 * "max_tokens":N,"budget_in":cur,"budget_out":cur}（任务行两列不动，
 * 仍由 budget_add 累加）。任意状态可记（调用点=dispatched 后）；
 * 任务不存在/DB 错 → -1 人话。max_tokens<=0 → bad args。
 */
int occ_task_budget_baseline(occ_db *db, const char *id, long long max_tokens,
			     char *err, size_t errlen);

/*
 * occ_task_budget_add - E7 追加：budget_in/budget_out 单事务累加
 * （UPDATE 两列 + kind='budget' 审计事件，payload={"in":din,"out":dout,
 * "src":"usage"|"estimated","budget_in":new,"budget_out":new}）。
 * 数据源口径由调用方负责（orch.c：子会话 occ_message usage 真值
 * 优先，无 usage 时 len/4 估算兜底且 estimated=1）。delta 负值钳 0
 * （账本单调——消息被 /undo 隐藏等收缩不改已记账面）；钳 0 后两值
 * 皆零=no-op 返回 0（不落 UPDATE/事件——审计流只记真账）。任意状态
 * 可记（终局回收/在跑核账都合法）；任务不存在/DB 错 → -1 人话。
 */
int occ_task_budget_add(occ_db *db, const char *id,
			long long add_in, long long add_out, int estimated,
			char *err, size_t errlen);

/*
 * 事件审计列表（id 升序=时间序）。*rows heap，返回行数（0=*rows=NULL）；
 * 错 -1。
 */
int occ_task_events(occ_db *db, const char *id,
		    occ_task_event_row **rows, size_t *n,
		    char *err, size_t errlen);

#endif /* _OCC_TASK_H */
