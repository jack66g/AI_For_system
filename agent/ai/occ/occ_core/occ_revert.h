/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_revert.h - /undo 三段式（T9b2；OCD 规格 §7.3 headless 形态）
 *
 * 三段语义（对齐 opencode revert.ts）：
 *   stage  = occ undo：找边界（最近 N 步的首条 user 消息）→ 边界及之后
 *            可见消息标 reverted=1（隐藏，不进上下文/不计步）→ 被撤范围内
 *            write/edit 触及文件按快照回滚（最早快照=改动前状态；ABSENT
 *            墓碑=删除该文件）→ undo 前现状另存 _redo/ 段（供 redo）→
 *            写 occ_revert 行 + system 注记消息（下轮模型知道哪些改动被撤）
 *   commit  = 用户重发（loop add_user 前自动）：occ_revert 行删除+redo 段
 *            清理——撤销落地、不可再 redo（消息保持 reverted 态）
 *   redo    = occ redo：_redo 段还原文件 + 消息取消隐藏 + 删注记+occ_revert
 *
 * 一步 = 一条 user 消息起的整个 turn；--step N=撤最近 N 步（可叠加：再次
 * undo 从现边界再往深处数）。文件恢复目标=被撤范围内该文件最早一次
 * write/edit 的快照（=范围起改前状态）。
 *
 * 边界与状态约束：status==running（环在跑）拒绝 undo；active/error/
 * interrupted 可撤。被撤范围无任何文件快照（纯对话轮/快照缺失）→ 人话
 * 报错不改库（先收集后提交，部分失败如实列出）。
 *
 * bash 修改的文件无快照（b1 只对 write/edit 快照）→ 不在恢复集内，
 * 报告如实列出（不谎称全量回滚）。
 */
#ifndef _OCC_REVERT_H
#define _OCC_REVERT_H

#include "occ_session.h"

#define OCC_UNDO_MAX_FILES 256		/* 单次 undo 受影响文件上限 */

/* 单文件回滚动作 */
#define OCC_UNDO_RESTORE 0		/* 快照回填（内容还原） */
#define OCC_UNDO_DELETE  1		/* ABSENT 墓碑 → 删除文件 */

typedef struct occ_undo_file {
	char *path;			/* 绝对路径（heap） */
	int action;			/* OCC_UNDO_RESTORE / _DELETE */
	int failed;			/* 1=回滚失败（err 见失败时 stderr） */
} occ_undo_file;

typedef struct occ_undo_result {
	char boundary_user_msg[OCC_ID_LEN];	/* 边界（被撤首条 user） */
	char *user_text;		/* 被撤最后一条 user 文本（回填语义；
					 * heap，可 NULL） */
	char note_msg[OCC_ID_LEN];	/* undo 注记消息（system） */
	occ_undo_file files[OCC_UNDO_MAX_FILES];
	size_t nfiles;			/* 受影响文件数（含跳过项） */
	size_t nskipped;		/* 无快照跳过数（bash 改动等） */
	size_t nmsgs_reverted;		/* 被标 reverted 的消息数 */
} occ_undo_result;

void occ_undo_result_free(occ_undo_result *r);

/*
 * occ_undo - 撤销最近 steps 步（≥1）。
 * 成功 0（*out 填充）；无可撤/状态不合法/无快照 -1（err 人话，不改库）。
 * snaproot NULL=OCC_SNAPROOT 缺省族。files 顺序=发现顺序（最早快照优先）。
 */
int occ_undo(occ_db *db, const char *session_id, int steps,
	     const char *snaproot, occ_undo_result *out,
	     char *err, size_t errlen);

/*
 * occ_redo - 撤销 undo（revert.clear）：_redo 段还原 + 消息解隐藏 +
 * 删注记 + 删 occ_revert。成功 0；无 stage 态 -1（人话）。
 * out 可 NULL（只要效果）；非 NULL 时 files 填还原文件清单。
 */
int occ_redo(occ_db *db, const char *session_id, const char *snaproot,
	     occ_undo_result *out, char *err, size_t errlen);

/*
 * occ_revert_commit - 用户重发即认（loop add_user 前调用）：
 * 删 occ_revert 行 + 清 _redo 段。无 stage 态=无操作（0）。
 * 幂等，绝不失败阻断主流程（失败仅 stderr 警告）。
 */
void occ_revert_commit(occ_db *db, const char *session_id,
		       const char *snaproot);

#endif /* _OCC_REVERT_H */
