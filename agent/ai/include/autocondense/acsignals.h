/* SPDX-License-Identifier: GPL-2.0 */
/*
 * acsignals.h - 压缩信号采集（collect）与候选判定（decide）
 *
 * T5b 逐语义复刻 ref-autocondense/signals.py（271 行）：
 *   - estimate_transcript_tokens：CJK×1 + 其他×0.25 按行估算（码点计数）；
 *   - urgency_of：水位 ≥ 0.85 → "urgent"，其余（含无水位）→ "normal"；
 *   - collect：token 来源 reported(10 轮新鲜) > estimated > reported(过期)；
 *     water=round(tokens/usable,4)；rounds_to_full 采样 ≥2 轮估算；
 *   - decide：固定判定顺序（in_progress → cooldown → plan_done →
 *     task_done → water_level → idle → turns → NO），reason 文案逐字。
 *
 * 时间走 acconfig.h 注入时钟（decide 的冷却剩余分钟、collect 的
 * minutes_since_condense / cooldown_active）。
 */
#ifndef _AIK_AUTOCONDENSE_ACSIGNALS_H
#define _AIK_AUTOCONDENSE_ACSIGNALS_H

#include "autocondense/acconfig.h"
#include "autocondense/acstate.h"

/* 水位达到该值即视为危急（判定矩阵放宽、可无视延迟窗口）*/
#define AC_URGENT_WATER 0.85

/* 上报 token 保鲜期（轮）；超过则回落 transcript 估算 */
#define AC_REPORTED_TOKEN_FRESH_TURNS 10

/*
 * ac_estimate_transcript_tokens - 估算 transcript(JSONL) 的 token 数
 *
 * path 为 NULL/空或非普通文件 → has=0；否则 has=1 且 *out =
 * int(Σ每行 CJK×1 + 其他×0.25)。universal newlines（\r\n→\n）；
 * UTF-8 坏字节按 errors="ignore" 丢弃。返回 0 成功。
 */
int ac_estimate_transcript_tokens(const char *path, int *has, long long *out);

/*
 * ac_urgency_of - 依 signals.water_level 计算紧急度
 *
 * water_level 为 INT/NUM（非 BOOL）且 ≥ 0.85 → "urgent"，否则 "normal"。
 */
const char *ac_urgency_of(const aik_json *signals);

/*
 * ac_collect - 从会话状态采集判定所需信号
 *
 * 返回键序（与 Python dict 插入序逐字对齐）：
 *   plan_total, plan_completed, plan_in_progress, turns_since_condense,
 *   minutes_since_condense, est_tokens, token_source, rounds_to_full,
 *   idle_rounds, water_level, cooldown_active, urgency
 */
aik_json *ac_collect(const ac_session *state, const ac_config *config);

/*
 * ac_decide - 按固定顺序判定是否产生压缩候选
 *
 * 返回 {should, trigger, urgency, reason, signals, action_hint}；
 * signals 原样回带（深拷贝）。now 取注入时钟。
 */
aik_json *ac_decide(const ac_session *state, const aik_json *signals,
		    const ac_config *config);

#endif /* _AIK_AUTOCONDENSE_ACSIGNALS_H */
