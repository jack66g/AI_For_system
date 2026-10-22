/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ask_context.h - ask 上下文注入/预算口径/系统提示运行时策略段（W55/W56）
 *
 * 与 cmd_ask.c 同目录；实现留在 ask_context.c（纯函数），此处只暴露
 * 给 cmd_ask.c 与专项测试复用，避免测试重复实现解析/百分比逻辑。
 */
#ifndef _AI_ASK_CONTEXT_H
#define _AI_ASK_CONTEXT_H

#include <stddef.h>

/* 内核状态紧凑摘要硬上限（字节，含 NUL 前） */
#define ASK_STATUS_SUMMARY_MAX 2048

/* ask 入口自动 compact 触发阈值（历史估算占历史预算的百分比，W56） */
#define ASK_AUTOCOMPACT_PCT 80

/*
 * W72：压缩后冷却轮数。W70 实测 T08→T09、T16→T17 连续两轮压缩；
 * 压缩后至少跳过 2 个 ask 轮（上下文再次越线也不压），第 3 轮才允许
 * 下一次，避免"压缩→工具结果又越线→再压缩"的抖动。
 */
#define ASK_COMPACT_COOLDOWN_TURNS 2

/*
 * W59：历史预算口径统一（cmd_ask/cmd_compact 共用）。
 * 历史可用预算 = ctx_len - 生效 max_tokens - 预留；下限 1024 防 ctx_len
 * 配得过小时预算归零。预留覆盖 system+tools schema+本轮问题+注入。
 */
#define ASK_HIST_RESERVE_TOKENS 3000
#define ASK_HIST_BUDGET_MIN     1024

/*
 * ask_ctx_hist_budget - 历史可用 token 预算
 * @ctx_len:    客户端上下文预算
 * @max_tokens: 生效生成上限（ai_config_effective_max_tokens，<=0 视为 0）
 */
long ask_ctx_hist_budget(int ctx_len, int max_tokens);

/*
 * ask_status_summary_build - /proc/ai/status 全文 → 紧凑摘要
 * @status: 完整 status 文本（约 30KB/841 行）
 * @out:    输出缓冲
 * @out_sz: 缓冲大小（建议 ASK_STATUS_SUMMARY_MAX）
 *
 * 只保留 runtime_state/enabled/log_level/telemetry_ring/telemetry_drain/
 * models 行数+模型名/dropped 总量与 top3；忽略每 CPU 的 sample_rate
 * 明细。返回写入字节数（不含 NUL），参数非法或空输入返回 -1。
 */
int ask_status_summary_build(const char *status, char *out, size_t out_sz);

/*
 * ask_prompt_policy_notes_build - system prompt 运行时策略段（W56）
 * @assume_yes: 预授权状态（ai_policy_get_assume_yes）
 * @plan_mode:  plan 只读模式（ai_policy_get_plan_mode）
 * @out/@out_sz: 输出缓冲（建议 ≥1024）
 *
 * 依次追加：assume_yes 预授权说明（plan 模式优先，plan=1 时省略）、
 * 语言默认说明。返回写入字节数（不含 NUL），参数非法返回 -1。
 */
int ask_prompt_policy_notes_build(int assume_yes, int plan_mode,
				  char *out, size_t out_sz);

/*
 * ask_ctx_budget_percent - 本次请求上下文占用百分比
 * @last_in:  最近一次请求 prompt_tokens（<=0 视为 0）
 * @last_out: 最近一次请求 completion_tokens（W56 起不再计入窗口；
 *            保留参数以兼容调用点/旧测试）
 * @ctx_len:  客户端上下文预算（token）
 *
 * 窗口语义 = 最近一次请求的输入 prompt（completion 是输出，受
 * max_tokens 约束且会体现在下一次 prompt 里，二者相加会重复计数，
 * compact 后出现 >100% 假警告）。0-100 钳位（W72：提示符/警告都
 * 显示"当前请求 / ctx_len"，上限 100%，不再出现 999%）。
 */
int ask_ctx_budget_percent(int last_in, int last_out, int ctx_len);

/*
 * ask_ctx_prompt_percent - 提示符实时上下文百分比（W72）
 * @last_in:  最近一次请求 prompt_tokens（<=0 表示尚无 usage 数据）
 * @ctx_len:  客户端上下文预算（token）
 *
 * 返回 -1=无数据（提示符显示 "?"）；否则 0-100（>ctx_len 钳到 100）。
 * 语义与 ask_ctx_budget_percent 一致，但把"无数据"与"0%"区分开。
 */
int ask_ctx_prompt_percent(int last_in, int ctx_len);

/*
 * ask_ctx_should_autocompact - 历史估算是否达到自动 compact 阈值
 * @used_est:   当前历史估算 token（ask_msg_est_tokens 累加）
 * @budget:     历史可用预算（ctx_len - max_tokens - 预留）
 *
 * 达到 ASK_AUTOCOMPACT_PCT（80%）返回 1。阈值从 W55 的 85% 提前，
 * 给 compact 本身（摘要请求）留出窗口，避免压缩请求自身超预算。
 */
int ask_ctx_should_autocompact(long used_est, long budget);

#endif /* _AI_ASK_CONTEXT_H */
