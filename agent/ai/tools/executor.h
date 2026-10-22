// SPDX-License-Identifier: GPL-2.0
/*
 * executor.h - AI 工具自动执行器（channel 路由）
 *
 * Ask 闭环的执行端：注册表查到的工具 + 模型给出的 arguments JSON
 * → 按通道路由执行 → 收集结果文本（回填 role:tool 消息）。
 *
 * 权限分级（P2，已实现）：工具风险级（tools.json 单源 R/W1/W2）
 * → ai_policy_gate 判定：
 *   - W1（只读/低危）自动执行；
 *   - W2（写/高危）交互确认：红色影响面 + y/N（非 tty 环境直接
 *     拒绝，不静默放行），确认与拒绝均落 ~/.aikernel/audit.log。
 * 审计由两层承载：
 *   - 内核侧：netlink-act/sysfs-write 触发的决策自动进决策 ring
 *     （4096 条）与因果链（trigger→decision→outcome）；
 *   - Agent 侧：每次执行（含失败）输出 [audit] 行到 stdout（过程可见）。
 *
 * 安全边界（与权限分级无关的硬约束）：
 *   - exec 通道：命令白名单 + 路径白名单（/usr/bin、/bin）+ 参数过滤
 *     （拒绝 ; | & ` $ 换行等 shell 元字符），fork+execv 不经 shell；
 *   - procfs-read：只读注册表中登记的 /proc/ai/... 固定路径（不接受
 *     模型传任意路径）；
 *   - sysfs-write：只写注册表中登记的 /sys/kernel/ai/... 固定节点。
 */
#ifndef _AI_TOOL_EXECUTOR_H
#define _AI_TOOL_EXECUTOR_H

#include <stddef.h>
#include "tools/tool_registry.h"

/* 工具输出文本上限（回填给模型时截断，防上下文爆炸） */
#define TOOL_EXEC_OUT_MAX   32768

/*
 * 结构化参数错误前缀（W65 P2-01/P2-03）。
 * 形如 "ERROR[E_PARAM_MISSING]: ..."，后接 USAGE/AVAILABLE 指引。
 * cmd_ask 据此对参数错误做一次自动纠正重试（每轮最多一次），
 * 并把重试计入 trace（degraded 事件）。
 */
#define TOOL_ERR_PARAM_PREFIX "ERROR[E_PARAM"

/*
 * 策略拒绝结果前缀（W69 P1-4）。只有 plan/W2/黑名单/沙箱隔离等**策略
 * 拒绝**才带此前缀；二进制缺失、执行失败、参数错误一律记为 fail。
 * cmd_ask 的 trace status 与 M3 口径据此判定 denied。
 */
#define TOOL_ERR_DENIED_PREFIX "ERROR: DENIED:"

/*
 * tool_executor_run - 执行一个工具调用
 * @tool:     注册表中的工具（channel 决定路由）
 * @args_json: 模型给出的参数 JSON 对象字符串（"{}" 可为 NULL）
 * @out:      出参，结果文本（malloc，调用者需 free；含成功结果与
 *            失败原因，均为人可读文本，直接回填模型）
 * @ok:       出参（可 NULL），1=工具执行成功，0=失败
 * 返回: AI_OK（已执行，无论成败）；AI_ERR_INVALID_ARG 参数错误
 */
int tool_executor_run(const struct ai_tool *tool, const char *args_json,
		      char **out, int *ok);

/*
 * tool_exec_effective_risk - 计算一次调用的**有效风险级**（W48）
 * exec 通道按命令级基础 risk + args0 动词表 + 动态写参数判定
 * （curl POST/-o、ip add/set、ethtool -s、journalctl --vacuum、
 * crontab -r 等 → W2）；其余通道返回工具级 risk（缺失按 W1）。
 * 供权限闸门/plan 闸门/测试共用，保证闸门与执行段同一语义。
 * 返回静态字符串 "R"/"W1"/"W2"（不释放）。
 */
const char *tool_exec_effective_risk(const struct ai_tool *tool,
				     const char *args_json);

/*
 * tool_exec_memory_last_rc - 最近一次 memory 通道执行的真实返回码。
 * 供 cmd_ask 用 sme_degrade_reason_of() 区分 unavailable/http_error，
 * 不再把所有 memory 失败都记成 "sme unavailable"（W69 P2-3）。
 * 返回 AI_OK/AI_ERR_*（executor 进程内单线程调用语义）。
 */
int tool_exec_memory_last_rc(void);

/*
 * tool_exec_result_is_denied - 结果文本是否为**策略拒绝**（W69 P1-4）。
 * 只认 TOOL_ERR_DENIED_PREFIX；二进制缺失/执行失败/参数错误均返回 0。
 * cmd_ask 的 trace status 与 M3 口径共用本判定。
 */
int tool_exec_result_is_denied(const char *out);

#endif /* _AI_TOOL_EXECUTOR_H */
