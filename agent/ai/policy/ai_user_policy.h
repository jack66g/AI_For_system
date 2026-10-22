// SPDX-License-Identifier: GPL-2.0
/*
 * ai_user_policy.h - AIKernel 用户权限分级策略（P2）
 *
 * 目标：让"谁在驱动 AI 代理"决定工具能自动执行到什么程度：
 *
 *   mode        生效对象            W1（只读/低风险）   W2（写/高影响）
 *   ----------  ------------------  ------------------  ------------------------
 *   privileged  uid 0（root）       ALLOW_AUTO          NEED_CONFIRM（二次确认）
 *   confirmed   sudo/wheel 组成员   ALLOW_AUTO          DENY（提示 sudo ai）
 *   restricted  其他所有用户        ALLOW_AUTO（白名单  DENY
 *                                   由 executor 把关）
 *
 * 配置来源（优先级从高到低）：
 *   1. ai_policy_init() 的 conf_path 参数；
 *   2. 环境变量 AIKERNEL_POLICY；
 *   3. 编译期默认 /etc/aikernel/policy.conf。
 * 配置为 INI 风格：
 *
 *   [root]
 *   mode = privileged
 *   [wheel]
 *   mode = confirmed
 *   group = sudo          # 可选：sudo 组名，缺省 wheel（Ubuntu 用 sudo）
 *   [default]
 *   mode = restricted
 *
 * 任何读取/解析失败一律回落 restricted（安全兜底）。
 */
#ifndef _AI_USER_POLICY_H
#define _AI_USER_POLICY_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 用户档位（对应 policy.conf 三个 section 的 mode 值） */
enum ai_policy_mode {
	AI_POLICY_MODE_PRIVILEGED = 0,  /* [root]     */
	AI_POLICY_MODE_CONFIRMED,       /* [wheel]    */
	AI_POLICY_MODE_RESTRICTED,      /* [default]  */
	AI_POLICY_MODE__COUNT,
};

/* 工具风险档位（由调用方按 channel 映射，见 executor 挂钩建议） */
enum ai_tool_risk {
	AI_RISK_W1 = 1,                 /* 只读/低风险：procfs-read/exec/memory */
	AI_RISK_W2 = 2,                 /* 写/高影响：sysfs-write/netlink-act   */
};

/* 判定结论 */
enum ai_policy_verdict {
	AI_POLICY_ALLOW_AUTO = 0,       /* 自动执行 */
	AI_POLICY_NEED_CONFIRM,         /* 需人工二次确认 */
	AI_POLICY_DENY,                 /* 直接拒绝 */
};

/*
 * ai_policy_init - 加载策略配置（进程内全局，可重复调用重载）
 * @conf_path: 配置路径；NULL 则按"环境变量 AIKERNEL_POLICY →
 *             /etc/aikernel/policy.conf"顺序解析。
 * 返回:  0 = 成功从文件加载；
 *        1 = 加载失败，已回落 restricted 兜底（功能仍可用）；
 *       -1 = 参数/内存错误。
 * 语义保证：调用后 ai_policy_check() 一定有安全结论。
 */
int ai_policy_init(const char *conf_path);

/* ai_policy_mode_for_uid - uid → 档位（root / 组成员 / 其他） */
enum ai_policy_mode ai_policy_mode_for_uid(uid_t uid);

/* ai_policy_check - 核心判定：uid + 工具风险档位 → 结论 */
enum ai_policy_verdict ai_policy_check(uid_t uid, enum ai_tool_risk risk);

/* 枚举 → 展示名（"privileged"/"confirmed"/"restricted" 等） */
const char *ai_policy_mode_name(enum ai_policy_mode m);
const char *ai_policy_verdict_name(enum ai_policy_verdict v);

/* ai_policy_conf_path - 实际生效的配置路径（init 后有效，便于日志） */
const char *ai_policy_conf_path(void);

/*
 * ai_policy_audit - 工具调用审计：追加一行到 $HOME/.aikernel/audit.log
 *   格式：<ISO 时间> uid=<uid> user=<name> mode=<mode> tool=<tool>
 *         args=<args> result=<result>   （单行；flock 防并发交错）
 * @result: 建议 "ALLOW_AUTO"/"NEED_CONFIRM"/"DENY"/"CONFIRM=yes"/"ok"/"fail"
 * 返回: 0 = 写入成功；-1 = 失败（审计失败不阻断业务，只打 stderr）。
 */
int ai_policy_audit(uid_t uid, enum ai_policy_mode mode,
		    const char *tool, const char *args, const char *result);

/*
 * W74：审计行尾追加 lease=<id> danger=<D> confirm=<source>
 * （旧 ai_policy_audit 等价于 lease="-"/danger="-"/confirm="none"）。
 */
int ai_policy_audit_ex(uid_t uid, enum ai_policy_mode mode,
		       const char *tool, const char *args, const char *result,
		       const char *lease_id, const char *danger,
		       const char *confirm_source);

/*
 * ai_policy_confirm_interactive - W2 二次确认交互
 * 红色 ANSI 输出影响面（工具名/参数/影响描述）后读 stdin 的 y/N；
 * stdin 非 tty（无人值守）一律拒绝（安全兜底）——除非调用方通过
 * ai_policy_set_assume_yes() 预授权（--yes / AIKERNEL_ASSUME_YES）。
 * 返回: 1 = 用户确认（或预授权自动确认）；0 = 拒绝/非 tty/读入失败。
 */
int ai_policy_confirm_interactive(const char *tool, const char *args,
				  const char *impact_desc);

/*
 * ai_policy_set_assume_yes - W2 确认预授权开关（修复 10）
 * 无人值守通道（API/脚本/管道）执行 W2 工具的显式授权入口：
 *   - CLI 全局参数 --yes / --assume-yes；
 *   - 环境变量 AIKERNEL_ASSUME_YES（"1"/"true"/"yes"/"on"）。
 * 开启后 NEED_CONFIRM 一律自动放行（审计记 CONFIRM=yes(auto)），
 * 预授权是明确的人工决定，不改变 restricted 档位 DENY 的判定。
 */
void ai_policy_set_assume_yes(int on);

/* ai_policy_get_assume_yes - 当前预授权状态 */
int ai_policy_get_assume_yes(void);

/*
 * ai_policy_set_plan_mode - plan（规划）只读模式开关（W43）
 * plan 态：工具执行闸门（executor.c）对非 R 级工具一律拒绝
 * （W1/W2 全拒、R 放行；exec 通道按命令级 risk 含 args0 动词细化），
 * ask 系统提示注入只读约束，REPL 提示符带 "|plan" 标记。
 * 会话级状态（不落盘），默认关闭；只影响工具闸门与提示词，
 * 不改变 uid 档位判定本身。
 */
void ai_policy_set_plan_mode(int on);

/* ai_policy_get_plan_mode - 当前 plan 模式状态（1=只读调研态） */
int ai_policy_get_plan_mode(void);

/*
 * ai_policy_gate - executor 一站式闸门（check + 确认交互 + 拒绝提示 + 审计）
 * NEED_CONFIRM → 发起交互确认；DENY → 打印"权限不足：该操作需要 root
 * （sudo ai）"。三种结果（含确认/拒绝）都会写审计。
 * 返回: 1 = 放行（ALLOW_AUTO 或用户确认）；0 = 拦截。
 */
int ai_policy_gate(uid_t uid, const char *tool_name, enum ai_tool_risk risk,
		   const char *impact_desc, const char *args_json);

/*
 * ai_policy_gate_result - 闸门拦截原因（T2 问题 2：语义区分）
 * 修复前：用户在 y/N 确认中按 n 与策略档位 DENY 在调用方不可区分，
 * 统一显示 policy 拒绝文案（"权限分级拦截…普通用户执行 W2 需 root"），
 * 用户自己拒绝的操作被误报成权限不足。
 */
enum ai_policy_gate_result {
	AI_GATE_ALLOW = 0,        /* 放行（自动或用户确认） */
	AI_GATE_USER_REFUSED = 1, /* 用户在 W2 y/N 再校验中选择拒绝 */
	AI_GATE_POLICY_DENY = 2,  /* 策略档位不足（权限错误） */
	AI_GATE_NEED_NO_TTY = 3,  /* 需人工确认但 stdin 非终端且未预授权
				   * （修复 10：结构化信号，调用方/API 可
				   *  据此给出明确指引而不是静默拒绝） */
};

/*
 * ai_policy_gate_reason - 带拦截原因的闸门（行为与 ai_policy_gate 一致，
 * 额外通过 *result 报告拦截原因；result 可为 NULL）。审计行为等价。
 * 返回: 1 = 放行；0 = 拦截（*result 区分 USER_REFUSED / POLICY_DENY）。
 */
int ai_policy_gate_reason(uid_t uid, const char *tool_name,
			  enum ai_tool_risk risk, const char *impact_desc,
			  const char *args_json,
			  enum ai_policy_gate_result *result);

#ifdef __cplusplus
}
#endif

#endif /* _AI_USER_POLICY_H */
