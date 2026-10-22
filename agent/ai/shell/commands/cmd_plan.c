// SPDX-License-Identifier: GPL-2.0
/*
 * cmd_plan.c - plan/unplan 命令实现（W43：会话级只读规划模式）
 *
 * plan 态语义：
 *   - 工具执行闸门（executor.c P2 块最前置一层）对非 R 级工具一律拒绝
 *     （W1/W2 全拒、R 放行）；exec 通道按命令级 risk 判定，只读 34 命令
 *     照常可用，mkdir/cp 等 W1 写命令与 kill/python3 等 W2 命令全部拦截；
 *   - ask 系统提示注入只读约束（TR_PLAN_SYS_NOTE，≤200 token）；
 *   - REPL 提示符带 "|plan" 标记（aikernel_main.c build_prompt）。
 *
 * 状态保存在策略模块静态标志位（ai_user_policy.c g_plan_mode）：
 * 会话内有效、不落盘，默认关闭。CLI 等价入口：ai --plan（启动即进入）。
 */
#include <stdio.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_lang.h"
#include "policy/ai_user_policy.h"

/*
 * cmd_plan - 进入 plan（规划）只读模式
 * 用法: /plan（无参数；已处于 plan 态时幂等）
 */
int cmd_plan(void *shell, int argc, char **argv)
{
	(void)shell;
	(void)argv;

	if (argc > 1) {
		printf("Usage: plan\n");
		return AI_ERR_INVALID_ARG;
	}
	ai_policy_set_plan_mode(1);
	printf("%s", tr(TR_PLAN_ON));
	return AI_OK;
}

/*
 * cmd_unplan - 退出 plan 模式，恢复完整工具权限
 * 用法: /unplan（无参数；未处于 plan 态时幂等）
 */
int cmd_unplan(void *shell, int argc, char **argv)
{
	(void)shell;
	(void)argv;

	if (argc > 1) {
		printf("Usage: unplan\n");
		return AI_ERR_INVALID_ARG;
	}
	ai_policy_set_plan_mode(0);
	printf("%s", tr(TR_PLAN_OFF));
	return AI_OK;
}
