// SPDX-License-Identifier: GPL-2.0
/*
 * cmd_sandbox.c - sandbox 命令实现（W43：隔离区手动管理）
 *
 * 直接复用 W42 sandbox 通道执行器（tool_executor_run）：status/create/
 * destroy 与 ask 内的 sandbox_* 工具走完全相同的注册表+闸门+执行链
 * ——权限分级（W1）、plan 只读模式、审计一并生效，不旁路任何安全层。
 * spawn 属 ask 交互职责（W2 人工确认语义），手动管理不提供，
 * 提示用户通过 ask 让 AI 派发子智能体。
 */
#define _GNU_SOURCE             /* asprintf */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_lang.h"
#include "ai_json_util.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"

/*
 * cmd_sandbox - 手动管理隔离区
 * 用法: /sandbox status | create <名> | destroy <名>
 */
int cmd_sandbox(void *shell, int argc, char **argv)
{
	struct tool_registry reg;
	char *err = NULL;
	const struct ai_tool *tool;
	char tname[32];
	char *args = NULL;
	char *esc = NULL;
	char *out = NULL;
	int ok = 0;
	int ret;

	(void)shell;

	if (argc < 2) {
		printf("%s", tr(TR_SANDBOX_USAGE));
		return AI_ERR_INVALID_ARG;
	}

	if (strcmp(argv[1], "status") == 0) {
		snprintf(tname, sizeof(tname), "sandbox_status");
		args = strdup("{}");
		if (!args)
			return AI_ERR_MEMORY;
	} else if (strcmp(argv[1], "create") == 0 ||
		   strcmp(argv[1], "destroy") == 0) {
		if (argc < 3) {
			printf("%s", tr(TR_SANDBOX_USAGE));
			return AI_ERR_INVALID_ARG;
		}
		esc = ai_json_escape(argv[2]);
		if (!esc)
			return AI_ERR_MEMORY;
		if (asprintf(&args, "{\"name\":\"%s\"}", esc) < 0) {
			free(esc);
			return AI_ERR_MEMORY;
		}
		free(esc);
		snprintf(tname, sizeof(tname), "sandbox_%s", argv[1]);
	} else {
		printf("%s", tr(TR_SANDBOX_USAGE));
		return AI_ERR_INVALID_ARG;
	}

	if (tool_registry_load(&reg, &err) != AI_OK) {
		printf("sandbox: %s\n", err ? err : "注册表加载失败");
		free(err);
		free(args);
		return AI_ERR_NOT_FOUND;
	}

	tool = tool_registry_find(&reg, tname);
	if (!tool) {
		printf("sandbox: 注册表中无 %s（检查 AIKERNEL_TOOLS_JSON）\n",
		       tname);
		tool_registry_free(&reg);
		free(args);
		return AI_ERR_NOT_FOUND;
	}

	/* 与 ask 完全同链路：闸门（uid 档位 + plan 态）在执行器内生效 */
	ret = tool_executor_run(tool, args, &out, &ok);
	printf("%s", out ? out : "(无输出)\n");
	free(out);
	free(args);
	tool_registry_free(&reg);

	return (ret == AI_OK && ok) ? AI_OK : AI_ERR_API;
}
