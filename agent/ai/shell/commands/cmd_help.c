/*
 * cmd_help.c - help 命令实现
 *
 * 显示可用命令列表或特定命令的详细帮助。
 * 描述文案双语：zh 用 tr_cmd_desc(name)（i18n 表），en 回退注册表
 * 原文（单一来源，commands_registry.c）。
 */
#include <stdio.h>
#include <string.h>
#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_lang.h"

/* 描述翻译：zh 返回中文对，否则回退注册表英文原文 */
static const char *desc_of(const struct ai_command *cmd)
{
	const char *d = tr_cmd_desc(cmd->name);

	return d ? d : cmd->description;
}

int cmd_help(void *shell_ptr, int argc, char **argv)
{
	struct ai_shell *shell = (struct ai_shell *)shell_ptr;
	int i;

	if (argc > 1) {
		/* 查找特定命令的帮助 */
		for (i = 0; i < shell->command_count; i++) {
			struct ai_command *cmd = &shell->commands[i];

			if (!cmd->name)
				break;
			if (strcmp(argv[1], cmd->name) == 0) {
				printf(tr(TR_HELP_DETAIL_ONE),
				       cmd->name, desc_of(cmd), cmd->usage);
				return AI_OK;
			}
		}
		printf(tr(TR_HELP_UNKNOWN), argv[1]);
		return AI_ERR_NOT_FOUND;
	}

	/* 显示所有命令 */
	printf("%s", tr(TR_HELP_TITLE));
	printf("%s", tr(TR_HELP_AVAIL));
	printf("  %-20s %s\n", tr(TR_HELP_CMDHDR), tr(TR_HELP_DESCHDR));
	printf("  %-20s %s\n", "-------", "-----------");

	for (i = 0; i < shell->command_count; i++) {
		struct ai_command *cmd = &shell->commands[i];

		if (!cmd->name)
			break;
		printf("  %-20s %s\n", cmd->name, desc_of(cmd));
	}

	printf("%s", tr(TR_HELP_DETAIL));
	return AI_OK;
}
