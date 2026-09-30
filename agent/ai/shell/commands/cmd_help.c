/*
 * cmd_help.c - help 命令实现
 *
 * 显示可用命令列表或特定命令的详细帮助。
 */
#include <stdio.h>
#include <string.h>
#include "ai_shell.h"
#include "ai_commands.h"

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
				printf("Command: %s\n", cmd->name);
				printf("  %s\n", cmd->description);
				printf("Usage: %s\n", cmd->usage);
				return AI_OK;
			}
		}
		printf("Unknown command: %s\n", argv[1]);
		return AI_ERR_NOT_FOUND;
	}

	/* 显示所有命令 */
	printf("\nAIKernel - AI Subsystem Shell\n");
	printf("Available commands:\n\n");
	printf("  %-20s %s\n", "Command", "Description");
	printf("  %-20s %s\n", "-------", "-----------");

	for (i = 0; i < shell->command_count; i++) {
		struct ai_command *cmd = &shell->commands[i];
		if (!cmd->name)
			break;
		printf("  %-20s %s\n", cmd->name, cmd->description);
	}

	printf("\nType 'help <command>' for detailed usage.\n\n");
	return AI_OK;
}
