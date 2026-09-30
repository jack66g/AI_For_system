/*
 * cmd_exit.c - exit 命令实现
 *
 * 退出 AI Shell。
 */
#include <stdio.h>
#include "ai_shell.h"

int cmd_exit(void *shell_ptr, int argc, char **argv)
{
	struct ai_shell *shell = (struct ai_shell *)shell_ptr;

	(void)argc;
	(void)argv;

	printf("Goodbye.\n");
	ai_shell_stop(shell);

	return AI_OK;
}
