/*
 * cmd_shell.c - REPL 逃生口：fork/exec /bin/bash 维护 shell
 *
 * 设计：
 *   - 交互 TTY：fork 子进程 execl /bin/bash（继承 stdio 与终端），
 *     父进程 waitpid 等退出后回到 REPL；终端模式由 bash 自管，
 *     REPL 侧 linenoise 在读行间隙处于 cooked 模式，无残留 raw 态。
 *   - 非交互环境（stdin/stdout 任一非终端，如管道/tmux capture）：
 *     友好提示并返回，不崩、不吞 stdin。
 * 用途：AI 控制台内的底层运维逃生通道（救援场景）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#include "ai_shell.h"
#include "ai_commands.h"

int cmd_shell(void *shell_ptr, int argc, char **argv)
{
	pid_t pid;
	int status = 0;

	(void)shell_ptr;
	(void)argc;
	(void)argv;

	if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
		printf("shell: 当前环境非交互终端（stdin/stdout 被重定向），"
		       "拒绝进入子 shell。\n");
		return AI_ERR_INVALID_ARG;
	}

	printf("进入维护 shell（bash）。输入 exit 返回 AI 控制台。\n");
	fflush(stdout);

	pid = fork();
	if (pid < 0) {
		printf("shell: fork 失败（%s）。\n", strerror(errno));
		return AI_ERR_GENERIC;
	}

	if (pid == 0) {
		execl("/bin/bash", "bash", (char *)NULL);
		/* exec 失败才到这里 */
		fprintf(stderr, "shell: 无法启动 /bin/bash（%s）。\n",
			strerror(errno));
		_exit(127);
	}

	/* 父进程：等待子 shell 退出（EINTR 重试） */
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 127)
		printf("shell: /bin/bash 启动失败。\n");

	printf("已返回 AI 控制台。\n");
	return AI_OK;
}
