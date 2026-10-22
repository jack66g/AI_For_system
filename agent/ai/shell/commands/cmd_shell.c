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
#include "ai_lang.h"

int cmd_shell(void *shell_ptr, int argc, char **argv)
{
	pid_t pid;
	int status = 0;

	(void)shell_ptr;
	(void)argc;
	(void)argv;

	if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
		printf("%s", tr(TR_SH_NOT_TTY));
		return AI_ERR_INVALID_ARG;
	}

	printf("%s", tr(TR_SH_ENTER));
	fflush(stdout);

	pid = fork();
	if (pid < 0) {
		printf(tr(TR_SH_FORK_FAIL), strerror(errno));
		return AI_ERR_GENERIC;
	}

	if (pid == 0) {
		execl("/bin/bash", "bash", (char *)NULL);
		/* exec 失败才到这里 */
		fprintf(stderr, tr(TR_SH_EXEC_FAIL), strerror(errno));
		_exit(127);
	}

	/* 父进程：等待子 shell 退出（EINTR 重试） */
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 127)
		printf("%s", tr(TR_SH_START_FAIL));

	printf("%s", tr(TR_SH_RETURN));
	return AI_OK;
}
