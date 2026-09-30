// SPDX-License-Identifier: GPL-2.0
/*
 * cmd_chat.c - chat 命令实现（ask 的别名/薄封装）
 *
 * 历史上 chat 是独立的双轨聊天路径（子 REPL + 单消息模式，无工具
 * 闭环），与 ask 长期并行维护造成行为漂移。现统一为 ask 的别名：
 * 参数原样透传，行为与 `ask` 完全一致（69 工具闭环、W2 再校验、
 * 会话持久化、流式输出全部相同），双轨维护就此消除。
 */
#define _GNU_SOURCE
#include "ai_commands.h"

int cmd_chat(void *shell_ptr, int argc, char **argv)
{
	/* 参数原样透传（含裸 `chat`——由 cmd_ask 打印 Usage） */
	return cmd_ask(shell_ptr, argc, argv);
}
