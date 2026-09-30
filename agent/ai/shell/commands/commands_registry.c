/*
 * commands_registry.c - 命令注册表
 *
 * 集中管理所有命令的定义和注册。
 * 每个命令在独立的文件中实现，在此统一注册。
 */
#include <stdio.h>
#include "ai_commands.h"

/* 命令注册表 —— 集中定义，分散实现 */
static struct ai_command command_table[] = {
	{
		.name        = "help",
		.description = "Show help information",
		.usage       = "help [command]",
		.handler     = cmd_help,
		.min_args    = 0,
		.max_args    = 1,
	},
	{
		.name        = "exit",
		.description = "Exit AI Shell",
		.usage       = "exit",
		.handler     = cmd_exit,
		.min_args    = 0,
		.max_args    = 0,
	},
	{
		.name        = "status",
		.description = "Show current status",
		.usage       = "status",
		.handler     = cmd_status,
		.min_args    = 0,
		.max_args    = 0,
	},
	{
		.name        = "config",
		.description = "View or modify configuration",
		.usage       = "config <get|set> [key] [value]",
		.handler     = cmd_config,
		.min_args    = 1,
		.max_args    = 3,
	},
	{
		.name        = "chat",
		.description = "Alias of ask (same tool-calling loop)",
		.usage       = "chat <question>",
		.handler     = cmd_chat,
		.min_args    = 0,
		.max_args    = -1,
	},
	{
		.name        = "ask",
		.description = "AI tool-calling loop (auto-executes tools)",
		.usage       = "ask <question>",
		.handler     = cmd_ask,
		.min_args    = 1,
		.max_args    = -1,
	},
	{
		.name        = "model",
		.description = "Manage AI models (add/list/use/remove/test)",
		.usage       = "model <add|list|use|remove|test> [args]",
		.handler     = cmd_model,
		.min_args    = 1,
		.max_args    = -1,
	},
	{
		.name        = "network",
		.description = "Network diagnostics (status/test)",
		.usage       = "network <status|test>",
		.handler     = cmd_network,
		.min_args    = 1,
		.max_args    = 1,
	},
	{
		.name        = "netlink",
		.description = "NETLINK_AI kernel channel (sense/act/reg)",
		.usage       = "netlink <sense|act|reg> [args]",
		.handler     = cmd_netlink,
		.min_args    = 1,
		.max_args    = -1,
	},
	{
		.name        = "session",
		.description = "Manage persistent chat sessions",
		.usage       = "session <new|list|switch|save|delete|show> [args]",
		.handler     = cmd_session,
		.min_args    = 1,
		.max_args    = -1,
	},
	{
		.name        = "compact",
		.description = "Summarize & shrink current session history",
		.usage       = "compact",
		.handler     = cmd_compact,
		.min_args    = 0,
		.max_args    = 0,
	},
	{
		.name        = "setup-password",
		.description = "Set/change root password (echo off, never seen by AI)",
		.usage       = "setup-password",
		.handler     = cmd_setup_password,
		.min_args    = 0,
		.max_args    = 0,
	},
	{
		.name        = "shell",
		.description = "Escape to bash maintenance shell (exit to return)",
		.usage       = "shell",
		.handler     = cmd_shell,
		.min_args    = 0,
		.max_args    = 0,
	},
	/* 哨兵 */
	{
		.name        = NULL,
		.description = NULL,
		.usage       = NULL,
		.handler     = NULL,
		.min_args    = 0,
		.max_args    = 0,
	},
};

struct ai_command *ai_commands_get_table(void)
{
	return command_table;
}

int ai_commands_get_count(void)
{
	return AI_ARRAY_SIZE(command_table) - 1; /* 减去哨兵 */
}
