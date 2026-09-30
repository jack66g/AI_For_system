/*
 * shell.c - AI Shell 主循环实现
 *
 * REPL (Read-Eval-Print Loop) 核心。
 * 类似 git/docker 的交互式 CLI。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_shell.h"
#include "ai_commands.h"

/* 前向声明 */
struct ai_provider *openai_compatible_provider_create(void);
struct ai_provider *local_provider_create(void);

/* 最大参数数量 */
#define AI_MAX_ARGS 32

int ai_shell_init(struct ai_shell *shell)
{
	int model_count;
	char **model_names;

	if (!shell)
		return AI_ERR_INVALID_ARG;

	memset(shell, 0, sizeof(*shell));
	shell->running = 0;
	shell->first_run = 0;

	/* 初始化配置 */
	shell->config = ai_config_init();
	if (!shell->config) {
		fprintf(stderr, "Error: Failed to initialize config\n");
		return AI_ERR_MEMORY;
	}

	/* 加载配置 */
	ai_config_load(shell->config);

	/* 检查是否有模型配置 */
	ai_config_get_models(shell->config, &model_names, &model_count);
	if (model_count == 0) {
		shell->first_run = 1;
	} else {
		/* 释放 model names 列表 */
		for (int i = 0; i < model_count; i++)
			free(model_names[i]);
		free(model_names);
	}

	/* 初始化 Provider 注册中心 */
	ai_provider_registry_init(&shell->registry);

	/* 注册 Provider（按 Kconfig 开关条件注册，见 Makefile） */
#ifdef CONFIG_AI_CLOUD_PROVIDER
	{
		struct ai_provider *openai_p =
			openai_compatible_provider_create();

		if (openai_p)
			ai_provider_register(&shell->registry, openai_p);
	}
#endif
#ifdef CONFIG_AI_LOCAL_PROVIDER
	{
		struct ai_provider *local_p = local_provider_create();

		if (local_p)
			ai_provider_register(&shell->registry, local_p);
	}
#endif

	/* 初始化 Runtime */
	ai_runtime_init(&shell->runtime, shell->config, &shell->registry);

	/* 如果有默认模型，自动切换 */
	if (!shell->first_run && shell->config->default_model) {
		ai_runtime_set_model(&shell->runtime,
				     shell->config->default_model);
	}

	/* 获取命令表 */
	shell->commands = ai_commands_get_table();
	shell->command_count = ai_commands_get_count();

	return AI_OK;
}

/*
 * split_line - 将输入行分割为 argc/argv
 *
 * 支持引号参数：model add "my model"
 * 返回参数个数
 */
static int split_line(char *line, char **argv, int max_args)
{
	int argc = 0;
	char *p = line;

	while (*p && argc < max_args) {
		/* 跳过空白 */
		while (*p == ' ' || *p == '\t' || *p == '\n')
			p++;
		if (!*p)
			break;

		if (*p == '"') {
			p++;
			argv[argc] = p;
			while (*p && *p != '"')
				p++;
			if (*p == '"') {
				*p = '\0';
				p++;
			}
		} else {
			argv[argc] = p;
			while (*p && *p != ' ' && *p != '\t' && *p != '\n')
				p++;
			if (*p) {
				*p = '\0';
				p++;
			}
		}
		argc++;
	}

	return argc;
}

/*
 * dispatch_command - 查找并执行命令
 */
static int dispatch_command(struct ai_shell *shell, int argc, char **argv)
{
	struct ai_command *cmd;
	int i;

	if (argc == 0)
		return AI_OK;

	/* 查找命令（支持子命令，如 "model add"） */
	for (i = 0; i < shell->command_count; i++) {
		cmd = &shell->commands[i];
		if (!cmd->name)
			break;
		if (strcmp(argv[0], cmd->name) == 0) {
			/* 检查参数数量 */
			int nargs = argc - 1;
			if (nargs < cmd->min_args) {
				printf("Usage: %s\n", cmd->usage);
				return AI_ERR_INVALID_ARG;
			}
			if (cmd->max_args >= 0 && nargs > cmd->max_args) {
				printf("Usage: %s\n", cmd->usage);
				return AI_ERR_INVALID_ARG;
			}
			return cmd->handler(shell, argc, argv);
		}
	}

	printf("Unknown command: %s\nType 'help' for available commands.\n",
	       argv[0]);
	return AI_ERR_NOT_FOUND;
}

int ai_shell_run(struct ai_shell *shell)
{
	char line[AI_MAX_LINE_LEN];
	char *argv[AI_MAX_ARGS];
	int argc;
	int ret;

	if (!shell)
		return AI_ERR_INVALID_ARG;

	/* 第一次运行检查 */
	if (shell->first_run) {
		printf("No AI Provider Configured.\n");
		printf("Please configure a model first.\n\n");
		printf("Suggested Command:\n");
		printf("  model add <name>\n");
	}

	shell->running = 1;

	/* REPL 主循环 */
	while (shell->running) {
		printf("AIKernel> ");
		fflush(stdout);

		if (!fgets(line, sizeof(line), stdin)) {
			/* EOF */
			printf("\n");
			break;
		}

		/* 分割命令行 */
		argc = split_line(line, argv, AI_MAX_ARGS);
		if (argc == 0)
			continue;

		/* 分发执行 */
		ret = dispatch_command(shell, argc, argv);
		AI_UNUSED(ret);
	}

	return AI_OK;
}

void ai_shell_stop(struct ai_shell *shell)
{
	if (shell)
		shell->running = 0;
}

void ai_shell_destroy(struct ai_shell *shell)
{
	if (!shell)
		return;

	ai_runtime_destroy(&shell->runtime);
	ai_provider_registry_destroy(&shell->registry);
	ai_config_destroy(shell->config);
	memset(shell, 0, sizeof(*shell));
}
