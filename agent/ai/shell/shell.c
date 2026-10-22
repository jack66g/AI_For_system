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
#include "ai_lang.h"

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

	/* i18n：语言初始化（AIKERNEL_LANG > [ui] lang > zh） */
	lang_init(shell->config->ui.lang);

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

	printf(tr(TR_REPL_UNKNOWN), argv[0]);
	return AI_ERR_NOT_FOUND;
}

/* P0-1 直说转 ask 的首次提示标志（每进程一次，不刷屏） */
static int g_ask_fallback_hint_shown;

/*
 * ask_fallback - P0-1：非命令输入按 "ask <原文>" 处理
 * @raw: 分词前的原始输入行副本（本函数接管并 free）
 */
static void ask_fallback(struct ai_shell *shell, char *raw)
{
	char *qargv[2];

	if (!raw)
		return;
	raw[strcspn(raw, "\r\n")] = '\0';
	if (!raw[0]) {
		free(raw);
		return;
	}
	if (!g_ask_fallback_hint_shown) {
		printf("%s", tr(TR_REPL_ASK_HINT));
		g_ask_fallback_hint_shown = 1;
	}
	qargv[0] = (char *)"ask";
	qargv[1] = raw;
	cmd_ask(shell, 2, qargv);
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
		printf("%s", tr(TR_SHELL_FIRST_RUN));
		printf("%s", tr(TR_SHELL_SUGGEST));
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

		/* 原始行副本（split_line 会写入 '\0' 破坏原行） */
		{
			char *raw = strdup(line);

			/* 分割命令行 */
			argc = split_line(line, argv, AI_MAX_ARGS);
			if (argc == 0) {
				free(raw);
				continue;
			}

			/* 分发执行；未命中命令表 → 直说转 ask（P0-1） */
			ret = dispatch_command(shell, argc, argv);
			if (ret == AI_ERR_NOT_FOUND)
				ask_fallback(shell, raw);
			else
				free(raw);
			AI_UNUSED(ret);
		}
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
