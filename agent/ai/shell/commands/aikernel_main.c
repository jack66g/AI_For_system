/*
 * aikernel_main.c - AIKernel Shell 入口点（终端 AI 界面主程序）
 *
 * AIKernel OS 默认 Shell（aikernel-shell / ai 两个入口共用本实现，
 * 见 shell/main.c 与 Makefile install 的 /usr/local/bin/ai 软链）。
 *
 * UI Phase 特性：
 *   - linenoise 行内 REPL（历史 ~/.aikernel/history、Ctrl+D 退出、UTF-8），
 *     提示符带模型名与上下文预算用量（如 ai[qwen:18%]>）；
 *   - 命令行参数三层配置的最上层（优先级高于环境变量与 model.toml [ui]）：
 *       --ctx N --max-tokens N --no-stream --session <name> --no-color
 *   - 单发模式：ai -p "问题" 直接走 ask 闭环并退出（脚本/管道友好）。
 *
 * 编译为 /bin/aikernel-shell 二进制文件。
 * 替代 BusyBox /bin/sh 作为 AIKernel 系统的默认交互入口。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/utsname.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_ui.h"
#include "linenoise.h"

/* 外部声明 */
extern struct ai_provider *openai_compatible_provider_create(void);
extern struct ai_provider *local_provider_create(void);

/* 行编辑历史文件与容量 */
#define UI_HISTORY_PATH  "~/.aikernel/history"
#define UI_HISTORY_MAX   500

/*
 * print_banner - 显示 AIKernel OS 启动横幅
 * T2 审计问题 7：Provider 状态此前硬编码 "Ready"/"Offline"——未配置也
 * 显示 Ready，演示会穿帮。改为按已加载配置（cfg）如实报告：
 * 未配置 → "Not configured"，已配置 → "Configured"（附模型/端点）。
 * 只读内存配置，不做任何阻塞的网络探测。
 */
static void print_banner(int color, const struct ai_config *cfg)
{
	struct utsname uts;

	if (uname(&uts) != 0)
		return;
	printf("\n");
	printf("====================================\n");
	printf("\n");
	printf("          AIKernel OS\n");
	printf("\n");
	printf("====================================\n");
	printf("\n");
	printf("Kernel: Linux %s\n", uts.release);
	printf("\n");

	/* 尝试读取 /proc/aikernel */
	if (access("/proc/aikernel", F_OK) == 0) {
		printf("AI Runtime Starting...\n");
		printf("Kernel AI Interface : Ready\n");
		if (cfg && cfg->model_count > 0 && cfg->default_model)
			printf("Cloud Provider      : Configured (%s)\n",
			       cfg->default_model);
		else
			printf("Cloud Provider      : Not configured"
			       " (use 'model add')\n");
		if (cfg && cfg->local.base_url && cfg->local.base_url[0])
			printf("Local Provider      : Configured (%s)\n",
			       cfg->local.base_url);
		else
			printf("Local Provider      : Not configured\n");
	} else {
		printf("AI Runtime Starting...\n");
		printf("(Kernel AI Interface not available)\n");
	}
	(void)color;
	printf("\n");
	printf("Type 'help' for commands, 'exit' to quit.\n");
	printf("\n");
}

/*
 * build_prompt - 构建行内提示符：ai[模型:NN%]>（带颜色）
 * 模型名取 API 模型名（本地原生通道即 Ollama 模型），截掉 ":tag" 尺寸
 * 后缀（qwen2.5:1.5b -> qwen2.5）保持短促；百分比 = 会话累计 token /
 * ctx_len 预算。
 */
static void build_prompt(const struct ai_shell *shell, char *buf, size_t len)
{
	const struct ai_config *cfg = shell->config;
	const struct ai_runtime *rt = &shell->runtime;
	int color = cfg->ui.color;
	char model[64];
	const char *src;
	char *colon;
	long used;
	int pct;

	src = rt->model_name ? rt->model_name :
	      (rt->current_model ? rt->current_model : "nomodel");
	snprintf(model, sizeof(model), "%s", src);
	colon = strrchr(model, ':');
	if (colon && colon != model)
		*colon = '\0';   /* 去掉 ":1.5b" 这类标签 */

	used = (long)rt->token_session_in + rt->token_session_out;
	pct = ui_ctx_percent(used, cfg->ui.ctx_len);

	snprintf(buf, len, "%sai[%s%s:%s%d%%%s%s]%s> ",
		 ui_c(color, UI_C_CYAN),
		 ui_c(color, UI_C_YELLOW), model,
		 pct > 80 ? ui_c(color, UI_C_YELLOW) : "",
		 pct,
		 pct > 80 ? ui_c(color, UI_C_RESET) : "",
		 ui_c(color, UI_C_YELLOW),
		 ui_c(color, UI_C_RESET));
}

/*
 * dispatch_line - 分发一行用户输入（分词 + 查命令表 + 调 handler）
 * 返回: AI_OK 或命令错误码
 */
static int dispatch_line(struct ai_shell *shell, char *line)
{
	/* 512 词上限：支持超长单行问题（如 num_ctx 验证用的数千 token
	 * 填充输入），cmd_ask 会把全部词拼接回完整问题 */
	char *argv[512];
	int argc = 0;
	int ret;
	char *p = line;

	while (*p && argc < 512) {
		while (*p == ' ' || *p == '\t' || *p == '\n')
			p++;
		if (!*p)
			break;
		argv[argc++] = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\n')
			p++;
		if (*p) {
			*p = '\0';
			p++;
		}
	}
	if (argc == 0)
		return AI_OK;

	{
		struct ai_command *cmd = NULL;
		int i;

		for (i = 0; i < shell->command_count; i++) {
			if (!shell->commands[i].name)
				break;
			if (strcmp(argv[0], shell->commands[i].name) == 0) {
				cmd = &shell->commands[i];
				break;
			}
		}

		if (cmd) {
			ret = cmd->handler(shell, argc, argv);
			(void)ret;
		} else {
			printf("Unknown command: %s\n"
			       "Type 'help' for available commands.\n",
			       argv[0]);
		}
	}
	return AI_OK;
}

/*
 * usage - 命令行帮助
 */
static void usage(FILE *fp, const char *prog)
{
	fprintf(fp,
		"用法: %s [选项] [命令...]\n"
		"  -p, --prompt <问题>  单发模式：执行一次 ask 后退出\n"
		"      --ctx <N>        上下文 token 预算"
		"（默认 %d，本地按模型上限钳制）\n"
		"      --max-tokens <N> 单次生成上限（默认 %d）\n"
		"      --no-stream      关闭流式输出\n"
		"      --session <name> 指定会话（默认 default）\n"
		"      --no-color       关闭 ANSI 颜色（NO_COLOR 同效）\n"
		"  -h, --help          显示本帮助\n",
		prog, UI_DEFAULT_CTX_LEN, UI_DEFAULT_MAX_TOKENS);
}

/*
 * aikernel_shell_main - 共享主入口（aikernel-shell 与 ai 两个二进制）
 */
int aikernel_shell_main(int argc, char **argv)
{
	struct ai_shell shell;
	struct ai_provider *openai_p, *local_p;
	char *single_question = NULL;
	int ret;
	int i;

	static struct option long_opts[] = {
		{ "prompt",     required_argument, NULL, 'p' },
		{ "ctx",        required_argument, NULL, 'c' },
		{ "max-tokens", required_argument, NULL, 'm' },
		{ "no-stream",  no_argument,       NULL, 'S' },
		{ "session",    required_argument, NULL, 's' },
		{ "no-color",   no_argument,       NULL, 'C' },
		{ "help",       no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	/* 预扫描：先建 shell 再应用参数（参数需写入 config->ui） */
	memset(&shell, 0, sizeof(shell));
	shell.running = 0;
	shell.first_run = 0;

	shell.config = ai_config_init();
	if (!shell.config) {
		fprintf(stderr, "Error: Failed to initialize config\n");
		return 1;
	}
	ai_config_load(shell.config);

	/* ---- 命令行参数（三层配置最高层） ---- */
	optind = 1;
	while ((ret = getopt_long(argc, argv, "+p:c:m:s:h",
				  long_opts, NULL)) != -1) {
		switch (ret) {
		case 'p':
			single_question = optarg;
			break;
		case 'c': {
			long v = strtol(optarg, NULL, 10);

			if (v > 0)
				shell.config->ui.ctx_len = (int)v;
			break;
		}
		case 'm': {
			long v = strtol(optarg, NULL, 10);

			if (v > 0)
				shell.config->ui.max_tokens = (int)v;
			break;
		}
		case 'S':
			shell.config->ui.stream = 0;
			break;
		case 's': {
			char *dup = strdup(optarg);

			if (dup) {
				free(shell.config->ui.session);
				shell.config->ui.session = dup;
			}
			break;
		}
		case 'C':
			shell.config->ui.color = 0;
			break;
		case 'h':
			usage(stdout, argv[0]);
			ai_config_destroy(shell.config);
			return 0;
		default:
			usage(stderr, argv[0]);
			ai_config_destroy(shell.config);
			return 1;
		}
	}
	/* 显示 AIKernel OS 横幅（单发模式不打横幅） */
	if (!single_question)
		print_banner(shell.config->ui.color, shell.config);

	/* 初始化 Provider 注册中心 */
	ai_provider_registry_init(&shell.registry);

	openai_p = openai_compatible_provider_create();
	if (openai_p)
		ai_provider_register(&shell.registry, openai_p);

	local_p = local_provider_create();
	if (local_p)
		ai_provider_register(&shell.registry, local_p);

	/* 初始化 Runtime */
	ai_runtime_init(&shell.runtime, shell.config, &shell.registry);

	/* 如果有默认模型，自动加载 */
	if (shell.config->default_model) {
		ai_runtime_set_model(&shell.runtime,
				     shell.config->default_model);
	}

	/* 获取命令表 */
	shell.commands = ai_commands_get_table();
	shell.command_count = ai_commands_get_count();

	/* 检查模型配置 */
	{
		int model_count;
		char **model_names;

		ai_config_get_models(shell.config, &model_names,
				     &model_count);
		if (model_count == 0)
			shell.first_run = 1;
		else {
			for (i = 0; i < model_count; i++)
				free(model_names[i]);
			free(model_names);
		}
	}

	/* ---- 单发模式：ai -p "问题" ---- */
	if (single_question) {
		char *qargv[512];
		int qargc = 0;
		char *p = single_question;

		qargv[qargc++] = (char *)"ask";
		while (*p && qargc < 511) {
			while (*p == ' ' || *p == '\t')
				p++;
			if (!*p)
				break;
			qargv[qargc++] = p;
			while (*p && *p != ' ' && *p != '\t')
				p++;
			if (*p)
				*p++ = '\0';
		}
		ret = AI_OK;
		if (qargc >= 2) {
			ret = cmd_ask(&shell, qargc, qargv);
		} else {
			fprintf(stderr, "ai: -p 需要一个问题字符串\n");
			ret = AI_ERR_INVALID_ARG;
		}

		ai_runtime_destroy(&shell.runtime);
		ai_provider_registry_destroy(&shell.registry);
		ai_config_destroy(shell.config);
		return ret == AI_OK ? 0 : 1;
	}

	/* ---- linenoise 行内 REPL ---- */
	shell.running = 1;
	{
		char hist_path[AI_PATH_MAX];
		const char *home = getenv("HOME");

		linenoiseHistorySetMaxLen(UI_HISTORY_MAX);
		if (home && home[0]) {
			snprintf(hist_path, sizeof(hist_path),
				 "%s/.aikernel/history", home);
			linenoiseHistoryLoad(hist_path);
		}
	}

	while (shell.running) {
		char prompt[160];
		char *line;

		build_prompt(&shell, prompt, sizeof(prompt));
		line = linenoise(prompt);
		if (!line) {
			/* Ctrl+D / 非终端 EOF */
			printf("\n");
			break;
		}
		if (line[0]) {
			linenoiseHistoryAdd(line);
			{
				char hist_path[AI_PATH_MAX];
				const char *home = getenv("HOME");

				if (home && home[0]) {
					snprintf(hist_path,
						 sizeof(hist_path),
						 "%s/.aikernel/history", home);
					linenoiseHistorySave(hist_path);
				}
			}
			dispatch_line(&shell, line);
		}
		linenoiseFree(line);
	}

	/* 清理 */
	ai_runtime_destroy(&shell.runtime);
	ai_provider_registry_destroy(&shell.registry);
	ai_config_destroy(shell.config);

	return 0;
}
