/*
 * ai_shell.h - AI Shell 框架接口
 *
 * AI Shell 是用户交互入口，类似 git/docker 的交互式 CLI。
 */
#ifndef _AI_SHELL_H
#define _AI_SHELL_H

#include "ai_types.h"
#include "ai_runtime.h"
#include "ai_config.h"
#include "ai_provider.h"

/* 命令处理函数类型 */
typedef int (*cmd_handler_t)(void *shell, int argc, char **argv);

/* 命令描述 */
struct ai_command {
	const char *name;           /* 命令名 */
	const char *description;    /* 简短描述 */
	const char *usage;          /* 用法说明 */
	cmd_handler_t handler;      /* 处理函数 */
	int min_args;               /* 最少参数个数 */
	int max_args;               /* 最多参数个数（-1=无限制） */
};

/*
 * ai_shell - Shell 主体结构
 */
struct ai_shell {
	int running;                            /* Shell 运行标志 */
	int first_run;                          /* 是否首次运行（无配置） */
	struct ai_config *config;               /* 配置管理器 */
	struct ai_runtime runtime;              /* Runtime */
	struct ai_provider_registry registry;   /* Provider 注册中心 */
	struct ai_command *commands;            /* 命令表（以 NULL name 结尾） */
	int command_count;                      /* 命令数量 */
};

/*
 * ai_shell_init - 初始化 Shell
 * @shell: 未初始化的 Shell 结构体
 * 返回: AI_OK 成功
 */
int ai_shell_init(struct ai_shell *shell);

/*
 * ai_shell_run - 启动 Shell 主循环（REPL）
 * @shell: 已初始化的 Shell
 * 返回: AI_OK 成功退出
 */
int ai_shell_run(struct ai_shell *shell);

/*
 * ai_shell_stop - 停止 Shell 主循环
 * @shell: Shell
 */
void ai_shell_stop(struct ai_shell *shell);

/*
 * ai_shell_destroy - 清理 Shell 资源
 * @shell: Shell
 */
void ai_shell_destroy(struct ai_shell *shell);

#endif /* _AI_SHELL_H */
