/*
 * ai_commands.h - 命令系统接口
 *
 * 声明所有命令处理函数。每个命令在独立的 .c 文件中实现。
 */
#ifndef _AI_COMMANDS_H
#define _AI_COMMANDS_H

#include "ai_shell.h"

/* 所有命令处理函数声明 */

int cmd_help(void *shell, int argc, char **argv);
int cmd_exit(void *shell, int argc, char **argv);
int cmd_status(void *shell, int argc, char **argv);
int cmd_config(void *shell, int argc, char **argv);
int cmd_chat(void *shell, int argc, char **argv);
int cmd_ask(void *shell, int argc, char **argv);
int cmd_model(void *shell, int argc, char **argv);
int cmd_network(void *shell, int argc, char **argv);
int cmd_netlink(void *shell, int argc, char **argv);
int cmd_session(void *shell, int argc, char **argv);
int cmd_compact(void *shell, int argc, char **argv);
int cmd_setup_password(void *shell, int argc, char **argv);
int cmd_shell(void *shell, int argc, char **argv);

/*
 * onboarding（cmd_onboarding.c）：首次初始化引导
 * onboarding_should_start - 出厂态标记缺失且交互 TTY 时返回 1
 * onboarding_run          - 运行引导流程（AI 欢迎→强制设密码→选模型→
 *                           落 /etc/aikernel/.onboarded 标记）
 */
int onboarding_should_start(void);
int onboarding_run(void *shell);

/*
 * ai_commands_register - 获取命令注册表
 * 返回: 静态命令数组（以 NULL name 结尾）
 */
struct ai_command *ai_commands_get_table(void);

/*
 * ai_commands_count - 获取命令数量
 */
int ai_commands_get_count(void);

#endif /* _AI_COMMANDS_H */
