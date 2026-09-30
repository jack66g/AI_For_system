// SPDX-License-Identifier: GPL-2.0
/*
 * cmd_session.c - session 命令实现（会话管理）
 *
 * 会话持久化在 ~/.aikernel/sessions/<name>.jsonl（每行一条消息 JSON），
 * ask 闭环的消息数组从会话文件加载（跨 ask 历史），结束后追加保存，
 * 退出重启后可完整恢复（见 shell/ui_common.c 与 cmd_ask.c）。
 *
 * 子命令：
 *   session new [name]     新建会话并切换（默认名 session2/test2 递增）
 *   session list           列出全部会话（* 标记当前）
 *   session switch <name|N>  按名字或列表序号切换
 *   session save           落盘状态确认（消息本就写透，此处显式同步）
 *   session delete <name>  删除会话文件（当前会话需先切换）
 *   session show [n]       查看会话内容（默认最近 10 条）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_ui.h"
#include "ai_config.h"

/* 当前会话名的快捷访问 */
static const char *cur_session(struct ai_shell *shell)
{
	return (shell->config->ui.session &&
		shell->config->ui.session[0]) ?
		shell->config->ui.session : UI_DEFAULT_SESSION;
}

/* 切换当前会话（写回 model.toml 持久化） */
static void session_set_current(struct ai_shell *shell, const char *name)
{
	char *dup = strdup(name);

	if (!dup)
		return;
	free(shell->config->ui.session);
	shell->config->ui.session = dup;
	ai_config_save(shell->config);
}

/* 递增生成一个不存在的默认会话名 */
static void gen_session_name(char *buf, size_t len)
{
	int i;

	for (i = 1; i < 1000; i++) {
		snprintf(buf, len, "session%d", i);
		if (!ui_session_exists(buf))
			return;
	}
	snprintf(buf, len, "session_%ld", time(NULL));
}

static int do_new(struct ai_shell *shell, int argc, char **argv)
{
	char name[UI_SESSION_NAME_MAX];

	if (argc >= 3) {
		if (!ui_session_valid_name(argv[2])) {
			printf("session: 非法会话名 '%s'"
			       "（只允许字母数字 - _ .）\n", argv[2]);
			return AI_ERR_INVALID_ARG;
		}
		snprintf(name, sizeof(name), "%s", argv[2]);
		if (ui_session_exists(name)) {
			printf("session: 会话 '%s' 已存在，切换到它"
			       "（历史保留）\n", name);
			session_set_current(shell, name);
			return AI_OK;
		}
	} else {
		gen_session_name(name, sizeof(name));
	}

	{
		int ret = ui_session_clear(name);

		if (ret != AI_OK) {
			printf("session: 创建失败: %s\n", ai_error_string(ret));
			return ret;
		}
	}
	session_set_current(shell, name);
	printf("已创建并切换到会话: %s\n", name);
	return AI_OK;
}

static void do_list(struct ai_shell *shell)
{
	char **names = NULL;
	int count = 0;
	int i;
	const char *cur = cur_session(shell);

	ui_session_list(&names, &count);
	if (count == 0) {
		printf("(无会话文件；ask 时自动以 '%s' 落盘)\n", cur);
		return;
	}
	printf("%-3s %-24s %s\n", "#", "会话", "消息数");
	for (i = 0; i < count; i++) {
		char mark[16];

		snprintf(mark, sizeof(mark), "%d%s", i + 1,
			 strcmp(names[i], cur) == 0 ? "*" : "");
		printf("%-3s %-24s %d\n", mark, names[i],
		       ui_session_count(names[i]));
	}
	{
		int i;

		for (i = 0; i < count; i++)
			free(names[i]);
		free(names);
	}
}

static int do_switch(struct ai_shell *shell, int argc, char **argv)
{
	const char *target = NULL;
	char **names = NULL;
	int count = 0;

	if (argc < 3) {
		printf("Usage: session switch <name|N>\n");
		return AI_ERR_INVALID_ARG;
	}

	/* 数字参数按 session list 的序号解析 */
	if (argv[2][0] >= '0' && argv[2][0] <= '9' &&
	    strspn(argv[2], "0123456789") == strlen(argv[2])) {
		int idx = atoi(argv[2]);
		char resolved[UI_SESSION_NAME_MAX];
		int i;

		ui_session_list(&names, &count);
		if (idx < 1 || idx > count) {
			printf("session: 序号超范围（1-%d）\n", count ? count : 0);
			for (i = 0; i < count; i++)
				free(names[i]);
			free(names);
			return AI_ERR_NOT_FOUND;
		}
		snprintf(resolved, sizeof(resolved), "%s", names[idx - 1]);
		for (i = 0; i < count; i++)
			free(names[i]);
		free(names);
		target = resolved;
	} else {
		target = argv[2];
		if (!ui_session_valid_name(target)) {
			printf("session: 非法会话名 '%s'\n", target);
			return AI_ERR_INVALID_ARG;
		}
	}

	if (strcmp(target, cur_session(shell)) == 0) {
		printf("已在会话 '%s'\n", target);
		return AI_OK;
	}

	/* 切换前落盘当前会话的运行统计（消息本已写透，这里只打印确认） */
	session_set_current(shell, target);
	printf("已切换到会话: %s（%d 条历史消息）\n", target,
	       ui_session_count(target));
	return AI_OK;
}

static void do_show(struct ai_shell *shell, int argc, char **argv)
{
	struct ai_chat_msg *msgs = NULL;
	int n = 0;
	char **pool = NULL;
	int npool = 0;
	int show_n = 10;
	int start;
	int i;
	int ret;
	const char *cur = cur_session(shell);

	if (argc >= 3)
		show_n = atoi(argv[2]);
	if (show_n <= 0)
		show_n = 10;

	ret = ui_session_load(cur, &msgs, &n, &pool, &npool);
	if (ret != AI_OK) {
		printf("session: 加载失败: %s\n", ai_error_string(ret));
		return;
	}
	printf("会话 '%s'：%d 条消息\n", cur, n);
	start = n - show_n;
	if (start < 0)
		start = 0;
	for (i = start; i < n; i++) {
		const char *role = msgs[i].role ? msgs[i].role : "?";
		const char *content = msgs[i].content ? msgs[i].content : "";
		char head[80];

		if (msgs[i].tool_call_id)
			snprintf(head, sizeof(head), "[tool %s]",
				 msgs[i].tool_call_id);
		else if (msgs[i].tool_calls_json)
			snprintf(head, sizeof(head), "[assistant+tools]");
		else
			snprintf(head, sizeof(head), "[%s]", role);
		printf("%-22s %.96s%s\n", head, content,
		       strlen(content) > 96 ? "..." : "");
	}
	for (i = 0; i < npool; i++)
		free(pool[i]);
	free(pool);
	free(msgs);
}

int cmd_session(void *shell_ptr, int argc, char **argv)
{
	struct ai_shell *shell = (struct ai_shell *)shell_ptr;

	if (argc < 2) {
		printf("Usage: session <new|list|switch|save|delete|show>"
		       " [args]\n");
		printf("  session new [name]      新建并切换会话\n");
		printf("  session list            列出会话\n");
		printf("  session switch <name|N> 切换会话\n");
		printf("  session save            确认落盘\n");
		printf("  session delete <name>   删除会话\n");
		printf("  session show [n]        查看最近 n 条消息\n");
		return AI_ERR_INVALID_ARG;
	}

	if (strcmp(argv[1], "new") == 0)
		return do_new(shell, argc, argv);
	if (strcmp(argv[1], "list") == 0) {
		do_list(shell);
		return AI_OK;
	}
	if (strcmp(argv[1], "switch") == 0)
		return do_switch(shell, argc, argv);
	if (strcmp(argv[1], "save") == 0) {
		/* 消息在 ask 过程中写透落盘，这里做显式同步确认 */
		printf("会话 '%s' 已落盘（%d 条消息，每轮 ask 自动追加）\n",
		       cur_session(shell), ui_session_count(cur_session(shell)));
		return AI_OK;
	}
	if (strcmp(argv[1], "delete") == 0) {
		if (argc < 3) {
			printf("Usage: session delete <name>\n");
			return AI_ERR_INVALID_ARG;
		}
		if (strcmp(argv[2], cur_session(shell)) == 0) {
			printf("session: 不能删除当前会话"
			       "（先 switch 到其他会话）\n");
			return AI_ERR_INVALID_ARG;
		}
		{
			int ret = ui_session_delete(argv[2]);

			if (ret == AI_OK)
				printf("已删除会话: %s\n", argv[2]);
			else
				printf("session: 删除失败: %s\n",
				       ai_error_string(ret));
			return ret;
		}
	}
	if (strcmp(argv[1], "show") == 0) {
		do_show(shell, argc, argv);
		return AI_OK;
	}

	printf("Unknown session subcommand: %s\n", argv[1]);
	return AI_ERR_INVALID_ARG;
}
