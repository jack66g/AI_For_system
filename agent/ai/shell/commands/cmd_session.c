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
#include "ai_lang.h"
#include "memory/sme_client.h"   /* W43: /session SME 可达性 */

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
			printf(tr(TR_SES_BAD_NAME), argv[2]);
			return AI_ERR_INVALID_ARG;
		}
		snprintf(name, sizeof(name), "%s", argv[2]);
		if (ui_session_exists(name)) {
			printf(tr(TR_SES_EXISTS_SWITCH), name);
			session_set_current(shell, name);
			return AI_OK;
		}
	} else {
		gen_session_name(name, sizeof(name));
	}

	{
		int ret = ui_session_clear(name);

		if (ret != AI_OK) {
			printf(tr(TR_SES_CREATE_FAIL), ai_error_string(ret));
			return ret;
		}
	}
	session_set_current(shell, name);
	printf(tr(TR_SES_CREATED), name);
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
		printf(tr(TR_SES_LIST_EMPTY), cur);
		return;
	}
	printf(tr(TR_SES_LIST_HDR), "#", tr(TR_SES_HDR_NAME),
	       tr(TR_SES_HDR_COUNT));
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
	/* W48 C1 修复：resolved 原先声明在数字分支块内，块外 target
	 * 仍指向它（形式上 use-after-scope/UB）。提升到函数作用域，
	 * 生命周期覆盖整个 do_switch。 */
	char resolved[UI_SESSION_NAME_MAX];

	if (argc < 3) {
		printf("Usage: session switch <name|N>\n");
		return AI_ERR_INVALID_ARG;
	}

	/* 数字参数按 session list 的序号解析 */
	if (argv[2][0] >= '0' && argv[2][0] <= '9' &&
	    strspn(argv[2], "0123456789") == strlen(argv[2])) {
		int idx = atoi(argv[2]);
		int i;

		ui_session_list(&names, &count);
		if (idx < 1 || idx > count) {
			printf(tr(TR_SES_RANGE), count ? count : 0);
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
			printf(tr(TR_SES_BAD_TARGET), target);
			return AI_ERR_INVALID_ARG;
		}
	}

	if (strcmp(target, cur_session(shell)) == 0) {
		printf(tr(TR_SES_ALREADY_IN), target);
		return AI_OK;
	}

	/* 切换前落盘当前会话的运行统计（消息本已写透，这里只打印确认） */
	session_set_current(shell, target);
	printf(tr(TR_SES_SWITCHED), target, ui_session_count(target));
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
		printf(tr(TR_SES_LOAD_FAIL), ai_error_string(ret));
		return;
	}
	printf(tr(TR_SES_SHOW), cur, n);
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
		/* W43：无子命令 → 会话状态速览（当前会话名/历史条数/
		 * SME 可达性），子命令帮助照旧附后。 */
		char sme_resp[SME_OUT_BUF_MIN];
		int sme_rc;

		printf(tr(TR_SES_STATUS_HDR), cur_session(shell),
		       ui_session_count(cur_session(shell)));
		fflush(stdout);
		sme_rc = sme_health(sme_resp, sizeof(sme_resp));
		printf("%s", sme_rc == AI_OK ? tr(TR_SME_REACHABLE) :
		       tr(TR_SME_UNREACHABLE));
		printf("Usage: session [<new|list|switch|save|delete|show>]"
		       " [args]\n");
		printf("%s", tr(TR_SES_HELP_NEW));
		printf("%s", tr(TR_SES_HELP_LIST));
		printf("%s", tr(TR_SES_HELP_SWITCH));
		printf("%s", tr(TR_SES_HELP_SAVE));
		printf("%s", tr(TR_SES_HELP_DELETE));
		printf("%s", tr(TR_SES_HELP_SHOW));
		return AI_OK;
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
		printf(tr(TR_SES_SAVED),
		       cur_session(shell), ui_session_count(cur_session(shell)));
		return AI_OK;
	}
	if (strcmp(argv[1], "delete") == 0) {
		if (argc < 3) {
			printf("Usage: session delete <name>\n");
			return AI_ERR_INVALID_ARG;
		}
		if (strcmp(argv[2], cur_session(shell)) == 0) {
			printf("%s", tr(TR_SES_DEL_CURRENT));
			return AI_ERR_INVALID_ARG;
		}
		{
			int ret = ui_session_delete(argv[2]);

			if (ret == AI_OK)
				printf(tr(TR_SES_DELETED), argv[2]);
			else
				printf(tr(TR_SES_DELETE_FAIL),
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
