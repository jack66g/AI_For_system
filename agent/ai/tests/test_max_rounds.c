/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_max_rounds.c - W72：最大轮数 8→12 + 触顶强制结论
 *
 * 背景：W70 T17（删除记忆+检索确认）在第 8 轮触顶，只打印
 * "max rounds limit (8) reached, forcing stop"，没有最终回答。
 * W72：
 *   - 默认轮数上限提高到 12；
 *   - 触顶后追加一次"禁止工具、只给结论"的收尾请求（tools_json=NULL），
 *     仍受 12 轮硬上限约束，不会死循环。
 * 本测试用 mock chat 连续 12 轮返回工具调用，第 13 次请求断言无 tools
 * 且收到收尾提示，返回最终回答。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_chat.h"
#include "ai_lang.h"
#include "test_ask_stubs.h"

static int g_fail;

#define CHECK(cond, msg)						\
	do {								\
		if (cond) {						\
			printf("  [PASS] %s\n", msg);			\
		} else {						\
			printf("  [FAIL] %s (%s:%d)\n", msg,		\
			       __FILE__, __LINE__);			\
			g_fail++;					\
		}							\
	} while (0)

static struct ai_chat_result *mk_result(const char *content,
					const char *call_id)
{
	struct ai_chat_result *r = calloc(1, sizeof(*r));

	if (!r)
		return NULL;
	r->content = strdup(content ? content : "");
	r->finish_reason = strdup(call_id ? "tool_calls" : "stop");
	r->prompt_tokens = 400;
	r->completion_tokens = 50;
	if (call_id) {
		r->tool_calls = calloc(1, sizeof(*r->tool_calls));
		if (!r->tool_calls) {
			free(r->content);
			free(r->finish_reason);
			free(r);
			return NULL;
		}
		r->tool_calls[0].id = strdup(call_id);
		r->tool_calls[0].name = strdup("procfs_read_status");
		r->tool_calls[0].arguments = strdup("{}");
		r->tool_call_count = 1;
	}
	return r;
}

static int mock_chat(int call_no, const struct ai_chat_msg *msgs, int nmsgs,
		     const char *tools_json, struct ai_chat_result **result)
{
	if (call_no <= 12) {
		char id[32];

		snprintf(id, sizeof(id), "call_r%d", call_no);
		*result = mk_result("", id);
		return *result ? AI_OK : AI_ERR_MEMORY;
	}
	if (call_no == 13) {
		int saw_hint = 0;
		int i;

		printf("---- final conclusion request (call 13) ----\n");
		CHECK(tools_json == NULL,
		      "收尾请求不带 tools（禁止继续工具循环）");
		for (i = 0; i < nmsgs; i++)
			if (msgs[i].role && strcmp(msgs[i].role, "user") == 0 &&
			    msgs[i].content &&
			    strstr(msgs[i].content, "已达到工具调用轮数上限"))
				saw_hint = 1;
		CHECK(saw_hint, "收尾请求注入『禁止工具、给结论』提示");
		*result = mk_result("已完成：12 轮工具后给出最终结论。", NULL);
		return *result ? AI_OK : AI_ERR_MEMORY;
	}
	printf("  [FAIL] unexpected mock call %d\n", call_no);
	g_fail++;
	return AI_ERR_API;
}

int main(void)
{
	struct ai_config cfg;
	struct ai_shell shell;
	char *argv[] = { "ask", "删除记忆并反复验证" };
	int rc;

	printf("==== test_max_rounds: W72 12 rounds + final answer ====\n");
	lang_set("zh");
	memset(&cfg, 0, sizeof(cfg));
	cfg.default_model = strdup("mock-model");
	cfg.ui.ctx_len = 32768;
	cfg.ui.max_tokens = 8192;
	cfg.ui.stream = 0;
	cfg.ui.color = 0;
	cfg.ui.verbose = 0;
	cfg.ui.session = strdup("w72-max-rounds");
	cfg.ui.lang = strdup("zh");
	cfg.routing.mode = AI_ROUTE_AUTONOMOUS;

	memset(&shell, 0, sizeof(shell));
	shell.config = &cfg;
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	unsetenv("AIKERNEL_MAX_ROUNDS");
	g_ask_mock_chat = mock_chat;

	rc = cmd_ask(&shell, 2, argv);
	CHECK(rc == AI_OK, "触顶后收尾回答成功，cmd_ask 返回 AI_OK");
	CHECK(g_ask_mock_calls == 13,
	      "12 轮工具 + 1 次收尾请求 = 13 次模型调用");
	CHECK(g_ask_dispatch_count == 12, "12 轮工具全部真实分发");
	CHECK(shell.runtime.token_session_in == 400 &&
	      shell.runtime.token_session_out == 0,
	      "提示符计数 = 收尾请求 prompt（不累计）");

	free(cfg.default_model);
	free(cfg.ui.session);
	free(cfg.ui.lang);
	if (g_fail == 0) {
		printf("RESULT: PASS\n");
		return 0;
	}
	printf("RESULT: FAIL (%d)\n", g_fail);
	return 1;
}
