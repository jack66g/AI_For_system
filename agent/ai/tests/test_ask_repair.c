// SPDX-License-Identifier: GPL-2.0
/*
 * test_ask_repair.c - W65 P2-03：参数契约自动纠正重试（每轮最多一次）
 *
 * mock 模型第一次把整条命令塞进 command；mock 执行器返回
 * ERROR[E_PARAM_WHOLE_COMMAND]（含 USAGE/AVAILABLE）。cmd_ask 必须：
 *   1. 把结构化错误回填给模型；
 *   2. 追加一条 user 修复指令（含 E_PARAM_* 与“重试”要求）；
 *   3. 自动发起下一次模型请求（不靠用户再问）；
 *   4. 第二次正确参数执行成功后正常收尾；
 *   5. 全程只自动重试一次（模型请求数 = 3，工具执行 = 2）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_chat.h"
#include "ai_lang.h"
#include "tools/tool_registry.h"
#include "test_ask_stubs.h"

static int g_fail;
static int g_saw_repair_hint;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
		g_fail++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

static struct ai_chat_result *mk_result(const char *content,
					const char *call_id,
					const char *name,
					const char *args)
{
	struct ai_chat_result *r = calloc(1, sizeof(*r));

	if (!r)
		return NULL;
	r->content = strdup(content ? content : "");
	r->finish_reason = strdup(call_id ? "tool_calls" : "stop");
	r->prompt_tokens = 100;
	r->completion_tokens = 10;
	if (call_id) {
		r->tool_calls = calloc(1, sizeof(*r->tool_calls));
		if (!r->tool_calls) {
			free(r->content);
			free(r->finish_reason);
			free(r);
			return NULL;
		}
		r->tool_calls[0].id = strdup(call_id);
		r->tool_calls[0].name = strdup(name);
		r->tool_calls[0].arguments = strdup(args ? args : "{}");
		r->tool_call_count = 1;
	}
	return r;
}

static int mock_chat(int call_no, const struct ai_chat_msg *msgs, int nmsgs,
		     const char *tools_json, struct ai_chat_result **result)
{
	(void)tools_json;
	if (call_no == 1) {
		*result = mk_result("", "call_bad", "exec_run",
				    "{\"command\":\"uname -a\"}");
		return *result ? AI_OK : AI_ERR_MEMORY;
	}
	if (call_no == 2) {
		int i;
		const char *hint = NULL;

		for (i = nmsgs - 1; i >= 0; i--) {
			if (msgs[i].role && strcmp(msgs[i].role, "user") == 0 &&
			    msgs[i].content &&
			    strstr(msgs[i].content, "E_PARAM_")) {
				hint = msgs[i].content;
				break;
			}
		}
		g_saw_repair_hint = hint != NULL;
		CHECK(hint && strstr(hint, "重试") != NULL,
		      "第 2 次请求前注入修复指令（含 E_PARAM_* 与重试）");
		*result = mk_result("", "call_good", "exec_run",
				    "{\"command\":\"uname\",\"args\":[\"-a\"]}");
		return *result ? AI_OK : AI_ERR_MEMORY;
	}
	if (call_no == 3) {
		*result = mk_result("Linux mock 6.18.39", NULL, NULL, NULL);
		return *result ? AI_OK : AI_ERR_MEMORY;
	}
	printf("FAIL: unexpected mock call %d\n", call_no);
	g_fail++;
	return AI_ERR_API;
}

static int mock_tool(const struct ai_tool *tool, const char *args_json,
		     char **out, int *ok)
{
	(void)tool;
	if (args_json && strstr(args_json, "uname -a")) {
		*out = strdup("ERROR[E_PARAM_WHOLE_COMMAND]: command 必须是"
			      "单个命令名\nUSAGE: {\"command\":\"uname\","
			      "\"args\":[\"-a\"]}\nAVAILABLE(1): uname");
		*ok = 0;
		return AI_OK;
	}
	*out = strdup("命令执行成功，输出:\nLinux mock 6.18.39");
	*ok = 1;
	return AI_OK;
}

int main(void)
{
	struct ai_config cfg;
	struct ai_shell shell;
	char *argv[] = { "ask", "看看内核版本" };
	int rc;

	printf("==== test_ask_repair: P2-03 ====\n");
	lang_set("zh");
	memset(&cfg, 0, sizeof(cfg));
	cfg.default_model = strdup("mock-model");
	cfg.ui.ctx_len = 8192;
	cfg.ui.max_tokens = 1024;
	cfg.ui.stream = 0;
	cfg.ui.color = 0;
	cfg.ui.verbose = 0;
	cfg.ui.session = strdup("w65-repair-test");
	cfg.ui.lang = strdup("zh");
	cfg.routing.mode = AI_ROUTE_AUTONOMOUS;

	memset(&shell, 0, sizeof(shell));
	shell.config = &cfg;

	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	g_ask_mock_chat = mock_chat;
	g_ask_mock_tool = mock_tool;

	rc = cmd_ask(&shell, 2, argv);
	CHECK(rc == AI_OK, "cmd_ask 返回 AI_OK");
	CHECK(g_saw_repair_hint, "修复指令已进入下一次模型请求");
	CHECK(g_ask_mock_calls == 3,
	      "共 3 次模型请求（原始 + 自动重试 + 最终回答）");
	CHECK(g_ask_dispatch_count == 2,
	      "共 2 次工具执行（失败参数 + 修正后成功）");
	CHECK(g_ask_dispatch_count == 2 &&
	      strcmp(g_ask_dispatched[0], "exec_run") == 0 &&
	      strcmp(g_ask_dispatched[1], "exec_run") == 0,
	      "两次都是 exec_run（无其它工具串入）");

	free(cfg.default_model);
	free(cfg.ui.session);
	free(cfg.ui.lang);
	if (g_fail) {
		printf("test_ask_repair: FAIL (%d)\n", g_fail);
		return 1;
	}
	printf("test_ask_repair: ALL PASS\n");
	return 0;
}
