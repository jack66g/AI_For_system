/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_ask_autocompact.c - W56 T5：长历史 + 大工具输出触发自动 compact
 *
 * 实机缺陷（VM，W55 部署版，fs 会话）：auto-compact 后仍出现
 * "session context budget 110% used"。根因两层：
 *   1. 触发阈值 85% 偏晚，摘要请求自身逼近窗口；
 *   2. 预算百分比把 completion 也算进窗口，输出 token 与下一轮 prompt
 *      重复计数（W56 改为只计最近一次请求的 prompt）。
 *
 * 本测试走 cmd_ask 真实主循环：
 *   - 注入 ~30KB 历史（含 16KB 工具结果，模拟大输出）；
 *   - 断言自动 compact 被调用 1 次、历史被摘要替换（不再出现在请求里）；
 *   - 断言 compact 后的请求 tools=7（W56 T2）且预算百分比 ≤100。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_lang.h"
#include "ask_context.h"
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

#define HIST_MARK "W56_HIST_MARK"

static char g_hist_msg[10][3072];
static char g_hist_tool[16384];
static struct ai_chat_msg g_hist[12];

static int count_substr(const char *hay, const char *needle)
{
	int n = 0;
	const char *p = hay;
	size_t nl = strlen(needle);

	if (!hay || !nl)
		return 0;
	while ((p = strstr(p, needle)) != NULL) {
		n++;
		p += nl;
	}
	return n;
}

static void build_history(void)
{
	int i;

	for (i = 0; i < 10; i++) {
		size_t off = 0;

		off += (size_t)snprintf(g_hist_msg[i], sizeof(g_hist_msg[i]),
					HIST_MARK " msg%d: ", i);
		memset(g_hist_msg[i] + off, 'h',
		       sizeof(g_hist_msg[i]) - off - 1);
		g_hist_msg[i][sizeof(g_hist_msg[i]) - 1] = '\0';
	}
	snprintf(g_hist_tool, sizeof(g_hist_tool),
		 HIST_MARK " tool result: ");
	memset(g_hist_tool + strlen(g_hist_tool), 't',
	       sizeof(g_hist_tool) - strlen(g_hist_tool) - 1);
	g_hist_tool[sizeof(g_hist_tool) - 1] = '\0';

	memset(g_hist, 0, sizeof(g_hist));
	g_hist[0].role = "user";
	g_hist[0].content = g_hist_msg[0];
	g_hist[1].role = "assistant";
	g_hist[1].content = g_hist_msg[1];
	g_hist[2].role = "user";
	g_hist[2].content = g_hist_msg[2];
	g_hist[3].role = "assistant";
	g_hist[3].tool_calls_json = "[{\"id\":\"call_hist\",\"type\":"
		"\"function\",\"function\":{\"name\":\"exec_run\","
		"\"arguments\":\"{}\"}}]";
	g_hist[4].role = "tool";
	g_hist[4].tool_call_id = "call_hist";
	g_hist[4].content = g_hist_tool;
	g_hist[5].role = "assistant";
	g_hist[5].content = g_hist_msg[3];
	g_hist[6].role = "user";
	g_hist[6].content = g_hist_msg[4];
	g_hist[7].role = "assistant";
	g_hist[7].content = g_hist_msg[5];
	g_hist[8].role = "user";
	g_hist[8].content = g_hist_msg[6];
	g_hist[9].role = "assistant";
	g_hist[9].content = g_hist_msg[7];
	g_hist[10].role = "user";
	g_hist[10].content = g_hist_msg[8];
	g_hist[11].role = "assistant";
	g_hist[11].content = g_hist_msg[9];
}

static int mock_compact(void *shell)
{
	(void)shell;
	printf("  [mock] compact invoked: replace history with summary\n");
	g_ask_session_msgs = NULL;
	g_ask_session_n = 0;
	return AI_OK;
}

static int mock_chat(int call_no, const struct ai_chat_msg *msgs, int nmsgs,
		     const char *tools_json, struct ai_chat_result **result)
{
	int i;
	int hist_seen = 0;

	if (call_no != 1) {
		printf("  [FAIL] unexpected mock call %d\n", call_no);
		g_fail++;
		return AI_ERR_API;
	}
	printf("---- mock round 1 (post-compact) ----\n");
	CHECK(tools_json != NULL, "请求带 tools 数组");
	CHECK(count_substr(tools_json, "\"type\":\"function\"") == 8,
	      "compact 后首请求 tools=8 件（W77c 含 clarify）");
	for (i = 0; i < nmsgs; i++)
		if (msgs[i].content && strstr(msgs[i].content, HIST_MARK))
			hist_seen = 1;
	CHECK(!hist_seen, "长历史已被 compact 摘要替换（请求中无历史标记）");
	CHECK(nmsgs >= 2 && msgs[0].role &&
	      strcmp(msgs[0].role, "system") == 0, "首条为 system");
	CHECK(msgs[0].content &&
	      strstr(msgs[0].content, "默认使用用户提问的语言") != NULL,
	      "system 含语言默认指令（W56 T4）");
	CHECK(msgs[0].content &&
	      strstr(msgs[0].content, "用户已通过 -y") == NULL,
	      "无 assume_yes 时 system 不含预授权段（闸门行为不变）");

	*result = calloc(1, sizeof(**result));
	if (!*result)
		return AI_ERR_MEMORY;
	(*result)->content = strdup("已完成：历史已压缩。");
	(*result)->finish_reason = strdup("stop");
	(*result)->prompt_tokens = 1200;
	(*result)->completion_tokens = 300;
	return AI_OK;
}

int main(void)
{
	struct ai_config cfg;
	struct ai_shell shell;
	char *argv[] = { "ask", "继续刚才的排查" };
	int rc;
	int pct;

	printf("==== test_ask_autocompact: W56 T5 ====\n");
	lang_set("zh");
	build_history();
	g_ask_session_msgs = g_hist;
	g_ask_session_n = 12;
	g_ask_mock_compact = mock_compact;
	g_ask_mock_chat = mock_chat;

	memset(&cfg, 0, sizeof(cfg));
	cfg.default_model = strdup("mock-model");
	cfg.ui.ctx_len = 8192;
	cfg.ui.max_tokens = 1024;
	cfg.ui.stream = 0;
	cfg.ui.color = 0;
	cfg.ui.verbose = 0;
	cfg.ui.session = strdup("w56-autocompact-test");
	cfg.ui.lang = strdup("zh");
	cfg.routing.mode = AI_ROUTE_AUTONOMOUS;

	memset(&shell, 0, sizeof(shell));
	shell.config = &cfg;

	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);

	rc = cmd_ask(&shell, 2, argv);
	CHECK(rc == AI_OK, "cmd_ask 返回 AI_OK");
	CHECK(g_ask_compact_calls == 1, "长历史触发自动 compact 1 次");
	CHECK(g_ask_mock_calls == 1, "压缩后正常发起 1 次模型请求");
	pct = ask_ctx_budget_percent(shell.runtime.token_last_in,
				     shell.runtime.token_last_out, 8192);
	printf("  post-compact token_last_in=%d token_last_out=%d pct=%d%%\n",
	       shell.runtime.token_last_in, shell.runtime.token_last_out, pct);
	CHECK(pct <= 100, "compact 后上下文预算百分比 ≤100%");
	CHECK(pct == 14, "prompt 1200/8192 → 14%（completion 不计入）");
	CHECK(shell.runtime.token_session_in == 1200 &&
	      shell.runtime.token_session_out == 0,
	      "W72 提示符计数 = 最近一次请求 prompt（不累计、不含 completion）");
	CHECK(ask_ctx_prompt_percent(1200, 8192) == 14,
	      "W72 ask_ctx_prompt_percent 实时值 14%");
	CHECK(ask_ctx_prompt_percent(90000, 8192) == 100,
	      "W72 实时百分比上限 100%（不再 999%）");
	CHECK(ask_ctx_prompt_percent(0, 8192) == -1,
	      "W72 无 usage 数据显示 ? (-1)");

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
