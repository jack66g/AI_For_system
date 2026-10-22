/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_router_activation.c - W55 P1：检索激活工具必须在下一请求生效
 *
 * 实机缺陷（VM，会话 w54-sandbox，查询"建个隔离区 demo9..."）：
 *   trace 证明第 2 次请求 tools 数组已含 sandbox_*（13/130），但框架
 *   回填文案写的是"完整定义已进入下一请求的 tools 数组，下一轮可直接
 *   调用"，模型据此认为"本轮还不能调"，只输出计划、不执行。
 *
 * 本测试用进程内 mock runtime 走 cmd_ask 真实主循环（注册表/工具查找/
 * 请求序列化/execute_round 全真，仅 shell 环境与模型调用打桩）：
 *   round 1: 断言 tools=7 个默认工具（W56 T2 含 memory_stats/
 *            memory_health）；断言 assume_yes 预授权与语言默认进入
 *            system prompt（W56 T1/T4）；返回 memory_search 调用；
 *            工具结果包含 sandbox_status/create/spawn/destroy；
 *   round 2: 断言 tools 数组已扩入 4 个 sandbox 工具（7+4=11）；断言
 *            回填文案说明"当前这次请求"且不再写"下一轮可直接调用"；
 *            返回 sandbox_status 调用；
 *   round 3: 断言执行器已分发 sandbox_status；返回最终回答。
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
	r->prompt_tokens = 3000;
	r->completion_tokens = 100;
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
	if (call_no == 1) {
		printf("---- mock round 1 ----\n");
		CHECK(tools_json != NULL, "round1 请求带 tools 数组");
		CHECK(count_substr(tools_json, "\"type\":\"function\"") == 8,
		      "round1 tools = 默认 8 件（W77c 含 clarify）");
		CHECK(strstr(tools_json, "\"name\":\"memory_search\"") != NULL,
		      "round1 含 memory_search");
		CHECK(strstr(tools_json, "\"name\":\"memory_stats\"") != NULL,
		      "round1 含 memory_stats（免检索直接调用）");
		CHECK(strstr(tools_json, "\"name\":\"memory_health\"") != NULL,
		      "round1 含 memory_health");
		CHECK(strstr(tools_json, "\"name\":\"sandbox_create\"") == NULL,
		      "round1 未激活 sandbox_create");
		CHECK(msgs && nmsgs >= 2 && msgs[0].role &&
		      strcmp(msgs[0].role, "system") == 0,
		      "首条为 system");
		CHECK(msgs[0].content &&
		      strstr(msgs[0].content, "不要只输出计划") != NULL,
		      "autonomous 提示含「不要只输出计划」");
		/* 目录/检索指引本身可能含"可直接调用"（描述工具已就绪），
		 * 这里只断言旧预授权承诺消失。 */
		CHECK(msgs[0].content &&
		      strstr(msgs[0].content, "预授权") != NULL &&
		      strstr(msgs[0].content, "D2") != NULL &&
		      strstr(msgs[0].content, "短租约") != NULL &&
		      strstr(msgs[0].content, "CONFIRM_REQUIRED") != NULL &&
		      strstr(msgs[0].content, "无需再次询问") == NULL &&
		      strstr(msgs[0].content, "CONFIRM=yes(auto)") == NULL,
		      "assume_yes 仅 D2 短租约，D3/D4 需确认（W74）");
		CHECK(msgs[0].content &&
		      strstr(msgs[0].content, "默认使用用户提问的语言") != NULL &&
		      strstr(msgs[0].content, "必须使用中文") != NULL,
		      "语言默认指令进入 system prompt（W56 T4）");
		*result = mk_result("", "call_mem_1", "memory_search",
				    "{\"text\":\"sandbox 隔离区 创建 子智能体 销毁\"}");
		return *result ? AI_OK : AI_ERR_MEMORY;
	}
	if (call_no == 2) {
		int last = nmsgs - 1;
		const char *tool_msg = (last >= 0 && msgs[last].role &&
			strcmp(msgs[last].role, "tool") == 0) ?
			msgs[last].content : NULL;

		printf("---- mock round 2 ----\n");
		CHECK(count_substr(tools_json, "\"type\":\"function\"") == 12,
		      "round2 tools 扩入到 12 件（默认 8 + sandbox 4）");
		CHECK(strstr(tools_json, "\"name\":\"sandbox_status\"") != NULL,
		      "round2 含 sandbox_status 完整 schema");
		CHECK(strstr(tools_json, "\"name\":\"sandbox_create\"") != NULL,
		      "round2 含 sandbox_create");
		CHECK(strstr(tools_json, "\"name\":\"sandbox_spawn\"") != NULL,
		      "round2 含 sandbox_spawn");
		CHECK(strstr(tools_json, "\"name\":\"sandbox_destroy\"") != NULL,
		      "round2 含 sandbox_destroy");
		CHECK(tool_msg != NULL, "round2 末尾为 memory_search 工具结果");
		CHECK(tool_msg && strstr(tool_msg, "当前这次请求") != NULL,
		      "框架提示说明工具已进入当前请求");
		CHECK(tool_msg && strstr(tool_msg, "你现在就可以直接调用") != NULL,
		      "框架提示要求立即调用");
		CHECK(tool_msg && strstr(tool_msg, "下一轮可直接调用") == NULL,
		      "不再出现「下一轮可直接调用」的误导文案");
		*result = mk_result("", "call_sb_1", "sandbox_status", "{}");
		return *result ? AI_OK : AI_ERR_MEMORY;
	}
	if (call_no == 3) {
		printf("---- mock round 3 ----\n");
		CHECK(g_ask_dispatch_count >= 2,
		      "执行器累计分发 ≥2 次（memory_search + sandbox_status）");
		CHECK(g_ask_dispatch_count >= 2 &&
		      strcmp(g_ask_dispatched[1], "sandbox_status") == 0,
		      "已激活的 sandbox_status 被真实分发");
		*result = mk_result("已创建并检查隔离区 demo9。", NULL, NULL,
				    NULL);
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
	char *argv[] = { "ask",
		"解释 cgroup v2 的 cpu.max 并给出一个例子" };
	int rc;

	printf("==== test_router_activation: W55 P1 + W56 T1/T2/T4 ====\n");
	lang_set("zh");
	memset(&cfg, 0, sizeof(cfg));
	cfg.default_model = strdup("mock-model");
	cfg.ui.ctx_len = 8192;
	cfg.ui.max_tokens = 1024;
	cfg.ui.stream = 0;
	cfg.ui.color = 0;
	cfg.ui.verbose = 0;
	cfg.ui.session = strdup("w55-router-test");
	cfg.ui.lang = strdup("zh");
	cfg.routing.mode = AI_ROUTE_AUTONOMOUS;

	memset(&shell, 0, sizeof(shell));
	shell.config = &cfg;

	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	g_ask_mock_chat = mock_chat;
	/* W56 T1：模拟 ai -y（AIKERNEL_ASSUME_YES）下的预授权状态 */
	g_ask_policy_assume_yes = 1;

	rc = cmd_ask(&shell, 2, argv);
	CHECK(rc == AI_OK, "cmd_ask 返回 AI_OK");
	CHECK(g_ask_mock_calls == 3, "共 3 次模型请求（工具调用闭环）");
	CHECK(g_ask_dispatch_count == 2, "共 2 次工具执行");
	CHECK(g_ask_dispatch_count == 2 &&
	      strcmp(g_ask_dispatched[0], "memory_search") == 0,
	      "第 1 次分发 memory_search");

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
