/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_toolcall_backfill.c - 多 tool_calls 回填链路专项回归（W41 bug①）
 *
 * T3 实测缺陷：模型单轮返回多个 tool_calls 时，回填到对话历史的
 * assistant 消息 tool_call_id 乱码/错位，下一轮请求被服务端 400。
 * 根因：execute_round 把 result->tool_calls[i].id/.name 指针直接
 * 入消息数组，主循环轮末 ai_chat_result_free() 释放后消息数组持有
 * 悬垂指针（跨轮重放读到已回收内存）。修复（cmd_ask.c execute_round）：
 * id/name/content 一律 strdup 进会话所有权池（ask_own）。
 *
 * 本测试按 execute_round 的真实数据流走全链路锁定不变式：
 *   模拟响应 → ai_chat_parse_response（解析 3 个 tool_calls）→
 *   ai_chat_render_tool_calls（assistant 消息 tool_calls_json）→
 *   strdup 入所有权池 → ai_chat_result_free 释放响应（制造与 T3
 *   相同的生命周期断面）→ 重建请求体 → 断言 3 个 tool_call_id 与
 *   function.name 逐字原样保留、assistant/tool 配对完整。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_types.h"
#include "ai_chat.h"
#include "ai_json_util.h"

/* 模拟 DeepSeek 单轮 3 个并行 tool_calls 响应（id 各不相同） */
static const char *RESP3 =
	"{\"id\":\"chatcmpl-t3\",\"object\":\"chat.completion\","
	"\"choices\":[{\"index\":0,\"message\":{"
	"\"role\":\"assistant\",\"content\":null,\"tool_calls\":["
	"{\"id\":\"call_111_aaa\",\"type\":\"function\",\"function\":"
	"{\"name\":\"procfs_read_status\",\"arguments\":\"{}\"}},"
	"{\"id\":\"call_222_bbb\",\"type\":\"function\",\"function\":"
	"{\"name\":\"netlink_act_sched_nice\",\"arguments\":"
	"\"{\\\"pid\\\":42,\\\"nice\\\":5}\"}},"
	"{\"id\":\"call_333_ccc\",\"type\":\"function\",\"function\":"
	"{\"name\":\"sysfs_write_policy_global_enable\",\"arguments\":"
	"\"{\\\"value\\\":1}\"}}]},"
	"\"finish_reason\":\"tool_calls\"}],"
	"\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":20}}";

/* 每个断言用的 id/名（与 RESP3 一一对应） */
static const char *IDS[3] = {
	"call_111_aaa", "call_222_bbb", "call_333_ccc"
};
static const char *NAMES[3] = {
	"procfs_read_status", "netlink_act_sched_nice",
	"sysfs_write_policy_global_enable"
};

static int count_occurrences(const char *hay, const char *needle)
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

/* 所有权池（模拟 cmd_ask 的 ask_owned：消息数组字符串的真正归宿） */
static char *g_owned[64];
static int g_owned_n;

static char *own(char *s)
{
	if (s && g_owned_n < 64)
		g_owned[g_owned_n++] = s;
	return s;
}

static void owned_free_all(void)
{
	int i;

	for (i = 0; i < g_owned_n; i++)
		free(g_owned[i]);
	g_owned_n = 0;
}

/* 模拟 execute_round 的回填（native 路径，逐字段对应） */
static int backfill_round(const struct ai_chat_result *result,
			  char *tc_json_copy,
			  struct ai_chat_msg *msgs, int n)
{
	struct ai_chat_msg am;
	int i;

	memset(&am, 0, sizeof(am));
	am.role = own(strdup("assistant"));
	am.content = own(strdup(result->content ? result->content : ""));
	am.tool_calls_json = tc_json_copy;
	msgs[n++] = am;

	for (i = 0; i < result->tool_call_count; i++) {
		const struct ai_tool_call *tc = &result->tool_calls[i];
		struct ai_chat_msg tm;

		memset(&tm, 0, sizeof(tm));
		tm.role = own(strdup("tool"));
		/* 修复点复刻：id/name 必须 strdup 入池，不得借用 result */
		tm.tool_call_id = own(strdup(tc->id ? tc->id : "unknown"));
		tm.tool_name = tc->name ? own(strdup(tc->name)) : NULL;
		tm.content = own(strdup("{\"ok\":true}"));
		msgs[n++] = tm;
	}
	return n;
}

static int run_chain(void)
{
	struct ai_chat_result result;
	char *body2, *resp_copy, *tc_json, *tc_json_copy;
	struct ai_chat_msg msgs[16];
	int n = 0;
	int i;
	int fails = 0;

	memset(&result, 0, sizeof(result));
	resp_copy = strdup(RESP3);

	/* 1. 解析模拟响应 */
	if (ai_chat_parse_response(resp_copy, &result) != AI_OK) {
		printf("FAIL: parse_response 失败\n");
		free(resp_copy);
		return 1;
	}
	if (result.tool_call_count != 3) {
		printf("FAIL: 期望 3 个 tool_calls, 得 %d\n",
		       result.tool_call_count);
		ai_chat_result_free(&result);
		free(resp_copy);
		return 1;
	}

	/* 2. 解析出的 id 必须逐字等于响应原文（解析器不错位） */
	for (i = 0; i < 3; i++) {
		if (!result.tool_calls[i].id ||
		    strcmp(result.tool_calls[i].id, IDS[i]) != 0) {
			printf("FAIL: tool_calls[%d].id 解析错位: %s != %s\n",
			       i, result.tool_calls[i].id ?
			       result.tool_calls[i].id : "(null)", IDS[i]);
			fails++;
		}
		if (!result.tool_calls[i].name ||
		    strcmp(result.tool_calls[i].name, NAMES[i]) != 0) {
			printf("FAIL: tool_calls[%d].name 解析错位\n", i);
			fails++;
		}
	}

	/* 3. 渲染 assistant tool_calls_json + 回填入池 */
	tc_json = ai_chat_render_tool_calls(result.tool_calls,
					    result.tool_call_count);
	if (!tc_json) {
		printf("FAIL: render_tool_calls 返回 NULL\n");
		ai_chat_result_free(&result);
		free(resp_copy);
		return 1;
	}
	tc_json_copy = own(tc_json);    /* cmd_ask 同款：副本入池 */

	memset(msgs, 0, sizeof(msgs));
	msgs[n].role = own(strdup("system"));
	msgs[n].content = own(strdup("sys"));
	n++;
	msgs[n].role = own(strdup("user"));
	msgs[n].content = own(strdup("问"));
	n++;
	n = backfill_round(&result, tc_json_copy, msgs, n);

	/* 4. 生命周期断面：释放响应与响应体（T3 悬垂指针触发点） */
	ai_chat_result_free(&result);
	free(resp_copy);
	resp_copy = NULL;

	/* 5. 用回填后的历史重建请求体（下一轮），断言 id 原样保留 */
	body2 = ai_chat_build_request_json_ex("m", msgs, n, NULL, 0.7,
					      100, 0);
	if (!body2) {
		printf("FAIL: 重建请求体失败\n");
		owned_free_all();
		return 1;
	}
	if (count_occurrences(body2, "\"tool_call_id\"") != 3) {
		printf("FAIL: 请求体 tool 消息数 %d != 3（配对被拆散）\n",
		       count_occurrences(body2, "\"tool_call_id\""));
		fails++;
	}
	for (i = 0; i < 3; i++) {
		char pat[128];

		/* role:tool 的 tool_call_id 逐字保留 */
		snprintf(pat, sizeof(pat), "\"tool_call_id\":\"%s\"",
			 IDS[i]);
		if (!strstr(body2, pat)) {
			printf("FAIL: 回填后 tool_call_id 丢失/乱码: %s\n",
			       IDS[i]);
			fails++;
		}
		/* assistant tool_calls 数组内的 id 逐字保留
		 * （tool_calls_json 原样嵌入请求体，不二次转义） */
		snprintf(pat, sizeof(pat), "\"id\":\"%s\"", IDS[i]);
		if (!strstr(body2, pat)) {
			printf("FAIL: 回填后 assistant tool_calls id 丢失: "
			       "%s\n", IDS[i]);
			fails++;
		}
		/* function.name 逐字保留 */
		snprintf(pat, sizeof(pat), "\"name\":\"%s\"", NAMES[i]);
		if (!strstr(body2, pat)) {
			printf("FAIL: 回填后 function.name 丢失: %s\n",
			       NAMES[i]);
			fails++;
		}
	}
	/* assistant(tool_calls) 必须在 3 条 tool 消息之前（配对不变式） */
	{
		const char *ptc = strstr(body2, "\"tool_calls\":");
		const char *ptid = strstr(body2, "\"tool_call_id\"");

		if (!ptc || !ptid || ptc > ptid) {
			printf("FAIL: assistant(tool_calls) 未先于 tool 消息\n");
			fails++;
		}
	}

	free(body2);
	owned_free_all();
	if (!fails)
		printf("PASS: 3 tool_calls 回填全链路 id/name 逐字保留、配对完整\n");
	return fails;
}

/* 二轮复用：同一所有权池历史再重建一次（跨轮重放稳定性） */
static int run_second_replay(void)
{
	struct ai_chat_result result;
	struct ai_chat_msg msgs[16];
	char *tc_json;
	int n = 0;
	int fails = 0;
	char *body;

	memset(&result, 0, sizeof(result));
	if (ai_chat_parse_response(RESP3, &result) != AI_OK)
		return 1;
	tc_json = own(ai_chat_render_tool_calls(result.tool_calls,
						result.tool_call_count));
	memset(msgs, 0, sizeof(msgs));
	msgs[n].role = own(strdup("system"));
	msgs[n].content = own(strdup("sys"));
	n++;
	msgs[n].role = own(strdup("user"));
	msgs[n].content = own(strdup("问"));
	n++;
	n = backfill_round(&result, tc_json, msgs, n);
	ai_chat_result_free(&result);

	/* 连续重建两轮请求体：池内副本必须稳定不变 */
	body = ai_chat_build_request_json_ex("m", msgs, n, NULL, 0.7,
					     100, 0);
	if (!body || !strstr(body, "\"call_222_bbb\"") ||
	    count_occurrences(body, "\"tool_call_id\"") != 3) {
		printf("FAIL: 第二轮重放 id 丢失（池化不生效）\n");
		fails++;
	}
	free(body);

	body = ai_chat_build_request_json_ex("m", msgs, n, NULL, 0.7,
					     100, 0);
	if (!body || !strstr(body, "\"call_333_ccc\"") ||
	    !strstr(body, "\"call_111_aaa\"")) {
		printf("FAIL: 第三轮重放 id 丢失（池化不生效）\n");
		fails++;
	}
	free(body);
	owned_free_all();
	if (!fails)
		printf("PASS: 跨轮重放（2/3 轮重建）id 稳定保留\n");
	return fails;
}

int main(void)
{
	int fails = 0;

	fails += run_chain();
	fails += run_second_replay();
	if (fails) {
		printf("==== %d FAIL ====\n", fails);
		return 1;
	}
	printf("==== 全部通过 ====\n");
	return 0;
}
