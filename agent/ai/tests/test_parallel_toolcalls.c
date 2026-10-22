// SPDX-License-Identifier: GPL-2.0
/*
 * test_parallel_toolcalls.c - 单轮并行多 tool_calls 序列化回归（主控合并态回归）
 *
 * 场景：模型单轮并行返回 2 个 tool_calls（call_A/call_B），execute_round
 * 回填 2 条 role:tool 消息。回归点：请求构造器的孤儿剔除逻辑必须保持
 * "assistant(tool_calls) 响应组"语义——连续多条 tool 消息同组全放行，
 * 不得在第一条 tool 后清零组标志把第二条误杀（症状：DeepSeek 400
 * "insufficient tool messages following tool_calls message"）。
 * 同时覆盖：真孤儿（前面无 assistant(tool_calls)）仍必须剔除、
 * Ollama 原生通道同语义。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_chat.h"
#include "ai_json_util.h"
#include "local/ollama_native.h"

/* 两个并行调用（渲染器产物形态：arguments 二次编码） */
static const char *TC2 =
	"[{\"id\":\"call_A\",\"type\":\"function\",\"function\":{\"name\":"
	"\"memory_search\",\"arguments\":\"{\\\"q\\\":\\\"a\\\"}\"}},"
	"{\"id\":\"call_B\",\"type\":\"function\",\"function\":{\"name\":"
	"\"memory_search\",\"arguments\":\"{\\\"q\\\":\\\"b\\\"}\"}}]";

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

/* 组内配对场景（OpenAI 兼容格式）：2 条 tool 消息都必须进请求体 */
static int test_paired_two_toolcalls(void)
{
	struct ai_chat_msg msgs[8];
	struct ai_chat_msg m_tool_a, m_tool_b;
	char *body;
	int n;

	memset(msgs, 0, sizeof(msgs));
	n = 0;
	msgs[n].role = "system";
	msgs[n].content = "sys";
	n++;
	msgs[n].role = "user";
	msgs[n].content = "问";
	n++;
	msgs[n].role = "assistant";
	msgs[n].content = "";
	msgs[n].tool_calls_json = TC2;
	n++;
	memset(&m_tool_a, 0, sizeof(m_tool_a));
	m_tool_a.role = "tool";
	m_tool_a.tool_call_id = "call_A";
	m_tool_a.tool_name = "memory_search";
	m_tool_a.content = "结果A";
	msgs[n++] = m_tool_a;
	memset(&m_tool_b, 0, sizeof(m_tool_b));
	m_tool_b.role = "tool";
	m_tool_b.tool_call_id = "call_B";
	m_tool_b.tool_name = "memory_search";
	m_tool_b.content = "结果B";
	msgs[n++] = m_tool_b;
	msgs[n].role = "assistant";
	msgs[n].content = "最终回答";
	n++;
	msgs[n].role = "user";
	msgs[n].content = "继续";
	n++;

	body = ai_chat_build_request_json_ex("m", msgs, n, NULL, 0.7, 100, 0);
	if (!body) {
		printf("FAIL: build_request returned NULL\n");
		return 1;
	}
	if (count_occurrences(body, "\"tool_call_id\"") != 2) {
		printf("FAIL: expected 2 tool msgs in request, got %d "
		       "(insufficient tool messages regression)\n",
		       count_occurrences(body, "\"tool_call_id\""));
		free(body);
		return 1;
	}
	if (!strstr(body, "\"call_A\"") || !strstr(body, "\"call_B\"")) {
		printf("FAIL: call_A/call_B missing in request\n");
		free(body);
		return 1;
	}
	free(body);
	printf("PASS: 并行双 tool_calls 的 2 条 tool 消息全保留（OpenAI 格式）\n");
	return 0;
}

/* 真孤儿：tool 消息前面没有 assistant(tool_calls)，必须剔除 */
static int test_orphan_still_dropped(void)
{
	struct ai_chat_msg msgs[4];
	char *body;
	int n;

	memset(msgs, 0, sizeof(msgs));
	n = 0;
	msgs[n].role = "system";
	msgs[n].content = "sys";
	n++;
	msgs[n].role = "user";
	msgs[n].content = "问";
	n++;
	msgs[n].role = "tool";
	msgs[n].tool_call_id = "call_X";
	msgs[n].content = "孤儿结果";
	n++;
	msgs[n].role = "user";
	msgs[n].content = "继续";
	n++;

	body = ai_chat_build_request_json_ex("m", msgs, n, NULL, 0.7, 100, 0);
	if (!body) {
		printf("FAIL: build_request returned NULL\n");
		return 1;
	}
	if (count_occurrences(body, "\"tool_call_id\"") != 0) {
		printf("FAIL: orphan tool msg was serialized\n");
		free(body);
		return 1;
	}
	free(body);
	printf("PASS: 真孤儿 tool 消息仍被剔除\n");
	return 0;
}

/* Ollama 原生通道：同组语义（原生 tool 消息带 tool_name 字段） */
static int test_ollama_paired(void)
{
	struct ai_chat_msg msgs[6];
	char *body;
	int n;

	memset(msgs, 0, sizeof(msgs));
	n = 0;
	msgs[n].role = "system";
	msgs[n].content = "sys";
	n++;
	msgs[n].role = "user";
	msgs[n].content = "问";
	n++;
	msgs[n].role = "assistant";
	msgs[n].content = "";
	msgs[n].tool_calls_json = TC2;
	n++;
	msgs[n].role = "tool";
	msgs[n].tool_call_id = "call_A";
	msgs[n].tool_name = "memory_search";
	msgs[n].content = "结果A";
	n++;
	msgs[n].role = "tool";
	msgs[n].tool_call_id = "call_B";
	msgs[n].tool_name = "memory_search";
	msgs[n].content = "结果B";
	n++;

	body = ollama_native_build_body("m", msgs, n, NULL, 100, 8192, 0);
	if (!body) {
		printf("FAIL: native build_body returned NULL\n");
		return 1;
	}
	if (count_occurrences(body, "\"tool_name\"") != 2) {
		printf("FAIL: expected 2 native tool msgs, got %d\n",
		       count_occurrences(body, "\"tool_name\""));
		free(body);
		return 1;
	}
	free(body);
	printf("PASS: 并行双 tool_calls 全保留（Ollama 原生格式）\n");
	return 0;
}

int main(void)
{
	int fails = 0;

	fails += test_paired_two_toolcalls();
	fails += test_orphan_still_dropped();
	fails += test_ollama_paired();
	if (fails) {
		printf("==== %d FAIL ====\n", fails);
		return 1;
	}
	printf("==== 全部通过 ====\n");
	return 0;
}
