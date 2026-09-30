// SPDX-License-Identifier: GPL-2.0
/*
 * t2fix_utf8_test.c - T2 问题 1 字节级回归测试
 *
 * 复现场景：ask 第 2 轮请求把含中文+emoji 的工具结果回传给 LLM 服务。
 * 历史 bug：cmd_ask.c 把 tool_name/tool_call_id 直接引用 result->tool_calls
 * （execute_round 返回后即被释放），下一轮序列化读到已释放堆内存 →
 * 请求体含非法 UTF-8（实测 tool_name 变堆指针字节 "\x89%z+"）→ 服务端
 * UnicodeDecodeError 拒收 → agent 静默无最终回复。
 *
 * 本测试链接 agent 真实序列化目标文件（ollama_native.o / local_chat.o /
 * local_http.o / ai_json_util.o），断言：
 *   1. 含中文+emoji+控制字符的工具结果消息序列化后的请求体是合法 UTF-8；
 *   2. HTTP 请求头 Content-Length == 实际 body 字节数（复刻
 *      local_http.c build_post_request 的组装路径，逐字一致）；
 *   3. tool_name 以合法字符串出现在请求体（UAF 回归）；
 *   4. ai_json_escape 对多字节字符往返无损；
 *   5. utf8_safe_len（cmd_ask.c 显示截断，T2 问题 2 修复件）不把多字节
 *      序列从中间切开。
 *
 * 编译（agent/ai 目录下）：
 *   gcc -Wall -Wextra -std=c11 -O2 -Iinclude -I. -Iruntime \
 *       -o t2fix_utf8_test t2fix_utf8_test.c \
 *       build/local/ollama_native.o build/local/local_chat.o \
 *       build/local/local_http.o build/runtime/ai_json_util.o -lpthread
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_types.h"
#include "ai_chat.h"
#include "ai_json_util.h"
#include "ollama_native.h"

static int g_fail;
static int g_pass;

static void expect(int cond, const char *what)
{
	printf("%s: %s\n", cond ? "PASS" : "FAIL", what);
	if (cond)
		g_pass++;
	else
		g_fail++;
}

/* UTF-8 合法性校验：逐序列验证（续字节完整、lead 字节合法） */
static int valid_utf8(const char *s, size_t n)
{
	size_t i = 0;

	while (i < n) {
		unsigned char c = (unsigned char)s[i];
		size_t cont;

		if (c < 0x80) {
			i++;
			continue;
		}
		if ((c & 0xE0) == 0xC0)
			cont = 1;
		else if ((c & 0xF0) == 0xE0)
			cont = 2;
		else if ((c & 0xF8) == 0xF0)
			cont = 3;
		else
			return 0;   /* 裸续字节 / 非法 lead */
		i++;
		if (i + cont > n)
			return 0;   /* 序列被截断 */
		for (size_t k = 0; k < cont; k++) {
			if (((unsigned char)s[i + k] & 0xC0) != 0x80)
				return 0;
		}
		i += cont;
	}
	return 1;
}

/*
 * build_post_request_replica - 复刻 local_http.c build_post_request 的
 * 报文组装路径（原函数 static 不可链接；此处逐字保持一致：Content-Length
 * 用 %zu + strlen(json_body)，恒为字节数）。若原实现漂移本测试需同步。
 */
static char *build_post_request_replica(const char *host, const char *path,
					const char *api_key,
					const char *json_body,
					size_t *req_len)
{
	size_t key_len = (api_key && api_key[0]) ? strlen(api_key) : 0;
	size_t cap = strlen(json_body) + strlen(host) + strlen(path)
		     + key_len + 1024;
	char *req;
	int n;

	req = malloc(cap);
	if (!req)
		return NULL;

	if (key_len > 0)
		n = snprintf(req, cap,
			     "POST %s HTTP/1.1\r\n"
			     "Host: %s\r\n"
			     "Content-Type: application/json\r\n"
			     "Authorization: Bearer %s\r\n"
			     "Content-Length: %zu\r\n"
			     "Connection: close\r\n"
			     "\r\n"
			     "%s",
			     path, host, api_key, strlen(json_body), json_body);
	else
		n = snprintf(req, cap,
			     "POST %s HTTP/1.1\r\n"
			     "Host: %s\r\n"
			     "Content-Type: application/json\r\n"
			     "Content-Length: %zu\r\n"
			     "Connection: close\r\n"
			     "\r\n"
			     "%s",
			     path, host, strlen(json_body), json_body);

	if (n < 0 || (size_t)n >= cap) {
		free(req);
		return NULL;
	}
	*req_len = (size_t)n;
	return req;
}

/* 复刻 cmd_ask.c utf8_safe_len（显示端 UTF-8 安全截断） */
static size_t utf8_safe_len(const char *s, size_t max_bytes)
{
	size_t n = strlen(s);

	if (n > max_bytes)
		n = max_bytes;
	while (n > 0 && ((unsigned char)s[n] & 0xC0) == 0x80)
		n--;
	return n;
}

int main(void)
{
	/* ---- 场景构造：第 2 轮请求（system + assistant(tool_calls) +
	 *      tool(中文+emoji 结果)），即 T2 失败形态 ---- */
	struct ai_chat_msg msgs[3];
	char *body, *req, *esc, *quoted, *back;
	size_t req_len = 0;
	const char *tc_json =
		"[{\"function\":{\"name\":\"netlink.act.sched.nice\","
		"\"arguments\":\"{\\\"pid\\\":1,\\\"value\\\":3}\"}}]";
	const char *tool_out = "OK: ACT 已下发 domain=1 param=sched.nice "
			       "value=3 已完成执行 🚀 中文工具结果含四字节"
			       "emoji😀与控制字符\t换行\n结束";

	memset(msgs, 0, sizeof(msgs));
	msgs[0].role = "system";
	msgs[0].content = "你是 AIKernel 系统管理员 AI。约束：只使用列出的工具。";
	msgs[1].role = "assistant";
	msgs[1].content = "";
	msgs[1].tool_calls_json = (char *)tc_json;
	msgs[2].role = "tool";
	msgs[2].tool_call_id = "unknown";
	msgs[2].tool_name = "netlink.act.sched.nice";
	msgs[2].content = (char *)tool_out;

	/* 1. 真实序列化函数产出请求体 */
	body = ollama_native_build_body("qwen2.5:1.5b", msgs, 3, NULL,
					2048, 32768, 0);
	expect(body != NULL, "ollama_native_build_body 产出请求体");
	if (!body)
		goto out;

	/* 2. 请求体整体合法 UTF-8（中文 + 3 字节汉字 + 4 字节 emoji） */
	expect(valid_utf8(body, strlen(body)),
	       "请求体合法 UTF-8（中文+emoji+控制字符）");

	/* 3. tool_name 合法出现在请求体（UAF 回归：非堆垃圾字节） */
	{
		const char *tn = strstr(body, "\"tool_name\":\"");

		expect(tn != NULL, "请求体含 tool_name 字段");
		if (tn)
			expect(strstr(tn,
				      "\"tool_name\":\"netlink.act.sched.nice\"")
			       == tn,
			       "tool_name 全名合法（无堆指针字节）");
	}
	expect(strstr(body, "已完成执行") != NULL &&
	       strstr(body, "\xF0\x9F\x9A\x80") != NULL,
	       "工具结果中文与 4 字节 emoji 完整进入请求体");

	/* 4. Content-Length == 实际字节数（字节安全，非字符数） */
	req = build_post_request_replica("127.0.0.1", "/api/chat", NULL,
					 body, &req_len);
	expect(req != NULL, "build_post_request 复刻路径组装成功");
	if (req) {
		const char *cl = strstr(req, "Content-Length: ");
		long declared = cl ? strtol(cl + strlen("Content-Length: "),
					    NULL, 10) : -1;
		size_t actual = strlen(body);

		expect(declared == (long)actual,
		       "Content-Length == body 实际字节数");
		/* 完整请求报文同样合法 UTF-8 */
		expect(valid_utf8(req, req_len), "完整请求报文合法 UTF-8");
		free(req);
	}

	/* 5. ai_json_escape 多字节往返无损 */
	esc = ai_json_escape("中文😀\n\t\"引号\"\\反斜杠");
	expect(esc != NULL && valid_utf8(esc, strlen(esc)),
	       "ai_json_escape 输出合法 UTF-8");
	if (esc) {
		quoted = malloc(strlen(esc) + 3);

		if (quoted) {
			quoted[0] = '"';
			memcpy(quoted + 1, esc, strlen(esc));
			quoted[strlen(esc) + 1] = '"';
			quoted[strlen(esc) + 2] = '\0';
			back = ai_json_strdup_str(quoted, strlen(quoted));
			expect(back != NULL &&
			       strcmp(back, "中文😀\n\t\"引号\"\\反斜杠") == 0,
			       "escape/unescape 往返无损（含 emoji 与控制符）");
			free(back);
			free(quoted);
		}
		free(esc);
	}

	/* 6. utf8_safe_len 字符边界截断（T2 问题 2 修复件） */
	{
		const char *zh = "权限分级拦截";      /* 每字 3 字节 */
		const char *em = "a\xF0\x9F\x98\x80" "b"; /* 4 字节 emoji */

		expect(utf8_safe_len(zh, 4) == 3,
		       "截 4 字节回退到字符边界 3（汉字不切半）");
		expect(utf8_safe_len(zh, 7) == 6,
		       "截 7 字节回退到字符边界 6");
		expect(utf8_safe_len(zh, 100) == 18,
		       "不超限时返回全長");
		expect(utf8_safe_len(em, 2) == 1,
		       "截 2 字节回退到边界 1（4 字节 emoji 不切半）");
		expect(utf8_safe_len(em, 6) == 6,
		       "截 6 字节恰在完整 emoji 之后");
	}

out:
	printf("\n%d 项通过, %d 项失败\n", g_pass, g_fail);
	free(body);
	return g_fail ? 1 : 0;
}
