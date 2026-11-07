/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_sse_openai.c - OpenAI 兼容 SSE 消费单测（T9a1）
 * 覆盖：正常流（文本+工具增量+usage+[DONE]）/ keepalive+data:null 容错 /
 * 坏 JSON 块中止 / EOF 截断检出 / [DONE] 后数据检出 / finish 后工具增量
 * 检出 / 任意字节切分等价。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../occ_llm/occ_llm.h"
#include "occ_norm.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

static const char FX_NORMAL[] =
	"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"Hello\"}}]}\n"
	"\n"
	"data: {\"choices\":[{\"delta\":{\"content\":\", world\"}}]}\n"
	"\n"
	": keepalive comment\n"
	"data: null\n"
	"\n"
	"data: : keepalive\n"
	"\n"
	"data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"thinking...\"}}]}\n"
	"\n"
	"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n"
	"\n"
	"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"city\\\":\"}}]}}]}\n"
	"\n"
	"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"\\\"北京\\\"}\"}}]}}]}\n"
	"\n"
	"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n"
	"\n"
	"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":42,\"completion_tokens\":7,\"prompt_cache_hit_tokens\":10}}\n"
	"\n"
	"data: [DONE]\n"
	"\n";

static const char WANT_NORMAL[] =
	"{\"text\":\"Hello, world\",\"reasoning\":\"thinking...\","
	"\"tool_calls\":[{\"idx\":0,\"id\":\"call_1\",\"name\":\"get_weather\","
	"\"arguments\":\"{\\\"city\\\":\\\"北京\\\"}\"}],"
	"\"usage\":{\"present\":1,\"input\":42,\"output\":7,\"cache_read\":10,\"cache_write\":0},"
	"\"finish\":\"tool-calls\",\"done\":1,\"done_src\":\"sentinel\",\"errors\":[]}";

static char *run_feed(const char *fx, size_t len, size_t chunk, size_t *outlen)
{
	occ_norm *n = occ_norm_new();
	occ_sse *s = occ_sse_new(OCC_PROTO_OPENAI_COMPAT, occ_norm_event, n);
	char *out;
	size_t off = 0;

	while (off < len) {
		size_t take = (chunk && len - off > chunk) ? chunk : len - off;

		occ_sse_feed(s, fx + off, take);
		off += take;
	}
	occ_sse_finish(s);
	out = occ_norm_dump(n, outlen);
	occ_sse_free(s);
	occ_norm_free(n);
	return out;
}

int main(void)
{
	char *out;
	size_t len = strlen(FX_NORMAL);

	/* 1) 整段一次喂入 */
	out = run_feed(FX_NORMAL, len, 0, NULL);
	CHECK(out && !strcmp(out, WANT_NORMAL), "normal stream golden normalized");
	if (out && strcmp(out, WANT_NORMAL))
		printf("  got:  %s\n", out);
	free(out);

	/* 2) 逐字节喂入（切分等价） */
	out = run_feed(FX_NORMAL, len, 1, NULL);
	CHECK(out && !strcmp(out, WANT_NORMAL), "byte-by-byte feed identical");
	free(out);

	/* 3) 7 字节块喂入 */
	out = run_feed(FX_NORMAL, len, 7, NULL);
	CHECK(out && !strcmp(out, WANT_NORMAL), "7-byte chunk feed identical");
	free(out);

	/* 4) 坏 JSON 块：报错且中止（后续块不再交付） */
	{
		const char fx[] =
			"data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n"
			"\n"
			"data: {\"choices\":[{\"delta\":{\"content\":\"BROK\n"
			"\n"
			"data: {\"choices\":[{\"delta\":{\"content\":\"after-bad\"}}]}\n"
			"\n";
		occ_norm *n = occ_norm_new();
		occ_sse *s = occ_sse_new(OCC_PROTO_OPENAI_COMPAT, occ_norm_event, n);

		occ_sse_feed(s, fx, strlen(fx));
		occ_sse_finish(s);
		out = occ_norm_dump(n, NULL);
		CHECK(out && strstr(out, "\"text\":\"ok\""), "bad json: text before bad block kept");
		CHECK(out && strstr(out, "after-bad") == NULL, "bad json: post-fatal data not delivered");
		CHECK(out && strstr(out, "\"done\":0"), "bad json: fatal -> no DONE");
		CHECK(out && strstr(out, "bad json block"), "bad json: error reported");
		free(out);
		occ_sse_free(s);
		occ_norm_free(n);
	}

	/* 5) EOF 截断：未终结块检出（有意差异：opencode 静默丢弃） */
	{
		const char fx[] =
			"data: {\"choices\":[{\"delta\":{\"content\":\"cut\"";

		out = run_feed(fx, strlen(fx), 0, NULL);
		CHECK(out && strstr(out, "truncated final SSE block"), "truncated block detected");
		CHECK(out && strstr(out, "\"done\":1"), "truncated: EOF DONE still emitted");
		free(out);
	}

	/* 6) [DONE] 后再收到数据 → 检出 */
	{
		const char fx[] =
			"data: {\"choices\":[{\"delta\":{\"content\":\"A\"}}]}\n"
			"\n"
			"data: [DONE]\n"
			"\n"
			"data: {\"choices\":[{\"delta\":{\"content\":\"sneak\"}}]}\n"
			"\n";

		out = run_feed(fx, strlen(fx), 0, NULL);
		CHECK(out && strstr(out, "\"text\":\"A\""), "after-DONE: prior text kept");
		CHECK(out && strstr(out, "sneak") == NULL, "after-DONE: payload not delivered");
		CHECK(out && strstr(out, "data after stream end"), "after-DONE: detected");
		free(out);
	}

	/* 7) finish 后工具增量 → 检出（openai-chat.ts:1138-1146） */
	{
		const char fx[] =
			"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n"
			"\n"
			"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"x\",\"function\":{\"name\":\"f\",\"arguments\":\"{}\"}}]}}]}\n"
			"\n";

		out = run_feed(fx, strlen(fx), 0, NULL);
		CHECK(out && strstr(out, "content after the finish reason"),
		      "tool delta after finish detected");
		free(out);
	}

	/* 8) choice.usage（Moonshot 风格）也能取到 */
	{
		const char fx[] =
			"data: {\"choices\":[{\"delta\":{},\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":1}}]}\n"
			"\n";

		out = run_feed(fx, strlen(fx), 0, NULL);
		CHECK(out && strstr(out, "\"input\":5") && strstr(out, "\"output\":1"),
		      "choice-level usage mapped");
		free(out);
	}

	/* 9) usage 字段级合并（后块只带 completion_tokens） */
	{
		const char fx[] =
			"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9}}\n"
			"\n"
			"data: {\"choices\":[],\"usage\":{\"completion_tokens\":4}}\n"
			"\n"
			"data: [DONE]\n"
			"\n";

		out = run_feed(fx, strlen(fx), 0, NULL);
		CHECK(out && strstr(out, "\"input\":9") && strstr(out, "\"output\":4"),
		      "usage field-merge across chunks");
		free(out);
	}

	if (fails) {
		printf("test_sse_openai: %d FAIL(s)\n", fails);
		return 1;
	}
	printf("test_sse_openai: all ok\n");
	return 0;
}
