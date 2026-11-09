/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_sse_anthropic.c - Anthropic Messages SSE 消费单测（T9a1）
 * 覆盖：message_start、content_block_ 系列、message_delta、message_stop 全链 /
 * ping 忽略 / [DONE] 对 anthropic 默认丢弃 / usage 字段级合并（inclusive
 * input）/ thinking_delta → reasoning / 截断检出 / error 事件 / 逐字节切分。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "occ_llm/occ_llm.h"
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
	"event: message_start\n"
	"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":12,\"cache_read_input_tokens\":4}}}\n"
	"\n"
	"event: content_block_start\n"
	"data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n"
	"\n"
	"event: ping\n"
	"data: {\"type\":\"ping\"}\n"
	"\n"
	"event: content_block_delta\n"
	"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"先想想\"}}\n"
	"\n"
	"event: content_block_delta\n"
	"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"你好\"}}\n"
	"\n"
	"event: content_block_stop\n"
	"data: {\"type\":\"content_block_stop\",\"index\":0}\n"
	"\n"
	"event: content_block_start\n"
	"data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"get_weather\"}}\n"
	"\n"
	"event: content_block_delta\n"
	"data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\":\"}}\n"
	"\n"
	"event: content_block_delta\n"
	"data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"北京\\\"}\"}}\n"
	"\n"
	"event: content_block_stop\n"
	"data: {\"type\":\"content_block_stop\",\"index\":1}\n"
	"\n"
	"event: message_delta\n"
	"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":9}}\n"
	"\n"
	"event: message_stop\n"
	"data: {\"type\":\"message_stop\"}\n"
	"\n";

static const char WANT_NORMAL[] =
	"{\"text\":\"你好\",\"reasoning\":\"先想想\","
	"\"tool_calls\":[{\"idx\":1,\"id\":\"toolu_01\",\"name\":\"get_weather\","
	"\"arguments\":\"{\\\"city\\\":\\\"北京\\\"}\"}],"
	"\"usage\":{\"present\":1,\"input\":16,\"output\":9,\"cache_read\":4,\"cache_write\":0},"
	"\"finish\":\"tool-calls\",\"done\":1,\"done_src\":\"message_stop\",\"errors\":[]}";

static char *run_feed(const char *fx, size_t len, size_t chunk, size_t *outlen)
{
	occ_norm *n = occ_norm_new();
	occ_sse *s = occ_sse_new(OCC_PROTO_ANTHROPIC, occ_norm_event, n);
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

	out = run_feed(FX_NORMAL, len, 0, NULL);
	CHECK(out && !strcmp(out, WANT_NORMAL), "normal stream golden normalized");
	if (out && strcmp(out, WANT_NORMAL))
		printf("  got:  %s\n", out);
	free(out);

	out = run_feed(FX_NORMAL, len, 1, NULL);
	CHECK(out && !strcmp(out, WANT_NORMAL), "byte-by-byte feed identical");
	free(out);

	/* [DONE] 对 anthropic 丢弃（framing.ts 默认）+ message_stop 终结 */
	{
		const char fx[] =
			"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":3}}}\n"
			"\n"
			"data: [DONE]\n"
			"\n"
			"data: {\"type\":\"ping\"}\n"
			"\n"
			"data: {\"type\":\"message_stop\"}\n"
			"\n"
			"data: null\n"
			"\n";

		out = run_feed(fx, strlen(fx), 0, NULL);
		CHECK(out && strstr(out, "\"done\":1,\"done_src\":\"message_stop\""),
		      "anthropic drops [DONE]; message_stop terminates");
		CHECK(out && strstr(out, "\"errors\":[]"),
		      "no errors: [DONE] dropped, ping ignored, null-after-stop dropped");
		free(out);
	}

	/* EOF 无 message_stop → done_src=eof，且是合法终结（不算错误） */
	{
		const char fx[] =
			"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"x\"}}\n"
			"\n";

		out = run_feed(fx, strlen(fx), 0, NULL);
		CHECK(out && strstr(out, "\"done\":1,\"done_src\":\"eof\""),
		      "EOF without message_stop -> done_src=eof");
		CHECK(out && strstr(out, "\"errors\":[]"), "clean EOF no errors");
		free(out);
	}

	/* error 事件 → OCC_EV_ERROR */
	{
		const char fx[] =
			"data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n"
			"\n";

		out = run_feed(fx, strlen(fx), 0, NULL);
		CHECK(out && strstr(out, "Overloaded"), "error event surfaced");
		free(out);
	}

	/* 缺 type 字段的 data 块 → 检出 */
	{
		const char fx[] =
			"data: {\"foo\":1}\n"
			"\n";

		out = run_feed(fx, strlen(fx), 0, NULL);
		CHECK(out && strstr(out, "missing type"), "missing type detected");
		free(out);
	}

	/* 截断（未终结块）→ 检出 */
	{
		const char fx[] =
			"data: {\"type\":\"message_stop\"";

		out = run_feed(fx, strlen(fx), 0, NULL);
		CHECK(out && strstr(out, "truncated final SSE block"), "truncated detected");
		free(out);
	}

	/* stop_reason 映射：end_turn→stop；max_tokens→length */
	{
		const char fx[] =
			"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n"
			"\n"
			"data: {\"type\":\"message_stop\"}\n"
			"\n";

		out = run_feed(fx, strlen(fx), 0, NULL);
		CHECK(out && strstr(out, "\"finish\":\"stop\""), "end_turn -> stop");
		free(out);
	}
	{
		const char fx[] =
			"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"max_tokens\"}}\n"
			"\n"
			"data: {\"type\":\"message_stop\"}\n"
			"\n";

		out = run_feed(fx, strlen(fx), 0, NULL);
		CHECK(out && strstr(out, "\"finish\":\"length\""), "max_tokens -> length");
		free(out);
	}

	if (fails) {
		printf("test_sse_anthropic: %d FAIL(s)\n", fails);
		return 1;
	}
	printf("test_sse_anthropic: all ok\n");
	return 0;
}
