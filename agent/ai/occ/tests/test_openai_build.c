/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_openai_build.c - OpenAI 兼容请求构造单测（T9a1）
 * 逐字节 golden 断言 + aik_json 逐字段走查（体序对齐 openai-chat.ts:901-925）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../occ_llm/occ_llm.h"
#include "store/store_json.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

static void check_bytes(const char *got, const char *want, const char *msg)
{
	if (strcmp(got, want)) {
		printf("FAIL: %s\n  got:  %s\n  want: %s\n", msg, got, want);
		fails++;
	} else {
		printf("ok: %s\n", msg);
	}
}

static const char *js(const aik_json *v)
{
	return (v && aik_json_typeof(v) == AIK_JSON_STR) ? aik_json_str(v) : "";
}

int main(void)
{
	char *b;
	aik_json *root;
	char err[96];

	/* ---- A: system + user、无 tools（tools 键整体省略） ---- */
	{
		occ_llm_req r;
		occ_msg msgs[1];

		memset(&r, 0, sizeof(r));
		memset(msgs, 0, sizeof(msgs));
		r.proto = OCC_PROTO_OPENAI_COMPAT;
		r.model = "deepseek-flash";
		r.system = "You are helpful.";
		msgs[0].role = OCC_ROLE_USER;
		msgs[0].text = "Hi";
		r.msgs = msgs;
		r.nmsgs = 1;
		r.gen.has_max_tokens = 1;
		r.gen.max_tokens = 256;
		b = occ_build_request(&r, NULL);
		check_bytes(b,
			"{\"model\":\"deepseek-flash\",\"messages\":["
			"{\"role\":\"system\",\"content\":\"You are helpful.\"},"
			"{\"role\":\"user\",\"content\":\"Hi\"}],"
			"\"stream\":true,"
			"\"stream_options\":{\"include_usage\":true},"
			"\"max_tokens\":256}",
			"A golden bytes (no tools key)");
		root = aik_json_parse(b, strlen(b), err, sizeof(err));
		CHECK(!!root, "A parses");
		CHECK(!strcmp(js(aik_json_get(root, "model")), "deepseek-flash"),
		      "A field model");
		CHECK(aik_json_count(aik_json_get(root, "messages")) == 2,
		      "A messages len (system inline first)");
		CHECK(!strcmp(js(aik_json_get(aik_json_at(aik_json_get(root, "messages"), 0), "role")),
			      "system"), "A msg0 role=system");
		CHECK(!strcmp(js(aik_json_get(aik_json_at(aik_json_get(root, "messages"), 1), "content")),
			      "Hi"), "A msg1 content");
		CHECK(aik_json_get(root, "tools") == NULL, "A tools omitted");
		CHECK(aik_json_bool(aik_json_get(root, "stream")) == 1, "A stream true");
		CHECK(aik_json_bool(aik_json_get(aik_json_get(root,
			"stream_options"), "include_usage")) == 1,
			"A stream_options.include_usage");
		CHECK(aik_json_int(aik_json_get(root, "max_tokens")) == 256, "A max_tokens");
		CHECK(aik_json_get(root, "temperature") == NULL, "A temperature omitted");
		aik_json_free(root);
		free(b);
	}

	/* ---- B: tools + assistant(tool_calls) + tool 结果回灌 ---- */
	{
		occ_llm_req r;
		occ_msg msgs[3];
		occ_tool_call calls[1];
		occ_tool_def tools[1];

		memset(&r, 0, sizeof(r));
		memset(msgs, 0, sizeof(msgs));
		memset(calls, 0, sizeof(calls));
		memset(tools, 0, sizeof(tools));
		r.proto = OCC_PROTO_OPENAI_COMPAT;
		r.model = "deepseek-flash";
		msgs[0].role = OCC_ROLE_USER;
		msgs[0].text = "What's the weather in Beijing?";
		msgs[1].role = OCC_ROLE_ASSISTANT;
		msgs[1].text = NULL;
		calls[0].id = "call_1";
		calls[0].name = "get_weather";
		calls[0].arguments = "{\"city\":\"北京\"}";
		msgs[1].calls = calls;
		msgs[1].ncalls = 1;
		msgs[2].role = OCC_ROLE_TOOL;
		msgs[2].tool_call_id = "call_1";
		msgs[2].text = "{\"temp\":20,\"unit\":\"C\"}";
		r.msgs = msgs;
		r.nmsgs = 3;
		tools[0].name = "get_weather";
		tools[0].description = "Get weather";
		tools[0].parameters = "{\"type\":\"object\",\"properties\":{\"city\":{\"type\":\"string\"}},\"required\":[\"city\"]}";
		r.tools = tools;
		r.ntools = 1;
		r.gen.has_max_tokens = 1;
		r.gen.max_tokens = 200;
		b = occ_build_request_openai(&r, NULL);
		check_bytes(b,
			"{\"model\":\"deepseek-flash\",\"messages\":["
			"{\"role\":\"user\",\"content\":\"What's the weather in Beijing?\"},"
			"{\"role\":\"assistant\",\"content\":null,\"tool_calls\":["
			"{\"id\":\"call_1\",\"type\":\"function\",\"function\":"
			"{\"name\":\"get_weather\",\"arguments\":\"{\\\"city\\\":\\\"北京\\\"}\"}}]},"
			"{\"role\":\"tool\",\"tool_call_id\":\"call_1\",\"content\":\"{\\\"temp\\\":20,\\\"unit\\\":\\\"C\\\"}\"}],"
			"\"tools\":[{\"type\":\"function\",\"function\":"
			"{\"name\":\"get_weather\",\"description\":\"Get weather\","
			"\"parameters\":{\"type\":\"object\",\"properties\":"
			"{\"city\":{\"type\":\"string\"}},\"required\":[\"city\"]},"
			"\"strict\":false}}],"
			"\"stream\":true,"
			"\"stream_options\":{\"include_usage\":true},"
			"\"max_tokens\":200}",
			"B golden bytes (tools + history)");
		root = aik_json_parse(b, strlen(b), err, sizeof(err));
		CHECK(!!root, "B parses");
		{
			const aik_json *ms = aik_json_get(root, "messages");
			const aik_json *a = aik_json_at(ms, 1);
			const aik_json *tcs = aik_json_get(a, "tool_calls");
			const aik_json *tc0 = aik_json_at(tcs, 0);
			const aik_json *tl = aik_json_at(aik_json_get(root, "tools"), 0);
			const aik_json *fn = aik_json_get(tl, "function");

			CHECK(aik_json_typeof(aik_json_get(a, "content")) == AIK_JSON_NULL,
			      "B assistant content null");
			CHECK(!strcmp(js(aik_json_get(tc0, "id")), "call_1"), "B tc id");
			CHECK(!strcmp(js(aik_json_get(aik_json_get(tc0, "function"), "name")),
				      "get_weather"), "B tc name");
			CHECK(!strcmp(js(aik_json_get(aik_json_get(tc0, "function"), "arguments")),
				      "{\"city\":\"北京\"}"), "B tc arguments raw JSON text");
			CHECK(!strcmp(js(aik_json_get(tl, "type")), "function"), "B tool type");
			CHECK(!strcmp(js(aik_json_get(fn, "name")), "get_weather"), "B fn name");
			CHECK(!strcmp(js(aik_json_get(fn, "description")), "Get weather"), "B fn description");
			CHECK(aik_json_count(aik_json_get(fn, "parameters")) == 3, "B fn parameters keys");
			CHECK(aik_json_bool(aik_json_get(fn, "strict")) == 0, "B fn strict false");
			CHECK(!strcmp(js(aik_json_get(aik_json_at(ms, 2), "tool_call_id")),
				      "call_1"), "B tool result tool_call_id");
		}
		aik_json_free(root);
		free(b);
	}

	/* ---- C: 工具历史无活跃工具 → tools:[]（openai-chat.ts:903-906） ---- */
	{
		occ_llm_req r;
		occ_msg msgs[2];
		occ_tool_call calls[1];

		memset(&r, 0, sizeof(r));
		memset(msgs, 0, sizeof(msgs));
		memset(calls, 0, sizeof(calls));
		r.proto = OCC_PROTO_OPENAI_COMPAT;
		r.model = "m";
		msgs[0].role = OCC_ROLE_ASSISTANT;
		calls[0].id = "c1";
		calls[0].name = "t";
		calls[0].arguments = "{}";
		msgs[0].calls = calls;
		msgs[0].ncalls = 1;
		msgs[1].role = OCC_ROLE_TOOL;
		msgs[1].tool_call_id = "c1";
		msgs[1].text = "ok";
		r.msgs = msgs;
		r.nmsgs = 2;
		b = occ_build_request_openai(&r, NULL);
		check_bytes(b,
			"{\"model\":\"m\",\"messages\":["
			"{\"role\":\"assistant\",\"content\":null,\"tool_calls\":["
			"{\"id\":\"c1\",\"type\":\"function\",\"function\":"
			"{\"name\":\"t\",\"arguments\":\"{}\"}}]},"
			"{\"role\":\"tool\",\"tool_call_id\":\"c1\",\"content\":\"ok\"}],"
			"\"tools\":[],\"stream\":true,"
			"\"stream_options\":{\"include_usage\":true}}",
			"C golden bytes (tools:[] with history, no active tools)");
		root = aik_json_parse(b, strlen(b), err, sizeof(err));
		CHECK(aik_json_count(aik_json_get(root, "tools")) == 0, "C tools empty array");
		aik_json_free(root);
		free(b);
	}

	/* ---- D: temperature + parallel_tool_calls（末位）+ 无 description ---- */
	{
		occ_llm_req r;
		occ_msg msgs[1];
		occ_tool_def tools[1];

		memset(&r, 0, sizeof(r));
		memset(msgs, 0, sizeof(msgs));
		memset(tools, 0, sizeof(tools));
		r.proto = OCC_PROTO_OPENAI_COMPAT;
		r.model = "m";
		msgs[0].role = OCC_ROLE_USER;
		msgs[0].text = "go";
		r.msgs = msgs;
		r.nmsgs = 1;
		tools[0].name = "echo";
		tools[0].description = NULL;
		tools[0].parameters = "{\"type\":\"object\"}";
		r.tools = tools;
		r.ntools = 1;
		r.gen.has_temperature = 1;
		r.gen.temperature = 0.2;
		r.parallel_tool_calls = 1;
		b = occ_build_request_openai(&r, NULL);
		check_bytes(b,
			"{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":\"go\"}],"
			"\"tools\":[{\"type\":\"function\",\"function\":"
			"{\"name\":\"echo\",\"parameters\":{\"type\":\"object\"},\"strict\":false}}],"
			"\"stream\":true,\"stream_options\":{\"include_usage\":true},"
			"\"temperature\":0.2,\"parallel_tool_calls\":true}",
			"D golden bytes (temp + parallel_tool_calls last, no description)");
		root = aik_json_parse(b, strlen(b), err, sizeof(err));
		CHECK(aik_json_get(aik_json_get(aik_json_at(aik_json_get(root, "tools"), 0),
			"function"), "description") == NULL, "D description omitted");
		CHECK(aik_json_num(aik_json_get(root, "temperature")) == 0.2, "D temperature num");
		CHECK(aik_json_bool(aik_json_get(root, "parallel_tool_calls")) == 1, "D parallel true");
		CHECK(aik_json_get(root, "max_tokens") == NULL, "D max_tokens omitted");
		aik_json_free(root);
		free(b);
	}

	/* ---- E: 转义压力（引号/反斜杠/换行/控制字符/中文+emoji） ---- */
	{
		occ_llm_req r;
		occ_msg msgs[1];

		memset(&r, 0, sizeof(r));
		memset(msgs, 0, sizeof(msgs));
		r.proto = OCC_PROTO_OPENAI_COMPAT;
		r.model = "m";
		msgs[0].role = OCC_ROLE_USER;
		msgs[0].text = "line1\nline2 \"quoted\" back\\slash \t tab 你好 \xF0\x9F\x98\x80";
		r.msgs = msgs;
		r.nmsgs = 1;
		b = occ_build_request_openai(&r, NULL);
		check_bytes(b,
			"{\"model\":\"m\",\"messages\":[{\"role\":\"user\",\"content\":"
			"\"line1\\nline2 \\\"quoted\\\" back\\\\slash \\t tab 你好 \xF0\x9F\x98\x80\"}],"
			"\"stream\":true,\"stream_options\":{\"include_usage\":true}}",
			"E golden bytes (escaping stress, ensure_ascii=False)");
		free(b);
	}

	/* ---- R: requireReasoning（deepseek 系）assistant 回放带后置
	 * reasoning_content（openai-chat.ts:529-570/:662-672；真 400 实证：
	 * 差分向量 g07_tool_result 首录） ---- */
	{
		occ_llm_req r;
		occ_msg msgs[2];
		occ_tool_call calls[1];

		memset(&r, 0, sizeof(r));
		memset(msgs, 0, sizeof(msgs));
		memset(calls, 0, sizeof(calls));
		r.proto = OCC_PROTO_OPENAI_COMPAT;
		r.model = "deepseek-flash";
		msgs[0].role = OCC_ROLE_ASSISTANT;
		msgs[0].reasoning = "先查天气";
		calls[0].id = "call_1";
		calls[0].name = "get_weather";
		calls[0].arguments = "{}";
		msgs[0].calls = calls;
		msgs[0].ncalls = 1;
		msgs[1].role = OCC_ROLE_TOOL;
		msgs[1].tool_call_id = "call_1";
		msgs[1].text = "ok";
		r.msgs = msgs;
		r.nmsgs = 2;
		r.require_reasoning = 1;
		b = occ_build_request_openai(&r, NULL);
		check_bytes(b,
			"{\"model\":\"deepseek-flash\",\"messages\":["
			"{\"role\":\"assistant\",\"content\":null,\"tool_calls\":["
			"{\"id\":\"call_1\",\"type\":\"function\",\"function\":"
			"{\"name\":\"get_weather\",\"arguments\":\"{}\"}}],"
			"\"reasoning_content\":\"先查天气\"},"
			"{\"role\":\"tool\",\"tool_call_id\":\"call_1\",\"content\":\"ok\"}],"
			"\"tools\":[],\"stream\":true,"
			"\"stream_options\":{\"include_usage\":true}}",
			"R golden bytes (require_reasoning, replayed reasoning)");
		msgs[0].reasoning = NULL;
		free(b);
		b = occ_build_request_openai(&r, NULL);
		CHECK(b && strstr(b, "reasoning_content"),
		      "R no-reasoning part -> empty string present");
		r.require_reasoning = 0;
		free(b);
		b = occ_build_request_openai(&r, NULL);
		CHECK(b && !strstr(b, "reasoning_content"),
		      "R flag off -> key omitted");
		free(b);
	}

	if (fails) {
		printf("test_openai_build: %d FAIL(s)\n", fails);
		return 1;
	}
	printf("test_openai_build: all ok\n");
	return 0;
}
