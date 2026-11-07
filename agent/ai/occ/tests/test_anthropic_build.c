/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_anthropic_build.c - Anthropic Messages 请求构造单测（T9a1）
 * 逐字节 golden + 逐字段走查（体序对齐 anthropic-messages.ts:1108-1129）。
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
	size_t dummy;

	/* ---- F: system 块数组 + 默认 max_tokens=32000 + 无 tools 键 ---- */
	{
		occ_llm_req r;
		occ_msg msgs[1];

		memset(&r, 0, sizeof(r));
		memset(msgs, 0, sizeof(msgs));
		r.proto = OCC_PROTO_ANTHROPIC;
		r.model = "claude-sonnet-4-5";
		r.system = "You are helpful.";
		msgs[0].role = OCC_ROLE_USER;
		msgs[0].text = "Hi";
		r.msgs = msgs;
		r.nmsgs = 1;
		b = occ_build_request_anthropic(&r, NULL);
		check_bytes(b,
			"{\"model\":\"claude-sonnet-4-5\","
			"\"system\":[{\"type\":\"text\",\"text\":\"You are helpful.\"}],"
			"\"messages\":[{\"role\":\"user\",\"content\":"
			"[{\"type\":\"text\",\"text\":\"Hi\"}]}],"
			"\"stream\":true,\"max_tokens\":32000}",
			"F golden bytes (system array, default max_tokens)");
		root = aik_json_parse(b, strlen(b), err, sizeof(err));
		CHECK(!!root, "F parses");
		CHECK(aik_json_count(aik_json_get(root, "system")) == 1, "F system 1 block");
		CHECK(!strcmp(js(aik_json_get(aik_json_at(aik_json_get(root, "system"), 0), "text")),
			      "You are helpful."), "F system text");
		CHECK(aik_json_get(root, "tools") == NULL, "F tools omitted (no tools)");
		CHECK(aik_json_int(aik_json_get(root, "max_tokens")) == 32000, "F default max_tokens");
		CHECK(aik_json_bool(aik_json_get(root, "stream")) == 1, "F stream true");
		CHECK(aik_json_get(root, "temperature") == NULL, "F temperature omitted");
		aik_json_free(root);
		free(b);
	}

	/* ---- G: tools + tool_use id 清洗 + 连续 tool_result 并轮 + gen ---- */
	{
		occ_llm_req r;
		occ_msg msgs[4];
		occ_tool_call calls[2];
		occ_tool_def tools[1];

		memset(&r, 0, sizeof(r));
		memset(msgs, 0, sizeof(msgs));
		memset(calls, 0, sizeof(calls));
		memset(tools, 0, sizeof(tools));
		r.proto = OCC_PROTO_ANTHROPIC;
		r.model = "claude-sonnet-4-5";
		msgs[0].role = OCC_ROLE_USER;
		msgs[0].text = "weather?";
		msgs[1].role = OCC_ROLE_ASSISTANT;
		msgs[1].text = "Checking";
		calls[0].id = "tool/call!1";
		calls[0].name = "get_weather";
		calls[0].arguments = "{\"city\":\"北京\"}";
		msgs[1].calls = calls;
		msgs[1].ncalls = 1;
		msgs[2].role = OCC_ROLE_TOOL;
		msgs[2].tool_call_id = "tool/call!1";
		msgs[2].text = "20C";
		msgs[3].role = OCC_ROLE_TOOL;
		msgs[3].tool_call_id = "tool/call!2";
		msgs[3].text = "ok";
		r.msgs = msgs;
		r.nmsgs = 4;
		tools[0].name = "get_weather";
		tools[0].description = "Get weather";
		tools[0].parameters = "{\"type\":\"object\",\"properties\":{\"city\":{\"type\":\"string\"}}}";
		r.tools = tools;
		r.ntools = 1;
		r.gen.has_max_tokens = 1;
		r.gen.max_tokens = 100;
		r.gen.has_temperature = 1;
		r.gen.temperature = 0.5;
		b = occ_build_request_anthropic(&r, NULL);
		check_bytes(b,
			"{\"model\":\"claude-sonnet-4-5\","
			"\"messages\":["
			"{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"weather?\"}]},"
			"{\"role\":\"assistant\",\"content\":["
			"{\"type\":\"text\",\"text\":\"Checking\"},"
			"{\"type\":\"tool_use\",\"id\":\"tool_call_1\",\"name\":\"get_weather\","
			"\"input\":{\"city\":\"北京\"}}]},"
			"{\"role\":\"user\",\"content\":["
			"{\"type\":\"tool_result\",\"tool_use_id\":\"tool_call_1\",\"content\":\"20C\"},"
			"{\"type\":\"tool_result\",\"tool_use_id\":\"tool_call_2\",\"content\":\"ok\"}]}],"
			"\"tools\":[{\"name\":\"get_weather\",\"description\":\"Get weather\","
			"\"input_schema\":{\"type\":\"object\",\"properties\":"
			"{\"city\":{\"type\":\"string\"}}}}],"
			"\"stream\":true,\"max_tokens\":100,\"temperature\":0.5}",
			"G golden bytes (id scrub, tool_result merge, tools before stream)");
		root = aik_json_parse(b, strlen(b), err, sizeof(err));
		CHECK(!!root, "G parses");
		{
			const aik_json *ms = aik_json_get(root, "messages");
			const aik_json *m2 = aik_json_at(ms, 2);
			const aik_json *c2 = aik_json_get(m2, "content");

			CHECK(aik_json_count(ms) == 3, "G 2 tool msgs merged into 1 user turn");
			CHECK(aik_json_count(c2) == 2, "G merged turn has 2 tool_result blocks");
			CHECK(!strcmp(js(aik_json_get(aik_json_at(c2, 0), "tool_use_id")),
				      "tool_call_1"), "G tool_use_id scrubbed");
			CHECK(!strcmp(js(aik_json_get(aik_json_at(aik_json_get(root,
				"tools"), 0), "name")), "get_weather"), "G tool name");
			{
				char *sd = NULL;

				aik_json_dump(aik_json_get(aik_json_at(aik_json_get(root,
					"tools"), 0), "input_schema"), &sd, &dummy);
				CHECK(sd && !strcmp(sd,
					"{\"type\":\"object\",\"properties\":{\"city\":{\"type\":\"string\"}}}"),
					"G input_schema raw");
				free(sd);
			}
			CHECK(aik_json_int(aik_json_get(root, "max_tokens")) == 100, "G max_tokens");
			CHECK(aik_json_num(aik_json_get(root, "temperature")) == 0.5, "G temperature");
		}
		aik_json_free(root);
		free(b);
	}

	/* ---- H: 空白文本跳过；空 arguments → input:{}；无 system 键 ---- */
	{
		occ_llm_req r;
		occ_msg msgs[3];
		occ_tool_call calls[1];

		memset(&r, 0, sizeof(r));
		memset(msgs, 0, sizeof(msgs));
		memset(calls, 0, sizeof(calls));
		r.proto = OCC_PROTO_ANTHROPIC;
		r.model = "m";
		msgs[0].role = OCC_ROLE_USER;
		msgs[0].text = "   ";
		msgs[1].role = OCC_ROLE_ASSISTANT;
		msgs[1].text = NULL;
		calls[0].id = "a b";
		calls[0].name = "t";
		calls[0].arguments = "";
		msgs[1].calls = calls;
		msgs[1].ncalls = 1;
		msgs[2].role = OCC_ROLE_USER;
		msgs[2].text = "next";
		r.msgs = msgs;
		r.nmsgs = 3;
		b = occ_build_request_anthropic(&r, NULL);
		check_bytes(b,
			"{\"model\":\"m\",\"messages\":["
			"{\"role\":\"assistant\",\"content\":["
			"{\"type\":\"tool_use\",\"id\":\"a_b\",\"name\":\"t\",\"input\":{}}]},"
			"{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"next\"}]}],"
			"\"stream\":true,\"max_tokens\":32000}",
			"H golden bytes (blank user dropped, empty args -> {})");
		root = aik_json_parse(b, strlen(b), err, sizeof(err));
		CHECK(aik_json_count(aik_json_get(root, "messages")) == 2, "H blank user msg dropped");
		CHECK(aik_json_get(root, "system") == NULL, "H system omitted");
		CHECK(aik_json_count(aik_json_get(aik_json_at(
			aik_json_get(root, "messages"), 0), "content")) == 1,
			"H assistant only tool_use block");
		aik_json_free(root);
		free(b);
	}

	if (fails) {
		printf("test_anthropic_build: %d FAIL(s)\n", fails);
		return 1;
	}
	printf("test_anthropic_build: all ok\n");
	return 0;
}
