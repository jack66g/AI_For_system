/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_lang_tools.c - O-20 A3：工具定义面语档单测
 *
 * 真实 12 件 defs（OCC_ORCH_TOOLS+OCC_NETCFG_TOOLS=1 首用定型）：
 * zh=描述+schema 指针恒等（差分红线在定义面的同型保证）；en=12×2
 * 逐件全译（任一缺键露馅）+ openai/anthropic 两面请求体英文铁证。
 * L_ 消费点=occ_llm/openai.c+anthropic.c 序列化处（A3 包点本尊）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "occ_llm/occ_llm.h"
#include "occ_tools/occ_tools.h"
#include "occ_tui/tui_lang.h"
#include "store/store_json.h"

static int fails, checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

int main(void)
{
	occ_llm_req r;
	occ_msg msgs[1];
	const occ_tool_def *defs;
	char *b;
	size_t n = 0, i;
	int all_id = 1, all_tr = 1;

	setenv("OCC_ORCH_TOOLS", "1", 1);
	setenv("OCC_NETCFG_TOOLS", "1", 1);
	defs = occ_tool_defs(&n);
	CHECK(n == 12, "12 defs (9 base + netcfg/task/recall)");

	/* 1) zh 缺省：定义面指针恒等（L_ 返回入参本尊） */
	tui_lang_set_en(0);
	for (i = 0; i < n; i++) {
		if (L_(defs[i].description) != defs[i].description)
			all_id = 0;
		if (L_(defs[i].parameters) != defs[i].parameters)
			all_id = 0;
	}
	CHECK(all_id, "zh identity on all 12 defs (desc+schema)");

	/* 2) en：12×2 逐件全译（缺键=仍 zh=露馅） */
	tui_lang_set_en(1);
	for (i = 0; i < n; i++) {
		if (strcmp(L_(defs[i].description), defs[i].description) == 0)
			all_tr = 0;
		if (strcmp(L_(defs[i].parameters), defs[i].parameters) == 0)
			all_tr = 0;
	}
	CHECK(all_tr, "en translates all 12 defs (desc+schema)");
	CHECK(strstr(L_(defs[0].description), "Read file contents") != NULL,
	      "en read description");
	CHECK(strstr(L_(defs[0].parameters), "Absolute or relative") != NULL,
	      "en read schema");
	CHECK(strstr(L_(defs[9].parameters), "comma-separated") != NULL,
	      "en netcfg schema (defs[9])");

	/* 3) 双协议请求体：en 档工具定义整体英文、zh 定义面退场 */
	memset(&r, 0, sizeof(r));
	memset(msgs, 0, sizeof(msgs));
	msgs[0].role = OCC_ROLE_USER;
	msgs[0].text = "go";
	r.msgs = msgs;
	r.nmsgs = 1;
	r.model = "m";
	r.tools = defs;
	r.ntools = n;

	r.proto = OCC_PROTO_OPENAI_COMPAT;
	b = occ_build_request_openai(&r, NULL);
	CHECK(b && strstr(b, "Read file contents")
	      && strstr(b, "Absolute or relative")
	      && !strstr(b, "读取文件内容"),
	      "openai request carries en definitions");
	free(b);

	r.proto = OCC_PROTO_ANTHROPIC;
	b = occ_build_request_anthropic(&r, NULL);
	CHECK(b && strstr(b, "Read file contents")
	      && strstr(b, "Absolute or relative")
	      && !strstr(b, "读取文件内容"),
	      "anthropic request carries en definitions");
	free(b);

	/* 4) zh 档：原文定义面进请求（差分门零漂移的同型证据） */
	tui_lang_set_en(0);
	r.proto = OCC_PROTO_OPENAI_COMPAT;
	b = occ_build_request_openai(&r, NULL);
	CHECK(b && strstr(b, "读取文件内容")
	      && strstr(b, "文件绝对或相对"),
	      "openai request carries zh definitions verbatim");
	free(b);
	r.proto = OCC_PROTO_ANTHROPIC;
	b = occ_build_request_anthropic(&r, NULL);
	CHECK(b && strstr(b, "读取文件内容"),
	      "anthropic request carries zh definitions verbatim");
	free(b);

	printf("test_lang_tools: %d checks, %d failures\n", checks, fails);
	return fails ? 1 : 0;
}
