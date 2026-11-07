
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_reqbuild.c - 差分台架驱动：冻结组 JSON → occ 请求构造字节
 * 用法: occ_reqbuild <openai|anthropic> [model]
 * stdin: 组 JSON（parity/vectors/occ/inputs.json 的单组对象）
 * stdout: 请求体原字节（无换行）；exit 0
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>

#include "../occ_llm/occ_llm.h"
#include "store/store_json.h"

static char *read_all(FILE *f, size_t *outlen)
{
	size_t cap = 4096, len = 0;
	char *buf = malloc(cap);

	while (buf) {
		size_t n;

		if (len == cap) {
			char *nb;

			cap *= 2;
			nb = realloc(buf, cap);
			if (!nb) {
				free(buf);
				return NULL;
			}
			buf = nb;
		}
		n = fread(buf + len, 1, cap - len, f);
		len += n;
		if (n == 0)
			break;
	}
	if (buf)
		buf[len] = '\0';
	if (outlen)
		*outlen = len;
	return buf;
}

static char *dup_str_field(const aik_json *o, const char *key)
{
	const aik_json *v = aik_json_get(o, key);
	const char *s;
	char *out;

	if (!v || aik_json_typeof(v) != AIK_JSON_STR)
		return NULL;
	s = aik_json_str(v);
	out = strdup(s);
	return out;
}

int main(int argc, char **argv)
{
	occ_llm_req req;
	occ_msg *msgs = NULL;
	occ_tool_def *tools = NULL;
	size_t i, nmsg = 0, ntool = 0;
	char *txt;
	size_t txtlen;
	aik_json *root;
	char err[96];
	const char *model_arg;
	char *model = NULL;
	char *out;

	if (argc < 2 ||
	    (strcmp(argv[1], "openai") && strcmp(argv[1], "anthropic"))) {
		fprintf(stderr, "usage: occ_reqbuild <openai|anthropic> [model] < group.json\n");
		return 2;
	}
	memset(&req, 0, sizeof(req));
	req.proto = !strcmp(argv[1], "openai") ?
		OCC_PROTO_OPENAI_COMPAT : OCC_PROTO_ANTHROPIC;
	model_arg = argc > 2 ? argv[2] : NULL;

	txt = read_all(stdin, &txtlen);
	if (!txt) {
		fprintf(stderr, "occ_reqbuild: read stdin failed\n");
		return 2;
	}
	root = aik_json_parse(txt, txtlen, err, sizeof(err));
	if (!root) {
		fprintf(stderr, "occ_reqbuild: bad group json: %s\n", err);
		free(txt);
		return 2;
	}
	free(txt);

	if (model_arg) {
		model = strdup(model_arg);
	} else {
		model = dup_str_field(root, "model");
	}
	req.model = model ? model : "";
	req.system = dup_str_field(root, "system");

	{
		const aik_json *arr = aik_json_get(root, "messages");

		if (arr && aik_json_typeof(arr) == AIK_JSON_ARR)
			nmsg = aik_json_count(arr);
	}
	msgs = calloc(nmsg ? nmsg : 1, sizeof(*msgs));
	for (i = 0; i < nmsg; i++) {
		const aik_json *m = aik_json_at(aik_json_get(root, "messages"), i);
		const char *role = NULL;
		const aik_json *rv = aik_json_get(m, "role");

		if (rv && aik_json_typeof(rv) == AIK_JSON_STR)
			role = aik_json_str(rv);
		msgs[i].text = dup_str_field(m, "text");
		msgs[i].reasoning = dup_str_field(m, "reasoning");
		msgs[i].tool_call_id = dup_str_field(m, "tool_call_id");
		if (role && !strcmp(role, "assistant")) {
			msgs[i].role = OCC_ROLE_ASSISTANT;
			{
				const aik_json *tc = aik_json_get(m, "tool_calls");
				size_t k, ntc = 0;

				if (tc && aik_json_typeof(tc) == AIK_JSON_ARR)
					ntc = aik_json_count(tc);
				if (ntc) {
					occ_tool_call *cs = calloc(ntc, sizeof(*cs));

					for (k = 0; k < ntc; k++) {
						const aik_json *c = aik_json_at(tc, k);

						cs[k].id = dup_str_field(c, "id");
						cs[k].name = dup_str_field(c, "name");
						cs[k].arguments = dup_str_field(c, "arguments");
					}
					msgs[i].calls = cs;
					msgs[i].ncalls = ntc;
				}
			}
		} else if (role && !strcmp(role, "tool")) {
			msgs[i].role = OCC_ROLE_TOOL;
		} else {
			msgs[i].role = OCC_ROLE_USER;
		}
	}
	req.msgs = msgs;
	req.nmsgs = nmsg;

	{
		const aik_json *arr = aik_json_get(root, "tools");

		if (arr && aik_json_typeof(arr) == AIK_JSON_ARR)
			ntool = aik_json_count(arr);
	}
	tools = calloc(ntool ? ntool : 1, sizeof(*tools));
	for (i = 0; i < ntool; i++) {
		const aik_json *t = aik_json_at(aik_json_get(root, "tools"), i);
		const aik_json *params = aik_json_get(t, "parameters");
		char *pdump = NULL;
		size_t pdump_len;

		tools[i].name = dup_str_field(t, "name");
		tools[i].description = dup_str_field(t, "description");
		if (params && aik_json_dump(params, &pdump, &pdump_len) == 0)
			tools[i].parameters = pdump;
	}
	req.tools = tools;
	req.ntools = ntool;

	{
		const aik_json *g = aik_json_get(root, "generation");
		const aik_json *v;

		if (g && aik_json_typeof(g) == AIK_JSON_OBJ) {
			v = aik_json_get(g, "max_tokens");
			if (v && (aik_json_typeof(v) == AIK_JSON_INT ||
				  aik_json_typeof(v) == AIK_JSON_NUM)) {
				req.gen.has_max_tokens = 1;
				req.gen.max_tokens = aik_json_int(v);
			}
			v = aik_json_get(g, "temperature");
			if (v && aik_json_typeof(v) == AIK_JSON_NUM) {
				req.gen.has_temperature = 1;
				req.gen.temperature = aik_json_num(v);
			}
		}
	}
	{
		const aik_json *v = aik_json_get(root, "parallel_tool_calls");

		if (v && aik_json_typeof(v) == AIK_JSON_BOOL && aik_json_bool(v))
			req.parallel_tool_calls = 1;
	}

	/* requireReasoning：model 含 deepseek（与 recorder.py 参考构造器同规则；
	 * URL 条件在库层 occ_llm_call，驱动侧只有 model） */
	{
		const char *mp;
		int hit = 0;

		for (mp = req.model; mp && *mp; mp++)
			if (!strncasecmp(mp, "deepseek", 8)) {
				hit = 1;
				break;
			}
		req.require_reasoning = hit;
	}
	out = occ_build_request(&req, NULL);
	if (!out) {
		fprintf(stderr, "occ_reqbuild: build failed\n");
		return 1;
	}
	fputs(out, stdout);
	free(out);

	/* 释放 */
	for (i = 0; i < nmsg; i++) {
		size_t k;

		free((void *)msgs[i].text);
		free((void *)msgs[i].reasoning);
		free((void *)msgs[i].tool_call_id);
		for (k = 0; k < msgs[i].ncalls; k++) {
			free((void *)msgs[i].calls[k].id);
			free((void *)msgs[i].calls[k].name);
			free((void *)msgs[i].calls[k].arguments);
		}
		free((void *)msgs[i].calls);
	}
	free(msgs);
	for (i = 0; i < ntool; i++) {
		free((void *)tools[i].name);
		free((void *)tools[i].description);
		free((void *)tools[i].parameters);
	}
	free(tools);
	free((void *)req.system);
	free(model);
	aik_json_free(root);
	return 0;
}
