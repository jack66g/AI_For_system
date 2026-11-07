/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_provider.c - provider 最小注册表单测（T9a1）
 * 1) [models.cloud] 解析（临时 toml fixture，不触真实 ~/.aikernel/model.toml）
 * 2) provider_type → 协议映射（含未知 → -1）
 * 3) occ_chat_url 端点拼接
 */
#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../occ_llm/occ_provider.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

int main(void)
{
	char path[] = "/tmp/occ_test_model_XXXXXX";
	int fd = mkstemp(path);
	FILE *f;
	occ_provider p;
	char buf[512];

	CHECK(fd >= 0, "mkstemp fixture");
	f = fdopen(fd, "w");
	fprintf(f, "# test fixture\n");
	fprintf(f, "[default]\nmodel = \"x\"\n");
	fprintf(f, "[models.cloud]\n");
	fprintf(f, "provider_type = \"openai_compatible\"\n");
	fprintf(f, "model_name = \"deepseek-flash\"\n");
	fprintf(f, "base_url = \"https://api.deepseek.com/v1\"\n");
	fprintf(f, "api_key = \"sk-testonly-not-real\"\n");
	fprintf(f, "[ui]\n");
	fprintf(f, "color = true\n");
	fclose(f);

	memset(&p, 0, sizeof(p));
	CHECK(occ_provider_load_cloud(&p, path) == 0, "load_cloud ok");
	CHECK(p.proto == OCC_PROTO_OPENAI_COMPAT, "proto openai_compatible");
	CHECK(!strcmp(p.model, "deepseek-flash"), "model_name");
	CHECK(!strcmp(p.base_url, "https://api.deepseek.com/v1"), "base_url");
	CHECK(p.api_key && !strcmp(p.api_key, "sk-testonly-not-real"), "api_key in-memory");
	occ_provider_free(&p);
	CHECK(p.api_key == NULL, "provider_free clears key");

	/* 缺段 → -1 */
	unlink(path);
	fd = open(path, O_WRONLY | O_CREAT, 0600);
	if (fd >= 0) {
		ssize_t n = write(fd, "[local]\nenabled = false\n", 24);

		(void)n;
		close(fd);
	}
	memset(&p, 0, sizeof(p));
	CHECK(occ_provider_load_cloud(&p, path) == -1, "missing section -> -1");
	occ_provider_free(&p);
	unlink(path);

	/* 协议映射 */
	CHECK(occ_protocol_from_type("openai_compatible") == OCC_PROTO_OPENAI_COMPAT,
	      "map openai_compatible");
	CHECK(occ_protocol_from_type("anthropic") == OCC_PROTO_ANTHROPIC,
	      "map anthropic");
	CHECK((int)occ_protocol_from_type("gemini") == -1, "map unknown -> -1");
	CHECK((int)occ_protocol_from_type(NULL) == -1, "map NULL -> -1");
	CHECK(!strcmp(occ_protocol_name(OCC_PROTO_OPENAI_COMPAT), "openai_compatible"),
	      "protocol_name openai");
	CHECK(!strcmp(occ_protocol_name(OCC_PROTO_ANTHROPIC), "anthropic"),
	      "protocol_name anthropic");

	/* URL 拼接 */
	CHECK(occ_chat_url(buf, sizeof(buf), OCC_PROTO_OPENAI_COMPAT,
			   "https://api.deepseek.com/v1") == 0 &&
	      !strcmp(buf, "https://api.deepseek.com/v1/chat/completions"),
	      "url openai (no trailing slash)");
	CHECK(occ_chat_url(buf, sizeof(buf), OCC_PROTO_OPENAI_COMPAT,
			   "https://x.example/v1/") == 0 &&
	      !strcmp(buf, "https://x.example/v1/chat/completions"),
	      "url openai (trailing slash)");
	CHECK(occ_chat_url(buf, sizeof(buf), OCC_PROTO_ANTHROPIC,
			   "https://api.anthropic.com/v1") == 0 &&
	      !strcmp(buf, "https://api.anthropic.com/v1/messages"),
	      "url anthropic /messages");
	CHECK(occ_chat_url(buf, 8, OCC_PROTO_ANTHROPIC,
			   "https://api.anthropic.com/v1") == -1,
	      "url buffer too small -> -1");
	CHECK(occ_chat_url(buf, sizeof(buf), OCC_PROTO_OPENAI_COMPAT, "") == -1,
	      "url empty base -> -1");

	if (fails) {
		printf("test_provider: %d FAIL(s)\n", fails);
		return 1;
	}
	printf("test_provider: all ok\n");
	return 0;
}
