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

#include "occ_llm/occ_provider.h"

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

	/* ---- B3：direct 地址配置化 + conf 校验 + 人话报错 ---- */
	{
		char p2path[] = "/tmp/occ_test_model_b3_XXXXXX";
		int fd2 = mkstemp(p2path);
		occ_provider_config cfg;
		occ_provider rp;
		char err[256];

		CHECK(fd2 >= 0, "b3 mkstemp fixture");
		f = fdopen(fd2, "w");
		fprintf(f, "[models.cloud]\n");
		fprintf(f, "provider = \"deepseek\"\n");
		fprintf(f, "model_name = \"deepseek-chat\"\n");
		fprintf(f, "[models.directslot]\n");
		fprintf(f, "provider_type = \"openai_compatible\"\n");
		fprintf(f, "model_name = \"m2\"\n");
		fprintf(f, "base_url = \"http://127.0.0.1:9443\"\n");
		fprintf(f, "direct_base_url = \"https://api.deepseek.com/v1\"\n");
		fprintf(f, "[models.ovr]\n");
		fprintf(f, "provider = \"deepseek\"\n");
		fprintf(f, "direct_base_url = \"https://override.example/v1\"\n");
		fprintf(f, "[provider.deepseek]\n");
		fprintf(f, "type = \"openai_compatible\"\n");
		fprintf(f, "base_url = \"http://127.0.0.1:9443\"\n");
		fprintf(f, "direct_base_url = \"https://direct-from-provider/v1\"\n");
		fprintf(f, "key = \"sk-testonly-not-real\"\n");
		fclose(f);

		occ_provider_config_init(&cfg);
		CHECK(occ_provider_load_all(&cfg, p2path, NULL) == 0,
		      "b3 load_all ok");
		CHECK(cfg.nslots == 3 && cfg.nproviders == 1, "b3 sections");

		/* 引用式无槽位级 direct → 取 provider 段 direct */
		memset(&rp, 0, sizeof(rp));
		CHECK(occ_provider_resolve(&cfg, "cloud", &rp) == 0,
		      "b3 resolve cloud");
		CHECK(!strcmp(rp.direct_base_url,
			      "https://direct-from-provider/v1"),
		      "b3 direct from provider section");
		occ_provider_free(&rp);

		/* 直填式槽位级 direct */
		memset(&rp, 0, sizeof(rp));
		CHECK(occ_provider_resolve(&cfg, "directslot", &rp) == 0,
		      "b3 resolve directslot");
		CHECK(!strcmp(rp.direct_base_url,
			      "https://api.deepseek.com/v1"),
		      "b3 direct from slot");
		CHECK(!strcmp(rp.base_url, "http://127.0.0.1:9443"),
		      "b3 base_url proxy kept");
		occ_provider_free(&rp);

		/* 槽位级覆盖 provider 段 */
		memset(&rp, 0, sizeof(rp));
		CHECK(occ_provider_resolve(&cfg, "ovr", &rp) == 0,
		      "b3 resolve ovr");
		CHECK(!strcmp(rp.direct_base_url, "https://override.example/v1"),
		      "b3 slot direct overrides provider");
		occ_provider_free(&rp);

		/* 未配置 direct 的既有 L1 形态：direct 为空（loop 走旧缺省
		 * 判形——B3 兼容语义） */
		/* resolve_ex：人话报错面 */
		memset(&rp, 0, sizeof(rp));
		err[0] = '\0';
		CHECK(occ_provider_resolve_ex(&cfg, "nosuch", &rp, err,
					      sizeof(err)) == -1 &&
		      strstr(err, "models.nosuch") != NULL,
		      "b3 resolve_ex unknown slot human error");
		CHECK(occ_provider_resolve_ex(&cfg, "cloud", &rp, err,
					      sizeof(err)) == 0,
		      "b3 resolve_ex ok path");
		occ_provider_free(&rp);

		occ_provider_config_free(&cfg);
		unlink(p2path);
	}

	/* B3：occ_provider_validate_url 人话校验矩阵 */
	{
		char err[256];

		CHECK(occ_provider_validate_url("https://api.x.com/v1", err,
						sizeof(err)) == 0,
		      "b3 url valid https");
		CHECK(occ_provider_validate_url("http://127.0.0.1:9443", err,
						sizeof(err)) == 0,
		      "b3 url valid http loopback");
		CHECK(occ_provider_validate_url("ftp://x.example", err,
						sizeof(err)) == -1 &&
		      strstr(err, "http") != NULL,
		      "b3 url bad scheme human msg");
		CHECK(occ_provider_validate_url("https://", err,
						sizeof(err)) == -1 &&
		      strstr(err, "主机名") != NULL,
		      "b3 url empty host");
		CHECK(occ_provider_validate_url("https://a b.com", err,
						sizeof(err)) == -1 &&
		      strstr(err, "非法字符") != NULL,
		      "b3 url space rejected");
		CHECK(occ_provider_validate_url("https://x/\"q", err,
						sizeof(err)) == -1,
		      "b3 url quote rejected");
		CHECK(occ_provider_validate_url("", err, sizeof(err)) == -1,
		      "b3 url empty");
		CHECK(occ_provider_validate_url(NULL, err, sizeof(err)) == -1,
		      "b3 url NULL");
	}

	/* B3：坏 direct_base_url → resolve_ex 拒收（conf 校验门） */
	{
		char p3path[] = "/tmp/occ_test_model_b3b_XXXXXX";
		int fd3 = mkstemp(p3path);
		occ_provider_config cfg;
		occ_provider rp;
		char err[256];

		CHECK(fd3 >= 0, "b3b mkstemp fixture");
		f = fdopen(fd3, "w");
		fprintf(f, "[models.bad]\n");
		fprintf(f, "provider_type = \"openai_compatible\"\n");
		fprintf(f, "base_url = \"https://ok.example/v1\"\n");
		fprintf(f, "direct_base_url = \"not-a-url\"\n");
		fclose(f);
		occ_provider_config_init(&cfg);
		CHECK(occ_provider_load_all(&cfg, p3path, NULL) == 0,
		      "b3b load_all ok");
		memset(&rp, 0, sizeof(rp));
		err[0] = '\0';
		CHECK(occ_provider_resolve_ex(&cfg, "bad", &rp, err,
					      sizeof(err)) == -1 &&
		      strstr(err, "direct_base_url 非法") != NULL,
		      "b3b bad direct rejected with human msg");
		CHECK(rp.api_key == NULL && rp.direct_base_url[0] == '\0',
		      "b3b no leak on reject");
		/* 旧 resolve（无人话面）同样拒收 */
		memset(&rp, 0, sizeof(rp));
		CHECK(occ_provider_resolve(&cfg, "bad", &rp) == -1,
		      "b3b legacy resolve also rejects");
		occ_provider_config_free(&cfg);
		unlink(p3path);
	}

	if (fails) {
		printf("test_provider: %d FAIL(s)\n", fails);
		return 1;
	}
	printf("test_provider: all ok\n");
	return 0;
}
