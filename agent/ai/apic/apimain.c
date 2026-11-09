/* SPDX-License-Identifier: GPL-2.0 */
/*
 * apimain.c - T7b 主程序(旗标/配置/监听/LISTENING 行;参考 main())。
 * 与 aikapi.c 分离使 libaikapi.a 无 main,单测可链全部模块。
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "apic/api.h"
#include "apiredact.h"
#include "desktop/dtcore.h"
#include "desktop/dtjson.h"

static void usage(void)
{
	fprintf(stderr,
		"usage: aikerneld-api [--frozen-now EPOCH] [--frozen-random] "
		"[--probe-netlink]\n");
}

static int home_toml_path(char *out, size_t cap)
{
	const char *home = getenv("HOME");

	if (!home || !*home)
		home = "/root";
	snprintf(out, cap, "%s/.aikernel/model.toml", home);
	return 0;
}

int main(int argc, char **argv)
{
	long long frozen_now = -1;
	int frozen_random = 0;
	int probe_netlink = 0;
	int i;
	aik_json *cfg;
	const aik_json *v;
	const char *bind = API_BIND_HOST;
	long long port = API_BIND_PORT;
	int tls = 0;
	const char *cert = "";
	const char *key = "";

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--frozen-now") == 0 && i + 1 < argc) {
			frozen_now = atoll(argv[++i]);
		} else if (strcmp(argv[i], "--frozen-random") == 0) {
			frozen_random = 1;
		} else if (strcmp(argv[i], "--probe-netlink") == 0) {
			probe_netlink = 1;
		} else {
			usage();
			return 2;
		}
	}
	memset(&g_api, 0, sizeof(g_api));
	home_toml_path(g_api.toml_file, sizeof(g_api.toml_file));
	snprintf(g_api.ai_bin, sizeof(g_api.ai_bin), "%s",
		 getenv("AIKERNEL_AI_BIN") ? getenv("AIKERNEL_AI_BIN")
					   : API_AI_BIN_DEFAULT);
	snprintf(g_api.tools_json, sizeof(g_api.tools_json), "%s",
		 getenv("AIKERNEL_TOOLS_JSON")
			 ? getenv("AIKERNEL_TOOLS_JSON")
			 : API_TOOLS_JSON_DEFAULT);
	{
		const char *t = getenv("AIKERNEL_API_ASK_TIMEOUT");

		if (!t || !api_py_int(t, &g_api.ask_timeout))
			g_api.ask_timeout = API_ASK_TIMEOUT_DEFAULT;
	}
	g_api.frozen = (frozen_now >= 0 || frozen_random);
	g_api.frozen_epoch = frozen_now >= 0 ? frozen_now : 1775000000;

	if (probe_netlink) {
		aik_json *ack = NULL;
		char *err = NULL;

		api_nl_act("llm.top_k", 41, 0, &ack, &err);
		printf("nl_act|llm.top_k|ack=%s|err=%s\n",
		       ack ? dt_json_dump_default(ack) : "null",
		       err ? err : "null");
		aik_json_free(ack);
		free(err);
		ack = NULL;
		err = NULL;
		api_nl_act("nope.param", 1, 0, &ack, &err);
		printf("nl_act|nope.param|ack=%s|err=%s\n",
		       ack ? dt_json_dump_default(ack) : "null",
		       err ? err : "null");
		aik_json_free(ack);
		free(err);
		return 0;
	}

	cfg = api_load_config();
	v = dt_get(cfg, "bind");
	if (aik_json_str(v))
		bind = aik_json_str(v);
	v = dt_get(cfg, "port");
	if (v && aik_json_typeof(v) == AIK_JSON_INT)
		port = aik_json_int(v);
	v = dt_get(cfg, "tls");
	tls = (v && aik_json_typeof(v) == AIK_JSON_BOOL &&
	       aik_json_bool(v));
	v = dt_get(cfg, "cert");
	if (aik_json_str(v))
		cert = aik_json_str(v);
	v = dt_get(cfg, "key");
	if (aik_json_str(v))
		key = aik_json_str(v);

	if (strcmp(bind, "127.0.0.1") != 0 && strcmp(bind, "localhost") != 0 &&
	    strcmp(bind, "::1") != 0) {
		char msg[512];
		aik_json *args = dt_new_obj();

		snprintf(msg, sizeof(msg),
			 "api 绑定非回环地址 %s —— 对外暴露必须配 TLS+token，"
			 "并确认防火墙（nft 默认 drop 仅放行 22）", bind);
		printf("[aikernel-api] WARN: %s\n", msg);
		fflush(stdout);
		dt_put_str(args, "bind", bind);
		dt_put_bool(args, "tls", tls);
		api_audit_line("api_bind", args, "WARN_NON_LOOPBACK");
		aik_json_free(args);
	}
	if (tls) {
		struct stat st;

		if (!*cert || !*key || stat(cert, &st) != 0 ||
		    stat(key, &st) != 0) {
			printf("[aikernel-api] FATAL: tls=true 但证书/私钥缺失"
			       "（model.toml [api] cert/key），拒绝以半配置"
			       "启动\n");
			fflush(stdout);
			return 1;
		}
		/* tls=true 且证书存在:本构建不含 TLS 服务面(mbedtls 归
		 * T7c tls-gateway);按已知限制拒绝启动,不静默降级明文 */
		printf("[aikernel-api] FATAL: 本构建未启用 TLS 服务面"
		       "（T7c aik-tls-gateway 承担,见 T7B-REPORT 已知限制）\n");
		fflush(stdout);
		return 1;
	}
	/* SENSE 脱敏档位启动行（设计 SENSE-REDACT-DESIGN §4.3）：off 静默
	 * （stdout/listening 行与重放向量逐字节一致——off 零输出是红线）；
	 * 非 off 一行 stderr 审计（含未知键透传提示口径） */
	{
		int rl = api_sense_redact_level(NULL, 0);

		if (rl != API_REDACT_OFF)
			fprintf(stderr,
				"[aikernel-api] sense_redact=%s (exposure-side; "
				"unknown keys passed+counted — see SENSE-REDACT-DESIGN)\n",
				rl == API_REDACT_STRICT ? "strict" : "soft");
	}
	/* 先监听后打 listening 行(绑不上时无 LISTENING,与参考 OSError 同) */
	if (api_http_listen(bind, (int)port) != 0) {
		fprintf(stderr, "[aikernel-api] bind %s:%lld failed: %s\n",
			bind, port, strerror(errno));
		return 1;
	}
	printf("[aikernel-api] v%d listening on %s:%lld (明文"
	       "（本机/SSH 隧道场景）, Bearer token: model.toml [api] token"
	       " > %s)\n",
	       API_VERSION, bind, port, API_TOKEN_FILE);
	printf("LISTENING %lld\n", port);
	fflush(stdout);
	api_http_accept_loop();
	return 0;
}
