
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_smoke.c - occ_llm 真传输全链烟测（差分台架证据之一，T9a1）
 *
 * 用法: occ_smoke <model.toml> [prompt]
 *
 * 1) occ_provider_load_cloud 读 [models.cloud]（key 仅进程内）
 * 2) 双尝试（dtchat call_llm 先例，策略在驱动层非库层）：
 *    先配的 base_url（转发口）→ 失败且为 loopback 则 direct
 *    https://api.deepseek.com/v1（T9-INTEGRATION-SURFACE.md:66 先例）
 * 3) occ_llm_call：occ 请求构造 → cloud/http https_post_stream → occ_sse
 * 4) 输出规范化 JSON（含 usage/finish/done_src）+ 命中的端点
 * 绝不打印 api_key。exit 0 成功；1 失败。
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../occ_llm/occ_provider.h"
#include "occ_norm.h"

static const char *loopback_hint(const char *url)
{
	return (strstr(url, "127.0.0.1") || strstr(url, "localhost")) ?
		"loopback" : "remote";
}

int main(int argc, char **argv)
{
	occ_provider p;
	occ_llm_req req;
	occ_msg msgs[1];
	occ_norm *n;
	char *out;
	char *err = NULL;
	const char *toml = argc > 1 ? argv[1] : NULL;
	const char *prompt = argc > 2 ? argv[2] : "Reply with the single word: pong";
	int rc;

	if (!toml) {
		fprintf(stderr, "usage: occ_smoke <model.toml> [prompt]\n");
		return 2;
	}
	if (occ_provider_load_cloud(&p, toml)) {
		fprintf(stderr, "occ_smoke: [models.cloud] unreadable in %s\n", toml);
		return 1;
	}
	if (!p.api_key || !p.api_key[0]) {
		fprintf(stderr, "occ_smoke: no api_key configured (不出网)\n");
		occ_provider_free(&p);
		return 1;
	}

	memset(&req, 0, sizeof(req));
	req.proto = p.proto;
	req.model = p.model;
	memset(msgs, 0, sizeof(msgs));
	msgs[0].role = OCC_ROLE_USER;
	msgs[0].text = prompt;
	req.msgs = msgs;
	req.nmsgs = 1;
	req.gen.has_max_tokens = 1;
	req.gen.max_tokens = 32;		/* 省 token：烟测只验链路 */

	n = occ_norm_new();
	fprintf(stderr, "occ_smoke: try endpoint %s (%s) model=%s proto=%s\n",
		p.base_url, loopback_hint(p.base_url), p.model,
		occ_protocol_name(p.proto));
	rc = occ_llm_call(&p, &req, occ_norm_event, n, &err);
	if (rc != 0 &&
	    !strcmp(loopback_hint(p.base_url), "loopback") &&
	    p.proto == OCC_PROTO_OPENAI_COMPAT) {
		/* dtchat 先例：loopback 转发口不可达 → direct 兜底 */
		occ_provider d;

		fprintf(stderr, "occ_smoke: forwarder failed (%s), direct fallback\n",
			err ? err : "transport");
		free(err);
		err = NULL;
		occ_norm_free(n);	/* 失败尝试的传输错误不混入成功输出 */
		n = occ_norm_new();
		memset(&d, 0, sizeof(d));
		snprintf(d.name, sizeof(d.name), "%s", p.name);
		d.proto = p.proto;
		snprintf(d.base_url, sizeof(d.base_url), "%s",
			 "https://api.deepseek.com/v1");
		snprintf(d.model, sizeof(d.model), "%s", p.model);
		d.api_key = strdup(p.api_key);
		fprintf(stderr, "occ_smoke: try endpoint %s (direct)\n", d.base_url);
		rc = occ_llm_call(&d, &req, occ_norm_event, n, &err);
		free(d.api_key);
	}
	out = occ_norm_dump(n, NULL);
	printf("%s\n", out ? out : "{}");
	free(out);
	if (err) {
		fprintf(stderr, "occ_smoke: error: %s\n", err);
		free(err);
	}
	occ_norm_free(n);
	occ_provider_free(&p);
	return rc == 0 ? 0 : 1;
}
