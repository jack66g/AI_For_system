// SPDX-License-Identifier: GPL-2.0
/*
 * test_provider_stream.c - provider 层 ops.stream 真实现回归测试（审计 B1 关闭证据）
 *
 * 直调 local provider（provider_local.c）的 ops.stream——原实现为
 * AI_ERR_NOT_IMPLEMENTED 死桩，现经 local_chat_stream_messages 真流式
 * （与 local_backend 同一实现）。内嵌 SSE 假服务端（chunked + 分批
 * 延迟），断言增量到达（时间戳跨度 ≥400ms）与内容完整。
 *
 * 构建：make -C tests（见 tests/Makefile）
 * 运行：./test_provider_stream
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "ai_provider.h"
#include "ai_config.h"

/* 工厂/配置函数（名称约定入口，非 ops 虚接口） */
struct ai_provider *local_provider_create(void);
void local_provider_configure(struct ai_provider *provider,
			      const char *model_name,
			      const char *base_url,
			      const char *api_key,
			      int timeout_ms);

static int g_fail;

static void expect(int cond, const char *what)
{
	printf("%s: %s\n", cond ? "PASS" : "FAIL", what);
	if (!cond)
		g_fail++;
}

static double now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void xwrite(int fd, const char *buf, size_t len)
{
	if (write(fd, buf, len) < 0)
		_exit(1);
}

/* ---- on_token 收集器 ---- */

#define MAX_SAMPLES 256

struct tok_collector {
	double ts[MAX_SAMPLES];
	int ns;
	char text[4096];
	size_t text_len;
};

static void collect_token(const char *tok, void *ud)
{
	struct tok_collector *c = ud;

	if (c->ns < MAX_SAMPLES)
		c->ts[c->ns++] = now_ms();
	if (c->text_len + strlen(tok) < sizeof(c->text)) {
		strcpy(c->text + c->text_len, tok);
		c->text_len += strlen(tok);
	}
	printf("  [token #%d] t=%.1fms len=%zu \"%s\"\n",
	       c->ns, c->ts[c->ns - 1], strlen(tok), tok);
}

/* ---- 内嵌 SSE 假服务端（chunked + 分批延迟，OpenAI /v1 协议） ---- */

static void sse_test_server(int port)
{
	int lfd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(port),
	};
	int one = 1, cfd;
	char req[2048];

	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	bind(lfd, (struct sockaddr *)&addr, sizeof(addr));
	listen(lfd, 4);

	cfd = accept(lfd, NULL, NULL);
	if (cfd < 0)
		_exit(1);
	if (read(cfd, req, sizeof(req)) <= 0)
		_exit(1);

	{
		const char *hdr =
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: text/event-stream\r\n"
			"Transfer-Encoding: chunked\r\n"
			"\r\n";

		xwrite(cfd, hdr, strlen(hdr));
	}

	{
		const char *events[3] = {
			"data: {\"choices\":[{\"delta\":{\"content\":"
			"\"local \"},\"finish_reason\":null}]}\n\n",
			"data: {\"choices\":[{\"delta\":{\"content\":"
			"\"provider \"},\"finish_reason\":null}]}\n\n",
			"data: {\"choices\":[{\"delta\":{\"content\":"
			"\"stream ok\"},\"finish_reason\":\"stop\"}]}\n\n"
			"data: [DONE]\n\n",
		};
		int i;

		for (i = 0; i < 3; i++) {
			char chunk_hdr[32];
			size_t elen = strlen(events[i]);

			usleep(250 * 1000);     /* 拖延：放大增量间隔 */
			snprintf(chunk_hdr, sizeof(chunk_hdr), "%zx\r\n",
				 elen);
			xwrite(cfd, chunk_hdr, strlen(chunk_hdr));
			xwrite(cfd, events[i], elen);
			xwrite(cfd, "\r\n", 2);
		}
		xwrite(cfd, "0\r\n\r\n", 5);
	}
	close(cfd);
	close(lfd);
	_exit(0);
}

int main(void)
{
	int port = 18435;
	pid_t pid;
	struct ai_provider *prov;
	struct tok_collector c;
	static struct ai_config cfg;
	int ret;
	double span;
	int i;
	int monotonic = 1;

	printf("==== test_provider_stream：local provider ops.stream ====\n");

	memset(&c, 0, sizeof(c));
	memset(&cfg, 0, sizeof(cfg));

	pid = fork();
	if (pid == 0)
		sse_test_server(port);
	usleep(120 * 1000);     /* 等 listen */

	prov = local_provider_create();
	expect(prov != NULL, "local_provider_create");
	expect(prov->ops.stream != NULL,
	       "ops.stream 非空（死桩已删除）");
	expect((prov->capabilities & AI_PROVIDER_CAP_STREAM) != 0,
	       "capabilities 含 CAP_STREAM（名副其实）");
	expect(prov->ops.init(prov->instance, &cfg) == AI_OK, "provider init");
	local_provider_configure(prov, "test-model",
				 "http://127.0.0.1:18435", "", 30000);
	expect(prov->ops.connect(prov->instance) == AI_OK, "provider connect");

	ret = prov->ops.stream(prov->instance, "测试",
			       collect_token, &c);
	expect(ret == AI_OK,
	       "ops.stream 返回 AI_OK（不再是 NOT_IMPLEMENTED）");

	expect(c.ns >= 3, "收到至少 3 个 token（非一次性 blob）");
	for (i = 1; i < c.ns; i++)
		if (c.ts[i] < c.ts[i - 1])
			monotonic = 0;
	expect(monotonic, "token 时间戳单调不减（增量到达）");
	span = c.ns ? c.ts[c.ns - 1] - c.ts[0] : 0.0;
	printf("  [时序] 首 token t=%.1fms，末 token t=%.1fms，跨度=%.1fms\n",
	       c.ns ? c.ts[0] : 0.0, c.ns ? c.ts[c.ns - 1] : 0.0, span);
	expect(span >= 400.0, "首末 token 跨度 ≥400ms（真增量）");
	expect(strcmp(c.text, "local provider stream ok") == 0,
	       "token 顺序拼接 == 服务端完整文本");

	prov->ops.close(prov->instance);
	free(prov->instance);
	free(prov);
	waitpid(pid, NULL, 0);

	printf("==== %s ====\n", g_fail ? "存在失败项" : "全部通过");
	return g_fail ? 1 : 0;
}
