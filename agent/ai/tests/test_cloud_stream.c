// SPDX-License-Identifier: GPL-2.0
/*
 * test_cloud_stream.c - 云通道真·增量流式回归测试（审计 A1 关闭证据）
 *
 * 直调 openai_stream（provider 层），on_token 回调打 CLOCK_MONOTONIC
 * 时间戳，断言：
 *   1. ≥3 个时间样本递增（非一次性 blob）；
 *   2. 首 token 与末 token 时间跨度 ≥ 400ms（内嵌服务端故意每批拖
 *      250ms，整体缓冲实现跨度会 ≈0ms）；
 *   3. 全部 token 顺序拼接 == 服务端下发的完整文本；
 *   4. chunked 编码正确解码（服务端用 Transfer-Encoding: chunked）。
 *
 * 两种模式：
 *   ./test_cloud_stream            —— 内嵌 127.0.0.1:端口的 SSE 假服务端
 *   ./test_cloud_stream <base_url> <model>
 *                                  —— 直打真实 OpenAI 兼容端点
 *                                     （如 http://127.0.0.1:11434/v1）
 *
 * 构建：make -C tests（见 tests/Makefile 的 test_cloud_stream 规则）
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
#include "http/http_client.h"

/* 工厂函数未进公共头（runtime.c 同款名称约定前向声明） */
struct ai_provider *openai_compatible_provider_create(void);
void openai_provider_configure(struct ai_provider *provider,
			       const char *model_name,
			       const char *base_url,
			       const char *api_key);

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

/* 测试服务端写 socket：失败即退出（warn_unused_result 安抚） */
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

/* ---- 内嵌 SSE 假服务端（chunked + 分批延迟） ---- */

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

	/* 响应头：SSE + chunked */
	{
		const char *hdr =
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: text/event-stream\r\n"
			"Transfer-Encoding: chunked\r\n"
			"\r\n";

		xwrite(cfd, hdr, strlen(hdr));
	}

	/* 3 批 SSE event（chunked 逐块下发，批间 250ms） */
	{
		const char *events[3] = {
			"data: {\"choices\":[{\"delta\":{\"content\":"
			"\"kernel \"},\"finish_reason\":null}]}\n\n",
			"data: {\"choices\":[{\"delta\":{\"content\":"
			"\"stream \"},\"finish_reason\":null}]}\n\n",
			"data: {\"choices\":[{\"delta\":{\"content\":"
			"\"test ok\"},\"finish_reason\":\"stop\"}]}\n\n"
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
		/* 终止块 */
		xwrite(cfd, "0\r\n\r\n", 5);
	}
	close(cfd);
	close(lfd);
	_exit(0);
}

/* ---- 断言公共逻辑 ---- */

/*
 * @min_span: 首末 token 最小跨度 ms。内嵌服务端故意 3×250ms 拖延，
 * 取 400；真实端点小模型生成快（token 间隔 ~25ms），取 50 即可
 * 与一次性 blob（跨度 ≈0ms）区分。
 */
static void check_collector(struct tok_collector *c, double min_span)
{
	double span;
	int i;
	int monotonic = 1;

	expect(c->ns >= 3, "收到至少 3 个 token（非一次性 blob）");
	for (i = 1; i < c->ns; i++)
		if (c->ts[i] < c->ts[i - 1])
			monotonic = 0;
	expect(monotonic, "token 时间戳单调不减（增量到达）");

	span = c->ts[c->ns - 1] - c->ts[0];
	printf("  [时序] 首 token t=%.1fms，末 token t=%.1fms，跨度=%.1fms\n",
	       c->ts[0], c->ts[c->ns - 1], span);
	printf("  [判据] 跨度 ≥%.0fms（整体缓冲会 ≈0ms）\n", min_span);
	expect(span >= min_span, "首末 token 跨度达标（真增量）");
}

/* ---- 模式一：内嵌假服务端 ---- */

static void run_embedded(void)
{
	int port = 18434;
	pid_t pid;
	struct ai_provider *prov;
	struct tok_collector c;
	int ret;

	memset(&c, 0, sizeof(c));

	pid = fork();
	if (pid == 0)
		sse_test_server(port);
	usleep(120 * 1000);     /* 等 listen */

	https_init();

	prov = openai_compatible_provider_create();
	expect(prov != NULL, "openai_compatible_provider_create");
	{
		static struct ai_config cfg;

		memset(&cfg, 0, sizeof(cfg));
		expect(prov->ops.init(prov->instance, &cfg) == AI_OK,
		       "provider init");
	}
	openai_provider_configure(prov, "test-model",
				  "http://127.0.0.1:18434", "sk-test");
	expect(prov->ops.connect(prov->instance) == AI_OK, "provider connect");

	printf("调用 openai_stream（内嵌 SSE 服务端 127.0.0.1:%d）...\n",
	       port);
	ret = prov->ops.stream(prov->instance,
			       "计数测试", collect_token, &c);
	expect(ret == AI_OK, "openai_stream 返回 AI_OK（不再是 NOT_IMPLEMENTED）");

	check_collector(&c, 400.0);
	expect(strcmp(c.text, "kernel stream test ok") == 0,
	       "token 顺序拼接 == 服务端完整文本");

	prov->ops.close(prov->instance);
	free(prov->instance);
	free(prov);
	https_cleanup();
	waitpid(pid, NULL, 0);
}

/* ---- 模式二：真实端点 ---- */

static void run_real(const char *base_url, const char *model)
{
	struct ai_provider *prov;
	struct tok_collector c;
	int ret;

	memset(&c, 0, sizeof(c));
	https_init();

	prov = openai_compatible_provider_create();
	{
		static struct ai_config cfg;

		memset(&cfg, 0, sizeof(cfg));
		if (prov->ops.init(prov->instance, &cfg) != AI_OK) {
			printf("FAIL: provider init\n");
			g_fail++;
			return;
		}
	}
	openai_provider_configure(prov, model, base_url, "");
	if (prov->ops.connect(prov->instance) != AI_OK) {
		printf("FAIL: provider connect\n");
		g_fail++;
		return;
	}

	printf("调用 openai_stream（真实端点 %s, model=%s）...\n",
	       base_url, model);
	ret = prov->ops.stream(prov->instance,
			       "从 1 数到 5，用空格分隔",
			       collect_token, &c);
	expect(ret == AI_OK, "openai_stream 返回 AI_OK");
	check_collector(&c, 50.0);

	prov->ops.close(prov->instance);
	free(prov->instance);
	free(prov);
	https_cleanup();
}

int main(int argc, char **argv)
{
	printf("==== test_cloud_stream：云通道真增量流式 ====\n");

	if (argc >= 3) {
		run_real(argv[1], argv[2]);
	} else {
		run_embedded();
	}

	printf("==== %s ====\n", g_fail ? "存在失败项" : "全部通过");
	return g_fail ? 1 : 0;
}
