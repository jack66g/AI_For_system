// SPDX-License-Identifier: GPL-2.0
/*
 * test_http_retry.c - T2 问题 3 回归测试：连接级失败重建连接重试
 *
 * 场景：服务端 accept 后异常关连接（不回包），local_http_post 第一轮
 * 收到空响应（AI_ERR_NETWORK）→ 关闭坏连接重建重试一次 → 第二轮服务端
 * 正常回 200 → 断言拿到响应体（修复前：直接报 "No response from local
 * service (timeout or connection lost)"，即 T2 实测的 ask 偶发
 * Network error，重发才恢复）。
 *
 * 构建：make -C tests 或 gcc 同 test_utf8_body（见 tests/Makefile）
 * 运行：./test_http_retry   （全部 PASS 且退出码 0；监听 127.0.0.1:11439）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "local_http.h"
#include "ai_types.h"

static int g_fail;

static void expect(int cond, const char *what)
{
	printf("%s: %s\n", cond ? "PASS" : "FAIL", what);
	if (!cond)
		g_fail++;
}

/* 服务端：第 1 个连接 accept 后直接 close（模拟异常关连接），
 * 第 2 个连接正常回 HTTP 200 + JSON 体 */
static void bad_then_good_server(int port)
{
	int lfd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = htons(port),
	};
	int one = 1, i;

	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	bind(lfd, (struct sockaddr *)&addr, sizeof(addr));
	listen(lfd, 4);

	for (i = 0; i < 2; i++) {
		int cfd = accept(lfd, NULL, NULL);

		if (cfd < 0)
			continue;
		if (i == 0) {
			close(cfd);         /* 第一轮：异常关连接 */
			continue;
		}
		{
			const char *resp =
				"HTTP/1.1 200 OK\r\n"
				"Content-Type: application/json\r\n"
				"Content-Length: 17\r\n"
				"Connection: close\r\n"
				"\r\n"
				"{\"retry\":\"ok123\"}";

			/* 读掉请求头（避免 RST 打断写回） */
			{
				char buf[4096];

				(void)!read(cfd, buf, sizeof(buf));
			}
			(void)!write(cfd, resp, strlen(resp));
			close(cfd);
		}
	}
	close(lfd);
}

int main(void)
{
	char *response = NULL, *error = NULL;
	int status = 0;
	int rc;

	if (fork() == 0) {
		bad_then_good_server(11439);
		_exit(0);
	}
	usleep(200 * 1000);     /* 等服务端就绪 */

	rc = local_http_post("http://127.0.0.1:11439/chat", NULL,
			     "{\"probe\":1}", 3000,
			     &response, &error, &status);
	wait(NULL);

	expect(status == 200, "重试后拿到 HTTP 200");
	expect(rc == AI_OK, "local_http_post 返回 AI_OK（重试成功）");
	expect(response && strstr(response, "retry") != NULL,
	       "响应体正确（第一轮坏连接被重建重试绕过）");
	expect(error == NULL, "无错误消息");

	free(response);
	free(error);
	printf("== test_http_retry: %s ==\n",
	       g_fail ? "存在失败" : "全部通过");
	return g_fail ? 1 : 0;
}
