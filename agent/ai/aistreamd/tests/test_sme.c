/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_sme.c - SME 写入单测：对 mock HTTP server 的请求体逐字节断言
 *
 * mock server（fork 子进程，**测试专用桩，生产代码零桩**）：监听
 * 127.0.0.1:0，接受 N 个连接，把原始请求（请求行+头+体）追加到捕获
 * 文件，回 200 {"id":"m1"}。父进程经真实 as_sme_post → sme_add_ex →
 * local_http 发起真 HTTP 调用，然后与冻结期望体逐字节比对。
 *
 * 冻结契约（sme_add_ex 字段序 + %.17g importance；SME 服务端按 double
 * 接收）：
 *   {"text":..,"metadata":{..},"tags":[..],"importance":<17g>,
 *    "source":"kernel_evt"}
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "as_conf.h"
#include "as_event.h"
#include "as_sme.h"
#include "as_stats.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

#define MOCK_BODY "{\"id\":\"m1\"}"
#define MOCK_RESP \
	"HTTP/1.1 200 OK\r\n" \
	"Content-Type: application/json\r\n" \
	"Content-Length: 13\r\n" \
	"Connection: close\r\n" \
	"\r\n" \
	MOCK_BODY

/* strcasestr 无 POSIX 保证，本地实现（仅头解析用） */
static char *strcasestr_local(const char *h, const char *n)
{
	size_t nl = strlen(n);

	for (; *h; h++)
		if (strncasecmp(h, n, nl) == 0)
			return (char *)h;
	return NULL;
}

/* 读到 \r\n\r\n，再按 Content-Length 读体；原样追加到 cap 文件 */
static int serve_one(int cli, FILE *cap)
{
	char req[8192];
	size_t off = 0;
	long clen = 0;

	while (off < sizeof(req) - 1) {
		ssize_t n = recv(cli, req + off, sizeof(req) - 1 - off, 0);

		if (n <= 0)
			return -1;
		off += (size_t)n;
		req[off] = '\0';
		if (strstr(req, "\r\n\r\n"))
			break;
	}
	{
		char *cl = strcasestr_local(req, "Content-Length:");

		if (cl)
			clen = strtol(cl + 15, NULL, 10);
	}
	while ((long)strlen(req) - (long)(strstr(req, "\r\n\r\n") - req) - 4
	       < clen && off < sizeof(req) - 1) {
		ssize_t n = recv(cli, req + off, sizeof(req) - 1 - off, 0);

		if (n <= 0)
			break;
		off += (size_t)n;
		req[off] = '\0';
	}
	fwrite(req, 1, off, cap);
	fputc('\n', cap);
	fflush(cap);
	{
		const char *r = MOCK_RESP;

		if (send(cli, r, strlen(r), 0) < 0)
			return -1;
	}
	return 0;
}

int main(void)
{
	char dir[64], portfile[128], capfile[128], conffile[128];
	pid_t srv;
	int port = 0;

	snprintf(dir, sizeof(dir), "/tmp/as-sme-%d", (int)getpid());
	{
		char cmd[512];

		snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s", dir,
			 dir);
		if (system(cmd) != 0)
			return 2;
	}
	snprintf(portfile, sizeof(portfile), "%s/port", dir);
	snprintf(capfile, sizeof(capfile), "%s/cap.txt", dir);
	snprintf(conffile, sizeof(conffile), "%s/sme.conf", dir);

	/* ---- mock server 子进程 ---- */
	srv = fork();
	if (srv == 0) {
		int s = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in a;
		socklen_t al = sizeof(a);
		FILE *cap;
		int served = 0;

		if (s < 0)
			_exit(3);
		memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		a.sin_port = 0;
		if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0 ||
		    listen(s, 8) < 0 ||
		    getsockname(s, (struct sockaddr *)&a, &al) < 0)
			_exit(3);
		{
			FILE *pf = fopen(portfile, "w");

			if (!pf)
				_exit(3);
			fprintf(pf, "%d\n", (int)ntohs(a.sin_port));
			fclose(pf);
		}
		cap = fopen(capfile, "w");
		if (!cap)
			_exit(3);
		while (served < 2) {
			int cli = accept(s, NULL, NULL);
			struct timeval tv = { .tv_sec = 5 };

			if (cli < 0)
				continue;
			setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tv,
				   sizeof(tv));
			if (serve_one(cli, cap) == 0)
				served++;
			close(cli);
		}
		fclose(cap);
		close(s);
		_exit(0);
	}

	/* 等 port 文件 */
	for (int i = 0; i < 100 && port == 0; i++) {
		FILE *f = fopen(portfile, "r");

		if (f) {
			if (fscanf(f, "%d", &port) != 1)
				port = 0;
			fclose(f);
		}
		usleep(50000);
	}
	CHECK(port > 0, "mock server port");
	if (port <= 0)
		return 1;

	/* ---- 两条真实 HTTP 写入 ---- */
	{
		struct as_conf c;
		struct as_stats st;
		struct as_sme s;
		struct as_event ev;
		char text[AS_TEXT_MAX], meta[AS_META_MAX], tags[AS_TAGS_MAX];

		as_conf_defaults(&c);
		snprintf(c.sme_url, sizeof(c.sme_url),
			 "http://127.0.0.1:%d", port);
		as_stats_init(&st, &c);
		CHECK(as_sme_init(&s, &c, &st) == 0, "as_sme_init");

		/* 1) 决策事件（decision_id 透传 + 冻结体） */
		as_event_ai_policy(&ev, 4711, 2, NULL, "mm.swappiness");
		as_sme_build(&ev, &c, text, sizeof(text), meta, sizeof(meta),
			     tags, sizeof(tags));
		CHECK(as_sme_post(&s, text, meta, tags) == 0, "post 1");
		CHECK(st.sme_ok == 1, "sme_ok=1");

		/* 2) uevent（action 作 category，进 tags/metadata） */
		as_event_uevent(&ev, "add", "/devices/virtual/block/loop9",
				"block");
		as_sme_build(&ev, &c, text, sizeof(text), meta, sizeof(meta),
			     tags, sizeof(tags));
		CHECK(as_sme_post(&s, text, meta, tags) == 0, "post 2");

		as_sme_free(&s);
	}
	{
		int status;

		waitpid(srv, &status, 0);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		      "mock server exit 0");
	}

	/* ---- 捕获文件逐字节断言（请求行 + 冻结体关键片段全字匹配） ---- */
	{
		FILE *f = fopen(capfile, "r");
		char all[16384];
		size_t n;

		CHECK(f != NULL, "reopen capture");
		if (!f)
			return 1;
		n = fread(all, 1, sizeof(all) - 1, f);
		all[n] = '\0';
		fclose(f);

		CHECK(strstr(all, "POST /memories ") != NULL,
		      "request line POST /memories");
		CHECK(strstr(all, "\"text\":\"[kern] event policy "
		      "decision_id=4711 executed=2 param=mm.swappiness\"")
		      != NULL, "frozen text body 1");
		CHECK(strstr(all, "\"category\":\"policy\"") != NULL,
		      "metadata category");
		CHECK(strstr(all, "\"decision_id\":4711") != NULL,
		      "decision_id verbatim in metadata");
		CHECK(strstr(all, "\"tags\":[\"kernel_evt\","
		      "\"stream:event\",\"cat:policy\"]") != NULL,
		      "frozen tags");
		CHECK(strstr(all, "\"importance\":0.29999999999999999")
		      != NULL, "importance %.17g frozen");
		CHECK(strstr(all, "\"source\":\"kernel_evt\"") != NULL,
		      "source field");
		CHECK(strstr(all, "\"text\":\"[kern] uevent add "
		      "dev=/devices/virtual/block/loop9 subsystem=block\"")
		      != NULL, "frozen text body 2");
		CHECK(strstr(all, "\"cat:add\"") != NULL, "uevent cat tag");
	}

	{
		char cmd[128];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
		(void)!system(cmd);
	}
	if (fails) {
		printf("test_sme: %d failures\n", fails);
		return 1;
	}
	printf("test_sme: OK\n");
	return 0;
}
