/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_http_headers.c - http_client 自定义请求头单测（T9a2 共享文件
 * 增量的行为门）
 *
 * 本地 mock HTTP server（fork 子进程，明文 http://127.0.0.1）逐字节
 * 落盘收到的请求，对拍断言：
 *   1. https_post_stream_ex(url, key, body, NULL) 与旧
 *      https_post_stream(url, key, body) 输出**逐字节相同**
 *      （extra_headers=NULL=旧行为——回归红线）
 *   2. anthropic 形态：x-api-key + anthropic-version 头、api_key=NULL
 *      → 无 Authorization 行
 *   3. extra 含 Authorization: 项 → 默认 Bearer 让位
 *   4. Bearer 与普通 extra 头共存
 *   5. api_key 空串 + extra（无认证项）→ 无 Authorization
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "cloud/http/http_client.h"

static int fails;

#define OK(cond, name) do { \
	if (cond) { printf("ok %s\n", name); } \
	else { printf("FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); fails++; } \
} while (0)

#define RESP "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\n{\"ok\":1}"

/* strcasestr 便携版（c11 无保证） */
static char *ci_strstr(const char *h, const char *ndl)
{
	size_t nl = strlen(ndl);

	for (; *h; h++)
		if (!strncasecmp(h, ndl, nl))
			return (char *)h;
	return NULL;
}

/*
 * mock server 子进程：bind 127.0.0.1:0（内核分配端口）→ 写端口到
 * report_fd → accept 一个连接 → 读到 "\r\n\r\n" 后按 Content-Length
 * 收齐 body → 原始字节全部写 dump_path → 回 RESP → 退出。
 */
static void mock_server_child(int report_fd, const char *dump_path)
{
	int srv, cli;
	struct sockaddr_in addr;
	socklen_t alen = sizeof(addr);
	FILE *dump;
	char buf[8192];
	size_t have = 0;
	ssize_t n;
	long content_length = 0;
	size_t header_end = 0;
	char portbuf[16];

	srv = socket(AF_INET, SOCK_STREAM, 0);
	if (srv < 0)
		_exit(10);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = 0;
	if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		_exit(11);
	if (getsockname(srv, (struct sockaddr *)&addr, &alen) < 0)
		_exit(12);
	snprintf(portbuf, sizeof(portbuf), "%u\n",
		 (unsigned)ntohs(addr.sin_port));
	if (write(report_fd, portbuf, strlen(portbuf)) < 0)
		_exit(13);
	if (listen(srv, 1) < 0)
		_exit(14);
	cli = accept(srv, NULL, NULL);
	if (cli < 0)
		_exit(15);
	close(report_fd);
	/*
	 * 收请求：全缓冲搜头终止符 "\r\n\r\n"（头+body 常同批到达，
	 * 终止符在缓冲中部而非尾部——只在尾部比对会错过而卡 recv），
	 * 再按 Content-Length 收齐 body。
	 */
	{
		int found = 0;

		while (have < sizeof(buf) - 1 && !found) {
			size_t i;

			for (i = 0; i + 4 <= have; i++)
				if (!memcmp(buf + i, "\r\n\r\n", 4)) {
					header_end = i + 4;
					found = 1;
					break;
				}
			if (found)
				break;
			n = recv(cli, buf + have,
				 sizeof(buf) - 1 - have, 0);
			if (n <= 0)
				break;
			have += (size_t)n;
		}
		if (!found) {
			/* 对端关闭且无完整头：落盘已收字节后退出 */
			dump = fopen(dump_path, "w");
			if (dump) {
				fwrite(buf, 1, have, dump);
				fclose(dump);
			}
			close(cli);
			close(srv);
			_exit(18);
		}
	}
	{
		char *cl = ci_strstr(buf, "Content-Length:");

		if (cl)
			content_length = strtol(cl + 15, NULL, 10);
	}
	while (content_length > 0 &&
	       have < header_end + (size_t)content_length &&
	       have < sizeof(buf) - 1) {
		n = recv(cli, buf + have, sizeof(buf) - 1 - have, 0);
		if (n <= 0)
			break;
		have += (size_t)n;
	}
	dump = fopen(dump_path, "w");
	if (!dump)
		_exit(16);
	fwrite(buf, 1, have, dump);
	fclose(dump);
	if (write(cli, RESP, strlen(RESP)) < 0)
		_exit(17);
	close(cli);
	close(srv);
	_exit(0);
}

/* on_data：丢弃（本测试只关心请求侧字节） */
static void sink_cb(void *ud, const char *data, size_t len)
{
	(void)ud;
	(void)data;
	(void)len;
}

/*
 * 一次请求：fork mock → https_post_stream(_ex) 发明文请求 → 收 dump。
 * use_ex=0 走旧通道；1 走 ex 通道。
 */
static char *fire_request(const char *api_key, const char *const *extra,
			  int use_ex, char tag)
{
	int fds[2];
	char tmpl[] = "/tmp/occ-hdr-test-XXXXXX";
	int tfd;
	char dump_path[64];
	pid_t pid;
	char portbuf[16];
	int port;
	ssize_t n;
	int status;
	char url[64];
	FILE *f;
	char *out;
	long len;
	char *err = NULL;
	int rc;

	if (pipe(fds) < 0)
		return NULL;
	tfd = mkstemp(tmpl);
	if (tfd < 0) {
		close(fds[0]);
		close(fds[1]);
		return NULL;
	}
	close(tfd);
	snprintf(dump_path, sizeof(dump_path), "%s", tmpl);
	pid = fork();
	if (pid == 0) {
		close(fds[0]);
		mock_server_child(fds[1], dump_path);
		_exit(99);		/* 不返回 */
	}
	close(fds[1]);
	n = read(fds[0], portbuf, sizeof(portbuf) - 1);
	close(fds[0]);
	if (n <= 0) {
		waitpid(pid, &status, 0);
		unlink(dump_path);
		return NULL;
	}
	portbuf[n] = '\0';
	port = atoi(portbuf);
	snprintf(url, sizeof(url), "http://127.0.0.1:%d/v%c", port, tag);
	if (use_ex)
		rc = https_post_stream_ex(url, api_key, "{\"x\":1}", extra,
					  sink_cb, NULL, NULL, &err);
	else
		rc = https_post_stream(url, api_key, "{\"x\":1}",
				       sink_cb, NULL, NULL, &err);
	free(err);
	waitpid(pid, &status, 0);
	if (rc != 0) {
		unlink(dump_path);
		return NULL;
	}
	f = fopen(dump_path, "rb");
	if (!f) {
		unlink(dump_path);
		return NULL;
	}
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	fseek(f, 0, SEEK_SET);
	out = malloc((size_t)len + 1);
	if (!out) {
		fclose(f);
		unlink(dump_path);
		return NULL;
	}
	if (fread(out, 1, (size_t)len, f) != (size_t)len) {
		fclose(f);
		free(out);
		unlink(dump_path);
		return NULL;
	}
	out[len] = '\0';
	fclose(f);
	unlink(dump_path);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		free(out);
		return NULL;
	}
	return out;
}

static int contains(const char *h, const char *needle)
{
	return strstr(h, needle) != NULL;
}

static int header_count(const char *h, const char *name)
{
	int n = 0;
	const char *p = h;

	while ((p = strstr(p, name)) != NULL) {
		n++;
		p += strlen(name);
	}
	return n;
}

int main(void)
{
	char *old_bytes, *exnull_bytes, *ant, *authov, *both, *nokey;

	https_init();
	https_set_timeout(5, 5);

	/* 1. 旧通道基线 */
	old_bytes = fire_request("sk-legacy", NULL, 0, 'a');
	OK(old_bytes != NULL, "old-stream-served");
	if (old_bytes) {
		OK(contains(old_bytes,
			    "Authorization: Bearer sk-legacy\r\n"),
		   "old-bearer-present");
		OK(contains(old_bytes,
			    "Content-Type: application/json\r\n"),
		   "old-content-type");
		OK(contains(old_bytes, "Connection: close\r\n"),
		   "old-connection");
		OK(contains(old_bytes, "Content-Length: 7\r\n"),
		   "old-content-length");
		OK(contains(old_bytes, "\r\n\r\n{\"x\":1}"),
		   "old-body-appended");
		OK(contains(old_bytes, "POST /va HTTP/1.1\r\n"),
		   "old-request-line");
	}

	/* 2. ex + NULL 头 ≡ 旧通道（逐字节） */
	exnull_bytes = fire_request("sk-legacy", NULL, 1, 'a');
	OK(exnull_bytes != NULL, "ex-null-served");
	if (old_bytes && exnull_bytes)
		OK(strcmp(old_bytes, exnull_bytes) == 0,
		   "ex-null-byte-identical");

	/* 3. anthropic 形态：x-api-key + anthropic-version，无 Authorization */
	{
		const char *extra[3] = {
			"x-api-key: sk-ant-test",
			"anthropic-version: 2023-06-01",
			NULL
		};

		ant = fire_request(NULL, extra, 1, 'b');
	}
	OK(ant != NULL, "anthropic-served");
	if (ant) {
		OK(contains(ant, "x-api-key: sk-ant-test\r\n"),
		   "anthropic-x-api-key");
		OK(contains(ant,
			    "anthropic-version: 2023-06-01\r\n"),
		   "anthropic-version-header");
		OK(!contains(ant, "Authorization"),
		   "anthropic-no-authorization");
		OK(header_count(ant, "x-api-key: sk-ant-test") +
		   header_count(ant, "anthropic-version: 2023-06-01") == 2,
		   "anthropic-headers-once");
		OK(contains(ant, "\r\n\r\n{\"x\":1}"),
		   "anthropic-body-intact");
		OK(contains(ant, "Content-Length: 7\r\n"),
		   "anthropic-content-length");
	}

	/* 4. Authorization 自备 → 默认 Bearer 让位 */
	{
		const char *extra[2] = {
			"Authorization: Custom tok",
			NULL
		};

		authov = fire_request("sk-ignored", extra, 1, 'c');
	}
	OK(authov != NULL, "auth-override-served");
	if (authov) {
		OK(contains(authov, "Authorization: Custom tok\r\n"),
		   "auth-override-present");
		OK(!contains(authov, "Bearer"),
		   "auth-override-no-bearer");
		OK(header_count(authov, "Authorization:") == 1,
		   "auth-override-single");
	}

	/* 5. Bearer + 普通 extra 共存 */
	{
		const char *extra[2] = { "X-Occ-Trace: t9a2", NULL };

		both = fire_request("sk-both", extra, 1, 'd');
	}
	OK(both != NULL, "bearer-plus-extra-served");
	if (both) {
		OK(contains(both, "Authorization: Bearer sk-both\r\n"),
		   "bearer-plus-extra-bearer");
		OK(contains(both, "X-Occ-Trace: t9a2\r\n"),
		   "bearer-plus-extra-custom");
	}

	/* 6. api_key 空串 + extra（无认证项）→ 无 Authorization */
	{
		const char *extra[2] = { "X-Plain: 1", NULL };

		nokey = fire_request("", extra, 1, 'e');
	}
	OK(nokey != NULL, "empty-key-extra-served");
	if (nokey)
		OK(!contains(nokey, "Authorization"),
		   "empty-key-extra-no-auth");

	free(old_bytes);
	free(exnull_bytes);
	free(ant);
	free(authov);
	free(both);
	free(nokey);

	if (fails) {
		printf("test_http_headers: FAIL(%d)\n", fails);
		return 1;
	}
	printf("test_http_headers: ALL GREEN\n");
	return 0;
}
