// SPDX-License-Identifier: GPL-2.0
/*
 * test_onboarding_cloud.c - W77d 云端优先 onboarding 流程回归（mock stdin）
 *
 * 覆盖（契约 B/F）：
 *   A. 成功路径：语言 → setup-password（chpasswd 桩）→ 云端配置
 *      （预设回车默认/手输 mock base_url/key/model → live 1-token 测试 200）
 *      → 本地模型可选步骤跳过 → .onboarded 写入
 *   B. live 测试 401 → 重试菜单 → 跳过 → 返回未完成，.onboarded 不写
 *   C. live 失败 → 回车重试 → 第二次成功 → 完成
 * 全程 mock HTTP（127.0.0.1 随机端口 /v1/chat/completions），不触网。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ai_types.h"
#include "ai_config.h"
#include "ai_chat.h"
#include "ai_runtime.h"
#include "ai_commands.h"

/* onboarding_run 由 cmd_onboarding.c 导出（ai_shell.h 声明？此处自查） */
int onboarding_run(void *shell_ptr);

static int g_fail;
static int g_model_use_calls;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		g_fail++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

/* ---- 桩：runtime chat（AI 面不可用 → 降级文案路径） ---- */
int ai_runtime_chat_ex(struct ai_runtime *rt,
		       const struct ai_chat_msg *msgs, int nmsgs,
		       const char *tools_json, ai_stream_delta_cb on_delta,
		       void *on_delta_ud, struct ai_chat_result **result)
{
	(void)rt; (void)msgs; (void)nmsgs; (void)tools_json;
	(void)on_delta; (void)on_delta_ud; (void)result;
	return AI_ERR_API;
}

/* ---- 桩：model use <name> 成功 ---- */
int cmd_model(void *shell_ptr, int argc, char **argv)
{
	(void)shell_ptr; (void)argc; (void)argv;
	g_model_use_calls++;
	return AI_OK;
}

/* ---- 桩：维护 shell 不进入 ---- */
int cmd_shell(void *shell_ptr, int argc, char **argv)
{
	(void)shell_ptr; (void)argc; (void)argv;
	return AI_OK;
}

/* ---------------- mock 云端服务（/v1/chat/completions） ---------------- */

static void mock_serve(int lfd, int fail_first)
{
	int served = 0;

	for (;;) {
		int cfd = accept(lfd, NULL, NULL);
		char buf[8192];
		size_t len = 0;
		ssize_t r;

		if (cfd < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		for (;;) {
			if (len >= sizeof(buf) - 1)
				break;
			r = recv(cfd, buf + len, sizeof(buf) - 1 - len, 0);
			if (r <= 0)
				break;
			len += (size_t)r;
			buf[len] = '\0';
			if (strstr(buf, "\r\n\r\n"))
				break;
		}
		served++;
		if (fail_first && served == 1) {
			const char *b = "{\"error\":{\"message\":\"bad key\"}}";

			dprintf(cfd,
				"HTTP/1.1 401 Unauthorized\r\n"
				"Content-Type: application/json\r\n"
				"Connection: close\r\n"
				"Content-Length: %zu\r\n\r\n%s",
				strlen(b), b);
		} else {
			const char *b =
				"{\"id\":\"x\",\"choices\":[{\"message\":"
				"{\"role\":\"assistant\",\"content\":\"ok\"},"
				"\"finish_reason\":\"stop\"}]}";

			dprintf(cfd,
				"HTTP/1.1 200 OK\r\n"
				"Content-Type: application/json\r\n"
				"Connection: close\r\n"
				"Content-Length: %zu\r\n\r\n%s",
				strlen(b), b);
		}
		close(cfd);
	}
}

static pid_t start_mock(int *port, int fail_first)
{
	struct sockaddr_in addr;
	socklen_t alen = sizeof(addr);
	int lfd = socket(AF_INET, SOCK_STREAM, 0);
	int one = 1;
	pid_t pid;

	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
	    listen(lfd, 8) != 0 ||
	    getsockname(lfd, (struct sockaddr *)&addr, &alen) != 0) {
		perror("mock bind");
		exit(2);
	}
	*port = ntohs(addr.sin_port);
	pid = fork();
	if (pid == 0) {
		signal(SIGINT, SIG_DFL);
		mock_serve(lfd, fail_first);
		_exit(0);
	}
	close(lfd);
	return pid;
}

/* 用脚本驱动 stdin（管道写端重定向到 fd 0） */
static int feed_script(const char *script)
{
	int pfd[2];

	if (pipe(pfd) != 0)
		return -1;
	if (write(pfd[1], script, strlen(script)) < 0)
		return -1;
	close(pfd[1]);
	dup2(pfd[0], STDIN_FILENO);
	close(pfd[0]);
	return 0;
}

static char g_home[180], g_marked[280];

static void env_reset(void)
{
	static int seq;

	seq++;
	snprintf(g_home, sizeof(g_home), "/tmp/aik-obtest-%d-%d",
		 (int)getpid(), seq);
	snprintf(g_marked, sizeof(g_marked), "%s/.onboarded", g_home);
	mkdir(g_home, 0755);
	setenv("HOME", g_home, 1);
	setenv("AIK_ONBOARDED_PATH", g_marked, 1);
	setenv("AIK_CHPASSWD_BIN", "/bin/true", 1);
	setenv("AIK_ML_CATALOG_PATH", "/nonexistent-catalog.json", 1);
	unlink(g_marked);
}

int main(void)
{
	char script[2048];
	pid_t pid;
	int port;
	int rc;

	signal(SIGCHLD, SIG_DFL);

	/* ---- A. 成功路径 ---- */
	env_reset();
	pid = start_mock(&port, 0);
	snprintf(script, sizeof(script),
		 "1\n"                       /* 语言：中文 */
		 "setup-password\n"
		 "testpw123\n"
		 "testpw123\n"
		 "cloud\n"                   /* 步骤2：云端（必经） */
		 "1\n"                       /* 预设 deepseek */
		 "http://127.0.0.1:%d/v1\n"  /* 手输 mock base_url 覆盖默认 */
		 "sk-test-key\n"             /* api key（非 TTY 明读路径） */
		 "mock-model\n"              /* 模型名 */
		 "\n"                        /* 步骤3 onboarding> 行 */
		 "\n"                        /* 本地模型可选：跳过 */
		 , port);
	feed_script(script);
	{
		struct ai_shell shell;

		memset(&shell, 0, sizeof(shell));
		shell.config = ai_config_init();
		ai_config_load(shell.config);
		g_model_use_calls = 0;
		rc = onboarding_run(&shell);
	}
	CHECK(rc == 0, "A: onboarding completes");
	CHECK(access(g_marked, F_OK) == 0, "A: .onboarded written");
	CHECK(g_model_use_calls >= 1, "A: model use cloud invoked");
	{
		char *ptype = NULL, *purl = NULL;
		struct ai_config *verify = ai_config_init();

		ai_config_load(verify);
		ai_config_get_model(verify, "cloud", &ptype, NULL, &purl, NULL);
		CHECK(ptype && strcmp(ptype, "openai_compatible") == 0 &&
		      purl && strstr(purl, "127.0.0.1"),
		      "A: [models.cloud] written with mock url");
		free(ptype);
		free(purl);
		ai_config_destroy(verify);
	}
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);

	/* ---- B. live 测试 401 → 跳过 → 未完成，.onboarded 不写 ---- */
	env_reset();
	pid = start_mock(&port, 1);       /* 第一次请求 401，之后 200 */
	snprintf(script, sizeof(script),
		 "2\n"                       /* 语言：English */
		 "setup-password\n"
		 "testpw123\n"
		 "testpw123\n"
		 "cloud\n"
		 "5\n"                       /* 自定义 */
		 "http://127.0.0.1:%d/v1\n"
		 "sk-bad\n"
		 "mock-model\n"
		 "2\n"                       /* live 失败 → 跳过 */
		 , port);
	feed_script(script);
	{
		struct ai_shell shell;

		memset(&shell, 0, sizeof(shell));
		shell.config = ai_config_init();
		ai_config_load(shell.config);
		rc = onboarding_run(&shell);
	}
	CHECK(rc == -1, "B: skip -> onboarding_run returns -1");
	CHECK(access(g_marked, F_OK) != 0,
	      "B: .onboarded NOT written after skip");
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);

	/* ---- C. 失败 → 回车重试 → 第二次成功 ---- */
	env_reset();
	pid = start_mock(&port, 1);       /* 第一次 401，之后 200 */
	snprintf(script, sizeof(script),
		 "1\n"
		 "setup-password\n"
		 "testpw123\n"
		 "testpw123\n"
		 "cloud\n"
		 "5\n"
		 "http://127.0.0.1:%d/v1\n"
		 "sk-first\n"
		 "mock-model\n"
		 "\n"                        /* 失败菜单：回车=重试 */
		 "5\n"                       /* 重试：再选预设 */
		 "http://127.0.0.1:%d/v1\n"  /* 重试输入 */
		 "sk-second\n"
		 "mock-model\n"
		 "\n"                        /* 步骤3 onboarding> 行 */
		 "\n"                        /* 本地模型可选：跳过 */
		 , port, port);
	feed_script(script);
	{
		struct ai_shell shell;

		memset(&shell, 0, sizeof(shell));
		shell.config = ai_config_init();
		ai_config_load(shell.config);
		rc = onboarding_run(&shell);
	}
	CHECK(rc == 0, "C: retry-then-success completes");
	CHECK(access(g_marked, F_OK) == 0, "C: .onboarded written");
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);

	unlink(g_marked);
	rmdir(g_home);

	printf("\nRESULT: %s (failures=%d)\n", g_fail ? "FAIL" : "PASS",
	       g_fail);
	return g_fail ? 1 : 0;
}
