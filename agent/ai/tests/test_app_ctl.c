/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
/*
 * test_app_ctl - W82 V4.4 应用控制面适配器单测
 *
 * 默认（非 root，全部真跑，不 mock 外部 APP）：
 *   - 纯函数：回环 URL 白名单（拒绝 https/外网/userinfo 冒充）、任务 ID、
 *     敏感键识别、argv 打码；
 *   - app_ctl_call：真 /bin/true /bin/false、stderr 捕获、stdin、超时
 *     SIGKILL、argv 逐项 execv（printf 注入串不被 shell 解释）；
 *   - app_ctl_probe：curl（CLI 有 / HTTP 无）+ 真 python3 -m http.server
 *     （CLI + HTTP 200）；
 *   - app_ctl_task：真 tar 打包/列目录/解包/diff/cat 六步任务（有依赖、
 *     有断言）；中途 cat 不存在文件 → 失败即停并回报原始 stderr；sleep 30
 *     运行中从另一进程 action=cancel → 进程组被杀、cancel 标记清理；
 *   - 审计：每次 call 写 backend/target/argv/rc/耗时，敏感值打码。
 *
 * --emit DIR：把 probe/成功任务/失败任务/取消任务输出与进度、audit.log、
 *   环境信息写到 DIR（W82 证据目录）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "../tools/tool_registry.h"
#include "../tools/app_ctl.h"

static int fails;
static int checks;
static int skips;
static char g_state[1024];
static char g_work[1024];

static char *g_probe_curl;
static char *g_probe_http;
static char *g_task_ok;
static char *g_task_fail;
static char *g_task_cancel;
static const char *g_emit;

#define CHECK(cond, msg) do { \
	checks++; \
	if (cond) { \
		printf("ok %s\n", msg); \
	} else { \
		printf("FAIL %s\n", msg); \
		fails++; \
	} \
} while (0)

#define SKIP(msg, why) do { \
	printf("skip %s（%s）\n", msg, why); \
	skips++; \
} while (0)

static int tool_call(const char *name, const char *args, char **out, int *rc)
{
	struct ai_tool t;

	memset(&t, 0, sizeof(t));
	t.name = (char *)name;
	t.channel = TOOL_CH_APPCTL;
	*out = NULL;
	*rc = exec_app_ctl_channel(&t, args, out);
	return *rc;
}

static int find_prog(const char *const *cands, char *out, size_t cap)
{
	int i;

	for (i = 0; cands[i]; i++) {
		if (access(cands[i], X_OK) == 0) {
			snprintf(out, cap, "%s", cands[i]);
			return 0;
		}
	}
	return -1;
}

static int mkdirs(const char *path)
{
	char tmp[1024];
	size_t i;

	snprintf(tmp, sizeof(tmp), "%s", path);
	for (i = 1; tmp[i]; i++) {
		if (tmp[i] != '/')
			continue;
		tmp[i] = '\0';
		if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
			return -1;
		tmp[i] = '/';
	}
	if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

static int write_text(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	if (fd < 0)
		return -1;
	(void)!write(fd, text, strlen(text));
	close(fd);
	return 0;
}

static int copy_file(const char *src, const char *dst)
{
	int in = open(src, O_RDONLY);
	int out;
	char buf[8192];
	ssize_t n;

	if (in < 0)
		return -1;
	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (out < 0) {
		close(in);
		return -1;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		if (write(out, buf, (size_t)n) != n)
			break;
	}
	close(in);
	close(out);
	return 0;
}

static char *read_all(const char *path)
{
	int fd = open(path, O_RDONLY);
	char *buf;
	size_t cap = 8192, len = 0;

	if (fd < 0)
		return NULL;
	buf = malloc(cap);
	if (!buf) {
		close(fd);
		return NULL;
	}
	for (;;) {
		ssize_t n;

		if (len == cap) {
			char *nb = realloc(buf, cap * 2);

			if (!nb) {
				free(buf);
				close(fd);
				return NULL;
			}
			buf = nb;
			cap *= 2;
		}
		n = read(fd, buf + len, cap - len);
		if (n <= 0)
			break;
		len += (size_t)n;
	}
	buf[len] = '\0';
	close(fd);
	return buf;
}

static void emit_text(const char *name, const char *text)
{
	char path[1200];

	if (!g_emit || !text)
		return;
	snprintf(path, sizeof(path), "%s/%s", g_emit, name);
	write_text(path, text);
}

static void emit_copy(const char *name, const char *src)
{
	char path[1200];

	if (!g_emit)
		return;
	snprintf(path, sizeof(path), "%s/%s", g_emit, name);
	copy_file(src, path);
}

/* ===================== 纯函数 ===================== */

static void test_pure(void)
{
	CHECK(ac_url_loopback("http://127.0.0.1:8080/x") == 1, "url-v4-ok");
	CHECK(ac_url_loopback("http://localhost/x") == 1, "url-localhost-ok");
	CHECK(ac_url_loopback("http://LOCALHOST:80/") == 1, "url-localhost-case");
	CHECK(ac_url_loopback("http://[::1]:9000/x") == 1, "url-v6-bracket");
	CHECK(ac_url_loopback("http://::1/x") == 1, "url-v6-raw");
	CHECK(ac_url_loopback("https://127.0.0.1/") == 0, "url-reject-https");
	CHECK(ac_url_loopback("http://example.com/") == 0, "url-reject-external");
	CHECK(ac_url_loopback("http://127.0.0.1.evil.com/") == 0,
	      "url-reject-suffix");
	CHECK(ac_url_loopback("http://localhost.evil.com/") == 0,
	      "url-reject-localhost-suffix");
	CHECK(ac_url_loopback("http://127.0.0.1@evil.com/") == 0,
	      "url-reject-userinfo");
	CHECK(ac_url_loopback("http://evil.com#@127.0.0.1/") == 0,
	      "url-reject-fragment-trick");
	CHECK(ac_url_loopback("http://192.168.1.1/") == 0, "url-reject-lan");
	CHECK(ac_url_loopback("ftp://127.0.0.1/") == 0, "url-reject-scheme");
	CHECK(ac_url_loopback("") == -1, "url-empty");

	CHECK(ac_task_id_valid("tar-roundtrip") == 1, "taskid-ok");
	CHECK(ac_task_id_valid("a.b_c-9") == 1, "taskid-dots");
	CHECK(ac_task_id_valid("") == 0, "taskid-empty");
	CHECK(ac_task_id_valid(".") == 0, "taskid-dot");
	CHECK(ac_task_id_valid("..") == 0, "taskid-dotdot");
	CHECK(ac_task_id_valid("a/b") == 0, "taskid-slash");
	CHECK(ac_task_id_valid("a b") == 0, "taskid-space");
	{
		char big[100];

		memset(big, 'a', sizeof(big) - 1);
		big[sizeof(big) - 1] = '\0';
		CHECK(ac_task_id_valid(big) == 0, "taskid-too-long");
	}

	CHECK(ac_key_sensitive("password") == 1, "key-password");
	CHECK(ac_key_sensitive("--api-key") == 1, "key-api-key");
	CHECK(ac_key_sensitive("access_token") == 1, "key-token");
	CHECK(ac_key_sensitive("X-Auth-Token") == 1, "key-auth-token");
	CHECK(ac_key_sensitive("username") == 0, "key-username");
	CHECK(ac_key_sensitive("--output") == 0, "key-output");

	{
		char *av[] = { "--password=hunter2", "--token", "s3cr3t",
			       "--output=/tmp/x", "PLAIN=1" };
		char *m = ac_mask_argv_json(av, 5);

		CHECK(m && strstr(m, "--password=***") != NULL, "mask-eq");
		CHECK(m && strstr(m, "\"--token\",\"***\"") != NULL,
		      "mask-next");
		CHECK(m && strstr(m, "hunter2") == NULL &&
		      strstr(m, "s3cr3t") == NULL, "mask-no-secret");
		CHECK(m && strstr(m, "--output=/tmp/x") != NULL &&
		      strstr(m, "PLAIN=1") != NULL, "mask-keep-normal");
		free(m);
	}
}

/* ===================== call ===================== */

static void test_call_cli(void)
{
	char *out = NULL;
	int rc;
	char truep[256], falsep[256], catp[256], printfp[256], sleepp[256];
	const char *const tc[] = { "/usr/bin/true", "/bin/true", NULL };
	const char *const fc[] = { "/usr/bin/false", "/bin/false", NULL };
	const char *const cc[] = { "/usr/bin/cat", "/bin/cat", NULL };
	const char *const pc[] = { "/usr/bin/printf", "/bin/printf", NULL };
	const char *const sc[] = { "/usr/bin/sleep", "/bin/sleep", NULL };

	if (find_prog(tc, truep, sizeof(truep)) != 0 ||
	    find_prog(fc, falsep, sizeof(falsep)) != 0 ||
	    find_prog(cc, catp, sizeof(catp)) != 0 ||
	    find_prog(pc, printfp, sizeof(printfp)) != 0 ||
	    find_prog(sc, sleepp, sizeof(sleepp)) != 0) {
		SKIP("call-cli", "缺少 true/false/cat/printf/sleep");
		return;
	}

	tool_call("app_ctl_call",
		  "{\"backend\":\"cli\",\"program\":\"/bin/true\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "\"rc\":0") != NULL &&
	      strstr(out, "\"ok\":true") != NULL, "call-true-rc0");
	free(out);

	out = NULL;
	tool_call("app_ctl_call",
		  "{\"backend\":\"cli\",\"program\":\"/bin/false\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "\"rc\":1") != NULL &&
	      strstr(out, "\"ok\":false") != NULL, "call-false-rc1");
	free(out);

	out = NULL;
	tool_call("app_ctl_call",
		  "{\"backend\":\"cli\",\"program\":\"/usr/bin/cat\","
		  "\"argv\":[\"no-such-file-w82\"]}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "\"rc\":1") != NULL &&
	      strstr(out, "no-such-file-w82") != NULL &&
	      strstr(out, "\"stderr\":\"") != NULL, "call-stderr");
	free(out);

	out = NULL;
	tool_call("app_ctl_call",
		  "{\"backend\":\"cli\",\"program\":\"/usr/bin/printf\","
		  "\"argv\":[\"%s\",\"hello-stdin\"]}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "\"stdout\":\"hello-stdin\"") != NULL,
	      "call-stdout");
	free(out);

	out = NULL;
	tool_call("app_ctl_call",
		  "{\"backend\":\"cli\",\"program\":\"/usr/bin/cat\","
		  "\"stdin\":\"piped-w82\\n\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "\"stdout\":\"piped-w82\\n\"") != NULL,
	      "call-stdin");
	free(out);

	/* 子进程不读 stdin 就退出：不得因 SIGPIPE 杀掉调用方 */
	out = NULL;
	tool_call("app_ctl_call",
		  "{\"backend\":\"cli\",\"program\":\"/bin/true\","
		  "\"stdin\":\"ignored\"}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "\"rc\":0") != NULL,
	      "call-stdin-early-exit");
	free(out);

	/* argv 逐项 execv：分号/反引号/$(...) 不得被 shell 解释 */
	unlink("/tmp/w82-appctl-pwned");
	out = NULL;
	tool_call("app_ctl_call",
		  "{\"backend\":\"cli\",\"program\":\"/usr/bin/printf\","
		  "\"argv\":[\"%s\",\"; touch /tmp/w82-appctl-pwned; `id` $(id)\"]}",
		  &out, &rc);
	CHECK(rc == 0 && out &&
	      strstr(out, "\"stdout\":\"; touch /tmp/w82-appctl-pwned; `id` $(id)\"")
	      != NULL,
	      "call-no-shell-expansion");
	CHECK(access("/tmp/w82-appctl-pwned", F_OK) != 0, "call-no-side-effect");
	free(out);

	out = NULL;
	tool_call("app_ctl_call",
		  "{\"backend\":\"cli\",\"program\":\"/usr/bin/sleep\","
		  "\"argv\":[\"3\"],\"timeout_s\":1}", &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "\"timed_out\":true") != NULL &&
	      strstr(out, "\"rc\":-1") != NULL, "call-timeout");
	free(out);

	out = NULL;
	tool_call("app_ctl_call",
		  "{\"backend\":\"http\",\"url\":\"http://example.com/\"}",
		  &out, &rc);
	CHECK(rc == AI_ERR_INVALID_ARG && out &&
	      strstr(out, "仅允许") != NULL, "call-http-external-reject");
	free(out);

	out = NULL;
	tool_call("app_ctl_call", "{\"backend\":\"cli\"}", &out, &rc);
	CHECK(rc == AI_ERR_INVALID_ARG && out &&
	      strstr(out, "需要 program") != NULL, "call-missing-program");
	free(out);

	/* 审计：敏感值打码 */
	out = NULL;
	tool_call("app_ctl_call",
		  "{\"backend\":\"cli\",\"program\":\"/usr/bin/printf\","
		  "\"argv\":[\"%s\",\"--password=hunter2\"]}", &out, &rc);
	free(out);
	out = NULL;
	tool_call("app_ctl_call",
		  "{\"backend\":\"cli\",\"program\":\"/usr/bin/printf\","
		  "\"argv\":[\"%s %s\",\"--token\",\"s3cr3t\"]}", &out, &rc);
	free(out);
	{
		char audit[1200];
		char *txt;

		snprintf(audit, sizeof(audit), "%s/audit.log", g_state);
		txt = read_all(audit);
		CHECK(txt && strstr(txt, "app_ctl_call backend=cli") != NULL &&
		      strstr(txt, "target=/usr/bin/printf") != NULL &&
		      strstr(txt, "rc=0") != NULL &&
		      strstr(txt, "duration_ms=") != NULL, "audit-fields");
		CHECK(txt && strstr(txt, "--password=***") != NULL, "audit-mask-eq");
		CHECK(txt && strstr(txt, "\"--token\",\"***\"") != NULL,
		      "audit-mask-next");
		CHECK(txt && strstr(txt, "hunter2") == NULL &&
		      strstr(txt, "s3cr3t") == NULL, "audit-no-secret");
		free(txt);
	}
}

/* ===================== HTTP 真服务 + probe ===================== */

struct http_srv {
	pid_t pid;
	int port;
};

static int connect_ok(int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa;
	int ok;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((unsigned short)port);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ok = connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0;
	close(fd);
	return ok;
}

static int start_http_server(const char *py, const char *dir,
			     struct http_srv *srv)
{
	int fd, port;
	struct sockaddr_in sa;
	socklen_t slen = sizeof(sa);
	pid_t pid;
	int i;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = 0;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
	    getsockname(fd, (struct sockaddr *)&sa, &slen) != 0) {
		close(fd);
		return -1;
	}
	port = ntohs(sa.sin_port);
	close(fd);

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		int dn = open("/dev/null", O_WRONLY);
		char portstr[16];

		if (dn >= 0) {
			dup2(dn, 1);
			dup2(dn, 2);
		}
		snprintf(portstr, sizeof(portstr), "%d", port);
		execl(py, "python3", "-m", "http.server", portstr,
		      "--bind", "127.0.0.1", "--directory", dir,
		      (char *)NULL);
		_exit(127);
	}
	for (i = 0; i < 60; i++) {
		if (connect_ok(port)) {
			srv->pid = pid;
			srv->port = port;
			return 0;
		}
		usleep(50 * 1000);
	}
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	return -1;
}

static void test_http_and_probe(void)
{
	char curlp[256], pyp[256];
	const char *const cc[] = { "/usr/bin/curl", "/bin/curl", NULL };
	const char *const pc[] = { "/usr/bin/python3", "/usr/bin/python3.10",
				   "/usr/bin/python3.11",
				   "/usr/bin/python3.12", NULL };
	char *out = NULL;
	int rc;

	if (find_prog(cc, curlp, sizeof(curlp)) == 0) {
		tool_call("app_ctl_probe", "{\"app\":\"curl\"}", &out, &rc);
		CHECK(rc == 0 && out && strstr(out, "\"tool\":\"app_ctl_probe\"") != NULL,
		      "probe-curl-json");
		CHECK(out && strstr(out, "\"backends\":[\"cli\"]") != NULL,
		      "probe-curl-backends-cli-only");
		CHECK(out && strstr(out, "\"call_supported\":{\"cli\":true,"
				    "\"http\":true,\"dbus\":false}") != NULL,
		      "probe-call-supported");
		CHECK(out && strstr(out, "\"http\":{\"available\":false") != NULL,
		      "probe-curl-no-http");
		CHECK(out && strstr(out, "\"found\":true") != NULL &&
		      strstr(out, "\"help_ok\":true") != NULL,
		      "probe-curl-help");
		CHECK(out && strstr(out, "\"at_spi\":{") != NULL &&
		      strstr(out, "\"implemented\":false") != NULL,
		      "probe-atspi-probe-only");
		free(g_probe_curl);
		g_probe_curl = out;
		out = NULL;
	} else {
		SKIP("probe-curl", "curl 不存在");
	}

	{
		char miss[512];

		snprintf(miss, sizeof(miss),
			 "{\"app\":\"/nonexistent/w82-app\"}");
		tool_call("app_ctl_probe", miss, &out, &rc);
		CHECK(rc == 0 && out && strstr(out, "\"found\":false") != NULL &&
		      strstr(out, "\"backends\":[]") != NULL,
		      "probe-missing-app");
		free(out);
		out = NULL;
	}

	if (find_prog(pc, pyp, sizeof(pyp)) != 0) {
		SKIP("probe-python-http", "python3 不存在");
		return;
	}
	{
		struct http_srv srv;
		char dir[1024];
		char args[1024];

		snprintf(dir, sizeof(dir), "%s/http", g_work);
		mkdirs(dir);
		{
			char f[1200];

			snprintf(f, sizeof(f), "%s/hello.txt", dir);
			write_text(f, "hello-http\n");
		}
		if (start_http_server(pyp, dir, &srv) != 0) {
			SKIP("probe-python-http", "无法启动 python3 -m http.server");
			return;
		}
		snprintf(args, sizeof(args),
			 "{\"app\":\"%s\",\"argv\":[\"-m\",\"http.server\","
			 "\"%d\"],\"http_ports\":[%d]}", pyp, srv.port,
			 srv.port);
		tool_call("app_ctl_probe", args, &out, &rc);
		CHECK(rc == 0 && out &&
		      strstr(out, "\"backends\":[\"cli\",\"http\"]") != NULL,
		      "probe-http-backends");
		CHECK(out && strstr(out, "\"status_code\":200") != NULL,
		      "probe-http-status");
		CHECK(out && strstr(out, "\"reachable\":true") != NULL,
		      "probe-http-reachable");
		free(g_probe_http);
		g_probe_http = out;
		out = NULL;

		{
			char cargs[512];

			snprintf(cargs, sizeof(cargs),
				 "{\"backend\":\"http\",\"method\":\"GET\","
				 "\"url\":\"http://127.0.0.1:%d/hello.txt\"}",
				 srv.port);
			tool_call("app_ctl_call", cargs, &out, &rc);
			CHECK(rc == 0 && out &&
			      strstr(out, "\"status_code\":200") != NULL &&
			      strstr(out, "\"body\":\"hello-http\\n\"") != NULL,
			      "call-http-get");
			free(out);
			out = NULL;
		}
		kill(srv.pid, SIGTERM);
		waitpid(srv.pid, NULL, 0);
		CHECK(!connect_ok(srv.port), "http-server-no-residue");
	}
}

/* ===================== task ===================== */

static void build_tar_task(char *buf, size_t cap, const char *workdir,
			   const char *task_id)
{
	snprintf(buf, cap,
		"{\"task_id\":\"%s\",\"workdir\":\"%s\",\"steps\":["
		"{\"name\":\"pack\",\"call\":{\"backend\":\"cli\","
		"\"program\":\"/usr/bin/tar\",\"argv\":[\"-czf\","
		"\"archive.tgz\",\"-C\",\"src\",\".\"]},"
		"\"assert\":{\"rc\":0,\"file_exists\":\"archive.tgz\","
		"\"file_min_size\":[{\"path\":\"archive.tgz\",\"min\":50}]}},"
		"{\"name\":\"list\",\"call\":{\"backend\":\"cli\","
		"\"program\":\"/usr/bin/tar\",\"argv\":[\"-tzf\","
		"\"archive.tgz\"]},\"assert\":{\"rc\":0,\"stdout_contains\":"
		"[\"a.txt\",\"sub/b.txt\"]}},"
		"{\"name\":\"mkdir\",\"call\":{\"backend\":\"cli\","
		"\"program\":\"/usr/bin/mkdir\",\"argv\":[\"dest\"]},"
		"\"assert\":{\"rc\":0}},"
		"{\"name\":\"extract\",\"call\":{\"backend\":\"cli\","
		"\"program\":\"/usr/bin/tar\",\"argv\":[\"-xzf\","
		"\"archive.tgz\",\"-C\",\"dest\"]},"
		"\"assert\":{\"rc\":0,\"file_exists\":[\"dest/a.txt\","
		"\"dest/sub/b.txt\"]}},"
		"{\"name\":\"diff\",\"call\":{\"backend\":\"cli\","
		"\"program\":\"/usr/bin/diff\",\"argv\":[\"-r\",\"src\","
		"\"dest\"]},\"assert\":{\"rc\":0}},"
		"{\"name\":\"cat\",\"call\":{\"backend\":\"cli\","
		"\"program\":\"/usr/bin/cat\",\"argv\":[\"dest/a.txt\"]},"
		"\"assert\":{\"rc\":0,\"stdout_matches\":\"hello-w82\","
		"\"file_contains\":[{\"path\":\"dest/a.txt\","
		"\"text\":\"hello-w82\"}]}}"
		"]}", task_id, workdir);
}

static void test_task_ok(void)
{
	char *out = NULL;
	int rc;
	char task[8192];
	char path[1200];
	char *progress;

	snprintf(g_work, sizeof(g_work), "%s/task-ok", g_state);
	mkdirs(g_work);
	{
		char src[1200], sub[1200], f[1300];

		snprintf(src, sizeof(src), "%s/src", g_work);
		mkdirs(src);
		snprintf(sub, sizeof(sub), "%s/src/sub", g_work);
		mkdirs(sub);
		snprintf(f, sizeof(f), "%s/a.txt", src);
		write_text(f, "hello-w82\n");
		snprintf(f, sizeof(f), "%s/sub/b.txt", src);
		write_text(f, "second-w82\n");
	}
	build_tar_task(task, sizeof(task), g_work, "w82-tar-ok");
	tool_call("app_ctl_task", task, &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "\"status\":\"ok\"") != NULL,
	      "task-ok-status");
	CHECK(out && strstr(out, "\"executed_steps\":6") != NULL &&
	      strstr(out, "\"failed_step\":null") != NULL,
	      "task-ok-steps");
	CHECK(out && strstr(out, "\"name\":\"pack\"") != NULL &&
	      strstr(out, "\"name\":\"extract\"") != NULL &&
	      strstr(out, "\"name\":\"diff\"") != NULL,
	      "task-ok-names");
	CHECK(out && strstr(out, "dest/sub/b.txt") != NULL &&
	      strstr(out, "\"file_exists\"") != NULL,
	      "task-ok-assertions");
	{
		char a[1300], d[1300];

		snprintf(a, sizeof(a), "%s/archive.tgz", g_work);
		snprintf(d, sizeof(d), "%s/dest/a.txt", g_work);
		CHECK(access(a, R_OK) == 0 && access(d, R_OK) == 0,
		      "task-ok-artifacts");
	}
	snprintf(path, sizeof(path), "%s/w82-tar-ok.progress.jsonl", g_state);
	progress = read_all(path);
	CHECK(progress && strstr(progress, "\"event\":\"task_start\"") != NULL &&
	      strstr(progress, "\"event\":\"step_start\"") != NULL &&
	      strstr(progress, "\"event\":\"step_done\"") != NULL &&
	      strstr(progress, "\"event\":\"task_done\"") != NULL &&
	      strstr(progress, "\"status\":\"ok\"") != NULL,
	      "task-ok-progress");
	free(progress);
	free(g_task_ok);
	g_task_ok = out;
	out = NULL;

	tool_call("app_ctl_task",
		  "{\"task_id\":\"w82-tar-ok\",\"steps\":[]}", &out, &rc);
	CHECK(rc == AI_ERR_INVALID_ARG && out &&
	      strstr(out, "至少 1 步") != NULL, "task-empty-reject");
	free(out);
	out = NULL;

	tool_call("app_ctl_task",
		  "{\"task_id\":\"bad/id\",\"steps\":[]}", &out, &rc);
	CHECK(rc == AI_ERR_INVALID_ARG && out &&
	      strstr(out, "task_id") != NULL, "task-bad-id");
	free(out);
	out = NULL;

	tool_call("app_ctl_task",
		  "{\"task_id\":\"yaml-w82\",\"task\":\"steps: []\","
		  "\"action\":\"run\"}", &out, &rc);
	CHECK(rc == AI_ERR_INVALID_ARG && out &&
	      strstr(out, "YAML") != NULL, "task-yaml-honest-error");
	free(out);
	out = NULL;
}

static void test_task_fail(void)
{
	char *out = NULL;
	int rc;
	char task[4096];
	char f[1200];
	char *progress;

	snprintf(f, sizeof(f), "%s/never-created", g_work);
	unlink(f);
	snprintf(task, sizeof(task),
		"{\"task_id\":\"w82-fail\",\"workdir\":\"%s\",\"steps\":["
		"{\"name\":\"ok1\",\"call\":{\"backend\":\"cli\","
		"\"program\":\"/usr/bin/cat\",\"argv\":[\"src/a.txt\"]},"
		"\"assert\":{\"rc\":0}},"
		"{\"name\":\"boom\",\"call\":{\"backend\":\"cli\","
		"\"program\":\"/usr/bin/cat\",\"argv\":[\"no-such-file-w82\"]},"
		"\"assert\":{\"rc\":0}},"
		"{\"name\":\"never\",\"call\":{\"backend\":\"cli\","
		"\"program\":\"/usr/bin/touch\",\"argv\":[\"never-created\"]},"
		"\"assert\":{\"rc\":0}}]}", g_work);
	tool_call("app_ctl_task", task, &out, &rc);
	CHECK(rc != 0 && out && strstr(out, "\"status\":\"failed\"") != NULL,
	      "task-fail-status");
	CHECK(out && strstr(out, "\"failed_step\":1") != NULL &&
	      strstr(out, "\"executed_steps\":2") != NULL,
	      "task-fail-stops-at-step1");
	CHECK(out && strstr(out, "no-such-file-w82") != NULL &&
	      strstr(out, "\"stderr\":\"") != NULL,
	      "task-fail-raw-stderr");
	CHECK(out && strstr(out, "\"name\":\"never\"") == NULL,
	      "task-fail-step3-not-run");
	CHECK(access(f, F_OK) != 0, "task-fail-no-side-effect");
	snprintf(f, sizeof(f), "%s/w82-fail.progress.jsonl", g_state);
	progress = read_all(f);
	CHECK(progress && strstr(progress, "\"status\":\"failed\"") != NULL &&
	      strstr(progress, "\"failed_step\":1") != NULL,
	      "task-fail-progress");
	free(progress);
	free(g_task_fail);
	g_task_fail = out;
	out = NULL;
}

static int wait_progress(const char *path, const char *needle, int ms)
{
	int i;

	for (i = 0; i < ms / 50; i++) {
		char *txt = read_all(path);

		if (txt) {
			int ok = strstr(txt, needle) != NULL;

			free(txt);
			if (ok)
				return 1;
		}
		usleep(50 * 1000);
	}
	return 0;
}

static long json_long(const char *s, const char *key)
{
	char pat[64];
	const char *p;

	snprintf(pat, sizeof(pat), "\"%s\":", key);
	p = strstr(s ? s : "", pat);
	if (!p)
		return -1;
	return atol(p + strlen(pat));
}

static void test_task_cancel(void)
{
	char progress[1200], cancel_args[512], outfile[1200];
	pid_t child;
	int status = 0, done = 0, i;
	char *out = NULL;
	int rc;
	char *child_out;
	long pid = -1;

	snprintf(progress, sizeof(progress), "%s/w82-cancel.progress.jsonl",
		 g_state);
	unlink(progress);
	snprintf(outfile, sizeof(outfile), "%s/w82-cancel-out.json", g_state);
	unlink(outfile);
	fflush(NULL);
	child = fork();
	if (child == 0) {
		char *cout = NULL;
		int crc;
		int fd;

		tool_call("app_ctl_task",
			"{\"task_id\":\"w82-cancel\",\"steps\":["
			"{\"name\":\"sleepy\",\"call\":{\"backend\":\"cli\","
			"\"program\":\"/usr/bin/sleep\",\"argv\":[\"30\"]},"
			"\"assert\":{\"rc\":0}}]}", &cout, &crc);
		fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);

		if (fd >= 0) {
			if (cout)
				(void)!write(fd, cout, strlen(cout));
			close(fd);
		}
		free(cout);
		_exit(crc == 0 ? 0 : 3);
	}
	CHECK(wait_progress(progress, "\"event\":\"step_start\"", 5000),
	      "cancel-step-started");
	{
		char pidf[1200];
		int i, up = 0;

		snprintf(pidf, sizeof(pidf), "%s/w82-cancel.child", g_state);
		for (i = 0; i < 100; i++) {
			if (access(pidf, F_OK) == 0) {
				up = 1;
				break;
			}
			usleep(50 * 1000);
		}
		CHECK(up, "cancel-child-pid-present");
	}

	snprintf(cancel_args, sizeof(cancel_args),
		 "{\"action\":\"status\",\"task_id\":\"w82-cancel\"}");
	tool_call("app_ctl_task", cancel_args, &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "\"pid_alive\":true") != NULL &&
	      strstr(out, "step_start") != NULL, "cancel-status-running");
	free(out);
	out = NULL;

	snprintf(cancel_args, sizeof(cancel_args),
		 "{\"action\":\"cancel\",\"task_id\":\"w82-cancel\"}");
	tool_call("app_ctl_task", cancel_args, &out, &rc);
	CHECK(rc == 0 && out && strstr(out, "\"killed\":true") != NULL &&
	      strstr(out, "\"pid_alive_after\":false") != NULL,
	      "cancel-killed");
	pid = json_long(out, "pid");
	free(out);
	out = NULL;

	for (i = 0; i < 100; i++) {
		pid_t w = waitpid(child, &status, WNOHANG);

		if (w == child) {
			done = 1;
			break;
		}
		usleep(50 * 1000);
	}
	CHECK(done && WIFEXITED(status) && WEXITSTATUS(status) == 3,
	      "cancel-task-returned");
	if (!done) {
		kill(child, SIGKILL);
		waitpid(child, &status, 0);
	}
	if (pid > 0) {
		char procf[64];

		snprintf(procf, sizeof(procf), "/proc/%ld", pid);
		CHECK(kill((pid_t)pid, 0) != 0 && errno == ESRCH &&
		      access(procf, F_OK) != 0, "cancel-no-process-residue");
	}
	{
		char cf[1200];

		snprintf(cf, sizeof(cf), "%s/w82-cancel.cancel", g_state);
		CHECK(access(cf, F_OK) != 0, "cancel-marker-cleaned");
		snprintf(cf, sizeof(cf), "%s/w82-cancel.child", g_state);
		CHECK(access(cf, F_OK) != 0, "cancel-pidfile-cleaned");
	}
	child_out = read_all(outfile);
	CHECK(child_out && strstr(child_out, "\"status\":\"canceled\"") != NULL &&
	      strstr(child_out, "\"canceled_at_step\":0") != NULL &&
	      strstr(child_out, "\"canceled\":true") != NULL,
	      "cancel-task-status");
	free(g_task_cancel);
	g_task_cancel = child_out;

	{
		char *prog = read_all(progress);

		CHECK(prog && strstr(prog, "\"event\":\"cancel_request\"") != NULL &&
		      strstr(prog, "\"event\":\"task_done\"") != NULL &&
		      strstr(prog, "\"status\":\"canceled\"") != NULL,
		      "cancel-progress");
		free(prog);
	}
	out = NULL;
	tool_call("app_ctl_task",
		  "{\"action\":\"cancel\",\"task_id\":\"no-such-task-w82\"}",
		  &out, &rc);
	CHECK(rc == AI_ERR_NOT_FOUND && out &&
	      strstr(out, "NOT_FOUND") != NULL, "cancel-not-found");
	free(out);
}

/* ===================== 注册表 ===================== */

static void test_registry(void)
{
	struct tool_registry reg;
	char *err = NULL;
	const struct ai_tool *t;

	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	if (tool_registry_load(&reg, &err) != 0) {
		printf("FAIL registry-load: %s\n", err ? err : "?");
		fails++;
		free(err);
		return;
	}
	CHECK(reg.tool_count == 220, "registry-220");
	t = tool_registry_find(&reg, "app_ctl_probe");
	CHECK(t && t->channel == TOOL_CH_APPCTL && t->risk &&
	      strcmp(t->risk, TOOL_RISK_R) == 0, "registry-probe-R");
	t = tool_registry_find(&reg, "app_ctl_call");
	CHECK(t && t->channel == TOOL_CH_APPCTL && t->risk &&
	      strcmp(t->risk, TOOL_RISK_W2) == 0, "registry-call-W2");
	t = tool_registry_find(&reg, "app_ctl_task");
	CHECK(t && t->channel == TOOL_CH_APPCTL && t->risk &&
	      strcmp(t->risk, TOOL_RISK_W2) == 0, "registry-task-W2");
	CHECK(tool_channel_from_str("appctl") == TOOL_CH_APPCTL,
	      "registry-channel-str");
	tool_registry_free(&reg);
}

/* ===================== 证据 ===================== */

static void emit_evidence(void)
{
	char path[1200];
	char *audit;
	char envbuf[2048];
	char timeline[16384];

	if (!g_emit)
		return;
	if (mkdir(g_emit, 0755) != 0 && errno != EEXIST)
		return;
	emit_text("probe-curl.json", g_probe_curl);
	emit_text("probe-http.json", g_probe_http);
	emit_text("task-success.json", g_task_ok);
	emit_text("task-fail.json", g_task_fail);
	emit_text("task-cancel.json", g_task_cancel);
	snprintf(path, sizeof(path), "%s/w82-tar-ok.progress.jsonl", g_state);
	emit_copy("task-success.progress.jsonl", path);
	snprintf(path, sizeof(path), "%s/w82-fail.progress.jsonl", g_state);
	emit_copy("task-fail.progress.jsonl", path);
	snprintf(path, sizeof(path), "%s/w82-cancel.progress.jsonl", g_state);
	emit_copy("task-cancel.progress.jsonl", path);
	snprintf(path, sizeof(path), "%s/audit.log", g_state);
	emit_copy("audit.log", path);

	audit = read_all(path);
	snprintf(timeline, sizeof(timeline),
		 "W82a appctl evidence\n"
		 "state=%s\nwork=%s\n"
		 "checks=%d fails=%d skips=%d\n\n"
		 "== audit.log ==\n%s\n", g_state, g_work, checks, fails,
		 skips, audit ? audit : "(missing)");
	emit_text("timeline.txt", timeline);
	free(audit);

	snprintf(envbuf, sizeof(envbuf),
		 "uid=%d\ncwd=", (int)geteuid());
	if (getcwd(envbuf + strlen(envbuf),
		   sizeof(envbuf) - strlen(envbuf)) == NULL)
		strncat(envbuf, "?", sizeof(envbuf) - strlen(envbuf) - 1);
	strncat(envbuf, "\nstate=", sizeof(envbuf) - strlen(envbuf) - 1);
	strncat(envbuf, g_state, sizeof(envbuf) - strlen(envbuf) - 1);
	strncat(envbuf, "\nwork=", sizeof(envbuf) - strlen(envbuf) - 1);
	strncat(envbuf, g_work, sizeof(envbuf) - strlen(envbuf) - 1);
	strncat(envbuf, "\n", sizeof(envbuf) - strlen(envbuf) - 1);
	emit_text("env.txt", envbuf);

}

int main(int argc, char **argv)
{
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--emit") == 0 && i + 1 < argc)
			g_emit = argv[++i];
	}
	{
		char tmpl[] = "/tmp/aik-appctl-test-XXXXXX";

		if (!mkdtemp(tmpl)) {
			printf("FAIL mkdtemp: %s\n", strerror(errno));
			return 1;
		}
		snprintf(g_state, sizeof(g_state), "%s", tmpl);
	}
	setenv("AIKERNEL_APPCTL_DIR", g_state, 1);
	snprintf(g_work, sizeof(g_work), "%s", g_state);
	mkdirs(g_work);

	printf("== W82 appctl tests (state=%s) ==\n", g_state);
	test_pure();
	test_call_cli();
	test_http_and_probe();
	test_task_ok();
	test_task_fail();
	test_task_cancel();
	test_registry();
	emit_evidence();

	printf("\nSUMMARY: checks=%d fails=%d skips=%d\n", checks, fails,
	       skips);
	free(g_probe_curl);
	free(g_probe_http);
	free(g_task_ok);
	free(g_task_fail);
	free(g_task_cancel);
	return fails ? 1 : 0;
}
