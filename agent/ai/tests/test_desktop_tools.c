// SPDX-License-Identifier: GPL-2.0
/*
 * test_desktop_tools.c - W76 桌面能力面工具层回归
 *
 * 覆盖：
 *   - 注册表 156 件 / desktop 通道 20 件 / 每件 risk 与 D 级；
 *   - tool_channel_from_str("desktop")；
 *   - D0/D1 无租约自动放行，真实走本机 mock HTTP；
 *   - D2 在 NONE 下 CONFIRM_REQUIRED（非 TTY，且不发起 HTTP）；
 *   - D2 在 -y 短租约/显式 D2 租约下放行；
 *   - D3 power：NONE/-y 都要确认，显式 D3 租约放行后后端 501 仍如实
 *     报 unavailable（不得伪造成功）；
 *   - 参数形状校验（非法 app/id/theme、注入字符转义）；
 *   - 后端不可达 / 非 loopback URL / 4xx 的结构化错误。
 *
 * 依赖：真 executor/tool_registry/ai_lease/local_http/ai_user_policy；
 * netlink/SME/策略交互桩来自 test_sandbox_stubs.c（-DW42_REAL_POLICY）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>

#include "policy/ai_lease.h"
#include "policy/ai_user_policy.h"
#include "tools/executor.h"
#include "tools/tool_registry.h"
#include "ai_json_util.h"
#include "ai_trace.h"

static int g_pass;
static int g_fail;

static void expect(int cond, const char *fmt, ...)
{
	va_list ap;

	printf("%s: ", cond ? "PASS" : "FAIL");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	if (cond)
		g_pass++;
	else
		g_fail++;
}

/* ------------------------------------------------------------------ mock */
#define MOCK_REQ_MAX 64

static int g_listen_fd = -1;
static int g_port;
static volatile int g_stop;
static pthread_t g_thread;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_req_count;
static char g_last_method[16];
static char g_last_path[256];
static char g_last_body[8192];

static int send_all_fd(int fd, const char *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t w = send(fd, buf + off, len - off, 0);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		off += (size_t)w;
	}
	return 0;
}

static void mock_handle(int fd)
{
	char req[16384];
	size_t off = 0, clen = 0, body_off = 0;
	char *hdr_end = NULL;
	char method[16] = "", path[256] = "", body[8192] = "";
	int status = 200;
	const char *resp = "{\"ok\":true}";
	char out[9000];

	for (;;) {
		ssize_t n = recv(fd, req + off, sizeof(req) - 1 - off, 0);

		if (n <= 0)
			break;
		off += (size_t)n;
		req[off] = '\0';
		hdr_end = strstr(req, "\r\n\r\n");
		if (hdr_end)
			break;
		if (off >= sizeof(req) - 1)
			break;
	}
	if (!hdr_end) {
		close(fd);
		return;
	}
	sscanf(req, "%15s %255s", method, path);
	{
		const char *cl = strcasestr(req, "Content-Length:");

		if (cl)
			clen = (size_t)strtoul(cl + 15, NULL, 10);
	}
	body_off = (size_t)(hdr_end + 4 - req);
	/* Content-Length body 可能分多次到达：补齐后再处理 */
	while (clen > 0 && body_off + clen > off && off < sizeof(req) - 1) {
		ssize_t n = recv(fd, req + off, sizeof(req) - 1 - off, 0);

		if (n <= 0)
			break;
		off += (size_t)n;
		req[off] = '\0';
	}
	if (clen > 0 && clen < sizeof(body) && body_off + clen <= off) {
		memcpy(body, req + body_off, clen);
		body[clen] = '\0';
	}

	pthread_mutex_lock(&g_lock);
	g_req_count++;
	snprintf(g_last_method, sizeof(g_last_method), "%s", method);
	snprintf(g_last_path, sizeof(g_last_path), "%s", path);
	snprintf(g_last_body, sizeof(g_last_body), "%s", body);
	pthread_mutex_unlock(&g_lock);

	if (strcmp(method, "GET") == 0 && strcmp(path, "/api/health") == 0) {
		resp = "{\"ok\":true,\"service\":\"img1\",\"desktop\":"
		       "{\"backend\":\"web-demo\",\"power\":\"unavailable\"}}";
	} else if (strcmp(method, "GET") == 0 &&
		   strcmp(path, "/api/windows") == 0) {
		resp = "{\"mode\":\"desktop\",\"count\":1,\"focused\":"
		       "\"w-0001\",\"windows\":[{\"id\":\"w-0001\","
		       "\"title\":\"Settings\",\"focused\":true}]}";
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/api/theme") == 0) {
		resp = "{\"ok\":true,\"current\":\"light\"}";
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/api/input") == 0) {
		resp = "{\"ok\":true,\"window_id\":\"w-0001\","
		       "\"text_after\":\"hello\"}";
	} else if (strcmp(method, "POST") == 0 &&
		   strcmp(path, "/api/power") == 0) {
		status = 501;
		resp = "{\"ok\":false,\"available\":false,\"executed\":false,"
		       "\"backend\":\"unavailable\",\"error\":\"power backend "
		       "unavailable\"}";
	}

	snprintf(out, sizeof(out),
		 "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\n"
		 "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
		 status, status == 200 ? "OK" : "Not Implemented",
		 strlen(resp), resp);
	send_all_fd(fd, out, strlen(out));
	close(fd);
}

static void *mock_thread(void *arg)
{
	(void)arg;
	while (!g_stop) {
		struct pollfd pfd = { g_listen_fd, POLLIN, 0 };
		int pr = poll(&pfd, 1, 100);

		if (pr <= 0)
			continue;
		{
			int fd = accept(g_listen_fd, NULL, NULL);

			if (fd >= 0)
				mock_handle(fd);
		}
	}
	return NULL;
}

static int mock_start(void)
{
	struct sockaddr_in sa;
	socklen_t sl = sizeof(sa);
	int one = 1;

	g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (g_listen_fd < 0)
		return -1;
	setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	if (bind(g_listen_fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
		return -1;
	if (listen(g_listen_fd, 16) != 0)
		return -1;
	if (getsockname(g_listen_fd, (struct sockaddr *)&sa, &sl) != 0)
		return -1;
	g_port = ntohs(sa.sin_port);
	if (pthread_create(&g_thread, NULL, mock_thread, NULL) != 0)
		return -1;
	return 0;
}

static void mock_stop(void)
{
	g_stop = 1;
	pthread_join(g_thread, NULL);
	close(g_listen_fd);
	g_listen_fd = -1;
}

static void mock_reset(void)
{
	pthread_mutex_lock(&g_lock);
	g_req_count = 0;
	g_last_method[0] = '\0';
	g_last_path[0] = '\0';
	g_last_body[0] = '\0';
	pthread_mutex_unlock(&g_lock);
}

static int mock_hits(void)
{
	int n;

	pthread_mutex_lock(&g_lock);
	n = g_req_count;
	pthread_mutex_unlock(&g_lock);
	return n;
}

/* --------------------------------------------------------------- helpers */
static struct tool_registry g_reg;
static char g_base[1024];
static char g_lease_dir[1200];

static int run_tool(const char *name, const char *args, char **out)
{
	const struct ai_tool *t = tool_registry_find(&g_reg, name);
	int ok = 0;

	*out = NULL;
	if (!t) {
		*out = strdup("missing tool");
		return -1;
	}
	tool_executor_run(t, args, out, &ok);
	return ok ? 0 : -1;
}

static void lease_none(void)
{
	char err[256];

	ai_lease_ctx_init(NULL, 0, getuid(), err, sizeof(err));
}

static void lease_ephemeral(void)
{
	char err[256];

	ai_lease_ctx_init(NULL, 1, getuid(), err, sizeof(err));
}

static int write_text(const char *path, const char *text, mode_t mode)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
	size_t off = 0, len = strlen(text);

	if (fd < 0)
		return -1;
	while (off < len) {
		ssize_t w = write(fd, text + off, len - off);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		off += (size_t)w;
	}
	close(fd);
	return 0;
}

static int make_lease(const char *id, const char *ceiling)
{
	char path[2048], json[2048], expires[64], principal[64];
	time_t now = time(NULL) + 3600;
	struct tm tmv;
	struct passwd *pw = getpwuid(getuid());

	snprintf(principal, sizeof(principal), "%s",
		 pw ? pw->pw_name : (getuid() == 0 ? "root" : "unknown"));
	gmtime_r(&now, &tmv);
	strftime(expires, sizeof(expires), "%Y-%m-%dT%H:%M:%SZ", &tmv);
	snprintf(json, sizeof(json),
		 "{\"lease_id\":\"%s\",\"principal\":\"%s\","
		 "\"subject\":\"root-ai\",\"scope\":[\"desktop\"],"
		 "\"risk_ceiling\":\"%s\",\"mission\":\"W76 desktop test\","
		 "\"expires_at\":\"%s\",\"revocable\":true}",
		 id, principal, ceiling, expires);
	snprintf(path, sizeof(path), "%s/%s.json", g_lease_dir, id);
	return write_text(path, json, 0600);
}

static int load_lease(const char *id)
{
	char err[256];

	return ai_lease_ctx_init(id, 0, getuid(), err, sizeof(err));
}

static const char *classify(const char *tool, const char *risk,
			    char **target)
{
	char *why = NULL;

	return ai_danger_name(ai_danger_classify(tool, "desktop", risk, "{}",
						 target, (const char **)&why));
}

/* ------------------------------------------------------------------ main */
int main(void)
{
	char tmpl[] = "/tmp/w76deskXXXXXX";
	char home[2048], confirm[2048], trace[2048], pol[2048], url[300];
	char *err = NULL, *out = NULL;
	FILE *fp;
	int i;

	/* 强制非 TTY：D2/D3 走 CONFIRM_REQUIRED 而不是交互阻塞 */
	if (!freopen("/dev/null", "r", stdin)) {
		perror("freopen stdin");
		return 2;
	}

	if (!mkdtemp(tmpl)) {
		perror("mkdtemp");
		return 2;
	}
	snprintf(g_base, sizeof(g_base), "%s", tmpl);
	snprintf(home, sizeof(home), "%s/home", g_base);
	snprintf(g_lease_dir, sizeof(g_lease_dir), "%s/leases", g_base);
	snprintf(confirm, sizeof(confirm), "%s/confirm", g_base);
	snprintf(trace, sizeof(trace), "%s/trace", g_base);
	mkdir(home, 0700);
	mkdir(g_lease_dir, 0700);
	mkdir(confirm, 0700);
	mkdir(trace, 0700);

	setenv("HOME", home, 1);
	setenv("AIKERNEL_LEASE_DIR", g_lease_dir, 1);
	setenv("AIKERNEL_CONFIRM_DIR", confirm, 1);
	setenv("AIKERNEL_TRACE_DIR", trace, 1);
	setenv("AIKERNEL_TRACE_ENABLED", "1", 1);
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	unsetenv("AIKERNEL_SANDBOX");
	unsetenv("AIKERNEL_CONFIRM_NONCE");

	snprintf(pol, sizeof(pol), "%s/policy.conf", g_base);
	fp = fopen(pol, "w");
	if (!fp) {
		perror("policy.conf");
		return 2;
	}
	fprintf(fp, "[root]\nmode = privileged\n[default]\nmode = privileged\n");
	fclose(fp);
	setenv("AIKERNEL_POLICY", pol, 1);
	ai_policy_init(NULL);
	ai_trace_init(NULL, 0);

	if (mock_start() != 0) {
		perror("mock_start");
		return 2;
	}
	snprintf(url, sizeof(url), "http://127.0.0.1:%d", g_port);
	setenv("AIKERNEL_DESKTOP_URL", url, 1);

	if (tool_registry_load(&g_reg, &err) != 0) {
		printf("FATAL: tool_registry_load: %s\n", err ? err : "?");
		free(err);
		return 2;
	}

	printf("== test_desktop_tools (uid=%u, mock=%s) ==\n",
	       (unsigned)getuid(), url);

	/* ---- 1. 注册表 ---- */
	expect(g_reg.tool_count == 156, "注册表总数 156（实际 %d）",
	       g_reg.tool_count);
	expect(tool_channel_from_str("desktop") == TOOL_CH_DESKTOP,
	       "tool_channel_from_str(\"desktop\") 映射");
	{
		int desktop_n = 0, routes = 0;
		const struct ai_tool *t;

		for (i = 0; i < g_reg.tool_count; i++)
			if (g_reg.tools[i].channel == TOOL_CH_DESKTOP)
				desktop_n++;
		expect(desktop_n == 20, "desktop 通道 20 件（实际 %d）",
		       desktop_n);
		for (i = 0; i < 20; i++)
			if (tool_registry_find(&g_reg, (const char *[]){
				"desktop_health", "desktop_stats",
				"desktop_apps_list", "desktop_windows_list",
				"desktop_theme_get", "desktop_wallpaper_get",
				"desktop_notifications_list",
				"desktop_screenshot", "desktop_clipboard_get",
				"desktop_theme_set", "desktop_wallpaper_set",
				"desktop_notifications_send",
				"desktop_apps_launch", "desktop_windows_focus",
				"desktop_windows_close", "desktop_apps_close",
				"desktop_input_type", "desktop_input_key",
				"desktop_clipboard_set", "desktop_power"}[i]))
				routes++;
		expect(routes == 20, "20 件 desktop 工具名全部存在（实际 %d）",
		       routes);
		t = tool_registry_find(&g_reg, "desktop_health");
		expect(t && strcmp(t->risk, "R") == 0, "health risk=R");
		t = tool_registry_find(&g_reg, "desktop_theme_set");
		expect(t && strcmp(t->risk, "W1") == 0, "theme.set risk=W1");
		t = tool_registry_find(&g_reg, "desktop_windows_close");
		expect(t && strcmp(t->risk, "W2") == 0, "windows.close risk=W2");
		t = tool_registry_find(&g_reg, "desktop_input_type");
		expect(t && strcmp(t->risk, "W2") == 0, "input.type risk=W2");
		t = tool_registry_find(&g_reg, "desktop_clipboard_set");
		expect(t && strcmp(t->risk, "W2") == 0, "clipboard.set risk=W2");
		t = tool_registry_find(&g_reg, "desktop_power");
		expect(t && strcmp(t->risk, "W2") == 0, "power risk=W2");
		t = tool_registry_find(&g_reg, "desktop_health");
		expect(t && t->sub_count == 1 && strcmp(t->sub[0], "desktop") == 0,
		       "desktop 工具 sub=desktop");
	}

	/* ---- 2. D0-D3 分级 ---- */
	{
		struct { const char *name; const char *risk; const char *want; }
		cases[] = {
			{ "desktop_health", "R", "D0" },
			{ "desktop_stats", "R", "D0" },
			{ "desktop_apps_list", "R", "D0" },
			{ "desktop_windows_list", "R", "D0" },
			{ "desktop_theme_get", "R", "D0" },
			{ "desktop_wallpaper_get", "R", "D0" },
			{ "desktop_notifications_list", "R", "D0" },
			{ "desktop_screenshot", "R", "D0" },
			{ "desktop_clipboard_get", "R", "D0" },
			{ "desktop_theme_set", "W1", "D1" },
			{ "desktop_wallpaper_set", "W1", "D1" },
			{ "desktop_notifications_send", "W1", "D1" },
			{ "desktop_apps_launch", "W1", "D1" },
			{ "desktop_windows_focus", "W1", "D1" },
			{ "desktop_windows_close", "W2", "D2" },
			{ "desktop_apps_close", "W2", "D2" },
			{ "desktop_input_type", "W2", "D2" },
			{ "desktop_input_key", "W2", "D2" },
			{ "desktop_clipboard_set", "W2", "D2" },
			{ "desktop_power", "W2", "D3" },
		};
		int bad = 0;

		for (i = 0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++) {
			char *target = NULL;
			const char *d = classify(cases[i].name, cases[i].risk,
						 &target);

			free(target);
			if (strcmp(d, cases[i].want) != 0) {
				printf("  D 级不符: %s -> %s (want %s)\n",
				       cases[i].name, d, cases[i].want);
				bad++;
			}
		}
		expect(bad == 0, "20 件 D0/D1/D2/D3 分级全正确");
		expect(strcmp(classify("desktop_future_write", "W2", NULL),
			      "D2") == 0,
		       "未知 desktop_* 写 fail-closed → D2");
	}

	/* ---- 3. D0/D1 无租约自动放行 ---- */
	lease_none();
	mock_reset();
	out = NULL;
	expect(run_tool("desktop_health", "{}", &out) == 0,
	       "D0 health 无租约放行");
	expect(out && strstr(out, "\"power\":\"unavailable\""),
	       "D0 health 返回后端能力（power unavailable）");
	free(out);
	expect(mock_hits() == 1, "D0 实际发起 1 次 HTTP（实际 %d）",
	       mock_hits());

	mock_reset();
	expect(run_tool("desktop_theme_set", "{\"name\":\"light\"}", &out) == 0,
	       "D1 theme.set 无租约自动放行");
	expect(out && strstr(out, "\"current\":\"light\""),
	       "D1 返回回读 current=light");
	free(out);
	{
		int hit = mock_hits();

		expect(hit == 1, "D1 实际发起 HTTP（实际 %d）", hit);
		pthread_mutex_lock(&g_lock);
		expect(strcmp(g_last_method, "POST") == 0 &&
		       strcmp(g_last_path, "/api/theme") == 0 &&
		       strstr(g_last_body, "\"light\""),
		       "D1 请求形状 POST /api/theme body=%s", g_last_body);
		pthread_mutex_unlock(&g_lock);
	}

	/* ---- 4. D2 NONE 确认，且不触达后端 ---- */
	lease_none();
	mock_reset();
	out = NULL;
	expect(run_tool("desktop_windows_close", "{\"id\":\"w-0001\"}",
			&out) != 0,
	       "D2 windows.close 在 NONE 下拒绝");
	expect(out && strstr(out, "CONFIRM_REQUIRED") &&
	       strstr(out, "\"danger\":\"D2\""),
	       "D2 返回 CONFIRM_REQUIRED danger=D2");
	free(out);
	expect(mock_hits() == 0, "D2 确认前未触达桌面后端（实际 %d）",
	       mock_hits());

	/* ---- 5. D2 -y 短租约放行 ---- */
	lease_ephemeral();
	mock_reset();
	out = NULL;
	expect(run_tool("desktop_windows_close", "{\"id\":\"w-0001\"}",
			&out) == 0,
	       "D2 在 -y 短租约下放行");
	free(out);
	expect(mock_hits() == 1, "D2 ephemeral 实际发起 HTTP");

	/* ---- 6. D2 显式租约放行；D3 越界拒绝 ---- */
	expect(make_lease("L-W76-D2", "D2") == 0, "签发测试 D2 租约");
	expect(load_lease("L-W76-D2") == 0, "加载显式 D2 租约");
	mock_reset();
	out = NULL;
	expect(run_tool("desktop_clipboard_set",
			"{\"text\":\"w76 clip\"}", &out) == 0,
	       "D2 clipboard.set 在显式 D2 租约下放行");
	free(out);
	expect(mock_hits() == 1, "D2 显式租约实际发起 HTTP");
	out = NULL;
	expect(run_tool("desktop_power", "{\"action\":\"reboot\"}", &out) != 0,
	       "D3 power 超出 D2 ceiling 被拒绝");
	expect(out && strstr(out, "lease_ceiling_denied"),
	       "D3 越界原因为 lease_ceiling_denied");
	free(out);

	/* ---- 7. D3 无租约/-y 必须确认；显式 D3 租约放行但后端 501 ---- */
	lease_none();
	mock_reset();
	out = NULL;
	expect(run_tool("desktop_power", "{\"action\":\"reboot\"}", &out) != 0,
	       "D3 power 在 NONE 下拒绝");
	expect(out && strstr(out, "CONFIRM_REQUIRED") &&
	       strstr(out, "\"danger\":\"D3\""),
	       "D3 返回 CONFIRM_REQUIRED danger=D3");
	free(out);
	expect(mock_hits() == 0, "D3 确认前未触达电源后端");

	lease_ephemeral();
	out = NULL;
	expect(run_tool("desktop_power", "{\"action\":\"reboot\"}", &out) != 0,
	       "D3 power 在 -y 下仍需确认（-y 只到 D2）");
	expect(out && strstr(out, "CONFIRM_REQUIRED"),
	       "-y 下 D3 仍 CONFIRM_REQUIRED");
	free(out);

	expect(make_lease("L-W76-D3", "D3") == 0, "签发测试 D3 租约");
	expect(load_lease("L-W76-D3") == 0, "加载显式 D3 租约");
	mock_reset();
	out = NULL;
	expect(run_tool("desktop_power", "{\"action\":\"reboot\"}", &out) != 0,
	       "D3 租约放行后后端 unavailable → 工具失败（不伪造成功）");
	expect(out && strstr(out, "E_DESKTOP_HTTP_501") &&
	       strstr(out, "\"available\":false"),
	       "D3 返回 E_DESKTOP_HTTP_501 + available=false");
	free(out);
	expect(mock_hits() == 1, "D3 确实请求到后端（未本地伪造）");

	/* ---- 8. 参数校验与注入转义 ---- */
	lease_none();
	mock_reset();
	expect(run_tool("desktop_theme_set",
			"{\"name\":\"../../etc\"}", &out) != 0,
	       "非法 theme name 被拒绝");
	expect(out && strstr(out, "E_PARAM_"), "非法 theme 返回 E_PARAM");
	free(out);
	expect(run_tool("desktop_apps_launch", "{}", &out) != 0,
	       "缺 app 参数被拒绝");
	expect(out && strstr(out, "E_PARAM_"), "缺 app 返回 E_PARAM");
	free(out);
	expect(run_tool("desktop_windows_focus", "{\"id\":\"../../x\"}",
			&out) != 0,
	       "非法 window id 被拒绝");
	free(out);
	expect(mock_hits() == 0, "非法参数未触达后端");

	out = NULL;
	expect(run_tool("desktop_input_type",
			"{\"text\":\"he\\\"llo\\nW76\"}", &out) != 0,
	       "D2 input.type 在 NONE 下拒绝");
	expect(out && strstr(out, "CONFIRM_REQUIRED"),
	       "D2 input.type 返回 CONFIRM_REQUIRED");
	free(out);
	{
		int hit = mock_hits();

		expect(hit == 0, "lease_none 下 D2 input.type 不应触达后端");
	}
	lease_ephemeral();
	mock_reset();
	out = NULL;
	expect(run_tool("desktop_input_type",
			"{\"text\":\"he\\\"llo\\nW76\"}", &out) == 0,
	       "D2 input.type 在 -y 下放行");
	free(out);
	pthread_mutex_lock(&g_lock);
	expect(strstr(g_last_body, "\\\"") != NULL &&
	       strstr(g_last_body, "\\n") != NULL,
	       "输入文本中的引号/换行被 JSON 转义: %s", g_last_body);
	pthread_mutex_unlock(&g_lock);

	/* ---- 9. 后端不可达 / 非 loopback URL ---- */
	lease_none();
	setenv("AIKERNEL_DESKTOP_URL", "http://127.0.0.1:1", 1);
	out = NULL;
	expect(run_tool("desktop_health", "{}", &out) != 0,
	       "后端不可达 → 工具失败");
	expect(out && strstr(out, "E_DESKTOP_UNAVAILABLE"),
	       "后端不可达返回 E_DESKTOP_UNAVAILABLE");
	free(out);
	setenv("AIKERNEL_DESKTOP_URL", "http://192.168.245.136:8091", 1);
	out = NULL;
	expect(run_tool("desktop_health", "{}", &out) != 0,
	       "非 loopback URL 被拒绝");
	expect(out && strstr(out, "E_DESKTOP_URL"),
	       "非 loopback 返回 E_DESKTOP_URL");
	free(out);
	setenv("AIKERNEL_DESKTOP_URL", url, 1);

	/* ---- 10. 清理 ---- */
	tool_registry_free(&g_reg);
	ai_trace_shutdown();
	ai_lease_ctx_reset();
	mock_stop();
	/* 证据保留：W76_EVIDENCE_DIR=/path 时复制 trace 与 audit 再清理 */
	{
		const char *keep = getenv("W76_EVIDENCE_DIR");

		if (keep && keep[0]) {
			char cmd[8192];

			snprintf(cmd, sizeof(cmd),
				 "mkdir -p '%s' && cp -a '%s/.' '%s/trace/' "
				 "2>/dev/null; cp -a '%s/.aikernel/audit.log' "
				 "'%s/audit.log' 2>/dev/null",
				 keep, trace, keep, home, keep);
			if (system(cmd) != 0)
				fprintf(stderr, "evidence copy failed\n");
		}
	}
	{
		char cmd[2048 + 32];

		snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_base);
		if (system(cmd) != 0)
			fprintf(stderr, "cleanup failed\n");
	}

	printf("== test_desktop_tools: %d PASS, %d FAIL ==\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}
