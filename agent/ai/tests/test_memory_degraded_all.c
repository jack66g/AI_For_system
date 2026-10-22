// SPDX-License-Identifier: GPL-2.0
/*
 * test_memory_degraded_all.c - W66 记忆面降级/边界回归
 *
 * 覆盖：
 *   1. SME 不可达时 30 件 memory_* 工具全部走真实执行器分发：
 *      返回 ERROR 文本 + 结构化降级附注，不崩溃、不挂死、不落盘；
 *   2. 空查询/缺参 → 结构化参数错误（不触网）；
 *   3. Unicode（中文+emoji）与 24KB 长文本查询 → 不崩溃，语义为网络错误；
 *   4. 导入/导出/报告路径白名单：/etc、.. 穿越、超大文件、非 JSON、NUL
 *      字节均在触网前拒绝；合法 /tmp 路径放行到网络段；
 *   5. 连接超时（接受连接但不响应）→ 健康检查 ≤7s 返回网络错误；
 *   6. HTTP 500 → AI_ERR_API + 可读 "HTTP 500"（降级原因映射 HTTP）；
 *   7. 记忆面失败后非记忆工具仍可执行（agent 仍可用）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ai_types.h"
#include "ai_lang.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"
#include "policy/ai_lease.h"
#include "memory/sme_client.h"

static int g_fail;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		g_fail++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

static double now_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

struct mem_case {
	const char *name;
	const char *args;
};

/* 30 件 memory_* 的最小合法参数（SME 不可达时都应在网络段失败）。 */
static const struct mem_case MEM_CASES[] = {
	{"memory_search", "{\"text\":\"W66 降级探测\"}"},
	{"memory_search_advanced", "{\"text\":\"W66\",\"top_k\":3}"},
	{"memory_add", "{\"text\":\"W66-degraded\"}"},
	{"memory_batch_add", "{\"memories\":\"[]\"}"},
	{"memory_stats", "{}"},
	{"memory_health", "{}"},
	{"memory_get", "{\"id\":\"m_w66test\"}"},
	{"memory_update", "{\"id\":\"m_w66test\",\"text\":\"W66 update\"}"},
	{"memory_delete", "{\"id\":\"m_w66test\"}"},
	{"memory_hit", "{\"id\":\"m_w66test\"}"},
	{"memory_archive", "{\"id\":\"m_w66test\"}"},
	{"memory_restore", "{\"id\":\"m_w66test\"}"},
	{"memory_import", "{\"memories\":\"[]\"}"},
	{"memory_facts_multi_hop", "{\"text\":\"W66\"}"},
	{"memory_graph", "{}"},
	{"memory_link", "{\"a\":\"m_w66a\",\"b\":\"m_w66b\"}"},
	{"memory_regions", "{}"},
	{"memory_regions_search", "{\"text\":\"W66\"}"},
	{"memory_regions_evolve", "{}"},
	{"memory_facts", "{}"},
	{"memory_facts_history", "{\"text\":\"W66\"}"},
	{"memory_profile", "{}"},
	{"memory_qapairs", "{}"},
	{"memory_consolidate", "{}"},
	{"memory_compress", "{}"},
	{"memory_export", "{\"path\":\"/tmp/w66-degraded-export.json\"}"},
	{"memory_metrics", "{}"},
	{"memory_metrics_report", "{\"path\":\"/tmp/w66-degraded-report.json\"}"},
	{"memory_config_get", "{}"},
	{"memory_config_check", "{\"ping\":false}"},
};

static int run_tool(struct tool_registry *reg, const char *name,
		    const char *args, char **out, int *ok, int *rc)
{
	const struct ai_tool *t = tool_registry_find(reg, name);

	*out = NULL;
	*ok = 0;
	*rc = AI_ERR_INVALID_ARG;
	if (!t)
		return 0;
	*rc = tool_executor_run(t, args, out, ok);
	return 1;
}

/* ---- 单连接假服务器 ---- */
struct one_shot {
	int listen_fd;
	int port;
	int do_hang;
};

static void *one_shot_thread(void *arg)
{
	struct one_shot *s = arg;
	int c = accept(s->listen_fd, NULL, NULL);

	if (c >= 0) {
		char buf[4096];

		recv(c, buf, sizeof(buf), 0);
		if (s->do_hang) {
			sleep(10);
		} else {
			static const char resp[] =
				"HTTP/1.1 500 Internal Server Error\r\n"
				"Content-Length: 5\r\n"
				"Connection: close\r\n\r\nboom\n";

			send(c, resp, sizeof(resp) - 1, 0);
		}
		close(c);
	}
	close(s->listen_fd);
	return NULL;
}

static int start_one_shot(struct one_shot *s, int do_hang, pthread_t *th)
{
	struct sockaddr_in a;
	socklen_t alen = sizeof(a);
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	int one = 1;

	if (fd < 0)
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.sin_port = 0;
	if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
		close(fd);
		return -1;
	}
	if (getsockname(fd, (struct sockaddr *)&a, &alen) != 0 ||
	    listen(fd, 4) != 0) {
		close(fd);
		return -1;
	}
	s->listen_fd = fd;
	s->port = ntohs(a.sin_port);
	s->do_hang = do_hang;
	if (pthread_create(th, NULL, one_shot_thread, s) != 0) {
		close(fd);
		return -1;
	}
	if (do_hang)
		pthread_detach(*th);
	return 0;
}

int main(void)
{
	struct tool_registry reg;
	char *err = NULL;
	char out[SME_OUT_BUF_MIN * 8];
	char *res = NULL;
	int ok = 0, rc, i, n_mem = 0;
	double t0, t1;
	const struct ai_tool *t;
	struct one_shot srv;
	pthread_t th;
	char url[128];
	char big_path[] = "/tmp/w66-import-big.json";
	char bad_path[] = "/tmp/w66-import-bad.json";
	char nul_path[] = "/tmp/w66-import-nul.json";
	char arr_path[] = "/tmp/w66-import-arr.json";

	setvbuf(stdout, NULL, _IONBF, 0);
	lang_set("zh");
	{
		char lerr[AI_LEASE_ERR_MAX] = "";

		/* W2 memory_* 工具需要 D2 预授权 */
		ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));
	}
	setenv("AIKERNEL_POLICY", "/dev/null", 1);
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	/* 端口 1 保留：本机立即拒绝，覆盖 30 次降级路径 */
	setenv("SME_URL", "http://127.0.0.1:1", 1);
	memset(&reg, 0, sizeof(reg));
	if (tool_registry_load(&reg, &err) != AI_OK) {
		printf("FATAL: tools.json load: %s\n", err ? err : "?");
		return 2;
	}

	printf("---- 1. 30 件 memory_* 全量降级 ----\n");
	for (i = 0; i < (int)(sizeof(MEM_CASES) / sizeof(MEM_CASES[0])); i++) {
		t = tool_registry_find(&reg, MEM_CASES[i].name);
		if (!t) {
			printf("FAIL: 工具缺失 %s\n", MEM_CASES[i].name);
			g_fail++;
			continue;
		}
		n_mem++;
		t0 = now_s();
		rc = tool_executor_run(t, MEM_CASES[i].args, &res, &ok);
		t1 = now_s();
		CHECK(rc == AI_OK && !ok && res,
		      "memory 工具分发返回失败结果");
		CHECK(res && strstr(res, "SME 服务不可达") != NULL,
		      "错误语义含「SME 服务不可达」");
		CHECK(res && strstr(res, "[SME 记忆服务不可达") != NULL,
		      "附注结构化降级说明");
		CHECK((t1 - t0) < 5.0, "拒绝连接快速失败（<5s）");
		free(res);
		res = NULL;
	}
	CHECK(n_mem == 30, "覆盖 30 件 memory_* 工具");
	CHECK(access("/tmp/w66-degraded-export.json", F_OK) != 0,
	      "SME 不可达时不产生导出文件");
	CHECK(access("/tmp/w66-degraded-report.json", F_OK) != 0,
	      "SME 不可达时不产生报告文件");

	printf("---- 2. 空查询/缺参结构化错误 ----\n");
	CHECK(run_tool(&reg, "memory_search", "{}", &res, &ok, &rc) &&
	      res && strstr(res, "缺少必填参数 text") != NULL,
	      "memory_search 缺 text → 参数错误");
	free(res);
	CHECK(run_tool(&reg, "memory_search", "{\"text\":\"\"}", &res, &ok, &rc) &&
	      res && strstr(res, "缺少必填参数 text") != NULL,
	      "memory_search 空 text → 参数错误");
	free(res);
	CHECK(run_tool(&reg, "memory_regions_search", "{}", &res, &ok, &rc) &&
	      res && strstr(res, "缺少必填参数 text") != NULL,
	      "memory_regions_search 空查询 → 参数错误");
	free(res);
	CHECK(run_tool(&reg, "memory_facts_history", "{}", &res, &ok, &rc) &&
	      res && strstr(res, "至少提供一个") != NULL,
	      "memory_facts_history 双空 → 参数错误");
	free(res);
	CHECK(run_tool(&reg, "memory_get", "{\"id\":\"../etc/passwd\"}",
		       &res, &ok, &rc) && res && !ok &&
	      (strstr(res, "id") != NULL || strstr(res, "非法") != NULL),
	      "memory_get 非法 id（路径穿越）被拒");
	free(res);

	printf("---- 3. Unicode / 24KB 长文本 ----\n");
	CHECK(run_tool(&reg, "memory_search", "{\"text\":\"记忆🧠测试\"}",
		       &res, &ok, &rc) && res && !ok &&
	      strstr(res, "SME 服务不可达") != NULL,
	      "Unicode 查询不崩溃且走网络降级");
	free(res);
	{
		size_t nchar = 8192, blen = nchar * 3 + 32;
		char *args = malloc(blen);
		char *p = args;

		p += sprintf(p, "{\"text\":\"");
		for (size_t k = 0; k < nchar; k++) {
			memcpy(p, "记", 3);
			p += 3;
		}
		sprintf(p, "\"}");
		CHECK(run_tool(&reg, "memory_search", args, &res, &ok, &rc) &&
		      res && !ok && strstr(res, "SME 服务不可达") != NULL,
		      "24KB 长文本不崩溃、不溢出");
		free(res);
		free(args);
		res = NULL;
	}

	printf("---- 4. 导入/导出路径白名单 ----\n");
	memset(out, 0, sizeof(out));
	rc = sme_export("/etc/w66-passwd", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG &&
	      (strstr(out, "/tmp") != NULL || strstr(out, "/var/ai") != NULL),
	      "export /etc 拒绝并提示白名单");
	rc = sme_export("/tmp/../etc/w66-passwd", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG && strstr(out, "..") != NULL,
	      "export .. 穿越拒绝");
	rc = sme_import_path("/etc/passwd", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG &&
	      (strstr(out, "/tmp") != NULL || strstr(out, "/var/ai") != NULL),
	      "import /etc 拒绝并提示白名单");
	rc = sme_import_path("/tmp/../etc/passwd", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG && strstr(out, "..") != NULL,
	      "import .. 穿越拒绝");
	rc = sme_import_path("/tmp/w66-no-such-file", out, sizeof(out));
	CHECK(rc == AI_ERR_NOT_FOUND, "import 不存在文件 → NOT_FOUND");
	rc = sme_metrics_report("/etc/w66-report.json", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "metrics_report /etc 拒绝");

	/* 超大文件 */
	{
		int fd = open(big_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);

		CHECK(fd >= 0, "创建 9MB 测试文件");
		if (fd >= 0) {
			CHECK(ftruncate(fd, 9 * 1024 * 1024) == 0,
			      "扩展 9MB 测试文件");
			close(fd);
		}
	}
	rc = sme_import_path(big_path, out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG && strstr(out, "文件大小非法") != NULL,
	      "import 9MB 文件拒绝");
	unlink(big_path);

	/* 非 JSON / NUL / 合法数组 */
	{
		FILE *fp = fopen(bad_path, "wb");

		if (fp) {
			fputs("not json\n", fp);
			fclose(fp);
		}
	}
	rc = sme_import_path(bad_path, out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG &&
	      strstr(out, "JSON") != NULL, "import 非 JSON 拒绝");
	unlink(bad_path);

	{
		FILE *fp = fopen(nul_path, "wb");

		if (fp) {
			fwrite("[]\0[]", 1, 5, fp);
			fclose(fp);
		}
	}
	rc = sme_import_path(nul_path, out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG && strstr(out, "NUL") != NULL,
	      "import 含 NUL 拒绝");
	unlink(nul_path);

	{
		FILE *fp = fopen(arr_path, "wb");

		if (fp) {
			fputs("[]", fp);
			fclose(fp);
		}
	}
	rc = sme_import_path(arr_path, out, sizeof(out));
	CHECK(rc == AI_ERR_NETWORK && strstr(out, "SME 服务不可达") != NULL,
	      "import 合法数组通过白名单后走网络降级");
	unlink(arr_path);

	printf("---- 5. 连接超时语义（接受但不响应） ----\n");
	memset(&srv, 0, sizeof(srv));
	if (start_one_shot(&srv, 1, &th) == 0) {
		snprintf(url, sizeof(url), "http://127.0.0.1:%d", srv.port);
		setenv("SME_URL", url, 1);
		t0 = now_s();
		rc = sme_health(out, sizeof(out));
		t1 = now_s();
		CHECK(rc == AI_ERR_NETWORK, "黑洞响应 → 网络错误");
		CHECK((t1 - t0) >= 2.0 && (t1 - t0) <= 7.0,
		      "健康检查按 3s 超时返回（2-7s）");
		CHECK(strstr(out, "SME 服务不可达") != NULL,
		      "超时返回可读降级说明");
	} else {
		printf("FAIL: 无法启动超时假服务器\n");
		g_fail++;
	}

	printf("---- 6. HTTP 500 语义 ----\n");
	memset(&srv, 0, sizeof(srv));
	if (start_one_shot(&srv, 0, &th) == 0) {
		snprintf(url, sizeof(url), "http://127.0.0.1:%d", srv.port);
		setenv("SME_URL", url, 1);
		rc = sme_stats(out, sizeof(out));
		CHECK(rc == AI_ERR_API && strstr(out, "HTTP 500") != NULL,
		      "HTTP 500 → AI_ERR_API + 可读状态码");
		CHECK(sme_degrade_reason_of(rc) == SME_DEGRADED_HTTP,
		      "HTTP 错误映射降级原因 HTTP");
		pthread_join(th, NULL);
	} else {
		printf("FAIL: 无法启动 500 假服务器\n");
		g_fail++;
	}

	printf("---- 7. 记忆面失败后 agent 仍可用 ----\n");
	setenv("SME_URL", "http://127.0.0.1:1", 1);
	CHECK(run_tool(&reg, "memory_stats", "{}", &res, &ok, &rc) &&
	      res && !ok, "memory_stats 失败");
	CHECK(tool_exec_memory_last_rc() == AI_ERR_NETWORK &&
	      sme_degrade_reason_of(tool_exec_memory_last_rc()) ==
	      SME_DEGRADED_UNAVAILABLE,
	      "memory 降级原因按真实返回码分类为 unavailable（W69 P2-3）");
	free(res);
	res = NULL;
	CHECK(run_tool(&reg, "sysctl_blacklist", "{}", &res, &ok, &rc) &&
	      res && ok, "非记忆工具 sysctl_blacklist 仍成功");
	free(res);

	printf("\n%s\n", g_fail ? "test_memory_degraded_all: FAIL" :
			  "test_memory_degraded_all: ALL PASS");
	return g_fail ? 1 : 0;
}
