// SPDX-License-Identifier: GPL-2.0
/*
 * test_memory_api.c - W50 SME 完整记忆管理面回归（mock HTTP 服务）
 *
 * 覆盖 16 件新工具对应的客户端函数（另含既有 health/get/search 回归）：
 *   - 方法/路径/请求体编码断言（PATCH/DELETE/JSON 转义/URL 编码）；
 *   - 成功（2xx）、HTTP 404/500、连接失败降级三类返回路径；
 *   - 非法 ID、JSON 片段注入、缺参、路径白名单等前置拒绝（不触网）；
 *   - 导入文件（数组 / 导出对象）、遥测报告落盘；
 *   - tools.json 中 30 件 memory 工具的 risk 分级。
 *
 * 不连接真实 SME：本进程内 fork 一个 127.0.0.1 随机端口 mock 服务，
 * 请求日志写入临时文件供父进程逐条断言。VM 只读实测另由现场脚本完成。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ai_types.h"
#include "memory/sme_client.h"
#include "tools/tool_registry.h"

static int g_fail;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		g_fail++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

static char g_log_path[256];

/* ---------------- mock HTTP 服务（子进程） ---------------- */

static long header_content_length(const char *buf, const char *hend)
{
	const char *p = buf;
	size_t name_len = strlen("Content-Length:");
	int ci = 0;

	while (p < hend) {
		if ((ci ? (p[-1] == '\r' || p[-1] == '\n') : 1) &&
		    strncasecmp(p, "Content-Length:", name_len) == 0) {
			return strtol(p + name_len, NULL, 10);
		}
		p++;
		ci = 1;
	}
	return 0;
}

static void mock_serve(int lfd, int logfd)
{
	for (;;) {
		int cfd = accept(lfd, NULL, NULL);
		char buf[65536];
		char method[16], path[2048];
		size_t len = 0;
		ssize_t r;
		char *hend = NULL;
		long clen = 0;
		size_t hlen = 0, blen = 0;
		int code = 200;
		const char *body = "{\"ok\":true,\"mock\":\"w50-mock\"}";

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
			hend = strstr(buf, "\r\n\r\n");
			if (hend) {
				hlen = (size_t)(hend - buf) + 4;
				clen = header_content_length(buf, hend);
				if (len >= hlen + (size_t)clen)
					break;
			}
		}
		if (hend)
			blen = len > hlen ? len - hlen : 0;
		if ((size_t)clen > blen)
			blen = (size_t)clen;
		if (sscanf(buf, "%15s %2047s", method, path) != 2) {
			close(cfd);
			continue;
		}
		if (strstr(path, "missing")) {
			code = 404;
			body = "{\"detail\":\"memory not found\"}";
		} else if (strstr(path, "boom")) {
			code = 500;
			body = "{\"detail\":\"boom\"}";
		}
		dprintf(logfd, "%s %s\n%zu\n", method, path, blen);
		if (blen)
			(void)!write(logfd, hend + 4, blen);
		(void)!write(logfd, "\n", 1);
		dprintf(cfd,
			"HTTP/1.1 %d %s\r\n"
			"Content-Type: application/json\r\n"
			"Content-Length: %zu\r\n"
			"Connection: close\r\n\r\n%s",
			code, code == 200 ? "OK" :
			      code == 404 ? "Not Found" : "Internal Error",
			strlen(body), body);
		close(cfd);
	}
}

/* 启动 mock 服务：返回 pid 与端口（日志路径走 g_log_path） */
static pid_t mock_start(int *port)
{
	int lfd, logfd, one = 1;
	struct sockaddr_in sa;
	socklen_t sl = sizeof(sa);
	pid_t pid;

	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0)
		return -1;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
	    listen(lfd, 16) != 0) {
		close(lfd);
		return -1;
	}
	if (getsockname(lfd, (struct sockaddr *)&sa, &sl) != 0) {
		close(lfd);
		return -1;
	}
	*port = ntohs(sa.sin_port);

	snprintf(g_log_path, sizeof(g_log_path), "/tmp/w50-mem-%d.log",
		 (int)getpid());
	logfd = open(g_log_path, O_CREAT | O_TRUNC | O_WRONLY | O_APPEND, 0600);
	if (logfd < 0) {
		close(lfd);
		return -1;
	}
	pid = fork();
	if (pid < 0) {
		close(lfd);
		close(logfd);
		return -1;
	}
	if (pid == 0) {
		close(logfd);   /* 子进程重新打开只写追加，避免共享偏移 */
		logfd = open(g_log_path, O_WRONLY | O_APPEND);
		mock_serve(lfd, logfd);
		_exit(0);
	}
	close(logfd);
	close(lfd);
	return pid;
}

/* ---------------- 请求日志断言 ---------------- */

struct mock_req {
	char method[16];
	char path[2048];
	char body[16384];
};

static int load_requests(struct mock_req *r, int max)
{
	FILE *fp = fopen(g_log_path, "r");
	char line[4096];
	int n = 0;

	if (!fp)
		return -1;
	while (n < max && fgets(line, sizeof(line), fp)) {
		long len;

		if (sscanf(line, "%15s %2047s", r[n].method, r[n].path) != 2)
			break;
		if (!fgets(line, sizeof(line), fp))
			break;
		len = strtol(line, NULL, 10);
		if (len < 0 || len >= (long)sizeof(r[n].body))
			break;
		if (fread(r[n].body, 1, (size_t)len, fp) != (size_t)len)
			break;
		r[n].body[len] = '\0';
		(void)fgetc(fp);   /* 记录尾部换行 */
		n++;
	}
	fclose(fp);
	return n;
}

static int body_has(const struct mock_req *r, const char *needle)
{
	return strstr(r->body, needle) != NULL;
}

static int expect_req(const struct mock_req *all, int n, int idx,
		      const char *method, const char *path)
{
	if (idx >= n) {
		printf("FAIL: 请求 #%d 不存在（共 %d 条）\n", idx, n);
		g_fail++;
		return 0;
	}
	if (strcmp(all[idx].method, method) != 0 ||
	    strcmp(all[idx].path, path) != 0) {
		printf("FAIL: 请求 #%d 期望 %s %s，实际 %s %s\n", idx,
		       method, path, all[idx].method, all[idx].path);
		g_fail++;
		return 0;
	}
	printf("ok: 请求 #%d = %s %s\n", idx, method, path);
	return 1;
}

/* ---------------- 测试主体 ---------------- */

static void write_file(const char *path, const char *text)
{
	FILE *fp = fopen(path, "wb");

	if (!fp) {
		printf("FAIL: 无法写 %s\n", path);
		g_fail++;
		return;
	}
	fwrite(text, 1, strlen(text), fp);
	fclose(fp);
}

int main(void)
{
	char out[SME_OUT_BUF_MIN * 4];
	char url[128];
	struct mock_req reqs[64];
	char path1[128], path2[128], report_path[128];
	int port = 0;
	pid_t srv;
	int rc, nreq, i;
	struct tool_registry reg;
	char *err = NULL;

	setvbuf(stdout, NULL, _IONBF, 0);

	srv = mock_start(&port);
	CHECK(srv > 0 && port > 0, "mock SME 服务启动（127.0.0.1 随机端口）");
	if (srv <= 0)
		return 1;
	snprintf(url, sizeof(url), "http://127.0.0.1:%d", port);
	setenv("SME_URL", url, 1);

	/* ============ 1. 注册表：30 件 memory 工具 ============ */
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	memset(&reg, 0, sizeof(reg));
	CHECK(tool_registry_load(&reg, &err) == AI_OK,
	      "tools.json 加载（156 件口径）");
	CHECK(reg.tool_count == 156, "注册表总数 156");
	{
		int mem = 0;
		const struct ai_tool *t;

		for (i = 0; i < reg.tool_count; i++)
			if (reg.tools[i].channel == TOOL_CH_MEMORY)
				mem++;
		CHECK(mem == 30, "memory 通道工具数 = 30");
		t = tool_registry_find(&reg, "memory_delete");
		CHECK(t && strcmp(t->risk, "W2") == 0, "memory_delete risk=W2");
		t = tool_registry_find(&reg, "memory_update");
		CHECK(t && strcmp(t->risk, "W1") == 0, "memory_update risk=W1");
		t = tool_registry_find(&reg, "memory_graph");
		CHECK(t && strcmp(t->risk, "R") == 0, "memory_graph risk=R");
		t = tool_registry_find(&reg, "memory_config_check");
		CHECK(t && strcmp(t->risk, "R") == 0,
		      "memory_config_check risk=R");
	}
	tool_registry_free(&reg);

	/* ============ 2. 成功路径（逐条断言方法/路径/body） ============ */
	memset(out, 0, sizeof(out));
	rc = sme_health(out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"),
	      "health GET /health 成功");

	rc = sme_memory_get("m_abc", out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"), "memory_get 成功");

	{
		struct sme_update_opts o;

		memset(&o, 0, sizeof(o));
		o.text = "中文 \"引号\"\n第二行";
		o.metadata_json = "{\"src\":\"ask\"}";
		o.tags_json = "[\"a\",\"b\"]";
		o.has_importance = 1;
		o.importance = 0.75;
		o.has_weight = 1;
		o.weight = 2.5;
		o.summary = "摘要";
		rc = sme_memory_update("m_abc", &o, out, sizeof(out));
		CHECK(rc == AI_OK && strstr(out, "w50-mock"),
		      "memory_update PATCH 成功");
	}

	rc = sme_memory_delete("m_abc", out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"), "memory_delete DELETE 成功");

	{
		struct sme_add_opts o;

		memset(&o, 0, sizeof(o));
		o.text = "新记忆";
		o.metadata_json = "{\"k\":1}";
		o.tags_json = "[\"t1\"]";
		o.has_importance = 1;
		o.importance = 0.9;
		o.source = "llm";
		o.link_to = "m_prev";
		o.link_kind = "causes";
		o.ns = "w50";
		rc = sme_add_ex(&o, out, sizeof(out));
		CHECK(rc == AI_OK && strstr(out, "w50-mock"),
		      "memory_add ex 成功");
	}

	{
		struct sme_search_opts o;

		memset(&o, 0, sizeof(o));
		o.text = "查询";
		o.top_k = 7;
		o.top_regions = 3;
		o.metadata_filters_json = "{\"src\":\"ask\"}";
		o.tags_json = "[\"a\"]";
		o.region_retrieval = "hybrid";
		o.has_include_archived = 1;
		o.include_archived = 1;
		o.graph_expand = 2;
		o.ns = "w50";
		rc = sme_search_ex(&o, out, sizeof(out));
		CHECK(rc == AI_OK && strstr(out, "w50-mock"),
		      "memory_search_advanced 成功");
	}

	rc = sme_memories_batch("[{\"text\":\"a\"},{\"text\":\"b\"}]", out,
				sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"),
	      "memory_batch_add 成功");

	rc = sme_import("[{\"id\":\"m_i\",\"text\":\"导入\"}]", out,
			sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"), "memory_import 成功");

	snprintf(path1, sizeof(path1), "/tmp/w50-import-%d-a.json",
		 (int)getpid());
	snprintf(path2, sizeof(path2), "/tmp/w50-import-%d-b.json",
		 (int)getpid());
	write_file(path1, "[{\"id\":\"m_f\",\"text\":\"文件导入\"}]");
	write_file(path2, "{\"memories\":[{\"id\":\"m_g\",\"text\":\"对象\"}]}");
	rc = sme_import_path(path1, out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"),
	      "memory_import path（数组）成功");
	rc = sme_import_path(path2, out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"),
	      "memory_import path（导出对象）成功");

	rc = sme_graph(out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"), "memory_graph 成功");

	rc = sme_graph_link("m_a", "m_b", "causes", 1, 0.8, "备注", out,
			    sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"), "memory_link 成功");

	rc = sme_regions(out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"), "memory_regions 成功");

	rc = sme_regions_evolve(out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"),
	      "memory_regions_evolve 成功");

	rc = sme_facts(out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"), "memory_facts 成功");

	rc = sme_facts_history("中文 查询", "", out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"),
	      "memory_facts_history 成功");

	rc = sme_profile(out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"), "memory_profile 成功");

	rc = sme_qapairs(out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"), "memory_qapairs 成功");

	snprintf(report_path, sizeof(report_path), "/tmp/w50-report-%d.json",
		 (int)getpid());
	rc = sme_metrics_report(report_path, out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"),
	      "memory_metrics_report 成功");
	{
		FILE *fp = fopen(report_path, "rb");
		char buf[256] = { 0 };

		CHECK(fp != NULL, "遥测报告文件已落盘");
		if (fp) {
			size_t got = fread(buf, 1, sizeof(buf) - 1, fp);

			buf[got] = '\0';
			fclose(fp);
			CHECK(strstr(buf, "w50-mock") != NULL,
			      "报告文件内容 = 服务端响应体");
		}
	}

	rc = sme_config(out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"),
	      "memory_config_get 成功");

	rc = sme_config_check(0, out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"),
	      "memory_config_check(ping=false) 成功");
	rc = sme_config_check(1, out, sizeof(out));
	CHECK(rc == AI_OK && strstr(out, "w50-mock"),
	      "memory_config_check(ping=true) 成功");

	/* HTTP 错误路径（mock 按路径关键字返回 404/500） */
	rc = sme_memory_get("missing", out, sizeof(out));
	CHECK(rc == AI_ERR_API && strstr(out, "HTTP 404"),
	      "404 → AI_ERR_API 且保留状态码");
	rc = sme_memory_get("boom", out, sizeof(out));
	CHECK(rc == AI_ERR_API && strstr(out, "HTTP 500"),
	      "500 → AI_ERR_API 且保留状态码");

	/* ============ 3. 逐条请求断言 ============ */
	nreq = load_requests(reqs, 64);
	CHECK(nreq == 24, "mock 收到 24 条请求");
	if (nreq == 24) {
		char exp[256];

		expect_req(reqs, nreq, 0, "GET", "/health");
		expect_req(reqs, nreq, 1, "GET", "/memories/m_abc");
		expect_req(reqs, nreq, 2, "PATCH", "/memories/m_abc");
		CHECK(body_has(&reqs[2], "\"text\":\"中文 \\\"引号\\\"\\n第二行\""),
		      "PATCH body 中文/引号/换行正确转义");
		CHECK(body_has(&reqs[2], "\"metadata\":{\"src\":\"ask\"}") &&
		      body_has(&reqs[2], "\"tags\":[\"a\",\"b\"]") &&
		      body_has(&reqs[2], "\"importance\":0.75") &&
		      body_has(&reqs[2], "\"weight\":2.5") &&
		      body_has(&reqs[2], "\"summary\":\"摘要\""),
		      "PATCH body 携带全部更新字段");
		expect_req(reqs, nreq, 3, "DELETE", "/memories/m_abc");
		expect_req(reqs, nreq, 4, "POST", "/memories");
		CHECK(body_has(&reqs[4], "\"link_to\":\"m_prev\"") &&
		      body_has(&reqs[4], "\"link_kind\":\"causes\"") &&
		      body_has(&reqs[4], "\"ns\":\"w50\"") &&
		      body_has(&reqs[4], "\"source\":\"llm\""),
		      "POST /memories 携带 link/ns/source");
		expect_req(reqs, nreq, 5, "POST", "/memories/search");
		CHECK(body_has(&reqs[5], "\"top_regions\":3") &&
		      body_has(&reqs[5], "\"include_archived\":true") &&
		      body_has(&reqs[5], "\"graph_expand\":2") &&
		      body_has(&reqs[5], "\"region_retrieval\":\"hybrid\"") &&
		      body_has(&reqs[5], "\"metadata_filters\":{\"src\":\"ask\"}"),
		      "高级检索 body 携带组合参数");
		expect_req(reqs, nreq, 6, "POST", "/memories/batch");
		CHECK(body_has(&reqs[6], "\"memories\":[{\"text\":\"a\"}"),
		      "batch body 包裹 memories 数组");
		expect_req(reqs, nreq, 7, "POST", "/import");
		CHECK(body_has(&reqs[7], "\"id\":\"m_i\""),
		      "import body 保留 id");
		expect_req(reqs, nreq, 8, "POST", "/import");
		CHECK(body_has(&reqs[8], "\"id\":\"m_f\""),
		      "import path 数组文件已包裹");
		expect_req(reqs, nreq, 9, "POST", "/import");
		CHECK(body_has(&reqs[9], "\"id\":\"m_g\""),
		      "import path 导出对象原样传递");
		expect_req(reqs, nreq, 10, "GET", "/graph");
		expect_req(reqs, nreq, 11, "POST", "/graph/link");
		CHECK(body_has(&reqs[11], "\"a\":\"m_a\"") &&
		      body_has(&reqs[11], "\"b\":\"m_b\"") &&
		      body_has(&reqs[11], "\"kind\":\"causes\"") &&
		      body_has(&reqs[11], "\"weight\":0.8") &&
		      body_has(&reqs[11], "\"note\":\"备注\""),
		      "graph/link body 参数完整");
		expect_req(reqs, nreq, 12, "GET", "/regions");
		expect_req(reqs, nreq, 13, "POST", "/regions/evolve");
		expect_req(reqs, nreq, 14, "GET", "/facts");
		CHECK(strncmp(reqs[15].method, "GET", 4) == 0,
		      "请求 #15 = GET facts/history");
		snprintf(exp, sizeof(exp),
			 "/facts/history?text=%%E4%%B8%%AD%%E6%%96%%87%%20"
			 "%%E6%%9F%%A5%%E8%%AF%%A2&memory_id=");
		CHECK(strcmp(reqs[15].path, exp) == 0,
		      "facts/history 中文与空格已百分号编码");
		expect_req(reqs, nreq, 16, "GET", "/profile");
		expect_req(reqs, nreq, 17, "GET", "/qapairs");
		expect_req(reqs, nreq, 18, "GET", "/metrics/report");
		expect_req(reqs, nreq, 19, "GET", "/config");
		expect_req(reqs, nreq, 20, "POST", "/config/check");
		CHECK(strstr(reqs[20].body, "\"ping\":false") != NULL,
		      "config/check ping=false 编码");
		expect_req(reqs, nreq, 21, "POST", "/config/check");
		CHECK(strstr(reqs[21].body, "\"ping\":true") != NULL,
		      "config/check ping=true 编码");
		expect_req(reqs, nreq, 22, "GET", "/memories/missing");
		expect_req(reqs, nreq, 23, "GET", "/memories/boom");
	}

	/* ============ 4. 前置拒绝（不触网） ============ */
	rc = sme_memory_get("../etc/passwd", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "非法 ID（.. 穿越）拒绝");
	rc = sme_memory_update("../etc/passwd", NULL, out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "update 非法 ID 拒绝");
	rc = sme_memory_delete("a/b", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "delete 非法 ID 拒绝");
	rc = sme_graph_link("m_a", "x/y", NULL, 0, 0, NULL, out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "link 非法 ID 拒绝");

	{
		struct sme_add_opts o;

		memset(&o, 0, sizeof(o));
		o.text = "x";
		o.metadata_json = "{},";
		rc = sme_add_ex(&o, out, sizeof(out));
		CHECK(rc == AI_ERR_INVALID_ARG &&
		      strstr(out, "metadata") != NULL,
		      "metadata JSON 注入（尾部附加）拒绝");
	}
	{
		struct sme_add_opts o;

		memset(&o, 0, sizeof(o));
		o.text = "x";
		o.metadata_json = "{\"a\":1} trailing";
		rc = sme_add_ex(&o, out, sizeof(out));
		CHECK(rc == AI_ERR_INVALID_ARG, "metadata 尾部垃圾拒绝");
	}
	{
		struct sme_search_opts o;

		memset(&o, 0, sizeof(o));
		o.text = "x";
		o.tags_json = "[1],";
		rc = sme_search_ex(&o, out, sizeof(out));
		CHECK(rc == AI_ERR_INVALID_ARG && strstr(out, "tags") != NULL,
		      "tags JSON 注入拒绝");
	}
	{
		struct sme_update_opts o;

		memset(&o, 0, sizeof(o));
		rc = sme_memory_update("m_abc", &o, out, sizeof(out));
		CHECK(rc == AI_ERR_INVALID_ARG && strstr(out, "至少") != NULL,
		      "update 无字段拒绝");
	}
	{
		struct sme_search_opts o;

		memset(&o, 0, sizeof(o));
		rc = sme_search_ex(&o, out, sizeof(out));
		CHECK(rc == AI_ERR_INVALID_ARG, "高级检索缺 text 拒绝");
	}
	rc = sme_memories_batch("[] trailing", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "batch 数组尾部垃圾拒绝");
	rc = sme_import("{\"text\":\"x\"}", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "import 非数组拒绝");
	rc = sme_import_path("relative.json", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "import 相对路径拒绝");
	rc = sme_import_path("/etc/passwd", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "import 白名单外路径拒绝");
	rc = sme_import_path("/tmp/w50-no-such-import.json", out, sizeof(out));
	CHECK(rc == AI_ERR_NOT_FOUND, "import 不存在文件拒绝");
	rc = sme_facts_history("", "", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "facts/history 缺参拒绝");
	rc = sme_metrics_report("/etc/w50.json", out, sizeof(out));
	CHECK(rc == AI_ERR_INVALID_ARG, "metrics/report 白名单外拒绝");

	/* ============ 5. 连接失败降级 ============ */
	kill(srv, SIGKILL);
	waitpid(srv, NULL, 0);
	/* 端口 1 为保留端口：本机必然立即拒绝（现有 W43 用例同口径） */
	setenv("SME_URL", "http://127.0.0.1:1", 1);
	memset(out, 0, sizeof(out));
	rc = sme_health(out, sizeof(out));
	CHECK(rc == AI_ERR_NETWORK && strstr(out, "SME") != NULL,
	      "连接失败 → AI_ERR_NETWORK + 人可读错误");
	CHECK(sme_degrade_reason_of(rc) == SME_DEGRADED_UNAVAILABLE,
	      "降级原因码 = UNAVAILABLE");

	unlink(g_log_path);
	unlink(path1);
	unlink(path2);
	unlink(report_path);

	printf("\n%s\n", g_fail ? "test_memory_api: FAIL" :
			  "test_memory_api: ALL PASS");
	return g_fail ? 1 : 0;
}
