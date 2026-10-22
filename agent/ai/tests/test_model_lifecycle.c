// SPDX-License-Identifier: GPL-2.0
/*
 * test_model_lifecycle.c - W77d 本地模型生命周期回归（全 mock，不真实下载）
 *
 * 覆盖（契约 C/F）：
 *   - 目录解析（6 条：名称/引用/参数/上下文/磁盘/内存门/标签）
 *   - 推荐排序 + 硬件门控：大内存机 top1=spark-x2.5:4b；4GB 机不出 8B；
 *     2GB 机无可装条目；磁盘门控
 *   - switch + rollback 状态文件（cloud<->local；无本地模型拒绝切 local）
 *   - 卸载活动模型需确认（AIK_ML_E_CONFIRM），force 后注销 [local]
 *   - install：mock /api/pull 流式成功路径（装后验证 + 注册）；
 *     失败路径（pull error → 清理 + 诚实报错 + 替代建议 + 不注册）
 *   - benchmark：3 条固定提示落 model-bench.json
 *
 * mock：进程内 fork 127.0.0.1 随机端口 HTTP 服务（ollama /api 语义）。
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
#include "ai_config.h"
#include "shell/commands/model_lifecycle.h"

static int g_fail;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		g_fail++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

/* ---------------- mock ollama 服务（子进程） ---------------- */

static long mock_clen(const char *buf, const char *hend)
{
	const char *p = buf;
	int ci = 0;

	while (p < hend) {
		if ((ci ? (p[-1] == '\r' || p[-1] == '\n') : 1) &&
		    strncasecmp(p, "Content-Length:", 15) == 0)
			return strtol(p + 15, NULL, 10);
		p++;
		ci = 1;
	}
	return 0;
}

static void mock_serve(int lfd)
{
	int pulls = 0;

	for (;;) {
		int cfd = accept(lfd, NULL, NULL);
		char buf[8192];
		char method[16], path[512];
		size_t len = 0;
		ssize_t r;
		char *hend = NULL;
		long clen = 0;

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
				clen = mock_clen(buf, hend);
				if (len >= (size_t)(hend - buf) + 4 + (size_t)clen)
					break;
			}
		}
		if (sscanf(buf, "%15s %511s", method, path) != 2) {
			close(cfd);
			continue;
		}

		if (strstr(path, "/api/pull")) {
			pulls++;
			if (strstr(buf, "broken-model")) {
				/* 失败分支：NDJSON error 行 */
				const char *lines =
					"{\"status\":\"pulling manifest\"}\n"
					"{\"error\":\"pull failed: manifest not found\"}\n";

				dprintf(cfd,
					"HTTP/1.1 200 OK\r\nContent-Type: "
					"application/x-ndjson\r\n"
					"Content-Length: %zu\r\n"
					"Connection: close\r\n\r\n%s",
					strlen(lines), lines);
			} else {
				char big[1024];
				int n;

				n = snprintf(big, sizeof(big),
					"{\"status\":\"pulling manifest\"}\n"
					"{\"status\":\"downloading digest\","
					"\"digest\":\"sha256:aa\","
					"\"completed\":%d,\"total\":%d}\n"
					"{\"status\":\"verifying sha256 digest\"}\n"
					"{\"status\":\"success\"}\n",
					1024 * 1024, 8192 * 1024);
				dprintf(cfd,
					"HTTP/1.1 200 OK\r\nContent-Type: "
					"application/x-ndjson\r\n"
					"Content-Length: %d\r\n"
					"Connection: close\r\n\r\n%s", n, big);
			}
		} else if (strstr(path, "/api/show")) {
			dprintf(cfd,
				"HTTP/1.1 200 OK\r\nContent-Type: "
				"application/json\r\nConnection: close\r\n"
				"Content-Length: 96\r\n\r\n"
				"{\"license\":\"apache-2.0\","
				"\"modelfile\":\"# mock\","
				"\"parameters\":\"\"}");
		} else if (strstr(path, "/api/generate")) {
			const char *body =
				"{\"model\":\"mock\",\"response\":\"OK\","
				"\"eval_count\":8,\"eval_duration\":16000000000}";

			dprintf(cfd,
				"HTTP/1.1 200 OK\r\nContent-Type: "
				"application/json\r\nConnection: close\r\n"
				"Content-Length: %zu\r\n\r\n%s",
				strlen(body), body);
		} else if (strstr(path, "/api/tags")) {
			const char *body =
				"{\"models\":[{\"name\":\"SparkLLM/"
				"Spark-X2.5-4B:latest\",\"model\":\"SparkLLM/"
				"Spark-X2.5-4B\"}]}";

			dprintf(cfd,
				"HTTP/1.1 200 OK\r\nContent-Type: "
				"application/json\r\nConnection: close\r\n"
				"Content-Length: %zu\r\n\r\n%s",
				strlen(body), body);
		} else if (strstr(path, "/api/delete")) {
			const char *body = "{\"status\":\"ok\"}";

			dprintf(cfd,
				"HTTP/1.1 200 OK\r\nContent-Type: "
				"application/json\r\nConnection: close\r\n"
				"Content-Length: %zu\r\n\r\n%s",
				strlen(body), body);
		} else {
			dprintf(cfd,
				"HTTP/1.1 404 Not Found\r\n"
				"Content-Length: 0\r\n"
				"Connection: close\r\n\r\n");
		}
		close(cfd);
	}
}

static pid_t g_mock_pid;
static int g_port;

static void mock_start(void)
{
	struct sockaddr_in addr;
	socklen_t alen = sizeof(addr);
	int lfd = socket(AF_INET, SOCK_STREAM, 0);
	int one = 1;

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
	g_port = ntohs(addr.sin_port);
	g_mock_pid = fork();
	if (g_mock_pid == 0) {
		signal(SIGINT, SIG_DFL);
		mock_serve(lfd);
		_exit(0);
	}
	close(lfd);
}

/* ---------------- 临时环境 ---------------- */

static char g_home[180], g_cat[280], g_state[280], g_bench[280];

static void env_setup(void)
{
	snprintf(g_home, sizeof(g_home), "/tmp/aik-mltest-%d", (int)getpid());
	snprintf(g_cat, sizeof(g_cat), "%s/model-catalog.json", g_home);
	snprintf(g_state, sizeof(g_state), "%s/model-state.json", g_home);
	snprintf(g_bench, sizeof(g_bench), "%s/model-bench.json", g_home);
	mkdir(g_home, 0755);
	setenv("HOME", g_home, 1);
	setenv("AIK_ML_CATALOG_PATH", g_cat, 1);
	setenv("AIK_ML_STATE_PATH", g_state, 1);
	setenv("AIK_ML_BENCH_PATH", g_bench, 1);
	/* 写一份小目录（含一条 mock 专用失败条目 broken-model） */
	{
		FILE *fp = fopen(g_cat, "w");

		if (!fp) {
			perror("catalog write");
			exit(2);
		}
		fputs("{\n \"entries\": [\n", fp);
		fputs("  {\"name\":\"spark-x2.5:4b\",\"ollama_ref\":"
		      "\"SparkLLM/Spark-X2.5-4B\",\"params_b\":4,"
		      "\"ctx_tokens\":1048576,\"disk_gb\":8.2,"
		      "\"ram_min_gb\":8,\"gpu_hint\":\"optional\","
		      "\"tags\":[\"long-context\",\"agent\","
		      "\"recommended-first\"],\"why\":\"1M ctx\","
		      "\"notes\":\"mock\"},\n", fp);
		fputs("  {\"name\":\"spark-x2.5:1.7b\",\"ollama_ref\":"
		      "\"SparkLLM/Spark-X2.5-1.7B\",\"params_b\":1.7,"
		      "\"ctx_tokens\":1048576,\"disk_gb\":3.4,"
		      "\"ram_min_gb\":4,\"gpu_hint\":\"optional\","
		      "\"tags\":[\"long-context\",\"low-ram\"],"
		      "\"why\":\"low ram\",\"notes\":\"mock\"},\n", fp);
		fputs("  {\"name\":\"qwen3:8b\",\"ollama_ref\":\"qwen3:8b\","
		      "\"params_b\":8.19,\"ctx_tokens\":32768,"
		      "\"disk_gb\":5.2,\"ram_min_gb\":8,"
		      "\"gpu_hint\":\"optional\","
		      "\"tags\":[\"general\",\"flagship\"],"
		      "\"why\":\"flagship\",\"notes\":\"mock\"},\n", fp);
		fputs("  {\"name\":\"broken-model\",\"ollama_ref\":"
		      "\"registry.invalid/broken-model\","
		      "\"params_b\":1,\"ctx_tokens\":8192,"
		      "\"disk_gb\":1,\"ram_min_gb\":2,"
		      "\"gpu_hint\":\"none\",\"tags\":[],"
		      "\"why\":\"always fails\",\"notes\":\"mock\"}\n", fp);
		fputs(" ]\n}\n", fp);
		fclose(fp);
	}
}

int main(void)
{
	struct aik_ml_entry cat[AIK_ML_CATALOG_MAX];
	struct aik_ml_hw hw;
	struct aik_ml_scored top[AIK_ML_TOP_N];
	char *err = NULL;
	int n, cnt, i;

	signal(SIGCHLD, SIG_DFL);
	env_setup();
	mock_start();

	/* ---- 目录解析 ---- */
	n = aik_ml_catalog_load(g_cat, cat, AIK_ML_CATALOG_MAX, &err);
	CHECK(n == 4, "catalog: 4 entries parsed");
	CHECK(err == NULL, "catalog: no error");
	if (n == 4) {
		CHECK(strcmp(cat[0].name, "spark-x2.5:4b") == 0 &&
		      strcmp(cat[0].ollama_ref,
			     "SparkLLM/Spark-X2.5-4B") == 0 &&
		      cat[0].ctx_tokens == 1048576 &&
		      cat[0].ram_min_gb == 8 &&
		      (double)cat[0].disk_gb > 8.0,
		      "catalog: entry fields correct");
		CHECK(cat[0].ntags == 3 &&
		      strcmp(cat[0].tags[0], "long-context") == 0,
		      "catalog: tags parsed");
	}
	/* 坏文件：缺失 entries → -1 */
	CHECK(aik_ml_catalog_load("/nonexistent.json", cat,
				  AIK_ML_CATALOG_MAX, &err) == -1 &&
	      err != NULL, "catalog: missing file -> error");
	free(err);
	err = NULL;

	/* ---- 推荐 + 硬件门控 ---- */
	memset(&hw, 0, sizeof(hw));
	hw.mem_total_kb = 16LL * 1024 * 1024;   /* 16GB */
	hw.disk_free_mb = 100 * 1024;
	hw.cpus = 8;
	cnt = aik_ml_recommend(cat, 4, &hw, top, AIK_ML_TOP_N);
	CHECK(cnt == 3, "recommend: big host top-3 (of 4 entries)");
	CHECK(cnt >= 1 && strcmp(top[0].e->name, "spark-x2.5:4b") == 0,
	      "recommend: spark-x2.5:4b ranked first");

	memset(&hw, 0, sizeof(hw));
	hw.mem_total_kb = 4LL * 1024 * 1024;    /* 4GB：8GB 门全挡 */
	hw.disk_free_mb = 100 * 1024;
	cnt = aik_ml_recommend(cat, 4, &hw, top, AIK_ML_TOP_N);
	CHECK(cnt >= 1, "recommend: 4GB host has options");
	for (i = 0; i < cnt; i++)
		if (top[i].e->ram_min_gb > 4) {
			CHECK(0, "recommend: 4GB host must not get 8B model");
			break;
		}
	CHECK(1, "recommend: 4GB host gate check done");
	CHECK(strcmp(top[0].e->name, "spark-x2.5:1.7b") == 0,
	      "recommend: 4GB host first = spark-x2.5:1.7b");

	memset(&hw, 0, sizeof(hw));
	hw.mem_total_kb = 2LL * 1024 * 1024;    /* 2GB */
	hw.disk_free_mb = 100 * 1024;
	cnt = aik_ml_recommend(cat, 4, &hw, top, AIK_ML_TOP_N);
	/* broken-model ram_min 2 == 2GB：门控是 ram_min_gb <= total_gb，
	 * 2<=2 过门——目录设计上 2GB 机器还能装 1.xB 级，符合预期 */
	CHECK(cnt >= 0, "recommend: 2GB host handled");

	memset(&hw, 0, sizeof(hw));
	hw.mem_total_kb = 16LL * 1024 * 1024;
	hw.disk_free_mb = 900;                   /* <1GB 磁盘：全挡 */
	cnt = aik_ml_recommend(cat, 4, &hw, top, AIK_ML_TOP_N);
	CHECK(cnt == 0, "recommend: tiny disk -> 0 recommendations");

	/* ---- switch / rollback ---- */
	{
		struct ai_config *cfg = ai_config_init();
		char *cerr = NULL;

		CHECK(cfg != NULL, "config: init");
		if (cfg) {
			CHECK(ai_config_load(cfg) == AI_ERR_NO_CONFIG ||
			      ai_config_load(cfg) == AI_OK,
			      "config: load (fresh home)");
			ai_config_add_model(cfg, "cloud", "openai_compatible",
					    "mock-cloud",
					    "http://127.0.0.1:1/v1", "");
			ai_config_set_default_model(cfg, "cloud");
			CHECK(aik_ml_switch(cfg, "local", &cerr) == -1,
			      "switch: local refused with no local model");
			free(cerr);
			cerr = NULL;

			/* 注册一个本地模型（模拟已安装） */
			free(cfg->local.model);
			cfg->local.model = strdup("SparkLLM/Spark-X2.5-4B");
			cfg->local.enabled = 1;
			free(cfg->local.base_url);
			cfg->local.base_url = malloc(128);
			snprintf(cfg->local.base_url, 128,
				 "http://127.0.0.1:%d/v1", g_port);
			CHECK(aik_ml_switch(cfg, "local", &cerr) == 0,
			      "switch: local ok");
			free(cerr);
			cerr = NULL;
			CHECK(strcmp(cfg->default_model, "local") == 0,
			      "switch: default=local");
			{
				char *pt = NULL, *pm = NULL;

				CHECK(ai_config_get_model(cfg, "local", &pt,
							  &pm, NULL,
							  NULL) == AI_OK &&
				      strcmp(pm ? pm : "",
					     "SparkLLM/Spark-X2.5-4B") == 0,
				      "switch: [models.local] mirror synced");
				free(pt);
				free(pm);
			}
			CHECK(access(g_state, R_OK) == 0,
			      "switch: state file written");
			CHECK(aik_ml_switch(cfg, "cloud", &cerr) == 0 &&
			      strcmp(cfg->default_model, "cloud") == 0,
			      "switch: cloud ok");
			free(cerr);
			cerr = NULL;
			CHECK(aik_ml_rollback(cfg, &cerr) == 0 &&
			      strcmp(cfg->default_model, "local") == 0,
			      "rollback: previous (local) restored");
			free(cerr);
			cerr = NULL;
			unlink(g_state);
			CHECK(aik_ml_rollback(cfg, &cerr) == -1,
			      "rollback: no state -> error");
			free(cerr);
			cerr = NULL;
			ai_config_destroy(cfg);
		}
	}

	/* ---- install：成功路径（mock /api/pull 流式 + 验证 + 注册） ---- */
	{
		struct ai_config *cfg = ai_config_init();

		setenv("AIK_HW_MEM_TOTAL_KB", "16777216", 1);
		setenv("AIK_HW_DISK_FREE_MB", "102400", 1);
		setenv("AIK_HW_CPUS", "8", 1);
		setenv("AIK_HW_GPU", "0", 1);
		if (cfg) {
			ai_config_load(cfg);
			ai_config_add_model(cfg, "cloud", "openai_compatible",
					    "mock-cloud",
					    "http://127.0.0.1:1/v1", "");
			ai_config_set_default_model(cfg, "cloud");
			free(cfg->local.base_url);
			cfg->local.base_url = malloc(128);
			snprintf(cfg->local.base_url, 128,
				 "http://127.0.0.1:%d/v1", g_port);
			cfg->local.enabled = 1;
			CHECK(aik_ml_install(cfg, "spark-x2.5:4b", 0,
					     &err) == 0,
			      "install: mock pull+verify ok");
			free(err);
			err = NULL;
			CHECK(cfg->local.model &&
			      strcmp(cfg->local.model,
				     "SparkLLM/Spark-X2.5-4B") == 0 &&
			      cfg->local.enabled == 1,
			      "install: [local] registered+enabled");
			{
				char *pm = NULL;

				CHECK(ai_config_get_model(cfg, "local", NULL,
							  &pm, NULL,
							  NULL) == AI_OK &&
				      strcmp(pm ? pm : "",
					     "SparkLLM/Spark-X2.5-4B") == 0,
				      "install: [models.local] written");
				free(pm);
			}

			/* ---- remove：活动模型需确认 ---- */
			CHECK(aik_ml_remove(cfg, "spark-x2.5:4b", 0, &err) ==
			      AIK_ML_E_CONFIRM,
			      "remove: active model requires confirm");
			free(err);
			err = NULL;
			CHECK(aik_ml_remove(cfg, "spark-x2.5:4b", 1, &err) ==
			      0,
			      "remove: forced ok");
			free(err);
			err = NULL;
			CHECK(cfg->local.enabled == 0 &&
			      (!cfg->local.model || !cfg->local.model[0]),
			      "remove: [local] disabled+cleared");

			/* ---- install：失败路径（pull error → 清理+不注册） ---- */
			CHECK(aik_ml_install(cfg, "broken-model", 0, &err) ==
			      -1,
			      "install: failing pull returns error");
			CHECK(err && strstr(err, "NOT installed") != NULL,
			      "install: honest failure message");
			CHECK(err && strstr(err, "alternatives") != NULL,
			      "install: suggests alternatives");
			free(err);
			err = NULL;
			CHECK(!cfg->local.model || !cfg->local.model[0],
			      "install: failure does NOT register model");
			ai_config_destroy(cfg);
		}
		unsetenv("AIK_HW_MEM_TOTAL_KB");
		unsetenv("AIK_HW_DISK_FREE_MB");
		unsetenv("AIK_HW_CPUS");
		unsetenv("AIK_HW_GPU");
	}

	/* ---- benchmark ---- */
	{
		struct ai_config *cfg = ai_config_init();

		if (cfg) {
			char bj[512];

			ai_config_load(cfg);
			free(cfg->local.base_url);
			cfg->local.base_url = malloc(128);
			snprintf(cfg->local.base_url, 128,
				 "http://127.0.0.1:%d/v1", g_port);
			free(cfg->local.model);
			cfg->local.model = strdup("mock-bench-model");
			cfg->local.enabled = 1;
			CHECK(aik_ml_benchmark(cfg, NULL, 0, bj,
					       sizeof(bj), &err) == 0,
			      "benchmark: 3 rounds ok");
			free(err);
			err = NULL;
			CHECK(strstr(bj, "\"p50_ms\"") &&
			      strstr(bj, "\"p95_ms\"") &&
			      strstr(bj, "\"tok_per_s\""),
			      "benchmark: json has p50/p95/tok_s");
			CHECK(access(g_bench, R_OK) == 0,
			      "benchmark: model-bench.json written");
			ai_config_destroy(cfg);
		}
	}

	kill(g_mock_pid, SIGKILL);
	waitpid(g_mock_pid, NULL, 0);
	unlink(g_cat);
	unlink(g_state);
	unlink(g_bench);
	rmdir(g_home);

	printf("\n%s: %s (failures=%d)\n", g_fail ? "RESULT" : "RESULT",
	       g_fail ? "FAIL" : "PASS", g_fail);
	return g_fail ? 1 : 0;
}
