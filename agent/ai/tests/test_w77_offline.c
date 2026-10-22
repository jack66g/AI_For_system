// SPDX-License-Identifier: GPL-2.0
/*
 * test_w77_offline.c - W77 离线意图层单测
 *
 * 覆盖：
 *   - 核心意图语料（tests/w77_intents.tsv）识别率 >=80%（目标 100%）；
 *   - 每个答案含 source/cache_age/latency + 机器可读 JSON；
 *   - /proc/statvfs/文件元数据/沙箱/租约/计划/路由/配置/网络/内核；
 *   - 文件意图只给元数据与行数，绝不输出正文（防 raw cat 世界模型）；
 *   - 动作/重推理问题不命中（防止离线层越权）；
 *   - SME 不可用时明确降级并给替代（最近计划）。
 *
 * 全部使用 AIKERNEL_OFFLINE_ROOT 临时根 + NO_EXEC，不触碰真实系统。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ai_runtime.h"
#include "ai_config.h"
#include "local/offline_intent.h"

static int g_pass, g_fail;

static void expect(int cond, const char *what)
{
	printf("%s: %s\n", cond ? "PASS" : "FAIL", what);
	if (cond)
		g_pass++;
	else
		g_fail++;
}

/* route 模块的 apply 依赖；本测试不切模型，stub 掉避免拉入通信层 */
int ai_runtime_set_model(struct ai_runtime *rt, const char *model_name)
{
	(void)rt;
	(void)model_name;
	return AI_OK;
}

static int mkdirs(const char *path)
{
	char tmp[1024];
	size_t i, n;

	snprintf(tmp, sizeof(tmp), "%s", path);
	n = strlen(tmp);
	for (i = 1; i < n; i++) {
		if (tmp[i] == '/') {
			tmp[i] = '\0';
			mkdir(tmp, 0700);
			tmp[i] = '/';
		}
	}
	return mkdir(tmp, 0700);
}

static int write_file(const char *path, const char *s)
{
	FILE *fp;

	fp = fopen(path, "w");
	if (!fp)
		return -1;
	fputs(s, fp);
	fclose(fp);
	return 0;
}

static char *read_file(const char *path)
{
	FILE *fp = fopen(path, "r");
	char *buf;
	long sz;

	if (!fp)
		return NULL;
	fseek(fp, 0, SEEK_END);
	sz = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (sz < 0 || sz > 1024 * 1024) {
		fclose(fp);
		return NULL;
	}
	buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(fp);
		return NULL;
	}
	if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
		free(buf);
		fclose(fp);
		return NULL;
	}
	buf[sz] = '\0';
	fclose(fp);
	return buf;
}

int main(void)
{
	char tmpl[] = "/tmp/w77-offline-XXXXXX";
	char *root;
	char path[1200];
	char home[512];
	struct ai_config cfg;
	struct ai_offline_answer ans;
	char *corpus;
	int pass = 0, total = 0;
	long long age = 0;
	char *plans;

	root = mkdtemp(tmpl);
	if (!root) {
		perror("mkdtemp");
		return 1;
	}
	setenv("AIKERNEL_OFFLINE_ROOT", root, 1);
	setenv("AIKERNEL_OFFLINE_NO_EXEC", "1", 1);
	snprintf(home, sizeof(home), "%s/home", root);
	mkdirs(home);
	setenv("HOME", home, 1);

	/* 临时根：/proc、/etc、/sandbox、/leases、/data.txt */
	snprintf(path, sizeof(path), "%s/proc", root);
	mkdirs(path);
	snprintf(path, sizeof(path), "%s/proc/uptime", root);
	write_file(path, "12345.67 45678.90\n");
	snprintf(path, sizeof(path), "%s/proc/loadavg", root);
	write_file(path, "0.42 0.31 0.20 3/456 7890\n");
	snprintf(path, sizeof(path), "%s/proc/meminfo", root);
	write_file(path,
		"MemTotal:        8000000 kB\n"
		"MemFree:         3000000 kB\n"
		"MemAvailable:    6000000 kB\n"
		"Buffers:          100000 kB\n"
		"Cached:          2000000 kB\n"
		"SwapTotal:       2000000 kB\n"
		"SwapFree:        1900000 kB\n");
	snprintf(path, sizeof(path), "%s/proc/net", root);
	mkdirs(path);
	snprintf(path, sizeof(path), "%s/proc/net/route", root);
	write_file(path,
		"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
		"eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n");
	snprintf(path, sizeof(path), "%s/etc", root);
	mkdirs(path);
	snprintf(path, sizeof(path), "%s/etc/resolv.conf", root);
	write_file(path, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
	snprintf(path, sizeof(path), "%s/proc/1", root);
	mkdirs(path);
	snprintf(path, sizeof(path), "%s/proc/1/status", root);
	write_file(path, "Name:\ttest-proc\nVmRSS:\t  12345 kB\n");
	snprintf(path, sizeof(path), "%s/proc/2", root);
	mkdirs(path);
	snprintf(path, sizeof(path), "%s/proc/2/status", root);
	write_file(path, "Name:\tbig-proc\nVmRSS:\t 999999 kB\n");
	snprintf(path, sizeof(path), "%s/data.txt", root);
	write_file(path, "TOP_SECRET_CONTENT_SHOULD_NEVER_APPEAR\nline2\nline3\n");
	snprintf(path, sizeof(path), "%s/sandbox/sb1", root);
	mkdirs(path);
	snprintf(path, sizeof(path), "%s/sandbox/sb1/meta", root);
	write_file(path, "{\"name\":\"sb1\"}\n");
	snprintf(path, sizeof(path), "%s/leases", root);
	mkdirs(path);
	snprintf(path, sizeof(path), "%s/leases/L-test.json", root);
	write_file(path, "{\"lease_id\":\"L-test\"}\n");
	setenv("AIKERNEL_SANDBOX_BASE", (snprintf(path, sizeof(path),
		"%s/sandbox", root), path), 1);
	setenv("AIKERNEL_LEASE_DIR", (snprintf(path, sizeof(path),
		"%s/leases", root), path), 1);
	setenv("SME_URL", "http://127.0.0.1:1", 1);

	/* 配置摘要（不得泄露 key） */
	memset(&cfg, 0, sizeof(cfg));
	cfg.default_model = "cloud";
	cfg.local.enabled = 1;
	cfg.local.model = "qwen2.5:1.5b";
	cfg.local.base_url = "http://127.0.0.1:11434/v1";
	cfg.ui.ctx_len = 32768;
	cfg.ui.max_tokens = 1024;
	cfg.route.mode = AI_MODEL_ROUTE_AUTO;
	cfg.route.offline_intents = 1;
	cfg.models_head = NULL;

	/* ---- 语料识别率 ---- */
	corpus = read_file("w77_intents.tsv");
	if (!corpus)
		corpus = read_file("../tests/w77_intents.tsv");
	expect(corpus != NULL, "corpus: tests/w77_intents.tsv 可读");
	if (corpus) {
		char *line = corpus;
		char *nl;

		while (line && *line) {
			char q[512], want[32];
			char *tab;

			nl = strchr(line, '\n');
			if (nl)
				*nl = '\0';
			if (line[0] && line[0] != '#') {
				tab = strchr(line, '\t');
				if (tab) {
					*tab = '\0';
					snprintf(q, sizeof(q), "%s", line);
					snprintf(want, sizeof(want), "%s",
						 tab + 1);
					memset(&ans, 0, sizeof(ans));
					total++;
					if (ai_offline_intent_match(q, &cfg,
								    &ans) &&
					    strcmp(ans.intent, want) == 0) {
						pass++;
					} else {
						printf("  INTENT FAIL: %s (want %s got %s)\n",
						       q, want,
						       ans.matched ?
						       ans.intent : "-");
					}
					ai_offline_answer_free(&ans);
				}
			}
			if (!nl)
				break;
			line = nl + 1;
		}
		free(corpus);
		printf("  core intents: %d/%d = %d%%\n", pass, total,
		       total ? pass * 100 / total : 0);
		expect(total >= 20 && pass * 100 >= total * 80,
		       "corpus: 核心意图识别率 >=80%");
	}

	/* ---- 每个意图的结构化字段 ---- */
	{
		static const char *const qs[] = {
			"系统状态", "内存使用情况", "磁盘空间", "当前负载",
			"服务 nginx 状态", "服务列表", "文件 /data.txt 大小",
			"沙箱", "最近计划", "路由模式", "配置", "网络状态",
			"内核版本", "运行多久", "租约", "日志", "记忆 部署",
			NULL
		};
		int i;

		for (i = 0; qs[i]; i++) {
			memset(&ans, 0, sizeof(ans));
			expect(ai_offline_intent_match(qs[i], &cfg, &ans) == 1 &&
			       ans.text && ans.json &&
			       strstr(ans.text, "source=") &&
			       strstr(ans.text, "age=") &&
			       strstr(ans.json, "\"intent\"") &&
			       strstr(ans.json, "\"cache_age_ms\"") &&
			       strstr(ans.json, "\"data\""),
			       qs[i]);
			ai_offline_answer_free(&ans);
		}
	}

	/* ---- 文件不泄露正文 ---- */
	memset(&ans, 0, sizeof(ans));
	expect(ai_offline_intent_match("文件 /data.txt 大小", &cfg, &ans) &&
	       ans.text && strstr(ans.text, "lines=") &&
	       strstr(ans.text, "TOP_SECRET") == NULL &&
	       strstr(ans.json, "TOP_SECRET") == NULL &&
	       strstr(ans.text, "content not dumped"),
	       "file: 只给元数据/行数，不输出正文");
	ai_offline_answer_free(&ans);

	/* ---- 动作/重推理不命中 ---- */
	expect(ai_offline_intent_match("帮我重启 nginx 服务", &cfg, &ans) == 0,
	       "guard: 重启动作不命中");
	expect(ai_offline_intent_match("分析一下为什么内存占用高", &cfg,
				       &ans) == 0,
	       "guard: 重推理问题不命中");
	expect(ai_offline_intent_match("帮我写一个 Python 脚本", &cfg,
				       &ans) == 0,
	       "guard: 写脚本不命中");

	/* ---- 沙箱/租约 ---- */
	memset(&ans, 0, sizeof(ans));
	expect(ai_offline_intent_match("沙箱", &cfg, &ans) &&
	       strstr(ans.text, "sb1") && strstr(ans.json, "\"count\":1"),
	       "sandbox: 列出 sb1");
	ai_offline_answer_free(&ans);
	memset(&ans, 0, sizeof(ans));
	expect(ai_offline_intent_match("租约", &cfg, &ans) &&
	       strstr(ans.text, "stored_leases=1") &&
	       strstr(ans.text, "D2+ still requires lease"),
	       "lease: 存储计数 + D2+ 不绕过声明");
	ai_offline_answer_free(&ans);

	/* ---- 计划缓存 ---- */
	expect(ai_offline_cache_plan("测试问题", "offline", "ok", 0,
				     "memory_search", "unit") == AI_OK,
	       "plan: 写入缓存");
	memset(&ans, 0, sizeof(ans));
	expect(ai_offline_intent_match("最近计划", &cfg, &ans) &&
	       strstr(ans.text, "测试问题") &&
	       strstr(ans.text, "memory_search") &&
	       ans.cache_age_ms >= 0,
	       "plan: 读取缓存 + 缓存年龄");
	ai_offline_answer_free(&ans);
	plans = ai_offline_last_plans(&age);
	expect(plans && strstr(plans, "测试问题") && age >= 0,
	       "plan: last_plans API");
	free(plans);

	/* ---- 路由 trace 查询 ---- */
	{
		char tdir[1024], tfile[1200];
		FILE *fp;

		snprintf(tdir, sizeof(tdir), "%s/trace", root);
		mkdirs(tdir);
		setenv("AIKERNEL_TRACE_DIR", tdir, 1);
		snprintf(tfile, sizeof(tfile), "%s/route.jsonl", tdir);
		fp = fopen(tfile, "w");
		if (fp) {
			fputs("{\"ts\":1,\"event\":\"route_decision\","
			      "\"decision\":\"local\",\"reason\":\"unit\","
			      "\"provider\":\"local\",\"model\":\"m\","
			      "\"latency_ms\":2}\n", fp);
			fclose(fp);
		}
		memset(&ans, 0, sizeof(ans));
		expect(ai_offline_intent_match("路由模式", &cfg, &ans) &&
		       strstr(ans.text, "\"reason\":\"unit\"") &&
		       strstr(ans.text, "route.jsonl"),
		       "route: 最后一条 route trace");
		ai_offline_answer_free(&ans);
	}

	/* ---- SME 不可用降级 ---- */
	memset(&ans, 0, sizeof(ans));
	expect(ai_offline_intent_match("记忆 部署", &cfg, &ans) &&
	       strstr(ans.text, "SME unavailable") &&
	       strstr(ans.text, "最近计划") && ans.degraded == 1,
	       "memory_query: SME 不可用明确降级 + 替代");
	ai_offline_answer_free(&ans);

	/* ---- 配置不泄露 key ---- */
	memset(&ans, 0, sizeof(ans));
	expect(ai_offline_intent_match("配置", &cfg, &ans) &&
	       strstr(ans.text, "qwen2.5:1.5b") &&
	       strstr(ans.text, "sk-") == NULL &&
	       strstr(ans.json, "api_key") != NULL &&
	       strstr(ans.json, "\"api_key_omitted\":true"),
	       "config: 摘要不含密钥");
	ai_offline_answer_free(&ans);

	/* 清理 */
	snprintf(path, sizeof(path), "rm -rf %s", root);
	if (system(path) != 0) {
		/* 测试清理尽力而为 */
	}
	printf("== test_w77_offline: %d PASS, %d FAIL ==\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}
