// SPDX-License-Identifier: GPL-2.0
/*
 * test_w77_route.c - W77 模型路由单测
 *
 * 覆盖：
 *   - auto|local|cloud 模式解析/环境覆盖；
 *   - 任务分类（运维/对话/重推理）；
 *   - 纯决策矩阵：隐私/云不可用/本地不可用/上下文/延迟；
 *   - 云→本切换耗时 <2s（stub ai_runtime_set_model 只做字段赋值）；
 *   - route.jsonl trace 字段完整、不含 api_key；
 *   - TCP 探测（本进程 listener / 关闭端口）；
 *   - 失败归类（400/422 不切换，429/5xx/网络切换）。
 *
 * 不启真模型：ai_runtime_set_model 由本文件 stub；trace 用真实现，
 * AIKERNEL_TRACE_DIR 指向 mkdtemp。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ai_runtime.h"
#include "ai_config.h"
#include "ai_trace.h"

static int g_pass, g_fail;

static void expect(int cond, const char *what)
{
	printf("%s: %s\n", cond ? "PASS" : "FAIL", what);
	if (cond)
		g_pass++;
	else
		g_fail++;
}

/* ---- stub：路由 apply 只做 provider 字段切换（不建网） ---- */
int ai_runtime_set_model(struct ai_runtime *rt, const char *model_name)
{
	static char local_type[] = "local";
	static char cloud_type[] = "openai_compatible";
	static char local_model[] = "qwen2.5:1.5b";
	static char cloud_model[] = "mock-cloud";

	if (!rt || !model_name)
		return AI_ERR_INVALID_ARG;
	/* 模拟真实 set_model 的配置切换开销（远小于 2s 预算） */
	usleep(2000);
	if (strcmp(model_name, "local") == 0) {
		rt->model_provider_type = local_type;
		rt->model_name = local_model;
		rt->current_model = (char *)model_name;
	} else {
		rt->model_provider_type = cloud_type;
		rt->model_name = cloud_model;
		rt->current_model = (char *)model_name;
	}
	return AI_OK;
}

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
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

static void facts_case(const char *name, struct ai_route_facts *f,
		       int want_target, const char *want_reason)
{
	struct ai_route_choice c;

	ai_route_decide_facts(f, &c);
	if (c.target != want_target ||
	    strcmp(c.reason, want_reason) != 0)
		printf("  got target=%d reason=%s\n", c.target, c.reason);
	expect(c.target == want_target &&
	       strcmp(c.reason, want_reason) == 0, name);
}

int main(void)
{
	char tmpl[] = "/tmp/w77-route-XXXXXX";
	char *base;
	char trace_dir[512];
	char trace_path[600];
	char *trace;
	struct ai_config cfg;
	struct ai_model_config cloud, local;
	struct ai_route_facts f;
	struct ai_route_choice c;
	struct ai_runtime rt;
	long long t0, ms;

	base = mkdtemp(tmpl);
	if (!base) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(trace_dir, sizeof(trace_dir), "%s/trace", base);
	mkdir(trace_dir, 0700);
	setenv("AIKERNEL_TRACE_DIR", trace_dir, 1);
	setenv("AIKERNEL_TRACE_ENABLED", "1", 1);
	setenv("AIKERNEL_ROUTE", "auto", 1);
	unsetenv("AIKERNEL_PRIVACY");
	unsetenv("AIKERNEL_CLOUD_DOWN");
	unsetenv("AIKERNEL_LOCAL_DOWN");
	ai_trace_init(NULL, 0);
	ai_route_reset_state();

	/* ---- 模式 ---- */
	expect(ai_route_mode_parse("auto") == AI_MODEL_ROUTE_AUTO &&
	       ai_route_mode_parse("LOCAL") == AI_MODEL_ROUTE_LOCAL &&
	       ai_route_mode_parse("cloud") == AI_MODEL_ROUTE_CLOUD &&
	       ai_route_mode_parse("bogus") == -1, "mode: parse");
	expect(strcmp(ai_route_mode_name(AI_MODEL_ROUTE_AUTO), "auto") == 0 &&
	       strcmp(ai_route_mode_name(AI_MODEL_ROUTE_LOCAL), "local") == 0 &&
	       strcmp(ai_route_mode_name(AI_MODEL_ROUTE_CLOUD), "cloud") == 0,
	       "mode: names");

	memset(&cfg, 0, sizeof(cfg));
	cfg.route.mode = AI_MODEL_ROUTE_CLOUD;
	setenv("AIKERNEL_ROUTE", "local", 1);
	expect(ai_route_effective_mode(&cfg) == AI_MODEL_ROUTE_LOCAL,
	       "mode: env overrides config");
	unsetenv("AIKERNEL_ROUTE");
	expect(ai_route_effective_mode(&cfg) == AI_MODEL_ROUTE_CLOUD,
	       "mode: config used when env absent");
	setenv("AIKERNEL_ROUTE", "auto", 1);

	/* ---- 任务分类 ---- */
	expect(ai_route_classify_task("内存使用情况") ==
	       AI_ROUTE_TASK_OPERATIONAL, "class: 内存=operational");
	expect(ai_route_classify_task("服务 nginx 状态") ==
	       AI_ROUTE_TASK_OPERATIONAL, "class: 服务=operational");
	expect(ai_route_classify_task("最近计划") ==
	       AI_ROUTE_TASK_OPERATIONAL, "class: 最近计划=operational");
	expect(ai_route_classify_task("请分析这段代码的设计并给出方案") ==
	       AI_ROUTE_TASK_REASONING, "class: 分析/方案=reasoning");
	expect(ai_route_classify_task("hello there") ==
	       AI_ROUTE_TASK_CHAT, "class: 闲聊=chat");

	/* ---- 纯决策矩阵 ---- */
	memset(&f, 0, sizeof(f));
	f.mode = AI_MODEL_ROUTE_AUTO;
	f.prefer_local = 1;
	f.failover = 1;
	f.local_up = 1;
	f.task = AI_ROUTE_TASK_OPERATIONAL;
	facts_case("facts: 运维任务本地优先", &f, AI_ROUTE_TARGET_LOCAL,
		   "operational_local");

	f.task = AI_ROUTE_TASK_REASONING;
	facts_case("facts: 重推理走云", &f, AI_ROUTE_TARGET_CLOUD,
		   "reasoning_cloud");

	f.privacy = 1;
	facts_case("facts: 隐私任务本地", &f, AI_ROUTE_TARGET_LOCAL,
		   "privacy_local");
	f.local_up = 0;
	facts_case("facts: 隐私+本地不可用=明确离线",
		   &f, AI_ROUTE_TARGET_OFFLINE, "privacy_local_unavailable");
	f.privacy = 0;
	f.local_up = 1;

	f.cloud_down = 1;
	f.task = AI_ROUTE_TASK_REASONING;
	facts_case("facts: 云不可用切本地", &f, AI_ROUTE_TARGET_LOCAL,
		   "cloud_down");
	f.local_up = 0;
	facts_case("facts: 云+本地都不可用=离线",
		   &f, AI_ROUTE_TARGET_OFFLINE, "cloud_and_local_down");
	f.local_up = 1;
	f.cloud_down = 0;

	f.tokens = 30000;
	f.task = AI_ROUTE_TASK_OPERATIONAL;
	facts_case("facts: 超本地窗口走云", &f, AI_ROUTE_TARGET_CLOUD,
		   "context_needs_cloud");
	f.tokens = 0;
	f.task = AI_ROUTE_TASK_CHAT;
	f.local_slow = 1;
	facts_case("facts: 本地慢时闲聊走云", &f, AI_ROUTE_TARGET_CLOUD,
		   "default_cloud");
	f.local_slow = 0;
	f.task = AI_ROUTE_TASK_OPERATIONAL;
	f.prefer_local = 0;
	facts_case("facts: prefer_local=0 运维走云", &f, AI_ROUTE_TARGET_CLOUD,
		   "operational_cloud");
	f.prefer_local = 1;

	f.mode = AI_MODEL_ROUTE_LOCAL;
	f.task = AI_ROUTE_TASK_REASONING;
	facts_case("facts: 强制本地", &f, AI_ROUTE_TARGET_LOCAL,
		   "forced_local");
	f.mode = AI_MODEL_ROUTE_CLOUD;
	facts_case("facts: 强制云", &f, AI_ROUTE_TARGET_CLOUD,
		   "forced_cloud");
	f.privacy = 1;
	facts_case("facts: 隐私优先于强制云", &f, AI_ROUTE_TARGET_LOCAL,
		   "privacy_local");
	f.privacy = 0;
	f.mode = AI_MODEL_ROUTE_AUTO;

	/* ---- 失败归类 ---- */
	cfg.route.failover = 1;
	cfg.local.enabled = 1;
	cfg.local.base_url = "http://127.0.0.1:1/v1";
	cfg.local.model = "qwen2.5:1.5b";
	setenv("AIKERNEL_LOCAL_DOWN", "1", 1);
	expect(ai_route_should_failover(&cfg, AI_ROUTE_TARGET_CLOUD,
		AI_ERR_API, 500, 0) == 0,
	       "failover: 本地不可用不切换");
	unsetenv("AIKERNEL_LOCAL_DOWN");
	setenv("AIKERNEL_LOCAL_UP", "1", 1);
	ai_route_reset_state();
	expect(ai_route_should_failover(&cfg, AI_ROUTE_TARGET_CLOUD,
		AI_ERR_API, 500, 0) == 1,
	       "failover: 500 切换");
	expect(ai_route_should_failover(&cfg, AI_ROUTE_TARGET_CLOUD,
		AI_ERR_API, 429, 0) == 1,
	       "failover: 429 切换");
	expect(ai_route_should_failover(&cfg, AI_ROUTE_TARGET_CLOUD,
		AI_ERR_NETWORK, 0, 0) == 1,
	       "failover: 网络/DNS/超时切换");
	expect(ai_route_should_failover(&cfg, AI_ROUTE_TARGET_CLOUD,
		AI_ERR_API, 400, 0) == 0,
	       "failover: 400 不切换（走文本工具协议）");
	expect(ai_route_should_failover(&cfg, AI_ROUTE_TARGET_CLOUD,
		AI_ERR_API, 500, 1) == 0,
	       "failover: 只切换一次");
	unsetenv("AIKERNEL_LOCAL_UP");
	ai_route_reset_state();

	/* ---- 探测 ---- */
	{
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in addr;
		socklen_t alen = sizeof(addr);
		char url[128];
		int on = 1;

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port = 0;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		expect(fd >= 0 && bind(fd, (struct sockaddr *)&addr,
				       sizeof(addr)) == 0 &&
		       listen(fd, 1) == 0 &&
		       getsockname(fd, (struct sockaddr *)&addr, &alen) == 0,
		       "probe: listener up");
		snprintf(url, sizeof(url), "http://127.0.0.1:%d",
			 ntohs(addr.sin_port));
		expect(ai_route_probe_url(url, 300) == 1,
		       "probe: 可达端口=1");
		close(fd);
		expect(ai_route_probe_url("http://127.0.0.1:1", 200) == 0,
		       "probe: 关闭端口=0");
	}

	/* ---- 健康记忆 ---- */
	ai_route_reset_state();
	ai_route_note_cloud(0, 500, AI_ERR_API);
	setenv("AIKERNEL_LOCAL_DOWN", "1", 1);
	memset(&cfg, 0, sizeof(cfg));
	cfg.route.mode = AI_MODEL_ROUTE_AUTO;
	cfg.route.prefer_local = 1;
	cfg.route.failover = 1;
	cfg.route.probe_timeout_ms = 100;
	ai_route_decide(&cfg, "请分析这段代码", &c);
	expect(c.target == AI_ROUTE_TARGET_OFFLINE &&
	       c.cloud_known_down == 1,
	       "health: 云失败记忆使决策直接离线");
	unsetenv("AIKERNEL_LOCAL_DOWN");
	ai_route_reset_state();

	/* ---- apply/切换耗时 ---- */
	memset(&rt, 0, sizeof(rt));
	rt.config = &cfg;
	memset(&cloud, 0, sizeof(cloud));
	cloud.name = "cloud";
	cloud.provider_type = "openai_compatible";
	cloud.model_name = "mock-cloud";
	cloud.base_url = "http://127.0.0.1:18977";
	memset(&local, 0, sizeof(local));
	local.name = "local";
	local.provider_type = "local";
	local.model_name = "qwen2.5:1.5b";
	local.base_url = "http://127.0.0.1:18978/v1";
	cloud.next = &local;
	cfg.models_head = &cloud;
	cfg.model_count = 2;
	cfg.default_model = "cloud";
	cfg.local.enabled = 1;
	cfg.local.base_url = "http://127.0.0.1:18978/v1";
	cfg.local.model = "qwen2.5:1.5b";
	rt.model_provider_type = "openai_compatible";
	t0 = now_ms();
	expect(ai_route_apply(&rt, AI_ROUTE_TARGET_LOCAL, &ms) == AI_OK,
	       "apply: cloud->local ok");
	t0 = now_ms() - t0;
	expect(rt.model_provider_type &&
	       strcmp(rt.model_provider_type, "local") == 0,
	       "apply: provider=local");
	expect(t0 < 2000 && ms < 2000, "apply: 切换 <2s");
	printf("  switch elapsed=%lldms (stub)\n", t0);
	expect(ai_route_current_target(&rt) == AI_ROUTE_TARGET_LOCAL,
	       "apply: current target=local");

	/* ---- trace ---- */
	snprintf(trace_path, sizeof(trace_path), "%s/route.jsonl", trace_dir);
	memset(&c, 0, sizeof(c));
	c.target = AI_ROUTE_TARGET_LOCAL;
	c.mode = AI_MODEL_ROUTE_AUTO;
	c.reason = "unit_test_reason";
	c.task_class = AI_ROUTE_TASK_OPERATIONAL;
	c.cloud_known_down = 1;
	c.local_available = 1;
	c.decide_ms = 7;
	rt.model_provider_type = "local";
	rt.model_name = "qwen2.5:1.5b";
	expect(ai_route_trace_decision(&cfg, &rt, &c, 3) == AI_OK,
	       "trace: decision write");
	expect(ai_route_trace_switch(&rt, AI_ROUTE_TARGET_CLOUD,
				     AI_ROUTE_TARGET_LOCAL, "unit_test",
				     4) == AI_OK,
	       "trace: switch write");
	expect(ai_route_trace_offline("memory", "/proc/meminfo", 0, 1) ==
	       AI_OK, "trace: offline write");
	trace = read_file(trace_path);
	expect(trace != NULL, "trace: file exists");
	if (trace) {
		expect(strstr(trace, "\"event\":\"route_decision\"") &&
		       strstr(trace, "\"decision\":\"local\"") &&
		       strstr(trace, "\"reason\":\"unit_test_reason\"") &&
		       strstr(trace, "\"provider\":\"local\"") &&
		       strstr(trace, "\"model\":\"qwen2.5:1.5b\"") &&
		       strstr(trace, "\"latency_ms\""),
		       "trace: route/decision/reason/latency/provider 完整");
		expect(strstr(trace, "\"event\":\"route_switch\"") &&
		       strstr(trace, "\"switch_ms\""),
		       "trace: 切换事件含 switch_ms");
		expect(strstr(trace, "\"event\":\"route_offline\"") != NULL,
		       "trace: 离线意图事件");
		expect(strstr(trace, "api_key") == NULL &&
		       strstr(trace, "sk-") == NULL &&
		       strstr(trace, "base_url") == NULL,
		       "trace: 不含 key/base_url");
		free(trace);
	}

	/* ---- 状态文本 ---- */
	{
		char status[1024];

		expect(ai_route_status_text(&cfg, &rt, status,
					    sizeof(status)) == AI_OK &&
		       strstr(status, "mode=") && strstr(status, "target=") &&
		       strstr(status, "last_switch_ms="),
		       "status: 文本字段");
	}

	/* ---- [route] 配置解析/保存/钳制 ---- */
	{
		char cfg_home[512];
		char cfg_dir[600];
		char cfg_path[700];
		struct ai_config *loaded;
		FILE *fp;

		snprintf(cfg_home, sizeof(cfg_home), "%s/cfghome", base);
		mkdir(cfg_home, 0700);
		snprintf(cfg_dir, sizeof(cfg_dir), "%s/.aikernel", cfg_home);
		mkdir(cfg_dir, 0700);
		setenv("HOME", cfg_home, 1);
		unsetenv("AIKERNEL_ROUTE");
		snprintf(cfg_path, sizeof(cfg_path), "%s/model.toml", cfg_dir);
		fp = fopen(cfg_path, "w");
		if (fp) {
			fputs("[default]\nmodel = \"cloud\"\n\n"
			      "[route]\nmode = \"local\"\n"
			      "privacy = true\nfailover = false\n"
			      "offline_intents = false\n"
			      "local_ctx = 99999\nlocal_p95_ms = 9000\n"
			      "switch_budget_ms = 1500\n"
			      "probe_timeout_ms = 250\n"
			      "cloud_down_ttl_ms = 30000\n\n"
			      "[models.cloud]\n"
			      "provider_type = \"openai_compatible\"\n"
			      "model_name = \"m\"\n"
			      "base_url = \"http://127.0.0.1:1\"\n"
			      "api_key = \"\"\n", fp);
			fclose(fp);
		}
		loaded = ai_config_init();
		expect(loaded != NULL && ai_config_load(loaded) == AI_OK,
		       "config: [route] load");
		if (loaded) {
			expect(loaded->route.mode == AI_MODEL_ROUTE_LOCAL &&
			       loaded->route.privacy == 1 &&
			       loaded->route.failover == 0 &&
			       loaded->route.offline_intents == 0 &&
			       loaded->route.local_ctx == AI_LOCAL_CTX_MAX &&
			       loaded->route.local_p95_ms == 9000 &&
			       loaded->route.switch_budget_ms == 1500 &&
			       loaded->route.probe_timeout_ms == 250,
			       "config: 字段解析 + local_ctx 钳 32768");
			expect(ai_config_save(loaded) == AI_OK,
			       "config: [route] save");
			{
				char *round = read_file(cfg_path);

				expect(round && strstr(round, "[route]") &&
				       strstr(round,
					      "mode = \"local\""),
				       "config: save 回写 [route]");
				free(round);
			}
			ai_config_destroy(loaded);
		}
		setenv("AIKERNEL_ROUTE", "auto", 1);
	}

	/* ---- 离线意图开关 ---- */
	setenv("AIKERNEL_OFFLINE_INTENTS", "0", 1);
	expect(ai_route_offline_intents_enabled(&cfg) == 0,
	       "offline intents: env off");
	setenv("AIKERNEL_OFFLINE_INTENTS", "force", 1);
	cfg.route.mode = AI_MODEL_ROUTE_CLOUD;
	expect(ai_route_offline_intents_enabled(&cfg) == 1,
	       "offline intents: force overrides cloud");
	unsetenv("AIKERNEL_OFFLINE_INTENTS");
	cfg.route.mode = AI_MODEL_ROUTE_CLOUD;
	expect(ai_route_offline_intents_enabled(&cfg) == 0,
	       "offline intents: 强制云默认关闭");
	cfg.route.mode = AI_MODEL_ROUTE_AUTO;
	expect(ai_route_offline_intents_enabled(&cfg) == 0,
	       "offline intents: cfg default off in synthetic cfg");
	cfg.route.offline_intents = 1;
	expect(ai_route_offline_intents_enabled(&cfg) == 1,
	       "offline intents: cfg on");

	ai_trace_shutdown();
	{
		char rm[700];

		snprintf(rm, sizeof(rm), "rm -rf %s", base);
		if (system(rm) != 0) {
			/* 测试清理尽力而为 */
		}
	}
	printf("== test_w77_route: %d PASS, %d FAIL ==\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}
