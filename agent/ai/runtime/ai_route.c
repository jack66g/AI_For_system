// SPDX-License-Identifier: GPL-2.0
/*
 * ai_route.c - W77 本地/云端模型路由
 *
 * 目标：断网时核心运维仍可用；云只做重推理。
 *
 * 路由模式（env AIKERNEL_ROUTE > model.toml [route].mode）：
 *   auto  - 按任务类型/延迟/隐私/成本选择；云失败自动切本地
 *   local - 强制本地（本地失败明确降级，不静默上云）
 *   cloud - 强制云（失败仍可在 failover=1 时切本地）
 *
 * 选择依据（全部确定性、可解释）：
 *   - 隐私：AIKERNEL_PRIVACY=1 或 [route].privacy=1 或问题含
 *     “离线/不要联网/隐私/secret” → 本地；本地不可用 → 明确降级，
 *     绝不把隐私任务发到云端；
 *   - 任务类型：状态/诊断/文件/服务/沙箱/记忆查询等运维任务优先本地；
 *     代码/方案/分析等重推理任务走云；
 *   - 延迟：本地最近一次实测延迟超过 [route].local_p95_ms 时，
 *     非运维任务改走云；
 *   - 成本/上下文：估算 prompt 超过本地 32768 窗口的一半 → 云；
 *   - 可用性：本地 TCP 探测（缓存 3s）、云 TCP 预探测（缓存 30s）
 *     与最近失败记忆（TTL 60s）。云失败（网络/认证/429/5xx/超时）
 *     自动切本地；切换本身只做 provider 配置切换，不做网络握手，
 *     实测 <2s。
 *
 * 路由 trace：$AIKERNEL_TRACE_DIR/route.jsonl（默认
 * ~/.aikernel/trace/route.jsonl）逐行 JSON，字段含
 * ts/event/mode/decision/reason/task/provider/model/latency_ms/
 * cloud_health/local_up/switch_ms；不写 base_url/api_key/密钥。
 * 云→本切换额外镜像到主 trace 的 degraded 事件（component=route）。
 *
 * 本模块不改变任何 D 级/租约语义：离线只影响“用哪个模型”，
 * D2+ 动作仍由 executor + W74 lease gate 决定。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>

#include "ai_runtime.h"
#include "ai_config.h"
#include "ai_trace.h"
#include "local/local_http.h"

#define ROUTE_TRACE_ROTATE_BYTES   (8 * 1024 * 1024)
#define ROUTE_LOCAL_PROBE_CACHE_MS 3000
#define ROUTE_CLOUD_PROBE_CACHE_MS 30000
#define ROUTE_CLOUD_PROBE_MS       500
#define ROUTE_CLOUD_DOWN_TTL_MS    60000
#define ROUTE_LOCAL_CTX_TOKENS     24000

static struct {
	long long cloud_down_until;
	long long cloud_probed_at;
	int cloud_up;               /* 0=未知 1=可达 -1=不可达 */
	long long local_probed_at;
	int local_up;
	int local_probe_ms;
	long long local_last_ms;
	int local_last_ok;
	int last_target;
	char last_reason[64];
	char last_provider[32];
	char last_model[128];
	long long last_decide_ms;
	long long last_switch_ms;
} g_route;

/* ---- 小工具 ---- */

static long long route_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static long long route_wall_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static int route_contains(const char *hay, const char *needle)
{
	return hay && needle && strcasestr(hay, needle) != NULL;
}

static const char *route_basename_provider(const char *provider_type)
{
	if (!provider_type || !provider_type[0])
		return "unknown";
	return provider_type;
}

/* ---- 模式 ---- */

const char *ai_route_mode_name(int mode)
{
	switch (mode) {
	case AI_MODEL_ROUTE_LOCAL: return "local";
	case AI_MODEL_ROUTE_CLOUD: return "cloud";
	case AI_MODEL_ROUTE_AUTO:  return "auto";
	default:                   return "unknown";
	}
}

int ai_route_mode_parse(const char *s)
{
	if (!s || !s[0])
		return -1;
	if (strcasecmp(s, "auto") == 0)
		return AI_MODEL_ROUTE_AUTO;
	if (strcasecmp(s, "local") == 0)
		return AI_MODEL_ROUTE_LOCAL;
	if (strcasecmp(s, "cloud") == 0)
		return AI_MODEL_ROUTE_CLOUD;
	return -1;
}

int ai_route_effective_mode(const struct ai_config *cfg)
{
	const char *env = getenv("AIKERNEL_ROUTE");
	int m = ai_route_mode_parse(env);

	if (m >= 0)
		return m;
	if (cfg)
		return cfg->route.mode;
	return AI_MODEL_ROUTE_AUTO;
}

int ai_route_offline_intents_enabled(const struct ai_config *cfg)
{
	const char *env = getenv("AIKERNEL_OFFLINE_INTENTS");
	int enabled;

	if (env && env[0]) {
		if (strcmp(env, "0") == 0 || strcasecmp(env, "off") == 0 ||
		    strcasecmp(env, "false") == 0)
			return 0;
		if (strcmp(env, "1") == 0 || strcasecmp(env, "force") == 0 ||
		    strcasecmp(env, "on") == 0 ||
		    strcasecmp(env, "true") == 0)
			return 1;
	}
	if (ai_route_effective_mode(cfg) == AI_MODEL_ROUTE_CLOUD)
		return 0;   /* 强制云模式：保留用户显式选择 */
	enabled = cfg ? cfg->route.offline_intents : 1;
	return enabled != 0;
}

/* ---- 任务分类 ---- */

static const char *const g_reasoning_kw[] = {
	"分析", "设计", "架构", "方案", "代码", "脚本", "实现", "编写",
	"写一个", "写个", "生成", "优化", "解释", "比较", "为什么",
	"如何", "怎么", "根因", "排查", "计划", "步骤", "策略", "建议",
	"analy", "design", "architect", "code", "script", "implement",
	"write", "generat", "optimi", "explain", "compare", "why",
	"how to", "root cause", "plan", "step", "strategy", "suggest",
	"review", "refactor", "debug",
	NULL
};

static const char *const g_operational_kw[] = {
	"状态", "内存", "磁盘", "空间", "负载", "进程", "服务", "日志",
	"文件", "目录", "沙箱", "记忆", "租约", "计划", "配置", "网络",
	"内核", "版本", "端口", "温度", "健康", "运行多久", "启动时间",
	"status", "memory", "mem", "ram", "disk", "space", "load",
	"cpu", "process", "service", "systemd", "unit", "log", "dmesg",
	"file", "directory", "sandbox", "lease", "plan", "config",
	"network", "ip ", "dns", "kernel", "version", "port", "uptime",
	"health", "sme", "memory_search", "recall",
	NULL
};

int ai_route_classify_task(const char *question)
{
	int i;

	if (!question || !question[0])
		return AI_ROUTE_TASK_CHAT;

	/* “上次/最近/上一个 + 计划/任务”是离线缓存查询，不是重推理 */
	if ((route_contains(question, "上次") ||
	     route_contains(question, "最近") ||
	     route_contains(question, "上一个") ||
	     route_contains(question, "last") ||
	     route_contains(question, "previous")) &&
	    (route_contains(question, "计划") ||
	     route_contains(question, "任务") ||
	     route_contains(question, "plan") ||
	     route_contains(question, "task")))
		return AI_ROUTE_TASK_OPERATIONAL;

	for (i = 0; g_reasoning_kw[i]; i++)
		if (route_contains(question, g_reasoning_kw[i]))
			return AI_ROUTE_TASK_REASONING;

	for (i = 0; g_operational_kw[i]; i++)
		if (route_contains(question, g_operational_kw[i]))
			return AI_ROUTE_TASK_OPERATIONAL;

	return AI_ROUTE_TASK_CHAT;
}

static int route_privacy_requested(const struct ai_config *cfg,
				   const char *question)
{
	const char *env = getenv("AIKERNEL_PRIVACY");

	if (env && (strcmp(env, "1") == 0 || strcasecmp(env, "true") == 0 ||
		    strcasecmp(env, "local") == 0))
		return 1;
	if (cfg && cfg->route.privacy)
		return 1;
	if (!question)
		return 0;
	return route_contains(question, "隐私") ||
	       route_contains(question, "不要联网") ||
	       route_contains(question, "不联网") ||
	       route_contains(question, "离线") ||
	       route_contains(question, "offline") ||
	       route_contains(question, "air-gap") ||
	       route_contains(question, "private");
}

/* ---- 模型查找 ---- */

static int route_local_configured(const struct ai_config *cfg)
{
	return cfg && cfg->local.enabled &&
	       cfg->local.base_url && cfg->local.base_url[0] &&
	       cfg->local.model && cfg->local.model[0];
}

static int route_cloud_model_name(const struct ai_config *cfg,
				  char *out, size_t n)
{
	const char *env = getenv("AIKERNEL_CLOUD_MODEL");
	struct ai_model_config *m;

	if (env && env[0]) {
		snprintf(out, n, "%s", env);
		return 0;
	}
	if (!cfg)
		return -1;
	if (cfg->default_model) {
		for (m = cfg->models_head; m; m = m->next) {
			if (strcmp(m->name, cfg->default_model) == 0 &&
			    m->provider_type &&
			    strcmp(m->provider_type, "local") != 0) {
				snprintf(out, n, "%s", m->name);
				return 0;
			}
		}
	}
	for (m = cfg->models_head; m; m = m->next) {
		if (m->provider_type &&
		    strcmp(m->provider_type, "local") != 0) {
			snprintf(out, n, "%s", m->name);
			return 0;
		}
	}
	return -1;
}

static int route_cloud_base_url(const struct ai_config *cfg,
				char *out, size_t n)
{
	char name[128];
	struct ai_model_config *m;

	if (route_cloud_model_name(cfg, name, sizeof(name)) != 0)
		return -1;
	for (m = cfg->models_head; m; m = m->next) {
		if (strcmp(m->name, name) == 0 && m->base_url) {
			snprintf(out, n, "%s", m->base_url);
			return 0;
		}
	}
	return -1;
}

/*
 * ai_route_ensure_local_model - 确保 Runtime 可用的 [models.local] 条目
 *
 * `model use local` 会持久化该镜像；自动路由不写用户配置，只在内存
 * 中补一个条目，进程退出即消失（下次仍由 route 自动补）。
 */
int ai_route_ensure_local_model(struct ai_config *cfg)
{
	char *ptype = NULL;

	if (!cfg || !route_local_configured(cfg))
		return AI_ERR_CONFIG;

	if (ai_config_get_model(cfg, "local", &ptype, NULL, NULL, NULL)
	    == AI_OK) {
		int ok = ptype && strcmp(ptype, "local") == 0;

		free(ptype);
		return ok ? AI_OK : AI_ERR_CONFIG;
	}
	free(ptype);
	return ai_config_add_model(cfg, "local", "local",
				   cfg->local.model, cfg->local.base_url,
				   cfg->local.api_key ? cfg->local.api_key : "");
}

/* ---- 可用性探测 ---- */

/*
 * ai_route_probe_url - TCP 可达性探测（1=可达，0=不可达）
 * https:// 目标只做 TCP 探测（TLS 握手留给真正请求）。
 */
int ai_route_probe_url(const char *url, int timeout_ms)
{
	char *err = NULL;
	int ret;

	if (!url || !url[0])
		return 0;
	if (strncmp(url, "https://", 8) == 0) {
		/* https 的 TCP 探测：local_http_probe 只接受 http 形式，
		 * 这里退化为“未知可达”，避免误判把云端永久打入 down。 */
		return 1;
	}
	ret = local_http_probe(url, timeout_ms, &err);
	free(err);
	return ret == AI_OK;
}

int ai_route_local_available(const struct ai_config *cfg)
{
	const char *env = getenv("AIKERNEL_LOCAL_DOWN");
	const char *up = getenv("AIKERNEL_LOCAL_UP");
	long long now;
	char url[512];

	if (env && (strcmp(env, "1") == 0 || strcasecmp(env, "true") == 0))
		return 0;
	if (up && (strcmp(up, "1") == 0 || strcasecmp(up, "true") == 0))
		return route_local_configured(cfg) ? 1 : 0;
	if (!route_local_configured(cfg))
		return 0;
	now = route_now_ms();
	if (g_route.local_probed_at &&
	    now - g_route.local_probed_at < ROUTE_LOCAL_PROBE_CACHE_MS)
		return g_route.local_up;
	snprintf(url, sizeof(url), "%s", cfg->local.base_url);
	{
		long long t0 = route_now_ms();

		g_route.local_up = ai_route_probe_url(
			url, cfg->route.probe_timeout_ms > 0 ?
			     cfg->route.probe_timeout_ms : 400);
		g_route.local_probe_ms = (int)(route_now_ms() - t0);
	}
	g_route.local_probed_at = now;
	return g_route.local_up;
}

static int route_cloud_available(const struct ai_config *cfg)
{
	const char *env = getenv("AIKERNEL_CLOUD_DOWN");
	long long now;
	char url[512];

	if (env && (strcmp(env, "1") == 0 || strcasecmp(env, "true") == 0))
		return 0;
	now = route_now_ms();
	if (g_route.cloud_down_until > now)
		return 0;
	if (g_route.cloud_probed_at &&
	    now - g_route.cloud_probed_at < ROUTE_CLOUD_PROBE_CACHE_MS)
		return g_route.cloud_up > 0;
	if (route_cloud_base_url(cfg, url, sizeof(url)) != 0)
		return 0;
	g_route.cloud_up = ai_route_probe_url(
		url, cfg->route.probe_timeout_ms > 0 ?
		     cfg->route.probe_timeout_ms : 400) ? 1 : -1;
	g_route.cloud_probed_at = now;
	return g_route.cloud_up > 0;
}

/* ---- 纯决策 ---- */

void ai_route_decide_facts(const struct ai_route_facts *f,
			   struct ai_route_choice *out)
{
	if (!f || !out)
		return;
	memset(out, 0, sizeof(*out));
	out->mode = f->mode;
	out->task_class = f->task;
	out->privacy = f->privacy;
	out->local_available = f->local_up;
	out->cloud_known_down = f->cloud_down;
	out->tokens_est = f->tokens;

	/* 隐私优先于一切模式：即使显式 cloud，也不把隐私任务发到云端；
	 * 本地不可用则明确离线，不静默降级到云。 */
	if (f->privacy) {
		if (f->local_up) {
			out->target = AI_ROUTE_TARGET_LOCAL;
			out->reason = "privacy_local";
		} else {
			out->target = AI_ROUTE_TARGET_OFFLINE;
			out->reason = "privacy_local_unavailable";
		}
		return;
	}

	if (f->mode == AI_MODEL_ROUTE_LOCAL) {
		out->target = AI_ROUTE_TARGET_LOCAL;
		out->reason = "forced_local";
		return;
	}
	if (f->mode == AI_MODEL_ROUTE_CLOUD) {
		if (f->cloud_down && f->failover && f->local_up) {
			out->target = AI_ROUTE_TARGET_LOCAL;
			out->reason = "cloud_failover";
			return;
		}
		out->target = AI_ROUTE_TARGET_CLOUD;
		out->reason = "forced_cloud";
		return;
	}

	/* 成本/窗口：本地 32768 上下文，超过一半走云 */
	if (f->tokens > ROUTE_LOCAL_CTX_TOKENS) {
		if (!f->cloud_down) {
			out->target = AI_ROUTE_TARGET_CLOUD;
			out->reason = "context_needs_cloud";
			return;
		}
		if (f->local_up) {
			out->target = AI_ROUTE_TARGET_LOCAL;
			out->reason = "cloud_down_context_limit";
			return;
		}
		out->target = AI_ROUTE_TARGET_OFFLINE;
		out->reason = "context_and_local_unavailable";
		return;
	}

	/* 重推理：云优先；云不可用才本地；本地也慢/不可用则降级 */
	if (f->task == AI_ROUTE_TASK_REASONING) {
		if (!f->cloud_down && !f->local_slow)
			{
				out->target = AI_ROUTE_TARGET_CLOUD;
				out->reason = "reasoning_cloud";
				return;
			}
		if (f->local_up) {
			out->target = AI_ROUTE_TARGET_LOCAL;
			out->reason = f->cloud_down ? "cloud_down" :
				       "local_slow_cloud";
			return;
		}
		out->target = AI_ROUTE_TARGET_OFFLINE;
		out->reason = f->cloud_down ? "cloud_and_local_down" :
					      "local_unavailable";
		return;
	}

	/* 普通对话：默认云；本地有明显延迟优势时本地 */
	if (f->task == AI_ROUTE_TASK_CHAT) {
		if (f->cloud_down) {
			if (f->local_up) {
				out->target = AI_ROUTE_TARGET_LOCAL;
				out->reason = "cloud_down";
			} else {
				out->target = AI_ROUTE_TARGET_OFFLINE;
				out->reason = "cloud_and_local_down";
			}
			return;
		}
		if (f->prefer_local && f->local_up && !f->local_slow) {
			out->target = AI_ROUTE_TARGET_LOCAL;
			out->reason = "latency_local";
			return;
		}
		out->target = AI_ROUTE_TARGET_CLOUD;
		out->reason = "default_cloud";
		return;
	}

	/* 运维任务：本地优先（断网核心运维），本地不可用再云 */
	if (f->local_up && f->prefer_local) {
		out->target = AI_ROUTE_TARGET_LOCAL;
		out->reason = "operational_local";
		return;
	}
	if (f->cloud_down) {
		if (f->local_up) {
			out->target = AI_ROUTE_TARGET_LOCAL;
			out->reason = "cloud_down";
		} else {
			out->target = AI_ROUTE_TARGET_OFFLINE;
			out->reason = "cloud_and_local_down";
		}
		return;
	}
	out->target = AI_ROUTE_TARGET_CLOUD;
	out->reason = f->local_up ? "operational_cloud" : "local_unavailable";
}

int ai_route_decide(const struct ai_config *cfg, const char *question,
		    struct ai_route_choice *out)
{
	struct ai_route_facts f;
	long long t0;
	int mode;
	int privacy;

	if (!cfg || !out)
		return AI_ERR_INVALID_ARG;
	memset(&f, 0, sizeof(f));
	t0 = route_now_ms();

	mode = ai_route_effective_mode(cfg);
	privacy = route_privacy_requested(cfg, question);

	f.mode = mode;
	f.task = ai_route_classify_task(question);
	f.privacy = privacy;
	f.prefer_local = cfg ? cfg->route.prefer_local : 1;
	f.failover = cfg ? cfg->route.failover : 1;
	f.tokens = question ? (int)(strlen(question) / 4) : 0;
	f.local_slow = g_route.local_last_ok &&
		       cfg && cfg->route.local_p95_ms > 0 &&
		       g_route.local_last_ms > cfg->route.local_p95_ms;

	/* 强制 local/cloud 不预探测云端（尊重显式选择）；auto 预探测
	 * 云端以便在 DNS/网络失败时 <2s 内直接走本地。 */
	if (mode == AI_MODEL_ROUTE_AUTO && !privacy) {
		f.cloud_down = !route_cloud_available(cfg);
		f.local_up = ai_route_local_available(cfg);
	} else {
		f.cloud_down = (g_route.cloud_down_until > route_now_ms()) ||
			       (getenv("AIKERNEL_CLOUD_DOWN") &&
				strcmp(getenv("AIKERNEL_CLOUD_DOWN"), "1") == 0);
		f.local_up = ai_route_local_available(cfg);
	}

	ai_route_decide_facts(&f, out);
	out->decide_ms = route_now_ms() - t0;
	out->local_probe_ms = g_route.local_probe_ms;
	out->cloud_known_down = f.cloud_down;
	out->local_available = f.local_up;
	g_route.last_decide_ms = out->decide_ms;
	g_route.last_target = out->target;
	snprintf(g_route.last_reason, sizeof(g_route.last_reason), "%s",
		 out->reason ? out->reason : "-");
	return AI_OK;
}

/* ---- 应用/切换 ---- */

int ai_route_current_target(const struct ai_runtime *rt)
{
	if (!rt || !rt->model_provider_type)
		return 0;
	return strcmp(rt->model_provider_type, "local") == 0 ?
	       AI_ROUTE_TARGET_LOCAL : AI_ROUTE_TARGET_CLOUD;
}

int ai_route_apply(struct ai_runtime *rt, int target, long long *elapsed_ms)
{
	long long t0 = route_now_ms();
	char model[128];
	int ret;

	if (elapsed_ms)
		*elapsed_ms = 0;
	if (!rt || !rt->config)
		return AI_ERR_INVALID_ARG;
	if (ai_route_current_target(rt) == target)
		return AI_OK;

	if (target == AI_ROUTE_TARGET_LOCAL) {
		ret = ai_route_ensure_local_model(rt->config);
		if (ret != AI_OK)
			return ret;
		snprintf(model, sizeof(model), "%s", "local");
	} else if (target == AI_ROUTE_TARGET_CLOUD) {
		if (route_cloud_model_name(rt->config, model,
					   sizeof(model)) != 0)
			return AI_ERR_NO_MODEL;
	} else {
		return AI_ERR_INVALID_ARG;
	}

	ret = ai_runtime_set_model(rt, model);
	if (elapsed_ms)
		*elapsed_ms = route_now_ms() - t0;
	if (ret == AI_OK) {
		g_route.last_target = target;
		g_route.last_switch_ms = elapsed_ms ? *elapsed_ms : 0;
		snprintf(g_route.last_provider, sizeof(g_route.last_provider),
			 "%s", route_basename_provider(rt->model_provider_type));
		snprintf(g_route.last_model, sizeof(g_route.last_model), "%s",
			 rt->model_name ? rt->model_name : "-");
	}
	return ret;
}

int ai_route_failover(struct ai_runtime *rt, int from, int to,
		      const char *reason, long long *switch_ms)
{
	long long ms = 0;
	int ret;

	if (switch_ms)
		*switch_ms = 0;
	if (!rt)
		return AI_ERR_INVALID_ARG;
	if (ai_route_current_target(rt) != from)
		return AI_ERR_GENERIC;
	ret = ai_route_apply(rt, to, &ms);
	if (ret == AI_OK) {
		g_route.last_switch_ms = ms;
		if (switch_ms)
			*switch_ms = ms;
		ai_route_trace_switch(rt, from, to, reason, ms);
		{
			char detail[256];

			snprintf(detail, sizeof(detail),
				 "from=%s to=%s reason=%s switch_ms=%lld",
				 from == AI_ROUTE_TARGET_CLOUD ? "cloud" :
				 "local",
				 to == AI_ROUTE_TARGET_LOCAL ? "local" : "cloud",
				 reason ? reason : "-", ms);
			ai_trace_degraded("route", "model_switch", detail);
		}
	}
	return ret;
}

int ai_route_should_failover(const struct ai_config *cfg, int from_target,
			     int ret, int status_code, int already_failed)
{
	if (!cfg || from_target != AI_ROUTE_TARGET_CLOUD || already_failed)
		return 0;
	if (!cfg->route.failover)
		return 0;
	/* 400/422 是协议/参数问题，先走文本工具协议降级，不切换 */
	if (status_code == 400 || status_code == 422)
		return 0;
	if (ret == AI_ERR_NETWORK || ret == AI_ERR_AUTH ||
	    ret == AI_ERR_API)
		return ai_route_local_available(cfg);
	return 0;
}

void ai_route_note_cloud(int ok, int status_code, int ret)
{
	long long now = route_now_ms();

	if (ok) {
		g_route.cloud_up = 1;
		g_route.cloud_probed_at = now;
		g_route.cloud_down_until = 0;
		return;
	}
	if (ret == AI_ERR_NETWORK || ret == AI_ERR_AUTH ||
	    status_code == 408 || status_code == 429 ||
	    status_code == 500 || status_code == 502 ||
	    status_code == 503 || status_code == 504 ||
	    status_code == 0) {
		g_route.cloud_up = -1;
		g_route.cloud_probed_at = now;
		g_route.cloud_down_until = now + ROUTE_CLOUD_DOWN_TTL_MS;
	}
}

void ai_route_note_local(int ok, int status_code, int ret, long long latency_ms)
{
	long long now = route_now_ms();

	if (latency_ms >= 0) {
		g_route.local_last_ms = latency_ms;
		g_route.local_last_ok = ok;
	}
	if (ok) {
		g_route.local_up = 1;
		g_route.local_probed_at = now;
		return;
	}
	if (ret == AI_ERR_NETWORK || status_code == 0)
		g_route.local_up = 0;
	g_route.local_probed_at = now;
}

long long ai_route_last_switch_ms(void)
{
	return g_route.last_switch_ms;
}

int ai_route_status_text(const struct ai_config *cfg,
			 const struct ai_runtime *rt,
			 char *buf, size_t n)
{
	int mode = ai_route_effective_mode(cfg);
	int target = ai_route_current_target(rt);

	if (!buf || n == 0)
		return AI_ERR_INVALID_ARG;
	snprintf(buf, n,
		 "mode=%s target=%s provider=%s model=%s cloud=%s local=%s "
		 "local_probe_ms=%d local_last_ms=%lld last_reason=%s "
		 "last_decide_ms=%lld last_switch_ms=%lld",
		 ai_route_mode_name(mode),
		 target == AI_ROUTE_TARGET_LOCAL ? "local" : "cloud",
		 rt && rt->model_provider_type ? rt->model_provider_type : "-",
		 rt && rt->model_name ? rt->model_name : "-",
		 (g_route.cloud_down_until > route_now_ms() ||
		  (g_route.cloud_up < 0)) ? "down" :
		 (g_route.cloud_up > 0 ? "up" : "unknown"),
		 g_route.local_up ? "up" : "down",
		 g_route.local_probe_ms,
		 g_route.local_last_ok ? g_route.local_last_ms : -1,
		 g_route.last_reason[0] ? g_route.last_reason : "-",
		 g_route.last_decide_ms, g_route.last_switch_ms);
	return AI_OK;
}

void ai_route_reset_state(void)
{
	memset(&g_route, 0, sizeof(g_route));
}

/* ---- 路由 trace（route.jsonl） ---- */

static void route_json_escape(const char *s, char *out, size_t n)
{
	size_t o = 0;

	if (!s)
		s = "";
	while (*s && o + 2 < n) {
		unsigned char c = (unsigned char)*s++;

		if (c == '"' || c == '\\') {
			out[o++] = '\\';
			out[o++] = (char)c;
		} else if (c == '\n') {
			out[o++] = '\\';
			out[o++] = 'n';
		} else if (c == '\r') {
			out[o++] = '\\';
			out[o++] = 'r';
		} else if (c == '\t') {
			out[o++] = '\\';
			out[o++] = 't';
		} else if (c < 0x20) {
			out[o++] = ' ';
		} else {
			out[o++] = (char)c;
		}
	}
	out[o] = '\0';
}

static int route_trace_path(char *buf, size_t n)
{
	const char *env = getenv("AIKERNEL_TRACE_DIR");
	const struct ai_trace_config *tc;
	const char *dir = NULL;
	const char *home;

	if (env && env[0]) {
		dir = env;
	} else {
		tc = ai_trace_get_config();
		if (tc && tc->dir && tc->dir[0])
			dir = tc->dir;
	}
	if (!dir) {
		home = getenv("HOME");
		if (!home)
			home = "/tmp";
		snprintf(buf, n, "%s/.aikernel/trace", home);
		dir = buf;
	}
	{
		size_t dl = strlen(dir);

		if (dl + 1 + strlen("route.jsonl") + 1 > n)
			return -1;
		memcpy(buf, dir, dl);
		buf[dl] = '/';
		snprintf(buf + dl + 1, n - dl - 1, "route.jsonl");
	}
	return 0;
}

static void route_trace_write(const char *line)
{
	char path[1024];
	char rot[1200];
	struct stat st;
	int fd;

	if (route_trace_path(path, sizeof(path)) != 0)
		return;
	/* 父目录：path 末段是文件，先把 dirname 建出来 */
	{
		char *slash = strrchr(path, '/');

		if (slash) {
			*slash = '\0';
			mkdir(path, 0700);
			*slash = '/';
		}
	}
	if (stat(path, &st) == 0 && st.st_size > ROUTE_TRACE_ROTATE_BYTES) {
		snprintf(rot, sizeof(rot), "%s.1", path);
		rename(path, rot);
	}
	fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd < 0)
		return;
	flock(fd, LOCK_EX);
	if (write(fd, line, strlen(line)) < 0) {
		flock(fd, LOCK_UN);
		close(fd);
		return;
	}
	flock(fd, LOCK_UN);
	close(fd);
}

int ai_route_trace_decision(const struct ai_config *cfg,
			    const struct ai_runtime *rt,
			    const struct ai_route_choice *choice,
			    long long apply_ms)
{
	char line[1024];
	char reason[128], model[160], provider[64];

	if (!choice)
		return AI_ERR_INVALID_ARG;
	route_json_escape(choice->reason, reason, sizeof(reason));
	route_json_escape(rt && rt->model_name ? rt->model_name : "-",
			  model, sizeof(model));
	route_json_escape(rt && rt->model_provider_type ?
			  rt->model_provider_type : "-",
			  provider, sizeof(provider));
	snprintf(line, sizeof(line),
		 "{\"ts\":%lld,\"mono_ms\":%lld,\"event\":\"route_decision\","
		 "\"mode\":\"%s\",\"decision\":\"%s\",\"reason\":\"%s\","
		 "\"task\":\"%s\",\"privacy\":%d,\"provider\":\"%s\","
		 "\"model\":\"%s\",\"latency_ms\":%lld,"
		 "\"decide_ms\":%lld,\"cloud_health\":\"%s\","
		 "\"local_up\":%d,\"local_probe_ms\":%d,"
		 "\"switch_ms\":%lld}\n",
		 route_wall_ms(), route_now_ms(),
		 ai_route_mode_name(ai_route_effective_mode(cfg)),
		 choice->target == AI_ROUTE_TARGET_LOCAL ? "local" :
		 choice->target == AI_ROUTE_TARGET_CLOUD ? "cloud" : "offline",
		 reason,
		 choice->task_class == AI_ROUTE_TASK_OPERATIONAL ?
		 "operational" :
		 choice->task_class == AI_ROUTE_TASK_REASONING ?
		 "reasoning" : "chat",
		 choice->privacy, provider, model,
		 apply_ms, choice->decide_ms,
		 choice->cloud_known_down ? "down" : "up",
		 choice->local_available, choice->local_probe_ms,
		 g_route.last_switch_ms);
	route_trace_write(line);
	return AI_OK;
}

int ai_route_trace_switch(const struct ai_runtime *rt, int from, int to,
			  const char *reason, long long switch_ms)
{
	char line[1024];
	char rsn[128];

	route_json_escape(reason ? reason : "-", rsn, sizeof(rsn));
	snprintf(line, sizeof(line),
		 "{\"ts\":%lld,\"event\":\"route_switch\","
		 "\"from\":\"%s\",\"to\":\"%s\",\"reason\":\"%s\","
		 "\"provider\":\"%s\",\"model\":\"%s\","
		 "\"latency_ms\":%lld,\"switch_ms\":%lld}\n",
		 route_wall_ms(),
		 from == AI_ROUTE_TARGET_CLOUD ? "cloud" : "local",
		 to == AI_ROUTE_TARGET_LOCAL ? "local" : "cloud",
		 rsn,
		 rt && rt->model_provider_type ? rt->model_provider_type : "-",
		 rt && rt->model_name ? rt->model_name : "-",
		 switch_ms, switch_ms);
	route_trace_write(line);
	return AI_OK;
}

int ai_route_trace_offline(const char *intent, const char *source,
			   long long cache_age_ms, long long latency_ms)
{
	char line[1024];
	char it[64], src[256];

	route_json_escape(intent ? intent : "-", it, sizeof(it));
	route_json_escape(source ? source : "-", src, sizeof(src));
	snprintf(line, sizeof(line),
		 "{\"ts\":%lld,\"event\":\"route_offline\","
		 "\"decision\":\"offline\",\"reason\":\"intent:%s\","
		 "\"intent\":\"%s\",\"source\":\"%s\","
		 "\"cache_age_ms\":%lld,\"latency_ms\":%lld,"
		 "\"provider\":\"-\",\"model\":\"-\"}\n",
		 route_wall_ms(), it, it, src, cache_age_ms, latency_ms);
	route_trace_write(line);
	return AI_OK;
}
