/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_router_cap.c - W72：router 激活上限 32
 *
 * 背景：W70 长会话实测 tools 数组最多扩到 74/130，schema 体积与请求
 * 延迟明显上升。总控已在 cmd_ask.c 加入 ASK_ROUTER_MAX_ACTIVE=32；
 * 本测试通过真实 cmd_ask 主循环 + mock SME 结果（40 个真实工具名）
 * 断言：
 *   - round1 = 默认 8 件；
 *   - round2 = 32 件（8 默认 + 24 检索命中），超出的 16 个被截断；
 *   - 默认 8 件全部保留，不被检索结果挤出。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_chat.h"
#include "ai_lang.h"
#include "test_ask_stubs.h"

static int g_fail;

#define CHECK(cond, msg)						\
	do {								\
		if (cond) {						\
			printf("  [PASS] %s\n", msg);			\
		} else {						\
			printf("  [FAIL] %s (%s:%d)\n", msg,		\
			       __FILE__, __LINE__);			\
			g_fail++;					\
		}							\
	} while (0)

static const char *const g_defaults[] = {
	"memory_search", "memory_stats", "memory_health", "exec_run",
	"procfs_read_status", "procfs_read_control", "netlink_sense",
	"clarify",
};

/* 40 个非默认工具（全部存在于 tools.json） */
static const char *const g_names[] = {
	"procfs_read_decisions", "procfs_read_chains",
	"procfs_read_latency", "procfs_read_hitrate",
	"procfs_read_telemetry", "procfs_read_sched_stats",
	"procfs_read_sched_classify", "procfs_read_vfs_stats",
	"procfs_read_vfs_rates",
	"procfs_read_stats_telemetry_emitted",
	"procfs_read_stats_telemetry_dropped",
	"procfs_read_stats_telemetry_sampled_skip",
	"procfs_read_stats_decisions_total",
	"procfs_read_stats_decisions_hit",
	"procfs_read_stats_decisions_hitrate_permille",
	"procfs_read_stats_runtime_state",
	"procfs_read_cgroup_inferences", "procfs_read_net_nf_conntrack",
	"sysfs_write_enabled", "sysfs_write_model_load",
	"sysfs_write_model_unload", "sysfs_write_policy_think",
	"sysfs_write_policy_outcome", "sysfs_write_policy_global_enable",
	"sysfs_write_policy_max_impact_pct",
	"sysfs_write_policy_rollback", "sysfs_write_policy_refresh",
	"sysfs_write_policy_chain_dir", "procfs_write_telemetry_format",
	"procfs_write_telemetry_reset", "netlink_act_sched_nice",
	"netlink_act_sched_affinity", "netlink_act_sched_oom_score",
	"netlink_act_sched_timeslice", "netlink_act_mm_swappiness",
	"netlink_act_mm_readahead", "netlink_act_mm_thp",
	"netlink_act_mm_reclaim_prio", "netlink_act_io_priority",
	"netlink_act_io_bandwidth",
};
#define N_NAMES (sizeof(g_names) / sizeof(g_names[0]))
#define N_DEFAULTS (sizeof(g_defaults) / sizeof(g_defaults[0]))
#define ROUTER_MAX_ACTIVE 32

static int count_substr(const char *hay, const char *needle)
{
	int n = 0;
	const char *p = hay;
	size_t nl = strlen(needle);

	if (!hay || !nl)
		return 0;
	while ((p = strstr(p, needle)) != NULL) {
		n++;
		p += nl;
	}
	return n;
}

static int tool_in(const char *tools_json, const char *name)
{
	char pat[128];

	snprintf(pat, sizeof(pat), "\"name\":\"%s\"", name);
	return tools_json && strstr(tools_json, pat) != NULL;
}

static struct ai_chat_result *mk_result(const char *content,
					const char *call_id,
					const char *name,
					const char *args)
{
	struct ai_chat_result *r = calloc(1, sizeof(*r));

	if (!r)
		return NULL;
	r->content = strdup(content ? content : "");
	r->finish_reason = strdup(call_id ? "tool_calls" : "stop");
	r->prompt_tokens = 3000;
	r->completion_tokens = 100;
	if (call_id) {
		r->tool_calls = calloc(1, sizeof(*r->tool_calls));
		if (!r->tool_calls) {
			free(r->content);
			free(r->finish_reason);
			free(r);
			return NULL;
		}
		r->tool_calls[0].id = strdup(call_id);
		r->tool_calls[0].name = strdup(name);
		r->tool_calls[0].arguments = strdup(args ? args : "{}");
		r->tool_call_count = 1;
	}
	return r;
}

static int mock_tool(const struct ai_tool *tool, const char *args_json,
		     char **out, int *ok)
{
	char buf[8192];
	size_t off = 0;
	size_t i;

	(void)tool;
	(void)args_json;
	off += (size_t)snprintf(buf + off, sizeof(buf) - off,
				"{\"query\":\"cap\",\"count\":40,"
				"\"results\":[{\"text\":\"");
	for (i = 0; i < N_NAMES && off + strlen(g_names[i]) + 3 < sizeof(buf);
	     i++)
		off += (size_t)snprintf(buf + off, sizeof(buf) - off,
					"%s%s", i ? " " : "", g_names[i]);
	snprintf(buf + off, sizeof(buf) - off, "\"}]}");
	*out = strdup(buf);
	if (ok)
		*ok = 1;
	return AI_OK;
}

static int mock_chat(int call_no, const struct ai_chat_msg *msgs, int nmsgs,
		     const char *tools_json, struct ai_chat_result **result)
{
	int i;
	int defaults_ok = 1;

	if (call_no == 1) {
		CHECK(tools_json != NULL, "round1 带 tools 数组");
		CHECK(count_substr(tools_json, "\"type\":\"function\"") == 8,
		      "round1 = 默认 8 件");
		CHECK(msgs && nmsgs >= 2 && msgs[0].role &&
		      strcmp(msgs[0].role, "system") == 0, "首条 system");
		*result = mk_result("", "call_cap_1", "memory_search",
				    "{\"text\":\"查工具\"}");
		return *result ? AI_OK : AI_ERR_MEMORY;
	}
	if (call_no == 2) {
		int nfun = count_substr(tools_json, "\"type\":\"function\"");

		printf("---- round2: tools=%d ----\n", nfun);
		CHECK(nfun == ROUTER_MAX_ACTIVE,
		      "round2 激活数被截断到 32");
		for (i = 0; i < (int)N_DEFAULTS; i++)
			if (!tool_in(tools_json, g_defaults[i]))
				defaults_ok = 0;
		CHECK(defaults_ok, "默认 8 件全部保留（未被检索结果挤出）");
		CHECK(tool_in(tools_json, g_names[0]),
		      "第 1 个检索命中已激活");
		CHECK(tool_in(tools_json, g_names[ROUTER_MAX_ACTIVE -
						 N_DEFAULTS - 1]),
		      "第 24 个检索命中已激活（8+24=32）");
		CHECK(!tool_in(tools_json,
			       g_names[ROUTER_MAX_ACTIVE - N_DEFAULTS]),
		      "第 25 个检索命中被截断");
		CHECK(!tool_in(tools_json, g_names[N_NAMES - 1]),
		      "第 40 个检索命中被截断");
		*result = mk_result("工具激活上限验证完成。", NULL, NULL,
				    NULL);
		return *result ? AI_OK : AI_ERR_MEMORY;
	}
	printf("  [FAIL] unexpected mock call %d\n", call_no);
	g_fail++;
	return AI_ERR_API;
}

int main(void)
{
	struct ai_config cfg;
	struct ai_shell shell;
	char *argv[] = { "ask", "检索并激活大量工具" };
	int rc;

	printf("==== test_router_cap: W72 ASK_ROUTER_MAX_ACTIVE=32 ====\n");
	lang_set("zh");
	memset(&cfg, 0, sizeof(cfg));
	cfg.default_model = strdup("mock-model");
	cfg.ui.ctx_len = 32768;
	cfg.ui.max_tokens = 8192;
	cfg.ui.stream = 0;
	cfg.ui.color = 0;
	cfg.ui.verbose = 0;
	cfg.ui.session = strdup("w72-router-cap");
	cfg.ui.lang = strdup("zh");
	cfg.routing.mode = AI_ROUTE_AUTONOMOUS;

	memset(&shell, 0, sizeof(shell));
	shell.config = &cfg;

	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	g_ask_mock_chat = mock_chat;
	g_ask_mock_tool = mock_tool;

	rc = cmd_ask(&shell, 2, argv);
	CHECK(rc == AI_OK, "cmd_ask 返回 AI_OK");
	CHECK(g_ask_mock_calls == 2, "共 2 次模型请求（检索 + 最终回答）");
	CHECK(g_ask_dispatch_count == 1 &&
	      strcmp(g_ask_dispatched[0], "memory_search") == 0,
	      "memory_search 被真实分发");

	free(cfg.default_model);
	free(cfg.ui.session);
	free(cfg.ui.lang);
	if (g_fail == 0) {
		printf("RESULT: PASS\n");
		return 0;
	}
	printf("RESULT: FAIL (%d)\n", g_fail);
	return 1;
}
