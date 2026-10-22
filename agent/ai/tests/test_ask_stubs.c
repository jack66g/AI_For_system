/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_ask_stubs.c - cmd_ask 集成测试的外部依赖桩（W55 P1）
 *
 * 只桩掉 shell 环境（配置/SME/netlink/界面/轨迹/会话），注册表、工具
 * 查找、请求序列化、文本协议解析全部用真实实现。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ai_shell.h"
#include "ai_config.h"
#include "ai_runtime.h"
#include "ai_ui.h"
#include "ai_lang.h"
#include "ai_trace.h"
#include "netlink/ai_netlink_client.h"
#include "local/offline_intent.h"
#include "memory/sme_client.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"
#include "policy/ai_user_policy.h"
#include "test_ask_stubs.h"

ask_mock_chat_fn g_ask_mock_chat;
int g_ask_mock_calls;
char g_ask_dispatched[16][128];
int g_ask_dispatch_count;
ask_mock_tool_fn g_ask_mock_tool;

/* W56：policy/会话/compact 可配置桩（默认值保持 W55 行为） */
int g_ask_policy_assume_yes;
int g_ask_policy_plan_mode;
struct ai_chat_msg *g_ask_session_msgs;
int g_ask_session_n;
ask_mock_compact_fn g_ask_mock_compact;
int g_ask_compact_calls;
long g_ask_compact_target;
int g_ask_compact_attempt;
int g_ask_compact_kept = 1;
long g_ask_compact_after;

/* W59：ui_session_replace 的进程内存储（深拷贝，跨 cmd_ask 重载可见） */
#define STUB_SESS_MAX 256
#define STUB_ALLOC_MAX (STUB_SESS_MAX * 5)
static struct ai_chat_msg g_stub_sess[STUB_SESS_MAX];
static char *g_stub_allocs[STUB_ALLOC_MAX];
static int g_stub_nalloc;

static void stub_store_free(void)
{
	int i;

	for (i = 0; i < g_stub_nalloc; i++)
		free(g_stub_allocs[i]);
	g_stub_nalloc = 0;
	memset(g_stub_sess, 0, sizeof(g_stub_sess));
}

static char *stub_strdup(const char *s)
{
	char *d;

	if (!s)
		return NULL;
	d = strdup(s);
	if (d && g_stub_nalloc < STUB_ALLOC_MAX)
		g_stub_allocs[g_stub_nalloc++] = d;
	return d;
}

void test_ask_session_reset(void)
{
	stub_store_free();
	g_ask_session_msgs = NULL;
	g_ask_session_n = 0;
}

int test_ask_session_contains(const char *needle)
{
	int i, n = 0;

	if (!needle)
		return 0;
	for (i = 0; i < g_ask_session_n; i++) {
		if (g_ask_session_msgs[i].content &&
		    strstr(g_ask_session_msgs[i].content, needle))
			n++;
	}
	return n;
}

/* ---- 配置 ---- */
const char *ai_config_get_default_model(struct ai_config *cfg)
{
	(void)cfg;
	return "mock-model";
}

int ai_config_get_model(struct ai_config *cfg, const char *name,
			char **provider_type, char **model_name,
			char **base_url, char **api_key)
{
	(void)cfg;
	(void)name;
	if (provider_type)
		*provider_type = strdup("openai_compatible");
	if (model_name)
		*model_name = strdup("mock-model");
	if (base_url)
		*base_url = strdup("http://127.0.0.1:1");
	if (api_key)
		*api_key = strdup("x");
	return AI_OK;
}

int ai_config_get_models(struct ai_config *cfg, char ***names, int *count)
{
	(void)cfg;
	if (names)
		*names = NULL;
	if (count)
		*count = 0;
	return AI_OK;
}

/* W59：与 config_manager.c 同口径（云端缺省 8192 / 本地 1024） */
int ai_config_effective_max_tokens(const struct ai_config *cfg,
				   const char *provider_type)
{
	if (provider_type &&
	    strcmp(provider_type, "openai_compatible") == 0) {
		const struct ai_model_config *m;

		if (cfg && cfg->default_model) {
			for (m = cfg->models_head; m; m = m->next) {
				if (m->name && m->max_tokens > 0 &&
				    strcmp(m->name, cfg->default_model) == 0)
					return m->max_tokens;
			}
		}
		return 8192;
	}
	if (cfg && cfg->local.max_tokens > 0)
		return cfg->local.max_tokens;
	if (cfg && cfg->ui.max_tokens > 0)
		return cfg->ui.max_tokens;
	return 1024;
}

int ai_config_set_default_model(struct ai_config *cfg, const char *name)
{
	(void)cfg;
	(void)name;
	return AI_OK;
}

int ai_config_save(struct ai_config *cfg)
{
	(void)cfg;
	return AI_OK;
}

/* ---- W77 路由/离线意图（ask 单测保持既有云路径行为） ----
 *
 * 这些 stub 让 cmd_ask 的 W77 分支在旧测试中成为 no-op：
 * 路由固定 cloud（与 ai_runtime_set_model stub 的 provider 一致），
 * 离线意图关闭，失败切换关闭（保留既有 tools 文本协议降级断言）。
 */
int ai_route_decide(const struct ai_config *cfg, const char *question,
		    struct ai_route_choice *out)
{
	(void)cfg;
	(void)question;
	if (!out)
		return AI_ERR_INVALID_ARG;
	memset(out, 0, sizeof(*out));
	out->target = AI_ROUTE_TARGET_CLOUD;
	out->mode = AI_MODEL_ROUTE_AUTO;
	out->reason = "stub_cloud";
	out->task_class = AI_ROUTE_TASK_OPERATIONAL;
	return AI_OK;
}

int ai_route_offline_intents_enabled(const struct ai_config *cfg)
{
	(void)cfg;
	return 0;
}

int ai_route_current_target(const struct ai_runtime *rt)
{
	if (rt && rt->model_provider_type &&
	    strcmp(rt->model_provider_type, "local") == 0)
		return AI_ROUTE_TARGET_LOCAL;
	return AI_ROUTE_TARGET_CLOUD;
}

int ai_route_apply(struct ai_runtime *rt, int target, long long *ms)
{
	(void)rt;
	(void)target;
	if (ms)
		*ms = 0;
	return AI_OK;
}

int ai_route_failover(struct ai_runtime *rt, int from, int to,
		      const char *reason, long long *ms)
{
	(void)rt;
	(void)from;
	(void)to;
	(void)reason;
	if (ms)
		*ms = 0;
	return AI_OK;
}

int ai_route_should_failover(const struct ai_config *cfg, int from,
			     int ret, int status, int already)
{
	(void)cfg;
	(void)from;
	(void)ret;
	(void)status;
	(void)already;
	return 0;
}

void ai_route_note_cloud(int ok, int status, int ret)
{
	(void)ok;
	(void)status;
	(void)ret;
}

void ai_route_note_local(int ok, int status, int ret, long long ms)
{
	(void)ok;
	(void)status;
	(void)ret;
	(void)ms;
}

const char *ai_route_mode_name(int mode)
{
	(void)mode;
	return "auto";
}

int ai_route_effective_mode(const struct ai_config *cfg)
{
	(void)cfg;
	return AI_MODEL_ROUTE_AUTO;
}

int ai_route_trace_decision(const struct ai_config *cfg,
			    const struct ai_runtime *rt,
			    const struct ai_route_choice *choice,
			    long long apply_ms)
{
	(void)cfg;
	(void)rt;
	(void)choice;
	(void)apply_ms;
	return AI_OK;
}

int ai_route_trace_offline(const char *intent, const char *source,
			   long long age, long long latency)
{
	(void)intent;
	(void)source;
	(void)age;
	(void)latency;
	return AI_OK;
}

int ai_offline_intent_match(const char *question, const struct ai_config *cfg,
			    struct ai_offline_answer *ans)
{
	(void)question;
	(void)cfg;
	if (ans)
		memset(ans, 0, sizeof(*ans));
	return 0;
}

void ai_offline_answer_free(struct ai_offline_answer *ans)
{
	(void)ans;
}

int ai_offline_cache_plan(const char *question, const char *route,
			  const char *status, int rounds,
			  const char *tools_csv, const char *detail)
{
	(void)question;
	(void)route;
	(void)status;
	(void)rounds;
	(void)tools_csv;
	(void)detail;
	return AI_OK;
}

/* ---- runtime ---- */
int ai_runtime_set_model(struct ai_runtime *rt, const char *model_name)
{
	if (!rt || !model_name)
		return AI_ERR_INVALID_ARG;
	free(rt->current_model);
	rt->current_model = strdup(model_name);
	free(rt->model_provider_type);
	rt->model_provider_type = strdup("openai_compatible");
	free(rt->model_name);
	rt->model_name = strdup(model_name);
	free(rt->model_base_url);
	rt->model_base_url = strdup("http://127.0.0.1:1");
	free(rt->model_api_key);
	rt->model_api_key = strdup("x");
	return AI_OK;
}

int ai_runtime_chat_ex(struct ai_runtime *rt,
		       const struct ai_chat_msg *msgs, int nmsgs,
		       const char *tools_json,
		       ai_stream_delta_cb on_delta, void *on_delta_ud,
		       struct ai_chat_result **result)
{
	int rc;

	(void)on_delta;
	(void)on_delta_ud;
	if (!result)
		return AI_ERR_INVALID_ARG;
	*result = NULL;
	g_ask_mock_calls++;
	if (!g_ask_mock_chat)
		return AI_ERR_API;
	rc = g_ask_mock_chat(g_ask_mock_calls, msgs, nmsgs, tools_json,
			     result);
	/* W56 T5：与真实 runtime 一致回填最近一次请求 usage */
	if (rc == AI_OK && rt && *result) {
		rt->token_last_in = (*result)->prompt_tokens;
		rt->token_last_out = (*result)->completion_tokens;
	}
	return rc;
}

/* ---- policy / compact ---- */
int ai_policy_get_plan_mode(void)
{
	return g_ask_policy_plan_mode;
}

int ai_policy_get_assume_yes(void)
{
	return g_ask_policy_assume_yes;
}

int cmd_compact(void *shell, int argc, char **argv)
{
	(void)argc;
	(void)argv;
	g_ask_compact_calls++;
	if (g_ask_mock_compact)
		return g_ask_mock_compact(shell);
	return AI_ERR_INVALID_ARG;
}

int cmd_compact_apply(void *shell, long target_tokens, int attempt)
{
	g_ask_compact_calls++;
	g_ask_compact_target = target_tokens;
	g_ask_compact_attempt = attempt;
	if (g_ask_mock_compact)
		return g_ask_mock_compact(shell);
	return AI_ERR_INVALID_ARG;
}

int cmd_compact_last_kept(void)
{
	return g_ask_compact_kept;
}

long cmd_compact_last_after(void)
{
	return g_ask_compact_after;
}

/* ---- SME / netlink ---- */
int sme_search(const char *text, int top_k, char *out, size_t n)
{
	(void)text;
	(void)top_k;
	(void)out;
	(void)n;
	return AI_ERR_NETWORK;
}

int sme_degrade_reason_of(int rc)
{
	(void)rc;
	return 0;
}

int ai_nl_client_open(struct ai_nl_client *cli)
{
	(void)cli;
	return AI_ERR_NETWORK;
}

void ai_nl_client_close(struct ai_nl_client *cli)
{
	(void)cli;
}

int ai_nl_send_sense(struct ai_nl_client *cli,
		     __u32 cpu, __u32 max_records, __u32 format,
		     struct ai_nl_sense_ack *ack,
		     void *stream, size_t stream_cap, size_t *stream_len,
		     int *kern_err)
{
	(void)cli;
	(void)cpu;
	(void)max_records;
	(void)format;
	(void)stream;
	(void)stream_cap;
	if (ack)
		memset(ack, 0, sizeof(*ack));
	if (stream_len)
		*stream_len = 0;
	if (kern_err)
		*kern_err = 0;
	return AI_ERR_NETWORK;
}

/* ---- 工具执行：记录分发，memory_search 返回可激活工具名 ---- */
int tool_executor_run(const struct ai_tool *tool, const char *args_json,
		      char **out, int *ok)
{
	const char *name = tool ? tool->name : "?";

	if (g_ask_dispatch_count < 16)
		snprintf(g_ask_dispatched[g_ask_dispatch_count++],
			 sizeof(g_ask_dispatched[0]), "%s", name);
	if (g_ask_mock_tool)
		return g_ask_mock_tool(tool, args_json, out, ok);
	if (ok)
		*ok = 1;
	if (strcmp(name, "memory_search") == 0) {
		*out = strdup("{\"query\":\"sandbox\",\"count\":1,"
			      "\"results\":[{\"text\":\"sandbox_status "
			      "sandbox_create sandbox_spawn sandbox_destroy\"}]}");
	} else {
		if (asprintf(out, "MOCK_OK %s args=%s", name,
			     args_json ? args_json : "{}") < 0)
			*out = NULL;
	}
	return AI_OK;
}

/* ---- UI ---- */
const char *ui_c(int cfg_color, const char *code)
{
	(void)cfg_color;
	(void)code;
	return "";
}

int ui_fbterm_compat(void)
{
	return 0;
}

void ui_spinner_start(const char *stage)
{
	(void)stage;
}

void ui_spinner_stop(void)
{
}

int ui_ctx_percent(long used, long ctx_len)
{
	if (ctx_len <= 0)
		return 0;
	{
		long pct = (used < 0 ? 0 : used) * 100 / ctx_len;

		return (int)(pct > 999 ? 999 : pct);
	}
}

/* W77b2：ask 单测不需要真实侧车文件；返回不可用使 restore/save no-op。 */
int ui_session_path(const char *name, char *buf, size_t len)
{
	(void)name;
	if (buf && len)
		buf[0] = '\0';
	return AI_ERR_STORAGE;
}

int ui_session_count(const char *name)
{
	(void)name;
	return g_ask_session_n;
}

int ui_session_load(const char *name, struct ai_chat_msg **msgs,
		    int *nmsgs, char ***strings, int *nstr)
{
	(void)name;
	/* W56 T5：默认空会话；测试可注入静态历史（无 pool，cmd_ask
	 * 只释放 pool 不逐条 free content）。 */
	if (msgs)
		*msgs = g_ask_session_msgs;
	if (nmsgs)
		*nmsgs = g_ask_session_n;
	if (strings)
		*strings = NULL;
	if (nstr)
		*nstr = 0;
	return AI_OK;
}

int ui_session_append(const char *name, const struct ui_session_rec *rec)
{
	int n;

	(void)name;
	if (!rec || !rec->role || g_ask_session_msgs != g_stub_sess)
		return AI_OK;
	n = g_ask_session_n;
	if (n < 0 || n >= STUB_SESS_MAX)
		return AI_OK;
	g_stub_sess[n].role = stub_strdup(rec->role);
	g_stub_sess[n].content = stub_strdup(rec->content);
	g_stub_sess[n].tool_call_id = stub_strdup(rec->tool_call_id);
	g_stub_sess[n].tool_name = stub_strdup(rec->tool_name);
	g_stub_sess[n].tool_calls_json = stub_strdup(rec->tool_calls_json);
	g_ask_session_n = n + 1;
	return AI_OK;
}

int ui_session_replace(const char *name, const struct ui_session_rec *recs,
		       int nrecs)
{
	int i;

	(void)name;
	if (nrecs < 0 || (nrecs > 0 && !recs))
		return AI_ERR_INVALID_ARG;
	if (nrecs > STUB_SESS_MAX)
		nrecs = STUB_SESS_MAX;
	/*
	 * 注意：不在这里 free 旧存储——recs 可能正指向旧存储的字符串
	 * （cmd_ask 的截断路径），先复制再覆盖；旧串由用例 reset 统一释放。
	 */
	memset(g_stub_sess, 0, sizeof(g_stub_sess));
	for (i = 0; i < nrecs; i++) {
		g_stub_sess[i].role = stub_strdup(recs[i].role ?
						  recs[i].role : "user");
		g_stub_sess[i].content = stub_strdup(recs[i].content);
		g_stub_sess[i].tool_call_id =
			stub_strdup(recs[i].tool_call_id);
		g_stub_sess[i].tool_name = stub_strdup(recs[i].tool_name);
		g_stub_sess[i].tool_calls_json =
			stub_strdup(recs[i].tool_calls_json);
	}
	g_ask_session_msgs = g_stub_sess;
	g_ask_session_n = nrecs;
	return AI_OK;
}

/* ---- 轨迹（全部 no-op） ---- */
int ai_trace_hash_file(const char *path, char *out, size_t n)
{
	(void)path;
	if (out && n)
		snprintf(out, n, "TESTHASH");
	return 0;
}

int ai_trace_session_start(const char *session, const char *model,
			   const char *provider, int ctx_len, int max_tokens,
			   int stream, const char *routing,
			   const char *tools_hash)
{
	(void)session; (void)model; (void)provider; (void)ctx_len;
	(void)max_tokens; (void)stream; (void)routing; (void)tools_hash;
	return 0;
}

int ai_trace_turn_start(const char *question)
{
	(void)question;
	return 1;
}

int ai_trace_turn_end(const char *reason, int rounds)
{
	(void)reason;
	(void)rounds;
	return 0;
}

long long ai_trace_now_ms(void)
{
	return 0;
}

long long ai_trace_wall_ms(void)
{
	return 0;
}

int ai_trace_route_activate(const char *trigger_token,
			    const char *const *tools, int ntools,
			    int active_before, int active_after)
{
	(void)trigger_token; (void)tools; (void)ntools;
	(void)active_before; (void)active_after;
	return 0;
}

/* W69：cmd_ask 现在记录 effective risk / memory 真实返回码。本测试面
 * 不链接 executor.c，提供等价最小桩（静态 risk、无降级）。 */
const char *tool_exec_effective_risk(const struct ai_tool *tool,
				     const char *args_json)
{
	(void)args_json;
	return (tool && tool->risk) ? tool->risk : "W1";
}

int tool_exec_memory_last_rc(void)
{
	return 0;
}

int tool_exec_result_is_denied(const char *out)
{
	return out && (strstr(out, "ERROR: DENIED:") != NULL ||
		       strstr(out, "ERROR[E_PARAM_PATH]") != NULL);
}

int ai_trace_tool_call_status(const char *tool, const char *channel,
			      const char *risk, const char *args_json,
			      long long start_wall_ms, long duration_ms,
			      const char *status, int exit_code,
			      const char *result, size_t result_len)
{
	(void)tool; (void)channel; (void)risk; (void)args_json;
	(void)start_wall_ms; (void)duration_ms; (void)status;
	(void)exit_code; (void)result; (void)result_len;
	return 0;
}

/* W74：cmd_ask 用扩展 trace 与租约元数据（本测试面不链租约模块） */
int ai_trace_tool_call_ex(const char *tool, const char *channel,
			  const char *risk, const char *args_json,
			  long long start_wall_ms, long duration_ms,
			  const char *status, int exit_code,
			  const char *result, size_t result_len,
			  const char *danger, const char *lease_id)
{
	(void)tool; (void)channel; (void)risk; (void)args_json;
	(void)start_wall_ms; (void)duration_ms; (void)status;
	(void)exit_code; (void)result; (void)result_len;
	(void)danger; (void)lease_id;
	return 0;
}

void ai_lease_last_reset(void)
{
}

const char *ai_lease_last_danger(void)
{
	return NULL;
}

const char *ai_lease_last_lease_id(void)
{
	return NULL;
}

int ai_trace_degraded(const char *component, const char *reason_code,
		      const char *detail)
{
	(void)component; (void)reason_code; (void)detail;
	return 0;
}

int ai_trace_error(const char *phase, const char *code, const char *message)
{
	(void)phase; (void)code; (void)message;
	return 0;
}

/* W77c：clarify 轨迹桩（本测试面不链接 ai_trace.c） */
int ai_trace_clarify_request(const char *nonce, const char *kind,
			     const char *question,
			     const char *const *option_ids, int n_options,
			     const char *recommended, int multi_select,
			     int tty)
{
	(void)nonce; (void)kind; (void)question; (void)option_ids;
	(void)n_options; (void)recommended; (void)multi_select; (void)tty;
	return 0;
}

int ai_trace_clarify_answer(const char *nonce, const char *kind,
			    const char *const *option_ids, int n_options,
			    const char *recommended,
			    const char *const *selected_ids, int n_selected,
			    const char *selected_text, const char *status,
			    int attempts, long elapsed_ms)
{
	(void)nonce; (void)kind; (void)option_ids; (void)n_options;
	(void)recommended; (void)selected_ids; (void)n_selected;
	(void)selected_text; (void)status; (void)attempts; (void)elapsed_ms;
	return 0;
}
