// SPDX-License-Identifier: GPL-2.0
/* test_dtchat.c - T6c 单测:意图表/别名/match_open_app/动作抽取/
 * endpoint 拼法/上下文组装/demo_reply/LLM 请求体 + dtvm 纯解析与命令串 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "desktop/dtchat.h"
#include "desktop/dtcore.h"
#include "desktop/dtjson.h"
#include "desktop/dtstate.h"
#include "desktop/dtvm.h"

#include "desktop/dthttp.h"

/* dthttp.o 经 dt_resp_json 被拉入;路由分发本体在 desktopd.c(测试不链),
 * 提供空实现满足链接 */
int dt_dispatch(struct dt_req *req, struct dt_resp *resp);

/* 便捷:字面量直接解析(长度由 strlen 取) */
static aik_json *parse_lit(const char *s)
{
	return dt_parse(s, strlen(s));
}

static int fails = 0;

static void check_str(const char *name, const char *got, const char *want)
{
	if (!got || strcmp(got, want) != 0) {
		printf("FAIL %s:\n  got : %s\n  want: %s\n", name,
		       got ? got : "(null)", want);
		fails++;
	} else {
		printf("ok %s\n", name);
	}
}

static void check_contains(const char *name, const char *got,
			   const char *needle)
{
	if (!got || !strstr(got, needle)) {
		printf("FAIL %s: 未含 %s(got=%s)\n", name, needle,
		       got ? got : "(null)");
		fails++;
	} else {
		printf("ok %s\n", name);
	}
}

static void check_bool(const char *name, int got, int want)
{
	if (got != want) {
		printf("FAIL %s: got %d want %d\n", name, got, want);
		fails++;
	} else {
		printf("ok %s\n", name);
	}
}

static void check_ll(const char *name, long long got, long long want)
{
	if (got != want) {
		printf("FAIL %s: got %lld want %lld\n", name, got, want);
		fails++;
	} else {
		printf("ok %s\n", name);
	}
}

static char g_dir[] = "/tmp/dt-test-chat-XXXXXX";

static void setup(void)
{
	if (!mkdtemp(g_dir)) {
		perror("mkdtemp");
		exit(1);
	}
	dt_path_join(g_cfg.chat_dir, sizeof(g_cfg.chat_dir), g_dir, "chats");
	mkdir(g_cfg.chat_dir, 0700);
	g_cfg.vm_enabled = 0;
}

/* 意图断言:期望为动作数组 dump(python 默认分隔符) */
static void check_intents(const char *name, const char *text,
			  const char *want_dump)
{
	aik_json *a = dt_parse_intents(text);
	char *d = a ? dt_json_dump_default(a) : NULL;

	check_str(name, d ? d : "[]", want_dump);
	free(d);
	aik_json_free(a);
}

static aik_json *fixture_apps(void)
{
	aik_json *apps = dt_new_arr();
	static const char *rows[] = {
		"{\"id\": \"alpha-demo\", \"name\": \"Alpha Demo\", "
		"\"name_en\": \"Alpha Demo\", \"name_zh\": \"阿尔法演示\"}",
		"{\"id\": \"demo-calculator\", \"name\": \"Demo Calculator\", "
		"\"name_en\": \"Demo Calculator\"}",
		"{\"id\": \"demo-settings\", \"name\": \"Demo Settings\", "
		"\"name_en\": \"Demo Settings\"}",
		"{\"id\": \"demo-terminal\", \"name\": \"Demo Terminal\", "
		"\"name_en\": \"Demo Terminal\"}",
		"{\"id\": \"info\", \"name\": \"Info Viewer\", "
		"\"name_en\": \"Info Viewer\"}"
	};

	for (int i = 0; i < 5; i++) {
		aik_json *a = dt_parse(rows[i], strlen(rows[i]));

		if (a)
			aik_json_arr_push(apps, a);
	}
	return apps;
}

/* match_open_app 断言:want=NULL 表示不命中 */
static void check_open(const char *name, const char *text,
		       aik_json *apps, const char *want_app)
{
	aik_json *oa = dt_match_open_app(text, apps);
	const aik_json *av;

	if (!want_app) {
		check_bool(name, oa == NULL, 1);
		aik_json_free(oa);
		return;
	}
	if (!oa) {
		printf("FAIL %s: 未命中(期望 %s)\n", name, want_app);
		fails++;
		return;
	}
	av = dt_get(oa, "app");
	check_str(name, av && aik_json_typeof(av) == AIK_JSON_STR
			     ? aik_json_str(av)
			     : NULL,
		  want_app);
	{
		char *d = dt_json_dump_default(oa);

		printf("    %s -> %s\n", name, d ? d : "?");
		free(d);
	}
	aik_json_free(oa);
}

/* 动作抽取断言:in 回复、初始 actions dump、期望 (回复, actions dump) */
static void check_tag(const char *name, const char *in,
		      const char *init_dump, const char *want_reply,
		      const char *want_dump)
{
	char buf[512];
	size_t len;
	aik_json *actions = dt_new_arr();

	snprintf(buf, sizeof(buf), "%s", in);
	len = strlen(buf);
	if (init_dump) {
		aik_json *init = dt_parse(init_dump, strlen(init_dump));

		if (init && aik_json_typeof(init) == AIK_JSON_ARR)
			for (size_t i = 0; i < aik_json_count(init); i++)
				dt_arr_push_copy(actions,
						 aik_json_at(init, i));
		aik_json_free(init);
	}
	dt_chat_extract_tag(buf, &len, actions);
	buf[len] = '\0';
	{
		char *d = dt_json_dump_default(actions);

		check_str(name, buf, want_reply);
		{
			char label[128];

			snprintf(label, sizeof(label), "%s(actions)", name);
			check_str(label, d ? d : "[]", want_dump);
		}
		free(d);
	}
	aik_json_free(actions);
}

static void write_chat(const char *sid, const char *json_text)
{
	char path[4096];
	FILE *f;

	dt_path_join(path, sizeof(path), g_cfg.chat_dir, sid);
	snprintf(path + strlen(path), sizeof(path) - strlen(path), ".json");
	f = fopen(path, "w");
	if (!f) {
		perror("write_chat");
		exit(1);
	}
	fprintf(f, "%s", json_text);
	fclose(f);
}

int dt_dispatch(struct dt_req *req, struct dt_resp *resp)
{
	(void)req;
	(void)resp;
	return 0;
}

int main(void)
{
	aik_json *apps;

	setup();
	apps = fixture_apps();

	/* ---------------- 意图表逐条 ---------------- */
	check_intents("intent_pink", "变粉",
		      "[{\"action\": \"set_theme\", \"theme\": \"pink\"}]");
	check_intents("intent_dark", "暗色",
		      "[{\"action\": \"set_theme\", \"theme\": \"dark\"}]");
	check_intents("intent_dark_en", "dark mode",
		      "[{\"action\": \"set_theme\", \"theme\": \"dark\"}]");
	check_intents("intent_light_dedup", "亮色 浅色",
		      "[{\"action\": \"set_theme\", \"theme\": \"light\"}]");
	check_intents("intent_show_apps", "显示应用",
		      "[{\"action\": \"show_apps\"}]");
	check_intents("intent_show_apps_en", "show apps",
		      "[{\"action\": \"show_apps\"}]");
	check_intents("intent_show_apps_list", "应用列表",
		      "[{\"action\": \"show_apps\"}]");
	check_intents("intent_switch_desktop", "切到桌面",
		      "[{\"action\": \"switch_mode\", \"mode\": \"desktop\"}]");
	check_intents("intent_switch_ai", "回到对话",
		      "[{\"action\": \"switch_mode\", \"mode\": \"ai\"}]");
	check_intents("intent_sandbox", "隔离区",
		      "[{\"action\": \"sandbox_view\"}]");
	check_intents("intent_vm_word", "看看vm",
		      "[{\"action\": \"get_vm_status\"}]");
	check_intents("intent_vm_api", "aikernel api 实况",
		      "[{\"action\": \"get_vm_status\"}]");
	check_intents("intent_status", "系统状态",
		      "[{\"action\": \"get_status\"}]");
	check_intents("intent_status_en", "status",
		      "[{\"action\": \"get_status\"}]");
	check_intents("intent_mem", "内存",
		      "[{\"action\": \"get_status\"}]");
	check_intents("intent_none", "你好", "[]");
	check_intents("intent_none_switch", "切换", "[]");
	check_intents("intent_none_svm", "svm", "[]");
	check_intents("intent_none_vmx", "vmx", "[]");
	check_intents("intent_mega_trunc4",
		      "变粉 暗色 亮色 显示应用 切到桌面 隔离区 看看vm 系统状态",
		      "[{\"action\": \"set_theme\", \"theme\": \"pink\"}, "
		      "{\"action\": \"set_theme\", \"theme\": \"dark\"}, "
		      "{\"action\": \"set_theme\", \"theme\": \"light\"}, "
		      "{\"action\": \"show_apps\"}]");
	check_intents("intent_vm_and_status", "vm 状态",
		      "[{\"action\": \"get_vm_status\"}, "
		      "{\"action\": \"get_status\"}]");

	/* ---------------- match_open_app 命中/拦截 ---------------- */
	check_open("open_alias_settings", "打开设置", apps, "demo-settings");
	check_open("open_alias_terminal", "打开终端", apps, "demo-terminal");
	check_open("open_alias_calc", "打开计算器", apps, "demo-calculator");
	check_open("open_exact_zh", "打开阿尔法演示", apps, "alpha-demo");
	check_open("open_exact_en", "open Demo Settings", apps,
		   "demo-settings");
	check_open("open_exact_en2", "打开Demo Terminal", apps,
		   "demo-terminal");
	check_open("open_prefix_strip", "打开系统设置", apps, "demo-settings");
	check_open("open_no_match", "启动一个不存在的东西", apps, NULL);
	check_open("open_stop_full", "打开应用", apps, NULL);
	check_open("open_stop_suffix", "打开应用抽屉", apps, NULL);
	check_open("open_stop_theme", "打开主题", apps, NULL);
	check_open("open_alias_nomatch_app", "帮我打开浏览器", apps, NULL);

	/* ---------------- [[...]] 动作抽取 ---------------- */
	check_tag("tag_single", "[[{\"action\":\"set_theme\","
				"\"theme\":\"pink\"}]] 已切换为粉色主题。",
		  NULL, " 已切换为粉色主题。",
		  "[{\"action\": \"set_theme\", \"theme\": \"pink\"}]");
	check_tag("tag_multi_invalid_json",
		  "[[{\"action\":\"set_theme\",\"theme\":\"light\"},"
		  "{\"action\":\"show_apps\"}]] 两个动作一起执行。",
		  NULL, " 两个动作一起执行。", "[]");
	check_tag("tag_badjson", "[[not-json-here]] 坏 JSON 应被忽略。", NULL,
		  " 坏 JSON 应被忽略。", "[]");
	check_tag("tag_noaction", "[[{\"foo\": 1}]] 没有 action 键。", NULL,
		  " 没有 action 键。", "[]");
	check_tag("tag_nondict_lazy", "[[[\"x1\",\"x2\"]]] 数组元素不是字典。",
		  NULL, "] 数组元素不是字典。", "[]");
	check_tag("tag_dedup", "[[{\"action\": \"show_apps\"}]] 应用抽屉已打开。",
		  "[{\"action\": \"show_apps\"}]", " 应用抽屉已打开。",
		  "[{\"action\": \"show_apps\"}]");
	check_tag("tag_keep_llm_key_order",
		  "[[{\"theme\":\"pink\",\"action\":\"set_theme\"}]] k", NULL,
		  " k", "[{\"theme\": \"pink\", \"action\": \"set_theme\"}]");
	check_tag("tag_none", "普通回复无标签", NULL, "普通回复无标签", "[]");

	/* canon 签名(sort_keys 等价) */
	{
		aik_json *v = parse_lit(
			"{\"theme\": \"pink\", \"action\": \"set_theme\"}");
		char *sig = dt_canon_sig(v);

		check_str("canon_sig_sorted", sig,
			  "{\"action\": \"set_theme\", \"theme\": \"pink\"}");
		free(sig);
		aik_json_free(v);
	}

	/* ---------------- endpoint 拼法 ---------------- */
	{
		char *e1 = dt_llm_endpoint("https://f.example/v1");
		char *e2 = dt_llm_endpoint("https://f.example/v1/");
		char *e3 = dt_llm_endpoint("https://f.example");
		char *e4 = dt_llm_endpoint("https://f.example/api/");

		check_str("endpoint_v1", e1,
			  "https://f.example/v1/chat/completions");
		check_str("endpoint_v1_slash", e2,
			  "https://f.example/v1/chat/completions");
		check_str("endpoint_bare", e3,
			  "https://f.example/v1/chat/completions");
		check_str("endpoint_sub", e4,
			  "https://f.example/api/v1/chat/completions");
		free(e1);
		free(e2);
		free(e3);
		free(e4);
	}

	/* ---------------- 上下文组装 ---------------- */
	{
		/* 服务端持久历史优先 */
		int crash = 0;
		aik_json *hist = parse_lit(
			"[{\"role\": \"user\", \"content\": \"客户端A\"}]");
		aik_json *msgs;

		write_chat("ctxsrv",
			   "[{\"role\": \"system\", \"content\": \"会话开始\"}, "
			   "{\"role\": \"user\", \"content\": \"服务端U\", "
			   "\"ts\": \"t\"}, "
			   "{\"role\": \"assistant\", \"content\": \"服务端A\", "
			   "\"ts\": \"t\", \"source\": \"demo\"}, "
			   "{\"role\": \"user\", \"content\": \"\", \"ts\": \"t\"}]");
		msgs = dt_chat_context("ctxsrv", hist, "当前消息", &crash);
		check_bool("ctx_server_priority_crash", crash, 0);
		check_ll("ctx_server_priority_len",
			 msgs ? (long long)aik_json_count(msgs) : -1, 4);
		if (msgs) {
			const aik_json *m0 = aik_json_at(msgs, 0);
			const aik_json *m1 = aik_json_at(msgs, 1);
			const aik_json *m3 = aik_json_at(msgs, 3);

			check_bool("ctx_system_first",
				   m0 && dt_get(m0, "role") &&
					   strcmp(aik_json_str(
						   dt_get(m0, "role")),
						  "system") == 0,
				   1);
			check_str("ctx_stored_used",
				  m1 && dt_get(m1, "content")
					  ? aik_json_str(
						  dt_get(m1, "content"))
					  : NULL,
				  "服务端U");
			check_str("ctx_final_user",
				  m3 && dt_get(m3, "content")
					  ? aik_json_str(
						  dt_get(m3, "content"))
					  : NULL,
				  "当前消息");
		}
		aik_json_free(msgs);
		aik_json_free(hist);
	}
	{
		/* 20 条封顶 */
		int crash = 0;
		aik_json *msgs;

		write_chat("ctxcap",
			   "[{\"role\": \"user\", \"content\": \"m01\"}, "
			   "{\"role\": \"user\", \"content\": \"m02\"}, "
			   "{\"role\": \"user\", \"content\": \"m03\"}, "
			   "{\"role\": \"user\", \"content\": \"m04\"}, "
			   "{\"role\": \"user\", \"content\": \"m05\"}, "
			   "{\"role\": \"user\", \"content\": \"m06\"}, "
			   "{\"role\": \"user\", \"content\": \"m07\"}, "
			   "{\"role\": \"user\", \"content\": \"m08\"}, "
			   "{\"role\": \"user\", \"content\": \"m09\"}, "
			   "{\"role\": \"user\", \"content\": \"m10\"}, "
			   "{\"role\": \"user\", \"content\": \"m11\"}, "
			   "{\"role\": \"user\", \"content\": \"m12\"}, "
			   "{\"role\": \"user\", \"content\": \"m13\"}, "
			   "{\"role\": \"user\", \"content\": \"m14\"}, "
			   "{\"role\": \"user\", \"content\": \"m15\"}, "
			   "{\"role\": \"user\", \"content\": \"m16\"}, "
			   "{\"role\": \"user\", \"content\": \"m17\"}, "
			   "{\"role\": \"user\", \"content\": \"m18\"}, "
			   "{\"role\": \"user\", \"content\": \"m19\"}, "
			   "{\"role\": \"user\", \"content\": \"m20\"}, "
			   "{\"role\": \"user\", \"content\": \"m21\"}, "
			   "{\"role\": \"user\", \"content\": \"m22\"}]");
		msgs = dt_chat_context("ctxcap", NULL, "now", &crash);
		check_ll("ctx_cap20_len",
			 msgs ? (long long)aik_json_count(msgs) : -1, 22);
		if (msgs && aik_json_count(msgs) == 22) {
			const aik_json *m1 = aik_json_at(msgs, 1);
			const aik_json *m20 = aik_json_at(msgs, 20);

			check_str("ctx_cap20_first",
				  aik_json_str(dt_get(m1, "content")), "m03");
			check_str("ctx_cap20_last",
				  aik_json_str(dt_get(m20, "content")), "m22");
		} else {
			check_bool("ctx_cap20_entries", 0, 1);
		}
		aik_json_free(msgs);
	}
	{
		/* 客户端 history 末 6 条 + 900 字截 800 */
		int crash = 0;
		aik_json *hist;
		aik_json *msgs;
		char big[4096];
		char hist_text[8192];

		/* 用合法 UTF-8 填 900 码点:"长" = 3 字节 → 2700 字节 */
		{
			size_t off = 0;
			const char u[3] = { (char)0xE9, (char)0x95, (char)0xBF };

			for (int i = 0; i < 900; i++) {
				memcpy(big + off, u, 3);
				off += 3;
			}
			big[off] = '\0';
		}
		snprintf(hist_text, sizeof(hist_text),
			 "[{\"role\": \"user\", \"content\": \"c0\"}, "
			 "{\"role\": \"assistant\", \"content\": \"c1\"}, "
			 "{\"role\": \"user\", \"content\": \"c2\"}, "
			 "{\"role\": \"assistant\", \"content\": \"c3\"}, "
			 "{\"role\": \"user\", \"content\": \"c4\"}, "
			 "{\"role\": \"system\", \"content\": \"c5-sys\"}, "
			 "{\"role\": \"user\", \"content\": \"c6\"}, "
			 "{\"role\": \"assistant\", \"content\": \"%s\"}]",
			 big);
		hist = dt_parse(hist_text, strlen(hist_text));
		msgs = dt_chat_context("noexist-sid", hist, "问", &crash);
		check_bool("ctx_client_crash", crash, 0);
		/* 末 6 条 = c2,c3,c4,c5-sys(滤),c6,900字 → 5 条;+system+user = 7 */
		check_ll("ctx_client_last6_len",
			 msgs ? (long long)aik_json_count(msgs) : -1, 7);
		if (msgs && aik_json_count(msgs) == 7) {
			const aik_json *m4 = aik_json_at(msgs, 4);
			const aik_json *c4v = dt_get(m4, "content");

			check_str("ctx_client_c6",
				  c4v ? aik_json_str(c4v) : NULL, "c6");
		}
		if (msgs && aik_json_count(msgs) == 7) {
			const aik_json *m5 = aik_json_at(msgs, 5);
			const aik_json *c5v = dt_get(m5, "content");

			check_ll("ctx_client_800cap",
				 c5v ? (long long)dt_utf8_cplen(
					   aik_json_str(c5v),
					   aik_json_strlen(c5v))
				     : -1,
				 800);
		}
		aik_json_free(msgs);
		aik_json_free(hist);
	}
	{
		/* 存档含非 dict 条目 → 等价未捕获异常 */
		int crash = 0;
		aik_json *msgs;

		write_chat("ctxbad", "[{\"role\": \"user\", \"content\": \"a\"}, "
			   "\"plain-string\"]");
		msgs = dt_chat_context("ctxbad", NULL, "m", &crash);
		check_bool("ctx_crash_nondict", crash, 1);
		aik_json_free(msgs);
	}

	/* ---------------- demo_reply ---------------- */
	{
		char *r = dt_demo_reply("你好", NULL, 5);

		check_str("demo_default", r,
			  "我在 AIKernel 演示应答模式(当前云端模型不可达,但"
			  "界面控制不受影响)。试试对我说:显示我装的 app / "
			  "把系统变粉 / 切到桌面 / 系统状态怎么样?");
		free(r);
	}
	{
		aik_json *a = parse_lit("[{\"action\": \"show_apps\"}]");
		char *r = dt_demo_reply("显示应用", a, 5);

		check_str("demo_showapps", r,
			  "已为你打开应用抽屉:检测到 5 款已安装应用,顶部框"
			  "可搜索。");
		free(r);
		aik_json_free(a);
	}
	{
		aik_json *a = parse_lit("[{\"action\": \"get_status\"}]");
		char *r = dt_demo_reply("系统状态", a, 5);

		check_contains("demo_status_head", r,
			       "这是实时读取的系统态势:\n```\n$ uname -r\n");
		check_contains("demo_status_tail", r, "MB\n```");
		free(r);
		aik_json_free(a);
	}
	{
		aik_json *a = parse_lit("[{\"action\": \"get_vm_status\"}]");
		char *r = dt_demo_reply("vm", a, 5);

		check_str("demo_vm_disabled", r,
			  "当前是 factory 本地桌面演示(AIK_DESKTOP_VM=0),"
			  "不连接 138:8761;生产实况请用 aikernel-api/ai 工具。");
		free(r);
		aik_json_free(a);
	}
	{
		aik_json *a = parse_lit(
			"[{\"action\": \"set_theme\", \"theme\": \"pink\"}, "
			"{\"action\": \"show_apps\"}]");
		char *r = dt_demo_reply("变粉 显示应用", a, 2);

		check_str("demo_join_two", r,
			  "已把整套系统切换为粉色主题,聊天区、任务栏、壁纸一并"
			  "变色。 已为你打开应用抽屉:检测到 2 款已安装应用,"
			  "顶部框可搜索。");
		free(r);
		aik_json_free(a);
	}
	{
		aik_json *a = parse_lit(
			"[{\"action\": \"open_app\", \"app\": \"demo-settings\", "
			"\"name\": \"Demo Settings\"}]");
		char *r = dt_demo_reply("打开设置", a, 5);

		check_str("demo_open_app", r,
			  "已为你定位「Demo Settings」,在应用抽屉中高亮显示"
			  "(demo 不真正拉起进程)。");
		free(r);
		aik_json_free(a);
	}

	/* ---------------- 系统提示与 LLM 请求体 ---------------- */
	check_ll("sys_prompt_cplen",
		 (long long)dt_utf8_cplen(dt_chat_sys_prompt(),
					  strlen(dt_chat_sys_prompt())),
		 467);
	{
		aik_json *msgs = parse_lit(
			"[{\"role\": \"system\", \"content\": \"你是\"}, "
			"{\"role\": \"user\", \"content\": \"变粉\"}]");
		char *body = dt_llm_body_build("test-model", msgs);

		check_str("llm_body_ascii", body,
			  "{\"model\": \"test-model\", \"messages\": "
			  "[{\"role\": \"system\", \"content\": "
			  "\"\\u4f60\\u662f\"}, {\"role\": \"user\", "
			  "\"content\": \"\\u53d8\\u7c89\"}], "
			  "\"temperature\": 0.6, \"max_tokens\": 500, "
			  "\"stream\": false}");
		free(body);
		aik_json_free(msgs);
	}

	/* ---------------- dtvm 纯解析与命令串 ---------------- */
	check_str("vm_cmd_ai", dt_vm_cmd_ai(),
		  "cat /proc/ai/status 2>&1; echo ---; cat /proc/loadavg; "
		  "echo ---; free -m | sed -n 2p");
	check_str("vm_cmd_aiops", dt_vm_cmd_aiops(),
		  "wc -c /proc/ai/decisions 2>&1; echo ---; "
		  "cat /proc/ai/decisions 2>&1 | head -c 4096; echo ---; "
		  "tail -c 4096 /proc/ai/telemetry 2>&1");
	check_str("vm_cmd_sandbox", dt_vm_cmd_sandbox(),
		  "ls -la /sandbox/ 2>&1; echo ---MOUNTS---; "
		  "mount | grep -i sandbox 2>&1; echo ---PROCS---; "
		  "ps -eo pid,comm | grep -iw sandbox 2>&1");
	check_str("vm_cmd_token", dt_vm_cmd_token(),
		  "cat /etc/aikernel/api-token");
	{
		aik_json *o = dt_new_obj();
		int rc = dt_vm_parse_ai(
			"enabled: 1\nruntime_state: 2\n"
			"model: name=m1 version=v1 source=3 state=4\n"
			"cpu0: emitted=10 dropped=1\n"
			"cpu1: emitted=20 dropped=2\n"
			"---\n0.52 0.58 1.23 2/456 7890\n"
			"---\nMem:          7894        1234         567 "
			"89  45        678         901",
			o);
		char *d = dt_json_dump_default(o);

		check_bool("vm_ai_parse_rc", rc, 0);
		check_str("vm_ai_dump", d,
			  "{\"reachable\": true, \"ai\": {\"enabled\": 1, "
			  "\"runtime_state\": 2, \"model\": \"m1\", "
			  "\"model_state\": 4, \"telemetry_emitted\": 30, "
			  "\"telemetry_dropped\": 3}, \"load1\": 0.52, "
			  "\"mem_pct\": 15.6}");
		free(d);
		aik_json_free(o);
	}
	{
		aik_json *o = dt_new_obj();
		int rc = dt_vm_parse_ai("cat: /proc/ai/status: No such file", o);

		check_bool("vm_ai_unreadable_rc", rc, -1);
		aik_json_free(o);
	}
	{
		aik_json *o = dt_new_obj();
		int rc = dt_vm_parse_aiops(
			"4096 /proc/ai/decisions\n"
			"---\nDECISION-BODY-LINE\n"
			"---\nts=1 pid=2 tgid=3 cpu=4 cat=5 ev=6 sev=7 len=8\n"
			"ts=11 pid=12 tgid=13 cpu=14 cat=15 ev=16 sev=17 "
			"len=18\nbadline here\n",
			o);
		char *d = dt_json_dump_default(o);

		check_bool("vm_aiops_parse_rc", rc, 0);
		check_str("vm_aiops_dump", d,
			  "{\"reachable\": true, \"decisions_size\": 4096, "
			  "\"decisions_raw\": \"DECISION-BODY-LINE\", "
			  "\"decisions_empty\": false, \"events\": "
			  "[{\"ts\": 1, \"pid\": 2, \"cpu\": 4, \"cat\": 5, "
			  "\"ev\": 6, \"sev\": 7, \"len\": 8}, "
			  "{\"ts\": 11, \"pid\": 12, \"cpu\": 14, "
			  "\"cat\": 15, \"ev\": 16, \"sev\": 17, "
			  "\"len\": 18}], \"event_total_recent\": 2}");
		free(d);
		aik_json_free(o);
	}
	check_bool("vm_sandbox_empty_true",
		   (int)dt_vm_sandbox_is_empty(
			   "total 8\ndr-xr-xr-x. 2 root root 6 Jan  1 2026 .\n"
			   "---MOUNTS---\n"),
		   1);
	check_bool("vm_sandbox_empty_false",
		   (int)dt_vm_sandbox_is_empty(
			   "total 12\n-rw-r--r--. 1 root root 3 Jan  1 2026 f\n"
			   "---MOUNTS---\n---PROCS---\n"),
		   0);

	aik_json_free(apps);

	if (fails) {
		printf("test_dtchat: FAIL(%d)\n", fails);
		return 1;
	}
	printf("test_dtchat: PASS\n");
	return 0;
}
