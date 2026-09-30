// SPDX-License-Identifier: GPL-2.0
/*
 * cmd_ask.c - ask 命令实现（AI 工具调用闭环）
 *
 * "AI 为主体"的入口：用户用自然语言下达系统管理任务，AI 通过工具
 * （procfs 读 / sysfs 写 / NETLINK_AI ACT / 白名单 exec / SME 记忆）
 * 自主完成操作并给出回答。
 *
 * 流程：
 *   1. 加载工具注册表（tools.json，tools/gen_registry.py 生成）；
 *   2. 组 system prompt：身份 + 工具清单 + 约束；
 *   3. 会话历史加载：从 ~/.aikernel/sessions/<name>.jsonl 读入跨 ask
 *      历史（session 命令管理，UI Phase 起默认会话 "default"）；
 *   4. 上下文注入：最近一次 NETLINK_AI sense 摘要（可选）+
 *      memory.search 用户问题的命中（可选，SME 服务未启动则跳过）；
 *   5. 模型循环（上限 5 轮防失控）：
 *        - 流式优先（[ui].stream=on）：delta.content 逐段实时打印，
 *          后端失败自动回退非流式（本地通道在 local_backend 内回退，
 *          云端通道整体缓冲后按 SSE 语义解析，行为一致）；
 *        - 原生 tool_calls 路径：请求体带 tools 数组，解析 tool_calls；
 *        - 降级路径：模型/服务不支持 tools 字段时（请求报错或模型只
 *          回文本），改用"文本 JSON 约定"（系统提示声明格式，文本解析）；
 *        - 每个工具调用 → 注册表查表 → 自动执行（无交互确认，全部
 *          自动执行；审计由决策 ring/因果链 + [audit] 行承载）→
 *          role:tool 消息回填 → 继续下一轮；
 *        - 等待模型期间显示 braille spinner（首 token 到达即清除）；
 *   6. 无工具调用的回答即最终答案；全部消息追加落盘会话文件。
 *
 * 过程可见性：工具调用输出折叠为单行卡片（`└─ 名字 · OK · 摘要`），
 * 结果超过 3 行提示行数；verbose on 切换为全展开。
 *
 * 内存所有权：消息数组中的 content/tool_calls_json 一律指向
 * owned 字符串池中的副本（进入池后统一在 cmd_ask 退出时释放），
 * 避免消息数组悬挂指针。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_runtime.h"
#include "ai_config.h"
#include "ai_json_util.h"
#include "ai_ui.h"
#include "netlink/ai_netlink_client.h"
#include "memory/sme_client.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"

/* 模型调用轮数上限（防工具循环失控） */
#define ASK_MAX_ROUNDS      5

/* 单次对话最大消息数 */
#define ASK_MAX_MESSAGES    64

/* 从会话历史加载的最大消息条数（超出裁掉最旧的） */
#define ASK_HIST_MAX        32

/* 记忆检索注入条数 */
#define ASK_MEMORY_TOP_K    3

/* 上下文注入片段上限（字节） */
#define ASK_CTX_SNIPPET_MAX 2048

/* 消息数组（动态增长） */
struct ask_msgs {
	struct ai_chat_msg *m;
	int n;
	int cap;
};

/* 字符串所有权池：放入的字符串在 ask 结束时统一释放 */
struct ask_owned {
	char **s;
	int n;
	int cap;
};

/* 流式打印上下文 */
struct ask_stream {
	int color;
	int printed;            /* 本轮已打印过增量内容 */
};

/* 接管字符串所有权（返回原指针，便于链式赋值；接管失败则立即释放） */
static char *ask_own(struct ask_owned *o, char *s)
{
	if (!s)
		return NULL;
	if (o->n >= o->cap) {
		int ncap = o->cap ? o->cap * 2 : 16;
		char **ns = realloc(o->s, sizeof(char *) * (size_t)ncap);

		if (!ns) {
			free(s);
			return NULL;
		}
		o->s = ns;
		o->cap = ncap;
	}
	o->s[o->n++] = s;
	return s;
}

static void ask_owned_free(struct ask_owned *o)
{
	int i;

	for (i = 0; i < o->n; i++)
		free(o->s[i]);
	free(o->s);
	memset(o, 0, sizeof(*o));
}

static int ask_msgs_push(struct ask_msgs *a, const struct ai_chat_msg *msg)
{
	if (a->n >= ASK_MAX_MESSAGES)
		return AI_ERR_INVALID_ARG;
	if (a->n >= a->cap) {
		int ncap = a->cap ? a->cap * 2 : 16;
		struct ai_chat_msg *nm = realloc(a->m,
						 sizeof(*nm) * (size_t)ncap);

		if (!nm)
			return AI_ERR_MEMORY;
		a->m = nm;
		a->cap = ncap;
	}
	a->m[a->n++] = *msg;
	return AI_OK;
}

/* ---- 流式增量打印 ---- */

/*
 * ask_on_delta - delta.content 逐段回调（流式路径）
 * 首段到达时清除 spinner 并打出 "AI:" 前缀，之后原样写 stdout。
 */
static void ask_on_delta(void *ud, const char *d, size_t n)
{
	struct ask_stream *s = ud;

	if (!s->printed) {
		ui_spinner_stop();
		printf("%sAI:%s ", ui_c(s->color, UI_C_CYAN),
		       ui_c(s->color, UI_C_RESET));
		s->printed = 1;
	}
	fwrite(d, 1, n, stdout);
	fflush(stdout);
}

/* ---- system prompt ---- */

#define ASK_SYSTEM_IDENTITY \
	"你是 AIKernel 系统管理员 AI（运行于 AIKernel Shell 的 ask 命令）。" \
	"你的职责：通过调用工具完成用户对系统/内核的查询与操作请求。\n\n"

#define ASK_SYSTEM_RULES \
	"\n约束：\n" \
	"1. 只能使用上面列出的工具，工具名必须一字不差；一次可以调用多个工具。\n" \
	"2. 工具参数必须符合给出的名称与类型；不要调用不存在的工具，" \
	"不要编造工具结果。\n" \
	"3. 需要信息就先调用工具获取，拿到全部需要的结果后再回答。\n" \
	"4. 工具失败时如实说明失败原因；回答使用简体中文，简洁准确。\n"

/* 降级协议声明（模型不支持 tools 字段时追加到 system prompt） */
static const char *const ASK_FALLBACK_RULES =
	"\n输出格式（重要，必须严格遵守）：\n"
	"你的每次输出只能是一个 JSON 对象，不要输出任何其他文字：\n"
	"- 需要调用工具时：{\"tool\":\"<工具名>\",\"arguments\":{<参数>}}\n"
	"  （arguments 为参数对象；无参数工具写 {}）\n"
	"- 信息齐全要回答时：{\"answer\":\"<中文回答>\"}\n";

/*
 * build_system_prompt - 组装 system 消息内容
 * @sum:     工具清单文本（tool_registry_summarize）
 * @fallback: 1=追加降级 JSON 协议说明
 */
static char *build_system_prompt(const char *sum, int fallback)
{
	size_t cap = strlen(ASK_SYSTEM_IDENTITY) + strlen(ASK_SYSTEM_RULES) +
		     strlen(sum) + 256;
	char *out;

	if (fallback)
		cap += strlen(ASK_FALLBACK_RULES);
	out = malloc(cap);
	if (!out)
		return NULL;

	snprintf(out, cap, "%s可用工具清单：\n%s%s%s",
		 ASK_SYSTEM_IDENTITY, sum,
		 ASK_SYSTEM_RULES,
		 fallback ? ASK_FALLBACK_RULES : "");
	return out;
}

/* ---- 上下文注入 ---- */

/*
 * inject_sense_context - 尝试拉取最近一次内核遥测（NETLINK_AI SENSE）
 * 成功返回 malloc 摘要文本；失败（宿主机无 AIKernel 内核等）返回 NULL，
 * 属正常场景静默跳过。该调用同时让 QEMU 内 ask 的 netlink sense 真实发生。
 */
static char *inject_sense_context(void)
{
	struct ai_nl_client cli;
	struct ai_nl_sense_ack ack;
	unsigned char *stream;
	size_t stream_len = 0;
	int kern_err = 0;
	int rc;
	char *out;

	rc = ai_nl_client_open(&cli);
	if (rc != AI_OK)
		return NULL;

	stream = malloc(AI_NL_PAYLOAD_MAX);
	if (!stream) {
		ai_nl_client_close(&cli);
		return NULL;
	}

	rc = ai_nl_send_sense(&cli, AI_NL_SENSE_CPU_ALL, 8,
			      AI_NL_FORMAT_HUMAN, &ack,
			      stream, AI_NL_PAYLOAD_MAX, &stream_len,
			      &kern_err);
	ai_nl_client_close(&cli);

	if (rc != AI_OK || ack.records == 0) {
		free(stream);
		return NULL;
	}

	{
		size_t snip = stream_len < (size_t)ASK_CTX_SNIPPET_MAX ?
			      stream_len : (size_t)ASK_CTX_SNIPPET_MAX;

		/* 截断对齐 UTF-8 边界（T2 问题 1：切半的汉字进请求体
		 * 会被服务端以非法 UTF-8 拒收） */
		snip = ai_json_utf8_floor((const char *)stream, snip);

		if (asprintf(&out, "最近一次内核遥测（NETLINK_AI SENSE，"
			     "%u 条记录）：\n%.*s\n", ack.records,
			     (int)snip, (const char *)stream) < 0) {
			free(stream);
			return NULL;
		}
	}
	free(stream);
	return out;
}

/*
 * inject_memory_context - SME 记忆检索命中注入
 * SME 服务不可达时返回 NULL 静默跳过（记忆是增强能力，非硬依赖）。
 */
static char *inject_memory_context(const char *question)
{
	char resp[SME_OUT_BUF_MIN * 2];
	char *out;
	int rc;

	rc = sme_search(question, ASK_MEMORY_TOP_K, resp, sizeof(resp));
	if (rc != AI_OK)
		return NULL;

	{
		size_t snip = strlen(resp);
		char body[ASK_CTX_SNIPPET_MAX + 1];

		if (snip > (size_t)ASK_CTX_SNIPPET_MAX)
			snip = (size_t)ASK_CTX_SNIPPET_MAX;
		/* 记忆命中是中文密集文本：截断对齐 UTF-8 边界（T2 问题 1） */
		snip = ai_json_utf8_floor(resp, snip);
		memcpy(body, resp, snip);
		body[snip] = '\0';

		if (asprintf(&out, "相关记忆（SME memory.search 命中，"
			     "JSON 原文）：\n%s\n", body) < 0)
			return NULL;
	}
	return out;
}

/* ---- 会话持久化 ---- */

/*
 * ask_sess_append - 追加一条消息到当前会话（失败静默：会话是增强，
 * 不因磁盘问题打断 ask 主流程）
 */
static void ask_sess_append(struct ai_shell *shell, const char *role,
			    const char *content, const char *tool_call_id,
			    const char *tool_name,
			    const char *tool_calls_json)
{
	struct ui_session_rec rec;

	memset(&rec, 0, sizeof(rec));
	rec.role = role;
	rec.content = content;
	rec.tool_call_id = tool_call_id;
	rec.tool_name = tool_name;
	rec.tool_calls_json = tool_calls_json;
	rec.ts = time(NULL);
	ui_session_append(shell->config->ui.session, &rec);
}

/* ---- 工具执行 ---- */

/*
 * run_one_tool - 查注册表并执行，返回结果文本（malloc，调用者接管）
 * 失败（未知工具/执行失败）也返回可回填模型的说明文本。
 */
static char *run_one_tool(const struct tool_registry *reg,
			  const struct ai_tool_call *tc, int *ok)
{
	const struct ai_tool *tool;
	char *out;

	*ok = 0;
	tool = tool_registry_find(reg, tc->name);
	if (!tool) {
		if (asprintf(&out, "ERROR: 未知工具 '%s'（只能使用工具清单"
			     "中列出的工具）", tc->name) < 0)
			out = NULL;
		return out;
	}
	tool_executor_run(tool, tc->arguments, &out, ok);
	return out;
}

/* 结果文本行数统计 */
static int count_lines(const char *s)
{
	int n = 1;
	const char *p;

	if (!s || !s[0])
		return 0;
	for (p = s; *p; p++) {
		if (*p == '\n')
			n++;
	}
	return n;
}

/*
 * print_tool_exchange - 打印单条工具调用与结果（折叠卡片 / 详展两种）
 * 默认（折叠）：`  └─ 名字(参数) · OK · 结果首行`，>3 行附行数提示；
 * verbose：两行全展开（兼容 UI Phase 之前的输出格式）。
 */
static void print_tool_exchange(int color, int verbose,
				const struct ai_tool_call *tc,
				const char *result, int ok)
{
	char disp[512];

	if (verbose) {
		size_t dlen = strlen(result ? result : "(空)");

		/* verbose 全展开也按 UTF-8 边界截断（512B 显示缓冲） */
		if (dlen >= sizeof(disp)) {
			dlen = ai_json_utf8_floor(result, sizeof(disp) - 4);
			memcpy(disp, result, dlen);
			disp[dlen] = '\0';
			strcat(disp, "…");
		} else {
			snprintf(disp, sizeof(disp), "%s", result ? result : "(空)");
		}
		printf("  [工具调用] %s(%s)\n", tc->name,
		       tc->arguments ? tc->arguments : "{}");
		printf("  [工具结果%s] %s%s\n", ok ? "ok" : "fail", disp,
		       strlen(result ? result : "") >= sizeof(disp) ?
		       " ...(截断)" : "");
		return;
	}

	/* 折叠单行卡片 */
	{
		char args[64];
		char first[96];
		const char *src = result ? result : "(空)";
		const char *nl = strchr(src, '\n');
		size_t flen = nl ? (size_t)(nl - src) : strlen(src);
		size_t alen;
		int lines = count_lines(result);

		alen = tc->arguments ? strlen(tc->arguments) : 2;
		if (alen > 48) {
			/* 截断对齐 UTF-8 边界（T2 问题 2：截半汉字显示乱码） */
			alen = ai_json_utf8_floor(tc->arguments, 45);
			memcpy(args, tc->arguments, alen);
			args[alen] = '\0';
			strcat(args, "...");
		} else {
			snprintf(args, sizeof(args), "%s",
				 tc->arguments ? tc->arguments : "{}");
		}
		if (flen >= sizeof(first)) {
			/* 预留 '…'(3B)+NUL；floor 保证不截半汉字 */
			flen = ai_json_utf8_floor(src, sizeof(first) - 5);
			memcpy(first, src, flen);
			first[flen] = '\0';
			strcat(first, "…");
		} else {
			memcpy(first, src, flen);
			first[flen] = '\0';
		}

		printf("  %s└─%s %s(%s) %s·%s %s%s%s %s·%s %s\n",
		       ui_c(color, UI_C_DIM), ui_c(color, UI_C_RESET),
		       tc->name, args,
		       ui_c(color, UI_C_DIM), ui_c(color, UI_C_RESET),
		       ok ? ui_c(color, UI_C_GREEN) : ui_c(color, UI_C_RED),
		       ok ? "OK" : "FAIL",
		       ok ? ui_c(color, UI_C_RESET) : ui_c(color, UI_C_RESET),
		       ui_c(color, UI_C_DIM), ui_c(color, UI_C_RESET),
		       first);
		if (lines > 3)
			printf("  %s[+%d 行，verbose on 查看全文]%s\n",
			       ui_c(color, UI_C_DIM), lines - 1,
			       ui_c(color, UI_C_RESET));
	}
}

/*
 * execute_round - 执行一轮全部工具调用并回填消息
 * @native: 1=原生 tool_calls（assistant 带 tool_calls_json + role:tool）；
 *          0=降级路径（assistant 保留原文 + user 消息带工具结果，
 *          对不支持 role:tool 的通道协议安全）
 * @executed: 出参，1=至少执行了一个工具
 */
static int execute_round(struct ai_shell *shell, struct ask_msgs *a,
			 struct ask_owned *owned,
			 const struct tool_registry *reg,
			 const struct ai_chat_result *result,
			 const char *assistant_tool_calls_json,
			 int native, int *executed)
{
	struct ai_shell *sh = shell;
	int color = sh->config->ui.color;
	int verbose = sh->config->ui.verbose;
	struct ai_chat_msg am;
	int i;

	memset(&am, 0, sizeof(am));

	/* assistant 消息先入列（工具结果必须跟随其后）。
	 * content/tool_calls_json 取副本入所有权池（result 随后被释放） */
	am.role = "assistant";
	am.content = ask_own(owned,
			     strdup(result->content ? result->content : ""));
	if (native)
		am.tool_calls_json =
			ask_own(owned, strdup(
				assistant_tool_calls_json ?
				assistant_tool_calls_json : "[]"));
	if (ask_msgs_push(a, &am) != AI_OK)
		return AI_ERR_MEMORY;

	/* 会话落盘：assistant 工具调用消息 */
	ask_sess_append(sh, "assistant", am.content, NULL, NULL,
			native ? am.tool_calls_json : NULL);

	for (i = 0; i < result->tool_call_count; i++) {
		const struct ai_tool_call *tc = &result->tool_calls[i];
		char *tool_out;
		int ok = 0;
		struct ai_chat_msg tm;

		if (!tc->name)
			continue;
		tool_out = run_one_tool(reg, tc, &ok);
		if (!tool_out)
			tool_out = strdup("(执行器无输出)");
		print_tool_exchange(color, verbose, tc, tool_out, ok);
		*executed = 1;

		memset(&tm, 0, sizeof(tm));
		if (native) {
			tm.role = "tool";
			tm.tool_call_id = tc->id ? tc->id : "unknown";
			tm.tool_name = tc->name;   /* 原生通道按名配对 */
			tm.content = ask_own(owned, tool_out);
		} else {
			/* 降级路径：user 消息回填（协议最兼容） */
			char *merged;

			if (asprintf(&merged, "[TOOL %s RESULT]\n%s\n"
				     "请根据以上工具结果继续（输出 JSON）。",
				     tc->name, tool_out) < 0)
				merged = NULL;
			tm.role = "user";
			tm.content = ask_own(owned, merged);
			free(tool_out);
		}
		if (ask_msgs_push(a, &tm) != AI_OK)
			return AI_ERR_MEMORY;

		/* 会话落盘：工具结果（附工具名便于人读） */
		if (native)
			ask_sess_append(sh, "tool", tm.content,
					tm.tool_call_id, tc->name, NULL);
		else
			ask_sess_append(sh, "user", tm.content, NULL,
					tc->name, NULL);
	}

	return AI_OK;
}

/* ---- 主命令 ---- */

int cmd_ask(void *shell_ptr, int argc, char **argv)
{
	struct ai_shell *shell = (struct ai_shell *)shell_ptr;
	struct tool_registry reg;
	char *reg_err = NULL;
	struct ask_msgs a = { NULL, 0, 0 };
	struct ask_owned owned = { NULL, 0, 0 };
	struct ask_stream st;
	char *system_native = NULL;
	char *system_fallback = NULL;
	char *tools_json = NULL;
	char *question = NULL;
	char *sense_ctx = NULL;
	char *mem_ctx = NULL;
	char **hist_pool = NULL;
	int hist_pool_n = 0;
	const char *sess_name;
	int color;
	int hist_n = 0;
	int fallback_mode = 0;
	int round;
	int ret = AI_OK;

	color = shell->config->ui.color;
	sess_name = (shell->config->ui.session &&
		     shell->config->ui.session[0]) ?
		    shell->config->ui.session : UI_DEFAULT_SESSION;
	st.color = color;
	st.printed = 0;

	if (argc < 2) {
		printf("Usage: ask <问题或任务描述>\n");
		printf("  例: ask 帮我看看这台机器内存多大，并记住答案\n");
		return AI_ERR_INVALID_ARG;
	}

	/* 1. 工具注册表 */
	ret = tool_registry_load(&reg, &reg_err);
	if (ret != AI_OK) {
		printf("ask: %s\n", reg_err ? reg_err : "注册表加载失败");
		free(reg_err);
		return ret;
	}
	{
		char *sum = tool_registry_summarize(&reg);

		if (!sum) {
			tool_registry_free(&reg);
			return AI_ERR_MEMORY;
		}
		system_native = build_system_prompt(sum, 0);
		system_fallback = build_system_prompt(sum, 1);
		free(sum);
		if (!system_native || !system_fallback) {
			free(system_native);
			free(system_fallback);
			tool_registry_free(&reg);
			return AI_ERR_MEMORY;
		}
	}

	/* 2. 模型（复用 chat 命令的默认模型逻辑） */
	{
		const char *default_model = ai_config_get_default_model(
			shell->config);

		if (!shell->runtime.current_model) {
			if (!default_model) {
				char **names;
				int count;

				ai_config_get_models(shell->config, &names,
						     &count);
				if (count == 0) {
					printf("No models configured.\n"
					       "Use 'model add <name>' "
					       "first.\n");
					ret = AI_ERR_NO_MODEL;
					goto out;
				}
				ai_config_set_default_model(shell->config,
							    names[0]);
				ai_config_save(shell->config);
				for (int i = 0; i < count; i++)
					free(names[i]);
				free(names);
				default_model = shell->config->default_model;
			}
			ret = ai_runtime_set_model(&shell->runtime,
						   default_model);
			if (ret != AI_OK) {
				printf("Failed to initialize model '%s': %s\n",
				       default_model, ai_error_string(ret));
				goto out;
			}
		}
	}

	/* 3. 拼接问题 + 上下文注入 */
	{
		size_t cap = 256;
		size_t off = 0;
		int i;

		for (i = 1; i < argc; i++)
			cap += strlen(argv[i]) + 1;
		question = malloc(cap);
		if (!question) {
			ret = AI_ERR_MEMORY;
			goto out;
		}
		for (i = 1; i < argc; i++) {
			if (i > 1)
				question[off++] = ' ';
			off += (size_t)snprintf(question + off, cap - off,
						"%s", argv[i]);
		}

		sense_ctx = inject_sense_context();
		mem_ctx = inject_memory_context(question);
	}

	/* 4. 会话历史加载（跨 ask；裁剪到最近 ASK_HIST_MAX 条） */
	{
		struct ai_chat_msg *hist = NULL;
		int nhist = 0;
		int i;

		ui_session_load(sess_name, &hist, &nhist, &hist_pool,
				&hist_pool_n);
		if (nhist > ASK_HIST_MAX) {
			hist += nhist - ASK_HIST_MAX;
			nhist = ASK_HIST_MAX;
		}
		hist_n = nhist;

		/* 首条 system（降级切换时 system 会重建） */
		{
			struct ai_chat_msg m;

			memset(&m, 0, sizeof(m));
			m.role = "system";
			m.content = system_native;
			ask_msgs_push(&a, &m);

			for (i = 0; i < nhist; i++)
				ask_msgs_push(&a, &hist[i]);
		}
		/* 注意：hist 指针入列后 hist_pool 在 out 处统一释放 */
	}

	/* 5. 本轮 user 消息（含遥测/记忆注入） */
	{
		char *user;
		struct ai_chat_msg m;

		if (asprintf(&user, "%s%s%s用户任务：%s",
			     sense_ctx ? sense_ctx : "",
			     mem_ctx ? mem_ctx : "",
			     (sense_ctx || mem_ctx) ? "\n" : "",
			     question) < 0) {
			ret = AI_ERR_MEMORY;
			goto out;
		}
		ask_own(&owned, user);

		memset(&m, 0, sizeof(m));
		m.role = "user";
		m.content = user;
		ask_msgs_push(&a, &m);

		/* 会话落盘：用户原始问题（注入内容不落盘） */
		ask_sess_append(shell, "user", question, NULL, NULL, NULL);
	}

	tools_json = tool_registry_build_tools_json(&reg);

	printf("%s=== AIKernel ask ===%s\n", ui_c(color, UI_C_CYAN),
	       ui_c(color, UI_C_RESET));
	printf("模型: %s | 工具: %d 个 | 最大轮数: %d | 会话: %s（%d 条历史）\n",
	       shell->runtime.current_model, reg.tool_count, ASK_MAX_ROUNDS,
	       sess_name, hist_n);
	if (sense_ctx)
		printf("上下文: 内核遥测摘要已注入\n");
	if (mem_ctx)
		printf("上下文: SME 记忆命中已注入\n");
	printf("\n");

	/* 6. 模型循环 */
	for (round = 1; round <= ASK_MAX_ROUNDS; round++) {
		struct ai_chat_result *result = NULL;

		printf("%s[第 %d 轮]%s ", ui_c(color, UI_C_DIM), round,
		       ui_c(color, UI_C_RESET));
		fflush(stdout);
		st.printed = 0;
		ui_spinner_start("thinking...");

		ret = ai_runtime_chat_ex(&shell->runtime, a.m, a.n,
					 fallback_mode ? NULL : tools_json,
					 shell->config->ui.stream ?
					 ask_on_delta : NULL, &st, &result);
		/* 无增量输出（非流式/工具调用轮）时收掉 spinner */
		ui_spinner_stop();

		if (ret != AI_OK) {
			/* 请求本身失败：可能是服务端不支持 tools 字段
			 * （HTTP 400 等）→ 切降级路径重试一次 */
			if (!fallback_mode && ret != AI_ERR_NETWORK &&
			    ret != AI_ERR_AUTH) {
				printf("  (请求失败，切换为文本约定降级"
				       "模式重试)\n");
				fallback_mode = 1;
				a.m[0].content = system_fallback;
				round--;
				continue;
			}
			printf("ask: 模型调用失败: %s\n", ai_error_string(ret));
			break;
		}

		if (!result) {
			ret = AI_ERR_API;
			printf("ask: 模型未返回结果\n");
			break;
		}

		/* finish_reason=length：生成被 max_tokens 截断 */
		if (result->finish_reason &&
		    strcmp(result->finish_reason, "length") == 0)
			printf("%s(已达 max_tokens 生成被截断，"
			       "可 config set max_tokens 调大)%s\n",
			       ui_c(color, UI_C_YELLOW),
			       ui_c(color, UI_C_RESET));

		/* 6a. 原生 tool_calls */
		if (result->tool_call_count > 0) {
			char *tc_json = ai_chat_render_tool_calls(
				result->tool_calls, result->tool_call_count);
			int executed = 0;

			if (st.printed)
				printf("\n");
			printf("  %s(模型请求 %d 个工具调用)%s\n",
			       ui_c(color, UI_C_DIM),
			       result->tool_call_count,
			       ui_c(color, UI_C_RESET));
			execute_round(shell, &a, &owned, &reg, result,
				      tc_json, 1, &executed);
			free(tc_json);
			ai_chat_result_free(result);
			free(result);
			if (!executed)
				break;
			continue;
		}

		/* 6b. 降级模式：文本 JSON 工具调用 */
		if (fallback_mode && result->content) {
			struct ai_tool_call tc;
			char *answer = NULL;
			int rc2 = ai_chat_parse_text_toolcall(result->content,
							      &tc, &answer);

			if (rc2 == AI_TEXT_TOOL_CALL) {
				int executed = 0;
				struct ai_chat_result tmp;

				memset(&tmp, 0, sizeof(tmp));
				tmp.content = result->content;
				tmp.tool_calls = &tc;
				tmp.tool_call_count = 1;
				printf("  %s(降级模式：解析到工具调用)%s\n",
				       ui_c(color, UI_C_DIM),
				       ui_c(color, UI_C_RESET));
				execute_round(shell, &a, &owned, &reg, &tmp,
					      NULL, 0, &executed);
				free(tc.id);
				free(tc.name);
				free(tc.arguments);
				ai_chat_result_free(result);
				free(result);
				if (!executed)
					break;
				continue;
			}
			/* {"answer":...} 或纯文本 → 最终回答 */
			if (st.printed) {
				printf("\n");
			} else {
				printf("\n%sAI:%s %s\n",
				       ui_c(color, UI_C_CYAN),
				       ui_c(color, UI_C_RESET),
				       answer ? answer : result->content);
			}
			/* 会话落盘：最终回答 */
			ask_sess_append(shell, "assistant",
					answer ? answer : result->content,
					NULL, NULL, NULL);
			free(answer);
			ai_chat_result_free(result);
			free(result);
			ret = AI_OK;
			break;
		}

		/* 6c. 原生模式但模型没用 tools：内容形似约定 JSON 时
		 * 自动降级解析一次（模型忽略 tools 字段的兜底） */
		if (result->content && strchr(result->content, '{')) {
			struct ai_tool_call tc;
			char *answer = NULL;

			if (ai_chat_parse_text_toolcall(result->content,
							&tc, &answer) ==
			    AI_TEXT_TOOL_CALL) {
				int executed = 0;
				struct ai_chat_result tmp;

				printf("  %s(模型未用原生 tools，切换为文本"
				       "约定模式)%s\n",
				       ui_c(color, UI_C_DIM),
				       ui_c(color, UI_C_RESET));
				fallback_mode = 1;
				memset(&tmp, 0, sizeof(tmp));
				tmp.content = result->content;
				tmp.tool_calls = &tc;
				tmp.tool_call_count = 1;
				execute_round(shell, &a, &owned, &reg, &tmp,
					      NULL, 0, &executed);
				free(tc.id);
				free(tc.name);
				free(tc.arguments);
				ai_chat_result_free(result);
				free(result);
				if (!executed)
					break;
				continue;
			}
			free(answer);
		}

		/* 6d. 最终回答（流式已实时打印则只补换行） */
		if (st.printed) {
			printf("\n");
		} else {
			printf("\n%sAI:%s %s\n", ui_c(color, UI_C_CYAN),
			       ui_c(color, UI_C_RESET),
			       result->content ? result->content : "(空回答)");
		}
		/* 会话落盘：最终回答 */
		ask_sess_append(shell, "assistant",
				result->content ? result->content : "",
				NULL, NULL, NULL);
		ai_chat_result_free(result);
		free(result);
		ret = AI_OK;
		break;
	}

	if (round > ASK_MAX_ROUNDS)
		printf("ask: 已达最大轮数上限（%d），强制结束\n",
		       ASK_MAX_ROUNDS);

	/* 上下文预算 >80% 黄色警告 */
	{
		struct ai_runtime *rt = &shell->runtime;
		long total = (long)rt->token_session_in + rt->token_session_out;
		int pct = ui_ctx_percent(total, shell->config->ui.ctx_len);

		if (pct > 80)
			printf("%s[警告] 会话上下文预算已用 %d%%"
			       "（config show 查看；compact 可压缩历史）%s\n",
			       ui_c(color, UI_C_YELLOW), pct,
			       ui_c(color, UI_C_RESET));
	}

out:
	free(question);
	free(sense_ctx);
	free(mem_ctx);
	free(tools_json);
	free(system_native);
	free(system_fallback);
	free(a.m);
	ask_owned_free(&owned);
	{
		int i;

		for (i = 0; i < hist_pool_n; i++)
			free(hist_pool[i]);
		free(hist_pool);
	}
	tool_registry_free(&reg);
	return ret;
}
