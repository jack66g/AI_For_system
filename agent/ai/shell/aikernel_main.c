/*
 * aikernel_main.c - AIKernel Shell 入口点（终端 AI 界面主程序）
 *
 * AIKernel OS 默认 Shell（aikernel-shell / ai 两个入口共用本实现，
 * 见 shell/main.c 与 Makefile install 的 /usr/local/bin/ai 软链）。
 *
 * UI Phase 特性：
 *   - linenoise 行内 REPL（历史 ~/.aikernel/history、Ctrl+D 退出、UTF-8），
 *     提示符带模型名与上下文预算用量（如 ai[qwen:18%]>）；
 *   - 命令行参数三层配置的最上层（优先级高于环境变量与 model.toml [ui]）：
 *       --ctx N --max-tokens N --no-stream --session <name> --no-color
 *   - 单发模式：ai -p "问题" 直接走 ask 闭环并退出（脚本/管道友好）。
 *
 * 编译为 /bin/aikernel-shell 二进制文件。
 * 替代 BusyBox /bin/sh 作为 AIKernel 系统的默认交互入口。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <sys/select.h>
#include <sys/utsname.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_ui.h"
#include "ai_json_util.h"
#include "ai_lang.h"
#include "policy/ai_user_policy.h"
#include "policy/ai_lease.h"
#include "linenoise.h"
#include "ai_trace.h"
#include "repl_paste.h"
#include "commands/ask_clarify.h"

/* W65 P1：Ctrl-C 取消接口（实现 shell/commands/cmd_ask.c） */
extern void ai_cancel_install(void);
extern void ai_cancel_restore(void);
extern volatile sig_atomic_t ai_cancel_requested;

/* W65 P3-02：--version 版本口径（与 alpha.8.0 基线一致） */
#define AIKERNEL_SHELL_VERSION "0.1.0-alpha.11.0"

/* 外部声明 */
extern struct ai_provider *openai_compatible_provider_create(void);
extern struct ai_provider *local_provider_create(void);

/* 行编辑历史文件与容量 */
#define UI_HISTORY_PATH  "~/.aikernel/history"
#define UI_HISTORY_MAX   500

/*
 * REPL 输入上限（字节，修复 4）：超过即明确报错拒绝，绝不静默丢失。
 * linenoise 本体支持 1MB 行缓冲；256KB 上限对超长上下文填充场景
 * （num_ctx 验证用的数千 token 输入）余量充足。
 */
#define REPL_INPUT_MAX  (256 * 1024)

/* 排队输入回显摘要长度（字节，UTF-8 截断用 utf8_floor） */
#define REPL_QUEUE_ECHO  48

/*
 * print_banner - 显示 AIKernel OS 启动横幅
 * T2 审计问题 7：Provider 状态此前硬编码 "Ready"/"Offline"——未配置也
 * 显示 Ready，演示会穿帮。改为按已加载配置（cfg）如实报告：
 * 未配置 → "Not configured"，已配置 → "Configured"（附模型/端点）。
 * 只读内存配置，不做任何阻塞的网络探测。
 */
static void print_banner(int color, const struct ai_config *cfg)
{
	struct utsname uts;

	if (uname(&uts) != 0)
		return;
	printf("\n");
	printf("====================================\n");
	printf("\n");
	printf("          AIKernel OS\n");
	printf("\n");
	printf("====================================\n");
	printf("\n");
	printf(tr(TR_BANNER_KERNEL), uts.release);
	printf("\n");

	/* 尝试读取 /proc/aikernel */
	if (access("/proc/aikernel", F_OK) == 0) {
		printf("%s", tr(TR_BANNER_AI_STARTING));
		printf("%s", tr(TR_BANNER_KAI_READY));
		if (cfg && cfg->model_count > 0 && cfg->default_model)
			printf(tr(TR_BANNER_CLOUD_CFG), cfg->default_model);
		else
			printf("%s", tr(TR_BANNER_CLOUD_NOTCFG));
		if (cfg && cfg->local.base_url && cfg->local.base_url[0])
			printf(tr(TR_BANNER_LOCAL_CFG), cfg->local.base_url);
		else
			printf("%s", tr(TR_BANNER_LOCAL_NOTCFG));
	} else {
		printf("%s", tr(TR_BANNER_AI_STARTING));
		printf("%s", tr(TR_BANNER_NO_KAI));
	}
	(void)color;
	printf("\n");
	printf("%s", tr(TR_BANNER_HINT));
	printf("\n");
}

/*
 * ui_completion_callback - linenoise Tab 补全回调
 *   - 第一个 token：补全命令名（命令表全量：ask/chat/config/model/
 *     session/verbose/help/status/...）；
 *   - "config set <Tab>"：补全 [ui] 键名（ctx_len/max_tokens/stream/
 *     local_api/color/verbose/session）。
 * linenoiseAddCompletion 替换整行，故带前缀补全时拼回完整行。
 * 非 TTY 时 linenoise 不启用行编辑，本回调不会被调用（无副作用）。
 */
static void ui_completion_callback(const char *buf, linenoiseCompletions *lc)
{
	static const char *const ui_keys[] = {
		"ctx_len", "max_tokens", "stream",
		"local_api", "color", "verbose", "session",
	};
	struct ai_command *table = ai_commands_get_table();
	int count = ai_commands_get_count();
	const char *sp = strchr(buf, ' ');
	int i;

	if (!sp) {
		/* 命令名前缀补全 */
		size_t len = strlen(buf);

		if (len == 0)
			return;
		for (i = 0; i < count; i++) {
			if (table[i].name &&
			    strncmp(table[i].name, buf, len) == 0)
				linenoiseAddCompletion(lc, table[i].name);
		}
		return;
	}

	/* config set <前缀> → 键名补全（带完整前缀替换整行） */
	if (strncmp(buf, "config set ", 11) == 0) {
		const char *pfx = buf + 11;
		size_t len = strlen(pfx);

		for (i = 0; i < (int)(sizeof(ui_keys) / sizeof(ui_keys[0]));
		     i++) {
			char tmp[64];

			if (strncmp(ui_keys[i], pfx, len) != 0)
				continue;
			snprintf(tmp, sizeof(tmp), "config set %s",
				 ui_keys[i]);
			linenoiseAddCompletion(lc, tmp);
		}
	}
}

/*
 * Ctrl+O 运行时切换 verbose（工具卡片折叠/展开）：
 * linenoise key hook（third_party_ui 唯一功能性扩展点）在主线程
 * 回调，直接翻转 shell->config->ui.verbose 并重画提示符（提示符带
 * V 标记即时反映状态）。工具卡片形态在下一次 ask 立即变化
 * （print_tool_exchange 每次调用时读取）。等价命令行操作：
 * `config set verbose on|off`（同样运行时生效）。
 */
static struct ai_shell *g_shell;        /* REPL 活动实例（单线程） */
static int g_verbose_announce;          /* 1=REPL 循环需播报切换结果 */

static void ui_ctrl_o_callback(void)
{
	if (!g_shell || !g_shell->config)
		return;
	g_shell->config->ui.verbose = !g_shell->config->ui.verbose;
	g_verbose_announce = 1;
}

/*
 * build_prompt - 构建行内提示符：ai[模型:NN%]>（带颜色）
 * 模型名取 API 模型名（本地原生通道即 Ollama 模型），截掉 ":tag" 尺寸
 * 后缀（qwen2.5:1.5b -> qwen2.5）保持短促；百分比 = 会话累计 token /
 * ctx_len 预算；verbose 开启时附加 "|V" 标记（Ctrl+O 切换即时反映）。
 * 修复 7（T2 P1-5/P2：提示符假显 0%）：尚无任何 usage 数据（首轮
 * 请求未发生，或服务端不给 usage 且无法估算）时显示 "?"——不显示
 * 假 0% 误导用户。真实值来源：ollama prompt_eval_count/eval_count
 * 或云端 usage.prompt_tokens/completion_tokens（runtime 层回填）。
 */
static void build_prompt(const struct ai_shell *shell, char *buf, size_t len)
{
	const struct ai_config *cfg = shell->config;
	const struct ai_runtime *rt = &shell->runtime;
	int color = cfg->ui.color;
	char model[64];
	char pctstr[16];
	const char *src;
	char *colon;
	long used;
	int pct;
	int no_data;

	src = rt->model_name ? rt->model_name :
	      (rt->current_model ? rt->current_model : "nomodel");
	snprintf(model, sizeof(model), "%s", src);
	colon = strrchr(model, ':');
	if (colon && colon != model)
		*colon = '\0';   /* 去掉 ":1.5b" 这类标签 */

	used = (long)rt->token_session_in + rt->token_session_out;
	no_data = (used <= 0);
	pct = ui_ctx_percent(used, cfg->ui.ctx_len);

	/* 修复 7：无 usage 数据显示 "?"（不是假 0%） */
	if (no_data)
		snprintf(pctstr, sizeof(pctstr), "?");
	else
		snprintf(pctstr, sizeof(pctstr), "%d%%", pct);

	/* W43：plan 态提示符标记（与 "|V" verbose 标记同位同风格，
	 * 如 ai[qwen:18%|plan]>） */
	if (ai_policy_get_plan_mode() &&
	    strlen(pctstr) + 5 < sizeof(pctstr))
		strcat(pctstr, "|plan");

	if (cfg->ui.verbose)
		snprintf(buf, len, "%sai[%s%s:%s%s%s%s|%sV%s%s]%s> ",
			 ui_c(color, UI_C_CYAN),
			 ui_c(color, UI_C_YELLOW), model,
			 pct > 80 ? ui_c(color, UI_C_YELLOW) : "",
			 pctstr,
			 pct > 80 ? ui_c(color, UI_C_RESET) : "",
			 ui_c(color, UI_C_YELLOW),
			 ui_c(color, UI_C_YELLOW),
			 ui_c(color, UI_C_RESET),
			 ui_c(color, UI_C_YELLOW),
			 ui_c(color, UI_C_RESET));
	else
		snprintf(buf, len, "%sai[%s%s:%s%s%s%s]%s> ",
			 ui_c(color, UI_C_CYAN),
			 ui_c(color, UI_C_YELLOW), model,
			 pct > 80 ? ui_c(color, UI_C_YELLOW) : "",
			 pctstr,
			 pct > 80 ? ui_c(color, UI_C_RESET) : "",
			 ui_c(color, UI_C_YELLOW),
			 ui_c(color, UI_C_RESET));
}

/* P0-1（W18）直说转 ask 的首次提示标志（每进程一次，不刷屏） */
static int g_ask_fallback_hint_shown;

/*
 * dispatch_line - 分发一行用户输入（分词 + 查命令表 + 调 handler）
 * 返回: AI_OK 或命令错误码
 *
 * P0-1：非命令字的一切非空输入默认按 ask 处理（等同 "ask <原文>"）
 * ——用户直说自然语言不再撞 "Unknown command"（真实用户首批对话
 * 4 次直说全被拒）。已知命令字的封闭集合仍走命令表；空输入/纯空白
 * 在 argc==0 已拦截。审计如实：走 cmd_ask 原通道，会话文件 role=user
 * 记录原始提问。
 */
static int dispatch_line(struct ai_shell *shell, char *line)
{
	/* 512 词上限：支持超长单行问题（如 num_ctx 验证用的数千 token
	 * 填充输入），cmd_ask 会把全部词拼接回完整问题 */
	char *argv[512];
	int argc = 0;
	int ret;
	char *p = line;
	/* 原始行副本：分词会写入 '\0' 破坏原行，转 ask 需要完整原文 */
	char *raw = strdup(line);

	if (raw) {
		/* W60：多行粘贴=一次 ask——只去掉行尾换行，保留内部换行。
		 * 旧代码 raw[strcspn(raw, "\r\n")] = '\0' 在首个换行处
		 * 截断，粘贴内容只剩第一行。 */
		size_t rl = strlen(raw);

		while (rl > 0 && (raw[rl-1] == '\r' || raw[rl-1] == '\n'))
			raw[--rl] = '\0';
	}

	while (*p && argc < 512) {
		while (*p == ' ' || *p == '\t' || *p == '\n')
			p++;
		if (!*p)
			break;
		argv[argc++] = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\n')
			p++;
		if (*p) {
			*p = '\0';
			p++;
		}
	}
	if (argc == 0) {
		free(raw);
		return AI_OK;
	}

	/* W43：slash 命令——前导 '/' 剥离后按命令表分发（/help 等价
	 * help）。未命中的 slash 输入给友好报错 + /help 提示，不落回
	 * ask 直说：以 / 开头是明确想敲命令，转问 AI 反而遮蔽拼写错误。 */
	if (argv[0][0] == '/') {
		struct ai_command *scmd = NULL;
		int i;

		memmove(argv[0], argv[0] + 1, strlen(argv[0]));
		if (!argv[0][0]) {
			free(raw);
			return AI_OK;
		}
		for (i = 0; i < shell->command_count; i++) {
			if (!shell->commands[i].name)
				break;
			if (strcmp(argv[0], shell->commands[i].name) == 0) {
				scmd = &shell->commands[i];
				break;
			}
		}
		if (scmd) {
			int sret = scmd->handler(shell, argc, argv);

			(void)sret;
		} else {
			printf(tr(TR_REPL_SLASH_UNKNOWN), argv[0]);
		}
		free(raw);
		return AI_OK;
	}

	{
		struct ai_command *cmd = NULL;
		int i;

		for (i = 0; i < shell->command_count; i++) {
			if (!shell->commands[i].name)
				break;
			if (strcmp(argv[0], shell->commands[i].name) == 0) {
				cmd = &shell->commands[i];
				break;
			}
		}

		if (cmd) {
			ret = cmd->handler(shell, argc, argv);
			(void)ret;
		} else if (raw && raw[0]) {
			/* 非命令输入 → 对 AI 直说（首次给一行轻提示） */
			char *qargv[2];

			if (!g_ask_fallback_hint_shown) {
				printf("%s", tr(TR_REPL_ASK_HINT));
				g_ask_fallback_hint_shown = 1;
			}
			qargv[0] = (char *)"ask";
			qargv[1] = raw;
			ret = cmd_ask(shell, 2, qargv);
			(void)ret;
		} else {
			printf(tr(TR_REPL_UNKNOWN), argv[0]);
		}
	}
	free(raw);
	return AI_OK;
}

/* ---- REPL 输入排队层（修复 3+4，T2 P1-2/P1-3） ----
 *
 * 根因：linenoise 只在行编辑期间开 raw 模式，ask 命令执行期间 tty
 * 回到 canonical 模式——连发输入落在内核 4096 字节 canonical 行缓冲：
 *   - 4KB 整行输入的第 4096 字节恰为换行时被行 discipline 吞掉，整行
 *     卡死后续输入（T2 e49：4KB 静默丢失而 10KB 反而受理）；
 *   - 连发 10 条 ask 只有第 1 条被处理，其余在 canonical 缓冲里被
 *     静默丢弃（T2 e48 F1：丢 9 条）。
 * 方案（全部用户态，不碰 tty 驱动）：
 *   1. 命令执行期间保持 ICANON off + ECHO off（ISIG 保留，Ctrl+C 仍
 *      可用）——输入进 raw 缓冲，内核只做流控不丢字节；
 *   2. 每条命令分发前后 select(0 超时) 主动排空 stdin，按 '\n' 组装
 *      行入 FIFO 队列，逐条顺序消费并回显——任何输入要么被处理要么
 *      被明确提示；
 *   3. 单行超过 REPL_INPUT_MAX 明确报错拒绝（不静默）；
 *   4. 无换行的尾部残余暂存（g_partial），下轮排空续拼（带可见提示，
 *      绝不丢弃已读字节）。
 */

/* 无换行尾部残余（跨 drain 续拼；调度单线程，无需加锁） */
static char *g_partial;

struct repl_queue {
	char **items;
	int n;
	int cap;
};

static void rq_push(struct repl_queue *q, char *s)   /* 接管所有权 */
{
	if (q->n >= q->cap) {
		int ncap = q->cap ? q->cap * 2 : 8;
		char **ni = realloc(q->items, sizeof(char *) * (size_t)ncap);

		if (!ni) {
			free(s);
			return;
		}
		q->items = ni;
		q->cap = ncap;
	}
	q->items[q->n++] = s;
}

static void rq_free(struct repl_queue *q)
{
	int i;

	for (i = 0; i < q->n; i++)
		free(q->items[i]);
	free(q->items);
	memset(q, 0, sizeof(*q));
}

/*
 * tty_exec_mode - 命令执行期 tty 模式（关 ICANON/ECHO，保留 ISIG）
 * 返回: 1=已切换（*saved 有效）；0=非 tty 或 tcgetattr 失败（caller
 * 按"无 tty 排队层"处理——管道模式下 linenoise/fgets 逐行天然顺序）。
 */
static int tty_exec_mode(struct termios *saved)
{
	struct termios t;

	if (!isatty(STDIN_FILENO))
		return 0;
	if (tcgetattr(STDIN_FILENO, &t) != 0)
		return 0;
	*saved = t;
	t.c_lflag &= ~(tcflag_t)(ICANON | ECHO);
	if (tcsetattr(STDIN_FILENO, TCSANOW, &t) != 0)
		return 0;
	return 1;
}

static void tty_restore(const struct termios *saved, int active)
{
	if (active && saved)
		tcsetattr(STDIN_FILENO, TCSANOW, saved);
}

/* 残余并入新字节、按 '\n' 切行入队；返回 1=有新行 */
static int repl_assemble_lines(struct repl_queue *q, const char *buf,
			       ssize_t rr)
{
	char *p;
	char *nl;
	size_t plen;
	int got = 0;

	if (!g_partial) {
		g_partial = malloc(1);
		if (!g_partial)
			return 0;
		g_partial[0] = '\0';
	}
	{
		char *np = realloc(g_partial, strlen(g_partial) +
				   (size_t)rr + 1);

		if (!np)
			return got;
		g_partial = np;
	}
	plen = strlen(g_partial);
	memcpy(g_partial + plen, buf, (size_t)rr);
	g_partial[plen + (size_t)rr] = '\0';

	p = g_partial;
	while ((nl = strchr(p, '\n')) != NULL) {
		size_t len = (size_t)(nl - p);
		char *line;

		*nl = '\0';
		if (len > 0 && nl[-1] == '\r') {
			nl[-1] = '\0';
			len--;
		}
			line = strdup(p);
			if (line) {
				if (strlen(line) > REPL_INPUT_MAX) {
					/* 修复 4：超限明确报错，绝不静默丢弃 */
					printf(tr(TR_REPL_REJECT_LINE),
					       strlen(line), REPL_INPUT_MAX);
					free(line);
			} else if (line[0]) {
				rq_push(q, line);
				got = 1;
			} else {
				free(line);   /* 空行忽略 */
			}
		}
		p = nl + 1;
	}

	/* 残余移到队首（无换行的最后一段留待下轮续拼） */
	if (*p)
		memmove(g_partial, p, strlen(p) + 1);
	else {
		free(g_partial);
		g_partial = NULL;
	}
	return got;
}

/*
 * repl_drain_stdin - 排空当前可读的 stdin 字节，完整行入队
 * 返回: 1=有新行入队；0=无；-1=EOF 或不可读。
 * 残余（g_partial）超过 REPL_INPUT_MAX：明确报错后丢弃。
 */
static int repl_drain_stdin(struct repl_queue *q)
{
	int got = 0;

	for (;;) {
		fd_set rf;
		struct timeval tv;
		char buf[4096];
		ssize_t rr;

		FD_ZERO(&rf);
		FD_SET(STDIN_FILENO, &rf);
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		if (select(STDIN_FILENO + 1, &rf, NULL, NULL, &tv) <= 0)
			break;
		rr = read(STDIN_FILENO, buf, sizeof(buf));
		if (rr <= 0)
			return -1;          /* EOF/错误：排队层结束 */
		if (repl_assemble_lines(q, buf, rr))
			got = 1;
		if (g_partial && strlen(g_partial) > REPL_INPUT_MAX) {
			printf(tr(TR_REPL_REJECT_TAIL), strlen(g_partial),
			       REPL_INPUT_MAX);
			free(g_partial);
			g_partial = NULL;
		}
	}
	return got;
}

/*
 * repl_run_line - 分发单行输入
 * @echo: 1=先打印排队回显（非当前键入，需可见性）
 */
static void repl_run_line(struct ai_shell *shell, char *line, int echo)
{
	if (echo) {
		char head[REPL_QUEUE_ECHO + 8];
		size_t l = strlen(line);

		if (l > REPL_QUEUE_ECHO) {
			l = (size_t)ai_json_utf8_floor(line,
						       REPL_QUEUE_ECHO);
			memcpy(head, line, l);
			head[l] = '\0';
			strcat(head, "…");
		} else {
			memcpy(head, line, l + 1);
		}
		printf("%s%s%s %s\n", ui_c(shell->config->ui.color,
		       UI_C_DIM), tr(TR_REPL_QUEUED),
		       ui_c(shell->config->ui.color,
		       UI_C_RESET), head);
		fflush(stdout);
	}
	dispatch_line(shell, line);
}

/*
 * repl_dispatch_with_queue - 分发首行并消费执行期间到达的排队输入
 * （修复 3：十连发不再丢 9 条；修复 4：4KB 输入不再被 canonical
 * 行缓冲吞掉）
 */
static void repl_dispatch_with_queue(struct ai_shell *shell, char *first)
{
	struct termios saved;
	int in_exec;
	struct repl_queue q = { NULL, 0, 0 };
	int qi = 0;

	/* 命令执行期（含首行）保持非 canonical：连发输入进 raw 缓冲 */
	in_exec = tty_exec_mode(&saved);

	repl_run_line(shell, first, 0);
	if (in_exec)
		repl_drain_stdin(&q);

	while (qi < q.n && shell->running) {
		repl_run_line(shell, q.items[qi++], 1);
		/* 处理本条期间又到达的输入继续入队 */
		if (in_exec)
			repl_drain_stdin(&q);
	}

	tty_restore(&saved, in_exec);
	rq_free(&q);
}

/*
 * usage - 命令行帮助
 */
static void usage(FILE *fp, const char *prog)
{
	fprintf(fp, tr(TR_USAGE_FMT),
		prog, UI_DEFAULT_CTX_LEN, UI_DEFAULT_MAX_TOKENS);
	/* W77c-2a：非 TTY 澄清恢复（argv 在 /proc 可见，敏感回答后续
	 * 应优先走文件/环境变量，见 CHANGELOG）。 */
	fprintf(fp, "      --clarify-answer <nonce>  恢复非 TTY 澄清（消费 pending）\n"
		    "      --clarify-select <ids>    选择项 id/序号（逗号或空格分隔）\n"
		    "      --clarify-other <text>    自由回答（Other）\n");
}

/* print_version - --version：Shell 版本 + 内核 release（P3-02） */
static void print_version(void)
{
	struct utsname uts;

	if (uname(&uts) != 0)
		snprintf(uts.release, sizeof(uts.release), "unknown");
	printf(tr(TR_VERSION_FMT), AIKERNEL_SHELL_VERSION, uts.release);
}

/*
 * run_clarify_resume - W77c-2a：消费非 TTY pending 并按记录恢复 ask
 *
 * 顺序：load+校验 -> 解析选择/Other -> 原子 consume -> 构造单行
 * [clarification answer] -> cmd_ask（记录 session）。选择非法时不消费，
 * 可修正后重试；消费后重放一律失败。澄清不创建租约，D2+ 仍走 W74 gate。
 * 注意：--clarify-select/--clarify-other 经 argv 传入，/proc 可见；
 * 当前可接受，敏感场景后续走文件/环境变量。
 */
static int run_clarify_resume(struct ai_shell *shell, const char *nonce,
			      const char *select, const char *other,
			      int session_explicit)
{
	struct ask_clarify_pending p;
	char labels[ASK_CLARIFY_RESUMED_MAX];
	char err[256] = "";
	char *resumed = NULL;
	char *qargv[2];
	int rc;

	if (!nonce || !nonce[0]) {
		fprintf(stderr, "clarify: --clarify-answer 需要 nonce\n");
		return AI_ERR_INVALID_ARG;
	}
	if ((!select || !select[0]) && (!other || !other[0])) {
		fprintf(stderr, "clarify: 需要 --clarify-select 或 "
			"--clarify-other\n");
		return AI_ERR_INVALID_ARG;
	}
	memset(&p, 0, sizeof(p));
	if (ask_clarify_pending_load(nonce,
				     session_explicit ?
				     shell->config->ui.session : NULL,
				     &p, err, sizeof(err)) != 0) {
		fprintf(stderr, "clarify: %s\n", err);
		return AI_ERR_INVALID_ARG;
	}
	if (!session_explicit) {
		char *dup = strdup(p.session);

		if (!dup) {
			fprintf(stderr, "clarify: 内存不足（session）\n");
			ask_clarify_pending_free(&p);
			return AI_ERR_MEMORY;
		}
		free(shell->config->ui.session);
		shell->config->ui.session = dup;
	}
	if (ask_clarify_resolve_selection(&p.req, select, other, labels,
					  sizeof(labels), err,
					  sizeof(err)) != 0) {
		fprintf(stderr, "clarify: %s\n", err);
		ask_clarify_pending_free(&p);
		return AI_ERR_INVALID_ARG;
	}
	if (ask_clarify_pending_consume(nonce, err, sizeof(err)) != 0) {
		fprintf(stderr, "clarify: %s\n", err);
		ask_clarify_pending_free(&p);
		return AI_ERR_INVALID_ARG;
	}
	{
		char abuf[16];

		snprintf(abuf, sizeof(abuf), "%d", p.asked);
		setenv("AIKERNEL_CLARIFY_ASKED", abuf, 1);
	}
	if (asprintf(&resumed, "%s\n[clarification answer] %s -> %s",
		     p.original_question, p.req.question, labels) < 0) {
		fprintf(stderr, "clarify: 内存不足（resume question）\n");
		ask_clarify_pending_free(&p);
		return AI_ERR_MEMORY;
	}
	qargv[0] = (char *)"ask";
	qargv[1] = resumed;
	rc = cmd_ask(shell, 2, qargv);
	free(resumed);
	ask_clarify_pending_free(&p);
	return rc;
}

/*
 * aikernel_shell_main - 共享主入口（aikernel-shell 与 ai 两个二进制）
 */
int aikernel_shell_main(int argc, char **argv)
{
	struct ai_shell shell;
	struct ai_provider *openai_p, *local_p;
	char *single_question = NULL;
	char *prompt_env = NULL;	/* W77c-2b：-p - 从环境读取问题 */
	char *lease_id = NULL;		/* --lease <id>（W74） */
	char *confirm_nonce = NULL;	/* --confirm <nonce>（W74） */
	char *clarify_answer = NULL;	/* --clarify-answer <nonce>（W77c-2a） */
	char *clarify_select = NULL;	/* --clarify-select <ids> */
	char *clarify_other = NULL;	/* --clarify-other <text> */
	int session_explicit = 0;	/* 显式 --session：必须匹配 pending */
	int assume_yes = 0;		/* -y / AIKERNEL_ASSUME_YES → ephemeral */
	int no_onboarding = 0;
	int ret;
	int i;

	/*
	 * T2 问题 4 根因修复：stdout 接管道/文件（如 tmux 编排
	 * `aikernel-shell | tee`、脚本重定向）时 glibc stdio 转为全缓冲，
	 * printf 输出（启动横幅/help 命令/ask 过程卡片）滞留在缓冲区，
	 * 终端上看不到——提示符与回显正常是因为 linenoise 直接
	 * write(2) 到 fd 绕过 stdio。强制行缓冲恢复与交互终端一致的
	 * 实时输出；stderr（W2 确认界面）默认无缓冲不受影响。
	 */
	setvbuf(stdout, NULL, _IOLBF, 0);

	/* W77c-2b：API tagged event 通道。立即读取并移除环境变量，
	 * 确保后续 exec 的工具子进程无法伪造澄清事件。非法 tag 时
	 * fail closed（API 调用方会得到协议错误，而不是裸 JSON）。 */
	if (ask_clarify_event_tag_init() < 0) {
		fprintf(stderr, "aikernel: AIKERNEL_EVENT_TAG 非法\n");
		return AI_ERR_INVALID_ARG;
	}

	static struct option long_opts[] = {
		{ "prompt",        required_argument, NULL, 'p' },
		{ "ctx",           required_argument, NULL, 'c' },
		{ "max-tokens",    required_argument, NULL, 'm' },
		{ "no-stream",     no_argument,       NULL, 'S' },
		{ "session",       required_argument, NULL, 's' },
		{ "no-color",      no_argument,       NULL, 'C' },
		{ "no-onboarding", no_argument,       NULL, 'N' },
		{ "yes",           no_argument,       NULL, 'y' },
		{ "assume-yes",    no_argument,       NULL, 'y' },
		{ "plan",          no_argument,       NULL, 'P' },
		/* W74：显式租约 / 单次确认消费（无短选项） */
		{ "lease",         required_argument, NULL, 1000 },
		{ "confirm",       required_argument, NULL, 1001 },
		/* W77c-2a：非 TTY 澄清恢复 */
		{ "clarify-answer", required_argument, NULL, 1002 },
		{ "clarify-select", required_argument, NULL, 1003 },
		{ "clarify-other", required_argument, NULL, 1004 },
		{ "version",       no_argument,       NULL, 'V' },
		{ "help",          no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	/* 预扫描：先建 shell 再应用参数（参数需写入 config->ui） */
	memset(&shell, 0, sizeof(shell));
	shell.running = 0;
	shell.first_run = 0;

	shell.config = ai_config_init();
	if (!shell.config) {
		fprintf(stderr, "%s", tr(TR_ERR_CONFIG_INIT));
		return 1;
	}
	ai_config_load(shell.config);

	/* i18n：语言初始化（AIKERNEL_LANG > model.toml [ui] lang > zh）。
	 * 必须在横幅/任何 tr() 使用之前执行 */
	lang_init(shell.config->ui.lang);

	/* 修复 10：环境变量预授权（AIKERNEL_ASSUME_YES=1/true/yes/on）。
	 * 命令行 --yes 优先（仅叠加置位，无取消语义） */
	{
		const char *ay = getenv("AIKERNEL_ASSUME_YES");

		if (ay && (strcasecmp(ay, "1") == 0 ||
			   strcasecmp(ay, "true") == 0 ||
			   strcasecmp(ay, "yes") == 0 ||
			   strcasecmp(ay, "on") == 0)) {
			ai_policy_set_assume_yes(1);
			assume_yes = 1;
		}
	}

	/* ---- 命令行参数（三层配置最高层） ---- */
	optind = 1;
	while ((ret = getopt_long(argc, argv, "+p:c:m:s:SCNhNyPV",
				  long_opts, NULL)) != -1) {
		switch (ret) {
		case 'p':
			single_question = optarg;
			break;
		case 'c': {
			long v = strtol(optarg, NULL, 10);

			if (v > 0)
				shell.config->ui.ctx_len = (int)v;
			break;
		}
		case 'm': {
			long v = strtol(optarg, NULL, 10);

			if (v > 0)
				shell.config->ui.max_tokens = (int)v;
			break;
		}
		case 'S':
			shell.config->ui.stream = 0;
			break;
		case 's': {
			char *dup = strdup(optarg);

			if (dup) {
				free(shell.config->ui.session);
				shell.config->ui.session = dup;
				session_explicit = 1;
			}
			break;
		}
		case 'C':
			shell.config->ui.color = 0;
			break;
		case 'N':
			no_onboarding = 1;
			break;
		case 'y':
			/* W74：-y 只生成"本次 ask 的 D2 短租约"，不再全局免确认；
			 * 仍置 assume_yes 供 system prompt 文案使用。 */
			ai_policy_set_assume_yes(1);
			assume_yes = 1;
			break;
		case 1000:
			lease_id = optarg;
			break;
		case 1001:
			confirm_nonce = optarg;
			break;
		case 1002:
			clarify_answer = optarg;
			break;
		case 1003:
			clarify_select = optarg;
			break;
		case 1004:
			clarify_other = optarg;
			break;
		case 'P':
			/* W43：plan 只读模式启动即进入（REPL 与单发 -p 通用；
			 * 闸门在 executor.c，提示注入在 cmd_ask.c） */
			ai_policy_set_plan_mode(1);
			break;
		case 'h':
			usage(stdout, argv[0]);
			ai_config_destroy(shell.config);
			return 0;
		case 'V':
			print_version();
			ai_config_destroy(shell.config);
			return 0;
		default:
			usage(stderr, argv[0]);
			ai_config_destroy(shell.config);
			return 1;
		}
	}
	/* W77c-2b：API 用环境变量传递选择，避免回答出现在 /proc/cmdline；
	 * 读取后立即移除，恢复 ask 的工具子进程不可见。 */
	if (!clarify_select || !clarify_select[0]) {
		const char *ev = getenv("AIKERNEL_CLARIFY_SELECT");

		if (ev) {
			char *dup = ev[0] ? strdup(ev) : NULL;

			unsetenv("AIKERNEL_CLARIFY_SELECT");
			if (dup)
				clarify_select = dup;
		}
	}
	if (!clarify_other || !clarify_other[0]) {
		const char *ev = getenv("AIKERNEL_CLARIFY_OTHER");

		if (ev) {
			char *dup = ev[0] ? strdup(ev) : NULL;

			unsetenv("AIKERNEL_CLARIFY_OTHER");
			if (dup)
				clarify_other = dup;
		}
	}
	/* W77c-2b：-p - 从 AIKERNEL_PROMPT 读取完整问题（保留空格/换行），
	 * 避免 API 把用户问题放进 argv。 */
	if (single_question && strcmp(single_question, "-") == 0) {
		const char *envq = getenv("AIKERNEL_PROMPT");

		prompt_env = (envq && envq[0]) ? strdup(envq) : NULL;
		unsetenv("AIKERNEL_PROMPT");
		if (!prompt_env) {
			fprintf(stderr,
				"ask: -p - 需要非空 AIKERNEL_PROMPT\n");
			ai_config_destroy(shell.config);
			return 1;
		}
		single_question = prompt_env;
	}
	/* W77c-2a：--clarify-select/other 必须依附 --clarify-answer，
	 * 且恢复至少需要一种回答；任何缺失都在模型调用前失败。 */
	if ((clarify_select || clarify_other) && !clarify_answer) {
		fprintf(stderr, "clarify: --clarify-select/--clarify-other "
			"需要 --clarify-answer <nonce>\n");
		usage(stderr, argv[0]);
		ai_config_destroy(shell.config);
		return 1;
	}
	if (clarify_answer &&
	    (!clarify_select || !clarify_select[0]) &&
	    (!clarify_other || !clarify_other[0])) {
		fprintf(stderr, "clarify: --clarify-answer 需要 "
			"--clarify-select 或 --clarify-other\n");
		ai_config_destroy(shell.config);
		return 1;
	}
	/* W48B：轨迹日志初始化（trace.toml 缺失用默认值；失败不阻断） */
	ai_trace_init(NULL, 0);

	/* W74：租约上下文初始化（trace 之后再写审计/轨迹）。
	 * 优先级：命令行 --lease > AIKERNEL_LEASE > -y ephemeral > NONE。
	 * 显式租约加载失败（不存在/解析错/过期/撤销/跨用户）一律非 0 退出，
	 * 绝不静默退回无租约。 */
	{
		const char *env_lease = getenv("AIKERNEL_LEASE");
		const char *env_confirm = getenv("AIKERNEL_CONFIRM_NONCE");
		const char *use_lease = (lease_id && lease_id[0]) ? lease_id :
					((env_lease && env_lease[0]) ?
					 env_lease : NULL);
		const char *use_confirm = (confirm_nonce && confirm_nonce[0]) ?
					  confirm_nonce :
					  ((env_confirm && env_confirm[0]) ?
					   env_confirm : NULL);
		char lerr[AI_LEASE_ERR_MAX] = "";

		if (use_confirm)
			setenv("AIKERNEL_CONFIRM_NONCE", use_confirm, 1);
		if (ai_lease_ctx_init(use_lease, assume_yes, getuid(),
				      lerr, sizeof(lerr)) != 0) {
			fprintf(stderr, "%s", tr(TR_LEASE_DENY_LOAD));
			if (lerr[0])
				fprintf(stderr, tr(TR_LEASE_ERR_LOAD), lerr);
			ai_trace_session_end("lease_load_failed");
			ai_trace_shutdown();
			ai_config_destroy(shell.config);
			return 1;
		}
		if (!single_question && !clarify_answer) {
			const struct ai_lease_ctx *lctx = ai_lease_ctx_get();

			if (lctx->mode == AI_LEASE_MODE_EXPLICIT)
				fprintf(stderr, tr(TR_LEASE_EXPLICIT_NOTE),
					lctx->lease.lease_id,
					ai_danger_name(lctx->lease.risk_ceiling),
					lctx->lease.scope_count);
			else if (lctx->mode == AI_LEASE_MODE_EPHEMERAL)
				fprintf(stderr, "%s",
					tr(TR_LEASE_EPHEMERAL_NOTE));
		}
	}

	/* 显示 AIKernel OS 横幅（单发/澄清恢复模式不打横幅） */
	if (!single_question && !clarify_answer)
		print_banner(shell.config->ui.color, shell.config);

	/* 初始化 Provider 注册中心（按 Kconfig 开关条件注册，见 Makefile） */
	ai_provider_registry_init(&shell.registry);

#ifdef CONFIG_AI_CLOUD_PROVIDER
	openai_p = openai_compatible_provider_create();
	if (openai_p)
		ai_provider_register(&shell.registry, openai_p);
#endif

#ifdef CONFIG_AI_LOCAL_PROVIDER
	local_p = local_provider_create();
	if (local_p)
		ai_provider_register(&shell.registry, local_p);
#endif
	(void)openai_p;
	(void)local_p;

	/* 初始化 Runtime */
	ai_runtime_init(&shell.runtime, shell.config, &shell.registry);

	/* 如果有默认模型，自动加载 */
	if (shell.config->default_model) {
		ai_runtime_set_model(&shell.runtime,
				     shell.config->default_model);
	}

	/* 获取命令表 */
	shell.commands = ai_commands_get_table();
	shell.command_count = ai_commands_get_count();

	/* 检查模型配置 */
	{
		int model_count;
		char **model_names;

		ai_config_get_models(shell.config, &model_names,
				     &model_count);
		if (model_count == 0)
			shell.first_run = 1;
		else {
			for (i = 0; i < model_count; i++)
				free(model_names[i]);
			free(model_names);
		}
	}

	/* ---- W77c-2a：非 TTY 澄清恢复 ---- */
	if (clarify_answer) {
		ret = run_clarify_resume(&shell, clarify_answer,
					 clarify_select, clarify_other,
					 session_explicit);
		ai_trace_session_end(ai_cancel_requested ? "cancelled" :
				     "clarify_resume_exit");
		ai_trace_shutdown();
		ai_cancel_restore();
		ai_runtime_destroy(&shell.runtime);
		ai_provider_registry_destroy(&shell.registry);
		ai_config_destroy(shell.config);
		return ret == AI_OK ? 0 : 1;
	}

	/* ---- 单发模式：ai -p "问题" ---- */
	if (single_question) {
		char *qargv[512];
		int qargc = 0;
		char *p = single_question;

		qargv[qargc++] = (char *)"ask";
		if (prompt_env) {
			/* W77c-2b：环境问题作为单个 argv，cmd_ask 原样拼接 */
			qargv[qargc++] = prompt_env;
		} else {
			while (*p && qargc < 511) {
				while (*p == ' ' || *p == '\t')
					p++;
				if (!*p)
					break;
				qargv[qargc++] = p;
				while (*p && *p != ' ' && *p != '\t')
					p++;
				if (*p)
					*p++ = '\0';
			}
		}
		ret = AI_OK;
		if (qargc >= 2) {
			ret = cmd_ask(&shell, qargc, qargv);
		} else {
			fprintf(stderr, "%s", tr(TR_ERR_P_QUESTION));
			ret = AI_ERR_INVALID_ARG;
		}

		ai_trace_session_end(ai_cancel_requested ? "cancelled" :
				     "single_shot_exit");
		ai_trace_shutdown();
		ai_cancel_restore();
		ai_runtime_destroy(&shell.runtime);
		ai_provider_registry_destroy(&shell.registry);
		ai_config_destroy(shell.config);
		return ret == AI_OK ? 0 : 1;
	}

	/* ---- onboarding：出厂态首次初始化引导 ----
	 * 条件：未带 --no-onboarding、非单发模式、/etc/aikernel/.onboarded
	 * 缺失且交互 TTY（onboarding_should_start 复核）。引导完成后落标
	 * 记，此后的启动直接进入正常 REPL；引导被中止（EOF）时正常 REPL
	 * 仍可进入（救援通道不因引导中断而关闭）。 */
	if (!single_question && !no_onboarding && onboarding_should_start())
		onboarding_run(&shell);

	/* ---- linenoise 行内 REPL ---- */
	shell.running = 1;
	g_shell = &shell;
	ai_cancel_install();
	ai_cancel_requested = 0;
	linenoiseSetKeyCallback(ui_ctrl_o_callback);
	{
		char hist_path[AI_PATH_MAX];
		const char *home = getenv("HOME");

		linenoiseHistorySetMaxLen(UI_HISTORY_MAX);
		linenoiseSetCompletionCallback(ui_completion_callback);
		if (home && home[0]) {
			snprintf(hist_path, sizeof(hist_path),
				 "%s/.aikernel/history", home);
			linenoiseHistoryLoad(hist_path);
		}
	}

	while (shell.running) {
		char prompt[160];
		char *line;

		if (g_verbose_announce) {
			printf(tr(TR_VERBOSE_ANNOUNCE),
			       shell.config->ui.verbose ? "on" : "off",
			       shell.config->ui.verbose ?
			       tr(TR_VERBOSE_EXPANDED) :
			       tr(TR_VERBOSE_COLLAPSED));
			g_verbose_announce = 0;
		}
		build_prompt(&shell, prompt, sizeof(prompt));
		/* W65 P1：清掉上一次空闲 Ctrl-C/取消留下的标志 */
		ai_cancel_requested = 0;
		errno = 0;
		line = linenoise(prompt);
		if (!line) {
			/* 区分 Ctrl-C 与 EOF：linenoise raw 模式 Ctrl-C 返回
			 * NULL+EAGAIN；TERM=dumb/NoTTY 下 SIGINT 使 fgets
			 * 返回 EINTR；真正 EOF 为 ENOENT 或 errno 未置位。 */
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EINTR) {
				printf("\n");
				fflush(stdout);
				ai_cancel_requested = 0;
				continue;       /* 清行继续，不退出 */
			}
			/* Ctrl+D / 非终端 EOF */
			printf("\n");
			break;
		}
		/* W65 P3-03：NoTTY/TERM=dumb 下合并 bracketed paste 多行，
		 * 避免一次 8KB 粘贴退化成 N 次模型请求。TTY raw 路径的
		 * 粘贴已由 linenoise 合并，本函数只剥残留标记。 */
		line = repl_paste_merge_line(line, stdin, REPL_INPUT_MAX);
		if (line[0]) {
			linenoiseHistoryAdd(line);
			{
				char hist_path[AI_PATH_MAX];
				const char *home = getenv("HOME");

				if (home && home[0]) {
					snprintf(hist_path,
						 sizeof(hist_path),
						 "%s/.aikernel/history", home);
					linenoiseHistorySave(hist_path);
				}
			}
			if (strlen(line) > REPL_INPUT_MAX) {
				/* 修复 4：超限明确报错（不静默丢弃） */
				printf(tr(TR_REPL_REJECT_LINE),
				       strlen(line), REPL_INPUT_MAX);
				fflush(stdout);
			} else {
				repl_dispatch_with_queue(&shell, line);
			}
		}
		linenoiseFree(line);
	}

	/* 清理 */
	ai_trace_session_end("repl_exit");
	ai_trace_shutdown();
	ai_cancel_restore();
	ai_runtime_destroy(&shell.runtime);
	ai_provider_registry_destroy(&shell.registry);
	ai_config_destroy(shell.config);

	return 0;
}
