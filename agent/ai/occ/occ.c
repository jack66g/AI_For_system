/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ.c - occ 主入口（T9a3：headless 一次性对话；交互 TUI 是 c 棒）
 *
 * 用法：
 *   occ -p "<prompt>" [--session <id>]   一次性对话（stdout 流式输出）
 *   occ --recover <id> [prompt]          从库重放中断环续跑；无进行中环
 *                                        时=打开续接（带 prompt 则续聊）
 *   occ undo --session <id> [--step N]   撤销最近 N 步（缺省 1；三段式
 *                                        stage——OCD §7.3 headless 形态）
 *   occ redo --session <id>              恢复上次 undo（revert.clear）
 *   occ retry --session <id>             重发最后一条 user 消息（中断后
 *                                        重发；tail=user/tool 时=重放）
 *   occ unstuck --session <id>            轻量解僵（running→interrupted，
 *                                        不重放——P-48 楔死/强杀残留）
 *   occ sessions                         会话列表（id/标题/token/状态/时间）
 *   occ tasks [--session <id>] [--json]  任务列表（id/标题/状态/rework/
 *                                        预算 tokens+cost_usd_ref；--json
 *                                        机读 JSONL——E8，ORCH §7）
 *   occ -h | occ                         用法
 *
 * 退出码：0 成功（含 ETOOLS——消息已留证）；1 运行错；2 用法错；
 *   130 = SIGINT 安全点中断（status=interrupted，可 occ retry/--recover）。
 *
 * 环境覆盖（产品配置路径，非测试后门）：
 *   OCC_MODEL_TOML   模型配置（缺省 ~/.aikernel/model.toml）
 *   OCC_PROVIDER_TOML provider 类型表（缺省 ~/.aikernel/provider.toml）
 *   OCC_DB           会话库（缺省 ~/.occ/sessions.db）
 *   OCC_SNAPROOT     快照根（缺省 ~/.occ/sessions… 见 occ_tools.h）
 *
 * 模型选择：model.toml `[default].model = "<slot>"` 选择器（系统正典，
 * config_manager/shell model switch 同源；LT-BUG-011 口径）命中即用；
 * 未指定则 [models.cloud] 槽位（dtchat 同源）；无 cloud 槽位时取首槽位。
 * 选择器悬空=人话报错不静默兜底。
 */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "occ_core/occ_ac.h"
#include "occ_core/occ_loop.h"
#include "occ_core/occ_replay.h"
#include "occ_core/occ_revert.h"
#include "occ_core/orch.h"			/* E3：编排运行时挂载 */
#include "occ_core/task.h"			/* E8：/tasks 面板+occ tasks */
#include "occ_llm/occ_catalog.h"
#include "occ_llm/occ_registry.h"
#include "occ_tui/tui_data.h"
#include "occ_tui/tui_usage.h"
#include "occ_tui/tui_utf8.h"
#include "occ_tui/tui_view.h"
#include "occ_tui/tui_gate.h"
#include "occ_tui/tui_lang.h"
#include "policy/ai_user_policy.h"	/* O-10（UX-O §3）：uid→档位 */
#include "occ_tools/occ_tools.h"	/* O-9（UX-O §2）：occ_w2_gate 面 */

/* O-9/O-10（UX-O §2/§3）：occ 面 W2 门 + /su 档位（main 初始化一次；
 * g_w2.tier 主线程写（/su）·worker 读——volatile int 单字，benign） */
static occ_w2_gate g_w2;
static int g_w2_base_tier = OCC_W2_TIER_RESTRICTED;
static int g_w2_ready;

#include "policy/ai_user_policy.h"	/* O-10（UX-O §3）：uid→档位 */
#include "occ_zoomrc.h"
#include "store/store_json.h"			/* E8：occ tasks --json 机读 */

static const char USAGE[] =
	"occ — AIKernel 编码助手（headless，T9a3+b2）\n"
	"用法：\n"
	"  occ -p \"<prompt>\" [--session <id>]   一次性对话（流式输出到 stdout）\n"
	"  （-p 下 W2 高危工具默认拒绝；--allow-w2 显式开门——O-9）\n"
	"  occ --recover <id> [prompt]          重放中断环续跑 / 打开续接\n"
	"  occ undo --session <id> [--step N]   撤销最近 N 步（文件回滚+消息隐藏）\n"
	"  occ redo --session <id>              恢复上次 undo\n"
	"  occ retry --session <id>             重发最后一条 user 消息\n"
	"  occ unstuck --session <id>            轻量解僵（running→interrupted，"
	"不重放）\n"
	"  occ sessions                         会话列表\n"
	"  occ tasks [--session <id>] [--json]  任务列表（状态/rework/预算；"
	"--json=机读 JSONL）\n"
	"环境：OCC_MODEL_TOML / OCC_PROVIDER_TOML / OCC_DB / OCC_SNAPROOT 可覆盖；"
	" 交互模式另支持 OCC_REPLAY_LINES（历史回放行数预算，缺省 1000，0=禁）\n";

/*
 * E3：编排运行时（进程级实例；OCC_ORCH_TOOLS=1 才建——默认关零开销）。
 * run_turn（headless 全链）与 tui_worker_main（交互 worker）经
 * occ_loop_opts.orch 透传进 occ_tool_ctx——task 第七工具执行面。
 * main out: 处 occ_orch_free 收尸（活子取消两段；§10 风险 3 口径）。
 */
static occ_orch *g_orch;

/* ---- SIGINT（T9b2；OCD §7.1 headless 版） ----
 * 第一次：置 occ_interrupt_flag——loop 在安全点（每工具后/每轮 LLM 前/
 * LLM 轮失败时）与 llm_call 退避中消费；第二次：_exit(130) 强退。 */
static void on_sigint(int sig)
{
	(void)sig;
	if (occ_interrupt_flag) {
		static const char m[] = "occ: force exit (SIGINT)\n";

		if (write(2, m, sizeof(m) - 1)) {
			/* 尽力而为 */
		}
		_exit(130);
	}
	occ_interrupt_flag = 1;
}

static void sigint_install(struct sigaction *old)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_sigint;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;			/* 不 SA_RESTART：可打断慢系统调用 */
	sigaction(SIGINT, &sa, old);
}

static const char *env_or(const char *name, const char *dflt)
{
	const char *v = getenv(name);

	return (v && v[0]) ? v : dflt;
}

static void fmt_time(long long ms, char *buf, size_t buflen)
{
	time_t t = (time_t)(ms / 1000);
	struct tm tm;

	localtime_r(&t, &tm);
	strftime(buf, buflen, "%Y-%m-%d %H:%M", &tm);
}

/* ---- 子命令 ---- */

static int cmd_sessions(occ_db *db)
{
	occ_session_row *rows = NULL;
	size_t n = 0, i;
	char err[160];
	char tbuf[32];

	if (occ_session_list(db, &rows, &n, err, sizeof(err))) {
		fprintf(stderr, "occ sessions: %s\n", err);
		return 1;
	}
	printf("%-38s %-30s %10s %-8s %-16s %s\n",
	       "ID", "TITLE", "TOKENS", "STATUS", "CREATED", "MODEL");
	for (i = 0; i < n; i++) {
		char tok[32];

		snprintf(tok, sizeof(tok), "%s%lld",
			 rows[i].tokens_est ? "~" : "",
			 rows[i].tokens_total);
		fmt_time(rows[i].created, tbuf, sizeof(tbuf));
		printf("%-38s %-30.30s %10s %-8s %-16s %s\n",
		       rows[i].id, rows[i].title, tok, rows[i].status,
		       tbuf, rows[i].model);
	}
	printf("(%zu session%s)\n", n, n == 1 ? "" : "s");
	free(rows);
	return 0;
}

static int resolve_provider(const char *model_toml, const char *provider_toml,
			    occ_provider *p, char *err, size_t errlen)
{
	occ_provider_config cfg;
	const char *slot;

	occ_provider_config_init(&cfg);
	if (occ_provider_load_all(&cfg, model_toml, provider_toml)) {
		snprintf(err, errlen,
			 "model config unreadable: %s", model_toml);
		occ_provider_config_free(&cfg);
		return -1;
	}
	/* LT-BUG-011：默认槽位=顶层 model= 选择器 → cloud → 首槽；
	 * 选择器悬空报人话错（不静默打到别的 provider）。 */
	slot = occ_provider_default_slot(&cfg);
	if (!slot) {
		if (cfg.selector[0])
			snprintf(err, errlen,
				 L_("model.toml model = \"%s\" 指向的 [models.%s] 不存在"), cfg.selector,
				 cfg.selector);
		else
			snprintf(err, errlen, "no model slots in %s",
				 model_toml);
		occ_provider_config_free(&cfg);
		return -1;
	}
	{
		int rc = occ_provider_resolve(&cfg, slot, p);

		occ_provider_config_free(&cfg);
		if (rc) {
			snprintf(err, errlen,
				 "resolve slot `%s' failed", slot);
			return -1;
		}
		if (p->api_key && !p->api_key[0])
			fprintf(stderr,
				L_("occ: 警告：[models.%s] api_key 为空，远端可能拒绝（%s）\n"), slot, model_toml);
		return 0;
	}
}

/* O-6：workdir 求值收口——cwd 命中 aik-sandbox 显式 bind 拒绝面
 * （/root 等，occ_sandbox_cwd_denied 同源表）→ 回退 /var/ai/work
 * （拒绝面外约定 rw 通道；mkdir -p 0755 尽力——失败留给沙箱面人话
 * 报错，不阻断启动）。TUI 与 headless 两路共用；*fb=是否回退（TUI
 * 首屏 notice/headless stderr 各自披露）。 */
static void occ_workdir_resolve(char *cwd, size_t cap, int *fb)
{
	*fb = 0;
	if (!occ_sandbox_cwd_denied(cwd))
		return;
	mkdir("/var/ai", 0755);			/* EEXIST 忽略 */
	if (mkdir("/var/ai/work", 0755) != 0 && errno != EEXIST) {
		/* 尽力建（root 常态可建；非 root 建不成不回退——原
		 * cwd 同样全灭，不更糟），失败留给沙箱面人话报错 */
	}
	snprintf(cwd, cap, "/var/ai/work");
	*fb = 1;
}

static int run_turn(occ_db *db, occ_provider *p, const char *session_id,
		    const char *prompt, int recover_mode)
{
	occ_loop_opts opts;
	occ_loop_result res;
	char err[512];
	struct sigaction old_int;
	int rc;

	memset(&opts, 0, sizeof(opts));
	opts.prompt = prompt;			/* NULL=重放（recover/retry） */
	opts.stream_out = stdout;
	opts.orch = g_orch;			/* E3：task 工具执行面 */
	{
		/* b1：工具工作目录=occ 启动目录（glob/grep/bash rw 面） */
		static char cwd[4096];
		int wd_fb;			/* O-6：沙箱拒绝面回退标志 */

		if (getcwd(cwd, sizeof(cwd))) {
			/* O-6：cwd=/root 等拒绝面首发 bash 全灭（rw-path
			 * 拒挂）——回退 /var/ai/work，stderr 一行披露 */
			occ_workdir_resolve(cwd, sizeof(cwd), &wd_fb);
			opts.workdir = cwd;
			if (wd_fb)
				fputs(L_("occ: workdir 回退 /var/ai/work（cwd 不可挂沙箱）\n"), stderr);
		}
	}
	opts.w2 = &g_w2;			/* O-9：W2 门（headless 默认拒） */
	sigint_install(&old_int);		/* b2：环内安全点中断 */
	rc = occ_loop_run(db, p, session_id, &opts, &res, err, sizeof(err));
	sigaction(SIGINT, &old_int, NULL);	/* 恢复默认（子命令期 Ctrl+C=杀） */
	if (rc == OCC_LOOP_OK || rc == OCC_LOOP_ETOOLS) {
		if (res.interrupted) {
			/* b2：安全点停——status=interrupted 已落库 */
			fputc('\n', stdout);
			fprintf(stderr, L_("occ: interrupted (safe point); session=%s status=interrupted\nocc: 用 `occ retry --session %s` 重发，或 `occ --recover %s` 续跑\n"),
				res.session_id, session_id ? session_id :
				res.session_id, session_id ? session_id :
				res.session_id);
			occ_loop_result_free(&res);
			return 130;
		}
		/* P-30：步数帽截断出声（87.6k tokens 零交付零提示教训）
		 * ——headless 尾部明示+retry/recover 指路 */
		if (res.steps_capped)
			fprintf(stderr, L_("occ: 步数帽 %d 截断（rounds=%d，工具链未收口）——`occ retry --session %s` 重发，或 `occ --recover %s` 续跑收口\n"),
				occ_loop_max_steps(), res.rounds,
				session_id ? session_id : res.session_id,
				session_id ? session_id : res.session_id);
		/* 流式正文已在环内输出；行尾补换行 */
		fputc('\n', stdout);
		if (rc == OCC_LOOP_ETOOLS)
			fprintf(stderr, "occ: %s\n", err);
		fprintf(stderr, "occ: session=%s msg=%s tokens=%lld%s"
			" finish=%s\n",
			res.session_id, res.assistant_msg_id,
			res.tokens.total, res.usage_est ? "(~est)" : "",
			res.finish);
		occ_loop_result_free(&res);
		if (recover_mode && !prompt)
			fprintf(stderr, "occ: recovered turn completed\n");
		return 0;
	}
	fprintf(stderr, "occ: %s\n", err);
	occ_loop_result_free(&res);
	return 1;
}

static int cmd_recover(occ_db *db, occ_provider *p, const char *id,
		       const char *prompt)
{
	occ_session_row s;
	occ_msg_row last;
	char err[160];
	char last_role[12] = "none";
	int has;

	if (occ_session_get(db, id, &s, err, sizeof(err)) != 1) {
		fprintf(stderr, "occ --recover: session %s not found\n", id);
		return 1;
	}
	has = occ_msg_last(db, id, &last, err, sizeof(err));
	if (has > 0) {
		snprintf(last_role, sizeof(last_role), "%s", last.role);
		occ_msg_row_free(&last);
	}
	printf("occ: session %s status=%s msgs-last=%s tokens=%lld%s\n",
	       id, s.status, last_role, s.tokens_total,
	       s.tokens_est ? "(~)" : "");
	if (!strcmp(s.status, OCC_ST_RUNNING) ||
	    !strcmp(s.status, OCC_ST_ERROR) ||
	    !strcmp(s.status, OCC_ST_INTERRUPTED)) {
		if (!strcmp(last_role, "user")) {
			/* 中断环：prompt=NULL → loop 重放路径（不重复落
			 * user 消息，从库重放窗口续跑） */
			return run_turn(db, p, id, NULL, 1);
		}
		if (!strcmp(last_role, "tool")) {
			/* b1：kill 在工具执行后、下一 LLM 轮前 → 续环 */
			return run_turn(db, p, id, NULL, 1);
		}
		if (!strcmp(last_role, "assistant")) {
			/* b1：assistant 携带 toolCall 未全应答（kill 在
			 * 落库与执行之间）→ 续环（先执行 pending） */
			occ_toolcall_part *pend = NULL;
			size_t npend = 0;

			if (occ_msg_pending_calls(db, id, &pend, &npend,
						  NULL, 0, err,
						  sizeof(err)) < 0) {
				fprintf(stderr, "occ --recover: %s\n", err);
				return 1;
			}
			if (npend > 0) {
				for (size_t q = 0; q < npend; q++) {
					free(pend[q].id);
					free(pend[q].tool);
					free(pend[q].arguments);
				}
				free(pend);
				return run_turn(db, p, id, NULL, 1);
			}
			free(pend);
		}
		/* running/error/interrupted 但环已收口（kill 在落库与状态
		 * 更新之间 / 中断落在收口后）：状态归位 active */
		if (!strcmp(s.status, OCC_ST_RUNNING) ||
		    !strcmp(s.status, OCC_ST_INTERRUPTED)) {
			occ_session_set_status(db, id, OCC_ST_ACTIVE,
					       err, sizeof(err));
			printf("occ: no in-flight turn; status reset to"
			       " active\n");
		}
		if (prompt)
			return run_turn(db, p, id, prompt, 1);
		return 0;
	}
	/* 无进行中环 = 打开续接 */
	if (prompt)
		return run_turn(db, p, id, prompt, 1);
	printf("occ: no in-flight turn; use `occ -p ... --session %s`"
	       " to continue\n", id);
	return 0;
}

/* ---- b2：/undo 三段式子命令（OCD §7.3 headless 形态） ---- */

static int cmd_undo(occ_db *db, const char *id, int steps)
{
	occ_undo_result r;
	char err[512];
	size_t i;
	int failed = 0;

	memset(&r, 0, sizeof(r));
	if (occ_undo(db, id, steps, NULL, &r, err, sizeof(err))) {
		fprintf(stderr, "%s\n", err);	/* err 已带 "occ undo: " 前缀 */
		return 1;
	}
	printf("occ: undo session=%s step=%d hidden=%zu files=%zu"
	       " un-reverted=%zu\n",
	       id, steps, r.nmsgs_reverted, r.nfiles, r.nskipped);
	for (i = 0; i < r.nfiles; i++) {
		const char *tag = r.files[i].failed ? L_("[失败] ") :
				  r.files[i].action == OCC_UNDO_DELETE ?
				  L_("[删除] ") : L_("[还原] ");

		if (r.files[i].failed)
			failed++;
		printf("  %s%s\n", tag, r.files[i].path);
	}
	if (r.user_text && r.user_text[0])
		printf(L_("被撤输入（回填语义）：\n%s\n"), r.user_text);
	printf(L_("occ: 发送新消息即确认撤销（此后不可 redo）；`occ redo --session %s` 可恢复\n"), id);
	occ_undo_result_free(&r);
	return failed ? 1 : 0;
}

static int cmd_redo(occ_db *db, const char *id)
{
	occ_undo_result r;
	char err[512];
	size_t i;
	int rc;

	memset(&r, 0, sizeof(r));
	err[0] = '\0';			/* 成功路径可能不置 err——防读未初始化 */
	rc = occ_redo(db, id, NULL, &r, err, sizeof(err));
	if (rc) {
		fprintf(stderr, "%s\n", err);	/* err 已带 "occ redo: " 前缀 */
		return 1;
	}
	printf("occ: redo session=%s restored=%zu unhidden=%zu\n",
	       id, r.nfiles, r.nmsgs_reverted);
	for (i = 0; i < r.nfiles; i++)
		printf("  %s%s\n", r.files[i].failed ? L_("[失败] ") : L_("[还原] "),
		       r.files[i].path);
	if (err[0])				/* 部分失败如实列出（err 已带前缀） */
		fprintf(stderr, "%s\n", err);
	occ_undo_result_free(&r);
	return 0;
}

/*
 * occ retry - 重发最后一条 user 消息（OCD §7.2 手动重试=中断后重发）。
 * 尾=user/tool 且状态 running/error/interrupted → 该尝试无 assistant
 * 产出：prompt=NULL 重放（原消息即尝试记录；避免连续 user——anthropic
 * 角色交替硬约束）。否则（尾=assistant / 状态 active）→ 原消息+新尝试
 * 双记录（loop 内折叠注记并 commit 撤销态）。
 */
static int cmd_retry(occ_db *db, occ_provider *p, const char *id)
{
	occ_session_row s;
	occ_msg_row last_user, last;
	char err[512];
	char *text = NULL;
	int has, hasl;
	int replay;
	int rc;

	if (occ_session_get(db, id, &s, err, sizeof(err)) != 1) {
		fprintf(stderr, "occ retry: session %s not found\n", id);
		return 1;
	}
	has = occ_msg_last_user(db, id, &last_user, err, sizeof(err));
	if (has < 0) {
		fprintf(stderr, "occ retry: %s\n", err);
		return 1;
	}
	if (has == 0) {
		fputs(L_("occ retry: 没有可重发的 user 消息\n"), stderr);
		return 1;
	}
	text = last_user.text ? strdup(last_user.text) : NULL;
	occ_msg_row_free(&last_user);
	if (!text) {
		fputs(L_("occ retry: 最后一条 user 消息为空\n"), stderr);
		return 1;
	}
	hasl = occ_msg_last(db, id, &last, err, sizeof(err));
	replay = hasl > 0 &&
		 (!strcmp(last.role, "user") || !strcmp(last.role, "tool")) &&
		 (!strcmp(s.status, OCC_ST_RUNNING) ||
		  !strcmp(s.status, OCC_ST_ERROR) ||
		  !strcmp(s.status, OCC_ST_INTERRUPTED));
	if (hasl > 0)
		occ_msg_row_free(&last);
	fprintf(stderr, "occ: retry session=%s mode=%s\n", id,
		replay ? "replay" : "re-send");
	rc = run_turn(db, p, id, replay ? NULL : text, 0);
	free(text);
	return rc;
}

/* P-48：轻量解僵——楔死/强杀后会话卡 status=running 挡 undo/retry。
 * occ --recover 可解但重放全上下文（TUI 全量 ~10.7k tokens）；本命令
 * 只把 running 归位 interrupted：上下文/token 原地保留，零重放零模型
 * 调用——occ retry 续跑、occ undo 即刻可用。幂等诚实：非 running 不
 * 改库、直言无需解僵。 */
static int cmd_unstuck(occ_db *db, const char *id)
{
	occ_session_row s;
	char err[160];

	if (occ_session_get(db, id, &s, err, sizeof(err)) != 1) {
		fprintf(stderr, L_("occ unstuck: 会话 %s 不存在（occ sessions 可查全部会话）\n"), id);
		return 1;
	}
	if (strcmp(s.status, OCC_ST_RUNNING)) {
		printf(L_("occ unstuck: 会话 %s 状态为 %s（非 running），无需解僵\n"), id, s.status);
		return 0;
	}
	if (occ_session_set_status(db, id, OCC_ST_INTERRUPTED,
				   err, sizeof(err)) != 0) {
		fprintf(stderr, L_("occ unstuck: 解僵失败：%s\n"), err);
		return 1;
	}
	printf(L_("occ unstuck: 会话 %s 已解僵（running→interrupted）：上下文/token 保留零重放；`occ retry --session %s` 续跑、`/undo` 现在可用\n"), id, id);
	return 0;
}

/* ---- T9c2 交互模式（全屏 TUI；headless 路径零改动） ---- */

/* T9c3 覆盖层 id（on_overlay_* 钩子按此分派） */
enum {
	OV_MODELS = 1,
	OV_SESSIONS = 2,
	OV_TOOLS = 3,
	OV_TRACE = 4,
	OV_LEASE = 5,
	OV_TASKS = 6,			/* E8：/tasks 任务面板 */
	OV_WIZ_MODEL = 11,		/* 向导 1/4 模型 */
	OV_WIZ_PROVIDER = 12,		/* 向导 2/4 provider */
	OV_WIZ_BASE = 13,		/* 向导 2.5 自定义 base_url（输入） */
	OV_WIZ_KEY = 14,		/* 向导 3/4 key（输入，mask） */
	OV_RENAME = 21,			/* /rename 无参（输入） */
	OV_W2 = TUI_VIEW_OV_W2,		/* O-9：W2 确认面板（worker 请求开；
					 * 值=tui_view.h 单源——view 侧 y/n
					 * 单键应答应答本面板，P-52 病①） */
	OV_SU = 23,			/* O-10：/su 密码输入（mask） */
	OV_UNDO_RECALL = 24		/* O-25：/undo 撤回输入回填（输入；
					 * Enter=重发即确认撤销） */
};

/* ov_map 值：SIZE_MAX=分组头（不可选）；OV_MAP_CUSTOM=向导自定义项 */
#define OV_MAP_NONE ((size_t)-1)
#define OV_MAP_CUSTOM ((size_t)-2)

/* 向导预设厂商（OPENCODE-PLAN §2.4「预设 5+自定义」） */
static const struct {
	const char *id;
	const char *display;
	const char *base;
	const char *ptype;		/* provider_type（occ 双协议） */
} WIZ_PRESET[] = {
	{ "openai", "OpenAI", "https://api.openai.com/v1",
	  "openai_compatible" },
	{ "anthropic", "Anthropic", "https://api.anthropic.com",
	  "anthropic" },
	{ "deepseek", "DeepSeek", "https://api.deepseek.com/v1",
	  "openai_compatible" },
	{ "google", "Google Gemini",
	  "https://generativelanguage.googleapis.com/v1beta/openai",
	  "openai_compatible" },
	{ "moonshot", "Moonshot (Kimi)", "https://api.moonshot.cn/v1",
	  "openai_compatible" }
};
#define WIZ_NPRESET ((int)(sizeof(WIZ_PRESET) / sizeof(WIZ_PRESET[0])))

struct tui_app {
	occ_db *db;
	occ_provider p;
	tui_view *view;
	pthread_t worker;
	int worker_live;		/* 双线程：worker 写（尾部），主线程读 */
	int worker_created;		/* 仅主线程（create/join 配对） */
	int shell_req;			/* T9e /shell：退屏跑 bash 后重建 view */
	uint64_t delete_arm;		/* O-12：/delete 双发确认窗（ms；10s 内再发生效） */
	char *prompt;			/* 本轮输入（主线程分配，worker 用） */
	char session_id[OCC_ID_LEN];	/* 当前会话；空=下条提交建新会话 */
	/* UXAB：顶栏缓存（title 由 worker/切换/改名写——mu 保护；
	 * model_prov 仅主线程，模型解析/切换后 app_update_model_prov 刷） */
	char session_title[128];
	char model_prov[48];
	long long tokens_total;		/* 会话累计计费额（/status 展示） */
	long long ctx_limit;		/* catalog limit.context；缺省 200k */
	int ctx_fallback;		/* 1=catalog 未命中/不可读 → 200k* */
	char cwd[4096];			/* 启动目录（workdir + 状态行） */
	int workdir_fb;			/* O-6：cwd 命中沙箱拒绝面→已回退
					 * /var/ai/work（首屏 notice 用；0=未回退） */
	pthread_mutex_t mu;		/* session/tokens/prompt/worker_live */
	/* O-9：W2 确认应答单槽（worker 问→view 面板应答；mu+w2_cond） */
	pthread_cond_t w2_cond;
	int w2_answered;
	int w2_verdict;
	/* O-10：/su 提权态（mu 保护；计数/冷却照 T4 gate 口径） */
	struct {
		int fails;
		long long cooldown_until;
		int elevated;
	} su;

	/* ---- c3：配置/目录/注册表（进程常驻；headless 不走此路径） ---- */
	char model_toml[512];
	char provider_toml[512];
	char state_path[512];		/* ~/.occ/state.json */
	occ_provider_config cfg;	/* 向导 reload + /models 切换用 */
	int cfg_ok;
	char cfg_warn[256];		/* O-3：首条坏段诊断（进首屏
					 * notice；空=配置全合法；诊断
					 * ≤192B+计数十余字余量） */
	occ_catalog *cat;		/* 惰性一次（ctx 分母 + 向导模型表） */
	int cat_tried;
	occ_registry *reg;		/* 惰性一次（/models）；保存后重建 */
	int reg_tried;

	/* ---- c3：五项 usage 同源缓存（元数据行与侧栏底部同一份） ---- */
	long long u_in, u_out, u_cr, u_cw;
	int u_est;

	/* ---- c3：密钥向导状态（key 只存这里与 model.toml，绝不外泄） ---- */
	struct {
		int step;			/* 0=未激活 */
		char model_id[OCC_CAT_ID_MAX];
		char display[OCC_CAT_NAME_MAX];
		char provider[OCC_CAT_PROVIDER_MAX];
		char base_url[OCC_PROVIDER_URL_MAX];
		char ptype[48];
		char slot[OCC_TOML_ID_MAX];
		long long ctx_limit;
		char key[256];
	} wiz;

	/* ---- OCC-DEBT：向导 4/4 验证 worker（异步——偿还 T9C3 取舍 4） ----
	 * 线程私有 ctx（含 key 拷贝）——wiz_reset/wiz.key 清零不影响在途调用；
	 * wiz_cancel 置位 + pthread_kill(SIGINT) = Esc 取消（EINTR 打断读）。 */
	pthread_t wiz_thread;
	int wiz_thread_live;		/* mu 保护 */
	int wiz_thread_created;		/* 仅主线程（create/join 配对） */
	int wiz_cancel;			/* mu 保护 */

	/* ---- B8：/rename 空题=AI 生成标题 worker（T9C3 取舍5 偿还） ----
	 * 与向导验证同手法：线程私有 ctx（provider 深拷贝）；生成期间主循环
	 * 自由渲染（busy spinner）；Esc=取消（SIGINT → EINTR → rc=2）。 */
	pthread_t ren_thread;
	int ren_thread_live;		/* mu 保护 */
	int ren_thread_created;		/* 仅主线程（create/join 配对） */
	int ren_cancel;			/* mu 保护 */

	/* ---- OCC-DEBT：/models 非对话条目显隐（默认过滤；ctrl+t 切换） ---- */
	int show_nonchat;

	/* ---- T2：长历史增量加载（转写区到顶 → 更大行预算重放） ----
	 * replay_budget=当前 occ_replay_plan 行预算（初值 OCC_REPLAY_LINES，
	 * 0=显式禁用）；replay_earlier=上次成功 plan 切掉的更早可见消息数；
	 * replay_ok=上次回放是否真跑成（busy 跳过/失败=0 → 下次到顶可补）；
	 * replay_mem_stop=1 已达 scrollback 内存上限（不再加载）；
	 * earliest_noticed/load_busy_noticed=提示节流（同一会话/同一 turn
	 * 只出一次，加载成功后重置）。 */
	int replay_budget;
	size_t replay_earlier;
	int replay_ok;
	int replay_mem_stop;
	int earliest_noticed;
	int load_busy_noticed;

	/* ---- c3：overlay 工作集（打开期间有效；换开重分配） ---- */
	size_t *ov_map;
	size_t ov_map_n;
	occ_session_row *ov_rows;	/* /sessions 行（提交期有效） */
	size_t ov_rows_n;

	/* ---- E8：/tasks 任务面板（OV_TASKS 工作集 + 异步进度轮询态） ---- */
	occ_task_row *ov_task_rows;	/* 面板行（打开期间有效；换开重分配） */
	size_t ov_task_rows_n;
	char tasks_fp[640];		/* 面板内容指纹（变化才重绘） */
};

static uint64_t tui_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* LT-BUG-005：会话标题按显示列截断（CJK 双宽安全，不在字节中间切出
 * U+FFFD）。通知/预填统一 40 列口径；id 段是纯 ASCII（ses_…），仍按
 * `%.14s` 字节截断（安全）。 */
static void app_clip_title(const char *src, char *dst, size_t cap)
{
	tui_utf8_clip_cols(src ? src : "", 40, dst, cap);
}

/* k/M 档：已由 tui_usage_fmt 承担（c3 同源化；fmt_tok 退役） */

/* ===================== OCC-DEBT：TUI 历史回放 =====================
 * 偿还 T9C2 裁定 2（转写不回放历史）：进屏（/shell 往返）与 /sessions
 * 切换时，从 durable SQLite 读当前会话消息 → occ_replay_plan 圈尾部
 * （OCD §1.3 尾部挂载语义；行预算 OCC_REPLAY_LINES 缺省 1000，0=禁）
 * → 逐条 tui_view_post 渲染进 scrollback。事件走既有队列，drain 在
 * 主循环——与 live 渲染完全同路（工具行/推理折叠/页脚形态不变）。
 * 运行中不回放（事件会插进 live 块）——诚实 notice，收口后切换可补。 */
static int app_replay_lines_budget(void)
{
	const char *v = getenv("OCC_REPLAY_LINES");
	long n;
	char *end = NULL;

	if (!v || !v[0])
		return 1000;
	n = strtol(v, &end, 10);
	if (!end || *end != '\0' || n < 0 || n > 1000000)
		return 1000;
	return (int)n;
}

/* T2：回放执行（进屏/切会话/到顶增量加载共用）。budget=occ_replay_plan
 * 行预算；成功时 *earlier_out=被切掉的更早可见消息数。返回 0=已投递
 * 全套事件（HIST_CLEAR→回放事件）；-1=跳过（busy/禁用）或失败——失败
 * 已出 notice（禁用静默），调用方不得更新锚点状态。 */
static int app_replay_run(struct tui_app *a, const char *sid, int clear_first,
			  int budget, size_t *earlier_out)
{
	occ_msg_row *rows = NULL;
	occ_tc_row *tcs = NULL;
	occ_replay_item *plan = NULL;
	size_t n = 0, ntc = 0, nplan = 0, nearlier = 0, i;
	char e[160];
	int live;

	if (!sid || !sid[0])
		return -1;
	pthread_mutex_lock(&a->mu);
	live = a->worker_live;
	pthread_mutex_unlock(&a->mu);
	if (live) {
		tui_view_notice(a->view,
				L_("replay: turn 运行中——历史回放跳过（收口后重进 /sessions 可补）"));
		return -1;
	}
	if (budget <= 0)
		return -1;			/* 显式禁用（静默——配置意图） */
	if (occ_msg_list(a->db, sid, &rows, &n, e, sizeof(e)) != 0) {
		tui_view_notice(a->view, e);
		return -1;
	}
	(void)occ_toolcalls_since(a->db, sid, 0, &tcs, &ntc, NULL, 0);
	if (occ_replay_plan(rows, n, tcs, ntc, budget, &plan, &nplan,
			    &nearlier) != 0) {
		occ_msg_rows_free(rows, n);
		occ_tc_rows_free(tcs, ntc);
		tui_view_notice(a->view, L_("replay: 规划失败（OOM）"));
		return -1;
	}
	if (clear_first)
		(void)tui_view_post(a->view, TUI_VIEW_HIST_CLEAR, NULL, 0,
				    NULL, 0);
	for (i = 0; i < nplan; i++) {
		const occ_replay_item *it = &plan[i];

		switch (it->kind) {
		case OCC_RP_SEP: {
			char sep[96];

			snprintf(sep, sizeof(sep),
				 L_("… 更早 %d 条消息未回放（尾部 %d 行挂载）"),
				 it->rc, budget);
			(void)tui_view_post(a->view, TUI_VIEW_HIST_SEP, sep,
					    0, NULL, 0);
			break;
		}
		case OCC_RP_USER:
			(void)tui_view_post(a->view, TUI_VIEW_HIST_USER,
					    it->text, strlen(it->text), NULL,
					    0);
			break;
		case OCC_RP_BEGIN:
			(void)tui_view_post(a->view, TUI_VIEW_HIST_BEGIN, NULL,
					    0, NULL, 0);
			break;
		case OCC_RP_REASON:
			(void)tui_view_post(a->view, TUI_VIEW_REASONING,
					    it->text, strlen(it->text), NULL,
					    0);
			break;
		case OCC_RP_TEXT:
			(void)tui_view_post(a->view, TUI_VIEW_TEXT, it->text,
					    strlen(it->text), NULL, 0);
			break;
		case OCC_RP_TOOL_START:
			(void)tui_view_post(a->view, TUI_VIEW_TOOL_START,
					    it->text, 0, it->arg, 0);
			break;
		case OCC_RP_TOOL_END:
			(void)tui_view_post(a->view, TUI_VIEW_TOOL_END,
					    it->text, 0, it->arg, it->rc);
			break;
		case OCC_RP_END:
			/* 回放页脚：如实标「回放」——DB 无时长/tok-s 数据，
			 * 不伪造 live 页脚的段值 */
			(void)tui_view_post(a->view, TUI_VIEW_TURN_END,
					    L_("OCC · 回放"), 0, NULL, 0);
			break;
		default:
			break;
		}
		/* T2：分段排空事件环——一套回放事件数可远超 TV_QMAX（512），
		 * 攒到最后会满队列等待（300ms/事件）并丢事件。每 128 个
		 * 计划项（≤256 事件）flush 一次，主线程就地应用到 chat 模型
		 * （不渲染；与后续事件同序）。 */
		if ((i & 0x7f) == 0x7f)
			(void)tui_view_flush(a->view);
	}
	(void)tui_view_flush(a->view);
	free(plan);
	occ_tc_rows_free(tcs, ntc);
	occ_msg_rows_free(rows, n);
	if (earlier_out)
		*earlier_out = nearlier;
	return 0;
}

/* 进屏/切会话：预算复位为 OCC_REPLAY_LINES 缺省；成功则记录 earlier
 * （到顶判定「还有更早」的唯一依据）。 */
static void app_replay_session(struct tui_app *a, const char *sid,
			       int clear_first)
{
	size_t earlier = 0;

	a->replay_budget = app_replay_lines_budget();
	a->replay_ok = 0;
	a->replay_mem_stop = 0;
	a->earliest_noticed = 0;
	if (app_replay_run(a, sid, clear_first, a->replay_budget,
			   &earlier) == 0) {
		a->replay_ok = 1;
		a->replay_earlier = earlier;
	}
}

/* T2 取证探针：OCC_T2_DEBUG_LOG=<path> 时追加一行加载流水（默认关、
 * 零 UI 影响）——自检「500 条钻证」记录 budget/渲染行/锚点用。 */
static void app_t2_dbg(const char *fmt, ...)
{
	const char *path = getenv("OCC_T2_DEBUG_LOG");
	va_list ap;
	FILE *f;

	if (!path || !path[0])
		return;
	f = fopen(path, "a");
	if (!f)
		return;
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fputc('\n', f);
	fclose(f);
}

/* T2：转写区到顶 → 增量加载更早历史。
 * 时序：取锚点（view_top 命中消息 id+偏移）→ 内存闸（渲染行折算）→
 * CLEAR + 更大预算全套回放事件 → HIST_ANCHOR（严格最后，view 据此
 * 还原视口）。返回 1=已发起；0=无更多/忙/内存上限/禁用（不滚动）。 */
static int tui_app_on_load_more(void *ud)
{
	struct tui_app *a = ud;
	struct tui_chat_scrollinfo si;
	char anchor[32];
	char nb[256];
	int off = 0;
	int live;
	int budget;
	int hard = TUI_CHAT_SB_CAP - 512;
	size_t earlier = 0;
	int have_anchor;

	if (!a->session_id[0])
		return 0;
	pthread_mutex_lock(&a->mu);
	live = a->worker_live;
	pthread_mutex_unlock(&a->mu);
	if (live) {
		if (!a->load_busy_noticed) {
			a->load_busy_noticed = 1;
			tui_view_notice(a->view,
					L_("加载更早历史：turn 运行中——收口后再按 PgUp"));
		}
		return 0;
	}
	if (a->replay_budget <= 0)
		return 0;			/* 显式禁用（静默） */
	if (a->replay_ok && a->replay_earlier == 0) {
		struct tui_chat_scrollinfo si;

		(void)tui_view_scroll_info(a->view, &si);
		app_t2_dbg("load budget=%d lines=%d earlier=0 result=earliest",
			   a->replay_budget, si.total);
		if (!a->earliest_noticed) {
			a->earliest_noticed = 1;
			tui_view_notice(a->view, L_("── 已到最早 ──"));
		}
		return 0;
	}
	if (a->replay_mem_stop)
		return 0;			/* 已提示过内存上限（节流） */
	/* 当前逐帧几何（渲染行数/视口）——内存闸与取证流水共用 */
	if (tui_view_scroll_info(a->view, &si) != 0)
		memset(&si, 0, sizeof(si));
	/* 内存闸：按当前「渲染行/预算」比折算新预算的渲染行；512 行余量
	 * 吸收块头/footer 等未纳入 occ_replay_est_lines 的行。超线即停并
	 * 诚实提示（更早 N 条仍可用 /sessions 看）。 */
	budget = a->replay_ok ? a->replay_budget + 1000 : a->replay_budget;
	if (a->replay_ok && a->replay_budget > 0 && si.total > 0) {
		long long proj = (long long)si.total * budget /
				 a->replay_budget;

		if (proj > hard) {
			a->replay_mem_stop = 1;
			snprintf(nb, sizeof(nb),
				 L_("── 已到内存上限（更早 %zu 条可用 /sessions 查看）──"), a->replay_earlier);
			tui_view_notice(a->view, nb);
			app_t2_dbg("load budget=%d lines_before=%d "
				   "earlier=%zu result=memcap",
				   a->replay_budget, si.total,
				   a->replay_earlier);
			return 0;
		}
	}
	have_anchor = tui_view_top_anchor(a->view, anchor, sizeof(anchor),
					  &off) == 0;
	app_t2_dbg("load budget=%d->%d lines_before=%d earlier_before=%zu "
		   "anchor=%s off=%d",
		   a->replay_budget, budget, si.total, a->replay_earlier,
		   have_anchor ? anchor : "-", off);
	if (app_replay_run(a, a->session_id, 1, budget, &earlier) != 0)
		return 0;
	a->replay_budget = budget;
	a->replay_earlier = earlier;
	a->replay_ok = 1;
	a->earliest_noticed = 0;	/* 新内容已入 → 到底提示可再出 */
	a->replay_mem_stop = 0;
	app_t2_dbg("load budget=%d earlier_after=%zu result=ok",
		   budget, earlier);
	(void)tui_view_post(a->view, TUI_VIEW_HIST_ANCHOR,
			    have_anchor ? anchor : "", 0, NULL, off);
	return 1;
}


/* SIGINT（进屏后覆盖 tui_sig_fatal）：仅置 b2 中断旗标。
 * sa_flags=0 → 无 SA_RESTART：阻塞读 EINTR 打断（b2 通路复用）。
 * headless 的双击强退不适用 TUI（raw 模式 Ctrl+C 是字节非信号）。 */
static void tui_on_sigint(int sig)
{
	(void)sig;
	occ_interrupt_flag = 1;
}

static void tui_app_on_entered(void *ud)
{
	struct tui_app *a = ud;
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = tui_on_sigint;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	/* OCC-DEBT 历史回放：进屏时已有当前会话（/shell 退屏往返）→ 从
	 * durable SQLite 回放尾部进 scrollback（T9C2 裁定 2 偿还）。
	 * 首次进屏无会话——保持「首条提交建新会话」（c2 语义不变）。 */
	if (a->session_id[0])
		app_replay_session(a, a->session_id, 0);
}

/* sink 回调（worker 线程）→ view 事件环（拷贝后返回） */
static void tui_sink_cb(void *ud, const occ_sink_ev *ev)
{
	tui_view *v = ud;

	(void)tui_view_post(v, ev->kind, ev->text, ev->len, ev->arg, ev->rc);
}

/* O-9（UX-O §2）：worker 侧 W2 确认——投 CONFIRM_REQ 事件后分片等
 * 应答（200ms 切片查 occ_interrupt_flag：SIGINT 不惊醒 cond_wait）；
 * 超时（OCC_W2_TIMEOUT_MS，缺省 5 分钟）=拒绝并投空事件收面板。 */
static int tui_w2_confirm(void *ud, const char *title, const char *detail)
{
	struct tui_app *a = ud;
	char payload[TUI_OV_TITLE_MAX + TUI_OV_DETAIL_MAX + 2];
	const char *env = getenv("OCC_W2_TIMEOUT_MS");
	long long timeout_ms = (env && atoll(env) > 0) ? atoll(env) :
			      300000;
	uint64_t t0;

	(void)title;
	snprintf(payload, sizeof(payload), "%.63s\n%.199s",
		 L_("W2 高危操作确认"), detail ? detail : "");
	pthread_mutex_lock(&a->mu);
	a->w2_answered = 0;
	a->w2_verdict = 0;
	pthread_mutex_unlock(&a->mu);
	if (!a->view || tui_view_post(a->view, TUI_VIEW_CONFIRM_REQ,
				      payload, strlen(payload), NULL,
				      OV_W2) != 0)
		return 0;		/* 视图关闭中=拒绝 */
	t0 = tui_now_ms();
	while (1) {
		struct timespec ts;
		int yes;

		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_nsec += 200 * 1000000L;
		if (ts.tv_nsec >= 1000000000L) {
			ts.tv_sec++;
			ts.tv_nsec -= 1000000000L;
		}
		pthread_mutex_lock(&a->mu);
		while (!a->w2_answered)
			if (pthread_cond_timedwait(&a->w2_cond, &a->mu,
						    &ts) != 0)
				break;	/* 超时/打断→外层复查 */
		yes = a->w2_verdict;
		pthread_mutex_unlock(&a->mu);
		if (a->w2_answered)
			return yes;
		if (occ_interrupt_flag)
			break;		/* b2 中断=拒绝 */
		if ((long long)(tui_now_ms() - t0) >= timeout_ms)
			break;		/* 超时=拒绝 */
	}
	/* 收面板（worker 已不等——面板留着只会误导） */
	if (a->view)
		(void)tui_view_post(a->view, TUI_VIEW_CONFIRM_REQ, "", 0,
				    NULL, OV_W2);
	return 0;
}

/* worker 线程：跑一个 turn，收口发 TURN_END（footer 按裁定 7 格式） */
static void *tui_worker_main(void *arg)
{
	struct tui_app *a = arg;
	occ_loop_opts opts;
	occ_loop_result res;
	char err[512];
	char footer[192];
	char sid[OCC_ID_LEN];
	uint64_t t0, t1;
	int rc;

	memset(&opts, 0, sizeof(opts));
	memset(&res, 0, sizeof(res));
	/* session 快照：/new 只影响下一轮，不撕本轮 */
	pthread_mutex_lock(&a->mu);
	snprintf(sid, sizeof(sid), "%s", a->session_id);
	opts.prompt = a->prompt;
	pthread_mutex_unlock(&a->mu);
	opts.sink.fn = tui_sink_cb;
	opts.sink.ud = a->view;
	opts.workdir = a->cwd;
	opts.orch = g_orch;			/* E3：task 工具执行面 */
	opts.w2 = &g_w2;			/* O-9：W2 门（TUI 交互确认） */

	t0 = tui_now_ms();
	rc = occ_loop_run(a->db, &a->p, sid[0] ? sid : NULL, &opts, &res,
			  err, sizeof(err));
	t1 = tui_now_ms();

	/* 会话/水位回写（/new 未动过才覆盖——防半途 /new 被撤销） */
	if (res.session_id[0]) {
		occ_session_row row;
		char e2[160];
		long long tok = 0;
		int have_row = 0;

		if (occ_session_get(a->db, res.session_id, &row, e2,
				    sizeof(e2)) == 1) {
			tok = row.tokens_total;
			have_row = 1;
		}
		pthread_mutex_lock(&a->mu);
		if (!a->session_id[0] || !strcmp(a->session_id, res.session_id)) {
			snprintf(a->session_id, sizeof(a->session_id), "%s",
				 res.session_id);
			a->tokens_total = tok;
			/* UXAB：首条消息建会话 → 顶栏标题即时可见 */
			if (have_row)
				snprintf(a->session_title,
					 sizeof(a->session_title), "%.95s",
					 row.title);
		}
		pthread_mutex_unlock(&a->mu);
	}
	/* c3：五项 usage 同源缓存（元数据行与侧栏底部都读这份；裁定 5）。
	 * 本轮无 usage 产出（早败）→ 保留旧值不清零。 */
	if (res.tokens.total > 0 || res.usage.present) {
		pthread_mutex_lock(&a->mu);
		a->u_in = res.tokens.input;
		a->u_out = res.tokens.output;
		a->u_cr = res.tokens.cache_read;
		a->u_cw = res.tokens.cache_write;
		a->u_est = res.tokens.est;
		pthread_mutex_unlock(&a->mu);
	}

	footer[0] = '\0';
	if (rc == OCC_LOOP_OK || rc == OCC_LOOP_ETOOLS) {
		if (res.interrupted) {
			(void)tui_view_post(a->view, TUI_VIEW_NOTICE,
					    L_("interrupted (safe point); status=interrupted — 下一条消息将自动附续传注记"), 0, NULL, 0);
			snprintf(footer, sizeof(footer), "OCC · interrupted");
		} else {
			/* P-30：TUI 出声（notice 进转写区；续发消息即收口） */
			if (res.steps_capped) {
				char nbuf[192];

				snprintf(nbuf, sizeof(nbuf),
					 L_("步数帽 %d 截断（rounds=%d）——工具链未收口；续发消息可直接收口"),
					 occ_loop_max_steps(), res.rounds);
				(void)tui_view_post(a->view, TUI_VIEW_NOTICE,
						    nbuf, 0, NULL, 0);
			}
			double secs = (double)(t1 - t0) / 1000.0;
			double tps = secs > 0.001 ?
				     (double)res.tokens.total / secs : 0.0;

			snprintf(footer, sizeof(footer),
				 "OCC · %s · %.1fs · %.1f tok/s",
				 a->p.model, secs, tps);
		}
	} else if (err[0]) {
		/* EARGS/ELLM：错误人话进转写区（TUI 不写 stderr 防污屏） */
		(void)tui_view_post(a->view, TUI_VIEW_NOTICE, err,
				    strlen(err), NULL, 0);
	}
	/* 先落 worker_live=0 再发 TURN_END：TURN_END 排空后用户立刻提交
	 * 不会撞上 busy 微闪（view.running 也在此前挡着） */
	pthread_mutex_lock(&a->mu);
	a->worker_live = 0;
	pthread_mutex_unlock(&a->mu);
	(void)tui_view_post(a->view, TUI_VIEW_TURN_END, footer,
			    strlen(footer), NULL, 0);
	occ_loop_result_free(&res);
	return NULL;
}

static int tui_app_on_submit(void *ud, const char *text, size_t len)
{
	struct tui_app *a = ud;
	int need_join;

	pthread_mutex_lock(&a->mu);
	if (a->worker_live) {
		pthread_mutex_unlock(&a->mu);
		return 1;		/* busy（view 亦有 running 门） */
	}
	pthread_mutex_unlock(&a->mu);

	need_join = a->worker_created;	/* 上轮已收口，join 瞬返 */
	if (need_join) {
		pthread_join(a->worker, NULL);
		a->worker_created = 0;
	}
	a->load_busy_noticed = 0;	/* T2：新 turn 可再提示一次 */
	pthread_mutex_lock(&a->mu);
	free(a->prompt);
	a->prompt = strndup(text, len);
	if (!a->prompt) {
		pthread_mutex_unlock(&a->mu);
		return -1;
	}
	occ_interrupt_flag = 0;		/* 新 turn 前清 b2 遗留旗标 */
	if (pthread_create(&a->worker, NULL, tui_worker_main, a) != 0) {
		free(a->prompt);
		a->prompt = NULL;
		pthread_mutex_unlock(&a->mu);
		return -1;
	}
	a->worker_live = 1;
	a->worker_created = 1;
	pthread_mutex_unlock(&a->mu);
	return 0;
}

static void tui_app_on_interrupt(void *ud)
{
	struct tui_app *a = ud;
	int live;

	occ_interrupt_flag = 1;		/* 先置旗：worker 安全点必见 */
	pthread_mutex_lock(&a->mu);
	live = a->worker_live;
	pthread_mutex_unlock(&a->mu);
	if (live)
		(void)pthread_kill(a->worker, SIGINT);	/* EINTR 打断读 */
}

/* ===================== T9c3：数据供给 / 向导 / 命令 ===================== */

/* ---- 惰性加载（进程内一次；headless 不走） ---- */

static int app_map_reserve(struct tui_app *a, size_t n)
{
	size_t *nm;

	if (n == 0)
		return 0;
	nm = realloc(a->ov_map, n * sizeof(*nm));
	if (!nm)
		return -1;
	a->ov_map = nm;
	a->ov_map_n = n;
	return 0;
}

/* /proc/self/exe 所在目录（数据文件 exe 锚定搜索链） */
static int exe_dir_of(char *buf, size_t cap)
{
	char tmp[4096];
	ssize_t n = readlink("/proc/self/exe", tmp, sizeof(tmp) - 1);
	char *slash;

	if (n <= 0)
		return -1;
	tmp[n] = '\0';
	slash = strrchr(tmp, '/');
	if (!slash)
		return -1;
	*slash = '\0';
	if (strlen(tmp) + 1 > cap)
		return -1;
	memcpy(buf, tmp, strlen(tmp) + 1);
	return 0;
}

/* ---- E8：headless `occ tasks`（ORCH §7；差分向量不含——新子命令，
 * occ -p 既有路径字节零变化） ---- */

/* 任务定价目录（进程惰性一次；搜索链同 app_load_catalog / tools.c
 * task_catalog：OCC_CATALOG → cwd → exe 目录 → 系统安装位） */
static occ_catalog *tasks_catalog(void)
{
	static occ_catalog cat;
	static int tried;
	char path[1100];
	char exed[1024];
	const char *env;

	if (tried)
		return &cat;
	tried = 1;
	env = getenv("OCC_CATALOG");
	if (env && env[0] && occ_catalog_load(&cat, env) == 0)
		return &cat;
	if (occ_catalog_load(&cat, "models.dev.snapshot.json") == 0)
		return &cat;
	if (exe_dir_of(exed, sizeof(exed)) == 0) {
		snprintf(path, sizeof(path), "%s/models.dev.snapshot.json",
			 exed);
		if (occ_catalog_load(&cat, path) == 0)
			return &cat;
	}
	if (occ_catalog_load(&cat,
			     "/usr/local/share/aikernel/models.dev.snapshot.json")
	    == 0)
		return &cat;
	return &cat;		/* 零值目录（nmodels=0）=无定价面 */
}

/*
 * task_priced - 预算定价参照（E7 budget_json 同源口径）：模型名取
 * 子会话 model 列（烧 token 的那一端）；目录命中 → 1（两单价+模型名
 * 写出）；未命中/无子会话 → 0（model[0]='\0'）。只读查询零写面。
 */
static int task_priced(occ_db *db, const occ_task_row *t, char *model,
		       size_t mcap, double *ipm, double *opm)
{
	model[0] = '\0';
	if (t->child_session[0]) {
		occ_session_row srow;

		if (occ_session_get(db, t->child_session, &srow, NULL, 0)
		    == 1)
			snprintf(model, mcap, "%s", srow.model);
	}
	if (!model[0])
		return 0;
	return occ_catalog_price(tasks_catalog(), model, ipm, opm) == 1;
}

/* 预算段文本（表格/面板 detail 共用）："12.3k/45.6k tok · $0.012345"
 * （cost_usd_ref 仅目录命中时追加——定价显示参考，§10 风险 6 口径） */
static void task_budget_str(occ_db *db, const occ_task_row *t,
			    char *buf, size_t cap)
{
	char ib[16], ob[16], model[96], cb[24];
	double ipm = 0.0, opm = 0.0;

	tui_usage_fmt(t->budget_in, ib, sizeof(ib));
	tui_usage_fmt(t->budget_out, ob, sizeof(ob));
	if (task_priced(db, t, model, sizeof(model), &ipm, &opm)) {
		snprintf(cb, sizeof(cb), "$%.6f",
			 occ_catalog_cost_usd(ipm, opm, t->budget_in,
					      t->budget_out));
		snprintf(buf, cap, "%s/%s tok · %s", ib, ob, cb);
	} else {
		snprintf(buf, cap, "%s/%s tok", ib, ob);
	}
}

/* occ tasks --json 单行（JSONL；budget 段字段名与 E7 tools.c
 * budget_json 同源——机读对账同口径）。0=已打印；-1=OOM（降级不炸） */
static int task_json_line(const occ_task_row *t, occ_db *db)
{
	aik_json *o, *b;
	char *dump = NULL;
	size_t dlen = 0;
	char cbuf[48], model[96];
	double ipm = 0.0, opm = 0.0;

	o = aik_json_new_obj();
	if (!o)
		return -1;
	if (aik_json_obj_put(o, "id", aik_json_new_str(t->id)) ||
	    aik_json_obj_put(o, "parent_session",
			     aik_json_new_str(t->parent_session)) ||
	    aik_json_obj_put(o, "child_session",
			     aik_json_new_str(t->child_session)) ||
	    aik_json_obj_put(o, "title", aik_json_new_str(t->title)) ||
	    aik_json_obj_put(o, "status", aik_json_new_str(t->status)) ||
	    aik_json_obj_put(o, "rework_count",
			     aik_json_new_int(t->rework_count)) ||
	    aik_json_obj_put(o, "rework_max",
			     aik_json_new_int(t->rework_max)) ||
	    aik_json_obj_put(o, "budget_in",
			     aik_json_new_int(t->budget_in)) ||
	    aik_json_obj_put(o, "budget_out",
			     aik_json_new_int(t->budget_out)) ||
	    aik_json_obj_put(o, "budget_total",
			     aik_json_new_int(t->budget_in + t->budget_out)) ||
	    aik_json_obj_put(o, "created", aik_json_new_int(t->created)) ||
	    aik_json_obj_put(o, "updated", aik_json_new_int(t->updated)))
		goto oom;
	b = aik_json_new_obj();
	if (!b)
		goto oom;
	if (aik_json_obj_put(b, "tokens_in",
			     aik_json_new_int(t->budget_in)) ||
	    aik_json_obj_put(b, "tokens_out",
			     aik_json_new_int(t->budget_out)))
		goto oom;
	if (task_priced(db, t, model, sizeof(model), &ipm, &opm)) {
		snprintf(cbuf, sizeof(cbuf), "%.6f",
			 occ_catalog_cost_usd(ipm, opm, t->budget_in,
					      t->budget_out));
		if (aik_json_obj_put(b, "model", aik_json_new_str(model)) ||
		    aik_json_obj_put(b, "unit",
				     aik_json_new_str("USD/1M")) ||
		    aik_json_obj_put(b, "in_per_m", aik_json_new_num(ipm)) ||
		    aik_json_obj_put(b, "out_per_m",
				     aik_json_new_num(opm)) ||
		    aik_json_obj_put(b, "cost_usd_ref",
				     aik_json_new_str(cbuf)))
			goto oom;
	} else if (aik_json_obj_put(b, "pricing",
				    aik_json_new_str("unavailable"))) {
		goto oom;
	}
	if (aik_json_obj_put(o, "budget", b)) {
		aik_json_free(b);
		goto oom;
	}
	if (aik_json_dump(o, &dump, &dlen) == 0 && dump) {
		printf("%s\n", dump);
		free(dump);
		aik_json_free(o);
		return 0;
	}
	free(dump);
	aik_json_free(o);
	return -1;
oom:
	aik_json_free(o);
	return -1;
}

/* occ tasks：表格式行（对齐；预算列含 cost_usd_ref 当目录命中）；
 * as_json=JSONL 机读。session 可 NULL（全部任务）。 */
static int cmd_tasks(occ_db *db, const char *session, int as_json)
{
	occ_task_row *rows = NULL;
	size_t n = 0, i;
	char e[160];

	if (occ_task_list_recent(db, session, 200, &rows, &n, NULL, NULL,
				 e, sizeof(e)) != 0) {
		fprintf(stderr, "occ tasks: %s\n", e);
		return 1;
	}
	if (as_json) {
		for (i = 0; i < n; i++)
			(void)task_json_line(&rows[i], db);
	} else {
		printf("%-38s %-24s %-11s %-6s %s\n", "ID", "TITLE",
		       "STATUS", "REWORK", "BUDGET IN/OUT");
		for (i = 0; i < n; i++) {
			char rw[8], bud[64], title_clip[96];
			int dim = !strcmp(rows[i].status, OCC_TASK_ST_DONE) ||
				  !strcmp(rows[i].status,
					  OCC_TASK_ST_ESCALATED);

			snprintf(rw, sizeof(rw), "%d/%d",
				 rows[i].rework_count, rows[i].rework_max);
			task_budget_str(db, &rows[i], bud, sizeof(bud));
			tui_utf8_clip_cols(rows[i].title, 22, title_clip,
					   sizeof(title_clip));
			printf("%-38s %-24s %-11s %-6s %s%s\n",
			       rows[i].id, title_clip, rows[i].status, rw,
			       bud, dim ? L_("  ·终态") : "");
		}
		printf("(%zu task%s)\n", n, n == 1 ? "" : "s");
	}
	occ_task_rows_free(rows, n);
	return 0;
}

static void app_load_catalog(struct tui_app *a)
{
	char path[1100];
	char exed[1024];
	const char *env;

	if (a->cat_tried)
		return;
	a->cat_tried = 1;
	a->cat = calloc(1, sizeof(*a->cat));
	if (!a->cat)
		return;
	env = getenv("OCC_CATALOG");
	if (env && env[0] && occ_catalog_load(a->cat, env) == 0)
		return;			/* 显式路径命中 */
	/* 搜索链：cwd → /proc/self/exe 目录 → 系统安装位（裁定 11） */
	if (occ_catalog_load(a->cat, "models.dev.snapshot.json") == 0)
		return;
	if (exe_dir_of(exed, sizeof(exed)) == 0) {
		snprintf(path, sizeof(path), "%s/models.dev.snapshot.json",
			 exed);
		if (occ_catalog_load(a->cat, path) == 0)
			return;
	}
	if (occ_catalog_load(a->cat,
			     "/usr/local/share/aikernel/models.dev.snapshot.json")
	    == 0)
		return;
	/* 全部失败：cat 保持零值 → ctx 兜底 200k*（fill_meta 标注） */
}

/* ctx 分母：catalog 命中=快照 context；否则 200k 兜底（OCD 未知窗口） */
static void app_resolve_ctx(struct tui_app *a)
{
	a->ctx_limit = 200000;
	a->ctx_fallback = 1;
	if (!a->cat || a->cat->nmodels == 0)
		return;
	{
		const occ_catalog_model *m =
			occ_catalog_find(a->cat, NULL, a->p.model);

		if (!m) {
			const occ_catalog_model *hits[4];
			size_t nh = occ_catalog_search(a->cat, a->p.model, 0,
						       hits, 4);

			if (nh >= 1)
				m = hits[0];
		}
		if (m && m->context_limit > 0) {
			a->ctx_limit = m->context_limit;
			a->ctx_fallback = 0;
		}
	}
}

static void app_load_reg(struct tui_app *a)
{
	if (a->reg_tried)
		return;
	a->reg_tried = 1;
	app_load_catalog(a);
	a->reg = calloc(1, sizeof(*a->reg));
	if (!a->reg)
		return;
	if (occ_registry_init(a->reg) != 0) {
		free(a->reg);
		a->reg = NULL;
		return;
	}
	occ_registry_build(a->reg, a->cfg_ok ? &a->cfg : NULL, a->cat);
	(void)occ_state_load(a->reg, a->state_path);
}

static void app_reg_rebuild(struct tui_app *a)
{
	if (!a->reg) {
		a->reg_tried = 0;
		app_load_reg(a);
		return;
	}
	/* build 为追加语义 → 先清空模型表（favorites/recents 字段不动） */
	a->reg->nmodels = 0;
	occ_registry_build(a->reg, a->cfg_ok ? &a->cfg : NULL, a->cat);
}

/* 会话切换：usage 缓存回读（最后一条带 usage 的 assistant；created 降序） */
static void app_load_usage_from_db(struct tui_app *a, const char *sid)
{
	occ_msg_row *rows = NULL;
	size_t n = 0, i;
	char e[160];

	pthread_mutex_lock(&a->mu);
	a->u_in = a->u_out = a->u_cr = a->u_cw = 0;
	a->u_est = 0;
	pthread_mutex_unlock(&a->mu);
	if (!sid || !sid[0])
		return;
	if (occ_msg_list(a->db, sid, &rows, &n, e, sizeof(e)) != 0)
		return;
	for (i = 0; i < n; i++) {
		if (strcmp(rows[i].role, "assistant") != 0)
			continue;
		if (!rows[i].usage_in && !rows[i].usage_out &&
		    !rows[i].usage_cache_read && !rows[i].usage_cache_write)
			continue;
		pthread_mutex_lock(&a->mu);
		a->u_in = rows[i].usage_in;
		a->u_out = rows[i].usage_out;
		a->u_cr = rows[i].usage_cache_read;
		a->u_cw = rows[i].usage_cache_write;
		a->u_est = rows[i].usage_est;
		pthread_mutex_unlock(&a->mu);
		break;			/* created 降序 → 首个即最新 */
	}
	occ_msg_rows_free(rows, n);
}

/* ---- 密钥向导（OPENCODE-PLAN §2.4 ≤4 步） ---- */

/* UXAB：顶栏厂商标签刷新（定义在 fill_meta 区——wiz_save 先用） */
static void app_update_model_prov(struct tui_app *a);

static void wiz_reset(struct tui_app *a)
{
	memset(&a->wiz, 0, sizeof(a->wiz));
}

static void wiz_slot_id(const char *prov, char *out, size_t cap)
{
	size_t i, j = 0;

	for (i = 0; prov && prov[i] && j + 1 < cap; i++) {
		unsigned char c = (unsigned char)prov[i];

		out[j++] = (isalnum(c) || c == '_' || c == '-') ?
			   (char)c : '_';
	}
	out[j] = '\0';
	if (!j)
		snprintf(out, cap, "custom");
	if (!strcmp(out, "cloud"))	/* cloud=主配置槽位，保留不覆盖 */
		snprintf(out, cap, "cloud_add");
}

static void wiz_err_human(const char *e, char *out, size_t cap)
{
	if (!e || !e[0]) {
		snprintf(out, cap, "%s", L_("验证失败（无错误文本）"));
		return;
	}
	if (strstr(e, "401") || strstr(e, "nauthorized") ||
	    strstr(e, "Invalid") || strstr(e, "invalid api"))
		snprintf(out, cap, "%s", L_("key 无效或未授权（401）——请检查 API key"));
	else if (strstr(e, "402") || strstr(e, "429") ||
		 strstr(e, "nsufficient") || strstr(e, "quota") ||
		 strstr(e, "balance") || strstr(e, "余额"))
		snprintf(out, cap, L_("额度/余额不足（%.140s）"), e);
	else if (strstr(e, "imeout") || strstr(e, "rc=28") ||
		 strstr(e, "ETIMEDOUT"))
		snprintf(out, cap,
			 L_("连接超时——检查 base_url/网络（%.140s）"), e);
	else if (strstr(e, "404") || strstr(e, "Not Found") ||
		 strstr(e, "not found"))
		snprintf(out, cap, "%s", L_("端点不存在（404）——检查 base_url"));
	else if (strstr(e, "400"))
		snprintf(out, cap,
			 L_("请求被拒（400）——模型名/参数不被接受（%.140s）"),
			 e);
	else
		snprintf(out, cap, "%.200s", e);
}

static void wiz_open_model(struct tui_app *a)
{
	tui_ov_item *items;
	size_t n = 0, cap, i;

	app_load_catalog(a);
	if (!a->cat || a->cat->nmodels == 0) {
		tui_view_notice(a->view,
				L_("models.dev 快照不可读——向导无法选模型（OCC_CATALOG 可指路径）"));
		return;
	}
	cap = a->cat->nmodels;
	items = calloc(cap, sizeof(*items));
	if (!items || app_map_reserve(a, cap) != 0) {
		free(items);
		tui_view_notice(a->view, L_("向导：内存不足"));
		return;
	}
	for (i = 0; i < cap; i++) {
		const occ_catalog_model *m = &a->cat->models[i];
		char ctx[24];

		if (!m->is_chat || m->is_deprecated)
			continue;
		if (m->context_limit > 0)
			tui_usage_fmt(m->context_limit, ctx, sizeof(ctx));
		else
			snprintf(ctx, sizeof(ctx), "?");
		snprintf(items[n].text, sizeof(items[n].text), "%s",
			 m->name[0] ? m->name : m->id);
		snprintf(items[n].tag, sizeof(items[n].tag), "%.44s",
			 m->provider_name[0] ? m->provider_name :
			 m->provider);
		snprintf(items[n].detail, sizeof(items[n].detail),
			 "%.48s/%.96s · ctx %s%s", m->provider, m->id, ctx,
			 m->reasoning ? " · reasoning" : "");
		items[n].flags = 0;
		a->ov_map[n] = i;
		n++;
	}
	if (n == 0) {
		free(items);
		tui_view_notice(a->view, L_("目录无可用 chat 模型"));
		return;
	}
	(void)tui_view_open_list(a->view, OV_WIZ_MODEL,
				 L_("add key · 1/4 模型"), items, (int)n, 1,
				 L_("输入过滤 · Enter=选择 · Esc=取消"));
	free(items);
}

static void wiz_open_provider(struct tui_app *a)
{
	tui_ov_item items[WIZ_NPRESET + 1];
	int order[WIZ_NPRESET];
	int i, k = 0, match = -1;

	a->wiz.step = 2;
	/* 模型厂商匹配的预设排第一（Enter 直取） */
	for (i = 0; i < WIZ_NPRESET; i++) {
		if (!strcmp(a->wiz.provider, WIZ_PRESET[i].id)) {
			match = i;
			break;
		}
	}
	if (match >= 0)
		order[k++] = match;
	for (i = 0; i < WIZ_NPRESET; i++) {
		if (i != match)
			order[k++] = i;
	}
	for (i = 0; i < k; i++) {
		int p = order[i];

		snprintf(items[i].text, sizeof(items[i].text), "%s",
			 WIZ_PRESET[p].display);
		snprintf(items[i].tag, sizeof(items[i].tag), "%s",
			 WIZ_PRESET[p].id);
		snprintf(items[i].detail, sizeof(items[i].detail), "%s%s",
			 WIZ_PRESET[p].base,
			 p == match ? L_("（模型厂商预设）") : "");
		items[i].flags = 0;
	}
	/* 自定义项 */
	snprintf(items[k].text, sizeof(items[k].text), "%s", L_("自定义 base_url…"));
	snprintf(items[k].tag, sizeof(items[k].tag), "custom");
	snprintf(items[k].detail, sizeof(items[k].detail),
		 "%s", L_("手动输入端点（协议按 openai 兼容）"));
	items[k].flags = 0;
	if (app_map_reserve(a, (size_t)k + 1) != 0) {
		tui_view_notice(a->view, L_("向导：内存不足"));
		return;
	}
	for (i = 0; i < k; i++)
		a->ov_map[i] = (size_t)order[i];
	a->ov_map[k] = OV_MAP_CUSTOM;
	{
		char title[160];

		snprintf(title, sizeof(title), "add key · 2/4 provider — %.60s",
			 a->wiz.display[0] ? a->wiz.display : a->wiz.model_id);
		(void)tui_view_open_list(a->view, OV_WIZ_PROVIDER, title,
					 items, k + 1, 0,
					 L_("Enter=选择 · Esc=取消"));
	}
}

static void wiz_open_base(struct tui_app *a)
{
	a->wiz.step = 2;
	(void)tui_view_open_input(a->view, OV_WIZ_BASE,
				  "add key · 2/4 base_url",
				  L_("端点 URL（https://…；协议按 openai 兼容）"),
				  a->wiz.base_url[0] ? a->wiz.base_url : NULL,
				  0);
}

static void wiz_open_key(struct tui_app *a)
{
	a->wiz.step = 3;
	(void)tui_view_open_input(a->view, OV_WIZ_KEY,
				  "add key · 3/4 API key",
				  L_("粘贴 key（掩码显示；仅写 model.toml 600，不入日志/报告）"), NULL, 1);
}

static void wiz_verify_cb(const occ_event *ev, void *ud)
{
	(void)ev;
	(void)ud;			/* 验证只看 rc/err，事件不消费 */
}

static void wiz_save(struct tui_app *a)
{
	occ_model_slot slot;
	char msg[512];

	memset(&slot, 0, sizeof(slot));
	snprintf(slot.id, sizeof(slot.id), "%s", a->wiz.slot);
	snprintf(slot.provider_type, sizeof(slot.provider_type), "%s",
		 a->wiz.ptype);
	slot.proto = occ_protocol_from_type(a->wiz.ptype);
	snprintf(slot.base_url, sizeof(slot.base_url), "%s",
		 a->wiz.base_url);
	snprintf(slot.model, sizeof(slot.model), "%.95s",
		 a->wiz.model_id);
	slot.api_key = a->wiz.key;	/* const 只读消费；不释放（数组） */
	if (occ_provider_toml_add_slot(a->model_toml, &slot) != 0) {
		tui_view_overlay_status(a->view,
					 L_("写入 model.toml 失败（值含非法字符/路径不可写？）"), 1);
		return;
	}
	/* reload cfg → 重建注册表 → 空闲则立即切换 */
	occ_provider_config_free(&a->cfg);
	occ_provider_config_init(&a->cfg);
	if (occ_provider_load_all(&a->cfg, a->model_toml, a->provider_toml)) {
		tui_view_overlay_status(a->view, L_("model.toml 重读失败"), 1);
		return;
	}
	a->cfg_ok = 1;
	app_reg_rebuild(a);
	if (!a->worker_live) {
		occ_provider np;

		if (occ_provider_resolve(&a->cfg, a->wiz.slot, &np) == 0) {
			occ_provider_free(&a->p);
			a->p = np;
			if (a->wiz.ctx_limit > 0) {
				a->ctx_limit = a->wiz.ctx_limit;
				a->ctx_fallback = 0;
			} else {
				a->ctx_limit = 200000;
				a->ctx_fallback = 1;
			}
			/* UXAB：顶栏厂商+块头模型标签随向导保存刷新 */
			app_update_model_prov(a);
			tui_view_set_assist_label(a->view, a->p.model);
		}
	}
	if (a->reg) {
		occ_registry_touch(a->reg, a->wiz.slot, a->wiz.model_id);
		(void)occ_state_save(a->reg, a->state_path);
	}
	snprintf(msg, sizeof(msg),
		 L_("已保存 key（model.toml 600）并切换到 %.80s（%s/%s）%s — 1-token 实测通过"),
		 a->wiz.display[0] ? a->wiz.display : a->wiz.model_id,
		 a->wiz.slot, a->wiz.model_id,
		 a->worker_live ? L_("；turn 运行中，下轮生效") : "");
	memset(a->wiz.key, 0, sizeof(a->wiz.key));
	tui_view_close_overlay(a->view);
	tui_view_notice(a->view, msg);
	wiz_reset(a);
}

/* ---- 向导 4/4：1-token 连通实测（OCC-DEBT 异步化——偿还 T9C3 取舍 4）
 * worker 线程跑 occ_llm_call（真调用——预算记账见报告；测试走 mock）；
 * 主线程自由渲染：busy spinner + Esc 取消（overlay.cancel → wiz_cancel
 * 置位 + pthread_kill SIGINT → 阻塞读 EINTR → 以取消态收口回投）。
 * 线程私有 ctx 深拷贝 provider/key——wiz_reset/wiz.key 清零互不影响。 */
struct wiz_vctx {
	struct tui_app *a;
	occ_provider vp;		/* api_key=heap 拷贝（线程私有） */
};

static void *wiz_verify_thread(void *arg)
{
	struct wiz_vctx *c = arg;
	occ_llm_req req;
	occ_msg msg;
	char *verr = NULL;
	int rc, cancel;

	memset(&req, 0, sizeof(req));
	req.proto = c->vp.proto;
	req.model = c->vp.model;
	memset(&msg, 0, sizeof(msg));
	msg.role = OCC_ROLE_USER;
	msg.text = "ping";
	req.msgs = &msg;
	req.nmsgs = 1;
	req.gen.max_tokens = 1;
	req.gen.has_max_tokens = 1;

	rc = occ_llm_call(&c->vp, &req, wiz_verify_cb, NULL, &verr);
	pthread_mutex_lock(&c->a->mu);
	cancel = c->a->wiz_cancel;
	pthread_mutex_unlock(&c->a->mu);
	if (rc == 0) {
		free(verr);
		(void)tui_view_post(c->a->view, TUI_VIEW_ASYNC_RESULT, NULL,
				    0, NULL, 0);
	} else if (cancel) {
		free(verr);
		(void)tui_view_post(c->a->view, TUI_VIEW_ASYNC_RESULT,
				    "cancelled", 0, NULL, 2);
	} else {
		/* 错误文本回投主线程人话化（text 转移所有权语义：post 拷贝） */
		(void)tui_view_post(c->a->view, TUI_VIEW_ASYNC_RESULT,
				    verr ? verr : "", 0, NULL, 1);
		free(verr);
	}
	free(c->vp.api_key);
	free(c);
	return NULL;
}

static void wiz_verify_save(struct tui_app *a)
{
	struct wiz_vctx *c;
	int live;

	/* 并发门：turn 运行中不验证——Esc 取消路径会置 occ_interrupt_flag
	 *（SIGINT 处理器全局），会误伤在途 turn；诚实留步。B8：标题生成
	 * 同入互斥门（SIGINT 全局旗标共享）。 */
	pthread_mutex_lock(&a->mu);
	live = a->worker_live || a->wiz_thread_live || a->ren_thread_live;
	pthread_mutex_unlock(&a->mu);
	if (live) {
		tui_view_overlay_status(a->view,
					a->worker_live ?
					L_("turn 运行中——Esc 中断或收口后再验证") :
					L_("验证已在进行中（Esc 取消）"), 1);
		return;
	}
	c = calloc(1, sizeof(*c));
	if (!c) {
		tui_view_overlay_status(a->view, L_("向导：内存不足"), 1);
		return;
	}
	c->a = a;
	snprintf(c->vp.name, sizeof(c->vp.name), "%s", a->wiz.slot);
	c->vp.proto = occ_protocol_from_type(a->wiz.ptype);
	snprintf(c->vp.base_url, sizeof(c->vp.base_url), "%s", a->wiz.base_url);
	snprintf(c->vp.model, sizeof(c->vp.model), "%.95s", a->wiz.model_id);
	c->vp.api_key = strdup(a->wiz.key[0] ? a->wiz.key : "");
	if (!c->vp.api_key) {
		free(c);
		tui_view_overlay_status(a->view, L_("向导：内存不足"), 1);
		return;
	}
	/* 清上一轮遗留中断旗标（取消路径经 SIGINT 处理器置位；llm_call
	 * 尝试前查旗标即中止——不清则重试永远失败。同 on_submit 口径） */
	occ_interrupt_flag = 0;
	a->wiz_cancel = 0;
	if (pthread_create(&a->wiz_thread, NULL, wiz_verify_thread, c) != 0) {
		free(c->vp.api_key);
		free(c);
		tui_view_overlay_status(a->view,
					L_("验证线程创建失败（稍后重试）"), 1);
		return;
	}
	pthread_mutex_lock(&a->mu);
	a->wiz_thread_live = 1;
	pthread_mutex_unlock(&a->mu);
	a->wiz_thread_created = 1;
	tui_view_overlay_status(a->view,
				L_("验证中…（1-token 实测，Esc 取消）"), 0);
	tui_view_set_busy(a->view, 1);	/* spinner 常刷 + Esc 改派 cancel */
}

/* ---- B8：/rename 空题=AI 生成标题（T9C3 取舍5 偿还） ----
 * 输入=会话首条 user 消息截断（≤512B UTF-8 边界）；调 occ_llm 既有接口
 * （occ_llm_call，一次性小请求 max_tokens=48）；输出清洗（单行、去成对
 * 包裹引号、≤48 字节 UTF-8 边界）后 occ_session_set_title 真改名。
 * 失败/取消诚实降级：面板留步可重试、标题不变（空题旧语义=不改名的
 * 安全侧）。busy 门：与 turn/向导验证互斥；生成期间主循环不阻塞
 * （worker 线程跑调用，view busy spinner 常刷——向导同手法）。
 * 线程安全：线程私有 ctx 深拷贝 provider+key，sid 快照；不改共享模块。 */

#define REN_TITLE_MAX 48		/* 输出标题字节上限（任务口径） */
#define REN_PROMPT_MAX 512		/* 首条 user 消息截断 */

struct ren_ctx {
	struct tui_app *a;
	occ_provider vp;		/* api_key=heap 拷贝（线程私有） */
	char sid[OCC_ID_LEN];
};

struct ren_acc {
	char buf[256];
	size_t len;
};

static void ren_collect_cb(const occ_event *ev, void *ud)
{
	struct ren_acc *acc = ud;
	size_t n;

	if (ev->type != OCC_EV_TEXT_DELTA || !ev->text)
		return;
	n = strlen(ev->text);
	if (acc->len + n >= sizeof(acc->buf))
		n = sizeof(acc->buf) - 1 - acc->len;
	if (n) {
		memcpy(acc->buf + acc->len, ev->text, n);
		acc->len += n;
		acc->buf[acc->len] = '\0';
	}
}

/* 清洗：首行；去首尾空白与成对包裹引号（「」『』"'）；≤48B UTF-8 边界。
 * 返回清洗后长度（0=空输出——调用方按失败降级）。 */
static size_t ren_sanitize(char *out, size_t cap, const char *in)
{
	static const struct { const char *l, *r; } QP[] = {
		{ "\xe3\x80\x8c", "\xe3\x80\x8d" },	/* 「」 */
		{ "\xe3\x80\x8e", "\xe3\x80\x8f" },	/* 『』 */
	};
	const char *p = in;
	size_t n, k;
	int i;

	while (*p == ' ' || *p == '\t')
		p++;
	n = strcspn(p, "\r\n");		/* 首行（无换行=全串） */
	while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t'))
		n--;
	/* 成对包裹引号剥离（一层；ASCII 对 + CJK 对） */
	if (n >= 2) {
		char c0 = p[0], cl = p[n - 1];

		if ((c0 == '"' && cl == '"') || (c0 == '\'' && cl == '\'')) {
			p++;
			n -= 2;
		}
	}
	for (i = 0; i < (int)(sizeof(QP) / sizeof(QP[0])); i++) {
		size_t ll = strlen(QP[i].l), rl = strlen(QP[i].r);

		if (n > ll + rl && memcmp(p, QP[i].l, ll) == 0 &&
		    memcmp(p + n - rl, QP[i].r, rl) == 0) {
			p += ll;
			n -= ll + rl;
			break;
		}
	}
	while (n > 0 && (p[0] == ' ' || p[0] == '\t')) {
		p++;
		n--;
	}
	if (n > REN_TITLE_MAX)
		n = REN_TITLE_MAX;
	while (n > 0 && ((unsigned char)p[n] & 0xC0) == 0x80)
		n--;			/* 截断回退到码点边界 */
	if (n >= cap)
		n = cap - 1;
	memcpy(out, p, n);
	out[n] = '\0';
	k = n;
	return k;
}

static void *ren_thread_main(void *arg)
{
	struct ren_ctx *c = arg;
	struct ren_acc acc;
	occ_llm_req req;
	occ_msg msg;
	occ_msg_row *rows = NULL;
	char first[REN_PROMPT_MAX + 8];
	char title[REN_TITLE_MAX + 8];
	char *err = NULL;
	char e[160];
	size_t n = 0, i;
	int rc, cancel, found = 0;

	memset(&acc, 0, sizeof(acc));
	memset(&req, 0, sizeof(req));
	memset(&msg, 0, sizeof(msg));
	first[0] = '\0';
	/* 首条 user 消息（升序首个非撤回；截断 UTF-8 边界） */
	if (occ_msg_list(c->a->db, c->sid, &rows, &n, e, sizeof(e)) == 0) {
		for (i = 0; i < n && !found; i++) {
			if (!strcmp(rows[i].role, "user") && !rows[i].reverted &&
			    rows[i].text && rows[i].text[0]) {
				size_t tl = strlen(rows[i].text);

				if (tl > REN_PROMPT_MAX) {
					tl = REN_PROMPT_MAX;
					while (tl > 0 &&
					       ((unsigned char)rows[i].text[tl]
						& 0xC0) == 0x80)
						tl--;	/* UTF-8 边界 */
				}
				memcpy(first, rows[i].text, tl);
				first[tl] = '\0';
				found = 1;
			}
		}
		occ_msg_rows_free(rows, n);
	}
	if (!found) {
		(void)tui_view_post(c->a->view, TUI_VIEW_ASYNC_RESULT,
				    L_("会话无 user 消息（无法生成标题）"), 0,
				    NULL, 1);
		goto out;
	}
	req.proto = c->vp.proto;
	req.model = c->vp.model;
	req.system = "根据用户会话的首条消息生成一个简短的会话标题。"
		     "只输出标题本身：单行纯文本，不超过 16 个字，"
		     "不要引号、句号或任何前后缀说明。";
	msg.role = OCC_ROLE_USER;
	msg.text = first;
	req.msgs = &msg;
	req.nmsgs = 1;
	req.gen.max_tokens = 48;
	req.gen.has_max_tokens = 1;

	rc = occ_llm_call(&c->vp, &req, ren_collect_cb, &acc, &err);
	pthread_mutex_lock(&c->a->mu);
	cancel = c->a->ren_cancel;
	pthread_mutex_unlock(&c->a->mu);
	if (rc != 0 && cancel) {
		free(err);
		(void)tui_view_post(c->a->view, TUI_VIEW_ASYNC_RESULT,
				    "cancelled", 0, NULL, 2);
	} else if (rc != 0) {
		(void)tui_view_post(c->a->view, TUI_VIEW_ASYNC_RESULT,
				    err ? err : "", 0, NULL, 1);
		free(err);
	} else if (ren_sanitize(title, sizeof(title), acc.buf) == 0) {
		(void)tui_view_post(c->a->view, TUI_VIEW_ASYNC_RESULT,
				    L_("模型未返回可用标题（空输出）"), 0, NULL, 1);
	} else {
		(void)tui_view_post(c->a->view, TUI_VIEW_ASYNC_RESULT, title,
				    0, NULL, 0);
	}
out:
	free(c->vp.api_key);
	free(c);
	return NULL;
}

static void ren_generate(struct tui_app *a)
{
	struct ren_ctx *c;
	int live;

	/* busy 门：turn/向导验证/生成中互斥（Esc 取消路径共用 SIGINT 全局
	 * 旗标，并发会误伤在途调用——诚实留步） */
	pthread_mutex_lock(&a->mu);
	live = a->worker_live || a->wiz_thread_live || a->ren_thread_live;
	pthread_mutex_unlock(&a->mu);
	if (live) {
		tui_view_overlay_status(a->view,
					a->worker_live ?
					L_("turn 运行中——收口后再生成标题") :
					L_("另一异步操作进行中（Esc 取消后再试）"),
					1);
		return;
	}
	if (!a->p.model[0]) {
		tui_view_overlay_status(a->view,
					L_("未配置模型——先 /models 或向导添加"), 1);
		return;
	}
	c = calloc(1, sizeof(*c));
	if (!c) {
		tui_view_overlay_status(a->view, L_("内存不足"), 1);
		return;
	}
	c->a = a;
	snprintf(c->sid, sizeof(c->sid), "%s", a->session_id);
	c->vp = a->p;				/* 字段拷贝（数组内联） */
	c->vp.api_key = strdup(a->p.api_key ? a->p.api_key : "");
	if (!c->vp.api_key) {
		free(c);
		tui_view_overlay_status(a->view, L_("内存不足"), 1);
		return;
	}
	/* 清上一轮遗留中断旗标（取消路径经 SIGINT 处理器置位——不清则
	 * llm_call 尝试前即中止；向导验证同口径） */
	occ_interrupt_flag = 0;
	a->ren_cancel = 0;
	if (pthread_create(&a->ren_thread, NULL, ren_thread_main, c) != 0) {
		free(c->vp.api_key);
		free(c);
		tui_view_overlay_status(a->view,
					L_("生成线程创建失败（稍后重试）"), 1);
		return;
	}
	pthread_mutex_lock(&a->mu);
	a->ren_thread_live = 1;
	pthread_mutex_unlock(&a->mu);
	a->ren_thread_created = 1;
	tui_view_overlay_status(a->view, L_("AI 生成标题中…（Esc 取消）"), 0);
	tui_view_set_busy(a->view, 1);
}

/* 异步结果回投（主循环 drain；TUI_VIEW_ASYNC_RESULT）——B8 起双工：
 * ren_thread_created=标题生成收口；否则向导验证（互斥门保证不并发） */
static void tui_app_on_async_result(void *ud, int rc, const char *text)
{
	struct tui_app *a = ud;

	if (a->ren_thread_created) {	/* B8：/rename AI 生成标题收口 */
		char e[160];
		char nb[320];

		pthread_join(a->ren_thread, NULL);
		a->ren_thread_created = 0;
		pthread_mutex_lock(&a->mu);
		a->ren_thread_live = 0;
		pthread_mutex_unlock(&a->mu);
		tui_view_set_busy(a->view, 0);
		if (rc == 0) {
			if (occ_session_set_title(a->db, a->session_id, text,
						  e, sizeof(e)) != 0) {
				tui_view_overlay_status(a->view, e, 1);
				return;
			}
			pthread_mutex_lock(&a->mu);
			snprintf(a->session_title, sizeof(a->session_title),
				 "%.95s", text);	/* UXAB：顶栏即时更新 */
			pthread_mutex_unlock(&a->mu);
			tui_view_close_overlay(a->view);
			snprintf(nb, sizeof(nb), "renamed → %.200s", text);
			tui_view_notice(a->view, nb);
			tui_view_refresh_sessions(a->view);	/* 侧栏标题 */
			return;
		}
		if (rc == 2) {
			tui_view_overlay_status(a->view,
						L_("已取消——可回车重试或 Esc 关闭"), 0);
			return;
		}
		snprintf(nb, sizeof(nb), L_("AI 生成标题失败：%.200s"),
			 text[0] ? text : L_("未知错误"));
		tui_view_overlay_status(a->view, nb, 1);
		return;
	}
	if (a->wiz_thread_created) {	/* 线程已发完结果：join 瞬返收尸 */
		pthread_join(a->wiz_thread, NULL);
		a->wiz_thread_created = 0;
	}
	pthread_mutex_lock(&a->mu);
	a->wiz_thread_live = 0;
	pthread_mutex_unlock(&a->mu);
	tui_view_set_busy(a->view, 0);
	if (rc == 0) {
		wiz_save(a);		/* 成功：写 toml + 切换 + 关面板 */
		return;
	}
	if (rc == 2) {
		/* 取消：留步可改 key 重试——与失败路径同语义（面板不关） */
		tui_view_overlay_status(a->view,
					L_("已取消——可修改 key 后回车重试"), 0);
		return;
	}
	{
		char human[240];

		wiz_err_human(text, human, sizeof(human));
		tui_view_overlay_status(a->view, human, 1);
	}
}

/* ---- /models 浏览器（registry 三方并集 + 分组 + 过滤） ---- */

static int cmd_models(struct tui_app *a)
{
	tui_ov_item *items;
	size_t *fav = NULL, *rec = NULL, *all = NULL;
	size_t nfav = 0, nrec = 0, nall = 0;
	size_t nmodels, cap, n = 0, i;
	int rc = 0;

	/* P-35：注册表空（无 model.toml 槽位且无 catalog 快照——离线
	 * 首装常态）不再静默自退：浮层照开、列 dim 提示行（空数据
	 * 即关=真机「卡一下→画面一闪→回主界面」根因；浮层开/关与
	 * Esc 语义不变）。registry 三查对 NULL reg 均零返回。 */
	app_load_reg(a);
	nmodels = a->reg ? a->reg->nmodels : 0;
	cap = nmodels + 130;	/* 分组头 + 提示行余量 */
	items = calloc(cap, sizeof(*items));
	fav = malloc((nmodels + 1) * sizeof(*fav));
	rec = malloc((nmodels + 1) * sizeof(*rec));
	all = malloc((nmodels + 1) * sizeof(*all));
	if (!items || !fav || !rec || !all ||
	    app_map_reserve(a, cap) != 0) {
		rc = -1;
		goto out;
	}
	nfav = occ_registry_favorites(a->reg, fav, nmodels);
	nrec = occ_registry_recents(a->reg, rec, nmodels);
	nall = occ_registry_all_by_provider(a->reg, 0, all, nmodels);

/* OCC-DEBT：非对话条目（is_chat==0）默认过滤；ctrl+t 显隐切换后
 * 显示时 dim + tag 标「非对话」（registry 三态位——目录 type 为主、
 * 配置位 id 特征；-1 未知不过滤不标注，宁缺勿错） */
#define PUSH_MODEL(RM) do { \
	if (a->show_nonchat || (RM)->is_chat != 0) { \
	if (n + 1 < cap) { \
		snprintf(items[n].text, sizeof(items[n].text), "%s", \
			 (RM)->display[0] ? (RM)->display : (RM)->id); \
		{ \
			int f = 0, q; \
			for (q = 0; q < (int)nfav; q++) { \
				if (fav[q] == \
				    (size_t)((RM) - a->reg->models)) { \
					f = 1; \
					break; \
				} \
			} \
			snprintf(items[n].tag, sizeof(items[n].tag), \
				 "%s%.36s%s", f ? "* " : "", \
				 (RM)->provider_name[0] ? \
				 (RM)->provider_name : (RM)->provider, \
				 (RM)->is_chat == 0 ? L_(" ·非对话") : ""); \
		} \
		{ \
			char ctx[24]; \
			if ((RM)->context_limit > 0) \
				tui_usage_fmt((RM)->context_limit, ctx, \
					      sizeof(ctx)); \
			else \
				snprintf(ctx, sizeof(ctx), "?"); \
			snprintf(items[n].detail, sizeof(items[n].detail), \
				 "%.32s/%.80s · ctx %s · %.40s", \
				 (RM)->provider, (RM)->id, ctx, \
				 (RM)->source == OCC_REG_SRC_TOML ? \
				 L_("配置（可直调）") : \
				 ((RM)->source == OCC_REG_SRC_OLLAMA ? \
				  L_("本地 ollama") : \
				  L_("目录（需 key：ctrl+a 添加）"))); \
		} \
		items[n].flags = ((RM)->is_deprecated || \
				  (RM)->is_chat == 0) ? TUI_OV_DIM : 0; \
		a->ov_map[n] = (size_t)((RM) - a->reg->models); \
		n++; \
	} \
	} \
} while (0)

#define PUSH_HEADER(HTXT) do { \
	if (n + 1 < cap) { \
		snprintf(items[n].text, sizeof(items[n].text), "%s", \
			 HTXT); \
		items[n].tag[0] = '\0'; \
		items[n].detail[0] = '\0'; \
		items[n].flags = TUI_OV_HEADER; \
		a->ov_map[n] = OV_MAP_NONE; \
		n++; \
	} \
} while (0)

/* P-35：dim 提示行（不可选语义——ov_map=NONE；P-42 起加 TUI_OV_NOSEL：
 * 初始光标/导航/回车一律跳过，光标直接落首个可选模型条目——旧形态
 * 首行置光标、首回车必得「该条目不可用」） */
#define PUSH_NOTE(NTXT) do { \
	if (n + 1 < cap) { \
		snprintf(items[n].text, sizeof(items[n].text), "%s", \
			 NTXT); \
		items[n].tag[0] = '\0'; \
		items[n].detail[0] = '\0'; \
		items[n].flags = TUI_OV_DIM | TUI_OV_NOSEL; \
		a->ov_map[n] = OV_MAP_NONE; \
		n++; \
	} \
} while (0)

	/* P-35：catalog 缺失（离线/未装快照）= 浮层内一行 dim 提示，
	 * 绝不因此退出浮层、绝不阻塞（加载链纯本地，无网络取数） */
	if (!a->cat || a->cat->nmodels == 0) {
		if (nmodels == 0)
			PUSH_NOTE(L_("无模型——model.toml 未配置且 catalog 快照未配置（离线）；先配置 model.toml"));
		else
			PUSH_NOTE(L_("catalog 快照未配置，仅显示已配置模型"));
	}
	if (nfav) {
		PUSH_HEADER("Favorites");
		for (i = 0; i < nfav && n + 1 < cap; i++) {
			if (fav[i] < nmodels)
				PUSH_MODEL(&a->reg->models[fav[i]]);
		}
	}
	if (nrec) {
		PUSH_HEADER("Recent");
		for (i = 0; i < nrec && n + 1 < cap; i++) {
			if (rec[i] < nmodels)
				PUSH_MODEL(&a->reg->models[rec[i]]);
		}
	}
	/* 按厂商分组（all 已按 provider 字典序） */
	{
		const char *cur = NULL;

		for (i = 0; i < nall && n + 2 < cap; i++) {
			const occ_reg_model *m =
				&a->reg->models[all[i]];

			if (!cur || strcmp(cur, m->provider) != 0) {
				cur = m->provider;
				PUSH_HEADER(m->provider_name[0] ?
					    m->provider_name : m->provider);
			}
			if (n + 1 < cap)
				PUSH_MODEL(m);
		}
	}
#undef PUSH_HEADER
#undef PUSH_MODEL
	if (n == 0) {
		/* 全量被非对话过滤掏空：浮层内 dim 说明（P-35：不再
		 * 静默不开——诚实说明而非谎报 OOM，也不退浮层） */
		PUSH_NOTE(L_("匹配条目全部为非对话（默认隐藏）——ctrl+t 显示全部"));
	}
#undef PUSH_NOTE
	(void)tui_view_open_list(a->view, OV_MODELS, "models", items,
				 (int)n, 1,
				 L_("Enter=切换/接入 · ctrl+a key · ctrl+f * · ctrl+t 非对话 · 过滤 · Esc=关闭"));
out:
	if (rc != 0)
		tui_view_notice(a->view, L_("models: 构建列表失败（OOM）"));
	free(items);
	free(fav);
	free(rec);
	free(all);
	return 0;
}

/* ---- /sessions 覆盖层（c2 notice 列表退役——裁定 10） ---- */

static int cmd_sessions_overlay(struct tui_app *a)
{
	tui_ov_item *items;
	occ_session_row *rows = NULL;
	size_t n = 0, i;
	char e[160];

	if (occ_session_list(a->db, &rows, &n, e, sizeof(e)) != 0) {
		tui_view_notice(a->view, e);
		return 0;
	}
	if (n == 0) {
		tui_view_notice(a->view, "(no sessions)");
		free(rows);
		return 0;
	}
	free(a->ov_rows);
	a->ov_rows = rows;
	a->ov_rows_n = n;
	items = calloc(n, sizeof(*items));
	if (!items) {
		tui_view_notice(a->view, "sessions: OOM");
		return 0;
	}
	for (i = 0; i < n; i++) {
		char ctx[24];

		tui_usage_fmt(rows[i].tokens_total, ctx, sizeof(ctx));
		snprintf(items[i].text, sizeof(items[i].text), "%.120s",
			 rows[i].title[0] ? rows[i].title : "(untitled)");
		snprintf(items[i].tag, sizeof(items[i].tag), "%s",
			 rows[i].status);
		snprintf(items[i].detail, sizeof(items[i].detail),
			 "%s · %s tok%s · %s", rows[i].id, ctx,
			 rows[i].tokens_est ? "~" : "",
			 rows[i].model);
		items[i].flags = 0;
	}
	(void)tui_view_open_list(a->view, OV_SESSIONS, "sessions", items,
				 (int)n, 1,
				 L_("Enter=切换并回放历史 · Esc=关闭"));
	free(items);		/* overlay 已深拷贝；行数据留 ov_rows 待提交 */
	return 0;
}

/* ---- E8：/tasks 任务面板（ORCH §7；R3 验收动作在面板内） ----
 * 任务行=status 着色（终态 done/escalated=DIM muted，活跃态正常+
 * tag=status 右对齐）+ 预算段（tokens in/out + cost_usd_ref 当目录
 * 命中——E7 定价消费同源）；标题带在跑计数；打开/1s 轮询刷新共用。 */

/* 面板内容指纹（djb2 累加：计数+各行 id·status·updated·预算——任一
 * 变化即指纹变；用于轮询判「变化才重绘」，避免每帧读库/闪烁） */
static unsigned long long tasks_fingerprint(const occ_task_row *rows,
					    size_t n, int total, int running)
{
	unsigned long long h = 5381;
	size_t i;

	h = h * 33 + (unsigned long long)(unsigned)total + 1;
	h = h * 33 + (unsigned long long)(unsigned)running + 1;
	for (i = 0; i < n; i++) {
		const char *p;

		for (p = rows[i].id; *p; p++)
			h = h * 33 + (unsigned char)*p;
		for (p = rows[i].status; *p; p++)
			h = h * 33 + (unsigned char)*p;
		h = h * 33 + (unsigned long long)rows[i].updated + 1;
		h = h * 33 + (unsigned long long)rows[i].budget_in;
		h = h * 33 + (unsigned long long)rows[i].budget_out;
	}
	return h;
}

static int cmd_tasks_overlay(struct tui_app *a)
{
	tui_ov_item *items;
	occ_task_row *rows = NULL;
	size_t n = 0, i;
	int total = 0, running = 0;
	char e[160];
	char title[TUI_OV_TITLE_MAX];

	if (occ_task_list_recent(a->db, NULL, 100, &rows, &n,
				 &total, &running, e, sizeof(e)) != 0) {
		tui_view_notice(a->view, e);
		return 0;
	}
	if (n == 0) {
		tui_view_notice(a->view, "(no tasks)");
		occ_task_rows_free(rows, n);
		return 0;
	}
	occ_task_rows_free(a->ov_task_rows, a->ov_task_rows_n);
	a->ov_task_rows = rows;		/* 行数据留提交期（同 ov_rows 口径） */
	a->ov_task_rows_n = n;
	items = calloc(n, sizeof(*items));
	if (!items) {
		tui_view_notice(a->view, "tasks: OOM");
		return 0;
	}
	snprintf(a->tasks_fp, sizeof(a->tasks_fp), "%016llx",
		 tasks_fingerprint(rows, n, total, running));
	for (i = 0; i < n; i++) {
		char bud[64];
		int term = !strcmp(rows[i].status, OCC_TASK_ST_DONE) ||
			   !strcmp(rows[i].status, OCC_TASK_ST_ESCALATED);

		snprintf(items[i].text, sizeof(items[i].text), "%.120s",
			 rows[i].title[0] ? rows[i].title : "(untitled)");
		snprintf(items[i].tag, sizeof(items[i].tag), "%s",
			 rows[i].status);
		task_budget_str(a->db, &rows[i], bud, sizeof(bud));
		snprintf(items[i].detail, sizeof(items[i].detail),
			 "%s · rew %d/%d · %s", rows[i].id,
			 rows[i].rework_count, rows[i].rework_max, bud);
		items[i].flags = term ? TUI_OV_DIM : 0;
	}
	if (running > 0)
		snprintf(title, sizeof(title), L_("tasks · 跑 %d"), running);
	else
		snprintf(title, sizeof(title), "tasks");
	(void)tui_view_open_list(a->view, OV_TASKS, title, items, (int)n, 1,
				 L_("Enter=验收提示(in_review) · Esc=关闭 · 面板 1s 自动刷新"));
	free(items);		/* overlay 已深拷贝；行数据留 ov_task_rows */
	return 0;
}

/*
 * E8：面板异步进度——主循环 on_tick 驱动 1s 节流读库；指纹（在跑数/
 * 总数/各行 status·updated·预算）变化才重建面板内容，无变化零重绘
 * （不为刷新而刷新——每帧读库被双重排除：tick 节流+指纹比对）。
 * 面板未开/非 OV_TASKS=纯 no-op（轮询开销=一次 id 查询）。
 */
static void tui_app_on_tick(void *ud)
{
	struct tui_app *a = ud;
	occ_task_row *rows = NULL;
	size_t n = 0;
	int total = 0, running = 0;
	char e[160];
	char fp[24];

	if (!tui_view_overlay_open(a->view) ||
	    tui_view_overlay_id(a->view) != OV_TASKS)
		return;
	if (occ_task_list_recent(a->db, NULL, 100, &rows, &n, &total,
				 &running, e, sizeof(e)) != 0)
		return;			/* 读失败保持现面板（不闪错） */
	snprintf(fp, sizeof(fp), "%016llx",
		 tasks_fingerprint(rows, n, total, running));
	occ_task_rows_free(rows, n);	/* 轻读只为指纹；变化才全量重开 */
	if (!strcmp(fp, a->tasks_fp))
		return;
	cmd_tasks_overlay(a);		/* 变化 → 重建（dirty 自置重绘） */
}

/* ---- /tools /trace /lease（读系统现成数据；裁定 8） ---- */

static int cmd_tools(struct tui_app *a)
{
	char path[1024];
	char e[240];
	tui_ov_item *items = NULL;
	int n = 0;

	if (tui_data_tools_path(path, sizeof(path)) != 0) {
		tui_view_notice(a->view,
				L_("tools.json 未找到——搜索链 AIKERNEL_TOOLS_JSON → ./tools.json → tools/tools.json → exe 目录 → /usr/local/share/aikernel/tools.json"));
		return 0;
	}
	if (tui_data_tools_load(path, &items, &n, e, sizeof(e)) != 0) {
		tui_view_notice(a->view, e);
		return 0;
	}
	(void)tui_view_open_list(a->view, OV_TOOLS, "tools", items, n, 1,
				 L_("↑↓/PgUp/PgDn 导航 · Enter=详情行 · Esc=关闭"));
	tui_data_items_free(items);
	return 0;
}

static int cmd_trace(struct tui_app *a)
{
	char dir[1024];
	char e[240];
	tui_ov_item *items = NULL;
	int n = 0;

	if (tui_data_trace_dir(dir, sizeof(dir)) != 0) {
		tui_view_notice(a->view, L_("trace: 无 HOME/OCC_TRACE_DIR"));
		return 0;
	}
	if (tui_data_trace_load(dir, 200, &items, &n, e, sizeof(e)) != 0) {
		tui_view_notice(a->view, e);
		return 0;
	}
	if (n == 0) {
		tui_view_notice(a->view,
				L_("（无 trace 记录——工具执行审计落 ~/.occ/trace）"));
		tui_data_items_free(items);
		return 0;
	}
	(void)tui_view_open_list(a->view, OV_TRACE, L_("trace（最近 200 条，新在前）"), items, n, 0,
				 L_("Enter=详情（args）· Esc=关闭"));
	tui_data_items_free(items);
	return 0;
}

static int cmd_lease(struct tui_app *a)
{
	char dir[1024];
	char e[240];
	tui_ov_item *items = NULL;
	int n = 0;

	if (tui_data_lease_dir(dir, sizeof(dir)) != 0) {
		tui_view_notice(a->view, L_("lease: 路径解析失败"));
		return 0;
	}
	if (tui_data_lease_load(dir, &items, &n, e, sizeof(e)) != 0) {
		tui_view_notice(a->view, e);
		return 0;
	}
	if (n == 0) {
		char nb[448];

		snprintf(nb, sizeof(nb),
			 L_("（无租约——目录 %.300s 为空/不存在；签发走系统命令，occ 只读展示）"), dir);
		tui_view_notice(a->view, nb);
		tui_data_items_free(items);
		return 0;
	}
	(void)tui_view_open_list(a->view, OV_LEASE, "lease", items, n, 0,
				 L_("Enter=详情（mission/scope）· Esc=关闭"));
	tui_data_items_free(items);
	return 0;
}

/* ---- /sandbox 只读探测（occ_tools 未导出状态 API——occ 自探，不改兄弟目录） ---- */

static int sb_find_bin(char *out, size_t cap)
{
	static const char *const envs[] = {
		"OCC_SANDBOX_BIN", "AIKERNEL_SANDBOX_BIN", NULL
	};
	const char *path;
	int i;

	for (i = 0; envs[i]; i++) {
		const char *v = getenv(envs[i]);

		if (v && v[0]) {
			snprintf(out, cap, "%s", v);
			return access(v, X_OK) == 0 ? 0 : -1;
		}
	}
	path = getenv("PATH");
	if (path) {
		char buf[4096];
		char *save = NULL;
		char *tok;

		snprintf(buf, sizeof(buf), "%s", path);
		for (tok = strtok_r(buf, ":", &save); tok;
		     tok = strtok_r(NULL, ":", &save)) {
			char cand[600];

			snprintf(cand, sizeof(cand), "%s/aik-sandbox", tok);
			if (access(cand, X_OK) == 0) {
				snprintf(out, cap, "%s", cand);
				return 0;
			}
		}
	}
	snprintf(out, cap, "%s", "/usr/local/bin/aik-sandbox");
	return access(out, X_OK) == 0 ? 0 : -1;
}

/* --occ-probe：输出含 --rw-path 即支持（sandbox.c 同判定）。返回 0=exec
 * 成功且读到输出；-1=exec 失败/超时（*sup=-1 未知）。5s 上限，防挂屏。 */
static int sb_probe(const char *bin, char *out, size_t cap, int *sup)
{
	int pfd[2];
	pid_t pid;
	size_t off = 0;
	int st = 0;
	int i;

	*sup = -1;
	out[0] = '\0';
	if (pipe(pfd) != 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDONLY);

		close(pfd[0]);
		if (devnull >= 0) {
			(void)dup2(devnull, STDIN_FILENO);
			close(devnull);
		}
		(void)dup2(pfd[1], STDOUT_FILENO);
		(void)dup2(pfd[1], STDERR_FILENO);
		close(pfd[1]);
		execl(bin, bin, "--occ-probe", (char *)NULL);
		_exit(127);
	}
	close(pfd[1]);
	/* 读 ≤5s（poll 轮询）；子进程应即刻退出 */
	for (i = 0; i < 500 && off + 1 < cap; i++) {
		struct pollfd p;
		int r;
		ssize_t got;

		p.fd = pfd[0];
		p.events = POLLIN;
		p.revents = 0;
		r = poll(&p, 1, 100);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (r == 0)
			break;		/* 100ms 静默 → 认为输出结束 */
		got = read(pfd[0], out + off, cap - 1 - off);
		if (got <= 0)
			break;
		off += (size_t)got;
	}
	out[off] = '\0';
	close(pfd[0]);
	/* 收尸（再等 ≤2s，超时 SIGKILL——夹具注入授权范围内） */
	for (i = 0; i < 20; i++) {
		pid_t w = waitpid(pid, &st, WNOHANG);

		if (w == pid)
			break;
		(void)poll(NULL, 0, 100);
	}
	if (i == 20) {
		kill(pid, SIGKILL);
		(void)waitpid(pid, &st, 0);
		return -1;
	}
	if (WIFEXITED(st) && WEXITSTATUS(st) == 127)
		return -1;		/* exec 失败（找不到/不可执行） */
	*sup = strstr(out, "--rw-path") ? 1 : 0;
	return 0;
}

static int cmd_sandbox(struct tui_app *a)
{
	char bin[600];
	char probe[4096];
	char nb[1024];
	int found, sup = -1;

	found = sb_find_bin(bin, sizeof(bin)) == 0;
	if (found)
		(void)sb_probe(bin, probe, sizeof(probe), &sup);
	snprintf(nb, sizeof(nb),
		 L_("sandbox: %.200s\n  二进制: %.200s%s\n  --rw-path 探测: %s\n  euid=%d（0=可组装 namespace；非 0=沙箱将拒绝裸跑）\n  写面: cwd 子树 ∪ /tmp ∪ /var/ai（~/.occ 拒绝）· 快照: ~/.occ/snapshots"),
		 found ? bin : L_("(未找到)"),
		 bin, found ? "" : L_("（不可执行/缺失）"),
		 sup == 1 ? L_("支持") : sup == 0 ?
		 L_("不支持（版本过旧——重建 aik-sandbox）") :
		 L_("不可执行"),
		 (int)geteuid());
	tui_view_notice(a->view, nb);
	return 0;
}

/* ---- /rename（带参真改名；无参输入框——OCD 空标题 AI 生成归后续棒） ---- */

static int cmd_rename(struct tui_app *a, const char *args)
{
	char e[160];
	char nb[320];

	while (*args == ' ' || *args == '\t')
		args++;
	if (*args) {
		if (!a->session_id[0]) {
			tui_view_notice(a->view,
					L_("尚无会话——先发一条消息再 /rename"));
			return 0;
		}
		if (occ_session_set_title(a->db, a->session_id, args, e,
					  sizeof(e)) != 0) {
			tui_view_notice(a->view, e);
			return 0;
		}
		{
			char tt[128];

			app_clip_title(args, tt, sizeof(tt));
			snprintf(nb, sizeof(nb), "renamed → %s", tt);
			tui_view_notice(a->view, nb);
		}
		return 0;
	}
	/* 无参：输入覆盖层（预填现题；B5/B8 起：空回车=AI 生成标题） */
	{
		char initial[128];

		initial[0] = '\0';
		if (a->session_id[0]) {
			occ_session_row r;

			if (occ_session_get(a->db, a->session_id, &r, e,
					    sizeof(e)) == 1) {
				char tt[128];

				app_clip_title(r.title, tt, sizeof(tt));
				snprintf(initial, sizeof(initial), "%s", tt);
			}
		}
		(void)tui_view_open_input(a->view, OV_RENAME, "rename",
					  L_("新标题（Enter 提交；空=AI 生成）"),
					  initial[0] ? initial : NULL, 0);
	}
	return 0;
}

/* ---- slash 命令分派 ---- */

/* T4：/theme 热重载请求 + /zoom 退出码 70（外层包装重启 fbterm+occ） */
static int g_t4_theme_req;
static int g_t4_exit_code;


/* T4 /theme：列出/切换内嵌预置主题（写 theme.ini + 重建 view 热重载） */
static int cmd_theme(struct tui_app *a, const char *arg)
{
	char path[512], name[64], msg[512];
	const char *home = getenv("HOME");
	const char *env = getenv("OCC_THEME");
	const struct tui_theme_preset *p;
	int i, n, off;

	if (env && env[0])
		snprintf(path, sizeof(path), "%s", env);
	else
		snprintf(path, sizeof(path), "%s/.occ/theme.ini",
			 home && home[0] ? home : "/root");
	while (*arg == ' ')
		arg++;
	if (!*arg) {
		if (tui_theme_current_preset(path, name, sizeof(name)) != 0)
			snprintf(name, sizeof(name), "default");
		off = snprintf(msg, sizeof(msg), L_("当前主题：%s。可选："), name);
		for (i = 0; off > 0 && off < (int)sizeof(msg) - 40; i++) {
			p = tui_theme_preset_at(i);
			if (!p)
				break;
			n = snprintf(msg + off, sizeof(msg) - off, " %s(%s)",
				     p->name, L_(p->desc));
			if (n < 0 || (size_t)(off + n) >= sizeof(msg) - 4)
				break;
			off += n;
		}
		tui_view_notice(a->view, msg);
		return 0;
	}
	p = tui_theme_preset_find(arg);
	if (!p) {
		snprintf(msg, sizeof(msg), L_("未知主题「%s」——/theme 查看可选"), arg);
		tui_view_notice(a->view, msg);
		return 0;
	}
	if (tui_theme_write_ini(path, p) != 0) {
		tui_view_notice(a->view, L_("写 theme.ini 失败（权限/磁盘）"));
		return 0;
	}
	g_t4_theme_req = 1;
	snprintf(msg, sizeof(msg), L_("主题已切换：%s——界面重载中…"), p->name);
	tui_view_notice(a->view, msg);
	tui_view_quit(a->view);
	return 0;
}

/* T4 /zoom：fbterm 字号（FBTERM 环境内）；退出码 70=外层重启应用新字号 */
static int cmd_zoom(struct tui_app *a, const char *arg)
{
	char path[512], line[256], err[128], msg[256];
	const char *home = getenv("HOME");
	const char *fb = getenv("FBTERM");
	int cur = 16, idx, size;
	FILE *f;

	if (!fb || !fb[0]) {
		tui_view_notice(a->view,
				L_("当前控制台不支持缩放（需图形控制台 fbterm；串口/SSH 不适用）"));
		return 0;
	}
	snprintf(path, sizeof(path), "%s/.fbtermrc",
		 home && home[0] ? home : "/root");
	f = fopen(path, "r");
	if (f) {
		while (fgets(line, sizeof(line), f))
			if (sscanf(line, "font-size=%d", &cur) == 1)
				break;
		fclose(f);
	}
	while (*arg == ' ')
		arg++;
	if (!*arg) {
		snprintf(msg, sizeof(msg),
			 L_("当前字号 %dpx。/zoom in|out|reset|<12|16|20|24|28|32|40>"),
			 cur);
		tui_view_notice(a->view, msg);
		return 0;
	}
	if (!strcmp(arg, "reset"))
		idx = occ_zoom_index(16);
	else if (!strcmp(arg, "in"))
		idx = occ_zoom_step(cur, 1);
	else if (!strcmp(arg, "out"))
		idx = occ_zoom_step(cur, -1);
	else {
		int v = atoi(arg);

		idx = v > 0 ? occ_zoom_index(v) : -1;
		if (idx < 0) {
			tui_view_notice(a->view, L_("无效字号——级表 12/16/20/24/28/32/40"));
			return 0;
		}
	}
	size = occ_zoom_size(idx);
	err[0] = '\0';
	if (occ_zoom_edit_fbtermrc(path, size, err, sizeof(err)) != 0) {
		snprintf(msg, sizeof(msg), L_("应用失败：%s"),
			 err[0] ? err : L_("未知"));
		tui_view_notice(a->view, msg);
		return 0;
	}
	g_t4_exit_code = 70;
	snprintf(msg, sizeof(msg), L_("应用新字号 %dpx——界面自动重启（会话保留）…"),
		 size);
	tui_view_notice(a->view, msg);
	tui_view_quit(a->view);
	return 0;
}


/* K11：AIKernel 内核侧观测行——/proc/ai/status 三件套 + audit 首行链
 * 统计 + agents 行数/actions 累加 + models 首行。非 AIKernel 主机
 * /proc/ai/status 不存在=整行静默省略（p-smoke/差分零扰动前提）。
 * 读面全小步：audit 只取首行（K9 实测 decisions 类全量读代价大，
 * 同纪律不整读）；各段缺省省段，不虚报。 */
static void cmd_status_kernel_line(struct tui_view *view)
{
	char buf[640], line[288];
	char kver[40] = "", abi[16] = "", cfg[32] = "";
	char chain[128] = "", ag[96] = "", md[128] = "";
	FILE *f;
	int agents = 0;
	unsigned long long acts = 0;

	f = fopen("/proc/ai/status", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "kernel_ver: %39s", kver) == 1)
			continue;
		if (sscanf(line, "abi_ver: %15s", abi) == 1)
			continue;
		if (sscanf(line, "config_hash: %31s", cfg) == 1)
			continue;
	}
	fclose(f);
	if (!kver[0] || !abi[0] || !cfg[0])
		return;

	f = fopen("/proc/ai/audit", "r");
	if (f) {
		if (fgets(line, sizeof(line), f)) {
			unsigned long long nodes = 0, ev = 0;

			if (sscanf(line, "chain head=%*s nodes=%llu evicted=%llu",
				   &nodes, &ev) == 2)
				snprintf(chain, sizeof(chain),
					 " · chain nodes=%llu evicted=%llu",
					 nodes, ev);
		}
		fclose(f);
	}

	f = fopen("/proc/ai/agents", "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			unsigned long long ac;
			unsigned id;
			char nm[64];

			if (sscanf(line, "id=%u name=%63s bound=%*u actions=%llu",
				   &id, nm, &ac) == 3) {
				agents++;
				acts += ac;
			}
		}
		fclose(f);
		if (agents)
			snprintf(ag, sizeof(ag), " · agents=%d acts=%llu",
				 agents, acts);
	}

	f = fopen("/proc/ai/models", "r");
	if (f) {
		if (fgets(line, sizeof(line), f)) {
			char nm[48];
			unsigned ver, st;

			if (sscanf(line, "name=%47s version=%u state=%u",
				   nm, &ver, &st) == 3)
				snprintf(md, sizeof(md),
					 " · model %s v%u st%u", nm, ver, st);
		}
		fclose(f);
	}

	snprintf(buf, sizeof(buf), "kernel=%s abi=%s cfg=%s%s%s%s",
		 kver, abi, cfg, chain, ag, md);
	tui_view_notice(view, buf);
}

/* O-19：命令分发兜底——原样匹配未命中（rc==1）且行以 '/' 开头时，
 * 去行尾空白（空格/制表）后重试一次（"/models " 等价 "/models"）。
 * 兜底式而非入口统一 trim：带参命令（/rename /theme /zoom）首轮按
 * 原样前缀匹配即命中，参数尾空白不被裁（如 /rename 标题尾空格）——
 * 仅无参命令尾随空白场景多走一轮。 */
static int tui_app_on_command_impl(void *ud, const char *line);

static int tui_app_on_command(void *ud, const char *line)
{
	int rc;
	size_t n, len;
	char *trim;

	if (!line)
		return 1;
	rc = tui_app_on_command_impl(ud, line);
	if (rc != 1 || line[0] != '/')
		return rc;
	len = n = strlen(line);
	while (n > 0 && (line[n - 1] == ' ' || line[n - 1] == '	'))
		n--;
	if (n == len)
		return rc;		/* 行尾无空白——不重试 */
	trim = malloc(n + 1);
	if (!trim)
		return rc;
	memcpy(trim, line, n);
	trim[n] = '\0';
	rc = tui_app_on_command_impl(ud, trim);
	free(trim);
	return rc;
}

/* O-25：TUI /undo——CLI 撤销链同源（occ_undo 一步）；结果以系统注记
 * 行进聊天流（/delete 同款 notice 通道，文案含撤销条数/文件回滚数/
 * 无快照未回滚数与 /redo 指引），被撤输入回填输入覆盖层（/rename 预
 * 填同款 API；Enter 重发=「发送新消息即确认撤销」，Esc 关闭保留撤销
 * 态仍可 /redo）。无可撤 → err 人话原样注记。 */
static void cmd_tui_undo(struct tui_app *a)
{
	occ_undo_result r;
	char err[512];
	char nb[400];
	int live;
	size_t failed = 0, i;

	pthread_mutex_lock(&a->mu);
	live = a->worker_live;
	pthread_mutex_unlock(&a->mu);
	if (live) {
		tui_view_notice(a->view,
				L_("undo: turn 运行中——Esc 中断或收口后再 /undo"));
		return;
	}
	if (!a->session_id[0]) {
		tui_view_notice(a->view,
				L_("尚无会话——先发一条消息再 /undo"));
		return;
	}
	memset(&r, 0, sizeof(r));
	err[0] = '\0';			/* 成功路径可能不置 err——防读未初始化 */
	if (occ_undo(a->db, a->session_id, 1, NULL, &r, err,
		     sizeof(err))) {
		/* 无可撤/状态不合法：err 已是人话（occ undo: 前缀） */
		tui_view_notice(a->view, err[0] ? err : L_("undo: 失败"));
		return;
	}
	for (i = 0; i < r.nfiles; i++)
		if (r.files[i].failed)
			failed++;
	{
		char fb[64];

		fb[0] = '\0';
		if (failed)
			snprintf(fb, sizeof(fb), L_("，回滚失败 %zu 处"),
				 failed);
		snprintf(nb, sizeof(nb),
			 L_("undo: 已撤销 %zu 条消息 + %zu 文件回滚（无快照未回滚 %zu 处%s）；/redo 可恢复，发送新消息即确认撤销"),
			 r.nmsgs_reverted, r.nfiles, r.nskipped, fb);
	}
	tui_view_notice(a->view, nb);
	if (r.user_text && r.user_text[0]) {
		/* 回填=输入覆盖层（/rename 预填同款 API；容量 240B——
		 * 超长不硬截断（截半行汉字），注记说明原文在转写区） */
		if (strlen(r.user_text) < TUI_OV_INPUT_MAX) {
			(void)tui_view_open_input(a->view, OV_UNDO_RECALL,
						  L_("undo 回填"),
						  L_("被撤输入（Enter 重发=确认撤销；Esc 关闭保留可 /redo）"),
						  r.user_text, 0);
		} else {
			tui_view_notice(a->view,
					L_("被撤输入超回填上限（240 字节）——原文见上方转写区，可手动复制重发"));
		}
	}
	occ_undo_result_free(&r);
}

/* O-25：TUI /redo——对称恢复（occ_redo：消息解隐藏+文件还原+清撤销
 * 态）；注记行进聊天流，部分失败如实附注（err 已带前缀）。 */
static void cmd_tui_redo(struct tui_app *a)
{
	occ_undo_result r;
	char err[512];
	char nb[400];
	int live;

	pthread_mutex_lock(&a->mu);
	live = a->worker_live;
	pthread_mutex_unlock(&a->mu);
	if (live) {
		tui_view_notice(a->view,
				L_("redo: turn 运行中——Esc 中断或收口后再 /redo"));
		return;
	}
	if (!a->session_id[0]) {
		tui_view_notice(a->view,
				L_("尚无会话——先发一条消息再 /redo"));
		return;
	}
	memset(&r, 0, sizeof(r));
	err[0] = '\0';			/* 部分失败才置——防读未初始化 */
	if (occ_redo(a->db, a->session_id, NULL, &r, err, sizeof(err))) {
		tui_view_notice(a->view, err[0] ? err : L_("redo: 失败"));
		return;
	}
	snprintf(nb, sizeof(nb),
		 L_("redo: 已恢复 %zu 条消息 + %zu 文件还原（/undo 可再撤；此后正常续聊）"),
		 r.nmsgs_reverted, r.nfiles);
	tui_view_notice(a->view, nb);
	if (err[0])
		tui_view_notice(a->view, err);
	occ_undo_result_free(&r);
}

static int tui_app_on_command_impl(void *ud, const char *line)
{
	struct tui_app *a = ud;

	if (!strcmp(line, "/new")) {
		pthread_mutex_lock(&a->mu);
		a->session_id[0] = '\0';
		a->session_title[0] = '\0';	/* UXAB：顶栏随之清空 */
		a->tokens_total = 0;
		a->u_in = a->u_out = a->u_cr = a->u_cw = 0;
		a->u_est = 0;
		pthread_mutex_unlock(&a->mu);
		/* T2：新会话重置增量加载状态（预算回缺省/无更早可加载） */
		a->replay_budget = app_replay_lines_budget();
		a->replay_earlier = 0;
		a->replay_ok = 0;
		a->replay_mem_stop = 0;
		a->earliest_noticed = 0;
		a->load_busy_noticed = 0;
		/* T1：立即清屏（走事件队列——与回放切换同源；下一条消息才
		 * 建会话的语义不变）。不发 notice：①直写 notice 会被队列里
		 * 的 CLEAR 反序清掉；②空态面板已承担引导语。 */
		(void)tui_view_post(a->view, TUI_VIEW_HIST_CLEAR, NULL, 0,
				    NULL, 0);
		return 0;
	}
	if (!strcmp(line, "/clear")) {
		/* E1（ORCH §2 拍板 6）：/clear=归档+换窗+清屏（T9c2 纯清屏
		 * 升级）。库面半件=occ_session_archive 单事务：会话
		 * status→archived（消息原地保留——/sessions 可找回续聊，
		 * 非删除）+ occ_window 回 native 空基线（digest_id 置空
		 * ——窗口换新而非删历史）；TUI 半件同 /new 态复位+清屏。
		 * 清屏与归档通知走同一事件队列（先 CLEAR 后 NOTICE——
		 * 直写 notice 会被队列里的 CLEAR 反序清掉，同 /new 注）。
		 * headless occ -p 无此路径（TUI 专属命令，差分输出不变）。 */
		int live;
		char e[192], nb[336], tt[128];
		occ_session_row r;

		pthread_mutex_lock(&a->mu);
		live = a->worker_live;
		pthread_mutex_unlock(&a->mu);
		if (live) {
			tui_view_notice(a->view,
					L_("clear: turn 运行中——Esc 中断或收口后再 /clear"));
			return 0;
		}
		if (!a->session_id[0]) {
			(void)tui_view_post(a->view, TUI_VIEW_HIST_CLEAR,
					    NULL, 0, NULL, 0);
			tui_view_notice(a->view,
					L_("clear: 尚无会话——已清屏"));
			return 0;
		}
		e[0] = '\0';
		if (occ_session_archive(a->db, a->session_id, e,
					sizeof(e))) {
			tui_view_notice(a->view, e[0] ? e : L_("clear: 归档失败"));
			return 0;
		}
		tt[0] = '\0';
		if (occ_session_get(a->db, a->session_id, &r, NULL, 0) == 1)
			app_clip_title(r.title, tt, sizeof(tt));
		/* 换窗：app 态回空（同 /new——下一条消息创建新会话）+
		 * T2 增量加载状态清零 */
		pthread_mutex_lock(&a->mu);
		a->session_id[0] = '\0';
		a->session_title[0] = '\0';
		a->tokens_total = 0;
		a->u_in = a->u_out = a->u_cr = a->u_cw = 0;
		a->u_est = 0;
		pthread_mutex_unlock(&a->mu);
		a->replay_budget = app_replay_lines_budget();
		a->replay_earlier = 0;
		a->replay_ok = 0;
		a->replay_mem_stop = 0;
		a->earliest_noticed = 0;
		a->load_busy_noticed = 0;
		(void)tui_view_post(a->view, TUI_VIEW_HIST_CLEAR, NULL, 0,
				    NULL, 0);
		snprintf(nb, sizeof(nb),
			 L_("session 已归档：%s（消息保留，/sessions 可找回续聊）——窗口已换新，下一条消息创建新会话"),
			 tt[0] ? tt : L_("(无题)"));
		(void)tui_view_post(a->view, TUI_VIEW_NOTICE, nb, 0, NULL, 0);
		return 0;
	}
	if (!strcmp(line, "/delete")) {
		/* O-12：删除当前会话。双发确认门（W2 精神）：首次 /delete
		 * 只布防，10s 内再发才真删——删除不可恢复。库层
		 * occ_session_delete 单事务级联（消息/工具/窗口/回滚+
		 * transcript best-effort）；删后回 /new 空态（侧栏
		 * fill_sessions 每帧活拉，自动反映）。 */
		int live;
		uint64_t now = tui_now_ms();
		char e[192];
		char t[64];
		occ_session_row r;

		pthread_mutex_lock(&a->mu);
		live = a->worker_live;
		pthread_mutex_unlock(&a->mu);
		if (live) {
			tui_view_notice(a->view,
				L_("delete: turn 运行中——Esc 中断或收口后再删"));
			return 0;
		}
		if (!a->session_id[0]) {
			tui_view_notice(a->view,
				L_("尚无会话——先发一条消息再 /delete"));
			return 0;
		}
		if (!(a->delete_arm && now - a->delete_arm <= 10000)) {
			a->delete_arm = now;
			tui_view_notice(a->view,
				L_("确认：10 秒内再发一次 /delete 将永久删除当前会话（不可恢复）"));
			return 0;
		}
		a->delete_arm = 0;
		t[0] = '\0';
		if (occ_session_get(a->db, a->session_id, &r, e,
				    sizeof(e)) == 1)
			snprintf(t, sizeof(t), "%.40s", r.title);
		if (occ_session_delete(a->db, a->session_id, e,
				       sizeof(e))) {
			tui_view_notice(a->view, e);
			return 0;
		}
		pthread_mutex_lock(&a->mu);
		a->session_id[0] = '\0';
		a->session_title[0] = '\0';
		a->tokens_total = 0;
		a->u_in = a->u_out = a->u_cr = a->u_cw = 0;
		a->u_est = 0;
		pthread_mutex_unlock(&a->mu);
		/* T2：删后回到无会话态——增量加载状态清零 */
		a->replay_budget = app_replay_lines_budget();
		a->replay_earlier = 0;
		a->replay_ok = 0;
		a->replay_mem_stop = 0;
		a->earliest_noticed = 0;
		a->load_busy_noticed = 0;
		{
			char nb[256];	/* tt≤120B + 固定后缀 ~78B */
			char tt[128];

			app_clip_title(t, tt, sizeof(tt));
			snprintf(nb, sizeof(nb),
				 L_("session 已删除：%s（级联清消息/工具/窗口/回滚）——下一条消息创建新会话"), tt);
			tui_view_notice(a->view, nb);
		}
		return 0;
	}
	if (!strcmp(line, "/theme") || !strncmp(line, "/theme ", 7))
		return cmd_theme(a, line + 6);
	if (!strcmp(line, "/zoom") || !strncmp(line, "/zoom ", 6))
		return cmd_zoom(a, line + 5);
	if (!strcmp(line, "/sessions"))
		return cmd_sessions_overlay(a);
	if (!strcmp(line, "/tasks"))		/* E8：任务面板（ORCH §7） */
		return cmd_tasks_overlay(a);
	/* O-20 A 部：语言档查询/切换（内存态——持久化走 OCC_LANG env）。
	 * 切换即时生效：渲染层逐帧取 L_()，系统提示下一轮随活档。 */
	if (!strcmp(line, "/lang")) {
		tui_view_notice(a->view, tui_lang_is_en() ?
				L_("语言档=en（/lang zh 切回中文）") :
				L_("语言档=zh（/lang en 切到英文）"));
		return 0;
	}
	if (!strcmp(line, "/lang en")) {
		tui_lang_set_en(1);
		tui_view_notice(a->view, L_("已切英文档（本会话内存态；"
					    "OCC_LANG=en 可持久）"));
		return 0;
	}
	if (!strcmp(line, "/lang zh")) {
		tui_lang_set_en(0);
		tui_view_notice(a->view, L_("已切中文档"));
		return 0;
	}
	/* O-10（UX-O §3）：/su gate 密码提权（/su 0 回落；/exit 注销同效）
	 * P-45：「已特权」只看会话提权态 su.elevated（唯一事实源；密码
	 * 验证成功才置 1）——不再掺策略基础档 g_w2.tier：base=privileged
	 * 部署下旧判定把未提权会话也当「已是特权档」，/su 永不弹密码框、
	 * /su 0 永不回落（真机 P-45 实证①②③）。 */
	if (!strcmp(line, "/su")) {
		long long now = (long long)tui_now_ms();

		if (a->su.elevated) {
			tui_view_notice(a->view, L_("已在特权档（/su 0 回落）"));
			return 0;
		}
		if (now < a->su.cooldown_until) {
			char nb[96];

			snprintf(nb, sizeof(nb), L_("冷却中（%lld 秒后再试）"),
				 (a->su.cooldown_until - now + 999) / 1000);
			tui_view_notice(a->view, nb);
			return 0;
		}
		(void)tui_view_open_input(a->view, OV_SU, L_("/su 提权"),
					  L_("admin 密码"), "", 1);
		return 0;
	}
	if (!strcmp(line, "/su 0")) {
		if (!a->su.elevated) {
			tui_view_notice(a->view, L_("未在提权档"));
			return 0;
		}
		pthread_mutex_lock(&a->mu);
		a->su.elevated = 0;
		if (g_w2_ready)
			g_w2.tier = g_w2_base_tier;
		pthread_mutex_unlock(&a->mu);
		(void)ai_policy_audit(getuid(),
				      ai_policy_mode_for_uid(getuid()),
				      "su", "delevate", "ok");
		tui_view_notice(a->view,
				(g_w2_ready &&
				 g_w2_base_tier == OCC_W2_TIER_PRIVILEGED) ?
				L_("已回落基础档位（策略基础档=特权）") :
				L_("已回落基础档位"));
		return 0;
	}
	if (!strcmp(line, "/status")) {
		char buf[640];
		char t1[24], t2[24], items[96], pbuf[16];
		long long in, out2, cr, cw, ctx, lim, billed;
		int est, fb, pct;
		char sid[OCC_ID_LEN];

		pthread_mutex_lock(&a->mu);
		in = a->u_in;
		out2 = a->u_out;
		cr = a->u_cr;
		cw = a->u_cw;
		est = a->u_est;
		lim = a->ctx_limit;
		fb = a->ctx_fallback;
		billed = a->tokens_total;
		snprintf(sid, sizeof(sid), "%s", a->session_id);
		pthread_mutex_unlock(&a->mu);
		ctx = tui_usage_ctx(in, out2, cr, cw, -1);
		pct = tui_usage_pct(ctx, lim);
		if (pct >= 0)
			snprintf(pbuf, sizeof(pbuf), " (%d%%)", pct);
		else
			pbuf[0] = '\0';
		tui_usage_fmt(ctx, t1, sizeof(t1));
		tui_usage_fmt(lim, t2, sizeof(t2));
		tui_usage_items(items, sizeof(items), in, out2, cr + cw, -1,
				est);
		snprintf(buf, sizeof(buf),
			 "session=%s model=%s ctx=%s%s/%s%s%s · %s"
			 " | billed=%lld%s | cwd=%.200s",
			 sid[0] ? sid : "(new)", a->p.model,
			 est ? "~" : "", t1, t2, fb ? "*" : "", pbuf, items,
			 billed, est ? "~" : "", a->cwd);
		tui_view_notice(a->view, buf);
		cmd_status_kernel_line(a->view);
		return 0;
	}
	if (!strcmp(line, "/models"))
		return cmd_models(a);
	if (!strncmp(line, "/rename", 7) &&
	    (line[7] == '\0' || line[7] == ' ' || line[7] == '\t'))
		return cmd_rename(a, line + 7);
	if (!strcmp(line, "/tools"))
		return cmd_tools(a);
	if (!strcmp(line, "/sandbox"))
		return cmd_sandbox(a);
	if (!strcmp(line, "/trace"))
		return cmd_trace(a);
	if (!strcmp(line, "/lease"))
		return cmd_lease(a);
	if (!strcmp(line, "/compact")) {
		/* T9e：接真 autocondense 手动换窗（occ_ac_compact_now：
		 * report→begin→digest→commit→换窗；force 跳过 check/judge）。
		 * 线程合同：仅在 worker 空闲时在主线程调用——worker_live==0
		 * 即 occ_loop_run 已完全返回（ac 静态状态无人持有），且 on_command
		 * 与 on_submit 同在主线程，不存在并发 submit。 */
		occ_ac_turn t;
		occ_session_row cur;
		char err[256], nb[400];
		int rc, live;

		if (!occ_ac_enabled()) {
			tui_view_notice(a->view,
					OCC_AC_ST_OFF
					"（OCC_AC=off，/compact 不可用）");
			return 0;
		}
		pthread_mutex_lock(&a->mu);
		live = a->worker_live;
		pthread_mutex_unlock(&a->mu);
		if (live) {
			tui_view_notice(a->view,
					L_("compact: turn 运行中——收口后再 /compact"));
			return 0;
		}
		if (!a->session_id[0]) {
			tui_view_notice(a->view,
					L_("compact: 尚无会话（先发一条消息）"));
			return 0;
		}
		memset(&t, 0, sizeof(t));
		t.db = a->db;
		t.p = &a->p;
		t.session_id = a->session_id;
		t.cwd = a->cwd;
		/* context：手动触发无「收口回复」；judge 不走（force），占位空串 */
		t.context = "";
		if (occ_session_get(a->db, a->session_id, &cur, NULL, 0) == 1)
			t.tokens = cur.tokens_total;
		err[0] = '\0';
		tui_view_notice(a->view,
				L_("compact: 触发 autocondense 换窗（begin→digest→commit）…"));
		tui_view_paint(a->view);	/* 阻塞调用前先落帧（同向导验证） */
		rc = occ_ac_compact_now(&t, err, sizeof(err));
		if (rc == 0) {
			/* 换窗成功：DB 账本已重置为新基线（tokens_est=1）——
			 * 刷新 TUI 五项缓存为新基线（估算口径，显示 ~）。
			 * 注：occ_ac_compact_now 内部经 tmp 拷贝跑链，digest_chars
			 * out 不回传（occ_core 禁改）——成功通知不带摘要字数。 */
			if (occ_session_get(a->db, a->session_id, &cur,
					     NULL, 0) == 1) {
				pthread_mutex_lock(&a->mu);
				a->tokens_total = cur.tokens_total;
				a->u_in = cur.tokens_total;
				a->u_out = a->u_cr = a->u_cw = 0;
				a->u_est = cur.tokens_est;
				pthread_mutex_unlock(&a->mu);
			}
			tui_view_notice(a->view,
					L_("compact: 换窗完成——历史已折叠为摘要，token 账本重置为新基线（显示 ~ 为估算）"));
		} else {
			snprintf(nb, sizeof(nb), "compact: %s",
				 err[0] ? err : L_("失败（ac 不可达或摘要未过校验）"));
			tui_view_notice(a->view, nb);
		}
		return 0;
	}
	if (!strcmp(line, "/shell")) {
		/* T9e：bash 逃逸（plan §1.9 /shell → bash，exit 回 occ）。
		 * 机制：置 shell_req + 退屏（tui_view_quit）→ run_interactive
		 * 在 view 销毁、worker join 后 fork/exec 交互 bash（继承 tty），
		 * bash 退出 → 重建 view 续跑。转写区按 c2 裁定 12 从空开始。
		 * worker 运行中拒绝（不打断 turn；Esc 中断后再进）。 */
		int live;

		pthread_mutex_lock(&a->mu);
		live = a->worker_live;
		pthread_mutex_unlock(&a->mu);
		if (live) {
			tui_view_notice(a->view,
					L_("shell: turn 运行中——Esc 中断或收口后再 /shell"));
			return 0;
		}
		a->shell_req = 1;
		tui_view_quit(a->view);
		return 0;
	}
	/* O-25：/undo /redo——TUI 面撤销（此前仅 CLI occ undo/redo，
	 * unstuck 文案却指引 /undo——本刀补齐闭环） */
	if (!strcmp(line, "/undo")) {
		cmd_tui_undo(a);
		return 0;
	}
	if (!strcmp(line, "/redo")) {
		cmd_tui_redo(a);
		return 0;
	}
	return 1;			/* 未知命令 → view 出提示 */
}

/* ---- 覆盖层钩子（view 传选中/输入/动作；occ 决策并开关面板） ---- */

static int tui_app_on_overlay_submit(void *ud, int ov_id, int idx)
{
	struct tui_app *a = ud;

	if (idx < 0)
		return 1;
	switch (ov_id) {
	case OV_W2: {
		/* O-9：y=执行（idx 0）/n=取消——唤醒在途 worker；
		 * O-18：idx 2=s 本会话同类放行——verdict=1 且当前理由键
		 * 入会话放行表（后续同键免问；广播后入表——下一次同键
		 * 调用的 decide 必在其后读到） */
		pthread_mutex_lock(&a->mu);
		a->w2_verdict = (idx == 0 || idx == 2);
		a->w2_answered = 1;
		pthread_cond_broadcast(&a->w2_cond);
		pthread_mutex_unlock(&a->mu);
		if (idx == 2)
			occ_w2_ses_allow_add(&g_w2);
		tui_view_close_overlay(a->view);
		return 0;
	}
	case OV_MODELS: {
		size_t mi;
		const occ_reg_model *rm;
		char nb[320];

		if (!a->reg || (size_t)idx >= a->ov_map_n)
			return 1;
		mi = a->ov_map[idx];
		if (mi == OV_MAP_NONE || mi >= a->reg->nmodels)
			return 1;
		rm = &a->reg->models[mi];
		if (rm->source == OCC_REG_SRC_TOML && rm->slot_id[0]) {
			occ_provider np;
			int busy;

			pthread_mutex_lock(&a->mu);
			busy = a->worker_live;
			pthread_mutex_unlock(&a->mu);
			if (busy) {
				tui_view_overlay_status(a->view,
							 L_("busy — turn 运行中，稍后再切换模型"), 1);
				return 0;
			}
			if (occ_provider_resolve(&a->cfg, rm->slot_id,
						 &np) != 0) {
				tui_view_overlay_status(a->view,
							 L_("槽位解析失败（model.toml 损坏？）"),
							 1);
				return 0;
			}
				occ_provider_free(&a->p);
				a->p = np;
				app_resolve_ctx(a);
				/* UXAB：顶栏厂商+块头模型标签随切换刷新 */
				app_update_model_prov(a);
				tui_view_set_assist_label(a->view, a->p.model);
				occ_registry_touch(a->reg, rm->provider, rm->id);
			(void)occ_state_save(a->reg, a->state_path);
			tui_view_close_overlay(a->view);
			{
				char ctb[24];

				tui_usage_fmt(a->ctx_limit, ctb,
					      sizeof(ctb));
				snprintf(nb, sizeof(nb),
					 L_("model → %s/%s（ctx %s%s）"),
					 rm->provider, rm->id, ctb,
					 a->ctx_fallback ? "*" : "");
			}
			tui_view_notice(a->view, nb);
			return 0;
		}
		/* 仅目录条目（无 key）→ 向导（模型已选，从 provider 步） */
		wiz_reset(a);
		snprintf(a->wiz.model_id, sizeof(a->wiz.model_id), "%s",
			 rm->id);
		snprintf(a->wiz.display, sizeof(a->wiz.display), "%s",
			 rm->display[0] ? rm->display : rm->id);
		snprintf(a->wiz.provider, sizeof(a->wiz.provider), "%s",
			 rm->provider);
		a->wiz.ctx_limit = rm->context_limit;
		wiz_open_provider(a);
		return 0;
	}
	case OV_SESSIONS: {
		occ_session_row *r;
		char nb[320];
		int live;

		if ((size_t)idx >= a->ov_rows_n)
			return 1;
		r = &a->ov_rows[idx];
		pthread_mutex_lock(&a->mu);
		snprintf(a->session_id, sizeof(a->session_id), "%s", r->id);
		snprintf(a->session_title, sizeof(a->session_title), "%.95s",
			 r->title);			/* UXAB：顶栏即时切换 */
		a->tokens_total = r->tokens_total;
		live = a->worker_live;
		pthread_mutex_unlock(&a->mu);
		app_load_usage_from_db(a, r->id);
		tui_view_close_overlay(a->view);
		/* OCC-DEBT：切换即回放该会话尾部历史（清旧转写；
		 * turn 运行中跳过——事件会插进 live 块，诚实留步）。
		 * 切换通告也走事件队列（在 HIST_CLEAR 之后入队）——直写
		 * chat 会被 CLEAR 清掉；落在历史尾部恰成分隔。 */
		if (!live) {
			char tt[128];

			app_replay_session(a, r->id, 1);
			app_clip_title(r->title[0] ? r->title : "(untitled)",
				       tt, sizeof(tt));
			snprintf(nb, sizeof(nb),
				 L_("── switched to %s (%.14s…) ──"),
				 tt, r->id);
			(void)tui_view_post(a->view, TUI_VIEW_NOTICE, nb,
					    strlen(nb), NULL, 0);
		} else {
			char tt[128];

			app_clip_title(r->title[0] ? r->title : "(untitled)",
				       tt, sizeof(tt));
			snprintf(nb, sizeof(nb),
				 L_("── switched to %s (%.14s…) ──"),
				 tt, r->id);
			tui_view_notice(a->view, nb);
			tui_view_notice(a->view,
					L_("turn 运行中——历史回放待收口（重进 /sessions 可补）"));
		}
		return 0;
	}
	case OV_WIZ_MODEL: {
		const occ_catalog_model *m;

		if (!a->cat || (size_t)idx >= a->ov_map_n)
			return 1;
		if (a->ov_map[idx] == OV_MAP_NONE ||
		    a->ov_map[idx] >= a->cat->nmodels)
			return 1;
		m = &a->cat->models[a->ov_map[idx]];
		memset(&a->wiz, 0, sizeof(a->wiz));
		snprintf(a->wiz.model_id, sizeof(a->wiz.model_id), "%s",
			 m->id);
		snprintf(a->wiz.display, sizeof(a->wiz.display), "%s",
			 m->name[0] ? m->name : m->id);
		snprintf(a->wiz.provider, sizeof(a->wiz.provider), "%s",
			 m->provider);
		a->wiz.ctx_limit = m->context_limit;
		wiz_open_provider(a);
		return 0;
	}
	case OV_WIZ_PROVIDER: {
		size_t pv;

		if ((size_t)idx >= a->ov_map_n)
			return 1;
		pv = a->ov_map[idx];
		if (pv == OV_MAP_CUSTOM) {
			wiz_open_base(a);
			return 0;
		}
		if (pv >= (size_t)WIZ_NPRESET)
			return 1;
		snprintf(a->wiz.base_url, sizeof(a->wiz.base_url), "%s",
			 WIZ_PRESET[pv].base);
		snprintf(a->wiz.ptype, sizeof(a->wiz.ptype), "%s",
			 WIZ_PRESET[pv].ptype);
		wiz_slot_id(WIZ_PRESET[pv].id, a->wiz.slot,
			    sizeof(a->wiz.slot));
		wiz_open_key(a);
		return 0;
	}
	case OV_TASKS: {
		const occ_task_row *r;

		/* E8 面板=只读展示+提示（不代行验收——机械判在 E4 task
		 * 工具面；R3 验收动作在面板内的最小形态）。 */
		if ((size_t)idx >= a->ov_task_rows_n)
			return 1;
		r = &a->ov_task_rows[idx];
		if (!strcmp(r->status, OCC_TASK_ST_IN_REVIEW))
			tui_view_overlay_status(a->view,
						L_("验收：对模型用 task 工具 return 提交裁决（面板只读，不代行）"), 0);
		else {
			char bud[64], det[TUI_OV_DETAIL_MAX];

			task_budget_str(a->db, r, bud, sizeof(bud));
			snprintf(det, sizeof(det), "%s · rew %d/%d · %s",
				 r->id, r->rework_count, r->rework_max,
				 bud);
			tui_view_overlay_status(a->view, det, 0);
		}
		return 0;		/* 面板保持打开（浏览态） */
	}
	case OV_TOOLS:
	case OV_TRACE:
	case OV_LEASE:
		return 0;		/* 浏览态：Enter 保持打开（detail 行） */
	default:
		return 1;
	}
}

static int tui_app_on_overlay_input(void *ud, int ov_id, const char *text,
				    size_t len)
{
	struct tui_app *a = ud;

	if (ov_id == OV_WIZ_KEY) {
		if (len == 0 || len >= sizeof(a->wiz.key)) {
			tui_view_overlay_status(a->view,
						 L_("key 不能为空/过长（≤255）"),
						 1);
			return 0;
		}
		memcpy(a->wiz.key, text, len);
		a->wiz.key[len] = '\0';
		wiz_verify_save(a);
		return 0;
	}
	if (ov_id == OV_WIZ_BASE) {
		if (len == 0 || len >= sizeof(a->wiz.base_url) ||
		    (strncmp(text, "http://", 7) != 0 &&
		     strncmp(text, "https://", 8) != 0)) {
			tui_view_overlay_status(a->view,
						 L_("base_url 须以 http:// 或 https:// 开头"), 1);
			return 0;
		}
		memcpy(a->wiz.base_url, text, len);
		a->wiz.base_url[len] = '\0';
		snprintf(a->wiz.ptype, sizeof(a->wiz.ptype), "%s",
			 "openai_compatible");
		wiz_slot_id(a->wiz.provider, a->wiz.slot,
			    sizeof(a->wiz.slot));
		wiz_open_key(a);
		return 0;
	}
	if (ov_id == OV_SU) {
		/* O-10：tui_gate crypt 复用（console-gate admin hash）；
		 * 3 错→10s 冷却（照 gate 口径）。 */
		char hash[128];
		long long ts;
		long long now = (long long)tui_now_ms();
		int ok;

		pthread_mutex_lock(&a->mu);
		if (now < a->su.cooldown_until) {
			long long left = (a->su.cooldown_until - now +
				       999) / 1000;

			pthread_mutex_unlock(&a->mu);
			{
				char nb[96];

				snprintf(nb, sizeof(nb),
					 L_("冷却中（%lld 秒）"), left);
				tui_view_overlay_status(a->view, nb, 1);
			}
			return 0;
		}
		if (tui_gate_read(tui_gate_path(), hash, &ts) != 0) {
			pthread_mutex_unlock(&a->mu);
			tui_view_overlay_status(a->view,
						 L_("凭据未设置（先在 T4 设密向导建 admin 密码）"),
						 1);
			return 0;
		}
		ok = (len > 0 && len < 128 &&
		      tui_gate_verify(text, hash));
		if (!ok) {
			a->su.fails++;
			/* P-45：错密码必须 audit 记账（fail；×3 连冷却也记）*/
			(void)ai_policy_audit(getuid(),
					      ai_policy_mode_for_uid(getuid()),
					      "su", "elevate", "fail");
			if (a->su.fails >= 3) {
				a->su.fails = 0;
				a->su.cooldown_until = now + 10000;
				pthread_mutex_unlock(&a->mu);
				tui_view_overlay_clear_input(a->view);
				tui_view_overlay_status(a->view,
							 L_("密码错误×3——10 秒冷却"),
							 1);
				return 0;
			}
			pthread_mutex_unlock(&a->mu);
			/* P-45：清空已拒文本——残留拼接会让重输必错 */
			tui_view_overlay_clear_input(a->view);
			tui_view_overlay_status(a->view, L_("密码错误"), 1);
			return 0;
		}
		a->su.fails = 0;
		a->su.elevated = 1;
		if (g_w2_ready)
			g_w2.tier = OCC_W2_TIER_PRIVILEGED;
		pthread_mutex_unlock(&a->mu);
		/* P-45：提权成功同源记账（ok）——降权后重提权全链路可审计 */
		(void)ai_policy_audit(getuid(),
				      ai_policy_mode_for_uid(getuid()),
				      "su", "elevate", "ok");
		tui_view_close_overlay(a->view);
		tui_view_notice(a->view,
				L_("已提权至特权档（/su 0 回落 · /exit 注销同效）"));
		return 0;
	}
	if (ov_id == OV_UNDO_RECALL) {
		/* O-25：回填面板 Enter=重发（「发送新消息即确认撤销」——
		 * 走 on_submit 同链，occ_revert_commit 由 loop add_user
		 * 收口）；空回车=只关面板（撤销态保留，可 /redo 或再发
		 * 任意消息确认）。重发不成（turn 忙）重开面板保文本。 */
		if (!text || !text[0]) {
			tui_view_close_overlay(a->view);
			tui_view_notice(a->view,
					L_("未重发——撤销保留（/redo 可恢复；再发任意消息即确认撤销）"));
			return 0;
		}
		tui_view_close_overlay(a->view);
		if (tui_app_on_submit(a, text, len) != 0) {
			tui_view_notice(a->view, L_("重发未成（turn 运行中）"));
			(void)tui_view_open_input(a->view, OV_UNDO_RECALL,
						  L_("undo 回填"),
						  L_("被撤输入（Enter 重发=确认撤销）"), text, 0);
		}
		return 0;
	}
	if (ov_id == OV_RENAME) {
		char e[160];
		char nb[320];

		if (len == 0) {
			/* B8：空回车=AI 生成标题（T9C3 取舍5 偿还）；
			 * 无会话/无 provider 诚实拒绝（ren_generate 内） */
			if (!a->session_id[0]) {
				tui_view_overlay_status(a->view,
							L_("尚无会话（先发一条消息）"),
							1);
				return 0;
			}
			ren_generate(a);
			return 0;
		}
		if (!a->session_id[0]) {
			tui_view_overlay_status(a->view,
						 L_("尚无会话（先发一条消息）"),
						 1);
			return 0;
		}
		if (occ_session_set_title(a->db, a->session_id, text, e,
					  sizeof(e)) != 0) {
			tui_view_overlay_status(a->view, e, 1);
			return 0;
		}
		pthread_mutex_lock(&a->mu);
		snprintf(a->session_title, sizeof(a->session_title), "%.95s",
			 text);			/* UXAB：顶栏即时更新 */
		pthread_mutex_unlock(&a->mu);
		{
			char tt[128];

			app_clip_title(text, tt, sizeof(tt));
			snprintf(nb, sizeof(nb), "renamed → %s", tt);
		}
		tui_view_close_overlay(a->view);
		tui_view_notice(a->view, nb);
		return 0;
	}
	return 1;
}

static int tui_app_on_overlay_key(void *ud, int ov_id, const char *action,
				  int idx)
{
	struct tui_app *a = ud;

	if (ov_id == OV_W2) {
		/* O-9：busy 态 Esc=取消确认——返回未处理，交回
		 * dialog.close 默认流（on_overlay_close 拒绝并唤醒） */
		return 1;
	}

	/* OCC-DEBT：busy 态 Esc → 取消在途验证（面板留步——与失败路径
	 * 同语义；由 tui_view_set_busy(1) 期间的 dialog.close 改派而来）；
	 * B8：标题生成中同派（ren_cancel + SIGINT → EINTR → rc=2 收口） */
	if (!strcmp(action, "overlay.cancel")) {
		int live, rlive;

		pthread_mutex_lock(&a->mu);
		rlive = a->ren_thread_live;
		if (rlive)
			a->ren_cancel = 1;
		pthread_mutex_unlock(&a->mu);
		if (rlive) {
			(void)pthread_kill(a->ren_thread, SIGINT);
			tui_view_overlay_status(a->view,
						L_("取消生成中…（收口后可重试）"), 0);
			return 0;
		}
		pthread_mutex_lock(&a->mu);
		live = a->wiz_thread_live;
		if (live)
			a->wiz_cancel = 1;
		pthread_mutex_unlock(&a->mu);
		if (!live)
			return 1;	/* 无在途验证：回落正常关闭 */
		(void)pthread_kill(a->wiz_thread, SIGINT);
		tui_view_overlay_status(a->view,
					 L_("取消验证中…（收口后可改 key 重试）"),
					 0);
		return 0;
	}
	if (ov_id != OV_MODELS)
		return 1;
	if (!strcmp(action, "model.add")) {
		wiz_reset(a);
		wiz_open_model(a);
		return 0;
	}
	if (!strcmp(action, "model.nonchat")) {
		/* OCC-DEBT：非对话条目显隐切换（默认过滤；显示时 dim 标注） */
		size_t i, nnon = 0;
		char st[96];

		if (!a->reg)
			return 1;
		for (i = 0; i < a->reg->nmodels; i++)
			if (a->reg->models[i].is_chat == 0)
				nnon++;
		a->show_nonchat = !a->show_nonchat;
		(void)cmd_models(a);	/* 重开列表反映过滤态（选择复位） */
		if (a->show_nonchat)
			snprintf(st, sizeof(st),
				 L_("已显示全部（非对话 %zu 条 dim 标注）"), nnon);
		else
			snprintf(st, sizeof(st),
				 L_("非对话 %zu 条已隐藏（默认过滤）"), nnon);
		tui_view_overlay_status(a->view, st, 0);
		return 0;
	}
	if (!strcmp(action, "model.favorite")) {
		size_t mi;
		const occ_reg_model *rm;
		int on;

		if (!a->reg || idx < 0 || (size_t)idx >= a->ov_map_n)
			return 1;
		mi = a->ov_map[idx];
		if (mi == OV_MAP_NONE || mi >= a->reg->nmodels)
			return 1;
		rm = &a->reg->models[mi];
		on = occ_registry_toggle_favorite(a->reg, rm->provider,
						  rm->id);
		(void)occ_state_save(a->reg, a->state_path);
		(void)cmd_models(a);	/* 重开列表反映 *（选择复位——取舍） */
		tui_view_overlay_status(a->view,
					 on ? L_("* 已收藏") : L_("已取消收藏"), 0);
		return 0;
	}
	return 1;
}

/* Esc 关面板：向导态整体作废（key 即刻清零——不留在工作集） */
static void tui_app_on_overlay_close(void *ud, int ov_id)
{
	struct tui_app *a = ud;

	if (ov_id == OV_WIZ_MODEL || ov_id == OV_WIZ_PROVIDER ||
	    ov_id == OV_WIZ_BASE || ov_id == OV_WIZ_KEY)
		wiz_reset(a);		/* memset 含 key 清零 */
	if (ov_id == OV_W2) {
		/* O-9：Esc 关确认面板=拒绝（唤醒在途 worker） */
		pthread_mutex_lock(&a->mu);
		a->w2_verdict = 0;
		a->w2_answered = 1;
		pthread_cond_broadcast(&a->w2_cond);
		pthread_mutex_unlock(&a->mu);
	}
}

/*
 * 元数据行（T9c3 §3 公式同源）：主体 = `occ · model · ~12.3k/200k[*] ·
 * ~i… o… c… r–`，返回 pct=round(ctx/limit×100)（view 追加着色后缀）。
 * 分子 ctx=五项和（OCD §5.2 上下文占用）；分母=catalog context，
 * 未命中兜底 200k 标 `*`（进屏 notice 注明）；rea 无独立位 → r–。
 */
static int tui_app_fill_meta(void *ud, char *buf, size_t cap)
{
	struct tui_app *a = ud;
	long long in, out, cr, cw, tok, lim;
	int est, fb;
	char t1[24], t2[24], items[96];

	pthread_mutex_lock(&a->mu);
	in = a->u_in;
	out = a->u_out;
	cr = a->u_cr;
	cw = a->u_cw;
	est = a->u_est;
	lim = a->ctx_limit;
	fb = a->ctx_fallback;
	pthread_mutex_unlock(&a->mu);
	tok = tui_usage_ctx(in, out, cr, cw, -1);
	tui_usage_fmt(tok, t1, sizeof(t1));
	tui_usage_fmt(lim, t2, sizeof(t2));
	tui_usage_items(items, sizeof(items), in, out, cr + cw, -1, est);
	snprintf(buf, cap, "occ · %s · %s%s/%s%s · %s", a->p.model,
		 est ? "~" : "", t1, t2, fb ? "*" : "", items);
	return tui_usage_pct(tok, lim);
}

static int tui_app_fill_status(void *ud, char *buf, size_t cap)
{
	struct tui_app *a = ud;
	const char *base = strrchr(a->cwd, '/');

	base = (base && base[1]) ? base + 1 : a->cwd;
	/* 裁定 10：cwd:branch，branch 简化为仓库名=cwd 末段（不接 git） */
	return snprintf(buf, cap, "%s:%s", a->cwd, base);
}

/* ---- UXAB A+B：顶栏 + 图形化 footer 供数 ---- */

/* 模型厂商标签（catalog 按 model id 查 provider；未命中留空=只显模型名）。
 * 仅主线程调用（与 app_resolve_ctx 同批：启动 /models 切换 / 向导保存） */
static void app_update_model_prov(struct tui_app *a)
{
	const occ_catalog_model *m = NULL;

	a->model_prov[0] = '\0';
	app_load_catalog(a);
	if (!a->cat || a->cat->nmodels == 0)
		return;
	m = occ_catalog_find(a->cat, NULL, a->p.model);
	if (!m) {
		const occ_catalog_model *hits[4];
		size_t nh = occ_catalog_search(a->cat, a->p.model, 0, hits, 4);

		if (nh >= 1)
			m = hits[0];
	}
	if (m)
		snprintf(a->model_prov, sizeof(a->model_prov), "%.40s",
			 m->provider);
}

/* 顶栏：title=当前会话标题（缓存——worker/切换/改名点写）；model=
 * `glm-5.3 · zhipu`（厂商未命中=仅模型名）。每帧拉取：只做互斥+拷贝 */
static void tui_app_fill_topbar(void *ud, char *title, size_t tcap,
				char *model, size_t mcap)
{
	struct tui_app *a = ud;

	pthread_mutex_lock(&a->mu);
	snprintf(title, tcap, "%.95s", a->session_title);
	pthread_mutex_unlock(&a->mu);
	if (a->model_prov[0])
		snprintf(model, mcap, "%.60s · %s", a->p.model, a->model_prov);
	else
		snprintf(model, mcap, "%.60s", a->p.model);
}

/* footer 结构化供数：ctx/pct 公式与旧 fill_meta 同源（tui_usage_ctx/
 * tui_usage_pct——OCD §5.2 五项和口径不变，纯展示层换图形） */
static void tui_app_fill_usage(void *ud, struct tui_footer *out)
{
	struct tui_app *a = ud;
	long long in, out2, cr, cw, tok, lim;
	int est, fb;

	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	pthread_mutex_lock(&a->mu);
	in = a->u_in;
	out2 = a->u_out;
	cr = a->u_cr;
	cw = a->u_cw;
	est = a->u_est;
	lim = a->ctx_limit;
	fb = a->ctx_fallback;
	pthread_mutex_unlock(&a->mu);
	{
		const char *tier_s = L_("受限");

		/* P-45：档标以会话提权态优先（特权*=唯一提权标记；星位
		 * 独占——ctx fallback 星已挪往水位段，不再拼档标后）；
		 * g_w2_ready=0（未初始化）安全兜底「受限」而非旧判特权 */
		if (a->su.elevated)
			tier_s = L_("特权*");
		else if (g_w2_ready &&
			 g_w2.tier == OCC_W2_TIER_PRIVILEGED)
			tier_s = L_("特权");
		else if (g_w2_ready &&
			 g_w2.tier == OCC_W2_TIER_CONFIRMED)
			tier_s = L_("确认");
		snprintf(out->model, sizeof(out->model), "%.44s · %s",
			 a->p.model, tier_s);
	}
	snprintf(out->cwd, sizeof(out->cwd), "%.150s", a->cwd);
	out->in = in;
	out->out = out2;
	out->cache_read = cr;
	tok = tui_usage_ctx(in, out2, cr, cw, -1);
	out->pct = tui_usage_pct(tok, lim);
	out->est = est;
	out->fallback = fb;
}

static void tui_app_fill_sessions(void *ud, tui_sb_data *out)
{
	struct tui_app *a = ud;
	occ_session_row *rows = NULL;
	size_t n = 0, i;
	char e[160];
	char cur[OCC_ID_LEN];
	long long in, out2, cr, cw, tok, lim;

	memset(out, 0, sizeof(*out));
	pthread_mutex_lock(&a->mu);
	snprintf(cur, sizeof(cur), "%s", a->session_id);
	in = a->u_in;
	out2 = a->u_out;
	cr = a->u_cr;
	cw = a->u_cw;
	lim = a->ctx_limit;
	pthread_mutex_unlock(&a->mu);
	/* c3 同源：侧栏底部与元数据行同一份 ctx 缓存（裁定 5）——
	 * 语义从「会话计费累计」改为「上下文占用」（OCD 侧栏口径） */
	tok = tui_usage_ctx(in, out2, cr, cw, -1);
	out->tokens_total = tok;
	out->pct = tui_usage_pct(tok, lim);

	if (occ_session_list(a->db, &rows, &n, e, sizeof(e)) != 0)
		return;
	for (i = 0; i < n && i < TUI_SB_MAX_ROWS; i++) {
		snprintf(out->rows[i].id, sizeof(out->rows[i].id), "%s",
			 rows[i].id);
		snprintf(out->rows[i].title, sizeof(out->rows[i].title),
			 "%.95s", rows[i].title);
		out->rows[i].tokens = rows[i].tokens_total;
		snprintf(out->rows[i].status, sizeof(out->rows[i].status),
			 "%s", rows[i].status);
		out->rows[i].is_current =
			cur[0] && !strcmp(cur, rows[i].id);
	}
	out->n = (int)i;
	/* T1：真值总数（>n 时侧栏末行显示 `⋯ +N 个（/sessions）`） */
	out->total = n > (size_t)0x7fffffff ? 0x7fffffff : (int)n;
	free(rows);
	/* E8：任务摘要行计数（occ_task_list_recent 真值；零任务=
	 * tasks_n=0 → 侧栏不渲染该行——零扰动） */
	{
		occ_task_row *tr = NULL;
		size_t tn = 0;
		int tot = 0, run = 0;

		if (occ_task_list_recent(a->db, NULL, 1, &tr, &tn, &tot,
					 &run, e, sizeof(e)) == 0) {
			out->tasks_n = tot;
			out->tasks_running = run;
			occ_task_rows_free(tr, tn);
		}
	}
}

static void tui_app_on_shutdown(void *ud)
{
	struct tui_app *a = ud;
	int live, wlive, rlive;

	pthread_mutex_lock(&a->mu);
	live = a->worker_live;
	wlive = a->wiz_thread_live;
	rlive = a->ren_thread_live;
	if (live || wlive || rlive)
		occ_interrupt_flag = 1;
	if (wlive)
		a->wiz_cancel = 1;
	if (rlive)
		a->ren_cancel = 1;
	pthread_mutex_unlock(&a->mu);
	if (live)
		(void)pthread_kill(a->worker, SIGINT);
	if (a->worker_created) {	/* join：等 worker 安全收口 */
		pthread_join(a->worker, NULL);
		a->worker_created = 0;
	}
	if (rlive)
		(void)pthread_kill(a->ren_thread, SIGINT);
	if (a->ren_thread_created) {	/* B8：标题生成线程同理 */
		pthread_join(a->ren_thread, NULL);
		a->ren_thread_created = 0;
	}
	if (wlive)
		(void)pthread_kill(a->wiz_thread, SIGINT);
	if (a->wiz_thread_created) {	/* 向导验证线程同理（OCC-DEBT） */
		pthread_join(a->wiz_thread, NULL);
		a->wiz_thread_created = 0;
	}
	/* mutex/prompt 由 run_interactive 收尾（enter 早退路径也要清） */
}

/* P-47：fbterm 转手吞掉子进程退出码（occ 退 71 → aik-console 只见
 * fbterm 的 0，O-1 退出即注销在 fb 链永不触发）——71 出带外：在
 * FBTERM env 门控（aik-console fb 分支同款 env）下写 marker 文件，
 * 由 aik-console v8 在 rc 判定链之前消费（读后即焚）。serial/ssh 链
 * 无 FBTERM env：rc 直达，零动作。
 * 70（/zoom）不写：fb 循环内重启而非终局退出，marker 会被
 * aik-console 当作本轮退出消费、污染下一轮判定。
 * OCC_EXIT_MARKER 仅测试用（指 /tmp 文件）；生产不设——缺省
 * /run/aik-occ-exit（VM /run 为 tmpfs 可写；不可写回落 /tmp 同名）。
 * 写失败只 stderr 警告，绝不影响退出码本身。 */
static void tui_exit_marker(int code)
{
	const char *fb = getenv("FBTERM");
	const char *path;
	FILE *fp;

	if (code == 70)
		return;			/* /zoom：非终局退出不出带外 */
	if (!fb || !fb[0])
		return;
	path = getenv("OCC_EXIT_MARKER");
	if (!path || !path[0])
		path = "/run/aik-occ-exit";
	fp = fopen(path, "w");
	if (!fp && !strcmp(path, "/run/aik-occ-exit")) {
		path = "/tmp/aik-occ-exit";	/* /run 不可写回落 */
		fp = fopen(path, "w");
	}
	if (!fp) {
		fprintf(stderr, L_("occ: 退出 marker 写失败（%s）\n"), path);
		return;
	}
	fprintf(fp, "%d\n", code);
	fclose(fp);
}

/* O-13：模型 last-used 持久化（读侧）——state.json last_model 键
 * 存在且仍在注册表（可直调 toml 槽位）→ 恢复为启动模型；坏
 * JSON/缺失/仅目录条目（无 key 不可直调）→ 静默回出厂默认。
 * 写侧=occ_registry_touch + occ_state_save（/models 选择生效
 * 与向导保存两路径已接）。headless 不经此——p-smoke 字节不变。 */
static void app_restore_last_model(struct tui_app *a)
{
	occ_registry *r;
	const occ_reg_model *rm;
	char key[OCC_REG_KEY_MAX];
	char *slash;

	if (occ_state_last_model(a->state_path, key, sizeof(key)) != 0)
		return;
	slash = strchr(key, '/');
	if (!slash)
		return;
	*slash = '\0';
	r = calloc(1, sizeof(*r));
	if (!r)
		return;
	if (occ_registry_init(r) != 0) {
		free(r);
		return;
	}
	occ_registry_build(r, a->cfg_ok ? &a->cfg : NULL, a->cat);
	rm = occ_registry_find(r, key, slash + 1);
	if (rm && rm->source == OCC_REG_SRC_TOML && rm->slot_id[0]) {
		occ_provider np;

		if (occ_provider_resolve(&a->cfg, rm->slot_id, &np) == 0) {
			occ_provider_free(&a->p);
			a->p = np;
		}
	}
	occ_registry_free(r);
	free(r);
}

static int run_interactive(occ_db *db, const char *model_toml,
			   const char *provider_toml)
{
	struct tui_app a;
	tui_view_hooks h;
	int rc;

	memset(&a, 0, sizeof(a));
	a.db = db;
	pthread_mutex_init(&a.mu, NULL);
	pthread_cond_init(&a.w2_cond, NULL);	/* O-9：W2 应答 */
	if (!getcwd(a.cwd, sizeof(a.cwd)))
		a.cwd[0] = '\0';
	else
		occ_workdir_resolve(a.cwd, sizeof(a.cwd),
				    &a.workdir_fb);	/* O-6：拒绝面回退 */
	snprintf(a.model_toml, sizeof(a.model_toml), "%s", model_toml);
	snprintf(a.provider_toml, sizeof(a.provider_toml), "%s",
		 provider_toml);
	{
		const char *home = getenv("HOME");

		if (home && home[0])
			snprintf(a.state_path, sizeof(a.state_path),
				 "%s/.occ/state.json", home);
		else
			snprintf(a.state_path, sizeof(a.state_path), "%s",
				 "/nonexistent/state.json");
	}
	occ_provider_config_init(&a.cfg);
	/* c3：cfg 常驻（/models 切换与向导 reload 都用它）；初始解析失败
	 * 在进屏前报错（stderr 仍正常终端）——与 headless 同口径。 */
	if (occ_provider_load_all(&a.cfg, model_toml, provider_toml)) {
		fprintf(stderr, "occ: model config unreadable: %s\n",
			model_toml);
		occ_provider_config_free(&a.cfg);
		pthread_mutex_destroy(&a.mu);
		pthread_cond_destroy(&a.w2_cond);	/* O-9：W2 应答 */
		return 1;
	}
	a.cfg_ok = 1;
	/* O-3（LT-1 踩坑）：坏段诊断取首条缓存（load_all 已逐条 stderr；
	 * TUI 进屏后 stderr 不可见，首条须进首屏 notice） */
	if (a.cfg.nslot_diag > 0) {
		if (a.cfg.nslot_diag > 1)
			snprintf(a.cfg_warn, sizeof(a.cfg_warn),
				 L_("%s（另有 %zu 段同类告警）"),
				 a.cfg.slot_diag[0],
				 a.cfg.nslot_diag - 1);
		else
			snprintf(a.cfg_warn, sizeof(a.cfg_warn), "%s",
				 a.cfg.slot_diag[0]);
	}
	{
		const char *slot = NULL;
		size_t i;

		for (i = 0; i < a.cfg.nslots; i++) {
			if (!strcmp(a.cfg.slots[i].id, "cloud")) {
				slot = "cloud";
				break;
			}
		}
		if (!slot && a.cfg.nslots > 0)
			slot = a.cfg.slots[0].id;
		if (!slot || occ_provider_resolve(&a.cfg, slot, &a.p) != 0) {
			fprintf(stderr, "occ: resolve slot `%s' failed\n",
				slot ? slot : "(none)");
			occ_provider_config_free(&a.cfg);
			pthread_mutex_destroy(&a.mu);
			return 1;
		}
	}
	/* catalog 分母（exe 锚定搜索链；未命中 → 200k* 进屏 notice） */
	app_load_catalog(&a);
	app_restore_last_model(&a);	/* O-13：last-used 恢复先于 ctx */
	app_resolve_ctx(&a);
	app_update_model_prov(&a);		/* UXAB：顶栏厂商标签 */
	a.replay_budget = app_replay_lines_budget();	/* T2：增量加载初值 */

	/* T4 登录门：仅交互 TUI 形态走到此处（-p/headless 不经 run_interactive）；
	 * 旁路 ai.skipgate=1；未解锁返回=occ 退出（外层包装重启仍锁定） */
	if (tui_gate_enter() != 0) {
		occ_provider_config_free(&a.cfg);
		free(a.cat);
		occ_provider_free(&a.p);
		pthread_mutex_destroy(&a.mu);
		return 1;
	}

	memset(&h, 0, sizeof(h));
	h.ud = &a;
	h.on_entered = tui_app_on_entered;
	h.on_submit = tui_app_on_submit;
	h.on_interrupt = tui_app_on_interrupt;
	h.on_command = tui_app_on_command;
	h.fill_meta = tui_app_fill_meta;
	h.fill_status = tui_app_fill_status;
	h.fill_topbar = tui_app_fill_topbar;	/* UXAB A+B：顶栏 */
	h.fill_usage = tui_app_fill_usage;	/* UXAB A+B：图形 footer */
	/* O-9/O-10（UX-O §2/§3）：W2 门接交互面（worker 请求→view 面板
	 * →on_overlay_submit/close 应答；/su 提权改 g_w2.tier） */
	if (g_w2_ready) {
		g_w2.confirm = tui_w2_confirm;
		g_w2.ud = &a;
	}
	h.fill_sessions = tui_app_fill_sessions;
	h.on_shutdown = tui_app_on_shutdown;
	h.on_overlay_submit = tui_app_on_overlay_submit;
	h.on_overlay_input = tui_app_on_overlay_input;
	h.on_overlay_key = tui_app_on_overlay_key;
	h.on_overlay_close = tui_app_on_overlay_close;
	h.on_async_result = tui_app_on_async_result;	/* OCC-DEBT */
	h.on_load_more = tui_app_on_load_more;		/* T2：到顶增量加载 */
	h.on_tick = tui_app_on_tick;			/* E8：/tasks 面板轮询 */

		/* T9e：view 生命周期循环——/shell 退屏跑 bash 后重建 view 续跑。
		 * ctx_fallback 提示只在首屏发一次（每轮重发会刷屏）。 */
		{
			int first_screen = 1;

			for (;;) {
				a.view = tui_view_create(&h);
				if (!a.view) {
					fprintf(stderr,
						"occ: TUI init failed\n");
					occ_provider_config_free(&a.cfg);
					free(a.cat);
					occ_provider_free(&a.p);
					pthread_mutex_destroy(&a.mu);
					return 1;
				}
				/* UXAB：assistant 块头标签=当前模型名
				 *（/shell 往返重建 view 后也要重设） */
				tui_view_set_assist_label(a.view, a.p.model);
				if (first_screen) {
					/* O-3：坏段诊断首条（model.toml 段
					 * 缺/错键——LT-1 无声丢弃坑）进
					 * 首屏 notice；空=全合法零输出 */
					if (a.cfg_warn[0])
						(void)tui_view_post(
							a.view,
							TUI_VIEW_NOTICE,
							a.cfg_warn, 0,
							NULL, 0);
					/* O-6：cwd 命中沙箱拒绝面→workdir 已
					 * 回退 /var/ai/work（首发 bash 可用） */
					if (a.workdir_fb)
						(void)tui_view_post(
							a.view,
							TUI_VIEW_NOTICE,
							L_("workdir 回退 /var/ai/work（cwd 不可挂沙箱）"),
							0, NULL, 0);
					if (a.ctx_fallback) {
						char nb[320];

						/* O-5：侧栏两行降一行短句（保留「兜底 200k*」
						 * 语义与 meta 的 * 标记） */
						snprintf(nb, sizeof(nb),
							 "%s", L_("catalog 未命中/不可读：context 分母兜底 200k*（OCC_CATALOG 可指 models.dev 快照）"));
						(void)tui_view_post(a.view,
								     TUI_VIEW_NOTICE,
								     nb, 0, NULL, 0);
					}
					first_screen = 0;
				}
				rc = tui_view_run(a.view);	/* enter → 循环 → shutdown → leave */
				tui_view_destroy(a.view);
				a.view = NULL;
				/* on_shutdown 已 join worker（若在 run 内走过循环）；enter 早退时
				 * worker 不可能存在（submit 只在循环里发生）。此处统一收尾： */
				if (a.worker_created) {
					pthread_join(a.worker, NULL);
					a.worker_created = 0;
				}
				if (a.wiz_thread_created) {	/* OCC-DEBT 同口径 */
					occ_interrupt_flag = 1;
					pthread_kill(a.wiz_thread, SIGINT);
					pthread_join(a.wiz_thread, NULL);
					a.wiz_thread_created = 0;
					pthread_mutex_lock(&a.mu);
					a.wiz_thread_live = 0;
					pthread_mutex_unlock(&a.mu);
				}
				if (a.ren_thread_created) {	/* B8 同口径 */
					occ_interrupt_flag = 1;
					pthread_kill(a.ren_thread, SIGINT);
					pthread_join(a.ren_thread, NULL);
					a.ren_thread_created = 0;
					pthread_mutex_lock(&a.mu);
					a.ren_thread_live = 0;
					pthread_mutex_unlock(&a.mu);
				}
				if (g_t4_exit_code)
					break;
				/* P-41/P-44：rc=72（tui_view_run 输出看门狗/IO
				 * 自退）随 rc!=0 在此直接 break 到进程退出
				 * （return rc=72）——/shell/theme 重建环绝不
				 * 拦截它：72 的语义就是「消费端楔死，重启整
				 * 链」（aik-console v7 sleep 2 循环自愈），
				 * 在坏终端上重建 view 只会再挂一次。 */
				if ((rc != 0 || !a.shell_req) && !g_t4_theme_req)
					break;
				/* T4 /theme：热重载=重建 view 重读 theme.ini */
				if (g_t4_theme_req) {
					g_t4_theme_req = 0;
					continue;
				}
				/* /shell：fork 交互 bash（继承 tty；bash 自管 termios），
				 * exit 后回到循环重建 view——plan §1.9 /shell→bash→occ */
				a.shell_req = 0;
				{
					pid_t pid = fork();

					if (pid == 0) {
						execl("/bin/bash", "bash",
						      (char *)NULL);
						execl("/bin/sh", "sh",
						      (char *)NULL);
						_exit(127);
					}
					if (pid > 0) {
						int st;

						while (waitpid(pid, &st, 0) <
						       0 && errno == EINTR)
							;
					}
				}
			}
		}
		free(a.prompt);
		free(a.ov_map);
		free(a.ov_rows);
		if (a.reg)
			occ_registry_free(a.reg);
		free(a.reg);
		free(a.cat);
		occ_provider_config_free(&a.cfg);
		pthread_mutex_destroy(&a.mu);
		pthread_cond_destroy(&a.w2_cond);	/* O-9：W2 应答 */
			occ_provider_free(&a.p);
		if (g_t4_exit_code) {
			/* P-47：显式终局退出码出带外（70=/zoom 在助手内判
			 * 掉——循环内重启非终局，防污染下一轮消费） */
			tui_exit_marker(g_t4_exit_code);
			return g_t4_exit_code;
		}
		/* O-1（UX-O §1）：用户主动退出 TUI=注销语义（aik-console v6
		 * 见 71 断链回 login 面；SSH/pts 下落回 shell 无害） */
		if (rc == 0) {
			/* P-47：71 经 fbterm 转手被吞——marker 出带外给
			 * aik-console v8 消费；serial/ssh 无 FBTERM=零动作 */
			tui_exit_marker(71);
			return 71;
		}
		return (rc < 0) ? 1 : rc;
	}

int main(int argc, char **argv)
{
	const char *model_toml, *provider_toml, *db_path;
	occ_db *db;
	occ_provider p;
	char err[512];
	int rc = 2;
	int want_tui = 0;

	memset(&p, 0, sizeof(p));
	tui_lang_init_env();	/* O-20 A：OCC_LANG=en|zh（缺省 zh）——
				 * 必须先于一切 L_() 消费点 */
	if (argc < 2) {
		/* T9c2 交互入口：tty → 全屏 TUI；非 tty → 人话报错 rc=2 */
		if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
			want_tui = 1;
		} else {
			fputs(L_("occ: 交互模式需要 TTY（stdout/stdin 非 tty）；headless 请用 occ -p \"<prompt>\"\n"), stderr);
			return 2;
		}
	}
	model_toml = env_or("OCC_MODEL_TOML", NULL);
	if (!model_toml) {
		static char mbuf[512];
		const char *home = getenv("HOME");

		if (!home) {
			fprintf(stderr, "occ: no HOME\n");
			return 2;
		}
		snprintf(mbuf, sizeof(mbuf), "%s/.aikernel/model.toml", home);
		model_toml = mbuf;
	}
	provider_toml = env_or("OCC_PROVIDER_TOML", NULL);
	if (!provider_toml) {
		static char pbuf[512];
		const char *home = getenv("HOME");

		snprintf(pbuf, sizeof(pbuf), "%s/.aikernel/provider.toml",
			 home ? home : "");
		provider_toml = pbuf;
	}
	db_path = env_or("OCC_DB", NULL);

	db = occ_db_open(db_path, err, sizeof(err));
	if (!db) {
		fprintf(stderr, "occ: %s\n", err);
		return 1;
	}
	/* O-10（UX-O §3）：policy 档位初始化（AIKERNEL_POLICY/
	 * /etc/aikernel/policy.conf；解析失败安全回落 restricted） */
	{
		enum ai_policy_mode m;

		(void)ai_policy_init(NULL);
		m = ai_policy_mode_for_uid(getuid());
		g_w2_base_tier = (m == AI_POLICY_MODE_PRIVILEGED) ?
			OCC_W2_TIER_PRIVILEGED :
			(m == AI_POLICY_MODE_CONFIRMED) ?
			OCC_W2_TIER_CONFIRMED : OCC_W2_TIER_RESTRICTED;
		g_w2.tier = g_w2_base_tier;
		g_w2_ready = 1;
	}
	/* E3：编排开关开才建运行时（默认关=零开销零行为变化） */
	if (occ_orch_tools_enabled()) {
		g_orch = occ_orch_new(db);
		if (!g_orch)
			fputs(L_("occ: 警告：编排运行时初始化失败——task 工具本次不可用\n"), stderr);
	}
	if (want_tui) {
		rc = run_interactive(db, model_toml, provider_toml);
		goto out;
	}
	/* T4：观感 CLI（脚本/键盘受限环境的可靠通道；与 TUI /theme /zoom 同源） */
	if (!strcmp(argv[1], "theme") && argc == 3) {
		const struct tui_theme_preset *p = tui_theme_preset_find(argv[2]);
		char path[512];
		const char *home = getenv("HOME");
		const char *env = getenv("OCC_THEME");

		if (!p) {
			fprintf(stderr, "occ: unknown theme '%s' "
				"(default/amber/green/paper/mono)\n", argv[2]);
			return 2;
		}
		if (env && env[0])
			snprintf(path, sizeof(path), "%s", env);
		else
			snprintf(path, sizeof(path), "%s/.occ/theme.ini",
				 home && home[0] ? home : "/root");
		if (tui_theme_write_ini(path, p) != 0) {
			fprintf(stderr, "occ: write %s failed\n", path);
			return 1;
		}
		printf("theme written: %s -- active on next occ start\n",
		       p->name);
		return 0;
	}
	if (!strcmp(argv[1], "zoom") && argc == 3) {
		int v = atoi(argv[2]);
		int idx = v > 0 ? occ_zoom_index(v) : -1;
		char path[512], err[128];
		const char *home = getenv("HOME");

		if (idx < 0) {
			fprintf(stderr, "occ: bad size "
				"(levels: 12/16/20/24/28/32/40)\n");
			return 2;
		}
		snprintf(path, sizeof(path), "%s/.fbtermrc",
			 home && home[0] ? home : "/root");
		err[0] = '\0';
		if (occ_zoom_edit_fbtermrc(path, occ_zoom_size(idx),
					   err, sizeof(err)) != 0) {
			fprintf(stderr, "occ: %s\n", err[0] ? err : "write failed");
			return 1;
		}
		printf("font-size written: %dpx -- takes effect on fbterm "
		       "console restart\n", occ_zoom_size(idx));
		return 0;
	}
	if (!strcmp(argv[1], "sessions")) {
		rc = cmd_sessions(db);
		goto out;
	}
	if (!strcmp(argv[1], "tasks")) {
		/* E8：任务列表子命令（ORCH §7）；标志任意位置：
		 * --session <id> 过滤 + --json 机读 JSONL */
		const char *sid = NULL;
		int as_json = 0;
		int i;

		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "--session")) {
				if (i + 1 >= argc) {
					fprintf(stderr, "occ tasks: --session"
						" missing value\n");
					rc = 2;
					goto out;
				}
				sid = argv[++i];
			} else if (!strcmp(argv[i], "--json")) {
				as_json = 1;
			} else {
				fprintf(stderr, "occ tasks: unknown option"
					" '%s'\n", argv[i]);
				rc = 2;
				goto out;
			}
		}
		rc = cmd_tasks(db, sid, as_json);
		goto out;
	}
	if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
		fputs(L_(USAGE), stdout);
		rc = 0;
		goto out;
	}
	if (!strcmp(argv[1], "--recover")) {
		const char *id = argc > 2 ? argv[2] : NULL;
		const char *prompt = argc > 3 ? argv[3] : NULL;

		if (!id) {
			fprintf(stderr, "occ --recover: missing <id>\n");
			rc = 2;
			goto out;
		}
		if (resolve_provider(model_toml, provider_toml, &p, err,
				     sizeof(err))) {
			fprintf(stderr, "occ: %s\n", err);
			rc = 1;
			goto out;
		}
		rc = cmd_recover(db, &p, id, prompt);
		occ_provider_free(&p);
		goto out;
	}
	if (!strcmp(argv[1], "undo") || !strcmp(argv[1], "redo") ||
	    !strcmp(argv[1], "retry") || !strcmp(argv[1], "unstuck")) {
		/* 标志任意位置：--session <id>（undo 另有 --step N） */
		const char *cmd = argv[1];
		const char *sid = NULL;
		int steps = 1;
		int i;

		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "--help") ||
			    !strcmp(argv[i], "-h")) {
				/* O-23：子命令 --help=用法帮助（标准惯例 rc=0；
				 * 旧行为当 unexpected argument 报错 rc=2） */
				printf(L_("用法：occ %s --session <id>%s\n"), cmd,
				       !strcmp(cmd, "undo") ? " [--step N]" : "");
				rc = 0;
				goto out;
			}
			if (!strcmp(argv[i], "--session")) {
				if (i + 1 >= argc) {
					fprintf(stderr, "occ %s: --session"
						" missing value\n", cmd);
					rc = 2;
					goto out;
				}
				sid = argv[++i];
			} else if (!strcmp(argv[i], "--step")) {
				char *end = NULL;
				long v;

				if (i + 1 >= argc) {
					fprintf(stderr, "occ %s: --step"
						" missing value\n", cmd);
					rc = 2;
					goto out;
				}
				v = strtol(argv[++i], &end, 10);
				if (end == argv[i] || *end != '\0' ||
				    v < 1 || v > 100000) {
					fprintf(stderr, L_("occ %s: --step 须为 ≥1 的整数\n"), cmd);
					rc = 2;
					goto out;
				}
				steps = (int)v;
			} else {
				fprintf(stderr, "occ %s: unexpected argument"
					" `%s'\n", cmd, argv[i]);
				rc = 2;
				goto out;
			}
		}
		if (!sid) {
			fprintf(stderr, L_("occ %s: --session <id> 必需\n"), cmd);
			rc = 2;
			goto out;
		}
		if (!strcmp(cmd, "undo")) {
			rc = cmd_undo(db, sid, steps);
			goto out;
		}
		if (!strcmp(cmd, "redo")) {
			rc = cmd_redo(db, sid);
			goto out;
		}
		/* P-48 unstuck：只归位库状态，无需 provider */
		if (!strcmp(cmd, "unstuck")) {
			rc = cmd_unstuck(db, sid);
			goto out;
		}
		/* retry 需要 provider（重发要过 LLM） */
		if (resolve_provider(model_toml, provider_toml, &p, err,
				     sizeof(err))) {
			fprintf(stderr, "occ: %s\n", err);
			rc = 1;
			goto out;
		}
		rc = cmd_retry(db, &p, sid);
		occ_provider_free(&p);
		goto out;
	}
	if (!strcmp(argv[1], "-p")) {
		/* T9a3 亲验补丁：标志位任意位置；首个非标志=提示词；
		 * 第二个非标志响亮报错（不静默吞参数——红线）。 */
		const char *prompt = NULL;
		const char *session_id = NULL;
		int allow_w2 = 0;
		int i;

		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "--allow-w2")) {
				/* O-9（UX-O §2）：headless W2 显式开门 */
				allow_w2 = 1;
			} else if (!strcmp(argv[i], "--session")) {
				if (i + 1 >= argc) {
					fprintf(stderr, "occ -p: --session missing value\n");
					rc = 2;
					goto out;
				}
				session_id = argv[++i];
			} else if (!prompt && argv[i][0] == '-' &&
				   argv[i][1] == '-') {
				/* O-23：-- 开头且非已知标志（--allow-w2/--session
				 * 已在前分支消费）占提示词位——疑似 flag 误当提示词：
				 * 拒绝（rc=2），不发起模型调用 */
				fprintf(stderr, L_("occ -p: `%s' 不是已知标志——疑似 flag 误当提示词（已知：--allow-w2 / --session <id>）\n"),
					argv[i]);
				rc = 2;
				goto out;
			} else if (!prompt) {
				prompt = argv[i];
			} else {
				fprintf(stderr, "occ -p: unexpected argument `%s'\n",
					argv[i]);
				rc = 2;
				goto out;
			}
		}
		if (!prompt) {
			fprintf(stderr, "occ -p: missing prompt\n");
			rc = 2;
			goto out;
		}
		if (session_id) {
			occ_session_row s;

			if (occ_session_get(db, session_id, &s, err,
					    sizeof(err)) != 1) {
				fprintf(stderr, "occ: session %s not found\n",
					session_id);
				rc = 1;
				goto out;
			}
		}
		if (resolve_provider(model_toml, provider_toml, &p, err,
				     sizeof(err))) {
			fprintf(stderr, "occ: %s\n", err);
			rc = 1;
			goto out;
		}
		g_w2.allow_w2 = allow_w2;	/* O-9：--allow-w2（W2 门） */
		rc = run_turn(db, &p, session_id, prompt, 0);
		if (g_w2.denied > 0)
			fprintf(stderr, L_("occ: %d 次 W2 高危工具调用被拒（-p 默认拒绝；--allow-w2 显式开门）\n"),
				g_w2.denied);
		occ_provider_free(&p);
		goto out;
	}
	fprintf(stderr, "occ: unknown command `%s'\n", argv[1]);
	fputs(L_(USAGE), stderr);
	rc = 2;
out:
	occ_orch_free(g_orch);			/* E3：活子收尸+登记表清理 */
	occ_db_close(db);
	return rc;
}
