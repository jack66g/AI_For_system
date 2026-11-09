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
 *   occ sessions                         会话列表（id/标题/token/状态/时间）
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
 * 模型选择：a3 默认 model.toml [models.cloud] 槽位（L1 实况唯一云位，
 * dtchat 同源）；无 cloud 槽位时取首槽位。/models 切换是 c 棒（registry
 * 数据层 a2 已备）。
 */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
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
#include "occ_llm/occ_catalog.h"
#include "occ_llm/occ_registry.h"
#include "occ_tui/tui_data.h"
#include "occ_tui/tui_usage.h"
#include "occ_tui/tui_view.h"

static const char USAGE[] =
	"occ — AIKernel 编码助手（headless，T9a3+b2）\n"
	"用法：\n"
	"  occ -p \"<prompt>\" [--session <id>]   一次性对话（流式输出到 stdout）\n"
	"  occ --recover <id> [prompt]          重放中断环续跑 / 打开续接\n"
	"  occ undo --session <id> [--step N]   撤销最近 N 步（文件回滚+消息隐藏）\n"
	"  occ redo --session <id>              恢复上次 undo\n"
	"  occ retry --session <id>             重发最后一条 user 消息\n"
	"  occ sessions                         会话列表\n"
	"环境：OCC_MODEL_TOML / OCC_PROVIDER_TOML / OCC_DB / OCC_SNAPROOT 可覆盖；"
	" 交互模式另支持 OCC_REPLAY_LINES（历史回放行数预算，缺省 200，0=禁）\n";

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
	const char *slot = NULL;

	occ_provider_config_init(&cfg);
	if (occ_provider_load_all(&cfg, model_toml, provider_toml)) {
		snprintf(err, errlen,
			 "model config unreadable: %s", model_toml);
		occ_provider_config_free(&cfg);
		return -1;
	}
	for (size_t i = 0; i < cfg.nslots; i++) {
		if (!strcmp(cfg.slots[i].id, "cloud")) {
			slot = "cloud";
			break;
		}
	}
	if (!slot && cfg.nslots > 0)
		slot = cfg.slots[0].id;	/* 无 cloud 槽位：取首槽位 */
	if (!slot) {
		snprintf(err, errlen, "no model slots in %s", model_toml);
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
		return 0;
	}
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
	{
		/* b1：工具工作目录=occ 启动目录（glob/grep/bash rw 面） */
		static char cwd[4096];

		if (getcwd(cwd, sizeof(cwd)))
			opts.workdir = cwd;
	}
	sigint_install(&old_int);		/* b2：环内安全点中断 */
	rc = occ_loop_run(db, p, session_id, &opts, &res, err, sizeof(err));
	sigaction(SIGINT, &old_int, NULL);	/* 恢复默认（子命令期 Ctrl+C=杀） */
	if (rc == OCC_LOOP_OK || rc == OCC_LOOP_ETOOLS) {
		if (res.interrupted) {
			/* b2：安全点停——status=interrupted 已落库 */
			fputc('\n', stdout);
			fprintf(stderr, "occ: interrupted (safe point);"
				" session=%s status=interrupted\n"
				"occ: 用 `occ retry --session %s` 重发，"
				"或 `occ --recover %s` 续跑\n",
				res.session_id, session_id ? session_id :
				res.session_id, session_id ? session_id :
				res.session_id);
			occ_loop_result_free(&res);
			return 130;
		}
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
		const char *tag = r.files[i].failed ? "[失败] " :
				  r.files[i].action == OCC_UNDO_DELETE ?
				  "[删除] " : "[还原] ";

		if (r.files[i].failed)
			failed++;
		printf("  %s%s\n", tag, r.files[i].path);
	}
	if (r.user_text && r.user_text[0])
		printf("被撤输入（回填语义）：\n%s\n", r.user_text);
	printf("occ: 发送新消息即确认撤销（此后不可 redo）；"
	       "`occ redo --session %s` 可恢复\n", id);
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
		printf("  %s%s\n", r.files[i].failed ? "[失败] " : "[还原] ",
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
		fprintf(stderr, "occ retry: 没有可重发的 user 消息\n");
		return 1;
	}
	text = last_user.text ? strdup(last_user.text) : NULL;
	occ_msg_row_free(&last_user);
	if (!text) {
		fprintf(stderr, "occ retry: 最后一条 user 消息为空\n");
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

/* ---- T9c2 交互模式（全屏 TUI；headless 路径零改动） ---- */

/* T9c3 覆盖层 id（on_overlay_* 钩子按此分派） */
enum {
	OV_MODELS = 1,
	OV_SESSIONS = 2,
	OV_TOOLS = 3,
	OV_TRACE = 4,
	OV_LEASE = 5,
	OV_WIZ_MODEL = 11,		/* 向导 1/4 模型 */
	OV_WIZ_PROVIDER = 12,		/* 向导 2/4 provider */
	OV_WIZ_BASE = 13,		/* 向导 2.5 自定义 base_url（输入） */
	OV_WIZ_KEY = 14,		/* 向导 3/4 key（输入，mask） */
	OV_RENAME = 21			/* /rename 无参（输入） */
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
	char *prompt;			/* 本轮输入（主线程分配，worker 用） */
	char session_id[OCC_ID_LEN];	/* 当前会话；空=下条提交建新会话 */
	long long tokens_total;		/* 会话累计计费额（/status 展示） */
	long long ctx_limit;		/* catalog limit.context；缺省 200k */
	int ctx_fallback;		/* 1=catalog 未命中/不可读 → 200k* */
	char cwd[4096];			/* 启动目录（workdir + 状态行） */
	pthread_mutex_t mu;		/* session/tokens/prompt/worker_live */

	/* ---- c3：配置/目录/注册表（进程常驻；headless 不走此路径） ---- */
	char model_toml[512];
	char provider_toml[512];
	char state_path[512];		/* ~/.occ/state.json */
	occ_provider_config cfg;	/* 向导 reload + /models 切换用 */
	int cfg_ok;
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

	/* ---- OCC-DEBT：/models 非对话条目显隐（默认过滤；ctrl+t 切换） ---- */
	int show_nonchat;

	/* ---- c3：overlay 工作集（打开期间有效；换开重分配） ---- */
	size_t *ov_map;
	size_t ov_map_n;
	occ_session_row *ov_rows;	/* /sessions 行（提交期有效） */
	size_t ov_rows_n;
};

static uint64_t tui_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* k/M 档：已由 tui_usage_fmt 承担（c3 同源化；fmt_tok 退役） */

/* ===================== OCC-DEBT：TUI 历史回放 =====================
 * 偿还 T9C2 裁定 2（转写不回放历史）：进屏（/shell 往返）与 /sessions
 * 切换时，从 durable SQLite 读当前会话消息 → occ_replay_plan 圈尾部
 * （OCD §1.3 尾部挂载语义；行预算 OCC_REPLAY_LINES 缺省 200，0=禁）
 * → 逐条 tui_view_post 渲染进 scrollback。事件走既有队列，drain 在
 * 主循环——与 live 渲染完全同路（工具行/推理折叠/页脚形态不变）。
 * 运行中不回放（事件会插进 live 块）——诚实 notice，收口后切换可补。 */
static int app_replay_lines_budget(void)
{
	const char *v = getenv("OCC_REPLAY_LINES");
	long n;
	char *end = NULL;

	if (!v || !v[0])
		return 200;
	n = strtol(v, &end, 10);
	if (!end || *end != '\0' || n < 0 || n > 1000000)
		return 200;
	return (int)n;
}

static void app_replay_session(struct tui_app *a, const char *sid,
			       int clear_first)
{
	occ_msg_row *rows = NULL;
	occ_tc_row *tcs = NULL;
	occ_replay_item *plan = NULL;
	size_t n = 0, ntc = 0, nplan = 0, nearlier = 0, i;
	char e[160];
	int budget;
	int live;

	if (!sid || !sid[0])
		return;
	pthread_mutex_lock(&a->mu);
	live = a->worker_live;
	pthread_mutex_unlock(&a->mu);
	if (live) {
		tui_view_notice(a->view,
				"replay: turn 运行中——历史回放跳过（收口后"
				"重进 /sessions 可补）");
		return;
	}
	budget = app_replay_lines_budget();
	if (budget == 0)
		return;				/* 显式禁用（静默——配置意图） */
	if (occ_msg_list(a->db, sid, &rows, &n, e, sizeof(e)) != 0) {
		tui_view_notice(a->view, e);
		return;
	}
	(void)occ_toolcalls_since(a->db, sid, 0, &tcs, &ntc, NULL, 0);
	if (occ_replay_plan(rows, n, tcs, ntc, budget, &plan, &nplan,
			    &nearlier) != 0) {
		occ_msg_rows_free(rows, n);
		occ_tc_rows_free(tcs, ntc);
		tui_view_notice(a->view, "replay: 规划失败（OOM）");
		return;
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
				 "⋯ 更早 %d 条消息未回放（尾部 %d 行挂载）",
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
					    "OCC · 回放", 0, NULL, 0);
			break;
		default:
			break;
		}
	}
	free(plan);
	occ_tc_rows_free(tcs, ntc);
	occ_msg_rows_free(rows, n);
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

	t0 = tui_now_ms();
	rc = occ_loop_run(a->db, &a->p, sid[0] ? sid : NULL, &opts, &res,
			  err, sizeof(err));
	t1 = tui_now_ms();

	/* 会话/水位回写（/new 未动过才覆盖——防半途 /new 被撤销） */
	if (res.session_id[0]) {
		occ_session_row row;
		char e2[160];
		long long tok = 0;

		if (occ_session_get(a->db, res.session_id, &row, e2,
				    sizeof(e2)) == 1)
			tok = row.tokens_total;
		pthread_mutex_lock(&a->mu);
		if (!a->session_id[0] || !strcmp(a->session_id, res.session_id)) {
			snprintf(a->session_id, sizeof(a->session_id), "%s",
				 res.session_id);
			a->tokens_total = tok;
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
					    "interrupted (safe point);"
					    " status=interrupted — 下一条消息"
					    "将自动附续传注记", 0, NULL, 0);
			snprintf(footer, sizeof(footer), "OCC · interrupted");
		} else {
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
		snprintf(out, cap, "验证失败（无错误文本）");
		return;
	}
	if (strstr(e, "401") || strstr(e, "nauthorized") ||
	    strstr(e, "Invalid") || strstr(e, "invalid api"))
		snprintf(out, cap, "key 无效或未授权（401）——请检查 API key");
	else if (strstr(e, "402") || strstr(e, "429") ||
		 strstr(e, "nsufficient") || strstr(e, "quota") ||
		 strstr(e, "balance") || strstr(e, "余额"))
		snprintf(out, cap, "额度/余额不足（%.140s）", e);
	else if (strstr(e, "imeout") || strstr(e, "rc=28") ||
		 strstr(e, "ETIMEDOUT"))
		snprintf(out, cap,
			 "连接超时——检查 base_url/网络（%.140s）", e);
	else if (strstr(e, "404") || strstr(e, "Not Found") ||
		 strstr(e, "not found"))
		snprintf(out, cap, "端点不存在（404）——检查 base_url");
	else if (strstr(e, "400"))
		snprintf(out, cap,
			 "请求被拒（400）——模型名/参数不被接受（%.140s）",
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
				"models.dev 快照不可读——向导无法选模型"
				"（OCC_CATALOG 可指路径）");
		return;
	}
	cap = a->cat->nmodels;
	items = calloc(cap, sizeof(*items));
	if (!items || app_map_reserve(a, cap) != 0) {
		free(items);
		tui_view_notice(a->view, "向导：内存不足");
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
		tui_view_notice(a->view, "目录无可用 chat 模型");
		return;
	}
	(void)tui_view_open_list(a->view, OV_WIZ_MODEL,
				 "add key · 1/4 模型", items, (int)n, 1,
				 "输入过滤 · Enter=选择 · Esc=取消");
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
			 p == match ? "（模型厂商预设）" : "");
		items[i].flags = 0;
	}
	/* 自定义项 */
	snprintf(items[k].text, sizeof(items[k].text), "自定义 base_url…");
	snprintf(items[k].tag, sizeof(items[k].tag), "custom");
	snprintf(items[k].detail, sizeof(items[k].detail),
		 "手动输入端点（协议按 openai 兼容）");
	items[k].flags = 0;
	if (app_map_reserve(a, (size_t)k + 1) != 0) {
		tui_view_notice(a->view, "向导：内存不足");
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
					 "Enter=选择 · Esc=取消");
	}
}

static void wiz_open_base(struct tui_app *a)
{
	a->wiz.step = 2;
	(void)tui_view_open_input(a->view, OV_WIZ_BASE,
				  "add key · 2/4 base_url",
				  "端点 URL（https://…；协议按 openai 兼容）",
				  a->wiz.base_url[0] ? a->wiz.base_url : NULL,
				  0);
}

static void wiz_open_key(struct tui_app *a)
{
	a->wiz.step = 3;
	(void)tui_view_open_input(a->view, OV_WIZ_KEY,
				  "add key · 3/4 API key",
				  "粘贴 key（掩码显示；仅写 model.toml 600，"
				  "不入日志/报告）", NULL, 1);
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
					 "写入 model.toml 失败"
					 "（值含非法字符/路径不可写？）", 1);
		return;
	}
	/* reload cfg → 重建注册表 → 空闲则立即切换 */
	occ_provider_config_free(&a->cfg);
	occ_provider_config_init(&a->cfg);
	if (occ_provider_load_all(&a->cfg, a->model_toml, a->provider_toml)) {
		tui_view_overlay_status(a->view, "model.toml 重读失败", 1);
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
		}
	}
	if (a->reg) {
		occ_registry_touch(a->reg, a->wiz.slot, a->wiz.model_id);
		(void)occ_state_save(a->reg, a->state_path);
	}
	snprintf(msg, sizeof(msg),
		 "已保存 key（model.toml 600）并切换到 %.80s"
		 "（%s/%s）%s — 1-token 实测通过",
		 a->wiz.display[0] ? a->wiz.display : a->wiz.model_id,
		 a->wiz.slot, a->wiz.model_id,
		 a->worker_live ? "；turn 运行中，下轮生效" : "");
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
	 *（SIGINT 处理器全局），会误伤在途 turn；诚实留步。 */
	pthread_mutex_lock(&a->mu);
	live = a->worker_live || a->wiz_thread_live;
	pthread_mutex_unlock(&a->mu);
	if (live) {
		tui_view_overlay_status(a->view,
					a->worker_live ?
					"turn 运行中——Esc 中断或收口后再验证" :
					"验证已在进行中（Esc 取消）", 1);
		return;
	}
	c = calloc(1, sizeof(*c));
	if (!c) {
		tui_view_overlay_status(a->view, "向导：内存不足", 1);
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
		tui_view_overlay_status(a->view, "向导：内存不足", 1);
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
					"验证线程创建失败（稍后重试）", 1);
		return;
	}
	pthread_mutex_lock(&a->mu);
	a->wiz_thread_live = 1;
	pthread_mutex_unlock(&a->mu);
	a->wiz_thread_created = 1;
	tui_view_overlay_status(a->view,
				"验证中…（1-token 实测，Esc 取消）", 0);
	tui_view_set_busy(a->view, 1);	/* spinner 常刷 + Esc 改派 cancel */
}

/* 异步结果回投（主循环 drain；TUI_VIEW_ASYNC_RESULT） */
static void tui_app_on_async_result(void *ud, int rc, const char *text)
{
	struct tui_app *a = ud;

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
					"已取消——可修改 key 后回车重试", 0);
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
	size_t cap, n = 0, i;
	int rc = 0;

	app_load_reg(a);
	if (!a->reg || a->reg->nmodels == 0) {
		tui_view_notice(a->view,
				"models: 注册表为空（model.toml 与快照均不可用）");
		return 0;
	}
	cap = a->reg->nmodels + 128;	/* 分组头余量 */
	items = calloc(cap, sizeof(*items));
	fav = malloc((a->reg->nmodels + 1) * sizeof(*fav));
	rec = malloc((a->reg->nmodels + 1) * sizeof(*rec));
	all = malloc((a->reg->nmodels + 1) * sizeof(*all));
	if (!items || !fav || !rec || !all ||
	    app_map_reserve(a, cap) != 0) {
		rc = -1;
		goto out;
	}
	nfav = occ_registry_favorites(a->reg, fav, a->reg->nmodels);
	nrec = occ_registry_recents(a->reg, rec, a->reg->nmodels);
	nall = occ_registry_all_by_provider(a->reg, 0, all,
					    a->reg->nmodels);

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
				 "%s%.36s%s", f ? "★ " : "", \
				 (RM)->provider_name[0] ? \
				 (RM)->provider_name : (RM)->provider, \
				 (RM)->is_chat == 0 ? " ·非对话" : ""); \
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
				 "配置（可直调）" : \
				 ((RM)->source == OCC_REG_SRC_OLLAMA ? \
				  "本地 ollama" : \
				  "目录（需 key：ctrl+a 添加）")); \
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

	if (nfav) {
		PUSH_HEADER("Favorites");
		for (i = 0; i < nfav && n + 1 < cap; i++) {
			if (fav[i] < a->reg->nmodels)
				PUSH_MODEL(&a->reg->models[fav[i]]);
		}
	}
	if (nrec) {
		PUSH_HEADER("Recent");
		for (i = 0; i < nrec && n + 1 < cap; i++) {
			if (rec[i] < a->reg->nmodels)
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
		/* 全量被非对话过滤掏空：诚实说明而非谎报 OOM */
		tui_view_notice(a->view,
				"models: 匹配条目全部为非对话（默认隐藏）——"
				"ctrl+t 显示全部");
		goto out;
	}
	(void)tui_view_open_list(a->view, OV_MODELS, "models", items,
				 (int)n, 1,
				 "Enter=切换/接入 · ctrl+a key · ctrl+f ★ · "
				 "ctrl+t 非对话 · 过滤 · Esc=关闭");
out:
	if (rc != 0)
		tui_view_notice(a->view, "models: 构建列表失败（OOM）");
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
				 "Enter=切换并回放历史 · Esc=关闭");
	free(items);		/* overlay 已深拷贝；行数据留 ov_rows 待提交 */
	return 0;
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
				"tools.json 未找到——搜索链 AIKERNEL_TOOLS_JSON"
				" → ./tools.json → tools/tools.json → exe 目录 →"
				" /usr/local/share/aikernel/tools.json");
		return 0;
	}
	if (tui_data_tools_load(path, &items, &n, e, sizeof(e)) != 0) {
		tui_view_notice(a->view, e);
		return 0;
	}
	(void)tui_view_open_list(a->view, OV_TOOLS, "tools", items, n, 1,
				 "↑↓/PgUp/PgDn 导航 · Enter=详情行 · Esc=关闭");
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
		tui_view_notice(a->view, "trace: 无 HOME/OCC_TRACE_DIR");
		return 0;
	}
	if (tui_data_trace_load(dir, 200, &items, &n, e, sizeof(e)) != 0) {
		tui_view_notice(a->view, e);
		return 0;
	}
	if (n == 0) {
		tui_view_notice(a->view,
				"（无 trace 记录——工具执行审计落 ~/.occ/trace）");
		tui_data_items_free(items);
		return 0;
	}
	(void)tui_view_open_list(a->view, OV_TRACE, "trace（最近 200 条，"
				 "新在前）", items, n, 0,
				 "Enter=详情（args）· Esc=关闭");
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
		tui_view_notice(a->view, "lease: 路径解析失败");
		return 0;
	}
	if (tui_data_lease_load(dir, &items, &n, e, sizeof(e)) != 0) {
		tui_view_notice(a->view, e);
		return 0;
	}
	if (n == 0) {
		char nb[448];

		snprintf(nb, sizeof(nb),
			 "（无租约——目录 %.300s 为空/不存在；签发走系统命令，"
			 "occ 只读展示）", dir);
		tui_view_notice(a->view, nb);
		tui_data_items_free(items);
		return 0;
	}
	(void)tui_view_open_list(a->view, OV_LEASE, "lease", items, n, 0,
				 "Enter=详情（mission/scope）· Esc=关闭");
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
		 "sandbox: %.200s\n"
		 "  二进制: %.200s%s\n"
		 "  --rw-path 探测: %s\n"
		 "  euid=%d（0=可组装 namespace；非 0=沙箱将拒绝裸跑）\n"
		 "  写面: cwd 子树 ∪ /tmp ∪ /var/ai（~/.occ 拒绝）· "
		 "快照: ~/.occ/snapshots",
		 found ? bin : "(未找到)",
		 bin, found ? "" : "（不可执行/缺失）",
		 sup == 1 ? "支持" : sup == 0 ?
		 "不支持（版本过旧——重建 aik-sandbox）" :
		 "不可执行",
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
					"尚无会话——先发一条消息再 /rename");
			return 0;
		}
		if (occ_session_set_title(a->db, a->session_id, args, e,
					  sizeof(e)) != 0) {
			tui_view_notice(a->view, e);
			return 0;
		}
		snprintf(nb, sizeof(nb), "renamed → %.200s", args);
		tui_view_notice(a->view, nb);
		return 0;
	}
	/* 无参：输入覆盖层（预填现题） */
	{
		char initial[128];

		initial[0] = '\0';
		if (a->session_id[0]) {
			occ_session_row r;

			if (occ_session_get(a->db, a->session_id, &r, e,
					    sizeof(e)) == 1)
				snprintf(initial, sizeof(initial), "%.100s",
					 r.title);
		}
		(void)tui_view_open_input(a->view, OV_RENAME, "rename",
					  "新标题（Enter 提交；空=不支持，"
					  "AI 生成标题归后续棒）",
					  initial[0] ? initial : NULL, 0);
	}
	return 0;
}

/* ---- slash 命令分派 ---- */

static int tui_app_on_command(void *ud, const char *line)
{
	struct tui_app *a = ud;

	if (!strcmp(line, "/new")) {
		pthread_mutex_lock(&a->mu);
		a->session_id[0] = '\0';
		a->tokens_total = 0;
		a->u_in = a->u_out = a->u_cr = a->u_cw = 0;
		a->u_est = 0;
		pthread_mutex_unlock(&a->mu);
		tui_view_notice(a->view, "new session（下一条消息创建新会话）");
		return 0;
	}
	if (!strcmp(line, "/sessions"))
		return cmd_sessions_overlay(a);
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
					"compact: turn 运行中——收口后再 /compact");
			return 0;
		}
		if (!a->session_id[0]) {
			tui_view_notice(a->view,
					"compact: 尚无会话（先发一条消息）");
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
				"compact: 触发 autocondense 换窗"
				"（begin→digest→commit）…");
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
					"compact: 换窗完成——历史已折叠为摘要，"
					"token 账本重置为新基线（显示 ~ 为估算）");
		} else {
			snprintf(nb, sizeof(nb), "compact: %s",
				 err[0] ? err : "失败（ac 不可达或摘要未过校验）");
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
					"shell: turn 运行中——Esc 中断或收口后再 /shell");
			return 0;
		}
		a->shell_req = 1;
		tui_view_quit(a->view);
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
							 "busy — turn 运行中，"
							 "稍后再切换模型", 1);
				return 0;
			}
			if (occ_provider_resolve(&a->cfg, rm->slot_id,
						 &np) != 0) {
				tui_view_overlay_status(a->view,
							 "槽位解析失败"
							 "（model.toml 损坏？）",
							 1);
				return 0;
			}
			occ_provider_free(&a->p);
			a->p = np;
			app_resolve_ctx(a);
			occ_registry_touch(a->reg, rm->provider, rm->id);
			(void)occ_state_save(a->reg, a->state_path);
			tui_view_close_overlay(a->view);
			{
				char ctb[24];

				tui_usage_fmt(a->ctx_limit, ctb,
					      sizeof(ctb));
				snprintf(nb, sizeof(nb),
					 "model → %s/%s（ctx %s%s）",
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
			app_replay_session(a, r->id, 1);
			snprintf(nb, sizeof(nb),
				 "── switched to %.100s (%.14s…) ──",
				 r->title[0] ? r->title : "(untitled)", r->id);
			(void)tui_view_post(a->view, TUI_VIEW_NOTICE, nb,
					    strlen(nb), NULL, 0);
		} else {
			snprintf(nb, sizeof(nb),
				 "── switched to %.100s (%.14s…) ──",
				 r->title[0] ? r->title : "(untitled)", r->id);
			tui_view_notice(a->view, nb);
			tui_view_notice(a->view,
					"turn 运行中——历史回放待收口（重进"
					" /sessions 可补）");
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
						 "key 不能为空/过长（≤255）",
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
						 "base_url 须以 http:// 或 "
						 "https:// 开头", 1);
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
	if (ov_id == OV_RENAME) {
		char e[160];
		char nb[320];

		if (len == 0) {
			tui_view_overlay_status(a->view,
						 "空标题不支持（AI 生成标题"
						 "归后续棒）", 1);
			return 0;
		}
		if (!a->session_id[0]) {
			tui_view_overlay_status(a->view,
						 "尚无会话（先发一条消息）",
						 1);
			return 0;
		}
		if (occ_session_set_title(a->db, a->session_id, text, e,
					  sizeof(e)) != 0) {
			tui_view_overlay_status(a->view, e, 1);
			return 0;
		}
		snprintf(nb, sizeof(nb), "renamed → %.200s", text);
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

	/* OCC-DEBT：busy 态 Esc → 取消在途验证（面板留步——与失败路径
	 * 同语义；由 tui_view_set_busy(1) 期间的 dialog.close 改派而来） */
	if (!strcmp(action, "overlay.cancel")) {
		int live;

		pthread_mutex_lock(&a->mu);
		live = a->wiz_thread_live;
		if (live)
			a->wiz_cancel = 1;
		pthread_mutex_unlock(&a->mu);
		if (!live)
			return 1;	/* 无在途验证：回落正常关闭 */
		(void)pthread_kill(a->wiz_thread, SIGINT);
		tui_view_overlay_status(a->view,
					 "取消验证中…（收口后可改 key 重试）",
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
				 "已显示全部（非对话 %zu 条 dim 标注）", nnon);
		else
			snprintf(st, sizeof(st),
				 "非对话 %zu 条已隐藏（默认过滤）", nnon);
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
		(void)cmd_models(a);	/* 重开列表反映 ★（选择复位——取舍） */
		tui_view_overlay_status(a->view,
					 on ? "★ 已收藏" : "已取消收藏", 0);
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
	free(rows);
}

static void tui_app_on_shutdown(void *ud)
{
	struct tui_app *a = ud;
	int live, wlive;

	pthread_mutex_lock(&a->mu);
	live = a->worker_live;
	wlive = a->wiz_thread_live;
	if (live || wlive)
		occ_interrupt_flag = 1;
	if (wlive)
		a->wiz_cancel = 1;
	pthread_mutex_unlock(&a->mu);
	if (live)
		(void)pthread_kill(a->worker, SIGINT);
	if (a->worker_created) {	/* join：等 worker 安全收口 */
		pthread_join(a->worker, NULL);
		a->worker_created = 0;
	}
	if (wlive)
		(void)pthread_kill(a->wiz_thread, SIGINT);
	if (a->wiz_thread_created) {	/* 向导验证线程同理（OCC-DEBT） */
		pthread_join(a->wiz_thread, NULL);
		a->wiz_thread_created = 0;
	}
	/* mutex/prompt 由 run_interactive 收尾（enter 早退路径也要清） */
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
	if (!getcwd(a.cwd, sizeof(a.cwd)))
		a.cwd[0] = '\0';
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
		return 1;
	}
	a.cfg_ok = 1;
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
	app_resolve_ctx(&a);

	memset(&h, 0, sizeof(h));
	h.ud = &a;
	h.on_entered = tui_app_on_entered;
	h.on_submit = tui_app_on_submit;
	h.on_interrupt = tui_app_on_interrupt;
	h.on_command = tui_app_on_command;
	h.fill_meta = tui_app_fill_meta;
	h.fill_status = tui_app_fill_status;
	h.fill_sessions = tui_app_fill_sessions;
	h.on_shutdown = tui_app_on_shutdown;
	h.on_overlay_submit = tui_app_on_overlay_submit;
	h.on_overlay_input = tui_app_on_overlay_input;
	h.on_overlay_key = tui_app_on_overlay_key;
	h.on_overlay_close = tui_app_on_overlay_close;
	h.on_async_result = tui_app_on_async_result;	/* OCC-DEBT */

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
				if (first_screen && a.ctx_fallback) {
					char nb[320];

					snprintf(nb, sizeof(nb),
						 "catalog 未命中/不可读：context 分母兜底 200k"
						 "（OCD 未知窗口默认，meta 标 *）——OCC_CATALOG "
						 "可指 models.dev 快照");
					(void)tui_view_post(a.view,
							     TUI_VIEW_NOTICE,
							     nb, 0, NULL, 0);
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
				if (rc != 0 || !a.shell_req)
					break;
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
		occ_provider_free(&a.p);
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
	if (argc < 2) {
		/* T9c2 交互入口：tty → 全屏 TUI；非 tty → 人话报错 rc=2 */
		if (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
			want_tui = 1;
		} else {
			fputs("occ: 交互模式需要 TTY（stdout/stdin 非 tty）；"
			      "headless 请用 occ -p \"<prompt>\"\n", stderr);
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
	if (want_tui) {
		rc = run_interactive(db, model_toml, provider_toml);
		goto out;
	}
	if (!strcmp(argv[1], "sessions")) {
		rc = cmd_sessions(db);
		goto out;
	}
	if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
		fputs(USAGE, stdout);
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
	    !strcmp(argv[1], "retry")) {
		/* 标志任意位置：--session <id>（undo 另有 --step N） */
		const char *cmd = argv[1];
		const char *sid = NULL;
		int steps = 1;
		int i;

		for (i = 2; i < argc; i++) {
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
					fprintf(stderr, "occ %s: --step 须为"
						" ≥1 的整数\n", cmd);
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
			fprintf(stderr, "occ %s: --session <id> 必需\n", cmd);
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
		int i;

		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "--session")) {
				if (i + 1 >= argc) {
					fprintf(stderr, "occ -p: --session missing value\n");
					rc = 2;
					goto out;
				}
				session_id = argv[++i];
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
		rc = run_turn(db, &p, session_id, prompt, 0);
		occ_provider_free(&p);
		goto out;
	}
	fprintf(stderr, "occ: unknown command `%s'\n", argv[1]);
	fputs(USAGE, stderr);
	rc = 2;
out:
	occ_db_close(db);
	return rc;
}
