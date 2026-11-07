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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "occ_core/occ_loop.h"
#include "occ_core/occ_revert.h"

static const char USAGE[] =
	"occ — AIKernel 编码助手（headless，T9a3+b2）\n"
	"用法：\n"
	"  occ -p \"<prompt>\" [--session <id>]   一次性对话（流式输出到 stdout）\n"
	"  occ --recover <id> [prompt]          重放中断环续跑 / 打开续接\n"
	"  occ undo --session <id> [--step N]   撤销最近 N 步（文件回滚+消息隐藏）\n"
	"  occ redo --session <id>              恢复上次 undo\n"
	"  occ retry --session <id>             重发最后一条 user 消息\n"
	"  occ sessions                         会话列表\n"
	"环境：OCC_MODEL_TOML / OCC_PROVIDER_TOML / OCC_DB / OCC_SNAPROOT 可覆盖\n";

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

int main(int argc, char **argv)
{
	const char *model_toml, *provider_toml, *db_path;
	occ_db *db;
	occ_provider p;
	char err[512];
	int rc = 2;

	memset(&p, 0, sizeof(p));
	if (argc < 2) {
		fputs(USAGE, stderr);
		return 2;
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
