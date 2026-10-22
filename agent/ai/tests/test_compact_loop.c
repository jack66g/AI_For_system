/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_compact_loop.c - W59 自动压缩死循环回归
 *
 * 复现 p5-03 实机缺陷（2026-10-19）：
 *   - 长历史（~8KB 多行审计日志 + 工具结果）>80% 预算；
 *   - 旧实现每轮压缩后摘要仍可能超阈值/不收缩，导致同一 ask 内反复
 *     压缩、turn 数无界、REPL 永不静默；
 *   - 压缩提示（"Compress the following..."）不得出现在持久历史中。
 *
 * 本测试走 cmd_ask 真实主循环，cmd_compact_apply / LLM / 会话文件由
 * test_ask_stubs 接管（mock LLM 返回固定摘要/回答）：
 *   1) 正常收缩：恰好 1 次压缩，之后正常回答，历史 <=80% 且无压缩提示；
 *   2) 压缩不收缩：最多 2 次压缩 -> 退化截断 -> 只请求 1 次模型，历史
 *      不超目标；
 *   3) 连续压缩上限：跨 3 个 ask 总压缩次数 <=2；
 *   4) 超大摘要：2 次后截断，最终历史为空/不超目标，turn 数有界；
 *   5) 纯函数计划：after <= target，保留窗口从 user 锚点开始。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_config.h"
#include "ai_lang.h"
#include "ai_ui.h"
#include "ask_context.h"
#include "ask_compact.h"
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

#define HIST_MARK "W59_HIST_MARK"

enum compact_mode {
	CM_SHRINK = 0,
	CM_NOOP,
	CM_HUGE,
	CM_FAIL
};

static enum compact_mode g_compact_mode;
static int g_answer_bytes = 120;
static int g_chat_saw_compact_prompt;
static int g_chat_calls;
static int g_ask_seq;
static int g_compact_seq[16];

static char g_msg[12][1600];
static char g_tool[2048];
static struct ai_chat_msg g_hist[12];
static char g_question[] = "综上所述，帮我看下当前磁盘使用率最高的挂载点。";

static void build_history(void)
{
	int i;

	for (i = 0; i < 12; i++) {
		size_t off = (size_t)snprintf(g_msg[i], sizeof(g_msg[i]),
					      HIST_MARK " msg%d line1\n", i);
		size_t j;

		for (j = off; j + 2 < sizeof(g_msg[i]); j += 2) {
			g_msg[i][j] = 'h';
			g_msg[i][j + 1] = (j % 80 == 0) ? '\n' : 'h';
		}
		g_msg[i][sizeof(g_msg[i]) - 1] = '\0';
	}
	snprintf(g_tool, sizeof(g_tool), HIST_MARK " tool result\n");
	memset(g_tool + strlen(g_tool), 't',
	       sizeof(g_tool) - strlen(g_tool) - 1);
	g_tool[sizeof(g_tool) - 1] = '\0';

	memset(g_hist, 0, sizeof(g_hist));
	g_hist[0].role = "user";
	g_hist[0].content = g_msg[0];
	g_hist[1].role = "assistant";
	g_hist[1].content = g_msg[1];
	g_hist[2].role = "user";
	g_hist[2].content = g_msg[2];
	g_hist[3].role = "assistant";
	g_hist[3].tool_calls_json = "[{\"id\":\"call_w59\",\"type\":"
		"\"function\",\"function\":{\"name\":\"exec_run\","
		"\"arguments\":\"{}\"}}]";
	g_hist[4].role = "tool";
	g_hist[4].tool_call_id = "call_w59";
	g_hist[4].content = g_tool;
	g_hist[5].role = "assistant";
	g_hist[5].content = g_msg[3];
	g_hist[6].role = "user";
	g_hist[6].content = g_msg[4];
	g_hist[7].role = "assistant";
	g_hist[7].content = g_msg[5];
	g_hist[8].role = "user";
	g_hist[8].content = g_msg[6];
	g_hist[9].role = "assistant";
	g_hist[9].content = g_msg[7];
	g_hist[10].role = "user";
	g_hist[10].content = g_msg[8];
	g_hist[11].role = "assistant";
	g_hist[11].content = g_msg[9];
}

static void reset_case(const char *session_marker)
{
	(void)session_marker;
	test_ask_session_reset();
	g_ask_session_msgs = g_hist;
	g_ask_session_n = 12;
	g_ask_compact_calls = 0;
	g_ask_mock_calls = 0;
	g_ask_compact_target = 0;
	g_ask_compact_attempt = 0;
	g_ask_compact_kept = 1;
	g_ask_compact_after = 0;
	g_chat_saw_compact_prompt = 0;
	g_chat_calls = 0;
	g_ask_mock_compact = NULL;
	g_ask_mock_chat = NULL;
}

static int mock_compact(void *shell)
{
	const char *summary =
		"[历史摘要] W59 summary: 用户提供了大量多行审计日志，"
		"已确认 cron 维护窗口正常完成；最近关注磁盘挂载点。";
	static struct ai_chat_msg huge_msg;
	static char huge[22000];
	struct ui_session_rec rec;
	int i;

	(void)shell;
	if (g_ask_compact_calls >= 1 &&
	    g_ask_compact_calls <= (int)(sizeof(g_compact_seq) /
					 sizeof(g_compact_seq[0])))
		g_compact_seq[g_ask_compact_calls - 1] = g_ask_seq;
	switch (g_compact_mode) {
	case CM_SHRINK:
		memset(&rec, 0, sizeof(rec));
		rec.role = "user";
		rec.content = summary;
		ui_session_replace("w59-test", &rec, 1);
		g_ask_compact_kept = 1;
		g_ask_compact_after = 300;
		return AI_OK;
	case CM_NOOP:
		g_ask_compact_kept = 0;
		g_ask_compact_after = 0;
		return AI_OK;
	case CM_HUGE:
		snprintf(huge, sizeof(huge), ASK_COMPACT_SUMMARY_PREFIX);
		for (i = (int)strlen(huge); i < (int)sizeof(huge) - 1; i++)
			huge[i] = 'S';
		huge[sizeof(huge) - 1] = '\0';
		memset(&huge_msg, 0, sizeof(huge_msg));
		huge_msg.role = "user";
		huge_msg.content = huge;
		g_ask_session_msgs = &huge_msg;
		g_ask_session_n = 1;
		g_ask_compact_kept = 0;
		g_ask_compact_after = 22000;
		return AI_OK;
	case CM_FAIL:
	default:
		g_ask_compact_kept = 0;
		g_ask_compact_after = 0;
		return AI_ERR_API;
	}
}

static int mock_chat(int call_no, const struct ai_chat_msg *msgs, int nmsgs,
		     const char *tools_json, struct ai_chat_result **result)
{
	char *answer;
	int i;

	(void)call_no;
	(void)tools_json;
	g_chat_calls++;
	for (i = 0; i < nmsgs; i++) {
		if (msgs[i].content &&
		    strstr(msgs[i].content, "Compress the following"))
			g_chat_saw_compact_prompt++;
	}
	if (g_chat_calls > 8) {
		printf("  [FAIL] mock chat 调用超过 8 次（循环失控）\n");
		g_fail++;
		return AI_ERR_API;
	}

	answer = malloc((size_t)g_answer_bytes + 16);
	if (!answer)
		return AI_ERR_MEMORY;
	snprintf(answer, 16, "ANSWER: ok");
	memset(answer + strlen(answer), 'A',
	       (size_t)g_answer_bytes - strlen(answer));
	answer[g_answer_bytes] = '\0';

	*result = calloc(1, sizeof(**result));
	if (!*result) {
		free(answer);
		return AI_ERR_MEMORY;
	}
	(*result)->content = answer;
	(*result)->finish_reason = strdup("stop");
	(*result)->prompt_tokens = 400;
	(*result)->completion_tokens = 50;
	return AI_OK;
}

static void setup_shell(struct ai_config *cfg, struct ai_shell *shell,
			char *session)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->default_model = strdup("mock-model");
	cfg->ui.ctx_len = 8192;
	cfg->ui.max_tokens = 1024;
	cfg->ui.stream = 0;
	cfg->ui.color = 0;
	cfg->ui.verbose = 0;
	cfg->ui.session = session;
	cfg->ui.lang = strdup("zh");
	cfg->routing.mode = AI_ROUTE_AUTONOMOUS;
	memset(shell, 0, sizeof(*shell));
	shell->config = cfg;
}

static int run_ask(struct ai_shell *shell)
{
	char *argv[] = { "ask", g_question };

	return cmd_ask(shell, 2, argv);
}

static long hist_used(void)
{
	return ask_compact_hist_tokens(g_ask_session_msgs, g_ask_session_n);
}

int main(void)
{
	struct ai_config cfg;
	struct ai_shell shell;
	char *session;
	int rc;
	long budget, target, used;

	printf("==== test_compact_loop: W59 auto-compact loop ====\n");
	lang_set("zh");
	build_history();
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);

	budget = ask_ctx_hist_budget(8192, 8192);
	target = budget * ASK_COMPACT_TARGET_PCT / 100;
	printf("  budget=%ld target=%ld threshold=%ld\n", budget, target,
	       budget * ASK_AUTOCOMPACT_PCT / 100);
	CHECK(ask_ctx_should_autocompact(
		      ask_compact_hist_tokens(g_hist, 12), budget) == 1,
	      "构造历史 >80% 预算（复现前提）");

	/* ---- 用例 1：正常收缩（恰好 1 次压缩） ---- */
	printf("-- case 1: compact shrinks, 1 attempt --\n");
	reset_case("w59-shrink");
	g_ask_mock_compact = mock_compact;
	g_ask_mock_chat = mock_chat;
	g_compact_mode = CM_SHRINK;
	g_answer_bytes = 120;
	session = strdup("w59-shrink");
	setup_shell(&cfg, &shell, session);
	rc = run_ask(&shell);
	CHECK(rc == AI_OK, "cmd_ask 返回 AI_OK");
	CHECK(g_ask_compact_calls == 1, "自动压缩恰好 1 次");
	CHECK(g_ask_compact_attempt == 1, "首次尝试目标 70%");
	CHECK(g_ask_compact_target > 0 &&
	      g_ask_compact_target <= budget * ASK_AUTOCOMPACT_PCT / 100,
	      "压缩目标 <= 80% 预算");
	CHECK(g_ask_mock_calls == 1, "压缩后只发起 1 次回答请求");
	CHECK(g_chat_saw_compact_prompt == 0,
	      "压缩指令未出现在回答请求历史中");
	CHECK(test_ask_session_contains("Compress the following") == 0,
	      "持久历史不含 'Compress the following'");
	CHECK(test_ask_session_contains("Compact kernel status summary") == 0,
	      "status 摘要仅属本次请求，未进入持久历史");
	CHECK(test_ask_session_contains(ASK_COMPACT_SUMMARY_PREFIX) == 1,
	      "持久历史含 [历史摘要]");
	used = hist_used();
	CHECK(used <= budget * ASK_AUTOCOMPACT_PCT / 100,
	      "压缩后历史 <=80% 预算");
	printf("  after: n=%d used=%ld\n", g_ask_session_n, used);

	/* ---- 用例 2：压缩不收缩 -> 2 次上限 -> 截断 ---- */
	printf("-- case 2: compact no-op, 2 attempts then truncate --\n");
	reset_case("w59-noop");
	g_ask_mock_compact = mock_compact;
	g_ask_mock_chat = mock_chat;
	g_compact_mode = CM_NOOP;
	g_answer_bytes = 120;
	session = strdup("w59-noop");
	setup_shell(&cfg, &shell, session);
	rc = run_ask(&shell);
	CHECK(rc == AI_OK, "cmd_ask 返回 AI_OK");
	CHECK(g_ask_compact_calls == 2, "压缩不收缩时最多 2 次");
	CHECK(g_ask_compact_attempt == 2, "第二次目标收紧到 40%");
	CHECK(g_ask_compact_target == budget * ASK_COMPACT_RETRY_PCT / 100,
	      "重试目标 = 40% 预算");
	CHECK(g_ask_mock_calls == 1, "退化截断后仍只回答 1 次");
	used = hist_used();
	CHECK(used < ask_compact_hist_tokens(g_hist, 12),
	      "截断后历史小于压缩前（确实收缩）");
	CHECK(g_ask_session_n >= 2 && g_ask_session_n < 12,
	      "截断保留最近完整轮且最旧历史已裁（W72 软目标）");
	printf("  after: n=%d used=%ld\n", g_ask_session_n, used);

	/* ---- 用例 3：跨 ask 连续压缩上限（3 个 ask 总 <=2 次） ---- */
	printf("-- case 3: consecutive compaction cap across 3 asks --\n");
	reset_case("w59-streak");
	g_ask_mock_compact = mock_compact;
	g_ask_mock_chat = mock_chat;
	g_compact_mode = CM_NOOP;
	g_answer_bytes = 3000;	/* 每轮回答把历史重新推过阈值 */
	session = strdup("w59-streak");
	setup_shell(&cfg, &shell, session);
	rc = run_ask(&shell);
	CHECK(rc == AI_OK, "第 1 个 ask 返回 AI_OK");
	rc = run_ask(&shell);
	CHECK(rc == AI_OK, "第 2 个 ask 返回 AI_OK");
	rc = run_ask(&shell);
	CHECK(rc == AI_OK, "第 3 个 ask 返回 AI_OK");
	CHECK(g_ask_compact_calls <= 2, "连续 3 个 ask 总压缩次数 <=2");
	CHECK(g_ask_mock_calls == 3, "每个 ask 仍只回答 1 次（turn 有界）");
	CHECK(g_chat_saw_compact_prompt == 0, "压缩指令从未进入回答历史");
	printf("  compact_calls=%d chat_calls=%d\n",
	       g_ask_compact_calls, g_ask_mock_calls);

	/* ---- 用例 4：超大摘要 -> 2 次后截断，不循环 ---- */
	printf("-- case 4: huge summary, bounded attempts --\n");
	reset_case("w59-huge");
	g_ask_mock_compact = mock_compact;
	g_ask_mock_chat = mock_chat;
	g_compact_mode = CM_HUGE;
	g_answer_bytes = 120;
	session = strdup("w59-huge");
	setup_shell(&cfg, &shell, session);
	rc = run_ask(&shell);
	CHECK(rc == AI_OK, "cmd_ask 返回 AI_OK");
	CHECK(g_ask_compact_calls <= 2, "超大摘要最多 2 次压缩");
	CHECK(g_ask_mock_calls == 1, "仍只回答 1 次");
	used = hist_used();
	CHECK(used <= budget * ASK_AUTOCOMPACT_PCT / 100,
	      "最终历史 <=80% 预算（超限摘要被截断）");
	CHECK(test_ask_session_contains("Compress the following") == 0,
	      "持久历史不含压缩指令");
	printf("  compact_calls=%d after_n=%d used=%ld\n",
	       g_ask_compact_calls, g_ask_session_n, used);

	/* ---- 用例 5：纯函数计划边界 ---- */
	printf("-- case 5: pure planner invariants --\n");
	{
		struct ask_compact_plan plan;
		size_t cap = ask_compact_summary_cap(target);
		int ok;

		CHECK(cap > 0 && cap <= ASK_COMPACT_SUMMARY_MAX,
		      "摘要上限受硬上限约束");
		ok = ask_compact_plan_summary(g_hist, 12, 400, 5000,
					      ASK_COMPACT_KEEP_MAX_MSGS,
					      &plan);
		CHECK(ok == 0, "summary plan 生成成功");
		CHECK(plan.after_tokens <= 5000, "summary plan after <= target");
		CHECK(plan.keep_from == 12 ||
		      (plan.keep_from >= 0 && plan.keep_from < 12 &&
		       ask_compact_is_user(&g_hist[plan.keep_from])),
		      "保留窗口从 user 锚点开始（不拆工具对）");
		ok = ask_compact_plan_truncate(g_hist, 12, 5000,
					       ASK_COMPACT_KEEP_MAX_MSGS,
					       &plan);
		CHECK(ok == 0 && plan.after_tokens <= 5000,
		      "truncate plan after <= target");
	}

	/* ---- 用例 6：W72 最近整轮保底（不再 kept=0） ---- */
	printf("-- case 6: recent-turn retention (W72) --\n");
	{
		static char u1[128] = "SILENT-HERON-482 early codeword";
		static char a1[2048], t1[12000], u2[64] = "second turn";
		static char a2[2048], t2[12000], u3[64] = "third turn";
		static char a3[2048];
		static char sum[512] = ASK_COMPACT_SUMMARY_PREFIX
			"SILENT-HERON-482 early topic retained in summary";
		struct ai_chat_msg rh[8];
		struct ask_compact_plan plan;
		int last_user = 6;
		int small_from;
		long small_after;
		int ok;

		memset(a1, 'a', sizeof(a1) - 1);
		memset(a2, 'b', sizeof(a2) - 1);
		memset(a3, 'c', sizeof(a3) - 1);
		memset(t1, 't', sizeof(t1) - 1);
		memset(t2, 'u', sizeof(t2) - 1);
		a1[sizeof(a1) - 1] = a2[sizeof(a2) - 1] = '\0';
		a3[sizeof(a3) - 1] = '\0';
		t1[sizeof(t1) - 1] = t2[sizeof(t2) - 1] = '\0';

		memset(rh, 0, sizeof(rh));
		rh[0].role = "user";
		rh[0].content = u1;
		rh[1].role = "assistant";
		rh[1].tool_calls_json = "{\"name\":\"exec_run\"}";
		rh[2].role = "tool";
		rh[2].content = t1;
		rh[2].tool_call_id = "c1";
		rh[3].role = "user";
		rh[3].content = u2;
		rh[4].role = "assistant";
		rh[4].tool_calls_json = "{\"name\":\"exec_run\"}";
		rh[5].role = "tool";
		rh[5].content = t2;
		rh[5].tool_call_id = "c2";
		rh[6].role = "user";
		rh[6].content = u3;
		rh[7].role = "assistant";
		rh[7].content = a3;

		/* 目标远小于最后一轮：仍必须保留最后 1 个完整轮（user 锚点） */
		ok = ask_compact_plan_summary(rh, 8, strlen(sum), 500,
					      ASK_COMPACT_KEEP_MAX_MSGS,
					      &plan);
		CHECK(ok == 0, "小目标 summary plan 成功");
		CHECK(plan.keep_from == last_user,
		      "最后 1 个完整轮无条件保留（W70 T11 kept=0 修复）");
		CHECK(plan.keep_from < 8 &&
		      ask_compact_is_user(&rh[plan.keep_from]),
		      "保留窗口从 user 锚点开始（工具配对不拆）");
		CHECK(8 - plan.keep_from >= 2,
		      "最近原文至少 2 条消息（user + assistant/tool）");
		CHECK(plan.after_tokens > 500,
		      "软目标允许最近整轮略超 target");
		small_from = plan.keep_from;
		small_after = plan.after_tokens;
		CHECK(strstr(sum, "SILENT-HERON-482") != NULL,
		      "早期暗号在摘要中可回忆（小目标窗口不含第一轮）");

		/* 大目标：向前扩到 3 个完整轮，早期暗号在保留原文中 */
		ok = ask_compact_plan_summary(rh, 8, strlen(sum), 100000,
					      ASK_COMPACT_KEEP_MAX_MSGS,
					      &plan);
		CHECK(ok == 0 && plan.keep_from == 0,
		      "大目标保留全部 3 个完整轮");
		CHECK(strstr(rh[plan.keep_from].content,
			     "SILENT-HERON-482") != NULL,
		      "早期暗号在保留原文中可回忆");
		printf("  small: keep_from=%d after=%ld; large: keep_from=%d "
		       "after=%ld\n", small_from, small_after,
		       plan.keep_from, plan.after_tokens);
	}

	/* ---- 用例 7：W72 冷却——4 个 ask 只在第 1/4 轮压缩 ---- */
	printf("-- case 7: compaction cooldown across asks (W72) --\n");
	reset_case("w59-cool");
	g_ask_mock_compact = mock_compact;
	g_ask_mock_chat = mock_chat;
	g_compact_mode = CM_SHRINK;
	g_answer_bytes = 20000;	/* 每轮回答再次把历史推过阈值 */
	session = strdup("w59-cool");
	setup_shell(&cfg, &shell, session);
	g_ask_seq = 0;
	g_ask_compact_calls = 0;
	{
		int s;

		for (s = 1; s <= 4; s++) {
			g_ask_seq = s;
			rc = run_ask(&shell);
			CHECK(rc == AI_OK, "冷却用例 ask 返回 AI_OK");
		}
	}
	CHECK(g_ask_compact_calls == 2,
	      "4 个 ask 只压缩 2 次（冷却跳过连续两轮）");
	CHECK(g_compact_seq[0] == 1 && g_compact_seq[1] == 4,
	      "压缩发生在第 1/4 轮，无连续压缩");
	CHECK(g_ask_mock_calls == 4, "每个 ask 仍只回答 1 次");
	printf("  compact_at=%d,%d chat_calls=%d\n",
	       g_compact_seq[0], g_compact_seq[1], g_ask_mock_calls);

	/* 收尾 */
	test_ask_session_reset();
	free(cfg.default_model);
	free(cfg.ui.lang);
	free(session);
	if (g_fail == 0) {
		printf("RESULT: PASS\n");
		return 0;
	}
	printf("RESULT: FAIL (%d)\n", g_fail);
	return 1;
}
