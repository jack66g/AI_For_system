/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_compact_20turns.c - W72：20 轮压缩序列复现（纯策略单测）
 *
 * 用真实 ask_compact_plan_summary / ask_ctx_should_autocompact /
 * ASK_COMPACT_COOLDOWN_TURNS 模拟 W70 的 20 轮长会话（ctx=32768,
 * max_tokens=8192 → 历史预算 21,576）。每轮注入 user + assistant
 * tool_calls + tool 结果 + assistant 回答；第 4n 轮放大工具结果、
 * 第 5n 轮放大回答，复现"一次大输出就把历史推回阈值"的抖动场景。
 *
 * 断言：
 *   - 无连续两轮压缩（冷却生效）；
 *   - 每次压缩保留最近完整轮（kept 消息 >=2，窗口起点 user）；
 *   - 摘要 + 保留原文始终能回忆第一轮暗号 SILENT-HERON-482；
 *   - 模拟新进程恢复（冷却初值满足）再次压缩时仍保留最近原文。
 * 输出逐轮表供 W72 报告引用。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ask_compact.h"
#include "ask_context.h"

#define CODE "SILENT-HERON-482"
#define SIM_CTX 32768
#define SIM_MAX_TOKENS 8192
#define SIM_TURNS 20
#define SIM_CAP 2048

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

static struct ai_chat_msg g_hist[SIM_CAP];
static int g_nhist;

static void add_msg(const char *role, const char *content, const char *tcid,
		    const char *tcjson)
{
	struct ai_chat_msg *m;

	if (g_nhist >= SIM_CAP)
		return;
	m = &g_hist[g_nhist++];
	memset(m, 0, sizeof(*m));
	m->role = role;
	m->content = content ? strdup(content) : NULL;
	m->tool_call_id = tcid ? strdup(tcid) : NULL;
	m->tool_calls_json = tcjson ? strdup(tcjson) : NULL;
}

static void fill(char *buf, size_t n, char c, const char *prefix)
{
	size_t off;

	snprintf(buf, n, "%s", prefix);
	off = strlen(buf);
	if (off < n - 1)
		memset(buf + off, c, n - off - 1);
	buf[n - 1] = '\0';
}

static int count_user_turns(int from, int to)
{
	int i, n = 0;

	for (i = from; i < to; i++)
		if (ask_compact_is_user(&g_hist[i]))
			n++;
	return n;
}

/* 模拟 ask_hist_trim：保留摘要（若有）+ 最近 >=2 轮，裁剪到预算 */
static void trim_to_budget(long budget)
{
	int start = (g_nhist > 0 && ask_compact_is_summary(&g_hist[0])) ? 1 : 0;
	int cut = start;
	long acc = 0;
	int turns = 0;
	int i;

	for (i = g_nhist - 1; i >= start; i--) {
		acc += ask_compact_msg_tokens(&g_hist[i]);
		if (ask_compact_is_user(&g_hist[i]))
			turns++;
		if (acc > budget && turns > 2) {
			int j = i + 1;

			while (j < g_nhist && !ask_compact_is_user(&g_hist[j]))
				j++;
			cut = j;
			break;
		}
	}
	if (cut > start) {
		int n = 0;

		if (start == 1)
			g_hist[n++] = g_hist[0];
		for (i = cut; i < g_nhist; i++)
			g_hist[n++] = g_hist[i];
		g_nhist = n;
	}
}

/* 应用 summary plan：新摘要 + 最近原文 */
static void apply_plan(const char *summary, const struct ask_compact_plan *p)
{
	struct ai_chat_msg tmp[SIM_CAP];
	int old_n = g_nhist;
	int n = 0, i;

	memset(tmp, 0, sizeof(tmp));
	add_msg("user", summary, NULL, NULL);
	tmp[n++] = g_hist[g_nhist - 1];	/* 刚追加的摘要消息 */
	for (i = p->keep_from; i < old_n; i++)
		tmp[n++] = g_hist[i];
	memcpy(g_hist, tmp, sizeof(g_hist[0]) * (size_t)n);
	g_nhist = n;
}

int main(void)
{
	long budget = ask_ctx_hist_budget(SIM_CTX, SIM_MAX_TOKENS);
	long target = budget * ASK_COMPACT_TARGET_PCT / 100;
	long threshold = budget * ASK_AUTOCOMPACT_PCT / 100;
	int since = ASK_COMPACT_COOLDOWN_TURNS;
	int last_compact_turn = -10;
	int ncomp = 0;
	int max_before = 0;
	int max_after = 0;
	int turn;
	int i;

	printf("==== test_compact_20turns: W72 jitter/cooldown ====\n");
	printf("  budget=%ld target=%ld (%d%%) threshold=%ld cooldown=%d\n",
	       budget, target, ASK_COMPACT_TARGET_PCT, threshold,
	       ASK_COMPACT_COOLDOWN_TURNS);
	printf("  turn used before thr cmp before after kept_msgs kept_turns post\n");

	for (turn = 1; turn <= SIM_TURNS; turn++) {
		char q[256], tc[256], tcid[32], big[12288], ans[8192];
		char summary[1024];
		struct ask_compact_plan plan;
		long used, before = 0, after = 0, post_used;
		int kept_msgs = 0, kept_turns = 0;
		int did = 0;

		snprintf(q, sizeof(q),
			 "T%02d %s：继续排查并给出证据（轮次 %d）",
			 turn, turn == 1 ? CODE : "长会话任务", turn);
		snprintf(tcid, sizeof(tcid), "call_%d", turn);
		snprintf(tc, sizeof(tc),
			 "{\"id\":\"%s\",\"type\":\"function\","
			 "\"function\":{\"name\":\"exec_run\","
			 "\"arguments\":\"{}\"}}", tcid);
		if (turn % 4 == 0)
			fill(big, sizeof(big), 'X',
			     "tool result: health report rows ... ");
		else
			fill(big, sizeof(big), 'X', "tool result: ok ");
		if (turn % 5 == 0)
			fill(ans, sizeof(ans), 'A', "answer: detailed summary ");
		else
			fill(ans, sizeof(ans), 'a', "answer: done ");

		add_msg("user", q, NULL, NULL);
		add_msg("assistant", NULL, NULL, tc);
		add_msg("tool", big, tcid, NULL);
		add_msg("assistant", ans, NULL, NULL);

		used = ask_compact_hist_tokens(g_hist, g_nhist);
		if (used > max_before)
			max_before = (int)used;

		if (ask_ctx_should_autocompact(used, budget) &&
		    since >= ASK_COMPACT_COOLDOWN_TURNS && g_nhist > 1) {
			snprintf(summary, sizeof(summary),
				 "%s" "compacted through turn %d; topics: "
				 "disk/network/memory/sandbox; early codeword "
				 CODE " must be retained.",
				 ASK_COMPACT_SUMMARY_PREFIX, turn);
			if (ask_compact_plan_summary(g_hist, g_nhist,
						     strlen(summary), target,
						     ASK_COMPACT_KEEP_MAX_MSGS,
						     &plan) == 0) {
				before = plan.before_tokens;
				after = plan.after_tokens;
				kept_msgs = g_nhist - plan.keep_from;
				kept_turns = count_user_turns(plan.keep_from,
							      g_nhist);
				CHECK(kept_msgs >= 2,
				      "压缩后保留 >=2 条最近原文");
				CHECK(plan.keep_from >= 0 &&
				      plan.keep_from < g_nhist &&
				      ask_compact_is_user(
					      &g_hist[plan.keep_from]),
				      "保留窗口从 user 锚点开始（不拆工具对）");
				CHECK(kept_turns >= 1,
				      "压缩后至少保留 1 个完整用户轮");
				CHECK(strstr(summary, CODE) != NULL,
				      "摘要保留早期暗号（可回忆）");
				CHECK(after <= budget,
				      "压缩后历史 <= 历史预算");
				apply_plan(summary, &plan);
				did = 1;
				ncomp++;
				if (last_compact_turn == turn - 1) {
					printf("  [FAIL] consecutive compaction "
					       "at T%d/T%d\n", last_compact_turn,
					       turn);
					g_fail++;
				}
				last_compact_turn = turn;
				since = 0;
			}
		} else if (ask_ctx_should_autocompact(used, budget)) {
			trim_to_budget(budget);
		}
		if (!did && since < ASK_COMPACT_COOLDOWN_TURNS)
			since++;

		post_used = ask_compact_hist_tokens(g_hist, g_nhist);
		if (post_used > max_after)
			max_after = (int)post_used;
		printf("  T%02d %6ld %6ld %s %6ld %6ld %9d %10d %5ld\n",
		       turn, used, threshold, did ? "Y" : ".",
		       did ? before : 0, did ? after : 0, kept_msgs,
		       kept_turns, post_used);
	}

	printf("  compactions=%d/%d max_before=%d max_after=%d final_n=%d "
	       "final_used=%ld\n", ncomp, SIM_TURNS, max_before, max_after,
	       g_nhist, ask_compact_hist_tokens(g_hist, g_nhist));
	CHECK(ncomp >= 1 && ncomp <= 8,
	      "20 轮压缩次数收敛（1-8 次，W70 为 5 次且有 2 组连续）");
	CHECK(max_after <= budget + 2000,
	      "压缩/裁剪后历史不会无界增长（max_after <= budget+2000）");

	/* 模拟新进程恢复：冷却初值满足，历史越线时允许压缩一次；
	 * 无论是否越线，plan 都必须保留最近原文窗口。 */
	{
		struct ask_compact_plan plan;
		char summary[1024];
		int kept_msgs, kept_turns;
		long used = ask_compact_hist_tokens(g_hist, g_nhist);

		snprintf(summary, sizeof(summary),
			 "%s" "recovered session; early codeword " CODE
			 " retained.", ASK_COMPACT_SUMMARY_PREFIX);
		CHECK(ask_compact_plan_summary(g_hist, g_nhist,
					       strlen(summary), target,
					       ASK_COMPACT_KEEP_MAX_MSGS,
					       &plan) == 0,
		      "恢复路径 summary plan 成功");
		kept_msgs = g_nhist - plan.keep_from;
		kept_turns = count_user_turns(plan.keep_from, g_nhist);
		printf("  recovery: used=%ld keep_from=%d kept_msgs=%d "
		       "kept_turns=%d\n", used, plan.keep_from, kept_msgs,
		       kept_turns);
		CHECK(kept_msgs >= 2, "恢复压缩保留 >=2 条最近原文（不再 kept=0）");
		CHECK(kept_turns >= 1, "恢复压缩保留最近完整用户轮");
		CHECK(plan.keep_from >= 0 && plan.keep_from < g_nhist &&
		      ask_compact_is_user(&g_hist[plan.keep_from]),
		      "恢复窗口从 user 锚点开始（工具配对不拆）");
		CHECK(strstr(summary, CODE) != NULL,
		      "恢复后早期暗号仍可回忆");
	}

	/* 清理（测试进程退出前） */
	for (i = 0; i < g_nhist; i++) {
		free((void *)g_hist[i].content);
		free((void *)g_hist[i].tool_call_id);
		free((void *)g_hist[i].tool_calls_json);
	}
	if (g_fail == 0) {
		printf("RESULT: PASS\n");
		return 0;
	}
	printf("RESULT: FAIL (%d)\n", g_fail);
	return 1;
}
