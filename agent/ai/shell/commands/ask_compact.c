// SPDX-License-Identifier: GPL-2.0
/*
 * ask_compact.c - W59 压缩替换计划（纯函数，无 IO/LLM 依赖）
 *
 * 预算口径与 cmd_ask.c 一致：bytes/3 + 1 的保守估算。所有计划都保证
 * after_tokens <= target_tokens（除非摘要本身超目标，此时返回 -1，
 * 由调用方先按 ask_compact_summary_cap 截断）。
 */
#include <stddef.h>
#include <string.h>

#include "ask_compact.h"

long ask_compact_msg_tokens(const struct ai_chat_msg *m)
{
	long bytes = 0;

	if (!m)
		return 1;
	if (m->content)
		bytes += (long)strlen(m->content);
	if (m->tool_calls_json)
		bytes += (long)strlen(m->tool_calls_json);
	if (m->tool_call_id)
		bytes += (long)strlen(m->tool_call_id);
	if (m->tool_name)
		bytes += (long)strlen(m->tool_name);
	return bytes / 3 + 1;
}

long ask_compact_hist_tokens(const struct ai_chat_msg *hist, int nhist)
{
	long sum = 0;
	int i;

	if (!hist || nhist <= 0)
		return 0;
	for (i = 0; i < nhist; i++)
		sum += ask_compact_msg_tokens(&hist[i]);
	return sum;
}

int ask_compact_is_user(const struct ai_chat_msg *m)
{
	return m && m->role && strcmp(m->role, "user") == 0;
}

int ask_compact_is_summary(const struct ai_chat_msg *m)
{
	return ask_compact_is_user(m) && m->content &&
	       strncmp(m->content, ASK_COMPACT_SUMMARY_PREFIX,
		       ASK_COMPACT_SUMMARY_PREFIX_LEN) == 0;
}

size_t ask_compact_summary_cap(long target_tokens)
{
	long bytes;
	long max_body;

	if (target_tokens <= 0)
		return 0;
	/* 目标 token -> 粗估字节，摘要占 60%，再扣前缀与截断标记余量 */
	bytes = target_tokens * 3;
	max_body = bytes * ASK_COMPACT_SUMMARY_PCT / 100 -
		   (long)ASK_COMPACT_SUMMARY_PREFIX_LEN - 8;
	if (max_body > ASK_COMPACT_SUMMARY_MAX)
		max_body = ASK_COMPACT_SUMMARY_MAX;
	if (max_body < 32)
		max_body = 32;
	return (size_t)max_body;
}

/*
 * plan_prev_user - 向前找最近的 user 锚点（>=floor）
 * 返回下标；未找到返回 -1。
 */
static int plan_prev_user(const struct ai_chat_msg *hist, int from, int floor)
{
	int i;

	for (i = from; i >= floor; i--)
		if (ask_compact_is_user(&hist[i]))
			return i;
	return -1;
}

static long plan_range_tokens(const struct ai_chat_msg *hist, int start,
			      int end)
{
	long sum = 0;
	int i;

	for (i = start; i < end; i++)
		sum += ask_compact_msg_tokens(&hist[i]);
	return sum;
}

/*
 * plan_keep_window - 选"最近整轮原文"窗口（W72）
 * @start: 允许的最小下标（0 或 1——1 表示 hist[0] 摘要已单独钉住）
 * @base_tokens: 已占用的 token（摘要/钉住消息）
 *
 * 策略：
 *   - 最后一条 user 消息起到结尾 = 最近 1 个完整轮，**无条件保留**
 *     （这是 W70 T11 kept=0 的修复：旧实现只要该轮自身超过 target
 *     就一条原文都不留）；
 *   - 优先向前扩到 2-4 个完整用户轮；第 2 轮即使略超 target 也保留
 *     （上限 1.5×target），第 3/4 轮严格按 target；
 *   - 工具调用（assistant.tool_calls）与 tool 结果始终同轮进/出，
 *     窗口起点一定是 user 锚点。
 * 返回保留窗口起点（nhist=不保留原文，仅无 user 且无消息时）。
 */
static int plan_keep_window(const struct ai_chat_msg *hist, int nhist,
			    int start, long base_tokens, long target_tokens,
			    int max_msgs, long *after)
{
	long acc, force_limit;
	int msgs, turns;
	int keep_from;
	int i;

	if (max_msgs <= 0)
		max_msgs = ASK_COMPACT_KEEP_MAX_MSGS;

	keep_from = plan_prev_user(hist, nhist - 1, start);
	if (keep_from < 0) {
		/* 损坏/无 user 锚点：退化为"最新消息按预算"，至少留 1 条，
		 * 且窗口不以 tool 开头（防孤儿）。 */
		acc = base_tokens;
		msgs = 0;
		keep_from = nhist;
		for (i = nhist - 1; i >= start; i--) {
			long t = ask_compact_msg_tokens(&hist[i]);

			if ((msgs > 0 && acc + t > target_tokens) ||
			    msgs >= max_msgs)
				break;
			acc += t;
			msgs++;
			keep_from = i;
		}
		if (keep_from == nhist && nhist > start) {
			keep_from = nhist - 1;
			acc += ask_compact_msg_tokens(&hist[keep_from]);
		}
		while (keep_from < nhist && hist[keep_from].role &&
		       strcmp(hist[keep_from].role, "tool") == 0)
			keep_from++;
		*after = base_tokens +
			 plan_range_tokens(hist, keep_from, nhist);
		return keep_from;
	}

	/* 最近完整轮无条件保留 */
	acc = base_tokens + plan_range_tokens(hist, keep_from, nhist);
	msgs = nhist - keep_from;
	turns = 1;

	/* 第 2 轮允许到 1.5×target；第 3/4 轮严格 target。 */
	force_limit = target_tokens + target_tokens / 2;
	while (turns < ASK_COMPACT_KEEP_TURNS_MAX) {
		int prev = plan_prev_user(hist, keep_from - 1, start);
		long t;
		int nmsg;

		if (prev < 0)
			break;
		nmsg = keep_from - prev;
		if (msgs + nmsg > max_msgs)
			break;
		t = plan_range_tokens(hist, prev, keep_from);
		if (acc + t > (turns < ASK_COMPACT_KEEP_TURNS_MIN ?
			       force_limit : target_tokens))
			break;
		acc += t;
		msgs += nmsg;
		keep_from = prev;
		turns++;
	}
	*after = acc;
	return keep_from;
}

int ask_compact_plan_summary(const struct ai_chat_msg *hist, int nhist,
			     size_t summary_bytes, long target_tokens,
			     int max_msgs, struct ask_compact_plan *plan)
{
	long summary_tokens;

	if (!plan || target_tokens <= 0)
		return -1;
	summary_tokens = (long)(ASK_COMPACT_SUMMARY_PREFIX_LEN +
				summary_bytes) / 3 + 1;
	if (summary_tokens > target_tokens)
		return -1;

	memset(plan, 0, sizeof(*plan));
	plan->before_tokens = ask_compact_hist_tokens(hist, nhist);
	plan->keep_first = 0;
	plan->keep_from = plan_keep_window(hist, nhist, 0, summary_tokens,
					   target_tokens, max_msgs,
					   &plan->after_tokens);
	return 0;
}

int ask_compact_plan_truncate(const struct ai_chat_msg *hist, int nhist,
			      long target_tokens, int max_msgs,
			      struct ask_compact_plan *plan)
{
	long base = 0;
	int start = 0;
	int pin = 0;

	if (!plan || target_tokens <= 0)
		return -1;

	memset(plan, 0, sizeof(*plan));
	plan->before_tokens = ask_compact_hist_tokens(hist, nhist);
	/* 单条摘要自身超目标：没有可保留的"最近原文"，只能丢弃；
	 * 否则它会永远留在历史里把每次请求顶超预算（W59 巨摘要回归）。
	 * 正常路径 summary_cap 已保证摘要装得下，这里是损坏/异常兜底。 */
	if (nhist == 1 && ask_compact_is_summary(&hist[0]) &&
	    ask_compact_msg_tokens(&hist[0]) > target_tokens) {
		plan->keep_first = 0;
		plan->keep_from = nhist;
		plan->after_tokens = 0;
		return 0;
	}
	if (nhist > 0 && ask_compact_is_summary(&hist[0])) {
		long t = ask_compact_msg_tokens(&hist[0]);

		if (t <= target_tokens) {
			pin = 1;
			base = t;
			start = 1;
		}
	}
	plan->keep_first = pin;
	plan->keep_from = plan_keep_window(hist, nhist, start, base,
					   target_tokens, max_msgs,
					   &plan->after_tokens);
	return 0;
}
