/* SPDX-License-Identifier: GPL-2.0 */
/*
 * replay.c - TUI 历史回放规划器实现（OCC-DEBT；规则见 occ_replay.h）
 */
#include "occ_replay.h"

#include <stdlib.h>
#include <string.h>

#define RP_COLS 72			/* 行估算口径（80 列减转写区留白） */

int occ_replay_est_lines(const occ_msg_row *r)
{
	size_t tl;
	int lines;

	if (!r)
		return 0;
	if (!strcmp(r->role, "user")) {
		tl = r->text ? strlen(r->text) : 0;
		return 1 + (int)((tl + RP_COLS - 1) / RP_COLS);
	}
	if (!strcmp(r->role, "assistant")) {
		tl = r->text ? strlen(r->text) : 0;
		lines = 1;			/* footer 行（回放标行） */
		if (r->reasoning && r->reasoning[0])
			lines += 1;		/* 折叠思维链单行 */
		lines += (int)((tl + RP_COLS - 1) / RP_COLS);
		lines += (int)r->ncalls;
		return lines;
	}
	return 0;				/* system/tool：不计（折叠/隐藏） */
}

/* 可回放行：user/assistant 且未被 /undo 隐藏 */
static int rp_visible(const occ_msg_row *r)
{
	return r && !r->reverted &&
	       (!strcmp(r->role, "user") || !strcmp(r->role, "assistant"));
}

/* 调用 id → 结果摘要：首个匹配 tool_call_id 的 tool 行文本 */
static const char *rp_tool_output(const occ_msg_row *rows, size_t n,
				  const char *call_id)
{
	size_t i;

	if (!call_id)
		return NULL;
	for (i = 0; i < n; i++)
		if (!rows[i].reverted && !strcmp(rows[i].role, "tool") &&
		    rows[i].tool_call_id &&
		    !strcmp(rows[i].tool_call_id, call_id))
			return rows[i].text && rows[i].text[0] ?
			       rows[i].text : NULL;
	return NULL;
}

/* assistant 消息 id + 工具名 → 执行 rc（occ_toolcall 行；缺=未落库） */
static int rp_tool_rc(const occ_tc_row *tcs, size_t ntc,
		      const char *msg_id, const char *tool)
{
	size_t i;

	if (!tcs || !msg_id || !tool)
		return 1;
	for (i = 0; i < ntc; i++)
		if (!strcmp(tcs[i].msg_id, msg_id) &&
		    !strcmp(tcs[i].tool, tool))
			return tcs[i].rc == 0 ? 0 : 1;
	return 1;				/* 无记录：按失败渲染不谎报 ✓ */
}

int occ_replay_plan(const occ_msg_row *rows, size_t n,
		    const occ_tc_row *tcs, size_t ntc,
		    int max_lines,
		    occ_replay_item **items, size_t *nitems,
		    size_t *n_earlier)
{
	occ_replay_item *out = NULL;
	size_t cap = 0, cnt = 0;
	/* first=纳入的最早可见行下标（尾部保底后往前扩到预算尽） */
	size_t first = n;
	long long used = 0;
	size_t earlier = 0;
	size_t i, k;
	int in_block = 0;

	if (!items || !nitems || !n_earlier)
		return -1;
	*items = NULL;
	*nitems = 0;
	*n_earlier = 0;

	/* ---- 尾部圈定：从最新往老扫，估算行数入预算 ----
	 * 最新一条可见消息无条件纳入（尾部保底——空回放无意义）；
	 * 其后每条：预算内纳入，预算外即止（再往前全记 earlier）。 */
	{
		int got_tail = 0;

		for (i = n; i > 0; i--) {
			const occ_msg_row *r = &rows[i - 1];
			int est;

			if (!rp_visible(r))
				continue;
			est = occ_replay_est_lines(r);
			if (!got_tail) {
				first = i - 1;
				used = est;
				got_tail = 1;
				continue;
			}
			if (max_lines > 0 && used + est > max_lines)
				break;
			first = i - 1;
			used += est;
		}
		/* first 之前的可见消息数 = earlier（隐藏/注记不计——
		 * 对用户不可见的行不冒充「更早历史」） */
		for (i = 0; i < first; i++)
			if (rp_visible(&rows[i]))
				earlier++;
	}

	/* ---- 事件容量上界：SEP + 每可见行（user 1；assistant 2+calls+1）
	 * + 组间 END——按实际展开计数分配一次 ---- */
	cap = 1 + 1;				/* SEP + 尾组 END 兜底 */
	for (i = first; i < n; i++) {
		if (!rp_visible(&rows[i]))
			continue;
		if (!strcmp(rows[i].role, "user")) {
			cap += 1 + 1;		/* USER + 前组 END */
		} else {
			cap += 2 + rows[i].ncalls * 2 + 1;
		}
	}
	out = malloc(cap * sizeof(*out));
	if (!out)
		return -1;

	if (earlier) {
		out[cnt].kind = OCC_RP_SEP;
		out[cnt].text = NULL;
		out[cnt].arg = NULL;
		out[cnt].rc = (int)(earlier > 0x7fffffff ? 0x7fffffff : earlier);
		cnt++;
	}
	for (i = first; i < n; i++) {
		const occ_msg_row *r = &rows[i];

		if (!rp_visible(r))
			continue;
		if (!strcmp(r->role, "user")) {
			if (in_block) {
				out[cnt].kind = OCC_RP_END;
				out[cnt].text = NULL;
				out[cnt].arg = NULL;
				out[cnt].rc = 0;
				cnt++;
				in_block = 0;
			}
			out[cnt].kind = OCC_RP_USER;
			out[cnt].text = r->text ? r->text : "";
			out[cnt].arg = NULL;
			out[cnt].rc = 0;
			cnt++;
			continue;
		}
		/* assistant：回合组开块（连续 assistant/tool 折叠为一个块） */
		if (!in_block) {
			out[cnt].kind = OCC_RP_BEGIN;
			out[cnt].text = NULL;
			out[cnt].arg = NULL;
			out[cnt].rc = 0;
			cnt++;
			in_block = 1;
		}
		if (r->reasoning && r->reasoning[0]) {
			out[cnt].kind = OCC_RP_REASON;
			out[cnt].text = r->reasoning;
			out[cnt].arg = NULL;
			out[cnt].rc = 0;
			cnt++;
		}
		if (r->text && r->text[0]) {
			out[cnt].kind = OCC_RP_TEXT;
			out[cnt].text = r->text;
			out[cnt].arg = NULL;
			out[cnt].rc = 0;
			cnt++;
		}
		for (k = 0; k < r->ncalls; k++) {
			const occ_toolcall_part *c = &r->calls[k];
			const char *summary;
			int rc;

			summary = rp_tool_output(rows, n, c->id);
			rc = summary ?
			     rp_tool_rc(tcs, ntc, r->id, c->tool) : 1;
			out[cnt].kind = OCC_RP_TOOL_START;
			out[cnt].text = c->tool ? c->tool : "?";
			out[cnt].arg = c->arguments ? c->arguments : "";
			out[cnt].rc = 0;
			cnt++;
			out[cnt].kind = OCC_RP_TOOL_END;
			out[cnt].text = c->tool ? c->tool : "?";
			out[cnt].arg = summary ? summary :
					"(结果未落库)";
			out[cnt].rc = rc;
			cnt++;
		}
	}
	if (in_block) {
		out[cnt].kind = OCC_RP_END;
		out[cnt].text = NULL;
		out[cnt].arg = NULL;
		out[cnt].rc = 0;
		cnt++;
	}

	*items = out;
	*nitems = cnt;
	*n_earlier = earlier;
	return 0;
}
