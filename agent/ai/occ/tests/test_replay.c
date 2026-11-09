/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_replay.c - TUI 历史回放规划器单测（OCC-DEBT）
 *
 * 两相：
 *   1. 纯规划（手造 occ_msg_row）：事件序列/预算切割/尾部保底/reverted
 *      隐藏/工具折叠/回合组合并/est_lines 口径；
 *   2. mock db 夹具（occ_msg_add_user/add_assistant/occ_tool_record 落
 *      真 SQLite → occ_msg_list 读回 → 规划）：DB 原文 → parts 解析 →
 *      事件序列端到端（回放进屏字节断言由 pty/取证脚本承接）。
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "occ_core/occ_replay.h"

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

/* ---- 手造行工具（strdup 存储；测试末统一 free） ---- */

static occ_msg_row mk_user(const char *id, const char *text, int reverted)
{
	occ_msg_row r;

	memset(&r, 0, sizeof(r));
	snprintf(r.id, sizeof(r.id), "%s", id);
	snprintf(r.role, sizeof(r.role), "user");
	r.text = strdup(text);
	r.reverted = reverted;
	return r;
}

static occ_msg_row mk_asst(const char *id, const char *text,
			   const char *reason, occ_toolcall_part *calls,
			   size_t ncalls, int reverted)
{
	occ_msg_row r;

	memset(&r, 0, sizeof(r));
	snprintf(r.id, sizeof(r.id), "%s", id);
	snprintf(r.role, sizeof(r.role), "assistant");
	if (text)
		r.text = strdup(text);
	if (reason)
		r.reasoning = strdup(reason);
	r.calls = calls;
	r.ncalls = ncalls;
	r.reverted = reverted;
	return r;
}

static occ_msg_row mk_tool(const char *id, const char *call_id,
			   const char *output)
{
	occ_msg_row r;

	memset(&r, 0, sizeof(r));
	snprintf(r.id, sizeof(r.id), "%s", id);
	snprintf(r.role, sizeof(r.role), "tool");
	r.tool_call_id = strdup(call_id);
	r.text = strdup(output);
	return r;
}

static occ_tc_row mk_tc(const char *msg_id, const char *tool, int rc)
{
	occ_tc_row t;

	memset(&t, 0, sizeof(t));
	snprintf(t.msg_id, sizeof(t.msg_id), "%s", msg_id);
	snprintf(t.tool, sizeof(t.tool), "%s", tool);
	t.rc = rc;
	return t;
}

/* 成员堆指针逐一释放（rows 本体与 calls 数组均为测试栈件——只释放
 * strdup 成员：text/reasoning/tool_call_id/calls[k].{id,tool,arguments}） */
static void free_rows(occ_msg_row *rows, size_t n)
{
	size_t i, k;

	for (i = 0; i < n; i++) {
		free(rows[i].text);
		free(rows[i].reasoning);
		free(rows[i].tool_call_id);
		for (k = 0; k < rows[i].ncalls; k++) {
			free(rows[i].calls[k].id);
			free(rows[i].calls[k].tool);
			free(rows[i].calls[k].arguments);
		}
	}
}

/* ---- 相 1：纯规划 ---- */

static void phase_pure(void)
{
	occ_replay_item *it = NULL;
	size_t ni = 0, ne = 0;

	/* 1. 空 → 零事件零 earlier */
	{
		occ_msg_row rows[1];
		size_t n = 0;

		memset(rows, 0, sizeof(rows));
		OK(occ_replay_plan(rows, n, NULL, 0, 200, &it, &ni, &ne) == 0,
		   "empty-plan-ok");
		OK(ni == 0 && ne == 0, "empty-no-events");
		free(it);
		it = NULL;
	}

	/* 2. 单轮 user+assistant（无工具）：[USER,BEGIN,TEXT,END] 无 SEP */
	{
		occ_msg_row rows[2];

		rows[0] = mk_user("msg_u1", "你好，请帮我看看", 0);
		rows[1] = mk_asst("msg_a1", "好的，马上处理", NULL, NULL, 0, 0);
		OK(occ_replay_plan(rows, 2, NULL, 0, 200, &it, &ni, &ne) == 0,
		   "turn1-plan-ok");
		OK(ni == 4, "turn1-4-items");
		OK(ne == 0, "turn1-no-earlier");
		if (ni == 4) {
			OK(it[0].kind == OCC_RP_USER &&
			   !strcmp(it[0].text, "你好，请帮我看看"),
			   "turn1-user-first");
			OK(it[1].kind == OCC_RP_BEGIN, "turn1-begin");
			OK(it[2].kind == OCC_RP_TEXT &&
			   !strcmp(it[2].text, "好的，马上处理"),
			   "turn1-text");
			OK(it[3].kind == OCC_RP_END, "turn1-end");
		}
		free(it);
		it = NULL;
		free_rows(rows, 2);
	}

	/* 3. 推理折叠 + 工具行（结果折叠 TOOL_END、rc 取 occ_toolcall） */
	{
		occ_msg_row rows[3];
		occ_toolcall_part calls[1];
		occ_tc_row tcs[1];

		calls[0].id = strdup("call_1");
		calls[0].tool = strdup("read");
		calls[0].arguments = strdup("{\"path\":\"/tmp/x\"}");
		rows[0] = mk_user("msg_u2", "读一下文件", 0);
		rows[1] = mk_asst("msg_a2", "文件内容是…", "用户要读文件",
				  calls, 1, 0);
		rows[2] = mk_tool("msg_t2", "call_1", "file-body-42B");
		tcs[0] = mk_tc("msg_a2", "read", 0);
		OK(occ_replay_plan(rows, 3, tcs, 1, 200, &it, &ni, &ne) == 0,
		   "turn2-plan-ok");
		/* 期望：USER BEGIN REASON TEXT TOOL_START TOOL_END END = 7 */
		OK(ni == 7, "turn2-7-items");
		if (ni == 7) {
			OK(it[2].kind == OCC_RP_REASON &&
			   !strcmp(it[2].text, "用户要读文件"),
			   "turn2-reason-folded");
			OK(it[4].kind == OCC_RP_TOOL_START &&
			   !strcmp(it[4].text, "read") &&
			   !strcmp(it[4].arg, "{\"path\":\"/tmp/x\"}"),
			   "turn2-tool-start-args");
			OK(it[5].kind == OCC_RP_TOOL_END &&
			   !strcmp(it[5].arg, "file-body-42B") &&
			   it[5].rc == 0,
			   "turn2-tool-end-result-rc");
			OK(it[6].kind == OCC_RP_END, "turn2-end");
		}
		free(it);
		it = NULL;
		free_rows(rows, 3);
	}

	/* 4. 工具结果未落库（crash 边界）：TOOL_END rc=1 + 占位摘要 */
	{
		occ_msg_row rows[2];
		occ_toolcall_part calls[1];

		calls[0].id = strdup("call_9");
		calls[0].tool = strdup("bash");
		calls[0].arguments = strdup("{}");
		rows[0] = mk_user("msg_u3", "跑个命令", 0);
		rows[1] = mk_asst("msg_a3", NULL, NULL, calls, 1, 0);
		OK(occ_replay_plan(rows, 2, NULL, 0, 200, &it, &ni, &ne) == 0,
		   "turn3-plan-ok");
		OK(ni == 5, "turn3-5-items");
		if (ni == 5) {
			OK(it[3].kind == OCC_RP_TOOL_END && it[3].rc == 1 &&
			   !strcmp(it[3].arg, "(结果未落库)"),
			   "turn3-missing-result-fail");
		}
		free(it);
		it = NULL;
		free_rows(rows, 2);
	}

	/* 5. 预算切割：多轮长消息 + 小预算 → SEP(earlier) + 尾部保底 */
	{
		occ_msg_row rows[6];
		char big[600];
		size_t i;

		memset(big, 'A', sizeof(big) - 1);
		big[sizeof(big) - 1] = '\0';
		for (i = 0; i < 3; i++) {
			char id[32];

			snprintf(id, sizeof(id), "msg_u%zu", i);
			rows[i * 2] = mk_user(id, big, 0);
			snprintf(id, sizeof(id), "msg_a%zu", i);
			rows[i * 2 + 1] = mk_asst(id, big, NULL, NULL, 0, 0);
		}
		/* 每轮 est=user(1+9)+asst(1+9)=20；预算 45 → 尾轮(20)+
		 * 第二轮(20)=40 纳入；首轮 20 超出 → earlier=2（u0+a0） */
		OK(occ_replay_plan(rows, 6, NULL, 0, 45, &it, &ni, &ne) == 0,
		   "budget-plan-ok");
		OK(ne == 2, "budget-earlier-2");
		if (ni > 0)
			OK(it[0].kind == OCC_RP_SEP && it[0].rc == 2,
			   "budget-sep-count");
		/* 尾部保底：首事件 SEP 后从第二轮 user 起（不是空回放） */
		OK(ni >= 5, "budget-tail-kept");
		/* 最新消息必在（尾 assistant 文本在末段） */
		if (ni >= 2)
			OK(it[ni - 2].kind == OCC_RP_TEXT, "budget-newest-in");
		free(it);
		it = NULL;
		free_rows(rows, 6);
	}

	/* 6. 极小预算尾部保底：最新一条可见消息无条件纳入 */
	{
		occ_msg_row rows[2];

		rows[0] = mk_user("msg_x0", "旧消息", 0);
		rows[1] = mk_user("msg_x1", "最新消息", 0);
		OK(occ_replay_plan(rows, 2, NULL, 0, 1, &it, &ni, &ne) == 0,
		   "tiny-budget-ok");
		OK(ni == 2 && it[0].kind == OCC_RP_SEP && it[0].rc == 1 &&
		   it[1].kind == OCC_RP_USER &&
		   !strcmp(it[1].text, "最新消息"), "tiny-budget-tail-only");
		OK(ne == 1, "tiny-budget-earlier-1");
		free(it);
		it = NULL;
		free_rows(rows, 2);
	}

	/* 7. reverted 隐藏：不回放也不计入 earlier（对用户不可见） */
	{
		occ_msg_row rows[4];

		rows[0] = mk_user("msg_h0", "被撤的旧问题", 1);
		rows[1] = mk_asst("msg_h1", "被撤的旧回答", NULL, NULL, 0, 1);
		rows[2] = mk_user("msg_h2", "当前问题", 0);
		rows[3] = mk_asst("msg_h3", "当前回答", NULL, NULL, 0, 0);
		OK(occ_replay_plan(rows, 4, NULL, 0, 200, &it, &ni, &ne) == 0,
		   "revert-plan-ok");
		OK(ne == 0, "revert-hidden-not-earlier");
		OK(ni == 4, "revert-only-visible");
		free(it);
		it = NULL;
		free_rows(rows, 4);
	}

	/* 8. 连续 assistant+tool 回合组合并为单块（footer 一条） */
	{
		occ_msg_row rows[5];
		occ_toolcall_part c1[1], c2[1];

		c1[0].id = strdup("call_a");
		c1[0].tool = strdup("read");
		c1[0].arguments = strdup("{}");
		c2[0].id = strdup("call_b");
		c2[0].tool = strdup("write");
		c2[0].arguments = strdup("{}");
		rows[0] = mk_user("msg_g0", "两步走", 0);
		rows[1] = mk_asst("msg_g1", "先读", NULL, c1, 1, 0);
		rows[2] = mk_tool("msg_g2", "call_a", "read-ok");
		rows[3] = mk_asst("msg_g3", "再写", NULL, c2, 1, 0);
		rows[4] = mk_tool("msg_g4", "call_b", "write-ok");
		OK(occ_replay_plan(rows, 5, NULL, 0, 200, &it, &ni, &ne) == 0,
		   "group-plan-ok");
		/* 期望：USER BEGIN TEXT TS TE TEXT TS TE END = 9；恰一个 END */
		{
			size_t k, nbegin = 0, nend = 0;

			for (k = 0; k < ni; k++) {
				if (it[k].kind == OCC_RP_BEGIN)
					nbegin++;
				if (it[k].kind == OCC_RP_END)
					nend++;
			}
			OK(nbegin == 1 && nend == 1, "group-single-block");
			OK(ni == 9, "group-9-items");
		}
		free(it);
		it = NULL;
		free_rows(rows, 5);
	}

	/* 9. est_lines 口径锚定 */
	{
		occ_msg_row r;

		memset(&r, 0, sizeof(r));
		snprintf(r.role, sizeof(r.role), "user");
		r.text = strdup("");
		OK(occ_replay_est_lines(&r) == 1, "est-user-empty-1");
		free(r.text);
		r.text = strdup("0123456789012345678901234567890123456789"
				"0123456789012345678901234567890123");
		/* 73 字节 → 1+2 */
		OK(occ_replay_est_lines(&r) == 3, "est-user-73b");
		free(r.text);
		free(r.reasoning);
		snprintf(r.role, sizeof(r.role), "assistant");
		r.reasoning = strdup("思考");
		r.text = strdup("0123456789");	/* 10B → 1 */
		r.ncalls = 2;
		/* 1(footer)+1(reason)+1(text)+2(calls) = 5 */
		OK(occ_replay_est_lines(&r) == 5, "est-asst-mixed");
		free(r.text);
		free(r.reasoning);
		snprintf(r.role, sizeof(r.role), "system");
		OK(occ_replay_est_lines(&r) == 0, "est-system-0");
	}
}

/* ---- 相 2：mock db 夹具（真 SQLite → 读回 → 规划） ---- */

static void phase_db(void)
{
	char dbp[512];
	occ_db *db;
	char err[256];
	occ_session_row ses;
	occ_msg_row *rows = NULL;
	occ_replay_item *it = NULL;
	size_t n = 0, ni = 0, ne = 0;
	occ_tool_call calls[1];
	char *mid1 = malloc(OCC_ID_LEN), *mid2 = malloc(OCC_ID_LEN);

	snprintf(dbp, sizeof(dbp), "/tmp/occ-replay-test-%d.db", (int)getpid());
	unlink(dbp);
	db = occ_db_open(dbp, err, sizeof(err));
	OK(db != NULL, "db-open");
	if (!db) {
		free(mid1);
		free(mid2);
		return;
	}
	OK(occ_session_create(db, "test-model", &ses, err, sizeof(err)) == 0,
	   "session-create");
	OK(occ_msg_add_user(db, ses.id, "请记住暗号：紫色企鹅", mid1,
			   OCC_ID_LEN, err, sizeof(err)) == 0, "add-user");
	memset(calls, 0, sizeof(calls));
	calls[0].id = (char *)"call_db1";
	calls[0].name = (char *)"bash";
	calls[0].arguments = (char *)"{\"cmd\":\"echo hi\"}";
	/* interim assistant（携带 toolCall）→ 工具结果 → 收口 assistant */
	OK(occ_msg_add_assistant_ex(db, ses.id, "先跑命令", NULL, calls, 1,
				    NULL, 0, "tool-calls", 1, mid2,
				    OCC_ID_LEN, err, sizeof(err)) == 0,
	   "add-asst-interim");
	OK(occ_tool_record(db, ses.id, mid2, "bash", "{\"cmd\":\"echo hi\"}",
			   "hi\n", 0, 12, "call_db1", NULL, 0, NULL, 0,
			   err, sizeof(err)) == 0, "tool-record");
	OK(occ_msg_add_assistant(db, ses.id, "暗号是紫色企鹅", "用户问暗号",
				 NULL, 0, NULL, 0, "stop", NULL, 0,
				 err, sizeof(err)) == 0, "add-asst-final");

	OK(occ_msg_list(db, ses.id, &rows, &n, err, sizeof(err)) == 0,
	   "msg-list");
	OK(n == 4, "db-4-rows");
	{
		occ_tc_row *tcs = NULL;
		size_t ntc = 0;

		OK(occ_toolcalls_since(db, ses.id, 0, &tcs, &ntc, err,
				       sizeof(err)) >= 0, "tc-since");
		OK(occ_replay_plan(rows, n, tcs, ntc, 200, &it, &ni, &ne) == 0,
		   "db-plan-ok");
		/* USER | BEGIN TEXT TS TE (msg2+folded tool) TEXT REASON END */
		{
			size_t k;
			int seen_user = 0, seen_ts = 0, seen_te = 0;

			for (k = 0; k < ni; k++) {
				if (it[k].kind == OCC_RP_USER &&
				    strstr(it[k].text, "紫色企鹅"))
					seen_user = 1;
				if (it[k].kind == OCC_RP_TOOL_START &&
				    !strcmp(it[k].text, "bash"))
					seen_ts = 1;
				if (it[k].kind == OCC_RP_TOOL_END &&
				    it[k].rc == 0 &&
				    strstr(it[k].arg, "hi"))
					seen_te = 1;
			}
			OK(seen_user, "db-user-replayed");
			OK(seen_ts, "db-tool-start");
			OK(seen_te, "db-tool-end-folded");
			/* 单块（组内 2 assistant 合并）恰一个 BEGIN/END */
			{
				int nb = 0, ne2 = 0;

				for (k = 0; k < ni; k++) {
					nb += it[k].kind == OCC_RP_BEGIN;
					ne2 += it[k].kind == OCC_RP_END;
				}
				OK(nb == 1 && ne2 == 1, "db-single-block");
			}
			OK(ne == 0, "db-no-earlier");
		}
		free(it);
		occ_tc_rows_free(tcs, ntc);
	}
	occ_msg_rows_free(rows, n);
	occ_db_close(db);
	unlink(dbp);
	free(mid1);
	free(mid2);
}

int main(void)
{
	phase_pure();
	phase_db();
	printf("test_replay: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
