/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_loop.c - occ_core/loop 单测（T9a3 + T9b1 工具环）
 *
 * 全环驱动：注入伪传输（occ_llm_call_fn 替身）——内部 occ_sse 直接
 * feed SSE 字节（内联构造基，语义对齐 a1 差分台架 fixtures/openai 下；
 * 环境变量 OCC_VECTORS_DIR 指向 a1 vectors 时额外用真 fixture 文件
 * 回放一环）。断言链：输入→落库→流式→落库（消息数/角色/usage/tokens/
 * status）。
 *
 * 伪传输还会记录收到的 occ_llm_req 关键字段（system prompt 进请求、
 * 历史全量、b1 六件套 tools）——上下文组装的间接断言。
 *
 * mock 仅本单测（生产路径 occ -p 走真 occ_llm_call）。
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sqlite3.h>

#include "occ_core/occ_loop.h"
#include "occ_core/occ_revert.h"
#include "occ_core/occ_sysprompt.h"

static int n_fail;
static int n_ok;

#define OK(cond, name) do { \
	if (cond) { n_ok++; printf("ok %s\n", name); } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

/* ---- 内联构造基 SSE（openai 语义；键序无关——occ_sse 按 JSON 解析） ---- */

static const char SSE_NORMAL[] =
	"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\","
	"\"content\":\"你好\"}}]}\n\n"
	"data: {\"choices\":[{\"delta\":{\"content\":\"，世界\"}}]}\n\n"
	"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"
	"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":55,"
	"\"completion_tokens\":6,\"prompt_tokens_details\":"
	"{\"cached_tokens\":10}}}\n\n"
	"data: [DONE]\n\n";

static const char SSE_NO_USAGE[] =
	"data: {\"choices\":[{\"delta\":{\"content\":\"短回复\"}}]}\n\n"
	"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"
	"data: [DONE]\n\n";

/* B1：OutputLimit 截断轮（finish=length 且有正文 → loop 续跑） */
static const char SSE_LENGTH[] =
	"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\","
	"\"content\":\"前半\"}}]}\n\n"
	"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"length\"}]}\n\n"
	"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":50,"
	"\"completion_tokens\":5}}\n\n"
	"data: [DONE]\n\n";

static const char SSE_BAD[] =
	"data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n"
	"data: {THIS IS NOT JSON}\n\n"
	"data: {\"choices\":[{\"delta\":{\"content\":\"after bad\"}}]}\n\n"
	"data: [DONE]\n\n";

/* ---- b1 工具环 fixtures（两段序列：调用 + 收口） ---- */

static const char SSE_TOOLCALL_WRITE[] =
	"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\","
	"\"tool_calls\":[{\"index\":0,\"id\":\"call_w1\",\"type\":"
	"\"function\",\"function\":{\"name\":\"write\",\"arguments\":"
	"\"\"}}]}}]}\n\n"
	"data: {\"choices\":[{\"delta\":{\"tool_calls\":"
	"[{\"index\":0,\"function\":{\"arguments\":\"{\\\"path\\\":\\\"ringtest.txt\\\",\"}}]}}]}\n\n"
	"data: {\"choices\":[{\"delta\":{\"tool_calls\":"
	"[{\"index\":0,\"function\":{\"arguments\":\"\\\"content\\\":\\\"ring4-body\\\"}\"}}]}}]}\n\n"
	"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n"
	"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":40,"
	"\"completion_tokens\":12}}\n\n"
	"data: [DONE]\n\n";

static const char SSE_TOOLCALL_UNKNOWN[] =
	"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\","
	"\"tool_calls\":[{\"index\":0,\"id\":\"call_u1\",\"type\":"
	"\"function\",\"function\":{\"name\":\"no_such_tool\","
	"\"arguments\":\"{}\"}}]}}]}\n\n"
	"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n"
	"data: [DONE]\n\n";

static const char SSE_FINAL_OK[] =
	"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\","
	"\"content\":\"文件已写好\"}}]}\n\n"
	"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"
	"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":70,"
	"\"completion_tokens\":5}}\n\n"
	"data: [DONE]\n\n";

/* ---- LT-BUG-001 fixtures（anthropic 智谱形态：thinking 块@0 + tool_use@1；
 * 与 SSE_ANT_* 既有形态的差异即线上块序不从工具 0 起） ---- */

static const char SSE_ANT_ZHIPU_TOOLCALL[] =
	"data: {\"type\":\"message_start\",\"message\":{\"usage\":"
	"{\"input_tokens\":30}}}\n\n"
	"data: {\"type\":\"content_block_start\",\"index\":0,"
	"\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\","
	"\"signature\":\"\"}}\n\n"
	"data: {\"type\":\"content_block_delta\",\"index\":0,"
	"\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"先读文件\"}}\n\n"
	"data: {\"type\":\"content_block_stop\",\"index\":0}\n\n"
	"data: {\"type\":\"content_block_start\",\"index\":1,"
	"\"content_block\":{\"type\":\"tool_use\",\"id\":\"call_zp1\","
	"\"name\":\"read\",\"input\":{}}}\n\n"
	"data: {\"type\":\"content_block_delta\",\"index\":1,"
	"\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":"
	"\"{\\\"path\\\":\\\"ringtest.txt\\\"}\"}}\n\n"
	"data: {\"type\":\"content_block_stop\",\"index\":1}\n\n"
	"data: {\"type\":\"message_delta\",\"delta\":"
	"{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":8}}\n\n"
	"data: {\"type\":\"message_stop\"}\n\n";

static const char SSE_ANT_FINAL[] =
	"data: {\"type\":\"content_block_start\",\"index\":0,"
	"\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n"
	"data: {\"type\":\"content_block_delta\",\"index\":0,"
	"\"delta\":{\"type\":\"text_delta\",\"text\":\"已读到\"}}\n\n"
	"data: {\"type\":\"message_delta\",\"delta\":"
	"{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":3}}\n\n"
	"data: {\"type\":\"message_stop\"}\n\n";

/* ---- 伪传输 ---- */

static const char *g_seq[4];			/* 回放序列（末位循环） */
static int g_seq_n, g_seq_i;
static char g_req_log[4096];			/* req 关键字段记录 */
static int g_req_ntools = -1;
static size_t g_req_nmsgs;
static const char *g_req_system;
static char g_msgs_log[2048];
static int g_fake_reset;			/* b2：先发垃圾文本+RESET 再
						 * 回放（验证收集器清空） */

static void sse_set(const char *one)
{
	g_seq[0] = one;
	g_seq_n = 1;
	g_seq_i = 0;
}

static void sse_set2(const char *a, const char *b)
{
	g_seq[0] = a;
	g_seq[1] = b;
	g_seq_n = 2;
	g_seq_i = 0;
}

static int fake_llm_call(const occ_provider *p, const occ_llm_req *req,
			 occ_event_cb cb, void *ud, char **err_out)
{
	occ_sse *sse;
	size_t i;
	const char *cur;

	(void)p;
	if (err_out)
		*err_out = NULL;
	/* 记录 req 组装面（上下文组装断言用） */
	g_req_ntools = (int)req->ntools;
	g_req_nmsgs = req->nmsgs;
	g_req_system = req->system;
	g_msgs_log[0] = '\0';
	for (i = 0; i < req->nmsgs && strlen(g_msgs_log) + 96 <
	     sizeof(g_msgs_log); i++) {
		char one[96];

		snprintf(one, sizeof(one), "%s:%.24s|",
			 req->msgs[i].role == OCC_ROLE_ASSISTANT ?
			 "A" : req->msgs[i].role == OCC_ROLE_TOOL ?
			 "T" : "U",
			 req->msgs[i].text ? req->msgs[i].text : "");
		strcat(g_msgs_log, one);
		if (req->msgs[i].role == OCC_ROLE_ASSISTANT &&
		    req->msgs[i].ncalls &&
		    strlen(g_msgs_log) + 32 < sizeof(g_msgs_log)) {
			char c[32];

			snprintf(c, sizeof(c), "(calls=%zu)",
				 req->msgs[i].ncalls);
			strcat(g_msgs_log, c);
		}
		if (req->msgs[i].role == OCC_ROLE_TOOL &&
		    req->msgs[i].tool_call_id &&
		    strlen(g_msgs_log) + 40 < sizeof(g_msgs_log)) {
			char c[40];

			snprintf(c, sizeof(c), "(tcid=%.16s)",
				 req->msgs[i].tool_call_id);
			strcat(g_msgs_log, c);
		}
	}
	snprintf(g_req_log, sizeof(g_req_log),
		 "tools=%d nmsgs=%zu system=%zd", g_req_ntools, g_req_nmsgs,
		 (ssize_t)(req->system ? strlen(req->system) : 0));

	if (g_fake_reset) {
		/* b2：上一尝试的部分输出 → OCC_EV_RESET → 正式回放。
		 * 消费方必须清空已累积内容（GARBAGE 不得进最终结果）。 */
		occ_event ev;

		memset(&ev, 0, sizeof(ev));
		ev.type = OCC_EV_TEXT_DELTA;
		ev.text = "GARBAGE-";
		cb(&ev, ud);
		memset(&ev, 0, sizeof(ev));
		ev.type = OCC_EV_RESET;
		ev.err = "重试：第 1/2 次尝试将在 1ms 后重发（单测模拟）";
		cb(&ev, ud);
	}

	cur = g_seq[g_seq_i < g_seq_n ? g_seq_i : g_seq_n - 1];
	g_seq_i++;
	sse = occ_sse_new(req->proto, cb, ud);
	if (!sse)
		return -1;
	occ_sse_feed(sse, cur, strlen(cur));
	occ_sse_finish(sse);
	occ_sse_free(sse);
	return 0;
}

static char tmpdir[128];

static char *dbpath(void)
{
	static char path[256];

	snprintf(path, sizeof(path), "%s/sessions.db", tmpdir);
	return path;
}

static int count_rows(const char *sql, const char *bind)
{
	sqlite3 *h;
	sqlite3_stmt *st;
	int n = -1;

	if (sqlite3_open_v2(dbpath(), &h, SQLITE_OPEN_READONLY, NULL) !=
	    SQLITE_OK)
		return -1;
	if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK) {
		if (bind)
			sqlite3_bind_text(st, 1, bind, -1, SQLITE_TRANSIENT);
		if (sqlite3_step(st) == SQLITE_ROW)
			n = sqlite3_column_int(st, 0);
		sqlite3_finalize(st);
	}
	sqlite3_close(h);
	return n;
}

static int msgs_of(const char *sid)
{
	return count_rows("SELECT COUNT(*) FROM occ_message WHERE"
			  " session_id=?1", sid);
}

/* 读一列 int64（sql 两参：bind sid） */
static long long ll_of(const char *sql, const char *sid)
{
	sqlite3 *h;
	sqlite3_stmt *st;
	long long v = -1;

	if (sqlite3_open_v2(dbpath(), &h, SQLITE_OPEN_READONLY, NULL) !=
	    SQLITE_OK)
		return -1;
	if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK) {
		sqlite3_bind_text(st, 1, sid, -1, SQLITE_TRANSIENT);
		if (sqlite3_step(st) == SQLITE_ROW)
			v = sqlite3_column_int64(st, 0);
		sqlite3_finalize(st);
	}
	sqlite3_close(h);
	return v;
}

static char *str_of(const char *sql, const char *sid)
{
	sqlite3 *h;
	sqlite3_stmt *st;
	char *v = NULL;

	if (sqlite3_open_v2(dbpath(), &h, SQLITE_OPEN_READONLY, NULL) !=
	    SQLITE_OK)
		return NULL;
	if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK) {
		sqlite3_bind_text(st, 1, sid, -1, SQLITE_TRANSIENT);
		if (sqlite3_step(st) == SQLITE_ROW) {
			const unsigned char *t = sqlite3_column_text(st, 0);

			v = t ? strdup((const char *)t) : NULL;
		}
		sqlite3_finalize(st);
	}
	sqlite3_close(h);
	return v;
}

/* status 快捷断言值（str_of + 显式判空——GNU ?: 在 -std=c11 禁用） */
static int status_is(const char *sid, const char *want)
{
	char *s = str_of("SELECT status FROM occ_session WHERE id=?1", sid);
	int eq = s && !strcmp(s, want);

	free(s);
	return eq;
}

/* shell 命令 rc==0 断言（trace/快照存在性检查） */
static int system_exit0(const char *cmd)
{
	fflush(NULL);
	return system(cmd) == 0;
}

int main(void)
{
	char err[512] = "";
	occ_db *db;
	occ_provider p;
	occ_loop_opts opts;
	occ_loop_result res;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/occ_loop_t_%d", (int)getpid());
	mkdir(tmpdir, 0755);
	db = occ_db_open(dbpath(), err, sizeof(err));
	OK(db != NULL, "db-open");

	memset(&p, 0, sizeof(p));
	p.proto = OCC_PROTO_OPENAI_COMPAT;
	snprintf(p.model, sizeof(p.model), "deepseek-flash");
	snprintf(p.base_url, sizeof(p.base_url), "%s", "http://127.0.0.1:1");

	/* ---- 用例 1：正常全环 ---- */
	sse_set(SSE_NORMAL);
	memset(&opts, 0, sizeof(opts));
	opts.prompt = "打个招呼";
	opts.llm_call = fake_llm_call;
	opts.stream_out = tmpfile();
	{
		int rc = occ_loop_run(db, &p, NULL, &opts, &res, err,
				      sizeof(err));

		OK(rc == OCC_LOOP_OK, "loop1-rc-ok");
		OK(res.session_id[0] != '\0', "loop1-session-created");
		OK(msgs_of(res.session_id) == 2, "loop1-two-msgs");
		OK(status_is(res.session_id, "active"), "loop1-status-active");
		OK(g_req_ntools == 6, "loop1-req-six-tools");
		OK(g_req_nmsgs == 1, "loop1-req-nmsgs-1");
		OK(g_req_system == OCC_SYSTEM_PROMPT,
		   "loop1-system-prompt-const");
		/* usage 落库 + tokens_total（55+6=61） */
		OK(ll_of("SELECT tokens_total FROM occ_session WHERE id=?1",
			 res.session_id) == 61, "loop1-tokens-61");
		OK(ll_of("SELECT usage_cache_read FROM occ_message WHERE"
			 " session_id=?1 AND role='assistant'",
			 res.session_id) == 10, "loop1-cache-read-col");
		{
			char *fin = str_of("SELECT finish FROM occ_message"
					   " WHERE session_id=?1 AND"
					   " role='assistant'",
					   res.session_id);

			OK(fin && !strcmp(fin, "stop"), "loop1-finish-stop");
			free(fin);
		}
		/* 流式输出捕获：正文完整 */
		{
			char cap[256];
			size_t n;

			rewind(opts.stream_out);
			n = fread(cap, 1, sizeof(cap) - 1, opts.stream_out);
			cap[n] = '\0';
			OK(strstr(cap, "你好，世界") != NULL,
			   "loop1-stream-captured");
		}
		fclose(opts.stream_out);
		occ_loop_result_free(&res);
	}

	/* ---- 用例 1b（B1）：OutputLimit 续跑（finish=length 且有正文，
	 * 至多 OCC_LOOP_MAX_LEN_CONT 次）——mock 层断言完整链路：
	 * 轮 1 截断（length+正文）→ 轮 2 续跑（stop），两轮 assistant
	 * 均落库、收口 finish=stop、收口正文含两段、轮 2 请求上下文
	 * 含轮 1 assistant 截断文本。 ---- */
	sse_set2(SSE_LENGTH, SSE_NORMAL);
	memset(&opts, 0, sizeof(opts));
	opts.prompt = "写长文";
	opts.llm_call = fake_llm_call;
	opts.stream_out = tmpfile();
	{
		int rc = occ_loop_run(db, &p, NULL, &opts, &res, err,
				      sizeof(err));
		char *fin;
		int nfin;

		OK(rc == OCC_LOOP_OK, "loop1b-rc-ok");
		OK(msgs_of(res.session_id) == 3,
		   "loop1b-3-msgs-user+2assistant");
		OK(res.finish && !strcmp(res.finish, "stop"),
		   "loop1b-final-finish-stop");
		/* 收口轮 ctx 每轮新收集器 → res.text=末轮正文（opencode
		 * 同语义：续跑轮各自成 assistant 消息；拼接面在流式输出
		 * 与库） */
		OK(res.text && strstr(res.text, "你好") != NULL,
		   "loop1b-text-final-round");
		{
			char cap[512];
			size_t n;

			rewind(opts.stream_out);
			n = fread(cap, 1, sizeof(cap) - 1, opts.stream_out);
			cap[n] = '\0';
			OK(strstr(cap, "前半") != NULL &&
			   strstr(cap, "你好") != NULL,
			   "loop1b-stream-both-parts");
		}
		fin = str_of("SELECT finish FROM occ_message WHERE"
			     " session_id=?1 AND role='assistant'"
			     " ORDER BY rowid DESC LIMIT 1",
			     res.session_id);
		OK(fin && !strcmp(fin, "stop"),
		   "loop1b-db-last-assistant-stop");
		free(fin);
		nfin = (int)ll_of("SELECT COUNT(*) FROM occ_message WHERE"
				  " session_id=?1 AND role='assistant'",
				  res.session_id);
		OK(nfin == 2, "loop1b-two-assistant-rounds");
		/* 轮 2（续跑）请求上下文含轮 1 截断 assistant（fake 记录
		 * 的是最后一次调用面） */
		OK(strstr(g_msgs_log, "A:前半") != NULL,
		   "loop1b-cont-ctx-has-truncated-assistant");
		/* DB 中间轮 finish=length 落账 */
		fin = str_of("SELECT finish FROM occ_message WHERE"
			     " session_id=?1 AND role='assistant'"
			     " ORDER BY rowid ASC LIMIT 1",
			     res.session_id);
		OK(fin && !strcmp(fin, "length"),
		   "loop1b-db-first-assistant-length");
		free(fin);
	}
	fclose(opts.stream_out);
	occ_loop_result_free(&res);

	/* ---- 用例 2：续接（--session 语义）——历史全量进请求 ---- */
	sse_set(SSE_NORMAL);
	memset(&opts, 0, sizeof(opts));
	opts.prompt = "第一轮";
	opts.llm_call = fake_llm_call;
	{
		char sid[OCC_ID_LEN];
		int rc = occ_loop_run(db, &p, NULL, &opts, &res, err,
				      sizeof(err));

		OK(rc == OCC_LOOP_OK, "loop2-first-turn");
		snprintf(sid, sizeof(sid), "%s", res.session_id);
		occ_loop_result_free(&res);

		opts.prompt = "第二轮（续接）";
		sse_set(SSE_NORMAL);
		rc = occ_loop_run(db, &p, sid, &opts, &res, err, sizeof(err));
		OK(rc == OCC_LOOP_OK, "loop2-second-turn");
		OK(msgs_of(sid) == 4, "loop2-four-msgs");
		OK(g_req_nmsgs == 3, "loop2-history-in-req");
		OK(strstr(g_msgs_log, "U:第一轮|") != NULL &&
		   strstr(g_msgs_log, "A:你好") != NULL,
		   "loop2-history-content");
		OK(ll_of("SELECT tokens_total FROM occ_session WHERE id=?1",
			 sid) == 122, "loop2-tokens-accum-122");
		occ_loop_result_free(&res);

		/* ---- 用例 3：重放（--recover 语义；不重复落 user） ---- */
		{
			occ_msg_row last;

			/* 手动制造中断环：user 落库（status=running）后不跑
			 * LLM——等效 kill -9 在流式中途 */
			OK(occ_msg_add_user(db, sid, "被中断的问题", NULL, 0,
					    err, sizeof(err)) == 0,
			   "loop3-add-user");
			OK(occ_msg_last(db, sid, &last, err, sizeof(err)) == 1
			   && !strcmp(last.role, "user"),
			   "loop3-last-user");
			occ_msg_row_free(&last);
			opts.prompt = NULL;	/* 重放 */
			sse_set(SSE_NORMAL);
			rc = occ_loop_run(db, &p, sid, &opts, &res, err,
					  sizeof(err));
			OK(rc == OCC_LOOP_OK, "loop3-replay-rc");
			OK(msgs_of(sid) == 6, "loop3-no-dup-user");
			OK(g_req_nmsgs == 5, "loop3-replay-history");
			OK(status_is(sid, "active"), "loop3-status-active");
			occ_loop_result_free(&res);
		}

		/* ---- 用例 4（b1）：工具环全链——tool_call→执行→durable
		 *    落库→回灌→收口（fixture 两段：write 调用 + 收口文本） */
		{
			char wd[256], snaproot[300], tracedir[300];
			char fpath[320];
			FILE *probe;

			snprintf(wd, sizeof(wd), "%s/ring4", tmpdir);
			mkdir(wd, 0755);
			snprintf(snaproot, sizeof(snaproot), "%s/snaps",
				 tmpdir);
			snprintf(tracedir, sizeof(tracedir), "%s/trace",
				 tmpdir);
			setenv("OCC_SNAPROOT", snaproot, 1);
			setenv("OCC_TRACE_DIR", tracedir, 1);
			opts.prompt = "帮我写文件 ringtest.txt";
			opts.workdir = wd;
			sse_set2(SSE_TOOLCALL_WRITE, SSE_FINAL_OK);
			rc = occ_loop_run(db, &p, sid, &opts, &res, err,
					  sizeof(err));
			OK(rc == OCC_LOOP_OK, "loop4-rc-ok");
			/* 真执行：文件真出现、内容正确 */
			snprintf(fpath, sizeof(fpath), "%s/ringtest.txt",
				 wd);
			probe = fopen(fpath, "rb");
			OK(probe != NULL, "loop4-file-really-created");
			if (probe) {
				char body[64];
				size_t n = fread(body, 1, sizeof(body) - 1,
						 probe);

				body[n] = '\0';
				OK(!strcmp(body, "ring4-body"),
				   "loop4-file-content");
				fclose(probe);
			}
			/* 消息序：+4 = assistant(toolCall)+tool+assistant */
			OK(msgs_of(sid) == 10, "loop4-msg-seq-4-new");
			/* occ_toolcall 行：tool=write rc=0，message_id=携带
			 * toolCall 的 assistant 消息 */
			OK(count_rows("SELECT COUNT(*) FROM occ_toolcall"
				      " WHERE tool='write' AND rc=0", NULL)
			   == 1, "loop4-toolcall-row");
			{
				char *mid = str_of(
					"SELECT message_id FROM occ_toolcall"
					" WHERE tool='write'", NULL);
				char *role = NULL;

				if (mid) {
					sqlite3 *h;
					sqlite3_stmt *st;

					if (sqlite3_open_v2(dbpath(), &h,
						SQLITE_OPEN_READONLY,
						NULL) == SQLITE_OK) {
						char q[256];

						snprintf(q, sizeof(q),
						  "SELECT role FROM"
						  " occ_message WHERE id='%s'",
						  mid);
						if (sqlite3_prepare_v2(h, q,
							-1, &st,
							NULL) == SQLITE_OK &&
						    sqlite3_step(st) ==
						    SQLITE_ROW) {
							const unsigned char
								*t =
								sqlite3_column_text(st, 0);

							role = strdup((const char *)
								      t);
							sqlite3_finalize(st);
						}
						sqlite3_close(h);
					}
				}
				OK(role && !strcmp(role, "assistant"),
				   "loop4-toolcall-msgid-is-assistant");
				free(mid);
				free(role);
			}
			/* durable 回灌：收口轮请求含 assistant(calls=1)+
			 * tool(tcid=call_w1)；tool 消息 content 带
			 * toolCallID */
			OK(strstr(g_msgs_log, "(calls=1)") != NULL,
			   "loop4-req-assistant-calls");
			OK(strstr(g_msgs_log, "(tcid=call_w1)") != NULL,
			   "loop4-req-tool-tcid");
			{
				char *cj = str_of(
					"SELECT content_json FROM occ_message"
					" WHERE session_id=?1 AND"
					" role='tool' ORDER BY created DESC"
					" LIMIT 1", sid);

				OK(cj && strstr(cj,
						"\"toolCallID\":\"call_w1\"") &&
				   strstr(cj, "已写入"),
				   "loop4-toolresult-part");
				free(cj);
			}
			/* 快照地基：新建文件 → ABSENT 墓碑 */
			{
				char cmd[512];

				snprintf(cmd, sizeof(cmd),
					 "find %s -name '*.ABSENT'"
					 " 2>/dev/null | grep -q .", snaproot);
				OK(system_exit0(cmd), "loop4-snapshot-absent");
			}
			/* trace JSONL：一行 tool_exec */
			{
				char cmd[512];
				int trc;

				snprintf(cmd, sizeof(cmd),
					 "grep -c '\"event\":\"tool_exec\"'"
					 " %s/%s.jsonl 2>/dev/null",
					 tracedir, sid);
				/* 行数 ≥1（该会话此前无工具） */
				trc = system_exit0(cmd);
				if (!trc)
					fprintf(stderr, "DBG trace cmd: %s"
						" (rc=%d)\n", cmd, trc);
				OK(trc, "loop4-trace-line");
			}
			OK(status_is(sid, "active"), "loop4-status-active");
			OK(res.unexpected_toolcalls == 1,
			   "loop4-one-call-executed");
			occ_loop_result_free(&res);
			opts.workdir = NULL;
		}

		/* ---- 用例 4b：未知工具名→错误文本回灌（不崩） ---- */
		{
			opts.prompt = "调用不存在的工具";
			sse_set2(SSE_TOOLCALL_UNKNOWN, SSE_FINAL_OK);
			rc = occ_loop_run(db, &p, sid, &opts, &res, err,
					  sizeof(err));
			OK(rc == OCC_LOOP_OK, "loop4b-rc-ok");
			{
				char *cj = str_of(
					"SELECT content_json FROM occ_message"
					" WHERE session_id=?1 AND"
					" role='tool' ORDER BY created DESC"
					" LIMIT 1", sid);

				OK(cj && strstr(cj, "未知工具"),
				   "loop4b-error-fed-back");
				free(cj);
			}
			OK(count_rows("SELECT COUNT(*) FROM occ_toolcall"
				      " WHERE tool='no_such_tool' AND rc=1",
				      NULL) == 1, "loop4b-toolcall-rc1");
			occ_loop_result_free(&res);
		}

		/* ---- 用例 4z（LT-BUG-001 回归）：anthropic 智谱形态——
		 *    thinking 块占线上 idx 0、tool_use 在 idx 1。收集器
		 *    append-on-START 映射：恰 1 个真调用，零幻影空调用
		 *    （修前按线上 idx 开槽→空名调用→未知工具→重试雪崩） */
		{
			char wd2[256];
			char sid2[OCC_ID_LEN];

			snprintf(wd2, sizeof(wd2), "%s/ring4", tmpdir);
			opts.prompt = "读 ringtest.txt";
			opts.workdir = wd2;
			p.proto = OCC_PROTO_ANTHROPIC;
			sse_set2(SSE_ANT_ZHIPU_TOOLCALL, SSE_ANT_FINAL);
			rc = occ_loop_run(db, &p, NULL, &opts, &res, err,
					  sizeof(err));
			OK(rc == OCC_LOOP_OK, "loop4z-rc-ok");
			snprintf(sid2, sizeof(sid2), "%s", res.session_id);
			OK(msgs_of(sid2) == 4, "loop4z-msg-seq-4-new");
			OK(count_rows("SELECT COUNT(*) FROM occ_toolcall"
				      " WHERE tool='read' AND rc=0", NULL)
			   == 1, "loop4z-one-real-call");
			OK(count_rows("SELECT COUNT(*) FROM occ_toolcall"
				      " WHERE tool=''", NULL) == 0,
			   "loop4z-no-phantom-call");
			occ_loop_result_free(&res);
			p.proto = OCC_PROTO_OPENAI_COMPAT;
		}

		/* ---- 用例 5：坏流（负向）→ ELLM + status=error ---- */
		opts.prompt = "坏流测试";
		sse_set(SSE_BAD);
		rc = occ_loop_run(db, &p, sid, &opts, &res, err, sizeof(err));
		OK(rc == OCC_LOOP_ELLM, "loop5-rc-ellm");
		OK(msgs_of(sid) == 15, "loop5-user-kept-no-assistant");
		OK(status_is(sid, "error"), "loop5-status-error");
		occ_loop_result_free(&res);

		/* ---- 用例 6：error 状态也可重放（网络错重试语义） ---- */
		opts.prompt = NULL;
		sse_set(SSE_NORMAL);
		rc = occ_loop_run(db, &p, sid, &opts, &res, err, sizeof(err));
		OK(rc == OCC_LOOP_OK, "loop6-replay-after-error");
		OK(msgs_of(sid) == 16, "loop6-replayed");
		occ_loop_result_free(&res);

		/* ---- 用例 7：无 usage → len/4 估算 + est 标志 ---- */
		opts.prompt = "估算测试";
		sse_set(SSE_NO_USAGE);
		rc = occ_loop_run(db, &p, sid, &opts, &res, err, sizeof(err));
		OK(rc == OCC_LOOP_OK, "loop7-rc-ok");
		OK(res.usage_est == 1, "loop7-est-flag");
		OK(res.usage.input > 0 && res.usage.output > 0,
		   "loop7-est-both-positive");
		OK(ll_of("SELECT tokens_est FROM occ_session WHERE id=?1",
			 sid) == 1, "loop7-session-est-col");
			OK(ll_of("SELECT usage_in FROM occ_message WHERE"
				 " session_id=?1 AND role='assistant' AND"
				 " usage_est=1", sid) > 0, "loop7-msg-est-row");
			occ_loop_result_free(&res);
		/* ---- 用例 9（b2）：reverted 过滤——被撤消息不进请求 ---- */
		{
			occ_msg_row *all = NULL;
			size_t na = 0;
			char idsjson[160];
			long long ch = 0;

			OK(occ_msg_list(db, sid, &all, &na, err, sizeof(err)) ==
			   0 && na >= 2, "loop9-list");
			/* 首轮 user+assistant（"第一轮" 仅此一处出现） */
			snprintf(idsjson, sizeof(idsjson), "[\"%s\",\"%s\"]",
				 all[0].id, all[1].id);
			OK(!all[0].reverted && !all[1].reverted,
			   "loop9-first-visible");
			occ_msg_rows_free(all, na);
			OK(occ_msgs_set_reverted(db, sid, idsjson, 1, &ch, err,
						 sizeof(err)) == 0 && ch == 2,
			   "loop9-hide-first-turn");
			opts.prompt = "第九问：验证过滤";
			sse_set(SSE_NORMAL);
			rc = occ_loop_run(db, &p, sid, &opts, &res, err,
					  sizeof(err));
			OK(rc == OCC_LOOP_OK, "loop9-rc");
			OK(strstr(g_msgs_log, "第一轮") == NULL,
			   "loop9-reverted-excluded");
			OK(strstr(g_msgs_log, "第九问") != NULL,
			   "loop9-new-prompt-included");
			occ_loop_result_free(&res);
			/* 复原（后续用例不依赖隐藏态） */
			OK(occ_msgs_set_reverted(db, sid, idsjson, 0, &ch, err,
						 sizeof(err)) == 0 && ch == 2,
			   "loop9-unhide");
		}

		/* ---- 用例 10（b2）：SIGINT 安全点（LLM 轮前）→ interrupted
		 *    + 尾态可重放 + 不冒充收口产物 ---- */
		{
			occ_msg_row last;

			occ_interrupt_flag = 1;
			opts.prompt = "第十问：应立即中断";
			sse_set(SSE_NORMAL);		/* 复位 fake 计数=0 */
			rc = occ_loop_run(db, &p, sid, &opts, &res, err,
					  sizeof(err));
			OK(rc == OCC_LOOP_OK, "loop10-rc-ok");
			OK(res.interrupted == 1, "loop10-interrupted-flag");
			OK(g_seq_i == 0, "loop10-llm-not-called");
			OK(status_is(sid, "interrupted"),
			   "loop10-status-interrupted");
			OK(occ_msg_last(db, sid, &last, err, sizeof(err)) == 1
			   && !strcmp(last.role, "user"),
			   "loop10-tail-user-replayable");
			occ_msg_row_free(&last);
			OK(res.text == NULL && res.assistant_msg_id[0] == '\0',
			   "loop10-no-fake-output");
			occ_loop_result_free(&res);

			/* ---- 用例 11（b2）：interrupted 会话重放（recover/
			 *    retry 路径）——不重复落 user，环跑完归位 active */
			occ_interrupt_flag = 0;
			opts.prompt = NULL;
			sse_set(SSE_NORMAL);
			rc = occ_loop_run(db, &p, sid, &opts, &res, err,
					  sizeof(err));
			OK(rc == OCC_LOOP_OK, "loop11-replay-rc");
			OK(res.interrupted == 0, "loop11-not-interrupted");
			OK(status_is(sid, "active"), "loop11-active");
			{
				char *uc = str_of(
					"SELECT COUNT(*) FROM occ_message WHERE"
					" session_id=?1 AND role='user' AND"
					" content_json LIKE '%第十问%'", sid);

				OK(uc && !strcmp(uc, "1"),
				   "loop11-user-not-duplicated");
				free(uc);
			}
			occ_loop_result_free(&res);
		}

		/* ---- 用例 12（b2）：中断起点在批次前 → 整批执行闭合上下文
		 *    → 安全点停（无合成行、状态 interrupted） ---- */
		{
			char wd2[256], fa[320], fb[320];
			char argsA[512], argsB[512];
			char u2[OCC_ID_LEN], a2id[OCC_ID_LEN];
			occ_tool_call tc2[2];

			snprintf(wd2, sizeof(wd2), "%s/b2batch", tmpdir);
			mkdir(wd2, 0755);
			snprintf(fa, sizeof(fa), "%s/a.txt", wd2);
			snprintf(fb, sizeof(fb), "%s/b.txt", wd2);
			OK(occ_msg_add_user(db, sid, "批执行中断测试", u2,
					    sizeof(u2), err, sizeof(err)) == 0,
			   "loop12-user");
			memset(tc2, 0, sizeof(tc2));
			snprintf(argsA, sizeof(argsA),
				 "{\"path\":\"%s\",\"content\":\"A\"}", fa);
			snprintf(argsB, sizeof(argsB),
				 "{\"path\":\"%s\",\"content\":\"B\"}", fb);
			tc2[0].id = "call_a";
			tc2[0].name = "write";
			tc2[0].arguments = argsA;
			tc2[1].id = "call_b";
			tc2[1].name = "write";
			tc2[1].arguments = argsB;
			OK(occ_msg_add_assistant_ex(db, sid, "", NULL, tc2, 2,
						    NULL, 0, "tool_calls", 1,
						    a2id, sizeof(a2id), err,
						    sizeof(err)) == 0,
			   "loop12-asst-pending");
			occ_interrupt_flag = 1;		/* 进环前已置位 */
			opts.prompt = NULL;		/* 重放（尾=assistant
							 * pending） */
			sse_set(SSE_NORMAL);
			rc = occ_loop_run(db, &p, sid, &opts, &res, err,
					  sizeof(err));
			OK(rc == OCC_LOOP_OK, "loop12-rc");
			OK(res.interrupted == 1, "loop12-interrupted");
			OK(!access(fa, F_OK) && !access(fb, F_OK),
			   "loop12-both-writes-executed");
			OK(status_is(sid, "interrupted"), "loop12-status");
			OK(count_rows("SELECT COUNT(*) FROM occ_toolcall WHERE"
				      " message_id=?1 AND rc=0", a2id) == 2,
			   "loop12-two-real-rows");
			OK(count_rows("SELECT COUNT(*) FROM occ_toolcall WHERE"
				      " message_id=?1 AND rc=1", a2id) == 0,
			   "loop12-no-synthesized-row");
			/* 尾=tool 且无 pending（不变量：可 retry/recover） */
			{
				occ_msg_row last;
				occ_toolcall_part *pend = NULL;
				size_t npend = 0;

				OK(occ_msg_last(db, sid, &last, err,
						sizeof(err)) == 1 &&
				   !strcmp(last.role, "tool"),
				   "loop12-tail-tool");
				occ_msg_row_free(&last);
				OK(occ_msg_pending_calls(db, sid, &pend,
							 &npend, NULL, 0, err,
							 sizeof(err)) == 0 &&
				   npend == 0, "loop12-no-pending");
				{
					size_t q;

					for (q = 0; q < npend; q++) {
						free(pend[q].id);
						free(pend[q].tool);
						free(pend[q].arguments);
					}
					free(pend);
				}
			}
			occ_loop_result_free(&res);
			occ_interrupt_flag = 0;
		}

		/* ---- 用例 13（b2）：OCC_EV_RESET——上一尝试部分输出作废
		 *    （GARBAGE 不得进落库/结果） ---- */
		{
			g_fake_reset = 1;
			opts.prompt = "第十三问：重试重置";
			sse_set(SSE_NORMAL);
			rc = occ_loop_run(db, &p, sid, &opts, &res, err,
					  sizeof(err));
			g_fake_reset = 0;
			OK(rc == OCC_LOOP_OK, "loop13-rc");
			OK(res.text != NULL && strstr(res.text, "你好") != NULL,
			   "loop13-final-text-ok");
			OK(res.text == NULL || strstr(res.text,
						      "GARBAGE") == NULL,
			   "loop13-garbage-cleared");
			/* 落库同样干净 */
			{
				char *cj = str_of(
					"SELECT content_json FROM occ_message"
					" WHERE session_id=?1 AND role='assistant'"
					" ORDER BY created DESC LIMIT 1", sid);

				OK(cj && strstr(cj, "GARBAGE") == NULL,
				   "loop13-db-clean");
				free(cj);
			}
			occ_loop_result_free(&res);
		}

		/* ---- 用例 14（b2）：注记折叠 + stage commit + 中断续传
		 *    注记（新 user 落库前的三件套） ---- */
		{
			char nid[OCC_ID_LEN];

			OK(occ_msg_add_note(db, sid, "[occ 注记] 测试折叠",
					    nid, sizeof(nid), err,
					    sizeof(err)) == 0, "loop14-note");
			OK(occ_revert_put(db, sid, "msg_fakeboundary", nid,
					  "[\"/tmp/x\"]", "[\"msg_fake\"]",
					  err, sizeof(err)) == 0,
			   "loop14-stage-put");
			opts.prompt = "第十四问";
			sse_set(SSE_NORMAL);
			rc = occ_loop_run(db, &p, sid, &opts, &res, err,
					  sizeof(err));
			OK(rc == OCC_LOOP_OK, "loop14-rc");
			/* 注记并入 user 文本（查落库原文——g_msgs_log 只留
			 * 前 24 字节，中文截断会误判） */
			{
				char *cj = str_of(
					"SELECT content_json FROM occ_message"
					" WHERE session_id=?1 AND role='user'"
					" ORDER BY created DESC, rowid DESC"
					" LIMIT 1", sid);

				OK(cj && strstr(cj, "测试折叠") != NULL,
				   "loop14-note-folded-into-user");
				free(cj);
			}
			OK(count_rows("SELECT COUNT(*) FROM occ_message WHERE"
				      " session_id=?1 AND role='system'",
				      sid) == 0, "loop14-note-row-deleted");
			{
				occ_revert_row st14;

				OK(occ_revert_get(db, sid, &st14, err,
						  sizeof(err)) == 0,
				   "loop14-stage-committed");
				occ_revert_row_free(&st14);
			}
			occ_loop_result_free(&res);

			/* 中断续传注记（OCD runner 同语义） */
			OK(occ_session_set_status(db, sid,
						  OCC_ST_INTERRUPTED, err,
						  sizeof(err)) == 0,
			   "loop14-set-interrupted");
			opts.prompt = "第十四问B";
			sse_set(SSE_NORMAL);
			rc = occ_loop_run(db, &p, sid, &opts, &res, err,
					  sizeof(err));
			OK(rc == OCC_LOOP_OK, "loop14b-rc");
			{
				char *cj = str_of(
					"SELECT content_json FROM occ_message"
					" WHERE session_id=?1 AND role='user'"
					" ORDER BY created DESC, rowid DESC"
					" LIMIT 1", sid);

				OK(cj && strstr(cj, "上一轮回复被中断") != NULL,
				   "loop14b-continuation-note");
				free(cj);
			}
			occ_loop_result_free(&res);
		}
		}

		/* ---- 用例 8（可选）：a1 vectors 真 fixture 回放一环 ---- */
	{
		const char *vd = getenv("OCC_VECTORS_DIR");

		if (vd && vd[0]) {
			char path[512];
			FILE *f;
			char *sse;
			long sz;

			snprintf(path, sizeof(path),
				 "%s/fixtures/openai/normal.sse", vd);
			f = fopen(path, "rb");
			if (f) {
				fseek(f, 0, SEEK_END);
				sz = ftell(f);
				fseek(f, 0, SEEK_SET);
				sse = malloc((size_t)sz + 1);
				if (sse && fread(sse, 1, (size_t)sz, f) ==
				    (size_t)sz) {
					occ_loop_opts o2;
					occ_loop_result r2;
					int rc;

					sse[sz] = '\0';
					memset(&o2, 0, sizeof(o2));
					o2.prompt = "真 fixture 回放";
					o2.llm_call = fake_llm_call;
					sse_set(sse);
					rc = occ_loop_run(db, &p, NULL, &o2,
							  &r2, err,
							  sizeof(err));
					/*
					 * a1 normal.sse 含 get_weather
					 * tool_call：b1 工具环全链——未知
					 * 工具错误回灌 + 续环直到步数上限
					 * （真 fixture 驱动的 step-cap 回归）
					 */
					OK(rc == OCC_LOOP_OK,
					   "loop8-real-fixture-turn");
					OK(r2.steps_capped == 1,
					   "loop8-step-capped");
					OK(msgs_of(r2.session_id) == 25,
					   "loop8-msgs-25");
					OK(r2.unexpected_toolcalls == 12,
					   "loop8-12-calls-executed");
					occ_loop_result_free(&r2);
				} else {
					OK(0, "loop8-read-fixture");
				}
				free(sse);
				fclose(f);
			} else {
				printf("skip loop8 (no fixture %s)\n", path);
			}
		} else {
			printf("skip loop8 (OCC_VECTORS_DIR unset)\n");
		}
	}

	occ_db_close(db);
	{
		char cmd[192];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
		if (system(cmd)) {
			/* 清理失败不影响判定 */
		}
	}
	printf("test_loop: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
