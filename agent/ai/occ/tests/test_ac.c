/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_ac.c - T9d §9 ac 绑定单测（transcript / 轮询上报 / 全链 / 换窗）
 *
 * 本地 mock autocondense HTTP 服务（OCC_AC_URL 指过去）+ 注入 fill
 * （occ_ac_set_fill，不走真 LLM）——零真网、零真调用：
 *   1) transcript 行流：user/assistant/tool 三行 JSONL（ac 兼容）；
 *   2) 全链驱动：session/start(水位+路径) → /check → /judge → /begin
 *      → /commit 请求序列与请求体断言；
 *   3) 换窗四证：摘要注记落库 / 旧历史 reverted=1 / token 账本重置为
 *      新基线 / occ_window.base_kind='digest'；
 *   4) 换窗正确性（上下文级）：下一轮请求里旧事实只以摘要形式存在
 *      ——「换窗后引用旧事实仍答对」的地基；
 *   5) 手动 /compact（occ_ac_compact_now）跳过 check/judge；
 *   6) ac 不可达 → @ac:off 诚实降级；OCC_AC=off → 零 HTTP；
 *   7) 绑定总闸 occ_bind_active 四象限。
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <sqlite3.h>

#include "occ_core/occ_ac.h"
#include "occ_core/occ_loop.h"
#include "occ_core/occ_session.h"
#include "occ_core/occ_sysprompt.h"
#include "occ_core/occ_tokens.h"

static int n_fail;
static int n_ok;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

/* ---- mock ac HTTP 服务 ---- */

static int g_srv = -1;
static volatile int g_run;
static pthread_t g_th;
static int g_port;
static char g_log[8192];		/* 请求序列（含关键体片段） */
static char g_judge_body[4096];
static char g_commit_body[8192];
static char g_start_body[2048];

static const char *check_json(void)
{
	return "{\"should\":\"JUDGE\",\"trigger\":\"turns\","
	       "\"urgency\":\"normal\",\"reason\":\"轮次到阈值\","
	       "\"signals\":{\"turns\":26},"
	       "\"action_hint\":\"condense_judge\"}";
}

static void respond(int c, int status, const char *body)
{
	char head[512];
	int n;

	n = snprintf(head, sizeof(head),
		     "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\n"
		     "Content-Length: %zu\r\nConnection: close\r\n\r\n",
		     status, status == 200 ? "OK" : "Error", strlen(body));
	if (send(c, head, n, 0) < 0) {
		/* 尽力而为 */
	}
	if (send(c, body, strlen(body), 0) < 0) {
		/* 尽力而为 */
	}
}

static void log_req(const char *tag, const char *body)
{
	size_t used = strlen(g_log);

	if (used + strlen(tag) + 2 < sizeof(g_log))
		snprintf(g_log + used, sizeof(g_log) - used, "%s;", tag);
	(void)body;
}

static void *srv_main(void *arg)
{
	(void)arg;
	while (g_run) {
		struct sockaddr_in ca;
		socklen_t cal = sizeof(ca);
		char buf[32768];
		size_t got = 0;
		int c, clen = 0;
		char *hdr_end;
		char *p;
		char *body;

		c = accept(g_srv, (struct sockaddr *)&ca, &cal);
		if (c < 0) {
			if (!g_run)
				break;
			continue;
		}
		memset(buf, 0, sizeof(buf));
		while (got + 1 < sizeof(buf)) {
			ssize_t n = recv(c, buf + got, sizeof(buf) - 1 - got,
					 0);

			if (n <= 0)
				break;
			got += (size_t)n;
			buf[got] = '\0';
			if (strstr(buf, "\r\n\r\n"))
				break;
		}
		hdr_end = strstr(buf, "\r\n\r\n");
		p = strstr(buf, "Content-Length:");
		if (p && (!hdr_end || p < hdr_end))
			clen = atoi(p + 15);
		if (hdr_end && clen > 0) {
			size_t body_at = (size_t)(hdr_end - buf) + 4;

			while (got - body_at < (size_t)clen &&
			       got + 1 < sizeof(buf)) {
				ssize_t n = recv(c, buf + got,
						 sizeof(buf) - 1 - got, 0);

				if (n <= 0)
					break;
				got += (size_t)n;
				buf[got] = '\0';
			}
		}
		body = hdr_end ? hdr_end + 4 : (char *)"";

		if (strncmp(buf, "POST /session/start", 19) == 0) {
			log_req("session/start", body);
			snprintf(g_start_body, sizeof(g_start_body), "%s",
				 body);
			respond(c, 200, "{\"session_id\":\"ses_x\"}");
		} else if (strncmp(buf, "GET /check", 10) == 0) {
			log_req("check", NULL);
			respond(c, 200, check_json());
		} else if (strncmp(buf, "POST /judge", 11) == 0) {
			log_req("judge", body);
			snprintf(g_judge_body, sizeof(g_judge_body), "%s",
				 body);
			respond(c, 200,
				"{\"decision\":\"COMPRESS_NOW\","
				"\"urgency\":\"normal\","
				"\"reason\":\"判定通过\"}");
		} else if (strncmp(buf, "POST /begin", 11) == 0) {
			log_req("begin", body);
			respond(c, 200,
				"{\"mode\":\"full\","
				"\"template\":\"## 目标\\n\\n## 已完成\\n\\n"
				"## 未完成\\n\\n## 文件变更清单\\n\\n"
				"## 恢复指针\\n\","
				"\"guidance\":\"逐节填写\","
				"\"required_sections\":[\"## 目标\","
				"\"## 已完成\",\"## 未完成\","
				"\"## 文件变更清单\",\"## 恢复指针\"]}");
		} else if (strncmp(buf, "POST /commit", 12) == 0) {
			log_req("commit", body);
			snprintf(g_commit_body, sizeof(g_commit_body), "%s",
				 body);
			respond(c, 200,
				"{\"ok\":true,\"segments_written\":0,"
				"\"sme\":{\"stored\":false}}");
		} else {
			respond(c, 404, "{\"errors\":[{\"msg\":\"nope\"}]}");
		}
		close(c);
	}
	return NULL;
}

static int srv_start(void)
{
	struct sockaddr_in sa;
	socklen_t sl = sizeof(sa);
	int one = 1;

	g_srv = socket(AF_INET, SOCK_STREAM, 0);
	if (g_srv < 0)
		return -1;
	setsockopt(g_srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = 0;
	if (bind(g_srv, (struct sockaddr *)&sa, sizeof(sa)) != 0)
		return -1;
	if (listen(g_srv, 16) != 0)
		return -1;
	if (getsockname(g_srv, (struct sockaddr *)&sa, &sl) != 0)
		return -1;
	g_port = ntohs(sa.sin_port);
	g_run = 1;
	if (pthread_create(&g_th, NULL, srv_main, NULL) != 0)
		return -1;
	return 0;
}

static void srv_stop(void)
{
	g_run = 0;
	if (g_srv >= 0) {
		shutdown(g_srv, SHUT_RDWR);
		close(g_srv);
		g_srv = -1;
	}
	pthread_join(g_th, NULL);
}

/* ---- 注入 fill（judge 出判定 JSON；其余出摘要） ---- */

static const char DIGEST[] =
	"## 目标\n为 occ 实现 ac 绑定与换窗。\n"
	"## 已完成\n- 换窗四证落地（测试通过）\n"
	"- 暗号 old-secret-token（换窗后仍可引用）\n"
	"## 未完成\n- parquet 沉淀待接\n"
	"## 文件变更清单\n- occ_core/occ_ac.c（新增）\n"
	"## 恢复指针\n- transcript: ~/.occ/sessions/<id>.jsonl\n"
	"（本段为测试用摘要，字数必须超过两百以通过 ac 的长度校验，"
	"因此继续填充占位内容：一二三四五六七八九十、"
	"一二三四五六七八九十、一二三四五六七八九十、"
	"一二三四五六七八九十、一二三四五六七八九十。）";

static const char JUDGE_JSON[] =
	"{\"task_finished\":true,\"impact\":\"low\","
	"\"impact_reason\":\"回合已收口\",\"safe_to_compress\":true,"
	"\"reason\":\"durable 落库无未保存状态\",\"confidence\":\"high\"}";

static int fake_fill(void *ud, const char *prompt, char **out)
{
	const char *src;

	(void)ud;
	src = (prompt && strstr(prompt, "压缩判定表")) ? JUDGE_JSON : DIGEST;
	*out = strdup(src);
	return *out ? 0 : -1;
}

/* ---- 伪 LLM（记录请求消息；吐固定 SSE） ---- */

static char g_msgs[32768];

static const char SSE_TEXT[] =
	"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\","
	"\"content\":\"第二答\"}}]}\n\n"
	"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"
	"data: [DONE]\n\n";

static int fake_llm_call(const occ_provider *p, const occ_llm_req *req,
			 occ_event_cb cb, void *ud, char **err_out)
{
	occ_sse *sse;
	size_t used = 0;
	size_t i;

	(void)p;
	if (err_out)
		*err_out = NULL;
	g_msgs[0] = '\0';
	for (i = 0; i < req->nmsgs && used + 1 < sizeof(g_msgs); i++) {
		int n = snprintf(g_msgs + used, sizeof(g_msgs) - used,
				 "[%s]%s\n",
				 req->msgs[i].role == OCC_ROLE_USER ? "U" :
				 req->msgs[i].role == OCC_ROLE_ASSISTANT ?
				 "A" : "T",
				 req->msgs[i].text ? req->msgs[i].text : "");

		if (n < 0 || (size_t)n >= sizeof(g_msgs) - used)
			break;
		used += (size_t)n;
	}
	sse = occ_sse_new(req->proto, cb, ud);
	if (!sse)
		return -1;
	occ_sse_feed(sse, SSE_TEXT, strlen(SSE_TEXT));
	occ_sse_finish(sse);
	occ_sse_free(sse);
	return 0;
}

/* ---- 断言辅助 ---- */

static char tmpdir[256];
static char dbpath[320];

static void read_file(const char *path, char *out, size_t cap)
{
	FILE *f = fopen(path, "rb");
	size_t n;

	out[0] = '\0';
	if (!f)
		return;
	n = fread(out, 1, cap - 1, f);
	out[n] = '\0';
	fclose(f);
}

int main(void)
{
	char url[64];
	char err[512];
	occ_db *db;
	occ_session_row sess;
	occ_ac_turn t;
	occ_usage u;
	char mid[40];
	char tpath[320];
	char fbuf[16384];
	int compacted = 0;
	int rc;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/occ_ac_t_%d", (int)getpid());
	{
		char cmd[320];

		snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
		if (system(cmd) != 0) {
			/* 尽力清理 */
		}
	}
	if (mkdir(tmpdir, 0755) != 0) {
		printf("mkdir failed\n");
		return 2;
	}
	snprintf(dbpath, sizeof(dbpath), "%s/sessions.db", tmpdir);
	setenv("OCC_SESSIONS_DIR", tmpdir, 1);
	setenv("OCC_SME", "off", 1);
	setenv("OCC_BIND", "on", 1);
	unsetenv("OCC_STATE_NOTICE");
	occ_ac_set_fill(fake_fill, NULL);
	occ_ac_test_set_state(0);

	/* ---- 1) 绑定总闸四象限 ---- */
	{
		occ_loop_opts o;

		memset(&o, 0, sizeof(o));
		unsetenv("OCC_BIND");
		OK(occ_bind_active(&o) == 1, "bind-auto-real-path-on");
		o.llm_call = fake_llm_call;
		OK(occ_bind_active(&o) == 0, "bind-auto-fake-path-off");
		setenv("OCC_BIND", "on", 1);
		OK(occ_bind_active(&o) == 1, "bind-force-on");
		setenv("OCC_BIND", "off", 1);
		memset(&o, 0, sizeof(o));
		OK(occ_bind_active(&o) == 0, "bind-force-off");
		OK(occ_bind_active(NULL) == 0, "bind-force-off-null-opts");
		setenv("OCC_BIND", "on", 1);
		OK(occ_bind_active(NULL) == 1, "bind-on-null-opts");
	}

	/* ---- 2) transcript 行流 ---- */
	OK(occ_ac_transcript("ses_t1", "user", "你好\"引号\n换行", NULL,
			     NULL) == 0, "transcript-user");
	{
		occ_usage au;

		memset(&au, 0, sizeof(au));
		au.present = 1;
		au.input = 12;
		au.output = 34;
		OK(occ_ac_transcript("ses_t1", "assistant", "答复", NULL,
				     &au) == 0, "transcript-assistant");
	}
	OK(occ_ac_transcript("ses_t1", "tool", "文件内容", "read", NULL) == 0,
	   "transcript-tool");
	snprintf(tpath, sizeof(tpath), "%s/ses_t1.jsonl", tmpdir);
	read_file(tpath, fbuf, sizeof(fbuf));
	OK(strstr(fbuf, "\"role\":\"user\"") != NULL, "tl-user-role");
	OK(strstr(fbuf, "你好\\\"引号\\n换行") != NULL, "tl-user-escaped");
	OK(strstr(fbuf, "\"role\":\"assistant\"") != NULL, "tl-asst-role");
	OK(strstr(fbuf, "\"usage\":{\"in\":12,\"out\":34") != NULL,
	   "tl-usage");
	OK(strstr(fbuf, "\"role\":\"tool\"") != NULL &&
	   strstr(fbuf, "\"tool\":\"read\"") != NULL, "tl-tool");
	{
		char *nl = strchr(fbuf, '\n');

		OK(nl && strchr(nl + 1, '\n') != NULL, "tl-three-lines");
	}

	/* ---- 3) 建会话与历史（被换窗隐藏的旧事实） ---- */
	db = occ_db_open(dbpath, err, sizeof(err));
	if (!db) {
		printf("db open: %s\n", err);
		return 2;
	}
	if (occ_session_create(db, "ac-model", &sess, err, sizeof(err))) {
		printf("session create: %s\n", err);
		return 2;
	}
	if (occ_msg_add_user(db, sess.id, "第一问：暗号是什么", mid,
			     sizeof(mid), err, sizeof(err))) {
		printf("add user: %s\n", err);
		return 2;
	}
	memset(&u, 0, sizeof(u));
	u.present = 1;
	u.input = 40;
	u.output = 12;
	if (occ_msg_add_assistant(db, sess.id,
				  "第一答：暗号是 old-secret-token", NULL,
				  NULL, 0, &u, 0, "stop", mid, sizeof(mid),
				  err, sizeof(err))) {
		printf("add assistant: %s\n", err);
		return 2;
	}

	/* ---- 4) 全链驱动（check→judge→begin→commit→换窗） ---- */
	if (srv_start() != 0) {
		printf("mock start failed\n");
		return 2;
	}
	snprintf(url, sizeof(url), "http://127.0.0.1:%d", g_port);
	setenv("OCC_AC_URL", url, 1);
	g_log[0] = '\0';

	memset(&t, 0, sizeof(t));
	t.db = db;
	t.session_id = sess.id;
	t.cwd = tmpdir;
	t.tokens = 12345;
	t.context = "第一答：暗号是 old-secret-token";
	rc = occ_ac_turn_end(&t, &compacted, err, sizeof(err));
	OK(rc == 0, "turn-end-rc0");
	OK(compacted == 1, "turn-end-compacted");
	OK(err[0] == '\0', "turn-end-no-error");
	OK(strstr(g_log, "session/start;") != NULL &&
	   strstr(g_log, "check;") != NULL &&
	   strstr(g_log, "judge;") != NULL &&
	   strstr(g_log, "begin;") != NULL &&
	   strstr(g_log, "commit;") != NULL, "chain-request-order");
	{
		const char *seq = strstr(g_log, "session/start;");

		OK(seq && strstr(seq, "check;") < strstr(seq, "judge;") &&
		   strstr(seq, "judge;") < strstr(seq, "begin;") &&
		   strstr(seq, "begin;") < strstr(seq, "commit;"),
		   "chain-order-strict");
	}
	OK(strstr(g_start_body, "\"context_tokens\":12345") != NULL,
	   "report-carries-token-watermark");
	OK(strstr(g_start_body, ".jsonl") != NULL,
	   "report-carries-transcript-path");
	OK(strstr(g_judge_body, "\"task_finished\"") != NULL &&
	   strstr(g_judge_body, "\"session_id\"") != NULL,
	   "judge-body-verdict");
	OK(strstr(g_commit_body, "\"digest_md\"") != NULL &&
	   strstr(g_commit_body, "## 恢复指针") != NULL &&
	   strstr(g_commit_body, "\"trigger\":\"water_level\"") != NULL,
	   "commit-body-digest");
	OK(strcmp(occ_ac_status(), OCC_AC_ST_OK) == 0, "status-ok");

	/* ---- 5) 换窗四证 ---- */
	{
		occ_msg_row *rows = NULL;
		size_t n = 0, i;
		int n_rev = 0, n_digest = 0;
		char wtxt[4096];

		OK(occ_msg_list(db, sess.id, &rows, &n, err, sizeof(err)) == 0,
		   "msg-list-after-digest");
		for (i = 0; i < n; i++) {
			if (rows[i].reverted)
				n_rev++;
			if (!strcmp(rows[i].role, "system") &&
			    rows[i].text &&
			    !strncmp(rows[i].text, OCC_DIGEST_PREFIX,
				     strlen(OCC_DIGEST_PREFIX)))
				n_digest++;
		}
		occ_msg_rows_free(rows, n);
		OK(n_digest == 1, "digest-note-rows");
		OK(n_rev == 2, "old-history-reverted");
		{
			occ_session_row after;
			char expect_text[sizeof(OCC_DIGEST_PREFIX) +
					 sizeof(DIGEST)];
			long long want;

			OK(occ_session_get(db, sess.id, &after, err,
					   sizeof(err)) == 1, "session-reread");
			OK(after.tokens_est == 1, "tokens-est-flag");
			strcpy(expect_text, OCC_DIGEST_PREFIX);
			strcat(expect_text, DIGEST);
			want = occ_tokens_estimate_len(OCC_SYSTEM_PROMPT) +
			      occ_tokens_estimate_len(expect_text);
			OK(after.tokens_total == want,
			   "tokens-reset-to-baseline");
			(void)wtxt;
		}
	}
	{
		/* occ_window → digest */
		sqlite3 *h = NULL;
		sqlite3_stmt *st = NULL;
		int kind_ok = 0;

		if (sqlite3_open(dbpath, &h) == SQLITE_OK &&
		    sqlite3_prepare_v2(h,
			"SELECT base_kind FROM occ_window WHERE session_id=?",
			-1, &st, NULL) == SQLITE_OK) {
			sqlite3_bind_text(st, 1, sess.id, -1,
					  SQLITE_TRANSIENT);
			if (sqlite3_step(st) == SQLITE_ROW) {
				const char *k =
					(const char *)sqlite3_column_text(st, 0);

				kind_ok = k && !strcmp(k, "digest");
			}
			sqlite3_finalize(st);
		}
		if (h)
			sqlite3_close(h);
		OK(kind_ok, "window-base-kind-digest");
	}

	/* ---- 6) 换窗正确性：下一轮上下文只剩摘要（旧事实以摘要存在） ---- */
	setenv("OCC_AC", "off", 1);		/* 本步只看上下文 */
	{
		occ_db *db2;
		occ_provider p;
		occ_loop_opts o;
		occ_loop_result res;

		db2 = occ_db_open(dbpath, err, sizeof(err));
		OK(db2 != NULL, "reopen-db");
		memset(&p, 0, sizeof(p));
		p.proto = OCC_PROTO_OPENAI_COMPAT;
		snprintf(p.model, sizeof(p.model), "ac-model");
		snprintf(p.base_url, sizeof(p.base_url), "%s",
			 "http://127.0.0.1:1");
		memset(&o, 0, sizeof(o));
		o.prompt = "第二问：暗号是什么（换窗后）";
		o.llm_call = fake_llm_call;
		memset(&res, 0, sizeof(res));
		rc = occ_loop_run(db2, &p, sess.id, &o, &res, err,
				  sizeof(err));
		OK(rc == OCC_LOOP_OK, "post-digest-turn-ok");
		OK(strstr(g_msgs, "old-secret-token") != NULL,
		   "digest-carries-old-fact");
		OK(strstr(g_msgs, "第一答：暗号是 old-secret-token") == NULL,
		   "old-turn-not-in-context");
		OK(strstr(g_msgs, OCC_DIGEST_PREFIX) != NULL ||
		   strstr(g_msgs, "会话摘要") != NULL,
		   "digest-in-context");
		occ_loop_result_free(&res);
		occ_db_close(db2);
	}
	unsetenv("OCC_AC");

	/* ---- 7) 手动 /compact：跳过 check/judge ---- */
	g_log[0] = '\0';
	memset(&t, 0, sizeof(t));
	t.db = db;
	t.session_id = sess.id;
	t.cwd = tmpdir;
	t.tokens = 999;
	rc = occ_ac_compact_now(&t, err, sizeof(err));
	OK(rc == 0, "compact-now-rc0");
	OK(strstr(g_log, "begin;") != NULL &&
	   strstr(g_log, "commit;") != NULL, "compact-now-chain");
	OK(strstr(g_log, "check;") == NULL, "compact-now-skips-check");
	OK(strstr(g_log, "judge;") == NULL, "compact-now-skips-judge");

	/* ---- 8) ac 不可达 → 诚实降级 ---- */
	srv_stop();
	g_log[0] = '\0';
	memset(&t, 0, sizeof(t));
	t.db = db;
	t.session_id = sess.id;
	t.cwd = tmpdir;
	t.tokens = 1;
	rc = occ_ac_turn_end(&t, &compacted, err, sizeof(err));
	OK(rc == 0, "turn-end-down-rc0");
	OK(compacted == 0, "turn-end-down-no-compact");
	OK(strcmp(occ_ac_status(), OCC_AC_ST_OFF) == 0, "status-off-when-down");
	rc = occ_ac_compact_now(&t, err, sizeof(err));
	OK(rc == -1, "compact-now-down-fails");
	OK(strstr(err, "不可达") != NULL, "compact-now-down-msg");

	/* ---- 9) OCC_AC=off → 零 HTTP ---- */
	setenv("OCC_AC", "off", 1);
	g_log[0] = '\0';
	memset(&t, 0, sizeof(t));
	t.db = db;
	t.session_id = sess.id;
	t.cwd = tmpdir;
	compacted = 7;
	rc = occ_ac_turn_end(&t, &compacted, err, sizeof(err));
	OK(rc == 0 && compacted == 0, "turn-end-disabled");
	OK(g_log[0] == '\0', "disabled-zero-http");
	OK(strcmp(occ_ac_status(), OCC_AC_ST_OFF) == 0, "status-off-when-disabled");
	unsetenv("OCC_AC");
	unsetenv("OCC_AC_URL");

	occ_db_close(db);
	{
		char cmd[320];

		snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
		if (system(cmd) != 0) {
			/* 尽力清理 */
		}
	}
	printf("test_ac: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
