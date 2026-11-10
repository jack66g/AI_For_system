/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_sme.c - T9d §8 SME 绑定单测（注入 / 写回配额 / 诚实降级）
 *
 * 全程本地 mock SME HTTP 服务（127.0.0.1 随机端口，SME_URL 指过去），
 * 零真网、零真 LLM：
 *   1) 检索注入：occ_sme_lookup 返回 `〈记忆〉` 块（含命中段落、定界符）；
 *      经 occ_loop_run（OCC_BIND=on + 注入伪传输）后请求 system 含该块
 *      ——「AI 开口就记得」的落地路径端到端断言；
 *   2) 诚实降级：服务停掉后再查 → NULL + 状态 `@sme:off`（不阻塞对话，
 *      环 rc 仍 OCC_LOOP_OK）；
 *   3) 写回配额：20 条写入成功、第 21 条被会话级配额挡下（读不限）；
 *   4) 开关：OCC_SME=off → 禁用且状态诚实显示 off。
 *
 * mock 仅本单测（明标）；线程模型与 test_memory_api 同款 accept 循环。
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
#include "occ_core/occ_sme.h"

static int n_fail;
static int n_ok;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

/* ---- mock SME HTTP 服务 ---- */

static int g_srv = -1;
static volatile int g_run;
static pthread_t g_th;
static int g_port;
static int g_n_search;
static int g_n_add;
static char g_last_add[4096];

static const char HIT_JSON[] =
	"{\"query\":\"q\",\"count\":2,\"results\":["
	"{\"id\":\"mem_a\",\"text\":\"暗号是 blue-whale-42\","
	"\"tags\":[\"occ\",\"user\"],\"importance\":0.5},"
	"{\"id\":\"mem_b\",\"text\":\"用户偏好中文简洁回答\","
	"\"tags\":[\"occ\"],\"importance\":0.5}]}";

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

static void *srv_main(void *arg)
{
	(void)arg;
	while (g_run) {
		struct sockaddr_in ca;
		socklen_t cal = sizeof(ca);
		char buf[16384];
		size_t got = 0;
		int c, clen = 0;
		char *hdr_end;
		char *p;

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
		if (p && p < hdr_end)
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
		if (strncmp(buf, "POST /memories/search", 21) == 0) {
			g_n_search++;
			respond(c, 200, HIT_JSON);
		} else if (strncmp(buf, "POST /memories", 14) == 0) {
			char *b = hdr_end ? hdr_end + 4 : NULL;

			g_n_add++;
			snprintf(g_last_add, sizeof(g_last_add), "%s",
				 b ? b : "");
			respond(c, 200, "{\"id\":\"mem_new\"}");
		} else if (strncmp(buf, "GET /health", 11) == 0) {
			respond(c, 200, "{\"status\":\"ok\"}");
		} else {
			respond(c, 404, "{\"detail\":\"not found\"}");
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

/* ---- 伪 LLM（记录请求 system；吐固定 SSE 收口） ---- */

static char g_sys[16384];
static int g_sys_seen;

static const char SSE_TEXT[] =
	"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\","
	"\"content\":\"收到\"}}]}\n\n"
	"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"
	"data: [DONE]\n\n";

static int fake_llm_call(const occ_provider *p, const occ_llm_req *req,
			 occ_event_cb cb, void *ud, char **err_out)
{
	occ_sse *sse;
	occ_event ev;

	(void)p;
	if (err_out)
		*err_out = NULL;
	if (req->system) {
		snprintf(g_sys, sizeof(g_sys), "%s", req->system);
		g_sys_seen = 1;
	}
	sse = occ_sse_new(req->proto, cb, ud);
	if (!sse)
		return -1;
	occ_sse_feed(sse, SSE_TEXT, strlen(SSE_TEXT));
	occ_sse_finish(sse);
	occ_sse_free(sse);
	memset(&ev, 0, sizeof(ev));
	(void)ev;
	return 0;
}

/* ---- 环驱动 ---- */

static char tmpdir[256];

static int run_turn(const char *prompt, occ_loop_result *res)
{
	occ_db *db;
	occ_provider p;
	occ_loop_opts opts;
	char err[512];
	char dbpath[320];
	int rc;

	snprintf(dbpath, sizeof(dbpath), "%s/sessions.db", tmpdir);
	db = occ_db_open(dbpath, err, sizeof(err));
	if (!db) {
		printf("db open: %s\n", err);
		return -99;
	}
	memset(&p, 0, sizeof(p));
	p.proto = OCC_PROTO_OPENAI_COMPAT;
	snprintf(p.model, sizeof(p.model), "sme-model");
	snprintf(p.base_url, sizeof(p.base_url), "%s", "http://127.0.0.1:1");
	memset(&opts, 0, sizeof(opts));
	opts.prompt = prompt;
	opts.llm_call = fake_llm_call;
	rc = occ_loop_run(db, &p, NULL, &opts, res, err, sizeof(err));
	if (rc != OCC_LOOP_OK)
		printf("  loop err: %s\n", err);
	occ_db_close(db);
	return rc;
}

int main(void)
{
	char url[64];
	char *blk;
	int i, rc;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/occ_sme_t_%d", (int)getpid());
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
	setenv("OCC_SESSIONS_DIR", tmpdir, 1);
	setenv("OCC_AC", "off", 1);		/* 本测只验 SME */
	setenv("OCC_BIND", "on", 1);
	unsetenv("OCC_SME");
	unsetenv("OCC_STATE_NOTICE");
	occ_sme_test_set_state(0);

	/* ---- 1) 检索注入（mock 在线） ---- */
	if (srv_start() != 0) {
		printf("mock server start failed\n");
		return 2;
	}
	snprintf(url, sizeof(url), "http://127.0.0.1:%d", g_port);
	setenv("SME_URL", url, 1);

	OK(occ_sme_enabled() == 1, "sme-enabled-default");
	blk = occ_sme_lookup("暗号 blue-whale-42 是什么");
	OK(blk != NULL, "lookup-hit-not-null");
	if (blk) {
		OK(strstr(blk, OCC_SME_BLOCK_HEAD) != NULL, "block-head");
		OK(strstr(blk, OCC_SME_BLOCK_TAIL) != NULL, "block-tail");
		OK(strstr(blk, "blue-whale-42") != NULL, "block-hit1");
		OK(strstr(blk, "中文简洁") != NULL, "block-hit2");
		free(blk);
	}
	OK(strcmp(occ_sme_status(), "@sme:on") == 0, "status-on");
	OK(g_n_search == 1, "search-request-count");

	/* ---- 2) 经 occ_loop_run 的注入端到端（system 含〈记忆〉） ---- */
	g_sys_seen = 0;
	g_sys[0] = '\0';
	{
		occ_loop_result res;

		memset(&res, 0, sizeof(res));
		rc = run_turn("记住：暗号是 blue-whale-42", &res);
		OK(rc == OCC_LOOP_OK, "loop-turn-ok");
		OK(g_sys_seen == 1, "loop-system-captured");
		OK(strstr(g_sys, OCC_SME_BLOCK_HEAD) != NULL,
		   "loop-system-has-memory-block");
		OK(strstr(g_sys, OCC_SME_BLOCK_TAIL) != NULL,
		   "loop-system-has-block-tail");
		OK(strstr(g_sys, "编码助手 occ") != NULL,
		   "loop-system-keeps-base-prompt");
		occ_loop_result_free(&res);
	}
	/* 提示词含「记住」→ §8.2 里程碑写回经环路自动发生 */
	OK(g_n_add == 1, "loop-milestone-writeback");
	OK(strstr(g_last_add, "blue-whale-42") != NULL,
	   "milestone-carries-fact");

	/* ---- 3) 写回配额 20（第 21 条被挡） ---- */
	{
		int base = g_n_add;

		for (i = 0; i < 25; i++) {
			char txt[64];

			snprintf(txt, sizeof(txt), "里程碑 %d：结论已固化", i);
			rc = occ_sme_remember("ses_test_quota", "测试会话",
					      txt);
			if (i < 20)
				OK(rc == 1, "remember-within-quota");
			else
				OK(rc == 0, "remember-quota-blocked");
		}
		OK(g_n_add - base == 20, "add-request-count-20");
	}
	OK(occ_sme_quota_left("ses_test_quota") == 0, "quota-left-zero");
	OK(strstr(g_last_add, "occ_session") != NULL, "write-tags-occ-session");
	OK(strstr(g_last_add, "\"importance\":0.5") != NULL,
	   "write-importance-0.5");
	OK(strstr(g_last_add, "测试会话") != NULL, "write-carries-title");

	/* ---- 4) 服务不可达 → 诚实降级 ---- */
	srv_stop();
	blk = occ_sme_lookup("还能查到吗");
	OK(blk == NULL, "lookup-down-null");
	OK(strcmp(occ_sme_status(), "@sme:off") == 0, "status-off-after-down");
	{
		occ_loop_result res;

		memset(&res, 0, sizeof(res));
		rc = run_turn("降级也要能聊", &res);
		OK(rc == OCC_LOOP_OK, "loop-ok-when-sme-down");
		occ_loop_result_free(&res);
	}

	/* ---- 5) OCC_SME=off 开关 ---- */
	setenv("OCC_SME", "off", 1);
	OK(occ_sme_enabled() == 0, "sme-disabled-by-env");
	OK(strcmp(occ_sme_status(), "@sme:off") == 0, "status-off-when-disabled");
	OK(occ_sme_lookup("anything") == NULL, "lookup-disabled-null");
	OK(occ_sme_remember("ses_x", NULL, "text") == 0, "remember-disabled-skip");
	unsetenv("OCC_SME");

	{
		char cmd[320];

		snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
		if (system(cmd) != 0) {
			/* 尽力清理 */
		}
	}
	printf("test_sme: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
