/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_sink.c - occ_loop 输出 sink 双路对拍单测（T9c2）
 *
 * 铁门固化：同一 fixture 下
 *   A 路 = sink.fn==NULL + stream_out=tmpfile（headless 缺省 file sink）
 *   B 路 = sink.fn 回调（TUI 路）
 * 断言：
 *   1) 正常流：两路 TEXT 输出逐字节相等；
 *   2) RESET 流：A 路 stderr 收到 "occ: 重试…"（缺省 sink 的 NOTICE/
 *      RESET 字节合同）；B 路 sink 收到 RESET 事件且 stderr 零字节
 *      （sink 接管合同——防 alt-screen 污染）；B 路 sink 按 RESET 语义
 *      清空 live 文本后不含 GARBAGE（A 路已流出字节不可收回=如实差异，
 *      由 test_loop 收集器断言覆盖）。
 *
 * mock 仅本单测（与 test_loop 同款伪传输；生产 occ -p 走真 occ_llm_call）。
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sqlite3.h>

#include "occ_core/occ_loop.h"

static int n_fail;
static int n_ok;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

/* ---- 内联构造基 SSE（openai；与 test_loop 同款） ---- */

static const char SSE_TEXT[] =
	"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\","
	"\"content\":\"你好\"}}]}\n\n"
	"data: {\"choices\":[{\"delta\":{\"content\":\"，世界\"}}]}\n\n"
	"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"
	"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":55,"
	"\"completion_tokens\":6}}\n\n"
	"data: [DONE]\n\n";

static int g_fake_reset;			/* 1=先吐 GARBAGE+RESET 再回放 */

static int fake_llm_call(const occ_provider *p, const occ_llm_req *req,
			 occ_event_cb cb, void *ud, char **err_out)
{
	occ_sse *sse;
	occ_event ev;

	(void)p;
	if (err_out)
		*err_out = NULL;
	if (g_fake_reset) {
		/* 上一尝试的部分输出 → RESET（消费方清空收集器/live 文本） */
		memset(&ev, 0, sizeof(ev));
		ev.type = OCC_EV_TEXT_DELTA;
		ev.text = "GARBAGE-";
		cb(&ev, ud);
		memset(&ev, 0, sizeof(ev));
		ev.type = OCC_EV_RESET;
		ev.err = "重试：第 1/2 次尝试将在 1ms 后重发（sink 单测）";
		cb(&ev, ud);
	}
	sse = occ_sse_new(req->proto, cb, ud);
	if (!sse)
		return -1;
	occ_sse_feed(sse, SSE_TEXT, strlen(SSE_TEXT));
	occ_sse_finish(sse);
	occ_sse_free(sse);
	return 0;
}

/* ---- sink B 路捕获（模拟 TUI：RESET 清 live 文本） ---- */

#define CAP_MAX (64 * 1024)
static char g_text[CAP_MAX];		/* TEXT 拼接（RESET 清空） */
static size_t g_text_n;
static char g_notices[4096];		/* NOTICE/RESET 拼接（带 kind 标记） */
static size_t g_notices_n;
static int g_n_tool_start, g_n_tool_end;

static void sink_cb(void *ud, const occ_sink_ev *ev)
{
	(void)ud;
	switch (ev->kind) {
	case OCC_SINK_TEXT:
		if (ev->text && g_text_n + ev->len < sizeof(g_text)) {
			memcpy(g_text + g_text_n, ev->text, ev->len);
			g_text_n += ev->len;
		}
		break;
	case OCC_SINK_NOTICE:
		g_notices_n += (size_t)snprintf(g_notices + g_notices_n,
			sizeof(g_notices) - g_notices_n, "[N]%s\n",
			ev->text ? ev->text : "");
		break;
	case OCC_SINK_RESET:
		/* TUI 语义：清空已流出的 live 文本 */
		g_text_n = 0;
		g_text[0] = '\0';
		g_notices_n += (size_t)snprintf(g_notices + g_notices_n,
			sizeof(g_notices) - g_notices_n, "[R]%s\n",
			ev->text ? ev->text : "");
		break;
	case OCC_SINK_TOOL_START:
		g_n_tool_start++;
		break;
	case OCC_SINK_TOOL_END:
		g_n_tool_end++;
		break;
	default:
		break;
	}
}

static char tmpdir[128];

static char *dbpath(void)
{
	static char path[256];

	snprintf(path, sizeof(path), "%s/sessions.db", tmpdir);
	return path;
}

/* 跑一轮：reset=1 先吐 GARBAGE+RESET 再回放；use_sink=1 走 B 路。
 * file_cap/file_n：A 路 FILE 捕获；err_cap/err_n：A 路 stderr 捕获
 * （传 NULL 不捕获）。返回 occ_loop_run rc。 */
static int run_turn(int use_sink, int reset, char *file_cap, size_t cap,
		    size_t *file_n, char *err_cap, size_t ecap, size_t *err_n)
{
	occ_db *db;
	occ_provider p;
	occ_loop_opts opts;
	occ_loop_result res;
	char err[512];
	FILE *tf = NULL;
	int saved_stderr = -1;
	int pfd[2] = { -1, -1 };
	int rc;

	g_fake_reset = reset;
	g_text_n = 0;
	g_notices_n = 0;
	g_n_tool_start = 0;
	g_n_tool_end = 0;
	g_text[0] = '\0';
	g_notices[0] = '\0';

	if (err_cap && ecap) {
		fflush(stderr);
		if (pipe(pfd) != 0)
			return -98;
		saved_stderr = dup(2);
		dup2(pfd[1], 2);
		close(pfd[1]);
	}

	db = occ_db_open(dbpath(), err, sizeof(err));
	if (!db) {
		printf("db open: %s\n", err);
		rc = -99;
		goto out_restore;
	}
	memset(&p, 0, sizeof(p));
	p.proto = OCC_PROTO_OPENAI_COMPAT;
	snprintf(p.model, sizeof(p.model), "sink-model");
	snprintf(p.base_url, sizeof(p.base_url), "%s", "http://127.0.0.1:1");

	memset(&opts, 0, sizeof(opts));
	opts.prompt = "sink 对拍提示";
	opts.llm_call = fake_llm_call;
	if (use_sink) {
		opts.sink.fn = sink_cb;
		opts.sink.ud = NULL;
	} else {
		tf = tmpfile();
		opts.stream_out = tf;
	}
	rc = occ_loop_run(db, &p, NULL, &opts, &res, err, sizeof(err));
	occ_loop_result_free(&res);
	if (tf) {
		size_t n = 0;

		rewind(tf);
		n = fread(file_cap, 1, cap, tf);
		fclose(tf);
		if (file_n)
			*file_n = n;
	}
	occ_db_close(db);

out_restore:
	if (err_cap && ecap) {
		size_t en = 0;
		ssize_t r;

		fflush(stderr);
		dup2(saved_stderr, 2);
		close(saved_stderr);
		while ((r = read(pfd[0], err_cap + en, ecap - 1 - en)) > 0)
			en += (size_t)r;
		close(pfd[0]);
		err_cap[en] = '\0';
		if (err_n)
			*err_n = en;
	}
	return rc;
}

int main(void)
{
	char fcap[CAP_MAX];
	char ecap[4096];
	size_t fn = 0, en = 0;
	int rc_a, rc_b;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/occ_sink_t_%d", (int)getpid());
	mkdir(tmpdir, 0755);

	/* ---- 用例 1：正常流——A 路 FILE 与 B 路 sink TEXT 逐字节相等 ---- */
	rc_a = run_turn(0, 0, fcap, sizeof(fcap), &fn, NULL, 0, NULL);
	OK(rc_a == OCC_LOOP_OK, "A-turn-ok");
	OK(fn > 0 && strstr(fcap, "你好，世界") != NULL, "A-file-has-text");
	rc_b = run_turn(1, 0, NULL, 0, NULL, NULL, 0, NULL);
	OK(rc_b == OCC_LOOP_OK, "B-turn-ok");
	OK(g_text_n == fn && memcmp(g_text, fcap, fn) == 0,
	   "sink-text-byte-identical");
	OK(g_notices_n == 0, "B-no-notice-normal");
	OK(g_n_tool_start == 0 && g_n_tool_end == 0, "B-no-tool-normal");

	/* ---- 用例 2：RESET 流 ----
	 * A 路：stderr 收 "occ: 重试…"（缺省 sink 的字节合同）；
	 *      FILE 已含 GARBAGE（已流出字节不可收回——如实差异）。
	 * B 路：sink 收 [R] 事件并清 live 文本 → 最终 TEXT==正常流；
	 *      stderr 零字节（sink 接管，防 alt-screen 污染）。 */
	rc_a = run_turn(0, 1, fcap, sizeof(fcap), &fn, ecap, sizeof(ecap),
			&en);
	OK(rc_a == OCC_LOOP_OK, "A2-turn-ok");
	OK(en > 0 && strstr(ecap, "occ: 重试：第 1/2 次尝试") != NULL,
	   "A2-stderr-retry-notice");
	OK(fn > 0 && strstr(fcap, "GARBAGE-") != NULL,
	   "A2-file-already-flushed-garbage");

	rc_b = run_turn(1, 1, NULL, 0, NULL, ecap, sizeof(ecap), &en);
	OK(rc_b == OCC_LOOP_OK, "B2-turn-ok");
	OK(strstr(g_notices, "[R]重试：第 1/2 次尝试") != NULL,
	   "B2-sink-reset-event");
	OK(en == 0, "B2-stderr-zero-bytes");
	OK(strstr(g_text, "GARBAGE") == NULL, "B2-sink-live-cleared");
	OK(strstr(g_text, "你好，世界") != NULL, "B2-sink-replayed-text");
	OK(g_n_tool_start == 0 && g_n_tool_end == 0, "B2-no-tool");

	/* ---- 清理 ---- */
	{
		char cmd[320];

		snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
		if (system(cmd) != 0) {
			/* 尽力清理 */
		}
	}
	printf("test_sink: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
