/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_telemetry.c - occ 会话遥测 → T8 parquet 沉淀（T9d/§9.6）
 * 接入面与边界见 occ_telemetry.h 文件头。
 */
#define _POSIX_C_SOURCE 200809L
#include "occ_telemetry.h"

#include "aistreamd/as_parquet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define OCC_PQ_ROW_MAX 400		/* data JSON 上限（< int16 列宽） */

static struct pq_tel_row g_rows[OCC_TELEMETRY_BUF_MAX];
static char g_pool[OCC_TELEMETRY_BUF_MAX][OCC_PQ_ROW_MAX];
static long g_n;
static int g_atexit_hooked;
static char g_root_override[512];

static void flush_atexit(void);		/* 定义见文件尾（atexit 签名） */

int occ_telemetry_enabled(void)
{
	const char *e = getenv("OCC_PARQUET");

	return !(e && *e && !strcmp(e, "off"));
}

const char *occ_telemetry_root(void)
{
	static char buf[512];
	const char *env;
	const char *home;

	if (g_root_override[0])
		return g_root_override;
	env = getenv("OCC_PARQUET_ROOT");
	if (env && *env)
		return env;
	home = getenv("HOME");
	if (!home || !*home)
		return NULL;
	snprintf(buf, sizeof(buf), "%s/.occ/telemetry", home);
	return buf;
}

const char *occ_telemetry_test_set_root(const char *root)
{
	static char old[512];

	snprintf(old, sizeof(old), "%s", g_root_override);
	if (root)
		snprintf(g_root_override, sizeof(g_root_override), "%s", root);
	else
		g_root_override[0] = '\0';
	return old;
}

static int64_t mono_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int push_row(const char *json)
{
	struct pq_tel_row *r;

	if (g_n >= OCC_TELEMETRY_BUF_MAX) {
		if (occ_telemetry_flush() < 0)
			return -1;
	}
	if (g_n >= OCC_TELEMETRY_BUF_MAX)
		return -1;
	snprintf(g_pool[g_n], OCC_PQ_ROW_MAX, "%s", json);
	r = &g_rows[g_n];
	memset(r, 0, sizeof(*r));
	r->ts_ns = mono_ns();
	r->pid = (int32_t)getpid();
	r->tgid = 0;
	r->cpu = 0;
	r->category = OCC_TELEMETRY_CATEGORY;
	r->event_type = 0;
	r->severity = 0;
	r->data_len = (int16_t)strlen(g_pool[g_n]);
	r->data = (const uint8_t *)g_pool[g_n];
	g_n++;
	return 0;
}

int occ_telemetry_flush(void)
{
	const char *root;
	struct pq_write_stat st;
	int r;

	if (!occ_telemetry_enabled() || g_n == 0)
		return 0;
	root = occ_telemetry_root();
	if (!root) {
		g_n = 0;
		return -1;
	}
	if (as_pq_ensure_root(root) != 0) {
		g_n = 0;
		return -1;
	}
	memset(&st, 0, sizeof(st));
	r = as_pq_write_telemetry(root, g_rows, (size_t)g_n,
				  as_pq_btime(), 65536, &st);
	g_n = 0;
	return r;
}

int occ_telemetry_turn(const char *session_id, long long tokens_total,
		       int rounds, const char *finish, int compacted,
		       long long digest_chars)
{
	char json[OCC_PQ_ROW_MAX];

	if (!occ_telemetry_enabled() || !session_id)
		return -1;
	if (!g_atexit_hooked) {
		g_atexit_hooked = 1;
		atexit(flush_atexit);
	}
	if (compacted)
		snprintf(json, sizeof(json),
			 "{\"ev\":\"compact\",\"sid\":\"%s\","
			 "\"digest_chars\":%lld,\"tokens\":%lld}",
			 session_id, digest_chars, tokens_total);
	else
		snprintf(json, sizeof(json),
			 "{\"ev\":\"turn\",\"sid\":\"%s\","
			 "\"tokens\":%lld,\"rounds\":%d,\"finish\":\"%s\"}",
			 session_id, tokens_total, rounds,
			 finish ? finish : "");
	if (push_row(json) != 0)
		return -1;
	/* 换窗是关键事件：立刻落盘（不等缓冲/退出） */
	if (compacted)
		return occ_telemetry_flush() < 0 ? -1 : 0;
	return 0;
}

long occ_telemetry_pending(void)
{
	return g_n;
}

/* atexit 需要 void(void) 签名 */
static void flush_atexit(void)
{
	(void)occ_telemetry_flush();
}
