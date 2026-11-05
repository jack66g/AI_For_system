/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_conf.c - conf 解析单测（好值通过、坏值/未知键/重复键拒绝）
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "as_conf.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

static char tmpdir[64];

/* 写临时 conf 文件并加载；返回 load rc */
static int load_str(const char *content, struct as_conf *c, char *err,
		    size_t errcap)
{
	char path[128];
	FILE *f;

	snprintf(path, sizeof(path), "%s/t.conf", tmpdir);
	f = fopen(path, "w");
	if (!f)
		return -99;
	fputs(content, f);
	fclose(f);
	as_conf_defaults(c);
	return as_conf_load(c, path, err, errcap);
}

int main(void)
{
	struct as_conf c;
	char err[256];

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/as-conf-%d", (int)getpid());
	{
		char cmd[128];

		snprintf(cmd, sizeof(cmd), "mkdir -p %s", tmpdir);
		if (system(cmd) != 0)
			return 2;
	}

	/* ---- 1) 全默认（空文件） ---- */
	CHECK(load_str("# comment only\n\n", &c, err, sizeof(err)) == 0,
	      "comment-only file OK");
	CHECK(c.rate_per_min == 60 && c.daily_max == 5000 &&
	      c.stream_daily_max == 1000 && c.dedup_window_ms == 10000 &&
	      c.ring_size == 4096 && c.importance == 0.3,
	      "defaults match spec");
	CHECK(c.enable_event == 1 && c.enable_taskstats == 1, "enables=1");
	CHECK(strcmp(c.sme_url, "http://127.0.0.1:8000") == 0, "sme url");

	/* ---- 2) 合法覆盖 ---- */
	CHECK(load_str("RATE_PER_MIN=120\nIMPORTANCE=0.7\n"
		       "ENABLE_NFLOG=0\nAI_MOCK_PROTO=2\n"
		       "STATS_FILE=/tmp/x.stats\n", &c, err,
		       sizeof(err)) == 0, "good overrides");
	CHECK(c.rate_per_min == 120, "rate 120");
	CHECK(c.importance > 0.699 && c.importance < 0.701, "importance");
	CHECK(c.enable_nflog == 0, "nflog off");
	CHECK(c.ai_mock_proto == 2, "mock proto 2");
	CHECK(strcmp(c.stats_file, "/tmp/x.stats") == 0, "stats path");

	/* ---- 3) 坏值拒绝 ---- */
	CHECK(load_str("RATE_PER_MIN=abc\n", &c, err, sizeof(err)) != 0,
	      "garbage int rejected");
	CHECK(load_str("RATE_PER_MIN=-5\n", &c, err, sizeof(err)) != 0,
	      "negative rejected");
	CHECK(load_str("RATE_PER_MIN=0\n", &c, err, sizeof(err)) != 0,
	      "zero rate rejected");
	CHECK(load_str("IMPORTANCE=1.5\n", &c, err, sizeof(err)) != 0,
	      "importance >1 rejected");
	CHECK(load_str("IMPORTANCE=0\n", &c, err, sizeof(err)) != 0,
	      "importance 0 rejected");
	CHECK(load_str("ENABLE_PROC=2\n", &c, err, sizeof(err)) != 0,
	      "enable=2 rejected");
	CHECK(load_str("AI_MOCK_PROTO=1\n", &c, err, sizeof(err)) != 0,
	      "mock proto 1 rejected");
	CHECK(load_str("AI_MOCK_PROTO=3\n", &c, err, sizeof(err)) != 0,
	      "mock proto 3 rejected");
	CHECK(load_str("RING_SIZE=99999999\n", &c, err, sizeof(err)) != 0,
	      "ring overflow rejected");
	CHECK(load_str("DEDUP_WINDOW_MS=10\n", &c, err, sizeof(err)) != 0,
	      "tiny dedup window rejected");

	/* ---- 4) 未知键/重复键/缺等号 ---- */
	CHECK(load_str("UNKNOWN_KEY=1\n", &c, err, sizeof(err)) != 0,
	      "unknown key rejected");
	CHECK(strstr(err, "unknown key") != NULL, "err mentions unknown");
	CHECK(load_str("RATE_PER_MIN=60\nRATE_PER_MIN=70\n", &c, err,
		       sizeof(err)) != 0, "duplicate key rejected");
	CHECK(load_str("RATE_PER_MIN 60\n", &c, err, sizeof(err)) != 0,
	      "missing = rejected");

	/* ---- 5) 缺文件拒绝 ---- */
	as_conf_defaults(&c);
	CHECK(as_conf_load(&c, "/nonexistent/as.conf", err, sizeof(err)) !=
	      0, "missing file rejected");

	{
		char cmd[128];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
		(void)!system(cmd);
	}
	if (fails) {
		printf("test_conf: %d failures\n", fails);
		return 1;
	}
	printf("test_conf: OK\n");
	return 0;
}
