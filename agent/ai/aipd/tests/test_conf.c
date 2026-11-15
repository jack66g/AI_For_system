/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_conf.c - conf 解析单测（好值通过、坏值/未知键/重复键/跨键拒绝）
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aip_conf.h"

static int fails, checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

static char tmpdir[64];

static int load_str(const char *content, struct aip_conf *c, char *err,
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
	aip_conf_defaults(c);
	return aip_conf_load(c, path, err, errcap);
}

int main(void)
{
	struct aip_conf c;
	char err[256];

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/m1a-conf-%d", (int)getpid());
	{
		char cmd[128];

		snprintf(cmd, sizeof(cmd), "mkdir -p %s", tmpdir);
		if (system(cmd) != 0)
			return 2;
	}

	/* ---- 1) 默认值 ---- */
	CHECK(load_str("# comment only\n\n", &c, err, sizeof(err)) == 0,
	      "comment-only file OK");
	CHECK(c.feat_source == 0 && c.poll_hz == 10 && c.shadow == 1 &&
	      c.stats_interval_sec == 10 && c.cmp_window == 256 &&
	      c.compare_enabled == 0 && c.feat_degrade_mock == 0,
	      "defaults match spec");
	CHECK(strcmp(c.parquet_dir, "/var/lib/aikernel") == 0 &&
	      strcmp(c.stats_file, "/run/aipd.stats") == 0 &&
	      strcmp(c.lock_file, "/run/aipd.lock") == 0,
	      "default paths");

	/* ---- 2) 合法覆盖 ---- */
	CHECK(load_str("FEAT_SOURCE=mock\nFEAT_MOCK_FILE=/tmp/f.jsonl\n"
		       "POLL_HZ=50\nSTATS_INTERVAL_SEC=5\nPARQUET_DIR=/tmp/x\n"
		       "MODEL_TABLE=builtin\nSHADOW=1\n"
		       "LOCK_FILE=/tmp/x.lock\n", &c, err,
		       sizeof(err)) == 0, "good overrides");
	CHECK(c.feat_source == 1 && c.poll_hz == 50 &&
	      strcmp(c.feat_mock_file, "/tmp/f.jsonl") == 0 &&
	      strcmp(c.parquet_dir, "/tmp/x") == 0, "overrides parsed");

	/* ---- 3) 坏值拒绝 ---- */
	CHECK(load_str("FEAT_SOURCE=bpf\n", &c, err, sizeof(err)) != 0,
	      "bad FEAT_SOURCE rejected");
	CHECK(load_str("FEAT_SOURCE=mock\n", &c, err, sizeof(err)) != 0,
	      "mock without FEAT_MOCK_FILE rejected");
	CHECK(load_str("POLL_HZ=0\n", &c, err, sizeof(err)) != 0,
	      "POLL_HZ=0 rejected");
	CHECK(load_str("POLL_HZ=1001\n", &c, err, sizeof(err)) != 0,
	      "POLL_HZ=1001 rejected");
	CHECK(load_str("POLL_HZ=abc\n", &c, err, sizeof(err)) != 0,
	      "POLL_HZ=abc rejected");
	CHECK(load_str("STATS_INTERVAL_SEC=0\n", &c, err, sizeof(err)) != 0,
	      "STATS_INTERVAL_SEC=0 rejected");
	CHECK(load_str("SHADOW=0\n", &c, err, sizeof(err)) != 0,
	      "SHADOW=0 rejected (M1 frozen)");
	CHECK(load_str("SHADOW=2\n", &c, err, sizeof(err)) != 0,
	      "SHADOW=2 rejected");
	CHECK(load_str("MODEL_TABLE=external\n", &c, err, sizeof(err)) != 0,
	      "MODEL_TABLE=external rejected");
	CHECK(load_str("CMP_WINDOW=4\n", &c, err, sizeof(err)) != 0,
	      "tiny CMP_WINDOW rejected");
	CHECK(load_str("FEAT_MOCK_FILE=relative.jsonl\n", &c, err,
		       sizeof(err)) != 0, "relative path rejected");
	CHECK(load_str("FEAT_DEGRADE_MOCK=1\n", &c, err, sizeof(err)) != 0,
	      "degrade without mock file rejected");
	CHECK(load_str("COMPARE_ENABLED=1\nCOMPARE_SOURCE=mock\n", &c, err,
		       sizeof(err)) != 0, "compare mock without file rejected");

	/* ---- 4) 未知键/重复键/缺等号/缺文件 ---- */
	CHECK(load_str("UNKNOWN=1\n", &c, err, sizeof(err)) != 0,
	      "unknown key rejected");
	CHECK(strstr(err, "unknown key") != NULL, "err mentions unknown");
	CHECK(load_str("POLL_HZ=10\nPOLL_HZ=20\n", &c, err, sizeof(err)) != 0,
	      "duplicate key rejected");
	CHECK(load_str("POLL_HZ 10\n", &c, err, sizeof(err)) != 0,
	      "missing = rejected");
	aip_conf_defaults(&c);
	CHECK(aip_conf_load(&c, "/nonexistent/aipd.conf", err,
			    sizeof(err)) != 0, "missing file rejected");

	/* ---- 5) 对照面合法覆盖 ---- */
	CHECK(load_str("COMPARE_ENABLED=1\nCOMPARE_SOURCE=mock\n"
		       "COMPARE_MOCK_FILE=/tmp/cmp.jsonl\nCMP_WINDOW=64\n",
		       &c, err, sizeof(err)) == 0, "compare keys accepted");
	CHECK(c.compare_enabled == 1 && c.compare_mock == 1 &&
	      c.cmp_window == 64, "compare values parsed");
	CHECK(load_str("COMPARE_SOURCE=netlink\n", &c, err, sizeof(err)) != 0,
	      "bad COMPARE_SOURCE rejected");

	{
		char cmd[128];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
		(void)!system(cmd);
	}
	if (fails) {
		printf("test_conf: %d failures (%d checks)\n", fails, checks);
		return 1;
	}
	printf("test_conf: OK (%d checks)\n", checks);
	return 0;
}
