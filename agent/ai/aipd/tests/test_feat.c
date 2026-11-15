/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_feat.c - mock jsonl 解析/新鲜度/map35 attr 打包自证/轮询源
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "aip_conf.h"
#include "aip_feat.h"

static int fails, checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

static char tmpdir[64];

static uint64_t now_mono_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(void)
{
	struct aip_conf c;
	struct aip_fvec v;
	char path[192];
	char err[256];

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/m1a-feat-%d", (int)getpid());
	{
		char cmd[128];

		snprintf(cmd, sizeof(cmd), "mkdir -p %s", tmpdir);
		if (system(cmd) != 0)
			return 2;
	}

	/* ---- 1) 冻结契约：48B/偏移（编译期 _Static_assert 的运行时镜面） ---- */
	CHECK(sizeof(struct aip_fvec) == 48, "vec==48B");

	/* ---- 2) mock 解析 ---- */
	CHECK(aip_mock_parse_line("{\"seq\":1,\"ts\":100,\"lat_ewma_ns\":250000,"
		"\"iowait_pct\":12,\"psi_mem_some\":204,\"cache_misses\":0,"
		"\"valid_bits\":7}", &v) == 0, "good line parses");
	CHECK(v.seq == 1 && v.ts == 100 && v.lat_ewma_ns == 250000,
	      "u64 fields");
	CHECK(v.iowait_pct == 12 && v.psi_mem_some == 204 &&
	      v.valid_bits == 7, "u32 fields");
	CHECK(v.rsv == 0, "rsv zero");
	/* 字段乱序也中（strstr 扫描，不依赖顺序） */
	CHECK(aip_mock_parse_line("{\"valid_bits\":7,\"seq\":2,\"ts\":9,"
		"\"lat_ewma_ns\":1,\"iowait_pct\":0,\"psi_mem_some\":0,"
		"\"cache_misses\":0}", &v) == 0 && v.seq == 2,
	      "field order agnostic");
	CHECK(aip_mock_parse_line("{\"seq\":1,\"ts\":100}", &v) != 0,
	      "missing fields rejected");
	CHECK(aip_mock_parse_line("not json at all", &v) != 0,
	      "garbage rejected");
	CHECK(aip_mock_parse_line("{\"seq\":1,\"ts\":1,\"lat_ewma_ns\":1,"
		"\"iowait_pct\":4294967296,\"psi_mem_some\":0,"
		"\"cache_misses\":0,\"valid_bits\":0}", &v) != 0,
	      "u32 overflow rejected");
	CHECK(aip_mock_parse_line("{\"seq\":1,\"ts\":1,\"lat_ewma_ns\":1,"
		"\"iowait_pct\":abc,\"psi_mem_some\":0,"
		"\"cache_misses\":0,\"valid_bits\":0}", &v) != 0,
	      "non-numeric rejected");

	/* ---- 3) 新鲜度 ---- */
	CHECK(aip_feat_is_stale(0, 3000000000LL) == 1,
	      "ts==0 (never published) stale");
	CHECK(aip_feat_is_stale(now_mono_ns(), 3000000000LL) == 0,
	      "fresh ts not stale");
	CHECK(aip_feat_is_stale(now_mono_ns() - 3500000000ULL,
				3000000000LL) == 1, "3.5s old stale @3s thresh");
	CHECK(aip_feat_is_stale(now_mono_ns() - 2500000000ULL,
				3000000000LL) == 0, "2.5s old fresh @3s thresh");
	CHECK(aip_feat_is_stale(now_mono_ns() + 60000000000ULL,
				3000000000LL) == 1,
	      "future ts (clock skew) honest stale");

	/* ---- 4) map35 attr 打包自证（k7feat selftest 同口径） ---- */
	{
		unsigned char attr[128];

		aip_feat_pack_create(attr);
		CHECK(attr[0] == 35 && attr[1] == 0 && attr[2] == 0 &&
		      attr[3] == 0, "map_type=35 LE @0");
		CHECK(attr[4] == 4 && attr[5] == 0 && attr[6] == 0 &&
		      attr[7] == 0, "key_size=4 LE @4");
		CHECK(attr[8] == 0 && attr[16] == 0,
		      "value_size/max_entries=0 (kernel clamps)");
	}

	/* ---- 5) mock 源生命周期：open/poll 逐行/坏行/EOF 复用 ---- */
	snprintf(path, sizeof(path), "%s/mock.jsonl", tmpdir);
	{
		FILE *f = fopen(path, "w");

		fprintf(f, "{\"seq\":1,\"ts\":%llu,\"lat_ewma_ns\":250000,"
			"\"iowait_pct\":12,\"psi_mem_some\":204,"
			"\"cache_misses\":0,\"valid_bits\":7}\n",
			(unsigned long long)now_mono_ns());
		fprintf(f, "garbage line\n");
		fprintf(f, "{\"seq\":3,\"ts\":%llu,\"lat_ewma_ns\":9000000,"
			"\"iowait_pct\":30,\"psi_mem_some\":500,"
			"\"cache_misses\":0,\"valid_bits\":7}\n",
			(unsigned long long)now_mono_ns());
		fclose(f);
	}
	aip_conf_defaults(&c);
	c.feat_source = 1;
	snprintf(c.feat_mock_file, sizeof(c.feat_mock_file), "%s", path);
	{
		struct aip_feat_src f;
		int stale = -1;

		CHECK(aip_feat_open(&f, &c, err, sizeof(err)) == 0,
		      "mock open");
		CHECK(f.type == AIP_FEAT_MOCK && f.mock_degraded == 0,
		      "mock type");
		CHECK(f.stale_thresh_ns == 3000000000LL,
		      "stale thresh = 3s @POLL_HZ=10");
		CHECK(aip_feat_poll(&f, &v, &stale) == 0 && v.seq == 1 &&
		      stale == 0, "poll line1 fresh");
		CHECK(aip_feat_poll(&f, &v, &stale) == -1 &&
		      f.bad_lines == 1, "poll bad line counted+skipped");
		CHECK(aip_feat_poll(&f, &v, &stale) == 0 && v.seq == 3,
		      "poll line3");
		CHECK(aip_feat_poll(&f, &v, &stale) == 0 && v.seq == 3,
		      "EOF reuses last vector");
		CHECK(f.polls == 4 && f.ok == 3 && f.errors == 0,
		      "poll counters");
		aip_feat_close(&f);
		aip_feat_close(&f);		/* 幂等 */
	}

	/* ---- 6) mock 文件缺失=诚实失败 ---- */
	aip_conf_defaults(&c);
	c.feat_source = 1;
	snprintf(c.feat_mock_file, sizeof(c.feat_mock_file),
		 "%s/missing.jsonl", tmpdir);
	{
		struct aip_feat_src f;

		CHECK(aip_feat_open(&f, &c, err, sizeof(err)) != 0,
		      "missing mock file honest fail");
	}

	{
		char cmd[128];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
		(void)!system(cmd);
	}
	if (fails) {
		printf("test_feat: %d failures (%d checks)\n", fails, checks);
		return 1;
	}
	printf("test_feat: OK (%d checks)\n", checks);
	return 0;
}
