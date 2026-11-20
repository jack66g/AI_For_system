/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_shadow.c - 影子 parquet 落盘：33 列/footer 行数读回（as_pq_file_
 * stats 独立读路径）/序号旋转/批写生命周期
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "aistreamd/as_parquet.h"

#include "aip_conf.h"
#include "aip_feat.h"
#include "aip_model.h"
#include "aip_shadow.h"

static int fails, checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

static char tmpdir[64];

static long long now_mono_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static struct aip_shadow_row mkrow(uint64_t id, uint64_t ts)
{
	struct aip_shadow_row r;

	memset(&r, 0, sizeof(r));
	r.decision_id = (int64_t)id;
	r.trigger_ts = (int64_t)ts;
	r.trigger_event_id = (int64_t)id;
	r.decision_ts = now_mono_ns();
	r.decision_type = AIP_ACT_RECLAIM_AGGRESSIVE;
	r.data[0] = 250000;
	r.data[1] = 12;
	r.data[2] = 500;
	r.model_version = (int32_t)AIP_TABLE_VER;
	r.confidence = 100;
	r.executed = 0;			/* M1 恒 0 */
	r.agent_id = 0;
	r.value = 0.0;
	return r;
}

int main(void)
{
	char root[192], path[256], daydir[512] = "", file1[600] = "";
	struct aip_shadow_row rows[5];
	struct pq_file_stats fs;
	struct aip_conf c;
	struct aip_shadow s;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/m1a-shadow-%d", (int)getpid());
	{
		char cmd[256];

		snprintf(cmd, sizeof(cmd), "rm -rf %s; mkdir -p %s",
			 tmpdir, tmpdir);
		if (system(cmd) != 0)
			return 2;
	}
	snprintf(root, sizeof(root), "%s/root", tmpdir);

	/* ---- 0) P-56：列名契约——唯一性 + 关键位定名 ---- */
	CHECK(aip_shadow_cols_unique() == 0, "P-56 colnames all-unique");
	CHECK(aip_shadow_ncols() == 33, "33 cols");
	CHECK(aip_shadow_colname(20) && strcmp(aip_shadow_colname(20),
	      "source") == 0, "col20 = source (int 决策源)");
	CHECK(aip_shadow_colname(32) && strcmp(aip_shadow_colname(32),
	      "producer") == 0, "col32 = producer (P-56 改名)");
	CHECK(aip_shadow_colname(-1) == NULL && aip_shadow_colname(33) == NULL,
	      "colname 越界 NULL");

	/* ---- 1) 直写单文件：33 列 + footer 行数（独立读路径验证） ---- */
	snprintf(path, sizeof(path), "%s/day-direct.parquet", tmpdir);
	for (int i = 0; i < 5; i++)
		rows[i] = mkrow(i + 1, 1000 + i);
	CHECK(aip_shadow_write_file(path, rows, 5) == 0, "write 5 rows");
	CHECK(aip_shadow_write_file(path, NULL, 0) != 0,
	      "empty write rejected");
	memset(&fs, 0, sizeof(fs));
	CHECK(as_pq_file_stats(path, &fs) == 0, "footer readable");
	CHECK(fs.num_rows == 5, "footer num_rows==5");
	CHECK(fs.has_ncols && fs.ncols == 33, "footer ncols==33 (32+producer)");
	{
		FILE *f = fopen(path, "r");
		char magic[5] = "";

		CHECK(f != NULL, "file open");
		if (f) {
			size_t n = fread(magic, 1, 4, f);

			fclose(f);
			magic[4] = '\0';
			CHECK(n == 4 && strcmp(magic, "PAR1") == 0,
			      "PAR1 magic");
		}
	}

	/* ---- 2) 记录器：feed→flush→<root>/aipd/<日>/shadow_0001 ---- */
	aip_conf_defaults(&c);
	snprintf(c.parquet_dir, sizeof(c.parquet_dir), "%s", root);
	c.shadow_flush_sec = 1;
	c.shadow_flush_rows = 128;
	CHECK(aip_shadow_init(&s, &c) == 0, "shadow init");
	{
		struct aip_fvec v;
		struct aip_decision d;

		memset(&v, 0, sizeof(v));
		v.seq = 1;
		v.ts = 42;
		v.valid_bits = 7;
		memset(&d, 0, sizeof(d));
		d.rule_idx = 0;
		d.action = AIP_ACT_SCHED_COMPENSATE;
			for (int i = 0; i < 3; i++)
				aip_shadow_feed(&s, &v, 0, &d, now_mono_ns(),
						0, AIP_TABLE_VER);
		CHECK(s.n == 3, "3 rows buffered");
		aip_shadow_flush(&s);
		CHECK(s.n == 0 && s.rows_written == 3 && s.files == 1,
		      "flush counted");
		aip_shadow_flush(&s);
		CHECK(s.files == 1, "empty flush no-op");
	}
	/* 定位日目录与 shadow_0001 */
	{
		char cmd[600];
		FILE *p;

		snprintf(cmd, sizeof(cmd),
			 "find %s/aipd -mindepth 1 -maxdepth 1 -type d",
			 root);
		p = popen(cmd, "r");
		CHECK(p != NULL, "day dir find");
		if (p) {
			if (fgets(daydir, sizeof(daydir), p))
				daydir[strcspn(daydir, "\n")] = '\0';
			pclose(p);
		}
		CHECK(daydir[0] != '\0', "day dir exists");
		{
			const char *day = strrchr(daydir, '/');

			day = day ? day + 1 : daydir;
			checks++;
			if (strlen(day) == 10 && day[4] == '-' &&
			    day[7] == '-' &&
			    strspn(day, "0123456789-") == 10) {
				/* YYYY-MM-DD ok */
			} else {
				printf("FAIL: day dir format '%s'\n", day);
				fails++;
			}
			snprintf(file1, sizeof(file1), "%s/shadow_0001"
				 ".parquet", daydir);
		}
		CHECK(access(file1, F_OK) == 0, "shadow_0001.parquet exists");
		memset(&fs, 0, sizeof(fs));
		CHECK(as_pq_file_stats(file1, &fs) == 0 && fs.num_rows == 3
		      && fs.ncols == 33, "batch footer rows==3 ncols==33");
	}

	/* ---- 3) 序号旋转：下一号=现有最大+1；二次 flush→shadow_0002 ---- */
	{
		const char *day = strrchr(daydir, '/');

		day = day ? day + 1 : daydir;
		CHECK(daydir[0] && aip_shadow_next_seq(root, day) == 2,
		      "next_seq==2 after one file");
		CHECK(aip_shadow_next_seq(root, "1970-01-01") == 1,
		      "empty day next_seq==1");
	}
	{
		struct aip_fvec v;
		struct aip_decision d;

		memset(&v, 0, sizeof(v));
		memset(&d, 0, sizeof(d));
		d.rule_idx = -1;
		d.action = AIP_ACT_NONE;
		aip_shadow_feed(&s, &v, 1, &d, now_mono_ns(), 0, AIP_TABLE_VER);
		aip_shadow_flush(&s);
		CHECK(s.files == 2 && s.rows_written == 4,
		      "rotation second file");
		{
			char f2[600];

			snprintf(f2, sizeof(f2), "%s/shadow_0002.parquet",
				 daydir);
			CHECK(access(f2, F_OK) == 0, "shadow_0002 exists");
		}
	}
	aip_shadow_close(&s);
	CHECK(s.files == 2, "close no extra flush (empty)");
	/* executed 恒 0 抽查：直写行回读列不做（footer 不含值），由
	 * 构造面断言：mkrow/ feed 路径 executed 字段源码恒 0（M1 红线） */

	{
		char cmd[256];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
		(void)!system(cmd);
	}
	if (fails) {
		printf("test_shadow: %d failures (%d checks)\n", fails,
		       checks);
		return 1;
	}
	printf("test_shadow: OK (%d checks)\n", checks);
	return 0;
}
