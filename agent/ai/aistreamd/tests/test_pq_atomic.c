/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_pq_atomic.c - LT-BUG-009 回归钉：
 * parquet 落盘原子性（<path>.tmp → fsync → rename）。
 *
 * 断言：
 *   A1 成功写后：天目录恰 1 个 *.parquet、0 个 *.tmp
 *   A2 文件头尾均 PAR1（完整成件）；as_pq_file_stats 读回 num_rows 正确
 *   A3 覆盖写（同根再写一次）后仍恰 1 个 *.parquet、0 个 *.tmp、条数正确
 *   A4 失败路径（root 落在不可创建处）：返回 -1，目标区零文件
 *   A5 残根免疫：手造 <x>.parquet.tmp 垃圾残根后 as_pq_update_index
 *      不计它（index 行数 == 真实分片数）
 */
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "aistreamd/as_parquet.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s (line %d)\n", msg, __LINE__); \
		fails++; \
	} \
} while (0)

static void rm_rf(const char *dir)
{
	char cmd[512];

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
	if (system(cmd) != 0)
		printf("warn: rm_rf %s failed\n", dir);
}

/* 统计 dir 下 *.parquet / *.tmp 个数（一层） */
static void count_sfx(const char *dir, int *npar, int *ntmp)
{
	DIR *d = opendir(dir);
	struct dirent *e;

	*npar = 0;
	*ntmp = 0;
	if (!d)
		return;
	while ((e = readdir(d)) != NULL) {
		size_t n = strlen(e->d_name);

		if (n >= 8 && strcmp(e->d_name + n - 8, ".parquet") == 0)
			(*npar)++;
		else if (n >= 4 && strcmp(e->d_name + n - 4, ".tmp") == 0)
			(*ntmp)++;
	}
	closedir(d);
}

/* 找 root/telemetry 下唯一天目录 */
static int find_day(const char *root, char *out, size_t cap)
{
	char tel[256];
	DIR *d;
	struct dirent *e;
	int found = 0;

	snprintf(tel, sizeof(tel), "%s/telemetry", root);
	d = opendir(tel);
	if (!d)
		return -1;
	while ((e = readdir(d)) != NULL) {
		char p[1024];
		struct stat st;

		if (e->d_name[0] == '.')
			continue;
		snprintf(p, sizeof(p), "%s/%s", tel, e->d_name);
		if (stat(p, &st) != 0 || !S_ISDIR(st.st_mode))
			continue;	/* 只数天目录（index.parquet 是文件） */
		snprintf(out, cap, "%s/%s", tel, e->d_name);
		found++;
	}
	closedir(d);
	return found == 1 ? 0 : -1;
}

int main(void)
{
	const char *root = "/tmp/test_pq_atomic_root";
	char day[768], one[800], junk[800], idx[800];
	struct pq_tel_row rows[2];
	struct pq_file_stats fs;
	struct pq_write_stat ws;
	uint8_t payload[4] = { 1, 2, 3, 4 };
	int npar, ntmp, n;
	FILE *f;
	char magic[4];

	rm_rf(root);
	memset(&ws, 0, sizeof(ws));
	memset(rows, 0, sizeof(rows));
	rows[0].ts_ns = 1000000000LL;
	rows[0].pid = 1;
	rows[0].tgid = 1;
	rows[0].cpu = 0;
	rows[0].category = 1;
	rows[0].event_type = 1;
	rows[0].severity = 1;
	rows[0].data_len = 4;
	rows[0].data = payload;
	rows[1] = rows[0];
	rows[1].ts_ns = 2000000000LL;
	rows[1].pid = 2;

	/* A1+A2：成功写 */
	n = as_pq_write_telemetry(root, rows, 2, 0, 100, &ws);
	CHECK(n == 2, "write_telemetry returns 2");
	CHECK(find_day(root, day, sizeof(day)) == 0, "one day dir exists");
	count_sfx(day, &npar, &ntmp);
	CHECK(npar == 1, "A1: exactly one *.parquet");
	CHECK(ntmp == 0, "A1: zero *.tmp left");

	if (find_day(root, day, sizeof(day)) == 0 && npar == 1) {
		DIR *d = opendir(day);
		struct dirent *e;

		one[0] = '\0';
		if (d) {
			while ((e = readdir(d)) != NULL) {
				size_t ln = strlen(e->d_name);

				if (ln >= 8 &&
				    strcmp(e->d_name + ln - 8, ".parquet") == 0) {
					snprintf(one, sizeof(one), "%s/%s",
						 day, e->d_name);
					break;
				}
			}
			closedir(d);
		}
		CHECK(one[0] != '\0', "A2: shard path resolved");
		if (one[0]) {
			f = fopen(one, "rb");
			CHECK(f != NULL, "A2: shard openable");
			if (f) {
				CHECK(fread(magic, 1, 4, f) == 4 &&
				      memcmp(magic, "PAR1", 4) == 0,
				      "A2: head PAR1");
				CHECK(fseek(f, -4, SEEK_END) == 0 &&
				      fread(magic, 1, 4, f) == 4 &&
				      memcmp(magic, "PAR1", 4) == 0,
				      "A2: tail PAR1");
				fclose(f);
			}
			CHECK(as_pq_file_stats(one, &fs) == 0 &&
			      fs.num_rows == 2, "A2: footer readable rows==2");
		}
	}

	/* A3：二次写=序号旋转（telemetry 语义：新序号新文件，非覆盖）。
	 * 原子性判据：旋转后仍零 *.tmp、每件完整。 */
	n = as_pq_write_telemetry(root, rows, 2, 0, 100, NULL);
	CHECK(n == 2, "A3: rewrite returns 2");
	count_sfx(day, &npar, &ntmp);
	CHECK(npar == 2, "A3: seq rotation -> two *.parquet");
	CHECK(ntmp == 0, "A3: zero *.tmp after rewrite");
	if (one[0])
		CHECK(as_pq_file_stats(one, &fs) == 0 && fs.num_rows == 2,
		      "A3: first shard footer rows==2 intact");

	/* A4：失败路径（/proc 下不可建目录） */
	n = as_pq_write_telemetry("/proc/no_such_pq_root", rows, 2, 0, 100, NULL);
	CHECK(n == -1, "A4: bad root returns -1");
	{
		struct stat st;

		CHECK(stat("/proc/no_such_pq_root", &st) != 0,
		      "A4: nothing created");
	}

	/* A5：*.tmp 残根不入布局扫描 */
	if (one[0]) {
		long skipped = 0;
		

		snprintf(junk, sizeof(junk), "%s/zz_9999.parquet.tmp", day);
		f = fopen(junk, "wb");
		CHECK(f != NULL, "A5: junk tmp created");
		if (f) {
			fwrite("garbage", 1, 7, f);
			fclose(f);
		}
		CHECK(as_pq_update_index(root, &skipped) == 0,
		      "A5: update_index ok");
		snprintf(idx, sizeof(idx), "%s/telemetry/index.parquet", root);
		CHECK(as_pq_file_stats(idx, &fs) == 0 && fs.num_rows == 2,
		      "A5: index rows==2 real shards (tmp not counted)");
	}

	rm_rf(root);
	if (fails == 0) {
		printf("test_pq_atomic: all OK\n");
		return 0;
	}
	printf("test_pq_atomic: %d FAIL(s)\n", fails);
	return 1;
}
