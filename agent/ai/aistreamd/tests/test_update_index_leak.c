/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_update_index_leak.c - LT-BUG-008 回归钉：
 * as_pq_update_index() 反复调用不得泄漏。
 *
 * 造法：写 1 条 telemetry 得到合法分片，再按字节复制成 N_SHARDS 个
 * 分片，然后循环调用 as_pq_update_index() N_ITERS 次，断言每次返回 0。
 *
 * 泄漏判定：
 *   - ASan/LSan 构建（-fsanitize=address，detect_leaks=1）由 LSan 在
 *     退出时报告，本驱动不重复断言 RSS（ASan 隔离区会干扰 RSS）。
 *   - 普通构建：/proc/self/statm RSS 增量 < 1 MiB（N_ITERS=200），
 *     并打印 glibc mallinfo2 的 in-use 增量作旁证。
 */
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__GLIBC__) && (__GLIBC__ > 2 || \
	(__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
#include <malloc.h>
#define HAVE_MALLINFO2 1
#else
#define HAVE_MALLINFO2 0
#endif

#include "aistreamd/as_parquet.h"

#define N_SHARDS	64
#define N_ITERS		200
#define RSS_LIMIT_KIB	1024

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s (line %d)\n", msg, __LINE__); \
		fails++; \
	} \
} while (0)

static long rss_kib(void)
{
	FILE *f = fopen("/proc/self/statm", "r");
	long total = 0, resident = 0;

	if (!f)
		return -1;
	if (fscanf(f, "%ld %ld", &total, &resident) != 2)
		resident = -1;
	fclose(f);
	if (resident < 0)
		return -1;
	return resident * (long)(sysconf(_SC_PAGESIZE) / 1024);
}

static int copy_file(const char *src, const char *dst)
{
	FILE *in = fopen(src, "rb");
	FILE *out;
	long sz;
	char *buf;
	size_t n;

	if (!in)
		return -1;
	if (fseek(in, 0, SEEK_END) != 0) {
		fclose(in);
		return -1;
	}
	sz = ftell(in);
	if (sz < 0 || fseek(in, 0, SEEK_SET) != 0) {
		fclose(in);
		return -1;
	}
	buf = malloc((size_t)sz ? (size_t)sz : 1);
	if (!buf) {
		fclose(in);
		return -1;
	}
	n = fread(buf, 1, (size_t)sz, in);
	fclose(in);
	out = fopen(dst, "wb");
	if (!out) {
		free(buf);
		return -1;
	}
	if (n != (size_t)sz || fwrite(buf, 1, n, out) != n) {
		fclose(out);
		free(buf);
		return -1;
	}
	fclose(out);
	free(buf);
	return 0;
}

static void rm_rf(const char *path)
{
	struct stat sb;

	if (lstat(path, &sb) != 0)
		return;
	if (S_ISDIR(sb.st_mode)) {
		DIR *d = opendir(path);

		if (d) {
			struct dirent *e;

			while ((e = readdir(d)) != NULL) {
				char p[1024];

				if (strcmp(e->d_name, ".") == 0 ||
				    strcmp(e->d_name, "..") == 0)
					continue;
				snprintf(p, sizeof(p), "%s/%s", path,
					 e->d_name);
				rm_rf(p);
			}
			closedir(d);
		}
		rmdir(path);
	} else {
		unlink(path);
	}
}

/* 在目录里找第一个非 .parquet 的项（即日目录名） */
static int find_day_dir(const char *teldir, char *day, size_t cap)
{
	DIR *d = opendir(teldir);
	struct dirent *e;
	int rc = -1;

	if (!d)
		return -1;
	while ((e = readdir(d)) != NULL) {
		size_t n = strlen(e->d_name);

		if (strcmp(e->d_name, ".") == 0 ||
		    strcmp(e->d_name, "..") == 0)
			continue;
		if (n >= 8 && strcmp(e->d_name + n - 8, ".parquet") == 0)
			continue;
		snprintf(day, cap, "%s", e->d_name);
		rc = 0;
		break;
	}
	closedir(d);
	return rc;
}

/* 在日目录里找第一个数据分片文件名 */
static int find_shard(const char *daydir, char *name, size_t cap)
{
	DIR *d = opendir(daydir);
	struct dirent *e;
	int rc = -1;

	if (!d)
		return -1;
	while ((e = readdir(d)) != NULL) {
		size_t n = strlen(e->d_name);

		if (strcmp(e->d_name, ".") == 0 ||
		    strcmp(e->d_name, "..") == 0)
			continue;
		if (n < 9 || strcmp(e->d_name + n - 8, ".parquet") != 0)
			continue;
		if (strchr(e->d_name, '_') == NULL)
			continue;
		snprintf(name, cap, "%s", e->d_name);
		rc = 0;
		break;
	}
	closedir(d);
	return rc;
}

int main(void)
{
	char tmpl[] = "/tmp/as-leak-XXXXXX";
	char root[512], teldir[600], day[256], daydir[1024];
	char seedname[256], seedpath[1600], dstpath[1600];
	char *tmp = mkdtemp(tmpl);
	struct pq_tel_row row;
	struct pq_file_stats fs;
	long sk = 0, rss0, rss1;
	int r;

	if (!tmp) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(root, sizeof(root), "%s", tmp);
	snprintf(teldir, sizeof(teldir), "%s/telemetry", root);

	/* 1. 造 1 个合法分片（write_telemetry 会自动建目录并重建 index） */
	memset(&row, 0, sizeof(row));
	row.ts_ns = 1000000000LL;
	row.pid = 4242;
	row.category = 1;
	row.severity = 3;
	row.data_len = 1;
	row.data = (const uint8_t *)"x";
	r = as_pq_write_telemetry(root, &row, 1, 0, 65536, NULL);
	CHECK(r == 1, "seed write_telemetry returns 1");
	if (r != 1) {
		rm_rf(root);
		return 1;
	}
	r = find_day_dir(teldir, day, sizeof(day));
	CHECK(r == 0, "find day dir");
	if (r != 0) {
		rm_rf(root);
		return 1;
	}
	snprintf(daydir, sizeof(daydir), "%s/%s", teldir, day);
	r = find_shard(daydir, seedname, sizeof(seedname));
	CHECK(r == 0, "find seed shard");
	if (r != 0) {
		rm_rf(root);
		return 1;
	}
	snprintf(seedpath, sizeof(seedpath), "%s/%s", daydir, seedname);

	/* 2. 复制成 N_SHARDS 个分片（字节复制，不触发任何 writer 逻辑） */
	for (int i = 1; i < N_SHARDS; i++) {
		snprintf(dstpath, sizeof(dstpath), "%s/bulk_%04d.parquet",
			 daydir, i);
		if (copy_file(seedpath, dstpath) != 0) {
			CHECK(0, "copy shard");
			break;
		}
	}

	/* 3. 循环重建 index */
	rss0 = rss_kib();
	{
		double used0 = 0.0, used1 = 0.0;
#if HAVE_MALLINFO2
		struct mallinfo2 mi0 = mallinfo2();
		used0 = (double)mi0.uordblks;
#endif

		for (int i = 0; i < N_ITERS; i++) {
			int rc = as_pq_update_index(root, &sk);

			if (rc != 0) {
				if (fails == 0)
					printf("FAIL: update_index rc=%d "
					       "at iter %d\n", rc, i);
				fails++;
			}
		}
		rss1 = rss_kib();
#if HAVE_MALLINFO2
		{
			struct mallinfo2 mi1 = mallinfo2();

			used1 = (double)mi1.uordblks;
			printf("mallinfo2 uordblks: before=%.0f after=%.0f "
			       "delta=%.0f bytes\n", used0, used1,
			       used1 - used0);
		}
#endif
	}

	printf("update_index: iters=%d shards=%d skipped=%ld\n",
	       N_ITERS, N_SHARDS, sk);
	printf("RSS: before=%ld KiB after=%ld KiB delta=%ld KiB\n",
	       rss0, rss1, rss1 - rss0);
	CHECK(sk == 0, "skipped == 0");
#if defined(__SANITIZE_ADDRESS__)
	printf("ASan build: RSS delta not asserted (LSan authoritative)\n");
#else
	if (rss0 >= 0 && rss1 >= 0)
		CHECK(rss1 - rss0 < RSS_LIMIT_KIB,
		      "RSS delta < 1 MiB over loop");
#endif

	/* 4. 成功路径结果仍正确：index 行数 = 分片数 */
	snprintf(dstpath, sizeof(dstpath), "%s/index.parquet", teldir);
	CHECK(as_pq_file_stats(dstpath, &fs) == 0, "index footer readable");
	CHECK(fs.num_rows == N_SHARDS, "index rows == shards");

	rm_rf(root);
	if (fails == 0) {
		printf("test_update_index_leak: all OK\n");
		return 0;
	}
	printf("test_update_index_leak: %d FAIL(s)\n", fails);
	return 1;
}
