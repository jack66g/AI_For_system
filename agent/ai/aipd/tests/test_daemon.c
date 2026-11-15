/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_daemon.c - daemon 冒烟：AIPD_ONCE=1 单轮（aistreamd AS_ONCE 先例）
 * ——锁互斥（daemon 级）/stats 终笔/影子 parquet 落盘/二次起（锁释放）
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
#include "aip_util.h"

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

static void write_conf(const char *path, const char *mock,
		       const char *lock, const char *stats,
		       const char *pidf, const char *root)
{
	FILE *f = fopen(path, "w");

	if (!f) {
		perror("conf write");
		exit(2);
	}
	fprintf(f, "FEAT_SOURCE=mock\n");
	fprintf(f, "FEAT_MOCK_FILE=%s\n", mock);
	fprintf(f, "POLL_HZ=10\n");
	fprintf(f, "STATS_INTERVAL_SEC=1\n");
	fprintf(f, "SHADOW=1\n");
	fprintf(f, "PARQUET_DIR=%s\n", root);
	fprintf(f, "SHADOW_FLUSH_SEC=1\n");
	fprintf(f, "SHADOW_FLUSH_ROWS=1\n");
	fprintf(f, "LOCK_FILE=%s\n", lock);
	fprintf(f, "STATS_FILE=%s\n", stats);
	fprintf(f, "PID_FILE=%s\n", pidf);
	fclose(f);
}

/* 取 stats 文件某 key 的数值；找到=0（val 可 NULL=只判存在） */
static int stats_key(const char *path, const char *key, long long *out)
{
	FILE *f = fopen(path, "r");
	char line[256];
	size_t klen = strlen(key);

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, key, klen) == 0 && line[klen] == '=') {
			if (out)
				*out = atoll(line + klen + 1);
			fclose(f);
			return 0;
		}
	}
	fclose(f);
	return -1;
}

int main(void)
{
	char conf[192], mock[192], lock[192], stats[192], pidf[192];
	char root[192], cmd[512];
	int rc;
	long long val;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/m1a-aipdd-%d", (int)getpid());
	snprintf(conf, sizeof(conf), "%s/aipd.conf", tmpdir);
	snprintf(mock, sizeof(mock), "%s/mock_features.jsonl", tmpdir);
	snprintf(lock, sizeof(lock), "%s/aipd.lock", tmpdir);
	snprintf(stats, sizeof(stats), "%s/aipd.stats", tmpdir);
	snprintf(pidf, sizeof(pidf), "%s/aipd.pid", tmpdir);
	snprintf(root, sizeof(root), "%s/root", tmpdir);
	snprintf(cmd, sizeof(cmd), "rm -rf %s; mkdir -p %s", tmpdir, tmpdir);
	if (system(cmd) != 0)
		return 2;

	/* mock 特征：一条新鲜行（psi 命中→决策非 NONE，影子行有信息量） */
	{
		FILE *f = fopen(mock, "w");

		if (!f)
			return 2;
		fprintf(f, "{\"seq\":1,\"ts\":%llu,\"lat_ewma_ns\":250000,"
			"\"iowait_pct\":12,\"psi_mem_some\":500,"
			"\"cache_misses\":0,\"valid_bits\":7}\n",
			(unsigned long long)now_mono_ns());
		fclose(f);
	}
	write_conf(conf, mock, lock, stats, pidf, root);
	setenv("AIPD_ONCE", "1", 1);

	/* ---- 1) 守护级锁互斥：本测先持锁，daemon 起动必失败 ---- */
	{
		struct aip_conf c;
		int fd = -1;

		aip_conf_defaults(&c);
		snprintf(c.lock_file, sizeof(c.lock_file), "%s", lock);
		snprintf(c.pid_file, sizeof(c.pid_file), "%s/t.pid", tmpdir);
		CHECK(aip_acquire_lease(&c, &fd) == 0, "test holds lease");
		{
			char run[320];

			snprintf(run, sizeof(run),
				 "./aipd --conf %s >/dev/null 2>&1", conf);
			rc = system(run);
			CHECK(rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) != 0,
			      "daemon start rejected while lock held");
		}
		aip_release_lease(&c, fd);
	}

	/* ---- 2) 单轮冒烟：退出 0 + stats 终笔 + 影子 parquet 落盘 ---- */
	{
		char run[320];

		snprintf(run, sizeof(run), "./aipd --conf %s", conf);
		rc = system(run);
		CHECK(rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) == 0,
		      "AIPD_ONCE run exit 0");
	}
	CHECK(access(stats, F_OK) == 0, "final stats written");
	CHECK(stats_key(stats, "decisions", &val) == 0 && val == 1,
	      "decisions==1");
	CHECK(stats_key(stats, "decision_hits", &val) == 0 && val == 1,
	      "decision_hits==1 (psi rule fired)");
	CHECK(stats_key(stats, "feat_stale", &val) == 0 && val == 0,
	      "fresh mock not stale");
	CHECK(stats_key(stats, "heartbeat_ts_ms", &val) == 0 && val > 0,
	      "heartbeat ts present");
	CHECK(stats_key(stats, "shadow_rows", &val) == 0 && val == 1,
	      "shadow_rows==1");
	CHECK(stats_key(stats, "shadow_files", &val) == 0 && val == 1,
	      "shadow_files==1");
	CHECK(stats_key(stats, "mismatch_pct", &val) == 0,
	      "mismatch_pct key present (0.00, compare off)");
	/* 影子文件 footer：行数=1、列数=33 */
	{
		char cmd2[512], out[600];
		FILE *p;

		snprintf(cmd2, sizeof(cmd2),
			 "find %s/aipd -name 'shadow_0001.parquet' 2>/dev/null",
			 root);
		p = popen(cmd2, "r");
		CHECK(p != NULL, "find shadow popen");
		if (p && fgets(out, sizeof(out), p)) {
			struct pq_file_stats fs;

			out[strcspn(out, "\n")] = '\0';
			memset(&fs, 0, sizeof(fs));
			CHECK(as_pq_file_stats(out, &fs) == 0 &&
			      fs.num_rows == 1 && fs.ncols == 33,
			      "shadow parquet rows==1 ncols==33");
		} else {
			CHECK(0, "shadow_0001.parquet exists");
		}
		if (p)
			pclose(p);
	}

	/* ---- 3) 二次起（前次已释放锁）→ shadow_0002 ---- */
	{
		char run[320], f2[600];
		char cmd2[512];
		FILE *p;
		char daydir[512] = "";

		snprintf(run, sizeof(run), "./aipd --conf %s", conf);
		rc = system(run);
		CHECK(rc != -1 && WIFEXITED(rc) && WEXITSTATUS(rc) == 0,
		      "second AIPD_ONCE run exit 0");
		snprintf(cmd2, sizeof(cmd2),
			 "find %s/aipd -mindepth 1 -maxdepth 1 -type d", root);
		p = popen(cmd2, "r");
		if (p) {
			if (fgets(daydir, sizeof(daydir), p))
				daydir[strcspn(daydir, "\n")] = '\0';
			pclose(p);
		}
		snprintf(f2, sizeof(f2), "%s/shadow_0002.parquet", daydir);
		CHECK(daydir[0] && access(f2, F_OK) == 0,
		      "rotation shadow_0002 after second run");
	}
	/* 锁/pid 清净（退出后无残留 pid 文件；锁文件存在但未持） */
	CHECK(access(pidf, F_OK) != 0, "pid file cleaned on exit");

	snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
	(void)!system(cmd);
	if (fails) {
		printf("test_daemon: %d failures (%d checks)\n", fails,
		       checks);
		return 1;
	}
	printf("test_daemon: OK (%d checks)\n", checks);
	return 0;
}
