/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_util.c - 原子写/stats 渲染/单实例 lease（含 fork 锁互斥）
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

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

static int file_eq(const char *path, const char *want)
{
	char buf[512];
	FILE *f = fopen(path, "r");
	size_t n;

	if (!f)
		return 0;
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	return strcmp(buf, want) == 0;
}

int main(void)
{
	struct aip_conf c;
	struct aip_stats st;
	char path[192], tmp[224];
	int lock_fd = -1;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/m1a-util-%d", (int)getpid());
	{
		char cmd[128];

		snprintf(cmd, sizeof(cmd), "mkdir -p %s", tmpdir);
		if (system(cmd) != 0)
			return 2;
	}
	aip_conf_defaults(&c);
	snprintf(c.lock_file, sizeof(c.lock_file), "%s/aipd.lock", tmpdir);
	snprintf(c.pid_file, sizeof(c.pid_file), "%s/aipd.pid", tmpdir);
	snprintf(c.stats_file, sizeof(c.stats_file), "%s/aipd.stats", tmpdir);

	/* ---- 1) 原子写 ---- */
	snprintf(path, sizeof(path), "%s/x.stats", tmpdir);
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	CHECK(aip_write_file_atomic(path, "pid=1\n", 6) == 0,
	      "atomic write ok");
	CHECK(file_eq(path, "pid=1\n"), "content roundtrip");
	CHECK(access(tmp, F_OK) != 0, "no tmp residue");
	CHECK(aip_write_file_atomic(path, "pid=2\n", 6) == 0,
	      "atomic overwrite ok");
	CHECK(file_eq(path, "pid=2\n"), "overwrite content");
	CHECK(aip_write_file_atomic("/nonexistent-dir/x/y", "a", 1) != 0,
	      "bad path write fails");

	/* ---- 2) stats 渲染（固定键序面） ---- */
	aip_stats_init(&st, &c, "/tmp/t.conf");
	CHECK(st.pid == (int)getpid(), "stats pid");
	{
		char *buf = NULL;
		size_t sz = 0;
		FILE *ms;

		st.heartbeat_ts_ms = 123456;
		st.decisions = 7;
		st.mismatch_pct = 12.5;
		ms = open_memstream(&buf, &sz);
		CHECK(ms != NULL, "memstream open");
		if (ms) {
			aip_stats_render(&st, ms);
			fclose(ms);
			CHECK(strstr(buf, "heartbeat_ts_ms=123456") != NULL,
			      "render heartbeat");
			CHECK(strstr(buf, "decisions=7") != NULL,
			      "render decisions");
			CHECK(strstr(buf, "mismatch_pct=12.50") != NULL,
			      "render mismatch_pct");
			CHECK(strstr(buf, "feat_source=map35") != NULL,
			      "render feat_source");
			CHECK(strstr(buf, "table_sha_ok=1") != NULL,
			      "render table check");
			free(buf);
		}
	}
	CHECK(aip_stats_write_file(&st, path) == 0, "stats write file");
	{
		char buf[2048];
		FILE *f = fopen(path, "r");

		CHECK(f != NULL, "stats file readable");
		if (f) {
			size_t n = fread(buf, 1, sizeof(buf) - 1, f);

			buf[n] = '\0';
			fclose(f);
			CHECK(strstr(buf, "heartbeat_ts_ms=") != NULL,
			      "file has heartbeat");
		}
	}

	/* ---- 3) lease：获取/pid 文件/释放/再获取 ---- */
	CHECK(aip_acquire_lease(&c, &lock_fd) == 0, "lease acquire");
	CHECK(lock_fd >= 0, "lock fd");
	{
		char pidbuf[32];
		FILE *f = fopen(c.pid_file, "r");

		CHECK(f != NULL, "pid file written");
		if (f) {
			if (fgets(pidbuf, sizeof(pidbuf), f))
				CHECK(atoi(pidbuf) == (int)getpid(),
				      "pid file pid");
			else
				CHECK(0, "pid file readable content");
			fclose(f);
		}
	}
	/* ---- 4) fork 锁互斥：子进程同锁文件获取必须失败 ---- */
	{
		pid_t p = fork();

		if (p == 0) {
			struct aip_conf cc;
			int fd2 = -1;

			aip_conf_defaults(&cc);
			snprintf(cc.lock_file, sizeof(cc.lock_file),
				 "%s/aipd.lock", tmpdir);
			snprintf(cc.pid_file, sizeof(cc.pid_file),
				 "%s/child.pid", tmpdir);
			/* 子进程 stderr 静音（FATAL 行是预期输出） */
			if (freopen("/dev/null", "w", stderr) == NULL)
				_exit(3);
			if (aip_acquire_lease(&cc, &fd2) == 0) {
				aip_release_lease(&cc, fd2);
				_exit(0);	/* 不该拿到 */
			}
			_exit(1);			/* 预期：拿不到 */
		}
		if (p > 0) {
			int st2 = 0;

			waitpid(p, &st2, 0);
			CHECK(WIFEXITED(st2) && WEXITSTATUS(st2) == 1,
			      "child lease mutual exclusion");
		} else {
			CHECK(0, "fork failed");
		}
	}
	aip_release_lease(&c, lock_fd);
	CHECK(access(c.pid_file, F_OK) != 0, "pid file unlinked on release");
	lock_fd = -1;
	CHECK(aip_acquire_lease(&c, &lock_fd) == 0, "re-acquire after release");
	aip_release_lease(&c, lock_fd);

	{
		char cmd[128];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
		(void)!system(cmd);
	}
	if (fails) {
		printf("test_util: %d failures (%d checks)\n", fails, checks);
		return 1;
	}
	printf("test_util: OK (%d checks)\n", checks);
	return 0;
}
