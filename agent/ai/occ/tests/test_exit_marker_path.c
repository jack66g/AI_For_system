/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_exit_marker_path.c - P-2a：退出 marker per-uid 路径/写面单测
 *
 * 路径选择（纯函数直测）：
 *   - uid==0 → /run/aik-occ-exit（P-47 原名，兼容不动）
 *   - uid!=0 → /run/aik-occ-exit.<uid>
 *   - env 显式（测试面）→ 整路径照用（M1-M3 契约不变）
 * 写面：env 桩精确落点；缺省路径 /run 不可写回落 /tmp 同名（非 root
 * 实测路径；root 下直接落 /run 并清场）。
 */
#define _DEFAULT_SOURCE 1		/* mkdtemp/system（严格 c11 的 POSIX 面） */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "occ_exit_marker.h"

static int fails;

#define CHECK(cond) do { \
	if (!(cond)) { fails++; \
		printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

static int fcontent(const char *path, char *buf, size_t cap)
{
	FILE *f = fopen(path, "rb");
	size_t n;

	if (!f)
		return -1;
	n = fread(buf, 1, cap - 1, f);
	fclose(f);
	buf[n] = '\0';
	return (int)n;
}

int main(void)
{
	char buf[320], path_out[320];
	char tmpl[] = "/tmp/occ-p2a-xmk-XXXXXX";
	char stub[340];
	char *dir;

	/* ---- 路径选择 ---- */
	CHECK(strcmp(occ_exit_marker_path(buf, sizeof(buf), 0, NULL),
		     "/run/aik-occ-exit") == 0);
	CHECK(strcmp(occ_exit_marker_path(buf, sizeof(buf), 0, ""),
		     "/run/aik-occ-exit") == 0);
	CHECK(strcmp(occ_exit_marker_path(buf, sizeof(buf), 1000, NULL),
		     "/run/aik-occ-exit.1000") == 0);
	CHECK(strcmp(occ_exit_marker_path(buf, sizeof(buf), 4294967295U, NULL),
		     "/run/aik-occ-exit.4294967295") == 0);
	CHECK(strcmp(occ_exit_marker_path(buf, sizeof(buf), 1000,
					  "/tmp/my-marker"),
		     "/tmp/my-marker") == 0);

	/* ---- 写面：env 桩精确落点 ---- */
	dir = mkdtemp(tmpl);
	CHECK(dir != NULL);
	snprintf(stub, sizeof(stub), "%s/marker", dir);
	unlink(stub);
	path_out[0] = '\0';
	CHECK(occ_exit_marker_write(1000, 71, stub, path_out,
				    sizeof(path_out)) == 0);
	CHECK(strcmp(path_out, stub) == 0);
	{
		char c[64];
		int n = fcontent(stub, c, sizeof(c));

		CHECK(n == 3 && strcmp(c, "71\n") == 0);
	}
	unlink(stub);

	/* ---- 写面：缺省路径（env 未设）按 uid 选路 ---- */
	{
		char run_default[64], tmp_uid[64], run_uid[64];

		snprintf(run_default, sizeof(run_default), "/run/aik-occ-exit");
		snprintf(tmp_uid, sizeof(tmp_uid), "/tmp/aik-occ-exit.%u",
			 (unsigned)geteuid());
		snprintf(run_uid, sizeof(run_uid), "/run/aik-occ-exit.%u",
			 (unsigned)geteuid());
		unlink(run_default);
		unlink(tmp_uid);
		unlink(run_uid);
		path_out[0] = '\0';
		CHECK(occ_exit_marker_write(geteuid(), 71, NULL, path_out,
					    sizeof(path_out)) == 0);
		if (geteuid() == 0) {
			/* root：直落 /run 原名（无后缀） */
			char c[64];

			CHECK(strcmp(path_out, run_default) == 0);
			CHECK(fcontent(run_default, c, sizeof(c)) == 3 &&
			      strcmp(c, "71\n") == 0);
			unlink(run_default);
		} else if (access("/run", W_OK) != 0) {
			/* 非 root 常态：/run 不可写回落 /tmp 带 uid 后缀 */
			char c[64];

			CHECK(strcmp(path_out, tmp_uid) == 0);
			CHECK(fcontent(tmp_uid, c, sizeof(c)) == 3 &&
			      strcmp(c, "71\n") == 0);
			CHECK(access(run_default, F_OK) != 0);
			unlink(tmp_uid);
		} else {
			/* /run 意外可写的非 root：落 /run 带 uid 后缀 */
			char c[64];

			CHECK(strcmp(path_out, run_uid) == 0);
			CHECK(fcontent(run_uid, c, sizeof(c)) == 3 &&
			      strcmp(c, "71\n") == 0);
			CHECK(access(run_default, F_OK) != 0);
			unlink(run_uid);
		}
	}

	/* ---- 写面：写失败诚实 -1（env 桩指不存在目录） ---- */
	CHECK(occ_exit_marker_write(0, 71, "/nonexistent-dir-x/m", path_out,
				    sizeof(path_out)) == -1);

	{
		char cmd[360];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
		if (system(cmd) != 0)
			printf("FAIL cleanup\n");
	}
	if (fails) {
		printf("test_exit_marker_path: %d FAIL\n", fails);
		return 1;
	}
	printf("test_exit_marker_path: all ok\n");
	return 0;
}
