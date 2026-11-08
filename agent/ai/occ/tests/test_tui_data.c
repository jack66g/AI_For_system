/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_tui_data.c - /tools /trace /lease 读取器（T9c3；夹具对拍）
 *
 * 全部本地夹具（/tmp/occ-c3-data-<pid>），零网络。
 * 覆盖：tools.json 双段分组与字段、坏 JSON 人话、路径 env 覆盖与
 * 显式坏路径响亮失败；trace 文件 mtime 序 + 坏行跳过 + 字段格式 +
 * 缺目录按空；lease valid/expired/revoked 排序 + 符号链接拒收。
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#include "../occ_tui/tui_data.h"

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

static char g_dir[256];

static void put_file(const char *rel, const char *content)
{
	char path[512];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", g_dir, rel);
	f = fopen(path, "w");
	if (!f) {
		printf("FAIL put_file %s\n", path);
		n_fail++;
		return;
	}
	fputs(content, f);
	fclose(f);
}

int main(void)
{
	char err[240];
	char path[512];
	tui_ov_item *items = NULL;
	int n = 0;
	int rc;

	snprintf(g_dir, sizeof(g_dir), "/tmp/occ-c3-data-%d", (int)getpid());
	if (mkdir(g_dir, 0700) != 0) {
		printf("FAIL mkdir %s\n", g_dir);
		return 1;
	}

	/* ================= tools.json ================= */
	put_file("tools.json",
		 "{\"tools\":[{\"name\":\"procfs_read_status\","
		 "\"channel\":\"procfs-read\",\"risk\":\"R\","
		 "\"description\":\"读取状态\"}],"
		 "\"occ_tools\":{\"tools\":[{\"name\":\"read\","
		 "\"channel\":\"occ\",\"risk\":\"R\","
		 "\"description\":\"读取文件\"}]}}");
	snprintf(path, sizeof(path), "%s/tools.json", g_dir);
	err[0] = '\0';
	rc = tui_data_tools_load(path, &items, &n, err, sizeof(err));
	OK(rc == 0, "tools-load");
	OK(n == 4, "tools-count");
	if (rc == 0 && n == 4) {
		OK((items[0].flags & TUI_OV_HEADER) != 0,
		   "tools-hdr-occ");
		OK(strstr(items[0].text, "六件套") != NULL,
		   "tools-hdr-occ-text");
		OK(strcmp(items[1].text, "read") == 0, "tools-occ-item");
		OK(strcmp(items[1].tag, "occ · R") == 0, "tools-occ-tag");
		OK((items[2].flags & TUI_OV_HEADER) != 0,
		   "tools-hdr-main");
		OK(strcmp(items[3].text, "procfs_read_status") == 0,
		   "tools-main-item");
		OK(strcmp(items[3].tag, "procfs-read · R") == 0,
		   "tools-main-tag");
		OK(strstr(items[3].detail, "读取状态") != NULL,
		   "tools-detail");
	}
	tui_data_items_free(items);
	items = NULL;

	/* 坏 JSON → -1 人话 */
	put_file("bad.json", "{not json");
	snprintf(path, sizeof(path), "%s/bad.json", g_dir);
	err[0] = '\0';
	rc = tui_data_tools_load(path, &items, &n, err, sizeof(err));
	OK(rc == -1, "tools-bad-json");
	OK(err[0] != '\0', "tools-bad-err-nonempty");
	tui_data_items_free(items);
	items = NULL;

	/* 路径解析：env 覆盖（显式存在 → 用之；显式坏 → 响亮失败） */
	snprintf(path, sizeof(path), "%s/tools.json", g_dir);
	setenv("AIKERNEL_TOOLS_JSON", path, 1);
	{
		char fp[1024];

		rc = tui_data_tools_path(fp, sizeof(fp));
		OK(rc == 0 && strcmp(fp, path) == 0, "tools-path-env");
		setenv("AIKERNEL_TOOLS_JSON", "/tmp/occ-c3-no-such.json", 1);
		rc = tui_data_tools_path(fp, sizeof(fp));
		OK(rc == -1, "tools-path-env-broken-loud");
	}
	unsetenv("AIKERNEL_TOOLS_JSON");

	/* ================= trace ================= */
	{
		char d[512];
		char p1[560], p2[560];
		struct utimbuf ut;

		snprintf(d, sizeof(d), "%s/trace", g_dir);
		mkdir(d, 0700);
		snprintf(p1, sizeof(p1), "%s/s1.jsonl", d);
		snprintf(p2, sizeof(p2), "%s/s2.jsonl", d);
		put_file("trace/s1.jsonl",
			 "{\"ts\":\"2026-11-07T10:00:00.000+0800\","
			 "\"session\":\"ses_aaaa\",\"tool\":\"read\","
			 "\"rc\":0,\"dur_ms\":5,\"args\":\"x\"}\n"
			 "not json at all\n"
			 "{\"ts\":\"2026-11-07T10:00:01.000+0800\","
			 "\"session\":\"ses_aaaa\",\"tool\":\"write\","
			 "\"rc\":1,\"dur_ms\":7,\"args\":\"y\"}\n");
		put_file("trace/s2.jsonl",
			 "{\"ts\":\"2026-11-07T11:00:00.000+0800\","
			 "\"session\":\"ses_bbbb\",\"tool\":\"bash\","
			 "\"rc\":0,\"dur_ms\":1200,\"args\":\"z\"}\n");
		/* mtime 显式序：s2 更新（同秒写入防 qsort 抖动） */
		ut.actime = time(NULL) - 100;
		ut.modtime = time(NULL) - 100;
		utime(p1, &ut);
		ut.actime = time(NULL);
		ut.modtime = time(NULL);
		utime(p2, &ut);

		err[0] = '\0';
		rc = tui_data_trace_load(d, 200, &items, &n, err,
					 sizeof(err));
		OK(rc == 0, "trace-load");
		OK(n == 3, "trace-count-skip-garbage");
		if (rc == 0 && n == 3) {
			OK(strcmp(items[0].text,
				  "11:00:00 bash rc=0 1200ms") == 0,
			   "trace-newest-first");
			OK(strcmp(items[0].tag, "ses_bbbb") == 0,
			   "trace-tag-session");
			OK(strcmp(items[1].text,
				  "10:00:01 write rc=1 7ms") == 0,
			   "trace-file-order-reversed");
			OK(strcmp(items[2].text,
				  "10:00:00 read rc=0 5ms") == 0,
			   "trace-oldest-last");
		}
		tui_data_items_free(items);
		items = NULL;

		/* max_lines 截断 */
		rc = tui_data_trace_load(d, 2, &items, &n, err,
					 sizeof(err));
		OK(rc == 0 && n == 2, "trace-max-lines");
		tui_data_items_free(items);
		items = NULL;

		/* 缺目录 → 空（0/0） */
		rc = tui_data_trace_load("/tmp/occ-c3-no-trace-dir", 10,
					 &items, &n, err, sizeof(err));
		OK(rc == 0 && n == 0, "trace-missing-dir-empty");
		tui_data_items_free(items);
		items = NULL;
	}

	/* ================= lease ================= */
	{
		char d[512];
		char nows[64];
		long long now = (long long)time(NULL);

		snprintf(d, sizeof(d), "%s/leases", g_dir);
		mkdir(d, 0700);
		snprintf(nows, sizeof(nows), "%lld", now + 3 * 86400);
		{
			char full[512];

			snprintf(full, sizeof(full),
				 "{\"lease_id\":\"L-1\",\"expires_at\":%s,"
				 "\"mission\":\"read procfs\","
				 "\"scope\":[\"procfs-read\",\"sysfs\"]}",
				 nows);
			put_file("leases/L-1.json", full);
		}
		snprintf(nows, sizeof(nows), "%lld", now - 100);
		{
			char full[512];

			snprintf(full, sizeof(full),
				 "{\"lease_id\":\"L-2\",\"expires_at\":%s,"
				 "\"mission\":\"expired op\"}", nows);
			put_file("leases/L-2.json", full);
		}
		snprintf(nows, sizeof(nows), "%lld", now + 86400);
		{
			char full[512];

			snprintf(full, sizeof(full),
				 "{\"lease_id\":\"L-3\",\"expires_at\":%s,"
				 "\"mission\":\"revoked op\"}", nows);
			put_file("leases/L-3.json", full);
		}
		put_file("leases/L-3.revoked", "");
		/* 符号链接伪装（展示级校验拒收） */
		{
			char evil[560], tgt[560];

			snprintf(evil, sizeof(evil), "%s/evil.json", d);
			snprintf(tgt, sizeof(tgt), "%s/L-1.json", d);
			(void)unlink(evil);
			if (symlink(tgt, evil) != 0)
				printf("warn: symlink failed (skip)\n");
		}

		err[0] = '\0';
		rc = tui_data_lease_load(d, &items, &n, err, sizeof(err));
		OK(rc == 0, "lease-load");
		OK(n == 3, "lease-count-symlink-skipped");
		if (rc == 0 && n == 3) {
			OK(strcmp(items[0].tag, "valid") == 0,
			   "lease-order-valid-first");
			OK(strstr(items[0].text, "剩余") != NULL,
			   "lease-remaining");
			OK(strstr(items[0].detail, "read procfs") != NULL,
			   "lease-mission");
			OK(strstr(items[0].detail, "procfs-read") != NULL,
			   "lease-scope");
			OK(strcmp(items[1].tag, "expired") == 0,
			   "lease-expired");
			OK(strstr(items[1].text, "已过期") != NULL,
			   "lease-expired-text");
			OK(strcmp(items[2].tag, "revoked") == 0,
			   "lease-revoked-last");
			OK(strstr(items[2].text, "已撤销") != NULL,
			   "lease-revoked-text");
		}
		tui_data_items_free(items);
		items = NULL;

		/* 缺目录 → 空 */
		rc = tui_data_lease_load("/tmp/occ-c3-no-lease-dir", &items,
					 &n, err, sizeof(err));
		OK(rc == 0 && n == 0, "lease-missing-dir-empty");
		tui_data_items_free(items);
		items = NULL;
	}

	/* 清场 */
	{
		char cmd[512];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir);
		if (system(cmd) != 0)
			printf("warn: cleanup failed\n");
	}

	printf("test_tui_data: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
