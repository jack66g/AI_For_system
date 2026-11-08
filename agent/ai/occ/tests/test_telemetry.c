/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_telemetry.c - T9d §9.6 会话遥测 → T8 parquet 沉淀单测
 *
 * 零真网、零真 LLM（直接调 occ_telemetry_* API）：
 *   1) 节流：turn 行进缓冲不落盘（pending 计数），换窗行触发立即 flush；
 *   2) 落盘：`<root>/telemetry/<UTC 日>/ai_NNNN.parquet` + index.parquet
 *      （T8 目录布局与 CAT_NAMES[18]="ai" 语义）；
 *   3) **读回**：as_pq_file_stats 读 footer FileMetaData 统计——行数、
 *      ts min/max、category max（T8 有意收窄的读面：footer + index，
 *      不读数据页）；index.parquet 同样走 footer 读回；
 *   4) 开关：OCC_PARQUET=off → 拒绝入缓冲。
 */
#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "occ_core/occ_telemetry.h"

#include "aistreamd/as_parquet.h"

static int n_fail;
static int n_ok;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

static char tmpdir[256];
static char parquet_path[600];

/* 递归找 telemetry/ 下的 ai_*.parquet（写在 UTC 日子目录里） */
static int find_ai_parquet(const char *dir, char *out, size_t cap, int *found)
{
	DIR *d = opendir(dir);
	struct dirent *e;

	if (!d)
		return -1;
	while ((e = readdir(d))) {
		char p[560];
		struct stat st;

		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		if (snprintf(p, sizeof(p), "%s/%s", dir, e->d_name) >=
		    (int)sizeof(p))
			continue;
		if (e->d_name[0] == '.' || e->d_type == DT_DIR) {
			if (e->d_type == DT_DIR ||
			    (e->d_type == DT_UNKNOWN && stat(p, &st) == 0 &&
			     S_ISDIR(st.st_mode))) {
				if (find_ai_parquet(p, out, cap, found) != 0) {
					closedir(d);
					return -1;
				}
				if (*found) {
					closedir(d);
					return 0;
				}
			}
			continue;
		}
		if (!strncmp(e->d_name, "ai_", 3) &&
		    strlen(e->d_name) > 8 &&
		    !strcmp(e->d_name + strlen(e->d_name) - 8, ".parquet")) {
			snprintf(out, cap, "%s", p);
			*found = 1;
			closedir(d);
			return 0;
		}
	}
	closedir(d);
	return 0;
}

int main(void)
{
	char url_root[320];
	int found = 0;
	struct pq_file_stats fs;
	struct pq_file_stats ifs;
	char ipath[600];
	int rc;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/occ_pq_t_%d", (int)getpid());
	{
		char cmd[320];

		snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
		if (system(cmd) != 0) {
			/* 尽力清理 */
		}
	}
	if (mkdir(tmpdir, 0755) != 0) {
		printf("mkdir failed\n");
		return 2;
	}
	snprintf(url_root, sizeof(url_root), "%s", tmpdir);
	occ_telemetry_test_set_root(url_root);
	unsetenv("OCC_PARQUET");

	/* ---- 1) 节流语义 ---- */
	OK(occ_telemetry_enabled() == 1, "enabled-by-default");
	OK(occ_telemetry_turn("ses_pq1", 1000, 2, "stop", 0, 0) == 0,
	   "turn-row-1");
	OK(occ_telemetry_turn("ses_pq1", 1400, 4, "tool-calls", 0, 0) == 0,
	   "turn-row-2");
	OK(occ_telemetry_pending() == 2, "pending-buffered");
	found = 0;
	(void)find_ai_parquet(tmpdir, parquet_path, sizeof(parquet_path),
			      &found);
	OK(found == 0, "no-file-before-flush");

	/* ---- 2) 换窗行触发立即 flush ---- */
	OK(occ_telemetry_turn("ses_pq1", 362, 0, "", 1, 512) == 0,
	   "compact-row");
	OK(occ_telemetry_pending() == 0, "flushed-on-compact");

	/* ---- 3) 落盘路径（T8 布局：telemetry/<UTC 日>/ai_NNNN.parquet）---- */
	found = 0;
	rc = find_ai_parquet(tmpdir, parquet_path, sizeof(parquet_path),
			     &found);
	OK(rc == 0 && found == 1, "parquet-file-exists");
	if (found) {
		const char *slash = strrchr(parquet_path, '/');

		OK(slash && strstr(parquet_path, "/telemetry/") != NULL,
		   "path-under-telemetry");
		if (slash)
			OK(strlen(slash + 1) > 12 &&
			   !strncmp(slash + 1, "ai_", 3),
			   "filename-ai-prefix");
		/* ---- 4) 读回：footer 统计（T8 读面）---- */
		memset(&fs, 0, sizeof(fs));
		OK(as_pq_file_stats(parquet_path, &fs) == 0,
		   "footer-read-ok");
		OK(fs.num_rows == 3, "footer-rows-3");
		OK(fs.has_cat && fs.cat_max == OCC_TELEMETRY_CATEGORY,
		   "footer-category-18");
		OK(fs.has_ts && fs.ts_max >= fs.ts_min && fs.ts_max > 0,
		   "footer-ts-range");
	}
	/* index.parquet（重建式，footer 读回） */
	snprintf(ipath, sizeof(ipath), "%s/telemetry/index.parquet",
		 tmpdir);
	{
		struct stat st;

		OK(stat(ipath, &st) == 0 && st.st_size > 0,
		   "index-parquet-exists");
	}
	memset(&ifs, 0, sizeof(ifs));
	{
		struct stat ist;

		OK(stat(ipath, &ist) == 0 && ist.st_size > 0 &&
		   as_pq_file_stats(ipath, &ifs) == 0 &&
		   ifs.num_rows == 1, "index-footer-rows-1");
	}

	/* ---- 5) 缓冲满自动 flush ---- */
	{
		int i;

		for (i = 0; i < OCC_TELEMETRY_BUF_MAX + 5; i++) {
			if (occ_telemetry_turn("ses_pq2", i, 1, "stop", 0,
					       0) != 0)
				break;
		}
		OK(occ_telemetry_pending() > 0 &&
		   occ_telemetry_pending() < OCC_TELEMETRY_BUF_MAX,
		   "buffer-rollover");
		OK(occ_telemetry_flush() >= 0, "manual-flush");
		OK(occ_telemetry_pending() == 0, "flush-empties-buffer");
	}

	/* ---- 6) 开关 ---- */
	setenv("OCC_PARQUET", "off", 1);
	OK(occ_telemetry_enabled() == 0, "disabled-by-env");
	OK(occ_telemetry_turn("ses_pq3", 1, 1, "stop", 0, 0) == -1,
	   "turn-rejected-when-off");
	OK(occ_telemetry_flush() == 0, "flush-noop-when-off");
	unsetenv("OCC_PARQUET");

	occ_telemetry_test_set_root(NULL);
	{
		char cmd[320];

		snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
		if (system(cmd) != 0) {
			/* 尽力清理 */
		}
	}
	printf("test_telemetry: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
