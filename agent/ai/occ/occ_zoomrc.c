/* SPDX-License-Identifier: GPL-2.0 */
/* occ_zoomrc.c - T4 /zoom：fbterm 字号级表 + fbtermrc 编辑（纯函数） */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "occ_tui/tui_lang.h"

#include "occ_zoomrc.h"

const int occ_zoom_sizes[] = { 12, 16, 20, 24, 28, 32, 40, -1 };
const char *const occ_zoom_names[] = { "12", "16", "20", "24",
				       "28", "32", "40" };

static int sizes_n(void)
{
	int n = 0;

	while (occ_zoom_sizes[n] > 0)
		n++;
	return n;
}

int occ_zoom_size(int idx)
{
	if (idx < 0 || idx >= sizes_n())
		return -1;
	return occ_zoom_sizes[idx];
}

int occ_zoom_index(int size)
{
	int i;

	for (i = 0; i < sizes_n(); i++)
		if (occ_zoom_sizes[i] == size)
			return i;
	return -1;
}

int occ_zoom_step(int cur, int dir)
{
	int i, idx = occ_zoom_index(cur);
	int n = sizes_n();

	if (n == 0)
		return -1;
	if (idx < 0) {
		/* 不在表内：折算到最近档再步进 */
		idx = 0;
		for (i = 0; i < n; i++)
			if (occ_zoom_sizes[i] <= cur)
				idx = i;
	}
	idx += (dir > 0) ? 1 : -1;
	if (idx < 0)
		idx = 0;
	if (idx >= n)
		idx = n - 1;
	return idx;
}

static void set_err(char *err, size_t errlen, const char *msg)
{
	if (err && errlen)
		snprintf(err, errlen, "%s", msg);
}

int occ_zoom_edit_fbtermrc(const char *path, int size,
			   char *err, size_t errlen)
{
	char tmp[600];
	FILE *in = NULL, *out = NULL;
	char line[512];
	int found = 0, wlines = 0;
	size_t n;

	if (!path || !path[0] || occ_zoom_index(size) < 0) {
		set_err(err, errlen, L_("字号不在级表内"));
		return -1;
	}
	n = strlen(path);
	if (n + 8 >= sizeof(tmp)) {
		set_err(err, errlen, L_("路径过长"));
		return -1;
	}
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);

	in = fopen(path, "r");
	out = fopen(tmp, "w");
	if (!out) {
		if (in)
			fclose(in);
		set_err(err, errlen, L_("无法写临时文件"));
		return -1;
	}
	if (!in) {
		/* 不存在 → 最小模板（fbterm 默认路径 fontconfig 名） */
		fprintf(out, "# AIKernel occ /zoom 生成（可手改；font-names 支持\n");
		fprintf(out, "# fontconfig 家族名或字体文件绝对路径）\n");
		fprintf(out, "font-names=mono\n");
		fprintf(out, "font-size=%d\n", size);
		wlines = 4;
	} else {
		while (fgets(line, sizeof(line), in)) {
			if (!found &&
			    (strncmp(line, "font-size=", 10) == 0 ||
			     strncmp(line, "#font-size=", 11) == 0)) {
				fprintf(out, "font-size=%d\n", size);
				found = 1;
			} else {
				fputs(line, out);
			}
			wlines++;
		}
		fclose(in);
		if (!found) {
			fprintf(out, "font-size=%d\n", size);
			wlines++;
		}
	}
	if (fflush(out) != 0 || fclose(out) != 0) {
		unlink(tmp);
		set_err(err, errlen, L_("写入失败"));
		return -1;
	}
	if (wlines <= 0) {
		unlink(tmp);
		set_err(err, errlen, L_("空配置"));
		return -1;
	}
	chmod(tmp, 0644);
	if (rename(tmp, path) != 0) {
		unlink(tmp);
		set_err(err, errlen, L_("rename 失败"));
		return -1;
	}
	return 0;
}
