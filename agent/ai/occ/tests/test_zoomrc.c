/* SPDX-License-Identifier: GPL-2.0 */
/* test_zoomrc.c - T4 /zoom fbtermrc 编辑器单测 */
#define _DEFAULT_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "occ_zoomrc.h"

static int fails;

#define CHECK(cond) do { \
	if (!(cond)) { fails++; \
		printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

static void write_file(const char *p, const char *s)
{
	FILE *f = fopen(p, "w");

	assert(f);
	fputs(s, f);
	fclose(f);
}

static int grep_file(const char *p, const char *needle)
{
	char line[512];
	FILE *f = fopen(p, "r");

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, needle))
			{ fclose(f); return 1; }
	fclose(f);
	return 0;
}

int main(void)
{
	char dir[] = "/tmp/zoomrcXXXXXX";
	char p[256], err[128];

	assert(mkdtemp(dir));
	snprintf(p, sizeof(p), "%s/fbtermrc", dir);

	/* ① 不存在 → 生成模板含 font-size */
	err[0] = '\0';
	CHECK(occ_zoom_edit_fbtermrc(p, 24, err, sizeof(err)) == 0);
	CHECK(grep_file(p, "font-size=24"));
	CHECK(grep_file(p, "font-names="));

	/* ② 已存在 → 改 size 保其余行 */
	write_file(p, "# my header\nfont-names=MyFont\nfont-size=16\n"
		      "color-foreground=15\n");
	CHECK(occ_zoom_edit_fbtermrc(p, 32, err, sizeof(err)) == 0);
	CHECK(grep_file(p, "font-size=32"));
	CHECK(grep_file(p, "font-names=MyFont"));
	CHECK(grep_file(p, "color-foreground=15"));
	CHECK(grep_file(p, "my header"));
	CHECK(!grep_file(p, "font-size=16"));

	/* ③ 无 font-size 行的存量文件 → 追加 */
	write_file(p, "font-names=X\n");
	CHECK(occ_zoom_edit_fbtermrc(p, 12, err, sizeof(err)) == 0);
	CHECK(grep_file(p, "font-size=12"));
	CHECK(grep_file(p, "font-names=X"));

	/* ④ 非法字号拒 */
	CHECK(occ_zoom_edit_fbtermrc(p, 13, err, sizeof(err)) == -1);

	/* ⑤ 级表/步进 */
	CHECK(occ_zoom_size(0) == 12 && occ_zoom_size(6) == 40);
	CHECK(occ_zoom_size(-1) == -1 && occ_zoom_size(7) == -1);
	CHECK(occ_zoom_index(16) == 1 && occ_zoom_index(13) == -1);
	CHECK(occ_zoom_step(16, 1) == 2);
	CHECK(occ_zoom_step(16, -1) == 0);
	CHECK(occ_zoom_step(12, -1) == 0);	/* 下限钳 */
	CHECK(occ_zoom_step(40, 1) == 6);	/* 上限钳 */
	CHECK(occ_zoom_step(18, 1) == 2);	/* 档外折算 */
	unlink(p);
	rmdir(dir);
	if (fails) {
		printf("test_zoomrc: %d FAIL\n", fails);
		return 1;
	}
	printf("test_zoomrc: all ok\n");
	return 0;
}
