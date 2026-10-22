// SPDX-License-Identifier: GPL-2.0
/*
 * test_paste_merge.c - W65 P3-03：NoTTY/TERM=dumb bracketed paste 合并
 *
 * 覆盖：
 *   1. 单行 paste（起止标记同处一行）→ 标记剥离；
 *   2. 多行 paste（起始标记首行、结束标记末行）→ 合并为一条，内部换行
 *      保留，发往 ask 的是 1 个请求而不是 N 个；
 *   3. 无标记普通行原样返回（不改变 TTY 路径行为）；
 *   4. 大粘贴（约 8KB、200 行）仍只产出一条结果。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../shell/repl_paste.h"

static int g_fail;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		g_fail++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

/* 把输入写入临时文件并 rewound，模拟 NoTTY 的 stdin 行流 */
static FILE *mkstream(const char *text)
{
	FILE *fp = tmpfile();

	if (!fp)
		return NULL;
	fputs(text, fp);
	rewind(fp);
	return fp;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("==== test_paste_merge: P3-03 ====\n");

	/* 1. 单行 paste */
	{
		FILE *fp = mkstream("");
		char *first = strdup("hello \033[200~world\033[201~ tail");
		char *out = repl_paste_merge_line(first, fp, 256 * 1024);

		CHECK(out && strcmp(out, "hello world tail") == 0,
		      "单行 paste：标记剥离、正文保留");
		CHECK(out && strstr(out, "\033[200~") == NULL &&
		      strstr(out, "\033[201~") == NULL,
		      "单行 paste：无残留 ESC 标记");
		free(out);
		fclose(fp);
	}

	/* 2. 多行 paste（首行起始标记、末行结束标记） */
	{
		FILE *fp = mkstream("line1\nline2\nline3\033[201~\n");
		char *first = strdup("\033[200~line0");
		char *out = repl_paste_merge_line(first, fp, 256 * 1024);

		CHECK(out && strcmp(out, "line0\nline1\nline2\nline3") == 0,
		      "多行 paste 合并为 1 条（换行保留）");
		CHECK(out && strstr(out, "\033[200~") == NULL &&
		      strstr(out, "\033[201~") == NULL,
		      "多行 paste 无残留标记");
		free(out);
		fclose(fp);
	}

	/* 3. 普通行（无标记）原样 */
	{
		FILE *fp = mkstream("");
		char *first = strdup("uname -a");
		char *out = repl_paste_merge_line(first, fp, 256 * 1024);

		CHECK(out && strcmp(out, "uname -a") == 0,
		      "无标记普通行不变");
		free(out);
		fclose(fp);
	}

	/* 4. 约 8KB / 200 行粘贴 → 一条结果 */
	{
		char input[16384];
		size_t off = 0;
		int i;
		FILE *fp;
		char *first;
		char *out;

		off += (size_t)snprintf(input + off, sizeof(input) - off,
					"\033[200~");
		for (i = 0; i < 200; i++)
			off += (size_t)snprintf(input + off,
						sizeof(input) - off,
						"line-%03d-abcdefghij\n", i);
		snprintf(input + off, sizeof(input) - off, "\033[201~\n");
		fp = mkstream(input + strlen("\033[200~"));
		first = strdup("\033[200~");
		out = repl_paste_merge_line(first, fp, 256 * 1024);
		CHECK(out && strstr(out, "line-000") != NULL &&
		      strstr(out, "line-199") != NULL,
		      "8KB/200 行粘贴合并完成（首尾行均在）");
		CHECK(out && strstr(out, "\033[200~") == NULL &&
		      strstr(out, "\033[201~") == NULL,
		      "大粘贴无残留标记");
		CHECK(out && strlen(out) > 4000,
		      "大粘贴内容未被截断（>4KB）");
		free(out);
		fclose(fp);
	}

	if (g_fail) {
		printf("test_paste_merge: FAIL (%d)\n", g_fail);
		return 1;
	}
	printf("test_paste_merge: ALL PASS\n");
	return 0;
}
