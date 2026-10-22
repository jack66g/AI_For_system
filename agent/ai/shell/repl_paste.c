// SPDX-License-Identifier: GPL-2.0
/*
 * repl_paste.c - bracketed paste 标记剥离与连续行合并（W65 P3-03）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "repl_paste.h"

#define PASTE_START "\033[200~"
#define PASTE_END   "\033[201~"

/* 去掉所有 paste 标记；saw_start 与 saw_end 记录是否出现 */
static char *paste_strip(const char *src, int *saw_start, int *saw_end)
{
	size_t cap = strlen(src) + 1;
	char *out = malloc(cap);
	size_t o = 0;
	const char *p = src;
	const size_t sl = strlen(PASTE_START);
	const size_t el = strlen(PASTE_END);

	if (!out)
		return NULL;
	while (*p) {
		if (strncmp(p, PASTE_START, sl) == 0) {
			*saw_start = 1;
			p += sl;
			continue;
		}
		if (strncmp(p, PASTE_END, el) == 0) {
			*saw_end = 1;
			p += el;
			continue;
		}
		out[o++] = *p++;
	}
	out[o] = '\0';
	return out;
}

static void strip_eol(char *s)
{
	size_t n = strlen(s);

	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
		s[--n] = '\0';
}

char *repl_paste_merge_line(char *first, FILE *in, size_t max_bytes)
{
	int saw_start = 0, saw_end = 0;
	char *out;
	char *clean;
	size_t out_len;

	if (!first)
		return NULL;
	clean = paste_strip(first, &saw_start, &saw_end);
	if (!clean) {
		/* 内存失败：至少把标记从原串就地删掉，保证不把 ESC 序列
		 * 当用户问题发给模型。 */
		char *p;

		while ((p = strstr(first, PASTE_START)) != NULL)
			memmove(p, p + strlen(PASTE_START),
				strlen(p + strlen(PASTE_START)) + 1);
		while ((p = strstr(first, PASTE_END)) != NULL)
			memmove(p, p + strlen(PASTE_END),
				strlen(p + strlen(PASTE_END)) + 1);
		return first;
	}
	free(first);
	out = clean;
	out_len = strlen(out);

	if (!saw_start || saw_end || !in)
		return out;

	/* 起始标记已见、结束标记未到：继续读 stdin（NoTTY 的 fgets 同源），
	 * 用换行合并为一次输入。 */
	for (;;) {
		char *line = NULL;
		size_t lcap = 0;
		ssize_t n = getline(&line, &lcap, in);

		if (n < 0) {
			free(line);
			break;
		}
		strip_eol(line);
		{
			int s2 = 0, e2 = 0;
			char *part = paste_strip(line, &s2, &e2);

			free(line);
			if (!part)
				break;
			{
				size_t pl = strlen(part);
				char *merged;

				if (out_len + 1 + pl + 1 > max_bytes) {
					free(part);
					break;
				}
				merged = realloc(out, out_len + 1 + pl + 1);
				if (!merged) {
					free(part);
					break;
				}
				out = merged;
				out[out_len++] = '\n';
				memcpy(out + out_len, part, pl + 1);
				out_len += pl;
				free(part);
			}
			if (e2) {
				saw_end = 1;
				break;
			}
		}
	}
	return out;
}
