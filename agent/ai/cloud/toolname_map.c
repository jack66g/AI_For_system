/* SPDX-License-Identifier: GPL-2.0 */
/*
 * toolname_map.c - 云端 API 工具名双向映射实现（W41 bug②）
 *
 * 见 ai_toolname_map.h 契约。实现要点：
 *   - 静态定长表，无堆分配（REPL 单线程，注册表装载期播种一次）；
 *   - seed 重名检测双保险：sanitize 产物撞本注册表任一真实名、
 *     或多条点号名 sanitize 后同形（多对一歧义），均跳过并计数；
 *   - restore 未查中一律透传——存量无点号工具与表外名字零影响。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_toolname_map.h"

struct toolname_entry {
	char real[AI_TOOLNAME_WIRE_MAX + 1];   /* 本名（可含点号） */
	char wire[AI_TOOLNAME_WIRE_MAX + 1];   /* 线缆名（点→下划线） */
};

static struct toolname_entry g_map[AI_TOOLNAME_MAP_MAX];
static int g_map_n;

void ai_toolname_map_reset(void)
{
	memset(g_map, 0, sizeof(g_map));
	g_map_n = 0;
}

static void sanitize_into(const char *name, char *out, size_t outsz)
{
	size_t i;

	for (i = 0; name[i] && i + 1 < outsz; i++)
		out[i] = (name[i] == '.') ? '_' : name[i];
	out[i] = '\0';
}

const char *ai_toolname_sanitize(const char *name, char *buf, size_t bufsz)
{
	if (!name || !name[0])
		return name;
	if (!buf || bufsz == 0)
		return name;
	if (!strchr(name, '.'))
		return name;                    /* 无点号：恒等透传 */
	sanitize_into(name, buf, bufsz);
	return buf;
}

int ai_toolname_map_seed(const char *const *names, int n)
{
	int i, j;
	int skipped = 0;

	if (!names || n <= 0)
		return 0;

	for (i = 0; i < n; i++) {
		char wire[AI_TOOLNAME_WIRE_MAX + 1];
		int collide = 0;

		if (!names[i] || !names[i][0])
			continue;
		if (!strchr(names[i], '.'))
			continue;               /* 无点号：不进表 */

		sanitize_into(names[i], wire, sizeof(wire));

		/* 冲突 1：wire 形态撞本注册表任一真实名（如已有 a_b
		 * 工具时，a.b 无法安全映射） */
		for (j = 0; j < n; j++) {
			if (names[j] && strcmp(names[j], wire) == 0) {
				collide = 1;
				break;
			}
		}
		/* 冲突 2：与已建条目 wire 同形（多对一歧义） */
		for (j = 0; j < g_map_n && !collide; j++) {
			if (strcmp(g_map[j].wire, wire) == 0)
				collide = 1;
		}

		if (collide) {
			skipped++;
			continue;
		}
		if (g_map_n >= AI_TOOLNAME_MAP_MAX) {
			skipped++;
			continue;
		}
		snprintf(g_map[g_map_n].real,
			 sizeof(g_map[g_map_n].real), "%s", names[i]);
		snprintf(g_map[g_map_n].wire,
			 sizeof(g_map[g_map_n].wire), "%s", wire);
		g_map_n++;
	}
	return skipped;
}

int ai_toolname_map_count(void)
{
	return g_map_n;
}

char *ai_toolname_map_restore_alloc(char *name)
{
	int i;

	/* W43: g_map_n==0 no longer short-circuits -- empty seed table is the
	 * common case (registry with no dotted tools); the dotted-name fallback
	 * below must still apply. */
	if (!name || !name[0])
		return name;
	for (i = 0; i < g_map_n; i++) {
		if (strcmp(g_map[i].wire, name) == 0) {
			char *real;

			if (strcmp(g_map[i].real, name) == 0)
				return name;    /* 本名即线缆名（无点号） */
			real = strdup(g_map[i].real);
			if (!real)
				return name;    /* OOM：保留线缆名，不丢指针 */
			free(name);
			return real;
		}
	}
	/* W43: unseeded dotted name -> normalize to underscores and retry
	 * downstream registry lookup (registry remains the final authority;
	 * observed legacy middleware rewriting pure-underscore names back
	 * to dotted form, e.g. memory_search -> memory.search). */
	if (strchr(name, '.')) {
		char *norm = strdup(name);
		size_t j;

		if (!norm)
			return name;
		for (j = 0; norm[j]; j++)
			if (norm[j] == '.')
				norm[j] = '_';
		free(name);
		return norm;
	}
	return name;                            /* 表外：透传 */
}
