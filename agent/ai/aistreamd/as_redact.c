// SPDX-License-Identifier: GPL-2.0
/*
 * as_redact.c - SENSE 遥测脱敏引擎（产生侧实现；设计 SENSE-REDACT-DESIGN §3）
 *
 * off 档零开销承诺：as_redact_level()==OFF 时调用方（as_event.c 构造器）
 * 的快路径直接用原值——本文件的变换函数只在 level!=OFF 时被喂非 pass
 * 策略；pass 策略本身也是恒等拷贝（防御性：即使被误喂也字节不变）。
 */
#include <stdio.h>
#include <string.h>

#include "as_redact.h"

/* ---- 进程级全局（单线程守护；测试可重置） ---- */

static int g_level = AS_REDACT_OFF;
static char g_salt[65];		/* ≤64 字节（as_conf 校验） */
static struct as_redact_stats g_stats;

void as_redact_set(int level, const char *salt)
{
	if (level < AS_REDACT_OFF || level > AS_REDACT_STRICT)
		level = AS_REDACT_OFF;
	g_level = level;
	snprintf(g_salt, sizeof(g_salt), "%s", salt ? salt : "");
	memset(&g_stats, 0, sizeof(g_stats));
}

int as_redact_level(void)
{
	return g_level;
}

struct as_redact_stats *as_redact_stats(void)
{
	return &g_stats;
}

/* ---- hash 基：FNV-1a64(salt || 0x01 || value)（设计 §3.3） ---- */

uint64_t as_redact_fnv64(const char *salt, const char *value)
{
	uint64_t h = 1469598103934665603ULL;	/* FNV offset basis */
	const char *p;

	for (p = salt && *salt ? salt : ""; *p; p++) {
		h ^= (unsigned char)*p;
		h *= 1099511628211ULL;
	}
	h ^= 0x01;			/* 盐/值分隔（无盐也分隔：空盐≠无界） */
	for (p = value ? value : ""; *p; p++) {
		h ^= (unsigned char)*p;
		h *= 1099511628211ULL;
	}
	return h;
}

/* ---- 值级变换 ---- */

static size_t redact_one(char *out, size_t cap, int strat, const char *v)
{
	switch (strat) {
	case AS_R_HASH: {
		char hex[17];
		uint64_t h = as_redact_fnv64(g_salt, v);

		snprintf(hex, sizeof(hex), "%016llx",
			 (unsigned long long)h);
		g_stats.hashed++;
		g_stats.applied++;
		return snprintf(out, cap, "h:%s", hex);
	}
	case AS_R_TRUNC: {
		size_t n = v ? strlen(v) : 0;

		g_stats.truncated++;
		g_stats.applied++;
		/* 前 8 字符 + "~<原长>"；不足 8 原样（仍标注） */
		return snprintf(out, cap, "%.*s~%zu", 8,
				v ? v : "", n);
	}
	case AS_R_MASK:
		g_stats.masked++;
		g_stats.applied++;
		if (v && *v)
			return snprintf(out, cap, "%c***", v[0]);
		return snprintf(out, cap, "***");
	case AS_R_DROP:
		g_stats.dropped++;
		g_stats.applied++;
		return snprintf(out, cap, "-");
	case AS_R_PASS:
	default:
		return snprintf(out, cap, "%s", v ? v : "");
	}
}

size_t as_redact_str(char *out, size_t cap, int strat, const char *value)
{
	return redact_one(out, cap, strat, value);
}

size_t as_redact_int(char *out, size_t cap, int strat, long long value)
{
	char num[32];

	snprintf(num, sizeof(num), "%lld", value);
	return redact_one(out, cap, strat, num);
}

int as_redact_pid_col(int pid)
{
	if (g_level == AS_REDACT_OFF || pid <= 0)
		return pid;
	{
		char num[32];
		uint64_t h;

		snprintf(num, sizeof(num), "%d", pid);
		h = as_redact_fnv64(g_salt, num);
		return (int)(h & 0x7fffffffULL);
	}
}
