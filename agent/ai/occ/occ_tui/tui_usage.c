/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_usage.c - token 水位纯函数实现（T9c3）
 *
 * pct 走整数半数进位：(tokens*100 + limit/2) / limit——正数域精确，
 * 无 double 边界抖动（69.5→70、89.5→90 的验收断言可复现）。
 */
#include "tui_usage.h"

#include <stdio.h>

int tui_usage_pct(long long tokens, long long limit)
{
	if (limit <= 0 || tokens < 0)
		return -1;
	return (int)((tokens * 100 + limit / 2) / limit);
}

int tui_usage_tier(int pct)
{
	if (pct >= 90)
		return 2;
	if (pct >= 70)
		return 1;
	return 0;
}

void tui_usage_fmt(long long v, char *buf, size_t cap)
{
	if (!buf || !cap)
		return;
	if (v >= 1000000)
		snprintf(buf, cap, "%.1fM", (double)v / 1000000.0);
	else if (v >= 1000) {
		if (v % 1000 == 0)
			snprintf(buf, cap, "%lldk", v / 1000);
		else
			snprintf(buf, cap, "%.1fk", (double)v / 1000.0);
	} else {
		snprintf(buf, cap, "%lld", v);
	}
}

long long tui_usage_ctx(long long in, long long out, long long cr,
			long long cw, long long rea)
{
	long long s = 0;

	s += in > 0 ? in : 0;
	s += out > 0 ? out : 0;
	s += cr > 0 ? cr : 0;
	s += cw > 0 ? cw : 0;
	s += rea > 0 ? rea : 0;
	return s;
}

void tui_usage_items(char *buf, size_t cap, long long in, long long out,
		     long long cache, long long rea, int est)
{
	char si[24], so[24], sc[24], sr[24];
	int n;

	if (!buf || !cap)
		return;
	tui_usage_fmt(in > 0 ? in : 0, si, sizeof(si));
	tui_usage_fmt(out > 0 ? out : 0, so, sizeof(so));
	tui_usage_fmt(cache > 0 ? cache : 0, sc, sizeof(sc));
	if (rea < 0)
		snprintf(sr, sizeof(sr), "–");
	else
		tui_usage_fmt(rea, sr, sizeof(sr));
	n = snprintf(buf, cap, "%si%s o%s c%s r%s", est ? "~" : "",
		     si, so, sc, sr);
	if (n < 0)
		buf[0] = '\0';
}
