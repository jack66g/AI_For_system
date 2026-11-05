/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_quota.c - 配额判定与记账（纯逻辑）
 */
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "as_quota.h"

/* 本地日期键（同日同值；跨日必变——用 ymd，tm_yday 在年叠加下也够，但 YMD 最直白） */
static long long day_key_of(long long now_real_ms)
{
	time_t t = (time_t)(now_real_ms / 1000);
	struct tm tm;

	localtime_r(&t, &tm);
	return (long long)(tm.tm_year + 1900) * 10000LL +
	       (tm.tm_mon + 1) * 100LL + tm.tm_mday;
}

/* 日界翻页（跨日清零；只前进不后退） */
static void rollover(struct as_quota *q, long long now_real_ms)
{
	long long k = day_key_of(now_real_ms);

	if (k != q->day_key) {
		q->day_key = k;
		q->day_count = 0;
		memset(q->stream_day_count, 0, sizeof(q->stream_day_count));
	}
}

int as_quota_init(struct as_quota *q, long long rate_per_min,
		  long long daily_max, long long stream_daily_max)
{
	memset(q, 0, sizeof(*q));
	q->rate_per_min = rate_per_min;
	q->daily_max = daily_max;
	q->stream_daily_max = stream_daily_max;
	q->win_head = 0;
	q->win_len = 0;
	q->win_cap = (int)rate_per_min;
	q->win = NULL;
	if (q->win_cap > 0) {
		q->win = malloc(sizeof(long long) * (size_t)q->win_cap);
		if (!q->win)
			return -1;
	}
	q->day_key = -1;
	return 0;
}

void as_quota_free(struct as_quota *q)
{
	free(q->win);
	q->win = NULL;
}

enum as_quota_verdict as_quota_check(struct as_quota *q, int stream_idx,
				     long long now_real_ms)
{
	rollover(q, now_real_ms);
	/* 修剪滑窗头部过期时间戳（均摊 O(1)）；
	 * 修剪后 win_len 即「窗口内已写条数」 */
	while (q->win_len > 0) {
		long long t = q->win[q->win_head];

		if (now_real_ms - t < AS_QUOTA_RATE_WIN_MS)
			break;
		q->win_head = (q->win_head + 1) % q->win_cap;
		q->win_len--;
	}
	if (q->win_len >= q->rate_per_min)
		return AS_Q_DENY_RATE;
	if (q->day_count >= q->daily_max)
		return AS_Q_DENY_DAILY;
	if (stream_idx >= 0 && stream_idx < AS_NSTREAMS &&
	    q->stream_day_count[stream_idx] >= q->stream_daily_max)
		return AS_Q_DENY_STREAM;
	return AS_Q_ALLOW;
}

void as_quota_commit(struct as_quota *q, int stream_idx, long long now_real_ms)
{
	rollover(q, now_real_ms);
	if (q->win_cap > 0) {
		if (q->win_len < q->win_cap) {
			q->win[(q->win_head + q->win_len) % q->win_cap] =
				now_real_ms;
			q->win_len++;
		} else {
			/* 环满（理论不可达：check 先拒绝）；防御性覆盖最旧 */
			q->win[q->win_head] = now_real_ms;
			q->win_head = (q->win_head + 1) % q->win_cap;
		}
	}
	q->day_count++;
	if (stream_idx >= 0 && stream_idx < AS_NSTREAMS)
		q->stream_day_count[stream_idx]++;
}

const char *as_quota_reason(enum as_quota_verdict v)
{
	switch (v) {
	case AS_Q_ALLOW:		return "allow";
	case AS_Q_DENY_RATE:		return "rate_per_min exceeded";
	case AS_Q_DENY_DAILY:		return "daily_max exceeded";
	case AS_Q_DENY_STREAM:		return "stream_daily_max exceeded";
	}
	return "?";
}
