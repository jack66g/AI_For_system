/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_quota.h - 写入配额（lease 的记忆洪泛防护）
 *
 * 三层，全部 conf 可调：
 *   1) 全局速率：滑动 60s 窗口内已写条数 < rate_per_min 才放行；
 *   2) 全局日上限 daily_max（本地日界翻页）；
 *   3) 每路日上限 stream_daily_max。
 * 拒绝时返回原因码（不静默——上层计数 + journal 限频告警）。
 *
 * 纯逻辑、时间注入（now_ms 参数），单测可冻结时间逐事件断言。
 */
#ifndef _AS_QUOTA_H
#define _AS_QUOTA_H

#include "as_conf.h"

enum as_quota_verdict {
	AS_Q_ALLOW = 0,
	AS_Q_DENY_RATE,		/* 全局速率超限 */
	AS_Q_DENY_DAILY,	/* 全局日上限 */
	AS_Q_DENY_STREAM,	/* 每路日上限 */
};

#define AS_QUOTA_RATE_WIN_MS 60000LL

struct as_quota {
	long long rate_per_min;
	long long daily_max;
	long long stream_daily_max;
	/* 滑动窗口时间戳环（容量 = rate_per_min 条） */
	long long *win;
	int win_cap;
	int win_len;
	int win_head;
	/* 日计数（按本地日期翻页） */
	long long day_key;
	long long day_count;
	long long stream_day_count[AS_NSTREAMS];
};

int as_quota_init(struct as_quota *q, long long rate_per_min,
		  long long daily_max, long long stream_daily_max);

void as_quota_free(struct as_quota *q);

/* 判定（不记账，但会修剪窗口内过期时间戳——均摊 O(1)）；
 * now_real_ms 为墙钟毫秒 */
enum as_quota_verdict as_quota_check(struct as_quota *q, int stream_idx,
				     long long now_real_ms);

/* 记账（放行后调用：滑窗入列 + 日计数+1） */
void as_quota_commit(struct as_quota *q, int stream_idx, long long now_real_ms);

const char *as_quota_reason(enum as_quota_verdict v);

#endif /* _AS_QUOTA_H */
