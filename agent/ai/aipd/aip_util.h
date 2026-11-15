/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_util.h - aipd 公共小工具（时间/限频日志/原子写/单实例 lease/
 * stats 渲染——as_util + as_stats 手法克隆，独立文件不动 aistreamd）
 */
#ifndef _AIP_UTIL_H
#define _AIP_UTIL_H

#include <stdio.h>

#include "aip_conf.h"

/* 单调毫秒/纳秒；墙钟毫秒（as_util 同语义） */
long long aip_now_mono_ms(void);
long long aip_now_mono_ns(void);
long long aip_now_real_ms(void);

/*
 * aip_warn_ratelimit - 限频日志（stderr→journald，前缀 "aipd: "）。
 * 同 key cooldown_ms 内只发一条（超限丢并靠 stats 计数，不静默刷屏）。
 * key 为静态字符串字面量。返回 1=已输出 0=被限频。
 */
int aip_warn_ratelimit(const char *key, long long cooldown_ms,
		       const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

/* 普通日志（前缀 "aipd: "）；debug 开关 aip_set_debug */
void aip_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void aip_log_debug(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));
void aip_set_debug(int on);

/* 原子写文件（tmp+rename，全有或全无）；0/-1 */
int aip_write_file_atomic(const char *path, const char *data, size_t len);

/* ---- 单实例 lease（flock + pid 双保险；aistreamd acquire_lock 同手法）----
 * aip_acquire_lease：0=拿到（*lock_fd 持有 fd，pid 文件已写）；
 * -1=失败（他实例持有/IO 错——日志已打）。aip_release_lease 配对。 */
int aip_acquire_lease(const struct aip_conf *c, int *lock_fd);
void aip_release_lease(const struct aip_conf *c, int lock_fd);

/* ---- stats（/run/aipd.stats；字段=主会话门禁口径，含 heartbeat ts） ---- */
struct aip_stats {
	long long started_mono_ms;
	long long started_real_ms;
	int pid;
	char conf_path[256];
	char feat_source[16];		/* map35|mock|mock(degraded) */
	/* 特征面 */
	long long polls, feat_ok, feat_errors, feat_stale, feat_bad_lines;
	long long feat_empty;
	/* 决策面 */
	long long decisions, decision_hits, decisions_stale;
	/* 对照面 */
	long long cmp_total, cmp_mismatch;
	double mismatch_pct;
	/* 影子落盘面 */
	long long shadow_rows, shadow_files, shadow_errors, shadow_flushes;
	/* 表自校验 */
	int table_sha_ok;		/* 1=启动自校验过 */
	long long table_ver;
	long long table_rules;
	/* 心跳（墙钟 ms——失联判据：stats N 秒不更新=不发 ACT；M1 无
	 * ACT 路径，本字段为 M2 心跳语义的预置面+soak 观测口径） */
	long long heartbeat_ts_ms;
};

void aip_stats_init(struct aip_stats *st, const struct aip_conf *c,
		    const char *conf_path);

/* 渲染（固定行序 key=value；A/B 解析依赖） */
void aip_stats_render(const struct aip_stats *st, FILE *out);

/* 渲染+原子写；0/-1 */
int aip_stats_write_file(const struct aip_stats *st, const char *path);

#endif /* _AIP_UTIL_H */
