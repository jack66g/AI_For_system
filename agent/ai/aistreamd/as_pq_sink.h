/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_pq_sink.h - aistreamd 事件 → Parquet telemetry 落盘缓冲（T8）
 *
 * 事件→行映射（as_event 字段 → telemetry 列，全部显式）：
 *   timestamp_ns ← (ev->ts_real_ms - btime*1000) * 1e6
 *                  （墙钟 ms → 单调 ns；与 REF"内核遥测=monotonic ns"
 *                   语义一致；经 btime 可逆还原墙钟）
 *   pid          ← ev->pid（proc 类事件带；其余 0）
 *   tgid         ← 0（aistreamd 归一化行无 tgid）
 *   cpu          ← 0（同上）
 *   category     ← 流→ai_category 固定映射（见 .c 表；文件名=CAT_NAMES）
 *   event_type   ← 0（0=非内核 ai_event_type——aistreamd 归一化行专用；
 *                   REF 内核记录为 1..103）
 *   severity     ← info=0 warn=1 error=2（as_event severity 字符串）
 *   data_len/data← ev->line 全文（[kern] 前缀起，零脱敏，all-ai 原则）
 *   trace_hi/lo  ← ev->trace_hi/trace_lo（K1 D10 v2 尾 2 列；环境
 *                   事件/聚合行 0）
 *
 * 采样点：去重窗口之后（首条+聚合记录都落盘；与 SME 配额独立——
 * 磁盘增长由 PARQUET_MAX_GB 保留策略约束，不受记忆配额影响）。
 *
 * 节流：FLUSH_SEC 秒或 FLUSH_ROWS 行 flush 一次（每次 flush =
 * as_pq_write_telemetry 一批 → 每类每日一文件+序号旋转，同 REF 语义）。
 *
 * 保留策略（PARQUET_MAX_GB，默认 2）：超限时删最老天目录（UTC 日），
 * 当天目录永不删；删前列名 journal 台账；只删本布局文件（telemetry
 * <cat>_NNNN.parquet / decisions.parquet / chains_*.parquet）——天目录
 * 内存在任何非布局文件则整个目录跳过不删。
 */
#ifndef _AS_PQ_SINK_H
#define _AS_PQ_SINK_H

#include <stddef.h>

#include "as_conf.h"
#include "as_event.h"
#include "as_stats.h"

#define AS_PQ_LINE_MAX	512		/* = AS_LINE_MAX */

struct as_pq_sink {
	int enabled;
	char root[256];
	int64_t btime;			/* 启动时读 /proc/stat；<=0=未知 */
	long long flush_sec;
	long long flush_rows;
	long long max_gb;
	long long retention_days;	/* L1 棒②：raw TTL（conf PARQUET_
					 * RETENTION_DAYS；0=关） */
	long long cur_retention_days;	/* curated TTL（conf CURATED_
					 * RETENTION_DAYS） */
	long long cur_max_gb;		/* curated 独立预算（conf CURATED_
					 * MAX_GB） */
	struct {
		char cat[32];
		long long days;
	} cat_ret[AS_CAT_RET_MAX];	/* per-cat TTL 覆盖（conf
					 * RETENTION_DAYS_<CAT>） */
	int n_cat_ret;
	struct as_stats *stats;		/* 计数直写（单线程） */

	/* 行缓冲（data 内联，无独立堆块） */
	struct as_pq_brow {
		int64_t ts_ns;
		int32_t pid;
		int8_t category;
		int8_t severity;
		uint16_t dlen;
		char data[AS_PQ_LINE_MAX];
		int64_t trace_hi;	/* K1 D10：ev->trace_hi/lo 透传（0:0=无） */
		int64_t trace_lo;
		double value;		/* L1 v3：ev->value 透传（未评=0） */
		int64_t vflags;		/* L1 v3：ev->vflags 位域透传 */
	} *buf;
	size_t n, cap;
};

int as_pq_sink_init(struct as_pq_sink *s, const struct as_conf *c,
		    struct as_stats *st);

/* 单事件入缓冲（enabled=0 时零操作零分配） */
void as_pq_sink_feed(struct as_pq_sink *s, const struct as_event *ev);

/* 缓冲行数（flush 触发判定用） */
static inline size_t as_pq_sink_pending(const struct as_pq_sink *s)
{
	return s->n;
}

/* flush：write_telemetry + 保留策略；失败计数+journal（行丢弃，缓冲清空） */
void as_pq_sink_flush(struct as_pq_sink *s);

/* 保留策略单跑（flush 内部调用；单测可直调） */
void as_pq_retain(struct as_pq_sink *s);

/*
 * as_pq_retain_root - 保留策略核心（root 级；T8 遗留接线：
 * as_decisions 落盘后与本 sink 共用同一规则——telemetry+decisions 链
 * 同一 PARQUET_MAX_GB 预算/同一布局白名单/同一当天不删口径；删除计数
 * 仍记 pq.retained_*（链级统一账目，decisions.* 段不重复计））。
 */
void as_pq_retain_root(const char *root, long long max_gb, int64_t btime,
		       struct as_stats *st);

/*
 * as_pq_retain_cfg / as_pq_retain_root_cfg - L1 棒② 三层保留配置与核心
 * （DATA-L1-DESIGN §2）。raw 层：TTL 先（per-cat 目录级覆盖取更长）
 * 体量预算后（历史语义原样）；curated 层：独立 TTL+独立预算。
 * ttl_days/cur_ttl_days=0 → 该层 TTL 关；cur_max_gb<0 → curated 层
 * 整体跳过（as_pq_retain_root 旧签名包裹路径用——只做 raw 预算，
 * 行为与历史逐字节一致，as_decisions 遗留接线不受影响）。
 */
struct as_pq_retain_cfg {
	long long ttl_days;
	long long max_gb;
	long long cur_ttl_days;
	long long cur_max_gb;
	struct {
		char cat[32];
		long long days;
	} cat_ret[AS_CAT_RET_MAX];
	int n_cat_ret;
};

void as_pq_retain_root_cfg(const char *root,
			   const struct as_pq_retain_cfg *cfg,
			   int64_t btime, struct as_stats *st);

/* 退出路径：flush + 释放 */
void as_pq_sink_close(struct as_pq_sink *s);

#endif /* _AS_PQ_SINK_H */
