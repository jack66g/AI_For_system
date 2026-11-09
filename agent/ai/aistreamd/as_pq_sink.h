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
	struct as_stats *stats;		/* 计数直写（单线程） */

	/* 行缓冲（data 内联，无独立堆块） */
	struct as_pq_brow {
		int64_t ts_ns;
		int32_t pid;
		int8_t category;
		int8_t severity;
		uint16_t dlen;
		char data[AS_PQ_LINE_MAX];
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

/* 退出路径：flush + 释放 */
void as_pq_sink_close(struct as_pq_sink *s);

#endif /* _AS_PQ_SINK_H */
