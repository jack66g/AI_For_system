/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_stats.h - 每路计数与 stats 文件（A/B 验收的决定性计数）
 *
 * 每路五个计数 + 状态：
 *   received        收到的原始事件数（解析成功即计）
 *   filtered_dedup  去重窗口合并掉的条数（含聚合记录产出后的 repeats 总和
 *                   由聚合记录自身承载，此计数=被抑制条数）
 *   filtered_quota  配额拒绝的条数（速率/日限/每路日限）
 *   written         SME 2xx 写成功条数
 *   buffer_dropped  SME 不可达环形缓冲溢出丢旧条数
 *   state           running | stopped | disabled
 *
 * stats 文件（/run/aistreamd.stats，原子写）格式固定：
 *   行 "key=value"，含每路五行 + 总计 + 运行元信息（uptime/pid/sme_ok/
 *   ring_used/nl_ai_portid 等）+ K3d-2 hotplug.* 计数段。A/B 与 soak
 *   全靠它（hotplug 段为 K3d-2 追加，旧键零位移）。
 */
#ifndef _AS_STATS_H
#define _AS_STATS_H

#include <stdio.h>

#include "as_conf.h"

enum as_stream_state {
	AS_ST_DISABLED = 0,
	AS_ST_RUNNING,
	AS_ST_STOPPED,		/* 打开失败诚实降级 */
};

struct as_stream_stats {
	long long received;
	long long filtered_dedup;
	long long filtered_quota;
	long long written;
	long long buffer_dropped;
	int state;
};

struct as_stats {
	struct as_stream_stats per[AS_NSTREAMS];
	long long written_total;	/* written 之和的缓存（含聚合） */
	long long sme_fail;		/* SME 写失败次数（进环形缓冲的次数） */
	long long sme_flushed;		/* 环形缓冲补写成功条数 */
	int sme_ok;			/* 最近一次写尝试结果 1/0 */
	int nl_ai_portid;		/* NETLINK_AI(mock) socket portid
						 * （注入器定位用；-1=未开） */
	/* K3d-2（I-9）：热插拔建议流水线计数（advisory-only，executed 恒
	 * false——C7 红线；计数是 A/B 验收的决定性口径） */
	struct {
		int enabled;			/* conf HOTPLUG_ENABLED */
		long long seen;			/* 分类进入流水线的事件数 */
		long long infer_ok;		/* 前向成功（sysfs ok + mock） */
		long long infer_timeout;	/* >2s 放弃的事件数 */
		long long infer_skipped;	/* 未配模型/noiface 跳过 */
		long long advisory_written;	/* JSONL 落盘成功条数 */
		long long dropped_noquota;	/* 配额拒绝条数 */
	} hp;
	/* T8：Parquet 落盘计数（stats 文件追加 parquet.* 段，旧键零位移） */
	struct {
		int enabled;			/* conf PARQUET_ENABLED */
		long long btime;		/* 启动读到的 btime（0=未知） */
		long long fed;			/* 入缓冲行数（去重后事件数） */
		long long buffered;		/* 当前待写行数（sink 回写） */
		long long rows_written;		/* 落盘行数 */
		long long files;		/* 落盘文件数 */
		long long bytes;		/* 落盘字节（st_size 计） */
		long long flushes;		/* flush 次数 */
		long long errors;		/* 写失败丢弃行数 */
		long long retained_files;	/* 保留策略删除文件数 */
		long long retained_bytes;	/* 保留策略删除字节 */
	} pq;
	long long started_mono_ms;
	long long started_real_ms;
	int pid;
	char conf_path[256];
	char sme_url[256];
};

void as_stats_init(struct as_stats *st, const struct as_conf *c);

/* conf_path 单独设置（init 时可能尚未解析完） */
void as_stats_set_conf_path(struct as_stats *st, const char *path);

/* 计数帮助：stream_idx 合法性内部钳制 */
void as_stats_received(struct as_stats *st, int idx);
void as_stats_dedup(struct as_stats *st, int idx);
void as_stats_quota(struct as_stats *st, int idx);
void as_stats_written(struct as_stats *st, int idx);

/*
 * as_stats_render - 渲染到 FILE*（固定行序；A/B 解析依赖）。
 */
void as_stats_render(const struct as_stats *st, int ring_used,
		     long long ring_dropped, FILE *out);

/*
 * as_stats_write_file - 渲染并原子写 stats 文件。0/-1。
 */
int as_stats_write_file(const struct as_stats *st, const char *path,
			int ring_used, long long ring_dropped);

#endif /* _AS_STATS_H */
