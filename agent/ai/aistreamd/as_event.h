/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_event.h - 事件规范化（每事件 → 一行人可读文本 + digest + 元数据）
 *
 * 一行文本格式（冻结，勿改；改动=破坏 A/B 与检索语料）：
 *   [kern] <stream> <category> <k=v ...>
 * 例：
 *   [kern] proc fork parent=1 child=42
 *   [kern] event policy decision_id=4711 executed=2 param=mm.swappiness
 * 去重聚合记录在行尾追加 " repeats=<N>"（N=窗口内被合并的重复条数，
 * 即该 digest 共出现 N+1 次，首条已单独写入）。
 *
 * digest = FNV-1a64("<stream>\0<category>\0<line>")（16 hex）。
 *
 * severity ∈ {info, warn, error}；决策事件（event/policy）的 decision_id
 * 原样透传（审计链关键，规格 K3-DESIGN §K3c）。
 */
#ifndef _AS_EVENT_H
#define _AS_EVENT_H

#include <stdint.h>

#include "as_conf.h"

#define AS_LINE_MAX 512

struct as_event {
	long long ts_real_ms;		/* 墙钟 epoch 毫秒 */
	int stream_idx;			/* AS 流下标 */
	int pid;			/* 事件主体 pid（T8 Parquet pid 列源；
					 * proc 类构造器填，无主体=0；行文本
					 * 格式不受影响——冻结不动） */
	const char *stream;		/* 静态字面量 */
	const char *category;		/* 静态字面量 */
	const char *severity;		/* info/warn/error */
	char line[AS_LINE_MAX];		/* 一行文本（不含 repeats 后缀） */
	uint64_t digest;
	char digest_hex[17];
	int has_decision_id;		/* event/policy 专属 */
	unsigned long long decision_id;
	int merged_count;		/* 聚合记录专用：合并总条数（含首条）；
					 * 普通事件为 0 */
};

/* 流名 → 下标（未知返回 -1） */
int as_stream_idx(const char *name);
const char *as_stream_name(int idx);

/*
 * as_event_mk - 公共构造（vsnprintf 组装 k=v 部分）。
 * severity 传 NULL → "info"。
 */
void as_event_mk(struct as_event *ev, int stream_idx, const char *category,
		 const char *severity, const char *kvfmt, ...)
	__attribute__((format(printf, 5, 6)));

/* ---- 各流规范化构造（SENSE_REDACT=off（出厂默认）下=纯函数，单测
 * 冻结 fixture 逐字节比对；soft/strict 下身份/内容字段先过 as_redact
 * 策略表（设计 SENSE-REDACT-DESIGN §2.2）再拼行——行格式（键名/键序）
 * 不变，仅字段值变换；decision_id 恒原样（审计链例外）；ev->pid 列同
 * 步脱敏（as_redact_pid_col）） ---- */

void as_event_proc_fork(struct as_event *ev, int ppid, int pid);
void as_event_proc_exec(struct as_event *ev, int pid);
void as_event_proc_exit(struct as_event *ev, int pid, unsigned code);
void as_event_proc_comm(struct as_event *ev, int pid, const char *comm);
void as_event_proc_id(struct as_event *ev, const char *what, int pid,
		      unsigned from, unsigned to);
void as_event_proc_other(struct as_event *ev, int what, int pid);

/* AI 异步事件：category=1 policy（decision_id=event_id）；
 * category=2 model（code 1=load 0=unload，event_id=model id）；
 * K3d-2（I-9）热插拔追加契约（EVENT 通道 AI_NL_EV_* 空间只追加——
 * 现 uapi 只到 2；3/4/5 为本流水线与未来内核 glue 的约定值，L1 经
 * K3c mock 通道注入，qemu 收口轮正式化）：
 *   category=3 device（code 0=probe 1=remove，param=dev 名，16.01 对齐）
 *   category=4 cpuhp（code 1=online 0=offline，param=cpu 号，01.07 对齐）
 *   category=5 mce（param="cpu,bank"，16.03 对齐） */
void as_event_ai_policy(struct as_event *ev, unsigned long long decision_id,
			int executed, const char *sev, const char *param);
/* I-10：outcome 回填合成事件（as_outcome 写口成功后经既有管道走
 * SME 记忆 + T8 parquet telemetry；行格式冻结：
 * "[kern] event outcome decision_id=%llu outcome=%s delta=%lld knob=%s"） */
void as_event_outcome(struct as_event *ev, unsigned long long decision_id,
		      int outcome, long long delta, const char *knob);
/* T8 遗留接线：decisions 消费合成事件（as_decisions 游标去重后每条新
 * 决策一行；与内核 ai_telemetry.h 18.01 AI_EV_AI_DECISION「决策记录回写
 * ring」对应——telemetry 链 category=18/event_type=0（aistreamd 归一化行
 * 专用，与 outcome 合成事件同口径，零新类）；行格式冻结：
 * "[kern] event decision decision_id=%llu type=%u domain=%u executed=%u
 *  safety_clamped=%u outcome=%u delta=%lld" */
void as_event_decision(struct as_event *ev, unsigned long long decision_id,
		       unsigned type, unsigned domain, unsigned executed,
		       unsigned safety_clamped, unsigned outcome,
		       long long delta);

void as_event_ai_model(struct as_event *ev, unsigned long long model_id,
		       int loaded, const char *name);
void as_event_ai_device(struct as_event *ev, int removed, const char *dev);
void as_event_ai_cpu(struct as_event *ev, int online, int cpu);
void as_event_ai_mce(struct as_event *ev, int cpu, int bank,
		     const char *sev);

void as_event_net_link(struct as_event *ev, int is_new, int ifindex,
		       const char *name, unsigned flags);
void as_event_net_addr(struct as_event *ev, int is_new, const char *family,
		       const char *addr, unsigned plen, int ifindex);
void as_event_net_route(struct as_event *ev, int is_new, const char *family,
			const char *dst, unsigned plen, int oif,
			const char *gw /* 可 NULL */);
void as_event_uevent(struct as_event *ev, const char *action,
		     const char *devpath, const char *subsystem);
void as_event_nflog(struct as_event *ev, unsigned hook, unsigned mark,
		    const char *prefix /* 可 NULL */, int has_uid,
		    unsigned uid);
void as_event_taskstats(struct as_event *ev, int n_pids,
			double cpu_delay_ms, double blkio_delay_ms,
			unsigned long long swapin_count);

/* ---- 去重窗口 ---- */

enum as_dedup_verdict {
	AS_DEDUP_PASS = 0,	/* 首见：放行（立即写，保 <5s 端到端） */
	AS_DEDUP_SUPPRESS = 1,	/* 窗口内重复：计数不写 */
};

struct as_dedup_entry {
	uint64_t digest;
	long long window_end_ms;
	long long suppressed;	/* 窗口内被合并条数 */
	int stream_idx;
	int pid;		/* 首见事件主体 pid（聚合记录透传，T8） */
	char category[24];
	char severity[8];
	char line[AS_LINE_MAX];
	int has_decision_id;
	unsigned long long decision_id;
	int used;
};

#define AS_DEDUP_SLOTS 256

struct as_dedup {
	struct as_dedup_entry slots[AS_DEDUP_SLOTS];
	long long window_ms;
};

void as_dedup_init(struct as_dedup *d, long long window_ms);

/*
 * as_dedup_filter - 首见/窗口判定。
 * PASS 时同时登记窗口（复制 ev 关键字段）；窗口过期后同 digest 再现
 * 视作新窗口首见。
 */
enum as_dedup_verdict as_dedup_filter(struct as_dedup *d,
				      const struct as_event *ev,
				      long long now_real_ms);

/*
 * as_dedup_flush - 窗口到期且 suppressed>0 的条目产出聚合事件
 * （line + " repeats=N"，merged_count=N+1），交回调写入（走配额，不走
 * 去重），随后条目回收。
 */
void as_dedup_flush(struct as_dedup *d, long long now_real_ms,
		    void (*emit)(struct as_event *agg, void *u), void *u);

#endif /* _AS_EVENT_H */
