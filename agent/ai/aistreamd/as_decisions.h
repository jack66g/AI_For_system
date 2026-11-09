/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_decisions.h - T8 遗留：/proc/ai/decisions 消费面（C1 只读轮询）
 *
 * 依据：T8-REPORT §7.2（decisions/chains 数据源待内核轮接线——本棒）
 * + I8-DATA-REPORT §1（VM 实测：ring 最近在前、行格式全解析、
 * /var/lib/aikernel/decisions/ 空未接线）。
 *
 * 语义要点：
 *   1) 数据源：周期读 <root>/proc/ai/decisions（内核
 *      ai_proc_decisions_show：ring 最新在前；行格式 23 字段，
 *      id/trig_ts/trig_evid(0x%04x)/dec_ts/type/data=8 段冒号/exec_ts/
 *      outcome_ts/outcome/delta/ver/conf/domain/src/executed/
 *      safety_clamped——解析 sscanf 与 as_outcome.c 反查同源对齐）。
 *   2) 去重：decision_id 单调递增（同 boot 内），游标=已摄取最大 id，
 *      仅摄取 id>游标 的行；ring 回绕/重启使可见最大 id<游标 →
 *      rebases 计数 + journal（如实：无法区分回绕与重启，boot 级
 *      重接线留 qemu 轮拍板，见 K 轨移交）。
 *   3) 落盘：T8 parquet 链 decisions 行（as_pq_write_decisions，
 *      23 列 schema 与 T8/aikd_lib 逐字段一致——本消费面零 schema
 *      改动）。批语义：有界日批累积（按 id 去重、decision_ts 升序保序，批保留不剪——
 *      晚到同日行并入下次重写，无覆盖丢行窗口）+ 每次写=
 *      decisions/<UTC日>/decisions.parquet 同名覆盖（= REF
 *      write_decisions 语义）；跨日分组各写各的日文件；
 *      DECISIONS_BATCH_MAX 容量满丢最旧+计数（有界内存的如实代价）。
 *      PARQUET_ENABLED=0 时不写文件（write_skipped 计数 + journal
 *      一次性明示），事件路照走。
 *   4) 事件路（既有口径，零新类）：每条新 decision 合成
 *      as_event（stream=event category=decision）→ 既有管道
 *      （as_pq_sink 的 event→ai 映射落 telemetry 链 category=18
 *      ——ai_telemetry.h 18.01 AI_EV_AI_DECISION「决策记录回写 ring」
 *      的守护侧对应物；event_type=0=aistreamd 归一化行专用，
 *      与 outcome 合成事件同口径）+ SME 记忆路（配额/去重自然约束）。
 *      T8 telemetry 9 列 / decision 23 列 schema 均不变（兼容性：
 *      仅按既有 category/event_type 口径新增行，不加列不改类型）。
 *   5) 诚实降级：无内核面（L1 无 AIKernel）→ ENOENT/EACCES 计数
 *      noiface_polls + journal 限频告警，进程不退；坏行跳过计数
 *      bad_lines；id 空洞计 gaps（ring 两轮间覆盖丢失的行）。
 *   6) 开关：DECISIONS_ENABLED 默认 0（出厂默认关——与 HOTPLUG/
 *      OUTCOME/SENSE 新面节奏一致；真内核验证随 ISO 拍板翻，理由
 *      见 aistreamd.conf 注释）。
 *
 * 路径前缀 root：默认 "/"（真内核）；单测/L1 冒烟 mock 树前缀
 * （as_decisions_set_root，同 as_outcome_set_root 手法）。
 */
#ifndef _AS_DECISIONS_H
#define _AS_DECISIONS_H

#include <stddef.h>

#include "as_conf.h"
#include "as_event.h"
#include "as_parquet.h"
#include "as_stats.h"

/* 内核子路径（ai_procfs.c ai_proc_decisions_show；root 前缀拼接） */
#define AS_DEC_SUB		"/proc/ai/decisions"

/* 决策行 → pq_dec_row 行缓冲硬上限（conf DECISIONS_BATCH_MAX 的
 * 解析上界；pq_dec_row ~200B，262144 行 ≈ 50MB 上界） */
#define AS_DEC_BATCH_HARD	262144

/* 扫描行硬上限（conf DECISIONS_SCAN_MAX 的解析上界；内核 ring
 * AI_POLICY_DECISION_RING_SIZE=4096 条，ai_policy.h:106） */
#define AS_DEC_SCAN_HARD	4096

struct as_decisions {
	struct as_conf *conf;
	struct as_stats *stats;
	void (*emit)(struct as_event *ev, void *ud);	/* 合成事件出口 */
	void *emit_ud;
	char root[256];			/* 路径前缀（默认 "/";测试 mock 树） */
	unsigned long long cursor;	/* 已摄取最大 decision_id（游标） */
	int have_cursor;
	struct pq_dec_row *batch;	/* 日批（decision_ts 升序、按 id 去重） */
	size_t n, cap;
	int dirty;			/* 批未落盘标志（flush 判定） */
	long long last_poll_mono_ms;	/* 上次轮询（due 计算） */
	long long last_flush_mono_ms;
	int noiface_warned;		/* ENOENT 一次性 journal（限频兜底） */
};

/* 初始化（batch 按 conf 分配；enabled=0 不分配零开销）。0/-1（内存） */
int as_decisions_init(struct as_decisions *d, struct as_conf *c,
		      struct as_stats *st);

/* 退出路径：尽力 flush + 释放 */
void as_decisions_close(struct as_decisions *d);

/* 测试/mock 钩子：路径前缀（仅测试与 L1 mock 冒烟；生产恒 "/"） */
void as_decisions_set_root(struct as_decisions *d, const char *root);

/* 合成事件出口注册（aistreamd.c 注管道；NULL=不合成） */
void as_decisions_set_sink(struct as_decisions *d,
			   void (*emit)(struct as_event *ev, void *ud),
			   void *ud);

/*
 * as_decisions_tick - 到期轮询（主循环挂接；now_mono_ms 调用方传）。
 * 读 ring → 解析/去重/坏行计数 → 游标推进 → 批累积 → 合成事件 →
 * 按 PARQUET_FLUSH_SEC/PARQUET_FLUSH_ROWS 节流落盘（含保留策略与
 * 跨日分组）。enabled=0 零开销。
 */
void as_decisions_tick(struct as_decisions *d, long long now_mono_ms);

/* 下次轮询还差多久（ms；未启用/无批返回 -1；主循环 poll 超时用） */
long long as_decisions_due_ms(const struct as_decisions *d,
			      long long now_mono_ms);

/* ---- 纯函数（单测冻结口径；与 as_outcome.c 反查解析同源） ---- */

/*
 * as_dec_parse_line - 解析 decisions ring 一行 → 行结构。
 * 0=成功；-1=坏行（调用方计数跳过）。
 */
struct as_dec_row {
	unsigned long long id;
	unsigned long long trig_ts;
	unsigned long long trig_evid;
	unsigned long long dec_ts;
	unsigned type;
	unsigned long long data[8];
	unsigned long long exec_ts;
	unsigned long long outcome_ts;
	unsigned outcome;
	long long delta;
	unsigned ver, conf, domain, src, executed, safety_clamped;
};

int as_dec_parse_line(const char *line, struct as_dec_row *out);

#endif /* _AS_DECISIONS_H */
