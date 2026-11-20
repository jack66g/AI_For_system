/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_shadow.h - AIPD-M1 影子记录（parquet 33 列）+ 对照 mismatch 滚动窗
 *
 * ================== schema 冻结（Lane-B 合同；设计 §1.4） ==================
 * 文件布局：<PARQUET_DIR>/aipd/<UTC日>/shadow_NNNN.parquet
 *   （NNNN=目录内现有最大序号+1，每次 flush 一个新文件；UTC 日界=
 *    btime+ts_ns/1e9 取 UTC 日期——as_parquet.c 同口径）
 * 列：decisions v3 32 列**同构**（列名/物理类型/逻辑宽度/顺序逐字段
 * 与 as_parquet.c dec_cols 一致）+ 尾加第 33 列 `source`
 * （BYTE_ARRAY/UTF8，值恒 "aipd_shadow"）。
 *   注：dec 第 21 列名亦为 `source`（i8 决策来源枚举，同构保留）；
 *   第 33 列为字符串来源标——按**列位**区分（31 号位前=同构 32 列），
 *   Lane-B 差分/断言按列位读取。
 * 编码：单 row group / PLAIN / snappy 页压缩 / DataPageV1 / OPTIONAL
 * 全 1 def-levels / statistics min-max / 写盘 tmp+fsync+rename 原子
 * （as_parquet.c 同格式面；独立 writer 实现于本目录——不动 aistreamd，
 * as_pq_write_decisions 不适配：固定 decisions.parquet 名+32 列冻结
 * PQ_MAXCOL 上限，见 AIPD-M1-DESIGN §1.4 逃生条款）。
 *
 * 行映射（aip_decision+特征快照 → 32 列；executed=金丝雀实发才 1
 * ——M2 §2.2：canary ack.executed>0 经 feed 参数传入；CANARY_ENABLED=0
 * 恒 0=M1 等价）：
 *   decision_id      ← 本地单调计数器（1 起；M1 本地记录绕开内核
 *                       ai_agent_id 无 AIPD 槽问题，agent_id=0，设计 §0）
 *   trigger_ts       ← 特征向量 ts（ktime 单调 ns）
 *   trigger_event_id ← 特征向量 seq
 *   decision_ts      ← 决策时刻（CLOCK_MONOTONIC ns）
 *   decision_type    ← 决策 action（enum aip_act）
 *   data_0..7        ← lat_ewma_ns / iowait_pct / psi_mem_some /
 *                       cache_misses / valid_bits / stale 位 / rule_idx
 *                       （无命中 -1）/ 0（预留）
 *   exec_ts/outcome_ts/outcome/metric_delta/expected/cost_ns/
 *   side_effect_mask/trace_hi/trace_lo/intent_id/parent_id ← 0（影子未执行）
 *   model_version    ← feed 参数（M2 §4 冻结映射：1=builtin A，
 *                       2=file B——schema 32 列不动）
 *   confidence       ← 100（静态阈值表：确定性的诚实满值）
 *   domain/source(i8)/safety_clamped ← 0
 *   agent_id         ← init 按 conf：CANARY_ENABLED=0 → 0（M1 等价）；
 *                       =1 → AI_AGENT_AIPD=6（M2 §1 uapi 追加后）
 *   value            ← 0.0（L1 评分不适用于影子行）
 *   source(尾列)     ← "aipd_shadow"
 * ==========================================================================
 *
 * ---- 对照 mismatch（滚动窗；语义冻结） ----
 * 对照流：/proc/ai/decisions（proc 源，as_decisions 摄取游标手法：
 * 仅摄取 id>游标 行）或 mock jsonl（{"decision_id":N,"action":A}）。
 * mismatch 判定（M1 冻结合同——时间窗对齐留 M2，台架按此构造双流）：
 *   每条对照记录按到达（升序 id）入窗，与「最新一条影子决策 action」
 *   比对：无影子或 action 不同 = mismatch；相同 = match。
 *   mismatch_pct = 窗内 mismatch / 窗内记录数 × 100（0 记录=0.00，
 *   两位小数）。只读对照——不计入 aistreamd 消费面，不影响其游标。
 */
#ifndef _AIP_SHADOW_H
#define _AIP_SHADOW_H

#include <stddef.h>
#include <stdint.h>

#include "aip_conf.h"
#include "aip_feat.h"
#include "aip_model.h"

#define AIP_SHADOW_NCOL		33	/* 32 dec v3 同构 + source 尾列 */
#define AIP_SHADOW_SOURCE_STR	"aipd_shadow"

struct aip_shadow_row {
	/* decisions v3 32 列同构（顺序=as_parquet.c dec_cols） */
	int64_t decision_id;
	int64_t trigger_ts;
	int64_t trigger_event_id;
	int64_t decision_ts;
	int8_t decision_type;
	int64_t data[8];
	int64_t exec_ts;
	int64_t outcome_ts;
	int8_t outcome;
	int64_t metric_delta;
	int32_t model_version;
	int8_t confidence;
	int8_t domain;
	int8_t source;
	int8_t executed;			/* 恒 0（M1 影子） */
	int8_t safety_clamped;
	int64_t trace_hi, trace_lo, intent_id, parent_id;
	int32_t agent_id;			/* 0：无 AIPD 槽（M1） */
	int64_t expected;
	int64_t cost_ns;
	int32_t side_effect_mask;
	double value;				/* 0.0 */
};

struct aip_shadow {
	int enabled;				/* 恒 1（M1 SHADOW 冻结） */
	char root[256];				/* conf parquet_dir */
	long long flush_sec, flush_rows;
	int32_t agent_id;			/* 行 agent_id 列值（M2：init
						 * 按 conf.canary_enabled
						 * 0|6——§1 AI_AGENT_AIPD） */
	int64_t btime;				/* /proc/stat（<=0=未知） */
	struct aip_shadow_row *buf;
	size_t n, cap;
	unsigned long long next_id;		/* 本地 decision_id 计数器 */
	/* 落盘计数（stats 面） */
	long long rows_written, files, errors, flushes, bytes;
	long long last_flush_mono_ms;
};

/* 初始化（buf 按容量 64 起始分配；enabled 恒 1）。0/-1（内存） */
int aip_shadow_init(struct aip_shadow *s, const struct aip_conf *c);

/*
 * aip_shadow_feed - 影子决策入缓冲（满/到时由主循环调 flush）。
 * 填 row 全列并计数。无返回错误面（内存失败=flush 期丢批计数，诚实）。
 * executed：金丝雀实发置 1（M2 §2.2——canary ack.executed>0 的唯一
 * 传播面；M1 调用方恒传 0）。model_version：1=builtin A / 2=file B
 * （§4 冻结映射）。
 */
void aip_shadow_feed(struct aip_shadow *s, const struct aip_fvec *v,
		     int stale, const struct aip_decision *d,
		     long long decision_ts_ns, int executed,
		     int model_version);

/* flush：缓冲 → <root>/aipd/<日>/shadow_NNNN.parquet（失败计数丢批） */
void aip_shadow_flush(struct aip_shadow *s);

/* 退出路径：尽力 flush + 释放 */
void aip_shadow_close(struct aip_shadow *s);

/* ---- 独立 writer（单测行落盘/计数断言直调） ---- */

/*
 * aip_shadow_write_file - rows[n] 写 path（33 列；tmp+fsync+rename）。
 * 返回 0/-1。btime_sec<=0 时按「写时今天」定日（caller 已定路径时
 * 仅用于列值无关——保留参数以对齐日界口径文档）。
 */
int aip_shadow_write_file(const char *path, const struct aip_shadow_row *rows,
			  size_t n);

/* 影子根下一天目录的下一序号（shadow_NNNN 扫描；测试断言旋转用） */
long aip_shadow_next_seq(const char *root, const char *day);

/* ---- P-56：列名面（重复列名=标准读者拒读的自检/契约访问） ---- */

/*
 * aip_shadow_colname - 第 ci 列（0 基）列名；越界返回 NULL。
 * aip_shadow_cols_unique - 全列名两两互异返回 0，有重名返回 -1。
 * （教训：旧 schema 决策块 int "source" 与尾列 string "source" 撞名，
 * pyarrow read_table 对重复列名直接 ArrowInvalid——E1' 回放断链，
 * T-2 B7 真机实证 11-20。启动期+测试期双用。）
 */
const char *aip_shadow_colname(int ci);
int aip_shadow_ncols(void);
int aip_shadow_cols_unique(void);

/* ---- 对照 mismatch 滚动窗（语义见文件头；纯逻辑） ---- */

struct aip_cmp_ent {
	unsigned long long id;
	int matched;
};

struct aip_cmp {
	struct aip_cmp_ent *ring;
	unsigned cap;			/* 滚动窗容量 */
	unsigned count;			/* 窗内有效记录数 */
	unsigned head;
	uint32_t last_shadow_action;	/* 最新影子决策 action */
	int have_shadow;
	unsigned long long cursor;	/* 对照流摄取游标（max id） */
	int have_cursor;
	long long matched, mismatch;	/* 窗内累计（stats：观测=和） */
};

int aip_cmp_init(struct aip_cmp *m, unsigned window);
void aip_cmp_free(struct aip_cmp *m);

/* 影子决策产出（更新 latest action 面） */
void aip_cmp_shadow(struct aip_cmp *m, uint32_t action);

/* 对照记录到达（id 升序由调用方保证；窗口滚动+判定） */
void aip_cmp_observe(struct aip_cmp *m, unsigned long long id,
		     uint32_t action);

/* 窗内 mismatch 百分比（两位小数精度；0 记录=0.0） */
double aip_cmp_pct(const struct aip_cmp *m);

/* mock 对照行解析：{"decision_id":N,"action":A}；0/-1 坏行 */
int aip_cmp_parse_mock_line(const char *line, unsigned long long *id,
			    uint32_t *action);

/*
 * /proc/ai/decisions 行解析（as_decisions.c as_dec_parse_line 同源
 * 23 字段 sscanf；此处只需 id/type——全字段校验=行有效性判据）。
 * 0/-1 坏行。
 */
int aip_cmp_parse_proc_line(const char *line, unsigned long long *id,
			    uint32_t *type);

#endif /* _AIP_SHADOW_H */
