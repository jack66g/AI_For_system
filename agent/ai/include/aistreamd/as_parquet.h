/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_parquet.h - Parquet writer-only（T8：aikd_lib.py 落盘链 C 化）
 *
 * 对齐 REF agent/ai/aikd/aikd_lib.py（alpha.11，只读参考）：
 *   - schema 三套逐字段一致（列名/物理类型/逻辑宽度/顺序）：
 *       telemetry 13 列 / decision 32 列 / index 6 列（见 .c 的 *_cols 表）
 *       K1 D10 append-only v2：telemetry 9->11（尾加 trace_hi/
 *       trace_lo i64，环境事件 0）、decision 23->31（尾加 trace_hi/
 *       trace_lo/intent_id/parent_id i64、agent_id i32、expected i64、
 *       cost_ns i64、side_effect_mask i32）——老行零列值，v1 向量
 *       继续通过=兼容证明（原「零 schema 改动」冻结契约由 K1 升级
 *       为 append-only v2，与 REF aikd_lib.py 双侧同步）。
 *       L1 棒① append-only v3（DATA-L1-DESIGN §1.2）：telemetry
 *       11->13（尾加 value DOUBLE + flags i64）、decision 31->32
 *       （尾加 value DOUBLE——恰达 PQ_MAXCOL=32 上限，再加列须先
 *       扩 PQ_MAXCOL/重构 chunk 数组，写进 .c 注释）。旧文件零迁移
 *       （parquet 按 file schema 自描述；REF 侧差分向量随 v3 列
 *       同步更新=宿主资产）。
 *   - 落盘布局：
 *       telemetry/YYYY-MM-DD/<cat>_NNNN.parquet（序号扫描现有文件递增，
 *       同 REF _next_seq 的 glob 语义）+ telemetry/index.parquet（重建式）
 *       decisions/YYYY-MM-DD/decisions.parquet
 *       decisions/YYYY-MM-DD/chains_YYYY-MM-DD.parquet
 *       （chains 实际写入按日目录内——对齐 REF write_chains 代码行为；
 *       REF 头注释写的 decisions/chains_*.parquet 与其代码不符，
 *       差分以代码行为为准，差异登记 T8-REPORT）
 *   - 日期边界：REF _ts_to_day 用 btime + ts_ns/1e9 再取 **UTC** 日期
 *     （任务书"本地时区"表述与 REF 代码不符；以 REF 代码为准，登记）。
 *     btime 不可用（<=0）时退回"写时今天"（同 REF）。
 *   - 每次调用 = 新文件（写函数不追加旧文件；decisions/chains 同名覆盖）
 *   - 65536 条/文件分块（chunk_max 可调，单测用小值覆盖多块路径）
 *
 * 文件格式（单 row group、PLAIN 编码、snappy 页压缩、DataPageV1、
 * OPTIONAL 列 + 全 1 def-levels、statistics min/max/null_count）：
 * thrift compact 协议手写序列化（仅本模块所需子集，非通用库）。
 *
 * 读路径边界（有意收窄）：仅 footer FileMetaData 统计读取
 * （as_pq_file_stats），服务 index 重建；不读数据页。
 *
 * created_by 如实写自家串（不冒充 parquet-cpp）。
 */
#ifndef _AS_PARQUET_H
#define _AS_PARQUET_H

#include <stddef.h>
#include <stdint.h>

/* ---- 列数（L1 棒①公开：单测/门禁断言 v3 列在） ---- */
#define TEL_NCOL	13		/* K1 v2 9->11；L1 v3 11->13 */
#define DEC_NCOL	32		/* K1 v2 23->31；L1 v3 31->32
					 * （=PQ_MAXCOL 上限，见 .c） */
#define IDX_NCOL	6
#define PQ_MAXCOL	32

/* ---- 行模型（列值语义见 REF schema_*()） ---- */

struct pq_tel_row {
	int64_t ts_ns;		/* CLOCK_MONOTONIC 纳秒（同 REF 遥测语义） */
	int32_t pid;
	int32_t tgid;
	int16_t cpu;
	int8_t category;	/* 1..18 */
	int8_t event_type;
	int8_t severity;
	int16_t data_len;
	const uint8_t *data;	/* 原始字节全量零脱敏（可为 NULL=len0） */
	int64_t trace_hi;	/* K1 D10：统一 trace 高 64 位（环境事件 0） */
	int64_t trace_lo;
	double value;		/* L1 v3：价值评分 [0,1]（未评=0；
				 * DOUBLE 列经 ints 数组按位型传——
				 * 见 .c pq_coldef 注） */
	int64_t flags;		/* L1 v3：AS_VF_* 位域（as_value.h） */
};

struct pq_dec_row {
	int64_t decision_id;
	int64_t trigger_ts;
	int64_t trigger_event_id;
	int64_t decision_ts;
	int8_t decision_type;
	int64_t data[8];	/* data_0..data_7（缺省补 0，同 REF） */
	int64_t exec_ts;
	int64_t outcome_ts;
	int8_t outcome;
	int64_t metric_delta;
	int32_t model_version;
	int8_t confidence;
	int8_t domain;
	int8_t source;
	int8_t executed;
	int8_t safety_clamped;
	/* K1 D10 append-only v2 尾 8 列（老行/无尾巴=0） */
	int64_t trace_hi;
	int64_t trace_lo;
	int64_t intent_id;
	int64_t parent_id;
	int32_t agent_id;
	int64_t expected;
	int64_t cost_ns;
	int32_t side_effect_mask;
};
/* pq_dec_row 不加 value 字段：decisions 尾列 value 由 writer 侧行内
 * 原料现算（as_value_dec_row_score——同名覆盖重写语义下逐行稳定；
 * 口径见 as_value.h 文件头注）。 */

/* 落盘产物统计（字节按写后 st_size 累计） */
struct pq_write_stat {
	long files;
	long long bytes;
};

/* ---- 目录/环境 ---- */

/* 宿主 btime（/proc/stat，秒）；失败 -1 */
int64_t as_pq_btime(void);

/* mkdir -p（root/telemetry、root/decisions、root/models；同 REF ensure_root） */
int as_pq_ensure_root(const char *root);

/*
 * 大类名（CAT_NAMES 对齐 REF：1..18 映射，未知 "cat%02d"）。
 * out 容量 >= 16。
 */
void as_pq_cat_name(int category, char *out, size_t cap);

/*
 * ts_ns（单调）→ YYYY-MM-DD（UTC 日界 = btime + ts_ns/1e9 的 UTC 日期；
 * btime<=0 → 当前 UTC 日期。整数运算，见 .c 注）。
 */
void as_pq_day_from_ts(int64_t ts_ns, int64_t btime_sec, char *out /*11*/);

/* ---- 落盘（对齐 REF write_*；返回写入条数，-1=失败） ---- */

/*
 * as_pq_write_telemetry - 按类别分组（类别升序）、组内按 ts 稳定排序，
 * 写入首条（最小 ts）所在 UTC 日的目录；chunk_max 条/文件分块旋转
 * （每块前重新扫描序号，同 REF）。写后重建 index（total>0 时）。
 * wstat 可 NULL。
 *
 * L1 棒① curated 双写（DATA-L1-DESIGN §1.3）：行 flags 带
 * AS_VF_PROMOTED 的子集镜像到 <root>/curated/<UTC日>/<cat>_NNNN.parquet
 * （直接天目录布局——curated 根无 telemetry 层）+ <root>/curated/
 * index.parquet；节流/旋转（flush 批次/chunk_max/next_seq）与 raw 路
 * 同机制复用。镜像门=as_value_curated_enabled()；镜像失败不坏 raw 路
 * （as_value 计数上报）。直接库调用（flags=0 行）零行为变化。
 */
int as_pq_write_telemetry(const char *root, const struct pq_tel_row *rows,
			  size_t n, int64_t btime_sec, size_t chunk_max,
			  struct pq_write_stat *wstat);

/* 决策表（decision_ts 首条定日；同名覆盖）。
 * L1 v3：尾列 value=as_value_dec_row_score 行内现算；进 promotion 带
 * 的行镜像 <root>/curated/<日>/decisions.parquet（chains 不镜像——
 * 分析视图，主行已镜像；门/失败语义同 telemetry 双写）。 */
int as_pq_write_decisions(const char *root, const struct pq_dec_row *rows,
			  size_t n, int64_t btime_sec,
			  struct pq_write_stat *wstat);

/* 因果链（trigger_ts 首条定日；chains_<date>.parquet 同名覆盖） */
int as_pq_write_chains(const char *root, const struct pq_dec_row *rows,
		       size_t n, int64_t btime_sec,
		       struct pq_write_stat *wstat);

/*
 * as_pq_update_index - 重建 telemetry/index.parquet（对齐 REF：扫描
 * telemetry 每个日子目录下的 *_*.parquet（跳过 index.parquet），行序
 * 按路径字典序
 * （REF 为 readdir 序——行序差异属有意差异，差分按 file 列排序归一）。
 * 每文件统计来自 footer（行数/ts min-max/category max，跨 chunk/row
 * group 合并）；footer 解析失败 → 跳过并计入 *skipped（REF 静默跳过；
 * 此处计数上报）。返回 0/-1。
 */
int as_pq_update_index(const char *root, long *skipped);

/*
 * as_pq_update_index_curated - L1 棒②：重建 curated 层 index
 * （<root>=curated 根；扫描其下每个日子目录的布局文件，语义同上）。
 */
int as_pq_update_index_curated(const char *root, long *skipped);

/* ---- footer 统计读取（index 重建专用；不做数据页读取） ---- */

struct pq_file_stats {
	int64_t num_rows;
	int has_ts;
	int64_t ts_min;		/* timestamp_ns 列 min（无统计=0） */
	int64_t ts_max;
	int has_cat;
	int64_t cat_max;	/* category 列 max（无统计=0） */
	int has_ncols;		/* L1 棒①：root schema num_children 可读 */
	int ncols;		/* 列数（=num_children−1；v3 断言用） */
};

int as_pq_file_stats(const char *path, struct pq_file_stats *out);

#endif /* _AS_PARQUET_H */
