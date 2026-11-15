/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_value.h - L1 棒①：价值评分器 + curated promotion（DATA-L1-DESIGN §1）
 *
 * 公式（SYSTEM-EVOLUTION-PLAN §5.2，线性可配 VALUE_W1..W6）：
 *   value = clamp01(W1·novelty + W2·反差 + W3·纠正 + W4·代价
 *                   + W5·稀有 − W6·重复罚)
 *
 * 分量归一基准（写明在案——所有分量先各自归一到 [0,1] 再加权）：
 *   novelty  = clamp01((digest 首见 ? 1.0 : 0.0) + severity 抬升)
 *              （error=+0.25 / warn=+0.125：已见 digest 的高severity 行
 *               仍有残余新颖度；首见 error 封顶 1）
 *   反差     = |outcome − expected| / (|Δ| + 64) × confidence/100
 *              （半饱和 K=64：Δ=64 → 0.5——覆盖决策枚举差 0..4 的低段
 *               与指标量级差的高段；内核 confidence 0..100 调制——
 *               低置信反差打折）
 *   纠正     = 恒 0（occ 侧用户纠正信号未接入=尾池；v0 如实 0 贡献
 *              + flags 缺失位）
 *   代价     = cost_ns / (cost_ns + 1e7)（半饱和 K=10ms——内核决策
 *              开销百 ns..百 µs 量级，10ms 视作代价显著）
 *   稀有     = 1 / (1 + 计数)：事件路按流计数（流与 telemetry category
 *              1:1 映射，as_pq_sink.c stream_cat）；decisions 路按
 *              agent_id 计数（决策行 cat 恒 18 无稀有信息——稀有轴
 *              换 agent；agent id 模 64 桶计数防无界表，碰撞=近似）
 *   重复罚   = min(1, repeats / 16)（repeats=窗口被合并条数=
 *              merged_count−1；16 次饱和）
 *
 * 两挂点（设计 §1.1）：
 *   - 事件路：on_event 去重后（aistreamd.c）——digest/repeats/
 *     merged_count/severity/cat 计数 → novelty/稀有/重复罚
 *   - decisions 路：decisions_emit——|outcome−expected|/cost_ns/
 *     confidence/agent_id（struct as_event v3 尾巴，as_decisions.c 填）
 *     → 反差/代价（+novelty/稀有照常）
 *
 * 缺原料的项如实 0 贡献 + flags 置对应缺失位（AS_VF_MISS_*）。
 *
 * 纯函数核心（as_value_score——可单测）与接线层（as_value_hook_*，
 * 维护 digest/计数状态并回填 ev->value/vflags）分离。
 *
 * decisions parquet 尾列（v3 32 列）由 writer 侧 as_value_dec_row_score
 * 就行内原料评分：novelty/稀有/重复罚态不在行内=0 贡献（有界确定性
 * ——同名覆盖重写语义下 value 必须逐行稳定，不受运行态漂移影响；
 * telemetry 侧同决策的合成事件行走挂点全量评分，两侧口径差=注释在案）。
 *
 * 模块为纯叶子（无日志/IO；失败经返回值与计数上报）——as_parquet.c
 * （leaf writer）可直链本对象（pq_dump 同）。
 */
#ifndef _AS_VALUE_H
#define _AS_VALUE_H

#include <stdint.h>

#include "as_conf.h"
#include "as_event.h"
#include "aistreamd/as_parquet.h"

/* ---- telemetry v3 flags 位域（尾列 flags，i64） ---- */
#define AS_VF_PROMOTED		(1 << 0)	/* value 进 promotion 带 */
#define AS_VF_DEC_PATH		(1 << 1)	/* 来自 decisions 路（合成事件） */
#define AS_VF_MISS_NOVELTY	(1 << 2)	/* 缺 digest/novelty 原料 */
#define AS_VF_MISS_DIVERGENCE	(1 << 3)	/* 缺 |outcome−expected| 原料 */
#define AS_VF_MISS_CORRECTION	(1 << 4)	/* 纠正信号未接入（v0 恒置） */
#define AS_VF_MISS_COST		(1 << 5)	/* 缺 cost_ns 原料 */
#define AS_VF_MISS_CONFIDENCE	(1 << 6)	/* 缺 confidence 原料 */
#define AS_VF_MISS_RARITY	(1 << 7)	/* 缺稀有态（流/agent 计数） */
#define AS_VF_MISS_REPEAT	(1 << 8)	/* 预留（repeats 恒可导出，现不置） */

/* ---- 权重/阈值（conf VALUE_W1..W6 / VALUE_PROMOTE_MIN/MAX 快照） ---- */

struct as_value_w {
	double w1, w2, w3, w4, w5, w6;	/* novelty/反差/纠正/代价/稀有/重复罚 */
	double promote_min;		/* promotion 带下沿（含） */
	double promote_max;		/* 上沿（含） */
};

/* ---- 纯函数核心入参/出参 ---- */

struct as_value_ev_mat {		/* 事件路原料 */
	uint64_t digest;			/* 0=缺（MISS_NOVELTY） */
	int severity;				/* 0 info / 1 warn / 2 error */
	int stream_idx;				/* 稀有计数轴；<0=缺（MISS_RARITY） */
	int merged_count;			/* 聚合合并总条数（含首条；首条/普通=0） */
};

struct as_value_dec_mat {		/* decisions 路原料（has=0=全缺） */
	int has;
	long long outcome;
	long long expected;
	unsigned long long cost_ns;
	int confidence;				/* 0..100 */
	int agent_id;				/* 稀有计数轴（>=0） */
};

struct as_value_state {			/* 接线层状态（纯函数入参快照） */
	int digest_seen;			/* digest 在近窗口已见 */
	long long stream_count;			/* 该流已评分行数 */
	long long agent_count;			/* 该 agent 已评分行数（dec 路） */
	int rarity_known;			/* 0=稀有态不可用（writer 路）→0 贡献 */
};

struct as_value_out {
	double value;				/* [0,1] */
	int64_t flags;				/* AS_VF_* */
};

/*
 * as_value_score - 纯函数核心（两路通用；缺原料项 0 贡献+缺失位）。
 * ev/dm/st 均 NULL 可（对应分量按缺失处理）。
 */
void as_value_score(const struct as_value_w *w,
		    const struct as_value_ev_mat *ev,
		    const struct as_value_dec_mat *dm,
		    const struct as_value_state *st,
		    struct as_value_out *out);

/* ---- 进程级策略快照（writer 层评分/curated 门；daemon/测试注入） ---- */

/* conf → 快照（权重带校验已由 as_conf 拒坏值；此调用幂等） */
void as_value_conf_init(const struct as_conf *c);

const struct as_value_w *as_value_weights(void);

/* value 进 [promote_min, promote_max]（含端点） */
int as_value_promoted(double value);

/* curated 双写门（CURATED_ENABLED 快照；缺省 1） */
int as_value_curated_enabled(void);

/* writer 侧 curated 镜像计数（rows=成功镜像行数，fails=镜像写失败批数） */
void as_value_curated_counts(long long *rows, long long *fails);

/* writer 层镜像记账（as_parquet.c curated 路回调；ok!=0=成功行数入账，
 * ok==0=失败批计数+nrows 行入失败账） */
void as_value_note_curated(int ok, long long nrows);

/*
 * as_value_dec_row_score - decisions parquet 尾列专用：行内 31 列原料
 * → value（novelty/稀有/重复罚态不在行内=0 贡献；口径见文件头）。
 */
double as_value_dec_row_score(const struct pq_dec_row *r);

/* ---- 接线层（状态 + 挂点回填；aistreamd.c 持实例） ---- */

/* novelty 近窗口 digest 集（boot 期有界环形——非全史，容量权衡在案） */
#define AS_VALUE_NOVELTY_SLOTS	1024
#define AS_VALUE_AGENT_BUCKETS	64

struct as_value_ctx {
	uint64_t digests[AS_VALUE_NOVELTY_SLOTS];
	size_t dig_n, dig_idx;			/* 环形插入游标 */
	long long stream_counts[6];		/* AS_NSTREAMS（稀有计数轴） */
	long long agent_counts[AS_VALUE_AGENT_BUCKETS];
	long long scored;			/* 已评分行数（两路合计） */
	long long promoted;			/* 进带行数 */
};

void as_value_ctx_init(struct as_value_ctx *c);

/*
 * as_value_hook_event - 事件路挂点：维护状态、评分并回填
 * ev->value/ev->vflags。返回 1=promoted（curated 补发门由调用方判）。
 */
int as_value_hook_event(struct as_value_ctx *c, struct as_event *ev);

/*
 * as_value_hook_decision - decisions 路挂点（ev v3 尾巴为原料；
 * 额外置 AS_VF_DEC_PATH）。语义同上。
 */
int as_value_hook_decision(struct as_value_ctx *c, struct as_event *ev);

#endif /* _AS_VALUE_H */
