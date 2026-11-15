/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_model.h - AIPD-M1 决策模型面：表 schema 冻结 + 纯函数决策入口
 *
 * 冻结契约（Lane-B 生成器 gen_aip_table.py 必须逐字节遵循本文件；
 * AIPD-M1-DESIGN §1.3/§3——schema 在本头文件冻结，改 schema=改契约，
 * 须过主会话拍板升 AIP_TABLE_VER）：
 *
 * 1) 特征枚举 enum aip_feat——ai_feature_vec 字段的序访问面；
 * 2) 规则 struct ai_rule——定长可序列化（见下序列化格式）；
 * 3) 决策合同 aip_decide：按序首命中单出 + 每规则命中计数（详下）；
 * 4) 表版本宏 AIP_TABLE_VER + 规则集 sha256 自校验（序列化格式见
 *    aip_table.h「生成器合同」——sha256 手写实现于 aip_table.c，
 *    生成器必须同算法同序列化）。
 *
 * M1 影子语义（设计 §0）：aipd 决策**只产影子记录，绝无 ACT 下发
 * 代码路径**（executed 恒 0；无任何 NETLINK_AI ACT 调用）。M2 才
 * 追加下发与金丝雀。
 */
#ifndef _AIP_MODEL_H
#define _AIP_MODEL_H

#include <stddef.h>
#include <stdint.h>

/* 前向声明（定义于 aip_feat.h——48B 冻结镜像；此处只需不完整类型） */
struct aip_fvec;

/* ---- 表版本（生成器产物与加载器共同声明；改 schema 必升版） ---- */
#define AIP_TABLE_VER		1u

/* 规则 reason 文案定长（NUL 结尾，不足补 '\0'；UTF-8） */
#define AIP_REASON_MAX		96
/* 规则数上界（生成器产物与加载校验的解析上界） */
#define AIP_RULES_MAX		64

/* ---- 特征枚举（对应 struct aip_fvec 字段；值=冻结 ABI，勿复排） ---- */
enum aip_feat {
	AIP_F_SEQ = 0,		/* u64 采样序号 */
	AIP_F_TS,		/* u64 采样时刻（ktime_get_ns，单调域） */
	AIP_F_LAT_EWMA_NS,	/* u64 sched latency EWMA（ns） */
	AIP_F_IOWAIT_PCT,	/* u32 iowait 百分比 0..100 */
	AIP_F_PSI_MEM_SOME,	/* u32 PSI mem some avg10 定点 0..2048
				 * （×100/2048=%，见 ai_features.h） */
	AIP_F_CACHE_MISSES,	/* u64 v1 恒 0 */
	AIP_F_VALID_BITS,	/* u32 AI_FEAT_VALID_* 掩码 */
	AIP_FEAT_MAX
};

/* valid_bits 位（镜像 senses/ai_features.h——冻结契约） */
#define AIP_VALID_LAT		(1u << 0)
#define AIP_VALID_IOWAIT	(1u << 1)
#define AIP_VALID_PSI		(1u << 2)
#define AIP_VALID_CACHE		(1u << 3)

/* ---- 动作建议 id（影子记录 decision_type 列；M1 只建议不下发） ---- */
enum aip_act {
	AIP_ACT_NONE = 0,		/* 无命中 */
	AIP_ACT_RECLAIM_AGGRESSIVE = 1, /* psi_mem_some 高→建议 reclaim 激进度↑ */
	AIP_ACT_SCHED_COMPENSATE = 2,	/* lat_ewma_ns 高→建议调度补偿 */
	AIP_ACT_READAHEAD_BOOST = 3,	/* iowait_pct 高→建议 readahead↑ */
};

/* ---- 阈值比较算子 ---- */
enum aip_op {
	AIP_OP_IN_RANGE = 0,	/* lo <= x <= hi 命中 */
	AIP_OP_GT,		/* x > lo 命中（hi 忽略，表内恒置 0） */
};

/*
 * struct ai_rule - 静态阈值规则（编译期查找表元素；冻结 schema）
 *
 * 序列化定长 128 字节/条（生成器合同，见 aip_table.h）。
 */
struct ai_rule {
	uint32_t feat;			/* enum aip_feat */
	uint32_t op;			/* enum aip_op */
	int64_t lo;			/* 下界（GT 语义严格大于） */
	int64_t hi;			/* 上界（仅 IN_RANGE 用） */
	uint32_t action;		/* enum aip_act 动作建议 id */
	int32_t param;			/* 动作参数（语义随 action，见表注释） */
	char reason[AIP_REASON_MAX];	/* 「因为」文案（影子记录人读面） */
};

/* 决策输出 flags */
#define AIP_DF_HIT		(1u << 0)	/* 命中任一规则 */
/* AIP_DF_STALE（1u<<1）由调用方按特征新鲜度补 OR（aip_decide 纯决定，
 * 不感知采样期）——aipd 主循环置位；影子行落盘。 */
#define AIP_DF_STALE		(1u << 1)

struct aip_decision {
	int64_t rule_idx;		/* 首命中规则下标；-1=无命中 */
	uint32_t action;		/* enum aip_act（无命中=NONE） */
	int32_t param;			/* 命中规则参数（无命中 0） */
	int64_t feat_val;		/* 命中规则的特征取值（无命中 0） */
	uint32_t flags;			/* AIP_DF_* */
	char reason[AIP_REASON_MAX];	/* 命中规则文案（无命中空串） */
};

/* ---- 特征取值/可信门（纯函数，单测冻结口径） ---- */

/* 按枚举取 ai_feature_vec 字段值（u32 字段零扩成 int64）。
 * feat 非法返回 -1 且 *out 不动。 */
int aip_feat_value(const struct aip_fvec *v, uint32_t feat, int64_t *out);

/*
 * 特征可信门：LAT/IOWAIT/PSI/CACHE 四特征要求 valid_bits 对应位
 * （AI_FEAT_VALID_* 契约：置位=已发布且来源可信）；SEQ/TS/VALID_BITS
 * 恒可信。不可信特征的规则**跳过不触发**（诚实降级——「无数据」不是
 * 「值为 0」，避免零值误触发阈值规则）。
 */
int aip_feat_trusted(const struct aip_fvec *v, uint32_t feat);

/* ---- 决策入口（冻结合同） ---- */

/*
 * aip_decide - 纯函数决策（无 IO/时钟/全局态；p99<1ms 测点本体）。
 *
 * 合同（多规则同时命中的裁定——设计 §1.3 主会话冻结）：
 *   - 规则按数组序扫描，**首命中单出**（decision=序最小命中规则）；
 *   - 每条命中规则仍计入 hits[i]（调用方可观测多命中全貌；
 *     hits 可 NULL=不计数）；
 *   - 特征不可信（valid_bits 缺位）的规则跳过；
 *   - 无命中：out->rule_idx=-1、action=NONE、flags 无 AIP_DF_HIT；
 *   - stale 位不在本函数置（调用方按新鲜度补 OR AIP_DF_STALE）。
 *
 * 返回 0 成功；-1 参数非法（vec/rules/out 为 NULL 或 n 越界上限
 * AIP_RULES_MAX），不写 out。
 */
int aip_decide(const struct aip_fvec *v, const struct ai_rule *rules,
	       size_t n, uint64_t *hits, struct aip_decision *out);

/* ---- bench 子命令（aipd bench；输出格式 Lane-B 台架解析合同） ---- */

/*
 * aip_bench_run - in-proc 决策延迟测点：内置表（aip_table）× 合成
 * 特征向量循环（覆盖命中/不命中/阈值边界），逐次 clock_gettime
 * (CLOCK_MONOTONIC) 包裹 aip_decide，排序取 p50/p99/max。
 * stdout 恰一行（Lane-B m1_bench.py 解析格式，字段顺序冻结）：
 *   AIPD_BENCH n=<N> p50_ns=<..> p99_ns=<..> max_ns=<..>
 * 返回 0；参数非法/内存失败返回 -1（stderr 说明）。
 */
int aip_bench_run(long n);

#endif /* _AIP_MODEL_H */
