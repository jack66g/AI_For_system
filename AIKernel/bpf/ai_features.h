/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ai_features.h - K7 D3：eBPF 特征出口（BPF_MAP_TYPE_AI_FEATURES）契约头
 *
 * 三方共用 schema（KERNEL-K7-DESIGN §2 D3）：
 *   - 内核生产者：ai_features.c 的 ai_features_sample_publish()——由
 *     ai_sched 采样器尾 1Hz 调用（集成行由主会话补，见函数注释）；
 *   - BPF map 读者：map_lookup_elem(key=cpu) 返回该 CPU 槽的快照副本；
 *   - 用户态探针（宿主 ~/k2/k3/k7feat.c）：自搓常量按偏移镜像本 schema。
 *
 * 固定 schema 48B（_Static_assert 钉扎在 ai_features.c；演进走版本号+
 * rsv 扩展，字段顺序/宽度冻结）。
 *
 * 广播语义（D3 落法，偏差登记）：publish 由单一采样器 kthread 调用，
 * lat_ewma_ns/psi_mem_some（均为系统级源）广播到全部 CPU 槽；iowait_pct
 * 仅写入调用时所在 CPU 的槽（其余槽该字段 0 且 valid_bits 不置 IOWAIT
 * 位——非本 CPU 实测，诚实登记粒度）。各槽 seq 独立单调，读者可判
 * 「该槽多久没被发布」与字段来源。
 *
 * psi_mem_some 单位：PSI some avg10 定点值（FIXED_1=2048 制，百分比=
 * 值*100/2048），与 ai_psi_read() 原生口径一致（调用方零换算）。
 */
#ifndef _AIKERNEL_BPF_AI_FEATURES_H
#define _AIKERNEL_BPF_AI_FEATURES_H

#include <linux/types.h>

/* schema 版本（结构冻结，v2 若扩走尾端 rsv/新版本号） */
#define AI_FEATURE_VEC_VERSION	1

/* valid_bits 掩码：置位=该槽此字段已发布且来源可信 */
#define AI_FEAT_VALID_LAT	((__u32)1 << 0)	/* lat_ewma_ns */
#define AI_FEAT_VALID_IOWAIT	((__u32)1 << 1)	/* iowait_pct（本 CPU 槽） */
#define AI_FEAT_VALID_PSI	((__u32)1 << 2)	/* psi_mem_some */
#define AI_FEAT_VALID_CACHE	((__u32)1 << 3)	/* cache_misses（v2 PMU 接入） */

/*
 * struct ai_feature_vec - per-CPU 特征快照（定长只读）
 *
 * seq=0 表示该槽从未发布（lookup 仍成功返回零值——「无数据」也是诚实态）。
 */
struct ai_feature_vec {
	__u64	seq;		/* per-CPU 单调采样序号（seqlock 计数含奇偶相） */
	__u64	ts;		/* ktime_get_ns() 采样时刻（新鲜度可判） */
	__u64	lat_ewma_ns;	/* sched latency EWMA（ns，系统级源广播） */
	__u32	iowait_pct;	/* iowait 百分比 0..100（仅本 CPU 槽置位） */
	__u32	psi_mem_some;	/* PSI mem some avg10 定点 0..2048（系统级） */
	__u64	cache_misses;	/* v1 恒 0（tcg 无 vPMU，CACHE 位不置） */
	__u32	valid_bits;	/* AI_FEAT_VALID_* 掩码 */
	__u32	rsv;		/* 保留恒 0 */
};

#ifdef CONFIG_AIKERNEL_BPF

void ai_features_sample_publish(u64 lat_ewma_ns, u32 iowait_pct,
				u32 psi_mem_some);

#else	/* !CONFIG_AIKERNEL_BPF */

/*
 * 空内联：ai_sched 采样器尾的调用行无需调用方自行 ifdef（与
 * ai_effect_tick() 同手法——CONFIG 关闭时零开销）。
 */
static inline void ai_features_sample_publish(u64 lat_ewma_ns, u32 iowait_pct,
					      u32 psi_mem_some)
{
}

#endif	/* CONFIG_AIKERNEL_BPF */

#endif	/* _AIKERNEL_BPF_AI_FEATURES_H */
