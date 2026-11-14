/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __AI_CHAIN_H
#define __AI_CHAIN_H

/*
 * ai_chain.h - K8 审计链（append-only xxh64 哈希链 + 锚 + 窗口验证）
 *
 * 设计册 KERNEL-K8-DESIGN.md：
 *   - 独立 72B 定长节点流（183B 决策记录冻约，decision_id 关联）；
 *   - 满覆盖最旧 + evicted 计数（链保持前进，K8-D1 裁决）；
 *   - 内核 verify 只证窗口内 seq 连续 + 哈希链接；全史凭据=导出+锚；
 *   - fire-and-forget：所有发射点一律忽略返回值，链永不阻断业务路径。
 *
 * !CONFIG_AIKERNEL_SECURITY 时全部 inline 空桩（照 ai_audit.h 手法）。
 */

#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>

#define AI_CHAIN_NODE_DATA	32
#define AI_CHAIN_RING_NODES	8192
#define AI_CHAIN_XXH_SEED	0x414b3831ULL	/* "AK81" */
#define AI_CHAIN_FLAG_ANCHOR	1
#define AI_CHAIN_DEFAULT_PERIOD	4096
#define AI_CHAIN_MIN_PERIOD	16

/* 事件族（§D5；aikctl 侧按同值解码） */
enum ai_chain_kind {
	AI_CHAIN_KIND_GENESIS		= 0,
	AI_CHAIN_KIND_DECISION_NEW	= 1,
	AI_CHAIN_KIND_DECISION_OUTCOME	= 2,
	AI_CHAIN_KIND_ROLLBACK		= 3,
	AI_CHAIN_KIND_AGENT_REJECT	= 4,
	AI_CHAIN_KIND_MODEL_EVENT	= 5,
	AI_CHAIN_KIND_KEY_EVENT		= 6,
	AI_CHAIN_KIND_SECCOMP_ANOMALY	= 7,
	AI_CHAIN_KIND_AUDIT_ANOMALY	= 8,
	AI_CHAIN_KIND_ANCHOR		= 9,
	AI_CHAIN_KIND_NR
};

/* 模型事件 op 值（AI_CHAIN_KIND_MODEL_EVENT.data[0]） */
#define AI_CHAIN_MODEL_OP_LOAD		0
#define AI_CHAIN_MODEL_OP_ARM		1
#define AI_CHAIN_MODEL_OP_CONFIRM	2
#define AI_CHAIN_MODEL_OP_REVERT	3

struct ai_chain_node {
	u64 seq;		/* 全局单调，genesis=1 */
	u64 ts_ns;
	u64 prev_hash;		/* h_{n-1}；genesis = seed 值或 0 */
	u64 self_hash;		/* xxh64(整 72B 且 self_hash 清零) */
	u32 pid;
	u16 kind;
	u16 flags;		/* bit0 = ANCHOR */
	u8  data[AI_CHAIN_NODE_DATA];
} __packed;

struct ai_chain_stats {
	u64 nodes;		/* 已铸节点总数（含 genesis/anchor） */
	u64 evicted;		/* 覆盖最旧计数 */
	u64 anchors;		/* ANCHOR 节点数（周期+即发） */
	u64 head_hash;		/* 末节点 self_hash */
	u64 first_seq;		/* 窗口首 seq（导出/verify 起点） */
	u32 period;
	u64 seeded_val;
	bool seeded;
	bool enabled;
	u64 boot_cookie;	/* genesis 后非 0；0=未铸 */
};

/* 事件 data 布局（packed ≤32B，零垫） */
struct ai_chain_ev_decision_new {
	u64 decision_id;
	u32 trigger_event_id;
	u8 decision_type;
	u8 domain;
	u8 source;
} __packed;

struct ai_chain_ev_decision_outcome {
	u64 decision_id;
	u8 outcome;
	u8 pad[7];
	s64 metric_delta;
	u64 outcome_ts;
} __packed;

struct ai_chain_ev_rollback {
	u64 decision_id;	/* 0 = rollback_all */
	u32 count;
	u32 pad;
} __packed;

struct ai_chain_ev_agent_reject {
	u32 agent_id;
	u32 failures;
	u32 window_actions;
	u32 pad;
} __packed;

struct ai_chain_ev_model {
	u8 op;
	u8 pad[3];
	u32 model_id;
	u64 sha256_hi64;	/* 仅 LOAD 有值；ARM/CONFIRM/REVERT 为 0 */
} __packed;

struct ai_chain_ev_key {
	char type[8];
	u64 desc_hash;
	u32 plen;
	u8 strength;
	u8 pad[11];
} __packed;

struct ai_chain_ev_seccomp {
	s32 syscall_nr;
	u32 score;
	u32 window;
	u32 pad;
} __packed;

struct ai_chain_ev_anomaly {
	u64 type_hash;
	u64 detail_hash;
} __packed;

struct ai_chain_ev_anchor {
	u64 nodes_total;
	u64 window_first_seq;	/* 上个 anchor（或 genesis）之后首 seq */
	u32 epoch;
	u32 pad;
} __packed;

#if IS_ENABLED(CONFIG_AIKERNEL_SECURITY)

int  ai_chain_append(u16 kind, const void *data, u16 len);
int  ai_chain_seed(u64 anchor_hash);
int  ai_chain_anchor_now(void);
int  ai_chain_verify(u64 *bad_seq);		/* 0/-EIO(定位)/-ENODATA */
void ai_chain_stats_read(struct ai_chain_stats *out);
int  ai_chain_node_copy(u64 seq, struct ai_chain_node *out); /* -ENOENT 越窗 */
int  ai_chain_enable_set(bool on);
bool ai_chain_enable_read(void);
int  ai_chain_period_set(u32 period);	/* min = AI_CHAIN_MIN_PERIOD */

/* sec 钩便捷发射器（ai_lsm.c 调用；fire-and-forget） */
void ai_chain_key_event(const char *type, const char *desc,
			size_t plen, u8 strength);
void ai_chain_seccomp_anomaly(int syscall_nr, u32 score);

#ifdef CONFIG_AIKERNEL_KUNIT_TEST
void ai_chain_test_reset(void);
int  ai_chain_test_tamper(u64 seq, u32 field);	/* 0=data 1=self 2=prev 3=seq */
#endif

#else	/* !CONFIG_AIKERNEL_SECURITY：空桩 */

static inline int ai_chain_append(u16 kind, const void *data, u16 len)
{ return 0; }
static inline int ai_chain_seed(u64 anchor_hash) { return 0; }
static inline int ai_chain_anchor_now(void) { return 0; }
static inline int ai_chain_verify(u64 *bad_seq) { return -ENODATA; }
static inline void ai_chain_stats_read(struct ai_chain_stats *out)
{ memset(out, 0, sizeof(*out)); out->period = AI_CHAIN_DEFAULT_PERIOD; }
static inline int ai_chain_node_copy(u64 seq, struct ai_chain_node *out)
{ return -ENOENT; }
static inline int ai_chain_enable_set(bool on) { return 0; }
static inline bool ai_chain_enable_read(void) { return false; }
static inline void ai_chain_key_event(const char *type, const char *desc,
				      size_t plen, u8 strength) {}
static inline void ai_chain_seccomp_anomaly(int syscall_nr, u32 score) {}

#endif	/* CONFIG_AIKERNEL_SECURITY */

#endif	/* __AI_CHAIN_H */
