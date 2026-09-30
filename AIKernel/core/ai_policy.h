// SPDX-License-Identifier: GPL-2.0
/*
 * ai_policy.h - AIKernel 决策策略引擎（Prompt 13 强化）
 *
 * AI 决策通过策略回调改变内核行为：AI Runtime 推理后调用 ai_policy_execute()，
 * 各子系统将自身的"AI 决策动作"注册为策略（ai_policy_register(domain, action,
 * callback, priv)）。
 *
 * Prompt 13 强化（重构计划 5.3 + 模块1 任务1.4）：
 *   - 注册表按 域+动作名 注册（action 名全表唯一）；
 *   - 执行器带回退：策略回调失败 → 调 rollback 回退内核默认行为（outcome=3）；
 *   - 决策记录：struct ai_decision_record（数据计划 23.2 全字段 + 因果链扩展），
 *     4096 条 ring 满覆盖最旧；outcome 可回写（ai_policy_outcome_update）；
 *   - 决策执行带安全边界（ai_policy_safety）：全局开关/最大影响幅度/快照回滚；
 *   - AI 自我观测遥测：第18类 AI_CAT_AI（decision/outcome 事件写回 ring buffer）。
 */

#ifndef _AIKERNEL_AI_POLICY_H
#define _AIKERNEL_AI_POLICY_H

#include "ai_types.h"
#include <linux/types.h>

/* ---- 策略决策域 ---- */

enum ai_policy_domain {
	AI_POLICY_DOMAIN_GENERAL   = 0,  /* 通用 */
	AI_POLICY_DOMAIN_SCHED     = 1,  /* 调度 */
	AI_POLICY_DOMAIN_MM        = 2,  /* 内存 */
	AI_POLICY_DOMAIN_IO        = 3,  /* I/O */
	AI_POLICY_DOMAIN_NET       = 4,  /* 网络 */
	AI_POLICY_DOMAIN_SECURITY  = 5,  /* 安全 */
	AI_POLICY_DOMAIN_POWER     = 6,  /* 电源 */
	AI_POLICY_DOMAIN_VFS       = 7,  /* VFS */
	AI_POLICY_DOMAIN_INTERRUPT = 8,  /* 中断 */
	AI_POLICY_DOMAIN_LOCK      = 9,  /* 锁 */
	AI_POLICY_DOMAIN_TIME      = 10, /* 时间 */
	AI_POLICY_DOMAIN_VIRT      = 11, /* 虚拟化 */
	AI_POLICY_DOMAIN_PROC      = 12, /* 进程 */
};

/* ---- 决策 outcome 常量（数据计划 20.2） ---- */

#define AI_OUTCOME_UNKNOWN   0   /* 未知（未观测） */
#define AI_OUTCOME_SUCCESS   1   /* 成功 */
#define AI_OUTCOME_PARTIAL   2   /* 部分成功（含被安全边界 clamp） */
#define AI_OUTCOME_FAILED    3   /* 失败（含被安全边界拒绝/回退） */
#define AI_OUTCOME_WORSE     4   /* 恶化（结果量化负向） */

/* ---- 决策来源 ---- */

#define AI_DEC_SRC_NETLINK   0   /* NETLINK_AI ACT 下发 */
#define AI_DEC_SRC_THINK     1   /* ai_runtime_think 闭环 */
#define AI_DEC_SRC_SYSFS     2   /* sysfs think 触发 */
#define AI_DEC_SRC_SAFETY    3   /* 安全边界（拒绝/回滚） */
#define AI_DEC_SRC_HEURISTIC 4   /* 内核确定性启发式决策源（W3 决策注入，
				  * ai_decision.c → ai_policy_record_heuristic） */

/* ---- 动作回调返回码（handler 返回语义） ---- */

#define AI_POLICY_RC_CLAMPED  1   /* 已生效但被安全边界 clamp（outcome=部分成功） */

/* 定向参数名长度（须与 UAPI AI_NL_ACT_PARAM_LEN 一致：
 * include/uapi/linux/ai_netlink.h；netlink 拷贝时长度不符即拒收） */
#define AI_POLICY_PARAM_LEN	24

/* ---- 决策执行上下文（对齐数据计划 20.2 决策记录格式） ---- */

struct ai_policy_ctx {
	u64  trigger_ts;        /* 触发事件时间戳 */
	u32  trigger_event_id;  /* 触发事件 ID（AI_EVENT_ID） */
	u8   decision_type;     /* 决策类型 */
	u64  decision_data[8];  /* 决策参数（最大 64 字节，全量零脱敏） */
	u8   confidence;        /* 模型置信度 0-100 */
	u32  model_version;     /* 决策模型版本 */
	enum ai_policy_domain domain;  /* 决策域 */
	u64  decision_id;       /* 本决策 ID（execute 分配，回填供闭环跟踪） */
	u8   source;            /* 决策来源（AI_DEC_SRC_*） */
	char param[AI_POLICY_PARAM_LEN]; /* 定向参数名（v2）：NUL 结尾；
			  * 空 = 按 domain 广播全部已启用动作（v1 语义，
			  * think/sysfs 路径保持为空）；非空 = 只执行动作名
			  * 全等或末段匹配（'.' 后缀）的那一条 */
};

/* ---- 策略回调 ---- */

struct ai_policy;

typedef int (*ai_policy_handler_t)(const struct ai_policy_ctx *ctx,
				   void *arg);
typedef int (*ai_policy_rollback_t)(const struct ai_policy_ctx *ctx,
				    void *arg);

struct ai_policy {
	char                 name[AI_MAX_NAME_LEN];  /* 动作名（注册表唯一） */
	enum ai_policy_domain domain;                /* 决策域 */
	u32                  priority;               /* 优先级（大者先执行） */
	u8                   enabled;                /* 1=启用 0=停用 */
	ai_policy_handler_t  handler;                /* 执行回调 */
	ai_policy_rollback_t rollback;               /* 回退回调（可 NULL） */
	void                 *private_data;          /* 回调私有参数 */
};

/* ---- 决策记录（数据计划 23.2 全字段 + 因果链扩展，全量零脱敏） ---- */

#define AI_POLICY_DECISION_RING_SIZE  4096   /* 决策记录 ring 容量 */

struct ai_decision_record {
	u64  trigger_ts;            /* 触发事件时间戳 */
	u32  trigger_event_id;      /* 触发事件 ID（AI_EVENT_ID） */
	u64  decision_ts;           /* 决策（推理完成）时间戳 */
	u8   decision_type;         /* 决策类型 */
	u64  decision_data[8];      /* 决策参数（最大 64 字节，零脱敏） */
	u64  execute_ts;            /* 策略执行时间戳 */
	u64  outcome_ts;            /* 结果观测时间戳 */
	u8   outcome;               /* AI_OUTCOME_*（0=未知 1=成功 2=部分 3=失败 4=恶化） */
	s64  metric_delta;          /* 结果量化（延迟/吞吐/内存变化） */
	u32  model_version;         /* 决策模型版本 */
	u8   confidence;            /* 模型置信度 0-100 */
	/* ---- 因果链扩展（trigger_event_id → decision_id → outcome） ---- */
	u64  decision_id;           /* 本决策 ID */
	u8   domain;                /* 决策域 */
	u8   source;                /* AI_DEC_SRC_* */
	u8   executed;              /* 实际执行的策略数（命中数） */
	u8   safety_clamped;        /* 1=被安全边界限制（幅度/范围 clamp） */
} __attribute__((packed));

/* ---- AI 自我观测遥测 payload（第18类，AI_CAT_AI） ---- */

struct ai_tp_decision {
	u8   type;                  /* 1=AI_DECISION */
	u64  decision_id;
	u64  trigger_ts;
	u32  trigger_event_id;
	u8   decision_type;
	u8   domain;
	u8   confidence;
	u32  model_version;
	u8   executed;
	u8   safety_clamped;
	u8   reserved[6];
} __attribute__((packed));

struct ai_tp_outcome {
	u8   type;                  /* 2=AI_OUTCOME */
	u64  decision_id;
	u8   outcome;
	s64  metric_delta;
	u8   reserved[7];
} __attribute__((packed));

struct ai_policy_stats {
	u64 decisions_total;   /* 决策记录累计条数 */
	u64 attempts;          /* 策略执行尝试次数 */
	u64 hits;              /* 命中（至少执行了一个策略）次数 */
	u64 latency_sum;       /* 决策执行延迟累计（ns） */
	u64 latency_min;       /* 决策执行延迟最小（ns） */
	u64 latency_max;       /* 决策执行延迟最大（ns） */
};

/* ---- 策略接口（实现于 ai_policy.c） ---- */

#ifdef CONFIG_AIKERNEL_RUNTIME

/**
 * ai_policy_register() - 注册一个可执行动作（域 + 动作名 + 回调）
 * @domain: 决策域（enum ai_policy_domain）
 * @action: 动作名（如 "mm.swappiness"，注册表唯一）
 * @callback: 执行回调（AI 决策命中该动作时调用）
 * @rollback: 回退回调（可 NULL；callback 失败时回退内核默认行为）
 * @priv: 回调私有参数
 *
 * 各子系统初始化时把"AI 可执行动作"注册进来（数据计划 20.3 可控制参数表
 * 每条 = 一个策略接口）。返回 AI_OK 或负错误码。
 */
int ai_policy_register(enum ai_policy_domain domain, const char *action,
		       ai_policy_handler_t callback,
		       ai_policy_rollback_t rollback, void *priv);

/**
 * ai_policy_unregister() - 注销一个动作
 * @action: 之前注册过的动作名
 *
 * 返回 AI_OK 或负错误码。
 */
int ai_policy_unregister(const char *action);

/**
 * ai_policy_execute() - 执行某决策域下的全部已启用动作（<200ns 目标）
 * @ctx: 决策上下文（AI Runtime 推理结果；decision_id 由本函数分配回填；
 *       ctx->param 非空时为定向执行：只执行动作名全等或末段匹配的那一条）
 * @arg: 透传给动作回调的私有参数（NULL 时用注册时的 priv）
 *
 * 流程：安全边界闸门（全局关闭 → AI_ERR_DISABLED）→ 分配 decision_id →
 * 按优先级降序执行匹配域动作（param 非空时再按参数名过滤，空则域内广播）→
 * 逐动作收集结果（回调失败 → 调 rollback 回退内核默认行为）→ outcome
 * 聚合（全成=1 部分=2 全败=3 无匹配=0）→ 决策记录写入 ring + AI_DECISION
 * 遥测 + 统计累计。
 * 返回已执行动作数（>=0）或负错误码。
 */
int ai_policy_execute(const struct ai_policy_ctx *ctx, void *arg);

/**
 * ai_policy_outcome_update() - 回写决策结果（决策闭环第 4 步）
 * @decision_id: execute 分配的决策 ID
 * @outcome: AI_OUTCOME_*
 * @metric_delta: 结果量化（延迟/吞吐/内存变化，正=改善 负=恶化）
 *
 * 回填 outcome/outcome_ts/metric_delta → AI_OUTCOME 遥测（cat18）→
 * 完整因果链记录推入 ai_causal（ai_causal_chain_push）。
 * 返回 AI_OK、AI_ERR_NOT_FOUND（决策已滚出 ring）或负错误码。
 */
int ai_policy_outcome_update(u64 decision_id, u8 outcome, s64 metric_delta);

/**
 * ai_policy_rollback_decision() - 回滚一次决策（恢复决策前状态）
 * @decision_id: 目标决策 ID
 *
 * 由安全层快照恢复全部受影响参数。返回 AI_OK 或负错误码。
 */
int ai_policy_rollback_decision(u64 decision_id);

/**
 * ai_policy_rollback_all() - 回滚全部已生效决策（紧急刹车/测试还原）
 *
 * 由安全层快照逆序恢复。返回 AI_OK 或负错误码。
 */
int ai_policy_rollback_all(void);

/**
 * ai_policy_set_enabled() - 启用/停用指定动作
 * @action: 动作名
 * @enable: 1=启用 0=停用
 *
 * 返回 AI_OK 或负错误码。
 */
int ai_policy_set_enabled(const char *action, u8 enable);

/**
 * ai_policy_get_name() - 按索引取动作名（sysfs policy/ 目录同步用）
 * @index: 0 起的索引
 * @name: 输出缓冲（AI_MAX_NAME_LEN）
 * @enabled: 可选输出当前开关
 *
 * 返回 AI_OK（有效），越界返回 AI_ERR_NOT_FOUND。
 */
int ai_policy_get_name(unsigned int index, char *name, u8 *enabled);

/**
 * ai_policy_lookup() - 按动作名查询开关状态
 * @action: 动作名
 * @enabled: 输出当前开关（1/0）
 *
 * 返回 AI_OK 或 AI_ERR_NOT_FOUND。
 */
int ai_policy_lookup(const char *action, u8 *enabled);

/**
 * ai_policy_stats_get() - 读取决策执行统计
 * @st: 统计输出
 *
 * 返回 AI_OK 或负错误码。
 */
int ai_policy_stats_get(struct ai_policy_stats *st);

/**
 * ai_policy_decision_read() - 读出决策记录（最旧在前）
 * @buf: 接收缓冲（struct ai_decision_record 数组）
 * @cap: 缓冲容量（字节）
 * @out_count: 回填读出条数
 * @out_bytes: 回填实际拷贝字节数（可 NULL）
 *
 * 单读者语义（procfs/netlink 串行）；返回 AI_OK 或负错误码。
 */
int ai_policy_decision_read(void *buf, size_t cap,
			    u32 *out_count, size_t *out_bytes);

/**
 * ai_policy_next_decision_id() - 分配下一个决策 ID（全局单调）
 *
 * 供 netlink/runtime 在构造决策前取 ID；execute 内部亦使用同一计数器。
 */
u64 ai_policy_next_decision_id(void);

/**
 * ai_policy_record_heuristic() - 启发式决策注入记账入 ring（W3）
 * @domain: 决策域（MM/SCHED）
 * @hook_id: enum ai_hook_id（触发挂点，写入 trigger_event_id 低 8 位）
 * @bias: 注入偏置值
 * @aux0/aux1: 生效观测（挂点自定义：前后值）
 *
 * 供 ai_decision.c 的节流采样调用：构造 source=AI_DEC_SRC_HEURISTIC 的
 * 决策记录推入 ring（decision_data[0]=hook_id [1]=bias [2]=aux0 [3]=aux1，
 * executed=1 confidence=100 确定性启发式）。可在原子上下文调用（内部
 * spinlock 短临界区）。返回 AI_OK。
 */
int ai_policy_record_heuristic(u8 domain, u8 hook_id,
			       s64 bias, s64 aux0, s64 aux1);

#else /* !CONFIG_AIKERNEL_RUNTIME */

static inline int ai_policy_register(enum ai_policy_domain domain,
				     const char *action,
				     ai_policy_handler_t callback,
				     ai_policy_rollback_t rollback,
				     void *priv)
{
	return AI_OK;
}
static inline int ai_policy_unregister(const char *action) { return AI_OK; }
static inline int ai_policy_execute(const struct ai_policy_ctx *ctx, void *arg)
{
	return 0;
}
static inline int ai_policy_outcome_update(u64 id, u8 outcome, s64 delta)
{
	return AI_OK;
}
static inline int ai_policy_rollback_decision(u64 id) { return AI_OK; }
static inline int ai_policy_rollback_all(void) { return AI_OK; }
static inline int ai_policy_set_enabled(const char *name, u8 enable) { return AI_OK; }
static inline int ai_policy_get_name(unsigned int index, char *name, u8 *enabled)
{
	return AI_ERR_NOT_FOUND;
}
static inline int ai_policy_lookup(const char *name, u8 *enabled)
{
	return AI_ERR_NOT_FOUND;
}
static inline int ai_policy_stats_get(struct ai_policy_stats *st)
{
	if (st)
		memset(st, 0, sizeof(*st));
	return AI_OK;
}
static inline int ai_policy_decision_read(void *buf, size_t cap,
					  u32 *out_count, size_t *out_bytes)
{
	if (out_count)
		*out_count = 0;
	if (out_bytes)
		*out_bytes = 0;
	return AI_OK;
}
static inline u64 ai_policy_next_decision_id(void) { return 0; }
static inline int ai_policy_record_heuristic(u8 domain, u8 hook_id,
					     s64 bias, s64 aux0, s64 aux1)
{
	return AI_OK;
}

#endif /* CONFIG_AIKERNEL_RUNTIME */

#endif /* _AIKERNEL_AI_POLICY_H */
