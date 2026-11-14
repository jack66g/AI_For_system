// SPDX-License-Identifier: GPL-2.0
/*
 * ai_runtime.h - AIKernel AI Runtime 中枢
 *
 * AI Runtime 是全部 AI 能力的执行中枢：
 *   生命周期（ai_runtime_init/destroy）
 *   推理请求提交（ai_runtime_chat，同步框架）
 *   决策推理（ai_runtime_think / ai_runtime_think_execute，Prompt 13：
 *     感知数据 → 决策模型推理 → 策略执行闭环）
 *   模型注册（ai_model_load/unload，见 ai_model.h）
 *   回调管理（ai_runtime_callback_register/unregister）
 *
 * init/main.c 的接入（start_kernel() 中调用 ai_runtime_init()）为 Prompt 02 任务。
 */

#ifndef _AIKERNEL_AI_RUNTIME_H
#define _AIKERNEL_AI_RUNTIME_H

#include "ai_types.h"
#include "../reflex/ai_model.h"
#include <linux/types.h>

/* ---- Runtime 生命周期状态 ---- */

enum ai_runtime_state {
	AI_RT_STATE_DOWN  = 0,  /* 未初始化 */
	AI_RT_STATE_INIT  = 1,  /* 初始化中 */
	AI_RT_STATE_READY = 2,  /* 就绪 */
};

/* ---- 推理请求/结果 ---- */

struct ai_inference_request {
	u64         id;         /* 请求 ID（调用方生成，随结果回填） */
	u32         model_id;   /* 目标模型句柄（ai_model_load 回填的 id） */
	const void *input;      /* 输入数据（原始，零脱敏） */
	size_t      input_len;  /* 输入长度 */
	void       *output;     /* 输出缓冲 */
	size_t      output_len; /* 输出缓冲容量 */
	u64         timeout_ns; /* 超时（0=默认；本步为同步框架，预留） */
};

struct ai_inference_result {
	u64     request_id;   /* 回填请求 id */
	u32     model_id;     /* 回填模型句柄 */
	int     status;       /* AI_OK 或负错误码 */
	size_t  output_len;   /* 实际输出长度 */
	u64     latency_ns;   /* 推理耗时 */
};

/* ---- 决策推理（Prompt 13：感知 → 决策 → 执行闭环） ---- */

#define AI_SENSE_DATA_MAX  128   /* 感知数据载荷上限 */

struct ai_sense_input {
	u64  ts;                     /* 触发事件时间戳 */
	u32  event_id;               /* 触发事件 ID（AI_EVENT_ID(cat,ev)） */
	u8   category;               /* 触发事件大类 */
	u8   severity;               /* 严重级别 */
	u16  data_len;               /* 感知数据长度 */
	u8   data[AI_SENSE_DATA_MAX]; /* 原始感知数据（零脱敏） */
};

struct ai_think_result {
	u64  decision_id;            /* 决策 ID（框架分配回填） */
	u8   domain;                 /* 决策域 */
	u8   decision_type;          /* 决策类型 */
	u64  decision_data[8];       /* 决策参数（≤64B，零脱敏） */
	u8   confidence;             /* 置信度 0-100 */
	u32  model_version;          /* 模型版本（回填） */
	int  status;                 /* AI_OK 或负错误码 */
};

/* 内置 decide 模型感知载荷（sysfs think 触发格式：
 *   <event_id>,<domain>,<type>,<value>         全局参数
 *   <event_id>,<domain>,<type>,<pid>,<value>   task 作用域参数） */
struct ai_sense_decision {
	u8  domain;
	u8  decision_type;
	u8  confidence;
	u8  pad;
	s64 value;
	s32 pid;
} __attribute__((packed));

/* ---- 推理完成回调 ---- */

typedef void (*ai_runtime_callback_t)(struct ai_inference_result *res,
				      void *priv);

/* ---- K6（WP-K6 施工 A）：推理预算 / 决策模型 A/B 切换 / enumerate 扩展 ---- */

/* 推理预算默认值（纳秒）；0=不限 */
#define AI_RUNTIME_INFER_BUDGET_DEFAULT_NS	10000000ULL

/* A/B 切换观察窗默认长度（confirm 后新模型首个 N 次 think 计 error/timeout 率） */
#define AI_RUNTIME_OBSERVE_DEFAULT	10u

/* sha256 前 12 hex 字符 + NUL（/proc/ai/models 渲染宽度，B 路） */
#define AI_MODEL_HASH_HEX_LEN	13

/* 模型槽位（enumerate 扩展出参；小枚举，直传 int 语义） */
enum ai_model_slot {
	AI_MODEL_SLOT_NORMAL  = 0,   /* 普通模型 */
	AI_MODEL_SLOT_ACTIVE  = 1,   /* 当前 active 决策模型 */
	AI_MODEL_SLOT_STANDBY = 2,   /* 观察窗内保活的旧决策模型（standby） */
};

/**
 * struct ai_model_info - 模型全量信息快照（K6 D3：/proc/ai/models 数据源）
 * @name: 模型名（注册表唯一）
 * @version/@source/@state: 同 ai_model_enumerate() 既有语义
 * @slot: enum ai_model_slot（active/standby/普通）
 * @file_bytes: 加载文件字节数（非文件加载=0；MLP 元数据）
 * @infer_n/@last_lat_ns/@timeout_n: D2 推理统计（非 MLP 模型为 0）
 * @hash: sha256 前 12 hex 字符（NUL 结尾；非文件加载=""）
 */
struct ai_model_info {
	char	name[AI_MAX_NAME_LEN];
	u32	version;
	u32	source;
	u32	state;
	u32	slot;
	u64	file_bytes;
	u64	infer_n;
	u64	last_lat_ns;
	u64	timeout_n;
	char	hash[AI_MODEL_HASH_HEX_LEN];
};

/* ---- Runtime 接口（实现于 ai_runtime.c） ---- */

#ifdef CONFIG_AIKERNEL_RUNTIME

/**
 * ai_runtime_init() - 初始化 AI Runtime 中枢
 *
 * 初始化模型注册表、回调表与遥测核心（ai_telemetry_init()）。
 * 幂等：重复调用返回 AI_OK。由 init/main.c 在 start_kernel() 调用（Prompt 02），
 * 本步供模块/测试直接调用。
 * 返回 AI_OK 或负错误码。
 */
int ai_runtime_init(void);

/**
 * ai_runtime_destroy() - 销毁 AI Runtime 中枢
 *
 * 逆序清理遥测核心与各注册表。幂等。
 */
void ai_runtime_destroy(void);

/**
 * ai_runtime_model_infer_by_name() - 按名对已加载模型执行一次真实推理
 * @name: 模型名（注册表唯一）
 * @input/@in_len: 输入字节（AIKWMDL MLP：float32 数组，首层 in_dim*4）
 * @output/@out_len: 输出缓冲（入参=容量，回填实际长度）
 * @latency_ns: 可选回填推理耗时
 * @budget_ns: K6 D2 本次推理预算（纳秒）。调用方从全局取
 *             （ai_model_infer_budget_ns_get()）或显式传值（如 1ns
 *             强制超时）；0=经 ops->infer 按全局预算执行。
 *
 * AIKWMDL MLP 真前向入口（sysfs model_infer 使用）。超预算返 -ETIME
 * （不写 output）。返回 AI_OK 或负错误码（AI_ERR_NOT_FOUND=无此模型/
 * 无 infer 回调）。
 */
int ai_runtime_model_infer_by_name(const char *name, const void *input,
				   size_t in_len, void *output,
				   size_t *out_len, u64 *latency_ns,
				   u64 budget_ns);

/**
 * ai_runtime_chat() - 提交一次推理请求（同步框架）
 *
 * 校验参数 → 按 model_id 查找模型 → 调用模型 ops->infer 执行推理 → 回填结果。
 * 无模型返回 AI_ERR_NO_MODEL；模型无 infer 实现返回 AI_ERR_NOT_IMPLEMENTED。
 * 本步为框架 + 空实现，真实模型自 Prompt 03 起随子系统注册。
 * 返回 AI_OK 或负错误码。
 */
int ai_runtime_chat(struct ai_inference_request *req,
		    struct ai_inference_result *res);

/**
 * ai_runtime_think() - 从感知数据推理出决策（决策闭环第 2 步）
 * @sense: 触发事件 + 原始感知数据（全量零脱敏）
 * @res: 决策输出（domain/type/data/confidence；decision_id/model_version 回填）
 *
 * 查找决策模型（ops->think 存在者，内置 "decide" 模型兜底）→ 模型推理 →
 * 框架分配 decision_id（与执行器同一计数器）→ 回填。
 * 与 ai_runtime_chat() 并行：chat=文本对话，think=感知→决策。
 * 返回 AI_OK 或负错误码（AI_ERR_NO_MODEL 无决策模型）。
 */
int ai_runtime_think(const struct ai_sense_input *sense,
		     struct ai_think_result *res);

/**
 * ai_runtime_think_execute() - 感知 → 决策 → 执行（闭环第 2+3 步）
 * @sense: 触发事件 + 原始感知数据
 * @res: 决策输出（status 回填执行结果，decision_id 供 outcome 上报）
 *
 * think → 组 ai_policy_ctx（trigger_ts/trigger_event_id 取自 sense）→
 * ai_policy_execute → res->status/decision_id 回填。
 * 返回 AI_OK（执行成功/部分/被限幅）或负错误码。
 */
int ai_runtime_think_execute(const struct ai_sense_input *sense,
			     struct ai_think_result *res);

/**
 * ai_runtime_get_state() - 查询 Runtime 状态
 *
 * 返回 enum ai_runtime_state。
 */
int ai_runtime_get_state(void);

/**
 * ai_runtime_callback_register() - 注册推理完成回调
 * @cb: 回调函数
 * @priv: 回调私有参数
 *
 * 最多 AI_RUNTIME_MAX_CALLBACKS 个。返回 AI_OK 或负错误码。
 */
int ai_runtime_callback_register(ai_runtime_callback_t cb, void *priv);

/**
 * ai_runtime_callback_unregister() - 注销推理完成回调
 * @cb: 之前注册的回调函数
 *
 * W63：返回前等待所有已持有该回调快照的在途 ai_runtime_chat() 完成回调
 * 执行（SRCU），因此返回后调用方即可安全释放 @priv。不得在回调内部注销
 * 自身（会等待自己造成死锁）。返回 AI_OK 或负错误码。
 */
int ai_runtime_callback_unregister(ai_runtime_callback_t cb);

/**
 * ai_model_infer_budget_ns_get() - 查询推理预算（K6 D2）
 *
 * 全局单值（纳秒），所有模型 ops->infer 入场锚定用；0=不限。
 * 默认 AI_RUNTIME_INFER_BUDGET_DEFAULT_NS（10ms）。
 */
u64 ai_model_infer_budget_ns_get(void);

/**
 * ai_model_infer_budget_ns_set() - 设置推理预算（K6 D2）
 * @budget_ns: 预算（纳秒）；0=不限
 *
 * /sys/kernel/ai/model_infer_budget_ns（B 路 sysfs）写入口。
 * 返回 AI_OK。
 */
int ai_model_infer_budget_ns_set(u64 budget_ns);

/**
 * ai_runtime_model_switch_arm() - 决策模型 A/B 切换布防（K6 D4）
 * @name: 目标模型名（必须 LOADED）
 * @token: 返回布防 token（无状态 FNV64a 派生，K2c blast token 同款手法）
 *
 * 目标必须 LOADED → 冒烟推理（固定微输入：think 模型走微 sense 载荷，
 * infer-only 模型如 MLP 走 1KB 零向量——失败/超预算 → 拒布防，不回填
 * token）→ 登记单槽 pending（name+id+token）。无 confirm 不生效。
 * 返回 0 成功；-EBUSY 单槽已布防；-ENOENT 目标不存在/非 LOADED；
 * -EIO 冒烟失败或超时；-EINVAL 参数无效。
 */
int ai_runtime_model_switch_arm(const char *name, u64 *token);

/**
 * ai_runtime_model_switch_confirm() - 确认切换生效（K6 D4）
 * @token: arm 返回的 token
 *
 * token 失配/未布防 → -ENOENT；目标在布防后被卸载 → -ENOENT。
 * 生效：active 指针换新（旧模型引用转入观察窗保活；窗关闭时释放）。
 * 返回 0 成功；负错误码。
 */
int ai_runtime_model_switch_confirm(u64 token);

/**
 * ai_runtime_switch_observe() - 设置 A/B 观察窗长度（K6 D4）
 * @n: 窗口长度（confirm 后新模型首 n 次 think 计 error/timeout，超半
 *     自动换回旧模型+审计；0=关窗——confirm 即释放旧引用）
 *
 * 只影响后续 confirm 的窗；在途窗不变。返回 0 或 -EINVAL（n 超上限）。
 */
int ai_runtime_switch_observe(unsigned int n);

/**
 * ai_model_enumerate_info() - 按索引枚举已加载模型全量信息（K6 D3）
 * @index: 0 起的索引（与 ai_model_enumerate 同一可见性口径：仅 LOADED）
 * @info: 输出快照（struct ai_model_info）
 *
 * /proc/ai/models（B 路 procfs）数据源。哈希/字节数/统计来自 MLP 模型
 * 元数据（ai_model_mlp.h），非 MLP 模型相应字段为 0/空串。
 * 返回 AI_OK（有效）或 AI_ERR_NOT_FOUND（越界）。
 */
int ai_model_enumerate_info(unsigned int index, struct ai_model_info *info);

#else /* !CONFIG_AIKERNEL_RUNTIME */

static inline int ai_runtime_init(void) { return AI_OK; }
static inline void ai_runtime_destroy(void) { }
static inline int ai_runtime_chat(struct ai_inference_request *req,
				  struct ai_inference_result *res)
{
	return AI_ERR_NOT_IMPLEMENTED;
}
static inline int ai_runtime_think(const struct ai_sense_input *sense,
				   struct ai_think_result *res)
{
	if (res)
		res->status = AI_ERR_NOT_IMPLEMENTED;
	return AI_ERR_NOT_IMPLEMENTED;
}
static inline int ai_runtime_think_execute(const struct ai_sense_input *sense,
					   struct ai_think_result *res)
{
	if (res)
		res->status = AI_ERR_NOT_IMPLEMENTED;
	return AI_ERR_NOT_IMPLEMENTED;
}
static inline int ai_runtime_get_state(void) { return AI_RT_STATE_DOWN; }
static inline int ai_runtime_callback_register(ai_runtime_callback_t cb, void *priv)
{
	return AI_OK;
}
static inline int ai_runtime_callback_unregister(ai_runtime_callback_t cb)
{
	return AI_OK;
}
static inline u64 ai_model_infer_budget_ns_get(void)
{
	return AI_RUNTIME_INFER_BUDGET_DEFAULT_NS;
}
static inline int ai_model_infer_budget_ns_set(u64 budget_ns)
{
	return AI_OK;
}
static inline int ai_runtime_model_switch_arm(const char *name, u64 *token)
{
	return AI_ERR_NOT_IMPLEMENTED;
}
static inline int ai_runtime_model_switch_confirm(u64 token)
{
	return AI_ERR_NOT_IMPLEMENTED;
}
static inline int ai_runtime_switch_observe(unsigned int n)
{
	return AI_OK;
}
static inline int ai_model_enumerate_info(unsigned int index,
					  struct ai_model_info *info)
{
	return AI_ERR_NOT_FOUND;
}

#endif /* CONFIG_AIKERNEL_RUNTIME */

#endif /* _AIKERNEL_AI_RUNTIME_H */
