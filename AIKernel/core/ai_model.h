// SPDX-License-Identifier: GPL-2.0
/*
 * ai_model.h - AIKernel 模型描述符与加载器抽象
 *
 * 双模式预留：
 *   AI_MODEL_SOURCE_EMBEDDED  - 内嵌轻量模型（TinyML，编译进内核或 initramfs 预置）
 *   AI_MODEL_SOURCE_USERSPACE - 用户态下发模型（经 aikctl/NETLINK_AI 下发，后续步骤）
 *
 * 模型注册/注销由 ai_runtime.c 的 ai_model_load() / ai_model_unload() 实现，
 * 本头文件只定义描述符与操作抽象。
 */

#ifndef _AIKERNEL_AI_MODEL_H
#define _AIKERNEL_AI_MODEL_H

#include "ai_types.h"
#include <linux/types.h>
#include <linux/refcount.h>
#include <linux/completion.h>

/* ---- 模型来源 ---- */

enum ai_model_source {
	AI_MODEL_SOURCE_EMBEDDED   = 0,  /* 内嵌轻量模型（TinyML） */
	AI_MODEL_SOURCE_USERSPACE  = 1,  /* 用户态下发模型 */
	AI_MODEL_SOURCE_MAX,
};

/* ---- 模型状态 ---- */

enum ai_model_state {
	AI_MODEL_STATE_UNLOADED = 0,  /* 未加载 */
	AI_MODEL_STATE_LOADED   = 1,  /* 已加载可用 */
	AI_MODEL_STATE_ERROR    = 2,  /* 加载失败/出错 */
	AI_MODEL_STATE_LOADING  = 3,  /* 已入册但 ops->load 未完成（读侧拒见） */
};

/* ---- 模型操作抽象（加载器接口） ---- */

struct ai_model;
struct ai_sense_input;
struct ai_think_result;

struct ai_model_ops {
	/* 模型加载（解析/初始化运行环境），成功返回 AI_OK */
	int (*load)(struct ai_model *model);
	/* 模型卸载（释放资源），成功返回 AI_OK */
	int (*unload)(struct ai_model *model);
	/* 推理：输入 input 长度 in_len，输出写入 output（容量 out_len），
	 * 实际输出长度经 out_len 回填；latency_ns 可选回填推理耗时。
	 * 成功返回 AI_OK，失败返回负错误码 */
	int (*infer)(struct ai_model *model,
		     const void *input, size_t in_len,
		     void *output, size_t *out_len, u64 *latency_ns);
	/* 决策推理（Prompt 13 新增，可选）：从感知数据推理出决策。
	 * 实现该回调的模型即"决策模型"（ai_runtime_think 使用）；
	 * sense 含触发事件与原始感知数据（全量零脱敏），res 填
	 * domain/decision_type/decision_data/confidence（框架回填
	 * decision_id/model_version）。成功返回 AI_OK。 */
	int (*think)(struct ai_model *model,
		     const struct ai_sense_input *sense,
		     struct ai_think_result *res);
};

/* ---- 模型描述符 ---- */

struct ai_model {
	char                    name[AI_MAX_NAME_LEN];  /* 模型名（注册表唯一） */
	u32                     version;                /* 模型版本 */
	enum ai_model_source    source;                 /* 内嵌/用户态下发 */
	const struct ai_model_ops *ops;                /* 加载器抽象 */
	void                    *private_data;          /* 模型私有数据 */
	u32                     id;                     /* runtime 分配句柄（load 时回填，1 起） */
	enum ai_model_state     state;                  /* 模型状态 */
	refcount_t              refcount;               /* 引用计数：注册表 1 + 在途读者 */
	bool                    dying;                  /* 已退册：拒绝新引用，等待旧引用归零 */
	struct completion       ref_done;               /* 引用归零完成量（unload 等待用） */
};

/* ---- 模型注册/注销（实现于 ai_runtime.c） ---- */

#ifdef CONFIG_AIKERNEL_RUNTIME

/**
 * ai_model_load() - 注册并加载一个模型到 AI Runtime
 * @model: 模型描述符（name/source/ops 必须有效）
 *
 * 先将模型以 LOADING 状态入册并回填 model->id，随后执行 ops->load；
 * 只有 ops->load 成功后状态才转 LOADED，此时才允许被 chat/infer/find 看到。
 * 任何读者看到 LOADED 时模型内部初始化已完成。ops->load 可睡眠，调用时
 * 不持自旋锁（仅持可睡眠的模型生命周期互斥量）。返回 AI_OK 或负错误码；
 * 失败时注册表项移除、model->state=ERROR，ops->load 的失败清理由 loader 负责。
 */
int ai_model_load(struct ai_model *model);

/**
 * ai_model_unload() - 从 AI Runtime 注销并卸载一个模型
 * @model: 之前 ai_model_load() 注册过的描述符
 *
 * 退册（拒绝新引用）→ 等待在途引用归零 → 调用 ops->unload。可能睡眠；
 * 不得在原子上下文调用。ops->unload 可释放 model 本身，返回后不可再解引用。
 * 返回 AI_OK 或负错误码（LOADING 中返回 AI_ERR_BUSY）。
 */
int ai_model_unload(struct ai_model *model);

/**
 * ai_model_find() - 按名称查找模型
 * @name: 模型名
 *
 * 返回模型 id（>=1），未找到返回 AI_ERR_NOT_FOUND。
 */
int ai_model_find(const char *name);

/**
 * ai_model_unload_by_name() - 按名称查找并注销模型
 * @name: 模型名
 *
 * 等价 ai_model_find() + ai_model_unload()，供 sysfs/procfs/NETLINK_AI
 * 等用户态接口按名操作。返回 AI_OK 或负错误码（AI_ERR_NOT_FOUND）。
 */
int ai_model_unload_by_name(const char *name);

/**
 * ai_mlp_model_create() - 从 AIKWMDL v1 权重文件创建真实稠密网络模型
 * @name: 模型名（注册表唯一）
 * @data: 文件内容（AIKWMDL v1：magic+层数+每层维度+float32 权重）
 * @data_len: 字节数
 *
 * 校验格式并量化加载（Q31 定点真前向，见 ai_model_mlp.c），注册进
 * AI Runtime。返回模型句柄（>=1）或负错误码；权重复制到模型自有缓冲，
 * data 生命周期与模型无关。实现于 ai_model_mlp.c。
 */
int ai_mlp_model_create(const char *name, const void *data, size_t data_len);

/**
 * ai_model_enumerate() - 按索引枚举已加载模型（/proc/ai/status 用）
 * @index: 0 起的索引
 * @name: 输出缓冲（AI_MAX_NAME_LEN）
 * @version: 可选输出版本
 * @source: 可选输出来源（enum ai_model_source）
 * @state: 可选输出状态（enum ai_model_state）
 *
 * 返回 AI_OK（有效）或 AI_ERR_NOT_FOUND（越界）。
 */
int ai_model_enumerate(unsigned int index, char *name, u32 *version,
		       u32 *source, u32 *state);

#else /* !CONFIG_AIKERNEL_RUNTIME */

static inline int ai_model_load(struct ai_model *model) { return AI_OK; }
static inline int ai_model_unload(struct ai_model *model) { return AI_OK; }
static inline int ai_model_find(const char *name) { return AI_ERR_NOT_FOUND; }
static inline int ai_model_unload_by_name(const char *name) { return AI_ERR_NOT_FOUND; }
static inline int ai_mlp_model_create(const char *name, const void *data,
				      size_t data_len)
{
	return AI_ERR_NOT_IMPLEMENTED;
}
static inline int ai_model_enumerate(unsigned int index, char *name,
				     u32 *version, u32 *source, u32 *state)
{
	return AI_ERR_NOT_FOUND;
}

#endif /* CONFIG_AIKERNEL_RUNTIME */

#endif /* _AIKERNEL_AI_MODEL_H */
