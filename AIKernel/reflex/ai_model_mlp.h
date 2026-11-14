// SPDX-License-Identifier: GPL-2.0
/*
 * ai_model_mlp.h - AIKernel MLP 模型（AIKWMDL v1）运行统计与元数据访问
 *
 * K6（WP-K6 施工 A）新增：ai_model_mlp.c 内新增的模型级统计（D2 推理
 * 预算/计数）与加载期元数据（D1 sha256/文件字节数）需要对 ai_runtime.c
 * （enumerate 扩展、-ETIME 回退记账）可见。共享头 ai_model.h 归主线
 * 冻约（不在 K6 施工 A 独占集内），故本头自带声明；仅被
 * ai_model_mlp.c（实现）与 ai_runtime.c（消费）包含，两文件均受
 * CONFIG_AIKERNEL_RUNTIME 门控，无需 !RUNTIME 桩。
 */

#ifndef _AIKERNEL_AI_MODEL_MLP_H
#define _AIKERNEL_AI_MODEL_MLP_H

#include "ai_model.h"
#include <linux/types.h>

/* sha256 摘要字节数（crypto/sha2.h 同值；自带常量避免头依赖扩散） */
#define AI_MODEL_SHA256_LEN	32

/**
 * struct ai_model_mlp_meta - MLP 模型运行统计与加载期元数据快照
 * @infer_n: 累计推理次数（含超时/出错尝试，atomic64 读快照）
 * @last_lat_ns: 最近一次前向耗时（纳秒；超时路径同样更新）
 * @timeout_n: 预算超时次数（infer 返 -ETIME 或 think 路径记账）
 * @file_bytes: 加载的 AIKWMDL 文件字节数
 * @sha256: 加载期文件 sha256（D1 白名单同源数据，32 字节）
 */
struct ai_model_mlp_meta {
	u64	infer_n;
	u64	last_lat_ns;
	u64	timeout_n;
	u64	file_bytes;
	u8	sha256[AI_MODEL_SHA256_LEN];
};

/**
 * ai_mlp_model_meta() - 读取 MLP 模型的统计/元数据快照
 * @model: 模型描述符（任意来源）
 * @out: 输出快照
 *
 * 仅当 @model 是 ai_model_mlp.c 注册的 MLP 模型时有效。
 * 返回 0 成功；-ENOENT 表示非 MLP 模型（调用方按零值呈现）。
 */
int ai_mlp_model_meta(const struct ai_model *model,
		      struct ai_model_mlp_meta *out);

/**
 * ai_mlp_model_infer() - 对 MLP 模型执行一次带显式预算的真实前向
 * @model: 模型描述符（任意来源）
 * @input/@in_len: 输入字节（float32 数组，首层 in_dim*4）
 * @output/@out_len: 输出缓冲（入参=容量，回填实际长度）
 * @latency_ns: 可选回填推理耗时
 * @budget_ns: 本次推理预算（纳秒；0=不限）
 *
 * 绕过 ops->infer 固定签名（共享头 ai_model.h 冻约），把每次调用的
 * 预算直送 Q31 前向（入场 ktime 锚定，层粒度检查，超时 -ETIME 不写
 * output）。调用方（ai_runtime_model_infer_by_name 第 7 参形态）从
 * 全局预算取值或显式传 1ns 强制超时。
 * 返回 AI_OK；-ETIME 预算超时；-ENODEV 表示非 MLP 模型（调用方回退
 * ops->infer 走全局预算）；其余负错误码同 ai_mlp_infer。
 */
int ai_mlp_model_infer(struct ai_model *model, const void *input,
		       size_t in_len, void *output, size_t *out_len,
		       u64 *latency_ns, u64 budget_ns);

/**
 * ai_mlp_model_note_timeout() - 对 MLP 模型记一次推理超时
 * @model: 超时的模型（think 回退路径由 ai_runtime 调用）
 *
 * D2 统计 timeout_n 的运行时侧记账入口；非 MLP 模型无处挂账，
 * 静默跳过。无返回值（记账尽力而为）。
 */
void ai_mlp_model_note_timeout(struct ai_model *model);

#endif /* _AIKERNEL_AI_MODEL_MLP_H */
