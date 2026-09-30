// SPDX-License-Identifier: GPL-2.0
/*
 * ai_cgroup.h - AIKernel ai.cgroup 控制器接口（Prompt 02 骨架 + Prompt 12 填充）
 *
 * Prompt 02：占位接口 ai_cgroup_inference_enter()/exit()（只计数）。
 * Prompt 12：max_inferences 强制生效（超限 → AI_ERR_BUSY + limit_hit 遥测）；
 *            max_tops/mem_limit_mb 接口字段；ai_cgroup_query() 查询。
 */

#ifndef _AIKERNEL_AI_CGROUP_H
#define _AIKERNEL_AI_CGROUP_H

#include "ai_types.h"
#include <linux/cgroup.h>

/* ai_cgroup_query() 输出 */
struct ai_cgroup_info {
	u64 inferences;          /* 已发起推理计数 */
	u64 max_inferences;      /* 推理上限（0=禁止 U64_MAX=不限） */
	u64 max_tops;            /* TOPS 上限（0=不限，度量接入后强制） */
	u64 mem_limit_mb;        /* AI 显存上限 MB（0=不限） */
};

#ifdef CONFIG_AIKERNEL_CGROUP

/**
 * ai_cgroup_inference_enter() - 标记一次推理开始（限制强制）
 * @css: 发起推理任务所属的 ai css（可为 NULL=不计入）
 *
 * 有 css 时：若已发起计数 >= ai.max_inferences（0=禁止）→ 拒绝（AI_ERR_BUSY）
 * 并发射 cgroup_limit_hit 遥测；否则计数 +1。返回 AI_OK 或 AI_ERR_BUSY。
 */
int ai_cgroup_inference_enter(struct cgroup_subsys_state *css);

/**
 * ai_cgroup_inference_exit() - 标记一次推理结束（计数回减）
 * @css: 进入时传入的 css
 *
 * 返回 AI_OK。
 */
int ai_cgroup_inference_exit(struct cgroup_subsys_state *css);

/**
 * ai_cgroup_query() - 查询 ai cgroup 限制与用量
 * @css: 目标 ai css
 * @info: 输出（限制/用量全量）
 *
 * 返回 AI_OK 或 AI_ERR_INVALID_ARG。
 */
int ai_cgroup_query(struct cgroup_subsys_state *css,
		    struct ai_cgroup_info *info);

#else /* !CONFIG_AIKERNEL_CGROUP */

static inline int ai_cgroup_inference_enter(struct cgroup_subsys_state *css)
{
	return AI_OK;
}
static inline int ai_cgroup_inference_exit(struct cgroup_subsys_state *css)
{
	return AI_OK;
}
static inline int ai_cgroup_query(struct cgroup_subsys_state *css,
				  struct ai_cgroup_info *info)
{
	if (info)
		memset(info, 0, sizeof(*info));
	return AI_OK;
}

#endif /* CONFIG_AIKERNEL_CGROUP */

#endif /* _AIKERNEL_AI_CGROUP_H */
