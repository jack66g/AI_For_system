// SPDX-License-Identifier: GPL-2.0
/*
 * ai_causal.h - AIKernel 决策因果链（数据计划 20.1/20.4，Prompt 13）
 *
 * 因果链 = {感知事件, 决策, 结果} 训练样本：trigger_event_id → decision_id
 * → outcome。内核侧通用导出接口先行：
 *   - ring（512 条，spinlock）恒存，/proc/ai/chains 数据源；
 *   - 进程上下文时经 kernel_write 追加写 /var/lib/aikernel/causal_chains/
 *     YYYY-MM-DD/chains_<seq>.csv（全量零脱敏；父目录不存在则仅 ring；
 *     parquet 由后续 aikd 读 /proc/ai/chains 落盘）。
 */

#ifndef _AIKERNEL_AI_CAUSAL_H
#define _AIKERNEL_AI_CAUSAL_H

#include "ai_types.h"
#include "ai_policy.h"
#include <linux/types.h>

#define AI_CAUSAL_RING_SIZE  512      /* 因果链 ring 容量 */
#define AI_CAUSAL_DEFAULT_DIR  "/var/lib/aikernel/causal_chains"

/* ---- 接口（实现于 ai_causal.c） ---- */

#ifdef CONFIG_AIKERNEL_RUNTIME

/**
 * ai_causal_chain_push() - 写入一条因果链记录（决策闭环第 5 步）
 * @rec: 完整决策记录（trigger→decision→outcome 全部字段）
 *
 * 恒写 ring（满覆盖最旧）；进程上下文（非原子）时追加写 CSV 文件
 * （按日目录，UTC 日期；文件头字段名在新建时写入）。
 * 返回 AI_OK 或负错误码。
 */
int ai_causal_chain_push(const struct ai_decision_record *rec);

/**
 * ai_causal_chain_read() - 读出因果链（最旧在前）
 * @buf: 接收缓冲（struct ai_decision_record 数组）
 * @cap: 缓冲容量（字节）
 * @out_count: 回填读出条数
 * @out_bytes: 回填实际拷贝字节数（可 NULL）
 *
 * 单读者语义；返回 AI_OK 或负错误码。
 */
int ai_causal_chain_read(void *buf, size_t cap,
			 u32 *out_count, size_t *out_bytes);

/**
 * ai_causal_set_export_dir() - 设置 CSV 导出根目录
 * @path: 目录路径（如 "/var/lib/aikernel/causal_chains"；默认值见上）
 *
 * 返回 AI_OK 或 AI_ERR_INVALID_ARG。
 */
int ai_causal_set_export_dir(const char *path);

/**
 * ai_causal_get_export_dir() - 读取 CSV 导出根目录
 * @path: 输出缓冲（AI_PATH_MAX）
 *
 * 返回 AI_OK 或负错误码。
 */
int ai_causal_get_export_dir(char *path);

/**
 * ai_causal_flush() - 关闭并重开 CSV 文件句柄（目录切换/测试用）
 *
 * 返回 AI_OK。
 */
int ai_causal_flush(void);

#else /* !CONFIG_AIKERNEL_RUNTIME */

static inline int ai_causal_chain_push(const struct ai_decision_record *rec)
{
	return AI_OK;
}
static inline int ai_causal_chain_read(void *buf, size_t cap,
				       u32 *out_count, size_t *out_bytes)
{
	if (out_count)
		*out_count = 0;
	if (out_bytes)
		*out_bytes = 0;
	return AI_OK;
}
static inline int ai_causal_set_export_dir(const char *path) { return AI_OK; }
static inline int ai_causal_get_export_dir(char *path)
{
	if (path)
		path[0] = '\0';
	return AI_OK;
}
static inline int ai_causal_flush(void) { return AI_OK; }

#endif /* CONFIG_AIKERNEL_RUNTIME */

#endif /* _AIKERNEL_AI_CAUSAL_H */
