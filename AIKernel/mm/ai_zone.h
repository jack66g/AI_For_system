// SPDX-License-Identifier: GPL-2.0
/*
 * ai_zone.h - AIKernel AI 专用内存区接口（Prompt 04，可选骨架）
 *
 * 为 AI 推理模型保留的快速内存区域（重构计划 3.11）。
 * CONFIG_AIKERNEL_AI_ZONE=n 时全部接口退化为 static inline 空函数。
 */

#ifndef _AIKERNEL_MM_AI_ZONE_H
#define _AIKERNEL_MM_AI_ZONE_H

#include "../core/ai_types.h"
#include <linux/types.h>

#define AI_ZONE_NAME_LEN  32

#ifdef CONFIG_AIKERNEL_AI_ZONE

/**
 * ai_zone_reserve() - 预留一个 AI 专用内存区域（骨架）
 * @name: 区域名（唯一）
 * @phys_start: 物理起始地址（0=由后续实现自动选择）
 * @size: 区域大小（字节）
 * @flags: 预留标志（0=普通，后续定义 AI_ZONE_F_* 位）
 *
 * 返回 AI_OK 或负错误码。本步仅登记，不实际映射。
 */
int ai_zone_reserve(const char *name, unsigned long phys_start,
		    unsigned long size, u32 flags);

/**
 * ai_zone_release() - 释放一个 AI 专用内存区域（骨架）
 * @name: 区域名
 *
 * 返回 AI_OK 或 AI_ERR_NOT_FOUND。
 */
int ai_zone_release(const char *name);

/**
 * ai_zone_query() - 查询 AI 专用内存区域信息（骨架）
 * @name: 区域名
 * @phys_start/@size/@flags: 输出参数（可空）
 *
 * 返回 AI_OK 或 AI_ERR_NOT_FOUND。
 */
int ai_zone_query(const char *name, unsigned long *phys_start,
		  unsigned long *size, u32 *flags);

/**
 * ai_zone_init() - 初始化 AI 专用内存区骨架
 *
 * 由 ai_mm_init() 调用（门控 CONFIG_AIKERNEL_AI_ZONE）。
 */
void ai_zone_init(void);

#else /* !CONFIG_AIKERNEL_AI_ZONE */

static inline int ai_zone_reserve(const char *name, unsigned long phys_start,
				  unsigned long size, u32 flags)
{ return AI_ERR_NOT_IMPLEMENTED; }
static inline int ai_zone_release(const char *name)
{ return AI_ERR_NOT_IMPLEMENTED; }
static inline int ai_zone_query(const char *name, unsigned long *phys_start,
				unsigned long *size, u32 *flags)
{ return AI_ERR_NOT_IMPLEMENTED; }
static inline void ai_zone_init(void) { }

#endif /* CONFIG_AIKERNEL_AI_ZONE */

#endif /* _AIKERNEL_MM_AI_ZONE_H */
