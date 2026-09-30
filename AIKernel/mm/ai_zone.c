// SPDX-License-Identifier: GPL-2.0
/*
 * ai_zone.c - AIKernel AI 专用内存区预留骨架（Prompt 04，可选）
 *
 * 为 AI 推理模型保留的快速内存区域（重构计划 3.11）。
 * 本步仅建骨架：region 注册表 + 预留/释放/查询接口；
 * 实际的内存映射（buddy 预留 / memblock 保留 / CMA 挂接）与
 * AI Runtime 的"模型权重驻留"策略由后续 Prompt 填充。
 *
 * CONFIG_AIKERNEL_AI_ZONE=n 时本文件不参与构建，接口在
 * ai_zone.h 中退化为 static inline 空函数（零开销零回归）。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include "../core/ai_types.h"
#include "ai_zone.h"

#define AI_ZONE_MAX_REGIONS  8

struct ai_zone_region {
	char name[AI_ZONE_NAME_LEN];
	unsigned long phys_start;
	unsigned long size;
	u32 flags;
	bool in_use;
};

static struct ai_zone_region ai_zone_regions[AI_ZONE_MAX_REGIONS];
static struct mutex ai_zone_lock = __MUTEX_INITIALIZER(ai_zone_lock);

static struct ai_zone_region *ai_zone_find_free(void)
{
	int i;

	for (i = 0; i < AI_ZONE_MAX_REGIONS; i++)
		if (!ai_zone_regions[i].in_use)
			return &ai_zone_regions[i];
	return NULL;
}

static struct ai_zone_region *ai_zone_find(const char *name)
{
	int i;

	for (i = 0; i < AI_ZONE_MAX_REGIONS; i++)
		if (ai_zone_regions[i].in_use &&
		    strncmp(ai_zone_regions[i].name, name,
			    AI_ZONE_NAME_LEN) == 0)
			return &ai_zone_regions[i];
	return NULL;
}

int ai_zone_reserve(const char *name, unsigned long phys_start,
		    unsigned long size, u32 flags)
{
	struct ai_zone_region *r;
	int ret = AI_OK;

	if (!name || !name[0])
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_zone_lock);
	if (ai_zone_find(name)) {
		ret = AI_ERR_INVALID_ARG;   /* 重名 */
		goto out;
	}
	r = ai_zone_find_free();
	if (!r) {
		ret = AI_ERR_NO_CONFIG;   /* 槽满（本步骨架：8 上限） */
		goto out;
	}
	strscpy(r->name, name, AI_ZONE_NAME_LEN);
	r->phys_start = phys_start;
	r->size = size;
	r->flags = flags;
	r->in_use = true;
	pr_info("AIKernel: ai_zone reserved '%s' phys=0x%lx size=0x%lx flags=0x%x\n",
		name, phys_start, size, flags);
out:
	mutex_unlock(&ai_zone_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(ai_zone_reserve);

int ai_zone_release(const char *name)
{
	struct ai_zone_region *r;
	int ret = AI_OK;

	mutex_lock(&ai_zone_lock);
	r = ai_zone_find(name);
	if (!r) {
		ret = AI_ERR_NOT_FOUND;
		goto out;
	}
	r->in_use = false;
	pr_info("AIKernel: ai_zone released '%s'\n", name);
out:
	mutex_unlock(&ai_zone_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(ai_zone_release);

int ai_zone_query(const char *name, unsigned long *phys_start,
		  unsigned long *size, u32 *flags)
{
	struct ai_zone_region *r;
	int ret = AI_OK;

	mutex_lock(&ai_zone_lock);
	r = ai_zone_find(name);
	if (!r) {
		ret = AI_ERR_NOT_FOUND;
		goto out;
	}
	if (phys_start)
		*phys_start = r->phys_start;
	if (size)
		*size = r->size;
	if (flags)
		*flags = r->flags;
out:
	mutex_unlock(&ai_zone_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(ai_zone_query);

void ai_zone_init(void)
{
	/* 骨架：无默认区域。启动参数/设备树驱动的区域注册由后续 Prompt 落地。 */
	pr_info("AIKernel: ai_zone skeleton ready (%d slots)\n",
		AI_ZONE_MAX_REGIONS);
}
EXPORT_SYMBOL_GPL(ai_zone_init);
