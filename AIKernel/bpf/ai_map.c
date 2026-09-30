// SPDX-License-Identifier: GPL-2.0
/*
 * ai_map.c - AIKernel BPF_MAP_TYPE_AI_MODEL map 实现（Prompt 11，重构计划 模块13.4）
 *
 * BPF 侧存储 AI 模型参数：数组式布局（key = u32 索引，value = 模型参数块），
 * 支持 map_lookup_elem/map_update_elem（load/store）。语义与 array map 对齐：
 *   - map_delete_elem 返回 -EINVAL（数组式不支持删除）；
 *   - 元素写读由 per-map raw_spinlock 保护（value 含 bpf_spin_lock 时走
 *     copy_map_value_locked 语义，copy_map_value 内部处理）；
 *   - value_size 上限 1MB（AI 模型参数载荷），max_entries >= 1；
 *   - 单次分配（struct + elems 柔性数组），bpf_map_area_alloc 清零。
 *
 * 零回归：本文件仅 CONFIG_AIKERNEL_BPF=y 构建；include/linux/bpf_types.h
 * 的注册行 #ifdef 包裹（n 配置 bpf_map_types[] 该位为 NULL，map_create 返回
 * -EINVAL，与基线一致）；验证器走 map_lookup_elem/map_update_elem 通用默认
 * 路径（check_map_func_compatibility map 视角 default:break），零特判。
 */

#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>

#include "ai_bpf.h"

#define AI_MODEL_VALUE_MAX	(1024 * 1024)	/* 单值上限 1MB（模型参数块） */
#define AI_MODEL_MAP_MEM_MAX	(256ULL * 1024 * 1024)	/* map 总内存上限 256MB */

struct ai_model_map {
	struct bpf_map map;
	raw_spinlock_t lock;		/* 元素写读保护 */
	u32 elem_size;			/* round_up(value_size, 8) */
	/* elems 柔性数组：max_entries * elem_size 连续区（单次分配清零） */
	u8 elems[] __aligned(8);
};

static void *ai_model_map_elem_ptr(struct ai_model_map *amap, u32 index)
{
	return amap->elems + (u64)amap->elem_size * index;
}

static void *ai_model_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct ai_model_map *amap = container_of(map, struct ai_model_map, map);
	u32 index = *(u32 *)key;

	if (index >= map->max_entries)
		return NULL;
	return ai_model_map_elem_ptr(amap, index);
}

static long ai_model_map_update_elem(struct bpf_map *map, void *key, void *value,
				     u64 flags)
{
	struct ai_model_map *amap = container_of(map, struct ai_model_map, map);
	u32 index = *(u32 *)key;
	void *elem;
	unsigned long irq_flags;

	if (flags != BPF_ANY && flags != BPF_NOEXIST && flags != BPF_EXIST)
		return -EINVAL;
	if (index >= map->max_entries)
		return -E2BIG;

	elem = ai_model_map_elem_ptr(amap, index);
	raw_spin_lock_irqsave(&amap->lock, irq_flags);
	copy_map_value(map, elem, value);
	raw_spin_unlock_irqrestore(&amap->lock, irq_flags);

	return 0;
}

static long ai_model_map_delete_elem(struct bpf_map *map, void *key)
{
	return -EINVAL;   /* 数组式 map 不支持删除（与 array map 一致） */
}

static int ai_model_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	u32 index = key ? *(u32 *)key : U32_MAX;

	if (index >= map->max_entries - 1) {
		*(u32 *)next_key = 0;
		return -ENOENT;
	}
	*(u32 *)next_key = index + 1;
	return 0;
}

static int ai_model_map_alloc_check(union bpf_attr *attr)
{
	if (attr->key_size != sizeof(u32))
		return -EINVAL;
	if (attr->value_size == 0 || attr->value_size > AI_MODEL_VALUE_MAX)
		return -E2BIG;
	if (attr->max_entries == 0)
		return -EINVAL;
	if (attr->map_flags)
		return -EINVAL;
	return 0;
}

static struct bpf_map *ai_model_map_alloc(union bpf_attr *attr)
{
	struct ai_model_map *amap;
	u64 array_size;
	u32 elem_size;

	elem_size = round_up(attr->value_size, 8);

	array_size = sizeof(*amap) + (u64)attr->max_entries * elem_size;
	if (array_size > AI_MODEL_MAP_MEM_MAX)
		return ERR_PTR(-E2BIG);

	amap = bpf_map_area_alloc(array_size, bpf_map_attr_numa_node(attr));
	if (!amap)
		return ERR_PTR(-ENOMEM);

	raw_spin_lock_init(&amap->lock);
	amap->elem_size = elem_size;

	/* copy mandatory map attributes */
	bpf_map_init_from_attr(&amap->map, attr);

	ai_telemetry_ai_map_create(attr->map_type, attr->max_entries,
				   attr->key_size, attr->value_size,
				   array_size, attr->map_name);
	return &amap->map;
}

static void ai_model_map_free(struct bpf_map *map)
{
	struct ai_model_map *amap = container_of(map, struct ai_model_map, map);

	bpf_map_area_free(amap);
}

static void ai_model_map_seq_show_elem(struct bpf_map *map, void *key,
				       struct seq_file *m)
{
	const u8 *data;
	u32 index;
	u32 i;

	rcu_read_lock();

	data = ai_model_map_lookup_elem(map, key);
	if (!data) {
		rcu_read_unlock();
		return;
	}

	index = *(u32 *)key;
	seq_printf(m, "%u: [", index);
	for (i = 0; i < map->value_size; i++)
		seq_printf(m, "%02x", data[i]);
	seq_puts(m, "]\n");

	rcu_read_unlock();
}

static u64 ai_model_map_mem_usage(const struct bpf_map *map)
{
	struct ai_model_map *amap = container_of(map, struct ai_model_map, map);

	return sizeof(*amap) + (u64)map->max_entries * amap->elem_size;
}

BTF_ID_LIST_SINGLE(ai_model_map_btf_ids, struct, bpf_map)

const struct bpf_map_ops ai_model_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = ai_model_map_alloc_check,
	.map_alloc = ai_model_map_alloc,
	.map_free = ai_model_map_free,
	.map_get_next_key = ai_model_map_get_next_key,
	.map_lookup_elem = ai_model_map_lookup_elem,
	.map_update_elem = ai_model_map_update_elem,
	.map_delete_elem = ai_model_map_delete_elem,
	.map_seq_show_elem = ai_model_map_seq_show_elem,
	.map_mem_usage = ai_model_map_mem_usage,
	.map_btf_id = &ai_model_map_btf_ids[0],
};
