// SPDX-License-Identifier: GPL-2.0
/*
 * ai_features.c - BPF_MAP_TYPE_AI_FEATURES map 实现（WP-K7 §2 D3）
 *
 * 自定义 per-CPU array map（仿 ai_map.c 手法：struct bpf_map 内嵌+自有
 * ops），只读特征快照出口：
 *   - 固定 schema：value_size=sizeof(struct ai_feature_vec)、
 *     max_entries=nr_cpu_ids，alloc_check 一律钳制（调用方传 0 亦合法，
 *     传非 0 值被静默改为内核侧唯一合法值——schema 冻结，无协商面）；
 *   - lookup_elem(key=u32 cpu)：把该 CPU 槽以 seqlock 读法复制到本 CPU
 *     弹跳缓冲后返回（快照语义，读者拿到稳定副本）；
 *   - update_elem/delete_elem 一律 -EACCES：生产者唯一（采样器尾的
 *     ai_features_sample_publish()），map 面对用户态只读；
 *   - 存储归属（设计册 D3 未明确实例归属，本实现定案为全局特征区+map
 *     只读视图，偏差登记）：特征槽数据在全局 per-CPU 区（init 一次性
 *     分配，与 map 实例生命周期解耦）——多实例共存均读到同一数据，
 *     无实例时发布照常进行（探针 create/read 各自独立进程也可读到
 *     连续 seq，K7P3 验收形态）。
 *
 * 发布协议（seqlock 写序）：seq 奇数相=写窗开启，偶数相=发布完成；
 * 读者复制前后校验 seq 一致（AI_FEAT_SNAPSHOT_RETRIES 次重试，1Hz
 * 生产者下写窗极窄）。seq 每次发布 +2（单调性验收口径）。
 *
 * cache_misses：tcg 无 vPMU（勘探 §1.5），恒 0 且 valid_bits 不置
 * CACHE 位——诚实登记，v2 接 perf_event_create_kernel_counter。
 *
 * 零回归：本文件仅 CONFIG_AIKERNEL_BPF=y 构建；bpf_types.h 注册行
 * #ifdef 包裹（n 配置 bpf_map_types[] 该位 NULL，map_create -EINVAL，
 * 与基线一致）；include/linux/bpf.h 的 BPF_MAP_TYPE 宏在 bpf.h 包
 * bpf_types.h 展开时自动生成 extern 声明（AI_MODEL 同机制，无需手工
 * extern）；syscall.c 白名单 case 与 AI_MODEL 同组 CAP_BPF。
 */

#include <linux/atomic.h>
#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/seq_file.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/timekeeping.h>

#include "../subsys/bpf/ai_bpf.h"
#include "ai_features.h"

_Static_assert(sizeof(struct ai_feature_vec) == 48,
	       "ai_feature_vec schema 冻结 48B（探针 k7feat.c 按偏移镜像）");

/* 快照读重试上限（写窗=数十 ns 级；8 次覆盖最坏调度噪声） */
#define AI_FEAT_SNAPSHOT_RETRIES	8

/*
 * 全局特征槽区：与 map 实例解耦（见文件头「存储归属」）。
 * alloc 失败保持 NULL：publish 静默跳过、lookup 返回零值槽——
 * 「无数据」是诚实态，不 panic 不告警轰炸（init 已 pr_warn 一次）。
 */
static struct ai_feature_vec __percpu *ai_features_vecs;

struct ai_features_map {
	struct bpf_map map;
	/* per-CPU 读侧弹跳缓冲：lookup 在本 CPU 复制出稳定快照后返回 */
	struct ai_feature_vec __percpu *snap;
};

/* ---- 单槽 seqlock 写（发布侧唯一调用点 ai_features_sample_publish） --- */

static void ai_feature_vec_store(struct ai_feature_vec *v, u64 now,
				 u64 lat_ewma_ns, u32 iowait_pct,
				 u32 psi_mem_some, u32 valid_bits)
{
	u32 seq = READ_ONCE(v->seq) + 1;	/* 偶→奇：写窗开启 */

	WRITE_ONCE(v->seq, seq);
	smp_wmb();
	WRITE_ONCE(v->ts, now);
	WRITE_ONCE(v->lat_ewma_ns, lat_ewma_ns);
	WRITE_ONCE(v->iowait_pct, iowait_pct);
	WRITE_ONCE(v->psi_mem_some, psi_mem_some);
	WRITE_ONCE(v->cache_misses, 0);
	WRITE_ONCE(v->valid_bits, valid_bits);
	WRITE_ONCE(v->rsv, 0);
	smp_wmb();
	WRITE_ONCE(v->seq, seq + 1);		/* 奇→偶：发布完成 */
}

/**
 * ai_features_sample_publish() - 发布一拍特征快照（采样器尾 1Hz 调用）
 * @lat_ewma_ns: sched latency EWMA（ns；ai_k4_lat_ewma 现成源，系统级）
 * @iowait_pct: 调用方所在 CPU 的 iowait 百分比 0..100
 * @psi_mem_some: PSI mem some avg10 定点值（2048 制，ai_psi_read 原生口径）
 *
 * 集成契约（主会话补采样器尾一行）：ai_sched_metrics_sample_once() 尾
 * （ai_k4_vruntime_settle/ai_effect_tick 之后）调用，lat=READ_ONCE(
 * ai_k4_lat_ewma)、iowait=本轮本 CPU iowait_pct（采样 kthread 上下文，
 * 无本轮值则传 0）、psi=PSI_MEM 轮的 some_avg10（需自
 * ai_sched_sample_psi() 上提局部变量或采样器尾重读一次 ai_psi_read）。
 *
 * 语义：本 CPU 槽全字段+LAT|IOWAIT|PSI 位；其余 CPU 槽广播 lat/psi
 * （系统级源）+LAT|PSI 位（IOWAIT 位不置——非该 CPU 实测，诚实粒度）。
 * CONFIG_AIKERNEL_BPF=n 时空内联（ai_features.h）。
 */
void ai_features_sample_publish(u64 lat_ewma_ns, u32 iowait_pct,
				u32 psi_mem_some)
{
	u64 now = ktime_get_ns();
	int cpu, other;

	if (!READ_ONCE(ai_features_vecs))
		return;

	preempt_disable();
	cpu = smp_processor_id();

	/* 本 CPU 槽：全字段 */
	ai_feature_vec_store(this_cpu_ptr(ai_features_vecs), now,
			     lat_ewma_ns, iowait_pct, psi_mem_some,
			     AI_FEAT_VALID_LAT | AI_FEAT_VALID_IOWAIT |
			     AI_FEAT_VALID_PSI);

	/* 广播面：lat/psi 系统级源 → 其余槽（iowait 位不置） */
	for_each_possible_cpu(other) {
		if (other == cpu)
			continue;
		ai_feature_vec_store(per_cpu_ptr(ai_features_vecs, other),
				     now, lat_ewma_ns, 0, psi_mem_some,
				     AI_FEAT_VALID_LAT | AI_FEAT_VALID_PSI);
	}
	preempt_enable();
}
EXPORT_SYMBOL_GPL(ai_features_sample_publish);

/* ---- map ops -------------------------------------------------------------- */

static int ai_features_map_alloc_check(union bpf_attr *attr)
{
	if (attr->key_size != sizeof(u32))
		return -EINVAL;
	/* 固定 schema 钳制：无论传入何值，一律内核侧唯一合法值 */
	attr->value_size = sizeof(struct ai_feature_vec);
	attr->max_entries = nr_cpu_ids;
	if (attr->map_flags)
		return -EINVAL;
	return 0;
}

static u64 ai_features_map_footprint(void)
{
	/* 审计口径：map 头 + 全局槽区 + 本实例弹跳缓冲（槽区跨实例共享，
	 * 按每实例上限口径计入——保守上界，供 memlock/遥测记账） */
	return sizeof(struct ai_features_map) +
		(u64)nr_cpu_ids * sizeof(struct ai_feature_vec) * 2;
}

static struct bpf_map *ai_features_map_alloc(union bpf_attr *attr)
{
	struct ai_features_map *fmap;

	fmap = bpf_map_area_alloc(sizeof(*fmap), bpf_map_attr_numa_node(attr));
	if (!fmap)
		return ERR_PTR(-ENOMEM);

	fmap->snap = alloc_percpu(struct ai_feature_vec);
	if (!fmap->snap) {
		bpf_map_area_free(fmap);
		return ERR_PTR(-ENOMEM);
	}

	/* copy mandatory map attributes（钳制后的 attr） */
	bpf_map_init_from_attr(&fmap->map, attr);

	ai_telemetry_ai_map_create(attr->map_type, attr->max_entries,
				   attr->key_size, attr->value_size,
				   ai_features_map_footprint(),
				   attr->map_name);
	return &fmap->map;
}

static void ai_features_map_free(struct bpf_map *map)
{
	struct ai_features_map *fmap =
		container_of(map, struct ai_features_map, map);

	free_percpu(fmap->snap);
	bpf_map_area_free(fmap);
}

static void *ai_features_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct ai_features_map *fmap =
		container_of(map, struct ai_features_map, map);
	struct ai_feature_vec *live, *snap;
	u32 cpu = *(u32 *)key;
	u32 seq;
	int i;

	if (!READ_ONCE(ai_features_vecs))
		return NULL;
	if (cpu >= map->max_entries)
		return NULL;
	live = per_cpu_ptr(ai_features_vecs, cpu);

	/* seqlock 读法：复制前后 seq 一致才可信；重试穷尽则返回最后一份
	 * 尽力副本（1Hz 生产者下实际不可达，防御性登记） */
	preempt_disable();
	snap = this_cpu_ptr(fmap->snap);
	for (i = 0; i < AI_FEAT_SNAPSHOT_RETRIES; i++) {
		seq = smp_load_acquire(&live->seq);
		if (!(seq & 1)) {
			*snap = *live;
			if (smp_load_acquire(&live->seq) == seq)
				break;
		}
		cpu_relax();
	}
	preempt_enable();
	return snap;
}

static long ai_features_map_update_elem(struct bpf_map *map, void *key,
					void *value, u64 flags)
{
	/* 只读快照出口：生产者唯一（采样器尾 publish），map 面一律拒写 */
	return -EACCES;
}

static long ai_features_map_delete_elem(struct bpf_map *map, void *key)
{
	return -EACCES;
}

static int ai_features_map_get_next_key(struct bpf_map *map, void *key,
					void *next_key)
{
	u32 index = key ? *(u32 *)key : U32_MAX;

	if (index >= map->max_entries - 1) {
		*(u32 *)next_key = 0;
		return -ENOENT;
	}
	*(u32 *)next_key = index + 1;
	return 0;
}

static void ai_features_map_seq_show_elem(struct bpf_map *map, void *key,
					  struct seq_file *m)
{
	const struct ai_feature_vec *v;
	u32 i;

	rcu_read_lock();

	v = ai_features_map_lookup_elem(map, key);
	if (!v) {
		rcu_read_unlock();
		return;
	}

	seq_printf(m, "%u: [", *(u32 *)key);
	for (i = 0; i < map->value_size; i++)
		seq_printf(m, "%02x", ((const u8 *)v)[i]);
	seq_puts(m, "]\n");

	rcu_read_unlock();
}

static u64 ai_features_map_mem_usage(const struct bpf_map *map)
{
	return ai_features_map_footprint();
}

BTF_ID_LIST_SINGLE(ai_features_map_btf_ids, struct, bpf_map)

const struct bpf_map_ops ai_features_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = ai_features_map_alloc_check,
	.map_alloc = ai_features_map_alloc,
	.map_free = ai_features_map_free,
	.map_get_next_key = ai_features_map_get_next_key,
	.map_lookup_elem = ai_features_map_lookup_elem,
	.map_update_elem = ai_features_map_update_elem,
	.map_delete_elem = ai_features_map_delete_elem,
	.map_seq_show_elem = ai_features_map_seq_show_elem,
	.map_mem_usage = ai_features_map_mem_usage,
	.map_btf_id = &ai_features_map_btf_ids[0],
};

/* ---- init ----------------------------------------------------------------- */

static int __init ai_features_init(void)
{
	ai_features_vecs = alloc_percpu(struct ai_feature_vec);
	if (!ai_features_vecs) {
		pr_warn("AIKernel: ai_features percpu alloc failed (feature publish disabled)\n");
		return -ENOMEM;
	}
	pr_info("AIKernel: ai_features store ready (ncpu=%u vec=%zuB)\n",
		nr_cpu_ids, sizeof(struct ai_feature_vec));
	return 0;
}
subsys_initcall(ai_features_init);
