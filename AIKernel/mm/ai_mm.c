// SPDX-License-Identifier: GPL-2.0
/*
 * ai_mm.c - AIKernel 内存管理子系统核心（Prompt 04）
 *
 * A 轨：AI 内存决策框架。
 *   - 页面访问预测 / 碎片预测 / KSM 收益预测（占位启发式，后续步骤由
 *     AI Runtime 推理策略替换）；
 *   - 全部 ai_mm_*_hook() 空实现 = 原样放行（返回值不改变内核默认行为），
 *     本步只负责签名落地 + 决策计数 + 遥测采集。
 *
 * B 轨：第2类 内存管理感知 10 子类的发射辅助（ai_mm_emit_*）。
 *   - 每个辅助先经 ai_telemetry_sample_take() 做采样判定（与 emit 共用
 *     同一 per-CPU 计数器），判定通过才构建 payload（含 gfp 字符串），
 *     再 ai_telemetry_emit_direct() 直写 —— 被采样掉的事件零字符串开销；
 *   - 全部路径：不阻塞、不分配（无 GFP_KERNEL）、无锁；
 *   - OOM/错误报告路径埋点只构建栈上 payload + memcpy 入 ring，无分配。
 *
 * 铁律：CONFIG_AIKERNEL_TELEMETRY=n 时本文件仍编译（Hook 计数 + 空放行），
 * 发射辅助经 sample_take=false 全部跳过（零开销）。
 *
 * 拆分说明：本文件为拆分后的 A 轨决策框架（原 ai_mm.c 913 行）：可控参数
 * mm.swappiness、决策统计、页面访问/碎片/KSM 预测与全部 ai_mm_*_hook 空实现，
 * 以及子系统 init。B 轨发射辅助拆至 ai_mm_telemetry_alloc.c（分配/缺页）与
 * ai_mm_telemetry_reclaim.c（回收/THP/OOM/内存错误）。对外接口 ai_mm.h 不变。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/gfp_types.h>
#include <linux/pagemap.h>
#include <linux/oom.h>
#include <linux/string.h>
#include <linux/cma.h>
#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"
#include "ai_mm.h"
#include "../core/ai_control.h"
#include "../core/ai_decision.h"
#include <linux/ai_accessors.h>

/* ---- mm.swappiness 立即生效参数（经 mm/vmscan.c 门控访问器） ---- */

static int ai_mm_swappiness_apply(struct ai_control_param *p, s32 pid,
				  s64 value, s64 *eff)
{
	int cur = ai_vmscan_swappiness_get();

	if (value < 0 || value > 100)
		return AI_ERR_INVALID_ARG;
	ai_vmscan_swappiness_set((int)value);
	if (eff)
		*eff = ai_vmscan_swappiness_get();
	pr_info("AIKernel: swappiness %d -> %lld (pid=%d)\n", cur, value, pid);
	return AI_OK;
}


/* ---- mm.readahead 立即生效参数（mm/backing-dev.c 门控访问器） ----
 * value 单位 KB（与 /sys/class/bdi/<dev> 下 read_ahead_kb 节点同源同
 * 值），写全部已注册 bdi 的 ra_pages（页单位，kb 右移 PAGE_SHIFT-10），
 * 对新 readahead 立即生效。 */
static int ai_mm_readahead_apply(struct ai_control_param *p, s32 pid,
				 s64 value, s64 *eff)
{
	unsigned long kb = 0;
	int rc;

	if (value < 0 || value > 4096)
		return AI_ERR_INVALID_ARG;
	rc = ai_bdi_ra_pages_set((unsigned long)value, &kb);
	if (rc)
		return AI_ERR_GENERIC;
	*eff = (s64)kb;
	pr_info("AIKernel: mm.readahead %lld KB -> %lu KB (all bdi)\n",
		value, kb);
	return AI_OK;
}

/* ---- mm.reclaim_prio 立即生效参数（vmscan 缓存回收倾向） ----
 * 语义选择（swappiness 邻接的 vmscan 参数）：value 直接映射
 * sysctl_vfs_cache_pressure（dentry/inode 缓存回收压力，/proc/sys/vm/
 * vfs_cache_pressure 同源）：0=绝不回收缓存（挂起倾向）… 100=系统默认
 * 倾向。选择理由：vmscan 内部 scan priority（DEF_PRIORITY）为静态
 * 逐节点状态、无运行时写入口；vfs_cache_pressure 是相邻的真实回收
 * 倾向旋钮且观测面明确。 */
static int ai_mm_reclaim_prio_apply(struct ai_control_param *p, s32 pid,
				    s64 value, s64 *eff)
{
	if (value < 0 || value > 100)
		return AI_ERR_INVALID_ARG;
	if (ai_vfs_cache_pressure_set((int)value))
		return AI_ERR_GENERIC;
	*eff = value;
	pr_info("AIKernel: mm.reclaim_prio %lld -> vfs_cache_pressure %lld\n",
		value, value);
	return AI_OK;
}

/* ---- mm.thp 立即生效参数（经 mm/huge_memory.c 门控访问器） ----
 * value 0/1/2 = never/madvise/always，改写 transparent_hugepage_flags 的
 * enabled 位（TRANSPARENT_HUGEPAGE_FLAG 与 REQ_MADV 互斥，语义同
 * huge_memory.c enabled sysfs store，仅对新映射生效）；范围 0~2 由注册表
 * clamp。CONFIG_TRANSPARENT_HUGEPAGE=n 时本函数剔除，注册退回接口预留。 */
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static int ai_mm_thp_apply(struct ai_control_param *p, s32 pid,
			   s64 value, s64 *eff)
{
	int cur = ai_thp_flags_get();

	if (value < AI_THP_MODE_NEVER || value > AI_THP_MODE_ALWAYS)
		return AI_ERR_INVALID_ARG;
	ai_thp_flags_set((int)value);
	if (eff)
		*eff = ai_thp_flags_get();
	pr_info("AIKernel: thp enabled %d -> %lld (pid=%d)\n", cur, value, pid);
	return AI_OK;
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

/* ==================================================================
 * 决策统计（近似计数，非精确账目）
 * ================================================================== */

static struct ai_mm_stats ai_mm_stats;

void ai_mm_stats_read(struct ai_mm_stats *st)
{
	if (!st)
		return;
	*st = ai_mm_stats;
}
EXPORT_SYMBOL_GPL(ai_mm_stats_read);

/* ==================================================================
 * A 轨：决策框架（占位启发式 + 默认放行 Hook）
 * ================================================================== */

static struct {
	u64 last_address;
	u8 last_type;
} ai_mm_access_predict;

int ai_mm_predict_page_access(unsigned long address, u8 fault_type)
{
	/* 占位启发式：同一地址连续写缺页 → 预测为热页面 */
	if (ai_mm_access_predict.last_address == address &&
	    ai_mm_access_predict.last_type == fault_type)
		return 1;
	ai_mm_access_predict.last_address = address;
	ai_mm_access_predict.last_type = fault_type;
	return 0;
}
EXPORT_SYMBOL_GPL(ai_mm_predict_page_access);

int ai_mm_predict_fragmentation(struct zone *zone)
{
	unsigned long free_pages, high_pages = 0;
	int order;

	if (!zone)
		return 0;

	free_pages = zone_managed_pages(zone);
	if (!free_pages)
		return 0;
	for (order = pageblock_order; order <= MAX_PAGE_ORDER; order++)
		high_pages += zone->free_area[order].nr_free;
	if (high_pages * 100 < free_pages / 10)
		return 1;   /* 高阶页占比 < 0.1%：碎片严重，建议 MOVABLE */
	return 0;
}
EXPORT_SYMBOL_GPL(ai_mm_predict_fragmentation);

int ai_mm_predict_ksm_benefit(struct page *page)
{
	return 0;   /* 占位：本步不做强制合并建议 */
}
EXPORT_SYMBOL_GPL(ai_mm_predict_ksm_benefit);

/* ---- Hook：空实现 = 原样放行 ---- */

void ai_mm_fault_hook(struct vm_fault *vmf, u8 fault_type)
{
	WRITE_ONCE(ai_mm_stats.fault_hook_calls,
		   READ_ONCE(ai_mm_stats.fault_hook_calls) + 1);
	/* AI 推理占位：本步不修改 vmf */
}
EXPORT_SYMBOL_GPL(ai_mm_fault_hook);

unsigned long ai_mm_readahead_hook(struct readahead_control *ractl,
				   unsigned long nr_to_read,
				   unsigned long lookahead_size)
{
	WRITE_ONCE(ai_mm_stats.readahead_hook_calls,
		   READ_ONCE(ai_mm_stats.readahead_hook_calls) + 1);

	/* AI 决策注入（W3 挂点4 预读窗口调整）：按当前任务分类槽调窗口
	 * —— 交互式 ×2 一档（延迟敏感），批处理 ÷2 一档（省内存带宽）；
	 * 钳 AI_DEC_RA_SHIFT_MAX=1 档，下限 1 页防 0、上限 ULONG_MAX/2
	 * 防溢出。三层开关默认关 = 原样返回（原生行为逐位一致）；决策源
	 * （启发式→第二阶段模型）经 ai_decision_query() 同一接口替换。 */
	{
		struct ai_hook_ctx hctx = { .pid = task_pid_nr(current) };
		s32 shift = ai_decision_query(AI_HOOK_MM_READAHEAD, &hctx);
		unsigned long out = nr_to_read;

		if (shift > 0) {
			if (nr_to_read <= (ULONG_MAX >> 1))
				out = nr_to_read << 1;
		} else if (shift < 0) {
			out = nr_to_read > 1 ? nr_to_read >> 1 : 1;
		}
		if (out != nr_to_read) {
			ai_decision_note_effect(AI_HOOK_MM_READAHEAD,
						(s64)nr_to_read, (s64)out);
			return out;
		}
	}
	return nr_to_read;   /* 原样返回 */
}
EXPORT_SYMBOL_GPL(ai_mm_readahead_hook);

void ai_mm_reclaim_hook(int nid, u8 mode, u8 priority,
			unsigned long nr_to_reclaim)
{
	WRITE_ONCE(ai_mm_stats.reclaim_hook_calls,
		   READ_ONCE(ai_mm_stats.reclaim_hook_calls) + 1);
	/* AI 推理占位：本步不修改扫描参数 */
}
EXPORT_SYMBOL_GPL(ai_mm_reclaim_hook);

bool ai_mm_workingset_hook(struct folio *folio, void *shadow, bool activate)
{
	WRITE_ONCE(ai_mm_stats.workingset_hook_calls,
		   READ_ONCE(ai_mm_stats.workingset_hook_calls) + 1);
	return activate;   /* 原样返回 */
}
EXPORT_SYMBOL_GPL(ai_mm_workingset_hook);

int ai_mm_alloc_hook(struct zone *zone, unsigned int order,
		     gfp_t gfp_flags, int migratetype)
{
	WRITE_ONCE(ai_mm_stats.alloc_hook_calls,
		   READ_ONCE(ai_mm_stats.alloc_hook_calls) + 1);
	return migratetype;   /* 原样返回 */
}
EXPORT_SYMBOL_GPL(ai_mm_alloc_hook);

void ai_mm_thp_hook(struct mm_struct *mm, unsigned long address, u8 *decision)
{
	WRITE_ONCE(ai_mm_stats.thp_hook_calls,
		   READ_ONCE(ai_mm_stats.thp_hook_calls) + 1);
	if (decision)
		*decision = 0;   /* 本步不干预 */
}
EXPORT_SYMBOL_GPL(ai_mm_thp_hook);

int ai_mm_ksm_hook(struct page *page, unsigned long address)
{
	WRITE_ONCE(ai_mm_stats.ksm_hook_calls,
		   READ_ONCE(ai_mm_stats.ksm_hook_calls) + 1);
	return 0;   /* 本步不干预合并决策 */
}
EXPORT_SYMBOL_GPL(ai_mm_ksm_hook);

int ai_mm_oom_hook(struct oom_control *oc)
{
	WRITE_ONCE(ai_mm_stats.oom_hook_calls,
		   READ_ONCE(ai_mm_stats.oom_hook_calls) + 1);
	return 0;   /* 本步接受内核选择；AI 换人建议后续步骤接通 */
}
EXPORT_SYMBOL_GPL(ai_mm_oom_hook);

unsigned long ai_mm_cma_hook(struct cma *cma, unsigned long count)
{
	WRITE_ONCE(ai_mm_stats.cma_hook_calls,
		   READ_ONCE(ai_mm_stats.cma_hook_calls) + 1);
	return count;   /* 原样返回 */
}
EXPORT_SYMBOL_GPL(ai_mm_cma_hook);

/* ==================================================================
 * 初始化：默认采样率（热路径事件采样，低频事件全量）
 * ================================================================== */

static int __init ai_mm_init(void)
{
	/* 幂等：CONFIG_AIKERNEL_RUNTIME 已在 start_kernel 调用过则无操作 */
	ai_telemetry_init();

	/* 热路径事件默认采样率（其余事件全量）：
	 * 单页分配 1/32、slab 对象 1/64、filemap_read 1/16、缺页延迟 1/16
	 * —— 控制性能预算同时保留统计意义（page_fault 本身全量，见数据计划 2.3） */
	ai_telemetry_set_sample_rate(AI_CAT_MM, AI_EV_PAGE_ALLOC, 32);
	ai_telemetry_set_sample_rate(AI_CAT_MM, AI_EV_SLAB_ALLOC, 64);
	ai_telemetry_set_sample_rate(AI_CAT_MM, AI_EV_PAGE_CACHE, 16);

	/* 可控制参数表（数据计划 20.3 内存域）：mm.swappiness 立即生效
	 * （经 mm/vmscan.c 门控访问器），其余接口预留（安全/记录全量生效，
	 * 内核行为接线在后续子系统步骤） */
	ai_control_register("mm.swappiness", AI_POLICY_DOMAIN_MM,
			    AI_CTRL_F_REAL, 0, 100, 60,
			    ai_mm_swappiness_apply);
	ai_control_register("mm.readahead", AI_POLICY_DOMAIN_MM,
			    AI_CTRL_F_REAL, 0, 4096, 128,
			    ai_mm_readahead_apply);
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	ai_control_register("mm.thp", AI_POLICY_DOMAIN_MM,
			    AI_CTRL_F_REAL, 0, 2, AI_THP_MODE_ALWAYS,
			    ai_mm_thp_apply);
#else
	ai_control_register("mm.thp", AI_POLICY_DOMAIN_MM, 0,
			    0, 2, 1, NULL);
#endif
	ai_control_register("mm.reclaim_prio", AI_POLICY_DOMAIN_MM,
			    AI_CTRL_F_REAL, 0, 100, 60,
			    ai_mm_reclaim_prio_apply);

	pr_info("AIKernel: mm subsystem ready (AI hooks + telemetry)\n");
	return 0;
}
late_initcall(ai_mm_init);
