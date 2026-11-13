// SPDX-License-Identifier: GPL-2.0
/*
 * ai_mm.c - AIKernel 内存管理子系统核心（Prompt 04）
 *
 * A 轨：AI 内存决策框架。
 *   - 页面访问预测 / 碎片预测 / KSM 收益预测（占位启发式，后续步骤由
 *     AI Runtime 推理策略替换）；
 *   - readahead 真决策钩（W3 挂点4 预读窗口调整）+ 决策计数 + 遥测采集。
 *     K5（2026-11）删除四个空桩门控钩，见 AIKernel/CHANGELOG.md。
 *
 * B 轨：第2类 内存管理感知 10 子类的发射辅助（ai_mm_emit_*）。
 *   - 每个辅助先经 ai_telemetry_sample_take() 做采样判定（与 emit 共用
 *     同一 per-CPU 计数器），判定通过才构建 payload（含 gfp 字符串），
 *     再 ai_telemetry_emit_direct() 直写 —— 被采样掉的事件零字符串开销；
 *   - 全部路径：不阻塞、不分配（无 GFP_KERNEL）、无锁；
 *   - OOM/错误报告路径埋点只构建栈上 payload + memcpy 入 ring，无分配。
 *
 * 铁律：CONFIG_AIKERNEL_TELEMETRY=n 时本文件仍编译（决策计数照常），
 * 发射辅助经 sample_take=false 全部跳过（零开销）。
 *
 * 拆分说明：本文件为拆分后的 A 轨决策框架（原 ai_mm.c 913 行）：可控参数
 * mm.swappiness、决策统计、页面访问/碎片/KSM 预测与 readahead 决策钩，
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
#include "../core/ai_effect.h"
#include <linux/ai_accessors.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/psi.h>

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

/* K2a（KERNEL-K2-DESIGN D7）：mm.swappiness 读回真值——经 set_read
 * 注册后，影子 current= 与恒等快路径都对内核真值生效（修「影子 60 /
 * sysctl 80 双源漂移、恒等误判」）。同源：ai_vmscan_swappiness_get
 * （kernel-overlays/mm/vmscan.c 访问器，与 apply 写侧同源）。
 * mm.readahead 无读访问器（backing-dev.c 仅 ai_bdi_ra_pages_set，
 * 无 get）——真值源不存在，按设计册 D7 不做（K2a 报告登记）。 */
static int ai_mm_swappiness_read(struct ai_control_param *p, s32 pid,
				 s64 *value)
{
	*value = (s64)ai_vmscan_swappiness_get();
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

/* K5（2026-11）：mm 域四个空桩门控钩（缺页/工作集/分配迁移类型/THP
 * 咨询）已删除，判决与复活路径见 AIKernel/CHANGELOG.md 与
 * work/refactor/KERNEL-K5-DESIGN.md §3；readahead 真决策钩保留。 */

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

/* ==================================================================
 * K4 效果结算器（K4.1 OOM re-OOM / K4.4 readahead 命中率 /
 * K4.5 reclaim PSI+回收量）
 *
 * 观测点：ai_mm_telemetry_reclaim.c 的 oom_event/readahead_hit/
 * shrink_lru 发射函数入口（先于采样门控 → 全量事件流）；结算逻辑
 * 全部在本文件，遥测侧只一行转发。
 * ================================================================== */

/* K4.1：上一次 OOM 事件时刻（任何 OOM 都更新，不管 AI 与否） */
static u64 ai_k4_last_oom_ns;

/**
 * ai_mm_k4_oom_is_reoom() - re-OOM 判定（纯函数，KUnit 可测）
 * @now_ns: 本次 OOM 时刻
 * @open_ns: OOM 效果窗开窗时刻（0=无在途窗）
 * @last_oom_ns: 上一次 OOM 时刻（0=首次）
 *
 * 在途窗 + 窗龄 <60s + 窗开于上次 OOM 之前 → true。第三个条件排除
 * 本 OOM 周期 badness 评分刚开的窗（评分与 kill/emit 同周期、间隔
 * 毫秒级，不加此过滤会把每次 AI 偏置过的 kill 都误判成 re-OOM）。
 */
bool ai_mm_k4_oom_is_reoom(u64 now_ns, u64 open_ns, u64 last_oom_ns)
{
	if (!open_ns || now_ns < open_ns)
		return false;
	if (now_ns - open_ns >= (u64)AI_EFFECT_WIN_SEC_OOM * NSEC_PER_SEC)
		return false;
	return last_oom_ns && open_ns < last_oom_ns;
}

/**
 * ai_mm_k4_oom_event_note() - K4.1 OOM re-OOM 探测
 * （ai_mm_emit_oom_event 入口调：一次 OOM kill 一次）
 *
 * 在途窗命中 re-OOM 判定 → close(BAD, metric=距上次 OOM 的秒数)
 * （偏置后 60s 内仍复发=偏置方向错误）；否则只滚动 last_oom_ns。
 * 60s 无复发由 ai_effect_tick 按到期 outcome 覆盖表兜底为 GOOD。
 */
void ai_mm_k4_oom_event_note(void)
{
	u64 now = ktime_get_ns();

#ifdef CONFIG_AIKERNEL_RUNTIME
	{
		struct ai_effect_win w;
		u64 last = READ_ONCE(ai_k4_last_oom_ns);

		if (ai_effect_win_peek(AI_HOOK_OOM_BADNESS, &w) &&
		    ai_mm_k4_oom_is_reoom(now, w.open_ns, last) &&
		    now > last)
			ai_effect_close(AI_HOOK_OOM_BADNESS,
					AI_EFFECT_OUTCOME_BAD,
					(long)div_u64(now - last,
						      NSEC_PER_SEC));
	}
#endif /* CONFIG_AIKERNEL_RUNTIME */
	WRITE_ONCE(ai_k4_last_oom_ns, now);
}
EXPORT_SYMBOL_GPL(ai_mm_k4_oom_event_note);

/**
 * ai_mm_k4_readahead_outcome() - K4.4 命中率判定（纯函数，KUnit 可测）
 * @hit: 命中页数
 * @miss: 未命中页数
 * @metric: 出参（百分点，ratio−50，值域 ±50）
 *
 * ratio≥50% → GOOD，否则 BAD；hit+miss=0（防 0 除）→ 中性 GOOD。
 */
u8 ai_mm_k4_readahead_outcome(unsigned long hit, unsigned long miss,
			      long *metric)
{
	unsigned long total = hit + miss;
	unsigned long pct;

	if (metric)
		*metric = 0;
	if (!total)
		return AI_EFFECT_OUTCOME_GOOD;
	pct = hit * 100 / total;
	if (metric)
		*metric = (long)pct - 50;
	return pct >= 50 ? AI_EFFECT_OUTCOME_GOOD : AI_EFFECT_OUTCOME_BAD;
}

/**
 * ai_mm_k4_readahead_settle() - K4.4 预读命中率结算
 * （ai_mm_emit_readahead_hit 入口调：逐 extent hit/miss 计数发射处）
 *
 * v1 以「最后一次注入的窗口」近似归属（单槽语义：窗口开于
 * ai_mm_readahead_hook 的 note_effect，同批预读结束即用该批命中率
 * 结算）。
 */
void ai_mm_k4_readahead_settle(unsigned long hit, unsigned long miss)
{
#ifdef CONFIG_AIKERNEL_RUNTIME
	struct ai_effect_win w;
	long metric = 0;
	u8 out;

	if (!ai_effect_win_peek(AI_HOOK_MM_READAHEAD, &w))
		return;
	out = ai_mm_k4_readahead_outcome(hit, miss, &metric);
	ai_effect_close(AI_HOOK_MM_READAHEAD, out, metric);
#endif /* CONFIG_AIKERNEL_RUNTIME */
}
EXPORT_SYMBOL_GPL(ai_mm_k4_readahead_settle);

/* K4.5：reclaim 查询点（mm/vmscan.c get_scan_count 内联，无 AIKernel
 * 侧包装可包）的 PSI 基线近似——以上一轮 shrink_lruvec 遥测尾的
 * PSI MEM full avg10（定点值）当本轮开窗水位（两轮回收间水位变化
 * 平缓，采样近似语义）。PSI 不可用（CONFIG_PSI=n / 访问器未编译 /
 * 运行时禁用）时只判回收量维度。 */
static unsigned long ai_k4_reclaim_open_full;
static bool ai_k4_reclaim_has_psi;

/**
 * ai_mm_k4_reclaim_settle() - K4.5 回收效果结算
 * （ai_mm_emit_shrink_lru 入口调：shrink_lruvec 尾=本轮回收完成）
 * @nr_reclaimed: 本轮回收页数
 *
 * v1 判定：回收到页（nr_reclaimed>0）且 PSI MEM full 未较上轮升 →
 * GOOD，否则 BAD；metric=nr_reclaimed。emit 签名无 nr_to_reclaim
 * （overlay 调用契约冻结），「reclaimed≥nr_to_reclaim」v1 退化为
 * 「reclaimed>0」，v2 扩 payload 后恢复精确语义。
 */
void ai_mm_k4_reclaim_settle(unsigned long nr_reclaimed)
{
#if defined(CONFIG_PSI) && defined(CONFIG_AIKERNEL_TELEMETRY)
	unsigned long some[3], full[3];
	unsigned long now_full;
	bool psi_ok;
#endif

#if defined(CONFIG_PSI) && defined(CONFIG_AIKERNEL_TELEMETRY)
	psi_ok = ai_psi_read(PSI_MEM, some, full) == AI_OK;
	now_full = psi_ok ? full[0] : 0;
#endif
#ifdef CONFIG_AIKERNEL_RUNTIME
	{
		struct ai_effect_win w;

		if (ai_effect_win_peek(AI_HOOK_MM_RECLAIM, &w)) {
			bool good = nr_reclaimed > 0;

#if defined(CONFIG_PSI) && defined(CONFIG_AIKERNEL_TELEMETRY)
			if (psi_ok && READ_ONCE(ai_k4_reclaim_has_psi) &&
			    now_full > READ_ONCE(ai_k4_reclaim_open_full))
				good = false;
#endif
			ai_effect_close(AI_HOOK_MM_RECLAIM,
					good ? AI_EFFECT_OUTCOME_GOOD :
					       AI_EFFECT_OUTCOME_BAD,
					(long)nr_reclaimed);
		}
	}
#endif /* CONFIG_AIKERNEL_RUNTIME */
#if defined(CONFIG_PSI) && defined(CONFIG_AIKERNEL_TELEMETRY)
	/* 滚动基线：本轮回收结束水位 = 下一轮开窗水位近似 */
	if (psi_ok) {
		WRITE_ONCE(ai_k4_reclaim_open_full, now_full);
		WRITE_ONCE(ai_k4_reclaim_has_psi, true);
	}
#endif
}
EXPORT_SYMBOL_GPL(ai_mm_k4_reclaim_settle);

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
	/* K2a D7：读回真值（sched 三参 set_read 先例照抄） */
	ai_control_set_read("mm.swappiness", ai_mm_swappiness_read);
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
