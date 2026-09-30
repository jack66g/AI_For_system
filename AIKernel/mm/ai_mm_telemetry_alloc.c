// SPDX-License-Identifier: GPL-2.0
/*
 * ai_mm_telemetry_alloc.c - AIKernel B 轨第2类分配/缺页遥测（自 ai_mm.c 拆分）
 *
 * 职责一句话：页分配/释放/失败/时延、slab 对象 alloc/free/grow/shrink/
 * 碎片、缺页与缺页时延、kswapd 唤醒、直接回收的发射辅助（采样判定 →
 * gfp 字符串 → emit_direct 直写）。
 *
 * 拆分说明：函数体自原 ai_mm.c（913 行）逐字搬移；gfp 字符串化辅助
 * ai_mm_gfp_str、slab 填充辅助 ai_mm_slab_fill 与 per-CPU 缺页时延计数
 * 仅本文件使用，保持 static，无跨文件共享。
 * 门控：随 ai_mm.o 在 CONFIG_AIKERNEL_MM 下构建（与拆分前一致）。
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

/* ==================================================================
 * B 轨：发射辅助（第2类 10 子类；先采样判定，后构建 payload）
 * ================================================================== */

/* gfp 标志 → 字符串（单遍扫描，零分配；只覆盖常用位与组合） */
static void ai_mm_gfp_str(gfp_t gfp, char *buf, size_t len)
{
	size_t off = 0;

#define AI_GFP_ADD(fmt, cond)						\
	do {								\
		if (cond)						\
			off += scnprintf(buf + off, len - off,		\
					 "%s" fmt, (off ? "|" : ""));	\
	} while (0)

	AI_GFP_ADD("GFP_KERNEL", gfp == GFP_KERNEL);
	AI_GFP_ADD("GFP_KERNEL_ACCOUNT", gfp == GFP_KERNEL_ACCOUNT);
	AI_GFP_ADD("GFP_ATOMIC", gfp == GFP_ATOMIC);
	AI_GFP_ADD("GFP_NOFS", gfp == GFP_NOFS);
	AI_GFP_ADD("GFP_NOIO", gfp == GFP_NOIO);
	AI_GFP_ADD("GFP_USER", gfp == GFP_USER);
	AI_GFP_ADD("GFP_HIGHUSER", gfp == GFP_HIGHUSER);
	AI_GFP_ADD("GFP_TRANSHUGE", gfp == GFP_TRANSHUGE);
	AI_GFP_ADD("GFP_DMA", gfp == GFP_DMA);
	AI_GFP_ADD("GFP_DMA32", gfp == GFP_DMA32);
	AI_GFP_ADD("GFP_HIGHUSER_MOVABLE", gfp == GFP_HIGHUSER_MOVABLE);
	AI_GFP_ADD("__GFP_RECLAIM", (gfp & __GFP_RECLAIM) == __GFP_RECLAIM);
	AI_GFP_ADD("__GFP_MOVABLE", gfp & __GFP_MOVABLE);
	AI_GFP_ADD("__GFP_HIGH", gfp & __GFP_HIGH);
	AI_GFP_ADD("__GFP_IO", gfp & __GFP_IO);
	AI_GFP_ADD("__GFP_FS", gfp & __GFP_FS);
	AI_GFP_ADD("__GFP_ZERO", gfp & __GFP_ZERO);
	AI_GFP_ADD("__GFP_ACCOUNT", gfp & __GFP_ACCOUNT);
	AI_GFP_ADD("__GFP_NOWARN", gfp & __GFP_NOWARN);
	AI_GFP_ADD("__GFP_NORETRY", gfp & __GFP_NORETRY);
	AI_GFP_ADD("__GFP_RETRY_MAYFAIL", gfp & __GFP_RETRY_MAYFAIL);
	AI_GFP_ADD("__GFP_NOFAIL", gfp & __GFP_NOFAIL);
	AI_GFP_ADD("__GFP_HARDWALL", gfp & __GFP_HARDWALL);
	AI_GFP_ADD("__GFP_THISNODE", gfp & __GFP_THISNODE);
	AI_GFP_ADD("__GFP_MEMALLOC", gfp & __GFP_MEMALLOC);
	AI_GFP_ADD("__GFP_NOMEMALLOC", gfp & __GFP_NOMEMALLOC);
	AI_GFP_ADD("__GFP_DIRECT_RECLAIM", gfp & __GFP_DIRECT_RECLAIM);
	AI_GFP_ADD("__GFP_KSWAPD_RECLAIM", gfp & __GFP_KSWAPD_RECLAIM);
	AI_GFP_ADD("__GFP_WRITE", gfp & __GFP_WRITE);
	AI_GFP_ADD("__GFP_COMP", gfp & __GFP_COMP);
	AI_GFP_ADD("__GFP_RECLAIMABLE", gfp & __GFP_RECLAIMABLE);
	AI_GFP_ADD("__GFP_DMA", gfp & __GFP_DMA);
	AI_GFP_ADD("__GFP_DMA32", gfp & __GFP_DMA32);
	AI_GFP_ADD("__GFP_HIGHMEM", gfp & __GFP_HIGHMEM);
#ifdef __GFP_CMA
	AI_GFP_ADD("__GFP_CMA", gfp & __GFP_CMA);
#endif
	if (off == 0)
		scnprintf(buf, len, "none");
#undef AI_GFP_ADD
}

/* ---- 02.01 页分配 ---- */

void ai_mm_emit_page_alloc(u8 order, gfp_t gfp, u8 migratetype)
{
	struct ai_mm_page_alloc_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_PAGE_ALLOC))
		return;
	p.type = AI_MM_PAGE_ALLOC;
	p.order = order;
	p.gfp_flags = (u32)gfp;
	p.migratetype = migratetype;
	p.cpu = (u16)smp_processor_id();
	p.pid = current ? current->pid : 0;
	ai_mm_gfp_str(gfp, p.gfp_str, sizeof(p.gfp_str));
	if (current)
		strscpy(p.comm, current->comm, TASK_COMM_LEN);
	else
		p.comm[0] = '\0';
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_PAGE_ALLOC, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_page_alloc);

void ai_mm_emit_page_free(u8 order, u8 migratetype)
{
	struct ai_mm_page_free_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_PAGE_ALLOC))
		return;
	p.type = AI_MM_PAGE_FREE;
	p.order = order;
	p.migratetype = migratetype;
	p.cpu = (u16)smp_processor_id();
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_PAGE_ALLOC, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_page_free);

void ai_mm_emit_page_alloc_failure(u8 order, gfp_t gfp, u32 retry_count)
{
	struct ai_mm_page_alloc_failure_payload p;

	/* 失败事件全量（直接发射，不走采样）：分配失败是重要信号 */
	p.type = AI_MM_PAGE_ALLOC_FAILURE;
	p.order = order;
	p.gfp_flags = (u32)gfp;
	p.retry_count = retry_count;
	p.pid = current ? current->pid : 0;
	ai_mm_gfp_str(gfp, p.gfp_str, sizeof(p.gfp_str));
	if (current)
		strscpy(p.comm, current->comm, TASK_COMM_LEN);
	else
		p.comm[0] = '\0';
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_PAGE_ALLOC, AI_SEV_CRITICAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_page_alloc_failure);

void ai_mm_emit_page_alloc_latency(u8 order, gfp_t gfp, u64 latency_ns)
{
	struct ai_mm_page_alloc_latency_payload p;

	/* 大阶分配延迟全量（order>0 时才被调用；慢路径罕见） */
	p.type = AI_MM_PAGE_ALLOC_LATENCY;
	p.order = order;
	p.gfp_flags = (u32)gfp;
	p.latency_ns = latency_ns;
	ai_mm_gfp_str(gfp, p.gfp_str, sizeof(p.gfp_str));
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_PAGE_ALLOC, AI_SEV_IMPORTANT,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_page_alloc_latency);

/* ---- 02.02 Slab/Slub ---- */

static void ai_mm_slab_fill(struct ai_mm_slab_payload *p, const char *name,
			    u32 size, u32 pages, u32 frag)
{
	p->pid = current ? current->pid : 0;
	p->size = size;
	p->pages = pages;
	p->frag_ratio = frag;
	strscpy(p->cache_name, name ? name : "?", sizeof(p->cache_name));
	if (current)
		strscpy(p->comm, current->comm, TASK_COMM_LEN);
	else
		p->comm[0] = '\0';
}

void ai_mm_emit_slab_alloc(const char *name, u32 size)
{
	struct ai_mm_slab_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_SLAB_ALLOC))
		return;
	p.type = AI_MM_SLAB_ALLOC;
	ai_mm_slab_fill(&p, name, size, 0, 0);
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_SLAB_ALLOC, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_slab_alloc);

void ai_mm_emit_slab_free(const char *name)
{
	struct ai_mm_slab_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_SLAB_ALLOC))
		return;
	p.type = AI_MM_SLAB_FREE;
	ai_mm_slab_fill(&p, name, 0, 0, 0);
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_SLAB_ALLOC, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_slab_free);

void ai_mm_emit_slab_grow(const char *name, u32 pages)
{
	struct ai_mm_slab_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_SLAB_ALLOC))
		return;
	p.type = AI_MM_SLAB_GROW;
	ai_mm_slab_fill(&p, name, 0, pages, 0);
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_SLAB_ALLOC, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_slab_grow);

void ai_mm_emit_slab_shrink(const char *name, u32 pages)
{
	struct ai_mm_slab_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_SLAB_ALLOC))
		return;
	p.type = AI_MM_SLAB_SHRINK;
	ai_mm_slab_fill(&p, name, 0, pages, 0);
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_SLAB_ALLOC, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_slab_shrink);

void ai_mm_emit_slab_fragmentation(const char *name, u32 frag_ratio)
{
	struct ai_mm_slab_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_SLAB_ALLOC))
		return;
	p.type = AI_MM_SLAB_FRAGMENTATION;
	ai_mm_slab_fill(&p, name, 0, 0, frag_ratio);
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_SLAB_ALLOC, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_slab_fragmentation);

/* ---- 02.03 缺页（全量） ---- */

void ai_mm_emit_page_fault(u8 fault_type, u8 access_type, u8 major,
			   unsigned long address)
{
	struct ai_mm_page_fault_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_PAGE_FAULT))
		return;
	p.type = AI_MM_PAGE_FAULT;
	p.pid = current ? current->pid : 0;
	p.address = address;
	p.fault_type = fault_type;
	p.access_type = access_type;
	p.major = major;
	if (current)
		strscpy(p.comm, current->comm, TASK_COMM_LEN);
	else
		p.comm[0] = '\0';
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_PAGE_FAULT, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_page_fault);

/* 缺页延迟自限频 1/16（与 page_fault 全量事件共用 AI_EV_PAGE_FAULT，
 * 用独立 per-CPU 计数器控制附加计时开销；emit_direct 不再做采样判定） */
static DEFINE_PER_CPU(u32, ai_mm_fault_lat_cnt);

void ai_mm_emit_page_fault_latency(u64 latency_ns, u8 resolved)
{
	struct ai_mm_page_fault_latency_payload p;
	u32 cnt = this_cpu_inc_return(ai_mm_fault_lat_cnt);

	if ((cnt & 0xF) != 0)
		return;
	p.type = AI_MM_PAGE_FAULT_LATENCY;
	p.pid = current ? current->pid : 0;
	p.latency_ns = latency_ns;
	p.fault_resolved = resolved;
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_PAGE_FAULT, AI_SEV_DEBUG,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_page_fault_latency);

/* ---- 02.04 回收 ---- */

void ai_mm_emit_kswapd_wake(s32 nid, u8 order, u32 alloc_flags)
{
	struct ai_mm_kswapd_wake_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_RECLAIM))
		return;
	p.type = AI_MM_KSWAPD_WAKE;
	p.nid = nid;
	p.order = order;
	p.alloc_flags = alloc_flags;
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_RECLAIM, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_kswapd_wake);

void ai_mm_emit_direct_reclaim(u8 order, gfp_t gfp, u64 latency_ns)
{
	struct ai_mm_direct_reclaim_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_RECLAIM))
		return;
	p.type = AI_MM_DIRECT_RECLAIM;
	p.pid = current ? current->pid : 0;
	p.order = order;
	p.gfp_flags = (u32)gfp;
	p.latency_ns = latency_ns;
	ai_mm_gfp_str(gfp, p.gfp_str, sizeof(p.gfp_str));
	if (current)
		strscpy(p.comm, current->comm, TASK_COMM_LEN);
	else
		p.comm[0] = '\0';
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_RECLAIM, AI_SEV_IMPORTANT, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_direct_reclaim);
