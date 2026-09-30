// SPDX-License-Identifier: GPL-2.0
/*
 * ai_mm_telemetry_reclaim.c - AIKernel B 轨第2类回收/异常遥测（自 ai_mm.c 拆分）
 *
 * 职责一句话：LRU/slab 回收、workingset refault/activate、filemap 读、
 * 预读与命中、页缓存逐出、回写、THP 缺页/合并/分裂、hugepage、压缩、
 * 页迁移、OOM 事件/评分、内存压力、内存错误与 KASAN/KFENCE 报告的发射辅助。
 *
 * 拆分说明：函数体自原 ai_mm.c（913 行）逐字搬移；本文件无 static 定义，
 * 无跨文件共享。门控：随 ai_mm.o 在 CONFIG_AIKERNEL_MM 下构建（与拆分前一致）。
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

void ai_mm_emit_shrink_lru(s32 nid, unsigned long nr_scanned_anon,
			   unsigned long nr_scanned_file,
			   unsigned long nr_reclaimed, u8 priority, u8 mode)
{
	struct ai_mm_shrink_lru_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_RECLAIM))
		return;
	p.type = AI_MM_SHRINK_LRU;
	p.nid = nid;
	p.nr_scanned_anon = nr_scanned_anon;
	p.nr_scanned_file = nr_scanned_file;
	p.nr_reclaimed = nr_reclaimed;
	p.priority = priority;
	p.mode = mode;
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_RECLAIM, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_shrink_lru);

void ai_mm_emit_shrink_slab(s32 nid, unsigned long nr_freed,
			    const char *shrinker_name)
{
	struct ai_mm_shrink_slab_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_RECLAIM))
		return;
	p.type = AI_MM_SHRINK_SLAB;
	p.nid = nid;
	p.nr_freed = nr_freed;
	strscpy(p.shrinker_name, shrinker_name ? shrinker_name : "?",
		sizeof(p.shrinker_name));
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_RECLAIM, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_shrink_slab);

/* ---- 02.05 工作集 ---- */

void ai_mm_emit_workingset_refault(unsigned long inode_nr, unsigned long offset,
				   unsigned long refault_distance, u8 activated)
{
	struct ai_mm_workingset_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_WORKINGSET))
		return;
	p.type = AI_MM_WORKINGSET_REFAULT;
	p.inode_nr = inode_nr;
	p.offset = offset;
	p.refault_distance = refault_distance;
	p.activated = activated;
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_WORKINGSET, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_workingset_refault);

void ai_mm_emit_workingset_activate(unsigned long inode_nr, unsigned long offset)
{
	struct ai_mm_workingset_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_WORKINGSET))
		return;
	p.type = AI_MM_WORKINGSET_ACTIVATE;
	p.inode_nr = inode_nr;
	p.offset = offset;
	p.refault_distance = 0;
	p.activated = 1;
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_WORKINGSET, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_workingset_activate);

/* ---- 02.06 页缓存 ---- */

void ai_mm_emit_filemap_read(unsigned long inode_nr, unsigned long offset,
			     unsigned long bytes, u8 cache_hit)
{
	struct ai_mm_filemap_read_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_PAGE_CACHE))
		return;
	p.type = AI_MM_FILEMAP_READ;
	p.pid = current ? current->pid : 0;
	p.inode_nr = inode_nr;
	p.offset = offset;
	p.bytes = bytes;
	p.cache_hit = cache_hit;
	if (current)
		strscpy(p.comm, current->comm, TASK_COMM_LEN);
	else
		p.comm[0] = '\0';
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_PAGE_CACHE, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_filemap_read);

void ai_mm_emit_readahead(unsigned long inode_nr, unsigned long start,
			  unsigned long size, u8 async)
{
	struct ai_mm_readahead_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_PAGE_CACHE))
		return;
	p.type = AI_MM_READAHEAD;
	p.pid = current ? current->pid : 0;
	p.inode_nr = inode_nr;
	p.start = start;
	p.size = size;
	p.async = async;
	if (current)
		strscpy(p.comm, current->comm, TASK_COMM_LEN);
	else
		p.comm[0] = '\0';
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_PAGE_CACHE, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_readahead);

void ai_mm_emit_readahead_hit(unsigned long inode_nr, unsigned long pages_hit,
			      unsigned long pages_missed)
{
	struct ai_mm_readahead_hit_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_PAGE_CACHE))
		return;
	p.type = AI_MM_READAHEAD_HIT;
	p.inode_nr = inode_nr;
	p.pages_hit = pages_hit;
	p.pages_missed = pages_missed;
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_PAGE_CACHE, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_readahead_hit);

void ai_mm_emit_page_cache_evict(unsigned long inode_nr, unsigned long offset)
{
	struct ai_mm_page_cache_evict_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_PAGE_CACHE))
		return;
	p.type = AI_MM_PAGE_CACHE_EVICT;
	p.inode_nr = inode_nr;
	p.offset = offset;
	p.reason = 0;
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_PAGE_CACHE, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_page_cache_evict);

void ai_mm_emit_writeback(unsigned long inode_nr, unsigned long nr_pages)
{
	struct ai_mm_writeback_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_PAGE_CACHE))
		return;
	p.type = AI_MM_WRITEBACK;
	p.inode_nr = inode_nr;
	p.nr_pages = nr_pages;
	p.reason = 1;
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_PAGE_CACHE, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_writeback);

/* ---- 02.07 THP/大页 ---- */

void ai_mm_emit_thp_fault_alloc(u32 pid, unsigned long address)
{
	struct ai_mm_thp_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_THP))
		return;
	p.type = AI_MM_THP_FAULT_ALLOC;
	p.pid = pid;
	p.address = address;
	p.success = 1;
	p.fallback_order = 0;
	p.reason = 0;
	if (current)
		strscpy(p.comm, current->comm, TASK_COMM_LEN);
	else
		p.comm[0] = '\0';
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_THP, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_thp_fault_alloc);

void ai_mm_emit_thp_fault_fallback(u32 pid, unsigned long address,
				   u8 fallback_order)
{
	struct ai_mm_thp_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_THP))
		return;
	p.type = AI_MM_THP_FAULT_FALLBACK;
	p.pid = pid;
	p.address = address;
	p.success = 0;
	p.fallback_order = fallback_order;
	p.reason = 0;
	if (current)
		strscpy(p.comm, current->comm, TASK_COMM_LEN);
	else
		p.comm[0] = '\0';
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_THP, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_thp_fault_fallback);

void ai_mm_emit_thp_collapse(u32 pid, unsigned long address, u8 success)
{
	struct ai_mm_thp_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_THP))
		return;
	p.type = AI_MM_THP_COLLAPSE;
	p.pid = pid;
	p.address = address;
	p.success = success;
	p.fallback_order = 0;
	p.reason = 0;
	if (current)
		strscpy(p.comm, current->comm, TASK_COMM_LEN);
	else
		p.comm[0] = '\0';
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_THP, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_thp_collapse);

void ai_mm_emit_thp_split(u32 pid, unsigned long address)
{
	struct ai_mm_thp_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_THP))
		return;
	p.type = AI_MM_THP_SPLIT;
	p.pid = pid;
	p.address = address;
	p.success = 1;
	p.fallback_order = 0;
	p.reason = 0;
	if (current)
		strscpy(p.comm, current->comm, TASK_COMM_LEN);
	else
		p.comm[0] = '\0';
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_THP, AI_SEV_IMPORTANT, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_thp_split);

void ai_mm_emit_hugetlb_alloc(const char *hstate_name, u8 success)
{
	struct ai_mm_hugetlb_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_THP))
		return;
	p.type = AI_MM_HUGETLB_ALLOC;
	p.pid = current ? current->pid : 0;
	p.success = success;
	strscpy(p.hstate_name, hstate_name ? hstate_name : "?",
		sizeof(p.hstate_name));
	if (current)
		strscpy(p.comm, current->comm, TASK_COMM_LEN);
	else
		p.comm[0] = '\0';
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_THP, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_hugetlb_alloc);

/* ---- 02.08 压缩与迁移 ---- */

void ai_mm_emit_compaction(s32 nid, u8 order, u8 success,
			   unsigned long scanned_pages)
{
	struct ai_mm_compaction_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_COMPACTION))
		return;
	p.type = AI_MM_COMPACTION;
	p.nid = nid;
	p.order = order;
	p.success = success;
	p.scanned_pages = scanned_pages;
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_COMPACTION, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_compaction);

void ai_mm_emit_page_migrate(s32 nid_from, s32 nid_to, unsigned long nr_pages)
{
	struct ai_mm_page_migrate_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_COMPACTION))
		return;
	p.type = AI_MM_PAGE_MIGRATE;
	p.nid_from = nid_from;
	p.nid_to = nid_to;
	p.nr_pages = nr_pages;
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_COMPACTION, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_page_migrate);

/* ---- 02.09 OOM（全量；无分配路径） ---- */

void ai_mm_emit_oom_event(u32 killed_pid, const char *killed_comm,
			  unsigned long total_vm_kb, unsigned long rss_kb,
			  s16 oom_score, u8 constraint)
{
	struct ai_mm_oom_event_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_OOM))
		return;
	p.type = AI_MM_OOM_EVENT;
	p.killed_pid = killed_pid;
	p.total_vm_kb = total_vm_kb;
	p.rss_kb = rss_kb;
	p.oom_score = oom_score;
	p.constraint = constraint;
	strscpy(p.killed_comm, killed_comm ? killed_comm : "?",
		TASK_COMM_LEN);
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_OOM, AI_SEV_CRITICAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_oom_event);

void ai_mm_emit_oom_score_adj(u32 pid, const char *comm, s16 old_score,
			      s16 new_score, u32 set_by_pid)
{
	struct ai_mm_oom_score_adj_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_OOM))
		return;
	p.type = AI_MM_OOM_SCORE_ADJ;
	p.pid = pid;
	p.old_score = old_score;
	p.new_score = new_score;
	p.set_by_pid = set_by_pid;
	strscpy(p.comm, comm ? comm : "?", TASK_COMM_LEN);
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_OOM, AI_SEV_NORMAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_oom_score_adj);

void ai_mm_emit_mem_pressure(s32 nid, u8 pressure_level)
{
	struct ai_mm_mem_pressure_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_OOM))
		return;
	p.type = AI_MM_MEM_PRESSURE;
	p.nid = nid;
	p.pressure_level = pressure_level;
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_OOM, AI_SEV_DEBUG, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_mem_pressure);

/* ---- 02.10 内存错误与检测（全量；训练金矿） ---- */

void ai_mm_emit_memory_failure(unsigned long pfn, u32 page_type, u8 action)
{
	struct ai_mm_memory_failure_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_MEM_ERROR))
		return;
	p.type = AI_MM_MEMORY_FAILURE;
	p.pfn = pfn;
	p.page_type = page_type;
	p.action = action;
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_MEM_ERROR, AI_SEV_CRITICAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_memory_failure);

void ai_mm_emit_kasan_report(unsigned long address, unsigned long ip,
			     u32 size, u8 is_write, const char *bug_type)
{
	struct ai_mm_kasan_report_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_MEM_ERROR))
		return;
	p.type = AI_MM_KASAN_REPORT;
	p.pid = current ? current->pid : 0;
	p.address = address;
	p.ip = ip;
	p.size = size;
	p.is_write = is_write;
	strscpy(p.bug_type, bug_type ? bug_type : "?",
		sizeof(p.bug_type));
	if (current)
		strscpy(p.comm, current->comm, TASK_COMM_LEN);
	else
		p.comm[0] = '\0';
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_MEM_ERROR, AI_SEV_CRITICAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_kasan_report);

void ai_mm_emit_kfence_report(unsigned long address, u8 is_write,
			      const char *bug_type)
{
	struct ai_mm_kfence_report_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_MM, AI_EV_MEM_ERROR))
		return;
	p.type = AI_MM_KFENCE_REPORT;
	p.pid = current ? current->pid : 0;
	p.address = address;
	p.is_write = is_write;
	strscpy(p.bug_type, bug_type ? bug_type : "?",
		sizeof(p.bug_type));
	if (current)
		strscpy(p.comm, current->comm, TASK_COMM_LEN);
	else
		p.comm[0] = '\0';
	ai_telemetry_emit_direct(AI_CAT_MM, AI_EV_MEM_ERROR, AI_SEV_CRITICAL, &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_mm_emit_kfence_report);
