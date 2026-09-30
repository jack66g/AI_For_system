// SPDX-License-Identifier: GPL-2.0
/*
 * ai_mm.h - AIKernel 内存管理子系统统一接口头（Prompt 04）
 *
 * 本文件是 mm/ 全部 AI 埋点的唯一接入点：
 *   A 轨（控制）：ai_mm_*_hook() 系列 —— 让 AI 参与内存管理决策
 *                 （缺页/预读窗口/回收/工作集/碎片迁移类型/THP/KSM/OOM/CMA），
 *                 空实现 = 原样放行（返回值不改变内核默认行为）；
 *   B 轨（感知）：第2类 内存管理感知 10 子类的 payload 结构 + 事件包装，
 *                 全量原始零脱敏（pid/comm/address/gfp 字符串全保留）。
 *
 * 零回归策略：
 *   - CONFIG_AIKERNEL_MM=n：本头文件不参与任何编译（mm/ 下各 .c 文件的
 *     条件 include 一并剔除），预处理产物与基线一致；
 *   - CONFIG_AIKERNEL_TELEMETRY=n：ai_telemetry_* 包装退化为 static inline
 *     空函数（ai_telemetry.h 内置兜底），Hook 本身只计数不发射。
 *
 * 遥测函数铁律：不阻塞、不分配（无 GFP_KERNEL）、无锁，仅供快速路径；
 * OOM/错误报告路径埋点不得再分配内存（栈上 payload + 直接入 ring buffer）。
 */

#ifndef _AIKERNEL_MM_AI_MM_H
#define _AIKERNEL_MM_AI_MM_H

#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/mmzone.h>
#include <linux/oom.h>

struct cma;	/* 前向声明：hook 只透传指针（完整定义在 mm/cma.h） */

/* ==================================================================
 * B 轨：第2类 内存管理感知 payload（事件编号对齐 enum ai_event_type）
 * ==================================================================
 * 每个 payload 首字节为 u8 type，区分计划内的子事件
 * （02.01 的 alloc/free/failure/latency 共用 AI_EV_PAGE_ALLOC 等）。
 */

/* 02.01 页分配子事件 */
enum ai_mm_page_alloc_type {
	AI_MM_PAGE_ALLOC		= 1,
	AI_MM_PAGE_FREE,
	AI_MM_PAGE_ALLOC_FAILURE,
	AI_MM_PAGE_ALLOC_LATENCY,
};

struct ai_mm_page_alloc_payload {
	u8 type;			/* AI_MM_PAGE_ALLOC */
	u8 order;
	u32 gfp_flags;			/* 原始 gfp 位（零脱敏） */
	u8 migratetype;
	u16 cpu;
	u32 pid;
	char gfp_str[64];		/* gfpflag 字符串（show_gfp_flags 风格简化） */
	char comm[TASK_COMM_LEN];
};

struct ai_mm_page_free_payload {
	u8 type;			/* AI_MM_PAGE_FREE */
	u8 order;
	u8 migratetype;
	u16 cpu;
};

struct ai_mm_page_alloc_failure_payload {
	u8 type;			/* AI_MM_PAGE_ALLOC_FAILURE */
	u8 order;
	u32 gfp_flags;
	u32 retry_count;		/* 重试轮数 */
	u32 pid;
	char gfp_str[64];
	char comm[TASK_COMM_LEN];
};

struct ai_mm_page_alloc_latency_payload {
	u8 type;			/* AI_MM_PAGE_ALLOC_LATENCY */
	u8 order;
	u32 gfp_flags;
	u64 latency_ns;
	char gfp_str[64];
};

/* 02.02 Slab/Slub 子事件 */
enum ai_mm_slab_type {
	AI_MM_SLAB_ALLOC		= 1,
	AI_MM_SLAB_FREE,
	AI_MM_SLAB_GROW,
	AI_MM_SLAB_SHRINK,
	AI_MM_SLAB_FRAGMENTATION,
};

struct ai_mm_slab_payload {
	u8 type;			/* AI_MM_SLAB_ALLOC / FREE / GROW / SHRINK / FRAG */
	u32 pid;
	u32 size;			/* alloc: 对象大小 */
	u32 pages;			/* grow/shrink: 页数；frag: frag_ratio*1000 */
	u32 frag_ratio;			/* fragmentation: 碎片率（1/1000 定点） */
	char cache_name[32];
	char comm[TASK_COMM_LEN];
};

/* 02.03 缺页子事件 */
enum ai_mm_page_fault_type {
	AI_MM_PAGE_FAULT		= 1,
	AI_MM_PAGE_FAULT_LATENCY,
};

struct ai_mm_page_fault_payload {
	u8 type;			/* AI_MM_PAGE_FAULT */
	u32 pid;
	unsigned long address;		/* 触发缺页的虚拟地址（零脱敏） */
	u8 fault_type;			/* 1=anon 2=file */
	u8 access_type;			/* 1=read 2=write 3=exec */
	u8 major;			/* 1=主缺页（发生 I/O） */
	char comm[TASK_COMM_LEN];
};

struct ai_mm_page_fault_latency_payload {
	u8 type;			/* AI_MM_PAGE_FAULT_LATENCY */
	u32 pid;
	u64 latency_ns;
	u8 fault_resolved;		/* 1=成功 */
};

/* 02.04 回收子事件 */
enum ai_mm_reclaim_type {
	AI_MM_KSWAPD_WAKE		= 1,
	AI_MM_DIRECT_RECLAIM,
	AI_MM_SHRINK_LRU,
	AI_MM_SHRINK_SLAB,
};

struct ai_mm_kswapd_wake_payload {
	u8 type;			/* AI_MM_KSWAPD_WAKE */
	s32 nid;
	u8 order;
	u32 alloc_flags;		/* ALLOC_* 位 */
};

struct ai_mm_direct_reclaim_payload {
	u8 type;			/* AI_MM_DIRECT_RECLAIM */
	u32 pid;
	u8 order;
	u32 gfp_flags;
	u64 latency_ns;
	char gfp_str[64];
	char comm[TASK_COMM_LEN];
};

struct ai_mm_shrink_lru_payload {
	u8 type;			/* AI_MM_SHRINK_LRU */
	s32 nid;
	unsigned long nr_scanned_anon;
	unsigned long nr_scanned_file;
	unsigned long nr_reclaimed;
	u8 priority;
	u8 mode;			/* 0=kswapd 1=direct 2=memcg */
};

struct ai_mm_shrink_slab_payload {
	u8 type;			/* AI_MM_SHRINK_SLAB */
	s32 nid;
	unsigned long nr_freed;
	char shrinker_name[32];
};

/* 02.05 工作集子事件 */
enum ai_mm_workingset_type {
	AI_MM_WORKINGSET_REFAULT	= 1,
	AI_MM_WORKINGSET_ACTIVATE,
};

struct ai_mm_workingset_payload {
	u8 type;			/* AI_MM_WORKINGSET_REFAULT / ACTIVATE */
	unsigned long inode_nr;		/* 宿主 inode 号 */
	unsigned long offset;		/* 文件内偏移页 */
	unsigned long refault_distance;	/* refault 距离（近似） */
	u8 activated;			/* refault: 是否激活 */
};

/* 02.06 页缓存子事件 */
enum ai_mm_page_cache_type {
	AI_MM_FILEMAP_READ		= 1,
	AI_MM_READAHEAD,
	AI_MM_READAHEAD_HIT,
	AI_MM_PAGE_CACHE_EVICT,
	AI_MM_WRITEBACK,
};

struct ai_mm_filemap_read_payload {
	u8 type;			/* AI_MM_FILEMAP_READ */
	u32 pid;
	unsigned long inode_nr;
	unsigned long offset;
	unsigned long bytes;
	u8 cache_hit;			/* 1=全部命中缓存 0=发生 I/O */
	char comm[TASK_COMM_LEN];
};

struct ai_mm_readahead_payload {
	u8 type;			/* AI_MM_READAHEAD */
	u32 pid;
	unsigned long inode_nr;
	unsigned long start;
	unsigned long size;		/* 本次预读页数（AI 调整后） */
	u8 async;
	char comm[TASK_COMM_LEN];
};

struct ai_mm_readahead_hit_payload {
	u8 type;			/* AI_MM_READAHEAD_HIT */
	unsigned long inode_nr;
	unsigned long pages_hit;	/* 已存在页 */
	unsigned long pages_missed;	/* 新分配页 */
};

struct ai_mm_page_cache_evict_payload {
	u8 type;			/* AI_MM_PAGE_CACHE_EVICT */
	unsigned long inode_nr;
	unsigned long offset;
	u8 reason;			/* 0=回收 */
};

struct ai_mm_writeback_payload {
	u8 type;			/* AI_MM_WRITEBACK */
	unsigned long inode_nr;
	unsigned long nr_pages;
	u8 reason;			/* 1=dirty */
};

/* 02.07 THP/大页子事件 */
enum ai_mm_thp_type {
	AI_MM_THP_FAULT_ALLOC		= 1,
	AI_MM_THP_FAULT_FALLBACK,
	AI_MM_THP_COLLAPSE,
	AI_MM_THP_SPLIT,
	AI_MM_HUGETLB_ALLOC,
};

struct ai_mm_thp_payload {
	u8 type;			/* AI_MM_THP_* */
	u32 pid;
	unsigned long address;
	u8 success;			/* collapse: 1=合并成功 */
	u8 fallback_order;		/* fallback: 回退阶 */
	u8 reason;			/* split: 0=文件分页 1=调试 */
	char comm[TASK_COMM_LEN];
};

struct ai_mm_hugetlb_payload {
	u8 type;			/* AI_MM_HUGETLB_ALLOC */
	u32 pid;
	u8 success;
	char hstate_name[16];
	char comm[TASK_COMM_LEN];
};

/* 02.08 压缩与迁移子事件 */
enum ai_mm_compaction_type {
	AI_MM_COMPACTION			= 1,
	AI_MM_PAGE_MIGRATE,
};

struct ai_mm_compaction_payload {
	u8 type;			/* AI_MM_COMPACTION */
	s32 nid;
	u8 order;
	u8 success;
	unsigned long scanned_pages;
};

struct ai_mm_page_migrate_payload {
	u8 type;			/* AI_MM_PAGE_MIGRATE */
	s32 nid_from;
	s32 nid_to;
	unsigned long nr_pages;
};

/* 02.09 OOM 子事件 */
enum ai_mm_oom_type {
	AI_MM_OOM_EVENT			= 1,
	AI_MM_OOM_SCORE_ADJ,
	AI_MM_MEM_PRESSURE,
};

struct ai_mm_oom_event_payload {
	u8 type;			/* AI_MM_OOM_EVENT */
	u32 killed_pid;
	unsigned long total_vm_kb;
	unsigned long rss_kb;
	s16 oom_score;
	u8 constraint;
	char killed_comm[TASK_COMM_LEN];
};

struct ai_mm_oom_score_adj_payload {
	u8 type;			/* AI_MM_OOM_SCORE_ADJ */
	u32 pid;
	s16 old_score;
	s16 new_score;
	u32 set_by_pid;
	char comm[TASK_COMM_LEN];
};

struct ai_mm_mem_pressure_payload {
	u8 type;			/* AI_MM_MEM_PRESSURE */
	s32 nid;
	u8 pressure_level;		/* 0=low 1=medium 2=high */
};

/* 02.10 内存错误与检测子事件 */
enum ai_mm_mem_error_type {
	AI_MM_MEMORY_FAILURE		= 1,
	AI_MM_KASAN_REPORT,
	AI_MM_KFENCE_REPORT,
	AI_MM_KMEMLEAK_REPORT,		/* 预留 */
	AI_MM_KMSAN_REPORT,		/* 预留 */
	AI_MM_UBSAN_REPORT,		/* 预留 */
	AI_MM_KCSAN_REPORT,		/* 预留 */
};

struct ai_mm_memory_failure_payload {
	u8 type;			/* AI_MM_MEMORY_FAILURE */
	unsigned long pfn;
	u32 page_type;			/* 页类型位 */
	u8 action;			/* MF_* 动作 */
};

struct ai_mm_kasan_report_payload {
	u8 type;			/* AI_MM_KASAN_REPORT（训练金矿） */
	u32 pid;
	unsigned long address;
	unsigned long ip;
	u32 size;
	u8 is_write;
	char bug_type[32];
	char comm[TASK_COMM_LEN];
};

struct ai_mm_kfence_report_payload {
	u8 type;			/* AI_MM_KFENCE_REPORT */
	u32 pid;
	unsigned long address;
	u8 is_write;
	char bug_type[24];
	char comm[TASK_COMM_LEN];
};

/* ==================================================================
 * A 轨：AI 内存决策框架
 * ==================================================================
 */

/* 决策统计（/proc/ai/mm/stats 数据源预留） */
struct ai_mm_stats {
	u64 fault_hook_calls, fault_ai_changed;
	u64 readahead_hook_calls, readahead_ai_changed;
	u64 reclaim_hook_calls, reclaim_ai_changed;
	u64 workingset_hook_calls, workingset_ai_changed;
	u64 alloc_hook_calls, alloc_ai_changed;
	u64 thp_hook_calls, thp_ai_changed;
	u64 ksm_hook_calls, ksm_ai_changed;
	u64 oom_hook_calls, oom_ai_changed;
	u64 cma_hook_calls, cma_ai_changed;
};

#ifdef CONFIG_AIKERNEL_MM

/* ---- A 轨 Hook（实现见 ai_mm.c；空实现 = 原样放行） ---- */

/**
 * ai_mm_fault_hook() - AI 参与缺页处理决策
 * @vmf: 缺页上下文
 * @fault_type: 1=anon 2=file
 *
 * 由 do_anonymous_page()/do_fault() 调用。空实现只计数，不修改任何值。
 */
void ai_mm_fault_hook(struct vm_fault *vmf, u8 fault_type);

/**
 * ai_mm_readahead_hook() - AI 决定预读窗口大小
 * @ractl: 预读控制
 * @nr_to_read: 本次计划预读页数
 * @lookahead_size: lookahead 窗口
 *
 * 返回 AI 调整后的预读页数（空实现原样返回 @nr_to_read）。
 */
unsigned long ai_mm_readahead_hook(struct readahead_control *ractl,
				   unsigned long nr_to_read,
				   unsigned long lookahead_size);

/**
 * ai_mm_reclaim_hook() - AI 建议回收优先级/扫描方向
 * @nid: 节点
 * @mode: 0=kswapd 1=direct 2=memcg
 * @priority: 扫描优先级（0~DEF_PRIORITY，值越小越激进）
 * @nr_to_reclaim: 目标回收页数
 *
 * 由 shrink_lruvec() 调用。空实现只计数，不修改扫描参数。
 */
void ai_mm_reclaim_hook(int nid, u8 mode, u8 priority,
			unsigned long nr_to_reclaim);

/**
 * ai_mm_workingset_hook() - AI 增强工作集重故障激活判断
 * @folio: 重故障的 folio
 * @shadow: 影子条目
 * @activate: 内核当前是否激活
 *
 * 返回 AI 建议的激活值（空实现原样返回 @activate）。
 */
bool ai_mm_workingset_hook(struct folio *folio, void *shadow, bool activate);

/**
 * ai_mm_alloc_hook() - AI 碎片预测，调整迁移类型
 * @zone: 目标 zone
 * @order: 分配阶
 * @gfp_flags: 分配标志
 * @migratetype: 当前迁移类型
 *
 * 返回 AI 建议的迁移类型（空实现原样返回 @migratetype）。
 */
int ai_mm_alloc_hook(struct zone *zone, unsigned int order,
		     gfp_t gfp_flags, int migratetype);

/**
 * ai_mm_thp_hook() - AI 判断 THP 是否合并
 * @mm: 扫描中的 mm
 * @address: 当前扫描地址
 * @decision: 出参建议（0=不干预）
 *
 * 由 khugepaged_scan_mm_slot() 调用。空实现只计数。
 */
void ai_mm_thp_hook(struct mm_struct *mm, unsigned long address, u8 *decision);

/**
 * ai_mm_ksm_hook() - AI 预测 KSM 合并收益
 * @page: 待扫描页
 * @address: 页地址
 *
 * 返回收益等级（0=不干预；>0 建议优先合并）。空实现返回 0。
 */
int ai_mm_ksm_hook(struct page *page, unsigned long address);

/**
 * ai_mm_oom_hook() - AI 辅助 OOM 目标选择
 * @oc: OOM 控制结构（oc->chosen 为当前选中的受害者）
 *
 * 返回 0=接受内核选择；>0=AI 建议换人（AI 推理后续步骤接通）。
 * 空实现返回 0（不改变内核默认行为）。本函数禁止分配内存。
 */
int ai_mm_oom_hook(struct oom_control *oc);

/**
 * ai_mm_cma_hook() - AI 预测设备内存需求
 * @cma: CMA 区域
 * @count: 请求页数
 *
 * 返回 AI 调整后的请求页数（空实现原样返回 @count）。
 */
unsigned long ai_mm_cma_hook(struct cma *cma, unsigned long count);

/* ---- 决策框架（实现见 ai_mm.c；占位启发式，AI 推理后续步骤替换） ---- */

/**
 * ai_mm_predict_page_access() - 页面访问模式预测
 * @address: 缺页地址
 * @fault_type: 1=anon 2=file
 *
 * 返回 1=预测为热页面（建议预分配/预读），0=普通。占位启发式。
 */
int ai_mm_predict_page_access(unsigned long address, u8 fault_type);

/**
 * ai_mm_predict_fragmentation() - 碎片趋势预测
 * @zone: 目标 zone
 *
 * 返回建议迁移类型：0=不干预；1=建议 MIGRATE_MOVABLE。占位启发式。
 */
int ai_mm_predict_fragmentation(struct zone *zone);

/**
 * ai_mm_predict_ksm_benefit() - KSM 合并收益预测
 * @page: 待判断页
 *
 * 返回收益等级（0~3，0=不建议）。占位返回 0。
 */
int ai_mm_predict_ksm_benefit(struct page *page);

/**
 * ai_mm_stats_read() - 决策统计读取
 * @st: 输出统计
 */
void ai_mm_stats_read(struct ai_mm_stats *st);

/* ---- B 轨：发射辅助（实现见 ai_mm.c；内部先采样判定后构建 payload） ---- */

void ai_mm_emit_page_alloc(u8 order, gfp_t gfp, u8 migratetype);
void ai_mm_emit_page_free(u8 order, u8 migratetype);
void ai_mm_emit_page_alloc_failure(u8 order, gfp_t gfp, u32 retry_count);
void ai_mm_emit_page_alloc_latency(u8 order, gfp_t gfp, u64 latency_ns);
void ai_mm_emit_slab_alloc(const char *name, u32 size);
void ai_mm_emit_slab_free(const char *name);
void ai_mm_emit_slab_grow(const char *name, u32 pages);
void ai_mm_emit_slab_shrink(const char *name, u32 pages);
void ai_mm_emit_slab_fragmentation(const char *name, u32 frag_ratio);
void ai_mm_emit_page_fault(u8 fault_type, u8 access_type, u8 major,
			   unsigned long address);
void ai_mm_emit_page_fault_latency(u64 latency_ns, u8 resolved);
void ai_mm_emit_kswapd_wake(s32 nid, u8 order, u32 alloc_flags);
void ai_mm_emit_direct_reclaim(u8 order, gfp_t gfp, u64 latency_ns);
void ai_mm_emit_shrink_lru(s32 nid, unsigned long nr_scanned_anon,
			   unsigned long nr_scanned_file,
			   unsigned long nr_reclaimed, u8 priority, u8 mode);
void ai_mm_emit_shrink_slab(s32 nid, unsigned long nr_freed,
			    const char *shrinker_name);
void ai_mm_emit_workingset_refault(unsigned long inode_nr, unsigned long offset,
				   unsigned long refault_distance, u8 activated);
void ai_mm_emit_workingset_activate(unsigned long inode_nr,
				    unsigned long offset);
void ai_mm_emit_filemap_read(unsigned long inode_nr, unsigned long offset,
			     unsigned long bytes, u8 cache_hit);
void ai_mm_emit_readahead(unsigned long inode_nr, unsigned long start,
			  unsigned long size, u8 async);
void ai_mm_emit_readahead_hit(unsigned long inode_nr, unsigned long pages_hit,
			      unsigned long pages_missed);
void ai_mm_emit_page_cache_evict(unsigned long inode_nr, unsigned long offset);
void ai_mm_emit_writeback(unsigned long inode_nr, unsigned long nr_pages);
void ai_mm_emit_thp_fault_alloc(u32 pid, unsigned long address);
void ai_mm_emit_thp_fault_fallback(u32 pid, unsigned long address,
				   u8 fallback_order);
void ai_mm_emit_thp_collapse(u32 pid, unsigned long address, u8 success);
void ai_mm_emit_thp_split(u32 pid, unsigned long address);
void ai_mm_emit_hugetlb_alloc(const char *hstate_name, u8 success);
void ai_mm_emit_compaction(s32 nid, u8 order, u8 success,
			   unsigned long scanned_pages);
void ai_mm_emit_page_migrate(s32 nid_from, s32 nid_to, unsigned long nr_pages);
void ai_mm_emit_oom_event(u32 killed_pid, const char *killed_comm,
			  unsigned long total_vm_kb, unsigned long rss_kb,
			  s16 oom_score, u8 constraint);
void ai_mm_emit_oom_score_adj(u32 pid, const char *comm, s16 old_score,
			      s16 new_score, u32 set_by_pid);
void ai_mm_emit_mem_pressure(s32 nid, u8 pressure_level);
void ai_mm_emit_memory_failure(unsigned long pfn, u32 page_type, u8 action);
void ai_mm_emit_kasan_report(unsigned long address, unsigned long ip,
			     u32 size, u8 is_write, const char *bug_type);
void ai_mm_emit_kfence_report(unsigned long address, u8 is_write,
			      const char *bug_type);

#else /* !CONFIG_AIKERNEL_MM */

/* 空函数兜底：CONFIG_AIKERNEL_MM=n 时 mm/ 不包含本头文件，
 * 此处兜底仅供 AIKernel/ 内部其他模块引用时保持可编译。 */
static inline void ai_mm_fault_hook(struct vm_fault *vmf, u8 fault_type) { }
static inline unsigned long ai_mm_readahead_hook(struct readahead_control *ractl,
						 unsigned long nr_to_read,
						 unsigned long lookahead_size)
{ return nr_to_read; }
static inline void ai_mm_reclaim_hook(int nid, u8 mode, u8 priority,
				      unsigned long nr_to_reclaim) { }
static inline bool ai_mm_workingset_hook(struct folio *folio, void *shadow,
					 bool activate)
{ return activate; }
static inline int ai_mm_alloc_hook(struct zone *zone, unsigned int order,
				   gfp_t gfp_flags, int migratetype)
{ return migratetype; }
static inline void ai_mm_thp_hook(struct mm_struct *mm, unsigned long address,
				  u8 *decision)
{ if (decision) *decision = 0; }
static inline int ai_mm_ksm_hook(struct page *page, unsigned long address)
{ return 0; }
static inline int ai_mm_oom_hook(struct oom_control *oc) { return 0; }
static inline unsigned long ai_mm_cma_hook(struct cma *cma, unsigned long count)
{ return count; }
static inline int ai_mm_predict_page_access(unsigned long address, u8 fault_type)
{ return 0; }
static inline int ai_mm_predict_fragmentation(struct zone *zone) { return 0; }
static inline int ai_mm_predict_ksm_benefit(struct page *page) { return 0; }
static inline void ai_mm_stats_read(struct ai_mm_stats *st)
{ if (st) memset(st, 0, sizeof(*st)); }
static inline void ai_mm_emit_page_alloc(u8 o, gfp_t g, u8 m) { }
static inline void ai_mm_emit_page_free(u8 o, u8 m) { }
static inline void ai_mm_emit_page_alloc_failure(u8 o, gfp_t g, u32 r) { }
static inline void ai_mm_emit_page_alloc_latency(u8 o, gfp_t g, u64 l) { }
static inline void ai_mm_emit_slab_alloc(const char *n, u32 s) { }
static inline void ai_mm_emit_slab_free(const char *n) { }
static inline void ai_mm_emit_slab_grow(const char *n, u32 p) { }
static inline void ai_mm_emit_slab_shrink(const char *n, u32 p) { }
static inline void ai_mm_emit_slab_fragmentation(const char *n, u32 f) { }
static inline void ai_mm_emit_page_fault(u8 f, u8 a, u8 m, unsigned long ad) { }
static inline void ai_mm_emit_page_fault_latency(u64 l, u8 r) { }
static inline void ai_mm_emit_kswapd_wake(s32 n, u8 o, u32 f) { }
static inline void ai_mm_emit_direct_reclaim(u8 o, gfp_t g, u64 l) { }
static inline void ai_mm_emit_shrink_lru(s32 n, unsigned long a,
					 unsigned long b, unsigned long r,
					 u8 p, u8 m) { }
static inline void ai_mm_emit_shrink_slab(s32 n, unsigned long f,
					  const char *s) { }
static inline void ai_mm_emit_workingset_refault(unsigned long i,
						 unsigned long o,
						 unsigned long d, u8 a) { }
static inline void ai_mm_emit_workingset_activate(unsigned long i,
						  unsigned long o) { }
static inline void ai_mm_emit_filemap_read(unsigned long i, unsigned long o,
					   unsigned long b, u8 h) { }
static inline void ai_mm_emit_readahead(unsigned long i, unsigned long s,
					unsigned long z, u8 a) { }
static inline void ai_mm_emit_readahead_hit(unsigned long i, unsigned long h,
					    unsigned long m) { }
static inline void ai_mm_emit_page_cache_evict(unsigned long i,
					       unsigned long o) { }
static inline void ai_mm_emit_writeback(unsigned long i, unsigned long n) { }
static inline void ai_mm_emit_thp_fault_alloc(u32 p, unsigned long a) { }
static inline void ai_mm_emit_thp_fault_fallback(u32 p, unsigned long a,
						 u8 o) { }
static inline void ai_mm_emit_thp_collapse(u32 p, unsigned long a, u8 s) { }
static inline void ai_mm_emit_thp_split(u32 p, unsigned long a) { }
static inline void ai_mm_emit_hugetlb_alloc(const char *h, u8 s) { }
static inline void ai_mm_emit_compaction(s32 n, u8 o, u8 s,
					 unsigned long sp) { }
static inline void ai_mm_emit_page_migrate(s32 f, s32 t, unsigned long n) { }
static inline void ai_mm_emit_oom_event(u32 p, const char *c, unsigned long t,
					unsigned long r, s16 o, u8 s) { }
static inline void ai_mm_emit_oom_score_adj(u32 p, const char *c, s16 o,
					    s16 n, u32 b) { }
static inline void ai_mm_emit_mem_pressure(s32 n, u8 l) { }
static inline void ai_mm_emit_memory_failure(unsigned long p, u32 t, u8 a) { }
static inline void ai_mm_emit_kasan_report(unsigned long a, unsigned long ip,
					   u32 s, u8 w, const char *b) { }
static inline void ai_mm_emit_kfence_report(unsigned long a, u8 w,
					    const char *b) { }

#endif /* CONFIG_AIKERNEL_MM */

/* ---- vm_swappiness 访问器（Prompt 13，mm.swappiness 可控制参数） ----
 * 实现于 mm/vmscan.c（CONFIG_AIKERNEL_RUNTIME 门控）；mm/ 与 AIKernel 内
 * 统一经本声明访问（n 配置时 vmscan.c 条件 include 一并剔除）。 */

#ifdef CONFIG_AIKERNEL_RUNTIME
int ai_vmscan_swappiness_get(void);
int ai_vmscan_swappiness_set(int val);
#endif /* CONFIG_AIKERNEL_RUNTIME */

/* ---- THP enabled 访问器（mm.thp 可控制参数；实现于 mm/huge_memory.c，
 *      CONFIG_TRANSPARENT_HUGEPAGE=y 才有定义，ai_mm.c 同门控调用） ---- */

#define AI_THP_MODE_NEVER	0
#define AI_THP_MODE_MADVISE	1
#define AI_THP_MODE_ALWAYS	2

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
int ai_thp_flags_get(void);
int ai_thp_flags_set(int mode);
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

#endif /* _AIKERNEL_MM_AI_MM_H */

