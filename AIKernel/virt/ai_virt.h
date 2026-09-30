// SPDX-License-Identifier: GPL-2.0
/*
 * ai_virt.h - AIKernel 虚拟化子系统统一接口头（Prompt 10，重构计划 模块12）
 *
 * 本文件是 virt/kvm/、arch/x86/kvm/、drivers/virtio/、drivers/vfio/ 全部 AI
 * 埋点的唯一接入点：
 *   A 轨（控制）：ai_virt_*_hook() 系列 —— 让 AI 参与虚拟化决策，
 *                 空实现 = 原样放行（不改变任何内核默认行为）；
 *   B 轨（感知）：第13类 虚拟化感知的 payload 结构 + 发射辅助，
 *                 全量原始零脱敏。
 *
 * 零回归策略：
 *   - CONFIG_AIKERNEL_VIRT=n：本头文件不参与任何编译（调用点条件剔除）；
 *   - CONFIG_AIKERNEL_TELEMETRY=n：ai_telemetry_* 退化为 static inline
 *     空函数（ai_telemetry.h 内置兜底），Hook 本身只计数不发射。
 *
 * 热路径安全性（VM Exit 热路径）：
 *   - 全部 Hook/发射辅助只传标量（KVM 类型由调用点解引用后传入）→ 本头零
 *     KVM 依赖，ai_virt.c 在 CONFIG_KVM=n 的基础配置下照常编译；
 *   - vcpu_run 发射 = sample_take（1 次 per-CPU inc+分支）+ 栈上 payload +
 *     emit_direct 直写（per-CPU ring 无锁，<100ns），零锁零分配零 printk；
 *   - per-CPU 计数器一律直接对符号操作（Prompt 09 早期启动崩溃先例）。
 */

#ifndef _AIKERNEL_VIRT_AI_VIRT_H
#define _AIKERNEL_VIRT_AI_VIRT_H

#include "../core/ai_types.h"
#include "../core/ai_telemetry.h"
#include <linux/types.h>

/* ==================================================================
 * B 轨：第13类 虚拟化感知 payload（事件编号对齐 enum ai_event_type
 * 13.01~13.05；首字节 type 区分计划内子事件）
 * ==================================================================
 */

enum ai_virt_sub_event {
	AI_VIRT_VCPU_SCHEDULE	= 1,	/* 13.01 vCPU 调度 */
	AI_VIRT_VM_START,		/* 13.01 VM 生命周期：创建 */
	AI_VIRT_VM_STOP,		/* 13.01 VM 生命周期：销毁 */
	AI_VIRT_VCPU_RUN,		/* 13.03 VM Exit 采样 */
	AI_VIRT_EPT_PREFETCH,		/* 13.02 EPT 预填充 */
	AI_VIRT_BALLOON_ADJUST,		/* 13.04 virtio-balloon 调整 */
};

struct ai_virt_vcpu_payload {
	u8 type;			/* AI_VIRT_VCPU_SCHEDULE */
	u32 vcpu_id;
	u16 cpu;			/* vCPU 线程被调度到的 CPU */
	u32 pid;
	u8 preempted;			/* 是否曾抢占 */
};

struct ai_virt_vm_payload {
	u8 type;			/* AI_VIRT_VM_START / AI_VIRT_VM_STOP */
	u32 pid;
	u32 vcpu_num;			/* VM 的 vCPU 数 */
	u64 mem_bytes;			/* VM 内存大小 */
	u64 vm_addr;			/* struct kvm 地址（全量零脱敏） */
	char comm[TASK_COMM_LEN];	/* 创建者进程名 */
};

struct ai_virt_vcpu_run_payload {
	u8 type;			/* AI_VIRT_VCPU_RUN */
	u32 vcpu_id;
	u32 exit_reason;		/* 本次 VM Exit 原因（VMX 退出码） */
	u64 exit_count;			/* 该 vCPU 累计退出次数 */
	u64 guest_rip;			/* 退出时 Guest 指令指针 */
};

struct ai_virt_ept_payload {
	u8 type;			/* AI_VIRT_EPT_PREFETCH */
	u32 vcpu_id;
	u64 gfn;			/* Guest 页帧号 */
	u8 level;			/* 页表层级（4K=1, 2M=2, 1G=3） */
	u8 exec;			/* 是否可执行 */
	u8 writable;			/* 是否可写 */
};

struct ai_virt_balloon_payload {
	u8 type;			/* AI_VIRT_BALLOON_ADJUST */
	u32 target_pages;		/* 目标气球页数 */
	u32 num_pages;			/* 当前气球页数 */
	s32 diff;			/* 本次调整量（>0 膨胀 <0 收缩） */
	u8 update_reason;		/* 调整原因（气球属性/命令） */
};

/* ---- 决策统计 ---- */

struct ai_virt_stats {
	u64 vcpu_hook_calls;
	u64 mmu_hook_calls;
	u64 irq_hook_calls;
	u64 balloon_hook_calls;
	u64 vfio_hook_calls;
	u64 emit_vcpu, emit_vm, emit_run, emit_ept, emit_balloon;
};

#ifdef CONFIG_AIKERNEL_VIRT

/* ---- A 轨 Hook（实现见 ai_virt.c；空实现 = 原样放行，全标量参数） ---- */

/**
 * ai_virt_vcpu_hook() - AI 优化 vCPU pinning/调度
 * @vcpu_id: vCPU 编号（用户态创建时给定）
 * @cpu: vCPU 线程被调度到的 CPU
 * @pid: vCPU 线程 pid
 * @preempted: 该 vCPU 此前是否曾被抢占
 *
 * 由 virt/kvm/kvm_main.c kvm_sched_in() 调用。空实现无操作。
 */
void ai_virt_vcpu_hook(int vcpu_id, int cpu, int pid, bool preempted);

/**
 * ai_virt_mmu_hook() - AI 预测 Guest 页面访问，预填充 EPT
 * @vcpu_id: vCPU 编号
 * @gfn: Guest 页帧号
 * @level: 页表层级
 * @exec: 是否可执行
 * @prefetch: 出参/入参；AI 建议预填充大页（空实现不改，默认 false）
 *
 * 由 arch/x86/kvm/mmu/mmu.c direct_page_fault() direct_map() 前调用。
 * 空实现不改 *prefetch（本步调用点仅预留位）。
 */
void ai_virt_mmu_hook(int vcpu_id, u64 gfn, u8 level, u8 exec,
		      bool *prefetch);

/**
 * ai_virt_irq_hook() - AI 聚合中断，减少 VM Exit
 * @irq: 中断源标识
 * @level: 中断电平
 * @coalesce: 出参/入参；AI 建议聚合（空实现不改，默认 false）
 *
 * 由 arch/x86/kvm/irq.c kvm_arch_set_irq_inatomic() 入口调用。空实现不改。
 */
void ai_virt_irq_hook(int irq, int level, bool *coalesce);

/**
 * ai_virt_balloon_hook() - AI 预测 Guest 内存需求，智能调节气球
 * @diff: 当前偏离目标量
 * @target_pages: 出参/入参；气球目标页数（AI 可改写）
 *
 * 由 drivers/virtio/virtio_balloon.c update_balloon_size_func() 调用。
 * 空实现不改 *target_pages。
 */
void ai_virt_balloon_hook(s64 diff, u32 *target_pages);

/**
 * ai_virt_vfio_hook() - AI 辅助直通 DMA 映射策略（预留）
 * @iova: DMA 地址
 * @pfn: 物理页帧号
 * @npage: 页数
 * @prot: 映射保护位
 *
 * 由 drivers/vfio/vfio_iommu_type1.c vfio_iommu_map() 入口调用。空实现无操作。
 */
void ai_virt_vfio_hook(dma_addr_t iova, unsigned long pfn, long npage,
		       int prot);

/* ---- 第13类发射辅助（实现见 ai_virt.c；全部 sample_take + emit_direct） ---- */

void ai_telemetry_vcpu_schedule(u32 vcpu_id, u16 cpu, u32 pid, u8 preempted);
void ai_telemetry_vm_start(u32 vcpu_num, u64 mem_bytes, u64 vm_addr);
void ai_telemetry_vm_stop(u32 vcpu_num, u64 vm_addr);
void ai_telemetry_vcpu_run(u32 vcpu_id, u32 exit_reason, u64 exit_count,
			   u64 guest_rip);
void ai_telemetry_ept_prefetch(u32 vcpu_id, u64 gfn, u8 level, u8 exec,
			       u8 writable);
void ai_telemetry_virtio_balloon(u32 target_pages, u32 num_pages, s32 diff,
				 u8 update_reason);

/* ---- 决策框架 ---- */

void ai_virt_stats_read(struct ai_virt_stats *st);
bool ai_virt_sample_take(u32 rate);

#else /* !CONFIG_AIKERNEL_VIRT */

/* 空函数兜底：CONFIG_AIKERNEL_VIRT=n 时调用点不编译，
 * 此处兜底仅供 AIKernel/ 内部其他模块引用时保持可编译。 */
static inline void ai_virt_vcpu_hook(int vcpu_id, int cpu, int pid,
				     bool preempted)
{ }
static inline void ai_virt_mmu_hook(int vcpu_id, u64 gfn, u8 level, u8 exec,
				    bool *prefetch)
{ }
static inline void ai_virt_irq_hook(int irq, int level, bool *coalesce)
{ }
static inline void ai_virt_balloon_hook(s64 diff, u32 *target_pages)
{ }
static inline void ai_virt_vfio_hook(dma_addr_t iova, unsigned long pfn,
				     long npage, int prot)
{ }
static inline void ai_telemetry_vcpu_schedule(u32 vcpu_id, u16 cpu, u32 pid,
					      u8 preempted)
{ }
static inline void ai_telemetry_vm_start(u32 vcpu_num, u64 mem_bytes,
					 u64 vm_addr)
{ }
static inline void ai_telemetry_vm_stop(u32 vcpu_num, u64 vm_addr)
{ }
static inline void ai_telemetry_vcpu_run(u32 vcpu_id, u32 exit_reason,
					 u64 exit_count, u64 guest_rip)
{ }
static inline void ai_telemetry_ept_prefetch(u32 vcpu_id, u64 gfn, u8 level,
					     u8 exec, u8 writable)
{ }
static inline void ai_telemetry_virtio_balloon(u32 target_pages,
					       u32 num_pages, s32 diff,
					       u8 update_reason)
{ }
static inline void ai_virt_stats_read(struct ai_virt_stats *st)
{ if (st) memset(st, 0, sizeof(*st)); }
static inline bool ai_virt_sample_take(u32 rate)
{ return false; }

#endif /* CONFIG_AIKERNEL_VIRT */

#endif /* _AIKERNEL_VIRT_AI_VIRT_H */
