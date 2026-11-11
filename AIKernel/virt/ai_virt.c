// SPDX-License-Identifier: GPL-2.0
/*
 * ai_virt.c - AIKernel 虚拟化核心（Prompt 10，重构计划 模块12）
 *
 * A 轨：原 5 个 ai_virt_*_hook() 决策钩已按 K0 真相表 §4 删除（空转纯
 *       开销；观测能力由 B 轨发射辅助承载不受影响）；
 * B 轨：第13类 虚拟化感知（13.01~13.05）发射辅助，全部
 *       sample_take 采样判定 + 栈上 payload + emit_direct 直写。
 *
 * 热路径安全性（VM Exit 热路径）：vcpu_run 发射 = 1 次 per-CPU inc + 分支
 * （1/64 采样才构建 payload），per-CPU ring 无锁写，零锁零分配零 printk。
 * per-CPU 计数器直接对符号操作（Prompt 09 早期启动崩溃先例）。
 */

#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/pid.h>

#include "ai_virt.h"

/* ---- 决策统计（per-CPU 近似，汇总读取） ---- */

static DEFINE_PER_CPU(struct ai_virt_stats, ai_virt_pcpu_stats);

/* ---- per-CPU 采样计数器（无锁） ---- */

struct ai_virt_percpu {
	u32 vcpu_samples;		/* vCPU 调度采样计数器 */
	u32 run_samples;		/* VM Exit 采样计数器 */
	u32 ept_samples;		/* EPT 预填充采样计数器 */
	u32 common_samples;		/* 通用采样计数器 */
};

static DEFINE_PER_CPU(struct ai_virt_percpu, ai_virt_percpu);

bool ai_virt_sample_take(u32 rate)
{
	u32 c = __this_cpu_inc_return(ai_virt_percpu.common_samples) - 1;

	return (rate <= 1) || ((c % rate) == 0);
}
EXPORT_SYMBOL_GPL(ai_virt_sample_take);

static bool ai_virt_vcpu_sample_take(void)
{
	u32 c = __this_cpu_inc_return(ai_virt_percpu.vcpu_samples) - 1;

	return (c % 32) == 0;
}

static bool ai_virt_run_sample_take(void)
{
	u32 c = __this_cpu_inc_return(ai_virt_percpu.run_samples) - 1;

	return (c % 64) == 0;
}

static bool ai_virt_ept_sample_take(void)
{
	u32 c = __this_cpu_inc_return(ai_virt_percpu.ept_samples) - 1;

	return (c % 64) == 0;
}

void ai_virt_stats_read(struct ai_virt_stats *st)
{
	int cpu;

	if (!st)
		return;
	memset(st, 0, sizeof(*st));
	for_each_possible_cpu(cpu) {
		const struct ai_virt_stats *p = per_cpu_ptr(&ai_virt_pcpu_stats,
							   cpu);

		st->emit_vcpu += p->emit_vcpu;
		st->emit_vm += p->emit_vm;
		st->emit_run += p->emit_run;
		st->emit_ept += p->emit_ept;
		st->emit_balloon += p->emit_balloon;
	}
}
EXPORT_SYMBOL_GPL(ai_virt_stats_read);

/* ==================================================================
 * B 轨：第13类 虚拟化感知发射辅助
 * ==================================================================
 */

void ai_telemetry_vcpu_schedule(u32 vcpu_id, u16 cpu, u32 pid, u8 preempted)
{
	struct ai_virt_vcpu_payload p;

	if (!ai_virt_vcpu_sample_take())
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_VIRT_VCPU_SCHEDULE;
	p.vcpu_id = vcpu_id;
	p.cpu = cpu;
	p.pid = pid;
	p.preempted = preempted;
	this_cpu_inc(ai_virt_pcpu_stats.emit_vcpu);
	ai_telemetry_emit_direct(AI_CAT_VIRT, AI_EV_VCPU, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_vcpu_schedule);

void ai_telemetry_vm_start(u32 vcpu_num, u64 mem_bytes, u64 vm_addr)
{
	struct ai_virt_vm_payload p;

	if (!ai_virt_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_VIRT_VM_START;
	p.pid = task_pid_nr(current);
	p.vcpu_num = vcpu_num;
	p.mem_bytes = mem_bytes;
	p.vm_addr = vm_addr;
	strscpy(p.comm, current->comm, sizeof(p.comm));
	this_cpu_inc(ai_virt_pcpu_stats.emit_vm);
	ai_telemetry_emit_direct(AI_CAT_VIRT, AI_EV_VCPU, AI_SEV_IMPORTANT,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_vm_start);

void ai_telemetry_vm_stop(u32 vcpu_num, u64 vm_addr)
{
	struct ai_virt_vm_payload p;

	if (!ai_virt_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_VIRT_VM_STOP;
	p.pid = task_pid_nr(current);
	p.vcpu_num = vcpu_num;
	p.mem_bytes = 0;
	p.vm_addr = vm_addr;
	strscpy(p.comm, current->comm, sizeof(p.comm));
	this_cpu_inc(ai_virt_pcpu_stats.emit_vm);
	ai_telemetry_emit_direct(AI_CAT_VIRT, AI_EV_VCPU, AI_SEV_IMPORTANT,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_vm_stop);

void ai_telemetry_vcpu_run(u32 vcpu_id, u32 exit_reason, u64 exit_count,
			   u64 guest_rip)
{
	struct ai_virt_vcpu_run_payload p;

	if (!ai_virt_run_sample_take())
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_VIRT_VCPU_RUN;
	p.vcpu_id = vcpu_id;
	p.exit_reason = exit_reason;
	p.exit_count = exit_count;
	p.guest_rip = guest_rip;
	this_cpu_inc(ai_virt_pcpu_stats.emit_run);
	ai_telemetry_emit_direct(AI_CAT_VIRT, AI_EV_KVM_EXIT, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_vcpu_run);

void ai_telemetry_ept_prefetch(u32 vcpu_id, u64 gfn, u8 level, u8 exec,
			       u8 writable)
{
	struct ai_virt_ept_payload p;

	if (!ai_virt_ept_sample_take())
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_VIRT_EPT_PREFETCH;
	p.vcpu_id = vcpu_id;
	p.gfn = gfn;
	p.level = level;
	p.exec = exec;
	p.writable = writable;
	this_cpu_inc(ai_virt_pcpu_stats.emit_ept);
	ai_telemetry_emit_direct(AI_CAT_VIRT, AI_EV_GUEST_MEM, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_ept_prefetch);

void ai_telemetry_virtio_balloon(u32 target_pages, u32 num_pages, s32 diff,
				 u8 update_reason)
{
	struct ai_virt_balloon_payload p;

	if (!ai_virt_sample_take(1))
		return;
	memset(&p, 0, sizeof(p));
	p.type = AI_VIRT_BALLOON_ADJUST;
	p.target_pages = target_pages;
	p.num_pages = num_pages;
	p.diff = diff;
	p.update_reason = update_reason;
	this_cpu_inc(ai_virt_pcpu_stats.emit_balloon);
	ai_telemetry_emit_direct(AI_CAT_VIRT, AI_EV_VIRTIO, AI_SEV_NORMAL,
				 &p, sizeof(p));
}
EXPORT_SYMBOL_GPL(ai_telemetry_virtio_balloon);
