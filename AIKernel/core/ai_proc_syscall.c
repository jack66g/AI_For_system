// SPDX-License-Identifier: GPL-2.0
/*
 * ai_proc_syscall.c - AIKernel B 轨 syscall 遥测（自 ai_proc.c 拆分）
 *
 * 职责一句话：syscall 全量参数采样（默认 1/256）入口/出口配对发射、
 * per-CPU 频率/序列/错误簇状态维护，以及第15.03类 syscall 模式发射
 * （frequency/sequence/error_cluster）。
 *
 * 拆分说明：函数体自原 ai_proc.c（1907 行）逐字搬移；per-CPU 状态
 * ai_syscall_freq/ai_syscall_seq/ai_syscall_seq_n 定义在本文件（原 static，
 * 拆分后经 ai_proc_internal.h 的 DECLARE_PER_CPU 供 ai_proc_sampler.c
 * 周期汇总）；AI_SYSCALL_NR_MAX 宏移入 ai_proc_internal.h。
 * 门控：整个文件在 CONFIG_AIKERNEL_TELEMETRY 下编译（与拆分前一致）。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/cgroup.h>
#include <linux/sort.h>
#include <linux/sched/deadline.h>
#include <linux/input-event-codes.h>
#include "ai_types.h"
#include "ai_proc.h"
#include "ai_control.h"

#ifdef CONFIG_AIKERNEL_TELEMETRY
#include "ai_telemetry.h"
#endif
#include "ai_proc_internal.h"

#ifdef CONFIG_AIKERNEL_TELEMETRY

/* ---- 05.04 syscall（默认采样 1/256，pair 联动） ---- */


DEFINE_PER_CPU(u32[AI_SYSCALL_NR_MAX], ai_syscall_freq);
DEFINE_PER_CPU(u32[64], ai_syscall_seq);
DEFINE_PER_CPU(u16, ai_syscall_seq_n);

bool ai_telemetry_syscall_entry(u32 nr, const char *name,
				u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5,
				u64 *entry_ts_ns)
{
	struct ai_syscall_entry_payload p;
	u32 *freq, *seq;
	u16 *seq_n;
	bool ok;

	if (entry_ts_ns)
		*entry_ts_ns = 0;
	if (nr >= AI_SYSCALL_NR_MAX)
		return false;

	preempt_disable();
	freq = this_cpu_ptr(ai_syscall_freq);
	freq[nr]++;

	/* 序列累积（完整无哈希，每 64 条 flush） */
	seq = this_cpu_ptr(ai_syscall_seq);
	seq_n = this_cpu_ptr(&ai_syscall_seq_n);
	if (*seq_n < 64) {
		seq[(*seq_n)++] = nr;
	} else {
		struct ai_syscall_seq_payload sp;

		sp.type = 2;
		sp.pid = current ? task_pid_nr(current) : 0;
		sp.n = 64;
		if (current)
			strscpy(sp.comm, current->comm, TASK_COMM_LEN);
		else
			sp.comm[0] = '\0';
		memcpy(sp.seq, seq, sizeof(sp.seq));
		ai_telemetry_emit_direct(AI_CAT_USER_BEHAVIOR,
					 AI_EV_SYSCALL_PATTERN,
					 AI_SEV_DEBUG, &sp, sizeof(sp));
		*seq_n = 0;
	}

	ok = ai_telemetry_sample_take(AI_CAT_USER_INPUT, AI_EV_SYSCALL);
	if (ok) {
		p.type = 1;
		p.syscall_nr = nr;
		strscpy(p.syscall_name, name ? name : "?", sizeof(p.syscall_name));
		p.arg0 = a0;
		p.arg1 = a1;
		p.arg2 = a2;
		p.arg3 = a3;
		p.arg4 = a4;
		p.arg5 = a5;
		if (entry_ts_ns)
			*entry_ts_ns = ktime_get_ns();
		ai_telemetry_emit_direct(AI_CAT_USER_INPUT, AI_EV_SYSCALL,
					 AI_SEV_DEBUG, &p, sizeof(p));
	}
	preempt_enable();
	return ok;
}
EXPORT_SYMBOL_GPL(ai_telemetry_syscall_entry);

/* 错误簇：per-CPU 64 槽（pid,nr,errno）连续错误计数 */
struct ai_err_cluster_ent {
	u32 pid, nr;
	s32 errno_val;
	u32 count;
};

static DEFINE_PER_CPU(struct ai_err_cluster_ent[64], ai_err_cluster);

void ai_telemetry_syscall_exit(u32 nr, s64 retval, u64 entry_ts_ns,
			       bool sampled)
{
	struct ai_syscall_exit_payload p;
	struct ai_err_cluster_ent *tbl;

	if (sampled) {
		p.type = 2;
		p.syscall_nr = nr;
		p.retval = retval;
		p.latency_ns = ktime_get_ns() - entry_ts_ns;
		ai_telemetry_emit_direct(AI_CAT_USER_INPUT, AI_EV_SYSCALL,
					 AI_SEV_DEBUG, &p, sizeof(p));
	}

	if (retval >= 0 || nr >= AI_SYSCALL_NR_MAX)
		return;

	preempt_disable();
	tbl = this_cpu_ptr(ai_err_cluster);
	if (current) {
		int i, free_i = -1;
		u32 pid = task_pid_nr(current);

		for (i = 0; i < 64; i++) {
			if (tbl[i].count &&
			    tbl[i].pid == pid && tbl[i].nr == nr &&
			    tbl[i].errno_val == (s32)retval) {
				tbl[i].count++;
				if (tbl[i].count >= 3) {
					struct ai_syscall_err_payload ep;

					ep.type = 3;
					ep.pid = pid;
					ep.syscall_nr = nr;
					ep.errno_val = (s32)retval;
					ep.consecutive_count = tbl[i].count;
					ep.syscall_name[0] = '\0';
					strscpy(ep.comm, current->comm,
						sizeof(ep.comm));
					ai_telemetry_emit_direct(
						AI_CAT_USER_BEHAVIOR,
						AI_EV_SYSCALL_PATTERN,
						AI_SEV_IMPORTANT,
						&ep, sizeof(ep));
					tbl[i].count = 0;
				}
				preempt_enable();
				return;
			}
			if (!tbl[i].count && free_i < 0)
				free_i = i;
		}
		if (free_i >= 0) {
			tbl[free_i].pid = pid;
			tbl[free_i].nr = nr;
			tbl[free_i].errno_val = (s32)retval;
			tbl[free_i].count = 1;
		}
	}
	preempt_enable();
}
EXPORT_SYMBOL_GPL(ai_telemetry_syscall_exit);

/* ---- 15.03 syscall 模式（frequency/sequence/error_cluster） ---- */

void ai_telemetry_syscall_frequency(u32 nr, u32 count_per_sec,
				    const char *name)
{
	struct ai_syscall_freq_payload p;

	p.type = 1;
	p.syscall_nr = nr;
	p.count_per_sec = count_per_sec;
	strscpy(p.syscall_name, name ? name : "?", sizeof(p.syscall_name));
	ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_SYSCALL_PATTERN,
			  AI_SEV_DEBUG, &p, sizeof(p));
}

void ai_telemetry_syscall_sequence(u32 pid, const u32 *seq, u16 n,
				   const char *comm)
{
	struct ai_syscall_seq_payload *p;
	u8 *stage;

	if (!seq || !n)
		return;
	preempt_disable();
	stage = this_cpu_ptr(ai_payload_stage);
	p = (struct ai_syscall_seq_payload *)stage;
	p->type = 2;
	p->pid = pid;
	p->n = n;
	strscpy(p->comm, comm ? comm : "?", sizeof(p->comm));
	memcpy(p->seq, seq, n * sizeof(u32));
	ai_telemetry_emit_direct(AI_CAT_USER_BEHAVIOR, AI_EV_SYSCALL_PATTERN,
				 AI_SEV_DEBUG, p, sizeof(*p));
	preempt_enable();
}

void ai_telemetry_syscall_error_cluster(u32 pid, u32 nr, s32 errno_val,
					u32 consecutive_count,
					const char *comm)
{
	struct ai_syscall_err_payload p;

	p.type = 3;
	p.pid = pid;
	p.syscall_nr = nr;
	p.errno_val = errno_val;
	p.consecutive_count = consecutive_count;
	p.syscall_name[0] = '\0';
	strscpy(p.comm, comm ? comm : "?", sizeof(p.comm));
	ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_SYSCALL_PATTERN,
			  AI_SEV_IMPORTANT, &p, sizeof(p));
}

#endif /* CONFIG_AIKERNEL_TELEMETRY */
