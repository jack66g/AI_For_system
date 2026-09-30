// SPDX-License-Identifier: GPL-2.0
/*
 * ai_proc_user.c - AIKernel B 轨第15类用户行为遥测（自 ai_proc.c 拆分）
 *
 * 职责一句话：用户会话、应用启动/生命周期/崩溃、用户活跃/空闲、
 * 焦点窗口、GPU 占位接口的类型化发射实现（15.01/15.02/15.06）。
 * （15.03 syscall 模式发射在 ai_proc_syscall.c，与采样状态同文件内聚。）
 *
 * 拆分说明：函数体自原 ai_proc.c（1907 行）逐字搬移；本文件无新增
 * static 共享（ai_payload_stage 经 ai_proc_internal.h 共享）。
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

/* ==================================================================
 * 第15类：用户行为
 * ================================================================== */

void ai_telemetry_user_session(u32 uid, u32 pid, u64 login_time_ns,
			       const char *tty_name, const char *comm)
{
	struct ai_user_session_payload p;

	p.type = 1;
	p.uid = uid;
	p.pid = pid;
	p.login_time_ns = login_time_ns;
	strscpy(p.tty_name, tty_name ? tty_name : "?", sizeof(p.tty_name));
	strscpy(p.comm, comm ? comm : "?", sizeof(p.comm));
	ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_USER_SESSION,
			  AI_SEV_NORMAL, &p, sizeof(p));
}

void ai_telemetry_app_launch(u32 uid, u32 pid, const char *full_path,
			     u16 cmdline_len, const u8 *cmdline,
			     u16 cwd_len, const u8 *cwd)
{
	struct ai_app_launch_payload *p;
	u8 *stage;
	u32 total;

	if (!full_path)
		return;
	total = (u32)cmdline_len + (u32)cwd_len;
	if (total > AI_TELEMETRY_MAX_DATA_LEN - sizeof(*p))
		total = AI_TELEMETRY_MAX_DATA_LEN - sizeof(*p);

	preempt_disable();
	stage = this_cpu_ptr(ai_payload_stage);
	p = (struct ai_app_launch_payload *)stage;
	p->type = 1;
	p->uid = uid;
	p->pid = pid;
	strscpy(p->full_path, full_path, sizeof(p->full_path));
	p->cmdline_len = cmdline_len;
	p->cwd_len = cwd_len;
	if (cmdline_len && cmdline)
		memcpy(p->data, cmdline, min_t(u32, cmdline_len, total));
	if (cwd_len && cwd && cmdline_len < total)
		memcpy(p->data + cmdline_len, cwd,
		       min_t(u32, cwd_len, total - cmdline_len));
	ai_telemetry_emit_direct(AI_CAT_USER_BEHAVIOR, AI_EV_USER_SESSION,
				 AI_SEV_NORMAL, p, sizeof(*p) + total);
	preempt_enable();
}

void ai_telemetry_app_lifetime(const char *full_path, u64 total_runtime_s,
			       int exit_code)
{
	struct ai_app_lifetime_payload p;

	p.type = 2;
	strscpy(p.full_path, full_path ? full_path : "?", sizeof(p.full_path));
	p.total_runtime_s = total_runtime_s;
	p.exit_code = exit_code;
	ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_USER_SESSION,
			  AI_SEV_NORMAL, &p, sizeof(p));
}

void ai_telemetry_app_crash(u32 pid, const char *full_path,
			    const char *signal_name)
{
	struct ai_app_crash_payload p;

	p.type = 3;
	p.pid = pid;
	strscpy(p.full_path, full_path ? full_path : "?", sizeof(p.full_path));
	strscpy(p.signal_name, signal_name ? signal_name : "?",
		sizeof(p.signal_name));
	ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_USER_SESSION,
			  AI_SEV_CRITICAL, &p, sizeof(p));
}

void ai_telemetry_user_active(u32 uid)
{
	struct ai_focus_payload p;

	p.type = 1;
	p.uid = uid;
	p.pid = current ? task_pid_nr(current) : 0;
	p.duration_ns = 0;
	p.window_title[0] = '\0';
	p.window_class[0] = '\0';
	p.tty_name[0] = '\0';
	ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_USER_ACTIVITY,
			  AI_SEV_DEBUG, &p, sizeof(p));
}

void ai_telemetry_user_idle(u64 idle_duration_s, const char *reason)
{
	struct ai_focus_payload p;

	p.type = 2;
	p.uid = 0;
	p.pid = 0;
	p.duration_ns = idle_duration_s * 1000000000ULL;
	strscpy(p.window_title, reason ? reason : "idle",
		sizeof(p.window_title));
	p.window_class[0] = '\0';
	p.tty_name[0] = '\0';
	ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_USER_ACTIVITY,
			  AI_SEV_NORMAL, &p, sizeof(p));
}

void ai_telemetry_focus_window(const char *tty_name, u32 pid,
			       const char *title, const char *klass,
			       u64 duration_ns)
{
	struct ai_focus_payload p;

	p.type = 3;
	p.uid = 0;
	p.pid = pid;
	p.duration_ns = duration_ns;
	strscpy(p.window_title, title ? title : "?", sizeof(p.window_title));
	strscpy(p.window_class, klass ? klass : "?", sizeof(p.window_class));
	strscpy(p.tty_name, tty_name ? tty_name : "?", sizeof(p.tty_name));
	ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_USER_ACTIVITY,
			  AI_SEV_DEBUG, &p, sizeof(p));
}


void ai_telemetry_gpu_usage(u32 pid, u32 gpu_id, u32 utilization_pct,
			    u32 mem_used_mb)
{
	struct ai_gpu_payload p;

	p.type = 1;
	p.pid = pid;
	p.gpu_id = gpu_id;
	p.utilization_pct = utilization_pct;
	p.mem_used_mb = mem_used_mb;
	p.kernel_name[0] = '\0';
	p.duration_us = 0;
	ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_GPU, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

void ai_telemetry_gpu_compute(u32 pid, u32 gpu_id, const char *kernel_name,
			      u64 duration_us)
{
	struct ai_gpu_payload p;

	p.type = 2;
	p.pid = pid;
	p.gpu_id = gpu_id;
	p.utilization_pct = 0;
	p.mem_used_mb = 0;
	strscpy(p.kernel_name, kernel_name ? kernel_name : "?",
		sizeof(p.kernel_name));
	p.duration_us = duration_us;
	ai_telemetry_emit(AI_CAT_USER_BEHAVIOR, AI_EV_GPU, AI_SEV_DEBUG,
			  &p, sizeof(p));
}

#endif /* CONFIG_AIKERNEL_TELEMETRY */
