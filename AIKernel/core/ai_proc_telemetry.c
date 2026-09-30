// SPDX-License-Identifier: GPL-2.0
/*
 * ai_proc_telemetry.c - AIKernel B 轨第5.05/6类进程遥测（自 ai_proc.c 拆分）
 *
 * 职责一句话：exec 命令行/Shell 命令/脚本内容发射（05.05）与进程生命周期/
 * 状态/信号/凭证/ns/cgroup/rusage/futex 类型化发射（第6类），以及大 payload
 * per-CPU 暂存区 ai_payload_stage 的定义（模块内共享）。
 *
 * 拆分说明：函数体自原 ai_proc.c（1907 行）逐字搬移；ai_sig_names/
 * ai_sig_name 仅本文件使用，保持 static；ai_payload_stage 原 static 定义
 * 提升为模块内部共享（声明见 ai_proc_internal.h）。
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

/* 大 payload（tty/exec/script 原始数据）用 per-CPU 暂存区，避免大栈 */
DEFINE_PER_CPU(u8[AI_TELEMETRY_MAX_DATA_LEN + 128], ai_payload_stage);

#define AI_SIGNAME_MAX 16

/* 信号名表（小表覆盖常用信号） */
static const struct {
	int sig;
	const char *name;
} ai_sig_names[] = {
	{ 1, "SIGHUP" }, { 2, "SIGINT" }, { 3, "SIGQUIT" }, { 4, "SIGILL" },
	{ 5, "SIGTRAP" }, { 6, "SIGABRT" }, { 7, "SIGBUS" }, { 8, "SIGFPE" },
	{ 9, "SIGKILL" }, { 10, "SIGUSR1" }, { 11, "SIGSEGV" }, { 12, "SIGUSR2" },
	{ 13, "SIGPIPE" }, { 14, "SIGALRM" }, { 15, "SIGTERM" }, { 16, "SIGSTKFLT" },
	{ 17, "SIGCHLD" }, { 18, "SIGCONT" }, { 19, "SIGSTOP" }, { 20, "SIGTSTP" },
	{ 21, "SIGTTIN" }, { 22, "SIGTTOU" }, { 23, "SIGURG" }, { 24, "SIGXCPU" },
	{ 25, "SIGXFSZ" }, { 26, "SIGVTALRM" }, { 27, "SIGPROF" }, { 28, "SIGWINCH" },
	{ 29, "SIGIO" }, { 30, "SIGPWR" }, { 31, "SIGSYS" }, { 34, "SIGRTMIN" },
};

static void ai_sig_name(int sig, char *buf, size_t sz)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ai_sig_names); i++) {
		if (ai_sig_names[i].sig == sig) {
			strscpy(buf, ai_sig_names[i].name, sz);
			return;
		}
	}
	snprintf(buf, sz, "sig%d", sig);
}

/* ---- 05.05 exec 命令行 / Shell 命令 / 脚本 ---- */

void ai_telemetry_exec_command(u32 pid, u32 ppid, u16 argc,
			       const u8 *full_cmdline, u16 cmdline_len,
			       const u8 *envp_sample, u16 envp_len)
{
	struct ai_exec_command_payload *p;
	u8 *stage;
	u32 total;

	if (!full_cmdline)
		return;
	total = (u32)cmdline_len + (u32)envp_len;
	if (total > AI_TELEMETRY_MAX_DATA_LEN - sizeof(*p))
		total = AI_TELEMETRY_MAX_DATA_LEN - sizeof(*p);

	preempt_disable();
	stage = this_cpu_ptr(ai_payload_stage);
	p = (struct ai_exec_command_payload *)stage;
	p->type = 1;
	p->pid = pid;
	p->ppid = ppid;
	p->argc = argc;
	p->full_cmdline_len = cmdline_len;
	memcpy(p->data, full_cmdline, min_t(u32, cmdline_len, total));
	if (envp_len && cmdline_len < total)
		memcpy(p->data + cmdline_len, envp_sample,
		       min_t(u32, envp_len, total - cmdline_len));
	ai_telemetry_emit_direct(AI_CAT_USER_INPUT, AI_EV_EXEC,
				 AI_SEV_NORMAL, p, sizeof(*p) + total);
	preempt_enable();
}

void ai_telemetry_shell_command(const char *shell, u16 cmdline_len,
				const u8 *cmdline, u16 cwd_len, const u8 *cwd)
{
	struct ai_shell_command_payload *p;
	u8 *stage;
	u32 total;

	if (!cmdline)
		return;
	total = (u32)cmdline_len + (u32)cwd_len;
	if (total > AI_TELEMETRY_MAX_DATA_LEN - sizeof(*p))
		total = AI_TELEMETRY_MAX_DATA_LEN - sizeof(*p);

	preempt_disable();
	stage = this_cpu_ptr(ai_payload_stage);
	p = (struct ai_shell_command_payload *)stage;
	p->type = 2;
	strscpy(p->shell, shell ? shell : "?", sizeof(p->shell));
	p->cmdline_len = cmdline_len;
	p->cwd_len = cwd_len;
	memcpy(p->data, cmdline, min_t(u32, cmdline_len, total));
	if (cwd_len && cmdline_len < total)
		memcpy(p->data + cmdline_len, cwd,
		       min_t(u32, cwd_len, total - cmdline_len));
	ai_telemetry_emit_direct(AI_CAT_USER_INPUT, AI_EV_EXEC,
				 AI_SEV_NORMAL, p, sizeof(*p) + total);
	preempt_enable();
}

void ai_telemetry_script_exec(const char *interp, const char *script_path,
			      const u8 *content, u16 content_len)
{
	struct ai_script_exec_payload *p;
	u8 *stage;
	u16 len;

	if (!content)
		return;
	len = min_t(u16, content_len,
		    (u16)(AI_TELEMETRY_MAX_DATA_LEN - sizeof(*p)));

	preempt_disable();
	stage = this_cpu_ptr(ai_payload_stage);
	p = (struct ai_script_exec_payload *)stage;
	p->type = 3;
	strscpy(p->interpreter, interp ? interp : "?", sizeof(p->interpreter));
	strscpy(p->script_path, script_path ? script_path : "?",
		sizeof(p->script_path));
	p->content_len = len;
	memcpy(p->content, content, len);
	ai_telemetry_emit_direct(AI_CAT_USER_INPUT, AI_EV_EXEC,
				 AI_SEV_NORMAL, p, sizeof(*p) + len);
	preempt_enable();
}

/* ==================================================================
 * 第6类：进程与线程
 * ================================================================== */

void ai_telemetry_process_fork(u32 parent_pid, u32 child_pid,
			       u64 clone_flags, const char *parent_comm,
			       const char *child_comm)
{
	struct ai_process_fork_payload p;
	u8 cls = AI_PROC_CLASS_BATCH;

#ifdef CONFIG_AIKERNEL_RUNTIME
	{
		struct ai_proc_slot slot;

		if (ai_proc_slot_get(child_pid, &slot) == AI_OK)
			cls = slot.class;
	}
#endif
	p.type = 1;
	p.parent_pid = parent_pid;
	p.child_pid = child_pid;
	p.clone_flags = clone_flags;
	p.child_class = cls;
	strscpy(p.parent_comm, parent_comm ? parent_comm : "?",
		sizeof(p.parent_comm));
	strscpy(p.child_comm, child_comm ? child_comm : "?",
		sizeof(p.child_comm));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_PROCESS_LIFE, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

void ai_telemetry_process_exec(u32 pid, u32 uid, u32 gid, u32 euid, u32 egid,
			       const char *full_path)
{
	struct ai_process_exec_payload p;

	p.type = 2;
	p.pid = pid;
	p.uid = uid;
	p.gid = gid;
	p.euid = euid;
	p.egid = egid;
	strscpy(p.full_path, full_path ? full_path : "?", sizeof(p.full_path));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_PROCESS_LIFE, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

void ai_telemetry_process_exit(u32 pid, int exit_code, int exit_signal,
			       u64 total_runtime_ns, const char *comm)
{
	struct ai_process_exit_payload p;

	p.type = 3;
	p.pid = pid;
	p.exit_code = exit_code;
	p.exit_signal = exit_signal;
	p.total_runtime_ns = total_runtime_ns;
	strscpy(p.comm, comm ? comm : "?", sizeof(p.comm));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_PROCESS_LIFE, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

void ai_telemetry_process_kthread(u32 pid, const char *kthread_name)
{
	struct ai_process_kthread_payload p;

	p.type = 4;
	p.pid = pid;
	strscpy(p.kthread_name, kthread_name ? kthread_name : "?",
		sizeof(p.kthread_name));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_PROCESS_LIFE, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

void ai_telemetry_process_state(u32 pid, u32 old_state, u32 new_state, u16 cpu,
				const char *comm)
{
	struct ai_process_state_payload p;

	p.type = 1;
	p.pid = pid;
	p.old_state = old_state;
	p.new_state = new_state;
	p.cpu = cpu;
	strscpy(p.comm, comm ? comm : "?", sizeof(p.comm));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_PROCESS_STATE, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

void ai_telemetry_process_priority(u32 pid, s32 old_prio, s32 new_prio,
				   s32 old_nice, s32 new_nice)
{
	struct ai_process_prio_payload p;

	p.type = 2;
	p.pid = pid;
	p.old_prio = old_prio;
	p.new_prio = new_prio;
	p.old_nice = old_nice;
	p.new_nice = new_nice;
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_PROCESS_STATE, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

void ai_telemetry_process_name(u32 pid, const char *old_comm,
			       const char *new_comm)
{
	struct ai_process_name_payload p;

	p.type = 3;
	p.pid = pid;
	strscpy(p.old_comm, old_comm ? old_comm : "?", sizeof(p.old_comm));
	strscpy(p.new_comm, new_comm ? new_comm : "?", sizeof(p.new_comm));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_PROCESS_STATE, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

void ai_telemetry_signal_generate(u32 from_pid, const char *from_comm,
				  u32 to_pid, const char *to_comm,
				  int signum, int sig_code)
{
	struct ai_signal_gen_payload p;

	p.type = 1;
	p.from_pid = from_pid;
	p.to_pid = to_pid;
	p.signum = signum;
	p.sig_code = sig_code;
	p.fault_addr = 0;
	strscpy(p.from_comm, from_comm ? from_comm : "?", sizeof(p.from_comm));
	strscpy(p.to_comm, to_comm ? to_comm : "?", sizeof(p.to_comm));
	ai_sig_name(signum, p.sig_name, sizeof(p.sig_name));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_SIGNAL, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

void ai_telemetry_signal_deliver(u32 pid, int signum, u8 handler_type,
				 const char *comm)
{
	struct ai_signal_deliver_payload p;

	p.type = 2;
	p.pid = pid;
	p.signum = signum;
	p.handler_type = handler_type;
	strscpy(p.comm, comm ? comm : "?", sizeof(p.comm));
	ai_sig_name(signum, p.sig_name, sizeof(p.sig_name));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_SIGNAL, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

void ai_telemetry_signal_abnormal(u32 pid, int signum, unsigned long fault_addr,
				  const char *comm)
{
	struct ai_signal_abnormal_payload p;

	p.type = 3;
	p.pid = pid;
	p.signum = signum;
	p.fault_addr = fault_addr;
	strscpy(p.comm, comm ? comm : "?", sizeof(p.comm));
	ai_sig_name(signum, p.sig_name, sizeof(p.sig_name));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_SIGNAL, AI_SEV_CRITICAL,
			  &p, sizeof(p));
}

void ai_telemetry_cred_change(u32 pid, u32 old_uid, u32 new_uid,
			      u32 old_gid, u32 new_gid, u32 old_euid,
			      u32 new_euid, u32 old_egid, u32 new_egid,
			      const char *comm)
{
	struct ai_cred_change_payload p;

	p.type = 1;
	p.pid = pid;
	p.old_uid = old_uid;
	p.new_uid = new_uid;
	p.old_gid = old_gid;
	p.new_gid = new_gid;
	p.old_euid = old_euid;
	p.new_euid = new_euid;
	p.old_egid = old_egid;
	p.new_egid = new_egid;
	strscpy(p.comm, comm ? comm : "?", sizeof(p.comm));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_CRED, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

void ai_telemetry_ns_change(u32 pid, u64 ns_type_flags, const char *comm)
{
	struct ai_ns_change_payload p;

	p.type = 2;
	p.pid = pid;
	p.ns_type_flags = ns_type_flags;
	strscpy(p.comm, comm ? comm : "?", sizeof(p.comm));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_CRED, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

void ai_telemetry_cgroup_attach(u32 pid, const char *comm,
				const char *cgroup_path)
{
	struct ai_cgroup_attach_payload p;

	p.type = 1;
	p.pid = pid;
	strscpy(p.comm, comm ? comm : "?", sizeof(p.comm));
	strscpy(p.cgroup_path, cgroup_path ? cgroup_path : "?",
		sizeof(p.cgroup_path));
	strscpy(p.subsys, "default", sizeof(p.subsys));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_CGROUP, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

void ai_telemetry_cgroup_limit_hit(const char *cgroup_path,
				   const char *resource, u64 limit, u64 usage)
{
	struct ai_cgroup_limit_payload p;

	p.type = 2;
	strscpy(p.cgroup_path, cgroup_path ? cgroup_path : "?",
		sizeof(p.cgroup_path));
	strscpy(p.resource, resource ? resource : "?", sizeof(p.resource));
	p.limit = limit;
	p.usage = usage;
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_CGROUP, AI_SEV_CRITICAL,
			  &p, sizeof(p));
}

void ai_telemetry_process_rusage(u32 pid, u64 utime_us, u64 stime_us,
				 u32 minflt, u32 majflt, u32 nvcsw,
				 u32 nivcsw, u32 rss_kb, u32 vsz_kb,
				 const char *comm)
{
	struct ai_process_rusage_payload p;

	p.type = 1;
	p.pid = pid;
	p.utime_us = utime_us;
	p.stime_us = stime_us;
	p.minflt = minflt;
	p.majflt = majflt;
	p.nvcsw = nvcsw;
	p.nivcsw = nivcsw;
	p.rss_kb = rss_kb;
	p.vsz_kb = vsz_kb;
	strscpy(p.comm, comm ? comm : "?", sizeof(p.comm));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_RUSAGE, AI_SEV_DEBUG,
			  &p, sizeof(p));
}

void ai_telemetry_process_io_stats(u32 pid, u64 rchar, u64 wchar,
				   u64 read_bytes, u64 write_bytes,
				   const char *comm)
{
	struct ai_process_io_payload p;

	p.type = 2;
	p.pid = pid;
	p.rchar = rchar;
	p.wchar = wchar;
	p.read_bytes = read_bytes;
	p.write_bytes = write_bytes;
	strscpy(p.comm, comm ? comm : "?", sizeof(p.comm));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_RUSAGE, AI_SEV_DEBUG,
			  &p, sizeof(p));
}

void ai_telemetry_process_fd_list(u32 pid, u32 fd_count,
				  const u8 *fd_details, u16 detail_len,
				  const char *comm)
{
	struct ai_process_fd_payload *p;
	u8 *stage;
	u16 len;

	len = min_t(u16, detail_len,
		    (u16)(AI_TELEMETRY_MAX_DATA_LEN - sizeof(*p)));
	if (len && !fd_details)
		len = 0;

	preempt_disable();
	stage = this_cpu_ptr(ai_payload_stage);
	p = (struct ai_process_fd_payload *)stage;
	p->type = 3;
	p->pid = pid;
	p->fd_count = fd_count;
	strscpy(p->comm, comm ? comm : "?", sizeof(p->comm));
	if (len) {
		memcpy(p->fd_details, fd_details, len);
		p->fd_details[len - 1] = '\0';
	} else {
		p->fd_details[0] = '\0';
	}
	ai_telemetry_emit_direct(AI_CAT_PROCESS, AI_EV_RUSAGE, AI_SEV_DEBUG,
				 p, sizeof(*p));
	preempt_enable();
}

void ai_telemetry_futex_wait(u32 pid, u64 addr, u32 val,
			     u64 wait_duration_us, const char *comm)
{
	struct ai_futex_wait_payload p;

	p.type = 1;
	p.pid = pid;
	p.addr = addr;
	p.val = val;
	p.wait_duration_us = wait_duration_us;
	strscpy(p.comm, comm ? comm : "?", sizeof(p.comm));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_FUTEX, AI_SEV_DEBUG,
			  &p, sizeof(p));
}

void ai_telemetry_futex_wake(u32 pid, u64 addr, u32 woken_count,
			     const char *comm)
{
	struct ai_futex_wake_payload p;

	p.type = 2;
	p.pid = pid;
	p.addr = addr;
	p.woken_count = woken_count;
	strscpy(p.comm, comm ? comm : "?", sizeof(p.comm));
	ai_telemetry_emit(AI_CAT_PROCESS, AI_EV_FUTEX, AI_SEV_DEBUG,
			  &p, sizeof(p));
}

#endif /* CONFIG_AIKERNEL_TELEMETRY */
