// SPDX-License-Identifier: GPL-2.0
/*
 * ai_proc_sampler.c - AIKernel 周期采样器 + ai_proc 子系统初始化（自 ai_proc.c 拆分）
 *
 * 职责一句话：1s 周期 kthread（ai_proc_sense）采样 rusage Top16/io 统计/
 * fd 列表/syscall 频率与序列并补发空闲事件，ai_proc_init 装配遥测初始化、
 * 采样率默认值与 proc 域可控参数表。
 *
 * 拆分说明：函数体自原 ai_proc.c（1907 行）逐字搬移；syscall per-CPU
 * 计数器经 ai_proc_internal.h 的 DECLARE_PER_CPU 访问（定义在
 * ai_proc_syscall.c）。ai_proc_init 内 CONFIG_AIKERNEL_TELEMETRY /
 * CONFIG_AIKERNEL_RUNTIME 条件块与拆分前逐字一致（仅 TELEMETRY 开启时
 * 才存在本文件与该 initcall，语义不变）。
 * 门控：整个文件在 CONFIG_AIKERNEL_TELEMETRY 下编译（与拆分前一致）。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
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
#include <linux/ai_accessors.h>

#ifdef CONFIG_AIKERNEL_TELEMETRY
#include "ai_telemetry.h"
#endif
#include "ai_proc_internal.h"

#ifdef CONFIG_AIKERNEL_TELEMETRY

/* ==================================================================
 * 周期采样器（1s：rusage/io/fd/syscall 频率/用户空闲）
 * ================================================================== */

#define AI_RUSAGE_TOP 16

static int ai_proc_rusage_cmp(const void *a, const void *b)
{
	const struct ai_process_rusage_payload *x = a, *y = b;
	u64 xc = x->utime_us + x->stime_us;
	u64 yc = y->utime_us + y->stime_us;

	return (xc < yc) - (xc > yc);
}

static void ai_proc_sample_rusage(void)
{
	struct ai_process_rusage_payload top[AI_RUSAGE_TOP];
	struct task_struct *p;
	int n = 0;

	rcu_read_lock();
	for_each_process(p) {
		u64 ut, st;

		if (p == current || p->pid != p->tgid)
			continue;
		task_lock(p);
		if (p->exit_state) {
			task_unlock(p);
			continue;
		}
		ut = p->utime / 1000;
		st = p->stime / 1000;
		if (n < AI_RUSAGE_TOP) {
			struct ai_process_rusage_payload *r = &top[n];
			struct mm_struct *mm;

			r->pid = task_pid_nr(p);
			r->utime_us = ut;
			r->stime_us = st;
			r->minflt = p->min_flt;
			r->majflt = p->maj_flt;
			r->nvcsw = p->nvcsw;
			r->nivcsw = p->nivcsw;
			mm = p->mm;
			if (mm) {
				r->rss_kb = get_mm_rss(mm) << (PAGE_SHIFT - 10);
				r->vsz_kb = (u32)(mm->total_vm << (PAGE_SHIFT - 10));
			} else {
				r->rss_kb = 0;
				r->vsz_kb = 0;
			}
			strscpy(r->comm, p->comm, TASK_COMM_LEN);
			n++;
		}
		task_unlock(p);
	}
	rcu_read_unlock();

	sort(top, n, sizeof(top[0]), ai_proc_rusage_cmp, NULL);
	for (n = 0; n < AI_RUSAGE_TOP; n++)
		ai_telemetry_process_rusage(top[n].pid, top[n].utime_us,
					    top[n].stime_us, top[n].minflt,
					    top[n].majflt, top[n].nvcsw,
					    top[n].nivcsw, top[n].rss_kb,
					    top[n].vsz_kb, top[n].comm);
}

static void ai_proc_sample_io(void)
{
	struct task_struct *p;
	int n = 0;

	rcu_read_lock();
	for_each_process(p) {
		struct ai_process_io_payload io;

		if (n >= AI_RUSAGE_TOP || p == current || p->pid != p->tgid)
			continue;
		task_lock(p);
		if (p->exit_state) {
			task_unlock(p);
			continue;
		}
		io.pid = task_pid_nr(p);
		io.rchar = READ_ONCE(p->ioac.rchar);
		io.wchar = READ_ONCE(p->ioac.wchar);
		io.read_bytes = READ_ONCE(p->ioac.read_bytes);
		io.write_bytes = READ_ONCE(p->ioac.write_bytes);
		strscpy(io.comm, p->comm, TASK_COMM_LEN);
		task_unlock(p);
		ai_telemetry_process_io_stats(io.pid, io.rchar, io.wchar,
					      io.read_bytes, io.write_bytes,
					      io.comm);
		n++;
	}
	rcu_read_unlock();
}

static void ai_proc_sample_fds(void)
{
	struct task_struct *p;
	int n = 0;

	rcu_read_lock();
	for_each_process(p) {
		struct files_struct *files;
		struct fdtable *fdt;
		unsigned int i, fd_count = 0;
		u8 buf[192];
		u8 *bp = buf;
		int left = sizeof(buf);

		if (n >= 4 || p == current || p->pid != p->tgid)
			continue;
		task_lock(p);
		if (p->exit_state || !p->files) {
			task_unlock(p);
			continue;
		}
		files = p->files;
		fdt = files_fdtable(files);
		rcu_read_lock();
		for (i = 0; i < fdt->max_fds; i++) {
			struct file *f;
			const char *path;
			char type;

			f = rcu_dereference(fdt->fd[i]);
			if (!f)
				continue;
			fd_count++;
			if (fd_count > 8 || left <= 16)
				continue;
			if (S_ISDIR(file_inode(f)->i_mode))
				type = 'D';
			else if (S_ISREG(file_inode(f)->i_mode))
				type = 'R';
			else if (S_ISCHR(file_inode(f)->i_mode))
				type = 'C';
			else if (S_ISSOCK(file_inode(f)->i_mode))
				type = 'S';
			else if (S_ISFIFO(file_inode(f)->i_mode))
				type = 'P';
			else
				type = '?';
			path = d_path(&f->f_path, (char *)bp + 8, left - 8);
			if (!IS_ERR(path)) {
				int pl = snprintf((char *)bp, left, "%u:%c:%s\n",
						  i, type, path);

				if (pl > 0) {
					bp += pl;
					left -= pl;
				}
			}
		}
		rcu_read_unlock();
		task_unlock(p);
		ai_telemetry_process_fd_list(task_pid_nr(p), fd_count, buf,
					     sizeof(buf) - left, p->comm);
		n++;
	}
	rcu_read_unlock();
}

/* 返回本周期全部 syscall 计数总和（已清零计数器） */
static u32 ai_proc_sample_syscall_freq(void)
{
	static u32 sum[AI_SYSCALL_NR_MAX];   /* 单采样线程专用，避免大栈 */
	u32 top_nr[8], top_cnt[8];
	u32 total = 0;
	int cpu, i, t;

	memset(top_nr, 0, sizeof(top_nr));
	memset(top_cnt, 0, sizeof(top_cnt));

	for_each_possible_cpu(cpu) {
		u32 *f = per_cpu_ptr(ai_syscall_freq, cpu);

		for (i = 0; i < AI_SYSCALL_NR_MAX; i++)
			sum[i] += READ_ONCE(f[i]);
	}
	for (i = 0; i < AI_SYSCALL_NR_MAX; i++) {
		if (!sum[i])
			continue;
		total += sum[i];
		for (t = 0; t < 8; t++) {
			if (sum[i] > top_cnt[t]) {
				memmove(&top_nr[t + 1], &top_nr[t],
					(8 - t - 1) * sizeof(u32));
				memmove(&top_cnt[t + 1], &top_cnt[t],
					(8 - t - 1) * sizeof(u32));
				top_nr[t] = i;
				top_cnt[t] = sum[i];
				break;
			}
		}
	}
	for (t = 0; t < 8; t++) {
		if (top_cnt[t])
			ai_telemetry_syscall_frequency(top_nr[t], top_cnt[t],
						       NULL);
	}
	for_each_possible_cpu(cpu) {
		u32 *f = per_cpu_ptr(ai_syscall_freq, cpu);

		memset(f, 0, AI_SYSCALL_NR_MAX * sizeof(u32));
	}
	return total;
}

static void ai_proc_sample_flush_seq(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		u16 n = per_cpu(ai_syscall_seq_n, cpu);

		if (n) {
			ai_telemetry_syscall_sequence(0,
				per_cpu_ptr(ai_syscall_seq, cpu), n, "?");
			per_cpu(ai_syscall_seq_n, cpu) = 0;
		}
	}
}

static struct task_struct *ai_proc_sampler_task;

static int ai_proc_sampler(void *unused)
{
	u32 idle_cnt = 0;
	static DEFINE_MUTEX(ai_idle_lock);
	static u64 last_idle_emit;

	while (!kthread_should_stop()) {
		u32 total;
		u64 now;

		set_current_state(TASK_INTERRUPTIBLE);
		if (schedule_timeout(HZ) > 0 && kthread_should_stop())
			break;
		if (kthread_should_stop())
			break;

		ai_proc_sample_rusage();
		ai_proc_sample_io();
		ai_proc_sample_fds();
		total = ai_proc_sample_syscall_freq();
		ai_proc_sample_flush_seq();

		/* 用户空闲：全局 syscall 计数静默连续 10s → idle（1/min 限频） */
		now = ktime_get_seconds();
		if (total == 0) {
			idle_cnt++;
			mutex_lock(&ai_idle_lock);
			if (idle_cnt >= 10 && (now - last_idle_emit) > 60) {
				ai_telemetry_user_idle((u64)idle_cnt,
						       "no-syscall");
				last_idle_emit = now;
			}
			mutex_unlock(&ai_idle_lock);
		} else {
			idle_cnt = 0;
		}
	}
	return 0;
}


/* ==================================================================
 * proc.signal / proc.freeze / proc.rlimit 立即生效参数
 * 真实内核效果：
 *   signal → send_sig_info 真实信号投递（value=信号号 0..64，0=探活校验）；
 *   freeze → value=1 SIGSTOP 冻结 / 0 SIGCONT 解冻（cgroup freezer 需要
 *            迁移目标进程到专用 cgroup，超参数接口安全边界，选择信号访问器，
 *            冻结态 task->__state=TASK_STOPPED 可经 ps 观测）；
 *   rlimit → data[2]=资源号，value=软限值，prlimit64 同语义（仅改
 *            rlim_cur 保留 rlim_max，经 kernel/sys.c 门控访问器）。
 * 安全边界：内核线程与 1 号进程拒绝；目标进程语义权限由 W2 闸门 +
 * ai_policy_safety 决策安全层约束（task 参数 data[0]=pid）。
 * ================================================================== */
static int ai_proc_target_get(s32 pid, struct task_struct **out)
{
	struct task_struct *task;

	if (pid <= 0)
		return AI_ERR_INVALID_ARG;
	task = find_get_task_by_vpid(pid);
	if (!task)
		return AI_ERR_NOT_FOUND;
	if ((task->flags & PF_KTHREAD) || task_pid_nr(task) <= 1) {
		put_task_struct(task);
		return AI_ERR_INVALID_ARG;   /* 内核线程 / init 拒绝 */
	}
	*out = task;
	return AI_OK;
}

static int ai_proc_signal_apply(struct ai_control_param *p, s32 pid,
				s64 value, s64 *eff)
{
	struct task_struct *task;
	struct kernel_siginfo info;
	int rc;

	rc = ai_proc_target_get(pid, &task);
	if (rc != AI_OK)
		return rc;

	if (value > 0) {
		clear_siginfo(&info);
		info.si_signo = (int)value;
		info.si_code = SI_KERNEL;
		rc = send_sig_info((int)value, &info, task);
		if (rc) {
			put_task_struct(task);
			return AI_ERR_GENERIC;
		}
	}
	put_task_struct(task);
	*eff = value;
	pr_info("AIKernel: proc.signal pid=%d sig=%lld delivered\n",
		pid, value);
	return AI_OK;
}

static int ai_proc_freeze_apply(struct ai_control_param *p, s32 pid,
				s64 value, s64 *eff)
{
	struct task_struct *task;
	int rc, sig;

	rc = ai_proc_target_get(pid, &task);
	if (rc != AI_OK)
		return rc;

	sig = (value == 1) ? SIGSTOP : SIGCONT;
	rc = send_sig(sig, task, 0);
	put_task_struct(task);
	if (rc)
		return AI_ERR_GENERIC;
	*eff = value;
	pr_info("AIKernel: proc.freeze pid=%d -> %lld (SIG%s)\n",
		pid, value, value == 1 ? "STOP" : "CONT");
	return AI_OK;
}

static int ai_proc_rlimit_apply_ex(struct ai_control_param *p, s32 pid,
				   s64 value, s64 *eff, const s64 *data)
{
	struct task_struct *task;
	unsigned int res;
	int rc;

	if (!data)
		return AI_ERR_INVALID_ARG;
	res = (unsigned int)data[2];   /* 决策 data[2]=rlimit 资源号 */
	rc = ai_proc_target_get(pid, &task);
	if (rc != AI_OK)
		return rc;

	rc = ai_sys_prlimit_set(task, res, (unsigned long)value);
	put_task_struct(task);
	if (rc)
		return AI_ERR_GENERIC;
	*eff = value;
	pr_info("AIKernel: proc.rlimit pid=%d res=%u cur=%lld set\n",
		pid, res, value);
	return AI_OK;
}

static int __init ai_proc_init(void)
{
#ifdef CONFIG_AIKERNEL_TELEMETRY
	/* 幂等：已有调用者则无操作 */
	ai_telemetry_init();
	/* 热路径默认采样率：syscall 全量参数 1/256（防 ring 饱和） */
	ai_telemetry_set_sample_rate(AI_CAT_USER_INPUT, AI_EV_SYSCALL, 256);
#endif

#ifdef CONFIG_AIKERNEL_RUNTIME
	ai_proc_sampler_task = kthread_run(ai_proc_sampler, NULL,
					   "ai_proc_sense");
	if (IS_ERR(ai_proc_sampler_task)) {
		ai_proc_sampler_task = NULL;
		pr_warn("AIKernel: proc sense sampler start failed\n");
	}

	/* 可控制参数表（数据计划 20.3 进程域）：signal/freeze/rlimit 全部
	 * 立即生效（真实信号投递 / SIGSTOP-SIGCONT 冻结 / prlimit 语义软限） */
	ai_control_register_ex("proc.signal", AI_POLICY_DOMAIN_PROC,
			       AI_CTRL_F_REAL | AI_CTRL_F_TASK | AI_CTRL_F_EVENT,
			       0, 64, 0, ai_proc_signal_apply, NULL);
	ai_control_register_ex("proc.freeze", AI_POLICY_DOMAIN_PROC,
			       AI_CTRL_F_REAL | AI_CTRL_F_TASK,
			       0, 1, 0, ai_proc_freeze_apply, NULL);
	ai_control_register_ex("proc.rlimit", AI_POLICY_DOMAIN_PROC,
			       AI_CTRL_F_REAL | AI_CTRL_F_TASK,
			       0, 1000000, 0, NULL, ai_proc_rlimit_apply_ex);
#endif
	pr_info("AIKernel: proc/user-sense ready\n");
	return 0;
}
late_initcall(ai_proc_init);

#endif /* CONFIG_AIKERNEL_TELEMETRY */
