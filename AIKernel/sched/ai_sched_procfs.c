// SPDX-License-Identifier: GPL-2.0
/*
 * ai_sched_procfs.c - AIKernel /proc/ai/sched/ 调度决策统计（Prompt 03）
 *
 * 接口：
 *   stats      R   全部 AI 调度 Hook 决策计数 + 进程分类分布
 *   classify   W/R 写 pid → 读该任务分类（AI_LOAD/INTERACTIVE/BATCH）
 *
 * 门控 CONFIG_AIKERNEL_SCHED。节点挂载到 /proc/ai/ 根（ai_procfs.c 导出），
 * ai.enabled=0 启动时与既有接口一致不创建（零回归）。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/kstrtox.h>
#include "../core/ai_types.h"
#include "ai_sched.h"

#ifdef CONFIG_AIKERNEL_RUNTIME
#include "../core/ai_startup.h"
#endif

/* ai_procfs.c（CONFIG_AIKERNEL_USRIFACE）导出的 /proc/ai 根节点 */
#ifdef CONFIG_AIKERNEL_USRIFACE
extern struct proc_dir_entry *ai_procfs_get_root(void);
#endif

static const char *ai_sched_class_name(int cls)
{
	switch (cls) {
	case AI_SCHED_CLASS_AI_LOAD:	return "ai_load";
	case AI_SCHED_CLASS_INTERACTIVE:return "interactive";
	default:			return "batch";
	}
}

static int ai_sched_stats_show(struct seq_file *m, void *v)
{
	struct ai_sched_stats st;
	int cls;

	ai_sched_stats_read(&st);

	seq_printf(m, "pick_next_calls=%llu\n", st.pick_next_calls);
	seq_printf(m, "pick_next_ai_changed=%llu\n", st.pick_next_ai_changed);
	seq_printf(m, "cfs_pick_calls=%llu\n", st.cfs_pick_calls);
	seq_printf(m, "cfs_pick_ai_changed=%llu\n", st.cfs_pick_ai_changed);
	seq_printf(m, "load_balance_calls=%llu\n", st.lb_calls);
	seq_printf(m, "load_balance_ai_veto=%llu\n", st.lb_ai_veto);
	seq_printf(m, "pelt_adjust_calls=%llu\n", st.pelt_adjust_calls);
	seq_printf(m, "context_switch_calls=%llu\n", st.context_switch_calls);
	seq_printf(m, "rt_admission_calls=%llu\n", st.rt_admission_calls);
	seq_printf(m, "dl_admission_calls=%llu\n", st.dl_admission_calls);
	seq_printf(m, "admission_rejected=%llu\n", st.admission_rejected);
	seq_printf(m, "isolate_hook_calls=%llu\n", st.isolate_hook_calls);
	seq_printf(m, "query_calls=%llu\n", st.query_calls);
	seq_printf(m, "classify:\n");
	for (cls = 0; cls < AI_SCHED_CLASS_MAX; cls++)
		seq_printf(m, "  %s=%llu\n", ai_sched_class_name(cls),
			   st.classify[cls]);
	return 0;
}

static int ai_sched_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, ai_sched_stats_show, NULL);
}

static const struct proc_ops ai_sched_stats_ops = {
	.proc_open    = ai_sched_stats_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ---- classify：写 pid，读分类（单值接口，读写各持一侧） ---- */

static int ai_sched_classify_pid_val;   /* echo <pid> > classify 写入的目标 */

static int ai_sched_classify_pid(int pid)
{
	struct task_struct *p;
	int cls = AI_SCHED_CLASS_BATCH;

	rcu_read_lock();
	p = find_task_by_vpid(pid);
	if (p)
		cls = ai_sched_classify_task(p);
	rcu_read_unlock();
	return cls;
}

static ssize_t ai_sched_classify_write(struct file *file,
				       const char __user *ubuf,
				       size_t count, loff_t *ppos)
{
	char buf[16];
	unsigned long pid;
	size_t n = min(count, sizeof(buf) - 1);
	int err;

	if (copy_from_user(buf, ubuf, n))
		return -EFAULT;
	buf[n] = '\0';

	err = kstrtoul(buf, 10, &pid);
	if (err || pid > INT_MAX)
		return -EINVAL;

	WRITE_ONCE(ai_sched_classify_pid_val, (int)pid);
	return count;
}

static int ai_sched_classify_show(struct seq_file *m, void *v)
{
	int pid = READ_ONCE(ai_sched_classify_pid_val);

	if (!pid) {
		seq_printf(m, "usage: echo <pid> > classify\n");
		return 0;
	}
	seq_printf(m, "pid=%d class=%s\n", pid,
		   ai_sched_class_name(ai_sched_classify_pid(pid)));
	return 0;
}

static int ai_sched_classify_open(struct inode *inode, struct file *file)
{
	return single_open(file, ai_sched_classify_show, NULL);
}

static const struct proc_ops ai_sched_classify_ops = {
	.proc_open    = ai_sched_classify_open,
	.proc_read    = seq_read,
	.proc_write   = ai_sched_classify_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ---- 初始化 ---- */

static struct proc_dir_entry *ai_proc_sched_dir;

static int __init ai_sched_procfs_init(void)
{
	struct proc_dir_entry *root = NULL;

#ifdef CONFIG_AIKERNEL_RUNTIME
	if (!ai_startup_get_enabled())
		return 0;   /* ai.enabled=0 启动：节点不创建（零回归） */
#endif

#ifdef CONFIG_AIKERNEL_USRIFACE
	root = ai_procfs_get_root();
#endif
	if (!root)
		root = proc_mkdir("ai", NULL);   /* USRIFACE 未开时自建 /proc/ai */
	if (!root)
		return -ENOMEM;

	ai_proc_sched_dir = proc_mkdir("sched", root);
	if (!ai_proc_sched_dir)
		return -ENOMEM;

	proc_create("stats", 0444, ai_proc_sched_dir, &ai_sched_stats_ops);
	proc_create("classify", 0644, ai_proc_sched_dir,
		    &ai_sched_classify_ops);

	pr_info("AIKernel: /proc/ai/sched/ ready\n");
	return 0;
}
subsys_initcall(ai_sched_procfs_init);

static void __exit ai_sched_procfs_exit(void)
{
	proc_remove(ai_proc_sched_dir);
	ai_proc_sched_dir = NULL;
}
module_exit(ai_sched_procfs_exit);
