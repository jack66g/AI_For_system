// SPDX-License-Identifier: GPL-2.0
/*
 * ai_core.c - AI Kernel 核心模块
 *
 * AI Agent 子系统的内核侧初始化入口。
 * 包含 /proc/aikernel 注册。
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

/* ---- /proc/aikernel ---- */

static int aikernel_proc_show(struct seq_file *m, void *v)
{
	/* T2 审计问题 7：此前硬编码 "Cloud Provider: Ready"/"Local Provider:
	 * Offline"——provider 是用户态 agent（aikernel-shell）管理的配置，
	 * 内核侧无从知晓其真实状态，硬编码会在未配置时假报 Ready 穿帮。
	 * 改为只输出内核可验证的事实，provider 状态指引用户态查询。 */
	seq_printf(m, "AI Agent Enabled\n");
	seq_printf(m, "\n");
	seq_printf(m, "Version: 0.1\n");
	seq_printf(m, "Kernel AI Interface: Ready\n");
	seq_printf(m, "Agent Providers: managed by aikernel-shell"
		      " (run 'status' in shell)\n");
	return 0;
}

static int aikernel_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, aikernel_proc_show, NULL);
}

static const struct proc_ops aikernel_proc_ops = {
	.proc_open    = aikernel_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *aikernel_proc_entry;

/* ---- 模块初始化 ---- */

static int __init aikernel_core_init(void)
{
	pr_info("AIKernel: AI Agent Core initializing...\n");

	aikernel_proc_entry = proc_create("aikernel", 0, NULL,
					  &aikernel_proc_ops);
	if (!aikernel_proc_entry) {
		pr_err("AIKernel: Failed to create /proc/aikernel\n");
		return -ENOMEM;
	}

	pr_info("AIKernel: /proc/aikernel registered\n");
	pr_info("AIKernel: AI Agent Core initialized successfully\n");
	return 0;
}

static void __exit aikernel_core_exit(void)
{
	if (aikernel_proc_entry) {
		proc_remove(aikernel_proc_entry);
		pr_info("AIKernel: /proc/aikernel removed\n");
	}
	pr_info("AIKernel: AI Agent Core shutdown\n");
}

module_init(aikernel_core_init);
module_exit(aikernel_core_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AIKernel Agent Core");
MODULE_AUTHOR("AIKernel Project");
