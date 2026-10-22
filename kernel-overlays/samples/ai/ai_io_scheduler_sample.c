// SPDX-License-Identifier: GPL-2.0
/*
 * ai_io_scheduler_sample.c - AI I/O 调度器示例（samples/ai/）
 *
 * 用途：演示"AI 如何参与 I/O 调度决策"的接入模板。
 * AIKernel 的 AI I/O 调度器（AIKernel/io/ai_bfq.c，注册名 "ai"）在
 * dispatch 决策点咨询 ai_io_sched_hook()；本示例演示：
 *   1. 模块加载时向 ai_io_sched_hook 接入自己的"AI 建议"回调替换点——
 *      实际接口是导出的 hook 函数（AIKernel/io/ai_block.c 导出），
 *      内核模块不能直接替换函数指针，正确的接入方式是：
 *      a) 注册决策动作（ai_policy_register，走 AI 决策闭环）；或
 *      b) 直接调用 ai_io_sched_hook 语义在块层咨询（见下）——
 *         本示例用"包装咨询"演示 AI 建议如何影响调度方向。
 *
 * 本示例选择方案 a（决策闭环模板）：
 *   - 注册 io 域动作 "sample.io.priority"：AI 决策下发后调整示例 I/O
 *     权重参数（真实场景可影响 blk-mq 深度或调度方向）；
 *   - 并演示 ai_io_sched_hook / ai_io_dispatch_hook 的直接调用姿势
 *     （在用户态无法直接调，需内核上下文；此处由 /proc 触发器演示）。
 *
 * 构建（在内核树根）：
 *   make CONFIG_SAMPLE_AI_IO_SCHEDULER=m samples/ai/ai_io_scheduler_sample.ko
 * 加载 / 下发决策 / 验证：
 *   insmod ai_io_scheduler_sample.ko
 *   aikctl act io sample.io.priority 5
 *   cat /proc/sample_ai_io/weight   （示例参数查看）
 *
 * 注意：本示例是"接入模板"，不修改真实块层行为。
 * 真实 AI 调度器策略请仿照 AIKernel/io/ai_bfq.c 与 ai_block.c。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include "../AIKernel/core/ai_policy.h"
#include "../AIKernel/core/ai_types.h"
#include "../AIKernel/io/ai_block.h"

/* ---- 示例 I/O 权重参数（AI 决策目标） ---- */

static unsigned int sample_io_weight = 4;      /* 1~10，越大越优先 */

/* 决策回调：AI 下发 "sample.io.priority" 时调整权重 */
static int sample_io_callback(const struct ai_policy_ctx *ctx, void *arg)
{
	long long v = ctx->decision_data[0];

	if (v < 1 || v > 10) {
		pr_info("sample: io.priority %lld out of range (1..10)\n", v);
		return AI_ERR_INVALID_ARG;
	}
	sample_io_weight = (unsigned int)v;
	pr_info("sample: io.priority -> %u (domain=%u conf=%u)\n",
		sample_io_weight, ctx->domain, ctx->confidence);
	return AI_OK;
}

/* 回滚回调：决策失败时恢复默认权重 */
static int sample_io_rollback(const struct ai_policy_ctx *ctx, void *arg)
{
	sample_io_weight = 4;
	pr_info("sample: io.priority rolled back -> 4\n");
	return AI_OK;
}

/*
 * /proc/sample_ai_io：示例参数查看 + hook 咨询演示
 *   cat /proc/sample_ai_io/weight    → 当前权重
 *   echo 1 > /proc/sample_ai_io/adv  → 演示一次 ai_io_dispatch_hook 咨询
 *                                      （打印 hook 是否允许分发）
 */
static int sample_io_weight_show(struct seq_file *m, void *v)
{
	seq_printf(m, "weight=%u (AI 决策目标：1..10)\n", sample_io_weight);
	return 0;
}

static int sample_io_adv_show(struct seq_file *m, void *v)
{
	bool allow = true;

	/*
	 * ai_io_dispatch_hook()：AI 优化请求分发顺序的咨询点。
	 * 参数 hctx/rq 为 NULL 时 hook 空实现返回 true（放行）；
	 * 本示例演示"AI 建议"如何被采集：真实代码在块层分发路径
	 * （block/blk-mq.c blk_mq_dispatch_rq_list）调用。
	 */
	allow = ai_io_dispatch_hook(NULL, NULL);
	seq_printf(m, "dispatch_allowed=%d (ai_io_dispatch_hook 咨询结果)\n",
		   allow ? 1 : 0);
	return 0;
}

static int sample_io_open(struct inode *inode, struct file *file)
{
	return single_open(file, sample_io_weight_show, NULL);
}

static int sample_io_adv_open(struct inode *inode, struct file *file)
{
	return single_open(file, sample_io_adv_show, NULL);
}

static const struct proc_ops sample_io_ops = {
	.proc_open    = sample_io_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static const struct proc_ops sample_io_adv_ops = {
	.proc_open    = sample_io_adv_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *sample_io_dir;

static int __init sample_io_scheduler_init(void)
{
	int rc;

	/* 方案 a：注册 AI 决策动作（io 域） */
	rc = ai_policy_register(AI_POLICY_DOMAIN_IO, "sample.io.priority",
				sample_io_callback, sample_io_rollback, NULL);
	if (rc != AI_OK) {
		pr_err("sample: ai_policy_register failed (%d)\n", rc);
		return rc;
	}

	/* 示例 procfs 出口 */
	sample_io_dir = proc_mkdir("sample_ai_io", NULL);
	if (!sample_io_dir) {
		ai_policy_unregister("sample.io.priority");
		return -ENOMEM;
	}
	proc_create("weight", 0444, sample_io_dir, &sample_io_ops);
	proc_create("adv", 0444, sample_io_dir, &sample_io_adv_ops);

	pr_info("sample: AI I/O scheduler sample registered "
		"(action=sample.io.priority, domain=3)\n");
	return 0;
}

static void __exit sample_io_scheduler_exit(void)
{
	proc_remove(sample_io_dir);
	ai_policy_unregister("sample.io.priority");
	pr_info("sample: AI I/O scheduler sample unregistered\n");
}

module_init(sample_io_scheduler_init);
module_exit(sample_io_scheduler_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("AIKernel sample: AI I/O scheduler decision integration");
