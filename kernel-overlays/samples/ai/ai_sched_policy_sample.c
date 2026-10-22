// SPDX-License-Identifier: GPL-2.0
/*
 * ai_sched_policy_sample.c - AI 调度器策略示例（samples/ai/）
 *
 * 用途：演示"AI 如何给内核注册一个调度决策动作"的完整模板。
 * AI 自动化接入流程：
 *   1. 模块加载时用 ai_policy_register() 注册一个"域+动作名+回调"；
 *   2. AI Runtime（aikctl act / think / NETLINK_AI）下发决策时，内核
 *      决策引擎按域匹配并调用本回调；
 *   3. 回调失败时内核自动调用 rollback 回退（本示例演示回退语义）。
 *
 * 决策域：AI_POLICY_DOMAIN_SCHED（1，调度域）。
 * 动作名："sample.sched.timeslice"（注册表全表唯一）。
 *
 * 构建（在内核树根）：
 *   make CONFIG_SAMPLE_AI_SCHED_POLICY=m samples/ai/ai_sched_policy_sample.ko
 * 加载：
 *   insmod ai_sched_policy_sample.ko
 * 下发决策（aikctl 或 sysfs think）：
 *   aikctl act sched sample.sched.timeslice 12
 *   或：echo "0,1,0,12" > /sys/kernel/ai/policy/think
 * 验证：
 *   cat /proc/ai/decisions   （看到 domain=1 的决策记录）
 * 卸载：
 *   rmmod ai_sched_policy_sample
 *
 * 注意：本示例是"接入模板"，不修改真实调度器行为；回调只记录并返回
 * AI_OK，展示接口契约。真实策略请仿照 AIKernel/sched/ai_sched.c。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include "../AIKernel/core/ai_policy.h"
#include "../AIKernel/core/ai_types.h"

/* ---- 决策参数快照（演示回滚：保存决策前的值） ---- */

static unsigned int sample_cur_timeslice = 10;   /* 示例参数：时间片（ms） */

/* 回调私有数据：保存决策前值，供 rollback 恢复 */
struct sample_priv {
	unsigned int saved;
	int applied;
};

/*
 * callback：AI 决策命中 "sample.sched.timeslice" 时调用。
 * ctx->decision_data[0] = AI 下发的参数值（aikctl act 的 param）。
 * 返回值语义：AI_OK=生效；负错误码=失败（内核调 rollback 回退）。
 */
static int sample_sched_callback(const struct ai_policy_ctx *ctx, void *arg)
{
	struct sample_priv *sp = arg;
	long long v = ctx->decision_data[0];

	/* 示例校验：时间片范围 1~1000ms（模拟安全边界） */
	if (v < 1 || v > 1000) {
		pr_info("sample: sched.timeslice %lld out of range\n", v);
		return AI_ERR_INVALID_ARG;
	}

	/* 快照 → 应用（真实策略会改调度器参数；示例只记录） */
	sp->saved = sample_cur_timeslice;
	sample_cur_timeslice = (unsigned int)v;
	sp->applied = 1;

	pr_info("sample: sched.timeslice %u -> %lld (domain=%u type=%u "
		"conf=%u)\n", sp->saved, v, ctx->domain, ctx->decision_type,
		ctx->confidence);
	return AI_OK;
}

/*
 * rollback：callback 失败或决策被安全边界回滚时调用，恢复决策前状态。
 * 内核会按需调用（ai_policy_execute 失败路径 / rollback 命令）。
 */
static int sample_sched_rollback(const struct ai_policy_ctx *ctx, void *arg)
{
	struct sample_priv *sp = arg;

	if (sp->applied) {
		sample_cur_timeslice = sp->saved;
		pr_info("sample: sched.timeslice rolled back -> %u\n",
			sp->saved);
		sp->applied = 0;
	}
	return AI_OK;
}

static struct sample_priv sample_priv;

static int __init sample_sched_policy_init(void)
{
	int rc;

	rc = ai_policy_register(AI_POLICY_DOMAIN_SCHED,
				"sample.sched.timeslice",
				sample_sched_callback,
				sample_sched_rollback, &sample_priv);
	if (rc != AI_OK) {
		pr_err("sample: ai_policy_register failed (%d)\n", rc);
		return rc;
	}
	pr_info("sample: AI sched policy registered "
		"(action=sample.sched.timeslice, domain=1)\n");
	return 0;
}

static void __exit sample_sched_policy_exit(void)
{
	ai_policy_unregister("sample.sched.timeslice");
	pr_info("sample: AI sched policy unregistered\n");
}

module_init(sample_sched_policy_init);
module_exit(sample_sched_policy_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("AIKernel sample: AI scheduler policy registration");
