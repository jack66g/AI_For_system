// SPDX-License-Identifier: GPL-2.0
/*
 * ai_cgroup.c - AIKernel ai.cgroup 控制器（Prompt 02 骨架 + Prompt 12 填充）
 *
 * 目标：AI 推理资源限制（TOPS、并发推理数、推理预算）。
 * Prompt 02 骨架：css 分配/上线/释放 + ai.inferences（RO）+ ai.max_inferences（RW）。
 * Prompt 12 填充：
 *   - ai.max_inferences 强制生效：ai_cgroup_inference_enter() 超限 →
 *     AI_ERR_BUSY（拒绝新推理）+ cgroup_limit_hit 遥测；
 *   - ai.max_tops（RW，默认 0=不限）：TOPS 上限接口字段（度量接入后强制）；
 *   - ai.mem_limit_mb（RW，默认 0=不限）：AI 推理显存上限接口字段；
 *   - inference_exit() 计数回减；
 *   - ai_cgroup_query()：查询限制/用量（供 AI Runtime/用户态）。
 *
 * 子系统注册：include/linux/cgroup_subsys.h 在 CONFIG_AIKERNEL_CGROUP 下
 * SUBSYS(ai)；内核 v2 默认层级（dfl）启用。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/seq_file.h>
#include "ai_types.h"
#include "ai_cgroup.h"
#ifdef CONFIG_AIKERNEL_TELEMETRY
#include "ai_proc.h"
#endif

struct ai_cgroup {
	struct cgroup_subsys_state css;
	u64 max_inferences;          /* 推理上限（0=禁止，U64_MAX=不限制） */
	u64 max_tops;                /* TOPS 上限（0=不限，接口字段） */
	u64 mem_limit_mb;            /* AI 显存上限 MB（0=不限，接口字段） */
	atomic64_t inferences;       /* 已发起推理计数 */
};

static inline struct ai_cgroup *ai_cg(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct ai_cgroup, css) : NULL;
}

/* ---- css 生命周期 ---- */

static struct cgroup_subsys_state *
ai_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct ai_cgroup *aic;

	aic = kzalloc(sizeof(*aic), GFP_KERNEL);
	if (!aic)
		return ERR_PTR(-ENOMEM);

	aic->max_inferences = U64_MAX;   /* 默认不限制 */
	aic->max_tops = 0;               /* 默认不限 */
	aic->mem_limit_mb = 0;           /* 默认不限 */
	atomic64_set(&aic->inferences, 0);
	return &aic->css;
}

static void ai_css_free(struct cgroup_subsys_state *css)
{
	kfree(ai_cg(css));
}

/* ---- cftypes ---- */

static int ai_inferences_show(struct seq_file *m, void *v)
{
	struct ai_cgroup *aic = ai_cg(seq_css(m));

	seq_printf(m, "%llu\n", (u64)atomic64_read(&aic->inferences));
	return 0;
}

static int ai_max_inferences_show(struct seq_file *m, void *v)
{
	struct ai_cgroup *aic = ai_cg(seq_css(m));

	seq_printf(m, "%llu\n", aic->max_inferences);
	return 0;
}

static ssize_t ai_max_inferences_write(struct kernfs_open_file *of,
				       char *buf, size_t nbytes,
				       loff_t off)
{
	struct ai_cgroup *aic = ai_cg(of_css(of));
	u64 val;
	int rc;

	rc = kstrtou64(strstrip(buf), 0, &val);
	if (rc)
		return rc;

	aic->max_inferences = val;
	return nbytes;
}

static int ai_max_tops_show(struct seq_file *m, void *v)
{
	struct ai_cgroup *aic = ai_cg(seq_css(m));

	seq_printf(m, "%llu\n", aic->max_tops);
	return 0;
}

static ssize_t ai_max_tops_write(struct kernfs_open_file *of,
				 char *buf, size_t nbytes, loff_t off)
{
	struct ai_cgroup *aic = ai_cg(of_css(of));
	u64 val;
	int rc;

	rc = kstrtou64(strstrip(buf), 0, &val);
	if (rc)
		return rc;

	aic->max_tops = val;
	return nbytes;
}

static int ai_mem_limit_mb_show(struct seq_file *m, void *v)
{
	struct ai_cgroup *aic = ai_cg(seq_css(m));

	seq_printf(m, "%llu\n", aic->mem_limit_mb);
	return 0;
}

static ssize_t ai_mem_limit_mb_write(struct kernfs_open_file *of,
				     char *buf, size_t nbytes, loff_t off)
{
	struct ai_cgroup *aic = ai_cg(of_css(of));
	u64 val;
	int rc;

	rc = kstrtou64(strstrip(buf), 0, &val);
	if (rc)
		return rc;

	aic->mem_limit_mb = val;
	return nbytes;
}

static struct cftype ai_cftypes[] = {
	{
		.name = "inferences",
		.seq_show = ai_inferences_show,
	},
	{
		.name = "max_inferences",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = ai_max_inferences_show,
		.write = ai_max_inferences_write,
	},
	{
		.name = "max_tops",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = ai_max_tops_show,
		.write = ai_max_tops_write,
	},
	{
		.name = "mem_limit_mb",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = ai_mem_limit_mb_show,
		.write = ai_mem_limit_mb_write,
	},
	{ }
};

/* ---- 接口：推理进入/退出（Prompt 12：max_inferences 强制生效） ---- */

int ai_cgroup_inference_enter(struct cgroup_subsys_state *css)
{
	struct ai_cgroup *aic = ai_cg(css);
	u64 limit, usage;

	if (!aic)
		return AI_OK;

	usage = (u64)atomic64_read(&aic->inferences);
	limit = READ_ONCE(aic->max_inferences);
	if (limit != U64_MAX && usage >= limit) {
		/* 超限：拒绝新推理 + cgroup_limit_hit 遥测（全量路径/限制/用量） */
#ifdef CONFIG_AIKERNEL_TELEMETRY
		{
			struct cgroup *cg = css->cgroup;
			char path[256];

			if (cgroup_path(cg, path, sizeof(path)))
				strscpy(path, "?", sizeof(path));
			ai_telemetry_cgroup_limit_hit(path, "inferences",
						      limit, usage);
		}
#endif
		return AI_ERR_BUSY;
	}

	atomic64_inc(&aic->inferences);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_cgroup_inference_enter);

int ai_cgroup_inference_exit(struct cgroup_subsys_state *css)
{
	struct ai_cgroup *aic = ai_cg(css);

	if (aic && atomic64_read(&aic->inferences) > 0)
		atomic64_dec(&aic->inferences);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_cgroup_inference_exit);

int ai_cgroup_query(struct cgroup_subsys_state *css,
		    struct ai_cgroup_info *info)
{
	struct ai_cgroup *aic = ai_cg(css);

	if (!aic || !info)
		return AI_ERR_INVALID_ARG;
	info->inferences = (u64)atomic64_read(&aic->inferences);
	info->max_inferences = READ_ONCE(aic->max_inferences);
	info->max_tops = READ_ONCE(aic->max_tops);
	info->mem_limit_mb = READ_ONCE(aic->mem_limit_mb);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_cgroup_query);

/* ---- 子系统注册 ---- */

struct cgroup_subsys ai_cgrp_subsys = {
	.css_alloc = ai_css_alloc,
	.css_free  = ai_css_free,
	.dfl_cftypes = ai_cftypes,
	.legacy_cftypes = ai_cftypes,
};
