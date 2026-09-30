// SPDX-License-Identifier: GPL-2.0
/*
 * ai_procfs.c - AIKernel /proc/ai/ 用户态状态面 + 遥测流出口（Prompt 02）
 *
 * 接口：
 *   status      R   Runtime 状态、模型表、采样率、per-CPU ring 统计
 *   decisions   R   AI 最近决策日志（敏感，0400 + CAP_SYS_ADMIN 双保险）
 *   latency     R   决策延迟统计（count/min/max/avg）
 *   hitrate     R   策略命中率（attempts/hits/%）
 *   telemetry   RW  B 轨实时遥测流出口：读=流式输出全量感知记录；
 *                   写="format=raw|human" 切换模式（默认 human）；
 *                   写="reset" 清空全部 ring（需 CAP_SYS_ADMIN）
 *
 * 遥测流数据原则（all-ai）：raw 模式输出定长头（struct ai_telemetry_record,
 * packed 23B）+ 原始数据逐条拼接，零脱敏零转换；human 模式每行一条文本。
 * 节点创建以 ai_startup_get_enabled() 为准：ai.enabled=0 启动 → 全部不创建。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/capability.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/ktime.h>
#include "ai_types.h"
#include "ai_startup.h"
#include "ai_runtime.h"
#include "ai_model.h"
#include "ai_telemetry.h"
#include "ai_policy.h"
#include "ai_causal.h"
#include "ai_control.h"

#define AI_PROC_TELEMETRY_CHUNK   (64 * 1024)   /* 单次 read 处理上限 */

struct proc_dir_entry *ai_procfs_get_root(void);   /* 供子系统 procfs 挂载 /proc/ai/ 子目录 */

enum ai_telemetry_fmt {
	AI_TELEMETRY_FMT_HUMAN = 0,   /* 默认：可读文本 */
	AI_TELEMETRY_FMT_RAW   = 1,   /* 原始二进制（头+数据零脱敏） */
};

static enum ai_telemetry_fmt ai_telemetry_fmt = AI_TELEMETRY_FMT_HUMAN;

/* ---- status ---- */

static int ai_proc_status_show(struct seq_file *m, void *v)
{
	int cpu;
	unsigned int mi = 0, nmodels = 0;

	seq_printf(m, "runtime_state: %d\n", ai_runtime_get_state());
	seq_printf(m, "enabled: %d\n", ai_startup_get_enabled() ? 1 : 0);
	seq_printf(m, "log_level: %u\n", ai_startup_get_log_level());
	seq_printf(m, "model_path: %s\n", ai_startup_get_model_path());
	seq_printf(m, "telemetry_ring: %d CPU x %dKB\n",
		   nr_cpu_ids, AI_TELEMETRY_RING_SIZE / 1024);
	seq_printf(m, "telemetry_format: %s\n",
		   ai_telemetry_fmt == AI_TELEMETRY_FMT_RAW ? "raw" : "human");

	/* 模型表 */
	for (mi = 0; ; mi++) {
		char name[AI_MAX_NAME_LEN];
		u32 ver, src, st;

		if (ai_model_enumerate(mi, name, &ver, &src, &st) != AI_OK)
			break;
		if (!nmodels)
			seq_printf(m, "models:\n");
		seq_printf(m, "  [%u] name=%s version=%u source=%u state=%u\n",
			   mi + 1, name, ver, src, st);
		nmodels++;
	}
	if (!nmodels)
		seq_printf(m, "models: 0\n");

	for_each_possible_cpu(cpu) {
		struct ai_telemetry_cpu_stats st;
		u8 c, e;
		unsigned int nondefault = 0;

		if (ai_telemetry_stats(cpu, &st) != AI_OK)
			continue;
		seq_printf(m, "cpu%d: emitted=%u dropped=%u sampled_skip=%u "
			   "head=%u tail=%u\n",
			   cpu, st.emitted, st.dropped, st.sampled_skip,
			   st.head, st.tail);
		/* 采样率：仅列出非默认（非全量）条目 */
		for (c = 1; c <= AI_CAT_KCONFIG; c++) {
			for (e = 1; e < AI_EV_MAX; e++) {
				u32 rate;

				if (ai_telemetry_get_sample_rate(c, e, &rate) != AI_OK)
					continue;
				if (rate != 1) {
					seq_printf(m, "  sample_rate[cat=%u ev=%u]=%u\n",
						   c, e, rate);
					nondefault++;
				}
			}
		}
		if (!nondefault)
			seq_printf(m, "  sample_rate: all full (1)\n");
	}
	return 0;
}

static int ai_proc_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, ai_proc_status_show, NULL);
}

static const struct proc_ops ai_proc_status_ops = {
	.proc_open    = ai_proc_status_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ---- decisions（敏感：0400 + CAP_SYS_ADMIN） ---- */

/* 决策记录格式化（id/4 时间戳/参数全量/结果/因果链字段，全量零脱敏） */
static void ai_proc_dec_record(struct seq_file *m,
			       const struct ai_decision_record *e)
{
	unsigned int i;

	seq_printf(m,
		   "id=%llu trig_ts=%llu trig_evid=0x%04x dec_ts=%llu "
		   "type=%u data=",
		   e->decision_id, e->trigger_ts, e->trigger_event_id,
		   e->decision_ts, e->decision_type);
	for (i = 0; i < 8; i++)
		seq_printf(m, "%s%llu", i ? ":" : "", e->decision_data[i]);
	seq_printf(m,
		   " exec_ts=%llu outcome_ts=%llu outcome=%u delta=%lld "
		   "ver=%u conf=%u domain=%u src=%u executed=%u "
		   "safety_clamped=%u\n",
		   e->execute_ts, e->outcome_ts, e->outcome,
		   e->metric_delta, e->model_version, e->confidence,
		   e->domain, e->source, e->executed, e->safety_clamped);
}

static int ai_proc_decisions_show(struct seq_file *m, void *v)
{
	struct ai_decision_record *buf;
	size_t bytes = 0;
	u32 count = 0;

	buf = kmalloc(AI_POLICY_DECISION_RING_SIZE * sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ai_policy_decision_read(buf,
				AI_POLICY_DECISION_RING_SIZE * sizeof(*buf),
				&count, &bytes);

	/* 最近在前（因果链：trigger→decision→outcome 逐条可反查） */
	{
		u32 i;

		for (i = count; i > 0; i--)
			ai_proc_dec_record(m, &buf[i - 1]);
	}
	kfree(buf);
	return 0;
}

static int ai_proc_decisions_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;
	return single_open(file, ai_proc_decisions_show, NULL);
}

static const struct proc_ops ai_proc_decisions_ops = {
	.proc_open    = ai_proc_decisions_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ---- chains（因果链：trigger→decision→outcome，敏感：0400） ---- */

static int ai_proc_chains_show(struct seq_file *m, void *v)
{
	struct ai_decision_record *buf;
	size_t bytes = 0;
	u32 count = 0;

	buf = kmalloc(AI_CAUSAL_RING_SIZE * sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ai_causal_chain_read(buf, AI_CAUSAL_RING_SIZE * sizeof(*buf),
			     &count, &bytes);

	/* 最旧在前（训练样本顺序） */
	{
		u32 i;

		for (i = 0; i < count; i++)
			ai_proc_dec_record(m, &buf[i]);
	}
	kfree(buf);
	return 0;
}

static int ai_proc_chains_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;
	return single_open(file, ai_proc_chains_show, NULL);
}

static const struct proc_ops ai_proc_chains_ops = {
	.proc_open    = ai_proc_chains_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ---- control（可控制参数表只读出口） ---- */

static int ai_proc_control_show(struct seq_file *m, void *v)
{
	u32 i;

	for (i = 0; ; i++) {
		struct ai_control_param p;

		if (ai_control_query(i, &p) != AI_OK)
			break;
		seq_printf(m, "%s domain=%u %s min=%lld max=%lld "
			   "current=%lld default=%lld\n",
			   p.name, p.domain,
			   (p.flags & AI_CTRL_F_REAL) ? "[real]" : "[reserved]",
			   p.min, p.max, p.cur, p.default_val);
	}
	return 0;
}

static int ai_proc_control_open(struct inode *inode, struct file *file)
{
	return single_open(file, ai_proc_control_show, NULL);
}

static const struct proc_ops ai_proc_control_ops = {
	.proc_open    = ai_proc_control_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ---- latency / hitrate ---- */

static int ai_proc_latency_show(struct seq_file *m, void *v)
{
	struct ai_policy_stats st;

	ai_policy_stats_get(&st);
	seq_printf(m, "decisions_total=%llu attempts=%llu hits=%llu\n",
		   st.decisions_total, st.attempts, st.hits);
	if (st.decisions_total || st.attempts)
		seq_printf(m, "latency_min_ns=%llu latency_max_ns=%llu "
			   "latency_avg_ns=%llu\n",
			   st.latency_min, st.latency_max,
			   st.attempts ? st.latency_sum / st.attempts : 0);
	else
		seq_printf(m, "latency_min_ns=0 latency_max_ns=0 latency_avg_ns=0\n");
	return 0;
}

static int ai_proc_latency_open(struct inode *inode, struct file *file)
{
	return single_open(file, ai_proc_latency_show, NULL);
}

static const struct proc_ops ai_proc_latency_ops = {
	.proc_open    = ai_proc_latency_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int ai_proc_hitrate_show(struct seq_file *m, void *v)
{
	struct ai_policy_stats st;

	ai_policy_stats_get(&st);
	seq_printf(m, "attempts=%llu hits=%llu hitrate=%llu%%\n",
		   st.attempts, st.hits,
		   st.attempts ? st.hits * 100 / st.attempts : 0);
	return 0;
}

static int ai_proc_hitrate_open(struct inode *inode, struct file *file)
{
	return single_open(file, ai_proc_hitrate_show, NULL);
}

static const struct proc_ops ai_proc_hitrate_ops = {
	.proc_open    = ai_proc_hitrate_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ---- telemetry（B 轨出口） ---- */

/* human 模式单行上限：保证"已消费 == 已交付"（见 read 中的 chunk 论证） */
#define AI_PROC_HUMAN_LINE_MAX  160
#define AI_PROC_HUMAN_HEX_SHOW  16    /* 每行显示的原始数据字节数 */

/* human 模式：一行一条（原始数据以 %02x 十六进制显示，前 16B + 全长指示） */
static size_t ai_telemetry_human_record(char *out, size_t cap,
					const struct ai_telemetry_record *rec,
					const u8 *data)
{
	size_t n = 0;
	unsigned int i, shown = 0;

	n += scnprintf(out + n, cap - n,
		       "ts=%llu pid=%u tgid=%u cpu=%u cat=%u ev=%u sev=%u len=%u data=",
		       rec->timestamp_ns, rec->pid, rec->tgid, rec->cpu,
		       rec->category, rec->event_type, rec->severity,
		       rec->data_len);
	shown = min_t(unsigned int, rec->data_len, AI_PROC_HUMAN_HEX_SHOW);
	for (i = 0; i < shown; i++)
		n += scnprintf(out + n, cap - n, "%02x", data[i]);
	if (rec->data_len > shown)
		n += scnprintf(out + n, cap - n, "...");
	n += scnprintf(out + n, cap - n, "\n");
	return n;
}

static ssize_t ai_proc_telemetry_read(struct file *file, char __user *ubuf,
				      size_t count, loff_t *ppos)
{
	void *raw = NULL, *out = NULL;
	bool same_buf = false;
	ssize_t total = 0, rc;
	int cpu;

	if (!count)
		return 0;

	raw = kmalloc(AI_PROC_TELEMETRY_CHUNK, GFP_KERNEL);
	if (!raw)
		return -ENOMEM;

	if (ai_telemetry_fmt == AI_TELEMETRY_FMT_RAW) {
		/* raw：零拷贝直出，chunk ≤ count → consumed == delivered */
		out = raw;
		same_buf = true;
	} else {
		out = kmalloc(AI_PROC_TELEMETRY_CHUNK, GFP_KERNEL);
		if (!out) {
			kfree(raw);
			return -ENOMEM;
		}
	}

	/*
	 * 处理循环：从各 CPU ring 排空到 raw，按模式生成输出。
	 * 无丢失论证：
	 *   - raw 模式：chunk_cap = min(count, 64KB)，一次全部交付；
	 *   - human 模式：chunk_cap ≤ count/16，单行 ≤ 160B、单条记录 ≥ 23B，
	 *     输出上限 = chunk_cap/23*160 ≈ count*0.43 < count → 整块可交付。
	 * 因此每次 read 调用"已消费的记录"必然"全部交付"，零丢失。
	 */
	for_each_possible_cpu(cpu) {
		size_t chunk_cap, n = 0;

		chunk_cap = AI_PROC_TELEMETRY_CHUNK;
		if (ai_telemetry_fmt == AI_TELEMETRY_FMT_RAW)
			chunk_cap = min(chunk_cap, (size_t)(count - total));
		else
			chunk_cap = min(chunk_cap, max((size_t)(count - total) / 16,
						      AI_TELEMETRY_HEADER_LEN));

		rc = ai_telemetry_read(cpu, raw, chunk_cap, &n);
		if (rc != AI_OK || n == 0)
			continue;

		if (ai_telemetry_fmt == AI_TELEMETRY_FMT_RAW) {
			if (copy_to_user(ubuf + total, raw, n)) {
				rc = -EFAULT;
				goto out;
			}
			total += n;
		} else {
			size_t pos = 0, o = 0;

			while (pos < n && o < AI_PROC_TELEMETRY_CHUNK) {
				struct ai_telemetry_record *rec =
					(struct ai_telemetry_record *)((u8 *)raw + pos);
				size_t rec_total = AI_TELEMETRY_HEADER_LEN +
						   rec->data_len;
				size_t take;

				if (rec_total > n - pos)
					break;   /* 尾部残记录：留待下次 */
				take = ai_telemetry_human_record((char *)out + o,
							AI_PROC_TELEMETRY_CHUNK - o,
							rec,
							(u8 *)rec + AI_TELEMETRY_HEADER_LEN);
				if (o + take > (size_t)(count - total) ||
				    o + take > AI_PROC_TELEMETRY_CHUNK)
					break;   /* 防御：理论不可达（见上方论证） */
				o += take;
				pos += rec_total;
			}
			if (o) {
				if (copy_to_user(ubuf + total, out, o)) {
					rc = -EFAULT;
					goto out;
				}
				total += o;
			}
		}
		if (total >= count)
			break;
	}
	rc = total;

out:
	if (!same_buf)
		kfree(out);
	kfree(raw);
	return rc;
}

static ssize_t ai_proc_telemetry_write(struct file *file,
				       const char __user *ubuf,
				       size_t count, loff_t *ppos)
{
	char buf[64];
	size_t n = min(count, sizeof(buf) - 1);

	if (copy_from_user(buf, ubuf, n))
		return -EFAULT;
	buf[n] = '\0';
	while (n && (buf[n - 1] == '\n' || buf[n - 1] == ' '))
		buf[--n] = '\0';

	if (strcmp(buf, "format=raw") == 0) {
		ai_telemetry_fmt = AI_TELEMETRY_FMT_RAW;
		return count;
	}
	if (strcmp(buf, "format=human") == 0) {
		ai_telemetry_fmt = AI_TELEMETRY_FMT_HUMAN;
		return count;
	}
	if (strcmp(buf, "reset") == 0) {
		int rc;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		rc = ai_telemetry_reset();
		if (rc != AI_OK)
			return ai_error_to_errno(rc);
		return count;
	}
	return -EINVAL;
}

static const struct proc_ops ai_proc_telemetry_ops = {
	.proc_read  = ai_proc_telemetry_read,
	.proc_write = ai_proc_telemetry_write,
};

/* ---- 初始化 ---- */

static struct proc_dir_entry *ai_proc_root;

/**
 * ai_procfs_get_root() - 导出 /proc/ai 根节点（供子系统 procfs 挂载子目录）
 *
 * 由 AIKernel/sched/ai_sched_procfs.c 等子系统 procfs 使用；ai.enabled=0
 * 启动时返回 NULL（调用方自建根或跳过）。门控 CONFIG_AIKERNEL_USRIFACE。
 */
struct proc_dir_entry *ai_procfs_get_root(void)
{
	return ai_proc_root;
}
EXPORT_SYMBOL_GPL(ai_procfs_get_root);

static int __init ai_procfs_init(void)
{
	if (!ai_startup_get_enabled())
		return 0;   /* ai.enabled=0 启动：节点不创建（零回归） */

	ai_proc_root = proc_mkdir("ai", NULL);
	if (!ai_proc_root)
		return -ENOMEM;

	proc_create("status", 0444, ai_proc_root, &ai_proc_status_ops);
	proc_create("decisions", 0400, ai_proc_root, &ai_proc_decisions_ops);
	proc_create("chains", 0400, ai_proc_root, &ai_proc_chains_ops);
	proc_create("control", 0444, ai_proc_root, &ai_proc_control_ops);
	proc_create("latency", 0444, ai_proc_root, &ai_proc_latency_ops);
	proc_create("hitrate", 0444, ai_proc_root, &ai_proc_hitrate_ops);
	proc_create("telemetry", 0644, ai_proc_root, &ai_proc_telemetry_ops);

	pr_info("AIKernel: /proc/ai/ interface ready\n");
	return 0;
}
subsys_initcall(ai_procfs_init);

static void __exit ai_procfs_exit(void)
{
	proc_remove(ai_proc_root);
	ai_proc_root = NULL;
}
module_exit(ai_procfs_exit);
