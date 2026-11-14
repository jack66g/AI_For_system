// SPDX-License-Identifier: GPL-2.0
/*
 * ai_procfs.c - AIKernel /proc/ai/ 用户态状态面 + 遥测流出口（Prompt 02）
 *
 * 接口：
 *   status      R   Runtime 状态、模型表、采样率、per-CPU ring 统计
 *   decisions   R   AI 最近决策日志（敏感，0400 + CAP_SYS_ADMIN 双保险）
 *   latency     R   决策延迟统计（count/min/max/avg）
 *   hitrate     R   策略命中率（attempts/hits/%）
 *   models      R   模型治理视图（K6 D3：每模型 name/version/state/slot/
 *                   hash 前 12hex/bytes/infer_n/last_lat_ns/timeout_n）
 *   telemetry   RW  B 轨实时遥测流出口：读=流式输出全量感知记录；
 *                   写="format=raw|human" 切换模式（默认 human）；
 *                   写="reset" 清空全部 ring（需 CAP_SYS_ADMIN）
 *
 * 遥测流数据原则（all-ai）：raw 模式输出定长头（struct ai_telemetry_record,
 * packed 44B，K7 D1）+ 原始数据逐条拼接，零脱敏零转换；human 模式每行一条
 * 文本（K7 D1：渲染统一走 ai_telemetry_format_human()，与 NETLINK SENSE
 * human 字节级同源）。
 * 节点创建以 ai_startup_get_enabled() 为准：ai.enabled=0 启动 → 全部不创建。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "../security/ai_chain.h"
#include <linux/xxhash.h>
#include <linux/ai_netlink.h>
#include <generated/utsrelease.h>
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
#include "ai_policy_safety.h"
#include "ai_agent.h"

#define AI_PROC_TELEMETRY_CHUNK   (64 * 1024)   /* 单次 read 处理上限 */

struct proc_dir_entry *ai_procfs_get_root(void);   /* 供子系统 procfs 挂载 /proc/ai/ 子目录 */

enum ai_telemetry_fmt {
	AI_TELEMETRY_FMT_HUMAN = 0,   /* 默认：可读文本 */
	AI_TELEMETRY_FMT_RAW   = 1,   /* 原始二进制（头+数据零脱敏） */
};

static enum ai_telemetry_fmt ai_telemetry_fmt = AI_TELEMETRY_FMT_HUMAN;

/* ---- status ---- */

/* K10.5：配置指纹——AIKERNEL 族符号 name=0/1 串接后 xxh64（运行时
 * 自证，与 .config 可独立对账；表驱动编译期取值，无构建系统改动） */
#define AI_CFG_ROW(sym) { #sym, IS_ENABLED(sym) ? 1 : 0 }

static const struct {
	const char *name;
	int on;
} ai_cfg_tab[] = {
	AI_CFG_ROW(CONFIG_AIKERNEL),
	AI_CFG_ROW(CONFIG_AIKERNEL_RUNTIME),
	AI_CFG_ROW(CONFIG_AIKERNEL_SCHED),
	AI_CFG_ROW(CONFIG_AIKERNEL_MM),
	AI_CFG_ROW(CONFIG_AIKERNEL_AI_ZONE),
	AI_CFG_ROW(CONFIG_AIKERNEL_IO),
	AI_CFG_ROW(CONFIG_AIKERNEL_NET),
	AI_CFG_ROW(CONFIG_AIKERNEL_SECURITY),
	AI_CFG_ROW(CONFIG_AIKERNEL_POWER),
	AI_CFG_ROW(CONFIG_AIKERNEL_VFS),
	AI_CFG_ROW(CONFIG_AIKERNEL_INTERRUPT),
	AI_CFG_ROW(CONFIG_AIKERNEL_LOCK),
	AI_CFG_ROW(CONFIG_AIKERNEL_TIME),
	AI_CFG_ROW(CONFIG_AIKERNEL_VIRT),
	AI_CFG_ROW(CONFIG_AIKERNEL_BPF),
	AI_CFG_ROW(CONFIG_AIKERNEL_TELEMETRY),
	AI_CFG_ROW(CONFIG_AIKERNEL_USRIFACE),
	AI_CFG_ROW(CONFIG_AIKERNEL_NETLINK),
	AI_CFG_ROW(CONFIG_AIKERNEL_CGROUP),
	AI_CFG_ROW(CONFIG_AIKERNEL_KUNIT_TEST),
	AI_CFG_ROW(CONFIG_AIKERNEL_EXPERIMENTAL),
	AI_CFG_ROW(CONFIG_AIKERNEL_AGENT),
	AI_CFG_ROW(CONFIG_AIKERNEL_CORE),
	AI_CFG_ROW(CONFIG_AIKERNEL_SHELL),
	AI_CFG_ROW(CONFIG_AIKERNEL_CLOUD_PROVIDER),
	AI_CFG_ROW(CONFIG_AIKERNEL_LOCAL_PROVIDER),
	AI_CFG_ROW(CONFIG_AIKERNEL_STREAM_MODE),
};

static u64 ai_config_hash(void)
{
	char buf[640];
	size_t off = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(ai_cfg_tab); i++)
		off += scnprintf(buf + off, sizeof(buf) - off, "%s=%d;",
				 ai_cfg_tab[i].name, ai_cfg_tab[i].on);
	return xxh64(buf, off, 0x4b313030ULL);   /* "K100" */
}

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
	/* w24 追加字段：后台排空线程状态（消费者常驻化，详见 ai_telemetry.c） */
	seq_printf(m, "telemetry_drain: period_ms=%d active=%d\n",
		   AI_TEL_DRAIN_PERIOD_MS,
		   ai_telemetry_drain_running() ? 1 : 0);

	/* 模型表 */
	for (mi = 0; ; mi++) {
		char name[AI_MAX_NAME_LEN];
		u32 ver, src, st;

		/* K6：enumerate 出参扩展（hash/bytes/infer_n/last_lat_ns/
		 * timeout_n/slot，施工 A 契约）；status 行格式不变，新字段
		 * 仅供 /proc/ai/models 使用，此处传 NULL 不取。 */
		if (ai_model_enumerate(mi, name, &ver, &src, &st,
				       NULL, NULL, NULL, NULL, NULL,
				       NULL) != AI_OK)
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
		u64 adapt_ago_ms = 0;   /* K7 D4：距上次升降档毫秒 */

		if (ai_telemetry_stats(cpu, &st) != AI_OK)
			continue;
		if (st.adapt_last_change_ns)
			adapt_ago_ms = div_u64(ktime_get_ns() -
					       st.adapt_last_change_ns,
					       1000000);
		/* w24/w58/w63 追加字段（语义见 ai_telemetry.h）：consumed=已消费
		 * 字节 adapt_shift=当前降档级（瞬时） adapt_skipped=自适应跳过
		 * 条数 resyncs=环错位次数 adapt_peak_shift=历史最高档
		 * adapt_episodes=进入降档次数 predrain_dropped=消费者就绪前环满
		 * 丢弃条数（含于 sampled_skip，不计入 dropped）。既有字段
		 * 顺序/语义不变，仅追加输出。
		 * K7（D2/D4）尾追：emitted64/dropped64/sampled_skip64=64 位
		 * 原子镜像（防回绕，读侧优先）；rate_skipped/drain_discards/
		 * sense_overread_dropped/resync_races=背压计数族；
		 * full_latch/full_episodes=环满告警闩与回合数；
		 * adapt: 段=升降档可解释（档位/上次变档积压/距上次变档毫秒）。 */
		seq_printf(m, "cpu%d: emitted=%u dropped=%u sampled_skip=%u "
			   "head=%u tail=%u consumed=%llu adapt_shift=%u "
			   "adapt_skipped=%llu resyncs=%u adapt_peak_shift=%u "
			   "adapt_episodes=%llu predrain_dropped=%llu "
			   "emitted64=%llu dropped64=%llu sampled_skip64=%llu "
			   "rate_skipped=%llu drain_discards=%llu "
			   "sense_overread_dropped=%llu resync_races=%llu "
			   "full_latch=%u full_episodes=%llu seq=%llu "
			   "adapt: shift=%u last_backlog=%zu "
			   "last_change_ago=%llums\n",
			   cpu, st.emitted, st.dropped, st.sampled_skip,
			   st.head, st.tail, st.consumed, st.adapt_shift,
			   st.adapt_skipped, st.resyncs, st.adapt_peak_shift,
			   st.adapt_episodes, st.predrain_dropped,
			   st.emitted64, st.dropped64, st.sampled_skip64,
			   st.rate_skipped, st.drain_discards,
			   st.sense_overread_dropped, st.resync_races,
			   st.full_latch, st.full_episodes, st.seq,
			   st.adapt_shift, (size_t)st.adapt_last_backlog,
			   adapt_ago_ms);
		/* 采样率：仅列出非默认（非全量）条目。
		 * K7 修：外层上界 AI_CAT_KCONFIG(17) 漏掉第 18 类
		 * （AI_CAT_AI）的非默认采样率显示。 */
		for (c = 1; c <= AI_CAT_AI; c++) {
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

	/* K10.5：版本三件套（尾部只追加；abi 与 uapi AI_ABI_VERSION 同源） */
	seq_printf(m, "kernel_ver: %s\n", UTS_RELEASE);
	seq_printf(m, "abi_ver: %u\n", AI_ABI_VERSION);
	seq_printf(m, "config_hash: %016llx\n", ai_config_hash());
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
		   "safety_clamped=%u",
		   e->execute_ts, e->outcome_ts, e->outcome,
		   e->metric_delta, e->model_version, e->confidence,
		   e->domain, e->source, e->executed, e->safety_clamped);
	/* K66 T3：决策前值（append-only 行尾字段；快照被 rollback 消费
	 * 或环淘汰后为 none；精确语法见 K66-REPORT §5） */
	seq_puts(m, " pre=");
	{
		s64 pre_vals[AI_SAFETY_SNAPSHOT_PARAMS];
		u8 n = AI_SAFETY_SNAPSHOT_PARAMS;
		u8 k;

		if (ai_policy_safety_snapshot_lookup(e->decision_id,
						     pre_vals, &n) == AI_OK) {
			for (k = 0; k < n; k++)
				seq_printf(m, "%s%lld", k ? ":" : "",
					   pre_vals[k]);
		} else {
			seq_puts(m, "none");
		}
	}
	/* K1（KERNEL-K1-DESIGN D4）：行尾追加（K66 pre= 先例续）。
	 * trace/cost 恒渲染（trace 构造恒非零、cost 恒可算）；
	 * intent/parent/agent/expected/se 非零才渲染（=0 语义「未供给」，
	 * 无元数据行与老格式逐字节相同——16.2/16.3 老样本天然 golden）。
	 * /proc/ai/chains 复用本函数自动同步；渲染走 seq_file 自管缓冲
	 * （无定长栈 buf，无余量风险）。 */
	seq_printf(m, " trace=0x%016llx:0x%016llx cost=%llu",
		   e->trace_hi, e->trace_lo, e->cost_ns);
	if (e->intent_id)
		seq_printf(m, " intent=0x%016llx", e->intent_id);
	if (e->parent_id)
		seq_printf(m, " parent=0x%016llx", e->parent_id);
	if (e->agent_id)
		seq_printf(m, " agent=%u", e->agent_id);
	if (e->expected)
		seq_printf(m, " expected=%lld", e->expected);
	if (e->side_effect_mask)
		seq_printf(m, " se=0x%08x", e->side_effect_mask);
	seq_putc(m, '\n');
}

static int ai_proc_decisions_show(struct seq_file *m, void *v)
{
	struct ai_decision_record *buf;
	size_t bytes = 0;
	u32 count = 0;

	/* K2b 修复 K1B-20：557KB 高阶 kmalloc 碎片下可 ENOMEM，改
	 * kvmalloc（优先连续页，失败退 vmalloc） */
	buf = kvmalloc(AI_POLICY_DECISION_RING_SIZE * sizeof(*buf), GFP_KERNEL);
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
	kvfree(buf);
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

	buf = kvmalloc(AI_CAUSAL_RING_SIZE * sizeof(*buf), GFP_KERNEL);   /* K2b（K1B-20） */
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
	kvfree(buf);
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

/*
 * K7 D1：human 渲染统一——本文件不再持有手写格式串，改调
 * ai_telemetry_format_human()（与 NETLINK SENSE human 同一份实现，
 * 两路字节级 golden）。单行上限 AI_TELEMETRY_HUMAN_LINE_MAX=192
 * （K7 由 160B 扩容：新增 seq/trace/agent/privacy 四字段）。
 */

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
	 * 无丢失论证（K7 头 44B/行 192B 口径）：
	 *   - raw 模式：chunk_cap = min(count, 64KB)，一次全部交付；
	 *   - human 模式：chunk_cap ≤ count/16，单行 ≤ 192B、单条记录 ≥ 44B，
	 *     输出上限 = chunk_cap/44*192 ≈ count*0.27 < count → 整块可交付。
	 * 因此每次 read 调用"已消费的记录"必然"全部交付"，零丢失
	 * （防御分支见循环内 break——理论不可达；已知例外：count 小于
	 * 单行长度时的首条消费-截断为史前既有行为，K7 施工记录登记）。
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
					/* K7 D1：共享渲染器（与 SENSE human
					 * 同源；数据紧随记录头连续布局） */
					take = ai_telemetry_format_human(
							rec, (char *)out + o,
							AI_PROC_TELEMETRY_CHUNK - o);
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

	/* K2b 修复 K1B-18：格式切换全局生效（影响所有读者解析），与
	 * rate=/reset= 同权补 CAP_SYS_ADMIN 闸（出厂 root 无行为变化；
	 * 节点 0644 root 属主，非 root 本就被 VFS 拦在 open，此为对称性
	 * 与纵深防御） */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (strcmp(buf, "format=raw") == 0) {
		ai_telemetry_fmt = AI_TELEMETRY_FMT_RAW;
		return count;
	}
	if (strcmp(buf, "format=human") == 0) {
		ai_telemetry_fmt = AI_TELEMETRY_FMT_HUMAN;
		return count;
	}
	/* w21：采样率运行时可调 "rate=cat:ev:N"（N∈[0,65535]，0=关 1=全量
	 * N=每 N 条 1 条；cat/ev 边界与 N 钳制在 ai_telemetry_rate_cmd）。
	 * 前置 "rate=" 后剩余须非空（防 "rate=" 空参误入）。 */
	if (strncmp(buf, "rate=", 5) == 0) {
		int rc;

		if (n <= 5)
			return -EINVAL;
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		rc = ai_telemetry_rate_cmd(buf + 5);
		if (rc != AI_OK)
			return ai_error_to_errno(rc);
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

/* ---- agents（K3：agent 角色注册表/配额/记账面，KERNEL-K3-DESIGN D4） ---- */

/*
 * 每角色一行（win=<当前窗动作>/<actions_per_win 上限>；cgroup 可空省略；
 * degraded 行：配额栏 n/a(记账only) + 行尾 degraded=1(记账only)——
 * 「静默不限制」是点名反模式）。数据源=ai_agent 静态原子读单次快照
 * （允许极小撕裂，D4 v1 口径）；不触碰 decisions 等任何既有行字节。
 */
static int ai_proc_agents_show(struct seq_file *m, void *v)
{
	struct ai_agent_view a;
	unsigned int i;

	for (i = 0; ai_agent_view_get(i, &a) == 0; i++) {
		if (a.degraded) {
			seq_printf(m, "id=%u name=%s bound=%u actions=%llu "
				   "cost_ns=%llu failures=%llu "
				   "win=n/a(记账only)",
				   a.id, a.name, (unsigned int)a.bound,
				   a.actions, a.cost_ns, a.failures);
			if (a.cgroup[0])
				seq_printf(m, " cgroup=%s", a.cgroup);
			seq_puts(m, " degraded=1(记账only)\n");
		} else {
			seq_printf(m, "id=%u name=%s bound=%u actions=%llu "
				   "cost_ns=%llu failures=%llu "
				   "win=%llu/%u",
				   a.id, a.name, (unsigned int)a.bound,
				   a.actions, a.cost_ns, a.failures,
				   a.win_used, a.actions_per_win);
			if (a.cgroup[0])
				seq_printf(m, " cgroup=%s", a.cgroup);
			seq_putc(m, '\n');
		}
	}
	return 0;
}

static int ai_proc_agents_open(struct inode *inode, struct file *file)
{
	return single_open(file, ai_proc_agents_show, NULL);
}

static const struct proc_ops ai_proc_agents_ops = {
	.proc_open    = ai_proc_agents_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ---- models（K6：模型治理视图，KERNEL-K6-DESIGN D3） ---- */

/*
 * 每模型一行：name= version= state= slot= hash=<前 12hex> bytes=
 * infer_n= last_lat_ns= timeout_n=（数据源=A 扩展的 ai_model_enumerate：
 * registry 基础字段 + ai_mlp_model 内新增统计）。
 * slot 语义（施工 A/B 契约）：0=无槽，1=A（active 决策模型），
 * 2=B（arm 待切/观察窗）。hash 为模型权重的 64 位短哈希（A 侧 sha256
 * 折叠），此处显示前 12 hex；builtin decide 无 infer 统计（恒 0）。
 */
static int ai_proc_models_show(struct seq_file *m, void *v)
{
	unsigned int i;

	for (i = 0; ; i++) {
		char name[AI_MAX_NAME_LEN];
		u32 ver, src, st, slot;
		u64 hash, bytes, infer_n, last_lat_ns, timeout_n;

		if (ai_model_enumerate(i, name, &ver, &src, &st,
				       &hash, &bytes, &infer_n, &last_lat_ns,
				       &timeout_n, &slot) != AI_OK)
			break;
		seq_printf(m,
			   "name=%s version=%u state=%u slot=%u hash=%012llx "
			   "bytes=%llu infer_n=%llu last_lat_ns=%llu "
			   "timeout_n=%llu\n",
			   name, ver, st, slot, hash, bytes, infer_n,
			   last_lat_ns, timeout_n);
	}
	return 0;
}

static int ai_proc_models_open(struct inode *inode, struct file *file)
{
	return single_open(file, ai_proc_models_show, NULL);
}

static const struct proc_ops ai_proc_models_ops = {
	.proc_open    = ai_proc_models_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
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

#if IS_ENABLED(CONFIG_AIKERNEL_SECURITY)
/* ---- audit（K8：审计链窗口导出；0400 敏感口径同 decisions） ---- */

static int ai_proc_audit_show(struct seq_file *m, void *v)
{
	struct ai_chain_stats st;
	struct ai_chain_node n;
	u64 s;

	ai_chain_stats_read(&st);
	seq_printf(m, "chain head=%016llx nodes=%llu evicted=%llu anchors=%llu seeded=%016llx\n",
		   st.head_hash, st.nodes, st.evicted, st.anchors,
		   st.seeded ? st.seeded_val : 0);
	for (s = st.first_seq; s && s <= st.nodes; s++) {
		if (ai_chain_node_copy(s, &n))
			break;
		seq_printf(m, "n seq=%llu ts=%llu k=%u pid=%u f=%u prev=%016llx h=%016llx d=%32phN\n",
			   n.seq, n.ts_ns, n.kind, n.pid, n.flags,
			   n.prev_hash, n.self_hash, n.data);
	}
	return 0;
}

static int ai_proc_audit_open(struct inode *inode, struct file *file)
{
	return single_open(file, ai_proc_audit_show, NULL);
}

static const struct proc_ops ai_proc_audit_ops = {
	.proc_open    = ai_proc_audit_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

#endif	/* CONFIG_AIKERNEL_SECURITY */

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
	/* K3：agent 角色注册表/配额/记账面（追加条目，既有行零改） */
	proc_create("agents", 0644, ai_proc_root, &ai_proc_agents_ops);
	/* K6：模型治理视图（D3 七字段+slot；照 agents 节点同款手法追加） */
	proc_create("models", 0444, ai_proc_root, &ai_proc_models_ops);
#if IS_ENABLED(CONFIG_AIKERNEL_SECURITY)
	/* K8：审计链窗口导出（hex 行单格式，aikctl 同口径解析） */
	proc_create("audit", 0400, ai_proc_root, &ai_proc_audit_ops);
#endif

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
