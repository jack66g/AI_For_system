// SPDX-License-Identifier: GPL-2.0
/*
 * ai_causal.c - AIKernel 决策因果链（数据计划 20.1/20.4，Prompt 13）
 *
 * 因果链 = {感知事件, 决策, 结果}：trigger_event_id → decision_id → outcome，
 * 是强化学习最宝贵的训练数据。内核侧通用导出接口：
 *   1. ring（512 条，spinlock 满覆盖最旧）——/proc/ai/chains 数据源；
 *   2. CSV 文件导出：进程上下文时经 filp_open/kernel_write 追加写
 *      <dir>/YYYY-MM-DD/chains_<seq>.csv（UTC 日期；新建时写字段名头；
 *      全量零脱敏；父目录不存在 → 仅 ring，不隐式 mkdir）。
 *      parquet（chains_*.parquet）由后续 aikd 从 /proc/ai/chains 落盘。
 *
 * 门控 CONFIG_AIKERNEL_RUNTIME（n 配置 stub）。
 */

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/timekeeping.h>
#include <linux/preempt.h>
#include <linux/ktime.h>
#include "ai_causal.h"

/* ---- ring ---- */

static struct ai_decision_record ai_causal_ring[AI_CAUSAL_RING_SIZE]
					____cacheline_aligned_in_smp;
static unsigned int ai_causal_head;
static u64 ai_causal_total;
static DEFINE_SPINLOCK(ai_causal_lock);

#define AI_CAUSAL_MASK  (AI_CAUSAL_RING_SIZE - 1)

/* ---- CSV 导出 ---- */

static char ai_causal_dir[AI_PATH_MAX] = AI_CAUSAL_DEFAULT_DIR;
static struct file *ai_causal_file;
static char ai_causal_day[24];      /* "YYYY-MM-DD"（当前打开文件对应日期）；
				     * 16→24：u64 极值年份可达 9 位（约 5.8e8），
				     * 预留余量使 format-truncation 可证安全（W=1） */
static u32 ai_causal_seq;
static DEFINE_MUTEX(ai_causal_export_lock);

/* 儒略日 → 公历（Howard Hinnant civil_from_days，UTC） */
static void ai_causal_date(u64 secs, char *out, size_t cap)
{
	long z = (long)(secs / 86400) + 719468;
	long era = (z >= 0 ? z : z - 146096) / 146097;
	unsigned long doe = (unsigned long)(z - era * 146097);
	unsigned long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	long y = (long)yoe + era * 400;
	unsigned long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	unsigned long mp = (5 * doy + 2) / 153;
	unsigned long d = doy - (153 * mp + 2) / 5 + 1;
	unsigned long m = mp < 10 ? mp + 3 : mp - 9;

	y += (m <= 2);
	if (out && cap)
		snprintf(out, cap, "%04ld-%02lu-%02lu", y, m, d);
}

static void ai_causal_csv_write_header(struct file *f)
{
	static const char hdr[] =
		"decision_id,trigger_ts,trigger_event_id,decision_ts,"
		"decision_type,decision_data,execute_ts,outcome_ts,outcome,"
		"metric_delta,model_version,confidence,domain,source,"
		"executed,safety_clamped\n";
	ssize_t rc = kernel_write(f, hdr, sizeof(hdr) - 1, &f->f_pos);

	if (rc < 0)
		pr_debug("AIKernel: causal csv header write failed (%zd)\n", rc);
}

static void ai_causal_csv_write_record(struct file *f,
				       const struct ai_decision_record *r)
{
	char line[512];
	char data[192];
	int n, i, pos = 0;

	for (i = 0; i < 8; i++)
		pos += scnprintf(data + pos, sizeof(data) - pos, "%s%llu",
				 i ? ":" : "", (unsigned long long)r->decision_data[i]);

	n = scnprintf(line, sizeof(line),
		      "%llu,%llu,%u,%llu,%u,%s,%llu,%llu,%u,%lld,%u,%u,%u,%u,%u,%u\n",
		      (unsigned long long)r->decision_id,
		      (unsigned long long)r->trigger_ts,
		      r->trigger_event_id,
		      (unsigned long long)r->decision_ts,
		      r->decision_type, data,
		      (unsigned long long)r->execute_ts,
		      (unsigned long long)r->outcome_ts,
		      r->outcome, (long long)r->metric_delta,
		      r->model_version, r->confidence, r->domain, r->source,
		      r->executed, r->safety_clamped);
	if (n > 0 && n < (int)sizeof(line))
		kernel_write(f, line, n, &f->f_pos);
}

int ai_causal_chain_push(const struct ai_decision_record *rec)
{
	unsigned long flags;

	if (!rec)
		return AI_ERR_INVALID_ARG;

	/* 恒写 ring（原子上下文安全；满覆盖最旧） */
	spin_lock_irqsave(&ai_causal_lock, flags);
	ai_causal_ring[ai_causal_head & AI_CAUSAL_MASK] = *rec;
	ai_causal_head++;
	ai_causal_total++;
	spin_unlock_irqrestore(&ai_causal_lock, flags);

	/* 进程上下文：CSV 文件追加导出（原子上下文仅 ring） */
	if (!in_atomic() && !irqs_disabled()) {
		struct file *f;
		char day[24], path[AI_PATH_MAX + 64];   /* day 同 ai_causal_day 放宽：
							 * u64 极值年份 9 位，16 字节
							 * 触发 W=1 format-truncation */
		struct timespec64 ts;

		ktime_get_real_ts64(&ts);
		ai_causal_date(ts.tv_sec, day, sizeof(day));

		mutex_lock(&ai_causal_export_lock);
		f = ai_causal_file;
		if (f && strcmp(day, ai_causal_day) != 0) {
			filp_close(f, NULL);
			ai_causal_file = NULL;
			f = NULL;
		}
		if (!f) {
			/* 父目录不存在 → 仅 ring（不隐式 mkdir） */
			snprintf(path, sizeof(path), "%s/%s/chains_%05u.csv",
				 ai_causal_dir, day, ai_causal_seq);
			f = filp_open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
			if (IS_ERR(f)) {
				mutex_unlock(&ai_causal_export_lock);
				return AI_OK;   /* 无目录：ring 已记录 */
			}
			ai_causal_file = f;
			strscpy(ai_causal_day, day, sizeof(ai_causal_day));
			ai_causal_seq++;
			/* 新建空文件时写字段名头（既有文件跳过） */
			if (file_inode(f)->i_size == 0)
				ai_causal_csv_write_header(f);
		}
		ai_causal_csv_write_record(f, rec);
		mutex_unlock(&ai_causal_export_lock);
	}
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_causal_chain_push);

int ai_causal_chain_read(void *buf, size_t cap,
			 u32 *out_count, size_t *out_bytes)
{
	unsigned long flags;
	unsigned int start, n, i;
	size_t copied = 0;
	u32 count = 0;

	if (!buf || !out_count)
		return AI_ERR_INVALID_ARG;

	spin_lock_irqsave(&ai_causal_lock, flags);
	n = min_t(u64, ai_causal_total, AI_CAUSAL_RING_SIZE);
	start = ai_causal_head - n;
	for (i = 0; i < n; i++) {
		const struct ai_decision_record *e =
			&ai_causal_ring[(start + i) & AI_CAUSAL_MASK];

		if (copied + sizeof(*e) > cap)
			break;
		memcpy((u8 *)buf + copied, e, sizeof(*e));
		copied += sizeof(*e);
		count++;
	}
	spin_unlock_irqrestore(&ai_causal_lock, flags);

	*out_count = count;
	if (out_bytes)
		*out_bytes = copied;
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_causal_chain_read);

int ai_causal_set_export_dir(const char *path)
{
	struct file *f;

	if (!path || !path[0] || strlen(path) >= AI_PATH_MAX)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_causal_export_lock);
	f = ai_causal_file;
	if (f) {
		filp_close(f, NULL);
		ai_causal_file = NULL;
	}
	strscpy(ai_causal_dir, path, sizeof(ai_causal_dir));
	mutex_unlock(&ai_causal_export_lock);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_causal_set_export_dir);

int ai_causal_get_export_dir(char *path)
{
	if (!path)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_causal_export_lock);
	strscpy(path, ai_causal_dir, AI_PATH_MAX);
	mutex_unlock(&ai_causal_export_lock);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_causal_get_export_dir);

int ai_causal_flush(void)
{
	struct file *f;

	mutex_lock(&ai_causal_export_lock);
	f = ai_causal_file;
	ai_causal_file = NULL;
	ai_causal_day[0] = '\0';
	mutex_unlock(&ai_causal_export_lock);
	if (f)
		filp_close(f, NULL);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_causal_flush);
