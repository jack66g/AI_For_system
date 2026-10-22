// SPDX-License-Identifier: GPL-2.0
/*
 * ask_context.c - ask 内核状态紧凑摘要 / 请求预算口径 / 策略提示段
 * （W55 P2、W56 T1/T3/T4/T5）
 *
 * 从 cmd_ask.c 抽出纯函数，便于专项测试直接链接（不依赖 shell/
 * runtime/registry）。/proc/ai/status 实机约 30KB/841 行，摘要只保留
 * 决策必需字段，完整内容仍由 procfs_read_status 工具按需读取。
 *
 * W56 摘要口径：dropped/sampled_skip 是启动以来累计值，不是"本次新增"；
 * 进程内保留上一次摘要的基线并给出增量（静态状态 + C11 原子锁，多线程
 * 调用安全）。sampled_skip 是主动降采样，不等于丢失。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdatomic.h>

#include "ask_context.h"
#include "ai_lang.h"

/* 上一次摘要的遥测基线（进程内；原子锁保护） */
static atomic_flag g_summary_lock = ATOMIC_FLAG_INIT;
static int g_summary_have_prev;
static unsigned long long g_summary_prev_dropped;

static void ask_summary_lock(void)
{
	while (atomic_flag_test_and_set(&g_summary_lock))
		; /* 极短临界区，自旋即可 */
}

static void ask_summary_unlock(void)
{
	atomic_flag_clear(&g_summary_lock);
}

static const char *ask_status_find_line(const char *status, const char *prefix)
{
	size_t n = strlen(prefix);
	const char *p = status;

	while (p && *p) {
		if (strncmp(p, prefix, n) == 0)
			return p;
		p = strchr(p, '\n');
		if (p)
			p++;
	}
	return NULL;
}

static size_t ask_status_append(char *out, size_t cap, size_t off,
				const char *fmt, ...)
{
	va_list ap;
	int n;

	if (!out || cap == 0)
		return 0;
	if (off >= cap)
		return cap - 1;
	va_start(ap, fmt);
	n = vsnprintf(out + off, cap - off, fmt, ap);
	va_end(ap);
	if (n < 0)
		return off;
	if ((size_t)n >= cap - off)
		return cap - 1;
	return off + (size_t)n;
}

static unsigned long long ask_status_kv_u64(const char *line, const char *key)
{
	const char *p;

	if (!line || !key)
		return 0;
	p = strstr(line, key);
	if (!p)
		return 0;
	return strtoull(p + strlen(key), NULL, 10);
}

int ask_status_summary_build(const char *status, char *out, size_t out_sz)
{
	const char *p, *line;
	size_t off = 0;
	unsigned long long dropped_total = 0, skip_total = 0;
	struct {
		unsigned long long dropped;
		unsigned long cpu;
	} top[3];
	int ndrop = 0;
	int ntop;
	int nmodels = 0;
	char names[192];
	size_t names_off = 0;
	int i;

	if (!status || !out || out_sz < 2)
		return -1;
	out[0] = '\0';
	names[0] = '\0';
	memset(top, 0, sizeof(top));

	/* 单行字段：整行复制（去掉前缀与换行） */
#define ASK_STATUS_COPY_LINE(prefix)					\
	do {								\
		line = ask_status_find_line(status, prefix);		\
		if (line) {						\
			const char *v = line + strlen(prefix);		\
			size_t n;					\
			while (*v == ' ' || *v == '\t')			\
				v++;					\
			n = strcspn(v, "\r\n");				\
			if (n > 96)					\
				n = 96;					\
			off = ask_status_append(out, out_sz, off,	\
						"%s %.*s\n", prefix,	\
						(int)n, v);		\
		}							\
	} while (0)

	ASK_STATUS_COPY_LINE("runtime_state:");
	ASK_STATUS_COPY_LINE("enabled:");
	ASK_STATUS_COPY_LINE("log_level:");
	ASK_STATUS_COPY_LINE("telemetry_ring:");
	ASK_STATUS_COPY_LINE("telemetry_drain:");
#undef ASK_STATUS_COPY_LINE

	/* models：统计行数并收集前 3 个模型名 */
	line = ask_status_find_line(status, "models:");
	if (line) {
		p = strchr(line, '\n');
		p = p ? p + 1 : NULL;
		while (p && *p == ' ') {
			const char *nm;
			const char *q = p;

			while (*q == ' ' || *q == '\t')
				q++;
			if (*q != '[')
				break;
			nmodels++;
			nm = strstr(q, "name=");
			if (nm && nmodels <= 3) {
				size_t n;

				nm += 5;
				n = strcspn(nm, " \t\r\n");
				if (n > 48)
					n = 48;
				if (names_off + n + 3 < sizeof(names))
					names_off += (size_t)snprintf(
						names + names_off,
						sizeof(names) - names_off,
						"%s%.*s",
						names_off ? "," : "",
						(int)n, nm);
			}
			p = strchr(p, '\n');
			p = p ? p + 1 : NULL;
		}
	}
	if (nmodels)
		off = ask_status_append(out, out_sz, off,
				       "models=%d (%s)\n", nmodels, names);
	else
		off = ask_status_append(out, out_sz, off, "models=0\n");

	/* 每 CPU dropped / sampled_skip 汇总 + dropped top3 */
	for (p = status; *p;
	     p = strchr(p, '\n') ? strchr(p, '\n') + 1 : p + strlen(p)) {
		unsigned long cpu;
		unsigned long long dropped, skip;
		char *end;

		if (strncmp(p, "cpu", 3) != 0 ||
		    p[3] < '0' || p[3] > '9')
			continue;
		cpu = strtoul(p + 3, &end, 10);
		if (!end || *end != ':')
			continue;
		dropped = ask_status_kv_u64(p, "dropped=");
		skip = ask_status_kv_u64(p, "sampled_skip=");
		dropped_total += dropped;
		skip_total += skip;
		if (dropped > 0) {
			ndrop++;
			for (i = 0; i < 3; i++) {
				if (dropped > top[i].dropped) {
					int j;

					for (j = 2; j > i; j--)
						top[j] = top[j - 1];
					top[i].dropped = dropped;
					top[i].cpu = cpu;
					break;
				}
			}
		}
	}
	ntop = ndrop < 3 ? ndrop : 3;

	{
		char drop_note[128];
		char skip_note[96];
		char delta[48];

		delta[0] = '\0';
		ask_summary_lock();
		if (g_summary_have_prev &&
		    dropped_total >= g_summary_prev_dropped)
			snprintf(delta, sizeof(delta),
				 tr(TR_ASK_STATUS_DELTA_FMT),
				 dropped_total - g_summary_prev_dropped);
		g_summary_have_prev = 1;
		g_summary_prev_dropped = dropped_total;
		ask_summary_unlock();

		snprintf(drop_note, sizeof(drop_note),
			 tr(TR_ASK_STATUS_DROPPED_NOTE), delta);
		snprintf(skip_note, sizeof(skip_note), "%s",
			 tr(TR_ASK_STATUS_SKIP_NOTE));
		off = ask_status_append(out, out_sz, off,
				       "dropped_total=%llu%s "
				       "sampled_skip_total=%llu%s\n",
				       dropped_total, drop_note,
				       skip_total, skip_note);
	}
	if (ntop == 0)
		off = ask_status_append(out, out_sz, off,
				       "dropped_top3=none\n");
	else {
		off = ask_status_append(out, out_sz, off, "dropped_top3=");
		for (i = 0; i < ntop; i++)
			off = ask_status_append(out, out_sz, off,
					       "%scpu%lu:%llu",
					       i ? ", " : "",
					       top[i].cpu, top[i].dropped);
		off = ask_status_append(out, out_sz, off, "\n");
	}

	if (off >= out_sz)
		out[out_sz - 1] = '\0';
	return (int)strlen(out);
}

/*
 * 窗口占用 = 最近一次请求的输入 prompt。W55 曾把 completion 也加上，
 * 实机出现 compact 后 "context budget 110% used" 假警告：completion 是
 * 输出（受 max_tokens 约束），下一轮又会出现在 prompt 里，相加即重复
 * 计数。last_out 参数保留兼容旧调用点，不参与计算。
 * W72：上限 100%（旧实现钳到 999，提示符曾显示 999%）。
 */
int ask_ctx_budget_percent(int last_in, int last_out, int ctx_len)
{
	long used;

	(void)last_out;
	if (ctx_len <= 0)
		return 0;
	used = (long)(last_in > 0 ? last_in : 0);
	{
		long pct = used * 100 / ctx_len;

		return (int)(pct > 100 ? 100 : pct);
	}
}

int ask_ctx_prompt_percent(int last_in, int ctx_len)
{
	long pct;

	if (ctx_len <= 0 || last_in <= 0)
		return -1;
	pct = (long)last_in * 100 / ctx_len;
	return (int)(pct > 100 ? 100 : pct);
}

int ask_ctx_should_autocompact(long used_est, long budget)
{
	if (budget <= 0 || used_est <= 0)
		return 0;
	return used_est * 100 > budget * ASK_AUTOCOMPACT_PCT;
}

long ask_ctx_hist_budget(int ctx_len, int max_tokens)
{
	long budget;

	if (ctx_len <= 0)
		return ASK_HIST_BUDGET_MIN;
	budget = (long)ctx_len - (max_tokens > 0 ? max_tokens : 0) -
		 ASK_HIST_RESERVE_TOKENS;
	if (budget < ASK_HIST_BUDGET_MIN)
		budget = ASK_HIST_BUDGET_MIN;
	return budget;
}

int ask_prompt_policy_notes_build(int assume_yes, int plan_mode,
				  char *out, size_t out_sz)
{
	size_t off = 0;

	if (!out || out_sz < 2)
		return -1;
	out[0] = '\0';

	/* plan 优先：plan 态即使 assume_yes 也不输出"可直接调用"，
	 * 只保留 plan 只读约束（由调用方追加 TR_PLAN_SYS_NOTE）。 */
	if (assume_yes && !plan_mode)
		off = ask_status_append(out, out_sz, off, "%s",
					tr(TR_ASK_SYS_ASSUME_YES));
	off = ask_status_append(out, out_sz, off, "%s",
				tr(TR_ASK_SYS_LANGUAGE));
	if (off >= out_sz)
		out[out_sz - 1] = '\0';
	return (int)strlen(out);
}
