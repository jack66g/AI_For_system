// SPDX-License-Identifier: GPL-2.0
/*
 * ai_audit.c - AIKernel AI 安全审计模块（审计关联 + 攻击链）
 *
 * 门控 CONFIG_AIKERNEL_SECURITY（default n）。AI 关闭时不构建零影响。
 *
 * A 轨（重构计划 6.6）：AI 实时关联审计事件，构建攻击链。
 *   - ai_audit_ingest()：kernel/audit.c 每个审计记录完成点同步原始字节
 *     （零脱敏）→ per-CPU ring + 类型分派；
 *   - ai_audit_chain_record()：攻击链记录接口（(pid, 类型序列)，关联推理
 *     由后续步骤/AI 填充）。
 * B 轨（数据计划 8.4）：audit_syscall/audit_path/audit_anomaly 事件发射。
 *
 * 决策日志默认仅特权可读（AI 全量可见，外部用户需授权）。
 */

#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/limits.h>
#include <linux/ptrace.h>
#include <uapi/linux/audit.h>
#include <asm/syscall.h>
#include "../core/ai_types.h"
#include "ai_audit.h"

/* per-CPU 原始记录 ring（32KB，无锁：head 属主写，AI Runtime 单读者） */
#define AI_AUDIT_RING_SIZE	(32 * 1024)

struct ai_audit_cpu {
	unsigned char ring[AI_AUDIT_RING_SIZE];
	u32 head, tail;
	u32 total;		/* 已接收记录数 */
	u32 dropped;		/* 满丢弃数 */
};

static DEFINE_PER_CPU(struct ai_audit_cpu, ai_audit_cpu);

/* 攻击链关联表（64 槽，spinlock 保护；满覆盖最旧） */
struct ai_audit_chain {
	u32 pid;
	u8  nodes[AI_AUDIT_CHAIN_DEPTH];
	u64 last_ts;
};

static struct ai_audit_chain ai_audit_chains[AI_AUDIT_CHAIN_SLOTS];
static DEFINE_SPINLOCK(ai_audit_chain_lock);

static u32 ai_audit_stat_syscall;
static u32 ai_audit_stat_path;
static u32 ai_audit_stat_anomaly;
static u32 ai_audit_stat_chains;

/* ---- 记录文本轻量解析（固定格式字段，解析失败保留 raw 不报错） ---- */

static long ai_audit_parse_long(const char *text, u32 len, const char *key,
				long dflt)
{
	const char *p = text, *end = text + len;
	unsigned int klen = strlen(key);
	long val = dflt;
	char *ep;

	while (p + klen <= end) {
		if (memcmp(p, key, klen) == 0) {
			p += klen;
			val = simple_strtol(p, &ep, 0);
			break;
		}
		p = memchr(p, ' ', end - p);
		if (!p)
			break;
		p++;
	}
	return val;
}

static int ai_audit_parse_success(const char *text, u32 len)
{
	const char *p = text, *end = text + len;
	unsigned int klen = strlen("success=");

	while (p + klen <= end) {
		if (memcmp(p, "success=", klen) == 0) {
			p += klen;
			if (end - p >= 3 && memcmp(p, "yes", 3) == 0)
				return 1;
			return 0;
		}
		p = memchr(p, ' ', end - p);
		if (!p)
			break;
		p++;
	}
	return 0;
}

/* ---- 攻击链记录 ---- */

int ai_audit_chain_record(u32 pid, u8 type, const char *detail)
{
	struct ai_audit_chain *chain = NULL;
	struct ai_audit_chain *free = NULL;
	unsigned long flags;
	int i;
	u64 now = ktime_get_ns();

	spin_lock_irqsave(&ai_audit_chain_lock, flags);
	for (i = 0; i < AI_AUDIT_CHAIN_SLOTS; i++) {
		if (ai_audit_chains[i].pid == pid) {
			chain = &ai_audit_chains[i];
			break;
		}
		if (!free && !ai_audit_chains[i].pid)
			free = &ai_audit_chains[i];
	}
	if (!chain)
		chain = free;
	if (!chain) {
		/* 满：覆盖最旧 */
		u64 oldest = U64_MAX;

		for (i = 0; i < AI_AUDIT_CHAIN_SLOTS; i++) {
			if (ai_audit_chains[i].last_ts < oldest) {
				oldest = ai_audit_chains[i].last_ts;
				chain = &ai_audit_chains[i];
			}
		}
	}
	chain->pid = pid;
	memmove(chain->nodes, chain->nodes + 1, AI_AUDIT_CHAIN_DEPTH - 1);
	chain->nodes[AI_AUDIT_CHAIN_DEPTH - 1] = type;
	chain->last_ts = now;
	ai_audit_stat_chains++;
	spin_unlock_irqrestore(&ai_audit_chain_lock, flags);
	return AI_OK;
}

/* ---- 事件发射 ---- */

void ai_telemetry_audit_path(const char *full_path, u32 rec_type)
{
	struct ai_sec_audit_path_payload p;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_AUDIT))
		return;
	p.type = AI_SEC_AUDIT_PATH;
	p.pid = current ? current->pid : 0;
	strscpy(p.full_path, full_path ? full_path : "?",
		sizeof(p.full_path));
	p.rec_type = rec_type;
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_AUDIT, AI_SEV_NORMAL,
				 &p, sizeof(p));
	ai_audit_stat_path++;
}

void ai_telemetry_audit_anomaly(const char *anomaly_type, const char *detail)
{
	struct ai_sec_audit_anomaly_payload p;
	static unsigned long last_emit;

	/* 审计异常事件按类型 1 秒限频（丢失风暴下防止淹没 ring，AI 仍可读统计） */
	if (time_before(jiffies, last_emit + HZ))
		return;
	last_emit = jiffies;

	if (!ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_AUDIT))
		return;
	p.type = AI_SEC_AUDIT_ANOMALY;
	p.pid = current ? current->pid : 0;
	strscpy(p.comm, current && current->comm[0] ? current->comm : "?",
		sizeof(p.comm));
	strscpy(p.anomaly_type, anomaly_type ? anomaly_type : "unknown",
		sizeof(p.anomaly_type));
	strscpy(p.full_detail, detail ? detail : "", sizeof(p.full_detail));
	ai_telemetry_emit_direct(AI_CAT_SECURITY, AI_EV_AUDIT, AI_SEV_CRITICAL,
				 &p, sizeof(p));
	ai_audit_stat_anomaly++;
}

/* ==================================================================
 * sec.audit 采集开关（真开关真效果）：关闭后 ai_audit_ingest 直接
 * 返回，审计记录不再进 AI ring/遥测/攻击链；gate 丢弃计数供观测面。
 * ================================================================== */
#include <linux/atomic.h>

static bool ai_audit_capture_enabled = true;
static atomic64_t ai_audit_gate_drops;

bool ai_audit_capture_is_enabled(void)
{
	return READ_ONCE(ai_audit_capture_enabled);
}

int ai_audit_capture_enable(bool on)
{
	WRITE_ONCE(ai_audit_capture_enabled, on);
	pr_info("AIKernel: sec.audit AI capture %s\n",
		on ? "enabled" : "disabled");
	return AI_OK;
}

u64 ai_audit_gate_drops_read(void)
{
	return atomic64_read(&ai_audit_gate_drops);
}

/* ---- 接收入口 ---- */

int ai_audit_ingest(u32 rec_type, const void *data, u32 data_len)
{
	struct ai_audit_cpu *cpu = this_cpu_ptr(&ai_audit_cpu);
	u32 free, hdr = sizeof(u32);

	if (!ai_audit_capture_is_enabled()) {
		atomic64_inc(&ai_audit_gate_drops);   /* sec.audit=0 真关 */
		return AI_OK;
	}
	if (!data || data_len == 0)
		return AI_ERR_INVALID_ARG;
	if (data_len > AI_TELEMETRY_MAX_DATA_LEN)
		data_len = AI_TELEMETRY_MAX_DATA_LEN;

	/* 1) 原始记录入 ring（零脱敏；满丢弃） */
	free = (cpu->head >= cpu->tail) ?
		(AI_AUDIT_RING_SIZE - (cpu->head - cpu->tail)) :
		(cpu->tail - cpu->head);
	if (free > hdr + data_len) {
		u32 head = cpu->head;

		memcpy(cpu->ring + head, &data_len, sizeof(data_len));
		head += hdr;
		if (head + data_len > AI_AUDIT_RING_SIZE) {
			u32 first = AI_AUDIT_RING_SIZE - head;

			memcpy(cpu->ring + head, data, first);
			memcpy(cpu->ring, (const char *)data + first,
			       data_len - first);
			head = data_len - first;
		} else {
			memcpy(cpu->ring + head, data, data_len);
			head += data_len;
		}
		cpu->head = head;
	} else {
		cpu->dropped++;
	}
	cpu->total++;

	/* 2) 类型分派：AUDIT_SYSCALL → audit_syscall 事件 */
	if (rec_type == AUDIT_SYSCALL) {
		struct ai_sec_audit_syscall_payload p;
		s32 nr;

		if (ai_telemetry_sample_take(AI_CAT_SECURITY, AI_EV_AUDIT)) {
			p.type = AI_SEC_AUDIT_SYSCALL;
			p.pid = current ? current->pid : 0;
			strscpy(p.comm,
				current && current->comm[0] ? current->comm : "?",
				sizeof(p.comm));
			nr = current ? syscall_get_nr(current,
						      current_pt_regs()) : -1;
			p.syscall_nr = nr;
			ai_sec_syscall_name(nr, p.syscall_name,
					    sizeof(p.syscall_name));
			p.success = (u8)ai_audit_parse_success(data, data_len);
			p.exit_code = ai_audit_parse_long(data, data_len,
							  "exit=", 0);
			ai_telemetry_emit_direct(AI_CAT_SECURITY,
						 AI_EV_AUDIT, AI_SEV_NORMAL,
						 &p, sizeof(p));
			ai_audit_stat_syscall++;
		}

		/* 攻击链节点：审计记录 = 观察 */
		ai_audit_chain_record(p.pid, 0, "audit_syscall");
	}

	return AI_OK;
}

int ai_audit_stats_read(u32 *total, u32 *syscall, u32 *path, u32 *anomaly,
			u32 *chains)
{
	struct ai_audit_cpu *cpu;
	u32 t = 0;
	int c;

	for_each_possible_cpu(c) {
		cpu = per_cpu_ptr(&ai_audit_cpu, c);
		t += cpu->total;
	}
	if (total)
		*total = t;
	if (syscall)
		*syscall = ai_audit_stat_syscall;
	if (path)
		*path = ai_audit_stat_path;
	if (anomaly)
		*anomaly = ai_audit_stat_anomaly;
	if (chains)
		*chains = ai_audit_stat_chains;
	return AI_OK;
}
