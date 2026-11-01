// SPDX-License-Identifier: GPL-2.0
/*
 * ai_lsm.c - AIKernel AI LSM 模块（AI 行为异常检测大脑）
 *
 * 门控 CONFIG_AIKERNEL_SECURITY（default n）。AI 关闭时不构建、不注册，
 * 安全框架行为与原生完全一致（可插拔 LSM，lsm=ai,... 启动参数显式启用）。
 *
 * A 轨（重构计划 6.1/6.2/6.3/6.4/6.5/6.8）：
 *   - LSM 钩子（W80：file_open/task_alloc/file_permission/socket_connect/
 *     socket_sendmsg/task_kill/ptrace_access_check）+ 行为建模与异常检测框架；
 *   - W80 三维规则（pid > label > path_prefix）与 per-task 工作区标签
 *     （LSM blob，fork 继承、退出随 blob 释放）；
 *   - ai_sec_seccomp/cap/key/crypto_hook：AI 决策接入点（空实现=原样放行；
 *     sec.seccomp 参数已于 W49 如实降级 reserved，见文末说明）；
 *   - ai_sec_syscall_name()：syscall 号→名称（低频事件专用）。
 * B 轨（数据计划 第8类）：8.1/8.2/8.3/8.5/8.6/8.8 事件发射全量原始零脱敏。
 * 8.4（审计）由 ai_audit.c 承担；8.7 kmsan/ubsan/kcsan 发射本文件提供，采集点在
 * mm/kmsan/report.c、lib/ubsan.c、kernel/kcsan/report.c（kasan/kfence 已在
 * Prompt 04 落地，核对通过不重复）。
 *
 * 决策日志默认仅特权可读（AI 全量可见，外部用户需授权）。
 * 拆分说明：本文件为拆分后的 LSM 主体（原 ai_lsm.c 862 行）：行为模型表、
 * 规则表、异常评估、LSM 钩子与 ai_sec_* 接入点及 LSM 注册。第8类发射辅助拆至
 * ai_lsm_telemetry.c（能力名表随迁）。对外接口 ai_lsm.h 不变。
 */

#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include "ai_audit.h"
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/signal.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <linux/kallsyms.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/minmax.h>
#include <linux/kernel.h>
#include <linux/jump_label.h>
#include <linux/net.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mutex.h>
#include <linux/capability.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <uapi/linux/lsm.h>
#include <asm/syscall.h>
#include "ai_lsm.h"
#include "../core/ai_control.h"
#include "../core/ai_startup.h"

/* ==================================================================
 * 工作区标签（workspace label，W80）
 *
 * 存储：per-task LSM blob（lbs_task，1 字节），不改 task_struct 布局；
 *       任务退出时 task->security 随 security_task_free() 释放，无泄漏。
 * 继承：task_alloc 钩子从父任务复制（CLONE_THREAD 同线程组一致；
 *       fork 后标签相同，之后各自独立）。
 * 默认：0 = 无标签，不参与任何 label 规则（空表/无标签零回归）。
 * 门控：仅 lsm= 启用 'ai' 时 prepare_lsm() 才分配 blob 偏移，
 *       ai_lsm_init() 置 ai_lsm_blob_ready；未启用时设置返回
 *       AI_ERR_DISABLED、读取恒为 0，规则引擎照常工作（pid 规则不受影响）。
 * ================================================================== */

struct ai_lsm_task_blob {
	u8 ws_label;
};

static struct lsm_blob_sizes ai_lsm_blob_sizes __ro_after_init = {
	.lbs_task = sizeof(struct ai_lsm_task_blob),
};

static bool ai_lsm_blob_ready __ro_after_init;

static u8 *ai_lsm_task_label_ptr(struct task_struct *task)
{
	if (!ai_lsm_blob_ready || !task || !task->security)
		return NULL;
	return (u8 *)task->security + ai_lsm_blob_sizes.lbs_task;
}

static u8 ai_lsm_label_get(struct task_struct *task)
{
	u8 *p = ai_lsm_task_label_ptr(task);

	return p ? READ_ONCE(*p) : 0;
}

int ai_lsm_ws_label_set(s32 pid, u8 label)
{
	struct task_struct *task, *t;

	if (!ai_lsm_blob_ready)
		return AI_ERR_DISABLED;
	if (pid <= 0)
		return AI_ERR_INVALID_ARG;

	task = find_get_task_by_vpid(pid);
	if (!task)
		return AI_ERR_NOT_FOUND;

	/* 线程组一致：整组线程同标签（CLONE_THREAD 语义） */
	rcu_read_lock();
	for_each_thread(task, t) {
		u8 *p = ai_lsm_task_label_ptr(t);

		if (p)
			WRITE_ONCE(*p, label);
	}
	rcu_read_unlock();
	put_task_struct(task);
	return AI_OK;
}

int ai_lsm_ws_label_get(s32 pid, u8 *label)
{
	struct task_struct *task;

	if (!label)
		return AI_ERR_INVALID_ARG;
	if (!ai_lsm_blob_ready)
		return AI_ERR_DISABLED;
	if (pid <= 0)
		return AI_ERR_INVALID_ARG;

	task = find_get_task_by_vpid(pid);
	if (!task)
		return AI_ERR_NOT_FOUND;
	*label = ai_lsm_label_get(task);
	put_task_struct(task);
	return AI_OK;
}

static int ai_lsm_task_alloc(struct task_struct *task, u64 clone_flags)
{
	u8 *dst = ai_lsm_task_label_ptr(task);
	u8 label = ai_lsm_label_get(current);

	if (dst)
		WRITE_ONCE(*dst, label);
	return 0;
}

/* ==================================================================
 * 行为模型表（per-pid 计数 + 滑动基线；无分配，spinlock 保护）
 * ================================================================== */

struct ai_lsm_model {
	u32 pid;		/* 0=空槽 */
	u64 last_ts;		/* 上次更新 */
	u64 window_ts;		/* 当前窗口起点 */
	u32 count_open;		/* 本窗口 file_open 次数 */
	u32 count_kill;		/* 本窗口 task_kill 次数 */
	u32 count_ptrace;	/* 本窗口 ptrace 次数 */
	u32 count_cap_deny;	/* 本窗口能力拒绝次数 */
	u32 count_seccomp;	/* 本窗口 seccomp 拦截次数 */
	u32 base_open;		/* 基线（上一窗口速率） */
	u32 base_kill;
	u8  anomaly;		/* 最近异常分 0~100 */
};

static struct ai_lsm_model ai_lsm_models[AI_LSM_MODEL_SLOTS];
static DEFINE_SPINLOCK(ai_lsm_model_lock);

#define AI_LSM_WINDOW_NS	(10ULL * NSEC_PER_SEC)

static struct ai_lsm_model *ai_lsm_model_get(u32 pid, u64 now, bool create)
{
	struct ai_lsm_model *m;
	u32 idx = pid % AI_LSM_MODEL_SLOTS;

	m = &ai_lsm_models[idx];
	if (m->pid != pid) {
		if (!create)
			return NULL;
		memset(m, 0, sizeof(*m));
		m->pid = pid;
		m->window_ts = now;
		m->last_ts = now;
	}
	return m;
}

static void ai_lsm_model_update(struct ai_lsm_model *m, u64 now, int kind)
{
	u32 *count, *base;

	switch (kind) {
	case 0: count = &m->count_open; base = &m->base_open; break;
	case 1: count = &m->count_kill; base = &m->base_kill; break;
	case 2: count = &m->count_ptrace; base = NULL; break;
	case 3: count = &m->count_cap_deny; base = NULL; break;
	default: count = &m->count_seccomp; base = NULL; break;
	}

	(*count)++;
	if (now - m->window_ts >= AI_LSM_WINDOW_NS) {
		/* 窗口滚动：基线 = 上一窗口速率与旧基线均值（慢适应） */
		if (base)
			*base = (*base + *count) / 2;
		*count = 0;
		m->window_ts = now;
	}

	/* 异常分：与基线偏离比（rate=count/窗口，基线=base/窗口，缩放抵消） */
	if (base && *base > 0 && *count > *base) {
		u32 dev = *count * 100 / *base;
		m->anomaly = dev > 100 ? 100 : (u8)dev;
	} else if (kind == 3 && *count >= 3) {
		/* 连续能力拒绝本身就是高可疑信号 */
		m->anomaly = *count > 10 ? 100 : (u8)(*count * 10);
	}
	m->last_ts = now;
}

/* ==================================================================
 * AI 决策规则表（W80 三维：pid / label / path_prefix）
 *
 * 匹配顺序（冲突时"更具体的赢"，级别优先于同类内部得分）：
 *   1) pid 精确规则（旧接口，向后兼容）
 *   2) label 规则（工作区标签，label 0 不参与）
 *   3) path_prefix 规则（最长前缀优先）
 * 同级内：op 具体 > ANY；平手时 deny 优先（保守）。
 *
 * 执行语义：
 *   - 旧 pid 规则保持 sec.lsm_override 档位（默认 observe 仅记录，
 *     enforce 才拦截）；
 *   - label/path 规则是显式工作区策略，命中 deny 立即拦截（不依赖
 *     sec.lsm_override），否则 W80 "工作区进程内核强制禁网"无法成立。
 *
 * 空表零回归：所有新 hook 先 atomic_read(nr_rules) 快路径（空表=立即
 * 返回 0），不做路径构造、不取标签、不扫表。
 *
 * 内存：64 槽 × 136B ≈ 8.5KiB（旧 72B/槽约 4.5KiB，增长约 4KiB，静态）。
 * ================================================================== */

enum ai_lsm_rule_kind {
	AI_LSM_RULE_FREE = 0,
	AI_LSM_RULE_PID,
	AI_LSM_RULE_LABEL,
	AI_LSM_RULE_PATH,
};

struct ai_lsm_rule {
	u32 pid;			/* PID 规则目标 */
	u8 kind;			/* enum ai_lsm_rule_kind */
	u8 label;			/* LABEL 规则标签（1~255） */
	u8 op_type;			/* enum ai_lsm_op_type */
	bool deny;
	char path_prefix[AI_LSM_PATH_PREFIX_LEN];
	char detail[AI_SEC_DETAIL_LEN];
};

/* 一次规则查询的裁决结果 */
struct ai_lsm_verdict {
	bool deny;			/* 命中规则是否要求拒绝 */
	u8 rule_kind;			/* 命中的规则类别 */
	u8 label;			/* 查询时的任务标签 */
	char detail[AI_SEC_DETAIL_LEN];
};

static struct ai_lsm_rule ai_lsm_rules[AI_LSM_RULE_MAX];
static DEFINE_SPINLOCK(ai_lsm_rule_lock);
/*
 * 规则条数：所有 hook 的第一条指令是 atomic_read() 快路径（空表=全放行）。
 * 不用 static key：规则增删可能发生在任意进程上下文，而 static key
 * 的 inc/dec 可能睡眠，与自旋锁保护区无法原子配对；atomic_t 读在
 * x86_64 是一条 MOV，代价与 jump label 同量级且无竞态。
 */
static atomic_t ai_lsm_nr_rules = ATOMIC_INIT(0);
/* path 规则条数：无 path 规则时 file hook 跳过 d_path() 路径构造
 * （读/写热路径上每 read()/write() 都会进 file_permission，路径构造
 * 只在确有 path 规则时才付这笔钱）。 */
static atomic_t ai_lsm_nr_path_rules = ATOMIC_INIT(0);
static u32 ai_lsm_policy_version;

static inline bool ai_lsm_rules_active(void)
{
	return atomic_read(&ai_lsm_nr_rules) != 0;
}

static inline bool ai_lsm_path_rules_active(void)
{
	return atomic_read(&ai_lsm_nr_path_rules) != 0;
}

static bool ai_lsm_path_match(const struct ai_lsm_rule *r, const char *path)
{
	size_t n = strlen(r->path_prefix);

	if (!n || !path)
		return false;
	return strncmp(path, r->path_prefix, n) == 0;
}

/* 同类规则内选最具体的一条（调用者持 ai_lsm_rule_lock） */
static struct ai_lsm_rule *ai_lsm_best_in_kind(u8 kind, u32 pid, u8 label,
					       const char *path, u8 op)
{
	struct ai_lsm_rule *best = NULL;
	int best_score = -1;
	int i;

	for (i = 0; i < AI_LSM_RULE_MAX; i++) {
		struct ai_lsm_rule *r = &ai_lsm_rules[i];
		int score;

		if (r->kind != kind)
			continue;
		if (r->op_type != AI_LSM_OP_ANY && r->op_type != op)
			continue;

		switch (kind) {
		case AI_LSM_RULE_PID:
			if (r->pid != pid)
				continue;
			score = r->op_type != AI_LSM_OP_ANY;
			break;
		case AI_LSM_RULE_LABEL:
			if (!label || r->label != label)
				continue;
			score = r->op_type != AI_LSM_OP_ANY;
			break;
		default:
			if (!ai_lsm_path_match(r, path))
				continue;
			/* 前缀越长越具体；等长时 op 具体者优先 */
			score = (int)strlen(r->path_prefix) * 2 +
				(r->op_type != AI_LSM_OP_ANY);
			break;
		}

		if (score > best_score ||
		    (score == best_score && best && r->deny && !best->deny)) {
			best = r;
			best_score = score;
		}
	}
	return best;
}

static bool ai_lsm_rule_lookup(u32 pid, u8 label, const char *path, u8 op,
			       struct ai_lsm_verdict *v)
{
	struct ai_lsm_rule *best;
	unsigned long flags;

	memset(v, 0, sizeof(*v));
	v->label = label;

	spin_lock_irqsave(&ai_lsm_rule_lock, flags);
	best = ai_lsm_best_in_kind(AI_LSM_RULE_PID, pid, label, path, op);
	if (!best)
		best = ai_lsm_best_in_kind(AI_LSM_RULE_LABEL, pid, label, path,
					   op);
	if (!best)
		best = ai_lsm_best_in_kind(AI_LSM_RULE_PATH, pid, label, path,
					   op);
	if (best) {
		v->rule_kind = best->kind;
		v->deny = best->deny;
		strscpy(v->detail, best->detail, sizeof(v->detail));
	}
	spin_unlock_irqrestore(&ai_lsm_rule_lock, flags);

	return best != NULL;
}

u32 ai_lsm_rule_count(void)
{
	return (u32)atomic_read(&ai_lsm_nr_rules);
}

static int ai_lsm_rule_add_internal(u8 kind, u32 pid, u8 label, u8 op_type,
				    const char *path_prefix, bool deny,
				    const char *detail)
{
	struct ai_lsm_rule *slot = NULL;
	unsigned long flags;
	bool added = false;
	int i;

	spin_lock_irqsave(&ai_lsm_rule_lock, flags);
	for (i = 0; i < AI_LSM_RULE_MAX; i++) {
		struct ai_lsm_rule *r = &ai_lsm_rules[i];

		if (r->kind != kind || r->op_type != op_type)
			continue;
		if (kind == AI_LSM_RULE_PID && r->pid == pid) {
			slot = r;
			break;
		}
		if (kind == AI_LSM_RULE_LABEL && r->label == label) {
			slot = r;
			break;
		}
		if (kind == AI_LSM_RULE_PATH && path_prefix &&
		    !strcmp(r->path_prefix, path_prefix)) {
			slot = r;
			break;
		}
	}
	if (!slot) {
		for (i = 0; i < AI_LSM_RULE_MAX; i++) {
			if (ai_lsm_rules[i].kind == AI_LSM_RULE_FREE) {
				slot = &ai_lsm_rules[i];
				added = true;
				break;
			}
		}
	}
	if (!slot) {
		spin_unlock_irqrestore(&ai_lsm_rule_lock, flags);
		return AI_ERR_MEMORY;
	}

	memset(slot, 0, sizeof(*slot));
	slot->kind = kind;
	slot->pid = pid;
	slot->label = label;
	slot->op_type = op_type;
	slot->deny = deny;
	if (path_prefix)
		strscpy(slot->path_prefix, path_prefix,
			sizeof(slot->path_prefix));
	strscpy(slot->detail, detail ? detail : "ai rule",
		sizeof(slot->detail));
	if (added)
		atomic_inc(&ai_lsm_nr_rules);
	if (added && kind == AI_LSM_RULE_PATH)
		atomic_inc(&ai_lsm_nr_path_rules);
	ai_lsm_policy_version++;
	spin_unlock_irqrestore(&ai_lsm_rule_lock, flags);

	ai_telemetry_lsm_policy_load(AI_LSM_NAME, ai_lsm_policy_version,
				     (u32)atomic_read(&ai_lsm_nr_rules) *
				     (u32)sizeof(struct ai_lsm_rule));
	return AI_OK;
}

int ai_lsm_rule_add(u32 pid, bool deny, const char *detail)
{
	if (!pid)
		return AI_ERR_INVALID_ARG;
	return ai_lsm_rule_add_internal(AI_LSM_RULE_PID, pid, 0,
					AI_LSM_OP_ANY, NULL, deny, detail);
}

int ai_lsm_rule_add_label(u8 label, u8 op_type, bool deny, const char *detail)
{
	if (!label || op_type >= AI_LSM_OP_MAX)
		return AI_ERR_INVALID_ARG;
	return ai_lsm_rule_add_internal(AI_LSM_RULE_LABEL, 0, label, op_type,
					NULL, deny, detail);
}

int ai_lsm_rule_add_path(const char *path_prefix, u8 op_type, bool deny,
			 const char *detail)
{
	if (!path_prefix || !path_prefix[0] ||
	    strlen(path_prefix) >= AI_LSM_PATH_PREFIX_LEN ||
	    op_type >= AI_LSM_OP_MAX)
		return AI_ERR_INVALID_ARG;
	return ai_lsm_rule_add_internal(AI_LSM_RULE_PATH, 0, 0, op_type,
					path_prefix, deny, detail);
}

int ai_lsm_rule_del(u32 pid)
{
	unsigned long flags;
	u32 removed = 0;
	int i;

	if (!pid)
		return AI_ERR_INVALID_ARG;

	spin_lock_irqsave(&ai_lsm_rule_lock, flags);
	for (i = 0; i < AI_LSM_RULE_MAX; i++) {
		if (ai_lsm_rules[i].kind == AI_LSM_RULE_PID &&
		    ai_lsm_rules[i].pid == pid) {
			memset(&ai_lsm_rules[i], 0, sizeof(ai_lsm_rules[i]));
			atomic_dec(&ai_lsm_nr_rules);
			removed++;
		}
	}
	ai_lsm_policy_version++;
	spin_unlock_irqrestore(&ai_lsm_rule_lock, flags);

	if (!removed)
		return AI_ERR_NOT_FOUND;

	ai_telemetry_lsm_policy_load(AI_LSM_NAME, ai_lsm_policy_version,
				     (u32)atomic_read(&ai_lsm_nr_rules) *
				     (u32)sizeof(struct ai_lsm_rule));
	return AI_OK;
}

int ai_lsm_rule_clear(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ai_lsm_rule_lock, flags);
	memset(ai_lsm_rules, 0, sizeof(ai_lsm_rules));
	atomic_set(&ai_lsm_nr_rules, 0);
	atomic_set(&ai_lsm_nr_path_rules, 0);
	ai_lsm_policy_version++;
	spin_unlock_irqrestore(&ai_lsm_rule_lock, flags);

	ai_telemetry_lsm_policy_load(AI_LSM_NAME, ai_lsm_policy_version, 0);
	return AI_OK;
}

/* ==================================================================
 * sec.lsm_override 执行档位（AIKernel 自家 LSM 的 enforce/observe）
 * observe（默认）：旧 pid 规则命中仅记录放行；enforce：命中拦截。
 * 仅作用于旧 pid 规则；label/path 规则是显式工作区策略，始终拦截。
 * 不覆盖上游 LSM 决策，仅切换 AIKernel 自家 LSM 的执行档位（参数名
 * 保持，描述如实）；默认 observe 与规则表初始为空共同保证零回归。
 * ================================================================== */
static bool ai_lsm_enforce_mode;

bool ai_lsm_enforce_get(void)
{
	return READ_ONCE(ai_lsm_enforce_mode);
}

int ai_lsm_enforce_set(bool on)
{
	WRITE_ONCE(ai_lsm_enforce_mode, on);
	pr_info("AIKernel: sec.lsm_override -> %s\n",
		on ? "enforce" : "observe");
	return AI_OK;
}

int ai_lsm_eval_anomaly(u32 pid, u8 *out_score)
{
	struct ai_lsm_model *m;
	unsigned long flags;
	u64 now = ktime_get_ns();

	if (!out_score)
		return AI_ERR_INVALID_ARG;

	spin_lock_irqsave(&ai_lsm_model_lock, flags);
	m = ai_lsm_model_get(pid, now, false);
	if (!m) {
		spin_unlock_irqrestore(&ai_lsm_model_lock, flags);
		return AI_ERR_NOT_FOUND;
	}
	*out_score = m->anomaly;
	spin_unlock_irqrestore(&ai_lsm_model_lock, flags);
	return AI_OK;
}

int ai_lsm_stats_read(char *buf, size_t len, size_t *out_len)
{
	size_t off = 0;
	int i;
	unsigned long flags;

	if (!buf || !out_len)
		return AI_ERR_INVALID_ARG;
	*out_len = 0;

	spin_lock_irqsave(&ai_lsm_model_lock, flags);
	off += scnprintf(buf + off, len - off,
			 "models:%d rules:%d version:%u\n",
			 AI_LSM_MODEL_SLOTS, AI_LSM_RULE_MAX,
			 READ_ONCE(ai_lsm_policy_version));
	for (i = 0; i < AI_LSM_MODEL_SLOTS && off < len; i++) {
		struct ai_lsm_model *m = &ai_lsm_models[i];

		if (!m->pid)
			continue;
		off += scnprintf(buf + off, len - off,
				 "%u open=%u/%u kill=%u/%u ptrace=%u capdeny=%u seccomp=%u anom=%u\n",
				 m->pid, m->count_open, m->base_open,
				 m->count_kill, m->base_kill, m->count_ptrace,
				 m->count_cap_deny, m->count_seccomp,
				 m->anomaly);
		if (off >= len)
			break;
	}
	spin_unlock_irqrestore(&ai_lsm_model_lock, flags);
	*out_len = off;
	return AI_OK;
}

/* ==================================================================
 * LSM 钩子（语义与原生一致：0=允许 -errno=拒绝；默认全放行）
 * ================================================================== */

/**
 * ai_lsm_file_path() - 取 file 的绝对路径（用于 path_prefix 规则/遥测）
 *
 * d_path() 失败时回退到 dentry 末节名（仍可做 object_label）。
 * 只在规则表非空时调用，避免热路径无谓的路径构造。
 */
static const char *ai_lsm_file_path(struct file *file, char *buf, size_t size)
{
	char *p;

	if (!file || !buf || !size)
		return NULL;
	p = d_path(&file->f_path, buf, (int)size);
	if (IS_ERR(p))
		return file->f_path.dentry ?
			(const char *)file->f_path.dentry->d_name.name : "?";
	return p;
}

/*
 * 旧 pid 规则在 file_open 上保持 sec.lsm_override 档位（observe 仅记录）；
 * ptrace/task_kill 历史上不看档位、命中即拦，此处保持原语义。
 * label/path 规则是显式工作区策略，任何 hook 都立即拦截。
 */
static bool ai_lsm_verdict_block(const struct ai_lsm_verdict *v,
				 bool honor_observe)
{
	if (!v->deny)
		return false;
	if (honor_observe && v->rule_kind == AI_LSM_RULE_PID &&
	    !ai_lsm_enforce_get())
		return false;
	return true;
}

static void ai_lsm_report(const char *hook, const char *object,
			  const char *av, const struct ai_lsm_verdict *v)
{
	char avbuf[AI_SEC_AV_LEN];

	scnprintf(avbuf, sizeof(avbuf), "ws=%u,%s", v->label, av);
	ai_telemetry_lsm_deny(hook, current->comm, object, avbuf, v->detail);
}

static void ai_lsm_report_observe(const char *hook, const char *object)
{
	ai_telemetry_lsm_check(hook, current->comm, object, 0,
			       "observe-allow");
}

static int ai_lsm_file_open(struct file *file)
{
	u32 pid;
	unsigned long flags;
	struct ai_lsm_model *m;
	u64 now;

	if (!current || !current->mm)
		return 0;

	pid = current->pid;

	/* 1) 决策表（pid/label/path 三维；旧 pid 规则看 sec.lsm_override） */
	if (ai_lsm_rules_active()) {
		char pathbuf[AI_SEC_PATH_LEN];
		const char *path;
		struct ai_lsm_verdict v;
		u8 label;

		if (ai_lsm_path_rules_active())
			path = ai_lsm_file_path(file, pathbuf, sizeof(pathbuf));
		else
			path = (const char *)file->f_path.dentry->d_name.name;
		label = ai_lsm_label_get(current);
		if (ai_lsm_rule_lookup(pid, label, path, AI_LSM_OP_FILE_OPEN,
				       &v)) {
			if (ai_lsm_verdict_block(&v, true)) {
				ai_lsm_report("file_open", path, "open", &v);
				return -EPERM;
			}
			if (v.deny)
				ai_lsm_report_observe("file_open", path);
		}
	}

	/* 2) 行为建模 */
	now = ktime_get_ns();
	spin_lock_irqsave(&ai_lsm_model_lock, flags);
	m = ai_lsm_model_get(pid, now, true);
	if (m)
		ai_lsm_model_update(m, now, 0);
	spin_unlock_irqrestore(&ai_lsm_model_lock, flags);

	/* 3) 全量检查记录（object_label=文件名末节，零脱敏） */
	ai_telemetry_lsm_check("file_open", current->comm,
			       file->f_path.dentry->d_name.name, 0, "allow");
	return 0;
}

static int ai_lsm_ptrace_access_check(struct task_struct *child,
				      unsigned int mode)
{
	u32 pid;
	unsigned long flags;
	struct ai_lsm_model *m;
	u64 now;

	if (!current || !current->mm)
		return 0;

	pid = current->pid;

	if (ai_lsm_rules_active()) {
		struct ai_lsm_verdict v;
		u8 label = ai_lsm_label_get(current);
		const char *av = (mode & PTRACE_MODE_ATTACH) ? "attach" : "read";

		if (ai_lsm_rule_lookup(pid, label, NULL, AI_LSM_OP_ANY, &v)) {
			if (ai_lsm_verdict_block(&v, false)) {
				ai_lsm_report("ptrace_access_check", child->comm,
					      av, &v);
				return -EPERM;
			}
			if (v.deny)
				ai_lsm_report_observe("ptrace_access_check",
						      child->comm);
		}
	}

	now = ktime_get_ns();
	spin_lock_irqsave(&ai_lsm_model_lock, flags);
	m = ai_lsm_model_get(pid, now, true);
	if (m)
		ai_lsm_model_update(m, now, 2);
	spin_unlock_irqrestore(&ai_lsm_model_lock, flags);

	ai_telemetry_lsm_check("ptrace_access_check", current->comm,
			       child->comm, 0, "allow");
	return 0;
}

static int ai_lsm_task_kill(struct task_struct *p, struct kernel_siginfo *info,
			    int sig, const struct cred *cred)
{
	u32 pid;
	char av[AI_SEC_AV_LEN];
	unsigned long flags;
	struct ai_lsm_model *m;
	u64 now;

	if (!current || !current->mm)
		return 0;

	pid = current->pid;
	scnprintf(av, sizeof(av), "sig=%d", sig);

	if (ai_lsm_rules_active()) {
		struct ai_lsm_verdict v;
		u8 label = ai_lsm_label_get(current);

		if (ai_lsm_rule_lookup(pid, label, NULL, AI_LSM_OP_ANY, &v)) {
			if (ai_lsm_verdict_block(&v, false)) {
				ai_lsm_report("task_kill", p->comm, av, &v);
				return -EPERM;
			}
			if (v.deny)
				ai_lsm_report_observe("task_kill", p->comm);
		}
	}

	now = ktime_get_ns();
	spin_lock_irqsave(&ai_lsm_model_lock, flags);
	m = ai_lsm_model_get(pid, now, true);
	if (m)
		ai_lsm_model_update(m, now, 1);
	spin_unlock_irqrestore(&ai_lsm_model_lock, flags);

	ai_telemetry_lsm_check("task_kill", current->comm, p->comm, 0, av);
	return 0;
}

/*
 * socket_connect（W80）：label/path/pid 规则按 AI_LSM_OP_SOCKET_CONNECT 裁决。
 * 仅检查 AF_INET/AF_INET6 —— 工作区"禁网"不波及 AF_UNIX（X11/dbus 等
 * 本地 IPC 仍可用），与 netns 方案的行为边界一致。
 */
static int ai_lsm_socket_connect(struct socket *sock, struct sockaddr *address,
				 int addrlen)
{
	struct ai_lsm_verdict v;
	char obj[AI_SEC_OBJ_LABEL_LEN];
	unsigned int family;
	u8 label;

	if (!ai_lsm_rules_active() || !current || !sock || !sock->ops)
		return 0;

	family = sock->ops->family;
	if (family != AF_INET && family != AF_INET6)
		return 0;

	label = ai_lsm_label_get(current);
	if (!ai_lsm_rule_lookup(current->pid, label, NULL,
				AI_LSM_OP_SOCKET_CONNECT, &v))
		return 0;

	if (address)
		scnprintf(obj, sizeof(obj), "%pISc", address);
	else
		scnprintf(obj, sizeof(obj), "af=%u", family);

	if (ai_lsm_verdict_block(&v, true)) {
		ai_lsm_report("socket_connect", obj, "connect", &v);
		return -EPERM;
	}
	if (v.deny)
		ai_lsm_report_observe("socket_connect", obj);
	return 0;
}

/*
 * socket_sendmsg（W80）：覆盖 UDP/DNS 等无 connect 的发送路径；
 * 仅 AF_INET/AF_INET6，理由同 socket_connect。
 */
static int ai_lsm_socket_sendmsg(struct socket *sock, struct msghdr *msg,
				 int size)
{
	struct ai_lsm_verdict v;
	char obj[AI_SEC_OBJ_LABEL_LEN];
	unsigned int family;
	u8 label;

	if (!ai_lsm_rules_active() || !current || !sock || !sock->ops)
		return 0;

	family = sock->ops->family;
	if (family != AF_INET && family != AF_INET6)
		return 0;

	label = ai_lsm_label_get(current);
	if (!ai_lsm_rule_lookup(current->pid, label, NULL,
				AI_LSM_OP_SOCKET_SENDMSG, &v))
		return 0;

	scnprintf(obj, sizeof(obj), "af=%u", family);
	if (ai_lsm_verdict_block(&v, true)) {
		ai_lsm_report("socket_sendmsg", obj, "sendmsg", &v);
		return -EPERM;
	}
	if (v.deny)
		ai_lsm_report_observe("socket_sendmsg", obj);
	return 0;
}

/*
 * file_permission（W80）：按 label + path_prefix 拦截越界读写。
 * 用 file_permission 而非 inode_permission，因为只有 file 携带 f_path，
 * 才能做路径前缀匹配；mask 归并为 READ/WRITE/EXEC 三类操作。
 */
static int ai_lsm_file_permission(struct file *file, int mask)
{
	struct ai_lsm_verdict v;
	char pathbuf[AI_SEC_PATH_LEN];
	const char *path, *av;
	u8 op, label;

	if (!ai_lsm_rules_active() || !current)
		return 0;

	if (mask & (MAY_WRITE | MAY_APPEND)) {
		op = AI_LSM_OP_FILE_WRITE;
		av = "write";
	} else if (mask & MAY_READ) {
		op = AI_LSM_OP_FILE_READ;
		av = "read";
	} else if (mask & MAY_EXEC) {
		op = AI_LSM_OP_FILE_EXEC;
		av = "exec";
	} else {
		return 0;
	}

	if (ai_lsm_path_rules_active())
		path = ai_lsm_file_path(file, pathbuf, sizeof(pathbuf));
	else if (file && file->f_path.dentry)
		path = (const char *)file->f_path.dentry->d_name.name;
	else
		path = "?";
	label = ai_lsm_label_get(current);
	if (!ai_lsm_rule_lookup(current->pid, label, path, op, &v))
		return 0;

	if (ai_lsm_verdict_block(&v, true)) {
		ai_lsm_report("file_permission", path, av, &v);
		return -EPERM;
	}
	if (v.deny)
		ai_lsm_report_observe("file_permission", path);
	return 0;
}

static const struct lsm_id ai_lsm_lsmid = {
	.name = AI_LSM_NAME,
	.id = AI_LSM_ID,
};

static struct security_hook_list ai_lsm_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(task_alloc, ai_lsm_task_alloc),
	LSM_HOOK_INIT(file_open, ai_lsm_file_open),
	LSM_HOOK_INIT(file_permission, ai_lsm_file_permission),
	LSM_HOOK_INIT(ptrace_access_check, ai_lsm_ptrace_access_check),
	LSM_HOOK_INIT(task_kill, ai_lsm_task_kill),
	LSM_HOOK_INIT(socket_connect, ai_lsm_socket_connect),
	LSM_HOOK_INIT(socket_sendmsg, ai_lsm_socket_sendmsg),
};

/* ==================================================================
 * ai_sec_* Hook（AI 决策接入点，空实现 = 原样放行）
 *
 * 注意：ai_sec_seccomp_hook 只在任务已挂 seccomp 过滤器时被
 * kernel/seccomp.c __seccomp_filter() 调用，且当前调用点不消费 action
 * 建议；它无法给任意任务安装过滤器（seccomp 设计上只允许进程自装/
 * clone 继承/同线程组 TSYNC）。因此它不是 sec.seccomp 参数的真实
 * 执行面，只作行为模型计数观测点。sec.seccomp 已降级 reserved。
 * ================================================================== */

void ai_sec_seccomp_hook(int syscall_nr, const struct seccomp_data *sd,
			 u32 *action)
{
	struct ai_lsm_model *m;
	unsigned long flags;
	u64 now;

	if (!current)
		return;

	now = ktime_get_ns();
	spin_lock_irqsave(&ai_lsm_model_lock, flags);
	m = ai_lsm_model_get(current->pid, now, true);
	if (m)
		ai_lsm_model_update(m, now, 4);
	spin_unlock_irqrestore(&ai_lsm_model_lock, flags);

	/* AI 建议规则为空：不改 action */
}

int ai_sec_cap_hook(const struct cred *cred, struct user_namespace *ns,
		    int cap, int ret)
{
	/* AI 风险评估为空：返回原结果，语义不变 */
	return ret;
}

void ai_sec_key_hook(const char *type, const char *desc, size_t plen,
		     u8 *strength)
{
	if (!strength)
		return;
	/* 启发式强度：载荷长度 + 描述长度（AI 推理后续替换） */
	if (plen < 8)
		*strength = 0;		/* 弱 */
	else if (plen < 16)
		*strength = 1;		/* 中 */
	else
		*strength = 2;		/* 强 */
}

void ai_sec_crypto_hook(const char **alg_name, u32 type, u32 mask)
{
	/* AI 负载选算法为空：不改算法名 */
}

void ai_sec_syscall_name(int nr, char *buf, size_t size)
{
	char sym[KSYM_NAME_LEN];
	const char *name = NULL;
	const char *p;

	if (!buf || !size)
		return;
	buf[0] = '\0';

	if (nr < 0 || !IS_ENABLED(CONFIG_KALLSYMS))
		goto fallback;

	if (!kallsyms_lookup((unsigned long)sys_call_table[nr], NULL, NULL,
			     NULL, sym))
		goto fallback;

	name = sym;
	if (strstarts(name, "__x64_sys_"))
		name += 10;
	else if (strstarts(name, "__ia32_sys_"))
		name += 11;
	else if (strstarts(name, "__sys_"))
		name += 6;
	else if (strstarts(name, "sys_"))
		name += 4;

	p = strchrnul(name, '.');
	strscpy(buf, name, min_t(size_t, p - name + 1, size));
	return;

fallback:
	scnprintf(buf, size, "sys_%d", nr);
}

/* ---- 工作区标签只读查询：/proc/ai/ws_labels（W80） ----
 *
 * 格式：<pid> <label> <comm>，仅列非 0 标签（0=无标签，无信息量）。
 * 未塞进 /proc/ai/control：后者是"每行一个参数 name/domain/min/max/
 * current/default"的固定格式（用户态按行解析），追加异形行会破坏既有
 * 解析器。故用独立 proc 文件；节点由 ai_procfs 创建，ai LSM 未启用时
 * 只是空列表。
 */
#if IS_ENABLED(CONFIG_PROC_FS) && IS_ENABLED(CONFIG_AIKERNEL_USRIFACE)
extern struct proc_dir_entry *ai_procfs_get_root(void);

static int ai_lsm_ws_labels_show(struct seq_file *m, void *v)
{
	struct task_struct *p, *t;

	rcu_read_lock();
	for_each_process(p) {
		for_each_thread(p, t) {
			u8 label = ai_lsm_label_get(t);

			if (label)
				seq_printf(m, "%u %u %s\n", t->pid, label,
					   t->comm);
		}
	}
	rcu_read_unlock();
	return 0;
}

static int __init ai_lsm_ws_labels_init(void)
{
	struct proc_dir_entry *root = ai_procfs_get_root();

	if (!root)
		return 0;	/* ai.enabled=0 或 usriface 未初始化 */
	proc_create_single("ws_labels", 0444, root, ai_lsm_ws_labels_show);
	return 0;
}
late_initcall(ai_lsm_ws_labels_init);

/* ==================================================================
 * 用户态规则注入面（B-117）：/proc/ai/lsm/rules
 *
 * 只对 root 开放（0600 + CAP_SYS_ADMIN）。整批原子生效：
 *   clear                              清空本批次暂存区（不动生效表）
 *   path <prefix> <op> <allow|deny>    路径前缀规则
 *   label <id> <op> <allow|deny>       工作区标签规则（id 1~255）
 *   label <pid> <label>                任务标签赋值（commit 时应用）
 *   pid <pid> <op> <allow|deny>        pid 规则（旧维度，受 observe 档位）
 *   commit                             用暂存区整体替换生效表
 *
 * 暂存区为全局单写者：第一条命令认领批次，commit/close 释放；未 commit
 * 直接 close = 丢弃。任何一行非法 → 整批拒绝、暂存区清空、批次标脏，
 * 需重新 clear 才能再 commit。容量沿用 AI_LSM_RULE_MAX（64 槽），超限
 * 整批返回 -ENOSPC，绝不静默截断。
 *
 * 生效表替换与既有 ai_lsm_rule_lock 共用，hook 匹配顺序/语义零改动
 * （pid > label > path_prefix 仍由 ai_lsm_rule_lookup 决定）。
 *
 * 操作名白名单：any（别名 test，W83 验收用）、open/file_open、
 * read/file_read、write/file_write、exec/file_exec、connect/
 * socket_connect、sendmsg/socket_sendmsg。所有数值仅接受十进制。
 * ================================================================== */

#define AI_LSM_RULES_WRITE_MAX	16384	/* 单次 write 上限 */
#define AI_LSM_RULES_READ_MAX	(20 * 1024)
#define AI_LSM_RULE_DETAIL	"procfs"

struct ai_lsm_label_assign {
	u32 pid;
	u8 label;
};

/* 批次暂存区（ai_lsm_batch_lock 保护；生效表另由 ai_lsm_rule_lock 保护） */
struct ai_lsm_batch {
	struct ai_lsm_rule rules[AI_LSM_RULE_MAX];
	u32 nr_rules;
	struct ai_lsm_label_assign labels[AI_LSM_RULE_MAX];
	u32 nr_labels;
	void *owner;		/* 批次属主（ai_lsm_rules_ctx *） */
	bool has_clear;		/* 本批次显式 clear 过 → commit 可清空生效表 */
	bool poisoned;		/* 批次已因非法行失败，需 clear 重来 */
};

static DEFINE_MUTEX(ai_lsm_batch_lock);
static struct ai_lsm_batch ai_lsm_batch;
static atomic_t ai_lsm_rejected_batches = ATOMIC_INIT(0);
static atomic_t ai_lsm_commit_count = ATOMIC_INIT(0);
static atomic_t ai_lsm_label_skipped = ATOMIC_INIT(0);
static atomic_t ai_lsm_last_commit_pid = ATOMIC_INIT(0);

struct ai_lsm_rules_ctx {
	bool owner;		/* 本打开文件持有批次 */
};

static const char *ai_lsm_op_name(u8 op)
{
	switch (op) {
	case AI_LSM_OP_ANY:
		return "any";
	case AI_LSM_OP_FILE_OPEN:
		return "file_open";
	case AI_LSM_OP_FILE_READ:
		return "file_read";
	case AI_LSM_OP_FILE_WRITE:
		return "file_write";
	case AI_LSM_OP_FILE_EXEC:
		return "file_exec";
	case AI_LSM_OP_SOCKET_CONNECT:
		return "socket_connect";
	case AI_LSM_OP_SOCKET_SENDMSG:
		return "socket_sendmsg";
	default:
		return "invalid";
	}
}

static int ai_lsm_op_parse(const char *s, u8 *op)
{
	if (!strcmp(s, "any") || !strcmp(s, "test"))
		*op = AI_LSM_OP_ANY;
	else if (!strcmp(s, "file_open") || !strcmp(s, "open"))
		*op = AI_LSM_OP_FILE_OPEN;
	else if (!strcmp(s, "file_read") || !strcmp(s, "read"))
		*op = AI_LSM_OP_FILE_READ;
	else if (!strcmp(s, "file_write") || !strcmp(s, "write"))
		*op = AI_LSM_OP_FILE_WRITE;
	else if (!strcmp(s, "file_exec") || !strcmp(s, "exec"))
		*op = AI_LSM_OP_FILE_EXEC;
	else if (!strcmp(s, "socket_connect") || !strcmp(s, "connect"))
		*op = AI_LSM_OP_SOCKET_CONNECT;
	else if (!strcmp(s, "socket_sendmsg") || !strcmp(s, "sendmsg"))
		*op = AI_LSM_OP_SOCKET_SENDMSG;
	else
		return -EINVAL;
	return 0;
}

static int ai_lsm_deny_parse(const char *s, bool *deny)
{
	if (!strcmp(s, "allow"))
		*deny = false;
	else if (!strcmp(s, "deny"))
		*deny = true;
	else
		return -EINVAL;
	return 0;
}

/* 严格十进制（无符号、无 0x、无 +/-、拒绝溢出） */
static int ai_lsm_u32_parse(const char *s, u32 *out)
{
	u64 v = 0;

	if (!s || !*s)
		return -EINVAL;
	for (; *s; s++) {
		if (*s < '0' || *s > '9')
			return -EINVAL;
		v = v * 10 + (u32)(*s - '0');
		if (v > 0xffffffffULL)
			return -EINVAL;
	}
	*out = (u32)v;
	return 0;
}

/* 取下一个空格/制表符分隔的 token（就地 NUL 截断） */
static char *ai_lsm_next_tok(char **pp)
{
	char *p = *pp, *start;

	while (*p == ' ' || *p == '\t' || *p == '\r')
		p++;
	if (!*p) {
		*pp = p;
		return NULL;
	}
	start = p;
	while (*p && *p != ' ' && *p != '\t' && *p != '\r')
		p++;
	if (*p)
		*p++ = '\0';
	*pp = p;
	return start;
}

static void ai_lsm_batch_clear_staged(void)
{
	memset(ai_lsm_batch.rules, 0, sizeof(ai_lsm_batch.rules));
	memset(ai_lsm_batch.labels, 0, sizeof(ai_lsm_batch.labels));
	ai_lsm_batch.nr_rules = 0;
	ai_lsm_batch.nr_labels = 0;
}

static void ai_lsm_batch_reset(void)
{
	ai_lsm_batch_clear_staged();
	ai_lsm_batch.owner = NULL;
	ai_lsm_batch.has_clear = false;
	ai_lsm_batch.poisoned = false;
}

static int ai_lsm_batch_claim(struct ai_lsm_rules_ctx *ctx)
{
	if (ai_lsm_batch.owner == ctx)
		return 0;
	if (ai_lsm_batch.owner)
		return -EBUSY;
	ai_lsm_batch_reset();
	ai_lsm_batch.owner = ctx;
	ctx->owner = true;
	return 0;
}

static void ai_lsm_batch_release(struct ai_lsm_rules_ctx *ctx)
{
	ai_lsm_batch_reset();
	if (ctx)
		ctx->owner = false;
}

/* 非法行：整批拒绝并清空暂存（保持属主与 poisoned，commit 亦拒绝） */
static int ai_lsm_batch_fail(struct ai_lsm_rules_ctx *ctx)
{
	atomic_inc(&ai_lsm_rejected_batches);
	if (ai_lsm_batch.owner == ctx) {
		ai_lsm_batch_clear_staged();
		ai_lsm_batch.has_clear = false;
		ai_lsm_batch.poisoned = true;
	}
	return -EINVAL;
}

/* 暂存一条规则：与 ai_lsm_rule_add_internal 相同的"同键同 op 覆盖"语义 */
static int ai_lsm_batch_stage_rule(u8 kind, u32 pid, u8 label, u8 op,
				   bool deny, const char *prefix)
{
	struct ai_lsm_rule *r = NULL;
	u32 i;

	for (i = 0; i < ai_lsm_batch.nr_rules; i++) {
		struct ai_lsm_rule *cur = &ai_lsm_batch.rules[i];

		if (cur->kind != kind || cur->op_type != op)
			continue;
		if (kind == AI_LSM_RULE_PID && cur->pid == pid)
			r = cur;
		else if (kind == AI_LSM_RULE_LABEL && cur->label == label)
			r = cur;
		else if (kind == AI_LSM_RULE_PATH && prefix &&
			 !strcmp(cur->path_prefix, prefix))
			r = cur;
		if (r)
			break;
	}
	if (!r) {
		if (ai_lsm_batch.nr_rules >= AI_LSM_RULE_MAX)
			return -ENOSPC;
		r = &ai_lsm_batch.rules[ai_lsm_batch.nr_rules++];
	}
	memset(r, 0, sizeof(*r));
	r->kind = kind;
	r->pid = pid;
	r->label = label;
	r->op_type = op;
	r->deny = deny;
	if (prefix)
		strscpy(r->path_prefix, prefix, sizeof(r->path_prefix));
	strscpy(r->detail, AI_LSM_RULE_DETAIL, sizeof(r->detail));
	return 0;
}

static int ai_lsm_batch_stage_label(u32 pid, u8 label)
{
	u32 i;

	for (i = 0; i < ai_lsm_batch.nr_labels; i++) {
		if (ai_lsm_batch.labels[i].pid == pid) {
			ai_lsm_batch.labels[i].label = label;
			return 0;
		}
	}
	if (ai_lsm_batch.nr_labels >= AI_LSM_RULE_MAX)
		return -ENOSPC;
	ai_lsm_batch.labels[ai_lsm_batch.nr_labels].pid = pid;
	ai_lsm_batch.labels[ai_lsm_batch.nr_labels].label = label;
	ai_lsm_batch.nr_labels++;
	return 0;
}

/* commit：整表替换 + 应用任务标签。调用者持 ai_lsm_batch_lock。 */
static int ai_lsm_batch_commit(struct ai_lsm_rules_ctx *ctx)
{
	struct ai_lsm_batch *b = &ai_lsm_batch;
	unsigned long flags;
	u32 i, nr = 0, npath = 0, nlabel = 0, npid = 0;
	u32 applied = 0, skipped = 0, version = 0;
	bool replace;
	int rc;

	if (b->owner != ctx)
		return -EINVAL;
	if (b->poisoned) {
		ai_lsm_batch_release(ctx);
		atomic_inc(&ai_lsm_rejected_batches);
		return -EINVAL;
	}

	/* 有规则或 clear 过 → 换表；只暂存标签 → 只应用标签 */
	replace = b->has_clear || b->nr_rules > 0;
	if (!replace && !b->nr_labels)
		return -EINVAL;

	if (replace) {
		spin_lock_irqsave(&ai_lsm_rule_lock, flags);
		memcpy(ai_lsm_rules, b->rules, sizeof(ai_lsm_rules));
		for (i = 0; i < AI_LSM_RULE_MAX; i++) {
			switch (ai_lsm_rules[i].kind) {
			case AI_LSM_RULE_PATH:
				npath++;
				nr++;
				break;
			case AI_LSM_RULE_LABEL:
				nlabel++;
				nr++;
				break;
			case AI_LSM_RULE_PID:
				npid++;
				nr++;
				break;
			default:
				break;
			}
		}
		atomic_set(&ai_lsm_nr_rules, (int)nr);
		atomic_set(&ai_lsm_nr_path_rules, (int)npath);
		version = ++ai_lsm_policy_version;
		spin_unlock_irqrestore(&ai_lsm_rule_lock, flags);
		ai_telemetry_lsm_policy_load(AI_LSM_NAME, version,
					     nr * (u32)sizeof(struct ai_lsm_rule));
	}

	/* 任务标签赋值：目标可能在 stage 与 commit 之间消失，跳过并计数 */
	for (i = 0; i < b->nr_labels; i++) {
		rc = ai_lsm_ws_label_set((s32)b->labels[i].pid,
					 b->labels[i].label);
		if (rc == AI_OK)
			applied++;
		else
			skipped++;
	}
	if (skipped)
		atomic_add((int)skipped, &ai_lsm_label_skipped);

	atomic_inc(&ai_lsm_commit_count);
	atomic_set(&ai_lsm_last_commit_pid, current->pid);
	/* 审计：只记规则数/来源 pid，不打印路径与规则内容 */
	pr_info("AIKernel: ai_lsm rules commit: %u effective (%u path, %u label, %u pid), task_labels=%u applied=%u skipped=%u, source_pid=%d\n",
		replace ? nr : ai_lsm_rule_count(), npath, nlabel, npid,
		b->nr_labels, applied, skipped, current->pid);

	ai_lsm_batch_release(ctx);
	return 0;
}

/* 解析并执行一行；调用者持 ai_lsm_batch_lock */
static int ai_lsm_rules_line(struct ai_lsm_rules_ctx *ctx, const char *cmd,
			     char **cursor)
{
	char *t1 = ai_lsm_next_tok(cursor);
	char *t2 = ai_lsm_next_tok(cursor);
	char *t3 = ai_lsm_next_tok(cursor);
	char *t4 = ai_lsm_next_tok(cursor);
	bool deny = false;
	u32 v1 = 0, v2 = 0;
	u8 op = AI_LSM_OP_ANY;
	int rc;

	if (!strcmp(cmd, "clear")) {
		if (t1)
			return ai_lsm_batch_fail(ctx);
		rc = ai_lsm_batch_claim(ctx);
		if (rc)
			return rc;
		ai_lsm_batch_clear_staged();
		ai_lsm_batch.poisoned = false;
		ai_lsm_batch.has_clear = true;
		return 0;
	}

	if (!strcmp(cmd, "commit")) {
		if (t1)
			return ai_lsm_batch_fail(ctx);
		rc = ai_lsm_batch_claim(ctx);
		if (rc)
			return rc;
		return ai_lsm_batch_commit(ctx);
	}

	if (!strcmp(cmd, "path")) {
		if (!t1 || !t2 || !t3 || t4)
			return ai_lsm_batch_fail(ctx);
		if (t1[0] != '/' || strlen(t1) >= AI_LSM_PATH_PREFIX_LEN)
			return ai_lsm_batch_fail(ctx);
		if (ai_lsm_op_parse(t2, &op) || ai_lsm_deny_parse(t3, &deny))
			return ai_lsm_batch_fail(ctx);
		rc = ai_lsm_batch_claim(ctx);
		if (rc)
			return rc;
		rc = ai_lsm_batch_stage_rule(AI_LSM_RULE_PATH, 0, 0, op,
					     deny, t1);
		if (rc) {
			ai_lsm_batch_fail(ctx);
			return rc;
		}
		return 0;
	}

	if (!strcmp(cmd, "pid")) {
		if (!t1 || !t2 || !t3 || t4)
			return ai_lsm_batch_fail(ctx);
		if (ai_lsm_u32_parse(t1, &v1) || !v1 || v1 > 0x7fffffffU)
			return ai_lsm_batch_fail(ctx);
		if (ai_lsm_op_parse(t2, &op) || ai_lsm_deny_parse(t3, &deny))
			return ai_lsm_batch_fail(ctx);
		rc = ai_lsm_batch_claim(ctx);
		if (rc)
			return rc;
		rc = ai_lsm_batch_stage_rule(AI_LSM_RULE_PID, v1, 0, op,
					     deny, NULL);
		if (rc) {
			ai_lsm_batch_fail(ctx);
			return rc;
		}
		return 0;
	}

	if (!strcmp(cmd, "label")) {
		/* 3 段：label <pid> <label> —— 任务标签赋值 */
		if (t1 && t2 && !t3) {
			if (ai_lsm_u32_parse(t1, &v1) || !v1 ||
			    v1 > 0x7fffffffU)
				return ai_lsm_batch_fail(ctx);
			if (ai_lsm_u32_parse(t2, &v2) ||
			    v2 > AI_LSM_LABEL_MAX)
				return ai_lsm_batch_fail(ctx);
			rc = ai_lsm_batch_claim(ctx);
			if (rc)
				return rc;
			rc = ai_lsm_batch_stage_label(v1, (u8)v2);
			if (rc) {
				ai_lsm_batch_fail(ctx);
				return rc;
			}
			return 0;
		}
		/* 4 段：label <id> <op> <allow|deny> —— 标签规则 */
		if (t1 && t2 && t3 && !t4) {
			if (ai_lsm_u32_parse(t1, &v1) || !v1 ||
			    v1 > AI_LSM_LABEL_MAX)
				return ai_lsm_batch_fail(ctx);
			if (ai_lsm_op_parse(t2, &op) ||
			    ai_lsm_deny_parse(t3, &deny))
				return ai_lsm_batch_fail(ctx);
			rc = ai_lsm_batch_claim(ctx);
			if (rc)
				return rc;
			rc = ai_lsm_batch_stage_rule(AI_LSM_RULE_LABEL, 0,
						     (u8)v1, op, deny, NULL);
			if (rc) {
				ai_lsm_batch_fail(ctx);
				return rc;
			}
			return 0;
		}
		return ai_lsm_batch_fail(ctx);
	}

	return ai_lsm_batch_fail(ctx);
}

static ssize_t ai_lsm_rules_write(struct file *file, const char __user *ubuf,
				  size_t count, loff_t *ppos)
{
	struct ai_lsm_rules_ctx *ctx = file->private_data;
	char *buf, *p;
	int rc = 0;

	/* 总闸关闭：明确的"未启用"语义，不改任何状态 */
	if (!ai_startup_get_enabled())
		return -ENODEV;
	if (!ctx)
		return -EINVAL;
	if (!count)
		return 0;
	if (count > AI_LSM_RULES_WRITE_MAX)
		return -E2BIG;

	buf = kzalloc(count + 1, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	if (copy_from_user(buf, ubuf, count)) {
		kfree(buf);
		return -EFAULT;
	}

	mutex_lock(&ai_lsm_batch_lock);
	for (p = buf; p && *p; ) {
		char *line = p, *nl = strchr(p, '\n'), *cursor = line, *cmd;

		if (nl) {
			*nl = '\0';
			p = nl + 1;
		} else {
			p = NULL;
		}
		cmd = ai_lsm_next_tok(&cursor);
		if (!cmd || cmd[0] == '#')
			continue;	/* 空行/注释（读回格式可回灌） */
		rc = ai_lsm_rules_line(ctx, cmd, &cursor);
		if (rc)
			break;
	}
	mutex_unlock(&ai_lsm_batch_lock);

	kfree(buf);
	return rc ? rc : (ssize_t)count;
}

static size_t ai_lsm_rules_format(char *buf, size_t cap, bool enabled)
{
	struct ai_lsm_rule *snap = NULL;
	struct ai_lsm_rule *staged = NULL;
	struct ai_lsm_label_assign *labels = NULL;
	u32 i, nr, npath, nlabel, npid, staged_nr, label_nr;
	bool active = ai_lsm_blob_ready, has_clear, poisoned, owner;
	unsigned long flags;
	size_t off = 0;

	off += scnprintf(buf + off, cap - off, "# ai_lsm rules v1\n");
	if (!enabled) {
		off += scnprintf(buf + off, cap - off,
				 "state: disabled\n# AI master switch (ai.enabled) is off; rule injection is not enabled.\n");
		return off;
	}
	off += scnprintf(buf + off, cap - off, "state: enabled\n");

	snap = kmalloc_array(AI_LSM_RULE_MAX, sizeof(*snap), GFP_KERNEL);
	staged = kmalloc_array(AI_LSM_RULE_MAX, sizeof(*staged), GFP_KERNEL);
	labels = kmalloc_array(AI_LSM_RULE_MAX, sizeof(*labels), GFP_KERNEL);
	if (!snap || !staged || !labels) {
		off += scnprintf(buf + off, cap - off,
				 "# snapshot allocation failed\n");
		goto out;
	}

	spin_lock_irqsave(&ai_lsm_rule_lock, flags);
	memcpy(snap, ai_lsm_rules, sizeof(ai_lsm_rules));
	spin_unlock_irqrestore(&ai_lsm_rule_lock, flags);
	nr = 0;
	npath = 0;
	nlabel = 0;
	npid = 0;
	for (i = 0; i < AI_LSM_RULE_MAX; i++) {
		switch (snap[i].kind) {
		case AI_LSM_RULE_PATH:
			npath++;
			nr++;
			break;
		case AI_LSM_RULE_LABEL:
			nlabel++;
			nr++;
			break;
		case AI_LSM_RULE_PID:
			npid++;
			nr++;
			break;
		default:
			break;
		}
	}

	mutex_lock(&ai_lsm_batch_lock);
	staged_nr = ai_lsm_batch.nr_rules;
	label_nr = ai_lsm_batch.nr_labels;
	memcpy(staged, ai_lsm_batch.rules, sizeof(ai_lsm_batch.rules));
	memcpy(labels, ai_lsm_batch.labels, sizeof(ai_lsm_batch.labels));
	has_clear = ai_lsm_batch.has_clear;
	poisoned = ai_lsm_batch.poisoned;
	owner = ai_lsm_batch.owner != NULL;
	mutex_unlock(&ai_lsm_batch_lock);

	off += scnprintf(buf + off, cap - off, "lsm: %s\n",
			 active ? "active" : "inactive");
	off += scnprintf(buf + off, cap - off, "version: %u\n",
			 READ_ONCE(ai_lsm_policy_version));
	off += scnprintf(buf + off, cap - off,
			 "effective: %u/%d path=%u label=%u pid=%u\n",
			 nr, AI_LSM_RULE_MAX, npath, nlabel, npid);
	off += scnprintf(buf + off, cap - off,
			 "staged: %u/%d task_labels=%u owner=%s clear=%s%s\n",
			 staged_nr, AI_LSM_RULE_MAX, label_nr,
			 owner ? "yes" : "no", has_clear ? "yes" : "no",
			 poisoned ? " poisoned" : "");
	off += scnprintf(buf + off, cap - off, "rejected: %d\n",
			 atomic_read(&ai_lsm_rejected_batches));
	off += scnprintf(buf + off, cap - off, "commits: %d\n",
			 atomic_read(&ai_lsm_commit_count));
	off += scnprintf(buf + off, cap - off, "label_skipped: %d\n",
			 atomic_read(&ai_lsm_label_skipped));
	off += scnprintf(buf + off, cap - off, "last_commit_pid: %d\n",
			 atomic_read(&ai_lsm_last_commit_pid));

	off += scnprintf(buf + off, cap - off, "# effective\n");
	for (i = 0; i < AI_LSM_RULE_MAX && off < cap; i++) {
		const struct ai_lsm_rule *r = &snap[i];
		const char *op = ai_lsm_op_name(r->op_type);
		const char *verdict = r->deny ? "deny" : "allow";

		if (r->kind == AI_LSM_RULE_PATH)
			off += scnprintf(buf + off, cap - off,
					 "path %s %s %s\n", r->path_prefix,
					 op, verdict);
		else if (r->kind == AI_LSM_RULE_LABEL)
			off += scnprintf(buf + off, cap - off,
					 "label %u %s %s\n", r->label, op,
					 verdict);
		else if (r->kind == AI_LSM_RULE_PID)
			off += scnprintf(buf + off, cap - off,
					 "pid %u %s %s\n", r->pid, op,
					 verdict);
	}

	off += scnprintf(buf + off, cap - off, "# staged\n");
	for (i = 0; i < staged_nr && off < cap; i++) {
		const struct ai_lsm_rule *r = &staged[i];
		const char *op = ai_lsm_op_name(r->op_type);
		const char *verdict = r->deny ? "deny" : "allow";

		if (r->kind == AI_LSM_RULE_PATH)
			off += scnprintf(buf + off, cap - off,
					 "path %s %s %s\n", r->path_prefix,
					 op, verdict);
		else if (r->kind == AI_LSM_RULE_LABEL)
			off += scnprintf(buf + off, cap - off,
					 "label %u %s %s\n", r->label, op,
					 verdict);
		else if (r->kind == AI_LSM_RULE_PID)
			off += scnprintf(buf + off, cap - off,
					 "pid %u %s %s\n", r->pid, op,
					 verdict);
	}
	for (i = 0; i < label_nr && off < cap; i++)
		off += scnprintf(buf + off, cap - off, "label %u %u\n",
				 labels[i].pid, labels[i].label);

out:
	kfree(snap);
	kfree(staged);
	kfree(labels);
	return off;
}

static ssize_t ai_lsm_rules_read(struct file *file, char __user *ubuf,
				 size_t count, loff_t *ppos)
{
	char *buf;
	size_t len;
	ssize_t ret;

	if (!count)
		return 0;
	buf = kmalloc(AI_LSM_RULES_READ_MAX, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	len = ai_lsm_rules_format(buf, AI_LSM_RULES_READ_MAX,
				  ai_startup_get_enabled());
	ret = simple_read_from_buffer(ubuf, count, ppos, buf, len);
	kfree(buf);
	return ret;
}

static int ai_lsm_rules_open(struct inode *inode, struct file *file)
{
	struct ai_lsm_rules_ctx *ctx;

	/* 只对 root（CAP_SYS_ADMIN）开放 */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	file->private_data = ctx;
	return 0;
}

static int ai_lsm_rules_release(struct inode *inode, struct file *file)
{
	struct ai_lsm_rules_ctx *ctx = file->private_data;

	if (ctx) {
		if (ctx->owner) {
			mutex_lock(&ai_lsm_batch_lock);
			if (ai_lsm_batch.owner == ctx)
				ai_lsm_batch_release(ctx);
			mutex_unlock(&ai_lsm_batch_lock);
		}
		kfree(ctx);
		file->private_data = NULL;
	}
	return 0;
}

static const struct proc_ops ai_lsm_rules_ops = {
	.proc_open	= ai_lsm_rules_open,
	.proc_read	= ai_lsm_rules_read,
	.proc_write	= ai_lsm_rules_write,
	.proc_release	= ai_lsm_rules_release,
};

static int __init ai_lsm_rules_init(void)
{
	struct proc_dir_entry *root = ai_procfs_get_root();
	struct proc_dir_entry *dir;

	if (!root)
		return 0;	/* ai.enabled=0 或 usriface 未初始化 */
	dir = proc_mkdir("lsm", root);
	if (!dir)
		return 0;
	if (!proc_create("rules", 0600, dir, &ai_lsm_rules_ops)) {
		pr_warn("AIKernel: /proc/ai/lsm/rules create failed\n");
		return 0;
	}
	pr_info("AIKernel: /proc/ai/lsm/rules ready (root-only rule injection)\n");
	return 0;
}
late_initcall(ai_lsm_rules_init);
#endif /* CONFIG_PROC_FS && CONFIG_AIKERNEL_USRIFACE */

/* ==================================================================
 * LSM 注册（可插拔：默认不在 CONFIG_LSM 列表 → 运行时禁用 → 零影响；
 * lsm=ai,... 启动参数显式启用）
 * ================================================================== */

static int __init ai_lsm_init(void)
{
	/* 可控制参数表（数据计划 20.3 安全域）已移至 ai_sec_control_init()
	 * （late_initcall）：DEFINE_LSM init 仅在 lsm= 启用 'ai' 时执行，
	 * 默认 boot 不注册会导致 control 表缺 sec.* —— 与 LSM 启用状态解耦 */
	ai_lsm_blob_ready = true;
	pr_info("AIKernel: AI LSM (name=%s id=%d) registered, %d model slots, %d rule slots, ws_label=on\n",
		AI_LSM_NAME, AI_LSM_ID, AI_LSM_MODEL_SLOTS, AI_LSM_RULE_MAX);
	security_add_hooks(ai_lsm_hooks, ARRAY_SIZE(ai_lsm_hooks), &ai_lsm_lsmid);
	return 0;
}

DEFINE_LSM(ai) = {
	.name = AI_LSM_NAME,
	.init = ai_lsm_init,
	.blobs = &ai_lsm_blob_sizes,
};

/* ---- sec.seccomp：W49 如实降级为 reserved（无 AI_CTRL_F_REAL） ----
 *
 * 降级理由（技术不可安全实现，非偷懒）：
 *   1) seccomp 过滤器只能由目标任务自己安装（或 clone 继承、同线程组
 *      TSYNC）。内核对已存在的外部任务强制安装过滤器没有安全路径：
 *      tsk->seccomp 是 kernel/seccomp.c 私有状态，绕过 seccomp_attach_
 *      filter() 直接改 mode/filter 会破坏引用计数与同步语义。
 *   2) 本参数 ABI 只有 pid + 0/1，没有 syscall 白名单/动作语义；把
 *      0/1 解释为"拒绝全部系统调用"会让目标任务立即不可用，不是可用
 *      的 seccomp 配置。
 *   3) 旧实现把 1 映射为 ai_lsm 规则表 deny 项，但：
 *      - 它拦的是 file_open/ptrace/task_kill，不是系统调用；
 *      - AIKernel 自家 LSM 默认不在 CONFIG_LSM 列表（需 lsm=ai 显式
 *        启用），生产 VM 实测 /sys/kernel/security/lsm 无 ai，规则永不
 *        被消费；
 *      - 即使启用，deny 还要配合 sec.lsm_override=enforce 才拦截。
 *      即"标 real 但空转"，违反诚实性原则。
 *   4) 若改为默认启用自家的 LSM 来让规则生效，会把一个自定义 LSM 的
 *      file_open 热路径钩子+遥测推上生产全量文件打开路径，属于超出
 *      A/B 内核升级范围的安全姿态变更，风险不可接受。
 *
 * 因此本参数保留 TASK 作用域（写入值仍记录、/proc/ai/control 明确显示
 * [reserved]），但不再产生任何规则注入/内核行为。真正的 seccomp 基线
 * 应由用户态在 exec 前对子进程自装过滤器（W51 工具面另行设计）。
 * ai_lsm 规则表本身保留：它是 lsm=ai 启用时的合法决策面，与参数解耦。
 */

/* ---- sec.lsm_override / sec.audit 立即生效参数 ---- */
static int ai_sec_lsm_override_apply(struct ai_control_param *p, s32 pid,
				     s64 value, s64 *eff)
{
	if (value != 0 && value != 1)
		return AI_ERR_INVALID_ARG;
	ai_lsm_enforce_set(value == 1);
	*eff = value;
	return AI_OK;
}

static int ai_sec_audit_apply(struct ai_control_param *p, s32 pid,
			      s64 value, s64 *eff)
{
	if (value != 0 && value != 1)
		return AI_ERR_INVALID_ARG;
	ai_audit_capture_enable(value == 1);
	*eff = value;
	return AI_OK;
}

/*
 * sec.ws_label（W80）：per-task 工作区标签，ACT data[0]=pid、data[1]=label。
 * 0~255 由控制表硬范围保证；label=0 清除标签。
 * 标志说明：
 *   TASK  —— data[0]=pid / data[1]=值（与 sched.nice 同约定）；
 *   EVENT —— 控制表 for TASK 参数的快路径会按"全局 cur"去重，同一 label
 *            写给不同 pid 时会被误判为同值跳过；EVENT 保证每次都执行；
 *   IDENT —— label 是标识符不是幅度，必须跳过 ai_policy_safety 的
 *            "相对当前值 ±max_impact%" 限幅（否则 0→200 会被砍到 127）。
 */
static int ai_sec_ws_label_apply(struct ai_control_param *p, s32 pid,
				 s64 value, s64 *eff)
{
	int rc;

	rc = ai_lsm_ws_label_set(pid, (u8)value);
	if (rc != AI_OK)
		return rc;
	*eff = value;
	return AI_OK;
}

/* ---- 可控制参数表（数据计划 20.3 安全域）：全部立即生效 ----
 * 独立 late_initcall：不依赖 lsm= 启用 'ai'，control 表 23 参数全量可见；
 * lsm=ai 双启用时安全（本处为唯一注册点，无重名冲突）。
 * sec.audit 默认 1（采集默认开，与既有行为一致）。 */
static int __init ai_sec_control_init(void)
{
	ai_control_register("sec.lsm_override", AI_POLICY_DOMAIN_SECURITY,
			    AI_CTRL_F_REAL, 0, 1, 0,
			    ai_sec_lsm_override_apply);
	/* W49：诚实降级 reserved —— 无 REAL、无 apply，只保留 TASK 作用域
	 * 记录写入值；/proc/ai/control 显示 [reserved]。详见上文长注释。 */
	ai_control_register("sec.seccomp", AI_POLICY_DOMAIN_SECURITY,
			    AI_CTRL_F_TASK, 0, 1, 0, NULL);
	ai_control_register("sec.audit", AI_POLICY_DOMAIN_SECURITY,
			    AI_CTRL_F_REAL, 0, 1, 1, ai_sec_audit_apply);
	/* W80：per-task 工作区标签（0=无标签）；见 ai_sec_ws_label_apply 注释 */
	ai_control_register("sec.ws_label", AI_POLICY_DOMAIN_SECURITY,
			    AI_CTRL_F_REAL | AI_CTRL_F_TASK | AI_CTRL_F_EVENT |
			    AI_CTRL_F_IDENT, 0, AI_LSM_LABEL_MAX, 0,
			    ai_sec_ws_label_apply);
	return 0;
}
late_initcall(ai_sec_control_init);
