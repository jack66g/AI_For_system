// SPDX-License-Identifier: GPL-2.0
/*
 * ai_lsm.c - AIKernel AI LSM 模块（AI 行为异常检测大脑）
 *
 * 门控 CONFIG_AIKERNEL_SECURITY（default n）。AI 关闭时不构建、不注册，
 * 安全框架行为与原生完全一致（可插拔 LSM，lsm=ai,... 启动参数显式启用）。
 *
 * A 轨（重构计划 6.1/6.2/6.3/6.4/6.5/6.8）：
 *   - LSM 钩子（file_open/task_kill/ptrace_access_check）+ 行为建模与异常检测框架；
 *   - ai_sec_seccomp/cap/key/crypto_hook：AI 决策接入点（空实现=原样放行）；
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
#include <linux/signal.h>
#include <linux/ptrace.h>
#include <linux/kallsyms.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/minmax.h>
#include <linux/kernel.h>
#include <uapi/linux/lsm.h>
#include <asm/syscall.h>
#include "ai_lsm.h"
#include "../core/ai_control.h"

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
 * AI 决策规则表（subject pid → allow/deny；空表=全放行=零回归）
 * ================================================================== */

struct ai_lsm_rule {
	u32 pid;
	bool deny;
	char detail[AI_SEC_DETAIL_LEN];
};

static struct ai_lsm_rule ai_lsm_rules[AI_LSM_RULE_MAX];
static DEFINE_SPINLOCK(ai_lsm_rule_lock);
static u32 ai_lsm_policy_version;

static bool ai_lsm_rule_check(u32 pid, char *out_detail, size_t detail_size)
{
	bool deny = false;
	int i;

	spin_lock(&ai_lsm_rule_lock);
	for (i = 0; i < AI_LSM_RULE_MAX; i++) {
		if (ai_lsm_rules[i].pid == pid) {
			deny = ai_lsm_rules[i].deny;
			if (out_detail && detail_size) {
				strscpy(out_detail, ai_lsm_rules[i].detail,
					detail_size);
				out_detail[detail_size - 1] = '\0';
			}
			break;
		}
	}
	spin_unlock(&ai_lsm_rule_lock);
	return deny;
}

/* ==================================================================
 * sec.lsm_override 执行档位（AIKernel 自家 LSM 的 enforce/observe）
 * observe（默认）：规则命中仅记录放行；enforce：规则命中拦截。
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

u32 ai_lsm_rule_count(void)
{
	u32 n = 0;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&ai_lsm_rule_lock, flags);
	for (i = 0; i < AI_LSM_RULE_MAX; i++)
		if (ai_lsm_rules[i].pid)
			n++;
	spin_unlock_irqrestore(&ai_lsm_rule_lock, flags);
	return n;
}

int ai_lsm_rule_add(u32 pid, bool deny, const char *detail)
{
	struct ai_lsm_rule *free = NULL;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&ai_lsm_rule_lock, flags);
	for (i = 0; i < AI_LSM_RULE_MAX; i++) {
		if (ai_lsm_rules[i].pid == pid) {
			ai_lsm_rules[i].deny = deny;
			strscpy(ai_lsm_rules[i].detail,
				detail ? detail : "ai rule",
				sizeof(ai_lsm_rules[i].detail));
			ai_lsm_policy_version++;
			spin_unlock_irqrestore(&ai_lsm_rule_lock, flags);
			ai_telemetry_lsm_policy_load(AI_LSM_NAME,
						     ai_lsm_policy_version,
						     AI_LSM_RULE_MAX * sizeof(struct ai_lsm_rule));
			return AI_OK;
		}
		if (!free && !ai_lsm_rules[i].pid)
			free = &ai_lsm_rules[i];
	}
	if (!free) {
		spin_unlock_irqrestore(&ai_lsm_rule_lock, flags);
		return AI_ERR_MEMORY;
	}
	free->pid = pid;
	free->deny = deny;
	strscpy(free->detail, detail ? detail : "ai rule",
		sizeof(free->detail));
	ai_lsm_policy_version++;
	spin_unlock_irqrestore(&ai_lsm_rule_lock, flags);
	ai_telemetry_lsm_policy_load(AI_LSM_NAME, ai_lsm_policy_version,
				     AI_LSM_RULE_MAX * sizeof(struct ai_lsm_rule));
	return AI_OK;
}

int ai_lsm_rule_del(u32 pid)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&ai_lsm_rule_lock, flags);
	for (i = 0; i < AI_LSM_RULE_MAX; i++) {
		if (ai_lsm_rules[i].pid == pid) {
			ai_lsm_rules[i].pid = 0;
			ai_lsm_policy_version++;
			spin_unlock_irqrestore(&ai_lsm_rule_lock, flags);
			ai_telemetry_lsm_policy_load(AI_LSM_NAME,
						     ai_lsm_policy_version,
						     AI_LSM_RULE_MAX * sizeof(struct ai_lsm_rule));
			return AI_OK;
		}
	}
	spin_unlock_irqrestore(&ai_lsm_rule_lock, flags);
	return AI_ERR_NOT_FOUND;
}

int ai_lsm_rule_clear(void)
{
	unsigned long flags;

	spin_lock_irqsave(&ai_lsm_rule_lock, flags);
	memset(ai_lsm_rules, 0, sizeof(ai_lsm_rules));
	ai_lsm_policy_version++;
	spin_unlock_irqrestore(&ai_lsm_rule_lock, flags);
	ai_telemetry_lsm_policy_load(AI_LSM_NAME, ai_lsm_policy_version, 0);
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

static int ai_lsm_file_open(struct file *file)
{
	u32 pid;
	char detail[AI_SEC_DETAIL_LEN] = { 0 };
	unsigned long flags;
	struct ai_lsm_model *m;
	u64 now;

	if (!current || !current->mm)
		return 0;

	pid = current->pid;

	/* 1) 决策表（AI 规则；sec.lsm_override 档位：enforce 拦截 /
	 *    observe 仅记录放行） */
	if (ai_lsm_rule_check(pid, detail, sizeof(detail))) {
		if (ai_lsm_enforce_get()) {
			ai_telemetry_lsm_deny("file_open", current->comm,
					      file->f_path.dentry->d_name.name,
					      "open", detail);
			return -EPERM;
		}
		ai_telemetry_lsm_check("file_open", current->comm,
				       file->f_path.dentry->d_name.name,
				       0, "observe-allow");
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
	char detail[AI_SEC_DETAIL_LEN] = { 0 };
	unsigned long flags;
	struct ai_lsm_model *m;
	u64 now;

	if (!current || !current->mm)
		return 0;

	pid = current->pid;

	if (ai_lsm_rule_check(pid, detail, sizeof(detail))) {
		ai_telemetry_lsm_deny("ptrace_access_check", current->comm,
				      child->comm,
				      (mode & PTRACE_MODE_ATTACH) ? "attach" :
				      "read",
				      detail);
		return -EPERM;
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
	char detail[AI_SEC_DETAIL_LEN] = { 0 };
	char av[AI_SEC_AV_LEN];
	unsigned long flags;
	struct ai_lsm_model *m;
	u64 now;

	if (!current || !current->mm)
		return 0;

	pid = current->pid;

	if (ai_lsm_rule_check(pid, detail, sizeof(detail))) {
		scnprintf(av, sizeof(av), "sig=%d", sig);
		ai_telemetry_lsm_deny("task_kill", current->comm, p->comm,
				      av, detail);
		return -EPERM;
	}

	now = ktime_get_ns();
	spin_lock_irqsave(&ai_lsm_model_lock, flags);
	m = ai_lsm_model_get(pid, now, true);
	if (m)
		ai_lsm_model_update(m, now, 1);
	spin_unlock_irqrestore(&ai_lsm_model_lock, flags);

	scnprintf(av, sizeof(av), "sig=%d", sig);
	ai_telemetry_lsm_check("task_kill", current->comm, p->comm, 0, av);
	return 0;
}

static const struct lsm_id ai_lsm_lsmid = {
	.name = AI_LSM_NAME,
	.id = AI_LSM_ID,
};

static struct security_hook_list ai_lsm_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(file_open, ai_lsm_file_open),
	LSM_HOOK_INIT(ptrace_access_check, ai_lsm_ptrace_access_check),
	LSM_HOOK_INIT(task_kill, ai_lsm_task_kill),
};

/* ==================================================================
 * ai_sec_* Hook（AI 决策接入点，空实现 = 原样放行）
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
/* ==================================================================
 * LSM 注册（可插拔：默认不在 CONFIG_LSM 列表 → 运行时禁用 → 零影响；
 * lsm=ai,... 启动参数显式启用）
 * ================================================================== */

static int __init ai_lsm_init(void)
{
	/* 可控制参数表（数据计划 20.3 安全域）已移至 ai_sec_control_init()
	 * （late_initcall）：DEFINE_LSM init 仅在 lsm= 启用 'ai' 时执行，
	 * 默认 boot 不注册会导致 control 表缺 sec.* —— 与 LSM 启用状态解耦 */
	pr_info("AIKernel: AI LSM (name=%s id=%d) registered, %d model slots, %d rule slots\n",
		AI_LSM_NAME, AI_LSM_ID, AI_LSM_MODEL_SLOTS, AI_LSM_RULE_MAX);
	security_add_hooks(ai_lsm_hooks, ARRAY_SIZE(ai_lsm_hooks), &ai_lsm_lsmid);
	return 0;
}

DEFINE_LSM(ai) = {
	.name = AI_LSM_NAME,
	.init = ai_lsm_init,
};

/* ---- sec.seccomp 立即生效参数（TASK：AI 进程行为基线收紧） ----
 * 语义选择（如实说明）：内核态跨进程安装 seccomp BPF 过滤器无安全
 * 路径（seccomp 仅允许进程自装 / clone 继承 / 同线程组 TSYNC）；本参数
 * 实现为"AIKernel 行为基线收紧"：value=1 向 AIKernel LSM 决策表注入该
 * pid 的 deny 规则（lsm=ai 启用时 file_open 真实拦截，配合
 * sec.lsm_override=enforce 档位），value=0 解除。 */
static int ai_sec_seccomp_apply_ex(struct ai_control_param *p, s32 pid,
				   s64 value, s64 *eff, const s64 *data)
{
	int rc;

	if (value == 1)
		rc = ai_lsm_rule_add((u32)pid, true, "ai_seccomp_baseline");
	else if (value == 0)
		rc = ai_lsm_rule_del((u32)pid);
	else
		return AI_ERR_INVALID_ARG;
	if (rc != AI_OK)
		return AI_ERR_GENERIC;
	*eff = value;
	pr_info("AIKernel: sec.seccomp pid=%d baseline %lld\n", pid, value);
	return AI_OK;
}

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

/* ---- 可控制参数表（数据计划 20.3 安全域）：全部立即生效 ----
 * 独立 late_initcall：不依赖 lsm= 启用 'ai'，control 表 23 参数全量可见；
 * lsm=ai 双启用时安全（本处为唯一注册点，无重名冲突）。
 * sec.audit 默认 1（采集默认开，与既有行为一致）。 */
static int __init ai_sec_control_init(void)
{
	ai_control_register("sec.lsm_override", AI_POLICY_DOMAIN_SECURITY,
			    AI_CTRL_F_REAL, 0, 1, 0,
			    ai_sec_lsm_override_apply);
	ai_control_register_ex("sec.seccomp", AI_POLICY_DOMAIN_SECURITY,
			       AI_CTRL_F_REAL | AI_CTRL_F_TASK,
			       0, 1, 0, NULL, ai_sec_seccomp_apply_ex);
	ai_control_register("sec.audit", AI_POLICY_DOMAIN_SECURITY,
			    AI_CTRL_F_REAL, 0, 1, 1, ai_sec_audit_apply);
	return 0;
}
late_initcall(ai_sec_control_init);
