// SPDX-License-Identifier: GPL-2.0
/*
 * ai_sysfs.c - AIKernel /sys/kernel/ai/ 用户态控制面（Prompt 02）
 *
 * 接口（"一个文件一个值"）：
 *   enabled            RW   AI 总开关（写需 CAP_SYS_ADMIN）
 *   model_load         W    下发模型（内置 echo 或 <model_path>/<name>.bin，CAP_SYS_ADMIN）
 *   model_unload       W    按名卸载模型（CAP_SYS_ADMIN）
 *   model_infer        W    MLP 真前向触发（name + float32 hex 输入）
 *   model_out          R    最近一次推理结果观测
 *   model_switch       W    决策模型 A/B 切换 arm（K6 D4：写 <name>，
 *                           冒烟推理过 → arm 切换窗，token 回显内核日志
 *                           "ARMED token=%llu"）
 *   model_switch_confirm W  写 token 生效切换（active 指针翻转 + 旧模型
 *                           观察窗保活，K6 D4）
 *   model_infer_budget_ns RW 推理硬上限预算（K6 D2：u64 ns，0=不限；
 *                           写需 CAP_SYS_ADMIN）
 *   policy/refresh     W    同步策略目录（扫描策略注册表，幂等新建 <name> 文件）
 *   policy/<name>      RW   各策略开关（1/0，写需 CAP_SYS_ADMIN）
 *   stats/             R    累计统计（telemetry 全 CPU 合计 + 决策统计 + runtime 状态）
 *
 * 所有写操作先过 capable(CAP_SYS_ADMIN)（内部走 LSM 的 security_capable），
 * 失败返回 -EPERM（可读错误码）。
 * 节点创建以 ai_startup_get_enabled() 为准：ai.enabled=0 启动 → 全部不创建。
 */
/*
 * 拆分说明：本文件为拆分后的主控节点（原 ai_sysfs.c 670 行）：enabled/
 * model_load/model_unload、policy/ 决策控制面（switch/refresh/global_enable/
 * max_impact/rollback/think/outcome/chain_dir）与 kobject 装配/初始化。
 * 只读统计视图 stats/ 拆至 ai_sysfs_stats.c（属性组经 ai_sysfs_internal.h 共享）。
 */


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/string.h>
#include <linux/capability.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/ctype.h>
#include "ai_types.h"
#include "ai_startup.h"
#include "ai_runtime.h"
#include "ai_model.h"
#include "ai_telemetry.h"
#include "ai_policy.h"
#include "ai_policy_safety.h"
#include "ai_causal.h"
#include "ai_decision.h"
#include "ai_effect.h"
#include "ai_agent.h"

static struct kobject *ai_kobj;          /* /sys/kernel/ai/ */
static struct kobject *ai_policy_kobj;   /* /sys/kernel/ai/policy/ */
static struct kobject *ai_stats_kobj;    /* /sys/kernel/ai/stats/ */
static struct kobject *ai_decision_kobj; /* /sys/kernel/ai/decision/ */

/* ---- 权限检查：全部写操作统一入口 ---- */

static int ai_sysfs_cap_check(void)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

/*
 * K6：返回码出口。AI_ERR_* 域为 -1..-17，与 errno 低区重叠，仅对已知
 * AI_ERR 码走 ai_error_to_errno() 映射；区间外的负值（如推理预算超时
 * 的 -ETIME，KERNEL-K6-DESIGN D2）按内核 errno 直通，避免被默认分支
 * 吞成 -EIO。
 */
static int ai_sysfs_rc_to_errno(int rc)
{
	if (rc >= AI_ERR_DISABLED && rc <= AI_OK)
		return ai_error_to_errno(rc);
	return rc;
}

/* ---- enabled ---- */

static ssize_t ai_enabled_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", ai_startup_get_enabled() ? 1 : 0);
}

static ssize_t ai_enabled_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	bool val;
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	if (kstrtobool(buf, &val) != 0)
		return -EINVAL;

	if (val && !ai_startup_get_enabled()) {
		/* 幂等：启动时被 ai.enabled=0 跳过的 Runtime 现在拉起。
		 * W63：不得吞掉初始化失败（此前失败仍返回成功并置 enabled=1，
		 * 用户态会误以为 AI 已可用）。 */
		rc = ai_runtime_init();
		if (rc != AI_OK)
			return ai_error_to_errno(rc);
	}
	ai_startup_set_enabled(val);
	return count;
}
static struct kobj_attribute ai_enabled_attr =
	__ATTR(enabled, 0644, ai_enabled_show, ai_enabled_store);

/* ---- model_load / model_unload ---- */

static int ai_sysfs_parse_name(const char *buf, size_t count, char *name)
{
	size_t len;

	while (count && (buf[count - 1] == '\n' || buf[count - 1] == ' '))
		count--;
	if (!count)
		return -EINVAL;
	len = count;
	if (len >= AI_MAX_NAME_LEN)
		return -E2BIG;
	memcpy(name, buf, len);
	name[len] = '\0';
	return 0;
}

static ssize_t ai_model_load_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	char name[AI_MAX_NAME_LEN];
	int rc, id;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	rc = ai_sysfs_parse_name(buf, count, name);
	if (rc)
		return rc;

	id = ai_startup_load_model(name);
	if (id < 0)
		return ai_error_to_errno(id);
	pr_info("AIKernel: sysfs model_load '%s' -> id=%d\n", name, id);
	return count;
}
static struct kobj_attribute ai_model_load_attr =
	__ATTR(model_load, 0200, NULL, ai_model_load_store);

static ssize_t ai_model_unload_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	char name[AI_MAX_NAME_LEN];
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	rc = ai_sysfs_parse_name(buf, count, name);
	if (rc)
		return rc;

	rc = ai_startup_unload_model(name);
	if (rc != AI_OK)
		return ai_error_to_errno(rc);
	return count;
}
static struct kobj_attribute ai_model_unload_attr =
	__ATTR(model_unload, 0200, NULL, ai_model_unload_store);

/* ---- policy/ 目录：refresh + 动态 <name> 开关 ---- */

#define AI_SYSFS_MAX_POLICY_FILES  64
struct ai_sysfs_policy_file {
	struct kobj_attribute attr;
	char name[AI_MAX_NAME_LEN];
};

static struct ai_sysfs_policy_file ai_sysfs_policy_files[AI_SYSFS_MAX_POLICY_FILES];
static unsigned int ai_sysfs_policy_file_count;
static DEFINE_MUTEX(ai_sysfs_policy_sync_lock);

static int ai_sysfs_policy_find_slot(const char *name)
{
	unsigned int i;

	for (i = 0; i < ai_sysfs_policy_file_count; i++)
		if (strcmp(ai_sysfs_policy_files[i].name, name) == 0)
			return (int)i;
	return -1;
}

static ssize_t ai_policy_switch_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	struct ai_sysfs_policy_file *pf =
		container_of(attr, struct ai_sysfs_policy_file, attr);
	u8 enabled;

	if (ai_policy_lookup(pf->name, &enabled) != AI_OK)
		return -ENOENT;
	return sysfs_emit(buf, "%d\n", enabled ? 1 : 0);
}

static ssize_t ai_policy_switch_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	struct ai_sysfs_policy_file *pf;
	bool val;
	int rc, idx;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	if (kstrtobool(buf, &val) != 0)
		return -EINVAL;

	/* 由 attr 定位回所属文件槽（attr 为结构体首成员，直接反推） */
	pf = container_of(attr, struct ai_sysfs_policy_file, attr);
	idx = ai_sysfs_policy_find_slot(pf->name);
	if (idx < 0)
		return -ENOENT;

	rc = ai_policy_set_enabled(pf->name, val ? 1 : 0);
	if (rc != AI_OK)
		return ai_error_to_errno(rc);
	pr_info("AIKernel: policy '%s' %s\n", pf->name,
		val ? "enabled" : "disabled");
	return count;
}

/* 同步：为每个新出现的已注册策略创建 <name> 文件（幂等，只增不减） */
static void ai_sysfs_policy_sync(void)
{
	unsigned int i;

	mutex_lock(&ai_sysfs_policy_sync_lock);
	for (i = 0; ; i++) {
		char name[AI_MAX_NAME_LEN];
		struct ai_sysfs_policy_file *pf;

		if (ai_policy_get_name(i, name, NULL) != AI_OK)
			break;
		if (ai_sysfs_policy_find_slot(name) >= 0)
			continue;
		if (ai_sysfs_policy_file_count >= AI_SYSFS_MAX_POLICY_FILES)
			break;

		pf = &ai_sysfs_policy_files[ai_sysfs_policy_file_count];
		strscpy(pf->name, name, sizeof(pf->name));
		sysfs_attr_init(&pf->attr.attr);
		pf->attr.attr.name = pf->name;
		pf->attr.attr.mode = 0644;
		pf->attr.show = ai_policy_switch_show;
		pf->attr.store = ai_policy_switch_store;

		if (sysfs_create_file(ai_policy_kobj, &pf->attr.attr) == 0)
			ai_sysfs_policy_file_count++;
	}
	mutex_unlock(&ai_sysfs_policy_sync_lock);
}

static ssize_t ai_policy_refresh_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	ai_sysfs_policy_sync();
	return count;
}
static struct kobj_attribute ai_policy_refresh_attr =
	__ATTR(refresh, 0200, NULL, ai_policy_refresh_store);

/* ---- policy/ 安全边界与控制面（Prompt 13） ---- */

/* global_enable：一键关闭 AI 决策执行（安全带） */
static ssize_t ai_global_enable_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", ai_policy_safety_get_enabled());
}

static ssize_t ai_global_enable_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	bool val;
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	if (kstrtobool(buf, &val) != 0)
		return -EINVAL;
	ai_policy_safety_set_enabled(val ? 1 : 0);
	pr_info("AIKernel: AI decision execution %s\n",
		val ? "enabled" : "DISABLED (emergency stop)");
	return count;
}
static struct kobj_attribute ai_global_enable_attr =
	__ATTR(global_enable, 0644, ai_global_enable_show,
	       ai_global_enable_store);

/* max_impact_pct：AI 决策最大影响幅度（参数范围 × pct%） */
static ssize_t ai_max_impact_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", ai_policy_safety_get_max_impact());
}

static ssize_t ai_max_impact_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	unsigned int val;
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	if (kstrtouint(buf, 0, &val) != 0)
		return -EINVAL;
	rc = ai_policy_safety_set_max_impact(val);
	if (rc != AI_OK)
		return ai_error_to_errno(rc);
	return count;
}
static struct kobj_attribute ai_max_impact_attr =
	__ATTR(max_impact_pct, 0644, ai_max_impact_show, ai_max_impact_store);

/* rollback：回滚决策（"all" 或十进制 decision_id），恢复决策前状态 */
static ssize_t ai_rollback_store(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	char cmd[32];
	size_t n = min(count, sizeof(cmd) - 1);
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	if (n == 0)
		return -EINVAL;
	memcpy(cmd, buf, n);
	while (n && (cmd[n - 1] == '\n' || cmd[n - 1] == ' '))
		cmd[--n] = '\0';
	cmd[n] = '\0';

	if (strcmp(cmd, "all") == 0) {
		rc = ai_policy_rollback_all();
	} else {
		u64 id;

		if (kstrtoull(cmd, 0, &id) != 0)
			return -EINVAL;
		rc = ai_policy_rollback_decision(id);
	}
	if (rc != AI_OK)
		return ai_error_to_errno(rc);
	pr_info("AIKernel: policy rollback '%s'\n", cmd);
	return count;
}
static struct kobj_attribute ai_rollback_attr =
	__ATTR(rollback, 0200, NULL, ai_rollback_store);

/* K2a（KERNEL-K2-DESIGN D5/D6）：批量事务 confirm（持久化确认——取消
 * pending 自动回滚）与 blast_threshold（radius 阈值） */
static ssize_t ai_policy_confirm_store(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	u64 id;
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;

	/* K2 收尾：容许尾随空白（sysfs 惯例 echo 带 LF）——
	 * kstrtoull 全串消费拒尾缀；rollback store 同款先 trim */
	while (count > 0 && isspace((unsigned char)buf[count - 1]))
		count--;
	if (count == 0 || count >= 32)
		return -EINVAL;
	{
		char tmp[33];

		memcpy(tmp, buf, count);
		tmp[count] = 0;
		if (kstrtoull(tmp, 0, &id) != 0)
			return -EINVAL;
	}
	rc = ai_policy_batch_confirm(id);
	if (rc)
		return rc;
	pr_info("AIKernel: policy batch %llu confirmed (auto-rollback cancelled)\n",
		id);
	return count;
}
static struct kobj_attribute ai_policy_confirm_attr =
	__ATTR(confirm, 0200, NULL, ai_policy_confirm_store);

static ssize_t ai_blast_threshold_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", ai_policy_blast_threshold_get());
}

static ssize_t ai_blast_threshold_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int val;
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	if (kstrtouint(buf, 0, &val) != 0)
		return -EINVAL;
	ai_policy_blast_threshold_set(val);	/* 0=关 */
	return count;
}
static struct kobj_attribute ai_blast_threshold_attr =
	__ATTR(blast_threshold, 0644, ai_blast_threshold_show,
	       ai_blast_threshold_store);

/* think：感知 → 决策 → 执行（决策闭环触发面，AI 外层程序用）
 * 格式：<event_id>,<domain>,<type>,<value>          （全局参数）
 *       <event_id>,<domain>,<type>,<pid>,<value>    （task 作用域参数） */
static ssize_t ai_think_store(struct kobject *kobj,
			      struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	struct ai_sense_input sense;
	struct ai_sense_decision d;
	struct ai_think_result res;
	char cmd[96];
	size_t n = min(count, sizeof(cmd) - 1);
	unsigned int event_id, domain, type;
	long long value;
	long pid = 0;
	char trail;
	int nfields, rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	if (n == 0)
		return -EINVAL;
	memcpy(cmd, buf, n);
	while (n && (cmd[n - 1] == '\n' || cmd[n - 1] == ' '))
		cmd[--n] = '\0';
	cmd[n] = '\0';

	/* 先试 5 字段（task 作用域：pid,value），再试 4 字段（全局：value） */
	nfields = sscanf(cmd, "%u,%u,%u,%ld,%lld%c", &event_id, &domain,
			 &type, &pid, &value, &trail);
	if (nfields != 5) {
		pid = 0;
		nfields = sscanf(cmd, "%u,%u,%u,%lld%c", &event_id, &domain,
				 &type, &value, &trail);
		if (nfields != 4)
			return -EINVAL;
	}
	if (domain > AI_POLICY_DOMAIN_PROC || type > 255)
		return -EINVAL;

	memset(&sense, 0, sizeof(sense));
	sense.ts = ktime_get_ns();
	sense.event_id = (u32)event_id;
	memset(&d, 0, sizeof(d));
	d.domain = (u8)domain;
	d.decision_type = (u8)type;
	d.confidence = 100;
	d.value = (s64)value;
	d.pid = (s32)pid;
	memcpy(sense.data, &d, sizeof(d));
	sense.data_len = sizeof(d);

	rc = ai_runtime_think_execute(&sense, &res);
	if (rc != AI_OK)
		return ai_error_to_errno(rc);
	pr_info("AIKernel: think evid=%u domain=%u type=%u value=%lld -> "
		"decision_id=%llu executed=%d\n",
		event_id, domain, type, value, res.decision_id, res.status);
	return count;
}
static struct kobj_attribute ai_think_attr =
	__ATTR(think, 0200, NULL, ai_think_store);

/* outcome：AI 外层程序上报决策结果（决策闭环第 4 步）
 * 格式：<decision_id>,<outcome>,<metric_delta> */
static ssize_t ai_outcome_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	char cmd[96];
	size_t n = min(count, sizeof(cmd) - 1);
	unsigned long long id;
	unsigned int outcome;
	long long delta;
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	if (n == 0)
		return -EINVAL;
	memcpy(cmd, buf, n);
	while (n && (cmd[n - 1] == '\n' || cmd[n - 1] == ' '))
		cmd[--n] = '\0';
	cmd[n] = '\0';

	if (sscanf(cmd, "%llu,%u,%lld", &id, &outcome, &delta) != 3)
		return -EINVAL;
	if (outcome > AI_OUTCOME_WORSE)
		return -EINVAL;

	rc = ai_policy_outcome_update(id, (u8)outcome, (s64)delta);
	if (rc != AI_OK)
		return ai_error_to_errno(rc);
	pr_info("AIKernel: outcome decision=%llu outcome=%u delta=%lld\n",
		id, outcome, delta);
	return count;
}
static struct kobj_attribute ai_outcome_attr =
	__ATTR(outcome, 0200, NULL, ai_outcome_store);

/* chain_dir：因果链 CSV 导出根目录（RW，CAP_SYS_ADMIN） */
static ssize_t ai_chain_dir_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	char path[AI_PATH_MAX];

	ai_causal_get_export_dir(path);
	return sysfs_emit(buf, "%s\n", path);
}

static ssize_t ai_chain_dir_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	char path[AI_PATH_MAX];
	size_t n = min(count, sizeof(path) - 1);
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	if (n == 0)
		return -EINVAL;
	memcpy(path, buf, n);
	while (n && (path[n - 1] == '\n' || path[n - 1] == ' '))
		path[--n] = '\0';
	path[n] = '\0';

	rc = ai_causal_set_export_dir(path);
	if (rc != AI_OK)
		return ai_error_to_errno(rc);
	return count;
}
static struct kobj_attribute ai_chain_dir_attr =
	__ATTR(chain_dir, 0644, ai_chain_dir_show, ai_chain_dir_store);

#include "ai_sysfs_internal.h"

/* ---- K8：审计链控制面（/sys/kernel/ai/chain 子树）---- */
#include "../security/ai_chain.h"

#if IS_ENABLED(CONFIG_AIKERNEL_SECURITY)

static struct kobject *ai_chain_kobj;

static ssize_t ai_chain_enable_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", ai_chain_enable_read() ? 1 : 0);
}

static ssize_t ai_chain_enable_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	bool on;
	int rc;

	rc = kstrtobool(buf, &on);
	if (rc)
		return rc;
	ai_chain_enable_set(on);
	return count;
}

static struct kobj_attribute ai_chain_enable_c_attr =
	__ATTR(enable, 0644, ai_chain_enable_show, ai_chain_enable_store);

static ssize_t ai_chain_period_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	struct ai_chain_stats st;

	ai_chain_stats_read(&st);
	return sysfs_emit(buf, "%u\n", st.period);
}

static ssize_t ai_chain_period_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	u32 v;
	int rc;

	rc = kstrtou32(buf, 0, &v);
	if (rc)
		return rc;
	rc = ai_chain_period_set(v);
	if (rc)
		return rc;
	return count;
}

static struct kobj_attribute ai_chain_period_c_attr =
	__ATTR(period, 0644, ai_chain_period_show, ai_chain_period_store);

/* seed（0200）：写 %016llx 续链种子——仅空链收（防事后改史） */
static ssize_t ai_chain_seed_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	u64 v;
	int rc;

	rc = kstrtou64(buf, 16, &v);
	if (rc)
		return rc;
	rc = ai_chain_seed(v);
	if (rc)
		return rc;
	return count;
}

static struct kobj_attribute ai_chain_seed_c_attr =
	__ATTR(seed, 0200, NULL, ai_chain_seed_store);

static ssize_t ai_chain_anchor_now_store(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	ai_chain_anchor_now();
	return count;
}

static struct kobj_attribute ai_chain_anchor_now_c_attr =
	__ATTR(anchor_now, 0200, NULL, ai_chain_anchor_now_store);

static struct attribute *ai_chain_group_attrs[] = {
	&ai_chain_enable_c_attr.attr,
	&ai_chain_period_c_attr.attr,
	&ai_chain_seed_c_attr.attr,
	&ai_chain_anchor_now_c_attr.attr,
	NULL,
};

static const struct attribute_group ai_chain_c_group = {
	.attrs = ai_chain_group_attrs,
};

#endif	/* CONFIG_AIKERNEL_SECURITY */

/* ---- 初始化 ---- */

/* ---- model_infer/model_out：AIKWMDL MLP 真前向触发与结果观测 ----
 * model_infer（0200）：写 "name hex..."（name 后跟 float32 小端 hex 输入
 * 向量）→ ai_runtime_model_infer_by_name 真实推理；
 * model_out（0440）：读最近一次推理的模型名/长度/输出 float32 hex。 */
#include <linux/mutex.h>

#define AI_MODEL_INFER_MAX 4096
static DEFINE_MUTEX(ai_infer_lock);
static u8 ai_infer_out_buf[AI_MODEL_INFER_MAX];
static size_t ai_infer_out_len;
static char ai_infer_out_name[AI_MAX_NAME_LEN];

static ssize_t ai_model_infer_store(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	char name[AI_MAX_NAME_LEN];
	u8 *in;
	size_t in_len = 0, out_len = sizeof(ai_infer_out_buf);
	size_t i, pos = 0;
	u64 lat = 0;
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;

	/* 4KB 输入缓冲走堆分配（内核栈上限 2048B，栈上会触发
	 * frame-larger-than -Werror） */
	in = kmalloc(sizeof(ai_infer_out_buf), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	while (pos < count && (buf[pos] == ' ' || buf[pos] == '\t'))
		pos++;
	for (i = 0; i < sizeof(name) - 1 && pos < count; i++, pos++) {
		if (buf[pos] == ' ' || buf[pos] == '\t' || buf[pos] == '\n')
			break;
		name[i] = buf[pos];
	}
	name[i] = '\0';
	if (!name[0])
		goto err_free;   /* K2b（K1B-17）：4 条早退不再泄 4KB */

	while (pos < count) {
		int hi, lo;

		if (buf[pos] == ' ' || buf[pos] == '\t' || buf[pos] == '\n') {
			pos++;
			continue;
		}
		hi = hex_to_bin(buf[pos]);
		if (hi < 0 || pos + 1 >= count)
			goto err_free;
		lo = hex_to_bin(buf[pos + 1]);
		if (lo < 0 || in_len >= AI_MODEL_INFER_MAX)
			goto err_free;
		in[in_len++] = (u8)(hi << 4 | lo);
		pos += 2;
	}
	if (!in_len)
		goto err_free;

	mutex_lock(&ai_infer_lock);
	rc = ai_runtime_model_infer_by_name(name, in, in_len,
					    ai_infer_out_buf, &out_len, &lat,
					    ai_model_infer_budget_ns_get());
	if (rc == AI_OK) {
		ai_infer_out_len = out_len;
		strscpy(ai_infer_out_name, name, sizeof(ai_infer_out_name));
		pr_info("AIKernel: model_infer '%s' in=%zu out=%zu lat=%llu ns\n",
			name, in_len, out_len, lat);
	}
	mutex_unlock(&ai_infer_lock);
	kfree(in);
	return rc == AI_OK ? (ssize_t)count : ai_sysfs_rc_to_errno(rc);

err_free:
	/* K2b 修复 K1B-17（Med-4）：4 条早退路径补释放（原每次失败泄 4KB） */
	kfree(in);
	return -EINVAL;
}

static ssize_t ai_model_out_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	ssize_t n;
	size_t i;

	mutex_lock(&ai_infer_lock);
	n = sysfs_emit(buf, "model=%s out_len=%zu hex=",
		       ai_infer_out_name, ai_infer_out_len);
	for (i = 0; i < ai_infer_out_len && n < PAGE_SIZE - 4; i++)
		n += scnprintf(buf + n, PAGE_SIZE - n, "%02x",
			       ai_infer_out_buf[i]);
	n += scnprintf(buf + n, PAGE_SIZE - n, "\n");
	mutex_unlock(&ai_infer_lock);
	return n;
}
static struct kobj_attribute ai_model_infer_attr =
	__ATTR(model_infer, 0200, NULL, ai_model_infer_store);
static struct kobj_attribute ai_model_out_attr =
	__ATTR(model_out, 0440, ai_model_out_show, NULL);

/* ---- K6（KERNEL-K6-DESIGN D2/D4）：推理预算 + 决策模型 A/B 切换 ---- */

/*
 * model_infer_budget_ns（0644 RW，写需 CAP_SYS_ADMIN）：推理硬上限
 * 预算（u64 ns，0=不限）。全局变量 ai_model_infer_budget_ns 与默认值
 * （10ms）由 ai_runtime.c 侧定义（施工 A）；本节点只做读写出口。
 */
static ssize_t ai_model_infer_budget_show(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  char *buf)
{
	return sysfs_emit(buf, "%llu\n", ai_model_infer_budget_ns_get());
}

static ssize_t ai_model_infer_budget_store(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   const char *buf, size_t count)
{
	u64 val;
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	if (kstrtoull(buf, 0, &val) != 0)
		return -EINVAL;
	ai_model_infer_budget_ns_set(val);
	pr_info("AIKernel: model_infer_budget_ns = %llu (%s)\n", val,
		val ? "ns cap" : "unlimited");
	return count;
}
static struct kobj_attribute ai_model_infer_budget_attr =
	__ATTR(model_infer_budget_ns, 0644, ai_model_infer_budget_show,
	       ai_model_infer_budget_store);

/*
 * model_switch（0200，CAP_SYS_ADMIN）：写 "<name>" arm 切换窗。
 * 实现=调 ai_runtime_model_switch_arm()（目标模型必须 LOADED、冒烟推理
 * 过才 arm，失败/超时拒切且 active 不动——均在 runtime 侧裁决）；arm
 * 成功后 token 回显内核日志（0200 写_only 节点无读面，回显格式
 * "ARMED token=%llu"，操作者从 dmesg 取 token 再写 confirm 节点）。
 * 切换窗/单槽/观察窗语义照 K2c blast token 模式自建于 runtime 侧。
 */
static ssize_t ai_model_switch_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	char name[AI_MAX_NAME_LEN];
	u64 token = 0;
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	rc = ai_sysfs_parse_name(buf, count, name);
	if (rc)
		return rc;

	rc = ai_runtime_model_switch_arm(name, &token);
	if (rc != AI_OK)
		return ai_sysfs_rc_to_errno(rc);
	pr_info("AIKernel: ARMED token=%llu (model_switch '%s')\n",
		token, name);
	return count;
}
static struct kobj_attribute ai_model_switch_attr =
	__ATTR(model_switch, 0200, NULL, ai_model_switch_store);

/*
 * model_switch_confirm（0200，CAP_SYS_ADMIN）：写十进制 token 生效
 * 切换（active 指针 RCU 翻转 + 旧模型观察窗保活）。token 失配/过期由
 * runtime 侧拒绝；容许尾随空白（sysfs 惯例 echo 带 LF，照 policy
 * confirm 同款先 trim 再 kstrtoull）。
 */
static ssize_t ai_model_switch_confirm_store(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     const char *buf, size_t count)
{
	u64 token;
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;

	while (count > 0 && isspace((unsigned char)buf[count - 1]))
		count--;
	if (count == 0 || count >= 32)
		return -EINVAL;
	{
		char tmp[33];

		memcpy(tmp, buf, count);
		tmp[count] = '\0';
		if (kstrtoull(tmp, 0, &token) != 0)
			return -EINVAL;
	}

	rc = ai_runtime_model_switch_confirm(token);
	if (rc != AI_OK)
		return ai_sysfs_rc_to_errno(rc);
	pr_info("AIKernel: model switch confirmed (token=%llu)\n", token);
	return count;
}
static struct kobj_attribute ai_model_switch_confirm_attr =
	__ATTR(model_switch_confirm, 0200, NULL,
	       ai_model_switch_confirm_store);

/* ---- decision_inject（W3 决策注入全局总开关，默认 0=关=原生行为） ---- */

static ssize_t ai_decision_inject_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", ai_decision_get_master());
}

static ssize_t ai_decision_inject_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	int val, rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	if (kstrtoint(buf, 0, &val) != 0 || (val != 0 && val != 1))
		return -EINVAL;
	ai_decision_set_master((u8)val);
	return count;
}
static struct kobj_attribute ai_decision_inject_attr =
	__ATTR(decision_inject, 0644, ai_decision_inject_show,
	       ai_decision_inject_store);

/* ---- decision/ 目录：per-hook 使能（默认全 0）+ 记账 stats ---- */

#define AI_DEC_HOOK_ATTR(_name, _id) \
static ssize_t ai_dec_##_name##_show(struct kobject *kobj, \
				     struct kobj_attribute *attr, char *buf) \
{ \
	return sysfs_emit(buf, "%u\n", ai_decision_get_hook_enable(_id)); \
} \
static ssize_t ai_dec_##_name##_store(struct kobject *kobj, \
				      struct kobj_attribute *attr, \
				      const char *buf, size_t count) \
{ \
	int val, rc; \
\
	rc = ai_sysfs_cap_check(); \
	if (rc) \
		return rc; \
	if (kstrtoint(buf, 0, &val) != 0 || (val != 0 && val != 1)) \
		return -EINVAL; \
	ai_decision_set_hook_enable(_id, (u8)val); \
	return count; \
} \
static struct kobj_attribute ai_dec_##_name##_attr = \
	__ATTR(_name, 0644, ai_dec_##_name##_show, ai_dec_##_name##_store)

AI_DEC_HOOK_ATTR(oom_badness, AI_HOOK_OOM_BADNESS);
AI_DEC_HOOK_ATTR(sched_vruntime, AI_HOOK_SCHED_VRUNTIME);
AI_DEC_HOOK_ATTR(sched_wakeup, AI_HOOK_SCHED_WAKEUP);
AI_DEC_HOOK_ATTR(readahead, AI_HOOK_MM_READAHEAD);
AI_DEC_HOOK_ATTR(reclaim, AI_HOOK_MM_RECLAIM);

static ssize_t ai_dec_stats_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	struct ai_decision_stats st;
	struct ai_effect_stats eff[AI_HOOK_NR];   /* K4.0 效果归因累计 */
	ssize_t n;
	unsigned int i;

	ai_decision_stats_get(&st);
	ai_effect_stats_get(eff);
	n = sysfs_emit(buf, "master: %u\n", st.master);
	n += sysfs_emit_at(buf, n,
			   "%-16s %3s %10s %9s %8s %9s %7s %10s %6s %6s %8s %12s\n",
			   "hook", "en", "queries", "injected", "effects",
			   "fallback", "ring", "last_bias",
			   "good", "bad", "timeout", "last_metric");
	for (i = 0; i < AI_HOOK_NR; i++) {
		n += sysfs_emit_at(buf, n,
				   "%-16s %3u %10llu %9llu %8llu %9llu %7llu %10d %6llu %6llu %8llu %12ld\n",
				   ai_decision_hook_name((enum ai_hook_id)i),
				   st.hook_en[i],
				   atomic64_read(&st.hook[i].queries),
				   atomic64_read(&st.hook[i].injected),
				   atomic64_read(&st.hook[i].effects),
				   atomic64_read(&st.hook[i].fallback),
				   atomic64_read(&st.hook[i].ring),
				   st.hook[i].last_bias,
				   atomic64_read(&eff[i].good),
				   atomic64_read(&eff[i].bad),
				   atomic64_read(&eff[i].timeout),
				   eff[i].last_metric);
	}
	return n;
}
static struct kobj_attribute ai_dec_stats_attr =
	__ATTR(stats, 0444, ai_dec_stats_show, NULL);

static struct attribute *ai_decision_attrs[] = {
	&ai_dec_oom_badness_attr.attr,
	&ai_dec_sched_vruntime_attr.attr,
	&ai_dec_sched_wakeup_attr.attr,
	&ai_dec_readahead_attr.attr,
	&ai_dec_reclaim_attr.attr,
	&ai_dec_stats_attr.attr,
	NULL,
};

static const struct attribute_group ai_decision_group = {
	.attrs = ai_decision_attrs,
};

/* ---- K3（KERNEL-K3-DESIGN D5）：agents/<name>/ 角色配额子目录 ----
 *
 * 每角色一目录（内置 7 角色）+ 两 knob：actions_per_win（0=不限，
 * 默认——出厂零行为变化）/ win_ms（滚动窗，默认 60000）。RW 0644，
 * 写需 CAP_SYS_ADMIN（ai_sysfs_cap_check）。目录创建照 policy/ 子目录
 * 手法（静态槽 + 逐 kobject/attr 装配）。 */

struct ai_sysfs_agent_dir {
	struct kobject *kobj;
	u32 agent_id;
	struct kobj_attribute apw_attr;	/* actions_per_win */
	struct kobj_attribute win_attr;	/* win_ms */
};

static struct kobject *ai_agents_kobj;
static struct ai_sysfs_agent_dir ai_sysfs_agent_dirs[16];

static ssize_t ai_agent_apw_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	struct ai_sysfs_agent_dir *d =
		container_of(attr, struct ai_sysfs_agent_dir, apw_attr);
	u32 apw = 0, win = 0;

	if (ai_agent_quota_get(d->agent_id, &apw, &win))
		return -ENOENT;
	return sysfs_emit(buf, "%u\n", apw);
}

static ssize_t ai_agent_apw_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	struct ai_sysfs_agent_dir *d =
		container_of(attr, struct ai_sysfs_agent_dir, apw_attr);
	unsigned int val;
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	if (kstrtouint(buf, 0, &val) != 0)
		return -EINVAL;
	rc = ai_agent_set_actions_per_win(d->agent_id, val);	/* 0=不限 */
	return rc ? rc : (ssize_t)count;
}

static ssize_t ai_agent_win_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	struct ai_sysfs_agent_dir *d =
		container_of(attr, struct ai_sysfs_agent_dir, win_attr);
	u32 apw = 0, win = 0;

	if (ai_agent_quota_get(d->agent_id, &apw, &win))
		return -ENOENT;
	return sysfs_emit(buf, "%u\n", win);
}

static ssize_t ai_agent_win_store(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	struct ai_sysfs_agent_dir *d =
		container_of(attr, struct ai_sysfs_agent_dir, win_attr);
	unsigned int val;
	int rc;

	rc = ai_sysfs_cap_check();
	if (rc)
		return rc;
	if (kstrtouint(buf, 0, &val) != 0)
		return -EINVAL;
	rc = ai_agent_set_win_ms(d->agent_id, val);	/* 0=不滚窗=不限 */
	return rc ? rc : (ssize_t)count;
}

static struct attribute *ai_attrs[] = {
	&ai_enabled_attr.attr,
	&ai_model_load_attr.attr,
	&ai_model_unload_attr.attr,
	&ai_model_infer_attr.attr,
	&ai_model_out_attr.attr,
	&ai_model_infer_budget_attr.attr,
	&ai_model_switch_attr.attr,
	&ai_model_switch_confirm_attr.attr,
	&ai_decision_inject_attr.attr,
	NULL,
};

static const struct attribute_group ai_group = {
	.attrs = ai_attrs,
};

static int __init ai_sysfs_init(void)
{
	struct ai_sysfs_agent_dir *d;
	unsigned int i;
	int rc;

	if (!ai_startup_get_enabled())
		return 0;   /* ai.enabled=0 启动：节点不创建（零回归） */

	ai_kobj = kobject_create_and_add("ai", kernel_kobj);
	if (!ai_kobj)
		return -ENOMEM;

	rc = sysfs_create_group(ai_kobj, &ai_group);
	if (rc)
		goto err_kobj;

	ai_policy_kobj = kobject_create_and_add("policy", ai_kobj);
	if (!ai_policy_kobj) {
		rc = -ENOMEM;
		goto err_kobj;
	}
	sysfs_attr_init(&ai_policy_refresh_attr.attr);
	rc = sysfs_create_file(ai_policy_kobj, &ai_policy_refresh_attr.attr);
	if (rc)
		goto err_kobj;
	rc = sysfs_create_file(ai_policy_kobj, &ai_global_enable_attr.attr);
	if (rc)
		goto err_kobj;
	rc = sysfs_create_file(ai_policy_kobj, &ai_max_impact_attr.attr);
	if (rc)
		goto err_kobj;
	rc = sysfs_create_file(ai_policy_kobj, &ai_rollback_attr.attr);
	if (rc)
		goto err_kobj;
	rc = sysfs_create_file(ai_policy_kobj, &ai_policy_confirm_attr.attr);
	if (rc)
		goto err_kobj;
	rc = sysfs_create_file(ai_policy_kobj,
			       &ai_blast_threshold_attr.attr);
	if (rc)
		goto err_kobj;
	rc = sysfs_create_file(ai_policy_kobj, &ai_think_attr.attr);
	if (rc)
		goto err_kobj;
	rc = sysfs_create_file(ai_policy_kobj, &ai_outcome_attr.attr);
	if (rc)
		goto err_kobj;
	rc = sysfs_create_file(ai_policy_kobj, &ai_chain_dir_attr.attr);
	if (rc)
		goto err_kobj;

	ai_stats_kobj = kobject_create_and_add("stats", ai_kobj);
	if (!ai_stats_kobj) {
		rc = -ENOMEM;
		goto err_kobj;
	}
	rc = sysfs_create_group(ai_stats_kobj, &ai_stats_group);
	if (rc)
		goto err_kobj;

	ai_decision_kobj = kobject_create_and_add("decision", ai_kobj);
	if (!ai_decision_kobj) {
		rc = -ENOMEM;
		goto err_kobj;
	}
	rc = sysfs_create_group(ai_decision_kobj, &ai_decision_group);
	if (rc)
		goto err_kobj;

#if IS_ENABLED(CONFIG_AIKERNEL_SECURITY)
	/* K8：审计链控制面 */
	ai_chain_kobj = kobject_create_and_add("chain", ai_kobj);
	if (!ai_chain_kobj) {
		rc = -ENOMEM;
		goto err_kobj;
	}
	rc = sysfs_create_group(ai_chain_kobj, &ai_chain_c_group);
	if (rc)
		goto err_kobj;
#endif
	/* K3：agents/<name>/{actions_per_win,win_ms}（照 policy/ 子目录手法） */
	ai_agents_kobj = kobject_create_and_add("agents", ai_kobj);
	if (!ai_agents_kobj) {
		rc = -ENOMEM;
		goto err_kobj;
	}
	for (i = 0; i < ARRAY_SIZE(ai_sysfs_agent_dirs); i++) {
		const char *name;

		d = &ai_sysfs_agent_dirs[i];
		if (ai_agent_enumerate(i, &d->agent_id, &name))
			break;
		d->kobj = kobject_create_and_add(name, ai_agents_kobj);
		if (!d->kobj) {
			rc = -ENOMEM;
			goto err_kobj;
		}
		sysfs_attr_init(&d->apw_attr.attr);
		d->apw_attr.attr.name = "actions_per_win";
		d->apw_attr.attr.mode = 0644;
		d->apw_attr.show = ai_agent_apw_show;
		d->apw_attr.store = ai_agent_apw_store;
		rc = sysfs_create_file(d->kobj, &d->apw_attr.attr);
		if (rc)
			goto err_kobj;
		sysfs_attr_init(&d->win_attr.attr);
		d->win_attr.attr.name = "win_ms";
		d->win_attr.attr.mode = 0644;
		d->win_attr.show = ai_agent_win_show;
		d->win_attr.store = ai_agent_win_store;
		rc = sysfs_create_file(d->kobj, &d->win_attr.attr);
		if (rc)
			goto err_kobj;
	}

	pr_info("AIKernel: /sys/kernel/ai/ interface ready\n");
	return 0;

err_kobj:
	for (i = 0; i < ARRAY_SIZE(ai_sysfs_agent_dirs); i++)
		kobject_put(ai_sysfs_agent_dirs[i].kobj);
#if IS_ENABLED(CONFIG_AIKERNEL_SECURITY)
	kobject_put(ai_chain_kobj);
#endif
	kobject_put(ai_agents_kobj);
	kobject_put(ai_decision_kobj);
	kobject_put(ai_stats_kobj);
	kobject_put(ai_policy_kobj);
	kobject_put(ai_kobj);
	ai_agents_kobj = NULL;
	ai_decision_kobj = ai_stats_kobj = ai_policy_kobj = ai_kobj = NULL;
	return rc;
}
subsys_initcall(ai_sysfs_init);

static void __exit ai_sysfs_exit(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ai_sysfs_agent_dirs); i++)
		kobject_put(ai_sysfs_agent_dirs[i].kobj);
#if IS_ENABLED(CONFIG_AIKERNEL_SECURITY)
	kobject_put(ai_chain_kobj);
#endif
	kobject_put(ai_agents_kobj);
	kobject_put(ai_decision_kobj);
	kobject_put(ai_stats_kobj);
	kobject_put(ai_policy_kobj);
	kobject_put(ai_kobj);
	ai_agents_kobj = NULL;
	ai_decision_kobj = ai_stats_kobj = ai_policy_kobj = ai_kobj = NULL;
}
module_exit(ai_sysfs_exit);
