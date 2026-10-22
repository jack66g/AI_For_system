// SPDX-License-Identifier: GPL-2.0
/*
 * ai_runtime.c - AIKernel AI Runtime 中枢
 *
 * 提供：
 *   - 生命周期：ai_runtime_init()/ai_runtime_destroy()（含遥测核心初始化）
 *   - 模型注册表：ai_model_load()/ai_model_unload()/ai_model_find()
 *   - 推理提交：ai_runtime_chat()（同步框架，调用已注册模型的 ops->infer）
 *   - 决策推理：ai_runtime_think()/ai_runtime_think_execute()（Prompt 13）：
 *     感知数据 → 决策模型 ops->think → 决策（decision_id+confidence+
 *     model_version）→ ai_policy_execute 执行（安全边界+决策记录）；
 *     内置 "decide" 模型（think = 解析 sense 载荷直通），用户态下发的
 *     真实模型推理可随时替换（模型推理由用户态下发，内核做安全兜底）。
 *   - 回调管理：ai_runtime_callback_register()/unregister()
 *
 * 生命周期与并发约束（W49 K1/K2/K3/K4/K5）：
 *   - 模型先以 AI_MODEL_STATE_LOADING 入册并执行 ops->load，成功后才转
 *     LOADED；find/chat/infer 只接受 LOADED，故看到 LOADED 时权重已就绪。
 *   - ops->load/unload 可睡眠，均在模型生命周期互斥量下、注册表锁外执行。
 *   - 每个模型有 refcount：注册表持 1 个引用，读者在注册表锁内取引用后
 *     锁外推理，结束释放；unload 先退册（dying=1 拒绝新引用）再等待在途
 *     引用归零，最后才调 ops->unload（其可释放模型内存）。
 *   - init/destroy/load/unload 全部由 ai_model_lifecycle_lock 串行化，
 *     destroy 逐模型走同一退册-等待-卸载路径，不再泄漏模型内部资源。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/refcount.h>
#include <linux/rcupdate.h>
#include <linux/srcu.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <generated/utsrelease.h>
#include "ai_runtime.h"
#include "ai_telemetry.h"
#include "ai_policy.h"
#include "../net/ai_netlink.h"

#define AI_RUNTIME_MAX_MODELS      16   /* 模型注册表容量 */
#define AI_RUNTIME_MAX_CALLBACKS   8    /* 回调表容量 */

static struct ai_runtime_ctx {
	enum ai_runtime_state state;
	struct ai_model *models[AI_RUNTIME_MAX_MODELS];
	unsigned int model_count;
	u32 next_model_id;              /* 单调递增句柄（1 起），退册不回收 */
	struct {
		ai_runtime_callback_t cb;
		void *priv;
	} callbacks[AI_RUNTIME_MAX_CALLBACKS];
	unsigned int callback_count;
} ai_rt = {
	.state = AI_RT_STATE_DOWN,
	.next_model_id = 1,
};

/* 注册表锁：只保护指针/计数/状态字段，绝不跨 ops->load/infer/unload 持有 */
static DEFINE_MUTEX(ai_runtime_lock);

/* 模型生命周期锁：串行化 init/destroy/load/unload（可睡眠路径） */
static DEFINE_MUTEX(ai_model_lifecycle_lock);

/*
 * W63：推理完成回调的 SRCU 域。
 *
 * ai_runtime_chat() 在锁外执行回调（回调可重入 runtime），而
 * ai_runtime_callback_unregister() 只把表项移出，不等待在途回调：
 * 若调用方在 unregister 返回后释放 priv，正在执行的回调会解引用已释放
 * priv（UAF）。注册方现在在快照前进入 SRCU 读临界区并覆盖整个回调执行，
 * unregister 在摘除表项后 synchronize_srcu()，返回时保证没有回调仍持有
 * 该表项快照（priv 可安全释放）。回调内可重入 runtime，但不得在回调内
 * 注销自身（会在 synchronize_srcu 上等待自己而造成死锁）。
 */
DEFINE_STATIC_SRCU(ai_cb_srcu);

static bool ai_runtime_ready(void)
{
	return READ_ONCE(ai_rt.state) == AI_RT_STATE_READY;
}

/* ---- 内置决策模型（Prompt 13：感知 → 决策直通，安全 clamp 兜底） ---- */

static int ai_rt_decide_think(struct ai_model *model,
			      const struct ai_sense_input *sense,
			      struct ai_think_result *res)
{
	const struct ai_sense_decision *d;

	if (!sense || !res || sense->data_len < sizeof(*d))
		return AI_ERR_INVALID_ARG;

	d = (const struct ai_sense_decision *)sense->data;
	res->domain = d->domain;
	res->decision_type = d->decision_type;
	res->confidence = d->confidence;
	if (d->pid > 0) {
		res->decision_data[0] = (u64)d->pid;
		res->decision_data[1] = (u64)d->value;
	} else {
		res->decision_data[0] = (u64)d->value;
	}
	return AI_OK;
}

static struct ai_model ai_rt_decide_model = {
	.name = "decide",
	.version = 1,
	.source = AI_MODEL_SOURCE_EMBEDDED,
	.ops = &(const struct ai_model_ops) {
		.think = ai_rt_decide_think,
	},
};

/* ---- 引用计数辅助（调用者按注释持锁） ---- */

/*
 * 取一个模型引用：仅接受 LOADED 且未 dying 的模型。注册表项本身持有
 * 1 个引用，故正常路径 inc_not_zero 不会失败；失败仅发生在退册竞争窗口，
 * 此时视为不可用（调用者返回 NOT_FOUND）。
 * 调用者必须持 ai_runtime_lock。
 */
static struct ai_model *ai_model_get_by_name_locked(const char *name)
{
	unsigned int i;

	for (i = 0; i < ai_rt.model_count; i++) {
		struct ai_model *m = ai_rt.models[i];

		if (m->state != AI_MODEL_STATE_LOADED || m->dying)
			continue;
		if (strcmp(m->name, name) != 0)
			continue;
		if (!refcount_inc_not_zero(&m->refcount))
			continue;
		return m;
	}
	return NULL;
}

/* 调用者必须持 ai_runtime_lock。 */
static struct ai_model *ai_model_get_by_id_locked(u32 id)
{
	unsigned int i;

	for (i = 0; i < ai_rt.model_count; i++) {
		struct ai_model *m = ai_rt.models[i];

		if (m->state != AI_MODEL_STATE_LOADED || m->dying)
			continue;
		if (m->id != id)
			continue;
		if (!refcount_inc_not_zero(&m->refcount))
			continue;
		return m;
	}
	return NULL;
}

/*
 * 释放读者引用；最后一个引用唤醒等待中的 unload。
 *
 * ref_done 内嵌在 model 里，而 unload 侧在 wait_for_completion() 返回后会
 * 调 ops->unload（MLP 会 kfree 整个 model）。若不额外同步，最后一个读者
 * 在 complete() 内部（唤醒后仍持有等待队列锁）与 unload 侧释放可能并发。
 * 把释放段放进 RCU 读临界区，unload 侧 wait 之后再做 synchronize_rcu()，
 * 保证最后一个读者已完全离开释放段才允许释放 model。
 */
static void ai_model_put(struct ai_model *model)
{
	rcu_read_lock();
	if (refcount_dec_and_test(&model->refcount))
		complete(&model->ref_done);
	rcu_read_unlock();
}

/*
 * 决策模型查找：返回时已持有引用（调用者负责 ai_model_put）。
 * 调用者必须持 ai_runtime_lock。
 */
static struct ai_model *ai_model_get_decision_locked(void)
{
	unsigned int i;

	for (i = 0; i < ai_rt.model_count; i++) {
		struct ai_model *m = ai_rt.models[i];

		if (m->state != AI_MODEL_STATE_LOADED || m->dying)
			continue;
		if (!m->ops || !m->ops->think)
			continue;
		if (!refcount_inc_not_zero(&m->refcount))
			continue;
		return m;
	}
	return NULL;
}

/*
 * 从注册表退册并标记 dying（拒绝新读者）。模型对象不释放，由调用者
 * 在锁外等待引用归零后执行 ops->unload。调用者必须持 ai_runtime_lock。
 * 返回 true=找到并退册。
 */
static bool ai_model_retire_locked(struct ai_model *model)
{
	unsigned int i;

	for (i = 0; i < ai_rt.model_count; i++) {
		if (ai_rt.models[i] != model)
			continue;
		memmove(&ai_rt.models[i], &ai_rt.models[i + 1],
			(ai_rt.model_count - i - 1) * sizeof(model));
		ai_rt.model_count--;
		model->dying = true;
		model->state = AI_MODEL_STATE_UNLOADED;
		return true;
	}
	return false;
}

/*
 * 已退册模型的收尾：释放注册表引用、等待在途读者归零、调用 ops->unload。
 * 可睡眠；@name 是退册前复制的名字（ops->unload 可能释放 model 本身，
 * 此后不得再解引用 model）。
 */
static void ai_model_finish_unload(struct ai_model *model, const char *name,
				   u32 id)
{
	if (refcount_dec_and_test(&model->refcount))
		complete(&model->ref_done);
	wait_for_completion(&model->ref_done);

	/* 见 ai_model_put()：等最后一个读者的 RCU 释放段完全结束再释放 */
	synchronize_rcu();

	if (model->ops && model->ops->unload)
		model->ops->unload(model);

	pr_info("AIKernel: model '%s' unloaded\n", name);
	ai_netlink_push_event(AI_NL_EV_MODEL, AI_NL_EV_SEV_INFO, id, 0, name);
}

/* ---- 生命周期 ---- */

/*
 * 模型装载核心（调用者必须持 ai_model_lifecycle_lock）。
 * 先入册为 LOADING → 锁外 ops->load（可睡眠）→ 成功后转 LOADED；
 * 失败则回滚注册表项并置 ERROR，绝不把半初始化模型暴露给读者。
 */
static int ai_model_load_internal(struct ai_model *model)
{
	unsigned int i;
	int rc = AI_OK;

	if (!model || !model->name[0] || !model->ops)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_runtime_lock);
	if (ai_rt.state != AI_RT_STATE_READY) {
		mutex_unlock(&ai_runtime_lock);
		return AI_ERR_DISABLED;
	}
	if (ai_rt.model_count >= AI_RUNTIME_MAX_MODELS) {
		mutex_unlock(&ai_runtime_lock);
		return AI_ERR_BUSY;
	}
	for (i = 0; i < ai_rt.model_count; i++) {
		if (strcmp(ai_rt.models[i]->name, model->name) == 0) {
			mutex_unlock(&ai_runtime_lock);
			return AI_ERR_INVALID_ARG;   /* 重名 */
		}
	}

	model->id = ai_rt.next_model_id;
	if (++ai_rt.next_model_id == 0)
		ai_rt.next_model_id = 1;   /* 句柄 0 保留为无效 */
	model->state = AI_MODEL_STATE_LOADING;
	model->dying = false;
	refcount_set(&model->refcount, 1);   /* 注册表引用 */
	init_completion(&model->ref_done);
	ai_rt.models[ai_rt.model_count++] = model;
	mutex_unlock(&ai_runtime_lock);

	/* ops->load 在注册表锁外执行：允许睡眠，也允许其查询/注册其他资源
	 * （但不得递归调用 ai_model_load —— 生命周期锁不可重入） */
	if (model->ops->load)
		rc = model->ops->load(model);

	if (rc != AI_OK) {
		mutex_lock(&ai_runtime_lock);
		ai_model_retire_locked(model);
		model->state = AI_MODEL_STATE_ERROR;
		mutex_unlock(&ai_runtime_lock);

		/* LOADING 期间无人能取到引用，注册表引用即最后一个引用 */
		if (refcount_dec_and_test(&model->refcount))
			complete(&model->ref_done);

		pr_err("AIKernel: model '%s' load failed (%d), rolled back\n",
		       model->name, rc);
		return rc;
	}

	mutex_lock(&ai_runtime_lock);
	model->state = AI_MODEL_STATE_LOADED;   /* 发布点：此后读者可见 */
	mutex_unlock(&ai_runtime_lock);

	pr_info("AIKernel: model '%s' v%u loaded (id=%u)\n",
		model->name, model->version, model->id);
	ai_netlink_push_event(AI_NL_EV_MODEL, AI_NL_EV_SEV_INFO,
			      model->id, 1, model->name);
	return AI_OK;
}

int ai_runtime_init(void)
{
	int rc;

	mutex_lock(&ai_model_lifecycle_lock);

	mutex_lock(&ai_runtime_lock);
	if (ai_rt.state != AI_RT_STATE_DOWN) {
		mutex_unlock(&ai_runtime_lock);
		mutex_unlock(&ai_model_lifecycle_lock);
		return AI_OK;   /* 幂等 */
	}
	ai_rt.state = AI_RT_STATE_INIT;
	mutex_unlock(&ai_runtime_lock);

	rc = ai_telemetry_init();
	if (rc != AI_OK) {
		pr_err("AIKernel: telemetry init failed (%d)\n", rc);
		mutex_lock(&ai_runtime_lock);
		ai_rt.state = AI_RT_STATE_DOWN;
		mutex_unlock(&ai_runtime_lock);
		mutex_unlock(&ai_model_lifecycle_lock);
		return rc;
	}

	/*
	 * W63：Runtime 在运行期重新初始化时（ai.enabled 0→1 sysfs 拉起、
	 * KUnit destroy/init 循环），排空线程已被 ai_telemetry_exit() 停掉，
	 * 而 early/late initcall 早已跑过。这里补启动，避免"遥测在产、无人
	 * 消费"退化为长期积压。system_state > SYSTEM_BOOTING 表示已离开
	 * start_kernel()（rest_init 已创建 kthreadd）；initcalls 阶段状态为
	 * SYSTEM_SCHEDULING/FREEING_INITMEM，kthread 可用。start_kernel 内
	 * （SYSTEM_BOOTING）跳过，由 early_initcall 负责。
	 */
	if (system_state > SYSTEM_BOOTING) {
		rc = ai_telemetry_drain_start();
		if (rc != AI_OK)
			pr_warn("AIKernel: telemetry drainer restart failed (%d)\n",
				rc);
	}

	mutex_lock(&ai_runtime_lock);
	ai_rt.state = AI_RT_STATE_READY;
	mutex_unlock(&ai_runtime_lock);

	/* 内置决策模型（Prompt 13）：用户态下发模型可覆盖/替换 */
	rc = ai_model_load_internal(&ai_rt_decide_model);
	if (rc != AI_OK)
		pr_err("AIKernel: built-in decide model load failed (%d)\n", rc);

#ifdef CONFIG_AIKERNEL_TELEMETRY
	/* 第17类：内核配置快照（启动采集一次，全量零脱敏） */
	{
		struct ai_kconfig_payload p;

		memset(&p, 0, sizeof(p));
#ifdef CONFIG_KUNIT
		p.kunit = 1;
#endif
#ifdef CONFIG_BPF
		p.bpf = 1;
#endif
#ifdef CONFIG_KVM
		p.kvm = 1;
#endif
#ifdef CONFIG_AIKERNEL
		p.aikernel = 1;
#endif
#ifdef CONFIG_SMP
		p.smp = 1;
#endif
#ifdef CONFIG_PREEMPT
		p.preempt = 1;
#endif
		strscpy(p.release, UTS_RELEASE, sizeof(p.release));
		ai_telemetry_config_change_evt(&p);
	}
#endif

	pr_info("AIKernel: AI Runtime ready (telemetry: %s, decide model: v%u)\n",
#ifdef CONFIG_AIKERNEL_TELEMETRY
		"enabled",
#else
		"disabled",
#endif
		ai_rt_decide_model.version);

	mutex_unlock(&ai_model_lifecycle_lock);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_runtime_init);

void ai_runtime_destroy(void)
{
	char name[AI_MAX_NAME_LEN];
	struct ai_model *model;
	u32 id;

	mutex_lock(&ai_model_lifecycle_lock);

	if (ai_rt.state == AI_RT_STATE_DOWN) {
		mutex_unlock(&ai_model_lifecycle_lock);
		return;
	}

	mutex_lock(&ai_runtime_lock);
	ai_rt.state = AI_RT_STATE_INIT;
	ai_rt.callback_count = 0;
	mutex_unlock(&ai_runtime_lock);

	/*
	 * W63：等待所有已拍快照的 chat 完成回调执行。chat 在回调前复查
	 * state（非 READY 即跳过），因此本函数返回后不会再有旧回调运行，
	 * 调用方可以安全释放回调 priv。
	 */
	synchronize_srcu(&ai_cb_srcu);

	ai_telemetry_exit();

	/* K2：逐模型退册-等待引用-ops->unload，避免 destroy 泄漏模型内部资源。
	 * 生命周期锁保证此刻没有 LOADING 中的模型（load 与其串行）。 */
	for (;;) {
		mutex_lock(&ai_runtime_lock);
		if (!ai_rt.model_count) {
			mutex_unlock(&ai_runtime_lock);
			break;
		}
		model = ai_rt.models[0];
		strscpy(name, model->name, sizeof(name));
		id = model->id;
		ai_model_retire_locked(model);
		mutex_unlock(&ai_runtime_lock);

		ai_model_finish_unload(model, name, id);
	}

	mutex_lock(&ai_runtime_lock);
	ai_rt.state = AI_RT_STATE_DOWN;
	mutex_unlock(&ai_runtime_lock);

	pr_info("AIKernel: AI Runtime destroyed\n");
	mutex_unlock(&ai_model_lifecycle_lock);
}
EXPORT_SYMBOL_GPL(ai_runtime_destroy);

int ai_runtime_get_state(void)
{
	return READ_ONCE(ai_rt.state);
}
EXPORT_SYMBOL_GPL(ai_runtime_get_state);

/* ---- 模型注册表 ---- */

int ai_model_load(struct ai_model *model)
{
	int rc;

	mutex_lock(&ai_model_lifecycle_lock);
	rc = ai_model_load_internal(model);
	mutex_unlock(&ai_model_lifecycle_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_model_load);

int ai_model_unload(struct ai_model *model)
{
	char name[AI_MAX_NAME_LEN];
	unsigned int i;
	u32 id = 0;
	int rc = AI_ERR_NOT_FOUND;

	if (!model)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_model_lifecycle_lock);
	mutex_lock(&ai_runtime_lock);
	for (i = 0; i < ai_rt.model_count; i++) {
		if (ai_rt.models[i] != model)
			continue;
		if (model->state == AI_MODEL_STATE_LOADING) {
			rc = AI_ERR_BUSY;   /* ops->load 未完成，不可卸载 */
			break;
		}
		strscpy(name, model->name, sizeof(name));
		id = model->id;
		ai_model_retire_locked(model);
		rc = AI_OK;
		break;
	}
	mutex_unlock(&ai_runtime_lock);

	if (rc == AI_OK)
		ai_model_finish_unload(model, name, id);   /* 可能释放 model */

	mutex_unlock(&ai_model_lifecycle_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_model_unload);

int ai_model_find(const char *name)
{
	unsigned int i;
	int rc = AI_ERR_NOT_FOUND;

	if (!name)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_runtime_lock);
	for (i = 0; i < ai_rt.model_count; i++) {
		struct ai_model *m = ai_rt.models[i];

		/* 只暴露 LOADED：LOADING（半初始化）对读者不可见 */
		if (m->state != AI_MODEL_STATE_LOADED || m->dying)
			continue;
		if (strcmp(m->name, name) == 0) {
			rc = (int)m->id;
			break;
		}
	}
	mutex_unlock(&ai_runtime_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_model_find);

int ai_model_unload_by_name(const char *name)
{
	char found_name[AI_MAX_NAME_LEN];
	struct ai_model *model = NULL;
	unsigned int i;
	u32 id = 0;
	int rc = AI_ERR_NOT_FOUND;

	if (!name)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_model_lifecycle_lock);
	mutex_lock(&ai_runtime_lock);
	for (i = 0; i < ai_rt.model_count; i++) {
		struct ai_model *m = ai_rt.models[i];

		if (strcmp(m->name, name) != 0)
			continue;
		if (m->state == AI_MODEL_STATE_LOADING) {
			rc = AI_ERR_BUSY;
			break;
		}
		if (!m->dying) {
			model = m;
			id = m->id;
			strscpy(found_name, m->name, sizeof(found_name));
			ai_model_retire_locked(m);
			rc = AI_OK;
		}
		break;
	}
	mutex_unlock(&ai_runtime_lock);

	if (rc == AI_OK && model)
		ai_model_finish_unload(model, found_name, id);

	mutex_unlock(&ai_model_lifecycle_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_model_unload_by_name);

int ai_model_enumerate(unsigned int index, char *name, u32 *version,
		       u32 *source, u32 *state)
{
	struct ai_model *found = NULL;
	unsigned int i, visible = 0;

	if (!name)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_runtime_lock);
	for (i = 0; i < ai_rt.model_count; i++) {
		struct ai_model *m = ai_rt.models[i];

		if (m->state != AI_MODEL_STATE_LOADED || m->dying)
			continue;
		if (visible++ != index)
			continue;
		found = m;
		break;
	}
	if (found) {
		strscpy(name, found->name, AI_MAX_NAME_LEN);
		if (version)
			*version = found->version;
		if (source)
			*source = found->source;
		if (state)
			*state = found->state;
	}
	mutex_unlock(&ai_runtime_lock);
	return found ? AI_OK : AI_ERR_NOT_FOUND;
}
EXPORT_SYMBOL_GPL(ai_model_enumerate);

/* ---- 决策推理（感知 → 决策 → 执行） ---- */

int ai_runtime_think(const struct ai_sense_input *sense,
		     struct ai_think_result *res)
{
	struct ai_model *model;
	u32 model_version;
	int rc;

	if (!sense || !res)
		return AI_ERR_INVALID_ARG;
	if (!ai_runtime_ready())
		return AI_ERR_DISABLED;

	memset(res, 0, sizeof(*res));

	mutex_lock(&ai_runtime_lock);
	model = ai_model_get_decision_locked();
	mutex_unlock(&ai_runtime_lock);

	if (!model)
		return AI_ERR_NO_MODEL;

	model_version = model->version;
	rc = model->ops->think(model, sense, res);
	ai_model_put(model);

	res->model_version = model_version;
	res->decision_id = ai_policy_next_decision_id();
	res->status = rc;
	return rc;
}
EXPORT_SYMBOL_GPL(ai_runtime_think);

int ai_runtime_think_execute(const struct ai_sense_input *sense,
			     struct ai_think_result *res)
{
	struct ai_policy_ctx ctx;
	u64 decision_id;
	int rc;

	if (!sense || !res)
		return AI_ERR_INVALID_ARG;

	rc = ai_runtime_think(sense, res);
	if (rc != AI_OK)
		return rc;

	/* 决策上下文：触发事件信息全量传递（trigger→decision 因果头） */
	decision_id = res->decision_id;
	memset(&ctx, 0, sizeof(ctx));
	ctx.trigger_ts = sense->ts ? sense->ts : ktime_get_ns();
	ctx.trigger_event_id = sense->event_id;
	ctx.decision_type = res->decision_type;
	memcpy(ctx.decision_data, res->decision_data,
	       sizeof(ctx.decision_data));
	ctx.confidence = res->confidence;
	ctx.model_version = res->model_version;
	ctx.domain = (enum ai_policy_domain)res->domain;
	ctx.decision_id = decision_id;
	ctx.source = AI_DEC_SRC_THINK;

	rc = ai_policy_execute(&ctx, NULL);
	res->status = rc;
	res->decision_id = ctx.decision_id;
	/* execute 返回执行动作数（>=0）；对调用方统一 AI_OK/负错误码 */
	return rc < 0 ? rc : AI_OK;
}
EXPORT_SYMBOL_GPL(ai_runtime_think_execute);

/* ---- 推理提交（同步框架） ---- */

int ai_runtime_model_infer_by_name(const char *name, const void *input,
				   size_t in_len, void *output,
				   size_t *out_len, u64 *latency_ns)
{
	struct ai_model *model;
	int rc;

	if (!name || !name[0] || !input || !output || !out_len)
		return AI_ERR_INVALID_ARG;
	if (!ai_runtime_ready())
		return AI_ERR_DISABLED;

	/* K4：锁内只取模型引用，推理在锁外执行（infer 可睡眠/耗时） */
	mutex_lock(&ai_runtime_lock);
	model = ai_model_get_by_name_locked(name);
	mutex_unlock(&ai_runtime_lock);

	if (!model || !model->ops || !model->ops->infer) {
		if (model)
			ai_model_put(model);
		return AI_ERR_NOT_FOUND;
	}

	rc = model->ops->infer(model, input, in_len, output, out_len,
			       latency_ns);
	ai_model_put(model);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_runtime_model_infer_by_name);

int ai_runtime_chat(struct ai_inference_request *req,
		    struct ai_inference_result *res)
{
	struct {
		ai_runtime_callback_t cb;
		void *priv;
	} cbs[AI_RUNTIME_MAX_CALLBACKS];
	struct ai_model *model;
	unsigned int i, cb_count;
	u64 t0, latency;
	int rc;

	if (!req || !res)
		return AI_ERR_INVALID_ARG;
	if (!req->input || !req->output || req->output_len == 0)
		return AI_ERR_INVALID_ARG;
	if (!ai_runtime_ready())
		return AI_ERR_DISABLED;

	/* K5：锁内取引用，推理在锁外（unload 会等待本引用释放） */
	mutex_lock(&ai_runtime_lock);
	model = ai_model_get_by_id_locked(req->model_id);
	mutex_unlock(&ai_runtime_lock);

	memset(res, 0, sizeof(*res));
	res->request_id = req->id;
	res->model_id = req->model_id;

	if (!model)
		return AI_ERR_NO_MODEL;
	if (!model->ops->infer) {
		ai_model_put(model);
		return AI_ERR_NOT_IMPLEMENTED;
	}

	t0 = ktime_get_ns();
	rc = model->ops->infer(model, req->input, req->input_len,
			       req->output, &req->output_len, &latency);
	latency = ktime_get_ns() - t0;
	ai_model_put(model);

	res->status = rc;
	res->output_len = req->output_len;
	res->latency_ns = latency;

	if (rc == AI_OK && ai_runtime_ready()) {
		int sidx;

		/* 回调在锁外调用：回调内允许再次进入 runtime（但不得等待本
		 * 请求所属模型的 unload —— 那会自锁，属调用方违约）。
		 * W63：SRCU 读临界区覆盖"快照 + 回调执行"，与 unregister 的
		 * synchronize_srcu() 配对，保证 unregister 返回后 priv 可释放；
		 * 推理期间 destroy 把 state 切走时跳过回调（destroy 侧
		 * synchronize_srcu 之后不会再有旧快照执行）。 */
		sidx = srcu_read_lock(&ai_cb_srcu);
		mutex_lock(&ai_runtime_lock);
		cb_count = ai_rt.callback_count;
		memcpy(cbs, ai_rt.callbacks, cb_count * sizeof(cbs[0]));
		mutex_unlock(&ai_runtime_lock);

		for (i = 0; i < cb_count; i++)
			cbs[i].cb(res, cbs[i].priv);
		srcu_read_unlock(&ai_cb_srcu, sidx);
	}

	return rc;
}
EXPORT_SYMBOL_GPL(ai_runtime_chat);

/* ---- 回调管理 ---- */

int ai_runtime_callback_register(ai_runtime_callback_t cb, void *priv)
{
	int rc = AI_OK;

	if (!cb)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_runtime_lock);
	if (ai_rt.callback_count >= AI_RUNTIME_MAX_CALLBACKS) {
		rc = AI_ERR_BUSY;
	} else {
		ai_rt.callbacks[ai_rt.callback_count].cb = cb;
		ai_rt.callbacks[ai_rt.callback_count].priv = priv;
		ai_rt.callback_count++;
	}
	mutex_unlock(&ai_runtime_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_runtime_callback_register);

int ai_runtime_callback_unregister(ai_runtime_callback_t cb)
{
	unsigned int i;
	int rc = AI_ERR_NOT_FOUND;

	if (!cb)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_runtime_lock);
	for (i = 0; i < ai_rt.callback_count; i++) {
		if (ai_rt.callbacks[i].cb == cb) {
			memmove(&ai_rt.callbacks[i], &ai_rt.callbacks[i + 1],
				(ai_rt.callback_count - i - 1) *
					sizeof(ai_rt.callbacks[0]));
			ai_rt.callback_count--;
			rc = AI_OK;
			break;
		}
	}
	mutex_unlock(&ai_runtime_lock);

	/*
	 * W63：等待所有已持有本回调快照的在途 ai_runtime_chat() 完成回调
	 * 执行再返回；此后调用方释放 priv 不再有 UAF 窗口。
	 */
	if (rc == AI_OK)
		synchronize_srcu(&ai_cb_srcu);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_runtime_callback_unregister);
