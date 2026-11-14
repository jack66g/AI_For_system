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
 *   - K6（WP-K6 施工 A）：推理预算全局（D2，B 路 sysfs 写）、决策模型
 *     A/B 切换（D4：active 指针 + arm/confirm 单槽 token + 观察窗自动
 *     换回）、think 路径 -ETIME 回退 builtin 启发式（D2/D5）、模型
 *     enumerate 扩展（D3：slot/hash/bytes/infer_n/last_lat_ns/timeout_n）。
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
#include "../reflex/ai_model_mlp.h"
#include "ai_telemetry.h"
#include "ai_policy.h"
#include "../senses/ai_netlink.h"
#include "../boundary/ai_chain.h"

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

/* ---- K6 D2：推理预算全局（/sys/kernel/ai/model_infer_budget_ns，B 路写） ---- */

static atomic64_t ai_rt_infer_budget_ns =
	ATOMIC64_INIT(AI_RUNTIME_INFER_BUDGET_DEFAULT_NS);

/* 命名随 B 路 sysfs/测试已固化的 de-facto 契约（ai_sysfs.c/ai_runtime_
 * test.c 调用 ai_model_infer_budget_ns_get/set） */
u64 ai_model_infer_budget_ns_get(void)
{
	return (u64)atomic64_read(&ai_rt_infer_budget_ns);
}
EXPORT_SYMBOL_GPL(ai_model_infer_budget_ns_get);

int ai_model_infer_budget_ns_set(u64 budget_ns)
{
	atomic64_set(&ai_rt_infer_budget_ns, (s64)budget_ns);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_model_infer_budget_ns_set);

/* ---- K6 D4：决策模型 A/B 切换状态（全部字段由 ai_runtime_lock 保护） ---- */

/*
 * active 指针：当前决策模型（默认内置 decide）。active 槽持 1 个"在值
 * 引用"（独立于注册表引用），保证 think 派发期间不被卸载释放；观察窗
 * 持 1 个保活引用（confirm 后旧模型的在值引用转入观察窗）。两引用的
 * 释放点：切换换新/观察窗结束/自动换回/模型卸载（ai_rt_switch_on_unload_
 * locked 先放引用再等待归零，避免 finish_unload 永等）。
 */
static struct {
	struct ai_model *active;        /* active 决策模型（持在值引用） */
	struct {
		bool armed;              /* 单槽：armed 再 arm → -EBUSY */
		u64  token;              /* FNV64a 无状态派生（K2c 同款手法） */
		char target_name[AI_MAX_NAME_LEN];
		u32  target_id;          /* 单调句柄：与名字双重校验防换血 */
	} pend;
	struct {
		struct ai_model *old;    /* 观察窗保活旧模型（持保活引用） */
		u32 window;              /* 窗长（0=关；confirm 时采样） */
		u32 remaining;
		u32 errors;
	} obs;
} ai_rt_sw = {
	.obs = { .window = AI_RUNTIME_OBSERVE_DEFAULT },
};

/* 无状态 token 派生（K2c ai_policy.c:740 手法同款自建：offset basis
 * 0xcbf29ce484222325 / prime 0x100000001b3；u64 小端逐字节 xor-mul。
 * 不复用 policy 单槽——模型切换自建独立槽位） */
#define AI_SW_FNV_OFFSET	0xcbf29ce484222325ULL
#define AI_SW_FNV_PRIME		0x100000001b3ULL
#define AI_SW_OBSERVE_MAX	1000u

static u64 ai_sw_fnv64a_mix(u64 h, u64 v)
{
	u8 k;

	for (k = 0; k < 8; k++) {
		h ^= (u8)v;
		h *= AI_SW_FNV_PRIME;
		v >>= 8;
	}
	return h;
}

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
 * 决策模型查找（K6 D4 改读 active 指针）：返回时已持有读者引用（调用者
 * 负责 ai_model_put）。active 缺位/退册中/不可 think 时回退内置 decide
 * 兜底（切换窗/自动换回间隙零停机）；@is_active 回填本次派发是否命中
 * active（观察窗只对 active 派发计数）。
 * 调用者必须持 ai_runtime_lock。
 */
static struct ai_model *ai_model_get_decision_locked(bool *is_active)
{
	struct ai_model *m = ai_rt_sw.active;

	if (is_active)
		*is_active = false;
	if (m && m->state == AI_MODEL_STATE_LOADED && !m->dying &&
	    m->ops && m->ops->think &&
	    refcount_inc_not_zero(&m->refcount)) {
		if (is_active)
			*is_active = true;
		return m;
	}
	/* 内置 decide 兜底：active 不可用的窗口期决策仍走启发式直通 */
	m = &ai_rt_decide_model;
	if (m->state == AI_MODEL_STATE_LOADED && !m->dying &&
	    m->ops && m->ops->think &&
	    refcount_inc_not_zero(&m->refcount))
		return m;
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

/* ---- K6 D4：决策模型 A/B 切换（arm → 冒烟 → confirm → 观察窗） ---- */

/*
 * 模型卸载时收尾切换状态（调用者已退册 @m、持 ai_runtime_lock、
 * 尚未进入 finish_unload 的引用等待）：布防目标随卸载作废；观察窗
 * 保活引用释放；active 在值引用释放并自动回退内置 decide。
 * 待释放引用经 @put_a/@put_b 带出，调用者在锁外 ai_model_put——
 * 必须先于 finish_unload 的 wait_for_completion，否则在值/保活引用
 * 令其永等。
 */
static void ai_rt_switch_on_unload_locked(struct ai_model *m,
					  struct ai_model **put_a,
					  struct ai_model **put_b)
{
	*put_a = NULL;
	*put_b = NULL;

	if (ai_rt_sw.pend.armed && ai_rt_sw.pend.target_id == m->id) {
		ai_rt_sw.pend.armed = false;
		pr_info("AIKernel: model_switch arm cancelled (target '%s' unloading)\n",
			m->name);
	}
	if (ai_rt_sw.obs.old == m) {
		*put_a = m;   /* 观察保活引用 */
		ai_rt_sw.obs.old = NULL;
		pr_info("AIKernel: model_switch observation window "
			"closed (old '%s' unloading)\n", m->name);
	}
	if (ai_rt_sw.active == m) {
		*put_b = m;   /* active 在值引用 */
		ai_rt_sw.active = NULL;
		if (ai_rt_decide_model.state == AI_MODEL_STATE_LOADED &&
		    !ai_rt_decide_model.dying &&
		    refcount_inc_not_zero(&ai_rt_decide_model.refcount))
			ai_rt_sw.active = &ai_rt_decide_model;
		pr_info("AIKernel: active decision model '%s' unloading -> %s\n",
			m->name,
			ai_rt_sw.active ? "builtin decide" : "no decision model");
		/* K8：active 卸载自动回退铸链（REVERT；builtin 无摘要） */
		{
			struct ai_chain_ev_model ev = {
				.op = AI_CHAIN_MODEL_OP_REVERT,
				.model_id = m->id,
			};

			ai_chain_append(AI_CHAIN_KIND_MODEL_EVENT, &ev,
					 sizeof(ev));
		}
	}
}

/* 冒烟推理（D4「固定微输入」）：
 *   - think 模型：固定微 sense 载荷（decide 直通格式）；
 *   - infer-only 模型（如 MLP）：固定微输入向量（1KB 零填充）——输入维
 *     超过微输入容量的模型（如 in_dim=1024 需 4KB）在 infer 维度检查处
 *     自然拒切；输出缓冲按最大输出维（4KB）备足。
 *   失败（含 infer -ETIME 预算超限）或耗时超全局预算 → 拒切（-EIO，
 *   active 不动）。调用者持目标读者引用，进程上下文（kzalloc 可睡眠）。 */
#define AI_SW_SMOKE_IN_BYTES	1024u   /* 256 float 微输入 */
#define AI_SW_SMOKE_OUT_BYTES	4096u   /* 最大输出维 1024 float */

static int ai_rt_switch_smoke(struct ai_model *m)
{
	struct ai_sense_input sense;
	struct ai_think_result res;
	struct ai_sense_decision d;
	u8 *in = NULL, *out = NULL;
	size_t out_len;
	u64 t0, lat, budget;
	int rc;

	budget = ai_model_infer_budget_ns_get();
	t0 = ktime_get_ns();

	if (m->ops->think) {
		memset(&sense, 0, sizeof(sense));
		memset(&res, 0, sizeof(res));
		memset(&d, 0, sizeof(d));
		d.confidence = 100;
		d.value = 1;
		sense.ts = t0;
		sense.data_len = sizeof(d);
		memcpy(sense.data, &d, sizeof(d));
		rc = m->ops->think(m, &sense, &res);
	} else if (m->ops->infer) {
		in = kzalloc(AI_SW_SMOKE_IN_BYTES, GFP_KERNEL);
		out = kzalloc(AI_SW_SMOKE_OUT_BYTES, GFP_KERNEL);
		if (!in || !out) {
			kfree(in);
			kfree(out);
			return -ENOMEM;
		}
		out_len = AI_SW_SMOKE_OUT_BYTES;
		rc = m->ops->infer(m, in, AI_SW_SMOKE_IN_BYTES, out,
				   &out_len, NULL);
	} else {
		return -EIO;   /* think/infer 皆无（arm 预检后理论不可达） */
	}
	lat = ktime_get_ns() - t0;
	kfree(in);
	kfree(out);

	if (rc != AI_OK) {
		pr_info("AIKernel: model_switch smoke failed '%s' (rc=%d)\n",
			m->name, rc);
		return -EIO;
	}
	if (budget && lat > budget) {
		pr_info("AIKernel: model_switch smoke over budget '%s' "
			"(%lluns > %lluns)\n", m->name, lat, budget);
		return -EIO;
	}
	return 0;
}

int ai_runtime_model_switch_arm(const char *name, u64 *token)
{
	struct ai_model *target;
	u64 h, t0;
	unsigned int i;
	int rc;

	if (!name || !name[0] || !token)
		return -EINVAL;
	if (!ai_runtime_ready())
		return -EIO;

	mutex_lock(&ai_runtime_lock);
	if (ai_rt_sw.pend.armed) {
		mutex_unlock(&ai_runtime_lock);
		return -EBUSY;   /* v1 单槽：诚实拒 */
	}
	target = ai_model_get_by_name_locked(name);
	mutex_unlock(&ai_runtime_lock);

	if (!target)
		return -ENOENT;
	if (!target->ops || (!target->ops->think && !target->ops->infer)) {
		/* 冒烟推理无路可走：拒切（think 模型走微 sense、infer-only
		 * 模型如 MLP 走固定微输入——均无法执行者拒切） */
		pr_info("AIKernel: model_switch refused '%s' (no think/infer op)\n",
			target->name);
		ai_model_put(target);
		return -EIO;
	}

	/* 冒烟推理在锁外（think 可睡眠/耗时；读者引用护住生命周期） */
	rc = ai_rt_switch_smoke(target);
	if (rc) {
		ai_model_put(target);
		return rc;   /* -EIO：拒切，active 不动 */
	}

	/* token = FNV64a(id + name + arm 时刻)：同一目标两次 arm token 不同 */
	t0 = ktime_get_ns();
	h = ai_sw_fnv64a_mix(AI_SW_FNV_OFFSET, target->id);
	for (i = 0; i < sizeof(target->name) && target->name[i]; i++)
		h = ai_sw_fnv64a_mix(h, (u8)target->name[i]);
	h = ai_sw_fnv64a_mix(h, t0);

	mutex_lock(&ai_runtime_lock);
	if (ai_rt_sw.pend.armed || ai_rt.state != AI_RT_STATE_READY) {
		mutex_unlock(&ai_runtime_lock);
		ai_model_put(target);
		return ai_rt.state != AI_RT_STATE_READY ? -EIO : -EBUSY;
	}
	ai_rt_sw.pend.target_id = target->id;
	strscpy(ai_rt_sw.pend.target_name, target->name,
		sizeof(ai_rt_sw.pend.target_name));
	ai_rt_sw.pend.token = h;
	ai_rt_sw.pend.armed = true;
	mutex_unlock(&ai_runtime_lock);

	*token = h;
	/* K8：布防成功铸链（ARM；冒烟已过，token 不入链） */
	{
		struct ai_chain_ev_model ev = {
			.op = AI_CHAIN_MODEL_OP_ARM,
			.model_id = target->id,
		};

		ai_chain_append(AI_CHAIN_KIND_MODEL_EVENT, &ev, sizeof(ev));
	}
	pr_info("AIKernel: model_switch armed '%s' (id=%u, smoke ok)\n",
		name, target->id);
	ai_model_put(target);
	return 0;
}
EXPORT_SYMBOL_GPL(ai_runtime_model_switch_arm);

int ai_runtime_model_switch_confirm(u64 token)
{
	struct ai_model *target = NULL, *old_active = NULL, *old_obs = NULL;
	const char *tname;
	int rc = 0;

	mutex_lock(&ai_runtime_lock);
	if (!ai_rt_sw.pend.armed || ai_rt_sw.pend.token != token) {
		rc = -ENOENT;   /* 未布防 / token 失配（K2c confirm 同款语义） */
		goto out;
	}
	if (ai_rt.state != AI_RT_STATE_READY) {
		rc = -EIO;
		goto out;
	}
	target = ai_model_get_by_id_locked(ai_rt_sw.pend.target_id);
	if (!target || strcmp(target->name, ai_rt_sw.pend.target_name) != 0) {
		rc = -ENOENT;   /* 布防目标已被卸载/换血 */
		goto out;
	}
	if (target == ai_rt_sw.active) {
		ai_rt_sw.pend.armed = false;
		pr_info("AIKernel: model_switch confirm no-op ('%s' already active)\n",
			target->name);
		goto out;   /* target 读者引用经 out 释放 */
	}

	/* 生效：读者引用转为 active 在值引用（不重复计数） */
	ai_rt_sw.pend.armed = false;
	old_active = ai_rt_sw.active;
	ai_rt_sw.active = target;
	target = NULL;   /* 引用已转移，勿再 put */
	tname = ai_rt_sw.active->name;

	/* 残留观察窗防御性收尾（正常路径 confirm 时窗必已结束） */
	if (ai_rt_sw.obs.old) {
		old_obs = ai_rt_sw.obs.old;
		ai_rt_sw.obs.old = NULL;
	}

	if (ai_rt_sw.obs.window) {
		/* 旧模型在值引用转入观察窗保活（不重复计数）；观察期其
		 * unload 语义不变（卸载即关窗释放，见 on_unload_locked） */
		ai_rt_sw.obs.old = old_active;
		ai_rt_sw.obs.remaining = ai_rt_sw.obs.window;
		ai_rt_sw.obs.errors = 0;
		old_active = NULL;
		pr_info("AIKernel: model_switch confirmed '%s' active "
			"(old '%s' kept for obs window %u)\n",
			tname, ai_rt_sw.obs.old->name, ai_rt_sw.obs.window);
	} else {
		pr_info("AIKernel: model_switch confirmed '%s' active "
			"(observation off, old released)\n", tname);
	}

	/* K8：切换生效铸链（两分支共用尾；no-op 路径已 goto out 不经此） */
	{
		struct ai_chain_ev_model ev = {
			.op = AI_CHAIN_MODEL_OP_CONFIRM,
			.model_id = ai_rt_sw.active->id,
		};

		ai_chain_append(AI_CHAIN_KIND_MODEL_EVENT, &ev, sizeof(ev));
	}
out:
	mutex_unlock(&ai_runtime_lock);
	if (target)
		ai_model_put(target);       /* 未生效路径：读者引用退还 */
	if (old_active)
		ai_model_put(old_active);   /* 窗关：旧 active 在值引用释放 */
	if (old_obs)
		ai_model_put(old_obs);      /* 残留窗：保活引用释放 */
	return rc;
}
EXPORT_SYMBOL_GPL(ai_runtime_model_switch_confirm);

int ai_runtime_switch_observe(unsigned int n)
{
	if (n > AI_SW_OBSERVE_MAX)
		return -EINVAL;

	mutex_lock(&ai_runtime_lock);
	ai_rt_sw.obs.window = n;
	mutex_unlock(&ai_runtime_lock);
	pr_info("AIKernel: model_switch observation window -> %u%s\n",
		n, n ? "" : " (off)");
	return 0;
}
EXPORT_SYMBOL_GPL(ai_runtime_switch_observe);

/*
 * 观察窗计数（触发点：ai_runtime_think 错误/超时路径）。
 * @dispatched：本次派发的模型（仅指针身份比较，用于确认派发对象是
 * 当前 active——观察窗只盯新模型）；@err：本次 think 是否失败。
 * 错误超半（2*errors > window）→ 自动换回旧模型 + 审计；窗口走完 →
 * 释放旧模型保活引用（正常 unload 语义恢复）。
 */
static void ai_rt_observe_tick(struct ai_model *dispatched, bool err)
{
	struct ai_model *revert_from = NULL, *release = NULL;

	mutex_lock(&ai_runtime_lock);
	if (!ai_rt_sw.obs.old || dispatched != ai_rt_sw.active)
		goto out;

	if (ai_rt_sw.obs.remaining)
		ai_rt_sw.obs.remaining--;
	if (err) {
		ai_rt_sw.obs.errors++;
		if (2u * ai_rt_sw.obs.errors > ai_rt_sw.obs.window) {
			revert_from = ai_rt_sw.active;
			ai_rt_sw.active = NULL;
			if (ai_rt_sw.obs.old->state == AI_MODEL_STATE_LOADED &&
			    !ai_rt_sw.obs.old->dying &&
			    refcount_inc_not_zero(&ai_rt_sw.obs.old->refcount)) {
				/* 旧模型站得住：另取在值引用，观察保活引用释放 */
				ai_rt_sw.active = ai_rt_sw.obs.old;
			}
			/* 无论换回与否，观察保活引用在此释放（旧模型不可用
			 * 时 active 空缺，think 由内置 decide 兜底零停机） */
			release = ai_rt_sw.obs.old;
			ai_rt_sw.obs.old = NULL;
			pr_info("AIKernel: model_switch auto-reverted -> %s "
				"(errors %u/%u in window)\n",
				ai_rt_sw.active ? ai_rt_sw.active->name
						: "builtin decide",
				ai_rt_sw.obs.errors, ai_rt_sw.obs.window);
		}
	}
	if (ai_rt_sw.obs.old && !ai_rt_sw.obs.remaining) {
		/* 窗口走完：新模型站住 */
		release = ai_rt_sw.obs.old;
		ai_rt_sw.obs.old = NULL;
		pr_info("AIKernel: model_switch observation window passed "
			"(new model stands, old released)\n");
	}
out:
	mutex_unlock(&ai_runtime_lock);
	if (revert_from)
		ai_model_put(revert_from);
	if (release)
		ai_model_put(release);
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
	if (rc != AI_OK) {
		pr_err("AIKernel: built-in decide model load failed (%d)\n", rc);
	} else {
		/* K6 D4：active 指针默认内置 decide（取在值引用，destroy 释放） */
		mutex_lock(&ai_runtime_lock);
		if (refcount_inc_not_zero(&ai_rt_decide_model.refcount))
			ai_rt_sw.active = &ai_rt_decide_model;
		mutex_unlock(&ai_runtime_lock);
	}

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

	/* K6 D4：先行释放切换状态（布防作废/观察窗关闭/active 在值引用退还），
	 * 否则下方逐模型 finish_unload 的引用等待会被在值/保活引用卡死 */
	{
		struct ai_model *put_active, *put_obs;

		mutex_lock(&ai_runtime_lock);
		ai_rt_sw.pend.armed = false;
		put_obs = ai_rt_sw.obs.old;
		ai_rt_sw.obs.old = NULL;
		put_active = ai_rt_sw.active;
		ai_rt_sw.active = NULL;
		mutex_unlock(&ai_runtime_lock);
		if (put_obs)
			ai_model_put(put_obs);
		if (put_active)
			ai_model_put(put_active);
	}

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
		struct ai_model *put_a, *put_b;

		if (ai_rt.models[i] != model)
			continue;
		if (model->state == AI_MODEL_STATE_LOADING) {
			rc = AI_ERR_BUSY;   /* ops->load 未完成，不可卸载 */
			break;
		}
		strscpy(name, model->name, sizeof(name));
		id = model->id;
		ai_model_retire_locked(model);
		/* K6 D4：active/观察窗/布防涉及本模型 → 先放引用再等待归零 */
		ai_rt_switch_on_unload_locked(model, &put_a, &put_b);
		mutex_unlock(&ai_runtime_lock);
		if (put_a)
			ai_model_put(put_a);
		if (put_b)
			ai_model_put(put_b);
		rc = AI_OK;
		goto finish;
	}
	mutex_unlock(&ai_runtime_lock);

finish:
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
		struct ai_model *put_a, *put_b;

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
			/* K6 D4：active/观察窗/布防涉及本模型 → 先放引用再等待 */
			ai_rt_switch_on_unload_locked(m, &put_a, &put_b);
			mutex_unlock(&ai_runtime_lock);
			if (put_a)
				ai_model_put(put_a);
			if (put_b)
				ai_model_put(put_b);
			rc = AI_OK;
			goto out;
		}
		break;
	}
	mutex_unlock(&ai_runtime_lock);
out:

	if (rc == AI_OK && model)
		ai_model_finish_unload(model, found_name, id);

	mutex_unlock(&ai_model_lifecycle_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_model_unload_by_name);

int ai_model_enumerate(unsigned int index, char *name, u32 *version,
		       u32 *source, u32 *state, u64 *hash, u64 *bytes,
		       u64 *infer_n, u64 *last_lat_ns, u64 *timeout_n,
		       u32 *slot)
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
		/* K6 D3 扩展（可选出参全 NULL 兼容旧调用面） */
		if (slot)
			*slot = (found == ai_rt_sw.active) ?
				AI_MODEL_SLOT_ACTIVE :
				(found == ai_rt_sw.obs.old) ?
				AI_MODEL_SLOT_STANDBY : AI_MODEL_SLOT_NORMAL;
		if (hash || bytes || infer_n || last_lat_ns || timeout_n) {
			struct ai_model_mlp_meta meta;

			if (ai_mlp_model_meta(found, &meta) == AI_OK) {
				if (hash) {   /* sha256 前 6 字节序数（%012llx 渲染） */
					*hash = ((u64)meta.sha256[0] << 40) |
						((u64)meta.sha256[1] << 32) |
						((u64)meta.sha256[2] << 24) |
						((u64)meta.sha256[3] << 16) |
						((u64)meta.sha256[4] << 8) |
						(u64)meta.sha256[5];
				}
				if (bytes)
					*bytes = meta.file_bytes;
				if (infer_n)
					*infer_n = meta.infer_n;
				if (last_lat_ns)
					*last_lat_ns = meta.last_lat_ns;
				if (timeout_n)
					*timeout_n = meta.timeout_n;
			} else if (hash || bytes || infer_n || last_lat_ns ||
				   timeout_n) {
				/* 非 MLP：扩展字段置 0（元数据无） */
				if (hash)
					*hash = 0;
				if (bytes)
					*bytes = 0;
				if (infer_n)
					*infer_n = 0;
				if (last_lat_ns)
					*last_lat_ns = 0;
				if (timeout_n)
					*timeout_n = 0;
			}
		}
	}
	mutex_unlock(&ai_runtime_lock);
	return found ? AI_OK : AI_ERR_NOT_FOUND;
}
EXPORT_SYMBOL_GPL(ai_model_enumerate);

/*
 * K6 D3：enumerate 扩展——/proc/ai/models（B 路 procfs 渲染）数据源。
 * 集成裁定（主会话）：主实现=ai_model_enumerate 11 参原地扩展
 * （ai_model.h），本函数降为薄包装（struct 出参 + 12hex 字符串哈希），
 * 消除双轨。
 */
int ai_model_enumerate_info(unsigned int index, struct ai_model_info *info)
{
	u64 hash = 0, bytes = 0, infer_n = 0, last_lat = 0, timeout_n = 0;
	u32 slot = AI_MODEL_SLOT_NORMAL;
	int rc;

	if (!info)
		return AI_ERR_INVALID_ARG;

	rc = ai_model_enumerate(index, info->name, &info->version,
				&info->source, &info->state, &hash, &bytes,
				&infer_n, &last_lat, &timeout_n, &slot);
	if (rc != AI_OK)
		return rc;
	info->slot = slot;
	info->file_bytes = bytes;
	info->infer_n = infer_n;
	info->last_lat_ns = last_lat;
	info->timeout_n = timeout_n;
	snprintf(info->hash, sizeof(info->hash), "%012llx", hash);
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_model_enumerate_info);

/* ---- 决策推理（感知 → 决策 → 执行） ---- */

int ai_runtime_think(const struct ai_sense_input *sense,
		     struct ai_think_result *res)
{
	struct ai_model *model;
	u32 model_version;
	bool is_active, think_err;
	int rc;

	if (!sense || !res)
		return AI_ERR_INVALID_ARG;
	if (!ai_runtime_ready())
		return AI_ERR_DISABLED;

	memset(res, 0, sizeof(*res));

	mutex_lock(&ai_runtime_lock);
	model = ai_model_get_decision_locked(&is_active);
	mutex_unlock(&ai_runtime_lock);

	if (!model)
		return AI_ERR_NO_MODEL;

	model_version = model->version;
	rc = model->ops->think(model, sense, res);
	think_err = (rc != AI_OK);

	/* K6 D2/D5：推理超时（-ETIME，如 MLP 冒烟/决策模型预算超限）→
	 * 回退 builtin decide 启发式直通分支（决策仍成功，零停机）；
	 * 该模型 timeout_n++（D2 统计，MLP 经 note_timeout 记账）+
	 * 观察窗计数。think_execute 经 think 传导同一路径 */
	if (rc == -ETIME) {
		pr_info_ratelimited("AIKernel: think timeout (model '%s' v%u) "
				    "-> fallback builtin decide\n",
				    model->name, model->version);
		ai_mlp_model_note_timeout(model);
		rc = ai_rt_decide_think(&ai_rt_decide_model, sense, res);
		if (rc == AI_OK)
			model_version = ai_rt_decide_model.version;
	}

	/* K6 D4：观察窗触发点（think 错误/超时；仅派发对象为 active 时计数，
	 * 读者引用未放——指针身份比较安全） */
	if (is_active)
		ai_rt_observe_tick(model, think_err);

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

/*
 * K6 D2：第 7 参 budget_ns——调用方从全局取（B 路 sysfs 传
 * ai_model_infer_budget_ns_get()）或显式传值（测试 1ns 强制超时）。
 * budget_ns>0 经 MLP 直达通道把预算送进 Q31 前向（ops->infer 签名
 * 冻约在共享头 ai_model.h，不带预算参）；非 MLP 模型或 budget_ns==0
 * 走 ops->infer（MLP 适配层自取全局预算）。两种路径的预算语义一致：
 * 入场 ktime 锚定、层粒度检查、超时 -ETIME 不写 output。
 */
int ai_runtime_model_infer_by_name(const char *name, const void *input,
				   size_t in_len, void *output,
				   size_t *out_len, u64 *latency_ns,
				   u64 budget_ns)
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

	if (budget_ns) {
		rc = ai_mlp_model_infer(model, input, in_len, output,
					out_len, latency_ns, budget_ns);
		if (rc != -ENODEV) {
			ai_model_put(model);
			return rc;   /* MLP：显式预算直达 */
		}
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
