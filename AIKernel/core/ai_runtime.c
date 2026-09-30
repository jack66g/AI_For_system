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
 * 后续 Prompt 填充：推理调度、模型加载器、多模型路由。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <generated/utsrelease.h>
#include "ai_runtime.h"
#include "ai_telemetry.h"
#include "ai_policy.h"

#define AI_RUNTIME_MAX_MODELS      16   /* 模型注册表容量 */
#define AI_RUNTIME_MAX_CALLBACKS   8    /* 回调表容量 */

static struct ai_runtime_ctx {
	enum ai_runtime_state state;
	struct ai_model *models[AI_RUNTIME_MAX_MODELS];
	unsigned int model_count;
	struct {
		ai_runtime_callback_t cb;
		void *priv;
	} callbacks[AI_RUNTIME_MAX_CALLBACKS];
	unsigned int callback_count;
} ai_rt = {
	.state = AI_RT_STATE_DOWN,
};

static DEFINE_MUTEX(ai_runtime_lock);

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

int ai_runtime_init(void)
{
	int rc;

	mutex_lock(&ai_runtime_lock);
	if (ai_rt.state != AI_RT_STATE_DOWN) {
		mutex_unlock(&ai_runtime_lock);
		return AI_OK;   /* 幂等 */
	}

	ai_rt.state = AI_RT_STATE_INIT;
	mutex_unlock(&ai_runtime_lock);

	rc = ai_telemetry_init();
	if (rc != AI_OK) {
		pr_err("AIKernel: telemetry init failed (%d)\n", rc);
		ai_rt.state = AI_RT_STATE_DOWN;
		return rc;
	}

	ai_rt.state = AI_RT_STATE_READY;

	/* 内置决策模型（Prompt 13）：用户态下发模型可覆盖/替换 */
	ai_model_load(&ai_rt_decide_model);

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
	return AI_OK;
}
EXPORT_SYMBOL_GPL(ai_runtime_init);

void ai_runtime_destroy(void)
{
	if (ai_rt.state == AI_RT_STATE_DOWN)
		return;

	ai_rt.state = AI_RT_STATE_INIT;
	ai_telemetry_exit();

	mutex_lock(&ai_runtime_lock);
	ai_rt.model_count = 0;
	ai_rt.callback_count = 0;
	mutex_unlock(&ai_runtime_lock);

	ai_rt.state = AI_RT_STATE_DOWN;
	pr_info("AIKernel: AI Runtime destroyed\n");
}
EXPORT_SYMBOL_GPL(ai_runtime_destroy);

int ai_runtime_get_state(void)
{
	return ai_rt.state;
}
EXPORT_SYMBOL_GPL(ai_runtime_get_state);

/* ---- 模型注册表 ---- */

int ai_model_load(struct ai_model *model)
{
	unsigned int i;
	int rc;

	if (!model || !model->name[0] || !model->ops)
		return AI_ERR_INVALID_ARG;
	if (ai_rt.state != AI_RT_STATE_READY)
		return AI_ERR_DISABLED;

	mutex_lock(&ai_runtime_lock);

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

	ai_rt.models[ai_rt.model_count] = model;
	model->id = ai_rt.model_count + 1;   /* 句柄 1 起 */
	model->state = AI_MODEL_STATE_LOADED;
	ai_rt.model_count++;
	rc = AI_OK;

	mutex_unlock(&ai_runtime_lock);

	if (rc == AI_OK && model->ops->load)
		rc = model->ops->load(model);

	pr_info("AIKernel: model '%s' v%u loaded (id=%u)\n",
		model->name, model->version, model->id);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_model_load);

int ai_model_unload(struct ai_model *model)
{
	unsigned int i;
	int rc = AI_ERR_NOT_FOUND;

	if (!model)
		return AI_ERR_INVALID_ARG;

	if (model->ops && model->ops->unload)
		model->ops->unload(model);

	mutex_lock(&ai_runtime_lock);
	for (i = 0; i < ai_rt.model_count; i++) {
		if (ai_rt.models[i] == model) {
			memmove(&ai_rt.models[i], &ai_rt.models[i + 1],
				(ai_rt.model_count - i - 1) * sizeof(model));
			ai_rt.model_count--;
			model->state = AI_MODEL_STATE_UNLOADED;
			rc = AI_OK;
			break;
		}
	}
	mutex_unlock(&ai_runtime_lock);

	pr_info("AIKernel: model '%s' unloaded\n", model->name);
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
		if (strcmp(ai_rt.models[i]->name, name) == 0) {
			rc = (int)ai_rt.models[i]->id;
			break;
		}
	}
	mutex_unlock(&ai_runtime_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_model_find);

int ai_model_unload_by_name(const char *name)
{
	unsigned int i;
	int rc = AI_ERR_NOT_FOUND;

	if (!name)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_runtime_lock);
	for (i = 0; i < ai_rt.model_count; i++) {
		if (strcmp(ai_rt.models[i]->name, name) == 0) {
			struct ai_model *model = ai_rt.models[i];

			if (model->ops && model->ops->unload)
				model->ops->unload(model);
			memmove(&ai_rt.models[i], &ai_rt.models[i + 1],
				(ai_rt.model_count - i - 1) * sizeof(model));
			ai_rt.model_count--;
			model->state = AI_MODEL_STATE_UNLOADED;
			rc = AI_OK;
			pr_info("AIKernel: model '%s' unloaded\n", name);
			break;
		}
	}
	mutex_unlock(&ai_runtime_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_model_unload_by_name);

int ai_model_enumerate(unsigned int index, char *name, u32 *version,
		       u32 *source, u32 *state)
{
	int rc = AI_ERR_NOT_FOUND;

	if (!name)
		return AI_ERR_INVALID_ARG;

	mutex_lock(&ai_runtime_lock);
	if (index < ai_rt.model_count) {
		struct ai_model *model = ai_rt.models[index];

		strscpy(name, model->name, AI_MAX_NAME_LEN);
		if (version)
			*version = model->version;
		if (source)
			*source = model->source;
		if (state)
			*state = model->state;
		rc = AI_OK;
	}
	mutex_unlock(&ai_runtime_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_model_enumerate);

/* ---- 决策推理（感知 → 决策 → 执行） ---- */

static struct ai_model *ai_rt_find_decision_model(void)
{
	unsigned int i;

	for (i = 0; i < ai_rt.model_count; i++)
		if (ai_rt.models[i]->ops &&
		    ai_rt.models[i]->ops->think)
			return ai_rt.models[i];
	return NULL;
}

int ai_runtime_think(const struct ai_sense_input *sense,
		     struct ai_think_result *res)
{
	struct ai_model *model;
	int rc;

	if (!sense || !res)
		return AI_ERR_INVALID_ARG;
	if (ai_rt.state != AI_RT_STATE_READY)
		return AI_ERR_DISABLED;

	memset(res, 0, sizeof(*res));

	mutex_lock(&ai_runtime_lock);
	model = ai_rt_find_decision_model();
	mutex_unlock(&ai_runtime_lock);

	if (!model)
		return AI_ERR_NO_MODEL;

	rc = model->ops->think(model, sense, res);
	res->model_version = model->version;
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
	struct ai_model *model = NULL;
	unsigned int i;
	int rc;

	if (!name || !name[0] || !input || !output || !out_len)
		return AI_ERR_INVALID_ARG;
	if (ai_rt.state != AI_RT_STATE_READY)
		return AI_ERR_DISABLED;

	mutex_lock(&ai_runtime_lock);
	for (i = 0; i < ai_rt.model_count; i++) {
		if (strcmp(ai_rt.models[i]->name, name) == 0) {
			model = ai_rt.models[i];
			break;
		}
	}
	if (!model || !model->ops || !model->ops->infer) {
		mutex_unlock(&ai_runtime_lock);
		return AI_ERR_NOT_FOUND;
	}
	rc = model->ops->infer(model, input, in_len, output, out_len,
			       latency_ns);
	mutex_unlock(&ai_runtime_lock);
	return rc;
}
EXPORT_SYMBOL_GPL(ai_runtime_model_infer_by_name);

int ai_runtime_chat(struct ai_inference_request *req,
		    struct ai_inference_result *res)
{
	struct ai_model *model = NULL;
	u64 t0, latency;
	unsigned int i;
	int rc;

	if (!req || !res)
		return AI_ERR_INVALID_ARG;
	if (!req->input || !req->output || req->output_len == 0)
		return AI_ERR_INVALID_ARG;
	if (ai_rt.state != AI_RT_STATE_READY)
		return AI_ERR_DISABLED;

	mutex_lock(&ai_runtime_lock);
	for (i = 0; i < ai_rt.model_count; i++) {
		if (ai_rt.models[i]->id == req->model_id) {
			model = ai_rt.models[i];
			break;
		}
	}
	mutex_unlock(&ai_runtime_lock);

	memset(res, 0, sizeof(*res));
	res->request_id = req->id;
	res->model_id = req->model_id;

	if (!model)
		return AI_ERR_NO_MODEL;
	if (!model->ops->infer)
		return AI_ERR_NOT_IMPLEMENTED;

	t0 = ktime_get_ns();
	rc = model->ops->infer(model, req->input, req->input_len,
			       req->output, &req->output_len, &latency);
	latency = ktime_get_ns() - t0;

	res->status = rc;
	res->output_len = req->output_len;
	res->latency_ns = latency;

	if (rc == AI_OK) {
		mutex_lock(&ai_runtime_lock);
		for (i = 0; i < ai_rt.callback_count; i++)
			ai_rt.callbacks[i].cb(res, ai_rt.callbacks[i].priv);
		mutex_unlock(&ai_runtime_lock);
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
	return rc;
}
EXPORT_SYMBOL_GPL(ai_runtime_callback_unregister);
