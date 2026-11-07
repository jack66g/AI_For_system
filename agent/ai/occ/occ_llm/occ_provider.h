/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_provider.h - occ provider 最小注册表（T9a1：仅结构 + model.toml
 * [models.cloud] 读取；完整目录/catalog/多 provider 正典是 a2 棒，不越界）
 *
 * model.toml 键面（L1 实况，值不落日志）：
 *   [models.cloud] provider_type / model_name / base_url / api_key
 *   provider_type 取值（provider.toml [providers].available）：openai_compatible
 */
#ifndef _OCC_PROVIDER_H
#define _OCC_PROVIDER_H

#include "occ_llm.h"

#define OCC_PROVIDER_NAME_MAX 64
#define OCC_PROVIDER_URL_MAX 256
#define OCC_PROVIDER_MODEL_MAX 96

typedef struct occ_provider {
	char name[OCC_PROVIDER_NAME_MAX];	/* 槽位名（"cloud"） */
	occ_protocol proto;
	char base_url[OCC_PROVIDER_URL_MAX];
	char model[OCC_PROVIDER_MODEL_MAX];
	char *api_key;				/* heap；绝不打印/落日志 */
} occ_provider;

/* provider_type 字符串 → 协议；未知返回 -1 */
occ_protocol occ_protocol_from_type(const char *provider_type);

/*
 * occ_provider_load_cloud - 读 toml 的 [models.cloud] 段（dtchat 式行扫描）
 * 段缺/键缺 → -1；成功 0（api_key 无则空串）。
 */
int occ_provider_load_cloud(occ_provider *p, const char *toml_path);

void occ_provider_free(occ_provider *p);	/* 释放 api_key 并清零 */

/*
 * occ_llm_call - 一次流式调用（构造请求 → cloud/http https_post_stream
 * → occ_sse 消费 → 事件回调）。err_out 可 NULL；成功 0。
 * 事件流即 occ_event_cb（含 OCC_EV_USAGE 账本钩子）。
 */
int occ_llm_call(const occ_provider *p, const occ_llm_req *req,
		 occ_event_cb cb, void *ud, char **err_out);

/* ---- 多 provider 正典（T9a2；OPENCODE-PLAN §2.3） ---- */

#define OCC_TOML_ID_MAX 64

/*
 * occ_model_slot - model.toml [models.<id>] 槽位。
 * 两种形态（与 L1 现有单 deepseek 配置兼容）：
 *   旧式（a1）：provider_type/model_name/base_url/api_key 直填；
 *   引用式：provider = "<name>" → [provider.<name>] 的 base_url/key/type
 *   （model/base_url 可在槽位覆盖 provider 段缺省）。
 */
typedef struct occ_model_slot {
	char id[OCC_TOML_ID_MAX];		/* [models.<id>] 的 <id> */
	char provider_ref[OCC_TOML_ID_MAX];	/* provider 引用；空=直填式 */
	char provider_type[48];			/* provider_type 直填 */
	occ_protocol proto;			/* 解析后的协议 */
	char base_url[OCC_PROVIDER_URL_MAX];
	char model[OCC_PROVIDER_MODEL_MAX];
	char *api_key;				/* heap 或 NULL（引用式为
						 * NULL——key 在 provider 段） */
} occ_model_slot;

/* occ_provider_def - model.toml [provider.<name>] 段（key/base_url） */
typedef struct occ_provider_def {
	char name[OCC_TOML_ID_MAX];
	char type[48];				/* 缺省 openai_compatible */
	occ_protocol proto;
	char base_url[OCC_PROVIDER_URL_MAX];
	char *api_key;				/* key；heap 或 NULL */
} occ_provider_def;

/*
 * occ_provider_config - 一份 model.toml（+可选 provider.toml 类型表）的
 * 全量解析结果。malformed=被容错跳过的坏段数（不炸进程）。
 */
typedef struct occ_provider_config {
	occ_model_slot *slots;			/* [models.*] */
	size_t nslots, slots_cap;
	occ_provider_def *providers;		/* [provider.*] */
	size_t nproviders, providers_cap;
	char available_types[16][32];		/* provider.toml [providers]
						 * available 数组（结构对齐
						 * L1 ~/.aikernel/provider.toml） */
	size_t navailable;
	size_t malformed;
} occ_provider_config;

void occ_provider_config_init(occ_provider_config *cfg);
void occ_provider_config_free(occ_provider_config *cfg);

/*
 * occ_provider_load_all - 解析 model.toml 全部 [models.*]/[provider.*] 段
 * + provider.toml 的 [providers] available 类型表（provider_toml 可 NULL
 * =跳过类型表）。model_toml 不可读 → -1；其余容错（缺键段跳过计
 * malformed）。api_key 绝不落日志。
 */
int occ_provider_load_all(occ_provider_config *cfg, const char *model_toml,
			  const char *provider_toml);

/*
 * occ_provider_resolve - 槽位 → 可调用的 occ_provider（解析 provider 引用
 * 链：槽位缺 base_url/key 时取 [provider.<ref>] 补齐）。槽位缺协议/无
 * base_url → -1。api_key 归 out 所有（occ_provider_free 清零释放）。
 */
int occ_provider_resolve(const occ_provider_config *cfg, const char *slot_id,
			 occ_provider *out);

/*
 * occ_provider_toml_add_slot - 向导写辅助：[models.<slot->id>] 段整段
 * 替换（不存在则文件尾追加）。原子写（<path>.tmp → chmod 600 →
 * rename）；api_key=NULL 则不写该键。成功 0。
 */
int occ_provider_toml_add_slot(const char *toml_path,
			       const occ_model_slot *slot);

/* 同上，写 [provider.<def->name>] 段（type/key/base_url） */
int occ_provider_toml_add_provider(const char *toml_path,
				   const occ_provider_def *def);

#endif /* _OCC_PROVIDER_H */
