/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_registry.h - occ 运行时模型注册表与 /models 分组视图（T9a2）
 *
 * 数据来源三方并集（OPENCODE-PLAN §2.2/§2.3/§2.5）：
 *   1. model.toml 配置槽位（occ_provider_config；带 key/base_url——可直调）
 *   2. models.dev 目录快照（occ_catalog；无 key——仅列示/选择后引导接入）
 *   3. ollama 本地发现占位（/api/tags 响应 JSON 由调用方拉取传入；
 *      proto=openai_compat，base_url=http://127.0.0.1:11434/v1 对齐
 *      model.toml [local] 先例）
 *
 * 分组视图（OCD-SPEC §4.1 dialog-model.tsx:102-201）：
 *   Favorites（收藏快照序）/ Recent（最近用过、不在收藏里的）/
 *   按 provider 分组全部（deprecated 过滤）。Recent/Favorites 持久化到
 *   ~/.occ/state.json。
 *
 * 过滤：子串 + 子序列 fuzzy（fuzzysort 观感对齐，不必逐位——连续命中
 * 优先、首字母命中加权）。
 */
#ifndef _OCC_REGISTRY_H
#define _OCC_REGISTRY_H

#include "occ_catalog.h"
#include "occ_llm.h"
#include "occ_provider.h"

#define OCC_REG_MAX 16384			/* 目录+配置+本地并集上限 */
#define OCC_REG_FAV_MAX 64
#define OCC_REG_RECENT_MAX 32
#define OCC_REG_KEY_MAX (OCC_CAT_PROVIDER_MAX + OCC_CAT_ID_MAX + 2)
#define OCC_STATE_PATH_MAX 256

typedef enum {
	OCC_REG_SRC_TOML = 0,		/* model.toml 配置（可直调） */
	OCC_REG_SRC_CATALOG = 1,	/* models.dev 快照（仅列示） */
	OCC_REG_SRC_OLLAMA = 2,		/* 本地 ollama 发现 */
} occ_reg_source;

typedef struct occ_reg_model {
	char provider[OCC_CAT_PROVIDER_MAX];	/* 分组键：provider id */
	char provider_name[OCC_CAT_NAME_MAX];
	char id[OCC_CAT_ID_MAX];		/* 模型 id */
	char display[OCC_CAT_NAME_MAX];		/* 显示名（模型 name） */
	occ_reg_source source;
	occ_protocol proto;			/* 调用协议 */
	char base_url[OCC_PROVIDER_URL_MAX];	/* 配置/本地才有 */
	long long context_limit;		/* 快照/0 */
	int tools;				/* 快照能力位 */
	int is_deprecated;			/* 列表过滤 */
	/* toml 槽位回链（source==TOML 且配置了槽位时；occ_provider_resolve） */
	char slot_id[OCC_TOML_ID_MAX];
} occ_reg_model;

typedef struct occ_registry {
	occ_reg_model *models;		/* heap（init 分配 OCC_REG_MAX 预留；
					 * 结构体 ~10MB 级——禁止栈上实例） */
	size_t nmodels;

	/* 持久化状态（~/.occ/state.json） */
	char favorites[OCC_REG_FAV_MAX][OCC_REG_KEY_MAX];	/* "provider/id" */
	size_t nfavorites;
	char recents[OCC_REG_RECENT_MAX][OCC_REG_KEY_MAX];	/* LRU 序：[0] 最新 */
	size_t nrecents;
} occ_registry;

/* 注册表生命周期：init 分配模型表（heap）；free 释放并清零 */
int occ_registry_init(occ_registry *reg);
void occ_registry_free(occ_registry *reg);

/* 三方并集构建。cfg/catalog 均可 NULL。同 provider+id 已存在则跳过
 * （优先级：toml > ollama > catalog——配置即真相，目录补全）。 */
void occ_registry_build(occ_registry *reg, const occ_provider_config *cfg,
			const occ_catalog *catalog);

/* ollama /api/tags 响应并入（{"models":[{"name":..,"details":{..}}]}）；
 * 坏 JSON/字段缺 → 跳过计数返回。 */
size_t occ_registry_add_ollama(occ_registry *reg, const char *tags_json,
			       size_t len);

/* "provider/id" 键查找；未命中 NULL */
const occ_reg_model *occ_registry_find(occ_registry *reg,
				       const char *provider,
				       const char *model_id);

/* ---- 分组视图（写入 idx 数组返回条数；idx 指向 reg->models 下标） ---- */

/* Favorites：收藏序（打开对话框时快照排序不再变） */
size_t occ_registry_favorites(const occ_registry *reg,
			      size_t *idx, size_t idx_max);

/* Recent：最近用过且不在收藏里的（LRU 序） */
size_t occ_registry_recents(const occ_registry *reg,
			    size_t *idx, size_t idx_max);

/*
 * 全量按 provider 分组：条目按 (provider_name, provider, id) 字典序稳定
 * 排列——TUI 依 provider 边界切段即得分组视图。deprecated 过滤=1 排除。
 */
size_t occ_registry_all_by_provider(const occ_registry *reg,
				    int include_deprecated,
				    size_t *idx, size_t idx_max);

/* fuzzy 过滤（搜索词非空时 TUI 去分组的扁平列表，dialog-model.tsx:182-194） */
size_t occ_registry_fuzzy(const occ_registry *reg, const char *query,
			  int include_deprecated,
			  size_t *idx, size_t idx_max);

/* ---- 持久化（~/.occ/state.json；原子写） ---- */

int occ_state_load(occ_registry *reg, const char *state_path);
int occ_state_save(const occ_registry *reg, const char *state_path);

/* 记一次使用（model.set {recent:true} 语义）：provider/id 提到 recents 头 */
void occ_registry_touch(occ_registry *reg, const char *provider,
			const char *model_id);

/* 收藏切换：已收→取消；未收→追加。返回新状态（1=已收藏）。 */
int occ_registry_toggle_favorite(occ_registry *reg, const char *provider,
				 const char *model_id);

#endif /* _OCC_REGISTRY_H */
