/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_catalog.h - models.dev 目录快照（T9a2）
 *
 * 数据源：https://models.opencode.ai/experimental/v2.0/api.json
 * （opencode core/src/models-dev.ts 同源；OCD-SPEC §4.3 字段口径）
 * 快照数据文件：agent/ai/occ/models.dev.snapshot.json（出厂带；升级=
 * 换数据文件不改代码）——由裁剪器从原始 api.json 提取 occ 所需字段，
 * _meta 段记录来源 URL / 拉取时间 / 原始 sha256。
 *
 * 解析容错：坏 JSON 整体失败（返回 -1）；单模型条目字段缺失/类型不符
 * → 该字段取默认值（id 缺失则整条跳过），nskipped 计数对外可见——
 * 目录数据升级换代不炸进程。
 */
#ifndef _OCC_CATALOG_H
#define _OCC_CATALOG_H

#include <stddef.h>

#define OCC_CAT_ID_MAX 128
#define OCC_CAT_NAME_MAX 160
#define OCC_CAT_PROVIDER_MAX 64

typedef struct occ_catalog_model {
	char id[OCC_CAT_ID_MAX];		/* 模型 id（provider 内键） */
	char canonical_id[OCC_CAT_ID_MAX * 2];	/* 别名一：厂商/模型 全名 */
	char name[OCC_CAT_NAME_MAX];		/* 别名二：显示名 */
	char provider[OCC_CAT_PROVIDER_MAX];	/* 所属厂商 id（分组键） */
	char provider_name[OCC_CAT_NAME_MAX];	/* 厂商显示名 */
	int is_chat;				/* type=="chat"（decision 不入会话列表） */
	int is_deprecated;			/* status=="deprecated"（TUI 过滤） */
	long long context_limit;		/* limit.context；0=未知 */
	long long max_output;			/* limit.output；0=未知 */
	double cost_input_per_m;		/* 每 1M token 输入价（美元） */
	double cost_output_per_m;
	double cost_cache_read;
	double cost_cache_write;		/* 分档取 5m */
	int tools;				/* capabilities.tools.supported */
	int reasoning;				/* capabilities.reasoning.supported */
} occ_catalog_model;

typedef struct occ_catalog {
	occ_catalog_model *models;
	size_t nmodels, cap;
	size_t nskipped;			/* 容错跳过的条目数 */
	char source[256];			/* _meta.source */
	char fetched_utc[40];			/* _meta.fetched_utc */
	char original_sha256[80];		/* _meta.original_sha256 */
} occ_catalog;

/*
 * occ_catalog_load - 解析快照 JSON 文件（aik_json DOM，一次构建后释放）
 * 成功 0（空目录 {}/缺 providers 键也算成功——0 模型）；文件不可读或
 * 坏 JSON 返回 -1。
 */
int occ_catalog_load(occ_catalog *c, const char *json_path);

void occ_catalog_free(occ_catalog *c);

/* 精确查找（provider+id 或全 id 匹配）；未命中 NULL */
const occ_catalog_model *occ_catalog_find(const occ_catalog *c,
					  const char *provider,
					  const char *model_id);

/* 按厂商 id 过滤（provider=NULL → 全部）；写入 out 索引数组，返回条数 */
size_t occ_catalog_by_provider(const occ_catalog *c, const char *provider,
			       const occ_catalog_model **out, size_t outmax);

/*
 * occ_catalog_search - 按 id/别名（canonical_id/name）子串过滤（大小写
 * 不敏感）；写入 out 指针数组（上限 outmax），返回实际命中数。
 * include_deprecated=0 时排除 deprecated（dialog-model.tsx 列表语义）。
 */
size_t occ_catalog_search(const occ_catalog *c, const char *needle,
			  int include_deprecated,
			  const occ_catalog_model **out, size_t outmax);

/*
 * E7 记账消费点（定价四字段首个只读消费；ORCH-DESIGN §8 棒 E7）：
 *
 * occ_catalog_price - 按模型名取输入/输出单价（cost_input_per_m /
 * cost_output_per_m——美元每 1M token 两档）。匹配次序：
 *   1) occ_catalog_find 语义（id / canonical_id 全名精确）；
 *   2) 显示名 name（大小写不敏感精确）。
 * 返回 1=命中（两单价写出——未标价模型为 0.0）；0=目录无此模型
 * （model_name 空/NULL 也走此路）。只读查询，无任何写面。
 */
int occ_catalog_price(const occ_catalog *c, const char *model_name,
		      double *in_per_m, double *out_per_m);

/*
 * occ_catalog_cost_usd - 金额算式（显示参考，不精确计费——§10 风险 6
 * 「定价时效」对策：定价仅显示参考」）：
 *
 *   usd = tokens_in × in_per_m / 1e6 + tokens_out × out_per_m / 1e6
 *
 * 单位换算：单价=美元/1M token（catalog 四字段口径），token 量×单价
 * 再除以 1,000,000。cache_read/write 另档计价不并入（与 occ_tokens
 * total=input+output 口径一致——cache 命中不计入 total 不双算）。
 */
double occ_catalog_cost_usd(double in_per_m, double out_per_m,
			    long long tokens_in, long long tokens_out);

#endif /* _OCC_CATALOG_H */
