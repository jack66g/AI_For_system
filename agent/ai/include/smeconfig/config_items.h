/* SPDX-License-Identifier: GPL-2.0 */
/*
 * config_items.h - T4e 配置注册表（101 可调项 / 5 预设 / 10 分组）
 *
 * 对齐 REF-PY e72bc75：
 *   - sme/config_items.py：ConfigItem / ITEMS / PRESETS / parse_value /
 *     validate_value / defaults_config / complete_config / load_config /
 *     save_config / build_help / validate_config / PRESET_BY_KEY
 *   - sme/api/server.py：GROUP_DEFS / _item_payload / _config_groups /
 *     _display_dict（分组映射与 GET /config 的 payload 形状）
 *
 * 数据表（config_items_data.h）由 scripts/gen_config_items.py 从参考实现
 * 生成，本模块只提供行为。语义约定：
 *
 *   - 取值/设值作用在**完整配置 DOM**（aik_config_defaults / _load /
 *     engine.config.to_dict 形状，137 键）上，路径不存在时 get 返回 NULL；
 *   - parse_value 把用户输入的字符串转成类型化 JSON（bool/enum/int/
 *     float/interval/str），区间与有限性检查与参考逐条一致，错误文案
 *     逐字相同（中文）；
 *   - validate_value 校验已是 JSON 类型的值（PUT 的原生类型分支 / 配置
 *     文件校验），错误文案同样逐字相同；
 *   - save 写 `<path>`：先 complete（101 项缺省补齐）、再加 `_help`
 *     （101 项 path→desc，已有键保持原位）、最后按 Python
 *     json.dump(..., ensure_ascii=False, indent=2) 的文本形态原子落盘；
 *   - load 对缺失/损坏/非对象文件回退到 defaults_config()（101 项
 *     item.default），合法对象原样返回（不补全，与参考 load_config 同）；
 *   - JSON 数值比较遵循 Python 语义：True == 1 / False == 0。
 *
 * 错误约定：返回 -1 表示失败且 err 已写原因（err 可为 NULL/errlen=0）；
 * validate 的 -1 表示"值非法，err 为中文原因"，-2 表示内部错误（OOM）。
 */
#ifndef _AIK_SMECONFIG_CONFIG_ITEMS_H
#define _AIK_SMECONFIG_CONFIG_ITEMS_H

#include <stddef.h>

#include "store/store_json.h"

typedef enum {
	AIK_CFG_KIND_STR,
	AIK_CFG_KIND_INT,
	AIK_CFG_KIND_FLOAT,
	AIK_CFG_KIND_BOOL,
	AIK_CFG_KIND_ENUM,
	AIK_CFG_KIND_INTERVAL
} aik_config_kind;

/*
 * 一个可调项。字符串字段借用静态数据（生成表），生命周期 = 进程。
 * minimum/maximum/default_json 为 JSON 字面量文本（NULL = 无下限/
 * 无上限）；default_json 永不为 NULL。
 */
typedef struct aik_config_item {
	const char *path;
	const char *name;
	const char *group;		/* 展示分组 key（GROUP_DEFS 映射后） */
	const char *desc;
	aik_config_kind kind;
	const char *const *choices;	/* kind==ENUM 时非 NULL */
	size_t n_choices;
	const char *minimum;		/* JSON 字面量或 NULL */
	const char *maximum;		/* JSON 字面量或 NULL */
	int required;
	const char *default_json;
} aik_config_item;

/* 预设中的一项：path + 类型化 JSON 字面量（保持 Python dict 插入序） */
typedef struct aik_config_preset_value {
	const char *path;
	const char *value_json;
} aik_config_preset_value;

typedef struct aik_config_preset {
	const char *key;
	const char *name;
	const char *desc;
	const aik_config_preset_value *values;
	size_t n_values;
} aik_config_preset;

/* 展示分组（server.py GROUP_DEFS 原序；空分组由 groups_build 过滤） */
typedef struct aik_config_group {
	const char *key;
	const char *name;
	const char *description;
} aik_config_group;

/* 注册表（config_items_data.h 定义） */
extern const aik_config_item aik_config_items[];
extern const size_t aik_config_item_count;
extern const aik_config_group aik_config_groups[];
extern const size_t aik_config_group_count;
extern const aik_config_preset aik_config_presets[];
extern const size_t aik_config_preset_count;

/* 查找；未命中返回 NULL */
const aik_config_item *aik_config_item_find(const char *path);
const aik_config_preset *aik_config_preset_find(const char *key);

/*
 * 从完整配置 DOM 取值：按 dotted path 走对象，返回借用节点；路径上任意
 * 一段缺失/不是对象返回 NULL。cfg 为 NULL 同样返回 NULL。
 */
const aik_json *aik_config_item_get(const aik_json *cfg,
				    const aik_config_item *it);

/* 1 = 路径存在（值为 null 也算存在）；0 = 缺失 */
int aik_config_item_has(const aik_json *cfg, const aik_config_item *it);

/*
 * 新建该 item 的默认值 DOM（解析 default_json；调用者 aik_json_free）。
 * 解析失败返回 NULL（生成表损坏）。
 */
aik_json *aik_config_item_default(const aik_config_item *it);

/*
 * 设值：按 dotted path 创建中间对象（非对象覆盖为空对象），已存在叶子
 * 保持首次出现位置（aik_json_obj_set 语义）。value 深拷贝（dump+parse）。
 * 成功 0，OOM/序列化失败 -1。
 */
int aik_config_item_set(aik_json *cfg, const aik_config_item *it,
			const aik_json *value);

/*
 * parse_value：字符串输入 -> 类型化 JSON（*out 由调用者 free）。
 *
 * kind 语义与参考一致：bool 认 1/0/true/false/yes/no/on/off/y/n/开/关/
 * 是/否（大小写不敏感）；enum 空串合法、否则大小写不敏感匹配 choices 并
 * 返回**注册表里的规范写法**；interval 认 off/none/关/关闭 → 1000000000，
 * 否则整数；int/float 走有限性与 min/max 检查；str 原样（trim 后）。
 * 失败 -1 且 err 为中文原因（与 Python ValueError 文案逐字一致）。
 */
int aik_config_item_parse(const aik_config_item *it, const char *raw,
			  aik_json **out, char *err, size_t errlen);

/*
 * validate_value：校验类型化 JSON。0 = 合法；-1 = 非法（err 中文原因）；
 * -2 = 内部错误（OOM 等）。错误文案与参考 validate_value 逐字一致。
 */
int aik_config_item_validate(const aik_config_item *it, const aik_json *value,
			     char *err, size_t errlen);

/* defaults_config()：101 项 item.default，ITEMS 插入序，新 OBJ。 */
aik_json *aik_config_defaults_build(void);

/* complete_config：缺项补 item.default（原地）；成功 0 / -1。 */
int aik_config_complete(aik_json *cfg);

/*
 * load_config：读文件。
 *   - 文件不存在/读失败/JSON 损坏/顶层非对象 → defaults_config()；
 *   - 合法对象 → 原样返回（不补全）。
 * 返回新 DOM；OOM/解析内部错误时返回 NULL 且 err 已写（与"回退默认"区分：
 * 回退默认不是错误）。UTF-8 BOM 允许（参考 encoding="utf-8-sig"）。
 */
aik_json *aik_config_load_file(const char *path, char *err, size_t errlen);

/*
 * save_config：complete + `_help` + 原子写（tmp + rename）。
 * 输出格式 = Python json.dump(cfg, ensure_ascii=False, indent=2)：两空格
 * 缩进、", "/": " 分隔、无结尾换行；父目录 mkdir -p。成功 0 / -1。
 */
int aik_config_save_file(const char *path, const aik_json *cfg,
			 char *err, size_t errlen);

/*
 * _display_dict：把配置 DOM 的 dict 段里的 null 叶子剔除，返回新 OBJ。
 * 顶层非 dict 值原样保留。OOM 返回 NULL。
 */
aik_json *aik_config_display(const aik_json *cfg);

/*
 * _config_groups：GET /config 的 groups 数组。
 *
 * display_cfg 必须是 _display_dict 后的 DOM。每项 payload 键序：
 *   path,name,value,default,help,type,choices,minimum,maximum,modified
 *   [,set]（仅 path 以 "api_key" 结尾：set=bool(真实值)，非空时
 *   value 替换为 "******"）。
 * 分组按 GROUP_DEFS 原序，空分组不下发；组内按 ITEMS 原序。新 ARR。
 */
aik_json *aik_config_groups_build(const aik_json *display_cfg);

/* presets 摘要数组：key,name,description,count（PRESETS 原序）。新 ARR。 */
aik_json *aik_config_presets_build(void);

/*
 * validate_config：对 cfg 中 has_value 的项做 validate_value，再追加条件
 * 必填告警（LLM 已配置→llm.model/api_key；embedding.base_url 已配置→
 * embedding.api_key）。返回新 ARR（元素为字符串），按 ITEMS 原序 + 条件
 * 告警顺序；文案与参考逐字一致。OOM 返回 NULL。
 *
 * cfg 应为 display 视图（null 叶子剔除后），调用方可用
 * aik_config_display 得到。
 */
aik_json *aik_config_validate_all(const aik_json *cfg, char *err,
				  size_t errlen);

/* JSON 值的 Python 相等语义（True==1、False==0；数值按 double 比较） */
int aik_config_value_equal(const aik_json *a, const aik_json *b);

#endif /* _AIK_SMECONFIG_CONFIG_ITEMS_H */
