/* SPDX-License-Identifier: GPL-2.0 */
/*
 * config.h - T4a SME 配置中心（默认值 + JSON 覆盖 + 显式键）
 *
 * 对齐 REF-PY e72bc75 `sme/config.py`：
 *   - 默认值 = json.dumps(SMEConfig().to_dict(), ensure_ascii=False)，由生成
 *     文件 config_default.h 提供（26 section / 137 键，含 JSON sha256）；
 *   - 覆盖只认已知 section.key（等价 from_dict 的 hasattr 守卫），未知键
 *     静默忽略；键序保持 Python to_dict() 的插入序，seed 永远第一；
 *   - 覆盖值按输入 JSON 的类型原样保存（Python setattr 不做类型转换）。
 *
 * 显式键（`_explicit_keys`）只记录来自输入文件的已知 section.key：
 * 默认键不显式，seed 永不显式（Python 的 seed 分支不写 _explicit_keys）。
 * 供 engine 的 region.min_join_cosine 校准判断使用。
 *
 * 错误约定：返回 NULL 表示失败且 err 已写入原因（err 可为 NULL/errlen=0）；
 * get_* 失败返回 -1（get_str 返回 NULL），由调用方决定默认值。
 */
#ifndef _AIK_SMECONFIG_CONFIG_H
#define _AIK_SMECONFIG_CONFIG_H

#include <stddef.h>

#include "store/store_json.h"

typedef struct aik_config aik_config;

/*
 * aik_config_defaults - 新建默认配置（每次返回独立 DOM，调用者 free）
 *
 * 失败返回 NULL（内置 JSON 无法解析/OOM），err 写原因。
 */
aik_config *aik_config_defaults(char *err, size_t errlen);

/*
 * aik_config_load - 从 JSON 文件加载配置
 *
 * 允许 {"sme": {...}} 包装（engine.py:89 `loaded.get("sme", loaded)`）。
 * 文件不存在/读失败/JSON 解析失败返回 NULL 并写 err。
 */
aik_config *aik_config_load(const char *path, char *err, size_t errlen);

/*
 * aik_config_from_json - 以默认 DOM 为底叠加 root 的覆盖
 *
 * root 已是 section 根（T1 config_template），也接受 {"sme": {...}} 包装；
 * root 为 NULL 或非对象时返回纯默认配置。不接管 root 的所有权。
 */
aik_config *aik_config_from_json(const aik_json *root, char *err,
				 size_t errlen);

/* 借用默认 DOM（SMEConfig.to_dict 形状）；c 为 NULL 返回 NULL */
const aik_json *aik_config_dom(const aik_config *c);

/* 1 = dotted 来自输入文件；默认键、未知键与 seed 返回 0 */
int aik_config_is_explicit(const aik_config *c, const char *dotted);

/*
 * 按 dotted path 取值（"region.min_join_cosine"，也接受单段 "seed"）。
 *
 * 类型规则：
 *   - get_i64  ：INT，或整数值的 NUM（10.0 与 10 同义）；
 *   - get_num  ：NUM 或 INT（JSON 整数转 double）；
 *   - get_bool ：BOOL（严格）；
 *   - get_str  ：STR（返回借用指针，随 config 失效）。
 * 其余类型/路径不存在返回 -1（get_str 返回 NULL）。out 可为 NULL，只做探测。
 */
int aik_config_get_i64(const aik_config *c, const char *dotted,
		       long long *out);
int aik_config_get_num(const aik_config *c, const char *dotted, double *out);
int aik_config_get_bool(const aik_config *c, const char *dotted, int *out);
const char *aik_config_get_str(const aik_config *c, const char *dotted);

/* 释放（NULL 安全） */
void aik_config_free(aik_config *c);

#endif /* _AIK_SMECONFIG_CONFIG_H */
