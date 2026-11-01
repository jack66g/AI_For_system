/* SPDX-License-Identifier: GPL-2.0 */
/*
 * store_json.h - 存储层 JSON DOM / 数字格式化 / 紧凑序列化
 *
 * 目标：逐字节复刻 Python `json.dumps(..., ensure_ascii=False,
 * separators=(",", ":"))` 的文本，供 T2a 存储快照读路径使用（后续 T2b
 * 写路径复用同一套 dtoa 与序列化）。语义约定见 T2-DESIGN.md §2：
 *   - 对象键保持插入序；重复键按 Python 语义（首次出现的位置、最后的值）；
 *   - 词法无 '.'/'e'/'E' 且落在 int64 → INT，否则 NUM（double）；
 *   - dump 时 INT 输出整数、NUM 走 aik_json_dtoa；
 *   - 解析失败返回 NULL，err 给出 "offset=N: reason"，绝不部分成功。
 *
 * 本模块零第三方依赖，C11，构建串行（见 store/Makefile）。
 */
#ifndef _AIK_STORE_JSON_H
#define _AIK_STORE_JSON_H

#include <stddef.h>

/* JSON 值类型 */
typedef enum {
	AIK_JSON_NULL,
	AIK_JSON_BOOL,
	AIK_JSON_INT,
	AIK_JSON_NUM,
	AIK_JSON_STR,
	AIK_JSON_ARR,
	AIK_JSON_OBJ
} aik_json_type;

/* 不透明 DOM 节点 */
typedef struct aik_json aik_json;

/*
 * aik_json_parse - 解析 [buf, buf+len) 的完整 JSON 文本
 *
 * 成功返回新 DOM（调用者 aik_json_free），失败返回 NULL 并在 err[0..errlen)
 * 写入 "offset=N: reason"。输入必须恰好是一个 JSON 值（前后可有空白，
 * 不允许尾随垃圾）。
 */
aik_json *aik_json_parse(const char *buf, size_t len, char *err, size_t errlen);

/* 递归释放整棵树；NULL 安全 */
void aik_json_free(aik_json *v);

/* 类型查询；NULL 返回 AIK_JSON_NULL */
aik_json_type aik_json_typeof(const aik_json *v);

/* 取值：类型不符或 NULL 时返回 0 / NULL（见各函数注释） */
int aik_json_bool(const aik_json *v);		/* BOOL → 0/1，否则 0 */
long long aik_json_int(const aik_json *v);	/* INT 原值；NUM 截断；否则 0 */
double aik_json_num(const aik_json *v);		/* NUM/INT → double；否则 0.0 */
const char *aik_json_str(const aik_json *v);	/* STR → NUL 结尾 UTF-8；否则 NULL */
size_t aik_json_strlen(const aik_json *v);	/* STR 字节长度；否则 0 */

/* 容器访问：ARR/OBJ 元素数；其它类型与 NULL 返回 0 */
size_t aik_json_count(const aik_json *v);

/* ARR 下标访问；越界或非 ARR 返回 NULL */
const aik_json *aik_json_at(const aik_json *v, size_t i);

/* OBJ 下标访问：键（NUL 结尾）与值；越界或非 OBJ 返回 NULL */
const char    *aik_json_key_at(const aik_json *v, size_t i);
const aik_json *aik_json_val_at(const aik_json *v, size_t i);

/* OBJ 按键查找：返回「首次出现」的值；未命中或非 OBJ 返回 NULL */
const aik_json *aik_json_get(const aik_json *v, const char *key);

/* 构造：失败返回 NULL（调用者仍可 aik_json_free 语义） */
aik_json *aik_json_new_null(void);
aik_json *aik_json_new_bool(int b);
aik_json *aik_json_new_int(long long i);
aik_json *aik_json_new_num(double d);
aik_json *aik_json_new_str(const char *utf8);
aik_json *aik_json_new_arr(void);
aik_json *aik_json_new_obj(void);

/* 追加到 ARR，转移 v 的所有权；成功 0，失败 -1（不接管 v） */
int aik_json_arr_push(aik_json *arr, aik_json *v);

/* OBJ 追加：允许重复键（与 Python dict 无关的显式构造）；成功 0 */
int aik_json_obj_put(aik_json *obj, const char *key, aik_json *v);

/* OBJ 设置：已存在同名键则替换其值（保持首次出现位置），否则追加 */
int aik_json_obj_set(aik_json *obj, const char *key, aik_json *v);

/*
 * aik_json_dump - 紧凑序列化（malloc 输出，调用者 free）
 *
 * out 收 NUL 结尾缓冲（outlen 不含结尾 NUL）。分隔符 ',' ':'，对象保持
 * 插入序，ensure_ascii=False 等价转义。成功 0，失败 -1（out 置 NULL）。
 */
int aik_json_dump(const aik_json *v, char **out, size_t *outlen);

/*
 * aik_json_dtoa - CPython repr 等价的最短往返数字文本
 *
 * 返回写入长度（不含 NUL），失败 -1（缓冲不足/参数非法）。非有限值输出
 * "Infinity" / "-Infinity" / "NaN"。结果与 LC_NUMERIC 无关。
 */
int aik_json_dtoa(double v, char *buf, size_t buflen);

#endif /* _AIK_STORE_JSON_H */
