/* SPDX-License-Identifier: GPL-2.0 */
/*
 * dtjson.h - JSON 序列化三模式 + DOM 构造工具(T6b)。
 *
 *   dt_json_dump_default : json.dumps(v, ensure_ascii=False)
 *                          —— python 默认分隔符 ", " / ": "(HTTP 响应、
 *                          chats/notifs/meta 裸数组直写);
 *   dt_json_dump_indent2 : json.dumps(v, ensure_ascii=False, indent=2)
 *                          —— 状态文件(theme/desktop/pin),无尾换行;
 *   aik_json_dump        : 紧凑(store_json.h 原生)。
 *
 * 转义语义全部对齐 aik_json_dump 现有实现(ensure_ascii=False)。
 * 浮点一律 aik_json_dtoa(CPython repr 等价)。
 */
#ifndef _AIK_DESKTOP_DTJSON_H
#define _AIK_DESKTOP_DTJSON_H

#include <stddef.h>

#include "store/store_json.h"

char *dt_json_dump_default(const aik_json *v);
char *dt_json_dump_indent2(const aik_json *v);

/* ---------------- DOM 构造(失败返回 NULL,调用者善后) ---------------- */

aik_json *dt_new_str(const char *s);          /* NULL s → null 值 */
aik_json *dt_new_strn(const char *s, size_t n);
aik_json *dt_new_int(long long i);
aik_json *dt_new_num(double d);
aik_json *dt_new_bool(int b);
aik_json *dt_new_null(void);
aik_json *dt_new_arr(void);
aik_json *dt_new_obj(void);

/* 深拷贝(json.loads(json.dumps(v)) 等价) */
aik_json *dt_copy(const aik_json *v);

int dt_put_str(aik_json *o, const char *k, const char *v);
int dt_put_int(aik_json *o, const char *k, long long v);
int dt_put_bool(aik_json *o, const char *k, int v);
int dt_put_null(aik_json *o, const char *k);
int dt_put_num(aik_json *o, const char *k, double v);
int dt_put_copy(aik_json *o, const char *k, const aik_json *v);

int dt_arr_push_str(aik_json *a, const char *v);
int dt_arr_push_int(aik_json *a, long long v);
int dt_arr_push_copy(aik_json *a, const aik_json *v);

/* OBJ 按键取「首个」值;只读(改动请用 dt_get_mut) */
const aik_json *dt_get(const aik_json *o, const char *k);
/* OBJ 按键取可变引用(const 剥离;树归调用者所有) */
aik_json *dt_get_mut(aik_json *o, const char *k);

/* Python obj.setdefault(k, v):已存在(按字节键)返回现有值并释放 v;
 * 不存在则追加并返回 v。 */
aik_json *dt_obj_setdefault(aik_json *o, const char *k, aik_json *v);
/* 便捷 setdefault:字符串/整数 */
aik_json *dt_obj_setdefault_str(aik_json *o, const char *k, const char *v);
aik_json *dt_obj_setdefault_int(aik_json *o, const char *k, long long v);

/* 读文件并解析(任何失败 → NULL) */
aik_json *dt_read_json(const char *path);

/* 原子写:tmp(<path>.tmp,无 pid)→ fchmod 0600 → rename */
int dt_write_json_indent2_atomic(const char *path, const aik_json *v);
int dt_write_json_default_atomic(const char *path, const aik_json *v);

/* 从内存 JSON 文本构造 demo dom(utf-8);失败 NULL */
aik_json *dt_parse(const char *buf, size_t len);

#endif /* _AIK_DESKTOP_DTJSON_H */
