/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ai_toolname_map.h - 云端 API 工具名双向映射（点号 → 下划线）
 *
 * 背景（W41 bug②）：DeepSeek/OpenAI 兼容服务端对 function name 有
 * ^[a-zA-Z0-9_-]{1,64}$ 规范，禁点号。工具注册表本名（tools.json）
 * 可能含点号（如 netlink.act.sched.nice），直发即被 400 拒绝。
 *
 * 约定：
 *   - 出站（tools 数组、历史 assistant tool_calls 重放）：点→下划线
 *     sanitize（无查表，纯字符替换，无点号时恒等）；
 *   - 入站（tool_calls 响应的 function.name）：查表还原本名
 *     （下划线→点的逆映射有歧义，必须查 seed 表）；表外名字原样
 *     透传（恒等），保证存量无点号工具零影响；
 *   - seed 由 tool_registry_load 装载 tools.json 后注入；重名检测：
 *     sanitize 产物与本注册表任一真实名冲突，或两条目 wire 形态
 *     相同（多对一歧义）时跳过该条目并计数上报（映射退化为透传）；
 *   - tools.json 本名永不改动，映射只发生在 API 线缆格式边界。
 */

#ifndef AI_TOOLNAME_MAP_H
#define AI_TOOLNAME_MAP_H

#include <stddef.h>

/* 映射表容量（注册表工具数上界 128，留裕量） */
#define AI_TOOLNAME_MAP_MAX 128
/* DeepSeek/OpenAI function name 长度上界 */
#define AI_TOOLNAME_WIRE_MAX 64

/*
 * ai_toolname_map_reset - 清空映射表（测试/注册表重载前调用）
 */
void ai_toolname_map_reset(void);

/*
 * ai_toolname_map_seed - 用注册表工具名数组播种映射表
 * @names: 工具本名数组（可含点号）
 * @n:     条数
 * 返回: 因重名/歧义被跳过的点号条目数（0=全部可安全映射）。
 *       非 0 时映射对冲突条目退化为透传，调用方可打印告警。
 */
int ai_toolname_map_seed(const char *const *names, int n);

/*
 * ai_toolname_map_count - 当前已建立的映射条目数（诊断/测试用）
 */
int ai_toolname_map_count(void);

/*
 * ai_toolname_sanitize - 出站线缆名：点→下划线
 * 返回: 无点号时原样返回 name（恒等）；有点号时写入 buf 并返回 buf。
 *       buf 满时截断（调用方给 AI_TOOLNAME_WIRE_MAX+1 即可）。
 */
const char *ai_toolname_sanitize(const char *name, char *buf,
				 size_t bufsz);

/*
 * ai_toolname_map_restore_alloc - 入站名还原（接管并可能替换原指针）
 * @name: malloc 的线缆名（所有权移入）；查中表且还原名不同时
 *        free(name) 并返回 strdup(本名)；未查中/内存不足时原样返回。
 * 返回: 还原后的本名（调用方 free）。
 */
char *ai_toolname_map_restore_alloc(char *name);

#endif /* AI_TOOLNAME_MAP_H */
