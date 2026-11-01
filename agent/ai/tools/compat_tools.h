/* SPDX-License-Identifier: GPL-2.0 */
/*
 * compat_tools.h - W82B V6 应用兼容（compat 通道，四件工具）
 *
 * 设计判断（ROADMAP §4.6 V6）：**适配器是数据，不是代码**。
 *   AI 产出的是规则 + 行为契约；应用本体一个字节都不改。
 *
 * 分层（第一版只做 L0 + L2）：
 *   L0 环境适配：路径重映射（shim）、环境变量、依赖库重定向
 *   L2 运行时隔离：workspace 自带 rootfs / 库 + /usr 挂载视图
 *   （L1 ABI 翻译 / L3 行为代理 明确未实现，探测到即如实标注 layer=L1）
 *
 * 四件工具（D0/D1/D2/D1）：
 *   compat_probe   (D0/R)  静态判定目标为什么跑不起来，逐条给证据
 *   compat_generate(D1/W1) 生成 adapters/<name>.json（每条规则带 because）
 *   compat_apply   (D2/W2) 在 workspace 内落地并试跑；失败自动回滚
 *   compat_verify  (D1/W1) 跑行为契约（输出/退出码/耗时 + syscall 轨迹
 *                          关键项 + 负向自检）；任一不过即 ok=false
 *
 * 硬约束：
 *   1) 永不 patch 目标二进制；只做路径/环境/库/视图层面的重映射。
 *   2) 适配器是数据，但数据也要过安检：所有落盘路径必须在 workspace
 *      的 stage 或 /.aik-compat/usr-upper 前缀内（见 compat_tools.c）。
 *   3) 契约必须含负向用例："返回 0 但输出为空" 判不合格——verify 会
 *      真的构造空输出/强制非零退出/未适配三种变异跑一遍，验证器自己
 *      也必须是可证伪的。
 *
 * 状态目录（AIKERNEL_COMPAT_ROOT 可覆盖，默认 /var/lib/aikernel/compat）：
 *   adapters/<name>.json        适配器（数据）
 *   state/<name>.applied.json   最近一次 apply 的回滚账本
 *   audit.log                   一行一次调用（工具/动作/结果）
 */
#ifndef _AI_COMPAT_TOOLS_H
#define _AI_COMPAT_TOOLS_H

#include <stddef.h>

#define AI_COMPAT_SCHEMA "aikernel.compat/v0"

/* 适配器名：[A-Za-z0-9_.-]{1,32}，首字符不能是 '.' 或 '-'，禁止 ".." */
int ai_compat_valid_name(const char *s);

/*
 * 纯函数：目标形态判定（不执行目标、不写盘）。
 * 返回 1=可执行（无 fatal 原因），0=有 fatal 原因，-1=参数非法。
 * out 为 malloc 的 JSON（调用者 free），可为 NULL。
 * 单测用它做无副作用断言；工具入口 compat_probe 也走同一条路径。
 */
int ai_compat_probe_json(const char *target, const char *argv_extra,
			 char **out, int *runnable);

/* 执行器入口（executor.c 的 TOOL_CH_COMPAT 分发调用） */
int exec_compat_channel(const void *tool, const char *args_json, char **out);

#endif /* _AI_COMPAT_TOOLS_H */
