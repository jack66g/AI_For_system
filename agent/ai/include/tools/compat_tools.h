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

/*
 * C1：符号版本纯函数探针（verneed/verdef，GLIBC_2.x 口径）。
 * 与 ai_compat_probe_json 同一先例导出：test_compat 用内存 fixture
 * 直测（走查器本身不做任何文件 IO；读文件只发生在 probe 路径内）。
 */
#define AI_COMPAT_VER_LEN      40	/* 版本串上限（"GLIBC_2.9999" 一类） */
#define AI_COMPAT_VERS_PER_LIB 16	/* 单库版本数上限 */

/* 一库的符号版本要求集（ELF verneed：vn_file + vna_name 链） */
struct ai_compat_verreq {
	char lib[64];
	char vers[AI_COMPAT_VERS_PER_LIB][AI_COMPAT_VER_LEN];
	int n_vers;
};

/* 版本比较：'.' 分段数值比较（"2.10">"2.9"；前缀剥离；段多者大）。
 * 返回 <0 / 0 / >0 */
int ai_compat_ver_cmp(const char *a, const char *b);

/* verneed 走查：blob（DT_VERNEED 指向）+ count（DT_VERNEEDNUM）+ strtab
 * → 要求集。返回库数（同名库合并追加版本；越界/坏版本号诚实截断） */
int ai_compat_verneed_walk(const unsigned char *vn, size_t vn_len, int count,
			   const char *strtab, size_t strtab_len,
			   struct ai_compat_verreq *out, int max);

/* verdef 走查：blob（DT_VERDEF 指向）+ count（DT_VERDEFNUM）+ strtab
 * → GLIBC_* 提供集最大版本写 out_max（无则空串）。返回 GLIBC_* 版本数 */
int ai_compat_verdef_max(const unsigned char *vd, size_t vd_len, int count,
			 const char *strtab, size_t strtab_len,
			 char *out_max, size_t cap);

/* libc 要求集 vs 宿主提供最大值 → 超新版本清单（probe 据此判
 * LIBC_VERSION_TOO_NEW）。req/provided_max 缺失返回 0（诚实降级） */
int ai_compat_ver_too_new(const struct ai_compat_verreq *req,
			  const char *provided_max,
			  char out[][AI_COMPAT_VER_LEN], int max);

/* 执行器入口（executor.c 的 TOOL_CH_COMPAT 分发调用） */
int exec_compat_channel(const void *tool, const char *args_json, char **out);

#endif /* _AI_COMPAT_TOOLS_H */
