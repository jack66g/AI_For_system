// SPDX-License-Identifier: GPL-2.0
/*
 * tool_registry.h - AI 工具注册表（Ask 工具调用闭环）
 *
 * 工具清单由 tools/gen_registry.py 离线生成（tools.json），来源按优先级：
 *   a. QEMU 实测采集（/proc/ai、/sys/kernel/ai 实际节点）；
 *   b. 内核源码静态梳理（AIKernel/vfs、core/ai_control.c 等 23 个可控参数）。
 * C 侧运行时加载 tools.json：
 *   - 组 system prompt（工具名+描述+参数）；
 *   - 生成 OpenAI function-calling 的 tools 数组（请求体用）；
 *   - 模型返回 tool_calls 时按名字查表得到 channel，交给 executor 路由。
 *
 * tools.json 中每个工具：{name, description, channel, risk, parameters(schema),
 * 加通道专属字段(path/param/domain/...)}。channel 取值：
 *   procfs-read | sysfs-write | netlink-act | netlink-sense | exec | memory
 * v2 起每个工具必带 "risk"（R/W1/W2），exec 工具内嵌 "exec" 单源白名单。
 */
#ifndef _AI_TOOL_REGISTRY_H
#define _AI_TOOL_REGISTRY_H

#include <stddef.h>

/* 通道枚举（executor 路由用） */
enum tool_channel {
	TOOL_CH_PROCFS_READ = 0,
	TOOL_CH_SYSFS_WRITE,
	TOOL_CH_NETLINK_ACT,
	TOOL_CH_NETLINK_SENSE,	/* v2：NETLINK_AI SENSE 拉遥测（只读） */
	TOOL_CH_EXEC,
	TOOL_CH_MEMORY,
	TOOL_CH_UNKNOWN,
};

/* channel 字符串 → 枚举 */
enum tool_channel tool_channel_from_str(const char *s);

/* 风险级（tools.json "risk" 字段，v2 起全量标注）：
 *   R  = 只读；W1 = 低危写；W2 = 高危写（见 gen_registry.py 分级表）。
 * 约定：未知/缺失视为 NULL，由调用方按通道推断旧版行为。 */
#define TOOL_RISK_R    "R"
#define TOOL_RISK_W1   "W1"
#define TOOL_RISK_W2   "W2"

/* exec 通道单源白名单条目（tools.json exec.run 工具内嵌
 * "exec":{"default_timeout":N,"commands":[...]}，v2 起运行时唯一
 * 权威来源；executor.c 内置表仅作 tools.json 缺失时的 fallback）。
 * 单条命令形态：
 *   {"command":"free","bin":"/usr/bin/free","args_template":[],
 *    "timeout":30,"risk":"R"}
 *   systemctl 类二级白名单（首参动词分级）：
 *   {"command":"systemctl","bin":"/usr/bin/systemctl","risk":"W2",
 *    "args0":[{"verb":"status","risk":"R"},...]} */
struct tool_exec_cmd {
	char *command;          /* 模型可见的命令名（exec.run 的 command 参数） */
	char *bin;              /* 绝对路径（单源权威；access X_OK 校验） */
	char **args_template;   /* 固定前置参数（如 journalctl --no-pager） */
	int   args_template_n;
	int   timeout;          /* 秒；0 = 用工具级 default_timeout */
	char *risk;             /* R/W1/W2 */
	char **args0_enum;      /* 非空时：args[0] 必须命中其一 */
	char **args0_risk;      /* 与 args0_enum 一一对应的风险级（可 NULL） */
	int   args0_count;
	int   path_check;       /* 1=W1 文件类：绝对路径目标限 /root /tmp /var/ai */
};

/* 工具参数（来自 parameters.properties 的成员） */
struct tool_param {
	char *name;             /* 参数名 */
	char *type;             /* string/integer/number/boolean/array */
	char *desc;             /* 参数说明 */
	int   required;         /* 1=必填（parameters.required 数组） */
	long long min;          /* minimum（无则 0，has_min=0） */
	long long max;          /* maximum（无则 0，has_max=0） */
	int   has_min;
	int   has_max;
	char **enum_vals;       /* enum 字符串集合（exec 白名单等） */
	int   enum_count;
	char *default_val;      /* default（字符串形式，可 NULL） */
};

/* 单个工具 */
struct ai_tool {
	char *name;             /* 工具名（注册表唯一，如 procfs.read.status） */
	char *desc;             /* 描述 */
	enum tool_channel channel;

	char *path;             /* procfs-read/sysfs-write: 目标绝对路径 */
	char *param;            /* netlink-act: 可控参数名（如 sched.nice） */
	int   domain;           /* netlink-act: 决策域 0..12 */
	int   task_param;       /* netlink-act: 1=任务参数(pid,value) */
	long long value_min;    /* netlink-act: 参数值域（executor 客户端钳制） */
	long long value_max;
	int   has_value_min;    /* v2: json 显式给了 value_min */
	int   has_value_max;

	char *risk;             /* v2: R/W1/W2（exec 通道按命令另查 exec_cmds） */

	/* v2: exec 通道单源白名单（tools.json 内嵌，见 struct tool_exec_cmd） */
	struct tool_exec_cmd *exec_cmds;
	int   exec_cmd_count;
	int   exec_default_timeout;     /* 秒；0 = executor 缺省 30 */

	struct tool_param *params;
	int param_count;
	char *parameters_json;  /* parameters schema 原文（构造请求体透传） */
};

struct tool_registry {
	struct ai_tool *tools;
	int tool_count;
	char *source_path;      /* 实际加载的 tools.json 路径 */
};

/*
 * tool_registry_load - 搜索并加载 tools.json
 * 搜索顺序：环境变量 AIKERNEL_TOOLS_JSON → ./tools.json →
 *   <exe目录>/tools.json → <exe目录>/tools/tools.json
 * @reg:  输出注册表（调用者 tool_registry_free 释放）
 * @err:  出参，失败原因（调用者需 free），成功为 NULL
 * 返回: AI_OK / AI_ERR_NOT_FOUND / AI_ERR_PARSE / AI_ERR_MEMORY
 */
int tool_registry_load(struct tool_registry *reg, char **err);

/*
 * tool_registry_find - 按名查找工具；未找到返回 NULL
 */
const struct ai_tool *tool_registry_find(const struct tool_registry *reg,
					 const char *name);

/*
 * tool_registry_build_tools_json - 生成 OpenAI function-calling 的
 * tools 数组 JSON（请求体 "tools" 字段原样嵌入）：
 *   [{"type":"function","function":{"name":..,"description":..,
 *     "parameters":<schema 原文>}}, ...]
 * 返回: malloc 字符串（调用者需 free），失败返回 NULL
 */
char *tool_registry_build_tools_json(const struct tool_registry *reg);

/*
 * tool_registry_summarize - 生成 system prompt 用的工具清单文本
 * 每行：- <name> [<channel>] <描述> | 参数: <p1>(<type>,必填) ...
 * 返回: malloc 字符串（调用者需 free），失败返回 NULL
 */
char *tool_registry_summarize(const struct tool_registry *reg);

/*
 * tool_registry_count_by_channel - 分通道计数
 * @counts: 输出数组，下标为 enum tool_channel（至少 TOOL_CH_UNKNOWN+1）
 */
void tool_registry_count_by_channel(const struct tool_registry *reg,
				    int *counts);

/* tool_registry_free - 释放注册表（幂等） */
void tool_registry_free(struct tool_registry *reg);

#endif /* _AI_TOOL_REGISTRY_H */
