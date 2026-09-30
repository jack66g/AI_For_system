// SPDX-License-Identifier: GPL-2.0
/*
 * ai_startup.h - AIKernel 启动参数与运行时开关（Prompt 02）
 *
 * ai.* 启动参数：
 *   ai.enabled=0|1   内核启动即控制 AI 总开关（默认 1 = CONFIG_AIKERNEL 构建时；
 *                    0 启动时 sysfs/procfs/NETLINK_AI 节点全部不创建，零回归）
 *   ai.model_path=/path   AI 模型目录（默认 /etc/ai/；initramfs 预加载与
 *                     /sys/kernel/ai/model_load 下发均在此目录下查找模型文件）
 *   ai.log_level=0..3 日志级别（0=静默 1=默认 2=详细 3=调试）
 *
 * 本模块归 CONFIG_AIKERNEL_RUNTIME 门控（Runtime 核心需要总开关）；
 * sysfs/procfs/netlink 的创建与运行时操作都以 ai_startup_get_enabled() 为准。
 */

#ifndef _AIKERNEL_AI_STARTUP_H
#define _AIKERNEL_AI_STARTUP_H

#include "ai_types.h"
#include <linux/types.h>

/* initramfs 预加载模型文件名（位于 ai.model_path 目录下） */
#define AI_STARTUP_INITRAMFS_MODEL	"model"
#define AI_STARTUP_MODEL_FILE_SUFFIX	".bin"
#define AI_STARTUP_MAX_MODEL_SIZE	(1024 * 1024)   /* 1MB */

#ifdef CONFIG_AIKERNEL_RUNTIME

/**
 * ai_startup_parse() - 启动参数统一解析入口
 * @key:  参数名（"enabled" / "model_path" / "log_level"）
 * @val:  参数值字符串（可为 NULL）
 *
 * 由三个 __setup 注册器（ai.enabled= / ai.model_path= / ai.log_level=）转发调用。
 * 返回 0=已处理；1=未知参数（由上层继续处理）。
 */
int ai_startup_parse(const char *key, const char *val);

/**
 * ai_startup_get_enabled() - 查询 AI 运行时总开关（1=开 0=关）
 *
 * 读取 ai.enabled 启动参数（默认 1）。sysfs/procfs/netlink 创建与
 * 运行时操作都以它为准。
 */
bool ai_startup_get_enabled(void);

/**
 * ai_startup_set_enabled() - 运行时修改 AI 总开关（sysfs enabled 写操作）
 * @enable: 1=开 0=关
 *
 * 关闭后 ACT/模型下发/遥测读取等运行时操作拒绝（AI_ERR_DISABLED）；
 * 节点仍存在（控制面保留）。返回 AI_OK。
 */
int ai_startup_set_enabled(bool enable);

/**
 * ai_startup_get_model_path() - 查询 AI 模型目录（ai.model_path）
 *
 * 返回内核静态缓冲（勿修改）。默认 "/etc/ai/"。
 */
const char *ai_startup_get_model_path(void);

/**
 * ai_startup_get_log_level() - 查询 AI 日志级别（0~3，默认 1）
 */
u8 ai_startup_get_log_level(void);

/**
 * ai_startup_load_model() - 按名称加载模型（内置 echo 模型 / 目录内模型文件）
 * @name: 模型名。name == "echo" 加载内置 echo 模型；否则加载
 *        <model_path>/<name>.bin 文件包装为 echo 模型（source=EMBEDDED）。
 *
 * 成功返回模型 id（>=1），失败返回负错误码（AI_ERR_NOT_FOUND / AI_ERR_MEMORY...）。
 */
int ai_startup_load_model(const char *name);

/**
 * ai_startup_unload_model() - 按名称卸载模型（转发 ai_model_unload_by_name）
 * @name: 模型名
 *
 * 返回 AI_OK 或负错误码（AI_ERR_NOT_FOUND）。
 */
int ai_startup_unload_model(const char *name);

/**
 * ai_initramfs_model_preload() - initramfs 模型预加载（由 init/initramfs.c 调用）
 *
 * 当 <model_path>/model.bin 存在时读入并注册为模型（AI_MODEL_SOURCE_EMBEDDED），
 * 不存在则跳过（pr_info 记录）。
 */
void ai_initramfs_model_preload(void);

#else /* !CONFIG_AIKERNEL_RUNTIME */

static inline bool ai_startup_get_enabled(void) { return false; }
static inline int ai_startup_set_enabled(bool enable) { return AI_OK; }
static inline const char *ai_startup_get_model_path(void) { return "/etc/ai/"; }
static inline u8 ai_startup_get_log_level(void) { return 0; }
static inline int ai_startup_load_model(const char *name) { return AI_ERR_NOT_IMPLEMENTED; }
static inline int ai_startup_unload_model(const char *name) { return AI_ERR_NOT_IMPLEMENTED; }
static inline void ai_initramfs_model_preload(void) { }

#endif /* CONFIG_AIKERNEL_RUNTIME */

#endif /* _AIKERNEL_AI_STARTUP_H */
