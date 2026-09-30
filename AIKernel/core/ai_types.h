// SPDX-License-Identifier: GPL-2.0
/*
 * ai_types.h - AIKernel 内核侧公共类型定义
 *
 * AIKernel 核心模块共享的基础类型、错误码和常量。
 * 错误码与 agent/ai/include/ai_types.h（用户态）对齐复用，
 * 并新增内核侧专用错误码（AI_ERR_BUSY / AI_ERR_RING_FULL / AI_ERR_DISABLED）。
 *
 * 所有新增 AIKernel 头文件必须先包含本文件。
 */

#ifndef _AIKERNEL_AI_TYPES_H
#define _AIKERNEL_AI_TYPES_H

#include <linux/types.h>
#include <linux/bug.h>

/* ---- 错误码（对齐 agent/00_AI_函数调用接口指南.md 第六节 + agent ai_types.h） ---- */

enum ai_error {
	AI_OK                   =  0,   /* 成功 */
	AI_ERR_GENERIC          = -1,   /* 通用错误 */
	AI_ERR_NO_CONFIG        = -2,   /* 配置不存在 */
	AI_ERR_NO_PROVIDER      = -3,   /* Provider 未配置 */
	AI_ERR_NO_MODEL         = -4,   /* 模型未选择/未加载 */
	AI_ERR_NETWORK          = -5,   /* 网络错误 */
	AI_ERR_API              = -6,   /* API 返回错误 */
	AI_ERR_AUTH             = -7,   /* 认证失败 */
	AI_ERR_CONFIG           = -8,   /* 配置错误 */
	AI_ERR_MEMORY           = -9,   /* 内存分配失败 */
	AI_ERR_NOT_FOUND        = -10,  /* 资源未找到 */
	AI_ERR_NOT_IMPLEMENTED  = -11,  /* 功能未实现 */
	AI_ERR_INVALID_ARG      = -12,  /* 无效参数 */
	AI_ERR_STORAGE          = -13,  /* 存储错误 */
	AI_ERR_PARSE            = -14,  /* 解析错误 */
	/* ---- AIKernel 内核侧专用（-15 起） ---- */
	AI_ERR_BUSY             = -15,  /* 资源忙 */
	AI_ERR_RING_FULL        = -16,  /* 遥测 ring buffer 满（记录被丢弃） */
	AI_ERR_DISABLED         = -17,  /* 功能被禁用（CONFIG 关闭或运行时关闭） */
};

/* ---- 公共常量 ---- */

#define AI_MAX_NAME_LEN         128   /* 名称（模型/策略）最大长度 */
#define AI_MAX_CMD_NAME         64    /* 命令名最大长度（对齐 agent） */
#define AI_PATH_MAX             1024  /* 路径最大长度（对齐 agent） */

/* ---- 公共宏 ---- */

#define AI_ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

/* ---- AI 错误码 → errno 映射（sysfs/procfs/netlink 出口统一使用） ---- */

#include <linux/errno.h>

static inline int ai_error_to_errno(int ai_err)
{
	switch (ai_err) {
	case AI_OK:                     return 0;
	case AI_ERR_NO_CONFIG:          return -ENOENT;
	case AI_ERR_NO_PROVIDER:        return -ENODEV;
	case AI_ERR_NO_MODEL:           return -ENOENT;
	case AI_ERR_NETWORK:            return -ENETDOWN;
	case AI_ERR_API:                return -EPROTO;
	case AI_ERR_AUTH:               return -EACCES;
	case AI_ERR_CONFIG:             return -EINVAL;
	case AI_ERR_MEMORY:             return -ENOMEM;
	case AI_ERR_NOT_FOUND:          return -ENOENT;
	case AI_ERR_NOT_IMPLEMENTED:    return -ENOSYS;
	case AI_ERR_INVALID_ARG:        return -EINVAL;
	case AI_ERR_STORAGE:            return -EIO;
	case AI_ERR_PARSE:              return -EINVAL;
	case AI_ERR_BUSY:               return -EBUSY;
	case AI_ERR_RING_FULL:          return -ENOSPC;
	case AI_ERR_DISABLED:           return -EPERM;
	default:                        return -EIO;
	}
}

#endif /* _AIKERNEL_AI_TYPES_H */
