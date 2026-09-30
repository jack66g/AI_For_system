/*
 * ai_types.h - AI 子系统公共类型定义
 *
 * 定义整个 AI 子系统共享的基础类型、错误码和常量。
 */
#ifndef _AI_TYPES_H
#define _AI_TYPES_H

#include <stddef.h>

/* ---- 错误码 ---- */

enum ai_error {
	AI_OK                   =  0,   /* 成功 */
	AI_ERR_GENERIC          = -1,   /* 通用错误 */
	AI_ERR_NO_CONFIG        = -2,   /* 配置不存在 */
	AI_ERR_NO_PROVIDER      = -3,   /* Provider 未配置 */
	AI_ERR_NO_MODEL         = -4,   /* 模型未选择 */
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
};

/* 将错误码转换为可读字符串 */
const char *ai_error_string(int err);

/* ---- 缓冲区大小常量 ---- */

#define AI_MAX_LINE_LEN        4096   /* 输入行最大长度 */
#define AI_MAX_CMD_NAME        64     /* 命令名最大长度 */
#define AI_MAX_MODEL_NAME      128    /* 模型名最大长度 */
#define AI_MAX_URL_LEN         512    /* URL 最大长度 */
#define AI_MAX_KEY_LEN         256    /* API Key 最大长度 */
#define AI_MAX_RESPONSE_LEN    65536  /* 响应最大长度 */
#define AI_MAX_PROVIDER_NAME   64     /* Provider 名最大长度 */
#define AI_PATH_MAX            1024   /* 路径最大长度 */

/* ---- 公共宏 ---- */

#define AI_ARRAY_SIZE(arr)    (sizeof(arr) / sizeof((arr)[0]))
#define AI_UNUSED(x)          ((void)(x))

#endif /* _AI_TYPES_H */
