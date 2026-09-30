/*
 * ai_types.c - 公共类型实现
 *
 * 提供错误码到字符串的转换等基础功能。
 */
#include <stdio.h>
#include "ai_types.h"

/* 错误码字符串映射表 */
static const char *error_strings[] = {
	[0]  = "Success",
	[1]  = "Generic error",           /* -1 -> index 1 */
	[2]  = "No configuration found",
	[3]  = "No provider configured",
	[4]  = "No model selected",
	[5]  = "Network error",
	[6]  = "API error",
	[7]  = "Authentication failed",
	[8]  = "Configuration error",
	[9]  = "Memory allocation failed",
	[10] = "Resource not found",
	[11] = "Not implemented",
	[12] = "Invalid argument",
	[13] = "Storage error",
	[14] = "Parse error",
};

const char *ai_error_string(int err)
{
	int idx;

	if (err == 0)
		return error_strings[0];

	idx = -err;
	if (idx < 0 || idx >= (int)(sizeof(error_strings) / sizeof(error_strings[0])))
		return "Unknown error";

	return error_strings[idx];
}
