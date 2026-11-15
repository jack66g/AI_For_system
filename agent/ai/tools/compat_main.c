// SPDX-License-Identifier: GPL-2.0
/*
 * compat_main.c - aik-compat：compat probe 的生产 CLI 面（C1）
 *
 * G2 缺口（COMPAT-C1-DESIGN §2.2）：probe 此前只有模型 tool-call 一条
 * 触达面（executor 的 TOOL_CH_COMPAT 分发），而 ai 二进制已出厂移除。
 * 本入口直调 ai_compat_probe_json 纯函数——同一判定器、两条面
 * （tool-call / CLI），probe JSON 输出零分叉。
 *
 * 用法：
 *   aik-compat probe <宿主绝对路径>
 * stdout：一行 probe JSON 原文 + 末行
 *   AIK_COMPAT rc=<0|1|-1> runnable=<0|1>
 * （rc 语义 = ai_compat_probe_json 返回值：1=可执行 / 0=有 fatal 原因 /
 * -1=参数非法）。进程退出码：0=可执行，1=有 fatal，2=使用错误。
 * 无参 / --help → 用法文本，退出 2。
 *
 * 链接（见 agent/ai/Makefile 的 aik-compat 目标）：本文件 +
 * compat_tools.c 两源，-ffunction-sections -fdata-sections +
 * -Wl,--gc-sections 只保留 probe 调用图（generate/apply/verify 与
 * 注册表/工作区面不进产物）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/compat_tools.h"

static void usage(FILE *f)
{
	fprintf(f,
		"用法: aik-compat probe <宿主绝对路径>\n"
		"  stdout: 一行 probe JSON + 末行 AIK_COMPAT rc=<0|1|-1> runnable=<0|1>\n"
		"  退出码: 0=可执行 1=有 fatal 原因 2=使用错误\n");
}

int main(int argc, char **argv)
{
	char *json = NULL;
	int runnable = 0, rc;

	if (argc == 2 && strcmp(argv[1], "--help") == 0) {
		usage(stdout);
		return 2;
	}
	if (argc != 3 || strcmp(argv[1], "probe") != 0) {
		usage(stderr);
		return 2;
	}
	rc = ai_compat_probe_json(argv[2], NULL, &json, &runnable);
	if (json) {
		printf("%s\n", json);
		free(json);
	}
	printf("AIK_COMPAT rc=%d runnable=%d\n", rc, runnable ? 1 : 0);
	return rc == 1 ? 0 : (rc < 0 ? 2 : 1);
}
