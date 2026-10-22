// SPDX-License-Identifier: GPL-2.0
/*
 * test_registry_shadow.c - W48 根注册表遮蔽回归（F1 同机制）
 *
 * 背景：tool_registry_load 搜索顺序是 AIKERNEL_TOOLS_JSON → ./tools.json
 * → <exe>/tools.json → <exe>/tools/tools.json。agent/ai 根目录若残留
 * 旧 79 件 tools.json，在树根直接运行 ai 时会遮蔽 tools/tools.json 的
 * 114 件正典（实测横幅 5/79，新工具对 AI 不可见）。W48 处置：根同名
 * 文件改为指向 tools/ 的符号链接（单一正典）。
 *
 * 本测试在 agent/ai 根目录（chdir("..")）加载注册表并断言：
 *   1. 无环境变量时加载到 114 件，且 realpath(source_path) ==
 *      realpath(tools/tools.json)；
 *   2. 根 tools-sandbox.json 同样指向正典，exec 白名单 57 条
 *      （W72 新增 python3/gcc/cc；W69 tar 升 W2 后为 54 条）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "ai_types.h"
#include "tools/tool_registry.h"

static int g_fail;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		g_fail++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

static int same_realpath(const char *a, const char *b)
{
	char ra[PATH_MAX], rb[PATH_MAX];

	if (!realpath(a, ra) || !realpath(b, rb))
		return 0;
	return strcmp(ra, rb) == 0;
}

int main(void)
{
	struct tool_registry reg;
	char *err = NULL;
	char oldcwd[PATH_MAX];
	const struct ai_tool *t;

	printf("==== test_registry_shadow: 根注册表遮蔽回归 ====\n");
	if (!getcwd(oldcwd, sizeof(oldcwd))) {
		printf("FAIL: getcwd\n");
		return 1;
	}
	if (chdir("..") != 0) {
		printf("FAIL: chdir(..)（应在 tests/ 下运行）\n");
		return 1;
	}
	unsetenv("AIKERNEL_TOOLS_JSON");
	memset(&reg, 0, sizeof(reg));
	CHECK(tool_registry_load(&reg, &err) == AI_OK,
	      "树根无环境变量加载 tools.json");
	CHECK(reg.tool_count == 156,
	      "树根加载到 156 件（W77d；未被旧副本遮蔽）");
	CHECK(reg.source_path && same_realpath(reg.source_path,
					       "tools/tools.json"),
	      "source_path 指向正典 tools/tools.json（符号链接已解析）");
	tool_registry_free(&reg);

	setenv("AIKERNEL_TOOLS_JSON", "tools-sandbox.json", 1);
	memset(&reg, 0, sizeof(reg));
	CHECK(tool_registry_load(&reg, &err) == AI_OK,
	      "树根加载 tools-sandbox.json");
	CHECK(reg.tool_count == 7, "受限表 7 件");
	CHECK(reg.source_path && same_realpath(reg.source_path,
					       "tools/tools-sandbox.json"),
	      "受限表 source_path 指向正典（未被旧副本遮蔽）");
	t = tool_registry_find(&reg, "exec_run");
	CHECK(t && t->exec_cmd_count == 57,
	      "受限表 exec 白名单 57 条（W72 新增编程三件）");
	tool_registry_free(&reg);
	unsetenv("AIKERNEL_TOOLS_JSON");

	if (chdir(oldcwd) != 0) {
		printf("FAIL: chdir(oldcwd) 恢复工作目录失败\n");
		g_fail++;
	}
	printf("== test_registry_shadow: %s ==\n",
	       g_fail ? "FAIL" : "ALL PASS");
	return g_fail ? 1 : 0;
}
