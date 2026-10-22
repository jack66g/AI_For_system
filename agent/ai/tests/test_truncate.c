// SPDX-License-Identifier: GPL-2.0
/*
 * test_truncate.c - 修复 8 截断行为单测
 * 用 cat 读取 200KB 文件：期望结果 ≤ 64KB 且带 "[截断，工具输出共 N 字节"
 * 标注（N ≈ 文件实际字节数），而不是静默截断。
 *
 * W18：夹具自足——测试开头内置生成 /tmp/afix_big.txt（204800 字节
 * 文本循环，40 字节模式 × 5120），不再依赖外部预置文件；atexit
 * 统一清理（含 FAIL 提前 return 路径）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ai_types.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"

#define FIXTURE_PATH    "/tmp/afix_big.txt"
#define FIXTURE_BYTES   204800
/* 40 字节模式串，40 × 5120 = 204800 恰好整除 */
#define FIXTURE_PATTERN "0123456789012345678901234567890123456789"

static void fixture_cleanup(void)
{
	unlink(FIXTURE_PATH);
}

/* fixture_build - 内置生成 204800 字节文本夹具（0=成功） */
static int fixture_build(void)
{
	FILE *fp = fopen(FIXTURE_PATH, "w");
	size_t plen = strlen(FIXTURE_PATTERN);
	size_t written = 0;

	if (!fp)
		return -1;
	while (written < FIXTURE_BYTES) {
		size_t remain = FIXTURE_BYTES - written;
		size_t n = remain < plen ? remain : plen;

		if (fwrite(FIXTURE_PATTERN, 1, n, fp) != n) {
			fclose(fp);
			return -1;
		}
		written += n;
	}
	fclose(fp);
	return 0;
}

int main(void)
{
	struct tool_registry reg;
	char *err = NULL;
	const struct ai_tool *tool;
	char *out = NULL;
	int ok = 0;
	int rc;
	size_t len;
	const char *marker;

	/* 夹具自足：内置生成 + atexit 清理（覆盖全部 return 路径） */
	if (atexit(fixture_cleanup) != 0) {
		printf("FAIL: atexit register\n");
		return 1;
	}
	if (fixture_build() != 0) {
		printf("FAIL: fixture build\n");
		return 1;
	}

	rc = tool_registry_load(&reg, &err);
	if (rc != AI_OK) {
		printf("FAIL: registry load: %s\n", err ? err : "?");
		return 1;
	}
	tool = tool_registry_find(&reg, "exec_run");
	if (!tool) {
		printf("FAIL: exec_run not found\n");
		return 1;
	}

	rc = tool_executor_run(tool,
			       "{\"command\":\"cat\",\"args\":"
			       "[\"/tmp/afix_big.txt\"]}", &out, &ok);
	if (rc != AI_OK || !out) {
		printf("FAIL: run rc=%d\n", rc);
		return 1;
	}
	len = strlen(out);
	printf("result bytes = %zu (limit %d)\n", len, 64 * 1024);
	marker = strstr(out, "[截断，工具输出共 ");
	if (len > (size_t)64 * 1024) {
		printf("FAIL: result exceeds 64KB without hard cap\n");
		return 1;
	}
	if (!marker) {
		printf("FAIL: truncation marker missing\n");
		return 1;
	}
	{
		const char *p = marker + strlen("[截断，工具输出共 ");
		long total = strtol(p, NULL, 10);

		printf("marker total bytes = %ld (file = 204800)\n", total);
		if (total < 204800) {
			printf("FAIL: marker total (%ld) < file size\n", total);
			return 1;
		}
	}
	printf("PASS: 截断标注存在且总字节数诚实\n");
	free(out);
	tool_registry_free(&reg);
	return 0;
}
