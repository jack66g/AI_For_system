/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_sandbox_programming.c - W72：沙箱受限表编程能力冒烟
 *
 * 背景：W70 T13 子智能体在沙箱内无法执行 python3（受限表不含，W2
 * fail-closed）、which 二进制在沙盒 root 不可用（/usr/bin/which →
 * /etc/alternatives/which，沙盒 /etc 不含 alternatives）。
 *
 * W72 受限表：
 *   - 新增 python3/gcc/cc（沙箱内 W1；主表 python3 仍 W2）；
 *   - which 保持 R，执行器在 AIKERNEL_SANDBOX 下用内建 PATH 查找；
 *   - 受限表仍 0 个 W2（fail-closed 不变）。
 *
 * 本测试以 AIKERNEL_SANDBOX 身份加载 tools-sandbox.json，真实执行
 * tee 写脚本 → python3 计算 → gcc/cc 编译 → which 探测。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "ai_types.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"
#include "policy/ai_lease.h"

static int g_fail;

#define CHECK(cond, msg)						\
	do {								\
		if (cond) {						\
			printf("  [PASS] %s\n", msg);			\
		} else {						\
			printf("  [FAIL] %s (%s:%d)\n", msg,		\
			       __FILE__, __LINE__);			\
			g_fail++;					\
		}							\
	} while (0)

static int run_exec(const struct ai_tool *t, const char *args,
		    char **out, int *ok)
{
	*out = NULL;
	*ok = 0;
	return tool_executor_run(t, args, out, ok);
}

int main(void)
{
	struct tool_registry reg;
	const struct ai_tool *t;
	char *err = NULL;
	char *out = NULL;
	int ok = 0;
	int i;
	int have_py = 0, have_gcc = 0, have_cc = 0, have_which = 0;
	int cmd_w2 = 0;

	printf("==== test_sandbox_programming: W72 sandbox exec ====\n");
	{
		char lerr[AI_LEASE_ERR_MAX] = "";

		/* worker：D2+ 仍拒绝；W1 受限表命令（python3 沙箱内 W1）放行 */
		ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));
	}
	setenv("AIKERNEL_POLICY", "/dev/null", 1);
	setenv("AIKERNEL_SANDBOX", "w72-smoke", 1);
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools-sandbox.json", 1);

	if (tool_registry_load(&reg, &err) != AI_OK) {
		printf("FATAL: tools-sandbox.json load: %s\n",
		       err ? err : "?");
		return 2;
	}
	CHECK(reg.tool_count == 7, "受限表 7 件");
	t = tool_registry_find(&reg, "exec_run");
	CHECK(t != NULL, "受限表含 exec_run");
	if (!t)
		return 1;
	CHECK(t->exec_cmd_count == 57,
	      "受限表 exec 命令 57 条（54 + python3/gcc/cc）");
	for (i = 0; i < t->exec_cmd_count; i++) {
		const struct tool_exec_cmd *c = &t->exec_cmds[i];

		if (c->risk && strcmp(c->risk, "W2") == 0)
			cmd_w2 = 1;
		if (strcmp(c->command, "python3") == 0)
			have_py = c->risk && strcmp(c->risk, "W1") == 0;
		if (strcmp(c->command, "gcc") == 0)
			have_gcc = c->risk && strcmp(c->risk, "W1") == 0;
		if (strcmp(c->command, "cc") == 0)
			have_cc = c->risk && strcmp(c->risk, "W1") == 0;
		if (strcmp(c->command, "which") == 0)
			have_which = c->risk && strcmp(c->risk, "R") == 0;
	}
	CHECK(!cmd_w2, "受限表 exec 命令 0 个 W2（fail-closed 保持）");
	CHECK(have_py, "python3 在沙箱表内为 W1");
	CHECK(have_gcc && have_cc, "gcc/cc 在沙箱表内为 W1");
	CHECK(have_which, "which 在沙箱表内为 R");

	unlink("/tmp/w72_hello.py");
	unlink("/tmp/w72_hello.c");
	unlink("/tmp/w72_hello_bin");
	unlink("/tmp/w72_hello_cc");

	/* 1) tee 写 python 脚本 → python3 计算 sum(range(10)) = 45 */
	CHECK(run_exec(t, "{\"command\":\"tee\",\"args\":"
		      "[\"/tmp/w72_hello.py\"],\"input\":"
		      "\"print(sum(range(10)))\\n\"}",
		      &out, &ok) == AI_OK && ok,
	      "沙箱内 tee 写 /tmp/w72_hello.py");
	free(out);
	out = NULL;
	CHECK(run_exec(t, "{\"command\":\"python3\",\"args\":"
		      "[\"/tmp/w72_hello.py\"]}", &out, &ok) == AI_OK && ok,
	      "沙箱内 python3 执行脚本成功（W1）");
	CHECK(out && strstr(out, "45") != NULL,
	      "python3 输出 45");
	printf("  python3 out: %.120s\n", out ? out : "(null)");
	free(out);
	out = NULL;

	/* 2) tee 写 C → gcc/cc 编译 */
	CHECK(run_exec(t, "{\"command\":\"tee\",\"args\":"
		      "[\"/tmp/w72_hello.c\"],\"input\":"
		      "\"int main(void){return 0;}\\n\"}",
		      &out, &ok) == AI_OK && ok,
	      "沙箱内 tee 写 /tmp/w72_hello.c");
	free(out);
	out = NULL;
	CHECK(run_exec(t, "{\"command\":\"gcc\",\"args\":"
		      "[\"/tmp/w72_hello.c\",\"-o\","
		      "\"/tmp/w72_hello_bin\"]}", &out, &ok) == AI_OK && ok,
	      "沙箱内 gcc 编译 hello.c 成功（W1，仅 /tmp）");
	free(out);
	out = NULL;
	{
		struct stat st;

		CHECK(stat("/tmp/w72_hello_bin", &st) == 0 && st.st_size > 0,
		      "gcc 产物存在且非空");
	}
	CHECK(run_exec(t, "{\"command\":\"cc\",\"args\":"
		      "[\"/tmp/w72_hello.c\",\"-o\","
		      "\"/tmp/w72_hello_cc\"]}", &out, &ok) == AI_OK && ok,
	      "沙箱内 cc 编译成功（沙箱表 cc→gcc）");
	free(out);
	out = NULL;
	{
		struct stat st;

		CHECK(stat("/tmp/w72_hello_cc", &st) == 0 && st.st_size > 0,
		      "cc 产物存在且非空");
	}

	/* 3) which：沙盒内建实现（不依赖 /etc/alternatives） */
	CHECK(run_exec(t, "{\"command\":\"which\",\"args\":"
		      "[\"python3\",\"gcc\"]}", &out, &ok) == AI_OK && ok,
	      "沙箱内 which python3 gcc 成功");
	CHECK(out && strstr(out, "/python3") != NULL,
	      "which 找到 python3 路径");
	CHECK(out && strstr(out, "/gcc") != NULL,
	      "which 找到 gcc 路径");
	printf("  which out: %.160s\n", out ? out : "(null)");
	free(out);
	out = NULL;

	unlink("/tmp/w72_hello.py");
	unlink("/tmp/w72_hello.c");
	unlink("/tmp/w72_hello_bin");
	unlink("/tmp/w72_hello_cc");
	tool_registry_free(&reg);
	if (g_fail == 0) {
		printf("RESULT: PASS\n");
		return 0;
	}
	printf("RESULT: FAIL (%d)\n", g_fail);
	return 1;
}
