// SPDX-License-Identifier: GPL-2.0
/*
 * demo_sandbox_chain.c - W42 演示：主进程经工具面 spawn 子智能体全链路
 *
 * 与 test_sandbox_tools 的差别：策略闸门用**真实现**（policy/ai_user_policy.c，
 * AIKERNEL_ASSUME_YES=1 预授权 W2），aik-sandbox / ai / 引擎全部为真链路。
 * 走的正是 ask 闭环里 sandbox_* 工具的执行代码（tool_executor_run →
 * exec_sandbox → aik-sandbox run → ai -p … -s sb-<name> -N）。
 *
 * L1 上 SME 记忆服务未运行，cmd_ask 的 SME 路由激活不到 sandbox_* 工具
 * （默认激活集 7 件，SME 语料命中才扩入——预有机制，非本波改动）；本演示
 * 因此在执行器层直接驱动工具面，作为「主进程派生子 ask」的完整记录。
 *
 * 用法: sudo ./demo_sandbox_chain <tools.json 路径> [区名] [任务]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ai_types.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"
#include "policy/ai_user_policy.h"
#include "policy/ai_lease.h"

int main(int argc, char **argv)
{
	struct tool_registry reg;
	char *err = NULL;
	const struct ai_tool *t_create, *t_spawn, *t_destroy;
	const char *tools_json = argc > 1 ? argv[1] : "../tools/tools.json";
	const char *zone = argc > 2 ? argv[2] : "demo1";
	char task[512];
	char args[1024];
	char *out = NULL;
	int ok = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	{
		char lerr[AI_LEASE_ERR_MAX] = "";

		ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));
	}
	if (argc > 3) {
		snprintf(task, sizeof(task), "%s", argv[3]);
	} else {
		snprintf(task, sizeof(task),
			 "用一句话报告：你的主机名、根目录可见的目录清单、"
			 "以及你能否读到 /etc/shadow");
	}

	/* 真注册表 + 真策略闸门（W2 需 root；assume_yes 预授权，
	 * 等价 ai -y / AIKERNEL_ASSUME_YES=1 的既有授权路径） */
	setenv("AIKERNEL_TOOLS_JSON", tools_json, 1);
	setenv("AIKERNEL_ASSUME_YES", "1", 1);
	ai_policy_set_assume_yes(1);
	memset(&reg, 0, sizeof(reg));
	if (tool_registry_load(&reg, &err) != AI_OK) {
		fprintf(stderr, "demo: 注册表加载失败: %s\n",
			err ? err : "?");
		free(err);
		return 2;
	}
	printf("== demo_sandbox_chain: tools=%d (%s) uid=%d ==\n",
	       reg.tool_count, tools_json, getuid());

	t_create = tool_registry_find(&reg, "sandbox_create");
	t_spawn = tool_registry_find(&reg, "sandbox_spawn");
	t_destroy = tool_registry_find(&reg, "sandbox_destroy");
	if (!t_create || !t_spawn || !t_destroy) {
		fprintf(stderr, "demo: sandbox 工具不在注册表\n");
		return 2;
	}

	printf("\n[1] sandbox_create {name:%s}\n", zone);
	snprintf(args, sizeof(args), "{\"name\":\"%s\"}", zone);
	tool_executor_run(t_create, args, &out, &ok);
	printf("    ok=%d out: %s\n", ok, out ? out : "(null)");
	free(out);

	printf("\n[2] sandbox_spawn {name:%s, max_seconds:180}\n"
	       "    task: %s\n", zone, task);
	snprintf(args, sizeof(args),
		 "{\"name\":\"%s\",\"task\":\"%s\",\"max_seconds\":180}",
		 zone, task);
	tool_executor_run(t_spawn, args, &out, &ok);
	printf("    ok=%d\n    ---- 子智能体摘要（工具返回原文） ----\n%s\n"
	       "    ---- 摘要结束 ----\n", ok, out ? out : "(null)");
	free(out);

	printf("\n[3] sandbox_destroy {name:%s}\n", zone);
	snprintf(args, sizeof(args), "{\"name\":\"%s\"}", zone);
	tool_executor_run(t_destroy, args, &out, &ok);
	printf("    ok=%d out: %s\n", ok, out ? out : "(null)");
	free(out);

	tool_registry_free(&reg);
	printf("\n== demo 完成 ==\n");
	return 0;
}
