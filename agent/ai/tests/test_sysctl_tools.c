// SPDX-License-Identifier: GPL-2.0
/*
 * test_sysctl_tools.c - W48 通用 sysctl/sysfs 通道回归
 *
 * 覆盖（任务书要求四例 + 扩展）：
 *   1. 合法读写：读 vm.swappiness，写回原值，确认 OK 与 old/new 回显；
 *   2. 黑名单拒绝：kernel.sysrq 必须拒绝且说明原因、无 --force 旁路；
 *   3. 穿越拒绝：../sysrq-trigger、net/../../sysrq-trigger 均拒绝；
 *   4. 非法值拒绝：JSON "\n" 换行注入必须拒绝；
 *   5. prefix 列举：kernel 子树输出 key = value 且可截断；
 *   6. 黑名单工具输出含 kernel.sysrq；
 *   7. sysfs_get 读 /proc/sys/vm/swappiness（允许前缀）；
 *      sysfs_get/set 对 /etc/passwd 一律拒绝。
 *
 * 写用例需要 root（vm.swappiness 权限 0644）。测试二进制应以
 * sudo 运行；非 root 时写用例标记 SKIP（不伪造通过）。
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

static int g_fail;
static int g_skip;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		g_fail++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

#define SKIP(msg) do { \
	printf("SKIP: %s\n", msg); \
	g_skip++; \
} while (0)

static int run_tool(struct tool_registry *reg, const char *name,
		    const char *args, char **out)
{
	const struct ai_tool *t = tool_registry_find(reg, name);
	int ok = 0;

	*out = NULL;
	if (!t) {
		*out = strdup("NO-SUCH-TOOL");
		return -1;
	}
	tool_executor_run(t, args, out, &ok);
	if (!*out)
		*out = strdup("(null out)");
	return ok;
}

/* 从 "vm.swappiness = 60" 提取值（返回 malloc 字符串） */
static char *extract_value(const char *out)
{
	const char *eq = strchr(out, '=');
	const char *p;

	if (!eq)
		return NULL;
	p = eq + 1;
	while (*p == ' ' || *p == '\t')
		p++;
	{
		size_t n = strcspn(p, "\r\n");
		char *v = malloc(n + 1);

		if (!v)
			return NULL;
		memcpy(v, p, n);
		v[n] = '\0';
		return v;
	}
}

int main(void)
{
	struct tool_registry reg;
	char *err = NULL;
	char *out = NULL;
	char *swappiness = NULL;
	int ok;

	printf("==== test_sysctl_tools: W48 通用 sysctl/sysfs ====\n");
	ai_policy_set_assume_yes(1);   /* W2 闸门放行（测试真正的拒绝面） */

	CHECK(tool_channel_from_str("sysctl") == TOOL_CH_SYSCTL,
	      "sysctl 通道映射");
	CHECK(tool_channel_from_str("sysfs") == TOOL_CH_SYSFS_DYN,
	      "sysfs 通道映射");

	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	memset(&reg, 0, sizeof(reg));
	CHECK(tool_registry_load(&reg, &err) == AI_OK,
	      "主注册表加载（tools.json）");
	CHECK(tool_registry_find(&reg, "sysctl_get") != NULL,
	      "sysctl_get 已注册");
	CHECK(tool_registry_find(&reg, "sysctl_set") != NULL,
	      "sysctl_set 已注册");
	CHECK(tool_registry_find(&reg, "sysctl_blacklist") != NULL,
	      "sysctl_blacklist 已注册");

	/* ---- 1. 合法读 ---- */
	ok = run_tool(&reg, "sysctl_get", "{\"key\":\"vm.swappiness\"}", &out);
	CHECK(ok == 1 && strstr(out, "vm.swappiness =") != NULL,
	      "sysctl_get 读 vm.swappiness");
	if (ok == 1)
		swappiness = extract_value(out);
	free(out);
	out = NULL;
	CHECK(swappiness != NULL, "解析 vm.swappiness 当前值");

	/* ---- 1b. 合法写回原值（root） ---- */
	if (swappiness && getuid() == 0) {
		char args[256];

		snprintf(args, sizeof(args),
			 "{\"key\":\"vm.swappiness\",\"value\":\"%s\"}",
			 swappiness);
		ok = run_tool(&reg, "sysctl_set", args, &out);
		CHECK(ok == 1 && strstr(out, "OK: 已写入") != NULL &&
		      strstr(out, "旧值:") != NULL &&
		      strstr(out, "新值:") != NULL,
		      "sysctl_set 写回原值（OK + 旧值/新值审计回显）");
		free(out);
		out = NULL;
	} else if (swappiness) {
		SKIP("sysctl_set 合法写需要 root（请 sudo 运行本测试）");
	}
	free(swappiness);

	if (getuid() == 0) {
	/* ---- 2. 黑名单拒绝 ---- */
	ok = run_tool(&reg, "sysctl_set",
		      "{\"key\":\"kernel.sysrq\",\"value\":\"1\"}", &out);
	CHECK(ok == 0 && strstr(out, "崩溃黑名单拒绝") != NULL &&
	      strstr(out, "SysRq") != NULL,
	      "kernel.sysrq 被黑名单拒绝并说明原因");
	CHECK(strstr(out, "OK: 已写入") == NULL, "黑名单拒绝未发生写入");
	free(out);
	out = NULL;

	ok = run_tool(&reg, "sysctl_set",
		      "{\"key\":\"kernel.core_pattern\",\"value\":\"|/bin/true\"}",
		      &out);
	CHECK(ok == 0 && strstr(out, "崩溃黑名单拒绝") != NULL,
	      "kernel.core_pattern 被黑名单拒绝");
	free(out);
	out = NULL;

	ok = run_tool(&reg, "sysctl_set",
		      "{\"key\":\"vm.panic_on_oom\",\"value\":\"1\"}", &out);
	CHECK(ok == 0 && strstr(out, "崩溃黑名单拒绝") != NULL,
	      "vm.panic_on_oom 被黑名单拒绝");
	free(out);
	out = NULL;

	/* ---- 3. 穿越拒绝 ---- */
	ok = run_tool(&reg, "sysctl_set",
		      "{\"key\":\"../sysrq-trigger\",\"value\":\"b\"}", &out);
	CHECK(ok == 0 && strstr(out, "非法 sysctl key") != NULL,
	      "../sysrq-trigger 穿越被拒绝");
	free(out);
	out = NULL;
	ok = run_tool(&reg, "sysctl_get",
		      "{\"key\":\"net/../../sysrq-trigger\"}", &out);
	CHECK(ok == 0 && strstr(out, "非法 sysctl key") != NULL,
	      "net/../../sysrq-trigger 穿越被拒绝");
	free(out);
	out = NULL;

	/* ---- 4. 非法值拒绝（JSON \n 解码为真实换行） ---- */
	ok = run_tool(&reg, "sysctl_set",
		      "{\"key\":\"vm.swappiness\",\"value\":\"60\\n70\"}",
		      &out);
	CHECK(ok == 0 && strstr(out, "非法值") != NULL,
	      "换行注入值被拒绝");
	CHECK(strstr(out, "OK: 已写入") == NULL, "非法值未发生写入");
	free(out);
	out = NULL;

	} else {
		SKIP("W2 拒绝面需要 root（sudo 运行）");
	}

	/* ---- 5. prefix 列举 ---- */
	ok = run_tool(&reg, "sysctl_get", "{\"prefix\":\"kernel\"}", &out);
	CHECK(ok == 1 && strstr(out, "kernel.") != NULL &&
	      strstr(out, " = ") != NULL,
	      "prefix=kernel 列举 key = value");
	free(out);
	out = NULL;

	/* ---- 6. 黑名单全文工具 ---- */
	ok = run_tool(&reg, "sysctl_blacklist", "{}", &out);
	CHECK(ok == 1 && strstr(out, "kernel.sysrq") != NULL &&
	      strstr(out, "不可") != NULL,
	      "sysctl_blacklist 输出黑名单与不可绕过说明");
	{
		static const char *const keys[] = {
			"kernel.sysrq", "kernel.panic", "kernel.hung_task_panic",
			"kernel.softlockup_panic", "kernel.hardlockup_panic",
			"kernel.core_pattern", "kernel.modules_disabled",
			"kernel.kexec_load_disabled",
			"kernel.sched_rt_runtime_us", "vm.panic_on_oom",
			"vm.oom_kill_allocating_task", "/proc/sysrq-trigger",
			NULL,
		};
		int all = 1, k;

		for (k = 0; keys[k]; k++) {
			if (!strstr(out, keys[k]))
				all = 0;
		}
		CHECK(all, "黑名单 12 项全文齐备（含 vm.oom_kill_allocating_task）");
	}
	free(out);
	out = NULL;

	/* ---- 7. sysfs 动态通道 ---- */
	ok = run_tool(&reg, "sysfs_get",
		      "{\"path\":\"/proc/sys/vm/swappiness\"}", &out);
	CHECK(ok == 1 && strpbrk(out, "0123456789") != NULL,
	      "sysfs_get 读 /proc/sys/vm/swappiness");
	free(out);
	out = NULL;
	/* /proc/net 是 /proc/self/net 的符号链接；realpath 后必须仍被接受 */
	ok = run_tool(&reg, "sysfs_get", "{\"path\":\"/proc/net/dev\"}", &out);
	CHECK(ok == 1 && out && strlen(out) > 0 && strstr(out, "ERROR") == NULL,
	      "sysfs_get 读 /proc/net/dev（realpath 符号链接不误拒）");
	free(out);
	out = NULL;
	ok = run_tool(&reg, "sysfs_get", "{\"path\":\"/proc/1/cmdline\"}", &out);
	CHECK(ok == 0 && strstr(out, "不在读取允许前缀") != NULL &&
	      strstr(out, "exec_run") != NULL,
	      "sysfs_get 拒绝 /proc/<pid>/* 并提示 exec_run");
	free(out);
	out = NULL;
	ok = run_tool(&reg, "sysfs_get", "{\"path\":\"/etc/passwd\"}", &out);
	CHECK(ok == 0 && strstr(out, "不在读取允许前缀") != NULL,
	      "sysfs_get 拒绝 /etc/passwd");
	free(out);
	out = NULL;
	if (getuid() == 0) {
	ok = run_tool(&reg, "sysfs_set",
		      "{\"path\":\"/etc/passwd\",\"value\":\"x\"}", &out);
	CHECK(ok == 0 && strstr(out, "不在写入允许前缀") != NULL,
	      "sysfs_set 拒绝 /etc/passwd");
	free(out);
	out = NULL;
	ok = run_tool(&reg, "sysfs_set",
		      "{\"path\":\"/sys/fs/cgroup/../../etc/passwd\",\"value\":\"x\"}",
		      &out);
	CHECK(ok == 0 && (strstr(out, "..") != NULL ||
			  strstr(out, "不在写入允许前缀") != NULL ||
			  strstr(out, "不可解析") != NULL),
	      "sysfs_set 拒绝 .. 穿越");
	} else {
		SKIP("sysfs_set W2 面需要 root（sudo 运行）");
	}

	free(out);
	out = NULL;

	tool_registry_free(&reg);
	printf("== test_sysctl_tools: %s (fail=%d skip=%d) ==\n",
	       g_fail ? "FAIL" : "ALL PASS", g_fail, g_skip);
	return g_fail ? 1 : 0;
}
