// SPDX-License-Identifier: GPL-2.0
/*
 * test_plan_mode.c - W43 plan 只读模式回归（真执行器+真策略+真 i18n）
 *
 * 覆盖面：
 *   1. plan 开关默认关闭，set/get 往返一致
 *   2. plan 系统提示文案在 i18n 表（TR_PLAN_SYS_NOTE 非空且含 plan 标记）
 *   3. plan 态工具级闸门：sandbox_create(W1)/sandbox_spawn(W2) 拒绝、
 *      sandbox_status(R)/procfs_read_status(R)/memory_search(R) 放行
 *   4. plan 态 exec 命令级分级（tools.json 单源 risk）：
 *      ls(R) 放行可执行、mkdir(W1)/kill(W2) 拒绝、
 *      systemctl args0 动词细化 status(R) 放行
 *   5. 退出 plan：W1 工具不再被 plan 闸门拦截（走真策略档位）
 *   6. 拒绝文案含 plan 标记（zh 默认表）；审计行含 PLAN_DENY
 *
 * 链接：executor/tool_registry/lang/真 ai_user_policy（-DW42_REAL_POLICY），
 * SME/netlink 用 W42 桩（恒不可用，不影响 plan 判定——memory 通道 risk=R）。
 * sandbox 二进制用 mock（AIKERNEL_SANDBOX_BIN），隔离真实环境。
 */
#define _GNU_SOURCE             /* setenv/mkdtemp */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>           /* chmod */
#include <dirent.h>

#include "ai_types.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"
#include "ai_lang.h"
#include "policy/ai_user_policy.h"
#include "policy/ai_lease.h"
#include "ai_trace.h"

static int g_fail;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		g_fail++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

/* 执行一个工具（按名查注册表），返回 ok 标志，out 为结果文本 */
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

/* mock aik-sandbox：立即成功输出一行 JSON（避免触碰真沙盒） */
static void write_mock_sb(const char *dir, const char *name)
{
	char path[512];
	FILE *fp;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fp = fopen(path, "w");
	if (!fp) {
		perror("mock sandbox script");
		exit(1);
	}
	fprintf(fp, "#!/bin/sh\n"
		    "if [ \"$1\" = \"status\" ]; then\n"
		    "  echo '{\"exists\":false}'\n"
		    "  exit 0\n"
		    "fi\n"
		    "echo '{\"ok\":true}'\n"
		    "exit 0\n");
	fclose(fp);
	chmod(path, 0755);
}

/* W69 P2-2：扫描 trace 目录，确认存在 gate=PLAN/decision=DENY 事件 */
static int trace_has_plan_deny(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	int found = 0;

	if (!d)
		return 0;
	while (!found && (e = readdir(d)) != NULL) {
		char path[512];
		FILE *fp;
		char buf[8192];
		size_t n;

		if (!strstr(e->d_name, ".jsonl"))
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		fp = fopen(path, "rb");
		if (!fp)
			continue;
		n = fread(buf, 1, sizeof(buf) - 1, fp);
		fclose(fp);
		buf[n] = 0;
		if (strstr(buf, "\"event\":\"policy_decision\"") &&
		    strstr(buf, "\"gate\":\"PLAN\"") &&
		    strstr(buf, "\"decision\":\"DENY\""))
			found = 1;
	}
	closedir(d);
	return found;
}

int main(void)
{
	struct tool_registry reg;
	char *err = NULL;
	char *out = NULL;
	char tmpdir[] = "/tmp/aik-w43sb-XXXXXX";
	char setbuf[600];
	int ok;

	if (!mkdtemp(tmpdir)) {
		perror("mkdtemp");
		return 1;
	}
	write_mock_sb(tmpdir, "mock-aik-sandbox");
	snprintf(setbuf, sizeof(setbuf), "AIKERNEL_SANDBOX_BIN=%s/mock-aik-sandbox",
		 tmpdir);
	putenv(setbuf);
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	{
		char lerr[AI_LEASE_ERR_MAX] = "";

		ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));
	}

	/* ---- 1. 开关默认与往返 ---- */
	CHECK(ai_policy_get_plan_mode() == 0, "plan 模式默认关闭");
	ai_policy_set_plan_mode(1);
	CHECK(ai_policy_get_plan_mode() == 1, "set(1) 后 get 为 1");

	/* ---- 2. 系统提示注入文案在表 ---- */
	{
		const char *note = tr(TR_PLAN_SYS_NOTE);

		CHECK(note && note[0] && strstr(note, "plan") &&
		      strstr(note, "\xe7\xa6\x81\xe6\xad\xa2") != NULL,
		      "plan 系统提示文案在 i18n 表（含\"禁止\"与 plan 标记）");
	}
	{
		const char *deny = tr(TR_PLAN_DENY);

		CHECK(deny && strstr(deny, "plan") && strstr(deny, "%s"),
		      "plan 拒绝文案在 i18n 表（含工具名/风险级占位）");
	}

	CHECK(tool_registry_load(&reg, &err) == AI_OK,
	      "主注册表加载（AIKERNEL_TOOLS_JSON=../tools/tools.json）");
	CHECK(reg.tool_count == 156, "注册表 156 件（W77d：151+5 model_*）");

	/* W69 P2-2：plan 拒绝必须写 policy_decision 事件 */
	setenv("AIKERNEL_TRACE_DIR", tmpdir, 1);
	setenv("AIKERNEL_TRACE_ENABLED", "1", 1);
	ai_trace_init(NULL, 0);
	ai_trace_session_start("w69-plan", "stub", "stub", 8192, 1024, 0,
			       "-", "-");

	/* ---- 3. 工具级：W1/W2 拒、R 放行 ---- */
	ok = run_tool(&reg, "sandbox_create", "{\"name\":\"w43t\"}", &out);
	CHECK(ok == 0 && strstr(out, "plan") != NULL,
	      "plan 态拒绝 sandbox_create（W1）");
	free(out);
	ok = run_tool(&reg, "sandbox_spawn",
		      "{\"name\":\"w43t\",\"task\":\"echo hi\"}", &out);
	CHECK(ok == 0 && strstr(out, "plan") != NULL,
	      "plan 态拒绝 sandbox_spawn（W2）");
	free(out);
	ok = run_tool(&reg, "sandbox_status", "{}", &out);
	CHECK(ok == 1 && strstr(out, "ERROR: plan") == NULL,
	      "plan 态放行 sandbox_status（R，mock bin 执行成功）");
	free(out);
	ok = run_tool(&reg, "procfs_read_status", "{}", &out);
	CHECK(strstr(out, "ERROR: plan") == NULL,
	      "plan 态放行 procfs_read_status（R，无内核时走自身错误路径）");
	free(out);
	ok = run_tool(&reg, "memory_search", "{\"text\":\"w43\"}", &out);
	CHECK(strstr(out, "ERROR: plan") == NULL,
	      "plan 态放行 memory_search（R，SME 桩不可用不影响闸门）");
	free(out);
	ok = run_tool(&reg, "memory_update",
		      "{\"id\":\"m_x\",\"text\":\"w50\"}", &out);
	CHECK(ok == 0 && strstr(out, "plan") != NULL,
	      "plan 态拒绝 memory_update（W1，记忆管理面闸门）");
	free(out);
	ok = run_tool(&reg, "memory_delete", "{\"id\":\"m_x\"}", &out);
	CHECK(ok == 0 && strstr(out, "plan") != NULL,
	      "plan 态拒绝 memory_delete（W2 红色确认）");
	free(out);

	/* ---- 4. exec 命令级分级 ---- */
	ok = run_tool(&reg, "exec_run",
		      "{\"command\":\"mkdir\",\"args\":[\"/tmp/w43t-d\"],\"timeout\":5}",
		      &out);
	CHECK(ok == 0 && strstr(out, "plan") != NULL,
	      "plan 态拒绝 exec mkdir（W1 命令）");
	free(out);
	ok = run_tool(&reg, "exec_run",
		      "{\"command\":\"kill\",\"args\":[\"12345\"],\"timeout\":5}",
		      &out);
	CHECK(ok == 0 && strstr(out, "plan") != NULL,
	      "plan 态拒绝 exec kill（W2 命令）");
	free(out);
	ok = run_tool(&reg, "exec_run",
		      "{\"command\":\"ls\",\"args\":[\"/tmp\"],\"timeout\":10}",
		      &out);
	CHECK(ok == 1 && strstr(out, "ERROR: plan") == NULL,
	      "plan 态放行 exec ls（R 命令，真执行）");
	free(out);
	ok = run_tool(&reg, "exec_run",
		      "{\"command\":\"systemctl\",\"args\":[\"status\"],\"timeout\":10}",
		      &out);
	CHECK(strstr(out, "ERROR: plan") == NULL,
	      "plan 态放行 systemctl status（args0 动词细化 R）");
	free(out);
	ok = run_tool(&reg, "exec_run",
		      "{\"command\":\"systemctl\",\"args\":[\"restart\"],\"timeout\":10}",
		      &out);
	CHECK(ok == 0 && strstr(out, "plan") != NULL,
	      "plan 态拒绝 systemctl restart（args0 动词 W2）");
	free(out);

	/* ---- 5. 退出 plan：不再被 plan 闸门拦 ---- */
	ai_policy_set_plan_mode(0);
	CHECK(ai_policy_get_plan_mode() == 0, "set(0) 后 get 为 0");
	ok = run_tool(&reg, "sandbox_create", "{\"name\":\"w43t\"}", &out);
	CHECK(ok == 1 && strstr(out, "ERROR: plan") == NULL,
	      "退出 plan 后 sandbox_create 不被 plan 闸门拦（mock 成功）");
	free(out);
	ok = run_tool(&reg, "exec_run",
		      "{\"command\":\"mkdir\",\"args\":[\"/tmp/w43t-d\"],\"timeout\":5}",
		      &out);
	CHECK(strstr(out, "ERROR: plan") == NULL,
	      "退出 plan 后 exec mkdir 不被 plan 闸门拦");
	free(out);

	ai_trace_shutdown();
	CHECK(trace_has_plan_deny(tmpdir),
	      "plan 拒绝写 policy_decision（gate=PLAN decision=DENY）");

	tool_registry_free(&reg);
	rmdir(tmpdir);

	printf("\n%s\n", g_fail ? "test_plan_mode: FAIL" :
			  "test_plan_mode: ALL PASS");
	return g_fail ? 1 : 0;
}
