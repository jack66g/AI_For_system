/* SPDX-License-Identifier: GPL-2.0 */
/* test_macros - W78 宏工具单测：纯函数校验 + R 件在 L1 真跑 + W 件参数拒绝路径 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/tool_registry.h"
#include "tools/macro_tools.h"

static int fails = 0;

#define CHECK(cond, name) do { \
	if (cond) { printf("ok %s\n", name); } \
	else { printf("FAIL %s\n", name); fails++; } \
} while (0)

/* 桩：macro_tools 引用的 executor 实现（本测不触达写路径） */
int exec_netlink_act(const struct ai_tool *tool, const char *args_json,
		     char **out)
{
	(void)tool; (void)args_json;
	*out = strdup("STUB-NETLINK");
	return 0;
}

int exec_sysctl_write(const struct ai_tool *tool, const char *args_json,
		      char **out)
{
	(void)tool; (void)args_json;
	*out = strdup("STUB-SYSCTL");
	return 0;
}

int exec_sysfs_dyn(const struct ai_tool *tool, const char *args_json,
		   char **out)
{
	(void)tool; (void)args_json;
	*out = strdup("STUB-SYSFS");
	return 0;
}

static void test_validators(void)
{
	CHECK(ai_macro_valid_unit("sshd.service") == 1, "unit-ok");
	CHECK(ai_macro_valid_unit("a/b") == 0, "unit-slash-rej");
	CHECK(ai_macro_valid_unit("") == 0, "unit-empty-rej");
	CHECK(ai_macro_valid_unit("x;rm -rf /") == 0, "unit-inject-rej");
	CHECK(ai_macro_valid_ip("192.168.1.10") == 1, "ip4-ok");
	CHECK(ai_macro_valid_ip("fd00::1") == 1, "ip6-ok");
	CHECK(ai_macro_valid_ip("1.2.3") == 0, "ip-short-rej");
	CHECK(ai_macro_valid_ip("a;drop") == 0, "ip-inject-rej");
	CHECK(ai_macro_valid_cal("hourly") == 1, "cal-ok");
	CHECK(ai_macro_valid_cal("Mon *-*-* 03:00:00") == 1, "cal2-ok");
	CHECK(ai_macro_valid_cal("x; reboot") == 0, "cal-inject-rej");
}

static void test_dispatch(void)
{
	struct ai_tool t;
	char *out = NULL;
	int rc;

	memset(&t, 0, sizeof(t));
	t.channel = TOOL_CH_MACRO;
	t.risk = "R";

	t.name = "psi_snapshot";
	rc = exec_macro_channel(&t, "{}", &out);
	CHECK(rc == 0 && out && out[0] == '{' &&
	      (strstr(out, "cpu") || strstr(out, "unavailable")),
	      "psi-snapshot-json");
	free(out); out = NULL;

	t.name = "kernel_ai_healthcheck";
	rc = exec_macro_channel(&t, "{}", &out);
	CHECK(rc == 0 && out && out[0] == '{' &&
	      (strstr(out, "status") || strstr(out, "unavailable")),
	      "kai-healthcheck-json");
	free(out); out = NULL;

	t.name = "disk_hogs";
	rc = exec_macro_channel(&t, "{}", &out);
	CHECK(rc == 0 && out && out[0] == '{' && strstr(out, "mounts"),
	      "disk-hogs-json");
	free(out); out = NULL;

	t.name = "sysctl_snapshot";
	rc = exec_macro_channel(&t, "{\"prefix\":\"vm\"}", &out);
	CHECK(rc == 0 && out && strstr(out, "= ") == NULL &&
	      strstr(out, "=") != NULL, "sysctl-snapshot-vm");
	free(out); out = NULL;

	t.name = "baseline_diff";
	rc = exec_macro_channel(&t,
				"{\"baseline\":\"vm.swappiness=60\"}", &out);
	CHECK(rc == 0 && out && strstr(out, "summary"), "baseline-diff-summary");
	free(out); out = NULL;

	/* W 件参数拒绝路径（不落 executor） */
	t.name = "ip_ban_verified";
	rc = exec_macro_channel(&t, "{\"ip\":\"bad;ip\"}", &out);
	CHECK(rc != 0 && out && strstr(out, "ERROR"), "ip-ban-bad-reject");
	free(out); out = NULL;

	t.name = "process_quarantine";
	rc = exec_macro_channel(&t, "{\"pid\":1}", &out);
	CHECK(rc != 0 && out && strstr(out, "ERROR"), "quarantine-pid1-reject");
	free(out); out = NULL;

	t.name = "schedule_create";
	rc = exec_macro_channel(&t, "{\"name\":\"x;y\",\"calendar\":\"h\","
				"\"command\":\"ls\"}", &out);
	CHECK(rc != 0 && out && strstr(out, "ERROR"), "sched-badname-reject");
	free(out); out = NULL;
}

int main(void)
{
	test_validators();
	test_dispatch();
	if (fails) {
		printf("test_macros: %d FAIL\n", fails);
		return 1;
	}
	printf("test_macros: all pass\n");
	return 0;
}
