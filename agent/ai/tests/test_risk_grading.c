// SPDX-License-Identifier: GPL-2.0
/*
 * test_risk_grading.c - W48 风险分级回归（F3 + ns-2/ns-6/sy-8）
 *
 * 覆盖：
 *   1. tool_exec_effective_risk：curl 写参数 W2 / 只读 URL R；
 *      ollama pull W2·list R；timedatectl set-time W2·status R；
 *      ip addr add W2·show R；ethtool -s W2·查询 R；
 *      journalctl --vacuum W2·普通查询 R；crontab -l R·-r W2；
 *      systemctl status R·restart W2；mkdir W1；python3 W2。
 *   2. find 受控面拒绝 -delete；crontab 无参数拒绝（防清表）。
 *   3. 沙盒受限表剔除动态风险命令（curl/ip/ethtool/journalctl/
 *      ollama/timedatectl）且 0 W2——防子智能体 W2 逃逸。
 *   4. 新通道名映射 sysctl/sysfs。
 *
 * 只做注册表/闸门级检查，不执行任何真实写命令。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ai_types.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"
#include "policy/ai_user_policy.h"

static int g_fail;

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
} while (0)

static const char *risk_of(struct tool_registry *reg, const char *name,
			   const char *args)
{
	const struct ai_tool *t = tool_registry_find(reg, name);

	if (!t)
		return "NO-TOOL";
	return tool_exec_effective_risk(t, args);
}

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

int main(void)
{
	struct tool_registry reg;
	struct tool_registry sreg;
	char *err = NULL;
	const struct ai_tool *t;
	int i;

	printf("==== test_risk_grading: W48 命令级风险 ====\n");
	/* W2 执行段需要闸门放行；测试只验证拒绝面/风险判定，不执行写
	 * 命令。预授权等价 --yes（与真实无人值守路径同一开关）。 */
	ai_policy_set_assume_yes(1);

	CHECK(tool_channel_from_str("sysctl") == TOOL_CH_SYSCTL,
	      "tool_channel_from_str(\"sysctl\") 映射");
	CHECK(tool_channel_from_str("sysfs") == TOOL_CH_SYSFS_DYN,
	      "tool_channel_from_str(\"sysfs\") 映射");

	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	memset(&reg, 0, sizeof(reg));
	CHECK(tool_registry_load(&reg, &err) == AI_OK,
	      "主注册表加载（tools.json）");
	CHECK(reg.tool_count == 151, "注册表 151 件");

	/* ---- 0. W50 记忆管理面风险分级 ---- */
	CHECK(strcmp(risk_of(&reg, "memory_update", "{}"), "W1") == 0,
	      "memory_update → W1");
	CHECK(strcmp(risk_of(&reg, "memory_delete",
			     "{\"id\":\"m_x\"}"), "W2") == 0,
	      "memory_delete → W2（红色确认）");
	CHECK(strcmp(risk_of(&reg, "memory_import", "{}"), "W1") == 0,
	      "memory_import → W1");
	CHECK(strcmp(risk_of(&reg, "memory_batch_add", "{}"), "W1") == 0,
	      "memory_batch_add → W1");
	CHECK(strcmp(risk_of(&reg, "memory_link", "{}"), "W1") == 0,
	      "memory_link → W1");
	CHECK(strcmp(risk_of(&reg, "memory_regions_evolve", "{}"), "W1") == 0,
	      "memory_regions_evolve → W1");
	CHECK(strcmp(risk_of(&reg, "memory_graph", "{}"), "R") == 0,
	      "memory_graph → R");
	CHECK(strcmp(risk_of(&reg, "memory_config_get", "{}"), "R") == 0,
	      "memory_config_get → R");
	CHECK(strcmp(risk_of(&reg, "memory_config_check", "{}"), "R") == 0,
	      "memory_config_check → R");

	/* ---- 1. 有效风险 ---- */
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"curl\",\"args\":[\"-sS\",\"http://127.0.0.1:8000/health\"]}"),
		"R") == 0, "curl 只读 URL → R");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"curl\",\"args\":[\"-X\",\"POST\",\"http://127.0.0.1:8000/memories\"]}"),
		"W2") == 0, "curl -X POST → W2");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"curl\",\"args\":[\"-o\",\"/tmp/x\",\"http://x\"]}"),
		"W2") == 0, "curl -o 落盘 → W2");

	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"ollama\",\"args\":[\"list\"]}"), "R") == 0,
		"ollama list → R");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"ollama\",\"args\":[\"pull\",\"llama3\"]}"), "W2") == 0,
		"ollama pull → W2");

	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"timedatectl\",\"args\":[\"status\"]}"), "R") == 0,
		"timedatectl status → R");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"timedatectl\",\"args\":[\"set-time\",\"2026-01-01 00:00:00\"]}"),
		"W2") == 0, "timedatectl set-time → W2");

	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"ip\",\"args\":[\"addr\",\"show\"]}"), "R") == 0,
		"ip addr show → R");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"ip\",\"args\":[\"addr\",\"add\",\"10.0.0.1/24\",\"dev\",\"eth0\"]}"),
		"W2") == 0, "ip addr add → W2");

	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"ethtool\",\"args\":[\"eth0\"]}"), "R") == 0,
		"ethtool 查询 → R");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"ethtool\",\"args\":[\"-s\",\"eth0\",\"speed\",\"1000\"]}"),
		"W2") == 0, "ethtool -s → W2");

	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"journalctl\",\"args\":[\"-u\",\"aikernel-api\"]}"),
		"R") == 0, "journalctl 查询 → R");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"journalctl\",\"args\":[\"--vacuum-size=10M\"]}"),
		"W2") == 0, "journalctl --vacuum-size → W2");

	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"crontab\",\"args\":[\"-l\"]}"), "R") == 0,
		"crontab -l → R");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"crontab\",\"args\":[\"-r\"]}"), "W2") == 0,
		"crontab -r → W2");

	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"systemctl\",\"args\":[\"status\",\"sshd\"]}"),
		"R") == 0, "systemctl status → R");
	/* W55 P3：只读 systemctl 子命令必须 R（原白名单缺 list-timers，
	 * 实机被误判 W2 拒执行）；启停/自启仍必须 W2。 */
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"systemctl\",\"args\":[\"list-timers\"]}"),
		"R") == 0, "systemctl list-timers → R");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"systemctl\",\"args\":[\"list-units\"]}"),
		"R") == 0, "systemctl list-units → R");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"systemctl\",\"args\":[\"show\",\"sshd\"]}"),
		"R") == 0, "systemctl show → R");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"systemctl\",\"args\":[\"cat\",\"sshd\"]}"),
		"R") == 0, "systemctl cat → R");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"systemctl\",\"args\":[\"is-enabled\",\"sshd\"]}"),
		"R") == 0, "systemctl is-enabled → R");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"systemctl\",\"args\":[\"is-active\",\"sshd\"]}"),
		"R") == 0, "systemctl is-active → R");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"systemctl\",\"args\":[\"restart\",\"sshd\"]}"),
		"W2") == 0, "systemctl restart → W2");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"systemctl\",\"args\":[\"start\",\"sshd\"]}"),
		"W2") == 0, "systemctl start → W2");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"systemctl\",\"args\":[\"stop\",\"sshd\"]}"),
		"W2") == 0, "systemctl stop → W2");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"systemctl\",\"args\":[\"enable\",\"sshd\"]}"),
		"W2") == 0, "systemctl enable → W2");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"systemctl\",\"args\":[\"disable\",\"sshd\"]}"),
		"W2") == 0, "systemctl disable → W2");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"mkdir\",\"args\":[\"/tmp/w48x\"]}"), "W1") == 0,
		"mkdir → W1");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"python3\",\"args\":[\"/tmp/x.py\"]}"), "W2") == 0,
		"python3 → W2");
	CHECK(strcmp(risk_of(&reg, "exec_run",
		"{\"command\":\"tar\",\"args\":[\"-cf\",\"/tmp/a.tar\",\"/tmp\"]}"),
		"W2") == 0, "tar → W2（W69 升级）");
	CHECK(strcmp(risk_of(&reg, "sys_shell", "{}"), "W2") == 0,
	      "sys_shell → W2（仅 TTY）");

	/* ---- 2. 受控 find / crontab 拒绝 ---- */
	{
		char *out = NULL;
		char tmpdir[] = "/tmp/w48-find-XXXXXX";
		char args[256];
		int ok;

		if (mkdtemp(tmpdir)) {
			char f[300];
			FILE *fp;

			snprintf(f, sizeof(f), "%s/victim", tmpdir);
			fp = fopen(f, "w");
			if (fp) {
				fputs("x", fp);
				fclose(fp);
			}
			snprintf(args, sizeof(args),
				 "{\"command\":\"find\",\"args\":[\"%s\",\"-delete\"]}",
				 tmpdir);
			ok = run_tool(&reg, "exec_run", args, &out);
			CHECK(ok == 0 && strstr(out, "受控 find") != NULL,
			      "find -delete 被拒绝（fs-6 受控面）");
			free(out);
			out = NULL;
			rmdir(tmpdir);
		}
		if (getuid() == 0) {
			ok = run_tool(&reg, "exec_run",
				      "{\"command\":\"crontab\",\"args\":[]}", &out);
			CHECK(ok == 0 && strstr(out, "覆盖当前表") != NULL,
			      "crontab 无参数被拒绝（防 stdin 空内容清表）");
			free(out);
		} else {
			SKIP("crontab W2 拒绝面需要 root（sudo 运行）");
		}
	}

	/* ---- 3. 沙盒受限表：动态风险命令不得入表 ---- */
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools-sandbox.json", 1);
	memset(&sreg, 0, sizeof(sreg));
	CHECK(tool_registry_load(&sreg, &err) == AI_OK,
	      "受限表加载（tools-sandbox.json）");
	t = tool_registry_find(&sreg, "exec_run");
	CHECK(t != NULL, "受限表含 exec_run");
	if (t) {
		static const char *const dyn[] = {
			"curl", "ip", "ethtool", "journalctl", "ollama",
			"timedatectl", NULL,
		};
		int no_dyn = 1;
		int no_w2 = 1;
		int no_tar = 1;
		int w1_hits = 0;
		int j;

		for (i = 0; i < t->exec_cmd_count; i++) {
			if (t->exec_cmds[i].risk &&
			    strcmp(t->exec_cmds[i].risk, "W2") == 0)
				no_w2 = 0;
			if (t->exec_cmds[i].risk &&
			    strcmp(t->exec_cmds[i].risk, "W1") == 0)
				w1_hits++;
			if (strcmp(t->exec_cmds[i].command, "tar") == 0)
				no_tar = 0;
			for (j = 0; dyn[j]; j++) {
				if (strcmp(t->exec_cmds[i].command,
					   dyn[j]) == 0)
					no_dyn = 0;
			}
		}
		CHECK(no_w2, "受限表 0 个 W2 命令");
		CHECK(no_dyn, "受限表剔除动态风险命令（curl/ip/ethtool/"
			      "journalctl/ollama/timedatectl）");
		CHECK(no_tar, "受限表剔除 tar（W69 升 W2）");
		CHECK(t->exec_cmd_count == 57,
		      "受限表白名单 57 命令（W72 新增 python3/gcc/cc）");
		CHECK(w1_hits == 11,
		      "受限表 W1 命令 11 个（8 写 + 编程三件）");
	}

	tool_registry_free(&reg);
	tool_registry_free(&sreg);
	printf("== test_risk_grading: %s ==\n",
	       g_fail ? "FAIL" : "ALL PASS");
	return g_fail ? 1 : 0;
}
