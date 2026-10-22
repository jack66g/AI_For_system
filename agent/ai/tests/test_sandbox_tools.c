// SPDX-License-Identifier: GPL-2.0
/*
 * test_sandbox_tools.c - W42 sandbox 通道回归（进程级 mock，无需 root）
 *
 * 覆盖面：
 *   1. tools.json 四件 sandbox 工具注册（channel=sandbox，risk R/W1/W2/W1）
 *   2. 通道名映射 tool_channel_from_str("sandbox")
 *   3. tools-sandbox.json 受限表：恰 7 件、无任何 W2（工具级与命令级）、
 *      exec 白名单=R46+9W1=55（W65 增 getent/systemd-analyze；绝无
 *      systemctl/kill/apt/嵌套派生工具；python3/gcc/cc 以 W1 受控开放）
 *   4. sandbox_spawn 执行链（mock aik-sandbox + mock ai）：
 *      - 参数组装：-p task -s sb-<name> -N，AIKERNEL_TOOLS_JSON 注入
 *      - 正常完成：stdout 尾部回传
 *      - 超时击杀：短预算 + 长任务 mock → SIGKILL 全组，进程无残留
 *   5. 参数校验：缺 task / 非法 name 拒绝
 *   6. status/create/destroy 透传
 *   7. i18n 文案在表（TR_SB_* 非空）
 *
 * mock 机制：AIKERNEL_SANDBOX_BIN/AIKERNEL_SANDBOX_AI_BIN 指向临时目录
 * 里测试自己写出的 sh 脚本；executor 只认这层契约，不感知真沙盒。
 */
#define _GNU_SOURCE             /* setenv/mkdtemp/clock_gettime（-std=c11） */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>

#include "ai_types.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"
#include "policy/ai_lease.h"
#include "ai_lang.h"

static int g_fail;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		g_fail++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

static void unsetenv_quiet(const char *k)
{
	unsetenv(k);
}

/* /proc 扫描：cmdline 含 marker 的进程是否仍存活 */
static int proc_scan_alive(const char *marker)
{
	DIR *d = opendir("/proc");
	struct dirent *e;
	int alive = 0;

	if (!d)
		return 0;
	while ((e = readdir(d))) {
		char path[320];
		char buf[1024];
		FILE *fp;
		size_t n;

		if (e->d_name[0] < '0' || e->d_name[0] > '9')
			continue;
		snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);
		fp = fopen(path, "rb");
		if (!fp)
			continue;
		n = fread(buf, 1, sizeof(buf) - 1, fp);
		fclose(fp);
		buf[n] = '\0';
		if (n && strstr(buf, marker)) {
			alive = 1;
			break;
		}
	}
	closedir(d);
	return alive;
}

static double now_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void write_file(const char *path, const char *content, int exe)
{
	FILE *fp = fopen(path, "w");

	if (!fp) {
		perror(path);
		exit(2);
	}
	fputs(content, fp);
	fclose(fp);
	if (exe)
		chmod(path, 0755);
}

static char *read_all(const char *path)
{
	FILE *fp = fopen(path, "rb");
	long n;
	char *b;

	if (!fp)
		return NULL;
	if (fseek(fp, 0, SEEK_END) != 0) {
		fclose(fp);
		return NULL;
	}
	n = ftell(fp);
	rewind(fp);
	if (n < 0) {
		fclose(fp);
		return NULL;
	}
	b = malloc((size_t)n + 1);
	if (!b) {
		fclose(fp);
		return NULL;
	}
	if (fread(b, 1, (size_t)n, fp) != (size_t)n) {
		free(b);
		fclose(fp);
		return NULL;
	}
	b[n] = 0;
	fclose(fp);
	return b;
}

static int write_all(const char *path, const char *s)
{
	FILE *fp = fopen(path, "w");

	if (!fp)
		return -1;
	fputs(s, fp);
	fclose(fp);
	return 0;
}

int main(void)
{
	struct tool_registry reg;
	struct tool_registry sreg;
	char *err = NULL;
	const struct ai_tool *t;
	char tmpdir[] = "/tmp/sbtest-XXXXXX";
	char mockbin[256], mockai[256];
	char envline[512];

	setvbuf(stdout, NULL, _IONBF, 0);
	{
		char lerr[AI_LEASE_ERR_MAX] = "";

		/* W74：本测试需要执行 D2 工具，显式使用 ephemeral 预授权 */
		ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));
	}

	/* ================= 1. tools.json 四件注册 ================= */
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	memset(&reg, 0, sizeof(reg));
	CHECK(tool_registry_load(&reg, &err) == AI_OK,
	      "主注册表加载（tools.json）");

	t = tool_registry_find(&reg, "sandbox_status");
	CHECK(t && t->channel == TOOL_CH_SANDBOX &&
	      t->risk && strcmp(t->risk, "R") == 0,
	      "sandbox_status 注册（channel=sandbox risk=R）");
	t = tool_registry_find(&reg, "sandbox_create");
	CHECK(t && t->channel == TOOL_CH_SANDBOX &&
	      t->risk && strcmp(t->risk, "W1") == 0,
	      "sandbox_create 注册（risk=W1）");
	t = tool_registry_find(&reg, "sandbox_spawn");
	CHECK(t && t->channel == TOOL_CH_SANDBOX &&
	      t->risk && strcmp(t->risk, "W2") == 0,
	      "sandbox_spawn 注册（risk=W2）");
	t = tool_registry_find(&reg, "sandbox_destroy");
	CHECK(t && t->channel == TOOL_CH_SANDBOX &&
	      t->risk && strcmp(t->risk, "W1") == 0,
	      "sandbox_destroy 注册（risk=W1）");
	t = tool_registry_find(&reg, "sys_shell");
	CHECK(t && t->channel == TOOL_CH_SHELL &&
	      t->risk && strcmp(t->risk, "W2") == 0,
	      "sys_shell 注册（risk=W2，仅 TTY）");
	CHECK(t && strcmp(tool_exec_effective_risk(t, "{}"), "W2") == 0,
	      "tool_exec_effective_risk(sys_shell) = W2");
	{
		int counts[TOOL_CH_UNKNOWN + 1];
		int i;

		for (i = 0; i <= TOOL_CH_UNKNOWN; i++)
			counts[i] = 0;
		tool_registry_count_by_channel(&reg, counts);
		CHECK(counts[TOOL_CH_SANDBOX] == 4,
		      "sandbox 通道计数 = 4");
	}
	CHECK(tool_channel_from_str("sandbox") == TOOL_CH_SANDBOX,
	      "tool_channel_from_str(\"sandbox\") 映射");

	/* ================= 2. 受限表 tools-sandbox.json ================= */
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools-sandbox.json", 1);
	memset(&sreg, 0, sizeof(sreg));
	CHECK(tool_registry_load(&sreg, &err) == AI_OK,
	      "受限表加载（tools-sandbox.json）");
	CHECK(sreg.tool_count == 7, "受限表恰 7 件工具");
	{
		const char *want[] = {
			"exec_run", "procfs_read_status",
			"procfs_read_control", "netlink_sense",
			"memory_search", "sandbox_status",
			"sandbox_destroy",
		};
		size_t i;
		int no_w2 = 1;
		int all_present = 1;

		for (i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
			if (!tool_registry_find(&sreg, want[i]))
				all_present = 0;
		}
		CHECK(all_present, "受限表 7 件名单齐全");
		CHECK(!tool_registry_find(&sreg, "sandbox_create") &&
		      !tool_registry_find(&sreg, "sandbox_spawn"),
		      "受限表无 sandbox_create/sandbox_spawn（防嵌套派生）");
		for (i = 0; i < (size_t)sreg.tool_count; i++) {
			if (sreg.tools[i].risk &&
			    strcmp(sreg.tools[i].risk, "W2") == 0)
				no_w2 = 0;
		}
		CHECK(no_w2, "受限表工具级 0 个 W2");
		/* exec_run 命令级：无 W2；黑名单命令绝不入表 */
		t = tool_registry_find(&sreg, "exec_run");
		if (t && t->exec_cmds) {
			static const char *const banned[] = {
				"systemctl", "kill", "apt",
				"dpkg", "passwd", "useradd", "usermod",
				"install", "nft", "tc", "aik-backup",
				"ping", "traceroute", "tar",
			};
			size_t i, j;
			int cmd_w2 = 0, banned_hit = 0;
			int w1_hits = 0;

			for (i = 0; i < (size_t)t->exec_cmd_count; i++) {
				if (t->exec_cmds[i].risk &&
				    strcmp(t->exec_cmds[i].risk, "W2") == 0)
					cmd_w2 = 1;
				for (j = 0; j < sizeof(banned) /
				     sizeof(banned[0]); j++) {
					if (strcmp(t->exec_cmds[i].command,
						   banned[j]) == 0)
						banned_hit = 1;
				}
				if (t->exec_cmds[i].risk &&
				    strcmp(t->exec_cmds[i].risk, "W1") == 0)
					w1_hits++;
			}
			CHECK(!cmd_w2, "受限表 exec 命令级 0 个 W2");
			CHECK(!banned_hit, "受限表无黑名单命令");
			CHECK(w1_hits == 11,
			      "受限表 W1 命令恰 11 个（8 写 + python3/gcc/cc）");
			CHECK(t->exec_cmd_count == 57,
			      "受限表 exec 白名单 46R+11W1=57 命令（W72 新增编程三件）");
		} else {
			CHECK(0, "受限表 exec_run 白名单解析");
		}
	}

	/* ========= 2b. W69 P1-2/P2-8：fail-closed 与完整性校验 ========= */
	{
		struct tool_registry bad;
		char *e2 = NULL;
		char badpath[128];
		FILE *fp;

		snprintf(badpath, sizeof(badpath), "/tmp/w69-missing-%ld.json",
			 (long)getpid());
		unlink(badpath);
		setenv("AIKERNEL_TOOLS_JSON", badpath, 1);
		memset(&bad, 0, sizeof(bad));
		CHECK(tool_registry_load(&bad, &e2) != AI_OK &&
		      bad.tool_count == 0,
		      "显式受限表缺失 → fail-closed（绝不回退 130 主表）");
		free(e2);
		tool_registry_free(&bad);

		snprintf(badpath, sizeof(badpath), "/tmp/w69-badcount-%ld.json",
			 (long)getpid());
		fp = fopen(badpath, "w");
		if (fp) {
			fputs("{\"version\":2,\"tool_count\":999,\"tools\":["
			      "{\"name\":\"procfs_read_status\",\"channel\":"
			      "\"procfs-read\",\"risk\":\"R\",\"path\":"
			      "\"/proc/ai/status\"}]}", fp);
			fclose(fp);
		}
		setenv("AIKERNEL_TOOLS_JSON", badpath, 1);
		memset(&bad, 0, sizeof(bad));
		e2 = NULL;
		CHECK(tool_registry_load(&bad, &e2) != AI_OK,
		      "tool_count 与解析数不一致 → 拒绝加载");
		free(e2);
		tool_registry_free(&bad);
		unlink(badpath);

		snprintf(badpath, sizeof(badpath), "/tmp/w69-badfield-%ld.json",
			 (long)getpid());
		fp = fopen(badpath, "w");
		if (fp) {
			fputs("{\"version\":2,\"tool_count\":1,\"tools\":["
			      "{\"name\":\"broken_procfs\",\"channel\":"
			      "\"procfs-read\",\"risk\":\"R\"}]}", fp);
			fclose(fp);
		}
		setenv("AIKERNEL_TOOLS_JSON", badpath, 1);
		memset(&bad, 0, sizeof(bad));
		e2 = NULL;
		CHECK(tool_registry_load(&bad, &e2) != AI_OK,
		      "procfs-read 缺 path → 拒绝加载");
		free(e2);
		tool_registry_free(&bad);
		unlink(badpath);

		/* 工具名清单篡改（长度不变），头部 hash 必须抓住 */
		{
			char *txt = read_all("../tools/tools.json");
			char *pos = txt ? strstr(txt, "\"exec_run\"") : NULL;

			snprintf(badpath, sizeof(badpath),
				 "/tmp/w69-badhash-%ld.json", (long)getpid());
			if (txt && pos) {
				pos[1] = 'E';   /* exec_run → Exec_run */
				write_all(badpath, txt);
				setenv("AIKERNEL_TOOLS_JSON", badpath, 1);
				memset(&bad, 0, sizeof(bad));
				e2 = NULL;
				CHECK(tool_registry_load(&bad, &e2) != AI_OK,
				      "tool_names_sha256 不匹配 → 拒绝加载");
				free(e2);
				tool_registry_free(&bad);
				unlink(badpath);
			} else {
				CHECK(0, "构造 hash 篡改样本失败");
			}
			free(txt);
		}

		/* 沙箱子进程加载主表（含 W2）→ 拒绝启动 */
		setenv("AIKERNEL_SANDBOX", "zoneA", 1);
		setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
		memset(&bad, 0, sizeof(bad));
		e2 = NULL;
		CHECK(tool_registry_load(&bad, &e2) != AI_OK,
		      "AIKERNEL_SANDBOX 下加载 130 主表（含 W2）→ fail-closed");
		free(e2);
		tool_registry_free(&bad);
		unsetenv("AIKERNEL_SANDBOX");
	}

	/* W2 拒绝：沙箱子进程即使拿到 W2 工具句柄也不得执行 */
	{
		char *out = NULL;
		int ok = 1;

		setenv("AIKERNEL_SANDBOX", "zoneA", 1);
		t = tool_registry_find(&reg, "sandbox_spawn");
		CHECK(tool_executor_run(t, "{\"name\":\"x\",\"task\":\"y\"}",
					&out, &ok) == AI_ERR_API && !ok && out &&
		      strstr(out, TOOL_ERR_DENIED_PREFIX) != NULL,
		      "sandbox 子进程拒绝 W2 工具（sandbox_spawn）");
		free(out);
		out = NULL;
		ok = 1;
		t = tool_registry_find(&reg, "sys_shell");
		CHECK(tool_executor_run(t, "{}", &out, &ok) == AI_ERR_API &&
		      !ok && out &&
		      strstr(out, TOOL_ERR_DENIED_PREFIX) != NULL,
		      "sandbox 子进程拒绝 sys_shell（W2）");
		free(out);
		unsetenv("AIKERNEL_SANDBOX");
	}

	unsetenv_quiet("AIKERNEL_TOOLS_JSON");

	/* ================= 3. mock 可执行文件 ================= */
	if (!mkdtemp(tmpdir)) {
		perror("mkdtemp");
		return 2;
	}
	snprintf(mockbin, sizeof(mockbin), "%s/mock-aik-sandbox", tmpdir);
	snprintf(mockai, sizeof(mockai), "%s/mock-ai", tmpdir);
	write_file(mockbin,
		   "#!/bin/sh\n"
		   "if [ \"$1\" = \"status\" ]; then "
		   "echo \"MOCK_STATUS_LINE zones=0\"; exit 0; fi\n"
		   "if [ \"$1\" = \"create\" ]; then "
		   "echo \"MOCK_CREATE_OK $2\"; exit 0; fi\n"
		   "if [ \"$1\" = \"destroy\" ]; then "
		   "echo \"MOCK_DESTROY_OK $2\"; exit 0; fi\n"
		   "if [ \"$1\" = \"run\" ]; then shift; shift; shift; "
		   "exec \"$@\"; fi\n"
		   "echo MOCK_UNKNOWN_ARGS; exit 3\n", 1);
	write_file(mockai,
		   "#!/bin/sh\n"
		   "echo \"SPAWN_OK_ARGS $@\"\n"
		   "echo \"TOOLS_JSON=$AIKERNEL_TOOLS_JSON\"\n"
		   "echo \"SANDBOX=$AIKERNEL_SANDBOX\"\n"
		   "echo \"[ai-status] end_reason=completed rounds=1 final=1 rc=0\"\n"
		   "exit 0\n", 1);
	setenv("AIKERNEL_SANDBOX_BIN", mockbin, 1);
	setenv("AIKERNEL_SANDBOX_AI_BIN", mockai, 1);
	setenv("AIKERNEL_SANDBOX_TOOLS_JSON", "../tools/tools-sandbox.json", 1);
	setenv("AIKERNEL_POLICY", "/dev/null", 1);

	/* 取主注册表里的 spawn 工具句柄（与通道实现解耦的契约面） */
	t = tool_registry_find(&reg, "sandbox_spawn");
	if (!t) {
		printf("FATAL: spawn 工具缺失\n");
		return 2;
	}

	/* ================= 4. spawn 正常完成链 ================= */
	{
		char *out = NULL;
		int ok = 0;

		CHECK(tool_executor_run(t,
					"{\"name\":\"sbt1\","
					"\"task\":\"报告你的根目录\","
					"\"max_seconds\":10}",
					&out, &ok) == AI_OK && ok && out,
		      "sandbox_spawn 执行成功");
		CHECK(out && strstr(out, "SPAWN_OK_ARGS") &&
		      strstr(out, "-p") && strstr(out, "报告你的根目录") &&
		      strstr(out, "sb-sbt1") && strstr(out, "-N"),
		      "spawn 参数链完整（-p task -s sb-<name> -N）");
		CHECK(out && strstr(out,
		      "TOOLS_JSON=../tools/tools-sandbox.json"),
		      "AIKERNEL_TOOLS_JSON 注入受限表路径");
		CHECK(out && (strstr(out, "沙盒任务结束") ||
		      strstr(out, "sandbox task finished")),
		      "完成文案在输出（TR_SB_DONE）");
		/* W65 P2：结果只含工具自身输出与正确格式化的文案——不得
		 * 混入 compact 调试行/字面占位符/上一条工具文案（旧 .o 与新
		 * lang.o 混链的事故形态）。 */
		CHECK(out && strncmp(out, tr(TR_SB_SPAWN_START),
				     strlen(tr(TR_SB_SPAWN_START))) == 0,
		      "spawn 首行 = TR_SB_SPAWN_START（非 create 文案）");
		CHECK(out && strstr(out, "compact:") == NULL,
		      "spawn 结果不含 compact 调试行");
		CHECK(out && strstr(out, "%s") == NULL &&
		      strstr(out, "%d") == NULL,
		      "spawn 结果无字面格式占位符");
		CHECK(out && strstr(out, "sbt1") != NULL &&
		      strstr(out, "dispatcher_exit=0") != NULL,
		      "完成行给出派发进程退出码 dispatcher_exit=0");
		CHECK(out && strstr(out, "task_status=completed") != NULL,
		      "完成行给出子任务状态 task_status=completed");
		CHECK(out && strstr(out, tr(TR_SB_TAIL_HDR)),
		      "尾部标题在输出（TR_SB_TAIL_HDR）");
		CHECK(out && strstr(out, "sandbox_destroy sbt1") != NULL,
		      "spawn 完成追加销毁提醒（B-019，不自动销毁）");
		free(out);
	}

	/* ================= 5. spawn 超时击杀 ================= */
	{
		char mocktmo[256];
		char *out = NULL;
		int ok = 0;
		double t0, t1;
		int timed_out_output;

		snprintf(mocktmo, sizeof(mocktmo), "%s/mock-ai-slow", tmpdir);
		write_file(mocktmo,
			   "#!/bin/sh\n"
			   "echo SLOW_STARTED\n"
			   "exec /bin/sleep 12345\n", 1);
		setenv("AIKERNEL_SANDBOX_AI_BIN", mocktmo, 1);

		t0 = now_sec();
		CHECK(tool_executor_run(t,
					"{\"name\":\"sbt2\","
					"\"task\":\"长任务\","
					"\"max_seconds\":1}",
					&out, &ok) == AI_OK,
		      "超时场景执行返回");
		t1 = now_sec();
		/* 注意：tr(TR_SB_TIMEOUT) 是含 %s/%d 的格式串，不能直接
		 * 做 strstr——用去参数前缀匹配完成文案 */
		timed_out_output = out &&
				   strstr(out, "沙盒任务超时，已 SIGKILL") !=
				   NULL;
		CHECK(timed_out_output,
		      "超时文案在输出（TR_SB_TIMEOUT 前缀）");
		CHECK(out && strstr(out, "%s") == NULL &&
		      strstr(out, "%ds") == NULL,
		      "超时文案无字面占位符");
		CHECK(out && strstr(out, "sbt2") != NULL,
		      "超时文案已代入 sandbox 名");
		CHECK(t1 - t0 < 5.0,
		      "超时击杀在预算附近返回（实测 <5s，预算 1s）");
		CHECK(out && strstr(out, "SLOW_STARTED"),
		      "击杀前已输出的行已进尾部采集");
		CHECK(!proc_scan_alive("/bin/sleep 12345"),
		      "SIGKILL 全组后无残留进程");
		free(out);
		setenv("AIKERNEL_SANDBOX_AI_BIN", mockai, 1);
	}

	/* ================= 6. 参数校验 ================= */
	{
		char *out = NULL;
		int ok = 1;

		CHECK(tool_executor_run(t, "{\"name\":\"sbt3\"}",
					&out, &ok) == AI_OK && !ok,
		      "缺 task → 执行器拒绝（ok=0）");
		free(out);
		out = NULL;
		CHECK(tool_executor_run(t,
					"{\"name\":\"../evil\","
					"\"task\":\"x\"}",
					&out, &ok) == AI_OK && !ok,
		      "路径穿越 name → 执行器拒绝（ok=0）");
		free(out);
		out = NULL;
		CHECK(tool_executor_run(tool_registry_find(&reg,
					"sandbox_create"),
					"{\"name\":\"bad name!\"}",
					&out, &ok) == AI_OK && !ok,
		      "create 非法 name → 执行器拒绝（ok=0）");
		free(out);
	}

	/* ================= 7. status/create/destroy 透传 ================= */
	{
		char *out = NULL;
		int ok = 0;
		const struct ai_tool *ts =
			tool_registry_find(&reg, "sandbox_status");
		const struct ai_tool *tc =
			tool_registry_find(&reg, "sandbox_create");
		const struct ai_tool *td =
			tool_registry_find(&reg, "sandbox_destroy");

		CHECK(tool_executor_run(ts, "{}", &out, &ok) == AI_OK &&
		      out && strstr(out, "MOCK_STATUS_LINE"),
		      "status 透传（channel=sandbox 可达）");
		free(out);
		out = NULL;
		CHECK(tool_executor_run(tc, "{\"name\":\"sbx\"}",
					&out, &ok) == AI_OK &&
		      out && strstr(out, "MOCK_CREATE_OK sbx"),
		      "create 透传");
		CHECK(out && strncmp(out, tr(TR_SB_CREATED),
				     strlen(tr(TR_SB_CREATED))) == 0,
		      "create 首行 = TR_SB_CREATED（无 compact 串线）");
		free(out);
		out = NULL;
		CHECK(tool_executor_run(td, "{\"name\":\"sbx\"}",
					&out, &ok) == AI_OK &&
		      out && strstr(out, "MOCK_DESTROY_OK sbx"),
		      "destroy 透传");
		CHECK(out && strncmp(out, tr(TR_SB_DESTROYED),
				     strlen(tr(TR_SB_DESTROYED))) == 0,
		      "destroy 首行 = TR_SB_DESTROYED（无 compact 串线）");
		CHECK(out && strstr(out, "compact:") == NULL &&
		      strstr(out, "%s") == NULL && strstr(out, "%d") == NULL,
		      "destroy 结果无调试行/占位符");
		free(out);
	}

	/* ========= 7b. W69 P1-2：sandbox_destroy 禁止跨区 ========= */
	{
		char *out = NULL;
		int ok = 1;
		const struct ai_tool *td =
			tool_registry_find(&reg, "sandbox_destroy");

		setenv("AIKERNEL_SANDBOX", "zoneA", 1);
		CHECK(tool_executor_run(td, "{\"name\":\"zoneB\"}",
					&out, &ok) == AI_OK && !ok && out &&
		      strstr(out, TOOL_ERR_DENIED_PREFIX) != NULL &&
		      strstr(out, "MOCK_DESTROY_OK") == NULL,
		      "跨区 sandbox_destroy → 拒绝且未执行");
		free(out);
		out = NULL;
		ok = 1;
		CHECK(tool_executor_run(td, "{\"name\":\"zoneA\"}",
					&out, &ok) == AI_OK && ok && out &&
		      strstr(out, "MOCK_DESTROY_OK zoneA") != NULL,
		      "销毁自身隔离区 → 放行");
		free(out);
		unsetenv("AIKERNEL_SANDBOX");
	}

	/* ================= 8. i18n 文案在表 ================= */
	CHECK(tr(TR_SB_CREATED)[0] && tr(TR_SB_SPAWN_START)[0] &&
	      tr(TR_SB_DONE)[0] && tr(TR_SB_TIMEOUT)[0] &&
	      tr(TR_SB_DESTROYED)[0] && tr(TR_SB_TAIL_HDR)[0] &&
	      tr(TR_SB_DESTROY_REMIND)[0],
	      "TR_SB_* 七条文案非空（zh 缺省）");
	/* W65：枚举/表一致性锚点——这些键必须映射到互不相同的文案。
	 * 旧 .o 与新 lang.o 混链时 TR_SB_CREATED 会等于 TR_CMP_TRUNC，
	 * 本断言在正确构建下恒过，混链产物会直接失败。 */
	CHECK(strcmp(tr(TR_SB_CREATED), tr(TR_CMP_TRUNC)) != 0 &&
	      strcmp(tr(TR_SB_SPAWN_START), tr(TR_CMP_GUARD)) != 0 &&
	      strcmp(tr(TR_SB_DONE), tr(TR_SB_CREATED)) != 0,
	      "TR_SB_* 与 TR_CMP_* 映射不串线（i18n 枚举一致性）");

	/* ---- 收尾 ---- */
	tool_registry_free(&reg);
	tool_registry_free(&sreg);
	snprintf(envline, sizeof(envline), "rm -rf %s", tmpdir);
	if (system(envline) != 0)
		printf("warn: 清理临时目录失败 %s\n", tmpdir);
	unsetenv_quiet("AIKERNEL_SANDBOX_BIN");
	unsetenv_quiet("AIKERNEL_SANDBOX_AI_BIN");
	unsetenv_quiet("AIKERNEL_SANDBOX_TOOLS_JSON");

	if (g_fail) {
		printf("test_sandbox_tools: FAIL (%d)\n", g_fail);
		return 1;
	}
	printf("test_sandbox_tools: ALL PASS\n");
	return 0;
}
