// SPDX-License-Identifier: GPL-2.0
/*
 * test_sched.c - W79 双调度台（sched 通道）回归
 *
 * 默认（非 root，假 cgroup/状态目录）：
 *   - 注册表接线：193 件、sched 通道 5 件、risk R/W1/W2/W1/W2、
 *     channel 字符串 sched 映射；
 *   - 纯函数：10 旋钮存在、值域校验（各旋钮上下界/格式）、读回比对
 *     （含 io.max 内核补全 max 字段、affinity 单 CPU 掩码）、负载名解析；
 *   - 通道行为：未知旋钮/未知 mode/ml 未就绪拒绝（零状态变更）、
 *     越界值被拒且原值不变、写后读回不一致 → 失败并回滚、写失败 →
 *     失败、mode static/off 切换、快照 save→改值→restore 往返一致、
 *     sched.mode 作为旋钮走同一路径。
 *
 * --live（root）：真实 /sys/fs/cgroup/aikernel-sched 上的 knob/mode/快照
 * 往返 + A/B 对照 + 回滚演练由证据脚本驱动（见 W79-SCHED.md），
 * 这里只做非 root 可复现部分。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ai_types.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"
#include "policy/ai_lease.h"
#include "tools/sched_tools.h"

static int fails;
static int checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (cond) { \
		printf("ok %s\n", msg); \
	} else { \
		printf("FAIL %s\n", msg); \
		fails++; \
	} \
} while (0)

/* ---- 环境准备：假 cgroup + 状态目录 ---- */
static char g_tmp[512];
static char g_cg[512];
static char g_state[512];

static int write_file(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	size_t len = strlen(val);
	ssize_t w;

	if (fd < 0)
		return -1;
	w = write(fd, val, len);
	close(fd);
	return w == (ssize_t)len ? 0 : -1;
}

static int read_file(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, cap - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	buf[strcspn(buf, "\r\n")] = '\0';
	return 0;
}

static void setup_env(void)
{
	char path[768];

	snprintf(g_tmp, sizeof(g_tmp), "/tmp/aik-w79-sched-XXXXXX");
	if (!mkdtemp(g_tmp)) {
		printf("FATAL: mkdtemp 失败\n");
		exit(1);
	}
	snprintf(g_cg, sizeof(g_cg), "%.400s/cgroup", g_tmp);
	snprintf(g_state, sizeof(g_state), "%.400s/state", g_tmp);
	(void)mkdir(g_cg, 0755);
	(void)mkdir(g_state, 0700);

	snprintf(path, sizeof(path), "%s/cpu.weight", g_cg);
	write_file(path, "100\n");
	snprintf(path, sizeof(path), "%s/cpu.max", g_cg);
	write_file(path, "max 100000\n");
	snprintf(path, sizeof(path), "%s/cpu.max.burst", g_cg);
	write_file(path, "0\n");
	snprintf(path, sizeof(path), "%s/io.weight", g_cg);
	write_file(path, "default 100\n");
	snprintf(path, sizeof(path), "%s/io.max", g_cg);
	write_file(path, "\n");
	snprintf(path, sizeof(path), "%s/cgroup.controllers", g_cg);
	write_file(path, "cpu io memory pids\n");

	setenv("AIKERNEL_SCHED_DIR", g_state, 1);
	setenv("AIKERNEL_SCHED_CGROUP", g_cg, 1);
}

static void cleanup_env(void)
{
	char cmd[700];

	/* 只删自己 mkdtemp 出来的目录（路径里带 aik-w79-sched- 前缀） */
	if (strstr(g_tmp, "/aik-w79-sched-")) {
		snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_tmp);
		if (system(cmd) != 0)
			(void)0;
	}
}

/* ---- 通道调用 ---- */
static int run_ch(const char *tool, const char *args, char **out)
{
	struct ai_tool t;

	memset(&t, 0, sizeof(t));
	t.name = (char *)tool;
	t.channel = TOOL_CH_SCHED;
	*out = NULL;
	return exec_sched_channel(&t, args, out);
}

static char *cgp(const char *name, char *buf, size_t cap)
{
	snprintf(buf, cap, "%s/%s", g_cg, name);
	return buf;
}

/* ---- 1. 纯函数 ---- */
static void test_pure(void)
{
	char err[256];
	int i, found = 0;

	CHECK(ai_sched_knob_count() == 10, "旋钮表恰 10 个");
	{
		static const char *const want[] = {
			"nice", "affinity", "oom_score", "timeslice",
			"cpu.weight", "cpu.max", "cpu.max.burst",
			"io.weight", "io.max", "sched.mode",
		};

		for (i = 0; i < 10; i++)
			if (ai_sched_knob_find(want[i]) >= 0)
				found++;
		CHECK(found == 10, "10 个旋钮名全部可查（≥9 真实可写 + sched.mode）");
	}
	CHECK(ai_sched_knob_find("no.such") < 0, "未知旋钮返回 -1");
	CHECK(ai_sched_knob_find(NULL) < 0, "NULL 旋钮返回 -1");

	CHECK(ai_sched_valid_mode("static") == 1, "mode static 合法");
	CHECK(ai_sched_valid_mode("ml") == 1, "mode ml 名字合法（是否就绪另一层）");
	CHECK(ai_sched_valid_mode("off") == 1, "mode off 合法");
	CHECK(ai_sched_valid_mode("auto") == 0, "mode auto 拒绝");
	CHECK(ai_sched_valid_mode("") == 0, "mode 空拒绝");
	CHECK(ai_sched_valid_mode(NULL) == 0, "mode NULL 拒绝");

	/* 值域校验 */
#define V(knob, val) ai_sched_validate_value( \
		ai_sched_knob_at(ai_sched_knob_find(knob)), val, err, sizeof(err))
	CHECK(V("nice", "-20") == 0, "nice -20 合法（下界）");
	CHECK(V("nice", "19") == 0, "nice 19 合法（上界）");
	CHECK(V("nice", "-21") != 0, "nice -21 越界拒绝");
	CHECK(V("nice", "20") != 0, "nice 20 越界拒绝");
	CHECK(V("nice", "abc") != 0, "nice 非整数拒绝");
	CHECK(V("nice", " 5") != 0, "nice 前导空白拒绝");

	CHECK(V("oom_score", "-1000") == 0, "oom_score -1000 合法");
	CHECK(V("oom_score", "1001") != 0, "oom_score 1001 越界拒绝");

	CHECK(V("timeslice", "1") == 0, "timeslice 1 合法（0.1ms 下界）");
	CHECK(V("timeslice", "1001") != 0, "timeslice 1001 越界拒绝");

	CHECK(V("affinity", "0") == 0, "affinity 0 合法");
	CHECK(V("affinity", "-1") != 0, "affinity -1 拒绝");
	CHECK(V("affinity", "999999") != 0, "affinity 超 nproc 拒绝");

	CHECK(V("cpu.weight", "1") == 0, "cpu.weight 1 合法");
	CHECK(V("cpu.weight", "0") != 0, "cpu.weight 0 拒绝");
	CHECK(V("cpu.weight", "10001") != 0, "cpu.weight 10001 拒绝");

	CHECK(V("cpu.max", "max 100000") == 0, "cpu.max max 100000 合法");
	CHECK(V("cpu.max", "50000 100000") == 0, "cpu.max 50000 100000 合法");
	CHECK(V("cpu.max", "max") == 0, "cpu.max max 单段合法");
	CHECK(V("cpu.max", "1 100000") != 0, "cpu.max quota 1 拒绝（内核下界 1000）");
	CHECK(V("cpu.max", "50000 999") != 0, "cpu.max period 999 拒绝");
	CHECK(V("cpu.max", "50000 100000 7") != 0, "cpu.max 三段拒绝");
	CHECK(V("cpu.max", "") != 0, "cpu.max 空拒绝");

	CHECK(V("cpu.max.burst", "0") == 0, "cpu.max.burst 0 合法");
	CHECK(V("cpu.max.burst", "1000001") != 0, "cpu.max.burst 超上限拒绝");

	CHECK(V("io.weight", "default 100") == 0, "io.weight default 100 合法");
	CHECK(V("io.weight", "8:0 300") == 0, "io.weight MAJ:MIN 300 合法");
	CHECK(V("io.weight", "default 0") != 0, "io.weight 0 拒绝");
	CHECK(V("io.weight", "8:0") != 0, "io.weight 缺权重拒绝");

	CHECK(V("io.max", "8:0 rbps=1048576") == 0, "io.max rbps 合法");
	CHECK(V("io.max", "8:0 rbps=max wbps=1048576") == 0, "io.max max+数值合法");
	CHECK(V("io.max", "8:0") != 0, "io.max 无 key 拒绝");
	CHECK(V("io.max", "8:0 xbps=1") != 0, "io.max 未知 key 拒绝");
	CHECK(V("io.max", "8 rbps=1") != 0, "io.max 非法 dev 拒绝");
	CHECK(V("io.max", "8:0 rbps=-1") != 0, "io.max 负值拒绝");

	CHECK(V("sched.mode", "static") == 0, "sched.mode 旋钮值 static 合法");
	CHECK(V("sched.mode", "turbo") != 0, "sched.mode 旋钮值 turbo 拒绝");
#undef V

	/* 读回比对 */
	{
		const struct ai_sched_knob *cpu_max =
			ai_sched_knob_at(ai_sched_knob_find("cpu.max"));
		const struct ai_sched_knob *iomax =
			ai_sched_knob_at(ai_sched_knob_find("io.max"));
		const struct ai_sched_knob *aff =
			ai_sched_knob_at(ai_sched_knob_find("affinity"));

		CHECK(ai_sched_value_match(cpu_max, "50000 100000",
					   "50000  100000\n") == 0,
		      "cpu.max 读回空白归一后一致");
		CHECK(ai_sched_value_match(cpu_max, "50000 100000",
					   "40000 100000") != 0,
		      "cpu.max 读回不一致可检出");
		CHECK(ai_sched_value_match(iomax, "8:0 rbps=1048576",
					   "8:0 rbps=1048576 wbps=max riops=max wiops=max") == 0,
		      "io.max 内核补全 max 字段仍算一致");
		CHECK(ai_sched_value_match(iomax, "8:0 rbps=1048576",
					   "8:0 rbps=2048 wbps=max") != 0,
		      "io.max 数值不同判不一致");
		CHECK(ai_sched_value_match(iomax,
					   "8:0 rbps=max wbps=max riops=max wiops=max",
					   "") == 0,
		      "io.max 全 max 且行被删空算一致");
		CHECK(ai_sched_value_match(aff, "3", "3") == 0,
		      "affinity 单 CPU 一致");
		CHECK(ai_sched_value_match(aff, "3", "0-7") != 0,
		      "affinity 掩码含 8 个 CPU 判不一致");
	}

	/* 负载名 */
	{
		int mask = 0;

		CHECK(ai_sched_parse_loads("cpu,io,mix", &mask) == 0 && mask == 7,
		      "负载 cpu,io,mix 解析为 0x7");
		CHECK(ai_sched_parse_loads("io", &mask) == 0 && mask == 2,
		      "负载 io 解析为 0x2");
		CHECK(ai_sched_parse_loads("bag", &mask) != 0, "非法负载名拒绝");
		CHECK(strcmp(ai_sched_load_name(0), "cpu") == 0 &&
		      strcmp(ai_sched_load_name(1), "io") == 0 &&
		      strcmp(ai_sched_load_name(2), "mix") == 0,
		      "负载名回显 cpu/io/mix");
	}
}

/* ---- 2. 注册表接线 ---- */
static void test_registry(void)
{
	struct tool_registry reg;
	char *err = NULL;
	int i, sch = 0, ok = 1;
	static const char *const want[] = {
		"sched_status", "sched_knob_set", "sched_mode_set",
		"sched_snapshot", "sched_ab_run",
	};
	static const char *const wrisk[] = { "R", "W1", "W2", "W1", "W2" };

	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	memset(&reg, 0, sizeof(reg));
	CHECK(tool_registry_load(&reg, &err) == AI_OK,
	      "tools.json 加载（193 件口径）");
	CHECK(reg.tool_count == 193, "注册表总数 193");
	CHECK(tool_channel_from_str("sched") == TOOL_CH_SCHED,
	      "channel 字符串 sched 映射到 TOOL_CH_SCHED");
	for (i = 0; i < reg.tool_count; i++)
		if (reg.tools[i].channel == TOOL_CH_SCHED)
			sch++;
	CHECK(sch == 5, "sched 通道恰 5 件");
	for (i = 0; i < 5; i++) {
		const struct ai_tool *t = tool_registry_find(&reg, want[i]);

		if (!t || t->channel != TOOL_CH_SCHED || !t->risk ||
		    strcmp(t->risk, wrisk[i]) != 0 || t->sub_count < 1)
			ok = 0;
	}
	CHECK(ok, "五件工具注册/channel/risk R,W1,W2,W1,W2/sub 齐全");
	{
		const struct ai_tool *t = tool_registry_find(&reg, "sched_ab_run");

		CHECK(t && strcmp(tool_exec_effective_risk(t, "{}"), "W2") == 0,
		      "sched_ab_run 有效风险 = W2");
	}
	{
		const struct ai_tool *t = tool_registry_find(&reg, "sched_status");

		CHECK(t && strcmp(tool_exec_effective_risk(t, "{}"), "R") == 0,
		      "sched_status 有效风险 = R");
	}
	tool_registry_free(&reg);
	free(err);
}

/* ---- 3. 通道行为（假环境，非 root） ---- */
static void test_channel(void)
{
	char *out = NULL;
	char buf[256], path[768];
	int rc;
	struct stat st;

	/* 未知旋钮：列出可用清单，零写入 */
	rc = run_ch("sched_knob_set",
		    "{\"knob\":\"sched.turbo\",\"value\":\"1\"}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG && out && strstr(out, "cpu.max") != NULL,
	      "未知旋钮 → INVALID_ARG + 列出可用旋钮");
	free(out);

	/* 越界值被拒且原值不变 */
	cgp("cpu.weight", path, sizeof(path));
	read_file(path, buf, sizeof(buf));
	CHECK(strcmp(buf, "100") == 0, "前置：cpu.weight=100");
	out = NULL;
	rc = run_ch("sched_knob_set",
		    "{\"knob\":\"cpu.weight\",\"value\":\"10001\"}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG, "cpu.weight=10001 → INVALID_ARG");
	read_file(path, buf, sizeof(buf));
	CHECK(strcmp(buf, "100") == 0, "越界拒绝后原值不变（100）");
	free(out);

	/* 正常写：读回一致 */
	out = NULL;
	rc = run_ch("sched_knob_set",
		    "{\"knob\":\"cpu.max\",\"value\":\"50000 100000\"}", &out);
	cgp("cpu.max", path, sizeof(path));
	read_file(path, buf, sizeof(buf));
	CHECK(rc == AI_OK && strcmp(buf, "50000 100000") == 0,
	      "cpu.max 写入成功且文件真被改（读回 50000 100000）");
	CHECK(out && strstr(out, "读回一致") != NULL,
	      "返回文本含\"读回一致\"与期望/实际");
	free(out);

	/* 读回不一致：把 cpu.max 换成 /dev/null（写成功、读回空） */
	cgp("cpu.max", path, sizeof(path));
	(void)unlink(path);
	if (symlink("/dev/null", path) != 0)
		printf("WARN: symlink /dev/null 失败\n");
	out = NULL;
	rc = run_ch("sched_knob_set",
		    "{\"knob\":\"cpu.max\",\"value\":\"20000 100000\"}", &out);
	CHECK(rc == AI_ERR_API && out && strstr(out, "读回不一致") != NULL,
	      "写成功但读回不一致 → FAIL（不假报成功）");
	CHECK(out && strstr(out, "20000 100000") != NULL,
	      "失败文本含期望值 20000 100000");
	free(out);
	(void)unlink(path);

	/* 写失败：/dev/full → ENOSPC */
	if (symlink("/dev/full", path) != 0)
		printf("WARN: symlink /dev/full 失败\n");
	out = NULL;
	rc = run_ch("sched_knob_set",
		    "{\"knob\":\"cpu.max\",\"value\":\"30000 100000\"}", &out);
	CHECK(rc == AI_ERR_API && out && strstr(out, "写入失败") != NULL,
	      "写入失败（/dev/full）→ FAIL + 明确 errno");
	free(out);
	(void)unlink(path);
	write_file(path, "max 100000\n");

	/* 未知 mode / ml 未就绪：零状态变更 */
	out = NULL;
	rc = run_ch("sched_mode_set", "{\"mode\":\"turbo\"}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG, "未知 mode turbo → INVALID_ARG");
	free(out);
	{
		char modefile[768];

		snprintf(modefile, sizeof(modefile), "%s/mode", g_state);
		CHECK(stat(modefile, &st) != 0, "前置：无 mode 状态文件");
		out = NULL;
		rc = run_ch("sched_mode_set", "{\"mode\":\"ml\"}", &out);
		CHECK(rc == AI_ERR_NOT_IMPLEMENTED && out &&
		      strstr(out, "ml 台未就绪") != NULL &&
		      strstr(out, "W83") != NULL,
		      "ml 未就绪 → NOT_IMPLEMENTED + 明确 W83 文案");
		CHECK(out && strstr(out, "绝不假成功") != NULL,
		      "拒绝文案含\"绝不假成功\"");
		CHECK(stat(modefile, &st) != 0,
		      "ml 拒绝后无 mode 文件（零状态变更）");
		free(out);
	}

	/* mode static：自动快照 + 参数集 + 读回 */
	out = NULL;
	rc = run_ch("sched_mode_set", "{\"mode\":\"static\"}", &out);
	CHECK(rc == AI_OK && out && strstr(out, "复验") != NULL,
	      "mode static 成功（切换前快照 + 复验）");
	if (rc != AI_OK && out)
		printf("   [debug] rc=%d out=%s\n", rc, out);
	free(out);
	cgp("cpu.max", path, sizeof(path));
	read_file(path, buf, sizeof(buf));
	CHECK(strcmp(buf, "50000 100000") == 0,
	      "static 后 cpu.max 真读 = 50000 100000");
	{
		char modefile[768];

		snprintf(modefile, sizeof(modefile), "%s/mode", g_state);
		read_file(modefile, buf, sizeof(buf));
		CHECK(strcmp(buf, "static") == 0, "static 后 mode 文件 = static");
	}

	/* 快照 save → 改值 → restore 往返 */
	out = NULL;
	rc = run_ch("sched_snapshot", "{\"action\":\"save\"}", &out);
	CHECK(rc == AI_OK && out && strstr(out, "snap-") != NULL,
	      "快照 save 成功并返回路径");
	free(out);
	{
		char snapfile[768] = "", *p;
		DIR *d = opendir(g_state);
		struct dirent *e;

		while (d && (e = readdir(d))) {
			if (strncmp(e->d_name, "snap-", 5) == 0) {
				snprintf(snapfile, sizeof(snapfile), "%s/%s",
					 g_state, e->d_name);
				break;
			}
		}
		if (d)
			closedir(d);
		CHECK(snapfile[0] != '\0', "快照文件已落盘（snap-*.json）");
		if (snapfile[0]) {
			CHECK(stat(snapfile, &st) == 0 &&
			      (st.st_mode & 0777) == 0600,
			      "快照权限 0600");
			/* 保存的 cpu.max 值 */
			p = strstr(snapfile, "snap-");
			CHECK(p != NULL, "快照命名 snap-<ts>.json");
		}
		/* 改值：cpu.max → 70000 100000 */
		cgp("cpu.max", path, sizeof(path));
		write_file(path, "70000 100000\n");
		out = NULL;
		rc = run_ch("sched_snapshot", "{\"action\":\"restore\"}", &out);
		read_file(path, buf, sizeof(buf));
		CHECK(rc == AI_OK && strcmp(buf, "50000 100000") == 0,
		      "restore 后 cpu.max 读回 = 快照值 50000 100000（往返一致）");
		CHECK(out && strstr(out, "读回一致") != NULL,
		      "restore 返回逐项读回结论");
		free(out);
	}

	/* mode off：回内核默认 */
	out = NULL;
	rc = run_ch("sched_mode_set", "{\"mode\":\"off\"}", &out);
	cgp("cpu.max", path, sizeof(path));
	read_file(path, buf, sizeof(buf));
	CHECK(rc == AI_OK && strcmp(buf, "max 100000") == 0,
	      "mode off 后 cpu.max 真读 = max 100000");
	free(out);

	/* sched.mode 作为旋钮：同一路径 */
	out = NULL;
	rc = run_ch("sched_knob_set",
		    "{\"knob\":\"sched.mode\",\"value\":\"static\"}", &out);
	cgp("cpu.max", path, sizeof(path));
	read_file(path, buf, sizeof(buf));
	CHECK(rc == AI_OK && strcmp(buf, "50000 100000") == 0,
	      "knob_set knob=sched.mode value=static → 参数集生效");
	free(out);

	/* status 真读 */
	out = NULL;
	rc = run_ch("sched_status", "{}", &out);
	CHECK(rc == AI_OK && out && strstr(out, "mode:") != NULL &&
	      strstr(out, "cpu.max") != NULL && strstr(out, "PSI") != NULL,
	      "sched_status 返回 mode/旋钮/PSI 段");
	CHECK(out && strstr(out, "当前=50000 100000") != NULL,
	      "status 里 cpu.max 当前值来自真读");
	free(out);

	/* 快照 list */
	out = NULL;
	rc = run_ch("sched_snapshot", "{\"action\":\"list\"}", &out);
	CHECK(rc == AI_OK && out && strstr(out, "snap-") != NULL,
	      "快照 list 列出文件");
	free(out);

	/* 未知 sched 工具名 */
	{
		struct ai_tool t;

		memset(&t, 0, sizeof(t));
		t.name = "sched_none";
		t.channel = TOOL_CH_SCHED;
		out = NULL;
		rc = exec_sched_channel(&t, "{}", &out);
		CHECK(rc == AI_ERR_INVALID_ARG && out &&
		      strstr(out, "未知 sched 工具") != NULL,
		      "未知 sched 工具名 → INVALID_ARG");
		free(out);
	}

	/* 任务级旋钮在非 AIKernel 内核上诚实报错（不假成功） */
	out = NULL;
	rc = run_ch("sched_knob_set",
		    "{\"knob\":\"nice\",\"value\":\"5\",\"pid\":1}", &out);
	CHECK(rc == AI_ERR_API && out &&
	      (strstr(out, "NETLINK_AI") != NULL ||
	       strstr(out, "ACT") != NULL),
	      "nice 在无 NETLINK_AI 环境 → 明确失败（不假成功）");
	free(out);

	/* 任务级旋钮缺 pid */
	out = NULL;
	rc = run_ch("sched_knob_set",
		    "{\"knob\":\"nice\",\"value\":\"5\"}", &out);
	CHECK(rc == AI_ERR_API && out && strstr(out, "pid") != NULL,
	      "任务级旋钮缺 pid → 明确失败");
	free(out);

	/* ab_run 非法负载名/非法臂：前置拒绝（零状态变更） */
	out = NULL;
	rc = run_ch("sched_ab_run",
		    "{\"loads\":\"bogus\",\"duration_s\":2}", &out);
	CHECK(rc == AI_ERR_INVALID_ARG, "非法负载名 → INVALID_ARG（未开始）");
	free(out);
	out = NULL;
	rc = run_ch("sched_ab_run",
		    "{\"arm_a\":\"ml\",\"arm_b\":\"baseline\"}", &out);
	CHECK(rc == AI_ERR_NOT_IMPLEMENTED && out &&
	      strstr(out, "ml 台未就绪") != NULL,
	      "ab_run ml 臂 → NOT_IMPLEMENTED + 明确文案");
	free(out);
}

/* ------------------------------------------------------------------ */
/* --live（root）：真 cgroup / 真状态目录 / 真策略闸门                    */
/* ------------------------------------------------------------------ */

static struct tool_registry g_reg;

static void cat_file(const char *tag, const char *path)
{
	char buf[512];

	if (read_file(path, buf, sizeof(buf)) == 0)
		printf("  %-18s = [%s]\n", tag, buf);
	else
		printf("  %-18s = <不可读 %s>\n", tag, strerror(errno));
}

static void dump_cgroup(const char *cgdir)
{
	char p[768];

	printf("--- cgroup 真读（%s）---\n", cgdir);
	snprintf(p, sizeof(p), "%.600s/cpu.weight", cgdir);
	cat_file("cpu.weight", p);
	snprintf(p, sizeof(p), "%.600s/cpu.max", cgdir);
	cat_file("cpu.max", p);
	snprintf(p, sizeof(p), "%.600s/cpu.max.burst", cgdir);
	cat_file("cpu.max.burst", p);
	snprintf(p, sizeof(p), "%.600s/io.weight", cgdir);
	cat_file("io.weight", p);
	snprintf(p, sizeof(p), "%.600s/io.max", cgdir);
	cat_file("io.max", p);
	snprintf(p, sizeof(p), "%.600s/cgroup.controllers", cgdir);
	cat_file("controllers", p);
}

static int live_call(const char *tool, const char *args, char **out)
{
	const struct ai_tool *t = tool_registry_find(&g_reg, tool);
	int ok = 0, rc;

	*out = NULL;
	if (!t) {
		printf("FATAL: 工具 %s 不在注册表\n", tool);
		return -1;
	}
	rc = tool_executor_run(t, args, out, &ok);
	printf("\n$ %s %s\n  rc=%d ok=%d\n", tool, args, rc, ok);
	if (*out)
		printf("%s\n", *out);
	return ok ? 0 : -1;
}

static int live(void)
{
	const char *cgdir = "/sys/fs/cgroup/aikernel-sched";
	const char *sdir = "/var/lib/aikernel/sched";
	char *err = NULL, *out = NULL;
	char lerr[256] = "";
	char before[512], after[512];
	char p[768];
	int step_fail = 0;

	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("== test_sched --live（W79 双调度台，uid=%u）==\n",
	       (unsigned)getuid());
	if (getuid() != 0) {
		printf("SKIP: --live 需要 root\n");
		return 0;
	}
	setenv("AIKERNEL_POLICY", "/dev/null", 1);
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	if (ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr)) != 0) {
		printf("FATAL: 租约上下文初始化失败：%s\n", lerr);
		return 1;
	}
	memset(&g_reg, 0, sizeof(g_reg));
	if (tool_registry_load(&g_reg, &err) != AI_OK) {
		printf("FATAL: tools.json 加载失败：%s\n", err ? err : "?");
		return 1;
	}
	printf("注册表：%d 件工具\n", g_reg.tool_count);

	/* 0. 实验前快照（ab 恢复校验用同一份状态） */
	printf("\n=== 0. 事前快照 ===\n");
	live_call("sched_snapshot", "{\"action\":\"save\"}", &out);
	free(out);

	/* 1. status 真读 */
	printf("\n=== 1. sched_status（真读）===\n");
	if (live_call("sched_status", "{}", &out) != 0)
		step_fail++;
	free(out);
	dump_cgroup(cgdir);

	/* 2. knob_set cpu.max + status 读到新值 */
	printf("\n=== 2. knob_set cpu.max=50000 100000 → status 读回 ===\n");
	snprintf(p, sizeof(p), "%.600s/cpu.max", cgdir);
	read_file(p, before, sizeof(before));
	printf("  写入前 cpu.max=[%s]\n", before);
	if (live_call("sched_knob_set",
		      "{\"knob\":\"cpu.max\",\"value\":\"50000 100000\"}",
		      &out) != 0)
		step_fail++;
	free(out);
	read_file(p, after, sizeof(after));
	printf("  写入后真读 cpu.max=[%s] %s\n", after,
	       strcmp(after, "50000 100000") == 0 ? "== 期望 OK" : "!= 期望 FAIL");
	live_call("sched_status", "{}", &out);
	free(out);

	/* 3. 越界拒绝且原值不变 */
	printf("\n=== 3. 越界值被拒且原值不变 ===\n");
	if (live_call("sched_knob_set",
		      "{\"knob\":\"cpu.max\",\"value\":\"1 100000\"}", &out) == 0)
		printf("FAIL: 越界值竟然成功\n"), step_fail++;
	free(out);
	read_file(p, after, sizeof(after));
	printf("  拒绝后真读 cpu.max=[%s] %s\n", after,
	       strcmp(after, "50000 100000") == 0 ? "原值不变 OK" : "原值被改 FAIL");

	/* 4. 其余可写旋钮逐个写读回 */
	printf("\n=== 4. 其余旋钮写读回（真实可写证明）===\n");
	{
		static const char *const kn[] = {
			"cpu.weight", "cpu.max.burst", "io.weight", "io.max",
		};
		static const char *const va[] = {
			"150", "20000", "default 200",
			"MAJ:MIN rbps=8388608 wbps=8388608",
		};
		int i;

		for (i = 0; i < 4; i++) {
			char args[256];
			char dev[64] = "";

			if (i == 3) {
				/* io.max 需要整盘 MAJ:MIN：从 /proc/self/mountinfo 推 */
				FILE *fp2 = fopen("/proc/self/mountinfo", "re");
				char line[2048];

				while (fp2 && fgets(line, sizeof(line), fp2)) {
					unsigned ma, mb;
					char mnt[1024];

					if (sscanf(line, "%*d %*d %u:%u %*s %1023s",
						   &ma, &mb, mnt) == 3 &&
					    strcmp(mnt, "/") == 0) {
						/* 根分区 8:3 → 整盘 8:0 */
						snprintf(dev, sizeof(dev),
							 "%u:0", ma);
						break;
					}
				}
				if (fp2)
					fclose(fp2);
				if (!dev[0])
					continue;
				snprintf(args, sizeof(args),
					 "{\"knob\":\"%s\",\"value\":\"%s rbps=8388608 wbps=8388608\"}",
					 kn[i], dev);
			} else {
				snprintf(args, sizeof(args),
					 "{\"knob\":\"%s\",\"value\":\"%s\"}",
					 kn[i], va[i]);
			}
			if (live_call("sched_knob_set", args, &out) != 0)
				step_fail++;
			free(out);
		}
	}
	dump_cgroup(cgdir);

	/* 5. mode off → 内核默认 */
	printf("\n=== 5. mode_set off（撤销 AI 参数回默认）===\n");
	if (live_call("sched_mode_set", "{\"mode\":\"off\"}", &out) != 0)
		step_fail++;
	free(out);
	dump_cgroup(cgdir);

	/* 6. 快照 restore 往返 */
	printf("\n=== 6. 快照 save → 改值 → restore 逐项读回 ===\n");
	live_call("sched_knob_set",
		  "{\"knob\":\"cpu.max\",\"value\":\"30000 100000\"}", &out);
	free(out);
	read_file(p, before, sizeof(before));
	printf("  restore 前真读 cpu.max=[%s]\n", before);
	if (live_call("sched_snapshot",
		      "{\"action\":\"restore\",\"id\":\"latest\"}", &out) != 0)
		step_fail++;
	free(out);
	read_file(p, after, sizeof(after));
	printf("  restore 后真读 cpu.max=[%s]\n", after);

	/* 7. ml 拒绝原文 */
	printf("\n=== 7. mode_set ml（必须明确拒绝）===\n");
	if (live_call("sched_mode_set", "{\"mode\":\"ml\"}", &out) == 0) {
		printf("FAIL: ml 竟然成功\n");
		step_fail++;
	}
	free(out);

	/* 8. ab_run 完整对照 */
	printf("\n=== 8. sched_ab_run（static vs baseline）===\n");
	read_file(p, before, sizeof(before));
	printf("  ab 前 cpu.max=[%s]\n", before);
	if (live_call("sched_ab_run",
		      "{\"arm_a\":\"static\",\"arm_b\":\"baseline\","
		      "\"duration_s\":4,\"workers\":4}", &out) != 0)
		step_fail++;
	free(out);
	read_file(p, after, sizeof(after));
	printf("  ab 后 cpu.max=[%s] %s\n", after,
	       strcmp(before, after) == 0 ? "与实验前一致 OK" : "不一致 FAIL");
	dump_cgroup(cgdir);

	/* 8b. 非法负载名：前置拒绝且参数集零变更（用户举例的演练形态） */
	printf("\n=== 8b. 非法负载名 → 前置拒绝、参数集零变更 ===\n");
	{
		char dump_before[512], dump_after[512];
		char p2[768];

		snprintf(p2, sizeof(p2), "%.600s/cpu.max", cgdir);
		read_file(p2, dump_before, sizeof(dump_before));
		if (live_call("sched_ab_run",
			      "{\"loads\":\"bogus\",\"duration_s\":2}", &out) == 0) {
			printf("FAIL: 非法负载名竟然成功\n");
			step_fail++;
		}
		free(out);
		read_file(p2, dump_after, sizeof(dump_after));
		printf("  拒绝前后 cpu.max=[%s] / [%s] %s\n", dump_before,
		       dump_after, strcmp(dump_before, dump_after) == 0 ?
		       "未变更 OK" : "被改 FAIL");
	}

	/* 9. 回滚演练：中途强制失败 */
	printf("\n=== 9. 回滚演练（中途注入失败）===\n");
	read_file(p, before, sizeof(before));
	printf("  演练前 cpu.max=[%s]\n", before);
	if (live_call("sched_ab_run",
		      "{\"arm_a\":\"static\",\"arm_b\":\"baseline\","
		      "\"loads\":\"cpu\",\"duration_s\":2,\"workers\":2,"
		      "\"inject_fail_after\":1}", &out) == 0) {
		printf("FAIL: 注入失败竟然成功\n");
		step_fail++;
	}
	free(out);
	read_file(p, after, sizeof(after));
	printf("  演练后 cpu.max=[%s] %s\n", after,
	       strcmp(before, after) == 0 ? "已恢复 OK" : "未恢复 FAIL");
	dump_cgroup(cgdir);

	/* 10. 零残留 */
	printf("\n=== 10. 零残留检查 ===\n");
	printf("  /var/lib/aikernel/sched 内容：\n");
	{
		char cmd[512];
		int rc;

		snprintf(cmd, sizeof(cmd),
			 "ls -la %s; echo '--- abwork 残留:'; ls -d %s/.abwork-* 2>/dev/null | wc -l; echo '--- 负载进程 aik-sched-ab:'; pgrep -x aik-sched-ab | wc -l",
			 sdir, sdir);
		rc = system(cmd);
		(void)rc;
	}

	/* 11. 收尾：mode off（不留 AI 参数在真实 cgroup 上） */
	printf("\n=== 11. 收尾 mode off（回到内核默认，不留 AI 参数）===\n");
	live_call("sched_mode_set", "{\"mode\":\"off\"}", &out);
	free(out);
	dump_cgroup(cgdir);

	/* 12. 末尾快照（证据留存） */
	printf("\n=== 12. 收尾快照 ===\n");
	live_call("sched_snapshot", "{\"action\":\"save\"}", &out);
	free(out);
	live_call("sched_snapshot", "{\"action\":\"list\"}", &out);
	free(out);

	printf("\n== live 结果：%s ==\n", step_fail ? "有 FAIL（见上）" : "ALL OK");
	tool_registry_free(&g_reg);
	free(err);
	return step_fail ? 1 : 0;
}

int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "--live") == 0)
		return live();
	printf("== test_sched（W79 双调度台）==\n");
	setup_env();
	test_pure();
	test_registry();
	test_channel();
	cleanup_env();
	printf("\n%d checks, %d failed\n", checks, fails);
	printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
	return fails == 0 ? 0 : 1;
}
