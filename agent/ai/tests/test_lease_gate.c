// SPDX-License-Identifier: GPL-2.0
/*
 * test_lease_gate.c - W74 executor 闸门集成
 *
 * 覆盖：
 *   - -y（ephemeral）D2 放行 / D3 确认 / python3 D3 / D4 强确认；
 *   - 显式 D3 lease：D3 放行、D4 只升级人工确认（不自动放行）；
 *   - 显式 D2 lease：D2 放行、D3 直接拒绝（交互不能绕过）；
 *   - worker D2+ 拒绝、plan 优先、跨用户/过期/撤销；
 *   - 非 TTY pending→approved 单次消费、args 绑定、过期、伪造 JSON；
 *   - 旧 gate 兼容（无租约上下文时 y/N/非 TTY 行为不变）；
 *   - 租约/确认存储不可被 tee/rm/cp/mv/sed/gcc/相对路径/符号链接写；
 *   - trace JSONL 含 lease_id/danger/confirmation；audit 行含 lease/danger。
 *
 * 全部使用临时目录与合成参数；不触碰真实服务/生产 VM。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "policy/ai_lease.h"
#include "policy/ai_user_policy.h"
#include "tools/executor.h"
#include "tools/tool_registry.h"
#include "ai_json_util.h"
#include "ai_lang.h"
#include "ai_trace.h"

static int g_fail;
static int g_pass;
static struct tool_registry g_reg;
/* 基路径限制在 2048 字节内，保证拼接后缀不触发 fortify 截断告警 */
static char g_base[1024];
static char g_confirm[2048];
static char g_home[2048];
static char g_trace[2048];
static char g_leases[2048];

static void expect(int cond, const char *what)
{
	printf("%s: %s\n", cond ? "PASS" : "FAIL", what);
	if (cond)
		g_pass++;
	else
		g_fail++;
}

static int write_mode(const char *path, const char *s, mode_t mode)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
	size_t len = strlen(s), off = 0;

	if (fd < 0)
		return -1;
	while (off < len) {
		ssize_t w = write(fd, s + off, len - off);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		off += (size_t)w;
	}
	close(fd);
	return 0;
}

static char *read_file(const char *path)
{
	FILE *fp = fopen(path, "r");
	char *buf;
	long sz;

	if (!fp)
		return NULL;
	fseek(fp, 0, SEEK_END);
	sz = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (sz < 0 || sz > 1024 * 1024) {
		fclose(fp);
		return NULL;
	}
	buf = malloc((size_t)sz + 1);
	if (!buf) {
		fclose(fp);
		return NULL;
	}
	if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
		free(buf);
		fclose(fp);
		return NULL;
	}
	buf[sz] = '\0';
	fclose(fp);
	return buf;
}

/* 在 JSONL 文本中找最后一条含 needle 的整行 */
static int last_line_with(const char *text, const char *needle,
			  char *out, size_t cap)
{
	const char *p = text;
	const char *last = NULL;
	const char *start;
	const char *end;
	size_t n;

	while ((p = strstr(p, needle)) != NULL) {
		last = p;
		p += strlen(needle);
	}
	if (!last)
		return -1;
	start = last;
	while (start > text && start[-1] != '\n')
		start--;
	end = strchr(last, '\n');
	if (!end)
		end = text + strlen(text);
	n = (size_t)(end - start);
	if (n >= cap)
		n = cap - 1;
	memcpy(out, start, n);
	out[n] = '\0';
	return 0;
}

/* 扫描 trace 目录，返回最后一条含 needle 的行 */
static int trace_last_line(const char *needle, char *out, size_t cap)
{
	DIR *d = opendir(g_trace);
	struct dirent *e;
	int found = -1;

	while (d && (e = readdir(d)) != NULL) {
		char fp[PATH_MAX + 300];
		char *j;
		char line[8192];

		if (!strstr(e->d_name, ".jsonl"))
			continue;
		snprintf(fp, sizeof(fp), "%s/%s", g_trace, e->d_name);
		j = read_file(fp);
		if (!j)
			continue;
		if (last_line_with(j, needle, line, sizeof(line)) == 0) {
			snprintf(out, cap, "%s", line);
			found = 0;
		}
		free(j);
	}
	if (d)
		closedir(d);
	return found;
}

static const struct ai_tool *find_tool(const char *name)
{
	const struct ai_tool *t = tool_registry_find(&g_reg, name);

	if (!t) {
		printf("FATAL: tool %s not found in registry\n", name);
		exit(2);
	}
	return t;
}

/* 执行工具；out 永远非 NULL（调用者 free） */
static char *run_tool(const char *name, const char *args, int *ok_out)
{
	const struct ai_tool *tool = find_tool(name);
	char *out = NULL;
	int ok = 0;

	tool_executor_run(tool, args, &out, &ok);
	if (!out)
		out = strdup("");
	if (ok_out)
		*ok_out = ok;
	return out;
}

static int is_denied(const char *out)
{
	return out && (strstr(out, TOOL_ERR_DENIED_PREFIX) != NULL ||
		       strstr(out, "ERROR[E_PARAM_PATH]") != NULL);
}

static int contains(const char *out, const char *needle)
{
	return out && strstr(out, needle) != NULL;
}

/* 从 "ERROR: DENIED: CONFIRM_REQUIRED {json}" 提取字段 */
static int confirm_field(const char *out, const char *key,
			 char *buf, size_t n)
{
	const char *p = out ? strstr(out, "CONFIRM_REQUIRED ") : NULL;
	const char *v;
	size_t vl;
	int vt;

	if (p) {
		p += strlen("CONFIRM_REQUIRED ");
	} else if (out && out[0] == '{') {
		p = out;	/* 直接 ai_lease_gate 的 JSON 对象 */
	} else {
		return -1;
	}
	if (ai_json_obj_get(p, strlen(p), key, &v, &vl, &vt) != 1)
		return -1;
	if (vt == AI_JSON_STR) {
		char *s = ai_json_strdup_str(v, vl);

		if (!s)
			return -1;
		snprintf(buf, n, "%s", s);
		free(s);
		return 0;
	}
	snprintf(buf, n, "%.*s", (int)vl, v);
	return 0;
}

/* 把 pending/approved JSON 的 expires_at 改成指定值（保持 0600） */
static void rewrite_expires(const char *path, long long val)
{
	char *j = read_file(path);
	char *key, *p, *end, *n;
	size_t pre, tail;
	int off;

	if (!j)
		return;
	key = strstr(j, "\"expires_at\":");
	if (!key) {
		free(j);
		return;
	}
	p = strchr(key, ':') + 1;
	while (*p == ' ')
		p++;
	end = p;
	while (*end >= '0' && *end <= '9')
		end++;
	pre = (size_t)(p - j);
	tail = strlen(end);
	n = malloc(pre + 32 + tail + 1);
	if (!n) {
		free(j);
		return;
	}
	memcpy(n, j, pre);
	off = snprintf(n + pre, 32, " %lld", val);
	strcpy(n + pre + off, end);
	write_mode(path, n, 0600);
	free(n);
	free(j);
}

static void pending_path(char *buf, size_t n, const char *nonce)
{
	snprintf(buf, n, "%s/pending/%s.json", g_confirm, nonce);
}

static void approved_path(char *buf, size_t n, const char *nonce)
{
	snprintf(buf, n, "%s/approved/%s.json", g_confirm, nonce);
}

static int approve(const char *nonce, int yes, const char *phrase)
{
	char err[AI_LEASE_ERR_MAX] = "";
	int rc = ai_lease_confirm_approve(nonce, yes, phrase, err,
					  sizeof(err));

	if (rc != 0)
		printf("  (approve note: %s)\n", err);
	return rc;
}

/* 直接构造动作并过 gate（不执行工具）；返回 1=allow */
static int gate_synth(uid_t uid, const char *tool, const char *domain,
		      const char *args, const char *risk_str,
		      enum ai_tool_risk risk, int is_exec,
		      char **out, enum ai_lease_gate_result *res)
{
	char *target = NULL;
	const char *why = NULL;
	struct ai_lease_action act;
	enum ai_danger d;
	int rc;

	d = ai_danger_classify(tool, domain, risk_str, args, &target, &why);
	memset(&act, 0, sizeof(act));
	act.tool = tool;
	act.domain = domain;
	act.target = target;
	act.args_json = args;
	act.risk_str = risk_str;
	act.risk = risk;
	act.danger = d;
	act.is_exec = is_exec;
	rc = ai_lease_gate(uid, &act, "synthetic test action", NULL, out,
			   res);
	free(target);
	return rc;
}

static int gen_pending(const char *tool, const char *args,
		       char *nonce, size_t n)
{
	char *out = run_tool(tool, args, NULL);
	int rc = confirm_field(out, "nonce", nonce, n);

	if (rc != 0)
		printf("  (pending note: %s)\n", out);
	free(out);
	return rc;
}

static void test_legacy(void)
{
	enum ai_policy_gate_result res = AI_GATE_ALLOW;

	ai_lease_ctx_reset();
	ai_policy_set_assume_yes(1);
	expect(ai_policy_get_assume_yes() == 1,
	       "legacy: ai_policy_get_assume_yes() 仍为 1（prompt 文案）");
	expect(ai_policy_gate_reason(getuid(), "legacy.tool", AI_RISK_W2,
				     "impact", "{}", &res) == 1 &&
	       res == AI_GATE_ALLOW,
	       "legacy: 无租约上下文时旧 gate 在 assume_yes 下放行");
	ai_policy_set_assume_yes(0);
	res = AI_GATE_ALLOW;
	expect(ai_policy_gate_reason(getuid(), "legacy.tool", AI_RISK_W2,
				     "impact", "{}", &res) == 0 &&
	       res == AI_GATE_NEED_NO_TTY,
	       "legacy: 非 TTY 无预授权仍走原 NEED_NO_TTY 拒绝");
	ai_policy_set_assume_yes(1);	/* 保留，验证 gate 不再无条件放行 */
}

static void test_none_confirm(void)
{
	char nonce[80], args[64], p[PATH_MAX];
	char *out;
	struct stat st;

	/* 不初始化 ctx：executor 必须自动进入 NONE，绝不回落到旧
	 * assume_yes/--yes 全局放行语义。 */
	ai_lease_ctx_reset();
	expect(!ai_lease_ctx_active(),
	       "none: 未初始化租约上下文");
	snprintf(args, sizeof(args), "{\"value\":\"0\"}");
	out = run_tool("procfs_write_telemetry_reset", args, NULL);
	expect(is_denied(out) && contains(out, "CONFIRM_REQUIRED"),
	       "none: 未初始化 + assume_yes=1，D2 仍 CONFIRM_REQUIRED");
	expect(ai_lease_ctx_active(),
	       "none: executor 自动初始化 NONE 上下文");
	free(out);

	out = run_tool("netlink_act_sched_nice",
		       "{\"pid\":1,\"value\":5}", NULL);
	expect(is_denied(out) && contains(out, "CONFIRM_REQUIRED"),
	       "none: 未初始化 + assume_yes=1，D3 仍 CONFIRM_REQUIRED");
	free(out);

	out = run_tool("procfs_write_telemetry_reset", args, NULL);
	expect(confirm_field(out, "danger", nonce, sizeof(nonce)) == 0 &&
	       strcmp(nonce, "D2") == 0,
	       "none: CONFIRM_REQUIRED danger=D2");
	expect(confirm_field(out, "nonce", nonce, sizeof(nonce)) == 0 &&
	       strlen(nonce) == 32,
	       "none: CONFIRM_REQUIRED nonce 为 32 hex");
	pending_path(p, sizeof(p), nonce);
	expect(stat(p, &st) == 0 && (st.st_mode & 0777) == 0600,
	       "none: pending 文件存在且 0600");
	free(out);

	/* 未批准重试：仍拒绝 */
	setenv("AIKERNEL_CONFIRM_NONCE", nonce, 1);
	out = run_tool("procfs_write_telemetry_reset", args, NULL);
	expect(is_denied(out), "none: 未批准时带 nonce 仍拒绝");
	free(out);

	expect(approve(nonce, 1, "yes") == 0, "none: /lease confirm yes 批准");
	out = run_tool("procfs_write_telemetry_reset", args, NULL);
	expect(!is_denied(out), "none: 批准后重试放行一次");
	free(out);

	out = run_tool("procfs_write_telemetry_reset", args, NULL);
	expect(is_denied(out), "none: 同一 nonce 重复使用拒绝");
	free(out);
	unsetenv("AIKERNEL_CONFIRM_NONCE");

	/* args 不匹配 */
	expect(gen_pending("procfs_write_telemetry_reset",
			   "{\"value\":\"1\"}", nonce, sizeof(nonce)) == 0,
	       "none: 生成 args=A 的 pending");
	expect(approve(nonce, 1, "yes") == 0, "none: 批准 args=A");
	setenv("AIKERNEL_CONFIRM_NONCE", nonce, 1);
	out = run_tool("procfs_write_telemetry_reset",
		       "{\"value\":\"2\"}", NULL);
	expect(is_denied(out) && contains(out, "confirm_invalid"),
	       "none: args 不匹配拒绝（绑定 tool+args）");
	free(out);
	unsetenv("AIKERNEL_CONFIRM_NONCE");

	/* 过期 pending */
	expect(gen_pending("procfs_write_telemetry_reset",
			   "{\"value\":\"3\"}", nonce, sizeof(nonce)) == 0,
	       "none: 生成过期用例 pending");
	pending_path(p, sizeof(p), nonce);
	rewrite_expires(p, (long long)time(NULL) - 10);
	expect(approve(nonce, 1, "yes") != 0,
	       "none: 过期 pending 批准拒绝");

	/* 伪造 approved：danger/tool 对但 args 不同 */
	expect(gen_pending("procfs_write_telemetry_reset",
			   "{\"value\":\"4\"}", nonce, sizeof(nonce)) == 0,
	       "none: 生成伪造测试 pending");
	{
		char ap[PATH_MAX];
		char fake[1024];

		approved_path(ap, sizeof(ap), nonce);
		snprintf(fake, sizeof(fake),
			 "{\"nonce\":\"%s\",\"tool\":\"procfs_write_telemetry_reset\","
			 "\"args_json\":\"{\\\"value\\\":\\\"999\\\"}\","
			 "\"danger\":\"D2\",\"lease_id\":null,"
			 "\"expires_at\":%lld,\"approved\":true}\n",
			 nonce, (long long)time(NULL) + 300);
		write_mode(ap, fake, 0600);
		setenv("AIKERNEL_CONFIRM_NONCE", nonce, 1);
		out = run_tool("procfs_write_telemetry_reset",
			       "{\"value\":\"4\"}", NULL);
		expect(is_denied(out), "none: 伪造 approved（args 不同）拒绝");
		free(out);
		expect(access(ap, F_OK) == 0,
		       "none: 不匹配的 approved 不被消费（保留审计）");
		unlink(ap);
		unsetenv("AIKERNEL_CONFIRM_NONCE");
	}
}

static void test_d4_phrase(void)
{
	char nonce[80], phrase[160], danger[16];
	char *out = NULL;
	char err[AI_LEASE_ERR_MAX];
	const char *args = "{\"value\":1,\"pid\":1}";
	enum ai_lease_gate_result res = AI_LGATE_DENY;
	int rc;

	/* D4 只允许 root 确认；用 uid 0 模拟 root AI 进程 */
	ai_lease_ctx_init(NULL, 0, 0, err, sizeof(err));
	rc = gate_synth(0, "netlink_act_sec_seccomp", "netsec", args,
			"W2", AI_RISK_W2, 0, &out, &res);
	expect(rc == 0 && res == AI_LGATE_CONFIRM_REQUIRED &&
	       confirm_field(out, "nonce", nonce, sizeof(nonce)) == 0 &&
	       confirm_field(out, "danger", danger, sizeof(danger)) == 0 &&
	       strcmp(danger, "D4") == 0,
	       "d4: sec_seccomp 非 TTY 返回 D4 CONFIRM_REQUIRED（root）");
	free(out);
	expect(approve(nonce, 1, "yes") != 0,
	       "d4: 脚本 yes 不能批准 D4");
	snprintf(phrase, sizeof(phrase), "CONFIRM D4 %s", nonce);
	expect(approve(nonce, 1, phrase) == 0,
	       "d4: 精确短语 CONFIRM D4 <nonce> 批准");
	setenv("AIKERNEL_CONFIRM_NONCE", nonce, 1);
	out = NULL;
	res = AI_LGATE_DENY;
	rc = gate_synth(0, "netlink_act_sec_seccomp", "netsec", args,
			"W2", AI_RISK_W2, 0, &out, &res);
	expect(rc == 1 && res == AI_LGATE_ALLOW,
	       "d4: 批准后放行一次（root）");
	free(out);
	unsetenv("AIKERNEL_CONFIRM_NONCE");
}

static void test_ephemeral(void)
{
	char nonce[80], danger[16];
	char *out;
	char err[AI_LEASE_ERR_MAX];

	ai_lease_ctx_init(NULL, 1, getuid(), err, sizeof(err));
	out = run_tool("procfs_write_telemetry_reset", "{\"value\":\"0\"}",
		       NULL);
	expect(!is_denied(out), "-y: D2 短租约自动放行");
	free(out);

	out = run_tool("netlink_act_sched_nice",
		       "{\"pid\":1,\"value\":5}", NULL);
	expect(is_denied(out) && contains(out, "CONFIRM_REQUIRED"),
	       "-y: D3（netlink act）进入确认");
	free(out);

	out = run_tool("exec_run",
		       "{\"command\":\"python3\",\"args\":[\"-c\",\"print(1)\"]}",
		       NULL);
	expect(is_denied(out) && contains(out, "CONFIRM_REQUIRED") &&
	       confirm_field(out, "danger", danger, sizeof(danger)) == 0 &&
	       strcmp(danger, "D3") == 0,
	       "-y: exec_run python3 归 D3 → CONFIRM_REQUIRED（不是 ALLOW）");
	free(out);

	out = run_tool("exec_run",
		       "{\"command\":\"systemctl\",\"args\":[\"restart\",\"nginx\"]}",
		       NULL);
	expect(is_denied(out) && contains(out, "CONFIRM_REQUIRED"),
	       "-y: systemctl restart D3 → CONFIRM_REQUIRED");
	free(out);

	/* 非 root 进程的 D4 直接拒绝 */
	out = run_tool("netlink_act_sec_seccomp", "{\"value\":1,\"pid\":1}",
		       NULL);
	expect(is_denied(out) && contains(out, "d4_requires_root"),
	       "-y: 非 root D4 → d4_requires_root（不弹确认）");
	free(out);

	/* root AI（uid 0）才进入 D4 强确认 */
	{
		enum ai_lease_gate_result res = AI_LGATE_DENY;
		int rc;

		out = NULL;
		rc = gate_synth(0, "netlink_act_sec_seccomp", "netsec",
				"{\"value\":1,\"pid\":1}", "W2",
				AI_RISK_W2, 0, &out, &res);
		expect(rc == 0 && res == AI_LGATE_CONFIRM_REQUIRED &&
		       confirm_field(out, "nonce", nonce, sizeof(nonce)) == 0 &&
		       confirm_field(out, "danger", danger,
				     sizeof(danger)) == 0 &&
		       strcmp(danger, "D4") == 0,
		       "-y: root D4 进入 D4 强确认");
		free(out);
	}
}

static void test_explicit(void)
{
	char id[AI_LEASE_ID_MAX] = "", path[PATH_MAX], err[AI_LEASE_ERR_MAX];
	char nonce[80], phrase[160], danger[16];
	char *out;

	/* D3 lease：D3 放行，D4 只升级人工确认 */
	err[0] = '\0';
	expect(ai_lease_issue("netsec,sysadmin,res", "D3",
			      "w74 gate D3 lease", 600, getuid(),
			      id, sizeof(id), path, sizeof(path),
			      err, sizeof(err)) == 0,
	       "explicit: 签发 D3 租约");
	expect(ai_lease_ctx_init(id, 0, getuid(), err, sizeof(err)) == 0,
	       "explicit: 加载 D3 租约");
	out = run_tool("netlink_act_sched_nice",
		       "{\"pid\":1,\"value\":5}", NULL);
	expect(!is_denied(out), "explicit: D3 lease + D3 netlink 放行");
	free(out);

	out = run_tool("netlink_act_sec_seccomp", "{\"value\":1,\"pid\":1}",
		       NULL);
	expect(is_denied(out) && contains(out, "d4_requires_root"),
	       "explicit: 非 root 进程的 D4 直接拒绝");
	free(out);

	/* root AI（uid 0）在 D3 lease 下仍需人工 D4 */
	{
		enum ai_lease_gate_result res = AI_LGATE_DENY;
		int rc;

		out = NULL;
		rc = gate_synth(0, "netlink_act_sec_seccomp", "netsec",
				"{\"value\":1,\"pid\":1}", "W2",
				AI_RISK_W2, 0, &out, &res);
		expect(rc == 0 && res == AI_LGATE_CONFIRM_REQUIRED &&
		       confirm_field(out, "nonce", nonce,
				     sizeof(nonce)) == 0 &&
		       confirm_field(out, "danger", danger,
				     sizeof(danger)) == 0 &&
		       strcmp(danger, "D4") == 0,
		       "explicit: D3 lease + sec_seccomp → CONFIRM_D4（root）");
		free(out);
	}
	snprintf(phrase, sizeof(phrase), "CONFIRM D4 %s", nonce);
	expect(approve(nonce, 1, phrase) == 0, "explicit: D4 短语批准");
	setenv("AIKERNEL_CONFIRM_NONCE", nonce, 1);
	{
		enum ai_lease_gate_result res = AI_LGATE_DENY;
		int rc;

		out = NULL;
		rc = gate_synth(0, "netlink_act_sec_seccomp", "netsec",
				"{\"value\":1,\"pid\":1}", "W2",
				AI_RISK_W2, 0, &out, &res);
		expect(rc == 1 && res == AI_LGATE_ALLOW,
		       "explicit: D4 人工批准后放行一次（root）");
		free(out);
	}
	unsetenv("AIKERNEL_CONFIRM_NONCE");

	/* D2 lease：D2 放行，D3 直接拒绝 */
	err[0] = '\0';
	id[0] = '\0';
	expect(ai_lease_issue("aicore,sysadmin", "D2", "w74 gate D2 lease", 600,
			      getuid(), id, sizeof(id), path, sizeof(path),
			      err, sizeof(err)) == 0,
	       "explicit: 签发 D2 租约");
	expect(ai_lease_ctx_init(id, 0, getuid(), err, sizeof(err)) == 0,
	       "explicit: 加载 D2 租约");
	out = run_tool("procfs_write_telemetry_reset", "{\"value\":\"0\"}",
		       NULL);
	expect(!is_denied(out), "explicit: D2 lease + D2 工具放行");
	free(out);

	out = run_tool("exec_run",
		       "{\"command\":\"systemctl\",\"args\":[\"restart\",\"nginx\"]}",
		       NULL);
	expect(is_denied(out) && contains(out, "lease_ceiling_denied"),
	       "explicit: D2 lease + D3 直接拒绝（交互不能绕过）");
	free(out);

	/* 撤销后拒绝 */
	expect(ai_lease_revoke(id, getuid(), err, sizeof(err)) == 0,
	       "explicit: 撤销 D2 租约");
	ai_lease_ctx_reset();
	expect(ai_lease_ctx_init(id, 0, getuid(), err, sizeof(err)) != 0,
	       "explicit: 启动加载已撤销租约 fail-closed");
}

static void test_d3_write_forms(void)
{
	static const struct {
		const char *json;
		const char *label;
	} cases[] = {
		{ "{\"command\":\"date\",\"args\":[\"-s\",\"2026-01-01\"]}",
		  "date -s" },
		{ "{\"command\":\"hostname\",\"args\":[\"-F\",\"/tmp/w74-hn\"]}",
		  "hostname -F" },
		{ "{\"command\":\"dmesg\",\"args\":[\"-c\"]}", "dmesg -c" },
		{ "{\"command\":\"smartctl\",\"args\":[\"-t\",\"short\",\"/dev/sda\"]}",
		  "smartctl -t" },
		{ "{\"command\":\"ss\",\"args\":[\"-K\"]}", "ss -K" },
	};
	char err[AI_LEASE_ERR_MAX];
	char id[AI_LEASE_ID_MAX] = "", lpath[512], danger[16];
	char *out;
	size_t i;

	ai_lease_ctx_init(NULL, 1, getuid(), err, sizeof(err));
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		char label[128];

		out = run_tool("exec_run", cases[i].json, NULL);
		snprintf(label, sizeof(label),
			 "-y: %s 写形态 → D3 CONFIRM_REQUIRED",
			 cases[i].label);
		expect(is_denied(out) && contains(out, "CONFIRM_REQUIRED") &&
		       confirm_field(out, "danger", danger,
				     sizeof(danger)) == 0 &&
		       strcmp(danger, "D3") == 0,
		       label);
		free(out);
	}

	/* SSH 私钥/PAM：非 root 进程直接拒绝；root（uid 0）才进入 D4 */
	out = run_tool("exec_run",
		       "{\"command\":\"tee\",\"args\":[\"/root/.ssh/id_ed25519\"]}",
		       NULL);
	expect(is_denied(out) && contains(out, "d4_requires_root"),
	       "-y: 非 root 写 SSH 私钥 → d4_requires_root");
	free(out);
	out = run_tool("exec_run",
		       "{\"command\":\"tee\",\"args\":[\"/etc/pam.d/w74\"]}",
		       NULL);
	expect(is_denied(out) && contains(out, "d4_requires_root"),
	       "-y: 非 root 写 /etc/pam.d → d4_requires_root");
	free(out);
	{
		enum ai_lease_gate_result res = AI_LGATE_DENY;
		int rc;

		out = NULL;
		rc = gate_synth(0, "exec_run", "fs,sysadmin",
				"{\"command\":\"tee\",\"args\":[\"/root/.ssh/id_ed25519\"]}",
				"W2", AI_RISK_W2, 1, &out, &res);
		expect(rc == 0 && res == AI_LGATE_CONFIRM_REQUIRED &&
		       confirm_field(out, "danger", danger,
				     sizeof(danger)) == 0 &&
		       strcmp(danger, "D4") == 0,
		       "-y: root 写 SSH 私钥 → D4 CONFIRM_REQUIRED");
		free(out);
	}

	/* D3 显式租约：同一批写形态在租约内 ALLOW（直接 gate，不执行） */
	err[0] = '\0';
	expect(ai_lease_issue("*", "D3", "w74 d3 write forms", 600,
			      getuid(), id, sizeof(id), lpath,
			      sizeof(lpath), err, sizeof(err)) == 0 &&
	       ai_lease_ctx_init(id, 0, getuid(), err, sizeof(err)) == 0,
	       "explicit: 签发/加载 D3 写形态租约");
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		struct ai_lease_action act;
		char *target = NULL;
		const char *why = NULL;
		enum ai_danger d = ai_danger_classify(
			"exec_run", "sysadmin,fs", "W2", cases[i].json,
			&target, &why);
		char *gout = NULL;
		enum ai_lease_gate_result res = AI_LGATE_DENY;
		char label[160];
		int rc;

		memset(&act, 0, sizeof(act));
		act.tool = "exec_run";
		act.domain = "sysadmin,fs";
		act.target = target;
		act.args_json = cases[i].json;
		act.risk_str = "W2";
		act.risk = AI_RISK_W2;
		act.danger = d;
		act.is_exec = 1;
		rc = ai_lease_gate(getuid(), &act, "test", NULL, &gout,
				   &res);
		snprintf(label, sizeof(label),
			 "explicit D3 lease: %s → ALLOW", cases[i].label);
		expect(rc == 1 && res == AI_LGATE_ALLOW &&
		       strcmp(ai_lease_last_confirm_source(), "lease") == 0,
		       label);
		free(gout);
		free(target);
	}

	/* 显式 D3 lease 遇到 SSH 私钥（D4）仍只给人工 D4（root） */
	{
		enum ai_lease_gate_result res = AI_LGATE_DENY;
		int rc;

		out = NULL;
		rc = gate_synth(0, "exec_run", "fs,sysadmin",
				"{\"command\":\"tee\",\"args\":[\"/root/.ssh/id_ed25519\"]}",
				"W2", AI_RISK_W2, 1, &out, &res);
		expect(rc == 0 && res == AI_LGATE_CONFIRM_REQUIRED &&
		       confirm_field(out, "danger", danger,
				     sizeof(danger)) == 0 &&
		       strcmp(danger, "D4") == 0,
		       "explicit D3 lease: SSH 私钥仍 CONFIRM_D4（root）");
		free(out);
	}
}

static void test_d4_nonroot_gate(void)
{
	struct ai_lease_action act;
	char err[AI_LEASE_ERR_MAX];
	char *out = NULL;
	enum ai_lease_gate_result res = AI_LGATE_ALLOW;

	if (getuid() == 0) {
		printf("SKIP: D4 非 root gate（当前即 root）\n");
		return;
	}
	ai_lease_ctx_init(NULL, 1, getuid(), err, sizeof(err));
	memset(&act, 0, sizeof(act));
	act.tool = "synthetic_d4";
	act.domain = "sysadmin";
	act.args_json = "{}";
	act.risk_str = "W1";
	act.risk = AI_RISK_W1;
	act.danger = AI_D4;
	expect(ai_lease_gate(getuid(), &act, "test", NULL, &out, &res) == 0 &&
	       res == AI_LGATE_DENY &&
	       strcmp(ai_lease_last_reason(), "d4_requires_root") == 0,
	       "gate: D4 + 非 root → d4_requires_root（不弹确认）");
	free(out);
}

static void test_audit_trace_protect(void)
{
	char err[AI_LEASE_ERR_MAX];
	char path[PATH_MAX];
	struct stat before, after;
	char *out;

	ai_lease_ctx_init(NULL, 1, getuid(), err, sizeof(err));
	out = run_tool("exec_run",
		       "{\"command\":\"tee\",\"args\":[\"/root/.aikernel/audit.log\"],\"input\":\"x\"}",
		       NULL);
	expect(is_denied(out) && contains(out, "E_PARAM_PATH"),
	       "audit-protect: tee /root/.aikernel/audit.log 拒绝");
	free(out);

	out = run_tool("exec_run",
		       "{\"command\":\"rm\",\"args\":[\"/root/.aikernel/audit.log\"]}",
		       NULL);
	expect(is_denied(out) && contains(out, "E_PARAM_PATH"),
	       "audit-protect: rm audit.log 拒绝");
	free(out);

	out = run_tool("exec_run",
		       "{\"command\":\"sed\",\"args\":[\"-i\",\"s/a/b/\",\"/var/log/aikernel/trace/x.jsonl\"]}",
		       NULL);
	expect(is_denied(out) && contains(out, "E_PARAM_PATH"),
	       "audit-protect: sed -i trace jsonl 拒绝");
	free(out);

	out = run_tool("exec_run",
		       "{\"command\":\"cat\",\"args\":[\"/root/.aikernel/audit.log\"]}",
		       NULL);
	expect(!is_denied(out), "audit-protect: 读审计仍允许（非策略拒绝）");
	free(out);

	snprintf(path, sizeof(path), "%s/.aikernel/audit.log", g_home);
	expect(stat(path, &before) == 0, "audit-protect: 测试审计文件存在");
	expect(ai_policy_audit_ex(getuid(), ai_policy_mode_for_uid(getuid()),
				  "w74.audit.test", "{}", "ok",
				  NULL, NULL, NULL) == 0,
	       "audit-protect: ai_policy_audit_ex 仍可追加");
	expect(stat(path, &after) == 0 && after.st_size >= before.st_size,
	       "audit-protect: 审计追加未被路径保护影响");
}

static void test_trace_sticky(void)
{
	char *out;
	char line[8192];
	const char *bad = "{\"command\":\"find\",\"args\":[\"/tmp\",\"-delete\"]}";
	char err[AI_LEASE_ERR_MAX];

	ai_lease_ctx_init(NULL, 1, getuid(), err, sizeof(err));
	out = run_tool("procfs_write_telemetry_reset", "{\"value\":\"0\"}",
		       NULL);
	expect(!is_denied(out), "trace-sticky: 前置 D2 gate 放行");
	free(out);
	expect(ai_lease_last_lease_id() != NULL,
	       "trace-sticky: 前置 gate 留下 lease 元数据");

	out = run_tool("exec_run", bad, NULL);
	expect(is_denied(out), "trace-sticky: 危险形态 early deny（find -delete）");
	expect(ai_lease_last_lease_id() == NULL &&
	       ai_lease_last_danger() == NULL,
	       "trace-sticky: early deny 后元数据已清空（无上一笔粘滞）");
	ai_trace_tool_call_ex("exec_run", "exec", "W2", bad, 0, 0,
			      "denied", -1, out, out ? strlen(out) : 0,
			      ai_lease_last_danger(),
			      ai_lease_last_lease_id());
	free(out);
	expect(trace_last_line("-delete", line, sizeof(line)) == 0,
	       "trace-sticky: 找到本次 tool_call trace");
	expect(!strstr(line, "\"danger\"") && !strstr(line, "\"lease_id\""),
	       "trace-sticky: 本次 tool_call 不带上一笔 danger/lease");
}

static void test_live_revocation(void)
{
	char id[AI_LEASE_ID_MAX] = "", err[AI_LEASE_ERR_MAX];
	char path[PATH_MAX], marker[PATH_MAX];
	char *out;
	FILE *fp;

	expect(ai_lease_issue("sysadmin,res", "D3", "w74 live revoke", 600,
			      getuid(), id, sizeof(id), path, sizeof(path),
			      err, sizeof(err)) == 0 &&
	       ai_lease_ctx_init(id, 0, getuid(), err, sizeof(err)) == 0,
	       "live: 签发并加载 D3 租约");

	out = run_tool("netlink_act_sched_nice",
		       "{\"pid\":1,\"value\":5}", NULL);
	expect(!is_denied(out), "live: 加载后 D3 放行");
	free(out);

	/* 文件被改写（size/mtime/inode 变化）→ fail-closed */
	fp = fopen(path, "a");
	if (fp) {
		fputs("\n", fp);
		fclose(fp);
	}
	out = run_tool("netlink_act_sched_nice",
		       "{\"pid\":1,\"value\":5}", NULL);
	expect(is_denied(out) && contains(out, "lease_file_changed"),
	       "live: 租约文件被改写 → DENY lease_file_changed");
	free(out);
	out = run_tool("procfs_read_status", "{}", NULL);
	expect(!is_denied(out), "live: 文件变化不阻断 D0 读");
	free(out);

	/* 重新加载（指纹更新）后恢复 */
	expect(ai_lease_ctx_init(id, 0, getuid(), err, sizeof(err)) == 0,
	       "live: 重新加载改写后的合法租约");
	out = run_tool("netlink_act_sched_nice",
		       "{\"pid\":1,\"value\":5}", NULL);
	expect(!is_denied(out), "live: 重载后 D3 再次放行");
	free(out);

	/* Principal 写撤销标记 → 下一次 gate 立即拒绝（无需重启） */
	snprintf(marker, sizeof(marker), "%s/%s.revoked", g_leases, id);
	write_mode(marker, "{\"revoked\":true}\n", 0600);
	out = run_tool("netlink_act_sched_nice",
		       "{\"pid\":1,\"value\":5}", NULL);
	expect(is_denied(out) && contains(out, "lease_revoked_live"),
	       "live: 运行中撤销立即生效（lease_revoked_live）");
	free(out);
	out = run_tool("procfs_read_status", "{}", NULL);
	expect(!is_denied(out), "live: 撤销不阻断 D0 读");
	free(out);

	/* 删除标记也不复活：本进程粘滞撤销，需重新签发/重启加载 */
	unlink(marker);
	out = run_tool("netlink_act_sched_nice",
		       "{\"pid\":1,\"value\":5}", NULL);
	expect(is_denied(out) && contains(out, "lease_revoked_live"),
	       "live: 删除标记后仍拒绝（进程内粘滞撤销）");
	free(out);
}

static void test_worker_plan(void)
{
	char err[AI_LEASE_ERR_MAX];
	char *out;

	/* worker：D2+ 拒绝，D1/D0 放行 */
	ai_lease_ctx_init(NULL, 1, getuid(), err, sizeof(err));
	setenv("AIKERNEL_SANDBOX", "w74-worker", 1);
	out = run_tool("procfs_write_telemetry_reset", "{\"value\":\"0\"}",
		       NULL);
	expect(is_denied(out), "worker: D2 拒绝（即使父租约 D2）");
	free(out);
	out = run_tool("procfs_write_telemetry_format", "{\"value\":\"0\"}",
		       NULL);
	expect(!is_denied(out), "worker: D1 放行");
	free(out);
	unsetenv("AIKERNEL_SANDBOX");

	/* plan：租约不能绕过只读 */
	ai_lease_ctx_init(NULL, 1, getuid(), err, sizeof(err));
	ai_policy_set_plan_mode(1);
	out = run_tool("procfs_write_telemetry_format", "{\"value\":\"0\"}",
		       NULL);
	expect(is_denied(out) && contains(out, "plan"),
	       "plan: D1 拒绝（租约不能绕过 plan）");
	free(out);
	out = run_tool("procfs_read_status", "{}", NULL);
	expect(!is_denied(out), "plan: D0 允许");
	free(out);
	ai_policy_set_plan_mode(0);
}

static void test_protected_writes(void)
{
	char *out;
	char linkp[PATH_MAX];
	char cwd[PATH_MAX];

	/* 用 ephemeral 让 D1/D2 过闸（D3/D4 仍确认），再由 executor
	 * 写目标校验拒绝受保护目录——验证路径层独立于 D 级。 */
	{
		char lerr[AI_LEASE_ERR_MAX] = "";

		ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));
	}

	out = run_tool("exec_run",
		       "{\"command\":\"tee\",\"args\":[\"/var/lib/aikernel/leases/pwn.json\"],\"input\":\"x\"}",
		       NULL);
	expect(is_denied(out) && contains(out, "E_PARAM_PATH"),
	       "protect: W1 tee 写 /var/lib/aikernel 拒绝");
	free(out);

	out = run_tool("exec_run",
		       "{\"command\":\"rm\",\"args\":[\"/var/lib/aikernel/leases/pwn.json\"]}",
		       NULL);
	expect(is_denied(out) && contains(out, "E_PARAM_PATH"),
	       "protect: W2 rm 写 /var/lib/aikernel 拒绝");
	free(out);

	out = run_tool("exec_run",
		       "{\"command\":\"cp\",\"args\":[\"/etc/hostname\",\"/run/aikernel/confirm/x.json\"]}",
		       NULL);
	expect(is_denied(out) && contains(out, "E_PARAM_PATH"),
	       "protect: cp 到 /run/aikernel 拒绝");
	free(out);

	out = run_tool("exec_run",
		       "{\"command\":\"mv\",\"args\":[\"/var/lib/aikernel/leases/x\",\"/tmp/x\"]}",
		       NULL);
	expect(is_denied(out) && contains(out, "E_PARAM_PATH"),
	       "protect: mv 从受保护目录拒绝");
	free(out);

	out = run_tool("exec_run",
		       "{\"command\":\"sed\",\"args\":[\"-i\",\"s/a/b/\",\"/run/aikernel/confirm/x.json\"]}",
		       NULL);
	expect(is_denied(out) && contains(out, "E_PARAM_PATH"),
	       "protect: sed -i 写受保护目录拒绝");
	free(out);

	{
		char src[2048], args[4096];

		snprintf(src, sizeof(src), "%s/gcc-src.c", g_base);
		write_mode(src, "int main(void){return 0;}\n", 0600);
		snprintf(args, sizeof(args),
			 "{\"command\":\"gcc\",\"args\":[\"-o\",\"/var/lib/aikernel/leases/x\",\"%s\"]}",
			 src);
		out = run_tool("exec_run", args, NULL);
		/* gcc 自身的 /tmp-only 规则更严（E_PARAM_GCC_ARGS），
		 * 无论走哪条分支都必须结构化拒绝。 */
		expect(contains(out, "ERROR[E_PARAM") &&
		       contains(out, "gcc"),
		       "protect: gcc -o 写受保护目录拒绝（/tmp-only 更严）");
		free(out);
	}

	/* .. 与相对路径 */
	out = run_tool("exec_run",
		       "{\"command\":\"tee\",\"args\":[\"/tmp/../var/lib/aikernel/leases/x\"],\"input\":\"x\"}",
		       NULL);
	expect(is_denied(out) && contains(out, "E_PARAM_PATH"),
	       "protect: .. 穿越写入拒绝");
	free(out);

	snprintf(linkp, sizeof(linkp), "%s/link-protected", g_base);
	unlink(linkp);
	if (symlink("/var/lib/aikernel/leases/x", linkp) == 0) {
		char args[PATH_MAX + 128];

		snprintf(args, sizeof(args),
			 "{\"command\":\"tee\",\"args\":[\"%s\"],\"input\":\"x\"}",
			 linkp);
		out = run_tool("exec_run", args, NULL);
		expect(is_denied(out) && contains(out, "E_PARAM_PATH"),
		       "protect: 符号链接写入拒绝");
		free(out);
		unlink(linkp);
	}

	if (getcwd(cwd, sizeof(cwd)) && chdir("/") == 0) {
		out = run_tool("exec_run",
			       "{\"command\":\"tee\",\"args\":[\"var/lib/aikernel/leases/x\"],\"input\":\"x\"}",
			       NULL);
		expect(is_denied(out) && contains(out, "E_PARAM_PATH"),
		       "protect: 相对路径（cwd=/）写入拒绝");
		free(out);
		if (chdir(cwd) != 0)
			fprintf(stderr, "chdir back failed\n");
	}
}

static void test_trace_audit(void)
{
	char path[PATH_MAX];
	char *j;
	DIR *d;
	struct dirent *e;
	int found_audit = 0, found_trace = 0;

	snprintf(path, sizeof(path), "%s/.aikernel/audit.log", g_home);
	j = read_file(path);
	if (j) {
		found_audit = strstr(j, "lease=") != NULL &&
			      strstr(j, "danger=") != NULL &&
			      strstr(j, "confirm=") != NULL;
		free(j);
	}
	expect(found_audit, "evidence: audit 行含 lease/danger/confirm");

	d = opendir(g_trace);
	while (d && (e = readdir(d)) != NULL) {
		char fp[PATH_MAX + 300];

		if (strstr(e->d_name, ".jsonl") == NULL)
			continue;
		snprintf(fp, sizeof(fp), "%s/%s", g_trace, e->d_name);
		j = read_file(fp);
		if (j) {
			if (strstr(j, "\"policy_decision\"") &&
			    strstr(j, "\"lease_id\"") &&
			    strstr(j, "\"danger\"") &&
			    strstr(j, "\"confirmation\""))
				found_trace = 1;
			free(j);
		}
	}
	if (d)
		closedir(d);
	expect(found_trace,
	       "evidence: trace JSONL policy_decision 含 lease_id/danger/confirmation");
}

int main(void)
{
	char tmpl[] = "/tmp/w74gateXXXXXX";
	char home[2048], leases[2048], confirm[2048];
	char trace[2048], pol[2048], cfile[2048 + 32];
	FILE *fp;
	char *err = NULL;
	int rc;

	if (!mkdtemp(tmpl)) {
		perror("mkdtemp");
		return 2;
	}
	snprintf(g_base, sizeof(g_base), "%s", tmpl);
	snprintf(home, sizeof(home), "%s/home", g_base);
	snprintf(leases, sizeof(leases), "%s/leases", g_base);
	snprintf(confirm, sizeof(confirm), "%s/confirm", g_base);
	snprintf(trace, sizeof(trace), "%s/trace", g_base);
	snprintf(g_home, sizeof(g_home), "%s", home);
	snprintf(g_confirm, sizeof(g_confirm), "%s", confirm);
	snprintf(g_trace, sizeof(g_trace), "%s", trace);
	snprintf(g_leases, sizeof(g_leases), "%s", leases);
	mkdir(home, 0700);
	mkdir(leases, 0700);
	mkdir(confirm, 0700);
	mkdir(trace, 0700);

	setenv("HOME", home, 1);
	setenv("AIKERNEL_LEASE_DIR", leases, 1);
	setenv("AIKERNEL_CONFIRM_DIR", confirm, 1);
	setenv("AIKERNEL_TRACE_DIR", trace, 1);
	setenv("AIKERNEL_TRACE_ENABLED", "1", 1);
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	unsetenv("AIKERNEL_CONFIRM_NONCE");
	unsetenv("AIKERNEL_SANDBOX");

	snprintf(pol, sizeof(pol), "%s/policy.conf", g_base);
	fp = fopen(pol, "w");
	if (!fp) {
		perror("policy.conf");
		return 2;
	}
	fprintf(fp, "[root]\nmode = privileged\n[default]\nmode = privileged\n");
	fclose(fp);
	setenv("AIKERNEL_POLICY", pol, 1);
	ai_policy_init(NULL);
	ai_trace_init(NULL, 0);

	if (tool_registry_load(&g_reg, &err) != 0) {
		printf("FATAL: tool_registry_load: %s\n", err ? err : "?");
		free(err);
		return 2;
	}

	printf("== test_lease_gate (uid=%u) ==\n", (unsigned)getuid());
	test_legacy();
	test_none_confirm();
	test_d4_phrase();
	test_ephemeral();
	test_d3_write_forms();
	test_d4_nonroot_gate();
	test_explicit();
	test_audit_trace_protect();
	test_trace_sticky();
	test_live_revocation();
	test_worker_plan();
	test_protected_writes();
	test_trace_audit();

	tool_registry_free(&g_reg);
	ai_trace_shutdown();
	ai_lease_ctx_reset();

	/* 证据保留：W74_EVIDENCE_DIR=/path 时复制 trace/audit 再清理 */
	{
		const char *keep = getenv("W74_EVIDENCE_DIR");

		if (keep && keep[0]) {
			char cmd[8192];

			snprintf(cmd, sizeof(cmd),
				 "mkdir -p '%s' && cp -a '%s/.' '%s/trace/' "
				 "2>/dev/null; cp -a '%s/.aikernel/audit.log' "
				 "'%s/audit.log' 2>/dev/null",
				 keep, g_trace, keep, g_home, keep);
			if (system(cmd) != 0)
				fprintf(stderr, "evidence copy failed\n");
		}
	}

	snprintf(cfile, sizeof(cfile), "rm -rf '%s'", g_base);
	rc = system(cfile);
	if (rc != 0)
		fprintf(stderr, "cleanup failed\n");

	printf("== test_lease_gate: %d PASS, %d FAIL ==\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}
