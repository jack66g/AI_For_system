// SPDX-License-Identifier: GPL-2.0
/*
 * test_lease.c - W74 租约解析 / 存储安全 / scope / D0-D4 / 纯决策矩阵
 *
 * 不依赖网络/内核：全部在 mkdtemp 临时目录内完成；AIKERNEL_TRACE_ENABLED=0。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "policy/ai_lease.h"
#include "policy/ai_user_policy.h"
#include "ai_json_util.h"

static int g_fail;
static int g_pass;

static void expect(int cond, const char *what)
{
	printf("%s: %s\n", cond ? "PASS" : "FAIL", what);
	if (cond)
		g_pass++;
	else
		g_fail++;
}

static void skip(const char *what)
{
	printf("SKIP: %s\n", what);
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

static int username(uid_t uid, char *buf, size_t n)
{
	FILE *fp = fopen("/etc/passwd", "r");
	char line[1024];

	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		char name[128];
		unsigned int u;

		if (sscanf(line, "%127[^:]:%*[^:]:%u:", name, &u) == 2 &&
		    (uid_t)u == uid) {
			snprintf(buf, n, "%s", name);
			fclose(fp);
			return 0;
		}
	}
	fclose(fp);
	return -1;
}

static const char *valid_json =
	"{\n"
	"  \"lease_id\": \"L-20261021-0001\",\n"
	"  \"principal\": \"%s\",\n"
	"  \"subject\": \"root-ai\",\n"
	"  \"scope\": [\"sysadmin\", \"fs:/var:write\", \"netsec:read\"],\n"
	"  \"risk_ceiling\": \"D3\",\n"
	"  \"mission\": \"排查并修复 nginx 启动失败\",\n"
	"  \"issued_at\": \"2026-10-01T09:00:00+08:00\",\n"
	"  \"expires_at\": \"2030-10-21T23:00:00+08:00\",\n"
	"  \"revocable\": true,\n"
	"  \"audit\": \"session-id\",\n"
	"  \"revoked\": false\n"
	"}\n";

/* 原地替换首个 old（new 长度可不同；调用方保证缓冲足够） */
static void replace_inplace(char *s, const char *old, const char *new)
{
	char *p = strstr(s, old);
	size_t ol = strlen(old), nl = strlen(new);

	if (!p)
		return;
	memmove(p + nl, p + ol, strlen(p + ol) + 1);
	memcpy(p, new, nl);
}

static char *make_lease(const char *principal)
{
	size_t n = strlen(valid_json) + strlen(principal) + 64;
	char *s = malloc(n);

	if (!s)
		return NULL;
	snprintf(s, n, valid_json, principal);
	return s;
}

static void make_action(struct ai_lease_action *a, const char *domains,
			const char *target, enum ai_danger d,
			enum ai_tool_risk r, int is_exec)
{
	memset(a, 0, sizeof(*a));
	a->tool = "test_tool";
	a->domain = domains;
	a->target = target;
	a->args_json = "{}";
	a->risk_str = r == AI_RISK_W2 ? "W2" : "W1";
	a->risk = r;
	a->danger = d;
	a->is_exec = is_exec;
}

static void make_ctx(struct ai_lease_ctx *ctx, uid_t uid,
		     const char *principal, const char *scope,
		     enum ai_danger ceiling, long long expires)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->mode = AI_LEASE_MODE_EXPLICIT;
	ctx->loaded = 1;
	ctx->file_owner = uid;
	snprintf(ctx->lease.lease_id, sizeof(ctx->lease.lease_id),
		 "L-TEST-0001");
	snprintf(ctx->lease.principal, sizeof(ctx->lease.principal), "%s",
		 principal);
	{
		char copy[AI_LEASE_SCOPE_LEN * 2];
		char *p, *tok;

		snprintf(copy, sizeof(copy), "%s", scope);
		p = copy;
		while ((tok = strsep(&p, ",")) != NULL &&
		       ctx->lease.scope_count < AI_LEASE_SCOPE_MAX) {
			if (!tok[0])
				continue;
			snprintf(ctx->lease.scope[ctx->lease.scope_count],
				 sizeof(ctx->lease.scope[0]), "%s", tok);
			ctx->lease.scope_count++;
		}
	}
	ctx->lease.risk_ceiling = ceiling;
	ctx->lease.expires_at = expires;
	ctx->lease.issued_at = expires - 3600;
	ctx->lease.has_issued_at = 1;
	snprintf(ctx->source, sizeof(ctx->source), "test");
}

static void test_parse(const char *me)
{
	struct ai_lease l;
	char err[AI_LEASE_ERR_MAX];
	char *json;
	long long now = 1795000000;	/* 2026-11-16，晚于 issued_at */

	json = make_lease(me);
	memset(&l, 0, sizeof(l));
	err[0] = '\0';
	expect(ai_lease_parse(json, strlen(json), now, &l, err,
			      sizeof(err)) == 0 &&
	       l.scope_count == 3 && l.risk_ceiling == AI_D3 &&
	       l.expires_at > now && strcmp(l.lease_id,
					    "L-20261021-0001") == 0,
	       "parse: 合法租约（3 scope/D3/带时区）");
	free(json);

	json = make_lease(me);
	replace_inplace(json,
		"  \"mission\": \"排查并修复 nginx 启动失败\",\n", "");
	expect(ai_lease_parse(json, strlen(json), now, &l, err,
			      sizeof(err)) != 0,
	       "parse: 缺 mission 拒绝");
	free(json);

	json = make_lease(me);
	replace_inplace(json, "\"risk_ceiling\": \"D3\"",
			"\"risk_ceiling\": \"D9\"");
	expect(ai_lease_parse(json, strlen(json), now, &l, err,
			      sizeof(err)) != 0,
	       "parse: 非法 risk_ceiling 拒绝");
	free(json);

	json = make_lease(me);
	replace_inplace(json, "2030-10-21T23:00:00+08:00",
			"2030-10-21T23:00:00");
	expect(ai_lease_parse(json, strlen(json), now, &l, err,
			      sizeof(err)) != 0,
	       "parse: expires_at 无时区拒绝");
	free(json);

	json = make_lease(me);
	replace_inplace(json, "2026-10-01T09:00:00+08:00",
			"2031-10-21T09:00:00+08:00");
	expect(ai_lease_parse(json, strlen(json), now, &l, err,
			      sizeof(err)) != 0,
	       "parse: issued_at 在未来（>60s）拒绝");
	free(json);

	json = make_lease(me);
	replace_inplace(json,
		"[\"sysadmin\", \"fs:/var:write\", \"netsec:read\"]", "[]");
	expect(ai_lease_parse(json, strlen(json), now, &l, err,
			      sizeof(err)) != 0,
	       "parse: scope 数组为空拒绝");
	free(json);

	json = make_lease(me);
	replace_inplace(json, "\"revocable\": true,",
			"\"revocable\": true,\n"
			"  \"unknown_field\": {\"x\": [1,2,3]},");
	expect(ai_lease_parse(json, strlen(json), now, &l, err,
			      sizeof(err)) == 0,
	       "parse: 未知字段忽略（向前兼容）");
	free(json);

	{
		long long t1, t2;

		expect(ai_lease_parse_time("2026-10-21T09:00:00+08:00", &t1) == 0
		       && ai_lease_parse_time("2026-10-21T01:00:00Z", &t2) == 0
		       && t1 == t2,
		       "time: +08:00 与 Z 表示同一时刻");
		expect(ai_lease_parse_time("2026-10-21T09:00:00", &t1) != 0,
		       "time: 无时区拒绝");
	}
}

static void test_ids(void)
{
	expect(ai_lease_id_valid("L-20261021-0001"), "id: 合法");
	expect(!ai_lease_id_valid("../etc/passwd"), "id: ../ 拒绝");
	expect(!ai_lease_id_valid("/etc/passwd"), "id: 绝对路径拒绝");
	expect(!ai_lease_id_valid(".."), "id: .. 拒绝");
	expect(!ai_lease_id_valid(""), "id: 空拒绝");
	expect(!ai_lease_id_valid("a/b"), "id: 含 / 拒绝");
	{
		char ctl[8] = "ab\ncd";

		expect(!ai_lease_id_valid(ctl), "id: 控制字符拒绝");
	}
	{
		char big[80];

		memset(big, 'a', sizeof(big));
		big[sizeof(big) - 1] = '\0';
		expect(!ai_lease_id_valid(big), "id: 超长拒绝");
	}
}

static enum ai_danger cls(const char *tool, const char *risk,
			  const char *args)
{
	char *target = NULL;
	const char *why = NULL;
	enum ai_danger d = ai_danger_classify(tool, "sysadmin", risk, args,
					      &target, &why);

	free(target);
	return d;
}

static void test_danger_rules(void)
{
	expect(cls("exec_run", "W2",
		   "{\"command\":\"date\",\"args\":[\"-s\",\"2026-01-01\"]}")
	       == AI_D3, "danger: date -s → D3");
	expect(cls("exec_run", "W2",
		   "{\"command\":\"date\",\"args\":[\"--set=2026-01-01\"]}")
	       == AI_D3, "danger: date --set= → D3");
	expect(cls("exec_run", "W2",
		   "{\"command\":\"date\",\"args\":[\"202601010000\"]}")
	       == AI_D3, "danger: date 位置参数 → D3");
	expect(cls("exec_run", "R",
		   "{\"command\":\"date\",\"args\":[\"+%s\"]}") == AI_D0,
	       "danger: date +format 只读 → D0");
	expect(cls("exec_run", "R",
		   "{\"command\":\"date\",\"args\":[\"-d\",\"2026-01-01\"]}")
	       == AI_D0, "danger: date -d 只读 → D0");

	expect(cls("exec_run", "R",
		   "{\"command\":\"hostname\",\"args\":[]}") == AI_D0,
	       "danger: hostname 无参只读 → D0");
	expect(cls("exec_run", "R",
		   "{\"command\":\"hostname\",\"args\":[\"-f\"]}") == AI_D0,
	       "danger: hostname -f 只读 → D0");
	expect(cls("exec_run", "W2",
		   "{\"command\":\"hostname\",\"args\":[\"-F\",\"/tmp/x\"]}")
	       == AI_D3, "danger: hostname -F → D3");
	expect(cls("exec_run", "W2",
		   "{\"command\":\"hostname\",\"args\":[\"newname\"]}")
	       == AI_D3, "danger: hostname 位置参数 → D3");

	expect(cls("exec_run", "R",
		   "{\"command\":\"dmesg\",\"args\":[]}") == AI_D0,
	       "danger: dmesg 只读 → D0");
	expect(cls("exec_run", "W2",
		   "{\"command\":\"dmesg\",\"args\":[\"-c\"]}") == AI_D3,
	       "danger: dmesg -c → D3");
	expect(cls("exec_run", "W2",
		   "{\"command\":\"dmesg\",\"args\":[\"-n\",\"3\"]}") == AI_D3,
	       "danger: dmesg -n → D3");

	expect(cls("exec_run", "R",
		   "{\"command\":\"smartctl\",\"args\":[\"-a\",\"/dev/sda\"]}")
	       == AI_D0, "danger: smartctl -a 只读 → D0");
	expect(cls("exec_run", "W2",
		   "{\"command\":\"smartctl\",\"args\":[\"-t\",\"short\",\"/dev/sda\"]}")
	       == AI_D3, "danger: smartctl -t → D3");
	expect(cls("exec_run", "W2",
		   "{\"command\":\"smartctl\",\"args\":[\"-s\",\"on\",\"/dev/sda\"]}")
	       == AI_D3, "danger: smartctl -s → D3");

	expect(cls("exec_run", "R",
		   "{\"command\":\"ss\",\"args\":[\"-tlnp\"]}") == AI_D0,
	       "danger: ss 只读 → D0");
	expect(cls("exec_run", "W2",
		   "{\"command\":\"ss\",\"args\":[\"-K\"]}") == AI_D3,
	       "danger: ss -K → D3");
	expect(cls("exec_run", "W2",
		   "{\"command\":\"ss\",\"args\":[\"-K\",\"dst\",\"1.2.3.4\"]}")
	       == AI_D3, "danger: ss -K dst → D3");

	/* effective risk=R 但工具名/命令命中 D3/D4 仍必须升级 */
	expect(cls("netlink_act_sec_seccomp", "R", "{}") == AI_D4,
	       "danger: synthetic R + netlink_act_sec_seccomp → D4");
	expect(cls("exec_run", "R",
		   "{\"command\":\"systemctl\",\"args\":[\"status\",\"nginx\"]}")
	       == AI_D0, "danger: systemctl status + R → D0");
	expect(cls("exec_run", "R",
		   "{\"command\":\"systemctl\",\"args\":[\"restart\",\"nginx\"]}")
	       == AI_D3, "danger: systemctl restart + R → D3");

	/* SSH 私钥/认证配置 */
	expect(cls("exec_run", "W1",
		   "{\"command\":\"tee\",\"args\":[\"/root/.ssh/id_ed25519\"]}")
	       == AI_D4, "danger: tee SSH 私钥 → D4");
	expect(cls("exec_run", "W1",
		   "{\"command\":\"tee\",\"args\":[\"/etc/pam.d/x\"]}")
	       == AI_D4, "danger: tee /etc/pam.d → D4");
	expect(cls("exec_run", "W1",
		   "{\"command\":\"tee\",\"args\":[\"/etc/ssh/sshd_config\"]}")
	       == AI_D4, "danger: tee sshd_config → D4");
	expect(cls("exec_run", "W1",
		   "{\"command\":\"tee\",\"args\":[\"/root/.ssh/known_hosts\"]}")
	       != AI_D4, "danger: known_hosts 不升 D4");
	expect(cls("exec_run", "R",
		   "{\"command\":\"cat\",\"args\":[\"/root/.ssh/id_ed25519\"]}")
	       == AI_D0, "danger: 读 SSH 私钥仍 D0（全知）");
}

static void test_d4_nonroot(void)
{
	struct ai_lease_ctx ctx;
	struct ai_lease_action a;
	struct ai_lease_verdict v;
	long long now = (long long)time(NULL);

	if (getuid() == 0) {
		skip("decision: D4 + 非 root（当前即 root）");
		return;
	}
	memset(&ctx, 0, sizeof(ctx));
	ctx.mode = AI_LEASE_MODE_NONE;
	make_action(&a, "sysadmin", NULL, AI_D4, AI_RISK_W1, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_DENY
	       && strcmp(v.reason, "d4_requires_root") == 0,
	       "decision: D4 + 非 root → d4_requires_root");
}

static void test_io(const char *base, const char *me)
{
	char dir[512], path[640], err[AI_LEASE_ERR_MAX];
	struct ai_lease l;
	uid_t owner = 0;
	long long now = (long long)time(NULL);
	char *json;

	snprintf(dir, sizeof(dir), "%s/store", base);
	mkdir(dir, 0700);
	setenv("AIKERNEL_LEASE_DIR", dir, 1);
	json = make_lease(me);
	snprintf(path, sizeof(path), "%s/L-20261021-0001.json", dir);
	write_mode(path, json, 0600);
	err[0] = '\0';
	expect(ai_lease_load(dir, "L-20261021-0001", getuid(), now, &l,
			     &owner, err, sizeof(err)) == 0 &&
	       owner == getuid(),
	       "io: 0600/属主正确加载成功");

	chmod(path, 0644);
	expect(ai_lease_load(dir, "L-20261021-0001", getuid(), now, &l,
			     &owner, err, sizeof(err)) != 0,
	       "io: 文件 0644 拒绝");
	chmod(path, 0600);

	{
		char linkp[640];

		snprintf(linkp, sizeof(linkp), "%s/L-link.json", dir);
		unlink(linkp);
		if (symlink(path, linkp) == 0) {
			expect(ai_lease_load(dir, "L-link", getuid(), now, &l,
					     &owner, err,
					     sizeof(err)) != 0,
			       "io: 符号链接租约文件拒绝");
			unlink(linkp);
		}
	}

	chmod(dir, 0755);
	expect(ai_lease_load(dir, "L-20261021-0001", getuid(), now, &l,
			     &owner, err, sizeof(err)) != 0,
	       "io: 目录 0755 拒绝");
	chmod(dir, 0700);

	{
		char marker[640];

		snprintf(marker, sizeof(marker), "%s/L-20261021-0001.revoked",
			 dir);
		write_mode(marker, "{\"revoked\":true}\n", 0600);
		expect(ai_lease_load(dir, "L-20261021-0001", getuid(), now, &l,
				     &owner, err, sizeof(err)) != 0,
		       "io: .revoked 标记优先拒绝");
		unlink(marker);
	}

	/* 过期 */
	{
		char exp[640];

		snprintf(exp, sizeof(exp), "%s/L-expired.json", dir);
		json = make_lease(me);
		{
			char *p = strstr(json, "2030-10-21T23:00:00+08:00");

			if (p)
				memcpy(p, "2020-10-21T23:00:00+08:00", 25);
		}
		write_mode(exp, json, 0600);
		free(json);
		json = NULL;
		expect(ai_lease_load(dir, "L-expired", getuid(), now, &l,
				     &owner, err, sizeof(err)) != 0,
		       "io: 过期租约拒绝");
	}

	/* root principal + 非 root uid（跨用户） */
	{
		char rp[640];
		char *rootjson = make_lease("root");

		snprintf(rp, sizeof(rp), "%s/L-root.json", dir);
		write_mode(rp, rootjson, 0600);
		free(rootjson);
		if (getuid() != 0)
			expect(ai_lease_load(dir, "L-root", getuid(), now, &l,
					     &owner, err,
					     sizeof(err)) != 0,
			       "io: root 租约 + 非 root uid 拒绝");
		else
			skip("io: root principal 非 0 uid（当前即 root）");
	}

	/* 属主错误：仅在 root 下可安全 chown */
	if (getuid() == 0) {
		if (chown(path, 65534, 65534) != 0)
			fprintf(stderr, "chown 65534 failed: %s\n",
				strerror(errno));
		expect(ai_lease_load(dir, "L-20261021-0001", getuid(), now, &l,
				     &owner, err, sizeof(err)) != 0,
		       "io: 文件属主错误拒绝");
		if (chown(path, 0, 0) != 0)
			fprintf(stderr, "chown 0 failed: %s\n",
				strerror(errno));
	} else {
		skip("io: 文件属主错误（非 root 无法 chown；实现按 st_uid 校验）");
	}

	free(json);
}

static void test_issue_revoke(const char *base, const char *me)
{
	char dir[512], err[AI_LEASE_ERR_MAX], id[AI_LEASE_ID_MAX];
	char path[640];
	struct ai_lease l;
	uid_t owner = 0;

	snprintf(dir, sizeof(dir), "%s/issue", base);
	setenv("AIKERNEL_LEASE_DIR", dir, 1);
	err[0] = '\0';
	id[0] = '\0';
	expect(ai_lease_issue("fs:/tmp:write,sysadmin", "D2", "w74 selftest",
			      600, getuid(), id, sizeof(id), path,
			      sizeof(path), err, sizeof(err)) == 0 &&
	       ai_lease_id_valid(id),
	       "issue: 生成合法租约并原子落盘");
	expect(ai_lease_load(dir, id, getuid(), (long long)time(NULL), &l,
			     &owner, err, sizeof(err)) == 0 &&
	       l.risk_ceiling == AI_D2 && l.scope_count == 2,
	       "issue: 落盘后可加载且字段一致");
	expect(ai_lease_revoke(id, getuid(), err, sizeof(err)) == 0,
	       "revoke: 写撤销标记");
	expect(ai_lease_load(dir, id, getuid(), (long long)time(NULL), &l,
			     &owner, err, sizeof(err)) != 0,
	       "revoke: 撤销后拒绝加载");
	(void)me;
}

static void test_scope_decide(const char *me)
{
	struct ai_lease_ctx ctx;
	struct ai_lease_action a;
	struct ai_lease_verdict v;
	long long now = (long long)time(NULL);
	long long exp = now + 3600;

	/* 精确域 / 路径边界 / write 覆盖 exec */
	make_ctx(&ctx, getuid(), me, "fs:/var:write", AI_D3, exp);
	make_action(&a, "fs,sysadmin", "/var/log/nginx/error.log", AI_D2,
		    AI_RISK_W2, 1);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_ALLOW
	       && strcmp(v.reason, "lease_allow") == 0,
	       "scope: fs:/var:write 覆盖 /var/log（边界前缀）+ 多域命中");

	make_action(&a, "fs", "/various/x", AI_D2, AI_RISK_W2, 1);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_DENY
	       && strcmp(v.reason, "lease_scope_denied") == 0,
	       "scope: /var 不匹配 /various（边界前缀）");

	make_action(&a, "netsec", "/etc/x", AI_D1, AI_RISK_W1, 0);
	make_ctx(&ctx, getuid(), me, "netsec:read", AI_D3, exp);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_DENY,
	       "scope: access=read 只允许 D0（D1 拒绝）");

	make_ctx(&ctx, getuid(), me, "netsec:read", AI_D3, exp);
	make_action(&a, "netsec", NULL, AI_D0, AI_RISK_W1, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_ALLOW,
	       "scope: access=read 允许 D0");

	/* ceiling */
	make_ctx(&ctx, getuid(), me, "sysadmin", AI_D2, exp);
	make_action(&a, "sysadmin", NULL, AI_D3, AI_RISK_W2, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_DENY
	       && strcmp(v.reason, "lease_ceiling_denied") == 0,
	       "ceiling: D2 租约遇到 D3 拒绝");

	/* D4 永不由租约自动放行：D3 ceiling → CONFIRM_D4（新口径）。
	 * D4 只能由 root 确认，纯函数测试用 uid 0 + root principal。 */
	make_ctx(&ctx, 0, "root", "netsec,sysadmin", AI_D3, exp);
	ctx.file_owner = 0;
	make_action(&a, "netsec", NULL, AI_D4, AI_RISK_W2, 0);
	expect(ai_lease_decide(&ctx, 0, &a, now, &v) ==
	       AI_LEASE_CONFIRM_D4,
	       "ceiling: D3 租约遇到 D4 只升级人工 D4（不自动放行）");

	/* 撤销优先 */
	make_ctx(&ctx, getuid(), me, "sysadmin", AI_D3, exp);
	ctx.lease.revoked = 1;
	make_action(&a, "sysadmin", NULL, AI_D2, AI_RISK_W2, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_DENY
	       && strcmp(v.reason, "lease_revoked") == 0,
	       "decision: revoked D2 拒绝");
	make_action(&a, "sysadmin", NULL, AI_D0, AI_RISK_W1, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_ALLOW,
	       "decision: revoked 不阻断 D0 读");

	/* 过期 */
	make_ctx(&ctx, getuid(), me, "sysadmin", AI_D3, now - 1);
	make_action(&a, "sysadmin", NULL, AI_D1, AI_RISK_W1, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_DENY
	       && strcmp(v.reason, "lease_expired") == 0,
	       "decision: 过期 D1 拒绝");
	make_action(&a, "sysadmin", NULL, AI_D0, AI_RISK_W1, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_ALLOW,
	       "decision: 过期不阻断 D0 读");

	/* 跨用户 principal */
	make_ctx(&ctx, getuid(), "someone-else", "sysadmin", AI_D3, exp);
	make_action(&a, "sysadmin", NULL, AI_D2, AI_RISK_W2, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_DENY
	       && strcmp(v.reason, "lease_principal_mismatch") == 0,
	       "decision: 跨用户 principal 拒绝");

	/* plan 优先 */
	make_ctx(&ctx, getuid(), me, "sysadmin", AI_D3, exp);
	make_action(&a, "sysadmin", NULL, AI_D1, AI_RISK_W1, 0);
	a.plan_mode = 1;
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_DENY
	       && strcmp(v.reason, "plan_read_only") == 0,
	       "decision: plan 拒绝 D1（租约不能绕过）");
	make_action(&a, "sysadmin", NULL, AI_D0, AI_RISK_W1, 0);
	a.plan_mode = 1;
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_ALLOW,
	       "decision: plan 允许 D0");

	/* worker */
	make_ctx(&ctx, getuid(), me, "sandbox", AI_D3, exp);
	make_action(&a, "sandbox", NULL, AI_D2, AI_RISK_W2, 1);
	a.worker = 1;
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_DENY
	       && strcmp(v.reason, "sandbox_child_d2") == 0,
	       "decision: worker + 父租约 D2 仍拒绝");
	make_action(&a, "sandbox", NULL, AI_D1, AI_RISK_W1, 1);
	a.worker = 1;
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_ALLOW,
	       "decision: worker D1 放行");
}

static void test_decision_matrix(const char *me)
{
	struct ai_lease_ctx ctx;
	struct ai_lease_action a;
	struct ai_lease_verdict v;
	long long now = (long long)time(NULL);
	long long exp = now + 3600;
	enum ai_danger d;

	/* NONE */
	memset(&ctx, 0, sizeof(ctx));
	ctx.mode = AI_LEASE_MODE_NONE;
	for (d = AI_D0; d <= AI_D4; d++) {
		enum ai_lease_decision want;

		if (d == AI_D0 || d == AI_D1)
			want = AI_LEASE_ALLOW;
		else if (d == AI_D4)
			want = AI_LEASE_CONFIRM_D4;
		else
			want = AI_LEASE_CONFIRM;
		make_action(&a, "sysadmin", NULL, d,
			    d >= AI_D2 ? AI_RISK_W2 : AI_RISK_W1, 0);
		/* D4 只能由 root 确认；矩阵用 uid 0 模拟 root AI 进程 */
		expect(ai_lease_decide(&ctx, d == AI_D4 ? 0 : getuid(), &a,
				       now, &v) == want,
		       d == AI_D0 ? "matrix NONE D0 ALLOW" :
		       d == AI_D1 ? "matrix NONE D1 ALLOW" :
		       d == AI_D2 ? "matrix NONE D2 CONFIRM" :
		       d == AI_D3 ? "matrix NONE D3 CONFIRM" :
				    "matrix NONE D4 CONFIRM_D4");
	}

	/* EPHEMERAL */
	memset(&ctx, 0, sizeof(ctx));
	ctx.mode = AI_LEASE_MODE_EPHEMERAL;
	ctx.loaded = 1;
	snprintf(ctx.lease.lease_id, sizeof(ctx.lease.lease_id),
		 "L-EPHEMERAL-test");
	snprintf(ctx.lease.scope[0], sizeof(ctx.lease.scope[0]), "*");
	ctx.lease.scope_count = 1;
	ctx.lease.risk_ceiling = AI_D2;
	ctx.lease.expires_at = exp;
	make_action(&a, "sysadmin", NULL, AI_D2, AI_RISK_W2, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_ALLOW
	       && strcmp(v.confirmation, "ephemeral") == 0,
	       "matrix EPHEMERAL D2 ALLOW（-y 短租约）");
	make_action(&a, "sysadmin", NULL, AI_D3, AI_RISK_W2, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) ==
	       AI_LEASE_CONFIRM,
	       "matrix EPHEMERAL D3 CONFIRM");
	make_action(&a, "sysadmin", NULL, AI_D4, AI_RISK_W2, 0);
	expect(ai_lease_decide(&ctx, 0, &a, now, &v) ==
	       AI_LEASE_CONFIRM_D4,
	       "matrix EPHEMERAL D4 CONFIRM_D4（root）");
	/* ephemeral 过期 → 回落 NONE 语义（D1 自动，D2/D3 确认，D4 强确认） */
	ctx.lease.expires_at = now - 1;
	make_action(&a, "sysadmin", NULL, AI_D0, AI_RISK_W1, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_ALLOW,
	       "matrix EPHEMERAL 过期 D0 ALLOW");
	make_action(&a, "sysadmin", NULL, AI_D1, AI_RISK_W1, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_ALLOW
	       && strcmp(v.reason, "ephemeral_expired") == 0,
	       "matrix EPHEMERAL 过期 D1 ALLOW（回落 NONE）");
	make_action(&a, "sysadmin", NULL, AI_D2, AI_RISK_W2, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) ==
	       AI_LEASE_CONFIRM && strcmp(v.reason, "ephemeral_expired") == 0,
	       "matrix EPHEMERAL 过期 D2 CONFIRM");
	make_action(&a, "sysadmin", NULL, AI_D3, AI_RISK_W2, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) ==
	       AI_LEASE_CONFIRM,
	       "matrix EPHEMERAL 过期 D3 CONFIRM");
	make_action(&a, "sysadmin", NULL, AI_D4, AI_RISK_W2, 0);
	expect(ai_lease_decide(&ctx, 0, &a, now, &v) ==
	       AI_LEASE_CONFIRM_D4,
	       "matrix EPHEMERAL 过期 D4 CONFIRM_D4（root）");

	/* EXPLICIT D3 */
	make_ctx(&ctx, getuid(), me, "sysadmin,netsec", AI_D3, exp);
	make_action(&a, "sysadmin", NULL, AI_D3, AI_RISK_W2, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_ALLOW,
	       "matrix EXPLICIT D3 lease + D3 ALLOW");
	make_action(&a, "sysadmin", NULL, AI_D2, AI_RISK_W2, 0);
	expect(ai_lease_decide(&ctx, getuid(), &a, now, &v) == AI_LEASE_ALLOW,
	       "matrix EXPLICIT D3 lease + D2 ALLOW");
}

static void test_protected(void)
{
	expect(ai_lease_path_protected("/var/lib/aikernel/leases/x"),
	       "protected: /var/lib/aikernel/**");
	expect(ai_lease_path_protected("/run/aikernel/confirm/pending/x"),
	       "protected: /run/aikernel/**");
	expect(!ai_lease_path_protected("/var/lib/aikernelx"),
	       "protected: 前缀边界（aikernelx 不保护）");
	expect(ai_lease_path_protected("../var/lib/aikernel/leases/x"),
	       "protected: 相对 + .. 按受保护处理");
}

int main(void)
{
	char base[] = "/tmp/w74leaseXXXXXX";
	char me[128] = "";
	char home[600], pol[600], cfile[700];
	FILE *fp;

	if (!mkdtemp(base)) {
		perror("mkdtemp");
		return 2;
	}
	if (username(getuid(), me, sizeof(me)) != 0)
		snprintf(me, sizeof(me), "uid%u", (unsigned)getuid());

	snprintf(home, sizeof(home), "%s/home", base);
	mkdir(home, 0700);
	setenv("HOME", home, 1);
	setenv("AIKERNEL_TRACE_ENABLED", "0", 1);

	snprintf(pol, sizeof(pol), "%s/policy.conf", base);
	fp = fopen(pol, "w");
	if (!fp) {
		perror("policy.conf");
		return 2;
	}
	fprintf(fp, "[root]\nmode = privileged\n[default]\nmode = privileged\n");
	fclose(fp);
	setenv("AIKERNEL_POLICY", pol, 1);
	ai_policy_init(NULL);

	printf("== test_lease (uid=%u user=%s) ==\n", (unsigned)getuid(), me);
	test_parse(me);
	test_ids();
	test_danger_rules();
	test_d4_nonroot();
	test_io(base, me);
	test_issue_revoke(base, me);
	test_scope_decide(me);
	test_decision_matrix(me);
	test_protected();

	/* 清理 */
	snprintf(cfile, sizeof(cfile), "rm -rf '%s'", base);
	if (system(cfile) != 0)
		fprintf(stderr, "cleanup failed: %s\n", cfile);

	printf("== test_lease: %d PASS, %d FAIL ==\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}
