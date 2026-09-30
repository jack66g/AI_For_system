// SPDX-License-Identifier: GPL-2.0
/*
 * ai_user_policy.c - AIKernel 用户权限分级策略实现（P2）
 *
 * 职责（与 executor/registry 解耦，只依赖 libc）：
 *   1. 解析 /etc/aikernel/policy.conf（INI 风格，AIKERNEL_POLICY 可覆盖）；
 *   2. getuid + 本地 /etc/passwd、/etc/group 解析判定 uid 档位
 *      （root / sudo 组 / 其他；不经 NSS——静态链接下 getpwuid/
 *      getgrouplist 会 dlopen libnss_*.so 并 SIGSEGV）；
 *   3. ai_policy_check(uid, risk) → ALLOW_AUTO / NEED_CONFIRM / DENY；
 *   4. 工具调用审计（~/.aikernel/audit.log，flock 防交错）；
 *   5. W2 二次确认交互（红色 ANSI 影响面 + y/N）。
 * 兜底原则：任何异常（文件缺失/字段非法/内存不足）一律按 restricted 处理。
 *
 * 自测：gcc -DAI_POLICY_SELFTEST -o policy_test ai_user_policy.c && ./policy_test
 *   （覆盖三 mode 判定、配置解析、兜底、审计落盘，见文件尾 main）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "policy/ai_user_policy.h"

/* ---- 模块内状态 ---- */

#define AI_POLICY_DEFAULT_CONF "/etc/aikernel/policy.conf"
#define AI_POLICY_GROUP_DEFAULT "wheel"	/* sudo 组缺省名（Ubuntu 覆写为 sudo） */

static char g_conf_path[512];		/* 实际加载的配置路径 */
static char g_group[64];		/* sudo 组名（[wheel] group= 键） */
static enum ai_policy_mode g_modes[AI_POLICY_MODE__COUNT] = {
	AI_POLICY_MODE_RESTRICTED,	/* [root]     缺省 restricted 兜底 */
	AI_POLICY_MODE_RESTRICTED,	/* [wheel]    缺省 restricted 兜底 */
	AI_POLICY_MODE_RESTRICTED,	/* [default]  缺省 restricted 兜底 */
};

/* ---- 小工具 ---- */

/* 去除行首尾空白（原地截断） */
static char *str_trim(char *s)
{
	char *end;

	while (*s && isspace((unsigned char)*s))
		s++;
	end = s + strlen(s);
	while (end > s && isspace((unsigned char)end[-1]))
		*--end = '\0';
	return s;
}

/* mode 字符串 → 枚举；非法返回 restricted（兜底） */
static enum ai_policy_mode mode_from_str(const char *s)
{
	if (!strcmp(s, "privileged"))
		return AI_POLICY_MODE_PRIVILEGED;
	if (!strcmp(s, "confirmed"))
		return AI_POLICY_MODE_CONFIRMED;
	if (!strcmp(s, "restricted"))
		return AI_POLICY_MODE_RESTRICTED;
	return AI_POLICY_MODE_RESTRICTED;
}

const char *ai_policy_mode_name(enum ai_policy_mode m)
{
	switch (m) {
	case AI_POLICY_MODE_PRIVILEGED:
		return "privileged";
	case AI_POLICY_MODE_CONFIRMED:
		return "confirmed";
	case AI_POLICY_MODE_RESTRICTED:
		return "restricted";
	default:
		return "?";
	}
}

const char *ai_policy_verdict_name(enum ai_policy_verdict v)
{
	switch (v) {
	case AI_POLICY_ALLOW_AUTO:
		return "ALLOW_AUTO";
	case AI_POLICY_NEED_CONFIRM:
		return "NEED_CONFIRM";
	case AI_POLICY_DENY:
		return "DENY";
	default:
		return "?";
	}
}

const char *ai_policy_conf_path(void)
{
	return g_conf_path[0] ? g_conf_path : AI_POLICY_DEFAULT_CONF;
}

/* ---- 配置解析 ---- */

/*
 * 解析 INI：仅认识 [section] 头与 key = value；# / ; 注释、空行忽略。
 * 认识的键：mode（三段各一）、group（仅 [wheel] 段）。
 * 未知键静默忽略（向前兼容）；非法 mode 值回落 restricted。
 */
static int parse_conf(FILE *fp)
{
	char line[512];
	char section[64] = "";
	int lineno = 0;

	while (fgets(line, sizeof(line), fp)) {
		char *s = line;

		lineno++;
		s = str_trim(s);
		if (!s[0] || s[0] == '#' || s[0] == ';')
			continue;

		if (s[0] == '[') {
			char *end = strchr(s, ']');

			if (!end) {
				fprintf(stderr,
					"ai_policy: %s:%d 段头缺少 ']'，忽略\n",
					g_conf_path, lineno);
				continue;
			}
			*end = '\0';
			snprintf(section, sizeof(section), "%s",
				 str_trim(s + 1));
			continue;
		}

		{
			char *eq = strchr(s, '=');

			if (!eq) {
				fprintf(stderr,
					"ai_policy: %s:%d 缺少 '='，忽略\n",
					g_conf_path, lineno);
				continue;
			}
			*eq = '\0';
			{
				char *key = str_trim(s);
				char *val = str_trim(eq + 1);
				/* 行内注释剥离：值中第一个 '#' 起视为
				 * 注释（行内注释曾致 mode 解析失败） */
				{
					char *hash = strchr(val, '#');

					if (hash)
						*hash = '\0';
					val = str_trim(val);
				}

				if (!strcmp(section, "root")) {
					if (!strcmp(key, "mode"))
						g_modes[AI_POLICY_MODE_PRIVILEGED] =
							mode_from_str(val);
				} else if (!strcmp(section, "wheel")) {
					if (!strcmp(key, "mode"))
						g_modes[AI_POLICY_MODE_CONFIRMED] =
							mode_from_str(val);
					else if (!strcmp(key, "group"))
						snprintf(g_group,
							 sizeof(g_group),
							 "%s", val);
				} else if (!strcmp(section, "default")) {
					if (!strcmp(key, "mode"))
						g_modes[AI_POLICY_MODE_RESTRICTED] =
							mode_from_str(val);
				}
				/* 其他 section/键：忽略（向前兼容） */
			}
		}
	}
	return 0;
}

int ai_policy_init(const char *conf_path)
{
	const char *path = conf_path;
	FILE *fp;

	if (!path)
		path = getenv("AIKERNEL_POLICY");
	if (!path || !path[0])
		path = AI_POLICY_DEFAULT_CONF;

	/* 先复位为兜底值（重复调用 init 时旧值不残留） */
	for (int i = 0; i < AI_POLICY_MODE__COUNT; i++)
		g_modes[i] = AI_POLICY_MODE_RESTRICTED;
	snprintf(g_group, sizeof(g_group), "%s", AI_POLICY_GROUP_DEFAULT);
	g_conf_path[0] = '\0';

	fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "ai_policy: 配置 %s 不可读（%s），"
			"回落 restricted 兜底\n", path, strerror(errno));
		return 1;
	}
	snprintf(g_conf_path, sizeof(g_conf_path), "%s", path);
	parse_conf(fp);
	fclose(fp);
	return 0;
}

/* ---- uid 档位与判定 ---- */

/*
 * 本地 passwd/group 文件查询（静态链接安全）：
 * 静态链接 glibc 的 getpwuid/getgrouplist/getgrgid 运行时会 dlopen
 * 系统 libnss_*.so（如 libnss_systemd.so.2），其内部依赖动态 glibc
 * 的状态，与静态链接程序混用实测 SIGSEGV（复现：ask → 工具闸门 →
 * getgrouplist → libnss_systemd 崩溃）。AIKernel 部署形态（开发机/
 * VM/guest rootfs）的用户与组均来自本地文件，直接解析 /etc/passwd
 * 与 /etc/group，零 NSS 依赖。
 */

struct ai_pw_ent {
	char name[64];
	uid_t uid;
	gid_t gid;
	char dir[256];
};

/* /etc/passwd 行格式：name:passwd:uid:gid:gecos:home:shell */
static int local_passwd_get(uid_t uid, struct ai_pw_ent *out)
{
	FILE *fp;
	char line[1024];

	fp = fopen("/etc/passwd", "r");
	if (!fp)
		return 0;
	while (fgets(line, sizeof(line), fp)) {
		char name[64];
		unsigned int u, g;

		if (sscanf(line, "%63[^:]:%*[^:]:%u:%u", name, &u, &g) != 3)
			continue;
		if ((uid_t)u != uid)
			continue;
		fclose(fp);
		memset(out, 0, sizeof(*out));
		snprintf(out->name, sizeof(out->name), "%s", name);
		out->uid = (uid_t)u;
		out->gid = (gid_t)g;
		/* home 字段（第 6 列）尽力提取 */
		{
			const char *p = line;
			int i;

			for (i = 0; i < 5 && p; i++)
				p = strchr(p + 1, ':');
			if (p) {
				const char *q = strchr(p + 1, ':');
				size_t n = q ? (size_t)(q - p - 1) :
					   strlen(p + 1);

				if (n >= sizeof(out->dir))
					n = sizeof(out->dir) - 1;
				memcpy(out->dir, p + 1, n);
				out->dir[n] = '\0';
			}
		}
		return 1;
	}
	fclose(fp);
	return 0;
}

/* gid → 组名（/etc/group 反查；主程序不用，AI_POLICY_SELFTEST 自测用） */
__attribute__((unused))
static int local_group_name(gid_t gid, char *out, size_t cap)
{
	FILE *fp;
	char line[1024];

	fp = fopen("/etc/group", "r");
	if (!fp)
		return 0;
	while (fgets(line, sizeof(line), fp)) {
		char gname[64];
		unsigned int g;

		if (sscanf(line, "%63[^:]:%*[^:]:%u:", gname, &g) != 2)
			continue;
		if ((gid_t)g != gid)
			continue;
		fclose(fp);
		snprintf(out, cap, "%s", gname);
		return 1;
	}
	fclose(fp);
	return 0;
}

/*
 * uid 是否属于指定组名（含主组与 /etc/group 成员列表补充组；
 * 语义与原 getgrouplist+getgrgid 实现一致，但不经 NSS）
 */
static int uid_in_group(uid_t uid, const char *group)
{
	struct ai_pw_ent pw;
	FILE *fp;
	char line[2048];
	int found = 0;

	if (!group || !group[0])
		return 0;
	if (!local_passwd_get(uid, &pw))
		return 0;

	fp = fopen("/etc/group", "r");
	if (!fp)
		return 0;
	while (fgets(line, sizeof(line), fp) && !found) {
		char gname[64];
		unsigned int gid;
		char *p;
		int i;

		if (sscanf(line, "%63[^:]:%*[^:]:%u:", gname, &gid) != 2)
			continue;
		if (strcmp(gname, group) != 0)
			continue;
		/* 主组命中 */
		if ((gid_t)gid == pw.gid) {
			found = 1;
			break;
		}
		/* 补充组成员列表（第 4 列，逗号分隔）命中 */
		p = line;
		for (i = 0; i < 3 && p; i++)
			p = strchr(p + 1, ':');
		if (!p)
			continue;
		{
			char *tok = strtok(p + 1, ",\n");

			while (tok) {
				while (*tok == ' ' || *tok == '\t')
					tok++;
				if (!strcmp(tok, pw.name)) {
					found = 1;
					break;
				}
				tok = strtok(NULL, ",\n");
			}
		}
	}
	fclose(fp);
	return found;
}

enum ai_policy_mode ai_policy_mode_for_uid(uid_t uid)
{
	if (uid == 0)
		return g_modes[AI_POLICY_MODE_PRIVILEGED];
	if (uid_in_group(uid, g_group))
		return g_modes[AI_POLICY_MODE_CONFIRMED];
	return g_modes[AI_POLICY_MODE_RESTRICTED];
}

enum ai_policy_verdict ai_policy_check(uid_t uid, enum ai_tool_risk risk)
{
	switch (ai_policy_mode_for_uid(uid)) {
	case AI_POLICY_MODE_PRIVILEGED:
		/* root：W1 自动；W2 二次确认（影响面可见） */
		return risk == AI_RISK_W2 ? AI_POLICY_NEED_CONFIRM
					  : AI_POLICY_ALLOW_AUTO;
	case AI_POLICY_MODE_CONFIRMED:
	case AI_POLICY_MODE_RESTRICTED:
	default:
		/* 非 root 一律：W1 自动（exec 白名单由 executor 把关）；
		 * W2 拒绝（confirmed 提示 sudo，restricted 直接拒绝） */
		return risk == AI_RISK_W2 ? AI_POLICY_DENY
					  : AI_POLICY_ALLOW_AUTO;
	}
}

/* ---- 审计 ---- */

/* 审计参数净化：压成单行、限长（防日志注入/撑爆） */
static void sanitize(char *buf, size_t cap, const char *src)
{
	size_t j = 0;

	for (size_t i = 0; src && src[i] && j + 1 < cap; i++)
		buf[j++] = (src[i] == '\n' || src[i] == '\r') ?
			   ' ' : src[i];
	buf[j] = '\0';
}

int ai_policy_audit(uid_t uid, enum ai_policy_mode mode,
		    const char *tool, const char *args, const char *result)
{
	char path[600];
	char tstamp[40];
	char args_1l[256];
	char tool_1l[128];
	char result_1l[32];
	char line[1024];
	struct ai_pw_ent pw_ent;
	int have_pw;
	const char *home = getenv("HOME");
	int fd;
	int n;
	int rc = 0;
	time_t now = time(NULL);
	struct tm tmbuf;

	have_pw = local_passwd_get(uid, &pw_ent);

	if (!result || !result[0])
		result = "?";
	strftime(tstamp, sizeof(tstamp), "%Y-%m-%dT%H:%M:%S%z",
		 localtime_r(&now, &tmbuf));
	sanitize(tool_1l, sizeof(tool_1l), tool);
	sanitize(args_1l, sizeof(args_1l), args);
	sanitize(result_1l, sizeof(result_1l), result);

	/* 审计落盘到目标用户家目录：优先 HOME，其次 passwd */
	if (!home || !home[0])
		home = have_pw ? pw_ent.dir : NULL;
	if (!home || !home[0]) {
		fprintf(stderr, "ai_policy: 无家目录可写审计\n");
		return -1;
	}
	snprintf(path, sizeof(path), "%s/.aikernel", home);
	if (mkdir(path, 0700) != 0 && errno != EEXIST) {
		fprintf(stderr, "ai_policy: mkdir %s: %s\n",
			path, strerror(errno));
		return -1;
	}
	snprintf(path, sizeof(path), "%s/.aikernel/audit.log", home);

	fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd < 0) {
		fprintf(stderr, "ai_policy: open %s: %s\n",
			path, strerror(errno));
		return -1;
	}

	/* flock 防多进程写交错；单次 write 保证行原子 */
	if (flock(fd, LOCK_EX) != 0) {
		fprintf(stderr, "ai_policy: flock %s: %s\n",
			path, strerror(errno));
		/* 拿不到锁也继续写（O_APPEND 仍尽量原子） */
	}
	n = snprintf(line, sizeof(line),
		     "%s uid=%u user=%s mode=%s tool=%s args=%s result=%s\n",
		     tstamp, (unsigned)uid,
		     have_pw ? pw_ent.name : "?",
		     ai_policy_mode_name(mode),
		     tool_1l, args_1l, result_1l);
	if (n > 0 && write(fd, line, (size_t)n) != (ssize_t)n) {
		fprintf(stderr, "ai_policy: write 审计失败: %s\n",
			strerror(errno));
		rc = -1;
	}
	flock(fd, LOCK_UN);
	close(fd);
	return rc;
}

/* ---- W2 二次确认交互 ---- */

int ai_policy_confirm_interactive(const char *tool, const char *args,
				  const char *impact_desc)
{
	char answer[32];

	/* 无人值守（非 tty）不可确认：安全兜底拒绝 */
	if (!isatty(STDIN_FILENO)) {
		fprintf(stderr,
			"ai_policy: NEED_CONFIRM 但 stdin 非终端，拒绝\n");
		return 0;
	}

	/* 红色 ANSI：完整影响面（工具/参数/影响描述） */
	fprintf(stderr,
		"\033[1;31m[W2 高影响操作 需要确认]\033[0m\n"
		"\033[1;31m  工具: %s\033[0m\n"
		"\033[1;31m  参数: %s\033[0m\n"
		"\033[1;31m  影响: %s\033[0m\n",
		tool ? tool : "?", args && args[0] ? args : "{}",
		impact_desc && impact_desc[0] ? impact_desc : "(见工具描述)");
	fprintf(stderr, "确认执行? [y/N] ");
	fflush(stderr);

	if (!fgets(answer, sizeof(answer), stdin))
		return 0;
	/* 只认 y/yes（任意大小写），其余（含回车）一律不执行 */
	for (char *p = answer; *p; p++)
		*p = (char)tolower((unsigned char)*p);
	return !strcmp(str_trim(answer), "y") ||
	       !strcmp(str_trim(answer), "yes");
}

/* ---- 一站式闸门 ---- */

/*
 * 一站式闸门（带拦截原因，T2 问题 2）：
 *   - DENY → *result = POLICY_DENY（权限错误，沿用完整 policy 文案）；
 *   - NEED_CONFIRM 且用户按 n → *result = USER_REFUSED（用户自主拒绝，
 *     不得误报为权限不足——修复前两种路径同文案造成语义混淆）。
 * 审计行为与修复前完全等价（三种结果全量落盘）。
 */
int ai_policy_gate_reason(uid_t uid, const char *tool_name,
			  enum ai_tool_risk risk, const char *impact_desc,
			  const char *args_json,
			  enum ai_policy_gate_result *result)
{
	enum ai_policy_mode mode = ai_policy_mode_for_uid(uid);
	enum ai_policy_verdict v = ai_policy_check(uid, risk);

	if (result)
		*result = AI_GATE_ALLOW;

	switch (v) {
	case AI_POLICY_ALLOW_AUTO:
		ai_policy_audit(uid, mode, tool_name, args_json,
				ai_policy_verdict_name(v));
		return 1;
	case AI_POLICY_NEED_CONFIRM: {
		int ok = ai_policy_confirm_interactive(tool_name, args_json,
						       impact_desc);

		ai_policy_audit(uid, mode, tool_name, args_json,
				ok ? "CONFIRM=yes" : "CONFIRM=no");
		if (!ok && result)
			*result = AI_GATE_USER_REFUSED;
		return ok;
	}
	case AI_POLICY_DENY:
	default:
		if (result)
			*result = AI_GATE_POLICY_DENY;
		fprintf(stderr, "权限不足：该操作需要 root（sudo ai）\n");
		ai_policy_audit(uid, mode, tool_name, args_json,
				ai_policy_verdict_name(AI_POLICY_DENY));
		return 0;
	}
}

/*
 * ai_policy_gate - 兼容入口：转调 gate_reason（忽略原因出参）。
 */
int ai_policy_gate(uid_t uid, const char *tool_name, enum ai_tool_risk risk,
		   const char *impact_desc, const char *args_json)
{
	return ai_policy_gate_reason(uid, tool_name, risk, impact_desc,
				     args_json, NULL);
}


/* ---- 自测（mini test main） ---- */

#ifdef AI_POLICY_SELFTEST

static int g_fail;

static void expect(int cond, const char *what)
{
	printf("%s: %s\n", cond ? "PASS" : "FAIL", what);
	if (!cond)
		g_fail++;
}

/* 写临时配置并 init（走环境变量路径）。
 * 注：路径带 pid 且先 unlink——规避 fs.protected_regular 对 sticky
 * /tmp 下"他人已存在文件"的 O_CREAT 拦截（Ubuntu 默认开启）。 */
static void load_str(const char *conf)
{
	static char tmp[128];
	FILE *fp;

	snprintf(tmp, sizeof(tmp), "/tmp/aik-policy-test-%d.conf",
		 (int)getpid());
	unlink(tmp);
	fp = fopen(tmp, "w");
	if (!fp) {
		perror("fopen tmp conf");
		exit(2);
	}
	fputs(conf, fp);
	fclose(fp);
	setenv("AIKERNEL_POLICY", tmp, 1);
	ai_policy_init(NULL);
}

/* 当前用户主组名（自测用：保证"组成员"用例有真实组可命中） */
static const char *self_primary_group(void)
{
	struct ai_pw_ent pw;
	static char gname[64];

	if (!local_passwd_get(getuid(), &pw))
		return NULL;
	return local_group_name(pw.gid, gname, sizeof(gname)) ? gname : NULL;
}

int main(int argc, char **argv)
{
	/* sudo 运行时主组不再是用户组，允许外部指定被测 uid 与组名 */
	uid_t member_uid = argc > 1 ? (uid_t)strtoul(argv[1], NULL, 10)
				    : getuid();
	const char *grp = argc > 2 ? argv[2] : self_primary_group();

	printf("== ai_user_policy 自测（runner uid=%u 组=%s）==\n",
	       (unsigned)getuid(), grp ? grp : "?");

	/* 1. 完整配置：三段 mode + 注释 + 空白容错 */
	{
		char conf[512];

		snprintf(conf, sizeof(conf),
			 "# policy test\n"
			 "[root]\n"
			 "mode = privileged\n"
			 "[wheel]\n"
			 "mode = confirmed\n"
			 "group = %s\n"
			 "[default]\n"
			 "mode = restricted\n",
			 grp ? grp : "root");
		load_str(conf);
	}
	expect(ai_policy_init(NULL) == 0, "配置从 AIKERNEL_POLICY 加载成功");
	expect(strstr(ai_policy_conf_path(), "aik-policy-test") != NULL,
	       "conf_path 生效");

	expect(ai_policy_mode_for_uid(0) == AI_POLICY_MODE_PRIVILEGED,
	       "uid 0 → privileged");
	expect(ai_policy_mode_for_uid(member_uid) == AI_POLICY_MODE_CONFIRMED,
	       "组成员 → confirmed");
	expect(ai_policy_check(0, AI_RISK_W1) == AI_POLICY_ALLOW_AUTO,
	       "root W1 → ALLOW_AUTO");
	expect(ai_policy_check(0, AI_RISK_W2) == AI_POLICY_NEED_CONFIRM,
	       "root W2 → NEED_CONFIRM");
	expect(ai_policy_check(member_uid, AI_RISK_W1) == AI_POLICY_ALLOW_AUTO,
	       "wheel W1 → ALLOW_AUTO");
	expect(ai_policy_check(member_uid, AI_RISK_W2) == AI_POLICY_DENY,
	       "wheel W2 → DENY");

	/* 2. default 段：任取一个不属于该组的 uid（65534 nobody 通常不在） */
	expect(ai_policy_mode_for_uid(65534) == AI_POLICY_MODE_RESTRICTED,
	       "其他用户 → restricted");
	expect(ai_policy_check(65534, AI_RISK_W1) == AI_POLICY_ALLOW_AUTO,
	       "restricted W1 → ALLOW_AUTO（白名单由 executor 把关）");
	expect(ai_policy_check(65534, AI_RISK_W2) == AI_POLICY_DENY,
	       "restricted W2 → DENY");

	/* 3. 配置缺失 → 全量 restricted 兜底 */
	unlink("/tmp/aik-policy-test.conf");
	setenv("AIKERNEL_POLICY", "/tmp/aik-policy-nosuch.conf", 1);
	expect(ai_policy_init(NULL) == 1, "配置缺失 init 返回 1（已兜底）");
	expect(ai_policy_mode_for_uid(0) == AI_POLICY_MODE_RESTRICTED,
	       "兜底：root 也 restricted");
	expect(ai_policy_check(0, AI_RISK_W2) == AI_POLICY_DENY,
	       "兜底：root W2 → DENY");

	/* 4. 非法 mode 值 → 该段 restricted */
	load_str("[root]\nmode = whatever\n[default]\nmode = restricted\n");
	expect(ai_policy_mode_for_uid(0) == AI_POLICY_MODE_RESTRICTED,
	       "非法 mode → restricted 兜底");

	/* 5. 显式路径参数优先于环境变量 */
	{
		char p2[128];
		FILE *fp;

		snprintf(p2, sizeof(p2), "/tmp/aik-policy-root-%d.conf",
			 (int)getpid());
		unlink(p2);
		fp = fopen(p2, "w");
		if (fp) {
			fputs("[root]\nmode = privileged\n", fp);
			fclose(fp);
		}
		expect(ai_policy_init(p2) == 0, "显式路径优先");
		expect(ai_policy_mode_for_uid(0) == AI_POLICY_MODE_PRIVILEGED,
		       "显式路径内容生效");
		unlink(p2);
	}

	/* 6. 审计落盘 */
	{
		const char *home = getenv("HOME");
		char path[600];
		char buf[1024];
		FILE *fp;

		expect(ai_policy_audit(getuid(),
				       ai_policy_mode_for_uid(getuid()),
				       "selftest.tool", "{\"v\":1}",
				       "ALLOW_AUTO") == 0,
		       "审计写入成功");
		snprintf(path, sizeof(path), "%s/.aikernel/audit.log",
			 home ? home : "/tmp");
		fp = fopen(path, "r");
		expect(!!fp, "audit.log 存在");
		if (fp) {
			int ok = 0;

			/* 单行完整性：最后一条 selftest 行以 \n 结尾 */
			while (fgets(buf, sizeof(buf), fp))
				if (strstr(buf, "selftest.tool"))
					ok = buf[strlen(buf) - 1] == '\n';
			fclose(fp);
			expect(ok, "审计行完整（单行 \\n 结尾）");
		}
	}

	/* 7. 枚举名 */
	expect(!strcmp(ai_policy_mode_name(AI_POLICY_MODE_PRIVILEGED),
		       "privileged") &&
	       !strcmp(ai_policy_verdict_name(AI_POLICY_NEED_CONFIRM),
		       "NEED_CONFIRM"),
	       "枚举名输出");

	printf("== 自测结束：%s ==\n", g_fail ? "存在失败" : "全部通过");
	return g_fail ? 1 : 0;
}

#endif /* AI_POLICY_SELFTEST */
