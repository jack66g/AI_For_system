// SPDX-License-Identifier: GPL-2.0
/*
 * ai_user_policy.c - AIKernel 用户权限分级策略实现（P2）
 *
 * 职责（与 executor/registry 解耦，只依赖 libc）：
 *   1. 解析 /etc/aikernel/policy.conf（INI 风格，AIKERNEL_POLICY 可覆盖；
 *      P2 Phase B 起支持 [user:<name>] per-user 档位覆盖段）；
 *   2. getuid + 本地 /etc/passwd、/etc/group 解析判定 uid 档位
 *      （root / sudo 组 / 其他；不经 NSS——静态链接下 getpwuid/
 *      getgrouplist 会 dlopen libnss_*.so 并 SIGSEGV）；
 *   3. ai_policy_check(uid, risk) → ALLOW_AUTO / NEED_CONFIRM / DENY；
 *   4. 工具调用审计（~/.aikernel/audit.log，flock 防交错）；
 *   5. W2 二次确认交互（红色 ANSI 影响面 + y/N）。
 * 兜底原则：任何异常（文件缺失/字段非法/内存不足）一律按 restricted 处理。
 *
 * 自测（自 agent/ai 目录）：gcc -Wall -Wextra -std=c11 -DAI_POLICY_SELFTEST \
 *   -Iinclude -I. -o /tmp/policy_test policy/ai_user_policy.c \
 *   i18n/lang.c trace/ai_trace.c runtime/ai_json_util.c runtime/ai_types.c \
 *   && /tmp/policy_test
 *   （覆盖三 mode 判定、配置解析、per-user 覆盖、兜底、审计落盘，
 *   见文件尾 main；W48B 起 tr/ai_trace 依赖需一并链接）
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
#include <sys/select.h>
#include <sys/time.h>

#include "policy/ai_user_policy.h"
#include "ai_lang.h"
#include "ai_trace.h"   /* W48B：策略判定轨迹 */

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

/*
 * per-user 档位覆盖表（P2 Phase B：[user:<name>] 段，优先级最高）。
 *   - 条目由 ai_policy_init 解析时一次性载入（与 g_modes 同生命周期，
 *     重复 init 先复位再重载，旧值不残留）；
 *   - 上限 AI_POLICY_USER_OV_MAX：超出静默忽略（覆盖属管理面小集合，
 *     超限不炸、多余段不生效，保守无害）；
 *   - 未知用户名段（passwd 无此名）永不命中，天然无害。
 */
#define AI_POLICY_USER_OV_MAX 64
#define AI_POLICY_USER_NAME_MAX 64	/* 与 ai_pw_ent.name 同宽 */

struct ai_policy_user_ov {
	char name[AI_POLICY_USER_NAME_MAX];
	enum ai_policy_mode mode;
};

static struct ai_policy_user_ov g_user_ov[AI_POLICY_USER_OV_MAX];
static int g_user_ov_count;

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

/* per-user 覆盖表操作（P2 Phase B） */

/* 记录/更新一条 [user:<name>] 覆盖（同名段重复出现：后写胜出，
 * 与现有三段 mode= 重复行的后写语义一致） */
static void user_ov_set(const char *name, enum ai_policy_mode mode)
{
	int i;

	for (i = 0; i < g_user_ov_count; i++) {
		if (!strcmp(g_user_ov[i].name, name)) {
			g_user_ov[i].mode = mode;
			return;
		}
	}
	if (g_user_ov_count >= AI_POLICY_USER_OV_MAX)
		return;		/* 超限静默忽略（保守：多余覆盖不生效） */
	snprintf(g_user_ov[g_user_ov_count].name,
		 sizeof(g_user_ov[g_user_ov_count].name), "%s", name);
	g_user_ov[g_user_ov_count].mode = mode;
	g_user_ov_count++;
}

/* 按用户名精确查覆盖；NULL = 该用户无 [user:<name>] 段 */
static const struct ai_policy_user_ov *user_ov_find(const char *name)
{
	int i;

	for (i = 0; i < g_user_ov_count; i++)
		if (!strcmp(g_user_ov[i].name, name))
			return &g_user_ov[i];
	return NULL;
}

/*
 * 解析 INI：仅认识 [section] 头与 key = value；# / ; 注释、空行忽略。
 * 认识的键：mode（三段各一）、group（仅 [wheel] 段）、
 * mode（[user:<name>] per-user 覆盖段）。
 * 未知键/未知段名静默忽略（向前兼容）；非法 mode 值回落 restricted。
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
				fprintf(stderr, tr(TR_POLICY_CONF_NO_BRACKET),
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
				fprintf(stderr, tr(TR_POLICY_CONF_NO_EQ),
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
				} else if (!strncmp(section, "user:", 5) &&
					   section[5]) {
					/* [user:<name>] per-user 覆盖段
					 * （P2 Phase B）：段名 "user:" 后即
					 * 用户名（str_trim 容错空白）；
					 * 仅认 mode=（非法值回落 restricted
					 * 兜底），其余键忽略不炸；
					 * "[user:]"（空名）不识别=忽略 */
					if (!strcmp(key, "mode"))
						user_ov_set(str_trim(section + 5),
							    mode_from_str(val));
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
	g_user_ov_count = 0;	/* per-user 覆盖表同步复位（不残留） */
	snprintf(g_group, sizeof(g_group), "%s", AI_POLICY_GROUP_DEFAULT);
	g_conf_path[0] = '\0';

	fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, tr(TR_POLICY_CONF_UNREAD), path,
			strerror(errno));
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
 * passwd 条目是否属于指定组名（含主组与 /etc/group 成员列表补充组；
 * 语义与原 getgrouplist+getgrgid 实现一致，但不经 NSS）。
 * P2 Phase B 拆出 pw 已知版本：uid 档位判定需先查 passwd 取用户名
 * （per-user 覆盖匹配），复用同一条目避免重复扫 /etc/passwd。
 */
static int pw_in_group(const struct ai_pw_ent *pw, const char *group)
{
	FILE *fp;
	char line[2048];
	int found = 0;

	if (!group || !group[0] || !pw)
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
		if ((gid_t)gid == pw->gid) {
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
					if (!strcmp(tok, pw->name)) {
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

/* uid 是否属于指定组名（先查 passwd 再判定；行为与重构前逐字节等价） */
static int uid_in_group(uid_t uid, const char *group)
{
	struct ai_pw_ent pw;

	if (!group || !group[0])
		return 0;
	if (!local_passwd_get(uid, &pw))
		return 0;
	return pw_in_group(&pw, group);
}

/*
 * uid → 档位判定序（P2 Phase B 起）：
 *   1. [user:<passwd 用户名>] per-user 覆盖（优先级最高）；
 *   2. uid 0 → [root] 段档位（缺省 privileged）；
 *   3. [wheel] group= 组成员 → [wheel] 段档位（缺省 confirmed）；
 *   4. 其余 → [default] 段档位（缺省 restricted）。
 *
 * 安全面决定（有意，勿"修复"）：per-user 覆盖对 uid 0 恒不生效——
 * [user:root] 一类段无法把 root 降档，root 档位只由 [root] 段
 * （缺省 privileged）决定。判定序中的"覆盖最优先"仅在查覆盖表前
 * 已显式排除 uid 0 的前提下成立：任何配置不能借 [user:*] 段改变
 * root 档位，防止 per-user 配置面意外扩大 root 的提权/降档面。
 */
enum ai_policy_mode ai_policy_mode_for_uid(uid_t uid)
{
	struct ai_pw_ent pw;
	int have_pw = 0;

	if (uid != 0) {
		have_pw = local_passwd_get(uid, &pw);
		if (have_pw) {
			const struct ai_policy_user_ov *ov =
				user_ov_find(pw.name);

			if (ov)
				return ov->mode;
		}
	}
	if (uid == 0)
		return g_modes[AI_POLICY_MODE_PRIVILEGED];
	if (have_pw ? pw_in_group(&pw, g_group)
		    : uid_in_group(uid, g_group))
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
	return ai_policy_audit_ex(uid, mode, tool, args, result,
				  NULL, NULL, NULL);
}

int ai_policy_audit_ex(uid_t uid, enum ai_policy_mode mode,
		       const char *tool, const char *args, const char *result,
		       const char *lease_id, const char *danger,
		       const char *confirm_source)
{
	char path[600];
	char tstamp[40];
	char args_1l[256];
	char tool_1l[128];
	char result_1l[32];
	char lease_1l[80];
	char danger_1l[16];
	char confirm_1l[32];
	char line[1600];
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
	sanitize(lease_1l, sizeof(lease_1l), lease_id && lease_id[0] ?
		 lease_id : "-");
	sanitize(danger_1l, sizeof(danger_1l), danger && danger[0] ?
		 danger : "-");
	sanitize(confirm_1l, sizeof(confirm_1l), confirm_source &&
		 confirm_source[0] ? confirm_source : "none");

	/* 审计落盘到目标用户家目录：优先 HOME，其次 passwd */
	if (!home || !home[0])
		home = have_pw ? pw_ent.dir : NULL;
	if (!home || !home[0]) {
		fprintf(stderr, "%s", tr(TR_POLICY_AUDIT_NO_HOME));
		return -1;
	}
	snprintf(path, sizeof(path), "%s/.aikernel", home);
	if (mkdir(path, 0700) != 0 && errno != EEXIST) {
		fprintf(stderr, tr(TR_POLICY_AUDIT_MKDIR), path,
			strerror(errno));
		return -1;
	}
	snprintf(path, sizeof(path), "%s/.aikernel/audit.log", home);

	fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd < 0) {
		fprintf(stderr, tr(TR_POLICY_AUDIT_OPEN), path,
			strerror(errno));
		return -1;
	}

	/* flock 防多进程写交错；单次 write 保证行原子 */
	if (flock(fd, LOCK_EX) != 0) {
		fprintf(stderr, tr(TR_POLICY_AUDIT_FLOCK), path,
			strerror(errno));
		/* 拿不到锁也继续写（O_APPEND 仍尽量原子） */
	}
	n = snprintf(line, sizeof(line),
		     "%s uid=%u user=%s mode=%s tool=%s args=%s result=%s"
		     " lease=%s danger=%s confirm=%s\n",
		     tstamp, (unsigned)uid,
		     have_pw ? pw_ent.name : "?",
		     ai_policy_mode_name(mode),
		     tool_1l, args_1l, result_1l,
		     lease_1l, danger_1l, confirm_1l);
	if (n > 0 && write(fd, line, (size_t)n) != (ssize_t)n) {
		fprintf(stderr, tr(TR_POLICY_AUDIT_WRITE), strerror(errno));
		rc = -1;
	}
	flock(fd, LOCK_UN);
	close(fd);
	return rc;
}

/* ---- W2 二次确认交互 ---- */

/* 预授权开关（修复 10：--yes / AIKERNEL_ASSUME_YES，无人值守通道） */
static int g_assume_yes;
static int g_plan_mode;	/* W43：plan 只读模式（会话级，不落盘） */

/*
 * W20 修4：确认应答读取（单键 + 窗口超时 + 陈旧输入防护）
 *
 * T3 C3 根因：原实现用裸 fgets 在确认面板里等整行——确认挂起期间
 * 到达的任何输入（执行器错位发出的下一场景文本）都被当作应答消费，
 * 而执行器随后补发的 y 又成了 REPL 的新输入行，形成"确认状态跨
 * 场景泄漏"（C2 的确认面板吞掉 C3 的任务文本，C3 完全未执行）。
 * 三重防护：
 *   1. 陈旧输入防护——面板弹出前 stdin 已滞留的可读字节不是本确认
 *      的应答（应答只能晚于面板），绝不消费，立即拒绝；输入留给
 *      REPL 排队层按正常指令处理；
 *   2. 窗口超时——面板显示后最多等 W2_CONFIRM_WAIT_MS，超时视为
 *      拒绝（确认未明 = 不执行，安全缺省）；
 *   3. 单键语义——只认 y/Y（首字符），与原"只认 y/yes"判定等价；
 *      逐字节 read，兼容 REPL 执行期关闭 ICANON 的 raw 模式。
 */
#define W2_CONFIRM_WAIT_MS   8000

static long w2_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* stdin 是否已有可读字节（只探测，不消费） */
static int w2_stdin_readable(void)
{
	fd_set rf;
	struct timeval tv;

	FD_ZERO(&rf);
	FD_SET(STDIN_FILENO, &rf);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	return select(STDIN_FILENO + 1, &rf, NULL, NULL, &tv) > 0;
}

/* 丢弃本行剩余字节（到 '\n' 为止；防残行串扰后续输入） */
static void w2_drain_line(void)
{
	char c;

	while (read(STDIN_FILENO, &c, 1) == 1 && c != '\n')
		;
}

/*
 * w2_confirm_read - 窗口内读确认应答（单键）
 * 返回: 1=确认(y/Y)，0=拒绝/超时/EOF。读到应答字符后吞掉行尾。
 */
static int w2_confirm_read(void)
{
	long deadline = w2_now_ms() + W2_CONFIRM_WAIT_MS;

	for (;;) {
		long remain = deadline - w2_now_ms();
		fd_set rf;
		struct timeval tv;
		ssize_t rr;
		char c;

		if (remain <= 0)
			return 0;           /* 超时：确认未明 = 拒绝 */
		FD_ZERO(&rf);
		FD_SET(STDIN_FILENO, &rf);
		tv.tv_sec = (long)(remain / 1000);
		tv.tv_usec = (long)((remain % 1000) * 1000);
		{
			int sr = select(STDIN_FILENO + 1, &rf, NULL, NULL,
					&tv);

			if (sr < 0) {
				if (errno == EINTR)
					continue;
				return 0;
			}
			if (sr == 0)
				return 0;   /* 窗口耗尽 */
		}
		rr = read(STDIN_FILENO, &c, 1);
		if (rr <= 0)
			return 0;           /* EOF */
		if (c == '\n' || c == '\r')
			continue;           /* 空行：继续等 */
		w2_drain_line();
		return c == 'y' || c == 'Y';
	}
}

/*
 * w2_take_stale_reply - W20 修4b：消费面板前滞留的"单键应答形态"行
 *
 * T3 C3 修复（陈旧输入绝不消费）在编排场景暴露误伤面：执行器检测
 * 到 AI 回答文字里的"确认"字样会提前发出 y（W20 D3 四轮实测：滞留
 * y → 真实面板被陈旧防护拒绝 → CONFIRM=no ×2）。折中语义：
 *   - 滞留行首字节为 y/Y/n/N（确认应答形态）→ 消费整行并按其意图
 *     判定（编排方提前应答视作预授权/预拒绝；审计由 gate 层以
 *     CONFIRM=yes/no 落盘，语义真实）；
 *   - 其他形态（用户下一条指令文本，T3 C3 场景）→ 整行忽略并明确
 *     提示（行边界完整，不吞半个字），本次确认按拒绝处理。
 * 返回: 1=滞留 y（确认），0=滞留 n 或非应答形态（拒绝）。
 */
static int w2_take_stale_reply(void)
{
	char c;
	ssize_t rr = read(STDIN_FILENO, &c, 1);

	if (rr <= 0)
		return 0;
	w2_drain_line();
	return c == 'y' || c == 'Y';
}

void ai_policy_set_assume_yes(int on)
{
	g_assume_yes = on ? 1 : 0;
}

int ai_policy_get_assume_yes(void)
{
	return g_assume_yes;
}

/*
 * ai_policy_set_plan_mode / ai_policy_get_plan_mode（W43）
 * plan（规划）只读模式开关：生效点在 executor.c 工具闸门
 * （非 R 级一律拒绝）与 cmd_ask.c 系统提示注入；本模块只持状态位。
 */
void ai_policy_set_plan_mode(int on)
{
	g_plan_mode = on ? 1 : 0;
}

int ai_policy_get_plan_mode(void)
{
	return g_plan_mode;
}

int ai_policy_confirm_interactive(const char *tool, const char *args,
				  const char *impact_desc)
{
	/* 修复 10：预授权（--yes / AIKERNEL_ASSUME_YES）下自动确认。
	 * 这是调用方的显式授权决定，审计仍全量落盘（CONFIRM=yes(auto)） */
	if (g_assume_yes) {
		fprintf(stderr, tr(TR_W2_AUTO_YES), tool ? tool : "?");
		return 1;
	}

	/* 无人值守（非 tty）不可确认：安全兜底拒绝 */
	if (!isatty(STDIN_FILENO)) {
		fprintf(stderr, "%s", tr(TR_W2_NO_TTY));
		return 0;
	}

	/* W20 修4/4b：面板弹出前 stdin 已滞留的输入——单键应答形态
	 * （y/n，编排方提前发出）消费并按意图判定；其他形态（用户
	 * 下一条指令）忽略整行，本次确认按拒绝处理，绝不吞用户指令 */
	if (w2_stdin_readable()) {
		int stale = w2_take_stale_reply();

		fprintf(stderr, "%s", tr(TR_W2_STALE_INPUT));
		return stale;
	}

	/* 红色 ANSI：完整影响面（工具/参数/影响描述）。
	 * W20：参数超长时截断显示（exec input 可达 60KB，面板不可刷屏） */
	{
		char args_show[280];

		if (args && args[0]) {
			size_t al = strlen(args);

			if (al >= sizeof(args_show)) {
				memcpy(args_show, args,
				       sizeof(args_show) - 4);
				args_show[sizeof(args_show) - 4] = '\0';
				strcat(args_show, "...");
			} else {
				memcpy(args_show, args, al + 1);
			}
		} else {
			args_show[0] = '\0';
		}
		fprintf(stderr, tr(TR_W2_PANEL),
			tool ? tool : "?",
			args_show[0] ? args_show : "{}",
			impact_desc && impact_desc[0] ? impact_desc :
			tr(TR_W2_IMPACT_FALLBACK));
	}
	fprintf(stderr, "%s", tr(TR_W2_CONFIRM));
	fflush(stderr);

	/* W20 修4：窗口内单键应答（超时=拒绝），替代裸 fgets——
	 * 后者在确认挂起期间会吞掉用户/执行器的下一行输入 */
	return w2_confirm_read();
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
		ai_trace_policy_decision(risk == AI_RISK_W2 ? "W2" : "W1",
					 "ALLOW", "policy_allow",
					 tool_name, "auto", args_json);
		return 1;
	case AI_POLICY_NEED_CONFIRM: {
		int unattended;
		int ok = ai_policy_confirm_interactive(tool_name, args_json,
						       impact_desc);

		unattended = !ok && !g_assume_yes &&
			     !isatty(STDIN_FILENO);
		ai_policy_audit(uid, mode, tool_name, args_json,
				ok ? (g_assume_yes ? "CONFIRM=yes(auto)" :
				      "CONFIRM=yes") :
				     (unattended ? "CONFIRM=unattended" :
				      "CONFIRM=no"));
		ai_trace_policy_decision("W2",
			ok ? "ALLOW" : (unattended ? "CONFIRM" : "DENY"),
			ok ? "policy_allow" :
			(unattended ? "needs_confirmation_no_tty" :
			 "user_refused"),
			tool_name,
			ok ? (g_assume_yes ? "assume_yes" : "interactive") :
			"none", args_json);
		if (!ok && result)
			*result = unattended ? AI_GATE_NEED_NO_TTY :
					       AI_GATE_USER_REFUSED;
		return ok;
	}
	case AI_POLICY_DENY:
	default:
		if (result)
			*result = AI_GATE_POLICY_DENY;
		fprintf(stderr, "%s", tr(TR_W2_DENY));
		ai_policy_audit(uid, mode, tool_name, args_json,
				ai_policy_verdict_name(AI_POLICY_DENY));
		ai_trace_policy_decision(risk == AI_RISK_W2 ? "W2" : "W1",
					 "DENY", "policy_tier", tool_name,
					 "none", args_json);
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

	/* 4b. per-user 档位覆盖（[user:<name>] 段，P2 Phase B） */
	{
		struct ai_pw_ent m_pw, r_pw;
		int have_m = local_passwd_get(member_uid, &m_pw);
		int have_root_name = local_passwd_get(0, &r_pw);
		const char *mname = have_m ? m_pw.name : NULL;

		if (!mname) {
			printf("SKIP: per-user 用例（uid %u 在 passwd 无名）\n",
			       (unsigned)member_uid);
		} else {
			/* 4b-1 提权：普通号越过 [default] → privileged */
			{
				char conf[640];

				snprintf(conf, sizeof(conf),
					 "[default]\nmode = restricted\n"
					 "[user:%s]\nmode = privileged\n",
					 mname);
				load_str(conf);
			}
			expect(ai_policy_mode_for_uid(member_uid) ==
			       AI_POLICY_MODE_PRIVILEGED,
			       "per-user：普通号提权 → privileged");
			expect(ai_policy_check(member_uid, AI_RISK_W2) ==
			       AI_POLICY_NEED_CONFIRM,
			       "per-user privileged：W2 → NEED_CONFIRM");
			expect(ai_policy_mode_for_uid(65534) ==
			       AI_POLICY_MODE_RESTRICTED,
			       "per-user：其他用户不受影响（仍 default）");

			/* 4b-2 降档：覆盖 wheel 组员 → restricted */
			{
				char conf[768];

				snprintf(conf, sizeof(conf),
					 "[wheel]\ngroup = %s\nmode = confirmed\n"
					 "[user:%s]\nmode = restricted\n",
					 grp ? grp : "root", mname);
				load_str(conf);
			}
			expect(ai_policy_mode_for_uid(member_uid) ==
			       AI_POLICY_MODE_RESTRICTED,
			       "per-user：wheel 组员降档 → restricted");

			/* 4b-3 坏段名/大小写变体：不识别=永不命中 */
			{
				char conf[896];

				snprintf(conf, sizeof(conf),
					 "[default]\nmode = restricted\n"
					 "[user bob]\nmode = privileged\n"
					 "[user:]\nmode = privileged\n"
					 "[User:%s]\nmode = privileged\n",
					 mname);
				load_str(conf);
			}
			expect(ai_policy_mode_for_uid(member_uid) ==
			       AI_POLICY_MODE_RESTRICTED,
			       "坏段名（无冒号/空名/大写）→ 忽略");

			/* 4b-4 未知键忽略 + 未知用户段永不命中 */
			{
				char conf[896];

				snprintf(conf, sizeof(conf),
					 "[default]\nmode = restricted\n"
					 "[user:nosuch-user-zzz]\n"
					 "mode = privileged\n"
					 "[user:%s]\nfoo = privileged\n"
					 "mode = confirmed\n",
					 mname);
				load_str(conf);
			}
			expect(ai_policy_mode_for_uid(member_uid) ==
			       AI_POLICY_MODE_CONFIRMED,
			       "未知键忽略，mode= 生效 → confirmed");

			/* 4b-5 非法 mode 值 → 该用户回落 restricted */
			{
				char conf[640];

				snprintf(conf, sizeof(conf),
					 "[default]\nmode = restricted\n"
					 "[user:%s]\nmode = Admin\n",
					 mname);
				load_str(conf);
			}
			expect(ai_policy_mode_for_uid(member_uid) ==
			       AI_POLICY_MODE_RESTRICTED,
			       "per-user 非法 mode → restricted 兜底");

			/* 4b-6 重复段后写胜出 */
			{
				char conf[768];

				snprintf(conf, sizeof(conf),
					 "[default]\nmode = restricted\n"
					 "[user:%s]\nmode = confirmed\n"
					 "[user:%s]\nmode = privileged\n",
					 mname, mname);
				load_str(conf);
			}
			expect(ai_policy_mode_for_uid(member_uid) ==
			       AI_POLICY_MODE_PRIVILEGED,
			       "重复 [user:] 段：后写胜出");

			/* 4b-7 覆盖表 init 复位：重载无 [user:] 段的
			 * 配置后旧覆盖不残留（回到三段行为） */
			{
				char conf[640];

				snprintf(conf, sizeof(conf),
					 "[root]\nmode = privileged\n"
					 "[default]\nmode = restricted\n");
				load_str(conf);
			}
			expect(ai_policy_mode_for_uid(member_uid) ==
			       AI_POLICY_MODE_RESTRICTED,
			       "重新 init 无 [user:] 段 → 覆盖不残留");
		}

		/* 4b-8 对 uid 0 恒不生效（安全面：root 不可经
		 * [user:root] 降档——有意决定，见判定序注释） */
		{
			char conf[512];

			snprintf(conf, sizeof(conf),
				 "[root]\nmode = privileged\n"
				 "[user:%s]\nmode = restricted\n",
				 have_root_name ? r_pw.name : "root");
			load_str(conf);
		}
		expect(ai_policy_mode_for_uid(0) == AI_POLICY_MODE_PRIVILEGED,
		       "per-user 对 uid 0 不生效（root 恒 [root] 档）");
		expect(ai_policy_check(0, AI_RISK_W2) == AI_POLICY_NEED_CONFIRM,
		       "root W2 仍 NEED_CONFIRM（未被 [user:root] 降档）");
	}


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
