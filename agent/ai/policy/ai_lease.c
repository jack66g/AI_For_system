// SPDX-License-Identifier: GPL-2.0
/*
 * ai_lease.c - AIKernel 授权租约 / D0-D4 意图保险丝实现（W74）
 *
 * 分层：
 *   1. 纯解析（ai_lease_parse / ai_lease_parse_time / ID 校验）；
 *   2. 安全 IO（O_NOFOLLOW + 0700/0600 + 属主校验 + 原子落盘/撤销）；
 *   3. 危险分级（ai_danger_classify，按 effective risk + 命令/路径细化）；
 *   4. 纯判定（ai_lease_decide，now 注入，不碰 IO）；
 *   5. 网关（ai_lease_gate：TTY 确认 / 非 TTY pending→approved 单次消费）；
 *   6. 确认协议与签发/撤销。
 *
 * 安全边界（务必与 docs/W74-LEASE.md 一致）：
 *   - 租约/确认存储不在 AI 工具可写路径内（executor 另行硬拒绝）；
 *   - 所有租约/确认文件必须非符号链接、0600、属主 root（测试目录可
 *     为调用 uid）；approval 绑定 tool+args+danger+lease 且单次消费；
 *   - 显式租约加载失败一律 fail-closed（调用方非 0 退出）；
 *   - root 租约只对 uid 0 生效；非 root principal 必须与 uid 用户名一致。
 *
 * 未解风险：root AI 仍可通过 python3/apt 等任意代码通道篡改存储；
 * 本模块防的是注入意图/误操作，不是防恶意 root AI（签名/broker 留 W83/W86）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/select.h>
#include <sys/time.h>

#include "policy/ai_lease.h"
#include "policy/ai_user_policy.h"
#include "tools/tool_registry.h"
#include "ai_json_util.h"
#include "ai_lang.h"
#include "ai_trace.h"

/* ---- 小工具 ---- */

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || !errlen)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

const char *ai_danger_name(enum ai_danger d)
{
	switch (d) {
	case AI_D0: return "D0";
	case AI_D1: return "D1";
	case AI_D2: return "D2";
	case AI_D3: return "D3";
	case AI_D4: return "D4";
	default: return "?";
	}
}

int ai_danger_parse(const char *s, enum ai_danger *out)
{
	if (!s || !out)
		return -1;
	if (strcmp(s, "D0") == 0) { *out = AI_D0; return 0; }
	if (strcmp(s, "D1") == 0) { *out = AI_D1; return 0; }
	if (strcmp(s, "D2") == 0) { *out = AI_D2; return 0; }
	if (strcmp(s, "D3") == 0) { *out = AI_D3; return 0; }
	if (strcmp(s, "D4") == 0) { *out = AI_D4; return 0; }
	return -1;
}

const char *ai_lease_decision_name(enum ai_lease_decision d)
{
	switch (d) {
	case AI_LEASE_ALLOW: return "ALLOW";
	case AI_LEASE_CONFIRM: return "CONFIRM";
	case AI_LEASE_CONFIRM_D4: return "CONFIRM_D4";
	case AI_LEASE_DENY: return "DENY";
	default: return "?";
	}
}

int ai_lease_id_valid(const char *id)
{
	size_t n, i;

	if (!id)
		return 0;
	n = strlen(id);
	if (n == 0 || n >= AI_LEASE_ID_MAX)
		return 0;
	if (strcmp(id, ".") == 0 || strcmp(id, "..") == 0)
		return 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)id[i];

		if (isalnum(c) || c == '.' || c == '_' || c == '-')
			continue;
		return 0;
	}
	return 1;
}

/* ---- 时间 ---- */

static int is_leap(int y)
{
	return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
}

static int days_in_month(int y, int m)
{
	static const int dom[] = { 31, 28, 31, 30, 31, 30,
				   31, 31, 30, 31, 30, 31 };

	if (m < 1 || m > 12)
		return 0;
	if (m == 2 && is_leap(y))
		return 29;
	return dom[m - 1];
}

int ai_lease_parse_time(const char *s, long long *out)
{
	int Y, M, D, h, mi, sec, n = 0;
	int oh = 0, om = 0, sign = 0;
	const char *p;
	struct tm tm;
	time_t t;

	if (!s || !out)
		return -1;
	if (sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d%n",
		   &Y, &M, &D, &h, &mi, &sec, &n) != 6)
		return -1;
	if (Y < 1970 || Y > 9999 || M < 1 || M > 12 || D < 1 ||
	    D > days_in_month(Y, M) || h < 0 || h > 23 || mi < 0 ||
	    mi > 59 || sec < 0 || sec > 60)
		return -1;
	p = s + n;
	/* 可选小数秒：.123456 */
	if (*p == '.') {
		p++;
		if (!isdigit((unsigned char)*p))
			return -1;
		while (isdigit((unsigned char)*p))
			p++;
	}
	if (*p == 'Z' && p[1] == '\0') {
		sign = 0;
	} else if ((*p == '+' || *p == '-') &&
		   isdigit((unsigned char)p[1]) &&
		   isdigit((unsigned char)p[2]) && p[3] == ':' &&
		   isdigit((unsigned char)p[4]) &&
		   isdigit((unsigned char)p[5]) && p[6] == '\0') {
		sign = (*p == '-') ? -1 : 1;
		oh = (p[1] - '0') * 10 + (p[2] - '0');
		om = (p[4] - '0') * 10 + (p[5] - '0');
		if (oh > 14 || om > 59)
			return -1;
	} else {
		/* 无时区/尾随垃圾：拒绝 */
		return -1;
	}

	memset(&tm, 0, sizeof(tm));
	tm.tm_year = Y - 1900;
	tm.tm_mon = M - 1;
	tm.tm_mday = D;
	tm.tm_hour = h;
	tm.tm_min = mi;
	tm.tm_sec = sec;
	tm.tm_isdst = 0;
	t = timegm(&tm);
	if (t == (time_t)-1)
		return -1;
	/* 本地时间 = UTC + offset → UTC = timegm - offset */
	t -= (time_t)(sign * (oh * 3600 + om * 60));
	*out = (long long)t;
	return 0;
}

static void format_iso_utc(long long epoch, char *buf, size_t n)
{
	time_t t = (time_t)epoch;
	struct tm tm;

	if (!gmtime_r(&t, &tm)) {
		snprintf(buf, n, "1970-01-01T00:00:00Z");
		return;
	}
	snprintf(buf, n, "%04d-%02d-%02dT%02d:%02d:%02dZ",
		 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		 tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* ---- 本地用户名（静态链接安全：直接读 /etc/passwd） ---- */

static int uid_to_name(uid_t uid, char *buf, size_t n)
{
	FILE *fp;
	char line[1024];

	if (!buf || n == 0)
		return -1;
	buf[0] = '\0';
	fp = fopen("/etc/passwd", "r");
	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		char name[128];
		unsigned int u;

		if (sscanf(line, "%127[^:]:%*[^:]:%u:", name, &u) != 2)
			continue;
		if ((uid_t)u != uid)
			continue;
		fclose(fp);
		snprintf(buf, n, "%s", name);
		return 0;
	}
	fclose(fp);
	return -1;
}

/* ---- JSON 读取 ---- */

static int json_str(const char *obj, size_t len, const char *key,
		    char *buf, size_t cap, int required,
		    char *err, size_t errlen)
{
	const char *v;
	size_t vl;
	int vt;

	buf[0] = '\0';
	if (ai_json_obj_get(obj, len, key, &v, &vl, &vt) != 1) {
		if (required)
			set_err(err, errlen, "缺少字段 %s", key);
		return required ? -1 : 0;
	}
	if (vt != AI_JSON_STR) {
		if (required)
			set_err(err, errlen, "字段 %s 不是字符串", key);
		return required ? -1 : 0;
	}
	{
		char *s = ai_json_strdup_str(v, vl);

		if (!s) {
			if (required)
				set_err(err, errlen, "字段 %s 解码失败", key);
			return required ? -1 : 0;
		}
		snprintf(buf, cap, "%s", s);
		free(s);
	}
	if (required && buf[0] == '\0') {
		set_err(err, errlen, "字段 %s 为空", key);
		return -1;
	}
	return 0;
}

static int json_ll_field(const char *obj, size_t len, const char *key,
			 long long *out)
{
	const char *v;
	size_t vl;
	int vt;

	if (ai_json_obj_get(obj, len, key, &v, &vl, &vt) != 1)
		return -1;
	if (vt != AI_JSON_NUM)
		return -1;
	*out = ai_json_ll(v, vl);
	return 0;
}

static int json_bool(const char *obj, size_t len, const char *key, int *out)
{
	const char *v;
	size_t vl;
	int vt;

	if (ai_json_obj_get(obj, len, key, &v, &vl, &vt) != 1)
		return 0;
	if (vt != AI_JSON_BOOL)
		return 0;
	*out = (strncmp(v, "true", 4) == 0);
	return 1;
}

/* ---- 租约解析 ---- */

static int scope_valid(const char *s)
{
	size_t i, n;

	if (!s || !s[0])
		return 0;
	n = strlen(s);
	if (n >= AI_LEASE_SCOPE_LEN)
		return 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];

		if (c < 0x20 || c == 0x7f)
			return 0;
	}
	/* 路径型 scope 拒绝 ".." 分量 */
	{
		const char *p = s;

		while ((p = strstr(p, "..")) != NULL) {
			int left = (p == s) || p[-1] == '/' || p[-1] == ':';
			int right = p[2] == '\0' || p[2] == '/' || p[2] == ':';

			if (left && right)
				return 0;
			p += 2;
		}
	}
	return 1;
}

int ai_lease_parse(const char *json, size_t len, long long now,
		   struct ai_lease *out, char *err, size_t errlen)
{
	const char *v;
	size_t vl;
	int vt;
	char tmp[AI_LEASE_MISSION_MAX];
	long long ts;
	int i, rc;

	if (!json || !out)
		return -1;
	memset(out, 0, sizeof(*out));
	if (len >= 2 * 1024 * 1024) {
		set_err(err, errlen, "租约文件过大");
		return -1;
	}
	if (json_str(json, len, "lease_id", out->lease_id,
		     sizeof(out->lease_id), 1, err, errlen) != 0)
		return -1;
	if (!ai_lease_id_valid(out->lease_id)) {
		set_err(err, errlen, "非法 lease_id（只允许 [A-Za-z0-9._-]{1,64}）");
		return -1;
	}
	if (json_str(json, len, "principal", out->principal,
		     sizeof(out->principal), 1, err, errlen) != 0)
		return -1;
	if (json_str(json, len, "subject", out->subject,
		     sizeof(out->subject), 1, err, errlen) != 0)
		return -1;
	if (json_str(json, len, "mission", out->mission,
		     sizeof(out->mission), 1, err, errlen) != 0)
		return -1;

	if (ai_json_obj_get(json, len, "scope", &v, &vl, &vt) != 1 ||
	    vt != AI_JSON_ARR) {
		set_err(err, errlen, "scope 必须是数组");
		return -1;
	}
	for (i = 0; ; i++) {
		const char *et;
		size_t el;
		int ety;
		char *sv;

		rc = ai_json_arr_get(v, vl, i, &et, &el, &ety);
		if (rc == 0)
			break;
		if (rc < 0) {
			set_err(err, errlen, "scope 数组语法错误");
			return -1;
		}
		if (ety != AI_JSON_STR) {
			set_err(err, errlen, "scope 元素必须是字符串");
			return -1;
		}
		if (out->scope_count >= AI_LEASE_SCOPE_MAX) {
			set_err(err, errlen, "scope 元素过多（上限 %d）",
				AI_LEASE_SCOPE_MAX);
			return -1;
		}
		sv = ai_json_strdup_str(et, el);
		if (!sv) {
			set_err(err, errlen, "scope 元素解码失败");
			return -1;
		}
		if (!scope_valid(sv)) {
			set_err(err, errlen, "非法 scope 元素");
			free(sv);
			return -1;
		}
		snprintf(out->scope[out->scope_count],
			 sizeof(out->scope[0]), "%s", sv);
		out->scope_count++;
		free(sv);
	}
	if (out->scope_count == 0) {
		set_err(err, errlen, "scope 数组为空");
		return -1;
	}

	if (json_str(json, len, "risk_ceiling", tmp, sizeof(tmp), 1,
		     err, errlen) != 0)
		return -1;
	if (ai_danger_parse(tmp, &out->risk_ceiling) != 0) {
		set_err(err, errlen, "非法 risk_ceiling（只接受 D0-D4）");
		return -1;
	}

	if (json_str(json, len, "expires_at", tmp, sizeof(tmp), 1,
		     err, errlen) != 0)
		return -1;
	if (ai_lease_parse_time(tmp, &ts) != 0) {
		set_err(err, errlen,
			"expires_at 非法或缺少时区（需要 ±HH:MM 或 Z）");
		return -1;
	}
	out->expires_at = ts;

	if (json_str(json, len, "issued_at", tmp, sizeof(tmp), 0,
		     err, errlen) != 0) {
		set_err(err, errlen, "issued_at 非法");
		return -1;
	}
	if (tmp[0]) {
		if (ai_lease_parse_time(tmp, &ts) != 0) {
			set_err(err, errlen,
				"issued_at 非法或缺少时区（需要 ±HH:MM 或 Z）");
			return -1;
		}
		out->issued_at = ts;
		out->has_issued_at = 1;
		if (now > 0 && ts > now + AI_LEASE_CLOCK_SKEW) {
			set_err(err, errlen, "issued_at 在未来（超过 %d 秒时钟偏差）",
				AI_LEASE_CLOCK_SKEW);
			return -1;
		}
	}

	out->revocable = 1;
	json_bool(json, len, "revocable", &out->revocable);
	json_bool(json, len, "revoked", &out->revoked);
	json_str(json, len, "audit", out->audit, sizeof(out->audit), 0,
		 err, errlen);
	return 0;
}

/* ---- 路径安全 ---- */

static int path_has_dotdot(const char *p)
{
	const char *s = p;

	if (!p)
		return 0;
	while ((s = strstr(s, "..")) != NULL) {
		int left = (s == p) || s[-1] == '/';
		int right = s[2] == '\0' || s[2] == '/';

		if (left && right)
			return 1;
		s += 2;
	}
	return 0;
}

static int path_under_prefix(const char *path, const char *prefix)
{
	size_t n = strlen(prefix);

	if (!path || !prefix)
		return 0;
	if (strncmp(path, prefix, n) != 0)
		return 0;
	return path[n] == '\0' || path[n] == '/';
}

static int path_is_protected_store(const char *p)
{
	const char *home = getenv("HOME");

	if (!p)
		return 0;
	if (path_under_prefix(p, AI_LEASE_PROTECT_PREFIX1) ||
	    path_under_prefix(p, AI_LEASE_PROTECT_PREFIX2) ||
	    path_under_prefix(p, "/var/log/aikernel") ||
	    path_under_prefix(p, "/root/.aikernel"))
		return 1;
	if (home && home[0]) {
		char h[PATH_MAX];

		if (snprintf(h, sizeof(h), "%s/.aikernel", home) <
		    (int)sizeof(h) && path_under_prefix(p, h))
			return 1;
	}
	return 0;
}

int ai_lease_path_protected(const char *path)
{
	char abs[PATH_MAX];
	char real[PATH_MAX];
	const char *probe = path;

	if (!path || !path[0])
		return 0;
	if (path_has_dotdot(path))
		return 1;	/* 含穿越分量：按受保护处理（拒绝写） */
	if (path[0] != '/') {
		char cwd[PATH_MAX];

		if (!getcwd(cwd, sizeof(cwd)))
			return 1;
		if (snprintf(abs, sizeof(abs), "%s/%s", cwd, path) >=
		    (int)sizeof(abs))
			return 1;
		probe = abs;
	}
	if (path_is_protected_store(probe))
		return 1;
	if (realpath(probe, real) && path_is_protected_store(real))
		return 1;
	return 0;
}

/* ---- 目录/文件信任 ---- */

static int env_override_is_set(const char *name)
{
	const char *v = getenv(name);

	return v && v[0];
}

static int dir_trusted(const char *path, uid_t uid, int allow_user_owner,
		       char *err, size_t errlen)
{
	struct stat st;

	if (lstat(path, &st) != 0) {
		set_err(err, errlen, "目录 %s 不可访问：%s", path,
			strerror(errno));
		return -1;
	}
	if (S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode)) {
		set_err(err, errlen, "目录 %s 不是真实目录（拒绝符号链接）",
			path);
		return -1;
	}
	if ((st.st_mode & 077) != 0) {
		set_err(err, errlen, "目录 %s 权限过宽（要求 0700）", path);
		return -1;
	}
	if (st.st_uid != 0 && st.st_uid != uid) {
		set_err(err, errlen, "目录 %s 属主 %u 不可信", path,
			(unsigned)st.st_uid);
		return -1;
	}
	if (!allow_user_owner && st.st_uid != 0) {
		set_err(err, errlen, "目录 %s 必须属于 root", path);
		return -1;
	}
	return 0;
}

static int mkdir_0700(const char *path, char *err, size_t errlen)
{
	if (mkdir(path, 0700) == 0)
		return 0;
	if (errno == EEXIST)
		return 0;
	set_err(err, errlen, "创建目录 %s 失败：%s", path, strerror(errno));
	return -1;
}

/* 递归创建目录（仅测试/显式覆盖路径需要；生产目录应预置） */
static int mkdirs_0700(const char *path, char *err, size_t errlen)
{
	char tmp[PATH_MAX];
	size_t i, n;

	if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp)) {
		set_err(err, errlen, "路径过长：%s", path);
		return -1;
	}
	n = strlen(tmp);
	for (i = 1; i < n; i++) {
		if (tmp[i] != '/')
			continue;
		tmp[i] = '\0';
		if (mkdir_0700(tmp, err, errlen) != 0)
			return -1;
		tmp[i] = '/';
	}
	return mkdir_0700(tmp, err, errlen);
}

/*
 * 读取受信任文件：非符号链接、常规文件、0600、属主 root（或测试
 * 覆盖目录下的调用 uid）。返回 malloc 内容（NUL 结尾）。
 */
static int read_trusted_file(const char *path, uid_t uid,
			     int allow_user_owner, char **out,
			     char *err, size_t errlen)
{
	int fd;
	struct stat st;
	char *buf;
	size_t cap = 65536, len = 0;

	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		set_err(err, errlen, "打开 %s 失败：%s", path, strerror(errno));
		return -1;
	}
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		set_err(err, errlen, "%s 不是常规文件", path);
		close(fd);
		return -1;
	}
	if ((st.st_mode & 0777) != 0600) {
		set_err(err, errlen, "%s 权限必须为 0600（实际 %04o）", path,
			(unsigned)(st.st_mode & 0777));
		close(fd);
		return -1;
	}
	if (st.st_uid != 0 && st.st_uid != uid) {
		set_err(err, errlen, "%s 属主 %u 不可信", path,
			(unsigned)st.st_uid);
		close(fd);
		return -1;
	}
	if (!allow_user_owner && st.st_uid != 0) {
		set_err(err, errlen, "%s 必须属于 root", path);
		close(fd);
		return -1;
	}
	if (st.st_size > (off_t)cap) {
		set_err(err, errlen, "%s 过大", path);
		close(fd);
		return -1;
	}
	buf = malloc(cap + 1);
	if (!buf) {
		set_err(err, errlen, "内存不足");
		close(fd);
		return -1;
	}
	while (len < cap) {
		ssize_t n = read(fd, buf + len, cap - len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			set_err(err, errlen, "读取 %s 失败：%s", path,
				strerror(errno));
			free(buf);
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		len += (size_t)n;
	}
	buf[len] = '\0';
	close(fd);
	*out = buf;
	return 0;
}

static int fsync_dir(const char *path)
{
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	int rc;

	if (fd < 0)
		return -1;
	rc = fsync(fd);
	close(fd);
	return rc;
}

/* ---- 加载 ---- */

void ai_lease_store_dir(char *buf, size_t n)
{
	const char *v = getenv("AIKERNEL_LEASE_DIR");

	if (!buf || !n)
		return;
	snprintf(buf, n, "%s", (v && v[0]) ? v : AI_LEASE_DIR_DEFAULT);
}

void ai_lease_confirm_dir(char *buf, size_t n)
{
	const char *v = getenv("AIKERNEL_CONFIRM_DIR");

	if (!buf || !n)
		return;
	snprintf(buf, n, "%s", (v && v[0]) ? v : AI_LEASE_CONFIRM_DEFAULT);
}

/* 读取 + 解析租约文件（不做 principal/过期判定） */
static int load_lease_raw(const char *dir, const char *id, uid_t uid,
			  int allow_user_owner, long long now,
			  struct ai_lease *out, uid_t *file_owner,
			  char *err, size_t errlen)
{
	char path[PATH_MAX];
	char rpath[PATH_MAX];
	char *json = NULL;
	int rc;

	if (!ai_lease_id_valid(id)) {
		set_err(err, errlen, "非法 lease_id");
		return -1;
	}
	if (snprintf(path, sizeof(path), "%s/%s.json", dir, id) >=
	    (int)sizeof(path)) {
		set_err(err, errlen, "租约路径过长");
		return -1;
	}
	/* 目录本身也校验（拒绝符号链接/宽权限） */
	if (realpath(dir, rpath)) {
		if (dir_trusted(rpath, uid, allow_user_owner, err, errlen) != 0)
			return -1;
	} else {
		set_err(err, errlen, "租约目录不可解析：%s", dir);
		return -1;
	}
	if (read_trusted_file(path, uid, allow_user_owner, &json,
			      err, errlen) != 0)
		return -1;
	rc = ai_lease_parse(json, strlen(json), now, out, err, errlen);
	if (rc != 0) {
		free(json);
		return -1;
	}
	free(json);
	{
		struct stat st;

		if (lstat(path, &st) == 0 && file_owner)
			*file_owner = st.st_uid;
	}
	/* 撤销标记优先 */
	{
		char marker[PATH_MAX];
		struct stat st;

		if (snprintf(marker, sizeof(marker), "%s/%s.revoked", dir, id) <
		    (int)sizeof(marker)) {
			if (lstat(marker, &st) == 0) {
				if (S_ISLNK(st.st_mode)) {
					set_err(err, errlen,
						"撤销标记是符号链接（拒绝）");
					return -1;
				}
				out->revoked = 1;
			}
		}
	}
	return 0;
}

int ai_lease_load(const char *dir, const char *id, uid_t uid, long long now,
		  struct ai_lease *out, uid_t *file_owner,
		  char *err, size_t errlen)
{
	int allow_user_owner = env_override_is_set("AIKERNEL_LEASE_DIR");
	char name[128];

	if (load_lease_raw(dir, id, uid, allow_user_owner, now, out,
			   file_owner, err, errlen) != 0)
		return -1;
	if (out->revoked) {
		set_err(err, errlen, "租约 %s 已撤销", id);
		return -1;
	}
	if (out->expires_at <= now) {
		set_err(err, errlen, "租约 %s 已过期", id);
		return -1;
	}
	if (out->has_issued_at && out->issued_at > now + AI_LEASE_CLOCK_SKEW) {
		set_err(err, errlen, "租约 %s 的 issued_at 在未来", id);
		return -1;
	}
	if (strcmp(out->principal, "root") == 0) {
		if (uid != 0) {
			set_err(err, errlen,
				"root 租约只能由 uid 0 使用（当前 uid=%u）",
				(unsigned)uid);
			return -1;
		}
		if (file_owner && *file_owner != 0) {
			set_err(err, errlen,
				"root 租约文件必须属于 root（实际 %u）",
				(unsigned)*file_owner);
			return -1;
		}
	} else {
		if (uid == 0) {
			/* root 可用任何租约，但 principal 必须存在 */
		} else if (uid_to_name(uid, name, sizeof(name)) != 0 ||
			   strcmp(name, out->principal) != 0) {
			set_err(err, errlen,
				"租约 principal=%s 与当前用户不匹配",
				out->principal);
			return -1;
		}
	}
	return 0;
}

int ai_lease_store_list(struct ai_lease *items, int cap, int *count,
			char *err, size_t errlen)
{
	char dir[512];
	DIR *d;
	struct dirent *e;
	int n = 0;

	if (count)
		*count = 0;
	ai_lease_store_dir(dir, sizeof(dir));
	if (access(dir, F_OK) != 0 && errno == ENOENT) {
		if (count)
			*count = 0;
		return 0;	/* 尚未签发任何租约 */
	}
	if (!env_override_is_set("AIKERNEL_LEASE_DIR")) {
		if (dir_trusted(dir, getuid(), 0, err, errlen) != 0)
			return -1;
	}
	d = opendir(dir);
	if (!d) {
		if (errno == ENOENT) {
			/* 尚未签发任何租约：只读 list 视为空集 */
			if (count)
				*count = 0;
			return 0;
		}
		set_err(err, errlen, "打开租约目录 %s 失败：%s", dir,
			strerror(errno));
		return -1;
	}
	while ((e = readdir(d)) != NULL && n < cap) {
		char id[AI_LEASE_ID_MAX];
		size_t len = strlen(e->d_name);
		struct ai_lease l;
		uid_t owner = 0;

		if (len < 6 || strcmp(e->d_name + len - 5, ".json") != 0)
			continue;
		if (len - 5 >= sizeof(id))
			continue;
		memcpy(id, e->d_name, len - 5);
		id[len - 5] = '\0';
		if (!ai_lease_id_valid(id))
			continue;
		if (load_lease_raw(dir, id, getuid(),
				   env_override_is_set("AIKERNEL_LEASE_DIR"),
				   time(NULL), &l, &owner, err, errlen) == 0)
			items[n++] = l;
	}
	closedir(d);
	if (count)
		*count = n;
	return 0;
}

/* ---- 上下文 ---- */

static struct ai_lease_ctx g_ctx;
static int g_ctx_active;

const struct ai_lease_ctx *ai_lease_ctx_get(void)
{
	return &g_ctx;
}

int ai_lease_ctx_active(void)
{
	return g_ctx_active;
}

void ai_lease_ctx_reset(void)
{
	memset(&g_ctx, 0, sizeof(g_ctx));
	g_ctx_active = 0;
}

int ai_lease_ephemeral_create(uid_t uid, struct ai_lease *out)
{
	char user[64];
	struct timespec ts;
	long long now;

	if (!out)
		return -1;
	memset(out, 0, sizeof(*out));
	if (uid == 0)
		snprintf(user, sizeof(user), "root");
	else if (uid_to_name(uid, user, sizeof(user)) != 0)
		snprintf(user, sizeof(user), "uid%u", (unsigned)uid);
	clock_gettime(CLOCK_REALTIME, &ts);
	now = (long long)ts.tv_sec;
	snprintf(out->lease_id, sizeof(out->lease_id),
		 "L-EPHEMERAL-%d-%lld", (int)getpid(), now);
	snprintf(out->principal, sizeof(out->principal), "%s", user);
	snprintf(out->subject, sizeof(out->subject), "%.60s-ai", user);
	snprintf(out->scope[0], sizeof(out->scope[0]), "*");
	out->scope_count = 1;
	out->risk_ceiling = AI_D2;
	snprintf(out->mission, sizeof(out->mission),
		 "ephemeral --yes lease for this ask");
	out->issued_at = now;
	out->has_issued_at = 1;
	out->expires_at = now + AI_LEASE_EPHEMERAL_TTL;
	out->revocable = 0;
	snprintf(out->audit, sizeof(out->audit), "ephemeral");
	return 0;
}

int ai_lease_ctx_init(const char *explicit_id, int ephemeral_yes, uid_t uid,
		      char *err, size_t errlen)
{
	long long now = (long long)time(NULL);

	memset(&g_ctx, 0, sizeof(g_ctx));
	g_ctx_active = 1;
	ai_lease_store_dir(g_ctx.dir, sizeof(g_ctx.dir));

	if (explicit_id && explicit_id[0]) {
		g_ctx.mode = AI_LEASE_MODE_EXPLICIT;
		snprintf(g_ctx.source, sizeof(g_ctx.source), "%s/%s.json",
			 g_ctx.dir, explicit_id);
		if (ai_lease_load(g_ctx.dir, explicit_id, uid, now,
				  &g_ctx.lease, &g_ctx.file_owner,
				  g_ctx.error, sizeof(g_ctx.error)) != 0) {
			g_ctx.loaded = 0;
			set_err(err, errlen, "显式租约加载失败：%s",
				g_ctx.error);
			return -1;
		}
		g_ctx.loaded = 1;
		/* 记录加载时文件指纹（live 撤销/篡改检测用） */
		{
			char path[PATH_MAX];
			struct stat st;

			if (snprintf(path, sizeof(path), "%s/%s.json",
				     g_ctx.dir, explicit_id) <
			    (int)sizeof(path) &&
			    lstat(path, &st) == 0) {
				g_ctx.file_ino = (unsigned long long)st.st_ino;
				g_ctx.file_size = (long long)st.st_size;
				g_ctx.file_mtime = (long long)st.st_mtime;
			}
		}
		return 0;
	}
	if (ephemeral_yes) {
		g_ctx.mode = AI_LEASE_MODE_EPHEMERAL;
		snprintf(g_ctx.source, sizeof(g_ctx.source), "ephemeral(-y)");
		if (ai_lease_ephemeral_create(uid, &g_ctx.lease) != 0) {
			set_err(err, errlen, "创建 ephemeral 租约失败");
			return -1;
		}
		g_ctx.loaded = 1;
		return 0;
	}
	g_ctx.mode = AI_LEASE_MODE_NONE;
	snprintf(g_ctx.source, sizeof(g_ctx.source), "none");
	return 0;
}

/* ---- 危险分级：命令解析 ---- */

struct cmdline {
	char *cmd;
	char **argv;
	int argc;
};

static void cmdline_free(struct cmdline *cl)
{
	int i;

	if (!cl)
		return;
	free(cl->cmd);
	for (i = 0; i < cl->argc; i++)
		free(cl->argv[i]);
	free(cl->argv);
	memset(cl, 0, sizeof(*cl));
}

static int split_ws(const char *s, char ***out, int *outn)
{
	char *copy, *p, *tok;
	char **arr = NULL;
	int n = 0;

	*out = NULL;
	*outn = 0;
	if (!s)
		return 0;
	copy = strdup(s);
	if (!copy)
		return -1;
	p = copy;
	while ((tok = strsep(&p, " \t\r\n")) != NULL) {
		char **na;

		if (!tok[0])
			continue;
		na = realloc(arr, sizeof(char *) * (size_t)(n + 1));
		if (!na) {
			free(copy);
			free(arr);
			return -1;
		}
		arr = na;
		arr[n] = strdup(tok);
		if (!arr[n]) {
			free(copy);
			for (int i = 0; i < n; i++)
				free(arr[i]);
			free(arr);
			return -1;
		}
		n++;
	}
	free(copy);
	*out = arr;
	*outn = n;
	return 0;
}

static int parse_exec_args(const char *args_json, struct cmdline *cl)
{
	const char *v;
	size_t vl;
	int vt;
	char *cmd = NULL;
	char **argv = NULL;
	int argc = 0;
	int i;

	memset(cl, 0, sizeof(*cl));
	if (!args_json)
		return 0;
	if (ai_json_obj_get(args_json, strlen(args_json), "command",
			    &v, &vl, &vt) == 1 && vt == AI_JSON_STR)
		cmd = ai_json_strdup_str(v, vl);
	if (!cmd)
		return 0;
	if (ai_json_obj_get(args_json, strlen(args_json), "args",
			    &v, &vl, &vt) == 1 && vt == AI_JSON_ARR) {
		for (i = 0; ; i++) {
			const char *et;
			size_t el;
			int ety;
			char **na;

			if (ai_json_arr_get(v, vl, i, &et, &el, &ety) != 1)
				break;
			if (ety != AI_JSON_STR)
				continue;
			na = realloc(argv, sizeof(char *) *
				     (size_t)(argc + 1));
			if (!na)
				break;
			argv = na;
			argv[argc] = ai_json_strdup_str(et, el);
			if (!argv[argc])
				break;
			argc++;
		}
	}
	/* 兼容旧式 "command": "systemctl restart nginx"（无 args） */
	if (argc == 0 && strpbrk(cmd, " \t") != NULL) {
		char **toks = NULL;
		int nt = 0;

		if (split_ws(cmd, &toks, &nt) == 0 && nt > 0) {
			free(cmd);
			cmd = toks[0];
			argv = NULL;
			argc = 0;
			for (i = 1; i < nt; i++) {
				char **na = realloc(argv, sizeof(char *) *
						    (size_t)(argc + 1));

				if (!na) {
					free(toks[i]);
					continue;
				}
				argv = na;
				argv[argc++] = toks[i];
			}
		}
	}
	/* 去掉目录前缀 */
	{
		char *slash = strrchr(cmd, '/');

		if (slash && slash[1])
			memmove(cmd, slash + 1, strlen(slash + 1) + 1);
	}
	cl->cmd = cmd;
	cl->argv = argv;
	cl->argc = argc;
	return 0;
}

static int argv_has(const struct cmdline *cl, const char *s)
{
	int i;

	for (i = 0; i < cl->argc; i++)
		if (strcmp(cl->argv[i], s) == 0)
			return 1;
	return 0;
}

static const char *argv_first_nonopt(const struct cmdline *cl)
{
	int i;

	for (i = 0; i < cl->argc; i++) {
		if (cl->argv[i][0] != '-')
			return cl->argv[i];
	}
	return cl->argc ? cl->argv[0] : NULL;
}

static int cmd_in(const char *cmd, const char *const *list)
{
	int i;

	for (i = 0; list[i]; i++)
		if (strcmp(cmd, list[i]) == 0)
			return 1;
	return 0;
}

/* 从 exec args 提取目标路径（尽量取写目标） */
static char *extract_target(const struct cmdline *cl)
{
	const char *last = NULL, *first = NULL;
	int i;
	int prefer_last = 0;

	if (cl && cl->cmd) {
		prefer_last = cmd_in(cl->cmd, (const char *const[]){
			"cp", "mv", "ln", "tee", "install", "dd", "gzip",
			"gunzip", "tar", "sed", NULL });
	}
	for (i = 0; cl && i < cl->argc; i++) {
		const char *a = cl->argv[i];

		if (strncmp(a, "of=", 3) == 0 && a[3] == '/') {
			last = a + 3;
			first = first ? first : last;
		} else if (a[0] == '/') {
			if (!first)
				first = a;
			last = a;
		}
	}
	if (prefer_last && last)
		return strdup(last);
	if (first)
		return strdup(first);
	return NULL;
}

/* 从 JSON 参数提取路径（path/file/target/output 等） */
static char *extract_json_target(const char *args_json)
{
	static const char *const keys[] = {
		"path", "file", "target", "output", "dest", "destination",
		NULL,
	};
	const char *v;
	size_t vl;
	int vt;
	int i;

	if (!args_json)
		return NULL;
	for (i = 0; keys[i]; i++) {
		if (ai_json_obj_get(args_json, strlen(args_json), keys[i],
				    &v, &vl, &vt) == 1 && vt == AI_JSON_STR) {
			char *s = ai_json_strdup_str(v, vl);

			if (s && s[0] == '/')
				return s;
			free(s);
		}
	}
	return NULL;
}

/* D4 路径（身份/启动链/租约存储） */
static int path_is_d4(const char *p)
{
	if (!p)
		return 0;
	if (path_under_prefix(p, "/etc/sudoers") ||
	    path_under_prefix(p, "/etc/sudoers.d") ||
	    strcmp(p, "/etc/passwd") == 0 ||
	    strcmp(p, "/etc/shadow") == 0 ||
	    strcmp(p, "/etc/group") == 0 ||
	    strcmp(p, "/etc/gshadow") == 0 ||
	    path_under_prefix(p, "/etc/grub.d") ||
	    strcmp(p, "/etc/default/grub") == 0 ||
	    strcmp(p, "/etc/aikernel/policy.conf") == 0)
		return 1;
	/* SSH：授权公钥 + 私钥/identity + 主机私钥；known_hosts 不升级 */
	if (strstr(p, "authorized_keys") ||
	    strstr(p, "/.ssh/id_") ||
	    strstr(p, "/.ssh/identity") ||
	    strstr(p, "/etc/ssh/ssh_host_") ||
	    path_under_prefix(p, "/etc/ssh/sshd_config"))
		return 1;
	/* 认证/安全配置 */
	if (path_under_prefix(p, "/etc/pam.d") ||
	    path_under_prefix(p, "/etc/security") ||
	    strcmp(p, "/etc/crypttab") == 0)
		return 1;
	/* 启动链 / 内核镜像 / EFI */
	if (path_under_prefix(p, "/boot") ||
	    path_under_prefix(p, "/sys/firmware/efi"))
		return 1;
	/* 注意：租约/确认存储（/var/lib/aikernel、/run/aikernel）不靠 D 级
	 * 保护，而由 executor 写目标硬拒绝（ai_lease_path_protected）。
	 * 这样普通写工具在任何 D 级/租约下都到不了存储层，删掉 D4 标签
	 * 也让“被授权后仍必须过路径校验”这条防线可测试。 */
	return 0;
}

/* D2+ 动作写系统路径 → 至少 D3 */
static int path_is_system(const char *p)
{
	if (!p)
		return 0;
	/* 租约/确认/审计/trace 存储由 executor 硬拒绝（路径层），
	 * 不需要 D3 升级，否则 D3 确认会先于路径拒绝。 */
	if (path_is_protected_store(p))
		return 0;
	return path_under_prefix(p, "/etc") ||
	       path_under_prefix(p, "/usr") ||
	       path_under_prefix(p, "/bin") ||
	       path_under_prefix(p, "/sbin") ||
	       path_under_prefix(p, "/lib") ||
	       path_under_prefix(p, "/lib64") ||
	       path_under_prefix(p, "/var/lib") ||
	       path_under_prefix(p, "/home") ||
	       path_under_prefix(p, "/opt") ||
	       path_under_prefix(p, "/proc/sys") ||
	       path_under_prefix(p, "/sys") ||
	       path_under_prefix(p, "/dev");
}

static int systemctl_verb_is_d3(const char *verb)
{
	static const char *const d3[] = {
		"start", "stop", "restart", "reload", "enable", "disable",
		"mask", "unmask", "set-default", "isolate", "rescue",
		"emergency", "reboot", "poweroff", "halt", NULL,
	};
	return cmd_in(verb, d3);
}

static int service_verb_is_d3(const char *verb)
{
	static const char *const d3[] = {
		"start", "stop", "restart", "reload", "force-reload",
		NULL,
	};
	return cmd_in(verb, d3);
}

static int ip_write_verb(const char *verb)
{
	static const char *const w[] = {
		"add", "del", "delete", "set", "flush", "replace",
		"append", "change", "up", "down", NULL,
	};
	return cmd_in(verb, w);
}

enum ai_danger ai_danger_classify(const char *tool_name, const char *domain,
				  const char *effective_risk,
				  const char *args_json,
				  char **target_path, const char **reason)
{
	enum ai_danger d;
	struct cmdline cl;
	char *target = NULL;
	const char *why = "risk_mapping";

	if (target_path)
		*target_path = NULL;
	if (reason)
		*reason = "risk_mapping";
	if (!effective_risk)
		effective_risk = TOOL_RISK_W2;
	if (strcmp(effective_risk, TOOL_RISK_R) == 0)
		d = AI_D0;
	else if (strcmp(effective_risk, TOOL_RISK_W1) == 0)
		d = AI_D1;
	else
		d = AI_D2;	/* W2 与未知风险一律至少 D2 */

	memset(&cl, 0, sizeof(cl));
	parse_exec_args(args_json, &cl);
	if (cl.cmd) {
		target = extract_target(&cl);
	} else {
		target = extract_json_target(args_json);
	}

	/* 注意：不能在工具名/命令/路径覆盖之前对 R 早退——effective risk=R
	 * 但工具名/命令命中 D3/D4 时必须能升级（如合成工具
	 * netlink_act_sec_seccomp + R）。纯读命令在覆盖后保持 D0。 */

	/* 工具名级覆盖 */
	if (tool_name) {
		if (strstr(tool_name, "lease_issue") ||
		    strstr(tool_name, "lease_revoke") ||
		    strstr(tool_name, "lease_confirm")) {
			d = AI_D4;
			why = "lease_management";
			goto out;
		}
		if (strcmp(tool_name, "netlink_act_sec_lsm_override") == 0 ||
		    strcmp(tool_name, "netlink_act_sec_seccomp") == 0 ||
		    strcmp(tool_name, "netlink_act_sec_audit") == 0) {
			d = AI_D4;
			why = "security_identity_tool";
			goto out;
		}
		if (strncmp(tool_name, "netlink_act_", 12) == 0) {
			d = AI_D3;
			why = "netlink_actuation";
			goto out;
		}
		if (strcmp(tool_name, "sysctl_set") == 0 ||
		    strcmp(tool_name, "sysfs_set") == 0 ||
		    strcmp(tool_name, "config_write_fstab") == 0) {
			d = AI_D3;
			why = "system_config_write";
			goto out;
		}
		if (strcmp(tool_name, "sys_shell") == 0) {
			d = AI_D3;
			why = "interactive_root_shell";
			goto out;
		}
		if (strcmp(tool_name, "procfs_write_telemetry_reset") == 0) {
			d = AI_D2;
			why = "telemetry_reset";
			goto out;
		}
		if (strcmp(tool_name, "sandbox_spawn") == 0) {
			d = AI_D2;
			why = "sandbox_subagent";
			goto out;
		}
		/* W76：桌面能力面 D0-D3（fail-closed：未知 desktop_* 至少 D2） */
		if (strncmp(tool_name, "desktop_", 8) == 0) {
			if (strcmp(tool_name, "desktop_health") == 0 ||
			    strcmp(tool_name, "desktop_stats") == 0 ||
			    strcmp(tool_name, "desktop_apps_list") == 0 ||
			    strcmp(tool_name, "desktop_windows_list") == 0 ||
			    strcmp(tool_name, "desktop_theme_get") == 0 ||
			    strcmp(tool_name, "desktop_wallpaper_get") == 0 ||
			    strcmp(tool_name,
				   "desktop_notifications_list") == 0 ||
			    strcmp(tool_name, "desktop_screenshot") == 0 ||
			    strcmp(tool_name, "desktop_clipboard_get") == 0) {
				d = AI_D0;
				why = "desktop_read";
			} else if (strcmp(tool_name,
					  "desktop_theme_set") == 0 ||
				   strcmp(tool_name,
					  "desktop_wallpaper_set") == 0 ||
				   strcmp(tool_name,
					  "desktop_notifications_send") == 0 ||
				   strcmp(tool_name,
					  "desktop_apps_launch") == 0 ||
				   strcmp(tool_name,
					  "desktop_windows_focus") == 0) {
				d = AI_D1;
				why = "desktop_reversible_write";
			} else if (strcmp(tool_name,
					  "desktop_power") == 0) {
				d = AI_D3;
				why = "desktop_system_power";
			} else {
				/* windows.close / apps.close / input.type /
				 * input.key / clipboard.set 及任何未来未登记
				 * 的 desktop_* 写。 */
				d = AI_D2;
				why = "desktop_irreversible_write";
			}
			goto out;
		}
	}

	/* 命令级覆盖 */
	if (cl.cmd) {
		const char *cmd = cl.cmd;

		if (cmd_in(cmd, (const char *const[]){
				"useradd", "usermod", "userdel", "groupadd",
				"groupmod", "groupdel", "passwd", "chpasswd",
				"chage", "vipw", "vigr", "visudo",
				"aa-enforce", "aa-complain", "aa-disable",
				"grub-install", "grub-mkconfig", "update-grub",
				"grub2-mkconfig", "ssh-copy-id", NULL })) {
			d = AI_D4;
			why = "identity_boot_management";
			goto out;
		}
		if (strcmp(cmd, "systemctl") == 0) {
			const char *verb = argv_first_nonopt(&cl);

			if (verb && systemctl_verb_is_d3(verb)) {
				d = AI_D3;
				why = "service_control";
				goto out;
			}
			if (verb && strcmp(verb, "daemon-reload") == 0) {
				d = AI_D3;
				why = "service_control";
				goto out;
			}
		} else if (strcmp(cmd, "service") == 0) {
			/* service <name> <verb> */
			const char *verb = cl.argc >= 2 ? cl.argv[1] : NULL;

			if (verb && service_verb_is_d3(verb)) {
				d = AI_D3;
				why = "service_control";
				goto out;
			}
		}
		if (cmd_in(cmd, (const char *const[]){
				"nft", "tc", "mount", "umount", "swapon",
				"swapoff", "fstrim", "setquota", "kill",
				"apt", "dpkg",
				"aik-backup", "aik-reset",
				"reboot", "shutdown", "poweroff", "halt",
				"sysctl", NULL })) {
			d = AI_D3;
			why = "system_level_command";
			goto out;
		}
		/* crontab -l 只读保持原级；其余（-r/文件安装/清表）D3 */
		if (strcmp(cmd, "crontab") == 0) {
			if (!(cl.argc >= 1 && strcmp(cl.argv[0], "-l") == 0)) {
				d = AI_D3;
				why = "scheduled_job_write";
				goto out;
			}
		}
		/* aik-upgrade：status/healthcheck 只读保持原级；
		 * install/boot/commit/rollback/auto-commit/grubenv → D3 */
		if (strcmp(cmd, "aik-upgrade") == 0) {
			static const char *const wsub[] = {
				"install", "boot", "commit", "rollback",
				"auto-commit", "grubenv", NULL,
			};
			int i;

			for (i = 0; i < cl.argc; i++) {
				if (cmd_in(cl.argv[i], wsub)) {
					d = AI_D3;
					why = "system_upgrade";
					goto out;
				}
			}
		}
		/* python3 在主表 W2→D3；沙箱受限表显式 W1（沙箱内部
		 * 执行）保持 D1，避免把 worker 的受限编程能力一刀切。 */
		if (strcmp(cmd, "python3") == 0 && d >= AI_D2) {
			d = AI_D3;
			why = "arbitrary_code";
			goto out;
		}
		/* 系统时间：-s/--set/--set=/位置参数（+format 仍只读） */
		if (strcmp(cmd, "date") == 0) {
			int i, set = 0;

			for (i = 0; i < cl.argc; i++) {
				const char *a = cl.argv[i];

				if (strcmp(a, "-s") == 0 ||
				    strcmp(a, "--set") == 0 ||
				    strncmp(a, "--set=", 6) == 0 ||
				    (a[0] == '-' && a[1] == 's' && a[2])) {
					set = 1;
					break;
				}
				if (strcmp(a, "-d") == 0 ||
				    strcmp(a, "--date") == 0 ||
				    strcmp(a, "-f") == 0 ||
				    strcmp(a, "--file") == 0 ||
				    strcmp(a, "-r") == 0 ||
				    strcmp(a, "--reference") == 0) {
					i++;	/* 读选项值 */
					continue;
				}
				if (strncmp(a, "--date=", 7) == 0 ||
				    strncmp(a, "--file=", 7) == 0 ||
				    strncmp(a, "--reference=", 12) == 0)
					continue;
				if (a[0] != '-' && a[0] != '+') {
					set = 1;
					break;
				}
			}
			if (set) {
				d = AI_D3;
				why = "system_time_write";
				goto out;
			}
		}
		/* hostname：无参/只读选项 D0；-b/--boot、-F/--file、
		 * 任何非选项位置参数为设置形态 → D3 */
		if (strcmp(cmd, "hostname") == 0) {
			int i, set = 0;

			for (i = 0; i < cl.argc; i++) {
				const char *a = cl.argv[i];

				if (strcmp(a, "-b") == 0 ||
				    strcmp(a, "--boot") == 0 ||
				    strcmp(a, "-F") == 0 ||
				    strcmp(a, "--file") == 0 ||
				    strncmp(a, "--file=", 7) == 0 ||
				    (a[0] != '-' && a[0])) {
					set = 1;
					break;
				}
			}
			if (set) {
				d = AI_D3;
				why = "hostname_write";
				goto out;
			}
		}
		/* dmesg：清日志/控制台级别/开关控制台 → D3 */
		if (strcmp(cmd, "dmesg") == 0) {
			static const char *const wflags[] = {
				"-c", "-C", "--clear", "--read-clear", "-n",
				"--console-level", "-D", "--console-off",
				"-E", "--console-on", NULL,
			};
			int i, set = 0;

			for (i = 0; i < cl.argc; i++) {
				const char *a = cl.argv[i];

				if (cmd_in(a, wflags) ||
				    strncmp(a, "--console-level=", 16) == 0 ||
				    (a[0] == '-' && a[1] == 'n' && a[2])) {
					set = 1;
					break;
				}
			}
			if (set) {
				d = AI_D3;
				why = "log_destruction";
				goto out;
			}
		}
		/* smartctl：自检/设置/abort → D3；-a 等读仍 D0 */
		if (strcmp(cmd, "smartctl") == 0) {
			static const char *const wflags[] = {
				"-t", "--test", "-s", "--set", "-o",
				"--offlineauto", "-S", "--saveauto", "-X",
				"--abort", NULL,
			};
			int i, set = 0;

			for (i = 0; i < cl.argc; i++) {
				const char *a = cl.argv[i];

				if (cmd_in(a, wflags) ||
				    strncmp(a, "--test=", 7) == 0 ||
				    strncmp(a, "--set=", 6) == 0 ||
				    strncmp(a, "--offlineauto=", 14) == 0 ||
				    strncmp(a, "--saveauto=", 11) == 0) {
					set = 1;
					break;
				}
			}
			if (set) {
				d = AI_D3;
				why = "disk_control";
				goto out;
			}
		}
		/* ss：-K/--kill 强制关闭 socket → D3；-D/--diag 仍 D2 */
		if (strcmp(cmd, "ss") == 0) {
			int i, set = 0;

			for (i = 0; i < cl.argc; i++) {
				const char *a = cl.argv[i];

				if (strcmp(a, "-K") == 0 ||
				    strcmp(a, "--kill") == 0 ||
				    (a[0] == '-' && a[1] != '-' &&
				     strchr(a + 1, 'K'))) {
					set = 1;
					break;
				}
			}
			if (set) {
				d = AI_D3;
				why = "socket_kill";
				goto out;
			}
		}
		if (strcmp(cmd, "conntrack") == 0 &&
		    (argv_has(&cl, "-F") || argv_has(&cl, "--flush") ||
		     argv_has(&cl, "-D") || argv_has(&cl, "--delete") ||
		     argv_has(&cl, "-U") || argv_has(&cl, "--update") ||
		     argv_has(&cl, "-I"))) {
			d = AI_D3;
			why = "firewall_state_write";
			goto out;
		}
		if (strcmp(cmd, "ip") == 0 && cl.argc >= 2 &&
		    ip_write_verb(cl.argv[1])) {
			d = AI_D3;
			why = "network_write";
			goto out;
		}
		if (strcmp(cmd, "ethtool") == 0 &&
		    (argv_has(&cl, "-s") || argv_has(&cl, "--change"))) {
			d = AI_D3;
			why = "network_write";
			goto out;
		}
		if (strcmp(cmd, "ifconfig") == 0 && cl.argc >= 2 &&
		    ip_write_verb(cl.argv[1])) {
			d = AI_D3;
			why = "network_write";
			goto out;
		}
		if (cmd_in(cmd, (const char *const[]){
				"iptables", "ip6tables", "ufw", "firewall-cmd",
				"route", "nmcli", NULL })) {
			d = AI_D3;
			why = "network_write";
			goto out;
		}
		if ((strcmp(cmd, "hostnamectl") == 0 ||
		     strcmp(cmd, "timedatectl") == 0 ||
		     strcmp(cmd, "resolvectl") == 0) && cl.argc >= 1 &&
		    strncmp(cl.argv[0], "set-", 4) == 0) {
			d = AI_D3;
			why = "system_config_write";
			goto out;
		}
		if (strcmp(cmd, "journalctl") == 0) {
			int i;

			for (i = 0; i < cl.argc; i++) {
				if (strncmp(cl.argv[i], "--vacuum", 8) == 0) {
					d = AI_D3;
					why = "log_destruction";
					goto out;
				}
			}
		}
		if (cmd_in(cmd, (const char *const[]){
				"mkfs", "mkfs.ext4", "mkfs.xfs", "fdisk",
				"parted", "sgdisk", "wipefs", NULL })) {
			d = AI_D3;
			why = "storage_destructive";
			goto out;
		}
		if (strcmp(cmd, "dd") == 0) {
			int i;

			for (i = 0; i < cl.argc; i++) {
				if (strncmp(cl.argv[i], "of=/dev/", 8) == 0) {
					d = AI_D3;
					why = "block_device_write";
					goto out;
				}
			}
		}
	}

	/* 路径级覆盖 */
	if (target) {
		/* 路径升级只对写动作（D1+）；R 读命令（cat/grep /etc/shadow）
		 * 保持 D0，不因读路径被误升级。 */
		if (d >= AI_D1 && path_is_d4(target)) {
			d = AI_D4;
			why = "identity_boot_path";
			goto out;
		}
		if (d >= AI_D2 && path_is_system(target)) {
			d = AI_D3;
			why = "system_path_write";
			goto out;
		}
	}

	if (d == AI_D0 && strcmp(why, "risk_mapping") == 0)
		why = "read_only";
out:
	cmdline_free(&cl);
	if (target_path)
		*target_path = target;
	else
		free(target);
	if (reason)
		*reason = why;
	(void)domain;
	return d;
}

void ai_lease_exec_domains(const char *args_json, char *buf, size_t cap)
{
	struct cmdline cl;
	const char *dom = NULL;
	static const char *const fs_cmds[] = {
		"ls", "cat", "head", "tail", "grep", "stat", "wc", "sort",
		"uniq", "cut", "find", "mkdir", "touch", "cp", "mv", "ln",
		"sed", "tee", "tar", "gzip", "gunzip", "gcc", "cc", "rm",
		"chmod", "chown", "sync", "df", "du", "lsblk", "findmnt",
		"blkid", "dumpe2fs", "quota", "repquota", "pvs", "vgs",
		"lvs", NULL };
	static const char *const net_cmds[] = {
		"ss", "curl", "ping", "traceroute", "ip", "ethtool", "nft",
		"tc", "conntrack", "resolvectl", "hostname", NULL };
	static const char *const sys_cmds[] = {
		"ps", "free", "uname", "uptime", "date", "dmesg", "journalctl",
		"systemctl", "systemd-analyze", "timedatectl", "hostnamectl",
		"getent", "id", "pidof", "pgrep", "kill", "mount", "umount",
		"swapon", "swapoff", "fstrim", "setquota", "apt", "dpkg",
		"crontab", "aik-upgrade", "aik-backup", "aik-reset", "python3",
		"passwd", "useradd", "usermod", "userdel", "groupadd",
		"groupmod", "groupdel", "aa-enforce", "aa-complain",
		"aa-disable", "visudo", NULL };

	if (!buf || !cap)
		return;
	parse_exec_args(args_json, &cl);
	if (!cl.cmd)
		return;
	if (cmd_in(cl.cmd, fs_cmds))
		dom = "fs";
	else if (cmd_in(cl.cmd, net_cmds))
		dom = "netsec";
	else if (cmd_in(cl.cmd, sys_cmds))
		dom = "sysadmin";
	if (dom) {
		size_t cur = strlen(buf);
		char needle[64];

		snprintf(needle, sizeof(needle), "%s%s", cur ? "," : "", dom);
		if (!strstr(buf, dom) && cur + strlen(needle) + 1 < cap)
			strcat(buf, needle);
	}
	cmdline_free(&cl);
}

void ai_lease_action_text(const struct ai_lease_action *act,
			  char *buf, size_t cap)
{
	char cmd[512];

	if (!buf || !cap)
		return;
	cmd[0] = '\0';
	if (act && act->args_json) {
		struct cmdline cl;

		parse_exec_args(act->args_json, &cl);
		if (cl.cmd) {
			size_t off = 0;
			int i;

			off += (size_t)snprintf(cmd + off, sizeof(cmd) - off,
						"%s", cl.cmd);
			for (i = 0; i < cl.argc && off < sizeof(cmd); i++)
				off += (size_t)snprintf(cmd + off,
							sizeof(cmd) - off,
							" %s", cl.argv[i]);
		}
		cmdline_free(&cl);
	}
	snprintf(buf, cap, "%s%s%s", act && act->tool ? act->tool : "?",
		 (act && act->target) ? " " : "",
		 (act && act->target) ? act->target : cmd);
}

/* ---- scope 匹配 ---- */

static int action_domain_match(const char *domains, const char *domain)
{
	const char *p = domains;
	size_t n = strlen(domain);

	if (!domains || !domain[0])
		return 0;
	while (*p) {
		const char *comma = strchr(p, ',');
		size_t len = comma ? (size_t)(comma - p) : strlen(p);

		if (len == n && strncmp(p, domain, n) == 0)
			return 1;
		if (!comma)
			break;
		p = comma + 1;
	}
	return 0;
}

static int path_prefix_ok(const char *target, const char *prefix)
{
	size_t n = strlen(prefix);

	if (!target || target[0] != '/')
		return 0;
	while (n > 1 && prefix[n - 1] == '/')
		n--;
	if (strncmp(target, prefix, n) != 0)
		return 0;
	return target[n] == '\0' || target[n] == '/';
}

enum scope_access {
	SCOPE_ACC_NONE = 0,
	SCOPE_ACC_READ,
	SCOPE_ACC_WRITE,
	SCOPE_ACC_EXEC,
	SCOPE_ACC_ADVISORY,
};

static enum scope_access access_parse(const char *s)
{
	if (strcmp(s, "read") == 0)
		return SCOPE_ACC_READ;
	if (strcmp(s, "write") == 0)
		return SCOPE_ACC_WRITE;
	if (strcmp(s, "exec") == 0)
		return SCOPE_ACC_EXEC;
	if (strcmp(s, "advisory") == 0)
		return SCOPE_ACC_ADVISORY;
	return SCOPE_ACC_NONE;
}

/* 判定单条 scope 是否覆盖动作；命中返回 1 并填 hit */
static int scope_match_one(const char *scope, const struct ai_lease_action *act,
			   enum scope_access act_acc, char *hit, size_t hitlen)
{
	char copy[AI_LEASE_SCOPE_LEN];
	char *parts[4];
	int np = 0;
	char *p;
	enum scope_access acc = SCOPE_ACC_NONE;
	const char *domain;
	const char *sub = NULL;
	const char *target = act->target;

	snprintf(copy, sizeof(copy), "%s", scope);
	p = copy;
	while (np < 4 && p) {
		parts[np++] = strsep(&p, ":");
	}
	if (np >= 2) {
		enum scope_access a = access_parse(parts[np - 1]);

		if (a != SCOPE_ACC_NONE) {
			acc = a;
			np--;
		}
	}
	if (np == 0)
		return 0;
	domain = parts[0];
	if (!action_domain_match(act->domain, domain))
		return 0;
	if (np >= 2)
		sub = parts[1];
	if (sub && sub[0]) {
		if (strchr(sub, '/')) {
			if (!path_prefix_ok(target, sub))
				return 0;
		} else {
			int found = 0;

			if (target && strstr(target, sub))
				found = 1;
			if (!found && act->tool && strstr(act->tool, sub))
				found = 1;
			if (!found)
				return 0;
		}
	}
	switch (acc) {
	case SCOPE_ACC_NONE:
		break;
	case SCOPE_ACC_READ:
		/* read 只允许 D0 */
		if (act->danger != AI_D0)
			return 0;
		break;
	case SCOPE_ACC_ADVISORY:
		if (act->danger != AI_D0)
			return 0;
		break;
	case SCOPE_ACC_WRITE:
		if (act_acc != SCOPE_ACC_WRITE && act_acc != SCOPE_ACC_EXEC)
			return 0;
		break;
	case SCOPE_ACC_EXEC:
		if (act_acc != SCOPE_ACC_EXEC)
			return 0;
		break;
	}
	if (hit && hitlen)
		snprintf(hit, hitlen, "%s", scope);
	return 1;
}

static int scope_covered(const struct ai_lease *l,
			 const struct ai_lease_action *act,
			 char *hit, size_t hitlen)
{
	enum scope_access act_acc;
	int i;

	if (act->danger == AI_D0)
		act_acc = SCOPE_ACC_READ;
	else if (act->is_exec)
		act_acc = SCOPE_ACC_EXEC;
	else
		act_acc = SCOPE_ACC_WRITE;
	if (hit && hitlen)
		hit[0] = '\0';
	for (i = 0; i < l->scope_count; i++) {
		if (strcmp(l->scope[i], "*") == 0) {
			if (hit && hitlen)
				snprintf(hit, hitlen, "*");
			return 1;
		}
		if (scope_match_one(l->scope[i], act, act_acc, hit, hitlen))
			return 1;
	}
	return 0;
}

/* ---- 纯判定 ---- */

static void verdict_set(struct ai_lease_verdict *v, enum ai_lease_decision d,
			const char *reason, const struct ai_lease *l,
			enum ai_danger danger, const char *hit,
			const char *rollback)
{
	memset(v, 0, sizeof(*v));
	v->decision = d;
	snprintf(v->reason, sizeof(v->reason), "%s", reason ? reason : "?");
	if (l)
		snprintf(v->lease_id, sizeof(v->lease_id), "%s", l->lease_id);
	v->danger = danger;
	snprintf(v->scope_hit, sizeof(v->scope_hit), "%s", hit ? hit : "");
	snprintf(v->rollback_hint, sizeof(v->rollback_hint), "%s",
		 rollback ? rollback : "");
	snprintf(v->confirmation, sizeof(v->confirmation), "none");
}

static const char *rollback_for(enum ai_danger d)
{
	switch (d) {
	case AI_D2: return tr(TR_LEASE_ROLLBACK_D2);
	case AI_D3: return tr(TR_LEASE_ROLLBACK_D3);
	case AI_D4: return tr(TR_LEASE_ROLLBACK_D4);
	default: return "";
	}
}

enum ai_lease_decision ai_lease_decide(const struct ai_lease_ctx *ctx,
				       uid_t uid,
				       const struct ai_lease_action *act,
				       long long now,
				       struct ai_lease_verdict *v)
{
	const struct ai_lease *l = NULL;
	int use_lease = 0;
	int revoked = 0;
	int expired = 0;
	char hit[AI_LEASE_HIT_MAX];
	const char *reason = "?";
	char name[128];

	if (!ctx || !act || !v)
		return AI_LEASE_DENY;
	hit[0] = '\0';

	/* 撤销优先于一切（D0 只读仍放行，见下） */
	if (ctx->mode == AI_LEASE_MODE_EXPLICIT) {
		l = &ctx->lease;
		if (!ctx->loaded)
			revoked = 1;	/* 加载失败：按不可用处理 */
		else {
			if (l->revoked)
				revoked = 1;
			if (l->expires_at <= now)
				expired = 1;
			if (l->has_issued_at &&
			    l->issued_at > now + AI_LEASE_CLOCK_SKEW)
				expired = 1;
		}
	} else if (ctx->mode == AI_LEASE_MODE_EPHEMERAL) {
		l = &ctx->lease;
		if (l->expires_at <= now)
			expired = 1;
	}

	/* 0. D4 + 非 root：直接拒绝，不给非 root 弹 D4 确认
	 * （即使合成工具的 risk 是 W1；外层档位可能先 DENY，但这里
	 * 给出明确的 d4_requires_root 语义）。 */
	if (act->danger == AI_D4 && uid != 0) {
		verdict_set(v, AI_LEASE_DENY, "d4_requires_root", l,
			    act->danger, NULL, rollback_for(act->danger));
		return AI_LEASE_DENY;
	}

	/* 1. 外层档位：租约不能提权 */
	if (ai_policy_check(uid, act->risk) == AI_POLICY_DENY) {
		verdict_set(v, AI_LEASE_DENY, "policy_tier", l, act->danger,
			    NULL, rollback_for(act->danger));
		return AI_LEASE_DENY;
	}

	/* 2. plan 只读优先：租约不能绕过 */
	if (act->plan_mode && act->danger > AI_D0) {
		verdict_set(v, AI_LEASE_DENY, "plan_read_only", l, act->danger,
			    NULL, rollback_for(act->danger));
		return AI_LEASE_DENY;
	}

	/* 3. worker：D2+ 一律拒绝（即使父租约允许） */
	if (act->worker && act->danger >= AI_D2) {
		verdict_set(v, AI_LEASE_DENY, "sandbox_child_d2", l,
			    act->danger, NULL, rollback_for(act->danger));
		return AI_LEASE_DENY;
	}

	/* 4. D0：全知，租约过期/撤销也不阻断读 */
	if (act->danger == AI_D0) {
		verdict_set(v, AI_LEASE_ALLOW, "danger_d0", l, AI_D0, NULL,
			    NULL);
		return AI_LEASE_ALLOW;
	}

	/* 5. 显式租约：revoked/expired/principal 一律拒绝 */
	if (ctx->mode == AI_LEASE_MODE_EXPLICIT) {
		if (revoked) {
			verdict_set(v, AI_LEASE_DENY, "lease_revoked", l,
				    act->danger, NULL,
				    rollback_for(act->danger));
			return AI_LEASE_DENY;
		}
		if (expired) {
			verdict_set(v, AI_LEASE_DENY, "lease_expired", l,
				    act->danger, NULL,
				    rollback_for(act->danger));
			return AI_LEASE_DENY;
		}
		if (strcmp(l->principal, "root") == 0) {
			if (uid != 0) {
				verdict_set(v, AI_LEASE_DENY,
					    "lease_principal_mismatch", l,
					    act->danger, NULL,
					    rollback_for(act->danger));
				return AI_LEASE_DENY;
			}
		} else if (uid != 0) {
			if (uid_to_name(uid, name, sizeof(name)) != 0 ||
			    strcmp(name, l->principal) != 0) {
				verdict_set(v, AI_LEASE_DENY,
					    "lease_principal_mismatch", l,
					    act->danger, NULL,
					    rollback_for(act->danger));
				return AI_LEASE_DENY;
			}
		}
		/* root 可使用任意属主的租约（它本来就能读/改）；非 root 只
		 * 能用自己或 root 属主的文件（loader 已校验）。 */
		if (uid != 0 && ctx->file_owner != 0 &&
		    ctx->file_owner != uid) {
			verdict_set(v, AI_LEASE_DENY, "lease_owner_mismatch", l,
				    act->danger, NULL,
				    rollback_for(act->danger));
			return AI_LEASE_DENY;
		}
		if (!scope_covered(l, act, hit, sizeof(hit))) {
			verdict_set(v, AI_LEASE_DENY, "lease_scope_denied", l,
				    act->danger, NULL,
				    rollback_for(act->danger));
			return AI_LEASE_DENY;
		}
		/* D4 永远不能由租约自动放行：D3 ceiling 可升级为人工 D4 */
		if (act->danger == AI_D4) {
			if (l->risk_ceiling >= AI_D3) {
				verdict_set(v, AI_LEASE_CONFIRM_D4,
					    "lease_d4_manual", l, AI_D4, hit,
					    rollback_for(AI_D4));
				return AI_LEASE_CONFIRM_D4;
			}
			verdict_set(v, AI_LEASE_DENY, "lease_ceiling_denied", l,
				    act->danger, hit,
				    rollback_for(act->danger));
			return AI_LEASE_DENY;
		}
		if (act->danger > l->risk_ceiling) {
			verdict_set(v, AI_LEASE_DENY, "lease_ceiling_denied", l,
				    act->danger, hit,
				    rollback_for(act->danger));
			return AI_LEASE_DENY;
		}
		use_lease = 1;
		reason = "lease_allow";
	} else if (ctx->mode == AI_LEASE_MODE_EPHEMERAL) {
		if (expired) {
			/* -y 只是 D2 短租约：过期后回落到 NONE 语义，
			 * 不能把长会话的 D1 写也锁死。 */
			reason = "ephemeral_expired";
		} else if (act->danger <= AI_D2) {
			verdict_set(v, AI_LEASE_ALLOW, "ephemeral_d2", l,
				    act->danger, NULL, NULL);
			snprintf(v->confirmation,
				 sizeof(v->confirmation), "ephemeral");
			return AI_LEASE_ALLOW;
		} else {
			reason = "ephemeral_escalate";
		}
	} else {
		/* NONE：D1 自动；D2/D3 确认；D4 强确认 */
		if (act->danger == AI_D1)
			reason = "danger_d1";
		else if (act->danger == AI_D4)
			reason = "danger_d4";
		else
			reason = "no_lease";
	}

	/* 非显式租约的 D1 自动（NONE 与 ephemeral 过期回落） */
	if (ctx->mode != AI_LEASE_MODE_EXPLICIT && act->danger == AI_D1) {
		verdict_set(v, AI_LEASE_ALLOW, reason, NULL, AI_D1, NULL,
			    NULL);
		return AI_LEASE_ALLOW;
	}

	if (act->danger == AI_D4) {
		verdict_set(v, AI_LEASE_CONFIRM_D4,
			    use_lease ? "lease_d4_manual" : reason, l,
			    AI_D4, hit, rollback_for(AI_D4));
		return AI_LEASE_CONFIRM_D4;
	}
	if (use_lease) {
		verdict_set(v, AI_LEASE_ALLOW, reason, l, act->danger, hit,
			    NULL);
		return AI_LEASE_ALLOW;
	}
	verdict_set(v, AI_LEASE_CONFIRM, reason, l, act->danger, hit,
		    rollback_for(act->danger));
	return AI_LEASE_CONFIRM;
}

/* ---- 非 TTY 确认协议 ---- */

static int rand_hex(char *buf, size_t n, size_t nbytes)
{
	unsigned char raw[32];
	int fd;
	size_t i, off = 0;
	static unsigned long counter;

	if (nbytes > sizeof(raw))
		nbytes = sizeof(raw);
	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		while (off < nbytes) {
			ssize_t r = read(fd, raw + off, nbytes - off);

			if (r <= 0) {
				if (r < 0 && errno == EINTR)
					continue;
				break;
			}
			off += (size_t)r;
		}
		close(fd);
	}
	if (off < nbytes) {
		/* 兜底：pid/time/counter 混合（仅测试/极端环境） */
		struct timespec ts;
		unsigned long mix;

		clock_gettime(CLOCK_REALTIME, &ts);
		mix = (unsigned long)ts.tv_nsec ^
		      ((unsigned long)getpid() << 16) ^
		      (++counter * 2654435761UL);
		for (i = off; i < nbytes; i++) {
			raw[i] = (unsigned char)(mix >> ((i % sizeof(mix)) * 8));
			mix = mix * 6364136223846793005ULL + 1;
		}
	}
	for (i = 0; i < nbytes; i++)
		snprintf(buf + i * 2, n - i * 2, "%02x", raw[i]);
	return 0;
}

static void confirm_subdir(char *buf, size_t n, const char *sub)
{
	char base[512];

	ai_lease_confirm_dir(base, sizeof(base));
	snprintf(buf, n, "%s/%s", base, sub);
}

static int confirm_ensure_dirs(char *err, size_t errlen)
{
	char base[512], p[PATH_MAX];

	ai_lease_confirm_dir(base, sizeof(base));
	if (mkdirs_0700(base, err, errlen) != 0)
		return -1;
	confirm_subdir(p, sizeof(p), "pending");
	if (mkdirs_0700(p, err, errlen) != 0)
		return -1;
	confirm_subdir(p, sizeof(p), "approved");
	if (mkdirs_0700(p, err, errlen) != 0)
		return -1;
	confirm_subdir(p, sizeof(p), "consumed");
	if (mkdirs_0700(p, err, errlen) != 0)
		return -1;
	confirm_subdir(p, sizeof(p), "denied");
	if (mkdirs_0700(p, err, errlen) != 0)
		return -1;
	return 0;
}

static int confirm_dirs_trusted(char *err, size_t errlen)
{
	char base[512];
	int allow = env_override_is_set("AIKERNEL_CONFIRM_DIR");
	uid_t uid = getuid();

	ai_lease_confirm_dir(base, sizeof(base));
	if (dir_trusted(base, uid, allow, err, errlen) != 0)
		return -1;
	return 0;
}

/* 原子写文件：temp + link（不覆盖）或 rename（覆盖） */
static int atomic_write_file(const char *dir, const char *name,
			     const char *data, int replace,
			     char *err, size_t errlen)
{
	char tmp[PATH_MAX], final[PATH_MAX];
	int fd;
	size_t len = strlen(data), off = 0;
	int rc = -1;

	if (snprintf(tmp, sizeof(tmp), "%s/.%s.tmp.%d", dir, name,
		     (int)getpid()) >= (int)sizeof(tmp) ||
	    snprintf(final, sizeof(final), "%s/%s", dir, name) >=
	    (int)sizeof(final)) {
		set_err(err, errlen, "路径过长");
		return -1;
	}
	unlink(tmp);
	fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
		  0600);
	if (fd < 0) {
		set_err(err, errlen, "创建临时文件 %s 失败：%s", tmp,
			strerror(errno));
		return -1;
	}
	while (off < len) {
		ssize_t w = write(fd, data + off, len - off);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			set_err(err, errlen, "写入 %s 失败：%s", tmp,
				strerror(errno));
			goto out;
		}
		off += (size_t)w;
	}
	if (fsync(fd) != 0) {
		set_err(err, errlen, "fsync %s 失败：%s", tmp, strerror(errno));
		goto out;
	}
	close(fd);
	fd = -1;
	if (replace) {
		if (rename(tmp, final) != 0) {
			set_err(err, errlen, "rename %s 失败：%s", final,
				strerror(errno));
			goto out;
		}
	} else {
		if (link(tmp, final) != 0) {
			set_err(err, errlen, "创建 %s 失败：%s", final,
				strerror(errno));
			goto out;
		}
		if (unlink(tmp) != 0) {
			/* 已 link 成功；残留 temp 可后续清理 */
		}
	}
	fsync_dir(dir);
	rc = 0;
out:
	if (fd >= 0)
		close(fd);
	if (rc != 0)
		unlink(tmp);
	return rc;
}

static char *json_dup_escaped(const char *s)
{
	char *e = ai_json_escape(s ? s : "");

	return e ? e : strdup("");
}

int ai_lease_confirm_pending_write(const struct ai_lease_action *act,
				   enum ai_danger danger,
				   const char *lease_id,
				   const char *impact,
				   const char *rollback,
				   char *nonce, size_t noncelen,
				   char *err, size_t errlen)
{
	char nbuf[65];
	char action[512];
	char *e_tool, *e_args, *e_act, *e_impact, *e_rb, *e_lease;
	char *json;
	char dir[PATH_MAX];
	char name[96];
	time_t now = time(NULL);
	int rc;

	if (confirm_ensure_dirs(err, errlen) != 0)
		return -1;
	if (rand_hex(nbuf, sizeof(nbuf), 16) != 0) {
		set_err(err, errlen, "生成 nonce 失败");
		return -1;
	}
	ai_lease_action_text(act, action, sizeof(action));
	e_tool = json_dup_escaped(act && act->tool ? act->tool : "?");
	e_args = json_dup_escaped(act && act->args_json ? act->args_json : "{}");
	e_act = json_dup_escaped(action);
	e_impact = json_dup_escaped(impact ? impact : "");
	e_rb = json_dup_escaped(rollback ? rollback : "");
	e_lease = json_dup_escaped(lease_id ? lease_id : "");
	if (!e_tool || !e_args || !e_act || !e_impact || !e_rb || !e_lease) {
		free(e_tool); free(e_args); free(e_act);
		free(e_impact); free(e_rb); free(e_lease);
		set_err(err, errlen, "内存不足");
		return -1;
	}
	if (asprintf(&json,
		     "{\"nonce\":\"%s\",\"tool\":\"%s\",\"args_json\":\"%s\","
		     "\"danger\":\"%s\",\"lease_id\":%s%s%s,"
		     "\"created_at\":%lld,\"expires_at\":%lld,\"uid\":%u,"
		     "\"action\":\"%s\",\"impact\":\"%s\",\"rollback\":\"%s\","
		     "\"question\":\"%s\"}\n",
		     nbuf, e_tool, e_args, ai_danger_name(danger),
		     (lease_id && lease_id[0]) ? "\"" : "",
		     (lease_id && lease_id[0]) ? e_lease : "null",
		     (lease_id && lease_id[0]) ? "\"" : "",
		     (long long)now,
		     (long long)now + AI_LEASE_CONFIRM_TTL,
		     (unsigned)getuid(), e_act, e_impact, e_rb,
		     tr(TR_LEASE_CONFIRM_QUESTION)) < 0) {
		free(e_tool); free(e_args); free(e_act);
		free(e_impact); free(e_rb); free(e_lease);
		set_err(err, errlen, "内存不足");
		return -1;
	}
	free(e_tool); free(e_args); free(e_act);
	free(e_impact); free(e_rb); free(e_lease);
	confirm_subdir(dir, sizeof(dir), "pending");
	snprintf(name, sizeof(name), "%s.json", nbuf);
	rc = atomic_write_file(dir, name, json, 0, err, errlen);
	free(json);
	if (rc != 0)
		return -1;
	if (nonce && noncelen)
		snprintf(nonce, noncelen, "%s", nbuf);
	return 0;
}

int ai_lease_confirm_pending_list(char *buf, size_t cap,
				  char *err, size_t errlen)
{
	char dir[PATH_MAX];
	DIR *d;
	struct dirent *e;
	size_t off = 0;

	if (!buf || !cap)
		return -1;
	buf[0] = '\0';
	confirm_subdir(dir, sizeof(dir), "pending");
	if (access(dir, F_OK) != 0 && errno == ENOENT)
		return 0;	/* 无 pending：空集 */
	if (confirm_dirs_trusted(err, errlen) != 0)
		return -1;
	d = opendir(dir);
	if (!d) {
		if (errno == ENOENT)
			return 0;	/* 无 pending：空集 */
		set_err(err, errlen, "打开 pending 目录失败：%s",
			strerror(errno));
		return -1;
	}
	while ((e = readdir(d)) != NULL) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		off += (size_t)snprintf(buf + off, off < cap ? cap - off : 0,
					"%s\n", e->d_name);
		if (off >= cap)
			break;
	}
	closedir(d);
	return 0;
}

/* 读取 pending/approved JSON；返回内容与文件属主 */
static int read_confirm_file(const char *sub, const char *nonce, char **out,
			     uid_t *owner, char *err, size_t errlen)
{
	char dir[PATH_MAX], path[PATH_MAX];
	int allow = env_override_is_set("AIKERNEL_CONFIRM_DIR");
	char *json = NULL;

	if (!ai_lease_id_valid(nonce) || strlen(nonce) < 16) {
		set_err(err, errlen, "非法 nonce");
		return -1;
	}
	confirm_subdir(dir, sizeof(dir), sub);
	if (dir_trusted(dir, getuid(), allow, err, errlen) != 0)
		return -1;
	if (snprintf(path, sizeof(path), "%s/%s.json", dir, nonce) >=
	    (int)sizeof(path)) {
		set_err(err, errlen, "路径过长");
		return -1;
	}
	if (read_trusted_file(path, getuid(), allow, &json, err, errlen) != 0)
		return -1;
	if (owner) {
		struct stat st;

		if (lstat(path, &st) == 0)
			*owner = st.st_uid;
	}
	*out = json;
	return 0;
}

int ai_lease_confirm_pending_danger(const char *nonce, enum ai_danger *out,
				    char *err, size_t errlen)
{
	char *json = NULL;
	char tmp[16];
	int rc;

	if (!out)
		return -1;
	rc = read_confirm_file("pending", nonce, &json, NULL, err, errlen);
	if (rc != 0)
		return rc;
	if (json_str(json, strlen(json), "danger", tmp, sizeof(tmp), 1,
		     err, errlen) != 0 ||
	    ai_danger_parse(tmp, out) != 0) {
		set_err(err, errlen, "pending danger 非法");
		free(json);
		return -1;
	}
	free(json);
	return 0;
}

int ai_lease_confirm_approve(const char *nonce, int yes, const char *phrase,
			     char *err, size_t errlen)
{
	char *json = NULL;
	char danger_s[16];
	enum ai_danger danger;
	long long expires;
	char tool[128], args[8192], lease_id[AI_LEASE_ID_MAX];
	char user[64];
	char dir[PATH_MAX], name[96];
	char *json2;
	char phrase_req[128];
	int allow = env_override_is_set("AIKERNEL_CONFIRM_DIR");
	uid_t owner = 0;
	time_t now = time(NULL);
	int rc = -1;

	if (read_confirm_file("pending", nonce, &json, &owner,
			      err, errlen) != 0)
		return -1;
	/* 生产确认文件必须 root 属主 */
	if (!allow && owner != 0) {
		set_err(err, errlen, "pending 文件必须属于 root");
		goto out;
	}
	if (json_str(json, strlen(json), "danger", danger_s,
		     sizeof(danger_s), 1, err, errlen) != 0 ||
	    ai_danger_parse(danger_s, &danger) != 0) {
		set_err(err, errlen, "pending danger 非法");
		goto out;
	}
	if (json_ll_field(json, strlen(json), "expires_at", &expires) != 0) {
		set_err(err, errlen, "pending expires_at 缺失/非数值");
		goto out;
	}
	if (expires <= (long long)now) {
		set_err(err, errlen, "pending 已过期");
		goto out;
	}
	if (json_str(json, strlen(json), "tool", tool, sizeof(tool), 1,
		     err, errlen) != 0 ||
	    json_str(json, strlen(json), "args_json", args, sizeof(args), 1,
		     err, errlen) != 0) {
		goto out;
	}
	json_str(json, strlen(json), "lease_id", lease_id,
		 sizeof(lease_id), 0, err, errlen);

	snprintf(phrase_req, sizeof(phrase_req), "CONFIRM D4 %s", nonce);
	if (danger == AI_D4) {
		if (!phrase || strcmp(phrase, phrase_req) != 0) {
			set_err(err, errlen,
				"D4 必须精确输入 \"%s\"", phrase_req);
			goto out;
		}
	} else if (yes && phrase && phrase[0] &&
		   strcmp(phrase, "yes") != 0 &&
		   strcmp(phrase, "no") != 0) {
		set_err(err, errlen, "非法确认短语");
		goto out;
	}

	if (uid_to_name(getuid(), user, sizeof(user)) != 0)
		snprintf(user, sizeof(user), "uid%u", (unsigned)getuid());
	{
		char *e_tool = json_dup_escaped(tool);
		char *e_args = json_dup_escaped(args);
		char *e_lease = json_dup_escaped(lease_id);
		char *e_user = json_dup_escaped(user);

		if (!e_tool || !e_args || !e_lease || !e_user) {
			free(e_tool); free(e_args); free(e_lease); free(e_user);
			set_err(err, errlen, "内存不足");
			goto out;
		}
		if (asprintf(&json2,
			     "{\"nonce\":\"%s\",\"tool\":\"%s\","
			     "\"args_json\":\"%s\",\"danger\":\"%s\","
			     "\"lease_id\":%s%s%s,\"expires_at\":%lld,"
			     "\"approved_at\":%lld,\"approved_by\":\"%s\","
			     "\"approved\":%s}\n",
			     nonce, e_tool, e_args, danger_s,
			     lease_id[0] ? "\"" : "",
			     lease_id[0] ? e_lease : "null",
			     lease_id[0] ? "\"" : "",
			     expires, (long long)now, e_user,
			     yes ? "true" : "false") < 0) {
			free(e_tool); free(e_args); free(e_lease); free(e_user);
			set_err(err, errlen, "内存不足");
			goto out;
		}
		free(e_tool); free(e_args); free(e_lease); free(e_user);
	}
	confirm_subdir(dir, sizeof(dir), yes ? "approved" : "denied");
	snprintf(name, sizeof(name), "%s.json", nonce);
	if (atomic_write_file(dir, name, json2, 0, err, errlen) != 0) {
		free(json2);
		goto out;
	}
	free(json2);
	/* 移除 pending（批准/拒绝都单次） */
	{
		char pdir[PATH_MAX], ppath[PATH_MAX + 96];

		confirm_subdir(pdir, sizeof(pdir), "pending");
		snprintf(ppath, sizeof(ppath), "%s/%s.json", pdir, nonce);
		unlink(ppath);
		fsync_dir(pdir);
	}
	rc = 0;
out:
	free(json);
	return rc;
}

/* 消费 approved：校验绑定 + 原子 rename 到 consumed */
static int confirm_consume(const struct ai_lease_action *act,
			   enum ai_danger danger, const char *lease_id,
			   const char *nonce, char *err, size_t errlen)
{
	char *json = NULL;
	char tool[128], args[8192], danger_s[16], lease[AI_LEASE_ID_MAX];
	long long expires;
	uid_t owner = 0;
	enum ai_danger ad;
	char adir[PATH_MAX], cdir[PATH_MAX];
	char from[PATH_MAX + 96], to[PATH_MAX + 96];
	int allow = env_override_is_set("AIKERNEL_CONFIRM_DIR");

	if (read_confirm_file("approved", nonce, &json, &owner,
			      err, errlen) != 0)
		return -1;
	if (!allow && owner != 0) {
		set_err(err, errlen, "approved 文件必须属于 root");
		free(json);
		return -1;
	}
	if (json_str(json, strlen(json), "tool", tool, sizeof(tool), 1,
		     err, errlen) != 0 ||
	    json_str(json, strlen(json), "args_json", args, sizeof(args), 1,
		     err, errlen) != 0 ||
	    json_str(json, strlen(json), "danger", danger_s,
		     sizeof(danger_s), 1, err, errlen) != 0 ||
	    json_ll_field(json, strlen(json), "expires_at", &expires) != 0) {
		free(json);
		return -1;
	}
	json_str(json, strlen(json), "lease_id", lease, sizeof(lease), 0,
		 err, errlen);
	free(json);

	if (ai_danger_parse(danger_s, &ad) != 0 || ad != danger) {
		set_err(err, errlen, "approved danger 不匹配");
		return -1;
	}
	if (expires <= (long long)time(NULL)) {
		set_err(err, errlen, "approved 已过期");
		return -1;
	}
	if (!act->tool || strcmp(tool, act->tool) != 0) {
		set_err(err, errlen, "approved tool 不匹配");
		return -1;
	}
	if (strcmp(args, act->args_json && act->args_json[0] ?
		   act->args_json : "{}") != 0) {
		set_err(err, errlen, "approved args_json 不匹配");
		return -1;
	}
	if ((lease_id ? lease_id : "")[0] == '\0') {
		if (lease[0] != '\0') {
			set_err(err, errlen, "approved lease_id 不匹配");
			return -1;
		}
	} else if (strcmp(lease, lease_id) != 0) {
		set_err(err, errlen, "approved lease_id 不匹配");
		return -1;
	}

	/* 原子单次消费：rename approved → consumed */
	confirm_subdir(adir, sizeof(adir), "approved");
	confirm_subdir(cdir, sizeof(cdir), "consumed");
	snprintf(from, sizeof(from), "%s/%s.json", adir, nonce);
	snprintf(to, sizeof(to), "%s/%s.json", cdir, nonce);
	if (rename(from, to) != 0) {
		set_err(err, errlen, "approved 已使用或不可消费：%s",
			strerror(errno));
		return -1;
	}
	fsync_dir(adir);
	fsync_dir(cdir);
	return 0;
}

/* ---- TTY 确认 ---- */

static int read_line_ms(char *buf, size_t cap, int timeout_ms)
{
	long long deadline;
	size_t n = 0;

	{
		struct timespec ts;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		deadline = ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL +
			   timeout_ms;
	}
	while (n + 1 < cap) {
		fd_set rf;
		struct timeval tv;
		long long now;
		struct timespec ts;
		int sr;
		char c;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		now = ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
		if (now >= deadline)
			break;
		FD_ZERO(&rf);
		FD_SET(STDIN_FILENO, &rf);
		tv.tv_sec = (long)((deadline - now) / 1000);
		tv.tv_usec = (long)(((deadline - now) % 1000) * 1000);
		sr = select(STDIN_FILENO + 1, &rf, NULL, NULL, &tv);
		if (sr < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (sr == 0)
			break;
		{
			ssize_t r = read(STDIN_FILENO, &c, 1);

			if (r <= 0)
				break;
		}
		if (c == '\n')
			break;
		if (c == '\r')
			continue;
		buf[n++] = c;
	}
	buf[n] = '\0';
	/* 行尾 CRLF 去除 */
	while (n > 0 && (buf[n - 1] == '\r' || buf[n - 1] == '\n'))
		buf[--n] = '\0';
	return (int)n;
}

static int tty_confirm(const struct ai_lease_action *act,
		       const struct ai_lease_verdict *v, const char *impact,
		       const char *rollback, char *err, size_t errlen)
{
	char line[256];

	fprintf(stderr, tr(TR_LEASE_PANEL),
		act->tool ? act->tool : "?",
		ai_danger_name(v->danger),
		v->lease_id[0] ? v->lease_id : "-",
		impact && impact[0] ? impact : tr(TR_W2_IMPACT_FALLBACK),
		rollback && rollback[0] ? rollback : v->rollback_hint);
	if (v->decision == AI_LEASE_CONFIRM_D4) {
		fprintf(stderr, tr(TR_LEASE_D4_PROMPT),
			act->tool ? act->tool : "?");
		fflush(stderr);
		read_line_ms(line, sizeof(line), 120000);
		{
			char req[256];

			snprintf(req, sizeof(req), "CONFIRM D4 %s",
				 act->tool ? act->tool : "?");
			if (strcmp(line, req) != 0) {
				fprintf(stderr, "%s", tr(TR_LEASE_D4_MISMATCH));
				set_err(err, errlen, "D4 确认短语不匹配");
				return 0;
			}
		}
		return 1;
	}
	fprintf(stderr, "%s", tr(TR_LEASE_CONFIRM_YN));
	fflush(stderr);
	read_line_ms(line, sizeof(line), 8000);
	if (line[0] == 'y' || line[0] == 'Y')
		return 1;
	set_err(err, errlen, "用户拒绝");
	return 0;
}

/* ---- 网关 ---- */

static char g_last_lease[AI_LEASE_ID_MAX];
static char g_last_danger[8];
static char g_last_confirm[AI_LEASE_CONFIRM_MAX];
static char g_last_reason[AI_LEASE_REASON_MAX];
static char g_last_scope[AI_LEASE_HIT_MAX];

void ai_lease_last_reset(void)
{
	g_last_lease[0] = '\0';
	g_last_danger[0] = '\0';
	g_last_confirm[0] = '\0';
	g_last_reason[0] = '\0';
	g_last_scope[0] = '\0';
}

const char *ai_lease_last_lease_id(void)
{
	return g_last_lease[0] ? g_last_lease : NULL;
}

const char *ai_lease_last_danger(void)
{
	return g_last_danger[0] ? g_last_danger : NULL;
}

const char *ai_lease_last_confirm_source(void)
{
	return g_last_confirm[0] ? g_last_confirm : NULL;
}

const char *ai_lease_last_reason(void)
{
	return g_last_reason[0] ? g_last_reason : NULL;
}

const char *ai_lease_last_scope_hit(void)
{
	return g_last_scope[0] ? g_last_scope : NULL;
}

static void gate_audit(uid_t uid, const char *tool, const char *args,
		       const char *result, const struct ai_lease_verdict *v,
		       const char *confirm)
{
	ai_policy_audit_ex(uid, ai_policy_mode_for_uid(uid), tool, args,
			   result, v->lease_id, ai_danger_name(v->danger),
			   confirm);
}

static void gate_trace(const char *decision, const char *reason,
		       const char *tool, const char *confirm,
		       const char *args, const struct ai_lease_verdict *v,
		       const char *nonce, const struct ai_lease_ctx *ctx)
{
	ai_trace_policy_decision_ex(
		v->danger >= AI_D2 ? "W2" : (v->danger == AI_D0 ? "W1" : "W2"),
		decision, reason, tool, confirm, args, v->lease_id,
		ai_danger_name(v->danger), confirm, nonce, ctx->source);
}

/*
 * live 撤销/篡改检测（MASTER-PLAN §5.1：撤销立即生效）。
 * - 进程内粘滞：一旦观察到撤销，本进程后续 D1+ 全部拒绝（删标记也不复活，
 *   需要重新签发/重启加载）；
 * - 租约文件 inode/size/mtime 与加载时不一致 → fail-closed；
 * - D0 读不受影响（由 decide 的 D0 分支先放行）。
 */
static const char *lease_live_check(struct ai_lease_ctx *ctx)
{
	char path[PATH_MAX], marker[PATH_MAX];
	struct stat st;

	if (ctx->mode != AI_LEASE_MODE_EXPLICIT || !ctx->loaded)
		return NULL;
	if (ctx->live_revoked)
		return "lease_revoked_live";
	if (snprintf(marker, sizeof(marker), "%s/%s.revoked", ctx->dir,
		     ctx->lease.lease_id) < (int)sizeof(marker) &&
	    lstat(marker, &st) == 0) {
		/* 标记本身是符号链接/非普通文件也按撤销处理（fail-closed） */
		ctx->live_revoked = 1;
		ctx->lease.revoked = 1;
		return "lease_revoked_live";
	}
	if (snprintf(path, sizeof(path), "%s/%s.json", ctx->dir,
		     ctx->lease.lease_id) >= (int)sizeof(path))
		return "lease_file_missing";
	if (lstat(path, &st) != 0)
		return "lease_file_missing";
	if (S_ISLNK(st.st_mode) || !S_ISREG(st.st_mode))
		return "lease_file_changed";
	if (ctx->file_ino &&
	    ((unsigned long long)st.st_ino != ctx->file_ino ||
	     (long long)st.st_size != ctx->file_size ||
	     (long long)st.st_mtime != ctx->file_mtime))
		return "lease_file_changed";
	return NULL;
}

int ai_lease_gate(uid_t uid, const struct ai_lease_action *act,
		  const char *impact, const char *rollback,
		  char **out, enum ai_lease_gate_result *result)
{
	struct ai_lease_ctx *ctx = &g_ctx;
	struct ai_lease_verdict v;
	long long now = (long long)time(NULL);
	enum ai_lease_decision d;
	char err[AI_LEASE_ERR_MAX];
	const char *live;
	const char *rb;

	if (out)
		*out = NULL;
	if (result)
		*result = AI_LGATE_DENY;
	if (!act) {
		set_err(err, sizeof(err), "内部错误：空动作");
		return 0;
	}
	live = lease_live_check(ctx);
	d = ai_lease_decide(ctx, uid, act, now, &v);
	if (live && act->danger > AI_D0) {
		/* 撤销/文件变化立即生效：D1+ 一律拒绝（D0 仍可读） */
		v.decision = AI_LEASE_DENY;
		snprintf(v.reason, sizeof(v.reason), "%s", live);
		d = AI_LEASE_DENY;
	}
	rb = (rollback && rollback[0]) ? rollback : v.rollback_hint;
	g_last_lease[0] = '\0';
	snprintf(g_last_lease, sizeof(g_last_lease), "%s", v.lease_id);
	snprintf(g_last_danger, sizeof(g_last_danger), "%s",
		 ai_danger_name(v.danger));
	snprintf(g_last_reason, sizeof(g_last_reason), "%s", v.reason);
	snprintf(g_last_scope, sizeof(g_last_scope), "%s", v.scope_hit);
	snprintf(g_last_confirm, sizeof(g_last_confirm), "none");

	if (d == AI_LEASE_DENY) {
		gate_audit(uid, act->tool, act->args_json, "DENY", &v, "none");
		gate_trace("DENY", v.reason, act->tool, "none", act->args_json,
			   &v, NULL, ctx);
		if (result)
			*result = AI_LGATE_DENY;
		return 0;
	}
	if (d == AI_LEASE_ALLOW) {
		const char *confirm = "none";

		if (ctx->mode == AI_LEASE_MODE_EXPLICIT)
			confirm = "lease";
		else if (ctx->mode == AI_LEASE_MODE_EPHEMERAL)
			confirm = "ephemeral";
		snprintf(g_last_confirm, sizeof(g_last_confirm), "%s", confirm);
		gate_audit(uid, act->tool, act->args_json, "ALLOW", &v,
			   confirm);
		gate_trace("ALLOW", v.reason, act->tool, confirm,
			   act->args_json, &v, NULL, ctx);
		if (result)
			*result = AI_LGATE_ALLOW;
		return 1;
	}

	/* CONFIRM / CONFIRM_D4 */
	if (isatty(STDIN_FILENO)) {
		int ok = tty_confirm(act, &v, impact, rb, err, sizeof(err));

		if (ok) {
			snprintf(g_last_confirm, sizeof(g_last_confirm),
				 "interactive");
			gate_audit(uid, act->tool, act->args_json,
				   "CONFIRM=yes", &v, "interactive");
			gate_trace("ALLOW", v.reason, act->tool, "interactive",
				   act->args_json, &v, NULL, ctx);
			if (result)
				*result = AI_LGATE_ALLOW;
			return 1;
		}
		snprintf(g_last_confirm, sizeof(g_last_confirm), "none");
		gate_audit(uid, act->tool, act->args_json, "CONFIRM=no", &v,
			   "none");
		gate_trace("DENY",
			   v.decision == AI_LEASE_CONFIRM_D4 ?
			   "d4_phrase_mismatch" : "user_refused",
			   act->tool, "none", act->args_json, &v, NULL, ctx);
		if (result)
			*result = AI_LGATE_USER_REFUSED;
		return 0;
	}

	/* 非 TTY：已有 nonce → 消费 approved；否则写 pending */
	{
		const char *nonce = getenv("AIKERNEL_CONFIRM_NONCE");

		if (nonce && nonce[0]) {
			if (confirm_consume(act, v.danger, v.lease_id, nonce,
					    err, sizeof(err)) != 0) {
				snprintf(g_last_reason,
					 sizeof(g_last_reason),
					 "confirm_invalid");
				gate_audit(uid, act->tool, act->args_json,
					   "DENY", &v, "none");
				gate_trace("DENY", "confirm_invalid",
					   act->tool, "none", act->args_json,
					   &v, nonce, ctx);
				if (result)
					*result = AI_LGATE_DENY;
				return 0;
			}
			snprintf(g_last_confirm, sizeof(g_last_confirm),
				 "approved_file");
			gate_audit(uid, act->tool, act->args_json, "ALLOW", &v,
				   "approved_file");
			gate_trace("ALLOW", "approved_file", act->tool,
				   "approved_file", act->args_json, &v, nonce,
				   ctx);
			if (result)
				*result = AI_LGATE_ALLOW;
			return 1;
		}

		/* 首次：生成 pending + 返回可解析 JSON */
		{
			char nb[65];
			char *json = NULL;

			if (ai_lease_confirm_pending_write(
				    act, v.danger, v.lease_id, impact, rb,
				    nb, sizeof(nb), err, sizeof(err)) != 0) {
				gate_audit(uid, act->tool, act->args_json,
					   "DENY", &v, "none");
				gate_trace("DENY", "confirm_pending_failed",
					   act->tool, "none", act->args_json,
					   &v, NULL, ctx);
				if (result)
					*result = AI_LGATE_DENY;
				return 0;
			}
			{
				char action[512];
				char *e_act, *e_impact, *e_rb, *e_lease;

				ai_lease_action_text(act, action,
						     sizeof(action));
				e_act = json_dup_escaped(action);
				e_impact = json_dup_escaped(impact ? impact :
							    "");
				e_rb = json_dup_escaped(rb);
				e_lease = json_dup_escaped(v.lease_id);
				if (!e_act || !e_impact || !e_rb ||
				    !e_lease ||
				    asprintf(&json,
					     "{\"status\":\"CONFIRM_REQUIRED\","
					     "\"nonce\":\"%s\",\"danger\":\"%s\","
					     "\"tool\":\"%s\",\"lease_id\":%s%s%s,"
					     "\"action\":\"%s\",\"impact\":\"%s\","
					     "\"rollback\":\"%s\",\"question\":\"%s\"}",
					     nb, ai_danger_name(v.danger),
					     act->tool ? act->tool : "?",
					     v.lease_id[0] ? "\"" : "",
					     v.lease_id[0] ? e_lease : "null",
					     v.lease_id[0] ? "\"" : "",
					     e_act, e_impact, e_rb,
					     tr(TR_LEASE_CONFIRM_QUESTION)) < 0)
					json = NULL;
				free(e_act); free(e_impact); free(e_rb);
				free(e_lease);
			}
			if (!json) {
				gate_audit(uid, act->tool, act->args_json,
					   "DENY", &v, "none");
				gate_trace("DENY", "confirm_pending_failed",
					   act->tool, "none", act->args_json,
					   &v, NULL, ctx);
				if (result)
					*result = AI_LGATE_DENY;
				return 0;
			}
			snprintf(g_last_confirm, sizeof(g_last_confirm), "none");
			gate_audit(uid, act->tool, act->args_json,
				   "CONFIRM_REQUIRED", &v, "none");
			gate_trace("CONFIRM", "needs_confirmation_no_tty",
				   act->tool, "none", act->args_json, &v, nb,
				   ctx);
			if (out)
				*out = json;
			else
				free(json);
			if (result)
				*result = AI_LGATE_CONFIRM_REQUIRED;
			return 0;
		}
	}
}

/* ---- 签发 / 撤销 ---- */

static int csv_scope_parse(const char *csv, char scopes[][AI_LEASE_SCOPE_LEN],
			   int max, int *count, char *err, size_t errlen)
{
	char *copy, *p, *tok;
	int n = 0;

	if (!csv || !csv[0]) {
		set_err(err, errlen, "scope 不能为空");
		return -1;
	}
	copy = strdup(csv);
	if (!copy) {
		set_err(err, errlen, "内存不足");
		return -1;
	}
	p = copy;
	while ((tok = strsep(&p, ",")) != NULL) {
		char *s = tok;

		while (*s == ' ' || *s == '\t')
			s++;
		{
			char *end = s + strlen(s);

			while (end > s && (end[-1] == ' ' || end[-1] == '\t'))
				*--end = '\0';
		}
		if (!s[0])
			continue;
		if (n >= max) {
			set_err(err, errlen, "scope 过多（上限 %d）", max);
			free(copy);
			return -1;
		}
		if (!scope_valid(s)) {
			set_err(err, errlen, "非法 scope: %s", s);
			free(copy);
			return -1;
		}
		snprintf(scopes[n], AI_LEASE_SCOPE_LEN, "%s", s);
		n++;
	}
	free(copy);
	if (n == 0) {
		set_err(err, errlen, "scope 不能为空");
		return -1;
	}
	*count = n;
	return 0;
}

int ai_lease_new_id(char *buf, size_t n)
{
	char rnd[8];
	struct tm tm;
	time_t now = time(NULL);

	if (!buf || n < 16)
		return -1;
	rand_hex(rnd, sizeof(rnd), 2);
	localtime_r(&now, &tm);
	snprintf(buf, n, "L-%04d%02d%02d-%s", tm.tm_year + 1900,
		 tm.tm_mon + 1, tm.tm_mday, rnd);
	return ai_lease_id_valid(buf) ? 0 : -1;
}

int ai_lease_issue(const char *scope_csv, const char *ceiling,
		   const char *mission, long ttl, uid_t uid,
		   char *out_id, size_t idlen, char *out_path, size_t pathlen,
		   char *err, size_t errlen)
{
	char scopes[AI_LEASE_SCOPE_MAX][AI_LEASE_SCOPE_LEN];
	int nscope = 0;
	enum ai_danger ceil_d;
	char dir[512];
	char user[64];
	char id[AI_LEASE_ID_MAX];
	char iss[40], exp[40];
	char *json = NULL;
	char *e_scope = NULL, *e_mission = NULL;
	time_t now = time(NULL);
	int attempt, rc = -1;

	/* 防御纵深：正式存储只允许 root 签发（cmd_lease 已校验 root+TTY；
	 * 测试目录覆盖时允许调用 uid，便于非 root 单测）。 */
	if (getuid() != 0 &&
	    !env_override_is_set("AIKERNEL_LEASE_DIR")) {
		set_err(err, errlen, "只有 root 可以签发租约");
		return -1;
	}
	if (csv_scope_parse(scope_csv, scopes, AI_LEASE_SCOPE_MAX, &nscope,
			    err, errlen) != 0)
		return -1;
	if (!ceiling || ai_danger_parse(ceiling, &ceil_d) != 0) {
		set_err(err, errlen, "risk_ceiling 只接受 D0-D4");
		return -1;
	}
	if (!mission || !mission[0]) {
		set_err(err, errlen, "mission 不能为空");
		return -1;
	}
	if (ttl <= 0 || ttl > 30 * 24 * 3600) {
		set_err(err, errlen, "ttl 必须在 1..2592000 秒");
		return -1;
	}
	ai_lease_store_dir(dir, sizeof(dir));
	if (mkdirs_0700(dir, err, errlen) != 0)
		return -1;
	if (dir_trusted(dir, uid,
			env_override_is_set("AIKERNEL_LEASE_DIR"),
			err, errlen) != 0)
		return -1;
	if (uid_to_name(uid, user, sizeof(user)) != 0)
		snprintf(user, sizeof(user), "uid%u", (unsigned)uid);

	format_iso_utc((long long)now, iss, sizeof(iss));
	format_iso_utc((long long)now + ttl, exp, sizeof(exp));

	e_scope = malloc((size_t)nscope * (AI_LEASE_SCOPE_LEN + 8) + 8);
	if (!e_scope)
		goto oom;
	e_scope[0] = '\0';
	for (int i = 0; i < nscope; i++) {
		char *e = json_dup_escaped(scopes[i]);

		if (!e) {
			free(e_scope);
			goto oom;
		}
		if (i)
			strcat(e_scope, ",");
		strcat(e_scope, "\"");
		strcat(e_scope, e);
		strcat(e_scope, "\"");
		free(e);
	}
	e_mission = json_dup_escaped(mission);
	if (!e_mission)
		goto oom;

	if (out_id && idlen && out_id[0]) {
		snprintf(id, sizeof(id), "%s", out_id);
		if (!ai_lease_id_valid(id)) {
			set_err(err, errlen, "非法候选 lease_id");
			return -1;
		}
	}
	for (attempt = 0; attempt < 16; attempt++) {
		char rnd[8];
		char final[PATH_MAX];
		char name[96];
		int suggested = (out_id && idlen && out_id[0]);

		if (!suggested) {
			rand_hex(rnd, sizeof(rnd), 2);
			/* 使用本地日期更直观 */
			{
				struct tm tm;

				localtime_r(&now, &tm);
				snprintf(id, sizeof(id), "L-%04d%02d%02d-%s",
					 tm.tm_year + 1900,
					 tm.tm_mon + 1, tm.tm_mday, rnd);
			}
		}
		if (snprintf(final, sizeof(final), "%s/%s.json", dir, id) >=
		    (int)sizeof(final))
			break;
		if (access(final, F_OK) == 0) {
			if (suggested) {
				set_err(err, errlen, "租约 %s 已存在", id);
				break;
			}
			continue;
		}
		if (asprintf(&json,
			     "{\n"
			     "  \"lease_id\": \"%s\",\n"
			     "  \"principal\": \"%s\",\n"
			     "  \"subject\": \"%s-ai\",\n"
			     "  \"scope\": [%s],\n"
			     "  \"risk_ceiling\": \"%s\",\n"
			     "  \"mission\": \"%s\",\n"
			     "  \"issued_at\": \"%s\",\n"
			     "  \"expires_at\": \"%s\",\n"
			     "  \"revocable\": true,\n"
			     "  \"audit\": \"w74-lease-issue\",\n"
			     "  \"revoked\": false\n"
			     "}\n",
			     id, user, user, e_scope, ai_danger_name(ceil_d),
			     e_mission, iss, exp) < 0)
			json = NULL;
		if (!json)
			goto oom;
		snprintf(name, sizeof(name), "%s.json", id);
		if (atomic_write_file(dir, name, json, 0, err, errlen) == 0) {
			if (out_id && idlen)
				snprintf(out_id, idlen, "%s", id);
			if (out_path && pathlen)
				snprintf(out_path, pathlen, "%s", final);
			rc = 0;
			free(json);
			json = NULL;
			break;
		}
		free(json);
		json = NULL;
	}
	if (rc != 0 && err && !err[0])
		set_err(err, errlen, "无法生成唯一 lease_id");
	free(e_scope);
	free(e_mission);
	return rc;
oom:
	set_err(err, errlen, "内存不足");
	free(e_scope);
	free(e_mission);
	free(json);
	return -1;
}

int ai_lease_revoke(const char *id, uid_t uid, char *err, size_t errlen)
{
	char dir[512], path[PATH_MAX];
	char name[96];
	char data[256];
	char iss[40];
	time_t now = time(NULL);

	if (!ai_lease_id_valid(id)) {
		set_err(err, errlen, "非法 lease_id");
		return -1;
	}
	if (getuid() != 0 &&
	    !env_override_is_set("AIKERNEL_LEASE_DIR")) {
		set_err(err, errlen, "只有 root 可以撤销租约");
		return -1;
	}
	ai_lease_store_dir(dir, sizeof(dir));
	if (dir_trusted(dir, uid,
			env_override_is_set("AIKERNEL_LEASE_DIR"),
			err, errlen) != 0)
		return -1;
	if (snprintf(path, sizeof(path), "%s/%s.revoked", dir, id) >=
	    (int)sizeof(path)) {
		set_err(err, errlen, "路径过长");
		return -1;
	}
	if (access(path, F_OK) == 0)
		return 0;	/* 幂等 */
	format_iso_utc((long long)now, iss, sizeof(iss));
	snprintf(data, sizeof(data),
		 "{\"lease_id\":\"%s\",\"revoked_at\":\"%s\","
		 "\"revoked_by\":%u}\n", id, iss, (unsigned)uid);
	snprintf(name, sizeof(name), "%s.revoked", id);
	return atomic_write_file(dir, name, data, 0, err, errlen);
}
