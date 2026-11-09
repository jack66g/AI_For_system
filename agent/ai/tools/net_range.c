// SPDX-License-Identifier: GPL-2.0
/*
 * net_range.c - W81 E2：V3.6 靶场攻击面（默认关闭 / 硬 CIDR / 全量审计）
 *
 * 设计顺序：边界先于能力。任何会发包的路径都必须先过
 *   1) 通道已启用且未过期；
 *   2) 目标在启用时声明的 CIDR 内（代码硬校验）；
 *   3) 目标在硬编码允许清单内；
 *   4) 审计写入成功（失败即拒绝发送）。
 * 不写漏洞利用、不打真实服务、不做 DoS、不扫描宿主 LAN。
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "tools/net_range.h"
#include "tools/tool_registry.h"
#include "ai_json_util.h"
#include "ai_types.h"
#include "netlink/ai_netlink_client.h"

#define RG_STATE_FILE		"state.json"
#define RG_AUDIT_FILE		"audit.log"
#define RG_WD_FILE		"watchdog.pid"
#define RG_STATE_MAX		8192
#define RG_AUDIT_MAX		32768
#define RG_TS_MAX		64

/* 硬编码允许清单（顺序即展示顺序） */
static const char *const rg_allow[] = {
	"10.231.0.0/16",
	"10.99.0.0/16",
	"127.0.0.0/8",
};

/* ===================== 基础工具 ===================== */

static long long rg_now(void)
{
	return (long long)time(NULL);
}

static void rg_iso(long long t, char *out, size_t cap)
{
	time_t tt = (time_t)t;
	struct tm tm;

	if (!gmtime_r(&tt, &tm) ||
	    strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
		snprintf(out, cap, "-");
}

static int rg_wr_all(int fd, const char *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = write(fd, buf + off, len - off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		off += (size_t)n;
	}
	return 0;
}

static int rg_read_text(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	ssize_t n;
	size_t off = 0;

	if (fd < 0)
		return -1;
	while (off + 1 < cap) {
		n = read(fd, buf + off, cap - 1 - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}
	close(fd);
	buf[off] = '\0';
	return (int)off;
}

/* 目录安全检查：必须是当前 euid 拥有的 0700 目录，且不是符号链接 */
static int rg_dir_ok(const char *path)
{
	struct stat st;

	if (lstat(path, &st) != 0)
		return -1;
	if (!S_ISDIR(st.st_mode))
		return -1;
	if (st.st_uid != geteuid())
		return -1;
	if ((st.st_mode & 077) != 0)
		return -1;
	return 0;
}

int rg_state_dir(char *out, size_t cap)
{
	const char *env = getenv("AIKERNEL_RANGE_DIR");
	int n;

	if (!out || cap < 2)
		return -1;
	if (env && env[0]) {
		size_t elen = strlen(env);

		if (env[0] != '/' || strstr(env, "/../") ||
		    (elen >= 3 && strcmp(env + elen - 3, "/..") == 0))
			return -1;
		n = snprintf(out, cap, "%s", env);
	} else if (geteuid() == 0) {
		n = snprintf(out, cap, "/run/aik-range");
	} else {
		n = snprintf(out, cap, "/tmp/aik-range-%u",
			     (unsigned int)geteuid());
	}
	if (n < 0 || (size_t)n >= cap)
		return -1;
	if (mkdir(out, 0700) != 0 && errno != EEXIST)
		return -1;
	/* 已存在时也强制复核，防 /tmp 预置目录/符号链接 */
	if (rg_dir_ok(out) != 0)
		return -1;
	return 0;
}

int rg_audit_path(char *out, size_t cap)
{
	char dir[512];
	int n;

	if (rg_state_dir(dir, sizeof(dir)) != 0)
		return -1;
	n = snprintf(out, cap, "%s/%s", dir, RG_AUDIT_FILE);
	return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/* ===================== CIDR / 目标边界 ===================== */

const char *rg_allowlist_text(void)
{
	return "10.231.0.0/16、10.99.0.0/16、127.0.0.0/8（仅限 netns 内）";
}

int rg_cidr_parse(const char *s, struct rg_cidr *out, char *err, size_t ecap)
{
	char tmp[48];
	char *slash;
	struct in_addr addr;
	long prefix;
	char *end = NULL;

	if (!s || !out) {
		snprintf(err, ecap, "cidr 为空");
		return -1;
	}
	if (strlen(s) >= sizeof(tmp)) {
		snprintf(err, ecap, "cidr 过长");
		return -1;
	}
	snprintf(tmp, sizeof(tmp), "%s", s);
	slash = strchr(tmp, '/');
	if (!slash) {
		snprintf(err, ecap, "cidr 缺少前缀长度（应形如 10.231.0.0/16）");
		return -1;
	}
	*slash = '\0';
	if (inet_pton(AF_INET, tmp, &addr) != 1) {
		snprintf(err, ecap, "cidr 网络地址不是合法 IPv4：%s", tmp);
		return -1;
	}
	errno = 0;
	prefix = strtol(slash + 1, &end, 10);
	if (errno || !end || *end != '\0' || prefix < 0 || prefix > 32) {
		snprintf(err, ecap, "cidr 前缀长度非法（0..32）：%s", slash + 1);
		return -1;
	}
	memset(out, 0, sizeof(*out));
	out->prefix = (int)prefix;
	out->mask = prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
	out->net = ntohl(addr.s_addr) & out->mask;
	if ((ntohl(addr.s_addr) & ~out->mask) != 0) {
		snprintf(err, ecap,
			 "cidr 主机位非零（请用规范网络地址，如 10.231.0.0/16）");
		return -1;
	}
	snprintf(out->text, sizeof(out->text), "%s/%d", tmp, out->prefix);
	return 0;
}

int rg_cidr_contains(const struct rg_cidr *c, const char *ip)
{
	struct in_addr addr;

	if (!c || !ip || inet_pton(AF_INET, ip, &addr) != 1)
		return 0;
	return ((ntohl(addr.s_addr) & c->mask) == c->net);
}

/* 精确匹配允许清单（不接受 10.231.0.0/8 之类的放宽） */
int rg_cidr_allowlisted(const char *s, char *err, size_t ecap)
{
	size_t i;

	for (i = 0; i < sizeof(rg_allow) / sizeof(rg_allow[0]); i++) {
		if (strcmp(s, rg_allow[i]) == 0)
			return 0;
	}
	snprintf(err, ecap,
		 "cidr=%s 不在硬编码允许清单内（仅 %s）", s ? s : "-",
		 rg_allowlist_text());
	return -1;
}

static int rg_target_in_allowlist(const char *ip)
{
	size_t i;
	struct rg_cidr c;
	char err[128];

	for (i = 0; i < sizeof(rg_allow) / sizeof(rg_allow[0]); i++) {
		if (rg_cidr_parse(rg_allow[i], &c, err, sizeof(err)) != 0)
			continue;
		if (rg_cidr_contains(&c, ip))
			return 1;
	}
	return 0;
}

/* 当前进程是否在宿主默认 netns（用于 127.0.0.0/8 的 netns 限制） */
static int rg_in_host_netns(void)
{
	char a[128], b[128];
	ssize_t na = readlink("/proc/self/ns/net", a, sizeof(a) - 1);
	ssize_t nb = readlink("/proc/1/ns/net", b, sizeof(b) - 1);

	if (na <= 0 || nb <= 0)
		return 1;	/* 无法判定时按宿主处理（对 loopback 更严） */
	a[na] = '\0';
	b[nb] = '\0';
	return strcmp(a, b) == 0;
}

/*
 * 目标边界硬校验：
 *   - 必须是数字 IPv4（拒绝 DNS/主机名，避免解析到清单外地址）；
 *   - 必须在启用时声明的 CIDR 内；
 *   - 必须在硬编码允许清单内；
 *   - 127.0.0.0/8 额外要求当前进程不在宿主默认 netns。
 */
static int rg_target_allowed(const struct rg_state *st, const char *target,
			     char *err, size_t ecap)
{
	struct in_addr addr;
	struct rg_cidr c;
	char cerr[128];

	if (!target || !*target) {
		snprintf(err, ecap, "缺少 target");
		return -1;
	}
	if (inet_pton(AF_INET, target, &addr) != 1) {
		snprintf(err, ecap,
			 "target 必须是数字 IPv4（拒绝主机名/IPv6）：%s", target);
		return -1;
	}
	if (rg_cidr_parse("192.168.245.0/24", &c, cerr, sizeof(cerr)) == 0 &&
	    rg_cidr_contains(&c, target)) {
		snprintf(err, ecap,
			 "target=%s 属于实验室宿主网段 192.168.245.0/24，显式拒绝",
			 target);
		return -1;
	}
	if (!rg_target_in_allowlist(target)) {
		snprintf(err, ecap,
			 "target=%s 不在硬编码允许清单内（%s），拒绝", target,
			 rg_allowlist_text());
		return -1;
	}
	if (!rg_cidr_contains(&st->net, target)) {
		snprintf(err, ecap,
			 "target=%s 不在启用时声明的 CIDR %s 内（硬校验拒绝）",
			 target, st->cidr);
		return -1;
	}
	if (rg_cidr_parse("127.0.0.0/8", &c, cerr, sizeof(cerr)) == 0 &&
	    rg_cidr_contains(&c, target) && rg_in_host_netns()) {
		snprintf(err, ecap,
			 "target=%s 属 127.0.0.0/8：仅允许在 netns 内使用，"
			 "当前进程在宿主默认 netns，拒绝", target);
		return -1;
	}
	return 0;
}

/* ===================== 端口 / 十六进制 ===================== */

int rg_parse_ports(const char *s, unsigned short *ports, int max, int *n,
		   char *err, size_t ecap)
{
	char tmp[2048];
	char *save = NULL, *tok;
	int cnt = 0;

	if (!s || !*s) {
		snprintf(err, ecap, "缺少 ports（如 22,80,8000-8010）");
		return -1;
	}
	if (strlen(s) >= sizeof(tmp)) {
		snprintf(err, ecap, "ports 过长（上限 2048 字节）");
		return -1;
	}
	snprintf(tmp, sizeof(tmp), "%s", s);
	for (tok = strtok_r(tmp, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		char *dash, *end = NULL;
		long lo, hi, p;

		while (*tok == ' ' || *tok == '\t')
			tok++;
		if (!*tok) {
			snprintf(err, ecap, "ports 含空项");
			return -1;
		}
		dash = strchr(tok, '-');
		if (dash) {
			*dash = '\0';
			errno = 0;
			lo = strtol(tok, &end, 10);
			if (errno || !end || *end || lo < 1 || lo > 65535) {
				snprintf(err, ecap, "端口区间起点非法：%s", tok);
				return -1;
			}
			errno = 0;
			hi = strtol(dash + 1, &end, 10);
			if (errno || !end || *end || hi < 1 || hi > 65535 ||
			    hi < lo) {
				snprintf(err, ecap, "端口区间终点非法：%s",
					 dash + 1);
				return -1;
			}
			if (cnt + (hi - lo + 1) > max) {
				snprintf(err, ecap,
					 "端口数超过上限 %d（本次请求 %d）", max,
					 cnt + (int)(hi - lo + 1));
				return -1;
			}
			for (p = lo; p <= hi; p++)
				ports[cnt++] = (unsigned short)p;
		} else {
			errno = 0;
			lo = strtol(tok, &end, 10);
			if (errno || !end || *end || lo < 1 || lo > 65535) {
				snprintf(err, ecap, "端口非法：%s", tok);
				return -1;
			}
			if (cnt + 1 > max) {
				snprintf(err, ecap, "端口数超过上限 %d", max);
				return -1;
			}
			ports[cnt++] = (unsigned short)lo;
		}
	}
	if (cnt == 0) {
		snprintf(err, ecap, "ports 为空");
		return -1;
	}
	*n = cnt;
	return 0;
}

int rg_hex_decode(const char *hex, unsigned char *out, size_t cap,
		  size_t *n, char *err, size_t ecap)
{
	size_t len, i;

	if (!hex)
		hex = "";
	len = strlen(hex);
	if (len % 2 != 0) {
		snprintf(err, ecap, "payload_hex 长度必须为偶数（实际 %zu）",
			 len);
		return -1;
	}
	if (len / 2 > cap) {
		snprintf(err, ecap,
			 "payload_hex 解码后 %zu 字节，超过上限 %zu 字节",
			 len / 2, cap);
		return -1;
	}
	for (i = 0; i < len; i += 2) {
		int hi, lo;

		if (!isxdigit((unsigned char)hex[i]) ||
		    !isxdigit((unsigned char)hex[i + 1])) {
			snprintf(err, ecap,
				 "payload_hex 含非十六进制字符（位置 %zu）", i);
			return -1;
		}
		hi = isdigit((unsigned char)hex[i]) ? hex[i] - '0' :
		     tolower((unsigned char)hex[i]) - 'a' + 10;
		lo = isdigit((unsigned char)hex[i + 1]) ? hex[i + 1] - '0' :
		     tolower((unsigned char)hex[i + 1]) - 'a' + 10;
		out[i / 2] = (unsigned char)((hi << 4) | lo);
	}
	*n = len / 2;
	return 0;
}

void rg_hex_encode(const unsigned char *buf, size_t n, char *out, size_t cap)
{
	static const char hexd[] = "0123456789abcdef";
	size_t i, o = 0;

	if (!out || cap == 0)
		return;
	for (i = 0; i < n && o + 2 < cap; i++) {
		out[o++] = hexd[buf[i] >> 4];
		out[o++] = hexd[buf[i] & 0xf];
	}
	out[o] = '\0';
}

/* ===================== 审计（不可关闭） ===================== */

static char *rg_esc(const char *s)
{
	char *e = ai_json_escape(s ? s : "");

	if (e)
		return e;
	e = strdup("?");
	return e ? e : strdup("");
}

static int rg_audit_v(const char *tool, const char *action, const char *target,
		      unsigned int port, const char *proto,
		      const char *payload_hex, int rc, const char *result,
		      const char *detail)
{
	char path[600];
	char timebuf[RG_TS_MAX];
	char *et, *ea, *etg, *ep, *ed, *ers;
	char *line;
	int fd, n, ret = -1;
	long long now = rg_now();

	if (rg_audit_path(path, sizeof(path)) != 0)
		return -1;
	rg_iso(now, timebuf, sizeof(timebuf));
	et = rg_esc(tool);
	ea = rg_esc(action);
	etg = rg_esc(target);
	ep = rg_esc(proto);
	ed = rg_esc(detail);
	ers = rg_esc(result);
	line = malloc(RG_AUDIT_MAX);
	if (!line)
		goto out;
	n = snprintf(line, RG_AUDIT_MAX,
		     "{\"ts\":%lld,\"time\":\"%s\",\"tool\":\"%s\","
		     "\"action\":\"%s\",\"target\":\"%s\",\"port\":%u,"
		     "\"protocol\":\"%s\",\"payload_hex\":\"%s\",\"rc\":%d,"
		     "\"result\":\"%s\",\"detail\":\"%s\",\"pid\":%d}\n",
		     now, timebuf, et, ea, etg, port, ep,
		     payload_hex ? payload_hex : "", rc, ers, ed,
		     (int)getpid());
	if (n < 0 || n >= RG_AUDIT_MAX) {
		errno = EOVERFLOW;
		goto out;
	}
	fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
		  0600);
	if (fd < 0)
		goto out;
	if (flock(fd, LOCK_EX) == 0) {
		if (rg_wr_all(fd, line, (size_t)n) == 0)
			ret = 0;
		(void)flock(fd, LOCK_UN);
	}
	close(fd);
out:
	free(line);
	free(et);
	free(ea);
	free(etg);
	free(ep);
	free(ed);
	free(ers);
	return ret;
}

/* ===================== 状态读写 ===================== */

void rg_state_default(struct rg_state *st)
{
	if (!st)
		return;
	memset(st, 0, sizeof(*st));
	st->enabled = 0;
}

int rg_state_expired(const struct rg_state *st, long long now)
{
	return st && st->enabled && st->expires_at > 0 && now >= st->expires_at;
}

static int rg_state_write(const struct rg_state *st)
{
	char dir[512], path[600], tmp[640];
	char *elsm;
	char buf[RG_STATE_MAX];
	int fd, n;

	if (rg_state_dir(dir, sizeof(dir)) != 0)
		return -1;
	if (snprintf(path, sizeof(path), "%s/%s", dir, RG_STATE_FILE) >=
	    (int)sizeof(path))
		return -1;
	if (snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid()) >=
	    (int)sizeof(tmp))
		return -1;
	elsm = rg_esc(st->lsm);
	if (!elsm)
		return -1;
	n = snprintf(buf, sizeof(buf),
		     "{\"enabled\":%d,\"cidr\":\"%s\",\"ttl_minutes\":%d,"
		     "\"enabled_at\":%lld,\"expires_at\":%lld,"
		     "\"actions\":%llu,\"session\":%llu,\"lsm\":\"%s\"}\n",
		     st->enabled, st->cidr, st->ttl_minutes,
		     st->enabled_at, st->expires_at, st->actions,
		     st->session, elsm);
	free(elsm);
	if (n < 0 || n >= (int)sizeof(buf))
		return -1;
	fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
		  0600);
	if (fd < 0)
		return -1;
	if (rg_wr_all(fd, buf, (size_t)n) != 0 || fsync(fd) != 0) {
		close(fd);
		unlink(tmp);
		return -1;
	}
	close(fd);
	if (rename(tmp, path) != 0) {
		unlink(tmp);
		return -1;
	}
	return 0;
}

int rg_state_save(const struct rg_state *st)
{
	return rg_state_write(st);
}

static int rg_state_read(struct rg_state *st, char *err, size_t ecap)
{
	char dir[512], path[600], buf[RG_STATE_MAX];
	const char *v;
	size_t vl;
	int ty;

	if (!st) {
		snprintf(err, ecap, "参数为空");
		return -1;
	}
	rg_state_default(st);
	if (rg_state_dir(dir, sizeof(dir)) != 0) {
		snprintf(err, ecap, "状态目录不可用（权限/归属/符号链接）");
		return -1;
	}
	if (snprintf(path, sizeof(path), "%s/%s", dir, RG_STATE_FILE) >=
	    (int)sizeof(path)) {
		snprintf(err, ecap, "状态路径过长");
		return -1;
	}
	if (access(path, F_OK) != 0)
		return 0;
	if (rg_read_text(path, buf, sizeof(buf)) < 0) {
		snprintf(err, ecap, "state.json 读取失败: %s", strerror(errno));
		return -1;
	}
	if (ai_json_obj_get(buf, strlen(buf), "enabled", &v, &vl, &ty) != 1 ||
	    ty != AI_JSON_NUM) {
		snprintf(err, ecap, "state.json 损坏（缺 enabled）");
		return -1;
	}
	st->enabled = (int)ai_json_ll(v, vl);
	if (ai_json_obj_get(buf, strlen(buf), "cidr", &v, &vl, &ty) == 1 &&
	    ty == AI_JSON_STR) {
		char *s = ai_json_strdup_str(v, vl);

		if (!s) {
			snprintf(err, ecap, "state.json cidr 解码失败");
			return -1;
		}
		snprintf(st->cidr, sizeof(st->cidr), "%s", s);
		free(s);
	}
	if (rg_cidr_parse(st->cidr, &st->net, err, ecap) != 0)
		return -1;
	if (ai_json_obj_get(buf, strlen(buf), "ttl_minutes", &v, &vl, &ty) ==
	    1 && ty == AI_JSON_NUM)
		st->ttl_minutes = (int)ai_json_ll(v, vl);
	if (ai_json_obj_get(buf, strlen(buf), "enabled_at", &v, &vl, &ty) == 1 &&
	    ty == AI_JSON_NUM)
		st->enabled_at = (long long)ai_json_ll(v, vl);
	if (ai_json_obj_get(buf, strlen(buf), "expires_at", &v, &vl, &ty) == 1 &&
	    ty == AI_JSON_NUM)
		st->expires_at = (long long)ai_json_ll(v, vl);
	if (ai_json_obj_get(buf, strlen(buf), "actions", &v, &vl, &ty) == 1 &&
	    ty == AI_JSON_NUM)
		st->actions = (unsigned long long)ai_json_ll(v, vl);
	if (ai_json_obj_get(buf, strlen(buf), "session", &v, &vl, &ty) == 1 &&
	    ty == AI_JSON_NUM)
		st->session = (unsigned long long)ai_json_ll(v, vl);
	if (ai_json_obj_get(buf, strlen(buf), "lsm", &v, &vl, &ty) == 1 &&
	    ty == AI_JSON_STR) {
		char *s = ai_json_strdup_str(v, vl);

		if (s) {
			snprintf(st->lsm, sizeof(st->lsm), "%s", s);
			free(s);
		}
	}
	return 1;
}

int rg_state_load(struct rg_state *st, char *err, size_t ecap)
{
	char myerr[128];
	int r;

	if (!err) {
		err = myerr;
		ecap = sizeof(myerr);
	}
	if (!st) {
		snprintf(err, ecap, "参数为空");
		return -1;
	}
	err[0] = '\0';
	r = rg_state_read(st, err, ecap);
	if (r != 1)
		return r;
	if (!st->enabled)
		return 0;
	if (rg_state_expired(st, rg_now())) {
		/* 惰性到期：即使 watchdog 丢失也自动关闭 */
		(void)rg_audit_v("-", "auto_disable", "-", 0, "-", "", 0,
				 "ttl_expired",
				 "expires_at 已到（watchdog 或惰性检查）自动关闭");
		rg_watchdog_stop();
		rg_state_remove();
		rg_state_default(st);
		return 0;
	}
	return 1;
}

int rg_state_remove(void)
{
	char dir[512], path[600];

	if (rg_state_dir(dir, sizeof(dir)) != 0)
		return -1;
	if (snprintf(path, sizeof(path), "%s/%s", dir, RG_STATE_FILE) >=
	    (int)sizeof(path))
		return -1;
	unlink(path);
	return 0;
}

static int rg_state_bump(struct rg_state *st)
{
	st->actions++;
	return rg_state_write(st);
}

/* ===================== watchdog（到期自动关闭） ===================== */

static void rg_wd_daemon(unsigned long long session, int ready_fd)
{
	char pbuf[32];

	(void)setsid();
	snprintf(pbuf, sizeof(pbuf), "%d\n", (int)getpid());
	if (ready_fd >= 0) {
		(void)rg_wr_all(ready_fd, pbuf, strlen(pbuf));
		close(ready_fd);
	}
	for (;;) {
		struct rg_state st;
		char err[128];
		int r;

		sleep(1);
		r = rg_state_load(&st, err, sizeof(err));
		if (r != 1) {
			/* 已关闭/已过期（load 内已审计）/损坏/读失败 */
			_exit(0);
		}
		if (st.session != session)
			_exit(0);
		if (rg_now() >= st.expires_at) {
			(void)rg_audit_v("-", "auto_disable", "-", 0, "-", "", 0,
					 "ttl_expired",
					 "watchdog 到期自动关闭并清状态");
			rg_watchdog_stop();
			rg_state_remove();
			_exit(0);
		}
	}
}

int rg_watchdog_spawn(unsigned long long session, char *err, size_t ecap)
{
	int pfd[2];
	pid_t p, p2;
	char buf[32];
	ssize_t n;
	struct pollfd pfdv;
	int status;

	if (pipe(pfd) != 0) {
		snprintf(err, ecap, "pipe 失败: %s", strerror(errno));
		return -1;
	}
	p = fork();
	if (p < 0) {
		close(pfd[0]);
		close(pfd[1]);
		snprintf(err, ecap, "fork 失败: %s", strerror(errno));
		return -1;
	}
	if (p == 0) {
		int devnull;

		close(pfd[0]);
		p2 = fork();
		if (p2 < 0)
			_exit(1);
		if (p2 > 0)
			_exit(0);
		devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			dup2(devnull, 0);
			dup2(devnull, 1);
			dup2(devnull, 2);
			if (devnull > 2)
				close(devnull);
		}
		rg_wd_daemon(session, pfd[1]);
		_exit(0);
	}
	close(pfd[1]);
	(void)waitpid(p, &status, 0);
	pfdv.fd = pfd[0];
	pfdv.events = POLLIN;
	n = poll(&pfdv, 1, 3000) > 0 ? read(pfd[0], buf, sizeof(buf) - 1) : -1;
	close(pfd[0]);
	if (n <= 0) {
		snprintf(err, ecap, "watchdog 握手超时");
		return -1;
	}
	buf[n] = '\0';
	{
		char dir[512], path[600];
		int fd;

		if (rg_state_dir(dir, sizeof(dir)) == 0 &&
		    snprintf(path, sizeof(path), "%s/%s", dir, RG_WD_FILE) <
		    (int)sizeof(path)) {
			fd = open(path, O_WRONLY | O_CREAT | O_TRUNC |
				  O_CLOEXEC | O_NOFOLLOW, 0600);
			if (fd >= 0) {
				(void)rg_wr_all(fd, buf, strlen(buf));
				close(fd);
			}
		}
	}
	return 0;
}

static int rg_watchdog_alive(void)
{
	char dir[512], path[600], buf[64];
	long pid;

	if (rg_state_dir(dir, sizeof(dir)) != 0 ||
	    snprintf(path, sizeof(path), "%s/%s", dir, RG_WD_FILE) >=
	    (int)sizeof(path) ||
	    rg_read_text(path, buf, sizeof(buf)) <= 0)
		return 0;
	pid = strtol(buf, NULL, 10);
	if (pid <= 1)
		return 0;
	return kill((pid_t)pid, 0) == 0 || errno == EPERM;
}

void rg_watchdog_stop(void)
{
	char dir[512], path[600], buf[64];
	long pid;

	if (rg_state_dir(dir, sizeof(dir)) != 0)
		return;
	if (snprintf(path, sizeof(path), "%s/%s", dir, RG_WD_FILE) >=
	    (int)sizeof(path))
		return;
	if (rg_read_text(path, buf, sizeof(buf)) <= 0)
		return;
	pid = strtol(buf, NULL, 10);
	if (pid > 1 && pid != (long)getpid())
		(void)kill((pid_t)pid, SIGTERM);
	unlink(path);
}

/* ===================== LSM socket hook 接线 ===================== */

int rg_lsm_probe(void)
{
	char buf[512];
	char *save = NULL, *tok;

	if (rg_read_text("/sys/kernel/security/lsm", buf, sizeof(buf)) <= 0)
		return 0;
	for (tok = strtok_r(buf, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		while (*tok == ' ' || *tok == '\t')
			tok++;
		if (strcmp(tok, "ai") == 0)
			return 1;
	}
	return 0;
}

/*
 * 用户态接线：给当前任务打 sec.ws_label=RG_LSM_LABEL（NETLINK_AI ACT，
 * domain=SECURITY，定向参数名 sec.ws_label，data[0]=pid、data[1]=label）。
 * 返回 1=已打标签；0=宿主无 hook（待 #61 验证）；-1=hook 在但接线失败
 * （range_enable 会 fail-closed 拒绝启用）。
 */
int rg_lsm_attach(char *out, size_t cap)
{
	struct ai_nl_client cli;
	struct ai_nl_act act;
	struct ai_nl_act_ack ack;
	int rc, kern_err = 0;
	int ret;

	if (!rg_lsm_probe()) {
		snprintf(out, cap,
			 "absent: 宿主内核 /sys/kernel/security/lsm 无 ai "
			 "（socket_connect/socket_sendmsg hook 待 #61 环境验证；"
			 "当前仅用户态 CIDR 硬校验）");
		return 0;
	}
	rc = ai_nl_client_open(&cli);
	if (rc != AI_OK) {
		snprintf(out, cap,
			 "failed: NETLINK_AI open rc=%d errno=%s"
			 "（hook 存在但无法接线，待 #61 环境验证）",
			 rc, strerror(errno));
		return -1;
	}
	memset(&act, 0, sizeof(act));
	memset(&ack, 0, sizeof(ack));
	act.domain = 5;		/* AI_POLICY_DOMAIN_SECURITY */
	act.confidence = 100;
	act.data[0] = (unsigned long long)getpid();
	act.data[1] = RG_LSM_LABEL;
	snprintf(act.param, sizeof(act.param), "sec.ws_label");
	rc = ai_nl_send_act(&cli, &act, &ack, &kern_err);
	ai_nl_client_close(&cli);
	if (rc == AI_OK && ack.ai_err == 0 && kern_err == 0) {
		snprintf(out, cap,
			 "attached: sec.ws_label=%d pid=%d（内核 socket hook "
			 "可作第二道闸门；实测规则待 #61）",
			 RG_LSM_LABEL, (int)getpid());
		ret = 1;
	} else {
		snprintf(out, cap,
			 "failed: sec.ws_label 接线 rc=%d kern_err=%d "
			 "ai_err=%d（待 #61 环境验证）",
			 rc, kern_err, (int)ack.ai_err);
		ret = -1;
	}
	return ret;
}

static void rg_lsm_detach(void)
{
	struct ai_nl_client cli;
	struct ai_nl_act act;
	struct ai_nl_act_ack ack;
	int kern_err = 0;

	if (!rg_lsm_probe())
		return;
	if (ai_nl_client_open(&cli) != AI_OK)
		return;
	memset(&act, 0, sizeof(act));
	memset(&ack, 0, sizeof(ack));
	act.domain = 5;
	act.confidence = 100;
	act.data[0] = (unsigned long long)getpid();
	act.data[1] = 0;
	snprintf(act.param, sizeof(act.param), "sec.ws_label");
	(void)ai_nl_send_act(&cli, &act, &ack, &kern_err);
	ai_nl_client_close(&cli);
}

/* ===================== 拒绝文本 ===================== */

static const char *rg_disabled_text(void)
{
	return "ERROR: range 通道未启用（出厂默认关闭；工具已注册，不是缺失"
	       "也不是桩）。\n"
	       "如何启用：调用 range_enable，参数 cidr=10.231.0.0/16 或 "
	       "10.99.0.0/16 或 127.0.0.0/8（仅 netns 内），ttl_minutes=1..60"
	       "（默认 30，上限 60）。range_enable 属 D3，需授权者确认；"
	       "到期自动关闭。\n"
	       "允许靶场 CIDR（硬编码）：10.231.0.0/16、10.99.0.0/16、"
	       "127.0.0.0/8。其它网段（含 192.168.245.0/24、10.0.0.0/8、"
	       "公网）一律拒绝。\n";
}

static int rg_refuse(char **out, const char *tool, const char *target,
		     const char *why, const char *detail)
{
	(void)rg_audit_v(tool, "refuse", target, 0, "-", "", -1, "refused",
			 why);
	if (asprintf(out, "ERROR: %s\n%s\n", why,
		     detail ? detail : "") < 0)
		*out = NULL;
	return -1;
}

/* ===================== 端口探测 ===================== */

static void rg_errno_state(int err, char *state, size_t cap)
{
	switch (err) {
	case ECONNREFUSED:
		snprintf(state, cap, "closed");
		break;
	case EHOSTUNREACH:
	case ENETUNREACH:
		snprintf(state, cap, "unreachable");
		break;
	case ETIMEDOUT:
		snprintf(state, cap, "filtered(timeout)");
		break;
	default:
		snprintf(state, cap, "error:%s", strerror(err));
		break;
	}
}

static int rg_tcp_probe(const char *target, unsigned short port,
			int timeout_ms, char *state, size_t cap)
{
	struct sockaddr_in sa;
	struct pollfd pfd;
	int fd, rc, soerr = 0;
	socklen_t sl = sizeof(soerr);

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (inet_pton(AF_INET, target, &sa.sin_addr) != 1) {
		snprintf(state, cap, "error:bad-target");
		return -1;
	}
	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		snprintf(state, cap, "error:socket:%s", strerror(errno));
		return -1;
	}
	rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (rc == 0) {
		close(fd);
		snprintf(state, cap, "open");
		return 0;
	}
	if (errno != EINPROGRESS) {
		rg_errno_state(errno, state, cap);
		close(fd);
		return 0;
	}
	pfd.fd = fd;
	pfd.events = POLLOUT;
	pfd.revents = 0;
	rc = poll(&pfd, 1, timeout_ms);
	if (rc == 0) {
		close(fd);
		snprintf(state, cap, "filtered(timeout)");
		return 0;
	}
	if (rc < 0) {
		snprintf(state, cap, "error:poll:%s", strerror(errno));
		close(fd);
		return -1;
	}
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0) {
		snprintf(state, cap, "error:getsockopt:%s", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	if (soerr == 0) {
		snprintf(state, cap, "open");
		return 0;
	}
	rg_errno_state(soerr, state, cap);
	return 0;
}

static int rg_udp_probe(const char *target, unsigned short port,
			int timeout_ms, char *state, size_t cap)
{
	struct sockaddr_in sa;
	struct pollfd pfd;
	unsigned char probe = 0;
	int fd, rc, soerr = 0;
	socklen_t sl = sizeof(soerr);

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (inet_pton(AF_INET, target, &sa.sin_addr) != 1) {
		snprintf(state, cap, "error:bad-target");
		return -1;
	}
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		snprintf(state, cap, "error:socket:%s", strerror(errno));
		return -1;
	}
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		snprintf(state, cap, "error:connect:%s", strerror(errno));
		close(fd);
		return -1;
	}
	/* UDP connect 探测：发 1 字节；ICMP port unreachable => closed，
	 * 有应答 => open，超时 => open|filtered（如实标注不确定性） */
	(void)send(fd, &probe, 1, 0);
	pfd.fd = fd;
	pfd.events = POLLIN | POLLERR;
	pfd.revents = 0;
	rc = poll(&pfd, 1, timeout_ms);
	if (rc == 0) {
		close(fd);
		snprintf(state, cap, "open|filtered");
		return 0;
	}
	if (rc < 0) {
		snprintf(state, cap, "error:poll:%s", strerror(errno));
		close(fd);
		return -1;
	}
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) == 0 &&
	    soerr != 0) {
		rg_errno_state(soerr, state, cap);
		close(fd);
		return 0;
	}
	if (pfd.revents & POLLIN) {
		unsigned char rbuf[64];

		if (recv(fd, rbuf, sizeof(rbuf), 0) >= 0) {
			snprintf(state, cap, "open");
			close(fd);
			return 0;
		}
	}
	snprintf(state, cap, "open|filtered");
	close(fd);
	return 0;
}

/* ===================== 报文构造 ===================== */

static unsigned int rg_sum16(const void *data, size_t len, unsigned int sum)
{
	const unsigned char *p = data;
	size_t i;

	for (i = 0; i + 1 < len; i += 2)
		sum += (unsigned int)((p[i] << 8) | p[i + 1]);
	if (i < len)
		sum += (unsigned int)(p[i] << 8);
	return sum;
}

static unsigned short rg_fold(unsigned int sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (unsigned short)~sum;
}

static unsigned short rg_tcp_csum(unsigned int saddr, unsigned int daddr,
				  const unsigned char *tcp, size_t len)
{
	unsigned int sum = 0;

	sum = rg_sum16(&saddr, 4, sum);
	sum = rg_sum16(&daddr, 4, sum);
	sum += 6;			/* protocol TCP */
	sum += (unsigned int)len;
	return rg_fold(rg_sum16(tcp, len, sum));
}

static unsigned short rg_icmp_csum(const unsigned char *icmp, size_t len)
{
	return rg_fold(rg_sum16(icmp, len, 0));
}

/* 选源地址：UDP connect 后 getsockname，内核按路由选，不发包 */
static int rg_pick_source(const char *target, unsigned int *src)
{
	struct sockaddr_in sa, local;
	socklen_t sl = sizeof(local);
	int fd;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	if (inet_pton(AF_INET, target, &sa.sin_addr) != 1)
		return -1;
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		close(fd);
		return -1;
	}
	if (getsockname(fd, (struct sockaddr *)&local, &sl) != 0) {
		close(fd);
		return -1;
	}
	close(fd);
	*src = local.sin_addr.s_addr;
	return 0;
}

static int rg_send_udp(const char *target, unsigned short port,
		       const unsigned char *payload, size_t plen, int *saved)
{
	struct sockaddr_in sa;
	int fd, n;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (inet_pton(AF_INET, target, &sa.sin_addr) != 1)
		return -1;
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		*saved = errno;
		return -1;
	}
	n = (int)sendto(fd, payload, plen, 0, (struct sockaddr *)&sa,
			sizeof(sa));
	*saved = errno;
	close(fd);
	return n;
}

static int rg_send_tcp_syn(const char *target, unsigned short port,
			   const unsigned char *payload, size_t plen,
			   int *saved, unsigned short *sport,
			   unsigned int *seq)
{
	struct sockaddr_in dst;
	unsigned int saddr = 0, daddr;
	unsigned char pkt[20 + RG_MAX_PAYLOAD];
	unsigned short csum;
	int fd, n;
	uint32_t s;
	unsigned short sp;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_port = htons(port);
	if (inet_pton(AF_INET, target, &dst.sin_addr) != 1)
		return -1;
	daddr = dst.sin_addr.s_addr;
	if (rg_pick_source(target, &saddr) != 0) {
		*saved = EHOSTUNREACH;
		return -1;
	}
	srand((unsigned int)(time(NULL) ^ getpid()));
	s = (uint32_t)rand() ^ (uint32_t)(time(NULL) << 7);
	sp = (unsigned short)(40000 + ((unsigned int)getpid() * 7) % 20000);
	*sport = sp;
	*seq = s;
	memset(pkt, 0, sizeof(pkt));
	pkt[0] = (unsigned char)(sp >> 8);
	pkt[1] = (unsigned char)(sp & 0xff);
	pkt[2] = (unsigned char)(port >> 8);
	pkt[3] = (unsigned char)(port & 0xff);
	pkt[4] = (unsigned char)(s >> 24);
	pkt[5] = (unsigned char)(s >> 16);
	pkt[6] = (unsigned char)(s >> 8);
	pkt[7] = (unsigned char)s;
	pkt[12] = 5 << 4;		/* data offset 5，无选项 */
	pkt[13] = 0x02;			/* SYN */
	pkt[14] = 0xff;
	pkt[15] = 0xff;			/* window 65535 */
	if (plen)
		memcpy(pkt + 20, payload, plen);
	csum = rg_tcp_csum(saddr, daddr, pkt, 20 + plen);
	pkt[16] = (unsigned char)(csum >> 8);
	pkt[17] = (unsigned char)(csum & 0xff);
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (fd < 0) {
		*saved = errno;
		return -1;
	}
	n = (int)sendto(fd, pkt, 20 + plen, 0, (struct sockaddr *)&dst,
			sizeof(dst));
	*saved = errno;
	close(fd);
	return n;
}

static int rg_send_icmp(const char *target, const unsigned char *payload,
			size_t plen, int *saved, unsigned short *icmp_id,
			unsigned short *icmp_seq)
{
	struct sockaddr_in dst;
	unsigned char pkt[8 + RG_MAX_PAYLOAD];
	unsigned short csum;
	unsigned short id, seq;
	int fd, n;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	if (inet_pton(AF_INET, target, &dst.sin_addr) != 1)
		return -1;
	id = (unsigned short)(getpid() & 0xffff);
	seq = 1;
	*icmp_id = id;
	*icmp_seq = seq;
	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 8;			/* echo request */
	pkt[1] = 0;
	pkt[4] = (unsigned char)(id >> 8);
	pkt[5] = (unsigned char)(id & 0xff);
	pkt[6] = (unsigned char)(seq >> 8);
	pkt[7] = (unsigned char)(seq & 0xff);
	if (plen)
		memcpy(pkt + 8, payload, plen);
	csum = rg_icmp_csum(pkt, 8 + plen);
	pkt[2] = (unsigned char)(csum >> 8);
	pkt[3] = (unsigned char)(csum & 0xff);
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd < 0) {
		*saved = errno;
		return -1;
	}
	n = (int)sendto(fd, pkt, 8 + plen, 0, (struct sockaddr *)&dst,
			sizeof(dst));
	*saved = errno;
	close(fd);
	return n;
}

/* ===================== 工具参数 ===================== */

static int rg_jget_str(const char *json, const char *key, char *out,
		       size_t cap)
{
	const char *v;
	size_t vl;
	int ty;

	if (!json || !key || !out || cap == 0)
		return -1;
	if (ai_json_obj_get(json, strlen(json), key, &v, &vl, &ty) != 1 ||
	    ty != AI_JSON_STR)
		return -1;
	{
		char *s = ai_json_strdup_str(v, vl);

		if (!s)
			return -1;
		snprintf(out, cap, "%s", s);
		free(s);
	}
	return 0;
}

static int rg_jget_int(const char *json, const char *key, long long *out)
{
	const char *v;
	size_t vl;
	int ty;

	if (!json || !key || !out)
		return -1;
	if (ai_json_obj_get(json, strlen(json), key, &v, &vl, &ty) != 1 ||
	    ty != AI_JSON_NUM)
		return -1;
	*out = ai_json_ll(v, vl);
	return 0;
}

static int rg_jhas(const char *json, const char *key)
{
	const char *v;
	size_t vl;
	int ty;

	if (!json || !key)
		return 0;
	return ai_json_obj_get(json, strlen(json), key, &v, &vl, &ty) == 1;
}

/* ===================== 五个工具 ===================== */

static int rg_tool_status(char **out)
{
	struct rg_state st;
	char err[128];
	int r;

	r = rg_state_load(&st, err, sizeof(err));
	if (r < 0) {
		(void)rg_audit_v("range_status", "status", "-", 0, "-", "", -1,
				 "error", err);
		if (asprintf(out, "ERROR: range_status 读取状态失败：%s\n", err) <
		    0)
			*out = NULL;
		return -1;
	}
	if (r == 0) {
		(void)rg_audit_v("range_status", "status", "-", 0, "-", "", -1,
				 "disabled", "未启用");
		if (asprintf(out, "%s当前状态: enabled=0 remaining_ttl=0 "
			     "actions=0\n", rg_disabled_text()) < 0)
			*out = NULL;
		return -1;
	}
	(void)rg_audit_v("range_status", "status", "-", 0, "-", "", 0,
			 "enabled", st.cidr);
	if (asprintf(out,
		     "range_status（enabled）\n"
		     "enabled=1 cidr=%s ttl_minutes=%d remaining_seconds=%lld "
		     "expires_at=%lld actions=%llu watchdog_alive=%d\n"
		     "allowed_cidr=%s\n"
		     "lsm_socket_hook=%s\n"
		     "state_dir=$AIKERNEL_RANGE_DIR 或 /run/aik-range（root）"
		     "/ /tmp/aik-range-<uid>；audit=audit.log（不可关闭）\n"
		     "闸门：enable/scan/inject=D3，disable=D1，status=D0；"
		     "目标必须同时落在声明 CIDR 与硬编码清单内。\n"
		     "待 #61 环境验证：内核 socket hook 实测（宿主 6.8 无 "
		     "ai LSM）。\n",
		     st.cidr, st.ttl_minutes,
		     (long long)(st.expires_at - rg_now()), st.expires_at,
		     st.actions, rg_watchdog_alive(), rg_allowlist_text(),
		     st.lsm) < 0)
		*out = NULL;
	return 0;
}

static int rg_tool_enable(const char *args, char **out)
{
	struct rg_state st;
	struct rg_cidr c;
	char cidr[RG_MAX_CIDR] = "";
	char err[256] = "";
	long long ttl = RG_DEFAULT_TTL_MIN;
	long long now;
	struct timespec ts;
	int lsm_rc;

	if (rg_state_load(&st, err, sizeof(err)) < 0) {
		return rg_refuse(out, "range_enable", "-", err, NULL);
	}
	if (st.enabled) {
		(void)rg_audit_v("range_enable", "enable", st.cidr, 0, "-", "",
				 -1, "refused", "已启用，需先 range_disable");
		if (asprintf(out,
			     "ERROR: range 通道已启用（cidr=%s，剩余 %lld 秒）。"
			     "变更 CIDR/TTL 前先 range_disable。\n",
			     st.cidr, (long long)(st.expires_at - rg_now())) < 0)
			*out = NULL;
		return -1;
	}
	if (rg_jget_str(args, "cidr", cidr, sizeof(cidr)) != 0) {
		(void)rg_audit_v("range_enable", "enable", "-", 0, "-", "", -1,
				 "refused", "缺 cidr");
		if (asprintf(out,
			     "ERROR: 缺少 cidr（必须在硬编码允许清单内：%s）\n",
			     rg_allowlist_text()) < 0)
			*out = NULL;
		return -1;
	}
	if (rg_cidr_allowlisted(cidr, err, sizeof(err)) != 0) {
		(void)rg_audit_v("range_enable", "enable", cidr, 0, "-", "", -1,
				 "refused", err);
		if (asprintf(out, "ERROR: %s\n", err) < 0)
			*out = NULL;
		return -1;
	}
	if (rg_cidr_parse(cidr, &c, err, sizeof(err)) != 0) {
		(void)rg_audit_v("range_enable", "enable", cidr, 0, "-", "", -1,
				 "refused", err);
		if (asprintf(out, "ERROR: %s\n", err) < 0)
			*out = NULL;
		return -1;
	}
	if (rg_jhas(args, "ttl_minutes") &&
	    rg_jget_int(args, "ttl_minutes", &ttl) != 0) {
		(void)rg_audit_v("range_enable", "enable", cidr, 0, "-", "",
				 -1, "refused", "ttl_minutes 类型非法");
		if (asprintf(out,
			     "ERROR: ttl_minutes 必须是整数 1..%d\n",
			     RG_MAX_TTL_MIN) < 0)
			*out = NULL;
		return -1;
	}
	if (rg_jget_int(args, "ttl_minutes", &ttl) == 0) {
		if (ttl < 1 || ttl > RG_MAX_TTL_MIN) {
			(void)rg_audit_v("range_enable", "enable", cidr, 0, "-",
					 "", -1, "refused", "ttl 越界");
			if (asprintf(out,
				     "ERROR: ttl_minutes 必须在 1..%d 之间"
				     "（实际 %lld，默认 %d）\n",
				     RG_MAX_TTL_MIN, ttl,
				     RG_DEFAULT_TTL_MIN) < 0)
				*out = NULL;
			return -1;
		}
	}
	now = rg_now();
	clock_gettime(CLOCK_REALTIME, &ts);
	rg_state_default(&st);
	st.enabled = 1;
	snprintf(st.cidr, sizeof(st.cidr), "%s", c.text);
	st.net = c;
	st.ttl_minutes = (int)ttl;
	st.enabled_at = now;
	st.expires_at = now + ttl * 60;
	st.actions = 0;
	st.session = (unsigned long long)ts.tv_nsec ^
		     ((unsigned long long)ts.tv_sec << 32) ^
		     (unsigned long long)getpid() ^ 0xA1C0FFEEULL;
	lsm_rc = rg_lsm_attach(st.lsm, sizeof(st.lsm));
	if (lsm_rc < 0) {
		(void)rg_audit_v("range_enable", "enable", cidr, 0, "-", "", -1,
				 "refused", st.lsm);
		if (asprintf(out,
			     "ERROR: range_enable 拒绝：LSM hook 存在但用户态"
			     "接线失败（fail-closed）。%s\n", st.lsm) < 0)
			*out = NULL;
		return -1;
	}
	(void)rg_audit_v("range_enable", "enable", st.cidr, 0, "-", "", 0,
			 "attempt", st.lsm);
	if (rg_state_write(&st) != 0) {
		(void)rg_audit_v("range_enable", "enable", st.cidr, 0, "-", "",
				 -1, "error", "state.json 写入失败");
		if (asprintf(out, "ERROR: state.json 写入失败：%s\n",
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	if (rg_watchdog_spawn(st.session, err, sizeof(err)) != 0) {
		(void)rg_lsm_detach();
		rg_state_remove();
		(void)rg_audit_v("range_enable", "enable", st.cidr, 0, "-", "",
				 -1, "error", err);
		if (asprintf(out, "ERROR: watchdog 启动失败：%s（已回滚）\n",
			     err) < 0)
			*out = NULL;
		return -1;
	}
	(void)rg_audit_v("range_enable", "enable", st.cidr, 0, "-", "", 0,
			 "enabled", st.lsm);
	if (asprintf(out,
		     "range_enable（完成）\n"
		     "enabled=1 cidr=%s ttl_minutes=%d expires_at=%lld\n"
		     "allowed_cidr=%s\n"
		     "lsm_socket_hook=%s\n"
		     "watchdog=已启动（到期自动关闭；每次调用前也做惰性"
		     "expires_at 检查）\n"
		     "闸门=D3（需授权者确认）；audit.log 已记录。\n",
		     st.cidr, st.ttl_minutes, st.expires_at,
		     rg_allowlist_text(), st.lsm) < 0)
		*out = NULL;
	return 0;
}

static int rg_tool_disable(char **out)
{
	struct rg_state st;
	char err[128];
	int r = rg_state_load(&st, err, sizeof(err));

	if (r < 0) {
		return rg_refuse(out, "range_disable", "-", err, NULL);
	}
	if (r == 0) {
		(void)rg_audit_v("range_disable", "disable", "-", 0, "-", "",
				 -1, "refused", "未启用");
		if (asprintf(out, "%s当前状态: enabled=0（无可关闭）\n",
			     rg_disabled_text()) < 0)
			*out = NULL;
		return -1;
	}
	(void)rg_audit_v("range_disable", "disable", st.cidr, 0, "-", "", 0,
			 "attempt", "manual");
	rg_watchdog_stop();
	rg_state_remove();
	rg_lsm_detach();
	(void)rg_audit_v("range_disable", "disable", st.cidr, 0, "-", "", 0,
			 "disabled", "手动关闭，状态已清");
	if (asprintf(out,
		     "range_disable（完成）\n"
		     "enabled=0 原 cidr=%s；watchdog 已停，state.json 已清，"
		     "sec.ws_label 已尝试清零。\n"
		     "再次调用 range_scan/range_inject 将被拒绝（需重新 "
		     "range_enable + D3）。\n", st.cidr) < 0)
		*out = NULL;
	return 0;
}

static int rg_tool_scan(const char *args, char **out)
{
	struct rg_state st;
	char err[256] = "";
	char target[64] = "";
	char proto[16] = "tcp";
	char portspec[1024] = "";
	unsigned short ports[RG_MAX_PORTS];
	int nports = 0, i, timeout_ms = RG_DEFAULT_TIMEOUT_MS;
	long long tmo = 0;
	char **lines = NULL;
	int open_n = 0, closed_n = 0, other_n = 0;
	char *body = NULL;
	size_t body_len = 0;
	FILE *ms = NULL;
	int r;

	r = rg_state_load(&st, err, sizeof(err));
	if (r < 0)
		return rg_refuse(out, "range_scan", "-", err, NULL);
	if (r == 0) {
		(void)rg_audit_v("range_scan", "scan", target, 0, proto, "", -1,
				 "refused", "未启用");
		if (asprintf(out, "%s当前状态: enabled=0（scan 不执行）\n",
			     rg_disabled_text()) < 0)
			*out = NULL;
		return -1;
	}
	if (rg_jget_str(args, "target", target, sizeof(target)) != 0) {
		(void)rg_audit_v("range_scan", "scan", "-", 0, proto, "", -1,
				 "refused", "缺 target");
		if (asprintf(out, "ERROR: 缺少 target\n") < 0)
			*out = NULL;
		return -1;
	}
	if (rg_jget_str(args, "protocol", proto, sizeof(proto)) != 0)
		snprintf(proto, sizeof(proto), "tcp");
	if (strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0) {
		(void)rg_audit_v("range_scan", "scan", target, 0, proto, "", -1,
				 "refused", "protocol 非法");
		if (asprintf(out, "ERROR: protocol 只支持 tcp|udp（实际 %s）\n",
			     proto) < 0)
			*out = NULL;
		return -1;
	}
	if (rg_jget_str(args, "ports", portspec, sizeof(portspec)) != 0) {
		(void)rg_audit_v("range_scan", "scan", target, 0, proto, "", -1,
				 "refused", "缺 ports");
		if (asprintf(out, "ERROR: 缺少 ports（如 22,80,8000-8010）\n") <
		    0)
			*out = NULL;
		return -1;
	}
	if (rg_parse_ports(portspec, ports, RG_MAX_PORTS, &nports, err,
			   sizeof(err)) != 0) {
		(void)rg_audit_v("range_scan", "scan", target, 0, proto, "", -1,
				 "refused", err);
		if (asprintf(out, "ERROR: %s\n", err) < 0)
			*out = NULL;
		return -1;
	}
	if (rg_jhas(args, "timeout_ms") &&
	    rg_jget_int(args, "timeout_ms", &tmo) != 0) {
		(void)rg_audit_v("range_scan", "scan", target, 0, proto, "",
				 -1, "refused", "timeout_ms 类型非法");
		if (asprintf(out, "ERROR: timeout_ms 必须是整数 1..%d\n",
			     RG_MAX_TIMEOUT_MS) < 0)
			*out = NULL;
		return -1;
	}
	if (rg_jget_int(args, "timeout_ms", &tmo) == 0) {
		if (tmo < 1 || tmo > RG_MAX_TIMEOUT_MS) {
			(void)rg_audit_v("range_scan", "scan", target, 0, proto,
					 "", -1, "refused", "timeout_ms 越界");
			if (asprintf(out,
				     "ERROR: timeout_ms 必须在 1..%d 之间"
				     "（默认 %d）\n", RG_MAX_TIMEOUT_MS,
				     RG_DEFAULT_TIMEOUT_MS) < 0)
				*out = NULL;
			return -1;
		}
		timeout_ms = (int)tmo;
	}
	if (rg_target_allowed(&st, target, err, sizeof(err)) != 0) {
		char det[1200];

		snprintf(det, sizeof(det), "ports=%s; %s", portspec, err);
		(void)rg_audit_v("range_scan", "scan", target, 0, proto, "",
				 -1, "refused", det);
		if (asprintf(out, "ERROR: %s\n（审计已留痕：target/协议/"
			     "端口列表/rc）\n", err) < 0)
			*out = NULL;
		return -1;
	}
	if (rg_audit_v("range_scan", "scan", target, 0, proto, "", 0,
		       "attempt", portspec) != 0) {
		if (asprintf(out,
			     "ERROR: audit.log 写入失败，拒绝执行（fail-closed）\n")
		    < 0)
			*out = NULL;
		return -1;
	}
	lines = calloc((size_t)nports, sizeof(*lines));
	if (!lines) {
		if (asprintf(out, "ERROR: 内存不足\n") < 0)
			*out = NULL;
		return -1;
	}
	ms = open_memstream(&body, &body_len);
	if (!ms) {
		free(lines);
		if (asprintf(out, "ERROR: open_memstream 失败\n") < 0)
			*out = NULL;
		return -1;
	}
	fprintf(ms, "range_scan（完成）\n");
	fprintf(ms, "target=%s protocol=%s timeout_ms=%d ports=%d cidr=%s\n",
		target, proto, timeout_ms, nports, st.cidr);
	fprintf(ms, "results:\n");
	for (i = 0; i < nports; i++) {
		char state[96] = "";
		int prc;

		if (strcmp(proto, "tcp") == 0)
			prc = rg_tcp_probe(target, ports[i], timeout_ms, state,
					   sizeof(state));
		else
			prc = rg_udp_probe(target, ports[i], timeout_ms, state,
					   sizeof(state));
		lines[i] = strdup(state);
		if (!lines[i]) {
			snprintf(state, sizeof(state), "error:oom");
			lines[i] = strdup(state);
		}
		fprintf(ms, " %u %s\n", ports[i], lines[i] ? lines[i] : "?");
		if (lines[i] && strcmp(lines[i], "open") == 0)
			open_n++;
		else if (lines[i] && strcmp(lines[i], "closed") == 0)
			closed_n++;
		else
			other_n++;
		/* 每端口一条全量审计：目标/端口/协议/rc */
		(void)rg_audit_v("range_scan", "scan", target, ports[i], proto,
				 "", prc, lines[i] ? lines[i] : "?", "probe");
	}
	fprintf(ms, "summary: open=%d closed=%d other=%d\n", open_n,
		closed_n, other_n);
	fprintf(ms, "cidr=%s actions=%llu\n", st.cidr, st.actions + 1);
	fclose(ms);
	(void)rg_state_bump(&st);
	(void)rg_audit_v("range_scan", "scan", target, 0, proto, "", 0,
			 "ok", "完成，见逐端口行");
	if (asprintf(out, "%s", body ? body : "range_scan（无输出）\n") < 0)
		*out = NULL;
	for (i = 0; i < nports; i++)
		free(lines[i]);
	free(lines);
	free(body);
	return 0;
}

static int rg_tool_inject(const char *args, char **out)
{
	struct rg_state st;
	char err[256] = "";
	char target[64] = "";
	char proto[16] = "udp";
	char *hex = NULL;
	unsigned char payload[RG_MAX_PAYLOAD];
	size_t plen = 0;
	long long port_ll = -1;
	unsigned short port = 0;
	char payload_hex[RG_MAX_PAYLOAD * 2 + 1];
	char errhint[256] = "";
	int rc = 0, saved = 0, bytes;
	unsigned short sport = 0, icmp_id = 0, icmp_seq = 0;
	unsigned int seq = 0;
	int r;

	r = rg_state_load(&st, err, sizeof(err));
	if (r < 0)
		return rg_refuse(out, "range_inject", "-", err, NULL);
	if (r == 0) {
		(void)rg_audit_v("range_inject", "inject", target, 0, proto, "",
				 -1, "refused", "未启用");
		if (asprintf(out, "%s当前状态: enabled=0（inject 不执行）\n",
			     rg_disabled_text()) < 0)
			*out = NULL;
		return -1;
	}
	if (rg_jget_str(args, "target", target, sizeof(target)) != 0) {
		(void)rg_audit_v("range_inject", "inject", "-", 0, proto, "", -1,
				 "refused", "缺 target");
		if (asprintf(out, "ERROR: 缺少 target\n") < 0)
			*out = NULL;
		return -1;
	}
	/* 目标边界在构造/发送前硬校验；但先解析参数，保证拒绝审计
	 * 也能记录请求的协议/端口/payload 全文。 */
	if (rg_jget_str(args, "protocol", proto, sizeof(proto)) != 0)
		snprintf(proto, sizeof(proto), "udp");
	if (strcmp(proto, "tcp") == 0)
		snprintf(proto, sizeof(proto), "tcp_syn");
	if (strcmp(proto, "udp") != 0 && strcmp(proto, "tcp_syn") != 0 &&
	    strcmp(proto, "icmp") != 0) {
		(void)rg_audit_v("range_inject", "inject", target, 0, proto, "",
				 -1, "refused", "protocol 非法");
		if (asprintf(out,
			     "ERROR: protocol 只支持 udp|tcp_syn|icmp（实际 %s）\n",
			     proto) < 0)
			*out = NULL;
		return -1;
	}
	if (rg_jhas(args, "port") &&
	    rg_jget_int(args, "port", &port_ll) != 0) {
		(void)rg_audit_v("range_inject", "inject", target, 0, proto,
				 "", -1, "refused", "port 类型非法");
		if (asprintf(out, "ERROR: port 必须是整数 0..65535\n") < 0)
			*out = NULL;
		return -1;
	}
	if (rg_jget_int(args, "port", &port_ll) == 0) {
		if (port_ll < 0 || port_ll > 65535) {
			(void)rg_audit_v("range_inject", "inject", target, 0,
					 proto, "", -1, "refused",
					 "port 越界");
			if (asprintf(out, "ERROR: port 必须在 0..65535\n") < 0)
				*out = NULL;
			return -1;
		}
		port = (unsigned short)port_ll;
	}
	if (strcmp(proto, "icmp") != 0 && port_ll < 0) {
		(void)rg_audit_v("range_inject", "inject", target, 0, proto, "",
				 -1, "refused", "缺 port");
		if (asprintf(out, "ERROR: protocol=%s 需要 port\n", proto) < 0)
			*out = NULL;
		return -1;
	}
	if (rg_jget_str(args, "payload_hex", payload_hex,
			sizeof(payload_hex)) == 0) {
		hex = payload_hex;
	}
	if (rg_hex_decode(hex, payload, sizeof(payload), &plen, err,
			  sizeof(err)) != 0) {
		(void)rg_audit_v("range_inject", "inject", target, port, proto,
				 hex ? hex : "", -1, "refused", err);
		if (asprintf(out, "ERROR: %s\n", err) < 0)
			*out = NULL;
		return -1;
	}
	rg_hex_encode(payload, plen, payload_hex, sizeof(payload_hex));
	if (rg_target_allowed(&st, target, err, sizeof(err)) != 0) {
		(void)rg_audit_v("range_inject", "inject", target, port, proto,
				 payload_hex, -1, "refused", err);
		if (asprintf(out, "ERROR: %s\n（审计已留痕：target/协议/端口/"
			     "payload 全文/rc）\n", err) < 0)
			*out = NULL;
		return -1;
	}
	if (rg_audit_v("range_inject", "inject", target, port, proto,
		       payload_hex, 0, "attempt", "发送前审计（payload 全文）")
	    != 0) {
		if (asprintf(out,
			     "ERROR: audit.log 写入失败，拒绝发送（fail-closed）\n")
		    < 0)
			*out = NULL;
		return -1;
	}
	if (strcmp(proto, "udp") == 0) {
		bytes = rg_send_udp(target, port, payload, plen, &saved);
	} else if (strcmp(proto, "tcp_syn") == 0) {
		bytes = rg_send_tcp_syn(target, port, payload, plen, &saved,
					&sport, &seq);
	} else {
		bytes = rg_send_icmp(target, payload, plen, &saved, &icmp_id,
				     &icmp_seq);
	}
	if (bytes < 0) {
		rc = -saved;
		if (saved == EPERM || saved == EACCES)
			snprintf(errhint, sizeof(errhint),
				 "（%s 需要 root/CAP_NET_RAW；UDP 不需要）",
				 proto);
		(void)rg_audit_v("range_inject", "inject", target, port, proto,
				 payload_hex, rc, "error", strerror(saved));
		if (asprintf(out,
			     "ERROR: range_inject 发送失败：%s%s\n"
			     "target=%s protocol=%s port=%u payload_bytes=%zu\n",
			     strerror(saved), errhint, target, proto, port,
			     plen) < 0)
			*out = NULL;
		return -1;
	}
	(void)rg_audit_v("range_inject", "inject", target, port, proto,
			 payload_hex, 0, "sent", "sendto 返回字节数");
	(void)rg_state_bump(&st);
	if (asprintf(out,
		     "range_inject（完成）\n"
		     "target=%s protocol=%s port=%u bytes_sent=%d "
		     "payload_bytes=%zu\n"
		     "payload_hex=%s\n"
		     "tcp_sport=%u tcp_seq=%u icmp_id=%u icmp_seq=%u\n"
		     "cidr=%s actions=%llu\n"
		     "audit.log 已记录（target/port/protocol/payload 全文/rc）\n",
		     target, proto, port, bytes, plen, payload_hex, sport,
		     seq, icmp_id, icmp_seq, st.cidr, st.actions) < 0)
		*out = NULL;
	return 0;
}

/* ===================== 通道入口 ===================== */

int exec_net_range_channel(const void *tool, const char *args_json,
			   char **out)
{
	const char *name = tool ? ((const struct ai_tool *)tool)->name : NULL;
	const char *args = args_json ? args_json : "{}";

	if (!out)
		return -1;
	*out = NULL;
	if (!name) {
		*out = strdup("ERROR: range 工具名为空（注册表异常）");
		return -1;
	}
	if (strcmp(name, "range_status") == 0)
		return rg_tool_status(out);
	if (strcmp(name, "range_enable") == 0)
		return rg_tool_enable(args, out);
	if (strcmp(name, "range_disable") == 0)
		return rg_tool_disable(out);
	if (strcmp(name, "range_scan") == 0)
		return rg_tool_scan(args, out);
	if (strcmp(name, "range_inject") == 0)
		return rg_tool_inject(args, out);
	if (asprintf(out, "ERROR: 未知 range 工具（注册表异常）：%s\n", name) <
	    0)
		*out = NULL;
	return -1;
}
