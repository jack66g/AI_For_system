/* SPDX-License-Identifier: GPL-2.0 */
/*
 * net_chain.c - W81 E1：conntrack 事件流 + 攻击链关联实现
 *
 * 数据流：
 *   事件源（procfs → conntrack 命令 → 内置 ctnetlink，逐级降级）
 *        │  每 interval 秒取一次连接表快照
 *        ▼
 *   与上一拍快照比较 → 本拍“新出现的连接”进入每源滑动窗口
 *        ▼
 *   scan（同源不同目的端口数）/ lateral（同源同端口不同目的主机数）/
 *   burst（同 (源,目的) 连接数从前窗低位跃变到当前高位）
 *        ▼
 *   命中 → events.jsonl + audit.log（只观测；不写 nft、不封禁）
 *
 * 诚实降级：
 *   - 三档事件源逐条探测（存在/可读/权限/空表），status 原样输出；
 *   - 全部不可用时 start 直接失败，绝不静默成功；
 *   - 表为空标 empty（不是错误，采样继续）；
 *   - 无 nf_conntrack_acct 时 packets/bytes 标“不可用”，
 *     关联规则只依赖连接事件，不假装有计数。
 *
 * 状态目录（0600 文件、0700 目录）：
 *   state pid run.cfg rules.json status.json audit.log events.jsonl
 *   daemon.log daemon.lock
 *
 * 生命周期与 net_hit 同款：start 父进程探测 + flock 单例 + 握手后立刻
 * 返回；采样循环在 setsid 子进程里跑。stop 先 SIGTERM 等自清理，5 秒不
 * 退才 SIGKILL，然后按持久化记录兜底清理。
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netlink.h>

#include "net_chain.h"
#include "tool_registry.h"

#ifndef NLA_TYPE_MASK
#define NLA_TYPE_MASK 0x3fff
#endif

#define NC_TEXT_CAP		(2 * 1024 * 1024)
#define NC_PATH_LEN		600
#define NC_MAX_TRIGGERS		4096	/* 单进程最多事件数（防审计刷爆） */

static volatile sig_atomic_t g_stop;

/* ======================================================================
 * 0) 小工具
 * ====================================================================== */

static void nc_sig_stop(int sig)
{
	(void)sig;
	g_stop = 1;
}

static char *nc_trim(char *s)
{
	char *e;

	while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
		s++;
	e = s + strlen(s);
	while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' ||
			 e[-1] == '\n'))
		*--e = '\0';
	return s;
}

static int nc_mkdir_p0700(const char *path)
{
	struct stat st;

	if (!path || !*path)
		return -1;
	if (mkdir(path, 0700) == 0)
		return 0;
	if (errno != EEXIST)
		return -1;
	if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
		return -1;
	return 0;
}

int nc_chain_dir(char *out, size_t cap)
{
	const char *env = getenv("AIKERNEL_NET_CHAIN_DIR");

	if (!out || cap == 0)
		return -1;
	if (env && *env)
		snprintf(out, cap, "%s", env);
	else if (geteuid() == 0)
		snprintf(out, cap, "/run/aik-net-chain");
	else
		snprintf(out, cap, "/tmp/aik-net-chain-%u", (unsigned)geteuid());
	return nc_mkdir_p0700(out);
}

static void nc_path(char *out, size_t cap, const char *dir, const char *name)
{
	size_t dl = strlen(dir);

	if (dl + 2 >= cap)
		dl = cap - 3;
	snprintf(out, cap, "%.*s/%.*s", (int)dl, dir,
		 (int)(cap - dl - 2), name);
}

static int nc_write_file0600(const char *path, const char *data)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	size_t len = data ? strlen(data) : 0;
	size_t off = 0;

	if (fd < 0)
		return -1;
	while (off < len) {
		ssize_t w = write(fd, data + off, len - off);

		if (w <= 0) {
			close(fd);
			return -1;
		}
		off += (size_t)w;
	}
	close(fd);
	return 0;
}

static int nc_read_text(const char *path, char *buf, size_t cap)
{
	int fd;
	size_t used = 0;

	if (!buf || cap == 0)
		return -1;
	buf[0] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	while (used + 1 < cap) {
		ssize_t r = read(fd, buf + used, cap - used - 1);

		if (r <= 0)
			break;
		used += (size_t)r;
	}
	close(fd);
	buf[used] = '\0';
	return 0;
}

/* 时间戳前缀追加（audit.log / daemon.log 同一格式） */
static void nc_slog(const char *path, const char *fmt, ...)
{
	char line[4096];
	char ts[64];
	time_t now = time(NULL);
	struct tm tmv;
	va_list ap;
	int n, fd;

	localtime_r(&now, &tmv);
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);
	n = snprintf(line, sizeof(line), "[%s] ", ts);
	va_start(ap, fmt);
	vsnprintf(line + n, sizeof(line) - (size_t)n, fmt, ap);
	va_end(ap);
	n = (int)strlen(line);
	if (n < (int)sizeof(line) - 1) {
		line[n++] = '\n';
		line[n] = '\0';
	}
	fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	(void)!write(fd, line, (size_t)n);
	close(fd);
}

static void nc_audit(const char *dir, const char *fmt, ...)
{
	char path[NC_PATH_LEN];
	char msg[3000];
	va_list ap;

	nc_path(path, sizeof(path), dir, "audit.log");
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	nc_slog(path, "%s", msg);
}

static void nc_dlog(const char *dir, const char *fmt, ...)
{
	char path[NC_PATH_LEN];
	char msg[3000];
	va_list ap;

	nc_path(path, sizeof(path), dir, "daemon.log");
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	nc_slog(path, "%s", msg);
}

static void nc_json_escape(const char *in, char *out, size_t cap)
{
	size_t o = 0;

	if (!out || cap == 0)
		return;
	for (; in && *in && o + 7 < cap; in++) {
		unsigned char c = (unsigned char)*in;

		if (c == '"' || c == '\\') {
			out[o++] = '\\';
			out[o++] = (char)c;
		} else if (c == '\n') {
			out[o++] = '\\';
			out[o++] = 'n';
		} else if (c == '\t') {
			out[o++] = '\\';
			out[o++] = 't';
		} else if (c < 0x20) {
			o += (size_t)snprintf(out + o, cap - o, "\\u%04x", c);
		} else {
			out[o++] = (char)c;
		}
	}
	out[o] = '\0';
}

/* 最小 JSON 取值（工具参数/策略文件；够用即可，不引入解析库） */
static int nc_jget_str(const char *json, const char *key, char *out,
		       size_t cap)
{
	const char *p, *q;
	size_t kl;

	if (!json || !key || !out || cap == 0)
		return -1;
	out[0] = '\0';
	kl = strlen(key);
	p = json;
	while ((p = strchr(p, '"')) != NULL) {
		p++;
		if (strncmp(p, key, kl) == 0 && p[kl] == '"') {
			q = strchr(p + kl + 1, ':');
			if (!q)
				return -1;
			q++;
			while (*q == ' ' || *q == '\t' || *q == '\r' ||
			       *q == '\n')
				q++;
			if (*q != '"')
				return -1;
			q++;
			{
				size_t o = 0;

				while (*q && *q != '"' && o + 1 < cap) {
					if (*q == '\\' && q[1]) {
						q++;
						if (*q == 'n')
							out[o++] = '\n';
						else if (*q == 't')
							out[o++] = '\t';
						else
							out[o++] = *q;
						q++;
					} else {
						out[o++] = *q++;
					}
				}
				out[o] = '\0';
				return 0;
			}
		}
	}
	return -1;
}

static int nc_jget_int(const char *json, const char *key, long *out)
{
	const char *p;
	size_t kl;

	if (!json || !key || !out)
		return -1;
	kl = strlen(key);
	p = json;
	while ((p = strchr(p, '"')) != NULL) {
		p++;
		if (strncmp(p, key, kl) == 0 && p[kl] == '"') {
			char *end;
			long v;

			p = strchr(p + kl + 1, ':');
			if (!p)
				return -1;
			p++;
			while (*p == ' ' || *p == '\t' || *p == '\r' ||
			       *p == '\n')
				p++;
			if (*p == '"')
				p++;
			v = strtol(p, &end, 10);
			if (end == p)
				return -1;
			*out = v;
			return 0;
		}
	}
	return -1;
}

/* ======================================================================
 * 1) 配置
 * ====================================================================== */

void nc_cfg_default(struct nc_cfg *c)
{
	if (!c)
		return;
	memset(c, 0, sizeof(*c));
	c->interval = 2;
	c->scan_window = 60;
	c->scan_ports = 15;
	c->lateral_window = 60;
	c->lateral_hosts = 3;
	c->burst_window = 30;
	c->burst_ratio = 4;
	c->burst_min = 8;
	c->burst_low = 3;
	c->cooldown = 60;
}

int nc_cfg_parse(const char *json, struct nc_cfg *c, char *err, size_t ecap)
{
	struct {
		const char *key;
		int *dst;
	} ints[] = {
		{ "interval", &c->interval },
		{ "scan_window", &c->scan_window },
		{ "scan_ports", &c->scan_ports },
		{ "lateral_window", &c->lateral_window },
		{ "lateral_hosts", &c->lateral_hosts },
		{ "burst_window", &c->burst_window },
		{ "burst_ratio", &c->burst_ratio },
		{ "burst_min", &c->burst_min },
		{ "burst_low", &c->burst_low },
		{ "cooldown", &c->cooldown },
	};
	size_t i;

	if (!json || !c)
		return -1;
	for (i = 0; i < sizeof(ints) / sizeof(ints[0]); i++) {
		long v;

		if (nc_jget_int(json, ints[i].key, &v) == 0) {
			if (v < -2147483647L || v > 2147483647L) {
				if (err && ecap)
					snprintf(err, ecap, "%s 超出范围",
						 ints[i].key);
				return -1;
			}
			*ints[i].dst = (int)v;
		}
	}
	{
		char ns[64];

		if (nc_jget_str(json, "netns", ns, sizeof(ns)) == 0)
			snprintf(c->netns, sizeof(c->netns), "%s", ns);
	}
	return 0;
}

int nc_cfg_check(const struct nc_cfg *c, char *err, size_t ecap)
{
	int maxwin, ticks;
	size_t i;

#define NC_BAD(...) do { \
	if (err && ecap) snprintf(err, ecap, __VA_ARGS__); \
	return -1; \
} while (0)

	if (!c)
		return -1;
	if (c->interval < 1 || c->interval > 300)
		NC_BAD("interval 必须在 1..300 秒（当前 %d）", c->interval);
	if (c->scan_window < 1 || c->scan_window > 3600)
		NC_BAD("scan_window 必须在 1..3600 秒（当前 %d）",
		       c->scan_window);
	if (c->scan_ports < 2 || c->scan_ports > 1024)
		NC_BAD("scan_ports 必须在 2..1024（当前 %d）", c->scan_ports);
	if (c->lateral_window < 1 || c->lateral_window > 3600)
		NC_BAD("lateral_window 必须在 1..3600 秒（当前 %d）",
		       c->lateral_window);
	if (c->lateral_hosts < 2 || c->lateral_hosts > 256)
		NC_BAD("lateral_hosts 必须在 2..256（当前 %d）",
		       c->lateral_hosts);
	if (c->burst_window < 1 || c->burst_window > 3600)
		NC_BAD("burst_window 必须在 1..3600 秒（当前 %d）",
		       c->burst_window);
	if (c->burst_ratio < 2 || c->burst_ratio > 1000)
		NC_BAD("burst_ratio 必须在 2..1000（当前 %d）", c->burst_ratio);
	if (c->burst_min < 2 || c->burst_min > 1000000)
		NC_BAD("burst_min 必须在 2..1000000（当前 %d）", c->burst_min);
	if (c->burst_low < 0 || c->burst_low > 1000000)
		NC_BAD("burst_low 必须在 0..1000000（当前 %d）", c->burst_low);
	if (c->burst_min <= c->burst_low)
		NC_BAD("burst_min(%d) 必须大于 burst_low(%d)：低位→高位跃变"
		       "才成立", c->burst_min, c->burst_low);
	if (c->cooldown < 0 || c->cooldown > 86400)
		NC_BAD("cooldown 必须在 0..86400 秒（当前 %d）", c->cooldown);
	if (c->netns[0]) {
		for (i = 0; c->netns[i]; i++) {
			char ch = c->netns[i];

			if (!((ch >= 'A' && ch <= 'Z') ||
			      (ch >= 'a' && ch <= 'z') ||
			      (ch >= '0' && ch <= '9') || ch == '.' ||
			      ch == '_' || ch == '-'))
				NC_BAD("netns 标注只允许 [A-Za-z0-9._-]（当前 "
				       "\"%s\"）", c->netns);
		}
	}
	maxwin = c->scan_window > c->lateral_window ?
		c->scan_window : c->lateral_window;
	if (c->burst_window * 2 > maxwin)
		maxwin = c->burst_window * 2;
	ticks = (maxwin + c->interval - 1) / c->interval;
	if (ticks > NC_MAX_OBS)
		NC_BAD("窗口/采样周期过大：需要 %d 拍 > 上限 %d（请增大 "
		       "interval 或缩小窗口）", ticks, NC_MAX_OBS);
#undef NC_BAD
	return 0;
}

/* ======================================================================
 * 2) conntrack 文本解析（procfs 与 conntrack -L 共用）
 * ====================================================================== */

static unsigned long long nc_hash_conn(const struct nc_conn *c)
{
	unsigned long long h = 1469598103934665603ULL;
	const unsigned char *p;

#define NC_HMIX(byte) do { h ^= (unsigned char)(byte); h *= 1099511628211ULL; } while (0)
	for (p = (const unsigned char *)c->src; p && *p; p++)
		NC_HMIX(*p);
	NC_HMIX(0);
	for (p = (const unsigned char *)c->dst; p && *p; p++)
		NC_HMIX(*p);
	NC_HMIX(0);
	NC_HMIX(c->proto);
	NC_HMIX(c->sport >> 8);
	NC_HMIX(c->sport & 0xff);
	NC_HMIX(c->dport >> 8);
	NC_HMIX(c->dport & 0xff);
#undef NC_HMIX
	return h;
}

static int nc_proto_from_name(const char *s)
{
	if (!s)
		return -1;
	if (strcasecmp(s, "tcp") == 0)
		return 6;
	if (strcasecmp(s, "udp") == 0)
		return 17;
	if (strcasecmp(s, "icmp") == 0)
		return 1;
	if (strcasecmp(s, "icmpv6") == 0 || strcasecmp(s, "ipv6-icmp") == 0)
		return 58;
	if (strcasecmp(s, "sctp") == 0)
		return 132;
	if (strcasecmp(s, "dccp") == 0)
		return 33;
	return -1;
}

static int nc_is_ipv4(const char *s)
{
	struct in_addr a;

	return inet_pton(AF_INET, s, &a) == 1;
}

static int nc_is_ipv6(const char *s)
{
	struct in6_addr a;

	return inet_pton(AF_INET6, s, &a) == 1;
}

/*
 * 解析一行连接：
 *   procfs:      ipv4 2 tcp 6 431999 ESTABLISHED src=... dst=... sport=...
 *                dport=... packets=5 bytes=300 src=... dst=... [ASSURED]
 *   conntrack -L: tcp 6 431999 ESTABLISHED src=... dst=... ...
 *   UDP 无状态词：udp 17 29 src=... dst=... [UNREPLIED]
 * 只取“原始方向”的第一个 src/dst/sport/dport；第二个方向忽略。
 * 返回 1=解析成功，0=跳过/无法解析。
 */
int nc_parse_ct_line(const char *line, struct nc_conn *out)
{
	char *buf, *save = NULL, *tok;
	char *toks[128];
	int ntok = 0, i, have_src = 0, have_dst = 0;
	int proto = -1;
	struct nc_conn c;

	if (!line || !out)
		return 0;
	buf = strdup(line);
	if (!buf)
		return 0;
	memset(&c, 0, sizeof(c));
	c.packets = -1;
	c.bytes = -1;
	for (tok = strtok_r(buf, " \t", &save); tok && ntok < 128;
	     tok = strtok_r(NULL, " \t", &save))
		toks[ntok++] = tok;
	if (ntok == 0)
		goto bad;
	/* 段首标记：procfs 有 ipv4/ipv6 + 家族号 */
	i = 0;
	if (strcmp(toks[0], "ipv4") == 0 || strcmp(toks[0], "ipv6") == 0)
		i = 2;
	if (i < ntok) {
		int p = nc_proto_from_name(toks[i]);

		if (p > 0) {
			proto = p;
			i++;
			if (i < ntok && isdigit((unsigned char)toks[i][0])) {
				long v = strtol(toks[i], NULL, 10);

				if (v > 0)
					proto = (int)v;
				i++;
			}
			/* timeout */
			if (i < ntok && isdigit((unsigned char)toks[i][0]))
				i++;
			/* 可选状态词（无 '='、非 '[' 开头） */
			if (i < ntok && !strchr(toks[i], '=') &&
			    toks[i][0] != '[') {
				snprintf(c.state, sizeof(c.state), "%s",
					 toks[i]);
				i++;
			}
		}
	}
	for (; i < ntok; i++) {
		char *eq = strchr(toks[i], '=');

		if (!eq) {
			if (strcmp(toks[i], "[UNREPLIED]") == 0 &&
			    !c.state[0])
				snprintf(c.state, sizeof(c.state), "%s",
					 "UNREPLIED");
			continue;
		}
		*eq = '\0';
		if (strcmp(toks[i], "src") == 0 && !have_src) {
			snprintf(c.src, sizeof(c.src), "%s", eq + 1);
			have_src = 1;
		} else if (strcmp(toks[i], "dst") == 0 && !have_dst) {
			snprintf(c.dst, sizeof(c.dst), "%s", eq + 1);
			have_dst = 1;
		} else if (strcmp(toks[i], "sport") == 0 && c.sport == 0) {
			c.sport = (unsigned short)strtoul(eq + 1, NULL, 10);
		} else if (strcmp(toks[i], "dport") == 0 && c.dport == 0) {
			c.dport = (unsigned short)strtoul(eq + 1, NULL, 10);
		} else if (strcmp(toks[i], "packets") == 0 &&
			   c.packets < 0) {
			c.packets = strtoll(eq + 1, NULL, 10);
			c.has_counter = 1;
		} else if (strcmp(toks[i], "bytes") == 0 && c.bytes < 0) {
			c.bytes = strtoll(eq + 1, NULL, 10);
			c.has_counter = 1;
		}
	}
	if (!have_src || !have_dst || proto <= 0)
		goto bad;
	if (!nc_is_ipv4(c.src) && !nc_is_ipv6(c.src))
		goto bad;
	if (!nc_is_ipv4(c.dst) && !nc_is_ipv6(c.dst))
		goto bad;
	c.proto = proto;
	if (!c.state[0])
		snprintf(c.state, sizeof(c.state), "%s", "UNKNOWN");
	c.hash = nc_hash_conn(&c);
	*out = c;
	free(buf);
	return 1;
bad:
	free(buf);
	return 0;
}

int nc_parse_ct_text(const char *text, struct nc_conn *out, int max, int *n,
		     int *lines_bad)
{
	char *buf, *save = NULL, *line;
	int cnt = 0, bad = 0;

	if (n)
		*n = 0;
	if (lines_bad)
		*lines_bad = 0;
	if (!text || !out || max <= 0)
		return -1;
	buf = strdup(text);
	if (!buf)
		return -1;
	for (line = strtok_r(buf, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char *t = nc_trim(line);

		if (!*t || *t == '#')
			continue;
		if (cnt >= max)
			break;
		if (nc_parse_ct_line(t, &out[cnt]))
			cnt++;
		else
			bad++;
	}
	free(buf);
	if (n)
		*n = cnt;
	if (lines_bad)
		*lines_bad = bad;
	return 0;
}

/* ======================================================================
 * 3) ctnetlink dump（内置兜底事件源，无外部库依赖）
 * ====================================================================== */

static int nc_nla_ok(const struct nlattr *a, int rem)
{
	return rem >= (int)sizeof(*a) && a->nla_len >= sizeof(*a) &&
	       a->nla_len <= rem;
}

static struct nlattr *nc_nla_next(struct nlattr *a, int *rem)
{
	int step = NLA_ALIGN(a->nla_len);

	*rem -= step;
	return (struct nlattr *)((char *)a + step);
}

static const struct nlattr *nc_nla_find(const void *data, int len, int type)
{
	const struct nlattr *a;
	int rem = len;

	for (a = (const struct nlattr *)data; nc_nla_ok(a, rem);
	     a = nc_nla_next((struct nlattr *)a, &rem)) {
		if ((a->nla_type & NLA_TYPE_MASK) == type)
			return a;
	}
	return NULL;
}

static const void *nc_nla_data(const struct nlattr *a)
{
	return (const char *)a + sizeof(*a);
}

static int nc_nla_plen(const struct nlattr *a)
{
	return (int)a->nla_len - (int)sizeof(*a);
}

static const char *nc_tcp_state_name(int s)
{
	static const char *const names[] = {
		"NONE", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT",
		"CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE",
		"SYN_SENT2", "LISTEN",
	};

	if (s < 0 || s > 10)
		return "TCP_UNKNOWN";
	return names[s];
}

static void nc_nl_parse_tuple(const struct nlattr *tup, struct nc_conn *c)
{
	const struct nlattr *ip, *pr, *a;

	if (!tup)
		return;
	ip = nc_nla_find(nc_nla_data(tup), nc_nla_plen(tup), CTA_TUPLE_IP);
	if (ip) {
		a = nc_nla_find(nc_nla_data(ip), nc_nla_plen(ip),
				CTA_IP_V4_SRC);
		if (a && nc_nla_plen(a) >= 4)
			inet_ntop(AF_INET, nc_nla_data(a), c->src,
				  sizeof(c->src));
		else if ((a = nc_nla_find(nc_nla_data(ip), nc_nla_plen(ip),
					  CTA_IP_V6_SRC)) &&
			 nc_nla_plen(a) >= 16)
			inet_ntop(AF_INET6, nc_nla_data(a), c->src,
				  sizeof(c->src));
		a = nc_nla_find(nc_nla_data(ip), nc_nla_plen(ip),
				CTA_IP_V4_DST);
		if (a && nc_nla_plen(a) >= 4)
			inet_ntop(AF_INET, nc_nla_data(a), c->dst,
				  sizeof(c->dst));
		else if ((a = nc_nla_find(nc_nla_data(ip), nc_nla_plen(ip),
					  CTA_IP_V6_DST)) &&
			 nc_nla_plen(a) >= 16)
			inet_ntop(AF_INET6, nc_nla_data(a), c->dst,
				  sizeof(c->dst));
	}
	pr = nc_nla_find(nc_nla_data(tup), nc_nla_plen(tup), CTA_TUPLE_PROTO);
	if (pr) {
		uint8_t p;
		uint16_t v;

		a = nc_nla_find(nc_nla_data(pr), nc_nla_plen(pr),
				CTA_PROTO_NUM);
		if (a && nc_nla_plen(a) >= 1) {
			memcpy(&p, nc_nla_data(a), 1);
			c->proto = p;
		}
		a = nc_nla_find(nc_nla_data(pr), nc_nla_plen(pr),
				CTA_PROTO_SRC_PORT);
		if (a && nc_nla_plen(a) >= 2) {
			memcpy(&v, nc_nla_data(a), 2);
			c->sport = ntohs(v);
		}
		a = nc_nla_find(nc_nla_data(pr), nc_nla_plen(pr),
				CTA_PROTO_DST_PORT);
		if (a && nc_nla_plen(a) >= 2) {
			memcpy(&v, nc_nla_data(a), 2);
			c->dport = ntohs(v);
		}
	}
}

static void nc_nl_parse_counters(const void *attrs, int alen,
				 struct nc_conn *c)
{
	const struct nlattr *co, *a;
	uint64_t v64;
	uint32_t v32;

	co = nc_nla_find(attrs, alen, CTA_COUNTERS_ORIG);
	if (co) {
		a = nc_nla_find(nc_nla_data(co), nc_nla_plen(co),
				CTA_COUNTERS_PACKETS);
		if (a && nc_nla_plen(a) >= 8) {
			memcpy(&v64, nc_nla_data(a), 8);
			c->packets = (long long)be64toh(v64);
			c->has_counter = 1;
		}
		a = nc_nla_find(nc_nla_data(co), nc_nla_plen(co),
				CTA_COUNTERS_BYTES);
		if (a && nc_nla_plen(a) >= 8) {
			memcpy(&v64, nc_nla_data(a), 8);
			c->bytes = (long long)be64toh(v64);
			c->has_counter = 1;
		}
		/* 老内核可能给 32bit 计数（同一 nested 属性内） */
		if (!c->has_counter) {
			a = nc_nla_find(nc_nla_data(co), nc_nla_plen(co),
					CTA_COUNTERS32_PACKETS);
			if (a && nc_nla_plen(a) >= 4) {
				memcpy(&v32, nc_nla_data(a), 4);
				c->packets = (long long)ntohl(v32);
				c->has_counter = 1;
			}
			a = nc_nla_find(nc_nla_data(co), nc_nla_plen(co),
					CTA_COUNTERS32_BYTES);
			if (a && nc_nla_plen(a) >= 4) {
				memcpy(&v32, nc_nla_data(a), 4);
				c->bytes = (long long)ntohl(v32);
				c->has_counter = 1;
			}
		}
	}
}

static void nc_nl_parse_one(const struct nlmsghdr *h, struct nc_conn *c)
{
	const char *base = (const char *)NLMSG_DATA(h) +
			   sizeof(struct nfgenmsg);
	int alen = (int)h->nlmsg_len - (int)NLMSG_LENGTH(sizeof(struct nfgenmsg));
	const struct nlattr *a;
	uint32_t status = 0;
	int have_status = 0;

	memset(c, 0, sizeof(*c));
	c->packets = -1;
	c->bytes = -1;
	a = nc_nla_find(base, alen, CTA_TUPLE_ORIG);
	nc_nl_parse_tuple(a, c);
	a = nc_nla_find(base, alen, CTA_TUPLE_REPLY);
	(void)a;	/* 只关心原始方向 */
	nc_nl_parse_counters(base, alen, c);
	a = nc_nla_find(base, alen, CTA_STATUS);
	if (a && nc_nla_plen(a) >= 4) {
		memcpy(&status, nc_nla_data(a), 4);
		status = ntohl(status);
		have_status = 1;
	}
	/* TCP 状态优先（比 status 位更具体） */
	{
		const struct nlattr *pi, *tcp, *st;

		pi = nc_nla_find(base, alen, CTA_PROTOINFO);
		tcp = pi ? nc_nla_find(nc_nla_data(pi), nc_nla_plen(pi),
				       CTA_PROTOINFO_TCP) : NULL;
		st = tcp ? nc_nla_find(nc_nla_data(tcp), nc_nla_plen(tcp),
				       CTA_PROTOINFO_TCP_STATE) : NULL;
		if (st && nc_nla_plen(st) >= 1) {
			uint8_t s;

			memcpy(&s, nc_nla_data(st), 1);
			snprintf(c->state, sizeof(c->state), "%s",
				 nc_tcp_state_name(s));
		}
	}
	if (!c->state[0]) {
		if (have_status && !(status & IPS_SEEN_REPLY))
			snprintf(c->state, sizeof(c->state), "%s",
				 "UNREPLIED");
		else
			snprintf(c->state, sizeof(c->state), "%s", "REPLIED");
	}
	c->hash = nc_hash_conn(c);
}

static int nc_nl_dump(struct nc_conn *out, int max, int *n, int *empty,
		      char *err, size_t ecap, int *truncated)
{
	int fd, total = 0, done = 0;
	unsigned int seq = (unsigned int)getpid() ^ (unsigned int)time(NULL);
	struct sockaddr_nl sa;
	char req[64];
	char buf[65536];
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;
	size_t reqlen;

	if (n)
		*n = 0;
	if (empty)
		*empty = 0;
	if (truncated)
		*truncated = 0;
	if (err && ecap)
		err[0] = '\0';
	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
	if (fd < 0) {
		if (err && ecap)
			snprintf(err, ecap, "socket(NETLINK_NETFILTER) 失败：%s",
				 strerror(errno));
		return -1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		if (err && ecap)
			snprintf(err, ecap, "netlink bind 失败：%s",
				 strerror(errno));
		close(fd);
		return -1;
	}
	memset(req, 0, sizeof(req));
	nlh = (struct nlmsghdr *)req;
	nfg = (struct nfgenmsg *)NLMSG_DATA(nlh);
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*nfg));
	nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq;
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(0);
	reqlen = nlh->nlmsg_len;
	if (sendto(fd, req, reqlen, 0, (struct sockaddr *)&sa, sizeof(sa)) <
	    0) {
		if (err && ecap)
			snprintf(err, ecap, "netlink 请求发送失败：%s",
				 strerror(errno));
		close(fd);
		return -1;
	}
	while (!done) {
		struct pollfd pf = { .fd = fd, .events = POLLIN };
		ssize_t r;
		int rem;

		if (poll(&pf, 1, 3000) <= 0) {
			if (err && ecap)
				snprintf(err, ecap,
					 "ctnetlink dump 超时（3s 无响应）");
			close(fd);
			return -1;
		}
		r = recv(fd, buf, sizeof(buf), 0);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			if (err && ecap)
				snprintf(err, ecap, "netlink recv 失败：%s",
					 strerror(errno));
			close(fd);
			return -1;
		}
		rem = (int)r;
		for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, rem);
		     nlh = NLMSG_NEXT(nlh, rem)) {
			if (nlh->nlmsg_type == NLMSG_DONE) {
				done = 1;
				break;
			}
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e =
					(struct nlmsgerr *)NLMSG_DATA(nlh);

				if (e->error == 0) {
					done = 1;
					break;
				}
				if (err && ecap) {
					if (e->error == -EPERM ||
					    e->error == -EACCES)
						snprintf(err, ecap,
							 "权限不足：需要 "
							 "root/CAP_NET_ADMIN"
							 "（%s）",
							 strerror(-e->error));
					else
						snprintf(err, ecap,
							 "ctnetlink 错误：%s",
							 strerror(-e->error));
				}
				close(fd);
				return -1;
			}
			if ((nlh->nlmsg_type >> 8) == NFNL_SUBSYS_CTNETLINK) {
				if (total < max) {
					nc_nl_parse_one(nlh, &out[total]);
					total++;
				} else if (truncated) {
					*truncated = 1;
				}
			}
		}
	}
	close(fd);
	if (n)
		*n = total;
	if (empty)
		*empty = (total == 0);
	return 0;
}

/* ======================================================================
 * 4) 事件源探测 / 采样
 * ====================================================================== */

static const char *const nc_ct_paths[] = {
	"/usr/sbin/conntrack",
	"/sbin/conntrack",
	"/usr/bin/conntrack",
	"/bin/conntrack",
	NULL,
};

/* 有界 fork/execv（合并 stdout+stderr，超时 SIGKILL；net_admin 同款） */
static int nc_run_argv(char *const argv[], int timeout_s, char *out,
		       size_t cap, int *truncated)
{
	int pfd[2];
	pid_t pid;
	size_t used = 0;
	long deadline_ms = (long)timeout_s * 1000;
	long spent = 0;
	int status;

	if (truncated)
		*truncated = 0;
	if (out && cap)
		out[0] = '\0';
	if (pipe(pfd) < 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}
	if (pid == 0) {
		close(pfd[0]);
		dup2(pfd[1], 1);
		dup2(pfd[1], 2);
		close(pfd[1]);
		execv(argv[0], (char *const *)argv);
		_exit(127);
	}
	close(pfd[1]);
	while (spent < deadline_ms) {
		struct pollfd p = { .fd = pfd[0], .events = POLLIN };
		int r = poll(&p, 1, 200);

		if (r > 0 && (p.revents & (POLLIN | POLLHUP))) {
			ssize_t nb;

			if (used + 1 >= cap)
				break;
			nb = read(pfd[0], out + used, cap - used - 1);
			if (nb <= 0) {
				while (waitpid(pid, &status, 0) < 0 &&
				       errno == EINTR)
					;
				close(pfd[0]);
				out[used] = '\0';
				return WIFEXITED(status) ?
					WEXITSTATUS(status) : -1;
			}
			used += (size_t)nb;
		} else if (r < 0 && errno != EINTR) {
			break;
		}
		spent += 200;
		if (waitpid(pid, &status, WNOHANG) == pid) {
			ssize_t nb;

			while (used + 1 < cap &&
			       (nb = read(pfd[0], out + used,
					  cap - used - 1)) > 0)
				used += (size_t)nb;
			close(pfd[0]);
			out[used] = '\0';
			return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
		}
	}
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	{
		ssize_t nb;

		while (used + 1 < cap &&
		       (nb = read(pfd[0], out + used, cap - used - 1)) > 0)
			used += (size_t)nb;
	}
	close(pfd[0]);
	out[used] = '\0';
	if (truncated && used + 1 >= cap)
		*truncated = 1;
	return -99;
}

int nc_probe_sources(struct nc_source *s, char *err, size_t ecap)
{
	int i;

	if (!s)
		return -1;
	memset(s, 0, sizeof(*s));
	if (err && ecap)
		err[0] = '\0';

	/* a) /proc/net/nf_conntrack */
	{
		int fd = open("/proc/net/nf_conntrack", O_RDONLY | O_CLOEXEC);

		if (fd < 0) {
			if (errno == ENOENT) {
				s->procfs = 0;
				snprintf(s->procfs_msg,
					 sizeof(s->procfs_msg),
					 "不可用：/proc/net/nf_conntrack 不存在"
					 "（内核未启用 CONFIG_NF_CONNTRACK_"
					 "PROCFS 或 nf_conntrack 未加载）");
			} else if (errno == EACCES || errno == EPERM) {
				s->procfs = -1;
				snprintf(s->procfs_msg,
					 sizeof(s->procfs_msg),
					 "不可用：权限不足（需要 root/"
					 "CAP_NET_ADMIN）");
			} else {
				s->procfs = 0;
				snprintf(s->procfs_msg,
					 sizeof(s->procfs_msg),
					 "不可用：打开失败（%s）",
					 strerror(errno));
			}
		} else {
			char one;

			if (read(fd, &one, 1) < 0 && errno != 0) {
				s->procfs = -1;
				snprintf(s->procfs_msg,
					 sizeof(s->procfs_msg),
					 "不可用：读取失败（%s）",
					 strerror(errno));
			} else {
				s->procfs = 1;
				snprintf(s->procfs_msg,
					 sizeof(s->procfs_msg),
					 "可用：/proc/net/nf_conntrack（轮询）");
			}
			close(fd);
		}
	}

	/* b) conntrack 命令（可选，不强制依赖） */
	for (i = 0; nc_ct_paths[i]; i++) {
		if (access(nc_ct_paths[i], X_OK) == 0) {
			s->cmd = 1;
			snprintf(s->cmd_path, sizeof(s->cmd_path), "%s",
				 nc_ct_paths[i]);
			snprintf(s->cmd_msg, sizeof(s->cmd_msg),
				 "可用：%s（conntrack -L 快照；不强制依赖）",
				 nc_ct_paths[i]);
			break;
		}
	}
	if (!s->cmd)
		snprintf(s->cmd_msg, sizeof(s->cmd_msg),
			 "不可用：未安装 conntrack 命令（不强制依赖，自动降级）");

	/* c) 内置 ctnetlink */
	{
		struct nc_conn tmp[8];
		int cn = 0, empty = 0, trunc = 0;
		char nerr[256];

		nerr[0] = '\0';
		if (nc_nl_dump(tmp, 8, &cn, &empty, nerr, sizeof(nerr),
			       &trunc) == 0) {
			s->netlink = 1;
			snprintf(s->netlink_msg, sizeof(s->netlink_msg),
				 "可用：内置 ctnetlink dump（%d 条%s）",
				 empty ? 0 : cn,
				 empty ? "，表为空" : "");
		} else {
			s->netlink = (strstr(nerr, "权限不足") != NULL) ? -1 : 0;
			snprintf(s->netlink_msg, sizeof(s->netlink_msg),
				 "不可用：%s", nerr[0] ? nerr : "未知错误");
		}
	}

	if (s->procfs == 1) {
		s->active = NC_SRC_PROCFS;
		snprintf(s->active_name, sizeof(s->active_name), "%s",
			 "procfs");
	} else if (s->cmd == 1) {
		s->active = NC_SRC_CMD;
		snprintf(s->active_name, sizeof(s->active_name), "%s",
			 "conntrack-cmd");
	} else if (s->netlink == 1) {
		s->active = NC_SRC_NETLINK;
		snprintf(s->active_name, sizeof(s->active_name), "%s",
			 "ctnetlink");
	} else {
		s->active = NC_SRC_NONE;
		snprintf(s->active_name, sizeof(s->active_name), "%s",
			 "none");
		if (err && ecap)
			snprintf(err, ecap,
				 "conntrack 事件源不可用：procfs=%s；"
				 "conntrack 命令=%s；ctnetlink=%s",
				 s->procfs_msg, s->cmd_msg, s->netlink_msg);
		return -1;
	}
	return 0;
}

static int nc_read_procfs(char *buf, size_t cap, int *truncated)
{
	int fd;
	size_t used = 0;

	if (truncated)
		*truncated = 0;
	fd = open("/proc/net/nf_conntrack", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	while (used + 1 < cap) {
		ssize_t r = read(fd, buf + used, cap - used - 1);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		if (r == 0)
			break;
		used += (size_t)r;
	}
	if (used + 1 >= cap && truncated)
		*truncated = 1;
	close(fd);
	buf[used] = '\0';
	return 0;
}

int nc_sample_now(struct nc_source *s, struct nc_conn *out, int max, int *n,
		  int *empty, char *err, size_t ecap)
{
	int trunc = 0;

	if (n)
		*n = 0;
	if (empty)
		*empty = 0;
	if (err && ecap)
		err[0] = '\0';
	if (!s || !out || max <= 0 || !n) {
		if (err && ecap)
			snprintf(err, ecap, "内部参数非法");
		return -1;
	}
	switch (s->active) {
	case NC_SRC_PROCFS: {
		char *text = malloc(NC_TEXT_CAP);

		if (!text) {
			if (err && ecap)
				snprintf(err, ecap, "内存不足（procfs 缓冲）");
			return -1;
		}
		if (nc_read_procfs(text, NC_TEXT_CAP, &trunc) != 0) {
			if (err && ecap)
				snprintf(err, ecap, "procfs 读取失败：%s",
					 strerror(errno));
			free(text);
			return -1;
		}
		{
			int bad = 0;

			(void)nc_parse_ct_text(text, out, max, n, &bad);
			if (trunc && err && ecap)
				snprintf(err, ecap,
					 "警告：procfs 输出超过 %d 字节已截断",
					 NC_TEXT_CAP);
		}
		free(text);
		if (empty)
			*empty = (*n == 0);
		return 0;
	}
	case NC_SRC_CMD: {
		char *text = malloc(NC_TEXT_CAP);
		char *argv[4];
		int rc;

		if (!text) {
			if (err && ecap)
				snprintf(err, ecap, "内存不足（conntrack 缓冲）");
			return -1;
		}
		argv[0] = s->cmd_path;
		argv[1] = (char *)"-L";
		argv[2] = NULL;
		rc = nc_run_argv(argv, 5, text, NC_TEXT_CAP, &trunc);
		if (rc != 0) {
			if (err && ecap)
				snprintf(err, ecap,
					 "conntrack -L 失败（rc=%d）：%.300s",
					 rc, text);
			free(text);
			return -1;
		}
		{
			int bad = 0;

			(void)nc_parse_ct_text(text, out, max, n, &bad);
		}
		free(text);
		if (empty)
			*empty = (*n == 0);
		return 0;
	}
	case NC_SRC_NETLINK:
		if (nc_nl_dump(out, max, n, empty, err, ecap, &trunc) != 0)
			return -1;
		return 0;
	default:
		if (err && ecap)
			snprintf(err, ecap,
				 "没有可用的事件源（procfs/conntrack 命令/"
				 "ctnetlink 均不可用）");
		return -1;
	}
}

/* ======================================================================
 * 5) 关联引擎
 * ====================================================================== */

void nc_engine_init(struct nc_engine *e)
{
	if (e)
		memset(e, 0, sizeof(*e));
}

static struct nc_src_state *nc_src_get(struct nc_engine *e, const char *src,
				       int create)
{
	int i;

	for (i = 0; i < e->src_n; i++)
		if (strcmp(e->src[i].src, src) == 0)
			return &e->src[i];
	if (!create)
		return NULL;
	if (e->src_n >= NC_MAX_SRCS) {
		e->dropped_srcs++;
		return NULL;
	}
	i = e->src_n++;
	memset(&e->src[i], 0, sizeof(e->src[i]));
	snprintf(e->src[i].src, sizeof(e->src[i].src), "%s", src);
	return &e->src[i];
}

int nc_engine_add(struct nc_engine *e, long ts, const struct nc_conn *c)
{
	struct nc_src_state *st;

	if (!e || !c || !c->src[0])
		return -1;
	st = nc_src_get(e, c->src, 1);
	if (!st)
		return -1;
	if (st->n >= NC_MAX_OBS) {
		int drop = st->n / 2;

		memmove(&st->obs[0], &st->obs[drop],
			(size_t)(st->n - drop) * sizeof(st->obs[0]));
		st->n -= drop;
		e->dropped_obs += drop;
	}
	st->obs[st->n].ts = ts;
	snprintf(st->obs[st->n].dst, sizeof(st->obs[st->n].dst), "%s",
		 c->dst);
	st->obs[st->n].dport = c->dport;
	st->obs[st->n].proto = c->proto;
	st->n++;
	st->total++;
	return 0;
}

static int nc_fire_ok(struct nc_engine *e, const char *key, long now,
		      int cooldown)
{
	int i, oldest = 0;

	for (i = 0; i < e->fire_n; i++) {
		if (strcmp(e->fires[i].key, key) == 0) {
			if (now - e->fires[i].ts < cooldown)
				return 0;
			e->fires[i].ts = now;
			return 1;
		}
		if (e->fires[i].ts < e->fires[oldest].ts)
			oldest = i;
	}
	if (e->fire_n < NC_MAX_FIRES) {
		i = e->fire_n++;
	} else {
		i = oldest;
		e->fires[i].ts = 0;
	}
	snprintf(e->fires[i].key, sizeof(e->fires[i].key), "%s", key);
	e->fires[i].ts = now;
	return 1;
}

static void nc_add_port(unsigned short *ports, int *pn, int max,
			unsigned short p, int *trunc)
{
	int i;

	for (i = 0; i < *pn && i < max; i++)
		if (ports[i] == p)
			return;
	if (*pn < max)
		ports[*pn] = p;
	else if (trunc)
		(*trunc)++;
	(*pn)++;
}

static void nc_add_dst(char dsts[][64], int *dn, int max, const char *dst,
		       int *trunc)
{
	int i;

	for (i = 0; i < *dn && i < max; i++)
		if (strcmp(dsts[i], dst) == 0)
			return;
	if (*dn < max)
		snprintf(dsts[*dn], 64, "%s", dst);
	else if (trunc)
		(*trunc)++;
	(*dn)++;
}

static void nc_prune_src(struct nc_src_state *st, long cutoff)
{
	int i, keep = 0;

	for (i = 0; i < st->n; i++)
		if (st->obs[i].ts >= cutoff)
			keep = i + 1;
	if (keep == 0) {
		st->n = 0;
		return;
	}
	if (keep < st->n) {
		memmove(&st->obs[0], &st->obs[st->n - keep],
			(size_t)keep * sizeof(st->obs[0]));
		st->n = keep;
	}
}

int nc_engine_eval(struct nc_engine *e, const struct nc_cfg *cfg, long now,
		   struct nc_hit *out, int max, int *n)
{
	int s, hits = 0, retention, maxwin;

	if (n)
		*n = 0;
	if (!e || !cfg || !out || max <= 0 || !n)
		return -1;
	maxwin = cfg->scan_window > cfg->lateral_window ?
		cfg->scan_window : cfg->lateral_window;
	if (cfg->burst_window * 2 > maxwin)
		maxwin = cfg->burst_window * 2;
	retention = maxwin + cfg->interval;
	for (s = 0; s < e->src_n; s++)
		nc_prune_src(&e->src[s], now - retention);

	for (s = 0; s < e->src_n && hits < max; s++) {
		struct nc_src_state *st = &e->src[s];
		long cutoff = now - cfg->scan_window;
		unsigned short ports[NC_MAX_TARGETS];
		char dsts[NC_MAX_TARGETS][64];
		int pn = 0, dn = 0, ptrunc = 0, dtrunc = 0;
		long ev = 0;
		int i;

		for (i = 0; i < st->n; i++) {
			if (st->obs[i].ts < cutoff)
				continue;
			ev++;
			nc_add_port(ports, &pn, NC_MAX_TARGETS,
				    st->obs[i].dport, &ptrunc);
			nc_add_dst(dsts, &dn, NC_MAX_TARGETS,
				   st->obs[i].dst, &dtrunc);
		}
		if (pn >= cfg->scan_ports && ev > 0) {
			char key[192];
			struct nc_hit *h = &out[hits];

			snprintf(key, sizeof(key), "scan|%s", st->src);
			if (nc_fire_ok(e, key, now, cfg->cooldown)) {
				memset(h, 0, sizeof(*h));
				h->type = NC_HIT_SCAN;
				snprintf(h->src, sizeof(h->src), "%s",
					 st->src);
				h->port_n = pn < NC_MAX_TARGETS ? pn :
					    NC_MAX_TARGETS;
				memcpy(h->ports, ports,
				       (size_t)h->port_n * sizeof(ports[0]));
				h->ports_truncated = ptrunc;
				h->dst_n = dn < NC_MAX_TARGETS ? dn :
					   NC_MAX_TARGETS;
				memcpy(h->dsts, dsts,
				       (size_t)h->dst_n * sizeof(dsts[0]));
				h->window = cfg->scan_window;
				h->evidence_count = ev;
				h->threshold = cfg->scan_ports;
				snprintf(h->rule, sizeof(h->rule),
					 "scan_ports>=%d", cfg->scan_ports);
				hits++;
			}
		}
	}

	/* lateral：同一源、同一目的端口、多个不同目的主机 */
	for (s = 0; s < e->src_n && hits < max; s++) {
		struct nc_src_state *st = &e->src[s];
		unsigned short dports[NC_MAX_OBS];
		int dpn = 0, i, j;
		long cutoff = now - cfg->lateral_window;

		for (i = 0; i < st->n; i++) {
			int seen = 0;

			if (st->obs[i].ts < cutoff)
				continue;
			for (j = 0; j < dpn; j++)
				if (dports[j] == st->obs[i].dport) {
					seen = 1;
					break;
				}
			if (!seen && dpn < NC_MAX_OBS)
				dports[dpn++] = st->obs[i].dport;
		}
		for (j = 0; j < dpn && hits < max; j++) {
			char dsts[NC_MAX_TARGETS][64];
			int dn = 0, dtrunc = 0, ptrunc = 0;
			unsigned short ports[NC_MAX_TARGETS];
			int pn = 0;
			long ev = 0;
			char key[192];

			for (i = 0; i < st->n; i++) {
				if (st->obs[i].ts < cutoff ||
				    st->obs[i].dport != dports[j])
					continue;
				ev++;
				nc_add_dst(dsts, &dn, NC_MAX_TARGETS,
					   st->obs[i].dst, &dtrunc);
				nc_add_port(ports, &pn, NC_MAX_TARGETS,
					    st->obs[i].dport, &ptrunc);
			}
			if (dn < cfg->lateral_hosts || ev <= 0)
				continue;
			snprintf(key, sizeof(key), "lateral|%s|%u", st->src,
				 (unsigned)dports[j]);
			if (!nc_fire_ok(e, key, now, cfg->cooldown))
				continue;
			{
				struct nc_hit *h = &out[hits];

				memset(h, 0, sizeof(*h));
				h->type = NC_HIT_LATERAL;
				snprintf(h->src, sizeof(h->src), "%s",
					 st->src);
				h->dst_n = dn < NC_MAX_TARGETS ? dn :
					   NC_MAX_TARGETS;
				memcpy(h->dsts, dsts,
				       (size_t)h->dst_n * sizeof(dsts[0]));
				h->port_n = 1;
				h->ports[0] = dports[j];
				h->ports_truncated = 0;
				h->window = cfg->lateral_window;
				h->evidence_count = ev;
				h->threshold = cfg->lateral_hosts;
				snprintf(h->rule, sizeof(h->rule),
					 "lateral_hosts>=%d@dport=%u",
					 cfg->lateral_hosts,
					 (unsigned)dports[j]);
				hits++;
			}
		}
	}

	/* burst：同一 (源,目的) 连接数从前窗低位跃变到当前高位 */
	for (s = 0; s < e->src_n && hits < max; s++) {
		struct nc_src_state *st = &e->src[s];
		char dsts[NC_MAX_OBS][64];
		int dn = 0, i, j;
		long cur_cut = now - cfg->burst_window;
		long prev_cut = now - cfg->burst_window * 2;

		for (i = 0; i < st->n; i++) {
			int seen = 0;

			if (st->obs[i].ts < prev_cut)
				continue;
			for (j = 0; j < dn; j++)
				if (strcmp(dsts[j], st->obs[i].dst) == 0) {
					seen = 1;
					break;
				}
			if (!seen && dn < NC_MAX_OBS)
				snprintf(dsts[dn++], 64, "%s",
					 st->obs[i].dst);
		}
		for (j = 0; j < dn && hits < max; j++) {
			long cur = 0, prev = 0;
			unsigned short ports[NC_MAX_TARGETS];
			int pn = 0, ptrunc = 0;
			char key[192];
			struct nc_hit *h;

			for (i = 0; i < st->n; i++) {
				if (strcmp(st->obs[i].dst, dsts[j]) != 0)
					continue;
				if (st->obs[i].ts > cur_cut) {
					cur++;
					nc_add_port(ports, &pn,
						    NC_MAX_TARGETS,
						    st->obs[i].dport,
						    &ptrunc);
				} else if (st->obs[i].ts > prev_cut) {
					prev++;
				}
			}
			if (prev < 1 || prev > cfg->burst_low ||
			    cur < cfg->burst_min ||
			    cur < (long)prev * cfg->burst_ratio)
				continue;
			snprintf(key, sizeof(key), "burst|%.63s|%.63s",
				 st->src, dsts[j]);
			if (!nc_fire_ok(e, key, now, cfg->cooldown))
				continue;
			h = &out[hits];
			memset(h, 0, sizeof(*h));
			h->type = NC_HIT_BURST;
			snprintf(h->src, sizeof(h->src), "%s", st->src);
			h->dst_n = 1;
			snprintf(h->dsts[0], 64, "%.63s", dsts[j]);
			h->port_n = pn < NC_MAX_TARGETS ? pn :
				    NC_MAX_TARGETS;
			memcpy(h->ports, ports,
			       (size_t)h->port_n * sizeof(ports[0]));
			h->ports_truncated = ptrunc;
			h->window = cfg->burst_window;
			h->evidence_count = cur;
			h->prev_count = prev;
			h->cur_count = cur;
			h->threshold = cfg->burst_min;
			snprintf(h->rule, sizeof(h->rule),
				 "burst cur>=%d && cur>=%dx prev(%ld)",
				 cfg->burst_min, cfg->burst_ratio, prev);
			hits++;
		}
	}
	*n = hits;
	return 0;
}

/* ======================================================================
 * 6) 事件/审计输出
 * ====================================================================== */

static const char *nc_hit_type_name(int t)
{
	switch (t) {
	case NC_HIT_SCAN:
		return "scan";
	case NC_HIT_LATERAL:
		return "lateral";
	case NC_HIT_BURST:
		return "burst";
	default:
		return "unknown";
	}
}

static void nc_join_ports(const struct nc_hit *h, char *out, size_t cap)
{
	size_t o = 0;
	int i;

	out[0] = '\0';
	for (i = 0; i < h->port_n && o + 16 < cap; i++)
		o += (size_t)snprintf(out + o, cap - o, "%s%u",
				      i ? "," : "", (unsigned)h->ports[i]);
	if (h->ports_truncated)
		snprintf(out + o, cap - o, "%s...(+%d)",
			 h->port_n ? "," : "", h->ports_truncated);
}

static void nc_join_dsts(const struct nc_hit *h, char *out, size_t cap)
{
	size_t o = 0;
	int i;

	out[0] = '\0';
	for (i = 0; i < h->dst_n && o + 80 < cap; i++)
		o += (size_t)snprintf(out + o, cap - o, "%s%s",
				      i ? "," : "", h->dsts[i]);
}

static void nc_write_event(const char *dir, const struct nc_hit *h,
			   const char *source, const char *netns, long now)
{
	char path[NC_PATH_LEN];
	char line[8192];
	char ts[64];
	char src[128], net[128];
	char dsts_json[2048];
	char ports_json[1024];
	char dsts_txt[2048], ports_txt[1024];
	struct tm tmv;
	time_t t = (time_t)now;
	size_t o = 0;
	int i, fd, n;

	localtime_r(&t, &tmv);
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);
	nc_json_escape(h->src, src, sizeof(src));
	nc_json_escape(netns && *netns ? netns : "", net, sizeof(net));
	o += (size_t)snprintf(dsts_json + o, sizeof(dsts_json) - o, "[");
	for (i = 0; i < h->dst_n && o + 100 < sizeof(dsts_json); i++) {
		char e[128];

		nc_json_escape(h->dsts[i], e, sizeof(e));
		o += (size_t)snprintf(dsts_json + o,
				      sizeof(dsts_json) - o, "%s\"%s\"",
				      i ? "," : "", e);
	}
	snprintf(dsts_json + o, sizeof(dsts_json) - o, "]");
	o = 0;
	o += (size_t)snprintf(ports_json + o, sizeof(ports_json) - o, "[");
	for (i = 0; i < h->port_n && o + 16 < sizeof(ports_json); i++)
		o += (size_t)snprintf(ports_json + o,
				      sizeof(ports_json) - o, "%s%u",
				      i ? "," : "", (unsigned)h->ports[i]);
	snprintf(ports_json + o, sizeof(ports_json) - o, "]");
	nc_join_dsts(h, dsts_txt, sizeof(dsts_txt));
	nc_join_ports(h, ports_txt, sizeof(ports_txt));

	n = snprintf(line, sizeof(line),
		     "{\"ts\":%ld,\"time\":\"%s\",\"type\":\"%s\","
		     "\"src\":\"%s\",\"dsts\":%s,\"ports\":%s,"
		     "\"window\":%d,\"evidence_count\":%ld,"
		     "\"prev_count\":%ld,\"cur_count\":%ld,"
		     "\"threshold\":%d,\"rule\":\"%s\","
		     "\"source\":\"%s\",\"netns\":\"%s\","
		     "\"action\":\"observe\","
		     "\"note\":\"只观测，不封禁\"}\n",
		     now, ts, nc_hit_type_name(h->type), src, dsts_json,
		     ports_json, h->window, h->evidence_count, h->prev_count,
		     h->cur_count, h->threshold, h->rule, source, net);
	if (n < 0 || n >= (int)sizeof(line))
		return;
	nc_path(path, sizeof(path), dir, "events.jsonl");
	fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	(void)!write(fd, line, (size_t)n);
	close(fd);

	nc_audit(dir,
		 "CHAIN type=%s src=%s dsts=%s ports=%s window=%ds "
		 "evidence=%ld prev=%ld cur=%ld threshold=%d rule=%s "
		 "source=%s netns=%s action=observe（只观测，不封禁）",
		 nc_hit_type_name(h->type), h->src, dsts_txt, ports_txt,
		 h->window, h->evidence_count, h->prev_count, h->cur_count,
		 h->threshold, h->rule, source,
		 netns && *netns ? netns : "-");
}

/* ======================================================================
 * 7) 配置持久化 / 状态
 * ====================================================================== */

static int nc_cfg_write(const char *dir, const char *name,
			const struct nc_cfg *c)
{
	char path[NC_PATH_LEN];
	char buf[1024];

	nc_path(path, sizeof(path), dir, name);
	snprintf(buf, sizeof(buf),
		 "{\n"
		 "  \"version\": 1,\n"
		 "  \"interval\": %d,\n"
		 "  \"scan_window\": %d,\n"
		 "  \"scan_ports\": %d,\n"
		 "  \"lateral_window\": %d,\n"
		 "  \"lateral_hosts\": %d,\n"
		 "  \"burst_window\": %d,\n"
		 "  \"burst_ratio\": %d,\n"
		 "  \"burst_min\": %d,\n"
		 "  \"burst_low\": %d,\n"
		 "  \"cooldown\": %d,\n"
		 "  \"netns\": \"%s\"\n"
		 "}\n",
		 c->interval, c->scan_window, c->scan_ports,
		 c->lateral_window, c->lateral_hosts, c->burst_window,
		 c->burst_ratio, c->burst_min, c->burst_low, c->cooldown,
		 c->netns);
	return nc_write_file0600(path, buf);
}

static int nc_cfg_load(const char *dir, const char *name, struct nc_cfg *c,
		       char *err, size_t ecap)
{
	char path[NC_PATH_LEN];
	char buf[2048];

	nc_cfg_default(c);
	nc_path(path, sizeof(path), dir, name);
	if (nc_read_text(path, buf, sizeof(buf)) != 0) {
		if (errno == ENOENT) {
			if (err && ecap)
				err[0] = '\0';
			return 0;	/* 首次使用：默认阈值 */
		}
		if (err && ecap)
			snprintf(err, ecap, "读取 %s 失败：%s", path,
				 strerror(errno));
		return -1;
	}
	if (nc_cfg_parse(buf, c, err, ecap) != 0)
		return -1;
	if (nc_cfg_check(c, err, ecap) != 0)
		return -1;
	return 0;
}

static void nc_write_status_json(const char *dir, const char *source,
				 int entries, const char *table, int acct,
				 long samples, long long new_conns,
				 long long events, long errors,
				 const char *last_error, long now)
{
	char path[NC_PATH_LEN];
	char line[2048];
	char escerr[512];

	nc_json_escape(last_error ? last_error : "", escerr, sizeof(escerr));
	nc_path(path, sizeof(path), dir, "status.json");
	snprintf(line, sizeof(line),
		 "{\"ts\":%ld,\"source\":\"%s\",\"entries\":%d,"
		 "\"table\":\"%s\",\"acct\":%d,\"samples\":%ld,"
		 "\"new_connections\":%lld,\"events\":%lld,\"errors\":%ld,"
		 "\"last_error\":\"%s\"}\n",
		 now, source, entries, table, acct,
		 samples, new_conns, events, errors, escerr);
	(void)nc_write_file0600(path, line);
}

static int nc_pid_alive(long pid)
{
	char path[64];

	if (pid <= 0)
		return 0;
	if (kill((pid_t)pid, 0) != 0 && errno != EPERM)
		return 0;
	snprintf(path, sizeof(path), "/proc/%ld", pid);
	return access(path, F_OK) == 0;
}

static long nc_read_pid(const char *dir)
{
	char path[NC_PATH_LEN];
	char buf[64];
	char *end;

	nc_path(path, sizeof(path), dir, "pid");
	if (nc_read_text(path, buf, sizeof(buf)) != 0)
		return 0;
	return strtol(buf, &end, 10);
}

static const char *nc_effective_state(const char *dir, long *pid_out,
				      int *alive_out)
{
	static char st[64];
	char path[NC_PATH_LEN];
	char buf[64];
	long pid;

	*pid_out = 0;
	*alive_out = 0;
	nc_path(path, sizeof(path), dir, "state");
	if (nc_read_text(path, buf, sizeof(buf)) != 0) {
		snprintf(st, sizeof(st), "not-running");
		return st;
	}
	{
		char *t = nc_trim(buf);

		snprintf(st, sizeof(st), "%s", *t ? t : "unknown");
	}
	pid = nc_read_pid(dir);
	*pid_out = pid;
	*alive_out = nc_pid_alive(pid);
	if (strcmp(st, "running") == 0 && !*alive_out)
		return "orphan";
	return st;
}

/* ======================================================================
 * 8) 采样器主循环
 * ====================================================================== */

static int nc_conn_is_new(const struct nc_conn *c, const struct nc_conn *prev,
			  int prev_n)
{
	int i;

	for (i = 0; i < prev_n; i++) {
		if (prev[i].hash != c->hash)
			continue;
		if (prev[i].proto == c->proto &&
		    prev[i].sport == c->sport &&
		    prev[i].dport == c->dport &&
		    strcmp(prev[i].src, c->src) == 0 &&
		    strcmp(prev[i].dst, c->dst) == 0)
			return 0;
	}
	return 1;
}

static void nc_daemon_loop(struct nc_cfg *cfg, const char *dir, int lockfd)
{
	struct nc_engine *eng;
	struct nc_conn *cur, *prev;
	struct nc_source src;
	char err[512], last_err[512];
	long last_err_at = 0, last_probe_at = 0;
	long samples = 0, errors = 0, events = 0;
	long long new_total = 0;
	time_t started = time(NULL);
	int prev_n = 0, primed = 0;
	int triggers = 0;

	g_stop = 0;
	signal(SIGTERM, nc_sig_stop);
	signal(SIGINT, nc_sig_stop);
	signal(SIGHUP, nc_sig_stop);

	eng = calloc(1, sizeof(*eng));
	cur = calloc(NC_MAX_ENTRIES, sizeof(*cur));
	prev = calloc(NC_MAX_ENTRIES, sizeof(*prev));
	if (!eng || !cur || !prev) {
		char path[NC_PATH_LEN];

		nc_dlog(dir, "采样器启动失败：内存不足");
		nc_path(path, sizeof(path), dir, "state");
		(void)nc_write_file0600(path, "failed\n");
		free(eng);
		free(cur);
		free(prev);
		if (lockfd >= 0)
			close(lockfd);
		_exit(1);
	}
	nc_engine_init(eng);
	memset(&src, 0, sizeof(src));
	err[0] = '\0';
	if (nc_probe_sources(&src, err, sizeof(err)) != 0) {
		nc_dlog(dir, "采样器启动失败：%s", err);
		nc_audit(dir, "WATCH-ERROR %s", err);
		{
			char path[NC_PATH_LEN];

			nc_path(path, sizeof(path), dir, "state");
			(void)nc_write_file0600(path, "failed\n");
		}
		free(eng);
		free(cur);
		free(prev);
		if (lockfd >= 0)
			close(lockfd);
		_exit(1);
	}
	{
		char path[NC_PATH_LEN];
		char pid[32];

		nc_path(path, sizeof(path), dir, "pid");
		snprintf(pid, sizeof(pid), "%ld\n", (long)getpid());
		(void)nc_write_file0600(path, pid);
		nc_path(path, sizeof(path), dir, "state");
		(void)nc_write_file0600(path, "running\n");
		(void)nc_cfg_write(dir, "run.cfg", cfg);
	}
	nc_audit(dir,
		 "WATCH-START pid=%ld source=%s interval=%ds "
		 "scan(window=%ds,ports>=%d) lateral(window=%ds,hosts>=%d) "
		 "burst(window=%ds,min=%d,ratio=%d,low<=%d) cooldown=%ds "
		 "netns=%s（只观测，不封禁）",
		 (long)getpid(), src.active_name, cfg->interval,
		 cfg->scan_window, cfg->scan_ports, cfg->lateral_window,
		 cfg->lateral_hosts, cfg->burst_window, cfg->burst_min,
		 cfg->burst_ratio, cfg->burst_low, cfg->cooldown,
		 cfg->netns[0] ? cfg->netns : "-");
	nc_dlog(dir, "采样器启动 pid=%ld source=%s", (long)getpid(),
		src.active_name);
	last_err[0] = '\0';

	while (!g_stop) {
		long now;
		int n = 0, empty = 0, rc;
		int acct = 0;

		/* 运行中每拍重读阈值（rules.json 热更新） */
		{
			struct nc_cfg p;
			char perr[256];

			if (nc_cfg_load(dir, "rules.json", &p, perr,
					sizeof(perr)) == 0) {
				p.netns[sizeof(p.netns) - 1] = '\0';
				cfg->interval = p.interval;
				cfg->scan_window = p.scan_window;
				cfg->scan_ports = p.scan_ports;
				cfg->lateral_window = p.lateral_window;
				cfg->lateral_hosts = p.lateral_hosts;
				cfg->burst_window = p.burst_window;
				cfg->burst_ratio = p.burst_ratio;
				cfg->burst_min = p.burst_min;
				cfg->burst_low = p.burst_low;
				cfg->cooldown = p.cooldown;
				snprintf(cfg->netns, sizeof(cfg->netns), "%s",
					 p.netns);
			}
		}
		now = (long)time(NULL);
		err[0] = '\0';
		rc = nc_sample_now(&src, cur, NC_MAX_ENTRIES, &n, &empty, err,
				   sizeof(err));
		samples++;
		if (rc != 0) {
			errors++;
			if (strcmp(last_err, err) != 0 ||
			    now - last_err_at >= 30) {
				nc_audit(dir, "SAMPLE-ERROR kind=%s err=%.400s",
					 src.active_name, err);
				snprintf(last_err, sizeof(last_err), "%s", err);
				last_err_at = now;
			}
			/* 采样失败：下一拍重新建基线，避免把旧连接全当新连接 */
			primed = 0;
			prev_n = 0;
			nc_write_status_json(dir, src.active_name, 0,
					     "unknown", 0, samples, new_total,
					     events, errors, err, now);
			/* 事件源可能恢复/切换：最多每 30 秒重探一次 */
			if (now - last_probe_at >= 30) {
				struct nc_source ns;
				char nerr[512];

				last_probe_at = now;
				if (nc_probe_sources(&ns, nerr,
						     sizeof(nerr)) == 0 &&
				    ns.active != src.active) {
					nc_audit(dir,
						 "SOURCE-SWITCH %s -> %s",
						 src.active_name,
						 ns.active_name);
					src = ns;
				}
			}
		} else {
			int i, added = 0;
			long long new_conns = 0;
			struct nc_hit hits[NC_MAX_EVENTS_PER_TICK];
			int hn = 0;

			if (empty && strcmp(last_err, "EMPTY") != 0) {
				nc_audit(dir,
					 "SAMPLE-EMPTY entries=0（conntrack "
					 "表为空；采样继续，不报错）");
				snprintf(last_err, sizeof(last_err), "%s",
					 "EMPTY");
				last_err_at = now;
			}
			for (i = 0; i < n; i++)
				if (cur[i].has_counter)
					acct = 1;
			if (!primed) {
				memcpy(prev, cur,
				       (size_t)n * sizeof(*prev));
				prev_n = n;
				primed = 1;
				nc_audit(dir,
					 "PRIMED source=%s entries=%d"
					 "（建立基线；已有连接不产生事件）",
					 src.active_name, n);
			} else {
				for (i = 0; i < n; i++) {
					if (!nc_conn_is_new(&cur[i], prev,
							    prev_n)) {
						continue;
					}
					if (nc_engine_add(eng, now, &cur[i]) ==
					    0) {
						added++;
						new_conns++;
					}
				}
				new_total += new_conns;
				memcpy(prev, cur, (size_t)n * sizeof(*prev));
				prev_n = n;
				if (added > 0)
					nc_engine_eval(eng, cfg, now, hits,
						       NC_MAX_EVENTS_PER_TICK,
						       &hn);
				{
					int hi;

					for (hi = 0; hi < hn; hi++) {
						if (triggers >= NC_MAX_TRIGGERS)
							break;
						nc_write_event(dir, &hits[hi],
							       src.active_name,
							       cfg->netns, now);
						triggers++;
						events++;
					}
				}
			}
			nc_write_status_json(dir, src.active_name, n,
					     empty ? "empty" : "non-empty",
					     acct, samples, new_total, events,
					     errors, "", now);
		}
		{
			int ticks = cfg->interval * 5;
			int slept = 0;

			while (!g_stop && slept < ticks) {
				usleep(200000);
				slept++;
			}
		}
	}
	{
		char path[NC_PATH_LEN];

		nc_audit(dir,
			 "WATCH-STOP pid=%ld uptime=%lds samples=%ld "
			 "new_connections=%lld events=%ld errors=%ld"
			 "（只观测，无规则需撤回）",
			 (long)getpid(), (long)(time(NULL) - started), samples,
			 new_total, events, errors);
		nc_dlog(dir, "采样器退出 pid=%ld", (long)getpid());
		nc_path(path, sizeof(path), dir, "state");
		(void)nc_write_file0600(path, "stopped\n");
		nc_path(path, sizeof(path), dir, "pid");
		unlink(path);
	}
	free(eng);
	free(cur);
	free(prev);
	if (lockfd >= 0)
		close(lockfd);
	_exit(0);
}

/* ======================================================================
 * 9) 工具层
 * ====================================================================== */

struct nc_buf {
	char *p;
	size_t cap;
	size_t used;
};

static void ncb_init(struct nc_buf *b, size_t cap)
{
	b->p = calloc(1, cap);
	b->cap = b->p ? cap : 0;
	b->used = 0;
}

static void ncb_add(struct nc_buf *b, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (!b || !b->p || b->used >= b->cap)
		return;
	va_start(ap, fmt);
	n = vsnprintf(b->p + b->used, b->cap - b->used, fmt, ap);
	va_end(ap);
	if (n > 0)
		b->used += (size_t)n < b->cap - b->used ?
			   (size_t)n : b->cap - b->used - 1;
}

static void ncb_free(struct nc_buf *b)
{
	free(b->p);
	b->p = NULL;
}

static void nc_tail_lines(const char *path, char *out, size_t cap, int want)
{
	char *buf;
	size_t n = 0, i, start;
	int fd, lines = 0;
	struct stat st;

	if (!out || cap == 0)
		return;
	out[0] = '\0';
	buf = malloc(256 * 1024);
	if (!buf)
		return;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		off_t off = 0;
		ssize_t r;

		if (fstat(fd, &st) == 0 && st.st_size > 256 * 1024 - 1)
			off = st.st_size - (256 * 1024 - 1);
		if (off > 0)
			(void)lseek(fd, off, SEEK_SET);
		r = read(fd, buf, 256 * 1024 - 1);
		close(fd);
		if (r > 0) {
			n = (size_t)r;
			if (off > 0) {
				/* 从行中间开始：跳到第一个完整行 */
				char *nl = memchr(buf, '\n', n);

				if (nl) {
					size_t skip = (size_t)(nl - buf) + 1;

					memmove(buf, buf + skip, n - skip);
					n -= skip;
				}
			}
		}
	}
	buf[n] = '\0';
	start = n;
	for (i = n; i > 0; i--) {
		if (buf[i - 1] == '\n') {
			lines++;
			if (lines > want) {
				start = i;
				break;
			}
		}
	}
	if (start > 0 && start < n && buf[start] == '\n')
		start++;
	snprintf(out, cap, "%.*s", (int)(cap - 1),
		 buf + (start < n ? start : 0));
	free(buf);
}

static void nc_probe_lines(const struct nc_source *s, struct nc_buf *b)
{
	ncb_add(b, "source_probe:\n");
	ncb_add(b, "  procfs=%s\n", s->procfs_msg);
	ncb_add(b, "  conntrack_cmd=%s\n", s->cmd_msg);
	ncb_add(b, "  ctnetlink=%s\n", s->netlink_msg);
	ncb_add(b, "  active=%s\n", s->active_name);
}

static void nc_rules_lines(const struct nc_cfg *c, struct nc_buf *b,
			   const char *path)
{
	ncb_add(b, "rules(interval=%ds cooldown=%ds netns=%s):\n",
		c->interval, c->cooldown, c->netns[0] ? c->netns : "-");
	ncb_add(b, "  scan    window=%ds distinct_dports>=%d\n",
		c->scan_window, c->scan_ports);
	ncb_add(b, "  lateral window=%ds distinct_dsts>=%d "
		"(same dport)\n", c->lateral_window, c->lateral_hosts);
	ncb_add(b, "  burst   window=%ds cur>=%d && cur>=%dx prev "
		"&& prev<=%d（prev>=1）\n", c->burst_window, c->burst_min,
		c->burst_ratio, c->burst_low);
	if (path)
		ncb_add(b, "rules_path=%s\n", path);
}

static int nc_tool_status(char **out)
{
	char dir[NC_PATH_LEN];
	char path[NC_PATH_LEN];
	char tbuf[1024];
	char tail[4096];
	struct nc_buf b;
	struct nc_cfg cfg;
	struct nc_source src;
	long pid = 0;
	int alive = 0, rc;
	const char *st;
	char err[512];

	if (nc_chain_dir(dir, sizeof(dir)) != 0) {
		if (asprintf(out, "ERROR: 状态目录不可写：%s",
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	st = nc_effective_state(dir, &pid, &alive);
	ncb_init(&b, 65536);
	if (!b.p) {
		*out = strdup("ERROR: 内存不足");
		return -1;
	}
	ncb_add(&b, "net_chain_watch status\n");
	ncb_add(&b, "state=%s pid=%ld alive=%s state_dir=%s\n", st, pid,
		alive ? "yes" : (pid > 0 ? "no（进程已不在）" : "n/a"), dir);

	err[0] = '\0';
	rc = nc_cfg_load(dir, "rules.json", &cfg, err, sizeof(err));
	if (rc != 0) {
		nc_cfg_default(&cfg);
		ncb_add(&b, "rules=默认（%s/rules.json 缺失或非法：%s）\n",
			dir, err);
	}
	nc_path(path, sizeof(path), dir, "rules.json");
	nc_rules_lines(&cfg, &b, path);

	nc_path(path, sizeof(path), dir, "status.json");
	if (nc_read_text(path, tbuf, sizeof(tbuf)) == 0) {
		long v = 0;
		char ss[64];

		ncb_add(&b, "last_sample:\n");
		if (nc_jget_str(tbuf, "source", ss, sizeof(ss)) == 0)
			ncb_add(&b, "  source=%s\n", ss);
		if (nc_jget_int(tbuf, "entries", &v) == 0)
			ncb_add(&b, "  entries=%ld\n", v);
		if (nc_jget_str(tbuf, "table", ss, sizeof(ss)) == 0)
			ncb_add(&b, "  table=%s%s\n", ss,
				strcmp(ss, "empty") == 0 ?
				"（0 条连接；采样继续，不报错）" :
				(strcmp(ss, "unknown") == 0 ?
				 "（本拍采样失败，见 last_error）" : ""));
		if (nc_jget_int(tbuf, "acct", &v) == 0)
			ncb_add(&b, "  acct=%s\n", v ?
				"on（packets/bytes 可用）" :
				"off（packets/bytes 不可用："
				"nf_conntrack_acct=0）");
		if (nc_jget_int(tbuf, "samples", &v) == 0)
			ncb_add(&b, "  samples=%ld\n", v);
		if (nc_jget_int(tbuf, "new_connections", &v) == 0)
			ncb_add(&b, "  new_connections=%ld\n", v);
		if (nc_jget_int(tbuf, "events", &v) == 0)
			ncb_add(&b, "  events=%ld\n", v);
		if (nc_jget_int(tbuf, "errors", &v) == 0)
			ncb_add(&b, "  errors=%ld\n", v);
		if (nc_jget_str(tbuf, "last_error", ss, sizeof(ss)) == 0 &&
		    ss[0])
			ncb_add(&b, "  last_error=%s\n", ss);
	} else {
		ncb_add(&b, "last_sample=n/a（尚未采样）\n");
	}

	err[0] = '\0';
	if (nc_probe_sources(&src, err, sizeof(err)) != 0)
		ncb_add(&b, "source_now=unavailable：%s\n", err);
	else
		ncb_add(&b, "source_now=%s\n", src.active_name);
	nc_probe_lines(&src, &b);

	nc_path(path, sizeof(path), dir, "audit.log");
	nc_tail_lines(path, tail, sizeof(tail), 8);
	ncb_add(&b, "---- audit.log 尾部 ----\n%s", tail);
	nc_path(path, sizeof(path), dir, "events.jsonl");
	nc_tail_lines(path, tail, sizeof(tail), 5);
	ncb_add(&b, "---- events.jsonl 尾部 ----\n%s", tail);
	ncb_add(&b, "说明：只观测（不写 nft、不封禁、不改网络配置）。\n");
	*out = b.p;
	return 0;
}

static int nc_tool_stop(char **out)
{
	char dir[NC_PATH_LEN];
	char path[NC_PATH_LEN];
	char tbuf[1024];
	long pid;
	int fd, got, i;
	int signaled = 0, killed = 0;
	long long events = 0;
	long evtmp = 0;

	if (nc_chain_dir(dir, sizeof(dir)) != 0) {
		if (asprintf(out, "ERROR: 状态目录不可写：%s",
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	nc_path(path, sizeof(path), dir, "daemon.lock");
	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0) {
		if (asprintf(out, "ERROR: 单例锁不可打开 %s: %s", path,
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	pid = nc_read_pid(dir);
	got = flock(fd, LOCK_EX | LOCK_NB);
	if (got != 0) {
		if (nc_pid_alive(pid)) {
			(void)kill((pid_t)pid, SIGTERM);
			signaled = 1;
			for (i = 0; i < 50; i++) {
				usleep(100000);
				if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
					got = 0;
					break;
				}
			}
			if (got != 0) {
				(void)kill((pid_t)pid, SIGKILL);
				killed = 1;
				for (i = 0; i < 20; i++) {
					usleep(100000);
					if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
						got = 0;
						break;
					}
				}
			}
		} else {
			for (i = 0; i < 20; i++) {
				usleep(100000);
				if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
					got = 0;
					break;
				}
			}
		}
	}
	if (got != 0) {
		if (asprintf(out,
			     "ERROR: 无法取得单例锁（pid=%ld 仍存活或仍在退出）；"
			     "未做任何清理，请稍后重试", pid) < 0)
			*out = NULL;
		close(fd);
		return -1;
	}
	nc_path(path, sizeof(path), dir, "status.json");
	if (nc_read_text(path, tbuf, sizeof(tbuf)) == 0 &&
	    nc_jget_int(tbuf, "events", &evtmp) == 0)
		events = evtmp;
	nc_path(path, sizeof(path), dir, "state");
	(void)nc_write_file0600(path, "stopped\n");
	nc_path(path, sizeof(path), dir, "pid");
	unlink(path);
	nc_audit(dir,
		 "WATCH-STOP-REQUEST pid=%ld signal=%s events=%lld"
		 "（只观测，无规则需撤回）",
		 pid, killed ? "KILL" : (signaled ? "TERM" : "none"), events);
	if (asprintf(out,
		     "net_chain_watch: 已停止\n"
		     "pid=%ld signal=%s state=stopped\n"
		     "已产生攻击链事件 %lld 条（只观测，无规则需撤回）\n"
		     "state_dir=%s\n",
		     pid, killed ? "SIGKILL（自清理超时，已按持久化记录兜底）" :
		     (signaled ? "SIGTERM（子进程自清理）" : "无运行进程"),
		     events, dir) < 0)
		*out = NULL;
	close(fd);
	return 0;
}

static int nc_tool_start(const char *args, char **out)
{
	char dir[NC_PATH_LEN];
	char path[NC_PATH_LEN];
	struct nc_cfg cfg;
	struct nc_source src;
	char err[1024], probe_err[1024];
	int lfd, got, pfd[2], probe_rc;
	long pid = 0;
	int alive = 0;
	char state_before[64] = "";

	if (nc_chain_dir(dir, sizeof(dir)) != 0) {
		if (asprintf(out, "ERROR: 状态目录不可写：%s",
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	err[0] = '\0';
	if (nc_cfg_load(dir, "rules.json", &cfg, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 阈值文件非法：%s（先 net_chain_rules "
			     "set 修正，或删除 %s/rules.json）", err, dir) < 0)
			*out = NULL;
		return -1;
	}
	if (nc_cfg_parse(args, &cfg, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 参数解析失败：%s", err) < 0)
			*out = NULL;
		return -1;
	}
	if (nc_cfg_check(&cfg, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 参数非法：%s", err) < 0)
			*out = NULL;
		return -1;
	}
	probe_err[0] = '\0';
	probe_rc = nc_probe_sources(&src, probe_err, sizeof(probe_err));
	if (probe_rc != 0) {
		if (asprintf(out,
			     "ERROR: %s\n"
			     "  procfs=%s\n  conntrack_cmd=%s\n"
			     "  ctnetlink=%s\n"
			     "未启动、零副作用。可先 net_chain_watch status "
			     "复核事件源可用性。",
			     probe_err, src.procfs_msg, src.cmd_msg,
			     src.netlink_msg) < 0)
			*out = NULL;
		return -1;
	}
	nc_path(path, sizeof(path), dir, "daemon.lock");
	lfd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (lfd < 0) {
		if (asprintf(out, "ERROR: 单例锁不可打开 %s: %s", path,
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	got = flock(lfd, LOCK_EX | LOCK_NB);
	if (got != 0) {
		pid = nc_read_pid(dir);
		if (asprintf(out,
			     "ERROR: 已有采样器在运行（pid=%ld）——先 "
			     "net_chain_watch stop 再 start；本次未做任何改动",
			     pid) < 0)
			*out = NULL;
		close(lfd);
		return -1;
	}
	(void)nc_effective_state(dir, &pid, &alive);
	{
		char sbuf[64];

		nc_path(path, sizeof(path), dir, "state");
		if (nc_read_text(path, sbuf, sizeof(sbuf)) == 0)
			snprintf(state_before, sizeof(state_before), "%s",
				 nc_trim(sbuf));
	}
	if (strcmp(state_before, "running") == 0 || pid > 0)
		nc_audit(dir,
			 "ORPHAN-DETECTED previous_state=%s previous_pid=%ld"
			 "（进程已不在；start 前清理残留）",
			 state_before, pid);
	(void)nc_cfg_write(dir, "rules.json", &cfg);
	(void)nc_cfg_write(dir, "run.cfg", &cfg);
	if (pipe(pfd) != 0) {
		if (asprintf(out, "ERROR: pipe 失败：%s", strerror(errno)) < 0)
			*out = NULL;
		close(lfd);
		return -1;
	}
	{
		pid_t child = fork();

		if (child < 0) {
			if (asprintf(out, "ERROR: fork 失败：%s",
				     strerror(errno)) < 0)
				*out = NULL;
			close(pfd[0]);
			close(pfd[1]);
			close(lfd);
			return -1;
		}
		if (child == 0) {
			struct nc_cfg c2 = cfg;
			int dn;
			char spath[NC_PATH_LEN];
			char pidbuf[32];

			close(pfd[0]);
			setsid();
			dn = open("/dev/null", O_RDWR);
			if (dn >= 0) {
				dup2(dn, 0);
				dup2(dn, 1);
				dup2(dn, 2);
				if (dn > 2)
					close(dn);
			}
			nc_path(spath, sizeof(spath), dir, "pid");
			snprintf(pidbuf, sizeof(pidbuf), "%ld\n",
				 (long)getpid());
			(void)nc_write_file0600(spath, pidbuf);
			nc_path(spath, sizeof(spath), dir, "state");
			(void)nc_write_file0600(spath, "running\n");
			(void)!write(pfd[1], "ok\n", 3);
			close(pfd[1]);
			nc_daemon_loop(&c2, dir, lfd);
			_exit(0);
		}
		close(pfd[1]);
		{
			struct pollfd pf;

			pf.fd = pfd[0];
			pf.events = POLLIN;
			pf.revents = 0;
			got = poll(&pf, 1, 3000);
		}
		if (got > 0) {
			char ok[8] = "";

			if (read(pfd[0], ok, sizeof(ok) - 1) < 0)
				ok[0] = 0;
			close(pfd[0]);
			if (strncmp(ok, "ok", 2) != 0)
				got = -1;
		} else {
			close(pfd[0]);
			got = -1;
		}
		if (got <= 0) {
			if (asprintf(out,
				     "ERROR: 采样器子进程启动失败（握手超时/即退）；"
				     "state_dir=%s 请查看 daemon.log", dir) < 0)
				*out = NULL;
			close(lfd);
			return -1;
		}
		pid = (long)child;
	}
	close(lfd);
	{
		char rules[2048];
		struct nc_buf rb;

		ncb_init(&rb, sizeof(rules));
		if (rb.p) {
			nc_rules_lines(&cfg, &rb, NULL);
			snprintf(rules, sizeof(rules), "%s", rb.p);
			ncb_free(&rb);
		} else {
			rules[0] = '\0';
		}
		if (asprintf(out,
			     "net_chain_watch: 采样器已启动（后台，不阻塞会话）\n"
			     "pid=%ld state=running source=%s\n"
			     "%s"
			     "事件源探测：procfs=%s | conntrack_cmd=%s | "
			     "ctnetlink=%s\n"
			     "state_dir=%s\n"
			     "只观测：不写 nft、不封禁、不改网络配置。"
			     "表为空/计数不可用会如实标注。\n",
			     pid, src.active_name, rules, src.procfs_msg,
			     src.cmd_msg, src.netlink_msg, dir) < 0)
			*out = NULL;
	}
	return 0;
}

static int nc_tool_rules(const char *args, char **out)
{
	char dir[NC_PATH_LEN];
	char path[NC_PATH_LEN];
	struct nc_cfg cfg, old;
	char err[512], action[16];
	char old_desc[1024];

	if (nc_chain_dir(dir, sizeof(dir)) != 0) {
		if (asprintf(out, "ERROR: 状态目录不可写：%s",
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	action[0] = '\0';
	(void)nc_jget_str(args, "action", action, sizeof(action));
	if (!action[0])
		snprintf(action, sizeof(action), "get");
	err[0] = '\0';
	if (nc_cfg_load(dir, "rules.json", &cfg, err, sizeof(err)) != 0) {
		nc_cfg_default(&cfg);
		if (strcmp(action, "get") != 0) {
			if (asprintf(out, "ERROR: 现有阈值文件非法：%s", err) <
			    0)
				*out = NULL;
			return -1;
		}
	}
	nc_path(path, sizeof(path), dir, "rules.json");
	if (strcmp(action, "get") == 0) {
		struct nc_buf b;

		ncb_init(&b, 16384);
		if (!b.p) {
			*out = strdup("ERROR: 内存不足");
			return -1;
		}
		ncb_add(&b, "net_chain_rules（get）\n");
		nc_rules_lines(&cfg, &b, path);
		ncb_add(&b, "运行中的采样器每拍重读（≤interval 秒生效）；"
			"只观测不封禁。\n");
		*out = b.p;
		return 0;
	}
	if (strcmp(action, "set") != 0) {
		if (asprintf(out, "ERROR: action 非法（get|set）：%s", action) <
		    0)
			*out = NULL;
		return -1;
	}
	old = cfg;
	snprintf(old_desc, sizeof(old_desc),
		 "interval=%ds scan(window=%ds,ports>=%d) "
		 "lateral(window=%ds,hosts>=%d) "
		 "burst(window=%ds,min=%d,ratio=%d,low<=%d) cooldown=%ds "
		 "netns=%s",
		 old.interval, old.scan_window, old.scan_ports,
		 old.lateral_window, old.lateral_hosts, old.burst_window,
		 old.burst_min, old.burst_ratio, old.burst_low, old.cooldown,
		 old.netns[0] ? old.netns : "-");
	if (nc_cfg_parse(args, &cfg, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 参数非法：%s", err) < 0)
			*out = NULL;
		return -1;
	}
	if (nc_cfg_check(&cfg, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 参数非法：%s", err) < 0)
			*out = NULL;
		return -1;
	}
	if (nc_cfg_write(dir, "rules.json", &cfg) != 0) {
		if (asprintf(out, "ERROR: 阈值写入失败 %s: %s", path,
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	if (asprintf(out,
		     "net_chain_rules（set 完成）\n"
		     "旧：%s\n"
		     "新：interval=%ds scan(window=%ds,ports>=%d) "
		     "lateral(window=%ds,hosts>=%d) "
		     "burst(window=%ds,min=%d,ratio=%d,low<=%d) "
		     "cooldown=%ds netns=%s\n"
		     "path=%s\n"
		     "运行中的采样器每拍重读（≤interval 秒生效）；"
		     "只观测不封禁。\n",
		     old_desc, cfg.interval, cfg.scan_window, cfg.scan_ports,
		     cfg.lateral_window, cfg.lateral_hosts, cfg.burst_window,
		     cfg.burst_min, cfg.burst_ratio, cfg.burst_low,
		     cfg.cooldown, cfg.netns[0] ? cfg.netns : "-", path) < 0)
		*out = NULL;
	return 0;
}

int exec_net_chain_channel(const void *tool, const char *args_json,
			   char **out)
{
	const char *name = tool ? ((const struct ai_tool *)tool)->name : NULL;
	char action[16];

	if (!out)
		return -1;
	*out = NULL;
	if (!name) {
		*out = strdup("ERROR: 工具名为空");
		return -1;
	}
	if (strcmp(name, "net_chain_rules") == 0)
		return nc_tool_rules(args_json ? args_json : "{}", out);
	if (strcmp(name, "net_chain_watch") == 0) {
		action[0] = '\0';
		(void)nc_jget_str(args_json ? args_json : "{}", "action",
				  action, sizeof(action));
		if (!action[0]) {
			*out = strdup(
				"ERROR: 缺少 action（start|stop|status）");
			return -1;
		}
		if (strcmp(action, "start") == 0)
			return nc_tool_start(args_json, out);
		if (strcmp(action, "stop") == 0)
			return nc_tool_stop(out);
		if (strcmp(action, "status") == 0)
			return nc_tool_status(out);
		if (asprintf(out, "ERROR: action 非法（start|stop|status）：%s",
			     action) < 0)
			*out = NULL;
		return -1;
	}
	if (asprintf(out, "ERROR: 未知 net_chain 工具（注册表异常）：%s",
		     name) < 0)
		*out = NULL;
	return -1;
}
