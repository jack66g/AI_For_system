/* SPDX-License-Identifier: GPL-2.0 */
/*
 * net_hit.c - W81 V3.2 规则命中观测闭环实现（TOOL_CH_NETINTENT，两件）
 *
 * 数据流：
 *   nft -j list ruleset ── ni_ruleset_snapshot() ──► 每条规则
 *        (table/chain/handle/counter/动作/注释/描述)
 *        │  与上一拍比较 → 增量（计数器回退按重置处理）
 *        ▼
 *   滑动窗口累计（默认 60s）≥ threshold（默认 10 包）且冷却已过
 *        ▼
 *   alert（D1）：audit.log + events.jsonl + 快照，不动规则
 *   escalate（D3）：向命中规则所在链追加 `ip saddr <src> counter drop`
 *                   临时规则（comment=aikhit-esc-*），TTL 到期自动删
 *   degrade（D3）：把 drop/reject 规则替换成 counter+log 只记日志规则，
 *                  stop/清理时按原动作恢复
 *
 * 状态目录（0600 文件、0700 目录）：
 *   state pid run.cfg policy.json audit.log events.jsonl daemon.log
 *   escalations degraded snap-<epoch>-<handle>.nft tx-<pid>.nft daemon.lock
 *
 * 不阻塞会话：start 父进程只做 nft 探测 + flock 单例 + fork 握手，随即返回；
 * 采样循环在 setsid 子进程里跑。stop 先 SIGTERM 让子进程自清理，5 秒不退才
 * SIGKILL，然后按持久化记录兜底清理。
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "tools/net_admin.h"
#include "tools/net_intent.h"
#include "tools/net_hit.h"

#define NH_MAX_RULES	256
#define NH_MAX_ESC	64
#define NH_MAX_DEG	64
#define NH_JSON_CAP	(512 * 1024)
#define NH_LIST_CAP	(64 * 1024)
#define NH_PATH_LEN	600
#define NH_MAX_TRIGGERS	4096	/* 单进程最多触发次数（防 audit 刷爆） */

static volatile sig_atomic_t g_stop;

/* ======================================================================
 * 0) 小工具
 * ====================================================================== */

static void nh_sig_stop(int sig)
{
	(void)sig;
	g_stop = 1;
}

static char *nh_trim(char *s)
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

static int nh_mkdir_p0700(const char *path)
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

int nh_hit_dir(char *out, size_t cap)
{
	const char *env = getenv("AIKERNEL_NFT_HIT_DIR");

	if (!out || cap == 0)
		return -1;
	if (env && *env)
		snprintf(out, cap, "%s", env);
	else if (geteuid() == 0)
		snprintf(out, cap, "/run/aik-nft-hit");
	else
		snprintf(out, cap, "/tmp/aik-nft-hit-%u", (unsigned)geteuid());
	return nh_mkdir_p0700(out);
}

static void nh_path(char *out, size_t cap, const char *dir, const char *name)
{
	size_t dl = strlen(dir);

	if (dl + 2 >= cap)
		dl = cap - 3;
	snprintf(out, cap, "%.*s/%.*s", (int)dl, dir,
		 (int)(cap - dl - 2), name);
}

static int nh_write_file0600(const char *path, const char *data)
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

static int nh_read_text(const char *path, char *buf, size_t cap)
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
static void nh_slog(const char *path, const char *fmt, ...)
{
	char line[2048];
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

static void nh_audit(const char *dir, const char *fmt, ...)
{
	char path[NH_PATH_LEN];
	char msg[1600];
	va_list ap;

	nh_path(path, sizeof(path), dir, "audit.log");
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	nh_slog(path, "%s", msg);
}

static void nh_dlog(const char *dir, const char *fmt, ...)
{
	char path[NH_PATH_LEN];
	char msg[1600];
	va_list ap;

	nh_path(path, sizeof(path), dir, "daemon.log");
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	nh_slog(path, "%s", msg);
}

static void nh_json_escape(const char *in, char *out, size_t cap)
{
	size_t o = 0;

	if (!out || cap == 0)
		return;
	for (; in && *in && o + 2 < cap; in++) {
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
			out[o++] = ' ';
		} else {
			out[o++] = (char)c;
		}
	}
	out[o] = '\0';
}

/* 简化 JSON 取值（策略/参数都是本模块生成的扁平 JSON） */
static int nh_jget_str(const char *json, const char *key, char *out,
		       size_t cap)
{
	char pat[64];
	const char *p;
	size_t used = 0;

	if (!json || !out || cap == 0)
		return -1;
	snprintf(pat, sizeof(pat), "\"%s\"", key);
	p = strstr(json, pat);
	if (!p)
		return 0;
	p += strlen(pat);
	while (*p == ' ' || *p == '\t' || *p == '\n')
		p++;
	if (*p != ':')
		return 0;
	p++;
	while (*p == ' ' || *p == '\t' || *p == '\n')
		p++;
	if (*p != '"')
		return -1;
	p++;
	while (*p && *p != '"') {
		char c = *p;

		if (c == '\\') {
			p++;
			switch (*p) {
			case '"': c = '"'; break;
			case '\\': c = '\\'; break;
			case '/': c = '/'; break;
			case 'n': c = '\n'; break;
			case 't': c = '\t'; break;
			case 'r': c = '\r'; break;
			default:
				return -1;
			}
		}
		if (used + 1 >= cap)
			return -1;
		out[used++] = c;
		p++;
	}
	if (*p != '"')
		return -1;
	out[used] = '\0';
	return 1;
}

/* 返回 1=读到合法整数，0=键不存在，-1=存在但非法 */
static int nh_jget_int(const char *json, const char *key, long *out)
{
	char pat[64];
	const char *p;
	char *end;
	long v;

	if (!json || !out)
		return 0;
	snprintf(pat, sizeof(pat), "\"%s\"", key);
	p = strstr(json, pat);
	if (!p)
		return 0;
	p += strlen(pat);
	while (*p == ' ' || *p == '\t' || *p == '\n')
		p++;
	if (*p != ':')
		return -1;
	p++;
	while (*p == ' ' || *p == '\t' || *p == '\n')
		p++;
	errno = 0;
	v = strtol(p, &end, 10);
	if (end == p)
		return -1;
	while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
		end++;
	if (*end != ',' && *end != '}' && *end != ']' && *end != '\0')
		return -1;
	if (errno == ERANGE)
		return -1;
	*out = v;
	return 1;
}

/* ======================================================================
 * 1) 配置
 * ====================================================================== */

void nh_cfg_default(struct nh_cfg *c)
{
	memset(c, 0, sizeof(*c));
	snprintf(c->table, sizeof(c->table), "aik_intent");
	c->threshold = 10;
	c->window = 60;
	c->interval = 5;
	c->cooldown = 60;
	snprintf(c->level, sizeof(c->level), "%s", NH_LEVEL_ALERT);
	c->esc_ttl = 60;
}

int nh_level_valid(const char *s)
{
	return s && (strcmp(s, NH_LEVEL_ALERT) == 0 ||
		     strcmp(s, NH_LEVEL_ESCALATE) == 0 ||
		     strcmp(s, NH_LEVEL_DEGRADE) == 0);
}

int nh_chain_valid(const char *s)
{
	size_t i, n;

	if (!s || !*s)
		return 0;
	n = strlen(s);
	if (n > 63)
		return 0;
	if (!(isalpha((unsigned char)s[0]) || s[0] == '_'))
		return 0;
	for (i = 0; i < n; i++) {
		char c = s[i];

		if (!(isalnum((unsigned char)c) || c == '_' || c == '-'))
			return 0;
	}
	return 1;
}

/* 仅允许 IPv4/IPv6 字面量与 /前缀；不接受任何 nft 语法字符 */
int nh_src_valid(const char *s)
{
	size_t i, n;
	int dots = 0, colons = 0, slash = 0, alpha = 0;
	long prefix = -1;

	if (!s || !*s)
		return 0;
	n = strlen(s);
	if (n > 63)
		return 0;
	for (i = 0; i < n; i++) {
		char c = s[i];

		if (c == '.') {
			dots++;
			continue;
		}
		if (c == ':') {
			colons++;
			continue;
		}
		if (c == '/') {
			slash++;
			if (i == 0 || i + 1 >= n)
				return 0;
			prefix = strtol(s + i + 1, NULL, 10);
			continue;
		}
		if (isdigit((unsigned char)c))
			continue;
		if (isxdigit((unsigned char)c)) {
			alpha = 1;
			continue;
		}
		return 0;
	}
	if (dots > 0 && colons > 0)
		return 0;
	if (dots == 0 && colons == 0)
		return 0;
	if (dots > 0 && alpha)
		return 0;
	if (slash > 1)
		return 0;
	if (slash == 1) {
		if (prefix < 0)
			return 0;
		if (colons > 0 && prefix > 128)
			return 0;
		if (dots > 0 && prefix > 32)
			return 0;
	}
	return 1;
}

int nh_cfg_parse(const char *json, struct nh_cfg *c, char *err, size_t ecap)
{
	long v;
	int r;
	char tmp[96];

	if (err && ecap)
		err[0] = '\0';
	if (!json || !c)
		return 0;
#define NH_STR_KEY(key, field, cap)					\
	do {								\
		int rr = nh_jget_str(json, key, tmp, sizeof(tmp));	\
									\
		if (rr < 0) {						\
			if (err)					\
				snprintf(err, ecap,			\
					 "%s 不是合法字符串", key);	\
			return -1;					\
		}							\
		if (rr == 1)						\
			snprintf(c->field, cap, "%.*s",			\
				 (int)(cap) - 1, tmp);			\
	} while (0)
	NH_STR_KEY("table", table, sizeof(c->table));
	NH_STR_KEY("chain", chain, sizeof(c->chain));
	NH_STR_KEY("level", level, sizeof(c->level));
	NH_STR_KEY("escalate_src", esc_src, sizeof(c->esc_src));
#undef NH_STR_KEY
	r = nh_jget_int(json, "handle", &v);
	if (r < 0 || (r == 1 && v < 0)) {
		if (err)
			snprintf(err, ecap, "handle 非法（须 >=0）");
		return -1;
	}
	if (r == 1)
		c->handle = v;
#define NH_INT_KEY(key, field)						\
	do {								\
		r = nh_jget_int(json, key, &v);				\
		if (r < 0) {						\
			if (err)					\
				snprintf(err, ecap,			\
					 "%s 不是合法整数", key);		\
			return -1;					\
		}							\
		if (r == 1)						\
			c->field = (int)v;				\
	} while (0)
	NH_INT_KEY("threshold", threshold);
	NH_INT_KEY("window", window);
	NH_INT_KEY("interval", interval);
	NH_INT_KEY("cooldown", cooldown);
	NH_INT_KEY("escalate_ttl", esc_ttl);
#undef NH_INT_KEY
	return 0;
}

int nh_cfg_check(struct nh_cfg *c, char *err, size_t ecap)
{
	if (err && ecap)
		err[0] = '\0';
	if (!c)
		return -1;
	if (!ni_valid_table(c->table)) {
		if (err)
			snprintf(err, ecap,
				 "table 非法（只允许 [a-z_][a-z0-9_]{0,14}）");
		return -1;
	}
	if (c->chain[0] && !nh_chain_valid(c->chain)) {
		if (err)
			snprintf(err, ecap,
				 "chain 非法（字母/数字/_/-，≤63 字节）");
		return -1;
	}
	if (!nh_level_valid(c->level)) {
		if (err)
			snprintf(err, ecap,
				 "level 非法（alert|escalate|degrade）");
		return -1;
	}
	if (c->threshold < 1 || c->threshold > 1000000000) {
		if (err)
			snprintf(err, ecap,
				 "threshold 非法（1..1000000000 包）");
		return -1;
	}
	if (c->window < 1 || c->window > 3600) {
		if (err)
			snprintf(err, ecap, "window 非法（1..3600 秒）");
		return -1;
	}
	if (c->interval < 1 || c->interval > 300) {
		if (err)
			snprintf(err, ecap, "interval 非法（1..300 秒）");
		return -1;
	}
	if (c->interval > c->window) {
		if (err)
			snprintf(err, ecap,
				 "interval=%d 不能大于 window=%d"
				 "（窗口内至少要有一拍）",
				 c->interval, c->window);
		return -1;
	}
	if (c->window > c->interval * NH_HIST) {
		if (err)
			snprintf(err, ecap,
				 "window/interval=%d 超过滑动窗口样本上限 %d"
				 "（请缩短 window 或增大 interval）",
				 c->window / c->interval, NH_HIST);
		return -1;
	}
	if (c->cooldown < 0 || c->cooldown > 86400) {
		if (err)
			snprintf(err, ecap, "cooldown 非法（0..86400 秒）");
		return -1;
	}
	if (c->handle < 0) {
		if (err)
			snprintf(err, ecap, "handle 非法（须 >=0）");
		return -1;
	}
	if (c->esc_src[0] && !nh_src_valid(c->esc_src)) {
		if (err)
			snprintf(err, ecap,
				 "escalate_src 非法（只接受 IPv4/IPv6 地址或"
				 "前缀字面量，不接受任何 nft 语法字符）");
		return -1;
	}
	if (c->esc_ttl < 5 || c->esc_ttl > 3600) {
		if (err)
			snprintf(err, ecap,
				 "escalate_ttl 非法（5..3600 秒，不允许关成 0）");
		return -1;
	}
	if (strcmp(c->level, NH_LEVEL_ESCALATE) == 0 && !c->esc_src[0]) {
		if (err)
			snprintf(err, ecap,
				 "level=escalate 必须给出 escalate_src"
				 "（隔离源地址/前缀），否则无法生成严格规则");
		return -1;
	}
	return 0;
}

static int nh_cfg_write(const char *dir, const char *name,
			const struct nh_cfg *c, int with_level)
{
	char path[NH_PATH_LEN];
	char buf[2048];

	nh_path(path, sizeof(path), dir, name);
	if (with_level)
		snprintf(buf, sizeof(buf),
			 "{\"table\":\"%s\",\"chain\":\"%s\",\"handle\":%ld,"
			 "\"threshold\":%d,\"window\":%d,\"interval\":%d,"
			 "\"cooldown\":%d,\"level\":\"%s\","
			 "\"escalate_src\":\"%s\",\"escalate_ttl\":%d}\n",
			 c->table, c->chain, c->handle, c->threshold,
			 c->window, c->interval, c->cooldown, c->level,
			 c->esc_src, c->esc_ttl);
	else
		snprintf(buf, sizeof(buf),
			 "{\"table\":\"%s\",\"chain\":\"%s\",\"handle\":%ld,"
			 "\"threshold\":%d,\"window\":%d,\"interval\":%d,"
			 "\"cooldown\":%d,\"escalate_src\":\"%s\","
			 "\"escalate_ttl\":%d}\n",
			 c->table, c->chain, c->handle, c->threshold,
			 c->window, c->interval, c->cooldown, c->esc_src,
			 c->esc_ttl);
	return nh_write_file0600(path, buf);
}

static int nh_cfg_load(const char *dir, const char *name, struct nh_cfg *c,
		       char *err, size_t ecap)
{
	char path[NH_PATH_LEN];
	char buf[4096];

	nh_path(path, sizeof(path), dir, name);
	nh_cfg_default(c);
	if (nh_read_text(path, buf, sizeof(buf)) != 0)
		return 1;	/* 没有文件：用默认值 */
	if (nh_cfg_parse(buf, c, err, ecap) != 0)
		return -1;
	return 0;
}

/* ======================================================================
 * 2) 滑动窗口（纯函数）
 * ====================================================================== */

void nh_hist_add(struct nh_hist *h, long ts, long d)
{
	h->ts[h->head] = ts;
	h->d[h->head] = d;
	h->head = (h->head + 1) % NH_HIST;
	if (h->n < NH_HIST)
		h->n++;
}

long nh_hist_sum(const struct nh_hist *h, long now, int window)
{
	long sum = 0;
	int i, idx = h->head;

	for (i = 0; i < h->n; i++) {
		idx = (idx - 1 + NH_HIST) % NH_HIST;
		if (now - h->ts[idx] < window)
			sum += h->d[idx];
	}
	return sum;
}

int nh_should_fire(long sum, int threshold, long now, long last_fire,
		   int cooldown)
{
	if (sum < threshold)
		return 0;
	if (last_fire == 0)
		return 1;
	return now - last_fire >= cooldown;
}

/* ======================================================================
 * 3) nft 薄封装（全部走 net_admin.c 的有界 fork/execv）
 * ====================================================================== */

static int nh_nft_probe(char *detail, size_t cap)
{
	const char *const argv[] = { "-j", "list", "ruleset", NULL };
	char *buf;
	int rc;

	if (detail && cap)
		detail[0] = '\0';
	buf = malloc(NH_JSON_CAP);
	if (!buf)
		return -1;
	buf[0] = '\0';
	rc = ai_nft_list_args(argv, buf, NH_JSON_CAP);
	if (detail && cap)
		snprintf(detail, cap, "%.500s", buf);
	free(buf);
	return rc;
}

/* 0=存在 1=不存在 2=权限不足 3=其他错误 */
static int nh_table_state(const char *table, char *out, size_t cap)
{
	const char *const argv[] = { "list", "table", "inet", table, NULL };
	int rc;

	if (out && cap)
		out[0] = '\0';
	rc = ai_nft_list_args(argv, out, cap);
	if (rc == 0)
		return 0;
	if (strstr(out, "No such file or directory") ||
	    strstr(out, "No such file") || strstr(out, "does not exist"))
		return 1;
	if (strstr(out, "Operation not permitted") ||
	    strstr(out, "Permission denied") || strstr(out, "EPERM"))
		return 2;
	return 3;
}

static int nh_nft_apply_text(const char *dir, const char *text, int check,
			     char *err, size_t ecap)
{
	char path[NH_PATH_LEN];
	char msg[2048];
	int rc;

	snprintf(path, sizeof(path), "%s/tx-%ld.nft", dir, (long)getpid());
	if (nh_write_file0600(path, text) != 0) {
		if (err)
			snprintf(err, ecap, "临时规则文件写入失败 %.300s: %.100s",
				 path, strerror(errno));
		return -1;
	}
	if (check) {
		msg[0] = '\0';
		rc = ai_nft_run_file(path, 1, 10, msg, sizeof(msg));
		if (rc != 0) {
			if (err)
				snprintf(err, ecap,
					 "语法预检失败（nft -c -f，rc=%d，"
					 "未应用任何变更）：%.400s",
					 rc, msg);
			unlink(path);
			return -1;
		}
	}
	msg[0] = '\0';
	rc = ai_nft_run_file(path, 0, 10, msg, sizeof(msg));
	if (rc != 0 && err)
		snprintf(err, ecap, "nft -f 应用失败（rc=%d）：%.400s", rc, msg);
	unlink(path);
	return rc == 0 ? 0 : -1;
}

static int nh_find_handle_by_comment(const char *dir, const char *table,
				     const char *chain, const char *comment,
				     long *handle)
{
	const char *const argv[] = { "-a", "list", "chain", "inet", table,
				     chain, NULL };
	char *listing;
	int rc;

	(void)dir;
	*handle = 0;
	listing = malloc(NH_LIST_CAP);
	if (!listing)
		return -1;
	listing[0] = '\0';
	rc = ai_nft_list_args(argv, listing, NH_LIST_CAP);
	if (rc == 0)
		rc = nh_parse_handle_by_comment(listing, comment, handle);
	free(listing);
	return rc;
}

static int nh_delete_rule(const char *dir, const char *table,
			  const char *chain, long handle, const char *comment,
			  char *err, size_t ecap)
{
	char tx[512];
	char msg[512];

	if (handle <= 0 && comment && *comment)
		(void)nh_find_handle_by_comment(dir, table, chain, comment,
						&handle);
	if (handle <= 0) {
		if (err)
			snprintf(err, ecap,
				 "无 handle 且未能按 comment 定位"
				 "（规则可能已被删除）");
		return -1;
	}
	snprintf(tx, sizeof(tx), "delete rule inet %s %s handle %ld\n",
		 table, chain, handle);
	msg[0] = '\0';
	if (nh_nft_apply_text(dir, tx, 0, msg, sizeof(msg)) == 0)
		return 0;
	/* 已不存在不算失败（清理幂等） */
	if (strstr(msg, "No such file") || strstr(msg, "does not exist") ||
	    strstr(msg, "Could not process rule"))
		return 0;
	if (err)
		snprintf(err, ecap, "%s", msg);
	return -1;
}

/* ======================================================================
 * 4) nft 文本解析（降级路径）
 * ====================================================================== */

/* 从尾部剥掉 "counter" / "counter packets N bytes M" */
static int nh_strip_counter(char *s)
{
	for (;;) {
		size_t n = strlen(s);
		char *p;

		while (n > 0 && isspace((unsigned char)s[n - 1]))
			s[--n] = '\0';
		if (n == 0)
			return 0;
		if (n >= 7 && strcmp(s + n - 7, "counter") == 0) {
			s[n - 7] = '\0';
			continue;
		}
		p = strstr(s, "counter packets ");
		while (p) {
			char *q = p + strlen("counter packets ");
			char *e1, *e2;

			(void)strtol(q, &e1, 10);
			if (e1 != q && strncmp(e1, " bytes ", 7) == 0) {
				(void)strtol(e1 + 7, &e2, 10);
				if (e2 != e1 + 7 &&
				    (*e2 == '\0' ||
				     isspace((unsigned char)*e2))) {
					*p = '\0';
					break;
				}
			}
			p = strstr(p + 1, "counter packets ");
		}
		if (!p)
			return 0;
	}
}

int nh_parse_rule_text(const char *listing, long handle, char *match,
		       size_t mcap, char *action, size_t acap, char *err,
		       size_t ecap)
{
	char *copy, *line, *save = NULL;
	int found = 0;

	if (err && ecap)
		err[0] = '\0';
	if (match && mcap)
		match[0] = '\0';
	if (action && acap)
		action[0] = '\0';
	if (!listing || !match || !action) {
		if (err)
			snprintf(err, ecap, "内部错误：空参数");
		return -1;
	}
	copy = strdup(listing);
	if (!copy) {
		if (err)
			snprintf(err, ecap, "内存不足");
		return -1;
	}
	for (line = strtok_r(copy, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char *hash = strstr(line, "# handle ");
		char *end;
		long h;

		if (!hash)
			continue;
		h = strtol(hash + strlen("# handle "), &end, 10);
		if (end == hash + strlen("# handle ") || h != handle)
			continue;
		*hash = '\0';
		found = 1;
		{
			char *t = nh_trim(line);
			char *last;

			if (!*t) {
				if (err)
					snprintf(err, ecap,
						 "规则文本为空"
						 "（多行规则不支持降级）");
				free(copy);
				return -1;
			}
			if (strlen(t) >= 512) {
				if (err)
					snprintf(err, ecap,
						 "规则文本过长（>512），"
						 "拒绝降级");
				free(copy);
				return -1;
			}
			if (strchr(t, ';') || strchr(t, '\n')) {
				if (err)
					snprintf(err, ecap,
						 "规则文本含语句分隔符，"
						 "拒绝降级");
				free(copy);
				return -1;
			}
			/* 尾部动作必须是单值 accept/drop/reject */
			last = t + strlen(t);
			while (last > t && !isspace((unsigned char)last[-1]))
				last--;
			if (strcmp(last, "accept") != 0 &&
			    strcmp(last, "drop") != 0 &&
			    strcmp(last, "reject") != 0) {
				if (err)
					snprintf(err, ecap,
						 "只支持降级 accept/drop/reject"
						 " 单动作规则（实际尾部：%s）",
						 last);
				free(copy);
				return -1;
			}
			snprintf(action, acap, "%s", last);
			*last = '\0';
			t = nh_trim(t);
			(void)nh_strip_counter(t);
			t = nh_trim(t);
			if (strchr(t, ';')) {
				if (err)
					snprintf(err, ecap,
						 "规则文本含语句分隔符，"
						 "拒绝降级");
				free(copy);
				return -1;
			}
			snprintf(match, mcap, "%s", t);
		}
		break;
	}
	free(copy);
	if (!found) {
		if (err)
			snprintf(err, ecap, "未找到 handle %ld 的规则", handle);
		return -1;
	}
	return 0;
}

int nh_parse_handle_by_comment(const char *listing, const char *comment,
			       long *handle)
{
	char *copy, *line, *save = NULL;
	char pat[160];
	int found = 0;

	if (handle)
		*handle = 0;
	if (!listing || !comment || !*comment)
		return -1;
	snprintf(pat, sizeof(pat), "comment \"%s\"", comment);
	copy = strdup(listing);
	if (!copy)
		return -1;
	for (line = strtok_r(copy, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char *hash, *end;
		long h;

		if (!strstr(line, pat))
			continue;
		hash = strstr(line, "# handle ");
		if (!hash)
			continue;
		h = strtol(hash + strlen("# handle "), &end, 10);
		if (end == hash + strlen("# handle ") || h <= 0)
			continue;
		if (handle)
			*handle = h;
		found = 1;
		break;
	}
	free(copy);
	return found ? 0 : -1;
}

/* ======================================================================
 * 5) 快照 / 审计事件
 * ====================================================================== */

static void nh_snapshot(const char *dir, const char *table, long long handle,
			char *out, size_t cap)
{
	const char *const argv[] = { "list", "table", "inet", table, NULL };
	char *text;
	char path[NH_PATH_LEN];
	char note[128];
	time_t now = time(NULL);

	snprintf(path, sizeof(path), "%s/snap-%ld-%lld.nft", dir, (long)now,
		 handle);
	snprintf(out, cap, "%s", path);
	text = malloc(NH_LIST_CAP);
	if (!text) {
		nh_write_file0600(path, "（快照失败：内存不足）\n");
		return;
	}
	text[0] = '\0';
	if (ai_nft_list_args(argv, text, NH_LIST_CAP) != 0) {
		snprintf(note, sizeof(note), "（快照失败：%.100s）\n", text);
		nh_write_file0600(path, note);
	} else {
		nh_write_file0600(path, text);
	}
	free(text);
}

struct nh_fire_res {
	char action[16];
	char result[512];
	char snapshot[NH_PATH_LEN];
	long esc_handle;
	long esc_expires;
};

static void nh_event(const char *dir, const struct nh_cfg *cfg,
		     const struct ni_rule_sample *r, long delta, long total,
		     const struct nh_fire_res *fr, long now)
{
	char path[NH_PATH_LEN];
	char desc[512], result[1024], snap[NH_PATH_LEN];
	char line[4096];
	char ts[64];
	struct tm tmv;
	time_t t = (time_t)now;
	int fd, n;

	localtime_r(&t, &tmv);
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);
	nh_json_escape(r->desc, desc, sizeof(desc));
	nh_json_escape(fr->result, result, sizeof(result));
	nh_json_escape(fr->snapshot, snap, sizeof(snap));
	nh_path(path, sizeof(path), dir, "events.jsonl");
	n = snprintf(line, sizeof(line),
		     "{\"ts\":%ld,\"time\":\"%s\",\"rule\":\"inet %s %s\","
		     "\"handle\":%lld,\"desc\":\"%s\",\"delta_packets\":%ld,"
		     "\"window_packets\":%ld,\"threshold\":%d,\"window\":%d,"
		     "\"action\":\"%s\",\"result\":\"%s\","
		     "\"snapshot\":\"%s\",\"escalation_handle\":%ld,"
		     "\"escalation_expires\":%ld}\n",
		     now, ts, r->table, r->chain, r->handle, desc, delta,
		     total, cfg->threshold, cfg->window, fr->action, result,
		     snap, fr->esc_handle, fr->esc_expires);
	fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	(void)!write(fd, line, (size_t)n);
	close(fd);
}

/* ======================================================================
 * 6) 升级规则 / 降级规则持久化
 * ====================================================================== */

struct nh_esc {
	char comment[96];
	char table[16];
	char chain[64];
	long handle;
	long expires;
	char src[64];
};

struct nh_deg {
	char table[16];
	char chain[64];
	long orig;
	long now;
	char action[16];
	char match[512];
};

static int nh_esc_load(const char *dir, struct nh_esc *arr, int max, int *n)
{
	char path[NH_PATH_LEN];
	char *buf;
	int count = 0;
	char *line, *save = NULL;

	*n = 0;
	nh_path(path, sizeof(path), dir, "escalations");
	buf = malloc(NH_LIST_CAP);
	if (!buf)
		return -1;
	if (nh_read_text(path, buf, NH_LIST_CAP) != 0) {
		free(buf);
		return 0;
	}
	for (line = strtok_r(buf, "\n", &save); line && count < max;
	     line = strtok_r(NULL, "\n", &save)) {
		struct nh_esc e;
		char extra[8];

		memset(&e, 0, sizeof(e));
		if (sscanf(line, "%95s %15s %63s %ld %ld %63s %7s", e.comment,
			   e.table, e.chain, &e.handle, &e.expires, e.src,
			   extra) != 6)
			continue;
		arr[count++] = e;
	}
	free(buf);
	*n = count;
	return 0;
}

static int nh_esc_save(const char *dir, const struct nh_esc *arr, int n)
{
	char path[NH_PATH_LEN];
	char tmp[NH_PATH_LEN + 8];
	int i, fd;

	nh_path(path, sizeof(path), dir, "escalations");
	if (n <= 0) {
		unlink(path);
		return 0;
	}
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	for (i = 0; i < n; i++) {
		char line[512];
		int len = snprintf(line, sizeof(line),
				   "%s %s %s %ld %ld %s\n",
				   arr[i].comment, arr[i].table, arr[i].chain,
				   arr[i].handle, arr[i].expires, arr[i].src);

		(void)!write(fd, line, (size_t)len);
	}
	close(fd);
	return rename(tmp, path);
}

static int nh_deg_load(const char *dir, struct nh_deg *arr, int max, int *n)
{
	char path[NH_PATH_LEN];
	char *buf;
	int count = 0;
	char *line, *save = NULL;

	*n = 0;
	nh_path(path, sizeof(path), dir, "degraded");
	buf = malloc(NH_LIST_CAP);
	if (!buf)
		return -1;
	if (nh_read_text(path, buf, NH_LIST_CAP) != 0) {
		free(buf);
		return 0;
	}
	for (line = strtok_r(buf, "\n", &save); line && count < max;
	     line = strtok_r(NULL, "\n", &save)) {
		struct nh_deg d;
		char *p, *fields[6];
		int f = 0;

		memset(&d, 0, sizeof(d));
		p = line;
		while (f < 6 && p) {
			fields[f++] = p;
			p = strchr(p, '\t');
			if (p)
				*p++ = '\0';
		}
		if (f < 5)
			continue;
		snprintf(d.table, sizeof(d.table), "%s", fields[0]);
		snprintf(d.chain, sizeof(d.chain), "%s", fields[1]);
		d.orig = strtol(fields[2], NULL, 10);
		d.now = strtol(fields[3], NULL, 10);
		snprintf(d.action, sizeof(d.action), "%s", fields[4]);
		if (f == 6)
			snprintf(d.match, sizeof(d.match), "%s", fields[5]);
		arr[count++] = d;
	}
	free(buf);
	*n = count;
	return 0;
}

static int nh_deg_save(const char *dir, const struct nh_deg *arr, int n)
{
	char path[NH_PATH_LEN];
	char tmp[NH_PATH_LEN + 8];
	int fd, i;

	nh_path(path, sizeof(path), dir, "degraded");
	if (n <= 0) {
		unlink(path);
		return 0;
	}
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	for (i = 0; i < n; i++) {
		char line[768];
		int len = snprintf(line, sizeof(line),
				   "%s\t%s\t%ld\t%ld\t%s\t%s\n",
				   arr[i].table, arr[i].chain, arr[i].orig,
				   arr[i].now, arr[i].action, arr[i].match);

		(void)!write(fd, line, (size_t)len);
	}
	close(fd);
	return rename(tmp, path);
}

/* ======================================================================
 * 7) 响应动作
 * ====================================================================== */

static void nh_add_escalation(const char *dir, const struct nh_cfg *cfg,
			      const struct ni_rule_sample *r,
			      struct nh_fire_res *fr)
{
	struct nh_esc arr[NH_MAX_ESC];
	int n = 0;
	time_t now = time(NULL);
	char comment[96];
	char tx[1024];
	char err[512];
	long h = 0;

	snprintf(comment, sizeof(comment), "aikhit-esc-%ld-%lld", (long)now,
		 r->handle);
	snprintf(tx, sizeof(tx),
		 "add rule inet %s %s %s saddr %s counter drop "
		 "comment \"%s\"\n",
		 r->table, r->chain, strchr(cfg->esc_src, ':') ? "ip6" : "ip",
		 cfg->esc_src, comment);
	if (nh_nft_apply_text(dir, tx, 1, err, sizeof(err)) != 0) {
		snprintf(fr->result, sizeof(fr->result),
			 "escalate-failed（未加规则）：%.400s", err);
		return;
	}
	if (nh_find_handle_by_comment(dir, r->table, r->chain, comment, &h) != 0) {
		usleep(150000);
		(void)nh_find_handle_by_comment(dir, r->table, r->chain,
						comment, &h);
	}
	if (nh_esc_load(dir, arr, NH_MAX_ESC, &n) == 0 && n < NH_MAX_ESC) {
		struct nh_esc *e = &arr[n];

		memset(e, 0, sizeof(*e));
		snprintf(e->comment, sizeof(e->comment), "%s", comment);
		snprintf(e->table, sizeof(e->table), "%s", r->table);
		snprintf(e->chain, sizeof(e->chain), "%s", r->chain);
		e->handle = h;
		e->expires = (long)now + cfg->esc_ttl;
		snprintf(e->src, sizeof(e->src), "%s", cfg->esc_src);
		if (nh_esc_save(dir, arr, n + 1) != 0)
			nh_dlog(dir, "升级规则记录写入失败（handle=%ld）", h);
	} else {
		nh_dlog(dir, "升级规则记录写入失败（数组满/读取失败）");
	}
	fr->esc_handle = h;
	fr->esc_expires = (long)now + cfg->esc_ttl;
	if (h > 0)
		snprintf(fr->result, sizeof(fr->result),
			 "escalation-added handle=%ld ttl=%ds src=%s"
			 "（TTL 到期自动撤）",
			 h, cfg->esc_ttl, cfg->esc_src);
	else
		snprintf(fr->result, sizeof(fr->result),
			 "escalation-added（comment=%s，未定位 handle；"
			 "stop 时按 comment 清理）ttl=%ds",
			 comment, cfg->esc_ttl);
}

static void nh_degrade(const char *dir, const struct nh_cfg *cfg,
		       const struct ni_rule_sample *r, struct nh_fire_res *fr)
{
	const char *const argv[] = { "-a", "list", "chain", "inet", r->table,
				     r->chain, NULL };
	char *listing;
	char match[512], action[16], err[512], tx[2048];
	char comment[96];
	long nh = 0;
	struct nh_deg arr[NH_MAX_DEG];
	int n = 0;

	(void)cfg;
	listing = malloc(NH_LIST_CAP);
	if (!listing) {
		snprintf(fr->result, sizeof(fr->result),
			 "degrade-failed：内存不足");
		return;
	}
	err[0] = '\0';
	listing[0] = '\0';
	if (ai_nft_list_args(argv, listing, NH_LIST_CAP) != 0 ||
	    nh_parse_rule_text(listing, (long)r->handle, match, sizeof(match),
			       action, sizeof(action), err, sizeof(err)) != 0) {
		snprintf(fr->result, sizeof(fr->result),
			 "degrade-failed（未改规则）：%s",
			 err[0] ? err : "读取规则文本失败");
		free(listing);
		return;
	}
	free(listing);
	if (strcmp(action, "drop") != 0 && strcmp(action, "reject") != 0) {
		snprintf(fr->result, sizeof(fr->result),
			 "degrade-refused：只降级 drop/reject 规则"
			 "（实际 %s）", action);
		return;
	}
	snprintf(comment, sizeof(comment), "aikhit-deg-%lld", r->handle);
	if (match[0])
		snprintf(tx, sizeof(tx),
			 "delete rule inet %s %s handle %lld\n"
			 "add rule inet %s %s %.400s counter log prefix "
			 "\"aik-hit-degraded \" comment \"%s\"\n",
			 r->table, r->chain, r->handle, r->table, r->chain,
			 match, comment);
	else
		snprintf(tx, sizeof(tx),
			 "delete rule inet %s %s handle %lld\n"
			 "add rule inet %s %s counter log prefix "
			 "\"aik-hit-degraded \" comment \"%s\"\n",
			 r->table, r->chain, r->handle, r->table, r->chain,
			 comment);
	if (nh_nft_apply_text(dir, tx, 1, err, sizeof(err)) != 0) {
		snprintf(fr->result, sizeof(fr->result),
			 "degrade-failed（单批次原子，未生效）：%s", err);
		return;
	}
	if (nh_find_handle_by_comment(dir, r->table, r->chain, comment, &nh) != 0) {
		usleep(150000);
		(void)nh_find_handle_by_comment(dir, r->table, r->chain,
						comment, &nh);
	}
	if (nh_deg_load(dir, arr, NH_MAX_DEG, &n) == 0 && n < NH_MAX_DEG) {
		struct nh_deg *d = &arr[n];

		memset(d, 0, sizeof(*d));
		snprintf(d->table, sizeof(d->table), "%s", r->table);
		snprintf(d->chain, sizeof(d->chain), "%s", r->chain);
		d->orig = (long)r->handle;
		d->now = nh;
		snprintf(d->action, sizeof(d->action), "%s", action);
		snprintf(d->match, sizeof(d->match), "%s", match);
		if (nh_deg_save(dir, arr, n + 1) != 0)
			nh_dlog(dir, "降级记录写入失败（orig=%lld new=%ld）",
				r->handle, nh);
	} else {
		nh_dlog(dir, "降级记录写入失败（数组满/读取失败）");
	}
	snprintf(fr->result, sizeof(fr->result),
		 "degraded orig_handle=%lld new_handle=%ld action=%s"
		 "（原动作已记录，stop/清理时恢复）",
		 r->handle, nh, action);
}

static void nh_expire_escalations(const char *dir, long now)
{
	struct nh_esc arr[NH_MAX_ESC];
	int n = 0, i, keep = 0;

	if (nh_esc_load(dir, arr, NH_MAX_ESC, &n) != 0 || n == 0)
		return;
	for (i = 0; i < n; i++) {
		char err[512];

		if (arr[i].expires > now) {
			arr[keep++] = arr[i];
			continue;
		}
		err[0] = '\0';
		if (nh_delete_rule(dir, arr[i].table, arr[i].chain,
				   arr[i].handle, arr[i].comment, err,
				   sizeof(err)) == 0)
			nh_audit(dir,
				 "ESCALATE-EXPIRE rule=inet %s %s#%ld "
				 "expires=%ld result=withdrawn",
				 arr[i].table, arr[i].chain, arr[i].handle,
				 arr[i].expires);
		else
			nh_audit(dir,
				 "ESCALATE-EXPIRE rule=inet %s %s#%ld "
				 "result=withdraw-failed（记录丢弃）err=%.300s",
				 arr[i].table, arr[i].chain, arr[i].handle,
				 err);
	}
	(void)nh_esc_save(dir, arr, keep);
}

/* 撤升级规则 + 恢复降级规则；stop / start 前 / 看门狗之后都走这里 */
static void nh_cleanup_leftovers(const char *dir, const char *why,
				 int *esc_n, int *deg_n)
{
	struct nh_deg darr[NH_MAX_DEG];
	int dn = 0, i, dkeep = 0;
	struct nh_esc earr[NH_MAX_ESC];
	int en = 0, ekeep = 0;

	if (esc_n)
		*esc_n = 0;
	if (deg_n)
		*deg_n = 0;
	if (nh_deg_load(dir, darr, NH_MAX_DEG, &dn) == 0 && dn > 0) {
		for (i = 0; i < dn; i++) {
			char err[512];
			char tx[2048];
			char comment[96];

			err[0] = '\0';
			snprintf(comment, sizeof(comment), "aikhit-deg-%ld",
				 darr[i].orig);
			if (nh_delete_rule(dir, darr[i].table, darr[i].chain,
					   darr[i].now,
					   darr[i].now > 0 ? NULL : comment,
					   err, sizeof(err)) != 0) {
				nh_audit(dir,
					 "DEGRADE-RESTORE-FAILED rule=inet %s "
					 "%s#%ld orig_handle=%ld err=%.300s"
					 "（记录保留）",
					 darr[i].table, darr[i].chain,
					 darr[i].now, darr[i].orig, err);
				darr[dkeep++] = darr[i];
				continue;
			}
			if (darr[i].match[0])
				snprintf(tx, sizeof(tx),
					 "add rule inet %.15s %.63s %.400s counter %.15s\n",
					 darr[i].table, darr[i].chain,
					 darr[i].match, darr[i].action);
			else
				snprintf(tx, sizeof(tx),
					 "add rule inet %.15s %.63s counter %.15s\n",
					 darr[i].table, darr[i].chain,
					 darr[i].action);
			if (nh_nft_apply_text(dir, tx, 1, err, sizeof(err)) == 0) {
				nh_audit(dir,
					 "DEGRADE-RESTORE rule=inet %s %s#%ld "
					 "orig_handle=%ld action=%s reason=%s",
					 darr[i].table, darr[i].chain,
					 darr[i].now, darr[i].orig,
					 darr[i].action, why);
				if (deg_n)
					(*deg_n)++;
			} else {
				nh_audit(dir,
					 "DEGRADE-RESTORE-FAILED rule=inet %s "
					 "%s#%ld orig_handle=%ld err=%.300s"
					 "（记录保留）",
					 darr[i].table, darr[i].chain,
					 darr[i].now, darr[i].orig, err);
				darr[dkeep++] = darr[i];
			}
		}
		(void)nh_deg_save(dir, darr, dkeep);
	}
	if (nh_esc_load(dir, earr, NH_MAX_ESC, &en) == 0 && en > 0) {
		for (i = 0; i < en; i++) {
			char err[512];

			err[0] = '\0';
			if (nh_delete_rule(dir, earr[i].table, earr[i].chain,
					   earr[i].handle, earr[i].comment, err,
					   sizeof(err)) == 0) {
				nh_audit(dir,
					 "ESCALATE-WITHDRAW rule=inet %s %s#%ld "
					 "reason=%s",
					 earr[i].table, earr[i].chain,
					 earr[i].handle, why);
				if (esc_n)
					(*esc_n)++;
			} else {
				nh_audit(dir,
					 "ESCALATE-WITHDRAW-FAILED rule=inet %s "
					 "%s#%ld err=%.300s（记录保留）",
					 earr[i].table, earr[i].chain,
					 earr[i].handle, err);
				earr[ekeep++] = earr[i];
			}
		}
		(void)nh_esc_save(dir, earr, ekeep);
	}
}

/* ======================================================================
 * 8) 采样器主体
 * ====================================================================== */

struct nh_track {
	char key[128];
	char table[16];
	char chain[64];
	long long handle;
	long long packets;
	int has_counter;
	int kind;
	int seen;
	long last_fire;
	struct nh_hist hist;
};

static int nh_track_find(struct nh_track *t, int n, const char *key)
{
	int i;

	for (i = 0; i < n; i++)
		if (strcmp(t[i].key, key) == 0)
			return i;
	return -1;
}

static int nh_selected(const struct nh_cfg *cfg,
		       const struct ni_rule_sample *r)
{
	if (cfg->chain[0] && strcmp(cfg->chain, r->chain) != 0)
		return 0;
	if (cfg->handle > 0 && r->handle != cfg->handle)
		return 0;
	return 1;
}

static void nh_reload_knobs(const char *dir, struct nh_cfg *cfg)
{
	struct nh_cfg p;
	char err[256];

	if (nh_cfg_load(dir, "policy.json", &p, err, sizeof(err)) != 0)
		return;
	if (nh_cfg_check(&p, err, sizeof(err)) != 0) {
		nh_dlog(dir, "策略文件非法，沿用上一拍参数：%s", err);
		return;
	}
	cfg->threshold = p.threshold;
	cfg->window = p.window;
	cfg->interval = p.interval;
	cfg->cooldown = p.cooldown;
	snprintf(cfg->chain, sizeof(cfg->chain), "%s", p.chain);
	cfg->handle = p.handle;
}

static void nh_fire(const char *dir, struct nh_cfg *cfg, struct nh_track *tr,
		    const struct ni_rule_sample *r, long delta, long total,
		    long now)
{
	struct nh_fire_res fr;

	memset(&fr, 0, sizeof(fr));
	snprintf(fr.action, sizeof(fr.action), "%s", cfg->level);
	nh_snapshot(dir, r->table, r->handle, fr.snapshot,
		    sizeof(fr.snapshot));
	if (strcmp(cfg->level, NH_LEVEL_ESCALATE) == 0)
		nh_add_escalation(dir, cfg, r, &fr);
	else if (strcmp(cfg->level, NH_LEVEL_DEGRADE) == 0)
		nh_degrade(dir, cfg, r, &fr);
	else
		snprintf(fr.result, sizeof(fr.result),
			 "event-only（不动规则）");
	nh_audit(dir,
		 "TRIGGER rule=\"inet %s %s #%lld\" desc=\"%s\" delta=%ld "
		 "total=%ld threshold=%d window=%ds action=%s result=%s "
		 "snapshot=%s",
		 r->table, r->chain, r->handle, r->desc, delta, total,
		 cfg->threshold, cfg->window, fr.action, fr.result,
		 fr.snapshot);
	nh_event(dir, cfg, r, delta, total, &fr, now);
	tr->last_fire = now;
}

static void nh_daemon_loop(struct nh_cfg *cfg, const char *dir, int lockfd)
{
	struct nh_track *tracks;
	char *json;
	long last_err_at = 0;
	char last_err[512];
	time_t started = time(NULL);
	int triggers = 0;
	int tn = 0;		/* 轨迹表跨拍保留（hist/last_fire 不能每拍重置） */
	int i;

	g_stop = 0;
	signal(SIGTERM, nh_sig_stop);
	signal(SIGINT, nh_sig_stop);
	signal(SIGHUP, nh_sig_stop);
	tracks = calloc(NH_MAX_RULES, sizeof(*tracks));
	json = malloc(NH_JSON_CAP);
	if (!tracks || !json) {
		char path[NH_PATH_LEN];

		nh_dlog(dir, "采样器启动失败：内存不足");
		nh_path(path, sizeof(path), dir, "state");
		(void)nh_write_file0600(path, "failed\n");
		free(tracks);
		free(json);
		if (lockfd >= 0)
			close(lockfd);
		_exit(1);
	}
	{
		char path[NH_PATH_LEN];
		char pid[32];

		nh_path(path, sizeof(path), dir, "pid");
		snprintf(pid, sizeof(pid), "%ld\n", (long)getpid());
		(void)nh_write_file0600(path, pid);
		nh_path(path, sizeof(path), dir, "state");
		(void)nh_write_file0600(path, "running\n");
		(void)nh_cfg_write(dir, "run.cfg", cfg, 1);
	}
	nh_dlog(dir,
		"采样器启动 pid=%ld table=inet %s level=%s interval=%ds "
		"window=%ds threshold=%d cooldown=%ds",
		(long)getpid(), cfg->table, cfg->level, cfg->interval,
		cfg->window, cfg->threshold, cfg->cooldown);
	nh_audit(dir,
		 "WATCH-START table=inet %s level=%s interval=%ds window=%ds "
		 "threshold=%d cooldown=%ds", cfg->table, cfg->level,
		 cfg->interval, cfg->window, cfg->threshold, cfg->cooldown);
	last_err[0] = '\0';
	while (!g_stop) {
		const char *const argv[] = { "-j", "list", "ruleset", NULL };
		long now;
		int rc, seen = 0, idx;

		nh_reload_knobs(dir, cfg);
		now = (long)time(NULL);
		json[0] = '\0';
		rc = ai_nft_list_args(argv, json, NH_JSON_CAP);
		if (rc != 0) {
			const char *kind = rc == 127 ?
				"nft 不可用（二进制不存在）" :
				(strstr(json, "Operation not permitted") ||
				 strstr(json, "Permission denied")) ?
				"权限不足（需要 root/CAP_NET_ADMIN）" :
				"nft 执行失败";

			if (strcmp(last_err, kind) != 0 ||
			    now - last_err_at >= 30) {
				nh_audit(dir,
					 "SAMPLE-ERROR kind=%s rc=%d err=%.300s",
					 kind, rc, json);
				snprintf(last_err, sizeof(last_err), "%s",
					 kind);
				last_err_at = now;
			}
		} else if (strlen(json) >= NH_JSON_CAP - 1) {
			if (strcmp(last_err, "nft -j 输出被截断") != 0 ||
			    now - last_err_at >= 30) {
				nh_audit(dir,
					 "SAMPLE-ERROR kind=nft -j 输出被截断 "
					 "cap=%d（请缩小表范围）", NH_JSON_CAP);
				snprintf(last_err, sizeof(last_err),
					 "nft -j 输出被截断");
				last_err_at = now;
			}
		} else {
			struct ni_rule_sample cur[NH_MAX_RULES];
			char err[256];
			int cn = 0;

			err[0] = '\0';
			if (ni_ruleset_snapshot(json, cfg->table, cur,
						NH_MAX_RULES, &cn, err,
						sizeof(err)) != 0) {
				if (strcmp(last_err, err) != 0 ||
				    now - last_err_at >= 30) {
					nh_audit(dir,
						 "SAMPLE-ERROR kind=解析失败 "
						 "err=%.300s", err);
					snprintf(last_err, sizeof(last_err),
						 "%s", err);
					last_err_at = now;
				}
			} else {
				last_err[0] = '\0';
				/* 每拍先清 seen：否则上一拍留下的 seen=1 会让已消失的
				 * 规则继续留在轨迹里，tn 只增不减，冷却/窗口状态被稀释。 */
				for (i = 0; i < tn; i++)
					tracks[i].seen = 0;
				for (idx = 0; idx < cn; idx++) {
					struct ni_rule_sample *r = &cur[idx];
					char key[128];
					int ti;
					long delta;

					if (strncmp(r->comment, "aikhit-", 7) == 0)
						continue;
					snprintf(key, sizeof(key), "%s#%lld",
						 r->chain, r->handle);
					ti = nh_track_find(tracks, tn, key);
					if (ti < 0) {
						if (tn >= NH_MAX_RULES)
							continue;
						ti = tn++;
						memset(&tracks[ti], 0,
						       sizeof(tracks[ti]));
						snprintf(tracks[ti].key,
							 sizeof(tracks[ti].key),
							 "%s", key);
					}
					tracks[ti].kind = r->kind;
					tracks[ti].has_counter = r->has_counter;
					snprintf(tracks[ti].table,
						 sizeof(tracks[ti].table), "%s",
						 r->table);
					snprintf(tracks[ti].chain,
						 sizeof(tracks[ti].chain), "%s",
						 r->chain);
					tracks[ti].handle = r->handle;
					tracks[ti].seen = 1;
					if (tracks[ti].packets > 0 &&
					    r->packets < tracks[ti].packets)
						delta = r->packets;
					else
						delta = r->packets -
							tracks[ti].packets;
					if (delta < 0)
						delta = 0;
					tracks[ti].packets = r->packets;
					if (!r->has_counter ||
					    r->kind != NI_R_DENY)
						continue;
					if (delta > 0)
						nh_hist_add(&tracks[ti].hist,
							    now, delta);
					{
						long total = nh_hist_sum(
							&tracks[ti].hist, now,
							cfg->window);

						if (nh_selected(cfg, r) &&
						    nh_should_fire(
							    total, cfg->threshold,
							    now,
							    tracks[ti].last_fire,
							    cfg->cooldown) &&
						    triggers < NH_MAX_TRIGGERS) {
							nh_fire(dir, cfg,
								&tracks[ti], r,
								delta, total,
								now);
							triggers++;
						}
					}
				}
				/* 剪掉本拍不存在的规则（handle 变化/规则被删） */
				seen = 0;
				for (i = 0; i < tn; i++)
					if (tracks[i].seen)
						tracks[seen++] = tracks[i];
				for (i = seen; i < tn; i++)
					memset(&tracks[i], 0,
					       sizeof(tracks[i]));
				tn = seen;
			}
		}
		nh_expire_escalations(dir, now);
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
		int esc = 0, deg = 0;
		char path[NH_PATH_LEN];

		nh_cleanup_leftovers(dir, "daemon-stop", &esc, &deg);
		nh_audit(dir,
			 "WATCH-STOP pid=%ld uptime=%lds triggers=%d "
			 "escalations_withdrawn=%d degraded_restored=%d",
			 (long)getpid(), (long)(time(NULL) - started),
			 triggers, esc, deg);
		nh_dlog(dir, "采样器退出 pid=%ld", (long)getpid());
		nh_path(path, sizeof(path), dir, "state");
		(void)nh_write_file0600(path, "stopped\n");
		nh_path(path, sizeof(path), dir, "pid");
		unlink(path);
	}
	free(tracks);
	free(json);
	if (lockfd >= 0)
		close(lockfd);
	_exit(0);
}


/* ======================================================================
 * 9) 工具层
 * ====================================================================== */

struct nh_buf {
	char *p;
	size_t cap;
	size_t used;
};

static void nb_init(struct nh_buf *b, size_t cap)
{
	b->p = calloc(1, cap);
	b->cap = b->p ? cap : 0;
	b->used = 0;
}

static void nb_add(struct nh_buf *b, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (!b->p || b->used + 1 >= b->cap)
		return;
	va_start(ap, fmt);
	n = vsnprintf(b->p + b->used, b->cap - b->used, fmt, ap);
	va_end(ap);
	if (n > 0 && (size_t)n < b->cap - b->used)
		b->used += (size_t)n;
	else if (n > 0)
		b->used = b->cap - 1;
}

static int nh_pid_alive(long pid)
{
	char path[64];

	if (pid <= 0)
		return 0;
	if (kill((pid_t)pid, 0) != 0 && errno != EPERM)
		return 0;
	snprintf(path, sizeof(path), "/proc/%ld", pid);
	return access(path, F_OK) == 0;
}

static long nh_read_pid(const char *dir)
{
	char path[NH_PATH_LEN];
	char buf[64];
	char *end;

	nh_path(path, sizeof(path), dir, "pid");
	if (nh_read_text(path, buf, sizeof(buf)) != 0)
		return 0;
	return strtol(buf, &end, 10);
}

static void nh_tail_lines(const char *path, char *out, size_t cap, int want)
{
	char *buf;
	size_t n = 0;
	int fd, lines = 0;
	size_t i, start;

	if (!out || cap == 0)
		return;
	out[0] = '\0';
	buf = malloc(NH_LIST_CAP);
	if (!buf)
		return;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		ssize_t r = read(fd, buf, NH_LIST_CAP - 1);

		close(fd);
		if (r > 0)
			n = (size_t)r;
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
	snprintf(out, cap, "%.*s", (int)(cap - 1), buf + (start < n ? start : 0));
	free(buf);
}

static const char *nh_effective_state(const char *dir, long *pid_out,
				      int *alive_out)
{
	static char st[64];
	char path[NH_PATH_LEN];
	char buf[64];
	long pid;

	*pid_out = 0;
	*alive_out = 0;
	nh_path(path, sizeof(path), dir, "state");
	if (nh_read_text(path, buf, sizeof(buf)) != 0) {
		snprintf(st, sizeof(st), "not-running");
		return st;
	}
	{
		char *t = nh_trim(buf);

		snprintf(st, sizeof(st), "%s", *t ? t : "unknown");
	}
	pid = nh_read_pid(dir);
	*pid_out = pid;
	*alive_out = nh_pid_alive(pid);
	if ((strcmp(st, "running") == 0) && !*alive_out)
		return "orphan";
	return st;
}

static int nh_tool_status(char **out)
{
	char dir[NH_PATH_LEN];
	struct nh_buf b;
	struct nh_cfg cfg;
	long pid = 0;
	int alive = 0;
	const char *st;
	char tbuf[1024];
	char tail[4096];
	struct nh_esc esc[NH_MAX_ESC];
	struct nh_deg deg[NH_MAX_DEG];
	int en = 0, dn = 0, i;

	if (nh_hit_dir(dir, sizeof(dir)) != 0) {
		if (asprintf(out, "ERROR: 状态目录不可写：%s",
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	st = nh_effective_state(dir, &pid, &alive);
	nb_init(&b, 32768);
	if (!b.p) {
		*out = strdup("ERROR: 内存不足");
		return -1;
	}
	nb_add(&b, "net_hit_watch status\n");
	nb_add(&b, "state=%s pid=%ld alive=%s state_dir=%s\n", st, pid,
	       alive ? "yes" : (pid > 0 ? "no（进程已不在）" : "n/a"), dir);
	{
		int r = nh_cfg_load(dir, "run.cfg", &cfg, tbuf,
				    sizeof(tbuf));

		if (r != 0)
			(void)nh_cfg_load(dir, "policy.json", &cfg, tbuf,
					  sizeof(tbuf));
	}
	nb_add(&b,
	       "table=inet %s level=%s interval=%ds window=%ds "
	       "threshold=%d cooldown=%ds chain=%s handle=%ld\n",
	       cfg.table, cfg.level, cfg.interval, cfg.window,
	       cfg.threshold, cfg.cooldown,
	       cfg.chain[0] ? cfg.chain : "（任意）",
	       cfg.handle > 0 ? cfg.handle : 0);
	nb_add(&b, "escalate_src=%s escalate_ttl=%ds\n",
	       cfg.esc_src[0] ? cfg.esc_src : "（空）", cfg.esc_ttl);
	{
		int ts = nh_table_state(cfg.table, tbuf, sizeof(tbuf));

		if (ts == 0)
			nb_add(&b, "table_present=yes\n");
		else if (ts == 1)
			nb_add(&b,
			       "table_present=no（表不存在：暂无规则可观测；"
			       "规则出现后自动开始计数）\n");
		else if (ts == 2)
			nb_add(&b,
			       "table_present=unknown（权限不足：非 root/"
			       "CAP_NET_ADMIN 无法读取 nft）\n");
		else
			nb_add(&b,
			       "table_present=unknown（nft 读取失败：%.200s）\n",
			       tbuf);
	}
	(void)nh_esc_load(dir, esc, NH_MAX_ESC, &en);
	(void)nh_deg_load(dir, deg, NH_MAX_DEG, &dn);
	nb_add(&b, "active_escalations=%d degraded=%d\n", en, dn);
	for (i = 0; i < en; i++) {
		long left = esc[i].expires - (long)time(NULL);

		nb_add(&b,
		       "  escalation id=%s rule=inet %s %s#%ld src=%s "
		       "expires_in=%lds\n",
		       esc[i].comment, esc[i].table, esc[i].chain,
		       esc[i].handle, esc[i].src, left > 0 ? left : 0);
	}
	for (i = 0; i < dn; i++)
		nb_add(&b,
		       "  degraded rule=inet %s %s orig=#%ld now=#%ld "
		       "action=%s match=\"%s\"\n",
		       deg[i].table, deg[i].chain, deg[i].orig, deg[i].now,
		       deg[i].action, deg[i].match);
	{
		char path[NH_PATH_LEN];

		nh_path(path, sizeof(path), dir, "audit.log");
		nh_tail_lines(path, tail, sizeof(tail), 8);
		nb_add(&b, "---- audit.log 尾部 ----\n%s", tail);
		nh_path(path, sizeof(path), dir, "daemon.log");
		nh_tail_lines(path, tail, sizeof(tail), 4);
		nb_add(&b, "---- daemon.log 尾部 ----\n%s", tail);
	}
	*out = b.p;
	return 0;
}

static int nh_tool_stop(char **out)
{
	char dir[NH_PATH_LEN];
	char path[NH_PATH_LEN];
	int fd, got, i;
	long pid;
	int signaled = 0, killed = 0;
	int esc = 0, deg = 0;

	if (nh_hit_dir(dir, sizeof(dir)) != 0) {
		if (asprintf(out, "ERROR: 状态目录不可写：%s",
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	nh_path(path, sizeof(path), dir, "daemon.lock");
	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0) {
		if (asprintf(out, "ERROR: 单例锁不可打开 %s: %s", path,
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	pid = nh_read_pid(dir);
	got = flock(fd, LOCK_EX | LOCK_NB);
	if (got != 0) {
		if (nh_pid_alive(pid)) {
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
	nh_cleanup_leftovers(dir, "stop", &esc, &deg);
	nh_path(path, sizeof(path), dir, "state");
	(void)nh_write_file0600(path, "stopped\n");
	nh_path(path, sizeof(path), dir, "pid");
	unlink(path);
	nh_audit(dir,
		 "WATCH-STOP-REQUEST pid=%ld signal=%s escalations_withdrawn=%d "
		 "degraded_restored=%d", pid,
		 killed ? "KILL" : (signaled ? "TERM" : "none"), esc, deg);
	if (asprintf(out,
		     "net_hit_watch: 已停止\n"
		     "pid=%ld signal=%s state=stopped\n"
		     "已撤升级规则 %d 条，恢复降级规则 %d 条\n"
		     "state_dir=%s\n",
		     pid, killed ? "SIGKILL（自清理超时，已按持久化记录兜底）" :
		     (signaled ? "SIGTERM（子进程自清理）" : "无运行进程"),
		     esc, deg, dir) < 0)
		*out = NULL;
	close(fd);
	return 0;
}

static int nh_tool_start(const char *args, char **out)
{
	char dir[NH_PATH_LEN];
	char path[NH_PATH_LEN];
	struct nh_cfg cfg;
	char err[512];
	char detail[1024];
	int r, ts, probe, lfd, got, pfd[2];
	long pid = 0;
	int alive = 0;
	char state_before[64] = "";
	int esc = 0, deg = 0;

	if (nh_hit_dir(dir, sizeof(dir)) != 0) {
		if (asprintf(out, "ERROR: 状态目录不可写：%s",
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	err[0] = '\0';
	r = nh_cfg_load(dir, "policy.json", &cfg, err, sizeof(err));
	if (r < 0) {
		if (asprintf(out, "ERROR: 策略文件非法：%s（先 net_hit_policy "
			     "set 修正，或删除 %s/policy.json）", err, dir) < 0)
			*out = NULL;
		return -1;
	}
	/* level 是每次 start 的显式授权决定，绝不从策略文件继承 */
	snprintf(cfg.level, sizeof(cfg.level), "%s", NH_LEVEL_ALERT);
	if (nh_cfg_parse(args, &cfg, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 参数解析失败：%s", err) < 0)
			*out = NULL;
		return -1;
	}
	if (nh_cfg_check(&cfg, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 参数非法：%s", err) < 0)
			*out = NULL;
		return -1;
	}
	if (geteuid() != 0) {
		*out = strdup(
			"ERROR: 权限不足：命中采样器需要 root/CAP_NET_ADMIN"
			"（当前非 root）——未启动、零副作用。非 root 可只用 "
			"net_hit_policy get/set 与 net_hit_watch status");
		return -1;
	}
	probe = nh_nft_probe(detail, sizeof(detail));
	if (probe != 0) {
		const char *kind = probe == 127 ?
			"nft 不可用（二进制不存在）" :
			(strstr(detail, "Operation not permitted") ||
			 strstr(detail, "Permission denied")) ?
			"权限不足（需要 root/CAP_NET_ADMIN）" :
			"nft 执行失败";

		if (asprintf(out, "ERROR: %s（rc=%d）：%.400s", kind, probe,
			     detail) < 0)
			*out = NULL;
		return -1;
	}
	ts = nh_table_state(cfg.table, detail, sizeof(detail));
	if (ts == 2) {
		if (asprintf(out,
			     "ERROR: 权限不足，无法读取 inet %s（%.300s）",
			     cfg.table, detail) < 0)
			*out = NULL;
		return -1;
	}
	if (ts == 3) {
		if (asprintf(out,
			     "ERROR: 读取 inet %s 失败（tbl_state=%d）：%.300s",
			     cfg.table, ts, detail) < 0)
			*out = NULL;
		return -1;
	}
	nh_path(path, sizeof(path), dir, "daemon.lock");
	lfd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (lfd < 0) {
		if (asprintf(out, "ERROR: 单例锁不可打开 %s: %s", path,
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	got = flock(lfd, LOCK_EX | LOCK_NB);
	if (got != 0) {
		pid = nh_read_pid(dir);
		if (asprintf(out,
			     "ERROR: 已有采样器在运行（pid=%ld）——先 "
			     "net_hit_watch stop 再 start；本次未做任何改动",
			     pid) < 0)
			*out = NULL;
		close(lfd);
		return -1;
	}
	/* 拿到单例锁 = 上一个采样器已不在；按持久化记录清残 */
	(void)nh_effective_state(dir, &pid, &alive);
	{
		char sbuf[64];

		nh_path(path, sizeof(path), dir, "state");
		if (nh_read_text(path, sbuf, sizeof(sbuf)) == 0)
			snprintf(state_before, sizeof(state_before), "%s",
				 nh_trim(sbuf));
	}
	if (strcmp(state_before, "running") == 0 || pid > 0) {
		nh_audit(dir,
			 "ORPHAN-DETECTED previous_state=%s previous_pid=%ld"
			 "（进程已不在；start 前清理残留）",
			 state_before, pid);
	}
	nh_cleanup_leftovers(dir, "start-orphan-cleanup", &esc, &deg);
	(void)nh_cfg_write(dir, "policy.json", &cfg, 0);
	(void)nh_cfg_write(dir, "run.cfg", &cfg, 1);
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
			struct nh_cfg c2 = cfg;
			int dn;
			char spath[NH_PATH_LEN];
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
			nh_path(spath, sizeof(spath), dir, "pid");
			snprintf(pidbuf, sizeof(pidbuf), "%ld\n",
				 (long)getpid());
			(void)nh_write_file0600(spath, pidbuf);
			nh_path(spath, sizeof(spath), dir, "state");
			(void)nh_write_file0600(spath, "running\n");
			(void)nh_cfg_write(dir, "run.cfg", &c2, 1);
			(void)!write(pfd[1], "ok\n", 3);
			close(pfd[1]);
			nh_daemon_loop(&c2, dir, lfd);
			_exit(0);
		}
		/* 父进程：握手后立刻返回，绝不后台阻塞会话 */
		close(pfd[1]);
		{
			struct pollfd pf;

			pf.fd = pfd[0];
			pf.events = POLLIN;
			pf.revents = 0;
			r = poll(&pf, 1, 3000);
		}
		if (r > 0) {
			char ok[8] = "";

			if (read(pfd[0], ok, sizeof(ok) - 1) < 0)
				ok[0] = 0;
			close(pfd[0]);
			if (strncmp(ok, "ok", 2) != 0)
				r = -1;
		} else {
			close(pfd[0]);
			r = -1;
		}
		if (r <= 0) {
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
	if (asprintf(out,
		     "net_hit_watch: 采样器已启动（后台，不阻塞会话）\n"
		     "pid=%ld state=running table=inet %s level=%s "
		     "interval=%ds window=%ds threshold=%d cooldown=%ds\n"
		     "chain=%s handle=%ld escalate_src=%s escalate_ttl=%ds\n"
		     "table_present=%s\n"
		     "前残留清理：升级规则 %d 条、降级规则 %d 条\n"
		     "state_dir=%s\n"
		     "级别说明：alert=D1（只审计）；escalate/degrade=D3"
		     "（start 时已走租约确认）\n",
		     pid, cfg.table, cfg.level, cfg.interval, cfg.window,
		     cfg.threshold, cfg.cooldown,
		     cfg.chain[0] ? cfg.chain : "（任意）", cfg.handle,
		     cfg.esc_src[0] ? cfg.esc_src : "（空）", cfg.esc_ttl,
		     ts == 0 ? "yes" :
		     (ts == 1 ? "no（暂无规则可观测）" : "unknown"),
		     esc, deg, dir) < 0)
		*out = NULL;
	return 0;
}

static int nh_tool_policy(const char *args, char **out)
{
	char dir[NH_PATH_LEN];
	struct nh_cfg cfg;
	char err[512], action[16];
	char old_desc[512];

	if (nh_hit_dir(dir, sizeof(dir)) != 0) {
		if (asprintf(out, "ERROR: 状态目录不可写：%s",
			     strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	action[0] = '\0';
	(void)nh_jget_str(args, "action", action, sizeof(action));
	if (!action[0])
		snprintf(action, sizeof(action), "get");
	{
		char lv[16];

		if (nh_jget_str(args, "level", lv, sizeof(lv)) != 0) {
			*out = strdup(
				"ERROR: level 不在策略里——它是每次 start 的"
				"显式授权决定（alert=D1；escalate/degrade=D3"
				" 必须走租约确认），请传给 net_hit_watch start");
			return -1;
		}
	}
	if (strcmp(action, "get") == 0) {
		err[0] = '\0';
		if (nh_cfg_load(dir, "policy.json", &cfg, err,
				sizeof(err)) < 0) {
			if (asprintf(out, "ERROR: 策略文件非法：%s", err) < 0)
				*out = NULL;
			return -1;
		}
		if (asprintf(out,
			     "net_hit_policy（命中阈值配置，get）\n"
			     "table=inet %s chain=%s handle=%ld\n"
			     "threshold=%d window=%ds interval=%ds "
			     "cooldown=%ds\n"
			     "escalate_src=%s escalate_ttl=%ds\n"
			     "path=%s/policy.json\n"
			     "level 不在策略里：start 时显式给出 "
			     "（alert=D1；escalate/degrade=D3，"
			     "必须走租约确认）\n",
			     cfg.table, cfg.chain[0] ? cfg.chain : "（任意）",
			     cfg.handle, cfg.threshold, cfg.window,
			     cfg.interval, cfg.cooldown,
			     cfg.esc_src[0] ? cfg.esc_src : "（空）",
			     cfg.esc_ttl, dir) < 0) {
			*out = NULL;
			return -1;
		}
		return 0;
	}
	if (strcmp(action, "set") != 0) {
		if (asprintf(out,
			     "ERROR: action 非法（get|set）：%s", action) < 0)
			*out = NULL;
		return -1;
	}
	err[0] = '\0';
	if (nh_cfg_load(dir, "policy.json", &cfg, err, sizeof(err)) < 0) {
		if (asprintf(out, "ERROR: 现有策略文件非法：%s", err) < 0)
			*out = NULL;
		return -1;
	}
	snprintf(old_desc, sizeof(old_desc),
		 "threshold=%d window=%ds interval=%ds cooldown=%ds "
		 "chain=%s handle=%ld src=%s ttl=%ds",
		 cfg.threshold, cfg.window, cfg.interval, cfg.cooldown,
		 cfg.chain[0] ? cfg.chain : "（任意）", cfg.handle,
		 cfg.esc_src[0] ? cfg.esc_src : "（空）", cfg.esc_ttl);
	if (nh_cfg_parse(args, &cfg, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 参数非法：%s", err) < 0)
			*out = NULL;
		return -1;
	}
	if (nh_cfg_check(&cfg, err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 参数非法：%s", err) < 0)
			*out = NULL;
		return -1;
	}
	if (nh_cfg_write(dir, "policy.json", &cfg, 0) != 0) {
		if (asprintf(out, "ERROR: 策略写入失败 %s/policy.json: %s",
			     dir, strerror(errno)) < 0)
			*out = NULL;
		return -1;
	}
	if (asprintf(out,
		     "net_hit_policy（set 完成）\n"
		     "旧：%s\n"
		     "新：threshold=%d window=%ds interval=%ds cooldown=%ds "
		     "chain=%s handle=%ld src=%s ttl=%ds\n"
		     "path=%s/policy.json\n"
		     "运行中的采样器每拍重读检测参数（threshold/window/"
		     "interval/cooldown/chain/handle），≤interval 秒生效；"
		     "level/escalate_src/escalate_ttl 固定在 start 时。\n",
		     old_desc, cfg.threshold, cfg.window, cfg.interval,
		     cfg.cooldown,
		     cfg.chain[0] ? cfg.chain : "（任意）", cfg.handle,
		     cfg.esc_src[0] ? cfg.esc_src : "（空）", cfg.esc_ttl,
		     dir) < 0) {
		*out = NULL;
		return -1;
	}
	return 0;
}

int exec_net_hit_tool(const char *name, const char *args_json, char **out)
{
	char action[16];

	if (!out)
		return -1;
	*out = NULL;
	if (!name) {
		*out = strdup("ERROR: 工具名为空");
		return -1;
	}
	if (strcmp(name, "net_hit_policy") == 0)
		return nh_tool_policy(args_json ? args_json : "{}", out);
	if (strcmp(name, "net_hit_watch") == 0) {
		action[0] = '\0';
		(void)nh_jget_str(args_json ? args_json : "{}", "action",
				  action, sizeof(action));
		if (!action[0]) {
			*out = strdup(
				"ERROR: 缺少 action（start|stop|status）");
			return -1;
		}
		if (strcmp(action, "start") == 0)
			return nh_tool_start(args_json, out);
		if (strcmp(action, "stop") == 0)
			return nh_tool_stop(out);
		if (strcmp(action, "status") == 0)
			return nh_tool_status(out);
		if (asprintf(out, "ERROR: action 非法（start|stop|status）：%s",
			     action) < 0)
			*out = NULL;
		return -1;
	}
	if (asprintf(out, "ERROR: 未知 net_hit 工具（注册表异常）：%s",
		     name) < 0)
		*out = NULL;
	return -1;
}
