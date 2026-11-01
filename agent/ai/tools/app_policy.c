/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
/*
 * app_policy.c - W82 V4.5 画像结论 → 自动策略（LSM 规则 + 路径白名单）
 *
 * 与 app_policy.h 的分工见头文件。本文件的实现要点：
 *
 * A. 生成（纯函数 + 一个薄执行器）
 *    - 输入只认两类事实：app_profile_dynamic 的事件流（读/写/mmap/exec/
 *      连接）与 app_profile_static 的 JSON（解释器/NEEDED/setuid/能力/包）。
 *      每条规则都必须能指回一条事实（fact_seq/fact_path/basis），否则不
 *      生成 —— 这是"可解释"的硬约束，也是本文件与"猜策略"的分界线。
 *    - allow 规则用目录前缀（宽松但全是事实覆盖的目录），deny 规则用
 *      精确路径（危险项绝不扩大打击面：绝不因为 /etc/shadow 命中就
 *      deny 整个 /etc）。
 *    - 路径前缀一律带结尾 '/'，与内核 strncmp 前缀匹配语义对齐，避免
 *      "/etc" 连 "/etcfoo" 一起命中。
 *    - 去重按 (kind, op, path_prefix)；同键不同 deny 时 deny 胜。
 *
 * B. 下发（状态机 + 注入后端抽象）
 *    闸门顺序：策略校验 → 敏感确认（纯策略侧）→ 内核 ai LSM（能力侧）
 *    → 规则注入面 → 下发。任何一道不过都 fail-closed 且不改任何状态。
 *    下发本身：快照 → 逐条 add → 读回校验；任一步失败 restore 快照。
 *
 * C. 诚实边界（本机实测结论，写进策略 JSON 的 degraded/warnings）
 *    - 当前宿主 LSM 列表没有 ai → apply 必定 fail-closed；
 *    - 即使内核启用 ai，规则注入面当前只有内核内部函数
 *      （ai_lsm_rule_add_path/_label），没有 procfs/sysfs/netlink 写口
 *      → apply 在第三道闸拒绝，并列出探测过的候选；
 *    - socket_connect/socket_sendmsg 不按路径匹配 → 网络目标不可表达，
 *      只进 allowlist.net 并标 enforceable=false。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "tools/tool_registry.h"
#include "app_profile.h"
#include "app_policy.h"

/* 编译期钉住与内核常量的一致性（改内核常量必须同步改这里） */
_Static_assert(APOL_MAX_RULES == 64, "APOL_MAX_RULES 必须 == AI_LSM_RULE_MAX");
_Static_assert(APOL_PREFIX_LEN == 63,
	       "APOL_PREFIX_LEN 必须 == AI_LSM_PATH_PREFIX_LEN-1");

/* ======================================================================
 * 0) 通用：可增长缓冲 + JSON 转义
 * ====================================================================== */

struct apolb {
	char *p;
	size_t len;
	size_t cap;
	int oom;
};

static int apolb_init(struct apolb *b, size_t cap)
{
	b->p = malloc(cap);
	b->len = 0;
	b->cap = cap;
	b->oom = b->p == NULL;
	if (b->p)
		b->p[0] = '\0';
	return b->oom ? -1 : 0;
}

static void apolb_free(struct apolb *b)
{
	free(b->p);
	b->p = NULL;
	b->len = b->cap = 0;
}

static int apolb_reserve(struct apolb *b, size_t need)
{
	size_t nc;
	char *np;

	if (b->oom)
		return -1;
	if (b->len + need + 1 <= b->cap)
		return 0;
	nc = b->cap ? b->cap : 4096;
	while (nc < b->len + need + 1) {
		if (nc > APOL_TEXT_MAX * 2) {
			b->oom = 1;
			return -1;
		}
		nc *= 2;
	}
	np = realloc(b->p, nc);
	if (!np) {
		b->oom = 1;
		return -1;
	}
	b->p = np;
	b->cap = nc;
	return 0;
}

static void apolb_put(struct apolb *b, const char *s, size_t n)
{
	if (apolb_reserve(b, n) != 0)
		return;
	memcpy(b->p + b->len, s, n);
	b->len += n;
	b->p[b->len] = '\0';
}

static void apolb_puts(struct apolb *b, const char *s)
{
	apolb_put(b, s, strlen(s));
}

static void apolb_printf(struct apolb *b, const char *fmt, ...)
{
	char tmp[1024];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if ((size_t)n < sizeof(tmp)) {
		apolb_put(b, tmp, (size_t)n);
		return;
	}
	if (apolb_reserve(b, (size_t)n) != 0)
		return;
	va_start(ap, fmt);
	vsnprintf(b->p + b->len, (size_t)n + 1, fmt, ap);
	va_end(ap);
	b->len += (size_t)n;
}

static void apolb_json_str(struct apolb *b, const char *s)
{
	char *esc = ai_json_escape(s ? s : "");

	if (!esc) {
		b->oom = 1;
		return;
	}
	apolb_put(b, "\"", 1);
	apolb_puts(b, esc);
	apolb_put(b, "\"", 1);
	free(esc);
}

static void apolb_json_str_or_null(struct apolb *b, const char *s)
{
	if (!s || !s[0])
		apolb_puts(b, "null");
	else
		apolb_json_str(b, s);
}

static const char *apol_base(const char *p)
{
	const char *s;

	if (!p)
		return "";
	s = strrchr(p, '/');
	return s ? s + 1 : p;
}

/* 定长拷贝（显式长度，避免 snprintf 截断告警） */
static void apol_copy(char *dst, size_t cap, const char *src)
{
	size_t n;

	if (!dst || cap == 0)
		return;
	if (!src)
		src = "";
	n = strlen(src);
	if (n >= cap)
		n = cap - 1;
	memcpy(dst, src, n);
	dst[n] = 0;
}

static char *apol_read_file(const char *path, size_t max, size_t *lenp)
{
	int fd;
	size_t cap, len = 0;
	char *buf;

	if (lenp)
		*lenp = 0;
	if (max == 0)
		max = 65536;
	cap = max < 65536 ? max : 65536;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	buf = malloc(cap + 1);
	if (!buf) {
		close(fd);
		return NULL;
	}
	for (;;) {
		ssize_t n;

		if (len == cap) {
			char *nb;

			if (cap >= max)
				break;
			cap *= 2;
			if (cap > max)
				cap = max;
			nb = realloc(buf, cap + 1);
			if (!nb) {
				free(buf);
				close(fd);
				return NULL;
			}
			buf = nb;
		}
		n = read(fd, buf + len, cap - len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0)
			break;
		len += (size_t)n;
	}
	close(fd);
	buf[len] = '\0';
	if (lenp)
		*lenp = len;
	return buf;
}

/* 参数值：@file → 读文件；否则原样拷贝。失败 NULL。 */
static char *apol_load_value(const char *v, size_t max, size_t *lenp, char *err,
			     size_t errcap)
{
	if (!v || !v[0]) {
		snprintf(err, errcap, "参数为空");
		return NULL;
	}
	if (v[0] == '@') {
		char *buf = apol_read_file(v + 1, max, lenp);

		if (!buf)
			snprintf(err, errcap, "读不到文件 %s：%s", v + 1,
				 strerror(errno));
		return buf;
	}
	if (lenp)
		*lenp = strlen(v);
	return strdup(v);
}

static void apol_trim(char *s)
{
	size_t n = strlen(s);
	char *p = s;

	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
			 s[n - 1] == ' ' || s[n - 1] == '\t'))
		s[--n] = '\0';
	while (*p == ' ' || *p == '\t')
		p++;
	if (p != s)
		memmove(s, p, strlen(p) + 1);
}

/* ======================================================================
 * 1) 纯函数：危险路径 / 路径合法性 / 前缀推导 / 标签 / op 映射
 * ====================================================================== */

static int apol_starts(const char *p, const char *prefix)
{
	return strncmp(p, prefix, strlen(prefix)) == 0;
}

/* /proc/<任意单层>/<leaf>（等价覆盖 /proc 下每个进程的 mem） */
static int apol_proc_file_match(const char *p, const char *leaf)
{
	const char *rest, *slash;

	if (!apol_starts(p, "/proc/"))
		return 0;
	rest = p + 6;
	slash = strchr(rest, '/');
	if (!slash || slash == rest)
		return 0;
	return strcmp(slash + 1, leaf) == 0;
}

int apol_path_sensitive(const char *path)
{
	if (!path || !path[0])
		return 0;
	if (strcmp(path, "/etc/shadow") == 0 ||
	    strcmp(path, "/etc/gshadow") == 0 ||
	    strcmp(path, "/etc/sudoers") == 0 ||
	    strcmp(path, "/etc/master.passwd") == 0)
		return 1;
	if (apol_starts(path, "/etc/sudoers.d/") ||
	    apol_starts(path, "/root/") ||
	    apol_starts(path, "/proc/kcore") ||
	    apol_starts(path, "/dev/mem") ||
	    apol_starts(path, "/dev/kmem") ||
	    apol_starts(path, "/dev/port") ||
	    apol_starts(path, "/etc/ssl/private/") ||
	    apol_starts(path, "/etc/pki/private/") ||
	    apol_starts(path, "/etc/ssh/ssh_host_") ||
	    apol_starts(path, "/var/lib/shadow"))
		return 1;
	if (strstr(path, "/.ssh/") != NULL)
		return 1;
	if (apol_proc_file_match(path, "mem") ||
	    apol_proc_file_match(path, "environ") ||
	    apol_proc_file_match(path, "kcore"))
		return 1;
	return 0;
}

int apol_path_valid(const char *path)
{
	const char *p;
	size_t n;

	if (!path || path[0] != '/')
		return 0;
	n = strlen(path);
	if (n < 2 || n >= APOL_PATH_MAX)
		return 0;
	for (p = path; *p; p++) {
		if ((unsigned char)*p < 0x20 || *p == 0x7f)
			return 0;
	}
	if (strstr(path, "/../") || strcmp(path, "/..") == 0 ||
	    strcmp(path, "..") == 0)
		return 0;
	if (n >= 3 && strcmp(path + n - 3, "/..") == 0)
		return 0;
	return 1;
}

int apol_prefix_valid(const char *prefix)
{
	size_t n;

	if (!prefix || prefix[0] != '/')
		return 0;
	n = strlen(prefix);
	if (n < 2 || n > APOL_PREFIX_LEN)
		return 0;
	if (strcmp(prefix, "/") == 0)
		return 0;
	if (strstr(prefix, "/../") || strstr(prefix, "//"))
		return 0;
	if (apol_starts(prefix, "/.."))
		return 0;
	return 1;
}

static int apol_is_dir(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static void apol_strip_slash(char *s)
{
	size_t n = strlen(s);

	while (n > 1 && s[n - 1] == '/') {
		s[n - 1] = '\0';
		n--;
	}
}

/* 取父目录（原地）：/a/b/c → /a/b；/a → / */
static void apol_dirname(char *s)
{
	size_t n = strlen(s);
	char *slash;

	while (n > 1 && s[n - 1] == '/') {
		s[n - 1] = '\0';
		n--;
	}
	slash = strrchr(s, '/');
	if (!slash)
		return;
	if (slash == s) {
		s[1] = '\0';
		return;
	}
	*slash = '\0';
}

int apol_path_to_prefix(const char *path, char *out, size_t cap, int *clamped)
{
	char buf[APOL_PATH_MAX];

	if (clamped)
		*clamped = 0;
	if (!apol_path_valid(path) || !out || cap < 3)
		return 0;
	snprintf(buf, sizeof(buf), "%s", path);
	apol_strip_slash(buf);
	if (!apol_is_dir(buf))
		apol_dirname(buf);
	apol_strip_slash(buf);
	if (strcmp(buf, "/") == 0 || buf[0] != '/')
		return 0;
	for (;;) {
		size_t n = strlen(buf);
		char tmp[APOL_PREFIX_MAX];

		if (n + 2 <= APOL_PREFIX_MAX) {
			snprintf(tmp, sizeof(tmp), "%s/", buf);
			if (!apol_prefix_valid(tmp) || strlen(tmp) > cap - 1)
				return 0;
			snprintf(out, cap, "%s", tmp);
			return 1;
		}
		/* 超长：向上收敛一级（绝不切断路径分量） */
		apol_dirname(buf);
		if (strcmp(buf, "/") == 0)
			return 0;
		if (clamped)
			*clamped = 1;
	}
}

int apol_op_from_name(const char *name)
{
	if (!name || !name[0])
		return -1;
	if (strcmp(name, "any") == 0)
		return APOL_OP_ANY;
	if (strcmp(name, "file_open") == 0)
		return APOL_OP_FILE_OPEN;
	if (strcmp(name, "file_read") == 0 || strcmp(name, "read") == 0)
		return APOL_OP_FILE_READ;
	if (strcmp(name, "file_write") == 0 || strcmp(name, "write") == 0)
		return APOL_OP_FILE_WRITE;
	if (strcmp(name, "file_exec") == 0 || strcmp(name, "exec") == 0)
		return APOL_OP_FILE_EXEC;
	if (strcmp(name, "socket_connect") == 0)
		return APOL_OP_SOCKET_CONNECT;
	if (strcmp(name, "socket_sendmsg") == 0)
		return APOL_OP_SOCKET_SENDMSG;
	if (isdigit((unsigned char)name[0])) {
		char *end = NULL;
		long v = strtol(name, &end, 10);

		if (end && *end == '\0' && v >= 0 && v < APOL_OP_MAX)
			return (int)v;
	}
	return -1;
}

const char *apol_op_name(int op)
{
	switch (op) {
	case APOL_OP_ANY:		return "any";
	case APOL_OP_FILE_OPEN:		return "file_open";
	case APOL_OP_FILE_READ:		return "file_read";
	case APOL_OP_FILE_WRITE:	return "file_write";
	case APOL_OP_FILE_EXEC:		return "file_exec";
	case APOL_OP_SOCKET_CONNECT:	return "socket_connect";
	case APOL_OP_SOCKET_SENDMSG:	return "socket_sendmsg";
	default:			return "invalid";
	}
}

static const char *apol_op_word(int op)
{
	switch (op) {
	case APOL_OP_FILE_READ:		return "读取";
	case APOL_OP_FILE_WRITE:	return "写入";
	case APOL_OP_FILE_EXEC:		return "执行";
	case APOL_OP_FILE_OPEN:		return "打开";
	default:			return "访问";
	}
}

int apol_label_of(const char *app_path, char *label, size_t cap, int *label_id)
{
	uint32_t h = 2166136261u;
	const unsigned char *p;

	if (!app_path || !app_path[0] || !label || cap < 16)
		return -1;
	for (p = (const unsigned char *)app_path; *p; p++) {
		h ^= (uint32_t)*p;
		h *= 16777619u;
	}
	h ^= h >> 16;
	if (label_id)
		*label_id = 1 + (int)(h % 255u);
	snprintf(label, cap, "app-%08x", h);
	return 0;
}

/* ======================================================================
 * 2) 规则表：去重 / 合并 / 冲突 / 上限
 * ====================================================================== */

int apol_rule_add(struct apol_policy *p, const struct apol_rule *r)
{
	int i;

	if (!p || !r)
		return 0;
	if (r->kind == APOL_KIND_PATH && !apol_prefix_valid(r->path_prefix))
		return 0;
	if (r->op <= APOL_OP_ANY || r->op >= APOL_OP_MAX)
		return 0;
	for (i = 0; i < p->rule_n; i++) {
		struct apol_rule *e = &p->rules[i];

		if (e->kind != r->kind || e->op != r->op)
			continue;
		if (r->kind == APOL_KIND_PATH) {
			if (strcmp(e->path_prefix, r->path_prefix) != 0)
				continue;
		} else if (e->label_id != r->label_id) {
			continue;
		}
		if (e->deny == r->deny) {
			p->merged++;
			e->witnesses += (r->witnesses > 0 ? r->witnesses : 1);
			if (r->sensitive)
				e->sensitive = 1;
			if (r->requires_confirm)
				e->requires_confirm = 1;
			return 2;
		}
		/* 冲突：deny 胜（同一路径前缀上拒绝永远压过放行） */
		p->conflicts++;
		p->merged++;
		if (r->deny) {
			struct apol_rule merged = *r;

			merged.witnesses = e->witnesses + 1;
			merged.id = e->id;
			*e = merged;
			return 3;
		}
		return 2;
	}
	if (p->rule_n >= APOL_MAX_RULES) {
		p->cap_hit = 1;
		return -1;
	}
	p->rules[p->rule_n] = *r;
	p->rules[p->rule_n].id = p->rule_n + 1;
	if (p->rules[p->rule_n].witnesses <= 0)
		p->rules[p->rule_n].witnesses = 1;
	p->rule_n++;
	return 1;
}

int apol_has_allow_all(const struct apol_policy *p)
{
	int i;

	if (!p)
		return 1;
	if (p->allow_all)
		return 1;
	for (i = 0; i < p->rule_n; i++) {
		const struct apol_rule *r = &p->rules[i];

		if (r->deny)
			continue;
		if (r->op == APOL_OP_ANY)
			return 1;
		if (r->path_prefix[0] == '\0' || strcmp(r->path_prefix, "/") == 0)
			return 1;
	}
	return 0;
}

static void apol_warn(struct apol_policy *p, const char *fmt, ...)
{
	char tmp[256];
	va_list ap;

	if (p->warn_n >= APOL_MAX_LINES)
		return;
	va_start(ap, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	snprintf(p->warn[p->warn_n], sizeof(p->warn[0]), "%s", tmp);
	p->warn_n++;
}

static void apol_degrade(struct apol_policy *p, const char *fmt, ...)
{
	char tmp[256];
	va_list ap;

	if (p->deg_n >= APOL_MAX_LINES)
		return;
	va_start(ap, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	snprintf(p->degraded[p->deg_n], sizeof(p->degraded[0]), "%s", tmp);
	p->deg_n++;
}

/* ======================================================================
 * 3) 静态画像 JSON → 事实子集
 * ====================================================================== */

static int apol_jget_str(const char *obj, size_t olen, const char *key,
			 char *out, size_t cap)
{
	const char *v;
	size_t vlen;
	int t;
	char *s;

	if (cap)
		out[0] = '\0';
	if (ai_json_obj_get(obj, olen, key, &v, &vlen, &t) != 1)
		return 0;
	if (t != AI_JSON_STR)
		return 0;
	s = ai_json_strdup_str(v, vlen);
	if (!s)
		return 0;
	snprintf(out, cap, "%s", s);
	free(s);
	return 1;
}

static int apol_jget_bool(const char *obj, size_t olen, const char *key,
			  int def)
{
	const char *v;
	size_t vlen;
	int t;

	if (ai_json_obj_get(obj, olen, key, &v, &vlen, &t) != 1)
		return def;
	if (t != AI_JSON_BOOL)
		return def;
	return vlen >= 4 && strncmp(v, "true", 4) == 0;
}

int apol_static_json_parse(const char *json, struct apol_static_input *st,
			   char *err, size_t errcap)
{
	const char *pp, *obj;
	size_t olen = 0;
	int t, i;

	memset(st, 0, sizeof(*st));
	if (!json || !json[0]) {
		snprintf(err, errcap, "静态画像为空");
		return -1;
	}
	pp = json;
	if (ai_json_scan_value(&pp, json + strlen(json), &obj, &olen, &t) != 0 ||
	    t != AI_JSON_OBJ) {
		snprintf(err, errcap, "静态画像不是 JSON 对象");
		return -1;
	}
	if (!apol_jget_str(obj, olen, "path", st->path, sizeof(st->path)) ||
	    !st->path[0]) {
		snprintf(err, errcap, "静态画像缺 path");
		return -1;
	}
	{
		const char *elf;
		size_t ellen;
		int et;

		if (ai_json_obj_get(obj, olen, "elf", &elf, &ellen, &et) == 1 &&
		    et == AI_JSON_OBJ)
			st->had_interp = apol_jget_str(elf, ellen, "interp",
						       st->interp,
						       sizeof(st->interp));
	}
	{
		const char *deps;
		size_t dlen;
		int dt;

		if (ai_json_obj_get(obj, olen, "deps", &deps, &dlen, &dt) == 1 &&
		    dt == AI_JSON_OBJ) {
			const char *arr;
			size_t alen;
			int at;

			if (ai_json_obj_get(deps, dlen, "needed", &arr, &alen,
					    &at) == 1 && at == AI_JSON_ARR) {
				for (i = 0; i < APOL_MAX_NEEDED; i++) {
					const char *el;
					size_t elen;
					int elt;
					char *s;

					if (ai_json_arr_get(arr, alen, i, &el,
							    &elen, &elt) != 1)
						break;
					if (elt != AI_JSON_STR)
						continue;
					s = ai_json_strdup_str(el, elen);
					if (!s)
						continue;
					snprintf(st->needed[st->needed_n],
						 sizeof(st->needed[0]), "%s",
						 s);
					free(s);
					st->needed_n++;
				}
			}
		}
	}
	{
		const char *sso;
		size_t slen;
		int sst;

		if (ai_json_obj_get(obj, olen, "stat", &sso, &slen, &sst) == 1 &&
		    sst == AI_JSON_OBJ) {
			st->setuid = apol_jget_bool(sso, slen, "setuid", 0);
			st->setgid = apol_jget_bool(sso, slen, "setgid", 0);
		}
	}
	{
		const char *pkg;
		size_t plen;
		int pt;

		if (ai_json_obj_get(obj, olen, "pkg", &pkg, &plen, &pt) == 1 &&
		    pt == AI_JSON_OBJ) {
			st->pkg_found = apol_jget_bool(pkg, plen, "found", 0);
			if (st->pkg_found)
				(void)apol_jget_str(pkg, plen, "package",
						    st->pkg, sizeof(st->pkg));
		}
	}
	{
		const char *caps;
		size_t clen;
		int ct;

		if (ai_json_obj_get(obj, olen, "caps", &caps, &clen, &ct) == 1 &&
		    ct == AI_JSON_OBJ)
			(void)apol_jget_str(caps, clen, "state",
					    st->caps_state,
					    sizeof(st->caps_state));
	}
	return 0;
}

/* ======================================================================
 * 4) 生成核心
 * ====================================================================== */

static int apol_add_path_rule(struct apol_policy *p, int op, int deny,
			      const char *prefix, const char *fact_path,
			      int fact_seq, const char *basis,
			      const char *because, int sensitive, int confirm)
{
	struct apol_rule r;
	int rc;

	memset(&r, 0, sizeof(r));
	r.kind = APOL_KIND_PATH;
	r.label_id = p->label_id;
	r.op = op;
	r.deny = deny;
	r.sensitive = sensitive;
	r.requires_confirm = confirm;
	r.fact_seq = fact_seq;
	snprintf(r.path_prefix, sizeof(r.path_prefix), "%s",
		 prefix ? prefix : "");
	snprintf(r.fact_path, sizeof(r.fact_path), "%s", fact_path ? fact_path :
		 "");
	snprintf(r.basis, sizeof(r.basis), "%s", basis ? basis : "static");
	snprintf(r.because, sizeof(r.because), "%s", because ? because : "");
	snprintf(r.detail, sizeof(r.detail), "%s %s",
		 deny ? "deny" : "allow", apol_op_name(op));
	rc = apol_rule_add(p, &r);
	if (rc == 0 || rc == -1)
		p->dropped++;
	return rc;
}

static void apol_add_sens(struct apol_policy *p, const char *path,
			  const char *why)
{
	int i;

	for (i = 0; i < p->sens_n; i++) {
		if (strcmp(p->sens[i].path, path) == 0)
			return;
	}
	if (p->sens_n >= APOL_MAX_SENS)
		return;
	snprintf(p->sens[p->sens_n].path, sizeof(p->sens[0].path), "%s", path);
	snprintf(p->sens[p->sens_n].why, sizeof(p->sens[0].why), "%s", why);
	p->sens_n++;
}

static void apol_add_net(struct apol_policy *p, const struct ap_event *e,
			 int seq)
{
	int i, loopback = 0;

	for (i = 0; i < p->net_n; i++) {
		if (strcmp(p->net[i].remote, e->remote) == 0 &&
		    strcmp(p->net[i].proto, e->proto) == 0) {
			p->net[i].count += e->count > 0 ? e->count : 1;
			return;
		}
	}
	if (p->net_n >= APOL_MAX_NET) {
		p->dropped++;
		return;
	}
	if (strncmp(e->remote, "127.", 4) == 0 ||
	    strcmp(e->remote, "::1") == 0 ||
	    strncmp(e->remote, "[::1]", 5) == 0 ||
	    strncmp(e->remote, "localhost", 9) == 0)
		loopback = 1;
	snprintf(p->net[p->net_n].proto, sizeof(p->net[0].proto), "%s",
		 e->proto);
	snprintf(p->net[p->net_n].remote, sizeof(p->net[0].remote), "%s",
		 e->remote);
	p->net[p->net_n].count = e->count > 0 ? e->count : 1;
	p->net[p->net_n].loopback = loopback;
	snprintf(p->net[p->net_n].because, sizeof(p->net[0].because),
		 "动态画像事件 #%d 连接了 %s/%s（原样记录；LSM 路径规则不可"
		 "表达网络目的地址，enforceable=false）", seq, e->proto,
		 e->remote);
	p->net_n++;
}

/* 一条动态事件 → 规则（或 net 目标） */
static void apol_fact_to_rules(struct apol_policy *p, const struct ap_event *e,
			       int seq)
{
	char prefix[APOL_PREFIX_MAX];
	char because[APOL_BECAUSE_MAX];
	char fact[AP_EV_PATH];
	int op, clamped = 0, is_exec = 0;
	const char *kind_word;

	snprintf(fact, sizeof(fact), "%s", e->path);
	switch (e->type) {
	case AP_EV_FILE_READ:
		op = APOL_OP_FILE_READ;
		kind_word = "读取";
		break;
	case AP_EV_FILE_MMAP:
		op = APOL_OP_FILE_READ;
		kind_word = "映射（按读权限可表达）";
		break;
	case AP_EV_FILE_WRITE:
		op = APOL_OP_FILE_WRITE;
		kind_word = "写入";
		break;
	case AP_EV_PROC_EXEC:
		op = APOL_OP_FILE_EXEC;
		kind_word = "执行";
		is_exec = 1;
		break;
	case AP_EV_NET_CONNECT:
	case AP_EV_NET_LISTEN:
	case AP_EV_NET_UNIX:
		apol_add_net(p, e, seq);
		return;
	default:
		p->dropped++;
		return;
	}
	if (!apol_path_valid(fact)) {
		apol_warn(p, "丢弃非法路径事实（非绝对/含 .. 或控制字符）："
			  "%.120s", fact);
		p->dropped++;
		return;
	}
	if (apol_path_sensitive(fact)) {
		/* 危险项：精确路径 deny，绝不放大到父目录，也绝不自动放行 */
		if (strlen(fact) > APOL_PREFIX_LEN) {
			int cl = 0;

			if (!apol_path_to_prefix(fact, prefix, sizeof(prefix),
						 &cl)) {
				apol_warn(p, "敏感路径过长且无法收敛，未生成 "
					  "deny：%.120s", fact);
				p->dropped++;
				return;
			}
			if (cl)
				p->clamped++;
		} else {
			snprintf(prefix, sizeof(prefix), "%s", fact);
		}
		snprintf(because, sizeof(because),
			 "动态画像事件 #%d 命中危险路径 %s（%s操作）：危险项"
			 "绝不自动放行，生成精确 deny 并要求人工确认",
			 seq, fact, kind_word);
		(void)apol_add_path_rule(p, op, 1, prefix, fact, seq, "dynamic",
					 because, 1, 1);
		apol_add_sens(p, fact, "危险路径命中动态画像");
		p->requires_confirm = 1;
		return;
	}
	if (is_exec) {
		/* 执行：精确文件路径（≤63 时原样，否则向上收敛） */
		if (strlen(fact) <= APOL_PREFIX_LEN) {
			snprintf(prefix, sizeof(prefix), "%s", fact);
		} else if (!apol_path_to_prefix(fact, prefix, sizeof(prefix),
						&clamped)) {
			p->dropped++;
			return;
		}
	} else if (!apol_path_to_prefix(fact, prefix, sizeof(prefix),
					&clamped)) {
		apol_warn(p, "路径无法收敛为合法前缀，已丢弃：%.120s", fact);
		p->dropped++;
		return;
	}
	if (clamped) {
		p->clamped++;
		apol_warn(p, "路径超过 %d 字节，前缀向上收敛为 %s（事实：%.100s）",
			  APOL_PREFIX_LEN, prefix, fact);
	}
	snprintf(because, sizeof(because),
		 "动态画像事件 #%d %s了 %s → 允许%s %s", seq, kind_word, fact,
		 apol_op_word(op), prefix);
	(void)apol_add_path_rule(p, op, 0, prefix, fact, seq, "dynamic",
				 because, 0, 0);
}

int apol_generate(const char *app_path, const struct ap_event *ev, int ev_n,
		  const struct apol_static_input *st, struct apol_policy *p,
		  char *err, size_t errcap)
{
	char path[APOL_PATH_MAX];
	char label[APOL_LABEL_MAX];
	int label_id = 0, i;

	memset(p, 0, sizeof(*p));
	snprintf(p->schema, sizeof(p->schema), "%s", APOL_SCHEMA);

	if (app_path && app_path[0])
		snprintf(path, sizeof(path), "%s", app_path);
	else if (st && st->path[0])
		snprintf(path, sizeof(path), "%s", st->path);
	else {
		snprintf(err, errcap, "bad_app_path|缺少 app（可执行文件路径）"
			 "且画像里也没有 path");
		return -1;
	}
	if (!apol_path_valid(path)) {
		snprintf(err, errcap, "bad_app_path|目标路径非法（需绝对路径且"
			 "不含 ..）：%s", path);
		return -1;
	}
	snprintf(p->app_path, sizeof(p->app_path), "%s", path);
	apol_copy(p->app_base, sizeof(p->app_base), apol_base(path));
	if (apol_label_of(path, label, sizeof(label), &label_id) != 0) {
		snprintf(err, errcap, "bad_app_path|无法派生策略标签");
		return -1;
	}
	snprintf(p->label, sizeof(p->label), "%s", label);
	p->label_id = label_id;

	/* 规则 1：主体自身的执行权（静态事实：这就是被约束的那个文件） */
	{
		char prefix[APOL_PREFIX_MAX];
		char because[APOL_BECAUSE_MAX];
		int clamped = 0;

		if (strlen(path) <= APOL_PREFIX_LEN) {
			snprintf(prefix, sizeof(prefix), "%s", path);
		} else if (!apol_path_to_prefix(path, prefix, sizeof(prefix),
						&clamped)) {
			snprintf(err, errcap,
				 "bad_app_path|目标路径无法收敛为合法前缀");
			return -1;
		}
		snprintf(because, sizeof(because),
			 "策略主体：目标自身 %s（静态事实；这是唯一一条不来自"
			 "运行观测的规则）", path);
		(void)apol_add_path_rule(p, APOL_OP_FILE_EXEC, 0, prefix, path,
					 0, "static", because, 0, 0);
	}

	/* 静态事实：解释器（ELF interp）+ NEEDED 的落点核对 */
	if (st) {
		if (st->had_interp && st->interp[0] &&
		    apol_path_valid(st->interp)) {
			char prefix[APOL_PREFIX_MAX];
			char because[APOL_BECAUSE_MAX];
			int clamped = 0;

			if (apol_path_to_prefix(st->interp, prefix,
						sizeof(prefix), &clamped)) {
				snprintf(because, sizeof(because),
					 "静态画像 elf.interp=%.400s：动态加载器"
					 "是运行必需", st->interp);
				(void)apol_add_path_rule(p, APOL_OP_FILE_READ, 0,
							 prefix, st->interp, 0,
							 "static", because, 0,
							 0);
			}
		}
		for (i = 0; i < st->needed_n; i++) {
			int j, found = 0;

			for (j = 0; j < ev_n; j++) {
				if ((ev[j].type == AP_EV_FILE_READ ||
				     ev[j].type == AP_EV_FILE_MMAP) &&
				    strcmp(apol_base(ev[j].path), st->needed[i])
				    == 0) {
					found = 1;
					break;
				}
			}
			if (found) {
				p->resolved_sonames++;
				continue;
			}
			if (p->unresolved_n < APOL_MAX_UNRESOLVED)
				snprintf(p->unresolved[p->unresolved_n++],
					 sizeof(p->unresolved[0]), "%s",
					 st->needed[i]);
		}
		if (st->setuid)
			apol_warn(p, "目标带 setuid 位：策略只约束文件访问，"
				  "不管提权面（提权需能力/SUID 专项策略）");
		if (st->setgid)
			apol_warn(p, "目标带 setgid 位：同上");
		if (st->caps_state[0] && strcmp(st->caps_state, "none") != 0)
			apol_warn(p, "目标带文件能力（caps.state=%s）：LSM "
				  "路径规则不涉及能力集", st->caps_state);
	}

	/* 动态事实：逐条事件 → 规则 */
	for (i = 0; i < ev_n; i++)
		apol_fact_to_rules(p, &ev[i], i + 1);
	p->dynamic_available = ev_n > 0;

	if (ev_n == 0) {
		if (!st) {
			snprintf(err, errcap, "empty_profile|空画像：既没有动态"
				 "事件也没有静态画像，无法生成任何规则");
			return -1;
		}
		apol_degrade(p, "无动态画像：策略仅含静态事实（主体 exec + 解释"
			    "器读），不含实际访问路径；建议先跑 "
			    "app_profile_dynamic 再生成");
	}
	if (p->rule_n == 0) {
		snprintf(err, errcap, "no_enforceable_rules|事实全部不可表达"
			 "（如只有网络目标而没有文件事实），未生成任何 LSM "
			 "规则");
		return -1;
	}
	if (p->cap_hit)
		apol_warn(p, "规则数撞到内核上限 %d：已丢弃 %d 条事实（不静默"
			  "截断，请缩小观测范围重采）", APOL_MAX_RULES,
			  p->dropped);
	/* 危险路径若落在某个更宽的 allow 前缀之下，必须明说"靠更长前缀
	 * deny 覆盖"（内核同级匹配：前缀越长越具体，deny 只在平手时优先），
	 * 否则策略读起来像自相矛盾。 */
	{
		int k, j;

		for (k = 0; k < p->sens_n; k++) {
			for (j = 0; j < p->rule_n; j++) {
				const struct apol_rule *a = &p->rules[j];
				size_t al;

				if (a->deny || a->op != APOL_OP_FILE_READ)
					continue;
				al = strlen(a->path_prefix);
				if (al == 0 || al >= strlen(p->sens[k].path))
					continue;
				if (strncmp(p->sens[k].path, a->path_prefix, al)
				    != 0)
					continue;
				apol_warn(p, "敏感路径 %s 落在 allow 前缀 %s 之下："
					  "由更长的精确 deny 覆盖（内核前缀越长"
					  "越具体）", p->sens[k].path,
					  a->path_prefix);
			}
		}
	}
	if (p->unresolved_n > 0)
		apol_degrade(p, "静态 NEEDED 里 %d 个库未在动态事件中定位到"
			    "绝对路径（未生成规则，首项 %s）", p->unresolved_n,
			    p->unresolved[0]);
	if (apol_has_allow_all(p)) {
		/* 最后一道自检：宁可失败也不下发 allow-all */
		snprintf(err, errcap, "no_enforceable_rules|内部自检失败：策略"
			 "里出现 allow-all");
		return -1;
	}
	return 0;
}

/* ======================================================================
 * 5) 渲染
 * ====================================================================== */

static void apol_render_rules(struct apolb *b, const struct apol_policy *p)
{
	int i;

	apolb_puts(b, "[");
	for (i = 0; i < p->rule_n; i++) {
		const struct apol_rule *r = &p->rules[i];

		if (i)
			apolb_puts(b, ",");
		apolb_printf(b, "{\"id\":%d,\"kind\":\"%s\",\"label\":", r->id,
			     r->kind == APOL_KIND_LABEL ? "label" : "path");
		apolb_json_str(b, p->label);
		apolb_printf(b, ",\"label_id\":%d,\"op\":\"%s\",\"op_id\":%d,"
			     "\"deny\":%s,\"sensitive\":%s,"
			     "\"requires_confirm\":%s,\"witnesses\":%d,"
			     "\"path_prefix\":", r->label_id,
			     apol_op_name(r->op), r->op,
			     r->deny ? "true" : "false",
			     r->sensitive ? "true" : "false",
			     r->requires_confirm ? "true" : "false",
			     r->witnesses);
		apolb_json_str(b, r->path_prefix);
		apolb_printf(b, ",\"fact\":{\"seq\":%d,\"basis\":", r->fact_seq);
		apolb_json_str(b, r->basis);
		apolb_puts(b, ",\"path\":");
		apolb_json_str_or_null(b, r->fact_path);
		apolb_puts(b, "},\"detail\":");
		apolb_json_str(b, r->detail);
		apolb_puts(b, ",\"because\":");
		apolb_json_str(b, r->because);
		apolb_puts(b, "}");
	}
	apolb_puts(b, "]");
}

static void apol_render_allowlist(struct apolb *b, const struct apol_policy *p)
{
	int i, first;

	apolb_puts(b, "{\"read\":[");
	first = 1;
	for (i = 0; i < p->rule_n; i++) {
		if (p->rules[i].deny || p->rules[i].op != APOL_OP_FILE_READ)
			continue;
		if (!first)
			apolb_puts(b, ",");
		apolb_json_str(b, p->rules[i].path_prefix);
		first = 0;
	}
	apolb_puts(b, "],\"write\":[");
	first = 1;
	for (i = 0; i < p->rule_n; i++) {
		if (p->rules[i].deny || p->rules[i].op != APOL_OP_FILE_WRITE)
			continue;
		if (!first)
			apolb_puts(b, ",");
		apolb_json_str(b, p->rules[i].path_prefix);
		first = 0;
	}
	apolb_puts(b, "],\"exec\":[");
	first = 1;
	for (i = 0; i < p->rule_n; i++) {
		if (p->rules[i].deny || p->rules[i].op != APOL_OP_FILE_EXEC)
			continue;
		if (!first)
			apolb_puts(b, ",");
		apolb_json_str(b, p->rules[i].path_prefix);
		first = 0;
	}
	apolb_puts(b, "],\"net\":[");
	for (i = 0; i < p->net_n; i++) {
		if (i)
			apolb_puts(b, ",");
		apolb_puts(b, "{\"proto\":");
		apolb_json_str(b, p->net[i].proto);
		apolb_puts(b, ",\"remote\":");
		apolb_json_str(b, p->net[i].remote);
		apolb_printf(b, ",\"count\":%d,\"loopback\":%s,"
			     "\"enforceable\":false,\"reason\":",
			     p->net[i].count,
			     p->net[i].loopback ? "true" : "false");
		apolb_json_str(b, "ai_lsm_socket_connect/socket_sendmsg 只按 "
			     "pid/label 匹配（path 传 NULL），路径规则无法表达"
			     "网络目的地址；本项仅作声明，不下发");
		apolb_puts(b, ",\"because\":");
		apolb_json_str(b, p->net[i].because);
		apolb_puts(b, "}");
	}
	apolb_puts(b, "]}");
}

int apol_policy_render_json(const struct apol_policy *p, const char *tool,
			    char **out)
{
	struct apolb b;
	int i;

	*out = NULL;
	if (apolb_init(&b, 8192) != 0)
		return -1;
	apolb_puts(&b, "{\"tool\":");
	apolb_json_str(&b, tool ? tool : "app_policy_generate");
	apolb_puts(&b, ",\"schema\":");
	apolb_json_str(&b, APOL_SCHEMA);
	apolb_puts(&b, ",\"ok\":true,\"policy\":{\"schema\":");
	apolb_json_str(&b, p->schema);
	apolb_puts(&b, ",\"app_path\":");
	apolb_json_str(&b, p->app_path);
	apolb_puts(&b, ",\"app_base\":");
	apolb_json_str(&b, p->app_base);
	apolb_puts(&b, ",\"label\":");
	apolb_json_str(&b, p->label);
	apolb_printf(&b, ",\"label_id\":%d,\"allow_all\":%s,"
		     "\"requires_confirm\":%s,\"dynamic_available\":%s",
		     p->label_id, p->allow_all ? "true" : "false",
		     p->requires_confirm ? "true" : "false",
		     p->dynamic_available ? "true" : "false");
	apolb_printf(&b, ",\"stats\":{\"rules\":%d,\"merged\":%d,"
		     "\"dropped\":%d,\"conflicts\":%d,\"clamped\":%d,"
		     "\"cap_hit\":%s,\"sensitive\":%d,\"net\":%d,"
		     "\"resolved_sonames\":%d}",
		     p->rule_n, p->merged, p->dropped, p->conflicts,
		     p->clamped, p->cap_hit ? "true" : "false", p->sens_n,
		     p->net_n, p->resolved_sonames);
	apolb_puts(&b, ",\"rules\":");
	apol_render_rules(&b, p);
	apolb_puts(&b, ",\"allowlist\":");
	apol_render_allowlist(&b, p);
	apolb_puts(&b, ",\"sensitive_hits\":[");
	for (i = 0; i < p->sens_n; i++) {
		if (i)
			apolb_puts(&b, ",");
		apolb_puts(&b, "{\"path\":");
		apolb_json_str(&b, p->sens[i].path);
		apolb_puts(&b, ",\"why\":");
		apolb_json_str(&b, p->sens[i].why);
		apolb_puts(&b, "}");
	}
	apolb_puts(&b, "],\"unresolved_sonames\":[");
	for (i = 0; i < p->unresolved_n; i++) {
		if (i)
			apolb_puts(&b, ",");
		apolb_json_str(&b, p->unresolved[i]);
	}
	apolb_puts(&b, "],\"warnings\":[");
	for (i = 0; i < p->warn_n; i++) {
		if (i)
			apolb_puts(&b, ",");
		apolb_json_str(&b, p->warn[i]);
	}
	apolb_puts(&b, "],\"degraded\":[");
	for (i = 0; i < p->deg_n; i++) {
		if (i)
			apolb_puts(&b, ",");
		apolb_json_str(&b, p->degraded[i]);
	}
	apolb_puts(&b, "]}}");
	if (b.oom) {
		apolb_free(&b);
		return -1;
	}
	*out = b.p;
	return 0;
}

/* ======================================================================
 * 6) 策略 JSON 解析 / 校验（apply 入口）
 * ====================================================================== */

static int apol_parse_rule(const char *obj, size_t olen, int idx,
			   struct apol_policy *p, char *err, size_t errcap)
{
	struct apol_rule r;
	char kind[32] = "path";
	char opname[32] = "";
	char prefix[APOL_PREFIX_MAX] = "";
	char because[APOL_BECAUSE_MAX] = "";
	const char *v;
	size_t vlen;
	int t, id = 0;

	memset(&r, 0, sizeof(r));
	(void)apol_jget_str(obj, olen, "kind", kind, sizeof(kind));
	if (strcmp(kind, "path") != 0 && strcmp(kind, "label") != 0) {
		snprintf(err, errcap, "rules[%d].kind 非法（%s）", idx, kind);
		return -1;
	}
	r.kind = strcmp(kind, "label") == 0 ? APOL_KIND_LABEL : APOL_KIND_PATH;
	if (ai_json_obj_get(obj, olen, "op_id", &v, &vlen, &t) == 1 &&
	    t == AI_JSON_NUM)
		r.op = (int)ai_json_ll(v, vlen);
	else if (apol_jget_str(obj, olen, "op", opname, sizeof(opname)))
		r.op = apol_op_from_name(opname);
	else {
		snprintf(err, errcap, "rules[%d] 缺 op/op_id", idx);
		return -1;
	}
	if (r.op <= APOL_OP_ANY || r.op >= APOL_OP_MAX) {
		snprintf(err, errcap, "rules[%d].op 非法（必须 1..6；ANY 不允许"
			 "出现在策略里）", idx);
		return -1;
	}
	if (r.kind == APOL_KIND_PATH) {
		if (!apol_jget_str(obj, olen, "path_prefix", prefix,
				   sizeof(prefix)) || !prefix[0]) {
			snprintf(err, errcap, "rules[%d] 缺 path_prefix", idx);
			return -1;
		}
		if (!apol_prefix_valid(prefix)) {
			snprintf(err, errcap, "rules[%d].path_prefix 非法（需以 "
				 "/ 开头、非根、≤%d 字节）：%s", idx,
				 APOL_PREFIX_LEN, prefix);
			return -1;
		}
	}
	if (ai_json_obj_get(obj, olen, "label_id", &v, &vlen, &t) == 1 &&
	    t == AI_JSON_NUM)
		id = (int)ai_json_ll(v, vlen);
	r.label_id = id > 0 ? id : p->label_id;
	r.deny = apol_jget_bool(obj, olen, "deny", 0);
	r.sensitive = apol_jget_bool(obj, olen, "sensitive", 0);
	r.requires_confirm = apol_jget_bool(obj, olen, "requires_confirm", 0);
	(void)apol_jget_str(obj, olen, "because", because, sizeof(because));
	if (!because[0]) {
		snprintf(err, errcap, "rules[%d] 缺 because：策略必须可解释，"
			 "不接受无依据规则", idx);
		return -1;
	}
	snprintf(r.path_prefix, sizeof(r.path_prefix), "%s", prefix);
	snprintf(r.because, sizeof(r.because), "%s", because);
	snprintf(r.basis, sizeof(r.basis), "%s", "policy");
	(void)apol_jget_str(obj, olen, "detail", r.detail, sizeof(r.detail));
	if (ai_json_obj_get(obj, olen, "fact", &v, &vlen, &t) == 1 &&
	    t == AI_JSON_OBJ) {
		const char *fv;
		size_t fvl;
		int ft;

		if (ai_json_obj_get(v, vlen, "seq", &fv, &fvl, &ft) == 1 &&
		    ft == AI_JSON_NUM)
			r.fact_seq = (int)ai_json_ll(fv, fvl);
		(void)apol_jget_str(v, vlen, "path", r.fact_path,
				    sizeof(r.fact_path));
	}
	if (apol_rule_add(p, &r) <= 0) {
		snprintf(err, errcap, "rules[%d] 无法加入策略（重复或超限）",
			 idx);
		return -1;
	}
	return 0;
}

int apol_policy_parse(const char *json, struct apol_policy *p, char *err,
		      size_t errcap)
{
	const char *pp, *root = NULL, *pol = NULL;
	size_t rlen = 0, plen = 0;
	int rt = 0;
	const char *v;
	size_t vlen;
	int t, i, n = 0;
	char schema[64] = "";

	memset(p, 0, sizeof(*p));
	if (!json || !json[0]) {
		snprintf(err, errcap, "策略为空");
		return -1;
	}
	pp = json;
	if (ai_json_scan_value(&pp, json + strlen(json), &root, &rlen, &rt) != 0
	    || rt != AI_JSON_OBJ) {
		snprintf(err, errcap, "策略不是合法 JSON 对象");
		return -1;
	}
	/* 接受 app_policy_generate 的整包（嵌套 policy）或裸策略对象 */
	if (ai_json_obj_get(root, rlen, "policy", &v, &vlen, &t) == 1 &&
	    t == AI_JSON_OBJ) {
		pol = v;
		plen = vlen;
	} else {
		pol = root;
		plen = rlen;
	}
	if (!apol_jget_str(pol, plen, "schema", schema, sizeof(schema)) ||
	    strcmp(schema, APOL_SCHEMA) != 0) {
		snprintf(err, errcap, "schema 不匹配：需要 %s，实际 '%s'",
			 APOL_SCHEMA, schema);
		return -1;
	}
	snprintf(p->schema, sizeof(p->schema), "%s", schema);
	(void)apol_jget_str(pol, plen, "app_path", p->app_path,
			    sizeof(p->app_path));
	apol_copy(p->app_base, sizeof(p->app_base), apol_base(p->app_path));
	(void)apol_jget_str(pol, plen, "label", p->label, sizeof(p->label));
	if (ai_json_obj_get(pol, plen, "label_id", &v, &vlen, &t) == 1 &&
	    t == AI_JSON_NUM)
		p->label_id = (int)ai_json_ll(v, vlen);
	if (p->label_id < 0 || p->label_id > 255) {
		snprintf(err, errcap, "label_id 越界（0..255）");
		return -1;
	}
	p->allow_all = apol_jget_bool(pol, plen, "allow_all", 0);
	p->requires_confirm = apol_jget_bool(pol, plen, "requires_confirm", 0);

	if (ai_json_obj_get(pol, plen, "rules", &v, &vlen, &t) != 1 ||
	    t != AI_JSON_ARR) {
		snprintf(err, errcap, "策略缺 rules 数组");
		return -1;
	}
	for (i = 0;; i++) {
		const char *el;
		size_t elen;
		int et;

		if (ai_json_arr_get(v, vlen, i, &el, &elen, &et) != 1)
			break;
		if (n >= APOL_MAX_RULES) {
			snprintf(err, errcap, "rules 超过内核上限 %d",
				 APOL_MAX_RULES);
			return -1;
		}
		if (et != AI_JSON_OBJ) {
			snprintf(err, errcap, "rules[%d] 不是对象", i);
			return -1;
		}
		if (apol_parse_rule(el, elen, i, p, err, errcap) != 0)
			return -1;
		n++;
	}
	if (n == 0) {
		snprintf(err, errcap, "empty_policy|策略里没有任何规则（拒绝"
			 "空策略下发）");
		return -1;
	}
	if (p->allow_all) {
		snprintf(err, errcap, "allow_all=true 被拒绝：本工具永不接受 "
			 "allow-all 策略");
		return -1;
	}
	if (apol_has_allow_all(p)) {
		snprintf(err, errcap, "策略含 allow-all 规则（op=any 或 "
			 "path_prefix=/）：拒绝");
		return -1;
	}
	for (i = 0; i < p->rule_n; i++) {
		if (p->rules[i].requires_confirm || p->rules[i].sensitive)
			p->requires_confirm = 1;
	}
	if (p->app_path[0] && !apol_path_valid(p->app_path)) {
		snprintf(err, errcap, "app_path 非法：%s", p->app_path);
		return -1;
	}
	return 0;
}

/* ======================================================================
 * 7) LSM / 注入面探测
 * ====================================================================== */

int apol_lsm_probe(const char *path, struct apol_lsm_info *info)
{
	const char *src = path && path[0] ? path : "/sys/kernel/security/lsm";
	char *raw;
	char *tok, *save = NULL;
	size_t len = 0;

	memset(info, 0, sizeof(*info));
	snprintf(info->source, sizeof(info->source), "%s", src);
	raw = apol_read_file(src, 511, &len);
	if (!raw) {
		info->ai_present = -1;
		snprintf(info->err, sizeof(info->err),
			 "读不到 %s（%s）：无法判定 LSM 集合，fail-closed",
			 src, strerror(errno));
		return -1;
	}
	apol_trim(raw);
	snprintf(info->raw, sizeof(info->raw), "%s", raw);
	for (tok = strtok_r(raw, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		char *s = tok;
		size_t n;

		while (*s == ' ' || *s == '\t')
			s++;
		n = strlen(s);
		while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
			s[--n] = '\0';
		if (!s[0])
			continue;
		if (info->list[0])
			strncat(info->list, ",",
				sizeof(info->list) - strlen(info->list) - 1);
		strncat(info->list, s,
			sizeof(info->list) - strlen(info->list) - 1);
		if (strcmp(s, "ai") == 0)
			info->ai_present = 1;
	}
	if (info->ai_present != 1)
		info->ai_present = 0;
	free(raw);
	return 0;
}

int apol_inject_probe(const char *root, struct apol_inject_info *info)
{
	static const char *const cands[] = {
		"proc/ai/lsm/rules",
		"sys/kernel/ai/lsm/rules",
		"proc/ai/lsm_rules",
		NULL
	};
	int i;
	size_t used = 0;

	memset(info, 0, sizeof(*info));
	for (i = 0; cands[i]; i++) {
		char full[512];
		struct stat st;

		if (!root || !root[0] || strcmp(root, "/") == 0)
			snprintf(full, sizeof(full), "/%s", cands[i]);
		else
			snprintf(full, sizeof(full), "%s/%s", root, cands[i]);
		if (used < sizeof(info->probes) - 1)
			used += (size_t)snprintf(info->probes + used,
						 sizeof(info->probes) - used,
						 "%s%s", used ? "," : "",
						 full);
		if (stat(full, &st) != 0)
			continue;
		if (!S_ISREG(st.st_mode) && !S_ISCHR(st.st_mode))
			continue;
		if (access(full, W_OK) != 0)
			continue;
		info->found = 1;
		apol_copy(info->path, sizeof(info->path), full);
		apol_copy(info->kind, sizeof(info->kind),
			  S_ISCHR(st.st_mode) ? "char-node" : "file-node");
		return 0;
	}
	snprintf(info->err, sizeof(info->err),
		 "没有可写的规则注入节点（探测过：%.200s）", info->probes);
	return -1;
}

/* ======================================================================
 * 8) 下发状态机
 * ====================================================================== */

int apol_rule_uri(const struct apol_rule *r, char *out, size_t cap)
{
	if (r->kind == APOL_KIND_LABEL)
		return snprintf(out, cap, "label:%d:%s:%s", r->label_id,
				apol_op_name(r->op),
				r->deny ? "deny" : "allow");
	return snprintf(out, cap, "path:%s:%s:%s", r->path_prefix,
			apol_op_name(r->op), r->deny ? "deny" : "allow");
}

int apol_apply_run(struct apol_sink *sink, const struct apol_policy *p,
		   struct apol_apply_result *res, char *err, size_t errcap)
{
	char *snap = NULL;
	char *rb = NULL;
	char se[256] = "";
	int i;

	memset(res, 0, sizeof(*res));
	if (!sink || !sink->snapshot || !sink->add || !sink->readback ||
	    !sink->restore) {
		snprintf(err, errcap, "注入后端不完整（内部错误）");
		return -1;
	}
	snprintf(res->sink, sizeof(res->sink), "%s",
		 sink->name ? sink->name : "unknown");
	if (!p || p->rule_n <= 0) {
		snprintf(err, errcap, "empty_policy|没有可下发的规则");
		return -1;
	}
	if (apol_has_allow_all(p)) {
		snprintf(err, errcap, "allow_all_refused|策略含 allow-all，拒绝"
			 "下发");
		return -1;
	}
	/* 1) 快照（失败即中止：还没有任何改动） */
	if (sink->snapshot(sink->ctx, &snap, se, sizeof(se)) != 0) {
		snprintf(err, errcap, "snapshot_failed|下发前快照失败（未做任何"
			 "改动）：%s", se);
		return -1;
	}
	res->snapshot_bytes = (int)strlen(snap);
	{
		unsigned long long h = 1469598103934665603ULL;
		const unsigned char *q = (const unsigned char *)snap;

		while (*q) {
			h ^= *q++;
			h *= 1099511628211ULL;
		}
		snprintf(res->snapshot_ref, sizeof(res->snapshot_ref),
			 "len=%d fnv64=%016llx", res->snapshot_bytes, h);
	}
	/* 2) 逐条下发 */
	for (i = 0; i < p->rule_n; i++) {
		char uri[200] = "";

		(void)apol_rule_uri(&p->rules[i], uri, sizeof(uri));
		if (sink->add(sink->ctx, &p->rules[i], se, sizeof(se)) != 0) {
			snprintf(res->fail_rule, sizeof(res->fail_rule), "%s",
				 uri);
			snprintf(res->fail_why, sizeof(res->fail_why), "%s", se);
			goto rollback;
		}
		res->rules_applied++;
	}
	/* 3) 读回校验 */
	if (sink->readback(sink->ctx, &rb, se, sizeof(se)) != 0) {
		snprintf(res->fail_why, sizeof(res->fail_why), "读回失败：%s",
			 se);
		goto rollback;
	}
	for (i = 0; i < p->rule_n; i++) {
		char uri[200] = "";

		(void)apol_rule_uri(&p->rules[i], uri, sizeof(uri));
		if (!strstr(rb, uri)) {
			snprintf(res->fail_rule, sizeof(res->fail_rule), "%s",
				 uri);
			snprintf(res->fail_why, sizeof(res->fail_why),
				 "读回校验：未在注入面找到该规则");
			goto rollback;
		}
		res->readback_matched++;
	}
	res->readback_ok = 1;
	free(rb);
	free(snap);
	return 0;

rollback:
	free(rb);
	res->rolled_back = 1;
	{
		char re[256] = "";

		if (sink->restore(sink->ctx, snap, re, sizeof(re)) == 0) {
			res->rollback_ok = 1;
			snprintf(err, errcap, "apply_failed|下发失败并已恢复快照"
				 "（规则 %s：%s）", res->fail_rule,
				 res->fail_why);
		} else {
			snprintf(err, errcap, "rollback_failed|下发失败（规则 "
				 "%s：%s），且快照恢复失败（%s）—— 必须人工"
				 "核对规则表", res->fail_rule, res->fail_why,
				 re);
		}
	}
	free(snap);
	return -1;
}

/* ---- 生产注入后端：procfs-line 节点（当前内核未提供该节点） ----
 *
 * 行协议（本工具定义；内核提供对应节点前不可用）：
 *   path <path_prefix> <op_name> <allow|deny>
 *   label <label_id> <op_name> <allow|deny>
 *   clear
 * 读该节点返回同样的行（读回校验用）。协议不承载 detail/because
 * （内核 detail 字段 64B；可解释性留在 app_policy_generate 的生成物里）。
 */
static int apol_node_write(void *ctx, const char *line, char *err,
			   size_t errcap)
{
	struct apol_node_sink_ctx *c = ctx;
	int fd;
	size_t len = strlen(line);
	ssize_t n;

	fd = open(c->node, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		snprintf(err, errcap, "打开 %s 失败：%s", c->node,
			 strerror(errno));
		return -1;
	}
	n = write(fd, line, len);
	close(fd);
	if (n < 0 || (size_t)n != len) {
		snprintf(err, errcap, "写 %s 失败：%s", c->node,
			 n < 0 ? strerror(errno) : "短写");
		return -1;
	}
	return 0;
}

static int apol_node_snapshot(void *ctx, char **snap, char *err, size_t errcap)
{
	struct apol_node_sink_ctx *c = ctx;
	char *buf = apol_read_file(c->node, 65536, NULL);

	if (!buf) {
		if (errno == ENOENT || errno == ENODEV) {
			*snap = strdup("");
			return *snap ? 0 : -1;
		}
		snprintf(err, errcap, "读 %s 失败：%s", c->node,
			 strerror(errno));
		return -1;
	}
	*snap = buf;
	return 0;
}

static int apol_node_clear(void *ctx, char *err, size_t errcap)
{
	return apol_node_write(ctx, "clear\n", err, errcap);
}

static int apol_node_add(void *ctx, const struct apol_rule *r, char *err,
			 size_t errcap)
{
	char line[320];

	if (r->kind == APOL_KIND_LABEL)
		snprintf(line, sizeof(line), "label %d %s %s\n", r->label_id,
			 apol_op_name(r->op), r->deny ? "deny" : "allow");
	else
		snprintf(line, sizeof(line), "path %s %s %s\n",
			 r->path_prefix, apol_op_name(r->op),
			 r->deny ? "deny" : "allow");
	return apol_node_write(ctx, line, err, errcap);
}

static int apol_node_readback(void *ctx, char **txt, char *err, size_t errcap)
{
	struct apol_node_sink_ctx *c = ctx;
	char *buf = apol_read_file(c->node, 65536, NULL);

	if (!buf) {
		snprintf(err, errcap, "读回 %s 失败：%s", c->node,
			 strerror(errno));
		return -1;
	}
	*txt = buf;
	return 0;
}

static int apol_node_restore(void *ctx, const char *snap, char *err,
			     size_t errcap)
{
	char *copy, *line, *save = NULL;
	int rc = 0;

	if (apol_node_clear(ctx, err, errcap) != 0)
		return -1;
	copy = strdup(snap ? snap : "");
	if (!copy) {
		snprintf(err, errcap, "内存不足（快照恢复）");
		return -1;
	}
	for (line = strtok_r(copy, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		char buf[512];

		if (!line[0])
			continue;
		snprintf(buf, sizeof(buf), "%s\n", line);
		if (apol_node_write(ctx, buf, err, errcap) != 0) {
			rc = -1;
			break;
		}
	}
	free(copy);
	return rc;
}

int apol_sink_node_init(struct apol_sink *sink, struct apol_node_sink_ctx *ctx,
			const char *node)
{
	memset(ctx, 0, sizeof(*ctx));
	snprintf(ctx->node, sizeof(ctx->node), "%s", node ? node : "");
	memset(sink, 0, sizeof(*sink));
	sink->name = "procfs-line-v1";
	sink->ctx = ctx;
	sink->snapshot = apol_node_snapshot;
	sink->clear = apol_node_clear;
	sink->add = apol_node_add;
	sink->readback = apol_node_readback;
	sink->restore = apol_node_restore;
	return 0;
}

/* ======================================================================
 * 9) 执行器：app_policy_generate / app_policy_apply
 * ====================================================================== */

static char *apol_arg_str(const char *json, const char *key)
{
	size_t n = strlen(json);
	const char *v;
	size_t vlen;
	int t;
	char *s;

	if (ai_json_obj_get(json, n, key, &v, &vlen, &t) != 1 ||
	    t != AI_JSON_STR)
		return NULL;
	s = ai_json_strdup_str(v, vlen);
	if (s && !s[0]) {
		free(s);
		return NULL;
	}
	return s;
}

static int apol_arg_bool(const char *json, const char *key, int def)
{
	size_t n = strlen(json);
	const char *v;
	size_t vlen;
	int t;

	if (ai_json_obj_get(json, n, key, &v, &vlen, &t) != 1)
		return def;
	if (t != AI_JSON_BOOL)
		return def;
	return vlen >= 4 && strncmp(v, "true", 4) == 0;
}

/* 字符串数组参数 → 逗号拼接的 JSON 数组原文（喂给 app_profile_*） */
static void apol_argv_json(const char *json, struct apolb *dst)
{
	const char *arr;
	size_t alen;
	int t, i;

	apolb_puts(dst, "[");
	if (ai_json_obj_get(json, strlen(json), "argv", &arr, &alen, &t) != 1 ||
	    t != AI_JSON_ARR) {
		apolb_puts(dst, "]");
		return;
	}
	for (i = 0; i < 16; i++) {
		const char *el;
		size_t elen;
		int et;
		char *s;

		if (ai_json_arr_get(arr, alen, i, &el, &elen, &et) != 1)
			break;
		if (et != AI_JSON_STR)
			continue;
		s = ai_json_strdup_str(el, elen);
		if (!s)
			continue;
		if (i)
			apolb_puts(dst, ",");
		apolb_json_str(dst, s);
		free(s);
	}
	apolb_puts(dst, "]");
}

/* 参数/结果错误：统一 JSON 形状（ok=false + error_code + error） */
static int apol_err_json(char **out, const char *tool, const char *code,
			 const char *detail)
{
	char *esc = ai_json_escape(detail ? detail : "");

	if (asprintf(out,
		     "{\"tool\":\"%s\",\"ok\":false,\"error_code\":\"%s\","
		     "\"error\":\"%s\"}", tool, code, esc ? esc : "") < 0)
		*out = NULL;
	free(esc);
	return AI_ERR_INVALID_ARG;
}

/* 内部跑 app_profile_static / app_profile_dynamic（复用 W81 通道） */
static char *apol_run_profile(const char *tool, const char *args)
{
	struct ai_tool t;
	char *out = NULL;

	memset(&t, 0, sizeof(t));
	t.name = (char *)tool;
	t.channel = TOOL_CH_APPPROFILE;
	t.available = 1;
	if (exec_app_profile_channel(&t, args, &out) != AI_OK || !out) {
		free(out);
		return NULL;
	}
	if (strncmp(out, "ERROR", 5) == 0) {
		free(out);
		return NULL;
	}
	return out;
}

static int apol_tool_generate(const char *args, char **out)
{
	char *app = NULL, *ps = NULL, *pd = NULL;
	char *ps_txt = NULL, *pd_txt = NULL;
	char err[512] = "";
	char perr[512] = "";
	char pserr[512] = "";
	size_t plen = 0;
	struct apol_static_input st;
	int have_st = 0;
	struct ap_event *ev = NULL;
	int ev_n = 0, truncated = 0;
	struct apol_policy p;
	char *json = NULL;
	int rc, run_dynamic;
	const char *chosen_app;

	app = apol_arg_str(args, "app");
	ps = apol_arg_str(args, "profile_static");
	pd = apol_arg_str(args, "profile_dynamic");
	run_dynamic = apol_arg_bool(args, "run_dynamic", 1);

	/* --- 静态画像 --- */
	if (ps) {
		ps_txt = apol_load_value(ps, APOL_TEXT_MAX, &plen, pserr,
					 sizeof(pserr));
		if (!ps_txt) {
			rc = apol_err_json(out, "app_policy_generate",
					   "BAD_STATIC_PROFILE", pserr);
			goto done;
		}
	} else if (app) {
		struct apolb ab;
		char *raw;

		if (apolb_init(&ab, 512) != 0) {
			rc = apol_err_json(out, "app_policy_generate",
					   "OUT_OF_MEMORY", "参数缓冲分配失败");
			goto done;
		}
		apolb_puts(&ab, "{\"path\":");
		apolb_json_str(&ab, app);
		apolb_puts(&ab, ",\"argv\":");
		apol_argv_json(args, &ab);
		apolb_puts(&ab, ",\"format\":\"json\"}");
		raw = ab.oom ? NULL : apol_run_profile("app_profile_static",
						       ab.p);
		apolb_free(&ab);
		if (!raw)
			snprintf(pserr, sizeof(pserr),
				 "内部 app_profile_static 失败（目标不可执行/"
				 "非 ELF 等，详见该工具输出）");
		else
			ps_txt = raw;
	}
	if (ps_txt) {
		if (apol_static_json_parse(ps_txt, &st, pserr,
					   sizeof(pserr)) == 0)
			have_st = 1;
	}
	/* --- 动态画像 --- */
	if (pd) {
		pd_txt = apol_load_value(pd, APOL_TEXT_MAX, &plen, perr,
					 sizeof(perr));
		if (!pd_txt) {
			rc = apol_err_json(out, "app_policy_generate",
					   "BAD_DYNAMIC_PROFILE", perr);
			goto done;
		}
	} else if (app && run_dynamic) {
		struct apolb ab;
		char *raw;

		if (apolb_init(&ab, 512) != 0) {
			rc = apol_err_json(out, "app_policy_generate",
					   "OUT_OF_MEMORY", "参数缓冲分配失败");
			goto done;
		}
		apolb_puts(&ab, "{\"path\":");
		apolb_json_str(&ab, app);
		apolb_puts(&ab, ",\"argv\":");
		apol_argv_json(args, &ab);
		apolb_puts(&ab, ",\"format\":\"json\",\"timeout_s\":10}");
		raw = ab.oom ? NULL : apol_run_profile("app_profile_dynamic",
						       ab.p);
		apolb_free(&ab);
		if (!raw)
			snprintf(perr, sizeof(perr),
				 "内部 app_profile_dynamic 失败（动态画像需要 "
				 "root + aik-sandbox 工作区），已降级：策略只含"
				 "静态事实");
		else
			pd_txt = raw;
	} else if (!pd) {
		snprintf(perr, sizeof(perr),
			 "未提供动态画像且 run_dynamic=false：策略只含静态事实");
	}
	if (pd_txt) {
		ev = calloc(AP_MAX_EVENTS, sizeof(*ev));
		if (!ev) {
			rc = apol_err_json(out, "app_policy_generate",
					   "OUT_OF_MEMORY", "事件表分配失败");
			goto done;
		}
		if (ap_dynamic_json_to_events(pd_txt, ev, AP_MAX_EVENTS, &ev_n,
					      &truncated, err, sizeof(err)) != 0) {
			rc = apol_err_json(out, "app_policy_generate",
					   "BAD_DYNAMIC_PROFILE", err);
			goto done;
		}
	}
	chosen_app = app ? app : (have_st ? st.path : NULL);
	if (!chosen_app) {
		rc = apol_err_json(out, "app_policy_generate", "MISSING",
				   "缺少 app，或 profile_static 里没有 path");
		goto done;
	}
	if (apol_generate(chosen_app, ev, ev_n, have_st ? &st : NULL, &p, err,
			  sizeof(err)) != 0) {
		char code[64] = "GENERATE_FAILED";
		char *bar = strchr(err, '|');
		size_t n;

		if (bar) {
			n = (size_t)(bar - err);
			if (n >= sizeof(code))
				n = sizeof(code) - 1;
			memcpy(code, err, n);
			code[n] = '\0';
			memmove(err, bar + 1, strlen(bar + 1) + 1);
		}
		rc = apol_err_json(out, "app_policy_generate", code, err);
		goto done;
	}
	if (!have_st && pserr[0])
		apol_warn(&p, "静态画像不可用：%s", pserr);
	if (pd_txt && truncated)
		apol_warn(&p, "动态事件超过 %d 条：只分析前 %d 条",
			  AP_MAX_EVENTS, ev_n);
	if (!pd_txt && perr[0])
		apol_degrade(&p, "%s", perr);

	if (apol_policy_render_json(&p, "app_policy_generate", &json) != 0) {
		rc = apol_err_json(out, "app_policy_generate", "OUT_OF_MEMORY",
				   "渲染策略 JSON 失败");
		goto done;
	}
	*out = json;
	json = NULL;
	rc = AI_OK;

done:
	free(app);
	free(ps);
	free(pd);
	free(ps_txt);
	free(pd_txt);
	free(ev);
	free(json);
	return rc;
}

/* 从 "<code>|说明" 里拆出 code（原地） */
static void apol_split_code(char *buf, char *code, size_t codecap)
{
	char *bar = strchr(buf, '|');

	snprintf(code, codecap, "FAILED");
	if (!bar)
		return;
	{
		size_t n = (size_t)(bar - buf);

		if (n >= codecap)
			n = codecap - 1;
		memcpy(code, buf, n);
		code[n] = '\0';
		memmove(buf, bar + 1, strlen(bar + 1) + 1);
	}
}

static int apol_tool_apply(const char *args, char **out)
{
	char *policy_arg = NULL, *policy_txt = NULL;
	char err[512] = "";
	char perr[512] = "";
	size_t plen = 0;
	struct apol_policy p;
	struct apol_lsm_info lsm;
	struct apol_inject_info inj;
	struct apol_sink sink;
	struct apol_node_sink_ctx nctx;
	struct apol_apply_result res;
	int rc, confirm, first;
	struct apolb b;
	char code[64];

	policy_arg = apol_arg_str(args, "policy");
	if (!policy_arg)
		return apol_err_json(out, "app_policy_apply", "MISSING",
				     "缺少 policy（策略 JSON 或 @文件）");
	confirm = apol_arg_bool(args, "confirm_sensitive", 0);
	policy_txt = apol_load_value(policy_arg, APOL_TEXT_MAX, &plen, perr,
				     sizeof(perr));
	if (!policy_txt) {
		rc = apol_err_json(out, "app_policy_apply", "BAD_POLICY_FILE",
				   perr);
		goto done;
	}
	if (apol_policy_parse(policy_txt, &p, err, sizeof(err)) != 0) {
		apol_split_code(err, code, sizeof(code));
		rc = apol_err_json(out, "app_policy_apply", code, err);
		goto done;
	}
	if (apolb_init(&b, 4096) != 0) {
		rc = apol_err_json(out, "app_policy_apply", "OUT_OF_MEMORY",
				   "输出缓冲分配失败");
		goto done;
	}
	apolb_puts(&b, "{\"tool\":\"app_policy_apply\",\"schema\":");
	apolb_json_str(&b, APOL_SCHEMA);
	apolb_puts(&b, ",\"policy\":{\"app_path\":");
	apolb_json_str(&b, p.app_path);
	apolb_puts(&b, ",\"label\":");
	apolb_json_str(&b, p.label);
	apolb_printf(&b, ",\"label_id\":%d,\"rules\":%d,"
		     "\"requires_confirm\":%s}", p.label_id, p.rule_n,
		     p.requires_confirm ? "true" : "false");

	/* 闸 1：危险项确认（纯策略侧，先于人任何内核动作） */
	if (p.requires_confirm && !confirm) {
		apolb_puts(&b, ",\"ok\":false,\"refused\":true,"
			   "\"changed\":false,\"applied\":0,"
			   "\"error_code\":\"requires_confirmation\","
			   "\"error\":");
		apolb_json_str(&b, "策略含敏感路径命中（sensitive=true / "
			     "requires_confirm=true）：必须先人工确认，传 "
			     "confirm_sensitive=true 才继续；本次未做任何改动");
		apolb_puts(&b, "}");
		*out = b.p;
		rc = AI_ERR_GENERIC;
		goto done;
	}
	/* 闸 2：内核是否有 ai LSM（fail-closed，原样报出实际列表） */
	(void)apol_lsm_probe(NULL, &lsm);
	if (lsm.ai_present != 1) {
		apolb_puts(&b, ",\"ok\":false,\"refused\":true,"
			   "\"changed\":false,\"applied\":0,"
			   "\"error_code\":\"no_ai_lsm\",\"error\":");
		if (lsm.ai_present == 0)
			apolb_json_str(&b, "内核未启用 ai LSM：AI LSM 规则面"
				     "不存在，策略无法下发（fail-closed，未做"
				     "任何改动、未写任何规则）");
		else
			apolb_json_str(&b, "无法读取内核 LSM 列表：不能确认 "
				     "ai LSM 是否存在，按 fail-closed 拒绝下发"
				     "（未做任何改动）");
		apolb_puts(&b, ",\"lsm\":{\"source\":");
		apolb_json_str(&b, lsm.source);
		apolb_puts(&b, ",\"raw\":");
		apolb_json_str_or_null(&b, lsm.raw);
		apolb_puts(&b, ",\"actual\":[");
		{
			char tmp[256], *save = NULL, *tok;

			snprintf(tmp, sizeof(tmp), "%s", lsm.list);
			first = 1;
			for (tok = strtok_r(tmp, ",", &save); tok;
			     tok = strtok_r(NULL, ",", &save)) {
				if (!first)
					apolb_puts(&b, ",");
				apolb_json_str(&b, tok);
				first = 0;
			}
		}
		apolb_puts(&b, "],\"ai_present\":");
		apolb_printf(&b, "%s,\"probe_error\":",
			     lsm.ai_present == 1 ? "true" : "false");
		apolb_json_str_or_null(&b, lsm.err);
		apolb_puts(&b, "},\"requires_confirmation\":");
		apolb_printf(&b, "%s", p.requires_confirm ? "true" : "false");
		apolb_puts(&b, ",\"next_steps\":[");
		for (first = 1; first <= 3; first++) {
			const char *s = first == 1 ?
				"内核打开 CONFIG_AIKERNEL_SECURITY 并以 "
				"lsm=...,ai,... 启动（多令牌 lsm= 已在 W80 修好）" :
				first == 2 ?
				"启动后确认 /sys/kernel/security/lsm 里出现 ai" :
				"规则注入面就绪后重跑 app_policy_apply";
			if (first > 1)
				apolb_puts(&b, ",");
			apolb_json_str(&b, s);
		}
		apolb_puts(&b, "]}");
		*out = b.p;
		rc = AI_ERR_GENERIC;
		goto done;
	}
	/* 闸 3：规则注入节点 */
	if (apol_inject_probe(NULL, &inj) != 0) {
		apolb_puts(&b, ",\"ok\":false,\"refused\":true,"
			   "\"changed\":false,\"applied\":0,"
			   "\"error_code\":\"no_rule_injection_interface\","
			   "\"error\":");
		apolb_json_str(&b, "内核有 ai LSM，但没有用户态规则注入节点："
			     "路径/标签规则目前只能由内核内部函数 "
			     "ai_lsm_rule_add_path/_label 添加，无 procfs/"
			     "sysfs/netlink 写口，拒绝伪造成功（未做任何改动）");
		apolb_puts(&b, ",\"lsm\":{\"source\":");
		apolb_json_str(&b, lsm.source);
		apolb_puts(&b, ",\"raw\":");
		apolb_json_str(&b, lsm.raw);
		apolb_puts(&b, ",\"ai_present\":true},\"inject_probe\":");
		apolb_json_str(&b, inj.probes);
		apolb_puts(&b, "}");
		*out = b.p;
		rc = AI_ERR_GENERIC;
		goto done;
	}
	/* 下发：快照 → add → 读回 →（失败）回滚 */
	apol_sink_node_init(&sink, &nctx, inj.path);
	if (apol_apply_run(&sink, &p, &res, err, sizeof(err)) != 0) {
		apol_split_code(err, code, sizeof(code));
		apolb_puts(&b, ",\"ok\":false,\"refused\":false,"
			   "\"error_code\":");
		apolb_json_str(&b, code);
		apolb_puts(&b, ",\"error\":");
		apolb_json_str(&b, err);
		apolb_printf(&b, ",\"applied\":%d,\"rolled_back\":%s,"
			     "\"rollback_ok\":%s,\"sink\":",
			     res.rules_applied,
			     res.rolled_back ? "true" : "false",
			     res.rollback_ok ? "true" : "false");
		apolb_json_str(&b, res.sink);
		apolb_puts(&b, "}");
		*out = b.p;
		rc = AI_ERR_GENERIC;
		goto done;
	}
	apolb_printf(&b, ",\"ok\":true,\"refused\":false,\"changed\":true,"
		     "\"applied\":%d,\"readback_ok\":%s,"
		     "\"readback_matched\":%d,\"sink\":", res.rules_applied,
		     res.readback_ok ? "true" : "false",
		     res.readback_matched);
	apolb_json_str(&b, res.sink);
	apolb_puts(&b, ",\"snapshot\":");
	apolb_json_str_or_null(&b, res.snapshot_ref);
	apolb_puts(&b, ",\"inject_node\":");
	apolb_json_str(&b, inj.path);
	apolb_puts(&b, ",\"degraded\":[");
	apolb_json_str(&b, "行协议不承载 detail/because（内核 detail 字段 "
		     "64B）：可解释性留在 app_policy_generate 的生成物里");
	apolb_puts(&b, "]}");
	*out = b.p;
	rc = AI_OK;

done:
	free(policy_arg);
	free(policy_txt);
	return rc;
}

int exec_app_policy_tool(const char *name, const char *args_json, char **out)
{
	*out = NULL;
	if (!name || !args_json) {
		*out = strdup("ERROR: app_policy 调用参数为空");
		return AI_ERR_INVALID_ARG;
	}
	if (strcmp(name, "app_policy_generate") == 0)
		return apol_tool_generate(args_json, out);
	if (strcmp(name, "app_policy_apply") == 0)
		return apol_tool_apply(args_json, out);
	if (asprintf(out, "ERROR: 未知 app_policy 工具（注册表异常）") < 0)
		*out = NULL;
	return AI_ERR_INVALID_ARG;
}
