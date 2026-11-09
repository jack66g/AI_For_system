// SPDX-License-Identifier: GPL-2.0
/*
 * app_ctl.c - W82 V4.4 应用控制面适配器（TOOL_CH_APPCTL）
 *
 * 设计说明见 app_ctl.h。本文件分五段：
 *   1) 通用工具（有界缓冲、JSON 取参、时间/环形输出、状态目录、审计、
 *      敏感参数打码、程序解析）
 *   2) CLI 执行（setsid + fork + execv，stdout/stderr 分流，超时/取消
 *      SIGKILL 进程组，PR_SET_PDEATHSIG 防孤儿）
 *   3) HTTP 客户端（仅回环，POSIX socket，chunked 解码）
 *   4) probe（CLI/HTTP/dbus/AT-SPI 探测；dbus/AT-SPI 只探测不实现）
 *   5) call/task（声明式任务：顺序执行、断言、失败即停、进度、取消）
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "tools/tool_registry.h"
#include "tools/app_ctl.h"
#include "tools/app_policy.h"

/* ======================================================================
 * 1) 通用工具
 * ====================================================================== */

struct acb {
	char *p;
	size_t len;
	size_t cap;
	int trunc;
};

static void acb_init(struct acb *b, char *buf, size_t cap)
{
	b->p = buf;
	b->len = 0;
	b->cap = cap;
	b->trunc = 0;
	if (cap)
		buf[0] = '\0';
}

static void acb_printf(struct acb *b, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (!b->p || b->trunc || b->len + 1 >= b->cap) {
		b->trunc = 1;
		return;
	}
	va_start(ap, fmt);
	n = vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap);
	va_end(ap);
	if (n < 0) {
		b->trunc = 1;
		return;
	}
	if ((size_t)n >= b->cap - b->len) {
		b->len = b->cap - 1;
		b->trunc = 1;
		return;
	}
	b->len += (size_t)n;
}

static void acb_json_str(struct acb *b, const char *s)
{
	char *e = ai_json_escape(s ? s : "");

	acb_printf(b, "\"%s\"", e ? e : "");
	free(e);
}

static const char *ac_base(const char *p)
{
	const char *s;

	if (!p)
		return "";
	s = strrchr(p, '/');
	return s ? s + 1 : p;
}

static int ac_has_ctl(const char *s)
{
	for (; s && *s; s++) {
		unsigned char c = (unsigned char)*s;

		if (c < 0x20 || c == 0x7f)
			return 1;
	}
	return 0;
}

static long long ac_now_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return (long long)time(NULL) * 1000;
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void ac_timestamp(char *out, size_t cap)
{
	time_t now = time(NULL);
	struct tm tmv;

	localtime_r(&now, &tmv);
	strftime(out, cap, "%Y-%m-%dT%H:%M:%S%z", &tmv);
}

/* ---- JSON 取参（对象 token 可位于父串内部，带长度） ---- */

static char *ac_obj_str(const char *obj, size_t olen, const char *key)
{
	const char *val;
	size_t vlen;
	int type;

	if (!obj || olen == 0)
		return NULL;
	if (ai_json_obj_get(obj, olen, key, &val, &vlen, &type) != 1)
		return NULL;
	if (type != AI_JSON_STR)
		return NULL;
	return ai_json_strdup_str(val, vlen);
}

static long long ac_obj_ll(const char *obj, size_t olen, const char *key,
			   long long def)
{
	const char *val;
	size_t vlen;
	int type;

	if (!obj || olen == 0)
		return def;
	if (ai_json_obj_get(obj, olen, key, &val, &vlen, &type) != 1)
		return def;
	if (type != AI_JSON_NUM)
		return def;
	return ai_json_ll(val, vlen);
}

static int ac_obj_bool(const char *obj, size_t olen, const char *key, int def)
{
	const char *val;
	size_t vlen;
	int type;

	if (!obj || olen == 0)
		return def;
	if (ai_json_obj_get(obj, olen, key, &val, &vlen, &type) != 1)
		return def;
	if (type != AI_JSON_BOOL)
		return def;
	return (vlen > 0 && val[0] == 't') ? 1 : 0;
}

static int ac_obj_has(const char *obj, size_t olen, const char *key)
{
	const char *val;
	size_t vlen;
	int type;

	if (!obj || olen == 0)
		return 0;
	return ai_json_obj_get(obj, olen, key, &val, &vlen, &type) == 1;
}

static int ac_obj_get_token(const char *obj, size_t olen, const char *key,
			    const char **val, size_t *vlen, int *type)
{
	if (!obj || olen == 0)
		return 0;
	return ai_json_obj_get(obj, olen, key, val, vlen, type);
}

/* 字符串数组 → malloc 字符串数组；返回项数，-1 错误 */
static int ac_obj_strarr(const char *obj, size_t olen, const char *key,
			 char **out, int max, char *err, size_t errcap)
{
	const char *arr;
	size_t alen;
	int type, i, n = 0;

	if (!ac_obj_get_token(obj, olen, key, &arr, &alen, &type))
		return 0;
	if (type != AI_JSON_ARR) {
		snprintf(err, errcap, "%s 必须是字符串数组", key);
		return -1;
	}
	for (i = 0; i < max; i++) {
		const char *el;
		size_t elen;
		char *s;

		if (ai_json_arr_get(arr, alen, i, &el, &elen, &type) != 1)
			break;
		if (type != AI_JSON_STR) {
			snprintf(err, errcap, "%s[%d] 不是字符串", key, i);
			return -1;
		}
		s = ai_json_strdup_str(el, elen);
		if (!s) {
			snprintf(err, errcap, "%s[%d] 解码失败", key, i);
			return -1;
		}
		if (strlen(s) > AC_PATH_MAX || ac_has_ctl(s)) {
			snprintf(err, errcap,
				 "%s[%d] 超长（>%d）或含控制字符",
				 key, i, AC_PATH_MAX);
			free(s);
			return -1;
		}
		out[n++] = s;
	}
	{
		const char *el;
		size_t elen;

		if (ai_json_arr_get(arr, alen, n, &el, &elen, &type) == 1) {
			snprintf(err, errcap, "%s 超过上限 %d 项", key, max);
			return -1;
		}
	}
	return n;
}

static int ac_obj_intarr(const char *obj, size_t olen, const char *key,
			 int *out, int max, char *err, size_t errcap)
{
	const char *arr;
	size_t alen;
	int type, i, n = 0;

	if (!ac_obj_get_token(obj, olen, key, &arr, &alen, &type))
		return 0;
	if (type != AI_JSON_ARR) {
		snprintf(err, errcap, "%s 必须是整数数组", key);
		return -1;
	}
	for (i = 0; i < max; i++) {
		const char *el;
		size_t elen;
		long long v;

		if (ai_json_arr_get(arr, alen, i, &el, &elen, &type) != 1)
			break;
		if (type != AI_JSON_NUM) {
			snprintf(err, errcap, "%s[%d] 不是整数", key, i);
			return -1;
		}
		v = ai_json_ll(el, elen);
		if (v < 1 || v > 65535) {
			snprintf(err, errcap, "%s[%d]=%lld 不是合法端口",
				 key, i, v);
			return -1;
		}
		out[n++] = (int)v;
	}
	{
		const char *el;
		size_t elen;

		if (ai_json_arr_get(arr, alen, n, &el, &elen, &type) == 1) {
			snprintf(err, errcap, "%s 超过上限 %d 项", key, max);
			return -1;
		}
	}
	return n;
}

/* ---- 有界环形输出（保留尾部，标记截断） ---- */

struct ac_ring {
	char *buf;
	size_t cap;
	size_t off;
	size_t fill;
	int trunc;
};

static int ac_ring_init(struct ac_ring *r, size_t cap)
{
	memset(r, 0, sizeof(*r));
	r->buf = malloc(cap);
	if (!r->buf)
		return -1;
	r->cap = cap;
	return 0;
}

static void ac_ring_add(struct ac_ring *r, const char *p, size_t n)
{
	size_t i;

	if (!r->buf)
		return;
	if (n >= r->cap) {
		p += n - r->cap;
		n = r->cap;
		r->trunc = 1;
		r->off = 0;
		r->fill = r->cap;
	}
	for (i = 0; i < n; i++) {
		r->buf[r->off] = p[i];
		r->off = (r->off + 1) % r->cap;
		if (r->fill < r->cap)
			r->fill++;
		else
			r->trunc = 1;
	}
}

static char *ac_ring_str(struct ac_ring *r)
{
	char *out;
	size_t start, i;

	if (!r->buf) {
		out = malloc(1);
		if (out)
			out[0] = '\0';
		return out;
	}
	out = malloc(r->fill + 1);
	if (!out)
		return NULL;
	start = (r->fill < r->cap) ? 0 : r->off;
	for (i = 0; i < r->fill; i++)
		out[i] = r->buf[(start + i) % r->cap];
	out[r->fill] = '\0';
	return out;
}

static void ac_ring_free(struct ac_ring *r)
{
	free(r->buf);
	r->buf = NULL;
}

/* ---- 状态目录与审计 ---- */

int ac_state_dir(char *out, size_t cap)
{
	const char *env = getenv("AIKERNEL_APPCTL_DIR");
	struct stat st;
	char path[AC_PATH_MAX];

	if (!out || cap == 0)
		return -1;
	if (env && env[0])
		snprintf(path, sizeof(path), "%s", env);
	else if (geteuid() == 0)
		snprintf(path, sizeof(path), "/run/aik-appctl");
	else
		snprintf(path, sizeof(path),
			 "/tmp/aik-appctl-%u", (unsigned)geteuid());

	if (mkdir(path, 0700) != 0) {
		if (errno != EEXIST)
			return -1;
		if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
			return -1;
	}
	snprintf(out, cap, "%s", path);
	return 0;
}

static void ac_path_join(char *out, size_t cap, const char *dir,
			 const char *name)
{
	size_t dl = strlen(dir);

	if (dl + 2 >= cap)
		dl = cap - sizeof("/.tmp") - 1;
	snprintf(out, cap, "%.*s/%.*s", (int)dl, dir,
		 (int)(cap - dl - 2), name);
}

static void ac_slog(const char *path, const char *fmt, ...)
{
	char line[AC_AUDIT_MAX];
	char ts[64];
	va_list ap;
	int n, fd;

	ac_timestamp(ts, sizeof(ts));
	n = snprintf(line, sizeof(line), "[%s] ", ts);
	if (n < 0 || n >= (int)sizeof(line))
		return;
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

static void ac_audit(const char *dir, const char *fmt, ...)
{
	char path[AC_PATH_MAX];
	char msg[AC_AUDIT_MAX - 256];
	va_list ap;

	ac_path_join(path, sizeof(path), dir, "audit.log");
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	ac_slog(path, "%s", msg);
}

/* ---- 敏感参数识别与打码 ---- */

int ac_key_sensitive(const char *key)
{
	static const char *const needles[] = {
		"password", "passwd", "passphrase", "token", "secret",
		"credential", "api-key", "apikey", "api_key", "access-key",
		"access_key", "accesskey", "private-key", "private_key",
		"authorization", "cookie", "session", NULL
	};
	char norm[128];
	size_t i, n = 0;
	const char *p = key;

	if (!key)
		return 0;
	while (*p == '-')
		p++;
	while (p[n] && p[n] != '=' && p[n] != ':' && n < sizeof(norm) - 1) {
		norm[n] = (char)tolower((unsigned char)p[n]);
		n++;
	}
	norm[n] = '\0';
	if (n == 0)
		return 0;
	if (strcmp(norm, "pass") == 0 || strcmp(norm, "pwd") == 0 ||
	    strcmp(norm, "key") == 0)
		return 1;
	if (n > 4 && strcmp(norm + n - 4, "-key") == 0)
		return 1;
	if (n > 4 && strcmp(norm + n - 4, "_key") == 0)
		return 1;
	for (i = 0; needles[i]; i++) {
		if (strstr(norm, needles[i]))
			return 1;
	}
	return 0;
}

/* 渲染单个参数（可能打码） */
static void ac_mask_arg(struct acb *b, const char *arg, int *mask_next)
{
	const char *eq;

	if (*mask_next) {
		acb_printf(b, "\"***\"");
		*mask_next = 0;
		return;
	}
	eq = strchr(arg, '=');
	if (eq && eq != arg) {
		char key[128];
		size_t klen = (size_t)(eq - arg);

		if (klen >= sizeof(key))
			klen = sizeof(key) - 1;
		memcpy(key, arg, klen);
		key[klen] = '\0';
		if (ac_key_sensitive(key)) {
			/* 保留 --flag= 前缀，值打码 */
			acb_printf(b, "\"%.*s=***\"", (int)klen, arg);
			return;
		}
	}
	if (arg[0] == '-' && !strchr(arg, '=') && ac_key_sensitive(arg)) {
		acb_json_str(b, arg);
		*mask_next = 1;
		return;
	}
	acb_json_str(b, arg);
}

char *ac_mask_argv_json(char *const argv[], int argc)
{
	char *buf = malloc(64 * 1024);
	struct acb b;
	int i, mask_next = 0;

	if (!buf)
		return NULL;
	acb_init(&b, buf, 64 * 1024);
	acb_printf(&b, "[");
	for (i = 0; i < argc; i++) {
		if (i)
			acb_printf(&b, ",");
		ac_mask_arg(&b, argv[i], &mask_next);
	}
	acb_printf(&b, "]");
	if (b.trunc) {
		free(buf);
		return NULL;
	}
	return buf;
}

/* 文本打码：JSON 键值（"password":"x"）与 KEY=value 形态 */
static char *ac_mask_text(const char *in)
{
	size_t cap, n = 0;
	char *out;
	const char *p = in ? in : "";

	cap = strlen(p) * 2 + 64;
	out = malloc(cap);
	if (!out)
		return NULL;
	while (*p) {
		if (n + 8 >= cap) {
			char *nb = realloc(out, cap * 2);

			if (!nb) {
				free(out);
				return NULL;
			}
			out = nb;
			cap *= 2;
		}
		if (*p == '"') {
			const char *k0 = ++p;
			const char *k1 = strchr(k0, '"');
			const char *q;
			size_t klen;

			if (!k1) {
				out[n++] = '"';
				continue;
			}
			klen = (size_t)(k1 - k0);
			if (klen < 120) {
				char key[128];

				memcpy(key, k0, klen);
				key[klen] = '\0';
				q = k1 + 1;
				while (*q == ' ' || *q == '\t')
					q++;
				if (*q == ':' && ac_key_sensitive(key)) {
					const char *v0, *v1;

					out[n++] = '"';
					memcpy(out + n, k0, klen);
					n += klen;
					out[n++] = '"';
					while (*q == ' ' || *q == '\t')
						q++;
					memcpy(out + n, q, (size_t)(q - (k1 + 1)));
					n += (size_t)(q - (k1 + 1));
					out[n++] = ':';
					q++;
					while (*q == ' ' || *q == '\t')
						q++;
					if (*q == '"') {
						v0 = q + 1;
						v1 = v0;
						while (*v1 && *v1 != '"') {
							if (*v1 == '\\' && v1[1])
								v1++;
							v1++;
						}
						(void)v0;
						out[n++] = '"';
						out[n++] = '*';
						out[n++] = '*';
						out[n++] = '*';
						out[n++] = '"';
						p = *v1 ? v1 + 1 : v1;
						continue;
					}
					while (*q && *q != ',' && *q != '}' &&
					       *q != '\n') {
						out[n++] = '*';
						q++;
					}
					p = q;
					continue;
				}
			}
			/* 非敏感键：原样输出引号与键 */
			out[n++] = '"';
			memcpy(out + n, k0, klen);
			n += klen;
			out[n++] = '"';
			p = k1 + 1;
			continue;
		}
		if (isalnum((unsigned char)*p) || *p == '_' || *p == '-') {
			const char *k0 = p;
			const char *k1;
			char key[128];
			size_t klen;

			while (isalnum((unsigned char)*p) || *p == '_' ||
			       *p == '-')
				p++;
			k1 = p;
			klen = (size_t)(k1 - k0);
			if (klen < 120 && *p == '=') {
				memcpy(key, k0, klen);
				key[klen] = '\0';
				if (ac_key_sensitive(key)) {
					memcpy(out + n, k0, klen);
					n += klen;
					out[n++] = '=';
					out[n++] = '*';
					out[n++] = '*';
					out[n++] = '*';
					p++;
					while (*p && *p != '&' && *p != ';' &&
					       *p != ' ' && *p != '\n')
						p++;
					continue;
				}
			}
			memcpy(out + n, k0, klen);
			n += klen;
			continue;
		}
		out[n++] = *p++;
	}
	out[n] = '\0';
	return out;
}

/* ---- 程序解析 ---- */

static int ac_resolve_program(const char *in, char *out, size_t cap,
			      char *err, size_t errcap)
{
	char cand[AC_PATH_MAX];
	const char *path;
	char *copy, *tok, *save = NULL;

	if (!in || !in[0]) {
		snprintf(err, errcap, "缺少程序路径");
		return -1;
	}
	if (strlen(in) >= AC_PATH_MAX || ac_has_ctl(in)) {
		snprintf(err, errcap, "程序路径超长或含控制字符");
		return -1;
	}
	if (strchr(in, '/')) {
		char real[PATH_MAX];

		if (!realpath(in, real)) {
			snprintf(err, errcap, "程序不存在或无法解析: %s (%s)",
				 in, strerror(errno));
			return -1;
		}
		if (access(real, X_OK) != 0) {
			snprintf(err, errcap, "程序不可执行: %.200s (%s)",
				 real, strerror(errno));
			return -1;
		}
		snprintf(out, cap, "%s", real);
		return 0;
	}
	path = getenv("PATH");
	if (!path || !path[0])
		path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:"
		       "/sbin:/bin";
	copy = strdup(path);
	if (!copy) {
		snprintf(err, errcap, "内存不足");
		return -1;
	}
	for (tok = strtok_r(copy, ":", &save); tok;
	     tok = strtok_r(NULL, ":", &save)) {
		char real[PATH_MAX];

		if (!tok[0])
			tok = (char *)".";
		snprintf(cand, sizeof(cand), "%s/%s", tok, in);
		if (access(cand, X_OK) != 0)
			continue;
		if (!realpath(cand, real))
			continue;
		snprintf(out, cap, "%s", real);
		free(copy);
		return 0;
	}
	free(copy);
	snprintf(err, errcap, "PATH 中找不到可执行程序: %s", in);
	return -1;
}

/* ======================================================================
 * 2) CLI 执行
 * ====================================================================== */

struct ac_run {
	int rc;
	int timed_out;
	int canceled;
	int spawn_errno;
	int out_trunc;
	int err_trunc;
	long long duration_ms;
	char *out;
	char *err;
	pid_t pid;
};

static int ac_write_pid_file(const char *path, pid_t pid)
{
	char tmp[64];
	int fd, n;

	if (!path)
		return 0;
	n = snprintf(tmp, sizeof(tmp), "%ld\n", (long)pid);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	(void)!write(fd, tmp, (size_t)n);
	close(fd);
	return 0;
}

static int ac_read_pid_file(const char *path, pid_t *pid)
{
	char buf[64];
	int fd, n;
	char *end;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	errno = 0;
	*pid = (pid_t)strtol(buf, &end, 10);
	if (errno != 0 || end == buf || *pid <= 0)
		return -1;
	return 0;
}

/*
 * 有界执行：stdout/stderr 各自环形缓冲（尾部 ≤ AC_OUT_LIMIT）。
 * 超时或 cancel_file 出现 → SIGKILL 整个进程组（子进程 setsid）。
 * pid_file 非空时，fork 后立即写入子进程 pid（外部取消用），返回前删除。
 */
static int ac_run_cli(char *const argv[], const char *cwd,
		      const char *stdin_data, int timeout_ms,
		      const char *cancel_file, const char *pid_file,
		      struct ac_run *r, char *errbuf, size_t errcap)
{
	int outp[2], errp[2], inp[2] = { -1, -1 };
	pid_t pid;
	int status = 0;
	int outfd = -1, errfd = -1;
	int child_reaped = 0;
	int killed = 0;
	long long start, deadline, kill_at = 0, reaped_at = 0;
	struct ac_ring ro, re;
	int rc = 0;

	memset(r, 0, sizeof(*r));
	r->rc = -1;
	r->pid = -1;
	if (ac_ring_init(&ro, AC_OUT_LIMIT) != 0)
		return -1;
	if (ac_ring_init(&re, AC_OUT_LIMIT) != 0) {
		ac_ring_free(&ro);
		return -1;
	}
	if (pipe2(outp, O_CLOEXEC) != 0 || pipe2(errp, O_CLOEXEC) != 0) {
		snprintf(errbuf, errcap, "pipe2 失败: %s", strerror(errno));
		rc = -1;
		goto out_free;
	}
	if (stdin_data) {
		if (pipe2(inp, O_CLOEXEC) != 0) {
			snprintf(errbuf, errcap, "stdin pipe 失败: %s",
				 strerror(errno));
			close(outp[0]);
			close(outp[1]);
			close(errp[0]);
			close(errp[1]);
			rc = -1;
			goto out_free;
		}
	}
	fflush(stdout);
	fflush(stderr);
	start = ac_now_ms();
	pid = fork();
	if (pid < 0) {
		snprintf(errbuf, errcap, "fork 失败: %s", strerror(errno));
		close(outp[0]);
		close(outp[1]);
		close(errp[0]);
		close(errp[1]);
		if (stdin_data) {
			close(inp[0]);
			close(inp[1]);
		}
		rc = -1;
		goto out_free;
	}
	if (pid == 0) {
		int devnull;

		setsid();
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		if (cwd && chdir(cwd) != 0)
			_exit(126);
		close(outp[0]);
		close(errp[0]);
		dup2(outp[1], STDOUT_FILENO);
		dup2(errp[1], STDERR_FILENO);
		close(outp[1]);
		close(errp[1]);
		if (stdin_data) {
			close(inp[1]);
			dup2(inp[0], STDIN_FILENO);
			close(inp[0]);
		} else {
			devnull = open("/dev/null", O_RDONLY);
			if (devnull >= 0) {
				dup2(devnull, STDIN_FILENO);
				close(devnull);
			}
		}
		execv(argv[0], argv);
		_exit(127);
	}
	r->pid = pid;
	close(outp[1]);
	close(errp[1]);
	outfd = outp[0];
	errfd = errp[0];
	fcntl(outfd, F_SETFL, fcntl(outfd, F_GETFL) | O_NONBLOCK);
	fcntl(errfd, F_SETFL, fcntl(errfd, F_GETFL) | O_NONBLOCK);
	if (stdin_data) {
		size_t left = strlen(stdin_data);
		const char *p = stdin_data;
		struct sigaction oldact, newact;
		int have_old;

		close(inp[0]);
		fcntl(inp[1], F_SETFL, fcntl(inp[1], F_GETFL) | O_NONBLOCK);
		/* 子进程可能不读 stdin 就退出：写已关闭管道会触发
		 * SIGPIPE 杀掉本进程。写入期间临时忽略 SIGPIPE。 */
		memset(&newact, 0, sizeof(newact));
		newact.sa_handler = SIG_IGN;
		sigemptyset(&newact.sa_mask);
		have_old = (sigaction(SIGPIPE, NULL, &oldact) == 0);
		if (have_old)
			sigaction(SIGPIPE, &newact, NULL);
		while (left > 0) {
			ssize_t w = write(inp[1], p, left);

			if (w > 0) {
				p += w;
				left -= (size_t)w;
				continue;
			}
			if (w < 0 && (errno == EAGAIN || errno == EINTR)) {
				struct pollfd pfd = { .fd = inp[1],
						      .events = POLLOUT };

				if (poll(&pfd, 1, 100) < 0 && errno != EINTR)
					break;
				continue;
			}
			break;
		}
		if (have_old)
			sigaction(SIGPIPE, &oldact, NULL);
		close(inp[1]);
	}
	ac_write_pid_file(pid_file, pid);
	deadline = start + (long long)timeout_ms;
	for (;;) {
		struct pollfd pfds[2];
		int nfds = 0;
		long long now = ac_now_ms();
		int timeout = 100;

		if (!child_reaped) {
			pid_t w = waitpid(pid, &status, WNOHANG);

			if (w == pid)
				child_reaped = 1;
		}
		if (child_reaped && outfd < 0 && errfd < 0)
			break;
		if (child_reaped) {
			/* 子进程已退出但孙进程仍持有管道：再等 500ms */
			if (reaped_at == 0)
				reaped_at = now;
			if (now - reaped_at > 500)
				break;
		}
		if (!child_reaped && !killed) {
			if (cancel_file && access(cancel_file, F_OK) == 0) {
				r->canceled = 1;
				killed = 1;
				kill_at = now;
				kill(-pid, SIGKILL);
				kill(pid, SIGKILL);
			} else if (now >= deadline) {
				r->timed_out = 1;
				killed = 1;
				kill_at = now;
				kill(-pid, SIGKILL);
				kill(pid, SIGKILL);
			}
		}
		if (killed && !child_reaped && now - kill_at > 2000) {
			kill(-pid, SIGKILL);
			kill(pid, SIGKILL);
			if (waitpid(pid, &status, 0) == pid)
				child_reaped = 1;
			break;
		}
		if (!child_reaped && now < deadline) {
			long long rem = deadline - now;

			if (rem < timeout)
				timeout = (int)rem;
		}
		if (outfd >= 0) {
			pfds[nfds].fd = outfd;
			pfds[nfds].events = POLLIN;
			nfds++;
		}
		if (errfd >= 0) {
			pfds[nfds].fd = errfd;
			pfds[nfds].events = POLLIN;
			nfds++;
		}
		if (nfds > 0 && poll(pfds, (nfds_t)nfds, timeout) > 0) {
			char chunk[4096];
			int i;

			for (i = 0; i < nfds; i++) {
				if (!(pfds[i].revents &
				      (POLLIN | POLLHUP | POLLERR)))
					continue;
				for (;;) {
					ssize_t n = read(pfds[i].fd, chunk,
							 sizeof(chunk));

					if (n > 0) {
						if (pfds[i].fd == outfd)
							ac_ring_add(&ro, chunk,
								    (size_t)n);
						else
							ac_ring_add(&re, chunk,
								    (size_t)n);
						continue;
					}
					if (n == 0) {
						close(pfds[i].fd);
						if (pfds[i].fd == outfd)
							outfd = -1;
						else
							errfd = -1;
					}
					if (n < 0 && errno == EAGAIN)
						break;
					if (n < 0 && errno == EINTR)
						continue;
					if (n < 0) {
						close(pfds[i].fd);
						if (pfds[i].fd == outfd)
							outfd = -1;
						else
							errfd = -1;
					}
					break;
				}
			}
		} else if (nfds == 0 && !child_reaped) {
			usleep(100 * 1000);
		}
	}
	if (!child_reaped) {
		kill(-pid, SIGKILL);
		kill(pid, SIGKILL);
		while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
			;
		child_reaped = 1;
	}
	if (outfd >= 0)
		close(outfd);
	if (errfd >= 0)
		close(errfd);
	r->duration_ms = ac_now_ms() - start;
	if (cancel_file && access(cancel_file, F_OK) == 0)
		r->canceled = 1;
	if (WIFEXITED(status))
		r->rc = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		r->rc = 128 + WTERMSIG(status);
	else
		r->rc = -1;
	if (r->canceled || r->timed_out)
		r->rc = -1;
	r->out = ac_ring_str(&ro);
	r->err = ac_ring_str(&re);
	r->out_trunc = ro.trunc;
	r->err_trunc = re.trunc;
	if (pid_file)
		unlink(pid_file);
	rc = (r->out && r->err) ? 0 : -1;
	if (rc != 0)
		snprintf(errbuf, errcap, "输出缓冲分配失败");
out_free:
	ac_ring_free(&ro);
	ac_ring_free(&re);
	return rc;
}
/* ======================================================================
 * 3) HTTP 客户端（只回环）
 * ====================================================================== */

struct ac_urlparts {
	char host[256];
	int port;
	char path[1024];
};

/*
 * 解析 http:// URL。只接受 127.0.0.1 / localhost / ::1：
 *   - 拒绝 https、userinfo（@）、畸形 IPv6、外网主机；
 *   - 端口缺省 80；path 缺省 "/"；#fragment 丢弃。
 * 返回 0 成功；-1 拒绝/畸形。
 */
static int ac_parse_http_url(const char *url, struct ac_urlparts *u)
{
	const char *p, *end, *at, *hash;
	size_t alen;

	memset(u, 0, sizeof(*u));
	if (!url || strncasecmp(url, "http://", 7) != 0)
		return -1;
	p = url + 7;
	end = p + strcspn(p, "/?#");
	alen = (size_t)(end - p);
	if (alen == 0 || alen >= 512)
		return -1;
	at = memchr(p, '@', alen);
	if (at)
		return -1;
	u->port = 80;
	if (p[0] == '[') {
		const char *rb = memchr(p, ']', alen);

		if (!rb || rb == p + 1)
			return -1;
		{
			size_t hlen = (size_t)(rb - p - 1);

			if (hlen >= sizeof(u->host))
				return -1;
			memcpy(u->host, p + 1, hlen);
			u->host[hlen] = '\0';
		}
		if (rb + 1 < end) {
			char tmp[16];
			size_t n;
			long v;
			char *e;

			if (rb[1] != ':')
				return -1;
			n = (size_t)(end - rb - 2);
			if (n == 0 || n >= sizeof(tmp))
				return -1;
			memcpy(tmp, rb + 2, n);
			tmp[n] = '\0';
			v = strtol(tmp, &e, 10);
			if (*e || v < 1 || v > 65535)
				return -1;
			u->port = (int)v;
		}
	} else {
		const char *colon = memchr(p, ':', alen);

		if (colon) {
			const char *colon2 = memchr(colon + 1, ':',
						    alen -
						    (size_t)(colon + 1 - p));

			if (colon2) {
				/* 裸 IPv6：只接受 ::1（可带 :port 时也拒绝） */
				if (alen == 3 && memcmp(p, "::1", 3) == 0)
					snprintf(u->host, sizeof(u->host), "::1");
				else
					return -1;
			} else {
				char tmp[16];
				size_t hlen = (size_t)(colon - p);
				size_t n = (size_t)(end - colon - 1);
				long v;
				char *e;

				if (hlen >= sizeof(u->host) || n == 0 ||
				    n >= sizeof(tmp))
					return -1;
				memcpy(u->host, p, hlen);
				u->host[hlen] = '\0';
				memcpy(tmp, colon + 1, n);
				tmp[n] = '\0';
				v = strtol(tmp, &e, 10);
				if (*e || v < 1 || v > 65535)
					return -1;
				u->port = (int)v;
			}
		} else {
			size_t hlen = alen;

			if (hlen >= sizeof(u->host))
				return -1;
			memcpy(u->host, p, hlen);
			u->host[hlen] = '\0';
		}
	}
	if (strcmp(u->host, "127.0.0.1") != 0 &&
	    strcasecmp(u->host, "localhost") != 0 &&
	    strcmp(u->host, "::1") != 0)
		return -1;
	if (*end == '\0' || *end == '#') {
		snprintf(u->path, sizeof(u->path), "/");
	} else if (*end == '?') {
		snprintf(u->path, sizeof(u->path), "/%s", end);
	} else {
		snprintf(u->path, sizeof(u->path), "%s", end);
	}
	hash = strchr(u->path, '#');
	if (hash)
		*(char *)hash = '\0';
	if (u->path[0] == '\0')
		snprintf(u->path, sizeof(u->path), "/");
	return 0;
}

int ac_url_loopback(const char *url)
{
	struct ac_urlparts u;

	if (!url || !url[0])
		return -1;
	return ac_parse_http_url(url, &u) == 0 ? 1 : 0;
}

static int ac_sockaddr_loopback(const struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *in = (const struct sockaddr_in *)sa;

		return ntohl(in->sin_addr.s_addr) == INADDR_LOOPBACK;
	}
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6 =
			(const struct sockaddr_in6 *)sa;

		return IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr);
	}
	return 0;
}

static int ac_tcp_connect(const char *host, int port, int timeout_ms,
			  char *err, size_t errcap)
{
	struct addrinfo hints, *res = NULL, *rp;
	char portstr[16];
	int rc, fd = -1;

	snprintf(portstr, sizeof(portstr), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	rc = getaddrinfo(host, portstr, &hints, &res);
	if (rc != 0) {
		snprintf(err, errcap, "getaddrinfo(%s) 失败: %s",
			 host, gai_strerror(rc));
		return -1;
	}
	for (rp = res; rp; rp = rp->ai_next) {
		int fl;
		struct pollfd pfd;
		int soerr = 0;
		socklen_t slen = sizeof(soerr);

		if (!ac_sockaddr_loopback(rp->ai_addr))
			continue;	/* 防御：只连回环地址 */
		fd = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC,
			    rp->ai_protocol);
		if (fd < 0)
			continue;
		fl = fcntl(fd, F_GETFL, 0);
		if (fl >= 0)
			fcntl(fd, F_SETFL, fl | O_NONBLOCK);
		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		if (errno != EINPROGRESS) {
			close(fd);
			fd = -1;
			continue;
		}
		pfd.fd = fd;
		pfd.events = POLLOUT;
		rc = poll(&pfd, 1, timeout_ms);
		if (rc <= 0 ||
		    getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) != 0 ||
		    soerr != 0) {
			if (err)
				snprintf(err, errcap, "connect %s:%d 失败: %s",
					 host, port,
					 rc <= 0 ? "timeout" :
					 strerror(soerr ? soerr : errno));
			close(fd);
			fd = -1;
			continue;
		}
		break;
	}
	freeaddrinfo(res);
	if (fd < 0 && err && err[0] == '\0')
		snprintf(err, errcap, "connect %s:%d 失败", host, port);
	return fd;
}

static int ac_send_all(int fd, const char *buf, size_t len, int timeout_ms)
{
	size_t off = 0;
	long long deadline = ac_now_ms() + timeout_ms;

	while (off < len) {
		ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
		struct pollfd pfd;

		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && errno != EAGAIN && errno != EINTR)
			return -1;
		if (ac_now_ms() >= deadline)
			return -1;
		pfd.fd = fd;
		pfd.events = POLLOUT;
		if (poll(&pfd, 1, 100) < 0 && errno != EINTR)
			return -1;
	}
	return 0;
}

static int ac_read_all(int fd, char **out, size_t *outlen, int timeout_ms,
		       size_t max, char *err, size_t errcap)
{
	size_t cap = 8192, len = 0;
	char *buf = malloc(cap + 1);
	long long deadline = ac_now_ms() + timeout_ms;

	if (!buf)
		return -1;
	for (;;) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		ssize_t n;
		long long now = ac_now_ms();
		int wait;

		if (now >= deadline) {
			if (len == 0) {
				snprintf(err, errcap, "读取响应超时");
				free(buf);
				return -1;
			}
			break;
		}
		wait = (int)(deadline - now);
		if (wait > 200)
			wait = 200;
		if (poll(&pfd, 1, wait) < 0) {
			if (errno == EINTR)
				continue;
			snprintf(err, errcap, "poll 失败: %s", strerror(errno));
			free(buf);
			return -1;
		}
		if (!(pfd.revents & (POLLIN | POLLHUP | POLLERR)))
			continue;
		if (len == cap) {
			char *nb;

			if (cap >= max) {
				snprintf(err, errcap,
					 "响应超过上限 %zu 字节", max);
				free(buf);
				return -1;
			}
			cap *= 2;
			if (cap > max)
				cap = max;
			nb = realloc(buf, cap + 1);
			if (!nb) {
				free(buf);
				return -1;
			}
			buf = nb;
		}
		n = recv(fd, buf + len, cap - len, 0);
		if (n > 0) {
			len += (size_t)n;
			continue;
		}
		if (n == 0)
			break;
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			continue;
		snprintf(err, errcap, "recv 失败: %s", strerror(errno));
		free(buf);
		return -1;
	}
	buf[len] = '\0';
	*out = buf;
	*outlen = len;
	return 0;
}

/* chunked 解码；返回 malloc body（可为空串），失败 NULL */
static char *ac_dechunk(const char *body, size_t len, size_t *outlen)
{
	char *out = malloc(len + 1);
	size_t o = 0, p = 0;

	if (!out)
		return NULL;
	while (p < len) {
		size_t line_end = p, sz;
		char *endp;
		unsigned long v;

		while (line_end + 1 < len &&
		       !(body[line_end] == '\r' && body[line_end + 1] == '\n'))
			line_end++;
		if (line_end + 1 >= len)
			break;
		{
			char tmp[32];
			size_t n = line_end - p;

			if (n >= sizeof(tmp))
				n = sizeof(tmp) - 1;
			memcpy(tmp, body + p, n);
			tmp[n] = '\0';
			v = strtoul(tmp, &endp, 16);
			if (endp == tmp)
				break;
		}
		p = line_end + 2;
		if (v == 0)
			break;
		sz = (size_t)v;
		if (p + sz > len)
			sz = len - p;
		memcpy(out + o, body + p, sz);
		o += sz;
		p += sz;
		if (p + 1 < len && body[p] == '\r' && body[p + 1] == '\n')
			p += 2;
	}
	out[o] = '\0';
	*outlen = o;
	return out;
}

struct ac_http_res {
	int status;
	int rc;
	long long duration_ms;
	char *body;
	size_t body_len;
	int body_trunc;
	char *error;
};

static void ac_http_res_free(struct ac_http_res *r)
{
	free(r->body);
	free(r->error);
	memset(r, 0, sizeof(*r));
}

static int ac_http_do(const char *method, const char *url, const char *body,
		      const char *content_type, int timeout_ms,
		      struct ac_http_res *r, char *errbuf, size_t errcap)
{
	struct ac_urlparts u;
	char *req = NULL;
	char *raw = NULL;
	size_t rawlen = 0, reqlen;
	int fd = -1, ret = -1;
	long long start = ac_now_ms();
	const char *ct = content_type;
	size_t blen = body ? strlen(body) : 0;

	memset(r, 0, sizeof(*r));
	if (ac_parse_http_url(url, &u) != 0) {
		snprintf(errbuf, errcap,
			 "URL 仅允许 http://127.0.0.1|localhost|::1（拒绝 "
			 "https/外网/畸形地址）");
		r->error = strdup(errbuf);
		r->rc = -1;
		return -1;
	}
	if (!ct || !ct[0])
		ct = blen ? "application/json" : NULL;
	fd = ac_tcp_connect(u.host, u.port, timeout_ms, errbuf, errcap);
	if (fd < 0) {
		r->error = strdup(errbuf);
		r->rc = -1;
		return -1;
	}
	{
		char hosthdr[320];
		const char *verb = method && method[0] ? method : "GET";
		char *tmpl;

		if (strchr(u.host, ':'))
			snprintf(hosthdr, sizeof(hosthdr), "[%s]:%d",
				 u.host, u.port);
		else
			snprintf(hosthdr, sizeof(hosthdr), "%s:%d",
				 u.host, u.port);
		if (asprintf(&tmpl,
			     "%s %s HTTP/1.1\r\n"
			     "Host: %s\r\n"
			     "User-Agent: aik-appctl/1\r\n"
			     "Accept: */*\r\n"
			     "Connection: close\r\n"
			     "%s%s%s"
			     "Content-Length: %zu\r\n"
			     "\r\n",
			     verb, u.path, hosthdr,
			     ct ? "Content-Type: " : "", ct ? ct : "",
			     ct ? "\r\n" : "", blen) < 0) {
			snprintf(errbuf, errcap, "内存不足");
			close(fd);
			r->error = strdup(errbuf);
			return -1;
		}
		req = tmpl;
		reqlen = strlen(req);
	}
	if (ac_send_all(fd, req, reqlen, timeout_ms) != 0) {
		snprintf(errbuf, errcap, "发送请求失败: %s", strerror(errno));
		r->error = strdup(errbuf);
		goto out;
	}
	if (blen && ac_send_all(fd, body, blen, timeout_ms) != 0) {
		snprintf(errbuf, errcap, "发送请求体失败: %s",
			 strerror(errno));
		r->error = strdup(errbuf);
		goto out;
	}
	if (ac_read_all(fd, &raw, &rawlen, timeout_ms,
			AC_HTTP_BODY_LIMIT + 256 * 1024, errbuf, errcap) != 0) {
		r->error = strdup(errbuf);
		goto out;
	}
	{
		char *hdr_end = NULL;
		char *line, *save = NULL;
		char *copy;
		long long clen = -1;
		int chunked = 0;

		if (strncmp(raw, "HTTP/", 5) != 0) {
			snprintf(errbuf, errcap, "非 HTTP 响应");
			r->error = strdup(errbuf);
			goto out;
		}
		{
			char *sp = strchr(raw, ' ');

			if (!sp) {
				snprintf(errbuf, errcap, "HTTP 状态行畸形");
				r->error = strdup(errbuf);
				goto out;
			}
			r->status = atoi(sp + 1);
		}
		hdr_end = strstr(raw, "\r\n\r\n");
		if (!hdr_end) {
			snprintf(errbuf, errcap, "HTTP 响应缺头部终止符");
			r->error = strdup(errbuf);
			goto out;
		}
		copy = strndup(raw, (size_t)(hdr_end - raw));
		if (!copy) {
			snprintf(errbuf, errcap, "内存不足");
			goto out;
		}
		for (line = strtok_r(copy, "\r\n", &save); line;
		     line = strtok_r(NULL, "\r\n", &save)) {
			if (strncasecmp(line, "Content-Length:", 15) == 0)
				clen = atoll(line + 15);
			else if (strncasecmp(line, "Transfer-Encoding:", 18) == 0 &&
				 strcasestr(line + 18, "chunked"))
				chunked = 1;
		}
		free(copy);
		{
			char *b = hdr_end + 4;
			size_t avail = rawlen - (size_t)(b - raw);

			if (chunked) {
				size_t dlen = 0;
				char *dec = ac_dechunk(b, avail, &dlen);

				if (!dec) {
					snprintf(errbuf, errcap, "chunked 解码失败");
					goto out;
				}
				r->body = dec;
				r->body_len = dlen;
			} else {
				size_t n = avail;

				if (clen >= 0 && (size_t)clen < n)
					n = (size_t)clen;
				r->body = malloc(n + 1);
				if (!r->body) {
					snprintf(errbuf, errcap, "内存不足");
					goto out;
				}
				memcpy(r->body, b, n);
				r->body[n] = '\0';
				r->body_len = n;
				if (clen < 0 && avail == AC_HTTP_BODY_LIMIT +
				    256 * 1024)
					r->body_trunc = 1;
			}
		}
	}
	r->rc = (r->status >= 200 && r->status < 400) ? 0 : 1;
	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	free(req);
	free(raw);
	r->duration_ms = ac_now_ms() - start;
	return ret;
}

/* ======================================================================
 * 4) probe（CLI / HTTP / dbus / AT-SPI）
 * ====================================================================== */

static void ac_excerpt(char *out, size_t cap, const char *in, size_t max)
{
	size_t o = 0;

	if (!cap)
		return;
	out[0] = '\0';
	if (!in)
		return;
	for (; *in && o + 1 < cap && o < max; in++) {
		unsigned char c = (unsigned char)*in;

		if (c == '\r' || c == '\n' || c == '\t')
			c = ' ';
		if (c < 0x20 || c == 0x7f)
			continue;
		out[o++] = (char)c;
	}
	out[o] = '\0';
}

static int ac_lookup_dbus_send(char *out, size_t cap)
{
	char err[256];

	return ac_resolve_program("dbus-send", out, cap, err, sizeof(err)) == 0;
}

static int ac_dbus_bus_present(char *addr, size_t cap)
{
	const char *env = getenv("DBUS_SESSION_BUS_ADDRESS");
	const char *xdg = getenv("XDG_RUNTIME_DIR");
	struct stat st;
	char path[AC_PATH_MAX];

	addr[0] = '\0';
	if (env && env[0]) {
		snprintf(addr, cap, "%s", env);
		return 1;
	}
	if (xdg && xdg[0]) {
		snprintf(path, sizeof(path), "%s/bus", xdg);
		if (stat(path, &st) == 0 && S_ISSOCK(st.st_mode)) {
			snprintf(addr, cap, "unix:path=%s", path);
			return 1;
		}
	}
	snprintf(path, sizeof(path), "/run/user/%u/bus", (unsigned)geteuid());
	if (stat(path, &st) == 0 && S_ISSOCK(st.st_mode)) {
		snprintf(addr, cap, "unix:path=%s", path);
		return 1;
	}
	return 0;
}

/* 查询 D-Bus 名字归属：owner=1 有主，0 无主，-1 无法查询 */
static int ac_dbus_name_owner(const char *name, int *owner, int timeout_s,
			      char *detail, size_t detailcap)
{
	char dbus_send[AC_PATH_MAX];
	char *av[9];
	char qname[300];
	struct ac_run r;
	char errbuf[256];
	int ok;

	*owner = -1;
	detail[0] = '\0';
	if (!name || !name[0]) {
		snprintf(detail, detailcap, "未提供 dbus_name");
		return -1;
	}
	if (!ac_lookup_dbus_send(dbus_send, sizeof(dbus_send))) {
		snprintf(detail, detailcap, "系统无 dbus-send，无法查询名字");
		return -1;
	}
	snprintf(qname, sizeof(qname), "string:%s", name);
	av[0] = dbus_send;
	av[1] = (char *)"--session";
	av[2] = (char *)"--print-reply";
	av[3] = (char *)"--reply-timeout=1500";
	av[4] = (char *)"--dest=org.freedesktop.DBus";
	av[5] = (char *)"/org/freedesktop/DBus";
	av[6] = (char *)"org.freedesktop.DBus.NameHasOwner";
	av[7] = qname;
	av[8] = NULL;
	ok = ac_run_cli(av, NULL, NULL, timeout_s * 1000, NULL, NULL, &r,
			errbuf, sizeof(errbuf));
	if (ok != 0) {
		snprintf(detail, detailcap, "dbus-send 启动失败: %s", errbuf);
		return -1;
	}
	{
		const char *all = r.out ? r.out : "";
		const char *e = r.err ? r.err : "";

		if (strstr(all, "boolean true")) {
			*owner = 1;
			snprintf(detail, detailcap, "NameHasOwner(%s)=true",
				 name);
		} else if (strstr(all, "boolean false")) {
			*owner = 0;
			snprintf(detail, detailcap, "NameHasOwner(%s)=false",
				 name);
		} else {
			snprintf(detail, detailcap,
				 "dbus-send rc=%d 无法判定（stderr: %.120s）",
				 r.rc, e);
		}
	}
	free(r.out);
	free(r.err);
	return *owner < 0 ? -1 : 0;
}

struct ac_http_ep {
	int used;
	char host[64];
	int port;
	char path[512];
	int reachable;
	int status;
	long long duration_ms;
	char error[160];
	char excerpt[240];
	size_t body_bytes;
};

static int ac_probe_http_endpoint(struct ac_http_ep *ep, int timeout_ms)
{
	char url[AC_PATH_MAX];
	char errbuf[256];
	struct ac_http_res res;

	if (strchr(ep->host, ':'))
		snprintf(url, sizeof(url), "http://[%s]:%d%s",
			 ep->host, ep->port, ep->path);
	else
		snprintf(url, sizeof(url), "http://%s:%d%s",
			 ep->host, ep->port, ep->path);
	memset(&res, 0, sizeof(res));
	ep->reachable = 0;
	ep->error[0] = '\0';
	ep->excerpt[0] = '\0';
	ep->status = 0;
	ep->body_bytes = 0;
	if (ac_http_do("GET", url, NULL, NULL, timeout_ms, &res,
		       errbuf, sizeof(errbuf)) != 0) {
		snprintf(ep->error, sizeof(ep->error), "%s",
			 res.error ? res.error : errbuf);
		ep->duration_ms = res.duration_ms;
		ac_http_res_free(&res);
		return -1;
	}
	ep->reachable = 1;
	ep->status = res.status;
	ep->duration_ms = res.duration_ms;
	ep->body_bytes = res.body_len;
	ac_excerpt(ep->excerpt, sizeof(ep->excerpt), res.body, 180);
	ac_http_res_free(&res);
	return 0;
}
/* ======================================================================
 * 5) call / task
 * ====================================================================== */

struct ac_call_spec {
	char backend[8];
	char *program;
	char *argv[AC_MAX_ARGV];
	int argc;
	char *cwd;
	char *stdin_data;
	char method[16];
	char *url;
	char *body;
	char *content_type;
	int timeout_s;
};

static void ac_call_spec_free(struct ac_call_spec *c)
{
	int i;

	free(c->program);
	for (i = 0; i < c->argc; i++)
		free(c->argv[i]);
	free(c->cwd);
	free(c->stdin_data);
	free(c->url);
	free(c->body);
	free(c->content_type);
	memset(c, 0, sizeof(*c));
}

static int ac_dir_ok(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int ac_make_dir0700(const char *path)
{
	struct stat st;

	if (mkdir(path, 0700) == 0)
		return 0;
	if (errno != EEXIST)
		return -1;
	return (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) ? 0 : -1;
}

static int ac_work_dir(const char *state, char *out, size_t cap)
{
	ac_path_join(out, cap, state, "work");
	return ac_make_dir0700(out);
}

static int ac_task_dir(const char *state, const char *task_id,
		       char *out, size_t cap)
{
	char tasks[AC_PATH_MAX];

	ac_path_join(tasks, sizeof(tasks), state, "tasks");
	if (ac_make_dir0700(tasks) != 0)
		return -1;
	ac_path_join(out, cap, tasks, task_id);
	return ac_make_dir0700(out);
}

static int ac_call_spec_parse(const char *obj, size_t olen,
			      const char *inherit_cwd, int require_backend,
			      struct ac_call_spec *c, char *err, size_t errcap)
{
	char *s;
	int n;

	memset(c, 0, sizeof(*c));
	c->timeout_s = 30;

	s = ac_obj_str(obj, olen, "backend");
	if (!s && !require_backend) {
		if (ac_obj_has(obj, olen, "program"))
			s = strdup("cli");
		else if (ac_obj_has(obj, olen, "url"))
			s = strdup("http");
	}
	if (!s) {
		snprintf(err, errcap, "缺少 backend（只接受 cli|http）");
		return -1;
	}
	if (strcmp(s, "cli") != 0 && strcmp(s, "http") != 0) {
		snprintf(err, errcap, "非法 backend='%s'（只接受 cli|http）", s);
		free(s);
		return -1;
	}
	snprintf(c->backend, sizeof(c->backend), "%s", s);
	free(s);

	c->program = ac_obj_str(obj, olen, "program");
	n = ac_obj_strarr(obj, olen, "argv", c->argv, AC_MAX_ARGV, err, errcap);
	if (n < 0)
		goto fail;
	c->argc = n;

	c->cwd = ac_obj_str(obj, olen, "cwd");
	if (c->cwd && c->cwd[0] != '/') {
		char joined[AC_PATH_MAX];

		snprintf(joined, sizeof(joined), "%s/%s",
			 inherit_cwd ? inherit_cwd : ".", c->cwd);
		free(c->cwd);
		c->cwd = strdup(joined);
	}
	if (!c->cwd)
		c->cwd = strdup(inherit_cwd ? inherit_cwd : ".");
	if (!c->cwd || !ac_dir_ok(c->cwd)) {
		snprintf(err, errcap, "cwd 不存在或不是目录: %s",
			 c->cwd ? c->cwd : "(空)");
		goto fail;
	}

	c->stdin_data = ac_obj_str(obj, olen, "stdin");
	if (c->stdin_data && strlen(c->stdin_data) > 60000) {
		snprintf(err, errcap, "stdin 超过 60000 字节上限");
		goto fail;
	}
	c->url = ac_obj_str(obj, olen, "url");
	c->body = ac_obj_str(obj, olen, "body");
	c->content_type = ac_obj_str(obj, olen, "content_type");
	s = ac_obj_str(obj, olen, "method");
	if (s && s[0]) {
		size_t i;

		if (strlen(s) >= sizeof(c->method)) {
			snprintf(err, errcap, "method 超长");
			free(s);
			goto fail;
		}
		for (i = 0; s[i]; i++)
			c->method[i] = (char)toupper((unsigned char)s[i]);
		c->method[i] = '\0';
	} else {
		snprintf(c->method, sizeof(c->method), "GET");
	}
	free(s);
	{
		size_t i;

		for (i = 0; c->method[i]; i++) {
			if (!isupper((unsigned char)c->method[i])) {
				snprintf(err, errcap,
					 "非法 method='%s'（只接受大写字母）",
					 c->method);
				goto fail;
			}
		}
	}
	c->timeout_s = (int)ac_obj_ll(obj, olen, "timeout_s", 30);
	if (c->timeout_s < 1 || c->timeout_s > 600) {
		snprintf(err, errcap, "timeout_s 必须在 1..600");
		goto fail;
	}

	if (strcmp(c->backend, "cli") == 0) {
		if (!c->program || !c->program[0]) {
			snprintf(err, errcap, "backend=cli 需要 program");
			goto fail;
		}
	} else {
		if (!c->url || !c->url[0]) {
			snprintf(err, errcap, "backend=http 需要 url");
			goto fail;
		}
		if (ac_url_loopback(c->url) != 1) {
			snprintf(err, errcap,
				 "url 仅允许 http://127.0.0.1|localhost|::1");
			goto fail;
		}
	}
	return 0;
fail:
	ac_call_spec_free(c);
	return -1;
}

struct ac_call_res {
	char backend[8];
	char target[AC_PATH_MAX];
	char *argv_json;
	char *cwd;
	int rc;
	int timed_out;
	int canceled;
	int ok;
	int spawn_errno;
	long long duration_ms;
	char *out;
	char *err;
	int out_trunc;
	int err_trunc;
	int status_code;
	char *body;
	size_t body_len;
	int body_trunc;
	char *error;
};

static void ac_call_res_free(struct ac_call_res *r)
{
	free(r->argv_json);
	free(r->cwd);
	free(r->out);
	free(r->err);
	free(r->body);
	free(r->error);
	memset(r, 0, sizeof(*r));
}

static int ac_do_call(const struct ac_call_spec *c, const char *cancel_file,
		      const char *pid_file, struct ac_call_res *r,
		      char *errbuf, size_t errcap)
{
	memset(r, 0, sizeof(*r));
	snprintf(r->backend, sizeof(r->backend), "%s", c->backend);
	r->cwd = strdup(c->cwd ? c->cwd : ".");
	if (strcmp(c->backend, "cli") == 0) {
		char resolved[AC_PATH_MAX];
		char *av[AC_MAX_ARGV + 2];
		struct ac_run run;
		int i;

		if (ac_resolve_program(c->program, resolved, sizeof(resolved),
				       errbuf, errcap) != 0) {
			r->rc = -1;
			r->error = strdup(errbuf);
			r->spawn_errno = errno;
			return 0;
		}
		snprintf(r->target, sizeof(r->target), "%s", resolved);
		av[0] = resolved;
		for (i = 0; i < c->argc; i++)
			av[i + 1] = c->argv[i];
		av[c->argc + 1] = NULL;
		r->argv_json = ac_mask_argv_json(c->argv, c->argc);
		if (ac_run_cli(av, c->cwd, c->stdin_data, c->timeout_s * 1000,
			       cancel_file, pid_file, &run, errbuf,
			       errcap) != 0) {
			r->rc = -1;
			r->error = strdup(errbuf);
			return 0;
		}
		r->rc = run.rc;
		r->timed_out = run.timed_out;
		r->canceled = run.canceled;
		r->duration_ms = run.duration_ms;
		r->out = run.out;
		r->err = run.err;
		r->out_trunc = run.out_trunc;
		r->err_trunc = run.err_trunc;
		r->ok = (r->rc == 0 && !r->timed_out && !r->canceled);
		return 0;
	}
	if (strcmp(c->backend, "http") == 0) {
		struct ac_http_res hr;

		snprintf(r->target, sizeof(r->target), "%s %s",
			 c->method, c->url);
		memset(&hr, 0, sizeof(hr));
		if (ac_http_do(c->method, c->url, c->body, c->content_type,
			       c->timeout_s * 1000, &hr, errbuf,
			       errcap) != 0) {
			r->rc = hr.rc ? hr.rc : -1;
			r->status_code = hr.status;
			r->duration_ms = hr.duration_ms;
			r->error = hr.error ? hr.error : strdup(errbuf);
			hr.error = NULL;
			ac_http_res_free(&hr);
			r->ok = 0;
			return 0;
		}
		r->rc = hr.rc;
		r->status_code = hr.status;
		r->duration_ms = hr.duration_ms;
		r->body = hr.body;
		r->body_len = hr.body_len;
		r->body_trunc = hr.body_trunc;
		hr.body = NULL;
		ac_http_res_free(&hr);
		r->ok = (r->rc == 0);
		return 0;
	}
	snprintf(errbuf, errcap, "未知 backend");
	r->rc = -1;
	r->error = strdup(errbuf);
	return -1;
}

static void acb_json_str_cap(struct acb *b, const char *s, size_t cap)
{
	size_t len = s ? strlen(s) : 0;
	char *tmp;
	size_t fl;

	if (len <= cap) {
		acb_json_str(b, s ? s : "");
		return;
	}
	tmp = strndup(s, cap);
	if (!tmp) {
		acb_json_str(b, "[truncated]");
		return;
	}
	fl = ai_json_utf8_floor(tmp, strlen(tmp));
	tmp[fl] = '\0';
	acb_json_str(b, tmp);
	free(tmp);
}

static void ac_render_call_fields(struct acb *b, const struct ac_call_res *r,
				  size_t stream_cap, int with_streams)
{
	acb_printf(b, "\"backend\":");
	acb_json_str(b, r->backend);
	acb_printf(b, ",\"target\":");
	acb_json_str(b, r->target);
	if (r->argv_json)
		acb_printf(b, ",\"argv\":%s", r->argv_json);
	if (r->cwd) {
		acb_printf(b, ",\"cwd\":");
		acb_json_str(b, r->cwd);
	}
	acb_printf(b, ",\"rc\":%d,\"timed_out\":%s,\"canceled\":%s,"
		   "\"duration_ms\":%lld",
		   r->rc, r->timed_out ? "true" : "false",
		   r->canceled ? "true" : "false", r->duration_ms);
	if (r->status_code)
		acb_printf(b, ",\"status_code\":%d", r->status_code);
	if (r->error) {
		acb_printf(b, ",\"error\":");
		acb_json_str(b, r->error);
	}
	if (!with_streams)
		return;
	if (strcmp(r->backend, "http") == 0) {
		acb_printf(b, ",\"body_bytes\":%zu,\"body_truncated\":%s,"
			   "\"body\":",
			   r->body_len, r->body_trunc ? "true" : "false");
		acb_json_str_cap(b, r->body ? r->body : "", stream_cap);
		return;
	}
	acb_printf(b, ",\"stdout_bytes\":%zu,\"stdout_truncated\":%s,"
		   "\"stdout\":",
		   r->out ? strlen(r->out) : 0,
		   r->out_trunc ? "true" : "false");
	acb_json_str_cap(b, r->out ? r->out : "", stream_cap);
	acb_printf(b, ",\"stderr_bytes\":%zu,\"stderr_truncated\":%s,"
		   "\"stderr\":",
		   r->err ? strlen(r->err) : 0,
		   r->err_trunc ? "true" : "false");
	acb_json_str_cap(b, r->err ? r->err : "", stream_cap);
}

static int ac_param_error(char **out, const char *tool, const char *code,
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

/* ---- 断言 ---- */

#define AC_MAX_ASSERT 32
#define AC_ASSERT_STR 192
#define AC_ASSERT_DETAIL 256

struct ac_assertion {
	int ok;
	char expr[AC_ASSERT_STR];
	char detail[AC_ASSERT_DETAIL];
};

static void ac_assert_add(struct ac_assertion *arr, int *n, int max,
			  int ok, const char *expr, const char *fmt, ...)
{
	char detail[AC_ASSERT_DETAIL];
	va_list ap;

	if (*n >= max)
		return;
	va_start(ap, fmt);
	vsnprintf(detail, sizeof(detail), fmt, ap);
	va_end(ap);
	arr[*n].ok = ok;
	snprintf(arr[*n].expr, sizeof(arr[*n].expr), "%s", expr);
	snprintf(arr[*n].detail, sizeof(arr[*n].detail), "%s", detail);
	(*n)++;
}

static int ac_regex_ok(const char *pat, const char *hay, char *why,
		       size_t whycap)
{
	regex_t re;
	int rc;

	rc = regcomp(&re, pat, REG_EXTENDED | REG_NOSUB);
	if (rc != 0) {
		regerror(rc, &re, why, whycap);
		return -1;
	}
	rc = regexec(&re, hay ? hay : "", 0, NULL, 0);
	regfree(&re);
	return rc == 0 ? 1 : 0;
}

static int ac_assert_contains_list(const char *val, size_t vlen, int type,
				   const char *hay, int want,
				   struct ac_assertion *arr, int *n,
				   int max, const char *label)
{
	int i, count = 0;

	if (type == AI_JSON_STR) {
		char *s = ai_json_strdup_str(val, vlen);
		int ok;

		if (!s)
			return -1;
		ok = (strstr(hay ? hay : "", s) != NULL) == want;
		ac_assert_add(arr, n, max, ok, label, "%s%s",
			      want ? (ok ? "找到: " : "未找到: ") :
				     (ok ? "未出现: " : "意外出现: "),
			      s);
		free(s);
		return 0;
	}
	if (type != AI_JSON_ARR)
		return -1;
	for (i = 0;; i++) {
		const char *el;
		size_t elen;
		int et;
		char *s;
		int ok;

		if (ai_json_arr_get(val, vlen, i, &el, &elen, &et) != 1)
			break;
		if (et != AI_JSON_STR)
			return -1;
		s = ai_json_strdup_str(el, elen);
		if (!s)
			return -1;
		ok = (strstr(hay ? hay : "", s) != NULL) == want;
		{
			char expr[AC_ASSERT_STR];

			snprintf(expr, sizeof(expr), "%s(\"%.120s\")",
				 label, s);
			ac_assert_add(arr, n, max, ok, expr, "%s%s",
				      want ? (ok ? "找到: " : "未找到: ") :
					     (ok ? "未出现: " : "意外出现: "),
				      s);
		}
		free(s);
		count++;
	}
	return count == 0 ? -1 : 0;
}

static int ac_join_path(const char *cwd, const char *p, char *out,
			size_t cap)
{
	if (!p || !p[0])
		return -1;
	if (p[0] == '/')
		snprintf(out, cap, "%s", p);
	else
		snprintf(out, cap, "%s/%s", cwd && cwd[0] ? cwd : ".", p);
	return 0;
}

static int ac_assert_file_list(const char *val, size_t vlen, int type,
			       const char *cwd, int want,
			       struct ac_assertion *arr, int *n, int max,
			       const char *label)
{
	int i, count = 0;

	if (type == AI_JSON_STR) {
		char *s = ai_json_strdup_str(val, vlen);
		char path[AC_PATH_MAX];
		struct stat st;
		int exists;

		if (!s)
			return -1;
		ac_join_path(cwd, s, path, sizeof(path));
		exists = (stat(path, &st) == 0);
		ac_assert_add(arr, n, max, exists == want, label,
			      "%s: %s", exists ? "存在" : "不存在", s);
		free(s);
		return 0;
	}
	if (type != AI_JSON_ARR)
		return -1;
	for (i = 0;; i++) {
		const char *el;
		size_t elen;
		int et;
		char *s;
		char path[AC_PATH_MAX];
		struct stat st;
		int exists;
		char expr[AC_ASSERT_STR];

		if (ai_json_arr_get(val, vlen, i, &el, &elen, &et) != 1)
			break;
		if (et != AI_JSON_STR)
			return -1;
		s = ai_json_strdup_str(el, elen);
		if (!s)
			return -1;
		ac_join_path(cwd, s, path, sizeof(path));
		exists = (stat(path, &st) == 0);
		snprintf(expr, sizeof(expr), "%s(\"%.120s\")", label, s);
		ac_assert_add(arr, n, max, exists == want, expr,
			      "%s: %s", exists ? "存在" : "不存在", s);
		free(s);
		count++;
	}
	return count == 0 ? -1 : 0;
}

static int ac_eval_assert(const char *aobj, size_t alen,
			  const struct ac_call_res *r, const char *cwd,
			  struct ac_assertion *arr, int *n, int max,
			  char *err, size_t errcap)
{
	const char *v;
	size_t vl;
	int t, i;

	if (!aobj || alen == 0) {
		ac_assert_add(arr, n, max, r->rc == 0, "rc==0", "rc=%d",
			      r->rc);
		return 0;
	}
	if (ac_obj_has(aobj, alen, "rc")) {
		long long want = ac_obj_ll(aobj, alen, "rc", 0);

		ac_assert_add(arr, n, max, r->rc == (int)want,
			      "rc==expected", "期望 %lld，实际 %d",
			      want, r->rc);
	} else {
		ac_assert_add(arr, n, max, r->rc == 0, "rc==0（隐式）",
			      "rc=%d", r->rc);
	}
	if (ac_obj_has(aobj, alen, "status_code")) {
		long long want = ac_obj_ll(aobj, alen, "status_code", 0);

		ac_assert_add(arr, n, max, r->status_code == (int)want,
			      "status_code==expected",
			      "期望 %lld，实际 %d", want, r->status_code);
	}
	{
		static const struct {
			const char *key;
			const char *label;
			int want;
			int is_err;
			int is_body;
		} table[] = {
			{ "stdout_contains", "stdout_contains", 1, 0, 0 },
			{ "stdout_not_contains", "stdout_not_contains", 0, 0, 0 },
			{ "stderr_contains", "stderr_contains", 1, 1, 0 },
			{ "stderr_not_contains", "stderr_not_contains", 0, 1, 0 },
			{ "body_contains", "body_contains", 1, 0, 1 },
			{ "body_not_contains", "body_not_contains", 0, 0, 1 },
		};

		for (i = 0; i < (int)(sizeof(table) / sizeof(table[0])); i++) {
			if (ai_json_obj_get(aobj, alen, table[i].key, &v, &vl,
					    &t) != 1)
				continue;
			{
				const char *hay = table[i].is_body ?
					(r->body ? r->body : "") :
					table[i].is_err ?
					(r->err ? r->err : "") :
					(r->out ? r->out : "");

				if (ac_assert_contains_list(v, vl, t, hay,
							    table[i].want,
							    arr, n, max,
							    table[i].label) != 0) {
					snprintf(err, errcap,
						 "%s 必须是字符串或字符串数组",
						 table[i].key);
					return -1;
				}
			}
		}
	}
	{
		static const char *const keys[] = {
			"stdout_matches", "stderr_matches", NULL
		};

		for (i = 0; keys[i]; i++) {
			if (ai_json_obj_get(aobj, alen, keys[i], &v, &vl,
					    &t) != 1)
				continue;
			if (t != AI_JSON_STR) {
				snprintf(err, errcap, "%s 必须是字符串", keys[i]);
				return -1;
			}
			{
				char *pat = ai_json_strdup_str(v, vl);
				char why[160] = "";
				char expr[AC_ASSERT_STR];
				int ok;

				if (!pat) {
					snprintf(err, errcap, "正则解码失败");
					return -1;
				}
				ok = ac_regex_ok(pat,
						 strstr(keys[i], "stdout") ?
						 (r->out ? r->out : "") :
						 (r->err ? r->err : ""),
						 why, sizeof(why));
				snprintf(expr, sizeof(expr), "%s(\"%.100s\")",
					 keys[i], pat);
				if (ok < 0) {
					ac_assert_add(arr, n, max, 0, expr,
						      "正则非法: %s", why);
				} else {
					ac_assert_add(arr, n, max, ok, expr,
						      "%s", ok ? "匹配" :
						      "不匹配");
				}
				free(pat);
			}
		}
	}
	if (ai_json_obj_get(aobj, alen, "file_exists", &v, &vl, &t) == 1) {
		if (ac_assert_file_list(v, vl, t, cwd, 1, arr, n, max,
					"file_exists") != 0) {
			snprintf(err, errcap, "file_exists 必须是字符串或数组");
			return -1;
		}
	}
	if (ai_json_obj_get(aobj, alen, "file_absent", &v, &vl, &t) == 1) {
		if (ac_assert_file_list(v, vl, t, cwd, 0, arr, n, max,
					"file_absent") != 0) {
			snprintf(err, errcap, "file_absent 必须是字符串或数组");
			return -1;
		}
	}
	if (ai_json_obj_get(aobj, alen, "file_min_size", &v, &vl, &t) == 1) {
		if (t != AI_JSON_ARR) {
			snprintf(err, errcap, "file_min_size 必须是对象数组");
			return -1;
		}
		for (i = 0;; i++) {
			const char *el;
			size_t elen;
			int et;
			char *path, *joined;
			long long min;
			struct stat st;
			int ok;
			char expr[AC_ASSERT_STR];

			if (ai_json_arr_get(v, vl, i, &el, &elen, &et) != 1)
				break;
			if (et != AI_JSON_OBJ) {
				snprintf(err, errcap,
					 "file_min_size[%d] 不是对象", i);
				return -1;
			}
			path = ac_obj_str(el, elen, "path");
			min = ac_obj_ll(el, elen, "min", 1);
			if (!path) {
				snprintf(err, errcap,
					 "file_min_size[%d] 缺 path", i);
				return -1;
			}
			{
				char p[AC_PATH_MAX];

				ac_join_path(cwd, path, p, sizeof(p));
				joined = strdup(p);
			}
			ok = (stat(joined, &st) == 0 &&
			      (long long)st.st_size >= min);
			snprintf(expr, sizeof(expr),
				 "file_min_size(\"%.100s\",%lld)", path, min);
			ac_assert_add(arr, n, max, ok, expr,
				      "实际 %lld 字节，要求 ≥%lld",
				      stat(joined, &st) == 0 ?
				      (long long)st.st_size : -1LL, min);
			free(path);
			free(joined);
		}
	}
	if (ai_json_obj_get(aobj, alen, "file_contains", &v, &vl, &t) == 1) {
		if (t != AI_JSON_ARR) {
			snprintf(err, errcap, "file_contains 必须是对象数组");
			return -1;
		}
		for (i = 0;; i++) {
			const char *el;
			size_t elen;
			int et;
			char *path, *text, *data = NULL;
			char p[AC_PATH_MAX];
			int ok = 0;
			char expr[AC_ASSERT_STR];
			FILE *fp;

			if (ai_json_arr_get(v, vl, i, &el, &elen, &et) != 1)
				break;
			if (et != AI_JSON_OBJ) {
				snprintf(err, errcap,
					 "file_contains[%d] 不是对象", i);
				return -1;
			}
			path = ac_obj_str(el, elen, "path");
			text = ac_obj_str(el, elen, "text");
			if (!path || !text) {
				free(path);
				free(text);
				snprintf(err, errcap,
					 "file_contains[%d] 需要 path/text",
					 i);
				return -1;
			}
			ac_join_path(cwd, path, p, sizeof(p));
			fp = fopen(p, "r");
			if (fp) {
				char buf[65536];
				size_t got = fread(buf, 1, sizeof(buf) - 1, fp);

				buf[got] = '\0';
				data = strdup(buf);
				fclose(fp);
			}
			if (data && strstr(data, text))
				ok = 1;
			snprintf(expr, sizeof(expr),
				 "file_contains(\"%.90s\",\"%.60s\")",
				 path, text);
			ac_assert_add(arr, n, max, ok, expr, "%s",
				      ok ? "包含" : "不包含或文件不可读");
			free(path);
			free(text);
			free(data);
		}
	}
	return 0;
}

static void ac_render_assertions(struct acb *b,
				 const struct ac_assertion *arr, int n)
{
	int i;

	acb_printf(b, "\"assertions\":[");
	for (i = 0; i < n; i++) {
		if (i)
			acb_printf(b, ",");
		acb_printf(b, "{\"expr\":");
		acb_json_str(b, arr[i].expr);
		acb_printf(b, ",\"ok\":%s,\"detail\":",
			   arr[i].ok ? "true" : "false");
		acb_json_str(b, arr[i].detail);
		acb_printf(b, "}");
	}
	acb_printf(b, "]");
}

/* ---- 进度 ---- */

static void ac_append_line(const char *path, const char *line)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);

	if (fd < 0)
		return;
	(void)!write(fd, line, strlen(line));
	(void)!write(fd, "\n", 1);
	close(fd);
}

/* ---- probe ---- */

struct ac_warns {
	char v[8][256];
	int n;
};

static void ac_warn_add(struct ac_warns *w, const char *fmt, ...)
{
	va_list ap;

	if (w->n >= (int)(sizeof(w->v) / sizeof(w->v[0])))
		return;
	va_start(ap, fmt);
	vsnprintf(w->v[w->n], sizeof(w->v[w->n]), fmt, ap);
	va_end(ap);
	w->n++;
}

static int ac_case_contains(const char *hay, const char *needle)
{
	return strcasestr(hay ? hay : "", needle) != NULL;
}

static void ac_probe_cli(const char *resolved, int timeout_s,
			 struct acb *b, struct ac_warns *w,
			 int *help_ok_out)
{
	char *av[3];
	struct ac_run r;
	char errbuf[256];
	char *combined = NULL;
	int usage = 0, help_ok = 0;
	int rc = 0;

	*help_ok_out = 0;
	acb_printf(b, "\"available\":%s", resolved ? "true" : "false");
	if (!resolved) {
		acb_printf(b, ",\"reason\":");
		acb_json_str(b, "可执行文件不存在或不可执行");
		return;
	}
	acb_printf(b, ",\"program\":");
	acb_json_str(b, resolved);
	/* D0 探测只跑 --help/-h，绝不执行调用方给的业务 argv：
	 * 否则 `python3 -m http.server` 会在 probe 里再起一个服务，
	 * 把只读探测变成动作。argv 只用于 HTTP 端口推断。 */
	av[0] = (char *)resolved;
	av[1] = (char *)"--help";
	av[2] = NULL;
	if (ac_run_cli(av, NULL, NULL, timeout_s * 1000, NULL, NULL, &r,
		       errbuf, sizeof(errbuf)) != 0) {
		acb_printf(b, ",\"help_ok\":false,\"help_rc\":-1,"
			   "\"help_timed_out\":false,\"duration_ms\":0,"
			   "\"help_excerpt\":");
		acb_json_str(b, errbuf);
		return;
	}
	if (r.rc != 0 || !r.out || !r.out[0]) {
		struct ac_run r2;
		char *av2[3];

		av2[0] = (char *)resolved;
		av2[1] = (char *)"-h";
		av2[2] = NULL;
		if (ac_run_cli(av2, NULL, NULL, timeout_s * 1000, NULL, NULL,
			       &r2, errbuf, sizeof(errbuf)) == 0 &&
		    r2.out && r2.out[0]) {
			free(r.out);
			free(r.err);
			r = r2;
		} else {
			free(r2.out);
			free(r2.err);
		}
	}
	{
		size_t lo = strlen(r.out ? r.out : "");
		size_t le = strlen(r.err ? r.err : "");

		combined = malloc(lo + le + 2);
		if (combined) {
			snprintf(combined, lo + le + 2, "%s%s",
				 r.out ? r.out : "", r.err ? r.err : "");
		}
	}
	usage = ac_case_contains(combined, "usage") ||
		ac_case_contains(combined, "用法") ||
		ac_case_contains(combined, "options") ||
		ac_case_contains(combined, "commands");
	help_ok = (r.rc == 0 && !r.timed_out && combined && combined[0]);
	*help_ok_out = help_ok;
	rc = r.rc;
	acb_printf(b, ",\"help_ok\":%s,\"help_usage_found\":%s,"
		   "\"help_rc\":%d,\"help_timed_out\":%s,"
		   "\"duration_ms\":%lld,\"help_excerpt\":",
		   help_ok ? "true" : "false", usage ? "true" : "false",
		   rc, r.timed_out ? "true" : "false", r.duration_ms);
	{
		char ex[512];

		ac_excerpt(ex, sizeof(ex), combined, 480);
		acb_json_str(b, ex);
	}
	if (r.timed_out)
		ac_warn_add(w, "CLI --help 探测超时（%ds），已 SIGKILL",
			    timeout_s);
	else if (!usage && !help_ok)
		ac_warn_add(w, "CLI --help 未能解析出 usage/options（rc=%d）",
			    rc);
	free(combined);
	free(r.out);
	free(r.err);
}

static int ac_infer_http_port(const char *program, char *const *argv,
			      int argc)
{
	const char *base = ac_base(program);
	int i, found = 0;

	if (!base)
		return 0;
	if (strcmp(base, "python") != 0 && strcmp(base, "python3") != 0 &&
	    strcmp(base, "python3.10") != 0 && strcmp(base, "python3.11") != 0 &&
	    strcmp(base, "python3.12") != 0)
		return 0;
	for (i = 0; i + 1 < argc; i++) {
		if (strcmp(argv[i], "-m") == 0 &&
		    strcmp(argv[i + 1], "http.server") == 0) {
			found = 1;
			i++;
			break;
		}
	}
	if (!found)
		return 0;
	for (i = 0; i < argc; i++) {
		const char *p = argv[i];

		if (strncmp(p, "--port=", 7) == 0) {
			int v = atoi(p + 7);

			if (v > 0 && v <= 65535)
				return v;
		}
		if (p[0] && strspn(p, "0123456789") == strlen(p)) {
			int v = atoi(p);

			if (v > 0 && v <= 65535)
				return v;
		}
	}
	return 8000;
}

static void ac_render_http_endpoints(struct acb *b,
				     const struct ac_http_ep *eps, int neps)
{
	int i;

	acb_printf(b, "\"endpoints\":[");
	for (i = 0; i < neps; i++) {
		const struct ac_http_ep *e = &eps[i];

		if (i)
			acb_printf(b, ",");
		acb_printf(b, "{\"host\":");
		acb_json_str(b, e->host);
		acb_printf(b, ",\"port\":%d,\"path\":", e->port);
		acb_json_str(b, e->path);
		acb_printf(b, ",\"reachable\":%s",
			   e->reachable ? "true" : "false");
		if (e->reachable) {
			acb_printf(b, ",\"status_code\":%d,"
				   "\"duration_ms\":%lld,\"body_bytes\":%zu,"
				   "\"body_excerpt\":",
				   e->status, e->duration_ms, e->body_bytes);
			acb_json_str(b, e->excerpt);
		} else {
			acb_printf(b, ",\"error\":");
			acb_json_str(b, e->error);
		}
		acb_printf(b, "}");
	}
	acb_printf(b, "]");
}

static int ac_probe_http(const char *program, char *const *argv, int argc,
			 int *ports, int nports, char **urls, int nurls,
			 char **paths, int npaths, int timeout_s,
			 struct acb *b, struct ac_warns *w)
{
	struct ac_http_ep eps[32];
	int neps = 0, i, j, available = 0;
	int all_ports[16];
	int nall = 0;
	int infer = ac_infer_http_port(program, argv, argc);

	for (i = 0; i < nports; i++) {
		if (nall < (int)(sizeof(all_ports) / sizeof(all_ports[0])))
			all_ports[nall++] = ports[i];
	}
	if (infer > 0) {
		int dup = 0;

		for (i = 0; i < nall; i++)
			if (all_ports[i] == infer)
				dup = 1;
		if (!dup && nall < (int)(sizeof(all_ports) /
					 sizeof(all_ports[0])))
			all_ports[nall++] = infer;
	}
	for (i = 0; i < nurls && neps < 32; i++) {
		struct ac_urlparts u;

		if (ac_parse_http_url(urls[i], &u) != 0)
			continue;
		memset(&eps[neps], 0, sizeof(eps[neps]));
		snprintf(eps[neps].host, sizeof(eps[neps].host), "%s", u.host);
		eps[neps].port = u.port;
		snprintf(eps[neps].path, sizeof(eps[neps].path), "%s", u.path);
		if (ac_probe_http_endpoint(&eps[neps],
					   timeout_s * 1000 > 2000 ?
					   2000 : timeout_s * 1000) == 0 &&
		    eps[neps].reachable)
			available = 1;
		neps++;
	}
	for (i = 0; i < nall && neps < 32; i++) {
		int already = 0;

		for (j = 0; j < neps; j++) {
			if (eps[j].port == all_ports[i])
				already = 1;
		}
		if (already)
			continue;
		for (j = 0; j < (npaths ? npaths : 1) && neps < 32; j++) {
			const char *path = npaths ? paths[j] : "/";

			memset(&eps[neps], 0, sizeof(eps[neps]));
			snprintf(eps[neps].host, sizeof(eps[neps].host),
				 "%s", "127.0.0.1");
			eps[neps].port = all_ports[i];
			snprintf(eps[neps].path, sizeof(eps[neps].path),
				 "%s", path);
			if (ac_probe_http_endpoint(&eps[neps],
						   timeout_s * 1000 > 2000 ?
						   2000 : timeout_s * 1000) != 0) {
				/* IPv4 失败时再试 ::1（本地服务可能只绑 v6） */
				char e4[160];

				snprintf(e4, sizeof(e4), "%s",
					 eps[neps].error);
				snprintf(eps[neps].host,
					 sizeof(eps[neps].host), "%s", "::1");
				if (ac_probe_http_endpoint(&eps[neps],
							   timeout_s * 1000 > 2000 ?
							   2000 : timeout_s *
							   1000) != 0)
					snprintf(eps[neps].error,
						 sizeof(eps[neps].error),
						 "v4: %.70s; v6: %.70s", e4,
						 eps[neps].error);
			}
			if (eps[neps].reachable)
				available = 1;
			neps++;
		}
	}
	acb_printf(b, "\"available\":%s,\"probed\":%s",
		   available ? "true" : "false",
		   (nall || nurls) ? "true" : "false");
	if (!nall && !nurls) {
		acb_printf(b, ",\"reason\":");
		acb_json_str(b, "未指定 http_ports/http_urls，且 APP 参数未显示"
			     "服务模式；不做端口扫描（避免把无关本地服务当成"
			     "该 APP 的 HTTP 控制面）");
		if (infer == 0)
			ac_warn_add(w, "HTTP 未探测：没有可用的本地端口线索");
	}
	acb_printf(b, ",\"inferred_port\":%d,", infer);
	ac_render_http_endpoints(b, eps, neps);
	return available;
}

static int ac_probe_dbus(const char *name, int timeout_s, struct acb *b,
			 int *owner_out)
{
	char addr[512] = "";
	char detail[256] = "";
	char dbus_send[AC_PATH_MAX] = "";
	int bus = ac_dbus_bus_present(addr, sizeof(addr));
	int have_send = ac_lookup_dbus_send(dbus_send, sizeof(dbus_send));
	int owner = -1;

	*owner_out = -1;
	if (name && name[0] && bus && have_send)
		ac_dbus_name_owner(name, &owner, timeout_s, detail,
				   sizeof(detail));
	else if (name && name[0] && !bus)
		snprintf(detail, sizeof(detail),
			 "无 session bus（env/socket 均未发现），无法查询 %s",
			 name);
	else if (name && name[0] && !have_send)
		snprintf(detail, sizeof(detail),
			 "系统无 dbus-send，无法查询 %s", name);
	else
		snprintf(detail, sizeof(detail),
			 "未提供 dbus_name；只报告 session bus 是否存在");
	*owner_out = owner;
	acb_printf(b, "\"session_bus\":%s,\"bus_address\":",
		   bus ? "true" : "false");
	acb_json_str(b, addr);
	acb_printf(b, ",\"dbus_send\":%s,\"name\":",
		   have_send ? "true" : "false");
	acb_json_str(b, name ? name : "");
	acb_printf(b, ",\"name_owner\":");
	if (owner == 1)
		acb_json_str(b, "true");
	else if (owner == 0)
		acb_json_str(b, "false");
	else
		acb_json_str(b, "unknown");
	acb_printf(b, ",\"detail\":");
	acb_json_str(b, detail);
	return bus;
}

static int ac_probe_atspi(int timeout_s, struct acb *b)
{
	const char *env_bus = getenv("AT_SPI_BUS_ADDRESS");
	const char *gtk = getenv("GTK_MODULES");
	const char *no_bridge = getenv("NO_AT_BRIDGE");
	char addr[512] = "";
	char detail[256] = "";
	struct stat st;
	int bus = ac_dbus_bus_present(addr, sizeof(addr));
	int have_bus_env = env_bus && env_bus[0];
	int atk = gtk && strstr(gtk, "atk-bridge") != NULL;
	int noat = no_bridge && no_bridge[0] && strcmp(no_bridge, "0") != 0;
	int launcher = (stat("/usr/libexec/at-spi-bus-launcher", &st) == 0) ||
		       (stat("/usr/lib/at-spi-bus-launcher", &st) == 0) ||
		       (stat("/usr/libexec/at-spi2-registryd", &st) == 0);
	char dbus_send[AC_PATH_MAX];
	int have_send = ac_lookup_dbus_send(dbus_send, sizeof(dbus_send));
	int owner = -1;

	if (bus && have_send)
		ac_dbus_name_owner("org.a11y.Bus", &owner, timeout_s, detail,
				   sizeof(detail));
	else
		snprintf(detail, sizeof(detail), "%s",
			 bus ? "无 dbus-send，无法查询 org.a11y.Bus" :
			 "无 session bus");
	acb_printf(b, "\"environment_present\":%s,\"at_spi_bus_address\":%s,"
		   "\"atk_bridge\":%s,\"no_at_bridge\":%s,"
		   "\"launcher_present\":%s,\"a11y_bus_owner\":",
		   (have_bus_env || atk || launcher || owner == 1) ?
		   "true" : "false",
		   have_bus_env ? "true" : "false",
		   atk ? "true" : "false", noat ? "true" : "false",
		   launcher ? "true" : "false");
	if (owner == 1)
		acb_json_str(b, "true");
	else if (owner == 0)
		acb_json_str(b, "false");
	else
		acb_json_str(b, "unknown");
	acb_printf(b, ",\"implemented\":false,\"detail\":");
	{
		char full[400];

		snprintf(full, sizeof(full),
			 "仅探测环境，不实现 AT-SPI 控制面（可访问性树操作留待"
			 "后续）；%s", detail);
		acb_json_str(b, full);
	}
	return have_bus_env || atk || launcher || owner == 1;
}

static int ac_tool_probe(const char *args, size_t alen, char **out)
{
	char *app = NULL;
	char *resolved = NULL;
	char *user_argv[AC_MAX_ARGV];
	int user_argc = 0;
	char *urls[8], *paths[8];
	int ports[8];
	int nurls = 0, npaths = 0, nports = 0;
	char *dbus_name = NULL;
	char *fmt = NULL;
	int timeout_s;
	char state[AC_PATH_MAX];
	char err[512];
	char *buf;
	struct acb b;
	struct ac_warns w;
	long long t0 = ac_now_ms();
	int found = 0, cli_avail = 0, http_avail = 0, dbus_owner = -1;
	int atspi_present, cli_help_ok = 0;
	int i;

	memset(&w, 0, sizeof(w));
	memset(user_argv, 0, sizeof(user_argv));
	memset(urls, 0, sizeof(urls));
	memset(paths, 0, sizeof(paths));
	if (ac_state_dir(state, sizeof(state)) != 0)
		snprintf(state, sizeof(state), "/tmp");
	app = ac_obj_str(args, alen, "app");
	if (!app || !app[0]) {
		free(app);
		return ac_param_error(out, "app_ctl_probe", "MISSING",
				      "缺少 app（可执行文件名或绝对路径）");
	}
	user_argc = ac_obj_strarr(args, alen, "argv", user_argv, AC_MAX_ARGV,
				  err, sizeof(err));
	if (user_argc < 0) {
		free(app);
		return ac_param_error(out, "app_ctl_probe", "BAD_ARGV", err);
	}
	nports = ac_obj_intarr(args, alen, "http_ports", ports, 8, err,
			       sizeof(err));
	if (nports < 0)
		goto bad_ports;
	nurls = ac_obj_strarr(args, alen, "http_urls", urls, 8, err,
			      sizeof(err));
	if (nurls < 0)
		goto bad_ports;
	npaths = ac_obj_strarr(args, alen, "http_paths", paths, 8, err,
			       sizeof(err));
	if (npaths < 0)
		goto bad_ports;
	for (i = 0; i < nurls; i++) {
		if (ac_url_loopback(urls[i]) != 1) {
			snprintf(err, sizeof(err),
				 "http_urls[%d] 仅允许回环 http:// 地址", i);
			goto bad_ports;
		}
	}
	for (i = 0; i < npaths; i++) {
		if (paths[i][0] != '/') {
			char fixed[512];

			snprintf(fixed, sizeof(fixed), "/%s", paths[i]);
			free(paths[i]);
			paths[i] = strdup(fixed);
		}
	}
	dbus_name = ac_obj_str(args, alen, "dbus_name");
	fmt = ac_obj_str(args, alen, "format");
	timeout_s = (int)ac_obj_ll(args, alen, "timeout_s", 5);
	if (timeout_s < 1 || timeout_s > 30)
		timeout_s = 5;

	resolved = malloc(AC_PATH_MAX);
	if (!resolved)
		goto oom;
	{
		char rerr[512];

		found = (ac_resolve_program(app, resolved, AC_PATH_MAX, rerr,
					    sizeof(rerr)) == 0);
	}

	buf = malloc(512 * 1024);
	if (!buf)
		goto oom;
	acb_init(&b, buf, 512 * 1024);
	acb_printf(&b, "{\"tool\":\"app_ctl_probe\",\"app\":");
	acb_json_str(&b, app);
	acb_printf(&b, ",\"resolved\":");
	acb_json_str(&b, found ? resolved : "");
	acb_printf(&b, ",\"found\":%s", found ? "true" : "false");
	if (!found)
		ac_warn_add(&w, "APP 未找到或不可执行: %s", app);

	acb_printf(&b, ",\"cli\":{");
	ac_probe_cli(found ? resolved : NULL, timeout_s, &b, &w,
		     &cli_help_ok);
	acb_printf(&b, "}");
	cli_avail = found;
	acb_printf(&b, ",\"http\":{");
	http_avail = ac_probe_http(found ? resolved : app, user_argv,
				   user_argc, ports, nports, urls, nurls,
				   paths, npaths, timeout_s, &b, &w);
	acb_printf(&b, "}");
	acb_printf(&b, ",\"dbus\":{");
	ac_probe_dbus(dbus_name, timeout_s, &b, &dbus_owner);
	acb_printf(&b, "}");
	acb_printf(&b, ",\"at_spi\":{");
	atspi_present = ac_probe_atspi(timeout_s, &b);
	acb_printf(&b, "}");
	acb_printf(&b, ",\"backends\":[");
	{
		int n = 0;

		if (cli_avail) {
			acb_printf(&b, "\"cli\"");
			n++;
		}
		if (http_avail) {
			acb_printf(&b, "%s\"http\"", n ? "," : "");
			n++;
		}
		if (dbus_owner == 1) {
			acb_printf(&b, "%s\"dbus\"", n ? "," : "");
			n++;
		}
	}
	acb_printf(&b, "]");
	acb_printf(&b, ",\"call_supported\":{\"cli\":true,\"http\":true,"
		   "\"dbus\":false}");
	if (dbus_owner == 1)
		ac_warn_add(&w, "检测到 dbus 控制面（name 有主），但 "
			    "app_ctl_call 仅实现 cli/http（dbus 仅探测不实现）");
	acb_printf(&b, ",\"warnings\":[");
	for (i = 0; i < w.n; i++) {
		if (i)
			acb_printf(&b, ",");
		acb_json_str(&b, w.v[i]);
	}
	acb_printf(&b, "],\"duration_ms\":%lld",
		   ac_now_ms() - t0);
	acb_printf(&b, ",\"state_dir\":");
	acb_json_str(&b, state);
	acb_printf(&b, "}");
	if (fmt && strcmp(fmt, "text") == 0) {
		/* text 视图：关键结论在前，完整 JSON 附后 */
		char *text = malloc(b.len + 512);

		if (text) {
			int off = snprintf(text, b.len + 512,
				"app=%s resolved=%s found=%s\n"
				"backends=%s%s%s\n"
				"cli: available=%d help_ok=%d\n"
				"http: available=%d\n"
				"dbus: session_bus=%s name_owner=%s\n"
				"at-spi: environment_present=%d implemented=false\n"
				"warnings=%d\n---- json ----\n",
				app, found ? resolved : "",
				found ? "yes" : "no",
				cli_avail ? "cli" : "",
				http_avail ? (cli_avail ? ",http" : "http") : "",
				dbus_owner == 1 ? ",dbus" : "",
				cli_avail, cli_help_ok, http_avail,
				ac_case_contains(buf, "\"session_bus\":true") ?
				"true" : "false",
				dbus_owner == 1 ? "true" :
				dbus_owner == 0 ? "false" : "unknown",
				atspi_present, w.n);
			if (off > 0 && (size_t)off < b.len + 512)
				snprintf(text + off, b.len + 512 - (size_t)off,
					 "%s", buf);
			free(buf);
			buf = NULL;
			*out = text;
		}
	}
	if (buf) {
		*out = buf;
		buf = NULL;
	}
	ac_audit(state, "app_ctl_probe app=%s resolved=%s found=%d "
		 "backends_cli=%d backends_http=%d dbus_owner=%d atspi=%d",
		 app, found ? resolved : "", found, cli_avail, http_avail,
		 dbus_owner, atspi_present);
	free(buf);
	free(app);
	free(resolved);
	free(dbus_name);
	free(fmt);
	for (i = 0; i < AC_MAX_ARGV; i++)
		free(user_argv[i]);
	for (i = 0; i < 8; i++) {
		free(urls[i]);
		free(paths[i]);
	}
	return AI_OK;
bad_ports:
	free(app);
	for (i = 0; i < AC_MAX_ARGV; i++)
		free(user_argv[i]);
	for (i = 0; i < 8; i++) {
		free(urls[i]);
		free(paths[i]);
	}
	return ac_param_error(out, "app_ctl_probe", "BAD_HTTP", err);
oom:
	free(app);
	free(resolved);
	free(dbus_name);
	free(fmt);
	for (i = 0; i < AC_MAX_ARGV; i++)
		free(user_argv[i]);
	for (i = 0; i < 8; i++) {
		free(urls[i]);
		free(paths[i]);
	}
	return ac_param_error(out, "app_ctl_probe", "OOM", "内存不足");
}

/* ---- call ---- */

static int ac_tool_call(const char *args, size_t alen, char **out)
{
	char state[AC_PATH_MAX];
	char work[AC_PATH_MAX];
	struct ac_call_spec spec;
	struct ac_call_res res;
	char err[512];
	char *buf;
	struct acb b;
	size_t cap = 1024 * 1024;

	if (ac_state_dir(state, sizeof(state)) != 0)
		return ac_param_error(out, "app_ctl_call", "STATE",
				      "无法创建/访问 appctl 状态目录");
	if (ac_work_dir(state, work, sizeof(work)) != 0)
		snprintf(work, sizeof(work), "/tmp");
	if (ac_call_spec_parse(args, alen, work, 1, &spec, err,
			       sizeof(err)) != 0)
		return ac_param_error(out, "app_ctl_call", "BAD_CALL", err);
	if (ac_do_call(&spec, NULL, NULL, &res, err, sizeof(err)) != 0) {
		ac_call_spec_free(&spec);
		return ac_param_error(out, "app_ctl_call", "EXEC", err);
	}
	if (strcmp(res.backend, "http") == 0 && res.body) {
		char *masked = ac_mask_text(res.body);

		ac_audit(state, "app_ctl_call backend=%s target=%s rc=%d "
			 "timed_out=%d canceled=%d duration_ms=%lld ok=%d "
			 "body_masked=%.400s",
			 res.backend, res.target, res.rc, res.timed_out,
			 res.canceled, res.duration_ms, res.ok,
			 masked ? masked : "");
		free(masked);
	} else {
		ac_audit(state, "app_ctl_call backend=%s target=%s rc=%d "
			 "timed_out=%d canceled=%d duration_ms=%lld ok=%d "
			 "argv=%s",
			 res.backend, res.target, res.rc, res.timed_out,
			 res.canceled, res.duration_ms, res.ok,
			 res.argv_json ? res.argv_json : "[]");
	}
	buf = malloc(cap);
	if (!buf) {
		ac_call_res_free(&res);
		ac_call_spec_free(&spec);
		return ac_param_error(out, "app_ctl_call", "OOM", "内存不足");
	}
	acb_init(&b, buf, cap);
	acb_printf(&b, "{\"tool\":\"app_ctl_call\",\"ok\":%s,",
		   res.ok ? "true" : "false");
	ac_render_call_fields(&b, &res, AC_OUT_LIMIT, 1);
	acb_printf(&b, ",\"audit_path\":");
	{
		char ap[AC_PATH_MAX];

		ac_path_join(ap, sizeof(ap), state, "audit.log");
		acb_json_str(&b, ap);
	}
	acb_printf(&b, "}");
	*out = buf;
	ac_call_res_free(&res);
	ac_call_spec_free(&spec);
	return AI_OK;
}
/* ---- task ---- */

struct ac_step_out {
	int index;
	char name[128];
	struct ac_call_res call;
	struct ac_assertion asserts[AC_MAX_ASSERT];
	int nassert;
	int ok;
	int continued;
};

static void ac_state_file(char *out, size_t cap, const char *state,
			  const char *task_id, const char *suffix)
{
	char name[AC_TASK_ID_MAX + 64];

	snprintf(name, sizeof(name), "%s%s", task_id, suffix);
	ac_path_join(out, cap, state, name);
}

static void ac_gen_task_id(char *out, size_t cap)
{
	time_t now = time(NULL);
	struct tm tmv;

	localtime_r(&now, &tmv);
	strftime(out, cap, "appctl-%Y%m%d-%H%M%S", &tmv);
	{
		size_t n = strlen(out);

		snprintf(out + n, cap - n, "-%ld", (long)getpid());
	}
}

static char *ac_read_tail_file(const char *path, size_t max)
{
	int fd;
	off_t sz;
	char *buf;
	ssize_t n;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	sz = lseek(fd, 0, SEEK_END);
	if (sz < 0) {
		close(fd);
		return NULL;
	}
	if ((size_t)sz > max)
		lseek(fd, sz - (off_t)max, SEEK_SET);
	else
		lseek(fd, 0, SEEK_SET);
	buf = malloc(max + 1);
	if (!buf) {
		close(fd);
		return NULL;
	}
	n = read(fd, buf, max);
	close(fd);
	if (n < 0) {
		free(buf);
		return NULL;
	}
	buf[n] = '\0';
	return buf;
}

static void ac_ev_start(const char *path, const char *task_id, int steps,
			const char *workdir)
{
	char line[2048];
	char ts[64];
	struct acb b;

	ac_timestamp(ts, sizeof(ts));
	acb_init(&b, line, sizeof(line));
	acb_printf(&b, "{\"ts\":\"%s\",\"event\":\"task_start\","
		   "\"task_id\":", ts);
	acb_json_str(&b, task_id);
	acb_printf(&b, ",\"steps\":%d,\"workdir\":", steps);
	acb_json_str(&b, workdir);
	acb_printf(&b, "}");
	ac_append_line(path, line);
}

static void ac_ev_step_start(const char *path, const char *task_id, int index,
			     const char *name, const char *backend,
			     const char *target)
{
	char line[2048];
	char ts[64];
	struct acb b;

	ac_timestamp(ts, sizeof(ts));
	acb_init(&b, line, sizeof(line));
	acb_printf(&b, "{\"ts\":\"%s\",\"event\":\"step_start\","
		   "\"task_id\":", ts);
	acb_json_str(&b, task_id);
	acb_printf(&b, ",\"index\":%d,\"name\":", index);
	acb_json_str(&b, name);
	acb_printf(&b, ",\"backend\":");
	acb_json_str(&b, backend);
	acb_printf(&b, ",\"target\":");
	acb_json_str(&b, target);
	acb_printf(&b, "}");
	ac_append_line(path, line);
}

static void ac_ev_step_done(const char *path, const char *task_id, int index,
			    const char *name, int rc, int ok,
			    long long duration_ms, int timed_out,
			    int canceled)
{
	char line[2048];
	char ts[64];
	struct acb b;

	ac_timestamp(ts, sizeof(ts));
	acb_init(&b, line, sizeof(line));
	acb_printf(&b, "{\"ts\":\"%s\",\"event\":\"step_done\","
		   "\"task_id\":", ts);
	acb_json_str(&b, task_id);
	acb_printf(&b, ",\"index\":%d,\"name\":", index);
	acb_json_str(&b, name);
	acb_printf(&b, ",\"rc\":%d,\"ok\":%s,\"duration_ms\":%lld,"
		   "\"timed_out\":%s,\"canceled\":%s}", rc,
		   ok ? "true" : "false", duration_ms,
		   timed_out ? "true" : "false",
		   canceled ? "true" : "false");
	ac_append_line(path, line);
}

static void ac_ev_task_done(const char *path, const char *task_id,
			    const char *status, long long duration_ms,
			    int failed_step)
{
	char line[2048];
	char ts[64];
	struct acb b;

	ac_timestamp(ts, sizeof(ts));
	acb_init(&b, line, sizeof(line));
	acb_printf(&b, "{\"ts\":\"%s\",\"event\":\"task_done\","
		   "\"task_id\":", ts);
	acb_json_str(&b, task_id);
	acb_printf(&b, ",\"status\":");
	acb_json_str(&b, status);
	acb_printf(&b, ",\"duration_ms\":%lld,\"failed_step\":",
		   duration_ms);
	if (failed_step >= 0)
		acb_printf(&b, "%d", failed_step);
	else
		acb_printf(&b, "null");
	acb_printf(&b, "}");
	ac_append_line(path, line);
}

static void ac_ev_cancel_request(const char *path, const char *task_id,
				 pid_t pid, int killed, int alive_after)
{
	char line[1024];
	char ts[64];
	struct acb b;

	ac_timestamp(ts, sizeof(ts));
	acb_init(&b, line, sizeof(line));
	acb_printf(&b, "{\"ts\":\"%s\",\"event\":\"cancel_request\","
		   "\"task_id\":", ts);
	acb_json_str(&b, task_id);
	acb_printf(&b, ",\"pid\":%ld,\"killed\":%s,"
		   "\"pid_alive_after\":%s}", (long)pid,
		   killed ? "true" : "false",
		   alive_after ? "true" : "false");
	ac_append_line(path, line);
}

static int ac_pid_alive(pid_t pid)
{
	if (pid <= 0)
		return 0;
	return kill(pid, 0) == 0 || errno == EPERM;
}

static int ac_tool_task_run(const char *args, size_t alen,
			    const char *state, char **out)
{
	char *id_arg = NULL;
	char task_id[AC_TASK_ID_MAX + 1];
	char workdir[AC_PATH_MAX];
	char progress[AC_PATH_MAX], cancel_path[AC_PATH_MAX];
	char pid_path[AC_PATH_MAX];
	char errbuf[512];
	const char *steps_tok = NULL;
	size_t steps_len = 0;
	int steps_type = 0;
	char *task_str = NULL;
	int step_count = 0, i;
	int fail_fast, task_timeout;
	long long t0 = ac_now_ms();
	struct ac_step_out *steps = NULL;
	int executed = 0, first_failed = -1, canceled_step = -1;
	int st = 0;	/* 0=ok 1=failed 2=canceled 3=timeout */
	char *buf = NULL;
	size_t cap = 2 * 1024 * 1024;
	struct acb b;

	id_arg = ac_obj_str(args, alen, "task_id");
	if (id_arg && id_arg[0]) {
		if (!ac_task_id_valid(id_arg)) {
			free(id_arg);
			return ac_param_error(out, "app_ctl_task", "BAD_TASK_ID",
					      "task_id 只允许 [A-Za-z0-9._-]，"
					      "1..64 字符，且不得为 . / ..");
		}
		snprintf(task_id, sizeof(task_id), "%s", id_arg);
	} else {
		ac_gen_task_id(task_id, sizeof(task_id));
	}
	free(id_arg);

	{
		char *wd = ac_obj_str(args, alen, "workdir");

		if (wd && wd[0]) {
			char real[PATH_MAX];

			if (wd[0] != '/' || !realpath(wd, real) ||
			    !ac_dir_ok(real)) {
				free(wd);
				return ac_param_error(out, "app_ctl_task",
						      "BAD_WORKDIR",
						      "workdir 必须是已存在的"
						      "绝对目录");
			}
			snprintf(workdir, sizeof(workdir), "%s", real);
			free(wd);
		} else {
			free(wd);
			if (ac_task_dir(state, task_id, workdir,
					sizeof(workdir)) != 0)
				return ac_param_error(out, "app_ctl_task",
						      "WORKDIR",
						      "无法创建任务工作目录");
		}
	}
	fail_fast = ac_obj_bool(args, alen, "fail_fast", 1);
	task_timeout = (int)ac_obj_ll(args, alen, "timeout_s", 300);
	if (task_timeout < 1 || task_timeout > 3600)
		task_timeout = 300;

	if (ac_obj_get_token(args, alen, "steps", &steps_tok, &steps_len,
			     &steps_type) != 1) {
		const char *tt;
		size_t tl;
		int ttype;

		if (ac_obj_get_token(args, alen, "task", &tt, &tl,
				     &ttype) != 1) {
			return ac_param_error(out, "app_ctl_task", "MISSING",
					      "缺少 steps（或 task.steps）");
		}
		if (ttype == AI_JSON_STR) {
			task_str = ai_json_strdup_str(tt, tl);
			if (!task_str)
				return ac_param_error(out, "app_ctl_task",
						      "BAD_TASK",
						      "task 字符串解码失败");
			tt = task_str;
			tl = strlen(task_str);
			ttype = AI_JSON_OBJ;
		}
		if (ttype != AI_JSON_OBJ ||
		    ai_json_obj_get(tt, tl, "steps", &steps_tok, &steps_len,
				    &steps_type) != 1) {
			free(task_str);
			return ac_param_error(out, "app_ctl_task", "BAD_TASK",
					      "task 必须是含 steps 数组的 JSON "
					      "对象（本版不接受 YAML）");
		}
	}
	if (steps_type != AI_JSON_ARR) {
		free(task_str);
		return ac_param_error(out, "app_ctl_task", "BAD_STEPS",
				      "steps 必须是数组");
	}
	for (;;) {
		const char *el;
		size_t elen;
		int et;

		if (ai_json_arr_get(steps_tok, steps_len, step_count, &el,
				    &elen, &et) != 1)
			break;
		if (et != AI_JSON_OBJ) {
			free(task_str);
			return ac_param_error(out, "app_ctl_task", "BAD_STEPS",
					      "steps 数组元素必须是对象");
		}
		step_count++;
		if (step_count > AC_MAX_STEPS) {
			free(task_str);
			return ac_param_error(out, "app_ctl_task",
					      "TOO_MANY_STEPS",
					      "steps 最多 32 步");
		}
	}
	if (step_count == 0) {
		free(task_str);
		return ac_param_error(out, "app_ctl_task", "EMPTY_STEPS",
				      "steps 至少 1 步");
	}

	ac_state_file(progress, sizeof(progress), state, task_id,
		      ".progress.jsonl");
	ac_state_file(cancel_path, sizeof(cancel_path), state, task_id,
		      ".cancel");
	ac_state_file(pid_path, sizeof(pid_path), state, task_id, ".child");
	unlink(cancel_path);
	unlink(pid_path);

	steps = calloc(AC_MAX_STEPS, sizeof(*steps));
	if (!steps) {
		free(task_str);
		return ac_param_error(out, "app_ctl_task", "OOM", "内存不足");
	}
	ac_ev_start(progress, task_id, step_count, workdir);
	ac_audit(state, "app_ctl_task action=run task_id=%s steps=%d "
		 "workdir=%s fail_fast=%d timeout_s=%d",
		 task_id, step_count, workdir, fail_fast, task_timeout);

	for (i = 0; i < step_count; i++) {
		const char *step_tok, *call_tok, *assert_tok = NULL;
		size_t step_len, call_len, assert_len = 0;
		int step_type, call_type, assert_type = 0;
		char *name_s = NULL;
		char name[128];
		struct ac_call_spec spec;
		struct ac_step_out *so = &steps[i];
		long long now, remaining_ms;
		int limited_by_task = 0;
		int j, all_ok;

		if (access(cancel_path, F_OK) == 0) {
			st = 2;
			canceled_step = i;
			break;
		}
		now = ac_now_ms();
		remaining_ms = t0 + (long long)task_timeout * 1000 - now;
		if (remaining_ms <= 0) {
			st = 3;
			first_failed = i;
			break;
		}
		if (ai_json_arr_get(steps_tok, steps_len, i, &step_tok,
				    &step_len, &step_type) != 1)
			break;
		so->index = i;
		name_s = ac_obj_str(step_tok, step_len, "name");
		snprintf(name, sizeof(name), "%s",
			 name_s && name_s[0] ? name_s : "");
		if (!name[0])
			snprintf(name, sizeof(name), "step-%d", i);
		free(name_s);
		snprintf(so->name, sizeof(so->name), "%s", name);
		call_tok = step_tok;
		call_len = step_len;
		if (ai_json_obj_get(step_tok, step_len, "call", &call_tok,
				    &call_len, &call_type) == 1) {
			if (call_type != AI_JSON_OBJ) {
				snprintf(errbuf, sizeof(errbuf),
					 "step[%d].call 必须是对象", i);
				goto step_parse_fail;
			}
		}
		if (ac_call_spec_parse(call_tok, call_len, workdir, 0, &spec,
				       errbuf, sizeof(errbuf)) != 0)
			goto step_parse_fail;
		if (remaining_ms < (long long)spec.timeout_s * 1000) {
			int eff = (int)((remaining_ms + 999) / 1000);

			if (eff < 1)
				eff = 1;
			spec.timeout_s = eff;
			limited_by_task = 1;
		}
		ac_ev_step_start(progress, task_id, i, name, spec.backend,
				 spec.program ? spec.program :
				 spec.url ? spec.url : "");
		ac_do_call(&spec, cancel_path, pid_path, &so->call, errbuf,
			   sizeof(errbuf));
		if (so->call.canceled) {
			st = 2;
			canceled_step = i;
			so->ok = 0;
			ac_assert_add(so->asserts, &so->nassert, AC_MAX_ASSERT,
				      0, "not_canceled", "任务在步骤中被取消");
		} else {
			if (so->call.timed_out && limited_by_task)
				st = 3;
			if (ai_json_obj_get(step_tok, step_len, "assert",
					    &assert_tok, &assert_len,
					    &assert_type) == 1 &&
			    assert_type == AI_JSON_OBJ) {
				if (ac_eval_assert(assert_tok, assert_len,
						   &so->call, spec.cwd,
						   so->asserts, &so->nassert,
						   AC_MAX_ASSERT, errbuf,
						   sizeof(errbuf)) != 0) {
					ac_assert_add(so->asserts,
						      &so->nassert,
						      AC_MAX_ASSERT, 0,
						      "assert-parse", "%s",
						      errbuf);
				}
			} else if (assert_tok && assert_type != AI_JSON_OBJ) {
				ac_assert_add(so->asserts, &so->nassert,
					      AC_MAX_ASSERT, 0, "assert-parse",
					      "assert 必须是对象");
			} else {
				ac_eval_assert(NULL, 0, &so->call, spec.cwd,
					       so->asserts, &so->nassert,
					       AC_MAX_ASSERT, errbuf,
					       sizeof(errbuf));
			}
			all_ok = so->call.ok;
			for (j = 0; j < so->nassert; j++)
				if (!so->asserts[j].ok)
					all_ok = 0;
			so->ok = all_ok;
			if (!so->ok && st == 0) {
				st = 1;
				first_failed = i;
			}
		}
		executed = i + 1;
		ac_ev_step_done(progress, task_id, i, name, so->call.rc,
				so->ok, so->call.duration_ms,
				so->call.timed_out, so->call.canceled);
		ac_audit(state, "app_ctl_task task_id=%s step=%d name=%s "
			 "backend=%s target=%s rc=%d ok=%d duration_ms=%lld "
			 "timed_out=%d canceled=%d",
			 task_id, i, name, so->call.backend,
			 so->call.target, so->call.rc, so->ok,
			 so->call.duration_ms, so->call.timed_out,
			 so->call.canceled);
		ac_call_spec_free(&spec);
		if (st == 2 || st == 3)
			break;
		if (!so->ok) {
			if (fail_fast)
				break;
			so->continued = 1;
		}
		continue;
step_parse_fail:
		so->ok = 0;
		snprintf(so->call.backend, sizeof(so->call.backend), "%s",
			 "invalid");
		so->call.rc = -1;
		so->call.error = strdup(errbuf);
		ac_assert_add(so->asserts, &so->nassert, AC_MAX_ASSERT, 0,
			      "call-parse", "%s", errbuf);
		executed = i + 1;
		if (st == 0) {
			st = 1;
			first_failed = i;
		}
		ac_ev_step_done(progress, task_id, i, name, -1, 0, 0, 0, 0);
		ac_audit(state, "app_ctl_task task_id=%s step=%d name=%s "
			 "call_parse_error=%s", task_id, i, name, errbuf);
		if (fail_fast)
			break;
		so->continued = 1;
	}

	{
		const char *status = st == 0 ? "ok" : st == 1 ? "failed" :
				     st == 2 ? "canceled" : "timeout";
		long long dur = ac_now_ms() - t0;

		ac_ev_task_done(progress, task_id, status, dur,
				st == 1 || st == 3 ? first_failed : -1);
		unlink(cancel_path);
		unlink(pid_path);

		buf = malloc(cap);
		if (!buf) {
			for (i = 0; i < executed; i++)
				ac_call_res_free(&steps[i].call);
			free(steps);
			free(task_str);
			return ac_param_error(out, "app_ctl_task", "OOM",
					      "内存不足");
		}
		acb_init(&b, buf, cap);
		acb_printf(&b, "{\"tool\":\"app_ctl_task\",\"action\":\"run\","
			   "\"task_id\":");
		acb_json_str(&b, task_id);
		acb_printf(&b, ",\"status\":");
		acb_json_str(&b, status);
		acb_printf(&b, ",\"fail_fast\":%s,\"workdir\":",
			   fail_fast ? "true" : "false");
		acb_json_str(&b, workdir);
		acb_printf(&b, ",\"duration_ms\":%lld,\"step_count\":%d,"
			   "\"executed_steps\":%d,\"failed_step\":",
			   dur, step_count, executed);
		if ((st == 1 || st == 3) && first_failed >= 0)
			acb_printf(&b, "%d", first_failed);
		else
			acb_printf(&b, "null");
		acb_printf(&b, ",\"canceled_at_step\":");
		if (st == 2 && canceled_step >= 0)
			acb_printf(&b, "%d", canceled_step);
		else
			acb_printf(&b, "null");
		acb_printf(&b, ",\"steps\":[");
		for (i = 0; i < executed; i++) {
			struct ac_step_out *so = &steps[i];

			if (i)
				acb_printf(&b, ",");
			acb_printf(&b, "{\"index\":%d,\"name\":", so->index);
			acb_json_str(&b, so->name);
			acb_printf(&b, ",\"ok\":%s,\"call_ok\":%s,"
				   "\"continued\":%s,",
				   so->ok ? "true" : "false",
				   so->call.ok ? "true" : "false",
				   so->continued ? "true" : "false");
			ac_render_call_fields(&b, &so->call, 16384, 1);
			acb_printf(&b, ",");
			ac_render_assertions(&b, so->asserts, so->nassert);
			acb_printf(&b, "}");
		}
		acb_printf(&b, "],\"progress_path\":");
		acb_json_str(&b, progress);
		acb_printf(&b, ",\"audit_path\":");
		{
			char ap[AC_PATH_MAX];

			ac_path_join(ap, sizeof(ap), state, "audit.log");
			acb_json_str(&b, ap);
		}
		acb_printf(&b, ",\"state_dir\":");
		acb_json_str(&b, state);
		acb_printf(&b, "}");
		*out = buf;
		for (i = 0; i < executed; i++)
			ac_call_res_free(&steps[i].call);
		free(steps);
		free(task_str);
		return st == 0 ? AI_OK : AI_ERR_GENERIC;
	}
}

static int ac_tool_task_cancel(const char *args, size_t alen,
			       const char *state, char **out)
{
	char *id = ac_obj_str(args, alen, "task_id");
	char progress[AC_PATH_MAX], cancel_path[AC_PATH_MAX];
	char pid_path[AC_PATH_MAX];
	pid_t pid = -1;
	int killed = 0, alive_before = 0, alive_after = 0;
	char *buf;
	struct acb b;
	size_t cap = 256 * 1024;

	if (!id || !ac_task_id_valid(id)) {
		free(id);
		return ac_param_error(out, "app_ctl_task", "BAD_TASK_ID",
				      "action=cancel 需要合法 task_id");
	}
	ac_state_file(progress, sizeof(progress), state, id,
		      ".progress.jsonl");
	ac_state_file(cancel_path, sizeof(cancel_path), state, id, ".cancel");
	ac_state_file(pid_path, sizeof(pid_path), state, id, ".child");
	if (ac_read_pid_file(pid_path, &pid) == 0)
		alive_before = ac_pid_alive(pid);
	if (pid <= 0 && access(progress, F_OK) != 0) {
		free(id);
		ac_param_error(out, "app_ctl_task", "NOT_FOUND",
			       "找不到该 task_id 的运行记录/进度文件");
		return AI_ERR_NOT_FOUND;
	}
	if (pid > 0) {
		kill(-pid, SIGKILL);
		kill(pid, SIGKILL);
		killed = 1;
	}
	{
		int fd = open(cancel_path,
			      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

		if (fd >= 0) {
			(void)!write(fd, "cancel requested\n", 17);
			close(fd);
		}
	}
	usleep(150 * 1000);
	alive_after = ac_pid_alive(pid);
	if (pid > 0 && !alive_after)
		unlink(pid_path);
	ac_ev_cancel_request(progress, id, pid, killed, alive_after);
	ac_audit(state, "app_ctl_task action=cancel task_id=%s pid=%ld "
		 "killed=%d alive_before=%d alive_after=%d", id,
		 (long)pid, killed, alive_before, alive_after);

	buf = malloc(cap);
	if (!buf) {
		free(id);
		return ac_param_error(out, "app_ctl_task", "OOM", "内存不足");
	}
	acb_init(&b, buf, cap);
	acb_printf(&b, "{\"tool\":\"app_ctl_task\",\"action\":\"cancel\","
		   "\"task_id\":");
	acb_json_str(&b, id);
	acb_printf(&b, ",\"pid\":%ld,\"killed\":%s,"
		   "\"pid_alive_before\":%s,\"pid_alive_after\":%s,"
		   "\"cancel_file\":",
		   (long)pid, killed ? "true" : "false",
		   alive_before ? "true" : "false",
		   alive_after ? "true" : "false");
	acb_json_str(&b, cancel_path);
	acb_printf(&b, ",\"progress_path\":");
	acb_json_str(&b, progress);
	acb_printf(&b, ",\"note\":");
	if (!killed)
		acb_json_str(&b, "任务当前无子进程（可能在步骤间隙/未启动），"
			     "已写取消标记；任务下次检查时取消");
	else if (alive_after)
		acb_json_str(&b, "SIGKILL 已发送但进程仍存活（可能为不可杀"
			     "状态），取消标记已写");
	else
		acb_json_str(&b, "进程组已 SIGKILL 且已退出，取消标记已写");
	acb_printf(&b, "}");
	*out = buf;
	free(id);
	return AI_OK;
}

static int ac_tool_task_status(const char *args, size_t alen,
			       const char *state, char **out)
{
	char *id = ac_obj_str(args, alen, "task_id");
	char progress[AC_PATH_MAX], cancel_path[AC_PATH_MAX];
	char pid_path[AC_PATH_MAX];
	pid_t pid = -1;
	int alive = 0, cancel_pending;
	char *tail;
	char *buf;
	struct acb b;
	size_t cap = 256 * 1024;

	if (!id || !ac_task_id_valid(id)) {
		free(id);
		return ac_param_error(out, "app_ctl_task", "BAD_TASK_ID",
				      "action=status 需要合法 task_id");
	}
	ac_state_file(progress, sizeof(progress), state, id,
		      ".progress.jsonl");
	ac_state_file(cancel_path, sizeof(cancel_path), state, id, ".cancel");
	ac_state_file(pid_path, sizeof(pid_path), state, id, ".child");
	if (ac_read_pid_file(pid_path, &pid) == 0)
		alive = ac_pid_alive(pid);
	cancel_pending = (access(cancel_path, F_OK) == 0);
	tail = ac_read_tail_file(progress, 4096);
	if (!tail && pid <= 0) {
		free(id);
		ac_param_error(out, "app_ctl_task", "NOT_FOUND",
			       "找不到该 task_id 的运行记录/进度文件");
		return AI_ERR_NOT_FOUND;
	}
	buf = malloc(cap);
	if (!buf) {
		free(tail);
		free(id);
		return ac_param_error(out, "app_ctl_task", "OOM", "内存不足");
	}
	acb_init(&b, buf, cap);
	acb_printf(&b, "{\"tool\":\"app_ctl_task\",\"action\":\"status\","
		   "\"task_id\":");
	acb_json_str(&b, id);
	acb_printf(&b, ",\"pid\":%ld,\"pid_alive\":%s,"
		   "\"cancel_pending\":%s,\"progress_path\":",
		   (long)pid, alive ? "true" : "false",
		   cancel_pending ? "true" : "false");
	acb_json_str(&b, progress);
	acb_printf(&b, ",\"progress_tail\":");
	acb_json_str(&b, tail ? tail : "");
	acb_printf(&b, "}");
	*out = buf;
	free(tail);
	free(id);
	return AI_OK;
}

static int ac_tool_task(const char *args, size_t alen, char **out)
{
	char state[AC_PATH_MAX];
	char *action;
	int rc;

	if (ac_state_dir(state, sizeof(state)) != 0)
		return ac_param_error(out, "app_ctl_task", "STATE",
				      "无法创建/访问 appctl 状态目录");
	action = ac_obj_str(args, alen, "action");
	if (!action || !action[0]) {
		free(action);
		action = strdup("run");
	}
	if (strcmp(action, "run") == 0)
		rc = ac_tool_task_run(args, alen, state, out);
	else if (strcmp(action, "cancel") == 0)
		rc = ac_tool_task_cancel(args, alen, state, out);
	else if (strcmp(action, "status") == 0)
		rc = ac_tool_task_status(args, alen, state, out);
	else
		rc = ac_param_error(out, "app_ctl_task", "BAD_ACTION",
				    "action 只接受 run|cancel|status");
	free(action);
	return rc;
}

/* ======================================================================
 * 6) 通道入口
 * ====================================================================== */

int exec_app_ctl_channel(const void *tool_v, const char *args_json,
			 char **out)
{
	const struct ai_tool *tool = tool_v;

	*out = NULL;
	if (!tool || !tool->name || !args_json) {
		*out = strdup("ERROR: appctl 调用参数为空");
		return AI_ERR_INVALID_ARG;
	}
	/* W82 V4.5：画像→策略两件走同一 appctl 通道（实现于 app_policy.c） */
	if (strncmp(tool->name, "app_policy_", 11) == 0)
		return exec_app_policy_tool(tool->name, args_json, out);
	if (strcmp(tool->name, "app_ctl_probe") == 0)
		return ac_tool_probe(args_json, strlen(args_json), out);
	if (strcmp(tool->name, "app_ctl_call") == 0)
		return ac_tool_call(args_json, strlen(args_json), out);
	if (strcmp(tool->name, "app_ctl_task") == 0)
		return ac_tool_task(args_json, strlen(args_json), out);
	*out = strdup("ERROR: 未知 appctl 工具（注册表异常）");
	return AI_ERR_INVALID_ARG;
}

int ac_task_id_valid(const char *id)
{
	size_t i, n;

	if (!id)
		return 0;
	n = strlen(id);
	if (n == 0 || n > AC_TASK_ID_MAX)
		return 0;
	if (strcmp(id, ".") == 0 || strcmp(id, "..") == 0)
		return 0;
	for (i = 0; i < n; i++) {
		char c = id[i];

		if (!(isalnum((unsigned char)c) || c == '.' || c == '_' ||
		      c == '-'))
			return 0;
	}
	return 1;
}
