/* SPDX-License-Identifier: GPL-2.0 */
/*
 * acmcp.c - T5e autocondense MCP stdio 薄代理（7 工具）
 *
 * 语义逐条对齐 REF-PY 42466f1 `autocondense/mcp_server.py`；wire 形态由
 * acmcp_data.h 提供（initialize / tools/list 静态数据），工具输出格式化
 * 见 acmcp_fmt_decision / _fmt_snapshots 与各工具包装文案。
 */
#define _POSIX_C_SOURCE 200809L

#include "autocondense/acmcp.h"

#include "autocondense/acconfig.h"
#include "autocondense/acstate.h"

#include "acmcp_data.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define AC_VERSION "0.3.0"
#define DEFAULT_PORT "8762"
#define SERVICE_LOG "/tmp/autocondense_service.log"

/* ------------------------------------------------------------------ */
/* 字符串缓冲                                                         */
/* ------------------------------------------------------------------ */
struct sbuf {
	char *p;
	size_t n, cap;
	int bad;
};

static void sb_init(struct sbuf *b)
{
	memset(b, 0, sizeof(*b));
}

static void sb_reserve(struct sbuf *b, size_t need)
{
	size_t cap;

	if (b->bad)
		return;
	if (b->n + need + 1 <= b->cap)
		return;
	cap = b->cap ? b->cap : 256;
	while (cap < b->n + need + 1)
		cap *= 2;
	{
		char *np = realloc(b->p, cap);

		if (!np) {
			b->bad = 1;
			return;
		}
		b->p = np;
		b->cap = cap;
	}
}

static void sb_addn(struct sbuf *b, const char *s, size_t n)
{
	sb_reserve(b, n);
	if (b->bad)
		return;
	memcpy(b->p + b->n, s, n);
	b->n += n;
	b->p[b->n] = '\0';
}

static void sb_add(struct sbuf *b, const char *s)
{
	sb_addn(b, s, strlen(s));
}

static void sb_addf(struct sbuf *b, const char *fmt, ...)
{
	va_list ap;
	int n;
	char tmp[512];

	va_start(ap, fmt);
	n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if ((size_t)n < sizeof(tmp)) {
		sb_addn(b, tmp, (size_t)n);
		return;
	}
	sb_reserve(b, (size_t)n);
	if (b->bad)
		return;
	va_start(ap, fmt);
	vsnprintf(b->p + b->n, b->cap - b->n, fmt, ap);
	va_end(ap);
	b->n += (size_t)n;
}

static char *sb_take(struct sbuf *b)
{
	if (b->bad) {
		free(b->p);
		return NULL;
	}
	if (!b->p) {
		b->p = malloc(1);
		if (!b->p)
			return NULL;
		b->p[0] = '\0';
	}
	return b->p;
}

static char *xstrdup(const char *s)
{
	size_t n;
	char *p;

	if (!s)
		return NULL;
	n = strlen(s);
	p = malloc(n + 1);
	if (p)
		memcpy(p, s, n + 1);
	return p;
}

/* JSON STR 节点的转义文本（含引号）；调用者 free */
static char *json_str_text(const aik_json *v)
{
	char *out = NULL;
	size_t len = 0;

	if (!v || aik_json_dump(v, &out, &len) != 0) {
		free(out);
		return NULL;
	}
	return out;
}

/* ------------------------------------------------------------------ */
/* 数据目录 / 端口                                                    */
/* ------------------------------------------------------------------ */
int acmcp_data_dir(char *out, size_t outlen)
{
	const char *env = getenv("AUTOCONDENSE_DATA_DIR");
	const char *home;

	if (env && *env) {
		if (env[0] == '~' && (env[1] == '/' || env[1] == '\0')) {
			home = getenv("HOME");
			snprintf(out, outlen, "%s%s", home ? home : ".", env + 1);
		} else {
			snprintf(out, outlen, "%s", env);
		}
		return 0;
	}
	home = getenv("HOME");
	if (!home || !*home)
		home = ".";
	snprintf(out, outlen, "%s/.autocondense", home);
	return 0;
}

static int g_http_timeout = 60;

void ac_http_set_timeout(int seconds)
{
	g_http_timeout = seconds > 0 ? seconds : 60;
}

static int get_port(void)
{
	const char *env = getenv("AUTOCONDENSE_PORT");
	char *end = NULL;
	long v;

	if (!env || !*env)
		return 8762;		/* T9d 改号：8761 归 aikernel-api */
	v = strtol(env, &end, 10);
	if (end == env || *end != '\0' || v <= 0 || v > 65535)
		return 8762;
	return (int)v;
}

static int mkdir_p(const char *path, mode_t mode)
{
	char tmp[2048];
	size_t len;
	size_t i;

	snprintf(tmp, sizeof(tmp), "%s", path);
	len = strlen(tmp);
	while (len > 1 && tmp[len - 1] == '/')
		tmp[--len] = '\0';
	for (i = 1; i <= len; i++) {
		if (tmp[i] == '/' || tmp[i] == '\0') {
			char c = tmp[i];

			tmp[i] = '\0';
			if (mkdir(tmp, mode) != 0 && errno != EEXIST)
				return -1;
			tmp[i] = c;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* HTTP 客户端（每请求新建连接，与 httpx.Client 行为一致）             */
/* ------------------------------------------------------------------ */
void ac_http_resp_free(struct ac_http_resp *r)
{
	if (!r)
		return;
	free(r->body);
	r->body = NULL;
	r->len = 0;
	r->status = 0;
}

static int recv_all(int fd, char **out, size_t *outlen)
{
	struct sbuf b;
	char buf[8192];

	sb_init(&b);
	for (;;) {
		ssize_t n = recv(fd, buf, sizeof(buf), 0);

		if (n == 0)
			break;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			free(b.p);
			return -1;
		}
		sb_addn(&b, buf, (size_t)n);
	}
	*outlen = b.n;
	*out = sb_take(&b);
	return *out ? 0 : -1;
}

int ac_http_call(const char *method, const char *path, const aik_json *body,
		 struct ac_http_resp *out, char *err, size_t errlen)
{
	int fd;
	struct sockaddr_in sa;
	char *body_text = NULL;
	size_t body_len = 0;
	char head[1024];
	int hn;
	char *raw = NULL;
	size_t rawlen = 0;
	char *sep;
	int port = get_port();
	char host[256];
	const char *base = getenv("AUTOCONDENSE_BASE_URL");

	snprintf(host, sizeof(host), "127.0.0.1");
	if (base && strncmp(base, "http://", 7) == 0) {
		const char *hp = base + 7;
		const char *slash = strchr(hp, '/');
		const char *colon = strchr(hp, ':');
		size_t hn = slash ? (size_t)(slash - hp) : strlen(hp);

		if (colon && (!slash || colon < slash)) {
			hn = (size_t)(colon - hp);
			port = atoi(colon + 1);
		}
		if (hn > 0 && hn < sizeof(host)) {
			memcpy(host, hp, hn);
			host[hn] = '\0';
		}
	}
	memset(out, 0, sizeof(*out));
	if (body && aik_json_dump(body, &body_text, &body_len) != 0) {
		snprintf(err, errlen, "JSON 序列化失败");
		return -1;
	}
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		free(body_text);
		snprintf(err, errlen, "socket: %s", strerror(errno));
		return -1;
	}
	{
		struct timeval tv;

		tv.tv_sec = g_http_timeout;
		tv.tv_usec = 0;
		(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	}
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((unsigned short)port);
	if (inet_pton(AF_INET, host, &sa.sin_addr) != 1)
		sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		snprintf(err, errlen, "ConnectError: %s", strerror(errno));
		close(fd);
		free(body_text);
		return -1;
	}
	hn = snprintf(head, sizeof(head),
		      "%s %s HTTP/1.1\r\nHost: %s:%d\r\n"
		      "Content-Type: application/json\r\n"
		      "Content-Length: %zu\r\nConnection: close\r\n\r\n",
		      method, path, host, port, body_len);
	if (hn > 0) {
		size_t off = 0;

		while (off < (size_t)hn) {
			ssize_t n = send(fd, head + off, (size_t)hn - off, 0);

			if (n <= 0) {
				snprintf(err, errlen, "WriteError: %s",
					 strerror(errno));
				close(fd);
				free(body_text);
				return -1;
			}
			off += (size_t)n;
		}
	}
	if (body_text && body_len) {
		size_t off = 0;

		while (off < body_len) {
			ssize_t n = send(fd, body_text + off, body_len - off, 0);

			if (n <= 0) {
				snprintf(err, errlen, "WriteError: %s",
					 strerror(errno));
				close(fd);
				free(body_text);
				return -1;
			}
			off += (size_t)n;
		}
	}
	free(body_text);
	if (recv_all(fd, &raw, &rawlen) != 0) {
		snprintf(err, errlen, "ReadTimeout: recv failed");
		close(fd);
		return -1;
	}
	close(fd);
	if (rawlen < 12 || strncmp(raw, "HTTP/1.", 7) != 0) {
		free(raw);
		snprintf(err, errlen, "ProtocolError: bad response");
		return -1;
	}
	out->status = atoi(raw + 9);
	sep = strstr(raw, "\r\n\r\n");
	if (sep) {
		size_t off = (size_t)(sep - raw) + 4;

		out->len = rawlen - off;
		out->body = malloc(out->len + 1);
		if (!out->body) {
			free(raw);
			snprintf(err, errlen, "out of memory");
			return -1;
		}
		memcpy(out->body, raw + off, out->len);
		out->body[out->len] = '\0';
	} else {
		out->body = xstrdup("");
		out->len = 0;
	}
	free(raw);
	return 0;
}

/* ------------------------------------------------------------------ */
/* 服务探活 / 拉起                                                    */
/* ------------------------------------------------------------------ */
static int health_ok(char *err, size_t errlen)
{
	struct ac_http_resp r;
	aik_json *dom;
	const aik_json *st;
	const aik_json *ver;
	int ok = 0;

	if (ac_http_call("GET", "/health", NULL, &r, err, errlen) != 0)
		return 0;
	if (r.status == 200) {
		dom = aik_json_parse(r.body, r.len, NULL, 0);
		if (dom) {
			st = aik_json_get(dom, "status");
			ver = aik_json_get(dom, "version");
			ok = st && aik_json_typeof(st) == AIK_JSON_STR &&
			     strcmp(aik_json_str(st), "ok") == 0 &&
			     ver && aik_json_typeof(ver) == AIK_JSON_STR &&
			     strcmp(aik_json_str(ver), AC_VERSION) == 0;
			aik_json_free(dom);
		}
	}
	ac_http_resp_free(&r);
	return ok;
}

static int terminate_pid(long pid)
{
	if (pid <= 4 || pid == (long)getpid())
		return 0;
	if (kill((pid_t)pid, SIGTERM) != 0)
		return 0;
	return 1;
}

static long read_pid_file(void)
{
	char dir[1024];
	char path[1200];
	FILE *f;
	char buf[512];
	size_t n;
	long pid = -1;

	acmcp_data_dir(dir, sizeof(dir));
	snprintf(path, sizeof(path), "%s/service.pid", dir);
	f = fopen(path, "rb");
	if (!f)
		return -1;
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	{
		char *p = strstr(buf, "\"pid\"");

		if (p) {
			p = strchr(p, ':');
			if (p)
				pid = strtol(p + 1, NULL, 10);
		}
	}
	return pid;
}

/*
 * spawn_service - 后台拉起同级 autocondensed
 *
 * 路径：AUTOCONDENSE_BIN > <argv0 目录>/autocondensed > PATH 查找。
 * 环境：AC_DATA_DIR = AUTOCONDENSE_DATA_DIR（或 ~/.autocondense）。
 */
static int spawn_service(const char *argv0)
{
	char bin[1200];
	char dir[1024];
	const char *envbin = getenv("AUTOCONDENSE_BIN");
	const char *slash;
	char *argv[3];
	int logfd;
	pid_t pid;

	if (envbin && *envbin) {
		snprintf(bin, sizeof(bin), "%s", envbin);
	} else {
		slash = strrchr(argv0 ? argv0 : "", '/');
		if (slash)
			snprintf(bin, sizeof(bin), "%.*sautocondensed",
				 (int)(slash - argv0 + 1), argv0);
		else
			snprintf(bin, sizeof(bin), "autocondensed");
	}
	acmcp_data_dir(dir, sizeof(dir));
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		int devnull;

		setsid();
		devnull = open("/dev/null", O_RDONLY);
		if (devnull >= 0) {
			dup2(devnull, 0);
			close(devnull);
		}
		logfd = open(SERVICE_LOG, O_WRONLY | O_CREAT | O_APPEND, 0644);
		if (logfd >= 0) {
			dup2(logfd, 1);
			dup2(logfd, 2);
			close(logfd);
		}
		{
			char portstr[16];

			snprintf(portstr, sizeof(portstr), "%d", get_port());
			setenv("AC_DATA_DIR", dir, 1);
			argv[0] = bin;
			argv[1] = "--port";
			argv[2] = portstr;
			execv(bin, argv);
		}
		_exit(127);
	}
	return 0;
}

static int ensure_service(const char *argv0, char *err, size_t errlen)
{
	char tmp[256];
	int i;

	if (health_ok(tmp, sizeof(tmp)))
		return 0;
	/* 旧版本服务：按 pid 文件定点接管（只认 /health 自证的本插件服务） */
	{
		long pid = read_pid_file();

		if (pid > 0)
			(void)terminate_pid(pid);
	}
	if (spawn_service(argv0) != 0) {
		snprintf(err, errlen, "autocondense 服务拉起失败（%s）",
			 SERVICE_LOG);
		return -1;
	}
	for (i = 0; i < 60; i++) {
		struct timespec ts = { 0, 500000000L };

		if (health_ok(tmp, sizeof(tmp)))
			return 0;
		nanosleep(&ts, NULL);
	}
	snprintf(err, errlen,
		 "autocondense 服务 30 秒内未就绪（http://127.0.0.1:%d），"
		 "请查看日志 %s", get_port(), SERVICE_LOG);
	return -1;
}

/* ------------------------------------------------------------------ */
/* _api：返回 0=成功（*out 为解析后的 DOM）；2=业务错误；-1=运行错误   */
/* ------------------------------------------------------------------ */
static int api_call(const char *argv0, const char *method, const char *path,
		    const aik_json *body, aik_json **out, char *err,
		    size_t errlen)
{
	struct ac_http_resp r;
	aik_json *dom;

	*out = NULL;
	if (ensure_service(argv0, err, errlen) != 0)
		return -1;
	if (ac_http_call(method, path, body, &r, err, errlen) != 0)
		return -1;
	if (r.status >= 400) {
		dom = aik_json_parse(r.body, r.len, NULL, 0);
		if (dom) {
			const aik_json *errors = aik_json_get(dom, "errors");

			if (errors && aik_json_typeof(errors) == AIK_JSON_ARR) {
				size_t i, n = aik_json_count(errors);
				struct sbuf b;

				sb_init(&b);
				for (i = 0; i < n; i++) {
					const aik_json *e =
						aik_json_at(errors, i);

					if (i)
						sb_add(&b, "；");
					if (e && aik_json_typeof(e) ==
							 AIK_JSON_STR)
						sb_add(&b, aik_json_str(e));
				}
				snprintf(err, errlen, "%s",
					 b.p ? b.p : "请求失败");
				free(b.p);
				aik_json_free(dom);
				ac_http_resp_free(&r);
				return 2;
			}
			aik_json_free(dom);
		}
		snprintf(err, errlen, "HTTP %d", r.status);
		ac_http_resp_free(&r);
		return -1;
	}
	dom = aik_json_parse(r.body, r.len, NULL, 0);
	if (!dom) {
		snprintf(err, errlen, "服务响应不是 JSON");
		ac_http_resp_free(&r);
		return -1;
	}
	ac_http_resp_free(&r);
	*out = dom;
	return 0;
}

/* ------------------------------------------------------------------ */
/* 会话映射                                                           */
/* ------------------------------------------------------------------ */
static void map_path(char *out, size_t outlen)
{
	char dir[1024];

	acmcp_data_dir(dir, sizeof(dir));
	snprintf(out, outlen, "%s/mcp-session-map.json", dir);
}

static aik_json *load_map(void)
{
	char path[1200];
	FILE *f;
	char *buf;
	long n;
	aik_json *dom = NULL;

	map_path(path, sizeof(path));
	f = fopen(path, "rb");
	if (!f)
		return aik_json_new_obj();
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (n < 0 || n > 1024 * 1024) {
		fclose(f);
		return aik_json_new_obj();
	}
	buf = malloc((size_t)n + 1);
	if (!buf) {
		fclose(f);
		return aik_json_new_obj();
	}
	n = (long)fread(buf, 1, (size_t)n, f);
	fclose(f);
	buf[n] = '\0';
	dom = aik_json_parse(buf, (size_t)n, NULL, 0);
	free(buf);
	if (!dom || aik_json_typeof(dom) != AIK_JSON_OBJ) {
		aik_json_free(dom);
		return aik_json_new_obj();
	}
	return dom;
}

static int save_map(const aik_json *map)
{
	char path[1200];
	struct sbuf b;
	size_t i, n;
	int rc;

	map_path(path, sizeof(path));
	{
		char dir[1024];

		acmcp_data_dir(dir, sizeof(dir));
		(void)mkdir_p(dir, 0755);
	}
	n = aik_json_count(map);
	if (n == 0) {
		return ac_atomic_write_text(path, "{}\n", 3);
	}
	sb_init(&b);
	sb_add(&b, "{\n");
	for (i = 0; i < n; i++) {
		const char *k = aik_json_key_at(map, i);
		const aik_json *v = aik_json_val_at(map, i);
		char *vt = json_str_text(v);
		char *kt = NULL;
		aik_json *kn = aik_json_new_str(k);

		if (kn) {
			kt = json_str_text(kn);
			aik_json_free(kn);
		}
		if (!vt || !kt) {
			free(vt);
			free(kt);
			free(b.p);
			return -1;
		}
		sb_addf(&b, "  %s: %s%s\n", kt, vt, i + 1 < n ? "," : "");
		free(vt);
		free(kt);
	}
	sb_add(&b, "}\n");
	if (b.bad || !b.p)
		return -1;
	rc = ac_atomic_write_text(path, b.p, b.n);
	free(b.p);
	return rc;
}

static int random_hex4(char out[5])
{
	unsigned char buf[2];
	int fd = open("/dev/urandom", O_RDONLY);
	size_t i;

	if (fd >= 0) {
		ssize_t n = read(fd, buf, sizeof(buf));

		close(fd);
		if (n == (ssize_t)sizeof(buf)) {
			for (i = 0; i < sizeof(buf); i++)
				snprintf(out + i * 2, 3, "%02x", buf[i]);
			return 0;
		}
	}
	{
		unsigned long v = (unsigned long)time(NULL) ^
				  ((unsigned long)getpid() << 8);

		snprintf(out, 5, "%04lx", v & 0xffffUL);
	}
	return 0;
}

/*
 * resolve_session - 显式 session_id 优先；否则按 cwd 的 project_hash 复用/创建
 *
 * 返回 0 成功（sid 写入 out），-1 失败（err 为 ValueError/ApiError 文案）。
 */
static int resolve_session(const char *argv0, const char *cwd,
			   const char *session_id, char *out, size_t outlen,
			   char *err, size_t errlen)
{
	char hash[11];
	char sid[64];
	char hex4[8];
	aik_json *map;
	const aik_json *hit;
	aik_json *body;
	aik_json *resp = NULL;
	char tmp[256];

	if (session_id && *session_id) {
		snprintf(out, outlen, "%s", session_id);
		return 0;
	}
	if (!cwd || !*cwd) {
		snprintf(err, errlen,
			 "无法确定会话：请传 cwd（你当前的工作目录），或显式传 session_id");
		return -1;
	}
	if (ac_project_hash(cwd, hash) != 0) {
		snprintf(err, errlen, "无法计算工作目录哈希：%s", cwd);
		return -1;
	}
	map = load_map();
	hit = aik_json_get(map, hash);
	if (hit && aik_json_typeof(hit) == AIK_JSON_STR) {
		snprintf(out, outlen, "%s", aik_json_str(hit));
		aik_json_free(map);
		return 0;
	}
	random_hex4(hex4);
	snprintf(sid, sizeof(sid), "mcp-%.8s-%s", hash, hex4);
	body = aik_json_new_obj();
	if (!body ||
	    aik_json_obj_put(body, "session_id",
			     aik_json_new_str(sid)) != 0 ||
	    aik_json_obj_put(body, "cwd", aik_json_new_str(cwd)) != 0) {
		aik_json_free(body);
		aik_json_free(map);
		snprintf(err, errlen, "out of memory");
		return -1;
	}
	if (api_call(argv0, "POST", "/session/start", body, &resp, tmp,
		     sizeof(tmp)) != 0) {
		aik_json_free(body);
		aik_json_free(map);
		snprintf(err, errlen, "%s", tmp);
		return -1;
	}
	aik_json_free(resp);
	aik_json_free(body);
	{
		aik_json *v = aik_json_new_str(sid);

		if (!v || aik_json_obj_set(map, hash, v) != 0) {
			aik_json_free(v);
			aik_json_free(map);
			snprintf(err, errlen, "out of memory");
			return -1;
		}
	}
	(void)save_map(map);
	aik_json_free(map);
	snprintf(out, outlen, "%s", sid);
	return 0;
}

/* ------------------------------------------------------------------ */
/* 格式化                                                             */
/* ------------------------------------------------------------------ */
static const aik_json *getj(const aik_json *o, const char *k)
{
	return o ? aik_json_get(o, k) : NULL;
}

/* Python str() 的常用分支（str/bool/int/num/null） */
static char *py_str(const aik_json *v)
{
	char buf[64];

	if (!v)
		return xstrdup("None");
	switch (aik_json_typeof(v)) {
	case AIK_JSON_STR:
		return xstrdup(aik_json_str(v));
	case AIK_JSON_BOOL:
		return xstrdup(aik_json_bool(v) ? "True" : "False");
	case AIK_JSON_INT:
		snprintf(buf, sizeof(buf), "%lld", aik_json_int(v));
		return xstrdup(buf);
	case AIK_JSON_NUM:
		{
			char n[64];

			if (aik_json_dtoa(aik_json_num(v), n, sizeof(n)) < 0)
				return xstrdup("0.0");
			return xstrdup(n);
		}
	case AIK_JSON_NULL:
		return xstrdup("None");
	default:
		return xstrdup("");
	}
}

static char *str_arg(const aik_json *args, const char *key,
		     const char *def)
{
	const aik_json *v = getj(args, key);

	if (!v || aik_json_typeof(v) == AIK_JSON_NULL)
		return xstrdup(def);
	return py_str(v);
}

char *acmcp_fmt_decision(const aik_json *d)
{
	struct sbuf b;
	const aik_json *sig = getj(d, "signals");
	const aik_json *should = getj(d, "should");
	const char *trigger;
	const char *reason;
	const char *hint;

	sb_init(&b);
	trigger = getj(d, "trigger") && aik_json_typeof(getj(d, "trigger")) ==
						 AIK_JSON_STR
			  ? aik_json_str(getj(d, "trigger"))
			  : NULL;
	sb_addf(&b, "判定：%s",
		should && aik_json_typeof(should) == AIK_JSON_STR
			? aik_json_str(should) : "?");
	if (trigger)
		sb_addf(&b, "（触发：%s）", trigger);
	if (should && aik_json_typeof(should) == AIK_JSON_STR &&
	    strcmp(aik_json_str(should), "NO") == 0)
		sb_add(&b, "，暂不压缩");
	else {
		const aik_json *u = getj(d, "urgency");

		if (u && aik_json_typeof(u) == AIK_JSON_STR &&
		    strcmp(aik_json_str(u), "urgent") == 0)
			sb_add(&b, "，紧急（水位危急）");
	}
	reason = getj(d, "reason") && aik_json_typeof(getj(d, "reason")) ==
					      AIK_JSON_STR
			 ? aik_json_str(getj(d, "reason")) : NULL;
	if (reason && *reason)
		sb_addf(&b, "\n原因：%s", reason);
	{
		struct sbuf bits;
		int any = 0;

		sb_init(&bits);
		if (getj(sig, "plan_total")) {
			any = 1;
			sb_addf(&bits, "计划 %lld/%lld 完成、进行中 %lld",
				(long long)aik_json_int(
					getj(sig, "plan_completed")),
				(long long)aik_json_int(
					getj(sig, "plan_total")),
				(long long)aik_json_int(
					getj(sig, "plan_in_progress")));
		}
		if (getj(sig, "turns_since_condense") &&
		    aik_json_typeof(getj(sig, "turns_since_condense")) !=
			    AIK_JSON_NULL) {
			if (any)
				sb_add(&bits, "；");
			any = 1;
			sb_addf(&bits, "距上次压缩 %lld 轮",
				(long long)aik_json_int(
					getj(sig, "turns_since_condense")));
		}
		if (getj(sig, "est_tokens") &&
		    aik_json_typeof(getj(sig, "est_tokens")) != AIK_JSON_NULL) {
			if (any)
				sb_add(&bits, "；");
			any = 1;
			sb_addf(&bits, "估算 %lld token",
				(long long)aik_json_int(
					getj(sig, "est_tokens")));
		}
		if (getj(sig, "water_level") &&
		    aik_json_typeof(getj(sig, "water_level")) != AIK_JSON_NULL) {
			if (any)
				sb_add(&bits, "；");
			any = 1;
			sb_addf(&bits, "水位 %.0f%%",
				aik_json_num(getj(sig, "water_level")) * 100.0);
		}
		if (getj(sig, "cooldown_active") &&
		    aik_json_typeof(getj(sig, "cooldown_active")) ==
			    AIK_JSON_BOOL &&
		    aik_json_bool(getj(sig, "cooldown_active"))) {
			if (any)
				sb_add(&bits, "；");
			any = 1;
			sb_add(&bits, "冷却中");
		}
		if (any)
			sb_addf(&b, "\n信号：%s", bits.p ? bits.p : "");
		free(bits.p);
	}
	{
		const aik_json *fields = getj(getj(d, "judgment_form"),
					      "fields");

		if (fields && aik_json_typeof(fields) == AIK_JSON_OBJ &&
		    aik_json_count(fields) > 0) {
			size_t i, n = aik_json_count(fields);

			sb_add(&b, "\n判定表字段：");
			for (i = 0; i < n; i++) {
				if (i)
					sb_add(&b, "、");
				sb_add(&b, aik_json_key_at(fields, i));
			}
		}
	}
	hint = getj(d, "action_hint") &&
			       aik_json_typeof(getj(d, "action_hint")) ==
				       AIK_JSON_STR
		       ? aik_json_str(getj(d, "action_hint")) : NULL;
	if (hint && *hint)
		sb_addf(&b, "\n动作建议：%s", hint);
	return sb_take(&b);
}

char *acmcp_fmt_snapshots(const aik_json *snaps)
{
	struct sbuf b;
	size_t i, n;

	sb_init(&b);
	n = aik_json_count(snaps);
	for (i = 0; i < n; i++) {
		const aik_json *s = aik_json_at(snaps, i);
		const aik_json *ts = getj(s, "ts");
		const aik_json *tr = getj(s, "trigger");
		const aik_json *ti = getj(s, "title");
		const aik_json *cc = getj(s, "char_count");

		if (i)
			sb_add(&b, "\n");
		sb_addf(&b, "%zu. %s [%s] %s（%lld 字）", i + 1,
			ts && aik_json_typeof(ts) == AIK_JSON_STR
				? aik_json_str(ts) : "None",
			tr && aik_json_typeof(tr) == AIK_JSON_STR
				? aik_json_str(tr) : "None",
			ti && aik_json_typeof(ti) == AIK_JSON_STR
				? aik_json_str(ti) : "None",
			(long long)aik_json_int(cc));
	}
	return sb_take(&b);
}

/* ------------------------------------------------------------------ */
/* 工具实现                                                           */
/* ------------------------------------------------------------------ */
/* condense_check */
static char *tool_check(const char *argv0, const aik_json *args)
{
	char cwd[1024], sidarg[256], sid[256], err[512];
	struct sbuf path;
	aik_json *d = NULL;
	char out[2048];

	{
		char *c = str_arg(args, "cwd", "");
		char *s = str_arg(args, "session_id", "");

		snprintf(cwd, sizeof(cwd), "%s", c);
		snprintf(sidarg, sizeof(sidarg), "%s", s);
		free(c);
		free(s);
	}
	if (resolve_session(argv0, cwd, sidarg, sid, sizeof(sid), err,
			    sizeof(err)) != 0) {
		snprintf(out, sizeof(out), "检查失败：%s", err);
		return xstrdup(out);
	}
	sb_init(&path);
	sb_add(&path, "/check?session_id=");
	{
		const unsigned char *p = (const unsigned char *)sid;

		for (; *p; p++) {
			if ((*p >= 'a' && *p <= 'z') ||
			    (*p >= 'A' && *p <= 'Z') ||
			    (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' ||
			    *p == '.')
				sb_addn(&path, (const char *)p, 1);
			else
				sb_addf(&path, "%%%02X", *p);
		}
	}
	if (api_call(argv0, "GET", path.p ? path.p : "/check", NULL, &d, err,
		     sizeof(err)) != 0) {
		free(path.p);
		snprintf(out, sizeof(out), "检查失败：%s", err);
		return xstrdup(out);
	}
	free(path.p);
	{
		char *r = acmcp_fmt_decision(d);

		aik_json_free(d);
		return r;
	}
}

/* condense_report */
static char *tool_report(const char *argv0, const aik_json *args)
{
	char cwd[1024], sidarg[256], sid[256], err[512];
	char *plan_raw = str_arg(args, "plan_items", "");
	aik_json *items;
	aik_json *body = NULL;
	aik_json *d = NULL;
	struct sbuf out;
	size_t i, n;

	items = aik_json_parse(plan_raw, strlen(plan_raw), NULL, 0);
	free(plan_raw);
	if (!items) {
		return xstrdup(
			"plan_items 不是合法 JSON。请传紧凑 JSON 数组字符串，例如："
			"[{\"title\":\"任务A\",\"status\":\"completed\"},"
			"{\"title\":\"任务B\",\"status\":\"pending\"}]");
	}
	if (aik_json_typeof(items) != AIK_JSON_ARR) {
		aik_json_free(items);
		return xstrdup(
			"plan_items 必须是 JSON 数组（每项 {\"title\":..., \"status\":...}）。");
	}
	{
		char *c = str_arg(args, "cwd", "");
		char *s = str_arg(args, "session_id", "");

		snprintf(cwd, sizeof(cwd), "%s", c);
		snprintf(sidarg, sizeof(sidarg), "%s", s);
		free(c);
		free(s);
	}
	if (resolve_session(argv0, cwd, sidarg, sid, sizeof(sid), err,
			    sizeof(err)) != 0) {
		aik_json_free(items);
		sb_init(&out);
		sb_addf(&out, "上报失败：%s", err);
		return sb_take(&out);
	}
	body = aik_json_new_obj();
	if (!body ||
	    aik_json_obj_put(body, "session_id",
			     aik_json_new_str(sid)) != 0 ||
	    aik_json_obj_put(body, "cwd", aik_json_new_str(cwd)) != 0) {
		aik_json_free(body);
		aik_json_free(items);
		return xstrdup("上报失败：out of memory");
	}
	{
		aik_json *arr = aik_json_new_arr();
		size_t src_n = aik_json_count(items);

		if (!arr) {
			aik_json_free(body);
			aik_json_free(items);
			return xstrdup("上报失败：out of memory");
		}
		for (i = 0; i < src_n; i++) {
			const aik_json *it = aik_json_at(items, i);
			aik_json *row;
			char *title;
			char *status;

			if (!it || aik_json_typeof(it) != AIK_JSON_OBJ)
				continue;
			{
				const aik_json *tv = getj(it, "title");
				const aik_json *sv = getj(it, "status");

				title = tv ? py_str(tv) : xstrdup("");
				status = sv ? py_str(sv) : xstrdup("pending");
			}
			row = aik_json_new_obj();
			if (!row ||
			    aik_json_obj_put(row, "title",
					     aik_json_new_str(title)) != 0 ||
			    aik_json_obj_put(row, "status",
					     aik_json_new_str(status)) != 0) {
				aik_json_free(row);
				free(title);
				free(status);
				aik_json_free(arr);
				aik_json_free(body);
				aik_json_free(items);
				return xstrdup("上报失败：out of memory");
			}
			free(title);
			free(status);
			aik_json_arr_push(arr, row);
		}
		n = aik_json_count(arr);
		if (aik_json_obj_put(body, "plan_items", arr) != 0) {
			aik_json_free(arr);
			aik_json_free(body);
			aik_json_free(items);
			return xstrdup("上报失败：out of memory");
		}
	}
	aik_json_free(items);
	if (api_call(argv0, "POST", "/report", body, &d, err, sizeof(err)) != 0) {
		aik_json_free(body);
		sb_init(&out);
		sb_addf(&out, "上报失败：%s", err);
		return sb_take(&out);
	}
	aik_json_free(body);
	{
		char *fmt = acmcp_fmt_decision(d);

		aik_json_free(d);
		sb_init(&out);
		sb_addf(&out, "已上报 %zu 项计划（会话 %s）。\n%s", n, sid,
			fmt ? fmt : "");
		free(fmt);
		return sb_take(&out);
	}
}

/* condense_judge */
static char *tool_judge(const char *argv0, const aik_json *args)
{
	char cwd[1024], sidarg[256], sid[256], err[512];
	char *impact = str_arg(args, "impact", "");
	char *impact_reason = str_arg(args, "impact_reason", "");
	char *reason = str_arg(args, "reason", "");
	const aik_json *tf = getj(args, "task_finished");
	const aik_json *sc = getj(args, "safe_to_compress");
	aik_json *body = NULL;
	aik_json *verdict = NULL;
	aik_json *d = NULL;
	struct sbuf out;
	int rc;

	{
		char *c = str_arg(args, "cwd", "");
		char *s = str_arg(args, "session_id", "");

		snprintf(cwd, sizeof(cwd), "%s", c);
		snprintf(sidarg, sizeof(sidarg), "%s", s);
		free(c);
		free(s);
	}
	if (resolve_session(argv0, cwd, sidarg, sid, sizeof(sid), err,
			    sizeof(err)) != 0) {
		sb_init(&out);
		sb_addf(&out, "判定提交失败：%s", err);
		free(impact);
		free(impact_reason);
		free(reason);
		return sb_take(&out);
	}
	verdict = aik_json_new_obj();
	if (!verdict ||
	    aik_json_obj_put(verdict, "task_finished",
			     aik_json_new_bool(tf && aik_json_typeof(tf) ==
							    AIK_JSON_BOOL
						       ? aik_json_bool(tf) : 0)) !=
		    0 ||
	    aik_json_obj_put(verdict, "impact",
			     aik_json_new_str(impact)) != 0 ||
	    aik_json_obj_put(verdict, "impact_reason",
			     aik_json_new_str(impact_reason)) != 0 ||
	    aik_json_obj_put(verdict, "safe_to_compress",
			     aik_json_new_bool(sc && aik_json_typeof(sc) ==
							    AIK_JSON_BOOL
						       ? aik_json_bool(sc) : 0)) !=
		    0 ||
	    aik_json_obj_put(verdict, "reason",
			     aik_json_new_str(reason)) != 0) {
		aik_json_free(verdict);
		free(impact);
		free(impact_reason);
		free(reason);
		return xstrdup("判定提交失败：out of memory");
	}
	free(impact);
	free(impact_reason);
	free(reason);
	body = aik_json_new_obj();
	if (!body ||
	    aik_json_obj_put(body, "session_id",
			     aik_json_new_str(sid)) != 0 ||
	    aik_json_obj_put(body, "cwd", aik_json_new_str(cwd)) != 0 ||
	    aik_json_obj_put(body, "verdict", verdict) != 0) {
		aik_json_free(body);
		aik_json_free(verdict);
		return xstrdup("判定提交失败：out of memory");
	}
	rc = api_call(argv0, "POST", "/judge", body, &d, err, sizeof(err));
	aik_json_free(body);
	sb_init(&out);
	if (rc != 0) {
		if (rc == 2) {
			/* ApiError：逐条列出 */
			char *copy = xstrdup(err);
			char *save = NULL;
			char *tok = strtok_r(copy, "；", &save);

			sb_add(&out,
			       "判定提交失败：\n");
			while (tok) {
				sb_addf(&out, "- %s\n", tok);
				tok = strtok_r(NULL, "；", &save);
			}
			sb_add(&out,
			       "请修正后重新调用 condense_judge。");
			free(copy);
		} else {
			sb_addf(&out, "判定提交失败：%s", err);
		}
		return sb_take(&out);
	}
	{
		const aik_json *dec = getj(d, "decision");
		const aik_json *urg = getj(d, "urgency");
		const aik_json *rsn = getj(d, "reason");
		const aik_json *def = getj(d, "defer_until_turn");
		const aik_json *hint = getj(d, "action_hint");

		sb_addf(&out, "已提交判定（会话 %s）。\n判定结果：%s",
			sid,
			dec && aik_json_typeof(dec) == AIK_JSON_STR
				? aik_json_str(dec) : "?");
		if (urg && aik_json_typeof(urg) == AIK_JSON_STR &&
		    *aik_json_str(urg))
			sb_addf(&out, "（%s 档）", aik_json_str(urg));
		if (rsn && aik_json_typeof(rsn) == AIK_JSON_STR &&
		    *aik_json_str(rsn))
			sb_addf(&out, "\n原因：%s", aik_json_str(rsn));
		if (def && aik_json_typeof(def) != AIK_JSON_NULL)
			sb_addf(&out, "\n延迟窗口：第 %lld 轮后自动重新评估",
				(long long)aik_json_int(def));
		if (hint && aik_json_typeof(hint) == AIK_JSON_STR &&
		    *aik_json_str(hint))
			sb_addf(&out, "\n动作建议：%s", aik_json_str(hint));
	}
	aik_json_free(d);
	return sb_take(&out);
}

/* condense_begin */
static char *tool_begin(const char *argv0, const aik_json *args)
{
	char cwd[1024], sidarg[256], sid[256], err[512];
	aik_json *body = NULL;
	aik_json *d = NULL;
	struct sbuf out;

	{
		char *c = str_arg(args, "cwd", "");
		char *s = str_arg(args, "session_id", "");

		snprintf(cwd, sizeof(cwd), "%s", c);
		snprintf(sidarg, sizeof(sidarg), "%s", s);
		free(c);
		free(s);
	}
	sb_init(&out);
	if (resolve_session(argv0, cwd, sidarg, sid, sizeof(sid), err,
			    sizeof(err)) != 0) {
		sb_addf(&out, "进入压缩流程失败：%s", err);
		return sb_take(&out);
	}
	body = aik_json_new_obj();
	if (!body ||
	    aik_json_obj_put(body, "session_id",
			     aik_json_new_str(sid)) != 0 ||
	    aik_json_obj_put(body, "cwd", aik_json_new_str(cwd)) != 0) {
		aik_json_free(body);
		return xstrdup("进入压缩流程失败：out of memory");
	}
	if (api_call(argv0, "POST", "/begin", body, &d, err, sizeof(err)) != 0) {
		aik_json_free(body);
		sb_addf(&out, "进入压缩流程失败：%s", err);
		return sb_take(&out);
	}
	aik_json_free(body);
	{
		const aik_json *guid = getj(d, "guidance");
		const aik_json *req = getj(d, "required_sections");
		const aik_json *tmpl = getj(d, "template");
		size_t i, n = aik_json_count(req);

		sb_addf(&out,
			"已进入压缩流程（会话 %s，condensing=true）。"
			"请把下面的模板复制出来，基于当前会话内容逐节填写：\n"
			"\n【填写指引】\n%s\n\n【必填章节】\n",
			sid,
			guid && aik_json_typeof(guid) == AIK_JSON_STR
				? aik_json_str(guid) : "");
		for (i = 0; i < n; i++) {
			const aik_json *e = aik_json_at(req, i);

			if (i)
				sb_add(&out, "、");
			if (e && aik_json_typeof(e) == AIK_JSON_STR)
				sb_add(&out, aik_json_str(e));
		}
		sb_addf(&out, "\n\n【模板】\n%s\n\n"
			      "填完后把整份 markdown 作为 digest_md 调用 "
			      "condense_commit 提交。",
			tmpl && aik_json_typeof(tmpl) == AIK_JSON_STR
				? aik_json_str(tmpl) : "");
	}
	aik_json_free(d);
	return sb_take(&out);
}

/* condense_commit */
static char *tool_commit(const char *argv0, const aik_json *args)
{
	char cwd[1024], sidarg[256], sid[256], err[512];
	char *digest = str_arg(args, "digest_md", "");
	char *trigger = str_arg(args, "trigger", "");
	aik_json *body = NULL;
	aik_json *d = NULL;
	struct sbuf out;
	int rc;

	{
		char *c = str_arg(args, "cwd", "");
		char *s = str_arg(args, "session_id", "");

		snprintf(cwd, sizeof(cwd), "%s", c);
		snprintf(sidarg, sizeof(sidarg), "%s", s);
		free(c);
		free(s);
	}
	if (resolve_session(argv0, cwd, sidarg, sid, sizeof(sid), err,
			    sizeof(err)) != 0) {
		free(digest);
		free(trigger);
		sb_init(&out);
		sb_addf(&out, "提交失败：%s", err);
		return sb_take(&out);
	}
	body = aik_json_new_obj();
	if (!body ||
	    aik_json_obj_put(body, "session_id",
			     aik_json_new_str(sid)) != 0 ||
	    aik_json_obj_put(body, "cwd", aik_json_new_str(cwd)) != 0 ||
	    aik_json_obj_put(body, "digest_md",
			     aik_json_new_str(digest)) != 0) {
		aik_json_free(body);
		free(digest);
		free(trigger);
		return xstrdup("提交失败：out of memory");
	}
	if (trigger && *trigger)
		(void)aik_json_obj_put(body, "trigger",
				       aik_json_new_str(trigger));
	free(digest);
	free(trigger);
	rc = api_call(argv0, "POST", "/commit", body, &d, err, sizeof(err));
	aik_json_free(body);
	sb_init(&out);
	if (rc != 0) {
		if (rc == 2) {
			char *copy = xstrdup(err);
			char *save = NULL;
			char *tok = strtok_r(copy, "；", &save);

			sb_add(&out, "提交失败，摘要校验未通过：\n");
			while (tok) {
				sb_addf(&out, "- %s\n", tok);
				tok = strtok_r(NULL, "；", &save);
			}
			sb_add(&out,
			       "请修正 digest_md 后重新调用 condense_commit"
			       "（必填章节标题必须原样保留）。");
			free(copy);
		} else {
			sb_addf(&out, "提交失败：%s", err);
		}
		return sb_take(&out);
	}
	{
		const aik_json *sme = getj(d, "sme");
		const aik_json *stored = getj(sme, "stored");
		const aik_json *mid = getj(sme, "memory_id");
		const aik_json *serr = getj(sme, "error");
		const aik_json *segw = getj(d, "segments_written");
		const aik_json *spath = getj(d, "snapshot_path");
		const aik_json *next = getj(d, "next_instruction");

		sb_addf(&out, "快照已保存：%s\n",
			spath && aik_json_typeof(spath) == AIK_JSON_STR
				? aik_json_str(spath) : "None");
		if (stored && aik_json_typeof(stored) == AIK_JSON_BOOL &&
		    aik_json_bool(stored)) {
			if (segw && aik_json_int(segw))
				sb_addf(&out,
					"SME 记忆入库：成功（分段画像 %lld 条，"
					"首条 memory_id=%s）\n",
					(long long)aik_json_int(segw),
					mid && aik_json_typeof(mid) !=
							 AIK_JSON_NULL
						? (aik_json_typeof(mid) ==
								   AIK_JSON_STR
							   ? aik_json_str(mid)
							   : "")
						: "None");
			else
				sb_addf(&out,
					"SME 记忆入库：成功（整篇，"
					"memory_id=%s）\n",
					mid && aik_json_typeof(mid) !=
							 AIK_JSON_NULL
						? (aik_json_typeof(mid) ==
								   AIK_JSON_STR
							   ? aik_json_str(mid)
							   : "")
						: "None");
		} else {
			sb_addf(&out,
				"SME 记忆入库：未入库（%s）——不影响本地快照\n",
				serr && aik_json_typeof(serr) == AIK_JSON_STR &&
						*aik_json_str(serr)
					? aik_json_str(serr)
					: "SME 服务不在线");
		}
		sb_addf(&out, "下一步：%s",
			next && aik_json_typeof(next) == AIK_JSON_STR
				? aik_json_str(next) : "None");
	}
	aik_json_free(d);
	return sb_take(&out);
}

/* condense_restore */
static char *tool_restore(const char *argv0, const aik_json *args)
{
	char cwd[1024];
	char *query = str_arg(args, "query", "");
	char *topn_s = str_arg(args, "top_n", "3");
	struct sbuf path;
	aik_json *d = NULL;
	char err[512];
	struct sbuf out;
	long topn = strtol(topn_s, NULL, 10);

	free(topn_s);
	{
		char *c = str_arg(args, "cwd", "");

		snprintf(cwd, sizeof(cwd), "%s", c);
		free(c);
	}
	if (!cwd[0]) {
		free(query);
		return xstrdup(
			"恢复失败：请传 cwd（你当前的工作目录），用于定位该项目的快照。");
	}
	sb_init(&path);
	sb_add(&path, "/restore?cwd=");
	{
		const unsigned char *p = (const unsigned char *)cwd;

		for (; *p; p++) {
			if ((*p >= 'a' && *p <= 'z') ||
			    (*p >= 'A' && *p <= 'Z') ||
			    (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' ||
			    *p == '.' || *p == '/' || *p == ':')
				sb_addn(&path, (const char *)p, 1);
			else
				sb_addf(&path, "%%%02X", *p);
		}
	}
	sb_addf(&path, "&top_n=%ld", topn > 0 ? topn : 3);
	if (query && *query) {
		const unsigned char *p = (const unsigned char *)query;

		sb_add(&path, "&query=");
		for (; *p; p++) {
			if ((*p >= 'a' && *p <= 'z') ||
			    (*p >= 'A' && *p <= 'Z') ||
			    (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' ||
			    *p == '.' || *p == '~')
				sb_addn(&path, (const char *)p, 1);
			else
				sb_addf(&path, "%%%02X", *p);
		}
	}
	free(query);
	if (api_call(argv0, "GET", path.p, NULL, &d, err, sizeof(err)) != 0) {
		free(path.p);
		sb_init(&out);
		sb_addf(&out, "恢复失败：%s", err);
		return sb_take(&out);
	}
	free(path.p);
	{
		const aik_json *snaps = getj(d, "snapshots");
		const aik_json *proj = getj(d, "project");
		size_t ns = aik_json_count(snaps);

		sb_init(&out);
		if (ns == 0) {
			sb_addf(&out, "项目 %s 还没有历史快照，无需恢复。",
				proj && aik_json_typeof(proj) == AIK_JSON_STR
					? aik_json_str(proj) : "");
			aik_json_free(d);
			return sb_take(&out);
		}
		sb_addf(&out, "项目 %s 的历史快照（最新在前）：\n",
			proj && aik_json_typeof(proj) == AIK_JSON_STR
				? aik_json_str(proj) : "");
		{
			char *list = acmcp_fmt_snapshots(snaps);

			sb_add(&out, list ? list : "");
			free(list);
		}
		sb_add(&out,
		       "\n\n【恢复内容（按优先级装配：未完成/恢复指针优先）】\n");
		{
			const aik_json *restore = getj(d, "restore");
			const aik_json *text = getj(restore, "text");
			const aik_json *tr = getj(restore, "truncated");
			const aik_json *ff = getj(restore, "full_file");

			sb_add(&out, text && aik_json_typeof(text) ==
						 AIK_JSON_STR
					? aik_json_str(text) : "");
			if (tr && aik_json_typeof(tr) == AIK_JSON_BOOL &&
			    aik_json_bool(tr))
				sb_addf(&out,
					"\n（以上内容已截断，完整快照：%s，"
					"需要时用 Read 工具读取）",
					ff && aik_json_typeof(ff) ==
							 AIK_JSON_STR
						? aik_json_str(ff) : "None");
		}
		{
			const aik_json *acts = getj(d, "next_actions");

			if (aik_json_count(acts) > 0) {
				size_t i, n = aik_json_count(acts);

				sb_add(&out, "\n恢复后动作：");
				for (i = 0; i < n; i++) {
					const aik_json *a =
						aik_json_at(acts, i);

					if (i)
						sb_add(&out, "；");
					if (a && aik_json_typeof(a) ==
							 AIK_JSON_STR)
						sb_add(&out, aik_json_str(a));
				}
			}
		}
		{
			const aik_json *hits = getj(d, "sme_results");
			size_t i, n = aik_json_count(hits);

			if (n > 0) {
				sb_add(&out, "\n\n【SME 记忆检索】");
				for (i = 0; i < n; i++) {
					const aik_json *m =
						aik_json_at(hits, i);
					const aik_json *id = getj(m, "id");
					const aik_json *score =
						getj(m, "score");
					const aik_json *txt =
						getj(m, "text");

					sb_addf(&out,
						"\n[%s] score=%.2f %s",
						id ? aik_json_str(id) : "None",
						aik_json_num(score),
						txt ? aik_json_str(txt) : "");
				}
			}
		}
	}
	aik_json_free(d);
	return sb_take(&out);
}

/* condense_status */
static char *tool_status(const char *argv0)
{
	aik_json *d = NULL;
	char err[512];
	struct sbuf out;
	const aik_json *cfg;
	const aik_json *sessions;
	const aik_json *events;
	const aik_json *en;
	const aik_json *cfg_en;
	int enabled;
	size_t ns, ne, i, show;

	if (api_call(argv0, "GET", "/status", NULL, &d, err, sizeof(err)) != 0) {
		sb_init(&out);
		sb_addf(&out, "状态查询失败：%s", err);
		return sb_take(&out);
	}
	cfg = getj(d, "config");
	sessions = getj(d, "sessions");
	events = getj(d, "recent_events");
	en = getj(d, "enabled");
	cfg_en = getj(cfg, "enabled");
	enabled = en && aik_json_typeof(en) == AIK_JSON_BOOL
			  ? aik_json_bool(en)
			  : (cfg_en && aik_json_typeof(cfg_en) == AIK_JSON_BOOL
				     ? aik_json_bool(cfg_en) : 0);
	ns = aik_json_count(sessions);
	ne = aik_json_count(events);
	show = ns > 5 ? 5 : ns;
	sb_init(&out);
	sb_addf(&out, "autocondense 服务：%s，会话 %zu 个，最近事件 %zu 条。",
		enabled ? "启用（全自动）"
			: "已关闭（enabled=false，不干预）", ns, ne);
	for (i = 0; i < show; i++) {
		const aik_json *s = aik_json_at(sessions, i);
		const aik_json *sid = getj(s, "session_id");
		const aik_json *cwd = getj(s, "cwd");
		const aik_json *pc = getj(s, "plan_completed");
		const aik_json *pt = getj(s, "plan_total");
		const aik_json *tsc = getj(s, "turns_since_condense");
		const aik_json *lj = getj(s, "last_judge");
		const aik_json *def = getj(s, "defer_until_turn");

		sb_addf(&out, "\n- %s 项目 %s 计划 %lld/%lld 完成 轮次 %lld",
			sid && aik_json_typeof(sid) == AIK_JSON_STR
				? aik_json_str(sid) : "",
			cwd && aik_json_typeof(cwd) == AIK_JSON_STR
				? aik_json_str(cwd) : "",
			(long long)aik_json_int(pc),
			(long long)aik_json_int(pt),
			(long long)aik_json_int(tsc));
		if (lj) {
			const aik_json *res = getj(lj, "result");

			if (res && aik_json_typeof(res) == AIK_JSON_STR &&
			    *aik_json_str(res))
				sb_addf(&out, " 上次判定 %s", aik_json_str(res));
		}
		if (def && aik_json_typeof(def) != AIK_JSON_NULL)
			sb_addf(&out, "（延迟至第 %lld 轮）",
				(long long)aik_json_int(def));
	}
	{
		const aik_json *jd = getj(d, "judge_defer_turns");
		char *water;
		char *cd;
		char *tt;
		char *rt;
		char *jdt;
		const aik_json *sme = getj(cfg, "sme");
		const aik_json *sme_en = getj(sme, "enabled");
		const aik_json *sme_url = getj(sme, "base_url");
		const aik_json *sme_split = getj(sme, "split_segments");

		if (!jd || aik_json_typeof(jd) == AIK_JSON_NULL)
			jd = getj(cfg, "judge_defer_turns");
		water = py_str(getj(cfg, "water_threshold"));
		cd = py_str(getj(cfg, "cooldown_minutes"));
		tt = py_str(getj(cfg, "turns_threshold"));
		rt = py_str(getj(cfg, "restore_top_n"));
		jdt = py_str(jd);
		sb_addf(&out,
			"\n配置：enabled=%s cooldown=%s 分钟 "
			"turns_threshold=%s water_threshold=%s "
			"judge_defer_turns=%s restore_top_n=%s SME=",
			enabled ? "开" : "关", cd, tt, water, jdt, rt);
		free(water);
		free(cd);
		free(tt);
		free(rt);
		free(jdt);
		if (sme_en && aik_json_typeof(sme_en) == AIK_JSON_BOOL &&
		    aik_json_bool(sme_en))
			sb_addf(&out, "启用（%s，分段=%s）",
				sme_url && aik_json_typeof(sme_url) ==
						   AIK_JSON_STR
					? aik_json_str(sme_url) : "None",
				sme_split && aik_json_typeof(sme_split) ==
						     AIK_JSON_BOOL
					? (aik_json_bool(sme_split) ? "True"
								    : "False")
					: "None");
		else
			sb_add(&out, "停用");
	}
	aik_json_free(d);
	return sb_take(&out);
}

/* ------------------------------------------------------------------ */
/* JSON-RPC 分派                                                      */
/* ------------------------------------------------------------------ */
static void emit_line(const char *line)
{
	fputs(line, stdout);
	fputc('\n', stdout);
	fflush(stdout);
}

static void emit_result(const aik_json *id, const char *result_json)
{
	struct sbuf b;
	char *idt = NULL;

	if (id)
		idt = json_str_text(id);
	sb_init(&b);
	sb_add(&b, "{\"jsonrpc\":\"2.0\",\"id\":");
	sb_add(&b, idt ? idt : "null");
	sb_add(&b, ",\"result\":");
	sb_add(&b, result_json);
	sb_add(&b, "}");
	free(idt);
	emit_line(b.p ? b.p : "{}");
	free(b.p);
}

static void emit_call_result(const aik_json *id, const char *text)
{
	struct sbuf b;
	char *idt = json_str_text(id);
	aik_json *t = aik_json_new_str(text ? text : "");
	char *tt = t ? json_str_text(t) : NULL;

	sb_init(&b);
	sb_add(&b, "{\"jsonrpc\":\"2.0\",\"id\":");
	sb_add(&b, idt ? idt : "null");
	sb_addf(&b,
		",\"result\":{\"content\":[{\"text\":%s,\"type\":\"text\"}],"
		"\"isError\":false,\"structuredContent\":{\"result\":%s}}}",
		tt ? tt : "\"\"", tt ? tt : "\"\"");
	aik_json_free(t);
	free(tt);
	free(idt);
	emit_line(b.p ? b.p : "{}");
	free(b.p);
}

static int dispatch_tool(const char *argv0, const char *name,
			 const aik_json *args, char **out)
{
	if (strcmp(name, "condense_check") == 0)
		*out = tool_check(argv0, args);
	else if (strcmp(name, "condense_report") == 0)
		*out = tool_report(argv0, args);
	else if (strcmp(name, "condense_judge") == 0)
		*out = tool_judge(argv0, args);
	else if (strcmp(name, "condense_begin") == 0)
		*out = tool_begin(argv0, args);
	else if (strcmp(name, "condense_commit") == 0)
		*out = tool_commit(argv0, args);
	else if (strcmp(name, "condense_restore") == 0)
		*out = tool_restore(argv0, args);
	else if (strcmp(name, "condense_status") == 0)
		*out = tool_status(argv0);
	else {
		struct sbuf b;

		sb_init(&b);
		sb_addf(&b, "未知工具：%s", name);
		*out = sb_take(&b);
	}
	return *out ? 0 : -1;
}

static void handle_line(const char *argv0, const char *line, size_t len)
{
	aik_json *req;
	const aik_json *id;
	const aik_json *method;
	const aik_json *params;

	if (len == 0)
		return;
	req = aik_json_parse(line, len, NULL, 0);
	if (!req)
		return;
	id = aik_json_get(req, "id");
	method = aik_json_get(req, "method");
	params = aik_json_get(req, "params");
	if (!method || aik_json_typeof(method) != AIK_JSON_STR) {
		aik_json_free(req);
		return;
	}
	if (strcmp(aik_json_str(method), "initialize") == 0) {
		emit_result(id, ACMCP_INIT_RESULT);
	} else if (strcmp(aik_json_str(method), "notifications/initialized") ==
		   0) {
		/* 通知：不回包 */
	} else if (strcmp(aik_json_str(method), "tools/list") == 0) {
		emit_result(id, ACMCP_TOOLS_RESULT);
	} else if (strcmp(aik_json_str(method), "ping") == 0) {
		emit_result(id, "{}");
	} else if (strcmp(aik_json_str(method), "tools/call") == 0) {
		const aik_json *name = getj(params, "name");
		const aik_json *args = getj(params, "arguments");
		char *text = NULL;

		if (name && aik_json_typeof(name) == AIK_JSON_STR &&
		    dispatch_tool(argv0, aik_json_str(name), args, &text) == 0) {
			emit_call_result(id, text);
			free(text);
		} else {
			emit_call_result(id, "工具执行失败");
		}
	}
	aik_json_free(req);
}

int acmcp_run(const char *argv0)
{
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;

	while ((n = getline(&line, &cap, stdin)) >= 0) {
		size_t len = (size_t)n;

		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
			len--;
		handle_line(argv0, line, len);
	}
	free(line);
	return 0;
}
