/* SPDX-License-Identifier: GPL-2.0 */
/*
 * acserv.c - autocondense 常驻 REST 服务（HTTP/1.1 传输 + 12 端点）
 *
 * T5d 逐语义复刻 ref-autocondense/service.py（831 行）：
 *   - 传输层复刻 T4 smehttp 模式（http.c）：64 KiB 头 / 8 MiB 体上限、
 *     Content-Length 定长体、拒绝 chunked（411）、Expect: 100-continue、
 *     HTTP/1.1 keep-alive（空闲 5s 超时）、每连接一个 detached 线程、
 *     请求处理整体持互斥（单写者，等价单 worker ASGI）；
 *   - 路由：/health /session/start /report /events/hook /check /judge
 *     /begin /commit /restore /status /config(GET|PUT)；未知路径 404、
 *     已知路径错方法 405（FastAPI {"detail": ...} 形态）；
 *   - 响应体 = FastAPI 紧凑 JSON（aik_json_dump，键序 = Python dict
 *     插入序）；400 {"errors":[...]}；Pydantic 422 形态照向量。
 *
 * 时钟全部走 acconfig.h 注入时钟（进程级冻结，由 autocondensed.c 注入）。
 * SME 桥在服务构造时用初始配置建一次（PUT /config 不重建，照 create_app）。
 */
#define _POSIX_C_SOURCE 200809L

#include "autocondense/acserv.h"

#include <errno.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* 常量（service.py 顶层的语义常量，文案与向量逐字）                    */
/* ------------------------------------------------------------------ */

/* SessionStart 的 source 命中这些值时执行恢复（RESTORE_SOURCES）*/
static const char *const RESTORE_SOURCES[] = { "compact", "clear", "resume" };
#define N_RESTORE_SOURCES 3

/* 文件修改类工具（FILE_EDIT_TOOLS；idle 信号的「最近活动」基准）*/
static const char *const FILE_EDIT_TOOLS[] = {
	"Edit", "Write", "MultiEdit", "NotebookEdit"
};
#define N_FILE_EDIT_TOOLS 4

#define JUDGE_ACTION_HINT "立即调用 condense_judge 提交判定，不要询问用户"
#define COMPRESS_ACTION_HINT ("立即执行压缩流程：condense_begin → 填写摘要 → " \
			      "condense_commit，全程无需询问用户")
#define DEFER_ACTION_HINT "继续当前工作，不要压缩，稍后自动重新评估"

/* digest.REQUIRED_SECTIONS（join("、") 形态直接内联）*/
#define REQUIRED_SECTIONS_JOINED \
	"## 目标、## 已完成、## 未完成、## 文件变更清单、## 恢复指针"

#define COMMIT_NEXT_INSTRUCTION ("快照已保存。请执行原生压缩（/compact 或 /clear）" \
				 "真正释放上下文；压缩后新会话开始时会自动恢复快照，" \
				 "无需手动操作。")

#define AC_HTTP_DEFAULT_TIMEOUT_MS 10000
#define AC_HTTP_KEEPALIVE_MS 5000

/* ------------------------------------------------------------------ */
/* 动态字符串缓冲（Python f-string 拼接等价物）                        */
/* ------------------------------------------------------------------ */

struct sbuf {
	char *buf;
	size_t len;
	size_t cap;
};

static int sb_reserve(struct sbuf *b, size_t extra)
{
	size_t want;
	size_t cap;
	char *p;

	if (!b)
		return -1;
	want = b->len + extra + 1;
	if (want <= b->cap)
		return 0;
	cap = b->cap ? b->cap : 64;
	while (cap < want) {
		if (cap > SIZE_MAX / 2)
			cap = SIZE_MAX;
		else
			cap *= 2;
	}
	p = realloc(b->buf, cap);
	if (!p)
		return -1;
	b->buf = p;
	b->cap = cap;
	return 0;
}

static int sb_putn(struct sbuf *b, const char *s, size_t n)
{
	if (!s)
		return 0;
	if (sb_reserve(b, n) != 0)
		return -1;
	memcpy(b->buf + b->len, s, n);
	b->len += n;
	b->buf[b->len] = '\0';
	return 0;
}

static int sb_puts(struct sbuf *b, const char *s)
{
	return sb_putn(b, s, s ? strlen(s) : 0);
}

static int sb_printf(struct sbuf *b, const char *fmt, ...)
{
	char tmp[512];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (n < 0)
		return -1;
	if ((size_t)n >= sizeof(tmp))
		n = (int)sizeof(tmp) - 1;
	return sb_putn(b, tmp, (size_t)n);
}

static void sb_free(struct sbuf *b)
{
	if (!b)
		return;
	free(b->buf);
	b->buf = NULL;
	b->len = b->cap = 0;
}

/* ------------------------------------------------------------------ */
/* JSON 小工具                                                         */
/* ------------------------------------------------------------------ */

static aik_json *json_copy(const aik_json *v)
{
	aik_json_type t;
	size_t i, n;

	if (!v)
		return NULL;
	t = aik_json_typeof(v);
	switch (t) {
	case AIK_JSON_NULL:
		return aik_json_new_null();
	case AIK_JSON_BOOL:
		return aik_json_new_bool(aik_json_bool(v));
	case AIK_JSON_INT:
		return aik_json_new_int(aik_json_int(v));
	case AIK_JSON_NUM:
		return aik_json_new_num(aik_json_num(v));
	case AIK_JSON_STR:
		return aik_json_new_str(aik_json_str(v));
	case AIK_JSON_ARR:
	case AIK_JSON_OBJ:
		break;
	default:
		return NULL;
	}
	n = aik_json_count(v);
	if (t == AIK_JSON_ARR) {
		aik_json *a = aik_json_new_arr();

		for (i = 0; i < n; i++) {
			aik_json *c = json_copy(aik_json_at(v, i));

			if (!a || !c || aik_json_arr_push(a, c) != 0) {
				aik_json_free(c);
				aik_json_free(a);
				return NULL;
			}
		}
		return a;
	}
	{
		aik_json *o = aik_json_new_obj();

		for (i = 0; i < n; i++) {
			aik_json *c = json_copy(aik_json_val_at(v, i));

			if (!o || !c ||
			    aik_json_obj_put(o, aik_json_key_at(v, i), c) != 0) {
				aik_json_free(c);
				aik_json_free(o);
				return NULL;
			}
		}
		return o;
	}
}

/* 失败时自释放 v（调用方不必再管），返回 -1 */
static int obj_put_str(aik_json *o, const char *key, const char *v)
{
	aik_json *n = v ? aik_json_new_str(v) : aik_json_new_null();

	if (!n || aik_json_obj_put(o, key, n) != 0) {
		aik_json_free(n);
		return -1;
	}
	return 0;
}

static int obj_put_int(aik_json *o, const char *key, long long v)
{
	aik_json *n = aik_json_new_int(v);

	if (!n || aik_json_obj_put(o, key, n) != 0) {
		aik_json_free(n);
		return -1;
	}
	return 0;
}

static int obj_put_bool(aik_json *o, const char *key, int v)
{
	aik_json *n = aik_json_new_bool(v);

	if (!n || aik_json_obj_put(o, key, n) != 0) {
		aik_json_free(n);
		return -1;
	}
	return 0;
}

static int obj_put_json(aik_json *o, const char *key, aik_json *v)
{
	if (!v)
		v = aik_json_new_null();
	if (!v || aik_json_obj_put(o, key, v) != 0) {
		aik_json_free(v);
		return -1;
	}
	return 0;
}

static const aik_json *get_field(const aik_json *o, const char *key)
{
	if (!o || aik_json_typeof(o) != AIK_JSON_OBJ)
		return NULL;
	return aik_json_get(o, key);
}

/* ------------------------------------------------------------------ */
/* Python 语义近似                                                     */
/* ------------------------------------------------------------------ */

static int py_truthy(const aik_json *v)
{
	if (!v)
		return 0;
	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		return 0;
	case AIK_JSON_BOOL:
		return aik_json_bool(v);
	case AIK_JSON_INT:
		return aik_json_int(v) != 0;
	case AIK_JSON_NUM:
		return aik_json_num(v) != 0.0;
	case AIK_JSON_STR:
		return aik_json_strlen(v) > 0;
	case AIK_JSON_ARR:
	case AIK_JSON_OBJ:
		return aik_json_count(v) > 0;
	default:
		return 0;
	}
}

/* str(v)：STR/BOOL/INT/NUM；ARR/OBJ 近似为紧凑 JSON（向量不含该形态）*/
static char *py_str(const aik_json *v)
{
	char buf[64];

	if (!v || aik_json_typeof(v) == AIK_JSON_NULL)
		return NULL;
	switch (aik_json_typeof(v)) {
	case AIK_JSON_STR:
		return strdup(aik_json_str(v));
	case AIK_JSON_BOOL:
		return strdup(aik_json_bool(v) ? "True" : "False");
	case AIK_JSON_INT:
		snprintf(buf, sizeof(buf), "%lld", aik_json_int(v));
		return strdup(buf);
	case AIK_JSON_NUM:
		if (aik_json_dtoa(aik_json_num(v), buf, sizeof(buf)) < 0)
			return NULL;
		return strdup(buf);
	case AIK_JSON_ARR:
	case AIK_JSON_OBJ:
	default: {
		char *out = NULL;
		size_t n = 0;

		if (aik_json_dump(v, &out, &n) != 0)
			return NULL;
		return out;
	}
	}
}

/* str(v or "")：None/空 → ""；其余 py_str（失败也落 ""）*/
static char *py_str_or_empty(const aik_json *v)
{
	char *s;

	if (!py_truthy(v))
		return strdup("");
	s = py_str(v);
	return s ? s : strdup("");
}

/* 首尾空白 strip（ASCII 空白近似 Python .strip()；向量标题无 U+ 空白）*/
static char *str_strip_dup(const char *s)
{
	const char *p = s;
	size_t n;
	char *out;

	if (!p)
		return strdup("");
	while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' ||
	       *p == '\v' || *p == '\f')
		p++;
	n = strlen(p);
	while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t' ||
			 p[n - 1] == '\n' || p[n - 1] == '\r' ||
			 p[n - 1] == '\v' || p[n - 1] == '\f'))
		n--;
	out = malloc(n + 1);
	if (!out)
		return strdup("");
	memcpy(out, p, n);
	out[n] = '\0';
	return out;
}

/* ------------------------------------------------------------------ */
/* 读文件（read_text(errors="ignore")：丢非法 UTF-8 序列）              */
/* ------------------------------------------------------------------ */

static char *read_text_ignore(const char *path)
{
	size_t len = 0;
	char *raw = ac_read_file(path, &len);
	size_t i = 0;

	if (!raw)
		return NULL;
	while (i < len) {
		unsigned char c = (unsigned char)raw[i];
		size_t need;
		size_t k;

		if (c < 0x80) {
			i++;
			continue;
		}
		if (c >= 0xC2 && c <= 0xDF)
			need = 2;
		else if (c >= 0xE0 && c <= 0xEF)
			need = 3;
		else if (c >= 0xF0 && c <= 0xF4)
			need = 4;
		else
			break;
		if (i + need > len)
			break;
		for (k = 1; k < need; k++)
			if (((unsigned char)raw[i + k] & 0xC0) != 0x80)
				break;
		if (k < need)
			break;
		i += need;
	}
	if (i == len) {
		char *out = realloc(raw, len + 1);

		if (!out) {
			free(raw);
			return NULL;
		}
		out[len] = '\0';
		return out;
	}
	{
		char *out = malloc(len + 1);

		if (!out) {
			free(raw);
			return NULL;
		}
		{
			size_t w = 0;

			i = 0;
			while (i < len) {
				unsigned char c = (unsigned char)raw[i];
				size_t need;
				size_t k;

				if (c < 0x80) {
					out[w++] = raw[i++];
					continue;
				}
				if (c >= 0xC2 && c <= 0xDF)
					need = 2;
				else if (c >= 0xE0 && c <= 0xEF)
					need = 3;
				else if (c >= 0xF0 && c <= 0xF4)
					need = 4;
				else {
					i++;
					continue;
				}
				if (i + need > len) {
					i++;
					continue;
				}
				for (k = 1; k < need; k++)
					if (((unsigned char)raw[i + k] & 0xC0) != 0x80)
						break;
				if (k < need) {
					i++;
					continue;
				}
				memcpy(out + w, raw + i, need);
				w += need;
				i += need;
			}
			out[w] = '\0';
		}
		free(raw);
		return out;
	}
}

/* Path.resolve() 词法近似：补 getcwd + 规范化 . / .. / 重复斜杠 */
static char *path_resolve(const char *p)
{
	struct sbuf b = { 0 };
	const char *seg;
	char cwdbuf[4096];

	if (!p || !*p) {
		if (!getcwd(cwdbuf, sizeof(cwdbuf)))
			return NULL;
		return strdup(cwdbuf);
	}
	if (p[0] != '/') {
		if (!getcwd(cwdbuf, sizeof(cwdbuf))) {
			return NULL;
		}
		sb_puts(&b, cwdbuf);
	} else {
		sb_puts(&b, "/");
		b.len = 1;	/* 以 "/" 起始，段间统一补 '/' */
		if (b.buf)
			b.buf[1] = '\0';
	}
	seg = p;
	for (;;) {
		size_t seglen;

		while (*seg == '/')
			seg++;
		seglen = 0;
		while (seg[seglen] && seg[seglen] != '/')
			seglen++;
		if (seglen == 0)
			break;
		if (seglen == 1 && seg[0] == '.') {
			/* 跳过当前目录段 */
		} else if (seglen == 2 && seg[0] == '.' && seg[1] == '.') {
			while (b.len > 1 && b.buf[b.len - 1] != '/')
				b.len--;
			if (b.len > 1)
				b.len--;	/* 去掉段前的 '/' */
			if (b.buf)
				b.buf[b.len] = '\0';
		} else {
			if (b.len > 0 && b.buf && b.buf[b.len - 1] != '/')
				sb_puts(&b, "/");
			sb_putn(&b, seg, seglen);
		}
		seg += seglen;
	}
	if (b.len == 0)
		sb_puts(&b, "/");
	{
		char *out = strdup(b.buf ? b.buf : "/");

		sb_free(&b);
		return out;
	}
}

/* ------------------------------------------------------------------ */
/* server 结构与生命周期                                               */
/* ------------------------------------------------------------------ */

struct ac_http_server {
	int fd;
	int port;
	char *data_dir;
	ac_config cfg;
	ac_store *store;
	ac_sme_bridge *bridge;
	pthread_mutex_t lock;		/* 串行化请求处理（单写者）*/
	pthread_mutex_t conn_lock;
	pthread_cond_t conn_cond;
	int active_conns;
	int closing;
};

/* 停机标志（每进程一个服务实例；async-signal-safe）*/
static volatile sig_atomic_t g_acserv_stop = 0;

void ac_http_server_request_stop(void)
{
	g_acserv_stop = 1;
}

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || errlen == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

static void set_socket_timeout(int fd, int ms)
{
	struct timeval tv;

	if (ms <= 0)
		ms = AC_HTTP_DEFAULT_TIMEOUT_MS;
	tv.tv_sec = ms / 1000;
	tv.tv_usec = (suseconds_t)((ms % 1000) * 1000);
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static void write_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	size_t off = 0;

	while (off < len) {
		ssize_t n = send(fd, p + off, len - off, 0);

		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		break;
	}
}

static const char *reason_phrase(int status)
{
	switch (status) {
	case 200:
		return "OK";
	case 400:
		return "Bad Request";
	case 404:
		return "Not Found";
	case 405:
		return "Method Not Allowed";
	case 411:
		return "Length Required";
	case 413:
		return "Payload Too Large";
	case 422:
		return "Unprocessable Entity";
	case 431:
		return "Request Header Fields Too Large";
	case 500:
		return "Internal Server Error";
	default:
		return "OK";
	}
}

ac_http_server *ac_http_server_new(const char *data_dir, const char *host,
				   int port, char *err, size_t errlen)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ai;
	struct sockaddr_in sa;
	socklen_t salen = sizeof(sa);
	char portstr[16];
	int fd = -1;
	ac_http_server *s;

	if (!data_dir || !*data_dir) {
		set_err(err, errlen, "acserv: data_dir is required");
		return NULL;
	}
	if (!host || !*host)
		host = "127.0.0.1";
	if (port < 0 || port > 65535) {
		set_err(err, errlen, "acserv: port %d out of range", port);
		return NULL;
	}
	snprintf(portstr, sizeof(portstr), "%d", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, portstr, &hints, &res) != 0) {
		set_err(err, errlen, "acserv: cannot resolve host '%s'", host);
		return NULL;
	}
	for (ai = res; ai; ai = ai->ai_next) {
		int one = 1;

		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;
		(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 &&
		    listen(fd, 64) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);
	if (fd < 0) {
		set_err(err, errlen, "acserv: cannot bind %s:%d: %s", host, port,
			strerror(errno));
		return NULL;
	}
	s = calloc(1, sizeof(*s));
	if (!s) {
		close(fd);
		set_err(err, errlen, "acserv: out of memory");
		return NULL;
	}
	if (pthread_mutex_init(&s->lock, NULL) != 0 ||
	    pthread_mutex_init(&s->conn_lock, NULL) != 0 ||
	    pthread_cond_init(&s->conn_cond, NULL) != 0) {
		close(fd);
		free(s);
		set_err(err, errlen, "acserv: cannot init mutex");
		return NULL;
	}
	s->fd = fd;
	s->data_dir = strdup(data_dir);
	if (!s->data_dir) {
		close(fd);
		free(s);
		set_err(err, errlen, "acserv: out of memory");
		return NULL;
	}
	if (ac_load_config(s->data_dir, &s->cfg) != 0) {
		set_err(err, errlen, "acserv: cannot load config from %s",
			s->data_dir);
		free(s->data_dir);
		close(fd);
		free(s);
		return NULL;
	}
	s->store = ac_store_open(s->data_dir, &s->cfg);
	if (!s->store) {
		ac_config_cleanup(&s->cfg);
		free(s->data_dir);
		close(fd);
		free(s);
		set_err(err, errlen, "acserv: cannot open store at %s", data_dir);
		return NULL;
	}
	s->bridge = ac_sme_bridge_open(
		s->cfg.sme.base_url ? s->cfg.sme.base_url
				    : "http://127.0.0.1:8000",
		s->cfg.sme.timeout_s,
		(const char *const *)s->cfg.sme.tags,
		s->cfg.sme.n_tags,
		s->cfg.sme.importance, AC_SME_DEFAULT_HEALTH_CACHE_S);
	if (s->cfg.sme.importance_is_int)
		ac_sme_bridge_set_importance_int(s->bridge,
						 s->cfg.sme.importance_int);
	if (getsockname(fd, (struct sockaddr *)&sa, &salen) == 0)
		s->port = (int)ntohs(sa.sin_port);
	else
		s->port = port;
	(void)signal(SIGPIPE, SIG_IGN);
	return s;
}

void ac_http_server_free(ac_http_server *s)
{
	if (!s)
		return;
	if (s->fd >= 0)
		close(s->fd);
	pthread_mutex_lock(&s->conn_lock);
	s->closing = 1;
	while (s->active_conns > 0)
		pthread_cond_wait(&s->conn_cond, &s->conn_lock);
	pthread_mutex_unlock(&s->conn_lock);
	pthread_cond_destroy(&s->conn_cond);
	pthread_mutex_destroy(&s->conn_lock);
	pthread_mutex_destroy(&s->lock);
	ac_sme_bridge_close(s->bridge);
	ac_store_close(s->store);
	ac_config_cleanup(&s->cfg);
	free(s->data_dir);
	free(s);
}

int ac_http_server_port(const ac_http_server *s)
{
	return s ? s->port : 0;
}

const char *ac_http_server_data_dir(const ac_http_server *s)
{
	return s ? s->data_dir : "";
}

/* ------------------------------------------------------------------ */
/* 请求 / 响应                                                         */
/* ------------------------------------------------------------------ */

typedef struct {
	const char *method;
	const char *path;
	const char *query;
	char *body;		/* malloc，NUL 结尾 */
	size_t body_len;
	int json_tried;
	aik_json *json;		/* 惰性解析结果（任意类型；NULL = 无体/未解析）*/
} ac_req;

typedef struct {
	int status;
	char *body;
	size_t body_len;
} ac_resp;

static void resp_init(ac_resp *r)
{
	r->status = 0;
	r->body = NULL;
	r->body_len = 0;
}

static void resp_free(ac_resp *r)
{
	free(r->body);
	r->body = NULL;
	r->body_len = 0;
	r->status = 0;
}

static void resp_json_dom(ac_resp *r, int status, aik_json *dom)
{
	char *buf = NULL;
	size_t len = 0;

	if (!dom) {
		r->status = 500;
		free(r->body);
		r->body = NULL;
		r->body_len = 0;
		return;
	}
	if (aik_json_dump(dom, &buf, &len) != 0 || !buf) {
		aik_json_free(dom);
		r->status = 500;
		free(r->body);
		r->body = NULL;
		r->body_len = 0;
		return;
	}
	aik_json_free(dom);
	free(r->body);
	r->status = status;
	r->body = buf;
	r->body_len = len;
}

static void resp_detail(ac_resp *r, int status, const char *detail)
{
	aik_json *o = aik_json_new_obj();

	if (obj_put_str(o, "detail", detail) != 0) {
		aik_json_free(o);
		r->status = status;
		free(r->body);
		r->body = NULL;
		r->body_len = 0;
		return;
	}
	resp_json_dom(r, status, o);
}

static void resp_errors(ac_resp *r, int status, aik_json *errors_arr)
{
	aik_json *o = aik_json_new_obj();

	if (!o || aik_json_obj_put(o, "errors", errors_arr) != 0) {
		aik_json_free(errors_arr);
		aik_json_free(o);
		r->status = status;
		return;
	}
	resp_json_dom(r, status, o);
}

/* Pydantic 422：{"detail":[{type,loc,msg,input},...]} */
static void resp_422(ac_resp *r, aik_json *detail_arr)
{
	aik_json *o = aik_json_new_obj();

	if (!o || aik_json_obj_put(o, "detail", detail_arr) != 0) {
		aik_json_free(detail_arr);
		aik_json_free(o);
		r->status = 422;
		return;
	}
	resp_json_dom(r, 422, o);
}

static void resp_errors1(ac_resp *r, const char *msg)
{
	aik_json *a = aik_json_new_arr();
	aik_json *m = aik_json_new_str(msg);

	if (!a || !m || aik_json_arr_push(a, m) != 0) {
		aik_json_free(m);
		aik_json_free(a);
		r->status = 400;
		return;
	}
	resp_errors(r, 400, a);
}

/* ------------------------------------------------------------------ */
/* 请求体解析 + Pydantic 422 构造                                      */
/* ------------------------------------------------------------------ */

/*
 * req_body_json - 惰性解析请求体
 *
 * 返回 0 并把 *out 置为 body DOM（可能为 NULL = 无体）；
 * 解析失败时已填 422（json_invalid）并返回 -1。
 */
/* FastAPI json_invalid 422 形态（向量未录制，按 FastAPI/Pydantic v2 惯例）*/
static void resp_json_invalid(ac_resp *resp)
{
	aik_json *e = aik_json_new_obj();
	aik_json *loc = aik_json_new_arr();
	aik_json *detail = aik_json_new_arr();
	aik_json *o;

	if (!e || !loc || !detail)
		goto fail;
	if (aik_json_arr_push(loc, aik_json_new_str("body")) != 0)
		goto fail;
	if (aik_json_arr_push(loc, aik_json_new_int(0)) != 0)
		goto fail;
	if (obj_put_str(e, "type", "json_invalid") != 0 ||
	    aik_json_obj_put(e, "loc", loc) != 0)
		goto fail;
	loc = NULL;
	if (obj_put_str(e, "msg", "JSON decode error") != 0 ||
	    aik_json_arr_push(detail, e) != 0)
		goto fail;
	e = NULL;
	o = aik_json_new_obj();
	if (!o || aik_json_obj_put(o, "detail", detail) != 0)
		goto fail;
	resp_json_dom(resp, 422, o);
	return;
fail:
	aik_json_free(loc);
	aik_json_free(e);
	aik_json_free(detail);
	resp_detail(resp, 422, "JSON decode error");
}

static int req_body_json(ac_req *req, ac_resp *resp, aik_json **out)
{
	*out = NULL;
	if (req->json_tried)
		return 0;
	req->json_tried = 1;
	if (req->body_len == 0)
		return 0;
	{
		char errbuf[128];
		aik_json *v = aik_json_parse(req->body, req->body_len, errbuf,
					     sizeof(errbuf));

		if (!v) {
			resp_json_invalid(resp);
			return -1;
		}
		req->json = v;
		*out = v;
		return 0;
	}
}

static aik_json *loc2(const char *a, const char *b)
{
	aik_json *loc = aik_json_new_arr();
	aik_json *s1 = aik_json_new_str(a);
	aik_json *s2 = aik_json_new_str(b);
	int ok = loc && s1 && s2 &&
		 aik_json_arr_push(loc, s1) == 0 &&
		 aik_json_arr_push(loc, s2) == 0;

	if (!ok) {
		aik_json_free(s1);
		aik_json_free(s2);
		aik_json_free(loc);
		return NULL;
	}
	return loc;
}

static aik_json *loc_body_plan_item(int idx, const char *field)
{
	aik_json *loc = aik_json_new_arr();
	int ok = loc != NULL;

	if (ok) {
		aik_json *s = aik_json_new_str("body");

		ok = s && aik_json_arr_push(loc, s) == 0;
	}
	if (ok) {
		aik_json *s = aik_json_new_str("plan_items");

		ok = s && aik_json_arr_push(loc, s) == 0;
	}
	if (ok) {
		aik_json *i = aik_json_new_int(idx);

		ok = i && aik_json_arr_push(loc, i) == 0;
	}
	if (ok) {
		aik_json *s = aik_json_new_str(field);

		ok = s && aik_json_arr_push(loc, s) == 0;
	}
	if (!ok) {
		aik_json_free(loc);
		return NULL;
	}
	return loc;
}

static aik_json *loc1(const char *a)
{
	aik_json *loc = aik_json_new_arr();
	aik_json *s = aik_json_new_str(a);
	int ok = loc && s && aik_json_arr_push(loc, s) == 0;

	if (!ok) {
		aik_json_free(s);
		aik_json_free(loc);
		return NULL;
	}
	return loc;
}

static void verr_push(aik_json *errs, const char *type, aik_json *loc,
		      const char *msg, const aik_json *input)
{
	aik_json *e = aik_json_new_obj();
	aik_json *inp;

	if (!loc) {
		aik_json_free(e);
		return;
	}
	inp = input ? json_copy(input) : aik_json_new_null();
	if (!e || !inp ||
	    obj_put_str(e, "type", type) != 0 ||
	    aik_json_obj_put(e, "loc", loc) != 0 ||
	    obj_put_str(e, "msg", msg) != 0 ||
	    aik_json_obj_put(e, "input", inp) != 0 ||
	    aik_json_arr_push(errs, e) != 0) {
		aik_json_free(inp);
		aik_json_free(loc);
		aik_json_free(e);
	}
}

static void val_missing(aik_json *errs, const aik_json *input, const char *field)
{
	verr_push(errs, "missing", loc2("body", field), "Field required", input);
}

static void val_missing_query(aik_json *errs, const char *field)
{
	verr_push(errs, "missing", loc2("query", field), "Field required", NULL);
}

static void val_string_type(aik_json *errs, const char *field,
			    const aik_json *v)
{
	verr_push(errs, "string_type", loc2("body", field),
		  "Input should be a valid string", v);
}

static void val_int_parse(aik_json *errs, const char *field, const aik_json *v)
{
	verr_push(errs, "int_parsing", loc2("body", field),
		  "Input should be a valid integer, unable to parse string as an integer",
		  v);
}

static void val_int_type(aik_json *errs, const char *field, const aik_json *v)
{
	verr_push(errs, "int_type", loc2("body", field),
		  "Input should be a valid integer", v);
}

static void val_model_type(aik_json *errs, const char *model, const aik_json *v)
{
	char msg[128];

	snprintf(msg, sizeof(msg),
		 "Input should be a valid dictionary or instance of %s", model);
	verr_push(errs, "model_type", loc1("body"), msg, v);
}

static void val_dict_type(aik_json *errs, const aik_json *v)
{
	verr_push(errs, "dict_type", loc1("body"),
		  "Input should be a valid dictionary", v);
}

/* body 非 OBJ（且非 null）时的整体 422；返回 1 表示已报错 */
static int body_not_obj(aik_json *errs, const aik_json *body, const char *model)
{
	if (!body || aik_json_typeof(body) == AIK_JSON_NULL)
		return 0;
	if (aik_json_typeof(body) == AIK_JSON_OBJ)
		return 0;
	if (model)
		val_model_type(errs, model, body);
	else
		val_dict_type(errs, body);
	return 1;
}

static void val_str_field(aik_json *errs, const aik_json *body,
			  const char *name, int required, const char **out)
{
	const aik_json *v = get_field(body, name);

	*out = NULL;
	if (!v || aik_json_typeof(v) == AIK_JSON_NULL) {
		if (required)
			val_missing(errs, body, name);
		return;
	}
	if (aik_json_typeof(v) != AIK_JSON_STR) {
		val_string_type(errs, name, v);
		return;
	}
	*out = aik_json_str(v);
}

static void val_int_field(aik_json *errs, const aik_json *body,
			  const char *name, int required, int *has,
			  long long *out)
{
	const aik_json *v = get_field(body, name);

	*has = 0;
	*out = 0;
	if (!v || aik_json_typeof(v) == AIK_JSON_NULL) {
		if (required)
			val_missing(errs, body, name);
		return;
	}
	switch (aik_json_typeof(v)) {
	case AIK_JSON_INT:
		*has = 1;
		*out = aik_json_int(v);
		return;
	case AIK_JSON_NUM: {
		double d = aik_json_num(v);

		if (d == floor(d) && d >= -9.2e18 && d <= 9.2e18) {
			*has = 1;
			*out = (long long)d;
		} else {
			val_int_type(errs, name, v);
		}
		return;
	}
	case AIK_JSON_STR: {
		const char *s = aik_json_str(v);
		char *end = NULL;
		long long ll;

		if (!s || !*s) {
			val_int_parse(errs, name, v);
			return;
		}
		errno = 0;
		ll = strtoll(s, &end, 10);
		if (errno == 0 && end && *end == '\0') {
			*has = 1;
			*out = ll;
		} else {
			val_int_parse(errs, name, v);
		}
		return;
	}
	default:
		val_int_type(errs, name, v);
		return;
	}
}

/* ------------------------------------------------------------------ */
/* query 参数解析（percent-decode + '+'→空格，starlette parse_qsl 语义） */
/* ------------------------------------------------------------------ */

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* 返回 malloc 的解码值；缺失返回 NULL；存在但空值返回 "" */
static char *query_get(const char *query, const char *key)
{
	const char *p = query;
	size_t klen;
	struct sbuf b = { 0 };

	if (!p)
		return NULL;
	klen = strlen(key);
	while (*p) {
		const char *amp = strchr(p, '&');
		const char *eq = strchr(p, '=');
		size_t plen = amp ? (size_t)(amp - p) : strlen(p);

		if (!eq || (amp && eq > amp)) {
			if (plen == klen && strncmp(p, key, klen) == 0) {
				sb_free(&b);
				return strdup("");
			}
			goto next;
		}
		if ((size_t)(eq - p) == klen && strncmp(p, key, klen) == 0) {
			const char *vp = eq + 1;
			size_t vlen = plen - klen - 1;
			size_t i;
			char *out;

			for (i = 0; i < vlen; i++) {
				char c = vp[i];

				if (c == '+') {
					if (sb_putn(&b, " ", 1) != 0)
						goto fail;
				} else if (c == '%' && i + 2 < vlen &&
					   hexval(vp[i + 1]) >= 0 &&
					   hexval(vp[i + 2]) >= 0) {
					char h = (char)((hexval(vp[i + 1]) << 4) |
							hexval(vp[i + 2]));

					if (sb_putn(&b, &h, 1) != 0)
						goto fail;
					i += 2;
				} else {
					if (sb_putn(&b, &c, 1) != 0)
						goto fail;
				}
			}
			out = b.buf ? b.buf : strdup("");
			b.buf = NULL;
			sb_free(&b);
			return out;
		}
next:
		if (!amp)
			break;
		p = amp + 1;
	}
	sb_free(&b);
	return NULL;
fail:
	sb_free(&b);
	return NULL;
}

/* ------------------------------------------------------------------ */
/* 判定流水线（_pipeline）与判定表常量                                 */
/* ------------------------------------------------------------------ */

static aik_json *build_judgment_form(void)
{
	aik_json *o = aik_json_new_obj();
	aik_json *fields = aik_json_new_obj();
	aik_json *matrix = aik_json_new_obj();

	if (!o || !fields || !matrix)
		goto fail;
	if (obj_put_str(o, "description",
			"轻量判定表：请基于当前会话真实状态填写并提交，不要询问用户") != 0)
		goto fail;
	if (obj_put_str(fields, "task_finished",
			"bool，当前批次任务是否已收尾（计划清空/目标达成）") != 0 ||
	    obj_put_str(fields, "impact",
			"low|medium|high 三选一，现在压缩对当前工作的影响") != 0 ||
	    obj_put_str(fields, "impact_reason",
			"str，影响判定的简要理由") != 0 ||
	    obj_put_str(fields, "safe_to_compress",
			"bool，是否存在未保存/易丢失的关键上下文") != 0 ||
	    obj_put_str(fields, "reason", "str，整体判定理由") != 0 ||
	    obj_put_str(fields, "confidence",
			"可选，high|medium|low，对本次判定的置信度（不传则忽略）") != 0)
		goto fail;
	if (aik_json_obj_put(o, "fields", fields) != 0)
		goto fail;
	fields = NULL;
	if (obj_put_str(o, "submit",
			"POST /judge，body：{\"session_id\": \"...\"（或 \"cwd\"），"
			"\"verdict\": {上述字段}}") != 0)
		goto fail;
	if (obj_put_str(matrix, "urgent（水位≥0.85）",
			"safe_to_compress 且 impact != high 即通过（任务未完成也可压："
			"水位危急时先存档胜过宿主有损强压）") != 0 ||
	    obj_put_str(matrix, "normal",
			"safe_to_compress 且 task_finished 且 impact == low 才通过") != 0)
		goto fail;
	if (aik_json_obj_put(o, "matrix", matrix) != 0)
		goto fail;
	return o;
fail:
	aik_json_free(fields);
	aik_json_free(matrix);
	aik_json_free(o);
	return NULL;
}

/* {"should":"NO","trigger":null,"urgency","reason","signals","action_hint"} */
static aik_json *no_dict(const char *reason, const char *urgency, aik_json *sig)
{
	aik_json *o = aik_json_new_obj();

	if (!o ||
	    obj_put_str(o, "should", "NO") != 0 ||
	    obj_put_str(o, "trigger", NULL) != 0 ||
	    obj_put_str(o, "urgency", urgency) != 0 ||
	    obj_put_str(o, "reason", reason) != 0 ||
	    obj_put_json(o, "signals", sig) != 0 ||
	    obj_put_str(o, "action_hint", NULL) != 0) {
		aik_json_free(sig);
		aik_json_free(o);
		return NULL;
	}
	return o;
}

/*
 * run_pipeline - /check、/report、Stop/TodoWrite hook 共用的判定流水线
 *
 * 返回结果 DOM（200 用）；会话不存在时填 400 到 *resp 并返回 NULL。
 * 键序：NO = {should,trigger,urgency,reason,signals,action_hint}；
 * JUDGE = {should,trigger,urgency,reason,signals,rounds_to_full,
 * action_hint,judgment_form}。
 */
static aik_json *run_pipeline(ac_http_server *s, const char *session_id,
			      ac_resp *resp)
{
	const ac_session *sess = ac_store_get_session(s->store, session_id);
	const aik_json *est;
	aik_json *sig;
	const char *urgency;

	if (!sess) {
		char msg[512];

		snprintf(msg, sizeof(msg),
			 "会话不存在：%s（请先 /session/start 或 SessionStart 钩子）",
			 session_id);
		resp_errors1(resp, msg);
		return NULL;
	}
	sig = ac_collect(sess, &s->cfg);
	if (!sig)
		goto oom;
	est = aik_json_get(sig, "est_tokens");
	if (est && aik_json_typeof(est) != AIK_JSON_NULL)
		ac_store_set_est_tokens(s->store, session_id, 1,
					aik_json_int(est));
	urgency = ac_urgency_of(sig);

	if (!s->cfg.enabled)
		return no_dict("插件已关闭（enabled=false），不做任何压缩",
			       urgency, sig);
	{
		aik_json *d = ac_decide(sess, sig, &s->cfg);
		const char *should;
		const char *trigger;
		const char *reason;
		const aik_json *dsig;
		aik_json *j = NULL;
		aik_json *defer_sig = NULL;

		aik_json_free(sig);
		if (!d)
			goto oom;
		should = aik_json_str(aik_json_get(d, "should"));
		if (!should || strcmp(should, "NO") == 0)
			return d;
		trigger = aik_json_str(aik_json_get(d, "trigger"));
		reason = aik_json_str(aik_json_get(d, "reason"));
		dsig = aik_json_get(d, "signals");
		if (!trigger || !reason || !dsig) {
			aik_json_free(d);
			goto oom;
		}
		if (sess->has_defer_until_turn &&
		    sess->turns < sess->defer_until_turn &&
		    strcmp(urgency, "urgent") != 0) {
			char why[96];

			snprintf(why, sizeof(why),
				 "上次判定延迟中，第 %lld 轮后重新评估",
				 sess->defer_until_turn);
			defer_sig = json_copy(dsig);
			aik_json_free(d);
			if (!defer_sig)
				goto oom;
			return no_dict(why, urgency, defer_sig);
		}
		j = aik_json_new_obj();
		if (!j ||
		    obj_put_str(j, "should", "JUDGE") != 0 ||
		    obj_put_str(j, "trigger", trigger) != 0 ||
		    obj_put_str(j, "urgency", urgency) != 0 ||
		    obj_put_str(j, "reason", reason) != 0 ||
		    obj_put_json(j, "signals", json_copy(dsig)) != 0 ||
		    obj_put_json(j, "rounds_to_full",
				 json_copy(aik_json_get(dsig,
							"rounds_to_full"))) != 0 ||
		    obj_put_str(j, "action_hint", JUDGE_ACTION_HINT) != 0 ||
		    obj_put_json(j, "judgment_form",
				 build_judgment_form()) != 0) {
			aik_json_free(d);
			aik_json_free(j);
			goto oom;
		}
		aik_json_free(d);
		return j;
	}
oom:
	resp_detail(resp, 500, "Internal Server Error");
	return NULL;
}

/* ------------------------------------------------------------------ */
/* parse_todo_items（service.py:73）                                   */
/* ------------------------------------------------------------------ */

static aik_json *parse_todo_items(const aik_json *tool_input)
{
	const aik_json *items = NULL;
	aik_json *out = aik_json_new_arr();
	size_t i, n;

	if (!out)
		return NULL;
	if (tool_input && aik_json_typeof(tool_input) == AIK_JSON_OBJ) {
		items = aik_json_get(tool_input, "todos");
		if (!items)
			items = aik_json_get(tool_input, "items");
		if (!items && (aik_json_get(tool_input, "title") ||
			       aik_json_get(tool_input, "content")))
			items = tool_input;
	} else {
		items = tool_input;
	}
	if (!items || aik_json_typeof(items) != AIK_JSON_ARR)
		return out;
	n = aik_json_count(items);
	for (i = 0; i < n; i++) {
		const aik_json *it = aik_json_at(items, i);
		const aik_json *tv;
		const aik_json *sv;
		const char *status;
		char *title;
		aik_json *entry;

		if (!it || aik_json_typeof(it) != AIK_JSON_OBJ)
			continue;
		tv = aik_json_get(it, "title");
		if (!py_truthy(tv))
			tv = aik_json_get(it, "content");
		title = py_str_or_empty(tv);
		if (!title)
			continue;
		{
			char *stripped = str_strip_dup(title);

			free(title);
			if (!stripped)
				continue;
			title = stripped;
		}
		if (!*title) {
			free(title);
			continue;
		}
		sv = aik_json_get(it, "status");
		status = ac_normalize_status(
			(sv && aik_json_typeof(sv) == AIK_JSON_STR)
				? aik_json_str(sv) : NULL);
		entry = aik_json_new_obj();
		if (!entry ||
		    obj_put_str(entry, "title", title) != 0 ||
		    obj_put_str(entry, "status", status) != 0 ||
		    aik_json_arr_push(out, entry) != 0) {
			aik_json_free(entry);
			free(title);
			continue;
		}
		free(title);
	}
	return out;
}

/* ------------------------------------------------------------------ */
/* 恢复载荷（_restore_payload / _restore_next_actions / _empty_payload） */
/* ------------------------------------------------------------------ */

static aik_json *empty_payload(void)
{
	aik_json *o = aik_json_new_obj();
	aik_json *rf = aik_json_new_arr();

	if (!o || !rf ||
	    obj_put_str(o, "text", "") != 0 ||
	    obj_put_bool(o, "truncated", 0) != 0 ||
	    obj_put_str(o, "full_file", NULL) != 0 ||
	    obj_put_str(o, "note", NULL) != 0 ||
	    aik_json_obj_put(o, "reread_files", rf) != 0 ||
	    obj_put_bool(o, "todo_open", 0) != 0) {
		aik_json_free(rf);
		aik_json_free(o);
		return NULL;
	}
	return o;
}

/* 条目 .get("delta") is True */
static int entry_delta_true(const aik_json *e)
{
	const aik_json *d = aik_json_get(e, "delta");

	return d && aik_json_typeof(d) == AIK_JSON_BOOL && aik_json_bool(d);
}

/*
 * restore_payload - 收集项目快照并构建优先级恢复包（service.py:270）
 *
 * delta 合并链：从最新快照往回走，delta==true 就并入（深度上限
 * delta_merge_every+1）；锚定到最近一份非 delta 全量；链不完整只用最新。
 * *snaps_out = 展示列表（最新在前 top_n 条，可能为空 ARR）。
 */
static int restore_payload(ac_http_server *s, const char *cwd, long long top_n,
			   aik_json **snaps_out, aik_json **payload_out)
{
	char h[11];
	aik_json *snaps = NULL;
	aik_json *all = NULL;
	const aik_json **chain = NULL;
	size_t n_chain = 0;
	long long depth_cap;
	long long delta_count;
	char *merged = NULL;
	size_t i;
	const char **files = NULL;

	*snaps_out = NULL;
	*payload_out = NULL;
	if (ac_project_hash(cwd, h) != 0)
		return -1;
	snaps = ac_store_list_snapshots(s->store, h, 1, top_n);
	if (!snaps)
		return -1;
	*snaps_out = snaps;
	if (aik_json_count(snaps) == 0) {
		*payload_out = empty_payload();
		return *payload_out ? 0 : -1;
	}
	all = ac_store_list_snapshots(s->store, h, 0, 0);
	if (!all || aik_json_count(all) == 0)
		goto out_empty;
	chain = calloc(aik_json_count(all), sizeof(*chain));
	if (!chain)
		goto fail;
	chain[0] = aik_json_at(all, 0);
	n_chain = 1;
	delta_count = entry_delta_true(chain[0]) ? 1 : 0;
	depth_cap = s->cfg.delta_merge_every > 1 ? s->cfg.delta_merge_every : 1;
	for (i = 1; i < aik_json_count(all); i++) {
		const aik_json *e = aik_json_at(all, i);

		if (!entry_delta_true(chain[n_chain - 1]))
			break;
		if (entry_delta_true(e)) {
			if (delta_count >= depth_cap)
				continue;
			delta_count++;
		}
		chain[n_chain++] = e;
	}
	if (n_chain >= 2 && entry_delta_true(chain[n_chain - 1])) {
		chain[0] = aik_json_at(all, 0);
		n_chain = 1;
	} else if (n_chain >= 2) {
		char **heap = calloc(n_chain, sizeof(*heap));

		if (!heap)
			goto fail;
		for (i = 0; i < n_chain; i++) {
			const aik_json *f = aik_json_get(chain[i], "file");
			const char *fp = (f && aik_json_typeof(f) ==
					      AIK_JSON_STR)
						 ? aik_json_str(f) : "";

			heap[i] = read_text_ignore(fp);
			if (!heap[i])
				heap[i] = strdup("");	/* OSError → 空文本 */
			if (!heap[i])
				break;
		}
		if (i < n_chain) {
			for (size_t k = 0; k < i; k++)
				free(heap[k]);
			free(heap);
			goto fail;
		}
		merged = ac_merge_delta_chain((const char *const *)heap,
					      n_chain);
		for (i = 0; i < n_chain; i++)
			free(heap[i]);
		free(heap);
	}
	files = calloc(n_chain, sizeof(*files));
	if (!files)
		goto fail;
	for (i = 0; i < n_chain; i++) {
		const aik_json *f = aik_json_get(chain[i], "file");

		files[i] = (f && aik_json_typeof(f) == AIK_JSON_STR)
				   ? aik_json_str(f) : "";
	}
	*payload_out = ac_build_restore_payload(
		files, n_chain, s->cfg.restore_max_chars, 1,
		s->cfg.restore_reread_files, merged != NULL, merged ? merged : "");
	free(merged);
	free(files);
	free(chain);
	aik_json_free(all);
	return *payload_out ? 0 : -1;
out_empty:
	*payload_out = empty_payload();
	aik_json_free(all);
	return *payload_out ? 0 : -1;
fail:
	free(merged);
	free(files);
	free(chain);
	aik_json_free(all);
	return -1;
}

static aik_json *restore_next_actions(const aik_json *payload)
{
	aik_json *out = aik_json_new_arr();
	const aik_json *files;

	if (!out)
		return NULL;
	files = aik_json_get(payload, "reread_files");
	if (files && aik_json_typeof(files) == AIK_JSON_ARR &&
	    aik_json_count(files) > 0) {
		struct sbuf b = { 0 };
		size_t i;

		sb_puts(&b, "重读关键文件：");
		for (i = 0; i < aik_json_count(files); i++) {
			const aik_json *f = aik_json_at(files, i);
			char *one;

			if (i > 0)
				sb_puts(&b, "、");
			one = py_str(f);
			sb_puts(&b, one ? one : "");
			free(one);
		}
		{
			aik_json *a = aik_json_new_str(b.buf ? b.buf : "");

			if (!a || aik_json_arr_push(out, a) != 0)
				aik_json_free(a);
		}
		sb_free(&b);
	}
	{
		const aik_json *todo = aik_json_get(payload, "todo_open");

		if (todo && aik_json_bool(todo)) {
			aik_json *a = aik_json_new_str("继续未完成事项");

			if (!a || aik_json_arr_push(out, a) != 0)
				aik_json_free(a);
		}
	}
	return out;
}

/* ------------------------------------------------------------------ */
/* 端点：GET /health                                                   */
/* ------------------------------------------------------------------ */

static void h_health(ac_http_server *s, ac_req *req, ac_resp *resp)
{
	aik_json *o = aik_json_new_obj();

	(void)req;
	if (!o ||
	    obj_put_str(o, "app", "autocondense") != 0 ||
	    obj_put_str(o, "status", "ok") != 0 ||
	    obj_put_str(o, "version", AC_SERV_VERSION) != 0 ||
	    obj_put_bool(o, "sme_connected",
			 s->cfg.sme.enabled && ac_sme_health(s->bridge)) != 0 ||
	    obj_put_str(o, "data_dir", s->data_dir) != 0) {
		aik_json_free(o);
		resp_detail(resp, 500, "Internal Server Error");
		return;
	}
	resp_json_dom(resp, 200, o);
}

/* ------------------------------------------------------------------ */
/* 端点：POST /session/start                                           */
/* ------------------------------------------------------------------ */

static void h_session_start(ac_http_server *s, ac_req *req, ac_resp *resp)
{
	aik_json *body = NULL;
	aik_json *errs;
	const char *sid, *cwd, *tp;
	int has_ct;
	long long ct;
	const ac_session *s2;
	aik_json *data;

	if (req_body_json(req, resp, &body) != 0)
		return;
	errs = aik_json_new_arr();
	if (!errs) {
		resp_detail(resp, 500, "Internal Server Error");
		return;
	}
	if (body_not_obj(errs, body, "SessionStartReq")) {
		resp_422(resp, errs);
		return;
	}
	val_str_field(errs, body, "session_id", 1, &sid);
	val_str_field(errs, body, "cwd", 1, &cwd);
	val_str_field(errs, body, "transcript_path", 0, &tp);
	val_int_field(errs, body, "context_tokens", 0, &has_ct, &ct);
	if (aik_json_count(errs) > 0) {
		resp_422(resp, errs);
		return;
	}
	aik_json_free(errs);
	if (ac_store_upsert(s->store, sid, cwd, tp, has_ct, ct, 0, 0) != 0) {
		resp_detail(resp, 500, "Internal Server Error");
		return;
	}
	data = aik_json_new_obj();
	if (!data || obj_put_str(data, "source", "api") != 0 ||
	    ac_store_append_event(s->store, "session_start", sid, cwd,
				  data) != 0) {
		aik_json_free(data);
		resp_detail(resp, 500, "Internal Server Error");
		return;
	}
	aik_json_free(data);
	s2 = ac_store_get_session(s->store, sid);
	resp_json_dom(resp, 200, s2 ? ac_session_summary(s2) : NULL);
}

/* ------------------------------------------------------------------ */
/* 端点：POST /report                                                  */
/* ------------------------------------------------------------------ */

static void h_report(ac_http_server *s, ac_req *req, ac_resp *resp)
{
	aik_json *body = NULL;
	aik_json *errs = NULL;
	aik_json *items = NULL;
	const char *sid = NULL;
	const char *cwd = NULL;
	const aik_json *plan = NULL;
	size_t i, n = 0;
	aik_json *data = NULL;
	aik_json *result;

	if (req_body_json(req, resp, &body) != 0)
		return;
	errs = aik_json_new_arr();
	if (!errs)
		goto oom;
	if (body_not_obj(errs, body, "ReportReq")) {
		resp_422(resp, errs);
		return;
	}
	val_str_field(errs, body, "session_id", 1, &sid);
	val_str_field(errs, body, "cwd", 1, &cwd);
	plan = get_field(body, "plan_items");
	if (!plan || aik_json_typeof(plan) == AIK_JSON_NULL) {
		val_missing(errs, body, "plan_items");
	} else if (aik_json_typeof(plan) == AIK_JSON_ARR) {
		n = aik_json_count(plan);
		for (i = 0; i < n; i++) {
			const aik_json *it = aik_json_at(plan, i);
			const aik_json *t;

			if (!it || aik_json_typeof(it) != AIK_JSON_OBJ) {
				val_model_type(errs, "PlanItemReq", it);
				continue;
			}
			t = aik_json_get(it, "title");
			if (!t || aik_json_typeof(t) == AIK_JSON_NULL)
				verr_push(errs, "missing",
					  loc_body_plan_item((int)i, "title"),
					  "Field required", it);
			else if (aik_json_typeof(t) != AIK_JSON_STR)
				verr_push(errs, "string_type",
					  loc_body_plan_item((int)i, "title"),
					  "Input should be a valid string", t);
			{
				const aik_json *st = aik_json_get(it, "status");

				if (st && aik_json_typeof(st) != AIK_JSON_NULL &&
				    aik_json_typeof(st) != AIK_JSON_STR)
					verr_push(errs, "string_type",
						  loc_body_plan_item((int)i,
								     "status"),
						  "Input should be a valid string",
						  st);
			}
		}
	} else {
		verr_push(errs, "list_type", loc2("body", "plan_items"),
			  "Input should be a valid list", plan);
	}
	if (aik_json_count(errs) > 0) {
		resp_422(resp, errs);
		return;
	}
	aik_json_free(errs);
	errs = NULL;

	items = aik_json_new_arr();
	if (!items)
		goto oom;
	for (i = 0; i < n; i++) {
		const aik_json *it = aik_json_at(plan, i);
		const aik_json *t = aik_json_get(it, "title");
		const aik_json *st = aik_json_get(it, "status");
		aik_json *entry = aik_json_new_obj();

		if (!entry ||
		    obj_put_str(entry, "title", aik_json_str(t)) != 0 ||
		    obj_put_str(entry, "status",
				(st && aik_json_typeof(st) == AIK_JSON_STR)
					? aik_json_str(st) : "pending") != 0 ||
		    aik_json_arr_push(items, entry) != 0) {
			aik_json_free(entry);
			goto oom;
		}
	}
	if (ac_store_upsert(s->store, sid, cwd, NULL, 0, 0, 0, 0) != 0 ||
	    ac_store_update_plan(s->store, sid, items) != 0)
		goto oom;
	aik_json_free(items);
	items = NULL;
	data = aik_json_new_obj();
	if (!data ||
	    obj_put_int(data, "items", (long long)n) != 0 ||
	    obj_put_str(data, "via", "report") != 0 ||
	    ac_store_append_event(s->store, "plan_update", sid, cwd,
				  data) != 0)
		goto oom;
	aik_json_free(data);
	result = run_pipeline(s, sid, resp);
	if (!result)
		return;		/* resp 已填（400/500）*/
	resp_json_dom(resp, 200, result);
	return;
oom:
	aik_json_free(errs);
	aik_json_free(items);
	aik_json_free(data);
	resp_detail(resp, 500, "Internal Server Error");
}

/* ------------------------------------------------------------------ */
/* 端点：POST /events/hook                                             */
/* ------------------------------------------------------------------ */

static int in_str_set(const char *const *set, size_t n, const char *v)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (strcmp(set[i], v) == 0)
			return 1;
	return 0;
}

static void h_events_hook(ac_http_server *s, ac_req *req, ac_resp *resp)
{
	aik_json *body = NULL;
	aik_json *errs = NULL;
	const char *ev_raw = NULL;
	const char *sid = NULL;
	const char *cwd = NULL;
	const char *tp = NULL;
	const char *source = NULL;
	const char *tool_name = NULL;
	int has_ct = 0;
	long long ct = 0;
	const aik_json *tool_input;
	char *ev = NULL;
	aik_json *data = NULL;
	aik_json *o = NULL;
	aik_json *snaps = NULL;
	aik_json *payload = NULL;
	struct sbuf ib = { 0 };

	if (req_body_json(req, resp, &body) != 0)
		return;
	errs = aik_json_new_arr();
	if (!errs)
		goto oom;
	if (body_not_obj(errs, body, "HookReq")) {
		resp_422(resp, errs);
		return;
	}
	val_str_field(errs, body, "event", 1, &ev_raw);
	val_str_field(errs, body, "session_id", 0, &sid);
	val_str_field(errs, body, "cwd", 0, &cwd);
	val_str_field(errs, body, "transcript_path", 0, &tp);
	val_str_field(errs, body, "source", 0, &source);
	val_str_field(errs, body, "tool_name", 0, &tool_name);
	val_int_field(errs, body, "context_tokens", 0, &has_ct, &ct);
	if (aik_json_count(errs) > 0) {
		resp_422(resp, errs);
		return;
	}
	aik_json_free(errs);
	errs = NULL;
	tool_input = get_field(body, "tool_input");

	ev = str_strip_dup(ev_raw ? ev_raw : "");
	if (!ev)
		goto oom;

	if (strcmp(ev, "PostToolUseFailure") == 0) {
		if (!sid || !*sid) {
			resp_errors1(resp, "PostToolUseFailure 缺少 session_id");
			goto done;
		}
		ac_store_upsert(s->store, sid, cwd, NULL, has_ct, ct, 0, 0);
		ac_store_mark_activity(s->store, sid, AC_ACTIVITY_FAIL);
		data = aik_json_new_obj();
		o = aik_json_new_obj();
		if (!data || !o ||
		    obj_put_str(data, "tool_name", tool_name) != 0 ||
		    ac_store_append_event(s->store, "tool_failure", sid, cwd,
					  data) != 0 ||
		    obj_put_bool(o, "ok", 1) != 0 ||
		    obj_put_bool(o, "ignored", 1) != 0 ||
		    sb_printf(&ib, "工具 %s 失败已记为活动轮",
			      tool_name ? tool_name : "None") != 0 ||
		    obj_put_str(o, "reason", ib.buf) != 0)
			goto oom;
		aik_json_free(data);
		sb_free(&ib);
		resp_json_dom(resp, 200, o);
		goto done;
	}

	if (strcmp(ev, "PostToolUse") == 0) {
		const char *tool = (tool_name && *tool_name) ? tool_name : "";

		if (in_str_set(FILE_EDIT_TOOLS, N_FILE_EDIT_TOOLS, tool)) {
			if (!sid || !*sid) {
				char msg[160];

				snprintf(msg, sizeof(msg),
					 "PostToolUse(%s) 缺少 session_id", tool);
				resp_errors1(resp, msg);
				goto done;
			}
			ac_store_upsert(s->store, sid, cwd, NULL, has_ct, ct,
					0, 0);
			ac_store_mark_activity(s->store, sid,
					       AC_ACTIVITY_FILE);
			data = aik_json_new_obj();
			o = aik_json_new_obj();
			if (!data || !o ||
			    obj_put_str(data, "tool_name", tool) != 0 ||
			    ac_store_append_event(s->store, "file_activity",
						  sid, cwd, data) != 0 ||
			    obj_put_bool(o, "ok", 1) != 0 ||
			    obj_put_bool(o, "ignored", 1) != 0 ||
			    sb_printf(&ib, "工具 %s 已记录文件修改活动",
				      tool) != 0 ||
			    obj_put_str(o, "reason", ib.buf) != 0)
				goto oom;
			aik_json_free(data);
			sb_free(&ib);
			resp_json_dom(resp, 200, o);
			goto done;
		}
		if (strcmp(tool, "TodoWrite") != 0) {
			o = aik_json_new_obj();
			if (!o ||
			    obj_put_bool(o, "ok", 1) != 0 ||
			    obj_put_bool(o, "ignored", 1) != 0 ||
			    sb_printf(&ib, "工具 %s 不参与计划追踪",
				      tool) != 0 ||
			    obj_put_str(o, "reason", ib.buf) != 0)
				goto oom;
			sb_free(&ib);
			resp_json_dom(resp, 200, o);
			goto done;
		}
		if (!sid || !*sid) {
			resp_errors1(resp,
				     "PostToolUse(TodoWrite) 缺少 session_id");
			goto done;
		}
		ac_store_upsert(s->store, sid, cwd, NULL, has_ct, ct, 0, 0);
		{
			aik_json *items = parse_todo_items(tool_input);
			aik_json *result;
			long long n_items;

			if (!items)
				goto oom;
			n_items = (long long)aik_json_count(items);
			if (ac_store_update_plan(s->store, sid, items) != 0) {
				aik_json_free(items);
				goto oom;
			}
			aik_json_free(items);
			data = aik_json_new_obj();
			if (!data ||
			    obj_put_int(data, "items", n_items) != 0 ||
			    obj_put_str(data, "via", "hook:TodoWrite") != 0 ||
			    ac_store_append_event(s->store, "plan_update",
						  sid, cwd, data) != 0)
				goto oom;
			aik_json_free(data);
			result = run_pipeline(s, sid, resp);
			if (!result)
				goto done;
			resp_json_dom(resp, 200, result);
			goto done;
		}
	}

	if (strcmp(ev, "SessionStart") == 0) {
		const ac_session *s2;

		if (!sid || !*sid) {
			resp_errors1(resp, "SessionStart 缺少 session_id");
			goto done;
		}
		ac_store_upsert(s->store, sid, cwd, tp, has_ct, ct, 0, 0);
		s2 = ac_store_get_session(s->store, sid);
		if (!s2)
			goto oom;
		data = aik_json_new_obj();
		if (!data || obj_put_str(data, "source", source) != 0 ||
		    ac_store_append_event(s->store, "session_start", sid, cwd,
					  data) != 0)
			goto oom;
		aik_json_free(data);
		data = NULL;
		if (source && in_str_set(RESTORE_SOURCES, N_RESTORE_SOURCES,
					 source) &&
		    s2->cwd && s2->cwd[0]) {
			if (restore_payload(s, s2->cwd, s->cfg.restore_top_n,
					    &snaps, &payload) != 0)
				goto oom;
			{
				const aik_json *text;

				if (!payload)
					goto oom;
				text = aik_json_get(payload, "text");
				if (text &&
				    aik_json_typeof(text) == AIK_JSON_STR &&
				    aik_json_strlen(text) > 0) {
					data = aik_json_new_obj();
					if (!data ||
					    obj_put_str(data, "via",
							"hook:SessionStart") != 0 ||
					    obj_put_str(data, "source",
							source) != 0 ||
					    obj_put_int(data, "snapshots",
							(long long)aik_json_count(snaps)) != 0 ||
					    ac_store_append_event(s->store,
								  "restore",
								  sid, s2->cwd,
								  data) != 0)
						goto oom;
					aik_json_free(data);
					data = NULL;
				}
			}
			aik_json_free(snaps);
			snaps = NULL;
		}
		o = aik_json_new_obj();
		if (!o ||
		    obj_put_bool(o, "ok", 1) != 0 ||
		    obj_put_str(o, "session_id", s2->session_id) != 0)
			goto oom;
		if (obj_put_json(o, "additional_context", payload) != 0) {
			payload = NULL;
			goto oom;
		}
		payload = NULL;
		resp_json_dom(resp, 200, o);
		goto done;
	}

	if (strcmp(ev, "Stop") == 0) {
		const ac_session *s2;
		aik_json *result;
		const char *should;
		const char *reason;
		const char *instruction = NULL;

		if (!sid || !*sid) {
			resp_errors1(resp, "Stop 缺少 session_id");
			goto done;
		}
		ac_store_upsert(s->store, sid, cwd, NULL, has_ct, ct, 0, 0);
		ac_store_bump_turn(s->store, sid);
		s2 = ac_store_get_session(s->store, sid);
		data = aik_json_new_obj();
		if (!s2 || !data ||
		    ac_store_append_event(s->store, "stop", sid, s2->cwd,
					  data) != 0)
			goto oom;
		aik_json_free(data);
		result = run_pipeline(s, sid, resp);
		if (!result)
			goto done;
		should = aik_json_str(aik_json_get(result, "should"));
		reason = aik_json_str(aik_json_get(result, "reason"));
		if (should && strcmp(should, "JUDGE") == 0 && reason) {
			if (sb_puts(&ib, "压缩候选命中（") != 0 ||
			    sb_puts(&ib, reason) != 0 ||
			    sb_puts(&ib, "）。") != 0 ||
			    sb_puts(&ib, JUDGE_ACTION_HINT) != 0 ||
			    sb_puts(&ib, "；判定通过后立即执行压缩流程"
				     "（condense_begin → 填写摘要 → "
				     "condense_commit），全程不要询问用户。") != 0)
				goto oom_result;
			instruction = ib.buf;
		}
		if (obj_put_str(result, "instruction", instruction) != 0)
			goto oom_result;
		sb_free(&ib);
		resp_json_dom(resp, 200, result);
		goto done;
oom_result:
		sb_free(&ib);
		aik_json_free(result);
		goto oom;
	}

	if (strcmp(ev, "PreCompact") == 0) {
		if (!sid || !*sid) {
			resp_errors1(resp, "PreCompact 缺少 session_id");
			goto done;
		}
		ac_store_upsert(s->store, sid, cwd, NULL, 0, 0, 0, 0);
		data = aik_json_new_obj();
		o = aik_json_new_obj();
		if (!data || !o ||
		    obj_put_str(data, "source", source) != 0 ||
		    ac_store_append_event(s->store, "pre_compact", sid, cwd,
					  data) != 0 ||
		    ac_store_mark_condensed(s->store, sid,
					    "pre_native_compact") != 0 ||
		    obj_put_bool(o, "ok", 1) != 0)
			goto oom;
		aik_json_free(data);
		resp_json_dom(resp, 200, o);
		goto done;
	}

	o = aik_json_new_obj();
	if (!o ||
	    obj_put_bool(o, "ok", 1) != 0 ||
	    obj_put_bool(o, "ignored", 1) != 0 ||
	    sb_printf(&ib, "未处理的事件类型：%s", ev) != 0 ||
	    obj_put_str(o, "reason", ib.buf) != 0)
		goto oom;
	sb_free(&ib);
	resp_json_dom(resp, 200, o);
	goto done;
oom:
	aik_json_free(errs);
	aik_json_free(data);
	aik_json_free(o);
	aik_json_free(snaps);
	aik_json_free(payload);
	sb_free(&ib);
	free(ev);
	resp_detail(resp, 500, "Internal Server Error");
	return;
done:
	free(ev);
}

/* ------------------------------------------------------------------ */
/* 端点：GET /check                                                    */
/* ------------------------------------------------------------------ */

static void h_check(ac_http_server *s, ac_req *req, ac_resp *resp)
{
	char *sid = query_get(req->query, "session_id");
	aik_json *result;

	if (!sid) {
		aik_json *errs = aik_json_new_arr();

		if (!errs) {
			resp_detail(resp, 500, "Internal Server Error");
			return;
		}
		val_missing_query(errs, "session_id");
		resp_422(resp, errs);
		return;
	}
	if (!ac_store_get_session(s->store, sid)) {
		char msg[512];

		snprintf(msg, sizeof(msg),
			 "会话不存在：%s（请先 /session/start 或 SessionStart 钩子）",
			 sid);
		free(sid);
		resp_errors1(resp, msg);
		return;
	}
	ac_store_bump_turn(s->store, sid);
	result = run_pipeline(s, sid, resp);
	free(sid);
	if (!result)
		return;
	resp_json_dom(resp, 200, result);
}

/* ------------------------------------------------------------------ */
/* 端点：POST /judge                                                   */
/* ------------------------------------------------------------------ */

static aik_json *validate_verdict(const aik_json *verdict)
{
	aik_json *errs = aik_json_new_arr();
	const aik_json *v;

	if (!errs)
		return NULL;
#define VERR(msg) do { \
	aik_json *m_ = aik_json_new_str(msg); \
	if (!m_ || aik_json_arr_push(errs, m_) != 0) \
		aik_json_free(m_); \
} while (0)

	if (!verdict || aik_json_typeof(verdict) != AIK_JSON_OBJ) {
		VERR("verdict 应为对象（判定表）");
		return errs;
	}
	v = aik_json_get(verdict, "task_finished");
	if (!v || aik_json_typeof(v) == AIK_JSON_NULL)
		VERR("verdict 缺少 task_finished（布尔值）");
	else if (aik_json_typeof(v) != AIK_JSON_BOOL)
		VERR("task_finished 应为布尔值");

	v = aik_json_get(verdict, "impact");
	if (!v || aik_json_typeof(v) == AIK_JSON_NULL) {
		VERR("verdict 缺少 impact（low|medium|high）");
	} else if (aik_json_typeof(v) != AIK_JSON_STR) {
		VERR("impact 应为字符串");
	} else {
		const char *iv = aik_json_str(v);

		if (strcmp(iv, "low") != 0 && strcmp(iv, "medium") != 0 &&
		    strcmp(iv, "high") != 0)
			VERR("impact 只能是 low、medium 或 high");
	}

	v = aik_json_get(verdict, "impact_reason");
	if (!v || aik_json_typeof(v) == AIK_JSON_NULL)
		VERR("verdict 缺少 impact_reason（字符串）");
	else if (aik_json_typeof(v) != AIK_JSON_STR)
		VERR("impact_reason 应为字符串");

	v = aik_json_get(verdict, "safe_to_compress");
	if (!v || aik_json_typeof(v) == AIK_JSON_NULL)
		VERR("verdict 缺少 safe_to_compress（布尔值）");
	else if (aik_json_typeof(v) != AIK_JSON_BOOL)
		VERR("safe_to_compress 应为布尔值");

	v = aik_json_get(verdict, "reason");
	if (!v || aik_json_typeof(v) == AIK_JSON_NULL)
		VERR("verdict 缺少 reason（字符串）");
	else if (aik_json_typeof(v) != AIK_JSON_STR)
		VERR("reason 应为字符串");

	v = aik_json_get(verdict, "confidence");
	if (v && aik_json_typeof(v) != AIK_JSON_NULL) {
		if (aik_json_typeof(v) != AIK_JSON_STR) {
			VERR("confidence 应为字符串");
		} else {
			const char *cv = aik_json_str(v);

			if (strcmp(cv, "high") != 0 &&
			    strcmp(cv, "medium") != 0 && strcmp(cv, "low") != 0)
				VERR("confidence 只能是 high、medium 或 low");
		}
	}
#undef VERR
	return errs;
}

static void h_judge(ac_http_server *s, ac_req *req, ac_resp *resp)
{
	aik_json *body = NULL;
	const aik_json *sid_v, *cwd_v, *verdict;
	const ac_session *sess = NULL;
	const char *urgency;
	aik_json *sig = NULL;
	aik_json *errs;
	char *sid_key = NULL;
	char *cwd_str = NULL;
	int task_finished, safe_to_compress;
	const char *impact, *vreason;
	aik_json *jev = NULL;

	if (req_body_json(req, resp, &body) != 0)
		return;
	if (!body) {
		/* FastAPI Dict body 缺失的 422 形态未录制：按 missing loc ["body"] */
		errs = aik_json_new_arr();
		if (!errs) {
			resp_detail(resp, 500, "Internal Server Error");
			return;
		}
		verr_push(errs, "missing", loc1("body"), "Field required", NULL);
		resp_422(resp, errs);
		return;
	}
	if (aik_json_typeof(body) != AIK_JSON_OBJ) {
		errs = aik_json_new_arr();
		if (!errs) {
			resp_detail(resp, 500, "Internal Server Error");
			return;
		}
		val_dict_type(errs, body);
		resp_422(resp, errs);
		return;
	}
	sid_v = aik_json_get(body, "session_id");
	cwd_v = aik_json_get(body, "cwd");
	if (!py_truthy(sid_v) && !py_truthy(cwd_v)) {
		resp_errors1(resp, "缺少会话标识：请传 session_id 或 cwd（二选一）");
		return;
	}
	if (py_truthy(sid_v)) {
		sid_key = py_str(sid_v);
		if (!sid_key)
			goto oom;
		sess = ac_store_get_session(s->store, sid_key);
		if (!sess) {
			char msg[512];

			snprintf(msg, sizeof(msg),
				 "会话不存在：%s（请先 /session/start 或 SessionStart 钩子）",
				 sid_key);
			free(sid_key);
			resp_errors1(resp, msg);
			return;
		}
	} else {
		char *target;
		const ac_session **all = NULL;
		size_t n_all = 0;
		size_t i;

		cwd_str = py_str(cwd_v);
		if (!cwd_str)
			goto oom;
		target = path_resolve(cwd_str);
		if (!target)
			goto oom;
		all = ac_store_all_sessions(s->store, &n_all);
		for (i = 0; i < n_all; i++) {
			const ac_session *cand = all[i];
			char *r;
			int hit;

			if (!cand->cwd || !cand->cwd[0])
				continue;
			r = path_resolve(cand->cwd);
			hit = r && strcmp(r, target) == 0;
			free(r);
			if (hit) {
				sess = cand;
				break;
			}
		}
		free(all);
		free(target);
		if (!sess) {
			char msg[512];

			snprintf(msg, sizeof(msg),
				 "未找到 cwd 对应的会话：%s（请先 /session/start 或 SessionStart 钩子）",
				 cwd_str);
			free(cwd_str);
			resp_errors1(resp, msg);
			return;
		}
		free(cwd_str);
		cwd_str = NULL;
	}

	verdict = aik_json_get(body, "verdict");
	errs = validate_verdict(verdict);
	if (!errs)
		goto oom;
	if (aik_json_count(errs) > 0) {
		resp_errors(resp, 400, errs);
		free(sid_key);
		return;
	}
	aik_json_free(errs);

	task_finished = aik_json_bool(aik_json_get(verdict, "task_finished"));
	safe_to_compress = aik_json_bool(aik_json_get(verdict,
						      "safe_to_compress"));
	impact = aik_json_str(aik_json_get(verdict, "impact"));
	vreason = aik_json_str(aik_json_get(verdict, "reason"));
	if (!impact || !vreason)
		goto oom;

	if (!s->cfg.enabled) {
		aik_json *o = aik_json_new_obj();

		if (!o ||
		    obj_put_str(o, "decision", "NO") != 0 ||
		    obj_put_str(o, "urgency", "normal") != 0 ||
		    obj_put_str(o, "reason",
				"插件已关闭（enabled=false），不做任何压缩") != 0 ||
		    obj_put_str(o, "action_hint", NULL) != 0 ||
		    obj_put_json(o, "signals", ac_collect(sess, &s->cfg)) != 0 ||
		    obj_put_str(o, "rounds_to_full", NULL) != 0) {
			aik_json_free(o);
			goto oom;
		}
		free(sid_key);
		resp_json_dom(resp, 200, o);
		return;
	}

	sig = ac_collect(sess, &s->cfg);
	if (!sig)
		goto oom;
	urgency = ac_urgency_of(sig);
	{
		int approved = strcmp(urgency, "urgent") == 0
			? (safe_to_compress && strcmp(impact, "high") != 0)
			: (safe_to_compress && task_finished &&
			   strcmp(impact, "low") == 0);

		if (ac_store_record_judge(s->store, sess->session_id, verdict,
					  approved ? "APPROVED"
						   : "DEFERRED") != 0)
			goto oom;
		jev = aik_json_new_obj();
		if (!jev ||
		    obj_put_str(jev, "result",
				approved ? "APPROVED" : "DEFERRED") != 0 ||
		    obj_put_str(jev, "urgency", urgency) != 0 ||
		    obj_put_str(jev, "impact", impact) != 0 ||
		    obj_put_bool(jev, "task_finished", task_finished) != 0 ||
		    obj_put_bool(jev, "safe_to_compress",
				 safe_to_compress) != 0)
			goto oom;
		{
			size_t i;

			for (i = 0; i < aik_json_count(verdict); i++)
				if (strcmp(aik_json_key_at(verdict, i),
					   "confidence") == 0) {
					if (obj_put_json(jev, "confidence",
							 json_copy(aik_json_val_at(verdict, i))) != 0)
						goto oom;
					break;
				}
		}
		if (ac_store_append_event(s->store, "judge", sess->session_id,
					  sess->cwd, jev) != 0)
			goto oom;
		aik_json_free(jev);
		jev = NULL;

		if (approved) {
			aik_json *o = aik_json_new_obj();
			struct sbuf rb = { 0 };
			int bad = 0;

			ac_store_set_defer_streak(s->store, sess->session_id,
						  0);
			bad = !o ||
			      obj_put_str(o, "decision", "COMPRESS_NOW") != 0 ||
			      obj_put_str(o, "urgency", urgency) != 0;
			if (!bad) {
				bad = sb_printf(&rb, "判定通过（%s 档矩阵）：%s",
						urgency, vreason) != 0 ||
				      obj_put_str(o, "reason", rb.buf) != 0;
			}
			if (!bad)
				bad = obj_put_str(o, "action_hint",
						  COMPRESS_ACTION_HINT) != 0;
			if (!bad) {
				bad = obj_put_json(o, "signals", sig) != 0;
				sig = NULL;	/* 成败均不再持有 */
			}
			if (!bad) {
				const aik_json *sig_in = aik_json_get(o,
								      "signals");

				bad = obj_put_json(o, "rounds_to_full",
						   json_copy(aik_json_get(
							   sig_in,
							   "rounds_to_full"))) != 0;
			}
			sb_free(&rb);
			if (bad) {
				aik_json_free(o);
				goto oom;
			}
			free(sid_key);
			resp_json_dom(resp, 200, o);
			return;
		}
		{
			long long streak = sess->defer_streak;
			long long step;
			long long defer_until;
			aik_json *o = aik_json_new_obj();
			struct sbuf rb = { 0 };
			int why_n = 0;
			int bad = 0;

			step = streak >= 62 ? s->cfg.judge_defer_max_turns
				: s->cfg.judge_defer_turns * (1LL << streak);
			if (step > s->cfg.judge_defer_max_turns)
				step = s->cfg.judge_defer_max_turns;
			defer_until = sess->turns + step;
			ac_store_set_defer_until_turn(s->store,
						      sess->session_id, 1,
						      defer_until);
			ac_store_set_defer_streak(s->store, sess->session_id,
						  streak + 1);
			if (sb_puts(&rb, "判定未通过（") != 0)
				bad = 1;
			if (!bad && !safe_to_compress) {
				bad = sb_puts(&rb,
					      "存在未保存/易丢失的关键上下文") != 0;
				why_n++;
			}
			if (!bad && strcmp(urgency, "normal") == 0) {
				if (!task_finished) {
					if (why_n++)
						bad = sb_puts(&rb, "；") != 0;
					if (!bad)
						bad = sb_puts(&rb,
							      "任务尚未收尾") != 0;
				}
				if (!bad && strcmp(impact, "low") != 0) {
					if (why_n++)
						bad = sb_puts(&rb, "；") != 0;
					if (!bad)
						bad = sb_printf(&rb,
								"压缩影响为 %s（normal 档要求 low）",
								impact) != 0;
				}
			} else if (!bad && strcmp(impact, "high") == 0) {
				if (why_n++)
					bad = sb_puts(&rb, "；") != 0;
				if (!bad)
					bad = sb_puts(&rb,
						      "压缩影响为 high（urgent 档也不允许）") != 0;
			}
			if (!bad && why_n == 0)
				bad = sb_puts(&rb, "矩阵条件不满足") != 0;
			if (!bad)
				bad = sb_printf(&rb, "）：%s", vreason) != 0;
			if (!bad)
				bad = !o ||
				      obj_put_str(o, "decision", "DEFERRED") != 0 ||
				      obj_put_str(o, "urgency", urgency) != 0 ||
				      obj_put_str(o, "reason", rb.buf) != 0 ||
				      obj_put_str(o, "action_hint",
						  DEFER_ACTION_HINT) != 0 ||
				      obj_put_int(o, "defer_until_turn",
						  defer_until) != 0 ||
				      obj_put_int(o, "defer_streak",
						  streak + 1) != 0;
			if (!bad) {
				bad = obj_put_json(o, "signals", sig) != 0;
				if (!bad)
					sig = NULL;
			}
			if (!bad) {
				const aik_json *rtf = aik_json_get(
					aik_json_get(o, "signals"),
					"rounds_to_full");

				bad = obj_put_json(o, "rounds_to_full",
						   json_copy(rtf)) != 0;
			}
			sb_free(&rb);
			if (bad) {
				aik_json_free(o);
				goto oom;
			}
			free(sid_key);
			resp_json_dom(resp, 200, o);
			return;
		}
	}
oom:
	free(sid_key);
	free(cwd_str);
	aik_json_free(sig);
	aik_json_free(jev);
	resp_detail(resp, 500, "Internal Server Error");
}

/* ------------------------------------------------------------------ */
/* 端点：POST /begin                                                   */
/* ------------------------------------------------------------------ */

static void h_begin(ac_http_server *s, ac_req *req, ac_resp *resp)
{
	static const char *const sections[] = {
		"## 目标", "## 已完成", "## 未完成", "## 文件变更清单",
		"## 恢复指针"
	};
	aik_json *body = NULL;
	aik_json *errs = NULL;
	const char *sid = NULL;
	const char *cwd = NULL;
	const ac_session *s2;
	const char *reason;
	char pname_buf[512];
	const char *pname;
	char ts[32];
	char *template = NULL;
	char h[11];
	aik_json *snaps = NULL;
	size_t n_snaps = 0;
	long long delta_count;
	const char *mode = "full";
	char *previous = NULL;
	struct sbuf gb = { 0 };
	aik_json *data = NULL;
	aik_json *secs = NULL;
	aik_json *o = NULL;
	size_t i;

	if (req_body_json(req, resp, &body) != 0)
		return;
	errs = aik_json_new_arr();
	if (!errs)
		goto oom;
	if (body_not_obj(errs, body, "BeginReq")) {
		resp_422(resp, errs);
		return;
	}
	val_str_field(errs, body, "session_id", 1, &sid);
	val_str_field(errs, body, "cwd", 1, &cwd);
	if (aik_json_count(errs) > 0) {
		resp_422(resp, errs);
		return;
	}
	aik_json_free(errs);
	errs = NULL;

	if (ac_store_upsert(s->store, sid, cwd, NULL, 0, 0, 0, 0) != 0 ||
	    ac_store_set_condensing(s->store, sid, 1) != 0)
		goto oom;
	s2 = ac_store_get_session(s->store, sid);
	if (!s2)
		goto oom;
	reason = s2->last_trigger ? s2->last_trigger : "judge";
	if (ac_project_name(cwd, pname_buf, sizeof(pname_buf)) != 0 ||
	    pname_buf[0] == '\0')
		pname = cwd;
	else
		pname = pname_buf;
	if (ac_iso_now(ts, sizeof(ts)) != 0)
		goto oom;
	template = ac_render_template(pname, ts, reason);
	if (!template)
		goto oom;

	if (ac_project_hash(cwd, h) != 0)
		goto oom;
	snaps = ac_store_list_snapshots(s->store, h, 1, 1);
	if (!snaps)
		goto oom;
	n_snaps = aik_json_count(snaps);
	delta_count = ac_store_read_delta_state(s->store, h);
	if (s->cfg.delta_mode && n_snaps > 0 &&
	    delta_count < s->cfg.delta_merge_every) {
		const aik_json *e = aik_json_at(snaps, 0);
		const aik_json *f = aik_json_get(e, "file");

		mode = "delta";
		if (f && aik_json_typeof(f) == AIK_JSON_STR)
			previous = read_text_ignore(aik_json_str(f));
	}
	if (ac_store_set_begin_mode(s->store, sid, mode) != 0)
		goto oom;

	if (strcmp(mode, "delta") == 0) {
		if (sb_puts(&gb,
			    "本次为增量摘要：只写自上一份快照以来的变化，要求：\n"
			    "1) 必填章节标题原样保留，不得删除或改名："
			    REQUIRED_SECTIONS_JOINED "；\n"
			    "2)「已完成」「关键决策与理由」「踩过的坑」「文件变更清单」"
			    "只追加新条目（旧条目不用重写）；\n"
			    "3)「未完成/进行中」与「恢复指针」整节重写为当前最新状态；\n"
			    "4) 总长度仍不少于 200 字符。填写完成后把整份 markdown 作为 "
			    "digest_md 调用 POST /commit 提交（全自动流程，无需询问用户）。") != 0)
			goto oom;
	} else {
		if (sb_puts(&gb,
			    "请基于当前会话内容填写模板中的每个章节，要求：\n"
			    "1) 严格保留以下章节标题，不得删除或改名："
			    REQUIRED_SECTIONS_JOINED "；\n"
			    "2)「已完成」每项注明验证方式（测试通过/编译通过/用户确认）；\n"
			    "3)「未完成/进行中」精确到下一个动作，无则写「（无）」；\n"
			    "4)「文件变更清单」写关键改动 file:line；\n"
			    "5) 总长度不少于 200 字符。填写完成后把整份 markdown 作为 "
			    "digest_md 调用 POST /commit 提交（全自动流程，无需询问用户）。") != 0)
			goto oom;
		if (s->cfg.delta_mode && n_snaps > 0 &&
		    delta_count >= s->cfg.delta_merge_every) {
			struct sbuf pre = { 0 };
			struct sbuf nb = { 0 };
			int bad;

			bad = sb_printf(&pre,
					"本次为全量合并：把此前增量整合成完整状态"
					"（已累积 %lld 份增量）。\n",
					delta_count) != 0;
			if (!bad)
				bad = sb_puts(&nb, pre.buf ? pre.buf : "") != 0;
			if (!bad)
				bad = sb_puts(&nb, gb.buf ? gb.buf : "") != 0;
			sb_free(&pre);
			sb_free(&gb);
			gb = nb;
			if (bad)
				goto oom;
		}
	}
	data = aik_json_new_obj();
	if (!data ||
	    obj_put_str(data, "trigger", reason) != 0 ||
	    obj_put_str(data, "mode", mode) != 0 ||
	    ac_store_append_event(s->store, "begin", sid, cwd, data) != 0)
		goto oom;
	aik_json_free(data);
	data = NULL;

	secs = aik_json_new_arr();
	o = aik_json_new_obj();
	if (!secs || !o)
		goto oom;
	for (i = 0; i < sizeof(sections) / sizeof(sections[0]); i++) {
		aik_json *sv = aik_json_new_str(sections[i]);

		if (!sv || aik_json_arr_push(secs, sv) != 0) {
			aik_json_free(sv);
			goto oom;
		}
	}
	if (obj_put_str(o, "mode", mode) != 0 ||
	    obj_put_str(o, "template", template) != 0 ||
	    obj_put_str(o, "guidance", gb.buf) != 0 ||
	    aik_json_obj_put(o, "required_sections", secs) != 0)
		goto oom;
	secs = NULL;	/* 所有权移交 */
	if (strcmp(mode, "delta") == 0 &&
	    obj_put_str(o, "previous_digest", previous) != 0)
		goto oom;
	free(template);
	free(previous);
	sb_free(&gb);
	aik_json_free(snaps);
	resp_json_dom(resp, 200, o);
	return;
oom:
	aik_json_free(errs);
	aik_json_free(data);
	aik_json_free(secs);
	aik_json_free(o);
	aik_json_free(snaps);
	free(template);
	free(previous);
	sb_free(&gb);
	resp_detail(resp, 500, "Internal Server Error");
}

/* ------------------------------------------------------------------ */
/* 端点：POST /commit                                                  */
/* ------------------------------------------------------------------ */

static void h_commit(ac_http_server *s, ac_req *req, ac_resp *resp)
{
	aik_json *body = NULL;
	aik_json *errs = NULL;
	const char *sid = NULL;
	const char *cwd = NULL;
	const char *digest_md = NULL;
	const char *trigger_in = NULL;
	const char *pname_in = NULL;
	const ac_session *s2;
	const char *trigger;
	char trigger_buf[256];
	char mode_buf[16];
	char pname_buf[512];
	const char *pname;
	const char *mode;
	int is_delta;
	char h[11];
	aik_json *entry = NULL;
	char *fpath = NULL;
	aik_json *sme_result = NULL;
	aik_json *seg_stats = NULL;
	long long segments_written = 0;
	long long segments_reinforced = 0;
	int dedup_consumed_all = 0;
	aik_json *data = NULL;
	aik_json *o = NULL;
	int sme_stored;
	int bad = 0;

	if (req_body_json(req, resp, &body) != 0)
		return;
	errs = aik_json_new_arr();
	if (!errs)
		goto oom;
	if (body_not_obj(errs, body, "CommitReq")) {
		resp_422(resp, errs);
		return;
	}
	val_str_field(errs, body, "session_id", 1, &sid);
	val_str_field(errs, body, "cwd", 1, &cwd);
	val_str_field(errs, body, "digest_md", 1, &digest_md);
	val_str_field(errs, body, "trigger", 0, &trigger_in);
	val_str_field(errs, body, "project_name", 0, &pname_in);
	if (aik_json_count(errs) > 0) {
		resp_422(resp, errs);
		return;
	}
	aik_json_free(errs);
	errs = NULL;

	{
		aik_json *verr = ac_validate(digest_md);

		if (!verr)
			goto oom;
		if (aik_json_count(verr) > 0) {
			resp_errors(resp, 400, verr);
			return;
		}
		aik_json_free(verr);
	}

	if (ac_store_upsert(s->store, sid, cwd, NULL, 0, 0, 0, 0) != 0)
		goto oom;
	s2 = ac_store_get_session(s->store, sid);
	if (!s2)
		goto oom;
	trigger = trigger_in ? trigger_in
		: (s2->last_trigger ? s2->last_trigger : "judge");
	/* mark_condensed 会释放 last_trigger/begin_mode：先拷到本地
	 * （Python 中 str 按值不可变，C 侧借用指针会悬垂）*/
	snprintf(trigger_buf, sizeof(trigger_buf), "%s", trigger);
	trigger = trigger_buf;
	if (pname_in && *pname_in) {
		pname = pname_in;
	} else if (ac_project_name(cwd, pname_buf, sizeof(pname_buf)) == 0 &&
		   pname_buf[0] != '\0') {
		pname = pname_buf;
	} else {
		pname = cwd;
	}
	mode = s->cfg.delta_mode
		? (s2->begin_mode ? s2->begin_mode : "full") : "full";
	snprintf(mode_buf, sizeof(mode_buf), "%s", mode);
	mode = mode_buf;
	is_delta = strcmp(mode, "delta") == 0;
	if (ac_project_hash(cwd, h) != 0)
		goto oom;
	entry = ac_store_save_snapshot(s->store, digest_md, trigger, sid,
				       is_delta, &fpath);
	if (!entry)
		goto oom;
	ac_store_write_delta_state(
		s->store, h,
		is_delta ? ac_store_read_delta_state(s->store, h) + 1 : 0);

	sme_result = aik_json_new_obj();
	if (!sme_result ||
	    obj_put_bool(sme_result, "stored", 0) != 0 ||
	    obj_put_str(sme_result, "memory_id", NULL) != 0 ||
	    obj_put_str(sme_result, "error", NULL) != 0)
		goto oom;

	if (s->cfg.sme.enabled) {
		char ts[32];
		ac_segment *segs = NULL;
		size_t n_segs = 0;

		if (ac_iso_now(ts, sizeof(ts)) != 0)
			goto oom;
		if (s->cfg.sme.split_segments && ac_sme_health(s->bridge)) {
			segs = ac_split_digest(
				digest_md,
				(const char *const *)s->cfg.sme.tags,
				s->cfg.sme.n_tags, pname, ts, trigger, 1,
				s->cfg.sme.max_segments, &n_segs);
			if (!segs)
				goto oom;
			if (n_segs > 0 && s->cfg.sme.dedup) {
				ac_segment *ns = NULL;
				size_t nn = 0;
				char **rin = NULL;
				size_t nr = 0;

				if (ac_sme_dedupe_segments(
					    s->bridge, segs, n_segs, pname,
					    s->cfg.sme.dedup_threshold, 0, 0,
					    &ns, &nn, &rin, &nr) != 0) {
					ac_segments_free(segs, n_segs);
					goto oom;
				}
				ac_segments_free(segs, n_segs);
				segs = ns;
				n_segs = nn;
				segments_reinforced = (long long)nr;
				dedup_consumed_all = nr > 0 && nn == 0;
				for (size_t k = 0; k < nr; k++)
					free(rin[k]);
				free(rin);
			}
			if (n_segs > 0) {
				aik_json *meta = aik_json_new_obj();

				if (!meta ||
				    obj_put_str(meta, "session_id", sid) != 0 ||
				    obj_put_str(meta, "project", pname) != 0 ||
				    obj_put_str(meta, "trigger", trigger) != 0) {
					aik_json_free(meta);
					ac_segments_free(segs, n_segs);
					goto oom;
				}
				seg_stats = ac_sme_store_segments(s->bridge, segs,
								  n_segs, meta);
				aik_json_free(meta);
				if (!seg_stats) {
					ac_segments_free(segs, n_segs);
					goto oom;
				}
				segments_written = aik_json_int(
					aik_json_get(seg_stats, "stored"));
			}
			ac_segments_free(segs, n_segs);
		}
		if (segments_written == 0 && !dedup_consumed_all) {
			aik_json *r = ac_sme_store_digest(s->bridge, digest_md,
							  pname, sid, trigger);

			if (!r)
				goto oom;
			aik_json_free(sme_result);
			sme_result = r;
		}
		if (segments_written > 0) {
			const aik_json *ids = aik_json_get(seg_stats,
							   "memory_ids");
			const aik_json *errors = aik_json_get(seg_stats,
							      "errors");
			const aik_json *failed = aik_json_get(seg_stats,
							      "failed");
			aik_json *r = aik_json_new_obj();
			const char *first_id = NULL;
			int rbad = 0;

			if (ids && aik_json_typeof(ids) == AIK_JSON_ARR)
				for (size_t k = 0; k < aik_json_count(ids); k++) {
					const aik_json *id = aik_json_at(ids, k);

					if (id &&
					    aik_json_typeof(id) == AIK_JSON_STR &&
					    aik_json_strlen(id) > 0) {
						first_id = aik_json_str(id);
						break;
					}
				}
			rbad = !r ||
			       obj_put_bool(r, "stored", 1) != 0 ||
			       obj_put_str(r, "memory_id", first_id) != 0;
			if (!rbad) {
				if (failed && aik_json_int(failed) > 0 &&
				    errors &&
				    aik_json_typeof(errors) == AIK_JSON_ARR &&
				    aik_json_count(errors) > 0) {
					struct sbuf eb = { 0 };

					for (size_t k = 0;
					     k < aik_json_count(errors); k++) {
						const aik_json *e2 =
							aik_json_at(errors, k);

						if (k > 0)
							sb_puts(&eb, "；");
						if (e2 &&
						    aik_json_typeof(e2) == AIK_JSON_STR)
							sb_puts(&eb,
								aik_json_str(e2));
					}
					rbad = !eb.buf ||
					       obj_put_str(r, "error",
							   eb.buf) != 0;
					sb_free(&eb);
				} else {
					rbad = obj_put_str(r, "error", NULL) != 0;
				}
			}
			if (rbad) {
				aik_json_free(r);
				goto oom;
			}
			aik_json_free(sme_result);
			sme_result = r;
		}
		{
			int stored = aik_json_bool(aik_json_get(sme_result,
								"stored"));
			const char *mid = aik_json_str(aik_json_get(sme_result,
								    "memory_id"));

			if (!stored && !dedup_consumed_all) {
				/* SME 入库失败不影响本地快照（service.py 仅告警）*/
			} else if (mid) {
				ac_store_set_snapshot_memory_id(s->store, h,
								fpath, mid);
			}
		}
	}

	ac_store_clear_completed_plan_items(s->store, sid);
	ac_store_mark_condensed(s->store, sid, trigger);
	sme_stored = aik_json_bool(aik_json_get(sme_result, "stored"));
	data = aik_json_new_obj();
	if (!data ||
	    obj_put_str(data, "trigger", trigger) != 0 ||
	    obj_put_str(data, "file", fpath) != 0 ||
	    obj_put_str(data, "mode", mode) != 0 ||
	    obj_put_bool(data, "sme_stored", sme_stored) != 0 ||
	    obj_put_int(data, "segments_written", segments_written) != 0 ||
	    obj_put_int(data, "segments_reinforced",
			segments_reinforced) != 0 ||
	    ac_store_append_event(s->store, "commit", sid, cwd, data) != 0)
		goto oom;
	aik_json_free(data);
	data = NULL;

	o = aik_json_new_obj();
	bad = !o ||
	      obj_put_str(o, "snapshot_path", fpath) != 0 ||
	      obj_put_str(o, "mode", mode) != 0;
	if (!bad) {
		bad = obj_put_json(o, "sme", sme_result) != 0;
		sme_result = NULL;	/* 成败均不再持有 */
	}
	if (!bad) {
		bad = obj_put_json(o, "sme_segments", seg_stats) != 0;
		seg_stats = NULL;
	}
	if (!bad)
		bad = obj_put_int(o, "segments_written", segments_written) != 0;
	if (!bad)
		bad = obj_put_int(o, "segments_reinforced",
				  segments_reinforced) != 0;
	if (!bad)
		bad = obj_put_str(o, "next_instruction",
				  COMMIT_NEXT_INSTRUCTION) != 0;
	if (bad) {
		aik_json_free(o);
		goto oom;
	}
	aik_json_free(entry);
	free(fpath);
	resp_json_dom(resp, 200, o);
	return;
oom:
	aik_json_free(errs);
	aik_json_free(entry);
	free(fpath);
	aik_json_free(sme_result);
	aik_json_free(seg_stats);
	aik_json_free(data);
	resp_detail(resp, 500, "Internal Server Error");
}

/* ------------------------------------------------------------------ */
/* 端点：GET /restore                                                  */
/* ------------------------------------------------------------------ */

static void h_restore(ac_http_server *s, ac_req *req, ac_resp *resp)
{
	char *cwd = query_get(req->query, "cwd");
	char *query = query_get(req->query, "query");
	char *top_n_raw = query_get(req->query, "top_n");
	int has_top = 0;
	long long top_n = 0;
	long long n;
	char pname_buf[512];
	const char *pname;
	const char *q;
	aik_json *snaps = NULL;
	aik_json *payload = NULL;
	aik_json *actions = NULL;
	aik_json *sme_results = NULL;
	aik_json *data = NULL;
	aik_json *o = NULL;

	if (!cwd) {
		aik_json *errs = aik_json_new_arr();

		if (!errs) {
			resp_detail(resp, 500, "Internal Server Error");
			goto out;
		}
		val_missing_query(errs, "cwd");
		resp_422(resp, errs);
		goto out;
	}
	if (top_n_raw) {
		char *end = NULL;

		errno = 0;
		top_n = strtoll(top_n_raw, &end, 10);
		if (errno != 0 || !end || *end != '\0') {
			aik_json *errs = aik_json_new_arr();

			if (!errs) {
				resp_detail(resp, 500, "Internal Server Error");
				goto out;
			}
			verr_push(errs, "int_parsing", loc2("query", "top_n"),
				  "Input should be a valid integer, unable to parse string as an integer",
				  NULL);
			resp_422(resp, errs);
			goto out;
		}
		has_top = 1;
	}
	if (ac_project_name(cwd, pname_buf, sizeof(pname_buf)) != 0 ||
	    pname_buf[0] == '\0')
		pname = cwd;
	else
		pname = pname_buf;
	n = (has_top && top_n > 0) ? top_n : s->cfg.restore_top_n;
	if (restore_payload(s, cwd, n, &snaps, &payload) != 0) {
		resp_detail(resp, 500, "Internal Server Error");
		goto out;
	}
	actions = restore_next_actions(payload);
	if (!actions) {
		resp_detail(resp, 500, "Internal Server Error");
		goto out;
	}
	q = (query && *query) ? query : pname;
	if (s->cfg.sme.enabled) {
		sme_results = ac_sme_search(s->bridge, q, n);
	} else {
		sme_results = aik_json_new_arr();
	}
	if (!sme_results) {
		resp_detail(resp, 500, "Internal Server Error");
		goto out;
	}
	data = aik_json_new_obj();
	if (!data ||
	    obj_put_str(data, "query", q) != 0 ||
	    obj_put_int(data, "snapshots",
			(long long)aik_json_count(snaps)) != 0 ||
	    ac_store_append_event(s->store, "restore", NULL, cwd, data) != 0) {
		resp_detail(resp, 500, "Internal Server Error");
		goto out;
	}
	aik_json_free(data);
	data = NULL;

	o = aik_json_new_obj();
	if (!o || obj_put_str(o, "project", pname) != 0) {
		aik_json_free(o);
		resp_detail(resp, 500, "Internal Server Error");
		goto out;
	}
	if (aik_json_obj_put(o, "snapshots", snaps) != 0) {
		aik_json_free(o);
		resp_detail(resp, 500, "Internal Server Error");
		goto out;
	}
	snaps = NULL;
	if (aik_json_obj_put(o, "restore", payload) != 0) {
		aik_json_free(o);
		resp_detail(resp, 500, "Internal Server Error");
		goto out;
	}
	payload = NULL;
	if (aik_json_obj_put(o, "next_actions", actions) != 0) {
		aik_json_free(o);
		resp_detail(resp, 500, "Internal Server Error");
		goto out;
	}
	actions = NULL;
	if (aik_json_obj_put(o, "sme_results", sme_results) != 0) {
		aik_json_free(o);
		resp_detail(resp, 500, "Internal Server Error");
		goto out;
	}
	sme_results = NULL;
	resp_json_dom(resp, 200, o);
out:
	free(cwd);
	free(query);
	free(top_n_raw);
	aik_json_free(snaps);
	aik_json_free(payload);
	aik_json_free(actions);
	aik_json_free(sme_results);
	aik_json_free(data);
}

/* ------------------------------------------------------------------ */
/* 端点：GET /status                                                   */
/* ------------------------------------------------------------------ */

static void h_status(ac_http_server *s, ac_req *req, ac_resp *resp)
{
	aik_json *sessions;
	aik_json *o;
	const ac_session **all;
	size_t n_all = 0;
	size_t i;
	int bad = 0;

	(void)req;
	sessions = aik_json_new_arr();
	if (!sessions) {
		resp_detail(resp, 500, "Internal Server Error");
		return;
	}
	all = ac_store_all_sessions(s->store, &n_all);
	for (i = 0; i < n_all && !bad; i++) {
		aik_json *sum = ac_session_summary(all[i]);

		if (!sum || aik_json_arr_push(sessions, sum) != 0) {
			aik_json_free(sum);
			bad = 1;
		}
	}
	free(all);
	o = aik_json_new_obj();
	if (!bad)
		bad = !o ||
		      obj_put_bool(o, "enabled", s->cfg.enabled) != 0 ||
		      obj_put_int(o, "judge_defer_turns",
				  s->cfg.judge_defer_turns) != 0 ||
		      obj_put_int(o, "judge_defer_max_turns",
				  s->cfg.judge_defer_max_turns) != 0;
	if (!bad)
		bad = aik_json_obj_put(o, "sessions", sessions) != 0;
	if (!bad) {
		sessions = NULL;
		bad = obj_put_json(o, "config", ac_config_to_dict(&s->cfg)) != 0;
	}
	if (!bad)
		bad = obj_put_json(o, "recent_events",
				   ac_store_recent_events(s->store, 20, 0)) != 0;
	aik_json_free(sessions);
	if (bad) {
		aik_json_free(o);
		resp_detail(resp, 500, "Internal Server Error");
		return;
	}
	resp_json_dom(resp, 200, o);
}

/* ------------------------------------------------------------------ */
/* 端点：GET /config、PUT /config                                      */
/* ------------------------------------------------------------------ */

static void h_config_get(ac_http_server *s, ac_req *req, ac_resp *resp)
{
	(void)req;
	resp_json_dom(resp, 200, ac_config_to_dict(&s->cfg));
}

static void h_config_put(ac_http_server *s, ac_req *req, ac_resp *resp)
{
	aik_json *body = NULL;
	aik_json *errs;

	if (req_body_json(req, resp, &body) != 0)
		return;
	if (!body) {
		/* body 缺失 422 形态未录制：missing loc ["body"] */
		errs = aik_json_new_arr();
		if (!errs) {
			resp_detail(resp, 500, "Internal Server Error");
			return;
		}
		verr_push(errs, "missing", loc1("body"), "Field required", NULL);
		resp_422(resp, errs);
		return;
	}
	if (aik_json_typeof(body) != AIK_JSON_OBJ) {
		errs = aik_json_new_arr();
		if (!errs) {
			resp_detail(resp, 500, "Internal Server Error");
			return;
		}
		val_dict_type(errs, body);
		resp_422(resp, errs);
		return;
	}
	errs = ac_validate_config_dict(body);
	if (!errs) {
		resp_detail(resp, 500, "Internal Server Error");
		return;
	}
	if (aik_json_count(errs) > 0) {
		resp_errors(resp, 400, errs);
		return;
	}
	aik_json_free(errs);
	{
		aik_json *cur = ac_config_to_dict(&s->cfg);
		aik_json *merged = ac_deep_merge(cur, body);

		aik_json_free(cur);
		if (!merged || ac_config_apply_dict(&s->cfg, merged) != 0) {
			aik_json_free(merged);
			resp_detail(resp, 500, "Internal Server Error");
			return;
		}
		aik_json_free(merged);
	}
	/* 保存失败仅告警（内存配置已生效）——service.py 同语义 */
	(void)ac_save_config(s->data_dir, &s->cfg);
	resp_json_dom(resp, 200, ac_config_to_dict(&s->cfg));
}

/* ------------------------------------------------------------------ */
/* 路由分派                                                            */
/* ------------------------------------------------------------------ */

typedef void (*ac_route_fn)(ac_http_server *, ac_req *, ac_resp *);

static void dispatch(ac_http_server *s, ac_req *req, ac_resp *resp)
{
	static const struct {
		const char *path;
		const char *method;
		ac_route_fn fn;
	} exact[] = {
		{ "/health", "GET", h_health },
		{ "/session/start", "POST", h_session_start },
		{ "/report", "POST", h_report },
		{ "/events/hook", "POST", h_events_hook },
		{ "/check", "GET", h_check },
		{ "/judge", "POST", h_judge },
		{ "/begin", "POST", h_begin },
		{ "/commit", "POST", h_commit },
		{ "/restore", "GET", h_restore },
		{ "/status", "GET", h_status },
		{ "/config", "GET", h_config_get },
		{ "/config", "PUT", h_config_put },
	};
	size_t i;
	int partial = 0;

	for (i = 0; i < sizeof(exact) / sizeof(exact[0]); i++) {
		if (strcmp(req->path, exact[i].path) != 0)
			continue;
		if (strcmp(req->method, exact[i].method) == 0) {
			exact[i].fn(s, req, resp);
			return;
		}
		partial = 1;
	}
	if (partial)
		resp_detail(resp, 405, "Method Not Allowed");
	else
		resp_detail(resp, 404, "Not Found");
}

/* ------------------------------------------------------------------ */
/* 请求解析（smehttp http.c 模式）                                     */
/* ------------------------------------------------------------------ */

static int read_head(int fd, char *buf, size_t cap, size_t *out_total,
		     size_t *out_head)
{
	size_t len = 0;
	size_t scanned = 0;

	for (;;) {
		size_t i;

		for (i = scanned; i + 4 <= len; i++) {
			if (buf[i] == '\r' && buf[i + 1] == '\n' &&
			    buf[i + 2] == '\r' && buf[i + 3] == '\n') {
				*out_total = len;
				*out_head = i + 4;
				return 1;
			}
		}
		scanned = len >= 3 ? len - 3 : 0;
		if (len >= cap)
			return -2;
		{
			ssize_t n = recv(fd, buf + len, cap - len, 0);

			if (n == 0)
				return 0;
			if (n < 0) {
				if (errno == EINTR)
					continue;
				return -1;
			}
			len += (size_t)n;
		}
	}
}

static int parse_size(const char *str, size_t *out)
{
	unsigned long long v = 0;
	const char *p = str;

	if (!p || !*p)
		return -1;
	for (; *p; p++) {
		if (*p < '0' || *p > '9')
			return -1;
		v = v * 10ULL + (unsigned long long)(*p - '0');
		if (v > (1ULL << 40))
			return -1;
	}
	*out = (size_t)v;
	return 0;
}

typedef struct {
	char *method;
	char *path;
	char *query;
	int has_content_length;
	size_t content_length;
	int chunked;
	int expect_continue;
	int http11;
	char *connection;
	int bad;
} parsed_head;

static char *trim_left(char *str)
{
	while (*str == ' ' || *str == '\t')
		str++;
	return str;
}

static void trim_right(char *str)
{
	size_t n = strlen(str);

	while (n > 0 && (str[n - 1] == ' ' || str[n - 1] == '\t'))
		str[--n] = '\0';
}

static int ci_contains(const char *hay, const char *needle)
{
	size_t nl;
	const char *p;

	if (!hay || !needle)
		return 0;
	nl = strlen(needle);
	if (nl == 0)
		return 1;
	for (p = hay; *p; p++) {
		size_t i;

		for (i = 0; i < nl; i++) {
			unsigned char a = (unsigned char)p[i];
			unsigned char b = (unsigned char)needle[i];

			if (a >= 'A' && a <= 'Z')
				a = (unsigned char)(a - 'A' + 'a');
			if (a != b)
				break;
		}
		if (i == nl)
			return 1;
		if (!p[1])
			break;
	}
	return 0;
}

static int parse_head(char *head, size_t head_len, parsed_head *h)
{
	char *p = head;
	char *end = head + head_len;
	char *line;

	memset(h, 0, sizeof(*h));
	{
		size_t i;

		for (i = 0; i < head_len; i++)
			if (head[i] == '\r' || head[i] == '\n')
				head[i] = '\0';
	}
	line = p;
	while (p < end && *p)
		p++;
	if (p >= end) {
		h->bad = 1;
		return -1;
	}
	{
		char *sp1 = strchr(line, ' ');
		char *sp2;
		char *target;
		char *ver;
		char *q;

		if (!sp1) {
			h->bad = 1;
			return -1;
		}
		*sp1 = '\0';
		h->method = line;
		target = sp1 + 1;
		sp2 = strchr(target, ' ');
		if (!sp2) {
			h->bad = 1;
			return -1;
		}
		*sp2 = '\0';
		ver = sp2 + 1;
		if (strncmp(ver, "HTTP/1.", 7) != 0) {
			h->bad = 1;
			return -1;
		}
		h->http11 = strcmp(ver, "HTTP/1.1") == 0;
		q = strchr(target, '?');
		if (q) {
			*q = '\0';
			h->query = q + 1;
		} else {
			h->query = target + strlen(target);
		}
		if (target[0] != '/') {
			h->bad = 1;
			return -1;
		}
		h->path = target;
	}
	p = line + strlen(line) + 1;
	for (; p < end; p++) {
		char *colon;
		char *key;
		char *val;

		if (*p == '\0')
			continue;
		line = p;
		while (p < end && *p)
			p++;
		colon = strchr(line, ':');
		if (!colon)
			continue;
		*colon = '\0';
		key = line;
		val = colon + 1;
		trim_right(key);
		val = trim_left(val);
		trim_right(val);
		if (strcasecmp(key, "content-length") == 0) {
			size_t cl;

			if (parse_size(val, &cl) != 0) {
				h->bad = 1;
				return -1;
			}
			h->has_content_length = 1;
			h->content_length = cl;
		} else if (strcasecmp(key, "transfer-encoding") == 0) {
			if (ci_contains(val, "chunked"))
				h->chunked = 1;
		} else if (strcasecmp(key, "expect") == 0) {
			if (ci_contains(val, "100-continue"))
				h->expect_continue = 1;
		} else if (strcasecmp(key, "connection") == 0) {
			if (!h->connection)
				h->connection = val;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* 单连接处理（keep-alive 循环 + 处理互斥）                            */
/* ------------------------------------------------------------------ */

static void write_response(int fd, const ac_resp *r, int keep_alive)
{
	char head[256];
	int n;

	n = snprintf(head, sizeof(head),
		     "HTTP/1.1 %d %s\r\n"
		     "Content-Type: application/json\r\n"
		     "Content-Length: %zu\r\n"
		     "Connection: %s\r\n"
		     "\r\n",
		     r->status, reason_phrase(r->status), r->body_len,
		     keep_alive ? "keep-alive" : "close");
	if (n > 0)
		write_all(fd, head, (size_t)n);
	if (r->body && r->body_len > 0)
		write_all(fd, r->body, r->body_len);
}

static int handle_one_request(ac_http_server *s, int fd)
{
	char *buf = NULL;
	size_t total = 0;
	size_t head_len = 0;
	parsed_head ph;
	ac_req req;
	ac_resp resp;
	int rc;
	int keep_alive;

	memset(&req, 0, sizeof(req));
	resp_init(&resp);
	memset(&ph, 0, sizeof(ph));

	buf = malloc((size_t)AC_HTTP_MAX_HEADER + 1);
	if (!buf)
		return -1;
	rc = read_head(fd, buf, (size_t)AC_HTTP_MAX_HEADER, &total, &head_len);
	if (rc == 0 || rc == -1) {
		free(buf);
		return 0;
	}
	if (rc == -2) {
		free(buf);
		resp_detail(&resp, 431, "Request Header Fields Too Large");
		write_response(fd, &resp, 0);
		resp_free(&resp);
		return -1;
	}
	if (parse_head(buf, head_len, &ph) != 0 || ph.bad) {
		free(buf);
		resp_detail(&resp, 400, "Bad Request");
		write_response(fd, &resp, 0);
		resp_free(&resp);
		return -1;
	}
	keep_alive = ph.http11
		? (!ph.connection || strcasecmp(ph.connection, "close") != 0)
		: (ph.connection &&
		   strcasecmp(ph.connection, "keep-alive") == 0);
	if (ph.chunked) {
		free(buf);
		resp_detail(&resp, 411, "Length Required");
		write_response(fd, &resp, 0);
		resp_free(&resp);
		return -1;
	}
	if (ph.has_content_length &&
	    ph.content_length > (size_t)AC_HTTP_MAX_BODY) {
		free(buf);
		resp_detail(&resp, 413, "Payload Too Large");
		write_response(fd, &resp, 0);
		resp_free(&resp);
		return -1;
	}
	req.body_len = ph.has_content_length ? ph.content_length : 0;
	if (ph.expect_continue && req.body_len > 0) {
		static const char cont[] = "HTTP/1.1 100 Continue\r\n\r\n";

		write_all(fd, cont, sizeof(cont) - 1);
	}
	req.body = malloc(req.body_len + 1);
	if (!req.body) {
		free(buf);
		resp_detail(&resp, 500, "Internal Server Error");
		write_response(fd, &resp, 0);
		resp_free(&resp);
		return -1;
	}
	{
		size_t have = total - head_len;

		if (have > req.body_len)
			have = req.body_len;
		if (have > 0)
			memcpy(req.body, buf + head_len, have);
		while (have < req.body_len) {
			ssize_t n = recv(fd, req.body + have,
					 req.body_len - have, 0);

			if (n == 0)
				break;
			if (n < 0) {
				if (errno == EINTR)
					continue;
				break;
			}
			have += (size_t)n;
		}
		req.body[have] = '\0';
		if (have < req.body_len) {
			free(req.body);
			free(buf);
			resp_detail(&resp, 400, "Bad Request");
			write_response(fd, &resp, 0);
			resp_free(&resp);
			return -1;
		}
		req.body_len = have;
	}
	req.method = ph.method;
	req.path = ph.path;
	req.query = ph.query;

	/* 状态/配置/存储非线程安全：处理整体持锁（等价单 worker ASGI）*/
	pthread_mutex_lock(&s->lock);
	dispatch(s, &req, &resp);
	if (resp.status == 0)
		resp_detail(&resp, 500, "Internal Server Error");
	pthread_mutex_unlock(&s->lock);

	write_response(fd, &resp, keep_alive);
	resp_free(&resp);
	aik_json_free(req.json);
	free(req.body);
	free(buf);
	return keep_alive ? 1 : -1;
}

static void handle_connection(ac_http_server *s, int fd)
{
	for (;;) {
		int rc = handle_one_request(s, fd);

		if (rc <= 0)
			return;
		set_socket_timeout(fd, AC_HTTP_KEEPALIVE_MS);
	}
}

struct conn_ctx {
	ac_http_server *s;
	int fd;
};

static void conn_done(ac_http_server *s)
{
	pthread_mutex_lock(&s->conn_lock);
	s->active_conns--;
	pthread_cond_broadcast(&s->conn_cond);
	pthread_mutex_unlock(&s->conn_lock);
}

static void *conn_main(void *arg)
{
	struct conn_ctx *c = arg;
	ac_http_server *s = c->s;
	int fd = c->fd;

	free(c);
	handle_connection(s, fd);
	close(fd);
	conn_done(s);
	return NULL;
}

/* ------------------------------------------------------------------ */
/* accept 循环（停机标志轮询，延迟上限 200ms）                         */
/* ------------------------------------------------------------------ */

int ac_http_server_serve(ac_http_server *s)
{
	if (!s || s->fd < 0)
		return -1;
	while (!g_acserv_stop) {
		struct pollfd pfd;
		int rc;
		int cfd;
		struct conn_ctx *ctx;
		pthread_t tid;

		pfd.fd = s->fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		rc = poll(&pfd, 1, 200);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (rc == 0)
			continue;
		cfd = accept(s->fd, NULL, NULL);
		if (cfd < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			return -1;
		}
		set_socket_timeout(cfd, AC_HTTP_DEFAULT_TIMEOUT_MS);
		ctx = malloc(sizeof(*ctx));
		if (!ctx) {
			close(cfd);
			continue;
		}
		ctx->s = s;
		ctx->fd = cfd;
		pthread_mutex_lock(&s->conn_lock);
		if (s->closing) {
			pthread_mutex_unlock(&s->conn_lock);
			free(ctx);
			close(cfd);
			continue;
		}
		s->active_conns++;
		pthread_mutex_unlock(&s->conn_lock);
		if (pthread_create(&tid, NULL, conn_main, ctx) == 0) {
			pthread_detach(tid);
			continue;
		}
		conn_main(ctx);
	}
	return 0;
}
