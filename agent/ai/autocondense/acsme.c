// SPDX-License-Identifier: GPL-2.0
/*
 * acsme.c - SME 记忆服务桥接（POSIX socket HTTP/1.1 薄客户端）
 *
 * T5c 逐语义复刻 ref-autocondense/sme_bridge.py（289 行）：
 *   - 每请求新建 TCP 连接（等价 with httpx.Client() 逐请求语义）；
 *   - 请求体逐字节 = httpx json= 形态（json.dumps(..., ensure_ascii=False,
 *     separators=(",", ":"))，经 aik_json_dump 产出）；
 *   - health 60s 缓存（计时从探测完成后起算）；
 *   - store_segments ≥2 段走 /memories/batch，非 2xx/异常回落逐条；
 *   - dedupe 查询截 160 码点；命中（score≥阈值∧同项目∧同类型）→
 *     POST /memories/{id}/hit；软预算超时剩余段直接入库；
 *   - 任何网络异常不外抛，按各方法的降级语义返回。
 */
#define _DEFAULT_SOURCE 1

#include "autocondense/acsme.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define AC_SME_HTTP_VERSION "HTTP/1.1"
#define AC_SME_UA "python-httpx/0.28.1"
#define AC_SME_BODY_CAP (16u * 1024u * 1024u)
#define AC_SME_HEADER_CAP (64u * 1024u)

struct ac_sme_bridge {
	char *base_url;		/* 尾部 '/' 全部剥掉 */
	char *host;
	char *port;		/* 十进制字符串 */
	double timeout_s;
	char **tags;
	size_t n_tags;
	double importance;
	int imp_is_int;
	long long imp_int;
	double health_cache_s;
	int health_has;
	int health_value;
	double health_at;
	pthread_mutex_t lock;
};

/* ------------------------------------------------------------------ */
/* 基础工具                                                            */
/* ------------------------------------------------------------------ */

static char *xstrdup_(const char *s)
{
	size_t n = s ? strlen(s) + 1 : 1;
	char *p = malloc(n);

	if (p) {
		if (s)
			memcpy(p, s, n);
		else
			p[0] = '\0';
	}
	return p;
}

static char *xstrndup_(const char *s, size_t n)
{
	char *p = malloc(n + 1);

	if (p) {
		if (s && n)
			memcpy(p, s, n);
		p[n] = '\0';
	}
	return p;
}

static aik_json *jdeep_copy(const aik_json *v)
{
	aik_json_type t = aik_json_typeof(v);

	switch (t) {
	case AIK_JSON_NULL:
		return aik_json_new_null();
	case AIK_JSON_BOOL:
		return aik_json_new_bool(aik_json_bool(v));
	case AIK_JSON_INT:
		return aik_json_new_int(aik_json_int(v));
	case AIK_JSON_NUM:
		return aik_json_new_num(aik_json_num(v));
	case AIK_JSON_STR: {
		const char *s = aik_json_str(v);

		return aik_json_new_str(s ? s : "");
	}
	case AIK_JSON_ARR: {
		aik_json *arr = aik_json_new_arr();
		size_t n = aik_json_count(v);

		for (size_t i = 0; arr && i < n; i++)
			aik_json_arr_push(arr, jdeep_copy(aik_json_at(v, i)));
		return arr;
	}
	case AIK_JSON_OBJ: {
		aik_json *obj = aik_json_new_obj();
		size_t n = aik_json_count(v);

		for (size_t i = 0; obj && i < n; i++)
			aik_json_obj_put(obj, aik_json_key_at(v, i),
					 jdeep_copy(aik_json_val_at(v, i)));
		return obj;
	}
	default:
		return aik_json_new_null();
	}
}

static double mono_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Python text[:160]：按码点截断（含多字节序列内部完整性）*/
static char *u8_prefix(const char *s, size_t n_cp)
{
	size_t len = strlen(s), i = 0, n = 0;

	if (n_cp == 0)
		return xstrdup_("");
	while (i < len && n < n_cp) {
		unsigned char c = (unsigned char)s[i];
		size_t adv;

		if (c < 0x80) {
			adv = 1;
		} else if ((c & 0xE0) == 0xC0) {
			adv = 2;
		} else if ((c & 0xF0) == 0xE0) {
			adv = 3;
		} else if ((c & 0xF8) == 0xF0) {
			adv = 4;
		} else {
			adv = 1;
		}
		if (i + adv > len)
			adv = 1;
		i += adv;
		n++;
	}
	{
		char *out = malloc(i + 1);

		if (!out)
			return xstrdup_("");
		memcpy(out, s, i);
		out[i] = '\0';
		return out;
	}
}

/* ------------------------------------------------------------------ */
/* HTTP/1.1 客户端（每请求新建连接）                                   */
/* ------------------------------------------------------------------ */

struct sme_resp {
	int ok;			/* 传输成功（有完整 HTTP 响应）*/
	int status;
	char *body;		/* NUL 结尾（malloc）*/
	char *err;		/* 传输错误串（malloc；ok=0 时有效）*/
};

static void sme_resp_free(struct sme_resp *r)
{
	free(r->body);
	free(r->err);
	memset(r, 0, sizeof(*r));
}

static void sme_set_err(struct sme_resp *r, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void sme_set_err(struct sme_resp *r, const char *fmt, ...)
{
	va_list ap;
	char buf[512];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	free(r->err);
	r->err = xstrdup_(buf);
}

/* 剥 base_url 尾部 '/' 后拆 scheme://host:port */
static int parse_base_url(const char *base_url, char **host_out, char **port_out)
{
	const char *s = base_url ? base_url : "";
	size_t n = strlen(s);
	const char *scheme_end;

	while (n > 0 && s[n - 1] == '/')
		n--;
	if (strncmp(s, "http://", 7) == 0)
		scheme_end = s + 7;
	else
		return -1;	/* https/裸 host 不支持（配置默认恒 http）*/
	{
		const char *hostp = scheme_end;
		const char *colon = NULL;

		for (const char *p = scheme_end; p < s + n; p++)
			if (*p == ':')
				colon = p;
		if (!colon) {
			/* 无端口：默认 80（httpx 默认 scheme 端口）*/
			if (hostp >= s + n)
				return -1;
			*host_out = xstrndup_(hostp, (size_t)(s + n - hostp));
			*port_out = xstrdup_("80");
		} else {
			if (colon == hostp || colon + 1 >= s + n)
				return -1;
			*host_out = xstrndup_(hostp, (size_t)(colon - hostp));
			*port_out = xstrndup_(colon + 1, (size_t)(s + n - colon - 1));
		}
		if (!*host_out || !*port_out || !**host_out || !**port_out) {
			free(*host_out);
			free(*port_out);
			*host_out = NULL;
			*port_out = NULL;
			return -1;
		}
		return 0;
	}
}

static int connect_one(const struct addrinfo *ai, double timeout_s)
{
	int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

	if (fd < 0)
		return -1;
	{
		int flags = fcntl(fd, F_GETFL, 0);

		if (flags >= 0)
			fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	}
	if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
		int fl = fcntl(fd, F_GETFL, 0);

		if (fl >= 0)
			fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
		return fd;
	}
	if (errno != EINPROGRESS) {
		close(fd);
		return -1;
	}
	{
		struct pollfd pfd = { fd, POLLOUT, 0 };
		int rc = poll(&pfd, 1, (int)(timeout_s * 1000.0));

		if (rc <= 0) {
			close(fd);
			errno = rc == 0 ? ETIMEDOUT : errno;
			return -2;	/* 超时 */
		}
		{
			int err = 0;
			socklen_t elen = sizeof(err);

			if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 && err == 0) {
				int fl = fcntl(fd, F_GETFL, 0);

				if (fl >= 0)
					fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
				return fd;
			}
			close(fd);
			return -1;
		}
	}
}

static int send_all(int fd, const char *buf, size_t len, double timeout_s)
{
	struct timeval tv;

	tv.tv_sec = (time_t)timeout_s;
	tv.tv_usec = (suseconds_t)((timeout_s - (double)tv.tv_sec) * 1e6);
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	size_t off = 0;

	while (off < len) {
		ssize_t w = send(fd, buf + off, len - off, MSG_NOSIGNAL);

		if (w > 0) {
			off += (size_t)w;
			continue;
		}
		if (w < 0 && errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

/* 读到 EOF 或满足 stop 条件；返回总读数，-1 错误（-2 超时）*/
static ssize_t recv_all(int fd, char **buf_out, size_t want, int to_eof,
			double timeout_s)
{
	struct timeval tv;

	tv.tv_sec = (time_t)timeout_s;
	tv.tv_usec = (suseconds_t)((timeout_s - (double)tv.tv_sec) * 1e6);
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	size_t cap = 4096, len = 0;
	char *buf = malloc(cap);

	if (!buf)
		return -1;
	for (;;) {
		if (!to_eof && len >= want)
			break;
		if (len == cap) {
			if (cap >= AC_SME_BODY_CAP + AC_SME_HEADER_CAP) {
				free(buf);
				return -1;
			}
			{
				char *g = realloc(buf, cap *= 2);

				if (!g) {
					free(buf);
					return -1;
				}
				buf = g;
			}
		}
		ssize_t r = recv(fd, buf + len, cap - len, 0);

		if (r > 0) {
			len += (size_t)r;
			continue;
		}
		if (r == 0)
			break;	/* EOF */
		if (errno == EINTR)
			continue;
		free(buf);
		return errno == EAGAIN || errno == EWOULDBLOCK ? -2 : -1;
	}
	buf[len] = '\0';
	{
		char *shrunk = realloc(buf, len + 1);

		*buf_out = shrunk ? shrunk : buf;
	}
	return (ssize_t)len;
}

static int parse_response(char *raw, size_t raw_len, struct sme_resp *out)
{
	/* 找 header/body 分界 */
	size_t hdr_end = 0;
	int found = 0;

	for (size_t i = 0; i + 3 < raw_len; i++)
		if (raw[i] == '\r' && raw[i + 1] == '\n' &&
		    raw[i + 2] == '\r' && raw[i + 3] == '\n') {
			hdr_end = i;
			found = 1;
			break;
		}
	if (!found)
		return -1;
	if (raw_len < 12 || strncmp(raw, "HTTP/", 5) != 0)
		return -1;
	{
		int status = 0;
		const char *sp = strchr(raw, ' ');

		if (!sp || sp > raw + hdr_end)
			return -1;
		status = atoi(sp + 1);
		if (status < 100 || status > 599)
			return -1;
		out->status = status;
		out->body = xstrdup_(raw + hdr_end + 4);
		return 0;
	}
}

static int sme_request(ac_sme_bridge *b, const char *method, const char *path,
		       const char *body, struct sme_resp *out)
{
	struct addrinfo hints, *res = NULL;
	int gai;

	memset(out, 0, sizeof(*out));
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	gai = getaddrinfo(b->host, b->port, &hints, &res);
	if (gai != 0 || !res) {
		sme_set_err(out, "ConnectError: failed to resolve host '%s'",
			    b->host);
		return -1;
	}
	int fd = -1;
	int timed_out = 0;

	for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
		int rc = connect_one(ai, b->timeout_s);

		if (rc >= 0) {
			fd = rc;
			break;
		}
		if (rc == -2)
			timed_out = 1;
	}
	freeaddrinfo(res);
	if (fd < 0) {
		if (timed_out)
			sme_set_err(out, "ConnectTimeout: timed out");
		else
			sme_set_err(out, "ConnectError: All connection attempts failed");
		return -1;
	}
	/* 请求行 + 头（逐字节对应 httpx 形态；体为紧凑 JSON）*/
	{
		char header[1024];
		int hn;

		if (body)
			hn = snprintf(header, sizeof(header),
				      "%s %s %s\r\n"
				      "Host: %s:%s\r\n"
				      "Accept: */*\r\n"
				      "Accept-Encoding: identity\r\n"
				      "Connection: close\r\n"
				      "User-Agent: %s\r\n"
				      "Content-Type: application/json\r\n"
				      "Content-Length: %zu\r\n"
				      "\r\n",
				      method, path, AC_SME_HTTP_VERSION,
				      b->host, b->port, AC_SME_UA, strlen(body));
		else
			hn = snprintf(header, sizeof(header),
				      "%s %s %s\r\n"
				      "Host: %s:%s\r\n"
				      "Accept: */*\r\n"
				      "Accept-Encoding: identity\r\n"
				      "Connection: close\r\n"
				      "User-Agent: %s\r\n"
				      "\r\n",
				      method, path, AC_SME_HTTP_VERSION,
				      b->host, b->port, AC_SME_UA);
		if (hn < 0 || (size_t)hn >= sizeof(header)) {
			close(fd);
			sme_set_err(out, "ProtocolError: request line too long");
			return -1;
		}
		if (send_all(fd, header, (size_t)hn, b->timeout_s) != 0 ||
		    (body && send_all(fd, body, strlen(body), b->timeout_s) != 0)) {
			close(fd);
			sme_set_err(out, "WriteError: %s", strerror(errno));
			return -1;
		}
	}
	{
		/* Connection: close：服务器发完即关，读到 EOF 为止 */
		char *raw = NULL;
		ssize_t rn = recv_all(fd, &raw, 0, 1, b->timeout_s);

		close(fd);
		if (rn < 0) {
			free(raw);
			if (rn == -2)
				sme_set_err(out, "ReadTimeout: timed out");
			else
				sme_set_err(out, "ReadError: %s", strerror(errno));
			return -1;
		}
		if (parse_response(raw, (size_t)rn, out) != 0) {
			free(raw);
			sme_set_err(out, "ProtocolError: malformed HTTP response");
			return -1;
		}
		free(raw);
	}
	out->ok = 1;
	return 0;
}

/* POST + json= 体（aik_json_dump = httpx json= 字节形态）*/
static char *dump_body(const aik_json *v)
{
	char *out = NULL;
	size_t n = 0;

	if (aik_json_dump(v, &out, &n) != 0)
		return NULL;
	return out;
}

/* ------------------------------------------------------------------ */
/* 桥生命周期                                                          */
/* ------------------------------------------------------------------ */

ac_sme_bridge *ac_sme_bridge_open(const char *base_url, double timeout_s,
				  const char *const *tags, size_t n_tags,
				  double importance, double health_cache_s)
{
	ac_sme_bridge *b = calloc(1, sizeof(*b));
	size_t n = base_url ? strlen(base_url) : 0;
	size_t trim = n;
	static const char *const default_tags[] = {
		"project", "todo", "session_digest"
	};

	if (!b)
		return NULL;
	while (trim > 0 && base_url[trim - 1] == '/')
		trim--;
	b->base_url = xstrndup_(base_url ? base_url : "", trim);
	if (!b->base_url) {
		free(b);
		return NULL;
	}
	if (parse_base_url(base_url, &b->host, &b->port) != 0) {
		free(b->base_url);
		free(b);
		return NULL;
	}
	b->timeout_s = timeout_s > 0 ? timeout_s : AC_SME_DEFAULT_TIMEOUT_S;
	if (!tags) {
		tags = default_tags;
		n_tags = 3;
	}
	b->tags = malloc((n_tags ? n_tags : 1) * sizeof(*b->tags));
	if (!b->tags) {
		free(b->base_url);
		free(b->host);
		free(b->port);
		free(b);
		return NULL;
	}
	for (size_t i = 0; i < n_tags; i++) {
		b->tags[b->n_tags] = xstrdup_(tags[i]);
		if (b->tags[b->n_tags])
			b->n_tags++;
	}
	b->importance = importance;
	b->health_cache_s = health_cache_s;
	if (pthread_mutex_init(&b->lock, NULL) != 0) {
		for (size_t i = 0; i < b->n_tags; i++)
			free(b->tags[i]);
		free(b->tags);
		free(b->base_url);
		free(b->host);
		free(b->port);
		free(b);
		return NULL;
	}
	return b;
}

void ac_sme_bridge_close(ac_sme_bridge *b)
{
	if (!b)
		return;
	pthread_mutex_destroy(&b->lock);
	for (size_t i = 0; i < b->n_tags; i++)
		free(b->tags[i]);
	free(b->tags);
	free(b->base_url);
	free(b->host);
	free(b->port);
	free(b);
}

/* 供 store_segments 设置整型 importance 形态（Python int → "1" 而非 "1.0"）*/
void ac_sme_bridge_set_importance_int(ac_sme_bridge *b, long long v)
{
	if (!b)
		return;
	b->imp_is_int = 1;
	b->imp_int = v;
	b->importance = (double)v;
}

static aik_json *bridge_importance_json(const ac_sme_bridge *b)
{
	if (b->imp_is_int)
		return aik_json_new_int(b->imp_int);
	return aik_json_new_num(b->importance);
}

static aik_json *bridge_tags_json(const ac_sme_bridge *b)
{
	aik_json *arr = aik_json_new_arr();

	for (size_t i = 0; arr && i < b->n_tags; i++)
		aik_json_arr_push(arr, aik_json_new_str(b->tags[i]));
	return arr;
}

/* ------------------------------------------------------------------ */
/* health                                                              */
/* ------------------------------------------------------------------ */

int ac_sme_health(ac_sme_bridge *b)
{
	double now = mono_now();
	int value = 0;

	if (!b)
		return 0;
	pthread_mutex_lock(&b->lock);
	if (b->health_has && now - b->health_at < b->health_cache_s) {
		value = b->health_value;
		pthread_mutex_unlock(&b->lock);
		return value;
	}
	pthread_mutex_unlock(&b->lock);
	{
		struct sme_resp r;

		if (sme_request(b, "GET", "/health", NULL, &r) == 0)
			value = (r.status == 200);
		sme_resp_free(&r);
	}
	/* 缓存计时从探测完成后起算（sme_bridge.py:59-64）*/
	pthread_mutex_lock(&b->lock);
	b->health_has = 1;
	b->health_value = value;
	b->health_at = mono_now();
	pthread_mutex_unlock(&b->lock);
	return value;
}

/* ------------------------------------------------------------------ */
/* store_digest                                                        */
/* ------------------------------------------------------------------ */

aik_json *ac_sme_store_digest(ac_sme_bridge *b, const char *digest_md,
			      const char *project, const char *session_id,
			      const char *trigger)
{
	aik_json *result = aik_json_new_obj();
	struct sme_resp r;
	aik_json *body = aik_json_new_obj();
	aik_json *meta = aik_json_new_obj();
	char *text = NULL;
	char *req = NULL;
	size_t tlen;

	if (!b || !result || !body || !meta)
		goto out;
	tlen = strlen("[会话快照||]\n") + strlen(digest_md ? digest_md : "") +
	       strlen(project ? project : "") + strlen(trigger ? trigger : "") + 1;
	text = malloc(tlen);
	if (!text)
		goto out;
	snprintf(text, tlen, "[会话快照|%s|%s]\n%s", project ? project : "",
		 trigger ? trigger : "", digest_md ? digest_md : "");
	aik_json_obj_put(body, "text", aik_json_new_str(text));
	aik_json_obj_put(body, "tags", bridge_tags_json(b));
	aik_json_obj_put(body, "importance", bridge_importance_json(b));
	aik_json_obj_put(body, "source", aik_json_new_str("session"));
	aik_json_obj_put(meta, "tool", aik_json_new_str("autocondense"));
	aik_json_obj_put(meta, "session_id",
			 aik_json_new_str(session_id ? session_id : ""));
	aik_json_obj_put(meta, "project", aik_json_new_str(project ? project : ""));
	aik_json_obj_put(meta, "trigger", aik_json_new_str(trigger ? trigger : ""));
	aik_json_obj_put(body, "metadata", meta);
	meta = NULL;
	req = dump_body(body);
	aik_json_free(body);
	body = NULL;
	if (!req)
		goto out;
	if (sme_request(b, "POST", "/memories", req, &r) != 0) {
		aik_json_obj_put(result, "stored", aik_json_new_bool(0));
		aik_json_obj_put(result, "memory_id", aik_json_new_null());
		aik_json_obj_put(result, "error",
				 r.err ? aik_json_new_str(r.err)
				       : aik_json_new_str("ConnectError: unknown"));
		sme_resp_free(&r);
		goto out;
	}
	if (r.status >= 200 && r.status < 300) {
		aik_json *memory_id = NULL;

		if (r.body) {
			char err[128];
			aik_json *data = aik_json_parse(r.body, strlen(r.body),
							err, sizeof(err));

			if (data) {
				const aik_json *id = aik_json_get(data, "id");

				if (aik_json_typeof(data) == AIK_JSON_OBJ && id)
					memory_id = jdeep_copy(id);
				aik_json_free(data);
			}
		}
		aik_json_obj_put(result, "stored", aik_json_new_bool(1));
		aik_json_obj_put(result, "memory_id",
				 memory_id ? memory_id : aik_json_new_null());
		aik_json_obj_put(result, "error", aik_json_new_null());
	} else {
		char buf[32];

		snprintf(buf, sizeof(buf), "HTTP %d", r.status);
		aik_json_obj_put(result, "stored", aik_json_new_bool(0));
		aik_json_obj_put(result, "memory_id", aik_json_new_null());
		aik_json_obj_put(result, "error", aik_json_new_str(buf));
	}
	sme_resp_free(&r);
out:
	free(text);
	free(req);
	aik_json_free(body);
	aik_json_free(meta);
	return result;
}

/* ------------------------------------------------------------------ */
/* store_segments                                                      */
/* ------------------------------------------------------------------ */

/* _segment_body：单段请求体（键序 text,tags,importance,source,metadata）*/
static aik_json *segment_body_json(size_t idx, const ac_segment *seg,
				   const aik_json *metadata)
{
	aik_json *o = aik_json_new_obj();
	aik_json *tags = aik_json_new_arr();
	aik_json *meta = aik_json_new_obj();

	if (!o || !tags || !meta) {
		aik_json_free(o);
		aik_json_free(tags);
		aik_json_free(meta);
		return NULL;
	}
	aik_json_obj_put(o, "text", aik_json_new_str(seg->text ? seg->text : ""));
	for (size_t i = 0; i < seg->n_tags; i++)
		aik_json_arr_push(tags, aik_json_new_str(seg->tags[i]));
	aik_json_obj_put(o, "tags", tags);
	aik_json_obj_put(o, "importance", aik_json_new_num(seg->importance));
	aik_json_obj_put(o, "source", aik_json_new_str("session"));
	aik_json_obj_put(meta, "tool", aik_json_new_str("autocondense"));
	aik_json_obj_put(meta, "segment_type",
			 aik_json_new_str(seg->type ? seg->type : "misc"));
	aik_json_obj_put(meta, "segment_index", aik_json_new_int((long long)idx));
	if (metadata && aik_json_typeof(metadata) == AIK_JSON_OBJ) {
		size_t n = aik_json_count(metadata);

		for (size_t i = 0; i < n; i++)
			aik_json_obj_put(meta, aik_json_key_at(metadata, i),
					 jdeep_copy(aik_json_val_at(metadata, i)));
	}
	aik_json_obj_put(o, "metadata", meta);
	return o;
}

static aik_json *store_one(ac_sme_bridge *b, size_t idx, const ac_segment *seg,
			   const aik_json *metadata)
{
	struct sme_resp r;
	aik_json *body = segment_body_json(idx, seg, metadata);
	aik_json *result = NULL;
	char *req;

	if (!body)
		return NULL;
	req = dump_body(body);
	aik_json_free(body);
	if (!req)
		return NULL;
	result = aik_json_new_obj();
	if (!result) {
		free(req);
		return NULL;
	}
	if (sme_request(b, "POST", "/memories", req, &r) != 0) {
		char buf[600];

		snprintf(buf, sizeof(buf), "段 %zu: %s", idx,
			 r.err ? r.err : "ConnectError: unknown");
		aik_json_obj_put(result, "stored", aik_json_new_int(0));
		{
			aik_json *ids = aik_json_new_arr();
			aik_json *errs = aik_json_new_arr();

			aik_json_arr_push(ids, aik_json_new_null());
			aik_json_arr_push(errs, aik_json_new_str(buf));
			aik_json_obj_put(result, "failed", aik_json_new_int(1));
			aik_json_obj_put(result, "memory_ids", ids);
			aik_json_obj_put(result, "errors", errs);
		}
		sme_resp_free(&r);
		free(req);
		return result;
	}
	free(req);
	if (r.status >= 200 && r.status < 300) {
		aik_json *memory_id = NULL;

		if (r.body) {
			char err[128];
			aik_json *data = aik_json_parse(r.body, strlen(r.body),
							err, sizeof(err));

			if (data) {
				const aik_json *id = aik_json_get(data, "id");

				if (aik_json_typeof(data) == AIK_JSON_OBJ && id)
					memory_id = jdeep_copy(id);
				aik_json_free(data);
			}
		}
		{
			aik_json *ids = aik_json_new_arr();
			aik_json *errs = aik_json_new_arr();

			aik_json_arr_push(ids,
					  memory_id ? memory_id : aik_json_new_null());
			aik_json_obj_put(result, "stored", aik_json_new_int(1));
			aik_json_obj_put(result, "failed", aik_json_new_int(0));
			aik_json_obj_put(result, "memory_ids", ids);
			aik_json_obj_put(result, "errors", errs);
		}
	} else {
		char buf[128];

		snprintf(buf, sizeof(buf), "段 %zu(%s): HTTP %d", idx,
			 seg->type ? seg->type : "misc", r.status);
		{
			aik_json *ids = aik_json_new_arr();
			aik_json *errs = aik_json_new_arr();

			aik_json_arr_push(ids, aik_json_new_null());
			aik_json_arr_push(errs, aik_json_new_str(buf));
			aik_json_obj_put(result, "stored", aik_json_new_int(0));
			aik_json_obj_put(result, "failed", aik_json_new_int(1));
			aik_json_obj_put(result, "memory_ids", ids);
			aik_json_obj_put(result, "errors", errs);
		}
	}
	sme_resp_free(&r);
	return result;
}

/* 返回 0 成功入库（batch 契约）；-1 任何异常/非 2xx/非 dict（回落逐条）*/
static int store_batch(ac_sme_bridge *b, const ac_segment *segs, size_t n,
		       const aik_json *metadata, aik_json **result_out)
{
	struct sme_resp r;
	aik_json *mem_arr = aik_json_new_arr();
	aik_json *body = aik_json_new_obj();
	aik_json *result = NULL;
	char *req;

	*result_out = NULL;
	if (!mem_arr || !body) {
		aik_json_free(mem_arr);
		aik_json_free(body);
		return -1;
	}
	for (size_t i = 0; i < n; i++) {
		aik_json *sb = segment_body_json(i, &segs[i], metadata);

		if (!sb || aik_json_arr_push(mem_arr, sb) != 0) {
			aik_json_free(sb);
			aik_json_free(mem_arr);
			aik_json_free(body);
			return -1;
		}
	}
	aik_json_obj_put(body, "memories", mem_arr);
	req = dump_body(body);
	aik_json_free(body);
	if (!req)
		return -1;
	if (sme_request(b, "POST", "/memories/batch", req, &r) != 0) {
		sme_resp_free(&r);
		free(req);
		return -1;
	}
	free(req);
	if (!(r.status >= 200 && r.status < 300)) {
		sme_resp_free(&r);
		return -1;
	}
	result = aik_json_new_obj();
	if (result) {
		/* r.json() 失败 → {}（dict）→ 计数全 0；仅非 dict 才回落（sme_bridge.py:134-140）*/
		aik_json *data = NULL;

		if (r.body) {
			char err[128];

			data = aik_json_parse(r.body, strlen(r.body), err, sizeof(err));
		}
		if (!data)
			data = aik_json_new_obj();
		if (aik_json_typeof(data) == AIK_JSON_OBJ) {
			aik_json *ids = aik_json_new_arr();
			aik_json *errs = aik_json_new_arr();
			long long added = 0, dropped = 0;
			const aik_json *v;

			v = aik_json_get(data, "added");
			if (aik_json_typeof(v) == AIK_JSON_INT)
				added = aik_json_int(v);
			v = aik_json_get(data, "dropped");
			if (aik_json_typeof(v) == AIK_JSON_INT)
				dropped = aik_json_int(v);
			if (dropped > 0) {
				char buf[96];

				snprintf(buf, sizeof(buf),
					 "SME 提取管线丢弃 %lld 条（重复/超限，不视为失败）",
					 dropped);
				aik_json_arr_push(errs, aik_json_new_str(buf));
			}
			aik_json_obj_put(result, "stored", aik_json_new_int(added));
			aik_json_obj_put(result, "failed", aik_json_new_int(0));
			aik_json_obj_put(result, "memory_ids", ids);
			aik_json_obj_put(result, "errors", errs);
			aik_json_free(data);
			sme_resp_free(&r);
			*result_out = result;
			return 0;
		}
		aik_json_free(data);
	}
	/* 响应非 dict → 回落逐条 */
	sme_resp_free(&r);
	aik_json_free(result);
	return -1;
}

aik_json *ac_sme_store_segments(ac_sme_bridge *b, const ac_segment *segs,
				size_t n_segs, const aik_json *metadata)
{
	if (!b)
		return NULL;
	if (n_segs >= 2) {
		aik_json *batch_result = NULL;

		if (store_batch(b, segs, n_segs, metadata, &batch_result) == 0)
			return batch_result;
	}
	/* 逐条路径 */
	{
		aik_json *result = aik_json_new_obj();
		aik_json *ids = aik_json_new_arr();
		aik_json *errs = aik_json_new_arr();
		long long ok = 0, failed = 0;

		if (!result) {
			aik_json_free(ids);
			aik_json_free(errs);
			return NULL;
		}

		for (size_t i = 0; i < n_segs; i++) {
			aik_json *one = store_one(b, i, &segs[i], metadata);

			if (one) {
				const aik_json *s = aik_json_get(one, "stored");
				const aik_json *ids1 = aik_json_get(one, "memory_ids");
				const aik_json *errs1 = aik_json_get(one, "errors");

				if (s && aik_json_typeof(s) == AIK_JSON_INT &&
				    aik_json_int(s) == 1)
					ok++;
				else
					failed++;
				if (ids1)
					aik_json_arr_push(ids, jdeep_copy(
						aik_json_at(ids1, 0)));
				if (errs1)
					for (size_t k = 0; k < aik_json_count(errs1); k++)
						aik_json_arr_push(errs, jdeep_copy(
							aik_json_at(errs1, k)));
				aik_json_free(one);
			}
		}
		aik_json_obj_put(result, "stored", aik_json_new_int(ok));
		aik_json_obj_put(result, "failed", aik_json_new_int(failed));
		aik_json_obj_put(result, "memory_ids", ids);
		aik_json_obj_put(result, "errors", errs);
		return result;
	}
}

/* ------------------------------------------------------------------ */
/* search / dedupe                                                     */
/* ------------------------------------------------------------------ */

/* POST /memories/search 原始结果（dict 条目原样深拷贝；异常/非 200 → 空表）*/
static aik_json *search_raw(ac_sme_bridge *b, const char *query, long long top_k)
{
	struct sme_resp r;
	aik_json *out = aik_json_new_arr();
	aik_json *body = aik_json_new_obj();

	if (!b || !out || !body) {
		aik_json_free(out);
		aik_json_free(body);
		return aik_json_new_arr();
	}
	aik_json_obj_put(body, "text", aik_json_new_str(query ? query : ""));
	aik_json_obj_put(body, "top_k", aik_json_new_int(top_k));
	{
		char *req = dump_body(body);

		aik_json_free(body);
		body = NULL;
		if (!req) {
			aik_json_free(out);
			return aik_json_new_arr();
		}
		if (sme_request(b, "POST", "/memories/search", req, &r) != 0) {
			sme_resp_free(&r);
			free(req);
			return out;
		}
		free(req);
	}
	if (r.status != 200) {
		sme_resp_free(&r);
		return out;
	}
	if (r.body) {
		char err[128];
		aik_json *data = aik_json_parse(r.body, strlen(r.body), err, sizeof(err));

		if (data && aik_json_typeof(data) == AIK_JSON_OBJ) {
			const aik_json *items = aik_json_get(data, "results");

			if (items && aik_json_typeof(items) == AIK_JSON_ARR) {
				size_t n = aik_json_count(items);

				for (size_t i = 0; i < n; i++) {
					const aik_json *it = aik_json_at(items, i);

					if (aik_json_typeof(it) == AIK_JSON_OBJ)
						aik_json_arr_push(out, jdeep_copy(it));
				}
			}
		}
		aik_json_free(data);
	}
	sme_resp_free(&r);
	return out;
}

aik_json *ac_sme_search(ac_sme_bridge *b, const char *query, long long top_k)
{
	aik_json *raw = search_raw(b, query, top_k);
	aik_json *out = aik_json_new_arr();
	size_t n = aik_json_count(raw);

	if (!out) {
		aik_json_free(raw);
		return aik_json_new_arr();
	}
	for (size_t i = 0; i < n; i++) {
		const aik_json *it = aik_json_at(raw, i);
		const aik_json *tags = aik_json_get(it, "tags");
		int keep = 0;

		if (tags && aik_json_typeof(tags) == AIK_JSON_ARR)
			for (size_t k = 0; k < aik_json_count(tags); k++) {
				const aik_json *t = aik_json_at(tags, k);

				if (aik_json_typeof(t) == AIK_JSON_STR &&
				    strcmp(aik_json_str(t) ? aik_json_str(t) : "",
					   "session_digest") == 0) {
					keep = 1;
					break;
				}
			}
		if (!keep)
			continue;
		{
			aik_json *o = aik_json_new_obj();

			aik_json_obj_put(o, "id", jdeep_copy(aik_json_get(it, "id")));
			aik_json_obj_put(o, "text", jdeep_copy(aik_json_get(it, "text")));
			aik_json_obj_put(o, "score", jdeep_copy(aik_json_get(it, "score")));
			aik_json_arr_push(out, o);
		}
	}
	aik_json_free(raw);
	return out;
}

/* hit id 的 URL 字符串形态（Python f"/memories/{id}/hit"）*/
static char *id_to_str(const aik_json *id)
{
	if (aik_json_typeof(id) == AIK_JSON_STR)
		return xstrdup_(aik_json_str(id) ? aik_json_str(id) : "");
	if (aik_json_typeof(id) == AIK_JSON_INT) {
		char buf[32];

		snprintf(buf, sizeof(buf), "%lld", aik_json_int(id));
		return xstrdup_(buf);
	}
	return NULL;	/* 其他形态按未命中处理（Python None 已在取值时排除）*/
}

int ac_sme_dedupe_segments(ac_sme_bridge *b, const ac_segment *segs,
			   size_t n_segs, const char *project, double threshold,
			   int has_budget_s, double budget_s,
			   ac_segment **new_segs, size_t *n_new,
			   char ***reinforced, size_t *n_rein)
{
	double deadline = mono_now() + (has_budget_s ? budget_s
						     : AC_SME_DEDUP_BUDGET_S);
	ac_segment *nout = malloc((n_segs ? n_segs : 1) * sizeof(*nout));
	char **rin = malloc((n_segs ? n_segs : 1) * sizeof(*rin));
	char *done = calloc(n_segs ? n_segs : 1, 1);
	size_t nn = 0, nr = 0;
	int rc = 0;

	*n_new = 0;
	*n_rein = 0;
	*new_segs = NULL;
	*reinforced = NULL;
	if (!b || !nout || !rin || !done) {
		free(nout);
		free(rin);
		free(done);
		return -1;
	}
	for (size_t i = 0; i < n_segs; i++) {
		if (mono_now() > deadline)
			break;	/* 软预算用尽：剩余段跳过查重 */
		{
			char *query = u8_prefix(segs[i].text ? segs[i].text : "", 160);
			aik_json *hits = search_raw(b, query, 3);
			size_t nh = aik_json_count(hits);
			char *matched = NULL;

			free(query);
			for (size_t h = 0; h < nh; h++) {
				const aik_json *hit = aik_json_at(hits, h);
				const aik_json *score = aik_json_get(hit, "score");
				const aik_json *meta = aik_json_get(hit, "metadata");
				const aik_json *id = aik_json_get(hit, "id");

				if (meta && aik_json_typeof(meta) != AIK_JSON_OBJ)
					meta = NULL;
				{
					const aik_json *mproj = meta ? aik_json_get(meta, "project") : NULL;
					const aik_json *mtype = meta ? aik_json_get(meta, "segment_type") : NULL;
					int score_ok = aik_json_typeof(score) == AIK_JSON_INT ||
						       aik_json_typeof(score) == AIK_JSON_NUM;
					int proj_ok = mproj && aik_json_typeof(mproj) == AIK_JSON_STR &&
						      strcmp(aik_json_str(mproj) ? aik_json_str(mproj) : "",
								     project ? project : "") == 0;
					int type_ok = mtype && aik_json_typeof(mtype) == AIK_JSON_STR &&
						      strcmp(aik_json_str(mtype) ? aik_json_str(mtype) : "",
								     segs[i].type ? segs[i].type : "") == 0;

					if (score_ok &&
					    aik_json_num(score) >= threshold &&
					    proj_ok && type_ok) {
						matched = id_to_str(id);
						if (matched)
							break;
					}
				}
			}
			aik_json_free(hits);
			if (!matched) {
				/* 未命中 → 新段（深拷贝）*/
				nout[nn].type = xstrdup_(segs[i].type);
				nout[nn].text = xstrdup_(segs[i].text);
				nout[nn].importance = segs[i].importance;
				nout[nn].tags = malloc((segs[i].n_tags ? segs[i].n_tags : 1) *
						       sizeof(char *));
				nout[nn].n_tags = 0;
				for (size_t k = 0; nout[nn].tags && k < segs[i].n_tags; k++)
					nout[nn].tags[nout[nn].n_tags++] =
						xstrdup_(segs[i].tags[k]);
				if (!nout[nn].type || !nout[nn].text || !nout[nn].tags) {
					free(matched);
					rc = -1;
					goto out;
				}
				nn++;
				done[i] = 1;
				continue;
			}
			{
				struct sme_resp r;
				char path[300];

				snprintf(path, sizeof(path), "/memories/%s/hit", matched);
				if (sme_request(b, "POST", path, NULL, &r) == 0 &&
				    r.status >= 200 && r.status < 300) {
					rin[nr++] = matched;
					done[i] = 1;
				} else {
					/* 强化失败按「无重复」处理：段照常入库 */
					free(matched);
					nout[nn].type = xstrdup_(segs[i].type);
					nout[nn].text = xstrdup_(segs[i].text);
					nout[nn].importance = segs[i].importance;
					nout[nn].tags = malloc((segs[i].n_tags ? segs[i].n_tags : 1) *
							       sizeof(char *));
					nout[nn].n_tags = 0;
					for (size_t k = 0; nout[nn].tags && k < segs[i].n_tags; k++)
						nout[nn].tags[nout[nn].n_tags++] =
							xstrdup_(segs[i].tags[k]);
					if (!nout[nn].type || !nout[nn].text || !nout[nn].tags) {
						rc = -1;
						goto out;
					}
					nn++;
					done[i] = 1;
				}
				sme_resp_free(&r);
			}
		}
	}
	/* 软预算用尽：剩余未查重段全部并入新段列表（原序）*/
	for (size_t i = 0; i < n_segs; i++) {
		if (done[i])
			continue;
		nout[nn].type = xstrdup_(segs[i].type);
		nout[nn].text = xstrdup_(segs[i].text);
		nout[nn].importance = segs[i].importance;
		nout[nn].tags = malloc((segs[i].n_tags ? segs[i].n_tags : 1) *
				       sizeof(char *));
		nout[nn].n_tags = 0;
		for (size_t k = 0; nout[nn].tags && k < segs[i].n_tags; k++)
			nout[nn].tags[nout[nn].n_tags++] = xstrdup_(segs[i].tags[k]);
		if (!nout[nn].type || !nout[nn].text || !nout[nn].tags) {
			rc = -1;
			goto out;
		}
		nn++;
	}
out:
	free(done);
	if (rc != 0) {
		ac_segments_free(nout, nn);
		for (size_t i = 0; i < nr; i++)
			free(rin[i]);
		free(rin);
		return -1;
	}
	*new_segs = nout;
	*n_new = nn;
	*reinforced = rin;
	*n_rein = nr;
	return 0;
}
