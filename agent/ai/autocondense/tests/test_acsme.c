// SPDX-License-Identifier: GPL-2.0
/*
 * test_acsme.c - T5c SME 桥差分测试（acsme.c）
 *
 * 内嵌最小 stub SME 服务器线程（127.0.0.1:0，脚本化响应与 T5a 录制器同规则：
 * DUPE→高分 decision 命中、FILTER→标签过滤样例、其余→空结果），按
 * smebridge.vectors.json 重放同序列桥调用，断言：
 *   ① 每组请求序列（方法/路径/体）与向量逐字节；
 *   ② 桥返回 JSON 与向量 results 逐字节；
 *   ③ health 第二次命中缓存（不再发请求）；
 *   ④ commit 全链（health→dedupe(search×N+hit)→batch 共 11 请求）与
 *     req_commit 逐字节；
 *   ⑤ 超时/拒连分支（127.0.0.1 闭端口 / 不可达地址）：health→false、
 *     store→error 串、search→[]；
 *   ⑥ 负向对照：篡改一个请求体字节必须被比较器检出。
 *
 * 运行：TZ=Asia/Shanghai ./tests/test_acsme
 */
#define _DEFAULT_SOURCE 1

#include "autocondense/acsme.h"

#include "ac_vec.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* ================================================================== */
/* 请求录制器                                                          */
/* ================================================================== */

struct rec_entry {
	char *method;
	char *path;
	char *body;		/* 无体为 "" */
};

static struct rec_entry g_rec[1024];
static size_t g_rec_n;
static pthread_mutex_t g_rec_lock = PTHREAD_MUTEX_INITIALIZER;

static void rec_clear(void)
{
	pthread_mutex_lock(&g_rec_lock);
	for (size_t i = 0; i < g_rec_n; i++) {
		free(g_rec[i].method);
		free(g_rec[i].path);
		free(g_rec[i].body);
	}
	g_rec_n = 0;
	pthread_mutex_unlock(&g_rec_lock);
}

static void rec_push(const char *method, const char *path, const char *body)
{
	pthread_mutex_lock(&g_rec_lock);
	if (g_rec_n < 1024) {
		g_rec[g_rec_n].method = strdup(method);
		g_rec[g_rec_n].path = strdup(path);
		g_rec[g_rec_n].body = strdup(body ? body : "");
		g_rec_n++;
	}
	pthread_mutex_unlock(&g_rec_lock);
}

/* 快照（仅读取；调用方须已与 stub 完成同步——桥读到完整响应即已录制）*/
static size_t rec_snapshot(struct rec_entry *out, size_t cap)
{
	size_t n;

	pthread_mutex_lock(&g_rec_lock);
	n = g_rec_n < cap ? g_rec_n : cap;
	for (size_t i = 0; i < n; i++)
		out[i] = g_rec[i];
	pthread_mutex_unlock(&g_rec_lock);
	return n;
}

static void rec_snapshot_free(struct rec_entry *e, size_t n)
{
	(void)e;
	(void)n;	/* 条目归录制器所有 */
}

/* ================================================================== */
/* stub SME 服务器（脚本与 record_ac_sme.py Stub 同规则）              */
/* ================================================================== */

static int g_listen_fd = -1;
static volatile int g_stub_stop = 0;
static pthread_t g_stub_thr;

static void stub_send(int fd, int status, const char *json)
{
	char head[256];
	int hn = snprintf(head, sizeof(head),
			  "HTTP/1.1 %d %s\r\n"
			  "Content-Type: application/json\r\n"
			  "Content-Length: %zu\r\n"
			  "Connection: close\r\n"
			  "\r\n",
			  status, status == 200 ? "OK" : "Not Found",
			  strlen(json));
	size_t total = (size_t)hn + strlen(json);
	char *buf = malloc(total + 1);

	if (!buf)
		return;
	memcpy(buf, head, (size_t)hn);
	memcpy(buf + hn, json, strlen(json));
	size_t off = 0;

	while (off < total) {
		ssize_t w = send(fd, buf + off, total - off, MSG_NOSIGNAL);

		if (w > 0) {
			off += (size_t)w;
			continue;
		}
		if (w < 0 && errno == EINTR)
			continue;
		break;
	}
	free(buf);
}

static aik_json *memory_body(const char *mid)
{
	aik_json *o = aik_json_new_obj();
	aik_json *meta = aik_json_new_obj();
	aik_json *tags = aik_json_new_arr();

	if (!o || !meta || !tags) {
		aik_json_free(o);
		aik_json_free(meta);
		aik_json_free(tags);
		return NULL;
	}
	aik_json_arr_push(tags, aik_json_new_str("session_digest"));
	aik_json_obj_put(o, "id", aik_json_new_str(mid));
	aik_json_obj_put(o, "text", aik_json_new_str("stub"));
	aik_json_obj_put(o, "metadata", meta);
	aik_json_obj_put(o, "created_at", aik_json_new_num(0.0));
	aik_json_obj_put(o, "last_hit", aik_json_new_num(0.0));
	aik_json_obj_put(o, "hit_count", aik_json_new_int(0));
	aik_json_obj_put(o, "weight", aik_json_new_num(1.0));
	aik_json_obj_put(o, "importance", aik_json_new_num(0.7));
	aik_json_obj_put(o, "freshness", aik_json_new_num(1.0));
	aik_json_obj_put(o, "decay_factor", aik_json_new_num(1.0));
	aik_json_obj_put(o, "region_id", aik_json_new_null());
	aik_json_obj_put(o, "neighbors", aik_json_new_arr());
	aik_json_obj_put(o, "tags", tags);
	aik_json_obj_put(o, "summary", aik_json_new_null());
	aik_json_obj_put(o, "version", aik_json_new_int(1));
	aik_json_obj_put(o, "parent_id", aik_json_new_null());
	aik_json_obj_put(o, "children", aik_json_new_arr());
	aik_json_obj_put(o, "archived", aik_json_new_bool(0));
	aik_json_obj_put(o, "source", aik_json_new_str("session"));
	return o;
}

static aik_json *search_hit_item(const char *id, const char *text, double score,
				 const char *tag0, const char *mproj,
				 const char *mtype)
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
	aik_json_arr_push(tags, aik_json_new_str(tag0));
	aik_json_obj_put(o, "id", aik_json_new_str(id));
	aik_json_obj_put(o, "text", aik_json_new_str(text));
	aik_json_obj_put(o, "score", aik_json_new_num(score));
	aik_json_obj_put(o, "tags", tags);
	if (mproj)
		aik_json_obj_put(meta, "project", aik_json_new_str(mproj));
	if (mtype)
		aik_json_obj_put(meta, "segment_type", aik_json_new_str(mtype));
	aik_json_obj_put(o, "metadata", meta);
	return o;
}

static void stub_dispatch(int fd, const char *method, const char *path,
			  const char *body)
{
	char *resp = NULL;
	size_t rn = 0;
	int status = 200;

	rec_push(method, path, body);
	if (strcmp(method, "GET") == 0) {
		if (strcmp(path, "/health") == 0) {
			aik_json *o = aik_json_new_obj();

			aik_json_obj_put(o, "status", aik_json_new_str("ok"));
			aik_json_obj_put(o, "memories", aik_json_new_int(3));
			aik_json_dump(o, &resp, &rn);
			aik_json_free(o);
		} else {
			status = 404;
			resp = strdup("{\"detail\": \"Not Found\"}");
		}
	} else if (strcmp(method, "POST") == 0) {
		if (strcmp(path, "/memories") == 0) {
			aik_json *o = memory_body("m_stub000000001");

			aik_json_dump(o, &resp, &rn);
			aik_json_free(o);
		} else if (strcmp(path, "/memories/batch") == 0) {
			char err[128];
			aik_json *data = aik_json_parse(body, strlen(body),
							err, sizeof(err));
			aik_json *o = aik_json_new_obj();
			size_t n = 0;

			if (data) {
				const aik_json *m = aik_json_get(data, "memories");

				if (m && aik_json_typeof(m) == AIK_JSON_ARR)
					n = aik_json_count(m);
			}
			aik_json_obj_put(o, "added", aik_json_new_int((long long)n));
			aik_json_obj_put(o, "dropped", aik_json_new_int(0));
			aik_json_obj_put(o, "total", aik_json_new_int((long long)n));
			aik_json_dump(o, &resp, &rn);
			aik_json_free(o);
			aik_json_free(data);
		} else if (strcmp(path, "/memories/search") == 0) {
			char err[128];
			aik_json *data = aik_json_parse(body, strlen(body),
							err, sizeof(err));
			const char *q = "";
			aik_json *o = aik_json_new_obj();
			aik_json *results = aik_json_new_arr();

			if (data) {
				const aik_json *t = aik_json_get(data, "text");

				if (t && aik_json_typeof(t) == AIK_JSON_STR)
					q = aik_json_str(t);
			}
			if (strstr(q ? q : "", "DUPE")) {
				aik_json *hit = search_hit_item(
					"m_dupe00000001", "旧段", 0.97,
					"session_digest", "ac-sme-proj", "decision");

				aik_json_arr_push(results, hit);
				aik_json_obj_put(o, "count", aik_json_new_int(1));
			} else if (strstr(q ? q : "", "FILTER")) {
				aik_json_arr_push(results, search_hit_item(
					"m_keep00000001", "保留", 0.9,
					"session_digest", NULL, NULL));
				aik_json_arr_push(results, search_hit_item(
					"m_drop00000001", "过滤", 0.8,
					"other", NULL, NULL));
				aik_json_obj_put(o, "count", aik_json_new_int(2));
			} else {
				aik_json_obj_put(o, "count", aik_json_new_int(0));
			}
			aik_json_obj_put(o, "query", aik_json_new_str(q ? q : ""));
			aik_json_obj_put(o, "results", results);
			/* 键序对齐录制器：query,count,results */
			aik_json_dump(o, &resp, &rn);
			aik_json_free(o);
			aik_json_free(data);
		} else {
			size_t plen = strlen(path);

			if (plen > 4 && strcmp(path + plen - 4, "/hit") == 0) {
				/* /memories/{id}/hit → {"memory_id": id, ...} */
				char idbuf[128];
				const char *s = path + strlen("/memories/");
				const char *e = strstr(s, "/hit");

				snprintf(idbuf, sizeof(idbuf), "%.*s",
					 e ? (int)(e - s) : 0, s);
				{
					aik_json *o = aik_json_new_obj();

					aik_json_obj_put(o, "memory_id",
							 aik_json_new_str(idbuf));
					aik_json_obj_put(o, "retention",
							 aik_json_new_num(0.9));
					aik_json_obj_put(o, "weight_delta",
							 aik_json_new_num(0.01));
					aik_json_obj_put(o, "importance_delta",
							 aik_json_new_num(0.0));
					aik_json_obj_put(o, "hit_count",
							 aik_json_new_int(1));
					aik_json_dump(o, &resp, &rn);
					aik_json_free(o);
				}
			} else {
				status = 404;
				resp = strdup("{\"detail\": \"Not Found\"}");
			}
		}
	} else {
		status = 404;
		resp = strdup("{\"detail\": \"Not Found\"}");
	}
	if (resp)
		stub_send(fd, status, resp);
	free(resp);
}

/* 读一个请求（Connection: close：每连接一个请求）*/
static void stub_handle(int fd)
{
	char buf[8192];
	size_t len = 0, hdr_end = 0;
	int found = 0;
	char method[16] = "", path[512] = "";
	size_t content_len = 0;
	struct timeval tv = { 5, 0 };

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	while (len < sizeof(buf) - 1) {
		for (size_t i = 0; !found && i + 3 < len; i++)
			if (buf[i] == '\r' && buf[i + 1] == '\n' &&
			    buf[i + 2] == '\r' && buf[i + 3] == '\n') {
				hdr_end = i;
				found = 1;
				break;
			}
		if (found)
			break;
		ssize_t r = recv(fd, buf + len, sizeof(buf) - 1 - len, 0);

		if (r <= 0) {
			if (r < 0 && errno == EINTR)
				continue;
			close(fd);
			return;
		}
		len += (size_t)r;
	}
	buf[len] = '\0';
	if (!found) {
		close(fd);
		return;
	}
	{
		/* 请求行 */
		ssize_t sp1 = -1, sp2 = -1;

		for (size_t i = 0; i < hdr_end; i++) {
			if (buf[i] == ' ') {
				if (sp1 < 0)
					sp1 = (ssize_t)i;
				else {
					sp2 = (ssize_t)i;
					break;
				}
			}
		}
		if (sp1 <= 0 || sp2 <= sp1) {
			close(fd);
			return;
		}
		snprintf(method, sizeof(method), "%.*s", (int)sp1, buf);
		snprintf(path, sizeof(path), "%.*s", (int)(sp2 - sp1 - 1),
			 buf + sp1 + 1);
		/* Content-Length（大小写不敏感）*/
		for (char *ln = buf; ln < buf + hdr_end; ) {
			char *eol = strstr(ln, "\r\n");

			if (!eol || eol > buf + hdr_end)
				break;
			if (strncasecmp(ln, "Content-Length:", 15) == 0)
				content_len = (size_t)strtoul(ln + 15, NULL, 10);
			ln = eol + 2;
		}
	}
	/* 读满 body */
	size_t have = len - hdr_end - 4;

	while (have < content_len) {
		ssize_t r = recv(fd, buf + len, sizeof(buf) - 1 - len, 0);

		if (r <= 0) {
			if (r < 0 && errno == EINTR)
				continue;
			break;
		}
		len += (size_t)r;
		have = len - hdr_end - 4;
	}
	buf[len] = '\0';
	if (have > content_len)
		have = content_len;
	{
		char *body = malloc(have + 1);

		memcpy(body, buf + hdr_end + 4, have);
		body[have] = '\0';
		stub_dispatch(fd, method, path, body);
		free(body);
	}
	close(fd);
}

static void *stub_thread(void *arg)
{
	(void)arg;
	while (!g_stub_stop) {
		int fd = accept(g_listen_fd, NULL, NULL);

		if (fd < 0) {
			if (g_stub_stop)
				break;
			continue;
		}
		stub_handle(fd);
	}
	return NULL;
}

static int stub_start(int *port_out)
{
	struct sockaddr_in addr;
	socklen_t alen = sizeof(addr);
	int one = 1;

	g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (g_listen_fd < 0)
		return -1;
	setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
	    listen(g_listen_fd, 16) != 0 ||
	    getsockname(g_listen_fd, (struct sockaddr *)&addr, &alen) != 0) {
		close(g_listen_fd);
		g_listen_fd = -1;
		return -1;
	}
	*port_out = ntohs(addr.sin_port);
	g_stub_stop = 0;
	if (pthread_create(&g_stub_thr, NULL, stub_thread, NULL) != 0) {
		close(g_listen_fd);
		g_listen_fd = -1;
		return -1;
	}
	return 0;
}

static void stub_stop(void)
{
	g_stub_stop = 1;
	if (g_listen_fd >= 0) {
		shutdown(g_listen_fd, SHUT_RDWR);
		close(g_listen_fd);
		g_listen_fd = -1;
	}
	pthread_join(g_stub_thr, NULL);
}

/* ================================================================== */
/* 断言助手                                                            */
/* ================================================================== */

static void dump_eq(const aik_json *got, const aik_json *want, const char *name)
{
	char *g = got ? ac_dump(got) : NULL;
	char *w = want ? ac_dump(want) : NULL;

	g_ac_checks++;
	if (!g || !w || strcmp(g, w) != 0)
		ac_fail("%s\n  got:  %.500s\n  want: %.500s", name,
			g ? g : "(null)", w ? w : "(null)");
	free(g);
	free(w);
}

static const char *jstr2(const aik_json *v, const char *key)
{
	const aik_json *s = aik_json_get(v, key);

	return (s && aik_json_typeof(s) == AIK_JSON_STR) ? aik_json_str(s) : "";
}

/* 请求序列与向量逐字节比对 */
static void req_seq_eq(const aik_json *vec_arr, const char *name)
{
	struct rec_entry snap[128];
	size_t n = rec_snapshot(snap, 128);
	size_t want_n = aik_json_count(vec_arr);

	g_ac_checks++;
	if (n != want_n) {
		ac_fail("%s: %zu requests, want %zu", name, n, want_n);
		return;
	}
	for (size_t i = 0; i < n; i++) {
		const aik_json *e = aik_json_at(vec_arr, i);
		const char *vm = aik_json_str(aik_json_at(e, 0));
		const char *vp = aik_json_str(aik_json_at(e, 1));
		const char *vb = aik_json_str(aik_json_at(e, 2));

		if (!vm || !vp || !vb ||
		    strcmp(vm, snap[i].method) != 0 ||
		    strcmp(vp, snap[i].path) != 0 ||
		    strcmp(vb, snap[i].body) != 0) {
			g_ac_failed++;
			ac_fail("%s[%zu]:\n  got:  %s %s %.300s\n  want: %s %s %.300s",
				name, i, snap[i].method, snap[i].path,
				snap[i].body, vm ? vm : "?", vp ? vp : "?",
				vb ? vb : "?");
			return;
		}
	}
	rec_snapshot_free(snap, n);
}

/* segments_used → ac_segment 数组（深拷贝）*/
static ac_segment *segs_from_vector(const aik_json *arr, size_t *n_out)
{
	size_t cnt = aik_json_count(arr);
	ac_segment *out = malloc((cnt ? cnt : 1) * sizeof(*out));

	*n_out = 0;
	if (!out)
		return NULL;
	for (size_t i = 0; i < cnt; i++) {
		const aik_json *e = aik_json_at(arr, i);
		const aik_json *tags = aik_json_get(e, "tags");
		const aik_json *imp = aik_json_get(e, "importance");
		size_t nt = tags ? aik_json_count(tags) : 0;

		out[i].type = strdup(jstr2(e, "type"));
		out[i].text = strdup(jstr2(e, "text"));
		out[i].tags = malloc((nt ? nt : 1) * sizeof(char *));
		out[i].n_tags = 0;
		for (size_t k = 0; out[i].tags && k < nt; k++)
			out[i].tags[out[i].n_tags++] =
				strdup(aik_json_str(aik_json_at(tags, k)));
		out[i].importance = imp ? aik_json_num(imp) : 0.7;
		(*n_out)++;
	}
	return out;
}

static void segs_free_local(ac_segment *s, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		free(s[i].type);
		free(s[i].text);
		for (size_t k = 0; k < s[i].n_tags; k++)
			free(s[i].tags[k]);
		free(s[i].tags);
	}
	free(s);
}

int main(void)
{
	signal(SIGPIPE, SIG_IGN);
	(void)ac_mkdtemp;	/* ac_vec.h 静态助手在本用例未用到，标记引用 */
	aik_json *vec = ac_load_vector("ac/smebridge.vectors.json");

	if (!vec)
		return 2;
	const aik_json *results = aik_json_get(vec, "results");
	const aik_json *requests = aik_json_get(vec, "requests");

	int port = 0;

	if (stub_start(&port) != 0) {
		fprintf(stderr, "FATAL: stub server start failed\n");
		return 2;
	}
	char base[64];

	snprintf(base, sizeof(base), "http://127.0.0.1:%d", port);
	static const char *const tags[] = { "project", "todo", "session_digest" };
	ac_sme_bridge *b = ac_sme_bridge_open(base, 2.0, tags, 3, 0.7, 60.0);

	if (!b) {
		fprintf(stderr, "FATAL: bridge open failed\n");
		return 2;
	}
	size_t n_segs = 0;
	ac_segment *segs = segs_from_vector(
		aik_json_get(vec, "segments_used"), &n_segs);

	/* ---- 1) health ×2（第二次命中缓存，无请求）---- */
	{
		rec_clear();
		int h1 = ac_sme_health(b);
		int h2 = ac_sme_health(b);

		dump_eq(aik_json_new_bool(h1), aik_json_get(results, "health_1"),
			"health_1");
		dump_eq(aik_json_new_bool(h2), aik_json_get(results, "health_2"),
			"health_2");
		req_seq_eq(aik_json_get(requests, "req_health"), "req_health");
	}

	/* ---- 2) store_digest ---- */
	{
		rec_clear();
		aik_json *r = ac_sme_store_digest(b, "DIGEST-BODY", "p1", "s1",
						  "trg");

		dump_eq(r, aik_json_get(results, "store_digest"), "store_digest");
		req_seq_eq(aik_json_get(requests, "req_store_digest"),
			   "req_store_digest");
		aik_json_free(r);
	}

	/* ---- 3) store_segments：batch（8 段）与逐条（1 段）---- */
	{
		rec_clear();
		aik_json *meta = aik_json_new_obj();

		aik_json_obj_put(meta, "session_id", aik_json_new_str("s1"));
		aik_json_obj_put(meta, "project", aik_json_new_str("ac-sme-proj"));
		aik_json_obj_put(meta, "trigger", aik_json_new_str("judge"));
		{
			aik_json *r = ac_sme_store_segments(b, segs, n_segs, meta);

			dump_eq(r, aik_json_get(results, "store_segments_batch"),
				"store_segments_batch");
			req_seq_eq(aik_json_get(requests, "req_batch"), "req_batch");
			aik_json_free(r);
		}
		{
			rec_clear();
			aik_json *r = ac_sme_store_segments(b, segs, 1, meta);

			dump_eq(r, aik_json_get(results, "store_segments_single"),
				"store_segments_single");
			req_seq_eq(aik_json_get(requests, "req_single"), "req_single");
			aik_json_free(r);
		}
		aik_json_free(meta);
	}

	/* ---- 4) search：FILTER（只留 session_digest 标签）---- */
	{
		rec_clear();
		aik_json *r = ac_sme_search(b, "FILTER 查询", 3);

		dump_eq(r, aik_json_get(results, "search_filter"), "search_filter");
		req_seq_eq(aik_json_get(requests, "req_search"), "req_search");
		aik_json_free(r);
	}

	/* ---- 5) dedupe：DUPE（decision 命中→hit）+ FRESH（miss→新段）---- */
	{
		rec_clear();
		ac_segment *ns = NULL;
		size_t nn = 0;
		char **rin = NULL;
		size_t nr = 0;
		int rc = ac_sme_dedupe_segments(b, segs, n_segs, "ac-sme-proj",
						0.92, 0, 0, &ns, &nn, &rin, &nr);

		g_ac_checks++;
		if (rc != 0)
			ac_fail("dedupe rc=%d", rc);
		{
			aik_json *out = aik_json_new_obj();
			aik_json *types = aik_json_new_arr();
			aik_json *rein = aik_json_new_arr();

			for (size_t i = 0; i < nn; i++)
				aik_json_arr_push(types,
						  aik_json_new_str(ns[i].type));
			for (size_t i = 0; i < nr; i++)
				aik_json_arr_push(rein, aik_json_new_str(rin[i]));
			aik_json_obj_put(out, "new_types", types);
			aik_json_obj_put(out, "reinforced", rein);
			dump_eq(out, aik_json_get(results, "dedupe"), "dedupe");
			aik_json_free(out);
		}
		req_seq_eq(aik_json_get(requests, "req_dedupe"), "req_dedupe");
		/* 负向对照：篡改向量第一条请求体一个字节必须检出 */
		{
			const aik_json *e = aik_json_at(
				aik_json_get(requests, "req_dedupe"), 0);
			const char *vb = aik_json_str(aik_json_at(e, 2));
			struct rec_entry snap[128];
			size_t n = rec_snapshot(snap, 128);

			if (vb && n >= 1 && strlen(vb) > 10) {
				char *tampered = strdup(vb);

				tampered[10] = (char)(tampered[10] ^ 0x01);
				g_ac_checks++;
				if (strcmp(tampered, snap[0].body) == 0)
					ac_fail("negative control req_dedupe[0]: not detected");
				free(tampered);
			}
		}
		ac_segments_free(ns, nn);
		for (size_t i = 0; i < nr; i++)
			free(rin[i]);
		free(rin);
	}

	/* ---- 6) commit 全链（fresh 桥）：health→dedupe→batch 共 11 请求 ---- */
	{
		rec_clear();
		ac_sme_bridge *b2 = ac_sme_bridge_open(base, 2.0, tags, 3, 0.7,
						       60.0);
		int h = ac_sme_health(b2);

		g_ac_checks++;
		if (h != 1)
			ac_fail("commit chain: health=%d", h);
		{
			ac_segment *ns = NULL;
			size_t nn = 0;
			char **rin = NULL;
			size_t nr = 0;

			if (ac_sme_dedupe_segments(b2, segs, n_segs,
						   "ac-sme-proj", 0.92, 0, 0,
						   &ns, &nn, &rin, &nr) != 0)
				ac_fail("commit chain dedupe failed");
			g_ac_checks++;
			if (nn != 7 || nr != 1)
				ac_fail("commit chain: new=%zu reinforced=%zu (want 7/1)",
					nn, nr);
			{
				aik_json *meta = aik_json_new_obj();

				aik_json_obj_put(meta, "session_id",
						 aik_json_new_str("s-sme"));
				aik_json_obj_put(meta, "project",
						 aik_json_new_str("ac-sme-proj"));
				aik_json_obj_put(meta, "trigger",
						 aik_json_new_str("judge"));
				{
					aik_json *r = ac_sme_store_segments(b2, ns, nn,
									    meta);

					aik_json_free(r);
				}
				aik_json_free(meta);
			}
			req_seq_eq(aik_json_get(requests, "req_commit"), "req_commit");
			ac_segments_free(ns, nn);
			for (size_t i = 0; i < nr; i++)
				free(rin[i]);
			free(rin);
		}
		ac_sme_bridge_close(b2);
	}

	/* ---- 7) restore 的 search（fresh 桥）---- */
	{
		rec_clear();
		ac_sme_bridge *b3 = ac_sme_bridge_open(base, 2.0, tags, 3, 0.7,
						       60.0);
		aik_json *r = ac_sme_search(b3, "FILTER", 3);

		aik_json_free(r);
		req_seq_eq(aik_json_get(requests, "req_restore"), "req_restore");
		ac_sme_bridge_close(b3);
	}

	segs_free_local(segs, n_segs);
	ac_sme_bridge_close(b);
	stub_stop();

	/* ---- 8) 拒连/超时分支（stub 已关：端口闭）---- */
	{
		/* 找一个确定关闭的端口：绑定后立即关闭 */
		int tmp = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in addr;
		socklen_t alen = sizeof(addr);
		int closed_port = 0;

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port = 0;
		if (bind(tmp, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
		    getsockname(tmp, (struct sockaddr *)&addr, &alen) == 0)
			closed_port = ntohs(addr.sin_port);
		close(tmp);
		if (closed_port > 0) {
			char cb[64];
			ac_sme_bridge *bc;

			snprintf(cb, sizeof(cb), "http://127.0.0.1:%d", closed_port);
			bc = ac_sme_bridge_open(cb, 0.5, NULL, 0, 0.7, 60.0);
			g_ac_checks++;
			if (!bc)
				ac_fail("closed-port bridge open failed");
			else {
				int h = ac_sme_health(bc);

				g_ac_checks++;
				if (h != 0)
					ac_fail("closed port: health should be 0");
				{
					aik_json *r = ac_sme_store_digest(
						bc, "X", "p", "s", "t");

					g_ac_checks++;
					if (aik_json_bool(aik_json_get(r, "stored")))
						ac_fail("closed port: stored should be false");
					g_ac_checks++;
					if (!aik_json_get(r, "error") ||
					    aik_json_typeof(aik_json_get(r, "error")) !=
						AIK_JSON_STR)
						ac_fail("closed port: error should be a string");
					aik_json_free(r);
				}
				{
					aik_json *r = ac_sme_search(bc, "q", 3);

					g_ac_checks++;
					if (aik_json_count(r) != 0)
						ac_fail("closed port: search should be []");
					aik_json_free(r);
				}
				ac_sme_bridge_close(bc);
			}
		}
		/* 连接超时分支：不可达地址（0.3s 预算内返回）*/
		{
			ac_sme_bridge *bt = ac_sme_bridge_open(
				"http://10.255.255.1:81", 0.3, NULL, 0, 0.7, 60.0);

			g_ac_checks++;
			if (!bt)
				ac_fail("timeout bridge open failed");
			else {
				int h = ac_sme_health(bt);

				g_ac_checks++;
				if (h != 0)
					ac_fail("unroutable: health should be 0");
				ac_sme_bridge_close(bt);
			}
		}
	}

	ac_summary("test_acsme");
	return g_ac_failed ? 1 : 0;
}
