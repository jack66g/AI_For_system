/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_http.c - T4b SME HTTP 自测（T4B-DESIGN.md §5）
 *
 * 9 组用例（fork 子进程起 ./smehttp --port 0，父进程裸 socket 发请求）：
 *   1. GET  /health                        200 {"status":"ok","memories":0}
 *   2. POST /memories（有效）              200 含 id/embedding/metadata
 *   3. POST /memories（空白 text）         422 detail[0].type=="value_error"
 *   4. POST /memories（缺 text）           422 detail[0].type=="missing"
 *   5. GET  /memories/m_ffffffffffff       404 {"detail":"memory not found"}
 *   6. POST /memories/search               200 count>0，results[0] 25 键
 *   7. GET  /nope                          404 {"detail":"Not Found"}
 *   8. auth（api.auth_token="secret"）：/health 放行；/stats 无 token 401；
 *      正确 token 200；错误 token 401
 *   9. SUMMARY http checks=N mismatches=M（失配退出 1）
 *
 * T4d 追加（同一 plain 服务上串行执行，复用前面的记忆）：
 *  10. PATCH /memories/{id}：text 变化 → version+1、embedding 变化；
 *      不存在 → 404 detail=str(KeyError)（repr 带引号）；类型/空白 422；
 *      importance/summary 生效
 *  11. DELETE /memories/{id}：{"deleted":id}；再删 → 404 memory not found
 *  12. archive → restore 往返：archived 标志、region_id null → 新 id；
 *      重复 archive/restore → 404
 *  13. POST /regions/search：count/results 与 RegionHit 五键；缺 text 422
 *  14. POST /regions/evolve：{"events":[...]}（可空）
 *  15. GET /graph + POST /graph/link：cause 双向边（edge_count +2，
 *      反向 conversation/note=timeline）；端点缺失 404；缺 b 422
 *  16. 六个可选模块只读路由 + /metrics/report 404（键序与空态）
 *
 * 临时配置写进 mkdtemp：storage.path=<tmp>/engine-*.json.gz、autosave=false、
 * persistence.enabled=false、api.auth_token 按用例设置。服务器 SIGTERM 必须
 * 干净退出（0）。
 */
#define _POSIX_C_SOURCE 200809L

#include "smehttp/http.h"

#include "smeconfig/config_items.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static size_t checks;
static size_t mismatches;

static void check_true(int cond, const char *fmt, ...)
{
	checks++;
	if (cond)
		return;
	mismatches++;
	{
		va_list ap;

		printf("MISMATCH: ");
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
		printf("\n");
	}
}

static void check_str(const char *got, const char *exp, const char *what)
{
	checks++;
	if (got && exp && strcmp(got, exp) == 0)
		return;
	mismatches++;
	printf("MISMATCH %s: got '%s' expected '%s'\n", what,
	       got ? got : "(null)", exp ? exp : "(null)");
}

static void check_int(long long got, long long exp, const char *what)
{
	checks++;
	if (got == exp)
		return;
	mismatches++;
	printf("MISMATCH %s: got %lld expected %lld\n", what, got, exp);
}

/* ------------------------------------------------------------------ */
/* 服务器进程                                                         */
/* ------------------------------------------------------------------ */
typedef struct {
	pid_t pid;
	int port;
	char cfg_path[512];
	char db_path[512];
} test_server;

static const char *server_bin(void)
{
	const char *env = getenv("AIK_SMEHTTP_BIN");

	if (env && *env)
		return env;
	if (access("./smehttp", X_OK) == 0)
		return "./smehttp";
	return "../smehttp";
}

static int write_config(const char *path, const char *db, const char *token)
{
	FILE *f = fopen(path, "w");
	int rc;

	if (!f)
		return -1;
	rc = fprintf(
		f,
		"{\n"
		"  \"seed\": 42,\n"
		"  \"embedding\": {\"provider\": \"hashing\", "
		"\"model\": \"hashing-d64-w3\", \"dim\": 64, "
		"\"hash_factors\": 3, \"hash_window\": 3, \"hash_seed\": 42, "
		"\"normalize\": true, \"mrl_dim\": 0},\n"
		"  \"region\": {\"min_region_size\": 3, "
		"\"min_join_cosine\": 0.70, \"auto_evolve\": true, "
		"\"evolve_interval\": 40},\n"
		"  \"retrieval\": {\"top_k\": 10, \"top_regions\": 3, "
		"\"fusion\": \"minmax\", \"candidate_window\": 20, "
		"\"keyword_candidates\": 0, \"min_similarity\": -1.0, "
		"\"query_cache_size\": 128},\n"
		"  \"storage\": {\"path\": \"%s\", \"autosave\": false, "
		"\"autosave_interval\": 100, \"compress\": true, "
		"\"backend\": \"json\"},\n"
		"  \"persistence\": {\"enabled\": false},\n"
		"  \"maintenance\": {\"background\": false},\n"
		"  \"observability\": {\"enabled\": false},\n"
		"  \"api\": {\"host\": \"127.0.0.1\", \"port\": 0, "
		"\"auth_token\": \"%s\"}\n"
		"}\n",
		db, token);
	if (fclose(f) != 0)
		return -1;
	return rc < 0 ? -1 : 0;
}

static int start_server(test_server *ts, const char *tmpdir, const char *tag,
			const char *token)
{
	int fds[2];
	char line[256];
	size_t used = 0;
	int port = -1;
	pid_t pid;

	snprintf(ts->cfg_path, sizeof(ts->cfg_path), "%s/sme-%s.json", tmpdir,
		 tag);
	snprintf(ts->db_path, sizeof(ts->db_path), "%s/engine-%s.json.gz",
		 tmpdir, tag);
	if (write_config(ts->cfg_path, ts->db_path, token) != 0) {
		fprintf(stderr, "test_http: cannot write config\n");
		return -1;
	}
	if (pipe(fds) != 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		close(fds[0]);
		close(fds[1]);
		return -1;
	}
	if (pid == 0) {
		close(fds[0]);
		if (dup2(fds[1], STDOUT_FILENO) < 0)
			_exit(127);
		close(fds[1]);
		execl(server_bin(), "smehttp", "--config", ts->cfg_path,
		      "--host", "127.0.0.1", "--port", "0", (char *)NULL);
		_exit(127);
	}
	close(fds[1]);
	ts->pid = pid;
	ts->port = -1;
	for (;;) {
		ssize_t n;
		char *nl;

		if (used + 1 >= sizeof(line))
			break;
		n = read(fds[0], line + used, sizeof(line) - 1 - used);
		if (n <= 0)
			break;
		used += (size_t)n;
		line[used] = '\0';
		nl = strchr(line, '\n');
		if (!nl)
			continue;
		*nl = '\0';
		if (strncmp(line, "LISTENING ", 10) == 0)
			port = atoi(line + 10);
		break;
	}
	close(fds[0]);
	if (port <= 0) {
		(void)kill(pid, SIGKILL);
		(void)waitpid(pid, NULL, 0);
		return -1;
	}
	ts->port = port;
	return 0;
}

/* SIGTERM 后必须 exit 0 */
static int stop_server(test_server *ts)
{
	int status = 0;

	if (kill(ts->pid, SIGTERM) != 0)
		return -1;
	if (waitpid(ts->pid, &status, 0) != ts->pid)
		return -1;
	(void)unlink(ts->cfg_path);
	(void)unlink(ts->db_path);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;
	return -1;
}

/* ------------------------------------------------------------------ */
/* 裸 socket HTTP 客户端                                              */
/* ------------------------------------------------------------------ */
static int send_all(int fd, const char *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = send(fd, buf + off, len - off, 0);

		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

static int read_all(int fd, char **out, size_t *out_len)
{
	size_t cap = 4096;
	size_t len = 0;
	char *buf = malloc(cap + 1);

	if (!buf)
		return -1;
	for (;;) {
		ssize_t n;

		if (len == cap) {
			char *nb;

			cap *= 2;
			nb = realloc(buf, cap + 1);
			if (!nb) {
				free(buf);
				return -1;
			}
			buf = nb;
		}
		n = recv(fd, buf + len, cap - len, 0);
		if (n == 0)
			break;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			return -1;
		}
		len += (size_t)n;
	}
	buf[len] = '\0';
	*out = buf;
	*out_len = len;
	return 0;
}

/*
 * http_call - 发一个请求并读全响应
 *
 * auth 为 Authorization 头的完整值（NULL 不发）；成功 0，失败 -1。
 * *status_out 为 HTTP 状态码，*body_out 为 malloc 的响应体（NUL 结尾）。
 */
static int http_call(int port, const char *method, const char *path,
		     const char *body, const char *auth, int *status_out,
		     char **body_out)
{
	struct sockaddr_in sa;
	struct timeval tv;
	char req[4096];
	char authhdr[512];
	char *resp = NULL;
	size_t resp_len = 0;
	size_t body_len = body ? strlen(body) : 0;
	const char *hdr_end;
	int fd;
	int rl;

	*status_out = -1;
	*body_out = NULL;
	authhdr[0] = '\0';
	if (auth)
		snprintf(authhdr, sizeof(authhdr), "Authorization: %s\r\n",
			 auth);
	rl = snprintf(req, sizeof(req),
		      "%s %s HTTP/1.1\r\n"
		      "Host: 127.0.0.1\r\n"
		      "Connection: close\r\n"
		      "Content-Type: application/json\r\n"
		      "%s"
		      "Content-Length: %zu\r\n"
		      "\r\n"
		      "%s",
		      method, path, authhdr, body_len, body ? body : "");
	if (rl <= 0 || (size_t)rl >= sizeof(req)) {
		fprintf(stderr, "test_http: request too large\n");
		return -1;
	}
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((unsigned short)port);
	if (inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr) != 1 ||
	    connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		close(fd);
		return -1;
	}
	if (send_all(fd, req, (size_t)rl) != 0) {
		close(fd);
		return -1;
	}
	if (read_all(fd, &resp, &resp_len) != 0) {
		close(fd);
		return -1;
	}
	close(fd);
	if (resp_len < 12 || strncmp(resp, "HTTP/1.1 ", 9) != 0) {
		free(resp);
		return -1;
	}
	*status_out = atoi(resp + 9);
	hdr_end = strstr(resp, "\r\n\r\n");
	if (!hdr_end) {
		free(resp);
		*status_out = -1;
		return -1;
	}
	hdr_end += 4;
	{
		size_t blen = resp_len - (size_t)(hdr_end - resp);
		char *copy = malloc(blen + 1);

		if (!copy) {
			free(resp);
			return -1;
		}
		memcpy(copy, hdr_end, blen);
		copy[blen] = '\0';
		*body_out = copy;
	}
	free(resp);
	return 0;
}

/* 解析响应体；失败返回 NULL */
static aik_json *parse_json(const char *body)
{
	char err[256];

	if (!body)
		return NULL;
	return aik_json_parse(body, strlen(body), err, sizeof(err));
}

/* {"detail": ...} 的 detail 节点 */
static const aik_json *detail_of(const aik_json *root)
{
	return aik_json_get(root, "detail");
}

/* loc 是否为 [<a>, <b>]（b 为 NULL 时只校验单元素） */
static int loc_is(const aik_json *loc, const char *a, const char *b)
{
	const char *s0;
	const char *s1;

	if (aik_json_typeof(loc) != AIK_JSON_ARR)
		return 0;
	if (aik_json_count(loc) != (b ? 2u : 1u))
		return 0;
	s0 = aik_json_str(aik_json_at(loc, 0));
	if (!s0 || strcmp(s0, a) != 0)
		return 0;
	if (!b)
		return 1;
	s1 = aik_json_str(aik_json_at(loc, 1));
	return s1 && strcmp(s1, b) == 0;
}

/* ------------------------------------------------------------------ */
/* 用例                                                               */
/* ------------------------------------------------------------------ */
static void test_health(int port)
{
	int status = -1;
	char *body = NULL;
	aik_json *root;
	const aik_json *detail;

	check_true(http_call(port, "GET", "/health", NULL, NULL, &status,
			     &body) == 0,
		   "health: request failed");
	check_int(status, 200, "health status");
	root = parse_json(body);
	check_true(root != NULL, "health: body is not JSON");
	if (root) {
		check_str(aik_json_str(aik_json_get(root, "status")), "ok",
			  "health.status");
		detail = aik_json_get(root, "memories");
		check_true(aik_json_typeof(detail) == AIK_JSON_INT,
			   "health.memories is not int");
		check_int(aik_json_int(detail), 0, "health.memories");
	}
	aik_json_free(root);
	free(body);
}

static void test_add_valid(int port, const char *text)
{
	int status = -1;
	char *body = NULL;
	char req[2048];
	aik_json *root;
	const aik_json *id;
	const aik_json *emb;
	const aik_json *meta;
	const char *idstr;

	snprintf(req, sizeof(req),
		 "{\"text\":\"%s\",\"metadata\":{\"origin\":\"test\"},"
		 "\"tags\":[\"t4b\"],\"importance\":0.7}",
		 text);
	check_true(http_call(port, "POST", "/memories", req, NULL, &status,
			     &body) == 0,
		   "add: request failed");
	check_int(status, 200, "add status");
	root = parse_json(body);
	check_true(root != NULL, "add: body is not JSON");
	if (root) {
		id = aik_json_get(root, "id");
		idstr = aik_json_str(id);
		check_true(idstr && strncmp(idstr, "m_", 2) == 0 &&
				   strlen(idstr) == 14,
			   "add.id is not m_ + 12 hex (got '%s')",
			   idstr ? idstr : "(null)");
		emb = aik_json_get(root, "embedding");
		check_true(aik_json_typeof(emb) == AIK_JSON_ARR &&
				   aik_json_count(emb) == 64,
			   "add.embedding is not a 64-dim array");
		meta = aik_json_get(root, "metadata");
		check_true(aik_json_typeof(meta) == AIK_JSON_OBJ,
			   "add.metadata is not an object");
		check_str(aik_json_str(aik_json_get(meta, "origin")), "test",
			  "add.metadata.origin");
		check_str(aik_json_str(aik_json_get(root, "text")), text,
			  "add.text");
	}
	aik_json_free(root);
	free(body);
}

static void test_blank_text(int port)
{
	int status = -1;
	char *body = NULL;
	aik_json *root;
	const aik_json *detail;
	const aik_json *first;

	check_true(http_call(port, "POST", "/memories", "{\"text\":\"   \"}",
			     NULL, &status, &body) == 0,
		   "blank: request failed");
	check_int(status, 422, "blank status");
	root = parse_json(body);
	check_true(root != NULL, "blank: body is not JSON");
	if (root) {
		detail = detail_of(root);
		check_true(aik_json_typeof(detail) == AIK_JSON_ARR &&
				   aik_json_count(detail) == 1,
			   "blank: detail is not a 1-element array");
		first = aik_json_at(detail, 0);
		check_str(aik_json_str(aik_json_get(first, "type")),
			  "value_error", "blank.type");
		check_str(aik_json_str(aik_json_get(first, "msg")),
			  "Value error, text must not be blank", "blank.msg");
		check_str(aik_json_str(aik_json_get(first, "input")), "   ",
			  "blank.input");
		{
			const aik_json *loc = aik_json_get(first, "loc");

			check_true(loc_is(loc, "body", "text"),
				   "blank.loc is not [\"body\",\"text\"]");
		}
		check_true(aik_json_typeof(aik_json_get(first, "ctx")) ==
				   AIK_JSON_OBJ,
			   "blank.ctx is not an object");
	}
	aik_json_free(root);
	free(body);
}

static void test_missing_text(int port)
{
	int status = -1;
	char *body = NULL;
	aik_json *root;
	const aik_json *detail;
	const aik_json *first;

	check_true(http_call(port, "POST", "/memories",
			     "{\"metadata\":{\"x\":1}}", NULL, &status,
			     &body) == 0,
		   "missing: request failed");
	check_int(status, 422, "missing status");
	root = parse_json(body);
	check_true(root != NULL, "missing: body is not JSON");
	if (root) {
		detail = detail_of(root);
		check_true(aik_json_typeof(detail) == AIK_JSON_ARR &&
				   aik_json_count(detail) == 1,
			   "missing: detail is not a 1-element array");
		first = aik_json_at(detail, 0);
		check_str(aik_json_str(aik_json_get(first, "type")), "missing",
			  "missing.type");
		check_str(aik_json_str(aik_json_get(first, "msg")),
			  "Field required", "missing.msg");
		{
			const aik_json *input = aik_json_get(first, "input");

			check_true(aik_json_typeof(input) == AIK_JSON_OBJ &&
					   aik_json_count(input) == 1 &&
					   aik_json_typeof(aik_json_get(
						   input, "metadata")) ==
						   AIK_JSON_OBJ,
				   "missing.input is not the request body");
		}
	}
	aik_json_free(root);
	free(body);
}

static void test_get_missing(int port)
{
	int status = -1;
	char *body = NULL;
	aik_json *root;

	check_true(http_call(port, "GET", "/memories/m_ffffffffffff", NULL,
			     NULL, &status, &body) == 0,
		   "get: request failed");
	check_int(status, 404, "get status");
	root = parse_json(body);
	check_true(root != NULL, "get: body is not JSON");
	if (root)
		check_str(aik_json_str(detail_of(root)), "memory not found",
			  "get.detail");
	aik_json_free(root);
	free(body);
}

static void test_search(int port, const char *text)
{
	int status = -1;
	char *body = NULL;
	char req[2048];
	aik_json *root;
	const aik_json *count;
	const aik_json *results;
	const aik_json *first;

	snprintf(req, sizeof(req), "{\"text\":\"%s\",\"top_k\":3}", text);
	check_true(http_call(port, "POST", "/memories/search", req, NULL,
			     &status, &body) == 0,
		   "search: request failed");
	check_int(status, 200, "search status");
	root = parse_json(body);
	check_true(root != NULL, "search: body is not JSON");
	if (root) {
		check_str(aik_json_str(aik_json_get(root, "query")), text,
			  "search.query");
		count = aik_json_get(root, "count");
		check_true(aik_json_typeof(count) == AIK_JSON_INT,
			   "search.count is not int");
		check_true(aik_json_int(count) > 0,
			   "search.count is not > 0 (got %lld)",
			   aik_json_int(count));
		results = aik_json_get(root, "results");
		check_true(aik_json_typeof(results) == AIK_JSON_ARR,
			   "search.results is not an array");
		check_int((long long)aik_json_count(results),
			  aik_json_int(count), "search.results length");
		first = aik_json_at(results, 0);
		check_true(aik_json_typeof(first) == AIK_JSON_OBJ,
			   "search.results[0] is not an object");
		check_int((long long)aik_json_count(first), 25,
			  "search.results[0] key count");
		check_true(aik_json_typeof(aik_json_get(first, "score")) ==
				   AIK_JSON_NUM,
			   "search.results[0].score is not a number");
	}
	aik_json_free(root);
	free(body);
}

static void test_unknown_route(int port)
{
	int status = -1;
	char *body = NULL;
	aik_json *root;

	check_true(http_call(port, "GET", "/nope", NULL, NULL, &status,
			     &body) == 0,
		   "404: request failed");
	check_int(status, 404, "404 status");
	root = parse_json(body);
	check_true(root != NULL, "404: body is not JSON");
	if (root)
		check_str(aik_json_str(detail_of(root)), "Not Found",
			  "404.detail");
	aik_json_free(root);
	free(body);
}

static void test_auth(int port)
{
	int status = -1;
	char *body = NULL;
	aik_json *root;

	/* /health 放行 */
	check_true(http_call(port, "GET", "/health", NULL, NULL, &status,
			     &body) == 0,
		   "auth health: request failed");
	check_int(status, 200, "auth health status");
	free(body);
	body = NULL;

	/* /stats 无 token → 401 unauthorized */
	check_true(http_call(port, "GET", "/stats", NULL, NULL, &status,
			     &body) == 0,
		   "auth anon: request failed");
	check_int(status, 401, "auth anon status");
	root = parse_json(body);
	check_true(root != NULL, "auth anon: body is not JSON");
	if (root)
		check_str(aik_json_str(detail_of(root)), "unauthorized",
			  "auth anon detail");
	aik_json_free(root);
	free(body);
	body = NULL;

	/* 正确 token → 200 */
	check_true(http_call(port, "GET", "/stats", NULL, "Bearer secret",
			     &status, &body) == 0,
		   "auth ok: request failed");
	check_int(status, 200, "auth ok status");
	root = parse_json(body);
	check_true(root != NULL, "auth ok: body is not JSON");
	aik_json_free(root);
	free(body);
	body = NULL;

	/* 错误 token → 401 */
	check_true(http_call(port, "GET", "/stats", NULL, "Bearer wrong",
			     &status, &body) == 0,
		   "auth bad: request failed");
	check_int(status, 401, "auth bad status");
	root = parse_json(body);
	check_true(root != NULL, "auth bad: body is not JSON");
	if (root)
		check_str(aik_json_str(detail_of(root)), "unauthorized",
			  "auth bad detail");
	aik_json_free(root);
	free(body);
}

/* ------------------------------------------------------------------ */
/* T4d 用例辅助                                                        */
/* ------------------------------------------------------------------ */
/* 对象键名与顺序（键名逐位比较） */
static void check_keys(const aik_json *obj, const char *const *keys, size_t n,
		       const char *what)
{
	size_t i;

	check_true(aik_json_typeof(obj) == AIK_JSON_OBJ, "%s is not an object",
		   what);
	check_int((long long)aik_json_count(obj), (long long)n, what);
	if (aik_json_typeof(obj) != AIK_JSON_OBJ)
		return;
	for (i = 0; i < n; i++) {
		const char *k = aik_json_key_at(obj, i);

		check_true(k && strcmp(k, keys[i]) == 0,
			   "%s key[%zu] is '%s' expected '%s'", what, i,
			   k ? k : "(null)", keys[i]);
	}
}

/* 两个数值数组是否逐位不同（非数组/长度不同视为不同） */
static int num_arr_differs(const aik_json *a, const aik_json *b)
{
	size_t i;
	size_t n;

	if (aik_json_typeof(a) != AIK_JSON_ARR ||
	    aik_json_typeof(b) != AIK_JSON_ARR)
		return 1;
	n = aik_json_count(a);
	if (n != aik_json_count(b))
		return 1;
	for (i = 0; i < n; i++) {
		const aik_json *x = aik_json_at(a, i);
		const aik_json *y = aik_json_at(b, i);

		if (aik_json_typeof(x) != AIK_JSON_NUM ||
		    aik_json_typeof(y) != AIK_JSON_NUM)
			return 1;
		if (aik_json_num(x) != aik_json_num(y))
			return 1;
	}
	return 0;
}

/* 数组是否为空 */
static int arr_empty(const aik_json *v)
{
	return aik_json_typeof(v) == AIK_JSON_ARR && aik_json_count(v) == 0;
}

/* 发 POST /memories，成功时把 id 写入 id_out，可选返回解析后的根 */
static void post_memory(int port, const char *json, char *id_out,
			size_t id_cap, aik_json **root_out)
{
	int status = -1;
	char *body = NULL;
	aik_json *root;
	const aik_json *j;

	if (root_out)
		*root_out = NULL;
	if (id_out && id_cap)
		id_out[0] = '\0';
	if (http_call(port, "POST", "/memories", json, NULL, &status, &body) !=
		    0 ||
	    status != 200) {
		free(body);
		return;
	}
	root = parse_json(body);
	free(body);
	if (!root)
		return;
	j = aik_json_get(root, "id");
	if (id_out && id_cap && aik_json_typeof(j) == AIK_JSON_STR)
		snprintf(id_out, id_cap, "%s", aik_json_str(j));
	if (root_out)
		*root_out = root;
	else
		aik_json_free(root);
}

/* ------------------------------------------------------------------ */
/* T4d：PATCH /memories/{id}                                          */
/* ------------------------------------------------------------------ */
static void test_patch(int port)
{
	int status = -1;
	char *body = NULL;
	aik_json *old = NULL;
	aik_json *root;
	char id[64] = "";
	char path[160];

	post_memory(port, "{\"text\":\"T4d patch 原文：春天的杭州西湖。\","
			  "\"tags\":[\"patch\"]}",
		    id, sizeof(id), &old);
	check_true(old != NULL && id[0] != '\0',
		   "patch: cannot add seed memory");
	if (!old || !id[0]) {
		aik_json_free(old);
		return;
	}
	snprintf(path, sizeof(path), "/memories/%s", id);

	/* 有效 PATCH：text 变化 → version+1、embedding 变化 */
	check_true(http_call(port, "PATCH", path,
			     "{\"text\":\"T4d patch 新文：秋天的苏州园林。\"}",
			     NULL, &status, &body) == 0,
		   "patch: request failed");
	check_int(status, 200, "patch status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "patch: body is not JSON");
	if (root) {
		check_str(aik_json_str(aik_json_get(root, "text")),
			  "T4d patch 新文：秋天的苏州园林。", "patch.text");
		check_int(aik_json_int(aik_json_get(root, "version")),
			  aik_json_int(aik_json_get(old, "version")) + 1,
			  "patch.version");
		check_true(num_arr_differs(aik_json_get(root, "embedding"),
					   aik_json_get(old, "embedding")),
			   "patch.embedding did not change");
		check_int(aik_json_int(aik_json_get(root, "hit_count")),
			  aik_json_int(aik_json_get(old, "hit_count")),
			  "patch.hit_count");
		check_int((long long)aik_json_count(root), 20,
			  "patch: memory.to_dict key count");
	}
	aik_json_free(root);

	/* PATCH 不存在 → 404，detail == str(KeyError(...))（repr 带引号） */
	check_true(http_call(port, "PATCH", "/memories/m_ffffffffffff",
			     "{\"text\":\"x\"}", NULL, &status, &body) == 0,
		   "patch missing: request failed");
	check_int(status, 404, "patch missing status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "patch missing: body is not JSON");
	if (root)
		check_str(aik_json_str(detail_of(root)),
			  "'memory m_ffffffffffff not found'",
			  "patch missing detail");
	aik_json_free(root);

	/* 类型错误 → 422 string_type，loc ["body","text"] */
	check_true(http_call(port, "PATCH", path, "{\"text\":123}", NULL,
			     &status, &body) == 0,
		   "patch type: request failed");
	check_int(status, 422, "patch type status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "patch type: body is not JSON");
	if (root) {
		const aik_json *detail = detail_of(root);
		const aik_json *first = aik_json_at(detail, 0);

		check_true(aik_json_typeof(detail) == AIK_JSON_ARR &&
				   aik_json_count(detail) == 1,
			   "patch type: detail is not a 1-element array");
		check_str(aik_json_str(aik_json_get(first, "type")),
			  "string_type", "patch type.type");
		check_true(loc_is(aik_json_get(first, "loc"), "body", "text"),
			   "patch type.loc is not [\"body\",\"text\"]");
		check_int(aik_json_int(aik_json_get(first, "input")), 123,
			  "patch type.input");
	}
	aik_json_free(root);

	/* 空白 text → 422 value_error（UpdateMemoryRequest 的非空白校验） */
	check_true(http_call(port, "PATCH", path, "{\"text\":\"   \"}", NULL,
			     &status, &body) == 0,
		   "patch blank: request failed");
	check_int(status, 422, "patch blank status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "patch blank: body is not JSON");
	if (root) {
		const aik_json *first = aik_json_at(detail_of(root), 0);

		check_str(aik_json_str(aik_json_get(first, "type")),
			  "value_error", "patch blank.type");
		check_str(aik_json_str(aik_json_get(first, "msg")),
			  "Value error, text must not be blank", "patch blank.msg");
	}
	aik_json_free(root);

	/* 其余 Optional 字段：importance / summary 生效 */
	check_true(http_call(port, "PATCH", path,
			     "{\"importance\":0.9,\"summary\":\"T4d 摘要\"}",
			     NULL, &status, &body) == 0,
		   "patch fields: request failed");
	check_int(status, 200, "patch fields status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "patch fields: body is not JSON");
	if (root) {
		const aik_json *imp = aik_json_get(root, "importance");

		check_true(aik_json_typeof(imp) == AIK_JSON_NUM &&
				   aik_json_num(imp) == 0.9,
			   "patch fields.importance is not 0.9");
		check_str(aik_json_str(aik_json_get(root, "summary")),
			  "T4d 摘要", "patch fields.summary");
	}
	aik_json_free(root);
	aik_json_free(old);
}

/* ------------------------------------------------------------------ */
/* T4d：DELETE /memories/{id}                                         */
/* ------------------------------------------------------------------ */
static void test_delete(int port)
{
	int status = -1;
	char *body = NULL;
	aik_json *root;
	char id[64] = "";
	char path[160];

	post_memory(port, "{\"text\":\"T4d delete 目标：待删除的临时记忆。\"}",
		    id, sizeof(id), NULL);
	check_true(id[0] != '\0', "delete: cannot add seed memory");
	if (!id[0])
		return;
	snprintf(path, sizeof(path), "/memories/%s", id);

	check_true(http_call(port, "DELETE", path, NULL, NULL, &status,
			     &body) == 0,
		   "delete: request failed");
	check_int(status, 200, "delete status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "delete: body is not JSON");
	if (root) {
		static const char *const keys[] = { "deleted" };

		check_keys(root, keys, 1, "delete");
		check_str(aik_json_str(aik_json_get(root, "deleted")), id,
			  "delete.deleted");
	}
	aik_json_free(root);

	/* 已删除 → GET 404 */
	check_true(http_call(port, "GET", path, NULL, NULL, &status, &body) == 0,
		   "delete get: request failed");
	check_int(status, 404, "delete get status");
	free(body);
	body = NULL;

	/* 再删 → 404 memory not found */
	check_true(http_call(port, "DELETE", path, NULL, NULL, &status,
			     &body) == 0,
		   "delete again: request failed");
	check_int(status, 404, "delete again status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "delete again: body is not JSON");
	if (root)
		check_str(aik_json_str(detail_of(root)), "memory not found",
			  "delete again detail");
	aik_json_free(root);
}

/* ------------------------------------------------------------------ */
/* T4d：archive → restore 往返                                        */
/* ------------------------------------------------------------------ */
static void test_archive_restore(int port)
{
	int status = -1;
	char *body = NULL;
	aik_json *root;
	aik_json *mem;
	char id[64] = "";
	char path[160];
	char old_region[64] = "";

	post_memory(port, "{\"text\":\"zzqarchiveprobe quux frobnicate 9917\"}",
		    id, sizeof(id), &mem);
	check_true(mem != NULL && id[0] != '\0',
		   "archive: cannot add probe memory");
	if (!mem || !id[0]) {
		aik_json_free(mem);
		return;
	}
	{
		const aik_json *rid = aik_json_get(mem, "region_id");

		check_true(aik_json_typeof(rid) == AIK_JSON_STR,
			   "archive: probe.region_id is not a string");
		if (aik_json_typeof(rid) == AIK_JSON_STR)
			snprintf(old_region, sizeof(old_region), "%s",
				 aik_json_str(rid));
		check_true(aik_json_typeof(aik_json_get(mem, "archived")) ==
				   AIK_JSON_BOOL &&
			   aik_json_bool(aik_json_get(mem, "archived")) == 0,
		   "archive: probe.archived is not false");
	}
	aik_json_free(mem);
	snprintf(path, sizeof(path), "/memories/%s", id);

	/* archive → {"archived": id} */
	{
		char apath[160];

		snprintf(apath, sizeof(apath), "/memories/%s/archive", id);
		check_true(http_call(port, "POST", apath, NULL, NULL, &status,
				     &body) == 0,
			   "archive: request failed");
		check_int(status, 200, "archive status");
		root = parse_json(body);
		free(body);
		body = NULL;
		check_true(root != NULL, "archive: body is not JSON");
		if (root) {
			static const char *const keys[] = { "archived" };

			check_keys(root, keys, 1, "archive");
			check_str(aik_json_str(aik_json_get(root, "archived")),
				  id, "archive.archived");
		}
		aik_json_free(root);
	}

	/* GET：archived=true、region_id=null */
	check_true(http_call(port, "GET", path, NULL, NULL, &status, &body) == 0,
		   "archive get: request failed");
	check_int(status, 200, "archive get status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "archive get: body is not JSON");
	if (root) {
		const aik_json *arch = aik_json_get(root, "archived");

		check_true(aik_json_typeof(arch) == AIK_JSON_BOOL &&
				   aik_json_bool(arch) == 1,
			   "archive get.archived is not true");
		check_true(aik_json_typeof(aik_json_get(root, "region_id")) ==
				   AIK_JSON_NULL,
			   "archive get.region_id is not null");
	}
	aik_json_free(root);

	/* 已归档再 archive → 404（Python archive_memory 返回 False） */
	{
		char apath[160];

		snprintf(apath, sizeof(apath), "/memories/%s/archive", id);
		check_true(http_call(port, "POST", apath, NULL, NULL, &status,
				     &body) == 0,
			   "archive twice: request failed");
		check_int(status, 404, "archive twice status");
		root = parse_json(body);
		free(body);
		body = NULL;
		check_true(root != NULL, "archive twice: body is not JSON");
		if (root)
			check_str(aik_json_str(detail_of(root)),
				  "memory not found", "archive twice detail");
		aik_json_free(root);
	}

	/* restore → {"restored": id}，archived=false、region_id 重新分配 */
	{
		char rpath[160];

		snprintf(rpath, sizeof(rpath), "/memories/%s/restore", id);
		check_true(http_call(port, "POST", rpath, NULL, NULL, &status,
				     &body) == 0,
			   "restore: request failed");
		check_int(status, 200, "restore status");
		root = parse_json(body);
		free(body);
		body = NULL;
		check_true(root != NULL, "restore: body is not JSON");
		if (root) {
			static const char *const keys[] = { "restored" };

			check_keys(root, keys, 1, "restore");
			check_str(aik_json_str(aik_json_get(root, "restored")),
				  id, "restore.restored");
		}
		aik_json_free(root);
	}

	check_true(http_call(port, "GET", path, NULL, NULL, &status, &body) == 0,
		   "restore get: request failed");
	check_int(status, 200, "restore get status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "restore get: body is not JSON");
	if (root) {
		const aik_json *arch = aik_json_get(root, "archived");
		const aik_json *rid = aik_json_get(root, "region_id");

		check_true(aik_json_typeof(arch) == AIK_JSON_BOOL &&
				   aik_json_bool(arch) == 0,
			   "restore get.archived is not false");
		check_true(aik_json_typeof(rid) == AIK_JSON_STR &&
				   aik_json_str(rid) && aik_json_str(rid)[0],
			   "restore get.region_id is not a non-empty string");
		check_true(aik_json_typeof(rid) == AIK_JSON_STR &&
				   old_region[0] &&
				   strcmp(aik_json_str(rid), old_region) != 0,
			   "restore get.region_id did not change (still %s)",
			   old_region);
	}
	aik_json_free(root);

	/* 未归档再 restore → 404 */
	{
		char rpath[160];

		snprintf(rpath, sizeof(rpath), "/memories/%s/restore", id);
		check_true(http_call(port, "POST", rpath, NULL, NULL, &status,
				     &body) == 0,
			   "restore twice: request failed");
		check_int(status, 404, "restore twice status");
		free(body);
		body = NULL;
	}
}
/* ------------------------------------------------------------------ */
/* T4d：POST /regions/search                                          */
/* ------------------------------------------------------------------ */
static void test_regions_search(int port)
{
	int status = -1;
	char *body = NULL;
	aik_json *root;
	const aik_json *detail;
	const aik_json *results;
	const aik_json *first;

	check_true(http_call(port, "POST", "/regions/search",
			     "{\"text\":\"T4d patch 新文：秋天的苏州园林。\","
			     "\"top_k\":3}",
			     NULL, &status, &body) == 0,
		   "regions/search: request failed");
	check_int(status, 200, "regions/search status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "regions/search: body is not JSON");
	if (root) {
		static const char *const root_keys[] = { "count", "results" };
		static const char *const hit_keys[] = {
			"region_id", "score", "distance", "size", "density"
		};
		long long count = aik_json_int(aik_json_get(root, "count"));

		check_keys(root, root_keys, 2, "regions/search");
		check_true(count >= 1, "regions/search.count is not >= 1 (got %lld)",
			   count);
		results = aik_json_get(root, "results");
		check_true(aik_json_typeof(results) == AIK_JSON_ARR,
			   "regions/search.results is not an array");
		check_int((long long)aik_json_count(results), count,
			  "regions/search.results length");
		first = aik_json_at(results, 0);
		check_keys(first, hit_keys, 5, "regions/search.hit");
		if (aik_json_typeof(first) == AIK_JSON_OBJ) {
			const aik_json *rid = aik_json_get(first, "region_id");
			const aik_json *score = aik_json_get(first, "score");
			const aik_json *dist = aik_json_get(first, "distance");
			const aik_json *size = aik_json_get(first, "size");
			const aik_json *density = aik_json_get(first, "density");

			check_true(aik_json_typeof(rid) == AIK_JSON_STR &&
					   aik_json_str(rid) &&
					   strncmp(aik_json_str(rid), "r_", 2) == 0,
				   "regions/search.hit.region_id is not r_*");
			check_true(aik_json_typeof(score) == AIK_JSON_NUM,
				   "regions/search.hit.score is not a number");
			check_true(aik_json_typeof(dist) == AIK_JSON_NUM,
				   "regions/search.hit.distance is not a number");
			check_true(aik_json_typeof(size) == AIK_JSON_INT &&
					   aik_json_int(size) >= 1,
				   "regions/search.hit.size is not >= 1");
			check_true(aik_json_typeof(density) == AIK_JSON_NUM,
				   "regions/search.hit.density is not a number");
		}
	}
	aik_json_free(root);

	/* 缺 text → 422 missing，input 为整个 body 对象 */
	check_true(http_call(port, "POST", "/regions/search", "{}", NULL,
			     &status, &body) == 0,
		   "regions/search missing: request failed");
	check_int(status, 422, "regions/search missing status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "regions/search missing: body is not JSON");
	if (root) {
		detail = detail_of(root);
		first = aik_json_at(detail, 0);
		check_true(aik_json_typeof(detail) == AIK_JSON_ARR &&
				   aik_json_count(detail) == 1,
			   "regions/search missing: detail is not a 1-element array");
		check_str(aik_json_str(aik_json_get(first, "type")), "missing",
			  "regions/search missing.type");
		check_str(aik_json_str(aik_json_get(first, "msg")),
			  "Field required", "regions/search missing.msg");
		check_true(loc_is(aik_json_get(first, "loc"), "body", "text"),
			   "regions/search missing.loc is not [\"body\",\"text\"]");
		check_true(aik_json_typeof(aik_json_get(first, "input")) ==
				   AIK_JSON_OBJ &&
			   aik_json_count(aik_json_get(first, "input")) == 0,
			   "regions/search missing.input is not the empty body");
	}
	aik_json_free(root);

	/* top_k 类型错误 → 422 int_type */
	check_true(http_call(port, "POST", "/regions/search",
			     "{\"text\":\"x\",\"top_k\":\"3\"}", NULL, &status,
			     &body) == 0,
		   "regions/search top_k: request failed");
	check_int(status, 422, "regions/search top_k status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "regions/search top_k: body is not JSON");
	if (root) {
		first = aik_json_at(detail_of(root), 0);

		check_str(aik_json_str(aik_json_get(first, "type")),
			  "int_type", "regions/search top_k.type");
		check_true(loc_is(aik_json_get(first, "loc"), "body", "top_k"),
			   "regions/search top_k.loc is not [\"body\",\"top_k\"]");
	}
	aik_json_free(root);
}

/* ------------------------------------------------------------------ */
/* T4d：POST /regions/evolve                                          */
/* ------------------------------------------------------------------ */
static void test_evolve(int port)
{
	int status = -1;
	char *body = NULL;
	aik_json *root;

	check_true(http_call(port, "POST", "/regions/evolve", NULL, NULL,
			     &status, &body) == 0,
		   "evolve: request failed");
	check_int(status, 200, "evolve status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "evolve: body is not JSON");
	if (root) {
		static const char *const keys[] = { "events" };
		const aik_json *events = aik_json_get(root, "events");

		check_keys(root, keys, 1, "evolve");
		check_true(aik_json_typeof(events) == AIK_JSON_ARR,
			   "evolve.events is not an array");
		/* 空数组合法；非空时每个事件必须带 kind/region_id/detail */
		if (aik_json_typeof(events) == AIK_JSON_ARR &&
		    aik_json_count(events) > 0) {
			static const char *const ev_keys[] = {
				"kind", "region_id", "detail"
			};
			const aik_json *ev = aik_json_at(events, 0);

			check_keys(ev, ev_keys, 3, "evolve.events[0]");
			check_true(aik_json_typeof(aik_json_get(ev, "kind")) ==
					   AIK_JSON_STR,
				   "evolve.events[0].kind is not a string");
			check_true(aik_json_typeof(
					   aik_json_get(ev, "region_id")) ==
					   AIK_JSON_STR,
				   "evolve.events[0].region_id is not a string");
		}
	}
	aik_json_free(root);
}

/* ------------------------------------------------------------------ */
/* T4d：GET /graph 与 POST /graph/link                                */
/* ------------------------------------------------------------------ */
/* 找 source→target/kind 的边；找不到返回 NULL */
static const aik_json *find_edge(const aik_json *edges, const char *source,
				 const char *target, const char *kind)
{
	size_t i;
	size_t n = aik_json_typeof(edges) == AIK_JSON_ARR ? aik_json_count(edges)
							  : 0;

	for (i = 0; i < n; i++) {
		const aik_json *e = aik_json_at(edges, i);
		const char *s = aik_json_str(aik_json_get(e, "source"));
		const char *t = aik_json_str(aik_json_get(e, "target"));
		const char *k = aik_json_str(aik_json_get(e, "kind"));

		if (s && t && k && strcmp(s, source) == 0 &&
		    strcmp(t, target) == 0 && strcmp(k, kind) == 0)
			return e;
	}
	return NULL;
}

static void test_graph(int port)
{
	int status = -1;
	char *body = NULL;
	aik_json *root;
	char a[64] = "";
	char b[64] = "";
	long long before = -1;
	char link_body[512];

	/* 初始图（可能已有 0 条边） */
	check_true(http_call(port, "GET", "/graph", NULL, NULL, &status,
			     &body) == 0,
		   "graph: request failed");
	check_int(status, 200, "graph status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "graph: body is not JSON");
	if (root) {
		static const char *const keys[] = { "edge_count", "edges" };
		const aik_json *ec = aik_json_get(root, "edge_count");
		const aik_json *edges = aik_json_get(root, "edges");

		check_keys(root, keys, 2, "graph");
		check_true(aik_json_typeof(ec) == AIK_JSON_INT,
			   "graph.edge_count is not int");
		check_true(aik_json_typeof(edges) == AIK_JSON_ARR,
			   "graph.edges is not an array");
		check_int(aik_json_int(ec), (long long)aik_json_count(edges),
			  "graph.edge_count vs edges length");
		before = aik_json_int(ec);
	} else {
		before = 0;
	}
	aik_json_free(root);

	post_memory(port, "{\"text\":\"T4d graph 端点 A：原因记忆。\"}", a,
		    sizeof(a), NULL);
	post_memory(port, "{\"text\":\"T4d graph 端点 B：结果记忆。\"}", b,
		    sizeof(b), NULL);
	check_true(a[0] != '\0' && b[0] != '\0',
		   "graph: cannot add endpoint memories");
	if (!a[0] || !b[0])
		return;

	snprintf(link_body, sizeof(link_body),
		 "{\"a\":\"%s\",\"b\":\"%s\",\"kind\":\"cause\"}", a, b);
	check_true(http_call(port, "POST", "/graph/link", link_body, NULL,
			     &status, &body) == 0,
		   "graph/link: request failed");
	check_int(status, 200, "graph/link status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "graph/link: body is not JSON");
	if (root) {
		static const char *const keys[] = { "linked" };
		const aik_json *linked = aik_json_get(root, "linked");

		check_keys(root, keys, 1, "graph/link");
		check_true(aik_json_typeof(linked) == AIK_JSON_BOOL &&
				   aik_json_bool(linked) == 1,
			   "graph/link.linked is not true");
	}
	aik_json_free(root);

	/* cause 双向：正向 cause + 反向 conversation/note=timeline */
	check_true(http_call(port, "GET", "/graph", NULL, NULL, &status,
			     &body) == 0,
		   "graph after link: request failed");
	check_int(status, 200, "graph after link status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "graph after link: body is not JSON");
	if (root) {
		const aik_json *edges = aik_json_get(root, "edges");
		const aik_json *fwd;
		const aik_json *rev;

		check_int(aik_json_int(aik_json_get(root, "edge_count")),
			  before + 2, "graph.edge_count delta");
		fwd = find_edge(edges, a, b, "cause");
		rev = find_edge(edges, b, a, "conversation");
		check_true(fwd != NULL, "graph: forward cause edge missing");
		check_true(rev != NULL,
			   "graph: reverse conversation edge missing");
		if (fwd) {
			check_true(aik_json_num(aik_json_get(fwd, "weight")) ==
					   1.0,
				   "graph: cause edge weight is not 1.0");
			check_str(aik_json_str(aik_json_get(fwd, "note")), "",
				  "graph: cause edge note");
		}
		if (rev) {
			check_true(aik_json_num(aik_json_get(rev, "weight")) ==
					   1.0,
				   "graph: conversation edge weight is not 1.0");
			check_str(aik_json_str(aik_json_get(rev, "note")),
				  "timeline", "graph: conversation edge note");
		}
	}
	aik_json_free(root);

	/* 端点不存在 → 404 one or both memories missing */
	snprintf(link_body, sizeof(link_body),
		 "{\"a\":\"%s\",\"b\":\"m_ffffffffffff\"}", a);
	check_true(http_call(port, "POST", "/graph/link", link_body, NULL,
			     &status, &body) == 0,
		   "graph/link missing: request failed");
	check_int(status, 404, "graph/link missing status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "graph/link missing: body is not JSON");
	if (root)
		check_str(aik_json_str(detail_of(root)),
			  "one or both memories missing",
			  "graph/link missing detail");
	aik_json_free(root);

	/* 缺 b → 422 missing（LinkRequest 字段序 a, b, ...） */
	snprintf(link_body, sizeof(link_body), "{\"a\":\"%s\"}", a);
	check_true(http_call(port, "POST", "/graph/link", link_body, NULL,
			     &status, &body) == 0,
		   "graph/link bad: request failed");
	check_int(status, 422, "graph/link bad status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "graph/link bad: body is not JSON");
	if (root) {
		const aik_json *first = aik_json_at(detail_of(root), 0);

		check_str(aik_json_str(aik_json_get(first, "type")), "missing",
			  "graph/link bad.type");
		check_true(loc_is(aik_json_get(first, "loc"), "body", "b"),
			   "graph/link bad.loc is not [\"body\",\"b\"]");
	}
	aik_json_free(root);
}

/* ------------------------------------------------------------------ */
/* T4d：可选模块只读路由（enabled:false 真实空态）                     */
/* ------------------------------------------------------------------ */
static void test_modules(int port)
{
	int status = -1;
	char *body = NULL;
	aik_json *root;

	/* GET /facts */
	check_true(http_call(port, "GET", "/facts", NULL, NULL, &status,
			     &body) == 0,
		   "facts: request failed");
	check_int(status, 200, "facts status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "facts: body is not JSON");
	if (root) {
		static const char *const keys[] = {
			"enabled", "entities", "relations", "facts"
		};
		const aik_json *en = aik_json_get(root, "enabled");

		check_keys(root, keys, 4, "facts");
		check_true(aik_json_typeof(en) == AIK_JSON_BOOL &&
				   aik_json_bool(en) == 0,
			   "facts.enabled is not false");
		check_true(arr_empty(aik_json_get(root, "entities")),
			   "facts.entities is not []");
		check_true(arr_empty(aik_json_get(root, "relations")),
			   "facts.relations is not []");
		check_true(arr_empty(aik_json_get(root, "facts")),
			   "facts.facts is not []");
	}
	aik_json_free(root);

	/* GET /facts/history */
	check_true(http_call(port, "GET", "/facts/history", NULL, NULL, &status,
			     &body) == 0,
		   "facts/history: request failed");
	check_int(status, 200, "facts/history status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "facts/history: body is not JSON");
	if (root) {
		static const char *const keys[] = { "enabled", "versions" };
		const aik_json *en = aik_json_get(root, "enabled");

		check_keys(root, keys, 2, "facts/history");
		check_true(aik_json_typeof(en) == AIK_JSON_BOOL &&
				   aik_json_bool(en) == 0,
			   "facts/history.enabled is not false");
		check_true(arr_empty(aik_json_get(root, "versions")),
			   "facts/history.versions is not []");
	}
	aik_json_free(root);

	/* POST /facts/multi_hop */
	check_true(http_call(port, "POST", "/facts/multi_hop", "{}", NULL,
			     &status, &body) == 0,
		   "facts/multi_hop: request failed");
	check_int(status, 200, "facts/multi_hop status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "facts/multi_hop: body is not JSON");
	if (root) {
		static const char *const keys[] = { "enabled", "results" };
		const aik_json *en = aik_json_get(root, "enabled");

		check_keys(root, keys, 2, "facts/multi_hop");
		check_true(aik_json_typeof(en) == AIK_JSON_BOOL &&
				   aik_json_bool(en) == 0,
			   "facts/multi_hop.enabled is not false");
		check_true(arr_empty(aik_json_get(root, "results")),
			   "facts/multi_hop.results is not []");
	}
	aik_json_free(root);

	/* GET /profile */
	check_true(http_call(port, "GET", "/profile", NULL, NULL, &status,
			     &body) == 0,
		   "profile: request failed");
	check_int(status, 200, "profile status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "profile: body is not JSON");
	if (root) {
		static const char *const keys[] = {
			"enabled", "profile_facts", "snapshots"
		};
		const aik_json *en = aik_json_get(root, "enabled");
		const aik_json *snap = aik_json_get(root, "snapshots");

		check_keys(root, keys, 3, "profile");
		check_true(aik_json_typeof(en) == AIK_JSON_BOOL &&
				   aik_json_bool(en) == 0,
			   "profile.enabled is not false");
		check_true(arr_empty(aik_json_get(root, "profile_facts")),
			   "profile.profile_facts is not []");
		check_true(aik_json_typeof(snap) == AIK_JSON_OBJ &&
				   aik_json_count(snap) == 0,
			   "profile.snapshots is not {}");
	}
	aik_json_free(root);

	/* GET /qapairs */
	check_true(http_call(port, "GET", "/qapairs", NULL, NULL, &status,
			     &body) == 0,
		   "qapairs: request failed");
	check_int(status, 200, "qapairs status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "qapairs: body is not JSON");
	if (root) {
		static const char *const keys[] = {
			"enabled", "count", "pairs"
		};
		const aik_json *en = aik_json_get(root, "enabled");
		const aik_json *count = aik_json_get(root, "count");

		check_keys(root, keys, 3, "qapairs");
		check_true(aik_json_typeof(en) == AIK_JSON_BOOL &&
				   aik_json_bool(en) == 0,
			   "qapairs.enabled is not false");
		check_true(aik_json_typeof(count) == AIK_JSON_INT &&
				   aik_json_int(count) == 0,
			   "qapairs.count is not 0");
		check_true(arr_empty(aik_json_get(root, "pairs")),
			   "qapairs.pairs is not []");
	}
	aik_json_free(root);

	/* GET /metrics */
	check_true(http_call(port, "GET", "/metrics", NULL, NULL, &status,
			     &body) == 0,
		   "metrics: request failed");
	check_int(status, 200, "metrics status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "metrics: body is not JSON");
	if (root) {
		static const char *const keys[] = { "enabled", "summary" };
		const aik_json *en = aik_json_get(root, "enabled");
		const aik_json *summary = aik_json_get(root, "summary");

		check_keys(root, keys, 2, "metrics");
		check_true(aik_json_typeof(en) == AIK_JSON_BOOL &&
				   aik_json_bool(en) == 0,
			   "metrics.enabled is not false");
		check_true(aik_json_typeof(summary) == AIK_JSON_OBJ &&
				   aik_json_count(summary) == 0,
			   "metrics.summary is not {}");
	}
	aik_json_free(root);

	/* GET /metrics/report → 404 telemetry disabled */
	check_true(http_call(port, "GET", "/metrics/report", NULL, NULL,
			     &status, &body) == 0,
		   "metrics/report: request failed");
	check_int(status, 404, "metrics/report status");
	root = parse_json(body);
	free(body);
	body = NULL;
	check_true(root != NULL, "metrics/report: body is not JSON");
	if (root)
		check_str(aik_json_str(detail_of(root)), "telemetry disabled",
			  "metrics/report detail");
	aik_json_free(root);
}

/* ================================================================== */
/* T4e 配置中心 + 动力学（routes_config.c）                            */
/* ================================================================== */
/*
 * 用例覆盖（任务书 E2-C）：
 *   - GET /config 的 groups/presets 与 parity/vectors/config 逐字节；
 *   - PUT /config 成功 / 未知项 / 非法值 / api_key 掩码跳过 / save 落盘；
 *   - mrl_dim 闸门（非空库改 embedding 身份 → ok:false，引擎保持原配置）；
 *   - POST /config/preset（未知 key 400、minimal 应用）；
 *   - POST /config/check 的形状与 llm/embedding 探测文案；
 *   - POST /config/reset 删文件 + 回默认 + 向量复现；
 *   - POST /consolidate / /compress 的 {"created":[...]} 形状。
 */
static void clear_sme_env(void)
{
	static const char *const names[] = {
		"SME_CONFIG_PATH", "SME_LLM_BASE_URL", "SME_LLM_API_KEY",
		"SME_LLM_MODEL", "SME_API_TOKEN", "SME_API_AUTH_TOKEN",
		"SME_EMBEDDING_PROVIDER", "SME_EMBEDDING_MODEL",
		"SME_EMBEDDING_DIM", "SME_EMBEDDING_BASE_URL",
		"SME_EMBEDDING_API_KEY",
	};
	size_t i;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
		(void)unsetenv(names[i]);
}

/* 不带配置文件的服务器：走默认配置 + source="defaults" */
static int start_server_defaults(test_server *ts, const char *tmpdir)
{
	int fds[2];
	char line[256];
	size_t used = 0;
	int port = -1;
	pid_t pid;

	snprintf(ts->cfg_path, sizeof(ts->cfg_path), "%s/sme-defaults.json",
		 tmpdir);
	snprintf(ts->db_path, sizeof(ts->db_path),
		 "%s/engine-defaults.json.gz", tmpdir);
	(void)unlink(ts->cfg_path);
	(void)unlink(ts->db_path);
	if (pipe(fds) != 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		close(fds[0]);
		close(fds[1]);
		return -1;
	}
	if (pid == 0) {
		close(fds[0]);
		if (dup2(fds[1], STDOUT_FILENO) < 0)
			_exit(127);
		close(fds[1]);
		execl(server_bin(), "smehttp", "--config", ts->cfg_path,
		      "--host", "127.0.0.1", "--port", "0", (char *)NULL);
		_exit(127);
	}
	close(fds[1]);
	ts->pid = pid;
	ts->port = -1;
	for (;;) {
		ssize_t n;
		char *nl;

		if (used + 1 >= sizeof(line))
			break;
		n = read(fds[0], line + used, sizeof(line) - 1 - used);
		if (n <= 0)
			break;
		used += (size_t)n;
		line[used] = '\0';
		nl = strchr(line, '\n');
		if (!nl)
			continue;
		*nl = '\0';
		if (strncmp(line, "LISTENING ", 10) == 0)
			port = atoi(line + 10);
		break;
	}
	close(fds[0]);
	if (port <= 0) {
		(void)kill(pid, SIGKILL);
		(void)waitpid(pid, NULL, 0);
		return -1;
	}
	ts->port = port;
	return 0;
}

/* AIK_PARITY_VECTORS 或 ~/aikernel-longterm/parity/vectors */
static const char *vectors_root(void)
{
	const char *env = getenv("AIK_PARITY_VECTORS");
	static char buf[512];
	const char *home;

	if (env && *env)
		return env;
	home = getenv("HOME");
	snprintf(buf, sizeof(buf), "%s/aikernel-longterm/parity/vectors",
		 home && *home ? home : ".");
	return buf;
}

static int vector_path(char *out, size_t cap, const char *name)
{
	int n = snprintf(out, cap, "%s/config/%s", vectors_root(), name);

	return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

static char *read_file_all(const char *path, size_t *out_len)
{
	FILE *f = fopen(path, "rb");
	long n;
	char *buf;
	size_t got;

	*out_len = 0;
	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return NULL;
	}
	n = ftell(f);
	if (n < 0 || fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return NULL;
	}
	buf = malloc((size_t)n + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}
	got = fread(buf, 1, (size_t)n, f);
	fclose(f);
	if (got != (size_t)n) {
		free(buf);
		return NULL;
	}
	buf[got] = '\0';
	*out_len = got;
	return buf;
}

/* JSON 节点 dump 后与向量文件逐字节比较 */
static void check_vector(const aik_json *node, const char *name,
			 const char *what)
{
	char path[640];
	char *exp = NULL;
	char *got = NULL;
	size_t elen = 0;
	size_t glen = 0;

	if (vector_path(path, sizeof(path), name) != 0 ||
	    !(exp = read_file_all(path, &elen))) {
		check_true(0, "%s: vector %s missing (%s)", what, name,
			   path);
		return;
	}
	if (aik_json_dump(node, &got, &glen) != 0 || !got) {
		free(exp);
		check_true(0, "%s: cannot dump JSON node", what);
		return;
	}
	check_int((long long)glen, (long long)elen, what);
	check_true(glen == elen && memcmp(got, exp, glen) == 0,
		   "%s: not byte-identical with %s", what, path);
	free(got);
	free(exp);
}

/* 文件字节与向量文件逐字节比较（save_config 输出） */
static void check_file_vs_vector(const char *path, const char *name,
				 const char *what)
{
	char vpath[640];
	char *exp = NULL;
	char *got = NULL;
	size_t elen = 0;
	size_t glen = 0;

	if (vector_path(vpath, sizeof(vpath), name) != 0 ||
	    !(exp = read_file_all(vpath, &elen))) {
		check_true(0, "%s: vector %s missing (%s)", what, name,
			   vpath);
		return;
	}
	got = read_file_all(path, &glen);
	check_true(got != NULL, "%s: cannot read %s", what, path);
	if (!got) {
		free(exp);
		return;
	}
	check_int((long long)glen, (long long)elen, what);
	check_true(glen == elen && memcmp(got, exp, glen) == 0,
		   "%s: not byte-identical with %s", what, vpath);
	free(got);
	free(exp);
}

/* groups -> items 里按 path 找 payload；未找到返回 NULL */
static const aik_json *config_item_payload(const aik_json *groups,
					   const char *path)
{
	size_t g;
	size_t n = aik_json_count(groups);

	for (g = 0; g < n; g++) {
		const aik_json *items =
			aik_json_get(aik_json_at(groups, g), "items");
		size_t i;

		for (i = 0; i < aik_json_count(items); i++) {
			const aik_json *it = aik_json_at(items, i);
			const char *p =
				aik_json_str(aik_json_get(it, "path"));

			if (p && strcmp(p, path) == 0)
				return it;
		}
	}
	return NULL;
}

static int payload_is_int(const aik_json *groups, const char *path,
			  long long want)
{
	const aik_json *p = config_item_payload(groups, path);
	const aik_json *v = p ? aik_json_get(p, "value") : NULL;

	return aik_json_typeof(v) == AIK_JSON_INT && aik_json_int(v) == want;
}

static int payload_is_num(const aik_json *groups, const char *path,
			  double want)
{
	const aik_json *p = config_item_payload(groups, path);
	const aik_json *v = p ? aik_json_get(p, "value") : NULL;

	return (aik_json_typeof(v) == AIK_JSON_NUM ||
		aik_json_typeof(v) == AIK_JSON_INT) &&
	       aik_json_num(v) == want;
}

static int payload_is_bool(const aik_json *groups, const char *path,
			   int want)
{
	const aik_json *p = config_item_payload(groups, path);
	const aik_json *v = p ? aik_json_get(p, "value") : NULL;

	return aik_json_typeof(v) == AIK_JSON_BOOL &&
	       aik_json_bool(v) == (want ? 1 : 0);
}

static int payload_is_str(const aik_json *groups, const char *path,
			  const char *want)
{
	const aik_json *p = config_item_payload(groups, path);
	const aik_json *v = p ? aik_json_get(p, "value") : NULL;

	return aik_json_typeof(v) == AIK_JSON_STR && want &&
	       strcmp(aik_json_str(v), want) == 0;
}

/* 发请求并解析 JSON（body_out 可选：拿原始响应体） */
static aik_json *call_json(int port, const char *method, const char *path,
			   const char *body, int *status_out,
			   char **body_out)
{
	char *resp_body = NULL;
	aik_json *root;

	if (http_call(port, method, path, body, NULL, status_out,
		      &resp_body) != 0)
		return NULL;
	root = parse_json(resp_body);
	if (body_out)
		*body_out = resp_body;
	else
		free(resp_body);
	return root;
}

/* {"ok":false,"errors":{...}}：断言并返回 errors（借用） */
static const aik_json *expect_ok_false(const aik_json *root,
				       const char *what)
{
	static const char *const keys[] = { "ok", "errors" };
	const aik_json *ok = aik_json_get(root, "ok");
	const aik_json *errors = aik_json_get(root, "errors");

	check_keys(root, keys, 2, what);
	check_true(aik_json_typeof(ok) == AIK_JSON_BOOL &&
			   aik_json_bool(ok) == 0,
		   "%s: ok is not false", what);
	check_true(aik_json_typeof(errors) == AIK_JSON_OBJ,
		   "%s: errors is not an object", what);
	return errors;
}

/* {"ok":true,"applied":N,"config_file":path} */
static void expect_applied_count(const aik_json *root, long long n,
				 const char *config_file, const char *what)
{
	static const char *const keys[] = {
		"ok", "applied", "config_file"
	};
	const aik_json *ok = aik_json_get(root, "ok");
	const aik_json *applied = aik_json_get(root, "applied");

	check_keys(root, keys, 3, what);
	check_true(aik_json_typeof(ok) == AIK_JSON_BOOL &&
			   aik_json_bool(ok) == 1,
		   "%s: ok is not true", what);
	check_true(aik_json_typeof(applied) == AIK_JSON_INT,
		   "%s: applied is not int", what);
	check_int(aik_json_int(applied), n, what);
	if (config_file)
		check_str(aik_json_str(aik_json_get(root, "config_file")),
			  config_file, what);
}

/* 顶层 {"detail":[...]} 的第一条错误 */
static const aik_json *first_detail(const aik_json *root, const char *what)
{
	const aik_json *detail = detail_of(root);

	check_true(aik_json_typeof(detail) == AIK_JSON_ARR &&
			   aik_json_count(detail) == 1,
		   "%s: detail is not a 1-element array", what);
	return aik_json_at(detail, 0);
}

/* loc == ["body", idx]（idx 为整数） */
static int loc_is_body_index(const aik_json *loc, long long idx)
{
	const char *s0;

	if (aik_json_typeof(loc) != AIK_JSON_ARR || aik_json_count(loc) != 2)
		return 0;
	s0 = aik_json_str(aik_json_at(loc, 0));
	if (!s0 || strcmp(s0, "body") != 0)
		return 0;
	return aik_json_typeof(aik_json_at(loc, 1)) == AIK_JSON_INT &&
	       aik_json_int(aik_json_at(loc, 1)) == idx;
}

/* ------------------------------------------------------------------ */
/* groups_mutated.json（进程内等价路径）                              */
/* ------------------------------------------------------------------ */
static int set_item_str(aik_json *dom, const char *path, const char *val)
{
	const aik_config_item *it = aik_config_item_find(path);
	aik_json *v;
	int rc;

	if (!it)
		return -1;
	v = aik_json_new_str(val);
	if (!v)
		return -1;
	rc = aik_config_item_set(dom, it, v);
	aik_json_free(v);
	return rc;
}

static int set_item_num(aik_json *dom, const char *path, double val)
{
	const aik_config_item *it = aik_config_item_find(path);
	aik_json *v;
	int rc;

	if (!it)
		return -1;
	v = aik_json_new_num(val);
	if (!v)
		return -1;
	rc = aik_config_item_set(dom, it, v);
	aik_json_free(v);
	return rc;
}

/*
 * 默认配置 DOM 上改密钥/令牌/枚举/阈值后 groups 与 groups_mutated.json
 * 逐字节一致。embedding.provider=openai 无法经 HTTP 生效（引擎拒绝非
 * hashing），因此走进程内等价路径（与 record_config.py 的构造一致）。
 */
static void test_config_groups_mutated(void)
{
	char err[256];
	aik_config *cfg;
	const aik_json *dom;
	aik_json *copy = NULL;
	aik_json *display = NULL;
	aik_json *groups = NULL;
	char *text = NULL;
	size_t len = 0;
	int ok;

	err[0] = '\0';
	cfg = aik_config_defaults(err, sizeof(err));
	check_true(cfg != NULL, "config.mutated: defaults: %s", err);
	if (!cfg)
		return;
	dom = aik_config_dom(cfg);
	ok = dom && aik_json_dump(dom, &text, &len) == 0 && text;
	if (ok) {
		copy = aik_json_parse(text, len, err, sizeof(err));
		free(text);
		text = NULL;
		ok = copy != NULL;
	}
	check_true(ok, "config.mutated: cannot deep-copy default DOM");
	if (ok) {
		ok = set_item_str(copy, "llm.api_key", "sk-test") == 0 &&
		     set_item_str(copy, "embedding.api_key", "emb-test") == 0 &&
		     set_item_str(copy, "api.auth_token", "tok") == 0 &&
		     set_item_str(copy, "embedding.provider", "openai") == 0 &&
		     set_item_str(copy, "retrieval.fusion", "weighted") == 0 &&
		     set_item_str(copy, "llm.reasoning_effort", "none") == 0 &&
		     set_item_num(copy, "consolidation.similarity_threshold",
				  0.9) == 0;
		check_true(ok, "config.mutated: item set failed");
	}
	if (ok) {
		display = aik_config_display(copy);
		groups = display ? aik_config_groups_build(display) : NULL;
		check_true(groups != NULL,
			   "config.mutated: groups build failed");
		if (groups) {
			const aik_json *p =
				config_item_payload(groups, "llm.api_key");

			check_str(aik_json_str(aik_json_get(p, "value")),
				  "******", "config.mutated llm.api_key mask");
			check_true(aik_json_typeof(
					   aik_json_get(p, "set")) ==
					   AIK_JSON_BOOL &&
					   aik_json_bool(
						   aik_json_get(p, "set")) ==
						   1,
				   "config.mutated llm.api_key.set");
			check_vector(groups, "groups_mutated.json",
				     "config.mutated groups");
		}
	}
	aik_json_free(groups);
	aik_json_free(display);
	aik_json_free(copy);
	aik_config_free(cfg);
}

/* ------------------------------------------------------------------ */
/* GET /config（默认配置来源）                                        */
/* ------------------------------------------------------------------ */
static void test_config_get_defaults(int port, const char *cfg_path)
{
	int status = -1;
	aik_json *root = call_json(port, "GET", "/config", NULL, &status,
				   NULL);
	static const char *const keys[] = {
		"config_file", "source", "groups", "presets"
	};
	const aik_json *groups;
	const aik_json *presets;
	const aik_json *p;

	check_int(status, 200, "config.get status");
	check_true(root != NULL, "config.get: body is not JSON");
	if (!root)
		return;
	check_keys(root, keys, 4, "config.get");
	check_str(aik_json_str(aik_json_get(root, "config_file")), cfg_path,
		  "config.get config_file");
	check_str(aik_json_str(aik_json_get(root, "source")), "defaults",
		  "config.get source");
	groups = aik_json_get(root, "groups");
	presets = aik_json_get(root, "presets");
	check_vector(groups, "groups_default.json", "config.get groups");
	check_vector(presets, "presets.json", "config.get presets");
	check_int((long long)aik_json_count(groups), 9,
		  "config.get groups count");
	check_str(aik_json_str(aik_json_get(aik_json_at(groups, 0), "key")),
		  "llm", "config.get first group");
	check_str(aik_json_str(aik_json_get(aik_json_at(groups, 8), "key")),
		  "extensions", "config.get last group");
	p = config_item_payload(groups, "llm.base_url");
	check_str(aik_json_str(aik_json_get(p, "value")),
		  "https://api.openai.com/v1", "config.get llm.base_url");
	check_true(aik_json_typeof(aik_json_get(p, "modified")) ==
			   AIK_JSON_BOOL &&
			   aik_json_bool(aik_json_get(p, "modified")) == 1,
		   "config.get llm.base_url.modified");
	p = config_item_payload(groups, "llm.api_key");
	check_str(aik_json_str(aik_json_get(p, "value")), "",
		  "config.get llm.api_key mask");
	check_true(aik_json_typeof(aik_json_get(p, "set")) ==
			   AIK_JSON_BOOL &&
			   aik_json_bool(aik_json_get(p, "set")) == 0,
		   "config.get llm.api_key.set");
	check_true(payload_is_int(groups, "embedding.mrl_dim", 0),
		   "config.get embedding.mrl_dim");
	aik_json_free(root);
}

/* POST /config/check（默认配置：hashing + LLM 未配置） */
static void test_config_check_defaults(int port)
{
	int status = -1;
	aik_json *root = call_json(port, "POST", "/config/check", "{}",
				   &status, NULL);
	static const char *const keys[] = {
		"config_valid", "errors", "engine_build_ok", "llm",
		"embedding"
	};
	static const char *const probe_keys[] = {
		"configured", "ok", "detail"
	};
	const aik_json *llm;
	const aik_json *emb;

	check_int(status, 200, "config.check status");
	check_true(root != NULL, "config.check: body is not JSON");
	if (!root)
		return;
	check_keys(root, keys, 5, "config.check");
	check_true(aik_json_typeof(aik_json_get(root, "config_valid")) ==
			   AIK_JSON_BOOL &&
			   aik_json_bool(aik_json_get(root, "config_valid")) ==
				   1,
		   "config.check config_valid is not true");
	check_true(arr_empty(aik_json_get(root, "errors")),
		   "config.check errors is not []");
	check_true(aik_json_typeof(aik_json_get(root, "engine_build_ok")) ==
			   AIK_JSON_BOOL &&
			   aik_json_bool(
				   aik_json_get(root, "engine_build_ok")) == 1,
		   "config.check engine_build_ok is not true");
	llm = aik_json_get(root, "llm");
	check_keys(llm, probe_keys, 3, "config.check llm");
	check_true(aik_json_typeof(aik_json_get(llm, "configured")) ==
			   AIK_JSON_BOOL &&
			   aik_json_bool(aik_json_get(llm, "configured")) == 0,
		   "config.check llm.configured is not false");
	check_true(aik_json_typeof(aik_json_get(llm, "ok")) ==
			   AIK_JSON_BOOL &&
			   aik_json_bool(aik_json_get(llm, "ok")) == 1,
		   "config.check llm.ok is not true");
	check_str(aik_json_str(aik_json_get(llm, "detail")),
		  "LLM 未配置（llm.base_url 为空 → 纯离线可用）",
		  "config.check llm.detail");
	emb = aik_json_get(root, "embedding");
	check_keys(emb, probe_keys, 3, "config.check embedding");
	check_true(aik_json_typeof(aik_json_get(emb, "configured")) ==
			   AIK_JSON_BOOL &&
			   aik_json_bool(aik_json_get(emb, "configured")) == 0,
		   "config.check embedding.configured is not false");
	check_true(aik_json_typeof(aik_json_get(emb, "ok")) ==
			   AIK_JSON_BOOL &&
			   aik_json_bool(aik_json_get(emb, "ok")) == 1,
		   "config.check embedding.ok is not true");
	check_str(aik_json_str(aik_json_get(emb, "detail")),
		  "embedding=hashing（hashing-d64-w3，无需网络）",
		  "config.check embedding.detail");
	aik_json_free(root);
}

/* ------------------------------------------------------------------ */
/* PUT /config                                                        */
/* ------------------------------------------------------------------ */
static void test_config_put(int port, const char *cfg_path)
{
	int status = -1;
	aik_json *root;
	const aik_json *errors;
	const aik_json *first;
	const aik_json *groups;

	/* 1) 无实际改动的 save=true：落盘文件与 Python save_config 逐字节 */
	root = call_json(port, "PUT", "/config",
			 "{\"values\":{\"retrieval.top_k\":10},"
			 "\"save\":true}",
			 &status, NULL);
	check_int(status, 200, "config.put save status");
	check_true(root != NULL, "config.put save: body is not JSON");
	if (root)
		expect_applied_count(root, 1, cfg_path, "config.put save");
	aik_json_free(root);
	check_true(access(cfg_path, F_OK) == 0,
		   "config.put save: config file was not written");
	check_file_vs_vector(cfg_path, "config_file.expected.txt",
			     "config.put save bytes");

	/* 2) values 非对象 → 422 dict_type loc ["body","values"] */
	root = call_json(port, "PUT", "/config", "{\"values\":[]}", &status,
			 NULL);
	check_int(status, 422, "config.put values-type status");
	first = root ? first_detail(root, "config.put values-type") : NULL;
	if (first) {
		check_str(aik_json_str(aik_json_get(first, "type")),
			  "dict_type", "config.put values-type.type");
		check_str(aik_json_str(aik_json_get(first, "msg")),
			  "Input should be a valid dictionary",
			  "config.put values-type.msg");
		check_true(loc_is(aik_json_get(first, "loc"), "body",
				  "values"),
			   "config.put values-type.loc");
	}
	aik_json_free(root);

	/* 3) save 非 bool → 422 bool_type loc ["body","save"] */
	root = call_json(port, "PUT", "/config",
			 "{\"values\":{},\"save\":\"yes\"}", &status, NULL);
	check_int(status, 422, "config.put save-type status");
	first = root ? first_detail(root, "config.put save-type") : NULL;
	if (first) {
		check_str(aik_json_str(aik_json_get(first, "type")),
			  "bool_type", "config.put save-type.type");
		check_str(aik_json_str(aik_json_get(first, "msg")),
			  "Input should be a valid boolean",
			  "config.put save-type.msg");
		check_true(loc_is(aik_json_get(first, "loc"), "body", "save"),
			   "config.put save-type.loc");
	}
	aik_json_free(root);

	/* 4) 非法 JSON → 422 json_invalid */
	root = call_json(port, "PUT", "/config", "{\"values\":", &status,
			 NULL);
	check_int(status, 422, "config.put json-invalid status");
	first = root ? first_detail(root, "config.put json-invalid") : NULL;
	if (first) {
		check_str(aik_json_str(aik_json_get(first, "type")),
			  "json_invalid", "config.put json-invalid.type");
		check_str(aik_json_str(aik_json_get(first, "msg")),
			  "JSON decode error",
			  "config.put json-invalid.msg");
		check_true(loc_is_body_index(aik_json_get(first, "loc"), 0),
			   "config.put json-invalid.loc");
		check_true(aik_json_typeof(aik_json_get(first, "ctx")) ==
				   AIK_JSON_OBJ,
			   "config.put json-invalid.ctx");
	}
	aik_json_free(root);

	/* 5) 未知配置项 */
	root = call_json(port, "PUT", "/config",
			 "{\"values\":{\"nope.item\":\"1\"}}", &status, NULL);
	check_int(status, 200, "config.put unknown status");
	errors = root ? expect_ok_false(root, "config.put unknown") : NULL;
	if (errors) {
		check_str(aik_json_str(aik_json_get(errors, "nope.item")),
			  "未知的配置项", "config.put unknown.errors");
	}
	aik_json_free(root);

	/* 6) 非法值（字符串走 parse_value） */
	root = call_json(port, "PUT", "/config",
			 "{\"values\":{\"llm.max_tokens\":\"abc\"}}",
			 &status, NULL);
	check_int(status, 200, "config.put bad-value status");
	errors = root ? expect_ok_false(root, "config.put bad-value") : NULL;
	if (errors)
		check_str(aik_json_str(
				  aik_json_get(errors, "llm.max_tokens")),
			  "最大 token 必须是整数",
			  "config.put bad-value.errors");
	aik_json_free(root);

	/* 6b) 原生 JSON 走 validate_value（bool 当 int） */
	root = call_json(port, "PUT", "/config",
			 "{\"values\":{\"llm.max_tokens\":true}}", &status,
			 NULL);
	check_int(status, 200, "config.put bad-native status");
	errors = root ? expect_ok_false(root, "config.put bad-native") : NULL;
	if (errors)
		check_str(aik_json_str(
				  aik_json_get(errors, "llm.max_tokens")),
			  "应为整数", "config.put bad-native.errors");
	aik_json_free(root);

	/* 7) api_key 掩码 "******" 跳过（只有另一个值生效） */
	root = call_json(port, "PUT", "/config",
			 "{\"values\":{\"llm.api_key\":\"******\","
			 "\"retrieval.top_k\":\"10\"},\"save\":false}",
			 &status, NULL);
	check_int(status, 200, "config.put mask status");
	if (root)
		expect_applied_count(root, 1, cfg_path, "config.put mask");
	aik_json_free(root);

	/* 7b) 空串同样跳过；全部跳过 → applied 0 */
	root = call_json(port, "PUT", "/config",
			 "{\"values\":{\"llm.api_key\":\"\"}}", &status,
			 NULL);
	check_int(status, 200, "config.put mask-empty status");
	if (root)
		expect_applied_count(root, 0, cfg_path,
				     "config.put mask-empty");
	aik_json_free(root);

	/* 8) 成功应用（save=false）：值生效、source 仍为 file */
	root = call_json(port, "PUT", "/config",
			 "{\"values\":{\"retrieval.top_k\":12,"
			 "\"llm.temperature\":\"0.9\"},\"save\":false}",
			 &status, NULL);
	check_int(status, 200, "config.put apply status");
	if (root)
		expect_applied_count(root, 2, cfg_path, "config.put apply");
	aik_json_free(root);
	root = call_json(port, "GET", "/config", NULL, &status, NULL);
	check_int(status, 200, "config.put verify status");
	if (root) {
		groups = aik_json_get(root, "groups");

		check_str(aik_json_str(aik_json_get(root, "source")),
			  "file", "config.put verify source");
		check_true(payload_is_int(groups, "retrieval.top_k", 12),
			   "config.put verify retrieval.top_k");
		check_true(payload_is_num(groups, "llm.temperature", 0.9),
			   "config.put verify llm.temperature");
		check_true(payload_is_str(groups, "llm.api_key", ""),
			   "config.put verify llm.api_key untouched");
		check_true(aik_json_typeof(aik_json_get(
				   config_item_payload(groups,
						       "retrieval.top_k"),
				   "modified")) == AIK_JSON_BOOL &&
				   aik_json_bool(aik_json_get(
					   config_item_payload(
						   groups, "retrieval.top_k"),
					   "modified")) == 1,
			   "config.put verify retrieval.top_k.modified");
	}
	aik_json_free(root);

	/* 9) 顶层非对象 → 422 dict_type loc ["body"] */
	root = call_json(port, "PUT", "/config", "[]", &status, NULL);
	check_int(status, 422, "config.put body-type status");
	first = root ? first_detail(root, "config.put body-type") : NULL;
	if (first)
		check_true(loc_is(aik_json_get(first, "loc"), "body", NULL),
			   "config.put body-type.loc");
	aik_json_free(root);
}

/* LLM 已配置时的 /config/check（含 ping 的明确限制） */
static void test_config_check_llm(int port)
{
	int status = -1;
	aik_json *root;
	const aik_json *llm;
	const aik_json *groups;

	root = call_json(port, "PUT", "/config",
			 "{\"values\":{\"llm.base_url\":"
			 "\"http://127.0.0.1:9/v1\","
			 "\"llm.api_key\":\"sk-test\","
			 "\"llm.model\":\"m-test\"},\"save\":false}",
			 &status, NULL);
	check_int(status, 200, "config.put llm status");
	if (root)
		expect_applied_count(root, 3, NULL, "config.put llm");
	aik_json_free(root);

	root = call_json(port, "POST", "/config/check", "{\"ping\":false}",
			 &status, NULL);
	check_int(status, 200, "config.check llm status");
	if (root) {
		llm = aik_json_get(root, "llm");
		check_true(aik_json_typeof(aik_json_get(llm, "configured")) ==
				   AIK_JSON_BOOL &&
				   aik_json_bool(
					   aik_json_get(llm, "configured")) == 1,
			   "config.check llm.configured is not true");
		check_true(aik_json_typeof(aik_json_get(llm, "ok")) ==
				   AIK_JSON_BOOL &&
				   aik_json_bool(aik_json_get(llm, "ok")) == 1,
			   "config.check llm.ok is not true");
		check_str(aik_json_str(aik_json_get(llm, "detail")),
			  "LLM 已配置：http://127.0.0.1:9/v1 model=m-test "
			  "key=已填",
			  "config.check llm.detail");
	}
	aik_json_free(root);

	/* ping=true：C 版本没有 LLM HTTP 客户端 → ok=false + 明确文案 */
	root = call_json(port, "POST", "/config/check", "{\"ping\":true}",
			 &status, NULL);
	check_int(status, 200, "config.check ping status");
	if (root) {
		llm = aik_json_get(root, "llm");
		check_true(aik_json_typeof(aik_json_get(llm, "configured")) ==
				   AIK_JSON_BOOL &&
				   aik_json_bool(
					   aik_json_get(llm, "configured")) == 1,
			   "config.check ping llm.configured");
		check_true(aik_json_typeof(aik_json_get(llm, "ok")) ==
				   AIK_JSON_BOOL &&
				   aik_json_bool(aik_json_get(llm, "ok")) == 0,
			   "config.check ping llm.ok is not false");
		check_str(aik_json_str(aik_json_get(llm, "detail")),
			  "LLM 已配置：http://127.0.0.1:9/v1 model=m-test "
			  "key=已填；请求失败：C 版本未内置 LLM HTTP 客户端",
			  "config.check ping llm.detail");
	}
	aik_json_free(root);

	/* 密钥回显仍是掩码 + set:true */
	root = call_json(port, "GET", "/config", NULL, &status, NULL);
	check_int(status, 200, "config.get masked status");
	if (root) {
		groups = aik_json_get(root, "groups");
		check_true(payload_is_str(groups, "llm.api_key", "******"),
			   "config.get llm.api_key is not masked");
		check_true(aik_json_typeof(aik_json_get(
				   config_item_payload(groups,
						       "llm.api_key"),
				   "set")) == AIK_JSON_BOOL &&
				   aik_json_bool(aik_json_get(
					   config_item_payload(
						   groups, "llm.api_key"),
					   "set")) == 1,
			   "config.get llm.api_key.set is not true");
	}
	aik_json_free(root);
}

/* ------------------------------------------------------------------ */
/* POST /config/preset                                                */
/* ------------------------------------------------------------------ */
static void test_config_preset(int port, const char *cfg_path)
{
	int status = -1;
	aik_json *root;
	const aik_json *detail;
	const aik_json *applied;
	const aik_json *groups;
	const char *applied0;
	const char *applied_last;

	/* 未知 key → 400 */
	root = call_json(port, "POST", "/config/preset",
			 "{\"key\":\"nope\"}", &status, NULL);
	check_int(status, 400, "config.preset unknown status");
	if (root)
		check_str(aik_json_str(detail_of(root)),
			  "未知预设 key：nope（可选：chat、kb_dynamic、"
			  "kb_static、robot、minimal）",
			  "config.preset unknown detail");
	aik_json_free(root);

	/* 缺 key → 422 missing loc ["body","key"] */
	root = call_json(port, "POST", "/config/preset", "{}", &status, NULL);
	check_int(status, 422, "config.preset missing status");
	detail = root ? first_detail(root, "config.preset missing") : NULL;
	if (detail) {
		check_str(aik_json_str(aik_json_get(detail, "type")),
			  "missing", "config.preset missing.type");
		check_true(loc_is(aik_json_get(detail, "loc"), "body", "key"),
			   "config.preset missing.loc");
	}
	aik_json_free(root);

	/* save 非 bool → 422 bool_type */
	root = call_json(port, "POST", "/config/preset",
			 "{\"key\":\"minimal\",\"save\":1}", &status, NULL);
	check_int(status, 422, "config.preset save-type status");
	detail = root ? first_detail(root, "config.preset save-type") : NULL;
	if (detail)
		check_str(aik_json_str(aik_json_get(detail, "type")),
			  "bool_type", "config.preset save-type.type");
	aik_json_free(root);

	/* minimal（save 默认 true）：applied 为预设原序 17 项 */
	root = call_json(port, "POST", "/config/preset",
			 "{\"key\":\"minimal\"}", &status, NULL);
	check_int(status, 200, "config.preset minimal status");
	check_true(root != NULL, "config.preset minimal: body is not JSON");
	if (root) {
		static const char *const keys[] = { "ok", "applied" };
		const aik_json *ok = aik_json_get(root, "ok");

		check_keys(root, keys, 2, "config.preset minimal");
		check_true(aik_json_typeof(ok) == AIK_JSON_BOOL &&
				   aik_json_bool(ok) == 1,
			   "config.preset minimal ok is not true");
		applied = aik_json_get(root, "applied");
		check_true(aik_json_typeof(applied) == AIK_JSON_ARR,
			   "config.preset minimal applied is not an array");
		check_int((long long)aik_json_count(applied), 17,
			  "config.preset minimal applied count");
		applied0 = aik_json_str(aik_json_at(applied, 0));
		check_str(applied0, "policy.decay_enabled",
			  "config.preset minimal applied[0]");
		applied_last =
			aik_json_str(aik_json_at(applied, 16));
		check_str(applied_last, "namespaces.enabled",
			  "config.preset minimal applied[16]");
	}
	aik_json_free(root);

	root = call_json(port, "GET", "/config", NULL, &status, NULL);
	check_int(status, 200, "config.preset verify status");
	if (root) {
		groups = aik_json_get(root, "groups");

		check_str(aik_json_str(aik_json_get(root, "source")),
			  "file", "config.preset source");
		check_true(payload_is_bool(groups, "policy.decay_enabled", 0),
			   "config.preset policy.decay_enabled");
		check_true(payload_is_bool(groups, "region.auto_evolve", 0),
			   "config.preset region.auto_evolve");
		check_true(payload_is_num(groups, "retrieval.keyword_weight",
					  0.3),
			   "config.preset retrieval.keyword_weight");
		/*
		 * memory.* 是会话层项：不在 SMEConfig.to_dict()/from_dict()
		 * 的映射里，热重建后按参考语义回落到注册表默认（参考实现
		 * 同样如此）；preset 的值只落在配置文件里。
		 */
		check_true(payload_is_bool(groups, "memory.reinforce_on", 1),
			   "config.preset memory.reinforce_on (registry default)");
		check_true(payload_is_int(groups, "memory.consolidate_every", 8),
			   "config.preset memory.consolidate_every (registry default)");
	}
	aik_json_free(root);

	/* preset 的会话层值必须写进配置文件（save 默认 true） */
	{
		char perr[256];
		aik_json *filecfg = aik_config_load_file(cfg_path, perr,
							 sizeof(perr));
		const aik_config_item *it;
		const aik_json *v;

		check_true(filecfg != NULL,
			   "config.preset: cannot load saved config file");
		if (filecfg) {
			it = aik_config_item_find("memory.reinforce_on");
			v = it ? aik_config_item_get(filecfg, it) : NULL;
			check_true(aik_json_typeof(v) == AIK_JSON_BOOL &&
					   aik_json_bool(v) == 0,
				   "config.preset file memory.reinforce_on");
			it = aik_config_item_find("memory.consolidate_every");
			v = it ? aik_config_item_get(filecfg, it) : NULL;
			check_true(aik_json_typeof(v) == AIK_JSON_INT &&
					   aik_json_int(v) == 1000000000LL,
				   "config.preset file memory.consolidate_every");
		}
		aik_json_free(filecfg);
	}
}

/* ------------------------------------------------------------------ */
/* POST /config/reset                                                 */
/* ------------------------------------------------------------------ */
static void test_config_reset(int port, const char *cfg_path)
{
	int status = -1;
	aik_json *root;
	const aik_json *groups;

	check_true(access(cfg_path, F_OK) == 0,
		   "config.reset: preset should have written the file");
	root = call_json(port, "POST", "/config/reset", NULL, &status, NULL);
	check_int(status, 200, "config.reset status");
	if (root) {
		static const char *const keys[] = { "ok" };
		const aik_json *ok = aik_json_get(root, "ok");

		check_keys(root, keys, 1, "config.reset");
		check_true(aik_json_typeof(ok) == AIK_JSON_BOOL &&
				   aik_json_bool(ok) == 1,
			   "config.reset ok is not true");
	}
	aik_json_free(root);
	check_true(access(cfg_path, F_OK) != 0,
		   "config.reset: config file was not deleted");

	/* 回默认：source=defaults，groups 与默认向量逐字节一致 */
	root = call_json(port, "GET", "/config", NULL, &status, NULL);
	check_int(status, 200, "config.reset verify status");
	if (root) {
		groups = aik_json_get(root, "groups");

		check_str(aik_json_str(aik_json_get(root, "source")),
			  "defaults", "config.reset source");
		check_str(aik_json_str(aik_json_get(root, "config_file")),
			  cfg_path, "config.reset config_file");
		check_vector(groups, "groups_default.json",
			     "config.reset groups");
		check_true(payload_is_str(groups, "llm.base_url",
					  "https://api.openai.com/v1"),
			   "config.reset llm.base_url");
		check_true(payload_is_str(groups, "llm.api_key", ""),
			   "config.reset llm.api_key");
	}
	aik_json_free(root);

	/* 文件已不存在时再 reset 也成功（幂等） */
	root = call_json(port, "POST", "/config/reset", NULL, &status, NULL);
	check_int(status, 200, "config.reset again status");
	if (root)
		check_true(aik_json_typeof(aik_json_get(root, "ok")) ==
				   AIK_JSON_BOOL &&
				   aik_json_bool(aik_json_get(root, "ok")) == 1,
			   "config.reset again ok");
	aik_json_free(root);
}

/* ------------------------------------------------------------------ */
/* mrl_dim 闸门（非空库改 embedding 身份必须拒绝）                    */
/* ------------------------------------------------------------------ */
static void test_config_gate(int port)
{
	int status = -1;
	aik_json *root;
	const aik_json *errors;
	const aik_json *groups;
	const char *msg;
	long long before = -1;

	/* 基线 */
	root = call_json(port, "GET", "/health", NULL, &status, NULL);
	check_int(status, 200, "config.gate health status");
	if (root) {
		const aik_json *m = aik_json_get(root, "memories");

		if (aik_json_typeof(m) == AIK_JSON_INT)
			before = aik_json_int(m);
	}
	aik_json_free(root);
	check_true(before > 0, "config.gate: engine should hold memories");
	root = call_json(port, "GET", "/config", NULL, &status, NULL);
	check_int(status, 200, "config.gate get status");
	if (root) {
		groups = aik_json_get(root, "groups");

		check_true(payload_is_int(groups, "embedding.mrl_dim", 0),
			   "config.gate mrl_dim baseline");
	}
	aik_json_free(root);

	/* mrl_dim 0 → 32：旧库非空 → ok:false + 中文提示，引擎保持原配置 */
	root = call_json(port, "PUT", "/config",
			 "{\"values\":{\"embedding.mrl_dim\":32},"
			 "\"save\":false}",
			 &status, NULL);
	check_int(status, 200, "config.gate put status");
	errors = root ? expect_ok_false(root, "config.gate put") : NULL;
	if (errors) {
		msg = aik_json_str(aik_json_get(errors, "_global"));
		check_true(msg && strncmp(msg, "embedding 配置变更（",
					  strlen("embedding 配置变更（")) ==
				   0,
			   "config.gate _global prefix (got '%s')",
			   msg ? msg : "(null)");
		check_true(msg && strstr(msg, "mrl_dim 0→32") != NULL,
			   "config.gate _global should mention mrl_dim 0→32");
	}
	aik_json_free(root);

	/* 配置未改、引擎仍可检索 */
	root = call_json(port, "GET", "/config", NULL, &status, NULL);
	check_int(status, 200, "config.gate verify status");
	if (root) {
		const aik_json *p;

		groups = aik_json_get(root, "groups");
		check_true(payload_is_int(groups, "embedding.mrl_dim", 0),
			   "config.gate mrl_dim unchanged");
		p = config_item_payload(groups, "embedding.mrl_dim");
		check_true(aik_json_typeof(aik_json_get(p, "modified")) ==
				   AIK_JSON_BOOL &&
				   aik_json_bool(
					   aik_json_get(p, "modified")) == 0,
			   "config.gate mrl_dim.modified");
	}
	aik_json_free(root);
	root = call_json(port, "POST", "/memories/search",
			 "{\"text\":\"T4b 测试记忆\"}", &status, NULL);
	check_int(status, 200, "config.gate search status");
	if (root)
		check_true(aik_json_typeof(aik_json_get(root, "count")) ==
				   AIK_JSON_INT &&
				   aik_json_int(aik_json_get(root, "count")) >
					   0,
			   "config.gate search count");
	aik_json_free(root);

	/* 合法 PUT（save=false）：top_k 生效且记忆数不变 */
	root = call_json(port, "PUT", "/config",
			 "{\"values\":{\"retrieval.top_k\":7},"
			 "\"save\":false}",
			 &status, NULL);
	check_int(status, 200, "config.gate apply status");
	if (root)
		expect_applied_count(root, 1, NULL, "config.gate apply");
	aik_json_free(root);
	root = call_json(port, "GET", "/config", NULL, &status, NULL);
	check_int(status, 200, "config.gate apply verify status");
	if (root) {
		groups = aik_json_get(root, "groups");
		check_true(payload_is_int(groups, "retrieval.top_k", 7),
			   "config.gate top_k applied");
	}
	aik_json_free(root);
	root = call_json(port, "GET", "/health", NULL, &status, NULL);
	check_int(status, 200, "config.gate health2 status");
	if (root)
		check_int(aik_json_int(aik_json_get(root, "memories")),
			  before, "config.gate memories preserved");
	aik_json_free(root);
}

/* ------------------------------------------------------------------ */
/* POST /consolidate 与 POST /compress（形状）                        */
/* ------------------------------------------------------------------ */
static void test_dynamics_http(int port)
{
	static const char *const keys[] = { "created" };
	int status = -1;
	aik_json *root;

	root = call_json(port, "POST", "/consolidate", NULL, &status, NULL);
	check_int(status, 200, "dynamics consolidate status");
	if (root) {
		check_keys(root, keys, 1, "dynamics consolidate");
		check_true(aik_json_typeof(aik_json_get(root, "created")) ==
				   AIK_JSON_ARR,
			   "dynamics consolidate created is not an array");
	}
	aik_json_free(root);

	root = call_json(port, "POST", "/compress", NULL, &status, NULL);
	check_int(status, 200, "dynamics compress status");
	if (root) {
		check_keys(root, keys, 1, "dynamics compress");
		check_true(aik_json_typeof(aik_json_get(root, "created")) ==
				   AIK_JSON_ARR,
			   "dynamics compress created is not an array");
	}
	aik_json_free(root);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */
int main(void)
{
	char tmpdir[] = "/tmp/smehttp-test-XXXXXX";
	static const char *text =
		"T4b 测试记忆：苹果公司总部在库比蒂诺。";
	test_server srv;

	/* 配置中心用例与宿主环境无关：清掉可能影响默认配置的 SME_* */
	clear_sme_env();
	if (!mkdtemp(tmpdir)) {
		fprintf(stderr, "test_http: mkdtemp: %s\n", strerror(errno));
		return 1;
	}
	test_config_groups_mutated();
	if (start_server(&srv, tmpdir, "plain", "") != 0) {
		fprintf(stderr, "test_http: cannot start server (plain)\n");
		return 1;
	}
	test_health(srv.port);
	test_add_valid(srv.port, text);
	test_blank_text(srv.port);
	test_missing_text(srv.port);
	test_get_missing(srv.port);
	test_search(srv.port, text);
	test_unknown_route(srv.port);
	test_patch(srv.port);
	test_delete(srv.port);
	test_archive_restore(srv.port);
	test_regions_search(srv.port);
	test_evolve(srv.port);
	test_graph(srv.port);
	test_modules(srv.port);
	test_config_gate(srv.port);
	test_dynamics_http(srv.port);
	check_true(stop_server(&srv) == 0,
		   "plain server did not exit 0 on SIGTERM");

	/* 默认配置来源：GET /config 向量 + PUT/check/preset/reset */
	if (start_server_defaults(&srv, tmpdir) != 0) {
		fprintf(stderr, "test_http: cannot start server (defaults)\n");
		return 1;
	}
	test_config_get_defaults(srv.port, srv.cfg_path);
	test_config_check_defaults(srv.port);
	test_config_put(srv.port, srv.cfg_path);
	test_config_check_llm(srv.port);
	test_config_preset(srv.port, srv.cfg_path);
	test_config_reset(srv.port, srv.cfg_path);
	check_true(stop_server(&srv) == 0,
		   "defaults server did not exit 0 on SIGTERM");

	if (start_server(&srv, tmpdir, "auth", "secret") != 0) {
		fprintf(stderr, "test_http: cannot start server (auth)\n");
		return 1;
	}
	test_auth(srv.port);
	check_true(stop_server(&srv) == 0,
		   "auth server did not exit 0 on SIGTERM");

	(void)unlink(srv.cfg_path);
	(void)unlink(srv.db_path);
	(void)rmdir(tmpdir);

	printf("SUMMARY http checks=%zu mismatches=%zu\n", checks, mismatches);
	return mismatches ? 1 : 0;
}
