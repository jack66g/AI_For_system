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
 * 临时配置写进 mkdtemp：storage.path=<tmp>/engine-*.json.gz、autosave=false、
 * persistence.enabled=false、api.auth_token 按用例设置。服务器 SIGTERM 必须
 * 干净退出（0）。
 */
#define _POSIX_C_SOURCE 200809L

#include "smehttp/http.h"

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
/* main                                                               */
/* ------------------------------------------------------------------ */
int main(void)
{
	char tmpdir[] = "/tmp/smehttp-test-XXXXXX";
	static const char *text =
		"T4b 测试记忆：苹果公司总部在库比蒂诺。";
	test_server srv;

	if (!mkdtemp(tmpdir)) {
		fprintf(stderr, "test_http: mkdtemp: %s\n", strerror(errno));
		return 1;
	}
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
	check_true(stop_server(&srv) == 0,
		   "plain server did not exit 0 on SIGTERM");

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
