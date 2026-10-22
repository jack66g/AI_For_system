// SPDX-License-Identifier: GPL-2.0
/*
 * test_trace.c - W48B 轨迹日志回归
 *
 * 覆盖：
 *   1. 配置加载/默认值/目录创建；
 *   2. 全部事件类型落盘、逐行 JSON 合法、头字段齐全、event_seq/时间单调；
 *   3. 脱敏：sk- / Bearer / api_key= / token= 假密钥断言不落盘；
 *   4. 单字段截断（max_payload_kb）与 result_truncated 标记；
 *   5. 轮转：max_file_mb/max_files 生效；
 *   6. 8 线程并发写不交错（每行可解析、seq 唯一）；
 *   7. 打开失败降级（不崩溃、is_enabled=0、事件静默丢弃）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>

#include "ai_trace.h"
#include "ai_types.h"
#include "ai_json_util.h"

static int g_assertions;
static int g_failures;

#define CHECK(cond) do { \
	g_assertions++; \
	if (!(cond)) { \
		g_failures++; \
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
	} \
} while (0)

static void write_text(const char *path, const char *text)
{
	FILE *fp = fopen(path, "w");

	if (!fp)
		return;
	fputs(text, fp);
	fclose(fp);
}

static int count_files(const char *dir, const char *needle)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	int n = 0;

	if (!d)
		return -1;
	while ((de = readdir(d)) != NULL) {
		if (strstr(de->d_name, needle) && strstr(de->d_name, ".jsonl"))
			n++;
	}
	closedir(d);
	return n;
}

static int cmp_names(const void *a, const void *b)
{
	const char *const *sa = a;
	const char *const *sb = b;

	return strcmp(*sa, *sb);
}

/* 读取目录内全部 .jsonl 文件，按文件名排序拼接 */
static char *slurp_dir(const char *dir, size_t *out_len)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	char **names = NULL;
	int n = 0;
	int cap = 0;
	int i;
	char *buf = NULL;
	size_t len = 0;
	size_t bcap = 0;

	if (!d)
		return NULL;
	while ((de = readdir(d)) != NULL) {
		if (!strstr(de->d_name, "trace-") ||
		    !strstr(de->d_name, ".jsonl"))
			continue;
		if (n == cap) {
			int nc = cap ? cap * 2 : 16;
			char **nn = realloc(names, sizeof(char *) * (size_t)nc);

			if (!nn)
				break;
			names = nn;
			cap = nc;
		}
		names[n++] = strdup(de->d_name);
	}
	closedir(d);
	qsort(names, (size_t)n, sizeof(char *), cmp_names);
	for (i = 0; i < n; i++) {
		char path[4096];
		FILE *fp;
		char tmp[8192];
		size_t r;

		snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
		fp = fopen(path, "r");
		if (!fp)
			continue;
		while ((r = fread(tmp, 1, sizeof(tmp), fp)) > 0) {
			if (len + r + 1 > bcap) {
				size_t nc = (len + r + 1) * 2;
				char *nb = realloc(buf, nc);

				if (!nb) {
					r = 0;
					break;
				}
				buf = nb;
				bcap = nc;
			}
			memcpy(buf + len, tmp, r);
			len += r;
		}
		fclose(fp);
	}
	for (i = 0; i < n; i++)
		free(names[i]);
	free(names);
	if (!buf) {
		buf = malloc(1);
		if (buf)
			buf[0] = '\0';
	} else {
		buf[len] = '\0';
	}
	if (out_len)
		*out_len = len;
	return buf;
}

/* 一行是否为合法 JSON 对象 */
static int line_is_json(const char *line, size_t len)
{
	const char *p = line;
	const char *end = line + len;
	const char *tok = NULL;
	size_t tlen = 0;
	int type = 0;

	p = ai_json_skip_ws(p, end);
	if (p >= end)
		return 0;
	if (ai_json_scan_value(&p, end, &tok, &tlen, &type) != 0)
		return 0;
	p = ai_json_skip_ws(p, end);
	if (p != end)
		return 0;
	return type == AI_JSON_OBJ;
}

static int line_get_int(const char *line, size_t len, const char *key,
			long long *out)
{
	const char *p = line;
	const char *end = line + len;
	const char *tok = NULL;
	size_t tlen = 0;
	const char *v = NULL;
	size_t vl = 0;
	int type = 0;

	if (ai_json_scan_value(&p, end, &tok, &tlen, &type) != 0 ||
	    type != AI_JSON_OBJ)
		return 0;
	if (ai_json_obj_get(tok, tlen, key, &v, &vl, &type) != 1 ||
	    type != AI_JSON_NUM)
		return 0;
	*out = ai_json_ll(v, vl);
	return 1;
}

static char *line_get_str(const char *line, size_t len, const char *key)
{
	const char *p = line;
	const char *end = line + len;
	const char *tok = NULL;
	size_t tlen = 0;
	const char *v = NULL;
	size_t vl = 0;
	int type = 0;

	if (ai_json_scan_value(&p, end, &tok, &tlen, &type) != 0 ||
	    type != AI_JSON_OBJ)
		return NULL;
	if (ai_json_obj_get(tok, tlen, key, &v, &vl, &type) != 1 ||
	    type != AI_JSON_STR)
		return NULL;
	return ai_json_strdup_str(v, vl);
}

struct scan_state {
	long long seq;
	long long mono;
	char ts[64];
	int first;
	int bad_json;
	int bad_header;
	int bad_mono;
	int bad_seq;
	int bad_ts;
	int events;
};

static void scan_lines(char *buf, struct scan_state *st)
{
	char *p = buf;
	char *nl;

	memset(st, 0, sizeof(*st));
	st->first = 1;
	while (p && *p) {
		char saved;
		nl = strchr(p, '\n');
		if (nl) {
			saved = *nl;
			*nl = '\0';
		} else {
			saved = '\0';
		}
		{
			size_t len = strlen(p);
			long long seq = 0;
			long long mono = 0;
			char *ts = NULL;
			char *sid = NULL;
			char *ev = NULL;

			if (!line_is_json(p, len)) {
				st->bad_json++;
				if (st->bad_json <= 3)
					fprintf(stderr,
						"BAD JSON line: %.200s\n", p);
			} else {
				st->events++;
				if (!line_get_int(p, len, "event_seq", &seq) ||
				    !line_get_int(p, len, "mono_ms", &mono) ||
				    !(ts = line_get_str(p, len, "ts")) ||
				    !(sid = line_get_str(p, len, "session_id")) ||
				    !(ev = line_get_str(p, len, "event")))
					st->bad_header++;
				if (sid && !sid[0])
					st->bad_header++;
				if (ev && !ev[0])
					st->bad_header++;
				if (!st->first) {
					if (mono < st->mono)
						st->bad_mono++;
					if (seq <= st->seq)
						st->bad_seq++;
					if (ts && strcmp(ts, st->ts) < 0)
						st->bad_ts++;
				}
				if (seq > st->seq)
					st->seq = seq;
				if (mono > st->mono)
					st->mono = mono;
				if (ts)
					snprintf(st->ts, sizeof(st->ts), "%s", ts);
				st->first = 0;
			}
			free(ts);
			free(sid);
			free(ev);
		}
		if (!nl)
			break;
		if (saved)
			*nl = saved;
		p = nl + 1;
	}
}

static int count_substr(const char *hay, const char *needle)
{
	int n = 0;
	size_t nl = strlen(needle);
	const char *p = hay;

	while ((p = strstr(p, needle)) != NULL) {
		n++;
		p += nl;
	}
	return n;
}

/* ---- 并发写 ---- */
struct thr_arg {
	int id;
	int n;
};

static void *thr_emit(void *ud)
{
	struct thr_arg *a = ud;
	int i;

	for (i = 0; i < a->n; i++) {
		char res[128];

		snprintf(res, sizeof(res), "thread-%d-event-%d: OK", a->id, i);
		ai_trace_tool_call("exec_run", "exec", "R", "{\"command\":\"echo\"}",
				   ai_trace_wall_ms(), 1, 1, 0, res,
				   strlen(res));
	}
	return NULL;
}

static void make_config(const char *root, const char *name, int max_mb,
			int max_files, char *path, size_t n)
{
	char body[1024];

	snprintf(path, n, "%s/%s.toml", root, name);
	snprintf(body, sizeof(body),
		 "[trace]\nenabled = true\n"
		 "dir = \"%s/%s\"\n"
		 "max_file_mb = %d\nmax_files = %d\n"
		 "include_model_text = true\nmax_payload_kb = 64\n",
		 root, name, max_mb, max_files);
	write_text(path, body);
}

int main(void)
{
	char tmpl[] = "/tmp/aik-trace-test-XXXXXX";
	char *root = mkdtemp(tmpl);
	char cfg_path[1024];
	char dir[1024];
	struct ai_trace_config cfg;
	char *buf;
	size_t blen;
	struct scan_state st;
	struct ai_chat_msg msgs[2];
	struct ai_tool_call tcs[1];
	struct ai_chat_result res;
	char tools_json[] =
		"[{\"type\":\"function\",\"function\":{\"name\":\"exec_run\"}},"
		"{\"type\":\"function\",\"function\":{\"name\":\"memory_search\"}}]";
	char *rid;
	char *longres;
	size_t longlen;
	int i;

	if (!root) {
		fprintf(stderr, "mkdtemp failed\n");
		return 1;
	}
	make_config(root, "main", 64, 20, cfg_path, sizeof(cfg_path));
	snprintf(dir, sizeof(dir), "%s/main", root);

	/* 1. 配置/init */
	CHECK(ai_trace_load_config(cfg_path, &cfg) == AI_OK);
	CHECK(cfg.enabled == 1);
	CHECK(cfg.max_file_mb == 64);
	CHECK(cfg.max_files == 20);
	CHECK(cfg.include_model_text == 1);
	CHECK(cfg.max_payload_kb == 64);
	CHECK(strstr(cfg.dir, "/main") != NULL);
	ai_trace_config_free(&cfg);
	CHECK(ai_trace_init(cfg_path, 0) == AI_OK);
	CHECK(ai_trace_is_enabled() == 1);

	/* 2. 全事件类型 */
	CHECK(ai_trace_session_start("default", "mock-model",
				     "openai_compatible", 8192, 1024, 0,
				     "autonomous", "0123456789abcdef") == 1);
	CHECK(ai_trace_session_start("default", "mock-model",
				     "openai_compatible", 8192, 1024, 0,
				     "autonomous", "0123456789abcdef") == 0);
	CHECK(ai_trace_turn_start("请执行 uname 并总结") == 1);

	memset(msgs, 0, sizeof(msgs));
	msgs[0].role = "system";
	msgs[0].content = "system prompt for trace test";
	msgs[1].role = "user";
	msgs[1].content = "my fake key is sk-ABCDEFGHIJKLMNOPQRSTUVWX and Bearer abc.def-ghi";
	rid = ai_trace_model_request("openai_compatible", "mock-model", msgs, 2,
				     tools_json, 0);
	CHECK(rid != NULL);
	CHECK(rid && strncmp(rid, "req-", 4) == 0);

	memset(&res, 0, sizeof(res));
	res.content = "done api_key=SECRETVALUE123 token=\"tok-ABCDEFGHIJKLMNOP\"";
	res.tool_calls = tcs;
	res.tool_call_count = 1;
	res.finish_reason = "tool_calls";
	res.http_status = 200;
	res.prompt_tokens = 100;
	res.completion_tokens = 20;
	tcs[0].id = "call_1";
	tcs[0].name = "exec_run";
	tcs[0].arguments = "{\"command\":\"uname\",\"password\":\"PASSWORDVALUE\"}";
	CHECK(ai_trace_model_response(rid, &res, 123) == 0);
	free(rid);

	{
		const char *hit[1] = { "exec_run" };

		CHECK(ai_trace_route_activate("memory_search", hit, 1, 5, 6) == 0);
	}

	longlen = 100 * 1024;
	longres = malloc(longlen + 1);
	CHECK(longres != NULL);
	if (longres) {
		memset(longres, 'A', longlen);
		longres[longlen] = '\0';
		memcpy(longres, "Bearer TOKENVALUE.ABC-123 ", 26);
		CHECK(ai_trace_tool_call("exec_run", "exec", "R",
					 "{\"command\":\"uname\",\"token\":\"ARGTOKENVALUE\"}",
					 ai_trace_wall_ms(), 5, 1, 0,
					 longres, longlen) == 0);
		free(longres);
	}
	CHECK(ai_trace_tool_call("procfs_read_status", "procfs-read", "R",
				 "{}", ai_trace_wall_ms(), 1, 0, -1,
				 "ENOENT: /proc/ai/status", 22) == 0);
	CHECK(ai_trace_policy_decision("W2", "DENY", "user_refused",
				       "exec_run", "interactive", "{}") == 0);
	CHECK(ai_trace_degraded("sme", "unavailable",
				"SME 127.0.0.1:8000 unreachable") == 0);
	CHECK(ai_trace_error("model_request", "AI_ERR_NETWORK",
			     "cannot connect") == 0);
	CHECK(ai_trace_turn_end("completed", 2) == 0);
	CHECK(ai_trace_session_end("test_exit") == 0);
	CHECK(ai_trace_event_count() >= 10);
	ai_trace_shutdown();

	/* 3. 逐行 JSON + 头字段 + 单调性 + 脱敏 + 截断 */
	buf = slurp_dir(dir, &blen);
	CHECK(buf != NULL);
	CHECK(blen > 0);
	scan_lines(buf, &st);
	CHECK(st.bad_json == 0);
	CHECK(st.bad_header == 0);
	CHECK(st.bad_mono == 0);
	CHECK(st.bad_seq == 0);
	CHECK(st.bad_ts == 0);
	CHECK(st.events >= 10);
	CHECK(count_substr(buf, "\"event\":\"session_start\"") == 1);
	CHECK(count_substr(buf, "\"event\":\"session_end\"") == 1);
	CHECK(count_substr(buf, "\"event\":\"turn_start\"") == 1);
	CHECK(count_substr(buf, "\"event\":\"turn_end\"") == 1);
	CHECK(count_substr(buf, "\"event\":\"model_request\"") == 1);
	CHECK(count_substr(buf, "\"event\":\"model_response\"") == 1);
	CHECK(count_substr(buf, "\"event\":\"route_activate\"") == 1);
	CHECK(count_substr(buf, "\"event\":\"tool_call\"") == 2);
	CHECK(count_substr(buf, "\"event\":\"policy_decision\"") == 1);
	CHECK(count_substr(buf, "\"event\":\"degraded\"") == 1);
	CHECK(count_substr(buf, "\"event\":\"error\"") == 1);

	CHECK(strstr(buf, "sk-ABCDEFGHIJKLMNOPQRSTUVWX") == NULL);
	CHECK(strstr(buf, "SECRETVALUE123") == NULL);
	CHECK(strstr(buf, "tok-ABCDEFGHIJKLMNOP") == NULL);
	CHECK(strstr(buf, "PASSWORDVALUE") == NULL);
	CHECK(strstr(buf, "ARGTOKENVALUE") == NULL);
	CHECK(strstr(buf, "TOKENVALUE.ABC-123") == NULL);
	CHECK(strstr(buf, "abc.def-ghi") == NULL);
	CHECK(strstr(buf, "***") != NULL);
	CHECK(strstr(buf, "\"result_truncated\":true") != NULL);
	CHECK(strstr(buf, "\"result_bytes\":102400") != NULL);
	free(buf);

	/* 4. 轮转 */
	make_config(root, "rot", 1, 3, cfg_path, sizeof(cfg_path));
	snprintf(dir, sizeof(dir), "%s/rot", root);
	CHECK(ai_trace_init(cfg_path, 0) == AI_OK);
	CHECK(ai_trace_session_start("rot", "m", "p", 1, 1, 0, "-", "h") == 1);
	longres = malloc(64 * 1024 + 1);
	CHECK(longres != NULL);
	if (longres) {
		memset(longres, 'R', 64 * 1024);
		longres[64 * 1024] = '\0';
		for (i = 0; i < 60; i++) {
			ai_trace_tool_call("exec_run", "exec", "R", "{}",
					   ai_trace_wall_ms(), 1, 1, 0,
					   longres, 64 * 1024);
		}
		free(longres);
	}
	ai_trace_session_end("rot_done");
	ai_trace_shutdown();
	CHECK(count_files(dir, "trace-") == 3);
	CHECK(count_files(dir, ".1.jsonl") == 1);
	CHECK(count_files(dir, ".2.jsonl") == 1);
	CHECK(count_files(dir, ".3.jsonl") == 0);

	/* 5. 并发写不交错 */
	make_config(root, "conc", 64, 20, cfg_path, sizeof(cfg_path));
	snprintf(dir, sizeof(dir), "%s/conc", root);
	CHECK(ai_trace_init(cfg_path, 0) == AI_OK);
	CHECK(ai_trace_session_start("conc", "m", "p", 1, 1, 0, "-", "h") == 1);
	{
		pthread_t th[8];
		struct thr_arg args[8];

		for (i = 0; i < 8; i++) {
			args[i].id = i;
			args[i].n = 25;
			pthread_create(&th[i], NULL, thr_emit, &args[i]);
		}
		for (i = 0; i < 8; i++)
			pthread_join(th[i], NULL);
	}
	ai_trace_session_end("conc_done");
	ai_trace_shutdown();
	buf = slurp_dir(dir, &blen);
	CHECK(buf != NULL);
	scan_lines(buf, &st);
	CHECK(st.bad_json == 0);
	CHECK(st.bad_header == 0);
	CHECK(st.bad_seq == 0);
	CHECK(st.bad_mono == 0);
	CHECK(st.events == 202);   /* session_start + 200 tool_call + session_end */
	free(buf);

	/* 6. 打开失败降级 */
	{
		char badcfg[1024];
		char body[1024];

		snprintf(badcfg, sizeof(badcfg), "%s/bad.toml", root);
		snprintf(body, sizeof(body),
			 "[trace]\nenabled = true\ndir = \"/proc/aik-trace-nope\"\n");
		write_text(badcfg, body);
		memset(&cfg, 0, sizeof(cfg));
		CHECK(ai_trace_init(badcfg, 0) == AI_ERR_STORAGE);
		CHECK(ai_trace_is_enabled() == 0);
		CHECK(ai_trace_session_start("x", "m", "p", 1, 1, 0, "-", "h") == -1);
		CHECK(ai_trace_tool_call("t", "c", "R", "{}", 0, 0, 1, 0,
					 "x", 1) == -1);
		ai_trace_shutdown();
	}

	/* 7. 强制禁用 */
	make_config(root, "off", 64, 20, cfg_path, sizeof(cfg_path));
	CHECK(ai_trace_init(cfg_path, AI_TRACE_FLAG_DISABLE) == AI_OK);
	CHECK(ai_trace_is_enabled() == 0);
	ai_trace_shutdown();

	/* 清理 */
	if (!getenv("KEEP_TRACE_TEST")) {
		char cmd[1200];

		snprintf(cmd, sizeof(cmd), "rm -rf '%s'", root);
		if (system(cmd) != 0)
			fprintf(stderr, "cleanup warning\n");
	} else {
		fprintf(stderr, "test dir kept: %s\n", root);
	}
	printf("test_trace: %d assertions, %d failures\n", g_assertions,
	       g_failures);
	return g_failures ? 1 : 0;
}
