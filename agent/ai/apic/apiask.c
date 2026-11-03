/* SPDX-License-Identifier: GPL-2.0 */
/*
 * apiask.c - T7b /ask /clarify(参考 _do_ask/_do_clarify/_run_ai/ai_env/
 * parse_tagged_event/validate_clarify_event/render_clarify_answer/
 * read_pending/normalize_selection/session_lock)。
 *
 * 关键语义:
 *   - 问题经 AIKERNEL_PROMPT 传给 `ai -p -`(绝不进 argv/stdin);
 *   - 子进程 stdin=/dev/null、stdout/stderr 全捕获、超时杀;
 *   - detail=stderr 尾 400 码点;answer=stdout.strip();
 *   - 事件只认 "AIKERNEL_EVENT <tag> " 前缀行;多行/坏 JSON=协议错误;
 *   - pending 只读探针(O_NOFOLLOW/0600/64KiB/CLARIFY_PENDING v1);
 *   - 同 session 串行(锁表 256,LRU 驱逐)。
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "apic/api.h"
#include "desktop/dtcore.h"
#include "desktop/dtjson.h"

int api_auth_check(struct api_http_req *req, struct api_http_resp *resp);

/* ---------------- 小工具 ---------------- */
static int is_str(const aik_json *v)
{
	return v && aik_json_typeof(v) == AIK_JSON_STR;
}

static int str_nonblank(const char *s)
{
	char *t = dt_strip(s ? s : "");
	int r = *t != '\0';

	free(t);
	return r;
}

/* stderr 尾 400 码点(malloc) */
static char *err_tail400(const char *s, size_t n)
{
	(void)n;
	return dt_utf8_tail(s ? s : "", 400);
}

static int body_has(const char *s, size_t n, const char *needle)
{
	return s && n && memmem(s, n, needle, strlen(needle)) != NULL;
}

/* ---------------- session 锁表(OrderedDict LRU 近似) ---------------- */
struct sess_entry {
	char name[128];
	pthread_mutex_t mu;
	int inited;
	int busy;
};

static struct sess_entry g_locks[API_SESSION_LOCK_MAX];
static pthread_mutex_t g_locks_guard = PTHREAD_MUTEX_INITIALIZER;
static int g_locks_used = 0;

static pthread_mutex_t *session_lock(const char *session)
{
	pthread_mutex_t *ret = NULL;
	int i;

	pthread_mutex_lock(&g_locks_guard);
	for (i = 0; i < g_locks_used; i++) {
		if (strcmp(g_locks[i].name, session) == 0) {
			if (i + 1 < g_locks_used) {
				struct sess_entry tmp = g_locks[i];

				memmove(&g_locks[i], &g_locks[i + 1],
					sizeof(struct sess_entry) *
						(size_t)(g_locks_used - i - 1));
				g_locks[g_locks_used - 1] = tmp;
				i = g_locks_used - 1;
			}
			ret = &g_locks[i].mu;
			goto out;
		}
	}
	if (g_locks_used >= API_SESSION_LOCK_MAX) {
		for (i = 0; i < g_locks_used; i++) {
			if (strcmp(g_locks[i].name, session) != 0 &&
			    !g_locks[i].busy) {
				memmove(&g_locks[i], &g_locks[i + 1],
					sizeof(struct sess_entry) *
						(size_t)(g_locks_used - i - 1));
				g_locks_used--;
				break;
			}
		}
	}
	if (g_locks_used < API_SESSION_LOCK_MAX) {
		struct sess_entry *e = &g_locks[g_locks_used];

		snprintf(e->name, sizeof(e->name), "%s", session);
		if (!e->inited) {
			pthread_mutex_init(&e->mu, NULL);
			e->inited = 1;
		}
		e->busy = 0;
		g_locks_used++;
		ret = &e->mu;
	}
out:
	pthread_mutex_unlock(&g_locks_guard);
	return ret;
}

static int lock_acquire_timeout(pthread_mutex_t *mu, long long timeout_s)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += (time_t)timeout_s;
	return pthread_mutex_timedlock(mu, &ts) == 0 ? 0 : -1;
}

/* ---------------- ai 子进程 ---------------- */
static char g_toml_env_default[API_CFG_PATH + 32];
static pthread_once_t g_toml_env_once = PTHREAD_ONCE_INIT;

static void toml_env_init(void)
{
	snprintf(g_toml_env_default, sizeof(g_toml_env_default),
		 "AIKERNEL_TOOLS_JSON=%.8000s", g_api.tools_json);
}

static char **build_child_env(const char *extra_env_kv[])
{
	extern char **environ;
	size_t n = 0, i, k = 0, d;
	char **out;
	int has_home = 0, has_term = 0, has_tools = 0;
	static const char *drop[] = { "AIKERNEL_ASSUME_YES=",
				      "AIKERNEL_CONFIRM_NONCE=",
				      "AIKERNEL_EVENT_TAG=",
				      "AIKERNEL_PROMPT=",
				      "AIKERNEL_CLARIFY_SELECT=",
				      "AIKERNEL_CLARIFY_OTHER=" };

	pthread_once(&g_toml_env_once, toml_env_init);
	while (environ && environ[n])
		n++;
	out = malloc((n + 8 + 1) * sizeof(char *));
	if (!out)
		return NULL;
	for (i = 0; i < n; i++) {
		int skip = 0;
		size_t dl;

		for (d = 0; d < sizeof(drop) / sizeof(drop[0]); d++) {
			dl = strlen(drop[d]);
			if (strncmp(environ[i], drop[d], dl) == 0) {
				skip = 1;
				break;
			}
		}
		if (skip)
			continue;
		if (strncmp(environ[i], "HOME=", 5) == 0)
			has_home = 1;
		if (strncmp(environ[i], "TERM=", 5) == 0)
			has_term = 1;
		if (strncmp(environ[i], "AIKERNEL_TOOLS_JSON=", 20) == 0)
			has_tools = 1;
		out[k++] = environ[i];
	}
	if (!has_home)
		out[k++] = (char *)"HOME=/root";
	if (!has_term)
		out[k++] = (char *)"TERM=xterm";
	if (!has_tools)
		out[k++] = g_toml_env_default;
	for (i = 0; extra_env_kv && extra_env_kv[i]; i++) {
		if (extra_env_kv[i][0])
			out[k++] = (char *)extra_env_kv[i];
	}
	out[k] = NULL;
	return out;
}

static void sbuf_read_all(int fd, struct dt_sbuf *sb)
{
	char chunk[16384];

	for (;;) {
		ssize_t n = read(fd, chunk, sizeof(chunk));

		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0)
			break;
		dt_sb_puts(sb, chunk, (size_t)n);
	}
}

/* 返回:0=完成(*rc_out);1=超时;2=exec ENOENT;-1=其它 io 错 */
int api_run_ai(char *const argv[], const char *extra_env_kv[],
	       long long timeout_s, char **stdout_out, size_t *stdout_len,
	       char **stderr_out, size_t *stderr_len, int *rc_out)
{
	int outp[2], errp[2], execp[2];
	pid_t pid;
	char **envp;
	struct dt_sbuf so, se;
	long long deadline_ms;
	int status = 0;
	int exec_err = 0;
	ssize_t er;

	*stdout_out = NULL;
	*stderr_out = NULL;
	*stdout_len = 0;
	*stderr_len = 0;
	if (pipe(outp) != 0)
		return -1;
	if (pipe(errp) != 0) {
		close(outp[0]);
		close(outp[1]);
		return -1;
	}
	if (pipe(execp) != 0) {
		close(outp[0]);
		close(outp[1]);
		close(errp[0]);
		close(errp[1]);
		return -1;
	}
	(void)fcntl(execp[1], F_SETFD, FD_CLOEXEC);
	envp = build_child_env(extra_env_kv);
	if (!envp)
		return -1;
	pid = fork();
	if (pid < 0) {
		free(envp);
		close(outp[0]);
		close(outp[1]);
		close(errp[0]);
		close(errp[1]);
		close(execp[0]);
		close(execp[1]);
		return -1;
	}
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDONLY);

		(void)signal(SIGPIPE, SIG_DFL);
		if (devnull >= 0) {
			dup2(devnull, 0);
			close(devnull);
		}
		dup2(outp[1], 1);
		dup2(errp[1], 2);
		close(outp[0]);
		close(outp[1]);
		close(errp[0]);
		close(errp[1]);
		close(execp[0]);
		execve(argv[0], (char *const *)argv, envp);
		{
			int e = errno;

			(void)api_write_discard(execp[1], &e, sizeof(e));
		}
		_exit(127);
	}
	free(envp);
	close(outp[1]);
	close(errp[1]);
	close(execp[1]);
	dt_sb_init(&so);
	dt_sb_init(&se);
	deadline_ms = (long long)time(NULL) * 1000 + timeout_s * 1000;
	for (;;) {
		struct pollfd pfd[2];
		int nready;
		pid_t r;

		pfd[0].fd = outp[0];
		pfd[0].events = POLLIN;
		pfd[1].fd = errp[0];
		pfd[1].events = POLLIN;
		nready = poll(pfd, 2, 100);
		if (nready > 0) {
			if (pfd[0].revents & POLLIN)
				sbuf_read_all(outp[0], &so);
			if (pfd[1].revents & POLLIN)
				sbuf_read_all(errp[0], &se);
		}
		r = waitpid(pid, &status, WNOHANG);
		if (r == pid) {
			sbuf_read_all(outp[0], &so);
			sbuf_read_all(errp[0], &se);
			break;
		}
		if (r < 0 && errno != EINTR)
			break;
		if ((long long)time(NULL) * 1000 > deadline_ms) {
			kill(pid, SIGKILL);
			(void)waitpid(pid, &status, 0);
			close(outp[0]);
			close(errp[0]);
			er = read(execp[0], &exec_err, sizeof(exec_err));
			(void)er;
			close(execp[0]);
			free(dt_sb_finish(&so));
			free(dt_sb_finish(&se));
			return 1;
		}
	}
	close(outp[0]);
	close(errp[0]);
	er = read(execp[0], &exec_err, sizeof(exec_err));
	close(execp[0]);
	if (er == (ssize_t)sizeof(exec_err) && exec_err == ENOENT) {
		free(dt_sb_finish(&so));
		free(dt_sb_finish(&se));
		return 2;
	}
	if (WIFEXITED(status))
		*rc_out = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		*rc_out = -WTERMSIG(status);
	else
		*rc_out = 0;
	*stdout_out = dt_sb_finish(&so);
	*stderr_out = dt_sb_finish(&se);
	*stdout_len = so.n;
	*stderr_len = se.n;
	return 0;
}

/* ---------------- 事件通道 ---------------- */
int api_parse_tagged_event(const char *stderr_text, size_t len,
			   const char *tag, aik_json **ev_out,
			   const char **err_out)
{
	char prefix[128];
	struct dt_sbuf sb;
	char *text;
	char *p;
	size_t nhits = 0;
	aik_json *hit = NULL;
	size_t plen;

	*ev_out = NULL;
	*err_out = NULL;
	if (!tag || !*tag) {
		*err_out = "missing_tag";
		return 0;
	}
	snprintf(prefix, sizeof(prefix), "%s %s ", API_EVENT_PREFIX, tag);
	plen = strlen(prefix);
	sb = (struct dt_sbuf){ 0 };
	dt_sb_init(&sb);
	dt_sb_puts(&sb, stderr_text ? stderr_text : "", len);
	text = dt_sb_finish(&sb);
	if (!text)
		return 0;
	p = text;
	while (p && *p) {
		char *nl = strchr(p, '\n');
		size_t linelen = nl ? (size_t)(nl - p) : strlen(p);

		if (linelen >= plen && strncmp(p, prefix, plen) == 0) {
			char *raw = malloc(linelen - plen + 1);
			char *rs;
			aik_json *obj;

			if (!raw)
				break;
			memcpy(raw, p + plen, linelen - plen);
			raw[linelen - plen] = '\0';
			rs = dt_strip(raw);
			obj = dt_parse(rs, strlen(rs));
			free(raw);
			free(rs);
			if (!obj) {
				free(text);
				*err_out = "invalid_event_json";
				return 0;
			}
			nhits++;
			aik_json_free(hit);
			hit = obj;
		}
		p = nl ? nl + 1 : NULL;
	}
	free(text);
	if (nhits == 0)
		return 0;
	if (nhits > 1) {
		aik_json_free(hit);
		*err_out = "multiple_events";
		return 0;
	}
	*ev_out = hit;
	return 0;
}

/* ---------------- 事件校验 ---------------- */
const char *api_validate_clarify_event(const aik_json *ev)
{
	static __thread char msgbuf[96];
	const aik_json *opts;
	const aik_json *rec;
	const aik_json *deflt;
	size_t nopt, i, nids = 0;
	char ids[API_CLARIFY_MAX_OPTIONS][128];
	static const char *strkeys[] = { "description", "why", "impact",
					 "rollback", "danger" };
	size_t k;

	if (!ev || aik_json_typeof(ev) != AIK_JSON_OBJ)
		return "event 不是对象";
	{
		const aik_json *st = dt_get(ev, "status");

		if (!is_str(st) ||
		    strcmp(aik_json_str(st), "CLARIFY_REQUIRED") != 0)
			return "event status 非法";
	}
	if (!api_valid_nonce(aik_json_str(dt_get(ev, "nonce"))))
		return "event nonce 非法";
	{
		const aik_json *q = dt_get(ev, "question");
		const char *qs = aik_json_str(q);

		if (!is_str(q) || !str_nonblank(qs) ||
		    dt_utf8_cplen(qs, aik_json_strlen(q)) > 1024)
			return "event question 非法";
	}
	opts = dt_get(ev, "options");
	if (!opts || aik_json_typeof(opts) != AIK_JSON_ARR)
		return "event options 数量非法";
	nopt = aik_json_count(opts);
	if (nopt < 2 || nopt > API_CLARIFY_MAX_OPTIONS)
		return "event options 数量非法";
	for (i = 0; i < nopt; i++) {
		const aik_json *o = aik_json_at(opts, i);
		const char *oid;
		size_t j;
		int dup = 0;

		if (!o || aik_json_typeof(o) != AIK_JSON_OBJ)
			return "event option 非法";
		oid = aik_json_str(dt_get(o, "id"));
		if (!is_str(dt_get(o, "id")) || !oid || !*oid)
			return "event option id 非法";
		for (j = 0; j < nids; j++) {
			if (strcmp(ids[j], oid) == 0) {
				dup = 1;
				break;
			}
		}
		if (dup)
			return "event option id 非法";
		if (nids < API_CLARIFY_MAX_OPTIONS) {
			snprintf(ids[nids], sizeof(ids[nids]), "%s", oid);
			nids++;
		}
		if (!is_str(dt_get(o, "label")) ||
		    !*aik_json_str(dt_get(o, "label")))
			return "event option label 非法";
		for (k = 0; k < sizeof(strkeys) / sizeof(strkeys[0]); k++) {
			const aik_json *v = dt_get(o, strkeys[k]);
			aik_json_type t = aik_json_typeof(v);

			if (v && t != AIK_JSON_STR && t != AIK_JSON_NULL) {
				snprintf(msgbuf, sizeof(msgbuf),
					 "event option %s 非法", strkeys[k]);
				return msgbuf;
			}
		}
	}
	rec = dt_get(ev, "recommended");
	if (rec && aik_json_typeof(rec) != AIK_JSON_NULL) {
		int found = 0;

		if (is_str(rec)) {
			for (i = 0; i < nids; i++) {
				if (strcmp(ids[i], aik_json_str(rec)) == 0) {
					found = 1;
					break;
				}
			}
		}
		if (!found)
			return "event recommended 非法";
	}
	deflt = dt_get(ev, "default");
	if (deflt && aik_json_typeof(deflt) != AIK_JSON_NULL) {
		int found = 0;

		if (is_str(deflt)) {
			for (i = 0; i < nids; i++) {
				if (strcmp(ids[i], aik_json_str(deflt)) == 0) {
					found = 1;
					break;
				}
			}
		}
		if (!found)
			return "event default 非法";
	}
	if (deflt && aik_json_typeof(deflt) != AIK_JSON_NULL) {
		const char *dang = aik_json_str(dt_get(ev, "danger"));
		int bad = 0;

		if (dang && (strcmp(dang, "D3") == 0 ||
			     strcmp(dang, "D4") == 0))
			bad = 1;
		for (i = 0; i < nopt && !bad; i++) {
			const aik_json *o = aik_json_at(opts, i);
			const char *od = aik_json_str(dt_get(o, "danger"));

			if (od && (strcmp(od, "D3") == 0 ||
				   strcmp(od, "D4") == 0))
				bad = 1;
		}
		if (bad)
			return "D3/D4 事件不得带 default";
	}
	return NULL;
}

/* ---------------- clarify_order / render ---------------- */
static size_t clarify_order(const aik_json *clar, size_t *order,
			    size_t cap)
{
	const aik_json *opts = dt_get(clar, "options");
	const aik_json *rec = dt_get(clar, "recommended");
	size_t nopt, i, n = 0;

	if (!opts || aik_json_typeof(opts) != AIK_JSON_ARR)
		return 0;
	nopt = aik_json_count(opts);
	if (nopt > cap)
		nopt = cap;
	for (i = 0; i < nopt; i++)
		order[n++] = i;
	if (is_str(rec)) {
		for (i = 0; i < n; i++) {
			const aik_json *o = aik_json_at(opts, order[i]);

			if (o && aik_json_typeof(o) == AIK_JSON_OBJ &&
			    is_str(dt_get(o, "id")) &&
			    strcmp(aik_json_str(dt_get(o, "id")),
				   aik_json_str(rec)) == 0) {
				size_t idx = order[i];

				memmove(&order[1], &order[0],
					i * sizeof(size_t));
				order[0] = idx;
				break;
			}
		}
	}
	return n;
}

char *api_render_clarify_answer(const aik_json *ev, const char *session)
{
	struct dt_sbuf sb;
	const aik_json *header = dt_get(ev, "header");
	const aik_json *opts = dt_get(ev, "options");
	size_t order[64];
	size_t norder = 0;
	size_t nopt = 0;
	size_t i;

	dt_sb_init(&sb);
	if (is_str(header) && str_nonblank(aik_json_str(header))) {
		char *h = dt_strip(aik_json_str(header));

		dt_sb_printf(&sb, "【%s】", h);
		dt_sb_putc(&sb, '\n');
	} else {
		dt_sb_putstr(&sb, "需要澄清：\n");
	}
	{
		const char *q = aik_json_str(dt_get(ev, "question"));

		dt_sb_putstr(&sb, q ? q : "");
		dt_sb_putc(&sb, '\n');
	}
	if (opts && aik_json_typeof(opts) == AIK_JSON_ARR)
		nopt = aik_json_count(opts);
	norder = clarify_order(ev, order, 64);
	{
		const char *recid = aik_json_str(dt_get(ev, "recommended"));

		for (i = 0; i < norder; i++) {
			size_t idx = order[i];
			const aik_json *o = (idx < nopt)
						    ? aik_json_at(opts, idx)
						    : NULL;
			const char *label = "";
			const char *desc = NULL;
			const char *oid = NULL;

			if (o && aik_json_typeof(o) == AIK_JSON_OBJ) {
				label = aik_json_str(dt_get(o, "label"));
				if (!label)
					label = "";
				oid = aik_json_str(dt_get(o, "id"));
				if (is_str(dt_get(o, "description")))
					desc = aik_json_str(
						dt_get(o, "description"));
			}
			dt_sb_printf(&sb, "%zu. %s%s", i + 1, label,
				     (oid && recid &&
				      strcmp(oid, recid) == 0)
					     ? "（推荐）"
					     : "");
			dt_sb_putc(&sb, '\n');
			if (desc && *desc) {
				dt_sb_putstr(&sb, "   ");
				dt_sb_putstr(&sb, desc);
				dt_sb_putc(&sb, '\n');
			}
		}
	}
	if (dt_truthy(dt_get(ev, "multi_select")))
		dt_sb_putstr(&sb, "可多选。\n");
	{
		const aik_json *rec = dt_get(ev, "recommended");

		if (is_str(rec)) {
			for (i = 0; i < nopt; i++) {
				const aik_json *o = aik_json_at(opts, i);

				if (o && aik_json_typeof(o) == AIK_JSON_OBJ &&
				    is_str(dt_get(o, "id")) &&
				    strcmp(aik_json_str(dt_get(o, "id")),
					   aik_json_str(rec)) == 0 &&
				    is_str(dt_get(o, "why")) &&
				    *aik_json_str(dt_get(o, "why"))) {
					dt_sb_printf(
						&sb, "推荐理由：%s\n",
						aik_json_str(dt_get(o,
								    "why")));
					break;
				}
			}
		}
	}
	dt_sb_printf(&sb,
		     "回复：POST /clarify {\"nonce\":\"%s\",\"session\":"
		     "\"%s\",\"selection\":[\"<选项 id 或序号>\"]}",
		     aik_json_str(dt_get(ev, "nonce"))
			     ? aik_json_str(dt_get(ev, "nonce"))
			     : "",
		     session);
	return dt_sb_finish(&sb);
}

/* ---------------- pending 只读探针 ---------------- */
static void clarify_paths(const char *nonce, char *pending, size_t pcap,
			  char *consumed, size_t ccap)
{
	const char *home = getenv("HOME");

	if (!home || !*home)
		home = "/root";
	snprintf(pending, pcap, "%s/.aikernel/clarify/pending/%s.json",
		 home, nonce);
	snprintf(consumed, ccap, "%s/.aikernel/clarify/consumed/%s.json",
		 home, nonce);
}

int api_read_pending(const char *nonce, aik_json **doc_out)
{
	char pending[API_PATH_MAX], consumed[API_PATH_MAX];
	struct stat st;
	int fd;
	char *raw, *decoded;
	size_t rawlen, declen;
	aik_json *doc;
	size_t have = 0;
	const aik_json *v;

	*doc_out = NULL;
	if (!api_valid_nonce(nonce))
		return API_PENDING_INVALID;
	clarify_paths(nonce, pending, sizeof(pending), consumed,
		      sizeof(consumed));
	if (access(pending, F_OK) != 0) {
		if (access(consumed, F_OK) == 0)
			return API_PENDING_CONSUMED;
		return API_PENDING_UNKNOWN;
	}
	fd = open(pending, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return API_PENDING_UNKNOWN;
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
	    st.st_size <= 0 || st.st_size > 65536 ||
	    (st.st_mode & 077) != 0) {
		close(fd);
		return API_PENDING_INVALID;
	}
	raw = malloc((size_t)st.st_size + 1);
	if (!raw) {
		close(fd);
		return API_PENDING_UNKNOWN;
	}
	while (have < (size_t)st.st_size) {
		ssize_t n = read(fd, raw + have,
				 (size_t)st.st_size - have);

		if (n <= 0)
			break;
		have += (size_t)n;
	}
	raw[have] = '\0';
	rawlen = have;
	close(fd);
	api_utf8_decode_replace(raw, rawlen, &decoded, &declen);
	free(raw);
	doc = dt_parse(decoded, declen);
	free(decoded);
	if (!doc)
		return API_PENDING_INVALID;
	if (aik_json_typeof(doc) != AIK_JSON_OBJ)
		goto invalid;
	v = dt_get(doc, "status");
	if (!is_str(v) || strcmp(aik_json_str(v), "CLARIFY_PENDING") != 0)
		goto invalid;
	v = dt_get(doc, "version");
	if (!v || aik_json_typeof(v) != AIK_JSON_INT || aik_json_int(v) != 1)
		goto invalid;
	v = dt_get(doc, "nonce");
	if (!is_str(v) || strcmp(aik_json_str(v), nonce) != 0)
		goto invalid;
	if (!is_str(dt_get(doc, "session")))
		goto invalid;
	v = dt_get(doc, "expires_at_ms");
	if (!v || aik_json_typeof(v) != AIK_JSON_INT)
		goto invalid;
	v = dt_get(doc, "clarify");
	if (!v || aik_json_typeof(v) != AIK_JSON_OBJ)
		goto invalid;
	v = dt_get(doc, "expires_at_ms");
	if (aik_json_int(v) <= api_time() * 1000) {
		*doc_out = doc;
		return API_PENDING_EXPIRED;
	}
	*doc_out = doc;
	return API_PENDING_OK;
invalid:
	aik_json_free(doc);
	return API_PENDING_INVALID;
}

int api_pending_state_error(int state, const char **err, const char **msg)
{
	switch (state) {
	case API_PENDING_UNKNOWN:
		*err = "unknown_nonce";
		*msg = "未知或已过期的 clarify nonce";
		return 404;
	case API_PENDING_CONSUMED:
		*err = "already_consumed";
		*msg = "clarify 已被消费（重放被拒绝）";
		return 409;
	case API_PENDING_EXPIRED:
		*err = "expired";
		*msg = "clarify 已过期，请重新发起 /ask";
		return 410;
	case API_PENDING_INVALID:
		*err = "invalid_pending";
		*msg = "clarify pending 记录非法";
		return 500;
	default:
		return 0;
	}
}

/* ---------------- normalize_selection ---------------- */
int api_normalize_selection(const aik_json *doc, const aik_json *selection,
			    const aik_json *other, aik_json **tokens_out,
			    char **other_out, const char **errc)
{
	static __thread char msgbuf[320];
	const aik_json *clar = dt_get(doc, "clarify");
	const aik_json *opts = NULL;
	size_t nopt = 0, i, j;
	char (*optids)[128] = NULL;
	size_t noptids = 0;
	char (*chosen)[128] = NULL;
	size_t nchosen = 0;
	char *other_str = NULL;
	size_t *order = NULL;
	size_t norder = 0;
	aik_json *arr = NULL;

	*tokens_out = NULL;
	*other_out = NULL;
	*errc = NULL;
	if (clar && aik_json_typeof(clar) == AIK_JSON_OBJ)
		opts = dt_get(clar, "options");
	if (!opts || aik_json_typeof(opts) != AIK_JSON_ARR ||
	    aik_json_count(opts) == 0) {
		*errc = "pending options 非法";
		return -1;
	}
	nopt = aik_json_count(opts);
	optids = calloc(nopt, sizeof(*optids));
	chosen = calloc(nopt, sizeof(*chosen));
	order = calloc(nopt + 1, sizeof(*order));
	if (!optids || !chosen || !order)
		goto oom;
	for (i = 0; i < nopt; i++) {
		const aik_json *o = aik_json_at(opts, i);

		if (o && aik_json_typeof(o) == AIK_JSON_OBJ &&
		    is_str(dt_get(o, "id"))) {
			snprintf(optids[noptids], sizeof(optids[noptids]),
				 "%s", aik_json_str(dt_get(o, "id")));
			noptids++;
		}
	}
	if (other && aik_json_typeof(other) != AIK_JSON_NULL &&
	    !is_str(other)) {
		*errc = "other 必须是字符串";
		goto fail;
	}
	other_str = (other && is_str(other))
			    ? dt_strip(aik_json_str(other))
			    : calloc(1, 1);
	if (!other_str)
		goto oom;
	{
		size_t cps = dt_utf8_cplen(other_str, strlen(other_str));

		if (cps > API_CLARIFY_MAX_TEXT ||
		    strchr(other_str, '\n') || strchr(other_str, '\r')) {
			snprintf(msgbuf, sizeof(msgbuf),
				 "other 非法（单行、≤%d 字符）",
				 API_CLARIFY_MAX_TEXT);
			*errc = msgbuf;
			goto fail;
		}
	}
	norder = clarify_order(clar, order, nopt);
	if (!selection || aik_json_typeof(selection) != AIK_JSON_ARR) {
		if (selection && aik_json_typeof(selection) !=
					 AIK_JSON_NULL) {
			*errc = "selection 必须是数组";
			goto fail;
		}
		/* req.get("selection", []):键缺省 → [];显式 null → [] */
		selection = NULL;
	}
	for (i = 0; selection && i < aik_json_count(selection); i++) {
		const aik_json *item = aik_json_at(selection, i);
		char tok[256];
		const char *oid = NULL;
		aik_json_type it;
		char *ts;

		if (!item)
			continue;
		it = aik_json_typeof(item);
		if (it == AIK_JSON_BOOL) {
			*errc = "selection 元素必须是字符串或整数";
			goto fail;
		}
		if (it == AIK_JSON_STR)
			snprintf(tok, sizeof(tok), "%s",
				 aik_json_str(item));
		else if (it == AIK_JSON_INT)
			snprintf(tok, sizeof(tok), "%lld",
				 aik_json_int(item));
		else {
			*errc = "selection 元素必须是字符串或整数";
			goto fail;
		}
		ts = dt_strip(tok);
		snprintf(tok, sizeof(tok), "%s", ts);
		free(ts);
		if (!*tok)
			continue;
		for (j = 0; j < noptids; j++) {
			if (strcmp(optids[j], tok) == 0) {
				oid = optids[j];
				break;
			}
		}
		if (!oid) {
			int alldigit = 1;

			for (j = 0; tok[j]; j++) {
				if (tok[j] < '0' || tok[j] > '9') {
					alldigit = 0;
					break;
				}
			}
			if (alldigit) {
				long long v = atoll(tok);

				if (v >= 1 && (size_t)v <= norder) {
					size_t idx = order[v - 1];
					const aik_json *o = aik_json_at(opts,
								    idx);

					oid = aik_json_str(dt_get(o, "id"));
				}
			}
		}
		if (!oid) {
			snprintf(msgbuf, sizeof(msgbuf), "未知选项 %s", tok);
			*errc = msgbuf;
			goto fail;
		}
		{
			int dup = 0;

			for (j = 0; j < nchosen; j++) {
				if (strcmp(chosen[j], oid) == 0) {
					dup = 1;
					break;
				}
			}
			if (!dup) {
				snprintf(chosen[nchosen],
					 sizeof(chosen[nchosen]), "%s", oid);
				nchosen++;
			}
		}
	}
	if (nchosen == 0 && !*other_str) {
		*errc = "需要 selection 或 other";
		goto fail;
	}
	if (nchosen > 1 && !dt_truthy(dt_get(clar, "multi_select"))) {
		*errc = "单选澄清只能选择一个选项";
		goto fail;
	}
	arr = dt_new_arr();
	for (i = 0; i < nchosen; i++)
		dt_arr_push_str(arr, chosen[i]);
	*tokens_out = arr;
	*other_out = other_str;
	free(optids);
	free(chosen);
	free(order);
	return 0;
oom:
	*errc = "pending options 非法";	/* 内存不足:吞为非法(不可达) */
fail:
	free(other_str);
	free(optids);
	free(chosen);
	free(order);
	aik_json_free(arr);
	return -1;
}

/* ---------------- 请求体读取(_read_json 等价) ---------------- */
/* 0=ok(*obj_out 空 dict 语义);-1=已写 400;-2=非对象真值体 → 关连接 */
static int read_json_req(struct api_http_req *req,
			 struct api_http_resp *resp, aik_json **obj_out,
			 char **raw_out, size_t *raw_len)
{
	size_t n = 0;
	int rc = 0;
	char *body = api_http_read_body(req, &n, &rc);
	aik_json *v;

	*obj_out = NULL;
	*raw_out = body;
	*raw_len = n;
	if (rc == -1 || rc == -3) {
		aik_json *b = api_err_body("invalid json", "invalid json");

		api_resp_json(resp, 400, b);
		aik_json_free(b);
		return -1;
	}
	if (rc == -2) {
		aik_json *b = api_err_body("invalid json",
					   "request body too large");

		api_resp_json(resp, 400, b);
		aik_json_free(b);
		resp->unread_body = 1;
		return -1;
	}
	if (n == 0) {
		*obj_out = dt_new_obj();
		return 0;
	}
	v = dt_parse(body, n);
	if (!v) {
		aik_json *b = api_err_body("invalid json", "invalid json");

		api_resp_json(resp, 400, b);
		aik_json_free(b);
		return -1;
	}
	if (aik_json_typeof(v) != AIK_JSON_OBJ) {
		if (!dt_truthy(v)) {
			aik_json_free(v);
			*obj_out = dt_new_obj();
			return 0;
		}
		aik_json_free(v);
		return -2;
	}
	*obj_out = v;
	return 0;
}

/* ---------------- 事件→clarify_required 响应(ask/clarify 共用) ---------------- */
static int emit_clarify_required(const aik_json *ev, const char *session,
				 struct api_http_resp *resp)
{
	char *answer = api_render_clarify_answer(ev, session);
	aik_json *clar = dt_copy(ev);
	aik_json *b = dt_new_obj();

	{
		aik_json *sv = dt_new_str(session);

		/* 原位覆写/追加;所有权转移给 clar,勿再 free */
		aik_json_obj_set(clar, "session", sv);
	}
	dt_put_str(b, "status", "clarify_required");
	dt_put_str(b, "session", session);
	dt_put_str(b, "answer", answer ? answer : "");
	dt_put_copy(b, "clarify", clar);
	api_resp_json(resp, 200, b);
	aik_json_free(b);
	aik_json_free(clar);
	free(answer);
	return 0;
}

/* ---------------- /ask ---------------- */
int api_do_ask(struct api_http_req *req, struct api_http_resp *resp)
{
	aik_json *body = NULL;
	char *raw = NULL;
	size_t rawlen = 0;
	const aik_json *q;
	const char *qs;
	const aik_json *session_obj;
	char session[160];
	char tag[33];
	pthread_mutex_t *lk = NULL;
	char *argv_term[6];
	char env_tag[80];
	char *env_prompt = NULL;
	const char *extra_env[3];
	char *out = NULL, *errb = NULL;
	size_t outlen = 0, errlen = 0;
	int rc = 0;
	int rc_out = 0;
	int r;

	if (api_auth_check(req, resp) != 0)
		return 0;
	r = read_json_req(req, resp, &body, &raw, &rawlen);
	if (r != 0) {
		aik_json_free(body);
		free(raw);
		return r == -2 ? -1 : 0;
	}
	q = dt_get(body, "question");
	qs = aik_json_str(q);
	if (!is_str(q) || !str_nonblank(qs)) {
		aik_json *b = api_err_body("question required",
					   "question 不能为空");

		api_resp_json(resp, 400, b);
		aik_json_free(b);
		goto out;
	}
	{
		int has_nul = memchr(qs, 0, aik_json_strlen(q)) != NULL;
		size_t cps = dt_utf8_cplen(qs, aik_json_strlen(q));

		if (cps > 65536 || has_nul) {
			aik_json *b = api_err_body(
				"invalid_question",
				"question 过长（>64KiB）或含 NUL");

			api_resp_json(resp, 400, b);
			aik_json_free(b);
			goto out;
		}
	}
	session_obj = dt_get(body, "session");
	if (session_obj && dt_truthy(session_obj)) {
		/* 真值:非串也交给 valid_session 拒(py req.get() or 语义) */
		snprintf(session, sizeof(session), "%s",
			 is_str(session_obj)
				 ? aik_json_str(session_obj)
				 : "<non-str>");
	} else {
		char hx[33];

		api_token_hex16(hx);
		snprintf(session, sizeof(session), "api-%s", hx);
	}
	if (!api_valid_session(session)) {
		aik_json *b = api_err_body(
			"invalid_session",
			"session 必须以 api- 开头且只含 "
			"[A-Za-z0-9._-]（≤100）");

		api_resp_json(resp, 400, b);
		aik_json_free(b);
		goto out;
	}
	api_token_hex16(tag);
	lk = session_lock(session);
	if (!lk || lock_acquire_timeout(lk, g_api.ask_timeout + 30) != 0) {
		aik_json *b = api_err_body("session_busy",
					   "同一 session 有请求在处理，"
					   "请稍后重试");

		api_resp_json(resp, 503, b);
		aik_json_free(b);
		goto out;
	}
	snprintf(env_tag, sizeof(env_tag), "AIKERNEL_EVENT_TAG=%s", tag);
	env_prompt = malloc(aik_json_strlen(q) + 32);
	if (!env_prompt)
		goto release;
	snprintf(env_prompt, 17 + aik_json_strlen(q) + 1, "AIKERNEL_PROMPT=%s",
		 qs);
	argv_term[0] = g_api.ai_bin;
	argv_term[1] = (char *)"-p";
	argv_term[2] = (char *)"-";
	argv_term[3] = (char *)"-s";
	argv_term[4] = session;
	argv_term[5] = NULL;
	extra_env[0] = env_tag;
	extra_env[1] = env_prompt;
	extra_env[2] = NULL;
	rc = api_run_ai(argv_term, extra_env, g_api.ask_timeout, &out,
			&outlen, &errb, &errlen, &rc_out);
	if (rc == 1) {
		char m[64];
		aik_json *b;

		snprintf(m, sizeof(m), "ai 超时（上限 %llds）",
			 g_api.ask_timeout);
		b = api_err_body("ai timeout", m);
		api_resp_json(resp, 504, b);
		aik_json_free(b);
		goto release;
	}
	if (rc == 2) {
		char m[API_CFG_PATH + 32];
		aik_json *b;

		snprintf(m, sizeof(m), "%s 不存在", g_api.ai_bin);
		b = api_err_body("ai binary missing", m);
		api_resp_json(resp, 502, b);
		aik_json_free(b);
		goto release;
	}
	if (rc_out != 0) {
		char m[64];
		aik_json *b = api_err_body("ai failed", "");
		char *detail = err_tail400(errb, errlen);

		aik_json_free(b);
		snprintf(m, sizeof(m), "ai rc=%d", rc_out);
		b = api_err_body("ai failed", m);
		dt_put_str(b, "detail", detail ? detail : "");
		api_resp_json(resp, 502, b);
		aik_json_free(b);
		free(detail);
		goto release;
	}
	{
		aik_json *ev = NULL;
		const char *ev_err = NULL;

		api_parse_tagged_event(errb ? errb : "", errlen, tag, &ev,
				       &ev_err);
		if (ev_err) {
			aik_json *b = api_err_body("clarify_protocol_error",
						   ev_err);

			api_resp_json(resp, 502, b);
			aik_json_free(b);
			goto release;
		}
		if (ev) {
			const char *verr = api_validate_clarify_event(ev);
			aik_json *doc = NULL;
			int st;

			if (verr) {
				aik_json *b = api_err_body(
					"clarify_protocol_error", verr);

				api_resp_json(resp, 502, b);
				aik_json_free(b);
				aik_json_free(ev);
				goto release;
			}
			st = api_read_pending(aik_json_str(dt_get(ev,
								  "nonce")),
					      &doc);
			if (st != API_PENDING_OK || !doc ||
			    !is_str(dt_get(doc, "session")) ||
			    strcmp(aik_json_str(dt_get(doc, "session")),
				   session) != 0) {
				aik_json *b = api_err_body(
					"clarify_state_mismatch",
					"事件 nonce 与 pending/session "
					"不一致");

				api_resp_json(resp, 502, b);
				aik_json_free(b);
				aik_json_free(doc);
				aik_json_free(ev);
				goto release;
			}
			aik_json_free(doc);
			emit_clarify_required(ev, session, resp);
			aik_json_free(ev);
			goto release;
		}
		if (body_has(out, outlen, "CLARIFY_REQUIRED")) {
			aik_json *b = api_err_body(
				"clarify_event_missing",
				"shell 未发出 tagged 事件（协议错误）");

			api_resp_json(resp, 502, b);
			aik_json_free(b);
			goto release;
		}
		{
			char *stripped = dt_strip(out ? out : "");
			aik_json *b = dt_new_obj();

			dt_put_str(b, "status", "ok");
			dt_put_str(b, "session", session);
			dt_put_str(b, "answer", stripped);
			api_resp_json(resp, 200, b);
			aik_json_free(b);
			free(stripped);
		}
	}
release:
	if (lk)
		pthread_mutex_unlock(lk);
out:
	aik_json_free(body);
	free(raw);
	free(out);
	free(errb);
	free(env_prompt);
	return 0;
}

/* ---------------- /clarify ---------------- */
int api_do_clarify(struct api_http_req *req, struct api_http_resp *resp)
{
	aik_json *body = NULL;
	char *raw = NULL;
	size_t rawlen = 0;
	const char *nonce;
	const char *session;
	aik_json *doc = NULL;
	int st;
	const char *err, *msg;
	int code;
	aik_json *tokens = NULL;
	char *other = NULL;
	const char *nerr = NULL;
	pthread_mutex_t *lk = NULL;
	char tag[33];
	char *out = NULL, *errb = NULL;
	size_t outlen = 0, errlen = 0;
	int rc = 0;
	int rc_out = 0;
	int r;
	const aik_json *sel;
	const aik_json *oth;

	if (api_auth_check(req, resp) != 0)
		return 0;
	r = read_json_req(req, resp, &body, &raw, &rawlen);
	if (r != 0) {
		aik_json_free(body);
		free(raw);
		return r == -2 ? -1 : 0;
	}
	nonce = aik_json_str(dt_get(body, "nonce"));
	if (!api_valid_nonce(nonce)) {
		aik_json *b = api_err_body(
			"invalid_nonce",
			"nonce 必须以 cq- 开头且只含 [A-Za-z0-9._-]");

		api_resp_json(resp, 400, b);
		aik_json_free(b);
		goto out;
	}
	session = aik_json_str(dt_get(body, "session"));
	if (!api_valid_session(session)) {
		aik_json *b = api_err_body(
			"invalid_session",
			"session 必须是 /ask 返回的 api-... 会话");

		api_resp_json(resp, 400, b);
		aik_json_free(b);
		goto out;
	}
	st = api_read_pending(nonce, &doc);
	code = api_pending_state_error(st, &err, &msg);
	if (code) {
		aik_json *b = api_err_body(err, msg);

		api_resp_json(resp, code, b);
		aik_json_free(b);
		aik_json_free(doc);
		goto out;
	}
	if (!is_str(dt_get(doc, "session")) ||
	    strcmp(aik_json_str(dt_get(doc, "session")), session) != 0) {
		aik_json *b = api_err_body(
			"session_mismatch", "session 与 pending 记录不一致");

		api_resp_json(resp, 409, b);
		aik_json_free(b);
		aik_json_free(doc);
		goto out;
	}
	/* req.get("selection", []) / req.get("other"):缺省与 null 同为空 */
	sel = dt_get(body, "selection");
	if (sel && aik_json_typeof(sel) == AIK_JSON_NULL)
		sel = NULL;
	oth = dt_get(body, "other");
	if (oth && aik_json_typeof(oth) == AIK_JSON_NULL)
		oth = NULL;
	if (api_normalize_selection(doc, sel, oth, &tokens, &other,
				    &nerr) != 0) {
		aik_json *b = api_err_body("invalid_selection", nerr);

		api_resp_json(resp, 400, b);
		aik_json_free(b);
		aik_json_free(doc);
		goto out;
	}
	aik_json_free(doc);
	doc = NULL;
	lk = session_lock(session);
	if (!lk || lock_acquire_timeout(lk, g_api.ask_timeout + 30) != 0) {
		aik_json *b = api_err_body("session_busy",
					   "同一 session 有请求在处理，"
					   "请稍后重试");

		api_resp_json(resp, 503, b);
		aik_json_free(b);
		goto out;
	}
	st = api_read_pending(nonce, &doc);
	code = api_pending_state_error(st, &err, &msg);
	if (code) {
		aik_json *b = api_err_body(err, msg);

		api_resp_json(resp, code, b);
		aik_json_free(b);
		aik_json_free(doc);
		goto release;
	}
	if (!is_str(dt_get(doc, "session")) ||
	    strcmp(aik_json_str(dt_get(doc, "session")), session) != 0) {
		aik_json *b = api_err_body(
			"session_mismatch", "session 与 pending 记录不一致");

		api_resp_json(resp, 409, b);
		aik_json_free(b);
		aik_json_free(doc);
		goto release;
	}
	aik_json_free(doc);
	doc = NULL;
	api_token_hex16(tag);
	{
		char env_tag[80];
		char env_select[API_PATH_MAX];
		char env_other[API_CLARIFY_MAX_TEXT * 4 + 32];
		const char *extra[4];
		size_t ne = 0;
		char *argv_term[6];
		struct dt_sbuf sb;

		snprintf(env_tag, sizeof(env_tag), "AIKERNEL_EVENT_TAG=%s",
			 tag);
		extra[ne++] = env_tag;
		if (tokens && aik_json_count(tokens) > 0) {
			char *joined;

			dt_sb_init(&sb);
			for (size_t idx = 0; idx < aik_json_count(tokens);
			     idx++) {
				if (idx)
					dt_sb_putc(&sb, ',');
				dt_sb_putstr(&sb, aik_json_str(
						     aik_json_at(tokens,
								 idx)));
			}
			joined = dt_sb_finish(&sb);
			snprintf(env_select, sizeof(env_select),
				 "AIKERNEL_CLARIFY_SELECT=%s",
				 joined ? joined : "");
			free(joined);
			extra[ne++] = env_select;
		}
		if (other && *other) {
			snprintf(env_other, sizeof(env_other),
				 "AIKERNEL_CLARIFY_OTHER=%s", other);
			extra[ne++] = env_other;
		}
		extra[ne] = NULL;
		argv_term[0] = g_api.ai_bin;
		argv_term[1] = (char *)"--clarify-answer";
		argv_term[2] = (char *)nonce;
		argv_term[3] = (char *)"-s";
		argv_term[4] = (char *)session;
		argv_term[5] = NULL;
		rc = api_run_ai(argv_term, extra, g_api.ask_timeout, &out,
				&outlen, &errb, &errlen, &rc_out);
	}
	if (rc == 1) {
		char m[64];
		aik_json *b;

		snprintf(m, sizeof(m), "ai 超时（上限 %llds）",
			 g_api.ask_timeout);
		b = api_err_body("ai timeout", m);
		api_resp_json(resp, 504, b);
		aik_json_free(b);
		goto release;
	}
	if (rc == 2) {
		char m[API_CFG_PATH + 32];
		aik_json *b;

		snprintf(m, sizeof(m), "%s 不存在", g_api.ai_bin);
		b = api_err_body("ai binary missing", m);
		api_resp_json(resp, 502, b);
		aik_json_free(b);
		goto release;
	}
	if (rc_out != 0) {
		aik_json *doc2 = NULL;
		int st2 = api_read_pending(nonce, &doc2);

		aik_json_free(doc2);
		if (st2 == API_PENDING_CONSUMED) {
			aik_json *b = api_err_body(
				"already_consumed",
				"clarify 已被消费（重放被拒绝）");

			api_resp_json(resp, 409, b);
			aik_json_free(b);
			goto release;
		}
		{
			char m[64];
			aik_json *b;
			char *detail = err_tail400(errb, errlen);

			snprintf(m, sizeof(m), "ai rc=%d", rc_out);
			b = api_err_body("ai failed", m);
			dt_put_str(b, "detail", detail ? detail : "");
			api_resp_json(resp, 502, b);
			aik_json_free(b);
			free(detail);
			goto release;
		}
	}
	{
		aik_json *ev = NULL;
		const char *ev_err = NULL;

		api_parse_tagged_event(errb ? errb : "", errlen, tag, &ev,
				       &ev_err);
		if (ev_err) {
			aik_json *b = api_err_body("clarify_protocol_error",
						   ev_err);

			api_resp_json(resp, 502, b);
			aik_json_free(b);
			goto release;
		}
		if (ev) {
			const char *verr = api_validate_clarify_event(ev);
			aik_json *doc2 = NULL;
			int st2;

			if (verr) {
				aik_json *b = api_err_body(
					"clarify_protocol_error", verr);

				api_resp_json(resp, 502, b);
				aik_json_free(b);
				aik_json_free(ev);
				goto release;
			}
			st2 = api_read_pending(aik_json_str(dt_get(ev,
								    "nonce")),
					       &doc2);
			if (st2 != API_PENDING_OK || !doc2 ||
			    !is_str(dt_get(doc2, "session")) ||
			    strcmp(aik_json_str(dt_get(doc2, "session")),
				   session) != 0) {
				aik_json *b = api_err_body(
					"clarify_state_mismatch",
					"事件 nonce 与 pending/session "
					"不一致");

				api_resp_json(resp, 502, b);
				aik_json_free(b);
				aik_json_free(doc2);
				aik_json_free(ev);
				goto release;
			}
			aik_json_free(doc2);
			emit_clarify_required(ev, session, resp);
			aik_json_free(ev);
			goto release;
		}
		if (body_has(out, outlen, "CLARIFY_REQUIRED")) {
			aik_json *b = api_err_body(
				"clarify_event_missing",
				"shell 未发出 tagged 事件（协议错误）");

			api_resp_json(resp, 502, b);
			aik_json_free(b);
			goto release;
		}
		{
			char *stripped = dt_strip(out ? out : "");
			aik_json *b = dt_new_obj();

			dt_put_str(b, "status", "ok");
			dt_put_str(b, "session", session);
			dt_put_str(b, "answer", stripped);
			api_resp_json(resp, 200, b);
			aik_json_free(b);
			free(stripped);
		}
	}
release:
	if (lk)
		pthread_mutex_unlock(lk);
out:
	aik_json_free(body);
	aik_json_free(tokens);
	free(other);
	free(raw);
	free(out);
	free(errb);
	return 0;
}
