/* SPDX-License-Identifier: GPL-2.0 */
/*
 * apiv2.c - T7b 结构化端点 /health /tools /params /sense /act
 * (参考 _do_health/_do_tools/_do_params/_do_sense/_do_act/
 * tools_summary/parse_control/truncate_sample/validate_act)。
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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

static int is_str(const aik_json *v)
{
	return v && aik_json_typeof(v) == AIK_JSON_STR;
}

/* ---------------- /health ---------------- */
/* systemctl is-active mock 同形:PATH 查找,捕获 stdout,超时杀 */
static int run_systemctl(const char *unit, char *out, size_t cap,
			 int *timeout_happened, int *decode_bad,
			 int *bad_byte, size_t *bad_pos)
{
	char *argv_term[4];
	char *outb = NULL;
	size_t outlen = 0;
	pid_t pid;
	int pfd[2];

	*timeout_happened = 0;
	*decode_bad = 0;
	*bad_byte = -1;
	*bad_pos = 0;
	out[0] = '\0';
	argv_term[0] = (char *)"systemctl";
	argv_term[1] = (char *)"is-active";
	argv_term[2] = (char *)unit;
	argv_term[3] = NULL;
	if (pipe(pfd) != 0)
		return -1;
	pid = fork();
	if (pid < 0) {
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}
	if (pid == 0) {
		(void)signal(SIGPIPE, SIG_DFL);
		close(pfd[0]);
		dup2(pfd[1], 1);
		close(pfd[1]);
		/* stderr 丢弃(capture_output 但只用 stdout;消息不含 stderr) */
		{
			int dn = open("/dev/null", O_WRONLY);

			if (dn >= 0) {
				dup2(dn, 2);
				close(dn);
			}
		}
		execvp("systemctl", argv_term);
		_exit(127);
	}
	close(pfd[1]);
	{
		struct dt_sbuf sb;
		char chunk[4096];
		long long deadline = (long long)time(NULL) + 10;
		int status = 0;

		dt_sb_init(&sb);
		for (;;) {
			struct pollfd pf;
			ssize_t n;

			pf.fd = pfd[0];
			pf.events = POLLIN;
			pf.revents = 0;
			n = poll(&pf, 1, 100);
			if (n > 0 && (pf.revents & POLLIN)) {
				ssize_t r = read(pfd[0], chunk, sizeof(chunk));

				if (r > 0) {
					dt_sb_puts(&sb, chunk, (size_t)r);
					continue;
				}
				if (r == 0)
					break;
			}
			if (n > 0 && (pf.revents & (POLLHUP | POLLERR)))
				break;
			if (waitpid(pid, &status, WNOHANG) == pid) {
				ssize_t r;

				do {
					r = read(pfd[0], chunk, sizeof(chunk));
					if (r > 0)
						dt_sb_puts(&sb, chunk,
							   (size_t)r);
				} while (r > 0);
				break;
			}
			if ((long long)time(NULL) > deadline) {
				kill(pid, SIGKILL);
				(void)waitpid(pid, &status, 0);
				*timeout_happened = 1;
				break;
			}
		}
		close(pfd[0]);
		(void)waitpid(pid, &status, 0);
		outb = dt_sb_finish(&sb);
		outlen = sb.n;
	}
	if (*timeout_happened) {
		free(outb);
		return 1;
	}
	/* text=True 严格 UTF-8 解码:坏字节 → UnicodeDecodeError */
	{
		size_t i = 0;

		while (i < outlen) {
			unsigned char c = (unsigned char)outb[i];
			size_t need = 1;

			if (c < 0x80)
				need = 1;
			else if ((c & 0xE0) == 0xC0)
				need = 2;
			else if ((c & 0xF0) == 0xE0)
				need = 3;
			else if ((c & 0xF8) == 0xF0)
				need = 4;
			else {
				*decode_bad = 1;
				*bad_byte = c;
				*bad_pos = i;
				break;
			}
			if (i + need > outlen) {
				*decode_bad = 1;
				*bad_byte = c;
				*bad_pos = i;
				break;
			}
			{
				size_t k;

				for (k = 1; k < need; k++) {
					if (((unsigned char)outb[i + k] &
					     0xC0) != 0x80) {
						*decode_bad = 1;
						*bad_byte = c;
						*bad_pos = i;
						break;
					}
				}
				if (*decode_bad)
					break;
			}
			i += need;
		}
	}
	if (*decode_bad) {
		free(outb);
		return 2;
	}
	{
		char *t = dt_strip(outb);

		snprintf(out, cap, "%s", t ? t : "");
		free(t);
		free(outb);
	}
	return 0;
}

int api_do_health(struct api_http_req *req, struct api_http_resp *resp)
{
	static const char *services[] = { "ollama", "aikernel-memory", "ssh" };
	aik_json *svcs = dt_new_obj();
	aik_json *body;
	size_t i;

	(void)req;
	for (i = 0; i < sizeof(services) / sizeof(services[0]); i++) {
		char unit[128];
		char out[256];
		int timeout_happened = 0, decode_bad = 0;
		int bad_byte = -1;
		size_t bad_pos = 0;
		int r;

		snprintf(unit, sizeof(unit), "%s.service", services[i]);
		r = run_systemctl(unit, out, sizeof(out), &timeout_happened,
				  &decode_bad, &bad_byte, &bad_pos);
		if (r == 1) {
			char m[256];

			/* py subprocess.TimeoutExpired str */
			snprintf(m, sizeof(m),
				 "error: Command '['systemctl', 'is-active', "
				 "'%s']' timed out after 10 seconds", unit);
			dt_put_str(svcs, services[i], m);
		} else if (r == 2) {
			char m[256];

			snprintf(m, sizeof(m),
				 "error: 'utf-8' codec can't decode byte "
				 "0x%02x in position %zu: invalid start byte",
				 (unsigned)bad_byte, bad_pos);
			dt_put_str(svcs, services[i], m);
		} else {
			dt_put_str(svcs, services[i],
				   *out ? out : "unknown");
		}
	}
	api_audit_line("api_health", NULL, "OK");
	body = dt_new_obj();
	dt_put_str(body, "status", "ok");
	dt_put_copy(body, "services", svcs);
	dt_put_int(body, "api_version", API_VERSION);
	{
		aik_json *eps = dt_new_arr();
		static const char *e[] = { "/health", "/tools", "/params",
					   "/sense", "/ask", "/clarify",
					   "/act" };
		size_t k;

		for (k = 0; k < 7; k++)
			dt_arr_push_str(eps, e[k]);
		dt_put_copy(body, "endpoints", eps);
		aik_json_free(eps);
	}
	api_resp_json(resp, 200, body);
	aik_json_free(body);
	aik_json_free(svcs);
	return 0;
}

/* ---------------- /tools ---------------- */
/* python json.JSONDecodeError 消息近似(已录形状:对象键位置) */
static char *py_json_errmsg(const char *buf, size_t n)
{
	size_t i = 0;
	size_t line = 1, col = 1;
	char m[160];

	while (i < n && (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\n' ||
			 buf[i] == '\r')) {
		if (buf[i] == '\n') {
			line++;
			col = 1;
		} else {
			col++;
		}
		i++;
	}
	if (i < n && buf[i] == '{') {
		i++;
		col++;
		while (i < n && (buf[i] == ' ' || buf[i] == '\t')) {
			i++;
			col++;
		}
		if (i < n && buf[i] != '"' && buf[i] != '}') {
			snprintf(m, sizeof(m),
				 "Expecting property name enclosed in "
				 "double quotes: line %zu column %zu "
				 "(char %zu)", line, col, i);
			return strdup(m);
		}
	}
	if (i >= n) {
		snprintf(m, sizeof(m),
			 "Expecting value: line %zu column %zu (char %zu)",
			 line, col, i);
		return strdup(m);
	}
	snprintf(m, sizeof(m),
		 "Expecting value: line %zu column %zu (char %zu)",
		 line, col, i);
	return strdup(m);
}

/* doc/tools 形状校验:0=ARR ok;-1=TypeError/AttributeError → 关连接 */
static int tools_doc_shape(const aik_json *doc, const aik_json **tools_out)
{
	const aik_json *tools;
	size_t i;

	if (!doc || aik_json_typeof(doc) != AIK_JSON_OBJ)
		return -1;	/* doc.get → AttributeError */
	tools = dt_get(doc, "tools");
	if (!tools) {
		*tools_out = NULL;	/* doc.get("tools", []) 缺省 */
		return 0;
	}
	if (aik_json_typeof(tools) != AIK_JSON_ARR)
		return -1;	/* None.get/迭代 str/dict → 异常 */
	for (i = 0; i < aik_json_count(tools); i++) {
		const aik_json *t = aik_json_at(tools, i);

		if (!t || aik_json_typeof(t) != AIK_JSON_OBJ)
			return -1;	/* t.get → AttributeError */
		{
			const aik_json *desc = dt_get(t, "description");

			if (desc && aik_json_typeof(desc) !=
					    AIK_JSON_STR)
				return -1;	/* desc[:160] → TypeError */
		}
	}
	*tools_out = tools;
	return 0;
}

int api_do_tools(struct api_http_req *req, struct api_http_resp *resp,
		 const char *channel, const char *risk)
{
	size_t n = 0;
	int e = 0;
	char *text = api_read_file(g_api.tools_json, &n, &e);
	aik_json *doc = NULL;
	const aik_json *tools = NULL;
	aik_json *out_arr;
	aik_json *out;
	aik_json *args;
	size_t i;

	(void)req;
	if (!text) {
		char m[API_CFG_PATH + 64];

		api_oserr_str(m, sizeof(m), e, g_api.tools_json);
		out = api_err_body("tools_json_unreadable", m);
		api_resp_json(resp, 500, out);
		aik_json_free(out);
		return 0;
	}
	{
		/* python open(encoding="utf-8") 严格解码:坏字节先于 json 报错 */
		size_t i = 0;
		int bad = 0;

		while (i < n) {
			unsigned char c = (unsigned char)text[i];
			size_t need;

			if (c < 0x80)
				need = 1;
			else if ((c & 0xE0) == 0xC0)
				need = 2;
			else if ((c & 0xF0) == 0xE0)
				need = 3;
			else if ((c & 0xF8) == 0xF0)
				need = 4;
			else
				need = 0;
			if (need == 0 || i + need > n) {
				bad = 1;
				break;
			}
			{
				size_t k;

				for (k = 1; k < need; k++) {
					if (((unsigned char)text[i + k] &
					     0xC0) != 0x80) {
						bad = 1;
						break;
					}
				}
				if (bad)
					break;
			}
			i += need;
		}
		if (bad) {
			char m[200];
			aik_json *o;

			api_utf8_errmsg(text, n, m, sizeof(m));
			o = api_err_body("tools_json_unreadable", m);
			api_resp_json(resp, 500, o);
			aik_json_free(o);
			free(text);
			return 0;
		}
	}
	doc = dt_parse(text, n);
	if (!doc) {
		char *m = py_json_errmsg(text, n);

		out = api_err_body("tools_json_unreadable", m ? m : "");
		api_resp_json(resp, 500, out);
		aik_json_free(out);
		free(m);
		free(text);
		return 0;
	}
	free(text);
	if (tools_doc_shape(doc, &tools) != 0) {
		aik_json_free(doc);
		return -1;	/* 未捕获异常等价:关连接 */
	}
	out_arr = dt_new_arr();
	for (i = 0; tools && i < aik_json_count(tools); i++) {
		const aik_json *t = aik_json_at(tools, i);
		const char *tch = aik_json_str(dt_get(t, "channel"));
		const char *trk = aik_json_str(dt_get(t, "risk"));
		const aik_json *desc = dt_get(t, "description");
		const char *ds = is_str(desc) ? aik_json_str(desc) : "";
		aik_json *o;

		if (channel && (!tch || strcmp(tch, channel) != 0))
			continue;
		if (risk && (!trk || strcmp(trk, risk) != 0))
			continue;
		o = dt_new_obj();
		{
			const aik_json *nm = dt_get(t, "name");

			if (nm)
				dt_put_copy(o, "name", nm);
			else
				dt_put_null(o, "name");
			if (dt_get(t, "channel"))
				dt_put_copy(o, "channel", dt_get(t, "channel"));
			else
				dt_put_null(o, "channel");
			if (dt_get(t, "risk"))
				dt_put_copy(o, "risk", dt_get(t, "risk"));
			else
				dt_put_null(o, "risk");
		}
		if (ds && dt_utf8_cplen(ds, strlen(ds)) > API_TOOLS_DESC_MAX) {
			char *head = dt_utf8_head(ds, API_TOOLS_DESC_MAX);

			dt_put_str(o, "description", head);
			free(head);
		} else {
			dt_put_str(o, "description", ds);
		}
		dt_arr_push_copy(out_arr, o);
		aik_json_free(o);
	}
	out = dt_new_obj();
	if (dt_get(doc, "version"))
		dt_put_copy(out, "version", dt_get(doc, "version"));
	else
		dt_put_null(out, "version");
	if (dt_get(doc, "tool_count"))
		dt_put_copy(out, "tool_count", dt_get(doc, "tool_count"));
	else
		dt_put_int(out, "tool_count",
			   tools ? (long long)aik_json_count(tools) : 0);
	dt_put_int(out, "count", (long long)aik_json_count(out_arr));
	dt_put_copy(out, "tools", out_arr);
	args = dt_new_obj();
	dt_put_str(args, "channel", channel);
	dt_put_str(args, "risk", risk);
	dt_put_int(args, "count", (long long)aik_json_count(out_arr));
	api_audit_line("api_tools", args, "OK");
	aik_json_free(args);
	api_resp_json(resp, 200, out);
	aik_json_free(out);
	aik_json_free(out_arr);
	aik_json_free(doc);
	return 0;
}

/* ---------------- /params ---------------- */
static aik_json *read_control_params_json(size_t *count_out)
{
	size_t n = 0;
	char *text = api_read_file(API_CONTROL_PROC, &n, NULL);
	aik_json *arr;
	size_t count = 0;

	if (!text) {
		*count_out = 0;
		return NULL;
	}
	arr = dt_new_arr();
	{
		char *line, *save;

		for (line = strtok_r(text, "\n", &save); line;
		     line = strtok_r(NULL, "\n", &save)) {
			char name[128];
			long long dom, lo, hi, cur, def;

			if (api_parse_control_line(line, name,
						   sizeof(name), &dom, &lo,
						   &hi, &cur, &def) != 0)
				continue;
			{
				aik_json *p = dt_new_obj();

				dt_put_str(p, "name", name);
				dt_put_int(p, "domain", dom);
				dt_put_int(p, "min", lo);
				dt_put_int(p, "max", hi);
				dt_put_int(p, "current", cur);
				dt_put_int(p, "default", def);
				dt_put_bool(p, "task_scoped",
					    api_is_task_param(name));
				dt_arr_push_copy(arr, p);
				aik_json_free(p);
				count++;
			}
		}
	}
	free(text);
	*count_out = count;
	return arr;
}

int api_do_params(struct api_http_req *req, struct api_http_resp *resp,
		  const char *name)
{
	size_t count = 0;
	aik_json *arr = read_control_params_json(&count);
	aik_json *body;
	aik_json *args;

	(void)req;
	if (!arr || count == 0) {
		body = api_err_body("control_unreadable",
				    "无法读取 /proc/ai/control");
		api_resp_json(resp, 500, body);
		aik_json_free(body);
		aik_json_free(arr);
		return 0;
	}
	if (name && *name) {
		size_t i;

		for (i = 0; i < count; i++) {
			const aik_json *p = aik_json_at(arr, i);

			if (strcmp(aik_json_str(dt_get(p, "name")),
				   name) == 0) {
				args = dt_new_obj();
				dt_put_str(args, "name", name);
				api_audit_line("api_params", args, "OK");
				aik_json_free(args);
				api_resp_json(resp, 200, p);
				aik_json_free(arr);
				return 0;
			}
		}
		{
			char m[256];

			snprintf(m, sizeof(m),
				 "未知参数 %s（27 参数见 GET /params）",
				 name);
			body = api_err_body("unknown_param", m);
			api_resp_json(resp, 404, body);
			aik_json_free(body);
			aik_json_free(arr);
			return 0;
		}
	}
	args = dt_new_obj();
	dt_put_int(args, "count", (long long)count);
	api_audit_line("api_params", args, "OK");
	aik_json_free(args);
	body = dt_new_obj();
	dt_put_int(body, "count", (long long)count);
	dt_put_copy(body, "params", arr);
	api_resp_json(resp, 200, body);
	aik_json_free(body);
	aik_json_free(arr);
	return 0;
}

/* ---------------- /sense ---------------- */
static const char *SENSE_WHAT[][2] = {
	{ "status", "/proc/ai/status" },
	{ "telemetry", "/proc/ai/telemetry" },
	{ "latency", "/proc/ai/latency" },
	{ "hitrate", "/proc/ai/hitrate" },
	{ "sched", "/proc/ai/sched" },
	{ "chains", "/proc/ai/chains" },
	{ "decisions", "/proc/ai/decisions" },
	{ "vfs", "/proc/ai/vfs" },
	{ "control", "/proc/ai/control" },
};

int api_do_sense(struct api_http_req *req, struct api_http_resp *resp,
		 const char *what, const char *limit)
{
	const char *node = NULL;
	size_t i;
	long long cap = API_SENSE_DEFAULT_LIMIT;
	size_t n = 0;
	int e = 0;
	char *text = NULL;
	char *decoded = NULL;
	size_t declen = 0;
	size_t total_cps, keep_cps;
	char *kept = NULL;
	int truncated = 0;
	aik_json *body;
	aik_json *args;

	(void)req;
	for (i = 0; i < sizeof(SENSE_WHAT) / sizeof(SENSE_WHAT[0]); i++) {
		if (what && strcmp(SENSE_WHAT[i][0], what) == 0) {
			node = SENSE_WHAT[i][1];
			break;
		}
	}
	if (!node) {
		body = api_err_body(
			"unknown_what",
			"what 取值：chains, control, decisions, hitrate, "
			"latency, sched, status, telemetry, vfs");
		api_resp_json(resp, 404, body);
		aik_json_free(body);
		return 0;
	}
	if (limit) {
		if (!api_py_int(limit, &cap)) {
			body = api_err_body("invalid_limit",
					    "limit 须为整数");
			api_resp_json(resp, 400, body);
			aik_json_free(body);
			return 0;
		}
		if (cap < 1 || cap > API_SENSE_MAX_LIMIT) {
			char m[64];

			snprintf(m, sizeof(m), "limit 取值 1..%d",
				 API_SENSE_MAX_LIMIT);
			body = api_err_body("invalid_limit", m);
			api_resp_json(resp, 400, body);
			aik_json_free(body);
			return 0;
		}
	}
	text = api_read_file(node, &n, &e);
	if (!text) {
		char m[API_PATH_MAX + 64];

		api_oserr_str(m, sizeof(m), e, node);
		body = api_err_body("sense_unreadable", m);
		api_resp_json(resp, 500, body);
		aik_json_free(body);
		return 0;
	}
	api_utf8_decode_replace(text, n, &decoded, &declen);
	free(text);
	total_cps = dt_utf8_cplen(decoded, declen);
	if (total_cps <= (size_t)cap) {
		kept = malloc(declen + 1);
		memcpy(kept, decoded, declen);
		kept[declen] = '\0';
		keep_cps = total_cps;
	} else {
		truncated = 1;
		if (strcmp(what, "telemetry") == 0)
			kept = dt_utf8_tail(decoded, (size_t)cap);
		else
			kept = dt_utf8_head(decoded, (size_t)cap);
		keep_cps = (size_t)cap;
	}
	free(decoded);
	args = dt_new_obj();
	dt_put_str(args, "what", what);
	dt_put_int(args, "limit", cap);
	dt_put_bool(args, "truncated", truncated);
	api_audit_line("api_sense", args, "OK");
	aik_json_free(args);
	body = dt_new_obj();
	dt_put_str(body, "what", what);
	dt_put_str(body, "node", node);
	dt_put_bool(body, "truncated", truncated);
	dt_put_int(body, "total_bytes", (long long)total_cps);
	dt_put_str(body, "content", kept ? kept : "");
	api_resp_json(resp, 200, body);
	aik_json_free(body);
	free(kept);
	(void)keep_cps;
	return 0;
}

/* ---------------- /act ---------------- */
int api_do_act(struct api_http_req *req, struct api_http_resp *resp)
{
	size_t n = 0;
	int rc = 0;
	char *raw = NULL;
	aik_json *body_json = NULL;
	const aik_json *paramv, *valuev, *pidv, *confirmv;
	const char *param;
	char parambuf[128];
	aik_json *value_copy = NULL;
	const aik_json *pid_keep = NULL;
	long long value_i = 0, pid_i = 0;
	int have_value = 0, have_pid = 0;
	int confirm;
	size_t count = 0;
	aik_json *arr = NULL;
	const aik_json *pdef = NULL;
	const char *verr_msg = NULL;
	int vcode = 0;
	aik_json *out;

	if (api_auth_check(req, resp) != 0)
		return 0;
	{
		aik_json *b = NULL;
		char *raw2 = NULL;
		size_t rl = 0;
		int r = 0;
		/* 复用 apiask 的 read 语义:此处内联(_read_json 同文) */
		rc = 0;
		raw = api_http_read_body(req, &rl, &rc);
		n = rl;
		(void)b;
		(void)r;
		(void)raw2;
	}
	if (rc == -1 || rc == -3) {
		out = api_err_body("invalid json", "invalid json");
		api_resp_json(resp, 400, out);
		aik_json_free(out);
		free(raw);
		return 0;
	}
	if (rc == -2) {
		out = api_err_body("invalid json", "request body too large");
		api_resp_json(resp, 400, out);
		aik_json_free(out);
		resp->unread_body = 1;
		free(raw);
		return 0;
	}
	if (n == 0) {
		body_json = dt_new_obj();
	} else {
		body_json = dt_parse(raw, n);
		if (!body_json) {
			out = api_err_body("invalid json", "invalid json");
			api_resp_json(resp, 400, out);
			aik_json_free(out);
			free(raw);
			return 0;
		}
		if (aik_json_typeof(body_json) != AIK_JSON_OBJ) {
			if (!dt_truthy(body_json)) {
				aik_json_free(body_json);
				body_json = dt_new_obj();
			} else {
				aik_json_free(body_json);
				free(raw);
				return -1;
			}
		}
	}
	free(raw);
	raw = NULL;
	paramv = dt_get(body_json, "param");
	{
		const char *ps = aik_json_str(paramv);
		char *t = ps ? dt_strip(ps) : NULL;
		int blank = !is_str(paramv) || !t || !*t;

		free(t);
		if (blank) {
			out = api_err_body(
				"param required",
				"body 需 {\"param\": \"...\", \"value\": N}");
			api_resp_json(resp, 400, out);
			aik_json_free(out);
			aik_json_free(body_json);
			return 0;
		}
	}
	{
		char *t = dt_strip(aik_json_str(paramv));

		snprintf(parambuf, sizeof(parambuf), "%s", t);
		free(t);
	}
	param = parambuf;
	valuev = dt_get(body_json, "value");
	if (valuev && aik_json_typeof(valuev) == AIK_JSON_STR) {
		long long iv;

		if (api_py_int0(aik_json_str(valuev), &iv)) {
			value_i = iv;
			have_value = 1;
		} else {
			have_value = 0;
		}
	} else if (valuev && aik_json_typeof(valuev) == AIK_JSON_INT) {
		value_i = aik_json_int(valuev);
		have_value = 1;
	} else {
		value_copy = valuev ? dt_copy(valuev) : NULL;
	}
	pidv = dt_get(body_json, "pid");
	if (pidv && aik_json_typeof(pidv) == AIK_JSON_STR) {
		long long pv;

		if (api_py_int(aik_json_str(pidv), &pv)) {
			pid_i = pv;
			have_pid = 1;
		}
	} else if (pidv && aik_json_typeof(pidv) == AIK_JSON_INT) {
		pid_i = aik_json_int(pidv);
		have_pid = 1;
	} else {
		pid_keep = pidv;
	}
	confirmv = dt_get(body_json, "confirm");
	confirm = (confirmv && aik_json_typeof(confirmv) == AIK_JSON_BOOL &&
		   aik_json_bool(confirmv));

	arr = read_control_params_json(&count);
	{
		size_t i;

		for (i = 0; i < count; i++) {
			const aik_json *p = aik_json_at(arr, i);

			if (strcmp(aik_json_str(dt_get(p, "name")),
				   param) == 0) {
				pdef = p;
				break;
			}
		}
	}
	/* validate_act */
	if (!pdef) {
		vcode = 404;
		verr_msg = "unknown param（范围限 /proc/ai/control 27 参数，"
			   "不开放 exec）";
	} else if (!have_value || value_copy) {
		vcode = 400;
		verr_msg = "value 必须是整数";
	} else if (value_i < aik_json_int(dt_get(pdef, "min")) ||
		   value_i > aik_json_int(dt_get(pdef, "max"))) {
		char m[128];

		vcode = 400;
		snprintf(m, sizeof(m), "value 超出 [%lld, %lld]",
			 aik_json_int(dt_get(pdef, "min")),
			 aik_json_int(dt_get(pdef, "max")));
		verr_msg = m;
	} else if (aik_json_bool(dt_get(pdef, "task_scoped"))) {
		if (!have_pid || pid_keep ||
		    (have_pid && pid_i <= 0)) {
			vcode = 400;
			verr_msg = "task 作用域参数需带正整数 pid"
				   "（data[0]=pid）";
		}
	}
	if (vcode == 404) {
		out = api_err_body("unknown_param", verr_msg);
		dt_put_str(out, "allowed", "GET /params");
		api_resp_json(resp, 404, out);
		aik_json_free(out);
		aik_json_free(arr);
		aik_json_free(body_json);
		aik_json_free(value_copy);
		return 0;
	}
	if (vcode == 400) {
		out = api_err_body("invalid_value", verr_msg);
		if (pdef) {
			dt_put_int(out, "min",
				   aik_json_int(dt_get(pdef, "min")));
			dt_put_int(out, "max",
				   aik_json_int(dt_get(pdef, "max")));
		}
		api_resp_json(resp, 400, out);
		aik_json_free(out);
		aik_json_free(arr);
		aik_json_free(body_json);
		aik_json_free(value_copy);
		return 0;
	}
	if (!confirm) {
		aik_json *args = dt_new_obj();

		out = api_err_body(
			"need_confirm",
			"受控写需显式确认：重发并带 \"confirm\": true");
		dt_put_str(out, "code", "NEED_CONFIRM");
		dt_put_str(out, "param", param);
		dt_put_int(out, "value", value_i);
		if (have_pid && !pid_keep)
			dt_put_int(out, "pid", pid_i);
		else if (pid_keep)
			dt_put_copy(out, "pid", pid_keep);
		else
			dt_put_null(out, "pid");
		dt_put_copy(out, "current", dt_get(pdef, "current"));
		dt_put_copy(out, "min", dt_get(pdef, "min"));
		dt_put_copy(out, "max", dt_get(pdef, "max"));
		dt_put_copy(out, "default", dt_get(pdef, "default"));
		dt_put_copy(out, "task_scoped", dt_get(pdef, "task_scoped"));
		dt_put_str(args, "param", param);
		dt_put_int(args, "value", value_i);
		if (have_pid && !pid_keep)
			dt_put_int(args, "pid", pid_i);
		else if (pid_keep)
			dt_put_copy(args, "pid", pid_keep);
		else
			dt_put_null(args, "pid");
		dt_put_bool(args, "confirm", 0);
		api_audit_line("api_act", args, "NEED_CONFIRM");
		aik_json_free(args);
		api_resp_json(resp, 409, out);
		aik_json_free(out);
		aik_json_free(arr);
		aik_json_free(body_json);
		aik_json_free(value_copy);
		return 0;
	}
	{
		aik_json *ack = NULL;
		char *nlerr = NULL;
		aik_json *args = dt_new_obj();

		dt_put_str(args, "param", param);
		dt_put_int(args, "value", value_i);
		if (have_pid && !pid_keep)
			dt_put_int(args, "pid", pid_i);
		else if (pid_keep)
			dt_put_copy(args, "pid", pid_keep);
		else
			dt_put_null(args, "pid");
		dt_put_bool(args, "confirm", 1);
		if (api_nl_act(param, value_i,
			       (have_pid && !pid_keep) ? pid_i : 0,
			       &ack, &nlerr) != 0 || !ack) {
			char m[512];

			snprintf(m, sizeof(m), "ERR: %s",
				 nlerr ? nlerr : "?");
			api_audit_line("api_act", args, m);
			out = api_err_body("kernel_rejected",
					   nlerr ? nlerr : "");
			api_resp_json(resp, 502, out);
			aik_json_free(out);
			aik_json_free(args);
			free(nlerr);
			aik_json_free(ack);
			aik_json_free(arr);
			aik_json_free(body_json);
			aik_json_free(value_copy);
			return 0;
		}
		if (aik_json_int(dt_get(ack, "ai_err")) != 0) {
			char m[96];
			char res[96];

			snprintf(m, sizeof(m), "内核 ai_err=%lld"
					  "（策略未执行）",
				 aik_json_int(dt_get(ack, "ai_err")));
			snprintf(res, sizeof(res), "ERR: ai_err=%lld",
				 aik_json_int(dt_get(ack, "ai_err")));
			api_audit_line("api_act", args, res);
			out = api_err_body("kernel_rejected", m);
			dt_put_copy(out, "executed", dt_get(ack, "executed"));
			dt_put_copy(out, "hit", dt_get(ack, "hit"));
			api_resp_json(resp, 502, out);
			aik_json_free(out);
			aik_json_free(args);
			aik_json_free(ack);
			aik_json_free(arr);
			aik_json_free(body_json);
			aik_json_free(value_copy);
			return 0;
		}
		if (aik_json_int(dt_get(ack, "executed")) == 0) {
			api_audit_line("api_act", args, "NOT_APPLIED");
			out = api_err_body(
				"not_applied",
				"策略未命中（0 条执行）：参数未注册或被安全"
				"策略过滤");
			dt_put_int(out, "executed", 0);
			dt_put_int(out, "hit", 0);
			api_resp_json(resp, 409, out);
			aik_json_free(out);
			aik_json_free(args);
			aik_json_free(ack);
			aik_json_free(arr);
			aik_json_free(body_json);
			aik_json_free(value_copy);
			return 0;
		}
		/* 成功:重读 control 取 after */
		{
			size_t count2 = 0;
			aik_json *arr2 = read_control_params_json(&count2);
			const aik_json *after = dt_get(pdef, "current");
			size_t i;

			for (i = 0; i < count2; i++) {
				const aik_json *p = aik_json_at(arr2, i);

				if (strcmp(aik_json_str(dt_get(p, "name")),
					   param) == 0) {
					after = dt_get(p, "current");
					break;
				}
			}
			dt_put_copy(args, "current_after", after);
			api_audit_line("api_act", args, "OK");
			out = dt_new_obj();
			dt_put_bool(out, "ok", 1);
			dt_put_str(out, "param", param);
			dt_put_int(out, "value", value_i);
			if (have_pid && !pid_keep)
				dt_put_int(out, "pid", pid_i);
			else if (pid_keep)
				dt_put_copy(out, "pid", pid_keep);
			else
				dt_put_null(out, "pid");
			dt_put_copy(out, "executed", dt_get(ack, "executed"));
			dt_put_copy(out, "hit", dt_get(ack, "hit"));
			dt_put_copy(out, "current_before",
				    dt_get(pdef, "current"));
			dt_put_copy(out, "current_after", after);
			api_resp_json(resp, 200, out);
			aik_json_free(out);
			aik_json_free(arr2);
		}
		aik_json_free(args);
		aik_json_free(ack);
	}
	aik_json_free(arr);
	aik_json_free(body_json);
	aik_json_free(value_copy);
	return 0;
}
