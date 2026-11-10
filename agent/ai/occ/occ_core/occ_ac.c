/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_ac.c - occ × autocondense 绑定（T9d，OPENCODE-PLAN §9）
 *
 * 传输：local/local_http（纯 HTTP/1.1 + 状态码 + 毫秒超时，与 sme_client
 * 同一底座）——不引 mbedTLS，ac 是本机 127.0.0.1:8762 的明文服务。
 * 链：POST /session/start（水位+transcript 路径）→ GET /check →
 *     POST /judge → POST /begin → 摘要生成 → POST /commit → 换窗。
 *     与 MCP 侧（acmcp.c condense_*）同构，只是把「模型填表」这一步在
 *     进程内用同一个 provider 完成——ac 内核一行未改。
 */
#define _POSIX_C_SOURCE 200809L
#include "occ_ac.h"

#include "occ_sysprompt.h"
#include "occ_tokens.h"

#include "local/local_http.h"
#include "store/store_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

/* 超时（毫秒）：判定/水位快；commit 含 SME 分段去重入库，参考实现给 300s */
#define OCC_AC_T_MS 4000
#define OCC_AC_COMMIT_MS 300000

/* 摘要必填章节（acserv /begin 的 REQUIRED_SECTIONS） */
#define OCC_AC_SECTIONS "目标、已完成、未完成、文件变更清单、恢复指针"
#define OCC_AC_MIN_DIGEST 200

/* 摘要生成的 system 提示（不进会话上下文，只用于这一次填表调用） */
#define OCC_AC_FILL_SYSTEM \
	"你是会话压缩助手。严格按用户给的模板与填写指引逐节作答，" \
	"必填章节标题原样保留、不得改名或删除；内容必须来自给定的会话" \
	"材料，不编造。直接输出填好的整份 markdown，不要任何解释、前言" \
	"或代码围栏。"

/* 判定表生成的 system 提示 */
#define OCC_AC_JUDGE_SYSTEM \
	"你是上下文压缩判定助手。只输出一个 JSON 对象（无围栏、无解释），" \
	"键序固定：task_finished(bool), impact(\"low\"|\"medium\"|" \
	"\"high\"), impact_reason(str), safe_to_compress(bool), reason(str)," \
	" confidence(\"high\"|\"medium\"|\"low\")。"

/* ---- 状态 ---- */
/* 0=off 1=idle 2=working 3=ok */
static int g_ac_state = 0;
static occ_ac_fill_fn g_fill;
static void *g_fill_ud;

int occ_ac_test_set_state(int v)
{
	int old = g_ac_state;

	g_ac_state = v;
	return old;
}

void occ_ac_set_fill(occ_ac_fill_fn fn, void *ud)
{
	g_fill = fn;
	g_fill_ud = ud;
}

int occ_ac_enabled(void)
{
	const char *e = getenv("OCC_AC");

	return !(e && *e && !strcmp(e, "off"));
}

const char *occ_ac_status(void)
{
	if (!occ_ac_enabled())
		return OCC_AC_ST_OFF;	/* 显式禁用同样是「关」 */
	switch (g_ac_state) {
	case 1:
		return OCC_AC_ST_IDLE;
	case 2:
		return OCC_AC_ST_WORKING;
	case 3:
		return OCC_AC_ST_OK;
	default:
		return OCC_AC_ST_OFF;
	}
}

/* ---- 绑定总闸（SME/ac 共用；契约见 occ_ac.h） ---- */

int occ_bind_active(const occ_loop_opts *opts)
{
	const char *e = getenv("OCC_BIND");

	if (e && *e) {
		if (!strcmp(e, "on"))
			return 1;
		if (!strcmp(e, "off"))
			return 0;
	}
	return !opts || opts->llm_call == NULL;
}

/* ---- 会话侧目录 ---- */

const char *occ_sessions_dir(void)
{
	static char dir[512];
	static int done;
	const char *env;
	const char *home;

	if (done)
		return dir[0] ? dir : NULL;
	done = 1;
	env = getenv("OCC_SESSIONS_DIR");
	if (env && *env) {
		snprintf(dir, sizeof(dir), "%s", env);
	} else {
		home = getenv("HOME");
		if (!home || !*home)
			return NULL;
		snprintf(dir, sizeof(dir), "%s/.occ/sessions", home);
	}
	/* 先建父目录（~/.occ 可能不存在）再建本体；已存在不报错 */
	{
		char parent[512];
		char *slash;

		snprintf(parent, sizeof(parent), "%s", dir);
		slash = strrchr(parent, '/');
		if (slash && slash != parent) {
			*slash = '\0';
			(void)mkdir(parent, 0755);
		}
	}
	(void)mkdir(dir, 0755);
	return dir;
}

/* ---- ① transcript JSONL ---- */

static void json_escape_append(char *out, size_t cap, size_t *used,
			       const char *s)
{
	static const char hex[] = "0123456789abcdef";

	if (!s)
		return;
	for (; *s && *used + 8 < cap; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == '"' || c == '\\') {
			out[(*used)++] = '\\';
			out[(*used)++] = (char)c;
		} else if (c == '\n') {
			out[(*used)++] = '\\';
			out[(*used)++] = 'n';
		} else if (c == '\r') {
			out[(*used)++] = '\\';
			out[(*used)++] = 'r';
		} else if (c == '\t') {
			out[(*used)++] = '\\';
			out[(*used)++] = 't';
		} else if (c < 0x20) {
			out[(*used)++] = '\\';
			out[(*used)++] = 'u';
			out[(*used)++] = '0';
			out[(*used)++] = '0';
			out[(*used)++] = hex[c >> 4];
			out[(*used)++] = hex[c & 0xF];
		} else {
			out[(*used)++] = (char)c;
		}
	}
	out[*used] = '\0';
}

int occ_ac_transcript(const char *session_id, const char *role,
		      const char *content, const char *tool,
		      const occ_usage *usage)
{
	const char *dir = occ_sessions_dir();
	char path[600], *line;
	size_t cap, used = 0;
	struct timeval tv;
	FILE *f;

	if (!dir || !session_id || !role)
		return -1;
	cap = (content ? strlen(content) : 0) * 6 + 256;
	line = malloc(cap);
	if (!line)
		return -1;
	gettimeofday(&tv, NULL);
	used = (size_t)snprintf(line, cap,
		"{\"ts\":%lld,\"role\":\"%s\"",
		(long long)tv.tv_sec * 1000 + tv.tv_usec / 1000, role);
	if (used >= cap)
		used = cap - 1;
	if (tool && *tool && used + 16 < cap) {
		used += (size_t)snprintf(line + used, cap - used,
					 ",\"tool\":\"");
		if (used >= cap)
			used = cap - 1;
		json_escape_append(line, cap, &used, tool);
		if (used + 2 < cap) {
			line[used++] = '"';
			line[used] = '\0';
		}
	}
	if (used + 16 < cap) {
		used += (size_t)snprintf(line + used, cap - used,
					 ",\"content\":\"");
		if (used >= cap)
			used = cap - 1;
		json_escape_append(line, cap, &used, content ? content : "");
		if (used + 2 < cap) {
			line[used++] = '"';
			line[used] = '\0';
		}
	}
	if (usage && usage->present && used + 64 < cap) {
		used += (size_t)snprintf(line + used, cap - used,
				",\"usage\":{\"in\":%lld,\"out\":%lld,"
				"\"cache_read\":%lld,\"cache_write\":%lld}",
				usage->input, usage->output,
				usage->cache_read, usage->cache_write);
	}
	if (used + 3 < cap) {
		line[used++] = '}';
		line[used++] = '\n';
		line[used] = '\0';
	}
	if (snprintf(path, sizeof(path), "%s/%s.jsonl", dir, session_id) >=
	    (int)sizeof(path)) {
		free(line);
		return -1;
	}
	f = fopen(path, "ab");
	if (!f) {
		free(line);
		return -1;
	}
	fputs(line, f);
	fclose(f);
	free(line);
	return 0;
}

/* ---- HTTP 基座 ---- */

static const char *ac_base(void)
{
	static char buf[256];
	static int done;
	const char *env;

	if (done)
		return buf;
	done = 1;
	env = getenv("OCC_AC_URL");
	if (!env || !*env)
		env = getenv("AUTOCONDENSE_BASE_URL");
	if (env && *env)
		snprintf(buf, sizeof(buf), "%s", env);
	else
		snprintf(buf, sizeof(buf), "%s", "http://127.0.0.1:8762");
	return buf;
}

/* POST JSON；返回 0=2xx（*out=heap 响应体），-1=传输/状态错 */
static int ac_post(const char *path, const char *body, int timeout_ms,
		   char **out)
{
	char url[512];
	char *resp = NULL, *err = NULL;
	int status = 0;
	int rc;

	if (out)
		*out = NULL;
	if (snprintf(url, sizeof(url), "%s%s", ac_base(), path) >=
	    (int)sizeof(url))
		return -1;
	rc = local_http_post(url, NULL, body ? body : "{}", timeout_ms,
			     &resp, &err, &status);
	free(err);
	if (rc != 0 || status < 200 || status > 299) {
		free(resp);
		return -1;
	}
	if (out)
		*out = resp;
	else
		free(resp);
	return 0;
}

static int ac_get(const char *path, int timeout_ms, char **out, int *status_out)
{
	char url[512];
	char *resp = NULL, *err = NULL;
	int status = 0;
	int rc;

	if (out)
		*out = NULL;
	if (snprintf(url, sizeof(url), "%s%s", ac_base(), path) >=
	    (int)sizeof(url))
		return -1;
	rc = local_http_get(url, timeout_ms, &resp, &err, &status);
	free(err);
	if (status_out)
		*status_out = status;
	if (rc != 0 || status < 200 || status > 299) {
		free(resp);
		return -1;
	}
	if (out)
		*out = resp;
	else
		free(resp);
	return 0;
}

/* 取 400 {"errors":[{"msg":…}]} 的首条人话（ac 契约） */
static void ac_err_line(const char *body, char *err, size_t errlen)
{
	aik_json *root;
	const aik_json *errs, *e0, *msg;

	if (!err || !errlen)
		return;
	err[0] = '\0';
	if (!body)
		return;
	root = aik_json_parse(body, strlen(body), NULL, 0);
	if (!root)
		return;
	errs = aik_json_get(root, "errors");
	e0 = (errs && aik_json_typeof(errs) == AIK_JSON_ARR &&
	      aik_json_count(errs)) ? aik_json_at(errs, 0) : NULL;
	msg = e0 ? aik_json_get(e0, "msg") : NULL;
	if (msg && aik_json_typeof(msg) == AIK_JSON_STR)
		snprintf(err, errlen, "%s", aik_json_str(msg));
	aik_json_free(root);
}

/* ---- ② 水位上报 + 轮询 ---- */

int occ_ac_report(const char *session_id, const char *cwd, long long tokens)
{
	aik_json *body;
	char *dump = NULL, *out = NULL;
	size_t dlen = 0;
	const char *dir;
	char tpath[600];
	int rc;

	if (!session_id)
		return -1;
	body = aik_json_new_obj();
	if (!body)
		return -1;
	dir = occ_sessions_dir();
	tpath[0] = '\0';
	if (dir)
		snprintf(tpath, sizeof(tpath), "%s/%s.jsonl", dir, session_id);
	if (aik_json_obj_put(body, "session_id",
			     aik_json_new_str(session_id)) != 0 ||
	    aik_json_obj_put(body, "cwd",
			     aik_json_new_str(cwd && *cwd ? cwd : ".")) != 0 ||
	    aik_json_obj_put(body, "transcript_path",
			     aik_json_new_str(tpath)) != 0 ||
	    aik_json_obj_put(body, "context_tokens",
			     aik_json_new_int(tokens)) != 0) {
		aik_json_free(body);
		return -1;
	}
	if (aik_json_dump(body, &dump, &dlen) != 0) {
		aik_json_free(body);
		return -1;
	}
	aik_json_free(body);
	rc = ac_post("/session/start", dump, OCC_AC_T_MS, &out);
	free(dump);
	free(out);
	if (rc != 0) {
		g_ac_state = 0;		/* 不可达 → @ac:off（诚实降级） */
		return -1;
	}
	return 0;
}

int occ_ac_check(const char *session_id, char *should, size_t n)
{
	char path[256];
	char *out = NULL;
	aik_json *root;
	const aik_json *v;
	int status = 0;

	if (should && n)
		should[0] = '\0';
	if (!session_id)
		return -1;
	snprintf(path, sizeof(path), "/check?session_id=%s", session_id);
	if (ac_get(path, OCC_AC_T_MS, &out, &status) != 0) {
		g_ac_state = 0;
		return -1;
	}
	root = out ? aik_json_parse(out, strlen(out), NULL, 0) : NULL;
	free(out);
	if (!root) {
		g_ac_state = 0;
		return -1;
	}
	v = aik_json_get(root, "should");
	if (should && n && v && aik_json_typeof(v) == AIK_JSON_STR)
		snprintf(should, n, "%s", aik_json_str(v));
	aik_json_free(root);
	return 0;
}

/* ---- 填表（judge / digest）：注入或缺省走 LLM ---- */

static size_t ac_session_material(occ_ac_turn *t, char *out, size_t cap,
				  size_t per_msg);

struct fill_ctx {
	char *buf;
	size_t len, cap;
	int oom;
};

static void fill_cb(const occ_event *ev, void *ud)
{
	struct fill_ctx *c = ud;

	if (!ev || ev->type != OCC_EV_TEXT_DELTA || !ev->text)
		return;
	{
		size_t n = strlen(ev->text);

		if (c->len + n + 1 > c->cap) {
			size_t nc = c->cap ? c->cap : 4096;
			char *nb;

			while (c->len + n + 1 > nc)
				nc *= 2;
			nb = realloc(c->buf, nc);
			if (!nb) {
				c->oom = 1;
				return;
			}
			c->buf = nb;
			c->cap = nc;
		}
		memcpy(c->buf + c->len, ev->text, n + 1);
		c->len += n;
	}
}

static int fill_default(occ_ac_turn *t, const char *prompt, char **out)
{
	occ_llm_req req;
	occ_msg m;
	struct fill_ctx c;
	char *llm_err = NULL;
	int rc;

	memset(&c, 0, sizeof(c));
	memset(&req, 0, sizeof(req));
	memset(&m, 0, sizeof(m));
	if (!t || !t->p)
		return -1;
	req.proto = t->p->proto;
	req.model = t->p->model;
	req.system = OCC_AC_FILL_SYSTEM;
	m.role = OCC_ROLE_USER;
	m.text = prompt;
	req.msgs = &m;
	req.nmsgs = 1;
	if (t->call_fn)
		rc = t->call_fn(t->p, &req, fill_cb, &c, &llm_err);
	else
		rc = occ_llm_call(t->p, &req, fill_cb, &c, &llm_err);
	free(llm_err);
	if (rc != 0 || c.oom || !c.buf || !c.buf[0]) {
		free(c.buf);
		return -1;
	}
	*out = c.buf;
	return 0;
}

/* 从模型输出里抠出第一个平衡的 {…}（容错围栏/前言） */
static char *extract_json_obj(const char *s)
{
	int depth = 0, in_str = 0, esc = 0;
	const char *start = NULL, *p;

	if (!s)
		return NULL;
	for (p = s; *p; p++) {
		if (!in_str && *p == '{') {
			if (!depth)
				start = p;
			depth++;
		} else if (!in_str && *p == '}') {
			depth--;
			if (depth == 0 && start) {
				size_t n = (size_t)(p - start) + 1;
				char *o = malloc(n + 1);

				if (o) {
					memcpy(o, start, n);
					o[n] = '\0';
				}
				return o;
			}
		}
		if (in_str && esc)
			esc = 0;
		else if (in_str && *p == '\\')
			esc = 1;
		else if (*p == '"')
			in_str = !in_str;
	}
	return NULL;
}

static int fill_prompt(occ_ac_turn *t, const char *system_hint,
		       const char *prompt, char **out)
{
	(void)system_hint;		/* 缺省 fill 的 system 固定（见上） */
	if (g_fill)
		return g_fill(g_fill_ud, prompt, out);
	return fill_default(t, prompt, out);
}

/* ---- /judge 判定 ---- */

/* 保守兜底：解析失败绝不强行压缩（impact=medium + safe=false → 矩阵必
 * DEFERRED）——诚实降级，不谎报「可以压」。 */
static const char JUDGE_FALLBACK[] =
	"{\"task_finished\":true,\"impact\":\"medium\","
	"\"impact_reason\":\"判定输出解析失败，保守不压缩\","
	"\"safe_to_compress\":false,"
	"\"reason\":\"模型未返回合法判定 JSON，本轮不压缩\","
	"\"confidence\":\"low\"}";

static int ac_judge(occ_ac_turn *t, const char *context, char *err,
		    size_t errlen, int *compress_now)
{
	char prompt[12288];
	char material[6144];
	char *raw = NULL, *json = NULL, *body = NULL, *resp = NULL;
	aik_json *root = NULL;
	const aik_json *dec;
	int rc = -1;

	*compress_now = 0;
	ac_session_material(t, material, sizeof(material), 400);
	snprintf(prompt, sizeof(prompt),
		 "宿主事实：本轮回合已正常收口（无未执行工具调用、无未保存"
		 "状态——会话已 durable 落 SQLite）。请据此填写压缩判定表。\n"
		 "【会话材料（截断）】\n%.6000s\n"
		 "最近一次回复（供判断现在压缩对工作的影响）：\n%.600s\n",
		 material[0] ? material : "（无）",
		 context ? context : "（无）");
	if (fill_prompt(t, OCC_AC_JUDGE_SYSTEM, prompt, &raw) != 0 || !raw) {
		snprintf(err, errlen, "judge: 生成判定失败");
		return -1;
	}
	json = extract_json_obj(raw);
	free(raw);
	if (!json)
		json = strdup(JUDGE_FALLBACK);
	if (!json) {
		snprintf(err, errlen, "judge: oom");
		return -1;
	}
	root = aik_json_parse(json, strlen(json), NULL, 0);
	free(json);
	if (!root) {
		snprintf(err, errlen, "judge: 判定 JSON 非法");
		return -1;
	}
	body = NULL;
	{
		size_t dlen = 0;

		if (aik_json_dump(root, &body, &dlen) != 0)
			body = NULL;
	}
	aik_json_free(root);
	if (!body) {
		snprintf(err, errlen, "judge: oom");
		return -1;
	}
	/* 请求体：{"session_id","cwd","verdict":{…}} */
	{
		aik_json *req = aik_json_new_obj();
		aik_json *v = aik_json_parse(body, strlen(body), NULL, 0);
		char *dump = NULL;
		size_t dlen = 0;

		free(body);
		if (!req || !v) {
			aik_json_free(req);
			aik_json_free(v);
			snprintf(err, errlen, "judge: oom");
			return -1;
		}
		if (aik_json_obj_put(req, "session_id",
				     aik_json_new_str(t->session_id)) != 0 ||
		    aik_json_obj_put(req, "cwd",
				     aik_json_new_str(t->cwd && *t->cwd ?
						      t->cwd : ".")) != 0 ||
		    aik_json_obj_put(req, "verdict", v) != 0) {
			aik_json_free(req);
			aik_json_free(v);
			snprintf(err, errlen, "judge: oom");
			return -1;
		}
		if (aik_json_dump(req, &dump, &dlen) != 0)
			dump = NULL;
		aik_json_free(req);
		if (!dump) {
			snprintf(err, errlen, "judge: oom");
			return -1;
		}
		rc = ac_post("/judge", dump, OCC_AC_T_MS, &resp);
		free(dump);
	}
	if (rc != 0) {
		snprintf(err, errlen, "judge: ac 不可达或拒绝（HTTP 非 2xx）");
		g_ac_state = 0;
		return -1;
	}
	root = aik_json_parse(resp, strlen(resp), NULL, 0);
	free(resp);
	if (!root) {
		snprintf(err, errlen, "judge: 响应非法");
		return -1;
	}
	dec = aik_json_get(root, "decision");
	if (dec && aik_json_typeof(dec) == AIK_JSON_STR &&
	    !strcmp(aik_json_str(dec), "COMPRESS_NOW"))
		*compress_now = 1;
	aik_json_free(root);
	return 0;
}

/* ---- 会话材料（填表用：模型在**新调用**里没有本会话上下文，必须
 * 由宿主把可见消息喂进去——否则摘要/判定全是空话，等于桩） ---- */
static size_t ac_session_material(occ_ac_turn *t, char *out, size_t cap,
				  size_t per_msg)
{
	occ_msg_row *rows = NULL;
	size_t n = 0, i, used = 0;

	out[0] = '\0';
	if (!t || !t->db || !t->session_id || !cap)
		return 0;
	if (occ_msg_list(t->db, t->session_id, &rows, &n, NULL, 0) != 0)
		return 0;
	for (i = 0; i < n && used + 8 < cap; i++) {
		const char *tag;
		const char *txt;
		size_t tl;
		int ln;

		if (rows[i].reverted)
			continue;		/* 已被换窗隐藏的不算材料 */
		if (!strcmp(rows[i].role, "system"))
			continue;		/* occ 注记不进材料 */
		if (!strcmp(rows[i].role, "user"))
			tag = "用户";
		else if (!strcmp(rows[i].role, "assistant"))
			tag = "助手";
		else
			tag = "工具";
		txt = rows[i].text ? rows[i].text : "";
		tl = strlen(txt);
		if (tl > per_msg)
			tl = per_msg;
		ln = snprintf(out + used, cap - used, "[%s] %.*s\n", tag,
			      (int)tl, txt);
		if (ln < 0 || (size_t)ln >= cap - used)
			break;
		used += (size_t)ln;
	}
	occ_msg_rows_free(rows, n);
	return used;
}

/* ---- /begin → 摘要 → /commit ---- */

static int ac_commit(occ_ac_turn *t, const char *digest, char *err,
		     size_t errlen)
{
	aik_json *req;
	char *dump = NULL, *resp = NULL;
	size_t dlen = 0;
	int rc;

	req = aik_json_new_obj();
	if (!req)
		return -1;
	if (aik_json_obj_put(req, "session_id",
			     aik_json_new_str(t->session_id)) != 0 ||
	    aik_json_obj_put(req, "cwd",
			     aik_json_new_str(t->cwd && *t->cwd ? t->cwd :
					      ".")) != 0 ||
	    aik_json_obj_put(req, "digest_md", aik_json_new_str(digest)) != 0 ||
	    aik_json_obj_put(req, "trigger",
			     aik_json_new_str(t->force ? "user" :
					      "water_level")) != 0) {
		aik_json_free(req);
		snprintf(err, errlen, "commit: oom");
		return -1;
	}
	if (aik_json_dump(req, &dump, &dlen) != 0)
		dump = NULL;
	aik_json_free(req);
	if (!dump) {
		snprintf(err, errlen, "commit: oom");
		return -1;
	}
	rc = ac_post("/commit", dump, OCC_AC_COMMIT_MS, &resp);
	free(dump);
	if (rc != 0) {
		ac_err_line(resp, err, errlen);
		if (!err[0])
			snprintf(err, errlen,
				 "commit: ac 不可达或摘要校验未通过");
		free(resp);
		return -1;
	}
	free(resp);
	return 0;
}

static int ac_begin_and_digest(occ_ac_turn *t, char *err,
			       size_t errlen, char **digest_out)
{
	aik_json *req, *root;
	char *dump = NULL, *resp = NULL;
	size_t dlen = 0;
	const aik_json *tpl, *guide, *secs, *prev;
	char prompt[65536];
	size_t used = 0;
	char *digest = NULL;
	int rc;

	*digest_out = NULL;
	req = aik_json_new_obj();
	if (!req)
		return -1;
	if (aik_json_obj_put(req, "session_id",
			     aik_json_new_str(t->session_id)) != 0 ||
	    aik_json_obj_put(req, "cwd",
			     aik_json_new_str(t->cwd && *t->cwd ? t->cwd :
					      ".")) != 0) {
		aik_json_free(req);
		return -1;
	}
	if (aik_json_dump(req, &dump, &dlen) != 0)
		dump = NULL;
	aik_json_free(req);
	if (!dump)
		return -1;
	rc = ac_post("/begin", dump, OCC_AC_T_MS, &resp);
	free(dump);
	if (rc != 0) {
		snprintf(err, errlen, "begin: ac 不可达或拒绝");
		g_ac_state = 0;
		return -1;
	}
	root = aik_json_parse(resp, strlen(resp), NULL, 0);
	free(resp);
	if (!root) {
		snprintf(err, errlen, "begin: 响应非法");
		return -1;
	}
	tpl = aik_json_get(root, "template");
	guide = aik_json_get(root, "guidance");
	secs = aik_json_get(root, "required_sections");
	prev = aik_json_get(root, "previous_digest");
	{
		char material[24576];

		ac_session_material(t, material, sizeof(material), 1200);
		used = (size_t)snprintf(prompt, sizeof(prompt),
			"【会话材料】（本会话当前可见消息，摘要必须从这里取事实）\n"
			"%s\n"
			"请基于上面的会话材料填写下面的摘要模板。\n"
			"【填写指引】\n%s\n"
			"【必填章节】%s\n【模板】\n%s\n",
			material[0] ? material : "（无）",
			guide && aik_json_typeof(guide) == AIK_JSON_STR ?
			aik_json_str(guide) : "（无）",
			OCC_AC_SECTIONS,
			tpl && aik_json_typeof(tpl) == AIK_JSON_STR ?
			aik_json_str(tpl) : "（无模板）");
	}
	if (prev && aik_json_typeof(prev) == AIK_JSON_STR &&
	    aik_json_str(prev) && aik_json_str(prev)[0] &&
	    used + 1200 < sizeof(prompt)) {
		used += (size_t)snprintf(prompt + used, sizeof(prompt) - used,
				"\n【上一份摘要（增量模式，只追加变化）】\n%.1000s\n",
				aik_json_str(prev));
	}
	if (used + 160 < sizeof(prompt))
		snprintf(prompt + used, sizeof(prompt) - used,
			 "\n输出要求：保留上述全部必填章节标题原样；总长度"
			 "不少于 %d 字符；直接输出整份 markdown。\n",
			 OCC_AC_MIN_DIGEST);
	aik_json_free(root);
	(void)secs;

	if (fill_prompt(t, NULL, prompt, &digest) != 0 || !digest) {
		snprintf(err, errlen, "digest: 摘要生成失败");
		return -1;
	}
	*digest_out = digest;
	return 0;
}

/* ---- ③ 换窗 ---- */

int occ_ac_apply_digest(occ_db *db, const char *session_id,
			const char *digest, char *err, size_t errlen)
{
	char *text = NULL;
	char note_id[OCC_ID_LEN];
	char *ids_json = NULL;
	size_t cap, used = 0;
	occ_msg_row *rows = NULL;
	size_t n = 0, i;
	long long changed = 0;
	long long baseline;
	char werr[160];

	if (!db || !session_id || !digest || !*digest) {
		if (err && errlen)
			snprintf(err, errlen, "apply_digest: bad args");
		return -1;
	}
	text = malloc(strlen(digest) + sizeof(OCC_DIGEST_PREFIX) + 8);
	if (!text) {
		if (err && errlen)
			snprintf(err, errlen, "apply_digest: oom");
		return -1;
	}
	strcpy(text, OCC_DIGEST_PREFIX);
	strcat(text, digest);

	/* 1) 先落摘要注记（中途崩溃时历史仍在——安全序） */
	if (occ_msg_add_note(db, session_id, text, note_id, sizeof(note_id),
			     err, errlen)) {
		free(text);
		return -1;
	}
	/* 2) 摘要前全部消息置 reverted=1（上下文过滤既有机制，不删行） */
	if (occ_msg_list(db, session_id, &rows, &n, err, errlen)) {
		free(text);
		return -1;
	}
	cap = n * (OCC_ID_LEN + 4) + 4;
	ids_json = malloc(cap);
	if (!ids_json) {
		occ_msg_rows_free(rows, n);
		free(text);
		if (err && errlen)
			snprintf(err, errlen, "apply_digest: oom");
		return -1;
	}
	used = (size_t)snprintf(ids_json, cap, "[");
	for (i = 0; i < n; i++) {
		int first = (used == 1);
		int ln;

		if (!strcmp(rows[i].id, note_id))
			continue;
		ln = snprintf(ids_json + used, cap - used, "%s\"%s\"",
			      first ? "" : ",", rows[i].id);
		if (ln < 0 || (size_t)ln >= cap - used)
			break;
		used += (size_t)ln;
	}
	snprintf(ids_json + used, cap - used, "]");
	occ_msg_rows_free(rows, n);
	if (used > 2 &&
	    occ_msgs_set_reverted(db, session_id, ids_json, 1, &changed,
				  err, errlen)) {
		free(ids_json);
		free(text);
		return -1;
	}
	free(ids_json);
	/* 3) token 账本重置为新基线（system + 摘要的 len/4 估算） */
	baseline = occ_tokens_estimate_len(OCC_SYSTEM_PROMPT) +
		   occ_tokens_estimate_len(text);
	if (occ_session_set_tokens(db, session_id, baseline, 1, werr,
				   sizeof(werr))) {
		if (err && errlen)
			snprintf(err, errlen, "apply_digest: 账本重置失败（%s）",
				 werr);
		free(text);
		return -1;
	}
	/* 4) occ_window → digest */
	if (occ_session_set_window_digest(db, session_id, note_id, werr,
					  sizeof(werr))) {
		if (err && errlen)
			snprintf(err, errlen, "apply_digest: 窗口标记失败（%s）",
				 werr);
		free(text);
		return -1;
	}
	free(text);
	return 0;
}

/* ---- 驱动：/check → judge → begin → digest → commit → 换窗 ---- */

static int ac_run_chain(occ_ac_turn *t, int *compacted, char *err,
			size_t errlen)
{
	char *digest = NULL;
	int rc;

	g_ac_state = 2;			/* @ac:working */
	if (ac_begin_and_digest(t, err, errlen, &digest) != 0) {
		g_ac_state = 1;
		return -1;
	}
	if (strlen(digest) < OCC_AC_MIN_DIGEST) {
		snprintf(err, errlen,
			 "digest: 摘要过短（%zu < %d 字符），本轮不换窗",
			 strlen(digest), OCC_AC_MIN_DIGEST);
		free(digest);
		g_ac_state = 1;
		return -1;
	}
	rc = ac_commit(t, digest, err, errlen);
	if (rc != 0) {
		free(digest);
		g_ac_state = 1;
		return -1;
	}
	rc = occ_ac_apply_digest(t->db, t->session_id, digest, err, errlen);
	if (rc == 0)
		t->digest_chars = (long long)strlen(digest);
	free(digest);
	if (rc != 0) {
		g_ac_state = 1;
		return -1;
	}
	g_ac_state = 3;			/* @ac:ok */
	if (compacted)
		*compacted = 1;
	return 0;
}

int occ_ac_turn_end(occ_ac_turn *t, int *compacted, char *err,
		    size_t errlen)
{
	char should[32];
	int compress_now = 0;

	if (compacted)
		*compacted = 0;
	if (err && errlen)
		err[0] = '\0';
	if (!occ_ac_enabled() || !t || !t->session_id || !t->db)
		return 0;
	/* ② 水位 + 轮询（每轮结束必查——「每次大消息后」） */
	if (occ_ac_report(t->session_id, t->cwd, t->tokens) != 0)
		return 0;		/* 不可达 → @ac:off，诚实降级不阻塞 */
	if (t->force)
		return ac_run_chain(t, compacted, err, errlen);
	if (occ_ac_check(t->session_id, should, sizeof(should)) != 0)
		return 0;
	if (strcmp(should, "JUDGE") != 0) {
		g_ac_state = 1;		/* @ac:idle */
		return 0;
	}
	if (ac_judge(t, t->context, err, errlen, &compress_now) != 0)
		return 0;		/* 判定失败=不压缩（已在 err 记因） */
	if (!compress_now) {
		g_ac_state = 1;
		if (err && errlen)
			err[0] = '\0';
		return 0;
	}
	return ac_run_chain(t, compacted, err, errlen);
}

int occ_ac_compact_now(occ_ac_turn *t, char *err, size_t errlen)
{
	int compacted = 0;
	occ_ac_turn tmp;

	if (!t)
		return -1;
	tmp = *t;
	tmp.force = 1;
	if (err && errlen)
		err[0] = '\0';
	if (!occ_ac_enabled())
		return 0;
	if (occ_ac_report(tmp.session_id, tmp.cwd, tmp.tokens) != 0) {
		snprintf(err, errlen, "compact: ac 不可达（@ac:off）");
		return -1;
	}
	return ac_run_chain(&tmp, &compacted, err, errlen);
}
