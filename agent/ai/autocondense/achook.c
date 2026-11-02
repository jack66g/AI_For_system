/* SPDX-License-Identifier: GPL-2.0 */
/*
 * achook.c - T5e autocondense 宿主钩子适配器（见 achook.h）
 */
#define _POSIX_C_SOURCE 200809L

#include "autocondense/achook.h"

#include "autocondense/acmcp.h"
#include "autocondense/acconfig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define HOOK_TIMEOUT_S 3
#define LATCH_WINDOW_S (15 * 60)
#define MAX_ADDITIONAL_CONTEXT 9000

static const char *const HOOK_FIELDS[] = {
	"session_id", "cwd", "transcript_path", "source",
	"tool_name", "tool_input", "context_tokens"
};

static void hook_log(const char *event, const char *msg)
{
	FILE *f = fopen("/tmp/autocondense_hook.log", "a");
	time_t now = time(NULL);
	struct tm tmv;
	char ts[64];

	if (!f)
		return;
	localtime_r(&now, &tmv);
	strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tmv);
	fprintf(f, "%s %s %s\n", ts, event ? event : "-", msg);
	fclose(f);
}

/* Python json.dumps(ensure_ascii=False) 默认分隔符（", " / ": "） */
static void emit_object(const char *const *keys, const char **values,
			size_t n)
{
	size_t i;

	fputs("{", stdout);
	for (i = 0; i < n; i++) {
		aik_json *kn;
		aik_json *vn;
		char *kt = NULL;
		char *vt = NULL;
		size_t kl = 0, vl = 0;

		if (i)
			fputs(", ", stdout);
		kn = aik_json_new_str(keys[i]);
		vn = aik_json_new_str(values[i] ? values[i] : "");
		if (kn)
			(void)aik_json_dump(kn, &kt, &kl);
		if (vn)
			(void)aik_json_dump(vn, &vt, &vl);
		fputs(kt ? kt : "\"\"", stdout);
		fputs(": ", stdout);
		fputs(vt ? vt : "\"\"", stdout);
		free(kt);
		free(vt);
		aik_json_free(kn);
		aik_json_free(vn);
	}
	fputs("}\n", stdout);
	fflush(stdout);
}

/* UTF-8 码点截断：返回 malloc 的前 max_cp 个码点 */
static char *utf8_prefix(const char *s, size_t max_cp)
{
	size_t i = 0, cp = 0;

	while (s[i]) {
		unsigned char c = (unsigned char)s[i];
		size_t len = 1;

		if (c >= 0xF0)
			len = 4;
		else if (c >= 0xE0)
			len = 3;
		else if (c >= 0xC0)
			len = 2;
		if (cp == max_cp)
			break;
		i += len;
		cp++;
	}
	{
		char *out = malloc(i + 1);

		if (out) {
			memcpy(out, s, i);
			out[i] = '\0';
		}
		return out;
	}
}

static size_t utf8_len(const char *s)
{
	size_t i = 0, cp = 0;

	while (s[i]) {
		unsigned char c = (unsigned char)s[i];

		if (c >= 0xF0)
			i += 4;
		else if (c >= 0xE0)
			i += 3;
		else if (c >= 0xC0)
			i += 2;
		else
			i += 1;
		cp++;
	}
	return cp;
}

static int latch_allows_and_arm(const char *session_id)
{
	char dir[1024];
	char path[1400];
	char safe[128];
	size_t i, n = 0;
	time_t now = time(NULL);
	FILE *f;
	char buf[512];
	size_t blen;

	acmcp_data_dir(dir, sizeof(dir));
	snprintf(path, sizeof(path), "%s/hook-latch", dir);
	(void)mkdir(path, 0755);
	for (i = 0; session_id[i] && n < 100; i++) {
		unsigned char c = (unsigned char)session_id[i];

		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '_' || c == '-')
			safe[n++] = (char)c;
		else
			safe[n++] = '_';
	}
	if (n == 0)
		snprintf(safe, sizeof(safe), "unknown");
	else
		safe[n] = '\0';
	snprintf(path, sizeof(path), "%s/hook-latch/%s.json", dir, safe);
	f = fopen(path, "rb");
	if (f) {
		blen = fread(buf, 1, sizeof(buf) - 1, f);
		fclose(f);
		buf[blen] = '\0';
		{
			char *p = strstr(buf, "\"last_block_ts\"");

			if (p) {
				p = strchr(p, ':');
				if (p) {
					double last = strtod(p + 1, NULL);

					if ((double)now - last <
					    (double)LATCH_WINDOW_S)
						return 0;
				}
			}
		}
	}
	{
		char payload[64];

		snprintf(payload, sizeof(payload),
			 "{\"last_block_ts\": %lld}", (long long)now);
		if (ac_atomic_write_text(path, payload, strlen(payload)) != 0)
			return 1;	/* 闩锁失败不拦 block */
	}
	return 1;
}

static void on_session_start(const aik_json *body)
{
	const aik_json *ac = aik_json_get(body, "additional_context");
	const aik_json *text;
	const char *full;
	char *out;

	if (!ac || aik_json_typeof(ac) != AIK_JSON_OBJ)
		return;
	text = aik_json_get(ac, "text");
	if (!text || aik_json_typeof(text) != AIK_JSON_STR ||
	    !*aik_json_str(text))
		return;
	full = aik_json_str(text);
	{
		const aik_json *tr = aik_json_get(ac, "truncated");
		const aik_json *ff = aik_json_get(ac, "full_file");
		int truncated = tr && aik_json_typeof(tr) == AIK_JSON_BOOL &&
				aik_json_bool(tr);
		char hint[1200];

		if (utf8_len(full) > MAX_ADDITIONAL_CONTEXT || truncated) {
			char *prefix;
			size_t hint_cp;

			snprintf(hint, sizeof(hint),
				 "\n（完整快照：%s，需要时用 Read 读取）",
				 ff && aik_json_typeof(ff) == AIK_JSON_STR
					 ? aik_json_str(ff) : "None");
			hint_cp = utf8_len(hint);
			{
				size_t room = hint_cp < MAX_ADDITIONAL_CONTEXT
					      ? MAX_ADDITIONAL_CONTEXT - hint_cp
					      : 0;
				prefix = utf8_prefix(full, room);
			}
			{
				size_t need = strlen(prefix ? prefix : "") +
					      strlen(hint) + 1;
				char *joined = malloc(need);

				if (joined) {
					snprintf(joined, need, "%s%s",
						 prefix ? prefix : "", hint);
					prefix = joined;
				}
			}
			out = prefix;
		} else {
			out = strdup(full);
		}
	}
	if (out) {
		const char *keys[] = { "additionalContext" };
		const char *vals[] = { out };

		emit_object(keys, vals, 1);
		free(out);
	}
}

static void on_stop(const aik_json *body, const aik_json *data)
{
	const aik_json *should;
	const aik_json *inst;
	const aik_json *sid;
	const char *sid_s;

	if (!body || aik_json_typeof(body) != AIK_JSON_OBJ)
		return;
	should = aik_json_get(body, "should");
	inst = aik_json_get(body, "instruction");
	if ((should && aik_json_typeof(should) == AIK_JSON_STR &&
	     strcmp(aik_json_str(should), "NO") == 0) ||
	    !inst || aik_json_typeof(inst) != AIK_JSON_STR ||
	    !*aik_json_str(inst))
		return;
	sid = data && aik_json_typeof(data) == AIK_JSON_OBJ
		      ? aik_json_get(data, "session_id") : NULL;
	if (!sid || aik_json_typeof(sid) != AIK_JSON_STR ||
	    !*aik_json_str(sid))
		return;
	sid_s = aik_json_str(sid);
	if (!latch_allows_and_arm(sid_s)) {
		hook_log("Stop", "闩锁生效：15 分钟内已 block 过");
		return;
	}
	{
		const char *keys[] = { "decision", "reason" };
		const char *vals[] = { "block", aik_json_str(inst) };

		emit_object(keys, vals, 2);
	}
}

int achook_run(const char *event)
{
	static const char *const valid[] = {
		"PostToolUse", "Stop", "SessionStart", "PreCompact",
		"PostToolUseFailure"
	};
	size_t i;
	int ok = 0;
	char *raw = NULL;
	size_t rawlen = 0, cap = 0;
	aik_json *data = NULL;

	if (!event || !*event) {
		hook_log("-", "未指定事件名，忽略");
		return 0;
	}
	for (i = 0; i < sizeof(valid) / sizeof(valid[0]); i++)
		if (strcmp(event, valid[i]) == 0)
			ok = 1;
	if (!ok) {
		hook_log(event, "未知事件名，忽略");
		return 0;
	}
	for (;;) {
		char buf[8192];
		size_t n = fread(buf, 1, sizeof(buf), stdin);

		if (n == 0)
			break;
		if (rawlen + n + 1 > cap) {
			size_t ncap = cap ? cap * 2 : 8192;
			char *nr;

			while (ncap < rawlen + n + 1)
				ncap *= 2;
			nr = realloc(raw, ncap);
			if (!nr) {
				free(raw);
				return 0;
			}
			raw = nr;
			cap = ncap;
		}
		memcpy(raw + rawlen, buf, n);
		rawlen += n;
	}
	if (raw) {
		raw[rawlen] = '\0';
		data = aik_json_parse(raw, rawlen, NULL, 0);
	}
	{
		aik_json *payload = aik_json_new_obj();
		struct ac_http_resp resp;
		char err[256];
		int rc;

		if (!payload) {
			free(raw);
			aik_json_free(data);
			return 0;
		}
		aik_json_obj_put(payload, "event", aik_json_new_str(event));
		for (i = 0; i < sizeof(HOOK_FIELDS) / sizeof(HOOK_FIELDS[0]);
		     i++) {
			const aik_json *v;

			if (!data || aik_json_typeof(data) != AIK_JSON_OBJ)
				break;
			v = aik_json_get(data, HOOK_FIELDS[i]);
			if (v && aik_json_typeof(v) != AIK_JSON_NULL) {
				char *dump = NULL;
				size_t len = 0;
				aik_json *copy = NULL;

				if (aik_json_dump(v, &dump, &len) == 0) {
					copy = aik_json_parse(dump, len, NULL,
							      0);
					free(dump);
				}
				if (copy)
					aik_json_obj_put(payload,
							 HOOK_FIELDS[i], copy);
			}
		}
		ac_http_set_timeout(HOOK_TIMEOUT_S);
		rc = ac_http_call("POST", "/events/hook", payload, &resp, err,
				  sizeof(err));
		aik_json_free(payload);
		if (rc == 0 && resp.status >= 200 && resp.status < 300) {
			aik_json *body = aik_json_parse(resp.body, resp.len,
							NULL, 0);

			if (body) {
				if (strcmp(event, "SessionStart") == 0)
					on_session_start(body);
				else if (strcmp(event, "Stop") == 0)
					on_stop(body, data);
				aik_json_free(body);
			}
		} else if (rc != 0) {
			hook_log(event, err);
		} else {
			hook_log(event, "服务返回非 2xx，静默");
		}
		ac_http_resp_free(&resp);
	}
	free(raw);
	aik_json_free(data);
	return 0;
}
