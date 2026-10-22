// SPDX-License-Identifier: GPL-2.0
/*
 * cmd_trace.c - 轨迹日志查询/导出命令
 *
 * 用法：
 *   trace stats
 *   trace dump --session <id|name> [--format jsonl|json] [--since T]
 *              [--until T] [--out FILE]
 *   trace export [--since T] [--until T] [--session S] [--out FILE]
 *
 * export 输出训练用扁平化 JSONL：一行一个回合
 *   {"session_id":..,"turn":N,"ts":..,"messages":[{role:user,...},
 *    {role:assistant,...}],"tools_used":[..],"outcome":..,"duration_ms":..}
 *
 * 只读：不修改任何轨迹文件。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "ai_commands.h"
#include "ai_trace.h"
#include "ai_json_util.h"

struct file_entry {
	char *name;
	time_t mtime;
};

struct file_list {
	struct file_entry *e;
	int n;
	int cap;
};

struct tool_count {
	char name[64];
	int count;
};

struct stats {
	unsigned long long events;
	unsigned long long sessions;
	unsigned long long turns;
	unsigned long long requests;
	unsigned long long tool_calls;
	unsigned long long prompt_tokens;
	unsigned long long completion_tokens;
	unsigned long long degraded;
	unsigned long long errors;
	struct tool_count *tools;
	int ntools;
	int captools;
};

static void file_list_free(struct file_list *fl)
{
	int i;

	for (i = 0; i < fl->n; i++)
		free(fl->e[i].name);
	free(fl->e);
	memset(fl, 0, sizeof(*fl));
}

/* 按 mtime 升序（轮转文件 .1 比 base 旧；文件名排序不可靠） */
static int name_cmp(const void *a, const void *b)
{
	const struct file_entry *ea = a;
	const struct file_entry *eb = b;

	if (ea->mtime != eb->mtime)
		return ea->mtime < eb->mtime ? -1 : 1;
	return strcmp(ea->name, eb->name);
}

static int list_trace_files(const char *dir, struct file_list *fl)
{
	DIR *d;
	struct dirent *de;

	memset(fl, 0, sizeof(*fl));
	d = opendir(dir);
	if (!d)
		return -1;
	while ((de = readdir(d)) != NULL) {
		size_t nl = strlen(de->d_name);
		char full[4096];
		struct stat st;

		if (strncmp(de->d_name, "trace-", 6) != 0)
			continue;
		if (nl < 6 || strcmp(de->d_name + nl - 6, ".jsonl") != 0)
			continue;
		snprintf(full, sizeof(full), "%s/%s", dir, de->d_name);
		if (stat(full, &st) != 0 || st.st_size == 0)
			continue;
		if (fl->n == fl->cap) {
			int nc = fl->cap ? fl->cap * 2 : 32;
			struct file_entry *ne = realloc(fl->e,
						sizeof(*ne) * (size_t)nc);

			if (!ne)
				break;
			fl->e = ne;
			fl->cap = nc;
		}
		fl->e[fl->n].name = strdup(de->d_name);
		if (!fl->e[fl->n].name)
			break;
		fl->e[fl->n].mtime = st.st_mtime;
		fl->n++;
	}
	closedir(d);
	qsort(fl->e, (size_t)fl->n, sizeof(fl->e[0]), name_cmp);
	return 0;
}

/* 逐行回调；line 已去掉换行 */
typedef int (*line_cb)(const char *line, size_t len, void *ud);

static int foreach_line(const char *dir, line_cb cb, void *ud)
{
	struct file_list fl;
	int i;

	if (list_trace_files(dir, &fl) != 0)
		return -1;
	for (i = 0; i < fl.n; i++) {
		char path[4096];
		FILE *fp;
		char *line = NULL;
		size_t cap = 0;
		ssize_t n;

		snprintf(path, sizeof(path), "%s/%s", dir, fl.e[i].name);
		fp = fopen(path, "r");
		if (!fp)
			continue;
		while ((n = getline(&line, &cap, fp)) > 0) {
			while (n > 0 && (line[n - 1] == '\n' ||
					 line[n - 1] == '\r'))
				line[--n] = '\0';
			if (n > 0 && cb(line, (size_t)n, ud) != 0)
				break;
		}
		free(line);
		fclose(fp);
	}
	file_list_free(&fl);
	return 0;
}

/* 解析一行对象；返回 1=对象，0=非对象/坏行 */
static int parse_line(const char *line, size_t len, const char **obj,
		      size_t *obj_len)
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
	if (type != AI_JSON_OBJ)
		return 0;
	*obj = tok;
	*obj_len = tlen;
	return 1;
}

static char *get_str(const char *obj, size_t obj_len, const char *key)
{
	const char *v = NULL;
	size_t vl = 0;
	int type = 0;

	if (ai_json_obj_get(obj, obj_len, key, &v, &vl, &type) != 1)
		return NULL;
	if (type != AI_JSON_STR)
		return NULL;
	return ai_json_strdup_str(v, vl);
}

static long long get_int(const char *obj, size_t obj_len, const char *key)
{
	const char *v = NULL;
	size_t vl = 0;
	int type = 0;

	if (ai_json_obj_get(obj, obj_len, key, &v, &vl, &type) != 1)
		return 0;
	if (type != AI_JSON_NUM)
		return 0;
	return ai_json_ll(v, vl);
}

static int ts_ge(const char *ts, const char *since)
{
	if (!since || !since[0])
		return 1;
	return strncmp(ts, since, strlen(since)) >= 0;
}

static int ts_le(const char *ts, const char *until)
{
	if (!until || !until[0])
		return 1;
	return strncmp(ts, until, strlen(until)) <= 0;
}

/* ---- stats ---- */

static void stats_add_tool(struct stats *st, const char *name)
{
	int i;

	if (!name || !name[0])
		return;
	for (i = 0; i < st->ntools; i++) {
		if (strcmp(st->tools[i].name, name) == 0) {
			st->tools[i].count++;
			return;
		}
	}
	if (st->ntools == st->captools) {
		int nc = st->captools ? st->captools * 2 : 32;
		struct tool_count *nt = realloc(st->tools,
						sizeof(*nt) * (size_t)nc);

		if (!nt)
			return;
		st->tools = nt;
		st->captools = nc;
	}
	snprintf(st->tools[st->ntools].name,
		 sizeof(st->tools[st->ntools].name), "%s", name);
	st->tools[st->ntools].count = 1;
	st->ntools++;
}

static int stats_line(const char *line, size_t len, void *ud)
{
	struct stats *st = ud;
	const char *obj;
	size_t obj_len;
	char *ev;

	if (!parse_line(line, len, &obj, &obj_len))
		return 0;
	st->events++;
	ev = get_str(obj, obj_len, "event");
	if (!ev)
		return 0;
	if (strcmp(ev, "session_start") == 0) {
		st->sessions++;
	} else if (strcmp(ev, "turn_end") == 0) {
		st->turns++;
	} else if (strcmp(ev, "model_response") == 0) {
		st->requests++;
		st->prompt_tokens += (unsigned long long)
			get_int(obj, obj_len, "prompt_tokens");
		st->completion_tokens += (unsigned long long)
			get_int(obj, obj_len, "completion_tokens");
	} else if (strcmp(ev, "tool_call") == 0) {
		char *tool = get_str(obj, obj_len, "tool");

		st->tool_calls++;
		stats_add_tool(st, tool);
		free(tool);
	} else if (strcmp(ev, "degraded") == 0) {
		st->degraded++;
	} else if (strcmp(ev, "error") == 0) {
		st->errors++;
	}
	free(ev);
	return 0;
}

static int tool_cmp(const void *a, const void *b)
{
	const struct tool_count *ta = a;
	const struct tool_count *tb = b;

	return tb->count - ta->count;
}

static int trace_stats(const struct ai_trace_config *cfg)
{
	struct stats st;
	struct file_list fl;
	int i;

	memset(&st, 0, sizeof(st));
	if (list_trace_files(cfg->dir, &fl) != 0) {
		printf("trace stats: 无法读取目录 %s\n", cfg->dir);
		return -1;
	}
	printf("trace dir : %s\n", cfg->dir);
	printf("files     : %d\n", fl.n);
	file_list_free(&fl);
	if (foreach_line(cfg->dir, stats_line, &st) != 0) {
		printf("trace stats: 扫描失败\n");
		free(st.tools);
		return -1;
	}
	printf("sessions  : %llu\n", st.sessions);
	printf("events    : %llu\n", st.events);
	printf("turns     : %llu\n", st.turns);
	printf("requests  : %llu\n", st.requests);
	printf("tool_calls: %llu\n", st.tool_calls);
	printf("tokens    : prompt=%llu completion=%llu total=%llu\n",
	       st.prompt_tokens, st.completion_tokens,
	       st.prompt_tokens + st.completion_tokens);
	printf("degraded  : %llu\n", st.degraded);
	printf("errors    : %llu\n", st.errors);
	if (st.ntools) {
		qsort(st.tools, (size_t)st.ntools, sizeof(st.tools[0]),
		      tool_cmp);
		printf("tool distribution:\n");
		for (i = 0; i < st.ntools; i++)
			printf("  %-32s %d\n", st.tools[i].name,
			       st.tools[i].count);
	}
	free(st.tools);
	return 0;
}

/* ---- dump ---- */

struct dump_opts {
	const char *session;
	const char *since;
	const char *until;
	const char *format;
	FILE *out;
	unsigned long long written;
};

static int dump_line(const char *line, size_t len, void *ud)
{
	struct dump_opts *o = ud;
	const char *obj;
	size_t obj_len;
	char *sid;
	char *ts;
	int match = 1;

	if (!parse_line(line, len, &obj, &obj_len))
		return 0;
	sid = get_str(obj, obj_len, "session_id");
	ts = get_str(obj, obj_len, "ts");
	if (o->session && o->session[0]) {
		char *name = get_str(obj, obj_len, "session");

		match = (sid && strcmp(sid, o->session) == 0) ||
			(name && strcmp(name, o->session) == 0);
		free(name);
	}
	if (match && ts) {
		if (!ts_ge(ts, o->since) || !ts_le(ts, o->until))
			match = 0;
	}
	free(sid);
	free(ts);
	if (!match)
		return 0;
	if (strcmp(o->format, "json") == 0) {
		if (o->written)
			fputs(",\n", o->out);
		fputs("  ", o->out);
		fwrite(line, 1, len, o->out);
	} else {
		fwrite(line, 1, len, o->out);
		fputc('\n', o->out);
	}
	o->written++;
	return 0;
}

static int trace_dump(const struct ai_trace_config *cfg, struct dump_opts *o)
{
	int rc;

	if (strcmp(o->format, "json") == 0)
		fputs("[\n", o->out);
	rc = foreach_line(cfg->dir, dump_line, o);
	if (strcmp(o->format, "json") == 0) {
		if (o->written)
			fputs("\n", o->out);
		fputs("]\n", o->out);
	}
	fprintf(stderr, "trace dump: %llu events\n", o->written);
	return rc;
}

/* ---- export（训练用一行一回合） ---- */

struct exp_opts {
	const char *since;
	const char *until;
	const char *session;
	FILE *out;
	unsigned long long turns;

	int active;
	char session_id[128];
	int turn;
	long long duration;
	char *user;
	char *assistant;
	char *outcome;
	char *ts;
	char tools[64][64];
	int ntools;
};

static void exp_put_str(FILE *fp, const char *s)
{
	char *esc = ai_json_escape(s ? s : "");

	if (esc) {
		fputc('"', fp);
		fputs(esc, fp);
		fputc('"', fp);
		free(esc);
	} else {
		fputs("\"\"", fp);
	}
}

static void exp_flush(struct exp_opts *e)
{
	int i;

	if (!e->active)
		return;
	fputs("{\"session_id\":", e->out);
	exp_put_str(e->out, e->session_id);
	fprintf(e->out, ",\"turn\":%d,\"ts\":", e->turn);
	exp_put_str(e->out, e->ts ? e->ts : "");
	fputs(",\"messages\":[{\"role\":\"user\",\"content\":", e->out);
	exp_put_str(e->out, e->user);
	fputs("},{\"role\":\"assistant\",\"content\":", e->out);
	exp_put_str(e->out, e->assistant);
	fputs("}],\"tools_used\":[", e->out);
	for (i = 0; i < e->ntools; i++) {
		if (i)
			fputc(',', e->out);
		exp_put_str(e->out, e->tools[i]);
	}
	fputs("],\"outcome\":", e->out);
	exp_put_str(e->out, e->outcome ? e->outcome : "unknown");
	fprintf(e->out, ",\"duration_ms\":%lld}\n", e->duration);
	e->turns++;

	free(e->user);
	free(e->assistant);
	free(e->outcome);
	free(e->ts);
	e->user = e->assistant = e->outcome = e->ts = NULL;
	e->ntools = 0;
	e->active = 0;
}

static void exp_add_tool(struct exp_opts *e, const char *name)
{
	int i;

	if (!name || !name[0])
		return;
	for (i = 0; i < e->ntools; i++)
		if (strcmp(e->tools[i], name) == 0)
			return;
	if (e->ntools >= (int)(sizeof(e->tools) / sizeof(e->tools[0])))
		return;
	snprintf(e->tools[e->ntools], sizeof(e->tools[0]), "%s", name);
	e->ntools++;
}

static int export_line(const char *line, size_t len, void *ud)
{
	struct exp_opts *e = ud;
	const char *obj;
	size_t obj_len;
	char *ev;
	char *ts;
	int ts_kept = 0;

	if (!parse_line(line, len, &obj, &obj_len))
		return 0;
	ts = get_str(obj, obj_len, "ts");
	if (!ts)
		return 0;
	if (!ts_ge(ts, e->since) || !ts_le(ts, e->until)) {
		free(ts);
		return 0;
	}
	ev = get_str(obj, obj_len, "event");
	if (!ev) {
		free(ts);
		return 0;
	}

	if (strcmp(ev, "turn_start") == 0) {
		char *sid = get_str(obj, obj_len, "session_id");
		char *q = get_str(obj, obj_len, "question");

		if (e->session && e->session[0] &&
		    !(sid && strcmp(sid, e->session) == 0)) {
			exp_flush(e);
			free(sid);
			free(q);
			free(ts);
			free(ev);
			return 0;
		}
		exp_flush(e);
		memset(e->session_id, 0, sizeof(e->session_id));
		if (sid)
			snprintf(e->session_id, sizeof(e->session_id), "%s",
				 sid);
		e->turn = (int)get_int(obj, obj_len, "turn");
		e->user = q;
		e->assistant = strdup("");
		e->outcome = NULL;
		e->ts = ts;
		ts_kept = 1;
		e->duration = 0;
		e->ntools = 0;
		e->active = 1;
		free(sid);
	} else if (strcmp(ev, "tool_call") == 0 && e->active) {
		char *tool = get_str(obj, obj_len, "tool");

		exp_add_tool(e, tool);
		free(tool);
	} else if (strcmp(ev, "model_response") == 0 && e->active) {
		char *content = get_str(obj, obj_len, "content");

		if (content && content[0]) {
			free(e->assistant);
			e->assistant = content;
			content = NULL;
		}
		free(content);
	} else if (strcmp(ev, "turn_end") == 0 && e->active) {
		char *reason = get_str(obj, obj_len, "end_reason");

		free(e->outcome);
		e->outcome = reason;
		e->duration = get_int(obj, obj_len, "duration_ms");
		exp_flush(e);
	} else if (strcmp(ev, "session_end") == 0) {
		exp_flush(e);
	}
	if (!ts_kept)
		free(ts);
	free(ev);
	return 0;
}

static int trace_export(const struct ai_trace_config *cfg, struct exp_opts *e)
{
	int rc = foreach_line(cfg->dir, export_line, e);

	exp_flush(e);
	fprintf(stderr, "trace export: %llu turns\n", e->turns);
	return rc;
}

/* ---- 命令入口 ---- */

int cmd_trace(void *shell_ptr, int argc, char **argv)
{
	struct ai_trace_config cfg;
	const char *sub;
	const char *session = NULL;
	const char *since = NULL;
	const char *until = NULL;
	const char *format = "jsonl";
	const char *out_path = NULL;
	FILE *out = stdout;
	int i;
	int rc = 0;

	(void)shell_ptr;
	if (argc < 2) {
		printf("用法: trace <stats|dump|export> [选项]\n");
		printf("  trace stats\n");
		printf("  trace dump --session <id|name> [--format jsonl|json]"
		       " [--since T] [--until T] [--out FILE]\n");
		printf("  trace export [--since T] [--until T] [--session S]"
		       " [--out FILE]\n");
		return 0;
	}
	sub = argv[1];
	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--session") == 0 && i + 1 < argc)
			session = argv[++i];
		else if (strcmp(argv[i], "--since") == 0 && i + 1 < argc)
			since = argv[++i];
		else if (strcmp(argv[i], "--until") == 0 && i + 1 < argc)
			until = argv[++i];
		else if (strcmp(argv[i], "--format") == 0 && i + 1 < argc)
			format = argv[++i];
		else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
			out_path = argv[++i];
		else {
			printf("trace: 未知参数 %s\n", argv[i]);
			return -1;
		}
	}
	if (ai_trace_load_config(NULL, &cfg) != AI_OK) {
		printf("trace: 配置加载失败\n");
		return -1;
	}
	if (!cfg.dir || !cfg.dir[0]) {
		printf("trace: 未配置日志目录\n");
		ai_trace_config_free(&cfg);
		return -1;
	}
	if (access(cfg.dir, R_OK) != 0) {
		printf("trace: 目录不存在或不可读: %s\n", cfg.dir);
		ai_trace_config_free(&cfg);
		return -1;
	}

	if (strcmp(sub, "stats") == 0) {
		rc = trace_stats(&cfg);
	} else if (strcmp(sub, "dump") == 0) {
		struct dump_opts o;

		if (out_path && (out = fopen(out_path, "w")) == NULL) {
			printf("trace: 无法写 %s\n", out_path);
			ai_trace_config_free(&cfg);
			return -1;
		}
		memset(&o, 0, sizeof(o));
		o.session = session;
		o.since = since;
		o.until = until;
		o.format = strcmp(format, "json") == 0 ? "json" : "jsonl";
		o.out = out;
		rc = trace_dump(&cfg, &o);
		if (out != stdout)
			fclose(out);
	} else if (strcmp(sub, "export") == 0) {
		struct exp_opts e;

		if (out_path && (out = fopen(out_path, "w")) == NULL) {
			printf("trace: 无法写 %s\n", out_path);
			ai_trace_config_free(&cfg);
			return -1;
		}
		memset(&e, 0, sizeof(e));
		e.since = since;
		e.until = until;
		e.session = session;
		e.out = out;
		rc = trace_export(&cfg, &e);
		if (out != stdout)
			fclose(out);
	} else {
		printf("trace: 未知子命令 %s\n", sub);
		rc = -1;
	}
	ai_trace_config_free(&cfg);
	return rc;
}
