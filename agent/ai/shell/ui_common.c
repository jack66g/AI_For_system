// SPDX-License-Identifier: GPL-2.0
/*
 * ui_common.c - 终端 UI 公共层实现
 *
 * 覆盖 include/ai_ui.h 的四块设施：
 *   1. ANSI 颜色开关（config [ui].color + NO_COLOR 环境变量，POSIX 约定）；
 *   2. token 计数人性化格式与上下文预算百分比；
 *   3. 会话持久化（~/.aikernel/sessions/<name>.jsonl，每行一条消息 JSON，
 *      写透落盘，ask 闭环跨次历史与重启恢复共用）；
 *   4. braille spinner 线程（ask 等待模型期间显示阶段文案，
 *      首 token 到达即由调用方 ui_spinner_stop 清除；fbterm 内
 *      （FBTERM_RUN 非空）自动切兼容模式：禁 \r 覆盖动画与
 *      \ESC[K 清行，改单行静态提示）。
 *
 * 会话文件行格式（单行 JSON，字段均可选，tool 消息附 name 便于人读）：
 *   {"ts":1690000000,"role":"user","content":"..."}
 *   {"ts":...,"role":"assistant","content":"...","tool_calls":[...]}
 *   {"ts":...,"role":"tool","tool_call_id":"call_x","name":"procfs.read",
 *    "content":"..."}
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "ai_ui.h"

/* ---- 颜色 ---- */

int ui_color_enabled(int cfg_color)
{
	const char *nc = getenv("NO_COLOR");

	if (!cfg_color)
		return 0;
	/* NO_COLOR 非空即关闭（https://no-color.org 约定） */
	if (nc && nc[0])
		return 0;
	return 1;
}

const char *ui_c(int cfg_color, const char *code)
{
	if (!ui_color_enabled(cfg_color))
		return "";
	return code;
}

/* ---- 计数格式化 ---- */

void ui_fmt_tokens(char *buf, size_t len, long n)
{
	if (n < 0)
		n = 0;
	if (n < 1000)
		snprintf(buf, len, "%ld", n);
	else if (n < 100000)
		snprintf(buf, len, "%.1fk", (double)n / 1000.0);
	else
		snprintf(buf, len, "%ldk", n / 1000);
}

int ui_ctx_percent(long used, long ctx_len)
{
	if (ctx_len <= 0)
		return 0;
	if (used < 0)
		used = 0;
	{
		long pct = used * 100 / ctx_len;

		return (int)(pct > 999 ? 999 : pct);
	}
}

/* ---- 会话存储 ---- */

int ui_session_dir(char *buf, size_t len)
{
	const char *home = getenv("HOME");

	if (!home || !home[0])
		home = "/tmp";
	snprintf(buf, len, "%s/.aikernel", home);
	if (mkdir(buf, 0700) != 0 && errno != EEXIST)
		return AI_ERR_STORAGE;
	snprintf(buf, len, "%s/.aikernel/sessions", home);
	if (mkdir(buf, 0700) != 0 && errno != EEXIST)
		return AI_ERR_STORAGE;
	return AI_OK;
}

int ui_session_valid_name(const char *name)
{
	size_t i, n;

	if (!name)
		return 0;
	n = strlen(name);
	if (n == 0 || n >= UI_SESSION_NAME_MAX)
		return 0;
	if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)name[i];

		if (!(isalnum(c) || c == '-' || c == '_' || c == '.'))
			return 0;
	}
	return 1;
}

int ui_session_path(const char *name, char *buf, size_t len)
{
	char dir[AI_PATH_MAX];
	size_t dl, nl;

	if (!ui_session_valid_name(name))
		return AI_ERR_INVALID_ARG;
	if (ui_session_dir(dir, sizeof(dir)) != AI_OK)
		return AI_ERR_STORAGE;
	dl = strlen(dir);
	nl = strlen(name);
	/* dir + '/' + name + ".jsonl" + '\0'（分段拼接避免 snprintf
	 * 截断告警；调用方缓冲恒为 AI_PATH_MAX，理论可达即校验） */
	if (dl + nl + 8 > len)
		return AI_ERR_INVALID_ARG;
	memcpy(buf, dir, dl);
	buf[dl] = '/';
	memcpy(buf + dl + 1, name, nl);
	memcpy(buf + dl + 1 + nl, ".jsonl", 6);
	buf[dl + 1 + nl + 6] = '\0';
	return AI_OK;
}

int ui_session_exists(const char *name)
{
	char path[AI_PATH_MAX];

	if (ui_session_path(name, path, sizeof(path)) != AI_OK)
		return 0;
	return access(path, F_OK) == 0;
}

/*
 * sess_write_rec - 写一条 JSONL 记录（调用方持有 fp 锁/生命周期）
 * 返回: AI_OK/AI_ERR_MEMORY
 */
static int sess_write_rec(FILE *fp, const struct ui_session_rec *rec)
{
	char *esc_content = NULL;
	char *esc_tcid = NULL;
	char *esc_name = NULL;

	if (fp == NULL || rec == NULL || rec->role == NULL)
		return AI_ERR_INVALID_ARG;

	/*
	 * T2 P0-1 根因修复（e43b/req_109）：旧实现用"下一字段的前缀
	 * `","` 关闭上一字符串、结尾统一补 `\"}`"的拼接协议——当 assistant
	 * 消息只有 tool_calls（裸 JSON，无开放字符串）时，结尾补的引号
	 * 落在 `]` 之后产生 `]"}` 非法 JSON，整行在 ui_session_load 被
	 * 当损坏行跳过 → 历史重放丢失 assistant(tool_calls) → tool 消息
	 * 孤儿化 → DeepSeek 400 且会话永久毒化。
	 * 改为每个字段自包含（自己关闭自己的引号），字段间只加逗号。
	 */
	fprintf(fp, "{\"ts\":%ld,\"role\":\"%s\"",
		rec->ts > 0 ? rec->ts : time(NULL), rec->role);

	if (rec->content && rec->content[0]) {
		esc_content = ai_json_escape(rec->content);
		if (esc_content)
			fprintf(fp, ",\"content\":\"%s\"", esc_content);
		else
			goto oom;
	}
	if (rec->tool_call_id && rec->tool_call_id[0]) {
		esc_tcid = ai_json_escape(rec->tool_call_id);
		if (esc_tcid)
			fprintf(fp, ",\"tool_call_id\":\"%s\"", esc_tcid);
		else
			goto oom;
	}
	if (rec->tool_name && rec->tool_name[0]) {
		esc_name = ai_json_escape(rec->tool_name);
		if (esc_name)
			fprintf(fp, ",\"name\":\"%s\"", esc_name);
		else
			goto oom;
	}
	if (rec->tool_calls_json && rec->tool_calls_json[0])
		fprintf(fp, ",\"tool_calls\":%s", rec->tool_calls_json);

	fprintf(fp, "}\n");

	free(esc_content);
	free(esc_tcid);
	free(esc_name);
	return AI_OK;

oom:
	free(esc_content);
	free(esc_tcid);
	free(esc_name);
	return AI_ERR_MEMORY;
}

int ui_session_append(const char *name, const struct ui_session_rec *rec)
{
	char path[AI_PATH_MAX];
	FILE *fp;
	int rc;

	if (!name || !rec || !rec->role)
		return AI_ERR_INVALID_ARG;
	if (ui_session_path(name, path, sizeof(path)) != AI_OK)
		return AI_ERR_INVALID_ARG;

	fp = fopen(path, "a");
	if (!fp)
		return AI_ERR_STORAGE;

	flockfile(fp);
	rc = sess_write_rec(fp, rec);
	funlockfile(fp);
	if (fclose(fp) != 0 && rc == AI_OK)
		rc = AI_ERR_STORAGE;
	return rc;
}

/*
 * ui_session_replace - 原子替换整个会话文件（W59）
 *
 * compact 的"摘要 + 最近原文"必须一次性替换旧历史：旧实现 clear 后逐条
 * append，进程在中间退出会留下空/半截会话，且清空窗口内并发读会看到
 * 中间态。这里写同目录临时文件 -> fsync -> rename 覆盖，读者只会看到
 * 旧文件或新文件。
 */
int ui_session_replace(const char *name, const struct ui_session_rec *recs,
		       int nrecs)
{
	char path[AI_PATH_MAX];
	char tmp[AI_PATH_MAX];
	FILE *fp;
	int i, rc = AI_OK;
	int n;

	if (!name || nrecs < 0 || (nrecs > 0 && !recs))
		return AI_ERR_INVALID_ARG;
	if (ui_session_path(name, path, sizeof(path)) != AI_OK)
		return AI_ERR_INVALID_ARG;
	n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
	if (n < 0 || (size_t)n >= sizeof(tmp))
		return AI_ERR_INVALID_ARG;

	fp = fopen(tmp, "w");
	if (!fp)
		return AI_ERR_STORAGE;

	for (i = 0; i < nrecs; i++) {
		rc = sess_write_rec(fp, &recs[i]);
		if (rc != AI_OK)
			break;
	}
	if (rc == AI_OK && fflush(fp) != 0)
		rc = AI_ERR_STORAGE;
	if (rc == AI_OK && fsync(fileno(fp)) != 0)
		rc = AI_ERR_STORAGE;
	if (fclose(fp) != 0 && rc == AI_OK)
		rc = AI_ERR_STORAGE;
	if (rc != AI_OK) {
		unlink(tmp);
		return rc;
	}
	if (rename(tmp, path) != 0) {
		unlink(tmp);
		return AI_ERR_STORAGE;
	}
	return AI_OK;
}

/*
 * sess_add_str - 把 malloc 字符串放入所有权池
 * 返回: 池内新基址（realloc 后原指针失效，返回 s 便于链式写法）
 */
static char **sess_add_str(char ***pool, int *n, char *s)
{
	char **np = realloc(*pool, sizeof(char *) * (size_t)(*n + 1));

	if (!np) {
		free(s);
		return NULL;
	}
	np[(*n)++] = s;
	*pool = np;
	return *pool;
}

int ui_session_load(const char *name, struct ai_chat_msg **msgs, int *nmsgs,
		    char ***strings, int *nstr)
{
	char path[AI_PATH_MAX];
	FILE *fp;
	char line[65536];
	struct ai_chat_msg *arr = NULL;
	int n = 0, cap = 0;
	char **pool = NULL;
	int npool = 0;

	if (msgs)
		*msgs = NULL;
	if (nmsgs)
		*nmsgs = 0;
	if (strings)
		*strings = NULL;
	if (nstr)
		*nstr = 0;

	if (!name || !msgs || !nmsgs || !strings || !nstr)
		return AI_ERR_INVALID_ARG;
	if (ui_session_path(name, path, sizeof(path)) != AI_OK)
		return AI_ERR_INVALID_ARG;

	fp = fopen(path, "r");
	if (!fp)
		return AI_OK;   /* 无历史视为空会话 */

	while (fgets(line, sizeof(line), fp)) {
		const char *tok, *v;
		size_t tl, vl;
		int vt;
		const char *p = line;
		const char *end;
		struct ai_chat_msg m;
		char *content = NULL, *tcid = NULL, *tcjson = NULL;

		end = line + strlen(line);
		if (ai_json_scan_value(&p, end, &tok, &tl, &vt) != 0 ||
		    vt != AI_JSON_OBJ)
			continue;   /* 损坏行跳过 */

		memset(&m, 0, sizeof(m));

		if (ai_json_obj_get(tok, tl, "role", &v, &vl, &vt) == 1 &&
		    vt == AI_JSON_STR) {
			char *r = ai_json_strdup_str(v, vl);

			if (!r)
				goto oom;
			if (!sess_add_str(&pool, &npool, r))
				goto oom;
			m.role = r;
		} else {
			continue;   /* 无 role 的行不构成消息 */
		}

		if (ai_json_obj_get(tok, tl, "content", &v, &vl, &vt) == 1 &&
		    vt == AI_JSON_STR) {
			content = ai_json_strdup_str(v, vl);
			if (!content)
				goto oom;
			if (!sess_add_str(&pool, &npool, content))
				goto oom;
			m.content = content;
		}
		if (ai_json_obj_get(tok, tl, "tool_call_id", &v, &vl,
				    &vt) == 1 && vt == AI_JSON_STR) {
			tcid = ai_json_strdup_str(v, vl);
			if (!tcid)
				goto oom;
			if (!sess_add_str(&pool, &npool, tcid))
				goto oom;
			m.tool_call_id = tcid;
		}
		if (ai_json_obj_get(tok, tl, "name", &v, &vl,
				    &vt) == 1 && vt == AI_JSON_STR) {
			/* tool 消息附加的工具名（原生通道重放需要） */
			char *tn = ai_json_strdup_str(v, vl);

			if (!tn)
				goto oom;
			if (!sess_add_str(&pool, &npool, tn))
				goto oom;
			m.tool_name = tn;
		}
		if (ai_json_obj_get(tok, tl, "tool_calls", &v, &vl,
				    &vt) == 1 && vt == AI_JSON_ARR) {
			tcjson = malloc(vl + 1);
			if (!tcjson)
				goto oom;
			memcpy(tcjson, v, vl);
			tcjson[vl] = '\0';
			if (!sess_add_str(&pool, &npool, tcjson))
				goto oom;
			m.tool_calls_json = tcjson;
		}

		if (n >= cap) {
			int ncap = cap ? cap * 2 : 16;
			struct ai_chat_msg *na = realloc(arr,
				sizeof(*na) * (size_t)ncap);

			if (!na)
				goto oom;
			arr = na;
			cap = ncap;
		}
		arr[n++] = m;
	}
	fclose(fp);

	*msgs = arr;
	*nmsgs = n;
	*strings = pool;
	*nstr = npool;
	return AI_OK;

oom:
	fclose(fp);
	free(arr);
	{
		int i;

		for (i = 0; i < npool; i++)
			free(pool[i]);
		free(pool);
	}
	return AI_ERR_MEMORY;
}

static int sess_name_cmp(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

int ui_session_list(char ***names, int *count)
{
	char dir[AI_PATH_MAX];
	DIR *d;
	struct dirent *e;
	char **arr = NULL;
	int n = 0, cap = 0;

	*names = NULL;
	*count = 0;
	if (ui_session_dir(dir, sizeof(dir)) != AI_OK)
		return AI_OK;   /* 无目录 = 空列表 */

	d = opendir(dir);
	if (!d)
		return AI_OK;

	while ((e = readdir(d)) != NULL) {
		size_t l = strlen(e->d_name);

		if (l < 7 || strcmp(e->d_name + l - 6, ".jsonl") != 0)
			continue;
		if (n >= cap) {
			int ncap = cap ? cap * 2 : 8;
			char **na = realloc(arr, sizeof(char *) *
					    (size_t)ncap);

			if (!na)
				break;
			arr = na;
			cap = ncap;
		}
		arr[n] = strndup(e->d_name, l - 6);
		if (!arr[n])
			continue;
		n++;
	}
	closedir(d);

	if (n > 1)
		qsort(arr, (size_t)n, sizeof(char *), sess_name_cmp);
	*names = arr;
	*count = n;
	return AI_OK;
}

int ui_session_clear(const char *name)
{
	char path[AI_PATH_MAX];
	FILE *fp;

	if (ui_session_path(name, path, sizeof(path)) != AI_OK)
		return AI_ERR_INVALID_ARG;
	fp = fopen(path, "w");
	if (!fp)
		return AI_ERR_STORAGE;
	fclose(fp);
	return AI_OK;
}

int ui_session_delete(const char *name)
{
	char path[AI_PATH_MAX];

	if (ui_session_path(name, path, sizeof(path)) != AI_OK)
		return AI_ERR_INVALID_ARG;
	if (unlink(path) != 0 && errno != ENOENT)
		return AI_ERR_STORAGE;
	return AI_OK;
}

int ui_session_count(const char *name)
{
	char path[AI_PATH_MAX];
	FILE *fp;
	int n = 0;
	int c;

	if (ui_session_path(name, path, sizeof(path)) != AI_OK)
		return 0;
	fp = fopen(path, "r");
	if (!fp)
		return 0;
	while ((c = fgetc(fp)) != EOF) {
		if (c == '\n')
			n++;
	}
	fclose(fp);
	return n;
}

/* ---- spinner ---- */

/*
 * fbterm 兼容探测（W18 问题 3）
 * FBTERM_RUN 非空 = 进程跑在 fbterm 内（.profile 链注入，防递归的
 * 同一变量）。fbterm 对 "\r 覆盖 + \ESC[K 清行 + 高频重绘" 的渲染
 * 不稳，该模式下禁用覆盖类序列：spinner 动画改单行静态提示，AI
 * 回复走普通整行输出（调用方据此关流式增量打印）。
 */
static int g_fbterm_compat = -1;	/* -1=未探测 */

int ui_fbterm_compat(void)
{
	if (g_fbterm_compat < 0) {
		const char *env = getenv("FBTERM_RUN");

		g_fbterm_compat = (env && env[0]) ? 1 : 0;
	}
	return g_fbterm_compat;
}

/* braille 转轮帧（UTF-8） */
static const char *const SPIN_FRAMES[] = {
	"\xe2\xa0\x8b", "\xe2\xa0\x99", "\xe2\xa0\xb9", "\xe2\xa0\xb8",
	"\xe2\xa0\xbc", "\xe2\xa0\xb4", "\xe2\xa0\xa6", "\xe2\xa0\xa7",
	"\xe2\xa0\x87", "\xe2\xa0\x8f",
};
#define SPIN_NFRAMES  ((int)(sizeof(SPIN_FRAMES) / sizeof(SPIN_FRAMES[0])))
#define SPIN_INTERVAL_US  90000

static pthread_mutex_t g_spin_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_t g_spin_tid;
static int g_spin_running;      /* 线程存活标志 */
static int g_spin_active;       /* 绘制中标志 */
static char g_spin_stage[160];

static void *spin_thread(void *arg)
{
	int frame = 0;

	(void)arg;
	for (;;) {
		pthread_mutex_lock(&g_spin_mu);
		if (!g_spin_active) {
			pthread_mutex_unlock(&g_spin_mu);
			break;
		}
		/* fbterm 兼容模式不画动画（ui_spinner_start 已打静态行） */
		if (isatty(1) && !ui_fbterm_compat()) {
			fprintf(stdout, "\r\033[2m%s %s\033[0m   ",
				SPIN_FRAMES[frame % SPIN_NFRAMES],
				g_spin_stage);
			fflush(stdout);
		}
		frame++;
		pthread_mutex_unlock(&g_spin_mu);
		usleep(SPIN_INTERVAL_US);
	}
	return NULL;
}

void ui_spinner_start(const char *stage)
{
	pthread_mutex_lock(&g_spin_mu);
	snprintf(g_spin_stage, sizeof(g_spin_stage), "%s",
		 stage ? stage : "thinking...");
	if (!g_spin_running) {
		g_spin_active = 1;
		if (pthread_create(&g_spin_tid, NULL, spin_thread, NULL) == 0) {
			g_spin_running = 1;
		} else {
			g_spin_active = 0;
		}
	}
	/* fbterm 兼容模式：单行静态提示（带换行，回复从新行开始） */
	if (g_spin_active && isatty(1) && ui_fbterm_compat()) {
		fprintf(stdout, "(%s)\n", g_spin_stage);
		fflush(stdout);
	}
	pthread_mutex_unlock(&g_spin_mu);
}

void ui_spinner_set_stage(const char *stage)
{
	pthread_mutex_lock(&g_spin_mu);
	snprintf(g_spin_stage, sizeof(g_spin_stage), "%s",
		 stage ? stage : "thinking...");
	pthread_mutex_unlock(&g_spin_mu);
}

void ui_spinner_stop(void)
{
	pthread_mutex_lock(&g_spin_mu);
	if (g_spin_active)
		g_spin_active = 0;
	pthread_mutex_unlock(&g_spin_mu);

	/* 等待线程退出并清除转轮行 */
	if (g_spin_running) {
		pthread_join(g_spin_tid, NULL);
		g_spin_running = 0;
	}
	/* fbterm 兼容模式：无覆盖行可清，跳过 \r\ESC[K */
	if (isatty(1) && !ui_fbterm_compat()) {
		fputs("\r\033[K", stdout);
		fflush(stdout);
	}
}
