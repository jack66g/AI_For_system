// SPDX-License-Identifier: GPL-2.0
/*
 * ask_clarify.c - W77c：结构化澄清（clarify 工具）
 *
 * 职责边界：
 *   - clarify 工具只问问题、收集选择，不是授权：不创建租约、不调用
 *     executor、不执行待办动作；后续 D2+ 操作仍走 W74 gate。
 *   - TTY：数字菜单（推荐项置顶并标注）、[o] 自由输入、[q] 取消，
 *     无效输入最多重试 3 次；支持多选（逗号/空格分隔序号或 id）。
 *   - 非 TTY：不阻塞，返回 CLARIFY_REQUIRED JSON（nonce/expires_at），
 *     由 cmd_ask 结束本轮 ask。
 *   - 每个 ask 最多 2 个澄清问题（ask_clarify_state 计数）。
 *
 * 歧义检测器只处理两类高价值歧义：服务启停缺 unit、破坏动作缺目标。
 * 只有在候选确实 >=2 时才提问；候选唯一/问题已带明确目标时直接放行。
 * 检测逻辑与 evidence 分离，纯函数可单测。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>

#include "ask_clarify.h"
#include "ai_json_util.h"
#include "ai_trace.h"

/* ---- 小型可增长字符串缓冲（JSON 构造） ---- */

struct clarify_buf {
	char *p;
	size_t len;
	size_t cap;
	int err;
};

static int cb_reserve(struct clarify_buf *b, size_t add)
{
	size_t need = b->len + add + 1;
	size_t ncap;
	char *np;

	if (b->err)
		return -1;
	if (need <= b->cap)
		return 0;
	ncap = b->cap ? b->cap : 256;
	while (ncap < need)
		ncap *= 2;
	np = realloc(b->p, ncap);
	if (!np) {
		b->err = 1;
		return -1;
	}
	b->p = np;
	b->cap = ncap;
	return 0;
}

static void cb_put(struct clarify_buf *b, const char *s, size_t n)
{
	if (cb_reserve(b, n) != 0)
		return;
	memcpy(b->p + b->len, s, n);
	b->len += n;
	b->p[b->len] = '\0';
}

static void cb_puts(struct clarify_buf *b, const char *s)
{
	if (s)
		cb_put(b, s, strlen(s));
}

static void cb_putc(struct clarify_buf *b, char c)
{
	cb_put(b, &c, 1);
}

static void cb_printf(struct clarify_buf *b, const char *fmt, ...)
{
	va_list ap;
	char tmp[128];
	int n;

	va_start(ap, fmt);
	n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (n > 0)
		cb_put(b, tmp, (size_t)n < sizeof(tmp) ? (size_t)n :
		       sizeof(tmp) - 1);
}

static void cb_json_str(struct clarify_buf *b, const char *s)
{
	char *esc;

	if (b->err)
		return;
	esc = ai_json_escape(s ? s : "");
	if (!esc) {
		b->err = 1;
		return;
	}
	cb_putc(b, '"');
	cb_puts(b, esc);
	cb_putc(b, '"');
	free(esc);
}

/* ---- 通用小工具 ---- */

static int copy_cap(char *dst, size_t cap, const char *src)
{
	size_t n;

	if (!dst || cap == 0)
		return -1;
	if (!src)
		src = "";
	n = strlen(src);
	if (n >= cap)
		return -1;
	memcpy(dst, src, n + 1);
	return 0;
}

static void trim_inplace(char *s)
{
	char *p = s;
	size_t n;

	while (*p && isspace((unsigned char)*p))
		p++;
	if (p != s)
		memmove(s, p, strlen(p) + 1);
	n = strlen(s);
	while (n > 0 && isspace((unsigned char)s[n - 1]))
		s[--n] = '\0';
}

static void sanitize_single_line(char *s)
{
	char *p;

	for (p = s; *p; p++) {
		unsigned char c = (unsigned char)*p;

		if (c == '\n' || c == '\r' || c == '\t' || c < 0x20)
			*p = ' ';
	}
	trim_inplace(s);
}

static int id_char_ok(char c)
{
	return isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.';
}

static int id_find(const struct ask_clarify_request *req, const char *id)
{
	int i;

	if (!id || !id[0])
		return -1;
	for (i = 0; i < req->n_options; i++)
		if (strcmp(req->options[i].id, id) == 0)
			return i;
	for (i = 0; i < req->n_options; i++)
		if (strcasecmp(req->options[i].id, id) == 0)
			return i;
	return -1;
}

static int req_has_high(const struct ask_clarify_request *req)
{
	int i;

	if (req->danger[0] == 'D' &&
	    (req->danger[1] == '3' || req->danger[1] == '4') &&
	    req->danger[2] == '\0')
		return 1;
	for (i = 0; i < req->n_options; i++) {
		const char *d = req->options[i].danger[0] ?
				req->options[i].danger : req->danger;

		if (d[0] == 'D' && (d[1] == '3' || d[1] == '4') &&
		    d[2] == '\0')
			return 1;
	}
	return 0;
}

static int is_auth_high(const struct ask_clarify_request *req)
{
	return strcmp(req->kind, "authorization") == 0 &&
	       req_has_high(req);
}

/* 推荐项置顶；其余保持原顺序。返回显示序号 → options 下标。 */
static void clarify_display_order(const struct ask_clarify_request *req,
				  int *order)
{
	int n = 0;
	int i;
	int rec = req->has_recommended ? id_find(req, req->recommended) : -1;

	if (rec >= 0)
		order[n++] = rec;
	for (i = 0; i < req->n_options; i++) {
		if (i == rec)
			continue;
		order[n++] = i;
	}
}

/* ---- 参数解析 ---- */

static int get_json_str(const char *obj, size_t len, const char *key,
			char *dst, size_t cap, int *found,
			char *err, size_t errlen)
{
	const char *v = NULL;
	size_t vl = 0;
	int vt = 0;
	char *s;
	int rc;

	*found = 0;
	dst[0] = '\0';
	rc = ai_json_obj_get(obj, len, key, &v, &vl, &vt);
	if (rc < 0) {
		snprintf(err, errlen, "JSON 语法错误（key=%s）", key);
		return -1;
	}
	if (rc == 0)
		return 0;
	if (vt != AI_JSON_STR) {
		snprintf(err, errlen, "字段 %s 必须是字符串", key);
		return -1;
	}
	s = ai_json_strdup_str(v, vl);
	if (!s) {
		snprintf(err, errlen, "字段 %s 解码失败", key);
		return -1;
	}
	if (copy_cap(dst, cap, s) != 0) {
		snprintf(err, errlen, "字段 %s 过长（上限 %zu 字节）", key,
			 cap - 1);
		free(s);
		return -1;
	}
	free(s);
	*found = 1;
	return 0;
}

static int parse_options(const char *obj, size_t len,
			 struct ask_clarify_request *req,
			 char *err, size_t errlen)
{
	const char *arr = NULL;
	size_t arr_len = 0;
	int arr_type = 0;
	int rc;
	int i;

	rc = ai_json_obj_get(obj, len, "options", &arr, &arr_len, &arr_type);
	if (rc <= 0 || arr_type != AI_JSON_ARR) {
		snprintf(err, errlen, "缺少 options 数组");
		return -1;
	}
	for (i = 0; i < ASK_CLARIFY_MAX_OPTIONS + 1; i++) {
		const char *et = NULL;
		size_t etl = 0;
		int et_type = 0;
		int found;

		rc = ai_json_arr_get(arr, arr_len, i, &et, &etl, &et_type);
		if (rc == 0)
			break;
		if (rc < 0 || et_type != AI_JSON_OBJ) {
			snprintf(err, errlen, "options[%d] 必须是对象", i);
			return -1;
		}
		if (i >= ASK_CLARIFY_MAX_OPTIONS) {
			snprintf(err, errlen, "options 最多 %d 个",
				 ASK_CLARIFY_MAX_OPTIONS);
			return -1;
		}
		if (get_json_str(et, etl, "id", req->options[i].id,
				 sizeof(req->options[i].id), &found,
				 err, errlen) != 0)
			return -1;
		if (!found || !req->options[i].id[0]) {
			snprintf(err, errlen, "options[%d].id 必填", i);
			return -1;
		}
		if (get_json_str(et, etl, "label", req->options[i].label,
				 sizeof(req->options[i].label), &found,
				 err, errlen) != 0)
			return -1;
		if (!found || !req->options[i].label[0]) {
			snprintf(err, errlen, "options[%d].label 必填", i);
			return -1;
		}
		sanitize_single_line(req->options[i].label);
		if (get_json_str(et, etl, "description",
				 req->options[i].description,
				 sizeof(req->options[i].description), &found,
				 err, errlen) != 0)
			return -1;
		if (get_json_str(et, etl, "why", req->options[i].why,
				 sizeof(req->options[i].why), &found,
				 err, errlen) != 0)
			return -1;
		if (get_json_str(et, etl, "impact", req->options[i].impact,
				 sizeof(req->options[i].impact), &found,
				 err, errlen) != 0)
			return -1;
		if (get_json_str(et, etl, "rollback", req->options[i].rollback,
				 sizeof(req->options[i].rollback), &found,
				 err, errlen) != 0)
			return -1;
		if (get_json_str(et, etl, "danger", req->options[i].danger,
				 sizeof(req->options[i].danger), &found,
				 err, errlen) != 0)
			return -1;
		sanitize_single_line(req->options[i].description);
		sanitize_single_line(req->options[i].why);
		sanitize_single_line(req->options[i].impact);
		sanitize_single_line(req->options[i].rollback);
		if (req->options[i].danger[0]) {
			char *q = req->options[i].danger;

			for (; *q; q++)
				*q = (char)toupper((unsigned char)*q);
		}
		req->n_options++;
	}
	if (req->n_options < ASK_CLARIFY_MIN_OPTIONS) {
		snprintf(err, errlen, "options 至少 %d 个",
			 ASK_CLARIFY_MIN_OPTIONS);
		return -1;
	}
	return 0;
}

int ask_clarify_parse_request(const char *json, struct ask_clarify_request *req,
			      char *err, size_t errlen)
{
	const char *p;
	const char *end;
	const char *tok = NULL;
	size_t tlen = 0;
	int type = 0;
	int found;
	int rc;

	if (!req) {
		snprintf(err, errlen, "内部错误：req 为空");
		return -1;
	}
	memset(req, 0, sizeof(*req));
	if (!json || !json[0]) {
		snprintf(err, errlen, "arguments 为空（需要 question/options）");
		return -1;
	}
	p = json;
	end = json + strlen(json);
	if (ai_json_scan_value(&p, end, &tok, &tlen, &type) != 0 ||
	    type != AI_JSON_OBJ) {
		snprintf(err, errlen, "arguments 必须是 JSON 对象");
		return -1;
	}

	if (get_json_str(tok, tlen, "question", req->question,
			 sizeof(req->question), &found, err, errlen) != 0)
		return -1;
	if (!found) {
		snprintf(err, errlen, "question 必填");
		return -1;
	}
	sanitize_single_line(req->question);
	if (!req->question[0]) {
		snprintf(err, errlen, "question 不能为空");
		return -1;
	}

	if (get_json_str(tok, tlen, "header", req->header,
			 sizeof(req->header), &found, err, errlen) != 0)
		return -1;
	sanitize_single_line(req->header);

	if (get_json_str(tok, tlen, "kind", req->kind, sizeof(req->kind),
			 &found, err, errlen) != 0)
		return -1;
	if (!found)
		copy_cap(req->kind, sizeof(req->kind), "intent");
	else {
		char *q = req->kind;

		for (; *q; q++)
			*q = (char)tolower((unsigned char)*q);
		/* W77c 规范化为五个 canonical kind；旧值仅做兼容映射，
		 * 不再出现在模型 schema 中。 */
		if (strcmp(req->kind, "choice") == 0)
			copy_cap(req->kind, sizeof(req->kind), "intent");
		else if (strcmp(req->kind, "service") == 0 ||
			 strcmp(req->kind, "destructive") == 0)
			copy_cap(req->kind, sizeof(req->kind), "scope");
	}

	if (get_json_str(tok, tlen, "danger", req->danger,
			 sizeof(req->danger), &found, err, errlen) != 0)
		return -1;
	if (found) {
		char *q = req->danger;

		for (; *q; q++)
			*q = (char)toupper((unsigned char)*q);
	}

	if (get_json_str(tok, tlen, "recommended", req->recommended,
			 sizeof(req->recommended), &found, err, errlen) != 0)
		return -1;
	req->has_recommended = found;

	if (get_json_str(tok, tlen, "default", req->default_id,
			 sizeof(req->default_id), &found, err, errlen) != 0)
		return -1;
	req->has_default = found;

	{
		const char *v = NULL;
		size_t vl = 0;
		int vt = 0;

		rc = ai_json_obj_get(tok, tlen, "multi_select", &v, &vl, &vt);
		if (rc < 0 || (rc == 1 && vt != AI_JSON_BOOL)) {
			snprintf(err, errlen, "multi_select 必须是布尔值");
			return -1;
		}
		if (rc == 1)
			req->multi_select = (vl >= 4 &&
					     strncmp(v, "true", 4) == 0);
	}

	return parse_options(tok, tlen, req, err, errlen);
}

static int danger_valid(const char *d)
{
	return d[0] == 'D' && d[1] >= '0' && d[1] <= '4' && d[2] == '\0';
}

static int danger_high(const char *d)
{
	return d && (strcmp(d, "D3") == 0 || strcmp(d, "D4") == 0);
}

/* 选项 danger 缺省继承请求 danger */
static const char *option_danger(const struct ask_clarify_request *req, int i)
{
	if (req->options[i].danger[0])
		return req->options[i].danger;
	return req->danger;
}

int ask_clarify_validate(const struct ask_clarify_request *req,
			 char *err, size_t errlen)
{
	int i, j;
	int rec;
	int def;

	if (!req) {
		snprintf(err, errlen, "内部错误：req 为空");
		return -1;
	}
	if (!req->question[0]) {
		snprintf(err, errlen, "question 不能为空");
		return -1;
	}
	if (strcmp(req->kind, "intent") != 0 &&
	    strcmp(req->kind, "scope") != 0 &&
	    strcmp(req->kind, "strategy") != 0 &&
	    strcmp(req->kind, "authorization") != 0 &&
	    strcmp(req->kind, "recovery") != 0) {
		snprintf(err, errlen, "kind 非法：%s（intent/scope/strategy/"
			 "authorization/recovery）", req->kind);
		return -1;
	}
	if (req->n_options < ASK_CLARIFY_MIN_OPTIONS ||
	    req->n_options > ASK_CLARIFY_MAX_OPTIONS) {
		snprintf(err, errlen, "options 数量必须在 %d-%d 之间",
			 ASK_CLARIFY_MIN_OPTIONS, ASK_CLARIFY_MAX_OPTIONS);
		return -1;
	}
	for (i = 0; i < req->n_options; i++) {
		const char *id = req->options[i].id;
		size_t k;

		if (!id[0] || strlen(id) > ASK_CLARIFY_ID_MAX) {
			snprintf(err, errlen, "options[%d].id 长度非法", i);
			return -1;
		}
		for (k = 0; id[k]; k++) {
			if (!id_char_ok(id[k])) {
				snprintf(err, errlen,
					 "options[%d].id 含非法字符：%s", i, id);
				return -1;
			}
		}
		if (!strcasecmp(id, "o") || !strcasecmp(id, "other") ||
		    !strcmp(id, "其他") || !strcasecmp(id, "q") ||
		    !strcasecmp(id, "quit") || !strcasecmp(id, "cancel")) {
			snprintf(err, errlen, "options[%d].id 使用了保留字：%s",
				 i, id);
			return -1;
		}
		if (!req->options[i].label[0]) {
			snprintf(err, errlen, "options[%d].label 不能为空", i);
			return -1;
		}
		if (req->options[i].danger[0] &&
		    !danger_valid(req->options[i].danger)) {
			snprintf(err, errlen,
				 "options[%d].danger 必须是 D0-D4", i);
			return -1;
		}
		for (j = 0; j < i; j++) {
			if (strcasecmp(req->options[j].id, id) == 0) {
				snprintf(err, errlen, "options id 重复：%s", id);
				return -1;
			}
		}
	}

	if (strcmp(req->kind, "authorization") == 0) {
		if (!danger_valid(req->danger)) {
			snprintf(err, errlen,
				 "authorization 的 danger 必须是 D0-D4");
			return -1;
		}
	} else if (req->danger[0] && !danger_valid(req->danger)) {
		snprintf(err, errlen, "danger 必须是 D0-D4");
		return -1;
	}

	rec = req->has_recommended ? id_find(req, req->recommended) : -1;
	if (req->has_recommended && rec < 0) {
		snprintf(err, errlen, "recommended 引用了不存在的 option：%s",
			 req->recommended);
		return -1;
	}
	def = req->has_default ? id_find(req, req->default_id) : -1;
	if (req->has_default && def < 0) {
		snprintf(err, errlen, "default 引用了不存在的 option：%s",
			 req->default_id);
		return -1;
	}

	if (req->has_default && req_has_high(req)) {
		/* 任一选项（含继承请求 danger）为 D3/D4 都不得带默认项，
		 * 避免任何形式的自动执行；与 kind 无关。 */
		snprintf(err, errlen,
			 "D3/D4 禁止 default（不得自动执行）");
		return -1;
	}
	if (!is_auth_high(req) && !req->has_recommended) {
		snprintf(err, errlen, "必须指定 recommended（唯一推荐项）");
		return -1;
	}
	if (req->has_recommended && !req->options[rec].why[0]) {
		snprintf(err, errlen,
			 "recommended 选项必须提供 why（证据/理由）");
		return -1;
	}
	for (i = 0; i < req->n_options; i++) {
		const char *d = option_danger(req, i);

		if (danger_high(d) &&
		    (!req->options[i].impact[0] ||
		     !req->options[i].rollback[0])) {
			snprintf(err, errlen,
				 "options[%d] danger=%s 必须提供 impact 与 "
				 "rollback", i, d);
			return -1;
		}
	}
	return 0;
}

/* ---- 菜单输入解析 ---- */

static int is_delim(char c)
{
	return isspace((unsigned char)c) || c == ',' || c == ';';
}

static int token_is_other(const char *tok)
{
	return !strcasecmp(tok, "o") || !strcasecmp(tok, "other") ||
	       !strcmp(tok, "其他");
}

static int resolve_token(const struct ask_clarify_request *req,
			 const int *order, const char *tok, int *out_idx)
{
	int i;
	int n;

	if (!tok || !tok[0])
		return -1;

	for (n = 0; tok[n]; n++)
		if (!isdigit((unsigned char)tok[n]))
			break;
	if (tok[n] == '\0') {
		long v = strtol(tok, NULL, 10);

		if (v < 1 || v > req->n_options)
			return -1;
		*out_idx = order[v - 1];
		return 0;
	}
	i = id_find(req, tok);
	if (i < 0)
		return -1;
	*out_idx = i;
	return 0;
}

static int answer_has(const struct ask_clarify_answer *ans, int idx)
{
	int i;

	for (i = 0; i < ans->n_selected; i++)
		if (ans->selected[i] == idx)
			return 1;
	return 0;
}

int ask_clarify_parse_answer(const char *line,
			     const struct ask_clarify_request *req,
			     struct ask_clarify_answer *ans)
{
	char buf[ASK_CLARIFY_TEXT_MAX * 2 + 64];
	char *p;
	int order[ASK_CLARIFY_MAX_OPTIONS];
	int other = 0;
	const char *other_text = NULL;

	if (!req || !ans || !line)
		return ASK_CLARIFY_ANS_INVALID;
	memset(ans, 0, sizeof(*ans));
	if (strlen(line) >= sizeof(buf))
		return ASK_CLARIFY_ANS_INVALID;
	copy_cap(buf, sizeof(buf), line);
	trim_inplace(buf);
	if (!buf[0])
		return ASK_CLARIFY_ANS_INVALID;
	if (!strcasecmp(buf, "q") || !strcasecmp(buf, "quit") ||
	    !strcasecmp(buf, "cancel") || !strcmp(buf, "取消") ||
	    !strcmp(buf, "退出"))
		return ASK_CLARIFY_ANS_CANCEL;

	clarify_display_order(req, order);
	p = buf;
	while (*p) {
		char *tok;
		char *rest;
		int idx;

		while (*p && is_delim(*p))
			p++;
		if (!*p)
			break;
		tok = p;
		while (*p && !is_delim(*p))
			p++;
		if (*p) {
			*p++ = '\0';
			rest = p;
		} else {
			rest = p;
		}
		if (token_is_other(tok)) {
			other = 1;
			while (*rest && isspace((unsigned char)*rest))
				rest++;
			other_text = rest;
			break;
		}
		if (resolve_token(req, order, tok, &idx) != 0)
			return ASK_CLARIFY_ANS_INVALID;
		if (!answer_has(ans, idx) &&
		    ans->n_selected < ASK_CLARIFY_MAX_OPTIONS)
			ans->selected[ans->n_selected++] = idx;
	}
	if (other_text && other_text[0]) {
		if (strlen(other_text) > ASK_CLARIFY_TEXT_MAX)
			return ASK_CLARIFY_ANS_INVALID;
		copy_cap(ans->text, sizeof(ans->text), other_text);
		trim_inplace(ans->text);
	}
	if (!req->multi_select) {
		if (ans->n_selected > 1)
			return ASK_CLARIFY_ANS_INVALID;
		if (ans->n_selected > 0 && ans->text[0])
			return ASK_CLARIFY_ANS_INVALID;
	}
	if (ans->n_selected > 0)
		return ASK_CLARIFY_ANS_OK;
	if (other)
		return ASK_CLARIFY_ANS_OTHER;
	return ASK_CLARIFY_ANS_INVALID;
}

int ask_clarify_run_inputs(const char *const *lines, int nlines,
			   const struct ask_clarify_request *req,
			   struct ask_clarify_answer *ans, int *attempts)
{
	int used = 0;
	int i;

	if (attempts)
		*attempts = 0;
	if (!lines || !req || !ans)
		return ASK_CLARIFY_ANS_INVALID;
	for (i = 0; i < nlines && used < ASK_CLARIFY_MAX_ATTEMPTS; i++) {
		int st = ask_clarify_parse_answer(lines[i], req, ans);

		used++;
		if (st == ASK_CLARIFY_ANS_OK || st == ASK_CLARIFY_ANS_CANCEL) {
			if (attempts)
				*attempts = used;
			return st;
		}
		if (st == ASK_CLARIFY_ANS_OTHER) {
			if (!ans->text[0] && i + 1 < nlines &&
			    used < ASK_CLARIFY_MAX_ATTEMPTS) {
				/* 下一行无条件作为 Other 文本 */
				memset(ans, 0, sizeof(*ans));
				copy_cap(ans->text, sizeof(ans->text),
					 lines[i + 1]);
				trim_inplace(ans->text);
				i++;
			}
			if (attempts)
				*attempts = used;
			return ASK_CLARIFY_ANS_OTHER;
		}
	}
	if (attempts)
		*attempts = used;
	return ASK_CLARIFY_ANS_INVALID;
}

int ask_clarify_run_events(const struct ask_clarify_input *events, int nevents,
			   const struct ask_clarify_request *req,
			   struct ask_clarify_answer *ans, int *attempts,
			   int *timed_out)
{
	int used = 0;
	int i;

	if (attempts)
		*attempts = 0;
	if (timed_out)
		*timed_out = 0;
	if (!events || !req || !ans)
		return ASK_CLARIFY_ANS_INVALID;
	for (i = 0; i < nevents && used < ASK_CLARIFY_MAX_ATTEMPTS; i++) {
		int st;

		used++;
		if (events[i].timeout) {
			/* 超时=取消，绝不自动选择 default */
			ans->timed_out = 1;
			if (timed_out)
				*timed_out = 1;
			if (attempts)
				*attempts = used;
			return ASK_CLARIFY_ANS_CANCEL;
		}
		st = ask_clarify_parse_answer(events[i].line, req, ans);
		if (st == ASK_CLARIFY_ANS_OK || st == ASK_CLARIFY_ANS_CANCEL) {
			if (attempts)
				*attempts = used;
			return st;
		}
		if (st == ASK_CLARIFY_ANS_OTHER) {
			if (!ans->text[0] && i + 1 < nevents &&
			    used < ASK_CLARIFY_MAX_ATTEMPTS) {
				i++;
				if (events[i].timeout) {
					ans->timed_out = 1;
					if (timed_out)
						*timed_out = 1;
					if (attempts)
						*attempts = used;
					return ASK_CLARIFY_ANS_CANCEL;
				}
				memset(ans, 0, sizeof(*ans));
				copy_cap(ans->text, sizeof(ans->text),
					 events[i].line);
				trim_inplace(ans->text);
			}
			if (attempts)
				*attempts = used;
			return ASK_CLARIFY_ANS_OTHER;
		}
	}
	if (attempts)
		*attempts = used;
	return ASK_CLARIFY_ANS_INVALID;
}

int ask_clarify_suppress_peer(int round_has_clarify, const char *tool_name,
			      int tty)
{
	/* 安全与终端无关：同轮有 clarify 时，任何其他工具都不得先执行
	 * （TTY 也必须等答案后让模型重试）。tty 仅为调用点自证/测试。 */
	(void)tty;
	if (!round_has_clarify || !tool_name)
		return 0;
	return strcmp(tool_name, "clarify") != 0;
}

/* ---- 名额 / 生命周期 ---- */

int ask_clarify_state_begin(struct ask_clarify_state *st)
{
	if (!st)
		return 0;
	if (st->asked >= ASK_CLARIFY_MAX_PER_ASK)
		return 0;
	st->asked++;
	return 1;
}

void ask_clarify_state_free(struct ask_clarify_state *st)
{
	if (!st)
		return;
	free(st->stop_text);
	free(st->original_question);
	memset(st, 0, sizeof(*st));
}

/* ---- W77c-2b：API tagged event 通道 ---- */

static char clarify_event_tag[65];

int ask_clarify_event_tag_init(void)
{
	const char *t = getenv("AIKERNEL_EVENT_TAG");
	size_t i, n;

	clarify_event_tag[0] = '\0';
	if (!t || !t[0])
		return 0;
	n = strlen(t);
	if (n > 64)
		return -1;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)t[i];

		if (!isalnum(c) && c != '-' && c != '_' && c != '.')
			return -1;
	}
	memcpy(clarify_event_tag, t, n + 1);
	/* 工具子进程绝不能看到 tag（否则可伪造可信事件） */
	unsetenv("AIKERNEL_EVENT_TAG");
	return 1;
}

void ask_clarify_emit_event(const char *json)
{
	if (!clarify_event_tag[0] || !json || !json[0])
		return;
	/* 事件必须是单行；JSON 构造器已转义换行，异常输入直接丢弃 */
	if (strchr(json, '\n') || strchr(json, '\r'))
		return;
	/* 仅 API 管道场景；交互终端不污染用户界面 */
	if (isatty(STDERR_FILENO))
		return;
	fprintf(stderr, "AIKERNEL_EVENT %s %s\n", clarify_event_tag, json);
	fflush(stderr);
}

void ask_clarify_state_set_context(struct ask_clarify_state *st,
				   const char *session,
				   const char *original_question)
{
	if (!st)
		return;
	if (copy_cap(st->session, sizeof(st->session), session) != 0)
		st->session[0] = '\0';
	free(st->original_question);
	st->original_question = (original_question && original_question[0]) ?
				strdup(original_question) : NULL;
}

/* ---- 非 TTY JSON ---- */

static void fmt_iso(long long wall_ms, char *buf, size_t n)
{
	time_t sec = (time_t)(wall_ms / 1000);
	int ms = (int)(wall_ms % 1000);
	struct tm tm;
	char base[64];
	char tz[16];

	tz[0] = '\0';
	if (!localtime_r(&sec, &tm) ||
	    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm) == 0) {
		snprintf(buf, n, "1970-01-01T00:00:00.000+0000");
		return;
	}
	strftime(tz, sizeof(tz), "%z", &tm);
	snprintf(buf, n, "%s.%03d%s", base, ms, tz);
}

static void add_option_arrays(struct clarify_buf *b,
			      const struct ask_clarify_request *req)
{
	int i;

	cb_puts(b, ",\"options\":[");
	for (i = 0; i < req->n_options; i++) {
		const struct ask_clarify_option *o = &req->options[i];

		if (i)
			cb_putc(b, ',');
		cb_puts(b, "{\"id\":");
		cb_json_str(b, o->id);
		cb_puts(b, ",\"label\":");
		cb_json_str(b, o->label);
		if (o->description[0]) {
			cb_puts(b, ",\"description\":");
			cb_json_str(b, o->description);
		}
		if (o->why[0]) {
			cb_puts(b, ",\"why\":");
			cb_json_str(b, o->why);
		}
		if (o->impact[0]) {
			cb_puts(b, ",\"impact\":");
			cb_json_str(b, o->impact);
		}
		if (o->rollback[0]) {
			cb_puts(b, ",\"rollback\":");
			cb_json_str(b, o->rollback);
		}
		if (option_danger(req, i)[0]) {
			cb_puts(b, ",\"danger\":");
			cb_json_str(b, option_danger(req, i));
		}
		if (req->has_recommended &&
		    strcmp(req->recommended, o->id) == 0)
			cb_puts(b, ",\"recommended\":true");
		if (req->has_default && strcmp(req->default_id, o->id) == 0)
			cb_puts(b, ",\"default\":true");
		cb_putc(b, '}');
	}
	cb_putc(b, ']');
}

/* ---- W77c-2a：pending 存储 ---- */

static int clarify_nonce_ok(const char *n)
{
	size_t len, i;

	if (!n || strncmp(n, "cq-", 3) != 0)
		return 0;
	len = strlen(n);
	if (len < 5 || len > ASK_CLARIFY_NONCE_MAX)
		return 0;
	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)n[i];

		if (!isalnum(c) && c != '-' && c != '_' && c != '.')
			return 0;
	}
	return 1;
}

static int clarify_mkdir_secure(const char *path)
{
	struct stat st;

	if (mkdir(path, 0700) != 0 && errno != EEXIST)
		return -1;
	if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
		return -1;
	if (chmod(path, 0700) != 0 && errno != EPERM)
		return -1;
	return 0;
}

static int clarify_dirs(char *pending, size_t pn, char *consumed, size_t cn,
			char *err, size_t errlen)
{
	const char *home = getenv("HOME");
	char root[PATH_MAX];
	char base[PATH_MAX];

	if (!home || !home[0]) {
		snprintf(err, errlen, "HOME 未设置，无法定位 clarify pending");
		return -1;
	}
	if (snprintf(root, sizeof(root), "%s/.aikernel", home) >=
	    (int)sizeof(root) ||
	    snprintf(base, sizeof(base), "%s/clarify", root) >=
	    (int)sizeof(base) ||
	    snprintf(pending, pn, "%s/pending", base) >= (int)pn ||
	    snprintf(consumed, cn, "%s/consumed", base) >= (int)cn) {
		snprintf(err, errlen, "clarify pending 路径过长");
		return -1;
	}
	if (mkdir(root, 0700) != 0 && errno != EEXIST) {
		snprintf(err, errlen, "创建 %s 失败：%s", root,
			 strerror(errno));
		return -1;
	}
	if (clarify_mkdir_secure(base) != 0 ||
	    clarify_mkdir_secure(pending) != 0 ||
	    clarify_mkdir_secure(consumed) != 0) {
		snprintf(err, errlen, "创建 clarify 目录失败：%s",
			 strerror(errno));
		return -1;
	}
	return 0;
}

static int clarify_paths(const char *nonce, char *pending, size_t pn,
			 char *consumed, size_t cn, char *err, size_t errlen)
{
	const char *home = getenv("HOME");
	char root[PATH_MAX];
	char base[PATH_MAX];

	if (!home || !home[0]) {
		snprintf(err, errlen, "HOME 未设置，无法定位 clarify pending");
		return -1;
	}
	if (snprintf(root, sizeof(root), "%s/.aikernel", home) >=
	    (int)sizeof(root) ||
	    snprintf(base, sizeof(base), "%s/clarify", root) >=
	    (int)sizeof(base) ||
	    snprintf(pending, pn, "%s/pending/%s.json", base, nonce) >=
	    (int)pn ||
	    snprintf(consumed, cn, "%s/consumed/%s.json", base, nonce) >=
	    (int)cn) {
		snprintf(err, errlen, "clarify pending 路径过长");
		return -1;
	}
	return 0;
}

static int write_all_fd(int fd, const char *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t w = write(fd, buf + off, len - off);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (w == 0)
			return -1;
		off += (size_t)w;
	}
	return 0;
}

int ask_clarify_pending_save(const struct ask_clarify_request *req,
			     const char *nonce, long long expires_at_ms,
			     const char *session,
			     const char *original_question,
			     int asked, char *err, size_t errlen)
{
	char pending_dir[PATH_MAX], consumed_dir[PATH_MAX];
	char final_path[PATH_MAX], tmp_path[PATH_MAX];
	struct clarify_buf b = { 0 };
	char ts[80];
	int fd = -1;
	int rc = -1;

	if (asked < 1)
		asked = 1;
	if (asked > ASK_CLARIFY_MAX_PER_ASK)
		asked = ASK_CLARIFY_MAX_PER_ASK;
	if (!req || !clarify_nonce_ok(nonce) || !expires_at_ms ||
	    !session || !session[0] ||
	    !original_question || !original_question[0]) {
		snprintf(err, errlen, "pending 参数非法");
		return -1;
	}
	if (strlen(session) > ASK_CLARIFY_SESSION_MAX ||
	    strlen(original_question) > ASK_CLARIFY_RESUMED_MAX) {
		snprintf(err, errlen, "pending session/question 过长");
		return -1;
	}
	if (ask_clarify_validate(req, err, errlen) != 0)
		return -1;
	if (clarify_dirs(pending_dir, sizeof(pending_dir), consumed_dir,
			 sizeof(consumed_dir), err, errlen) != 0)
		return -1;
	if (snprintf(final_path, sizeof(final_path), "%s/%s.json",
		     pending_dir, nonce) >= (int)sizeof(final_path) ||
	    snprintf(tmp_path, sizeof(tmp_path), "%s/.tmp-%s-%d",
		     pending_dir, nonce, (int)getpid()) >=
	    (int)sizeof(tmp_path)) {
		snprintf(err, errlen, "pending 路径过长");
		return -1;
	}

	fmt_iso(expires_at_ms, ts, sizeof(ts));
	cb_puts(&b, "{\"status\":\"CLARIFY_PENDING\",\"version\":1,"
		   "\"nonce\":");
	cb_json_str(&b, nonce);
	cb_printf(&b, ",\"expires_at\":%lld", expires_at_ms / 1000);
	cb_printf(&b, ",\"expires_at_ms\":%lld", expires_at_ms);
	cb_printf(&b, ",\"asked\":%d", asked);
	cb_puts(&b, ",\"expires_at_iso\":");
	cb_json_str(&b, ts);
	cb_puts(&b, ",\"session\":");
	cb_json_str(&b, session);
	cb_puts(&b, ",\"original_question\":");
	cb_json_str(&b, original_question);
	cb_puts(&b, ",\"clarify\":{\"question\":");
	cb_json_str(&b, req->question);
	if (req->header[0]) {
		cb_puts(&b, ",\"header\":");
		cb_json_str(&b, req->header);
	}
	cb_puts(&b, ",\"kind\":");
	cb_json_str(&b, req->kind);
	if (req->danger[0]) {
		cb_puts(&b, ",\"danger\":");
		cb_json_str(&b, req->danger);
	}
	cb_printf(&b, ",\"multi_select\":%s",
		  req->multi_select ? "true" : "false");
	if (req->has_recommended) {
		cb_puts(&b, ",\"recommended\":");
		cb_json_str(&b, req->recommended);
	}
	if (req->has_default) {
		cb_puts(&b, ",\"default\":");
		cb_json_str(&b, req->default_id);
	}
	add_option_arrays(&b, req);
	cb_puts(&b, "}}\n");
	if (b.err || !b.p) {
		snprintf(err, errlen, "pending JSON 构造失败");
		goto out;
	}

	fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0 && errno == EEXIST) {
		unlink(tmp_path);
		fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
			  0600);
	}
	if (fd < 0) {
		snprintf(err, errlen, "创建 pending 临时文件失败：%s",
			 strerror(errno));
		goto out;
	}
	fchmod(fd, 0600);
	if (write_all_fd(fd, b.p, b.len) != 0 || fsync(fd) != 0) {
		snprintf(err, errlen, "写 pending 失败：%s", strerror(errno));
		goto out;
	}
	if (close(fd) != 0) {
		fd = -1;
		snprintf(err, errlen, "关闭 pending 失败：%s", strerror(errno));
		goto out;
	}
	fd = -1;
	if (rename(tmp_path, final_path) != 0) {
		snprintf(err, errlen, "提交 pending 失败：%s", strerror(errno));
		goto out;
	}
	rc = 0;
out:
	if (fd >= 0)
		close(fd);
	if (rc != 0)
		unlink(tmp_path);
	free(b.p);
	(void)consumed_dir;
	return rc;
}

static int read_file_secure(const char *path, char **out, size_t *outlen,
			    char *err, size_t errlen)
{
	int fd;
	struct stat st;
	char *buf;
	size_t off = 0;

	*out = NULL;
	*outlen = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) {
		snprintf(err, errlen, "打开 pending 失败：%s",
			 strerror(errno));
		return -1;
	}
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
	    st.st_size <= 0 || st.st_size > 64 * 1024) {
		close(fd);
		snprintf(err, errlen, "pending 文件非法或过大");
		return -1;
	}
	buf = malloc((size_t)st.st_size + 1);
	if (!buf) {
		close(fd);
		snprintf(err, errlen, "内存不足（pending）");
		return -1;
	}
	while (off < (size_t)st.st_size) {
		ssize_t r = read(fd, buf + off, (size_t)st.st_size - off);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			close(fd);
			snprintf(err, errlen, "读 pending 失败：%s",
				 strerror(errno));
			return -1;
		}
		if (r == 0)
			break;
		off += (size_t)r;
	}
	close(fd);
	if (off != (size_t)st.st_size) {
		free(buf);
		snprintf(err, errlen, "pending 文件被截断");
		return -1;
	}
	buf[off] = '\0';
	*out = buf;
	*outlen = off;
	return 0;
}

static int json_get_ll(const char *obj, size_t len, const char *key,
		       long long *out, int *found)
{
	const char *v = NULL;
	size_t vl = 0;
	int vt = 0;
	int rc = ai_json_obj_get(obj, len, key, &v, &vl, &vt);

	*found = 0;
	if (rc <= 0)
		return rc;
	if (vt != AI_JSON_NUM)
		return -1;
	*out = ai_json_ll(v, vl);
	*found = 1;
	return 1;
}

int ask_clarify_pending_load(const char *nonce, const char *session_expected,
			     struct ask_clarify_pending *out,
			     char *err, size_t errlen)
{
	char pending_path[PATH_MAX], consumed_path[PATH_MAX];
	char *text = NULL;
	size_t tlen = 0;
	const char *p;
	const char *end;
	const char *tok = NULL;
	size_t tlen_tok = 0;
	int type = 0;
	int found;
	long long version = 0;
	long long expires = 0;
	long long asked = 0;
	long long now;
	char *clarify_json = NULL;
	int rc = -1;

	if (!out) {
		snprintf(err, errlen, "内部错误：pending 输出为空");
		return -1;
	}
	if (errlen)
		err[0] = '\0';
	memset(out, 0, sizeof(*out));
	if (!clarify_nonce_ok(nonce)) {
		snprintf(err, errlen, "非法 clarify nonce（需要 cq- 前缀）");
		return -1;
	}
	if (clarify_paths(nonce, pending_path, sizeof(pending_path),
			  consumed_path, sizeof(consumed_path),
			  err, errlen) != 0)
		return -1;
	if (read_file_secure(pending_path, &text, &tlen, err, errlen) != 0) {
		if (access(consumed_path, F_OK) == 0)
			snprintf(err, errlen,
				 "clarify pending 已被消费（重放被拒绝）");
		else if (access(pending_path, F_OK) != 0)
			snprintf(err, errlen,
				 "未知或已过期的 clarify nonce");
		else if (!err[0])
			snprintf(err, errlen, "读 pending 失败");
		return -1;
	}
	p = text;
	end = text + tlen;
	if (ai_json_scan_value(&p, end, &tok, &tlen_tok, &type) != 0 ||
	    type != AI_JSON_OBJ) {
		snprintf(err, errlen, "pending 记录不是 JSON 对象");
		goto out;
	}
	{
		char status[32];

		if (get_json_str(tok, tlen_tok, "status", status,
				 sizeof(status), &found, err, errlen) != 0 ||
		    !found || strcmp(status, "CLARIFY_PENDING") != 0) {
			snprintf(err, errlen, "pending status 非法");
			goto out;
		}
	}
	if (json_get_ll(tok, tlen_tok, "version", &version, &found) != 1 ||
	    !found || version != 1) {
		snprintf(err, errlen, "pending version 非法");
		goto out;
	}
	if (get_json_str(tok, tlen_tok, "nonce", out->nonce,
			 sizeof(out->nonce), &found, err, errlen) != 0 ||
	    !found || strcmp(out->nonce, nonce) != 0) {
		snprintf(err, errlen, "pending nonce 不匹配");
		goto out;
	}
	if (json_get_ll(tok, tlen_tok, "expires_at_ms", &expires,
			&found) != 1 || !found) {
		snprintf(err, errlen, "pending expires_at_ms 缺失/非法");
		goto out;
	}
	now = ai_trace_wall_ms();
	if (expires <= now) {
		snprintf(err, errlen, "clarify pending 已过期");
		goto out;
	}
	if (expires > now + ASK_CLARIFY_TTL_MS + 60000) {
		snprintf(err, errlen, "pending TTL 超出 15 分钟上限");
		goto out;
	}
	out->expires_at_ms = expires;
	if (json_get_ll(tok, tlen_tok, "asked", &asked, &found) != 1 ||
	    !found || asked < 1 || asked > ASK_CLARIFY_MAX_PER_ASK) {
		snprintf(err, errlen, "pending asked 缺失/非法");
		goto out;
	}
	out->asked = (int)asked;
	{
		char iso[80];

		if (get_json_str(tok, tlen_tok, "expires_at_iso", iso,
				 sizeof(iso), &found, err, errlen) != 0 ||
		    !found || !iso[0]) {
			snprintf(err, errlen, "pending expires_at_iso 缺失");
			goto out;
		}
	}
	if (get_json_str(tok, tlen_tok, "session", out->session,
			 sizeof(out->session), &found, err, errlen) != 0 ||
	    !found || !out->session[0]) {
		snprintf(err, errlen, "pending session 缺失");
		goto out;
	}
	if (session_expected && session_expected[0] &&
	    strcmp(session_expected, out->session) != 0) {
		snprintf(err, errlen, "session 不匹配（记录=%s 请求=%s）",
			 out->session, session_expected);
		goto out;
	}
	{
		const char *v = NULL;
		size_t vl = 0;
		int vt = 0;

		if (ai_json_obj_get(tok, tlen_tok, "original_question",
				    &v, &vl, &vt) <= 0 || vt != AI_JSON_STR) {
			snprintf(err, errlen, "pending original_question 缺失");
			goto out;
		}
		out->original_question = ai_json_strdup_str(v, vl);
		if (!out->original_question || !out->original_question[0] ||
		    strlen(out->original_question) > ASK_CLARIFY_RESUMED_MAX) {
			snprintf(err, errlen, "pending original_question 非法");
			goto out;
		}
	}
	{
		const char *v = NULL;
		size_t vl = 0;
		int vt = 0;

		if (ai_json_obj_get(tok, tlen_tok, "clarify", &v, &vl,
				    &vt) <= 0 || vt != AI_JSON_OBJ) {
			snprintf(err, errlen, "pending clarify 缺失/非法");
			goto out;
		}
		clarify_json = malloc(vl + 1);
		if (!clarify_json) {
			snprintf(err, errlen, "内存不足（pending clarify）");
			goto out;
		}
		memcpy(clarify_json, v, vl);
		clarify_json[vl] = '\0';
		if (ask_clarify_parse_request(clarify_json, &out->req,
					      err, errlen) != 0 ||
		    ask_clarify_validate(&out->req, err, errlen) != 0)
			goto out;
	}
	rc = 0;
out:
	free(text);
	free(clarify_json);
	if (rc != 0) {
		free(out->original_question);
		out->original_question = NULL;
	}
	return rc;
}

int ask_clarify_pending_consume(const char *nonce, char *err, size_t errlen)
{
	char pending_path[PATH_MAX], consumed_path[PATH_MAX];

	if (!clarify_nonce_ok(nonce)) {
		snprintf(err, errlen, "非法 clarify nonce（需要 cq- 前缀）");
		return -1;
	}
	if (clarify_paths(nonce, pending_path, sizeof(pending_path),
			  consumed_path, sizeof(consumed_path),
			  err, errlen) != 0)
		return -1;
	if (rename(pending_path, consumed_path) == 0)
		return 0;
	if (errno == ENOENT) {
		if (access(consumed_path, F_OK) == 0)
			snprintf(err, errlen,
				 "clarify pending 已被消费（重放被拒绝）");
		else
			snprintf(err, errlen, "未知或已过期的 clarify nonce");
	} else {
		snprintf(err, errlen, "消费 pending 失败：%s",
			 strerror(errno));
	}
	return -1;
}

void ask_clarify_pending_free(struct ask_clarify_pending *p)
{
	if (!p)
		return;
	free(p->original_question);
	memset(p, 0, sizeof(*p));
}

int ask_clarify_resolve_selection(const struct ask_clarify_request *req,
				  const char *select, const char *other,
				  char *out, size_t outlen,
				  char *err, size_t errlen)
{
	struct ask_clarify_answer ans;
	char obuf[ASK_CLARIFY_TEXT_MAX + 1];
	size_t off = 0;
	int i;

	if (!req || !out || outlen == 0) {
		snprintf(err, errlen, "内部错误：selection 参数为空");
		return -1;
	}
	out[0] = '\0';
	memset(&ans, 0, sizeof(ans));
	obuf[0] = '\0';
	if (select && select[0]) {
		char sbuf[ASK_CLARIFY_TEXT_MAX * 2 + 64];
		int order[ASK_CLARIFY_MAX_OPTIONS];
		char *p;
		int k;

		if (strlen(select) >= sizeof(sbuf)) {
			snprintf(err, errlen, "--clarify-select 过长");
			return -1;
		}
		copy_cap(sbuf, sizeof(sbuf), select);
		trim_inplace(sbuf);
		clarify_display_order(req, order);
		p = sbuf;
		while (*p) {
			char *tok;
			int idx;

			while (*p && is_delim(*p))
				p++;
			if (!*p)
				break;
			tok = p;
			while (*p && !is_delim(*p))
				p++;
			if (*p)
				*p++ = '\0';
			/* CLI 优先按 id 精确匹配；纯数字再回落为菜单序号 */
			idx = id_find(req, tok);
			if (idx < 0) {
				int all_digits = tok[0] != '\0';

				for (k = 0; tok[k]; k++)
					if (!isdigit((unsigned char)tok[k])) {
						all_digits = 0;
						break;
					}
				if (all_digits) {
					long v = strtol(tok, NULL, 10);

					if (v >= 1 && v <= req->n_options)
						idx = order[v - 1];
				}
			}
			if (idx < 0) {
				snprintf(err, errlen,
					 "--clarify-select 含未知/非法选项"
					 "（可用 id 或序号）");
				return -1;
			}
			for (k = 0; k < ans.n_selected; k++)
				if (ans.selected[k] == idx)
					break;
			if (k < ans.n_selected)
				continue;
			if (ans.n_selected >= ASK_CLARIFY_MAX_OPTIONS) {
				snprintf(err, errlen, "选择项过多");
				return -1;
			}
			ans.selected[ans.n_selected++] = idx;
		}
		if (ans.n_selected == 0) {
			snprintf(err, errlen, "--clarify-select 为空/非法");
			return -1;
		}
		if (!req->multi_select && ans.n_selected > 1) {
			snprintf(err, errlen,
				 "该澄清为单选，--clarify-select 只能一个");
			return -1;
		}
	}
	if (other && other[0]) {
		if (strlen(other) > ASK_CLARIFY_TEXT_MAX) {
			snprintf(err, errlen, "--clarify-other 过长");
			return -1;
		}
		copy_cap(obuf, sizeof(obuf), other);
		sanitize_single_line(obuf);
		if (!obuf[0]) {
			snprintf(err, errlen, "--clarify-other 不能为空");
			return -1;
		}
	}
	if (ans.n_selected == 0 && !obuf[0]) {
		snprintf(err, errlen,
			 "--clarify-answer 需要 --clarify-select 或 "
			 "--clarify-other");
		return -1;
	}
	for (i = 0; i < ans.n_selected; i++) {
		const char *label = req->options[ans.selected[i]].label;

		if (off && off + 2 < outlen) {
			out[off++] = ',';
			out[off++] = ' ';
			out[off] = '\0';
		}
		if (off + strlen(label) + 1 > outlen) {
			snprintf(err, errlen, "选择结果过长");
			return -1;
		}
		memcpy(out + off, label, strlen(label));
		off += strlen(label);
		out[off] = '\0';
	}
	if (obuf[0]) {
		const char *pfx = "[Other] ";
		size_t need = strlen(pfx) + strlen(obuf);

		if (off && off + 2 < outlen) {
			out[off++] = ',';
			out[off++] = ' ';
			out[off] = '\0';
		}
		if (off + need + 1 > outlen) {
			snprintf(err, errlen, "选择结果过长");
			return -1;
		}
		memcpy(out + off, pfx, strlen(pfx));
		off += strlen(pfx);
		memcpy(out + off, obuf, strlen(obuf));
		off += strlen(obuf);
		out[off] = '\0';
	}
	return 0;
}

int ask_clarify_build_required_json_ex(const struct ask_clarify_request *req,
				       const char *nonce,
				       long long expires_at_ms,
				       int resume_saved,
				       const char *resume_error,
				       char **out)
{
	struct clarify_buf b = { 0 };
	char ts[80];

	if (!req || !out)
		return -1;
	*out = NULL;
	fmt_iso(expires_at_ms, ts, sizeof(ts));
	cb_puts(&b, "{\"status\":\"CLARIFY_REQUIRED\",\"version\":1,\"nonce\":");
	cb_json_str(&b, nonce ? nonce : "");
	cb_printf(&b, ",\"expires_at\":%lld", expires_at_ms / 1000);
	cb_printf(&b, ",\"expires_at_ms\":%lld", expires_at_ms);
	cb_puts(&b, ",\"expires_at_iso\":");
	cb_json_str(&b, ts);
	cb_puts(&b, ",\"question\":");
	cb_json_str(&b, req->question);
	if (req->header[0]) {
		cb_puts(&b, ",\"header\":");
		cb_json_str(&b, req->header);
	}
	cb_puts(&b, ",\"kind\":");
	cb_json_str(&b, req->kind);
	if (req->danger[0]) {
		cb_puts(&b, ",\"danger\":");
		cb_json_str(&b, req->danger);
	}
	cb_printf(&b, ",\"multi_select\":%s",
		  req->multi_select ? "true" : "false");
	if (req->has_recommended) {
		cb_puts(&b, ",\"recommended\":");
		cb_json_str(&b, req->recommended);
	}
	if (req->has_default) {
		cb_puts(&b, ",\"default\":");
		cb_json_str(&b, req->default_id);
	}
	if (resume_saved >= 0) {
		cb_printf(&b, ",\"resume_saved\":%s",
			  resume_saved ? "true" : "false");
		if (resume_saved) {
			char hint[256];

			snprintf(hint, sizeof(hint),
				 "ai --clarify-answer %s --clarify-select <ids>",
				 nonce ? nonce : "<nonce>");
			cb_puts(&b, ",\"resume_hint\":");
			cb_json_str(&b, hint);
		} else if (resume_error && resume_error[0]) {
			cb_puts(&b, ",\"resume_error\":");
			cb_json_str(&b, resume_error);
		}
	}
	add_option_arrays(&b, req);
	cb_putc(&b, '}');
	if (b.err || !b.p) {
		free(b.p);
		return -1;
	}
	*out = b.p;
	return 0;
}

int ask_clarify_build_required_json(const struct ask_clarify_request *req,
				    const char *nonce, long long expires_at_ms,
				    char **out)
{
	return ask_clarify_build_required_json_ex(req, nonce, expires_at_ms,
						  -1, NULL, out);
}

static void add_selected_arrays(struct clarify_buf *b,
				const struct ask_clarify_request *req,
				const struct ask_clarify_answer *ans)
{
	int i;

	cb_puts(b, ",\"selected\":[");
	for (i = 0; i < ans->n_selected; i++) {
		if (i)
			cb_putc(b, ',');
		cb_json_str(b, req->options[ans->selected[i]].id);
	}
	cb_putc(b, ']');
	cb_puts(b, ",\"labels\":[");
	for (i = 0; i < ans->n_selected; i++) {
		if (i)
			cb_putc(b, ',');
		cb_json_str(b, req->options[ans->selected[i]].label);
	}
	cb_putc(b, ']');
}

int ask_clarify_build_answer_json(const struct ask_clarify_request *req,
				  const char *nonce,
				  const struct ask_clarify_answer *ans,
				  const char *status, int attempts,
				  char **out)
{
	struct clarify_buf b = { 0 };
	struct ask_clarify_answer empty = { 0 };

	if (!req || !ans || !out)
		return -1;
	*out = NULL;
	cb_puts(&b, "{\"status\":");
	cb_json_str(&b, status ? status : "CLARIFY_ANSWER");
	cb_puts(&b, ",\"nonce\":");
	cb_json_str(&b, nonce ? nonce : "");
	cb_puts(&b, ",\"kind\":");
	cb_json_str(&b, req->kind);
	add_selected_arrays(&b, req, ans ? ans : &empty);
	cb_puts(&b, ",\"text\":");
	cb_json_str(&b, ans ? ans->text : "");
	cb_printf(&b, ",\"multi_select\":%s",
		  req->multi_select ? "true" : "false");
	cb_printf(&b, ",\"attempts\":%d", attempts);
	cb_printf(&b, ",\"timed_out\":%s",
		  ans->timed_out ? "true" : "false");
	if (ans->timed_out)
		cb_puts(&b, ",\"reason\":\"timeout\"");
	cb_putc(&b, '}');
	if (b.err || !b.p) {
		free(b.p);
		return -1;
	}
	*out = b.p;
	return 0;
}

int ask_clarify_make_nonce(char *buf, size_t n)
{
	static unsigned long counter;
	unsigned char raw[12];
	int fd;
	ssize_t got = -1;
	size_t i;
	size_t off = 0;

	if (!buf || n < 8)
		return -1;
	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		got = read(fd, raw, sizeof(raw));
		close(fd);
	}
	if (got == (ssize_t)sizeof(raw)) {
		off = (size_t)snprintf(buf, n, "cq-");
		for (i = 0; i < sizeof(raw) && off + 2 < n; i++)
			off += (size_t)snprintf(buf + off, n - off, "%02x",
						raw[i]);
		return 0;
	}
	snprintf(buf, n, "cq-%d-%lld-%lu", (int)getpid(),
		 (long long)time(NULL), counter++);
	return 0;
}

/* ---- TTY 菜单 ---- */

static void print_menu(const struct ask_clarify_request *req)
{
	int order[ASK_CLARIFY_MAX_OPTIONS];
	int i;
	int n;

	clarify_display_order(req, order);
	if (req->header[0])
		printf("\n[clarify] %s\n  %s\n", req->header, req->question);
	else
		printf("\n[clarify] %s\n", req->question);
	for (i = 0; i < req->n_options; i++) {
		const struct ask_clarify_option *o = &req->options[order[i]];
		int rec = req->has_recommended &&
			  strcmp(req->recommended, o->id) == 0;
		int def = req->has_default &&
			  strcmp(req->default_id, o->id) == 0;
		const char *d = option_danger(req, order[i]);

		printf("  %d) %s%s%s%s%s", i + 1, o->label,
		       rec ? "（推荐）" : "", def ? "（默认）" : "",
		       d[0] ? " [" : "", d[0] ? d : "");
		if (d[0])
			printf("]");
		if (o->description[0])
			printf("  — %s", o->description);
		printf("\n");
		if (o->why[0])
			printf("      理由: %s\n", o->why);
		if (o->impact[0])
			printf("      影响: %s\n", o->impact);
		if (o->rollback[0])
			printf("      回滚: %s\n", o->rollback);
	}
	printf("  [o] 其他（自由输入）\n");
	printf("  [q] 取消\n");
	if (req->multi_select) {
		n = printf("选择（多选：逗号/空格分隔序号或 id）: ");
	} else {
		n = printf("选择（序号或 id）: ");
	}
	(void)n;
	fflush(stdout);
}

/*
 * tty_read_line - 带超时的单行读取（select/read，15 分钟兜底）
 * 返回 1=读到一行；0=EOF/读错误；-2=超时（调用方按取消处理）。
 */
static int tty_read_line(char *buf, size_t cap, int timeout_ms)
{
	long long deadline;
	size_t n = 0;

	buf[0] = '\0';
	{
		struct timespec ts;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		deadline = (long long)ts.tv_sec * 1000 +
			   ts.tv_nsec / 1000000 + timeout_ms;
	}
	for (;;) {
		fd_set rf;
		struct timeval tv;
		struct timespec ts;
		long long now;
		int sr;
		char c;
		ssize_t r;

		clock_gettime(CLOCK_MONOTONIC, &ts);
		now = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
		if (now >= deadline)
			return -2;
		FD_ZERO(&rf);
		FD_SET(STDIN_FILENO, &rf);
		tv.tv_sec = (long)((deadline - now) / 1000);
		tv.tv_usec = (long)(((deadline - now) % 1000) * 1000);
		sr = select(STDIN_FILENO + 1, &rf, NULL, NULL, &tv);
		if (sr == 0)
			return -2;
		if (sr < 0) {
			if (errno == EINTR)
				continue;
			return 0;
		}
		r = read(STDIN_FILENO, &c, 1);
		if (r <= 0)
			return 0;
		if (c == '\n')
			break;
		if (c == '\r')
			continue;
		if (n + 1 < cap)
			buf[n++] = c;
	}
	buf[n] = '\0';
	return 1;
}

int ask_clarify_tty(void)
{
	return isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
}

static int tty_ask(const struct ask_clarify_request *req,
		   struct ask_clarify_answer *ans, int *attempts)
{
	char line[ASK_CLARIFY_TEXT_MAX * 2 + 64];
	int attempt;

	print_menu(req);
	for (attempt = 1; attempt <= ASK_CLARIFY_MAX_ATTEMPTS; attempt++) {
		int st;
		int rr;

		rr = tty_read_line(line, sizeof(line), ASK_CLARIFY_TTL_MS);
		if (rr == -2) {
			ans->timed_out = 1;
			if (attempts)
				*attempts = attempt;
			return ASK_CLARIFY_ANS_CANCEL;
		}
		if (rr == 0) {
			if (attempts)
				*attempts = attempt;
			return ASK_CLARIFY_ANS_CANCEL;
		}
		if (!line[0]) {
			printf("  无效输入，请重试（%d/%d）\n", attempt,
			       ASK_CLARIFY_MAX_ATTEMPTS);
			continue;
		}
		st = ask_clarify_parse_answer(line, req, ans);
		if (st == ASK_CLARIFY_ANS_OK ||
		    st == ASK_CLARIFY_ANS_CANCEL) {
			if (attempts)
				*attempts = attempt;
			return st;
		}
		if (st == ASK_CLARIFY_ANS_OTHER) {
			if (!ans->text[0]) {
				printf("  Other: ");
				fflush(stdout);
				rr = tty_read_line(line, sizeof(line),
						   ASK_CLARIFY_TTL_MS);
				if (rr == -2) {
					ans->timed_out = 1;
					if (attempts)
						*attempts = attempt;
					return ASK_CLARIFY_ANS_CANCEL;
				}
				if (rr == 0 || !line[0]) {
					printf("  无效输入，请重试（%d/%d）\n",
					       attempt,
					       ASK_CLARIFY_MAX_ATTEMPTS);
					continue;
				}
				copy_cap(ans->text, sizeof(ans->text), line);
				trim_inplace(ans->text);
			}
			if (attempts)
				*attempts = attempt;
			return ASK_CLARIFY_ANS_OTHER;
		}
		printf("  无效输入，请重试（%d/%d）\n", attempt,
		       ASK_CLARIFY_MAX_ATTEMPTS);
	}
	if (attempts)
		*attempts = ASK_CLARIFY_MAX_ATTEMPTS;
	return ASK_CLARIFY_ANS_INVALID;
}

/* ---- 发起澄清 ---- */

int ask_clarify_exec(const struct ask_clarify_request *req,
		     struct ask_clarify_state *st, int tty,
		     struct ask_clarify_answer *ans, char **out_json)
{
	const char *ids[ASK_CLARIFY_MAX_OPTIONS];
	struct ask_clarify_answer local = { 0 };
	char nonce[64];
	long long t0;
	long long expires;
	int attempts = 0;
	int stt = ASK_CLARIFY_ANS_INVALID;
	int i;

	if (!req || !st || !out_json)
		return -1;
	*out_json = NULL;
	if (!ans)
		ans = &local;
	memset(ans, 0, sizeof(*ans));
	if (ask_clarify_make_nonce(nonce, sizeof(nonce)) != 0)
		nonce[0] = '\0';
	for (i = 0; i < req->n_options; i++)
		ids[i] = req->options[i].id;
	t0 = ai_trace_now_ms();
	expires = ai_trace_wall_ms() + ASK_CLARIFY_TTL_MS;
	ai_trace_clarify_request(nonce, req->kind, req->question, ids,
				 req->n_options,
				 req->has_recommended ? req->recommended : "",
				 req->multi_select, tty);

	if (!tty) {
		char resume_err[256] = "";
		int resume_saved = 0;

		if (st->session[0] && st->original_question) {
			if (ask_clarify_pending_save(req, nonce, expires,
						     st->session,
						     st->original_question,
						     st->asked,
						     resume_err,
						     sizeof(resume_err)) == 0) {
				resume_saved = 1;
			} else {
				ai_trace_degraded("clarify",
						  "pending_save_failed",
						  resume_err);
			}
		} else {
			snprintf(resume_err, sizeof(resume_err),
				 "no session context; resume not available");
			ai_trace_degraded("clarify", "pending_no_context",
					  resume_err);
		}
		if (ask_clarify_build_required_json_ex(req, nonce, expires,
						       resume_saved,
						       resume_err,
						       out_json) != 0)
			return -1;
		/* W77c-2b：API 调用方只认 tagged stderr 事件；每轮最多一行 */
		if (!st->event_sent) {
			ask_clarify_emit_event(*out_json);
			st->event_sent = 1;
		}
		st->stop = 1;
		ai_trace_clarify_answer(nonce, req->kind, ids, req->n_options,
					req->has_recommended ?
					req->recommended : "", NULL, 0, "",
					"required", 0,
					ai_trace_now_ms() - t0);
		return 0;
	}

	stt = tty_ask(req, ans, &attempts);
	if (stt == ASK_CLARIFY_ANS_OK) {
		if (ask_clarify_build_answer_json(req, nonce, ans,
						  "CLARIFY_ANSWER",
						  attempts, out_json) != 0)
			return -1;
	} else if (stt == ASK_CLARIFY_ANS_OTHER) {
		if (ask_clarify_build_answer_json(req, nonce, ans,
						  "CLARIFY_ANSWER",
						  attempts, out_json) != 0)
			return -1;
	} else if (stt == ASK_CLARIFY_ANS_CANCEL) {
		if (ask_clarify_build_answer_json(req, nonce, ans,
						  "CLARIFY_CANCELLED",
						  attempts, out_json) != 0)
			return -1;
		st->stop = 1;
	} else {
		if (ask_clarify_build_answer_json(req, nonce, ans,
						  "CLARIFY_INVALID",
						  attempts, out_json) != 0)
			return -1;
		st->stop = 1;
	}

	{
		const char *sel[ASK_CLARIFY_MAX_OPTIONS];
		int nsel = ans->n_selected;

		for (i = 0; i < nsel; i++)
			sel[i] = req->options[ans->selected[i]].id;
		ai_trace_clarify_answer(nonce, req->kind, ids, req->n_options,
					req->has_recommended ?
					req->recommended : "", sel, nsel,
					ans->text,
					stt == ASK_CLARIFY_ANS_OK ? "answered" :
					stt == ASK_CLARIFY_ANS_OTHER ? "other" :
					stt == ASK_CLARIFY_ANS_CANCEL ?
					(ans->timed_out ? "timeout" :
					 "cancelled") : "invalid",
					attempts, ai_trace_now_ms() - t0);
	}
	return 0;
}

int ask_clarify_handle_tool_ex(const char *args_json,
			       struct ask_clarify_state *st, int tty,
			       char **out_text)
{
	struct ask_clarify_request req;
	struct ask_clarify_answer ans;
	char err[256];
	char *json = NULL;
	int rc;

	if (!st || !out_text)
		return -1;
	*out_text = NULL;
	rc = ask_clarify_parse_request(args_json, &req, err, sizeof(err));
	if (rc == 0)
		rc = ask_clarify_validate(&req, err, sizeof(err));
	if (rc != 0) {
		if (asprintf(out_text, "ERROR[E_PARAM_CLARIFY]: %s\n"
			     "USAGE: clarify(question, options[2-4] with "
			     "id/label/why/impact/rollback/danger, "
			     "recommended?, default?, header?, kind?, "
			     "multi_select?)", err) < 0)
			*out_text = NULL;
		return -1;
	}
	if (!ask_clarify_state_begin(st)) {
		*out_text = strdup("ERROR: clarify limit reached "
				   "(max 2 per ask); proceed without further "
				   "clarification.");
		return 0;
	}
	if (ask_clarify_exec(&req, st, tty, &ans, &json) != 0 || !json) {
		*out_text = strdup("ERROR: clarify generation failed");
		return -1;
	}
	if (st->stop) {
		free(st->stop_text);
		st->stop_text = json;
		*out_text = strdup(json);
		return 0;
	}
	*out_text = json;
	return 0;
}

int ask_clarify_handle_tool(const char *args_json,
			    struct ask_clarify_state *st, char **out_text)
{
	return ask_clarify_handle_tool_ex(args_json, st, ask_clarify_tty(),
					  out_text);
}

/* ---- 歧义检测器 ---- */

static const char *const SERVICE_VERBS[] = {
	"restart", "stop", "start", "重启", "停止", "启动",
};

static const char *const DESTRUCTIVE_VERBS[] = {
	"delete", "remove", "clear", "wipe", "删除", "删掉", "删了",
	"清空", "清理", "移除", "抹掉", "擦除",
};

static char *lower_dup(const char *s)
{
	char *out;
	size_t i, n;

	if (!s)
		return NULL;
	n = strlen(s);
	out = malloc(n + 1);
	if (!out)
		return NULL;
	for (i = 0; i <= n; i++)
		out[i] = (char)tolower((unsigned char)s[i]);
	return out;
}

static int word_at(const char *s, const char *w)
{
	size_t n = strlen(w);

	while (*s) {
		const char *p = strstr(s, w);

		if (!p)
			return 0;
		if ((p == s || !isalnum((unsigned char)p[-1])) &&
		    !isalnum((unsigned char)p[n]))
			return 1;
		s = p + 1;
	}
	return 0;
}

static int has_any(const char *s, const char *const *words, int n)
{
	int i;

	for (i = 0; i < n; i++)
		if (strstr(s, words[i]))
			return 1;
	return 0;
}

static const char *find_verb(const char *lower,
			     const char *const *verbs, int n, int *which)
{
	const char *best = NULL;
	int best_i = -1;
	int i;

	for (i = 0; i < n; i++) {
		const char *p;
		size_t wl = strlen(verbs[i]);

		if (wl == 0)
			continue;
		if (isascii((unsigned char)verbs[i][0])) {
			const char *s = lower;

			p = NULL;
			while (*s) {
				const char *q = strstr(s, verbs[i]);

				if (!q)
					break;
				if ((q == lower ||
				     !isalnum((unsigned char)q[-1])) &&
				    !isalnum((unsigned char)q[wl])) {
					p = q;
					break;
				}
				s = q + 1;
			}
		} else {
			p = strstr(lower, verbs[i]);
		}
		if (p && (!best || p < best)) {
			best = p;
			best_i = i;
		}
	}
	if (which)
		*which = best_i;
	return best;
}

static int question_blocked(const char *lower)
{
	static const char *const info[] = {
		"怎么", "如何", "为什么", "什么是", "介绍", "说明",
	};
	static const char *const neg[] = {
		"不要", "别", "禁止", "不能", "无需", "不用", "don't",
		"do not",
	};
	/* 名词/诊断语境里的动词不是操作请求（如“系统启动时间”） */
	static const char *const noun[] = {
		"启动时间", "启动多久", "启动耗时", "开机时间", "运行时间",
		"启动项", "启动失败", "启动不了", "启动报错", "启动日志",
		"重启失败", "停止失败",
		"starting time", "start time", "startup time", "boot time",
		"uptime", "started at",
	};

	if (has_any(lower, info, (int)(sizeof(info) / sizeof(info[0]))))
		return 1;
	if (has_any(lower, neg, (int)(sizeof(neg) / sizeof(neg[0]))))
		return 1;
	if (has_any(lower, noun, (int)(sizeof(noun) / sizeof(noun[0]))))
		return 1;
	if (word_at(lower, "how") || word_at(lower, "why") ||
	    word_at(lower, "what"))
		return 1;
	return 0;
}

int ask_clarify_question_candidate(const char *question)
{
	char *lower;
	int rc = 0;

	if (!question || !question[0])
		return 0;
	lower = lower_dup(question);
	if (!lower)
		return 0;
	if (!question_blocked(lower) &&
	    (find_verb(lower, SERVICE_VERBS,
		       (int)(sizeof(SERVICE_VERBS) / sizeof(SERVICE_VERBS[0])),
		       NULL) ||
	     find_verb(lower, DESTRUCTIVE_VERBS,
		       (int)(sizeof(DESTRUCTIVE_VERBS) /
			     sizeof(DESTRUCTIVE_VERBS[0])), NULL)))
		rc = 1;
	free(lower);
	return rc;
}

static int is_filler(const char *tok)
{
	static const char *const fillers[] = {
		"一下", "下", "这个", "那个", "一个", "服务", "进程", "的",
		"它", "帮我", "请", "把", "将", "给", "我", "the", "a",
		"an", "please", "service", "services", "unit", "process",
		"daemon",
	};
	int i;

	for (i = 0; i < (int)(sizeof(fillers) / sizeof(fillers[0])); i++)
		if (!strcasecmp(tok, fillers[i]))
			return 1;
	return 0;
}

static int is_cn_punct(const char *p, size_t *plen)
{
	static const char *const punct[] = {
		"。", "，", "、", "：", "；", "！", "？",
		"“", "”", "「", "」", "（", "）",
	};
	size_t i;

	for (i = 0; i < sizeof(punct) / sizeof(punct[0]); i++) {
		size_t l = strlen(punct[i]);

		if (strncmp(p, punct[i], l) == 0) {
			*plen = l;
			return 1;
		}
	}
	return 0;
}

static void strip_cn_punct_tail(char *tok)
{
	int again = 1;

	while (again) {
		size_t n = strlen(tok);
		size_t i;

		again = 0;
		if (n == 0)
			break;
		for (i = 0; i < 13; i++) {
			static const char *const punct[] = {
				"。", "，", "、", "：", "；", "！", "？",
				"“", "”", "「", "」", "（", "）",
			};
			size_t l = strlen(punct[i]);

			if (n >= l && strcmp(tok + n - l, punct[i]) == 0) {
				tok[n - l] = '\0';
				again = 1;
				break;
			}
		}
	}
}

static int service_target_present(const char *after)
{
	const char *p = after;
	int tried = 0;

	while (*p && tried < 6) {
		char tok[128];
		size_t n = 0;
		size_t pl = 0;

		for (;;) {
			if (*p && isspace((unsigned char)*p)) {
				p++;
			} else if (*p && strchr(",.;:!?", *p)) {
				p++;
			} else if (is_cn_punct(p, &pl)) {
				p += pl;
			} else {
				break;
			}
		}
		if (!*p)
			break;
		while (*p && !isspace((unsigned char)*p) &&
		       !strchr(",.;:!?", *p) && !is_cn_punct(p, &pl) &&
		       n + 1 < sizeof(tok))
			tok[n++] = *p++;
		tok[n] = '\0';
		tried++;
		if (!tok[0])
			break;
		strip_cn_punct_tail(tok);
		if (!tok[0])
			break;
		if (is_filler(tok))
			continue;
		if (strstr(tok, ".service"))
			return 1;
		{
			size_t i;
			int unit = 1;
			int ascii_alnum = 0;

			for (i = 0; tok[i]; i++) {
				unsigned char c = (unsigned char)tok[i];

				if (c >= 0x80)
					continue;
				if (isalnum(c))
					ascii_alnum = 1;
				else if (c != '_' && c != '-' &&
					 c != '@' && c != '.') {
					unit = 0;
					break;
				}
			}
			return (unit && ascii_alnum) ? 1 : 0;
		}
	}
	return 0;
}

static int has_path_target(const char *q)
{
	const char *p;

	for (p = q; *p; p++) {
		if (*p == '/' && p[1] && !isspace((unsigned char)p[1]))
			return 1;
	}
	return 0;
}

static int build_service_request(const char *lower,
				 const struct ask_clarify_evidence *ev,
				 const char *verb,
				 struct ask_clarify_request *req)
{
	int n = ev->n_services < ASK_CLARIFY_MAX_OPTIONS ?
		ev->n_services : ASK_CLARIFY_MAX_OPTIONS;
	int ascii = 1;
	int i;

	for (i = 0; lower[i]; i++)
		if ((unsigned char)lower[i] >= 0x80) {
			ascii = 0;
			break;
		}
	memset(req, 0, sizeof(*req));
	snprintf(req->question, sizeof(req->question),
		 ascii ? "Which service should I %s?" :
			 "要对哪个服务执行「%s」？", verb);
	snprintf(req->header, sizeof(req->header),
		 ascii ? "Choose the service to %s" : "选择要%s的服务", verb);
	copy_cap(req->kind, sizeof(req->kind), "scope");
	req->multi_select = 0;
	for (i = 0; i < n; i++) {
		snprintf(req->options[i].id, sizeof(req->options[i].id),
			 "%d", i + 1);
		copy_cap(req->options[i].label,
			 sizeof(req->options[i].label), ev->services[i]);
		copy_cap(req->options[i].description,
			 sizeof(req->options[i].description),
			 "当前运行中的 systemd 服务");
		copy_cap(req->options[i].why, sizeof(req->options[i].why),
			 ascii ? "Active per systemctl list-units" :
				 "systemctl list-units 显示该服务正在运行");
		copy_cap(req->options[i].impact,
			 sizeof(req->options[i].impact),
			 ascii ? "Brief service interruption" :
				 "该服务会短暂中断");
		copy_cap(req->options[i].rollback,
			 sizeof(req->options[i].rollback),
			 ascii ? "Service can be restarted" :
				 "可重新启动该服务");
	}
	req->n_options = n;
	copy_cap(req->recommended, sizeof(req->recommended), "1");
	req->has_recommended = 1;
	return 0;
}

static void add_candidate(char cands[ASK_CLARIFY_MAX_OPTIONS]
				       [ASK_CLARIFY_LABEL_MAX + 1],
			  int *n, const char *path)
{
	int i;

	if (!path || !path[0] || *n >= ASK_CLARIFY_MAX_OPTIONS)
		return;
	for (i = 0; i < *n; i++)
		if (strcmp(cands[i], path) == 0)
			return;
	copy_cap(cands[*n], ASK_CLARIFY_LABEL_MAX + 1, path);
	(*n)++;
}

static int build_destructive_request(const struct ask_clarify_evidence *ev,
				     struct ask_clarify_request *req)
{
	char cands[ASK_CLARIFY_MAX_OPTIONS][ASK_CLARIFY_LABEL_MAX + 1];
	int n = 0;
	int i;
	int added;

	memset(cands, 0, sizeof(cands));
	for (i = 0; i < ev->n_tmp_paths && i < 2; i++)
		add_candidate(cands, &n, ev->tmp_paths[i]);
	if (ev->tmp_exists)
		add_candidate(cands, &n, "/tmp");
	if (ev->var_ai_exists)
		add_candidate(cands, &n, "/var/ai");
	if (ev->root_exists)
		add_candidate(cands, &n, "/root");
	if (n < 2)
		return 0;

	memset(req, 0, sizeof(*req));
	snprintf(req->question, sizeof(req->question),
		 "要删除/清理哪个目标？（不会自动执行）");
	copy_cap(req->header, sizeof(req->header), "选择删除目标");
	copy_cap(req->kind, sizeof(req->kind), "scope");
	req->multi_select = 0;
	added = 0;
	for (i = 0; i < n && added < ASK_CLARIFY_MAX_OPTIONS; i++) {
		struct ask_clarify_option *o = &req->options[added];

		snprintf(o->id, sizeof(o->id), "%d", added + 1);
		copy_cap(o->label, sizeof(o->label), cands[i]);
		copy_cap(o->description, sizeof(o->description),
			 "安全根下的候选目标");
		copy_cap(o->why, sizeof(o->why),
			 "该路径位于安全根下（删除后不可恢复）");
		copy_cap(o->impact, sizeof(o->impact),
			 "目标内容将被删除");
		copy_cap(o->rollback, sizeof(o->rollback),
			 "需从备份恢复");
		added++;
	}
	req->n_options = added;
	copy_cap(req->recommended, sizeof(req->recommended), "1");
	req->has_recommended = 1;
	return 1;
}

int ask_clarify_detect(const char *question,
		       const struct ask_clarify_evidence *ev,
		       struct ask_clarify_request *req,
		       char *err, size_t errlen)
{
	char *lower;
	const char *verb;
	int which = -1;
	int rc = 0;

	if (!question || !ev || !req) {
		snprintf(err, errlen, "内部错误：detector 参数为空");
		return -1;
	}
	lower = lower_dup(question);
	if (!lower) {
		snprintf(err, errlen, "内存不足");
		return -1;
	}
	if (question_blocked(lower)) {
		free(lower);
		return 0;
	}

	verb = find_verb(lower, SERVICE_VERBS,
			 (int)(sizeof(SERVICE_VERBS) / sizeof(SERVICE_VERBS[0])),
			 &which);
	if (verb) {
		const char *after = verb + strlen(SERVICE_VERBS[which]);

		if (!service_target_present(after) && ev->n_services >= 2) {
			build_service_request(lower, ev,
					      SERVICE_VERBS[which], req);
			rc = 1;
			goto out;
		}
	}

	verb = find_verb(lower, DESTRUCTIVE_VERBS,
			 (int)(sizeof(DESTRUCTIVE_VERBS) /
			       sizeof(DESTRUCTIVE_VERBS[0])), &which);
	if (verb && !has_path_target(question)) {
		if (build_destructive_request(ev, req))
			rc = 1;
	}
out:
	free(lower);
	return rc;
}

/* ---- evidence 采集（固定命令/目录，不接受外部参数） ---- */

static int cmp_str_ptr(const void *a, const void *b)
{
	const char *const *sa = a;
	const char *const *sb = b;

	return strcmp(*sa, *sb);
}

int ask_clarify_collect_evidence(struct ask_clarify_evidence *ev)
{
	char **svc;
	char *cmd;
	const char *systemctl = "/bin/systemctl";
	int n = 0;

	if (!ev)
		return -1;
	memset(ev, 0, sizeof(*ev));
	svc = calloc(32, sizeof(char *));
	if (!svc)
		return -1;
	if (access("/usr/bin/systemctl", X_OK) == 0)
		systemctl = "/usr/bin/systemctl";
	if (asprintf(&cmd, "%s list-units --type=service --state=running "
		     "--no-legend --no-pager 2>/dev/null", systemctl) >= 0) {
		FILE *fp = popen(cmd, "r");

		free(cmd);
		if (fp) {
			char line[1024];

			while (fgets(line, sizeof(line), fp) && n < 32) {
				char unit[256];
				size_t ul;

				if (sscanf(line, " %255s", unit) != 1)
					continue;
				ul = strlen(unit);
				if (ul < 9 ||
				    strcmp(unit + ul - 8, ".service") != 0)
					continue;
				svc[n] = strdup(unit);
				if (svc[n])
					n++;
			}
			pclose(fp);
		}
	}
	ev->services = (const char *const *)svc;
	ev->n_services = n;

	{
		DIR *d = opendir("/tmp");
		char *names[32];
		int total = 0;
		int nn = 0;
		int i;

		if (d) {
			struct dirent *de;

			while ((de = readdir(d)) && total < 32) {
				if (!strcmp(de->d_name, ".") ||
				    !strcmp(de->d_name, ".."))
					continue;
				names[total] = strdup(de->d_name);
				if (names[total])
					total++;
			}
			closedir(d);
			qsort(names, (size_t)total, sizeof(char *), cmp_str_ptr);
			nn = total > 8 ? 8 : total;
			if (nn > 0) {
				char **paths = calloc((size_t)nn, sizeof(char *));

				if (paths) {
					for (i = 0; i < nn; i++) {
						if (asprintf(&paths[i], "/tmp/%s",
							     names[i]) < 0)
							paths[i] = NULL;
					}
					ev->tmp_paths =
						(const char *const *)paths;
					ev->n_tmp_paths = nn;
				}
			}
			for (i = 0; i < total; i++)
				free(names[i]);
		}
	}
	ev->tmp_exists = (access("/tmp", F_OK) == 0);
	ev->root_exists = (access("/root", F_OK) == 0);
	ev->var_ai_exists = (access("/var/ai", F_OK) == 0);
	return 0;
}

void ask_clarify_evidence_free(struct ask_clarify_evidence *ev)
{
	int i;

	if (!ev)
		return;
	if (ev->services) {
		char **svc = (char **)ev->services;

		for (i = 0; i < ev->n_services; i++)
			free(svc[i]);
		free(svc);
	}
	if (ev->tmp_paths) {
		char **paths = (char **)ev->tmp_paths;

		for (i = 0; i < ev->n_tmp_paths; i++)
			free(paths[i]);
		free(paths);
	}
	memset(ev, 0, sizeof(*ev));
}
