// SPDX-License-Identifier: GPL-2.0
/*
 * acdigest.c - 会话摘要模板 / 校验 / 分段画像 / 恢复载荷 / delta 合并链
 *
 * T5c 逐语义复刻 ref-autocondense/digest.py（638 行）。全部字符串操作对齐
 * Python str 语义：长度与切片按 Unicode 码点、strip 为 Unicode 空白、
 * splitlines 边界含 \r/\v/\f/\x1c-\x1e/\x85/\u2028/\u2029。分段/打包/合并
 * 共享同一份 split_sections 解析（digest.py:87-109）。
 */
#include "autocondense/acdigest.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* ------------------------------------------------------------------ */
/* 常量（digest.py 逐字）                                              */
/* ------------------------------------------------------------------ */

static const char AC_TEMPLATE[] =
	"# 会话快照 · {project} · {ts} · 触发:{reason}\n\n"
	"## 目标（用户最终想要什么）\n\n"
	"- （用 1-3 句写清用户最终想要什么，写结论不写过程）\n\n"
	"## 关键决策与理由（含被否决的方案）\n\n"
	"- 决策：（做了什么决定、为什么）\n"
	"- 被否决：（考虑过但放弃的方案及原因）\n\n"
	"## 已完成（每项注明验证方式：测试通过/编译通过/用户确认）\n\n"
	"- （已完成事项：验证方式）\n\n"
	"## 未完成/进行中（精确到下一个动作；无则写「（无）」）\n\n"
	"（无）\n\n"
	"## 文件变更清单（关键改动 file:line）\n\n"
	"- （路径:行号 —— 关键改动说明）\n\n"
	"## 踩过的坑与已排除的方向\n\n"
	"- （坑与已排除方向，避免恢复后重蹈覆辙）\n\n"
	"## 恢复指针（transcript 路径、更早快照路径、SME 检索关键词）\n\n"
	"- transcript:（当前会话 transcript 路径）\n"
	"- 更早快照:（最近一次快照文件路径，如无写「无」）\n"
	"- SME 检索关键词:（3-5 个用于检索历史记忆的关键词）\n";

static const char *const AC_REQUIRED_SECTIONS[] = {
	"## 目标", "## 已完成", "## 未完成", "## 文件变更清单", "## 恢复指针"
};
#define AC_N_REQUIRED (sizeof(AC_REQUIRED_SECTIONS) / sizeof(AC_REQUIRED_SECTIONS[0]))

#define AC_MIN_CHARS 200
#define AC_BULLET_CHAR_CAP 200		/* 决策/坑：每条截 ≤200 字符 */
#define AC_BULLET_PER_SECTION_CAP 10	/* 决策/坑/已完成：每节最多条数 */
#define AC_DONE_LINE_CAP 80		/* 已完成：每条压成一行 ≤80 字符 */
#define AC_GOAL_CHAR_CAP 300		/* 目标：≤300 字符 */
#define AC_FILE_LIST_MAX_BULLETS 8	/* 文件清单 bullet 条数上限 */

static const char SEC_GOAL[] = "## 目标";
static const char SEC_DECISIONS[] = "## 关键决策与理由";
static const char SEC_DONE[] = "## 已完成";
static const char SEC_TODO[] = "## 未完成";
static const char SEC_FILES[] = "## 文件变更清单";
static const char SEC_PITFALLS[] = "## 踩过的坑与已排除的方向";
static const char SEC_RESTORE_PTR[] = "## 恢复指针";

static const char MISC_TYPE[] = "misc";
static const char MISC_TAG[] = "misc";
#define MISC_IMPORTANCE 0.55
static const char DIGEST_TYPE[] = "digest";
static const char DIGEST_TAG[] = "session_digest";
#define DIGEST_IMPORTANCE 0.7

enum split_mode { MODE_WHOLE = 0, MODE_BULLETS, MODE_FILES };

struct seg_spec {
	const char *prefix;
	const char *type;
	const char *tag;
	double importance;
	enum split_mode mode;
};

static const struct seg_spec SEG_SPECS[] = {
	{ SEC_GOAL, "goal", "session_goal", 0.65, MODE_WHOLE },
	{ SEC_DECISIONS, "decision", "decision", 0.8, MODE_BULLETS },
	{ SEC_DONE, "accomplishment", "accomplishment", 0.7, MODE_BULLETS },
	{ SEC_TODO, "todo", "todo", 0.75, MODE_BULLETS },
	{ SEC_FILES, "file_change", "file_change", 0.6, MODE_FILES },
	{ SEC_PITFALLS, "pitfall", "pitfall", 0.8, MODE_BULLETS },
	{ SEC_RESTORE_PTR, "restore_pointer", "restore_pointer", 0.5, MODE_WHOLE },
};
#define N_SEG_SPECS (sizeof(SEG_SPECS) / sizeof(SEG_SPECS[0]))

/* ------------------------------------------------------------------ */
/* UTF-8 / Python str 语义助手                                         */
/* ------------------------------------------------------------------ */

static size_t slen(const char *s)
{
	return s ? strlen(s) : 0;
}

static char *xstrdup(const char *s)
{
	size_t n = slen(s) + 1;
	char *p = malloc(n);

	if (p)
		memcpy(p, s ? s : "", n);
	return p;
}

static char *xstrndup(const char *s, size_t n)
{
	char *p = malloc(n + 1);

	if (p) {
		if (s && n)
			memcpy(p, s, n);
		p[n] = '\0';
	}
	return p;
}

static char *xstrndup_guard(const char *s, size_t n)
{
	if (!s)
		return xstrndup("", 0);
	return xstrndup(s, n);
}

/* 解码一个码点；非法序列按单字节计（对齐 Python errors 丢弃的计数语义）*/
static uint32_t u8_next(const char *s, size_t len, size_t *adv)
{
	const unsigned char *p = (const unsigned char *)s;

	*adv = 1;
	if (len == 0 || p[0] < 0x80)
		return p[0];
	if (p[0] >= 0xC2 && p[0] <= 0xDF && len >= 2 && (p[1] & 0xC0) == 0x80) {
		*adv = 2;
		return ((uint32_t)(p[0] & 0x1F) << 6) | (p[1] & 0x3F);
	}
	if (p[0] >= 0xE0 && p[0] <= 0xEF && len >= 3 && (p[1] & 0xC0) == 0x80 &&
	    (p[2] & 0xC0) == 0x80) {
		uint32_t cp = ((uint32_t)(p[0] & 0x0F) << 12) |
			      ((uint32_t)(p[1] & 0x3F) << 6) | (p[2] & 0x3F);

		if (cp >= 0x800 && !(cp >= 0xD800 && cp <= 0xDFFF)) {
			*adv = 3;
			return cp;
		}
	}
	if (p[0] >= 0xF0 && p[0] <= 0xF4 && len >= 4 && (p[1] & 0xC0) == 0x80 &&
	    (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80) {
		uint32_t cp = ((uint32_t)(p[0] & 0x07) << 18) |
			      ((uint32_t)(p[1] & 0x3F) << 12) |
			      ((uint32_t)(p[2] & 0x3F) << 6) | (p[3] & 0x3F);

		if (cp >= 0x10000 && cp <= 0x10FFFF) {
			*adv = 4;
			return cp;
		}
	}
	return 0xFFFD;		/* 非法首字节：按 1 字节跳过 */
}

static size_t u8_cplen(const char *s)
{
	size_t len = slen(s), i = 0, n = 0;

	while (i < len) {
		size_t adv;

		u8_next(s + i, len - i, &adv);
		i += adv;
		n++;
	}
	return n;
}

/* Python str.isspace() 空白集（ASCII + Unicode White_Space + \x1c-\x1f）*/
static int cp_is_ws(uint32_t cp)
{
	if (cp == 0x20 || (cp >= 0x09 && cp <= 0x0D) || (cp >= 0x1C && cp <= 0x1F))
		return 1;
	switch (cp) {
	case 0x85:
	case 0xA0:
	case 0x1680:
	case 0x2028:
	case 0x2029:
	case 0x202F:
	case 0x205F:
	case 0x3000:
		return 1;
	default:
		return cp >= 0x2000 && cp <= 0x200A;
	}
}

/* Python str.splitlines() 行边界（注意不含 \x1f 与 \xa0）*/
static int cp_is_line_break(uint32_t cp)
{
	return cp == 0x0A || cp == 0x0D || cp == 0x0B || cp == 0x0C ||
	       cp == 0x1C || cp == 0x1D || cp == 0x1E || cp == 0x85 ||
	       cp == 0x2028 || cp == 0x2029;
}

/* Python s.splitlines()：不产生尾随空行；每行 malloc */
static char **py_splitlines(const char *s, size_t *n_out)
{
	size_t len = slen(s), i = 0, cap = 16, n = 0;
	char **out = malloc(cap * sizeof(*out));

	*n_out = 0;
	if (!out)
		return NULL;
	while (i < len) {
		size_t start = i;

		while (i < len) {
			size_t adv;
			uint32_t cp = u8_next(s + i, len - i, &adv);

			if (cp_is_line_break(cp)) {
				/* \r\n 计为一个换行 */
				if (cp == 0x0D && i + adv < len && s[i + adv] == '\n')
					adv++;
				break;
			}
			i += adv;
		}
		if (n == cap) {
			char **grown = realloc(out, (cap *= 2) * sizeof(*out));

			if (!grown)
				break;
			out = grown;
		}
		out[n] = xstrndup_guard(s + start, i - start);
		if (!out[n])
			break;
		n++;
		if (i >= len)
			break;
		{
			size_t adv;

			u8_next(s + i, len - i, &adv);
			i += adv;
		}
	}
	*n_out = n;
	return out;
}

static void free_lines(char **lines, size_t n)
{
	if (!lines)
		return;
	for (size_t i = 0; i < n; i++)
		free(lines[i]);
	free(lines);
}

static char *py_strip(const char *s)
{
	size_t len = slen(s), i = 0, j;

	if (!s || len == 0)
		return xstrdup("");
	/* 前向 */
	while (i < len) {
		size_t adv;
		uint32_t cp = u8_next(s + i, len - i, &adv);

		if (!cp_is_ws(cp))
			break;
		i += adv;
	}
	/* 后向：从尾部退整码点 */
	j = len;
	while (j > i) {
		size_t k = j - 1, adv;
		uint32_t cp;

		while (k > i && ((unsigned char)s[k] & 0xC0) == 0x80)
			k--;
		cp = u8_next(s + k, j - k, &adv);
		if (!cp_is_ws(cp))
			break;
		j = k;
	}
	return xstrndup(s + i, j - i);
}

static char *py_lstrip(const char *s)
{
	size_t len = slen(s), i = 0;

	if (!s)
		return xstrdup("");
	while (i < len) {
		size_t adv;
		uint32_t cp = u8_next(s + i, len - i, &adv);

		if (!cp_is_ws(cp))
			break;
		i += adv;
	}
	return xstrndup(s + i, len - i);
}

/* " ".join(s.split())：按 Unicode 空白切分再用单空格连接 */
static char *py_ws_collapse(const char *s)
{
	size_t len = slen(s), i = 0;
	char *buf = malloc(len + 1);
	size_t o = 0;
	int at_tok = 0;

	if (!buf || !s) {
		free(buf);
		return xstrdup("");
	}
	while (i < len) {
		size_t adv;
		uint32_t cp = u8_next(s + i, len - i, &adv);

		if (cp_is_ws(cp)) {
			at_tok = 0;
			i += adv;
			continue;
		}
		if (!at_tok && o > 0)
			buf[o++] = ' ';
		at_tok = 1;
		memcpy(buf + o, s + i, adv);
		o += adv;
		i += adv;
	}
	buf[o] = '\0';
	return buf;
}

/* Python 切片 s[start:end]（码点语义，负值从尾数）*/
static char *u8_slice(const char *s, long long start, long long end)
{
	long long len, b, e, i;
	size_t byte_start, byte_end, sl, off;

	if (!s)
		return xstrdup("");
	len = (long long)u8_cplen(s);
	if (start < 0) {
		start += len;
		if (start < 0)
			start = 0;
	}
	if (end < 0) {
		end += len;
		if (end < 0)
			end = 0;
	}
	if (start > len)
		start = len;
	if (end > len)
		end = len;
	b = start;
	e = end < b ? b : end;
	i = 0;
	sl = strlen(s);
	off = 0;
	while (i < b && off < sl) {
		size_t adv;

		u8_next(s + off, sl - off, &adv);
		off += adv;
		i++;
	}
	byte_start = off;
	while (i < e && off < sl) {
		size_t adv;

		u8_next(s + off, sl - off, &adv);
		off += adv;
		i++;
	}
	byte_end = off;
	return xstrndup(s + byte_start, byte_end - byte_start);
}

static int starts_with(const char *s, const char *prefix)
{
	return s && prefix && strncmp(s, prefix, strlen(prefix)) == 0;
}

static char *str_join(const char *const *parts, size_t n, const char *sep)
{
	size_t sep_n = slen(sep), total = 1;
	char *out, *o;

	for (size_t i = 0; i < n; i++)
		total += slen(parts[i]) + (i ? sep_n : 0);
	out = malloc(total);
	if (!out)
		return NULL;
	o = out;
	for (size_t i = 0; i < n; i++) {
		if (i && sep_n) {
			memcpy(o, sep, sep_n);
			o += sep_n;
		}
		size_t l = slen(parts[i]);

		if (l) {
			memcpy(o, parts[i], l);
			o += l;
		}
	}
	*o = '\0';
	return out;
}

static char *str_concat3(const char *a, const char *b, const char *c)
{
	size_t na = slen(a), nb = slen(b), nc = slen(c);
	char *out = malloc(na + nb + nc + 1);

	if (!out)
		return NULL;
	if (na)
		memcpy(out, a, na);
	if (nb)
		memcpy(out + na, b, nb);
	if (nc)
		memcpy(out + na + nb, c, nc);
	out[na + nb + nc] = '\0';
	return out;
}

/* ------------------------------------------------------------------ */
/* 章节解析（split_sections，分段/打包/合并共用）                      */
/* ------------------------------------------------------------------ */

struct md_section {
	char *heading;		/* strip 后的标题行 */
	char **lines;		/* 正文行（原始行，未 strip） */
	size_t n_lines;
};

struct md_doc {
	char **pre;
	size_t n_pre;
	struct md_section *secs;
	size_t n_secs;
};

static void md_doc_free(struct md_doc *d)
{
	free_lines(d->pre, d->n_pre);
	for (size_t i = 0; i < d->n_secs; i++) {
		free(d->secs[i].heading);
		free_lines(d->secs[i].lines, d->secs[i].n_lines);
	}
	free(d->secs);
	memset(d, 0, sizeof(*d));
}

static int is_section_heading(const char *line)
{
	char *t;
	int eq;

	if (starts_with(line, "## "))
		return 1;
	t = py_strip(line);
	eq = t && strcmp(t, "##") == 0;
	free(t);
	return eq;
}

/* 失败时 *d 已清零（调用方无须再 free）。成功返回 0。*/
static int md_doc_parse(struct md_doc *d, const char *md)
{
	size_t n_lines = 0;
	char **lines;
	struct md_section *secs;
	char **pre;
	size_t n_pre = 0, n_secs = 0, cap_lines;
	struct md_section cur;
	int in_sec = 0, ok = 1;

	memset(d, 0, sizeof(*d));
	lines = py_splitlines(md ? md : "", &n_lines);
	if (!lines)
		return -1;
	cap_lines = n_lines + 1;
	pre = malloc(cap_lines * sizeof(*pre));
	secs = malloc(cap_lines * sizeof(*secs));
	if (!pre || !secs) {
		free(pre);
		free(secs);
		free_lines(lines, n_lines);
		return -1;
	}
	memset(&cur, 0, sizeof(cur));
	for (size_t i = 0; i < n_lines; i++) {
		char *line = lines[i];

		if (is_section_heading(line)) {
			if (in_sec)
				secs[n_secs++] = cur;
			memset(&cur, 0, sizeof(cur));
			cur.heading = py_strip(line);
			cur.lines = malloc(cap_lines * sizeof(char *));
			cur.n_lines = 0;
			in_sec = 1;
			if (!cur.heading || !cur.lines) {
				free(cur.heading);
				free(cur.lines);
				in_sec = 0;
				free(line);	/* 本行丢弃，停止解析 */
				ok = 0;
				break;
			}
		} else if (in_sec) {
			cur.lines[cur.n_lines++] = line;
		} else {
			pre[n_pre++] = line;
		}
	}
	if (in_sec && ok)
		secs[n_secs++] = cur;
	else if (in_sec && !ok) {
		free(cur.heading);
		free_lines(cur.lines, cur.n_lines);
	}
	free(lines);	/* 行本身已转移给 pre/secs；异常路径剩余行泄漏可接受（OOM）*/
	if (!ok) {
		for (size_t i = 0; i < n_secs; i++) {
			free(secs[i].heading);
			free_lines(secs[i].lines, secs[i].n_lines);
		}
		free_lines(pre, n_pre);
		free(pre);
		free(secs);
		return -1;
	}
	d->pre = pre;
	d->n_pre = n_pre;
	d->secs = secs;
	d->n_secs = n_secs;
	return 0;
}

static const struct md_section *find_section(const struct md_doc *d,
					     const char *prefix)
{
	for (size_t i = 0; i < d->n_secs; i++)
		if (starts_with(d->secs[i].heading, prefix))
			return &d->secs[i];
	return NULL;
}

static char *section_content(const struct md_section *sec)
{
	char *joined = str_join((const char *const *)sec->lines, sec->n_lines, "\n");
	char *stripped = py_strip(joined ? joined : "");

	free(joined);
	return stripped;
}

static char *doc_section_content(const struct md_doc *d, const char *prefix)
{
	const struct md_section *sec = find_section(d, prefix);

	if (!sec)
		return xstrdup("");
	return section_content(sec);
}

static char *first_line(const char *text)
{
	size_t n;
	char **lines = py_splitlines(text, &n);
	char *out = NULL;

	for (size_t i = 0; i < n; i++) {
		char *t = py_strip(lines[i]);

		if (t && *t) {
			out = t;
			break;
		}
		free(t);
	}
	free_lines(lines, n);
	return out ? out : xstrdup("");
}

/* ------------------------------------------------------------------ */
/* 模板渲染                                                            */
/* ------------------------------------------------------------------ */

char *ac_render_template(const char *project, const char *ts, const char *reason)
{
	size_t len = sizeof(AC_TEMPLATE) - 1, cap = len + 64;
	char *out = malloc(cap);
	size_t o = 0, i = 0;

	if (!out)
		return NULL;
	while (i < len) {
		const char *rep = NULL;
		size_t tok = 0;

		if (starts_with(AC_TEMPLATE + i, "{project}")) {
			rep = project ? project : "";
			tok = 9;
		} else if (starts_with(AC_TEMPLATE + i, "{ts}")) {
			rep = ts ? ts : "";
			tok = 4;
		} else if (starts_with(AC_TEMPLATE + i, "{reason}")) {
			rep = reason ? reason : "";
			tok = 8;
		}
		if (rep) {
			size_t rl = strlen(rep);

			while (o + rl + 32 > cap) {
				char *g = realloc(out, cap *= 2);

				if (!g) {
					free(out);
					return NULL;
				}
				out = g;
			}
			memcpy(out + o, rep, rl);
			o += rl;
			i += tok;
			continue;
		}
		while (o + 32 > cap) {
			char *g = realloc(out, cap *= 2);

			if (!g) {
				free(out);
				return NULL;
			}
			out = g;
		}
		out[o++] = AC_TEMPLATE[i++];
	}
	out[o] = '\0';
	return out;
}

/* ------------------------------------------------------------------ */
/* 顶层 bullet 分组                                                    */
/* ------------------------------------------------------------------ */

struct line_group {
	char **lines;		/* 借引用（归属 md_doc/调用方行数组） */
	size_t n;
};

static struct line_group *split_top_bullets(char **lines, size_t n, size_t *n_out)
{
	struct line_group *groups = malloc((n + 1) * sizeof(*groups));
	size_t g = 0;

	*n_out = 0;
	if (!groups)
		return NULL;
	for (size_t i = 0; i < n; i++) {
		char *line = lines[i];
		char *stripped = py_strip(line);
		int is_bullet = starts_with(line, "- ") || starts_with(line, "* ") ||
				(stripped && (strcmp(stripped, "-") == 0 ||
					      strcmp(stripped, "*") == 0));

		free(stripped);
		if (is_bullet) {
			groups[g].lines = malloc((n - i + 1) * sizeof(char *));
			if (!groups[g].lines)
				break;
			groups[g].lines[0] = line;
			groups[g].n = 1;
			g++;
		} else if (g > 0) {
			char *t = py_strip(line);

			if (t && *t)
				groups[g - 1].lines[groups[g - 1].n++] = line;
			free(t);
		}
		/* bullet 之前的散行：无所属段落，忽略 */
	}
	*n_out = g;
	return groups;
}

static void free_groups(struct line_group *groups, size_t n)
{
	if (!groups)
		return;
	for (size_t i = 0; i < n; i++)
		free(groups[i].lines);
	free(groups);
}

/* 去掉块首行的顶层 bullet 标记（- / * ），保留续行原样 */
static char *strip_bullet_marker(const char *block)
{
	size_t n;
	char **lines = py_splitlines(block, &n);
	char *out;

	if (!lines || n == 0) {
		free_lines(lines, n);
		return xstrdup(block ? block : "");
	}
	char *first = py_lstrip(lines[0]);

	if (starts_with(first, "- ") || starts_with(first, "* ")) {
		char *rest = n > 1
			? str_join((const char *const *)lines + 1, n - 1, "\n")
			: xstrdup("");

		out = str_concat3(first + 2, n > 1 ? "\n" : "", rest ? rest : "");
		free(rest);
	} else {
		out = str_join((const char *const *)lines, n, "\n");
	}
	free(first);
	free_lines(lines, n);
	return out;
}

/* ------------------------------------------------------------------ */
/* validate                                                            */
/* ------------------------------------------------------------------ */

aik_json *ac_validate(const char *digest_md)
{
	aik_json *errs = aik_json_new_arr();
	char *t = digest_md ? py_strip(digest_md) : xstrdup("");
	int empty = !digest_md || !t || !*t;

	free(t);
	if (!errs)
		return NULL;
	if (empty) {
		aik_json_arr_push(errs, aik_json_new_str("摘要为空"));
		return errs;
	}
	for (size_t i = 0; i < AC_N_REQUIRED; i++)
		if (!strstr(digest_md, AC_REQUIRED_SECTIONS[i])) {
			char msg[128];

			snprintf(msg, sizeof(msg), "缺少必填章节：%s",
				 AC_REQUIRED_SECTIONS[i]);
			aik_json_arr_push(errs, aik_json_new_str(msg));
		}
	size_t n = u8_cplen(digest_md);

	if (n < AC_MIN_CHARS) {
		char msg[96];

		snprintf(msg, sizeof(msg), "总长度不足 %d 字符（当前 %zu）",
			 AC_MIN_CHARS, n);
		aik_json_arr_push(errs, aik_json_new_str(msg));
	}
	return errs;
}

/* ------------------------------------------------------------------ */
/* split_digest                                                        */
/* ------------------------------------------------------------------ */

void ac_segment_free(ac_segment *s)
{
	if (!s)
		return;
	free(s->type);
	free(s->text);
	for (size_t i = 0; i < s->n_tags; i++)
		free(s->tags[i]);
	free(s->tags);
}

void ac_segments_free(ac_segment *segs, size_t n)
{
	for (size_t i = 0; i < n; i++)
		ac_segment_free(&segs[i]);
	free(segs);
}

static char **dedupe_tags(const char *const *base, size_t n_base,
			  const char *extra, size_t *n_out)
{
	char **out = malloc((n_base + 1) * sizeof(*out));
	size_t n = 0;

	if (!out) {
		*n_out = 0;
		return NULL;
	}
	for (size_t i = 0; i < n_base; i++) {
		out[n] = xstrdup(base[i]);
		if (out[n])
			n++;
	}
	if (extra) {
		int found = 0;

		for (size_t i = 0; i < n; i++)
			if (strcmp(out[i], extra) == 0) {
				found = 1;
				break;
			}
		if (!found) {
			out[n] = xstrdup(extra);
			if (out[n])
				n++;
		}
	}
	*n_out = n;
	return out;
}

aik_json *ac_segments_to_json(const ac_segment *segs, size_t n)
{
	aik_json *arr = aik_json_new_arr();

	if (!arr)
		return NULL;
	for (size_t i = 0; i < n; i++) {
		aik_json *o = aik_json_new_obj();
		aik_json *tags = aik_json_new_arr();

		if (!o || !tags) {
			aik_json_free(o);
			aik_json_free(tags);
			continue;
		}
		aik_json_obj_put(o, "type", aik_json_new_str(segs[i].type));
		aik_json_obj_put(o, "text", aik_json_new_str(segs[i].text));
		for (size_t j = 0; j < segs[i].n_tags; j++)
			aik_json_arr_push(tags, aik_json_new_str(segs[i].tags[j]));
		aik_json_obj_put(o, "tags", tags);
		aik_json_obj_put(o, "importance",
				 aik_json_new_num(segs[i].importance));
		aik_json_arr_push(arr, o);
	}
	return arr;
}

struct raw_seg {
	const char *type;
	const char *tag;
	double importance;
	char *content;		/* 堆串 */
};

ac_segment *ac_split_digest(const char *digest_md,
			    const char *const *base_tags, size_t n_base_tags,
			    const char *project, const char *ts, const char *trigger,
			    int has_cap, long long cap, size_t *n_out)
{
	struct md_doc doc;
	char prefix[512];
	struct raw_seg *raw = NULL;
	size_t n_raw = 0, cap_raw = 0;
	char **misc = NULL;
	size_t n_misc = 0;
	ac_segment *out = NULL;

	*n_out = 0;
	snprintf(prefix, sizeof(prefix), "[autocondense|%s|%s|%s] ",
		 project ? project : "", ts ? ts : "", trigger ? trigger : "");
	if (md_doc_parse(&doc, digest_md ? digest_md : "") != 0)
		return NULL;

	if (doc.n_secs == 0) {
		/* 没有任何章节头 → 兜底整篇一段 */
		char *body = py_strip(digest_md ? digest_md : "");
		char *text = str_concat3(prefix, body, "");

		free(body);
		md_doc_free(&doc);
		if (!text)
			return NULL;
		out = malloc(sizeof(*out));
		if (!out) {
			free(text);
			return NULL;
		}
		out->type = xstrdup(DIGEST_TYPE);
		out->text = text;
		out->tags = dedupe_tags(base_tags, n_base_tags, DIGEST_TAG,
					&out->n_tags);
		out->importance = DIGEST_IMPORTANCE;
		if (!out->type || !out->tags) {
			ac_segment_free(out);
			return NULL;
		}
		*n_out = 1;
		return out;
	}

#define RAW_PUSH(ty, tg, im, cn) do {					\
	if (n_raw == cap_raw) {						\
		struct raw_seg *g_;					\
		cap_raw = cap_raw ? cap_raw * 2 : 16;			\
		g_ = realloc(raw, cap_raw * sizeof(*raw));		\
		if (!g_)							\
			goto fail;					\
		raw = g_;						\
	}								\
	raw[n_raw].type = (ty);					\
	raw[n_raw].tag = (tg);					\
	raw[n_raw].importance = (im);					\
	raw[n_raw].content = (cn);					\
	n_raw++;							\
} while (0)

	misc = malloc((doc.n_pre + doc.n_secs + 1) * sizeof(*misc));
	if (!misc)
		goto fail;
	for (size_t i = 0; i < doc.n_pre; i++) {
		char *t = py_strip(doc.pre[i]);

		if (t && *t && !starts_with(doc.pre[i], "# "))
			misc[n_misc++] = t;
		else
			free(t);
	}

	for (size_t si = 0; si < doc.n_secs; si++) {
		const struct md_section *sec = &doc.secs[si];
		const struct seg_spec *spec = NULL;
		char *content;

		for (size_t k = 0; k < N_SEG_SPECS; k++)
			if (starts_with(sec->heading, SEG_SPECS[k].prefix)) {
				spec = &SEG_SPECS[k];
				break;
			}
		content = section_content(sec);
		if (!spec) {
			if (content && *content) {
				char *merged = str_concat3(sec->heading, "\n", content);

				if (merged)
					misc[n_misc++] = merged;
			}
			free(content);
			continue;
		}
		if (!*content) {
			free(content);
			continue;
		}
		if (spec->mode == MODE_WHOLE) {
			RAW_PUSH(spec->type, spec->tag, spec->importance, content);
			continue;
		}
		{
			size_t n_groups = 0;
			struct line_group *groups =
				split_top_bullets(sec->lines, sec->n_lines, &n_groups);

			if (!groups) {
				free(content);
				goto fail;
			}
			if (n_groups == 0) {
				RAW_PUSH(spec->type, spec->tag, spec->importance,
					 content);
			} else if (spec->mode == MODE_FILES &&
				   (long long)n_groups > AC_FILE_LIST_MAX_BULLETS) {
				RAW_PUSH(spec->type, spec->tag, spec->importance,
					 content);
			} else {
				for (size_t g = 0; g < n_groups; g++) {
					char *joined = str_join(
						(const char *const *)groups[g].lines,
						groups[g].n, "\n");
					char *gtext = py_strip(joined ? joined : "");

					free(joined);
					if (gtext && *gtext)
						RAW_PUSH(spec->type, spec->tag,
							 spec->importance, gtext);
					else
						free(gtext);
				}
				free(content);
			}
			free_groups(groups, n_groups);
		}
	}

	if (n_misc > 0) {
		char *joined = str_join((const char *const *)misc, n_misc, "\n\n");

		for (size_t i = 0; i < n_misc; i++)
			free(misc[i]);
		free(misc);
		misc = NULL;
		if (!joined)
			goto fail;
		RAW_PUSH(MISC_TYPE, MISC_TAG, MISC_IMPORTANCE, joined);
	} else {
		free(misc);
		misc = NULL;
	}

	/* 溢出合并：保留 importance 最高的 cap-1 段（稳定排序），溢出段按
	 * 原序合成一个 misc 段（digest.py:267-275）*/
	if (has_cap && cap >= 1 && (long long)n_raw > cap) {
		long long keep = cap - 1;
		long long overflow_n = (long long)n_raw - keep;
		size_t *order = malloc(n_raw * sizeof(*order));
		char *is_over = calloc(n_raw, 1);
		char **over_content = malloc((size_t)overflow_n * sizeof(char *));
		size_t oc = 0, nk = 0;
		char *merged;
		struct raw_seg *kept;

		if (!order || !is_over || !over_content) {
			free(order);
			free(is_over);
			free(over_content);
			goto fail;
		}
		for (size_t i = 0; i < n_raw; i++)
			order[i] = i;
		/* 插入排序（key=importance；比较仅大于时移动 → 稳定）*/
		for (size_t i = 1; i < n_raw; i++) {
			size_t key = order[i];
			size_t j = i;

			while (j > 0 && raw[order[j - 1]].importance >
					raw[key].importance) {
				order[j] = order[j - 1];
				j--;
			}
			order[j] = key;
		}
		for (long long i = 0; i < overflow_n; i++)
			is_over[order[i]] = 1;
		for (size_t i = 0; i < n_raw; i++)
			if (is_over[i])
				over_content[oc++] = raw[i].content;
		merged = str_join((const char *const *)over_content, oc, "\n\n");
		kept = malloc((size_t)(keep + 1) * sizeof(*kept));
		if (!merged || !kept) {
			free(merged);
			free(kept);
			free(order);
			free(is_over);
			free(over_content);
			goto fail;
		}
		for (size_t i = 0; i < n_raw; i++)
			if (!is_over[i])
				kept[nk++] = raw[i];
		kept[nk].type = MISC_TYPE;
		kept[nk].tag = MISC_TAG;
		kept[nk].importance = MISC_IMPORTANCE;
		kept[nk].content = merged;
		nk++;
		for (size_t i = 0; i < n_raw; i++)
			if (is_over[i])
				free(raw[i].content);
		free(order);
		free(is_over);
		free(over_content);
		free(raw);
		raw = kept;
		n_raw = nk;
	}

	if (n_raw == 0) {
		md_doc_free(&doc);
		*n_out = 0;
		return malloc(1);	/* 空列表（非 NULL 区别于失败）*/
	}
	out = malloc(n_raw * sizeof(*out));
	if (!out)
		goto fail;
	for (size_t i = 0; i < n_raw; i++) {
		out[i].type = xstrdup(raw[i].type);
		out[i].text = str_concat3(prefix, raw[i].content, "");
		out[i].tags = dedupe_tags(base_tags, n_base_tags, raw[i].tag,
					  &out[i].n_tags);
		out[i].importance = raw[i].importance;
		if (!out[i].type || !out[i].text || !out[i].tags) {
			ac_segments_free(out, i);
			out = NULL;
			goto fail;
		}
	}
	for (size_t i = 0; i < n_raw; i++)
		free(raw[i].content);
	free(raw);
	md_doc_free(&doc);
	*n_out = n_raw;
	return out;

fail:
	if (misc) {
		for (size_t i = 0; i < n_misc; i++)
			free(misc[i]);
		free(misc);
	}
	for (size_t i = 0; raw && i < n_raw; i++)
		free(raw[i].content);
	free(raw);
	md_doc_free(&doc);
	return NULL;
}

/* ------------------------------------------------------------------ */
/* reread / todo_open                                                  */
/* ------------------------------------------------------------------ */

aik_json *ac_extract_reread_files(const char *md, int limit)
{
	aik_json *arr = aik_json_new_arr();
	struct md_doc doc;

	if (!arr)
		return NULL;
	if (!md || !md[0] || !limit || limit <= 0)
		return arr;
	if (md_doc_parse(&doc, md) != 0)
		return arr;
	{
		const struct md_section *sec = find_section(&doc, SEC_FILES);

		if (sec) {
			size_t n_groups = 0;
			struct line_group *groups =
				split_top_bullets(sec->lines, sec->n_lines, &n_groups);

			for (size_t g = 0; g < n_groups; g++) {
				char *marked = strip_bullet_marker(groups[g].lines[0]);
				char *content = py_strip(marked);
				char *token = NULL;

				free(marked);
				if (content && *content) {
					/* re.split(r"[:\s]", content, 1)[0].strip() */
					size_t len = strlen(content), i = 0;
					char *head;

					while (i < len) {
						size_t adv;
						uint32_t cp = u8_next(content + i, len - i, &adv);

						if (cp == ':' || cp_is_ws(cp))
							break;
						i += adv;
					}
					head = xstrndup(content, i);
					token = py_strip(head ? head : "");
					free(head);
				}
				if (token && *token && !starts_with(token, "（")) {
					aik_json_arr_push(arr, aik_json_new_str(token));
					if ((long long)aik_json_count(arr) >= (long long)limit) {
						free(token);
						free(content);
						break;
					}
				}
				free(token);
				free(content);
			}
			free_groups(groups, n_groups);
		}
	}
	md_doc_free(&doc);
	return arr;
}

int ac_todo_open(const char *md)
{
	struct md_doc doc;
	int open_ = 0;

	if (md_doc_parse(&doc, md ? md : "") != 0)
		return 0;
	{
		char *content = doc_section_content(&doc, SEC_TODO);

		if (content && *content) {
			size_t len = strlen(content), o = 0;
			char *nos = malloc(len + 1);

			if (nos) {
				for (size_t i = 0; i < len; i++)
					if (content[i] != ' ')
						nos[o++] = content[i];
				nos[o] = '\0';
				open_ = strcmp(nos, "（无）") != 0 &&
					strcmp(nos, "(无)") != 0 &&
					strcmp(nos, "无") != 0;
				free(nos);
			}
		}
		free(content);
	}
	md_doc_free(&doc);
	return open_;
}

/* ------------------------------------------------------------------ */
/* 恢复载荷打包（_pack_restore）                                       */
/* ------------------------------------------------------------------ */

struct packer {
	char **parts;
	size_t n, cap;
	long long used, max_chars;
	int lost;
};

static void pack_emit(struct packer *p, const char *block)
{
	if (p->n == p->cap) {
		char **g = realloc(p->parts, (p->cap ? p->cap * 2 : 16) * sizeof(char *));

		if (!g)
			return;
		p->parts = g;
	}
	p->parts[p->n++] = xstrdup(block ? block : "");
	p->used += (long long)u8_cplen(block ? block : "") + 1;
}

static long long pack_room(const struct packer *p)
{
	return p->max_chars - p->used;
}

/* 整节装入；放不下保标题截正文（digest.py _whole_section）*/
static void pack_whole_block(struct packer *p, const char *heading,
			     const char *content)
{
	char *block = str_concat3(heading, "\n\n", content);
	long long hl = (long long)u8_cplen(heading);

	if ((long long)u8_cplen(block ? block : "") + 1 <= pack_room(p)) {
		pack_emit(p, block);
	} else if (pack_room(p) > hl + 3) {
		char *cut = u8_slice(content, 0, pack_room(p) - hl - 3);
		char *part = str_concat3(heading, "\n\n", cut);

		pack_emit(p, part);
		p->lost = 1;
		free(cut);
		free(part);
	} else {
		p->lost = 1;
	}
	free(block);
}

static void pack_whole_section(struct packer *p, const struct md_doc *doc,
			       const char *prefix)
{
	const struct md_section *sec = find_section(doc, prefix);

	if (!sec)
		return;
	char *content = section_content(sec);

	if (!content || !*content) {
		free(content);
		return;
	}
	pack_whole_block(p, sec->heading, content);
	free(content);
}

static void pack_goal_section(struct packer *p, const struct md_doc *doc)
{
	const struct md_section *sec = find_section(doc, SEC_GOAL);

	if (!sec)
		return;
	char *content = section_content(sec);

	if (!content || !*content) {
		free(content);
		return;
	}
	if ((long long)u8_cplen(content) > AC_GOAL_CHAR_CAP) {
		p->lost = 1;
		{
			char *cut = u8_slice(content, 0, AC_GOAL_CHAR_CAP);

			free(content);
			content = cut;
		}
	}
	pack_whole_block(p, sec->heading, content);
	free(content);
}

static void pack_bullet_section(struct packer *p, const struct md_doc *doc,
				const char *prefix, int one_line)
{
	const struct md_section *sec = find_section(doc, prefix);

	if (!sec)
		return;
	{
		long long hl = (long long)u8_cplen(sec->heading);
		size_t n_groups = 0;
		struct line_group *groups =
			split_top_bullets(sec->lines, sec->n_lines, &n_groups);

		if (n_groups == 0) {
			/* 无 bullet（如「（无）」散行）：整节一块 */
			char *content = section_content(sec);

			if (content && *content) {
				if (hl + (long long)u8_cplen(content) + 3 <= pack_room(p)) {
					char *blk = str_concat3(sec->heading, "\n\n", content);

					pack_emit(p, blk);
					free(blk);
				} else {
					p->lost = 1;
				}
			}
			free(content);
			free_groups(groups, n_groups);
			return;
		}
		{
			char **bullets = malloc(n_groups * sizeof(*bullets));
			size_t n_bullets = 0;

			if (!bullets) {
				free_groups(groups, n_groups);
				return;
			}
			for (size_t g = 0; g < n_groups; g++) {
				char *joined = str_join(
					(const char *const *)groups[g].lines,
					groups[g].n, "\n");
				char *marked = strip_bullet_marker(joined ? joined : "");
				char *text = one_line ? py_ws_collapse(marked)
						      : py_strip(marked);

				free(joined);
				free(marked);
				if (!text || !*text) {
					free(text);
					continue;
				}
				{
					int capl = one_line ? AC_DONE_LINE_CAP
							    : AC_BULLET_CHAR_CAP;
					char *cut;

					if ((long long)u8_cplen(text) > capl)
						p->lost = 1;
					cut = u8_slice(text, 0, capl);
					free(text);
					bullets[n_bullets++] = cut;
				}
			}
			if ((long long)n_bullets > AC_BULLET_PER_SECTION_CAP) {
				p->lost = 1;
				for (size_t i = AC_BULLET_PER_SECTION_CAP; i < n_bullets; i++)
					free(bullets[i]);
				n_bullets = AC_BULLET_PER_SECTION_CAP;
			}
			/* 预算内尽量多装：从尾部丢 bullet 直到放得下 */
			for (;;) {
				char *block;

				if (n_bullets == 0) {
					p->lost = 1;
					break;
				}
				{
					char **segs = malloc(n_bullets * sizeof(*segs));
					char *body;

					if (!segs)
						break;
					for (size_t i = 0; i < n_bullets; i++)
						segs[i] = str_concat3("- ", bullets[i], "");
					body = str_join((const char *const *)segs, n_bullets, "\n");
					for (size_t i = 0; i < n_bullets; i++)
						free(segs[i]);
					free(segs);
					block = str_concat3(sec->heading, "\n",
							     body ? body : "");
					free(body);
				}
				if ((long long)u8_cplen(block ? block : "") + 1 <= pack_room(p)) {
					pack_emit(p, block);
					free(block);
					break;
				}
				free(block);
				free(bullets[--n_bullets]);
				p->lost = 1;
			}
			for (size_t i = 0; i < n_bullets; i++)
				free(bullets[i]);
			free(bullets);
		}
		free_groups(groups, n_groups);
	}
}

/* 返回 malloc 的打包文本；*lost_out 置 lost 标志（digest.py _pack_restore）*/
static char *pack_restore(const char *md, long long max_chars,
			  char **titles, size_t n_titles, int *lost_out)
{
	struct packer p;
	struct md_doc doc;

	memset(&p, 0, sizeof(p));
	p.max_chars = max_chars;
	*lost_out = 0;
	if (max_chars <= 0) {
		char *t = md ? py_strip(md) : xstrdup("");
		int nonempty = t && *t;

		free(t);
		*lost_out = nonempty;
		return xstrdup("");
	}
	if (md_doc_parse(&doc, md ? md : "") != 0)
		return xstrdup("");
	p.parts = malloc(16 * sizeof(char *));
	if (!p.parts) {
		md_doc_free(&doc);
		return xstrdup("");
	}
	/* 0) h1 标题行（首个非空行） */
	{
		char *title = first_line(md ? md : "");

		if (title && *title) {
			if ((long long)u8_cplen(title) + 1 <= pack_room(&p)) {
				pack_emit(&p, title);
			} else {
				long long room = pack_room(&p);
				char *cut = u8_slice(title, 0, room - 1 > 0 ? room - 1 : 0);

				pack_emit(&p, cut);
				p.lost = 1;
				free(cut);
			}
		}
		free(title);
	}
	if (doc.n_secs > 0) {
		pack_whole_section(&p, &doc, SEC_TODO);		/* 1) 未完成 */
		pack_whole_section(&p, &doc, SEC_RESTORE_PTR);	/* 2) 恢复指针 */
		pack_bullet_section(&p, &doc, SEC_DECISIONS, 0);/* 3) 决策 */
		pack_bullet_section(&p, &doc, SEC_PITFALLS, 0);	/* 3) 坑 */
		pack_goal_section(&p, &doc);			/* 4) 目标 */
		pack_bullet_section(&p, &doc, SEC_DONE, 1);	/* 5) 已完成 */
	} else {
		/* 没有章节头（非模板格式快照）：整篇视作单块 */
		char *content = py_strip(md ? md : "");

		if (*content) {
			if ((long long)u8_cplen(content) + 1 <= pack_room(&p)) {
				pack_emit(&p, content);
			} else {
				long long room = pack_room(&p);
				char *cut = u8_slice(content, 0,
						      room - 1 > 0 ? room - 1 : 0);

				pack_emit(&p, cut);
				p.lost = 1;
				free(cut);
			}
		}
		free(content);
	}
	/* 6) preamble 散行（h1 除外） */
	{
		char **extra = malloc((doc.n_pre + 1) * sizeof(*extra));

		if (extra) {
			size_t n = 0;

			for (size_t i = 0; i < doc.n_pre; i++) {
				char *t = py_strip(doc.pre[i]);

				if (t && *t && !starts_with(doc.pre[i], "# "))
					extra[n++] = doc.pre[i];
				free(t);
			}
			{
				char *joined = str_join((const char *const *)extra, n, "\n");

				free(extra);
				if (joined && *joined) {
					if ((long long)u8_cplen(joined) + 1 <= pack_room(&p))
						pack_emit(&p, joined);
					else
						p.lost = 1;
				}
				free(joined);
			}
		}
	}
	/* 7) 更旧快照标题行 */
	for (size_t i = 0; i < n_titles; i++) {
		if ((long long)u8_cplen(titles[i]) + 1 <= pack_room(&p))
			pack_emit(&p, titles[i]);
		else
			p.lost = 1;
	}
	{
		char *out = str_join((const char *const *)p.parts, p.n, "\n");

		for (size_t i = 0; i < p.n; i++)
			free(p.parts[i]);
		free(p.parts);
		md_doc_free(&doc);
		*lost_out = p.lost;
		return out ? out : xstrdup("");
	}
}

/* ------------------------------------------------------------------ */
/* 文件读取                                                            */
/* ------------------------------------------------------------------ */

/* Path.read_text(encoding="utf-8", errors="ignore") + universal newlines */
static char *read_text_safe(const char *path)
{
	FILE *f = fopen(path, "rb");
	long sz;
	char *buf, *clean, *out;
	size_t o = 0, i = 0, len;

	if (!f)
		return xstrdup("");
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return xstrdup("");
	}
	sz = ftell(f);
	if (sz < 0 || fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return xstrdup("");
	}
	buf = malloc((size_t)sz + 1);
	if (!buf || (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz)) {
		fclose(f);
		free(buf);
		return xstrdup("");
	}
	fclose(f);
	buf[sz] = '\0';
	clean = malloc((size_t)sz + 1);
	if (!clean) {
		free(buf);
		return xstrdup("");
	}
	len = (size_t)sz;
	while (i < len) {
		size_t adv;
		uint32_t cp = u8_next(buf + i, len - i, &adv);

		if (cp == 0xFFFD && adv == 1 && (unsigned char)buf[i] >= 0x80) {
			i++;	/* 非法字节丢弃 */
			continue;
		}
		memcpy(clean + o, buf + i, adv);
		o += adv;
		i += adv;
	}
	clean[o] = '\0';
	free(buf);
	/* universal newlines：\r\n 与 \r → \n */
	out = malloc(o + 1);
	if (!out) {
		free(clean);
		return xstrdup("");
	}
	{
		size_t w = 0;

		for (i = 0; i < o; i++) {
			if (clean[i] == '\r') {
				out[w++] = '\n';
				if (i + 1 < o && clean[i + 1] == '\n')
					i++;
				continue;
			}
			out[w++] = clean[i];
		}
		out[w] = '\0';
	}
	free(clean);
	return out;
}

static int path_is_file(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* ------------------------------------------------------------------ */
/* build_restore_payload                                               */
/* ------------------------------------------------------------------ */

aik_json *ac_build_restore_payload(const char *const *files, size_t n_files,
				   long long max_chars,
				   int has_reread_limit, long long reread_limit,
				   int has_merged_md, const char *merged_md)
{
	aik_json *o = aik_json_new_obj();
	char **exist = malloc((n_files + 1) * sizeof(*exist));
	size_t n_exist = 0;

	if (!o || !exist) {
		aik_json_free(o);
		free(exist);
		return NULL;
	}
	for (size_t i = 0; i < n_files; i++)
		if (files[i] && path_is_file(files[i]))
			exist[n_exist++] = xstrdup(files[i]);
	if (n_exist == 0) {
		free(exist);
		aik_json_obj_put(o, "text", aik_json_new_str(""));
		aik_json_obj_put(o, "truncated", aik_json_new_bool(0));
		aik_json_obj_put(o, "full_file", aik_json_new_null());
		aik_json_obj_put(o, "note", aik_json_new_null());
		aik_json_obj_put(o, "reread_files", aik_json_new_arr());
		aik_json_obj_put(o, "todo_open", aik_json_new_bool(0));
		return o;
	}
	{
		const char *newest = exist[0];
		char full_buf[4096];
		char *full_file = realpath(newest, full_buf) ? xstrdup(full_buf)
							     : xstrdup(newest);
		char *base_md = has_merged_md ? xstrdup(merged_md ? merged_md : "")
					      : read_text_safe(newest);
		char **titles = malloc(n_exist * sizeof(*titles));
		size_t n_titles = 0;
		int lost = 0;
		char *text;

		if (titles)
			for (size_t i = 1; i < n_exist; i++) {
				char *txt = read_text_safe(exist[i]);
				char *t = first_line(txt);

				free(txt);
				if (t && *t)
					titles[n_titles++] = t;
				else
					free(t);
			}
		text = pack_restore(base_md, max_chars, titles, n_titles, &lost);
		if (lost) {
			/* 截断 → 文末指针行；预算不够时二次打包（digest.py:546-555）*/
			char *pointer = str_concat3("（完整快照：",
						     full_file ? full_file : "", "）");
			long long reserve =
				(long long)u8_cplen(pointer ? pointer : "") + 1;

			if ((long long)u8_cplen(text) + reserve > max_chars) {
				int lost2 = 0;
				long long budget = max_chars - reserve;

				if (budget < 0)
					budget = 0;
				free(text);
				text = pack_restore(base_md, budget, titles, n_titles, &lost2);
			}
			{
				char *rs = py_strip(text);
				int ok = rs && *rs &&
					 (long long)u8_cplen(rs) + reserve <= max_chars;

				if (ok) {
					free(text);
					text = str_concat3(rs, "\n",
							   pointer ? pointer : "");
				} else {
					free(text);
					if (max_chars >
					    (long long)u8_cplen(pointer ? pointer : "")) {
						char *np = str_concat3("\n",
								       pointer ? pointer : "", "");

						text = u8_slice(np, 0, max_chars);
						free(np);
					} else {
						text = u8_slice(pointer ? pointer : "",
								0, max_chars);
					}
				}
				free(rs);
			}
			free(pointer);
		}
		aik_json_obj_put(o, "text", aik_json_new_str(text ? text : ""));
		aik_json_obj_put(o, "truncated", aik_json_new_bool(lost ? 1 : 0));
		aik_json_obj_put(o, "full_file",
				 full_file ? aik_json_new_str(full_file)
					   : aik_json_new_null());
		if (full_file) {
			char *note = str_concat3("完整内容在 ", full_file,
						 "，需要时用 Read 工具读取");

			aik_json_obj_put(o, "note",
					 aik_json_new_str(note ? note : ""));
			free(note);
		} else {
			aik_json_obj_put(o, "note", aik_json_new_null());
		}
		{
			long long rlimit = has_reread_limit ? reread_limit : 5;
			long long capped = rlimit > INT_MAX ? INT_MAX : rlimit;

			aik_json_obj_put(o, "reread_files",
					 ac_extract_reread_files(base_md, (int)capped));
		}
		aik_json_obj_put(o, "todo_open",
				 aik_json_new_bool(ac_todo_open(base_md)));
		free(text);
		free(full_file);
		free(base_md);
		for (size_t i = 0; i < n_titles; i++)
			free(titles[i]);
		free(titles);
	}
	for (size_t i = 0; i < n_exist; i++)
		free(exist[i]);
	free(exist);
	return o;
}

/* ------------------------------------------------------------------ */
/* merge_delta_chain                                                   */
/* ------------------------------------------------------------------ */

struct merge_spec {
	const char *prefix;
	int whole;		/* 1=whole（取最新非空），0=union（bullet 并集） */
};

static const struct merge_spec MERGE_SPECS[] = {
	{ SEC_GOAL, 1 },
	{ SEC_DECISIONS, 0 },
	{ SEC_DONE, 0 },
	{ SEC_TODO, 1 },
	{ SEC_FILES, 0 },
	{ SEC_PITFALLS, 0 },
	{ SEC_RESTORE_PTR, 1 },
};
#define N_MERGE_SPECS (sizeof(MERGE_SPECS) / sizeof(MERGE_SPECS[0]))

/* 顶层 bullet → 文本块列表（去标记）；无 bullet 时非空正文视作单块 */
static char **bullet_groups(char **lines, size_t n, size_t *n_out)
{
	size_t n_groups = 0;
	struct line_group *groups = split_top_bullets(lines, n, &n_groups);
	char **out;
	size_t k = 0;

	*n_out = 0;
	if (groups && n_groups > 0) {
		out = malloc(n_groups * sizeof(*out));
		if (!out) {
			free_groups(groups, n_groups);
			return NULL;
		}
		for (size_t g = 0; g < n_groups; g++) {
			char *joined = str_join((const char *const *)groups[g].lines,
						groups[g].n, "\n");
			char *stripped = py_strip(joined ? joined : "");
			char *marked;
			char *t;

			free(joined);
			if (!stripped || !*stripped) {
				free(stripped);
				continue;
			}
			marked = strip_bullet_marker(stripped);
			t = py_strip(marked);
			free(marked);
			free(stripped);
			out[k++] = t;
		}
		free_groups(groups, n_groups);
		*n_out = k;
		return out;
	}
	free_groups(groups, n_groups);
	{
		char *joined = str_join((const char *const *)lines, n, "\n");
		char *t = py_strip(joined ? joined : "");

		free(joined);
		if (t && *t) {
			out = malloc(sizeof(*out));
			if (out) {
				out[0] = t;
				*n_out = 1;
				return out;
			}
			free(t);
			return NULL;
		}
		free(t);
	}
	out = malloc(sizeof(*out));
	if (out)
		*n_out = 0;
	return out;	/* 空块列表（非 NULL）*/
}

char *ac_merge_delta_chain(const char *const *texts, size_t n)
{
	const char **keep = malloc((n + 1) * sizeof(*keep));
	size_t nk = 0;

	if (!keep)
		return NULL;
	for (size_t i = 0; i < n; i++) {
		if (!texts[i] || !*texts[i])
			continue;
		{
			char *t = py_strip(texts[i]);

			if (t && *t)
				keep[nk++] = texts[i];
			free(t);
		}
	}
	if (nk == 0) {
		free(keep);
		return xstrdup("");
	}
	if (nk == 1) {
		char *out = xstrdup(keep[0]);

		free(keep);
		return out;
	}
	{
		struct md_doc *parsed = malloc(nk * sizeof(*parsed));
		size_t nb = 0;
		char **blocks = malloc((N_MERGE_SPECS + 2) * sizeof(*blocks));

		if (!parsed || !blocks) {
			free(parsed);
			free(blocks);
			free(keep);
			return xstrdup("");
		}
		for (size_t i = 0; i < nk; i++)
			if (md_doc_parse(&parsed[i], keep[i]) != 0)
				memset(&parsed[i], 0, sizeof(parsed[i]));	/* 已自清理，视作空文档 */
		/* 标题取自最新提供方 */
		for (size_t i = 0; i < nk; i++) {
			char *t = first_line(keep[i]);

			if (t && *t) {
				blocks[nb++] = t;
				break;
			}
			free(t);
		}
		for (size_t s = 0; s < N_MERGE_SPECS; s++) {
			const char *prefix = MERGE_SPECS[s].prefix;

			if (MERGE_SPECS[s].whole) {
				for (size_t i = 0; i < nk; i++) {
					const struct md_section *sec =
						find_section(&parsed[i], prefix);

					if (!sec)
						continue;
					{
						char *content = section_content(sec);

						if (*content) {
							char *b = str_concat3(sec->heading, "\n\n",
									      content);

							if (b)
								blocks[nb++] = b;
							free(content);
							break;
						}
						free(content);
					}
				}
			} else {
				char **seen = NULL, **bullets = NULL;
				size_t n_seen = 0, n_bullets = 0, cap = 16;
				const char *heading = NULL;

				seen = malloc(cap * sizeof(*seen));
				bullets = malloc(cap * sizeof(*bullets));
				if (seen && bullets)
					for (size_t i = 0; i < nk; i++) {
						const struct md_section *sec =
							find_section(&parsed[i], prefix);

						if (!sec)
							continue;
						{
							char *content = section_content(sec);

							if (*content && !heading)
								heading = sec->heading;
							free(content);
						}
						{
							size_t ng = 0;
							char **bs = bullet_groups(sec->lines,
										  sec->n_lines, &ng);

							for (size_t b = 0; b < ng; b++) {
								int dup = 0;

								for (size_t k2 = 0; k2 < n_seen; k2++)
									if (strcmp(seen[k2], bs[b]) == 0) {
										dup = 1;
										break;
									}
								if (dup) {
									free(bs[b]);
									continue;
								}
								if (n_seen == cap) {
									size_t nc = cap * 2;
									char **s2 = realloc(seen, nc * sizeof(*s2));
									char **b2 = realloc(bullets, nc * sizeof(*b2));

									if (!s2 || !b2) {
										free(bs[b]);
										free(s2 ? s2 : seen);
										free(b2 ? b2 : bullets);
										seen = NULL;
										bullets = NULL;
										break;
									}
									seen = s2;
									bullets = b2;
									cap = nc;
								}
								seen[n_seen++] = bs[b];
								bullets[n_bullets++] = bs[b];
							}
							free(bs);
							if (!seen || !bullets)
								break;
						}
					}
				if (n_bullets > 0) {
					char **parts = malloc(n_bullets * sizeof(*parts));
					char *body;
					char *block;
					const char *head = heading ? heading : prefix;

					for (size_t b = 0; b < n_bullets; b++)
						parts[b] = str_concat3("- ", bullets[b], "");
					body = str_join((const char *const *)parts, n_bullets, "\n");
					block = str_concat3(head, "\n", body ? body : "");
					for (size_t b = 0; b < n_bullets; b++)
						free(parts[b]);
					free(parts);
					free(body);
					if (block)
						blocks[nb++] = block;
				}
				for (size_t k2 = 0; k2 < n_seen; k2++)
					free(seen[k2]);
				free(seen);
				free(bullets);
			}
		}
		{
			char *joined = str_join((const char *const *)blocks, nb, "\n\n");
			char *stripped = py_strip(joined ? joined : "");
			char *out = str_concat3(stripped, "\n", "");

			for (size_t i = 0; i < nk; i++)
				md_doc_free(&parsed[i]);
			for (size_t i = 0; i < nb; i++)
				free(blocks[i]);
			free(blocks);
			free(parsed);
			free(joined);
			free(stripped);
			free(keep);
			return out;
		}
	}
}
