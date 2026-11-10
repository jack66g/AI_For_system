/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_chat.c - occ TUI 转写区实现（T9c2）
 *
 * 双段结构（见 tui_chat.h 头注）：定稿消息 → cells 行推 tui_scrollback；
 * live assistant 块每帧从逻辑模型重渲钉底。markdown-lite 渲染管线：
 *   逻辑行切分 → 围栏状态机 → 行前缀（#标题/列表/引用）→ 行内 span
 *   （行内 code、加粗、代码块 naive 语法色）→ grapheme 数组 → 空格回绕
 *   （CJK 硬断）→ cells 行。
 */
#define _DEFAULT_SOURCE 1
#include "tui_chat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tui_utf8.h"

/* ---- 内部类型 ---- */

/* 单 grapheme（回绕前） */
typedef struct {
	char b[8];
	uint8_t n;			/* 字节数 */
	uint8_t w;			/* 显示宽 0/1/2（B7 EXTEND=0 并入） */
	uint8_t sp;			/* 1=空格（回绕断点） */
	uint8_t bump;			/* B7：VS16——并入且前 grapheme 1→2 */
	tui_attr a;
} gitem;

/* 物化行 = cells 数组（列下标==终端列） */
typedef struct {
	tui_cell *cells;
	int len;			/* cell 数 */
	int w;			/* 显示宽度 */
	int cap;
} lbuf;

typedef struct {
	lbuf *v;
	int n, cap;
} llist;

/* 消息 */
#define TUI_ROLE_USER 0
#define TUI_ROLE_ASSISTANT 1
#define TUI_ROLE_NOTICE 2
#define TUI_ROLE_ERROR 3

typedef struct {
	char *name;
	char *summary;
	int st;				/* 0=running 1=ok 2=fail */
} tui_toolrow;

typedef struct {
	int role;
	char *text;
	size_t tlen, tcap;
	char *reason;
	size_t rlen, rcap;
	tui_toolrow *tools;
	size_t nt, toolscap;
	char footer[192];
	int has_footer;
	time_t ts;
	int live;			/* assistant 流式块 */
	int reason_open;			/* B5：推理折叠展开态 */
	/* RESET 截断标记（本轮起点）：boundary 后首个增量时打点 */
	size_t text_mark, reason_mark;
	int text_marked, reason_marked;
	/* T2：本消息块在 scrollback 的起始绝对行（含块前空行——视口命中
	 * 该空行也归属本块，锚点偏移恒 ≥0 且跨重放稳定；live 块不入
	 * scrollback，恒 0）。chat_push_msg/chat_rebuild 同口径重算。 */
	int first_line;
	/* T2：内容稳定 id（role+文本+思维链+工具行+footer 的 FNV-1a）。
	 * 回放重放后同一条历史消息得到同一 id——视口锚点据此还原。 */
	char id[24];
} tui_msg;

/* B5：点击命中的折叠行（render 期间记录，click 消费） */
struct tui_fold_hit {
	int row;			/* 转写区域相对行 */
	size_t msg;			/* tui_chat.msgs 下标 */
};

struct tui_chat {
	tui_theme th;
	tui_msg *msgs;
	size_t nmsgs, mcap;
	tui_scrollback sb;
	int width;			/* 当前渲染宽度（rewidth 同步） */
	char assist_label[64];		/* UXAB：assistant 块头标签（空="occ"） */
	int live_fold_idx;		/* UXAB：live 折叠行在 live_lines 的下标（-1 无） */
	llist live_lines;		/* live 块行缓存 */
	/* B5：定稿 reasoning 消息的折叠行 {scrollback 绝对行, msgs 下标}
	 * ——chat_push_msg 追加（升序）、rebuild 重算；无 reasoning 消息
	 * 不入表（点击不误中）。二分查找用。 */
	struct tui_fold_ref {
		long long abs;
		size_t msg;
	} *folds;
	size_t nfolds, foldscap;
	struct tui_fold_hit hits[64];	/* 上帧可见折叠行（含 live） */
	int nhits;
};

/* ---- lbuf / llist ---- */

static void lb_init(lbuf *l)
{
	l->cells = NULL;
	l->len = l->w = l->cap = 0;
}

static void lb_reset(lbuf *l)
{
	l->len = 0;
	l->w = 0;
}

static void lb_free(lbuf *l)
{
	free(l->cells);
	l->cells = NULL;
	l->len = l->w = l->cap = 0;
}

/* 追加一个 grapheme（base + 可选续格）；返回 0 成功，-1 溢出 */
static int lb_gph(lbuf *l, const char *b, uint8_t n, int w, tui_attr a)
{
	int need = (w == 2) ? 2 : 1;

	if (l->len + need > l->cap) {
		int nc = l->cap ? l->cap * 2 : 32;
		tui_cell *nb;

		while (nc < l->len + need)
			nc *= 2;
		nb = realloc(l->cells, (size_t)nc * sizeof(tui_cell));
		if (!nb)
			return -1;
		l->cells = nb;
		l->cap = nc;
	}
	memset(&l->cells[l->len], 0, sizeof(tui_cell));
	memcpy(l->cells[l->len].utf8, b, n);
	l->cells[l->len].len = n;
	l->cells[l->len].width = (uint8_t)w;
	l->cells[l->len].attr = a;
	l->len++;
	l->w += w;
	if (w == 2) {
		memset(&l->cells[l->len], 0, sizeof(tui_cell));
		l->cells[l->len].len = 0;
		l->cells[l->len].width = 0;
		l->cells[l->len].attr = a;
		l->len++;
	}
	return 0;
}

/* 追加一个 grapheme 进行（零宽组合符并入前一格，放不下则丢）。
 * B7：bump（VS16）并入后把前一主格 1→2 宽并补续格——行末（len==cap
 * 已满或前格宽 2）放不下时按普通并入（宽不变，对齐优先）。 */
static void lb_push_g(lbuf *lb, const gitem *g)
{
	if (g->w == 0) {
		if (lb->len > 0) {
			tui_cell *prev = &lb->cells[lb->len - 1];

			if (prev->width == 0 && lb->len >= 2)
				prev = &lb->cells[lb->len - 2];
			if (prev->len + g->n <= TUI_CELL_MAX) {
				memcpy(prev->utf8 + prev->len, g->b, g->n);
				prev->len = (uint8_t)(prev->len + g->n);
				if (g->bump && prev->width == 1 &&
				    lb->len < lb->cap) {
					prev->width = 2;
					memset(&lb->cells[lb->len], 0,
					       sizeof(tui_cell));
					lb->cells[lb->len].width = 0;
					lb->cells[lb->len].attr = prev->attr;
					lb->len++;
					lb->w += 1;
				}
			}
		}
		return;
	}
	lb_gph(lb, g->b, g->n, g->w, g->a);
}

static void ll_reset(llist *ll)
{
	int i;

	for (i = 0; i < ll->n; i++)
		lb_reset(&ll->v[i]);
	ll->n = 0;
}

static void ll_free(llist *ll)
{
	int i;

	for (i = 0; i < ll->n; i++)
		lb_free(&ll->v[i]);
	free(ll->v);
	ll->v = NULL;
	ll->n = ll->cap = 0;
}

static lbuf *ll_new(llist *ll)
{
	if (ll->n == ll->cap) {
		int nc = ll->cap ? ll->cap * 2 : 16;
		lbuf *nv = realloc(ll->v, (size_t)nc * sizeof(lbuf));

		if (!nv)
			return NULL;
		ll->v = nv;
		ll->cap = nc;
	}
	lb_init(&ll->v[ll->n]);
	return &ll->v[ll->n++];
}

/* ---- grapheme 装载 ---- */

static int gi_push(gitem **arr, int *n, int *cap, const char *s, size_t len,
		   tui_attr a, tui_gph_st *gst)
{
	uint32_t cp;
	size_t adv = 0;
	tui_u8stat st;
	int w;
	int synth = 0;			/* 1=合成字节（tab→空格），不拷 s */
	int act;
	gitem *g;
	size_t nb;

	st = tui_utf8_decode((const uint8_t *)s, len, &cp, &adv);
	if (st == TUI_U8_NEEDMORE || st == TUI_U8_INVALID)
		cp = TUI_REPLACEMENT;
	if (adv == 0)
		adv = 1;
	w = tui_wcwidth(cp);
	if (w < 0)
		w = 0;
	if (cp == '\t') {		/* tab → 空格（宽 1，可回绕） */
		cp = ' ';
		w = 1;
		synth = 1;
	} else if (w == 0 && !tui_is_combining(cp)) {
		/* 其他 C0/C1 控制符：丢弃（原字节回写终端会乱移光标） */
		return (int)adv;
	}
	/* B7：ZWJ/肤色/RI/VS16 续接判定（状态跨 gi_push——序列不拆 span） */
	act = tui_graph_feed(gst, cp, w);
	if (act == TUI_GPH_EXTEND)
		w = 0;
	else if (act == TUI_GPH_BUMP)
		w = 0;			/* bump 位在 gitem 上 */
	if (*n == *cap) {
		int nc = *cap ? *cap * 2 : 64;
		gitem *nv = realloc(*arr, (size_t)nc * sizeof(gitem));

		if (!nv)
			return -1;
		*arr = nv;
		*cap = nc;
	}
	g = &(*arr)[*n];
	memset(g, 0, sizeof(*g));
	if (synth) {
		g->b[0] = ' ';
		nb = 1;
	} else if (st == TUI_U8_OK) {
		nb = adv;
		if (nb == 0 || nb > 7) {
			g->b[0] = '?';
			nb = 1;
		} else {
			memcpy(g->b, s, nb);
		}
	} else {
		nb = tui_utf8_encode(cp, (uint8_t *)g->b);
		if (nb == 0 || nb > 7) {
			g->b[0] = '?';
			nb = 1;
		}
	}
	g->n = (uint8_t)nb;
	g->w = (uint8_t)w;
	g->sp = (cp == ' ') ? 1 : 0;
	g->bump = (act == TUI_GPH_BUMP) ? 1 : 0;
	g->a = a;
	(*n)++;
	return (int)adv;
}

/* 把一段 UTF-8 文本追加进 grapheme 数组（tab 当 1 空格） */
static int gi_append(gitem **arr, int *n, int *cap, const char *s, size_t len,
		     tui_attr a, tui_gph_st *gst)
{
	size_t i = 0;

	while (i < len) {
		int adv = gi_push(arr, n, cap, s + i, len - i, a, gst);

		if (adv < 0)
			return -1;
		i += (size_t)adv;
	}
	return 0;
}

/* 把一段 UTF-8 文本装载为 grapheme 数组 */
static int load_gitems(const char *s, size_t len, tui_attr a, gitem **out,
		       int *nout, int *capout)
{
	gitem *arr = NULL;
	int n = 0, cap = 0;
	tui_gph_st gst = {0, 0, 0};

	if (gi_append(&arr, &n, &cap, s, len, a, &gst) < 0) {
		free(arr);
		return -1;
	}
	*out = arr;
	*nout = n;
	*capout = cap;
	return 0;
}

/* ---- 回绕：grapheme 数组 → 行列表 ---- */

static void wrap_gitems(gitem *g, int n, int width, int wordwrap, llist *out)
{
	int i;
	int cur_start = 0;		/* 当前行首 gitem 下标 */
	int cur_w = 0;
	int last_sp = -1;		/* 当前行内最后一个空格下标 */

	if (width < 4)
		width = 4;
	for (i = 0; i <= n; i++) {
		int gw = (i < n) ? g[i].w : 1;	/* 尾 sentinel 触发收行 */

		if (i < n && g[i].w == 0) {		/* 零宽：并入当前行 */
			continue;
		}
		if (i < n && cur_w + gw > width) {
			int brk;

			if (wordwrap && last_sp > cur_start) {
				brk = last_sp + 1;	/* 断在空格后 */
			} else {
				brk = i;		/* 硬断 */
			}
			if (brk <= cur_start)
				brk = i;		/* 防死循环 */
			/* 输出 [cur_start, brk) */
			{
				lbuf *lb = ll_new(out);
				int k;

				if (!lb) {
					free(g);
					return;
				}
				for (k = cur_start; k < brk && k < n; k++)
					lb_push_g(lb, &g[k]);
			}
			/* 跳过断点处的空格 */
			cur_start = brk;
			while (cur_start < n && g[cur_start].sp)
				cur_start++;
			cur_w = 0;
			last_sp = -1;
			i = cur_start - 1;	/* for 的 i++ 补偿 */
			continue;
		}
		if (i < n) {
			cur_w += gw;
			if (g[i].sp)
				last_sp = i;
		} else if (cur_start < n) {
			/* 收尾行 */
			lbuf *lb = ll_new(out);
			int k;

			if (!lb) {
				free(g);
				return;
			}
			for (k = cur_start; k < n; k++)
				lb_push_g(lb, &g[k]);
		}
	}
	if (n == 0) {
		/* 空行也占一行 */
		ll_new(out);
	}
	free(g);
}

/* ---- 语法高亮（naive 行级扫描） ---- */

static int is_kw(const char *s, size_t n)
{
	static const char *const kws[] = {
		"if", "else", "for", "while", "return", "int", "void",
		"char", "const", "static", "struct", "unsigned", "sizeof",
		"include", "define", "def", "class", "import", "from",
		"function", "var", "let", "true", "false", "NULL", "printf",
		"malloc", "free", "this", "try", "catch", "new", "public",
		"private", "break", "continue", "switch", "case", "default",
		"float", "double", "long", "short", "unsigned", "goto",
		NULL
	};
	int k;

	for (k = 0; kws[k]; k++) {
		size_t wl = strlen(kws[k]);

		if (wl == n && memcmp(s, kws[k], n) == 0)
			return 1;
	}
	return 0;
}

/* 代码行：注释/字符串/数字/关键字/普通 → 逐段装载 gitem */
static int load_code_line(const char *s, size_t len, tui_attr base,
			  gitem **out, int *nout, int *capout)
{
	gitem *arr = NULL;
	int n = 0, cap = 0;
	size_t i = 0;
	tui_gph_st gst = {0, 0, 0};
	tui_attr a_cmt = tui_thm_attr(TUI_THM_CMT, TUI_THM_CODE_BG, 0);
	tui_attr a_str = tui_thm_attr(TUI_THM_STR, TUI_THM_CODE_BG, 0);
	tui_attr a_num = tui_thm_attr(TUI_THM_NUM, TUI_THM_CODE_BG, 0);
	tui_attr a_kw = tui_thm_attr(TUI_THM_KW, TUI_THM_CODE_BG,
				     TUI_ST_BOLD);
	tui_attr a_code = tui_thm_attr(TUI_THM_CODE_FG, TUI_THM_CODE_BG, 0);

	(void)base;
	while (i < len) {
		size_t start = i;
		tui_attr ra = a_code;
		int adv;

		/* 注释：行首 #（shell/python）或 // */
		if (s[i] == '#' && (i == 0 || s[i - 1] == ' ' ||
				    s[i - 1] == '\t')) {
			ra = a_cmt;
			i = len;
		} else if (s[i] == '/' && i + 1 < len && s[i + 1] == '/') {
			ra = a_cmt;
			i = len;
		} else if (s[i] == '"' || s[i] == '\'') {
			char q = s[i];

			ra = a_str;
			i++;
			while (i < len) {
				if (s[i] == '\\' && i + 1 < len) {
					i += 2;
					continue;
				}
				if (s[i] == q) {
					i++;
					break;
				}
				i++;
			}
		} else if (s[i] >= '0' && s[i] <= '9') {
			ra = a_num;
			while (i < len && ((s[i] >= '0' && s[i] <= '9') ||
					   s[i] == '.' || s[i] == 'x' ||
					   (s[i] >= 'a' && s[i] <= 'f') ||
					   (s[i] >= 'A' && s[i] <= 'F')))
				i++;
		} else if ((s[i] >= 'a' && s[i] <= 'z') ||
			   (s[i] >= 'A' && s[i] <= 'Z') || s[i] == '_') {
			while (i < len && ((s[i] >= 'a' && s[i] <= 'z') ||
					   (s[i] >= 'A' && s[i] <= 'Z') ||
					   (s[i] >= '0' && s[i] <= '9') ||
					   s[i] == '_'))
				i++;
			if (is_kw(s + start, i - start))
				ra = a_kw;
		} else if ((unsigned char)s[i] >= 0x80) {
			/* 非 ASCII（代码块里的 CJK 注释/字符串）：整段吞一个
			 * UTF-8 序列——逐字节会喂给 gi_push 半截序列，渲染成
			 * 一片 U+FFFD（T1 视觉自证发现） */
			int sl = tui_utf8_seqlen((uint8_t)s[i]);

			if (sl > 0 && (size_t)sl <= len - i)
				i += (size_t)sl;
			else
				i++;
		} else {
			i++;
		}
		{
			size_t j = start;

			while (j < i) {
				adv = gi_push(&arr, &n, &cap, s + j, i - j,
					      ra, &gst);
				if (adv < 0) {
					free(arr);
					return -1;
				}
				j += (size_t)adv;
			}
		}
	}
	*out = arr;
	*nout = n;
	*capout = cap;
	return 0;
}

/* ---- 行内 markdown span 解析 → gitem ---- */

static int load_inline(const char *s, size_t len, tui_attr base, int code_ctx,
		       gitem **out, int *nout, int *capout)
{
	if (code_ctx)
		return load_code_line(s, len, base, out, nout, capout);

	{
		gitem *arr = NULL;
		int n = 0, cap = 0;
		size_t i = 0;
		tui_gph_st gst = {0, 0, 0};	/* B7：跨 span 的续接状态 */

		while (i < len) {
			size_t start = i;
			int adv;
			tui_attr ra = base;

			if (s[i] == '`') {
				size_t j = i + 1;

				while (j < len && s[j] != '`')
					j++;
				if (j < len) {	/* 闭合 */
					tui_attr ac = tui_thm_attr(
						TUI_THM_CODE_FG,
						TUI_THM_CODE_BG, 0);

					i = i + 1;
					while (i < j) {
						adv = gi_push(&arr, &n, &cap,
							      s + i, j - i,
							      ac, &gst);
						if (adv < 0) {
							free(arr);
							return -1;
						}
						i += (size_t)adv;
					}
					i = j + 1;	/* 跳过闭合 ` */
					continue;
				}
				/* 未闭合：字面量 */
			} else if (i + 1 < len && s[i] == '*' && s[i + 1] ==
				   '*') {
				size_t j = i + 2;

				while (j + 1 < len &&
				       !(s[j] == '*' && s[j + 1] == '*'))
					j++;
				if (j + 1 < len) {
					tui_attr ab = base;

					ab.style |= TUI_ST_BOLD;
						i = i + 2;
						while (i < j) {
							adv = gi_push(&arr, &n, &cap,
								      s + i, j - i,
								      ab, &gst);
						if (adv < 0) {
							free(arr);
							return -1;
						}
						i += (size_t)adv;
					}
					i = j + 2;
					continue;
				}
				/* 未闭合：字面量 */
			}
			/* 普通段：吃到现在下一个标记符 */
			i++;
			while (i < len) {
				if (s[i] == '`')
					break;
				if (s[i] == '*' && i + 1 < len &&
				    s[i + 1] == '*')
					break;
				i++;
			}
			(void)start;
			(void)ra;
			{
				size_t j = start;

				while (j < i) {
					adv = gi_push(&arr, &n, &cap, s + j,
						      i - j, base, &gst);
					if (adv < 0) {
						free(arr);
						return -1;
					}
					j += (size_t)adv;
				}
			}
		}
		*out = arr;
		*nout = n;
		*capout = cap;
		return 0;
	}
}

/* ---- 消息文本 → 行列表（markdown-lite） ---- */

static void msg_render_lines(const char *text, size_t len, int width,
			     tui_attr base, int role, llist *out)
{
	size_t pos = 0;
	int in_fence = 0;

	while (pos < len) {
		size_t eol = pos;
		const char *ls;
		size_t ll;
		tui_attr la = base;
		int skip = 0;
		gitem *g = NULL;
		int gn = 0, gcap = 0;

		while (eol < len && text[eol] != '\n')
			eol++;
		ls = text + pos;
		ll = eol - pos;

		/* 围栏 */
		if (ll >= 3 && ls[0] == '`' && ls[1] == '`' && ls[2] == '`') {
			in_fence = !in_fence;
			skip = 1;
		}
		if (skip) {
			pos = (eol < len) ? eol + 1 : len + 1;
			if (pos > len)
				break;
			continue;
		}

		if (in_fence) {
			if (load_inline(ls, ll, base, 1, &g, &gn, &gcap) == 0)
				wrap_gitems(g, gn, width, 0, out);
			else
				free(g);
			pos = (eol < len) ? eol + 1 : len + 1;
			if (pos > len)
				break;
			continue;
		}

		/* 行前缀 */
		if (role == TUI_ROLE_ASSISTANT || role == TUI_ROLE_USER) {
			if (ls[0] == '#' && (ll == 1 || ls[1] == ' ')) {
				size_t k = 0;

				while (k < ll && ls[k] == '#')
					k++;
				if (k < ll && ls[k] == ' ')
					k++;
				ls += k;
				ll -= k;
				la = tui_thm_attr(TUI_THM_ACCENT, TUI_THM_BG,
						  TUI_ST_BOLD);
			} else if ((ll >= 2 && ls[0] == '-' && ls[1] == ' ') ||
				   (ll >= 2 && ls[0] == '*' && ls[1] == ' ')) {
				/* 列表：· 前缀（muted，E 白名单）+ 正文（la）合成一行 */
				ls += 2;
				ll -= 2;
				if (load_gitems("· ", strlen("· "),
						tui_thm_muted(),
						&g, &gn, &gcap) == 0) {
					tui_gph_st lgst = {0, 0, 0};

					if (gi_append(&g, &gn, &gcap, ls, ll,
						      la, &lgst) < 0) {
						free(g);
						g = NULL;
						gn = gcap = 0;
					}
					wrap_gitems(g, gn, width, 1, out);
					g = NULL;
					gn = gcap = 0;
				}
				if (eol >= len)
					break;
				pos = eol + 1;
				continue;
			} else if (ll >= 2 && ls[0] == '>' && ls[1] == ' ') {
				ls += 2;
				ll -= 2;
				la = tui_thm_attr(TUI_THM_MUTED, TUI_THM_BG,
						  TUI_ST_ITALIC);
			}
		}

		if (load_inline(ls, ll, la, 0, &g, &gn, &gcap) == 0)
			wrap_gitems(g, gn, width, 1, out);
		else
			free(g);

		if (eol >= len)
			break;
		pos = eol + 1;
	}
}

/* ---- 消息模型 ---- */

/* UXAB/E：消息块头 `▌你 · 02:15` / `◆ <label> · 02:16`——
 * 前缀+角色标签 accent 加粗、时间戳 dim 纯文本（无 chip 底色）。
 * head 由调用方给全（E 裁定：▌ 与「你」贴紧、◆ 与模型名留空格）；
 * 双 attr 合成行：装载前缀 gitem 后追加 dim 段，再整行回绕。 */
static void render_block_header(tui_chat *c, const char *head,
				time_t ts, llist *ll)
{
	char tb[24];
	char tbuf[16] = "??:??";
	struct tm tmv;
	tui_gph_st gst = {0, 0, 0};
	gitem *g = NULL;
	int gn = 0, gcap = 0;
	size_t hn;

	localtime_r(&ts, &tmv);
	strftime(tbuf, sizeof(tbuf), "%H:%M", &tmv);
	hn = strlen(head);
	if (load_gitems(head, hn, tui_thm_accent(TUI_ST_BOLD),
			&g, &gn, &gcap) != 0)
		return;
	snprintf(tb, sizeof(tb), "· %s", tbuf);
	if (gi_append(&g, &gn, &gcap, tb, strlen(tb), tui_thm_muted(),
		      &gst) < 0) {
		free(g);
		return;
	}
	wrap_gitems(g, gn, c->width, 1, ll);	/* 内部 free(g) */
}

/* UXAB/E：工具行树形化 `  ├─ + bash · summary`——枝干 dim、状态符+主体
 * 按状态着色（+ ok 绿 / × error 红 / ○ pending muted / spinner live）。
 * 定稿与 live 共用。 */
static void render_tool_row(tui_chat *c, const tui_toolrow *t,
			    const char *mark, llist *ll)
{
	char tb[336];
	tui_attr ta = tui_thm_attr(t->st == 1 ? TUI_THM_OK :
				   t->st == 2 ? TUI_THM_ERROR :
				   TUI_THM_MUTED, TUI_THM_BG, 0);
	tui_gph_st gst = {0, 0, 0};
	gitem *g = NULL;
	int gn = 0, gcap = 0;
	int tn;

	tn = snprintf(tb, sizeof(tb), "%s %s · %s", mark,
		      t->name ? t->name : "?",
		      t->summary ? t->summary : "");
	if (tn < 0)
		return;
	if (tn >= (int)sizeof(tb))
		tn = (int)sizeof(tb) - 1;
	if (load_gitems("  ├─ ", strlen("  ├─ "), tui_thm_muted(),
			&g, &gn, &gcap) != 0) {
		msg_render_lines(tb, (size_t)tn, c->width, ta,
				 TUI_ROLE_NOTICE, ll);
		return;
	}
	if (gi_append(&g, &gn, &gcap, tb, (size_t)tn, ta, &gst) < 0) {
		free(g);
		return;
	}
	wrap_gitems(g, gn, c->width, 0, ll);	/* 内部 free(g) */
}

static void msg_init(tui_msg *m, int role, time_t ts)
{
	memset(m, 0, sizeof(*m));
	m->role = role;
	m->ts = ts;
}

static void msg_free(tui_msg *m)
{
	size_t i;

	free(m->text);
	free(m->reason);
	for (i = 0; i < m->nt; i++) {
		free(m->tools[i].name);
		free(m->tools[i].summary);
	}
	free(m->tools);
	memset(m, 0, sizeof(*m));
}

static void msg_append(char **buf, size_t *len, size_t *cap, const char *s,
		       size_t n)
{
	if (*len + n + 1 > *cap) {
		size_t nc = *cap ? *cap : 128;
		char *nb;

		while (nc < *len + n + 1)
			nc *= 2;
		nb = realloc(*buf, nc);
		if (!nb)
			return;
		*buf = nb;
		*cap = nc;
	}
	memcpy(*buf + *len, s, n);
	*len += n;
	(*buf)[*len] = '\0';
}

/* ---- T2：消息内容 id（FNV-1a；跨回放重放稳定） ---- */

static void msg_hash_add(uint64_t *h, const void *p, size_t n)
{
	const unsigned char *b = p;

	while (n--) {
		*h ^= *b++;
		*h *= 1099511628211ULL;
	}
}

/* role+text+reason+tools(name/summary/st)+footer → 16 位十六进制。
 * 刻意不含时间戳：回放每条消息的 ts=渲染时刻，含入即每次重放都变。
 * 同内容消息 id 相同（滚动定位取首个匹配——同内容块视觉等价）。 */
static void msg_compute_id(tui_msg *m)
{
	uint64_t h = 1469598103934665603ULL;
	size_t i;
	int sep = 0x1f;

	msg_hash_add(&h, &m->role, sizeof(m->role));
	msg_hash_add(&h, &sep, sizeof(sep));
	msg_hash_add(&h, m->text ? m->text : "",
		     m->text ? m->tlen : 0);
	msg_hash_add(&h, &sep, sizeof(sep));
	msg_hash_add(&h, m->reason ? m->reason : "",
		     m->reason ? m->rlen : 0);
	for (i = 0; i < m->nt; i++) {
		const char *n = m->tools[i].name ? m->tools[i].name : "";
		const char *s = m->tools[i].summary ? m->tools[i].summary : "";
		int st = m->tools[i].st;

		msg_hash_add(&h, &sep, sizeof(sep));
		msg_hash_add(&h, n, strlen(n));
		msg_hash_add(&h, &sep, sizeof(sep));
		msg_hash_add(&h, s, strlen(s));
		msg_hash_add(&h, &st, sizeof(st));
	}
	if (m->has_footer) {
		msg_hash_add(&h, &sep, sizeof(sep));
		msg_hash_add(&h, m->footer, strlen(m->footer));
	}
	snprintf(m->id, sizeof(m->id), "%016llx",
		 (unsigned long long)h);
}

/* 流式中的 assistant 块：turn 中途可能有 NOTICE 插到它后面（如重试通告），
 * 按"最后一条"取会指错消息——所有 live 块操作统一用回扫定位。 */
static tui_msg *chat_live(tui_chat *c)
{
	size_t i;

	for (i = c->nmsgs; i > 0; i--) {
		if (c->msgs[i - 1].live)
			return &c->msgs[i - 1];
	}
	return NULL;
}

static tui_msg *chat_push(tui_chat *c, int role)
{
	if (c->nmsgs == c->mcap) {
		size_t nc = c->mcap ? c->mcap * 2 : 16;
		tui_msg *nv = realloc(c->msgs, nc * sizeof(tui_msg));

		if (!nv)
			return NULL;
		c->msgs = nv;
		c->mcap = nc;
	}
	msg_init(&c->msgs[c->nmsgs], role, time(NULL));
	c->nmsgs++;
	return &c->msgs[c->nmsgs - 1];
}

/* B5：推理块渲染（折叠行 + 可选展开正文；live 与定稿共用）
 * 展开正文超 RSN_CAP 字节只渲尾部并加省略行（每帧重渲的 live 块
 * 需有界；对齐无关——行数不影响列宽）。 */
#define RSN_CAP 6000

static void render_reasoning(tui_chat *c, tui_msg *m, int live, llist *ll)
{
	char hb[96];
	int hn;
	const char *rs = m->reason;
	size_t rn = m->rlen, skip = 0;

	if (!rs || !rn)
		return;
	if (m->reason_open) {
		/* E：展开态折头 ●（收起态 ○）——白名单字形，无 U+2303 附加符 */
		hn = snprintf(hb, sizeof(hb), live ?
			      "● thinking (%zu chars)" :
			      "● thought · %zu chars", rn);
		msg_render_lines(hb, (size_t)hn, c->width, tui_thm_muted(),
				 TUI_ROLE_NOTICE, ll);
		if (rn > RSN_CAP) {
			skip = rn - RSN_CAP;
			/* 回退到 UTF-8 边界（防切多字节） */
			while (skip < rn && ((uint8_t)rs[skip] & 0xC0) == 0x80)
				skip++;
			msg_render_lines("…（前文省略）", strlen("…（前文省略）"),
					 c->width, tui_thm_muted(),
					 TUI_ROLE_NOTICE, ll);
		}
		msg_render_lines(rs + skip, rn - skip, c->width,
				 tui_thm_muted(), TUI_ROLE_NOTICE, ll);
		return;
	}
	hn = snprintf(hb, sizeof(hb), live ?
		      "○ thinking… (%zu chars)" :
		      "○ thought · %zu chars", rn);
	msg_render_lines(hb, (size_t)hn, c->width, tui_thm_muted(),
			 TUI_ROLE_NOTICE, ll);
}

/* 把一个定稿消息渲染成行推进 scrollback */
static void chat_push_msg(tui_chat *c, tui_msg *m)
{
	llist ll;
	int i;
	int had_sep;

	if (c->width < 4)
		return;
	/* T1：块间空一行——非首个块前先推一条空行（定稿与回放同源：
	 * 回放同样走 chat_push_msg，形态天然一致）。
	 * T2：块区域首行=该空行（含）——块与块区域首尾相接，视口任意
	 * 一行都能唯一归属一个消息块（锚点偏移恒 ≥0）。 */
	had_sep = c->sb.count > 0;
	if (had_sep)
		tui_sb_push(&c->sb, NULL, 0);
	m->first_line = c->sb.dropped + c->sb.count - (had_sep ? 1 : 0);
	msg_compute_id(m);
	memset(&ll, 0, sizeof(ll));
	if (m->role == TUI_ROLE_ASSISTANT) {
		/* UXAB/E：块头 ◆ label · HH:MM（label=assist_label，occ.c 供模型名） */
		char hh[128];

		snprintf(hh, sizeof(hh), "◆ %s ",
			 c->assist_label[0] ? c->assist_label : "occ");
		render_block_header(c, hh, m->ts, &ll);
		/* reasoning 折叠行（B5：点击展开——记 scrollback 绝对行号） */
		if (m->reason && m->rlen) {
			if (c->nfolds == c->foldscap) {
				size_t nc = c->foldscap ? c->foldscap * 2 : 8;
				struct tui_fold_ref *nv;

				nv = realloc(c->folds,
					     nc * sizeof(*nv));
				if (nv) {
					c->folds = nv;
					c->foldscap = nc;
				}
			}
			if (c->nfolds < c->foldscap) {
				/* UXAB：◆ 头行先占 ll.n 行——折叠行绝对号
				 * 随之偏移（头行可能回绕多行，按 ll.n 计） */
				c->folds[c->nfolds].abs =
					(long long)(c->sb.dropped +
						    c->sb.count + ll.n);
				c->folds[c->nfolds].msg =
					(size_t)(m - c->msgs);
				c->nfolds++;
			}
			render_reasoning(c, m, 0, &ll);
		}
		if (m->text && m->tlen)
			msg_render_lines(m->text, m->tlen, c->width,
					 tui_thm_plain(), m->role, &ll);
		/* 工具行（UXAB 树形：枝干 ├─ dim + 状态符着色；E 白名单） */
		for (i = 0; i < (int)m->nt; i++) {
			const char *mk = m->tools[i].st == 1 ? "+" :
					 m->tools[i].st == 2 ? "×" : "○";

			render_tool_row(c, &m->tools[i], mk, &ll);
		}
		if (m->has_footer && m->footer[0])
			msg_render_lines(m->footer, strlen(m->footer),
					 c->width, tui_thm_muted(),
					 TUI_ROLE_NOTICE, &ll);
	} else if (m->role == TUI_ROLE_USER) {
		/* UXAB/E：块头 ▌你 · HH:MM（accent+bold / dim 时间；▌ 贴紧） */
		render_block_header(c, "▌你 ", m->ts, &ll);
		if (m->text && m->tlen)
			msg_render_lines(m->text, m->tlen, c->width,
					 tui_thm_attr(TUI_THM_FG,
						      TUI_THM_USER_BG, 0),
					 m->role, &ll);
	} else {
			tui_attr ea = m->role == TUI_ROLE_ERROR ?
				      tui_thm_attr(TUI_THM_ERROR, TUI_THM_BG, 0) :
				      tui_thm_muted();
			const char *pref = m->role == TUI_ROLE_ERROR ? "× " : "· ";

			if (m->text && m->tlen) {
				size_t plen = strlen(pref);
				char *full = malloc(plen + m->tlen + 1);

				if (full) {
					memcpy(full, pref, plen);
					memcpy(full + plen, m->text, m->tlen);
					msg_render_lines(full, plen + m->tlen,
							 c->width, ea,
							 TUI_ROLE_NOTICE, &ll);
					free(full);
				}
			}
		}
	for (i = 0; i < ll.n; i++)
		tui_sb_push(&c->sb, ll.v[i].cells, ll.v[i].len);
	ll_free(&ll);
}

/* ---- 公开 API ---- */

tui_chat *tui_chat_create(const tui_theme *th)
{
	tui_chat *c = calloc(1, sizeof(*c));

	if (!c)
		return NULL;
	if (th)
		c->th = *th;
	else
		tui_theme_default(&c->th);
	tui_sb_init(&c->sb, TUI_CHAT_SB_CAP, 10);
	c->width = 80;
	return c;
}

void tui_chat_destroy(tui_chat *c)
{
	size_t i;

	if (!c)
		return;
	for (i = 0; i < c->nmsgs; i++)
		msg_free(&c->msgs[i]);
	free(c->msgs);
	free(c->folds);
	ll_free(&c->live_lines);
	tui_sb_destroy(&c->sb);
	free(c);
}

void tui_chat_set_assist_label(tui_chat *c, const char *label)
{
	if (!c)
		return;
	if (!label || !label[0]) {
		c->assist_label[0] = '\0';
		return;
	}
	snprintf(c->assist_label, sizeof(c->assist_label), "%.60s", label);
}

void tui_chat_add_user(tui_chat *c, const char *text, size_t len)
{
	tui_msg *m;

	if (!c || !text)
		return;
	/* 防御：上个 live 未收口先定稿（回扫——NOTICE 可能插在其后） */
	if (chat_live(c))
		tui_chat_end_assistant(c, "");
	m = chat_push(c, TUI_ROLE_USER);
	if (!m)
		return;
	msg_append(&m->text, &m->tlen, &m->tcap, text, len);
	chat_push_msg(c, m);
}

void tui_chat_add_notice(tui_chat *c, const char *text)
{
	tui_msg *m;

	if (!c || !text)
		return;
	m = chat_push(c, TUI_ROLE_NOTICE);
	if (!m)
		return;
	msg_append(&m->text, &m->tlen, &m->tcap, text, strlen(text));
	chat_push_msg(c, m);
}

void tui_chat_add_error(tui_chat *c, const char *text)
{
	tui_msg *m;

	if (!c || !text)
		return;
	m = chat_push(c, TUI_ROLE_ERROR);
	if (!m)
		return;
	msg_append(&m->text, &m->tlen, &m->tcap, text, strlen(text));
	chat_push_msg(c, m);
}

void tui_chat_begin_assistant(tui_chat *c)
{
	tui_msg *m;

	if (!c)
		return;
	if (chat_live(c))
		return;			/* 已有 live 块 */
	m = chat_push(c, TUI_ROLE_ASSISTANT);
	if (!m)
		return;
	m->live = 1;
}

void tui_chat_append_text(tui_chat *c, const char *s, size_t len)
{
	tui_msg *m;

	if (!c || !s || !len)
		return;
	m = chat_live(c);
	if (!m || !m->live || m->role != TUI_ROLE_ASSISTANT)
		return;
	if (!m->text_marked) {
		m->text_mark = m->tlen;
		m->text_marked = 1;
	}
	msg_append(&m->text, &m->tlen, &m->tcap, s, len);
}

void tui_chat_append_reasoning(tui_chat *c, const char *s, size_t len)
{
	tui_msg *m;

	if (!c || !s || !len)
		return;
	m = chat_live(c);
	if (!m || !m->live || m->role != TUI_ROLE_ASSISTANT)
		return;
	if (!m->reason_marked) {
		m->reason_mark = m->rlen;
		m->reason_marked = 1;
	}
	msg_append(&m->reason, &m->rlen, &m->rcap, s, len);
}

void tui_chat_tool_start(tui_chat *c, const char *name, const char *args)
{
	tui_msg *m;
	char sum[192];
	size_t i, n = 0;

	if (!c)
		return;
	m = chat_live(c);
	if (!m || !m->live || m->role != TUI_ROLE_ASSISTANT)
		return;
	/* 摘要：args 压缩为单行截断 */
	for (i = 0; args && args[i] && n + 1 < sizeof(sum); i++) {
		char ch = args[i];

		if (ch == '\n' || ch == '\r' || ch == '\t')
			ch = ' ';
		sum[n++] = ch;
	}
	sum[n] = '\0';
	if (m->nt == m->toolscap) {
		size_t nc = m->toolscap ? m->toolscap * 2 : 4;
		tui_toolrow *nv = realloc(m->tools,
					  nc * sizeof(tui_toolrow));

		if (!nv)
			return;
		m->tools = nv;
		m->toolscap = nc;
	}
	memset(&m->tools[m->nt], 0, sizeof(tui_toolrow));
	m->tools[m->nt].name = strdup(name ? name : "?");
	m->tools[m->nt].summary = strdup(sum);
	m->tools[m->nt].st = 0;
	m->nt++;
	/* 新轮次边界：下一个文本增量打点 */
	m->text_marked = 0;
	m->reason_marked = 0;
}

void tui_chat_tool_end(tui_chat *c, const char *name, const char *summary,
		       int rc)
{
	tui_msg *m;
	size_t i;
	char sum[192];
	size_t n = 0;

	if (!c)
		return;
	m = chat_live(c);
	if (!m)
		return;
	for (i = 0; summary && summary[i] && n + 1 < sizeof(sum); i++) {
		char ch = summary[i];

		if (ch == '\n' || ch == '\r' || ch == '\t') {
			if (n == 0 || sum[n - 1] == ' ')
				continue;	/* 压首行 */
			ch = ' ';
		}
		sum[n++] = ch;
	}
	sum[n] = '\0';
	for (i = 0; i < m->nt; i++) {
		if (m->tools[i].st == 0 &&
		    strcmp(m->tools[i].name ? m->tools[i].name : "",
			   name ? name : "") == 0) {
			m->tools[i].st = rc == 0 ? 1 : 2;
			if (sum[0]) {
				free(m->tools[i].summary);
				m->tools[i].summary = strdup(sum);
			}
			return;
		}
	}
	/* 无匹配 running 行（容错）：补一个定稿行 */
	if (m->nt == m->toolscap) {
		size_t nc = m->toolscap ? m->toolscap * 2 : 4;
		tui_toolrow *nv = realloc(m->tools,
					  nc * sizeof(tui_toolrow));

		if (!nv)
			return;
		m->tools = nv;
		m->toolscap = nc;
	}
	memset(&m->tools[m->nt], 0, sizeof(tui_toolrow));
	m->tools[m->nt].name = strdup(name ? name : "?");
	m->tools[m->nt].summary = strdup(sum);
	m->tools[m->nt].st = rc == 0 ? 1 : 2;
	m->nt++;
}

void tui_chat_reset_live(tui_chat *c)
{
	tui_msg *m;

	if (!c)
		return;
	m = chat_live(c);
	if (!m || !m->live)
		return;
	if (m->text_marked && m->text_mark <= m->tlen)
		m->tlen = m->text_mark;
	if (m->text)
		m->text[m->tlen] = '\0';
	if (m->reason_marked && m->reason_mark <= m->rlen)
		m->rlen = m->reason_mark;
	if (m->reason)
		m->reason[m->rlen] = '\0';
	m->text_marked = 0;
	m->reason_marked = 0;
}

void tui_chat_end_assistant(tui_chat *c, const char *footer)
{
	tui_msg *m;

	if (!c)
		return;
	m = chat_live(c);
	if (!m || !m->live)
		return;
	if (footer && footer[0]) {
		snprintf(m->footer, sizeof(m->footer), "%s", footer);
		m->has_footer = 1;
	}
	m->live = 0;
	/* 空块丢弃（无任何内容） */
	if ((!m->text || !m->tlen) && (!m->reason || !m->rlen) && m->nt == 0) {
		msg_free(m);
		c->nmsgs--;
		return;
	}
	chat_push_msg(c, m);
}

void tui_chat_clear(tui_chat *c)
{
	size_t i;

	if (!c)
		return;
	for (i = 0; i < c->nmsgs; i++)
		msg_free(&c->msgs[i]);
	c->nmsgs = 0;
	c->nhits = 0;
	c->nfolds = 0;
	ll_reset(&c->live_lines);
	tui_sb_destroy(&c->sb);
	tui_sb_init(&c->sb, TUI_CHAT_SB_CAP, 10);
}

/* ---- live 块渲染 ---- */

static void live_render(tui_chat *c, uint64_t now_ms)
{
	tui_msg *m = chat_live(c);
	int width = c->width;
	int i;

	ll_reset(&c->live_lines);
	c->live_fold_idx = -1;
	if (!m || !m->live || m->role != TUI_ROLE_ASSISTANT)
		return;
	(void)now_ms;
	/* T1：live 块前也留空行（与上方已定稿块隔开；scrollback 空=不画） */
	if (c->sb.count > 0 && !ll_new(&c->live_lines))
		return;
	/* UXAB/E：块头 ◆ label · HH:MM（live 块同样带头——流式开始即可见）。
	 * 头行占位后折叠行不再是 live 首行——记录其行下标供点击命中。 */
	{
		char hh[128];

		snprintf(hh, sizeof(hh), "◆ %s ",
			 c->assist_label[0] ? c->assist_label : "occ");
		render_block_header(c, hh, m->ts, &c->live_lines);
	}
	c->live_fold_idx = (m->reason && m->rlen) ? c->live_lines.n : -1;
	/* reasoning 折叠行（B5：点击切换展开——可见行号在 render 记 hits） */
	if (m->reason && m->rlen)
		render_reasoning(c, m, 1, &c->live_lines);
	if (m->text && m->tlen)
		msg_render_lines(m->text, m->tlen, width, tui_thm_plain(),
				 TUI_ROLE_ASSISTANT, &c->live_lines);
	for (i = 0; i < (int)m->nt; i++) {
		const char *mk;

		if (m->tools[i].st == 1)
			mk = "+";
		else if (m->tools[i].st == 2)
			mk = "×";
		else
			mk = tui_thm_spinner(now_ms);
		render_tool_row(c, &m->tools[i], mk, &c->live_lines);
	}
}

/* ---- 渲染 ---- */

static void draw_line(tui_screen *s, int row, int x, const tui_cell *cells,
		      int len, int maxw)
{
	int k;

	if (row < 0 || row >= s->rows)
		return;
	for (k = 0; k < len && x + k < s->cols && k < maxw; k++) {
		/* 起点落在续格上：跳到主格（防御） */
		if (k == 0 && cells[0].width == 0 && x + k < s->cols) {
			/* 直接覆盖（前一主格不在本行窗口内时的降级） */
		}
		s->cells[(size_t)row * (size_t)s->cols + x + k] = cells[k];
	}
	s->dirty[row] = 1;
}

/* B5：folds[] 升序（abs）→ 二分找折叠行落在 abs 的消息下标 */
static long long fold_msg_at(const tui_chat *c, long long abs)
{
	size_t lo = 0, hi = c->nfolds;

	if (!c->folds || abs < 0)
		return -1;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		long long v = c->folds[mid].abs;

		if (v == abs)
			return (long long)c->folds[mid].msg;
		if (v < abs)
			lo = mid + 1;
		else
			hi = mid;
	}
	return -1;
}

void tui_chat_render(tui_chat *c, tui_screen *s, int x, int y, int w, int h,
		     uint64_t now_ms)
{
	int live_h = 0;
	int sb_h;
	int i;
	tui_msg *lm = chat_live(c);

	if (!c || !s || w < 1 || h < 1)
		return;
	if (w != c->width)
		tui_chat_rewidth(c, w);

	live_render(c, now_ms);
	live_h = c->live_lines.n;
	if (h >= 2 && live_h > h - 1)
		live_h = h - 1;		/* 至少留 1 行历史视口 */
	if (live_h > h)
		live_h = h;		/* h==1 时也不越出区域 */
	if (live_h < 0)
		live_h = 0;
	sb_h = h - live_h;

	/* scrollback 视口 */
	c->sb.rows = sb_h;
	if (c->sb.follow)
		tui_sb_jump_latest(&c->sb);
	else if (c->sb.view_top < c->sb.dropped ||
		 (c->sb.count > 0 && c->sb.view_top >
		  c->sb.dropped + c->sb.count - 1))
		tui_sb_scroll(&c->sb, 0);	/* 越界才钳（锚点留白保留） */

	/* B5：记录可见折叠行（点击命中表——render 后 click 间有效） */
	c->nhits = 0;
	for (i = 0; i < sb_h; i++) {
		int abs = tui_sb_view_index(&c->sb, i);
		long long mi = fold_msg_at(c, abs);

		if (mi < 0)
			continue;
		if (c->msgs[mi].live || !c->msgs[mi].reason ||
		    !c->msgs[mi].rlen)
			continue;
		if (c->nhits < (int)(sizeof(c->hits) / sizeof(c->hits[0]))) {
			c->hits[c->nhits].row = i;
			c->hits[c->nhits].msg = (size_t)mi;
			c->nhits++;
		}
	}
	if (lm && lm->live && lm->reason && lm->rlen &&
	    c->live_fold_idx >= 0 &&
	    c->nhits < (int)(sizeof(c->hits) / sizeof(c->hits[0]))) {
		/* UXAB：live 折叠行位置=live_fold_idx（◆ 头行后）折算视口行 */
		int off = c->live_fold_idx - (c->live_lines.n - live_h);

		if (off >= 0 && off < live_h) {
			c->hits[c->nhits].row = sb_h + off;
			c->hits[c->nhits].msg = (size_t)(lm - c->msgs);
			c->nhits++;
		}
	}

	for (i = 0; i < sb_h; i++) {
		int abs = tui_sb_view_index(&c->sb, i);
		const tui_sline *ln;

		if (abs < 0)
			continue;
		ln = tui_sb_line(&c->sb, abs);
		if (ln)
			draw_line(s, y + i, x, ln->cells, ln->len, w);
	}
	/* live 尾部 */
	for (i = 0; i < live_h; i++) {
		int src = c->live_lines.n - live_h + i;
		const lbuf *lb = &c->live_lines.v[src];

		draw_line(s, y + sb_h + i, x, lb->cells, lb->len, w);
	}
}

int tui_chat_fold_row(const tui_chat *c)
{
	if (!c || c->nhits == 0)
		return -1;
	return c->hits[c->nhits - 1].row;
}

/* 重建 scrollback（B5 折叠切换 / rewidth 共用），保视口位置 */
static void chat_rebuild(tui_chat *c, int keep_view)
{
	int top = c->sb.view_top;
	int follow = c->sb.follow;
	int rows = c->sb.rows;
	size_t i;

	tui_sb_destroy(&c->sb);
	tui_sb_init(&c->sb, TUI_CHAT_SB_CAP, rows > 0 ? rows : 10);
	c->nfolds = 0;			/* 折叠行绝对号随重建重算 */
	for (i = 0; i < c->nmsgs; i++) {
		if (c->msgs[i].live)
			continue;
		chat_push_msg(c, &c->msgs[i]);
	}
	if (follow || !keep_view) {
		tui_sb_jump_latest(&c->sb);
		return;
	}
	c->sb.view_top = top;
	tui_sb_scroll(&c->sb, 0);	/* 钳位（展开行数变化后可能越界） */
}

int tui_chat_click(tui_chat *c, int row)
{
	int i;

	if (!c || row < 0)
		return 0;
	for (i = 0; i < c->nhits; i++) {
		if (c->hits[i].row != row)
			continue;
		{
			tui_msg *m = &c->msgs[c->hits[i].msg];
			int live = m->live;

			m->reason_open = !m->reason_open;
			if (!live)
				chat_rebuild(c, 1);	/* 定稿：重建保视口 */
			/* live：下帧 live_render 自然反映 */
		}
		return 1;
	}
	return 0;
}

void tui_chat_scroll(tui_chat *c, int lines)
{
	if (!c)
		return;
	tui_sb_scroll(&c->sb, lines);
}

void tui_chat_jump_latest(tui_chat *c)
{
	if (!c)
		return;
	tui_sb_jump_latest(&c->sb);
}

int tui_chat_at_bottom(const tui_chat *c)
{
	return c ? tui_sb_at_bottom(&c->sb) : 1;
}

void tui_chat_rewidth(tui_chat *c, int width)
{
	if (!c || width < 4 || width == c->width)
		return;
	c->width = width;
	chat_rebuild(c, 0);		/* B5：与折叠切换共用；宽度变化贴底 */
}

size_t tui_chat_dump_text(const tui_chat *c, char *buf, size_t cap)
{
	size_t n = 0;
	size_t i;

	if (!c || !cap)
		return 0;
	buf[0] = '\0';
	for (i = 0; i < c->nmsgs; i++) {
		const tui_msg *m = &c->msgs[i];

		if (m->text && m->tlen) {
			size_t k = m->tlen;

			if (n + 2 >= cap)
				break;	/* 放不下换行+NUL */
			if (n + k + 2 > cap)
				k = cap - n - 2;
			if (k > 0) {
				memcpy(buf + n, m->text, k);
				n += k;
			}
			buf[n++] = '\n';
			buf[n] = '\0';
		}
	}
	return n;
}

int tui_chat_live_empty(const tui_chat *c)
{
	size_t i;
	const tui_msg *m = NULL;

	if (!c)
		return 1;
	for (i = c->nmsgs; i > 0; i--) {
		if (c->msgs[i - 1].live) {
			m = &c->msgs[i - 1];
			break;
		}
	}
	if (!m)
		return 1;
	return (!m->text || !m->tlen) && (!m->reason || !m->rlen) &&
	       m->nt == 0;
}

int tui_chat_is_empty(const tui_chat *c)
{
	if (!c)
		return 1;
	return c->nmsgs == 0;
}

int tui_chat_scroll_info(const tui_chat *c, struct tui_chat_scrollinfo *out)
{
	int extra;

	if (!c || !out)
		return -1;
	extra = c->sb.count > c->sb.rows ? c->sb.count - c->sb.rows : 0;
	out->total = c->sb.count;
	out->rows = c->sb.rows;
	out->top = c->sb.view_top;
	out->lo = c->sb.dropped;
	out->hi = c->sb.dropped + extra;	/* 贴底位（== tui_sb_scroll 上界） */
	out->follow = c->sb.follow;
	return 0;
}

/* ---- T2：长历史滚动锚点 ---- */

/* 视口是否已顶到最旧行（含「全部内容一屏装下」的贴顶态）。空转写区
 * 不算顶——避免空屏 PgUp 触发无谓的历史加载。 */
int tui_chat_at_top(const tui_chat *c)
{
	if (!c || c->sb.count <= 0)
		return 0;
	return c->sb.view_top <= c->sb.dropped;
}

/* 当前 view_top 命中的消息 id + 相对 first_line 的偏移。
 * 只在 user/assistant 块上取锚（notice/error 文本可变——如「… 更早
 * N 条」分隔行每次加载都会改写，不能当锚）。视口顶落在首条对话块
 * 之前（典型：分隔行）→ 锚到该块、偏移为负（重现「块在屏幕同一行」）。
 * 返回 0=有效；-1=无对话块/参数坏。 */
int tui_chat_top_anchor(const tui_chat *c, char *msg_id, size_t cap,
			int *line_off)
{
	size_t i, best = (size_t)-1;
	int top;

	if (!c || !msg_id || cap == 0)
		return -1;
	msg_id[0] = '\0';
	top = c->sb.view_top;
	for (i = 0; i < c->nmsgs; i++) {
		const tui_msg *m = &c->msgs[i];

		if (m->live)
			break;
		if (m->role != TUI_ROLE_USER &&
		    m->role != TUI_ROLE_ASSISTANT)
			continue;
		if (m->first_line <= top)
			best = i;
		else
			break;		/* first_line 升序 */
	}
	if (best == (size_t)-1) {
		/* 视口顶在首条对话块之前：锚到其后首块（偏移 ≤0） */
		for (i = 0; i < c->nmsgs; i++) {
			const tui_msg *m = &c->msgs[i];

			if (m->live)
				break;
			if (m->role != TUI_ROLE_USER &&
			    m->role != TUI_ROLE_ASSISTANT)
				continue;
			snprintf(msg_id, cap, "%s", m->id);
			if (line_off)
				*line_off = top - m->first_line;
			return 0;
		}
		return -1;
	}
	snprintf(msg_id, cap, "%s", c->msgs[best].id);
	if (line_off)
		*line_off = top - c->msgs[best].first_line;
	return 0;
}

/* 找该 id 的消息块，view_top=first_line+line_off（钳位；follow 由
 * 钳位后的位置决定——落到底即恢复贴底）。返回 0=已定位；-1=找不到
 * （锚点丢失，调用方回退到新顶部）。 */
int tui_chat_scroll_to_msg(tui_chat *c, const char *msg_id, int line_off)
{
	size_t i;

	if (!c || !msg_id || !msg_id[0])
		return -1;
	for (i = 0; i < c->nmsgs; i++) {
		tui_msg *m = &c->msgs[i];
		long long top;

		if (m->live || strcmp(m->id, msg_id) != 0)
			continue;
		c->sb.follow = 0;
		/* T2 锚点契约：视口首行恒=锚行（块在屏幕同一行），与视口高
		 * 无关——锚行近内容末尾时允许越过 sb_hi 留尾白，不按
		 * 「满屏贴底」钳位（否则转写区变矮即挤掉锚行上方内容）。 */
		top = (long long)m->first_line + line_off;
		if (top < (long long)c->sb.dropped)
			top = c->sb.dropped;
		if (c->sb.count > 0 &&
		    top > (long long)(c->sb.dropped + c->sb.count) - 1)
			top = (long long)(c->sb.dropped + c->sb.count) - 1;
		c->sb.view_top = (int)top;
		return 0;
	}
	return -1;
}

/* O-14：notice-only 转写区（只有 notice/error、无 user/assistant、无
 * live）返回 scrollback 已占行数——空态面板起始行=该值（不与 notice
 * 重叠）。有对话内容/空转写区返回 0。 */
int tui_chat_notice_lines(const tui_chat *c)
{
	size_t i;

	if (!c)
		return 0;
	for (i = 0; i < c->nmsgs; i++) {
		if (c->msgs[i].role == TUI_ROLE_USER ||
		    c->msgs[i].role == TUI_ROLE_ASSISTANT)
			return 0;
	}
	return c->sb.count;
}
