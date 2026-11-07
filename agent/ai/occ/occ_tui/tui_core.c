/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_core.c - 终端模式管理 + 屏幕缓冲 + 脏行渲染 + 滚动视口（T9c1）
 *
 * 设计取舍（写明）：
 *   - raw 模式关 ISIG（真 raw）：OCD 键位要求 ctrl+c 区分「退出/清空」、
 *     ctrl+d/ctrl+z/ctrl+j 等必须以字节到达解析器；保留 ISIG 会让这些键
 *     变成信号，视图层拿不到键事件。外部 kill -INT/-TERM 仍送达，由
 *     信号处理器恢复终端后 re-raise（退出码语义不变）。
 *   - 恢复双保险：atexit（正常退出）+ SIGINT/SIGTERM/SIGHUP 处理器
 *     （异常路径）都走幂等 tui_term_leave。处理器内 tcsetattr 非严格
 *     async-signal-safe——nano/vim 同款业界惯例，接受；SIGWINCH 处理器
 *     只置 flag（tui_frame_winch_flag_set），零嵌套信号安全问题。
 *   - 非 TTY：stdout 非 tty 拒绝进入全屏，人话报错 stderr，rc=2。
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include "tui_core.h"

#include "tui_frame.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* ================= 颜色 / 属性 / SGR 生成器 ================= */

tui_color tui_color_default(void)
{
	tui_color c;
	c.kind = TUI_COLOR_DEFAULT;
	c.idx = 0;
	return c;
}

tui_color tui_color_idx(int idx)
{
	tui_color c;
	c.kind = TUI_COLOR_INDEXED;
	c.idx = (uint8_t)(idx & 0xff);
	return c;
}

tui_attr tui_attr_default(void)
{
	tui_attr a;
	a.fg = tui_color_default();
	a.bg = tui_color_default();
	a.style = 0;
	return a;
}

static int color_eq(tui_color a, tui_color b)
{
	return a.kind == b.kind && a.idx == b.idx;
}

int tui_attr_eq(const tui_attr *a, const tui_attr *b)
{
	return color_eq(a->fg, b->fg) && color_eq(a->bg, b->bg) &&
	       a->style == b->style;
}

/* 样式位 → SGR 码（顺序固定：bold,dim,italic,underline） */
static const char *style_code(uint16_t bit)
{
	switch (bit) {
	case TUI_ST_BOLD:      return "1";
	case TUI_ST_DIM:       return "2";
	case TUI_ST_ITALIC:    return "3";
	case TUI_ST_UNDERLINE: return "4";
	default:               return NULL;
	}
}

/* fg/bg → SGR 参数段（fg 默认 39 / 38;5;n；bg 默认 49 / 48;5;n） */
static int add_fg_part(char parts[][16], int np, tui_color c)
{
	if (np >= 8)
		return np;
	if (c.kind == TUI_COLOR_DEFAULT)
		snprintf(parts[np], 16, "39");
	else
		snprintf(parts[np], 16, "38;5;%u", (unsigned)c.idx);
	return np + 1;
}

static int add_bg_part(char parts[][16], int np, tui_color c)
{
	if (np >= 8)
		return np;
	if (c.kind == TUI_COLOR_DEFAULT)
		snprintf(parts[np], 16, "49");
	else
		snprintf(parts[np], 16, "48;5;%u", (unsigned)c.idx);
	return np + 1;
}

size_t tui_sgr_transition(const tui_attr *cur, const tui_attr *want,
			  char *buf, size_t cap)
{
	char parts[8][16];
	int np = 0;
	int removed;
	uint16_t bits;
	int i;
	size_t n = 0;

	if (tui_attr_eq(cur, want))
		return 0;
	if (cap < 8)
		return 0;

	removed = (cur->style & ~want->style) != 0;
	if (removed) {
		/* 有样式位要清：先 ESC[0 再按 want 重建（fg/bg 复位后只需
		 * 补 indexed 色；default 色复位后已是默认，无需再发） */
		snprintf(parts[np++], 16, "0");
		for (i = 0; i < 4; i++) {
			bits = (uint16_t)(1u << i);
			if (want->style & bits) {
				const char *c = style_code(bits);
				if (c && np < 8)
					snprintf(parts[np++], 16, "%s", c);
			}
		}
		if (want->fg.kind == TUI_COLOR_INDEXED)
			np = add_fg_part(parts, np, want->fg);
		if (want->bg.kind == TUI_COLOR_INDEXED)
			np = add_bg_part(parts, np, want->bg);
	} else {
		/* 无清除：只发增量（新增样式位 + 变化的 fg/bg） */
		for (i = 0; i < 4; i++) {
			bits = (uint16_t)(1u << i);
			if ((want->style & bits) && !(cur->style & bits)) {
				const char *c = style_code(bits);
				if (c && np < 8)
					snprintf(parts[np++], 16, "%s", c);
			}
		}
		if (!color_eq(cur->fg, want->fg))
			np = add_fg_part(parts, np, want->fg);
		if (!color_eq(cur->bg, want->bg))
			np = add_bg_part(parts, np, want->bg);
	}
	if (np == 0)
		return 0;

	buf[n++] = '\x1b';
	buf[n++] = '[';
	for (i = 0; i < np; i++) {
		size_t l = strlen(parts[i]);
		if (n + l + 2 >= cap)
			return 0;
		if (i > 0)
			buf[n++] = ';';
		memcpy(buf + n, parts[i], l);
		n += l;
	}
	buf[n++] = 'm';
	return n;
}

size_t tui_sgr_reset(char *buf, size_t cap)
{
	if (cap < 4)
		return 0;
	memcpy(buf, "\x1b[0m", 4);
	return 4;
}

/* ================= 单元格 / 屏幕缓冲 ================= */

static void cell_set_space(tui_cell *c, tui_attr a)
{
	c->utf8[0] = ' ';
	c->len = 1;
	c->width = 1;
	c->attr = a;
}

static void cell_set_cp(tui_cell *c, uint32_t cp, int w, tui_attr a)
{
	uint8_t b[4];
	size_t nb = tui_utf8_encode(cp, b);
	if (nb == 0) {
		cell_set_space(c, a);
		return;
	}
	memcpy(c->utf8, b, nb);
	c->len = (uint8_t)nb;
	c->width = (uint8_t)w;
	c->attr = a;
}

static void cell_set_cont(tui_cell *c, tui_attr a)
{
	c->len = 0;
	c->width = 0;
	c->attr = a;
}

static int cell_eq(const tui_cell *a, const tui_cell *b)
{
	return a->len == b->len && a->width == b->width &&
	       a->attr.fg.kind == b->attr.fg.kind &&
	       a->attr.fg.idx == b->attr.fg.idx &&
	       a->attr.bg.kind == b->attr.bg.kind &&
	       a->attr.bg.idx == b->attr.bg.idx &&
	       a->attr.style == b->attr.style &&
	       memcmp(a->utf8, b->utf8, a->len) == 0;
}

static void cells_fill_space(tui_cell *cells, int n, tui_attr a)
{
	int i;
	for (i = 0; i < n; i++)
		cell_set_space(&cells[i], a);
}

tui_screen *tui_screen_create(int rows, int cols)
{
	tui_screen *s;
	int i;

	if (rows < 1 || cols < 1)
		return NULL;
	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;
	s->rows = rows;
	s->cols = cols;
	s->cells = calloc((size_t)rows * (size_t)cols, sizeof(tui_cell));
	s->dirty = calloc((size_t)rows, 1);
	if (!s->cells || !s->dirty) {
		free(s->cells);
		free(s->dirty);
		free(s);
		return NULL;
	}
	cells_fill_space(s->cells, rows * cols, tui_attr_default());
	for (i = 0; i < rows; i++)
		s->dirty[i] = 1;
	return s;
}

void tui_screen_destroy(tui_screen *s)
{
	if (!s)
		return;
	free(s->cells);
	free(s->dirty);
	free(s);
}

void tui_screen_resize(tui_screen *s, int rows, int cols)
{
	tui_cell *nc;
	uint8_t *nd;
	int i;

	if (!s || rows < 1 || cols < 1)
		return;
	nc = calloc((size_t)rows * (size_t)cols, sizeof(tui_cell));
	nd = calloc((size_t)rows, 1);
	if (!nc || !nd) {
		free(nc);
		free(nd);
		return;
	}
	cells_fill_space(nc, rows * cols, tui_attr_default());
	for (i = 0; i < rows; i++)
		nd[i] = 1;
	free(s->cells);
	free(s->dirty);
	s->cells = nc;
	s->dirty = nd;
	s->rows = rows;
	s->cols = cols;
}

void tui_screen_fill(tui_screen *s, tui_attr a)
{
	int i;
	if (!s)
		return;
	cells_fill_space(s->cells, s->rows * s->cols, a);
	for (i = 0; i < s->rows; i++)
		s->dirty[i] = 1;
}

void tui_screen_mark_dirty(tui_screen *s, int row)
{
	if (!s || row < 0 || row >= s->rows)
		return;
	s->dirty[row] = 1;
}

tui_cell *tui_screen_at(tui_screen *s, int row, int col)
{
	if (!s || row < 0 || row >= s->rows || col < 0 || col >= s->cols)
		return NULL;
	return &s->cells[(size_t)row * (size_t)s->cols + (size_t)col];
}

/*
 * 写入 UTF-8 串（grapheme 级）。返回写后列号；row 越界/col<0 返回 -1。
 * 截断在 cell 边界：双宽放不下即停（不撕半个汉字）；落在续格上的写入
 * 先把左侧宽字主格降为空格；零宽组合符附着前一基字符（同 put 或跨 put
 * 的 col-1；行首无处可依则丢弃）；控制符跳过（分行归视图层）。
 */
int tui_screen_put(tui_screen *s, int row, int col,
		   const char *utf8, size_t len, tui_attr a)
{
	tui_cell *rc;
	int c, last_base = -1, touched = 0;
	size_t i = 0;

	if (!s || row < 0 || row >= s->rows || col < 0 || !utf8)
		return -1;
	if (col >= s->cols)
		return col;
	rc = s->cells + (size_t)row * (size_t)s->cols;
	c = col;

	while (i < len && c < s->cols) {
		uint32_t cp;
		size_t adv;
		tui_u8stat st = tui_utf8_decode((const uint8_t *)utf8 + i,
						len - i, &cp, &adv);
		int w;

		if (st == TUI_U8_NEEDMORE)
			cp = TUI_REPLACEMENT;	/* 串尾截断 → 一个 FFFD */
		else if (st == TUI_U8_INVALID)
			cp = TUI_REPLACEMENT;
		i += adv;

		w = tui_wcwidth(cp);
		if (w == 0) {
			/* 控制符（\n 等）跳过——分行归视图层 */
			if (!tui_is_combining(cp))
				continue;
			/* 组合符：附着到前一基字符 */
			int tgt = last_base;
			if (tgt < 0 && c > 0) {
				tgt = c - 1;
				while (tgt > 0 && rc[tgt].width == 0)
					tgt--;
				if (rc[tgt].width == 0)
					tgt = -1;
			}
			if (tgt >= 0 && tgt < s->cols && rc[tgt].width > 0) {
				uint8_t b[4];
				size_t nb = tui_utf8_encode(cp, b);
				if (nb > 0 &&
				    rc[tgt].len + nb <= TUI_CELL_MAX) {
					memcpy(rc[tgt].utf8 + rc[tgt].len,
					       b, nb);
					rc[tgt].len =
						(uint8_t)(rc[tgt].len + nb);
					touched = 1;
				}
				/* 放不下 → 丢弃（每 cell 有界） */
			}
			continue;	/* 零宽：不占列 */
		}
		if (w == 2 && c + 1 >= s->cols)
			break;		/* 不撕半个汉字 */

		/* 覆盖前清理被撕裂的旧宽字结构 */
		if (rc[c].width == 0 && c > 0 && rc[c - 1].width == 2)
			cell_set_space(&rc[c - 1], rc[c - 1].attr);
		if (w == 1 && rc[c].width == 2 && c + 1 < s->cols)
			cell_set_space(&rc[c + 1], rc[c + 1].attr);
		if (w == 2 && c + 1 < s->cols && rc[c + 1].width == 2 &&
		    c + 2 < s->cols)
			cell_set_space(&rc[c + 2], rc[c + 2].attr);

		cell_set_cp(&rc[c], cp, w, a);
		if (w == 2)
			cell_set_cont(&rc[c + 1], a);
		last_base = c;
		c += w;
		touched = 1;
	}
	if (touched)
		s->dirty[row] = 1;
	return c;
}

int tui_screen_puts(tui_screen *s, int row, int col,
		    const char *utf8, tui_attr a)
{
	if (!utf8)
		return -1;
	return tui_screen_put(s, row, col, utf8, strlen(utf8), a);
}

/* ================= 输出汇 ================= */

static void sink_fd_write(void *ctx, const char *data, size_t len)
{
	int fd = (int)(intptr_t)ctx;
	size_t off = 0;

	while (off < len) {
		ssize_t w = write(fd, data + off, len - off);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			return;
		}
		off += (size_t)w;
	}
}

void tui_sink_init_fd(tui_sink *s, int fd)
{
	s->fn = sink_fd_write;
	s->ctx = (void *)(intptr_t)fd;
}

/* ================= 渲染器（front/back 双缓冲 + 脏行 diff） ================= */

tui_renderer *tui_renderer_create(int rows, int cols, tui_sink sink)
{
	tui_renderer *r;

	if (rows < 1 || cols < 1)
		return NULL;
	r = calloc(1, sizeof(*r));
	if (!r)
		return NULL;
	r->front = tui_screen_create(rows, cols);
	r->back = tui_screen_create(rows, cols);
	if (!r->front || !r->back) {
		tui_screen_destroy(r->front);
		tui_screen_destroy(r->back);
		free(r);
		return NULL;
	}
	r->sink = sink;
	r->cur_attr = tui_attr_default();
	r->cur_row = -1;	/* 未知（standalone 假定空白+默认色由调用方保证） */
	r->cur_col = -1;
	r->need_clear = 0;
	return r;
}

void tui_renderer_destroy(tui_renderer *r)
{
	if (!r)
		return;
	tui_screen_destroy(r->front);
	tui_screen_destroy(r->back);
	free(r);
}

tui_screen *tui_renderer_front(tui_renderer *r)
{
	return r ? r->front : NULL;
}

void tui_renderer_set_sink(tui_renderer *r, tui_sink sink)
{
	if (r)
		r->sink = sink;
}

void tui_renderer_clear(tui_renderer *r)
{
	if (r)
		r->need_clear = 1;
}

void tui_renderer_resize(tui_renderer *r, int rows, int cols)
{
	if (!r || rows < 1 || cols < 1)
		return;
	tui_screen_resize(r->front, rows, cols);
	tui_screen_resize(r->back, rows, cols);
	r->need_clear = 1;		/* 终端重排不可知 → 下帧全清 */
	r->cur_row = -1;
	r->cur_col = -1;
}

int tui_renderer_flush(tui_renderer *r, int crow, int ccol)
{
	int row, redrawn = 0;

	if (!r || !r->sink.fn || r->front->rows < 1)
		return 0;

	if (r->need_clear) {
		static const char clr[] = "\x1b[0m\x1b[2J\x1b[H";
		r->sink.fn(r->sink.ctx, clr, sizeof(clr) - 1);
		cells_fill_space(r->back->cells,
				 r->back->rows * r->back->cols,
				 tui_attr_default());
		for (row = 0; row < r->front->rows; row++)
			r->front->dirty[row] = 1;
		r->cur_attr = tui_attr_default();
		r->cur_row = 0;
		r->cur_col = 0;
		r->need_clear = 0;
	}

	for (row = 0; row < r->front->rows; row++) {
		tui_cell *fc, *bc;
		int cols = r->front->cols;
		int first = -1, last = -1, k;
		char cup[32];
		int n;

		if (!r->front->dirty[row])
			continue;
		fc = r->front->cells + (size_t)row * (size_t)cols;
		bc = r->back->cells + (size_t)row * (size_t)cols;
		for (k = 0; k < cols; k++) {
			if (!cell_eq(&fc[k], &bc[k])) {
				if (first < 0)
					first = k;
				last = k;
			}
		}
		if (first < 0) {
			r->front->dirty[row] = 0;
			continue;
		}
		/* 落在续格上 → 回退到主格（防御：正常不应发生） */
		while (first > 0 && fc[first].width == 0)
			first--;

		n = snprintf(cup, sizeof(cup), "\x1b[%d;%dH", row + 1,
			     first + 1);
		if (n > 0)
			r->sink.fn(r->sink.ctx, cup, (size_t)n);

		for (k = first; k <= last; k++) {
			tui_cell *cc = &fc[k];
			if (cc->width == 0)
				continue;	/* 续格由主格双宽覆盖 */
			if (!tui_attr_eq(&r->cur_attr, &cc->attr)) {
				char sb[64];
				size_t sn = tui_sgr_transition(&r->cur_attr,
							      &cc->attr, sb,
							      sizeof(sb));
				if (sn) {
					r->sink.fn(r->sink.ctx, sb, sn);
					r->cur_attr = cc->attr;
				}
			}
			r->sink.fn(r->sink.ctx, (const char *)cc->utf8,
				   cc->len);
		}
		memcpy(bc, fc, (size_t)cols * sizeof(tui_cell));
		r->front->dirty[row] = 0;
		redrawn++;
		/* 跟踪绘制后物理光标位（宽主格占 2 列） */
		r->cur_row = row;
		r->cur_col = last + 1 + (fc[last].width == 2 ? 1 : 0);
	}

	if (crow >= 0 && (crow != r->cur_row || ccol != r->cur_col)) {
		char cup[32];
		int n = snprintf(cup, sizeof(cup), "\x1b[%d;%dH", crow + 1,
				 ccol + 1);
		if (n > 0)
			r->sink.fn(r->sink.ctx, cup, (size_t)n);
		r->cur_row = crow;
		r->cur_col = ccol;
	}
	return redrawn;
}

/* ================= 滚动视口原语（scrollback 环） ================= */

void tui_sb_init(tui_scrollback *sb, int cap, int view_rows)
{
	if (!sb)
		return;
	memset(sb, 0, sizeof(*sb));
	if (cap < 1)
		cap = 1;
	if (view_rows < 1)
		view_rows = 1;
	sb->ring = calloc((size_t)cap, sizeof(tui_sline));
	if (!sb->ring) {
		sb->cap = 0;
		return;
	}
	sb->cap = cap;
	sb->rows = view_rows;
	sb->follow = 1;
}

void tui_sb_destroy(tui_scrollback *sb)
{
	int i;
	if (!sb || !sb->ring)
		return;
	for (i = 0; i < sb->count; i++) {
		int pos = (sb->head + i) % sb->cap;
		free(sb->ring[pos].cells);
	}
	free(sb->ring);
	memset(sb, 0, sizeof(*sb));
}

/* 视口底（最旧可见绝对行上界）：lo=dropped，hi=dropped+max(0,count-rows) */
static int sb_hi(const tui_scrollback *sb)
{
	int extra = sb->count > sb->rows ? sb->count - sb->rows : 0;
	return sb->dropped + extra;
}

void tui_sb_push(tui_scrollback *sb, const tui_cell *cells, int len)
{
	tui_cell *copy = NULL;
	int slot, lo, hi;

	if (!sb || !sb->ring || sb->cap < 1)
		return;
	if (len > 0) {
		if (!cells)
			return;
		copy = malloc((size_t)len * sizeof(tui_cell));
		if (!copy)
			return;		/* OOM：丢该行，不改环状态 */
		memcpy(copy, cells, (size_t)len * sizeof(tui_cell));
	}
	slot = (sb->head + sb->count) % sb->cap;
	if (sb->count == sb->cap) {
		free(sb->ring[slot].cells);	/* 覆盖最旧行 */
		sb->head = (sb->head + 1) % sb->cap;
		sb->dropped++;
	} else {
		sb->count++;
	}
	sb->ring[slot].cells = copy;
	sb->ring[slot].len = len;

	lo = sb->dropped;
	hi = sb_hi(sb);
	if (sb->follow)
		sb->view_top = hi;
	else {
		if (sb->view_top < lo)
			sb->view_top = lo;
		if (sb->view_top > hi)
			sb->view_top = hi;
	}
}

const tui_sline *tui_sb_line(const tui_scrollback *sb, int abs_idx)
{
	int pos;
	if (!sb || !sb->ring)
		return NULL;
	if (abs_idx < sb->dropped || abs_idx >= sb->dropped + sb->count)
		return NULL;
	pos = (sb->head + (abs_idx - sb->dropped)) % sb->cap;
	return &sb->ring[pos];
}

int tui_sb_view_index(const tui_scrollback *sb, int i)
{
	int abs;
	if (!sb || i < 0 || i >= sb->rows)
		return -1;
	abs = sb->view_top + i;
	if (abs < sb->dropped || abs >= sb->dropped + sb->count)
		return -1;
	return abs;
}

void tui_sb_scroll(tui_scrollback *sb, int lines)
{
	int lo, hi, t;
	if (!sb || !sb->ring)
		return;
	lo = sb->dropped;
	hi = sb_hi(sb);
	t = sb->view_top - lines;	/* >0 向旧（上） */
	if (t < lo)
		t = lo;
	if (t > hi)
		t = hi;
	sb->view_top = t;
	sb->follow = (t == hi);		/* 滚到底=恢复 follow-latest */
}

void tui_sb_jump_latest(tui_scrollback *sb)
{
	if (!sb || !sb->ring)
		return;
	sb->view_top = sb_hi(sb);
	sb->follow = 1;
}

int tui_sb_at_bottom(const tui_scrollback *sb)
{
	return sb ? sb->follow : 0;
}

int tui_sb_top(const tui_scrollback *sb)
{
	return sb ? sb->view_top : -1;
}

int tui_sb_count(const tui_scrollback *sb)
{
	return sb ? sb->count : 0;
}

int tui_sb_dropped(const tui_scrollback *sb)
{
	return sb ? sb->dropped : 0;
}

/* ================= 调色板（主题=数据；加载归 c3） ================= */

void tui_theme_default(tui_theme *t)
{
	if (!t)
		return;
	t->slot[TUI_THEME_FG] = tui_color_idx(252);
	t->slot[TUI_THEME_BG] = tui_color_idx(235);
	t->slot[TUI_THEME_MUTED] = tui_color_idx(242);
	t->slot[TUI_THEME_ACCENT] = tui_color_idx(81);
	t->slot[TUI_THEME_BORDER] = tui_color_idx(238);
	t->slot[TUI_THEME_ERROR] = tui_color_idx(203);
	t->slot[TUI_THEME_OK] = tui_color_idx(114);
	t->slot[TUI_THEME_WARN] = tui_color_idx(214);
	t->slot[TUI_THEME_USER_BG] = tui_color_idx(236);
	t->slot[TUI_THEME_ASSISTANT_BG] = tui_color_idx(234);
}

tui_color tui_theme_get(const tui_theme *t, tui_theme_slot s)
{
	if (!t || (unsigned)s >= (unsigned)TUI_THEME_COUNT)
		return tui_color_default();
	return t->slot[s];
}

void tui_theme_set(tui_theme *t, tui_theme_slot s, tui_color c)
{
	if (!t || (unsigned)s >= (unsigned)TUI_THEME_COUNT)
		return;
	t->slot[s] = c;
}

/* ================= 终端模式管理 ================= */

static tui_term *g_term;		/* 全屏活动终端（单实例约定） */

static int write_all(int fd, const char *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t w = write(fd, buf + off, len - off);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		off += (size_t)w;
	}
	return 0;
}

int tui_term_write(tui_term *t, const char *data, size_t len)
{
	if (!t || !data)
		return -1;
	return write_all(t->fd, data, len);
}

void tui_term_init(tui_term *t, int fd)
{
	if (!t)
		return;
	memset(t, 0, sizeof(*t));
	t->fd = fd;
}

void tui_term_hide_cursor(tui_term *t)
{
	if (t && t->entered)
		(void)write_all(t->fd, "\x1b[?25l", 6);
}

void tui_term_show_cursor(tui_term *t)
{
	if (t && t->entered)
		(void)write_all(t->fd, "\x1b[?25h", 6);
}

int tui_mouse_enable(tui_term *t, int on)
{
	(void)t;
	(void)on;
	return TUI_ERR_UNSUPPORTED;	/* 本棒不做，留 API（c2/c3 后续接） */
}

/* 恢复（幂等）：发恢复序列 + 还原 termios + 还原信号处理 */
void tui_term_leave(tui_term *t)
{
	static const char seq[] = "\x1b[?2004l\x1b[?25h\x1b[0m\x1b[?1049l";

	if (!t || !t->entered)
		return;
	(void)write_all(t->fd, seq, sizeof(seq) - 1);
	(void)tcsetattr(t->fd, TCSAFLUSH, &t->saved);
	if (t->sigs_saved) {
		sigaction(SIGINT, &t->old_int, NULL);
		sigaction(SIGTERM, &t->old_term, NULL);
		sigaction(SIGHUP, &t->old_hup, NULL);
		sigaction(SIGWINCH, &t->old_winch, NULL);
		t->sigs_saved = 0;
	}
	t->entered = 0;
	if (g_term == t)
		g_term = NULL;
}

/* 异常路径：恢复终端 → 信号复位默认 → re-raise（退出码语义不变） */
static void tui_sig_fatal(int sig)
{
	tui_term *t = g_term;
	struct sigaction sa;

	if (t && t->entered)
		tui_term_leave(t);
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sigaction(sig, &sa, NULL);
	raise(sig);
}

/* SIGWINCH 只置 flag（sig_atomic_t），重绘在主循环做 */
static void tui_sig_winch(int sig)
{
	(void)sig;
	tui_frame_winch_flag_set();
}

static void tui_atexit_restore(void)
{
	if (g_term && g_term->entered)
		tui_term_leave(g_term);
}

int tui_term_enter(tui_term *t)
{
	struct termios raw;
	struct sigaction sa;
	static const char seq[] =
		"\x1b[?1049h\x1b[0m\x1b[2J\x1b[H\x1b[?25l\x1b[?2004h\x1b[?u";
	static int atexit_done;

	if (!t)
		return -1;
	if (t->entered)
		return 0;
	/* 非 TTY：人话报错，拒绝全屏，不动任何状态（rc=2） */
	if (!isatty(t->fd)) {
		fprintf(stderr,
			"occ_tui: 需要真实 TTY（stdout 非 tty），拒绝进入全屏模式；"
			"headless 场景请用 occ -p\n");
		return 2;
	}
	if (g_term && g_term->entered && g_term != t)
		return -1;		/* 已有全屏终端（单实例约定） */

	if (tcgetattr(t->fd, &t->saved) != 0)
		return -1;
	raw = t->saved;
	/* 取舍见文件头：关 ISIG（键字节化），关 ECHO/ICANON/OPOST（真 raw） */
	raw.c_iflag &= (tcflag_t)~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR |
				   IGNCR | ICRNL | IXON);
	raw.c_oflag &= (tcflag_t)~OPOST;
	raw.c_lflag &= (tcflag_t)~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	raw.c_cflag &= (tcflag_t)~(CSIZE | PARENB);
	raw.c_cflag |= CS8;
	raw.c_cc[VMIN] = 1;
	raw.c_cc[VTIME] = 0;
	if (tcsetattr(t->fd, TCSAFLUSH, &raw) != 0)
		return -1;
	if (write_all(t->fd, seq, sizeof(seq) - 1) != 0) {
		(void)tcsetattr(t->fd, TCSAFLUSH, &t->saved);
		return -1;
	}

	/* 信号：fatal 恢复+re-raise；WINCH 只置 flag */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = tui_sig_fatal;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, &t->old_int) != 0 ||
	    sigaction(SIGTERM, &sa, &t->old_term) != 0 ||
	    sigaction(SIGHUP, &sa, &t->old_hup) != 0) {
		(void)tcsetattr(t->fd, TCSAFLUSH, &t->saved);
		return -1;
	}
	sa.sa_handler = tui_sig_winch;
	if (sigaction(SIGWINCH, &sa, &t->old_winch) != 0) {
		sigaction(SIGINT, &t->old_int, NULL);
		sigaction(SIGTERM, &t->old_term, NULL);
		sigaction(SIGHUP, &t->old_hup, NULL);
		(void)tcsetattr(t->fd, TCSAFLUSH, &t->saved);
		return -1;
	}
	t->sigs_saved = 1;

	if (!atexit_done) {
		atexit(tui_atexit_restore);
		atexit_done = 1;
	}
	t->entered = 1;
	g_term = t;
	return 0;
}

int tui_term_is_entered(const tui_term *t)
{
	return t && t->entered;
}

int tui_term_get_size(int fd, int *rows, int *cols)
{
	struct winsize ws;

	if (ioctl(fd, TIOCGWINSZ, &ws) != 0)
		return -1;
	*rows = ws.ws_row;
	*cols = ws.ws_col;
	if (*rows <= 0)
		*rows = 24;		/* 0 尺寸兜底 */
	if (*cols <= 0)
		*cols = 80;
	return 0;
}
