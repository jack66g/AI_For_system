/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_render.c - 脏行增量重绘 golden 字节级测试（T9c1）
 *
 * 断言构造帧 A→B 的输出 ANSI 字节逐位相等；SGR 最小化切换；双宽占位
 * 与截断不撕汉字；组合符合并；clear/resize 序列；滚动视口原语。
 */
#include "../tui_core.h"

#include <stdio.h>
#include <string.h>

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

/* 内存汇：收集渲染字节 */
struct memsink {
	char buf[8192];
	size_t len;
};

static void memsink_fn(void *ud, const char *d, size_t n)
{
	struct memsink *m = (struct memsink *)ud;
	if (m->len + n <= sizeof(m->buf)) {
		memcpy(m->buf + m->len, d, n);
		m->len += n;
	}
}

static void sink_reset(struct memsink *m)
{
	m->len = 0;
}

/* 断言渲染输出 == 期望字节串（golden 逐位） */
static void ok_bytes(const char *name, const struct memsink *m,
		     const char *want, size_t want_len)
{
	size_t i;

	if (m->len == want_len && memcmp(m->buf, want, want_len) == 0) {
		n_ok++;
		return;
	}
	n_fail++;
	printf("FAIL %s (line %d)\n  want(%zu):", name, __LINE__, want_len);
	for (i = 0; i < want_len; i++)
		printf(" %02x", (unsigned char)want[i]);
	printf("\n  got (%zu):", m->len);
	for (i = 0; i < m->len && i < 128; i++)
		printf(" %02x", (unsigned char)m->buf[i]);
	printf("\n");
}

#define OK_BYTES(name, m, lit) ok_bytes(name, m, lit, sizeof(lit) - 1)

/* 直接断言 SGR 生成器输出 */
static void ok_sgr(const char *name, size_t n, const char *buf,
		   const char *want, size_t want_len)
{
	if (n == want_len && memcmp(buf, want, want_len) == 0) {
		n_ok++;
		return;
	}
	n_fail++;
	printf("FAIL %s (line %d) n=%zu\n", name, __LINE__, n);
}

static tui_attr A_FG(int idx, uint16_t style)
{
	tui_attr a = tui_attr_default();
	a.fg = tui_color_idx(idx);
	a.style = style;
	return a;
}

/* ---- SGR 生成器单测 ---- */

static void test_sgr(void)
{
	char buf[64];
	size_t n;
	tui_attr d = tui_attr_default();
	tui_attr red_bold = A_FG(1, TUI_ST_BOLD);
	tui_attr red = A_FG(1, 0);
	tui_attr green = A_FG(2, 0);
	tui_attr bg;

	/* 默认→红+粗：无清除，增量（样式位+fg） */
	n = tui_sgr_transition(&d, &red_bold, buf, sizeof(buf));
	ok_sgr("sgr-default-to-red-bold", n, buf, "\x1b[1;38;5;1m", 11);

	/* 红+粗→默认：有清除 → ESC[0m */
	n = tui_sgr_transition(&red_bold, &d, buf, sizeof(buf));
	ok_sgr("sgr-red-bold-to-default", n, buf, "\x1b[0m", 4);

	/* 红→绿：无清除，仅 fg 变化 */
	n = tui_sgr_transition(&red, &green, buf, sizeof(buf));
	ok_sgr("sgr-red-to-green", n, buf, "\x1b[38;5;2m", 9);

	/* 红→默认：39 */
	n = tui_sgr_transition(&red, &d, buf, sizeof(buf));
	ok_sgr("sgr-red-to-default", n, buf, "\x1b[39m", 5);

	/* 相等 → 0 字节 */
	n = tui_sgr_transition(&red, &red, buf, sizeof(buf));
	OK(n == 0, "sgr-equal-zero");

	/* 默认 bg→索引 bg */
	bg = tui_attr_default();
	bg.bg = tui_color_idx(200);
	n = tui_sgr_transition(&d, &bg, buf, sizeof(buf));
	ok_sgr("sgr-bg-default-to-200", n, buf, "\x1b[48;5;200m", 11);

	/* 粗+红→仅红（清粗但重建 fg）→ ESC[0;38;5;1m（11 字节） */
	n = tui_sgr_transition(&red_bold, &red, buf, sizeof(buf));
	ok_sgr("sgr-bold-to-plain-red", n, buf, "\x1b[0;38;5;1m", 11);

	/* reset 序列 */
	n = tui_sgr_reset(buf, sizeof(buf));
	ok_sgr("sgr-reset-seq", n, buf, "\x1b[0m", 4);

	/* 四样式位全开：默认→{b,d,i,u} */
	{
		tui_attr all = tui_attr_default();
		all.style = TUI_ST_BOLD | TUI_ST_DIM | TUI_ST_ITALIC |
			    TUI_ST_UNDERLINE;
		n = tui_sgr_transition(&d, &all, buf, sizeof(buf));
		ok_sgr("sgr-all-styles", n, buf, "\x1b[1;2;3;4m", 10);
	}
}

/* ---- 屏幕缓冲结构断言 ---- */

static void test_screen_struct(void)
{
	tui_screen *s = tui_screen_create(3, 10);
	tui_attr d = tui_attr_default();
	int col;

	OK(s != NULL, "screen-create");
	if (!s)
		return;
	OK(s->rows == 3 && s->cols == 10, "screen-dims");
	OK(tui_screen_at(s, 0, 0)->width == 1 &&
	   tui_screen_at(s, 0, 0)->len == 1 &&
	   tui_screen_at(s, 0, 0)->utf8[0] == ' ', "screen-initial-blank");

	/* 双宽占位：中 → base(w2) + cont(w0) */
	col = tui_screen_put(s, 0, 0, "\xe4\xb8\xad", 3, d);
	OK(col == 2, "put-wide-advance2");
	OK(tui_screen_at(s, 0, 0)->width == 2, "put-wide-base");
	OK(tui_screen_at(s, 0, 1)->width == 0 &&
	   tui_screen_at(s, 0, 1)->len == 0, "put-wide-cont");

	/* 截断在 cell 边界：10 列行写 6 个宽字（需 12 列）→ 只放 5 个 */
	tui_screen_fill(s, d);
	col = tui_screen_put(s, 2, 0,
			     "\xe4\xb8\xad\xe4\xb8\xad\xe4\xb8\xad"
			     "\xe4\xb8\xad\xe4\xb8\xad\xe4\xb8\xad", 18, d);
	OK(col == 10, "put-trunc-stop-10cols");
	OK(tui_screen_at(s, 2, 8)->width == 2, "put-trunc-fifth-wide");
	OK(tui_screen_at(s, 2, 9)->width == 0, "put-trunc-fifth-cont");

	/* 双宽放最后一列：不写（不撕半字） */
	tui_screen_fill(s, d);
	col = tui_screen_put(s, 1, 9, "\xe4\xb8\xad", 3, d);
	OK(col == 9, "put-wide-last-col-refused");
	OK(tui_screen_at(s, 1, 9)->utf8[0] == ' ', "put-wide-last-col-blank");

	/* 落在续格上的写入：先拆左邻宽字 */
	tui_screen_fill(s, d);
	tui_screen_put(s, 0, 0, "\xe4\xb8\xad", 3, d);	/* 中 @0-1 */
	col = tui_screen_put(s, 0, 1, "X", 1, d);	/* X 落在续格 */
	OK(col == 2, "put-on-cont-advance");
	OK(tui_screen_at(s, 0, 0)->width == 1 &&
	   tui_screen_at(s, 0, 0)->utf8[0] == ' ',
	   "put-on-cont-left-cleared");
	OK(tui_screen_at(s, 0, 1)->utf8[0] == 'X', "put-on-cont-written");

	/* 窄字盖宽字主格：右续格降空格 */
	tui_screen_fill(s, d);
	tui_screen_put(s, 0, 0, "\xe4\xb8\xad", 3, d);
	tui_screen_put(s, 0, 0, "Y", 1, d);
	OK(tui_screen_at(s, 0, 0)->utf8[0] == 'Y',
	   "put-narrow-over-wide-base");
	OK(tui_screen_at(s, 0, 1)->width == 1 &&
	   tui_screen_at(s, 0, 1)->utf8[0] == ' ',
	   "put-narrow-over-wide-right-blank");

	/* 组合符：同 put 附着 */
	tui_screen_fill(s, d);
	tui_screen_put(s, 0, 0, "e\xcc\x81", 3, d);	/* e + U+0301 */
	OK(tui_screen_at(s, 0, 0)->len == 3 &&
	   memcmp(tui_screen_at(s, 0, 0)->utf8, "e\xcc\x81", 3) == 0,
	   "put-combining-attach");
	OK(tui_screen_at(s, 0, 0)->width == 1, "put-combining-width1");

	/* 组合符：跨 put 附着到 col-1 基字符 */
	tui_screen_fill(s, d);
	tui_screen_put(s, 0, 0, "e", 1, d);
	tui_screen_put(s, 0, 1, "\xcc\x81", 2, d);
	OK(tui_screen_at(s, 0, 0)->len == 3, "put-combining-cross-put");

	/* 行首孤立组合符：丢弃（无处可依） */
	tui_screen_fill(s, d);
	tui_screen_put(s, 1, 0, "\xcc\x81", 2, d);
	OK(tui_screen_at(s, 1, 0)->len == 1 &&
	   tui_screen_at(s, 1, 0)->utf8[0] == ' ',
	   "put-combining-linehead-drop");

	/* 控制符跳过（分行归视图层） */
	tui_screen_fill(s, d);
	col = tui_screen_put(s, 2, 0, "a\nb", 3, d);
	OK(col == 2, "put-ctl-skipped");
	OK(tui_screen_at(s, 2, 0)->utf8[0] == 'a' &&
	   tui_screen_at(s, 2, 1)->utf8[0] == 'b', "put-ctl-both-written");

	/* 非法 UTF-8 → 替换符 */
	tui_screen_fill(s, d);
	tui_screen_put(s, 2, 0, "\xff", 1, d);
	OK(memcmp(tui_screen_at(s, 2, 0)->utf8, "\xef\xbf\xbd", 3) == 0,
	   "put-invalid-replacement");

	/* 越界 row → -1 */
	OK(tui_screen_put(s, 9, 0, "x", 1, d) == -1, "put-bad-row-neg1");

	tui_screen_destroy(s);
}

/* ---- 脏行 diff golden 字节 ---- */

static void test_flush_golden(void)
{
	struct memsink m;
	tui_renderer *r;
	tui_attr d = tui_attr_default();

	memset(&m, 0, sizeof(m));
	r = tui_renderer_create(4, 8, (tui_sink){ memsink_fn, &m });
	OK(r != NULL, "renderer-create");
	if (!r)
		return;

	/* 帧A：全空（front==back）→ 0 字节（含清脏） */
	OK(tui_renderer_flush(r, -1, -1) == 0, "flush-blank-no-redraw");
	ok_bytes("flush-blank-bytes", &m, "", 0);

	/* 帧B：行0 写 "Hi" → 只重绘行0 */
	sink_reset(&m);
	tui_screen_puts(tui_renderer_front(r), 0, 0, "Hi", d);
	OK(tui_renderer_flush(r, -1, -1) == 1, "flush-hi-one-row");
	OK_BYTES("flush-hi-bytes", &m, "\x1b[1;1HHi");

	/* 帧C：行1 写 "中" → 只重绘行1（双宽 3 字节） */
	sink_reset(&m);
	tui_screen_puts(tui_renderer_front(r), 1, 0, "\xe4\xb8\xad", d);
	OK(tui_renderer_flush(r, -1, -1) == 1, "flush-wide-one-row");
	OK_BYTES("flush-wide-bytes", &m, "\x1b[2;1H\xe4\xb8\xad");

	/* 帧D：行2 三段 SGR（红粗→默认→绿）最小切换 */
	sink_reset(&m);
	tui_screen_puts(tui_renderer_front(r), 2, 0, "X",
			A_FG(1, TUI_ST_BOLD));
	tui_screen_puts(tui_renderer_front(r), 2, 1, "Y", d);
	tui_screen_puts(tui_renderer_front(r), 2, 2, "Z", A_FG(2, 0));
	OK(tui_renderer_flush(r, -1, -1) == 1, "flush-sgr-one-row");
	OK_BYTES("flush-sgr-bytes", &m,
		 "\x1b[3;1H\x1b[1;38;5;1mX\x1b[0mY\x1b[38;5;2mZ");

	/* 无变化再 flush → 0 字节 */
	sink_reset(&m);
	OK(tui_renderer_flush(r, -1, -1) == 0, "flush-no-change-zero");
	ok_bytes("flush-no-change-bytes", &m, "", 0);

	/* 光标管理：目标与已知位不同 → 尾部 CUP；相同 → 0 字节 */
	sink_reset(&m);
	OK(tui_renderer_flush(r, 3, 4) == 0, "flush-cursor-no-redraw");
	OK_BYTES("flush-cursor-bytes", &m, "\x1b[4;5H");
	sink_reset(&m);
	OK(tui_renderer_flush(r, 3, 4) == 0, "flush-cursor-same-zero");
	ok_bytes("flush-cursor-same-bytes", &m, "", 0);

	/* 只有行2 变化 → 输出只含行2（SGR 从上帧绿态收回默认 → 39） */
	sink_reset(&m);
	tui_screen_puts(tui_renderer_front(r), 2, 5, "!", d);
	OK(tui_renderer_flush(r, -1, -1) == 1, "flush-row2-only");
	OK_BYTES("flush-row2-only-bytes", &m, "\x1b[3;6H\x1b[39m!");

	/* 组合符渲染字节 */
	sink_reset(&m);
	tui_screen_puts(tui_renderer_front(r), 3, 0, "e\xcc\x81", d);
	OK(tui_renderer_flush(r, -1, -1) == 1, "flush-combining");
	OK_BYTES("flush-combining-bytes", &m, "\x1b[4;1He\xcc\x81");

	/* clear：前缓冲同步清空 → 只有清屏序列，无行重绘 */
	sink_reset(&m);
	tui_screen_fill(tui_renderer_front(r), d);
	tui_renderer_clear(r);
	OK(tui_renderer_flush(r, -1, -1) == 0, "flush-clear-no-redraw");
	OK_BYTES("flush-clear-bytes", &m, "\x1b[0m\x1b[2J\x1b[H");

	/* resize：前后缓冲重建空白 + need_clear → 只有清屏序列 */
	sink_reset(&m);
	tui_renderer_resize(r, 2, 6);
	OK(tui_renderer_flush(r, -1, -1) == 0, "flush-resize-no-redraw");
	OK_BYTES("flush-resize-bytes", &m, "\x1b[0m\x1b[2J\x1b[H");
	OK(r->front->rows == 2 && r->front->cols == 6, "resize-dims");

	/* resize 后写入正常重绘（新几何） */
	sink_reset(&m);
	tui_screen_puts(tui_renderer_front(r), 1, 0, "ok", d);
	OK(tui_renderer_flush(r, -1, -1) == 1, "flush-post-resize");
	OK_BYTES("flush-post-resize-bytes", &m, "\x1b[2;1Hok");

	tui_renderer_destroy(r);
}

/* ---- 宽/窄替换的 span diff ---- */

static void test_span_diff(void)
{
	struct memsink m;
	tui_renderer *r;
	tui_attr d = tui_attr_default();

	memset(&m, 0, sizeof(m));
	r = tui_renderer_create(1, 8, (tui_sink){ memsink_fn, &m });
	if (!r)
		return;

	/* 行写 "abcd" */
	tui_screen_puts(tui_renderer_front(r), 0, 0, "abcd", d);
	tui_renderer_flush(r, -1, -1);

	/* 只改 col2 → span 只有 1 列 */
	sink_reset(&m);
	tui_screen_puts(tui_renderer_front(r), 0, 2, "X", d);
	OK(tui_renderer_flush(r, -1, -1) == 1, "span-one-col");
	OK_BYTES("span-one-col-bytes", &m, "\x1b[1;3HX");

	/* 宽字盖窄对：中 盖 "ab"（cols0-1）→ span=2 列、3 字节 */
	sink_reset(&m);
	tui_screen_puts(tui_renderer_front(r), 0, 0, "\xe4\xb8\xad", d);
	OK(tui_renderer_flush(r, -1, -1) == 1, "span-wide-replace");
	OK_BYTES("span-wide-replace-bytes", &m, "\x1b[1;1H\xe4\xb8\xad");

	/* 宽字行内单格变化：中→文（base 变、cont 属性同）→ 3 字节 */
	sink_reset(&m);
	tui_screen_puts(tui_renderer_front(r), 0, 0, "\xe6\x96\x87", d);
	OK(tui_renderer_flush(r, -1, -1) == 1, "span-wide-swap");
	OK_BYTES("span-wide-swap-bytes", &m, "\x1b[1;1H\xe6\x96\x87");

	tui_renderer_destroy(r);
}

/* ---- 滚动视口原语 ---- */

static void test_scrollback(void)
{
	tui_scrollback sb;
	tui_cell line;
	int i;

	tui_sb_init(&sb, 5, 2);	/* 容量5，视口2行 */
	OK(sb.cap == 5 && sb.rows == 2, "sb-init");
	OK(tui_sb_at_bottom(&sb), "sb-init-follow");

	for (i = 0; i < 5; i++) {
		memset(&line, 0, sizeof(line));
		line.utf8[0] = (uint8_t)('0' + i);
		line.len = 1;
		line.width = 1;
		line.attr = tui_attr_default();
		tui_sb_push(&sb, &line, 1);
	}
	OK(tui_sb_count(&sb) == 5, "sb-count-5");
	OK(tui_sb_dropped(&sb) == 0, "sb-no-drop");
	/* follow：视口贴底 → view_top = 5-2 = 3 */
	OK(tui_sb_top(&sb) == 3, "sb-follow-top3");
	OK(tui_sb_view_index(&sb, 0) == 3 && tui_sb_view_index(&sb, 1) == 4,
	   "sb-view-lines");
	OK(tui_sb_line(&sb, 3)->cells[0].utf8[0] == '3', "sb-line-content");
	OK(tui_sb_line(&sb, 0)->cells[0].utf8[0] == '0', "sb-line-first-exists");

	/* push 第6行 → 挤掉最旧，follow 保持贴底 */
	memset(&line, 0, sizeof(line));
	line.utf8[0] = '5';
	line.len = 1;
	line.width = 1;
	line.attr = tui_attr_default();
	tui_sb_push(&sb, &line, 1);
	OK(tui_sb_count(&sb) == 5 && tui_sb_dropped(&sb) == 1, "sb-evict");
	OK(tui_sb_top(&sb) == 4, "sb-follow-top4");
	OK(tui_sb_line(&sb, 0) == NULL, "sb-line-evicted-null");
	OK(tui_sb_line(&sb, 1)->cells[0].utf8[0] == '1' &&
	   tui_sb_line(&sb, 5)->cells[0].utf8[0] == '5', "sb-range");

	/* 上滚 2 行 → 离底，follow 关 */
	tui_sb_scroll(&sb, 2);
	OK(tui_sb_top(&sb) == 2, "sb-scroll-up");
	OK(!tui_sb_at_bottom(&sb), "sb-not-bottom");

	/* 过量上滚 → 钳到最旧可见 */
	tui_sb_scroll(&sb, 100);
	OK(tui_sb_top(&sb) == 1, "sb-clamp-lo");
	OK(!tui_sb_at_bottom(&sb), "sb-clamp-lo-not-bottom");

	/* 下滚回底 → follow 恢复 */
	tui_sb_scroll(&sb, -100);
	OK(tui_sb_top(&sb) == 4, "sb-clamp-hi");
	OK(tui_sb_at_bottom(&sb), "sb-restore-follow");

	/* jump-to-latest */
	tui_sb_scroll(&sb, 1);
	tui_sb_jump_latest(&sb);
	OK(tui_sb_top(&sb) == 4 && tui_sb_at_bottom(&sb), "sb-jump-latest");

	/* 视口高于内容 → 越内容行返回 -1（留白） */
	{
		tui_scrollback sb2;
		tui_sb_init(&sb2, 3, 4);
		memset(&line, 0, sizeof(line));
		line.utf8[0] = 'x';
		line.len = 1;
		line.width = 1;
		line.attr = tui_attr_default();
		tui_sb_push(&sb2, &line, 1);
		OK(tui_sb_view_index(&sb2, 0) == 0, "sb2-view0");
		OK(tui_sb_view_index(&sb2, 1) == -1, "sb2-view-beyond");
		tui_sb_destroy(&sb2);
	}

	tui_sb_destroy(&sb);
	OK(sb.ring == NULL, "sb-destroy");
}

/* ---- 调色板默认值 ---- */

static void test_theme(void)
{
	tui_theme th;

	tui_theme_default(&th);
	OK(tui_theme_get(&th, TUI_THEME_FG).kind == TUI_COLOR_INDEXED,
	   "theme-fg-indexed");
	OK(tui_theme_get(&th, TUI_THEME_ERROR).idx == 203, "theme-error-203");
	tui_theme_set(&th, TUI_THEME_ACCENT, tui_color_idx(42));
	OK(tui_theme_get(&th, TUI_THEME_ACCENT).idx == 42, "theme-set");
	OK(tui_theme_get(&th, (tui_theme_slot)999).kind == TUI_COLOR_DEFAULT,
	   "theme-oob-default");
}

int main(void)
{
	test_sgr();
	test_screen_struct();
	test_flush_golden();
	test_span_diff();
	test_scrollback();
	test_theme();
	printf("test_render: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
