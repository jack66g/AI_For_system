/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_core.h - occ_tui 终端控制 + 屏幕缓冲 + 脏行渲染（T9c1）
 *
 * 职责（PLAN §4.1 原语级）：
 *   - 模式管理：alternate screen 进出（atexit+信号双保险恢复）、
 *     raw 模式（termios 关 ECHO/ICANON/ISIG——ISIG 取舍见 tui_core.c 头注）、
 *     光标隐藏/恢复、无 TTY 拒绝（rc=2 人话报错）。
 *   - 缓冲渲染：cell 行缓冲（grapheme 宽度占位）、脏行增量重绘
 *     （front/back 双缓冲逐行 diff，SGR 最小化切换）、
 *     滚动视口原语（scrollback 环形缓冲+视口+follow-latest 位）。
 *   - 颜色：SGR 生成器（256 色+默认、样式位）；调色板=数据结构，
 *     主题文件加载归 c3，本棒只做渲染 API。
 *
 * 视图/聊天渲染/主题加载不属本棒（c2/c3）。
 */
#ifndef OCC_TUI_CORE_H
#define OCC_TUI_CORE_H

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <termios.h>

#include "tui_utf8.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TUI_ERR_UNSUPPORTED (-2)	/* 留 API 未实现（如鼠标） */

/* ---- 颜色与样式 ---- */
#define TUI_COLOR_DEFAULT 0
#define TUI_COLOR_INDEXED 1

typedef struct {
	uint8_t kind;		/* TUI_COLOR_DEFAULT / TUI_COLOR_INDEXED */
	uint8_t idx;		/* kind==INDEXED 时 0..255 */
} tui_color;

#define TUI_ST_BOLD      0x0001u
#define TUI_ST_DIM       0x0002u
#define TUI_ST_ITALIC    0x0004u
#define TUI_ST_UNDERLINE 0x0008u

typedef struct {
	tui_color fg, bg;
	uint16_t style;		/* TUI_ST_* 位或 */
} tui_attr;

tui_color tui_color_idx(int idx);	/* 256 色索引色 */
tui_color tui_color_default(void);
tui_attr tui_attr_default(void);
int tui_attr_eq(const tui_attr *a, const tui_attr *b);

/*
 * SGR 生成器：从 cur 切到 want 的最短转义序列写入 buf（含 ESC[...m）。
 * 规则：需清除样式位 → 先 ESC[0 再重建；否则只发增量（新增样式位/
 * 变化的 fg/bg）。cur==want → 返回 0。返回写入字节数（0 或 >0，
 * cap 不足返回 0）。buf 至少 64 字节。
 */
size_t tui_sgr_transition(const tui_attr *cur, const tui_attr *want,
			  char *buf, size_t cap);
/* ESC[0m 复位序列（4 字节），写入 buf 返回 4；cap<4 返回 0 */
size_t tui_sgr_reset(char *buf, size_t cap);

/* ---- 单元格与屏幕缓冲 ---- */
#define TUI_CELL_MAX 16		/* 一个 grapheme 的 UTF-8 字节上限
				 * （基字符≤4 + 组合符追加） */

typedef struct {
	uint8_t utf8[TUI_CELL_MAX];
	uint8_t len;		/* 字节数（>=1） */
	uint8_t width;		/* 显示列数：1/2；0=宽字续格 */
	tui_attr attr;
} tui_cell;

typedef struct tui_screen {
	int rows, cols;
	tui_cell *cells;	/* rows*cols，行优先；列下标==终端列 */
	uint8_t *dirty;		/* 每行脏位 */
} tui_screen;

tui_screen *tui_screen_create(int rows, int cols);
void tui_screen_destroy(tui_screen *s);
/*
 * 尺寸变更：重建为空白缓冲（新格=默认属性空格），全行标脏。
 * 终端侧重排不可知——调用方（c2）随后整体重绘；配合
 * tui_renderer_clear 在下一帧发 ESC[2J（语义见 tui_renderer_resize）。
 */
void tui_screen_resize(tui_screen *s, int rows, int cols);
void tui_screen_fill(tui_screen *s, tui_attr a);	/* 空格填充+全脏 */
void tui_screen_mark_dirty(tui_screen *s, int row);
tui_cell *tui_screen_at(tui_screen *s, int row, int col);	/* 越界 NULL */

/*
 * 在 (row,col) 写入 UTF-8 串（grapheme 级）。
 *   - 逐 grapheme：基字符按宽度占位；零宽组合符追加进前一 grapheme
 *     （同 put 内跟随基字符，或跨 put 落到 col-1 的基字符；放不下则丢）。
 *     控制符（\n 等）跳过——分行归视图层。
 *   - 截断在 cell 边界：双宽字放不下剩余列即停止，绝不写半个汉字；
 *     落在续格上的写入先把左侧宽字主格降为空格再写（不撕左邻）。
 *   - 非法 UTF-8 → U+FFFD 单格；串尾截断序列 → 一个 U+FFFD。
 * 返回写后列号；row 越界返回 -1。
 */
int tui_screen_put(tui_screen *s, int row, int col,
		   const char *utf8, size_t len, tui_attr a);
int tui_screen_puts(tui_screen *s, int row, int col,
		    const char *utf8, tui_attr a);

/* ---- 输出汇（渲染字节去向；测试用内存汇做 golden 对拍） ---- */
typedef void (*tui_sink_fn)(void *ctx, const char *data, size_t len);
typedef struct {
	tui_sink_fn fn;
	void *ctx;
} tui_sink;

void tui_sink_init_fd(tui_sink *s, int fd);	/* write(2)，EINTR/短写重试 */

/* ---- 渲染器（front/back 双缓冲 + 脏行 diff + 光标跟踪） ---- */
typedef struct tui_renderer {
	tui_screen *front;	/* 应用绘制面 */
	tui_screen *back;	/* 终端当前画面（上次 flush 后） */
	tui_sink sink;
	tui_attr cur_attr;	/* 终端当前 SGR（我们最后发出的） */
	int cur_row, cur_col;	/* 已知终端光标位；-1=未知 */
	int need_clear;		/* resize/clear 后下一帧先发 ESC[2J */
} tui_renderer;

tui_renderer *tui_renderer_create(int rows, int cols, tui_sink sink);
void tui_renderer_destroy(tui_renderer *r);
tui_screen *tui_renderer_front(tui_renderer *r);
void tui_renderer_set_sink(tui_renderer *r, tui_sink sink);
/*
 * 尺寸变更：前后缓冲重建为空白，置 need_clear——下一 flush 先发
 * ESC[2J（终端重排不可知，全清后由调用方整体重绘）。
 */
void tui_renderer_resize(tui_renderer *r, int rows, int cols);
/* 请求下一帧全清（/clear 等）：置 need_clear */
void tui_renderer_clear(tui_renderer *r);

/*
 * 增量重绘：只 diff 脏行；变化行发 CUP+最短 SGR+内容；末尾按需把光标
 * 移到 (cur_row,cur_col)（<0=不管理光标）。返回本帧重绘行数。
 * 无脏行且光标未变 → 输出 0 字节。
 */
int tui_renderer_flush(tui_renderer *r, int cur_row, int cur_col);

/* ---- 滚动视口原语（scrollback 环 + 视口 + follow-latest） ----
 * 行=cell 数组（列下标==列）；环按 push 挤出最旧行（dropped 计数）。
 * 绝对行号：oldest=dropped，newest=dropped+count-1。
 * 视口 view_top=首可见绝对行；follow=1 时 push 自动贴底（Jump-to-latest
 * 的底层位）。OCD 尾 40 行挂载/60 回填是 c2 在此之上的渲染策略。 */
typedef struct {
	tui_cell *cells;
	int len;		/* cell 数 */
} tui_sline;

typedef struct {
	tui_sline *ring;
	int cap, head, count;	/* 环容量/写位/在环数 */
	int dropped;		/* 已挤掉行数（绝对偏移） */
	int view_top;		/* 视口首行绝对号 */
	int rows;		/* 视口高（行） */
	int follow;		/* follow-latest 位 */
} tui_scrollback;

void tui_sb_init(tui_scrollback *sb, int cap, int view_rows);
void tui_sb_destroy(tui_scrollback *sb);
void tui_sb_push(tui_scrollback *sb, const tui_cell *cells, int len);
const tui_sline *tui_sb_line(const tui_scrollback *sb, int abs_idx);
/* 视口第 i 行（0..rows-1）绝对号；越界/无内容返回 -1 */
int tui_sb_view_index(const tui_scrollback *sb, int i);
void tui_sb_scroll(tui_scrollback *sb, int lines); /* >0 向旧（上） */
void tui_sb_jump_latest(tui_scrollback *sb);
int tui_sb_at_bottom(const tui_scrollback *sb);
int tui_sb_top(const tui_scrollback *sb);
int tui_sb_count(const tui_scrollback *sb);
int tui_sb_dropped(const tui_scrollback *sb);

/* ---- 调色板（主题=数据；加载归 c3，本棒给结构+内置默认） ---- */
typedef enum {
	TUI_THEME_FG = 0, TUI_THEME_BG, TUI_THEME_MUTED, TUI_THEME_ACCENT,
	TUI_THEME_BORDER, TUI_THEME_ERROR, TUI_THEME_OK, TUI_THEME_WARN,
	TUI_THEME_USER_BG, TUI_THEME_ASSISTANT_BG,
	TUI_THEME_COUNT
} tui_theme_slot;

typedef struct {
	tui_color slot[TUI_THEME_COUNT];
} tui_theme;

void tui_theme_default(tui_theme *t);	/* 内置 256 色默认（非文件加载） */
tui_color tui_theme_get(const tui_theme *t, tui_theme_slot s);
void tui_theme_set(tui_theme *t, tui_theme_slot s, tui_color c);

/* ---- 终端模式管理 ---- */
typedef struct tui_term {
	int fd;
	struct termios saved;
	int entered;		/* 已进全屏 */
	int sigs_saved;		/* 旧信号处理已保存 */
	struct sigaction old_int, old_term, old_hup, old_winch;
} tui_term;

/* 记录 fd（通常 STDOUT_FILENO），不进入全屏 */
void tui_term_init(tui_term *t, int fd);
/*
 * 进入全屏：isatty 检查（非 tty → 人话报错 stderr + 返回 2，不动状态）；
 * raw 模式（关 ECHO/ICANON/ISIG/OPOST，取舍见 .c 头注）；alt screen；
 * 清屏；光标隐藏；bracketed paste 开；kitty 协议探测查询（CSI ? u）；
 * atexit+SIGINT/SIGTERM/SIGHUP 恢复双保险；SIGWINCH→只置 flag。
 * 成功 0；非 tty 2；系统调用失败 -1。
 */
int tui_term_enter(tui_term *t);
/* 恢复（幂等）：发恢复序列 + 还原 termios + 还原信号处理 */
void tui_term_leave(tui_term *t);
int tui_term_is_entered(const tui_term *t);
/* TIOCGWINSZ；失败 -1；得 0 行/列时替换 24x80 并返回 0 */
int tui_term_get_size(int fd, int *rows, int *cols);
void tui_term_hide_cursor(tui_term *t);
void tui_term_show_cursor(tui_term *t);
int tui_term_write(tui_term *t, const char *data, size_t len);

/* 鼠标：本棒不做，留 API（返回 TUI_ERR_UNSUPPORTED，c2/c3 后续接） */
int tui_mouse_enable(tui_term *t, int on);

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_CORE_H */
