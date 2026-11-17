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
#define TUI_ST_INVERSE   0x0010u	/* P-42：SGR 7 反色——fbterm 等
					 * 256 色背景不可靠终端上仍确定
					 * 可见的选中态原语 */

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
#define TUI_CELL_MAX 32		/* 一个 grapheme 的 UTF-8 字节上限
					 * （基字符≤4 + 组合符/ZWJ 序列追加；
					 * B7：16→32——家庭 emoji+肤色修饰最长
					 * ~30B；超出仍丢弃（对齐不撕行）） */

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

/* 缓冲硬上限（P-41/P-44）：一帧全量重绘上限为几十 KB 量级，512KB 已是
 * 「消费端停摆 + 缓冲无限涨」的异常态——超限按消费失败处理（drain -1，
 * 进程退出自愈），防失控内存。 */
#define TUI_SINK_BUF_MAX (512 * 1024)

typedef struct {
	tui_sink_fn fn;
	void *ctx;
	/* P-41/P-44 缓冲模式（buf_mode=1）：fn 只追加进 buf，drain 一次
	 * 排空——一帧=一个有序完整批次（整帧原子刷）。直写模式
	 * （buf_mode=0：tui_sink_init_fd/内存汇）语义零变化。 */
	int buf_mode;
	int fd;			/* 缓冲模式的目标 fd */
	int fd_flags_saved;	/* init_fd_buf 前原 flags（set_blocking 还原） */
	int wd_ms;		/* drain 总时限；0=禁用（无限等=旧直写语义） */
	int wd_fired;		/* 看门狗已触发（粘性：后续 drain 立返 -2） */
	int ovf;		/* 追加超硬上限/OOM（粘性；drain 按消费失败 -1） */
	char *buf;
	size_t blen, bcap;	/* 已积字节数/缓冲容量 */
	long stats_writes;	/* drain 内实际 write(2) 次数（测试断言用） */
	long stats_drains;	/* 成功 drain 次数（测试断言用） */
} tui_sink;

void tui_sink_init_fd(tui_sink *s, int fd);	/* write(2)，EINTR/短写重试 */
/*
 * P-41/P-44：fd 缓冲汇——fd 置 O_NONBLOCK（保存原 flags），缓冲 64KB 起
 * 可增长（硬上限 TUI_SINK_BUF_MAX）。看门狗时限取 env OCC_TUI_WD_MS
 * （缺省 15000；0=禁用）。成功 0；fd 坏/分配失败 -1（已回滚零残留）。
 * 注意：ctx 自指本结构——经 tui_renderer_create 值传入后由其修正指向
 * renderer 自家副本（权威副本唯一：view 的 term.bsink 也应指它）。
 */
int tui_sink_init_fd_buf(tui_sink *s, int fd);
/*
 * 排空缓冲：poll(POLLOUT, ≤200ms 片)+write 循环，总时限 wd_ms（每次
 * poll 前核对已耗累计；wd_ms=0 则无限等=旧直写语义）。
 *   0=排空成功（stats_drains++/stats_writes 累加实际 write 次数）；
 *  -2=看门狗超时（wd_fired=1 粘性；丢弃未排空缓冲——楔死终端上保序
 *      无意义，重启后 need_clear 全量重同步）；
 *  -1=EPIPE/EBADF/EIO 等 IO 错或超缓冲硬上限（消费端已死，同样丢缓冲）。
 */
int tui_sink_drain(tui_sink *s);
/* 还原 init_fd_buf 保存的 fd flags（幂等；term_leave 与 /shell fork 前
 * 调——bash 继承非阻塞 tty 会读异常） */
void tui_sink_set_blocking(tui_sink *s);
/* 释放缓冲（幂等；tui_renderer_destroy 对自家 sink 调用） */
void tui_sink_fini(tui_sink *s);

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
 * P-41/P-44 返回值扩展：sink 为缓冲模式时本函数尾部一次 drain（整帧
 * 字节一个有序批次）；drain 看门狗超时 → 返回 -2，IO 错 → -1（调用方
 * 退出自愈，见 tui_view_run/tui_gate）。
 */
int tui_renderer_flush(tui_renderer *r, int cur_row, int cur_col);
/*
 * P-41/P-44c 体量心跳：一拍 TUI_HB_BULK 字节的 "\x1b[m"（SGR 复位）
 * 重复 + 尾随一条 default→cur_attr 重放，一次 drain 收口。
 *
 * 为什么体量（真机 SIGSTOP fbterm 实证）：8 字节 CUP 探针会被 64KB
 * pty 缓冲照单吞下——write 成功≠被消费，drain 只在缓冲满时才计时，
 * 空闲态小探针填满要 11 小时；56KB 一拍则楔死端第二拍即 EAGAIN→
 * 看门狗（检出上界 ≈2×HB+WD，通用任何不消费态）。健康端毫秒级吃
 * 掉无感。TIOCOUTQ 不可用（pty 从端恒 0——数据即刻转入主端读队列，
 * 从端看不到消费进度）。
 *
 * 为什么 "\x1b[m"：属性复位幂等（连续 reset=仍 default）且无字形
 * 输出=零视觉；无数字参数——P-41 崩溃点在 fbterm 数字解析路径，
 * 空参数走不同分支，避开饲喂面。
 *
 * 为什么尾随 cur_attr 重放（选重放而非依赖下帧兜底）：bulk 把终端
 * SGR 清回 default，而 renderer 记忆的 cur_attr 可能非默认——不重放
 * 则下一帧首段「cell attr==stale cur_attr → 不发 SGR」或增量转移
 * 都会错色，直到某次全量复位才对齐；重放 3~30 字节让终端状态与
 * 跟踪完全一致，帧间任何属性段渲染正确。
 *
 * 串口径：56KB@115200≈4.8s/拍 < wd 缺省 15s——drain 的 poll 等它
 * 排完（POLLOUT 随 uart 排空恢复），勿把 wd 配小于排空时间。
 * 返回 drain 结果（0/-1/-2）；wd/ovf 粘性时不再发字节、如实返回；
 * 直写模式无看门狗（旧语义）直写返 0。bulk 块进程内生成一次复用。
 */
#define TUI_HB_BULK (3 * 19148)		/* 57444≈56KB：19148 × "\x1b[m"。
					 * 必须整除 3（块内全是三字节
					 * 重复，无填充尾巴） */
int tui_renderer_heartbeat(tui_renderer *r);
/*
 * P-41/P-44d 输出致命自退前击毙父进程（真楔死 fbterm 卡在 evdev
 * 循环不读 pty：occ 退出关 slave 它也看不到 EOF——aik-console 的
 * wait 永挂、链条不自愈）。双重目的：
 *   ① 强制楔死消费端退出（fbterm 死 → pty 释放 → aik-console 重启
 *      整链）；
 *   ② 退出码出带外传递：fbterm 转手吞退出码（occ exit(72) → fbterm
 *      以 0 退出——P-47「/exit rc=0 非 71」谜底）；击毙后 shell 报
 *      143 = aik-console v7 的 occ-wd 线索位。
 * 门卫：FBTERM env 只在 aik-console 的 fb 分支设置（serial/ssh 场景
 * 无此 env → 不误杀 sshd/shell）；只在 wd/IO 致命收口调用（单点、
 * 恰一次——多处调用有 ppid 复用误杀风险），正常退出零动作。
 */
void tui_out_fatal_kill_parent(void);

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
	int mouse_on;		/* B5：鼠标模式已开（leave 时补关——幂等） */
	/* P-41/P-44：可选缓冲汇（缺省 NULL=原直写）。非空时
	 * tui_term_write/光标显隐/鼠标序列改走它（fn 追加）——渲染过程中
	 * 的光标/鼠标序列与帧同批，不破坏帧原子性。指向的 sink 必须比本
	 * term 活得久（view 里=renderer 自家副本）。tui_term_leave 尾部对
	 * 它先 drain+set_blocking 再发恢复序列（wd 已触发则跳过恢复字节
	 * ——楔死终端上阻塞 write 会挂死收尾链）。 */
	tui_sink *bsink;
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

/*
 * B5 鼠标开关：on=1 发 CSI ? 1000;1006 h（正常追踪 + SGR 编码；终端
 * 无 1006 时回落 X10 三字节报告——解析器两编码并存）；on=0 发复位。
 * 诚实降级：未进全屏 / 非 tty / TERM 缺失/dumb（无鼠标能力信号）→ -1，
 * 不发任何字节、不置 mouse_on（调用方 /help 按此如实展示）。成功 0。
 * 重复同向调用幂等（不发字节）；tui_term_leave 对 mouse_on 补发复位
 * （含信号/atexit 异常路径），未开鼠标时 leave 字节流与 B5 前逐字节一致。
 */
int tui_mouse_enable(tui_term *t, int on);
/* 查询 mouse_on（帮助文案不撒谎用） */
int tui_mouse_active(const tui_term *t);

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_CORE_H */
