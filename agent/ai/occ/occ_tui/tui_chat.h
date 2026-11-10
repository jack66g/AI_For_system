/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_chat.h - occ TUI 转写区：消息模型 + markdown-lite 渲染（T9c2）
 *
 * 结构（双段——T9C2-PROGRESS 设计裁定 4）：
 *   - 已定稿消息（user/notice/error/收口的 assistant）→ 渲染成 cells 行
 *     推入 tui_scrollback（c1 视口原语：follow-latest=贴底、PgUp=视口上移、
 *     dropped=回填极限——OCD「尾 40 挂载/60 回填」的 C 等价）；
 *   - 当前流式 live assistant 块（reasoning 折叠行 + 文本 span + 工具行
 *     交错）每帧从逻辑模型重渲，钉在转写区底部。
 * resize 时全量重建 scrollback（消息原文保留，按新宽度重排）。
 *
 * markdown-lite 范围（取舍如实，见 T9C2-REPORT）：代码块围栏（``` 状态机
 * + 行级 naive 语法色：关键字词表/字符串/注释/数字）、行内 `code`、
 * 双星号加粗、列表（减号/星号前缀 → •）、引用（> dim 斜体）、# 标题
 * （bold accent）、空格回绕（CJK 按宽度硬断）。不做：表格/链接渲染
 * （原文保留）、跨行 emphasis、嵌套列表、CommonMark 合规。
 */
#ifndef OCC_TUI_CHAT_H
#define OCC_TUI_CHAT_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "tui_core.h"
#include "tui_theme.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tui_chat tui_chat;

/* T2：scrollback 环容量（tui_chat_create / chat_rebuild / clear 同口径；
 * occ 侧「已到内存上限」门用 CAP-512 作渲染行停止线）。
 * 内存闸口径（L1 实测）：sizeof(tui_cell)=40B、sizeof(tui_sline)=16B；
 * tui_sb_push 按行实际长精确 malloc（无 2 次幂放大），80 列满行
 * = 80*40+16 = 3216B → 5000 行 = 15.3MiB ≤ 16MiB 预算。更宽列（>80）
 * 单行更贵，属已知边界。 */
#define TUI_CHAT_SB_CAP 5000

tui_chat *tui_chat_create(const tui_theme *th);
void tui_chat_destroy(tui_chat *c);

/* UXAB：assistant 块头标签（`◆ <label> · HH:MM`；缺省 "occ"）。
 * occ.c 在模型解析/切换后设为当前模型名 */
void tui_chat_set_assist_label(tui_chat *c, const char *label);

/* ---- 模型更新（主线程；sink 事件经 view queue 派发后调用） ---- */

/* user 消息：立即渲染定稿推进 scrollback */
void tui_chat_add_user(tui_chat *c, const char *text, size_t len);
/* 系统通告行（dim）/错误行（red）：立即定稿 */
void tui_chat_add_notice(tui_chat *c, const char *text);
void tui_chat_add_error(tui_chat *c, const char *text);
/* assistant live 块（turn 开始） */
void tui_chat_begin_assistant(tui_chat *c);
void tui_chat_append_text(tui_chat *c, const char *s, size_t len);
void tui_chat_append_reasoning(tui_chat *c, const char *s, size_t len);
/* 工具行：start=spinner 行出现；end=按名匹配首个 running 行置 ✓/✗ */
void tui_chat_tool_start(tui_chat *c, const char *name, const char *args);
void tui_chat_tool_end(tui_chat *c, const char *name, const char *summary,
		       int rc);
/* 传输重试（OCC_SINK_RESET）：截断 live 文本/思维链到本轮起点（此前
 * 轮次内容与工具行保留——与 loop 收集器清空语义对齐） */
void tui_chat_reset_live(tui_chat *c);
/* turn 收口：渲染 footer 行，live 块整体定稿推进 scrollback；无内容则丢弃 */
void tui_chat_end_assistant(tui_chat *c, const char *footer);
/* /clear：清空消息与 scrollback */
void tui_chat_clear(tui_chat *c);

/* ---- 渲染与视口 ---- */

/* 把转写区 [x,y,w,h] 画进 screen：scrollback 视口（h-live_h 行）+ live
 * 尾部（live_h 行，超高中仅显示尾部）。now_ms 驱动 spinner 帧。 */
void tui_chat_render(tui_chat *c, tui_screen *s, int x, int y, int w, int h,
		     uint64_t now_ms);
/* 滚动（>0 向旧；到达底部自动恢复 follow）。lines 可为页长/半页。 */
void tui_chat_scroll(tui_chat *c, int lines);
void tui_chat_jump_latest(tui_chat *c);
int tui_chat_at_bottom(const tui_chat *c);

/* T1：滚动指标（视图画滚动条用；render 之后取值才有本帧几何）。
 * total=环内在行数；rows=上帧 scrollback 视口行数；top=视口首行绝对号；
 * lo=最旧可及绝对行（dropped）；hi=贴底时视口首行绝对号；follow=贴底位。
 * 返回 0=有效，-1=c/out 空。 */
struct tui_chat_scrollinfo {
	int total;
	int rows;
	int top;
	int lo;
	int hi;
	int follow;
};
int tui_chat_scroll_info(const tui_chat *c, struct tui_chat_scrollinfo *out);
/* 终端尺寸变化：按新宽度全量重建 scrollback 并跳回底部 */
void tui_chat_rewidth(tui_chat *c, int width);

/* ---- T2：长历史滚动锚点（增量加载更早历史时保持视口不跳） ----
 * 每条定稿消息块在 scrollback 有 first_line（块区域首行，含块前空行）；
 * 消息 id 由内容（role/文本/思维链/工具行/footer）哈希而来——回放重放
 * 同一历史消息得到同一 id，故锚点可跨「清空 + 更大预算重放」还原。 */

/* 视口是否已顶到最旧行（空转写区返回 0——不触发加载） */
int tui_chat_at_top(const tui_chat *c);
/* 取当前视口顶的锚：msg_id（写入 id，cap 至少 17）/ line_off=top-
 * first_line（可负——视口顶在首条对话块之上）。只锚 user/assistant 块；
 * 返回 0=有效，-1=无对话块/参数坏。 */
int tui_chat_top_anchor(const tui_chat *c, char *msg_id, size_t cap,
			int *line_off);
/* 定位到该消息块 + 行偏移（view_top=first_line+line_off，钳位；
 * follow 按钳位后位置恢复）。返回 0=定位成功；-1=锚点丢失。 */
int tui_chat_scroll_to_msg(tui_chat *c, const char *msg_id, int line_off);
/* O-14：notice-only（无 user/assistant/live）时返回 scrollback 已占行数
 * ——空态面板画在其下、不重叠；有对话内容返回 0。 */
int tui_chat_notice_lines(const tui_chat *c);

/* ---- B5：推理折叠区点击展开/收起 ----
 * row=转写区域内相对行（0..h-1，tui_chat_render 的 y 偏移已扣除）。
 * 命中 live 块或定稿消息的 ✻ 折叠行 → 切换展开态（定稿消息切换后
 * 重建 scrollback，尽量保视口位置；底部 follow 保持贴底）。
 * 返回 1=命中并切换；0=未命中。仅对带 reasoning 的 assistant 块有效。 */
int tui_chat_click(tui_chat *c, int row);
/* 上次 render 后 live 折叠行是否可见（诊断/测试断言）；-1=不可见 */
int tui_chat_fold_row(const tui_chat *c);

/* ---- 单测观察口（golden 断言用） ---- */

/* 把消息文本（含 live）拼进 buf（调试/断言）；返回写入字节数 */
size_t tui_chat_dump_text(const tui_chat *c, char *buf, size_t cap);
/* live 块是否为空（无 text/reasoning/tool） */
int tui_chat_live_empty(const tui_chat *c);
/* T1：转写区是否全空（无任何消息，且无 live 块）——空态面板判定 */
int tui_chat_is_empty(const tui_chat *c);

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_CHAT_H */
