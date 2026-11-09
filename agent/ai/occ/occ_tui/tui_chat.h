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

tui_chat *tui_chat_create(const tui_theme *th);
void tui_chat_destroy(tui_chat *c);

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
/* 终端尺寸变化：按新宽度全量重建 scrollback 并跳回底部 */
void tui_chat_rewidth(tui_chat *c, int width);

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

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_CHAT_H */
