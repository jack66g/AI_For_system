/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_input.h - occ_tui 键位解析：字节流 → 结构化键事件（T9c1）
 *
 * 覆盖（PLAN §4.1 / 对齐 OCD 键位表底层）：
 *   - 可打印字符（UTF-8 跨 feed 装配，非法→U+FFFD）
 *   - 控制键 Enter/Tab/Backspace/Esc；Ctrl+A..Z、Ctrl+符号
 *   - 方向/Home/End/PgUp/PgDn/Delete/Insert/F1-F12
 *   - ESC 序列状态机：CSI/SS3 解析、孤立 Esc 超时=裸 Esc 键
 *     （默认 25ms 可配）、OSC/DCS 吞噬、双 Esc 连发
 *   - kitty 键盘协议：探测回复（CSI ? n u）+ CSI-u 键形式；不支持的
 *     终端无回复 → 走 legacy 字节路径（优雅降级，两套解析并存）
 *   - bracketed paste（CSI 200~ / 201~，内容按 CHAR+paste 位回放）
 *   - 鼠标：本棒不做（解析器吞掉鼠标 CSI 不产事件；tui_mouse_enable
 *     留 API 返回 TUI_ERR_UNSUPPORTED）
 *
 * 事件 → keybind 字符串（tui_event_keystr）产出 OCD keymap 规范名
 * （ctrl+c / alt+f / shift+tab / return / escape / pageup ...），供 c2
 * 直接查 keybind 表（对接面见 T9C1-REPORT）。
 */
#ifndef OCC_TUI_INPUT_H
#define OCC_TUI_INPUT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 事件类型 ---- */
typedef enum {
	TUI_EV_KEY = 1,
	TUI_EV_PASTE_START,
	TUI_EV_PASTE_END,
	TUI_EV_KITTY_FLAGS	/* arg=kitty 键盘增强 flags（探测回复） */
} tui_ev_type;

/* ---- 键枚举（名字对齐 OCD keybind 规范名） ---- */
typedef enum {
	TUI_KEY_NONE = 0,
	TUI_KEY_CHAR,		/* ch=码点（Ctrl 字母亦走 CHAR+CTRL 位） */
	TUI_KEY_RETURN,		/* keybind 名 "return"（别名 enter） */
	TUI_KEY_TAB,
	TUI_KEY_BACKSPACE,
	TUI_KEY_ESCAPE,		/* keybind 名 "escape"（别名 esc） */
	TUI_KEY_UP, TUI_KEY_DOWN, TUI_KEY_LEFT, TUI_KEY_RIGHT,
	TUI_KEY_HOME, TUI_KEY_END,
	TUI_KEY_PAGEUP, TUI_KEY_PAGEDOWN,
	TUI_KEY_DELETE, TUI_KEY_INSERT,
	TUI_KEY_F1, TUI_KEY_F2, TUI_KEY_F3, TUI_KEY_F4,
	TUI_KEY_F5, TUI_KEY_F6, TUI_KEY_F7, TUI_KEY_F8,
	TUI_KEY_F9, TUI_KEY_F10, TUI_KEY_F11, TUI_KEY_F12
} tui_key;

/* ---- 修饰键位（keybind 组合串顺序：ctrl+ alt+ super+ shift+） ---- */
#define TUI_MOD_SHIFT 0x01u
#define TUI_MOD_ALT   0x02u
#define TUI_MOD_CTRL  0x04u
#define TUI_MOD_SUPER 0x08u

typedef struct {
	uint8_t type;		/* tui_ev_type */
	uint16_t key;		/* tui_key（type==TUI_EV_KEY） */
	uint32_t ch;		/* TUI_KEY_CHAR 时=码点；KITTY_FLAGS 时 flags */
	uint8_t mods;		/* TUI_MOD_* 位或 */
	uint8_t paste;		/* 1=位于 bracketed paste 内容中 */
} tui_event;

#define TUI_INPUT_QMAX 512

/* 解析器状态（暴露以便栈上静态分配；调用方勿直接改字段） */
typedef enum {
	TUI_ST_GROUND = 0,
	TUI_ST_ESC,		/* 已见 ESC，等下一字节/超时 */
	TUI_ST_CSI,
	TUI_ST_SS3,		/* ESC O x */
	TUI_ST_STR,		/* OSC/DCS/SOS/PM/APC 吞噬态 */
	TUI_ST_STR_ESC,		/* 串内见 ESC（等 \ 收尾 ST） */
	TUI_ST_PASTE,		/* bracketed paste 内容 */
	TUI_ST_MOUSE		/* 传统 X10 鼠标报告吞 3 字节（不产事件） */
} tui_inp_state;

typedef struct {
	uint8_t state;		/* tui_inp_state */
	/* CSI 收集 */
	uint8_t csi[48];
	uint8_t csi_len;
	uint8_t csi_ovf;	/* 超 48 字节：丢内容但吞到 final */
	uint8_t csi_priv;	/* '?','>','<','=' 或 0 */
	/* ESC/序列计时（超时结算裸 Esc；每续字节刷新） */
	uint64_t esc_t0;
	/* alt+键暂存（ESC+字节同轮消费，不跨 feed） */
	uint8_t alt_pending;
	/* STR 吞噬：BEL 是否可作终止（OSC=1，DCS/APC/PM/SOS=0）+长度上限 */
	uint8_t str_bel;
	uint16_t str_len;
	/* bracketed paste：终止符 "\x1b[201~" 前缀缓冲 */
	uint8_t pend[8];
	uint8_t pend_len;
	/* UTF-8 跨 feed 装配（含 alt/paste 上下文 + 慢速半截超时） */
	uint8_t u8[4];
	uint8_t u8_len;
	uint8_t u8_need;
	uint8_t u8_alt;
	uint8_t u8_paste;
	uint64_t u8_t0;
	uint8_t mouse_left;	/* MOUSE 态剩余吞字节数 */
	/* 事件队列（环） */
	tui_event q[TUI_INPUT_QMAX];
	int q_head, q_count;
	int dropped;		/* 队列溢出丢弃计数 */
	/* 配置/状态 */
	unsigned esc_timeout_ms;	/* 默认 25 */
} tui_input;

void tui_input_init(tui_input *in);
/* 孤立 Esc 超时（ms），默认 25（OCD kitty 探测容忍窗口，可配） */
void tui_input_set_esc_timeout(tui_input *in, unsigned ms);

/*
 * 喂字节（now_ms=单调毫秒，用于 Esc 超时判定）。返回本次入队事件数。
 * 跨调用保留半截 UTF-8 / 半截 CSI / 半截粘贴终止符。
 */
int tui_input_feed(tui_input *in, const void *data, size_t n, uint64_t now_ms);
/* 时间推进：结算孤立 Esc（及被放弃的 CSI/SS3 序列）。返回入队数。 */
int tui_input_tick(tui_input *in, uint64_t now_ms);
/* 取一个事件；1=取到，0=队列空 */
int tui_input_next(tui_input *in, tui_event *out);
int tui_input_pending(const tui_input *in);
/*
 * 距孤立 Esc 超时还剩多少 ms（供事件循环算 poll 超时）；
 * 无待结算 ESC 返回 -1。
 */
long tui_input_esc_deadline(const tui_input *in, uint64_t now_ms);

/* 键名（keybind 规范名）："return"/"escape"/"pageup"/"up"/"f5"... */
const char *tui_key_name(uint16_t key);
/*
 * 事件 → keybind 字符串（规范名+修饰前缀，顺序 ctrl+ alt+ super+ shift+）：
 *   ctrl+c / alt+f / shift+tab / ctrl+shift+a / return / escape /
 *   pageup / f2 / a / 中 / space（CHAR ' '）
 * 非键事件返回 "paste-start"/"paste-end"/"kitty-flags"。
 * 返回写入长度（不含 NUL）；cap 不足返回 -1。
 */
int tui_event_keystr(const tui_event *ev, char *buf, size_t cap);

/* ---- kitty 键盘协议辅助（探测回复由解析器产 KITTY_FLAGS 事件；
 *      是否启用由 c2 决定——本棒提供序列生成，优雅降级=不发/无回复） ---- */
/* CSI > flags u（push）；返回字节数，cap 不足 -1 */
int tui_kitty_push_seq(char *buf, size_t cap, uint32_t flags);
/* CSI < u（pop）；返回字节数，cap 不足 -1 */
int tui_kitty_pop_seq(char *buf, size_t cap);

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_INPUT_H */
