/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_input.c - 键位解析状态机：字节流 → 结构化键事件（T9c1）
 *
 * 状态机：GROUND / ESC / CSI / SS3 / STR(OSC..) / PASTE / MOUSE(X10 吞 3B)
 *   - 孤立 Esc 超时（默认 25ms，可配）→ 裸 ESC 键；新字节到达同样先结算。
 *   - ESC+字节（超时内）= Alt+键；ESC+ESC = 双 Esc（第一下立即成键，
 *     第二下待超时）——OCD Esc 双击中断的底层。
 *   - 半截 CSI/SS3/STR 超时 → 静默丢弃（多为终端回复；裸 ESC 才成键）。
 *   - kitty：探测回复 CSI ? <flags> u → KITTY_FLAGS 事件；CSI-u 键形式
 *     （CSI <cp>;<mods> u、CSI 27;mod;cp ~）全解析——探测不到时终端只走
 *     legacy 字节，解析器两套并存即优雅降级。
 *   - bracketed paste：CSI 200~ → PASTE 态，终止符 "\x1b[201~" 字节级
 *     匹配（可跨 feed），内容按 CHAR+paste=1 回放（控制字节也当字面量）。
 *   - 鼠标（B5）：SGR（CSI < cb;cx;cy M/m）全量——press/release/motion/
 *     wheel + 修饰位（cb 位 4/8/16=shift/alt/ctrl）+1 基坐标；X10 兼容
 *     （CSI M + 3 原始字节）——无 release、坐标-32、按钮位同 SGR 低 2 位
 *     +位 6/7（64/128）=wheel。两编码并存：终端开 1000 无 1006 时回 X10。
 */
#include "tui_input.h"

#include "tui_utf8.h"

#include <stdio.h>
#include <string.h>

#define CSI_MAX 64
#define STR_MAX 4096

void tui_input_init(tui_input *in)
{
	memset(in, 0, sizeof(*in));
	in->esc_timeout_ms = 25;
}

void tui_input_set_esc_timeout(tui_input *in, unsigned ms)
{
	in->esc_timeout_ms = ms ? ms : 25;
}

/* ---- 事件队列（环） ---- */

static tui_event *q_push(tui_input *in)
{
	tui_event *e;
	if (in->q_count >= TUI_INPUT_QMAX) {
		in->dropped++;
		return NULL;
	}
	e = &in->q[(in->q_head + in->q_count) % TUI_INPUT_QMAX];
	in->q_count++;
	return e;
}

static int push_key(tui_input *in, uint16_t key, uint32_t ch, uint8_t mods,
		    uint8_t paste)
{
	tui_event *e = q_push(in);
	if (!e)
		return 0;
	e->type = TUI_EV_KEY;
	e->key = key;
	e->ch = ch;
	e->mods = mods;
	e->paste = paste;
	e->mx = 0;
	e->my = 0;
	return 1;
}

static int push_ev(tui_input *in, uint8_t type, uint32_t ch)
{
	tui_event *e = q_push(in);
	if (!e)
		return 0;
	e->type = type;
	e->key = 0;
	e->ch = ch;
	e->mods = 0;
	e->paste = 0;
	e->mx = 0;
	e->my = 0;
	return 1;
}

/* B5：鼠标事件（key=动作、ch=按钮、mods、mx/my 1 基） */
static int push_mouse(tui_input *in, uint16_t act, uint32_t btn, uint8_t mods,
		      int x, int y)
{
	tui_event *e = q_push(in);
	if (!e)
		return 0;
	e->type = TUI_EV_MOUSE;
	e->key = act;
	e->ch = btn;
	e->mods = mods;
	e->paste = 0;
	e->mx = (uint16_t)(x > 0 ? x : 1);
	e->my = (uint16_t)(y > 0 ? y : 1);
	return 1;
}

int tui_input_next(tui_input *in, tui_event *out)
{
	if (!in || in->q_count == 0)
		return 0;
	*out = in->q[in->q_head];
	in->q_head = (in->q_head + 1) % TUI_INPUT_QMAX;
	in->q_count--;
	return 1;
}

int tui_input_pending(const tui_input *in)
{
	return in ? in->q_count : 0;
}

long tui_input_esc_deadline(const tui_input *in, uint64_t now_ms)
{
	uint64_t t0;
	uint64_t dl;

	if (!in)
		return -1;
	if (in->state == TUI_ST_GROUND && in->u8_len == 0)
		return -1;
	t0 = (in->state != TUI_ST_GROUND) ? in->esc_t0 : in->u8_t0;
	dl = t0 + in->esc_timeout_ms;
	if (dl <= now_ms)
		return 0;
	return (long)(dl - now_ms);
}

/* ---- 修饰键参数（xterm/kitty：值-1 的位域） ---- */

static uint8_t mod_bits(int param)
{
	int m;
	uint8_t r = 0;

	if (param < 2)
		return 0;
	m = param - 1;
	if (m & 1)
		r |= TUI_MOD_SHIFT;
	if (m & 2)
		r |= TUI_MOD_ALT;
	if (m & 4)
		r |= TUI_MOD_CTRL;
	if (m & 8)
		r |= TUI_MOD_SUPER;
	return r;
}

/* ---- UTF-8 跨 feed 装配 ---- */

static void u8_start(tui_input *in, uint8_t b, uint64_t now, uint8_t alt,
		     uint8_t paste)
{
	int need = tui_utf8_seqlen(b);

	if (need <= 1) {		/* 非法前导（0x80-0xC1/0xF5-0xFF） */
		push_key(in, TUI_KEY_CHAR, TUI_REPLACEMENT, alt, paste);
		return;
	}
	in->u8[0] = b;
	in->u8_len = 1;
	in->u8_need = (uint8_t)need;
	in->u8_t0 = now;
	in->u8_alt = alt;
	in->u8_paste = paste;
}

static void u8_append(tui_input *in, uint8_t b, uint64_t now)
{
	uint32_t cp = 0;
	size_t adv = 0;

	in->u8[in->u8_len++] = b;
	in->u8_t0 = now;
	if (in->u8_len < in->u8_need)
		return;
	if (tui_utf8_decode(in->u8, in->u8_len, &cp, &adv) != TUI_U8_OK)
		cp = TUI_REPLACEMENT;
	push_key(in, TUI_KEY_CHAR, cp, in->u8_alt, in->u8_paste);
	in->u8_len = 0;
}

/* 半截 UTF-8 超时/断裂 → 一个替换符 */
static void u8_flush_fffd(tui_input *in)
{
	if (in->u8_len == 0)
		return;
	push_key(in, TUI_KEY_CHAR, TUI_REPLACEMENT, in->u8_alt,
		 in->u8_paste);
	in->u8_len = 0;
}

/* ---- 字节分发 ---- */

static void handle_byte(tui_input *in, uint8_t b, uint64_t now);

/* GROUND：控制字节映射 + 可打印 + UTF-8 入口 */
static void ground_byte(tui_input *in, uint8_t b, uint64_t now)
{
	uint8_t mods;

	if (b == 0x1b) {
		in->state = TUI_ST_ESC;
		in->esc_t0 = now;
		return;
	}
	if (in->u8_len > 0) {
		if ((b & 0xC0) == 0x80) {
			u8_append(in, b, now);
			return;
		}
		u8_flush_fffd(in);	/* 断裂：先吐替换符再处理新字节 */
	}
	if (b >= 0x80) {
		mods = in->alt_pending;
		in->alt_pending = 0;
		u8_start(in, b, now, mods, 0);
		return;
	}
	mods = in->alt_pending;
	in->alt_pending = 0;

	if (b <= 0x1f || b == 0x7f) {
		switch (b) {
		case 0x09:
			push_key(in, TUI_KEY_TAB, 0, mods, 0);
			return;
		case 0x0d:
			push_key(in, TUI_KEY_RETURN, 0, mods, 0);
			return;
		case 0x08:		/* BS 键（终端亦有发 0x08 者） */
		case 0x7f:
			push_key(in, TUI_KEY_BACKSPACE, 0, mods, 0);
			return;
		case 0x00:		/* Ctrl+Space / NUL */
			push_key(in, TUI_KEY_CHAR, ' ', mods | TUI_MOD_CTRL,
				 0);
			return;
		case 0x0a:		/* Ctrl+J（OCD input.newline） */
			push_key(in, TUI_KEY_CHAR, 'j', mods | TUI_MOD_CTRL, 0);
			return;
		default:
			if (b <= 0x1a) {	/* Ctrl+A..Z（除已处理） */
				push_key(in, TUI_KEY_CHAR,
					 (uint32_t)('a' + b - 1),
					 mods | TUI_MOD_CTRL, 0);
				return;
			}
			/* 0x1c-0x1f: Ctrl+\ ] ^ _ */
			push_key(in, TUI_KEY_CHAR,
				 (uint32_t)"\\]^_"[b - 0x1c],
				 mods | TUI_MOD_CTRL, 0);
			return;
		}
	}
	push_key(in, TUI_KEY_CHAR, b, mods, 0);	/* 0x20-0x7e */
}

/* PASTE 内容字节：字面量回放（含控制字节），UTF-8 装配 paste=1 */
static void paste_content_byte(tui_input *in, uint8_t b, uint64_t now)
{
	if (in->u8_len > 0) {
		if ((b & 0xC0) == 0x80) {
			u8_append(in, b, now);
			return;
		}
		u8_flush_fffd(in);
	}
	if (b >= 0x80) {
		u8_start(in, b, now, 0, 1);
		return;
	}
	push_key(in, TUI_KEY_CHAR, b, 0, 1);
}

static const char PASTE_TERM[] = "\x1b[201~";	/* 6 字节 */

static void paste_byte(tui_input *in, uint8_t b, uint64_t now)
{
	if (in->pend_len > 0 || b == (uint8_t)PASTE_TERM[0]) {
		if (b == (uint8_t)PASTE_TERM[in->pend_len]) {
			in->pend[in->pend_len++] = b;
			if (in->pend_len == 6) {	/* 终止符完整 */
				in->pend_len = 0;
				in->state = TUI_ST_GROUND;
				u8_flush_fffd(in);
				push_ev(in, TUI_EV_PASTE_END, 0);
			}
			return;
		}
		/* 不匹配：已匹配前缀是内容 → 逐字节回放，再重处理本字节 */
		{
			uint8_t i;
			for (i = 0; i < in->pend_len; i++)
				paste_content_byte(in, in->pend[i], now);
		}
		in->pend_len = 0;
	}
	if (b == (uint8_t)PASTE_TERM[0]) {
		in->pend[0] = b;
		in->pend_len = 1;
		return;
	}
	paste_content_byte(in, b, now);
}

/* CSI 参数串 → 整数数组（';'/':' 分隔；空项=-1）。返回个数，-1=格式坏 */
static int csi_parse(const uint8_t *s, size_t len, int *out, int max)
{
	int n = 0, v = 0, has = 0;
	size_t i;

	for (i = 0; i < len; i++) {
		uint8_t c = s[i];
		if (c >= '0' && c <= '9') {
			v = v * 10 + (c - '0');
			if (v > 65535)
				v = 65535;
			has = 1;
		} else if (c == ';' || c == ':') {
			if (n >= max)
				return -1;
			out[n++] = has ? v : -1;
			v = 0;
			has = 0;
		} else {
			return -1;
		}
	}
	if (has) {
		if (n >= max)
			return -1;
		out[n++] = v;
	} else if (len > 0 && (s[len - 1] == ';' || s[len - 1] == ':')) {
		if (n >= max)
			return -1;
		out[n++] = -1;
	}
	return n;
}

/* CSI-u / modifyOtherKeys 的码点 → 键事件 */
static void emit_csiu_code(tui_input *in, int cp, uint8_t mods)
{
	if (cp < 0)
		return;
	if (cp == 13) {
		push_key(in, TUI_KEY_RETURN, 0, mods, 0);
		return;
	}
	if (cp == 9) {
		push_key(in, TUI_KEY_TAB, 0, mods, 0);
		return;
	}
	if (cp == 27) {
		push_key(in, TUI_KEY_ESCAPE, 0, mods, 0);
		return;
	}
	if (cp == 127 || cp == 8) {
		push_key(in, TUI_KEY_BACKSPACE, 0, mods, 0);
		return;
	}
	if (cp == 0) {
		push_key(in, TUI_KEY_CHAR, ' ', mods | TUI_MOD_CTRL, 0);
		return;
	}
	if (cp <= 26) {			/* 1..26 → Ctrl+字母（除上已处理） */
		push_key(in, TUI_KEY_CHAR, (uint32_t)('a' + cp - 1),
			 mods | TUI_MOD_CTRL, 0);
		return;
	}
	if (cp >= 0x20 && cp <= 0x10FFFF)
		push_key(in, TUI_KEY_CHAR, (uint32_t)cp, mods, 0);
}

static void parse_csi(tui_input *in, uint8_t final_b)
{
	int p[8];
	int np = -1;
	int priv = 0;
	int start = 0;
	uint8_t mods = 0;

	if (in->csi_len > 0 &&
	    (in->csi[0] == '?' || in->csi[0] == '>' ||
	     in->csi[0] == '<' || in->csi[0] == '=')) {
		priv = in->csi[0];
		start = 1;
	}
	if ((int)in->csi_len > start) {
		np = csi_parse(in->csi + start, in->csi_len - start, p, 8);
		if (np < 0)
			return;			/* 格式坏 → 丢弃 */
	} else {
		np = 0;
	}

	/* kitty 键盘协议探测回复：CSI ? <flags> u */
	if (priv == '?' && final_b == 'u') {
		push_ev(in, TUI_EV_KITTY_FLAGS,
			(np >= 1 && p[0] >= 0) ? (uint32_t)p[0] : 0u);
		return;
	}
	/* SGR 鼠标（1006）：CSI < cb ; cx ; cy M/m（B5 真实现）
	 * cb 位：0-1 按钮、2 保留、4 shift、8 alt、16 ctrl、32 motion、
	 * 64 wheel（0=上 1=下）；'M'=按下/拖动/滚轮，'m'=释放。 */
	if (priv == '<' && (final_b == 'M' || final_b == 'm')) {
		int cb = (np >= 1 && p[0] >= 0) ? p[0] : 0;
		int cx = (np >= 2 && p[1] >= 0) ? p[1] : 1;
		int cy = (np >= 3 && p[2] >= 0) ? p[2] : 1;
		uint8_t mods = 0;
		uint16_t act;

		if (cb & 4)
			mods |= TUI_MOD_SHIFT;
		if (cb & 8)
			mods |= TUI_MOD_ALT;
		if (cb & 16)
			mods |= TUI_MOD_CTRL;
		if (cb & 64)
			act = (cb & 3) == 0 ? TUI_MOUSE_WHEEL_UP :
			      TUI_MOUSE_WHEEL_DOWN;
		else if (cb & 32)
			act = TUI_MOUSE_MOTION;
		else if (final_b == 'm')
			act = TUI_MOUSE_RELEASE;
		else
			act = TUI_MOUSE_PRESS;
		push_mouse(in, act, (uint32_t)(cb & 3), mods, cx, cy);
		return;
	}
	/* X10 兼容：CSI M + 3 原始字节（按钮/列/行各 +32；无释放事件；
	 * 坐标上限 223——B5 评估后实现：occ 开 1000 无 1006 的终端回落此编码 */
	if (priv == 0 && np == 0 && final_b == 'M') {
		in->state = TUI_ST_MOUSE;
		in->mouse_left = 3;
		in->mouse_n = 0;
		return;
	}
	/* 其余鼠标编码（urxvt CSI cb;cx;cy M 等）：吞——occ 从不启用 */
	if (final_b == 'M' || final_b == 'm')
		return;
	/* 焦点进出 CSI I / CSI O：吞 */
	if (priv == 0 && (final_b == 'I' || final_b == 'O'))
		return;
	/* 其余私有序列（DECSET 回显、DA 应答等）：吞 */
	if (priv != 0)
		return;

	switch (final_b) {
	case 'A':
	case 'B':
	case 'C':
	case 'D': {
		static const uint16_t keys[4] = {
			TUI_KEY_UP, TUI_KEY_DOWN, TUI_KEY_RIGHT, TUI_KEY_LEFT
		};
		mods = (np >= 2) ? mod_bits(p[1]) : 0;
		push_key(in, keys[final_b - 'A'], 0, mods, 0);
		return;
	}
	case 'H':
	case 'F':
		mods = (np >= 2) ? mod_bits(p[1]) : 0;
		push_key(in, final_b == 'H' ? TUI_KEY_HOME : TUI_KEY_END, 0,
			 mods, 0);
		return;
	case 'Z':			/* CSI Z = Backtab（shift+tab） */
		push_key(in, TUI_KEY_TAB, 0, TUI_MOD_SHIFT, 0);
		return;
	case 'u':			/* kitty CSI-u */
		if (np < 1)
			return;
		mods = (np >= 2) ? mod_bits(p[1]) : 0;
		emit_csiu_code(in, p[0], mods);
		return;
	case '~': {
		int code = (np >= 1) ? p[0] : -1;
		mods = (np >= 2) ? mod_bits(p[1]) : 0;
		if (code == 200) {	/* bracketed paste 开始 */
			u8_flush_fffd(in);
			in->pend_len = 0;
			in->state = TUI_ST_PASTE;
			push_ev(in, TUI_EV_PASTE_START, 0);
			return;
		}
		if (code == 201)	/* 游离的 paste end：忽略 */
			return;
		if (code == 27) {	/* modifyOtherKeys: CSI 27;mod;cp ~ */
			if (np >= 3)
				emit_csiu_code(in, p[2],
					       (uint8_t)((p[1] >= 2) ?
							 mod_bits(p[1]) : 0));
			return;
		}
		switch (code) {
		case 1:
		case 7:
			push_key(in, TUI_KEY_HOME, 0, mods, 0);
			return;
		case 2:
			push_key(in, TUI_KEY_INSERT, 0, mods, 0);
			return;
		case 3:
			push_key(in, TUI_KEY_DELETE, 0, mods, 0);
			return;
		case 4:
		case 8:
			push_key(in, TUI_KEY_END, 0, mods, 0);
			return;
		case 5:
			push_key(in, TUI_KEY_PAGEUP, 0, mods, 0);
			return;
		case 6:
			push_key(in, TUI_KEY_PAGEDOWN, 0, mods, 0);
			return;
		case 11: push_key(in, TUI_KEY_F1, 0, mods, 0); return;
		case 12: push_key(in, TUI_KEY_F2, 0, mods, 0); return;
		case 13: push_key(in, TUI_KEY_F3, 0, mods, 0); return;
		case 14: push_key(in, TUI_KEY_F4, 0, mods, 0); return;
		case 15: push_key(in, TUI_KEY_F5, 0, mods, 0); return;
		case 17: push_key(in, TUI_KEY_F6, 0, mods, 0); return;
		case 18: push_key(in, TUI_KEY_F7, 0, mods, 0); return;
		case 19: push_key(in, TUI_KEY_F8, 0, mods, 0); return;
		case 20: push_key(in, TUI_KEY_F9, 0, mods, 0); return;
		case 21: push_key(in, TUI_KEY_F10, 0, mods, 0); return;
		case 23: push_key(in, TUI_KEY_F11, 0, mods, 0); return;
		case 24: push_key(in, TUI_KEY_F12, 0, mods, 0); return;
		default:
			return;		/* 未知编号序列：吞 */
		}
	}
	default:
		return;			/* 未知 CSI：吞 */
	}
}

static void handle_byte(tui_input *in, uint8_t b, uint64_t now)
{
	for (;;) {
		/* 新字节到达先结算过期的挂起态 */
		if (in->state == TUI_ST_ESC &&
		    now - in->esc_t0 >= in->esc_timeout_ms) {
			push_key(in, TUI_KEY_ESCAPE, 0, 0, 0);
			in->state = TUI_ST_GROUND;
		} else if (in->state != TUI_ST_GROUND &&
			   in->state != TUI_ST_PASTE &&
			   now - in->esc_t0 >= in->esc_timeout_ms) {
			in->state = TUI_ST_GROUND;	/* 半截序列静默丢弃 */
		}

		switch (in->state) {
		case TUI_ST_GROUND:
			ground_byte(in, b, now);
			return;
		case TUI_ST_ESC:
			in->esc_t0 = now;	/* 序列续字节刷新计时 */
			switch (b) {
			case '[':
				in->state = TUI_ST_CSI;
				in->csi_len = 0;
				in->csi_ovf = 0;
				return;
			case 'O':
				in->state = TUI_ST_SS3;
				return;
			case ']':
				in->state = TUI_ST_STR;
				in->str_bel = 1;
				in->str_len = 0;
				return;
			case 'P':
			case '_':
			case '^':
			case 'X':
				in->state = TUI_ST_STR;
				in->str_bel = 0;
				in->str_len = 0;
				return;
			case 0x1b:	/* 双 Esc：第一下立即成键 */
				push_key(in, TUI_KEY_ESCAPE, 0, 0, 0);
				return;
			default:	/* Alt+键：带 ALT 重进 GROUND */
				in->state = TUI_ST_GROUND;
				in->alt_pending = TUI_MOD_ALT;
				continue;
			}
		case TUI_ST_CSI:
			in->esc_t0 = now;
			if (b >= 0x30 && b <= 0x3f) {	/* 参数/私有标记 */
				if (in->csi_len < CSI_MAX)
					in->csi[in->csi_len++] = b;
				else
					in->csi_ovf = 1;
				return;
			}
			if (b >= 0x20 && b <= 0x2f) {	/* 中间字节：丢序列 */
				in->csi_ovf = 1;
				return;
			}
			if (b >= 0x40 && b <= 0x7e) {	/* 终字节 */
				in->state = TUI_ST_GROUND;
				if (!in->csi_ovf)
					parse_csi(in, b);
				in->csi_len = 0;
				in->csi_ovf = 0;
				return;
			}
			/* CSI 中混入控制字节：中止序列，按 GROUND 重处理 */
			in->state = TUI_ST_GROUND;
			in->csi_len = 0;
			in->csi_ovf = 0;
			continue;
		case TUI_ST_SS3:
			in->esc_t0 = now;
			in->state = TUI_ST_GROUND;
			switch (b) {
			case 'A':
				push_key(in, TUI_KEY_UP, 0, 0, 0);
				return;
			case 'B':
				push_key(in, TUI_KEY_DOWN, 0, 0, 0);
				return;
			case 'C':
				push_key(in, TUI_KEY_RIGHT, 0, 0, 0);
				return;
			case 'D':
				push_key(in, TUI_KEY_LEFT, 0, 0, 0);
				return;
			case 'H':
				push_key(in, TUI_KEY_HOME, 0, 0, 0);
				return;
			case 'F':
				push_key(in, TUI_KEY_END, 0, 0, 0);
				return;
			case 'P':
				push_key(in, TUI_KEY_F1, 0, 0, 0);
				return;
			case 'Q':
				push_key(in, TUI_KEY_F2, 0, 0, 0);
				return;
			case 'R':
				push_key(in, TUI_KEY_F3, 0, 0, 0);
				return;
			case 'S':
				push_key(in, TUI_KEY_F4, 0, 0, 0);
				return;
			default:
				return;	/* 未知 SS3：吞 */
			}
		case TUI_ST_STR:
			in->esc_t0 = now;
			if (in->str_bel && b == 0x07) {
				in->state = TUI_ST_GROUND;
				return;
			}
			if (b == 0x1b) {
				in->state = TUI_ST_STR_ESC;
				return;
			}
			if (++in->str_len > STR_MAX)
				in->state = TUI_ST_GROUND;	/* 防卡死 */
			return;
		case TUI_ST_STR_ESC:
			in->esc_t0 = now;
			if (b == '\\') {	/* ST 收尾 */
				in->state = TUI_ST_GROUND;
				return;
			}
			/* 非 ST：字符串作废，本字节按 GROUND 重处理 */
			in->state = TUI_ST_GROUND;
			in->str_len = 0;
			continue;
		case TUI_ST_PASTE:
			paste_byte(in, b, now);
			return;
		case TUI_ST_MOUSE:
			in->esc_t0 = now;
			if (in->mouse_left > 0) {
				in->mouse_left--;
				if (in->mouse_n < 3)
					in->mouse_b[in->mouse_n++] = b;
			}
			if (in->mouse_left == 0) {
				/* X10 三字节齐 → 事件（B5）：b0=按钮+32
				 * （位 4/8/16 修饰、32 motion、64/128 wheel）；
				 * b1/b2=列/行+32（1 基）。无释放语义。 */
				int cb = (int)in->mouse_b[0] - 32;
				int cx = (int)in->mouse_b[1] - 32;
				int cy = (int)in->mouse_b[2] - 32;
				uint8_t mods = 0;
				uint16_t act;

				if (cb < 0)
					cb = 0;
				if (cb & 4)
					mods |= TUI_MOD_SHIFT;
				if (cb & 8)
					mods |= TUI_MOD_ALT;
				if (cb & 16)
					mods |= TUI_MOD_CTRL;
				if (cb & 64)
					act = (cb & 3) == 0 ?
					      TUI_MOUSE_WHEEL_UP :
					      TUI_MOUSE_WHEEL_DOWN;
				else if (cb & 32)
					act = TUI_MOUSE_MOTION;
				else
					act = TUI_MOUSE_PRESS;
				push_mouse(in, act, (uint32_t)(cb & 3), mods,
					   cx, cy);
				in->mouse_n = 0;
				in->state = TUI_ST_GROUND;
			}
			return;
		default:
			in->state = TUI_ST_GROUND;
			return;
		}
	}
}

int tui_input_feed(tui_input *in, const void *data, size_t n, uint64_t now_ms)
{
	const uint8_t *p = (const uint8_t *)data;
	int before;
	size_t i;

	if (!in || (!data && n > 0))
		return 0;
	before = in->q_count;
	for (i = 0; i < n; i++)
		handle_byte(in, p[i], now_ms);
	return in->q_count - before;
}

int tui_input_tick(tui_input *in, uint64_t now_ms)
{
	int before;

	if (!in)
		return 0;
	before = in->q_count;
	if (in->state == TUI_ST_ESC &&
	    now_ms - in->esc_t0 >= in->esc_timeout_ms) {
		push_key(in, TUI_KEY_ESCAPE, 0, 0, 0);
		in->state = TUI_ST_GROUND;
	} else if (in->state != TUI_ST_GROUND &&
		   in->state != TUI_ST_PASTE &&
		   now_ms - in->esc_t0 >= in->esc_timeout_ms) {
		in->state = TUI_ST_GROUND;	/* 半截序列静默丢弃 */
		in->csi_len = 0;
		in->csi_ovf = 0;
	} else if (in->state == TUI_ST_GROUND && in->u8_len > 0 &&
		   now_ms - in->u8_t0 >= in->esc_timeout_ms) {
		u8_flush_fffd(in);		/* 慢速半截 UTF-8 → 替换符 */
	}
	return in->q_count - before;
}

/* ---- 键名 / keybind 字符串（OCD 对接面） ---- */

const char *tui_key_name(uint16_t key)
{
	switch (key) {
	case TUI_KEY_RETURN:    return "return";
	case TUI_KEY_TAB:       return "tab";
	case TUI_KEY_BACKSPACE: return "backspace";
	case TUI_KEY_ESCAPE:    return "escape";
	case TUI_KEY_UP:        return "up";
	case TUI_KEY_DOWN:      return "down";
	case TUI_KEY_LEFT:      return "left";
	case TUI_KEY_RIGHT:     return "right";
	case TUI_KEY_HOME:      return "home";
	case TUI_KEY_END:       return "end";
	case TUI_KEY_PAGEUP:    return "pageup";
	case TUI_KEY_PAGEDOWN:  return "pagedown";
	case TUI_KEY_DELETE:    return "delete";
	case TUI_KEY_INSERT:    return "insert";
	case TUI_KEY_F1:        return "f1";
	case TUI_KEY_F2:        return "f2";
	case TUI_KEY_F3:        return "f3";
	case TUI_KEY_F4:        return "f4";
	case TUI_KEY_F5:        return "f5";
	case TUI_KEY_F6:        return "f6";
	case TUI_KEY_F7:        return "f7";
	case TUI_KEY_F8:        return "f8";
	case TUI_KEY_F9:        return "f9";
	case TUI_KEY_F10:       return "f10";
	case TUI_KEY_F11:       return "f11";
	case TUI_KEY_F12:       return "f12";
	default:                return "";
	}
}

/* 事件 → keybind 规范串。修饰前缀顺序：ctrl+ alt+ super+ shift+
 * （对齐 keybind.ts 组合样例 ctrl+shift+t / alt+shift+f / super+shift+z）。
 * CHAR ' ' → "space"；命名键用规范名（return/escape/pageup/pagedown，
 * 即 keymap 别名归一的目标形）。返回写入长度；cap 不足返回 -1。 */
int tui_event_keystr(const tui_event *ev, char *buf, size_t cap)
{
	char tmp[80];
	size_t n = 0;
	const char *name = NULL;
	uint8_t mods = 0;

	if (!ev || !buf || cap == 0)
		return -1;
	if (ev->type == TUI_EV_PASTE_START) {
		name = "paste-start";
	} else if (ev->type == TUI_EV_PASTE_END) {
		name = "paste-end";
	} else if (ev->type == TUI_EV_KITTY_FLAGS) {
		name = "kitty-flags";
	} else if (ev->type == TUI_EV_MOUSE) {
		static const char *const mact[5] = {
			"press", "release", "motion", "wheel-up", "wheel-down"
		};
		size_t k;

		snprintf(tmp, sizeof(tmp), "mouse-%s",
			 ev->key >= 1 && ev->key <= 5 ? mact[ev->key - 1] :
			 "?");
		k = strlen(tmp);
		if (k + 1 > cap)
			return -1;
		memcpy(buf, tmp, k + 1);
		return (int)k;
	} else if (ev->key == TUI_KEY_CHAR) {
		mods = ev->mods;
		if (mods & TUI_MOD_CTRL) {
			memcpy(tmp + n, "ctrl+", 5);
			n += 5;
		}
		if (mods & TUI_MOD_ALT) {
			memcpy(tmp + n, "alt+", 4);
			n += 4;
		}
		if (mods & TUI_MOD_SUPER) {
			memcpy(tmp + n, "super+", 6);
			n += 6;
		}
		if (mods & TUI_MOD_SHIFT) {
			memcpy(tmp + n, "shift+", 6);
			n += 6;
		}
		if (ev->ch == ' ') {
			memcpy(tmp + n, "space", 5);
			n += 5;
		} else if (ev->ch < 0x80) {
			tmp[n++] = (char)ev->ch;
		} else {
			uint8_t u[4];
			size_t k = tui_utf8_encode(ev->ch, u);
			if (k == 0 || n + k >= sizeof(tmp))
				return -1;
			memcpy(tmp + n, u, k);
			n += k;
		}
	} else {
		mods = ev->mods;
		if (mods & TUI_MOD_CTRL) {
			memcpy(tmp + n, "ctrl+", 5);
			n += 5;
		}
		if (mods & TUI_MOD_ALT) {
			memcpy(tmp + n, "alt+", 4);
			n += 4;
		}
		if (mods & TUI_MOD_SUPER) {
			memcpy(tmp + n, "super+", 6);
			n += 6;
		}
		if (mods & TUI_MOD_SHIFT) {
			memcpy(tmp + n, "shift+", 6);
			n += 6;
		}
		name = tui_key_name(ev->key);
		if (!name || !name[0])
			return -1;
	}
	if (name) {
		size_t k = strlen(name);
		if (n + k >= sizeof(tmp))
			return -1;
		memcpy(tmp + n, name, k);
		n += k;
	}
	if (n + 1 > cap)
		return -1;
	memcpy(buf, tmp, n);
	buf[n] = '\0';
	return (int)n;
}

/* ---- kitty 键盘协议辅助（是否启用由 c2 依 KITTY_FLAGS 决定） ---- */

int tui_kitty_push_seq(char *buf, size_t cap, uint32_t flags)
{
	int n;
	if (!buf || cap == 0)
		return -1;
	n = snprintf(buf, cap, "\x1b[>%uu", (unsigned)flags);
	if (n < 0 || (size_t)n >= cap)
		return -1;
	return n;
}

int tui_kitty_pop_seq(char *buf, size_t cap)
{
	int n;
	if (!buf || cap == 0)
		return -1;
	n = snprintf(buf, cap, "\x1b[<u");
	if (n < 0 || (size_t)n >= cap)
		return -1;
	return n;
}
