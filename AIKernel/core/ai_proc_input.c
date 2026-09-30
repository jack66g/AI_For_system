// SPDX-License-Identifier: GPL-2.0
/*
 * ai_proc_input.c - AIKernel B 轨第5类用户输入遥测（自 ai_proc.c 拆分）
 *
 * 职责一句话：tty 输入全量/输出采样/线路规程、键盘事件+序列+组合
 * （per-CPU 输入状态机）、鼠标移动/按键/滚轮、触摸事件、tty 焦点窗口
 * 跟踪（8 槽表）的 ai_telemetry_* / ai_proc_* 发射实现。
 *
 * 拆分说明：函数体自原 ai_proc.c（1907 行）逐字搬移；ai_key_names/
 * ai_key_name、输入状态机（ai_input_state）与焦点表仅本文件使用，保持
 * static；ai_payload_stage 经 ai_proc_internal.h 共享。门控：整个文件在
 * CONFIG_AIKERNEL_TELEMETRY 下编译（与拆分前一致）。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/cgroup.h>
#include <linux/sort.h>
#include <linux/sched/deadline.h>
#include <linux/input-event-codes.h>
#include "ai_types.h"
#include "ai_proc.h"
#include "ai_control.h"

#ifdef CONFIG_AIKERNEL_TELEMETRY
#include "ai_telemetry.h"
#endif
#include "ai_proc_internal.h"

#ifdef CONFIG_AIKERNEL_TELEMETRY

/* 常见键名表（AT 键码，零脱敏语义保留键位） */
static const struct {
	u16 code;
	const char *name;
} ai_key_names[] = {
	{ KEY_ESC, "ESC" }, { KEY_BACKSPACE, "BACKSPACE" }, { KEY_TAB, "TAB" },
	{ KEY_ENTER, "ENTER" }, { KEY_LEFTCTRL, "LCTRL" },
	{ KEY_LEFTSHIFT, "LSHIFT" }, { KEY_RIGHTSHIFT, "RSHIFT" },
	{ KEY_LEFTALT, "LALT" }, { KEY_RIGHTALT, "RALT" },
	{ KEY_LEFTMETA, "LMETA" }, { KEY_RIGHTMETA, "RMETA" },
	{ KEY_SPACE, "SPACE" }, { KEY_CAPSLOCK, "CAPS" }, { KEY_NUMLOCK, "NUMLOCK" },
	{ KEY_SCROLLLOCK, "SCROLL" }, { KEY_INSERT, "INSERT" }, { KEY_DELETE, "DELETE" },
	{ KEY_HOME, "HOME" }, { KEY_END, "END" }, { KEY_PAGEUP, "PGUP" },
	{ KEY_PAGEDOWN, "PGDN" }, { KEY_UP, "UP" }, { KEY_DOWN, "DOWN" },
	{ KEY_LEFT, "LEFT" }, { KEY_RIGHT, "RIGHT" },
	{ KEY_F1, "F1" }, { KEY_F2, "F2" }, { KEY_F3, "F3" }, { KEY_F4, "F4" },
	{ KEY_F5, "F5" }, { KEY_F6, "F6" }, { KEY_F7, "F7" }, { KEY_F8, "F8" },
	{ KEY_F9, "F9" }, { KEY_F10, "F10" }, { KEY_F11, "F11" }, { KEY_F12, "F12" },
	{ KEY_MINUS, "MINUS" }, { KEY_EQUAL, "EQUAL" }, { KEY_LEFTBRACE, "LBRACE" },
	{ KEY_RIGHTBRACE, "RBRACE" }, { KEY_BACKSLASH, "BACKSLASH" },
	{ KEY_SEMICOLON, "SEMICOLON" }, { KEY_APOSTROPHE, "APOSTROPHE" },
	{ KEY_GRAVE, "GRAVE" }, { KEY_COMMA, "COMMA" }, { KEY_DOT, "DOT" },
	{ KEY_SLASH, "SLASH" }, { KEY_BACKSPACE, "BACKSPACE" },
	{ KEY_KP0, "KP0" }, { KEY_KP1, "KP1" }, { KEY_KP2, "KP2" },
	{ KEY_KP3, "KP3" }, { KEY_KP4, "KP4" }, { KEY_KP5, "KP5" },
	{ KEY_KP6, "KP6" }, { KEY_KP7, "KP7" }, { KEY_KP8, "KP8" }, { KEY_KP9, "KP9" },
	{ KEY_KPDOT, "KP." }, { KEY_KPSLASH, "KP/" }, { KEY_KPASTERISK, "KP*" },
	{ KEY_KPMINUS, "KP-" }, { KEY_KPPLUS, "KP+" }, { KEY_KPENTER, "KPENTER" },
	{ KEY_LEFT, "LEFT" }, { KEY_COMPOSE, "COMPOSE" }, { KEY_PAUSE, "PAUSE" },
};

static void ai_key_name(u16 code, char *buf, size_t sz)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ai_key_names); i++) {
		if (ai_key_names[i].code == code) {
			strscpy(buf, ai_key_names[i].name, sz);
			return;
		}
	}
	/* 可打印 ASCII 区（a-z/0-9）直接用具名字符 */
	if (code >= KEY_A && code <= KEY_Z) {
		char c = (char)('a' + (code - KEY_A));

		snprintf(buf, sz, "%c", c);
		return;
	}
	if (code >= KEY_1 && code <= KEY_0) {
		char c = (char)('1' + (code - KEY_1));

		if (code == KEY_0)
			c = '0';
		snprintf(buf, sz, "%c", c);
		return;
	}
	snprintf(buf, sz, "key%u", code);
}

/* ---- 第5类：用户输入 ---- */

void ai_telemetry_tty_input(const char *tty_name, const u8 *raw, u16 len)
{
	struct ai_tty_input_payload *p;
	u8 *stage;

	if (!tty_name || !raw || !len)
		return;
	preempt_disable();
	stage = this_cpu_ptr(ai_payload_stage);
	p = (struct ai_tty_input_payload *)stage;
	p->type = 1;
	strscpy(p->tty_name, tty_name, sizeof(p->tty_name));
	p->data_len = len;
	memcpy(p->data, raw, len);
	ai_telemetry_emit(AI_CAT_USER_INPUT, AI_EV_TTY, AI_SEV_NORMAL,
			  p, sizeof(*p) + len);
	preempt_enable();
}

void ai_telemetry_tty_output(const char *tty_name, const u8 *raw, u16 len)
{
	static DEFINE_PER_CPU(u32, ai_tty_out_cnt);
	struct ai_tty_output_payload *p;
	u8 *stage;
	u32 cnt;

	if (!tty_name || !raw || !len)
		return;
	preempt_disable();
	cnt = this_cpu_inc_return(ai_tty_out_cnt);
	if ((cnt & 0x3F) != 0) {   /* 1/64 采样（内部限频，与输入共享事件 ID） */
		preempt_enable();
		return;
	}
	stage = this_cpu_ptr(ai_payload_stage);
	p = (struct ai_tty_output_payload *)stage;
	p->type = 2;
	strscpy(p->tty_name, tty_name, sizeof(p->tty_name));
	p->data_len = len;
	memcpy(p->data, raw, len);
	ai_telemetry_emit_direct(AI_CAT_USER_INPUT, AI_EV_TTY, AI_SEV_DEBUG,
				 p, sizeof(*p) + len);
	preempt_enable();
}

void ai_telemetry_tty_line_discipline(const char *tty_name,
				      int old_ldisc, int new_ldisc)
{
	struct ai_tty_ldisc_payload p;

	p.type = 3;
	strscpy(p.tty_name, tty_name ? tty_name : "?", sizeof(p.tty_name));
	p.old_ldisc = old_ldisc;
	p.new_ldisc = new_ldisc;
	ai_telemetry_emit(AI_CAT_USER_INPUT, AI_EV_TTY, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

/* ---- 键盘：事件 + 序列 + 组合（per-CPU 状态，完整定义见输入状态机节） ---- */

struct ai_input_cpu_state {
	u16 seq_keys[64];
	u16 seq_delays[64];
	u8  seq_n;
	u64 seq_last_ts;
	u16 held[8];
	u8  n_held;
	u64 combo_start;
	s16 mpos_x, mpos_y;
	u32 mpos_dev_hash;
	u16 tx, ty, tp;
	u8  have_tx, have_ty;
	u8  touch_slots;
};

static DEFINE_PER_CPU(struct ai_input_cpu_state, ai_input_state);

static void ai_flush_key_sequence(const char *device,
				  struct ai_input_cpu_state *st)
{
	struct ai_input_key_seq_payload *p;
	u8 *stage;
	u16 i;
	u64 dur;

	if (!st->seq_n)
		return;
	preempt_disable();
	stage = this_cpu_ptr(ai_payload_stage);
	p = (struct ai_input_key_seq_payload *)stage;
	p->type = 2;
	strscpy(p->device, device ? device : "?", sizeof(p->device));
	p->n_keys = st->seq_n;
	dur = 0;
	for (i = 0; i < st->seq_n; i++)
		dur += (u64)st->seq_delays[i] * 1000000ULL;
	p->duration_ns = dur;
	p->typing_speed_keys_per_s =
		dur ? (u16)((u64)st->seq_n * 1000000000ULL / dur) : 0;
	for (i = 0; i < st->seq_n; i++) {
		u16 *kv = (u16 *)&p[1];

		kv[i * 2] = st->seq_keys[i];
		kv[i * 2 + 1] = st->seq_delays[i];
	}
	ai_telemetry_emit_direct(AI_CAT_USER_INPUT, AI_EV_INPUT_KEY,
				 AI_SEV_NORMAL, p,
				 sizeof(*p) + st->seq_n * 4);
	st->seq_n = 0;
	preempt_enable();
}

void ai_telemetry_input_key_event(const char *device, u16 keycode,
				  u8 pressed, u64 ts_ns, const char *key_name)
{
	struct ai_input_key_payload p;

	p.type = 1;
	strscpy(p.device, device ? device : "?", sizeof(p.device));
	p.keycode = keycode;
	p.pressed = pressed;
	p.event_ts_ns = ts_ns;
	strscpy(p.key_name, key_name ? key_name : "?", sizeof(p.key_name));
	ai_telemetry_emit(AI_CAT_USER_INPUT, AI_EV_INPUT_KEY, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

void ai_telemetry_input_key_sequence(const char *device,
				     const struct ai_key_pair *pairs, u16 n,
				     u64 duration_ns)
{
	struct ai_input_key_seq_payload *p;
	u8 *stage;
	u16 i;

	if (!pairs || !n)
		return;
	preempt_disable();
	stage = this_cpu_ptr(ai_payload_stage);
	p = (struct ai_input_key_seq_payload *)stage;
	p->type = 2;
	strscpy(p->device, device ? device : "?", sizeof(p->device));
	p->n_keys = n;
	p->duration_ns = duration_ns;
	p->typing_speed_keys_per_s =
		duration_ns ? (u16)((u64)n * 1000000000ULL / duration_ns) : 0;
	for (i = 0; i < n; i++) {
		u16 *kv = (u16 *)&p[1];

		kv[i * 2] = pairs[i].keycode;
		kv[i * 2 + 1] = pairs[i].delay_ms;
	}
	ai_telemetry_emit_direct(AI_CAT_USER_INPUT, AI_EV_INPUT_KEY,
				 AI_SEV_NORMAL, p, sizeof(*p) + n * 4);
	preempt_enable();
}

void ai_telemetry_input_key_combo(const char *device, const u16 *keys,
				  u16 n, u32 duration_ms)
{
	struct ai_input_key_combo_payload p;
	u16 i;

	if (!keys || !n || n > 8)
		return;
	p.type = 3;
	strscpy(p.device, device ? device : "?", sizeof(p.device));
	p.n_keys = n;
	p.duration_ms = duration_ms;
	for (i = 0; i < n; i++)
		p.keys[i] = keys[i];
	ai_telemetry_emit(AI_CAT_USER_INPUT, AI_EV_INPUT_KEY, AI_SEV_NORMAL,
			  &p, sizeof(p));
}

void ai_telemetry_input_mouse_move(const char *device, s16 dx, s16 dy,
				   s16 x, s16 y, u64 ts_ns)
{
	struct ai_input_mouse_payload p;

	p.type = 1;
	strscpy(p.device, device ? device : "?", sizeof(p.device));
	p.dx = dx;
	p.dy = dy;
	p.x = x;
	p.y = y;
	p.event_ts_ns = ts_ns;
	ai_telemetry_emit(AI_CAT_USER_INPUT, AI_EV_INPUT_POINTER,
			  AI_SEV_DEBUG, &p, sizeof(p));
}

void ai_telemetry_input_mouse_button(const char *device, u16 button,
				     u8 pressed, s16 x, s16 y, u64 ts_ns)
{
	struct ai_input_btn_payload p;

	p.type = 2;
	strscpy(p.device, device ? device : "?", sizeof(p.device));
	p.button = button;
	p.pressed = pressed;
	p.x = x;
	p.y = y;
	p.event_ts_ns = ts_ns;
	ai_telemetry_emit(AI_CAT_USER_INPUT, AI_EV_INPUT_POINTER,
			  AI_SEV_NORMAL, &p, sizeof(p));
}

void ai_telemetry_input_mouse_scroll(const char *device, s16 dx, s16 dy)
{
	struct ai_input_scroll_payload p;

	p.type = 3;
	strscpy(p.device, device ? device : "?", sizeof(p.device));
	p.dx = dx;
	p.dy = dy;
	ai_telemetry_emit(AI_CAT_USER_INPUT, AI_EV_INPUT_POINTER,
			  AI_SEV_NORMAL, &p, sizeof(p));
}

void ai_telemetry_input_touch_event(const char *device, u16 x, u16 y,
				    u16 pressure, u8 touch_type,
				    u8 contact_count, u64 ts_ns)
{
	struct ai_input_touch_payload p;

	p.type = 4;
	strscpy(p.device, device ? device : "?", sizeof(p.device));
	p.x = x;
	p.y = y;
	p.pressure = pressure;
	p.touch_type = touch_type;
	p.contact_count = contact_count;
	p.event_ts_ns = ts_ns;
	ai_telemetry_emit(AI_CAT_USER_INPUT, AI_EV_INPUT_POINTER,
			  AI_SEV_NORMAL, &p, sizeof(p));
}

/* ---- 输入状态机（input_handle_event 汇聚点驱动） ---- */

static u32 ai_dev_hash(const char *device)
{
	u32 h = 0;
	const u8 *p = (const u8 *)device;

	while (*p)
		h = (h << 5) - h + *p++;
	return h;
}

static void ai_key_press(const char *device, u16 code, u64 now,
			 struct ai_input_cpu_state *st)
{
	char kname[24];
	u16 delay;

	ai_key_name(code, kname, sizeof(kname));
	ai_telemetry_input_key_event(device, code, 1, now, kname);

	/* 序列：与上一键间隔 >1s → flush 旧序列，开始新序列 */
	if (st->seq_n &&
	    (now - st->seq_last_ts) > 1000000000ULL)
		ai_flush_key_sequence(device, st);
	delay = st->seq_n ?
		(u16)((now - st->seq_last_ts) / 1000000ULL) : 0;
	if (st->seq_n < 64) {
		st->seq_keys[st->seq_n] = code;
		st->seq_delays[st->seq_n] = delay;
		st->seq_n++;
	} else {
		ai_flush_key_sequence(device, st);
	}
	st->seq_last_ts = now;

	/* 组合键 */
	if (st->n_held < 8) {
		st->held[st->n_held++] = code;
		if (st->n_held >= 2 && !st->combo_start)
			st->combo_start = now;
		else if (st->n_held >= 2)
			ai_telemetry_input_key_combo(device, st->held,
					st->n_held,
					(u32)((now - st->combo_start) / 1000000ULL));
	}
}

static void ai_key_release(const char *device, u16 code, u64 now,
			   struct ai_input_cpu_state *st)
{
	char kname[24];
	int i;

	ai_key_name(code, kname, sizeof(kname));
	ai_telemetry_input_key_event(device, code, 0, now, kname);

	for (i = 0; i < st->n_held; i++) {
		if (st->held[i] == code) {
			st->held[i] = st->held[--st->n_held];
			break;
		}
	}
	if (st->n_held < 2)
		st->combo_start = 0;
}

void ai_proc_input_event(const char *device, unsigned int type,
			 unsigned int code, int value, bool is_pointer)
{
	struct ai_input_cpu_state *st;
	u64 now;

	if (!device)
		device = "?";
	preempt_disable();
	st = this_cpu_ptr(&ai_input_state);
	now = ktime_get_ns();

	switch (type) {
	case EV_KEY:
		if (is_pointer) {
			ai_telemetry_input_mouse_button(device, (u16)code,
					value ? 1 : 0, st->mpos_x, st->mpos_y,
					now);
		} else if (value == 1) {
			ai_key_press(device, (u16)code, now, st);
		} else if (value == 0) {
			ai_key_release(device, (u16)code, now, st);
		} else {
			char kname[24];

			ai_key_name((u16)code, kname, sizeof(kname));
			ai_telemetry_input_key_event(device, (u16)code, 2, now,
						     kname);
		}
		break;
	case EV_REL:
		if (code == REL_X) {
			if (st->mpos_dev_hash != ai_dev_hash(device)) {
				st->mpos_dev_hash = ai_dev_hash(device);
				st->mpos_x = 0;
				st->mpos_y = 0;
			}
			st->mpos_x += (s16)value;
			ai_telemetry_input_mouse_move(device, (s16)value, 0,
					st->mpos_x, st->mpos_y, now);
		} else if (code == REL_Y) {
			if (st->mpos_dev_hash != ai_dev_hash(device)) {
				st->mpos_dev_hash = ai_dev_hash(device);
				st->mpos_x = 0;
				st->mpos_y = 0;
			}
			st->mpos_y += (s16)value;
			ai_telemetry_input_mouse_move(device, 0, (s16)value,
					st->mpos_x, st->mpos_y, now);
		} else if (code == REL_WHEEL) {
			ai_telemetry_input_mouse_scroll(device, 0, (s16)value);
		} else if (code == REL_HWHEEL) {
			ai_telemetry_input_mouse_scroll(device, (s16)value, 0);
		}
		break;
	case EV_ABS:
		if (code == ABS_X || code == ABS_MT_POSITION_X) {
			st->tx = (u16)value;
			st->have_tx = 1;
		} else if (code == ABS_Y || code == ABS_MT_POSITION_Y) {
			st->ty = (u16)value;
			if (st->have_tx) {
				ai_telemetry_input_touch_event(device, st->tx,
						st->ty, st->tp,
						st->have_ty ? 2 : 1,
						st->touch_slots ? st->touch_slots : 1,
						now);
				st->have_ty = 1;
			}
		} else if (code == ABS_PRESSURE ||
			   code == ABS_MT_PRESSURE) {
			st->tp = (u16)value;
		} else if (code == ABS_MT_SLOT) {
			st->touch_slots = (u8)(value + 1);
		} else if (code == ABS_MT_TRACKING_ID) {
			if (value < 0) {
				ai_telemetry_input_touch_event(device, st->tx,
						st->ty, st->tp, 3,
						st->touch_slots, now);
				st->have_tx = 0;
				st->have_ty = 0;
			}
		}
		break;
	default:
		break;
	}
	preempt_enable();
}
EXPORT_SYMBOL_GPL(ai_proc_input_event);

/* ---- tty 焦点窗口跟踪（8 槽，tty 输入路径驱动） ---- */

#define AI_FOCUS_SLOTS 8

struct ai_focus_ent {
	char tty_name[64];
	char fg_comm[TASK_COMM_LEN];
	u32 fg_pid;
	u64 last_input_ns;
};

static struct ai_focus_ent ai_focus_table[AI_FOCUS_SLOTS];
static DEFINE_SPINLOCK(ai_focus_lock);

void ai_proc_tty_input_focus(const char *tty_name, u32 fg_pid,
			     const char *fg_comm)
{
	struct ai_focus_ent *ent = NULL;
	unsigned long flags;
	int i, free_i = -1;
	u64 now = ktime_get_ns();

	if (!tty_name)
		return;
	spin_lock_irqsave(&ai_focus_lock, flags);
	for (i = 0; i < AI_FOCUS_SLOTS; i++) {
		if (ai_focus_table[i].tty_name[0] &&
		    !strcmp(ai_focus_table[i].tty_name, tty_name)) {
			ent = &ai_focus_table[i];
			break;
		}
		if (!ai_focus_table[i].tty_name[0] && free_i < 0)
			free_i = i;
	}
	if (!ent && free_i >= 0) {
		ent = &ai_focus_table[free_i];
		strscpy(ent->tty_name, tty_name, sizeof(ent->tty_name));
		ent->last_input_ns = 0;
	}
	if (ent) {
		u64 dur = ent->last_input_ns ? now - ent->last_input_ns : 0;

		if (ent->last_input_ns && dur > 1000000ULL) {
			ai_telemetry_focus_window(tty_name, ent->fg_pid,
					ent->fg_comm[0] ? ent->fg_comm : "?",
					"tty", dur);
		}
		ent->last_input_ns = now;
		ent->fg_pid = fg_pid;
		strscpy(ent->fg_comm, fg_comm ? fg_comm : "?",
			sizeof(ent->fg_comm));
	}
	spin_unlock_irqrestore(&ai_focus_lock, flags);
}
EXPORT_SYMBOL_GPL(ai_proc_tty_input_focus);

#endif /* CONFIG_AIKERNEL_TELEMETRY */
