/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_input.c - 输入 fixture 回放 golden 测试（T9c1）
 *
 * 字节流 → 键事件序列断言：可打印/UTF-8 装配（含跨 feed 断字）、控制键、
 * Ctrl+A..Z、方向/翻页/F 键（CSI+SS3）、孤立 Esc 超时、双 Esc、Alt+键、
 * kitty CSI-u 与探测回复、modifyOtherKeys、bracketed paste（含跨 feed
 * 终止符）、OSC/鼠标吞噬、keybind 字符串、kitty push/pop 序列。
 */
#include "../tui_input.h"

#include "../tui_utf8.h"

#include <stdio.h>
#include <string.h>

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

#define MAXEV 64

struct replay {
	tui_input in;
	tui_event ev[MAXEV];
	int n;
};

static void replay_init(struct replay *r)
{
	tui_input_init(&r->in);
	r->n = 0;
}

/* 喂字节并收事件 */
static void feed(struct replay *r, const char *bytes, size_t len,
		 uint64_t now)
{
	tui_input_feed(&r->in, bytes, len, now);
	while (r->n < MAXEV &&
	       tui_input_next(&r->in, &r->ev[r->n]))
		r->n++;
}

static void feeds(struct replay *r, const char *str, uint64_t now)
{
	feed(r, str, strlen(str), now);
}

static void tick(struct replay *r, uint64_t now)
{
	tui_input_tick(&r->in, now);
	while (r->n < MAXEV &&
	       tui_input_next(&r->in, &r->ev[r->n]))
		r->n++;
}

/* 断言第 i 个事件为 KEY/key/ch/mods/paste */
static void ok_ev(const char *name, const struct replay *r, int i,
		  uint8_t type, uint16_t key, uint32_t ch, uint8_t mods,
		  uint8_t paste)
{
	const tui_event *e;

	if (i >= r->n) {
		n_fail++;
		printf("FAIL %s (line %d): no event #%d (have %d)\n", name,
		       __LINE__, i, r->n);
		return;
	}
	e = &r->ev[i];
	if (e->type == type && e->key == key && e->ch == ch &&
	    e->mods == mods && e->paste == paste) {
		n_ok++;
		return;
	}
	n_fail++;
	printf("FAIL %s (line %d): ev#%d type=%u key=%u ch=U+%X mods=%u "
	       "paste=%u (want type=%u key=%u ch=U+%X mods=%u paste=%u)\n",
	       name, __LINE__, i, e->type, e->key, e->ch, e->mods, e->paste,
	       type, key, ch, mods, paste);
}

static void ok_count(const char *name, const struct replay *r, int want)
{
	if (r->n == want) {
		n_ok++;
		return;
	}
	n_fail++;
	printf("FAIL %s (line %d): got %d events, want %d\n", name, __LINE__,
	       r->n, want);
}

#define KEY(name, r, i, key, ch, mods) \
	ok_ev(name, r, i, TUI_EV_KEY, key, ch, mods, 0)
#define PKEY(name, r, i, key, ch, mods) \
	ok_ev(name, r, i, TUI_EV_KEY, key, ch, mods, 1)

/* ---- 可打印 / UTF-8 ---- */

static void test_plain(void)
{
	struct replay r;

	replay_init(&r);
	feeds(&r, "abc", 100);
	ok_count("plain-3ev", &r, 3);
	KEY("plain-a", &r, 0, TUI_KEY_CHAR, 'a', 0);
	KEY("plain-b", &r, 1, TUI_KEY_CHAR, 'b', 0);
	KEY("plain-c", &r, 2, TUI_KEY_CHAR, 'c', 0);

	/* 单段 UTF-8 中文 */
	replay_init(&r);
	feed(&r, "\xe4\xb8\xad", 3, 100);
	ok_count("utf8-zhong-1ev", &r, 1);
	KEY("utf8-zhong", &r, 0, TUI_KEY_CHAR, 0x4E2D, 0);

	/* 跨 feed 断字：两段拼装 */
	replay_init(&r);
	feed(&r, "\xe4\xb8", 2, 100);
	ok_count("utf8-split-none", &r, 0);
	feed(&r, "\xad", 1, 101);
	ok_count("utf8-split-1ev", &r, 1);
	KEY("utf8-split-joined", &r, 0, TUI_KEY_CHAR, 0x4E2D, 0);

	/* 非法字节 → 替换符 */
	replay_init(&r);
	feed(&r, "\xff", 1, 100);
	ok_count("bad-ff-1ev", &r, 1);
	KEY("bad-ff-replacement", &r, 0, TUI_KEY_CHAR, TUI_REPLACEMENT, 0);

	/* 断裂：半截后跟 ASCII → 替换符 + ASCII 两事件 */
	replay_init(&r);
	feed(&r, "\xe4""a", 2, 100);
	ok_count("bad-broken-2ev", &r, 2);
	KEY("bad-broken-repl", &r, 0, TUI_KEY_CHAR, TUI_REPLACEMENT, 0);
	KEY("bad-broken-a", &r, 1, TUI_KEY_CHAR, 'a', 0);

	/* 4 字节 emoji */
	replay_init(&r);
	feed(&r, "\xf0\x9f\x98\x80", 4, 100);
	ok_count("utf8-emoji-1ev", &r, 1);
	KEY("utf8-emoji", &r, 0, TUI_KEY_CHAR, 0x1F600, 0);
}

/* ---- 控制键 ---- */

static void test_controls(void)
{
	struct replay r;

	replay_init(&r);
	feed(&r, "\x03", 1, 100);	/* Ctrl+C */
	KEY("ctl-c", &r, 0, TUI_KEY_CHAR, 'c', TUI_MOD_CTRL);
	ok_count("ctl-c-1ev", &r, 1);

	replay_init(&r);
	feed(&r, "\x01", 1, 100);	/* Ctrl+A */
	KEY("ctl-a", &r, 0, TUI_KEY_CHAR, 'a', TUI_MOD_CTRL);

	replay_init(&r);
	feed(&r, "\x1a", 1, 100);	/* Ctrl+Z */
	KEY("ctl-z", &r, 0, TUI_KEY_CHAR, 'z', TUI_MOD_CTRL);

	replay_init(&r);
	feed(&r, "\x09", 1, 100);
	KEY("tab", &r, 0, TUI_KEY_TAB, 0, 0);

	replay_init(&r);
	feed(&r, "\x0d", 1, 100);
	KEY("return", &r, 0, TUI_KEY_RETURN, 0, 0);

	replay_init(&r);
	feed(&r, "\x7f", 1, 100);
	KEY("backspace-del", &r, 0, TUI_KEY_BACKSPACE, 0, 0);

	replay_init(&r);
	feed(&r, "\x08", 1, 100);
	KEY("backspace-bs", &r, 0, TUI_KEY_BACKSPACE, 0, 0);

	replay_init(&r);
	feed(&r, "\x00", 1, 100);	/* Ctrl+Space */
	KEY("ctl-space", &r, 0, TUI_KEY_CHAR, ' ', TUI_MOD_CTRL);

	replay_init(&r);
	feed(&r, "\x0a", 1, 100);	/* Ctrl+J = input.newline */
	KEY("ctl-j", &r, 0, TUI_KEY_CHAR, 'j', TUI_MOD_CTRL);

	replay_init(&r);
	feed(&r, "\x0b", 1, 100);	/* Ctrl+K */
	KEY("ctl-k", &r, 0, TUI_KEY_CHAR, 'k', TUI_MOD_CTRL);

	replay_init(&r);
	feed(&r, "\x1c", 1, 100);	/* Ctrl+\ */
	KEY("ctl-backslash", &r, 0, TUI_KEY_CHAR, '\\', TUI_MOD_CTRL);

	replay_init(&r);
	feed(&r, "\x1f", 1, 100);	/* Ctrl+_ */
	KEY("ctl-underscore", &r, 0, TUI_KEY_CHAR, '_', TUI_MOD_CTRL);

	replay_init(&r);
	feed(&r, "\x1d", 1, 100);	/* Ctrl+] */
	KEY("ctl-rbracket", &r, 0, TUI_KEY_CHAR, ']', TUI_MOD_CTRL);
}

/* ---- 孤立 Esc 超时 / 双 Esc / Alt ---- */

static void test_esc(void)
{
	struct replay r;

	/* 孤立 Esc：超时前无事件，到点成裸 Esc 键 */
	replay_init(&r);
	feed(&r, "\x1b", 1, 1000);
	ok_count("esc-pending-none", &r, 0);
	OK(tui_input_esc_deadline(&r.in, 1000) == 25, "esc-deadline-25");
	OK(tui_input_esc_deadline(&r.in, 1010) == 15, "esc-deadline-15");
	tick(&r, 1024);
	ok_count("esc-tick-before", &r, 0);
	tick(&r, 1025);
	ok_count("esc-tick-fire", &r, 1);
	KEY("esc-key", &r, 0, TUI_KEY_ESCAPE, 0, 0);
	OK(tui_input_esc_deadline(&r.in, 1025) == -1, "esc-deadline-gone");

	/* 超时后新字节：先结算 Esc，字节按 GROUND 处理 */
	replay_init(&r);
	feed(&r, "\x1b", 1, 2000);
	feed(&r, "a", 1, 2100);
	ok_count("esc-timeout-then-byte-2ev", &r, 2);
	KEY("esc-timeout-key", &r, 0, TUI_KEY_ESCAPE, 0, 0);
	KEY("esc-timeout-a", &r, 1, TUI_KEY_CHAR, 'a', 0);

	/* 超时内 ESC+a → Alt+a */
	replay_init(&r);
	feed(&r, "\x1b", 1, 3000);
	feed(&r, "a", 1, 3010);
	ok_count("alt-a-1ev", &r, 1);
	KEY("alt-a", &r, 0, TUI_KEY_CHAR, 'a', TUI_MOD_ALT);

	/* Alt+方向（CSI 由 ESC 起 → 走序列不是 alt）：ESC [ A = 普通 Up */
	replay_init(&r);
	feed(&r, "\x1b[A", 3, 4000);
	KEY("esc-bracket-a-up", &r, 0, TUI_KEY_UP, 0, 0);
	ok_count("esc-bracket-a-1ev", &r, 1);

	/* Alt+Ctrl：ESC 0x03 → alt+ctrl+c */
	replay_init(&r);
	feed(&r, "\x1b\x03", 2, 5000);
	ok_count("alt-ctl-c-1ev", &r, 1);
	KEY("alt-ctl-c", &r, 0, TUI_KEY_CHAR, 'c', TUI_MOD_ALT | TUI_MOD_CTRL);

	/* 双 Esc：第二字节到达立即结算第一下，超时结算第二下 */
	replay_init(&r);
	feed(&r, "\x1b\x1b", 2, 6000);
	ok_count("double-esc-first", &r, 1);
	KEY("double-esc-ev1", &r, 0, TUI_KEY_ESCAPE, 0, 0);
	tick(&r, 6025);
	ok_count("double-esc-second", &r, 2);
	KEY("double-esc-ev2", &r, 1, TUI_KEY_ESCAPE, 0, 0);

	/* Alt+UTF8：ESC + 中（跨 feed）→ 中 + ALT */
	replay_init(&r);
	feed(&r, "\x1b", 1, 7000);
	feed(&r, "\xe4\xb8\xad", 3, 7005);
	ok_count("alt-utf8-1ev", &r, 1);
	KEY("alt-utf8", &r, 0, TUI_KEY_CHAR, 0x4E2D, TUI_MOD_ALT);
}

/* ---- CSI / SS3 方向与修饰 ---- */

static void test_sequences(void)
{
	struct replay r;

	replay_init(&r);
	feeds(&r, "\x1b[A", 100);
	KEY("csi-up", &r, 0, TUI_KEY_UP, 0, 0);
	feeds(&r, "\x1b[B", 100);
	KEY("csi-down", &r, 1, TUI_KEY_DOWN, 0, 0);
	feeds(&r, "\x1b[C", 100);
	KEY("csi-right", &r, 2, TUI_KEY_RIGHT, 0, 0);
	feeds(&r, "\x1b[D", 100);
	KEY("csi-left", &r, 3, TUI_KEY_LEFT, 0, 0);
	ok_count("csi-arrows-4ev", &r, 4);

	/* 修饰：5=Ctrl（值-1 位域），2=Shift，3=Alt */
	replay_init(&r);
	feeds(&r, "\x1b[1;5A", 100);
	KEY("csi-up-ctrl", &r, 0, TUI_KEY_UP, 0, TUI_MOD_CTRL);
	feeds(&r, "\x1b[1;2A", 100);
	KEY("csi-up-shift", &r, 1, TUI_KEY_UP, 0, TUI_MOD_SHIFT);
	feeds(&r, "\x1b[1;3D", 100);
	KEY("csi-left-alt", &r, 2, TUI_KEY_LEFT, 0, TUI_MOD_ALT);
	feeds(&r, "\x1b[1;16C", 100);
	KEY("csi-right-all", &r, 3, TUI_KEY_RIGHT, 0,
	    TUI_MOD_SHIFT | TUI_MOD_ALT | TUI_MOD_CTRL | TUI_MOD_SUPER);
	ok_count("csi-mods-4ev", &r, 4);

	/* Home/End 两式 */
	replay_init(&r);
	feeds(&r, "\x1b[H", 100);
	KEY("csi-home", &r, 0, TUI_KEY_HOME, 0, 0);
	feeds(&r, "\x1b[F", 100);
	KEY("csi-end", &r, 1, TUI_KEY_END, 0, 0);
	feeds(&r, "\x1b[1;5H", 100);
	KEY("csi-home-ctrl", &r, 2, TUI_KEY_HOME, 0, TUI_MOD_CTRL);
	ok_count("csi-home-end-3ev", &r, 3);

	/* ~ 编号键 */
	replay_init(&r);
	feeds(&r, "\x1b[5~", 100);
	KEY("csi-pgup", &r, 0, TUI_KEY_PAGEUP, 0, 0);
	feeds(&r, "\x1b[6~", 100);
	KEY("csi-pgdn", &r, 1, TUI_KEY_PAGEDOWN, 0, 0);
	feeds(&r, "\x1b[3~", 100);
	KEY("csi-delete", &r, 2, TUI_KEY_DELETE, 0, 0);
	feeds(&r, "\x1b[2~", 100);
	KEY("csi-insert", &r, 3, TUI_KEY_INSERT, 0, 0);
	feeds(&r, "\x1b[1~", 100);
	KEY("csi-home-num", &r, 4, TUI_KEY_HOME, 0, 0);
	feeds(&r, "\x1b[4~", 100);
	KEY("csi-end-num", &r, 5, TUI_KEY_END, 0, 0);
	feeds(&r, "\x1b[3;5~", 100);
	KEY("csi-delete-ctrl", &r, 6, TUI_KEY_DELETE, 0, TUI_MOD_CTRL);
	ok_count("csi-tilde-7ev", &r, 7);

	/* F 键：CSI ~ 11-24 与 SS3 P-S */
	replay_init(&r);
	feeds(&r, "\x1b[11~", 100);
	KEY("f1-tilde", &r, 0, TUI_KEY_F1, 0, 0);
	feeds(&r, "\x1b[15~", 100);
	KEY("f5-tilde", &r, 1, TUI_KEY_F5, 0, 0);
	feeds(&r, "\x1b[17~", 100);
	KEY("f6-tilde", &r, 2, TUI_KEY_F6, 0, 0);
	feeds(&r, "\x1b[24~", 100);
	KEY("f12-tilde", &r, 3, TUI_KEY_F12, 0, 0);
	feeds(&r, "\x1bOP", 100);
	KEY("f1-ss3", &r, 4, TUI_KEY_F1, 0, 0);
	feeds(&r, "\x1bOS", 100);
	KEY("f4-ss3", &r, 5, TUI_KEY_F4, 0, 0);
	ok_count("fkeys-6ev", &r, 6);

	/* SS3 方向与 Home/End（应用键盘模式） */
	replay_init(&r);
	feeds(&r, "\x1bOA", 100);
	KEY("ss3-up", &r, 0, TUI_KEY_UP, 0, 0);
	feeds(&r, "\x1bOB", 100);
	KEY("ss3-down", &r, 1, TUI_KEY_DOWN, 0, 0);
	feeds(&r, "\x1bOH", 100);
	KEY("ss3-home", &r, 2, TUI_KEY_HOME, 0, 0);
	feeds(&r, "\x1bOF", 100);
	KEY("ss3-end", &r, 3, TUI_KEY_END, 0, 0);
	ok_count("ss3-4ev", &r, 4);

	/* Backtab = shift+tab */
	replay_init(&r);
	feeds(&r, "\x1b[Z", 100);
	KEY("csi-backtab", &r, 0, TUI_KEY_TAB, 0, TUI_MOD_SHIFT);
	ok_count("backtab-1ev", &r, 1);

	/* 半截 CSI 超时 → 静默丢弃，后续字节正常 */
	replay_init(&r);
	feed(&r, "\x1b[", 2, 8000);
	tick(&r, 8100);
	ok_count("csi-stall-dropped", &r, 0);
	feeds(&r, "x", 8200);
	KEY("csi-stall-x", &r, 0, TUI_KEY_CHAR, 'x', 0);
	ok_count("csi-stall-1ev", &r, 1);
}

/* ---- kitty 协议 ---- */

static void test_kitty(void)
{
	struct replay r;
	char buf[32];
	int n;

	/* 探测回复 CSI ? <flags> u */
	replay_init(&r);
	feeds(&r, "\x1b[?5u", 100);
	ok_count("kitty-flags-1ev", &r, 1);
	ok_ev("kitty-flags-ev", &r, 0, TUI_EV_KITTY_FLAGS, 0, 5, 0, 0);

	/* 查询回显（无参数）→ flags=0 */
	replay_init(&r);
	feeds(&r, "\x1b[?u", 100);
	ok_ev("kitty-query-zero", &r, 0, TUI_EV_KITTY_FLAGS, 0, 0, 0, 0);

	/* CSI-u 键形式 */
	replay_init(&r);
	feeds(&r, "\x1b[97;5u", 100);	/* a + ctrl */
	KEY("kitty-csiu-ctrl-a", &r, 0, TUI_KEY_CHAR, 'a', TUI_MOD_CTRL);
	feeds(&r, "\x1b[27u", 100);	/* Esc */
	KEY("kitty-csiu-esc", &r, 1, TUI_KEY_ESCAPE, 0, 0);
	feeds(&r, "\x1b[13u", 100);	/* Enter */
	KEY("kitty-csiu-enter", &r, 2, TUI_KEY_RETURN, 0, 0);
	feeds(&r, "\x1b[127u", 100);	/* Backspace */
	KEY("kitty-csiu-bs", &r, 3, TUI_KEY_BACKSPACE, 0, 0);
	feeds(&r, "\x1b[9;2u", 100);	/* Tab + shift */
	KEY("kitty-csiu-shift-tab", &r, 4, TUI_KEY_TAB, 0, TUI_MOD_SHIFT);
	feeds(&r, "\x1b[233;4u", 100);	/* é + shift+alt（4→m=3→shift|alt） */
	KEY("kitty-csiu-accent", &r, 5, TUI_KEY_CHAR, 0xE9,
	    TUI_MOD_SHIFT | TUI_MOD_ALT);
	ok_count("kitty-csiu-6ev", &r, 6);

	/* modifyOtherKeys: CSI 27;mod;code ~ */
	replay_init(&r);
	feeds(&r, "\x1b[27;5;97~", 100);
	KEY("mok-ctrl-a", &r, 0, TUI_KEY_CHAR, 'a', TUI_MOD_CTRL);
	feeds(&r, "\x1b[27;3;113~", 100);	/* alt+q */
	KEY("mok-alt-q", &r, 1, TUI_KEY_CHAR, 'q', TUI_MOD_ALT);
	ok_count("mok-2ev", &r, 2);

	/* push/pop 序列生成（ESC[>1u = 5 字节） */
	n = tui_kitty_push_seq(buf, sizeof(buf), 1);
	OK(n == 5 && memcmp(buf, "\x1b[>1u", 5) == 0, "kitty-push-seq");
	n = tui_kitty_pop_seq(buf, sizeof(buf));
	OK(n == 4 && memcmp(buf, "\x1b[<u", 4) == 0, "kitty-pop-seq");
	n = tui_kitty_push_seq(buf, 2, 1);
	OK(n == -1, "kitty-push-toosmall");
}

/* ---- bracketed paste ---- */

static void test_paste(void)
{
	struct replay r;
	int i;
	int all_paste = 1;

	/* 单段完整粘贴 */
	replay_init(&r);
	feeds(&r, "\x1b[200~hello\nworld\x1b[201~", 100);
	/* START + 11 内容 + END = 13 */
	ok_count("paste-full-13ev", &r, 13);
	ok_ev("paste-start", &r, 0, TUI_EV_PASTE_START, 0, 0, 0, 0);
	PKEY("paste-h", &r, 1, TUI_KEY_CHAR, 'h', 0);
	/* 内容含换行 0x0a：字面量（paste=1），不是 ctrl+j */
	PKEY("paste-newline", &r, 6, TUI_KEY_CHAR, '\n', 0);
	PKEY("paste-w", &r, 7, TUI_KEY_CHAR, 'w', 0);
	ok_ev("paste-end", &r, 12, TUI_EV_PASTE_END, 0, 0, 0, 0);
	for (i = 1; i <= 11; i++) {
		if (r.ev[i].paste != 1 || r.ev[i].type != TUI_EV_KEY)
			all_paste = 0;
	}
	OK(all_paste, "paste-content-marked");

	/* 终止符跨 feed 切断 */
	replay_init(&r);
	feed(&r, "\x1b[200~ab\x1b[20", 12, 100);
	ok_count("paste-split-mid-3ev", &r, 3);
	feed(&r, "1~", 2, 101);
	ok_count("paste-split-4ev", &r, 4);
	ok_ev("paste-split-start", &r, 0, TUI_EV_PASTE_START, 0, 0, 0, 0);
	PKEY("paste-split-a", &r, 1, TUI_KEY_CHAR, 'a', 0);
	PKEY("paste-split-b", &r, 2, TUI_KEY_CHAR, 'b', 0);
	ok_ev("paste-split-end", &r, 3, TUI_EV_PASTE_END, 0, 0, 0, 0);

	/* 粘贴内容含中文（跨 feed 断字在粘贴内同样拼装） */
	replay_init(&r);
	feeds(&r, "\x1b[200~\xe4\xb8", 100);
	feeds(&r, "\xad\x1b[201~", 101);
	ok_count("paste-utf8-3ev", &r, 3);
	ok_ev("paste-utf8-start", &r, 0, TUI_EV_PASTE_START, 0, 0, 0, 0);
	PKEY("paste-utf8-zhong", &r, 1, TUI_KEY_CHAR, 0x4E2D, 0);
	ok_ev("paste-utf8-end", &r, 2, TUI_EV_PASTE_END, 0, 0, 0, 0);

	/* 粘贴中出现形似终止符前缀的垃圾 → 前缀回放为内容不吞 */
	replay_init(&r);
	feeds(&r, "\x1b[200~x\x1b[20y\x1b[201~", 100);
	/* START + x + (ESC [ 2 0 y 回放 5 内容) + END = 8 */
	ok_count("paste-false-prefix-8ev", &r, 8);
	PKEY("paste-fp-x", &r, 1, TUI_KEY_CHAR, 'x', 0);
	PKEY("paste-fp-esc", &r, 2, TUI_KEY_CHAR, 0x1B, 0);
	PKEY("paste-fp-bracket", &r, 3, TUI_KEY_CHAR, '[', 0);
	PKEY("paste-fp-2", &r, 4, TUI_KEY_CHAR, '2', 0);
	PKEY("paste-fp-0", &r, 5, TUI_KEY_CHAR, '0', 0);
	PKEY("paste-fp-y", &r, 6, TUI_KEY_CHAR, 'y', 0);
	ok_ev("paste-fp-end", &r, 7, TUI_EV_PASTE_END, 0, 0, 0, 0);

	/* 粘贴进行中再喂普通字节（未到终止符）→ 全是内容，无普通键 */
	replay_init(&r);
	feed(&r, "\x1b[200~z", 7, 100);
	ok_count("paste-open-2ev", &r, 2);
	PKEY("paste-open-z", &r, 1, TUI_KEY_CHAR, 'z', 0);
	OK(tui_input_pending(&r.in) == 0, "paste-open-drained");
}

/* ---- 吞噬类序列（不产事件） ---- */

static void test_swallow(void)
{
	struct replay r;

	/* OSC + BEL */
	replay_init(&r);
	feeds(&r, "\x1b]0;window title\x07x", 100);
	ok_count("osc-bel-1ev", &r, 1);
	KEY("osc-bel-x", &r, 0, TUI_KEY_CHAR, 'x', 0);

	/* OSC + ST (ESC \) */
	replay_init(&r);
	feeds(&r, "\x1b]11;rgb:0000/0000/0000\x1b\\y", 100);
	ok_count("osc-st-1ev", &r, 1);
	KEY("osc-st-y", &r, 0, TUI_KEY_CHAR, 'y', 0);

	/* DCS（ESC P ... ST） */
	replay_init(&r);
	feeds(&r, "\x1bP+q544e\x1b\\z", 100);
	ok_count("dcs-1ev", &r, 1);
	KEY("dcs-z", &r, 0, TUI_KEY_CHAR, 'z', 0);

	/* B5：SGR 鼠标 → 真事件（press@10,20 + release@10,20） */
	replay_init(&r);
	feeds(&r, "\x1b[<0;10;20M", 100);
	feeds(&r, "\x1b[<0;10;20m", 100);
	ok_count("mouse-sgr-2ev", &r, 2);
	ok_ev("mouse-sgr-press", &r, 0, TUI_EV_MOUSE,
	      TUI_MOUSE_PRESS, 0, 0, 0);
	OK(r.ev[0].mx == 10 && r.ev[0].my == 20, "mouse-sgr-coords");
	ok_ev("mouse-sgr-release", &r, 1, TUI_EV_MOUSE,
	      TUI_MOUSE_RELEASE, 0, 0, 0);

	/* SGR 修饰位（cb=1+4+8=13 → middle+shift+alt press@1,2） */
	replay_init(&r);
	feeds(&r, "\x1b[<13;1;2M", 100);
	ok_count("mouse-sgr-mods-1ev", &r, 1);
	ok_ev("mouse-sgr-mods", &r, 0, TUI_EV_MOUSE, TUI_MOUSE_PRESS, 1,
	      TUI_MOD_SHIFT | TUI_MOD_ALT, 0);

	/* SGR 滚轮（cb=64 上 / 65 下） */
	replay_init(&r);
	feeds(&r, "\x1b[<64;5;6M\x1b[<65;5;6M", 100);
	ok_count("mouse-sgr-wheel-2ev", &r, 2);
	ok_ev("mouse-wheel-up", &r, 0, TUI_EV_MOUSE, TUI_MOUSE_WHEEL_UP,
	      0, 0, 0);
	ok_ev("mouse-wheel-down", &r, 1, TUI_EV_MOUSE, TUI_MOUSE_WHEEL_DOWN,
	      1, 0, 0);

	/* SGR 拖动（cb=32+0 motion；仅开 motion 报告的终端才发） */
	replay_init(&r);
	feeds(&r, "\x1b[<32;7;8M", 100);
	ok_count("mouse-sgr-motion-1ev", &r, 1);
	ok_ev("mouse-motion", &r, 0, TUI_EV_MOUSE, TUI_MOUSE_MOTION, 0,
	      0, 0);

	/* SGR 后恢复正常解析 */
	replay_init(&r);
	feeds(&r, "\x1b[<0;1;1Mm", 100);
	ok_count("mouse-sgr-then-key-2ev", &r, 2);

	/* B5：X10 鼠标（ESC [ M + 3 原始字节）→ press 事件（无 release）
	 * b0=32+0 左键、b1=32+9=41→列 9、b2=32+5→行 5 */
	replay_init(&r);
	{
		uint8_t x10[6] = { 0x1b, '[', 'M', 32, 32 + 9, 32 + 5 };

		feed(&r, (const char *)x10, 6, 100);
	}
	ok_count("mouse-x10-1ev", &r, 1);
	ok_ev("mouse-x10-press", &r, 0, TUI_EV_MOUSE, TUI_MOUSE_PRESS, 0,
	      0, 0);
	OK(r.ev[0].mx == 9 && r.ev[0].my == 5, "mouse-x10-coords");

	/* X10 滚轮（b0=32+64=96）→ WHEEL_UP */
	replay_init(&r);
	{
		uint8_t x10[6] = { 0x1b, '[', 'M', 32 + 64, 33, 34 };

		feed(&r, (const char *)x10, 6, 100);
	}
	ok_count("mouse-x10-wheel-1ev", &r, 1);
	ok_ev("mouse-x10-wheel", &r, 0, TUI_EV_MOUSE, TUI_MOUSE_WHEEL_UP,
	      0, 0, 0);

	/* 收 3 字节后恢复正常解析 */
	replay_init(&r);
	feed(&r, "\x1b[MxyzQ", 7, 100);
	ok_count("mouse-x10-then-key-2ev", &r, 2);
	ok_ev("mouse-x10-then-Q", &r, 1, TUI_EV_KEY, TUI_KEY_CHAR, 'Q',
	      0, 0);

	/* keystr：mouse-* 规范名 */
	{
		tui_event me;
		char buf[32];

		memset(&me, 0, sizeof(me));
		me.type = TUI_EV_MOUSE;
		me.key = TUI_MOUSE_WHEEL_DOWN;
		OK(tui_event_keystr(&me, buf, sizeof(buf)) > 0 &&
		   !strcmp(buf, "mouse-wheel-down"), "mouse-keystr-wheel");
		me.key = TUI_MOUSE_PRESS;
		OK(tui_event_keystr(&me, buf, sizeof(buf)) > 0 &&
		   !strcmp(buf, "mouse-press"), "mouse-keystr-press");
	}

	/* 焦点进出 */
	replay_init(&r);
	feeds(&r, "\x1b[I\x1b[Ow", 100);
	ok_count("focus-1ev", &r, 1);
	KEY("focus-after", &r, 0, TUI_KEY_CHAR, 'w', 0);

	/* DEC 私有（?25h 应答之类）吞掉 */
	replay_init(&r);
	feeds(&r, "\x1b[?1049hv", 100);
	ok_count("decprivate-1ev", &r, 1);
	KEY("decprivate-after", &r, 0, TUI_KEY_CHAR, 'v', 0);
}

/* ---- 队列溢出 ---- */

static void test_overflow(void)
{
	struct replay r;
	char big[600];
	int i;

	for (i = 0; i < 600; i++)
		big[i] = 'x';
	replay_init(&r);
	tui_input_feed(&r.in, big, 600, 100);
	OK(tui_input_pending(&r.in) == TUI_INPUT_QMAX, "overflow-cap");
	OK(r.in.dropped == 600 - TUI_INPUT_QMAX, "overflow-dropped-count");
	/* 消费完 → pending 0 */
	{
		tui_event e;
		while (tui_input_next(&r.in, &e))
			;
		OK(tui_input_pending(&r.in) == 0, "overflow-drain");
	}
}

/* ---- keybind 字符串（OCD 对接面） ---- */

static void test_keystr(void)
{
	char buf[64];
	tui_event e;
	int n;

	memset(&e, 0, sizeof(e));
	e.type = TUI_EV_KEY;

	e.key = TUI_KEY_CHAR;
	e.ch = 'c';
	e.mods = TUI_MOD_CTRL;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 6 && strcmp(buf, "ctrl+c") == 0, "keystr-ctrl-c");

	e.ch = 'f';
	e.mods = TUI_MOD_ALT;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 5 && strcmp(buf, "alt+f") == 0, "keystr-alt-f");

	e.ch = 'x';
	e.mods = TUI_MOD_CTRL | TUI_MOD_SHIFT;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 12 && strcmp(buf, "ctrl+shift+x") == 0, "keystr-ctrl-shift-x");

	e.ch = 'z';
	e.mods = TUI_MOD_ALT | TUI_MOD_CTRL;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 10 && strcmp(buf, "ctrl+alt+z") == 0, "keystr-ctrl-alt-z");

	e.ch = 'a';
	e.mods = TUI_MOD_ALT | TUI_MOD_CTRL | TUI_MOD_SHIFT | TUI_MOD_SUPER;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 22 && strcmp(buf, "ctrl+alt+super+shift+a") == 0,
	   "keystr-all-mods");

	e.ch = ' ';
	e.mods = 0;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 5 && strcmp(buf, "space") == 0, "keystr-space");

	e.ch = ' ';
	e.mods = TUI_MOD_CTRL;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 10 && strcmp(buf, "ctrl+space") == 0, "keystr-ctrl-space");

	e.ch = 0x4E2D;			/* 中 */
	e.mods = 0;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 3 && strcmp(buf, "\xe4\xb8\xad") == 0, "keystr-cjk");

	e.ch = 'q';
	e.mods = 0;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 1 && strcmp(buf, "q") == 0, "keystr-plain");

	/* 命名键（keymap 别名归一的目标形） */
	e.key = TUI_KEY_RETURN;
	e.mods = 0;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 6 && strcmp(buf, "return") == 0, "keystr-return");

	e.key = TUI_KEY_ESCAPE;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 6 && strcmp(buf, "escape") == 0, "keystr-escape");

	e.key = TUI_KEY_PAGEUP;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 6 && strcmp(buf, "pageup") == 0, "keystr-pageup");

	e.key = TUI_KEY_PAGEDOWN;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 8 && strcmp(buf, "pagedown") == 0, "keystr-pagedown");

	e.key = TUI_KEY_TAB;
	e.mods = TUI_MOD_SHIFT;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 9 && strcmp(buf, "shift+tab") == 0, "keystr-shift-tab");

	e.key = TUI_KEY_UP;
	e.mods = TUI_MOD_ALT;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 6 && strcmp(buf, "alt+up") == 0, "keystr-alt-up");

	e.key = TUI_KEY_F2;
	e.mods = 0;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 2 && strcmp(buf, "f2") == 0, "keystr-f2");

	e.key = TUI_KEY_HOME;
	e.mods = TUI_MOD_CTRL;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 9 && strcmp(buf, "ctrl+home") == 0, "keystr-ctrl-home");

	e.key = TUI_KEY_BACKSPACE;
	e.mods = 0;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 9 && strcmp(buf, "backspace") == 0, "keystr-backspace");

	/* 非键事件 */
	e.type = TUI_EV_PASTE_START;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 11 && strcmp(buf, "paste-start") == 0, "keystr-paste-start");

	e.type = TUI_EV_PASTE_END;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 9 && strcmp(buf, "paste-end") == 0, "keystr-paste-end");

	e.type = TUI_EV_KITTY_FLAGS;
	n = tui_event_keystr(&e, buf, sizeof(buf));
	OK(n == 11 && strcmp(buf, "kitty-flags") == 0, "keystr-kitty-flags");

	/* cap 不足 → -1 */
	e.type = TUI_EV_KEY;
	e.key = TUI_KEY_PAGEDOWN;
	e.mods = 0;
	n = tui_event_keystr(&e, buf, 4);
	OK(n == -1, "keystr-toosmall");

	/* NULL 参数 → -1 */
	OK(tui_event_keystr(NULL, buf, sizeof(buf)) == -1, "keystr-null-ev");
	OK(tui_event_keystr(&e, NULL, 10) == -1, "keystr-null-buf");
}

/* ---- 可配置超时 ---- */

static void test_timeout_config(void)
{
	struct replay r;

	replay_init(&r);
	tui_input_set_esc_timeout(&r.in, 50);
	feed(&r, "\x1b", 1, 0);
	tick(&r, 49);
	ok_count("cfg-timeout-49", &r, 0);
	tick(&r, 50);
	ok_count("cfg-timeout-50", &r, 1);
	KEY("cfg-timeout-key", &r, 0, TUI_KEY_ESCAPE, 0, 0);

	/* 0 → 回落默认 25 */
	tui_input_set_esc_timeout(&r.in, 0);
	OK(r.in.esc_timeout_ms == 25, "cfg-timeout-zero-fallback");
}

int main(void)
{
	test_plain();
	test_controls();
	test_esc();
	test_sequences();
	test_kitty();
	test_paste();
	test_swallow();
	test_overflow();
	test_keystr();
	test_timeout_config();
	printf("test_input: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
