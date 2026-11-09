/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_view.c - occ TUI 视图框架实现（T9c2）
 *
 * 事件队列：互斥环（QMAX）+ 自唤醒 pipe（post 后写 1 字节，主循环
 * poll(stdin ∪ pipe) 立即醒来 drain）。队列满 → cond_timedwait 让主循环
 * 排空；三连超时才丢弃（dropped 计数，测试断言用）。closing 置位后
 * post 立即失败——防 shutdown join 时 worker 卡在满队列上死锁。
 *
 * 主循环：drain → resize → 帧门渲染（dirty && frame_due，30fps）→
 * 算 poll 超时（frame_wait / 运行中 33ms / Esc 结算截止）→ poll →
 * 喂字节/排空 pipe → 派发键事件 → tui_input_tick（孤立 Esc 结算）。
 */
#define _DEFAULT_SOURCE 1
#include "tui_view.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "tui_chat.h"
#include "tui_frame.h"
#include "tui_input.h"
#include "tui_inputbox.h"
#include "tui_usage.h"
#include "tui_utf8.h"

#define TV_QMAX 512		/* 事件环容量（33ms drain 一次，远够） */
#define TV_WAIT_MS 100		/* 队列满单次 cond 等待 */
#define TV_WAIT_TRIES 3		/* 超时次数上限 → 丢弃 */

typedef struct {
	int kind;
	char *text;			/* heap 拷贝（sink 合同：回调后失效） */
	char *arg;
	size_t len;
	int rc;
} tv_ev;

struct tui_view {
	tui_view_hooks hooks;
	tui_theme th;
	tui_term term;
	tui_input input;
	tui_frame frame;
	tui_renderer *ren;
	tui_chat *chat;
	tui_inputbox *ib;
	tui_sb_data sb_data;
	int running;			/* turn 进行中（submit 接受→TURN_END） */
	int interrupted;		/* 本 turn 收到过 Esc 中断请求 */
	int quit;
	int closing;			/* 置位后 post 拒收（shutdown 死锁防护） */
	int dirty_needed;		/* 下帧门到期时重绘 */
	int tr_h;			/* 上帧转写区高（PgUp/PgDn 翻页量） */
	/* T9c3：覆盖层 + 键位表 + leader 序列 */
	tui_overlay *ov;
	tui_keymap *km;
	int leader_pending;		/* leader 键已按、等续键（2s 超时） */
	uint64_t leader_deadline;
	int cursor_hidden;		/* 列表覆盖层隐藏光标（成对恢复） */
	char init_notice[2][320];	/* theme/keymap 回落 notice（进屏后打） */
	/* 事件环（worker post / 主循环 drain） */
	pthread_mutex_t qm;
	pthread_cond_t qc;
	tv_ev q[TV_QMAX];
	int qh, qn;
	unsigned long dropped;
	int wake[2];			/* 自唤醒 pipe（非阻塞） */
};

/* ---- 小工具 ---- */

static uint64_t tv_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static void tv_deadline(struct timespec *ts, long ms)
{
	clock_gettime(CLOCK_REALTIME, ts);
	ts->tv_nsec += ms * 1000000L;
	while (ts->tv_nsec >= 1000000000L) {
		ts->tv_sec++;
		ts->tv_nsec -= 1000000000L;
	}
}

/* ---- 事件队列 ---- */

static void tv_free_ev(tv_ev *e)
{
	free(e->text);
	free(e->arg);
	e->text = NULL;
	e->arg = NULL;
}

static void footer_degrade(char *fb, size_t cap, int cols);

int tui_view_post(tui_view *v, int kind, const char *text, size_t len,
		  const char *arg, int rc)
{
	tv_ev *slot;
	int tries = 0;
	char b = 'x';

	if (!v)
		return -1;
	pthread_mutex_lock(&v->qm);
	while (v->qn >= TV_QMAX && !v->closing) {
		struct timespec ts;

		tv_deadline(&ts, TV_WAIT_MS);
		if (pthread_cond_timedwait(&v->qc, &v->qm, &ts) == ETIMEDOUT &&
		    ++tries >= TV_WAIT_TRIES) {
			v->dropped++;
			pthread_mutex_unlock(&v->qm);
			return -2;
		}
	}
	if (v->closing) {
		pthread_mutex_unlock(&v->qm);
		return -1;
	}
	slot = &v->q[(v->qh + v->qn) % TV_QMAX];
	slot->kind = kind;
	slot->rc = rc;
	slot->len = len;
	slot->text = NULL;
	slot->arg = NULL;
	if (text) {
		slot->text = strndup(text, len ? len : strlen(text));
		if (!slot->text) {
			v->dropped++;
			pthread_mutex_unlock(&v->qm);
			return -2;
		}
		if (!len)
			slot->len = strlen(slot->text);
	}
	if (arg) {
		slot->arg = strdup(arg);
		if (!slot->arg) {
			free(slot->text);
			slot->text = NULL;
			v->dropped++;
			pthread_mutex_unlock(&v->qm);
			return -2;
		}
	}
	v->qn++;
	pthread_mutex_unlock(&v->qm);
	/* 自唤醒：字节失败仅意味着 pipe 已满=已有待处理唤醒，可忽略 */
	if (write(v->wake[1], &b, 1) < 0 && errno != EAGAIN) {
		/* 尽力而为 */
	}
	return 0;
}

/* 排空事件环到本地并应用到 chat 模型；返回是否有事件 */
static int tv_drain(tui_view *v)
{
	tv_ev local[TV_QMAX];
	int n = 0;
	int i;
	int freed_space = 0;

	pthread_mutex_lock(&v->qm);
	while (v->qn > 0) {
		tv_ev *src = &v->q[v->qh];

		local[n++] = *src;
		v->qh = (v->qh + 1) % TV_QMAX;
		v->qn--;
	}
	if (n > 0)
		freed_space = 1;
	pthread_mutex_unlock(&v->qm);
	if (freed_space)
		pthread_cond_signal(&v->qc);	/* 唤醒满队列等待者 */

	for (i = 0; i < n; i++) {
		tv_ev *e = &local[i];

		switch (e->kind) {
		case TUI_VIEW_TEXT:
			if (e->text && e->len)
				tui_chat_append_text(v->chat, e->text, e->len);
			break;
		case TUI_VIEW_REASONING:
			if (e->text && e->len)
				tui_chat_append_reasoning(v->chat, e->text,
							 e->len);
			break;
		case TUI_VIEW_TOOL_START:
			if (e->text)
				tui_chat_tool_start(v->chat, e->text, e->arg);
			break;
		case TUI_VIEW_TOOL_END:
			if (e->text)
				tui_chat_tool_end(v->chat, e->text, e->arg,
						  e->rc);
			break;
		case TUI_VIEW_NOTICE:
			if (e->text)
				tui_chat_add_notice(v->chat, e->text);
			break;
		case TUI_VIEW_RESET:
			/* 中断导致的 EINTR 读错会被传输层分级为可重试 →
			 * 发 RESET；但本轮不会再重发——若照清，已流出的
			 * 正文被抹、空块又被 TURN_END 丢弃（footer 丢失）。
			 * 中断请求后到达的 RESET 一律忽略；真重试（无中断）
			 * 不受影响。 */
			if (!v->interrupted)
				tui_chat_reset_live(v->chat);
			break;
		case TUI_VIEW_TURN_END: {
			char fb[192];
			int cols = 80;

			v->running = 0;
			snprintf(fb, sizeof(fb), "%s", e->text ? e->text : "");
			if (v->ren) {
				tui_screen *s = tui_renderer_front(v->ren);

				if (s)
					cols = s->cols;
			}
			footer_degrade(fb, sizeof(fb), cols);
			tui_chat_end_assistant(v->chat, fb);
			/* 主线程拉会话快照（无并发写：worker 已收口） */
			if (v->hooks.fill_sessions)
				v->hooks.fill_sessions(v->hooks.ud,
						       &v->sb_data);
			break;
		}
		default:
			break;
		}
		tv_free_ev(e);
	}
	return n > 0;
}

unsigned long tui_view_dropped(const tui_view *v)
{
	return v ? v->dropped : 0;
}

/* ---- 会话快照 ---- */

static void tv_pull_sessions(tui_view *v)
{
	if (v->hooks.fill_sessions)
		v->hooks.fill_sessions(v->hooks.ud, &v->sb_data);
}

/* ---- 命令 ---- */

/* /help 文本（动态：exit 绑定与 leader 取自 keymap——覆盖文件生效后不撒谎；
 * /compact//shell 语义与 occ.c 实现对齐：换窗=occ_ac_compact_now
 * （前置门：OCC_AC=on、turn 空闲、已有会话）、/shell=退屏跑 bash 后重建 view） */
static void tv_help_text(tui_view *v, char *buf, size_t cap)
{
	char exitb[96];

	exitb[0] = '\0';
	if (v->km)
		(void)tui_keymap_binding_str(v->km, "app.exit", exitb,
					     sizeof(exitb));
	snprintf(buf, cap,
		 "commands: /exit /clear /help (built-in) · /new /sessions"
		 " /status /models /rename /tools /sandbox /trace /lease"
		 " /compact /shell (live)\n"
		 "/compact: 手动触发 autocondense 换窗——历史折叠为摘要、"
		 "token 账本重置为新基线（需 OCC_AC=on、turn 空闲、已有会话）\n"
		 "/shell: 临时退到 bash，exit 返回 occ（turn 运行中拒绝）\n"
		 "keys: Enter=send · Tab=complete · Esc=interrupt ·"
		 " PgUp/PgDn=scroll · exit=%s · leader=%s (2s timeout;"
		 " ~/.occ/keymap 可覆盖) · overlay: ↑↓/PgUp/PgDn/Home/End"
		 " 导航 · Enter 确认 · Esc 关闭 · 输入即过滤",
		 exitb[0] ? exitb : "ctrl+c, ctrl+d",
		 v->km ? tui_keymap_leader(v->km) : "ctrl+x");
}

static void tv_quit(tui_view *v)
{
	char b = 'q';

	v->quit = 1;
	/* 唤醒可能阻塞在 poll(-1) 的主循环 */
	if (write(v->wake[1], &b, 1) < 0 && errno != EAGAIN) {
		/* 尽力而为 */
	}
}

void tui_view_quit(tui_view *v)
{
	if (v)
		tv_quit(v);
}

void tui_view_notice(tui_view *v, const char *text)
{
	if (!v || !text)
		return;
	tui_chat_add_notice(v->chat, text);
	v->dirty_needed = 1;
}

static void tv_submit(tui_view *v)
{
	size_t len = 0;
	const char *text = tui_inputbox_text(v->ib, &len);
	int rc;

	if (len == 0)
		return;
	/* 整行退出词（OCD §2.5） */
	if (strcmp(text, "exit") == 0 || strcmp(text, "quit") == 0 ||
	    strcmp(text, ":q") == 0) {
		tui_inputbox_clear(v->ib);
		tv_quit(v);
		return;
	}
	if (text[0] == '/') {
		if (strcmp(text, "/exit") == 0) {
			tui_inputbox_clear(v->ib);
			tv_quit(v);
			return;
		}
		if (strcmp(text, "/clear") == 0) {
			tui_chat_clear(v->chat);
			tui_inputbox_clear(v->ib);
			v->dirty_needed = 1;
			return;
		}
		if (strcmp(text, "/help") == 0) {
			char help[800];	/* 最坏 ~720B（exitb≤95 + leader≤47） */

			tv_help_text(v, help, sizeof(help));
			tui_chat_add_notice(v->chat, help);
			tui_inputbox_clear(v->ib);
			v->dirty_needed = 1;
			return;
		}
		rc = v->hooks.on_command ?
		     v->hooks.on_command(v->hooks.ud, text) : 1;
		if (rc != 0) {
			char buf[320];

			snprintf(buf, sizeof(buf),
				 "unknown command: %.240s (try /help)", text);
			tui_chat_add_notice(v->chat, buf);
		} else {
			tv_pull_sessions(v);
		}
		tui_inputbox_clear(v->ib);
		v->dirty_needed = 1;
		return;
	}
	if (v->running) {
		tui_chat_add_notice(v->chat,
				    "busy — turn running (Esc to interrupt)");
		v->dirty_needed = 1;
		return;
	}
	if (!v->hooks.on_submit ||
	    v->hooks.on_submit(v->hooks.ud, text, len) != 0) {
		tui_chat_add_notice(v->chat, "submit failed (busy?)");
		v->dirty_needed = 1;
		return;
	}
	tui_chat_add_user(v->chat, text, len);
	tui_chat_begin_assistant(v->chat);
	tui_chat_jump_latest(v->chat);
	tui_inputbox_clear(v->ib);
	v->running = 1;
	v->interrupted = 0;		/* 新 turn：解除 RESET 过滤 */
	v->dirty_needed = 1;
}

/* ---- 键事件派发（T9c3：keymap 动作层 + 覆盖层模态 + 输入框编辑层） ---- */

/* 合成 slash 命令 → on_command 现有路径（/new /sessions /models …） */
static void tv_run_command(tui_view *v, const char *cmd)
{
	int rc = v->hooks.on_command ?
		 v->hooks.on_command(v->hooks.ud, cmd) : 1;

	if (rc != 0) {
		char buf[320];

		snprintf(buf, sizeof(buf),
			 "unknown command: %.240s (try /help)", cmd);
		tui_chat_add_notice(v->chat, buf);
	} else {
		tv_pull_sessions(v);
	}
}

/*
 * 执行 BASE 动作。is_exit/is_clear=该键是否绑在两个退出类动作上
 * （普通路径查表得；leader 路径按动作名推导）——「空=退出/有字=清空」
 * 语义分裂与 c2 逐键等价，app.exit 有字=失效（OCD §2.5）。
 */
static void tv_exec_action(tui_view *v, const char *act, int is_exit,
			   int is_clear)
{
	if (!strcmp(act, "app.exit") || !strcmp(act, "prompt.clear")) {
		int empty = tui_inputbox_empty(v->ib);

		if (!empty && is_clear) {
			tui_inputbox_clear(v->ib);
			return;
		}
		if (is_exit && empty) {
			tv_quit(v);
			return;
		}
		return;		/* 其余组合：无操作（不误退不误清） */
	}
	if (!strcmp(act, "session.interrupt")) {
		if (v->running && v->hooks.on_interrupt) {
			v->interrupted = 1;
			v->hooks.on_interrupt(v->hooks.ud);
		}
		return;
	}
	if (!strcmp(act, "session.page.up")) {
		tui_chat_scroll(v->chat, v->tr_h > 0 ? v->tr_h : 10);
		return;
	}
	if (!strcmp(act, "session.page.down")) {
		tui_chat_scroll(v->chat, -(v->tr_h > 0 ? v->tr_h : 10));
		return;
	}
	if (!strcmp(act, "session.new")) {
		tv_run_command(v, "/new");
		return;
	}
	if (!strcmp(act, "session.list")) {
		tv_run_command(v, "/sessions");
		return;
	}
	if (!strcmp(act, "model.list")) {
		tv_run_command(v, "/models");
		return;
	}
	if (!strcmp(act, "session.rename")) {
		tv_run_command(v, "/rename");
		return;
	}
	if (!strcmp(act, "session.compact")) {
		tv_run_command(v, "/compact");
		return;
	}
	if (!strcmp(act, "opencode.status")) {
		tv_run_command(v, "/status");
		return;
	}
}

/* 覆盖层模态键（dialog.* 导航/确认/关闭 + 模型框行内动作 + 字符输入） */
static void tv_dispatch_overlay(tui_view *v, const tui_event *ev,
				const char *ks, int has_ks)
{
	const char *act = has_ks ?
			 tui_keymap_lookup(v->km, ks, TUI_KM_CTX_OVERLAY) :
			 NULL;

	if (act) {
		if (!strcmp(act, "dialog.close")) {
			if (v->hooks.on_overlay_close)
				v->hooks.on_overlay_close(v->hooks.ud,
							  tui_overlay_id(v->ov));
			tui_overlay_clear(v->ov);
			v->dirty_needed = 1;
			return;
		}
		if (!strcmp(act, "dialog.select.submit")) {
			if (tui_overlay_is_input(v->ov)) {
				size_t l = 0;
				const char *txt =
					tui_overlay_input_text(v->ov, &l);

				if (v->hooks.on_overlay_input)
					(void)v->hooks.on_overlay_input(
						v->hooks.ud,
						tui_overlay_id(v->ov), txt,
						l);
			} else {
				int idx = tui_overlay_submit_idx(v->ov);

				if (idx < 0) {
					tui_overlay_status(v->ov,
							   "无可选项", 1);
				} else if (!v->hooks.on_overlay_submit) {
					tui_overlay_status(v->ov,
							   "无处理器", 1);
				} else if (v->hooks.on_overlay_submit(
						   v->hooks.ud,
						   tui_overlay_id(v->ov),
						   idx) != 0) {
					tui_overlay_status(v->ov,
							   "该条目不可用",
							   1);
				} else {
					tv_pull_sessions(v);
				}
			}
			v->dirty_needed = 1;
			return;
		}
		if (!strcmp(act, "dialog.select.prev")) {
			(void)tui_overlay_nav(v->ov, -1);
			v->dirty_needed = 1;
			return;
		}
		if (!strcmp(act, "dialog.select.next")) {
			(void)tui_overlay_nav(v->ov, 1);
			v->dirty_needed = 1;
			return;
		}
		if (!strcmp(act, "dialog.select.page_up")) {
			(void)tui_overlay_page(v->ov, -1);
			v->dirty_needed = 1;
			return;
		}
		if (!strcmp(act, "dialog.select.page_down")) {
			(void)tui_overlay_page(v->ov, 1);
			v->dirty_needed = 1;
			return;
		}
		if (!strcmp(act, "dialog.select.home")) {
			(void)tui_overlay_home(v->ov);
			v->dirty_needed = 1;
			return;
		}
		if (!strcmp(act, "dialog.select.end")) {
			(void)tui_overlay_end(v->ov);
			v->dirty_needed = 1;
			return;
		}
		if (!strcmp(act, "model.add") ||
		    !strcmp(act, "model.favorite")) {
			int idx = tui_overlay_submit_idx(v->ov);
			int rc = v->hooks.on_overlay_key ?
				 v->hooks.on_overlay_key(v->hooks.ud,
							  tui_overlay_id(v->ov),
							  act, idx) : 1;

			if (rc != 0)
				tui_overlay_status(v->ov,
						   "此覆盖层不支持该动作", 1);
			v->dirty_needed = 1;
			return;
		}
		v->dirty_needed = 1;	/* 其余已绑动作：面板吞 */
		return;
	}
	/* 无动作 → 字符进过滤/输入缓冲（输入态与可过滤列表） */
	if (ev->key == TUI_KEY_CHAR) {
		uint8_t u[4];
		size_t n;

		if (ev->mods & (TUI_MOD_CTRL | TUI_MOD_ALT | TUI_MOD_SUPER))
			return;
		if (ev->ch < 0x20 || ev->ch == 0x7f)
			return;
		n = tui_utf8_encode(ev->ch, u);
		if (n)
			(void)tui_overlay_type(v->ov, (const char *)u, n);
		v->dirty_needed = 1;
		return;
	}
	if (ev->key == TUI_KEY_BACKSPACE) {
		(void)tui_overlay_backspace(v->ov);
		v->dirty_needed = 1;
		return;
	}
	/* 其余键（未绑定的 return/方向键等）：模态吞掉 */
}

static void tv_dispatch(tui_view *v, const tui_event *ev)
{
	char ks[96];
	int klen;
	int act_domain;

	if (ev->type != TUI_EV_KEY)
		return;			/* paste-start/end、kitty flags 忽略 */
	klen = tui_event_keystr(ev, ks, sizeof(ks));
	if (klen < 0) {
		ks[0] = '\0';
		klen = 0;
	}

	/* 覆盖层模态优先（对话框内 session.interrupt 等不穿透） */
	if (tui_overlay_active(v->ov)) {
		tv_dispatch_overlay(v, ev, ks, klen > 0);
		return;
	}

	/* leader 序列：2s 超时（主循环结算）、Esc 取消、无匹配取消并重放 */
	if (v->leader_pending) {
		if (ev->key == TUI_KEY_ESCAPE) {
			v->leader_pending = 0;
			return;
		}
		if (klen > 0) {
			const char *lact =
				tui_keymap_lookup_leader(v->km, ks);

			if (lact) {
				v->leader_pending = 0;
				tv_exec_action(v, lact,
					       !strcmp(lact, "app.exit"),
					       !strcmp(lact,
						       "prompt.clear"));
				v->dirty_needed = 1;
				return;
			}
		}
		v->leader_pending = 0;	/* 取消；本键按普通键继续 */
	}
	if (klen > 0 && !strcmp(ks, tui_keymap_leader(v->km))) {
		v->leader_pending = 1;
		v->leader_deadline = tv_now_ms() +
			(uint64_t)tui_keymap_leader_timeout_ms(v->km);
		return;
	}

	/* keymap 动作层（BASE 上下文） */
	if (klen > 0) {
		const char *act =
			tui_keymap_lookup(v->km, ks, TUI_KM_CTX_BASE);

		if (act) {
			tv_exec_action(v, act,
				       tui_keymap_matches(v->km, "app.exit",
							  ks,
							  TUI_KM_CTX_BASE),
				       tui_keymap_matches(v->km,
							  "prompt.clear", ks,
							  TUI_KM_CTX_BASE));
			v->dirty_needed = 1;
			return;
		}
	}
	/* 动作域键（escape/pgup/pgdn/ctrl+c/ctrl+d）未绑定=keymap 权威：
	 * 吞掉不落回输入框（覆盖 c2 的硬编码路径；单测直调输入框不受影响） */
	act_domain = klen > 0 && (!strcmp(ks, "escape") ||
				  !strcmp(ks, "pageup") ||
				  !strcmp(ks, "pagedown") ||
				  !strcmp(ks, "ctrl+c") ||
				  !strcmp(ks, "ctrl+d"));
	if (act_domain)
		return;

	/* 输入框编辑层（字符/光标/Tab/return/ctrl+j——c2 内置，裁定 3） */
	{
		int act = tui_inputbox_key(v->ib, ev);

		switch (act) {
		case TUI_IN_SUBMIT:
			tv_submit(v);
			break;
		case TUI_IN_EXIT:
			tv_quit(v);
			break;
		case TUI_IN_CLEAR:
			v->dirty_needed = 1;
			break;
		case TUI_IN_SCROLL_UP:
			tui_chat_scroll(v->chat, v->tr_h > 0 ? v->tr_h : 10);
			v->dirty_needed = 1;
			break;
		case TUI_IN_SCROLL_DOWN:
			tui_chat_scroll(v->chat,
					-(v->tr_h > 0 ? v->tr_h : 10));
			v->dirty_needed = 1;
			break;
		default:
			v->dirty_needed = 1;
			break;
		}
	}
}

static void tv_drain_keys(tui_view *v)
{
	tui_event ev;

	while (tui_input_next(&v->input, &ev))
		tv_dispatch(v, &ev);
}

/* ---- 渲染 ---- */

/* 裁定 7：assistant 尾行宽度降级——<36 去时长段、<28 再去 model 段。
 * footer 由 occ.c 生成 "OCC · model · 1.2s · 34.5 tok/s"，以 " · "
 * （U+00B7 两侧空格，4 字节）为分隔切段，不能按字符集 strtok。 */
static void footer_degrade(char *fb, size_t cap, int cols)
{
	char parts[4][96];
	int np = 0;
	char tmp[192];
	char *p;

	if (cols >= 36 || !fb || !fb[0])
		return;
	snprintf(tmp, sizeof(tmp), "%s", fb);
	p = tmp;
	while (np < 4) {
		char *sep = strstr(p, " · ");
		size_t n = sep ? (size_t)(sep - p) : strlen(p);

		if (n >= sizeof(parts[0]))
			n = sizeof(parts[0]) - 1;
		memcpy(parts[np], p, n);
		parts[np][n] = '\0';
		np++;
		if (!sep)
			break;
		p = sep + 4;		/* " · " = 1+3(U+00B7)+1? 实为1+2+1=4 */
	}
	if (np < 4)
		return;			/* 段数不足（如 OCC · interrupted） */
	if (cols < 28)			/* 去 model+时长：OCC · tok/s */
		snprintf(fb, cap, "%.40s · %.80s", parts[0], parts[3]);
	else			/* 28..35 去时长：OCC · model · tok/s */
		snprintf(fb, cap, "%.40s · %.60s · %.70s", parts[0],
			 parts[1], parts[3]);
}

static void tv_render(tui_view *v, uint64_t now)
{
	tui_screen *s = tui_renderer_front(v->ren);
	int rows = s->rows, cols = s->cols;
	int sbw, mx, mw;
	int status_y, input_h, input_y, meta_y, tr_h;
	int cr = 0, cc = 0;
	char buf[256];
	tui_attr a_muted = tui_thm_muted();
	tui_attr a_err = tui_thm_attr(TUI_THM_ERROR, TUI_THM_BG, 0);
	tui_attr a_warn = tui_thm_attr(TUI_THM_WARN, TUI_THM_BG, 0);

	/* 底色填充（renderer 与 back 逐行 diff，未变行零字节） */
	tui_screen_fill(s, tui_thm_plain());

	/* 布局：侧栏 22 列（宽 <60 隐藏）| 主列 */
	sbw = (cols >= TUI_SB_MIN_COLS) ? TUI_SB_WIDTH : 0;
	mx = sbw;
	mw = cols - sbw;
	if (mw < 8) {
		mx = 0;
		mw = cols;
		sbw = 0;
	}

	/* 纵向：转写区 / 元数据行 / 输入框 / 状态行 */
	status_y = rows - 1;
	input_h = tui_inputbox_lines(v->ib);
	{
		int max_ih = rows / 3;

		if (max_ih < 1)
			max_ih = 1;
		if (max_ih > 8)
			max_ih = 8;
		if (input_h > max_ih)
			input_h = max_ih;
		if (input_h > rows - 3)
			input_h = rows - 3;
		if (input_h < 1)
			input_h = 1;
	}
	input_y = status_y - input_h;
	meta_y = input_y - 1;
	tr_h = meta_y;
	if (tr_h < 0)
		tr_h = 0;
	v->tr_h = tr_h;

	/* 侧栏 */
	if (sbw > 0)
		tui_sidebar_render(&v->sb_data, s, rows, &v->th);

	/* 转写区（chat 内部按宽度自适应 rewidth） */
	if (tr_h > 0 && mw > 0)
		tui_chat_render(v->chat, s, mx, 0, mw, tr_h, now);

	/* 元数据行：fill_meta 给主体（含五项 usage），view 追加按水位
	 * 着色的 (N%)——pct 阈值与侧栏同走 tui_usage_tier（70/90）。
	 * 主体裁到剩余宽并回退 UTF-8 边界（不切多字节）；后缀优先保底。 */
	if (meta_y >= 0 && mw > 0) {
		int pct = -1;
		size_t ml;
		int col = mx;
		char suf[32];
		int sn = 0;

		buf[0] = '\0';
		if (v->hooks.fill_meta)
			pct = v->hooks.fill_meta(v->hooks.ud, buf, sizeof(buf));
		if (pct >= 0) {
			sn = snprintf(suf, sizeof(suf), " (%d%%)", pct);
			if (sn < 0)
				sn = 0;
		}
		ml = strlen(buf);
		{
			int avail = mw - sn;

			if (avail < 0)
				avail = 0;
			if (ml > (size_t)avail) {
				ml = (size_t)avail;
				while (ml > 0 &&
				       ((unsigned char)buf[ml] & 0xC0) == 0x80)
					ml--;
			}
		}
		if (ml > 0)
			col = tui_screen_put(s, meta_y, mx, buf, ml, a_muted);
		if (pct >= 0 && sn > 0 && col >= mx) {
			int tier = tui_usage_tier(pct);
			tui_attr a = tier == 2 ? a_err :
				     tier == 1 ? a_warn : a_muted;

			(void)tui_screen_put(s, meta_y, col, suf, (size_t)sn,
					     a);
		}
	}

	/* 输入框（区域右缘==屏幕右缘，put 自然截断） */
	if (input_y >= 0 && mw > 0)
		tui_inputbox_render(v->ib, s, mx, input_y, mw, input_h,
				    &cr, &cc);

	/* 状态行：运行中 spinner+提示；空闲 cwd:repo */
	if (mw > 0) {
		if (v->running) {
			static const char hint[] = " esc interrupt";
			const char *sp = tui_thm_spinner(now);
			int col = tui_screen_put(s, status_y, mx, sp,
						 strlen(sp), a_muted);

			if (col > mx)
				(void)tui_screen_put(s, status_y, col,
						     hint, sizeof(hint) - 1,
						     a_muted);
		} else {
			buf[0] = '\0';
			if (v->hooks.fill_status)
				(void)v->hooks.fill_status(v->hooks.ud, buf,
							   sizeof(buf));
			if (buf[0])
				(void)tui_screen_put(s, status_y, mx, buf,
						     strlen(buf), a_muted);
		}
	}

	/* T9c3 覆盖层：整屏覆盖在底图之上（全屏面板，裁定 1）；
	 * 列表态隐藏光标、输入态定位到文本尾。 */
	if (tui_overlay_active(v->ov)) {
		int ovr = -1, ovc = -1;

		tui_overlay_render(v->ov, s, &ovr, &ovc);
		if (ovr >= 0) {
			if (v->cursor_hidden) {
				tui_term_show_cursor(&v->term);
				v->cursor_hidden = 0;
			}
			cr = ovr;
			cc = ovc;
		} else {
			if (!v->cursor_hidden) {
				tui_term_hide_cursor(&v->term);
				v->cursor_hidden = 1;
			}
			cr = -1;
			cc = -1;
		}
	} else if (v->cursor_hidden) {
		tui_term_show_cursor(&v->term);
		v->cursor_hidden = 0;
	}

	tui_renderer_flush(v->ren, cr, cc);
}

/* ---- 主循环 ---- */

int tui_view_run(tui_view *v)
{
	int rc;
	int rows = 24, cols = 80;
	tui_sink sink;

	if (!v)
		return -1;
	tui_term_init(&v->term, STDOUT_FILENO);
	rc = tui_term_enter(&v->term);
	if (rc != 0)
		return rc;		/* 2=非 tty（stderr 已报）/-1=系统错 */
	tui_term_show_cursor(&v->term);
	if (v->hooks.on_entered)
		v->hooks.on_entered(v->hooks.ud);

	tui_term_get_size(v->term.fd, &rows, &cols);
	tui_sink_init_fd(&sink, STDOUT_FILENO);
	v->ren = tui_renderer_create(rows, cols, sink);
	if (!v->ren) {
		tui_term_leave(&v->term);
		return -1;
	}
	tv_pull_sessions(v);
	/* theme/keymap 回落 notice（create 期发现；进屏后打——诚实注明） */
	if (v->init_notice[0][0])
		tui_chat_add_notice(v->chat, v->init_notice[0]);
	if (v->init_notice[1][0])
		tui_chat_add_notice(v->chat, v->init_notice[1]);
	v->dirty_needed = 1;

	for (;;) {
		uint64_t now = tv_now_ms();
		struct pollfd pf[2];
		int timeout = -1;
		int n;
		long esc;

		/* leader 序列 2s 超时结算（OCD keymap.tsx:143） */
		if (v->leader_pending && now >= v->leader_deadline)
			v->leader_pending = 0;

		if (tv_drain(v))
			v->dirty_needed = 1;
		/* resize：SIGWINCH 只置 flag，这里消费 */
		{
			int nr = 0, nc = 0;

			if (tui_frame_check_resize(v->term.fd, &nr, &nc)) {
				tui_renderer_resize(v->ren, nr, nc);
				v->dirty_needed = 1;
			}
		}
		/* 运行中：30fps 常刷（spinner 动画 + 流式即时性） */
		if (v->running)
			v->dirty_needed = 1;
		if (v->dirty_needed && tui_frame_due(&v->frame, now)) {
			tv_render(v, now);
			tui_frame_mark(&v->frame, now);
			v->dirty_needed = 0;
		}
		if (v->quit)
			break;

		/* poll 超时：待渲染→帧门剩余；孤立 Esc→结算截止 */
		if (v->dirty_needed) {
			uint64_t w = tui_frame_wait_ms(&v->frame, now);

			timeout = (w > 0x7ffffffu) ? 0x7fffffff : (int)w;
		}
		esc = tui_input_esc_deadline(&v->input, now);
		if (esc >= 0 && (timeout < 0 || esc < timeout))
			timeout = (int)esc;
		if (v->leader_pending) {
			uint64_t rem = v->leader_deadline > now ?
				       v->leader_deadline - now : 0;
			int li = rem > 0x7fffffffu ? 0x7fffffff : (int)rem;

			if (timeout < 0 || li < timeout)
				timeout = li;
		}

		pf[0].fd = STDIN_FILENO;
		pf[0].events = POLLIN;
		pf[0].revents = 0;
		pf[1].fd = v->wake[0];	/* 自唤醒 pipe 读端（写端=post） */
		pf[1].events = POLLIN;
		pf[1].revents = 0;
		n = poll(pf, 2, timeout);
		if (n < 0) {
			if (errno == EINTR)
				continue;	/* SIGWINCH/SIGINT：回到循环顶 */
			break;
		}
		if (pf[0].revents & (POLLIN | POLLHUP)) {
			char buf[1024];
			ssize_t r = read(STDIN_FILENO, buf, sizeof(buf));

			if (r > 0) {
				(void)tui_input_feed(&v->input, buf,
						     (size_t)r, tv_now_ms());
				tv_drain_keys(v);
			} else if (r == 0) {
				break;		/* stdin EOF → 退出 */
			} else if (errno != EINTR && errno != EAGAIN) {
				break;
			}
		}
		if (pf[1].revents & POLLIN) {
			char sinkbuf[256];

			while (read(v->wake[0], sinkbuf, sizeof(sinkbuf)) > 0)
				;		/* 排空唤醒字节 */
		}
		/* 孤立 Esc 结算（25ms 无续字节 → ESC 键事件） */
		(void)tui_input_tick(&v->input, tv_now_ms());
		tv_drain_keys(v);
	}

	/* 收口：拒收新事件 → 中断+join worker（on_shutdown）→ 退屏 */
	pthread_mutex_lock(&v->qm);
	v->closing = 1;
	pthread_cond_broadcast(&v->qc);
	pthread_mutex_unlock(&v->qm);
	if (v->hooks.on_shutdown)
		v->hooks.on_shutdown(v->hooks.ud);
	tui_term_leave(&v->term);
	return 0;
}

/* ---- 构造/析构 ---- */

tui_view *tui_view_create(const tui_view_hooks *hooks)
{
	tui_view *v = calloc(1, sizeof(*v));

	if (!v)
		return NULL;
	if (hooks)
		v->hooks = *hooks;
	tui_theme_default(&v->th);
	tui_input_init(&v->input);
	tui_frame_init(&v->frame);
	v->chat = tui_chat_create(&v->th);
	v->ib = tui_inputbox_create(&v->th);
	v->ov = tui_overlay_create();
	v->km = tui_keymap_create();
	if (!v->chat || !v->ib || !v->ov || !v->km) {
		tui_view_destroy(v);
		return NULL;
	}
	/* ---- T9c3 数据文件（产品配置路径；坏文件回落+进屏 notice） ---- */
	{
		char path[512];
		char e[300];
		const char *home = getenv("HOME");
		const char *env = getenv("OCC_THEME");

		path[0] = '\0';
		if (env && env[0])
			snprintf(path, sizeof(path), "%s", env);
		else if (home && home[0])
			snprintf(path, sizeof(path), "%s/.occ/theme.ini",
				 home);
		e[0] = '\0';
		if (path[0] && tui_thm_load(path, e, sizeof(e)) != 0)
			snprintf(v->init_notice[0], sizeof(v->init_notice[0]),
				 "%s — 已回落出厂缺省调色板", e);
	}
	{
		char path[512];
		char e[300];
		const char *home = getenv("HOME");
		const char *env = getenv("OCC_KEYMAP");

		path[0] = '\0';
		if (env && env[0])
			snprintf(path, sizeof(path), "%s", env);
		else if (home && home[0])
			snprintf(path, sizeof(path), "%s/.occ/keymap", home);
		e[0] = '\0';
		if (path[0] && tui_keymap_load(v->km, path, e, sizeof(e)) != 0)
			snprintf(v->init_notice[1], sizeof(v->init_notice[1]),
				 "%s — 已回落默认键位表", e);
	}
	pthread_mutex_init(&v->qm, NULL);
	pthread_cond_init(&v->qc, NULL);
	if (pipe(v->wake) != 0) {
		tui_view_destroy(v);
		return NULL;
	}
	(void)fcntl(v->wake[0], F_SETFL, O_NONBLOCK);
	(void)fcntl(v->wake[1], F_SETFL, O_NONBLOCK);
	(void)fcntl(v->wake[0], F_SETFD, FD_CLOEXEC);
	(void)fcntl(v->wake[1], F_SETFD, FD_CLOEXEC);
	return v;
}

void tui_view_destroy(tui_view *v)
{
	int i;

	if (!v)
		return;
	/* 防御：未走 run 的早退路径也要拒收 */
	pthread_mutex_lock(&v->qm);
	v->closing = 1;
	pthread_cond_broadcast(&v->qc);
	for (i = 0; i < v->qn; i++)
		tv_free_ev(&v->q[(v->qh + i) % TV_QMAX]);
	v->qn = 0;
	pthread_mutex_unlock(&v->qm);

	if (v->wake[0] >= 0)
		close(v->wake[0]);
	if (v->wake[1] >= 0)
		close(v->wake[1]);
	pthread_cond_destroy(&v->qc);
	pthread_mutex_destroy(&v->qm);
	if (v->ren)
		tui_renderer_destroy(v->ren);
	tui_chat_destroy(v->chat);
	tui_inputbox_destroy(v->ib);
	tui_overlay_destroy(v->ov);
	tui_keymap_destroy(v->km);
	free(v);
}

/* ---- T9c3 覆盖层 API ---- */

int tui_view_open_list(tui_view *v, int ov_id, const char *title,
		       const tui_ov_item *items, int n, int searchable,
		       const char *footer)
{
	int rc;

	if (!v)
		return -1;
	v->leader_pending = 0;		/* 开面板取消 leader 序列 */
	rc = tui_overlay_set_list(v->ov, ov_id, title, items, n, searchable,
				  footer);
	v->dirty_needed = 1;
	return rc;
}

int tui_view_open_input(tui_view *v, int ov_id, const char *title,
			const char *prompt, const char *initial, int mask)
{
	int rc;

	if (!v)
		return -1;
	v->leader_pending = 0;
	rc = tui_overlay_set_input(v->ov, ov_id, title, prompt, initial,
				   mask);
	v->dirty_needed = 1;
	return rc;
}

void tui_view_close_overlay(tui_view *v)
{
	if (!v)
		return;
	tui_overlay_clear(v->ov);
	v->dirty_needed = 1;
}

void tui_view_overlay_status(tui_view *v, const char *msg, int is_err)
{
	if (!v)
		return;
	tui_overlay_status(v->ov, msg, is_err);
	v->dirty_needed = 1;
}

int tui_view_overlay_open(const tui_view *v)
{
	return v && tui_overlay_active(v->ov);
}

void tui_view_paint(tui_view *v)
{
	if (!v || !v->ren)
		return;
	tv_render(v, tv_now_ms());
	v->dirty_needed = 0;
}
