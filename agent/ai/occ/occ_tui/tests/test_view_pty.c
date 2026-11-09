/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_view_pty.c - 视图层伪终端集成测试（T9c2 验收 1）
 *
 * 复用 c1 openpty 方法（posix_openpt 三件套，避免 -lutil）：父进程持
 * master 注入按键字节，子进程在 slave 上跑完整 tui_view_run（mock 钩子，
 * 无 db/网络——真流式由 occ 级真对话验收覆盖）。断言：
 *   A. 进屏字节：alt-screen enter 序列 + 初始渲染内容（侧栏/元数据/状态行）
 *   B. 输入编辑：键入 → 输入框回显出现在 pty 字节流
 *   C. 提交流式：submit → mock worker 线程跨线程 post → 转写区出现回复
 *   D. 中断路径：运行中裸 Esc → on_interrupt → 通告+TURN_END 渲染
 *   E. 退出字节：/exit 与 ctrl+d 两路 → leave 序列 + 子进程 rc=0
 *   F. 覆盖层（T9c3）：/models 开列表 → ↓+Enter 选中 → 元数据行模型名变化
 *   G. keymap 覆盖（T9c3）：OCC_KEYMAP 改 leader=ctrl+g → ctrl+g+q 退出
 *   H. theme 文件（T9c3）：OCC_THEME accent=196 → SGR 38;5;196 进字节流
 *   I. /help 真实语义（T9 收尾）：/compact 换窗与 /shell bash 文案进字节流、
 *      假占位归属（T9d/T9e）零残留（命令本体已接真：occ_ac_compact_now
 *      换窗 / fork bash 重建 view——文案不得再谎称归后续棒）
 *   J. 历史回放（OCC-DEBT）：HIST_* 事件 → 分隔行/user 行/「OCC · 回放」
 *      footer 进字节流（occ.c 侧 db→事件端到端由 test_replay+取证脚本承）
 *   K. 向导异步验证（OCC-DEBT）：输入 key → busy spinner 帧字节 + Esc →
 *      overlay.cancel 取消 → 「已取消…重试」留步（面板不关）+ 收口
 *   L. /models 非对话（OCC-DEBT）：默认过滤非对话条目；ctrl+t → 显示
 *      全部 + dim + 「·非对话」tag 标注字节
 *   M. 鼠标（B5）：TERM=xterm-256color → 开鼠标字节 + /help 如实 on；
 *      滚轮上翻旧内容；点击 live ✻ thinking 行展开/收起；TERM=dumb →
 *      零鼠标字节 + /help 如实 off（无假交互）
 *   KT. kitty（B6）：TERM=xterm-kitty 渲染（CJK/SGR 256）；探测回复
 *      CSI ? 1 u → push CSI > 1 u + CSI-u Enter 提交 + 退出 pop CSI < u；
 *      无回复 → 零 push 字节（legacy 并行，回退路径）
 *
 * 渲染断言用子串（字节流含帧 diff/SGR 增量，逐字节 golden 不稳定——
 * 细粒度 SGR golden 由 c1 test_render 91 断言与 test_chat 25 断言覆盖）。
 */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1

#include "../tui_view.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

/* ---- mock 钩子 ---- */

struct mock {
	tui_view *view;
	pthread_t th;
	int th_live;
	volatile int stop;
	int slow;			/* 1=长 turn（等中断） */
	char model[64];			/* /models 选中后改写（F 场景） */
	/* OCC-DEBT K：异步验证线程（busy spinner + Esc 取消） */
	pthread_t wizth;
	int wiz_live;
	volatile int wiz_stop;
	/* OCC-DEBT L：非对话显隐（模拟 occ.c 过滤态） */
	int show_all;
};

/* 快 turn：50ms 后跨线程 post 回复 + 收口 */
static void *mock_fast_turn(void *arg)
{
	struct mock *m = arg;

	usleep(50000);
	(void)tui_view_post(m->view, TUI_VIEW_TEXT, "MOCK_REPLY", 0, NULL, 0);
	(void)tui_view_post(m->view, TUI_VIEW_TURN_END,
			    "OCC · mock · 0.1s · 10.0 tok/s", 0, NULL, 0);
	return NULL;
}

/* 慢 turn：先发一段流式文本，然后等 stop（模拟长生成） */
static void *mock_slow_turn(void *arg)
{
	struct mock *m = arg;
	int i;

	(void)tui_view_post(m->view, TUI_VIEW_TEXT, "SLOWTEXT", 0, NULL, 0);
	for (i = 0; i < 100 && !m->stop; i++)
		usleep(50000);
	if (!m->stop) {			/* 超时兜底：防测试悬挂 */
		(void)tui_view_post(m->view, TUI_VIEW_TURN_END,
				    "OCC · mock · timeout", 0, NULL, 0);
	}
	return NULL;
}

static int mock_submit(void *ud, const char *text, size_t len)
{
	struct mock *m = ud;

	(void)text;
	(void)len;
	if (m->th_live) {		/* 上一 turn 已收口（view.running 门） */
		pthread_join(m->th, NULL);
		m->th_live = 0;
	}
	m->stop = 0;
	if (pthread_create(&m->th, NULL,
			   m->slow ? mock_slow_turn : mock_fast_turn, m) != 0)
		return -1;
	m->th_live = 1;
	return 0;
}

static void mock_interrupt(void *ud)
{
	struct mock *m = ud;

	m->stop = 1;
	/* 复现真路径：中断引发的 EINTR 被分级为可重试 → 传输层发 RESET
	 *（真流式里它会清掉已流出正文→空块被 TURN_END 丢→footer 丢）。
	 * view 必须过滤中断后的 RESET——此序列即回归测试。 */
	(void)tui_view_post(m->view, TUI_VIEW_RESET,
			    "重试：第 1/2 次尝试（中断误分级）", 0, NULL, 0);
	(void)tui_view_post(m->view, TUI_VIEW_NOTICE, "GOT_INTERRUPT", 0,
			    NULL, 0);
	(void)tui_view_post(m->view, TUI_VIEW_TURN_END, "OCC · interrupted", 0,
			    NULL, 0);
}

static int mock_command(void *ud, const char *line)
{
	struct mock *m = ud;

	if (!strcmp(line, "/models")) {
		tui_ov_item it[3];

		memset(it, 0, sizeof(it));
		snprintf(it[0].text, sizeof(it[0].text), "Favorites");
		it[0].flags = TUI_OV_HEADER;
		snprintf(it[1].text, sizeof(it[1].text), "model-alpha");
		snprintf(it[1].tag, sizeof(it[1].tag), "prov-a");
		snprintf(it[2].text, sizeof(it[2].text), "model-beta");
		snprintf(it[2].tag, sizeof(it[2].tag), "prov-b");
		(void)tui_view_open_list(m->view, 99, "models", it, 3, 1,
					 "Enter=switch · Esc=close");
		return 0;
	}
	if (!strcmp(line, "/replay")) {
		/* J：模拟 occ.c 回放投递（db→事件由 occ 级 test_replay 承） */
		(void)tui_view_post(m->view, TUI_VIEW_HIST_CLEAR, NULL, 0,
				    NULL, 0);
		(void)tui_view_post(m->view, TUI_VIEW_HIST_SEP,
				    "⋯ 更早 2 条消息未回放", 0, NULL, 0);
		(void)tui_view_post(m->view, TUI_VIEW_HIST_USER,
				    "HISTQ-user-line", 0, NULL, 0);
		(void)tui_view_post(m->view, TUI_VIEW_HIST_BEGIN, NULL, 0,
				    NULL, 0);
		(void)tui_view_post(m->view, TUI_VIEW_TEXT, "HISTA-asst-line",
				    0, NULL, 0);
		(void)tui_view_post(m->view, TUI_VIEW_TOOL_START, "bash",
				    0, "{\"cmd\":\"echo hi\"}", 0);
		(void)tui_view_post(m->view, TUI_VIEW_TOOL_END, "bash", 0,
				    "hi", 0);
		(void)tui_view_post(m->view, TUI_VIEW_TURN_END, "OCC · 回放",
				    0, NULL, 0);
		return 0;
	}
	if (!strcmp(line, "/wiz")) {
		/* K：向导 3/4 key 输入面板（模拟 occ.c wiz_open_key） */
		(void)tui_view_open_input(m->view, 98,
					  "add key · 3/4 API key",
					  "粘贴 key（掩码显示）", NULL, 1);
		return 0;
	}
	if (!strcmp(line, "/models2")) {
		/* L：模拟 occ.c /models 过滤态（非对话默认隐藏） */
		tui_ov_item it[2];

		memset(it, 0, sizeof(it));
		snprintf(it[0].text, sizeof(it[0].text), "chat-model");
		snprintf(it[0].tag, sizeof(it[0].tag), "prov-a");
		if (m->show_all) {
			snprintf(it[1].text, sizeof(it[1].text), "emb-model");
			snprintf(it[1].tag, sizeof(it[1].tag),
				 "prov-a ·非对话");
			it[1].flags = TUI_OV_DIM;
			(void)tui_view_open_list(m->view, 97, "models", it, 2,
						 1, "ctrl+t 非对话显隐");
		} else {
			(void)tui_view_open_list(m->view, 97, "models", it, 1,
						 1, "ctrl+t 非对话显隐");
		}
		return 0;
	}
	if (!strcmp(line, "/many")) {
		/* M2：30 行通告（滚轮翻旧内容断言用） */
		int i;

		for (i = 0; i < 30; i++) {
			char nb[32];

			snprintf(nb, sizeof(nb), "MANY-%02d", i);
			tui_view_notice(m->view, nb);
		}
		return 0;
	}
	if (!strcmp(line, "/think")) {
		/* M3：live 推理块（begin+reasoning——无 turn 的 live 块，
		 * 折叠行钉转写区底部供点击） */
		(void)tui_view_post(m->view, TUI_VIEW_HIST_BEGIN, NULL, 0,
				    NULL, 0);
		(void)tui_view_post(m->view, TUI_VIEW_REASONING,
				    "SECRET_THINKING_DATA", 0, NULL, 0);
		return 0;
	}
	if (!strcmp(line, "/cjk")) {
		/* KT1：CJK 渲染进字节流（kitty TERM 下宽字符兼容） */
		tui_view_notice(m->view, "汉字宽度测试");
		return 0;
	}
	return 1;			/* 未知 → view 提示 */
}

/* /models 选中（F 场景）：idx 1=alpha 2=beta → 改 mock 模型名并关面板 */
static int mock_overlay_submit(void *ud, int ov_id, int idx)
{
	struct mock *m = ud;

	if (ov_id != 99)
		return 1;
	if (idx == 1)
		snprintf(m->model, sizeof(m->model), "model-alpha");
	else if (idx == 2)
		snprintf(m->model, sizeof(m->model), "model-beta");
	else
		return 1;
	tui_view_close_overlay(m->view);
	return 0;
}

/* ---- K：异步验证（模拟 occ.c wiz 验证 worker：忙等取消/超时收口） ---- */

static void *mock_verify_thread(void *arg)
{
	struct mock *m = arg;
	int i;

	for (i = 0; i < 60 && !m->wiz_stop; i++)
		usleep(50000);		/* 最多 3s（超时=成功路径兜底） */
	(void)tui_view_post(m->view, TUI_VIEW_ASYNC_RESULT,
			    m->wiz_stop ? "cancelled" : "", 0, NULL,
			    m->wiz_stop ? 2 : 0);
	return NULL;
}

/* 输入态 Enter（ov 98=key 面板）：启验证线程 + busy spinner */
static int mock_overlay_input(void *ud, int ov_id, const char *text,
			      size_t len)
{
	struct mock *m = ud;

	(void)text;
	if (ov_id != 98 || len == 0)
		return 1;
	if (m->wiz_live) {
		pthread_join(m->wizth, NULL);
		m->wiz_live = 0;
	}
	m->wiz_stop = 0;
	if (pthread_create(&m->wizth, NULL, mock_verify_thread, m) != 0)
		return 1;
	m->wiz_live = 1;
	tui_view_overlay_status(m->view, "验证中…（1-token 实测，Esc 取消）",
				0);
	tui_view_set_busy(m->view, 1);
	return 0;
}

/* busy 态 Esc（view 改派 overlay.cancel）/ ctrl+t（model.nonchat） */
static int mock_overlay_key(void *ud, int ov_id, const char *action,
			    int idx)
{
	struct mock *m = ud;

	(void)idx;
	if (!strcmp(action, "overlay.cancel")) {
		if (!m->wiz_live)
			return 1;	/* 回落正常关闭 */
		m->wiz_stop = 1;
		tui_view_overlay_status(m->view, "取消验证中…", 0);
		return 0;
	}
	if (ov_id == 97 && !strcmp(action, "model.nonchat")) {
		m->show_all = !m->show_all;
		(void)mock_command(m, "/models2");	/* 重开反映过滤态 */
		tui_view_overlay_status(m->view, m->show_all ?
					"已显示全部（非对话 dim 标注）" :
					"非对话条目已隐藏（默认）", 0);
		return 0;
	}
	return 1;
}

/* 异步结果（主循环 drain）：取消=留步；成功=关面板+notice */
static void mock_async_result(void *ud, int rc, const char *text)
{
	struct mock *m = ud;

	(void)text;
	if (m->wiz_live) {
		pthread_join(m->wizth, NULL);
		m->wiz_live = 0;
	}
	tui_view_set_busy(m->view, 0);
	if (rc == 0) {
		tui_view_close_overlay(m->view);
		tui_view_notice(m->view, "WIZ_SAVED");
	} else if (rc == 2) {
		tui_view_overlay_status(m->view,
					"已取消——可修改 key 后回车重试", 0);
	}
}

static int mock_meta(void *ud, char *buf, size_t cap)
{
	struct mock *m = ud;

	snprintf(buf, cap, "occ · %s · 1.0k/200k",
		 m->model[0] ? m->model : "mock-model");
	return 1;
}

static int mock_status(void *ud, char *buf, size_t cap)
{
	(void)ud;
	snprintf(buf, cap, "cwd:mockrepo");
	return (int)strlen(buf);
}

static void mock_sessions(void *ud, tui_sb_data *out)
{
	(void)ud;
	memset(out, 0, sizeof(*out));
	snprintf(out->rows[0].id, sizeof(out->rows[0].id), "ses_aaaaaaaa");
	snprintf(out->rows[0].title, sizeof(out->rows[0].title), "first");
	out->rows[0].is_current = 1;
	snprintf(out->rows[1].id, sizeof(out->rows[1].id), "ses_bbbbbbbb");
	snprintf(out->rows[1].title, sizeof(out->rows[1].title), "second");
	out->n = 2;
	out->tokens_total = 1000;
	out->pct = 1;
}

static void mock_shutdown(void *ud)
{
	struct mock *m = ud;

	m->stop = 1;
	if (m->th_live) {
		pthread_join(m->th, NULL);
		m->th_live = 0;
	}
	m->wiz_stop = 1;
	if (m->wiz_live) {
		pthread_join(m->wizth, NULL);
		m->wiz_live = 0;
	}
}

/* ---- 子进程：跑完整视图 ---- */

static int child_main(void)
{
	struct mock m;
	tui_view_hooks h;
	int rc;

	memset(&m, 0, sizeof(m));
	m.slow = getenv("MOCK_SLOW") != NULL;
	snprintf(m.model, sizeof(m.model), "mock-model");
	memset(&h, 0, sizeof(h));
	h.ud = &m;
	h.on_submit = mock_submit;
	h.on_interrupt = mock_interrupt;
	h.on_command = mock_command;
	h.fill_meta = mock_meta;
	h.fill_status = mock_status;
	h.fill_sessions = mock_sessions;
	h.on_shutdown = mock_shutdown;
	h.on_overlay_submit = mock_overlay_submit;

	h.on_overlay_input = mock_overlay_input;
	h.on_overlay_key = mock_overlay_key;
	h.on_async_result = mock_async_result;

	m.view = tui_view_create(&h);
	if (!m.view)
		return 10;
	rc = tui_view_run(m.view);
	tui_view_destroy(m.view);
	return rc == 0 ? 0 : 11;
}

/* ---- 伪终端（照 c1 test_pty 方法） ---- */

struct pty {
	int master;
	int slave;
};

static int pty_open(struct pty *p)
{
	char *name;

	p->master = posix_openpt(O_RDWR | O_NOCTTY);
	if (p->master < 0)
		return -1;
	if (grantpt(p->master) != 0 || unlockpt(p->master) != 0) {
		close(p->master);
		return -1;
	}
	name = ptsname(p->master);
	if (!name) {
		close(p->master);
		return -1;
	}
	p->slave = open(name, O_RDWR | O_NOCTTY);
	if (p->slave < 0) {
		close(p->master);
		return -1;
	}
	return 0;
}

static void pty_close(struct pty *p)
{
	if (p->slave >= 0)
		close(p->slave);
	if (p->master >= 0)
		close(p->master);
	p->slave = p->master = -1;
}

#define OUT_CAP (256 * 1024)

/* 手写子串搜索（memmem 是 GNU 扩展，_DEFAULT_SOURCE 下不声明） */
static const char *find_bytes(const char *hay, int haylen, const char *needle)
{
	size_t nlen = strlen(needle);
	int i;

	if (nlen == 0 || haylen < (int)nlen)
		return NULL;
	for (i = 0; i <= haylen - (int)nlen; i++) {
		if (memcmp(hay + i, needle, nlen) == 0)
			return hay + i;
	}
	return NULL;
}

/* 子串出现次数（M3 折叠展开/收起的重绘计数断言） */
static int count_bytes(const char *hay, int haylen, const char *needle)
{
	size_t nlen = strlen(needle);
	int i, n = 0;

	if (nlen == 0 || haylen < (int)nlen)
		return 0;
	for (i = 0; i <= haylen - (int)nlen; i++) {
		if (memcmp(hay + i, needle, nlen) == 0)
			n++;
	}
	return n;
}

/* 读到累计输出包含 needle（或超时 -1 / EOF 1） */
static int read_until_contains(int fd, char *buf, int cap, int *have,
			       const char *needle, int timeout_ms)
{
	struct timespec start, now;
	size_t nlen = strlen(needle);

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		return -1;
	for (;;) {
		long long remain;
		struct pollfd p;
		int r;
		ssize_t n;

		if (*have >= (int)nlen && find_bytes(buf, *have, needle))
			return 0;
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return -1;
		remain = timeout_ms - ((now.tv_sec - start.tv_sec) * 1000LL +
				       (now.tv_nsec - start.tv_nsec) / 1000000LL);
		if (remain <= 0)
			return -1;
		if (*have >= cap)
			return -1;
		p.fd = fd;
		p.events = POLLIN;
		p.revents = 0;
		r = poll(&p, 1, (int)remain);
		if (r == 0)
			return -1;
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		n = read(fd, buf + *have, (size_t)(cap - *have));
		if (n > 0) {
			*have += (int)n;
			continue;
		}
		if (n == 0)
			return 1;
		if (errno == EINTR)
			continue;
		if (errno == EIO)
			return 1;
		return -1;
	}
}

/* 在 pty 上跑一轮子进程：进屏 → 写 keys → 等 needles（第 after_n 根
 * 出现后补写 keys2、第 after2 根后补写 keys3——中途多点注入，供中断/
 * 异步取消场景）→ 收尾 exit_keys → 等 leave */
static int run_scenario(const char *keys, size_t keys_len,
			const char *const *needles, int nneedles, int after_n,
			const char *keys2, size_t keys2_len,
			int after2, const char *keys3, size_t keys3_len,
			const char *exit_keys, size_t exit_len,
			char *out, int *out_len, int slow)
{
	struct pty pt;
	pid_t pid;
	int have = 0;
	int i;
	int rc = 0;
	struct winsize ws = { .ws_row = 24, .ws_col = 80 };

	if (pty_open(&pt) != 0)
		return -1;
	(void)ioctl(pt.slave, TIOCSWINSZ, &ws);
	pid = fork();
	if (pid < 0) {
		pty_close(&pt);
		return -1;
	}
	if (pid == 0) {
		close(pt.master);
		if (setsid() < 0)
			_exit(12);
		if (ioctl(pt.slave, TIOCSCTTY, 0) < 0)
			_exit(13);
		if (dup2(pt.slave, STDIN_FILENO) < 0 ||
		    dup2(pt.slave, STDOUT_FILENO) < 0 ||
		    dup2(pt.slave, STDERR_FILENO) < 0)
			_exit(14);
		if (pt.slave > STDERR_FILENO)
			close(pt.slave);
		if (slow)
			setenv("MOCK_SLOW", "1", 1);
		_exit(child_main());
	}
	close(pt.slave);
	pt.slave = -1;

	/* 先等进屏序列：child 的 tcsetattr(TCSAFLUSH) 会冲掉过早写入的
	 * 按键字节——必须等 raw 模式就绪（enter 序列在 tcsetattr 之后发出） */
	if (read_until_contains(pt.master, out, OUT_CAP, &have,
				"\x1b[?1049h", 5000) != 0) {
		rc = -1;
	} else if (keys_len > 0) {
		if (write(pt.master, keys, keys_len) < 0)
			rc = -1;
	}
	for (i = 0; i < nneedles && rc == 0; i++) {
		/* BTUI B5："\x01W" 哨兵 needle=不等流——对 master 做
		 * TIOCSWINSZ（24→25 行）触发子进程 SIGWINCH → renderer
		 * need_clear 全帧重绘（diff 渲染器只吐变化格——滚轮滚动的
		 * 行只有尾数字变化，整串 needle 需全帧才可见）。 */
		if (!strncmp(needles[i], "\x01W", 2)) {
			struct winsize wz = { .ws_row = 25, .ws_col = 80 };

			(void)ioctl(pt.master, TIOCSWINSZ, &wz);
			continue;
		}
		if (read_until_contains(pt.master, out, OUT_CAP, &have,
					needles[i], 5000) != 0) {
			printf("  dbg: needle[%d] '%s' missing (have=%d)\n",
			       i, needles[i], have);
			rc = -1;
			break;
		}
		if (keys2 && i == after_n) {
			if (write(pt.master, keys2, keys2_len) < 0)
				rc = -1;
		}
		if (keys3 && i == after2) {
			if (write(pt.master, keys3, keys3_len) < 0)
				rc = -1;
		}
	}
	if (rc == 0 && exit_len > 0) {
		if (exit_keys[0] == '\x1b' && exit_len > 1) {
			/* 首字节 Esc 须单独写——与后续字节同批会被 c1 解析成
			 * Alt+<char>（真实终端人类时序；c3 取证教训 #8） */
			if (write(pt.master, exit_keys, 1) < 0)
				rc = -1;
			usleep(60000);		/* > 25ms 孤立 Esc 结算窗 */
			if (write(pt.master, exit_keys + 1, exit_len - 1) < 0)
				rc = -1;
		} else {
			if (write(pt.master, exit_keys, exit_len) < 0)
				rc = -1;
		}
		/* leave 序列 = 子进程收尾完成 */
		if (read_until_contains(pt.master, out, OUT_CAP, &have,
					"\x1b[?1049l", 5000) != 0) {
			printf("  dbg: leave seq missing (have=%d)\n", have);
			rc = -1;
		}
	}
	*out_len = have;

	/* 收尸：先等子进程，再关 master（顺序反了会 EIO 噪声） */
	{
		int st = 0;
		int w;

		for (w = 0; w < 50; w++) {
			pid_t r = waitpid(pid, &st, WNOHANG);

			if (r == pid)
				break;
			usleep(100000);
		}
		if (w == 50) {
			kill(pid, SIGKILL);
			waitpid(pid, &st, 0);
			rc = -1;
		} else if (rc == 0 && (!WIFEXITED(st) || WEXITSTATUS(st) != 0)) {
			printf("  child exit status=%d\n",
			       WIFEXITED(st) ? WEXITSTATUS(st) : -1);
			rc = -1;
		}
	}
	pty_close(&pt);
	return rc;
}

int main(void)
{
	static char out[OUT_CAP];
	int out_len = 0;
	int rc;

	/* ---- A. 进屏字节 + 初始渲染（侧栏/元数据/状态行） ---- */
	{
		const char *needles[] = {
			"\x1b[?1049h",		/* alt-screen enter */
			"sessions",		/* 侧栏标题 */
			"occ · mock-model",	/* 元数据行 */
			"cwd:mockrepo",		/* 状态行 */
			"ses_aaaa",		/* 会话行（侧栏 id 截 8 位） */
		};

		rc = run_scenario("", 0, needles, 5, -1, NULL, 0, -1, NULL, 0,
				  "/exit\r", 6, out, &out_len, 0);
		OK(rc == 0, "A-enter-screen-render");
		OK(find_bytes(out, out_len, "\x1b[?1049h") != NULL,
		   "A-alt-screen-bytes");
		OK(find_bytes(out, out_len, "sessions") != NULL,
		   "A-sidebar-rendered");
	}

	/* ---- B. 输入编辑：键入 → 输入框回显进字节流 ---- */
	{
		const char *needles[] = { "helloTUI" };

		/* 键入等回显；再 8 次退格清空 + /exit 退出 */
		rc = run_scenario("helloTUI", 8, needles, 1, -1, NULL, 0,
				  -1, NULL, 0,
				  "\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f/exit\r",
				  14, out, &out_len, 0);
		OK(rc == 0, "B-input-echo-exit");
		OK(find_bytes(out, out_len, "helloTUI") != NULL,
		   "B-echo-in-pty-bytes");
	}

	/* ---- C. 提交 + 跨线程流式渲染 ---- */
	{
		const char *needles[] = { "helloTUI", "MOCK_REPLY" };

		rc = run_scenario("helloTUI\r", 9, needles, 2, -1, NULL, 0,
				  -1, NULL, 0,
				  "/exit\r", 6, out, &out_len, 0);
		OK(rc == 0, "C-submit-stream");
		OK(find_bytes(out, out_len, "MOCK_REPLY") != NULL,
		   "C-streamed-reply-rendered");
		OK(find_bytes(out, out_len, "you") != NULL,
		   "C-user-header");
		OK(find_bytes(out, out_len, "OCC · mock") != NULL,
		   "C-footer");
	}

	/* ---- D. 中断：运行中裸 Esc → on_interrupt → 通告渲染 ----
	 * keys=x\r 提交慢 turn → 等 SLOWTEXT（第 1 根）后注入 Esc →
	 * 等 GOT_INTERRUPT */
	{
		const char *needles[] = { "SLOWTEXT", "GOT_INTERRUPT" };
		char esc = 0x1b;

		rc = run_scenario("x\r", 2, needles, 2, 0, &esc, 1,
				  -1, NULL, 0,
				  "/exit\r", 6, out, &out_len, 1 /* slow */);
		OK(rc == 0, "D-interrupt-path");
		OK(find_bytes(out, out_len, "GOT_INTERRUPT") != NULL,
		   "D-interrupt-notice");
		/* 精确 footer 字节（仅 notice 含 "interrupted" 不算过） */
		OK(find_bytes(out, out_len, "OCC \xc2\xb7 interrupted") != NULL,
		   "D-interrupt-footer");
	}

	/* ---- E1. ctrl+d（空缓冲）退出 ---- */
	{
		const char *needles[] = { "sessions" };
		char ctrl_d = 0x04;

		/* exit_keys=NULL：ctrl+d 本身即退出，只等子进程 rc=0 */
		rc = run_scenario(&ctrl_d, 1, needles, 1, -1, NULL, 0,
				  -1, NULL, 0,
				  NULL, 0, out, &out_len, 0);
		OK(rc == 0, "E1-ctrl-d-exit");
	}

	/* ---- E2. 整行退出词（quit） ---- */
	{
		const char *needles[] = { "sessions" };

		rc = run_scenario("quit\r", 5, needles, 1, -1, NULL, 0,
				  -1, NULL, 0,
				  NULL, 0, out, &out_len, 0);
		OK(rc == 0, "E2-quit-word-exit");
	}

	/* ---- F. 覆盖层：/models → ↓+Enter 选中 model-beta → 元数据行变 ----
	 * 分两段注入（keys2 在 needle[0] 出现后写）：若 /models\r 与 ↓\r
	 * 同批到达，覆盖层开合落在同一 drain 内、面板帧永不渲染。 */
	{
		const char *needles[] = {
			"model-alpha",		/* 覆盖层渲染 */
			"occ · model-beta"	/* 选中切换 → meta 变化 */
		};
		static const char keys[] = "/models\r";
		static const char keys2[] = "\x1b[B\r";	/* down, enter */

		rc = run_scenario(keys, sizeof(keys) - 1, needles, 2, 0,
				  keys2, sizeof(keys2) - 1,
				  -1, NULL, 0,
				  "/exit\r", 6, out, &out_len, 0);
		OK(rc == 0, "F-models-overlay-switch");
		OK(find_bytes(out, out_len, "model-beta") != NULL,
		   "F-overlay-list-rendered");
		OK(find_bytes(out, out_len, "occ \xc2\xb7 model-beta") != NULL,
		   "F-meta-model-changed");
		/* 选中行前缀（▸ = E2 96 B8）出现在字节流 */
		OK(find_bytes(out, out_len, "\xe2\x96\xb8 model-") != NULL,
		   "F-selected-marker");
	}

	/* ---- G. keymap 覆盖：OCC_KEYMAP 改 leader=ctrl+g → ctrl+g+q 退出 ---- */
	{
		const char *needles[] = { "\x1b[?1049h" };
		static const char keys[] = "\x07q";	/* ctrl+g, q */
		char kmppath[512];

		snprintf(kmppath, sizeof(kmppath),
			 "tests/.tmp_c3_keymap_%d", (int)getpid());
		{
			FILE *f = fopen(kmppath, "w");

			OK(f != NULL, "G-keymap-fixture");
			if (f) {
				fputs("# c3 pty fixture\n"
				      "leader = ctrl+g\n", f);
				fclose(f);
			}
		}
		setenv("OCC_KEYMAP", kmppath, 1);
		/* ctrl+g（0x07）arm leader → q 解析 <leader>q=app.exit → 退出 */
		rc = run_scenario(keys, sizeof(keys) - 1, needles, 1, -1,
				  NULL, 0, -1, NULL, 0, NULL, 0, out,
				  &out_len, 0);
		OK(rc == 0, "G-keymap-leader-override");
		unsetenv("OCC_KEYMAP");
		unlink(kmppath);
	}

	/* ---- H. theme 文件：OCC_THEME accent=196 → SGR 进字节流 ---- */
	{
		const char *needles[] = {
			"\x1b[?1049h",
			"38;5;196"		/* accent=196 的 SGR */
		};
		char thpath[512];

		snprintf(thpath, sizeof(thpath),
			 "tests/.tmp_c3_theme_%d", (int)getpid());
		{
			FILE *f = fopen(thpath, "w");

			OK(f != NULL, "H-theme-fixture");
			if (f) {
				fputs("# c3 pty fixture\n"
				      "accent = 196\n", f);
				fclose(f);
			}
		}
		setenv("OCC_THEME", thpath, 1);
		rc = run_scenario("", 0, needles, 2, -1, NULL, 0, -1, NULL,
				  0, "/exit\r", 6, out, &out_len, 0);
		OK(rc == 0, "H-theme-file-load");
		OK(find_bytes(out, out_len, "38;5;196") != NULL,
		   "H-accent-sgr-bytes");
		unsetenv("OCC_THEME");
		unlink(thpath);
	}

	/* ---- I. /help 真实语义：/compact 换窗 + /shell bash 文案、占位清零 ----
	 * （T9 收尾：命令本体已接真——occ_ac_compact_now 换窗 / fork bash
	 * 重建 view；help 文案必须与实现一致。notice 走 wordwrap 折行：
	 * 断言取空格围边的短 token，保证不被折断成两段。） */
	{
		const char *needles[] = {
			"autocondense",		/* /compact 换窗语义 */
			"bash"			/* /shell bash 逃逸语义 */
		};

		rc = run_scenario("/help\r", 6, needles, 2, -1, NULL, 0,
				  -1, NULL, 0,
				  "/exit\r", 6, out, &out_len, 0);
		OK(rc == 0, "I-help-real-semantics");
		OK(find_bytes(out, out_len, "autocondense") != NULL,
		   "I-help-compact-window-swap");
		OK(find_bytes(out, out_len, "bash") != NULL,
		   "I-help-shell-bash-escape");
		/* 假占位归属串必须零残留（T9d/T9e 两型——needle 用字节拼装，
	 * 源码 grep 零残留口径连测试文件一并成立） */
		OK(find_bytes(out, out_len, "\xe5\xbd\x92 T9") == NULL,
		   "I-help-no-t9-placeholder");
	}

	/* ---- J. 历史回放（OCC-DEBT）：/replay → HIST 事件渲染进字节流 ----
	 * 断言：分隔行（更早 N 条）+ user 消息行 + 工具行 + 「OCC · 回放」
	 * footer——渲染形态与 live 同路（db→事件规划链由 test_replay 承）。 */
	{
		const char *needles[] = {
			"HISTQ-user-line",	/* 回放 user 消息 */
			"HISTA-asst-line",	/* 回放 assistant 正文 */
			"OCC \xc2\xb7 \xe5\x9b\x9e\xe6\x94\xbe"	/* OCC · 回放 */
		};
		static const char keys[] = "/replay\r";

		rc = run_scenario(keys, sizeof(keys) - 1, needles, 3, -1,
				  NULL, 0, -1, NULL, 0,
				  "/exit\r", 6, out, &out_len, 0);
		OK(rc == 0, "J-hist-replay-render");
		OK(find_bytes(out, out_len,
			      "\xe2\x8b\xaf \xe6\x9b\xb4\xe6\x97\xa9 2") !=
		   NULL, "J-hist-separator");		/* ⋯ 更早 2 */
		OK(find_bytes(out, out_len, "HISTQ-user-line") != NULL,
		   "J-hist-user-line");
		OK(find_bytes(out, out_len,
			      "OCC \xc2\xb7 \xe5\x9b\x9e\xe6\x94\xbe") !=
		   NULL, "J-hist-footer");
		/* 工具行 ✓ bash（回放折叠形态=live 工具行） */
		OK(find_bytes(out, out_len, "\xe2\x9c\x93 bash") != NULL,
		   "J-hist-tool-row");
	}

	/* ---- K. 向导异步验证（OCC-DEBT）：busy spinner + Esc 取消留步 ----
	 * /wiz 开 key 面板 → 输入 sk-mock 并回车 → 验证线程起（busy spinner
	 * 帧字节=braille e2 a0 xx）→ 等「验证中」渲染后注入 Esc → 取消路径
	 * （overlay.cancel → 线程停 → ASYNC_RESULT rc=2 → 留步提示）→
	 * Esc 关面板（busy 已除）→ /exit 退出。 */
	{
		const char *needles[] = {
			"add key",		/* key 输入面板 */
			"验证中",		/* busy 状态行 */
			"已取消——可修改 key 后回车重试"	/* 取消留步（面板未关） */
		};
		static const char keys[] = "/wiz\r";
		static const char keys2[] = "sk-mock-key\r";
		static const char keys3[] = "\x1b";		/* Esc=取消 */
		static const char exit_keys[] = "\x1b/exit\r";	/* Esc 关面板再退 */

		rc = run_scenario(keys, sizeof(keys) - 1, needles, 3, 0,
				  keys2, sizeof(keys2) - 1,
				  1, keys3, sizeof(keys3) - 1,
				  exit_keys, sizeof(exit_keys) - 1,
				  out, &out_len, 0);
		OK(rc == 0, "K-wiz-async-cancel");
		/* spinner 帧字节（U+2800 段 braille：e2 a0 80..bf） */
		OK(find_bytes(out, out_len, "\xe2\xa0") != NULL,
		   "K-busy-spinner-bytes");
		/* 掩码输入（mask=1：明文 key 不得进字节流） */
		OK(find_bytes(out, out_len, "sk-mock-key") == NULL,
		   "K-key-not-echoed");
		/* 留步提示渲染=面板仍开（状态行只在面板上） */
		OK(find_bytes(out, out_len, "已取消") != NULL,
		   "K-cancel-stay-open");
	}

	/* ---- L. /models 非对话（OCC-DEBT）：默认过滤 + ctrl+t 显示全部 ---- */
	{
		const char *needles[] = {
			"chat-model",		/* 默认视图（非对话已隐藏） */
			"emb-model"		/* ctrl+t 后非对话条目出现 */
		};
		static const char keys[] = "/models2\r";
		static const char keys2[] = "\x14";	/* ctrl+t */
		static const char exit_keys[] = "\x1b/exit\r";

		rc = run_scenario(keys, sizeof(keys) - 1, needles, 2, 0,
				  keys2, sizeof(keys2) - 1,
				  -1, NULL, 0,
				  exit_keys, sizeof(exit_keys) - 1,
				  out, &out_len, 0);
		OK(rc == 0, "L-nonchat-toggle");
		/* ctrl+t 后 tag 标注「·非对话」（UTF-8 字节） */
		OK(find_bytes(out, out_len,
			      "\xc2\xb7\xe9\x9d\x9e\xe5\xaf\xb9\xe8\xaf\x9d") !=
		   NULL, "L-nonchat-tag-bytes");	/* ·非对话 */
	}

	/* ---- M1. 鼠标：TERM=xterm-256color → 开鼠标字节 + /help 如实 on ----
	 * 滚动条点击无设计依据（无滚动条）——不测不实现。 */
	{
		const char *needles[] = {
			"\x1b[?1000;1006h",	/* tui_mouse_enable 开 */
			"SGR 1006"		/* /help mouse 行如实 on */
		};
		const char *old = getenv("TERM");

		setenv("TERM", "xterm-256color", 1);
		rc = run_scenario("/help\r", 6, needles, 2, -1, NULL, 0,
				  -1, NULL, 0, "/exit\r", 6, out, &out_len, 0);
		OK(rc == 0, "M1-mouse-enable-bytes");
		OK(find_bytes(out, out_len, "\x1b[?1000;1006h") != NULL,
		   "M1-enable-in-stream");
		OK(find_bytes(out, out_len, "SGR 1006") != NULL,
		   "M1-help-mouse-on-honest");
		/* 退出复位字节（mouse_on → leave 前置关） */
		OK(find_bytes(out, out_len, "\x1b[?1000;1006l") != NULL,
		   "M1-disable-on-exit");
		if (old)
			setenv("TERM", old, 1);
		else
			unsetenv("TERM");
	}

	/* ---- M2. 滚轮上翻：/many 30 行 → 初始只显尾部；滚轮×5(15 行)
	 * → WINCH 全帧重绘 → 头部 MANY-00 整串重现于字节流 ---- */
	{
		static const char wheel_up[] =
			"\x1b[<64;30;10M\x1b[<64;30;10M\x1b[<64;30;10M"
			"\x1b[<64;30;10M\x1b[<64;30;10M";
		const char *needles[] = {
			"MANY-29",	/* 初始尾部可见 */
			"\x01W",	/* 滚轮后触发 SIGWINCH 全帧重绘 */
			"MANY-00"	/* 滚轮上翻后头部重现 */
		};

		setenv("TERM", "xterm-256color", 1);
		rc = run_scenario("/many\r", 6, needles, 3, 0,
				  wheel_up, sizeof(wheel_up) - 1,
				  -1, NULL, 0, "/exit\r", 6, out, &out_len, 0);
		OK(rc == 0, "M2-wheel-scroll-up");
		setenv("TERM", "dumb", 1);
	}

	/* ---- M3. 点击 live ✻ thinking 折叠行：展开 → 正文进字节流；
	 * 再点同格 → 收起（折叠头重绘，计数增加） ---- */
	{
		/* 24 行布局：转写区 0..20、live 折叠行=row20 → SGR y=21；
		 * 主列 x=22..（80 列有侧栏）→ 点击 x=30 */
		static const char click[] = "\x1b[<0;30;21M\x1b[<0;30;21m";
		const char *needles[] = {
			"thinking",	/* 折叠行渲染 */
			"SECRET_THINKING_DATA"	/* 展开后正文 */
		};

		setenv("TERM", "xterm-256color", 1);
		rc = run_scenario("/think\r", 7, needles, 2, 0,
				  click, sizeof(click) - 1,
				  -1, NULL, 0, "/exit\r", 6, out, &out_len, 0);
		OK(rc == 0, "M3-fold-click-expand");
		OK(find_bytes(out, out_len, "SECRET_THINKING_DATA") != NULL,
		   "M3-expanded-reasoning-bytes");
		OK(find_bytes(out, out_len, "\xe2\x8c\x83") != NULL,
		   "M3-open-header-marker");	/* ⌃ 展开态标记 */
		OK(count_bytes(out, out_len, "thinking") >= 2,
		   "M3-fold-header-redrawn");	/* 折叠头至少画 2 次（展开重绘） */
		setenv("TERM", "dumb", 1);
	}

	/* ---- M4. TERM=dumb：零鼠标字节 + /help 如实 off（诚实降级） ---- */
	{
		const char *needles[] = { "mouse: off" };

		setenv("TERM", "dumb", 1);
		rc = run_scenario("/help\r", 6, needles, 1, -1, NULL, 0,
				  -1, NULL, 0, "/exit\r", 6, out, &out_len, 0);
		OK(rc == 0, "M4-mouse-dumb-degrade");
		OK(find_bytes(out, out_len, "\x1b[?1000;1006h") == NULL,
		   "M4-no-mouse-enable-bytes");
		OK(find_bytes(out, out_len, "mouse: off") != NULL,
		   "M4-help-mouse-off-honest");
	}

	/* ---- KT1. TERM=xterm-kitty：进屏/SGR 256/CJK 宽字符渲染 ---- */
	{
		const char *needles[] = {
			"\x1b[?1049h",
			"38;5;",			/* 256 色 SGR */
			"\xe6\xb1\x89\xe5\xad\x97\xe5\xae\xbd\xe5\xba\xa6"
			"\xe6\xb5\x8b\xe8\xaf\x95"	/* 汉字宽度测试 */
		};

		setenv("TERM", "xterm-kitty", 1);
		rc = run_scenario("/cjk\r", 6, needles, 3, -1, NULL, 0,
				  -1, NULL, 0, "/exit\r", 6, out, &out_len, 0);
		OK(rc == 0, "KT1-kitty-term-render");
		OK(find_bytes(out, out_len, "\x1b[?25l") != NULL,
		   "KT1-cursor-hide-bytes");
		OK(find_bytes(out, out_len,
			      "\xe6\xb1\x89\xe5\xad\x97\xe5\xae\xbd\xe5\xba\xa6"
			      "\xe6\xb5\x8b\xe8\xaf\x95") != NULL,
		   "KT1-cjk-widewidth-bytes");
	}

	/* ---- KT2. kitty 探测回复 → push 增强 + CSI-u Enter 提交 + pop ----
	 * 进屏即发探测 CSI ? u；注入回复 CSI ? 1 u → view push CSI > 1 u；
	 * 再 CSI-u 形 Enter（\x1b[13u）提交 /help；退出前 pop CSI < u。 */
	{
		static const char reply[] = "\x1b[?1u";	/* 探测回复 flags=1 */
		static const char keys2[] = "/help\x1b[13u";	/* CSI-u Enter */
		const char *needles[] = {
			"\x1b[>1u",		/* push 增强键型 */
			"commands:"		/* CSI-u Enter 生效 */
		};

		rc = run_scenario(reply, sizeof(reply) - 1, needles, 2, 0,
				  keys2, sizeof(keys2) - 1,
				  -1, NULL, 0, "/exit\r", 6, out, &out_len, 0);
		OK(rc == 0, "KT2-kitty-probe-push-csiu");
		OK(find_bytes(out, out_len, "\x1b[>1u") != NULL,
		   "KT2-push-bytes");
		OK(find_bytes(out, out_len, "commands:") != NULL,
		   "KT2-csiu-enter-submit");
		OK(find_bytes(out, out_len, "\x1b[<u") != NULL,
		   "KT2-pop-before-exit");
		/* pop 晚于 push（顺序：增强开启 … 退出前 pop） */
		{
			const char *ph = find_bytes(out, out_len, "\x1b[>1u");
			const char *pp = find_bytes(out, out_len, "\x1b[<u");

			OK(ph != NULL && pp != NULL && pp > ph,
			   "KT2-pop-after-push");
		}
		setenv("TERM", "dumb", 1);
	}

	/* ---- KT3. 无探测回复 → 零 push 字节（legacy 并行——回退路径） ---- */
	{
		const char *needles[] = { "sessions" };

		rc = run_scenario("", 0, needles, 1, -1, NULL, 0,
				  -1, NULL, 0, "/exit\r", 6, out, &out_len, 0);
		OK(rc == 0, "KT3-no-reply-legacy");
		OK(find_bytes(out, out_len, "\x1b[>1u") == NULL,
		   "KT3-no-push-bytes");
		OK(find_bytes(out, out_len, "\x1b[<u") == NULL,
		   "KT3-no-pop-bytes");
	}

	printf("test_view_pty: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
