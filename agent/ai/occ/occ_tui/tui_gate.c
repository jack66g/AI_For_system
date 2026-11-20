/* SPDX-License-Identifier: GPL-2.0 */
/* tui_gate.c - T4 控制台登录门：crypt 凭据 + 独立 tui_screen 登录/向导 UI */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int gate_term_restore;
static struct termios gate_term_orig;

#include <crypt.h>

#include "tui_core.h"
#include "tui_input.h"
#include "tui_lang.h"
#include "tui_theme.h"
#include "tui_utf8.h"
#include "tui_gate.h"

#define GATE_USER "admin"
#define GATE_PW_MAX 64
#define GATE_MAX_FAIL 3
#define GATE_COOLDOWN_SEC 10

const char *tui_gate_path(void)
{
	const char *env = getenv("AIK_CONSOLE_GATE");

	if (env && env[0])
		return env;
	return "/etc/aikernel/console-gate";
}

int tui_gate_skipboot_path(const char *cmdline_path)
{
	FILE *f;
	char buf[4096];
	size_t n;

	f = fopen(cmdline_path, "r");
	if (!f)
		return 0;
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	return strstr(buf, "ai.skipgate=1") != NULL;
}

int tui_gate_skipboot(void)
{
	return tui_gate_skipboot_path("/proc/cmdline");
}

int tui_gate_read(const char *path, char hash[128], long long *ts)
{
	FILE *f;
	char line[256];
	char *p1, *p2;

	f = fopen(path, "r");
	if (!f)
		return -1;
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	p1 = strchr(line, ':');
	if (!p1)
		return -1;
	*p1++ = '\0';
	p2 = strchr(p1, ':');
	if (!p2)
		return -1;
	*p2++ = '\0';
	if (strcmp(line, GATE_USER) != 0)
		return -1;
	if (strncmp(p1, "$6$", 3) != 0 || strlen(p1) >= 128)
		return -1;
	strcpy(hash, p1);
	if (ts)
		*ts = strtoll(p2, NULL, 10);
	return 0;
}

int tui_gate_hash(const char *pw, char out[128])
{
	static const char cs[] =
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	char salt[32];
	unsigned char rnd[8];
	int fd, i;
	char *res;

	if (!pw || !*pw || strlen(pw) > GATE_PW_MAX)
		return -1;
	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0 || read(fd, rnd, sizeof(rnd)) != (ssize_t)sizeof(rnd)) {
		if (fd >= 0)
			close(fd);
		return -1;
	}
	close(fd);
	for (i = 0; i < 8; i++)
		salt[i] = cs[rnd[i] % (sizeof(cs) - 1)];
	salt[8] = '\0';
	snprintf(out, 128, "$6$%.8s$", salt);
	res = crypt(pw, out);
	if (!res || strlen(res) >= 128)
		return -1;
	snprintf(out, 128, "%s", res);
	return 0;
}

int tui_gate_verify(const char *pw, const char *hash)
{
	const char *res;
	const volatile unsigned char *a, *b;
	size_t la, lb, i;
	unsigned char d = 0;

	if (!pw || !hash || strncmp(hash, "$6$", 3) != 0)
		return 0;
	res = crypt(pw, hash);
	if (!res)
		return 0;
	a = (const volatile unsigned char *)res;
	b = (const volatile unsigned char *)hash;
	la = strlen(res);
	lb = strlen(hash);
	d |= (unsigned char)(la ^ lb);
	for (i = 0; i < la && i < lb; i++)
		d |= (unsigned char)(a[i] ^ b[i]);
	return d == 0;
}

int tui_gate_write(const char *path, const char *hash)
{
	char tmp[512];
	FILE *f;

	if (!path || !path[0] || !hash || strncmp(hash, "$6$", 3) != 0)
		return -1;
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	f = fopen(tmp, "w");
	if (!f)
		return -1;
	fprintf(f, "%s:%s:%lld\n", GATE_USER, hash, (long long)time(NULL));
	if (fflush(f) != 0 || fclose(f) != 0) {
		unlink(tmp);
		return -1;
	}
	chmod(tmp, 0600);
	if (rename(tmp, path) != 0) {
		unlink(tmp);
		return -1;
	}
	return 0;
}

/* ---- UI ---- */

struct gate_field {
	char buf[GATE_PW_MAX];
	int len;
};

static void draw_center(tui_screen *s, int row, int cols,
			const char *txt, tui_attr a)
{
	/* q17 audit A-5：按显示列居中（字节长度会把 CJK 行整体推右） */
	int c = (cols - (int)tui_utf8_cols(txt)) / 2;

	if (c < 0)
		c = 0;
	tui_screen_puts(s, row, c + 1, txt, a);
}

static void draw_masked(tui_screen *s, int row, int cols,
			const struct gate_field *f, int active)
{
	char stars[GATE_PW_MAX + 3];
	int i, c;
	tui_attr a = tui_thm_attr(TUI_THM_FG, TUI_THM_USER_BG, 0);

	for (i = 0; i < f->len; i++)
		stars[i] = '*';
	stars[f->len] = active ? '_' : ' ';
	stars[f->len + 1] = '\0';
	c = (cols - 40) / 2;
	if (c < 1)
		c = 1;
	tui_screen_puts(s, row, c, "                                      ", a);
	tui_screen_puts(s, row, c, stars, a);
}

static void box_frame(tui_screen *s, int rows, int cols)
{
	int r0 = rows / 2 - 6, r1 = rows / 2 + 5;
	int c0 = (cols - 44) / 2, c1 = c0 + 43, r, c;
	tui_attr border = tui_thm_attr(TUI_THM_ACCENT, TUI_THM_BG, 0);
	tui_attr bg = tui_thm_attr(TUI_THM_FG, TUI_THM_BG, 0);

	if (r0 < 0)
		r0 = 0;
	if (c0 < 0)
		c0 = 0;
	for (c = c0; c <= c1 && c < cols; c++) {
		tui_screen_puts(s, r0, c, c == c0 ? "+" :
				(c == c1 ? "+" : "-"), border);
		tui_screen_puts(s, r1, c, c == c0 ? "+" :
				(c == c1 ? "+" : "-"), border);
	}
	for (r = r0 + 1; r < r1 && r < rows; r++) {
		tui_screen_puts(s, r, c0, "|", border);
		tui_screen_puts(s, r, c1, "|", border);
	}
	(void)bg;
}

#define GATE_MODE_SETUP 0
#define GATE_MODE_LOGIN 1

static int gate_field_input(tui_input *in, struct gate_field *f, int *done,
			    int *quit)
{
	tui_event ev;

	*done = 0;
	*quit = 0;
	if (tui_input_next(in, &ev) <= 0)
		return 0;
	if (ev.type != TUI_EV_KEY)
		return 0;
	if (ev.key == TUI_KEY_CHAR) {
		if ((ev.mods & TUI_MOD_CTRL) && (ev.ch == 'c' || ev.ch == 'C')) {
			*quit = 1;
			return 0;
		}
		if (ev.ch >= 32 && ev.ch < 127 && f->len < GATE_PW_MAX - 1)
			f->buf[f->len++] = (char)ev.ch;
		return 0;
	}
	if (ev.key == TUI_KEY_RETURN) {
		*done = 1;
		return 0;
	}
	if (ev.key == TUI_KEY_BACKSPACE) {
		if (f->len > 0)
			f->len--;
		return 0;
	}
	if (ev.key == TUI_KEY_ESCAPE)
		*quit = 1;
	return 0;
}

/* q17 实机抓获（audit A-1，致命）：gate 只出队（tui_input_next）不进队
 * ——无人调 tui_input_feed，首屏画完即冻死、CPU 空转，掩码/两段确认/
 * 3 错冷却在实机全部不可达（串口日志实证：喂键后零掩码重绘零状态变化）。
 * 补上主 TUI 同源的 poll→read→feed 泵（tui_view.c 输入口径）；
 * EOF/读错按主 TUI 惯例退出（termios 由收尾路径恢复）。 */
static uint64_t gate_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void gate_pump_input(tui_input *in, int *quit)
{
	struct pollfd pfd;
	char buf[256];
	ssize_t r;

	pfd.fd = STDIN_FILENO;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd, 1, 30) <= 0)
		return;
	if (!(pfd.revents & (POLLIN | POLLHUP)))
		return;
	r = read(STDIN_FILENO, buf, sizeof(buf));
	if (r > 0)
		(void)tui_input_feed(in, buf, (size_t)r, gate_now_ms());
	else if (r == 0 || (errno != EINTR && errno != EAGAIN))
		*quit = 1;
}

/* P-41/P-44：gate 输出致命（wd -2 / IO -1）——gate 在 view 之前、无会话
 * 无清理链：还原 termios → 人话 stderr → 释放渲染器（含缓冲）→
 * exit(72)。aik-console v7 对 72 循环 2s 重启整链（gate 卡死同治）。 */
static void gate_sink_fatal(tui_renderer *ren, int frc)
{
	if (gate_term_restore) {
		tcsetattr(STDIN_FILENO, TCSANOW, &gate_term_orig);
		gate_term_restore = 0;
	}
	/* 楔死终端上缓冲无保序意义：丢弃并还原 fd flags（防 exit 路径
	 * 再碰非阻塞描述） */
	tui_sink_drain(&ren->sink);
	tui_sink_set_blocking(&ren->sink);
	if (frc == -2)
		fprintf(stderr,
			L_("occ-tui: 输出看门狗 %dms 无消费（fbterm 楔死？）——退出重启\n"),
			ren->sink.wd_ms);
	else
		fputs(L_("occ-tui: 输出 IO 错误（fbterm/pty 消亡？）——退出重启\n"), stderr);
	tui_renderer_destroy(ren);
	/* P-41/P-44d：exit 前击毙楔死的 fbterm 父进程（单点、恰一次；
	 * 时机取舍同 tui_view_run 收口——人话行已落 stderr 文件） */
	tui_out_fatal_kill_parent();
	exit(72);
}

static int gate_run_ui(int mode, int *unlocked)
{
	tui_sink sink;
	tui_renderer *ren;
	tui_input in;
	tui_screen *s;
	int rows, cols, rc = 1;
	struct gate_field f1, f2;
	int stage = 0;		/* setup: 0=首次输入 1=确认输入 */
	int fails = 0;
	char hash[128];
	char login_note[160] = "";	/* 一次性状态（SETUP→LOGIN 切换说明） */
	int hb_ms;			/* P-41/P-44b：空闲心跳周期（0=禁用） */
	uint64_t hb_next;		/* 下次心跳探针到点 */
	tui_attr title_a = tui_thm_attr(TUI_THM_ACCENT, TUI_THM_BG, 0);
	tui_attr txt_a = tui_thm_attr(TUI_THM_FG, TUI_THM_BG, 0);
	tui_attr mut_a = tui_thm_attr(TUI_THM_MUTED, TUI_THM_BG, 0);
	tui_attr err_a = tui_thm_attr(TUI_THM_ERROR, TUI_THM_BG, 0);

	*unlocked = 0;
	/* T4 勘误（实机抓获）：tty 默认 ECHO+ICANON 会把密码明文回显到屏上
	 * （gate 自绘掩码之外的第二份）——进 UI 前关回显转 raw（同 occ 主
	 * TUI 口径），退出恢复。 */
	{
		struct termios orig, raw;

		if (tcgetattr(STDIN_FILENO, &orig) == 0) {
			raw = orig;
			raw.c_lflag &= ~(unsigned)(ECHO | ICANON | ISIG);
			raw.c_iflag &= ~(unsigned)(IXON | ICRNL);
			raw.c_cc[VMIN] = 1;
			raw.c_cc[VTIME] = 0;
			tcsetattr(STDIN_FILENO, TCSANOW, &raw);
			gate_term_restore = 1;
			gate_term_orig = orig;
		}
	}
	if (tui_term_get_size(STDIN_FILENO, &rows, &cols) != 0) {
		rows = 24;
		cols = 80;
	}
	/* P-41/P-44：fd 缓冲汇+看门狗（同主 TUI 口径——gate 也吃同一个
	 * fbterm 楔死面：整帧一批次，15s 无消费 exit(72) 自愈） */
	if (tui_sink_init_fd_buf(&sink, STDOUT_FILENO) != 0) {
		if (gate_term_restore)
			tcsetattr(STDIN_FILENO, TCSANOW, &gate_term_orig);
		return 1;
	}
	ren = tui_renderer_create(rows, cols, sink);
	if (!ren) {
		/* q17 audit A-2：raw 已置位后的失败路径必须还 termios */
		tui_sink_fini(&sink);
		if (gate_term_restore)
			tcsetattr(STDIN_FILENO, TCSANOW, &gate_term_orig);
		return 1;
	}
	s = tui_renderer_front(ren);
	tui_input_init(&in);

	memset(&f1, 0, sizeof(f1));
	memset(&f2, 0, sizeof(f2));
	/* P-41/P-44c：空闲心跳——gate 静止等待输入时零帧输出，wd 无从
	 * 计时（真机实测：静止 gate strace 12s 零 write）；时间基准每
	 * OCC_TUI_HB_MS（缺省 5000，0=禁用，钳位 [0,600000]）发体量
	 * 心跳（56KB SGR 复位拍+cur_attr 重放，零视觉——小探针会被
	 * pty 缓冲整吞检测不出楔死，见 tui_renderer_heartbeat）检测
	 * 消费端。规格原文按「sleep(1)×5 次一跳」计数——本循环实为
	 * ~30ms/迭代（输入泵 poll 30ms），计数会 150ms 一跳刷屏，按
	 * 时间基准实现同一 5s 语义（冷却内环 sleep(1) 同样覆盖）。 */
	hb_ms = 5000;
	{
		const char *e = getenv("OCC_TUI_HB_MS");

		if (e && e[0]) {
			long hv = strtol(e, NULL, 10);

			if (hv >= 0 && hv <= 600000)
				hb_ms = (int)hv;
		}
	}
	hb_next = gate_now_ms() + (uint64_t)hb_ms;
	for (;;) {
		int done = 0, quit = 0;
		const char *status;
		static char status_buf[160];

		if (hb_ms > 0 && gate_now_ms() >= hb_next) {
			int prc = tui_renderer_heartbeat(ren);

			hb_next = gate_now_ms() + (uint64_t)hb_ms;
			if (prc == -2 || prc == -1)
				gate_sink_fatal(ren, prc);
		}
		tui_screen_fill(s, tui_thm_attr(TUI_THM_FG, TUI_THM_BG, 0));
		box_frame(s, rows, cols);
		if (mode == GATE_MODE_SETUP) {
			draw_center(s, rows / 2 - 4, cols,
				    L_("AIKernel 初始化"), title_a);
			draw_center(s, rows / 2 - 3, cols,
				    L_("首次使用：设置 admin 密码（≥6 位）"), mut_a);
			draw_center(s, rows / 2 - 2, cols,
				    stage == 0 ? L_("设置密码：") : L_("确认密码："),
				    txt_a);
			draw_masked(s, rows / 2 - 1, cols,
				    stage == 0 ? &f1 : &f2, 1);
			status = status_buf;
			draw_center(s, rows / 2 + 1, cols, status,
				    status[0] ? err_a : txt_a);
			draw_center(s, rows / 2 + 3, cols,
				    L_("配置云端模型：解锁后 /models"), mut_a);
			draw_center(s, rows / 2 + 4, cols,
				    L_("本地模型：/models 选 ollama"), mut_a);
		} else {
			draw_center(s, rows / 2 - 4, cols,
				    "AIKernel · alpha", title_a);
			draw_center(s, rows / 2 - 3, cols,
				    L_("用户：admin"), txt_a);
			draw_center(s, rows / 2 - 2, cols, L_("密码："), txt_a);
			draw_masked(s, rows / 2 - 1, cols, &f1, 1);
			if (login_note[0]) {
				snprintf(status_buf, sizeof(status_buf), "%s",
					 login_note);
				login_note[0] = '\0';
			}
			status = status_buf;
			draw_center(s, rows / 2 + 1, cols, status,
				    status[0] ? err_a : txt_a);
			draw_center(s, rows / 2 + 3, cols,
				    L_("Enter 登录 · Ctrl-C 退出"), mut_a);
		}
		{
			int frc = tui_renderer_flush(ren, rows / 2 - 1,
						     cols / 2);

			if (frc == -2 || frc == -1)
				gate_sink_fatal(ren, frc);
		}
		gate_pump_input(&in, &quit);
		if (quit) {
			rc = 1;
			break;
		}

		if (mode == GATE_MODE_SETUP) {
			gate_field_input(&in, stage == 0 ? &f1 : &f2,
					 &done, &quit);
			if (quit) {
				rc = 1;
				break;
			}
			if (done) {
					if (stage == 0) {
						if (f1.len < 6) {
							snprintf(status_buf,
								 sizeof(status_buf),
								 "%s", L_("密码至少 6 位，重输"));
							memset(&f1, 0, sizeof(f1));
						} else {
							stage = 1;
							snprintf(status_buf,
								 sizeof(status_buf),
								 "%s", L_("再输入一次确认"));
						}
				} else {
					if (strcmp(f1.buf, f2.buf) != 0) {
						snprintf(status_buf,
							 sizeof(status_buf),
							 "%s", L_("两次不一致，重新设置"));
						memset(&f1, 0, sizeof(f1));
						memset(&f2, 0, sizeof(f2));
						stage = 0;
					} else if (tui_gate_read(tui_gate_path(),
								 hash, NULL) == 0) {
						/* q17 覆写探针实机抓获：双
						 * 控制台并发 SETUP，后到者会
						 * 静默覆写先设好的密码。提交
						 * 前重读凭据——已被其他控制
						 * 台设置则不覆写，转 LOGIN。 */
						mode = GATE_MODE_LOGIN;
						memset(&f1, 0, sizeof(f1));
						memset(&f2, 0, sizeof(f2));
						stage = 0;
						fails = 0;
						snprintf(login_note,
							 sizeof(login_note),
							 "%s", L_("密码已由其他控制台设置，请登录"));
						continue;
					} else if (tui_gate_hash(f1.buf,
								 hash) == 0 &&
						   tui_gate_write(
							   tui_gate_path(),
							   hash) == 0) {
						*unlocked = 1;
						rc = 0;
						break;
					} else {
						snprintf(status_buf,
							 sizeof(status_buf),
							 "%s", L_("写入失败（权限？）"));
						memset(&f2, 0, sizeof(f2));
					}
				}
			}
			continue;
		}
		/* LOGIN */
		if (fails >= GATE_MAX_FAIL) {
			/* 冷却倒计时（阻塞 1s 步进重绘） */
			int left = GATE_COOLDOWN_SEC;
			tui_event ev_drain;

			/* q17 audit A-7：冷却期输入整段丢弃——先排空已泵入
			 * 队列的事件 + flush tty 层，倒计时结束再 flush 一次
			 * （否则解冻后旧字符会并入密码首段） */
			while (tui_input_next(&in, &ev_drain) > 0)
				;
			tcflush(STDIN_FILENO, TCIFLUSH);
			while (left > 0) {
				int frc;

				snprintf(status_buf, sizeof(status_buf),
					 L_("尝试过多，冷却 %d 秒…"), left);
				/* 重绘状态行即可 */
				draw_center(s, rows / 2 + 1, cols,
					    status_buf, err_a);
				frc = tui_renderer_flush(ren, rows / 2 - 1,
							 cols / 2);
				if (frc == -2 || frc == -1)
					gate_sink_fatal(ren, frc);
				/* P-41/P-44c：冷却 10s > 心跳 5s——内环同
				 * 步心跳，不留盲窗（帧每秒有输出，心跳只
				 * 是补 wd 计时锚点） */
				if (hb_ms > 0 && gate_now_ms() >= hb_next) {
					int prc = tui_renderer_heartbeat(ren);

					hb_next = gate_now_ms() +
						  (uint64_t)hb_ms;
					if (prc == -2 || prc == -1)
						gate_sink_fatal(ren, prc);
				}
				sleep(1);
				left--;
			}
			tcflush(STDIN_FILENO, TCIFLUSH);
			fails = 0;
			memset(&f1, 0, sizeof(f1));
			snprintf(status_buf, sizeof(status_buf), "%s", "");
			continue;
		}
		gate_field_input(&in, &f1, &done, &quit);
		if (quit) {
			rc = 1;
			break;
		}
		if (done) {
			if (tui_gate_read(tui_gate_path(), hash, NULL) != 0) {
				/* 文件消失（管理员删除=复位）→ 转向导 */
				mode = GATE_MODE_SETUP;
				memset(&f1, 0, sizeof(f1));
				stage = 0;
				status_buf[0] = '\0';	/* q17 audit A-8 */
				continue;
			}
			if (f1.len > 0 && tui_gate_verify(f1.buf, hash)) {
				*unlocked = 1;
				rc = 0;
				break;
			}
			fails++;
			/* q17 实机抓获：msg 曾是循环顶每帧置空的局部量，
			 * LOGIN 画面前状态就被清空——错误消息从未上过屏。
			 * 改直接写 status_buf（SETUP 口径）。 */
			snprintf(status_buf, sizeof(status_buf),
				 L_("密码不正确（%d/%d）"), fails, GATE_MAX_FAIL);
			memset(&f1, 0, sizeof(f1));
		}
	}
	if (gate_term_restore)
		tcsetattr(STDIN_FILENO, TCSANOW, &gate_term_orig);
	/* P-41/P-44：正常退出同样还原 fd flags（后续 occ 主 TUI 自会重置
	 * 自己的缓冲汇；不留非阻塞描述给无关使用者） */
	tui_sink_set_blocking(&ren->sink);
	tui_renderer_destroy(ren);
	return rc;
}

int tui_gate_enter(void)
{
	char hash[128];
	long long ts;
	int unlocked;

	/* 旁路：引导参数（ISO 烟测）或环境标记（pty 集成测试注入；
	 * 物理接触者本可旁路，非漏洞） */
	if (tui_gate_skipboot())
		return 0;
	{
		const char *e = getenv("AIK_CONSOLE_GATE_SKIP");
		if (e && e[0] && strcmp(e, "0") != 0)
			return 0;
	}
	if (tui_gate_read(tui_gate_path(), hash, &ts) != 0)
		return gate_run_ui(GATE_MODE_SETUP, &unlocked);
	return gate_run_ui(GATE_MODE_LOGIN, &unlocked);
}
