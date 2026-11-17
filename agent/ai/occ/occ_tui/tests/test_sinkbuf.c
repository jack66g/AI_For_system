/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_sinkbuf.c - P-41/P-44 缓冲汇 + 整帧原子刷 + 输出看门狗单测
 *
 * 背景（strace 实证 ~/k10-evidence/p44-wedge/）：fbterm 楔死后旧逐格碎片
 * write 把 64KB pty 缓冲填满即永久阻塞=冻结无自愈。本套断言新链：
 *   1. 缓冲追加顺序保真（三段拼接 → drain → 读回逐字节一致）
 *   2. 整帧一批次：脏 3 行 flush → drain 恰一次、write 次数远小于逐格
 *      （drain 次数=flush 次数——原子性主断言）
 *   3. 字节流全等：缓冲 renderer 与直写 renderer 同输入同输出（总序不变
 *      ——pty 级可见行为零变化的单元级证明）
 *   4. wd 超时：OCC_TUI_WD_MS=300 + 填满的 pipe → -2/wd_fired/耗时段合理
 *      +粘性（二次 drain 立返）
 *   5. IO 错：读端关闭的 pipe → drain -1
 *   6. set_blocking 幂等 + flags 还原
 *   7. 512KB 硬上限：超限按消费失败 -1
 *   8. renderer 级 wd：flush 透传 drain -2
 *   9. env 语义：缺省 15000；OCC_TUI_WD_MS=0 → 禁用（drain 不带时限）
 */
#define _DEFAULT_SOURCE 1

#include "tui_core.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* 从 fd 收满 want 字节（超时 -1）——drain 后读回对拍用 */
static int read_exact(int fd, char *buf, size_t want, int timeout_ms)
{
	size_t have = 0;
	uint64_t t0 = now_ms();

	while (have < want) {
		struct pollfd p;
		ssize_t n;

		p.fd = fd;
		p.events = POLLIN;
		p.revents = 0;
		if (poll(&p, 1, 200) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		n = read(fd, buf + have, want - have);
		if (n > 0) {
			have += (size_t)n;
			continue;
		}
		if (n < 0 && (errno == EINTR || errno == EAGAIN))
			;
		else
			return -1;
		if (now_ms() - t0 > (uint64_t)timeout_ms)
			return -1;
	}
	return 0;
}

/* ---- 1. 追加顺序保真 + 默认 wd 时限 ---- */
static void test_append_order(void)
{
	int pfd[2];
	tui_sink s;
	char got[32];

	unsetenv("OCC_TUI_WD_MS");
	OK(pipe(pfd) == 0, "order-pipe");
	OK(tui_sink_init_fd_buf(&s, pfd[1]) == 0, "order-init");
	OK(s.buf_mode == 1 && s.bcap == 64 * 1024, "order-bufmode-64k");
	OK(s.wd_ms == 15000, "order-wd-default-15000");
	OK((fcntl(pfd[1], F_GETFL) & O_NONBLOCK) != 0, "order-nonblock-set");

	s.fn(s.ctx, "AAA", 3);
	s.fn(s.ctx, "-BB", 3);
	s.fn(s.ctx, "-CC", 3);
	OK(s.blen == 9, "order-append-len-9");
	OK(tui_sink_drain(&s) == 0, "order-drain-ok");
	OK(s.blen == 0, "order-drained-empty");
	OK(s.stats_drains == 1, "order-drains-1");
	OK(s.stats_writes >= 1 && s.stats_writes <= 4,
	   "order-writes-small");		/* 9 字节至多几次部分写 */
	OK(read_exact(pfd[0], got, 9, 2000) == 0 &&
	   memcmp(got, "AAA-BB-CC", 9) == 0, "order-bytes-exact");

	tui_sink_set_blocking(&s);
	tui_sink_fini(&s);
	close(pfd[0]);
	close(pfd[1]);
}

/* ---- 2. 整帧一批次：drain 次数=flush 次数、write 次数远小于逐格 ---- */
static void test_frame_atomic(void)
{
	int pfd[2];
	tui_sink s;
	tui_renderer *r;
	tui_attr red = tui_attr_default();
	char got[512];

	red.fg = tui_color_idx(1);
	red.style = TUI_ST_BOLD;
	unsetenv("OCC_TUI_WD_MS");
	OK(pipe(pfd) == 0, "fa-pipe");
	OK(tui_sink_init_fd_buf(&s, pfd[1]) == 0, "fa-init");
	r = tui_renderer_create(4, 8, s);
	OK(r != NULL && r->sink.buf_mode == 1, "fa-ren-init");
	OK(r->sink.ctx == &r->sink, "fa-ren-ctx-self");	/* 值拷贝后自指修正 */

	/* 脏 3 行（含 SGR 切换+双宽字——旧逐格路径 = CUP+SGR+逐格 write
	 * 10+ 次；新路径全积缓冲一次 drain） */
	tui_screen_puts(tui_renderer_front(r), 0, 0, "Hi", tui_attr_default());
	tui_screen_puts(tui_renderer_front(r), 1, 0,
			"\xe4\xb8\xad\xe6\x96\x87", red);
	tui_screen_puts(tui_renderer_front(r), 3, 2, "XY", tui_attr_default());
	{
		int rc = tui_renderer_flush(r, -1, -1);

		OK(rc == 3, "fa-flush-3-rows");
		OK(r->sink.stats_drains == 1, "fa-one-drain-per-flush");
		OK(r->sink.stats_writes >= 1 && r->sink.stats_writes <= 4,
		   "fa-writes-le-4");
	}
	/* 再 flush（无变化）→ 又一次 drain（空批次也计数：drain==flush） */
	OK(tui_renderer_flush(r, -1, -1) == 0, "fa-flush-nochange-0");
	OK(r->sink.stats_drains == 2, "fa-drains-eq-flushes");

	/* 读回并验证三行字节齐全有序（行0 → 行1 → 行3；行3 先 CUP 后
	 * SGR 复位——red_bold→default 有样式清除走 ESC[0） */
	{
		static const char exp[] =
			"\x1b[1;1HHi"
			"\x1b[2;1H\x1b[1;38;5;1m\xe4\xb8\xad\xe6\x96\x87"
			"\x1b[4;3H\x1b[0mXY";
		size_t want = sizeof(exp) - 1;

		OK(read_exact(pfd[0], got, want, 2000) == 0 &&
		   memcmp(got, exp, want) == 0, "fa-bytes-golden");
	}

	tui_sink_set_blocking(&r->sink);
	tui_renderer_destroy(r);
	close(pfd[0]);
	close(pfd[1]);
}

/* ---- 3. 字节流全等：缓冲 renderer == 直写 renderer（同输入同输出） ---- */

/* 内存汇：收集直写流（golden 对拍口径，照 test_render） */
struct sinkbuf_mem {
	char b[8192];
	size_t n;
};

static void sinkbuf_mem_fn(void *ctx, const char *d, size_t n)
{
	struct sinkbuf_mem *m = ctx;

	if (m->n + n <= sizeof(m->b)) {
		memcpy(m->b + m->n, d, n);
		m->n += n;
	}
}

static void test_parity_direct(void)
{
	struct sinkbuf_mem mm;
	tui_sink direct;
	tui_sink sbuf;
	tui_renderer *ra, *rb;
	int pfd[2];
	tui_attr red = tui_attr_default();
	char got[8192];

	red.fg = tui_color_idx(203);
	unsetenv("OCC_TUI_WD_MS");
	memset(&mm, 0, sizeof(mm));
	memset(&direct, 0, sizeof(direct));
	direct.fn = sinkbuf_mem_fn;
	direct.ctx = &mm;
	OK(pipe(pfd) == 0, "par-pipe");
	OK(tui_sink_init_fd_buf(&sbuf, pfd[1]) == 0, "par-init");
	ra = tui_renderer_create(4, 8, direct);
	rb = tui_renderer_create(4, 8, sbuf);
	OK(ra && rb, "par-ren-create");

	/* 同输入：need_clear + 脏 2 行（SGR+双宽）+ 尾光标 CUP */
	tui_renderer_clear(ra);
	tui_renderer_clear(rb);
	tui_screen_puts(tui_renderer_front(ra), 1, 1, "ok",
			tui_attr_default());
	tui_screen_puts(tui_renderer_front(rb), 1, 1, "ok",
			tui_attr_default());
	tui_screen_puts(tui_renderer_front(ra), 2, 0, "\xe6\xb1\x89", red);
	tui_screen_puts(tui_renderer_front(rb), 2, 0, "\xe6\xb1\x89", red);
	OK(tui_renderer_flush(ra, 3, 3) == 2, "par-a-flush");
	OK(tui_renderer_flush(rb, 3, 3) == 2, "par-b-flush");

	/* B 流（pipe 读回）与 A 内存流逐字节全等——缓冲化不改变字节总序 */
	OK(mm.n > 0, "par-a-collected");
	OK(read_exact(pfd[0], got, mm.n, 2000) == 0 &&
	   memcmp(got, mm.b, mm.n) == 0, "par-bytes-identical");
	tui_sink_set_blocking(&rb->sink);
	tui_renderer_destroy(ra);
	tui_renderer_destroy(rb);
	close(pfd[0]);
	close(pfd[1]);
}

/* ---- 3b. 扩容路径：150KB（>初始 64KB）单批保真（临时文件 fd——普通
 * 文件永不 EAGAIN，读回不经由并发消费者，drain 一次成功） ---- */
static void test_growth(void)
{
	tui_sink s;
	FILE *tf = tmpfile();
	char *big;
	size_t i, n = 150 * 1024;
	char got[8192];
	size_t have = 0;
	int fd;

	unsetenv("OCC_TUI_WD_MS");
	OK(tf != NULL, "grow-tmpfile");
	if (!tf)
		return;
	fd = fileno(tf);
	big = malloc(n);
	OK(big != NULL, "grow-alloc");
	if (!big) {
		fclose(tf);
		return;
	}
	for (i = 0; i < n; i++)
		big[i] = (char)('A' + i % 26);
	OK(tui_sink_init_fd_buf(&s, fd) == 0, "grow-init");
	OK(s.bcap == 64 * 1024, "grow-initial-64k");
	/* 三段追加共 150KB → 触发 64K→128K→256K 扩容 */
	s.fn(s.ctx, big, n / 2);
	s.fn(s.ctx, big + n / 2, n / 2 - 10);
	s.fn(s.ctx, big + n - 10, 10);
	OK(s.blen == n, "grow-blen-150k");
	OK(s.bcap >= n && s.bcap <= TUI_SINK_BUF_MAX, "grow-cap-expanded");
	OK(tui_sink_drain(&s) == 0, "grow-drain-ok");
	OK(s.ovf == 0, "grow-no-ovf");
	/* 读回整段对拍 */
	OK(lseek(fd, 0, SEEK_SET) == 0, "grow-seek0");
	while (have < n) {
		ssize_t r = read(fd, got, sizeof(got));

		if (r <= 0)
			break;
		if (memcmp(got, big + have, (size_t)r) != 0)
			break;
		have += (size_t)r;
	}
	OK(have == n, "grow-bytes-all-equal");
	free(big);
	tui_sink_set_blocking(&s);
	tui_sink_fini(&s);
	fclose(tf);
}

/* ---- 4. wd 超时：填满 pipe + OCC_TUI_WD_MS=300 → -2/粘性 ---- */
static void test_wd_timeout(void)
{
	int pfd[2];
	tui_sink s;
	char big[65536];
	uint64_t t0, el;

	setenv("OCC_TUI_WD_MS", "300", 1);
	OK(pipe(pfd) == 0, "wd-pipe");
	OK(tui_sink_init_fd_buf(&s, pfd[1]) == 0, "wd-init");
	OK(s.wd_ms == 300, "wd-env-300");
	/* 填满 pipe（O_NONBLOCK 下写至 EAGAIN=消费端停摆仿真） */
	while (write(pfd[1], big, sizeof(big)) > 0)
		;
	OK(errno == EAGAIN, "wd-pipe-full-eagain");
	s.fn(s.ctx, "STUCK-FRAME", 11);
	t0 = now_ms();
	OK(tui_sink_drain(&s) == -2, "wd-drain-neg2");
	el = now_ms() - t0;
	OK(s.wd_fired == 1, "wd-fired");
	OK(s.blen == 0, "wd-buf-discarded");
	OK(el >= 250 && el < 3000, "wd-elapsed-sane");	/* ~300ms，非秒级 */
	/* 粘性：楔死后二次 drain 立返（leave 收尾不再等第二个 wd 周期） */
	t0 = now_ms();
	OK(tui_sink_drain(&s) == -2, "wd-sticky-neg2");
	OK(now_ms() - t0 < 200, "wd-sticky-fast");
	tui_sink_set_blocking(&s);
	tui_sink_fini(&s);
	close(pfd[0]);
	close(pfd[1]);
	unsetenv("OCC_TUI_WD_MS");
}

/* ---- 5. IO 错：读端关闭 → drain -1 ---- */
static void test_io_error(void)
{
	int pfd[2];
	tui_sink s;

	unsetenv("OCC_TUI_WD_MS");
	OK(pipe(pfd) == 0, "io-pipe");
	OK(tui_sink_init_fd_buf(&s, pfd[1]) == 0, "io-init");
	close(pfd[0]);			/* 消费端消亡（pty 消亡同型） */
	signal(SIGPIPE, SIG_IGN);	/* EPIPE 以返回值到达（occ 链同判） */
	s.fn(s.ctx, "ORPHAN", 6);
	OK(tui_sink_drain(&s) == -1, "io-drain-neg1");
	OK(s.blen == 0, "io-buf-discarded");
	OK(s.wd_fired == 0, "io-not-wd");
	tui_sink_set_blocking(&s);
	tui_sink_fini(&s);
	close(pfd[1]);
}

/* ---- 6. set_blocking 幂等 + flags 精确还原 ---- */
static void test_set_blocking(void)
{
	int pfd[2];
	tui_sink s;
	int fl0, fl1;

	unsetenv("OCC_TUI_WD_MS");
	OK(pipe(pfd) == 0, "sb-pipe");
	fl0 = fcntl(pfd[1], F_GETFL);	/* 记原始（含可能已有的 O_NONBLOCK） */
	OK(fl0 >= 0, "sb-getfl0");
	OK(tui_sink_init_fd_buf(&s, pfd[1]) == 0, "sb-init");
	fl1 = fcntl(pfd[1], F_GETFL);
	OK(fl1 == (fl0 | O_NONBLOCK), "sb-nonblock-applied");
	tui_sink_set_blocking(&s);
	OK(fcntl(pfd[1], F_GETFL) == fl0, "sb-restore-exact");
	tui_sink_set_blocking(&s);	/* 幂等 */
	tui_sink_set_blocking(&s);
	OK(fcntl(pfd[1], F_GETFL) == fl0, "sb-idempotent");
	tui_sink_fini(&s);
	close(pfd[0]);
	close(pfd[1]);
}

/* ---- 7. 512KB 硬上限：超限=按消费失败 -1 ---- */
static void test_overflow(void)
{
	int pfd[2];
	tui_sink s;
	char *big;

	unsetenv("OCC_TUI_WD_MS");
	big = malloc(TUI_SINK_BUF_MAX + 16);
	OK(big != NULL, "ovf-alloc");
	if (!big)
		return;
	memset(big, 'X', TUI_SINK_BUF_MAX + 16);
	OK(pipe(pfd) == 0, "ovf-pipe");
	OK(tui_sink_init_fd_buf(&s, pfd[1]) == 0, "ovf-init");
	s.fn(s.ctx, big, TUI_SINK_BUF_MAX + 16);	/* 单段超限 */
	OK(s.ovf == 1, "ovf-flag-set");
	OK(s.blen == 0, "ovf-nothing-stored");
	OK(tui_sink_drain(&s) == -1, "ovf-drain-neg1");
	s.fn(s.ctx, "zz", 2);		/* 判死后追加=丢弃 */
	OK(s.blen == 0, "ovf-post-drop");
	free(big);
	tui_sink_set_blocking(&s);
	tui_sink_fini(&s);
	close(pfd[0]);
	close(pfd[1]);
}

/* ---- 8. renderer 级 wd：flush 尾 drain 透传 -2 ---- */
static void test_renderer_wd(void)
{
	int pfd[2];
	tui_sink s;
	tui_renderer *r;
	char big[65536];

	setenv("OCC_TUI_WD_MS", "300", 1);
	OK(pipe(pfd) == 0, "rw-pipe");
	OK(tui_sink_init_fd_buf(&s, pfd[1]) == 0, "rw-init");
	r = tui_renderer_create(4, 8, s);
	OK(r != NULL, "rw-ren");
	while (write(pfd[1], big, sizeof(big)) > 0)
		;
	tui_screen_puts(tui_renderer_front(r), 0, 0, "WD", tui_attr_default());
	OK(tui_renderer_flush(r, -1, -1) == -2, "rw-flush-neg2");
	OK(r->sink.wd_fired == 1, "rw-fired");
	tui_sink_set_blocking(&r->sink);
	tui_renderer_destroy(r);
	close(pfd[0]);
	close(pfd[1]);
	unsetenv("OCC_TUI_WD_MS");
}

/* ---- 9. env 语义：0=禁用；空 drain 立即成功 ---- */
static void test_env_semantics(void)
{
	int pfd[2];
	tui_sink s;

	setenv("OCC_TUI_WD_MS", "0", 1);
	OK(pipe(pfd) == 0, "env-pipe");
	OK(tui_sink_init_fd_buf(&s, pfd[1]) == 0, "env-init");
	OK(s.wd_ms == 0, "env-zero-disabled");
	OK(tui_sink_drain(&s) == 0, "env-empty-drain-ok");	/* 无限等≠空转 */
	tui_sink_set_blocking(&s);
	tui_sink_fini(&s);
	close(pfd[0]);
	close(pfd[1]);
	unsetenv("OCC_TUI_WD_MS");
}

int main(void)
{
	test_append_order();
	test_frame_atomic();
	test_parity_direct();
	test_growth();
	test_wd_timeout();
	test_io_error();
	test_set_blocking();
	test_overflow();
	test_renderer_wd();
	test_env_semantics();
	printf("test_sinkbuf: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
