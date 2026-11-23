/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_gate_pty.c - q17 回归：gate 输入泵端到端（pty 驱动 SETUP/LOGIN）
 *
 * 背景（q17 audit A-1，实机抓获）：gate 只出队（tui_input_next）不进队
 * （无人 read+tui_input_feed）——首屏画完即冻死，掩码/两段确认/3 错冷却
 * 在实机全部不可达。本测试在真 pty 上驱动 tui_gate_enter() 全流：
 *   A. SETUP：短密码 →「至少 6 位」；两次不一致 →「两次不一致」；
 *      正确×2 → tui_gate_enter()==0 + 凭据文件 0600 + admin:$6$ 前缀。
 *      （掩码/错误消息随按键重绘=输入泵活的直接证据。）
 *   B. LOGIN：错误密码×3 →「尝试过多，冷却」（泵+计数+冷却路径）。
 *   C. 双控制台覆写守卫（q17 覆写探针）：SETUP 提交时凭据文件已存在
 *      → 拒写转 LOGIN（「密码已由其他控制台设置」）。
 *   D. P-2a 双用户登录（用户名框/逐用户计数/冷却独立/last 预填）。
 *   E. P-60/D1（CON-02b）凭据「读不了」≠「没有」：gate 路径是目录
 *      （fopen 成功、读取出错 EISDIR）→ 诚实报错屏（「登录凭据不可读」）、
 *      零 SETUP 向导文案、等键后以 TUI_GATE_DENIED 退出（与 uid 无关）。
 *   F. 同上·权限面：属主他人 0600 的凭据文件。root 跑=root 造文件+子进程
 *      降权 nobody（原型 F1）；非 root 跑=自家只写文件 0200（等价 EACCES，
 *      F2），原型显式 SKIP 不冒充。各带对照：文件恢复可读 → LOGIN →
 *      正确密码解锁（证明降权/桩本身没坏，报错确由权限引起）。
 *   G. P-60 进程内失败计数：凭据「可读不可写」（0644、属主非当前用户；
 *      root=造文件+降权，非 root=自家只读目录内 0644）→ 连错 3 次触发
 *      冷却、冷却期内第 4 次「冷却中」；冷却期满计数清零（下一错从
 *      1/3 起算、正确密码可解锁）；文件字节不动。
 *   H. D1 SETUP 提交复核：向导进行中凭据文件「出现但读不出」→ 不覆写
 *      （旧口径 fopen 失败=不在→新建覆写+解锁）、转诚实报错屏（非 root）。
 *   D7（DEC-07 过渡方案）：A/D 段的文件权限断言为「契约值」——root 且
 *      机器上有 aik-gate 组=0640 root:aik-gate（期望值测试侧独立查组得出），
 *      否则 0600；有组环境须 root 且显式开关 AIK_TEST_HAVE_GATE_GROUP=1
 *      （测试自建组 gid 942、atexit 删组）。
 */
#define _XOPEN_SOURCE 700	/* posix_openpt/grantpt/unlockpt/ptsname */
#define _DEFAULT_SOURCE 1
#define _GNU_SOURCE 1		/* ptsname_r */

#include "tui_gate.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>				/* P-60/D1：setgroups（降权） */
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int fails;

#define CHECK(cond) do { \
	if (!(cond)) { fails++; \
		printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

static char acc[65536];
static size_t acc_n;
static char g_last[160];			/* P-2a：last-user 隔离桩路径 */

/* P-60/D1：降权/退出码透传（F/G 用例）。g_drop_uid 非 0=gate 子进程
 * setresuid 降到该裸 uid（只有 root 跑的测试进程有权——「属主他人文件」
 * 的权限面才成立）；g_raw_exit=子进程以 tui_gate_enter() 原值退出
 * （区分 TUI_GATE_DENIED 与一般未解锁的 42）。 */
#define NOBODY_UID 65534		/* 不查 passwd：root 可降到任意裸 uid */
static uid_t g_drop_uid;
static int g_raw_exit;

/* ⑨c/H 只写凭据桩（有效 admin 条目形态；哈希体为桩字节，非真密） */
#define WO_LINE ("admin:$6$wo$" \
		 "WronlyWronlyWronlyWronlyWronlyWronlyWronly" \
		 "WronlyWronlyWronlyWronlyWronlyWronlyWronly:1\n")

/* P-60/D7：写出文件的权限契约——期望值由测试侧独立查组得出（不复用
 * 被测的判定函数，免得「把契约改没了」的变异连期望值一起改）。
 * 有组环境：仅 root 且显式开关 AIK_TEST_HAVE_GATE_GROUP=1 才建组
 * （gid 942=出厂定值），atexit 兜底删组（C 侧的「trap」）；机器上本有
 * 该组=沿用、不建不删；否则测 0600 老口径。 */
static int g_made_group;

static void gate_group_cleanup(void)
{
	if (g_made_group) {
		int rc = system("groupdel aik-gate >/dev/null 2>&1");

		if (rc != 0)
			printf("WARN groupdel aik-gate failed (rc=%d) -- "
			       "please clean up\n", rc);
	}
}

static void gate_group_setup(void)
{
	struct group gr, *res = NULL;
	char buf[2048];
	const char *sw;

	if (geteuid() != 0)
		return;
	if (getgrnam_r("aik-gate", &gr, buf, sizeof(buf), &res) == 0 && res) {
		printf("[D7] machine has aik-gate (gid %u): 0640 path\n",
		       (unsigned)gr.gr_gid);
		return;
	}
	sw = getenv("AIK_TEST_HAVE_GATE_GROUP");
	if (!sw || strcmp(sw, "1") != 0) {
		printf("SKIP D7 0640 path (needs AIK_TEST_HAVE_GATE_GROUP=1;"
		       " testing 0600 fallback)\n");
		return;
	}
	if (system("groupadd -g 942 aik-gate >/dev/null 2>&1") == 0) {
		g_made_group = 1;
		printf("[D7] created group aik-gate gid 942 (groupdel at "
		       "exit): 0640 path\n");
	} else {
		printf("SKIP D7 0640 path (groupadd -g 942 aik-gate failed;"
		       " testing 0600 fallback)\n");
	}
}

static int test_wide(gid_t *gid)
{
	struct group gr, *res = NULL;
	char buf[2048];

	if (geteuid() != 0)
		return 0;
	if (getgrnam_r("aik-gate", &gr, buf, sizeof(buf), &res) != 0 || !res)
		return 0;
	if (gid)
		*gid = gr.gr_gid;
	return 1;
}

static mode_t expect_gate_mode(void)
{
	return test_wide(NULL) ? (mode_t)0640 : (mode_t)0600;
}

static int find_tok(const char *tok)
{
	size_t tl = strlen(tok);
	size_t i;

	if (tl == 0 || acc_n < tl)
		return 0;
	for (i = 0; i + tl <= acc_n; i++)
		if (memcmp(acc + i, tok, tl) == 0)
			return 1;
	return 0;
}

static int wait_tok(int mfd, const char *tok, int sec)
{
	time_t t0 = time(NULL);
	struct pollfd p = { .fd = mfd, .events = POLLIN };

	while (time(NULL) - t0 < sec) {
		if (find_tok(tok))
			return 1;
		if (poll(&p, 1, 400) > 0 && (p.revents & POLLIN)) {
			ssize_t n = read(mfd, acc + acc_n, 512);

			if (n <= 0)
				break;
			acc_n += (size_t)n;
			if (acc_n > sizeof(acc) - 1024)
				acc_n = 0;	/* 溢出保护：重accum */
		}
	}
	if (!find_tok(tok)) {
		size_t from = acc_n > 300 ? acc_n - 300 : 0;

		printf("[wait_tok miss %s] tail: %.*s\n", tok,
		       (int)(acc_n - from), acc + from);
	}
	return find_tok(tok);
}

static void feed(int mfd, const char *s)
{
	size_t n = strlen(s);
	char cr = '\r';

	(void)!write(mfd, s, n);
	(void)!write(mfd, &cr, 1);
}

/* P-2a：原样写字节（Tab/退格等控制键——feed 会补 \r 破坏控制流） */
static void feedraw(int mfd, const char *s)
{
	(void)!write(mfd, s, strlen(s));
}

/* 限时等子进程退出（q17 教训：waitpid 第三参是 flags 不是秒——
 * $6$ crypt ~200ms，误传 15=WNOHANG 组会在解锁完成前抢跑断言失败） */
static int wait_exit(pid_t pid, int *status, int sec)
{
	time_t t0 = time(NULL);

	while (time(NULL) - t0 < sec) {
		if (waitpid(pid, status, WNOHANG) == pid)
			return 1;
		usleep(100000);
	}
	return waitpid(pid, status, WNOHANG) == pid;
}

/* 起 gate 子进程：stdin/stdout=pty slave；返回 master fd，*pid 出参 */
static int spawn_gate(const char *path, pid_t *pid)
{
	int m = posix_openpt(O_RDWR | O_NOCTTY);
	char slave[128];
	struct winsize wz = { .ws_row = 24, .ws_col = 80 };

	if (m < 0)
		return -1;
	if (grantpt(m) != 0 || unlockpt(m) != 0) {
		close(m);
		return -1;
	}
	if (ptsname_r(m, slave, sizeof(slave)) != 0) {
		close(m);
		return -1;
	}
	*pid = fork();
	if (*pid < 0) {
		close(m);
		return -1;
	}
	if (*pid == 0) {
		int s = open(slave, O_RDWR);

		if (s < 0)
			_exit(99);
		setsid();
		/* TIOCSCTTY 尽力而为：gate 只按 stdin 是 tty 工作 */
		(void)!ioctl(s, TIOCSCTTY, 0);
		dup2(s, 0);
		dup2(s, 1);
		dup2(s, 2);
		if (s > 2)
			close(s);
		close(m);
		setenv("AIK_CONSOLE_GATE", path, 1);
		setenv("AIK_CONSOLE_GATE_LAST", g_last, 1);
		unsetenv("AIK_CONSOLE_GATE_SKIP");
		if (g_drop_uid) {
			/* 降权到 nobody 类裸 uid。顺序：先清补充组（需 root，
			 * 必须在 setuid 前）→ setresgid → setresuid（real/
			 * effective/saved 一并降，不可逆）；失败即以专用码退
			 * （不被当成 gate 行为）。pty 三件已在降权前 dup 好。 */
			if (setgroups(0, NULL) != 0 ||
			    setresgid(g_drop_uid, g_drop_uid, g_drop_uid) != 0 ||
			    setresuid(g_drop_uid, g_drop_uid, g_drop_uid) != 0 ||
			    geteuid() != g_drop_uid || getegid() != g_drop_uid)
				_exit(97);
		}
		{
			int grc = tui_gate_enter();

			_exit(g_raw_exit ? grc : (grc == 0 ? 0 : 42));
		}
	}
	ioctl(m, TIOCSWINSZ, &wz);
	return m;
}

static void write_file(const char *p, const char *s)
{
	FILE *f = fopen(p, "w");

	if (!f) {
		CHECK(f != NULL);
		return;
	}
	fputs(s, f);
	fclose(f);
}

static int file_eq(const char *path, const char *want)
{
	char buf[1024];
	FILE *f = fopen(path, "r");
	size_t n;

	if (!f)
		return 0;
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	return strcmp(buf, want) == 0;
}

/* P-60/D1：凭据不可读报错屏断言——诚实文案在（why=「原因：」行 token，
 * 可 NULL）、SETUP 向导文案零出现、未按键不退、任意一键后以
 * TUI_GATE_DENIED 退出。调用方须在 spawn 前 acc_n=0（或提交前清一次
 * ——SETUP 文案若是此前正当出现的，只认提交后的新字节）。 */
static void denied_case(int m, pid_t pid, const char *why)
{
	int status;

	CHECK(wait_tok(m, "登录凭据不可读", 8));
	if (why)
		CHECK(wait_tok(m, why, 8));
	CHECK(wait_tok(m, "按任意键退出", 8));
	/* 不得落进 SETUP 向导（标题/首次使用/设置密码/确认密码） */
	CHECK(!find_tok("首次使用"));
	CHECK(!find_tok("AIKernel 初始化"));
	CHECK(!find_tok("设置密码"));
	CHECK(!find_tok("确认密码"));
	/* 未按键不退（报错屏可读；不自旋自退） */
	usleep(600000);
	CHECK(waitpid(pid, &status, WNOHANG) == 0);
	/* 任意一键（Enter）后非零退出，且是 DENIED 专属码 */
	feedraw(m, "\r");
	CHECK(wait_exit(pid, &status, 15));
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == TUI_GATE_DENIED);
}

/* 本用例（自 f0 起）是否零失败——分段状态行用 */
static const char *case_status(int f0)
{
	return fails == f0 ? "ok" : "FAIL";
}

int main(void)
{
	char tmpl[] = "/tmp/q17gate_pty_XXXXXX";
	char path[128];
	struct stat st;
	char head[16];
	int m, status;
	pid_t pid;
	FILE *f;

	alarm(60);	/* gate 冻死类回归=挂起形态，60s 硬杀 */
	atexit(gate_group_cleanup);		/* P-60/D7：本测试建的组退出即删 */
	gate_group_setup();

	/* A: SETUP 全流 */
	{
		int fd = mkstemp(tmpl);

		CHECK(fd >= 0);
		close(fd);
		unlink(tmpl);	/* SETUP 要求凭据文件不存在 */
		snprintf(path, sizeof(path), "%s", tmpl);

		snprintf(g_last, sizeof(g_last), "%s-last", path);
		unlink(g_last);
		acc_n = 0;
		m = spawn_gate(path, &pid);
		CHECK(m >= 0);
		CHECK(wait_tok(m, "AIKernel 初始化", 8));
		feed(m, "abc");
		CHECK(wait_tok(m, "至少 6 位", 8));
		feed(m, "aaa123");
		/* diff 渲染只发变化格：提示行 token（设置密码→确认密码）不连续，
		 * 用整行绘制的状态行 token 断言（q17 实机口径同此）。 */
		CHECK(wait_tok(m, "再输入一次确认", 8));
		feed(m, "bbb123");
		CHECK(wait_tok(m, "两次不一致", 8));
		feed(m, "q17pw1!");
		CHECK(wait_tok(m, "再输入一次确认", 8));
		feed(m, "q17pw1!");
		CHECK(wait_exit(pid, &status, 15));
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		CHECK(stat(path, &st) == 0);
		/* P-60/D7：向导建出的文件=契约值（root 且有 aik-gate 组=
		 * 0640 root:aik-gate；否则 0600——期望值测试侧独立得出） */
		CHECK((st.st_mode & 0777) == expect_gate_mode());
		{
			gid_t gg = 0;

			if (test_wide(&gg))
				CHECK(st.st_uid == 0 && st.st_gid == gg);
		}
		f = fopen(path, "r");
		CHECK(f != NULL);
		if (f) {
			size_t n = fread(head, 1, 9, f);
			fclose(f);
			CHECK(n == 9 && strncmp(head, "admin:$6$", 9) == 0);
		}
		close(m);
		printf("test_gate_pty A (setup flow): %s\n",
		       fails ? "FAIL" : "ok");
	}

	/* B: LOGIN 3 错 → 冷却 */
	{
		printf("[B] gate file: exists=%d mode=%o\n",
		       stat(path, &st) == 0, stat(path, &st) == 0 ?
		       (unsigned)(st.st_mode & 0777) : 0u);
		acc_n = 0;
		m = spawn_gate(path, &pid);
		CHECK(m >= 0);
		CHECK(wait_tok(m, "Enter 登录", 8));
		feed(m, "wrong1");
		CHECK(wait_tok(m, "密码不正确", 8));
		feed(m, "wrong2");
		feed(m, "wrong3");
		CHECK(wait_tok(m, "尝试过多，冷却", 8));
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		close(m);
		printf("test_gate_pty B (login+cooldown): %s\n",
		       fails ? "FAIL" : "ok");
	}

	/* C: 覆写守卫——凭据已在时 SETUP 提交拒绝转 LOGIN */
	{
		acc_n = 0;
		m = spawn_gate(path, &pid);
		CHECK(m >= 0);
		CHECK(wait_tok(m, "Enter 登录", 8));	/* 文件在=LOGIN */
		/* 删文件 + 提交 → 文件消失路径转 SETUP（q17 audit A-8 面） */
		unlink(path);
		feed(m, "zzz999");
		CHECK(wait_tok(m, "首次使用", 8));
		feed(m, "zzz999");
		CHECK(wait_tok(m, "再输入一次确认", 8));
		/* 另一控制台抢先设密（stale-SETUP 覆写探针场景） */
		{
			char h[128];

			CHECK(tui_gate_hash("stolen77", h) == 0);
			CHECK(tui_gate_write(path, h) == 0);
		}
		feed(m, "zzz999");
		CHECK(wait_tok(m, "密码已由其他控制台设置", 8));
		/* stolen77 可登录=未覆写 */
		feed(m, "stolen77");
		CHECK(wait_exit(pid, &status, 15));
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		close(m);
		unlink(path);
		printf("test_gate_pty C (overwrite guard): %s\n",
		       fails ? "FAIL" : "ok");
	}

	/* D: P-2a 双用户登录（用户名框+密码错/对、逐用户独立计数、
	 * 冷却独立、last 预填与落盘）——gate 文件 admin+u1+u2 三条目 */
	{
		char h_admin[128], h_u1[128], h_u2[128], rd[128];
		char lb[64];
		int ff = -1;
		FILE *lf;

		CHECK(tui_gate_hash("adm-p2a-pw", h_admin) == 0);
		CHECK(tui_gate_hash("u1-p2a-pw", h_u1) == 0);
		CHECK(tui_gate_hash("u2-p2a-pw", h_u2) == 0);
		CHECK(tui_gate_write(path, h_admin) == 0);
		CHECK(tui_gate_write_entry(path, "u1", h_u1, 0) == 0);
		CHECK(tui_gate_write_entry(path, "u2", h_u2, 0) == 0);
		unlink(g_last);			/* 无 last → 预填 admin */

		/* D1: u1 错一次——计数只落 u1 行 */
		acc_n = 0;
		m = spawn_gate(path, &pid);
		CHECK(m >= 0);
		CHECK(wait_tok(m, "Enter 登录", 8));
		CHECK(wait_tok(m, "用户", 8));			/* 用户名框在屏 */
		feedraw(m, "\t");				/* Tab→用户名框 */
		feedraw(m, "\x7f\x7f\x7f\x7f\x7f");	/* 退格清预填 admin */
		feed(m, "u1");				/* 用户名+Enter 跳密码 */
		feed(m, "wrong-pw");
		CHECK(wait_tok(m, "密码不正确（1/3）", 8));
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		close(m);
		CHECK(tui_gate_read_user(path, "u1", rd, &ff) == 0 && ff == 1);
		CHECK(tui_gate_read_user(path, "u2", rd, &ff) == 0 && ff == 0);
		CHECK(tui_gate_read_user(path, "admin", rd, &ff) == 0 &&
		      ff == 0);

		/* D2: 预填 admin——不动用户名直接打密码（老习惯兼容）；
		 * admin 计数独立于 u1 */
		acc_n = 0;
		m = spawn_gate(path, &pid);
		CHECK(m >= 0);
		CHECK(wait_tok(m, "Enter 登录", 8));
		feed(m, "wrong-pw");
		CHECK(wait_tok(m, "密码不正确（1/3）", 8));
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		close(m);
		CHECK(tui_gate_read_user(path, "admin", rd, &ff) == 0 &&
		      ff == 1);
		CHECK(tui_gate_read_user(path, "u1", rd, &ff) == 0 && ff == 1);

		/* D3: ghost 拒绝（不枚举用户）→ 改回 u1 成功 + last 落盘 */
		acc_n = 0;
		m = spawn_gate(path, &pid);
		CHECK(m >= 0);
		CHECK(wait_tok(m, "Enter 登录", 8));
		feedraw(m, "\t");
		feedraw(m, "\x7f\x7f\x7f\x7f\x7f");	/* 退格清预填 */
		feed(m, "ghost");
		feed(m, "whatever");
		CHECK(wait_tok(m, "用户名或密码不正确", 8));
		feedraw(m, "\t");			/* 用户名框保留 ghost */
		feedraw(m, "\x7f\x7f\x7f\x7f\x7f");
		feed(m, "u1");
		feed(m, "u1-p2a-pw");
		CHECK(wait_exit(pid, &status, 15));
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		close(m);
		lf = fopen(g_last, "r");
		CHECK(lf != NULL);
		if (lf) {
			CHECK(fgets(lb, sizeof(lb), lf) != NULL &&
			      strcmp(lb, "u1\n") == 0);
			fclose(lf);
		}
		CHECK(tui_gate_read_user(path, "u1", rd, &ff) == 0 &&
		      ff == 0);			/* 成功清零 */

		/* D4: u1（预填）打满 3 错触发冷却——u2 不受牵连可登录
		 * （逐用户独立：非阻塞冷却） */
		acc_n = 0;
		m = spawn_gate(path, &pid);
		CHECK(m >= 0);
		CHECK(wait_tok(m, "Enter 登录", 8));
		feed(m, "w1");
		CHECK(wait_tok(m, "密码不正确（1/3）", 8));
		feed(m, "w2");
		/* 差分渲染只发变化格：1/3→2/3 仅一个数字格变化，字节流
		 * 不再含完整 token——以文件计数为准（写侧同步落盘） */
		usleep(700000);
		CHECK(tui_gate_read_user(path, "u1", rd, &ff) == 0 &&
		      ff == 2);
		feed(m, "w3");
		CHECK(wait_tok(m, "尝试过多，冷却", 8));
		feedraw(m, "\t");			/* 冷却中切用户名 */
		feedraw(m, "\x7f\x7f");			/* 清 "u1" */
		feed(m, "u2");
		feed(m, "u2-p2a-pw");
		CHECK(wait_exit(pid, &status, 15));
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		close(m);
		CHECK(tui_gate_read_user(path, "u1", rd, &ff) == 0 &&
		      ff == 3);			/* u1 计数留痕 */
		CHECK(tui_gate_read_user(path, "u2", rd, &ff) == 0 &&
		      ff == 0);
		/* P-60/D7：登录计数多次重写（tui_gate_write_entry 的更新
		 * 路径）之后，文件权限仍是契约值 */
		CHECK(stat(path, &st) == 0 &&
		      (st.st_mode & 0777) == expect_gate_mode());
		{
			gid_t gg = 0;

			if (test_wide(&gg))
				CHECK(st.st_uid == 0 && st.st_gid == gg);
		}
		printf("test_gate_pty D (multi-user login): %s\n",
		       fails ? "FAIL" : "ok");
	}

	/* E~G（G 含 10s 冷却等待）：重置挂起硬杀线 */
	alarm(150);

	/* E: P-60/D1——gate 路径是目录（fopen 成功、读取出错 EISDIR）。
	 * 与 uid 无关（root/非 root 同路）：不得出现 SETUP 向导文案，应出
	 * 诚实报错，等键后以 TUI_GATE_DENIED 退出；目录本身与邻域不被写动。 */
	{
		char dpath[128], tmpchk[160];
		int f0 = fails;

		snprintf(dpath, sizeof(dpath), "%s.gatedir", tmpl);
		unlink(dpath);
		CHECK(mkdir(dpath, 0700) == 0);
		g_raw_exit = 1;
		acc_n = 0;
		m = spawn_gate(dpath, &pid);
		CHECK(m >= 0);
		denied_case(m, pid, "原因：凭据文件不是普通文件");
		close(m);
		g_raw_exit = 0;
		snprintf(tmpchk, sizeof(tmpchk), "%s.tmp", dpath);
		CHECK(access(tmpchk, 0) != 0);	/* 无 tmp 残留 */
		CHECK(stat(dpath, &st) == 0 && S_ISDIR(st.st_mode));
		rmdir(dpath);
		printf("test_gate_pty E (gate path is a directory -> honest "
		       "screen, no SETUP wizard): %s\n", case_status(f0));
	}

	/* F: P-60/D1——凭据文件在却读不出（权限）。原型=属主他人 0600：
	 * 造文件+降权需 root（F1）；非 root 跑等价形态 F2（自家只写 0200：
	 * owner 无 r 位且无 CAP_DAC_OVERRIDE → open EACCES），原型显式 SKIP
	 * 不冒充。两路各带对照：文件恢复可读 → LOGIN → 正确密码解锁。 */
	{
		char h[128], line[256];
		int f0 = fails;

		CHECK(tui_gate_hash("own-p60-pw", h) == 0);
		snprintf(line, sizeof(line), "admin:%s:1700000000\n", h);
		unlink(g_last);
		if (geteuid() == 0) {
			write_file(path, line);
			CHECK(chmod(path, 0600) == 0);
			g_drop_uid = NOBODY_UID;
			g_raw_exit = 1;
			acc_n = 0;
			m = spawn_gate(path, &pid);
			CHECK(m >= 0);
			denied_case(m, pid, "原因：权限不足");
			close(m);
			/* 凭据文件未被 SETUP 路径写动：权限与内容逐字不变 */
			CHECK(stat(path, &st) == 0 &&
			      (st.st_mode & 0777) == 0600);
			CHECK(file_eq(path, line));
			/* 对照：改 0644 可读 → LOGIN → 正确密码解锁 */
			CHECK(chmod(path, 0644) == 0);
			g_raw_exit = 0;
			acc_n = 0;
			m = spawn_gate(path, &pid);
			CHECK(m >= 0);
			CHECK(wait_tok(m, "Enter 登录", 8));
			CHECK(!find_tok("登录凭据不可读"));
			feed(m, "own-p60-pw");
			CHECK(wait_exit(pid, &status, 15));
			CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
			close(m);
			g_drop_uid = 0;
			printf("test_gate_pty F1 (owner-other 0600 gate, dropped "
			       "to nobody -> honest screen + readable control "
			       "logs in): %s\n", case_status(f0));
		} else {
			printf("SKIP F1 (root-only: owner-other 0600 gate + "
			       "setuid drop)\n");
			write_file(path, line);
			CHECK(chmod(path, 0200) == 0);
			g_raw_exit = 1;
			acc_n = 0;
			m = spawn_gate(path, &pid);
			CHECK(m >= 0);
			denied_case(m, pid, "原因：权限不足");
			close(m);
			CHECK(chmod(path, 0600) == 0);
			CHECK(file_eq(path, line));
			/* 对照：恢复可读 → LOGIN → 正确密码解锁 */
			g_raw_exit = 0;
			acc_n = 0;
			m = spawn_gate(path, &pid);
			CHECK(m >= 0);
			CHECK(wait_tok(m, "Enter 登录", 8));
			CHECK(!find_tok("登录凭据不可读"));
			feed(m, "own-p60-pw");
			CHECK(wait_exit(pid, &status, 15));
			CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
			close(m);
			printf("test_gate_pty F2 (write-only 0200 gate, self-owned "
			       "variant -> honest screen + readable control logs "
			       "in): %s\n", case_status(f0));
		}
		unlink(path);
	}

	/* G: P-60 进程内失败计数——凭据「可读不可写」（0644、属主非当前
	 * 用户）。root 跑=root 造文件+子进程降权 nobody；非 root 跑=自家
	 * 只读目录（0555）内 0644 文件（等价：tmp 建不成→写不进）。文件
	 * 计数恒 0，内存计数接管：连错 3 次触发冷却、冷却期内「冷却中」；
	 * 冷却期满计数清零（下一错从 1/3 起算，正确密码可解锁）。 */
	{
		char wdir[] = "/tmp/q17gate_ptyw_XXXXXX";
		char wpath[160], h[128], line[256], tmpchk[200];
		int f0 = fails;

		CHECK(tui_gate_hash("ro-p60-pw", h) == 0);
		snprintf(line, sizeof(line), "admin:%s:1700000000\n", h);
		CHECK(mkdtemp(wdir) != NULL);
		snprintf(wpath, sizeof(wpath), "%s/gate", wdir);
		write_file(wpath, line);
		CHECK(chmod(wpath, 0644) == 0);
		CHECK(chmod(wdir, 0555) == 0);	/* 目录不可写→tmp 建不成 */
		if (geteuid() == 0)
			g_drop_uid = NOBODY_UID;	/* 属主他人（root） */
		g_raw_exit = 0;
		unlink(g_last);
		acc_n = 0;
		m = spawn_gate(wpath, &pid);
		CHECK(m >= 0);
		CHECK(wait_tok(m, "Enter 登录", 8));	/* 可读=LOGIN 框 */
		feed(m, "wrong-a");
		CHECK(wait_tok(m, "密码不正确（1/3）", 8));
		feed(m, "wrong-b");
		/* 差分渲染只发变化格：1/3→2/3 仅一个数字格变化，字节流不含
		 * 完整 token（test D4 同注）；且本形态文件计数写不进无处
		 * 可查——直接打第 3 错，以冷却文案为内存计数到 3 的证据 */
		usleep(700000);
		feed(m, "wrong-c");
		CHECK(wait_tok(m, "尝试过多，冷却", 8));	/* 第 3 错触发 */
		feed(m, "wrong-d");
		CHECK(wait_tok(m, "冷却中", 8));		/* 冷却期内第 4 次 */
		/* 文件计数写不进：字节逐一动、无 tmp 残留（确为「不可写」） */
		CHECK(file_eq(wpath, line));
		snprintf(tmpchk, sizeof(tmpchk), "%s.tmp", wpath);
		CHECK(access(tmpchk, 0) != 0);
		/* 冷却期满（GATE_COOLDOWN_SEC=10）：计数清零——下一错从
		 * 1/3 起算（未清零则再触「尝试过多，冷却」） */
		sleep(11);
		acc_n = 0;		/* 旧 1/3 token 在缓冲里：清后再等新字节 */
		feed(m, "wrong-e");
		CHECK(wait_tok(m, "密码不正确（1/3）", 8));
		/* 计数=1（<3）：正确密码即可解锁 */
		feed(m, "ro-p60-pw");
		CHECK(wait_exit(pid, &status, 15));
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		close(m);
		g_drop_uid = 0;
		printf("test_gate_pty G (in-memory fail counter, readable-"
		       "unwritable gate%s): %s\n",
		       geteuid() == 0 ? ", dropped to nobody" :
		       ", self-owned variant",
		       case_status(f0));
		CHECK(chmod(wdir, 0700) == 0);
		unlink(wpath);
		rmdir(wdir);
	}

	/* H: P-60/D1——SETUP 提交复核：向导进行中凭据文件「出现但读不
	 * 出」（只写 0200；/tmp 可写——旧口径 fopen 失败=不在→新建覆写
	 * 原文件并以新密码解锁）。新口径：不覆写、转诚实报错屏。非 root
	 * 前提（root 读得了 0200 文件→走「已由其他控制台设置」路）。 */
	if (geteuid() == 0) {
		printf("SKIP H (non-root premise: root reads a 0200 file)\n");
		unlink(path);
	} else {
		int f0 = fails;

		unlink(path);
		g_raw_exit = 1;
		acc_n = 0;
		m = spawn_gate(path, &pid);	/* 文件不在→SETUP（正当） */
		CHECK(m >= 0);
		CHECK(wait_tok(m, "首次使用", 8));
		feed(m, "setup-p60-pw");
		CHECK(wait_tok(m, "再输入一次确认", 8));
		/* 此刻凭据文件「出现但读不出」 */
		write_file(path, WO_LINE);
		CHECK(chmod(path, 0200) == 0);
		acc_n = 0;		/* SETUP 文案是此前正当出现：只认提交后新字节 */
		feed(m, "setup-p60-pw");
		denied_case(m, pid, "原因：权限不足");
		close(m);
		g_raw_exit = 0;
		/* 原文件未被覆写（旧口径此处已被新 admin 行替换） */
		CHECK(chmod(path, 0600) == 0);
		CHECK(file_eq(path, WO_LINE));
		unlink(path);
		printf("test_gate_pty H (SETUP commit recheck: file appeared "
		       "but unreadable -> not overwritten, honest screen): "
		       "%s\n", case_status(f0));
	}
	unlink(g_last);

	printf("test_gate_pty: %s (%d fails)\n", fails ? "FAIL" : "all ok",
	       fails);
	return fails ? 1 : 0;
}
