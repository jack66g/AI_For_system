/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_su_pty.c - P-45 回归：/su 档位流转端到端（pty 驱动真 occ）
 *
 * 真机实证三缺陷（base=privileged 部署复现）：
 *   ① /su 0 后 footer 仍显「特权*」（fallback 星叠在档标后 + tier 未降）
 *   ② 降权后 /su 不弹密码框（「已特权」判定掺策略基础档）
 *   ③ 无密码重提权路径（/su 0 与 /su 读两层状态互不同步）
 *
 * 本测试在真 pty 上 fork+exec occ 二进制（fixture 隔离），桩凭据走
 * gate 同源机制（tui_gate_hash 生成——不硬编码真密码），policy.conf
 * 桩统一 restricted（base 档稳定 = 受限，与运行 uid 无关）。断言：
 *   A. /su → 密码 overlay（「admin 密码」字节）
 *   B. 错密码 → overlay 内「密码错误」+ audit.log fail 记账
 *   C. 对密码 → 「已提权至特权档」+ footer 新字节「特权*」
 *   D. 已特权再 /su → 「已在特权档（/su 0 回落）」
 *   E. /su 0 → 「已回落基础档位」+ footer 新字节「受限」且零「特权」
 *      （P-45 后 ctx fallback 星在水位段——档标段无假星）
 *   F. 降权后再 /su → 密码 overlay 再弹（重提权必过密码）
 *   G. audit.log 三笔齐：elevate fail / elevate ok / delevate ok
 */
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE 1

#include "tui_gate.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

#define OUT_CAP (2 * 1024 * 1024)

/* 测试桩密码（gate 哈希同源生成——非真机凭据） */
#define SU_PW "p45-pty-stub-pw"

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

static const char *find_bytes(const char *buf, int len, const char *needle)
{
	int nl = (int)strlen(needle);
	int i;

	if (nl == 0 || len < nl)
		return NULL;
	for (i = 0; i + nl <= len; i++)
		if (memcmp(buf + i, needle, (size_t)nl) == 0)
			return buf + i;
	return NULL;
}

static int read_until_contains(int fd, char *buf, int cap, int *have,
			       const char *needle, int timeout_ms)
{
	struct timespec start, now;
	const int nlen = (int)strlen(needle);

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		return -1;
	for (;;) {
		struct pollfd p;
		int r;
		ssize_t n;

		if (*have >= nlen && find_bytes(buf, *have, needle))
			return 0;
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return -1;
		{
			long long remain = timeout_ms -
				((now.tv_sec - start.tv_sec) * 1000LL +
				 (now.tv_nsec - start.tv_nsec) / 1000000LL);

			if (remain <= 0)
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
		}
		n = read(fd, buf + *have, (size_t)(cap - *have));
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		*have += (int)n;
	}
}

/* P-45：自 from 起等新字节（read_until 全缓冲找会命中历史 token——
 * footer 档标/密码框提示这类反复出现的串必须只认 from 后新字节） */
static int wait_new(int fd, char *buf, int cap, int *have, int from,
		    const char *needle, int timeout_ms)
{
	struct timespec start, now;

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		return -1;
	for (;;) {
		struct pollfd p;
		int r;
		ssize_t n;

		if (*have - from >= (int)strlen(needle) &&
		    find_bytes(buf + from, *have - from, needle))
			return 0;
		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			return -1;
		{
			long long remain = timeout_ms -
				((now.tv_sec - start.tv_sec) * 1000LL +
				 (now.tv_nsec - start.tv_nsec) / 1000000LL);
			int slice;

			if (remain <= 0)
				return -1;
			slice = remain > 200 ? 200 : (int)remain;
			p.fd = fd;
			p.events = POLLIN;
			p.revents = 0;
			r = poll(&p, 1, slice);
			if (r == 0)
				continue;
			if (r < 0) {
				if (errno == EINTR)
					continue;
				return -1;
			}
		}
		n = read(fd, buf + *have, (size_t)(cap - *have));
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		*have += (int)n;
	}
}

static int file_contains(const char *path, const char *a, const char *b)
{
	FILE *f = fopen(path, "r");
	char line[2048];
	int hit_a = 0, hit_b = 0;

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (a && strstr(line, a))
			hit_a = 1;
		if (b && strstr(line, b))
			hit_b = 1;
	}
	fclose(f);
	return (!a || hit_a) && (!b || hit_b);
}

static int wait_child(pid_t pid)
{
	int st = 0, w;

	for (w = 0; w < 50; w++) {
		pid_t r = waitpid(pid, &st, WNOHANG);

		if (r == pid)
			return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
		usleep(100000);
	}
	kill(pid, SIGKILL);
	waitpid(pid, &st, 0);
	return -1;
}

int main(void)
{
	static char out[OUT_CAP];
	int have = 0, mark;
	char tmpl[] = "/tmp/btui-p45-XXXXXX";
	char *tmp;
	char toml[512], dbp[512], homep[512], occbin[512], gatep[512];
	char polp[512], auditp[600];
	char hash[128];
	struct pty pt;
	struct winsize ws = { .ws_row = 24, .ws_col = 80 };
	pid_t pid;
	int rc;
	struct termios tio;

	signal(SIGPIPE, SIG_IGN);

	if (access("../occ", X_OK) != 0) {
		printf("test_su_pty: SKIP（../occ 未构建——occ 顶层 "
		       "make all 后生效）\n");
		return 0;
	}
	tmp = mkdtemp(tmpl);
	if (!tmp) {
		printf("FAIL mkdtemp\n");
		return 1;
	}
	snprintf(toml, sizeof(toml), "%s/model.toml", tmp);
	snprintf(dbp, sizeof(dbp), "%s/sessions.db", tmp);
	snprintf(homep, sizeof(homep), "%s/home", tmp);
	snprintf(gatep, sizeof(gatep), "%s/gate", tmp);
	snprintf(polp, sizeof(polp), "%s/policy.conf", tmp);
	snprintf(auditp, sizeof(auditp), "%s/.aikernel/audit.log", homep);
	snprintf(occbin, sizeof(occbin), "%s/occ", tmp);
	if (mkdir(homep, 0700) != 0) {
		printf("FAIL mkdir home\n");
		return 1;
	}
	{
		FILE *f = fopen(toml, "w");

		if (!f ||
		    fputs("[models.cloud]\n"
			  "provider_type = \"openai_compatible\"\n"
			  "model_name = \"glm-p45\"\n"
			  "base_url = \"http://127.0.0.1:9/v1\"\n"
			  "api_key = \"mock-key-not-real\"\n", f) < 0) {
			printf("FAIL fixture toml\n");
			return 1;
		}
		fclose(f);
	}
	/* policy 桩：三段全 restricted——base 档稳定「受限」，
	 * 与运行用户是否 root/wheel 无关（base=privileged 的三缺陷
	 * 场景由修复后的语义统一覆盖：/su 只看会话提权态）。 */
	{
		FILE *f = fopen(polp, "w");

		if (!f ||
		    fputs("[root]\nmode = restricted\n"
			  "[wheel]\nmode = restricted\ngroup = p45-nogrp\n"
			  "[default]\nmode = restricted\n", f) < 0) {
			printf("FAIL fixture policy\n");
			return 1;
		}
		fclose(f);
	}
	/* gate 凭据桩：tui_gate_hash 同源（sha512crypt），非硬编码真密 */
	if (tui_gate_hash(SU_PW, hash) != 0 || !hash[0]) {
		printf("FAIL gate hash stub\n");
		return 1;
	}
	if (tui_gate_write(gatep, hash) != 0) {
		printf("FAIL gate stub write\n");
		return 1;
	}
	{
		char cmd[1100];

		snprintf(cmd, sizeof(cmd), "cp ../occ %s", occbin);
		if (system(cmd) != 0 || access(occbin, X_OK) != 0) {
			printf("FAIL fixture occ copy\n");
			return 1;
		}
	}

	if (pty_open(&pt) != 0) {
		printf("FAIL pty_open\n");
		return 1;
	}
	memset(&tio, 0, sizeof(tio));
	(void)ioctl(pt.slave, TIOCSWINSZ, &ws);
	pid = fork();
	if (pid < 0) {
		printf("FAIL fork\n");
		return 1;
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
		if (chdir(tmp) != 0)
			_exit(15);
		setenv("OCC_MODEL_TOML", toml, 1);
		setenv("OCC_DB", dbp, 1);
		setenv("HOME", homep, 1);
		setenv("TERM", "xterm", 1);
		setenv("OCC_CATALOG", "/tmp/p45-none-catalog.json", 1);
		setenv("AIK_CONSOLE_GATE", gatep, 1);
		setenv("AIK_CONSOLE_GATE_SKIP", "1", 1);
		setenv("AIKERNEL_POLICY", polp, 1);
		execl(occbin, "occ", (char *)NULL);
		_exit(127);
	}
	close(pt.slave);
	pt.slave = -1;

	/* 进屏 */
	OK(read_until_contains(pt.master, out, OUT_CAP, &have,
			       "\x1b[?1049h", 8000) == 0, "enter-alt-screen");

	/* A. /su → 密码 overlay */
	mark = have;
	if (write(pt.master, "/su\r", 4) < 0)
		printf("FAIL write\n");
	OK(wait_new(pt.master, out, OUT_CAP, &have, mark,
		    "admin 密码", 15000) == 0, "a-su-overlay-opens");

	/* B. 错密码 → overlay 内拒绝 + audit fail */
	mark = have;
	if (write(pt.master, "wrong-p45-pass\r", 15) < 0)
		printf("FAIL write\n");
	OK(wait_new(pt.master, out, OUT_CAP, &have, mark,
		    "密码错误", 15000) == 0, "b-wrong-pw-rejected");
	usleep(300000);			/* audit 落盘（同步写——留呼吸） */
	OK(file_contains(auditp, "tool=su", "result=fail"),
	   "b-audit-fail-row");

	/* C. 对密码 → 提权 + footer 档标「特权*」（自 B 起新字节） */
	mark = have;
	if (write(pt.master, SU_PW "\r", (int)strlen(SU_PW) + 1) < 0)
		printf("FAIL write\n");
	OK(wait_new(pt.master, out, OUT_CAP, &have, mark,
		    "已提权至特权档", 15000) == 0,
	   "c-correct-pw-elevates");
	/* 整屏重绘帧很长：notice 行先到、footer 行殿后——续等档标新字节 */
	OK(wait_new(pt.master, out, OUT_CAP, &have, mark,
		    "特权*", 5000) == 0,
	   "c-footer-tier-privileged-star");

	/* D. 已特权再 /su → 提示不重弹 */
	mark = have;
	if (write(pt.master, "/su\r", 4) < 0)
		printf("FAIL write\n");
	OK(wait_new(pt.master, out, OUT_CAP, &have, mark,
		    "已在特权档（/su 0 回落）", 15000) == 0,
	   "d-already-elevated-notice");

	/* E. /su 0 → 回落 + footer 新字节「受限」且零「特权」 */
	mark = have;
	if (write(pt.master, "/su 0\r", 6) < 0)
		printf("FAIL write\n");
	OK(wait_new(pt.master, out, OUT_CAP, &have, mark,
		    "已回落基础档位", 15000) == 0,
	   "e-delevate-notice");
	OK(wait_new(pt.master, out, OUT_CAP, &have, mark,
		    "受限", 5000) == 0,
	   "e-footer-tier-restricted");
	OK(find_bytes(out + mark, have - mark, "特权") == NULL,
	   "e-footer-no-privileged-bytes");

	/* F. 降权后再 /su → 密码 overlay 必再弹（无绕过） */
	mark = have;
	if (write(pt.master, "/su\r", 4) < 0)
		printf("FAIL write\n");
	OK(wait_new(pt.master, out, OUT_CAP, &have, mark,
		    "admin 密码", 15000) == 0,
	   "f-su-overlay-reopens-after-delevate");
	/* Esc 关闭密码框（25ms 结算窗——孤立 Esc 字节） */
	usleep(100000);
	if (write(pt.master, "\x1b", 1) < 0)
		printf("FAIL write\n");
	usleep(200000);

	/* 退出 */
	if (write(pt.master, "/exit\r", 6) < 0)
		printf("FAIL write\n");
	OK(read_until_contains(pt.master, out, OUT_CAP, &have,
			       "\x1b[?1049l", 8000) == 0, "exit-alt-screen");
	rc = wait_child(pid);
	/* O-1（UX-O §1）：用户 /exit 主动退出=注销语义——occ 以 71 断链
	 * （aik-console v6 见 71 回 login 面；SSH/pts 下落回 shell 无害） */
	OK(rc == 71, "child-exit-71-logout");

	/* G. audit 三笔：fail（B）+ ok（C）+ delevate ok（E） */
	usleep(300000);
	OK(file_contains(auditp, "tool=su args=elevate result=ok", NULL),
	   "g-audit-elevate-ok-row");
	OK(file_contains(auditp, "tool=su args=delevate result=ok", NULL),
	   "g-audit-delevate-ok-row");

	/* 清理 fixture */
	{
		char cmd[700];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp);
		if (system(cmd) != 0)
			printf("FAIL cleanup\n");
	}

	printf("test_su_pty: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
