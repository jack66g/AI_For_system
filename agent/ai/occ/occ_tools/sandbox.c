/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sandbox.c - occ bash 工具底座：aik-sandbox CLI 对接（T9b1）
 *
 * 调用契约（读自 agent/ai/sandbox/aik-sandbox.c，只读复用——动态调用
 * 其 CLI，不链接其源；executor.c sandbox 通道同款手法）：
 *   aik-sandbox create <name> [--cpus/--mem-mb/--pids/--net …]
 *   aik-sandbox run <name> [--keep] [--ro-path P] [--rw-path P] --
 *                   <cmd> [args…]     子进程退出码透传
 *   aik-sandbox destroy <name>                         （幂等）
 *   退出码：0 成功 / 1 用法 / 2 沙盒组装失败 / 127 exec 失败 /
 *           子进程码或 128+信号 原样透传。
 *   隔离面：CLONE_NEWNS|NEWPID|NEWUTS + tmpfs 空根 + /usr ro bind +
 *   fresh procfs/sysfs + /etc 白名单 ro + 能力裁到 CAP_NET_RAW（W71：
 *   沙盒内无 DAC_OVERRIDE——rw-path 目标目录须属沙盒 uid 可写）。
 *   产物通道：/var/ai/sandbox-artifacts/<name>（沙盒内唯一 rw 外通道）。
 *
 * occ bash 每次调用的生命周期（一调用一区，不留驻）：
 *   zone = "occ"+8hex ← create（默认限额；非 root 经 sudo -n 组装
 *   namespace——仅此用途；sudo 不可用即拒绝）→ run --rw-path <workdir>
 *   -- /bin/sh -c "cd <workdir> && <command>"（stdout+stderr 合流采集，
 *   截止时间到 SIGKILL 全进程组）→ destroy（尽力，不影响结果）。
 *
 * 红线：沙箱不可用（二进制缺失/无执行权、create 失败、非 root 且
 * sudo -n 不可用、沙盒版本不支持 --rw-path）一律拒绝执行并人话报错，
 * 绝不降级裸跑。
 *
 * 二进制定位（env 覆盖，executor 同名约定）：OCC_SANDBOX_BIN →
 * AIKERNEL_SANDBOX_BIN → /usr/local/bin/aik-sandbox。
 */
#define _GNU_SOURCE
#include "occ_tools.h"
#include "occ_tools_priv.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* ---- 二进制定位 ---- */

static const char *sb_bin(void)
{
	const char *e;

	e = getenv("OCC_SANDBOX_BIN");
	if (e && e[0])
		return e;
	e = getenv("AIKERNEL_SANDBOX_BIN");
	if (e && e[0])
		return e;
	return "/usr/local/bin/aik-sandbox";
}

/* ---- 子进程运行器（合流采集 + 截止时间 + 组杀） ---- */

typedef struct {
	char *out;			/* heap（stdout+stderr 合流） */
	size_t len;			/* 采集字节数 */
	int exit_code;			/* 退出码；128+信号；-1=异常 */
	int timed_out;
	int spawn_fail;			/* 1=fork/pipe 失败 */
} sb_run;

static void sb_run_free(sb_run *r)
{
	free(r->out);
	memset(r, 0, sizeof(*r));
}

#define SB_CAP_MAX (1024 * 1024)	/* 采集上限 1MB（8KB 截断前） */

/*
 * sb_run_capture - 运行 argv（setsid 自成进程组）。
 * timeout_ms<=0 → 只等退出。stdout/stderr 同管道合流。
 */
static int sb_run_capture(char *const argv[], long long timeout_ms,
			  sb_run *res)
{
	int pfd[2];
	pid_t pid;
	char *buf;
	size_t have = 0;
	long long deadline;
	int status = 0;
	int got_exit = 0;

	memset(res, 0, sizeof(*res));
	buf = malloc(SB_CAP_MAX + 1);
	if (!buf) {
		res->spawn_fail = 1;
		return -1;
	}
	if (pipe(pfd)) {
		free(buf);
		res->spawn_fail = 1;
		return -1;
	}
	deadline = timeout_ms > 0 ?
		   occ_monotonic_ms() + timeout_ms : 0;
	pid = fork();
	if (pid < 0) {
		close(pfd[0]);
		close(pfd[1]);
		free(buf);
		res->spawn_fail = 1;
		return -1;
	}
	if (pid == 0) {
		/* 子：新会话（组杀锚点）→ 输出合流 → exec */
		close(pfd[0]);
		dup2(pfd[1], 1);
		dup2(pfd[1], 2);
		if (pfd[1] > 2)
			close(pfd[1]);
		setsid();
		execvp(argv[0], (char *const *)argv);
		_exit(127);
	}
	close(pfd[1]);
	for (;;) {
		struct pollfd pf = { pfd[0], POLLIN, 0 };
		int pr = poll(&pf, 1, 100);
		ssize_t n;

		if (pr > 0 && (pf.revents & (POLLIN | POLLHUP | POLLERR))) {
			n = read(pfd[0], buf + have, SB_CAP_MAX - have);
			if (n == 0)
				break;			/* EOF */
			if (n > 0)
				have += (size_t)n;
			else if (errno != EINTR && errno != EAGAIN)
				break;
			if (have >= SB_CAP_MAX)
				break;
		} else if (pr < 0 && errno != EINTR) {
			break;
		}
		if (deadline && occ_monotonic_ms() > deadline) {
			if (!got_exit) {
				kill(-pid, SIGKILL);
				kill(pid, SIGKILL);
			}
			res->timed_out = 1;
			break;
		}
		if (!got_exit &&
		    waitpid(pid, &status, WNOHANG) == pid) {
			got_exit = 1;
			/* 已退出：非阻塞抽干余量后收口 */
			for (;;) {
				n = read(pfd[0], buf + have,
					 SB_CAP_MAX - have);
				if (n <= 0)
					break;
				have += (size_t)n;
				if (have >= SB_CAP_MAX)
					break;
			}
			break;
		}
	}
	close(pfd[0]);
	if (!got_exit) {
		if (res->timed_out)
			waitpid(pid, &status, 0);
		else
			waitpid(pid, &status, 0);
	}
	if (res->timed_out && !got_exit)
		res->exit_code = -1;
	else if (WIFEXITED(status))
		res->exit_code = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		res->exit_code = 128 + WTERMSIG(status);
	else
		res->exit_code = -1;
	buf[have] = '\0';
	res->out = buf;
	res->len = have;
	return 0;
}

/* ---- sudo 包装（非 root 组装 namespace 用；仅此用途） ---- */

static int sudo_ok(void)
{
	char *argv[4];
	sb_run r;
	int ok;

	if (geteuid() == 0)
		return 1;
	argv[0] = (char *)"sudo";
	argv[1] = (char *)"-n";
	argv[2] = (char *)"true";
	argv[3] = NULL;
	if (sb_run_capture(argv, 5000, &r))
		return 0;
	ok = (r.exit_code == 0);
	sb_run_free(&r);
	return ok;
}

/* sudo 前缀填充（返回 argv 起始下标；euid==0 时无前缀） */
static int sb_prefix(char **v)
{
	if (geteuid() != 0) {
		v[0] = (char *)"sudo";
		v[1] = (char *)"-n";
		return 2;
	}
	return 0;
}

/* ---- --rw-path 支持探测（一次/进程；沙盒版本不足=不可用） ---- */

static int g_sb_rwpath_cached = -1;

static int sb_supports_rwpath(void)
{
	char *argv[3];
	sb_run r;
	int sup;

	if (g_sb_rwpath_cached >= 0)
		return g_sb_rwpath_cached;
	argv[0] = (char *)sb_bin();
	argv[1] = (char *)"--occ-probe";
	argv[2] = NULL;
	if (sb_run_capture(argv, 5000, &r)) {
		g_sb_rwpath_cached = 0;
		return 0;
	}
	/* usage 文本（非法参数 → 用法打印）里含 --rw-path 即支持 */
	sup = r.out && strstr(r.out, "--rw-path");
	sb_run_free(&r);
	g_sb_rwpath_cached = sup ? 1 : 0;
	return g_sb_rwpath_cached;
}

/* 测试钩子：清空探测缓存（单测换 stub 沙箱用；生产不调） */
void occ_sandbox_probe_cache_reset(void)
{
	g_sb_rwpath_cached = -1;
}

/* ---- bash 主入口 ---- */

/* 单引号安全包一段路径进 sh -c 命令串 */
static void sh_quote(const char *s, char *out, size_t outlen)
{
	size_t j = 0;

	out[j++] = '\'';
	for (size_t i = 0; s[i] && j + 5 < outlen; i++) {
		if (s[i] == '\'') {
			out[j++] = '\'';
			out[j++] = '\\';
			out[j++] = '\'';
			out[j++] = '\'';
		} else {
			out[j++] = s[i];
		}
	}
	out[j++] = '\'';
	out[j] = '\0';
}

static void ob_num(occ_obuf *o, const char *prefix, long long v,
		   const char *suffix)
{
	char n[32];

	snprintf(n, sizeof(n), "%lld", v);
	occ_ob_puts(o, prefix);
	occ_ob_puts(o, n);
	occ_ob_puts(o, suffix);
}

int occ_sandbox_bash(const occ_tool_ctx *ctx, const char *command,
		     const char *workdir_arg, long long timeout_ms,
		     void *obuf_ptr)
{
	occ_obuf *o = obuf_ptr;
	char workdir[4096];
	char zone[32];
	char shcmd[8192 + 160];
	char qdir[4200];
	char *argv[16];
	sb_run rr;
	const char *bin = sb_bin();
	struct stat st;
	unsigned char rnd[4];
	int rc = 0;
	long long cap_ms = ctx->timeout_ms > 0 ? ctx->timeout_ms :
			   OCC_TOOL_TIMEOUT_DEF_MS;

	if (timeout_ms <= 0 || timeout_ms > cap_ms)
		timeout_ms = cap_ms;

	/* 0) 可用性门（红线：不可用即拒，绝不裸跑） */
	if (access(bin, X_OK)) {
		occ_ob_puts(o, "ERROR: bash 工具不可用：aik-sandbox（路径"
			   "解析顺序 OCC_SANDBOX_BIN → AIKERNEL_SANDBOX_BIN"
			   " → /usr/local/bin/aik-sandbox）不存在或不可执行"
			   "（当前：");
		occ_ob_puts(o, bin);
		occ_ob_puts(o, "）。occ 的 bash 一律在沙箱内执行，沙箱"
			   "不可用时拒绝执行（不降级裸跑）。");
		return -1;
	}
	if (!sb_supports_rwpath()) {
		occ_ob_puts(o, "ERROR: bash 工具不可用：aik-sandbox 版本"
			   "过旧（不识别 --rw-path，无法把工作目录挂入"
			   "沙箱）。请升级 aik-sandbox 或用 OCC_SANDBOX_BIN"
			   " 指向当前版本（agent/ai/sandbox/aik-sandbox.c"
			   " 构建）。拒绝执行（不降级裸跑）。");
		return -1;
	}
	if (!sudo_ok()) {
		occ_ob_puts(o, "ERROR: bash 工具不可用：当前非 root 且 "
			   "sudo -n 不可用——组装 namespace 需要特权。"
			   "拒绝执行（不降级裸跑）。");
		return -1;
	}

	/* 1) workdir 解析（默认 occ 启动目录） */
	if (workdir_arg && workdir_arg[0]) {
		char trial[4300];

		if (workdir_arg[0] == '/') {
			snprintf(trial, sizeof(trial), "%s", workdir_arg);
		} else {
			char cwd[4096];

			if (!getcwd(cwd, sizeof(cwd))) {
				occ_ob_puts(o, "ERROR: bash 无法确定当前"
					    "目录");
				return -1;
			}
			if (strlen(cwd) + strlen(workdir_arg) + 2 >
			    sizeof(trial)) {
				occ_ob_puts(o, "ERROR: bash workdir 路径"
					    "过长");
				return -1;
			}
			snprintf(trial, sizeof(trial), "%s/%s", cwd,
				 workdir_arg);
		}
		if (!realpath(trial, workdir) ||
		    stat(workdir, &st) || !S_ISDIR(st.st_mode)) {
			occ_ob_puts(o, "ERROR: bash workdir 不存在或不是"
				    "目录：");
			occ_ob_puts(o, workdir_arg);
			return -1;
		}
	} else {
		if (ctx->workdir && ctx->workdir[0])
			snprintf(workdir, sizeof(workdir), "%s",
				 ctx->workdir);
		else if (!getcwd(workdir, sizeof(workdir))) {
			occ_ob_puts(o, "ERROR: bash 无法确定工作目录");
			return -1;
		}
		if (stat(workdir, &st) || !S_ISDIR(st.st_mode)) {
			occ_ob_puts(o, "ERROR: bash 工作目录不可访问：");
			occ_ob_puts(o, workdir);
			return -1;
		}
	}

	/* 2) 区名（一调用一区） */
	{
		int fd = open("/dev/urandom", O_RDONLY);

		if (fd >= 0) {
			if (read(fd, rnd, sizeof(rnd)) != (ssize_t)sizeof(rnd))
				memset(rnd, 0, sizeof(rnd));
			close(fd);
		} else {
			memset(rnd, 0, sizeof(rnd));
		}
		snprintf(zone, sizeof(zone), "occ%02x%02x%02x%02x",
			 rnd[0], rnd[1], rnd[2], rnd[3]);
	}

	/* 3) create（失败=不可用，拒） */
	{
		int i = sb_prefix(argv);

		argv[i++] = (char *)bin;
		argv[i++] = (char *)"create";
		argv[i++] = (char *)zone;
		argv[i] = NULL;
		if (sb_run_capture(argv, 15000, &rr)) {
			occ_ob_puts(o, "ERROR: bash 工具不可用：无法启动 "
				   "aik-sandbox create。拒绝执行"
				   "（不降级裸跑）。");
			return -1;
		}
		if (rr.exit_code != 0) {
			occ_ob_puts(o, "ERROR: bash 工具不可用：aik-sandbox"
				    " create 失败");
			ob_num(o, "（exit=", rr.exit_code, "）：");
			occ_ob_puts(o, rr.out ? rr.out : "");
			occ_ob_puts(o, "。拒绝执行（不降级裸跑）。");
			sb_run_free(&rr);
			return -1;
		}
		sb_run_free(&rr);
	}

	/* 4) run --rw-path <workdir> -- /bin/sh -c "cd … && command" */
	sh_quote(workdir, qdir, sizeof(qdir));
	snprintf(shcmd, sizeof(shcmd), "cd %s && { %s ; }", qdir, command);
	{
		int i = sb_prefix(argv);

		argv[i++] = (char *)bin;
		argv[i++] = (char *)"run";
		argv[i++] = (char *)zone;
		argv[i++] = (char *)"--rw-path";
		argv[i++] = (char *)workdir;
		argv[i++] = (char *)"--";
		argv[i++] = (char *)"/bin/sh";
		argv[i++] = (char *)"-c";
		argv[i++] = (char *)shcmd;
		argv[i] = NULL;
		if (sb_run_capture(argv, timeout_ms, &rr)) {
			occ_ob_puts(o, "ERROR: bash 工具不可用：无法启动 "
				   "aik-sandbox run。拒绝执行"
				   "（不降级裸跑）。");
			sb_run_free(&rr);
			rr.out = NULL;
			rc = -1;
		}
	}
	if (rr.out || rr.timed_out) {
		if (rr.timed_out) {
			occ_ob_puts(o, rr.out ? rr.out : "");
			occ_ob_puts(o, "\nERROR: 命令超时");
			ob_num(o, "（上限 ", timeout_ms, "ms），已 SIGKILL"
				" 全进程组（沙箱随 destroy 回收）。");
			rc = -1;
		} else if (rr.exit_code == 1 || rr.exit_code == 2) {
			/* 1=用法/2=组装失败：沙箱面故障，人话报错 */
			occ_ob_puts(o, "ERROR: bash 沙箱执行失败"
				    "（aik-sandbox");
			ob_num(o, " exit=", rr.exit_code, "）：");
			occ_ob_puts(o, rr.out ? rr.out : "");
			rc = -1;
		} else {
			/* 0 / 127 / 子进程码 / 128+信号：命令级结果
			 *（127 等失败码是正常执行——exit 写进结果文本，
			 * 由模型自行判断；工具 rc=0） */
			occ_ob_puts(o, rr.out ? rr.out : "");
			ob_num(o, "\n[exit=", rr.exit_code, "]");
		}
		sb_run_free(&rr);
	}

	/* 5) destroy（尽力；失败不改变工具结果，只进 stderr） */
	{
		int i = sb_prefix(argv);
		sb_run dr;

		argv[i++] = (char *)bin;
		argv[i++] = (char *)"destroy";
		argv[i++] = (char *)zone;
		argv[i] = NULL;
		if (!sb_run_capture(argv, 10000, &dr) && dr.exit_code != 0)
			fprintf(stderr, "occ-bash: sandbox destroy %s: "
				"exit=%d\n", zone, dr.exit_code);
		sb_run_free(&dr);
	}
	return rc;
}
