/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sandbox.c - occ bash 工具底座：aik-sandbox CLI 对接（T9b1）
 *
 * 调用契约（读自 agent/ai/sandbox/aik-sandbox.c，只读复用——动态调用
 * 其 CLI，不链接其源；executor.c sandbox 通道同款手法）：
 *   aik-sandbox create <name> [--cpus/--mem-mb/--pids/--net …]
 *   aik-sandbox run <name> [--keep] [--status-fd N] [--ro-path P]
 *                   [--rw-path P] -- <cmd> [args…]     子进程退出码透传
 *   aik-sandbox destroy <name>                         （幂等）
 *   退出码：0 成功 / 1 用法 / 2 沙盒组装失败 / 127 exec 失败 /
 *           子进程码或 128+信号 原样透传。
 *   状态通道（AIF-09）：run 传 --status-fd 3 时，包装器在 fd 3 写一行
 *   AIK-SANDBOX-STATUS v1 phase=<usage|setup|exec|child|timeout|signal>
 *   rc=<n>。本文件据此把「沙箱面故障（usage/setup/exec）」与「命令自己
 *   非零（child，含 1/2/127/128+信号）」分开；无状态/坏状态=来源未定，
 *   原样保留输出（兼容旧包装器与 sudo 关 fd 的非 root 路径）。
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

#include "occ_tui/tui_lang.h"		/* O-20 A2：语档文案面 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>				/* P-2：per-user 回退取名 */
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
#define SB_STATUS_FD 3			/* 状态通道约定 fd（AIF-09） */
#define SB_STATUS_MAX 512		/* 状态文本上限（一行 ≤128 字节） */

/*
 * sb_run_capture_ex - 运行 argv（setsid 自成进程组）。
 * timeout_ms<=0 → 只等退出。stdout/stderr 同管道合流。
 * want_status=1 时另开一根状态管道：写端在 fork 后 dup 到 SB_STATUS_FD
 * 并清 CLOEXEC（跨 exec 传进 aik-sandbox），读端非阻塞、子进程回收后
 * 一次抽干即关（防死锁）；stat_buf/stat_sz 收原始字节（无=空串）。
 */
static int sb_run_capture_ex(char *const argv[], long long timeout_ms,
			     sb_run *res, int want_status,
			     char *stat_buf, size_t stat_sz)
{
	int pfd[2] = { -1, -1 };
	int sp[2] = { -1, -1 };
	pid_t pid;
	char *buf;
	size_t have = 0;
	long long deadline;
	int st_status = 0;
	int got_exit = 0;

	memset(res, 0, sizeof(*res));
	if (stat_buf && stat_sz)
		stat_buf[0] = '\0';
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
	if (want_status && pipe2(sp, O_CLOEXEC)) {
		sp[0] = -1;
		sp[1] = -1;		/* 状态通道建不成 → 调用方按来源未定 */
	}
	deadline = timeout_ms > 0 ?
		   occ_monotonic_ms() + timeout_ms : 0;
	pid = fork();
	if (pid < 0) {
		close(pfd[0]);
		close(pfd[1]);
		if (sp[0] >= 0)
			close(sp[0]);
		if (sp[1] >= 0)
			close(sp[1]);
		free(buf);
		res->spawn_fail = 1;
		return -1;
	}
	if (pid == 0) {
		/* 子：新会话（组杀锚点）→ 输出合流 → 状态 fd → exec */
		close(pfd[0]);
		dup2(pfd[1], 1);
		dup2(pfd[1], 2);
		if (pfd[1] > 2)
			close(pfd[1]);
		if (sp[0] >= 0) {
			close(sp[0]);
			if (sp[1] >= 0 &&
			    dup2(sp[1], SB_STATUS_FD) == SB_STATUS_FD) {
				if (sp[1] != SB_STATUS_FD && sp[1] > 2)
					close(sp[1]);
				fcntl(SB_STATUS_FD, F_SETFD, 0);
			}
		}
		setsid();
		execvp(argv[0], (char *const *)argv);
		_exit(127);
	}
	close(pfd[1]);
	if (sp[1] >= 0)
		close(sp[1]);
	if (sp[0] >= 0)
		fcntl(sp[0], F_SETFL, O_NONBLOCK);
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
		    waitpid(pid, &st_status, WNOHANG) == pid) {
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
			waitpid(pid, &st_status, 0);
		else
			waitpid(pid, &st_status, 0);
	}
	if (res->timed_out && !got_exit)
		res->exit_code = -1;
	else if (WIFEXITED(st_status))
		res->exit_code = WEXITSTATUS(st_status);
	else if (WIFSIGNALED(st_status))
		res->exit_code = 128 + WTERMSIG(st_status);
	else
		res->exit_code = -1;
	buf[have] = '\0';
	res->out = buf;
	res->len = have;
	/* 状态通道：写端已随进程退出关闭，非阻塞抽干后立刻关读端 */
	if (sp[0] >= 0 && stat_buf && stat_sz) {
		size_t sh = 0;

		for (;;) {
			ssize_t n2 = read(sp[0], stat_buf + sh,
					  stat_sz - 1 - sh);

			if (n2 > 0) {
				sh += (size_t)n2;
				if (sh >= stat_sz - 1)
					break;
				continue;
			}
			if (n2 < 0 && errno == EINTR)
				continue;
			break;
		}
		stat_buf[sh] = '\0';
	}
	if (sp[0] >= 0)
		close(sp[0]);
	return 0;
}

static int sb_run_capture(char *const argv[], long long timeout_ms,
			  sb_run *res)
{
	return sb_run_capture_ex(argv, timeout_ms, res, 0, NULL, 0);
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

/* ---- O-6：workdir 沙箱拒绝面判定 ---- */

/* aik-sandbox 显式 bind 源拒绝面（--ro-path/--rw-path 共用）的同源
 * 硬编码副本——occ 不链沙箱源（只读 CLI 契约），两处同步维护：
 * agent/ai/sandbox/aik-sandbox.c valid_bind_src 的 deny 表。cwd 命中
 * 任一（含子树）即 --rw-path 挂不进沙箱（140 默认 cwd=/root → 每
 * 会话首发 bash 全灭）——启动处据此回退 /var/ai/work。
 *
 * P-2 Phase A（C 棒，MULTIUSER §6）：occ 侧保守面多拒 "/home"——
 * 家目录树不进沙箱视图（多用户下他人/自家家数据不暴露给沙箱内进程；
 * 工作区走回退目录）。aik-sandbox 侧 valid_bind_src 无此条（显式
 * --rw-path /home/… 仍可挂，沙箱内 /home 本是 tmpfs 空目录）——
 * occ cwd 面先行回退即永不把家树传给 rw-path，两侧不冲突（occ 侧
 * 更保守，方向安全）。仅目录前缀匹配（"/homex" 不命中），不破坏
 * 现有 /root、/etc 条目语义。 */
int occ_sandbox_cwd_denied(const char *cwd)
{
	static const char *const deny[] = {
		"/proc", "/sys", "/dev", "/usr", "/bin", "/sbin",
		"/lib", "/lib64", "/etc", "/root", "/boot",
		"/var/lib/aikernel", "/var/ai/sandbox-artifacts",
		"/home", NULL,
	};
	size_t i;

	if (!cwd || cwd[0] != '/' || !cwd[1])
		return 0;
	for (i = 0; deny[i]; i++) {
		size_t n = strlen(deny[i]);

		if (strncmp(cwd, deny[i], n) == 0 &&
		    (cwd[n] == '\0' || cwd[n] == '/'))
			return 1;
	}
	return 0;
}

/* ---- P-2 Phase A（C 棒，MULTIUSER §6/§7）：共享回退工作区 per-user 化 ---- */

/* 共享回退工作区（occ.c occ_workdir_resolve 同值字面量——occ.c 不在本
 * 棒文件集，两侧以值相等保持契约；root/admin 旧路径恒用此共享路径） */
#define OCC_SANDBOX_SHARED_WORKDIR "/var/ai/work"

/*
 * occ_sandbox_user_workdir_for - per-user 回退工作区路径计算（纯函数，
 * 不碰文件系统；单测直接喂 uid）。口径：
 *   uid==0            → -1（root/admin 旧路径保持共享 /var/ai/work，
 *                       兼容现役行为+全部现有测试）；
 *   无 passwd 条目/名字不合法 → -1（诚实回落共享路径，不炸）；
 *   否则             → 0 且 buf 填 "/var/ai/work/<pw_name>"。
 * 名字仅许 [A-Za-z0-9._-]（passwd 常规字符）——路径段防注入；越界
 * 名（超长）同样 -1 回落。env 无既有覆盖通道（OCC_SANDBOX_WORKDIR
 * 不存在），默认路径计算即唯一面。
 */
int occ_sandbox_user_workdir_for(uid_t uid, char *buf, size_t buflen)
{
	struct passwd *pw;
	size_t n;

	if (uid == 0 || !buf || buflen <= sizeof(OCC_SANDBOX_SHARED_WORKDIR))
		return -1;
	pw = getpwuid(uid);
	if (!pw || !pw->pw_name || !pw->pw_name[0])
		return -1;
	for (n = 0; pw->pw_name[n]; n++) {
		char c = pw->pw_name[n];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		      c == '-'))
			return -1;
	}
	if (!n || n > 64)			/* 登录名常规上限余量 */
		return -1;
	if (snprintf(buf, buflen, "%s/%s", OCC_SANDBOX_SHARED_WORKDIR,
		     pw->pw_name) >= (int)buflen)
		return -1;
	return 0;
}

/*
 * occ_sandbox_ensure_user_workdir - 懒建 per-user 工作区（0700 属
 * uid:gid）。幂等：已有同名目录不重建不清空直接可用；同名非目录
 * =失败。实际权限路径（按组装者身份注明）：
 *   euid==0（代组装面）→ mkdir + chown 归 uid:gid（chown 失败=该 uid
 *                         进不去 0700 目录，诚实判失败）；
 *   非 root 组装者     → mkdir 属自己（uid 参数即本人；父目录对组装
 *                         者可写才成——/var/ai/work 属 root 时部署侧
 *                         需预建 per-user 目录或放开父目录，本函数
 *                         失败即由调用方诚实回落共享路径，不更糟）。
 * 返回 0=目录就绪可用；-1=建不成/非目录。
 */
int occ_sandbox_ensure_user_workdir(const char *path, uid_t uid, gid_t gid)
{
	struct stat st;

	if (!path || !path[0])
		return -1;
	if (mkdir(path, 0700) == 0) {
		if (geteuid() == 0 && uid != 0 &&
		    chown(path, uid, gid) != 0)
			return -1;
		return 0;
	}
	if (errno != EEXIST)
		return -1;
	/* 已存在：不重建不清空（部署侧预建/上次懒建均算数） */
	if (stat(path, &st) || !S_ISDIR(st.st_mode))
		return -1;
	return 0;
}

/* ---- 能力探测（一次/进程；沙盒版本不足=不可用） ----
 * 一次 --occ-probe 同时判两件事：
 *   --rw-path   → 能把 workdir 挂进沙箱（版本门槛，缺了拒绝执行）
 *   --status-fd → 支持版本化状态通道（AIF-09；缺了走「来源未定」）
 */
#define SB_PROBE_RWPATH   0x1
#define SB_PROBE_STATUSFD 0x2

static int g_sb_probe_cached = -1;

static int sb_probe(void)
{
	char *argv[3];
	sb_run r;

	if (g_sb_probe_cached >= 0)
		return g_sb_probe_cached;
	g_sb_probe_cached = 0;
	argv[0] = (char *)sb_bin();
	argv[1] = (char *)"--occ-probe";
	argv[2] = NULL;
	if (sb_run_capture(argv, 5000, &r))
		return g_sb_probe_cached;
	/* usage 文本（非法参数 → 用法打印）里出现的选项即支持 */
	if (r.out) {
		if (strstr(r.out, "--rw-path"))
			g_sb_probe_cached |= SB_PROBE_RWPATH;
		if (strstr(r.out, "--status-fd"))
			g_sb_probe_cached |= SB_PROBE_STATUSFD;
	}
	sb_run_free(&r);
	return g_sb_probe_cached;
}

static int sb_supports_rwpath(void)
{
	return (sb_probe() & SB_PROBE_RWPATH) != 0;
}

static int sb_supports_statusfd(void)
{
	return (sb_probe() & SB_PROBE_STATUSFD) != 0;
}

/* 测试钩子：清空探测缓存（单测换 stub 沙箱用；生产不调） */
void occ_sandbox_probe_cache_reset(void)
{
	g_sb_probe_cached = -1;
}

/* ---- 状态通道解析（AIF-09） ----
 *
 * 严格口径：整个状态缓冲必须是**恰好一行**合法状态且以换行结尾——
 *   AIK-SANDBOX-STATUS v1 phase=<phase> rc=<n>\n
 * 且 rc 必须等于包装器真实退出码（值不一致=伪造/损坏）。其余一律
 * UNKNOWN（来源未定：旧包装器、sudo 关 fd、写失败、截断、伪造）。
 */
enum sb_st_kind {
	SB_ST_UNKNOWN = 0,
	SB_ST_CHILD,		/* 命令结果：输出 + [exit=n]，工具 rc=0 */
	SB_ST_SANDBOX,		/* 沙箱面故障：usage|setup|exec，工具 rc=-1 */
	SB_ST_TIMEOUT,		/* 超时相位（保留给施加超时的包装器） */
	SB_ST_SIGNAL,		/* 包装器自身被信号终止 */
};

struct sb_st {
	enum sb_st_kind kind;
	const char *phase;	/* 合法相位字面量；UNKNOWN 时 NULL */
	int rc;
};

static const char *const sb_st_phases[] = {
	"usage", "setup", "exec", "child", "timeout", "signal", NULL,
};

static void sb_status_parse(const char *buf, int exit_code, struct sb_st *st)
{
	static const char prefix[] = "AIK-SANDBOX-STATUS v1 phase=";
	const char *p;
	size_t plen = sizeof(prefix) - 1;
	int i, rc = 0;

	memset(st, 0, sizeof(*st));
	st->kind = SB_ST_UNKNOWN;
	if (!buf || !buf[0])
		return;
	/* 恰好一行：只允许结尾一个换行，不得有多行/残留 */
	if (strncmp(buf, prefix, plen) != 0)
		return;
	p = buf + plen;
	for (i = 0; sb_st_phases[i]; i++) {
		size_t n = strlen(sb_st_phases[i]);

		if (strncmp(p, sb_st_phases[i], n) != 0)
			continue;
		if (strncmp(p + n, " rc=", 4) != 0)
			return;
		p += n + 4;
		/* 十进制 rc，必须一路到换行且换行即缓冲结尾 */
		if (*p < '0' || *p > '9')
			return;
		for (; *p >= '0' && *p <= '9'; p++) {
			rc = rc * 10 + (*p - '0');
			if (rc > 999)
				return;
		}
		if (*p != '\n' || p[1] != '\0')
			return;
		/* 状态与真实退出码必须一致（不一致=伪造/损坏） */
		if (rc != exit_code)
			return;
		st->phase = sb_st_phases[i];
		st->rc = rc;
		if (strcmp(st->phase, "child") == 0)
			st->kind = SB_ST_CHILD;
		else if (strcmp(st->phase, "timeout") == 0)
			st->kind = SB_ST_TIMEOUT;
		else if (strcmp(st->phase, "signal") == 0)
			st->kind = SB_ST_SIGNAL;
		else if (strcmp(st->phase, "usage") == 0 ||
			 strcmp(st->phase, "setup") == 0 ||
			 strcmp(st->phase, "exec") == 0)
			st->kind = SB_ST_SANDBOX;
		else
			st->kind = SB_ST_UNKNOWN;
		return;
	}
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
	char statbuf[SB_STATUS_MAX];	/* AIF-09：状态通道原始字节 */
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
		occ_ob_puts(o, L_("ERROR: bash 工具不可用：aik-sandbox（路径解析顺序 OCC_SANDBOX_BIN → AIKERNEL_SANDBOX_BIN → /usr/local/bin/aik-sandbox）不存在或不可执行（当前："));
		occ_ob_puts(o, bin);
		occ_ob_puts(o, L_("）。occ 的 bash 一律在沙箱内执行，沙箱不可用时拒绝执行（不降级裸跑）。"));
		return -1;
	}
	if (!sb_supports_rwpath()) {
		occ_ob_puts(o, L_("ERROR: bash 工具不可用：aik-sandbox 版本过旧（不识别 --rw-path，无法把工作目录挂入沙箱）。请升级 aik-sandbox 或用 OCC_SANDBOX_BIN 指向当前版本（agent/ai/sandbox/aik-sandbox.c 构建）。拒绝执行（不降级裸跑）。"));
		return -1;
	}
	if (!sudo_ok()) {
		occ_ob_puts(o, L_("ERROR: bash 工具不可用：当前非 root 且 sudo -n 不可用——组装 namespace 需要特权。拒绝执行（不降级裸跑）。"));
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
				occ_ob_puts(o, L_("ERROR: bash 无法确定当前目录"));
				return -1;
			}
			if (strlen(cwd) + strlen(workdir_arg) + 2 >
			    sizeof(trial)) {
				occ_ob_puts(o, L_("ERROR: bash workdir 路径过长"));
				return -1;
			}
			snprintf(trial, sizeof(trial), "%s/%s", cwd,
				 workdir_arg);
		}
		if (!realpath(trial, workdir) ||
		    stat(workdir, &st) || !S_ISDIR(st.st_mode)) {
			occ_ob_puts(o, L_("ERROR: bash workdir 不存在或不是目录："));
			occ_ob_puts(o, workdir_arg);
			return -1;
		}
	} else {
		if (ctx->workdir && ctx->workdir[0])
			snprintf(workdir, sizeof(workdir), "%s",
				 ctx->workdir);
		else if (!getcwd(workdir, sizeof(workdir))) {
			occ_ob_puts(o, L_("ERROR: bash 无法确定工作目录"));
			return -1;
		}
		if (stat(workdir, &st) || !S_ISDIR(st.st_mode)) {
			occ_ob_puts(o, L_("ERROR: bash 工作目录不可访问："));
			occ_ob_puts(o, workdir);
			return -1;
		}
	}

	/* 1b) P-2 Phase A：共享回退工作区 per-user 化——workdir 为共享
	 * 回退路径且调用者非 root 时，实际 rw 面改挂 /var/ai/work/<user>
	 * （懒建 0700 属 uid:gid，已有目录不重建）。root（uid==0）保持
	 * 共享路径不变（兼容现役+现有测试）；路径计算或懒建任一失败 =
	 * 诚实回落共享路径（现状行为，不更糟不炸——部署侧未放开
	 * /var/ai/work 时即此态）。stderr 一行披露（destroy 同款风格）。 */
	if (getuid() != 0 &&
	    strcmp(workdir, OCC_SANDBOX_SHARED_WORKDIR) == 0) {
		char udir[256];		/* "/var/ai/work/"+登录名(≤64) 余量 */

		if (occ_sandbox_user_workdir_for(getuid(), udir,
						 sizeof(udir)) == 0 &&
		    occ_sandbox_ensure_user_workdir(udir, getuid(),
						    getgid()) == 0 &&
		    strlen(udir) < sizeof(workdir)) {
			snprintf(workdir, sizeof(workdir), "%s", udir);
			fprintf(stderr, "occ-bash: per-user rw-path %s\n",
				udir);
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
			occ_ob_puts(o, L_("ERROR: bash 工具不可用：无法启动 aik-sandbox create。拒绝执行（不降级裸跑）。"));
			return -1;
		}
		if (rr.exit_code != 0) {
			occ_ob_puts(o, L_("ERROR: bash 工具不可用：aik-sandbox create 失败"));
			ob_num(o, L_("（exit="), rr.exit_code, L_("）："));
			occ_ob_puts(o, rr.out ? rr.out : "");
			occ_ob_puts(o, L_("。拒绝执行（不降级裸跑）。"));
			sb_run_free(&rr);
			return -1;
		}
		sb_run_free(&rr);
	}

	/* 4) run --rw-path <workdir> [--status-fd 3] -- /bin/sh -c "cd … && command" */
	sh_quote(workdir, qdir, sizeof(qdir));
	snprintf(shcmd, sizeof(shcmd), "cd %s && { %s ; }", qdir, command);
	{
		int i = sb_prefix(argv);
		int want_st = sb_supports_statusfd();

		argv[i++] = (char *)bin;
		argv[i++] = (char *)"run";
		argv[i++] = (char *)zone;
		argv[i++] = (char *)"--rw-path";
		argv[i++] = (char *)workdir;
		if (want_st) {
			/* 版本化状态通道（AIF-09）：fd 号写死 3，值是自证——
			 * 包装器只写自己的相位，子命令输出走 stdout/stderr
			 * 合流，两条通道互不污染。旧包装器（探测无此项）
			 * 不传该参数，输出与退出码逐字保持原样。 */
			argv[i++] = (char *)"--status-fd";
			argv[i++] = (char *)"3";
		}
		argv[i++] = (char *)"--";
		argv[i++] = (char *)"/bin/sh";
		argv[i++] = (char *)"-c";
		argv[i++] = (char *)shcmd;
		argv[i] = NULL;
		if (sb_run_capture_ex(argv, timeout_ms, &rr, want_st,
				      statbuf, sizeof(statbuf))) {
			occ_ob_puts(o, L_("ERROR: bash 工具不可用：无法启动 aik-sandbox run。拒绝执行（不降级裸跑）。"));
			sb_run_free(&rr);
			rr.out = NULL;
			rc = -1;
		}
	}
	if (rr.out || rr.timed_out) {
		if (rr.timed_out) {
			occ_ob_puts(o, rr.out ? rr.out : "");
			occ_ob_puts(o, L_("\nERROR: 命令超时"));
			ob_num(o, L_("（上限 "), timeout_ms, L_("ms），已 SIGKILL 全进程组（沙箱随 destroy 回收）。"));
			rc = -1;
		} else {
			struct sb_st st;

			sb_status_parse(statbuf, rr.exit_code, &st);
			switch (st.kind) {
			case SB_ST_CHILD:
				/* 命令确实跑了：1/2/127/128+信号都是命令结果
				 * ——— 输出照旧 + [exit=n]，工具 rc=0。 */
				occ_ob_puts(o, rr.out ? rr.out : "");
				ob_num(o, "\n[exit=", rr.exit_code, "]");
				break;
			case SB_ST_SANDBOX:
				/* usage/setup/exec：沙箱面故障（不是命令结果） */
				occ_ob_puts(o, L_("ERROR: bash 沙箱执行失败（阶段 "));
				occ_ob_puts(o, st.phase);
				occ_ob_puts(o, L_("，aik-sandbox"));
				ob_num(o, " exit=", rr.exit_code, L_("）："));
				occ_ob_puts(o, rr.out ? rr.out : "");
				rc = -1;
				break;
			case SB_ST_TIMEOUT:
				/* 保留相位：施加超时的包装器走到这里 = 超时 */
				occ_ob_puts(o, rr.out ? rr.out : "");
				occ_ob_puts(o, L_("\nERROR: 命令超时（沙箱阶段 timeout"));
				ob_num(o, L_("，exit="), rr.exit_code,
				       L_("），已回收沙盒。"));
				rc = -1;
				break;
			case SB_ST_SIGNAL:
				/* 包装器自身被信号终止：输出可能不完整，不能
				 * 当命令结果，也不能当子命令自己的退出码 */
				occ_ob_puts(o, rr.out ? rr.out : "");
				occ_ob_puts(o, L_("\nERROR: bash 沙箱包装器被信号终止"));
				ob_num(o, L_("（exit="), rr.exit_code,
				       L_("）；输出可能不完整。"));
				rc = -1;
				break;
			case SB_ST_UNKNOWN:
			default:
				/* 旧包装器 / sudo 关 fd / 写失败 / 截断 / 伪造：
				 * 来源未定——原样保留输出并标出来，不静默当成功
				 * 也不当沙箱失败（退出码照实给出）。 */
				occ_ob_puts(o, rr.out ? rr.out : "");
				ob_num(o, "\n[exit=", rr.exit_code,
				       L_(" 来源未定]"));
				break;
			}
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
