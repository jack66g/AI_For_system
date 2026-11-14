/* SPDX-License-Identifier: GPL-2.0 */
/*
 * orch.c - occ 子智能体运行时（ORCH-DESIGN §8 棒 E2；R4 进程隔离）
 *
 * 实现：fork+execve 每子一个 `occ -p <prompt> --session <sid>` 子进程
 * （独立进程组 setpgid——取消 TERM/KILL 发 -pgid 只断目标子树），
 * env 注入 OCC_DB（子会话/任务与主运行时同库，B2 并发写库即真实
 * 生产路径），stdout/stderr 重定向文件（R4 文件 IPC）。头注语义
 * 详见 orch.h。
 *
 * 与 E1 底座的关系（只读消费，零 API 扩展）：
 *   occ_session_create_kind（child 子会话）/ occ_task_create /
 *   occ_task_dispatch（pending→dispatched）/ occ_task_review
 *   （dispatched→in_review，终局结果回收）/ occ_task_escalate
 *   （spawn 失败审计）。
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "orch.h"

extern char **environ;

struct occ_orch_child {
	occ_orch *o;			/* 所属运行时（出表用） */
	pid_t pid;
	pid_t pgid;			/* 独立进程组（取消面） */
	char session_id[OCC_ID_LEN];
	char task_id[OCC_ID_LEN];	/* 空=无任务面 */
	long long started_ms;		/* mono 时钟 */
	long long deadline_ms;		/* 0=无限 */
	int cancelling;			/* TERM 已发（分类用） */
	int timed_out;			/* deadline 触发的取消 */
	int killed;			/* KILL 段已发 */
	long long kill_at_ms;		/* 宽限期到点 */
	char *stdout_path;		/* heap；终局读回后释放 */
	char *stderr_path;
	int own_files;			/* 1=自动 mkstemp（终局 unlink） */
};

struct occ_orch {
	occ_db *db;
	occ_orch_child *live[OCC_ORCH_MAX_CHILDREN];
	int n_live;
	long long backoff_ms;		/* 缺省 OCC_ORCH_BACKOFF_MS */
	long long win_start_ms;		/* 撞限窗起点（0=从未撞限） */
	int rejects;			/* 窗内拒绝次数（诊断） */
};

/* ---- 小工具 ---- */

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || !errlen)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

static long long mono_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static long long backoff_remaining(const occ_orch *o, long long now)
{
	if (!o->win_start_ms)
		return 0;
	if (now - o->win_start_ms >= o->backoff_ms)
		return 0;
	return o->backoff_ms - (now - o->win_start_ms);
}

/*
 * utf8_trunc - UTF-8 边界截断（自动建任务的 title 用；同 session.c
 * title 语义——截在字符边界不劈多字节字符）。max=最大字节数。
 */
static void utf8_trunc(const char *src, size_t max, char *dst, size_t dstlen)
{
	size_t i = 0, cut = 0;

	if (!src)
		src = "";
	while (src[i] && i <= max) {
		size_t next = i;

		if ((unsigned char)src[next] < 0x80) {
			next++;
		} else if (((unsigned char)src[next] & 0xE0) == 0xC0) {
			next++;
			if (src[next] &&
			    ((unsigned char)src[next] & 0xC0) == 0x80)
				next++;
		} else if (((unsigned char)src[next] & 0xF0) == 0xE0) {
			next++;
			while (src[next] &&
			       ((unsigned char)src[next] & 0xC0) == 0x80 &&
			       next - i < 3)
				next++;
		} else if (((unsigned char)src[next] & 0xF8) == 0xF0) {
			next++;
			while (src[next] &&
			       ((unsigned char)src[next] & 0xC0) == 0x80 &&
			       next - i < 4)
				next++;
		} else {
			next++;		/* 非法首字节：按单字节吞掉 */
		}
		i = next;
		if (i <= max)
			cut = i;
	}
	if (cut >= dstlen) {
		cut = dstlen - 1;
		while (cut > 0 && ((unsigned char)src[cut] & 0xC0) == 0x80)
			cut--;
	}
	memcpy(dst, src, cut);
	dst[cut] = '\0';
}

/* ---- env 数组（fork 前建好整张 envp——不 setenv，线程安全面） ---- */

static int env_set(char ***envp, const char *kv)
{
	size_t n = 0, klen;
	char **arr = *envp;
	char *dup;

	while (arr && arr[n])
		n++;
	klen = strcspn(kv, "=");
	for (size_t i = 0; i < n; i++) {
		if (!strncmp(arr[i], kv, klen) && arr[i][klen] == '=') {
			dup = strdup(kv);
			if (!dup)
				return -1;
			free(arr[i]);
			arr[i] = dup;
			return 0;
		}
	}
	arr = realloc(arr, (n + 2) * sizeof(*arr));
	if (!arr)
		return -1;		/* 旧数组仍 *envp 有效，调用方回收 */
	dup = strdup(kv);
	if (!dup) {
		arr[n] = NULL;
		*envp = arr;
		return -1;
	}
	arr[n] = dup;
	arr[n + 1] = NULL;
	*envp = arr;
	return 0;
}

static char **env_build(const char *db_override, const char *const *extra)
{
	char **envp = NULL;
	size_t i;
	int bad = 0;

	for (i = 0; environ[i]; i++) {
		if (env_set(&envp, environ[i])) {
			bad = 1;
			break;
		}
	}
	if (!bad && db_override && env_set(&envp, db_override))
		bad = 1;
	for (i = 0; !bad && extra && extra[i]; i++) {
		if (!strchr(extra[i], '='))
			continue;	/* 非 NAME=VALUE：跳过不炸 */
		if (env_set(&envp, extra[i]))
			bad = 1;
	}
	if (bad) {
		for (i = 0; envp && envp[i]; i++)
			free(envp[i]);
		free(envp);
		return NULL;
	}
	return envp;
}

static void env_free(char **envp)
{
	size_t i;

	if (!envp)
		return;
	for (i = 0; envp[i]; i++)
		free(envp[i]);
	free(envp);
}

/* ---- 可执行解析 ---- */

static int resolve_bin(const char *bin, char *out, size_t outlen)
{
	if (!bin || !bin[0])
		return -1;
	if (strchr(bin, '/')) {
		snprintf(out, outlen, "%s", bin);
		return access(out, X_OK) == 0 ? 0 : -1;
	}
	{
		const char *path = getenv("PATH");
		const char *p;

		if (!path)
			return -1;
		p = path;
		while (*p) {
			const char *e = strchr(p, ':');
			size_t seg = e ? (size_t)(e - p) : strlen(p);

			if (seg) {
				if (seg + strlen(bin) + 2 < outlen) {
					snprintf(out, outlen, "%.*s/%s",
						 (int)seg, p, bin);
					if (access(out, X_OK) == 0)
						return 0;
				}
			} else {
				/* 空段=当前目录 */
				snprintf(out, outlen, "%s", bin);
				if (access(out, X_OK) == 0)
					return 0;
			}
			if (!e)
				break;
			p = e + 1;
		}
	}
	return -1;
}

/*
 * default_bin - 缺省 occ 可执行：/proc/self/exe 同目录 occ（主会话
 * 进程即 occ——子进程同厂同版本）；不可执行退 PATH「occ」。
 */
static int default_bin(char *out, size_t outlen)
{
	char self[512];
	ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
	char *slash;

	if (n <= 0)
		goto path;
	self[n] = '\0';
	slash = strrchr(self, '/');
	if (!slash)
		goto path;
	*slash = '\0';
	if (snprintf(out, outlen, "%s/occ", self) < (int)outlen &&
	    access(out, X_OK) == 0)
		return 0;
path:
	return resolve_bin("occ", out, outlen);
}

/* ---- 运行时生命周期 ---- */

occ_orch *occ_orch_new(occ_db *db)
{
	occ_orch *o;

	if (!db)
		return NULL;
	o = calloc(1, sizeof(*o));
	if (!o)
		return NULL;
	o->db = db;
	o->backoff_ms = OCC_ORCH_BACKOFF_MS;
	return o;
}

int occ_orch_nrunning(const occ_orch *o)
{
	return o ? o->n_live : 0;
}

long long occ_orch_backoff_ms(const occ_orch *o)
{
	return o ? backoff_remaining(o, mono_ms()) : 0;
}

void occ_orch_set_backoff_ms(occ_orch *o, long long ms)
{
	if (!o)
		return;
	o->backoff_ms = ms > 0 ? ms : OCC_ORCH_BACKOFF_MS;
	o->win_start_ms = 0;		/* 覆写即清窗（测试复位口） */
	o->rejects = 0;
}

static void child_unhook(occ_orch_child *c)
{
	occ_orch *o = c->o;
	int i, j;

	for (i = 0; i < o->n_live; i++) {
		if (o->live[i] == c) {
			for (j = i; j < o->n_live - 1; j++)
				o->live[j] = o->live[j + 1];
			o->n_live--;
			return;
		}
	}
}

static void child_free(occ_orch_child *c)
{
	child_unhook(c);
	if (c->own_files) {
		if (c->stdout_path)
			unlink(c->stdout_path);
		if (c->stderr_path)
			unlink(c->stderr_path);
	}
	free(c->stdout_path);
	free(c->stderr_path);
	free(c);
}

/*
 * occ_orch_free - 活子按取消两段收尸（TERM→宽限→KILL→waitpid），
 * 不 review（半完成态留 dispatched 可审计，§10 风险 3 口径）。
 */
void occ_orch_free(occ_orch *o)
{
	if (!o)
		return;
	while (o->n_live > 0) {
		occ_orch_child *c = o->live[0];
		int st;
		int reaped = 0;

		(void)kill(-c->pgid, SIGTERM);
		(void)kill(c->pid, SIGTERM);
		{
			long long t0 = mono_ms();

			while (mono_ms() - t0 < OCC_ORCH_TERM_GRACE_MS) {
				if (waitpid(c->pid, &st, WNOHANG) ==
				    c->pid) {
					reaped = 1;
					break;
				}
				{
					struct timespec ts = {
						0, 20 * 1000 * 1000
					};

					nanosleep(&ts, NULL);
				}
			}
		}
		if (!reaped) {
			(void)kill(-c->pgid, SIGKILL);
			(void)kill(c->pid, SIGKILL);
			while (waitpid(c->pid, &st, 0) < 0 &&
			       errno == EINTR)
				;
		}
		child_free(c);
	}
	free(o);
}

/* ---- spawn ---- */

static int temp_path(char *buf, size_t buflen, const char *tag)
{
	int fd;

	snprintf(buf, buflen, "/tmp/occ_orch_%s_XXXXXX", tag);
	fd = mkstemp(buf);
	if (fd < 0)
		return -1;
	close(fd);
	return 0;
}

static void escalate_best_effort(occ_db *db, const char *task_id,
				 const char *why)
{
	char rj[320];

	if (!task_id || !task_id[0])
		return;
	snprintf(rj, sizeof(rj),
		 "{\"reason\":\"spawn_failed\",\"detail\":\"%.192s\"}", why);
	occ_task_escalate(db, task_id, rj, NULL, 0);
}

int occ_orch_spawn(occ_orch *o, const occ_orch_spawn_opts *opts,
		   occ_orch_child **out, char *err, size_t errlen)
{
	char bin[512], dbkv[600];
	char sid[OCC_ID_LEN] = "", tid[OCC_ID_LEN] = "";
	char sop[96], sep[96];
	char *argv[6], **envp = NULL;
	occ_orch_child *c;
	long long now;
	int dispatched = 0;

	if (!o || !opts || !opts->prompt || !opts->prompt[0] || !out) {
		set_err(err, errlen,
			"occ_orch_spawn: 参数不合法（prompt 必填）");
		return OCC_ORCH_EARGS;
	}
	*out = NULL;

	/* ---- 并发闸：退避窗优先于槽位（撞过限的路必须等满窗） ---- */
	now = mono_ms();
	{
		long long rem = backoff_remaining(o, now);

		if (rem > 0) {
			set_err(err, errlen, "并发退避窗内（剩 %lld ms）——"
				"撞限后须等满 %lld ms 再重试该路",
				rem, o->backoff_ms);
			return OCC_ORCH_EBACKOFF;
		}
	}
	if (o->n_live >= OCC_ORCH_MAX_CHILDREN) {
		if (!o->win_start_ms ||
		    now - o->win_start_ms >= o->backoff_ms) {
			o->win_start_ms = now;
			o->rejects = 0;
		}
		o->rejects++;
		set_err(err, errlen, "并发上限 %d 已满（活子 %d，立即拒绝"
			"；本窗第 %d 次拒绝）——退避 %lld ms 后重试",
			OCC_ORCH_MAX_CHILDREN, o->n_live, o->rejects,
			o->backoff_ms);
		return OCC_ORCH_ELIMIT;
	}

	/* ---- 会话面：私有 child 会话（已给 id 则复用） ---- */
	if (opts->session_id && opts->session_id[0]) {
		snprintf(sid, sizeof(sid), "%s", opts->session_id);
	} else {
		occ_session_row srow;
		char e2[192];

		if (occ_session_create_kind(o->db,
					    opts->model ? opts->model : "",
					    OCC_SK_CHILD, &srow, e2,
					    sizeof(e2)) != 0) {
			set_err(err, errlen, "occ_orch_spawn: 建子会话失败"
				"：%s", e2);
			return OCC_ORCH_EDB;
		}
		snprintf(sid, sizeof(sid), "%s", srow.id);
	}

	/* ---- 任务面：自动建行（可免）+ dispatch 钉 child 会话 ---- */
	if (opts->task_id && opts->task_id[0]) {
		snprintf(tid, sizeof(tid), "%s", opts->task_id);
	} else if (opts->parent_session && opts->parent_session[0]) {
		occ_task_row trow;
		char title[OCC_TASK_TITLE_MAX];
		char e2[192];

		if (opts->title && opts->title[0])
			utf8_trunc(opts->title, sizeof(title) - 1, title,
				   sizeof(title));
		else
			utf8_trunc(opts->prompt, 64, title, sizeof(title));
		if (occ_task_create(o->db, opts->parent_session, title,
				    opts->prompt, 0, &trow, e2,
				    sizeof(e2)) != 0) {
			set_err(err, errlen, "occ_orch_spawn: 建任务失败"
				"：%s", e2);
			return OCC_ORCH_EDB;
		}
		snprintf(tid, sizeof(tid), "%s", trow.id);
		occ_task_row_free(&trow);
	}
	if (tid[0]) {
		char e2[192];

		if (occ_task_dispatch(o->db, tid, sid, e2, sizeof(e2)) != 0) {
			set_err(err, errlen, "occ_orch_spawn: 派发失败"
				"：%s", e2);
			return OCC_ORCH_EDB;	/* 任务留 pending，干净 */
		}
		dispatched = 1;
	}

	/* ---- 可执行 + 输出文件 + env ---- */
	if (opts->occ_bin && opts->occ_bin[0]) {
		if (resolve_bin(opts->occ_bin, bin, sizeof(bin))) {
			set_err(err, errlen, "occ_orch_spawn: 可执行不可用"
				" `%.200s'", opts->occ_bin);
			if (dispatched)
				escalate_best_effort(o->db, tid,
						     "occ_bin resolve");
			return OCC_ORCH_ESPAWN;
		}
	} else if (default_bin(bin, sizeof(bin))) {
		set_err(err, errlen, "occ_orch_spawn: occ 可执行未找到"
			"（/proc/self/exe 同目录与 PATH 均无）");
		if (dispatched)
			escalate_best_effort(o->db, tid, "occ bin not found");
		return OCC_ORCH_ESPAWN;
	}
	if (opts->stdout_path && opts->stdout_path[0]) {
		snprintf(sop, sizeof(sop), "%s", opts->stdout_path);
	} else if (temp_path(sop, sizeof(sop), "out")) {
		set_err(err, errlen, "occ_orch_spawn: stdout 临时文件失败"
			"：%s", strerror(errno));
		if (dispatched)
			escalate_best_effort(o->db, tid, "stdout tempfile");
		return OCC_ORCH_ESPAWN;
	}
	if (opts->stderr_path && opts->stderr_path[0]) {
		snprintf(sep, sizeof(sep), "%s", opts->stderr_path);
	} else if (temp_path(sep, sizeof(sep), "err")) {
		unlink(sop);
		set_err(err, errlen, "occ_orch_spawn: stderr 临时文件失败"
			"：%s", strerror(errno));
		if (dispatched)
			escalate_best_effort(o->db, tid, "stderr tempfile");
		return OCC_ORCH_ESPAWN;
	}
	/* OCC_DB 注入：子会话/任务与运行时同库（B2 并发写库即生产路径；
	 * env 同名项在后覆盖——调用方可显式改道） */
	snprintf(dbkv, sizeof(dbkv), "OCC_DB=%.480s", occ_db_path(o->db));
	envp = env_build(dbkv, opts->env);
	if (!envp) {
		unlink(sop);
		unlink(sep);
		set_err(err, errlen, "occ_orch_spawn: env 构建失败（oom）");
		if (dispatched)
			escalate_best_effort(o->db, tid, "env oom");
		return OCC_ORCH_ESPAWN;
	}

	/* ---- fork+execve（子侧全 async-signal-safe） ---- */
	c = calloc(1, sizeof(*c));
	if (!c) {
		env_free(envp);
		unlink(sop);
		unlink(sep);
		set_err(err, errlen, "occ_orch_spawn: oom");
		if (dispatched)
			escalate_best_effort(o->db, tid, "child oom");
		return OCC_ORCH_ESPAWN;
	}
	c->o = o;
	snprintf(c->session_id, sizeof(c->session_id), "%s", sid);
	snprintf(c->task_id, sizeof(c->task_id), "%s", tid);
	c->stdout_path = strdup(sop);
	c->stderr_path = strdup(sep);
	c->own_files = !(opts->stdout_path && opts->stdout_path[0]) &&
		       !(opts->stderr_path && opts->stderr_path[0]);
	c->started_ms = mono_ms();
	c->deadline_ms = opts->timeout_ms > 0 ?
		c->started_ms + opts->timeout_ms : 0;

	argv[0] = bin;
	argv[1] = (char *)"-p";
	argv[2] = (char *)opts->prompt;
	argv[3] = (char *)"--session";
	argv[4] = sid;
	argv[5] = NULL;

	c->pid = fork();
	if (c->pid < 0) {
		int e = errno;

		env_free(envp);
		free(c->stdout_path);
		free(c->stderr_path);
		free(c);
		unlink(sop);
		unlink(sep);
		set_err(err, errlen, "occ_orch_spawn: fork 失败：%s",
			strerror(e));
		if (dispatched)
			escalate_best_effort(o->db, tid, "fork failed");
		return OCC_ORCH_ESPAWN;
	}
	if (c->pid == 0) {
		/* 子侧：独立进程组 + fd 三路重定向 + cwd + execve。
		 * 任一步失败 _exit(12x)——如实回收，不继承父 fd 语义。 */
		int fd;

		setpgid(0, 0);
		fd = open("/dev/null", O_RDONLY);
		if (fd < 0)
			_exit(125);
		dup2(fd, STDIN_FILENO);
		close(fd);
		fd = open(sop, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd < 0)
			_exit(125);
		dup2(fd, STDOUT_FILENO);
		close(fd);
		fd = open(sep, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd < 0)
			_exit(125);
		dup2(fd, STDERR_FILENO);
		close(fd);
		if (opts->workdir && opts->workdir[0] &&
		    chdir(opts->workdir))
			_exit(126);
		execve(bin, argv, envp);
		_exit(127);		/* execve 失败：如实回收 127 */
	}
	env_free(envp);
	setpgid(c->pid, c->pid);	/* 与子侧互兜（竞态无害） */
	c->pgid = c->pid;
	o->live[o->n_live++] = c;
	*out = c;
	return OCC_ORCH_OK;
}

/* ---- 回收（poll/wait/cancel 共路） ---- */

static void term_group(occ_orch_child *c, int timeout_flag)
{
	if (c->cancelling)
		return;
	c->cancelling = 1;
	c->timed_out = timeout_flag;
	c->kill_at_ms = mono_ms() + OCC_ORCH_TERM_GRACE_MS;
	(void)kill(-c->pgid, SIGTERM);
	(void)kill(c->pid, SIGTERM);
}

/* stdout 尾窗读回（文件缺失/读失败 → NULL，不炸回收主路径） */
static char *read_stdout_tail(const char *path)
{
	char *buf;
	off_t sz;
	int fd;
	ssize_t got;
	size_t want;

	if (!path)
		return NULL;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;
	sz = lseek(fd, 0, SEEK_END);
	if (sz < 0) {
		close(fd);
		return NULL;
	}
	want = (size_t)sz > OCC_ORCH_STDOUT_TAIL ? OCC_ORCH_STDOUT_TAIL :
		(size_t)sz;
	buf = malloc(want + 1);
	if (!buf) {
		close(fd);
		return NULL;
	}
	if (lseek(fd, sz - (off_t)want, SEEK_SET) < 0)
		got = -1;
	else
		got = read(fd, buf, want);
	close(fd);
	if (got < 0) {
		free(buf);
		return NULL;
	}
	buf[got] = '\0';
	return buf;
}

static const char *end_str(occ_orch_end e)
{
	switch (e) {
	case OCC_ORCH_END_EXIT:
		return "exit";
	case OCC_ORCH_END_SIGNAL:
		return "signal";
	case OCC_ORCH_END_CANCELLED:
		return "cancelled";
	case OCC_ORCH_END_TIMEOUT:
		return "timeout";
	}
	return "?";
}

/*
 * collect - 终局收口（waitpid 已收尸后）：分类 → stdout 读回 →
 * 任务面 review（dispatched→in_review；payload=终局摘要 JSON——
 * 纯 ASCII 数值+路径，无自由文本转义面）→ 出表释放（c 失效）。
 */
static void collect(occ_orch_child *c, int st, occ_orch_result *res)
{
	occ_orch_result r;
	int sig = 0, code = 0;
	occ_orch_end end = OCC_ORCH_END_EXIT;

	memset(&r, 0, sizeof(r));
	if (WIFEXITED(st)) {
		end = OCC_ORCH_END_EXIT;
		code = WEXITSTATUS(st);
	} else if (WIFSIGNALED(st)) {
		sig = WTERMSIG(st);
		if (c->timed_out)
			end = OCC_ORCH_END_TIMEOUT;
		else if (c->cancelling)
			end = OCC_ORCH_END_CANCELLED;
		else
			end = OCC_ORCH_END_SIGNAL;
	}
	r.end = end;
	r.exit_code = code;
	r.signal = sig;
	r.dur_ms = mono_ms() - c->started_ms;
	r.stdout_tail = read_stdout_tail(c->stdout_path);
	snprintf(r.session_id, sizeof(r.session_id), "%s", c->session_id);
	snprintf(r.task_id, sizeof(r.task_id), "%s", c->task_id);
	if (r.task_id[0]) {
		char rj[640];
		char e2[192];

		snprintf(rj, sizeof(rj),
			 "{\"end\":\"%s\",\"exit_code\":%d,\"signal\":%d,"
			 "\"dur_ms\":%lld,\"stdout_path\":\"%.256s\"}",
			 end_str(end), code, sig, r.dur_ms,
			 c->stdout_path ? c->stdout_path : "");
		r.reviewed = occ_task_review(c->o->db, r.task_id, rj, e2,
					     sizeof(e2)) == 0;
	}
	if (res)
		*res = r;			/* 所有权移交调用方 */
	else
		free(r.stdout_tail);
	child_free(c);
}

/*
 * poll_once - 单轮探测：deadline→TERM（超时走取消同路径）；宽限到
 * →KILL；waitpid WNOHANG。返回 1=终局（c 已释放）；0=在跑；-1=错。
 */
static int poll_once(occ_orch_child *c, occ_orch_result *res)
{
	int st;
	long long now = mono_ms();

	if (!c->cancelling && c->deadline_ms && now >= c->deadline_ms)
		term_group(c, 1);
	if (c->cancelling && !c->killed && now >= c->kill_at_ms) {
		c->killed = 1;
		(void)kill(-c->pgid, SIGKILL);
		(void)kill(c->pid, SIGKILL);
	}
	if (waitpid(c->pid, &st, WNOHANG) == c->pid) {
		collect(c, st, res);
		return 1;
	}
	return 0;
}

int occ_orch_poll(occ_orch_child *c, occ_orch_result *res)
{
	if (!c)
		return -1;
	if (res)
		memset(res, 0, sizeof(*res));
	if (poll_once(c, res) == 1)
		return 1;
	return 0;
}

int occ_orch_wait(occ_orch_child *c, occ_orch_result *res,
		  char *err, size_t errlen)
{
	if (!c) {
		set_err(err, errlen, "occ_orch_wait: child 已终局（句柄"
			"在终局回收时失效）");
		return -1;
	}
	if (res)
		memset(res, 0, sizeof(*res));
	for (;;) {
		int rc = poll_once(c, res);

		if (rc == 1)
			return OCC_ORCH_OK;
		if (rc < 0) {
			set_err(err, errlen, "occ_orch_wait: waitpid 异常"
				"：%s", strerror(errno));
			return -1;
		}
		{
			struct timespec ts = { 0, 20 * 1000 * 1000 };

			nanosleep(&ts, NULL);
		}
	}
}

int occ_orch_cancel(occ_orch_child *c, occ_orch_result *res,
		    char *err, size_t errlen)
{
	if (!c) {
		set_err(err, errlen, "occ_orch_cancel: child 已终局（句柄"
			"在终局回收时失效）");
		return -1;
	}
	term_group(c, 0);
	return occ_orch_wait(c, res, err, errlen);
}

void occ_orch_result_free(occ_orch_result *r)
{
	if (!r)
		return;
	free(r->stdout_tail);
	memset(r, 0, sizeof(*r));
}

/* ---- 活子观测 ---- */

pid_t occ_orch_child_pid(const occ_orch_child *c)
{
	return c ? c->pid : (pid_t)-1;
}

const char *occ_orch_child_session(const occ_orch_child *c)
{
	return c ? c->session_id : "";
}

const char *occ_orch_child_task(const occ_orch_child *c)
{
	return c ? c->task_id : "";
}
