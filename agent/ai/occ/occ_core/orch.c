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
 *
 * E3 追加（§8 棒 E3，语义详见 orch.h 头注 E3 段）：
 *   文件集互斥登记表（活任务独占声明；spawn 冲突即拒 OCC_ORCH_EFILESET，
 *   终局/取消/释放自动注销）+ 任务注册表（task_id → 结果文件，终局后
 *   保留供 read_result）+ OCC_TASK_RESULT_FILE env 通道 + 总闸
 *   occ_orch_tools_enabled + occ_bin 的 OCC_ORCH_BIN env 覆写（测试
 *   注入 stub occ 用；生产进程 /proc/self/exe 同目录优先级不变）。
 *
 * E7 追加（§8 棒 E7，语义详见 orch.h 头注 E7 段）：
 *   逐任务 token 记账管线（budget_in/budget_out 列 E1 已建）——
 *   spawn 预算基线事件（occ_task_budget_baseline）/终局回收从子会话
 *   usage 真值累加（child_usage_sum+occ_task_budget_add，无 usage 时
 *   len/4 估算兜底标 estimated）/max_tokens 熔断三检查点（spawn 前
 *   拒绝再派、poll 在跑节流探查超限走取消同路径、终局记账后
 *   escalate——复用既有状态机路，不静默）。
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "orch.h"
#include "review.h"			/* E4：终局机械预判挂点 */
#include "occ_tokens.h"			/* E7：估算兜底 len/4 */
#include "occ_tui/tui_lang.h"		/* O-20 A2：语档文案面 */

#include <sqlite3.h>			/* E7：子会话 usage 汇总直查 */

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
	long long max_tokens;		/* E7：预算熔断上限（0=不设限） */
	long long last_bud_ms;		/* E7：在跑探查节流锚（下次可查时刻） */
	long long sum_in0;		/* E7：spawn 时子会话 usage 快照（增量
					 * 记账防 rework 再派同会话双计） */
	long long sum_out0;
};

struct occ_orch {
	occ_db *db;
	occ_orch_child *live[OCC_ORCH_MAX_CHILDREN];
	int n_live;
	long long backoff_ms;		/* 缺省 OCC_ORCH_BACKOFF_MS */
	long long win_start_ms;		/* 撞限窗起点（0=从未撞限） */
	int rejects;			/* 窗内拒绝次数（诊断） */
	/* E3：文件集互斥登记表（在跑任务独占声明；终局自动注销） */
	struct {
		char task_id[OCC_ID_LEN];
		char **files;		/* heap 拷贝（绝对路径串） */
		size_t nfiles;
	} *fsx;
	size_t n_fsx;
	/* E3：任务注册表（task_id → 结果文件；终局后保留至 free） */
	struct {
		char task_id[OCC_ID_LEN];
		char *result_path;	/* NULL=该任务无结果文件 */
		int own_result;		/* 1=本运行时自动生成（free 时删） */
	} *trec;
	size_t n_trec;
	/* E4：独立评审智能体挂载点（§4 可选项；缺省 NULL=裁判主会话） */
	occ_orch_review_hook review_hook;
	void *review_ud;
};

/* ---- E3：总闸 ---- */

int occ_orch_tools_enabled(void)
{
	const char *v = getenv("OCC_ORCH_TOOLS");

	return v && v[0] && strcmp(v, "0") != 0 &&
	       strcasecmp(v, "false") != 0;
}

/* ---- E3：文件集互斥登记表 ---- */

int occ_orch_fileset_conflict(const occ_orch *o, const char *const *files,
			      size_t n, char *owner_task, size_t buflen)
{
	size_t i, j, k;

	if (owner_task && buflen)
		owner_task[0] = '\0';
	if (!o || !files || !n)
		return 0;
	for (i = 0; i < o->n_fsx; i++) {
		for (j = 0; j < o->fsx[i].nfiles; j++) {
			for (k = 0; k < n; k++) {
				if (files[k] && o->fsx[i].files[j] &&
				    !strcmp(o->fsx[i].files[j], files[k])) {
					if (owner_task && buflen)
						snprintf(owner_task, buflen,
							 "%s",
							 o->fsx[i].task_id);
					return 1;
				}
			}
		}
	}
	return 0;
}

/* fork 前登记（tid 已知）；失败=oom 返回 -1（调用方回滚）。 */
static int fsx_add(occ_orch *o, const char *task_id,
		   const char *const *files, size_t n)
{
	char **cp;
	size_t i, j;

	if (!o || !task_id || !task_id[0] || !files || !n)
		return 0;
	cp = calloc(n, sizeof(*cp));
	if (!cp)
		return -1;
	for (i = 0; i < n; i++) {
		cp[i] = strdup(files[i] ? files[i] : "");
		if (!cp[i]) {
			for (j = 0; j < i; j++)
				free(cp[j]);
			free(cp);
			return -1;
		}
	}
	{
		void *nb = realloc(o->fsx, (o->n_fsx + 1) * sizeof(*o->fsx));

		if (!nb) {
			for (j = 0; j < n; j++)
				free(cp[j]);
			free(cp);
			return -1;
		}
		o->fsx = nb;
	}
	snprintf(o->fsx[o->n_fsx].task_id, sizeof(o->fsx[0].task_id), "%s",
		 task_id);
	o->fsx[o->n_fsx].files = cp;
	o->fsx[o->n_fsx].nfiles = n;
	o->n_fsx++;
	return 0;
}

/* 任务终局/取消/spawn 失败回滚：注销独占声明（无该任务则无副作用） */
static void fsx_release(occ_orch *o, const char *task_id)
{
	size_t i, j;

	if (!o || !task_id || !task_id[0])
		return;
	for (i = 0; i < o->n_fsx; i++) {
		if (!strcmp(o->fsx[i].task_id, task_id)) {
			for (j = 0; j < o->fsx[i].nfiles; j++)
				free(o->fsx[i].files[j]);
			free(o->fsx[i].files);
			memmove(&o->fsx[i], &o->fsx[i + 1],
				(o->n_fsx - i - 1) * sizeof(o->fsx[0]));
			o->n_fsx--;
			return;
		}
	}
}

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

/* P-31：OCC_TASK_FILESET env 值拼装（\n 分隔；元素绝对路径合同
 * ——orch.h 拍板，原样透传；尾 \n 多余无害，解析跳空段） */
static char *fs_env_kv(const char *const *fs, size_t n)
{
	size_t cap = 32, len = 0, i;
	char *kv = malloc(cap);

	if (!kv)
		return NULL;
	len = (size_t)snprintf(kv, cap, "OCC_TASK_FILESET=");
	for (i = 0; i < n && fs[i]; i++) {
		size_t el = strlen(fs[i]) + 2;
		char *nb;

		while (len + el + 1 > cap)
			cap *= 2;
		nb = realloc(kv, cap);
		if (!nb) {
			free(kv);
			return NULL;
		}
		kv = nb;
		len += (size_t)snprintf(kv + len, cap - len, "%s\n",
					fs[i]);
	}
	return kv;
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
 * default_bin - 缺省 occ 可执行：OCC_ORCH_BIN env 覆写（测试注入
 * stub occ；生产勿设）→ /proc/self/exe 同目录 occ（主会话进程即
 * occ——子进程同厂同版本）→ PATH「occ」。
 */
static int default_bin(char *out, size_t outlen)
{
	const char *env = getenv("OCC_ORCH_BIN");
	char self[512];
	ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
	char *slash;

	if (env && env[0]) {
		snprintf(out, outlen, "%s", env);
		if (access(out, X_OK) == 0)
			return 0;
	}
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

/* ---- E3：任务注册表（task_id → 结果文件；终局后保留） ---- */

/* upsert：同 task 覆盖（旧 own_result 文件不删——终局前覆盖属异常路径，
 * 文件留 /tmp 审计）；失败=oom 返回 -1。 */
static int trec_add(occ_orch *o, const char *task_id,
		    const char *result_path, int own_result)
{
	size_t i;
	char *cp = NULL;

	if (!o || !task_id || !task_id[0])
		return 0;
	if (result_path && result_path[0]) {
		cp = strdup(result_path);
		if (!cp)
			return -1;
	}
	for (i = 0; i < o->n_trec; i++) {
		if (!strcmp(o->trec[i].task_id, task_id)) {
			free(o->trec[i].result_path);
			o->trec[i].result_path = cp;
			o->trec[i].own_result = own_result;
			return 0;
		}
	}
	{
		void *nb = realloc(o->trec, (o->n_trec + 1) * sizeof(*o->trec));

		if (!nb) {
			free(cp);
			return -1;
		}
		o->trec = nb;
	}
	snprintf(o->trec[o->n_trec].task_id, sizeof(o->trec[0].task_id), "%s",
		 task_id);
	o->trec[o->n_trec].result_path = cp;
	o->trec[o->n_trec].own_result = own_result;
	o->n_trec++;
	return 0;
}

const char *occ_orch_result_path(const occ_orch *o, const char *task_id)
{
	size_t i;

	if (!o || !task_id)
		return NULL;
	for (i = 0; i < o->n_trec; i++)
		if (!strcmp(o->trec[i].task_id, task_id))
			return o->trec[i].result_path;
	return NULL;
}

occ_orch_child *occ_orch_find_task(occ_orch *o, const char *task_id)
{
	int i;

	if (!o || !task_id || !task_id[0])
		return NULL;
	for (i = 0; i < o->n_live; i++)
		if (o->live[i]->task_id[0] &&
		    !strcmp(o->live[i]->task_id, task_id))
			return o->live[i];
	return NULL;
}

/* E4：独立评审智能体挂载点（§4 可选项；语义见 orch.h 头注——
 * 回调在终局 review+机械预判后触发，缺省 NULL=裁判主会话） */
void occ_orch_set_review_hook(occ_orch *o, occ_orch_review_hook fn,
			      void *ud)
{
	if (!o)
		return;
	o->review_hook = fn;
	o->review_ud = ud;
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
	/* E3：任务终局（含取消/超时/orch_free 收尸）自动注销独占声明 */
	fsx_release(c->o, c->task_id);
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
	/* E3：登记表/注册表清空；自动生成的结果文件回收（/tmp 纪律） */
	while (o->n_fsx > 0) {
		size_t j;

		for (j = 0; j < o->fsx[0].nfiles; j++)
			free(o->fsx[0].files[j]);
		free(o->fsx[0].files);
		memmove(&o->fsx[0], &o->fsx[1],
			(o->n_fsx - 1) * sizeof(o->fsx[0]));
		o->n_fsx--;
	}
	free(o->fsx);
	{
		size_t i;

		for (i = 0; i < o->n_trec; i++) {
			if (o->trec[i].own_result && o->trec[i].result_path)
				unlink(o->trec[i].result_path);
			free(o->trec[i].result_path);
		}
		free(o->trec);
	}
	free(o);
}

/* ---- E7：预算记账（管线语义见 orch.h 头注 E7 段） ---- */

/*
 * child_usage_sum - 子会话 usage 真值汇总（occ_message 五项口径的
 * in/out 两项：role='assistant' 且 reverted=0 的消息求和）。est=任一
 * 消息 usage_est=1（loop 侧无 usage 回传时已按 len/4 估算落库并标记
 * ——估算兜底经此口径自然携带）。返回 0=查询成功；-1=参数/DB 错。
 */
static int child_usage_sum(occ_db *db, const char *session_id,
			   long long *tin, long long *tout, int *est)
{
	static const char *sel =
		"SELECT COALESCE(SUM(usage_in),0),"
		"COALESCE(SUM(usage_out),0),COALESCE(MAX(usage_est),0)"
		" FROM occ_message"
		" WHERE session_id=?1 AND role='assistant' AND reverted=0";
	sqlite3 *h;
	sqlite3_stmt *st = NULL;
	int rc;

	*tin = 0;
	*tout = 0;
	*est = 0;
	if (!db || !session_id || !session_id[0])
		return -1;
	h = occ_db_sqlite(db);
	if (sqlite3_prepare_v2(h, sel, -1, &st, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_text(st, 1, session_id, -1, SQLITE_TRANSIENT);
	rc = sqlite3_step(st);
	if (rc == SQLITE_ROW) {
		*tin = sqlite3_column_int64(st, 0);
		*tout = sqlite3_column_int64(st, 1);
		*est = sqlite3_column_int(st, 2);
		rc = 0;
	} else {
		rc = -1;
	}
	sqlite3_finalize(st);
	return rc;
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

/*
 * E3：dispatch 之后的失败路径统一清理——注销独占声明 + 删本运行时
 * 自动生成的结果文件 + escalate 审计（原 dispatched 分支并入）。
 */
static void spawn_fail_cleanup(occ_orch *o, const char *tid,
			       const char *rpath, int own_result,
			       const char *why)
{
	if (tid && tid[0])
		fsx_release(o, tid);
	if (own_result && rpath && rpath[0])
		unlink(rpath);
	escalate_best_effort(o->db, tid, why);
}

int occ_orch_spawn(occ_orch *o, const occ_orch_spawn_opts *opts,
		   occ_orch_child **out, char *err, size_t errlen)
{
	char bin[512], dbkv[600];
	char sid[OCC_ID_LEN] = "", tid[OCC_ID_LEN] = "";
	char sop[96], sep[96], rpath[192];
	char *argv[6], **envp = NULL, *pfull = NULL;
	occ_orch_child *c;
	long long now;
	long long bin0 = 0, bout0 = 0;	/* E7：spawn 时 usage 快照 */
	int dispatched = 0;
	int own_result = 0;		/* E3：结果文件为本运行时生成 */

	rpath[0] = '\0';
	if (!o || !opts || !opts->prompt || !opts->prompt[0] || !out) {
		set_err(err, errlen, "%s",
			L_("occ_orch_spawn: 参数不合法（prompt 必填）"));
		return OCC_ORCH_EARGS;
	}
	*out = NULL;

	/* ---- 并发闸：退避窗优先于槽位（撞过限的路必须等满窗） ---- */
	now = mono_ms();
	{
		long long rem = backoff_remaining(o, now);

		if (rem > 0) {
			set_err(err, errlen, L_("并发退避窗内（剩 %lld ms）——"
				"撞限后须等满 %lld ms 再重试该路"),
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
		set_err(err, errlen, L_("并发上限 %d 已满（活子 %d，立即拒绝"
			"；本窗第 %d 次拒绝）——退避 %lld ms 后重试"),
			OCC_ORCH_MAX_CHILDREN, o->n_live, o->rejects,
			o->backoff_ms);
		return OCC_ORCH_ELIMIT;
	}

	/* ---- E3：文件集互斥（会话/任务面未动，干净拒绝） ---- */
	if (opts->fileset && opts->nfileset) {
		char owner[OCC_ID_LEN];

		if (occ_orch_fileset_conflict(o, opts->fileset,
					      opts->nfileset, owner,
					      sizeof(owner))) {
			set_err(err, errlen,
				L_("文件集互斥冲突：已由在跑任务 %s 独占声明"
				  "（并发任务不得写同一文件——等其终局或换文件集）"),
				owner);
			return OCC_ORCH_EFILESET;
		}
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
			set_err(err, errlen, L_("occ_orch_spawn: 建子会话失败"
						"：%s"), e2);
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
				    opts->prompt, opts->rework_max, &trow,
				    e2, sizeof(e2)) != 0) {
			set_err(err, errlen, L_("occ_orch_spawn: 建任务失败"
						"：%s"), e2);
			return OCC_ORCH_EDB;
		}
		snprintf(tid, sizeof(tid), "%s", trow.id);
		occ_task_row_free(&trow);
	}
	if (tid[0]) {
		char e2[192];

		/*
		 * E7 熔断检查点①（spawn 前）：任务累计 budget_in+out 已超
		 * max_tokens（回炉重派路防越烧越多）→ 拒绝再派 + escalate
		 * 审计尽力（pending 态迁移非法时以拒绝为准——不静默）。
		 */
		if (opts->max_tokens > 0) {
			occ_task_row trow;

			if (occ_task_get(o->db, tid, &trow, e2,
					 sizeof(e2)) == 1) {
				long long used = trow.budget_in +
						 trow.budget_out;

				occ_task_row_free(&trow);
				if (used > opts->max_tokens) {
					char rj[192];

					snprintf(rj, sizeof(rj),
						 "{\"reason\":"
						 "\"budget_exceeded\","
						 "\"max_tokens\":%lld,"
						 "\"used\":%lld}",
						 opts->max_tokens, used);
					(void)occ_task_escalate(o->db, tid,
								rj, NULL, 0);
					set_err(err, errlen,
						L_("预算熔断：任务 %s 累计 "
						  "%lld tokens 已超上限 "
						  "%lld——拒绝再派（已记 "
						  "escalate 审计）"),
						tid, used,
						opts->max_tokens);
					return OCC_ORCH_EBUDGET;
				}
			}
		}
		if (occ_task_dispatch(o->db, tid, sid, e2, sizeof(e2)) != 0) {
			set_err(err, errlen, L_("occ_orch_spawn: 派发失败"
						"：%s"), e2);
			return OCC_ORCH_EDB;	/* 任务留 pending，干净 */
		}
		dispatched = 1;
		/*
		 * E7：预算基线入任务事件流（kind='budget' phase=baseline；
		 * 任务行两列仍恒由终局 budget_add 累加）。落库失败=账面
		 * 不可审计 → 与其它 dispatch 后失败同路（escalate 收口）。
		 */
		if (opts->max_tokens > 0 &&
		    occ_task_budget_baseline(o->db, tid, opts->max_tokens, e2,
					     sizeof(e2)) != 0) {
			set_err(err, errlen, L_("occ_orch_spawn: 预算基线落库"
						"失败：%s"), e2);
			spawn_fail_cleanup(o, tid, "", 0, "budget baseline");
			return OCC_ORCH_EDB;
		}
	}
	/*
	 * E7：子会话 usage 快照（fork 前）——终局 delta 记账基准（rework
	 * 再派同会话只记增量，不双计）。查询失败按 0（终局如实落账）。
	 */
	{
		long long s0in = 0, s0out = 0;
		int s0est;

		(void)child_usage_sum(o->db, sid, &s0in, &s0out, &s0est);
		bin0 = s0in;
		bout0 = s0out;
	}

	/* ---- E3：结果文件（报告 IPC）+ 登记（fork 前——oom 等失败在
	 * 此干净回滚，不留半登记状态） ---- */
	if (opts->result_path && opts->result_path[0]) {
		snprintf(rpath, sizeof(rpath), "%s", opts->result_path);
	} else if (tid[0]) {
		if (temp_path(rpath, sizeof(rpath), "res")) {
			set_err(err, errlen, L_("occ_orch_spawn: 结果文件临时"
						"生成失败：%s"), strerror(errno));
			if (dispatched)
				spawn_fail_cleanup(o, tid, "", 0,
						   "result tempfile");
			return OCC_ORCH_ESPAWN;
		}
		own_result = 1;
	}
	if (tid[0] && opts->fileset && opts->nfileset) {
		if (fsx_add(o, tid, opts->fileset, opts->nfileset)) {
			set_err(err, errlen, L_("occ_orch_spawn: 文件集登记失败"
						"（oom）"));
			if (dispatched)
				spawn_fail_cleanup(o, tid, rpath, own_result,
						   "fsx oom");
			else if (own_result)
				unlink(rpath);
			return OCC_ORCH_ESPAWN;
		}
	}
	if (tid[0] && trec_add(o, tid, rpath[0] ? rpath : NULL, own_result)) {
		set_err(err, errlen, "%s", L_("occ_orch_spawn: 任务注册失败（oom）"));
		if (dispatched) {
			spawn_fail_cleanup(o, tid, "", 0, "trec oom");
		} else {
			fsx_release(o, tid);	/* 未 dispatch：无 escalate 面 */
			if (own_result)
				unlink(rpath);
		}
		return OCC_ORCH_ESPAWN;
	}
	/*
	 * E10③：结果文件持久登记（kind='result_file' 事件，追加式
	 * 审计）。运行时注册表进程私有——派发进程死后 task 工具
	 * read_result/return 以此兜底恢复路径（任务不再「永久无法
	 * 验收」）。落库失败尽力不阻断 spawn（活注册表本进程内仍
	 * 有效；stderr 留痕可审计）。
	 */
	if (tid[0] && rpath[0]) {
		char pj[320];
		char e2[192];

		snprintf(pj, sizeof(pj), "{\"path\":\"%.256s\"}", rpath);
		if (occ_task_note_kind(o->db, tid, OCC_TASK_EV_RESULT_FILE,
				       pj, e2, sizeof(e2)) != 0)
			fprintf(stderr, L_("occ-orch: result_file 事件落库失败"
				"（task %s）：%s\n"), tid, e2);
	}

	/* ---- 可执行 + 输出文件 + env ---- */
	if (opts->occ_bin && opts->occ_bin[0]) {
		if (resolve_bin(opts->occ_bin, bin, sizeof(bin))) {
			set_err(err, errlen, L_("occ_orch_spawn: 可执行不可用"
						" `%.200s'"), opts->occ_bin);
			if (dispatched)
				spawn_fail_cleanup(o, tid, rpath, own_result,
						   "occ_bin resolve");
			return OCC_ORCH_ESPAWN;
		}
	} else if (default_bin(bin, sizeof(bin))) {
		set_err(err, errlen, "%s", L_("occ_orch_spawn: occ 可执行未找到"
			"（OCC_ORCH_BIN/proc/self/exe 同目录与 PATH 均无）"));
		if (dispatched)
			spawn_fail_cleanup(o, tid, rpath, own_result,
					   "occ bin not found");
		return OCC_ORCH_ESPAWN;
	}
	if (opts->stdout_path && opts->stdout_path[0]) {
		snprintf(sop, sizeof(sop), "%s", opts->stdout_path);
	} else if (temp_path(sop, sizeof(sop), "out")) {
		set_err(err, errlen, L_("occ_orch_spawn: stdout 临时文件失败"
					"：%s"), strerror(errno));
		if (dispatched)
			spawn_fail_cleanup(o, tid, rpath, own_result,
					   "stdout tempfile");
		return OCC_ORCH_ESPAWN;
	}
	if (opts->stderr_path && opts->stderr_path[0]) {
		snprintf(sep, sizeof(sep), "%s", opts->stderr_path);
	} else if (temp_path(sep, sizeof(sep), "err")) {
		unlink(sop);
		set_err(err, errlen, L_("occ_orch_spawn: stderr 临时文件失败"
					"：%s"), strerror(errno));
		if (dispatched)
			spawn_fail_cleanup(o, tid, rpath, own_result,
					   "stderr tempfile");
		return OCC_ORCH_ESPAWN;
	}
	/* OCC_DB 注入：子会话/任务与运行时同库（B2 并发写库即生产路径；
	 * env 同名项在后覆盖——调用方可显式改道） */
	snprintf(dbkv, sizeof(dbkv), "OCC_DB=%.480s", occ_db_path(o->db));
	envp = env_build(dbkv, opts->env);
	if (!envp) {
		unlink(sop);
		unlink(sep);
		set_err(err, errlen, "%s", L_("occ_orch_spawn: env 构建失败（oom）"));
		if (dispatched)
			spawn_fail_cleanup(o, tid, rpath, own_result,
					   "env oom");
		return OCC_ORCH_ESPAWN;
	}
	/* E3：结果文件 env 通道（OCC_TASK_RESULT_FILE→子进程报告写它；
	 * 同名项 env_build 已含调用方附加——此处后写覆盖生效） */
	/* E6：任务 id 通道（子会话 t: 层记忆注入用） */
	{
		char tkv[160];

		snprintf(tkv, sizeof(tkv), "OCC_TASK_ID=%s",
			 tid[0] ? tid : "");
		if (env_set(&envp, tkv)) {
			env_free(envp);
			unlink(sop);
			unlink(sep);
			set_err(err, errlen, "%s", L_("occ_orch_spawn: OCC_TASK_ID env"
				" 注入失败（oom）"));
			if (dispatched)
				spawn_fail_cleanup(o, tid, rpath, own_result,
						   "taskid env");
			return OCC_ORCH_ESPAWN;
		}
	}
	/* P-31：fileset 授权 env 通道（子进程 write_guard 强制依据） */
	if (tid[0] && opts->fileset && opts->nfileset) {
		char *kv = fs_env_kv(opts->fileset, opts->nfileset);

		if (!kv || env_set(&envp, kv)) {
			free(kv);
			env_free(envp);
			unlink(sop);
			unlink(sep);
			set_err(err, errlen, "%s", L_("occ_orch_spawn: "
				"OCC_TASK_FILESET env 注入失败（oom）"));
			if (dispatched)
				spawn_fail_cleanup(o, tid, rpath, own_result,
						   "fileset env");
			return OCC_ORCH_ESPAWN;
		}
		free(kv);
	}
	if (rpath[0]) {
		char rkv[512];

		snprintf(rkv, sizeof(rkv), "%s=%.480s", OCC_ORCH_RESULT_ENV,
			 rpath);
		if (env_set(&envp, rkv)) {
			env_free(envp);
			unlink(sop);
			unlink(sep);
			set_err(err, errlen, "%s", L_("occ_orch_spawn: 结果文件 env"
				" 注入失败（oom）"));
			if (dispatched)
				spawn_fail_cleanup(o, tid, rpath, own_result,
						   "result env oom");
			return OCC_ORCH_ESPAWN;
		}
	}

	/* ---- fork+execve（子侧全 async-signal-safe） ---- */
	c = calloc(1, sizeof(*c));
	if (!c) {
		env_free(envp);
		unlink(sop);
		unlink(sep);
		set_err(err, errlen, "occ_orch_spawn: oom");
		if (dispatched)
			spawn_fail_cleanup(o, tid, rpath, own_result,
					   "child oom");
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
	/* E7：预算面（上限/探查节流锚/usage 快照——终局增量记账基准） */
	c->max_tokens = opts->max_tokens > 0 ? opts->max_tokens : 0;
	c->last_bud_ms = c->started_ms + OCC_ORCH_BUDGET_PROBE_MS;
	c->sum_in0 = bin0;
	c->sum_out0 = bout0;

	/*
	 * R2（E10 复跑虫②）：结果文件 prompt 通道。aik-sandbox 剥 env
	 * ——子进程内 $OCC_TASK_RESULT_FILE 为空，报告落点找不到（复跑
	 * 8 次预算被此烧掉）。有结果文件（rpath）时把路径直书 prompt
	 * 尾行（env 通道保留双保险）；malloc 尽力（失败回退原 prompt，
	 * stderr 留痕——spawn 已过任务面建行，为此 escalate 代价比
	 * 报告通道降级大）。无任务面（无 rpath）不追加。
	 */
	if (rpath[0]) {
		pfull = malloc(strlen(opts->prompt) + sizeof(rpath) + 128);
		if (pfull) {
			snprintf(pfull,
				 strlen(opts->prompt) + sizeof(rpath) + 128,
				 L_("%s\n结果报告写此文件：%.192s"
				   "（报告=任务书要求+# VERDICT 表）\n"),
				 opts->prompt, rpath);
		} else {
			fputs(L_("occ-orch: 结果文件 prompt 通道"
				 " 追加失败（oom）——env 通道兜底\n"), stderr);
		}
	}
	argv[0] = bin;
	argv[1] = (char *)"-p";
	argv[2] = pfull ? pfull : (char *)opts->prompt;
	argv[3] = (char *)"--session";
	argv[4] = sid;
	argv[5] = NULL;

	c->pid = fork();
	if (c->pid < 0) {
		int e = errno;

		env_free(envp);
		free(pfull);
		free(c->stdout_path);
		free(c->stderr_path);
		free(c);
		unlink(sop);
		unlink(sep);
		set_err(err, errlen, L_("occ_orch_spawn: fork 失败：%s"),
			strerror(e));
		if (dispatched)
			spawn_fail_cleanup(o, tid, rpath, own_result,
					   "fork failed");
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
	free(pfull);		/* fork 后父侧独释（子侧 execve 用副本） */
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
		/*
		 * E4 挂点（§4 验收环）：终局即机械预判（occ_review_prenote
		 * ——结果文件+brief 验收标准→机械判结论落 kind='return'
		 * 审计事件，不动状态机；read_result/裁判提前可见）+ 可选
		 * 独立评审智能体回调（缺省 NULL=裁判主会话）。两者皆
		 * best-effort：失败不阻断收口、不丢任务（留 in_review 待
		 * 主会话 task return 动作走验收环兜底）。
		 */
		if (r.reviewed) {
			const char *rp = occ_orch_result_path(c->o, r.task_id);

			occ_review_prenote(c->o->db, r.task_id, rp);
			if (c->o->review_hook)
				c->o->review_hook(c->o->review_ud, c->o->db,
						  r.task_id, rp, rj);
		}
		/*
		 * E7 记账（终局回收）：从子会话 usage 累加 budget_in/out
		 * ——真值优先（occ_message 五项口径 SUM；估算成分经
		 * usage_est 标注）；子会话零消息且 stdout 有产出时以
		 * len/4 估算兜底（src=estimated）。增量口径=终局 sum−
		 * spawn 快照（rework 再派同会话不双计；负增量钳 0——
		 * /undo 隐藏等收缩不改已记账面）。单事务 UPDATE+kind=
		 * 'budget' 审计事件（task.c occ_task_budget_add）；失败
		 * best-effort 不阻断收口（账面留 0 可由事件流诊断）。
		 */
		{
			long long sin = 0, sout = 0;
			int est = 0;

			if (child_usage_sum(c->o->db, c->session_id, &sin,
					    &sout, &est) == 0) {
				long long din = sin - c->sum_in0;
				long long dout = sout - c->sum_out0;

				if (din < 0)
					din = 0;
				if (dout < 0)
					dout = 0;
				if (din + dout == 0 && r.stdout_tail &&
				    r.stdout_tail[0]) {
					dout = occ_tokens_estimate_len(
						r.stdout_tail);
					est = 1;
				}
				if (din + dout > 0)
					(void)occ_task_budget_add(c->o->db,
						r.task_id, din, dout, est,
						e2, sizeof(e2));
			}
		}
		/*
		 * E7 熔断检查点③（回收终局后）：记账落账面后累计超限 →
		 * occ_task_escalate（in_review/dispatched→escalated 均合法
		 * 迁移路；payload reason=budget_exceeded——不许静默）。
		 */
		if (c->max_tokens > 0) {
			occ_task_row trow;

			if (occ_task_get(c->o->db, r.task_id, &trow, NULL,
					 0) == 1) {
				long long used = trow.budget_in +
						 trow.budget_out;

				if (used > c->max_tokens) {
					snprintf(rj, sizeof(rj),
						 "{\"reason\":"
						 "\"budget_exceeded\","
						 "\"max_tokens\":%lld,"
						 "\"budget_in\":%lld,"
						 "\"budget_out\":%lld}",
						 c->max_tokens,
						 trow.budget_in,
						 trow.budget_out);
					(void)occ_task_escalate(c->o->db,
								r.task_id,
								rj, NULL, 0);
				}
				occ_task_row_free(&trow);
			}
		}
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

	/*
	 * E7 熔断检查点②（在跑）：节流探查（OCC_ORCH_BUDGET_PROBE_MS
	 * 上限一次查库）——任务累计账面+本轮子会话增量（spawn 快照起算）
	 * 超限 → 取消同路径（TERM→宽限→KILL——复用既有取消面；终局
	 * collect 记账后由检查点③ escalate 收口，不静默）。
	 */
	if (!c->cancelling && c->max_tokens > 0 &&
	    now >= c->last_bud_ms) {
		long long sin = 0, sout = 0;
		int est;

		c->last_bud_ms = now + OCC_ORCH_BUDGET_PROBE_MS;
		if (child_usage_sum(c->o->db, c->session_id, &sin, &sout,
				    &est) == 0) {
			long long used = 0;

			if (c->task_id[0]) {
				occ_task_row trow;

				if (occ_task_get(c->o->db, c->task_id, &trow,
						 NULL, 0) == 1) {
					used = trow.budget_in +
					       trow.budget_out;
					occ_task_row_free(&trow);
				}
			}
			if (used + (sin - c->sum_in0) +
			    (sout - c->sum_out0) > c->max_tokens)
				term_group(c, 0);
		}
	}
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
		set_err(err, errlen, "%s",
			L_("occ_orch_wait: child 已终局（句柄在终局回收时失效）"));
		return -1;
	}
	if (res)
		memset(res, 0, sizeof(*res));
	for (;;) {
		int rc = poll_once(c, res);

		if (rc == 1)
			return OCC_ORCH_OK;
		if (rc < 0) {
			set_err(err, errlen, L_("occ_orch_wait: waitpid 异常"
						"：%s"), strerror(errno));
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
		set_err(err, errlen, "%s",
			L_("occ_orch_cancel: child 已终局（句柄在终局回收时失效）"));
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


/* ---- E5 子会话蒸馏（ORCH §5：子不压缩只蒸馏） ---- */
#include "occ_sme.h"
#include "occ_ac.h"

/* E5 闸1 旗营（定义在此：tools/orch 面置旗、ac 收口取用——
 * 避免 occ_ac.o 拖 LLM/HTTP 级联进轻量测试链接） */
static int g_compact_req;

void occ_ac_request_compact(void)
{
	g_compact_req = 1;
}

int occ_orch_compact_take(void)
{
	int v = g_compact_req;

	g_compact_req = 0;
	return v;
}

/* 两级蒸馏第二级：关键实体清单（goal+brief 内引号串=acceptance/
 * fileset 实体）——第一级报告摘要已由 task 工具 read_result 进主
 * 上下文。仅 done 态；幂等（已有 distill 事件返回 NULL）。
 * 副作用：occ_task_distill 审计事件 + child 会话 archived +
 * SME 记忆条目（尽力，失败不阻塞）。返回蒸馏文（调用方 free）。 */
char *occ_orch_distill(occ_db *db, const char *task_id)
{
	occ_task_row row;
	occ_task_event_row *evs = NULL;
	size_t nevs = 0, i, o = 0;
	char err[192], *out;
	int already = 0;

	if (!db || !task_id || !task_id[0])
		return NULL;
	if (occ_task_get(db, task_id, &row, err, sizeof(err)) != 1)
		return NULL;
	if (strcmp(row.status, OCC_TASK_ST_DONE) != 0)
		return NULL;
	if (occ_task_events(db, task_id, &evs, &nevs, NULL, 0) == 0) {
		for (i = 0; i < nevs; i++)
			if (!strcmp(evs[i].kind, OCC_TASK_EV_DISTILL))
				already = 1;
		occ_task_event_rows_free(evs, nevs);
	}
	if (already) {
		occ_task_row_free(&row);
		return NULL;
	}

	out = malloc(2048);
	if (!out) {
		occ_task_row_free(&row);
		return NULL;
	}
	{
		/* goal 无独立列——从 brief_json 提取（工具面组包，无内嵌引号） */
		const char *g = strstr(row.brief_json ? row.brief_json : "",
				       "\"goal\":\"");
		char gbuf[224];

		gbuf[0] = '\0';
		if (g) {
			size_t gl;

			g += 8;
			gl = strcspn(g, "\"");
			if (gl > 200)
				gl = 200;
			/* R6：200 字节上限若落在多字节序列中间，回退到
			 * 字符边界（原按字节腰斩——distill payload 落库
			 * 即非法 UTF-8，严格解码方首读即炸） */
			while (gl > 0 && ((unsigned char)g[gl] & 0xC0) == 0x80)
				gl--;
			memcpy(gbuf, g, gl);
			gbuf[gl] = '\0';
		}
		o += (size_t)snprintf(out + o, 2048 - o,
				      L_("【任务蒸馏 %s】\n目标：%s\n"
					"关键实体：\n"), row.id,
				      gbuf[0] ? gbuf : L_("(brief 缺 goal)"));
	}
	/* brief_json 引号串实体扫描（acceptance/fileset 路径与 md5——
	 * 简扫描不处理转义：实体为路径/hex/断言串，工程上无内嵌引号） */
	{
		const char *p = row.brief_json;

		while (p && *p && o < 1600) {
			const char *q = strchr(p + 1, '"');

			if (*p != '"') {
				p = q;
				continue;
			}
			if (q && q - p > 2) {
				char ent[224];

				/* R6：原 %.160s 按字节截断腰斩多字节字符
				 * （复跑 B 任务 distill 事件 7 处非法
				 * UTF-8）——同文件 utf8_trunc 字符边界
				 * 裁剪后输出（≤160 字节，实体行恒合法） */
				utf8_trunc(p + 1, 160, ent, sizeof(ent));
				o += (size_t)snprintf(out + o, 2048 - o,
						      "- %s\n", ent);
			}
			p = q;
		}
	}
	o += (size_t)snprintf(out + o, 2048 - o,
			      L_("（子会话 %s 已归档；完整报告走 read_result）\n"),
			      row.child_session[0] ? row.child_session : "-");
	(void)occ_task_distill(db, task_id, out, err, sizeof(err));
	if (row.child_session[0])
		(void)occ_session_set_status(db, row.child_session,
					     OCC_ST_ARCHIVED, err,
					     sizeof(err));
	/* E6：蒸馏条目入 t:<task_id> 任务层（随任务归档域） */
	if (occ_sme_enabled()) {
		char lay[96];

		snprintf(lay, sizeof(lay), "t:%.80s", row.id);
		(void)occ_sme_remember_ex(
			row.parent_session[0] ? row.parent_session : task_id,
			"task 蒸馏", out, lay, "ok");
	}
	occ_task_row_free(&row);
	return out;
}
