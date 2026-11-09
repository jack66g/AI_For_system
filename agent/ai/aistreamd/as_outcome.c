/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_outcome.c - I-10 决策闭环第 4 步 outcome 回填器实现（C3，默认关）
 *
 * 三段（设计 §4 草图）：
 *   tap   EVENT policy → decisions 反查 → 表命中 → 快照基线 → pending 队
 *   tick  窗口到期 → 重读指标 → delta → 分类（§4.3）→ 写
 *         /sys/kernel/ai/policy/outcome → decisions 自校验 → 合成事件
 *   失败  -ENOENT→notfound（环覆盖/重启，不重试）；指标源读失败→
 *         PARTIAL+delta=0+meas_fail（不装 FAILED）；队满丢旧（洪泛截流）
 *
 * 风险定级（§4.6）：读=既有只读面（C1）；EVENT=既有订阅（C2）；
 * 写 policy/outcome=内核纯注记（C3——本模块的全部写面，无其他）。
 * outcome_auto_rollback（C4）不在本模块实现（conf 接收+journal 提示）。
 *
 * L1 无 AIKernel 内核（/sys/kernel/ai 不在）——单测与 L1 冒烟经
 * as_outcome_set_root 覆盖 mock 树；真内核 qemu 轮移交 K3C §9-1。
 */
#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "as_outcome.h"
#include "as_util.h"

/* ---- 写口（0200 root；内核纯注记——ai_sysfs.c ai_outcome_store） ---- */
#define AS_OC_SUB_OUTCOME	"/sys/kernel/ai/policy/outcome"
/* ---- 读面（全部既有；root 前缀可换 mock 树） ---- */
#define AS_OC_SUB_DECISIONS	"/proc/ai/decisions"
#define AS_OC_SUB_CONTROL	"/proc/ai/control"
#define AS_OC_SUB_WS_LABELS	"/proc/ai/ws_labels"
#define AS_OC_SUB_AI_ACTIONS	"/sys/kernel/ai/stats/ai_actions"
#define AS_OC_SUB_DEC_TOTAL	"/sys/kernel/ai/stats/decisions_total"
#define AS_OC_SUB_VMSTAT	"/proc/vmstat"
#define AS_OC_SUB_NETSTAT	"/proc/net/netstat"
#define AS_OC_SUB_PRESSURE	"/proc/pressure/"
#define AS_OC_SUB_BDI		"/sys/class/bdi"
#define AS_OC_SUB_NETDEV	"/sys/class/net/"
#define AS_OC_SUB_CPUBASE	"/sys/devices/system/cpu"

/* ====================================================================
 * metric 表（设计 §3 全 28 行；unit=metric_delta 量纲——内核不解释，
 * 本表即文档。dir=数值类方向；threshold=噪声带（带内=PARTIAL））
 * ==================================================================== */
const struct as_oc_row as_oc_rows[] = {
	/* ---- SCHED（§3.1） ---- */
	{ "sched.nice", OC_K_TASK_SCHED_DELAY, NULL, 0, AS_OC_DIR_UP, 1,
	  "ms", AS_OC_F_TASK },
	{ "sched.affinity", OC_K_MATCH_AFFINITY, NULL, 0, 0, 1,
	  "match(-1..1)", AS_OC_F_TASK },
	{ "sched.oom_score", OC_K_TASK_OOMADJ, NULL, 0, AS_OC_DIR_UP, 1,
	  "oom_score_adj", AS_OC_F_TASK | AS_OC_F_SCENARIO |
	  AS_OC_F_READBACK },
	{ "sched.timeslice", OC_K_PSI_CPU, NULL, 1, AS_OC_DIR_INTENT, 200,
	  "centi-percent-avg10", 0 },
	{ "ai.decision_sched", OC_K_DECISIONS_TOTAL, NULL, 0, AS_OC_DIR_UP, 1,
	  "decisions", 0 },
	/* ---- MM（§3.2） ---- */
	{ "mm.swappiness", OC_K_PSI_MEM, NULL, 1, AS_OC_DIR_UP, 200,
	  "centi-percent-avg10", 0 },
	{ "mm.readahead", OC_K_BDI_RA_PAGES, NULL, 0, AS_OC_DIR_UP, 1,
	  "KB(ra_pages)", AS_OC_F_READBACK },
	{ "mm.thp", OC_K_VMSTAT_RATE, "thp_fault_alloc,thp_cow_fault", 1,
	  AS_OC_DIR_UP, 1, "events/s", 0 },
	{ "mm.reclaim_prio", OC_K_AI_ACT_GAUGE, "vfs_cache_pressure", 1,
	  AS_OC_DIR_UP, 1, "vfs_cache_pressure", AS_OC_F_READBACK },
	{ "ai.decision_oom", OC_K_DECISIONS_TOTAL, NULL, 0, AS_OC_DIR_UP, 1,
	  "decisions", 0 },
	{ "ai.decision_mm", OC_K_DECISIONS_TOTAL, NULL, 0, AS_OC_DIR_UP, 1,
	  "decisions", 0 },
	/* ---- IO（§3.3） ---- */
	{ "io.priority", OC_K_CONTROL_CURRENT, NULL, 0, AS_OC_DIR_UP, 1,
	  "ioprio", AS_OC_F_TASK | AS_OC_F_READBACK },
	{ "io.bandwidth", OC_K_BDI_MAX_RATIO, NULL, 1, AS_OC_DIR_UP, 1,
	  "percent(max_ratio)", AS_OC_F_READBACK },
	/* ---- NET（§3.4） ---- */
	{ "net.cwnd", OC_K_TCPEXT_RATE, "TcpRetransSegs", 0,
	  AS_OC_DIR_INTENT, 1, "segs/s", 0 },
	{ "net.rto", OC_K_TCPEXT_RATE, "TCPTimeouts", 0,
	  AS_OC_DIR_INTENT, 1, "events/s", 0 },
	{ "net.qdisc", OC_K_MATCH_QDISC, "eth0", 0, 0, 1,
	  "match(-1..1)", 0 },
	{ "net.nftables", OC_K_AI_ACT_RATE, "netfilter_pkts", 0,
	  AS_OC_DIR_UP, 1, "events/s", 0 },
	/* ---- SECURITY（§3.5） ---- */
	{ "sec.lsm_override", OC_K_AI_ACT_GAUGE, "lsm_enforce", 0,
	  AS_OC_DIR_UP, 0, "lsm_enforce", AS_OC_F_READBACK },
	{ "sec.seccomp", OC_K_RESERVED, NULL, 0, 0, 0, "-", 0 },
	{ "sec.audit", OC_K_AI_ACT_GAUGE, "audit_capture", 0,
	  AS_OC_DIR_UP, 0, "audit_capture", AS_OC_F_READBACK },
	{ "sec.ws_label", OC_K_MATCH_WS_LABEL, NULL, 0, 0, 1,
	  "match(-1..1)", AS_OC_F_TASK },
	{ "ai.decision_inject", OC_K_DECISIONS_TOTAL, NULL, 0,
	  AS_OC_DIR_UP, 1, "decisions", 0 },
	/* ---- POWER（§3.6） ---- */
	{ "power.freq", OC_K_CPUFREQ_MEAN, NULL, 0, AS_OC_DIR_UP, 1000,
	  "kHz", 0 },
	{ "power.cstate", OC_K_CPUIDLE_DEEP_US, NULL, 1, AS_OC_DIR_UP, 1000,
	  "us", 0 },
	{ "power.wakeup", OC_K_AI_ACT_RATE, "wakeup_events", 0,
	  AS_OC_DIR_UP, 1, "events/s", 0 },
	/* ---- PROC（§3.7） ---- */
	{ "proc.signal", OC_K_MATCH_SIGNAL, NULL, 0, 0, 1,
	  "match(-1..1)", AS_OC_F_TASK },
	{ "proc.freeze", OC_K_MATCH_FREEZE, NULL, 0, 0, 1,
	  "cpu-ms", AS_OC_F_TASK },
	{ "proc.rlimit", OC_K_TASK_LIMITS_SOFT, NULL, 0, AS_OC_DIR_UP, 1,
	  "soft-limit", AS_OC_F_TASK | AS_OC_F_READBACK },
};

const size_t as_oc_rows_n = sizeof(as_oc_rows) / sizeof(as_oc_rows[0]);

int as_oc_row_lookup(const char *param)
{
	if (!param || !param[0])
		return -1;
	for (size_t i = 0; i < as_oc_rows_n; i++)
		if (strcmp(as_oc_rows[i].param, param) == 0)
			return (int)i;
	return -1;
}

/* ====================================================================
 * 小工具：路径拼接 / 文件读
 * ==================================================================== */

/* root 归一（init/set_root 保证无尾部 '/'，"/" 除外）；sub 以 '/' 开头 */
static void mkpath(char *buf, size_t cap, const char *root, const char *sub)
{
	if (!root || !root[0] || (root[0] == '/' && root[1] == '\0'))
		snprintf(buf, cap, "%s", sub);
	else
		snprintf(buf, cap, "%s%s", root, sub);
}

static void mkpath_fmt(char *buf, size_t cap, const char *root,
		       const char *fmt, ...)
{
	char sub[320];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(sub, sizeof(sub), fmt, ap);
	va_end(ap);
	mkpath(buf, cap, root, sub);
}

/* 小文件全读（vmstat/netstat/ai_actions/pressure/pid 文件；不含 decisions） */
static int read_all(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, cap - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	/* n==0：空文件合法（如空 ws_labels 列表）——内容由各 reader 校验 */
	return 0;
}

/* 单数值文件（"%lld\n" 形态） */
static int read_ll(const char *path, long long *out)
{
	char buf[128];

	if (read_all(path, buf, sizeof(buf)) != 0)
		return -1;
	return sscanf(buf, "%lld", out) == 1 ? 0 : -1;
}

/* 整数除法四舍五入（避免 -lm） */
static long long rdiv(long long a, long long b)
{
	if (b <= 0)
		return a;
	if (a >= 0)
		return (a + b / 2) / b;
	return -((-a + b / 2) / b);
}

static int sgn(long long v)
{
	return v > 0 ? 1 : (v < 0 ? -1 : 0);
}

static long long clk_tck(void)
{
	long v = sysconf(_SC_CLK_TCK);

	return v > 0 ? v : 100;
}

/* ====================================================================
 * 指标源读取（每 kind 一个 reader；返回 0/-1，值语义见 as_oc_snapshot）
 * ==================================================================== */

/* /proc/pressure/<res> some avg10 → 厘（×100 整数） */
static int rd_psi(const char *root, const char *res, long long *out)
{
	char path[384], buf[512];
	double v;

	mkpath_fmt(path, sizeof(path), root, "%s%s", AS_OC_SUB_PRESSURE, res);
	if (read_all(path, buf, sizeof(buf)) != 0)
		return -1;
	/* 首行 "some avg10=0.00 avg60=.. avg300=.. total=.." */
	if (sscanf(buf, "some avg10=%lf", &v) != 1)
		return -1;
	*out = (long long)(v * 100.0 + (v >= 0 ? 0.5 : -0.5));
	return 0;
}

/* /proc/vmstat 多键求和（key 逗号分隔） */
static int rd_vmstat_sum(const char *root, const char *keys, long long *out)
{
	char path[320], buf[8192], want[3][48];
	int nw = 0;

	{
		char ks[128];

		snprintf(ks, sizeof(ks), "%s", keys);
		for (char *tok = strtok(ks, ","); tok && nw < 3;
		     tok = strtok(NULL, ","))
			snprintf(want[nw++], sizeof(want[0]), "%s", tok);
	}
	mkpath(path, sizeof(path), root, AS_OC_SUB_VMSTAT);
	if (read_all(path, buf, sizeof(buf)) != 0)
		return -1;
	*out = 0;
	/* strtok 嵌套规避：逐行手扫 */
	{
		char *p = buf;

		for (;;) {
			char *nl = strchr(p, '\n');
			char k[64];
			long long v;

			if (sscanf(p, "%63s %lld", k, &v) == 2) {
				for (int i = 0; i < nw; i++)
					if (strcmp(k, want[i]) == 0) {
						*out += v;
						break;
					}
			}
			if (!nl)
				break;
			p = nl + 1;
		}
	}
	return 0;
}

/* /proc/net/netstat TcpExt 键值（"TcpExt: k1 k2.." / "TcpExt: v1 v2.."） */
static int rd_tcpext(const char *root, const char *key, long long *out)
{
	char path[320], buf[8192];
	char names[8192], vals[8192];
	int got = 0;
	char *p = buf;

	mkpath(path, sizeof(path), root, AS_OC_SUB_NETSTAT);
	if (read_all(path, buf, sizeof(buf)) != 0)
		return -1;
	names[0] = '\0';
	vals[0] = '\0';
	while (got < 2) {
		char *nl = strchr(p, '\n');

		if (strncmp(p, "TcpExt:", 7) == 0) {
			size_t n = nl ? (size_t)(nl - p) : strlen(p);

			if (got == 0) {
				memcpy(names, p + 7, n > 7 ? n - 7 : 0);
				names[n > 7 ? n - 7 : 0] = '\0';
			} else {
				memcpy(vals, p + 7, n > 7 ? n - 7 : 0);
				vals[n > 7 ? n - 7 : 0] = '\0';
			}
			got++;
		}
		if (!nl)
			break;
		p = nl + 1;
	}
	if (got != 2)
		return -1;
	{
		char *save1 = NULL, *save2 = NULL;

		for (char *tok = strtok_r(names, " \t", &save1), *val =
		     strtok_r(vals, " \t", &save2); tok && val;
		     tok = strtok_r(NULL, " \t", &save1), val =
		     strtok_r(NULL, " \t", &save2)) {
			if (strcmp(tok, key) == 0) {
				*out = atoll(val);
				return 0;
			}
		}
	}
	return -1;
}

/* /sys/kernel/ai/stats/ai_actions 键（"key: value" 多行） */
static int rd_ai_actions(const char *root, const char *key, long long *out)
{
	char path[384], buf[2048];
	size_t klen = strlen(key);
	char *p = buf;

	mkpath(path, sizeof(path), root, AS_OC_SUB_AI_ACTIONS);
	if (read_all(path, buf, sizeof(buf)) != 0)
		return -1;
	for (;;) {
		char *nl = strchr(p, '\n');

		if (strncmp(p, key, klen) == 0 && p[klen] == ':' &&
		    p[klen + 1] == ' ') {
			char *vs = p + klen + 2;
			long long v;

			if (sscanf(vs, "%lld", &v) == 1) {
				*out = v;
				return 0;
			}
			return -1;
		}
		if (!nl)
			break;
		p = nl + 1;
	}
	return -1;
}

/* /proc/ai/control 本旋钮 current 读回（mm.swappiness 等不落 /proc/sys/vm
 * ——内核门控访问器，设计 §7.8：以本面为准，避免双源歧义） */
static int rd_control_current(const char *root, const char *param,
			      long long *out)
{
	char path[320], buf[16384], pfx[64];
	size_t plen;
	char *p = buf;

	mkpath(path, sizeof(path), root, AS_OC_SUB_CONTROL);
	if (read_all(path, buf, sizeof(buf)) != 0)
		return -1;
	snprintf(pfx, sizeof(pfx), "%s ", param);
	plen = strlen(pfx);
	for (;;) {
		char *nl = strchr(p, '\n');
		size_t ln = nl ? (size_t)(nl - p) : strlen(p);
		char line[512];

		if (ln < sizeof(line)) {
			memcpy(line, p, ln);
			line[ln] = '\0';
			if (strncmp(line, pfx, plen) == 0) {
				const char *cur = strstr(line + plen,
							 "current=");

				if (!cur)
					return -1;
				*out = atoll(cur + 8);
				return 0;
			}
		}
		if (!nl)
			break;
		p = nl + 1;
	}
	return -1;
}

/* /sys/class/bdi/<名>/…：取字典序最小 bdi（确定性；io.* 旋钮写全 bdi，
 * 读回取其一——同名文件同值，报告如实注明） */
static int rd_bdi(const char *root, const char *leaf, long long *out)
{
	char dirp[320], best[128] = "", path[448];
	DIR *d;
	struct dirent *e;

	mkpath(dirp, sizeof(dirp), root, AS_OC_SUB_BDI);
	d = opendir(dirp);
	if (!d)
		return -1;
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.')
			continue;
		if (!best[0] || strcmp(e->d_name, best) < 0)
			snprintf(best, sizeof(best), "%.127s", e->d_name);
	}
	closedir(d);
	if (!best[0])
		return -1;
	mkpath_fmt(path, sizeof(path), root, "%s/%s/%s", AS_OC_SUB_BDI, best,
		   leaf);
	return read_ll(path, out);
}

/* cpufreq 全 cpu scaling_cur_freq 均值（kHz；无 cpufreq 的 cpu 跳过） */
static int rd_cpufreq_mean(const char *root, long long *out)
{
	long long sum = 0;
	int n = 0;

	for (int cpu = 0; cpu < 256; cpu++) {
		char path[448];
		long long v;

		mkpath_fmt(path, sizeof(path), root,
			   "%s/cpu%d/cpufreq/scaling_cur_freq",
			   AS_OC_SUB_CPUBASE, cpu);
		if (read_ll(path, &v) != 0)
			continue;
		sum += v;
		n++;
	}
	if (n == 0)
		return -1;
	*out = sum / n;
	return 0;
}

/* cpuidle 深态（state1+）time 之和（us） */
static int rd_cpuidle_deep(const char *root, long long *out)
{
	long long sum = 0;

	*out = 0;
	for (int cpu = 0; cpu < 256; cpu++) {
		for (int st = 1; st < 10; st++) {
			char path[448];
			long long v;

			mkpath_fmt(path, sizeof(path), root,
				   "%s/cpu%d/cpuidle/state%d/time",
				   AS_OC_SUB_CPUBASE, cpu, st);
			if (read_ll(path, &v) != 0)
				break;		/* 该 cpu state 列举尽 */
			sum += v;
		}
	}
	*out = sum;
	return 0;
}

/* /proc/<pid>/stat：剥 comm（含空格/括号）取 after-')' 文本（state 起） */
static int rd_task_stat(const char *root, int32_t pid, char *after,
			size_t aftercap)
{
	char path[320], buf[1024];
	char *rp;

	mkpath_fmt(path, sizeof(path), root, "/proc/%d/stat", pid);
	if (read_all(path, buf, sizeof(buf)) != 0)
		return -1;
	rp = strrchr(buf, ')');
	if (!rp || rp[1] != ' ')
		return -1;
	rp += 2;
	snprintf(after, aftercap, "%s", rp);
	return after[0] ? 0 : -1;
}

/* after-')' token 下标（state=0；utime=11、stime=12——proc(5) 字段号 N
 * 对应 token N-3；nice=字段19→token16 不用，读回走 schedstat 路线） */
static int stat_token(const char *after, int idx, long long *out)
{
	char tmp[1024];
	char *save = NULL;
	int i = 0;

	snprintf(tmp, sizeof(tmp), "%s", after);
	for (char *tok = strtok_r(tmp, " ", &save); tok;
	     tok = strtok_r(NULL, " ", &save), i++) {
		if (i == idx) {
			*out = atoll(tok);
			return 0;
		}
	}
	return -1;
}

/* /proc/<pid>/schedstat 第 2 列（run 等待 ns）→ ms（taskstats cpu_delay
 * 的标准文件同源替代，设计 §3 sched.nice 行） */
static int rd_task_sched_delay(const char *root, int32_t pid, long long *ms)
{
	char path[320], buf[256];
	long long a, b, c;

	mkpath_fmt(path, sizeof(path), root, "/proc/%d/schedstat", pid);
	if (read_all(path, buf, sizeof(buf)) != 0)
		return -1;
	if (sscanf(buf, "%lld %lld %lld", &a, &b, &c) != 3)
		return -1;
	*ms = rdiv(b, 1000000);
	return 0;
}

/* /proc/<pid>/limits 第 res 行 soft 列（行尾三 token：… soft hard units） */
static int rd_task_limits_soft(const char *root, int32_t pid, int res,
			       long long *out)
{
	char path[320];
	FILE *f;
	int lineno = 0;

	if (res < 0)
		return -1;
	mkpath_fmt(path, sizeof(path), root, "/proc/%d/limits", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;
	{
		char line[512];
		int found = 0;

		while (!found && fgets(line, sizeof(line), f))
			if (lineno++ == res)
				found = 1;
		fclose(f);
		if (!found)
			return -1;
		{
			char tmp[512], *save = NULL;
			char *l3[3] = { NULL, NULL, NULL };
			int m = 0;

			snprintf(tmp, sizeof(tmp), "%s", line);
			for (char *t = strtok_r(tmp, " \t\n", &save); t;
			     t = strtok_r(NULL, " \t\n", &save)) {
				l3[0] = l3[1];
				l3[1] = l3[2];
				l3[2] = t;
				m++;
			}
			if (m >= 3 && l3[0]) {
				if (strcmp(l3[0], "unlimited") == 0)
					return -1;	/* 非数值如实拒 */
				*out = atoll(l3[0]);
				return 0;
			}
		}
	}
	return -1;
}

/* /proc/<pid>/status 键值行（如 Cpus_allowed_list） */
static int rd_task_status(const char *root, int32_t pid, const char *key,
			  char *out, size_t outcap)
{
	char path[320], kpfx[64];
	size_t klen;
	FILE *f;

	mkpath_fmt(path, sizeof(path), root, "/proc/%d/status", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;
	snprintf(kpfx, sizeof(kpfx), "%s:", key);
	klen = strlen(kpfx);
	{
		char line[512];
		int found = 0;

		while (!found && fgets(line, sizeof(line), f)) {
			if (strncmp(line, kpfx, klen) == 0) {
				char *v = line + klen;
				size_t l;

				while (*v == ' ' || *v == '\t')
					v++;
				l = strlen(v);
				while (l > 0 && (v[l - 1] == '\n' ||
						 v[l - 1] == '\r'))
					v[--l] = '\0';
				snprintf(out, outcap, "%s", v);
				found = 1;
			}
		}
		fclose(f);
		if (!found || !out[0])
			return -1;
	}
	return 0;
}

/* qdisc 名（/sys/class/net/<dev>/qdisc——RTM_GETQDISC 同源标准面；
 * 注入值映射 0=回滚 1=codel 2=fq 3=fq_codel，设计 §3.4） */
static int rd_qdisc_match(const char *root, const char *dev, long long injected,
			  int *ok, int *no_expect)
{
	char path[384], buf[256], got[64];
	const char *want;

	*ok = 0;
	*no_expect = 0;
	switch (injected) {
	case 1:	want = "codel";		break;
	case 2:	want = "fq";		break;
	case 3:	want = "fq_codel";	break;
	default:
		*no_expect = 1;	/* 0=回滚/未知：无期望态 → PARTIAL */
		return 0;
	}
	mkpath_fmt(path, sizeof(path), root, "%s%s/qdisc", AS_OC_SUB_NETDEV,
		   dev);
	if (read_all(path, buf, sizeof(buf)) != 0)
		return -1;
	if (sscanf(buf, "%63s", got) != 1)
		return -1;
	*ok = strcmp(got, want) == 0;
	return 0;
}

/* /proc/ai/ws_labels："<pid> <label> <comm>" 行存在（label 非 0 才列） */
static int rd_ws_label_match(const char *root, int32_t pid, long long label,
			     int *ok)
{
	char path[320], want[64], buf[16384];

	*ok = 0;
	mkpath(path, sizeof(path), root, AS_OC_SUB_WS_LABELS);
	if (read_all(path, buf, sizeof(buf)) != 0)
		return -1;
	snprintf(want, sizeof(want), "%d %lld ", pid, (long long)label);
	for (char *line = strtok(buf, "\n"); line; line = strtok(NULL, "\n"))
		if (strncmp(line, want, strlen(want)) == 0) {
			*ok = 1;
			return 0;
		}
	return 0;
}

/* proc.signal 期望态（§3.7：19→T；18→非 T；9/15→消亡；其余无期望） */
static int rd_signal_match(const char *root, int32_t pid, long long sig,
			   int *ok, int *no_expect)
{
	char after[1024];

	*ok = 0;
	*no_expect = 0;
	switch (sig) {
	case 19:
		if (rd_task_stat(root, pid, after, sizeof(after)) != 0)
			return 0;	/* 已消亡：非 T（未达成，如实） */
		*ok = after[0] == 'T';
		return 0;
	case 18:
		if (rd_task_stat(root, pid, after, sizeof(after)) != 0)
			return 0;
		*ok = after[0] != 'T';
		return 0;
	case 9:
	case 15:
		if (rd_task_stat(root, pid, after, sizeof(after)) != 0)
			*ok = 1;	/* 期望消亡：读失败即达成 */
		return 0;
	default:
		*no_expect = 1;
		return 0;
	}
}

static int rd_freeze_match(const char *root, int32_t pid, long long injected,
			   int *ok, long long *cpu_ticks)
{
	char after[1024];
	long long ut = 0, st = 0;

	*ok = 0;
	*cpu_ticks = 0;
	if (rd_task_stat(root, pid, after, sizeof(after)) != 0)
		return -1;
	stat_token(after, 11, &ut);
	stat_token(after, 12, &st);
	*cpu_ticks = ut + st;
	*ok = ((injected != 0) == (after[0] == 'T'));
	return 0;
}

/* ====================================================================
 * as_oc_snapshot - 统一快照（arm/fill 共用）
 * out[0]=主指标值 / match 期望态成立位（无期望态=-1）；out[1]=辅助
 * （freeze：utime+stime 累计 tick）。
 * ==================================================================== */
int as_oc_snapshot(const char *root, const struct as_oc_row *row, int32_t pid,
		   unsigned long long injected, const unsigned long long data[8], long long out[2])
{
	int ok = 0, no_expect = 0;

	out[0] = 0;
	out[1] = 0;
	if (!row || !root || !root[0])
		return -1;
	switch (row->kind) {
	case OC_K_PSI_CPU:
		return rd_psi(root, "cpu", &out[0]);
	case OC_K_PSI_MEM:
		return rd_psi(root, "memory", &out[0]);
	case OC_K_PSI_IO:
		return rd_psi(root, "io", &out[0]);
	case OC_K_VMSTAT_RATE:
		return rd_vmstat_sum(root, row->key, &out[0]);
	case OC_K_TCPEXT_RATE:
		return rd_tcpext(root, row->key, &out[0]);
	case OC_K_AI_ACT_RATE:
	case OC_K_AI_ACT_GAUGE:
		return rd_ai_actions(root, row->key, &out[0]);
	case OC_K_DECISIONS_TOTAL: {
		char path[384];

		mkpath(path, sizeof(path), root, AS_OC_SUB_DEC_TOTAL);
		return read_ll(path, &out[0]);
	}
	case OC_K_CONTROL_CURRENT:
		return rd_control_current(root, row->param, &out[0]);
	case OC_K_BDI_RA_PAGES:
		return rd_bdi(root, "ra_pages", &out[0]);
	case OC_K_BDI_MAX_RATIO:
		return rd_bdi(root, "max_ratio", &out[0]);
	case OC_K_CPUFREQ_MEAN:
		return rd_cpufreq_mean(root, &out[0]);
	case OC_K_CPUIDLE_DEEP_US:
		return rd_cpuidle_deep(root, &out[0]);
	case OC_K_TASK_SCHED_DELAY:
		return rd_task_sched_delay(root, pid, &out[0]);
	case OC_K_TASK_OOMADJ: {
		char path[320];

		mkpath_fmt(path, sizeof(path), root, "/proc/%d/oom_score_adj",
			   pid);
		return read_ll(path, &out[0]);
	}
	case OC_K_TASK_LIMITS_SOFT:
		return rd_task_limits_soft(root, pid,
					   (int)(data ? data[2] : 0), &out[0]);
	case OC_K_MATCH_AFFINITY: {
		char v[128], want[32];

		if (rd_task_status(root, pid, "Cpus_allowed_list", v,
				   sizeof(v)) != 0)
			return -1;
		snprintf(want, sizeof(want), "%lld", (long long)injected);
		out[0] = (long long)strcmp(v, want) == 0;
		return 0;
	}
	case OC_K_MATCH_QDISC:
		if (rd_qdisc_match(root, row->key ? row->key : "eth0",
				   (long long)injected, &ok, &no_expect) != 0)
			return -1;
		out[0] = no_expect ? -1 : (long long)ok;
		return 0;
	case OC_K_MATCH_WS_LABEL:
		if (rd_ws_label_match(root, pid, (long long)injected, &ok) != 0)
			return -1;
		out[0] = (long long)ok;
		return 0;
	case OC_K_MATCH_SIGNAL:
		if (rd_signal_match(root, pid, (long long)injected, &ok,
				    &no_expect) != 0)
			return -1;
		out[0] = no_expect ? -1 : (long long)ok;
		return 0;
	case OC_K_MATCH_FREEZE:
		if (rd_freeze_match(root, pid, (long long)injected, &ok,
				    &out[1]) != 0)
			return -1;
		out[0] = (long long)ok;
		return 0;
	case OC_K_RESERVED:
	default:
		return -1;
	}
}

/* ====================================================================
 * 分类（纯函数；单测冻结口径）
 * ==================================================================== */

int as_oc_intent(long long injected, long long before)
{
	if (injected > before)
		return 1;
	if (injected < before)
		return -1;
	return 0;
}

/* 速率类 delta=（差值/窗口秒）四舍五入；其余原差 */
static long long oc_delta_of(const struct as_oc_row *row, long long base,
			     long long now, int window_sec)
{
	switch (row->kind) {
	case OC_K_VMSTAT_RATE:
	case OC_K_TCPEXT_RATE:
	case OC_K_AI_ACT_RATE:
		return rdiv(now - base, window_sec > 0 ? window_sec : 1);
	default:
		return now - base;
	}
}

struct as_oc_class as_oc_classify_num(const struct as_oc_row *row,
				      long long injected, long long before,
				      int has_before, long long base,
				      long long now, int window_sec)
{
	struct as_oc_class c;
	long long delta;
	int intent;

	memset(&c, 0, sizeof(c));
	c.outcome = AS_OC_PARTIAL;
	c.delta = 0;

	if (!has_before) {
		/* U66：意图基线 pre= 不可得（none/#65 旧行/环淘汰）——
		 * 如实 PARTIAL+pre_none（非 meas_fail：指标源未失败；
		 * delta 照算——base/now 可得时仍有意义）。恒等决策
		 * no-op→PARTIAL 的诚实判定语义保留（成因不可分辨，
		 * 统一按基线不可得降级，报告 §1 有述） */
		c.pre_none = 1;
		c.delta = oc_delta_of(row, base, now, window_sec);
		return c;
	}
	delta = oc_delta_of(row, base, now, window_sec);
	c.delta = delta;
	intent = as_oc_intent(injected, before);
	if (intent == 0) {
		c.noop = 1;		/* 无操作对照：值未变（§5.3） */
		return c;
	}
	if (llabs(delta) <= (long long)row->threshold)
		return c;		/* 带内：无效果证据 ≠ 变好（PARTIAL） */
	if (row->dir == AS_OC_DIR_INTENT)
		c.outcome = AS_OC_SUCCESS;	/* 权衡型：出带即生效（§3） */
	else if (sgn(delta) == row->dir * intent)
		c.outcome = AS_OC_SUCCESS;
	else
		c.outcome = AS_OC_WORSE;
	/* 效果类需场景（§3 oom_score 行）：读回变化≠效果——如实降 PARTIAL */
	if ((row->flags & AS_OC_F_SCENARIO) && c.outcome == AS_OC_SUCCESS)
		c.outcome = AS_OC_PARTIAL;
	return c;
}

int as_oc_sig_group(long long sig)
{
	switch (sig) {
	case 19:
		return 1;	/* stop（state T） */
	case 18:
		return 2;	/* cont（非 T） */
	case 9:
	case 15:
		return 3;	/* dead（读失败即达成，rd_signal_match） */
	default:
		return 0;	/* 无组（未知信号→no_expect 路） */
	}
}

int as_oc_match_base(enum as_oc_kind kind, long long injected, long long pre)
{
	switch (kind) {
	case OC_K_MATCH_AFFINITY:
	case OC_K_MATCH_QDISC:
	case OC_K_MATCH_WS_LABEL:
		/* 值域即状态域：pre==injected ⇔ 期望态决策前已成立。
		 * ws_label 无 read 回调 → pre 为全局表值（K66 §5
		 * fallback）：异 pid 同值连发保守判已成立→PARTIAL
		 * （宁漏报 SUCCESS 不虚报——报告 §1） */
		return pre == injected;
	case OC_K_MATCH_SIGNAL: {
		int gp = as_oc_sig_group(pre);

		/* pre（全局表值=上次信号号）与 injected 同状态组 ⇔
		 * 期望态大概率已成立（保守）；异组/无组=未成立 */
		return gp != 0 && gp == as_oc_sig_group(injected);
	}
	case OC_K_MATCH_FREEZE:
		/* pre=决策前 per-task 冻结位（read 回调真值） */
		return (pre != 0) == (injected != 0);
	default:
		return 0;
	}
}

struct as_oc_class as_oc_classify_match(const struct as_oc_row *row,
					int no_expect, int base_known,
					int base_ok, int now_ok,
					long long aux_base, long long aux_now)
{
	struct as_oc_class c;

	memset(&c, 0, sizeof(c));
	c.outcome = AS_OC_PARTIAL;
	c.delta = 0;
	if (no_expect) {
		c.no_expect = 1;
		return c;
	}
	if (row->kind == OC_K_MATCH_FREEZE)
		/* aux（CPU 累计 tick）与基线判定无关，恒可报 */
		c.delta = rdiv((aux_now - aux_base) * 1000, clk_tck());
	if (!base_known) {
		/* U66：pre= 不可得 → 迁移不可判——如实 PARTIAL+pre_none
		 * （freeze 的 aux delta 仍报） */
		c.pre_none = 1;
		return c;
	}
	if (row->kind != OC_K_MATCH_FREEZE)
		c.delta = (long long)now_ok - (long long)base_ok;
	if (now_ok && !base_ok)
		c.outcome = AS_OC_SUCCESS;
	else if (!now_ok && base_ok)
		c.outcome = AS_OC_WORSE;
	/* else：未达成且原本未成立（PARTIAL）/ 已成立且仍成立（无操作对照
	 * 天然 PARTIAL——§5.3 反假阳性口径） */
	return c;
}

const char *as_oc_outcome_name(int outcome)
{
	switch (outcome) {
	case AS_OC_SUCCESS:	return "SUCCESS";
	case AS_OC_PARTIAL:	return "PARTIAL";
	case AS_OC_WORSE:	return "WORSE";
	default:		return "UNKNOWN";
	}
}

/* ====================================================================
 * /proc/ai/decisions 反查（ai_proc_dec_record 格式逐字段对齐：
 * id/trig_ts/trig_evid(0x%04x)/dec_ts/type/data=8 段冒号/exec_ts/
 * outcome_ts/outcome/delta/ver/conf/domain/src/executed/safety_clamped
 * [+U66/#66 行尾 append-only pre=<…>——K66-REPORT §5 契约]）
 * ==================================================================== */

/*
 * oc_parse_pre - 行尾 pre= 字段解析（K66 §5 精确语法，容忍降级）：
 *   none → n=0；<s64>[:<s64>…]（1..8 项，handler 保存序）→ 逐项填；
 *   字段缺席（#65 旧行）/畸形 → n=0。主 23 字段已解析成功 → 本函数
 *   任何失败都不构成坏行（旧解析器兼容口径：行尾未知字段忽略）。
 */
static void oc_parse_pre(char *line, long long pre[8], int *n)
{
	char *p, *end;
	int k = 0;

	*n = 0;
	p = strstr(line, " pre=");
	if (!p)
		return;			/* #65 及之前：无此字段 */
	p += 5;
	if (strncmp(p, "none", 4) == 0 &&
	    (p[4] == '\0' || p[4] == '\n' || p[4] == '\r' || p[4] == ' '))
		return;			/* 无快照：恒等快路径/淘汰/已消费 */
	while (k < 8) {
		long long v;
		char sep;

		errno = 0;
		v = strtoll(p, &end, 10);
		if (end == p || errno != 0)
			return;		/* 畸形 → 按无基线（不坏行） */
		pre[k++] = v;
		sep = *end;
		if (sep == ':') {
			p = end + 1;
			continue;
		}
		if (sep == '\0' || sep == '\n' || sep == '\r' ||
		    sep == ' ') {
			*n = k;		/* 正常收尾 */
			return;
		}
		return;			/* 畸形尾随 → 按无基线 */
	}
	*n = k;				/* 8 项满（n=8 于容量截断，K66 §5） */
}

int as_oc_scan_decisions(const char *path, unsigned long long id, int scan_max,
			 struct as_oc_decision *out)
{
	FILE *f;
	char line[512];
	int n = 0;

	f = fopen(path, "r");
	if (!f)
		return -1;
	while (n < scan_max && fgets(line, sizeof(line), f)) {
		unsigned long long rid, t1, evid, t2, e1, ots;
		unsigned long long d[8];
		unsigned type, oc, ver, conf, dom, src, exec, sc;
		long long delta;

		n++;
		if (sscanf(line,
			   "id=%llu trig_ts=%llu trig_evid=%llx dec_ts=%llu "
			   "type=%u data=%llu:%llu:%llu:%llu:%llu:%llu:%llu:"
			   "%llu exec_ts=%llu outcome_ts=%llu outcome=%u "
			   "delta=%lld ver=%u conf=%u domain=%u src=%u "
			   "executed=%u safety_clamped=%u",
			   &rid, &t1, &evid, &t2, &type,
			   &d[0], &d[1], &d[2], &d[3], &d[4], &d[5], &d[6],
			   &d[7], &e1, &ots, &oc, &delta, &ver, &conf, &dom,
			   &src, &exec, &sc) != 23)
			continue;
		if (rid != id)
			continue;
		if (out) {
			memset(out, 0, sizeof(*out));
			out->id = rid;
			for (int i = 0; i < 8; i++)
				out->data[i] = d[i];
			out->domain = dom;
			out->executed = exec;
			out->outcome_ts = ots;
			/* U66：行尾 pre=（早读——快照环 64 决策/rollback
			 * 即消费，K66 §5「消费方应尽早读」；arm 反查即取） */
			oc_parse_pre(line, out->pre, &out->pre_n);
		}
		fclose(f);
		return 0;
	}
	fclose(f);
	return 1;
}

/* ====================================================================
 * 生命周期 / tap / tick
 * ==================================================================== */

int as_outcome_init(struct as_outcome *oc, struct as_conf *c,
		    struct as_stats *st)
{
	memset(oc, 0, sizeof(*oc));
	oc->conf = c;
	oc->stats = st;
	snprintf(oc->root, sizeof(oc->root), "/");
	st->oc.enabled = c->outcome_enabled ? 1 : 0;
	if (!c->outcome_enabled) {
		as_log("outcome backfill: disabled (OUTCOME_ENABLED=0) - "
		       "zero-overhead tap");
		return 0;
	}
	if (c->outcome_auto_rollback)
		as_warn_ratelimit("oc-c4", 3600000,
				  "OUTCOME_AUTO_ROLLBACK=1 acknowledged but "
				  "rollback write is NOT implemented (C4 "
				  "needs separate approval) - no rollback "
				  "will be written");
	oc->cap = (int)c->outcome_max_pending;
	oc->jobs = calloc((size_t)oc->cap, sizeof(*oc->jobs));
	if (!oc->jobs) {
		oc->cap = 0;
		return -1;
	}
	if (strcmp(c->outcome_mock_root, "/") != 0 &&
	    c->outcome_mock_root[0]) {
		char norm[256];

		snprintf(norm, sizeof(norm), "%s", c->outcome_mock_root);
		as_outcome_set_root(oc, norm);
		as_warn_ratelimit("oc-mockroot", 3600000,
				  "outcome backfill: MOCK ROOT %s "
				  "(TEST ONLY - not for production)",
				  oc->root);
	}
	as_log("outcome backfill: enabled (windows %llds/%llds grace=%llds "
	       "max_pending=%d scan_max=%lld write_sme=%d) - C3 annotation "
	       "only (policy/outcome)",
	       c->outcome_window_short_sec, c->outcome_window_long_sec,
	       c->outcome_grace_sec, oc->cap, c->outcome_decisions_scan_max,
	       c->outcome_write_sme);
	return 0;
}

void as_outcome_close(struct as_outcome *oc)
{
	if (oc->jobs) {
		free(oc->jobs);
		oc->jobs = NULL;
	}
	oc->cap = 0;
}

void as_outcome_set_root(struct as_outcome *oc, const char *root)
{
	snprintf(oc->root, sizeof(oc->root), "%s",
		 root && root[0] ? root : "/");
	{
		size_t l = strlen(oc->root);

		if (l > 1 && oc->root[l - 1] == '/')
			oc->root[l - 1] = '\0';
		if (!oc->root[0])
			snprintf(oc->root, sizeof(oc->root), "/");
	}
	as_log("outcome backfill: root prefix %s (TEST/mock path)", oc->root);
}

void as_outcome_set_sink(struct as_outcome *oc,
			 void (*emit)(struct as_event *ev, void *ud), void *ud)
{
	oc->emit = emit;
	oc->emit_ud = ud;
}

/* pending FIFO：队满丢最旧（§4.4 洪泛截流；丢弃计数） */
static void oc_push(struct as_outcome *oc, const struct as_oc_job *job)
{
	if (oc->count >= oc->cap) {
		oc->head = (oc->head + 1) % oc->cap;
		oc->count--;
		oc->dropped++;
		oc->stats->oc.dropped++;
		as_warn_ratelimit("oc-flood", 60000,
				  "outcome pending full - dropping oldest "
				  "(dropped=%lld)", oc->dropped);
	}
	oc->jobs[(oc->head + oc->count) % oc->cap] = *job;
	oc->count++;
}

static struct as_oc_job oc_pop(struct as_outcome *oc)
{
	struct as_oc_job j = oc->jobs[oc->head];

	oc->head = (oc->head + 1) % oc->cap;
	oc->count--;
	return j;
}

/* EVENT policy 行解析："decision_id=%llu executed=%d param=<至空格>"
 * （sev!=info 时行尾另有 " sev=…"——param 到空格即止，不受影响） */
static int oc_parse_policy_line(const char *line, unsigned long long *id,
				int *executed, char *param, size_t pcap)
{
	const char *p;

	if (sscanf(line, "[kern] event policy decision_id=%llu executed=%d",
		   id, executed) != 2)
		return -1;
	p = strstr(line, "param=");
	if (!p)
		return -1;
	p += 6;
	param[0] = '\0';
	for (size_t i = 0; p[i] && p[i] != ' ' && i < pcap - 1; i++) {
		param[i] = p[i];
		param[i + 1] = '\0';
	}
	return 0;
}

void as_outcome_tap(struct as_outcome *oc, const struct as_event *ev)
{
	struct as_oc_decision dec;
	struct as_oc_job job;
	const struct as_oc_row *row;
	char param[AS_OC_PARAM_MAX];
	char dpath[384];
	unsigned long long id;
	int executed, ridx, is_task;
	long long now;

	if (!oc || !oc->conf->outcome_enabled || !ev)
		return;
	if (ev->stream_idx != as_stream_idx(AS_STREAM_EVENT) ||
	    strcmp(ev->category, "policy") != 0 || !ev->has_decision_id)
		return;
	if (oc_parse_policy_line(ev->line, &id, &executed, param,
				 sizeof(param)) != 0)
		return;			/* 防御：不合形态（不计入任何桶） */

	if (!param[0]) {
		oc->stats->oc.skip_broadcast++;
		return;			/* 域广播：无法归因单一旋钮（§4.4） */
	}
	if (executed <= 0) {
		oc->stats->oc.skip_noexec++;
		return;			/* 内核已置 FAILED/UNKNOWN（§4.4） */
	}
	ridx = as_oc_row_lookup(param);
	if (ridx < 0) {
		oc->stats->oc.skip_unknown++;
		as_warn_ratelimit("oc-unknown", 60000,
				  "outcome: knob %s not in metric table - "
				  "skipped (skip_unknown=%lld)", param,
				  oc->stats->oc.skip_unknown);
		return;
	}
	row = &as_oc_rows[ridx];
	if (row->kind == OC_K_RESERVED) {
		oc->stats->oc.skip_reserved++;
		return;			/* sec.seccomp：不可注入生效（§3.5） */
	}

	/* decisions 反查（EVENT 载荷不带 domain/pid——设计 §7.9） */
	mkpath(dpath, sizeof(dpath), oc->root, AS_OC_SUB_DECISIONS);
	if (as_oc_scan_decisions(dpath, id,
				 (int)oc->conf->outcome_decisions_scan_max,
				 &dec) != 0) {
		/* 反查不到：截断/环覆盖/重启（§7.6）或文件不可读——均归
		 * notfound（如实，不重试风暴） */
		oc->stats->oc.notfound++;
		as_warn_ratelimit("oc-rev", 60000,
				  "outcome: decision %llu not in %s "
				  "(scan_max=%lld) - notfound=%lld",
				  id, dpath,
				  oc->conf->outcome_decisions_scan_max,
				  oc->stats->oc.notfound);
		return;
	}

	memset(&job, 0, sizeof(job));
	job.decision_id = id;
	snprintf(job.param, sizeof(job.param), "%s", param);
	job.row_idx = ridx;
	is_task = (row->flags & AS_OC_F_TASK) != 0;
	job.pid = is_task ? (int32_t)dec.data[0] : 0;
	job.injected = (long long)(is_task ? dec.data[1] : dec.data[0]);
	for (int i = 0; i < 8; i++)
		job.data[i] = dec.data[i];

	/* U66/A1：意图基线改取 decisions 行 pre=（F16 §2-1 根因——
	 * arm 时点 control current 已是注入值，before==injected 恒
	 * noop-PARTIAL；pre= 为决策前真值，K66-REPORT §5 契约）。
	 * pre=none/#65 旧行 → has_before=0 → fill 侧 PARTIAL+pre_none。 */
	job.has_before = dec.pre_n > 0;
	job.before = job.has_before ? dec.pre[0] : 0;

	/* 指标基线（U66 按行类分道）：
	 *  - 环境型（PSI/速率/延迟等）：arm 时点快照（execute 对其无
	 *    即时影响，T0=窗口起点）——失败仍入队：fill 侧如实 PARTIAL
	 *    +meas_fail，§4.4；
	 *  - 读回型（AS_OC_F_READBACK）：execute 即落地 → arm 快照恒等
	 *    注入值（结构性 delta=0）——基线取 pre（after−pre 口径），
	 *    has_base=has_before；
	 *  - match 型：base[0]=as_oc_match_base(pre)（pre 状态映射），
	 *    has_base=has_before；aux（freeze CPU tick）取 arm 快照
	 *    （累计计数器与 execute 无关，仍可用）。 */
	{
		long long sb[2] = { 0, 0 };
		int has_sb = as_oc_snapshot(oc->root, row, job.pid,
					    (unsigned long long)job.injected,
					    job.data, sb) == 0;

		if (row->kind >= OC_K_MATCH_AFFINITY &&
		    row->kind <= OC_K_MATCH_FREEZE) {
			job.has_base = job.has_before;
			job.base[0] = job.has_before ?
				as_oc_match_base(row->kind, job.injected,
						 dec.pre[0]) : 0;
			job.base[1] = sb[1];	/* aux 恒记（freeze delta） */
		} else if (row->flags & AS_OC_F_READBACK) {
			job.has_base = job.has_before;
			job.base[0] = job.before;
			job.base[1] = sb[1];
		} else {
			job.has_base = has_sb;
			job.base[0] = sb[0];
			job.base[1] = sb[1];
		}
	}
	now = as_now_mono_ms();
	job.arm_mono_ms = now;
	job.due_mono_ms = now + (row->win_long ?
				 oc->conf->outcome_window_long_sec :
				 oc->conf->outcome_window_short_sec) * 1000;
	oc_push(oc, &job);
	oc->stats->oc.armed++;
	oc->armed_any = 1;
	as_log_debug("outcome armed: id=%llu knob=%s pid=%d inj=%lld "
		     "pre=%lld(%d) base=%lld/%lld(%d)",
		     id, param, job.pid, job.injected, job.before,
		     job.has_before, job.base[0], job.base[1],
		     job.has_base);
}

/* 写口："<id>,<outcome>,<delta>"（0200 root；-2=ENOENT→notfound） */
static int oc_write_outcome(struct as_outcome *oc, unsigned long long id, int outcome,
			    long long delta)
{
	char path[384], buf[96];
	int fd, n, rc = 0;

	mkpath(path, sizeof(path), oc->root, AS_OC_SUB_OUTCOME);
	/* 尾部换行：内核 ai_outcome_store 剥离后 sscanf——真 sysfs 兼容；
	 * mock 累积文件可按行解析 */
	n = snprintf(buf, sizeof(buf), "%llu,%u,%lld\n", id, outcome, delta);
	if (n <= 0 || (size_t)n >= sizeof(buf))
		return -1;
	fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT ? -2 : -1;
	if (write(fd, buf, (size_t)n) != n)
		rc = errno == ENOENT ? -2 : -1;
	close(fd);
	return rc;
}

static void oc_emit_event(struct as_outcome *oc, unsigned long long id, int outcome,
			  long long delta, const char *knob)
{
	struct as_event ev;

	if (!oc->conf->outcome_write_sme || !oc->emit)
		return;
	as_event_outcome(&ev, id, outcome, delta, knob);
	oc->emit(&ev, oc->emit_ud);
}

void as_outcome_tick(struct as_outcome *oc, long long now_mono_ms)
{
	if (!oc || !oc->conf->outcome_enabled || !oc->jobs)
		return;
	/* FIFO 逐条到期处理（n 固定：本轮新 arm 不膨胀循环） */
	for (int i = 0, n = oc->count; i < n; i++) {
		struct as_oc_job job = oc_pop(oc);
		const struct as_oc_row *row = &as_oc_rows[job.row_idx];
		struct as_oc_class cls;
		long long nowv[2] = { 0, 0 };
		int has_now, wrc;
		int window_sec = (int)(row->win_long ?
				       oc->conf->outcome_window_long_sec :
				       oc->conf->outcome_window_short_sec);

		if (now_mono_ms < job.due_mono_ms) {
			oc_push(oc, &job);	/* 未到期：回队（保 FIFO 序） */
			continue;
		}
		oc->stats->oc.filled++;

		/* 窗口末快照 + 分类 */
		has_now = as_oc_snapshot(oc->root, row, job.pid,
						 (unsigned long long)job.injected, job.data,
						 nowv) == 0;
		if (!has_now) {
			/* 窗口末指标源读失败（pid 消亡/无内核面）→ PARTIAL
			 * +delta=0+meas_fail（不装 FAILED，§4.4） */
			memset(&cls, 0, sizeof(cls));
			cls.outcome = AS_OC_PARTIAL;
			cls.meas_fail = 1;
		} else if (row->kind >= OC_K_MATCH_AFFINITY &&
			   row->kind <= OC_K_MATCH_FREEZE) {
			int no_expect = (nowv[0] < 0);

			cls = as_oc_classify_match(row, no_expect,
						   job.has_base,
						   (int)job.base[0],
						   (int)nowv[0], job.base[1],
						   nowv[1]);
		} else if (!job.has_base && (row->flags & AS_OC_F_READBACK)) {
			/* U66：读回型基线即 pre → pre=none ⇒ delta 不可算
			 * （after 可得、pre 缺席）→ PARTIAL+pre_none */
			memset(&cls, 0, sizeof(cls));
			cls.outcome = AS_OC_PARTIAL;
			cls.pre_none = 1;
		} else if (!job.has_base) {
			/* 环境型 arm 快照失败 → PARTIAL+delta=0+meas_fail */
			memset(&cls, 0, sizeof(cls));
			cls.outcome = AS_OC_PARTIAL;
			cls.meas_fail = 1;
		} else {
			cls = as_oc_classify_num(row, job.injected, job.before,
						 job.has_before, job.base[0],
						 nowv[0], window_sec);
		}
		if (cls.meas_fail)
			oc->stats->oc.meas_fail++;
		if (cls.noop)
			oc->stats->oc.noop++;
		if (cls.pre_none)
			oc->stats->oc.pre_none++;

		/* 写口（每 job 恰一次——ENOENT/write_fail 不重试，§4.4） */
		wrc = oc_write_outcome(oc, job.decision_id, cls.outcome,
				       cls.delta);
		if (wrc == -2) {
			oc->stats->oc.notfound++;
			as_warn_ratelimit("oc-enoent", 60000,
					  "outcome write id=%llu: -ENOENT "
					  "(ring wrapped/reboot?) - notfound="
					  "%lld", job.decision_id,
					  oc->stats->oc.notfound);
			continue;	/* ENOENT：不写 success/partial 计数 */
		}
		if (wrc != 0) {
			oc->stats->oc.write_fail++;
			as_warn_ratelimit("oc-write", 60000,
					  "outcome write id=%llu failed: %s "
					  "(write_fail=%lld)",
					  job.decision_id, strerror(errno),
					  oc->stats->oc.write_fail);
			continue;
		}
		if (cls.outcome == AS_OC_SUCCESS)
			oc->stats->oc.success++;
		else if (cls.outcome == AS_OC_WORSE)
			oc->stats->oc.worse++;
		else
			oc->stats->oc.partial++;

		/* 自校验：decisions 该条 outcome_ts>0（§4.3 t0+W+δ；失败只
		 * 计数——grace 由外部验收脚本按 OUTCOME_GRACE_SEC 复核） */
		{
			char dpath[384];
			struct as_oc_decision chk;

			mkpath(dpath, sizeof(dpath), oc->root,
			       AS_OC_SUB_DECISIONS);
			if (as_oc_scan_decisions(dpath, job.decision_id,
						 (int)oc->conf->
						 outcome_decisions_scan_max,
						 &chk) != 0 || !chk.outcome_ts)
				oc->stats->oc.verify_fail++;
		}

		/* journal 审计行（量纲=表行 unit）+ 合成事件（SME/parquet） */
		as_log("outcome: id=%llu knob=%s outcome=%s delta=%lld %s%s%s%s",
		       job.decision_id, job.param,
		       as_oc_outcome_name(cls.outcome), cls.delta,
		       row->unit, cls.meas_fail ? " meas_fail" : "",
		       cls.noop ? " noop" : "",
		       cls.pre_none ? " pre_none" : "");
		oc_emit_event(oc, job.decision_id, cls.outcome, cls.delta,
			      job.param);
	}
}

long long as_outcome_due_ms(const struct as_outcome *oc, long long now_mono_ms)
{
	long long best = -1;

	if (!oc || !oc->jobs || oc->count == 0)
		return -1;
	for (int i = 0; i < oc->count; i++) {
		const struct as_oc_job *j =
			&oc->jobs[(oc->head + i) % oc->cap];
		long long d = j->due_mono_ms - now_mono_ms;

		if (d < 0)
			d = 0;
		if (best < 0 || d < best)
			best = d;
	}
	return best;
}
