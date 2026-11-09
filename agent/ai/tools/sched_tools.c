// SPDX-License-Identifier: GPL-2.0
/*
 * sched_tools.c - W79 双调度台（sched 通道，五件工具）
 *
 * 计划书 V2.1–V2.3："两块台子并存——一块规则/固定参数，一块模型输出；
 * Agent 一句话切换，两者可做 A/B 对照"。本棒只做台子 + 旋钮 + 对照能力，
 * 不做 ML 模型（W83）：ml 台未就绪时必须明确拒绝（C2），绝不假成功。
 *
 * 台子落地方式（全部真读文件，不由配置回显）：
 *   - 任务级旋钮：复用 NETLINK_AI ACT（param=sched.nice/affinity/
 *     oom_score/timeslice，data[0]=pid data[1]=value），读回走 /proc/<pid> 下的 stat/status/oom_score_adj
 *     与 /proc/ai/control；ACT 不可用（非 AIKernel 内核）时诚实报错。
 *   - cgroup 级旋钮：cgroup v2 专用子组 /sys/fs/cgroup/aikernel-sched
 *     （首次写入时创建；cpu/io 控制器按需写入 root cgroup.subtree_control，
 *     已启用则不动）。写 → pread 读回 → 逐项比对；不一致即回滚并报失败。
 *   - 台子模式：/var/lib/aikernel/sched/mode（0600），static|ml|off。
 *
 * 对照实验（sched_ab_run）：
 *   2 参数集 × 3 档负载（cpu/io/mix），内置自旋与 pwrite+fdatasync 负载
 *   （零新依赖），指标 = 吞吐 / p99 单元延迟 / 公平性 CV / 能耗代理（RAPL，
 *   不可读则 N/A）。总时长硬上限 180 秒：每档 duration_s 在 2..20，
 *   2*loads*duration 超预算时自动缩 duration 并在报告里写明。实验前自动
 *   快照、实验后必然恢复并逐项读回校验（C6），中途失败也一样。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "netlink/ai_netlink_client.h"
#include "tools/tool_registry.h"
#include "tools/sched_tools.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define SCHED_STATE_DIR_DEFAULT	"/var/lib/aikernel/sched"
#define SCHED_CGROUP_DEFAULT	"/sys/fs/cgroup/aikernel-sched"
#define SCHED_CGROUP_ROOT_DEFAULT "/sys/fs/cgroup"

#define SCHED_PATH_MAX		512
#define SCHED_VALUE_MAX		256
#define SCHED_SNAP_MAX_KNOBS	16
#define SCHED_SNAP_MAX_NA	8
#define SCHED_SNAP_LIST_MAX	64

/* 对照实验硬上限（C6：长操作不能挂死会话） */
#define AB_TOTAL_MAX_SEC	180
#define AB_DURATION_MIN		2
#define AB_DURATION_MAX		20
#define AB_WORKERS_MAX		8
#define AB_LAT_MAX		4096

#define SCHED_MODE_STATIC	"static"
#define SCHED_MODE_ML		"ml"
#define SCHED_MODE_OFF		"off"

/* ------------------------------------------------------------------ */
/* 小工具                                                              */
/* ------------------------------------------------------------------ */

struct sbuf {
	char *p;
	size_t len;
	size_t cap;
};

static int sb_init(struct sbuf *b)
{
	b->cap = 2048;
	b->len = 0;
	b->p = malloc(b->cap);
	if (!b->p)
		return -1;
	b->p[0] = '\0';
	return 0;
}

static void sb_free(struct sbuf *b)
{
	free(b->p);
	b->p = NULL;
	b->len = b->cap = 0;
}

static int sb_add(struct sbuf *b, const char *fmt, ...)
{
	va_list ap, ap2;
	int need;
	size_t cap;

	if (!b->p)
		return -1;
	va_start(ap, fmt);
	va_copy(ap2, ap);
	need = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (need < 0) {
		va_end(ap2);
		return -1;
	}
	if (b->len + (size_t)need + 1 > b->cap) {
		cap = b->cap * 2;
		while (cap < b->len + (size_t)need + 1)
			cap *= 2;
		{
			char *np = realloc(b->p, cap);

			if (!np) {
				va_end(ap2);
				return -1;
			}
			b->p = np;
			b->cap = cap;
		}
	}
	vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap2);
	va_end(ap2);
	b->len += (size_t)need;
	return 0;
}

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	if (!err || !errlen)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
}

static int path_exists(const char *p)
{
	struct stat st;

	return p && stat(p, &st) == 0;
}

static int is_dir(const char *p)
{
	struct stat st;

	return p && stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

/* 读文本文件并去掉尾部换行；返回 0 成功 / -1（errno） */
static int read_text(const char *path, char *buf, size_t cap)
{
	int fd, n;
	size_t len = 0;

	if (!buf || cap == 0)
		return -1;
	buf[0] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	while (len + 1 < cap) {
		n = (int)read(fd, buf + len, cap - 1 - len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			buf[0] = '\0';
			return -1;
		}
		if (n == 0)
			break;
		len += (size_t)n;
	}
	close(fd);
	buf[len] = '\0';
	while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
		buf[--len] = '\0';
	return 0;
}

/* 写文本文件（整串；create=0 要求文件已存在，cgroup 旋钮路径用）；
 * 返回 0 成功 / -1（errno） */
static int write_text_ex(const char *path, const char *text, int create,
			 mode_t mode)
{
	int fd, rc;
	size_t len = strlen(text), off = 0;

	fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC | (create ? O_CREAT : 0),
		  mode);
	if (fd < 0)
		return -1;
	while (off < len) {
		rc = (int)write(fd, text + off, len - off);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		off += (size_t)rc;
	}
	if (close(fd) != 0)
		return -1;
	return 0;
}

static int write_text(const char *path, const char *text)
{
	return write_text_ex(path, text, 0, 0);
}

static int mkdir_p(const char *path, mode_t mode)
{
	char tmp[SCHED_PATH_MAX];
	size_t i, len;

	if (is_dir(path))
		return 0;
	len = strlen(path);
	if (len == 0 || len >= sizeof(tmp))
		return -1;
	memcpy(tmp, path, len + 1);
	for (i = 1; i < len; i++) {
		if (tmp[i] != '/')
			continue;
		tmp[i] = '\0';
		if (mkdir(tmp, mode) != 0 && errno != EEXIST)
			return -1;
		tmp[i] = '/';
	}
	if (mkdir(tmp, mode) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

static long long mono_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

static unsigned long long epoch_now(void)
{
	return (unsigned long long)time(NULL);
}

static void iso_utc(unsigned long long t, char *buf, size_t cap)
{
	time_t tt = (time_t)t;
	struct tm tm;

	if (gmtime_r(&tt, &tm))
		strftime(buf, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
	else
		snprintf(buf, cap, "%llu", t);
}

/* 严格整数解析：空/前导空白/尾随垃圾一律拒绝 */
static int parse_ll(const char *s, long long *out)
{
	char *end = NULL;
	long long v;

	if (!s || !s[0])
		return -1;
	if (s[0] == ' ' || s[0] == '\t' || s[0] == '\n')
		return -1;
	errno = 0;
	v = strtoll(s, &end, 10);
	if (errno || !end || *end != '\0')
		return -1;
	*out = v;
	return 0;
}

static int parse_dev(const char *s, unsigned *maj, unsigned *min, int *consumed)
{
	unsigned long a, b;
	char *end = NULL;

	if (!s || !s[0])
		return -1;
	errno = 0;
	a = strtoul(s, &end, 10);
	if (errno || !end || *end != ':')
		return -1;
	b = strtoul(end + 1, &end, 10);
	if (errno || !end)
		return -1;
	if (a > 4095 || b > 1048575)
		return -1;
	*maj = (unsigned)a;
	*min = (unsigned)b;
	if (consumed)
		*consumed = (int)(end - s);
	return 0;
}

static void norm_ws(const char *in, char *out, size_t cap)
{
	size_t o = 0;
	int sp = 0;

	if (!out || cap == 0)
		return;
	out[0] = '\0';
	if (!in)
		return;
	while (*in && o + 1 < cap) {
		if (*in == ' ' || *in == '\t' || *in == '\n' || *in == '\r') {
			sp = 1;
			in++;
			continue;
		}
		if (sp && o > 0)
			out[o++] = ' ';
		sp = 0;
		out[o++] = *in++;
	}
	out[o] = '\0';
}

/* 定长拷贝（超长返回 -1），用于拼接好的路径落盘，避免 snprintf 截断告警 */
static int copy_str(char *dst, size_t cap, const char *src)
{
	size_t n;

	if (!dst || !src || cap == 0)
		return -1;
	n = strlen(src);
	if (n >= cap)
		return -1;
	memcpy(dst, src, n + 1);
	return 0;
}

static int str_eq_norm(const char *a, const char *b)
{
	char na[SCHED_VALUE_MAX * 2], nb[SCHED_VALUE_MAX * 2];

	norm_ws(a, na, sizeof(na));
	norm_ws(b, nb, sizeof(nb));
	return strcmp(na, nb) == 0;
}

/* ------------------------------------------------------------------ */
/* 旋钮表                                                              */
/* ------------------------------------------------------------------ */

static const struct ai_sched_knob g_knobs[] = {
	{
		"nice", AI_SCHED_KNOB_TASK, "sched.nice", NULL,
		-20, 19, "[-20,19]（set_user_nice）", NULL, 1
	},
	{
		"affinity", AI_SCHED_KNOB_TASK, "sched.affinity", NULL,
		0, 4095, "[0,nproc-1]（单 CPU 掩码）", NULL, 1
	},
	{
		"oom_score", AI_SCHED_KNOB_TASK, "sched.oom_score", NULL,
		-1000, 1000, "[-1000,1000]（oom_score_adj）", NULL, 1
	},
	{
		"timeslice", AI_SCHED_KNOB_TASK, "sched.timeslice", NULL,
		1, 1000, "[1,1000]（0.1ms；全局 EEVDF base_slice）", "7", 0
	},
	{
		"cpu.weight", AI_SCHED_KNOB_CGROUP, NULL, "cpu.weight",
		1, 10000, "[1,10000]", "100", 0
	},
	{
		"cpu.max", AI_SCHED_KNOB_CGROUP, NULL, "cpu.max",
		1000, 1000000,
		"max [period] | quota(1000-1000000) period(1000-1000000)",
		"max 100000", 0
	},
	{
		"cpu.max.burst", AI_SCHED_KNOB_CGROUP, NULL, "cpu.max.burst",
		0, 1000000, "[0,1000000]", "0", 0
	},
	{
		"io.weight", AI_SCHED_KNOB_CGROUP, NULL, "io.weight",
		1, 10000, "default N | MAJ:MIN N（N 1-10000）",
		"default 100", 0
	},
	{
		"io.max", AI_SCHED_KNOB_CGROUP, NULL, "io.max",
		0, 0,
		"MAJ:MIN [rbps=|wbps=|riops=|wiops=]<N|max>（整盘设备，至少一项）",
		NULL, 0
	},
	{
		"sched.mode", AI_SCHED_KNOB_MODE, NULL, NULL,
		0, 0, "static | ml | off", SCHED_MODE_OFF, 0
	},
};

int ai_sched_knob_count(void)
{
	return (int)ARRAY_SIZE(g_knobs);
}

const struct ai_sched_knob *ai_sched_knob_at(int idx)
{
	if (idx < 0 || idx >= (int)ARRAY_SIZE(g_knobs))
		return NULL;
	return &g_knobs[idx];
}

int ai_sched_knob_find(const char *name)
{
	size_t i;

	if (!name)
		return -1;
	for (i = 0; i < ARRAY_SIZE(g_knobs); i++)
		if (strcmp(g_knobs[i].name, name) == 0)
			return (int)i;
	return -1;
}

int ai_sched_valid_mode(const char *s)
{
	return s && (strcmp(s, SCHED_MODE_STATIC) == 0 ||
		     strcmp(s, SCHED_MODE_ML) == 0 ||
		     strcmp(s, SCHED_MODE_OFF) == 0);
}

/* ---- 值校验 ---- */

static int valid_int_range(const struct ai_sched_knob *k, const char *value,
			   char *err, size_t errlen)
{
	long long v;

	if (parse_ll(value, &v) != 0) {
		set_err(err, errlen, "%s 需要整数（收到 \"%s\"）",
			k->name, value ? value : "");
		return -1;
	}
	if (v < k->vmin || v > k->vmax) {
		set_err(err, errlen, "%s 越界：%lld 不在 %s",
			k->name, v, k->range);
		return -1;
	}
	return 0;
}

static int valid_cpu_max(const char *value, char *err, size_t errlen)
{
	char buf[SCHED_VALUE_MAX];
	char *tok, *save = NULL;
	long long quota = -1, period = -1;
	int n = 0;

	snprintf(buf, sizeof(buf), "%s", value ? value : "");
	for (tok = strtok_r(buf, " \t", &save); tok;
	     tok = strtok_r(NULL, " \t", &save)) {
		if (n == 0) {
			if (strcmp(tok, "max") != 0 &&
			    (parse_ll(tok, &quota) != 0 ||
			     quota < 1000 || quota > 1000000)) {
				set_err(err, errlen,
					"cpu.max 第一段须为 max 或 1000-1000000 的 quota（收到 \"%s\"）",
					tok);
				return -1;
			}
		} else if (n == 1) {
			if (parse_ll(tok, &period) != 0 ||
			    period < 1000 || period > 1000000) {
				set_err(err, errlen,
					"cpu.max period 须为 1000-1000000（收到 \"%s\"）",
					tok);
				return -1;
			}
		} else {
			set_err(err, errlen, "cpu.max 至多两段（quota period）");
			return -1;
		}
		n++;
	}
	if (n == 0) {
		set_err(err, errlen, "cpu.max 不能为空（例：max 100000 / 50000 100000）");
		return -1;
	}
	return 0;
}

static int valid_io_weight(const char *value, char *err, size_t errlen)
{
	char buf[SCHED_VALUE_MAX];
	char *tok, *save = NULL;
	char *parts[3];
	int n = 0;
	long long w;

	snprintf(buf, sizeof(buf), "%s", value ? value : "");
	for (tok = strtok_r(buf, " \t", &save); tok && n < 3;
	     tok = strtok_r(NULL, " \t", &save))
		parts[n++] = tok;
	if (n != 2) {
		set_err(err, errlen,
			"io.weight 需要两段：default N 或 MAJ:MIN N");
		return -1;
	}
	if (strcmp(parts[0], "default") != 0) {
		unsigned ma, mi;
		int used = 0;

		if (parse_dev(parts[0], &ma, &mi, &used) != 0 ||
		    parts[0][used] != '\0') {
			set_err(err, errlen,
				"io.weight 第一段须为 default 或 MAJ:MIN（收到 \"%s\"）",
				parts[0]);
			return -1;
		}
	}
	if (parse_ll(parts[1], &w) != 0 || w < 1 || w > 10000) {
		set_err(err, errlen, "io.weight 权重须为 1-10000（收到 \"%s\"）",
			parts[1]);
		return -1;
	}
	return 0;
}

static int valid_io_max(const char *value, char *err, size_t errlen)
{
	char buf[SCHED_VALUE_MAX];
	char *tok, *save = NULL;
	unsigned ma, mi;
	int used = 0, keys = 0;

	snprintf(buf, sizeof(buf), "%s", value ? value : "");
	tok = strtok_r(buf, " \t", &save);
	if (!tok) {
		set_err(err, errlen,
			"io.max 不能为空（清空请用 sched.mode off 或显式写 max）");
		return -1;
	}
	if (parse_dev(tok, &ma, &mi, &used) != 0 || tok[used] != '\0') {
		set_err(err, errlen,
			"io.max 第一段须为 MAJ:MIN（收到 \"%s\"；设备须为整盘）",
			tok);
		return -1;
	}
	for (tok = strtok_r(NULL, " \t", &save); tok;
	     tok = strtok_r(NULL, " \t", &save)) {
		char *eq = strchr(tok, '=');
		const char *key;
		long long v;

		if (!eq) {
			set_err(err, errlen,
				"io.max 项须为 key=value（收到 \"%s\"）", tok);
			return -1;
		}
		*eq = '\0';
		key = tok;
		if (strcmp(key, "rbps") != 0 && strcmp(key, "wbps") != 0 &&
		    strcmp(key, "riops") != 0 && strcmp(key, "wiops") != 0) {
			set_err(err, errlen,
				"io.max 未知 key \"%s\"（rbps|wbps|riops|wiops）",
				key);
			return -1;
		}
		if (strcmp(eq + 1, "max") != 0) {
			if (parse_ll(eq + 1, &v) != 0 || v < 0) {
				set_err(err, errlen,
					"io.max %s 值须为非负整数或 max（收到 \"%s\"）",
					key, eq + 1);
				return -1;
			}
		}
		keys++;
	}
	if (keys == 0) {
		set_err(err, errlen,
			"io.max 至少给一项 rbps/wbps/riops/wiops");
		return -1;
	}
	return 0;
}

int ai_sched_validate_value(const struct ai_sched_knob *k, const char *value,
			    char *err, size_t errlen)
{
	long nproc;

	if (!k || !value) {
		set_err(err, errlen, "旋钮或值为空");
		return -1;
	}
	switch (k->kind) {
	case AI_SCHED_KNOB_MODE:
		if (!ai_sched_valid_mode(value)) {
			set_err(err, errlen,
				"sched.mode 只接受 static | ml | off（收到 \"%s\"）",
				value);
			return -1;
		}
		return 0;
	case AI_SCHED_KNOB_TASK:
		if (strcmp(k->name, "affinity") == 0) {
			long long v;

			if (parse_ll(value, &v) != 0) {
				set_err(err, errlen,
					"affinity 需要 CPU 编号整数（收到 \"%s\"）",
					value);
				return -1;
			}
			nproc = sysconf(_SC_NPROCESSORS_ONLN);
			if (nproc < 1)
				nproc = 1;
			if (v < 0 || v >= nproc) {
				set_err(err, errlen,
					"affinity 越界：%lld 不在 [0,%ld]",
					v, nproc - 1);
				return -1;
			}
			return 0;
		}
		return valid_int_range(k, value, err, errlen);
	case AI_SCHED_KNOB_CGROUP:
		if (strcmp(k->name, "cpu.max") == 0)
			return valid_cpu_max(value, err, errlen);
		if (strcmp(k->name, "io.weight") == 0)
			return valid_io_weight(value, err, errlen);
		if (strcmp(k->name, "io.max") == 0)
			return valid_io_max(value, err, errlen);
		return valid_int_range(k, value, err, errlen);
	default:
		set_err(err, errlen, "未知旋钮类型");
		return -1;
	}
}

/* ---- 读回比对 ---- */

/* io.max 读回会被内核补全未写的 key（=max）并规范化为整盘设备行；
 * 比较口径：请求的 key 逐个相等即算一致（未写 key 视为 max） */
static int iomax_match(const char *want, const char *got)
{
	char w[SCHED_VALUE_MAX];
	char *tok, *save = NULL;
	unsigned want_ma, want_mi;
	int used = 0, need_key = 0;
	const char *line = NULL;
	char lines[2048];
	char *lsave = NULL, *l;

	snprintf(w, sizeof(w), "%s", want ? want : "");
	tok = strtok_r(w, " \t", &save);
	if (!tok || parse_dev(tok, &want_ma, &want_mi, &used) != 0)
		return 1;
	snprintf(lines, sizeof(lines), "%s", got ? got : "");
	for (l = strtok_r(lines, "\n", &lsave); l;
	     l = strtok_r(NULL, "\n", &lsave)) {
		unsigned gma, gmi;
		int gused = 0;
		char lbuf[SCHED_VALUE_MAX];
		char *first, *s2 = NULL;

		snprintf(lbuf, sizeof(lbuf), "%s", l);
		first = strtok_r(lbuf, " \t", &s2);
		if (!first || parse_dev(first, &gma, &gmi, &gused) != 0)
			continue;
		if (gma == want_ma && gmi == want_mi) {
			line = l;
			break;
		}
	}
	/* 请求全是 max 且内核把该设备行删空 = 已无限制，视为一致 */
	if (!line) {
		char tmp[SCHED_VALUE_MAX];
		char *t2, *sv2 = NULL;

		snprintf(tmp, sizeof(tmp), "%s", want ? want : "");
		t2 = strtok_r(tmp, " 	", &sv2);
		while ((t2 = strtok_r(NULL, " 	", &sv2))) {
			char *eq2 = strchr(t2, '=');

			if (eq2 && strcmp(eq2 + 1, "max") != 0)
				need_key = 1;
		}
		return need_key ? 1 : 0;
	}
	/* 逐个请求 key 比对 */
	snprintf(w, sizeof(w), "%s", want ? want : "");
	tok = strtok_r(w, " \t", &save);	/* dev */
	while ((tok = strtok_r(NULL, " \t", &save))) {
		char key[16], val[32], pat[48];
		char *eq = strchr(tok, '=');
		char lbuf[2048];
		char *lt, *ls = NULL;
		int found = 0;

		if (!eq)
			return 1;
		snprintf(key, sizeof(key), "%.*s", (int)(eq - tok), tok);
		snprintf(val, sizeof(val), "%s", eq + 1);
		if (strcmp(val, "max") == 0)
			continue;	/* 未写 key 的默认就是 max */
		snprintf(pat, sizeof(pat), "%s=", key);
		snprintf(lbuf, sizeof(lbuf), "%s", line);
		lt = strtok_r(lbuf, " \t", &ls);
		while ((lt = strtok_r(NULL, " \t", &ls))) {
			if (strncmp(lt, pat, strlen(pat)) != 0)
				continue;
			if (strcmp(lt + strlen(pat), val) == 0)
				found = 1;
			break;
		}
		if (!found)
			return 1;
	}
	return 0;
}

/* Cpus_allowed_list（如 "3" 或 "0-7,9"）与单个 CPU 编号是否一致 */
static int cpulist_equals_one(const char *list, long long cpu)
{
	char buf[512];
	char *tok, *save = NULL;
	int n = 0;

	snprintf(buf, sizeof(buf), "%s", list ? list : "");
	for (tok = strtok_r(buf, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		char *dash = strchr(tok, '-');
		long long a, b;

		if (dash) {
			*dash = '\0';
			if (parse_ll(tok, &a) != 0 ||
			    parse_ll(dash + 1, &b) != 0)
				return 0;
			if (b < a)
				return 0;
			if (cpu < a || cpu > b)
				return 0;
			n += (int)(b - a + 1);
		} else {
			if (parse_ll(tok, &a) != 0 || a != cpu)
				return 0;
			n++;
		}
	}
	return n == 1;
}

/* io.max 请求是否为"清空"（所有 key=max）：清空后内核会删掉该设备行，
 * 读回为空是**预期状态**，但必须与"读回一致"区分开报告（见 cg_apply 返回 2） */
static int iomax_is_clear(const char *value)
{
	char buf[SCHED_VALUE_MAX];
	char *tok, *save = NULL;
	int keys = 0, all_max = 1;

	snprintf(buf, sizeof(buf), "%s", value ? value : "");
	tok = strtok_r(buf, " \t", &save);	/* dev */
	while ((tok = strtok_r(NULL, " \t", &save))) {
		char *eq = strchr(tok, '=');

		if (!eq)
			return 0;
		keys++;
		if (strcmp(eq + 1, "max") != 0)
			all_max = 0;
	}
	return keys > 0 && all_max;
}

int ai_sched_value_match(const struct ai_sched_knob *k, const char *want,
			 const char *got)
{
	if (!k || !want || !got)
		return 1;
	if (strcmp(k->name, "io.max") == 0)
		return iomax_match(want, got);
	if (strcmp(k->name, "affinity") == 0) {
		long long cpu;

		if (parse_ll(want, &cpu) != 0)
			return 1;
		return cpulist_equals_one(got, cpu) ? 0 : 1;
	}
	return str_eq_norm(want, got) ? 0 : 1;
}

/* ---- 负载名 ---- */

static const char *const g_load_names[3] = { "cpu", "io", "mix" };

const char *ai_sched_load_name(int bit)
{
	if (bit < 0 || bit > 2)
		return "?";
	return g_load_names[bit];
}

int ai_sched_parse_loads(const char *s, int *mask)
{
	char buf[SCHED_VALUE_MAX];
	char *tok, *save = NULL;
	int m = 0;

	if (!s || !mask)
		return -1;
	snprintf(buf, sizeof(buf), "%s", s);
	for (tok = strtok_r(buf, ", \t", &save); tok;
	     tok = strtok_r(NULL, ", \t", &save)) {
		if (strcmp(tok, "cpu") == 0)
			m |= 1 << 0;
		else if (strcmp(tok, "io") == 0)
			m |= 1 << 1;
		else if (strcmp(tok, "mix") == 0)
			m |= 1 << 2;
		else if (strcmp(tok, "all") == 0)
			m |= 0x7;
		else
			return -1;
	}
	if (m == 0)
		m = 0x7;
	*mask = m;
	return 0;
}

/* ------------------------------------------------------------------ */
/* 环境：状态目录 / cgroup                                              */
/* ------------------------------------------------------------------ */

static const char *state_dir(void)
{
	const char *e = getenv("AIKERNEL_SCHED_DIR");

	return (e && e[0]) ? e : SCHED_STATE_DIR_DEFAULT;
}

static const char *cg_dir(void)
{
	const char *e = getenv("AIKERNEL_SCHED_CGROUP");

	return (e && e[0]) ? e : SCHED_CGROUP_DEFAULT;
}

static const char *cg_root(void)
{
	const char *e = getenv("AIKERNEL_SCHED_CGROUP_ROOT");

	/* 只允许覆盖 cgroup 父目录；默认 /sys/fs/cgroup */
	if (e && e[0] && strncmp(e, "/sys/fs/cgroup", 14) == 0)
		return e;
	return SCHED_CGROUP_ROOT_DEFAULT;
}

static int mode_path(char *buf, size_t cap)
{
	return snprintf(buf, cap, "%.480s/mode", state_dir()) < (int)cap ? 0 : -1;
}

static int state_dir_ensure(char *err, size_t errlen)
{
	const char *d = state_dir();

	if (mkdir_p(d, 0700) != 0) {
		set_err(err, errlen, "状态目录不可用：%s（mkdir: %s）",
			d, strerror(errno));
		return -1;
	}
	return 0;
}

/* root cgroup.subtree_control 里补齐 cpu/io；已启用则不动。
 * 只对真实 cgroup 根目录生效（测试覆盖路径下不做系统级写入）。 */
static int cg_ensure_controllers(char *err, size_t errlen)
{
	char path[SCHED_PATH_MAX], cur[SCHED_VALUE_MAX];
	char want[64] = "";
	int add_cpu = 0, add_io = 0;

	if (strcmp(cg_root(), SCHED_CGROUP_ROOT_DEFAULT) != 0)
		return 0;	/* 覆盖路径：只做只读探测 */
	snprintf(path, sizeof(path), "%.460s/cgroup.subtree_control", cg_root());
	if (read_text(path, cur, sizeof(cur)) != 0) {
		set_err(err, errlen, "读 %s 失败：%s", path, strerror(errno));
		return -1;
	}
	if (!strstr(cur, "cpu") || !strstr(cur, "io")) {
		if (!strstr(cur, "cpu"))
			add_cpu = 1;
		if (!strstr(cur, "io"))
			add_io = 1;
		if (add_cpu)
			snprintf(want + strlen(want),
				 sizeof(want) - strlen(want), "+cpu ");
		if (add_io)
			snprintf(want + strlen(want),
				 sizeof(want) - strlen(want), "+io");
		if (write_text(path, want) != 0) {
			set_err(err, errlen,
				"启用 cgroup 控制器失败（写 %s \"%s\"：%s）",
				path, want, strerror(errno));
			return -1;
		}
	}
	return 0;
}

/* cgroup 目录就绪（不存在则创建） */
static int cg_dir_ensure(char *err, size_t errlen)
{
	char cgctrl[SCHED_PATH_MAX];

	if (is_dir(cg_dir()))
		return 0;
	if (cg_ensure_controllers(err, errlen) != 0)
		return -1;
	if (mkdir(cg_dir(), 0755) != 0 && errno != EEXIST) {
		set_err(err, errlen, "创建 cgroup %s 失败：%s（需要 root）",
			cg_dir(), strerror(errno));
		return -1;
	}
	snprintf(cgctrl, sizeof(cgctrl), "%.470s/cgroup.controllers", cg_dir());
	if (!path_exists(cgctrl)) {
		set_err(err, errlen,
			"cgroup %s 无 cgroup.controllers（不是 cgroup v2 挂载点？）",
			cg_dir());
		return -1;
	}
	return 0;
}

static int cg_knob_path(const struct ai_sched_knob *k, char *buf, size_t cap)
{
	int n = snprintf(buf, cap, "%.470s/%s", cg_dir(), k->file);

	return (n > 0 && n < (int)cap) ? 0 : -1;
}

/* 读旋钮当前值；-1 = 文件不存在/不可读（errno） */
static int cg_read(const struct ai_sched_knob *k, char *buf, size_t cap)
{
	char path[SCHED_PATH_MAX];

	if (cg_knob_path(k, path, sizeof(path)) != 0)
		return -1;
	return read_text(path, buf, cap);
}

/* ------------------------------------------------------------------ */
/* 单个 cgroup 旋钮写 + 读回                                            */
/* ------------------------------------------------------------------ */

struct apply_rec {
	char knob[32];
	char before[SCHED_VALUE_MAX];
	char after[SCHED_VALUE_MAX];
};

/* 应用单个 cgroup 旋钮：预检（存在+可写+读旧值）→ 校验 → 写 → 读回 → 比对。
 * 不一致或写失败时用旧值回滚，并读回确认回滚结果。
 * 返回：0 = 写入且读回一致；1 = N/A（文件不存在/设备不支持，未写）；
 *       2 = 已清空（io.max 全 max，文件存在且可写，读回无限制行）；
 *       -1 = 失败（已回滚）。空读回绝不返回 0。 */
static int cg_apply(const struct ai_sched_knob *k, const char *value,
		    struct apply_rec *rec, char *err, size_t errlen)
{
	char path[SCHED_PATH_MAX], before[SCHED_VALUE_MAX];
	char after[SCHED_VALUE_MAX * 2];
	char verr[SCHED_VALUE_MAX];

	if (cg_knob_path(k, path, sizeof(path)) != 0) {
		set_err(err, errlen, "路径过长");
		return -1;
	}
	/* C2：先确认目标文件存在且可写。不存在 = 该内核/设备不支持，明确 N/A，
	 * 绝不进入写入路径（否则会退化成"写空文件也成功"的假成功）。 */
	if (access(path, F_OK) != 0) {
		set_err(err, errlen,
			"%s 不可用：%s 不存在（该内核/该设备不支持 %s）",
			k->name, path, k->name);
		return 1;
	}
	if (access(path, W_OK) != 0) {
		set_err(err, errlen, "%s 不可写：%s（%s；通常需要 root）",
			k->name, path, strerror(errno));
		return -1;
	}
	if (read_text(path, before, sizeof(before)) != 0) {
		if (errno == ENOENT || errno == ENODEV) {
			set_err(err, errlen,
				"%s 不可用（%s 不存在：内核未编该项或设备不支持）",
				k->name, path);
			return 1;
		}
		set_err(err, errlen, "%s 预检读旧值失败：%s",
			k->name, strerror(errno));
		return -1;
	}
	if (ai_sched_validate_value(k, value, verr, sizeof(verr)) != 0) {
		set_err(err, errlen, "%s", verr);
		return -1;
	}
	if (rec) {
		snprintf(rec->knob, sizeof(rec->knob), "%s", k->name);
		snprintf(rec->before, sizeof(rec->before), "%s", before);
	}
	if (write_text(path, value) != 0) {
		int e = errno;

		/* 设备级限制可能被内核拒（ENODEV/ENOTSUP）：不当作成功 */
		set_err(err, errlen, "%s 写入失败（\"%s\" → %s：%s）",
			k->name, value, path, strerror(e));
		return -1;
	}
	if (read_text(path, after, sizeof(after)) != 0) {
		(void)write_text(path, before);
		set_err(err, errlen, "%s 读回失败：%s（已回滚为 \"%s\"）",
			k->name, strerror(errno), before);
		return -1;
	}
	/* 空读回永远不算"一致"：
	 *   - io.max 清空请求（全 max）且文件存在 → 返回 2（"已清空"，报告措辞
	 *     与"一致"区分）；
	 *   - 其余任何空读回 → 判定写入未生效，回滚并失败。 */
	if (!after[0]) {
		if (strcmp(k->name, "io.max") == 0 && iomax_is_clear(value)) {
			if (rec)
				snprintf(rec->after, sizeof(rec->after), "%s",
					 "(已清空)");
			return 2;
		}
		{
			char rb[SCHED_VALUE_MAX];

			(void)write_text(path, before);
			rb[0] = '\0';
			(void)read_text(path, rb, sizeof(rb));
			set_err(err, errlen,
				"%s 读回为空：期望 \"%s\" 但内核未返回任何值（写入未生效；已回滚为 \"%s\"，回滚读回 \"%s\"）",
				k->name, value, before, rb);
			return -1;
		}
	}
	if (ai_sched_value_match(k, value, after) != 0) {
		char rb[SCHED_VALUE_MAX];

		(void)write_text(path, before);
		rb[0] = '\0';
		(void)read_text(path, rb, sizeof(rb));
		set_err(err, errlen,
			"%s 读回不一致：期望 \"%s\" 实际 \"%s\"（已回滚为 \"%s\"，回滚读回 \"%s\"）",
			k->name, value, after, before, rb);
		return -1;
	}
	if (rec)
		snprintf(rec->after, sizeof(rec->after), "%.255s", after);
	return 0;
}

/* ------------------------------------------------------------------ */
/* 任务级旋钮（NETLINK_AI ACT）                                        */
/* ------------------------------------------------------------------ */

/* 读 /proc/<pid>/stat 的第 field 个字段（1-based） */
static int proc_stat_field(long long pid, int field, char *out, size_t cap)
{
	char path[64], buf[2048];
	char *p, *end;
	int cur = 3;

	snprintf(path, sizeof(path), "/proc/%lld/stat", pid);
	if (read_text(path, buf, sizeof(buf)) != 0)
		return -1;
	p = strrchr(buf, ')');
	if (!p)
		return -1;
	p += 2;			/* 跳过 ") "，此时 p 指向第 3 字段 */
	if (field < 3) {
		/* 第 1、2 字段（pid/comm）本工具不用 */
		return -1;
	}
	while (p && *p) {
		end = strchr(p, ' ');
		if (cur == field) {
			size_t n = end ? (size_t)(end - p) : strlen(p);

			if (n >= cap)
				return -1;
			memcpy(out, p, n);
			out[n] = '\0';
			return 0;
		}
		if (!end)
			break;
		p = end + 1;
		cur++;
	}
	return -1;
}

/* 任务级读回：返回 0 成功，-1 不可读 */
static int task_readback(const struct ai_sched_knob *k, long long pid,
			 char *buf, size_t cap)
{
	char path[64], tmp[SCHED_VALUE_MAX];
	long long slice;

	if (strcmp(k->name, "nice") == 0) {
		if (proc_stat_field(pid, 19, buf, cap) != 0)
			return -1;
		return 0;
	}
	if (strcmp(k->name, "affinity") == 0) {
		FILE *fp;
		char line[SCHED_VALUE_MAX];

		snprintf(path, sizeof(path), "/proc/%lld/status", pid);
		fp = fopen(path, "re");
		if (!fp)
			return -1;
		buf[0] = '\0';
		while (fgets(line, sizeof(line), fp)) {
			if (strncmp(line, "Cpus_allowed_list:", 18) != 0)
				continue;
			snprintf(buf, cap, "%s", line + 18);
			buf[strcspn(buf, "\r\n")] = '\0';
			/* 去前导空白 */
			{
				char *s = buf;

				while (*s == ' ' || *s == '\t')
					s++;
				memmove(buf, s, strlen(s) + 1);
			}
			fclose(fp);
			return buf[0] ? 0 : -1;
		}
		fclose(fp);
		return -1;
	}
	if (strcmp(k->name, "oom_score") == 0) {
		snprintf(path, sizeof(path), "/proc/%lld/oom_score_adj", pid);
		return read_text(path, buf, cap);
	}
	if (strcmp(k->name, "timeslice") == 0) {
		/* 首选 /proc/sys/kernel/sched_base_slice（ns → 0.1ms） */
		if (read_text("/proc/sys/kernel/sched_base_slice", tmp,
			      sizeof(tmp)) == 0 &&
		    parse_ll(tmp, &slice) == 0 && slice > 0) {
			snprintf(buf, cap, "%lld", slice / 100000);
			return 0;
		}
		/* 回退 /proc/ai/control：sched.timeslice ... current=N */
		{
			FILE *fp = fopen("/proc/ai/control", "re");
			char line[512];

			if (!fp)
				return -1;
			while (fgets(line, sizeof(line), fp)) {
				char *c;

				if (strncmp(line, "sched.timeslice ", 16) != 0)
					continue;
				c = strstr(line, "current=");
				if (!c) {
					fclose(fp);
					return -1;
				}
				c += 8;
				snprintf(buf, cap, "%s", c);
				buf[strcspn(buf, "\r\n ")] = '\0';
				fclose(fp);
				return buf[0] ? 0 : -1;
			}
			fclose(fp);
		}
		return -1;
	}
	return -1;
}

/* 通过 NETLINK_AI ACT 下发任务级参数；参数名定向（req.param） */
static int nl_act_task(const struct ai_sched_knob *k, long long pid,
		       long long value, char *err, size_t errlen)
{
	struct ai_nl_client cli;
	struct ai_nl_act req;
	struct ai_nl_act_ack ack;
	int kern_err = 0, rc;

	memset(&req, 0, sizeof(req));
	req.decision_type = 1;
	req.domain = 1;		/* AI_POLICY_DOMAIN_SCHED */
	req.confidence = 100;
	snprintf(req.param, sizeof(req.param), "%s", k->param);
	if (k->is_task) {
		req.data[0] = (__u64)pid;
		req.data[1] = (__u64)value;
	} else {
		/* 全局参数（如 sched.timeslice）：内核 core/ai_control.c:155
		 * 按 !AI_CTRL_F_TASK 取 data[0] 为值；data[1] 被忽略。
		 * 这里若照搬 data[0]=pid 会把 pid 写进 base_slice。 */
		req.data[0] = (__u64)value;
	}

	memset(&cli, 0, sizeof(cli));
	cli.fd = -1;
	rc = ai_nl_client_open(&cli);
	if (rc != AI_OK) {
		set_err(err, errlen,
			"NETLINK_AI 不可用（%s）：任务级旋钮 %s 需要 AIKernel 内核",
			ai_error_string(rc), k->name);
		return -1;
	}
	memset(&ack, 0, sizeof(ack));
	rc = ai_nl_send_act(&cli, &req, &ack, &kern_err);
	ai_nl_client_close(&cli);
	if (rc != AI_OK) {
		const char *hint = ai_nl_errno_hint(kern_err);

		set_err(err, errlen, "ACT 下发失败：%s（errno=%d %s%s%s）",
			ai_error_string(rc), kern_err,
			kern_err ? strerror(kern_err) : "-",
			hint ? "；提示: " : "", hint ? hint : "");
		return -1;
	}
	if (ack.ai_err != 0) {
		set_err(err, errlen, "内核策略层拒绝：ai_err=%d（%s=%lld pid=%lld）",
			ack.ai_err, k->param, value, pid);
		return -1;
	}
	if (ack.executed == 0)
		set_err(err, errlen,
			"ACT 未命中（executed=0）：参数名 %s 未被内核策略表接收",
			k->param);
	else
		err[0] = '\0';
	return ack.executed ? 0 : -1;
}

/* 任务级写 + 读回；失败时尝试用旧值回滚（旧值不可读则只能报告） */
static int task_apply(const struct ai_sched_knob *k, const char *value,
		      long long pid, struct apply_rec *rec,
		      char *err, size_t errlen)
{
	char before[SCHED_VALUE_MAX], after[SCHED_VALUE_MAX];
	char verr[SCHED_VALUE_MAX];
	long long v;

	if (k->is_task && pid <= 0) {
		set_err(err, errlen, "%s 是任务级旋钮，需要 pid>0", k->name);
		return -1;
	}
	if (ai_sched_validate_value(k, value, verr, sizeof(verr)) != 0) {
		set_err(err, errlen, "%s", verr);
		return -1;
	}
	if (parse_ll(value, &v) != 0) {
		set_err(err, errlen, "%s 需要整数", k->name);
		return -1;
	}
	before[0] = '\0';
	if (task_readback(k, pid, before, sizeof(before)) != 0)
		before[0] = '\0';
	if (rec) {
		snprintf(rec->knob, sizeof(rec->knob), "%s", k->name);
		snprintf(rec->before, sizeof(rec->before), "%s", before);
	}
	if (nl_act_task(k, pid, v, err, errlen) != 0)
		return -1;
	if (task_readback(k, pid, after, sizeof(after)) != 0) {
		set_err(err, errlen,
			"%s 已下发但读回不可用（/proc/%lld 无对应字段）；不判定为成功",
			k->name, pid);
		return -1;
	}
	if (ai_sched_value_match(k, value, after) != 0) {
		char rb[SCHED_VALUE_MAX];

		rb[0] = '\0';
		if (before[0]) {
			long long bv;

			if (parse_ll(before, &bv) == 0)
				(void)nl_act_task(k, pid, bv, rb, sizeof(rb));
			rb[0] = '\0';
			(void)task_readback(k, pid, rb, sizeof(rb));
		}
		set_err(err, errlen,
			"%s 读回不一致：期望 \"%s\" 实际 \"%s\"（回滚读回 \"%s\"）",
			k->name, value, after, rb);
		return -1;
	}
	if (rec)
		snprintf(rec->after, sizeof(rec->after), "%.255s", after);
	return 0;
}

/* ------------------------------------------------------------------ */
/* 台子模式与参数集                                                     */
/* ------------------------------------------------------------------ */

static int mode_read(char *buf, size_t cap, int *has_file)
{
	char path[SCHED_PATH_MAX];

	if (has_file)
		*has_file = 0;
	if (mode_path(path, sizeof(path)) != 0)
		return -1;
	if (read_text(path, buf, cap) != 0) {
		snprintf(buf, cap, "%s", SCHED_MODE_OFF);
		return 0;
	}
	if (has_file)
		*has_file = 1;
	if (!ai_sched_valid_mode(buf))
		snprintf(buf, cap, "%s", SCHED_MODE_OFF);
	return 0;
}

static int mode_write(const char *mode, char *err, size_t errlen)
{
	char path[SCHED_PATH_MAX];

	if (state_dir_ensure(err, errlen) != 0)
		return -1;
	if (mode_path(path, sizeof(path)) != 0) {
		set_err(err, errlen, "mode 路径过长");
		return -1;
	}
	if (write_text_ex(path, mode, 1, 0600) != 0) {
		set_err(err, errlen, "写 %s 失败：%s", path, strerror(errno));
		return -1;
	}
	if (chmod(path, 0600) != 0) {
		set_err(err, errlen, "chmod %s 失败：%s", path, strerror(errno));
		return -1;
	}
	return 0;
}

/* static 台的固定参数集（"规则/固定参数"台）：CPU 配额半核 + nice 10 +
 * io 16MiB/s 读写（设备可解析时 best-effort）。off 用内核默认。 */
struct param_item {
	const char *knob;
	const char *value;	/* 空串 = 不写（如 io.max 清空） */
	int best_effort;
};

/*
 * 解析根文件系统所在整盘的 dev_t（"8:0"）：io.max 只认整盘设备
 * （分区 dev 会被内核回 ENODEV）。失败返回 -1，调用方按 best-effort
 * 记 N/A，绝不编造设备号。
 */
static int root_disk_dev(char *buf, size_t cap)
{
	FILE *fp = fopen("/proc/self/mountinfo", "re");
	char line[2048];
	char mnt[1024];
	char sysp[SCHED_PATH_MAX + 64], real[PATH_MAX];
	char dir[SCHED_PATH_MAX + 64], part[SCHED_PATH_MAX + 64];
	unsigned maj = 0, mi = 0;
	struct stat st;
	char *slash;

	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		unsigned ma, mi2;
		char m[1024];

		if (sscanf(line, "%*d %*d %u:%u %*s %1023s", &ma, &mi2,
			   m) != 3)
			continue;
		if (strcmp(m, "/") != 0)
			continue;
		maj = ma;
		mi = mi2;
		break;
	}
	fclose(fp);
	if (maj == 0 && mi == 0)
		return -1;
	snprintf(sysp, sizeof(sysp), "/sys/dev/block/%u:%u", maj, mi);
	if (!realpath(sysp, real))
		return -1;
	snprintf(dir, sizeof(dir), "%.570s", real);
	snprintf(part, sizeof(part), "%.560s/partition", real);
	if (stat(part, &st) == 0) {
		slash = strrchr(dir, '/');
		if (!slash)
			return -1;
		*slash = '\0';
	}
	snprintf(sysp, sizeof(sysp), "%.570s/dev", dir);
	if (read_text(sysp, buf, cap) != 0)
		return -1;
	snprintf(mnt, sizeof(mnt), "%s", buf);
	return mnt[0] ? 0 : -1;
}

static int param_set_apply(const char *which, struct sbuf *log,
			   char *err, size_t errlen)
{
	struct apply_rec recs[SCHED_SNAP_MAX_KNOBS];
	struct param_item items[SCHED_SNAP_MAX_KNOBS];
	int n = 0, i, rc;
	char dev[64] = "";
	char iomax[SCHED_VALUE_MAX] = "";

	if (strcmp(which, SCHED_MODE_STATIC) == 0) {
		items[n].knob = "cpu.weight";
		items[n].value = "100";
		items[n].best_effort = 0;
		n++;
		items[n].knob = "cpu.max";
		items[n].value = "50000 100000";	/* 半核 */
		items[n].best_effort = 0;
		n++;
		items[n].knob = "cpu.max.burst";
		items[n].value = "0";
		items[n].best_effort = 1;
		n++;
		items[n].knob = "io.weight";
		items[n].value = "default 100";
		items[n].best_effort = 1;
		n++;
		if (root_disk_dev(dev, sizeof(dev)) == 0) {
			snprintf(iomax, sizeof(iomax),
				 "%s rbps=16777216 wbps=16777216", dev);
			items[n].knob = "io.max";
			items[n].value = iomax;
			items[n].best_effort = 1;
			n++;
		}
	} else {	/* off：内核默认 */
		items[n].knob = "cpu.max";
		items[n].value = "max 100000";
		items[n].best_effort = 0;
		n++;
		items[n].knob = "cpu.weight";
		items[n].value = "100";
		items[n].best_effort = 0;
		n++;
		items[n].knob = "cpu.max.burst";
		items[n].value = "0";
		items[n].best_effort = 1;
		n++;
		items[n].knob = "io.weight";
		items[n].value = "default 100";
		items[n].best_effort = 1;
		n++;
		if (root_disk_dev(dev, sizeof(dev)) == 0) {
			snprintf(iomax, sizeof(iomax),
				 "%s rbps=max wbps=max riops=max wiops=max",
				 dev);
			items[n].knob = "io.max";
			items[n].value = iomax;
			items[n].best_effort = 1;
			n++;
		}
	}

	if (cg_dir_ensure(err, errlen) != 0)
		return -1;

	for (i = 0; i < n; i++) {
		const struct ai_sched_knob *k;
		int idx = ai_sched_knob_find(items[i].knob);

		if (idx < 0) {
			set_err(err, errlen, "内部错误：未知旋钮 %s",
				items[i].knob);
			return -1;
		}
		k = &g_knobs[idx];
		memset(&recs[i], 0, sizeof(recs[i]));
		rc = cg_apply(k, items[i].value, &recs[i], err, errlen);
		if (rc == 1) {
			if (!items[i].best_effort) {
				char nerr[SCHED_VALUE_MAX];

				snprintf(nerr, sizeof(nerr), "%s", err);
				set_err(err, errlen,
					"%s 不可用（required）：%s",
					k->name, nerr);
				return -1;
			}
			sb_add(log, "  %-14s N/A（%s）\n", k->name, err);
			continue;
		}
		if (rc == 2) {
			sb_add(log, "  %-14s %s → 已清空（读回无限制行，非\"一致\"判定）\n",
			       k->name, recs[i].before[0] ? recs[i].before :
			       "(空)");
			continue;
		}
		if (rc < 0) {
			int j;

			/* 回滚本调用里已应用的项（尽力而为） */
			for (j = i - 1; j >= 0; j--) {
				int idx2 = ai_sched_knob_find(recs[j].knob);
				char rerr[SCHED_VALUE_MAX];

				if (idx2 < 0 || !recs[j].before[0])
					continue;
				(void)cg_apply(&g_knobs[idx2], recs[j].before,
					       NULL, rerr, sizeof(rerr));
			}
			return -1;
		}
		sb_add(log, "  %-14s %s → %s（读回一致）\n",
		       recs[i].knob,
		       recs[i].before[0] ? recs[i].before : "(空)",
		       recs[i].after[0] ? recs[i].after : "(空)");
	}

	/* timeslice 是全局 base_slice：仅在 AIKernel ACT 可用时施加 */
	{
		int ts_idx = ai_sched_knob_find("timeslice");
		const struct ai_sched_knob *ts;
		char terr[SCHED_VALUE_MAX];
		char cur[SCHED_VALUE_MAX];
		struct apply_rec trec;

		memset(&trec, 0, sizeof(trec));
		if (ts_idx < 0)
			return 0;
		ts = &g_knobs[ts_idx];
		if (strcmp(which, SCHED_MODE_OFF) == 0) {
			if (task_readback(ts, (long long)getpid(), cur,
					  sizeof(cur)) == 0) {
				if (task_apply(ts, ts->dflt, (long long)getpid(),
					       &trec, terr, sizeof(terr)) == 0)
					sb_add(log,
					       "  %-14s %s → %s（读回一致）\n",
					       ts->name, cur, trec.after);
				else
					sb_add(log,
					       "  %-14s 未施加（%s）\n",
					       ts->name, terr);
			} else {
				sb_add(log, "  %-14s N/A（读回不可用：无 /proc/sys/kernel/sched_base_slice 与 /proc/ai/control）\n",
				       ts->name);
			}
		} else {
			sb_add(log,
			       "  %-14s 保持内核启动值（static 台不改全局 base_slice）\n",
			       ts->name);
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* 快照                                                                */
/* ------------------------------------------------------------------ */

struct sched_snap_item {
	char knob[32];
	char value[SCHED_VALUE_MAX];
};

struct sched_snapshot {
	char mode[16];
	unsigned long long epoch;
	char when[32];
	struct sched_snap_item items[SCHED_SNAP_MAX_KNOBS];
	int n;
	char na[SCHED_SNAP_MAX_NA][32];
	int na_n;
};

static int snap_collect(struct sched_snapshot *s, char *err, size_t errlen)
{
	int i, has_file = 0;
	char mbuf[16];

	memset(s, 0, sizeof(*s));
	s->epoch = epoch_now();
	iso_utc(s->epoch, s->when, sizeof(s->when));
	if (mode_read(mbuf, sizeof(mbuf), &has_file) != 0) {
		set_err(err, errlen, "读 mode 失败");
		return -1;
	}
	snprintf(s->mode, sizeof(s->mode), "%s", mbuf);

	for (i = 0; i < (int)ARRAY_SIZE(g_knobs); i++) {
		const struct ai_sched_knob *k = &g_knobs[i];
		char v[SCHED_VALUE_MAX];

		if (k->kind == AI_SCHED_KNOB_MODE)
			continue;
		if (k->kind == AI_SCHED_KNOB_CGROUP) {
			if (cg_read(k, v, sizeof(v)) == 0 && v[0]) {
				snprintf(s->items[s->n].knob, 32, "%s", k->name);
				snprintf(s->items[s->n].value,
					 SCHED_VALUE_MAX, "%s", v);
				s->n++;
			} else if (s->na_n < SCHED_SNAP_MAX_NA) {
				snprintf(s->na[s->na_n++], 32, "%s", k->name);
			}
			continue;
		}
		/* 任务级：只快照全局的 timeslice（per-pid 参数不可快照） */
		if (strcmp(k->name, "timeslice") == 0) {
			if (task_readback(k, (long long)getpid(), v,
					  sizeof(v)) == 0 && v[0]) {
				snprintf(s->items[s->n].knob, 32, "%s", k->name);
				snprintf(s->items[s->n].value,
					 SCHED_VALUE_MAX, "%s", v);
				s->n++;
			} else if (s->na_n < SCHED_SNAP_MAX_NA) {
				snprintf(s->na[s->na_n++], 32, "%s", k->name);
			}
		}
	}
	return 0;
}

static int snap_path(unsigned long long ts, char *buf, size_t cap)
{
	int n = snprintf(buf, cap, "%.450s/snap-%llu.json", state_dir(), ts);

	return (n > 0 && n < (int)cap) ? 0 : -1;
}

static int snap_write(const struct sched_snapshot *s, char *path, size_t cap,
		      char *err, size_t errlen)
{
	struct sbuf b;
	int i;
	char *esc;
	char p[SCHED_PATH_MAX];
	unsigned long long ts = s->epoch;
	int fd;

	if (state_dir_ensure(err, errlen) != 0)
		return -1;
	/* 同秒重复保存：追加序号避免覆盖 */
	for (;;) {
		if (snap_path(ts, p, sizeof(p)) != 0) {
			set_err(err, errlen, "快照路径过长");
			return -1;
		}
		if (!path_exists(p))
			break;
		ts++;
	}
	snprintf(path, cap, "%s", p);
	if (sb_init(&b) != 0) {
		set_err(err, errlen, "内存不足");
		return -1;
	}
	sb_add(&b, "{\n  \"schema\": \"aik-sched-snap/1\",\n");
	sb_add(&b, "  \"ts\": %llu,\n", s->epoch);
	sb_add(&b, "  \"time\": \"%s\",\n", s->when);
	sb_add(&b, "  \"mode\": \"%s\",\n", s->mode);
	sb_add(&b, "  \"cgroup\": \"%s\",\n", cg_dir());
	sb_add(&b, "  \"params\": {\n");
	for (i = 0; i < s->n; i++) {
		esc = ai_json_escape(s->items[i].value);
		sb_add(&b, "    \"%s\": \"%s\"%s\n", s->items[i].knob,
		       esc ? esc : "", i + 1 < s->n ? "," : "");
		free(esc);
	}
	sb_add(&b, "  },\n");
	sb_add(&b, "  \"unavailable\": [");
	for (i = 0; i < s->na_n; i++)
		sb_add(&b, "%s\"%s\"", i ? ", " : "", s->na[i]);
	sb_add(&b, "],\n");
	sb_add(&b, "  \"note\": \"per-pid task knobs (nice/affinity/oom_score) are not captured\"\n}\n");

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0) {
		set_err(err, errlen, "创建 %s 失败：%s", path, strerror(errno));
		sb_free(&b);
		return -1;
	}
	if (write(fd, b.p, b.len) != (ssize_t)b.len) {
		set_err(err, errlen, "写 %s 失败：%s", path, strerror(errno));
		close(fd);
		unlink(path);
		sb_free(&b);
		return -1;
	}
	close(fd);
	(void)chmod(path, 0600);
	sb_free(&b);
	return 0;
}

static int snap_parse(const char *text, struct sched_snapshot *s,
		      char *err, size_t errlen)
{
	const char *v;
	size_t vl;
	int vt, i;
	long long ts;
	size_t len = strlen(text);

	memset(s, 0, sizeof(*s));
	if (ai_json_obj_get(text, len, "schema", &v, &vl, &vt) != 1 ||
	    vt != AI_JSON_STR || vl < 5 ||
	    strncmp(v + 1, "aik-sched-snap/1", 16) != 0) {
		set_err(err, errlen, "不是 aik-sched-snap/1 快照");
		return -1;
	}
	if (ai_json_obj_get(text, len, "ts", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_NUM) {
		ts = ai_json_ll(v, vl);
		s->epoch = (unsigned long long)ts;
	}
	if (ai_json_obj_get(text, len, "time", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_STR) {
		char *str = ai_json_strdup_str(v, vl);

		if (str) {
			snprintf(s->when, sizeof(s->when), "%s", str);
			free(str);
		}
	}
	if (ai_json_obj_get(text, len, "mode", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_STR) {
		char *str = ai_json_strdup_str(v, vl);

		if (str) {
			snprintf(s->mode, sizeof(s->mode), "%s", str);
			free(str);
		}
	}
	if (!ai_sched_valid_mode(s->mode))
		snprintf(s->mode, sizeof(s->mode), "%s", SCHED_MODE_OFF);
	if (ai_json_obj_get(text, len, "params", &v, &vl, &vt) != 1 ||
	    vt != AI_JSON_OBJ) {
		set_err(err, errlen, "快照缺 params 对象");
		return -1;
	}
	for (i = 0; i < SCHED_SNAP_MAX_KNOBS; i++) {
		const char *key, *val;
		size_t klen, vlen;
		int vtype;
		char *kn, *vv;
		int rc = ai_json_obj_member(v, vl, i, &key, &klen, &val, &vlen,
					    &vtype);

		if (rc == 0)
			break;
		if (rc < 0 || vtype != AI_JSON_STR)
			continue;
		kn = ai_json_strdup_str(key, klen);
		vv = ai_json_strdup_str(val, vlen);
		if (kn && vv) {
			snprintf(s->items[s->n].knob, 32, "%s", kn);
			snprintf(s->items[s->n].value, SCHED_VALUE_MAX, "%s",
				 vv);
			s->n++;
		}
		free(kn);
		free(vv);
	}
	if (ai_json_obj_get(text, len, "unavailable", &v, &vl, &vt) == 1 &&
	    vt == AI_JSON_ARR) {
		int idx;

		for (idx = 0; idx < SCHED_SNAP_MAX_NA; idx++) {
			const char *e;
			size_t el;
			int et;
			char *str;

			if (ai_json_arr_get(v, vl, idx, &e, &el, &et) != 1)
				break;
			if (et != AI_JSON_STR)
				continue;
			str = ai_json_strdup_str(e, el);
			if (str) {
				snprintf(s->na[s->na_n++], 32, "%s", str);
				free(str);
			}
		}
	}
	return 0;
}

/* 应用快照（逐项写 + 读回）；返回 0 全部一致，-1 有失败（逐项结果在 log） */
static int snap_apply(const struct sched_snapshot *s, struct sbuf *log,
		      int *ok_n, int *fail_n, char *err, size_t errlen)
{
	int i;

	*ok_n = 0;
	*fail_n = 0;
	for (i = 0; i < s->n; i++) {
		int idx = ai_sched_knob_find(s->items[i].knob);
		struct apply_rec rec;
		char aerr[SCHED_VALUE_MAX];
		int rc;

		if (idx < 0) {
			sb_add(log, "  %-14s 未知旋钮（跳过）\n",
			       s->items[i].knob);
			(*fail_n)++;
			continue;
		}
		memset(&rec, 0, sizeof(rec));
		if (g_knobs[idx].kind == AI_SCHED_KNOB_TASK) {
			rc = task_apply(&g_knobs[idx], s->items[i].value,
					(long long)getpid(), &rec, aerr,
					sizeof(aerr));
			if (rc < 0) {
				sb_add(log, "  %-14s FAIL：%s\n",
				       g_knobs[idx].name, aerr);
				(*fail_n)++;
				continue;
			}
			sb_add(log, "  %-14s → %s（读回一致）\n",
			       g_knobs[idx].name, rec.after);
			(*ok_n)++;
			continue;
		}
		rc = cg_apply(&g_knobs[idx], s->items[i].value, &rec, aerr,
			      sizeof(aerr));
		if (rc < 0) {
			sb_add(log, "  %-14s FAIL：%s\n", g_knobs[idx].name,
			       aerr);
			(*fail_n)++;
			continue;
		}
		if (rc == 1) {
			/* 快照里的值本该可写；文件消失/不支持视为恢复失败 */
			sb_add(log, "  %-14s FAIL（N/A）：%s\n",
			       g_knobs[idx].name, aerr);
			(*fail_n)++;
			continue;
		}
		if (rc == 2) {
			sb_add(log,
			       "  %-14s %s → 已清空（读回无限制行）\n",
			       g_knobs[idx].name, rec.before);
			(*ok_n)++;
			continue;
		}
		sb_add(log, "  %-14s %s → %s（读回一致）\n", g_knobs[idx].name,
		       rec.before, rec.after);
		(*ok_n)++;
	}
	if (mode_write(s->mode, err, errlen) != 0) {
		sb_add(log, "  %-14s FAIL：%s\n", "sched.mode", err);
		(*fail_n)++;
	} else {
		sb_add(log, "  %-14s → %s\n", "sched.mode", s->mode);
		(*ok_n)++;
	}
	return (*fail_n == 0) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* 通用：读全部参数（status / ab 报告用）                               */
/* ------------------------------------------------------------------ */

static void dump_knob_line(struct sbuf *b, const struct ai_sched_knob *k,
			   long long pid)
{
	char v[SCHED_VALUE_MAX * 2];

	if (k->kind == AI_SCHED_KNOB_MODE) {
		char m[16];
		int hf = 0;

		mode_read(m, sizeof(m), &hf);
		sb_add(b, "  %-14s %-42s 当前=%s%s\n", k->name, k->range, m,
		       hf ? "" : "（无状态文件=默认）");
		return;
	}
	if (k->kind == AI_SCHED_KNOB_TASK) {
		if (!k->is_task) {
			/* 全局参数（timeslice）：与 pid 无关，直接读当前值 */
			if (task_readback(k, (long long)getpid(), v,
					  sizeof(v)) == 0)
				sb_add(b, "  %-14s %-42s 当前=%s（全局）\n",
				       k->name, k->range, v);
			else
				sb_add(b, "  %-14s %-42s 当前=N/A（读回不可用）\n",
				       k->name, k->range);
			return;
		}
		if (pid > 0) {
			if (task_readback(k, pid, v, sizeof(v)) == 0)
				sb_add(b, "  %-14s %-42s pid=%lld 当前=%s\n",
				       k->name, k->range, pid, v);
			else
				sb_add(b, "  %-14s %-42s pid=%lld 当前=N/A（读回不可用）\n",
				       k->name, k->range, pid);
		} else {
			sb_add(b, "  %-14s %-42s 当前=N/A（按 pid 生效，传 pid 可读）\n",
			       k->name, k->range);
		}
		return;
	}
	if (cg_read(k, v, sizeof(v)) == 0) {
		size_t x;

		for (x = 0; v[x]; x++)
			if (v[x] == '\n')
				v[x] = '|';
		if (!v[0])
			snprintf(v, sizeof(v), "(空=无限制/默认)");
		sb_add(b, "  %-14s %-42s 当前=%s\n", k->name, k->range, v);
	} else
		sb_add(b, "  %-14s %-42s 当前=N/A（%s）\n", k->name, k->range,
		       path_exists(cg_dir()) ? "文件不存在/不可读"
					     : "cgroup 未创建");
}

static int read_psi(const char *res, char *buf, size_t cap)
{
	char path[64];

	snprintf(path, sizeof(path), "/proc/pressure/%s", res);
	if (read_text(path, buf, cap) != 0)
		return -1;
	/* 多行 → 单行 */
	{
		size_t i;

		for (i = 0; buf[i]; i++)
			if (buf[i] == '\n')
				buf[i] = '|';
	}
	return 0;
}

/* 列出最近快照（按文件名倒序） */
static int snap_list(char names[][64], int max)
{
	DIR *d = opendir(state_dir());
	struct dirent *e;
	int n = 0;

	if (!d)
		return 0;
	while ((e = readdir(d)) && n < max) {
		if (strncmp(e->d_name, "snap-", 5) != 0)
			continue;
		if (strlen(e->d_name) >= 64)
			continue;
		snprintf(names[n], 64, "%s", e->d_name);
		n++;
	}
	closedir(d);
	/* 名字带 10 位以上 epoch：字典序 == 时间序；冒泡倒排（n 小） */
	{
		int i, j;

		for (i = 0; i < n; i++)
			for (j = i + 1; j < n; j++)
				if (strcmp(names[i], names[j]) < 0) {
					char t[64];

					memcpy(t, names[i], 64);
					memcpy(names[i], names[j], 64);
					memcpy(names[j], t, 64);
				}
	}
	return n;
}

/* ------------------------------------------------------------------ */
/* NETLINK_AI 可用性自检（sched_status 用）                             */
/* ------------------------------------------------------------------ */

/*
 * 只看 /proc/ai/control 存在是不够的：socket/bind/REG 任何一层失败，
 * ACT 都会不可用。这里做一次真实握手（REG 只登记本进程 portid，幂等，
 * 不改任何调度参数），失败时把确切的返回码/errno 交给 status 展示。
 * 返回 0=可用，-1=不可用（reason 填原因）。
 */
static int nl_probe(char *reason, size_t cap)
{
	struct ai_nl_client cli;
	int kern_err = 0, rc, e;
	__s32 ai_err = 0;
	__u32 count = 0;

	if (!path_exists("/proc/ai/control")) {
		set_err(reason, cap, "无 /proc/ai/control（非 AIKernel 内核）");
		return -1;
	}
	memset(&cli, 0, sizeof(cli));
	cli.fd = -1;
	errno = 0;
	rc = ai_nl_client_open(&cli);
	e = errno;
	if (rc != AI_OK) {
		set_err(reason, cap,
			"NETLINK_AI 打开失败：%s（errno=%d %s）",
			ai_error_string(rc), e, e ? strerror(e) : "-");
		return -1;
	}
	rc = ai_nl_send_reg(&cli, 0, &ai_err, &count, &kern_err);
	ai_nl_client_close(&cli);
	if (rc != AI_OK) {
		const char *hint = ai_nl_errno_hint(kern_err);

		set_err(reason, cap,
			"REG 握手失败：%s（ai_err=%d kern_errno=%d %s%s%s）",
			ai_error_string(rc), ai_err, kern_err,
			kern_err ? strerror(kern_err) : "-",
			hint ? "；" : "", hint ? hint : "");
		return -1;
	}
	set_err(reason, cap, "REG 握手通过，内核已登记 portid 数=%u", count);
	return 0;
}

/* ------------------------------------------------------------------ */
/* sched_status                                                        */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* 参数解析                                                             */
/* ------------------------------------------------------------------ */

static char *arg_str(const char *args_json, const char *key)
{
	const char *v;
	size_t vl;
	int vt;

	if (!args_json || !args_json[0])
		return NULL;
	if (ai_json_obj_get(args_json, strlen(args_json), key, &v, &vl,
			    &vt) == 1) {
		if (vt == AI_JSON_STR)
			return ai_json_strdup_str(v, vl);
		return strndup(v, vl);
	}
	return NULL;
}

static long long arg_ll(const char *args_json, const char *key, long long def)
{
	const char *v;
	size_t vl;
	int vt;

	if (!args_json || !args_json[0])
		return def;
	if (ai_json_obj_get(args_json, strlen(args_json), key, &v, &vl,
			    &vt) == 1 && vt == AI_JSON_NUM)
		return ai_json_ll(v, vl);
	return def;
}

/* ------------------------------------------------------------------ */
/* sched_status（R）                                                    */
/* ------------------------------------------------------------------ */

static int cmd_status(const char *args_json, char **out)
{
	struct sbuf b;
	char mode[16];
	int has_file = 0;
	char psi[3][SCHED_VALUE_MAX * 2];
	char cur[SCHED_VALUE_MAX];
	const char *psi_names[3] = { "cpu", "memory", "io" };
	long long pid = arg_ll(args_json, "pid", 0);
	char names[SCHED_SNAP_LIST_MAX][64];
	int nsnap, i;
	char path[SCHED_PATH_MAX];

	if (pid < 0)
		pid = 0;
	if (sb_init(&b) != 0)
		return AI_ERR_MEMORY;

	mode_read(mode, sizeof(mode), &has_file);
	sb_add(&b, "== AIKernel 双调度台状态 ==\n");
	if (mode_path(path, sizeof(path)) == 0) {
		struct stat st;

		if (has_file && stat(path, &st) == 0)
			sb_add(&b, "mode:             %s（真读 %s，%lld 字节）\n",
			       mode, path, (long long)st.st_size);
		else
			sb_add(&b, "mode:             %s（无状态文件 %s：内核默认态）\n",
			       mode, path);
	}
	sb_add(&b, "ml 台:            未就绪（W83）——当前可用 static|off；sched_mode_set ml 会被明确拒绝\n");
	{
		char reason[SCHED_VALUE_MAX * 2];

		if (nl_probe(reason, sizeof(reason)) == 0)
			sb_add(&b, "netlink-ai:       可用（%s）\n", reason);
		else
			sb_add(&b,
			       "netlink-ai:       unavailable（%s）——任务级旋钮会被明确拒绝，绝不假成功\n",
			       reason);
	}
	if (is_dir(cg_dir())) {
		char ctrl[SCHED_PATH_MAX], list[SCHED_VALUE_MAX];

		snprintf(ctrl, sizeof(ctrl), "%.470s/cgroup.controllers", cg_dir());
		if (read_text(ctrl, list, sizeof(list)) == 0)
			sb_add(&b, "cgroup:           %s（存在；controllers=%s）\n",
			       cg_dir(), list);
		else
			sb_add(&b, "cgroup:           %s（存在；controllers 不可读）\n",
			       cg_dir());
	} else {
		sb_add(&b, "cgroup:           %s（未创建；首次 knob_set/ab_run 时创建）\n",
		       cg_dir());
	}
	{
		char sub[SCHED_VALUE_MAX];

		snprintf(path, sizeof(path), "%s/cgroup.subtree_control",
			 cg_root());
		if (read_text(path, sub, sizeof(sub)) == 0)
			sb_add(&b, "root 控制器:      %s（%s）\n", sub, path);
	}
	sb_add(&b, "CPU:              %ld 核在线\n",
	       sysconf(_SC_NPROCESSORS_ONLN));
	if (read_text("/proc/loadavg", cur, sizeof(cur)) == 0)
		sb_add(&b, "loadavg:          %s\n", cur);
	sb_add(&b, "\n--- PSI（/proc/pressure，some/full；total 单位 us）---\n");
	for (i = 0; i < 3; i++) {
		if (read_psi(psi_names[i], psi[i], sizeof(psi[i])) == 0)
			sb_add(&b, "%-8s %s\n", psi_names[i], psi[i]);
		else
			sb_add(&b, "%-8s N/A（/proc/pressure/%s 不可读）\n",
			       psi_names[i], psi_names[i]);
	}
	sb_add(&b, "\n--- 旋钮（当前值全部真读文件/内核接口）---\n");
	sb_add(&b, "[任务级 · NETLINK_AI ACT，按 pid 生效]\n");
	for (i = 0; i < ai_sched_knob_count(); i++)
		if (g_knobs[i].kind == AI_SCHED_KNOB_TASK)
			dump_knob_line(&b, &g_knobs[i], pid);
	sb_add(&b, "[cgroup 级 · %s]\n", cg_dir());
	for (i = 0; i < ai_sched_knob_count(); i++)
		if (g_knobs[i].kind == AI_SCHED_KNOB_CGROUP)
			dump_knob_line(&b, &g_knobs[i], pid);
	sb_add(&b, "[台子]\n");
	for (i = 0; i < ai_sched_knob_count(); i++)
		if (g_knobs[i].kind == AI_SCHED_KNOB_MODE)
			dump_knob_line(&b, &g_knobs[i], pid);
	nsnap = snap_list(names, SCHED_SNAP_LIST_MAX);
	sb_add(&b, "\n--- 快照（最近 %d 条，%s）---\n", nsnap, state_dir());
	if (nsnap == 0)
		sb_add(&b, "  （无）\n");
	for (i = 0; i < nsnap && i < 5; i++)
		sb_add(&b, "  %s\n", names[i]);

	*out = b.p;
	return AI_OK;
}

/* ------------------------------------------------------------------ */
/* sched_knob_set（W1）                                                 */
/* ------------------------------------------------------------------ */

static int mode_set_impl(const char *mode, char **out);

static int cmd_knob_set(const char *args_json, char **out)
{
	char *knob = arg_str(args_json, "knob");
	char *value = arg_str(args_json, "value");
	long long pid = arg_ll(args_json, "pid", 0);
	char err[SCHED_VALUE_MAX * 2] = "";
	struct apply_rec rec;
	int idx, rc, ret = AI_OK;

	if (!knob || !knob[0] || !value || !value[0]) {
		*out = strdup("ERROR: 需要 knob 与 value 参数"
			      "（可用旋钮见 sched_status）");
		free(knob);
		free(value);
		return AI_ERR_INVALID_ARG;
	}
	idx = ai_sched_knob_find(knob);
	if (idx < 0) {
		struct sbuf b;

		if (sb_init(&b) == 0) {
			int i;

			sb_add(&b, "ERROR: 未知旋钮 \"%s\"。可用旋钮：", knob);
			for (i = 0; i < ai_sched_knob_count(); i++)
				sb_add(&b, "%s%s", i ? ", " : "",
				       g_knobs[i].name);
			sb_add(&b, "\n");
			*out = b.p;
		} else {
			*out = strdup("ERROR: 未知旋钮");
		}
		free(knob);
		free(value);
		return AI_ERR_INVALID_ARG;
	}
	/* sched.mode 本身也是一个可写旋钮：走同一套"快照→应用→读回" */
	if (g_knobs[idx].kind == AI_SCHED_KNOB_MODE) {
		ret = mode_set_impl(value, out);
		free(knob);
		free(value);
		return ret;
	}
	if (ai_sched_validate_value(&g_knobs[idx], value, err, sizeof(err))
	    != 0) {
		if (asprintf(out, "ERROR: %s", err) < 0)
			*out = NULL;
		free(knob);
		free(value);
		return AI_ERR_INVALID_ARG;
	}
	memset(&rec, 0, sizeof(rec));
	if (g_knobs[idx].kind == AI_SCHED_KNOB_TASK) {
		rc = task_apply(&g_knobs[idx], value, pid, &rec, err,
				sizeof(err));
	} else {
		char derr[SCHED_VALUE_MAX];

		if (cg_dir_ensure(derr, sizeof(derr)) != 0) {
			snprintf(err, sizeof(err), "%s", derr);
			rc = -1;
		} else {
			rc = cg_apply(&g_knobs[idx], value, &rec, err,
				      sizeof(err));
		}
	}
	if (rc == 1) {
		/* C2：文件不存在 = 该内核/设备不支持。明确 N/A 并判失败，
		 * 绝不返回 OK（历史上这里会落到下面的成功分支报"写后读回一致"）。 */
		if (asprintf(out, "N/A: %s 未写入：%s", knob, err) < 0)
			*out = NULL;
		free(knob);
		free(value);
		return AI_ERR_NOT_IMPLEMENTED;
	}
	if (rc < 0) {
		if (asprintf(out, "ERROR: %s 写入失败：%s", knob, err) < 0)
			*out = NULL;
		free(knob);
		free(value);
		return AI_ERR_API;
	}
	if (rc == 2) {
		if (asprintf(out,
			     "OK: %s %s → 已清空（读回无限制行；文件存在且可写，"
			     "此为「清空」状态，不是「一致」判定）\n"
			     "  机制: cgroup v2 控制文件\n  值域: %s\n",
			     knob, rec.before[0] ? rec.before : "(空)",
			     g_knobs[idx].range) < 0)
			*out = NULL;
		free(knob);
		free(value);
		return AI_OK;
	}
	{
		char tail[64] = "";

		if (g_knobs[idx].kind == AI_SCHED_KNOB_TASK)
			snprintf(tail, sizeof(tail), " pid=%lld", pid);
		if (asprintf(out,
			     "OK: %s %s → %s（写后读回一致）%s\n"
			     "  机制: %s\n  值域: %s\n",
			     knob,
			     rec.before[0] ? rec.before : "(空)",
			     rec.after[0] ? rec.after : "(空)",
			     tail,
			     g_knobs[idx].kind == AI_SCHED_KNOB_TASK ?
			     "NETLINK_AI ACT（param 定向）" :
			     "cgroup v2 控制文件",
			     g_knobs[idx].range) < 0)
			*out = NULL;
	}
	free(knob);
	free(value);
	return AI_OK;
}


/* ------------------------------------------------------------------ */
/* sched_mode_set（W2）：static | ml | off                              */
/* ------------------------------------------------------------------ */

/* switch 后独立复验：按目标参数集逐项真读当前值并比对 */
static int param_verify(const char *which, struct sbuf *log, int *ok_n,
			int *fail_n)
{
	char dev[64];
	char iomax[SCHED_VALUE_MAX];
	const char *knobs[6];
	const char *vals[6];
	int n = 0, i;

	*ok_n = 0;
	*fail_n = 0;
	if (strcmp(which, SCHED_MODE_STATIC) == 0) {
		knobs[n] = "cpu.weight"; vals[n++] = "100";
		knobs[n] = "cpu.max"; vals[n++] = "50000 100000";
		knobs[n] = "cpu.max.burst"; vals[n++] = "0";
		knobs[n] = "io.weight"; vals[n++] = "default 100";
		if (root_disk_dev(dev, sizeof(dev)) == 0) {
			snprintf(iomax, sizeof(iomax),
				 "%s rbps=16777216 wbps=16777216", dev);
			knobs[n] = "io.max"; vals[n++] = iomax;
		}
	} else {
		knobs[n] = "cpu.max"; vals[n++] = "max 100000";
		knobs[n] = "cpu.weight"; vals[n++] = "100";
		knobs[n] = "cpu.max.burst"; vals[n++] = "0";
		knobs[n] = "io.weight"; vals[n++] = "default 100";
		if (root_disk_dev(dev, sizeof(dev)) == 0) {
			snprintf(iomax, sizeof(iomax),
				 "%s rbps=max wbps=max riops=max wiops=max",
				 dev);
			knobs[n] = "io.max"; vals[n++] = iomax;
		}
	}
	for (i = 0; i < n; i++) {
		int idx = ai_sched_knob_find(knobs[i]);
		char got[SCHED_VALUE_MAX * 2];

		if (idx < 0) {
			(*fail_n)++;
			continue;
		}
		if (cg_read(&g_knobs[idx], got, sizeof(got)) != 0) {
			sb_add(log, "  %-14s 复验 N/A（文件不可读；该内核不支持）\n",
			       knobs[i]);
			continue;
		}
		if (!got[0]) {
			/* 空读回：io.max 全 max 清空请求视为"已清空"（不是一致），
			 * 其余一律复验失败（写入未生效）。 */
			if (strcmp(knobs[i], "io.max") == 0 &&
			    iomax_is_clear(vals[i])) {
				sb_add(log,
				       "  %-14s 复验：已清空（读回无限制行）\n",
				       knobs[i]);
				(*ok_n)++;
			} else {
				sb_add(log,
				       "  %-14s 复验失败：读回为空，写入未生效\n",
				       knobs[i]);
				(*fail_n)++;
			}
			continue;
		}
		if (ai_sched_value_match(&g_knobs[idx], vals[i], got) == 0) {
			sb_add(log, "  %-14s 复验一致 = %s\n", knobs[i], got);
			(*ok_n)++;
		} else {
			sb_add(log, "  %-14s 复验不一致：期望 %s 实际 %s\n",
			       knobs[i], vals[i], got);
			(*fail_n)++;
		}
	}
	return *fail_n ? -1 : 0;
}

static int mode_set_impl(const char *mode, char **out)
{
	struct sched_snapshot pre;
	char snapfile[SCHED_PATH_MAX] = "";
	char err[SCHED_VALUE_MAX * 2] = "";
	char tmp_err[SCHED_VALUE_MAX * 2];
	struct sbuf log = { 0 };
	int rc, ok_n = 0, fail_n = 0;

	if (!ai_sched_valid_mode(mode)) {
		if (asprintf(out, "ERROR: 无效 mode \"%s\"（只接受 static|ml|off）",
			     mode ? mode : "") < 0)
			*out = NULL;
		return AI_ERR_INVALID_ARG;
	}
	/* C2：ml 台未交付（W83）——必须明确拒绝，绝不假成功；零状态变更 */
	if (strcmp(mode, SCHED_MODE_ML) == 0) {
		*out = strdup(
			"ERROR: ml 台未就绪（计划 W83 交付），拒绝切换——本工具"
			"绝不假成功。当前可用：static | off。\n"
			"  static = 规则/固定参数台（cpu.max=50000 100000、"
			"cpu.weight=100、cpu.max.burst=0、io.max=16MiB/s，"
			"实验子进程 nice=10）；\n"
			"  off    = 撤销 AI 施加的全部调度参数，回到内核默认"
			"（cpu.max=max 100000、cpu.weight=100、io.max 清空等）。\n"
			"  本次调用未做任何快照/写入/切换（mode 保持原值）。");
		return AI_ERR_NOT_IMPLEMENTED;
	}
	if (sb_init(&log) != 0)
		return AI_ERR_MEMORY;

	/* 1. 切换前自动快照（落盘 0600，失败则不切换） */
	if (snap_collect(&pre, err, sizeof(err)) != 0 ||
	    snap_write(&pre, snapfile, sizeof(snapfile), err,
		       sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: 切换前快照失败，已中止切换：%s",
			     err) < 0)
			*out = NULL;
		sb_free(&log);
		return AI_ERR_STORAGE;
	}
	/* 2. 应用目标参数集（逐项 预检→写→读回） */
	if (param_set_apply(mode, &log, err, sizeof(err)) != 0) {
		struct sbuf rl = { 0 };
		int r_ok = 0, r_fail = 0;

		if (sb_init(&rl) == 0) {
			(void)snap_apply(&pre, &rl, &r_ok, &r_fail, err,
					 sizeof(err));
			sb_free(&rl);
		}
		if (asprintf(out,
			     "ERROR: mode=%s 应用失败，已按切换前快照回滚（%d 项一致）：%s\n%s",
			     mode, r_ok, err, log.p ? log.p : "") < 0)
			*out = NULL;
		sb_free(&log);
		return AI_ERR_API;
	}
	/* 3. 独立复验（再次真读）*/
	rc = param_verify(mode, &log, &ok_n, &fail_n);
	/* 4. 写 mode（台子标签）*/
	snprintf(tmp_err, sizeof(tmp_err), "%s", err);
	if (rc == 0 && mode_write(mode, err, sizeof(err)) != 0) {
		snprintf(tmp_err, sizeof(tmp_err), "写 mode 状态文件失败：%s",
			 err);
		snprintf(err, sizeof(err), "%s", tmp_err);
		rc = -1;
	}
	if (rc != 0) {
		struct sbuf rl = { 0 };
		int r_ok = 0, r_fail = 0;

		if (sb_init(&rl) == 0) {
			(void)snap_apply(&pre, &rl, &r_ok, &r_fail, err,
					 sizeof(err));
			sb_free(&rl);
		}
		if (asprintf(out,
			     "ERROR: mode=%s 复验/落盘失败，已回滚到切换前快照（%d 项一致）：%s\n%s",
			     mode, r_ok, err, log.p ? log.p : "") < 0)
			*out = NULL;
		sb_free(&log);
		return AI_ERR_API;
	}
	if (asprintf(out,
		     "OK: mode → %s（切换前快照 %s；复验 %d 项一致，%d 项失败）\n%s",
		     mode, snapfile, ok_n, fail_n, log.p ? log.p : "") < 0)
		*out = NULL;
	sb_free(&log);
	return AI_OK;
}

/* ------------------------------------------------------------------ */
/* sched_snapshot（W1）：save / list / restore                          */
/* ------------------------------------------------------------------ */

/* 把 "1761..." / "snap-1761....json" / "latest" 解析为实际快照路径 */
static int snap_resolve(const char *id, char *path, size_t cap,
			char *err, size_t errlen)
{
	char names[SCHED_SNAP_LIST_MAX][64];
	int n;

	if (!id || !id[0] || strcmp(id, "latest") == 0) {
		n = snap_list(names, SCHED_SNAP_LIST_MAX);
		if (n == 0) {
			set_err(err, errlen, "没有可用快照（先 save 或 mode_set）");
			return -1;
		}
		snprintf(path, cap, "%.430s/%s", state_dir(), names[0]);
		return 0;
	}
	{
		char tmp[SCHED_PATH_MAX];

		if (strncmp(id, "snap-", 5) == 0 || strstr(id, ".json"))
			snprintf(tmp, sizeof(tmp), "%.430s/%.60s", state_dir(),
				 id);
		else
			snprintf(tmp, sizeof(tmp), "%.400s/snap-%.60s.json",
				 state_dir(), id);
		if (copy_str(path, cap, tmp) != 0) {
			set_err(err, errlen, "快照路径过长");
			return -1;
		}
	}
	if (!path_exists(path)) {
		set_err(err, errlen, "快照不存在：%s", path);
		return -1;
	}
	return 0;
}

static int cmd_snapshot(const char *args_json, char **out)
{
	char *action = arg_str(args_json, "action");
	char *id = arg_str(args_json, "id");
	char err[SCHED_VALUE_MAX * 2] = "";
	int ret = AI_OK;

	if (!action || !action[0]) {
		*out = strdup("ERROR: 需要 action 参数（save | list | restore）");
		free(action);
		free(id);
		return AI_ERR_INVALID_ARG;
	}
	if (strcmp(action, "save") == 0) {
		struct sched_snapshot s;
		char path[SCHED_PATH_MAX];
		struct sbuf b;
		int i;

		if (snap_collect(&s, err, sizeof(err)) != 0 ||
		    snap_write(&s, path, sizeof(path), err, sizeof(err)) != 0) {
			if (asprintf(out, "ERROR: 保存快照失败：%s", err) < 0)
				*out = NULL;
			free(action);
			free(id);
			return AI_ERR_STORAGE;
		}
		if (sb_init(&b) != 0) {
			free(action);
			free(id);
			return AI_ERR_MEMORY;
		}
		sb_add(&b, "OK: 快照已保存 %s（0600）\n  mode=%s\n",
		       path, s.mode);
		for (i = 0; i < s.n; i++)
			sb_add(&b, "  %-14s = %s\n", s.items[i].knob,
			       s.items[i].value);
		for (i = 0; i < s.na_n; i++)
			sb_add(&b, "  %-14s = N/A（不可读，未入快照）\n",
			       s.na[i]);
		*out = b.p;
	} else if (strcmp(action, "list") == 0) {
		char names[SCHED_SNAP_LIST_MAX][64];
		struct sbuf b;
		int n, i;

		n = snap_list(names, SCHED_SNAP_LIST_MAX);
		if (sb_init(&b) != 0) {
			free(action);
			free(id);
			return AI_ERR_MEMORY;
		}
		sb_add(&b, "OK: %d 个快照（%.430s，按时间倒序）\n", n, state_dir());
		for (i = 0; i < n; i++) {
			char full[SCHED_PATH_MAX], text[8192];
			struct sched_snapshot s;
			char perr[SCHED_VALUE_MAX];

			{
				char tmp[SCHED_PATH_MAX];

				snprintf(tmp, sizeof(tmp), "%.430s/%.63s",
					 state_dir(), names[i]);
				if (copy_str(full, sizeof(full), tmp) != 0)
					continue;
			}
			if (read_text(full, text, sizeof(text)) != 0 ||
			    snap_parse(text, &s, perr, sizeof(perr)) != 0) {
				sb_add(&b, "  %s（解析失败）\n", names[i]);
				continue;
			}
			sb_add(&b, "  %s  %s  mode=%s  %d 项\n", names[i],
			       s.when, s.mode, s.n);
		}
		*out = b.p;
	} else if (strcmp(action, "restore") == 0) {
		char path[SCHED_PATH_MAX], text[16384];
		struct sched_snapshot s;
		struct sbuf log = { 0 };
		int ok_n = 0, fail_n = 0, rc;

		if (snap_resolve(id, path, sizeof(path), err, sizeof(err)) != 0) {
			if (asprintf(out, "ERROR: %s", err) < 0)
				*out = NULL;
			free(action);
			free(id);
			return AI_ERR_NOT_FOUND;
		}
		if (read_text(path, text, sizeof(text)) != 0) {
			if (asprintf(out, "ERROR: 读快照 %s 失败：%s", path,
				     strerror(errno)) < 0)
				*out = NULL;
			free(action);
			free(id);
			return AI_ERR_STORAGE;
		}
		if (snap_parse(text, &s, err, sizeof(err)) != 0) {
			if (asprintf(out, "ERROR: 解析快照失败：%s", err) < 0)
				*out = NULL;
			free(action);
			free(id);
			return AI_ERR_PARSE;
		}
		if (cg_dir_ensure(err, sizeof(err)) != 0) {
			if (asprintf(out, "ERROR: %s", err) < 0)
				*out = NULL;
			free(action);
			free(id);
			return AI_ERR_API;
		}
		if (sb_init(&log) != 0) {
			free(action);
			free(id);
			return AI_ERR_MEMORY;
		}
		sb_add(&log, "  快照 %s（%s，mode=%s）\n", path, s.when, s.mode);
		rc = snap_apply(&s, &log, &ok_n, &fail_n, err, sizeof(err));
		if (asprintf(out,
			     "%s: restore %s → %d 项读回一致，%d 项失败\n%s",
			     rc == 0 ? "OK" : "ERROR", path, ok_n, fail_n,
			     log.p ? log.p : "") < 0)
			*out = NULL;
		sb_free(&log);
		ret = rc == 0 ? AI_OK : AI_ERR_API;
	} else {
		if (asprintf(out, "ERROR: 未知 action \"%s\"（save|list|restore）",
			     action) < 0)
			*out = NULL;
		ret = AI_ERR_INVALID_ARG;
	}
	free(action);
	free(id);
	return ret;
}

/* ------------------------------------------------------------------ */
/* 对照实验：内置负载 + 指标                                            */
/* ------------------------------------------------------------------ */

#define AB_IO_UNIT	(256 * 1024)	/* 单工作单元每向 IO 字节数 */
#define AB_IO_LOADS	2		/* 一次 IO 单元 = 写 + fsync + 读 */

struct ab_shm {
	unsigned long long units;
	unsigned long long bytes;
	unsigned int lat_n;
	int err;
	unsigned int lat_us[AB_LAT_MAX];
};

struct ab_result {
	char arm[16];
	char load[8];
	int workers;
	int ok;
	double wall_s;
	unsigned long long units;
	unsigned long long bytes;
	unsigned long long umin;
	unsigned long long umax;
	double cv;
	double p50_ms;
	double p99_ms;
	double max_ms;
	double energy_j;	/* < 0 = N/A */
	int child_err;
};

static volatile unsigned long long g_spin_sink;

/* 自旋负载（CPU 密集）：xorshift64，n 次 */
static unsigned long long spin_batch(unsigned long long n)
{
	unsigned long long x = 0x9e3779b97f4a7c15ULL;

	while (n--) {
		x ^= x << 13;
		x ^= x >> 7;
		x ^= x << 17;
	}
	return x;
}

/* 无 libm 的平方根（Newton；避免为一个开方引入 -lm） */
static double dsqrt(double x)
{
	double r;
	int i;

	if (x <= 0.0)
		return 0.0;
	r = x > 1.0 ? x : 1.0;
	for (i = 0; i < 40; i++)
		r = 0.5 * (r + x / r);
	return r;
}

/* 能耗代理：RAPL 包能量（µJ）；不可读返回 -1 */
static int rapl_read_uj(unsigned long long *out)
{
	static const char *const paths[] = {
		"/sys/class/powercap/intel-rapl:0/energy_uj",
		"/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj",
	};
	char buf[64];
	size_t i;

	for (i = 0; i < ARRAY_SIZE(paths); i++) {
		long long v;

		if (read_text(paths[i], buf, sizeof(buf)) != 0)
			continue;
		if (parse_ll(buf, &v) != 0 || v < 0)
			continue;
		*out = (unsigned long long)v;
		return 0;
	}
	return -1;
}

static int cmp_u32(const void *a, const void *b)
{
	unsigned int x = *(const unsigned int *)a;
	unsigned int y = *(const unsigned int *)b;

	return (x > y) - (x < y);
}

static void ab_kill_all(pid_t *pids, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if (pids[i] <= 0)
			continue;
		(void)kill(-pids[i], SIGKILL);
		(void)kill(pids[i], SIGKILL);
	}
	for (i = 0; i < n; i++) {
		int st;

		if (pids[i] <= 0)
			continue;
		(void)waitpid(pids[i], &st, 0);
		pids[i] = -1;
	}
}

/* 子进程：type 0=CPU 自旋，1=IO（pwrite+fdatasync+pread） */
static void ab_child(int type, int duration_s, long long batch, int nicev,
		     const char *path, struct ab_shm *shm, int gofd)
{
	unsigned char *buf = NULL;
	long long deadline;
	char go = 0;
	int fd = -1;

	(void)prctl(PR_SET_NAME, "aik-sched-ab", 0, 0, 0);
	(void)setpgid(0, 0);
	if (nicev != 0)
		(void)setpriority(PRIO_PROCESS, 0, nicev);
	if (read(gofd, &go, 1) != 1)
		_exit(2);
	if (posix_memalign((void **)&buf, 4096, AB_IO_UNIT) != 0) {
		shm->err = 1;
		_exit(3);
	}
	memset(buf, 0x5a, AB_IO_UNIT);
	if (type == 1) {
		fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
		if (fd < 0) {
			shm->err = 1;
			_exit(4);
		}
	}
	deadline = mono_us() + (long long)duration_s * 1000000LL;
	for (;;) {
		long long t0 = mono_us(), dt;

		if (t0 >= deadline)
			break;
		if (type == 1) {
			if (pwrite(fd, buf, AB_IO_UNIT, 0) != AB_IO_UNIT ||
			    fdatasync(fd) != 0 ||
			    pread(fd, buf, AB_IO_UNIT, 0) != AB_IO_UNIT) {
				shm->err = 1;
				break;
			}
			shm->bytes += (unsigned long long)AB_IO_UNIT *
				      AB_IO_LOADS;
		} else {
			g_spin_sink ^= spin_batch((unsigned long long)batch);
		}
		dt = mono_us() - t0;
		shm->units++;
		if (shm->lat_n < AB_LAT_MAX)
			shm->lat_us[shm->lat_n++] = (unsigned int)dt;
	}
	if (fd >= 0)
		close(fd);
	free(buf);
	_exit(0);
}

/* 单次（参数集 × 负载）测量；失败时 kill 全部子进程并返回 -1 */
static int ab_run_one(const char *arm, int type, int duration_s, int workers,
		      long long batch, int nicev, const char *workdir,
		      struct ab_result *res, char *err, size_t errlen)
{
	struct ab_shm *shm;
	size_t shm_len = sizeof(struct ab_shm) * (size_t)workers;
	pid_t pids[AB_WORKERS_MAX];
	int pipefd[2] = { -1, -1 };
	int i, npid = 0, rc = -1;
	long long t0 = 0, t1 = 0, deadline;
	unsigned long long e0 = 0, e1 = 0;
	int have_energy = 0, alive;

	memset(res, 0, sizeof(*res));
	snprintf(res->arm, sizeof(res->arm), "%s", arm);
	snprintf(res->load, sizeof(res->load), "%s", ai_sched_load_name(type));
	res->workers = workers;
	res->energy_j = -1.0;
	for (i = 0; i < AB_WORKERS_MAX; i++)
		pids[i] = -1;

	if (workers <= 0 || workers > AB_WORKERS_MAX) {
		set_err(err, errlen, "workers 越界（1-%d）", AB_WORKERS_MAX);
		return -1;
	}
	shm = mmap(NULL, shm_len, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shm == MAP_FAILED) {
		set_err(err, errlen, "共享内存分配失败：%s", strerror(errno));
		return -1;
	}
	memset(shm, 0, shm_len);
	if (pipe(pipefd) != 0) {
		set_err(err, errlen, "pipe 失败：%s", strerror(errno));
		munmap(shm, shm_len);
		return -1;
	}
	if (cg_dir_ensure(err, errlen) != 0)
		goto fail;
	if (rapl_read_uj(&e0) == 0)
		have_energy = 1;

	for (i = 0; i < workers; i++) {
		char wpath[SCHED_PATH_MAX];
		pid_t p;

		snprintf(wpath, sizeof(wpath), "%s/w%d.bin", workdir, i);
		p = fork();
		if (p < 0) {
			set_err(err, errlen, "fork 失败：%s", strerror(errno));
			goto fail;
		}
		if (p == 0) {
			int wtype = (type == 2) ? (i % 2) : type;

			close(pipefd[1]);
			ab_child(wtype, duration_s, batch, nicev, wpath,
				 &shm[i], pipefd[0]);
			_exit(0);
		}
		pids[npid++] = p;
		(void)setpgid(p, p);
	}
	/* 全部子进程先入 cgroup 再放行（否则起步阶段不受限额） */
	{
		char gopath[SCHED_PATH_MAX];

		snprintf(gopath, sizeof(gopath), "%.470s/cgroup.procs", cg_dir());
		for (i = 0; i < npid; i++) {
			char pidbuf[32];
			int fd, len;

			fd = open(gopath, O_WRONLY | O_CLOEXEC);
			if (fd < 0) {
				set_err(err, errlen,
					"打开 %s 失败：%s（需要 root）",
					gopath, strerror(errno));
				goto fail;
			}
			len = snprintf(pidbuf, sizeof(pidbuf), "%d",
				       (int)pids[i]);
			if (write(fd, pidbuf, (size_t)len) != len) {
				set_err(err, errlen,
					"把 pid %d 放入 cgroup 失败：%s",
					(int)pids[i], strerror(errno));
				close(fd);
				goto fail;
			}
			close(fd);
		}
	}
	t0 = mono_us();
	for (i = 0; i < npid; i++) {
		char c = 'g';
		ssize_t w;

		do {
			w = write(pipefd[1], &c, 1);
		} while (w < 0 && errno == EINTR);
		if (w != 1)
			break;
	}
	close(pipefd[1]);
	pipefd[1] = -1;
	deadline = t0 + (long long)(duration_s + 15) * 1000000LL;
	for (;;) {
		alive = 0;
		for (i = 0; i < npid; i++) {
			int st;
			pid_t w;

			if (pids[i] <= 0)
				continue;
			w = waitpid(pids[i], &st, WNOHANG);
			if (w == pids[i])
				pids[i] = -1;
			else if (w == 0)
				alive++;
		}
		if (alive == 0)
			break;
		if (mono_us() > deadline) {
			set_err(err, errlen,
				"负载超时（%ds + 15s 余量），已 SIGKILL 全部子进程",
				duration_s);
			goto fail;
		}
		usleep(5000);
	}
	t1 = mono_us();
	if (have_energy && rapl_read_uj(&e1) == 0 && e1 >= e0)
		res->energy_j = (double)(e1 - e0) / 1000000.0;

	/* 汇总：单元数 / 每子进程完成量 / 延迟样本 */
	{
		unsigned long long sum2 = 0, mean = 0;
		unsigned int *lats;
		size_t nl = 0, cap = (size_t)workers * AB_LAT_MAX;
		double var = 0.0;

		lats = malloc(cap * sizeof(unsigned int));
		if (!lats) {
			set_err(err, errlen, "延迟样本内存分配失败");
			goto fail_reaped;
		}
		res->umin = ~0ULL;
		for (i = 0; i < workers; i++) {
			unsigned int j;

			res->units += shm[i].units;
			res->bytes += shm[i].bytes;
			if (shm[i].err)
				res->child_err++;
			if (shm[i].units < res->umin)
				res->umin = shm[i].units;
			if (shm[i].units > res->umax)
				res->umax = shm[i].units;
			for (j = 0; j < shm[i].lat_n && nl < cap; j++)
				lats[nl++] = shm[i].lat_us[j];
		}
		if (res->umin == ~0ULL)
			res->umin = 0;
		res->wall_s = (double)(t1 - t0) / 1000000.0;
		if (res->wall_s <= 0.0)
			res->wall_s = 0.001;
		mean = res->units / (unsigned long long)workers;
		for (i = 0; i < workers; i++) {
			long long d = (long long)shm[i].units - (long long)mean;

			sum2 += (unsigned long long)(d * d);
		}
		if (mean > 0)
			var = (double)sum2 / (double)workers;
		res->cv = mean > 0 ? dsqrt(var) / (double)mean : 0.0;
		if (nl > 0) {
			size_t idx;

			qsort(lats, nl, sizeof(unsigned int), cmp_u32);
			res->p50_ms = lats[nl * 50 / 100] / 1000.0;
			idx = (size_t)((double)nl * 0.99);
			if (idx >= nl)
				idx = nl - 1;
			res->p99_ms = lats[idx] / 1000.0;
			res->max_ms = lats[nl - 1] / 1000.0;
		}
		free(lats);
	}
	for (i = 0; i < workers; i++) {
		char wpath[SCHED_PATH_MAX];

		snprintf(wpath, sizeof(wpath), "%s/w%d.bin", workdir, i);
		(void)unlink(wpath);
	}
	res->ok = 1;
	rc = 0;
	munmap(shm, shm_len);
	return rc;

fail_reaped:
	munmap(shm, shm_len);
	return -1;

fail:
	if (pipefd[1] >= 0)
		close(pipefd[1]);
	if (pipefd[0] >= 0)
		close(pipefd[0]);
	ab_kill_all(pids, npid);
	for (i = 0; i < workers; i++) {
		char wpath[SCHED_PATH_MAX];

		snprintf(wpath, sizeof(wpath), "%s/w%d.bin", workdir, i);
		(void)unlink(wpath);
	}
	munmap(shm, shm_len);
	return rc;
}

static const char *arm_mode(const char *arm)
{
	return strcmp(arm, "static") == 0 ? SCHED_MODE_STATIC : SCHED_MODE_OFF;
}

static void ab_write_report(const char *path, const struct ab_result *ra,
			    const struct ab_result *rb, int nloads,
			    int duration_s, int workers, double total_wall,
			    int budget_sec, const char *snap_before,
			    const char *restore_log, int r_ok, int r_fail,
			    const char *log_a, const char *log_b)
{
	FILE *fp = fopen(path, "we");
	int i;
	char when[32];

	if (!fp)
		return;
	iso_utc(epoch_now(), when, sizeof(when));
	fprintf(fp, "# AIKernel 双调度台 A/B 对照报告（W79）\n\n");
	fprintf(fp, "- 生成时间: %s\n", when);
	fprintf(fp, "- 主机: Linux（%ld 逻辑核）\n",
		sysconf(_SC_NPROCESSORS_ONLN));
	fprintf(fp, "- cgroup: `%s`\n", cg_dir());
	fprintf(fp, "- 参数集 A: `%s`（规则/固定参数台）\n",
		ra ? ra->arm : "static");
	fprintf(fp, "- 参数集 B: `%s`（基线，内核默认）\n",
		rb ? rb->arm : "baseline");
	fprintf(fp, "- 负载: %d 档 × 每档 %d 进程 × %d 秒；实际墙钟 %.2fs（上限 %ds）\n",
		nloads, workers, duration_s, total_wall, budget_sec);
	fprintf(fp, "\n## 指标口径\n\n");
	fprintf(fp, "- 吞吐 = 工作单元数 / 墙钟秒。CPU 单元 = 一批自适应 ~2ms 的 xorshift 自旋；"
		"IO 单元 = 256KiB pwrite + fdatasync + 256KiB pread。\n");
	fprintf(fp, "- p99 = 单个工作单元墙钟耗时（进程内 CLOCK_MONOTONIC 采样）的 99 分位；"
		"这是单元延迟近似，不是端到端请求延迟。\n");
	fprintf(fp, "- 公平性 = 各工作进程完成单元数的变异系数 CV（越小越均衡）。\n");
	fprintf(fp, "- 能耗代理 = RAPL 包能量差值（J）；本机不可读则为 N/A，绝不估算。\n");
	fprintf(fp, "\n## 结果\n\n");
	fprintf(fp, "| 负载 | 参数集 | 吞吐 (unit/s) | 吞吐 (MiB/s) | p50 (ms) | p99 (ms) | max (ms) | 公平性 CV | 能耗 (J) |\n");
	fprintf(fp, "|---|---|---|---|---|---|---|---|---|\n");
	for (i = 0; i < nloads; i++) {
		const struct ab_result *r[2] = { &ra[i], &rb[i] };
		int k;

		for (k = 0; k < 2; k++) {
			const struct ab_result *x = r[k];
			char tp[32] = "-", mib[32] = "-", en[32] = "N/A";

			if (x->ok) {
				snprintf(tp, sizeof(tp), "%.1f",
					 (double)x->units / x->wall_s);
				if (x->bytes > 0)
					snprintf(mib, sizeof(mib), "%.2f",
						 (double)x->bytes /
						 (1024.0 * 1024.0) /
						 x->wall_s);
				if (x->energy_j >= 0)
					snprintf(en, sizeof(en), "%.2f",
						 x->energy_j);
			}
			fprintf(fp,
				"| %s | %s | %s | %s | %.2f | %.2f | %.2f | %.3f | %s |\n",
				ai_sched_load_name(i), x->arm, tp, mib,
				x->ok ? x->p50_ms : 0.0,
				x->ok ? x->p99_ms : 0.0,
				x->ok ? x->max_ms : 0.0,
				x->ok ? x->cv : 0.0, en);
		}
	}
	fprintf(fp, "\n## 参数集实际生效值（写后读回）\n\n");
	fprintf(fp, "### A = %s\n```\n%s```\n", ra ? ra->arm : "static",
		log_a ? log_a : "");
	fprintf(fp, "### B = %s\n```\n%s```\n", rb ? rb->arm : "baseline",
		log_b ? log_b : "");
	fprintf(fp, "\n## 恢复校验（C6：实验前快照 → 实验后逐项读回）\n\n");
	fprintf(fp, "- 实验前快照: `%s`\n", snap_before ? snap_before : "");
	fprintf(fp, "- 恢复结果: %d 项一致 / %d 项失败\n\n```\n%s```\n",
		r_ok, r_fail, restore_log ? restore_log : "");
	fprintf(fp, "\n## 诚实说明\n\n");
	fprintf(fp, "- ml 台未交付（W83）：本报告两个臂都是规则/固定参数，"
		"不是“模型输出 vs 规则”对照。装置已就绪，W83 接入 ml 臂"
		"只需增加参数集定义。\n");
	fprintf(fp, "- 能耗代理在本机不可读（无 /sys/class/powercap RAPL），"
		"报告为 N/A。\n");
	fprintf(fp, "- p99 是单元级近似（见口径），非请求级端到端延迟。\n");
	fclose(fp);
}

static int cmd_ab_run(const char *args_json, char **out)
{
	char *arm_a = arg_str(args_json, "arm_a");
	char *arm_b = arg_str(args_json, "arm_b");
	char *loads = arg_str(args_json, "loads");
	long long dur = arg_ll(args_json, "duration_s", 6);
	long long workers = arg_ll(args_json, "workers", 4);
	long long inject = arg_ll(args_json, "inject_fail_after", 0);
	int mask = 0x7, nloads = 0, i, k, ret = AI_OK;
	int loadbits[3];
	struct ab_result res_a[3], res_b[3];
	struct sbuf log_a = { 0 }, log_b = { 0 }, restore_log = { 0 };
	struct sched_snapshot pre;
	char snapfile[SCHED_PATH_MAX] = "";
	char report[SCHED_PATH_MAX] = "";
	char workdir[SCHED_PATH_MAX] = "";
	char err[SCHED_VALUE_MAX * 2] = "";
	long long batch = 2000000;
	double total_wall = 0.0;
	int r_ok = 0, r_fail = 0, run_no = 0, aborted = 0;
	long long budget, t_start;
	const char *A, *B;

	if (!arm_a)
		arm_a = strdup("static");
	if (!arm_b)
		arm_b = strdup("baseline");
	if (!arm_a || !arm_b) {
		free(arm_a);
		free(arm_b);
		free(loads);
		return AI_ERR_MEMORY;
	}
	if (strcmp(arm_a, "ml") == 0 || strcmp(arm_b, "ml") == 0) {
		*out = strdup(
			"ERROR: ml 台未就绪（W83 交付），拒绝运行 ml 臂——绝不假成功。"
			"可用臂：static | baseline（off 与 baseline 等价）。");
		free(arm_a);
		free(arm_b);
		free(loads);
		return AI_ERR_NOT_IMPLEMENTED;
	}
	if (!(strcmp(arm_a, "static") == 0 || strcmp(arm_a, "baseline") == 0 ||
	      strcmp(arm_a, "off") == 0) ||
	    !(strcmp(arm_b, "static") == 0 || strcmp(arm_b, "baseline") == 0 ||
	      strcmp(arm_b, "off") == 0)) {
		*out = strdup("ERROR: arm_a/arm_b 只接受 static | baseline | off"
			      "（ml 会被拒绝）");
		free(arm_a);
		free(arm_b);
		free(loads);
		return AI_ERR_INVALID_ARG;
	}
	if (strcmp(arm_a, arm_b) == 0) {
		*out = strdup("ERROR: arm_a 与 arm_b 相同（或等价），A/B 对照无意义");
		free(arm_a);
		free(arm_b);
		free(loads);
		return AI_ERR_INVALID_ARG;
	}
	if (loads && ai_sched_parse_loads(loads, &mask) != 0) {
		*out = strdup("ERROR: 非法负载名（只接受 cpu | io | mix，可用逗号组合）");
		free(arm_a);
		free(arm_b);
		free(loads);
		return AI_ERR_INVALID_ARG;
	}
	for (i = 0; i < 3; i++)
		if (mask & (1 << i))
			loadbits[nloads++] = i;
	if (dur < AB_DURATION_MIN)
		dur = AB_DURATION_MIN;
	if (dur > AB_DURATION_MAX)
		dur = AB_DURATION_MAX;
	if (workers < 1)
		workers = 1;
	if (workers > AB_WORKERS_MAX)
		workers = AB_WORKERS_MAX;
	/* 预算：2 臂 × n 负载 × dur + 25s 开销 ≤ 180s */
	budget = (long long)(AB_TOTAL_MAX_SEC - 25) /
		 (2 * (long long)(nloads > 0 ? nloads : 1));
	if (budget < AB_DURATION_MIN) {
		*out = strdup("ERROR: 负载过多，2×负载数×2s 已超 180s 上限");
		free(arm_a);
		free(arm_b);
		free(loads);
		return AI_ERR_INVALID_ARG;
	}
	if (dur > budget)
		dur = budget;
	A = arm_a;
	B = arm_b;

	/* 1. 实验前快照（C6） */
	if (snap_collect(&pre, err, sizeof(err)) != 0 ||
	    snap_write(&pre, snapfile, sizeof(snapfile), err, sizeof(err))
	    != 0) {
		if (asprintf(out, "ERROR: 实验前快照失败，未开始：%s", err) < 0)
			*out = NULL;
		free(arm_a);
		free(arm_b);
		free(loads);
		return AI_ERR_STORAGE;
	}
	snprintf(workdir, sizeof(workdir), "%.450s/.abwork-%ld", state_dir(),
		 (long)getpid());
	if (mkdir_p(workdir, 0700) != 0) {
		if (asprintf(out, "ERROR: 工作目录不可用 %s：%s", workdir,
			     strerror(errno)) < 0)
			*out = NULL;
		ret = AI_ERR_STORAGE;
		goto restore;
	}
	if (cg_dir_ensure(err, sizeof(err)) != 0) {
		if (asprintf(out, "ERROR: cgroup 不可用：%s", err) < 0)
			*out = NULL;
		ret = AI_ERR_API;
		goto restore;
	}
	if (sb_init(&log_a) != 0 || sb_init(&log_b) != 0 ||
	    sb_init(&restore_log) != 0) {
		*out = strdup("ERROR: 内存不足");
		ret = AI_ERR_MEMORY;
		goto restore;
	}
	/* CPU 单元自适应 ~2ms */
	{
		long long t0 = mono_us(), t1;

		g_spin_sink ^= spin_batch(1000000);
		t1 = mono_us();
		if (t1 - t0 > 0) {
			batch = (long long)(2000.0 * 1000000.0 /
					    (double)(t1 - t0));
			if (batch < 50000)
				batch = 50000;
			if (batch > 50000000)
				batch = 50000000;
		}
	}
	t_start = mono_us();

	/* 2. 两臂 × 各负载 */
	for (k = 0; k < 2 && !aborted; k++) {
		const char *arm = k == 0 ? A : B;
		const char *amode = arm_mode(arm);
		struct sbuf *alog = k == 0 ? &log_a : &log_b;
		struct ab_result *arr = k == 0 ? res_a : res_b;

		memset(arr, 0, sizeof(res_a));
		if (param_set_apply(amode, alog, err, sizeof(err)) != 0) {
			if (asprintf(out, "ERROR: 参数集 %s 应用失败：%s\n%s",
				     arm, err, alog->p ? alog->p : "") < 0)
				*out = NULL;
			ret = AI_ERR_API;
			aborted = 1;
			break;
		}
		(void)mode_write(strcmp(amode, SCHED_MODE_OFF) == 0 ?
				 SCHED_MODE_OFF : SCHED_MODE_STATIC,
				 err, sizeof(err));
		for (i = 0; i < nloads; i++) {
			if (inject > 0 && run_no >= inject) {
				set_err(err, sizeof(err),
					"演练注入：第 %d 次 run 后强制失败（inject_fail_after=%lld）",
					run_no, inject);
				if (asprintf(out,
					     "ERROR: 对照运行中途失败（演练注入，%s / %s 之前）：%s\n已恢复实验前参数集，见下方",
					     arm, ai_sched_load_name(loadbits[i]),
					     err) < 0)
					*out = NULL;
				ret = AI_ERR_API;
				aborted = 1;
				break;
			}
			memset(&arr[i], 0, sizeof(arr[i]));
			if (ab_run_one(arm, loadbits[i], (int)dur,
				       (int)workers, batch,
				       strcmp(arm, "static") == 0 ? 10 : 0,
				       workdir, &arr[i], err,
				       sizeof(err)) != 0) {
				if (asprintf(out,
					     "ERROR: 对照运行失败（%s / %s）：%s\n已恢复实验前参数集，见下方",
					     arm, ai_sched_load_name(loadbits[i]),
					     err) < 0)
					*out = NULL;
				ret = AI_ERR_API;
				aborted = 1;
				break;
			}
			run_no++;
		}
	}
	total_wall = (double)(mono_us() - t_start) / 1000000.0;

restore:
	/* 3. 无论成败恢复实验前参数集（C6） */
	if (snap_apply(&pre, &restore_log, &r_ok, &r_fail, err,
		       sizeof(err)) != 0) {
		if (out && *out) {
			char *old = *out;
			char *msg = NULL;

			if (asprintf(&msg, "%s\n恢复失败 %d 项：%s\n%s", old,
				     r_fail, err,
				     restore_log.p ? restore_log.p : "") > 0) {
				free(old);
				*out = msg;
			}
		}
		ret = AI_ERR_API;
	} else if (ret == AI_OK) {
		/* 4. 报告 */
		char ts[32];
		unsigned long long now = epoch_now();

		iso_utc(now, ts, sizeof(ts));
		snprintf(report, sizeof(report), "%.450s/ab-%llu.md", state_dir(),
			 now);
		ab_write_report(report, res_a, res_b, nloads, (int)dur,
				(int)workers, total_wall, AB_TOTAL_MAX_SEC,
				snapfile, restore_log.p, r_ok, r_fail,
				log_a.p, log_b.p);
		(void)chmod(report, 0600);
		{
			struct sbuf b;

			if (sb_init(&b) == 0) {
				sb_add(&b,
				       "OK: A/B 对照完成（%d 档 × 每档 %d 进程 × %llds，墙钟 %.1fs，上限 %ds）\n",
				       nloads, (int)workers, dur, total_wall,
				       AB_TOTAL_MAX_SEC);
				sb_add(&b, "报告: %s\n", report);
				sb_add(&b,
				       "参数集: A=%s（规则/固定参数） B=%s（基线）\n",
				       A, B);
				sb_add(&b, "\n| 负载 | A 吞吐 unit/s | B 吞吐 unit/s | A p99 ms | B p99 ms | A CV | B CV | 能耗 |\n");
				sb_add(&b, "|---|---|---|---|---|---|---|---|\n");
				for (i = 0; i < nloads; i++) {
					char ea[32] = "N/A", eb[32] = "N/A";

					if (res_a[i].energy_j >= 0)
						snprintf(ea, sizeof(ea),
							 "%.1fJ",
							 res_a[i].energy_j);
					if (res_b[i].energy_j >= 0)
						snprintf(eb, sizeof(eb),
							 "%.1fJ",
							 res_b[i].energy_j);
					sb_add(&b,
					       "| %s | %.1f | %.1f | %.2f | %.2f | %.3f | %.3f | %s/%s |\n",
					       ai_sched_load_name(loadbits[i]),
					       (double)res_a[i].units /
					       (res_a[i].wall_s > 0 ?
						res_a[i].wall_s : 1),
					       (double)res_b[i].units /
					       (res_b[i].wall_s > 0 ?
						res_b[i].wall_s : 1),
					       res_a[i].p99_ms,
					       res_b[i].p99_ms, res_a[i].cv,
					       res_b[i].cv, ea, eb);
				}
				sb_add(&b,
				       "\n口径: 吞吐=工作单元/秒；p99=单单元墙钟耗时 99 分位（单元级近似）；CV=各进程完成量变异系数（越小越公平）；能耗=RAPL 包能量，本机%s。\n",
				       res_a[0].energy_j >= 0 ? "可读" :
				       "不可读 → N/A");
				sb_add(&b,
				       "恢复: 实验前快照 %s → %d 项一致 / %d 项失败%s\n",
				       snapfile, r_ok, r_fail,
				       r_fail ? "（失败项见报告）" : "");
				if (asprintf(out, "%s", b.p) < 0)
					*out = NULL;
				sb_free(&b);
			}
		}
	} else {
		/* 失败但已恢复：把恢复结论补进返回文本 */
		if (out && *out) {
			char *old = *out;
			char *msg = NULL;

			if (asprintf(&msg,
				     "%s\n恢复: 实验前快照 %s → %d 项一致 / %d 项失败",
				     old, snapfile, r_ok, r_fail) > 0) {
				free(old);
				*out = msg;
			}
		}
	}
	/* 清理工作目录残留 */
	if (workdir[0]) {
		char p[SCHED_PATH_MAX];

		for (i = 0; i < (int)workers; i++) {
			snprintf(p, sizeof(p), "%s/w%d.bin", workdir, i);
			(void)unlink(p);
		}
		(void)rmdir(workdir);
	}
	sb_free(&log_a);
	sb_free(&log_b);
	sb_free(&restore_log);
	free(arm_a);
	free(arm_b);
	free(loads);
	return ret;
}

/* ------------------------------------------------------------------ */
/* 通道分发                                                             */
/* ------------------------------------------------------------------ */

int exec_sched_channel(const void *tool, const char *args_json, char **out)
{
	const struct ai_tool *t = tool;

	if (!out)
		return AI_ERR_INVALID_ARG;
	*out = NULL;
	if (!t || !t->name) {
		*out = strdup("ERROR: sched 工具缺失注册信息");
		return AI_ERR_INVALID_ARG;
	}
	if (strcmp(t->name, "sched_status") == 0)
		return cmd_status(args_json, out);
	if (strcmp(t->name, "sched_knob_set") == 0)
		return cmd_knob_set(args_json, out);
	if (strcmp(t->name, "sched_mode_set") == 0) {
		char *mode = arg_str(args_json, "mode");
		int rc;

		if (!mode || !mode[0]) {
			*out = strdup("ERROR: 需要 mode 参数（static | ml | off）");
			free(mode);
			return AI_ERR_INVALID_ARG;
		}
		rc = mode_set_impl(mode, out);
		free(mode);
		return rc;
	}
	if (strcmp(t->name, "sched_snapshot") == 0)
		return cmd_snapshot(args_json, out);
	if (strcmp(t->name, "sched_ab_run") == 0)
		return cmd_ab_run(args_json, out);
	*out = strdup("ERROR: 未知 sched 工具（注册表异常）");
	return AI_ERR_INVALID_ARG;
}
