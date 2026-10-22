// SPDX-License-Identifier: GPL-2.0
/*
 * executor.c - AI 工具自动执行器实现（channel 路由）
 *
 * 六条通道：
 *   procfs-read   : 直接读注册表登记的固定路径（/proc/ai、/sys/kernel/ai/
 *                   stats、/sys/fs/cgroup/ai.*）；失败（如无 AIKernel 内核）
 *                   返回"通道不可用"。
 *   sysfs-write   : 写注册表登记的固定节点（value 参数；也承载
 *                   /proc/ai/telemetry 的 format=/reset 写工具）；
 *                   EPERM 时提示需要 CAP_SYS_ADMIN。
 *   netlink-act   : 组 struct ai_nl_act 下发（domain/confidence/data 约定
 *                   与内核 ai_control 一致：任务参数 data[0]=pid,
 *                   data[1]=value）。v2：下发前按注册表 value_min/value_max
 *                   做客户端钳制（内核安全边界之外的纵深防御）。
 *   netlink-sense : AI_CMD_SENSE 拉取内核遥测（cpu/count/format），执行
 *                   结果即遥测文本。
 *   exec          : fork + execv 白名单命令（不经 shell），收集 stdout/stderr。
 *                   v2 三条硬约束：
 *                     a) 子进程 stdin 重定向 /dev/null（无参 cat 等不再
 *                        永久挂起拖死会话）；
 *                     b) 父进程 poll+deadline 轮询，超时（默认 30 秒，可
 *                        按命令配置）SIGKILL 并报"工具超时"；
 *                     c) 白名单单源化——tools.json exec 工具内嵌
 *                        "exec"."commands"（bin/args_template/timeout/risk/
 *                        path_check/args0），本文件内置表降级为 fallback。
 *   memory        : 调 sme_client（13 个端点），原始 JSON 直接回填。
 *   shell         : AI 应用户请求降入交互式维护 shell（fork/exec bash，
 *                   继承终端；exit 返回后以工具结果回填 ask 闭环）。
 *   sandbox（W42）: 隔离区 + 子智能体——包装独立工具 aik-sandbox，
 *                   status/create/destroy 透传；spawn 派子 AI 进
 *                   namespace 沙盒干活，超时 SIGKILL 全组，回传输出
 *                   尾部 4KB 作摘要（详见 exec_sandbox 段注释）。
 *
 * 通道说明（netlink-act 粒度，v3 定向协议）：ACT 载荷 v2 起携带 param
 * 定向参数名——本执行器按注册表 tool->param（tools.json 单源，即内核
 * 策略动作名，如 "mm.swappiness"）填写，缺失时回退从工具名解析
 * （netlink.act.<param> 前缀剥离）。内核按参数名定向 apply 只执行那一条
 * 策略；param 为空（旧路径）仍按 domain 广播。参数值域由客户端钳制 +
 * 内核安全边界（min/max + max_impact）双层兜底。
 *
 * 风险级（v2，tools.json "risk"）：R 只读 / W1 低危写 / W2 高危写。
 * 执行器当前仅对 W1 文件类命令做目标路径校验（限 /root /tmp /var/ai），
 * 其余级别用于审计标注与后续权限分级（项目决策：暂缓交互确认）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "ai_lang.h"
#include "ai_trace.h"
#include "netlink/ai_netlink_client.h"
#include "memory/sme_client.h"
#include "tools/executor.h"
#include "local/local_http.h"
#include <unistd.h>                  /* getuid（P2 权限分级） */
#include "policy/ai_user_policy.h"   /* P2: uid→档位→W1/W2 闸门 */
#include "policy/ai_lease.h"         /* W74: 授权租约 / D0-D4 意图保险丝 */

/* exec 默认超时（秒）：tools.json 未配置时生效；可用环境变量
 * AIKERNEL_TOOL_TIMEOUT_SEC 覆盖（修复 8：超时可配置，默认 30s，
 * 超时返回明确错误给模型而非挂死） */
#define EXEC_DEFAULT_TIMEOUT_SEC  30
#define EXEC_INPUT_MAX            60000   /* exec input 字节上限（<pipe 容量 64KB） */

/* 工具结果上限（字节）：超长截断并标注 "[截断，共 N 字节]"（修复 8）。
 * exec 通道采集上限；procfs-read 保持 32KB 定额并附截断标注 */
#define TOOL_RESULT_MAX  (64 * 1024)

/* W42 sandbox 通道：spawn 摘要只回传子智能体输出尾部（4KB），超时
 * 默认/上限（秒）；生命周期由独立工具 aik-sandbox 承载 */
#define SB_SPAWN_TAIL_MAX     4096
#define SB_SPAWN_TIMEOUT_DEF  300
#define SB_SPAWN_TIMEOUT_MAX  900
#define SB_SIMPLE_TIMEOUT     30    /* create/destroy/status 的采集超时 */

/* W1 文件类命令允许写入的目录（tools.json path_check=true 时校验） */
static const char *const g_w1_allow_dirs[] = {
	"/root", "/tmp", "/var/ai",
	NULL,
};

/* ---- W48：通用 sysctl / sysfs 动态通道的安全边界 ---- */

/*
 * 崩溃黑名单（安全关键路径编译进二进制，不依赖可被替换的数据文件）。
 * 与 tools/gen_registry.py 的 CRASH_BLACKLIST 一一对应（专项测试比对）。
 * 准入原则：只有"一次写入即可能 brick/panic/不可恢复/远程失联"的键。
 * 其余敏感键（如 net.ipv4.conf.*.rp_filter）放行但按 W2 二次确认。
 */
struct sysctl_block_rule {
	const char *key;	/* 前缀匹配（含自身） */
	const char *reason;
};

static const struct sysctl_block_rule g_sysctl_blacklist[] = {
	{ "kernel.sysrq",
	  "SysRq 可立即重启/崩溃/杀进程，远程不可恢复" },
	{ "kernel.panic",
	  "panic 族把可恢复错误升级为立即 panic/重启" },
	{ "kernel.hung_task_panic",
	  "hung task 超时即 panic，IO 抖动可触发宕机" },
	{ "kernel.softlockup_panic",
	  "soft lockup 即 panic，高负载可误触发" },
	{ "kernel.hardlockup_panic",
	  "hard lockup 即 panic，NMI 抖动可宕机" },
	{ "kernel.core_pattern",
	  "core 管道处理器可 root 执行任意程序，消费端不读会永久挂起" },
	{ "kernel.modules_disabled",
	  "写 1 后永久禁止模块加载，只能重启恢复" },
	{ "kernel.kexec_load_disabled",
	  "写 1 后永久禁止 kexec，只能重启恢复" },
	{ "kernel.sched_rt_runtime_us",
	  "RT 带宽 -1 可让 RT 任务饿死整机（硬锁死）" },
	{ "vm.panic_on_oom",
	  "OOM 直接 panic 而非杀进程" },
	{ "vm.oom_kill_allocating_task",
	  "OOM 杀分配者（常为关键服务/内核路径），易误杀致不可用" },
	{ "/proc/sysrq-trigger",
	  "SysRq 触发文件，写单字符即可立即重启/崩溃；不在 /proc/sys 下，"
	  "sysctl 通道 realpath 前缀已天然拒绝" },
};

#define SYSCTL_KEY_MAX     512
#define SYSCTL_VALUE_MAX   4096
#define SYSCTL_LIST_MAX    (TOOL_EXEC_OUT_MAX - 512)
#define SYSCTL_LIST_DEPTH  8
#define SYSCTL_LIST_FILES  2048

/* sysfs 动态写允许前缀（与 gen_registry.py SYSFS_WRITE_ALLOW_PREFIXES 对齐） */
static const char *const g_sysfs_write_allow[] = {
	"/sys/fs/cgroup/",
	"/sys/kernel/ai/",
	"/sys/devices/system/cpu/",
	"/sys/block/",
	"/sys/class/net/",
	"/proc/irq/",
	"/proc/ai/",
	NULL,
};

/* sysfs 动态读允许前缀 */
static const char *const g_sysfs_read_allow[] = {
	"/sys/", "/proc/sys/", "/proc/irq/", "/proc/ai/",
	"/proc/pressure/", "/proc/net/", NULL,
};

/* ---- 审计 ---- */

/* 审计输出：与用户可见过程合一（stdout），格式稳定便于留存回放 */
static void audit_line_res(const char *tool, const char *channel,
			   const char *args, const char *result)
{
	printf("[audit] tool=%s channel=%s args=%s result=%s\n",
	       tool ? tool : "?", channel ? channel : "?",
	       args && args[0] ? args : "{}", result ? result : "?");
}


/* W43：memory 通道本次降级标记（audit result=degraded；单线程 REPL，
 * 无需加锁；spawn 子进程各自独立内存） */
static int g_mem_degraded;
/* W69 P2-3：最近一次 memory 通道真实返回码（供 degrade 原因分类） */
static int g_mem_last_rc = AI_OK;

/* ---- W48 通用写通道辅助 ---- */

/* path 是否严格位于 dir 之下（dir 自身不算；与 w1_path_allowed 同语义） */
static int path_under_dir(const char *path, const char *dir)
{
	size_t dl = strlen(dir);

	return strncmp(path, dir, dl) == 0 && path[dl] == '/';
}

static int path_under_proc_net(const char *path)
{
	const char *p;

	if (strncmp(path, "/proc/", 6) != 0)
		return 0;
	p = path + 6;
	if (strncmp(p, "self/net/", 9) == 0)
		return 1;
	if (*p >= '0' && *p <= '9') {
		while (*p >= '0' && *p <= '9')
			p++;
		if (strncmp(p, "/net/", 5) == 0)
			return 1;
	}
	return 0;
}

static int path_under_prefixes(const char *path, const char *const *dirs)
{
	int i;

	for (i = 0; dirs[i]; i++) {
		const char *d = dirs[i];
		size_t dl = strlen(d);

		if (dl > 0 && d[dl - 1] == '/') {
			/* 前缀自带尾部 '/'（如 /sys/fs/cgroup/）：直接
			 * 前缀比较即可，不能再要求 path[dl]=='/' */
			if (strncmp(path, d, dl) == 0)
				return 1;
		} else if (path_under_dir(path, d) || strcmp(path, d) == 0) {
			return 1;
		}
	}
	return 0;
}

/* 单行值校验：拒绝 NUL/换行/回车及其余 C0 控制字符（允许 TAB） */
static int value_single_line_ok(const char *v, char **err_out)
{
	const unsigned char *p = (const unsigned char *)v;
	size_t n;

	if (!v || !v[0]) {
		*err_out = strdup("值不能为空");
		return 0;
	}
	n = strlen(v);
	if (n > SYSCTL_VALUE_MAX) {
		if (asprintf(err_out, "值超长（%zu > %d 字节）", n,
			     SYSCTL_VALUE_MAX) < 0)
			*err_out = NULL;
		return 0;
	}
	for (; *p; p++) {
		if (*p == '\n' || *p == '\r') {
			*err_out = strdup("值含换行/回车（只允许单行）");
			return 0;
		}
		if (*p < 0x20 && *p != '\t') {
			if (asprintf(err_out, "值含控制字符 0x%02x，已拒绝",
				     *p) < 0)
				*err_out = NULL;
			return 0;
		}
		if (*p == 0x7f) {
			*err_out = strdup("值含 DEL 控制字符，已拒绝");
			return 0;
		}
	}
	return 1;
}

/* 读取整个小文件（≤cap-1 字节；返回字节数，-1 失败） */
static ssize_t read_small_file(const char *path, char *buf, size_t cap)
{
	int fd;
	ssize_t off = 0;

	if (cap == 0)
		return -1;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	while (off < (ssize_t)cap - 1) {
		ssize_t n = read(fd, buf + off, (size_t)(cap - 1 - off));

		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		off += n;
	}
	close(fd);
	buf[off] = '\0';
	return off;
}

/*
 * 写审计：~/.aikernel/audit.log 追加一行（old/new 便于回滚）。
 * 与 policy 层 audit.log 同文件、同目录；失败不阻断主操作（stderr 提示）。
 */
static void sysctl_audit_record(const char *path, const char *old,
				const char *newv)
{
	const char *home = getenv("HOME");
	char dir[PATH_MAX];
	char log[PATH_MAX + 32];
	FILE *fp;
	time_t t;
	struct tm tmv;

	if (!home || !home[0])
		return;
	snprintf(dir, sizeof(dir), "%s/.aikernel", home);
	if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
		fprintf(stderr, "sysctl audit: mkdir %s: %s\n", dir,
			strerror(errno));
		return;
	}
	snprintf(log, sizeof(log), "%s/audit.log", dir);
	fp = fopen(log, "a");
	if (!fp) {
		fprintf(stderr, "sysctl audit: open %s: %s\n", log,
			strerror(errno));
		return;
	}
	t = time(NULL);
	localtime_r(&t, &tmv);
	fprintf(fp,
		"%04d-%02d-%02d %02d:%02d:%02d sysctl_write path=%s old=\"%s\" new=\"%s\"\n",
		tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
		tmv.tm_hour, tmv.tm_min, tmv.tm_sec, path,
		old ? old : "", newv ? newv : "");
	fclose(fp);
}

/* sysctl key → /proc/sys 路径（点号/斜杠两种写法；拒绝穿越与非法字符） */
static int sysctl_key_to_path(const char *key, char *path, size_t n,
			      char **err_out)
{
	size_t i, o = 0;
	static const char prefix[] = "/proc/sys/";

	*err_out = NULL;
	if (!key || !key[0]) {
		*err_out = strdup("key 不能为空");
		return 0;
	}
	if (strlen(key) > SYSCTL_KEY_MAX) {
		*err_out = strdup("key 超长");
		return 0;
	}
	if (strstr(key, "..") || key[0] == '/' || key[0] == '.') {
		*err_out = strdup("key 含非法路径分量（拒绝 ..、前导 / 或 .）");
		return 0;
	}
	if (strlen(prefix) + strlen(key) + 2 > n) {
		*err_out = strdup("key 过长");
		return 0;
	}
	memcpy(path, prefix, strlen(prefix));
	o = strlen(prefix);
	for (i = 0; key[i]; i++) {
		char c = key[i];

		if (c == '.' || c == '/') {
			path[o++] = '/';
			continue;
		}
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '_' || c == '-')) {
			if (asprintf(err_out, "key 含非法字符 '%c'", c) < 0)
				*err_out = NULL;
			return 0;
		}
		path[o++] = c;
	}
	path[o] = '\0';
	/* 防止尾部分隔符与连续分隔符构造空分量 */
	if (path[o - 1] == '/' || strstr(path, "//")) {
		*err_out = strdup("key 含空路径分量");
		return 0;
	}
	return 1;
}

/* 黑名单命中检查：返回 reason（未命中 NULL） */
static const char *sysctl_blacklist_hit(const char *key, const char *path)
{
	int i;

	for (i = 0; i < (int)(sizeof(g_sysctl_blacklist) /
			      sizeof(g_sysctl_blacklist[0])); i++) {
		const char *k = g_sysctl_blacklist[i].key;

		if (strncmp(key, k, strlen(k)) == 0)
			return g_sysctl_blacklist[i].reason;
		if (path && strcmp(path, k) == 0)
			return g_sysctl_blacklist[i].reason;
	}
	return NULL;
}

/* realpath 后必须落在指定前缀内（防符号链接/穿越逃逸） */
static int realpath_under_prefix(const char *path, const char *prefix,
				 char *resolved, size_t n)
{
	char *rp;

	rp = realpath(path, NULL);
	if (!rp)
		return 0;
	if (!path_under_dir(rp, prefix) && strcmp(rp, prefix) != 0) {
		free(rp);
		return 0;
	}
	if (resolved)
		snprintf(resolved, n, "%s", rp);
	free(rp);
	return 1;
}


/* ---- 参数提取 ---- */

/* 从 arguments JSON 取字符串参数（malloc；不存在返回 NULL） */
static char *arg_str(const char *args_json, const char *key)
{
	const char *v;
	size_t vl;
	int vt;

	if (!args_json || !args_json[0])
		return NULL;
	if (ai_json_obj_get(args_json, strlen(args_json), key,
			    &v, &vl, &vt) == 1) {
		if (vt == AI_JSON_STR)
			return ai_json_strdup_str(v, vl);
		/* 数值/布尔参数宽容处理：原样文本 */
		return strndup(v, vl);
	}
	return NULL;
}

/* 取整数参数（缺省 def；不存在/非法返回 def） */
static long long arg_ll(const char *args_json, const char *key,
			long long def)
{
	const char *v;
	size_t vl;
	int vt;

	if (!args_json || !args_json[0])
		return def;
	if (ai_json_obj_get(args_json, strlen(args_json), key,
			    &v, &vl, &vt) == 1 && vt == AI_JSON_NUM)
		return ai_json_ll(v, vl);
	return def;
}

/* 取浮点参数（缺省 def；不存在/非法返回 def） */
static double arg_dbl(const char *args_json, const char *key, double def)
{
	const char *v;
	size_t vl;
	int vt;
	char tmp[64];

	if (!args_json || !args_json[0])
		return def;
	if (ai_json_obj_get(args_json, strlen(args_json), key,
			    &v, &vl, &vt) != 1 || vt != AI_JSON_NUM)
		return def;
	if (vl >= sizeof(tmp))
		return def;
	memcpy(tmp, v, vl);
	tmp[vl] = '\0';
	return strtod(tmp, NULL);
}

/* 取布尔参数（缺省 def；只接受 true/false） */
static int arg_bool(const char *args_json, const char *key, int def)
{
	const char *v;
	size_t vl;
	int vt;

	if (!args_json || !args_json[0])
		return def;
	if (ai_json_obj_get(args_json, strlen(args_json), key,
			    &v, &vl, &vt) != 1)
		return def;
	if (vt == AI_JSON_BOOL)
		return v[0] == 't';
	if (vt == AI_JSON_NUM)
		return ai_json_ll(v, vl) != 0;
	return def;
}

/* 参数是否存在（区分"缺省"与显式 0/空串） */
static int arg_has(const char *args_json, const char *key)
{
	const char *v;
	size_t vl;
	int vt;

	if (!args_json || !args_json[0])
		return 0;
	return ai_json_obj_get(args_json, strlen(args_json), key,
			       &v, &vl, &vt) == 1;
}

/* ---- procfs-read ---- */

static int exec_procfs_read(const struct ai_tool *tool, char **out)
{
	FILE *fp;
	size_t n;
	char *buf;

	/* W65 P2-05：能力探测（如 /proc/pressure）——不把内核未启用的
	 * 能力伪装成 ENOENT 通道故障，返回明确 unavailable 与替代建议。 */
	if (tool->probe && access(tool->probe, F_OK) != 0) {
		if (asprintf(out,
			     "ERROR: unavailable: 工具 %s 依赖 %s，本内核未提供"
			     "（能力探测失败；若为 PSI，需 CONFIG_PSI=y 且内核"
			     "未禁用 psi=0）。请改用替代数据：/proc/meminfo、"
			     "/proc/vmstat、/proc/loadavg 或 procfs_read_swaps",
			     tool->name, tool->probe) < 0)
			*out = NULL;
		return AI_ERR_NOT_FOUND;
	}

	fp = fopen(tool->path, "rb");
	if (!fp) {
		/* 无 AIKernel 内核/节点不存在：明确"通道不可用" */
		if (asprintf(out, "ERROR: 读取 %s 失败: %s（procfs-read 通道"
			     "不可用：需要 AIKernel 内核，且节点存在）",
			     tool->path, strerror(errno)) < 0)
			*out = NULL;
		return AI_ERR_NOT_FOUND;
	}

	buf = malloc(TOOL_EXEC_OUT_MAX + 192);
	if (!buf) {
		fclose(fp);
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	n = fread(buf, 1, TOOL_EXEC_OUT_MAX, fp);
	{
		/* 修复 8：超过采集上限不静默——标注截断（模型可改用
		 * exec cat 分段读取）；定长截断对齐 UTF-8 边界（T2 问题 1） */
		int truncated = !feof(fp) && !ferror(fp);

		n = ai_json_utf8_floor(buf, n);
		buf[n] = '\0';
		if (truncated)
			snprintf(buf + n, 192,
				 "\n[截断，文件超过 %d 字节采集上限，"
				 "仅读取前 %zu 字节]\n",
				 TOOL_EXEC_OUT_MAX, n);
	}
	fclose(fp);

	if (n == 0)
		snprintf(buf, TOOL_EXEC_OUT_MAX + 1, "(空文件) %s", tool->path);
	*out = buf;
	return AI_OK;
}

/* ---- W48: sysctl 通用通道（R 读 / W2 写 / 黑名单） ---- */

/* 递归列举 /proc/sys 子树，按 "key = value" 追加到缓冲 */
static void sysctl_dump_tree(const char *dir, const char *key_prefix,
			     int depth, char *buf, size_t cap, size_t *off,
			     int *files, int *truncated)
{
	DIR *d;
	struct dirent *e;

	if (*truncated || depth > SYSCTL_LIST_DEPTH)
		return;
	d = opendir(dir);
	if (!d)
		return;
	while ((e = readdir(d)) != NULL) {
		char path[PATH_MAX];
		char key[SYSCTL_KEY_MAX];
		struct stat st;

		if (strcmp(e->d_name, ".") == 0 ||
		    strcmp(e->d_name, "..") == 0)
			continue;
		if (++(*files) > SYSCTL_LIST_FILES) {
			*truncated = 1;
			break;
		}
		snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
		snprintf(key, sizeof(key), "%s%s%s", key_prefix,
			 key_prefix[0] ? "." : "", e->d_name);
		if (stat(path, &st) != 0)
			continue;
		if (S_ISDIR(st.st_mode)) {
			sysctl_dump_tree(path, key, depth + 1, buf, cap,
					 off, files, truncated);
			continue;
		}
		if (!S_ISREG(st.st_mode))
			continue;
		{
			char val[512];
			ssize_t n = read_small_file(path, val, sizeof(val));
			size_t need;
			int w;

			if (n < 0)
				continue;
			while (n > 0 && (val[n - 1] == '\n' ||
					 val[n - 1] == '\r'))
				val[--n] = '\0';
			need = strlen(key) + (size_t)n + 8;
			if (*off + need >= cap) {
				*truncated = 1;
				break;
			}
			w = snprintf(buf + *off, cap - *off, "%s = %s\n",
				     key, val);
			if (w < 0 || (size_t)w >= cap - *off) {
				*truncated = 1;
				break;
			}
			*off += (size_t)w;
		}
	}
	closedir(d);
}

static int exec_sysctl_read(const struct ai_tool *tool, const char *args_json,
			    char **out)
{
	char *key = arg_str(args_json, "key");
	char *prefix = arg_str(args_json, "prefix");
	char path[PATH_MAX];
	char resolved[PATH_MAX];
	char *err = NULL;
	int rc = AI_OK;

	(void)tool;
	if (key && prefix && key[0] && prefix[0]) {
		*out = strdup("ERROR: key 与 prefix 只能二选一");
		rc = AI_ERR_INVALID_ARG;
		goto done;
	}
	if ((!key || !key[0]) && (!prefix || !prefix[0])) {
		*out = strdup("ERROR: 需要 key（单键）或 prefix（子树）参数");
		rc = AI_ERR_INVALID_ARG;
		goto done;
	}
	if (key && key[0]) {
		char val[512];
		ssize_t n;

		if (!sysctl_key_to_path(key, path, sizeof(path), &err)) {
			if (asprintf(out, "ERROR: 非法 sysctl key: %s",
				     err ? err : "格式错误") < 0)
				*out = NULL;
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		if (!realpath_under_prefix(path, "/proc/sys", resolved,
					   sizeof(resolved))) {
			if (asprintf(out, "ERROR: sysctl 路径校验失败（%s "
				     "不存在或逃逸 /proc/sys），已拒绝", path) < 0)
				*out = NULL;
			rc = AI_ERR_NOT_FOUND;
			goto done;
		}
		n = read_small_file(resolved, val, sizeof(val));
		if (n < 0) {
			if (asprintf(out, "ERROR: 读取 %s 失败: %s", resolved,
				     strerror(errno)) < 0)
				*out = NULL;
			rc = AI_ERR_GENERIC;
			goto done;
		}
		while (n > 0 && (val[n - 1] == '\n' || val[n - 1] == '\r'))
			val[--n] = '\0';
		if (asprintf(out, "%s = %s\n", key, val) < 0)
			*out = NULL;
		goto done;
	}

	/* prefix 列举 */
	{
		struct stat st;
		char *buf;
		size_t off = 0;
		int files = 0, truncated = 0;

		if (!sysctl_key_to_path(prefix, path, sizeof(path), &err)) {
			if (asprintf(out, "ERROR: 非法 sysctl prefix: %s",
				     err ? err : "格式错误") < 0)
				*out = NULL;
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		if (!realpath_under_prefix(path, "/proc/sys", resolved,
					   sizeof(resolved))) {
			if (asprintf(out, "ERROR: sysctl 前缀校验失败（%s "
				     "不存在或逃逸 /proc/sys）", path) < 0)
				*out = NULL;
			rc = AI_ERR_NOT_FOUND;
			goto done;
		}
		if (stat(resolved, &st) != 0) {
			if (asprintf(out, "ERROR: stat %s 失败: %s", resolved,
				     strerror(errno)) < 0)
				*out = NULL;
			rc = AI_ERR_GENERIC;
			goto done;
		}
		buf = malloc(SYSCTL_LIST_MAX + 1);
		if (!buf) {
			*out = strdup("ERROR: 内存不足");
			rc = AI_ERR_MEMORY;
			goto done;
		}
		buf[0] = '\0';
		if (S_ISDIR(st.st_mode)) {
			sysctl_dump_tree(resolved, prefix, 0, buf,
					 SYSCTL_LIST_MAX, &off, &files,
					 &truncated);
		} else {
			char val[512];
			ssize_t n = read_small_file(resolved, val,
						    sizeof(val));

			if (n >= 0) {
				while (n > 0 && (val[n - 1] == '\n' ||
						 val[n - 1] == '\r'))
					val[--n] = '\0';
				off = (size_t)snprintf(buf, SYSCTL_LIST_MAX + 1,
						       "%s = %s\n", prefix, val);
			}
		}
		if (off == 0)
			snprintf(buf, SYSCTL_LIST_MAX + 1,
				 "(前缀下无可见 sysctl 键) %s\n", prefix);
		if (truncated)
			snprintf(buf + off, SYSCTL_LIST_MAX + 1 - off,
				 "\n[截断：仅列出前 %d 项/%d 字节；请缩小 prefix]\n",
				 files, SYSCTL_LIST_MAX);
		*out = buf;
		goto done;
	}

done:
	free(key);
	free(prefix);
	free(err);
	return rc;
}

static int exec_sysctl_write(const struct ai_tool *tool,
			     const char *args_json, char **out)
{
	char *key = arg_str(args_json, "key");
	char *value = arg_str(args_json, "value");
	char path[PATH_MAX];
	char resolved[PATH_MAX];
	char old[512];
	char *err = NULL;
	const char *reason;
	ssize_t oldn;
	int fd = -1;
	int rc = AI_ERR_INVALID_ARG;
	size_t voff = 0;

	(void)tool;
	if (!key || !key[0] || !value) {
		*out = strdup("ERROR: 缺少必填参数 key/value");
		goto done;
	}
	if (!value_single_line_ok(value, &err)) {
		if (asprintf(out, "ERROR: 非法值: %s（未执行任何写入）",
			     err ? err : "格式错误") < 0)
			*out = NULL;
		goto done;
	}
	if (!sysctl_key_to_path(key, path, sizeof(path), &err)) {
		if (asprintf(out, "ERROR: 非法 sysctl key: %s（未写入）",
			     err ? err : "格式错误") < 0)
			*out = NULL;
		goto done;
	}
	reason = sysctl_blacklist_hit(key, path);
	if (reason) {
		if (asprintf(out, TOOL_ERR_DENIED_PREFIX " 崩溃黑名单拒绝: %s —— %s（不可"
			     "绕过；本工具没有 --force 通道）", key, reason) < 0)
			*out = NULL;
		rc = AI_ERR_API;
		goto done;
	}
	if (!realpath_under_prefix(path, "/proc/sys", resolved,
				   sizeof(resolved))) {
		if (asprintf(out, "ERROR: sysctl 路径校验失败（%s 不存在或"
			     "逃逸 /proc/sys），未写入", path) < 0)
			*out = NULL;
		rc = AI_ERR_NOT_FOUND;
		goto done;
	}
	reason = sysctl_blacklist_hit(key, resolved);
	if (reason) {
		if (asprintf(out, TOOL_ERR_DENIED_PREFIX " 崩溃黑名单拒绝: %s —— %s", key,
			     reason) < 0)
			*out = NULL;
		rc = AI_ERR_API;
		goto done;
	}

	oldn = read_small_file(resolved, old, sizeof(old));
	if (oldn < 0) {
		if (asprintf(out, "ERROR: 读取旧值失败（%s），为可回滚性"
			     "拒绝写入", strerror(errno)) < 0)
			*out = NULL;
		rc = AI_ERR_GENERIC;
		goto done;
	}
	while (oldn > 0 && (old[oldn - 1] == '\n' || old[oldn - 1] == '\r'))
		old[--oldn] = '\0';
	sysctl_audit_record(resolved, old, value);

	fd = open(resolved, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) {
		int e = errno;

		if (asprintf(out, "ERROR: 写入 %s 失败: %s%s", resolved,
			     strerror(e),
			     (e == EPERM || e == EACCES) ?
			     "（需要 root/CAP_SYS_ADMIN；请 sudo ai）" : "") < 0)
			*out = NULL;
		rc = AI_ERR_API;
		goto done;
	}
	for (;;) {
		size_t len = strlen(value) + 1;	/* + 换行 */
		const char *p = value;
		char tmp[SYSCTL_VALUE_MAX + 2];
		size_t total;

		snprintf(tmp, sizeof(tmp), "%s\n", p);
		total = len;
		while (voff < total) {
			ssize_t w = write(fd, tmp + voff, total - voff);

			if (w < 0) {
				if (errno == EINTR)
					continue;
				if (asprintf(out, "ERROR: 写入 %s 失败: %s",
					     resolved, strerror(errno)) < 0)
					*out = NULL;
				rc = AI_ERR_API;
				goto done;
			}
			voff += (size_t)w;
		}
		break;
	}
	close(fd);
	fd = -1;

	{
		char now[512];
		ssize_t n = read_small_file(resolved, now, sizeof(now));

		if (n < 0)
			now[0] = '\0';
		else {
			while (n > 0 && (now[n - 1] == '\n' ||
					 now[n - 1] == '\r'))
				now[--n] = '\0';
		}
		if (asprintf(out, "OK: 已写入 %s\n  旧值: %s\n  新值: %s"
			     "（审计已记录，可据此回滚）", key, old, now) < 0)
			*out = NULL;
	}
	rc = AI_OK;

done:
	if (fd >= 0)
		close(fd);
	free(key);
	free(value);
	free(err);
	return rc;
}

static int exec_sysctl_blacklist(char **out)
{
	char buf[8192];
	size_t off = 0;
	int i;

	off += (size_t)snprintf(buf + off, sizeof(buf) - off,
				"sysctl 崩溃黑名单（写入即拒绝，不可绕过）:\n");
	for (i = 0; i < (int)(sizeof(g_sysctl_blacklist) /
			      sizeof(g_sysctl_blacklist[0])); i++) {
		int w = snprintf(buf + off, sizeof(buf) - off,
				 "  %-32s %s\n", g_sysctl_blacklist[i].key,
				 g_sysctl_blacklist[i].reason);

		if (w < 0 || (size_t)w >= sizeof(buf) - off)
			break;
		off += (size_t)w;
	}
	snprintf(buf + off, sizeof(buf) - off,
		 "匹配方式: 前缀（kernel.panic 覆盖 panic_on_oops 等）；"
		 "bypass=不可（无 --force 通道）。\n");
	*out = strdup(buf);
	return AI_OK;
}

/* ---- W48: sysfs/procfs 动态路径通道（R 读 / W2 写） ---- */

static int exec_sysfs_dyn(const struct ai_tool *tool, const char *args_json,
			  char **out)
{
	int is_set = tool->name && strcmp(tool->name, "sysfs_set") == 0;
	char *path = arg_str(args_json, "path");
	char resolved[PATH_MAX];
	char *value = NULL;
	char *err = NULL;
	char *buf = NULL;
	int fd = -1;
	int rc = AI_ERR_INVALID_ARG;

	if (!path || path[0] != '/') {
		*out = strdup("ERROR: 缺少必填参数 path（必须是绝对路径）");
		goto done;
	}
	if (strstr(path, "..")) {
		*out = strdup("ERROR: path 含 .. 路径穿越分量，已拒绝");
		goto done;
	}
	if (!realpath(path, resolved)) {
		if (asprintf(out, "ERROR: 路径不存在或不可解析: %s (%s)",
			     path, strerror(errno)) < 0)
			*out = NULL;
		rc = AI_ERR_NOT_FOUND;
		goto done;
	}
	/* /proc/net 是 /proc/self/net 的符号链接；realpath 后变成
	 * /proc/<pid>/net/...，原前缀检查会误拒合法只读路径。
	 * 仅读模式接受该内核受控形状；写模式不受影响。 */
	if (!path_under_prefixes(resolved, is_set ? g_sysfs_write_allow :
				 g_sysfs_read_allow) &&
	    !(!is_set && path_under_proc_net(resolved))) {
		if (asprintf(out,
			     "ERROR: %s 不在%s允许前缀内，已拒绝；sysfs_get 仅支持 "
			     "/sys、/proc/sys、/proc/irq、/proc/ai、/proc/pressure、"
			     "/proc/net；/proc/<pid>/* 或 /etc/* 请改用 exec_run "
			     "（如 ps、cat）或对应的 procfs_* 工具",
			     resolved, is_set ? "写入" : "读取") < 0)
			*out = NULL;
		rc = AI_ERR_INVALID_ARG;
		goto done;
	}
	if (!is_set) {
		long long maxb = arg_ll(args_json, "max_bytes", 32768);
		ssize_t n;

		if (maxb < 1)
			maxb = 1;
		if (maxb > 131072)
			maxb = 131072;
		buf = malloc((size_t)maxb + 1);
		if (!buf) {
			*out = strdup("ERROR: 内存不足");
			rc = AI_ERR_MEMORY;
			goto done;
		}
		n = read_small_file(resolved, buf, (size_t)maxb + 1);
		if (n < 0) {
			if (asprintf(out, "ERROR: 读取 %s 失败: %s", resolved,
				     strerror(errno)) < 0)
				*out = NULL;
			rc = AI_ERR_GENERIC;
			goto done;
		}
		if (n == 0)
			snprintf(buf, (size_t)maxb + 1, "(空文件) %s", resolved);
		*out = buf;
		buf = NULL;
		rc = AI_OK;
		goto done;
	}

	/* set 分支 */
	value = arg_str(args_json, "value");
	if (!value) {
		*out = strdup("ERROR: 缺少必填参数 value");
		goto done;
	}
	if (!value_single_line_ok(value, &err)) {
		if (asprintf(out, "ERROR: 非法值: %s（未写入）",
			     err ? err : "格式错误") < 0)
			*out = NULL;
		goto done;
	}
	{
		char old[512];
		ssize_t oldn = read_small_file(resolved, old, sizeof(old));
		ssize_t n;

		if (oldn < 0) {
			if (asprintf(out, "ERROR: 读取旧值失败（%s），为可"
				     "回滚性拒绝写入", strerror(errno)) < 0)
				*out = NULL;
			rc = AI_ERR_GENERIC;
			goto done;
		}
		while (oldn > 0 && (old[oldn - 1] == '\n' ||
				    old[oldn - 1] == '\r'))
			old[--oldn] = '\0';
		sysctl_audit_record(resolved, old, value);
		fd = open(resolved, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
		if (fd < 0) {
			int e = errno;

			if (asprintf(out, "ERROR: 写入 %s 失败: %s%s", resolved,
				     strerror(e),
				     (e == EPERM || e == EACCES) ?
				     "（需要 root/CAP_SYS_ADMIN）" : "") < 0)
				*out = NULL;
			rc = AI_ERR_API;
			goto done;
		}
		{
			char tmp[SYSCTL_VALUE_MAX + 2];
			size_t total, off = 0;

			snprintf(tmp, sizeof(tmp), "%s\n", value);
			total = strlen(tmp);
			while (off < total) {
				ssize_t w = write(fd, tmp + off, total - off);

				if (w < 0) {
					if (errno == EINTR)
						continue;
					if (asprintf(out, "ERROR: 写入 %s "
						     "失败: %s", resolved,
						     strerror(errno)) < 0)
						*out = NULL;
					rc = AI_ERR_API;
					goto done;
				}
				off += (size_t)w;
			}
		}
		close(fd);
		fd = -1;
		{
			char now[512];

			n = read_small_file(resolved, now, sizeof(now));
			if (n < 0)
				now[0] = '\0';
			else {
				while (n > 0 && (now[n - 1] == '\n' ||
						 now[n - 1] == '\r'))
					now[--n] = '\0';
			}
			if (asprintf(out, "OK: 已写入 %s\n  旧值: %s\n  新值: %s"
				     "（审计已记录）", resolved, old, now) < 0)
				*out = NULL;
		}
	}
	rc = AI_OK;

done:
	if (fd >= 0)
		close(fd);
	free(path);
	free(value);
	free(err);
	free(buf);
	return rc;
}



static int exec_sysfs_write(const struct ai_tool *tool, const char *args_json,
			    char **out)
{
	char *value;
	FILE *fp;

	value = arg_str(args_json, "value");
	if (!value || !value[0]) {
		*out = strdup("ERROR: 缺少必填参数 value（写入目标 " \
			      "固定，不接受路径参数）");
		free(value);
		return AI_ERR_INVALID_ARG;
	}

	fp = fopen(tool->path, "w");
	if (!fp) {
		const int e = errno;

		if (asprintf(out, "ERROR: 写入 %s 失败: %s%s",
			     tool->path, strerror(e),
			     e == EPERM || e == EACCES ?
			     "（写需要 CAP_SYS_ADMIN，"
			     "请以 root/sudo 运行）" : "") < 0)
			*out = NULL;
		free(value);
		return AI_ERR_GENERIC;
	}
	fprintf(fp, "%s\n", value);
	fclose(fp);

	/* 回读确认（可读节点），失败不影响结论 */
	{
		char rd[256];
		FILE *r = fopen(tool->path, "r");

		rd[0] = '\0';
		if (r) {
			size_t n = fread(rd, 1, sizeof(rd) - 1, r);

			rd[n] = '\0';
			fclose(r);
		}
		if (asprintf(out, "OK: 已写入 %s <- %s%s%s",
			     tool->path, value,
			     rd[0] ? "（当前值: " : "",
			     rd[0] ? rd : "") < 0)
			*out = NULL;
	}
	free(value);
	return AI_OK;
}

/* ---- netlink-act（v2：客户端值域钳制） ---- */

static int exec_netlink_act(const struct ai_tool *tool, const char *args_json,
			    char **out)
{
	struct ai_nl_client cli;
	struct ai_nl_act req;
	struct ai_nl_act_ack ack;
	long long value, orig_value, pid = 0, confidence;
	char *clamp_note = NULL;
	int clamped = 0;
	int kern_err = 0;
	int rc;

	value = arg_ll(args_json, "value", 0);
	confidence = arg_ll(args_json, "confidence", 50);
	if (confidence < 0)
		confidence = 0;
	if (confidence > 100)
		confidence = 100;

	/*
	 * P0 纵深防御：按注册表 value_min/value_max 客户端钳制。
	 * 内核安全边界仍兜底（min/max + max_impact），但客户端先行
	 * 限幅可避免"下发即被拒/被静默限幅"的语义漂移，并向模型
	 * 显式回报调整。
	 */
	orig_value = value;
	if (tool->has_value_min && value < tool->value_min) {
		value = tool->value_min;
		clamped = 1;
	}
	if (tool->has_value_max && value > tool->value_max) {
		value = tool->value_max;
		clamped = 1;
	}
	if (clamped && asprintf(&clamp_note,
				"[钳制] 请求值 %lld 超出 [%lld, %lld]，"
				"已调整为 %lld\n",
				orig_value,
				tool->has_value_min ? tool->value_min :
						      orig_value,
				tool->has_value_max ? tool->value_max :
						      orig_value,
				value) < 0)
		clamp_note = NULL;

	memset(&req, 0, sizeof(req));
	req.domain = (__u8)tool->domain;
	req.decision_type = 1;          /* 工具调用标记（内核仅记录） */
	req.confidence = (__u8)confidence;

	/*
	 * v3 定向协议：注册表 tool->param 即内核策略动作名
	 * （tools.json 单源，如 "mm.swappiness"）；缺失时回退从工具名
	 * 解析（剥 "netlink.act." 前缀）。超长直接拒绝，绝不静默截断
	 * （截断可能命中错误参数）。
	 */
	{
		/* 内核参数名与工具名是两层：注册表 param 字段是唯一映射
		 * （如工具 netlink_act_sched_nice → 内核参数 "sched.nice"）。
		 * T14 工具名下划线化后，无法从名字无损还原内核点号参数名
		 * （sec.lsm_override / ai.decision_inject 同含两类分隔符），
		 * 旧的按名剥 "netlink.act." 前缀兜底已删：param 缺失一律
		 * 拒绝，不再退化到广播语义。 */
		const char *p = (tool->param && tool->param[0]) ?
				tool->param : NULL;

		if (!p) {
			*out = strdup("ERROR: 注册表工具缺少 param 字段"
				      "（内核参数名单源），拒绝下发");
			free(clamp_note);
			return AI_ERR_INVALID_ARG;
		}
		if (strlen(p) >= sizeof(req.param)) {
			*out = strdup("ERROR: 参数名过长（>= "
				      "AI_NL_ACT_PARAM_LEN），"
				      "拒绝下发");
			free(clamp_note);
			return AI_ERR_INVALID_ARG;
		}
		snprintf(req.param, sizeof(req.param), "%s", p);
	}

	if (tool->task_param) {
		pid = arg_ll(args_json, "pid", 0);
		if (pid <= 0) {
			*out = strdup("ERROR: 该工具为任务参数，缺少必填"
				      "参数 pid（>0）");
			free(clamp_note);
			return AI_ERR_INVALID_ARG;
		}
		/* 内核约定：data[0]=pid, data[1]=value（ai_control.c） */
		req.data[0] = (__u64)pid;
		req.data[1] = (__u64)value;
		/* proc.rlimit 需第三槽 data[2]=资源号（内核
		 * ai_proc_rlimit_apply_ex：res 经 ai_sys_prlimit_set），
		 * 缺省 7=RLIMIT_NOFILE；后续带附加槽的参数照此模式扩展 */
		if (tool->param && strcmp(tool->param, "proc.rlimit") == 0) {
			long long res = arg_ll(args_json, "res", 7);

			if (res < 0 || res > 15)
				res = 7;
			req.data[2] = (__u64)res;
		}
	} else {
		req.data[0] = (__u64)value;
	}

	rc = ai_nl_client_open(&cli);
	if (rc != AI_OK) {
		if (asprintf(out, "%sERROR: NETLINK_AI 通道不可用 (%s)——"
			     "需要在 AIKernel 内核上运行",
			     clamp_note ? clamp_note : "",
			     ai_error_string(rc)) < 0)
			*out = NULL;
		free(clamp_note);
		return rc;
	}

	rc = ai_nl_send_act(&cli, &req, &ack, &kern_err);
	ai_nl_client_close(&cli);

	if (rc == AI_ERR_API) {
		const char *hint = ai_nl_errno_hint(kern_err);

		if (asprintf(out, "%sERROR: 内核拒绝 (errno=%d %s)%s%s",
			     clamp_note ? clamp_note : "",
			     kern_err, strerror(kern_err),
			     hint ? " 提示: " : "", hint ? hint : "") < 0)
			*out = NULL;
		free(clamp_note);
		return rc;
	}
	if (rc != AI_OK) {
		if (asprintf(out, "%sERROR: netlink 传输失败: %s",
			     clamp_note ? clamp_note : "",
			     ai_error_string(rc)) < 0)
			*out = NULL;
		free(clamp_note);
		return rc;
	}

	{
		char tail[96];

		tail[0] = '\0';
		if (tool->task_param)
			snprintf(tail, sizeof(tail), " pid=%lld", pid);
		if (asprintf(out, "%sOK: ACT 已下发 domain=%u param=%s"
			     " value=%lld confidence=%u%s | executed=%u"
			     " hit=%s ai_err=%d%s",
			     clamp_note ? clamp_note : "",
			     (unsigned)req.domain,
			     req.param[0] ? req.param : "(broadcast)", value,
			     (unsigned)req.confidence, tail,
			     ack.executed, ack.hit ? "yes" : "no",
			     ack.ai_err,
			     (ack.executed == 0 && ack.ai_err == 0) ?
			     "（未命中任何策略）" : "") < 0)
			*out = NULL;
	}
	free(clamp_note);
	return AI_OK;
}

/* ---- netlink-sense（v2 新增：AI_CMD_SENSE 拉遥测） ---- */

static int exec_netlink_sense(const struct ai_tool *tool,
			      const char *args_json, char **out)
{
	struct ai_nl_client cli;
	struct ai_nl_sense_ack ack;
	void *stream = NULL;
	size_t stream_len = 0;
	char *cpu_s = NULL, *fmt_s = NULL;
	long long count;
	__u32 cpu = AI_NL_SENSE_CPU_ALL;
	__u32 format = AI_NL_FORMAT_HUMAN;
	int kern_err = 0;
	int rc;

	(void)tool;

	cpu_s = arg_str(args_json, "cpu");
	fmt_s = arg_str(args_json, "format");
	count = arg_ll(args_json, "count", 128);

	/* cpu: "all" 或 CPU 编号（0..8191，钳到合理范围） */
	if (cpu_s && cpu_s[0] && strcmp(cpu_s, "all") != 0) {
		char *endp = NULL;
		long v = strtol(cpu_s, &endp, 10);

		if (endp && *endp == '\0' && v >= 0 && v <= 8191)
			cpu = (__u32)v;
	}

	/* count: 1..4096（与内核校验一致） */
	if (count < 1)
		count = 1;
	if (count > AI_NL_SENSE_MAX_RECORDS)
		count = AI_NL_SENSE_MAX_RECORDS;

	/* format: raw/human（默认 human） */
	if (fmt_s && strcmp(fmt_s, "raw") == 0)
		format = AI_NL_FORMAT_RAW;

	free(cpu_s);
	free(fmt_s);

	stream = malloc(AI_NL_PAYLOAD_MAX + 1);
	if (!stream) {
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}

	rc = ai_nl_client_open(&cli);
	if (rc != AI_OK) {
		if (asprintf(out, "ERROR: NETLINK_AI 通道不可用 (%s)——"
			     "需要在 AIKernel 内核上运行（提示: SENSE 要求"
			     " AI 子系统已启用）", ai_error_string(rc)) < 0)
			*out = NULL;
		free(stream);
		return rc;
	}

	rc = ai_nl_send_sense(&cli, cpu, (__u32)count, format,
			      &ack, stream, AI_NL_PAYLOAD_MAX, &stream_len,
			      &kern_err);
	ai_nl_client_close(&cli);

	if (rc == AI_ERR_API) {
		const char *hint = ai_nl_errno_hint(kern_err);

		if (asprintf(out, "ERROR: 内核拒绝 (errno=%d %s)%s%s",
			     kern_err, strerror(kern_err),
			     hint ? " 提示: " : "", hint ? hint : "") < 0)
			*out = NULL;
		free(stream);
		return rc;
	}
	if (rc != AI_OK) {
		if (asprintf(out, "ERROR: netlink 传输失败: %s",
			     ai_error_string(rc)) < 0)
			*out = NULL;
		free(stream);
		return rc;
	}

	{
		char cpu_label[16];

		/* cpu 显示：ALL → "all"，数值 CPU → 十进制（修复空串） */
		if (cpu == AI_NL_SENSE_CPU_ALL)
			snprintf(cpu_label, sizeof(cpu_label), "all");
		else
			snprintf(cpu_label, sizeof(cpu_label), "%u", cpu);

		if (format == AI_NL_FORMAT_HUMAN) {
			size_t show = stream_len;

			if (show > TOOL_EXEC_OUT_MAX - 256)
				show = TOOL_EXEC_OUT_MAX - 256;
			/* %.*s 截断同样不得切断 UTF-8 序列（T2 问题 1） */
			show = ai_json_utf8_floor((const char *)stream, show);
			if (asprintf(out,
				     "OK: SENSE cpu=%s count=%u | 记录数=%u "
				     "字节=%zu ai_err=%d\n%.*s%s",
				     cpu_label, (unsigned)count,
				     ack.records, stream_len, ack.ai_err,
				     (int)show, (const char *)stream,
				     stream_len > show ?
				     "\n(输出超限截断)" : "") < 0)
				*out = NULL;
		} else {
			/* raw 为二进制定长记录流：给头部统计 + 十六进制预览 */
			size_t show = stream_len < 64 ? stream_len : 64;
			size_t i;
			char hex[64 * 3 + 1];
			size_t off = 0;

			for (i = 0; i < show; i++)
				off += (size_t)snprintf(hex + off,
							sizeof(hex) - off,
							"%02x ",
							((const unsigned char *)
								stream)[i]);
			if (asprintf(out, "OK: SENSE cpu=%s count=%u | "
				     "记录数=%u 字节=%zu ai_err=%d（raw "
				     "二进制流，预览前 %zu 字节）\n%s",
				     cpu_label, (unsigned)count,
				     ack.records, stream_len, ack.ai_err,
				     show, hex) < 0)
				*out = NULL;
		}
	}
	free(stream);
	return AI_OK;
}

/* ---- exec（v2：单源白名单 + 超时 + stdin 防挂死 + 整条拒绝） ---- */

/*
 * 内置 fallback 白名单（仅当 tools.json 的 exec 工具未内嵌
 * "exec"."commands" 时使用；正常路径以 tools.json 为唯一权威，
 * 彻底消除双源漂移）。bin 为 NULL 时按 /usr/bin → /bin 查找。
 */
static const struct tool_exec_cmd g_exec_fallback[] = {
	{ .command = "ls",     .risk = "R" },
	{ .command = "cat",    .risk = "R" },
	{ .command = "head",   .risk = "R" },
	{ .command = "tail",   .risk = "R" },
	{ .command = "grep",   .risk = "R" },
	{ .command = "ps",     .risk = "R" },
	{ .command = "free",   .risk = "R" },
	{ .command = "df",     .risk = "R" },
	{ .command = "uname",  .risk = "R" },
	{ .command = "uptime", .risk = "R" },
	{ .command = "date",   .risk = "R" },
};

/* 命令查找：优先 tools.json 内嵌表，缺失时退回内置表 */
static const struct tool_exec_cmd *exec_spec_find(const struct ai_tool *tool,
						  const char *cmd)
{
	int i;

	for (i = 0; tool->exec_cmds && i < tool->exec_cmd_count; i++) {
		if (strcmp(tool->exec_cmds[i].command, cmd) == 0)
			return &tool->exec_cmds[i];
	}
	for (i = 0; i < (int)(sizeof(g_exec_fallback) /
			      sizeof(g_exec_fallback[0])); i++) {
		if (strcmp(g_exec_fallback[i].command, cmd) == 0)
			return &g_exec_fallback[i];
	}
	return NULL;
}

/* 参数中的 shell 元字符黑名单（fork+execv 不经 shell，双保险） */
static int arg_has_meta(const char *s)
{
	static const char meta[] = ";|&`$><\\\n\r";

	return s[strcspn(s, meta)] != '\0';
}

/*
 * args_array_parse - 解析数组 token 内全部字符串元素为参数向量
 * （arg_str_array 的核心循环；任一元素含元字符/超长 → 整条拒绝）
 */
static int args_array_parse(const char *arr, size_t alen,
			    char ***outv, int *outn, char **err_out)
{
	int i;

	for (i = 0; ; i++) {
		const char *et;
		size_t el;
		int ety;
		char *s;
		char **nv;

		if (ai_json_arr_get(arr, alen, i, &et, &el, &ety) != 1)
			break;
		if (ety != AI_JSON_STR)
			continue;
		s = ai_json_strdup_str(et, el);
		if (!s)
			break;
		if (arg_has_meta(s)) {
			if (asprintf(err_out,
				     "args[%d]=%s 含 shell 元字符；exec_run "
				     "不经过 shell，管道/重定向/&& 请拆成多次"
				     "工具调用（单命令 + args 数组）",
				     i, s) < 0)
				*err_out = NULL;
			free(s);
			goto reject;
		}
		if (strlen(s) > 256) {
			if (asprintf(err_out,
				     "args[%d] 超长（%zu > 256 字符）；请拆分",
				     i, strlen(s)) < 0)
				*err_out = NULL;
			free(s);
			goto reject;
		}
		nv = realloc(*outv, sizeof(char *) * (size_t)(*outn + 1));
		if (!nv) {
			free(s);
			break;
		}
		*outv = nv;
		(*outv)[(*outn)++] = s;
	}
	return AI_OK;

reject:
	for (i = 0; i < *outn; i++)
		free((*outv)[i]);
	free(*outv);
	*outv = NULL;
	*outn = 0;
	return AI_ERR_INVALID_ARG;
}

/*
 * 解析 args 数组参数为字符串向量（P0 语义修复：任一参数含元字符或
 * 超长 → **整条拒绝**，不再静默丢弃导致命令语义改变）。
 * 返回 AI_OK 或 AI_ERR_INVALID_ARG（*err_out 收到拒绝原因文本）。
 *
 * W20 修3b 容错：deepseek 类模型偶发把 args 编码为**字符串值**且
 * 其内容本身是数组文本（"args": "[\"/tmp/x.txt\"]"，T3「参数错乱」
 * 同款；w20 tee-loop 20 次实测 4 次复现 → tee 静默无参执行、文件
 * 未落盘）。此形态不再按 0 参数执行：对字符串值去转义后若以 '['
 * 开头，按数组文本二次解析。
 */
static int arg_str_array(const char *args_json, const char *key,
			 char ***outv, int *outn, char **err_out)
{
	const char *v;
	size_t vl;
	int vt;

	*outv = NULL;
	*outn = 0;
	*err_out = NULL;
	if (!args_json || !args_json[0])
		return AI_OK;
	if (ai_json_obj_get(args_json, strlen(args_json), key,
			    &v, &vl, &vt) != 1)
		return AI_OK;

	if (vt == AI_JSON_ARR)
		return args_array_parse(v, vl, outv, outn, err_out);

	if (vt == AI_JSON_STR) {
		char *inner = ai_json_strdup_str(v, vl);
		int rc = AI_OK;

		if (inner && inner[0] == '[')
			rc = args_array_parse(inner, strlen(inner),
					      outv, outn, err_out);
		free(inner);
		return rc;
	}
	return AI_OK;
}

/*
 * exec_python3_args_ok - W20 修5：python3 参数形态校验
 * 白名单允许的形态：python3 <script.py> [脚本参数...]。
 *   - 首参必须以 .py 结尾的脚本路径（不得以 '-' 开头）——禁用
 *     -c/-m 等解释器表达式/模块入口（裸代码执行面不受控）；
 *   - 首参之后的脚本参数放行（脚本自有 argparse 选项如 -p/-t 属
 *     脚本行为，非解释器入口；W20 E1 实测 -p 1-65535 被误挡后放宽）；
 *   - 全部参数仍过 arg_str_array 的元字符黑名单（双保险之一）。
 * 返回: 1=通过；0=拒绝（*err_out 收到拒绝原因）。
 */
static int exec_python3_args_ok(char **argv, int n, char **err_out)
{
	size_t len;

	if (n < 1) {
		*err_out = strdup("用法: python3 <script.py> [参数...]——"
				  "缺少脚本路径（禁止 -c/-m 等解释器表达式"
				  "入口），已拒绝执行");
		return 0;
	}
	if (argv[0][0] == '-') {
		if (asprintf(err_out, "python3 白名单形态校验失败：首参 "
			     "'%s' 以 '-' 开头（禁止解释器选项/表达式"
			     "入口如 -c/-m；脚本选项请写在脚本路径之后），"
			     "已拒绝执行", argv[0]) < 0)
			*err_out = NULL;
		return 0;
	}
	len = strlen(argv[0]);
	if (len < 4 || strcmp(argv[0] + len - 3, ".py") != 0) {
		if (asprintf(err_out, "python3 白名单形态校验失败：首参 "
			     "'%s' 不是 .py 脚本路径（仅允许 "
			     "python3 <script.py> 形态），已拒绝执行",
			     argv[0]) < 0)
			*err_out = NULL;
		return 0;
	}
	return 1;
}

/* ".." 路径分量检测（防 /root/../etc 与相对路径穿越） */
static int path_has_dotdot(const char *s)
{
	const char *p = s;

	while ((p = strstr(p, "..")) != NULL) {
		int prev_ok = (p == s) || p[-1] == '/';
		int next_ok = (p[2] == '\0') || p[2] == '/';

		if (prev_ok && next_ok)
			return 1;
		p += 2;
	}
	return 0;
}

/* 允许根判定：abs 必须等于根或位于根下（按 '/' 边界，防 /tmpfoo 绕过） */
static int w1_abs_in_roots(const char *abs, const char *const *roots)
{
	int i;

	for (i = 0; roots && roots[i]; i++) {
		const char *d = roots[i];
		size_t dl = strlen(d);

		if (strcmp(abs, d) == 0 ||
		    (strncmp(abs, d, dl) == 0 && abs[dl] == '/'))
			return 1;
	}
	return 0;
}

/*
 * W69 P1-1：W1/W2 写目标校验（符号链接解析 + 父目录校验）。
 *   - 绝对路径：解析后必须在允许根内；相对路径按当前 cwd 解析再判；
 *   - 目标已存在：realpath 解析全部符号链接，解析结果必须在允许根内
 *     （拦 ln -s /etc/passwd /tmp/x + tee /tmp/x 一类写穿链接）；
 *   - 目标不存在：父目录 realpath 必须在允许根内；
 *   - 一律拒绝 ".." 穿越。
 * 说明：TOCTOU 窗口仍存在（外部命令在检查后可使用链接），故 W1 写面
 * 另有命令级参数过滤与 W2 确认兜底；本校验把常见链接逃逸关死。
 */
static int w1_path_allowed_in(const char *arg, const char *const *roots,
			      char **err_out)
{
	char abs[PATH_MAX];
	char real[PATH_MAX];
	char parent[PATH_MAX];
	char cwd[PATH_MAX];
	char *slash;
	struct stat st;
	size_t alen;

	if (!arg || !arg[0]) {
		*err_out = strdup("路径校验失败（W1/W2 写路径）：空路径，"
				  "已拒绝执行");
		return 0;
	}
	/* W74：租约/确认存储是不可写黑名单（realpath/相对路径/符号链接
	 * 解析后命中一律拒绝），普通文件工具无法伪造 approval。 */
	if (ai_lease_path_protected(arg)) {
		*err_out = strdup("路径校验失败（W1/W2 写路径）：目标属于"
				  "租约/确认受保护存储（/var/lib/aikernel 或 "
				  "/run/aikernel），已拒绝执行");
		return 0;
	}
	if (path_has_dotdot(arg)) {
		*err_out = strdup("路径校验失败（W1/W2 写路径）：参数含 \"..\" "
				  "路径穿越分量，已拒绝执行");
		return 0;
	}
	if (arg[0] == '/') {
		alen = strlen(arg);
		if (alen >= sizeof(abs)) {
			*err_out = strdup("路径校验失败（W1/W2 写路径）："
					  "路径过长，已拒绝执行");
			return 0;
		}
		memcpy(abs, arg, alen + 1);
	} else {
		if (!getcwd(cwd, sizeof(cwd))) {
			*err_out = strdup("路径校验失败（W1/W2 写路径）：无法"
					  "解析当前工作目录");
			return 0;
		}
		if (snprintf(abs, sizeof(abs), "%s/%s", cwd, arg) >=
		    (int)sizeof(abs)) {
			*err_out = strdup("路径校验失败（W1/W2 写路径）："
					  "路径过长，已拒绝执行");
			return 0;
		}
	}

	if (lstat(abs, &st) == 0) {
		/* 已存在（含符号链接）：解析后必须落在允许根内 */
		if (!realpath(abs, real)) {
			if (asprintf(err_out, "路径校验失败（W1/W2 写路径）："
				     "无法解析 %s: %s", abs,
				     strerror(errno)) < 0)
				*err_out = NULL;
			return 0;
		}
		if (ai_lease_path_protected(real)) {
			*err_out = strdup("路径校验失败（W1/W2 写路径）：符号"
					  "链接解析到租约/确认受保护存储，"
					  "已拒绝执行");
			return 0;
		}
		if (w1_abs_in_roots(real, roots))
			return 1;
		if (asprintf(err_out, "路径校验失败（W1/W2 写路径）：%s 解析为 "
			     "%s，不在允许目录内，已拒绝执行", arg, real) < 0)
			*err_out = NULL;
		return 0;
	}
	if (errno != ENOENT) {
		if (asprintf(err_out, "路径校验失败（W1/W2 写路径）：无法检查 "
			     "%s: %s", abs, strerror(errno)) < 0)
			*err_out = NULL;
		return 0;
	}

	/* 目标不存在：父目录必须存在且解析后在允许根内 */
	memcpy(parent, abs, sizeof(parent));
	slash = strrchr(parent, '/');
	if (!slash || slash == parent) {
		*err_out = strdup("路径校验失败（W1/W2 写路径）：不允许直接"
				  "写根目录下的目标，已拒绝执行");
		return 0;
	}
	*slash = '\0';
	if (!realpath(parent, real)) {
		if (asprintf(err_out, "路径校验失败（W1/W2 写路径）：父目录 %s "
			     "不可解析: %s", parent, strerror(errno)) < 0)
			*err_out = NULL;
		return 0;
	}
	if (ai_lease_path_protected(real)) {
		*err_out = strdup("路径校验失败（W1/W2 写路径）：父目录解析"
				  "到租约/确认受保护存储，已拒绝执行");
		return 0;
	}
	if (w1_abs_in_roots(real, roots))
		return 1;
	{
		char msg[512];
		size_t off = 0;
		int i;

		off += (size_t)snprintf(msg, sizeof(msg),
					"路径校验失败（W1/W2 写路径）：%s 的父"
					"目录解析为 %s，不在允许目录（",
					arg, real);
		for (i = 0; roots && roots[i] && off < sizeof(msg); i++)
			off += (size_t)snprintf(msg + off, sizeof(msg) - off,
						"%s%s", i ? " " : "", roots[i]);
		if (off < sizeof(msg))
			snprintf(msg + off, sizeof(msg) - off,
				 "）内，已拒绝执行");
		*err_out = strdup(msg);
	}
	return 0;
}

/*
 * W69 P1-1：选项是否需要消费下一个参数（只用于"操作数"提取）。
 * 返回 1 表示下一个 argv 是选项值、不是写目标（如 touch -d TIME）。
 */
static int exec_opt_takes_value(const char *cmd, const char *a)
{
	static const char *const tar_ro[] = {
		"-T", "-X", "-b", "-H", "-V", "-L", "--files-from",
		"--exclude-from", "--blocking-factor", "--format", "--label",
		"--tape-length", "--owner", "--group", "--mode", "--mtime",
		"--transform", "--xform", "--exclude", "--newer",
		"--after-date", NULL,
	};

	if (!cmd || !a || a[0] != '-' || !a[1])
		return 0;
	if (a[1] == '-' && strchr(a, '='))
		return 0;               /* --opt=VAL 是单参数 */
	if (strcmp(cmd, "touch") == 0)
		return !strcmp(a, "-d") || !strcmp(a, "-r") ||
		       !strcmp(a, "-t") || !strcmp(a, "--date") ||
		       !strcmp(a, "--reference");
	if (strcmp(cmd, "mkdir") == 0)
		return !strcmp(a, "-m") || !strcmp(a, "--mode");
	if (strcmp(cmd, "gzip") == 0)
		return !strcmp(a, "-S") || !strcmp(a, "--suffix");
	if (strcmp(cmd, "cp") == 0 || strcmp(cmd, "mv") == 0 ||
	    strcmp(cmd, "ln") == 0)
		return !strcmp(a, "-S") || !strcmp(a, "--suffix");
	if (strcmp(cmd, "tar") == 0) {
		int i;

		for (i = 0; tar_ro[i]; i++)
			if (strcmp(a, tar_ro[i]) == 0)
				return 1;
	}
	return 0;
}

/*
 * W69 P1-1：按命令语义提取真正的写目标并逐个做链接安全校验。
 *   - cp：只校验目标；-t DIR 校验 DIR。
 *   - mv：校验源+目标（源会被删除；只校验目标可把 /etc/x 移进 /tmp）。
 *   - ln：符号链接只校验目标；硬链接校验源（inode 别名可被后续写穿）。
 *   - sed：只有 -i/--in-place 才写文件；无 -i 时 --sandbox 已禁 e/r/w。
 *   - gcc/cc：只校验输出类选项（-o/-MF/-MJ）；输入路径另由
 *     exec_gcc_args_ok 限 /tmp（含链接解析）。
 *   - chmod/chown：跳过第一个操作数（模式/属主），其余为路径。
 *   - touch/mkdir/tar/gzip/tee/rm 等：非选项参数（跳过选项值）。
 * 返回 1=通过；0=拒绝（*err_out 收到原因）。
 */
static int exec_check_write_targets(const char *cmd, char **argv, int argc,
				    const char *const *roots, char **err_out)
{
	int operands[128];
	int nops = 0;
	int i;

	if (!cmd)
		return 1;

	if (strcmp(cmd, "gcc") == 0 || strcmp(cmd, "cc") == 0) {
		for (i = 0; i < argc; i++) {
			const char *a = argv[i];
			const char *v = NULL;

			if (strcmp(a, "-o") == 0 ||
			    strcmp(a, "-MF") == 0 ||
			    strcmp(a, "-MJ") == 0 ||
			    strcmp(a, "--output") == 0) {
				if (i + 1 < argc)
					v = argv[++i];
			} else if (a[0] == '-' && a[1] == 'o' && a[2]) {
				v = a + 2;
			} else if (strncmp(a, "-MF", 3) == 0 && a[3]) {
				v = a + 3;
			} else if (strncmp(a, "-MJ", 3) == 0 && a[3]) {
				v = a + 3;
			}
			if (v && !w1_path_allowed_in(v, roots, err_out))
				return 0;
		}
		return 1;
	}

	if (strcmp(cmd, "sed") == 0) {
		int inplace = 0;
		int expr_opt = 0;
		int after_dd = 0;

		for (i = 0; i < argc; i++) {
			const char *a = argv[i];
			size_t alen;

			if (after_dd) {
				operands[nops++] = i;
				continue;
			}
			if (strcmp(a, "--") == 0) {
				after_dd = 1;
				continue;
			}
			if (a[0] != '-' || !a[1]) {
				operands[nops++] = i;
				continue;
			}
			alen = strlen(a);
			if (strcmp(a, "--in-place") == 0 ||
			    strncmp(a, "--in-place=", 11) == 0 ||
			    strcmp(a, "-i") == 0 ||
			    (a[1] != '-' && strchr(a, 'i')))
				inplace = 1;
			if (strcmp(a, "--expression") == 0 ||
			    strcmp(a, "--file") == 0 ||
			    (a[1] != '-' && (a[alen - 1] == 'e' ||
					     a[alen - 1] == 'f'))) {
				expr_opt = 1;
				if (i + 1 < argc)
					i++;    /* 跳过 -e/-f 的脚本值 */
			}
		}
		if (!inplace)
			return 1;       /* --sandbox 已禁用 e/r/w；无 -i 不落盘 */
		/* 无 -e/-f 时首个操作数是 sed 脚本，不是文件 */
		for (i = (expr_opt || nops == 0) ? 0 : 1; i < nops; i++) {
			if (!w1_path_allowed_in(argv[operands[i]], roots,
						err_out))
				return 0;
		}
		return 1;
	}

	if (strcmp(cmd, "cp") == 0 || strcmp(cmd, "mv") == 0 ||
	    strcmp(cmd, "ln") == 0) {
		int is_mv = strcmp(cmd, "mv") == 0;
		int is_ln = strcmp(cmd, "ln") == 0;
		int is_cp = strcmp(cmd, "cp") == 0;
		int ln_sym = 0;
		int cp_link = 0;
		int after_dd = 0;
		const char *tdir = NULL;

		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (after_dd) {
				operands[nops++] = i;
				continue;
			}
			if (strcmp(a, "--") == 0) {
				after_dd = 1;
				continue;
			}
			if (a[0] != '-' || !a[1]) {
				operands[nops++] = i;
				continue;
			}
			if (is_ln && strcmp(a, "--symbolic") == 0)
				ln_sym = 1;
			else if (is_ln && a[1] != '-' && strchr(a, 's'))
				ln_sym = 1;
			if (is_cp && (strcmp(a, "--link") == 0 ||
				      (a[1] != '-' && strchr(a, 'l'))))
				cp_link = 1;
			if (strncmp(a, "--target-directory=", 19) == 0) {
				tdir = a + 19;
			} else if (strcmp(a, "-t") == 0 ||
				   strcmp(a, "--target-directory") == 0) {
				if (i + 1 < argc)
					tdir = argv[++i];
			} else if (exec_opt_takes_value(cmd, a) &&
				   i + 1 < argc) {
				i++;    /* -S 等选项值 */
			}
		}
		if (tdir && !w1_path_allowed_in(tdir, roots, err_out))
			return 0;
		if (tdir) {
			/* 目标目录已校验；mv/硬链接（含 cp -l）源也要校验 */
			if (is_mv || (is_ln && !ln_sym) ||
			    (is_cp && cp_link)) {
				for (i = 0; i < nops; i++) {
					if (!w1_path_allowed_in(
						    argv[operands[i]], roots,
						    err_out))
						return 0;
				}
			}
			return 1;
		}
		if (nops == 0)
			return 1;
		/* 最后一个操作数是目标 */
		if (!w1_path_allowed_in(argv[operands[nops - 1]], roots,
					err_out))
			return 0;
		if (is_mv || (is_ln && !ln_sym) || (is_cp && cp_link)) {
			for (i = 0; i < nops - 1; i++) {
				if (!w1_path_allowed_in(argv[operands[i]],
							roots, err_out))
					return 0;
			}
		}
		(void)is_cp;
		return 1;
	}

	if (strcmp(cmd, "chmod") == 0 || strcmp(cmd, "chown") == 0) {
		int first = 1;
		int has_ref = 0;

		for (i = 0; i < argc; i++) {
			if (strncmp(argv[i], "--reference=", 12) == 0 ||
			    strcmp(argv[i], "--reference") == 0)
				has_ref = 1;
		}
		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (a[0] == '-' && a[1])
				continue;       /* 选项 */
			/* --reference 形态没有"模式/属主"操作数，全部校验 */
			if (first && !has_ref) {
				first = 0;      /* 模式/属主说明符 */
				continue;
			}
			first = 0;
			if (!w1_path_allowed_in(a, roots, err_out))
				return 0;
		}
		return 1;
	}

	/* 通用面：非选项参数即目标；跳过已知选项值 */
	for (i = 0; i < argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "--") == 0)
			continue;
		/* tar 的长选项贴合形式：--directory=DIR / --file=ARCHIVE */
		if (strcmp(cmd, "tar") == 0 &&
		    (strncmp(a, "--directory=", 12) == 0 ||
		     strncmp(a, "--file=", 7) == 0)) {
			const char *v = a + (a[2] == 'd' ? 12 : 7);

			if (!w1_path_allowed_in(v, roots, err_out))
				return 0;
			continue;
		}
		if (a[0] == '-' && a[1]) {
			/* tar 短选项贴合值：-C/etc、-f/tmp/a、-cvf/tmp/a */
			if (strcmp(cmd, "tar") == 0 && a[1] != '-') {
				const char *p;

				for (p = a + 1; *p; p++) {
					const char *v = NULL;

					if (*p == 'C' || *p == 'f') {
						if (p[1])
							v = p + 1;
						else if (i + 1 < argc)
							v = argv[++i];
						if (v && !w1_path_allowed_in(
							    v, roots, err_out))
							return 0;
						break;
					}
					/* 只读/数值选项值不参与路径校验 */
					if (strchr("TXbHVL", *p)) {
						if (!p[1] && i + 1 < argc)
							i++;
						break;
					}
				}
			}
			if (exec_opt_takes_value(cmd, a) && i + 1 < argc)
				i++;
			continue;
		}
		if (!w1_path_allowed_in(a, roots, err_out))
			return 0;
	}
	return 1;
}

/* 单调毫秒时钟（超时 deadline 用） */
static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ---- W65：exec 参数契约 / 写入回读 / 取消 ---- */

/*
 * 取消标志：由 shell/commands/cmd_ask.c 的 SIGINT handler 置位。
 * executor 独立链接（单测）时弱定义兜底为 0；ask 二进制里 cmd_ask.o
 * 的强定义优先。poll 等待期间看到置位即 SIGKILL 子进程并返回取消。
 */
__attribute__((weak)) volatile sig_atomic_t ai_cancel_requested;

/* 白名单命令名列表（结构化错误里的 AVAILABLE 段，按注册表顺序） */
static void exec_available_list(const struct ai_tool *tool, char *buf,
				size_t n)
{
	size_t off = 0;
	int i;

	if (!buf || !n)
		return;
	buf[0] = '\0';
	for (i = 0; tool->exec_cmds && i < tool->exec_cmd_count; i++) {
		const char *c = tool->exec_cmds[i].command;
		int w;

		if (!c)
			continue;
		w = snprintf(buf + off, n - off, "%s%s",
			     off ? ", " : "", c);
		if (w < 0 || (size_t)w >= n - off) {
			if (off + 4 < n)
				snprintf(buf + off, n - off, "...");
			break;
		}
		off += (size_t)w;
	}
}

/*
 * exec_param_error - 结构化参数错误（P2-01/P2-03）
 * 统一格式：ERROR[E_PARAM_<code>]: <detail>
 *           USAGE: <正确 JSON 形态>
 *           AVAILABLE(<n>): <白名单命令名>
 * cmd_ask 用 TOOL_ERR_PARAM_PREFIX 识别并自动纠正重试一次。
 */
static void exec_param_error(char **out, const char *code, const char *detail,
			     const struct ai_tool *tool)
{
	char avail[2048];

	exec_available_list(tool, avail, sizeof(avail));
	if (asprintf(out,
		     "%s_%s]: %s\n"
		     "USAGE: {\"command\":\"<单个白名单命令名>\","
		     "\"args\":[\"参数1\",\"参数2\"],"
		     "\"input\":\"<可选：喂给 stdin 的文本>\"}\n"
		     "AVAILABLE(%d): %s",
		     TOOL_ERR_PARAM_PREFIX, code, detail,
		     tool && tool->exec_cmd_count ? tool->exec_cmd_count : 0,
		     avail[0] ? avail : "(无)") < 0)
		*out = NULL;
}

/* 顶层参数键校验：未知键一律拒绝（stdin/stdin_data 是 input 的兼容别名） */
static int exec_check_arg_keys(const char *args_json, char **bad_key,
			       char **err)
{
	const char *k, *v;
	size_t kl, vl;
	int vt, i;

	*bad_key = NULL;
	*err = NULL;
	if (!args_json || !args_json[0])
		return AI_OK;
	for (i = 0; ; i++) {
		int mr = ai_json_obj_member(args_json, strlen(args_json), i,
					    &k, &kl, &v, &vl, &vt);
		char *key;

		if (mr == 0)
			break;
		if (mr < 0) {
			*err = strdup("arguments 不是合法的 JSON 对象，无法解析"
				      "参数");
			return AI_ERR_PARSE;
		}
		key = ai_json_strdup_str(k, kl);
		if (!key)
			return AI_ERR_MEMORY;
		if (strcmp(key, "command") && strcmp(key, "args") &&
		    strcmp(key, "input") && strcmp(key, "stdin") &&
		    strcmp(key, "stdin_data") && strcmp(key, "timeout")) {
			*bad_key = key;
			if (asprintf(err,
				     "未知参数 \"%s\"（exec_run 接受 "
				     "command/args/input/timeout；stdin 与 "
				     "stdin_data 是 input 的兼容别名，不会静默"
				     "忽略）",
				     key) < 0)
				*err = NULL;
			return AI_ERR_INVALID_ARG;
		}
		free(key);
	}
	return AI_OK;
}

/* input 及其兼容别名（stdin/stdin_data）解析；冲突返回 conflict=1 */
static char *exec_input_arg(const char *args_json, int *conflict)
{
	char *in = arg_str(args_json, "input");
	char *a = arg_str(args_json, "stdin");
	char *b = arg_str(args_json, "stdin_data");
	char *pick = in;

	*conflict = 0;
	if (!pick) {
		pick = a ? a : b;
		if (a && b && strcmp(a, b) != 0)
			*conflict = 1;
	} else if ((a && strcmp(pick, a) != 0) ||
		   (b && strcmp(pick, b) != 0))
		*conflict = 1;
	if (pick != a)
		free(a);
	if (pick != b)
		free(b);
	return pick;
}

/*
 * 写类命令的目标收集（P2-01 写后回读校验）：
 *   tee/touch/mkdir：全部非 flag 参数；
 *   cp/mv/ln：最后一个非 flag 参数（写目标）；
 *   gcc/cc：-o 后的输出文件。
 * 返回目标数（≤cap）；命令不在校验面返回 0。
 */
static int exec_collect_write_targets(const char *cmd, char **argv, int argc,
				      const char **paths, int cap)
{
	int i, n = 0;

	if (!cmd)
		return 0;
	if (strcmp(cmd, "tee") == 0) {
		for (i = 0; i < argc && n < cap; i++)
			if (argv[i][0] != '-')
				paths[n++] = argv[i];
	} else if (strcmp(cmd, "touch") == 0 ||
		   strcmp(cmd, "mkdir") == 0) {
		/* touch -d TIME / -r FILE / -t STAMP、mkdir -m MODE 的
		 * 选项值不是写目标，必须跳过，否则回读校验会 stat 失败。
		 * touch -m 是"只改 mtime"开关，不带值。 */
		int is_touch = (strcmp(cmd, "touch") == 0);
		int skip = 0;

		for (i = 0; i < argc && n < cap; i++) {
			if (skip) {
				skip = 0;
				continue;
			}
			if (argv[i][0] == '-') {
				char c = argv[i][1];

				if (c && !argv[i][2] &&
				    ((is_touch && (c == 'd' || c == 'r' ||
						   c == 't')) ||
				     (!is_touch && c == 'm')))
					skip = 1;
				continue;
			}
			paths[n++] = argv[i];
		}
	} else if (strcmp(cmd, "cp") == 0 || strcmp(cmd, "mv") == 0 ||
		   strcmp(cmd, "ln") == 0) {
		for (i = argc - 1; i >= 0; i--) {
			if (argv[i][0] != '-') {
				paths[n++] = argv[i];
				break;
			}
		}
	} else if (strcmp(cmd, "gcc") == 0 || strcmp(cmd, "cc") == 0) {
		for (i = 0; i + 1 < argc; i++) {
			if (strcmp(argv[i], "-o") == 0) {
				paths[n++] = argv[i + 1];
				break;
			}
			if (strncmp(argv[i], "-o", 2) == 0 && argv[i][2]) {
				paths[n++] = argv[i] + 2;
				break;
			}
		}
	}
	return n;
}

/*
 * exec_verify_write - 子进程退出码 0 后的写入回读校验
 * @pre_sz/@pre_ok: tee 目标执行前大小（append 模式需要）
 * 返回 1=通过；0=失败（*err 为可指导模型修复的错误文本）。
 */
static int exec_verify_write(const char *cmd, const char *const *paths,
			     int npaths, const off_t *pre_sz,
			     const int *pre_ok, int input_given,
			     size_t input_len, int append_mode, char **err)
{
	int i;

	*err = NULL;
	for (i = 0; i < npaths; i++) {
		struct stat st;

		if (stat(paths[i], &st) != 0) {
			if (asprintf(err,
				     "ERROR[E_WRITE_VERIFY]: %s 退出码 0 但目标 "
				     "'%s' 不存在（%s）；写入未生效。请检查 "
				     "args 中的目标路径与 input 内容",
				     cmd, paths[i], strerror(errno)) < 0)
				*err = NULL;
			return 0;
		}
		if (strcmp(cmd, "tee") == 0 && input_given &&
		    input_len > 0) {
			off_t want = append_mode ?
				     (pre_ok && pre_ok[i] ? pre_sz[i] : 0) +
				     (off_t)input_len : (off_t)input_len;

			if (st.st_size < want) {
				if (asprintf(err,
					     "ERROR[E_WRITE_VERIFY]: tee 退出码 0 "
					     "但 '%s' 仅 %lld 字节（期望至少 "
					     "%lld 字节）；stdin 内容未写入。"
					     "正确用法：{\"command\":\"tee\","
					     "\"args\":[\"%s\"],"
					     "\"input\":\"<内容>\"}",
					     paths[i], (long long)st.st_size,
					     (long long)want, paths[i]) < 0)
					*err = NULL;
				return 0;
			}
		}
		if ((strcmp(cmd, "gcc") == 0 || strcmp(cmd, "cc") == 0) &&
		    st.st_size == 0) {
			if (asprintf(err,
				     "ERROR[E_WRITE_VERIFY]: 编译器退出码 0 但产物 "
				     "'%s' 为 0 字节；请检查源码路径与编译参数",
				     paths[i]) < 0)
				*err = NULL;
			return 0;
		}
	}
	return 1;
}

/* ---- W48：命令级风险细化（F3/ns-2/ns-6/sy-8 修复） ---- */

/* curl：任何可能产生写副作用/落盘的参数都升 W2（POST/上传/输出/配置） */
/* ---- W69 round 2：R/W1 命令的动态危险形态扫描 ---- */
struct exec_dyn {
	int w2;
	int deny;
	char *deny_reason;
	const char *wpaths[8];
	int wpath_n;
};

static void exec_dyn_mark(struct exec_dyn *d, int deny, const char *why)
{
	d->w2 = 1;
	if (deny) {
		d->deny = 1;
		if (!d->deny_reason)
			d->deny_reason = strdup(why);
	}
}

static void exec_dyn_path(struct exec_dyn *d, const char *p)
{
	d->w2 = 1;
	if (p && p[0] && strcmp(p, "-") != 0 && d->wpath_n < 8)
		d->wpaths[d->wpath_n++] = p;
}

/*
 * W72：/dev/null 是只读丢弃 sink，不是落盘写目标。curl -o /dev/null
 * 是常见"只要 HTTP 状态/计时、不要响应体"的诊断形态（W70 T04 被
 * E_PARAM_PATH 误拒）。仅放行该精确路径；其他输出目标仍 W2 + realpath。
 */
static int exec_is_devnull(const char *p)
{
	return p && strcmp(p, "/dev/null") == 0;
}

static int exec_any_exact(const char *a, const char *const *v)
{
	int i;

	for (i = 0; v[i]; i++)
		if (strcmp(a, v[i]) == 0)
			return 1;
	return 0;
}

static int exec_any_prefix(const char *a, const char *const *v)
{
	int i;

	for (i = 0; v[i]; i++)
		if (strncmp(a, v[i], strlen(v[i])) == 0)
			return 1;
	return 0;
}

static const char *exec_next_value(char **argv, int argc, int *i)
{
	if (*i + 1 >= argc)
		return NULL;
	(*i)++;
	return argv[*i];
}

/*
 * 扫描一次 exec 调用的参数，给出：
 *   - 是否必须升 W2（写盘/系统状态变更/网络上传/执行面）；
 *   - 是否直接拒绝（不可审计的外部程序/配置/批量脚本形态）；
 *   - 动态写目标（交由 w1_path_allowed_in 做 realpath 校验）。
 * 与 exec_spec_effective_risk / exec_exec_channel 共用，避免口径漂移。
 */
static void exec_dyn_scan(const struct tool_exec_cmd *spec, char **argv,
			  int argc, struct exec_dyn *d)
{
	const char *c;
	int i;

	memset(d, 0, sizeof(*d));
	if (!spec || !argv || argc <= 0)
		return;
	c = spec->command;

	if (strcmp(c, "sort") == 0) {
		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (strcmp(a, "-o") == 0 ||
			    strcmp(a, "--output") == 0) {
				const char *v = exec_next_value(argv, argc, &i);

				if (v)
					exec_dyn_path(d, v);
				else
					exec_dyn_mark(d, 1, "sort -o 缺少文件参数");
			} else if (strncmp(a, "--output=", 9) == 0) {
				exec_dyn_path(d, a + 9);
			} else if (strcmp(a, "-T") == 0 ||
				   strcmp(a, "--temporary-directory") == 0) {
				const char *v = exec_next_value(argv, argc, &i);

				if (v)
					exec_dyn_path(d, v);
			} else if (strncmp(a, "--temporary-directory=",
					   22) == 0) {
				exec_dyn_path(d, a + 22);
			} else if (strcmp(a, "--compress-program") == 0 ||
				   strncmp(a, "--compress-program=",
					   19) == 0) {
				exec_dyn_mark(d, 1, "sort --compress-program 会"
					      "执行外部程序，已拒绝");
			} else if (a[0] == '-' && a[1] && a[1] != '-') {
				const char *p;

				for (p = a + 1; *p; p++) {
					const char *v;

					if (*p == 'o' || *p == 'T') {
						v = p[1] ? p + 1 :
						    exec_next_value(argv, argc,
								    &i);
						if (v)
							exec_dyn_path(d, v);
						break;
					}
					if (*p == 'k' || *p == 't' ||
					    *p == 'S') {
						if (!p[1])
							exec_next_value(argv,
									argc, &i);
						break;
					}
				}
			}
		}
	} else if (strcmp(c, "uniq") == 0) {
		const char *ops[4];
		int nops = 0;

		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (strcmp(a, "--") == 0) {
				for (i++; i < argc && nops < 4; i++)
					ops[nops++] = argv[i];
				break;
			}
			if (a[0] != '-' || !a[1]) {
				if (nops < 4)
					ops[nops++] = a;
				continue;
			}
			if (strcmp(a, "-f") == 0 || strcmp(a, "-s") == 0 ||
			    strcmp(a, "-w") == 0 ||
			    strcmp(a, "--skip-fields") == 0 ||
			    strcmp(a, "--skip-chars") == 0 ||
			    strcmp(a, "--check-chars") == 0) {
				exec_next_value(argv, argc, &i);
				continue;
			}
			if (strncmp(a, "--skip-fields=", 14) == 0 ||
			    strncmp(a, "--skip-chars=", 13) == 0 ||
			    strncmp(a, "--check-chars=", 14) == 0)
				continue;
			if (a[1] != '-') {
				const char *p;

				for (p = a + 1; *p; p++) {
					if (*p == 'f' || *p == 's' ||
					    *p == 'w') {
						if (!p[1])
							exec_next_value(argv,
									argc, &i);
						break;
					}
				}
			}
		}
		if (nops >= 2)
			exec_dyn_path(d, ops[1]);
	} else if (strcmp(c, "date") == 0) {
		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (strcmp(a, "-s") == 0 ||
			    strcmp(a, "--set") == 0) {
				exec_dyn_mark(d, 0, "date 设置系统时间");
				exec_next_value(argv, argc, &i);
			} else if (strncmp(a, "--set=", 6) == 0) {
				exec_dyn_mark(d, 0, "date 设置系统时间");
			} else if (a[0] == '-' && a[1] == 's' && a[2]) {
				exec_dyn_mark(d, 0, "date 设置系统时间");
			} else if (a[0] != '-' && a[0] != '+') {
				exec_dyn_mark(d, 0, "date 位置参数设置系统时间");
			}
		}
	} else if (strcmp(c, "dmesg") == 0) {
		static const char *const wflags[] = {
			"-c", "-C", "--clear", "--read-clear", "-n",
			"--console-level", "-D", "--console-off", "-E",
			"--console-on", NULL,
		};

		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (exec_any_exact(a, wflags) ||
			    strncmp(a, "--console-level=", 16) == 0 ||
			    (a[0] == '-' && a[1] == 'n' && a[2]))
				exec_dyn_mark(d, 0, "dmesg 清除日志/修改控制台级别");
			if ((strcmp(a, "-n") == 0 ||
			     strcmp(a, "--console-level") == 0) &&
			    i + 1 < argc)
				i++;
		}
	} else if (strcmp(c, "ss") == 0) {
		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (strcmp(a, "-K") == 0 ||
			    strcmp(a, "--kill") == 0) {
				exec_dyn_mark(d, 0, "ss 强制关闭 socket");
			} else if (strcmp(a, "-D") == 0 ||
				   strcmp(a, "--diag") == 0) {
				const char *v = exec_next_value(argv, argc, &i);

				exec_dyn_mark(d, 0, "ss 导出 TCP diag 到文件");
				if (v)
					exec_dyn_path(d, v);
			} else if (strncmp(a, "--diag=", 7) == 0) {
				exec_dyn_mark(d, 0, "ss 导出 TCP diag 到文件");
				exec_dyn_path(d, a + 7);
			} else if (a[0] == '-' && a[1] != '-') {
				const char *p;

				for (p = a + 1; *p; p++) {
					if (*p == 'K')
						exec_dyn_mark(d, 0,
							"ss 强制关闭 socket");
					if (*p == 'D') {
						const char *v = p[1] ? p + 1 :
						    exec_next_value(argv,
								    argc, &i);

						exec_dyn_mark(d, 0, "ss 导出 "
							"TCP diag 到文件");
						if (v)
							exec_dyn_path(d, v);
						break;
					}
				}
			}
		}
	} else if (strcmp(c, "hostname") == 0) {
		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (strcmp(a, "-b") == 0 ||
			    strcmp(a, "--boot") == 0 ||
			    strcmp(a, "-F") == 0 ||
			    strcmp(a, "--file") == 0) {
				exec_dyn_mark(d, 0, "hostname 设置主机名");
				if (strcmp(a, "-F") == 0 ||
				    strcmp(a, "--file") == 0)
					exec_next_value(argv, argc, &i);
			} else if (strncmp(a, "--file=", 7) == 0 ||
				   (a[0] == '-' && a[1] == 'F' && a[2])) {
				exec_dyn_mark(d, 0, "hostname 设置主机名");
			} else if (a[0] == '-' && a[1]) {
				continue;
			} else {
				exec_dyn_mark(d, 0, "hostname 位置参数设置主机名");
			}
		}
	} else if (strcmp(c, "blkid") == 0) {
		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (strcmp(a, "-w") == 0 ||
			    strcmp(a, "--write-cache") == 0 ||
			    strncmp(a, "--write-cache=", 14) == 0 ||
			    (a[0] == '-' && a[1] == 'w' && a[2]) ||
			    strcmp(a, "-g") == 0 ||
			    strcmp(a, "--garbage-collect") == 0)
				exec_dyn_mark(d, 0, "blkid 写/回收缓存");
		}
	} else if (strcmp(c, "smartctl") == 0) {
		static const char *const wflags[] = {
			"-t", "--test", "-s", "--set", "-o", "--offlineauto",
			"-S", "--saveauto", "-X", "--abort", NULL,
		};
		static const char *const wprefix[] = {
			"--test=", "--set=", "--offlineauto=", "--saveauto=",
			"--abort=", NULL,
		};

		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (exec_any_exact(a, wflags) ||
			    exec_any_prefix(a, wprefix) ||
			    (a[0] == '-' && a[1] && a[2] &&
			     strchr("tsoSX", a[1])))
				exec_dyn_mark(d, 0, "smartctl 启动测试/修改设备设置");
		}
	} else if (strcmp(c, "ip") == 0) {
		static const char *const wverbs[] = {
			"add", "del", "delete", "replace", "flush", "set",
			"change", "append", "prepend", "save", "restore",
			"attach", "detach", "update", "rename", "-force", NULL,
		};

		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (strcmp(a, "netns") == 0 && i + 1 < argc &&
			    strcmp(argv[i + 1], "exec") == 0)
				exec_dyn_mark(d, 1, "ip netns exec 会执行任意"
					      "命令，已拒绝");
			if (strcmp(a, "vrf") == 0 && i + 1 < argc &&
			    strcmp(argv[i + 1], "exec") == 0)
				exec_dyn_mark(d, 1, "ip vrf exec 会执行任意"
					      "命令，已拒绝");
			if (strcmp(a, "-b") == 0 ||
			    strcmp(a, "-batch") == 0 ||
			    strcmp(a, "--batch") == 0 ||
			    strncmp(a, "-batch=", 7) == 0 ||
			    strncmp(a, "--batch=", 8) == 0 ||
			    (a[0] == '-' && a[1] == 'b' && a[2] &&
			     a[2] != 'r'))
				exec_dyn_mark(d, 1, "ip -batch 读取并执行批量"
					      "命令文件，已拒绝");
			if (exec_any_exact(a, wverbs))
				exec_dyn_mark(d, 0, "ip 写/改网络状态");
		}
	} else if (strcmp(c, "ethtool") == 0) {
		static const char *const wflags[] = {
			"-s", "--change", "-A", "--pause", "-C", "--coalesce",
			"-G", "--set-ring", "-K", "--features", "--offload",
			"-E", "--change-eeprom", "-f", "--flash", "-r",
			"--negotiate", "-p", "--identify", "-t", "--test",
			"-N", "--config-nfc", "-U", "--config-ntuple", "-X",
			"--set-rxfh-indir", "--rxfh", "-L", "--set-channels",
			"-W", "--set-dump", "-Q", "--per-queue",
			"--set-priv-flags", "--set-eee", "--set-phy-tunable",
			"--set-tunable", "--set-fec", "--set-wol", "--reset",
			"--cable-test", "--cable-test-tdr", NULL,
		};
		int regdump = 0;
		int getdump = 0;

		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (exec_any_exact(a, wflags))
				exec_dyn_mark(d, 0, "ethtool 改设备/启动测试");
			if (strcmp(a, "-d") == 0 ||
			    strcmp(a, "--register-dump") == 0)
				regdump = 1;
			if (strcmp(a, "-w") == 0 ||
			    strcmp(a, "--get-dump") == 0)
				getdump = 1;
		}
		for (i = 0; i < argc; i++) {
			if (regdump && strcmp(argv[i], "file") == 0 &&
			    i + 1 < argc) {
				exec_dyn_mark(d, 0, "ethtool 寄存器 dump 写文件");
				exec_dyn_path(d, argv[i + 1]);
			}
			if (getdump && strcmp(argv[i], "data") == 0 &&
			    i + 1 < argc) {
				exec_dyn_mark(d, 0, "ethtool dump 数据写文件");
				exec_dyn_path(d, argv[i + 1]);
			}
		}
	} else if (strcmp(c, "journalctl") == 0) {
		static const char *const wprefix[] = {
			"--vacuum-", "--rotate", "--flush", "--sync",
			"--relinquish-var", "--smart-relinquish-var",
			"--setup-keys", "--update-catalog", NULL,
		};

		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (exec_any_prefix(a, wprefix))
				exec_dyn_mark(d, 0, "journalctl 改日志存储/密钥/"
					      "catalog");
			if (strcmp(a, "--cursor-file") == 0) {
				const char *v = exec_next_value(argv, argc, &i);

				exec_dyn_mark(d, 0, "journalctl 更新 cursor 文件");
				if (v)
					exec_dyn_path(d, v);
			} else if (strncmp(a, "--cursor-file=", 14) == 0) {
				exec_dyn_mark(d, 0, "journalctl 更新 cursor 文件");
				exec_dyn_path(d, a + 14);
			}
		}
	} else if (strcmp(c, "curl") == 0) {
		static const char *const path_long[] = {
			"--output", "--dump-header", "--cookie-jar",
			"--etag-save", "--trace", "--trace-ascii",
			"--trace-config", "--stderr", "--libcurl", "--hsts",
			"--alt-svc", "--output-dir", NULL,
		};
		static const char *const wflags[] = {
			"--remote-name", "--remote-name-all",
			"--remote-header-name", "--create-dirs",
			"--remove-on-error", "--no-clobber", "--xattr",
			"--remote-time", "--ftp-create-dirs", "--append",
			"--crlf", NULL,
		};

		for (i = 0; i < argc; i++) {
			const char *a = argv[i];
			const char *v;

			if (strcmp(a, "-K") == 0 ||
			    strcmp(a, "--config") == 0 ||
			    strncmp(a, "--config=", 9) == 0 ||
			    strcmp(a, "--engine") == 0 ||
			    strncmp(a, "--engine=", 9) == 0 ||
			    strcmp(a, "--ssl-engine") == 0 ||
			    strncmp(a, "--ssl-engine=", 13) == 0) {
				exec_dyn_mark(d, 1, "curl 配置/加密引擎可加载"
					      "外部程序或不可审计配置，已拒绝");
				continue;
			}
			if (exec_any_exact(a, path_long)) {
				v = exec_next_value(argv, argc, &i);
				if (exec_is_devnull(v))
					continue;	/* W72: /dev/null sink */
				exec_dyn_mark(d, 0, "curl 写输出/缓存/调试文件");
				if (v)
					exec_dyn_path(d, v);
				continue;
			}
			if (strncmp(a, "--output=", 9) == 0 ||
			    strncmp(a, "--dump-header=", 14) == 0 ||
			    strncmp(a, "--cookie-jar=", 13) == 0 ||
			    strncmp(a, "--etag-save=", 12) == 0 ||
			    strncmp(a, "--trace=", 8) == 0 ||
			    strncmp(a, "--trace-ascii=", 14) == 0 ||
			    strncmp(a, "--trace-config=", 15) == 0 ||
			    strncmp(a, "--stderr=", 9) == 0 ||
			    strncmp(a, "--libcurl=", 10) == 0 ||
			    strncmp(a, "--hsts=", 7) == 0 ||
			    strncmp(a, "--alt-svc=", 10) == 0 ||
			    strncmp(a, "--output-dir=", 13) == 0) {
				const char *eq = strchr(a, '=');

				if (eq && exec_is_devnull(eq + 1))
					continue;	/* W72: /dev/null sink */
				exec_dyn_mark(d, 0, "curl 写输出/缓存/调试文件");
				if (eq)
					exec_dyn_path(d, eq + 1);
				continue;
			}
			if (exec_any_exact(a, wflags)) {
				exec_dyn_mark(d, 0, "curl 写本地/远端文件");
				if (strncmp(a, "--remote-name", 13) == 0 ||
				    strcmp(a, "--remote-header-name") == 0)
					exec_dyn_path(d, ".");
				continue;
			}
			if (strncmp(a, "--data", 6) == 0 ||
			    strncmp(a, "--json", 6) == 0 ||
			    strncmp(a, "--form", 6) == 0 ||
			    strncmp(a, "--upload-file", 13) == 0 ||
			    strncmp(a, "--request", 9) == 0) {
				exec_dyn_mark(d, 0, "curl 上传/发送数据");
				continue;
			}
			if (a[0] == '-' && a[1] && a[1] != '-') {
				const char *p;

				for (p = a + 1; *p; p++) {
					if (*p == 'd' || *p == 'F' ||
					    *p == 'T' || *p == 'X' ||
					    *p == 'a') {
						exec_dyn_mark(d, 0, "curl 上传/"
							      "发送数据");
				} else if (*p == 'o' || *p == 'D' ||
					   *p == 'c') {
					v = p[1] ? p + 1 :
					    exec_next_value(argv,
							    argc, &i);
					if (exec_is_devnull(v))
						break;	/* W72: /dev/null sink */
					exec_dyn_mark(d, 0, "curl 写"
						      "文件");
					if (v)
						exec_dyn_path(d, v);
					break;
				} else if (*p == 'K') {
						exec_dyn_mark(d, 1, "curl "
							      "配置选项已拒绝");
						break;
					} else if (*p == 'O' || *p == 'J') {
						exec_dyn_mark(d, 0, "curl "
							      "remote-name 写"
							      "当前目录");
						exec_dyn_path(d, ".");
					} else if (*p == 'R') {
						exec_dyn_mark(d, 0, "curl "
							      "设置输出时间");
					}
				}
			}
		}
	} else if (strcmp(c, "systemd-analyze") == 0) {
		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (strcmp(a, "--generators") == 0) {
				exec_dyn_mark(d, 0, "systemd-analyze 运行 unit "
					      "generators");
			} else if (strncmp(a, "--generators=", 13) == 0) {
				const char *v = a + 13;

				if (strcmp(v, "no") != 0 &&
				    strcmp(v, "false") != 0 &&
				    strcmp(v, "0") != 0)
					exec_dyn_mark(d, 0, "systemd-analyze "
						      "运行 unit generators");
			} else if (strcmp(a, "--output") == 0 ||
				   strcmp(a, "-o") == 0) {
				const char *v = exec_next_value(argv, argc, &i);

				exec_dyn_mark(d, 0, "systemd-analyze 写输出文件");
				if (v)
					exec_dyn_path(d, v);
			} else if (strncmp(a, "--output=", 9) == 0) {
				exec_dyn_mark(d, 0, "systemd-analyze 写输出文件");
				exec_dyn_path(d, a + 9);
			}
		}
	} else if (strcmp(c, "pvs") == 0 || strcmp(c, "vgs") == 0 ||
		   strcmp(c, "lvs") == 0) {
		for (i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (strcmp(a, "--config") == 0 ||
			    strncmp(a, "--config=", 9) == 0 ||
			    strcmp(a, "--commandprofile") == 0 ||
			    strncmp(a, "--commandprofile=", 17) == 0 ||
			    strcmp(a, "--profile") == 0 ||
			    strncmp(a, "--profile=", 10) == 0) {
				exec_dyn_mark(d, 1, "LVM --config/--profile 为"
					      "不可审计配置，已拒绝");
			} else if (strcmp(a, "--reportfile") == 0 ||
				   strncmp(a, "--reportfile=", 13) == 0 ||
				   strcmp(a, "--logfile") == 0 ||
				   strncmp(a, "--logfile=", 10) == 0) {
				const char *v = NULL;

				exec_dyn_mark(d, 0, "LVM 写报告/日志文件");
				if (strchr(a, '='))
					v = strchr(a, '=') + 1;
				else
					v = exec_next_value(argv, argc, &i);
				if (v)
					exec_dyn_path(d, v);
			}
		}
	} else if (strcmp(c, "df") == 0) {
		for (i = 0; i < argc; i++) {
			if (strcmp(argv[i], "--sync") == 0)
				exec_dyn_mark(d, 0, "df --sync 强制回写文件系统");
		}
	} else if (strcmp(c, "find") == 0) {
		static const char *const bad[] = {
			"-delete", "-exec", "-execdir", "-ok", "-okdir",
			"-fprintf", "-fls", "-fprint", "-fprint0", NULL,
		};

		for (i = 0; i < argc; i++) {
			if (exec_any_exact(argv[i], bad))
				exec_dyn_mark(d, 1, "find 参数属任意执行/删除/"
					      "写文件谓词，已拒绝（受控 find 仅"
					      "支持纯检索）");
		}
	} else if (strcmp(c, "ping") == 0) {
		for (i = 0; i < argc; i++) {
			if (strcmp(argv[i], "-f") == 0 ||
			    strcmp(argv[i], "--flood") == 0 ||
			    strcmp(argv[i], "-l") == 0 ||
			    strcmp(argv[i], "--preload") == 0)
				exec_dyn_mark(d, 0, "ping flood/preload 可被"
					      "用作 DoS");
		}
	}
}

/*
 * 命令级有效风险：基础 risk + args0 动词表 + 特殊命令的动态判定。
 * 执行闸门与 plan 闸门共用本函数（W48 消除两处重复逻辑）。
 */
static const char *exec_spec_effective_risk(const struct tool_exec_cmd *spec,
					    char **argv, int argc)
{
	const char *risk = (spec && spec->risk) ? spec->risk : "R";
	int i;

	if (!spec)
		return risk;
	if (spec->args0_count > 0 && argc >= 1) {
		for (i = 0; i < spec->args0_count; i++) {
			if (spec->args0_enum[i] &&
			    strcmp(argv[0], spec->args0_enum[i]) == 0) {
				if (spec->args0_risk && spec->args0_risk[i])
					risk = spec->args0_risk[i];
				break;
			}
		}
	}
	{
		struct exec_dyn dyn;

		exec_dyn_scan(spec, argv, argc, &dyn);
		if (dyn.w2 || dyn.deny)
			risk = "W2";
		free(dyn.deny_reason);
	}
	if (strcmp(spec->command, "crontab") == 0) {
		/* -l 查询 R；无参数会从 stdin 读空内容覆盖表（执行段拒绝）；
		 * -e 交互（执行段拒绝）；其余（-r/文件安装）W2 */
		if (argc >= 1 && strcmp(argv[0], "-l") == 0)
			risk = "R";
		else
			risk = "W2";
	}
	return risk;
}

const char *tool_exec_effective_risk(const struct ai_tool *tool,
				     const char *args_json)
{
	const char *risk;
	char *cmd = NULL;
	char **argv = NULL;
	int argc = 0;
	char *err = NULL;
	const struct tool_exec_cmd *spec;

	if (!tool)
		return "W1";
	risk = tool->risk ? tool->risk : "W1";
	if (tool->channel != TOOL_CH_EXEC)
		return risk;
	cmd = arg_str(args_json, "command");
	if (!cmd || !cmd[0]) {
		free(cmd);
		return risk;
	}
	spec = exec_spec_find(tool, cmd);
	if (!spec) {
		free(cmd);
		return risk;
	}
	if (arg_str_array(args_json, "args", &argv, &argc, &err) == AI_OK)
		risk = exec_spec_effective_risk(spec, argv, argc);
	else
		risk = spec->risk ? spec->risk : risk;
	{
		int i;

		for (i = 0; i < argc; i++)
			free(argv[i]);
	}
	free(argv);
	free(err);
	free(cmd);
	return risk;
}

int tool_exec_memory_last_rc(void)
{
	return g_mem_last_rc;
}

int tool_exec_result_is_denied(const char *out)
{
	if (!out)
		return 0;
	/* 显式策略前缀（plan/W2/黑名单/沙箱隔离/sys_shell 非 TTY） */
	if (strstr(out, TOOL_ERR_DENIED_PREFIX))
		return 1;
	/* 写路径白名单拒绝属策略拒绝（W68 P1-4 的"真正策略拒绝"口径；
	 * 二进制缺失没有该前缀，记 fail）。 */
	return strstr(out, "ERROR[E_PARAM_PATH]") != NULL;
}

/*
 * W69 round 2：在权限门前直接拒绝不可审计的执行形态（opaque config、
 * 外部程序执行、批量命令文件等）。返回 1 时 *reason 为 malloc 文本。
 * 解析失败返回 0，交由后续结构化参数错误处理。
 */
static int exec_args_denied(const struct ai_tool *tool, const char *args_json,
			    char **reason)
{
	char *cmd;
	char **argv = NULL;
	int argc = 0;
	char *err = NULL;
	const struct tool_exec_cmd *spec;
	struct exec_dyn dyn;
	int denied = 0;

	*reason = NULL;
	if (!tool || tool->channel != TOOL_CH_EXEC || !args_json)
		return 0;
	cmd = arg_str(args_json, "command");
	if (!cmd || !cmd[0]) {
		free(cmd);
		return 0;
	}
	spec = exec_spec_find(tool, cmd);
	if (!spec) {
		free(cmd);
		return 0;
	}
	if (arg_str_array(args_json, "args", &argv, &argc, &err) != AI_OK) {
		free(cmd);
		free(err);
		return 0;
	}
	exec_dyn_scan(spec, argv, argc, &dyn);
	if (dyn.deny) {
		*reason = dyn.deny_reason ? dyn.deny_reason :
			  strdup("危险执行形态");
		dyn.deny_reason = NULL;
		denied = 1;
	}
	free(dyn.deny_reason);
	{
		int i;

		for (i = 0; i < argc; i++)
			free(argv[i]);
	}
	free(argv);
	free(err);
	free(cmd);
	return denied;
}

/* find 受控面：拒绝任意执行/删除/写文件谓词（fs-6） */
static int exec_find_args_ok(char **argv, int argc, char **err_out)
{
	static const char *const banned[] = {
		"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprintf",
		"-fls", "-fprint", "-fprint0", NULL,
	};
	int i, j;

	for (i = 0; i < argc; i++) {
		for (j = 0; banned[j]; j++) {
			if (strcmp(argv[i], banned[j]) == 0) {
				if (asprintf(err_out,
					     "find 参数 '%s' 属任意执行/写文件"
					     "谓词，已拒绝（受控 find 仅支持纯检索）",
					     argv[i]) < 0)
					*err_out = NULL;
				return 0;
			}
		}
	}
	return 1;
}

/* W69 P1-1：tar 执行面选项黑名单。
 * --checkpoint-action/--to-command/--use-compress-program/-I/
 * --rmt-command/--info-script/--new-volume-script 等会执行外部程序；
 * -P/--absolute-names 允许归档成员以绝对路径写穿目标目录。tar 同时
 * 升为 W2（逐次确认 + 沙箱受限表剔除），本过滤是纵深防御。 */
static int exec_tar_args_ok(char **argv, int argc, char **err_out)
{
	static const char *const banned_long[] = {
		"--checkpoint-action", "--to-command",
		"--use-compress-program", "--rmt-command",
		"--rsh-command", "--info-script", "--new-volume-script",
		"--volno-file", "--index-file", "--remove-files",
		"--listed-incremental", "--absolute-names", NULL,
	};
	int i, j;

	for (i = 0; i < argc; i++) {
		const char *a = argv[i];

		for (j = 0; banned_long[j]; j++) {
			if (strncmp(a, banned_long[j],
				    strlen(banned_long[j])) == 0) {
				if (asprintf(err_out, "tar 参数 '%s' 属执行面/"
					     "绝对路径选项，已拒绝（tar 仅允许"
					     "受限打包/解包）", a) < 0)
					*err_out = NULL;
				return 0;
			}
		}
		if (a[0] == '-' && a[1] && a[1] != '-') {
			const char *c;

			for (c = a + 1; *c; c++) {
				if (*c == 'I' || *c == 'F' || *c == 'P' ||
				    *c == 'g') {
					if (asprintf(err_out, "tar 短选项 "
						     "'-%c' 属执行面/绝对路径/"
						     "增量快照选项，已拒绝",
						     *c) < 0)
						*err_out = NULL;
					return 0;
				}
			}
		}
	}
	return 1;
}

/* W65 P2-04：gcc/cc 仅 /tmp。除 path_check 的非选项参数外，还要拦
 * 组合形式选项（-I/root、-T/tmp/ld、-include/root/x）与可执行外部
 * 程序的选项（-wrapper/-specs/-fplugin/-B/@file/-Wl,/-Wa,/-Wp,）。 */
static int gcc_path_ok(const char *p)
{
	static const char *const tmp_roots[] = { "/tmp", NULL };
	char *err = NULL;
	int ok;

	if (!p || p[0] != '/' || path_has_dotdot(p))
		return 0;
	ok = w1_path_allowed_in(p, tmp_roots, &err);
	free(err);
	return ok;
}

static int exec_gcc_args_ok(char **argv, int argc, char **err_out)
{
	static const char *const bad[] = {
		"-wrapper", "-specs", "--specs", "-fplugin", "-B",
		"-Wl,", "-Wa,", "-Wp,", "-Xlinker", "-Xassembler",
		"-Xpreprocessor", "@", "--sysroot", NULL,
	};
	int i, j;

	for (i = 0; i < argc; i++) {
		const char *a = argv[i];
		const char *val = NULL;

		for (j = 0; bad[j]; j++) {
			if (strncmp(a, bad[j], strlen(bad[j])) == 0) {
				if (asprintf(err_out,
					     "gcc/cc 参数 '%s' 被拒绝（该选项可"
					     "执行外部程序或把产物写往 /tmp "
					     "之外；编译器仅允许 /tmp 内编译）",
					     a) < 0)
					*err_out = NULL;
				return 0;
			}
		}
		if (a[0] != '-') {
			if (!gcc_path_ok(a)) {
				if (asprintf(err_out,
					     "gcc/cc 路径 '%s' 不在 /tmp 内（编译"
					     "器仅允许绝对路径 /tmp/...）", a) < 0)
					*err_out = NULL;
				return 0;
			}
			continue;
		}
		/* 组合形式：-I<path> / -L<path> / -isystem<path> 等 */
		if (strncmp(a, "-isystem", 8) == 0)
			val = a[8] ? a + 8 : (i + 1 < argc ? argv[++i] : NULL);
		else if (strncmp(a, "-iquote", 7) == 0)
			val = a[7] ? a + 7 : (i + 1 < argc ? argv[++i] : NULL);
		else if (strncmp(a, "-include", 8) == 0)
			val = a[8] ? a + 8 : (i + 1 < argc ? argv[++i] : NULL);
		else if (strncmp(a, "-I", 2) == 0 && a[2])
			val = a + 2;
		else if (strncmp(a, "-L", 2) == 0 && a[2])
			val = a + 2;
		else if (strncmp(a, "-T", 2) == 0 && a[2])
			val = a + 2;
		else if (strcmp(a, "-dumpdir") == 0)
			val = (i + 1 < argc) ? argv[++i] : NULL;
		else if (strncmp(a, "-dumpdir=", 9) == 0)
			val = a + 9;
		else if (strncmp(a, "-fprofile-generate=", 19) == 0)
			val = a + 19;
		else if (strncmp(a, "-fprofile-dir=", 14) == 0)
			val = a + 14;
		else if (strncmp(a, "-fprofile-note=", 15) == 0)
			val = a + 15;
		else if (strncmp(a, "-o", 2) == 0 && a[2])
			val = a + 2;
		else if (strncmp(a, "-MF", 3) == 0 && a[3])
			val = a + 3;
		else if (strncmp(a, "-MJ", 3) == 0 && a[3])
			val = a + 3;
		if (val && !gcc_path_ok(val)) {
			if (asprintf(err_out,
				     "gcc/cc 路径 '%s' 不在 /tmp 内（组合选项 %s）",
				     val, a) < 0)
				*err_out = NULL;
			return 0;
		}
	}
	return 1;
}

/* crontab 受控面：-l 查询；-e 交互拒绝；无参数会读空 stdin 清表拒绝 */static int exec_crontab_args_ok(char **argv, int argc, char **err_out)
{
	if (argc == 0) {
		*err_out = strdup("crontab 无参数会从 stdin 读取内容并覆盖当前"
				  "表（exec 的 stdin 为 /dev/null，等价清空），"
				  "已拒绝；查询用 args=[\"-l\"]，安装用 "
				  "args=[\"<文件>\"]");
		return 0;
	}
	if (strcmp(argv[0], "-e") == 0) {
		*err_out = strdup("crontab -e 是交互式编辑器，exec 通道无法"
				  "交互，已拒绝；请用文件安装形态");
		return 0;
	}
	return 1;
}

/*
 * W72：沙箱内建 which。
 *
 * 根因：VM 的 /usr/bin/which 是指向 /etc/alternatives/which 的符号链接；
 * 沙盒 /etc 只 bind 白名单文件（不含 alternatives），子智能体里
 * access(/usr/bin/which) 必然 ENOENT（W70 T13 实测）。which 是纯只读
 * 的 PATH 查找，直接在执行器内实现，既不依赖沙盒 /etc，也不增加写面。
 * 仅在 AIKERNEL_SANDBOX 非空时启用；宿主路径仍走注册表二进制。
 */
static int exec_which_builtin(char **argv, int argc, char **out)
{
	const char *path = getenv("PATH");
	char buf[4096];
	size_t off = 0;
	int all = 1;
	int i;

	if (!path || !path[0])
		path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:"
		       "/sbin:/bin";
	if (argc < 1) {
		*out = strdup("ERROR[E_PARAM_ARGS]: 用法: which <命令名>...");
		return AI_ERR_INVALID_ARG;
	}
	buf[0] = '\0';
	for (i = 0; i < argc; i++) {
		char dirs[2048];
		char *save = NULL;
		char *d;
		int found = 0;

		if (argv[i][0] == '-') {
			*out = strdup("ERROR[E_PARAM_ARGS]: 沙箱 which 仅接受"
				      "命令名（不支持选项），已拒绝");
			return AI_ERR_INVALID_ARG;
		}
		snprintf(dirs, sizeof(dirs), "%s", path);
		for (d = strtok_r(dirs, ":", &save); d;
		     d = strtok_r(NULL, ":", &save)) {
			char cand[PATH_MAX];
			struct stat st;

			if (!d[0])
				continue;
			if (snprintf(cand, sizeof(cand), "%s/%s", d,
				     argv[i]) >= (int)sizeof(cand))
				continue;
			if (access(cand, X_OK) == 0 &&
			    stat(cand, &st) == 0 && S_ISREG(st.st_mode)) {
				if (off < sizeof(buf)) {
					int n = snprintf(buf + off,
							 sizeof(buf) - off,
							 "%s\n", cand);

					if (n > 0)
						off += (size_t)n;
					if (off >= sizeof(buf))
						off = sizeof(buf) - 1;
				}
				found = 1;
				break;
			}
		}
		if (!found) {
			all = 0;
			if (off < sizeof(buf)) {
				int n = snprintf(buf + off,
						 sizeof(buf) - off,
						 "which: no %s in (%s)\n",
						 argv[i], path);

				if (n > 0)
					off += (size_t)n;
				if (off >= sizeof(buf))
					off = sizeof(buf) - 1;
			}
		}
		if (off >= sizeof(buf) - 1)
			break;
	}
	*out = strdup(buf[0] ? buf : "(无输出)");
	return all ? AI_OK : AI_ERR_NOT_FOUND;
}

static int exec_exec_channel(const struct ai_tool *tool, const char *args_json,
			     char **out)
{	char *cmd = NULL;
	char **argv_extra = NULL;
	int argv_extra_n = 0;
	char *err_arg = NULL;
	char path[512];
	const char *bin = NULL;
	char *full_argv[65];
	int pipefd[2];
	pid_t pid;
	int status = 0;
	int rc;
	int i, argc;
	char *buf = NULL;
	size_t cap, off, total;
	const struct tool_exec_cmd *spec;
	int timeout_sec;
	int path_check;
	long long deadline;
	int timed_out = 0;
	int cancelled = 0;
	int poll_failed = 0;
	int poll_errno = 0;
	char *input_data = NULL;
	size_t input_len = 0;
	int inpipefd[2] = { -1, -1 };
	int input_max;
	/* W20 修3：input 改临时文件中转（fork 前落盘，子进程 dup2 只读
	 * fd 到 stdin），消除"父进程 write stdin 管道 × 子进程读取"的
	 * 时序窗口（T3 D3 首写 tee 0 字节）；管道保留为落盘失败回退 */
	int input_fd = -1;
	char input_tmp[64] = "";
	char *bad_key = NULL;
	int input_conflict = 0;
	const char *write_paths[8];
	off_t pre_sz[8];
	int pre_ok[8];
	int append_mode = 0;
	int write_n = 0;

	/* W65 P2-01：先做参数键白名单——未知键返回结构化错误，绝不静默
	 * 忽略（历史缺陷：stdin/stdin_data 被丢弃，tee 写 0 字节仍报成功）。 */
	rc = exec_check_arg_keys(args_json, &bad_key, &err_arg);
	if (rc != AI_OK) {
		if (rc == AI_ERR_PARSE)
			exec_param_error(out, "BAD_JSON",
					 err_arg ? err_arg :
					 "arguments 不是合法 JSON 对象", tool);
		else
			exec_param_error(out, "UNKNOWN_KEY",
					 err_arg ? err_arg : "未知参数", tool);
		free(err_arg);
		free(bad_key);
		return rc;
	}
	free(err_arg);
	err_arg = NULL;

	cmd = arg_str(args_json, "command");
	if (!cmd || !cmd[0]) {
		exec_param_error(out, "MISSING",
				 "缺少必填参数 command（必须给单个白名单"
				 "命令名，不要把整条命令串放进来）", tool);
		free(cmd);
		return AI_ERR_INVALID_ARG;
	}
	if (arg_has_meta(cmd)) {
		exec_param_error(out, "META",
				 "command 含 shell 元字符；exec_run 以 "
				 "fork+execv 直接执行、不经过 shell，管道/重定向/"
				 "命令串联一律不支持。请拆成多次调用", tool);
		free(cmd);
		return AI_ERR_INVALID_ARG;
	}

	/* 整条命令串塞进 command（W62 M3 主因：19 次）：给出可一次改对的
	 * FIX 示例；首个 token 是白名单命令时直接给出 args 拆分建议。 */
	if (strpbrk(cmd, " \t") != NULL) {
		char first[128];
		size_t fl = strcspn(cmd, " \t");
		char *detail;

		if (fl >= sizeof(first))
			fl = sizeof(first) - 1;
		memcpy(first, cmd, fl);
		first[fl] = '\0';
		if (asprintf(&detail,
			     "command 必须是单个命令名，不能是整条命令串"
			     "（收到 \"%s\"）。FIX: {\"command\":\"%s\","
			     "\"args\":[...]}（选项/操作数逐个放进 args 数组，"
			     "本工具不经过 shell）", cmd, first) < 0)
			detail = NULL;
		exec_param_error(out, "WHOLE_COMMAND",
				 detail ? detail : "command 含空格", tool);
		free(detail);
		free(cmd);
		return AI_ERR_INVALID_ARG;
	}

	/* 单源白名单查找（tools.json 权威，内置表仅 fallback） */
	spec = exec_spec_find(tool, cmd);
	if (!spec) {
		char *detail;

		if (asprintf(&detail,
			     "命令 '%s' 不在 exec 白名单（单源：tools.json "
			     "exec.commands）。先看 AVAILABLE 列表选一个命令，"
			     "再用 args 数组传参", cmd) < 0)
			detail = NULL;
		exec_param_error(out, "UNKNOWN_COMMAND",
				 detail ? detail : "命令不在白名单", tool);
		free(detail);
		free(cmd);
		return AI_ERR_INVALID_ARG;
	}
	/* T14：可选 input 参数——喂给子进程 stdin 的文本（写文件走
	 * tee：input→stdin→tee→文件）。stdin/stdin_data 为兼容别名。
	 * 超长整条拒绝。 */
	input_max = tool->exec_input_max ? tool->exec_input_max :
					  EXEC_INPUT_MAX;
	input_data = exec_input_arg(args_json, &input_conflict);
	if (input_conflict) {
		exec_param_error(out, "ALIAS_CONFLICT",
				 "input 与 stdin/stdin_data 同时给出且内容"
				 "不同；请只保留 input（stdin/stdin_data 是"
				 "兼容别名）", tool);
		free(input_data);
		free(cmd);
		return AI_ERR_INVALID_ARG;
	}
	if (input_data && strlen(input_data) > (size_t)input_max) {
		char *detail;

		if (asprintf(&detail,
			     "input 超长（%zu > %d 字节）。大文件请先用 "
			     "head/split 分段，或改用 python3 脚本",
			     strlen(input_data), input_max) < 0)
			detail = NULL;
		exec_param_error(out, "INPUT_TOO_LONG",
				 detail ? detail : "input 超长", tool);
		free(detail);
		free(input_data);
		free(cmd);
		return AI_ERR_INVALID_ARG;
	}
	input_len = input_data ? strlen(input_data) : 0;

	/* 超时优先级：调用级 timeout（兼容既有调用/测试）> tools.json
	 * 命令级 > 工具级 default_timeout > 环境变量 > 内置默认 30s。
	 * 调用级钳制 1..300 秒，防止模型传入过大值拖死会话。 */
	{
		const char *env_to = getenv("AIKERNEL_TOOL_TIMEOUT_SEC");
		int env_val = env_to ? atoi(env_to) : 0;
		long long req_to = arg_ll(args_json, "timeout", 0);

		if (req_to > 0) {
			if (req_to > 300)
				req_to = 300;
			timeout_sec = (int)req_to;
		} else if (spec->timeout)
			timeout_sec = spec->timeout;
		else if (tool->exec_default_timeout)
			timeout_sec = tool->exec_default_timeout;
		else if (env_val > 0)
			timeout_sec = env_val;
		else
			timeout_sec = EXEC_DEFAULT_TIMEOUT_SEC;
	}
	path_check = spec->path_check;

	/* P0：任一参数含元字符/超长 → 整条拒绝（不再静默丢弃） */
	rc = arg_str_array(args_json, "args", &argv_extra, &argv_extra_n,
			   &err_arg);
	if (rc != AI_OK) {
		int meta = err_arg && strstr(err_arg, "元字符") != NULL;

		exec_param_error(out, meta ? "META_ARG" : "ARGS",
				 err_arg ? err_arg :
				 "参数非法，已拒绝执行", tool);
		free(err_arg);
		free(cmd);
		return AI_ERR_INVALID_ARG;
	}
	free(err_arg);

	/* 二级白名单：args0 限定动词（如 systemctl status|start|...），
	 * 命中后由 exec_spec_effective_risk 统一细化风险级（含 curl/ip/
	 * ethtool/journalctl/crontab 的动态写参数判定） */
	if (spec->args0_count > 0) {
		int hit = -1;

		if (argv_extra_n < 1) {
			exec_param_error(out, "SUBCOMMAND",
					 "该命令要求首个 args 元素为指定子命令"
					 "（见 AVAILABLE 与工具 schema 的 args0 "
					 "白名单）", tool);
			rc = AI_ERR_INVALID_ARG;
			goto out_free;
		}
		for (i = 0; i < spec->args0_count; i++) {
			if (strcmp(spec->args0_enum[i], argv_extra[0]) == 0) {
				hit = i;
				break;
			}
		}
		if (hit < 0) {
			char *detail;

			if (asprintf(&detail,
				     "子命令 '%s' 不在该命令的允许列表内",
				     argv_extra[0]) < 0)
				detail = NULL;
			exec_param_error(out, "SUBCOMMAND",
					 detail ? detail : "子命令不在白名单",
					 tool);
			free(detail);
			rc = AI_ERR_INVALID_ARG;
			goto out_free;
		}
	}
	/* W20 修5：python3 参数形态校验（仅 python3 <script.py> 形态） */
	if (strcmp(cmd, "python3") == 0) {
		if (!exec_python3_args_ok(argv_extra, argv_extra_n,
					  &err_arg)) {
			if (asprintf(out, "ERROR: %s",
				     err_arg ? err_arg :
				     "python3 参数形态校验失败") < 0)
				*out = NULL;
			free(err_arg);
			rc = AI_ERR_INVALID_ARG;
			goto out_free;
		}
		free(err_arg);
		err_arg = NULL;
	}
	/* W48 fs-6：受控 find（拒绝任意执行/删除/写文件谓词） */
	if (strcmp(cmd, "find") == 0) {
		if (!exec_find_args_ok(argv_extra, argv_extra_n, &err_arg)) {
			if (asprintf(out, "ERROR: %s",
				     err_arg ? err_arg : "find 参数非法") < 0)
				*out = NULL;
			free(err_arg);
			rc = AI_ERR_INVALID_ARG;
			goto out_free;
		}
		free(err_arg);
		err_arg = NULL;
	}
	/* W48 sy-1：crontab 交互/清表形态拒绝 */
	if (strcmp(cmd, "crontab") == 0) {
		if (!exec_crontab_args_ok(argv_extra, argv_extra_n,
					  &err_arg)) {
			if (asprintf(out, "ERROR: %s",
				     err_arg ? err_arg : "crontab 参数非法") < 0)
				*out = NULL;
			free(err_arg);
			rc = AI_ERR_INVALID_ARG;
			goto out_free;
		}
		free(err_arg);
		err_arg = NULL;
	}
	/* W69 P1-1：tar 执行面/绝对路径选项拒绝 */
	if (strcmp(cmd, "tar") == 0) {
		if (!exec_tar_args_ok(argv_extra, argv_extra_n, &err_arg)) {
			exec_param_error(out, "TAR_ARGS",
					 err_arg ? err_arg :
					 "tar 参数非法", tool);
			free(err_arg);
			rc = AI_ERR_INVALID_ARG;
			goto out_free;
		}
		free(err_arg);
		err_arg = NULL;
	}
	/* W65 P2-04：gcc/cc 仅 /tmp 的选项形态校验 */
	if (strcmp(cmd, "gcc") == 0 || strcmp(cmd, "cc") == 0) {
		if (!exec_gcc_args_ok(argv_extra, argv_extra_n, &err_arg)) {
			exec_param_error(out, "GCC_ARGS",
					 err_arg ? err_arg :
					 "gcc/cc 参数不在 /tmp 内", tool);
			free(err_arg);
			rc = AI_ERR_INVALID_ARG;
			goto out_free;
		}
		free(err_arg);
		err_arg = NULL;
	}

	/* W69 P1-1：W1/W2 文件类命令的写目标校验。
	 * 按命令语义提取目标（cp/mv/ln 的 -t、sed -i、gcc -o、
	 * chmod 模式位等），再做 realpath/符号链接解析；系统路径与
	 * 链接逃逸一律拒绝。 */
	if (path_check) {
		const char *const *roots = g_w1_allow_dirs;

		/* W65：命令级 path_roots 覆盖全局（gcc/cc 仅 /tmp） */
		if (spec->path_root_count > 0)
			roots = (const char *const *)spec->path_roots;

		if (!exec_check_write_targets(cmd, argv_extra, argv_extra_n,
					      roots, &err_arg)) {
			exec_param_error(out, "PATH",
					 err_arg ? err_arg :
					 "写路径不在允许目录", tool);
			free(err_arg);
			rc = AI_ERR_INVALID_ARG;
			goto out_free;
		}
		free(err_arg);
		err_arg = NULL;
	}

	/* W69 round 2：R/W1 动态写目标（sort -o、uniq 输出、ss -D、
	 * curl -o、journalctl --cursor-file、ethtool file/data 等）
	 * 继续走 realpath/父目录校验；不可审计形态直接拒绝。 */
	{
		const char *const *roots = g_w1_allow_dirs;
		struct exec_dyn dyn;
		int j;

		if (spec->path_root_count > 0)
			roots = (const char *const *)spec->path_roots;
		exec_dyn_scan(spec, argv_extra, argv_extra_n, &dyn);
		if (dyn.deny) {
			if (asprintf(out, "%s %s", TOOL_ERR_DENIED_PREFIX,
				     dyn.deny_reason ? dyn.deny_reason :
				     "危险执行形态") < 0)
				*out = NULL;
			free(dyn.deny_reason);
			rc = AI_ERR_API;
			goto out_free;
		}
		for (j = 0; j < dyn.wpath_n; j++) {
			char *perr = NULL;

			if (!w1_path_allowed_in(dyn.wpaths[j], roots,
						&perr)) {
				exec_param_error(out, "PATH",
						 perr ? perr :
						 "写路径不在允许目录", tool);
				free(perr);
				free(dyn.deny_reason);
				rc = AI_ERR_INVALID_ARG;
				goto out_free;
			}
			free(perr);
		}
		free(dyn.deny_reason);
	}

	/* W72：沙盒内建 which（见 exec_which_builtin；宿主仍走注册表） */
	if (strcmp(cmd, "which") == 0) {
		const char *sb = getenv("AIKERNEL_SANDBOX");

		if (sb && sb[0]) {
			rc = exec_which_builtin(argv_extra, argv_extra_n, out);
			goto out_free;
		}
	}

	/* bin 解析：注册表 bin 为唯一权威（access 失败即拒绝，验证单源）；
	 * 仅 fallback 表条目（无 bin）按 /usr/bin → /bin 查找 */
	if (spec->bin && spec->bin[0]) {
		if (access(spec->bin, X_OK) != 0) {
			if (asprintf(out, "ERROR: 命令 '%s' 的注册表可执行"
				     "文件 %s 不可用: %s（tools.json 单源"
				     "校验失败，拒绝执行）",
				     cmd, spec->bin, strerror(errno)) < 0)
				*out = NULL;
			rc = AI_ERR_NOT_FOUND;
			goto out_free;
		}
		bin = spec->bin;
	} else {
		rc = AI_ERR_NOT_FOUND;
		for (i = 0; i < 2; i++) {
			snprintf(path, sizeof(path), "%s/%s",
				 i == 0 ? "/usr/bin" : "/bin", cmd);
			if (access(path, X_OK) == 0) {
				rc = AI_OK;
				break;
			}
		}
		if (rc != AI_OK) {
			if (asprintf(out, "ERROR: exec 通道不可用：在 "
				     "/usr/bin 与 /bin 下均未找到可执行"
				     "文件 '%s'", cmd) < 0)
				*out = NULL;
			rc = AI_ERR_NOT_FOUND;
			goto out_free;
		}
		bin = path;
	}

	/* W65 P2-01：写类命令记录目标与执行前大小（tee append 回读基准）。
	 * 子进程退出码 0 后再 stat 校验，0 字节/缺失一律报失败，不再把
	 * "tee 写空文件"当成功回填给模型。 */
	write_n = exec_collect_write_targets(cmd, argv_extra, argv_extra_n,
					     write_paths, 8);
	for (i = 0; i < argv_extra_n; i++) {
		if (argv_extra[i][0] == '-' &&
		    (strcmp(argv_extra[i], "-a") == 0 ||
		     strcmp(argv_extra[i], "--append") == 0))
			append_mode = 1;
	}
	for (i = 0; i < write_n; i++) {
		struct stat st;

		pre_ok[i] = (stat(write_paths[i], &st) == 0);
		pre_sz[i] = pre_ok[i] ? st.st_size : 0;
	}

	if (pipe(pipefd) != 0) {
		*out = strdup("ERROR: pipe 创建失败");
		rc = AI_ERR_GENERIC;
		goto out_free;
	}

	if (input_data) {
		/* W20 修3：优先临时文件中转——fork 前把 input 完整落盘
		 * （0600 + pid 唯一名 + O_EXCL 防残留/符号链接竞争），
		 * 再以只读 fd 交给子进程 stdin：子进程读到的是确定性的
		 * 完整内容，与读取时机无关。落盘失败才回退 stdin 管道。 */
		snprintf(input_tmp, sizeof(input_tmp),
			 "/tmp/.aik_exec_in_%d.tmp", (int)getpid());
		unlink(input_tmp);
		{
			int wfd = open(input_tmp, O_WRONLY | O_CREAT | O_EXCL,
				       0600);

			if (wfd >= 0) {
				size_t woff = 0;

				while (woff < input_len) {
					ssize_t wn = write(wfd,
							   input_data + woff,
							   input_len - woff);

					if (wn < 0) {
						if (errno == EINTR)
							continue;
						break;
					}
					woff += (size_t)wn;
				}
				close(wfd);
				if (woff < input_len) {
					/* 落盘不完整：删残留，回退管道 */
					unlink(input_tmp);
					input_tmp[0] = '\0';
				} else {
					input_fd = open(input_tmp,
							O_RDONLY);
					if (input_fd < 0) {
						unlink(input_tmp);
						input_tmp[0] = '\0';
					}
				}
			} else {
				input_tmp[0] = '\0';
			}
		}
		if (input_fd < 0 && pipe(inpipefd) != 0) {
			*out = strdup("ERROR: stdin 中转（临时文件与管道）"
				      "均创建失败");
			close(pipefd[0]);
			close(pipefd[1]);
			rc = AI_ERR_GENERIC;
			goto out_free;
		}
	}

	pid = fork();
	if (pid < 0) {
		*out = strdup("ERROR: fork 失败");
		close(pipefd[0]);
		close(pipefd[1]);
		if (inpipefd[0] >= 0) {
			close(inpipefd[0]);
			inpipefd[0] = -1;   /* 置 -1：防 out_free 双重 close */
		}
		if (inpipefd[1] >= 0) {
			close(inpipefd[1]);
			inpipefd[1] = -1;
		}
		rc = AI_ERR_GENERIC;
		goto out_free;
	}

	if (pid == 0) {
		/* 子进程：stdin←input 管道（给定时）或 /dev/null（缺省，
		 * P0：无参 cat 等不再挂起）；stdout+stderr → pipe，
		 * execv 不经 shell */
		int devnull = open("/dev/null", O_RDWR);

		if (input_fd >= 0) {
			/* W20 修3：stdin ← 临时文件（fork 前已完整落盘） */
			dup2(input_fd, STDIN_FILENO);
			close(input_fd);
		} else if (inpipefd[0] >= 0) {
			dup2(inpipefd[0], STDIN_FILENO);
			close(inpipefd[0]);
			close(inpipefd[1]);     /* 关写端：读尽即 EOF */
		} else if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
			if (devnull > STDERR_FILENO)
				close(devnull);
		} else {
			close(STDIN_FILENO);    /* 读 stdin 即 EBADF 退出 */
		}
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);

		full_argv[0] = (char *)bin;
		argc = 1;
		/* W69 P1-1：sed 强制 --sandbox——GNU sed 4.8 起该选项在
		 * 解析期禁用 e/r/w 命令（任意命令执行/脚本读写），从根上
		 * 关闭 "sed 'e id'" 与 "sed 'w /etc/x'" 逃逸面。L1/VM
		 * 均为 GNU sed 4.8；旧版缺失时 sed 直接报错（fail-closed）。 */
		if (strcmp(cmd, "sed") == 0)
			full_argv[argc++] = (char *)"--sandbox";
		for (i = 0; spec->args_template &&
			    i < spec->args_template_n && argc < 63; i++)
			full_argv[argc++] = spec->args_template[i];
		for (i = 0; i < argv_extra_n && argc < 63; i++)
			full_argv[argc++] = argv_extra[i];
		full_argv[argc] = NULL;
		/* W65 P2-04：gcc/cc 仅 /tmp——临时文件也强制 /tmp，且 cwd
		 * 切到 /tmp（无 -o 时的默认 a.out 不会落到 /root）。 */
		if (strcmp(cmd, "gcc") == 0 || strcmp(cmd, "cc") == 0) {
			setenv("TMPDIR", "/tmp", 1);
			if (chdir("/tmp") != 0)
				_exit(126);
		}
		execv(bin, full_argv);
		_exit(127);             /* execv 失败 */
	}

	/*
	 * 父进程（P0：有界等待）：
	 *   读阶段 poll+deadline——子进程不退出也不再无限阻塞；
	 *   收尾阶段 WNOHANG 轮询 2 秒，仍存活则 SIGKILL 兜底。
	 */
	close(pipefd[1]);

	/* W20 修3 主路径（临时文件中转）：fork 后立即关 input_fd 即可，
	 * 无任何 write/读取时序依赖。
	 * 回退路径（stdin 管道）：input ≤60000 < pipe 容量（64KB），单次
	 * write 即整体进入缓冲，父进程不阻塞；随后立即关写端（子进程
	 * 读尽得 EOF），再开始排空 stdout——顺序保证无"读写互等"死锁。
	 * 子进程提前退出时 write 得 EPIPE：SIGPIPE 临时屏蔽，闭环恢复。 */
	if (input_data && inpipefd[1] >= 0) {
		size_t woff = 0;
		struct sigaction sa_ign, sa_old;

		memset(&sa_ign, 0, sizeof(sa_ign));
		sa_ign.sa_handler = SIG_IGN;
		sigaction(SIGPIPE, &sa_ign, &sa_old);
		close(inpipefd[0]);
		inpipefd[0] = -1;
		while (woff < input_len) {
			ssize_t wn = write(inpipefd[1], input_data + woff,
					   input_len - woff);

			if (wn < 0) {
				if (errno == EINTR)
					continue;
				break;          /* EPIPE：子进程已退出 */
			}
			woff += (size_t)wn;
		}
		close(inpipefd[1]);
		inpipefd[1] = -1;
		sigaction(SIGPIPE, &sa_old, NULL);
	}

	deadline = now_ms() + (long long)timeout_sec * 1000;
	cap = 8192;
	off = 0;
	total = 0;
	buf = malloc(cap);
	if (!buf) {
		close(pipefd[0]);
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		*out = strdup("ERROR: 内存不足");
		rc = AI_ERR_MEMORY;
		goto out_free;
	}
	for (;;) {
		long long remain = deadline - now_ms();
		struct pollfd pfd;
		int pr;

		/* W65 P1：Ctrl-C 取消本次 ask——立即终止正在跑的工具，
		 * 不再等满工具超时。 */
		if (ai_cancel_requested) {
			cancelled = 1;
			kill(pid, SIGKILL);
			break;
		}
		if (remain <= 0) {
			timed_out = 1;
			break;
		}
		pfd.fd = pipefd[0];
		pfd.events = POLLIN;
		pfd.revents = 0;
		pr = poll(&pfd, 1, (int)remain);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			/* W48 C3：poll 真实错误必须留下证据，不能把截断
			 * 输出当完整结果返回 */
			poll_failed = 1;
			poll_errno = errno;
			break;
		}
		if (pr == 0) {
			timed_out = 1;  /* 超时且无输出 */
			break;
		}
		{
			char tmp[4096];
			ssize_t rr = read(pipefd[0], tmp, sizeof(tmp));

			if (rr == 0)
				break;          /* EOF：子进程关闭了输出 */
			if (rr < 0) {
				if (errno == EINTR)
					continue;
				break;
			}
			total += (size_t)rr;
			if (off + (size_t)rr + 1 > cap) {
				char *nb;

				if (cap >= TOOL_RESULT_MAX) {
					/* 修复 8：已达采集上限——不再入库但
					 * 继续读排空管道（统计总字节供截断
					 * 标注；也避免子进程阻塞在 write 上
					 * 白白拖到超时） */
					continue;
				}
				cap *= 2;
				if (cap > TOOL_RESULT_MAX)
					cap = TOOL_RESULT_MAX;
				nb = realloc(buf, cap);
				if (!nb)
					continue;   /* 转排空模式（尽力而为） */
				buf = nb;
			}
			{
				/* 截到剩余容量内；半字节切界由循环后的
				 * utf8_floor 统一对齐 */
				size_t room = cap - off - 1;
				size_t take = (size_t)rr;

				if (take > room)
					take = room;
				memcpy(buf + off, tmp, take);
				off += take;
			}
		}
	}
	/* 终点对齐 UTF-8 边界（单次 read 恰好切在多字节中间的情形） */
	off = ai_json_utf8_floor(buf, off);
	buf[off] = '\0';
	close(pipefd[0]);

	/* 修复 8：超长截断标注（让模型知道结果不完整，可改用
	 * head/sed 等手段取段，而不是把截断当全文理解） */
	if (!timed_out && total > off) {
		char marker[128];
		size_t mlen;
		char *merged;

		snprintf(marker, sizeof(marker),
			 "\n[截断，工具输出共 %zu 字节，保留前 %zu 字节；"
			 "需要其余部分请分段读取]\n", total, off);
		mlen = strlen(marker);
		merged = realloc(buf, off + mlen + 1);
		if (merged) {
			buf = merged;
			memcpy(buf + off, marker, mlen + 1);
		}
	}

	/* 收尾：WNOHANG 轮询最多 2 秒，超期 SIGKILL */
	{
		long long wait_deadline = now_ms() + 2000;

		for (;;) {
			pid_t w = waitpid(pid, &status, WNOHANG);

			if (w == pid)
				break;
			if (w < 0) {
				status = 0;
				break;
			}
			if (now_ms() >= wait_deadline) {
				kill(pid, SIGKILL);
				waitpid(pid, &status, 0);
				break;
			}
			usleep(20000);
		}
	}

	if (cancelled) {
		*out = strdup("ERROR: 已取消（用户 Ctrl-C），命令已被终止");
		rc = AI_ERR_GENERIC;
		goto out_free_buf;
	}

	if (poll_failed) {
		if (asprintf(out, "ERROR: 采集管道 poll 失败 (errno=%d %s)，"
			     "结果可能不完整%s%s", poll_errno,
			     strerror(poll_errno),
			     off ? "\n已采集部分输出:\n" : "",
			     off ? buf : "") < 0)
			*out = NULL;
		rc = AI_ERR_API;
		goto out_free_buf;
	}

	if (timed_out) {
		if (asprintf(out, "ERROR: 工具超时（超过 %d 秒未完成），"
			     "已发送 SIGKILL 终止 '%s'%s%s%s",
			     timeout_sec, cmd,
			     off ? "\n部分输出:\n" : "",
			     off ? buf : "",
			     (!off && strcmp(cmd, "cat") == 0) ?
			     "（提示: 无参 cat 的 stdin 已重定向 /dev/null，"
			     "不会挂起）" : "") < 0)
			*out = NULL;
		rc = AI_ERR_API;
		goto out_free_buf;
	}

	{
		int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

		if (code == 127) {
			*out = strdup("ERROR: execv 失败（127）");
			rc = AI_ERR_NOT_FOUND;
		} else if (code != 0) {
			if (asprintf(out, "命令退出码 %d，输出:\n%s",
				     code, buf) < 0)
				*out = NULL;
			rc = AI_ERR_API;
		} else {
			/* W65 P2-01：退出码 0 不等于写入生效——回读校验目标
			 * 存在且非空（tee 内容/编译器产物），失败按工具失败
			 * 回填，避免模型误报完成。 */
			char *werr = NULL;

			if (!exec_verify_write(cmd, write_paths, write_n,
					       pre_sz, pre_ok, input_len > 0,
					       input_len, append_mode, &werr)) {
				*out = werr ? werr :
				       strdup("ERROR[E_WRITE_VERIFY]: 写入回读"
					      "校验失败");
				rc = AI_ERR_API;
			} else if (asprintf(out, "命令执行成功，输出:\n%s",
					    off ? buf : "(无输出)") < 0) {
				*out = NULL;
				rc = AI_ERR_MEMORY;
			} else {
				rc = AI_OK;
			}
		}
	}

out_free_buf:
	free(buf);
out_free:
	free(input_data);
	if (input_fd >= 0)
		close(input_fd);
	if (input_tmp[0])
		unlink(input_tmp);      /* W20 修3：中转文件用后即焚 */
	if (inpipefd[0] >= 0)
		close(inpipefd[0]);
	if (inpipefd[1] >= 0)
		close(inpipefd[1]);
	free(cmd);
	for (i = 0; i < argv_extra_n; i++)
		free(argv_extra[i]);
	free(argv_extra);
	return rc;
}

/* ---- memory（SME，W50：30 工具覆盖 29 条记忆/引擎端点） ---- */

static int exec_memory(const struct ai_tool *tool, const char *args_json,
		       char **out)
{
	char resp[SME_OUT_BUF_MIN * 4];
	char *av[12] = { NULL };
	int rc = AI_OK;
	int i;

	memset(resp, 0, sizeof(resp));

	if (strcmp(tool->name, "memory_search") == 0) {
		av[0] = arg_str(args_json, "text");
		if (!av[0] || !av[0][0]) {
			*out = strdup("ERROR: 缺少必填参数 text");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		rc = sme_search(av[0],
				(int)arg_ll(args_json, "top_k", 3),
				resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_search_advanced") == 0) {
		struct sme_search_opts o;

		memset(&o, 0, sizeof(o));
		av[0] = arg_str(args_json, "text");
		av[1] = arg_str(args_json, "metadata_filters");
		av[2] = arg_str(args_json, "tags");
		av[3] = arg_str(args_json, "region_retrieval");
		av[4] = arg_str(args_json, "ns");
		o.text = av[0];
		o.metadata_filters_json = av[1];
		o.tags_json = av[2];
		o.region_retrieval = av[3];
		o.ns = av[4];
		if (!o.text || !o.text[0]) {
			*out = strdup("ERROR: 缺少必填参数 text");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		o.top_k = (int)arg_ll(args_json, "top_k", 10);
		o.top_regions = (int)arg_ll(args_json, "top_regions", 0);
		o.graph_expand = (int)arg_ll(args_json, "graph_expand", 0);
		o.has_include_archived =
			arg_has(args_json, "include_archived");
		o.include_archived =
			arg_bool(args_json, "include_archived", 0);
		rc = sme_search_ex(&o, resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_add") == 0) {
		struct sme_add_opts o;

		memset(&o, 0, sizeof(o));
		av[0] = arg_str(args_json, "text");
		av[1] = arg_str(args_json, "metadata");
		/* 保持 W43 语义：AI 写入的默认来源标记 src=ask */
		if (!av[1])
			av[1] = strdup("{\"src\":\"ask\"}");
		av[2] = arg_str(args_json, "tags");
		av[3] = arg_str(args_json, "source");
		av[4] = arg_str(args_json, "link_to");
		av[5] = arg_str(args_json, "link_kind");
		av[6] = arg_str(args_json, "ns");
		o.text = av[0];
		o.metadata_json = av[1];
		o.tags_json = av[2];
		o.source = av[3];
		o.link_to = av[4];
		o.link_kind = av[5];
		o.ns = av[6];
		if (!o.text || !o.text[0]) {
			*out = strdup("ERROR: 缺少必填参数 text");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		o.has_importance = arg_has(args_json, "importance");
		o.importance = arg_dbl(args_json, "importance", 0.5);
		rc = sme_add_ex(&o, resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_batch_add") == 0) {
		av[0] = arg_str(args_json, "memories");
		if (!av[0] || !av[0][0]) {
			*out = strdup("ERROR: 缺少必填参数 memories");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		rc = sme_memories_batch(av[0], resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_stats") == 0) {
		rc = sme_stats(resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_health") == 0) {
		rc = sme_health(resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_get") == 0) {
		av[0] = arg_str(args_json, "id");
		if (!av[0] || !av[0][0]) {
			*out = strdup("ERROR: 缺少必填参数 id");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		rc = sme_memory_get(av[0], resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_update") == 0) {
		struct sme_update_opts o;

		memset(&o, 0, sizeof(o));
		av[0] = arg_str(args_json, "id");
		av[1] = arg_str(args_json, "text");
		av[2] = arg_str(args_json, "metadata");
		av[3] = arg_str(args_json, "tags");
		av[4] = arg_str(args_json, "summary");
		o.text = av[1];
		o.metadata_json = av[2];
		o.tags_json = av[3];
		o.summary = av[4];
		if (!av[0] || !av[0][0]) {
			*out = strdup("ERROR: 缺少必填参数 id");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		o.has_importance = arg_has(args_json, "importance");
		o.importance = arg_dbl(args_json, "importance", 0.5);
		o.has_weight = arg_has(args_json, "weight");
		o.weight = arg_dbl(args_json, "weight", 1.0);
		rc = sme_memory_update(av[0], &o, resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_delete") == 0) {
		av[0] = arg_str(args_json, "id");
		if (!av[0] || !av[0][0]) {
			*out = strdup("ERROR: 缺少必填参数 id");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		rc = sme_memory_delete(av[0], resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_hit") == 0) {
		av[0] = arg_str(args_json, "id");
		if (!av[0] || !av[0][0]) {
			*out = strdup("ERROR: 缺少必填参数 id");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		rc = sme_memory_hit(av[0], resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_archive") == 0) {
		av[0] = arg_str(args_json, "id");
		if (!av[0] || !av[0][0]) {
			*out = strdup("ERROR: 缺少必填参数 id");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		rc = sme_memory_archive(av[0], resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_restore") == 0) {
		av[0] = arg_str(args_json, "id");
		if (!av[0] || !av[0][0]) {
			*out = strdup("ERROR: 缺少必填参数 id");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		rc = sme_memory_restore(av[0], resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_import") == 0) {
		av[0] = arg_str(args_json, "path");
		av[1] = arg_str(args_json, "memories");
		if (av[0] && av[0][0] && av[1] && av[1][0]) {
			*out = strdup("ERROR: path 与 memories 只能二选一");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		if (av[0] && av[0][0]) {
			rc = sme_import_path(av[0], resp, sizeof(resp));
		} else if (av[1] && av[1][0]) {
			rc = sme_import(av[1], resp, sizeof(resp));
		} else {
			*out = strdup("ERROR: 缺少参数（path 或 memories）");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
	} else if (strcmp(tool->name, "memory_facts_multi_hop") == 0) {
		av[0] = arg_str(args_json, "text");
		if (!av[0] || !av[0][0]) {
			*out = strdup("ERROR: 缺少必填参数 text");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		rc = sme_facts_multi_hop(av[0],
					 (int)arg_ll(args_json, "top_k", 10),
					 resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_graph") == 0) {
		rc = sme_graph(resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_link") == 0) {
		int has_weight;

		av[0] = arg_str(args_json, "a");
		av[1] = arg_str(args_json, "b");
		av[2] = arg_str(args_json, "kind");
		av[3] = arg_str(args_json, "note");
		if (!av[0] || !av[0][0] || !av[1] || !av[1][0]) {
			*out = strdup("ERROR: 缺少必填参数 a/b");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		has_weight = arg_has(args_json, "weight");
		rc = sme_graph_link(av[0], av[1], av[2], has_weight,
				    arg_dbl(args_json, "weight", 1.0),
				    av[3], resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_regions") == 0) {
		rc = sme_regions(resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_regions_search") == 0) {
		av[0] = arg_str(args_json, "text");
		if (!av[0] || !av[0][0]) {
			*out = strdup("ERROR: 缺少必填参数 text");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		rc = sme_regions_search(av[0],
					(int)arg_ll(args_json, "top_k", 5),
					resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_regions_evolve") == 0) {
		rc = sme_regions_evolve(resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_facts") == 0) {
		rc = sme_facts(resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_facts_history") == 0) {
		av[0] = arg_str(args_json, "text");
		av[1] = arg_str(args_json, "memory_id");
		if ((!av[0] || !av[0][0]) && (!av[1] || !av[1][0])) {
			*out = strdup("ERROR: text 与 memory_id 至少提供一个");
			rc = AI_ERR_INVALID_ARG;
			goto done;
		}
		rc = sme_facts_history(av[0], av[1], resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_profile") == 0) {
		rc = sme_profile(resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_qapairs") == 0) {
		rc = sme_qapairs(resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_consolidate") == 0) {
		rc = sme_consolidate(resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_compress") == 0) {
		rc = sme_compress(resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_export") == 0) {
		av[0] = arg_str(args_json, "path");
		rc = sme_export(av[0], resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_metrics") == 0) {
		rc = sme_metrics(resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_metrics_report") == 0) {
		av[0] = arg_str(args_json, "path");
		rc = sme_metrics_report(av[0], resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_config_get") == 0) {
		rc = sme_config(resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory_config_check") == 0) {
		rc = sme_config_check(arg_bool(args_json, "ping", 0),
				      resp, sizeof(resp));
	} else {
		*out = strdup("ERROR: 未知 memory 工具");
		rc = AI_ERR_INVALID_ARG;
		goto done;
	}

done:
	g_mem_last_rc = rc;
	for (i = 0; i < (int)(sizeof(av) / sizeof(av[0])); i++)
		free(av[i]);
	/* W43/W50 失忆降级：所有 memory 工具在 SME 不可达时统一附注结构化
	 * 降级说明（随结果回填模型），并置 audit 标记 result=degraded。 */
	if (rc == AI_ERR_NETWORK && resp[0]) {
		size_t degraded_len = strlen(resp);

		snprintf(resp + degraded_len, sizeof(resp) - degraded_len,
			 "%s", tr(TR_SME_DEGRADED_NOTE));
		g_mem_degraded = 1;
	}
	if (resp[0])
		*out = strdup(resp);
	else if (!*out)
		*out = strdup("ERROR: memory 工具执行失败");
	return rc;
}

/* ---- shell（AI 应用户请求降入维护 shell，方案 A） ----
 *
 * 复用 cmd_shell 内置动作语义：fork/exec /bin/bash 继承 stdio 与终端，
 * 父进程 waitpid 等退出。区别在于触发路径：由模型在 ask 闭环中调用
 * sys.shell 工具进入（用户说「帮我打开一个 shell」），exit 后以工具
 * 结果回填 ask 对话。审计行按通道记录，另在进入前打印一行人读说明。
 */
static int exec_shell_drop(const struct ai_tool *tool, char **out)
{
	pid_t pid;
	int status = 0;

	(void)tool;

	/* W69 P1-1：sys_shell 已升 W2；沙箱子进程与无 TTY 环境一律
	 * 拒绝（即使 -y/assume_yes 也不能把交互 shell 塞进管道）。 */
	if (getenv("AIKERNEL_SANDBOX") && getenv("AIKERNEL_SANDBOX")[0]) {
		*out = strdup(TOOL_ERR_DENIED_PREFIX " sandbox 子进程禁止"
			      "降入维护 shell（sys_shell 仅宿主 TTY 可用）");
		return AI_ERR_API;
	}
	if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
		*out = strdup(TOOL_ERR_DENIED_PREFIX " 当前环境非交互终端"
			      "（stdin/stdout 被重定向），无法降入维护 shell；"
			      "sys_shell 仅支持 TTY 会话");
		return AI_ERR_API;
	}

	printf("AI 应请求开启 shell：进入维护 shell（bash）。"
	       "输入 exit 返回 AI 对话。\n");
	fflush(stdout);

	pid = fork();
	if (pid < 0) {
		if (asprintf(out, "ERROR: fork 失败（%s）。",
			     strerror(errno)) < 0)
			*out = NULL;
		return AI_ERR_GENERIC;
	}

	if (pid == 0) {
		execl("/bin/bash", "bash", (char *)NULL);
		fprintf(stderr, "shell: 无法启动 /bin/bash（%s）。\n",
			strerror(errno));
		_exit(127);
	}

	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;

	if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
		*out = strdup("ERROR: /bin/bash 启动失败。");
		return AI_ERR_GENERIC;
	}

	printf("已返回 AI 对话。\n");
	fflush(stdout);
	*out = strdup("用户已在维护 shell 中输入 exit 返回，"
		      "继续 AI 对话。");
	return AI_OK;
}

/* ---- W42: sandbox 通道（隔离区 + 子智能体） ----
 *
 * 生命周期工具 aik-sandbox（agent/ai/sandbox/aik-sandbox.c）负责真正的
 * namespace 组装（CLONE_NEWNS|NEWPID|NEWUTS + tmpfs 空根 + /usr /proc /sys
 * /etc 白名单 ro bind + pivot_root）；本通道四件工具是它的宿主侧包装：
 *
 *   sandbox_status   (R)  列隔离区与存活 pid；
 *   sandbox_create   (W1) 建挂载点；
 *   sandbox_spawn    (W2) 派子智能体：fork → setsid →
 *                        exec aik-sandbox run <name> -- <ai> -p <task>
 *                            -s sb-<name> -N
 *                        环境注入 AIKERNEL_TOOLS_JSON=<受限表>；父进程
 *                        poll 带截止时间，超时 SIGKILL 全组（setsid 后
 *                        子进程自成一组，kill(-pid) 连泄漏的孙进程一起
 *                        收掉）；stdout+stderr 合流采集，只回传尾部 4KB
 *                        作摘要。
 *   sandbox_destroy  (W1) 焚区。
 *
 * 路径定位（生产布局优先，环境变量可覆盖便于测试）：
 *   aik-sandbox     AIKERNEL_SANDBOX_BIN     → /usr/local/bin/aik-sandbox
 *   ai              AIKERNEL_SANDBOX_AI_BIN  → /usr/local/bin/ai
 *   受限工具表       AIKERNEL_SANDBOX_TOOLS_JSON
 *                                            → /usr/local/share/aikernel/
 *                                              tools-sandbox.json
 */

static const char *sb_bin(void)
{
	const char *e = getenv("AIKERNEL_SANDBOX_BIN");

	return (e && e[0]) ? e : "/usr/local/bin/aik-sandbox";
}

static const char *sb_ai_bin(void)
{
	const char *e = getenv("AIKERNEL_SANDBOX_AI_BIN");

	return (e && e[0]) ? e : "/usr/local/bin/ai";
}

static const char *sb_tools_json(void)
{
	const char *e = getenv("AIKERNEL_SANDBOX_TOOLS_JSON");

	if (e && e[0])
		return e;
	return "/usr/local/share/aikernel/tools-sandbox.json";
}

/* 区名合法性（与 aik-sandbox 侧 valid_name 同规则，宿主侧先挡一道） */
static int sb_name_ok(const char *s)
{
	size_t i, n;

	if (!s || !s[0])
		return 0;
	n = strlen(s);
	if (n > 64 || s[0] == '.' || s[0] == '-')
		return 0;
	for (i = 0; i < n; i++) {
		char c = s[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '-' || c == '_' ||
		      c == '.'))
			return 0;
	}
	return !strstr(s, "..");
}

/*
 * fork + exec argv，采集 stdout/stderr 合流输出的尾部（≤out_max 字节）。
 * 子进程 setsid 自成进程组；timeout_sec>0 时超时 kill(-pid, SIGKILL)。
 * 返回 0 成功（*timed_out 置位表示超时击杀）；-1 fork/pipe 失败。
 */
static int sb_spawn_capture(char **argv, char **extra_env, int extra_env_n,
			    int timeout_sec, size_t out_max,
			    char **tail, int *timed_out, int *cancelled,
			    int *exit_code)
{
	int pipefd[2];
	pid_t pid;
	int st = 0;
	char *ring;
	size_t ring_off = 0, ring_fill = 0;
	long long deadline_ms;
	int i;

	*timed_out = 0;
	*cancelled = 0;
	*exit_code = -1;
	ring = malloc(out_max);
	if (!ring)
		return -1;
	if (pipe(pipefd)) {
		free(ring);
		return -1;
	}
	fflush(stdout);
	fflush(stderr);
	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		free(ring);
		return -1;
	}
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDONLY);

		close(pipefd[0]);
		setsid();
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);
		if (devnull >= 0) {
			dup2(devnull, STDIN_FILENO);
			close(devnull);
		}
		for (i = 0; i < extra_env_n; i++) {
			char *eq = strchr(extra_env[i], '=');

			if (eq) {
				*eq = '\0';
				setenv(extra_env[i], eq + 1, 1);
				*eq = '=';
			}
		}
		execv(argv[0], argv);
		fprintf(stderr, "ERROR: exec %s: %s\n", argv[0],
			strerror(errno));
		_exit(127);
	}
	close(pipefd[1]);

	/* 读端非阻塞：子进程（如 exec 成 sleep 的长任务）长期持写端但
	 * 不出数据时，排空循环的 read() 不得阻塞到 deadline 之后 */
	fcntl(pipefd[0], F_SETFL,
	      fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);

	deadline_ms = (long long)time(NULL) * 1000 +
		      (long long)timeout_sec * 1000;
	while (1) {
		struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
		char chunk[2048];
		ssize_t n;
		long long now_ms;

		now_ms = (long long)time(NULL) * 1000;
		/* W65 P1：Ctrl-C 取消——SIGKILL 整个沙盒进程组 */
		if (ai_cancel_requested) {
			kill(-(pid_t)pid, SIGKILL);
			kill((pid_t)pid, SIGKILL);
			*cancelled = 1;
			while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
				;
			while ((n = read(pipefd[0], chunk,
					 sizeof(chunk))) > 0)
				;
			break;
		}
		if (now_ms >= deadline_ms) {
			/* 超时：SIGKILL 全组（子进程 setsid 后 pgid=pid，
			 * 组内孙进程一并收掉），防孤儿拖死会话 */
			kill(-(pid_t)pid, SIGKILL);
			kill((pid_t)pid, SIGKILL);
			*timed_out = 1;
			while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
				;
			/* 击杀后写端全关，把管道残余排干（read 到 0 为止） */
			while ((n = read(pipefd[0], chunk,
					 sizeof(chunk))) > 0) {
				for (i = 0; i < (int)n; i++) {
					ring[ring_off] = chunk[i];
					ring_off = (ring_off + 1) % out_max;
					if (ring_fill < out_max)
						ring_fill++;
				}
			}
			break;
		}
		if (poll(&pfd, 1, 200) > 0 &&
		    (pfd.revents & (POLLIN | POLLHUP))) {
			while ((n = read(pipefd[0], chunk,
					 sizeof(chunk))) > 0) {
				for (i = 0; i < (int)n; i++) {
					ring[ring_off] = chunk[i];
					ring_off = (ring_off + 1) % out_max;
					if (ring_fill < out_max)
						ring_fill++;
				}
			}
		}
		if (pfd.revents & POLLHUP) {
			/* 写端全关（子进程及全部孙进程都已退出）：
			 * 排空完成，收尸退出 */
			while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
				;
			break;
		}
		/* 子进程本体退出但写端仍被孙进程持有：先记尸不收，
		 * 继续等到 deadline——输出未完即任务未完，语义一致 */
		waitpid(pid, &st, WNOHANG);
	}
	close(pipefd[0]);

	/* 尾部取出（环缓冲 → 连续缓冲） */
	{
		size_t start = (ring_fill < out_max) ?
			       0 : ring_off;

		*tail = malloc(ring_fill + 1);
		if (!*tail) {
			free(ring);
			return -1;
		}
		for (i = 0; (size_t)i < ring_fill; i++)
			(*tail)[i] = ring[(start + (size_t)i) % out_max];
		(*tail)[ring_fill] = '\0';
	}
	free(ring);

	if (WIFEXITED(st))
		*exit_code = WEXITSTATUS(st);
	else if (WIFSIGNALED(st))
		*exit_code = 128 + WTERMSIG(st);
	return 0;
}

/*
 * W72：解析子智能体 stdout 末尾的机器可读状态行：
 *   [ai-status] end_reason=completed rounds=3 final=1 rc=0
 * （cmd_ask 仅在 AIKERNEL_SANDBOX 非空时输出）。父模型不能把
 * dispatcher_exit=0 当成子任务成功——必须同时看 task_status。
 * 返回: completed / partial_max_rounds / no_final_answer / cancelled /
 *       <reason> / unknown。
 */
static void sb_task_status(const char *tail, char *out, size_t n)
{
	const char *p = NULL;
	const char *q = tail;
	const char *r;
	const char *f;
	char reason[48] = "unknown";
	int final = -1;

	if (!out || n == 0)
		return;
	out[0] = '\0';
	/* 取最后一个状态行（工具输出里若出现同形字符串，不遮蔽真正结尾） */
	while (q && (q = strstr(q, "[ai-status] ")) != NULL) {
		p = q;
		q += strlen("[ai-status] ");
	}
	if (!p) {
		snprintf(out, n, "unknown");
		return;
	}
	r = strstr(p, "end_reason=");
	f = strstr(p, "final=");
	if (r) {
		size_t i = 0;
		const char *v = r + strlen("end_reason=");

		while (v[i] && v[i] != ' ' && v[i] != '\n' &&
		       i < sizeof(reason) - 1) {
			reason[i] = v[i];
			i++;
		}
		reason[i] = '\0';
	}
	if (f)
		final = atoi(f + strlen("final="));
	if (!r && !f) {
		snprintf(out, n, "unknown");
		return;
	}
	if (strcmp(reason, "completed") == 0 && final == 1)
		snprintf(out, n, "completed");
	else if (strcmp(reason, "max_rounds") == 0 && final == 1)
		snprintf(out, n, "partial_max_rounds");
	else if (strcmp(reason, "cancelled") == 0)
		snprintf(out, n, "cancelled");
	else if (final == 0)
		snprintf(out, n, "no_final_answer");
	else
		snprintf(out, n, "%s", reason);
}

static int exec_sandbox(const struct ai_tool *tool, const char *args_json,
			char **out)
{
	char *name = NULL;
	char *argv[16];

	if (strcmp(tool->name, "sandbox_spawn") != 0) {
		/* status / create / destroy：薄包装直接透传 */
		char *tail = NULL;
		int timed_out = 0, cancelled = 0, exit_code = -1;

		if (strcmp(tool->name, "sandbox_status") == 0) {
			argv[0] = (char *)sb_bin();
			argv[1] = (char *)"status";
			argv[2] = NULL;
		} else {
			name = arg_str(args_json, "name");
			if (!sb_name_ok(name)) {
				if (asprintf(out, "ERROR: 非法或缺失的隔离区名"
					     " name='%s'（允许字母数字.-_，"
					     "≤64 字符）",
					     name ? name : "(无)") < 0)
					*out = NULL;
				free(name);
				return AI_ERR_INVALID_ARG;
			}
			/* W69 P1-2：沙箱子进程只能焚毁自身隔离区
			 * （AIKERNEL_SANDBOX 为 aik-sandbox run 注入的
			 * 自身区名），禁止跨区销毁宿主/兄弟区。 */
			if (strcmp(tool->name, "sandbox_destroy") == 0) {
				const char *self = getenv("AIKERNEL_SANDBOX");

				if (self && self[0] && strcmp(self, name) != 0) {
					if (asprintf(out, TOOL_ERR_DENIED_PREFIX
						     " sandbox_destroy 只能销毁"
						     "自身隔离区（当前 %s，请求 "
						     "%s），禁止跨区销毁",
						     self, name) < 0)
						*out = NULL;
					free(name);
					return AI_ERR_API;
				}
			}
			argv[0] = (char *)sb_bin();
			argv[1] = (char *)(strcmp(tool->name,
						  "sandbox_create") == 0 ?
					   "create" : "destroy");
			argv[2] = name;
			argv[3] = NULL;
		}
		if (access(argv[0], X_OK)) {
			if (asprintf(out, "ERROR: 找不到 %s（%s）。请先安装 "
				     "aik-sandbox，或用 AIKERNEL_SANDBOX_BIN "
				     "指定路径", argv[0], strerror(errno)) < 0)
				*out = NULL;
			free(name);
			return AI_ERR_NOT_FOUND;
		}
		if (sb_spawn_capture(argv, NULL, 0, SB_SIMPLE_TIMEOUT,
				     8192, &tail, &timed_out, &cancelled,
				     &exit_code)) {
			*out = strdup("ERROR: fork/pipe 失败（沙盒工具无法"
				      "启动）");
			free(name);
			return AI_ERR_GENERIC;
		}
		if (cancelled) {
			*out = strdup("ERROR: 已取消（用户 Ctrl-C），沙盒操作"
				      "已终止");
			free(tail);
			free(name);
			return AI_ERR_GENERIC;
		}
		if (exit_code == 127) {
			if (asprintf(out, "ERROR: %s 执行失败（见上方诊断）",
				     argv[0]) < 0)
				*out = NULL;
		} else if (strcmp(tool->name, "sandbox_create") == 0) {
			char *bin_out = tail ? tail : (char *)"";

			if (asprintf(out, "%s%s",
				     tr(TR_SB_CREATED), bin_out) < 0)
				*out = NULL;
		} else if (strcmp(tool->name, "sandbox_destroy") == 0) {
			char *bin_out = tail ? tail : (char *)"";

			if (asprintf(out, "%s%s",
				     tr(TR_SB_DESTROYED), bin_out) < 0)
				*out = NULL;
		} else {
			/* status：原样透传（已在输出里） */
			if (asprintf(out, "%s", tail ? tail : "(无输出)") < 0)
				*out = NULL;
		}
		free(tail);
		free(name);
		return AI_OK;
	}

	/* ---- sandbox_spawn：派子智能体 ---- */
	{
		char *task = arg_str(args_json, "task");
		char *model = arg_str(args_json, "model");
		long long maxsec = arg_ll(args_json, "max_seconds",
					  SB_SPAWN_TIMEOUT_DEF);
		char sess[96];
		char envbuf[512];
		char *tail = NULL;
		int timed_out = 0, cancelled = 0, exit_code = -1;
		time_t t0, t1;
		char *extra_env[2];
		int extra_env_n = 0;

		name = arg_str(args_json, "name");
		if (!sb_name_ok(name) || !task || !task[0]) {
			if (asprintf(out, "ERROR: 参数不合法：name='%s'"
				     "（必填，字母数字.-_）task=%s（必填非空）",
				     name ? name : "(无)",
				     task ? "ok" : "(缺失)") < 0)
				*out = NULL;
			free(name);
			free(task);
			free(model);
			return AI_ERR_INVALID_ARG;
		}
		if (maxsec <= 0)
			maxsec = SB_SPAWN_TIMEOUT_DEF;
		if (maxsec > SB_SPAWN_TIMEOUT_MAX)
			maxsec = SB_SPAWN_TIMEOUT_MAX;
		if (access(sb_bin(), X_OK) || access(sb_ai_bin(), X_OK)) {
			if (asprintf(out, "ERROR: 可执行文件缺失：aik-sandbox="
				     "%s ai=%s（安装到 /usr/local/bin 或用 "
				     "AIKERNEL_SANDBOX_BIN/"
				     "AIKERNEL_SANDBOX_AI_BIN 指定）",
				     sb_bin(), sb_ai_bin()) < 0)
				*out = NULL;
			free(name);
			free(task);
			free(model);
			return AI_ERR_NOT_FOUND;
		}

		snprintf(sess, sizeof(sess), "sb-%s", name);
		snprintf(envbuf, sizeof(envbuf), "AIKERNEL_TOOLS_JSON=%s",
			 sb_tools_json());
		extra_env[extra_env_n++] = envbuf;

		argv[0] = (char *)sb_bin();
		argv[1] = (char *)"run";
		argv[2] = name;
		argv[3] = (char *)"--";
		argv[4] = (char *)sb_ai_bin();
		argv[5] = (char *)"-p";
		argv[6] = task;
		argv[7] = (char *)"-s";
		argv[8] = sess;
		argv[9] = (char *)"-N";
		argv[10] = NULL;

		time(&t0);
		if (sb_spawn_capture(argv, extra_env, extra_env_n,
				     (int)maxsec, SB_SPAWN_TAIL_MAX,
				     &tail, &timed_out, &cancelled,
				     &exit_code)) {
			*out = strdup("ERROR: fork/pipe 失败（子智能体无法"
				      "启动）");
			free(name);
			free(task);
			free(model);
			return AI_ERR_GENERIC;
		}
		if (cancelled) {
			*out = strdup("ERROR: 已取消（用户 Ctrl-C），子智能体"
				      "已被终止");
			free(tail);
			free(name);
			free(task);
			free(model);
			return AI_ERR_GENERIC;
		}
		time(&t1);

		/* 摘要组装：启动行 + 完成/超时行 + 输出尾部（≤4KB） */
		{
			char head[1024];
			char mnote[512];

			if (model && model[0])
				snprintf(mnote, sizeof(mnote),
					 "（model=%s：当前 ai CLI 无模型选择"
					 "参数，已登记 AIKERNEL_SANDBOX_MODEL"
					 " 环境变量，模型沿用子智能体自身 "
					 "model.toml）", model);
			else
				mnote[0] = '\0';
			snprintf(head, sizeof(head),
				 "%s%s", tr(TR_SB_SPAWN_START), mnote);
			{
				char *status_line;
				char *remind = NULL;
				char *merged;
				char task_status[64];

				sb_task_status(tail, task_status,
					       sizeof(task_status));
				if (asprintf(&remind, tr(TR_SB_DESTROY_REMIND),
					     name) < 0)
					remind = NULL;
				if (timed_out) {
					if (asprintf(&status_line,
						     tr(TR_SB_TIMEOUT),
						     name, (int)maxsec) < 0)
						status_line = NULL;
				} else {
					if (asprintf(&status_line,
						     tr(TR_SB_DONE),
						     name,
						     (int)(t1 - t0),
						     exit_code,
						     task_status) < 0)
						status_line = NULL;
				}
				if (asprintf(&merged, "%s%s--- %s\n%s%s",
					     head,
					     status_line ? status_line : "",
					     tr(TR_SB_TAIL_HDR),
					     tail ? tail : "(无输出)",
					     remind ? remind : "") < 0)
					*out = NULL;
				else
					*out = merged;
				free(remind);
				free(status_line);
			}
		}
		free(tail);
		free(name);
		free(task);
		free(model);
		return AI_OK;
	}
}

/* ---- W74：租约闸门辅助 ---- */

/* 拼接动作域：tool->sub（W51 元数据）+ exec 命令语义域 */
static void lease_domains_for_tool(const struct ai_tool *tool,
				   const char *args_json,
				   char *buf, size_t cap)
{
	size_t off = 0;
	int i;

	if (!buf || !cap)
		return;
	buf[0] = '\0';
	for (i = 0; i < tool->sub_count; i++) {
		if (!tool->sub[i] || !tool->sub[i][0])
			continue;
		off += (size_t)snprintf(buf + off, off < cap ? cap - off : 0,
					"%s%s", off ? "," : "", tool->sub[i]);
		if (off >= cap)
			return;
	}
	if (tool->channel == TOOL_CH_EXEC)
		ai_lease_exec_domains(args_json, buf, cap);
}

static const char *lease_reason_detail(const char *reason)
{
	if (!reason)
		return tr(TR_LEASE_DENY_LOAD);
	if (strcmp(reason, "lease_scope_denied") == 0)
		return tr(TR_LEASE_DENY_SCOPE);
	if (strcmp(reason, "lease_ceiling_denied") == 0)
		return tr(TR_LEASE_DENY_CEILING);
	if (strcmp(reason, "lease_expired") == 0)
		return tr(TR_LEASE_DENY_EXPIRED);
	if (strcmp(reason, "lease_revoked") == 0 ||
	    strcmp(reason, "lease_revoked_live") == 0)
		return tr(TR_LEASE_DENY_REVOKED);
	if (strcmp(reason, "lease_file_changed") == 0 ||
	    strcmp(reason, "lease_file_missing") == 0)
		return tr(TR_LEASE_DENY_LOAD);
	if (strcmp(reason, "lease_principal_mismatch") == 0 ||
	    strcmp(reason, "lease_owner_mismatch") == 0)
		return tr(TR_LEASE_DENY_PRINCIPAL);
	if (strcmp(reason, "sandbox_child_d2") == 0)
		return tr(TR_LEASE_DENY_WORKER);
	if (strcmp(reason, "confirm_invalid") == 0)
		return tr(TR_LEASE_DENY_CONFIRM);
	if (strcmp(reason, "d4_requires_root") == 0)
		return tr(TR_LEASE_DENY_D4_ROOT);
	if (strcmp(reason, "plan_read_only") == 0)
		return tr(TR_PLAN_DENY);
	return tr(TR_LEASE_DENY_LOAD);
}

/* ---------------------------------------------------------------------------
 * W76：desktop 通道（桌面能力面，本机 HTTP）
 *
 * 后端固定为 loopback 上的 Web demo（默认 127.0.0.1:8091，测试用
 * AIKERNEL_DESKTOP_URL 覆盖）。硬约束：
 *   - 只允许 http://127.0.0.1 / http://localhost / http://[::1]；
 *   - path 由工具名固定映射，模型不能传 URL/路径/JS/命令；
 *   - 用 local_http（POSIX socket）直连，不经 shell/curl；
 *   - 4xx/5xx 原样带回 body 并标 ERROR[E_DESKTOP_HTTP_*]；
 *   - 连接失败标 ERROR[E_DESKTOP_UNAVAILABLE]，绝不伪造成功。
 * 所有 D 级/lease 判定在 tool_executor_run 的统一闸门里，本函数只做
 * 参数形状校验与传输。
 * ------------------------------------------------------------------------- */
#define DESKTOP_DEFAULT_URL "http://127.0.0.1:8091"
#define DESKTOP_TIMEOUT_MS  8000
#define DESKTOP_SHOT_TIMEOUT_MS 30000

struct desktop_route {
	const char *tool;
	const char *method;
	const char *path;
	int timeout_ms;
};

static const struct desktop_route g_desktop_routes[] = {
	{ "desktop_health", "GET", "/api/health", DESKTOP_TIMEOUT_MS },
	{ "desktop_stats", "GET", "/api/stats", DESKTOP_TIMEOUT_MS },
	{ "desktop_apps_list", "GET", "/api/apps", DESKTOP_TIMEOUT_MS },
	{ "desktop_windows_list", "GET", "/api/windows", DESKTOP_TIMEOUT_MS },
	{ "desktop_theme_get", "GET", "/api/theme", DESKTOP_TIMEOUT_MS },
	{ "desktop_wallpaper_get", "GET", "/api/wallpaper", DESKTOP_TIMEOUT_MS },
	{ "desktop_notifications_list", "GET", "/api/notifs",
	  DESKTOP_TIMEOUT_MS },
	{ "desktop_screenshot", "GET", "/api/screenshot",
	  DESKTOP_SHOT_TIMEOUT_MS },
	{ "desktop_clipboard_get", "GET", "/api/clipboard",
	  DESKTOP_TIMEOUT_MS },
	{ "desktop_theme_set", "POST", "/api/theme", DESKTOP_TIMEOUT_MS },
	{ "desktop_wallpaper_set", "POST", "/api/wallpaper",
	  DESKTOP_TIMEOUT_MS },
	{ "desktop_notifications_send", "POST", "/api/notifs",
	  DESKTOP_TIMEOUT_MS },
	{ "desktop_apps_launch", "POST", "/api/apps/launch",
	  DESKTOP_TIMEOUT_MS },
	{ "desktop_windows_focus", "POST", "/api/windows/focus",
	  DESKTOP_TIMEOUT_MS },
	{ "desktop_windows_close", "POST", "/api/windows/close",
	  DESKTOP_TIMEOUT_MS },
	{ "desktop_apps_close", "POST", "/api/apps/close",
	  DESKTOP_TIMEOUT_MS },
	{ "desktop_input_type", "POST", "/api/input", DESKTOP_TIMEOUT_MS },
	{ "desktop_input_key", "POST", "/api/input", DESKTOP_TIMEOUT_MS },
	{ "desktop_clipboard_set", "POST", "/api/clipboard",
	  DESKTOP_TIMEOUT_MS },
	{ "desktop_power", "POST", "/api/power", DESKTOP_TIMEOUT_MS },
};

static void desktop_param_error(char **out, const char *code,
				const char *detail, const char *usage)
{
	if (asprintf(out, "%s_%s]: %s\nUSAGE: %s", TOOL_ERR_PARAM_PREFIX,
		     code, detail, usage) < 0)
		*out = NULL;
}

/* 校验 loopback base URL；成功去掉尾部 '/' 写入 buf。 */
static int desktop_base_url(char *buf, size_t n)
{
	const char *env = getenv("AIKERNEL_DESKTOP_URL");
	size_t len;

	if (!env || !env[0])
		env = DESKTOP_DEFAULT_URL;
	if (strncmp(env, "http://127.0.0.1:", 17) != 0 &&
	    strncmp(env, "http://localhost:", 16) != 0)
		return -1;
	len = strlen(env);
	if (len >= n || len > 256)
		return -1;
	while (len > 0 && env[len - 1] == '/')
		len--;
	if (len == 0 || len >= n)
		return -1;
	memcpy(buf, env, len);
	buf[len] = '\0';
	return 0;
}

static int desktop_charset_ok(const char *s, size_t maxlen, int allow_at)
{
	size_t i, n;

	if (!s || !s[0])
		return 0;
	n = strlen(s);
	if (n > maxlen)
		return 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];

		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		    c == '-' || c == '+' || (allow_at && c == '@'))
			continue;
		return 0;
	}
	return 1;
}

static int desktop_window_id_ok(const char *s)
{
	size_t i, n;

	if (!s || strncmp(s, "w-", 2) != 0)
		return 0;
	n = strlen(s);
	if (n < 6 || n > 14)
		return 0;
	for (i = 2; i < n; i++)
		if (s[i] < '0' || s[i] > '9')
			return 0;
	return 1;
}

static int desktop_key_ok(const char *key)
{
	static const char *const names[] = {
		"Enter", "Backspace", "Tab", "Escape", "Delete", "Home",
		"End", "PageUp", "PageDown", "ArrowUp", "ArrowDown",
		"ArrowLeft", "ArrowRight", "F1", "F2", "F3", "F4", "F5",
		"F6", "F7", "F8", "F9", "F10", "F11", "F12", NULL,
	};
	int i;

	if (!key || !key[0])
		return 0;
	if (strlen(key) == 1) {
		unsigned char c = (unsigned char)key[0];

		return c >= 0x20 && c <= 0x7e;
	}
	for (i = 0; names[i]; i++)
		if (strcmp(key, names[i]) == 0)
			return 1;
	return 0;
}

static int desktop_modifiers_ok(const char *mods)
{
	char buf[64];
	char *save = NULL;
	char *tok;
	int n = 0;

	if (!mods || !mods[0])
		return 1;
	if (strlen(mods) >= sizeof(buf))
		return 0;
	snprintf(buf, sizeof(buf), "%s", mods);
	for (tok = strtok_r(buf, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		char *m = tok;

		while (*m == ' ')
			m++;
		{
			size_t l = strlen(m);

			while (l > 0 && m[l - 1] == ' ')
				m[--l] = '\0';
		}
		if (strcmp(m, "ctrl") && strcmp(m, "alt") &&
		    strcmp(m, "shift") && strcmp(m, "meta"))
			return 0;
		n++;
	}
	return n > 0 && n <= 4;
}

static int desktop_json_str(char **out, const char *s)
{
	char *esc = ai_json_escape(s ? s : "");

	if (!esc) {
		*out = NULL;
		return -1;
	}
	*out = esc;
	return 0;
}

static int exec_desktop(const struct ai_tool *tool, const char *args_json,
			char **out)
{
	const struct desktop_route *route = NULL;
	char base[300], url[400], *body = NULL, *resp = NULL, *err = NULL;
	char *a = NULL, *b = NULL, *c = NULL, *ea = NULL, *eb = NULL, *ec = NULL;
	int status = 0, rc, i;
	int is_post;

	for (i = 0; i < (int)(sizeof(g_desktop_routes) /
			      sizeof(g_desktop_routes[0])); i++) {
		if (strcmp(g_desktop_routes[i].tool, tool->name) == 0) {
			route = &g_desktop_routes[i];
			break;
		}
	}
	if (!route) {
		if (asprintf(out, "ERROR[E_DESKTOP_ROUTE]: 未知 desktop 工具 %s"
			     "（注册表/执行器不一致）", tool->name) < 0)
			*out = NULL;
		return AI_ERR_INVALID_ARG;
	}
	if (desktop_base_url(base, sizeof(base)) != 0) {
		if (asprintf(out, "ERROR[E_DESKTOP_URL]: AIKERNEL_DESKTOP_URL"
			     " 必须是 loopback http://127.0.0.1:<port> 或 "
			     "http://localhost:<port>，拒绝任意远端 URL") < 0)
			*out = NULL;
		return AI_ERR_INVALID_ARG;
	}
	snprintf(url, sizeof(url), "%s%s", base, route->path);
	is_post = strcmp(route->method, "POST") == 0;

	/* ---- 参数形状校验 + JSON body（固定字段，不含任何路径） ---- */
	if (is_post) {
		if (strcmp(tool->name, "desktop_theme_set") == 0) {
			a = arg_str(args_json, "name");
			if (!a || !desktop_charset_ok(a, 32, 0)) {
				desktop_param_error(out, "MISSING",
					"name 必须是 dark|light|pink|custom",
					"{\"name\":\"light\"}");
				free(a);
				return AI_ERR_INVALID_ARG;
			}
			desktop_json_str(&ea, a);
			if (asprintf(&body, "{\"name\":\"%s\"}", ea ? ea : "") < 0)
				body = NULL;
		} else if (strcmp(tool->name, "desktop_wallpaper_set") == 0) {
			a = arg_str(args_json, "wallpaper");
			if (!a || !desktop_charset_ok(a, 64, 0)) {
				desktop_param_error(out, "MISSING",
					"wallpaper 必须是 gradient 或 wall-* 名",
					"{\"wallpaper\":\"wall-aurora\"}");
				free(a);
				return AI_ERR_INVALID_ARG;
			}
			desktop_json_str(&ea, a);
			if (asprintf(&body, "{\"wallpaper\":\"%s\"}",
				     ea ? ea : "") < 0)
				body = NULL;
		} else if (strcmp(tool->name,
				  "desktop_notifications_send") == 0) {
			a = arg_str(args_json, "title");
			b = arg_str(args_json, "body");
			c = arg_str(args_json, "tag");
			if (!a || !a[0] || strlen(a) > 240 ||
			    (b && strlen(b) > 1200) ||
			    (c && !desktop_charset_ok(c, 24, 1))) {
				desktop_param_error(out, "MISSING",
					"title 必填（≤240B）；body≤1200B；tag 字母数字",
					"{\"title\":\"任务完成\","
					"\"body\":\"已切换主题\",\"tag\":\"ai\"}");
				free(a); free(b); free(c);
				return AI_ERR_INVALID_ARG;
			}
			desktop_json_str(&ea, a);
			desktop_json_str(&eb, b ? b : "");
			desktop_json_str(&ec, c ? c : "ai");
			if (asprintf(&body,
				     "{\"title\":\"%s\",\"body\":\"%s\","
				     "\"tag\":\"%s\"}",
				     ea ? ea : "", eb ? eb : "",
				     ec ? ec : "") < 0)
				body = NULL;
		} else if (strcmp(tool->name, "desktop_apps_launch") == 0 ||
			   strcmp(tool->name, "desktop_apps_close") == 0) {
			a = arg_str(args_json, "app");
			if (!a || !desktop_charset_ok(a, 128, 1)) {
				desktop_param_error(out, "MISSING",
					"app 必须是 desktop_apps_list 返回的 id",
					"{\"app\":\"gnome-control-center\"}");
				free(a);
				return AI_ERR_INVALID_ARG;
			}
			desktop_json_str(&ea, a);
			if (asprintf(&body, "{\"app\":\"%s\"}",
				     ea ? ea : "") < 0)
				body = NULL;
		} else if (strcmp(tool->name, "desktop_windows_focus") == 0 ||
			   strcmp(tool->name, "desktop_windows_close") == 0) {
			a = arg_str(args_json, "id");
			if (!desktop_window_id_ok(a)) {
				desktop_param_error(out, "MISSING",
					"id 必须是 desktop_windows_list 的 w-XXXX",
					"{\"id\":\"w-0001\"}");
				free(a);
				return AI_ERR_INVALID_ARG;
			}
			if (asprintf(&body, "{\"id\":\"%s\"}", a) < 0)
				body = NULL;
		} else if (strcmp(tool->name, "desktop_input_type") == 0) {
			a = arg_str(args_json, "text");
			if (!a || strlen(a) > 8192) {
				desktop_param_error(out, "MISSING",
					"text 必填且 ≤8192 字节",
					"{\"text\":\"hello\"}");
				free(a);
				return AI_ERR_INVALID_ARG;
			}
			desktop_json_str(&ea, a);
			if (asprintf(&body,
				     "{\"type\":\"type\",\"text\":\"%s\"}",
				     ea ? ea : "") < 0)
				body = NULL;
		} else if (strcmp(tool->name, "desktop_input_key") == 0) {
			a = arg_str(args_json, "key");
			b = arg_str(args_json, "modifiers");
			if (!desktop_key_ok(a)) {
				desktop_param_error(out, "MISSING",
					"key 必须是单字符或 Enter/Backspace/"
					"Tab/Escape/方向键/F1-F12",
					"{\"key\":\"Enter\"}");
				free(a); free(b);
				return AI_ERR_INVALID_ARG;
			}
			if (b && b[0] && !desktop_modifiers_ok(b)) {
				desktop_param_error(out, "MISSING",
					"modifiers 仅允许 ctrl,alt,shift,meta",
					"{\"key\":\"l\",\"modifiers\":\"ctrl\"}");
				free(a); free(b);
				return AI_ERR_INVALID_ARG;
			}
			desktop_json_str(&ea, a);
			if (b && b[0]) {
				desktop_json_str(&eb, b);
				if (asprintf(&body,
					     "{\"type\":\"key\",\"key\":\"%s\","
					     "\"modifiers\":\"%s\"}",
					     ea ? ea : "", eb ? eb : "") < 0)
					body = NULL;
			} else if (asprintf(&body,
					    "{\"type\":\"key\",\"key\":\"%s\"}",
					    ea ? ea : "") < 0) {
				body = NULL;
			}
		} else if (strcmp(tool->name, "desktop_clipboard_set") == 0) {
			a = arg_str(args_json, "text");
			if (!a || strlen(a) > 65536) {
				desktop_param_error(out, "MISSING",
					"text 必填且 ≤65536 字节",
					"{\"text\":\"要写入剪贴板的文本\"}");
				free(a);
				return AI_ERR_INVALID_ARG;
			}
			desktop_json_str(&ea, a);
			if (asprintf(&body, "{\"text\":\"%s\"}",
				     ea ? ea : "") < 0)
				body = NULL;
		} else if (strcmp(tool->name, "desktop_power") == 0) {
			a = arg_str(args_json, "action");
			if (!a || (strcmp(a, "lock") && strcmp(a, "logout") &&
				   strcmp(a, "reboot") && strcmp(a, "shutdown") &&
				   strcmp(a, "suspend"))) {
				desktop_param_error(out, "MISSING",
					"action 必须是 lock|logout|reboot|"
					"shutdown|suspend",
					"{\"action\":\"lock\"}");
				free(a);
				return AI_ERR_INVALID_ARG;
			}
			if (asprintf(&body, "{\"action\":\"%s\"}", a) < 0)
				body = NULL;
		} else {
			if (asprintf(out, "ERROR[E_DESKTOP_ROUTE]: %s 缺实现",
				     tool->name) < 0)
				*out = NULL;
			return AI_ERR_INVALID_ARG;
		}
		free(a); free(b); free(c);
		free(ea); free(eb); free(ec);
		if (!body) {
			if (asprintf(out, "ERROR[E_MEMORY]: 构造 desktop 请求体"
				     "失败") < 0)
				*out = NULL;
			return AI_ERR_MEMORY;
		}
	}

	if (is_post)
		rc = local_http_post(url, NULL, body, route->timeout_ms,
				     &resp, &err, &status);
	else
		rc = local_http_get(url, route->timeout_ms, &resp, &err,
				    &status);
	free(body);
	if (rc != AI_OK) {
		if (asprintf(out,
			     "ERROR[E_DESKTOP_UNAVAILABLE]: 桌面后端不可达 "
			     "(%s)：%s；检查 L1 demo（127.0.0.1:8091）是否在运行"
			     "（cd ~/fix-w48gui/img1 && bash run.sh start）",
			     url, err ? err : "network error") < 0)
			*out = NULL;
		free(resp);
		free(err);
		return AI_ERR_NETWORK;
	}
	free(err);
	if (status < 200 || status >= 300) {
		if (asprintf(out, "ERROR[E_DESKTOP_HTTP_%d]: %s",
			     status, resp ? resp : "(empty)") < 0)
			*out = NULL;
		free(resp);
		return AI_ERR_API;
	}
	if (!resp) {
		*out = strdup("{}");
		return AI_OK;
	}
	if (strlen(resp) > TOOL_EXEC_OUT_MAX) {
		/* 结果截断并明确标注，避免桌面大列表撑爆模型上下文 */
		char *tr;

		if (asprintf(&tr, "%.*s\n[截断，共 %zu 字节]",
			     TOOL_EXEC_OUT_MAX, resp, strlen(resp)) < 0)
			tr = NULL;
		free(resp);
		if (!tr) {
			*out = NULL;
			return AI_ERR_MEMORY;
		}
		*out = tr;
		return AI_OK;
	}
	*out = resp;
	return AI_OK;
}

/* ---- 统一入口 ---- */

int tool_executor_run(const struct ai_tool *tool, const char *args_json,
		      char **out, int *ok)
{
	int rc = AI_OK;

	if (!tool || !out)
		return AI_ERR_INVALID_ARG;
	if (ok)
		*ok = 0;
	/* W74：清空上一笔 gate 元数据，避免 early deny（exec_args_denied/
	 * sandbox/plan）把上一笔 lease/danger 写进本次 tool_call trace。 */
	ai_lease_last_reset();

	/* W69 round 2：不可审计形态直接拒绝（早于 plan/UID 确认）。 */
	if (tool->channel == TOOL_CH_EXEC) {
		char *dreason = NULL;

		if (exec_args_denied(tool, args_json, &dreason)) {
			if (asprintf(out, "%s %s", TOOL_ERR_DENIED_PREFIX,
				     dreason ? dreason : "危险执行形态") < 0)
				*out = NULL;
			free(dreason);
			audit_line_res(tool->name, "exec-deny", args_json,
				       "DENY_DYNAMIC");
			ai_trace_policy_decision("W2", "DENY",
						 "dangerous_exec_form",
						 tool->name, "none",
						 args_json);
			return AI_ERR_API;
		}
	}

	/* P2 权限分级闸门：tools.json 单源 risk → policy.conf 档位判定。
	 * W2=NEED_CONFIRM(root) 或 DENY(非 root)；审计全量落 ~/.aikernel/audit.log
	 * T2 问题 2：区分"用户在 y/N 中拒绝"与"策略档位不足"，文案不再混淆。 */
	{
		/* W48：工具级 + 命令级（含 args0 与 curl/ip/ethtool/
		 * journalctl/crontab 动态写参数）统一由
		 * tool_exec_effective_risk 计算；plan 闸门与权限闸门共用，
		 * 不再维护两份易漂移的分支。 */
		const char *erisk = tool_exec_effective_risk(tool, args_json);
		enum ai_tool_risk prisk =
			(erisk && strcmp(erisk, TOOL_RISK_W2) == 0) ?
			AI_RISK_W2 : AI_RISK_W1;
		const char *sb_zone = getenv("AIKERNEL_SANDBOX");

		/* W69 P1-2：沙箱子进程拒绝任何 W2（即使受限表被替换/
		 * 加载回退，也不能让子智能体拿到宿主级写能力）。 */
		if (sb_zone && sb_zone[0] && erisk &&
		    strcmp(erisk, TOOL_RISK_W2) == 0) {
			if (asprintf(out, TOOL_ERR_DENIED_PREFIX " sandbox "
				     "子进程（%s）禁止 W2 工具 %s（risk=%s）",
				     sb_zone, tool->name, erisk) < 0)
				*out = NULL;
			audit_line_res(tool->name, "sandbox-gate", args_json,
				       "DENY_W2");
			ai_trace_policy_decision("W2", "DENY",
						 "sandbox_child_w2",
						 tool->name, "none",
						 args_json);
			return AI_ERR_API;
		}

		/* W43 plan（规划）只读模式：闸门最前置一层（先于 uid 档位
		 * 判定——plan 是会话态，与身份档位正交）。生效范围：有效
		 * risk 非 R 的一律拒绝（W1/W2 全拒、R 放行）。 */
		if (ai_policy_get_plan_mode() &&
		    strcmp(erisk ? erisk : TOOL_RISK_W1, TOOL_RISK_R) != 0) {
			if (asprintf(out, tr(TR_PLAN_DENY),
				     tool->name, erisk ? erisk : TOOL_RISK_W1) < 0)
				*out = NULL;
			audit_line_res(tool->name, "plan-gate",
				       args_json, "PLAN_DENY");
			/* W69 P2-2：plan 拒绝补 policy_decision 事件
			 * （W66 有 tool_call 但缺 policy 事件的正是此分支） */
			ai_trace_policy_decision("PLAN", "DENY",
						 "plan_read_only",
						 tool->name, "none",
						 args_json);
			return AI_ERR_API;
		}

		static int policy_inited;
		if (!policy_inited) {
			ai_policy_init(NULL);   /* /etc/aikernel/policy.conf */
			policy_inited = 1;
		}

		/* W74：未初始化租约上下文的调用方（嵌入/新工具/测试）
		 * 一律自动进入 NONE（D2+ 必须确认），绝不回落到旧
		 * -y/assume_yes 语义。 */
		if (!ai_lease_ctx_active()) {
			char lerr[AI_LEASE_ERR_MAX] = "";

			if (ai_lease_ctx_init(NULL, 0, getuid(), lerr,
					      sizeof(lerr)) != 0) {
				if (asprintf(out, TOOL_ERR_DENIED_PREFIX
					     " 租约上下文初始化失败，已按 "
					     "fail-closed 拒绝（%s）",
					     lerr[0] ? lerr : "unknown") < 0)
					*out = NULL;
				audit_line_res(tool->name, "lease-init",
					       args_json, "DENY");
				ai_trace_policy_decision("W2", "DENY",
							 "lease_ctx_init_failed",
							 tool->name, "none",
							 args_json);
				return AI_ERR_API;
			}
		}
		{
			/* W74：Principal 租约 → D0-D4 → 确认/预授权 */
			char domains[256];
			char *target = NULL;
			const char *class_reason = NULL;
			enum ai_danger danger;
			struct ai_lease_action act;
			char *gout = NULL;
			enum ai_lease_gate_result lgate = AI_LGATE_DENY;
			const char *lreason;
			const char *ldanger;
			const char *llease;

			lease_domains_for_tool(tool, args_json, domains,
					       sizeof(domains));
			danger = ai_danger_classify(tool->name, domains, erisk,
						    args_json, &target,
						    &class_reason);
			/* sysfs-write 类工具的目标在注册表 path 上
			 * （如 config_write_fstab → /etc/fstab）。 */
			if (!target && tool->path)
				target = strdup(tool->path);
			memset(&act, 0, sizeof(act));
			act.tool = tool->name;
			act.domain = domains;
			act.target = target;
			act.args_json = args_json;
			act.risk_str = erisk ? erisk : TOOL_RISK_W1;
			act.risk = prisk;
			act.danger = danger;
			act.is_exec = (tool->channel == TOOL_CH_EXEC ||
				       tool->channel == TOOL_CH_SHELL ||
				       tool->channel == TOOL_CH_SANDBOX);
			act.plan_mode = ai_policy_get_plan_mode();
			act.worker = (sb_zone && sb_zone[0]) ? 1 : 0;

			if (!ai_lease_gate(getuid(), &act, tool->desc, NULL,
					   &gout, &lgate)) {
				lreason = ai_lease_last_reason();
				ldanger = ai_lease_last_danger();
				llease = ai_lease_last_lease_id();
				if (lgate == AI_LGATE_CONFIRM_REQUIRED &&
				    gout) {
					/* 非 TTY：一行可解析协议
					 * ERROR: DENIED: CONFIRM_REQUIRED {...} */
					if (asprintf(out,
						     TOOL_ERR_DENIED_PREFIX
						     " CONFIRM_REQUIRED %s",
						     gout) < 0)
						*out = NULL;
				} else if (lgate == AI_LGATE_USER_REFUSED) {
					if (asprintf(out,
						     TOOL_ERR_DENIED_PREFIX
						     " 已按您的选择（n/短语不匹配）"
						     "拒绝执行：%s（danger=%s）",
						     tool->name,
						     ldanger ? ldanger : "?") < 0)
						*out = NULL;
				} else if (lreason &&
					   strcmp(lreason, "policy_tier") == 0) {
					if (asprintf(out,
						     TOOL_ERR_DENIED_PREFIX
						     " 权限分级拦截（tool=%s "
						     "risk=%s）。普通用户执行 W2 需 "
						     "root（sudo ai）；策略见 "
						     "/etc/aikernel/policy.conf",
						     tool->name,
						     erisk ? erisk : "W1") < 0)
						*out = NULL;
				} else {
					if (asprintf(out,
						     TOOL_ERR_DENIED_PREFIX
						     " %s（tool=%s danger=%s "
						     "reason=%s lease=%s）",
						     lease_reason_detail(lreason),
						     tool->name,
						     ldanger ? ldanger : "?",
						     lreason ? lreason : "?",
						     llease ? llease : "-") < 0)
						*out = NULL;
				}
				free(gout);
				free(target);
				return AI_ERR_API;
			}
			free(gout);
			free(target);
		}
	}

	switch (tool->channel) {
	case TOOL_CH_PROCFS_READ:
		rc = exec_procfs_read(tool, out);
		break;
	case TOOL_CH_SYSFS_WRITE:
		rc = exec_sysfs_write(tool, args_json, out);
		break;
	case TOOL_CH_NETLINK_ACT:
		rc = exec_netlink_act(tool, args_json, out);
		break;
	case TOOL_CH_NETLINK_SENSE:
		rc = exec_netlink_sense(tool, args_json, out);
		break;
	case TOOL_CH_EXEC:
		rc = exec_exec_channel(tool, args_json, out);
		break;
	case TOOL_CH_MEMORY:
		rc = exec_memory(tool, args_json, out);
		break;
	case TOOL_CH_SHELL:
		rc = exec_shell_drop(tool, out);
		break;
	case TOOL_CH_SANDBOX:
		rc = exec_sandbox(tool, args_json, out);
		break;
	case TOOL_CH_SYSCTL:
		if (strcmp(tool->name, "sysctl_get") == 0)
			rc = exec_sysctl_read(tool, args_json, out);
		else if (strcmp(tool->name, "sysctl_set") == 0)
			rc = exec_sysctl_write(tool, args_json, out);
		else if (strcmp(tool->name, "sysctl_blacklist") == 0)
			rc = exec_sysctl_blacklist(out);
		else {
			*out = strdup("ERROR: 未知 sysctl 工具（注册表异常）");
			rc = AI_ERR_INVALID_ARG;
		}
		break;
	case TOOL_CH_SYSFS_DYN:
		rc = exec_sysfs_dyn(tool, args_json, out);
		break;
	case TOOL_CH_DESKTOP:
		rc = exec_desktop(tool, args_json, out);
		break;
	case TOOL_CH_CLARIFY:
		/* W77c：澄清只能由 ask 交互层处理；通用执行器即使被误调
		 * 也绝不提问/建租约/执行动作。 */
		*out = strdup("ERROR: clarify 只能由 ask 交互层执行"
			      "（不创建租约、不执行动作）");
		rc = AI_ERR_INVALID_ARG;
		break;
	default:
		*out = strdup("ERROR: 未知通道（注册表数据异常）");
		rc = AI_ERR_INVALID_ARG;
		break;
	}

	if (!*out)
		*out = strdup("ERROR: 执行器内部错误（无结果文本）");

	audit_line_res(tool->name, tool->channel == TOOL_CH_PROCFS_READ ?
		   "procfs-read" : tool->channel == TOOL_CH_SYSFS_WRITE ?
		   "sysfs-write" : tool->channel == TOOL_CH_NETLINK_ACT ?
		   "netlink-act" : tool->channel == TOOL_CH_NETLINK_SENSE ?
		   "netlink-sense" : tool->channel == TOOL_CH_EXEC ?
		   "exec" : tool->channel == TOOL_CH_SHELL ?
		   "shell（AI 应请求开启 shell）" :
		   tool->channel == TOOL_CH_SANDBOX ?
		   "sandbox（隔离区+子智能体）" :
		   tool->channel == TOOL_CH_SYSCTL ? "sysctl" :
		   tool->channel == TOOL_CH_SYSFS_DYN ? "sysfs" :
		   tool->channel == TOOL_CH_DESKTOP ? "desktop" : "memory",
		   args_json,
		   g_mem_degraded ? "degraded" :
		   (rc == AI_OK ? "ok" : "fail"));
	g_mem_degraded = 0;

	if (ok)
		*ok = (rc == AI_OK);
	return AI_OK;
}
