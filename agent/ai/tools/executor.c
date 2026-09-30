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
#include <sys/wait.h>
#include <sys/stat.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "netlink/ai_netlink_client.h"
#include "memory/sme_client.h"
#include "tools/executor.h"
#include <unistd.h>                  /* getuid（P2 权限分级） */
#include "policy/ai_user_policy.h"   /* P2: uid→档位→W1/W2 闸门 */

/* exec 默认超时（秒）：tools.json 未配置时生效 */
#define EXEC_DEFAULT_TIMEOUT_SEC  30

/* W1 文件类命令允许写入的目录（tools.json path_check=true 时校验） */
static const char *const g_w1_allow_dirs[] = {
	"/root", "/tmp", "/var/ai",
	NULL,
};

/* ---- 审计 ---- */

/* 审计输出：与用户可见过程合一（stdout），格式稳定便于留存回放 */
static void audit_line(const char *tool, const char *channel,
		       const char *args, int ok)
{
	printf("[audit] tool=%s channel=%s args=%s result=%s\n",
	       tool ? tool : "?", channel ? channel : "?",
	       args && args[0] ? args : "{}", ok ? "ok" : "fail");
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

/* ---- procfs-read ---- */

static int exec_procfs_read(const struct ai_tool *tool, char **out)
{
	FILE *fp;
	size_t n;
	char *buf;

	fp = fopen(tool->path, "rb");
	if (!fp) {
		/* 无 AIKernel 内核/节点不存在：明确"通道不可用" */
		if (asprintf(out, "ERROR: 读取 %s 失败: %s（procfs-read 通道"
			     "不可用：需要 AIKernel 内核，且节点存在）",
			     tool->path, strerror(errno)) < 0)
			*out = NULL;
		return AI_ERR_NOT_FOUND;
	}

	buf = malloc(TOOL_EXEC_OUT_MAX + 1);
	if (!buf) {
		fclose(fp);
		*out = strdup("ERROR: 内存不足");
		return AI_ERR_MEMORY;
	}
	n = fread(buf, 1, TOOL_EXEC_OUT_MAX, fp);
	/* 定长截断不得切在多字节 UTF-8 中间（T2 问题 1） */
	n = ai_json_utf8_floor(buf, n);
	buf[n] = '\0';
	fclose(fp);

	if (n == 0)
		snprintf(buf, TOOL_EXEC_OUT_MAX + 1, "(空文件) %s", tool->path);
	*out = buf;
	return AI_OK;
}

/* ---- sysfs-write（含 /proc/ai/telemetry 写工具） ---- */

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
		const char *p = (tool->param && tool->param[0]) ?
				tool->param : NULL;
		const char *prefix = "netlink.act.";
		const size_t prefix_len = strlen(prefix);

		if (!p && tool->name &&
		    strncmp(tool->name, prefix, prefix_len) == 0 &&
		    tool->name[prefix_len] != '\0')
			p = tool->name + prefix_len;
		if (p) {
			if (strlen(p) >= sizeof(req.param)) {
				*out = strdup("ERROR: 参数名过长（>= "
					      "AI_NL_ACT_PARAM_LEN），"
					      "拒绝下发");
				free(clamp_note);
				return AI_ERR_INVALID_ARG;
			}
			snprintf(req.param, sizeof(req.param), "%s", p);
		}
		/* p 为空：param 保持空 = 旧广播语义（注册表异常时兜底） */
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
 * 解析 args 数组参数为字符串向量（P0 语义修复：任一参数含元字符或
 * 超长 → **整条拒绝**，不再静默丢弃导致命令语义改变）。
 * 返回 AI_OK 或 AI_ERR_INVALID_ARG（*err_out 收到拒绝原因文本）。
 */
static int arg_str_array(const char *args_json, const char *key,
			 char ***outv, int *outn, char **err_out)
{
	const char *v;
	size_t vl;
	int vt;
	int i;

	*outv = NULL;
	*outn = 0;
	*err_out = NULL;
	if (!args_json || !args_json[0])
		return AI_OK;
	if (ai_json_obj_get(args_json, strlen(args_json), key,
			    &v, &vl, &vt) != 1)
		return AI_OK;
	if (vt != AI_JSON_ARR)
		return AI_OK;

	for (i = 0; ; i++) {
		const char *et;
		size_t el;
		int ety;
		char *s;
		char **nv;

		if (ai_json_arr_get(v, vl, i, &et, &el, &ety) != 1)
			break;
		if (ety != AI_JSON_STR)
			continue;
		s = ai_json_strdup_str(et, el);
		if (!s)
			break;
		if (arg_has_meta(s)) {
			*err_out = strdup("参数含禁止字符，已拒绝执行"
					  "（检测到 shell 元字符；未执行"
					  "任何部分）");
			free(s);
			goto reject;
		}
		if (strlen(s) > 256) {
			*err_out = strdup("参数超长（>256 字符），已拒绝"
					  "执行（未执行任何部分）");
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

/* W1 目标路径校验：绝对路径限白名单目录；一律拒绝 ".." 穿越 */
static int w1_path_allowed(const char *arg, char **err_out)
{
	int i;

	if (path_has_dotdot(arg)) {
		*err_out = strdup("W1 路径校验失败：参数含 \"..\" 路径"
				  "穿越分量，已拒绝执行");
		return 0;
	}
	if (arg[0] != '/')
		return 1;       /* 相对路径：落在 agent 工作目录内 */
	for (i = 0; g_w1_allow_dirs[i]; i++) {
		const char *d = g_w1_allow_dirs[i];
		size_t dl = strlen(d);

		if (strcmp(arg, d) == 0 ||
		    (strncmp(arg, d, dl) == 0 && arg[dl] == '/'))
			return 1;
	}
	{
		char msg[512];

		snprintf(msg, sizeof(msg),
			 "W1 路径校验失败：绝对路径 %s 不在允许目录"
			 "（/root /tmp /var/ai）内，已拒绝执行", arg);
		*err_out = strdup(msg);
	}
	return 0;
}

/*
 * W1 校验范围：cp/mv/ln 是"源 → 目标"命令，只把最后一个非 flag 参数
 * 当写目标（读源不受限，读取面由 R 级命令与内核权限覆盖）；其余
 * W1 文件类命令（mkdir/touch/tee/sed/tar/gzip 及 ping/traceroute）
 * 全部非 flag 参数都按目标校验（保守侧）。
 */
static int w1_dest_is_last_only(const char *cmd)
{
	return cmd && (strcmp(cmd, "cp") == 0 || strcmp(cmd, "mv") == 0 ||
		       strcmp(cmd, "ln") == 0);
}

/* 单调毫秒时钟（超时 deadline 用） */
static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int exec_exec_channel(const struct ai_tool *tool, const char *args_json,
			     char **out)
{
	char *cmd = NULL;
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
	size_t cap, off;
	const struct tool_exec_cmd *spec;
	const char *risk;
	int timeout_sec;
	int path_check;
	long long deadline;
	int timed_out = 0;

	cmd = arg_str(args_json, "command");
	if (!cmd || !cmd[0]) {
		*out = strdup("ERROR: 缺少必填参数 command");
		free(cmd);
		return AI_ERR_INVALID_ARG;
	}

	/* 单源白名单查找（tools.json 权威，内置表仅 fallback） */
	spec = exec_spec_find(tool, cmd);
	if (!spec) {
		if (asprintf(out, "ERROR: 命令 '%s' 不在 exec 白名单"
			     "（单源：tools.json exec.commands；可用命令见"
			     " exec.run 工具的 command 参数 enum）",
			     cmd) < 0)
			*out = NULL;
		free(cmd);
		return AI_ERR_INVALID_ARG;
	}
	risk = spec->risk ? spec->risk : "R";
	timeout_sec = spec->timeout ? spec->timeout :
		      (tool->exec_default_timeout ?
		       tool->exec_default_timeout : EXEC_DEFAULT_TIMEOUT_SEC);
	path_check = spec->path_check;

	/* P0：任一参数含元字符/超长 → 整条拒绝（不再静默丢弃） */
	rc = arg_str_array(args_json, "args", &argv_extra, &argv_extra_n,
			   &err_arg);
	if (rc != AI_OK) {
		if (asprintf(out, "ERROR: %s", err_arg ? err_arg :
			     "参数非法，已拒绝执行") < 0)
			*out = NULL;
		free(err_arg);
		free(cmd);
		return AI_ERR_INVALID_ARG;
	}
	free(err_arg);

	/* 二级白名单：args0 限定动词（如 systemctl status|start|...），
	 * 命中时可按动词细化风险级 */
	if (spec->args0_count > 0) {
		int hit = -1;

		if (argv_extra_n < 1) {
			*out = strdup("ERROR: 该命令要求首参数为指定子命令"
				      "（见注册表 args0 白名单），已拒绝"
				      "执行");
			goto out_free;
		}
		for (i = 0; i < spec->args0_count; i++) {
			if (strcmp(spec->args0_enum[i], argv_extra[0]) == 0) {
				hit = i;
				break;
			}
		}
		if (hit < 0) {
			if (asprintf(out, "ERROR: 子命令 '%s' 不在该命令的"
				     "允许列表内，已拒绝执行",
				     argv_extra[0]) < 0)
				*out = NULL;
			goto out_free;
		}
		if (spec->args0_risk && spec->args0_risk[hit])
			risk = spec->args0_risk[hit];
	}

	/* W1 文件类命令：目标路径校验（/root /tmp /var/ai）。
	 * cp/mv/ln 只校验最后一个非 flag 参数（写目标）；其余命令
	 * 全部非 flag 参数都校验。 */
	if (path_check && strcmp(risk, "W1") == 0) {
		int last_only = w1_dest_is_last_only(cmd);
		int last_path = -1;

		if (last_only) {
			for (i = argv_extra_n - 1; i >= 0; i--) {
				if (argv_extra[i][0] != '-') {
					last_path = i;
					break;
				}
			}
		}
		for (i = 0; i < argv_extra_n; i++) {
			if (argv_extra[i][0] == '-')
				continue;       /* 选项不参与路径校验 */
			if (last_only && i != last_path)
				continue;       /* 源参数不限 */
			if (!w1_path_allowed(argv_extra[i], &err_arg)) {
				if (asprintf(out, "ERROR: %s", err_arg) < 0)
					*out = NULL;
				free(err_arg);
				goto out_free;
			}
			free(err_arg);
			err_arg = NULL;
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
			goto out_free;
		}
		bin = path;
	}

	if (pipe(pipefd) != 0) {
		*out = strdup("ERROR: pipe 创建失败");
		goto out_free;
	}

	pid = fork();
	if (pid < 0) {
		*out = strdup("ERROR: fork 失败");
		close(pipefd[0]);
		close(pipefd[1]);
		goto out_free;
	}

	if (pid == 0) {
		/* 子进程：stdin←/dev/null（P0：无参 cat 等不再挂起），
		 * stdout+stderr → pipe，execv 不经 shell */
		int devnull = open("/dev/null", O_RDWR);

		if (devnull >= 0) {
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
		for (i = 0; spec->args_template &&
			    i < spec->args_template_n && argc < 63; i++)
			full_argv[argc++] = spec->args_template[i];
		for (i = 0; i < argv_extra_n && argc < 63; i++)
			full_argv[argc++] = argv_extra[i];
		full_argv[argc] = NULL;
		execv(bin, full_argv);
		_exit(127);             /* execv 失败 */
	}

	/*
	 * 父进程（P0：有界等待）：
	 *   读阶段 poll+deadline——子进程不退出也不再无限阻塞；
	 *   收尾阶段 WNOHANG 轮询 2 秒，仍存活则 SIGKILL 兜底。
	 */
	close(pipefd[1]);
	deadline = now_ms() + (long long)timeout_sec * 1000;
	cap = 8192;
	off = 0;
	buf = malloc(cap);
	if (!buf) {
		close(pipefd[0]);
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		*out = strdup("ERROR: 内存不足");
		goto out_free;
	}
	for (;;) {
		long long remain = deadline - now_ms();
		struct pollfd pfd;
		int pr;

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
			if (off + (size_t)rr + 1 > cap) {
				char *nb;

				if (cap >= TOOL_EXEC_OUT_MAX) {
					/* 超限截断：保留已有内容 */
					break;
				}
				cap *= 2;
				if (cap > TOOL_EXEC_OUT_MAX)
					cap = TOOL_EXEC_OUT_MAX;
				nb = realloc(buf, cap);
				if (!nb)
					break;
				buf = nb;
			}
			if (off + (size_t)rr + 1 > cap) {
				/* 单次读取超出剩余容量：截到容量内（先对齐
				 * UTF-8 边界，T2 问题 1） */
				rr = (ssize_t)(cap - off - 1);
				if (rr <= 0)
					break;
				rr = (ssize_t)ai_json_utf8_floor(tmp,
								 (size_t)rr);
				if (rr <= 0)
					break;
			}
			memcpy(buf + off, tmp, (size_t)rr);
			off += (size_t)rr;
		}
	}
	/* 终点对齐 UTF-8 边界（单次 read 恰好切在多字节中间的情形） */
	off = ai_json_utf8_floor(buf, off);
	buf[off] = '\0';
	close(pipefd[0]);

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
			if (asprintf(out, "命令执行成功，输出:\n%s",
				     off ? buf : "(无输出)") < 0)
				*out = NULL;
			rc = AI_OK;
		}
	}

out_free_buf:
	free(buf);
out_free:
	free(cmd);
	for (i = 0; i < argv_extra_n; i++)
		free(argv_extra[i]);
	free(argv_extra);
	return rc;
}

/* ---- memory（SME，v2：13 端点） ---- */

static int exec_memory(const struct ai_tool *tool, const char *args_json,
		       char **out)
{
	char resp[SME_OUT_BUF_MIN * 4];
	char *text;
	char *id;
	int rc;

	memset(resp, 0, sizeof(resp));

	if (strcmp(tool->name, "memory.search") == 0) {
		text = arg_str(args_json, "text");
		if (!text || !text[0]) {
			*out = strdup("ERROR: 缺少必填参数 text");
			free(text);
			return AI_ERR_INVALID_ARG;
		}
		rc = sme_search(text,
				(int)arg_ll(args_json, "top_k", 3),
				resp, sizeof(resp));
		free(text);
	} else if (strcmp(tool->name, "memory.add") == 0) {
		text = arg_str(args_json, "text");
		if (!text || !text[0]) {
			*out = strdup("ERROR: 缺少必填参数 text");
			free(text);
			return AI_ERR_INVALID_ARG;
		}
		rc = sme_add(text, "{\"src\":\"ask\"}", resp, sizeof(resp));
		free(text);
	} else if (strcmp(tool->name, "memory.stats") == 0) {
		rc = sme_stats(resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory.get") == 0) {
		id = arg_str(args_json, "id");
		if (!id || !id[0]) {
			*out = strdup("ERROR: 缺少必填参数 id");
			free(id);
			return AI_ERR_INVALID_ARG;
		}
		rc = sme_memory_get(id, resp, sizeof(resp));
		free(id);
	} else if (strcmp(tool->name, "memory.hit") == 0) {
		id = arg_str(args_json, "id");
		if (!id || !id[0]) {
			*out = strdup("ERROR: 缺少必填参数 id");
			free(id);
			return AI_ERR_INVALID_ARG;
		}
		rc = sme_memory_hit(id, resp, sizeof(resp));
		free(id);
	} else if (strcmp(tool->name, "memory.archive") == 0) {
		id = arg_str(args_json, "id");
		if (!id || !id[0]) {
			*out = strdup("ERROR: 缺少必填参数 id");
			free(id);
			return AI_ERR_INVALID_ARG;
		}
		rc = sme_memory_archive(id, resp, sizeof(resp));
		free(id);
	} else if (strcmp(tool->name, "memory.restore") == 0) {
		id = arg_str(args_json, "id");
		if (!id || !id[0]) {
			*out = strdup("ERROR: 缺少必填参数 id");
			free(id);
			return AI_ERR_INVALID_ARG;
		}
		rc = sme_memory_restore(id, resp, sizeof(resp));
		free(id);
	} else if (strcmp(tool->name, "memory.facts_multi_hop") == 0) {
		text = arg_str(args_json, "text");
		if (!text || !text[0]) {
			*out = strdup("ERROR: 缺少必填参数 text");
			free(text);
			return AI_ERR_INVALID_ARG;
		}
		rc = sme_facts_multi_hop(text,
					 (int)arg_ll(args_json, "top_k", 10),
					 resp, sizeof(resp));
		free(text);
	} else if (strcmp(tool->name, "memory.regions_search") == 0) {
		text = arg_str(args_json, "text");
		if (!text || !text[0]) {
			*out = strdup("ERROR: 缺少必填参数 text");
			free(text);
			return AI_ERR_INVALID_ARG;
		}
		rc = sme_regions_search(text,
					(int)arg_ll(args_json, "top_k", 5),
					resp, sizeof(resp));
		free(text);
	} else if (strcmp(tool->name, "memory.consolidate") == 0) {
		rc = sme_consolidate(resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory.compress") == 0) {
		rc = sme_compress(resp, sizeof(resp));
	} else if (strcmp(tool->name, "memory.export") == 0) {
		text = arg_str(args_json, "path");
		rc = sme_export(text, resp, sizeof(resp));
		free(text);
	} else if (strcmp(tool->name, "memory.metrics") == 0) {
		rc = sme_metrics(resp, sizeof(resp));
	} else {
		*out = strdup("ERROR: 未知 memory 工具");
		return AI_ERR_INVALID_ARG;
	}

	*out = strdup(resp);
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

	if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
		*out = strdup("ERROR: 当前环境非交互终端（stdin/stdout 被重"
			      "定向），无法降入维护 shell。");
		return AI_ERR_INVALID_ARG;
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

/* ---- 统一入口 ---- */

int tool_executor_run(const struct ai_tool *tool, const char *args_json,
		      char **out, int *ok)
{
	int rc = AI_OK;

	if (!tool || !out)
		return AI_ERR_INVALID_ARG;

	/* P2 权限分级闸门：tools.json 单源 risk → policy.conf 档位判定。
	 * W2=NEED_CONFIRM(root) 或 DENY(非 root)；审计全量落 ~/.aikernel/audit.log
	 * T2 问题 2：区分"用户在 y/N 中拒绝"与"策略档位不足"，文案不再混淆。 */
	{
		/* tools.json 单源 risk（"R"/"W1"/"W2"）→ 策略枚举 */
		enum ai_tool_risk prisk = AI_RISK_W1;
		enum ai_policy_gate_result gate = AI_GATE_ALLOW;

		if (tool->risk && strcmp(tool->risk, "W2") == 0)
			prisk = AI_RISK_W2;

		static int policy_inited;
		if (!policy_inited) {
			ai_policy_init(NULL);   /* /etc/aikernel/policy.conf */
			policy_inited = 1;
		}

		if (!ai_policy_gate_reason(getuid(), tool->name, prisk,
					   tool->desc, args_json, &gate)) {
			if (gate == AI_GATE_USER_REFUSED) {
				/* 用户在 W2 再校验中主动按 n：如实报告，
				 * 文案短于折叠卡片一行限额，全文可见 */
				if (asprintf(out,
					     "已按您的选择（n）拒绝执行：%s",
					     tool->name) < 0)
					*out = NULL;
			} else {
				/* 策略档位不足：完整权限错误文案 */
				if (asprintf(out,
					     "ERROR: 权限分级拦截（tool=%s "
					     "risk=%s）。普通用户执行 W2 需 "
					     "root（sudo ai）；策略见 "
					     "/etc/aikernel/policy.conf",
					     tool->name,
					     tool->risk ? tool->risk : "W1") < 0)
					*out = NULL;
			}
			return AI_ERR_API;
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
	default:
		*out = strdup("ERROR: 未知通道（注册表数据异常）");
		rc = AI_ERR_INVALID_ARG;
		break;
	}

	if (!*out)
		*out = strdup("ERROR: 执行器内部错误（无结果文本）");

	audit_line(tool->name, tool->channel == TOOL_CH_PROCFS_READ ?
		   "procfs-read" : tool->channel == TOOL_CH_SYSFS_WRITE ?
		   "sysfs-write" : tool->channel == TOOL_CH_NETLINK_ACT ?
		   "netlink-act" : tool->channel == TOOL_CH_NETLINK_SENSE ?
		   "netlink-sense" : tool->channel == TOOL_CH_EXEC ?
		   "exec" : tool->channel == TOOL_CH_SHELL ?
		   "shell（AI 应请求开启 shell）" : "memory",
		   args_json, rc == AI_OK);

	if (ok)
		*ok = (rc == AI_OK);
	return AI_OK;
}
