// SPDX-License-Identifier: GPL-2.0
/*
 * test_exec_contract.c - W65 exec_run 参数契约 / 写入回读 / 能力探测回归
 *
 * 覆盖：
 *   1. 结构化参数错误（E_PARAM_*）+ USAGE/AVAILABLE 指引：
 *      - 缺 command
 *      - 整条命令串塞进 command（"uname -a"）
 *      - 未知参数键（不再静默忽略）
 *      - args 元素含 shell 元字符
 *   2. input 兼容别名 stdin / stdin_data（tee 落盘后回读内容）
 *   3. 未知键拒绝时绝不执行命令（无副作用）
 *   4. gcc/cc path_roots 仅 /tmp（/root 目标被结构化拒绝）
 *   5. 白名单新增 getent/systemd-analyze（R）与 gcc/cc（W1 + path_roots）
 *   6. 能力探测 probe：不存在 → 请求数组/目录页/清单均排除；存在 → 保留
 *
 * 执行器/注册表/i18n 全真；netlink/SME/策略闸门用 test_sandbox_stubs。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "ai_types.h"
#include "ai_lang.h"
#include "tools/tool_registry.h"
#include "tools/executor.h"
#include "policy/ai_lease.h"

static int g_fail;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		g_fail++; \
	} else { \
		printf("ok: %s\n", msg); \
	} \
} while (0)

static char *read_file(const char *path)
{
	FILE *fp = fopen(path, "rb");
	char *buf;
	long n;

	if (!fp)
		return NULL;
	fseek(fp, 0, SEEK_END);
	n = ftell(fp);
	rewind(fp);
	buf = calloc(1, (size_t)n + 1);
	if (buf && n > 0 && fread(buf, 1, (size_t)n, fp) != (size_t)n) {
		free(buf);
		buf = NULL;
	}
	fclose(fp);
	return buf;
}

static int run(const struct ai_tool *t, const char *args, char **out, int *ok)
{
	*out = NULL;
	*ok = 0;
	return tool_executor_run(t, args, out, ok);
}

static void check_param_error(const struct ai_tool *t, const char *args,
			      const char *code, const char *needle,
			      const char *label)
{
	char *out = NULL;
	int ok = 1;
	char want[64];

	snprintf(want, sizeof(want), "ERROR[E_PARAM_%s]", code);
	CHECK(run(t, args, &out, &ok) == AI_OK && !ok && out,
	      label);
	CHECK(out && strstr(out, want) != NULL,
	      "结构化错误码 E_PARAM_* 正确");
	CHECK(out && strstr(out, "USAGE:") != NULL,
	      "错误含 USAGE 正确形态");
	CHECK(out && strstr(out, "AVAILABLE(") != NULL,
	      "错误含 AVAILABLE 白名单");
	if (needle)
		CHECK(out && strstr(out, needle) != NULL,
		      "错误含可一次改对的 FIX 线索");
	free(out);
}

static int write_tmp_json(const char *path, const char *body)
{
	FILE *fp = fopen(path, "w");

	if (!fp)
		return -1;
	fputs(body, fp);
	fclose(fp);
	return 0;
}

int main(void)
{
	struct tool_registry reg;
	char *err = NULL;
	const struct ai_tool *t;
	char tee1[128], tee2[128], noexec[128];
	int i, found_getent = 0, found_sa = 0, found_gcc = 0, found_cc = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	lang_set("zh");
	{
		/* W74：本测试需要执行 D2/D3 命令以验证执行段边界，
		 * 用临时目录 + 显式 D3 lease（scope=*）代替旧 assume_yes。 */
		char ldir[] = "/tmp/w74ec-XXXXXX";
		char lid[AI_LEASE_ID_MAX] = "";
		char lpath[512];
		char lerr[AI_LEASE_ERR_MAX] = "";

		if (mkdtemp(ldir)) {
			setenv("AIKERNEL_LEASE_DIR", ldir, 1);
			if (ai_lease_issue("*", "D3", "exec contract test",
					   3600, getuid(), lid, sizeof(lid),
					   lpath, sizeof(lpath), lerr,
					   sizeof(lerr)) == 0)
				ai_lease_ctx_init(lid, 0, getuid(), lerr,
						  sizeof(lerr));
		}
	}
	setenv("AIKERNEL_POLICY", "/dev/null", 1);
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	memset(&reg, 0, sizeof(reg));
	if (tool_registry_load(&reg, &err) != AI_OK) {
		printf("FATAL: tools.json load: %s\n", err ? err : "?");
		return 2;
	}
	t = tool_registry_find(&reg, "exec_run");
	if (!t) {
		printf("FATAL: exec_run missing\n");
		return 2;
	}
	CHECK(reg.tool_count == 156, "主表 156 件（W77d：151+5 model_*，manifest 未漂移）");

	/* ---- 1. 参数契约 ---- */
	check_param_error(t, "{}", "MISSING", "command", "缺 command → 结构化拒绝");
	check_param_error(t, "{\"command\":\"uname -a\"}", "WHOLE_COMMAND",
			  "\"command\":\"uname\"",
			  "整条命令串 → 给出 args 拆分 FIX");
	check_param_error(t, "{\"command\":\"ls\",\"bogus\":1}",
			  "UNKNOWN_KEY", "bogus",
			  "未知参数键 → 结构化拒绝且指出键名");
	check_param_error(t, "{\"command\":\"ls\",\"args\":[\"a;b\"]}",
			  "META_ARG", "args[0]",
			  "args 含 shell 元字符 → 结构化拒绝");
	check_param_error(t, "{\"command\":\"uname\",\"stdin\":\"x\","
			  "\"stdin_data\":\"y\"}", "ALIAS_CONFLICT",
			  "input", "input 与别名冲突 → 结构化拒绝");

	/* ---- 2. stdin/stdin_data 别名：tee 真落盘回读 ---- */
	snprintf(tee1, sizeof(tee1), "/tmp/w65-tee-%ld-a", (long)getpid());
	snprintf(tee2, sizeof(tee2), "/tmp/w65-tee-%ld-b", (long)getpid());
	unlink(tee1);
	unlink(tee2);
	{
		char args[512];
		char *out = NULL;
		int ok = 0;
		char *body;

		snprintf(args, sizeof(args),
			 "{\"command\":\"tee\",\"args\":[\"%s\"],"
			 "\"stdin\":\"W65-STDIN-ALIAS\\n\"}", tee1);
		CHECK(run(t, args, &out, &ok) == AI_OK && ok,
		      "stdin 别名被接受并执行成功");
		body = read_file(tee1);
		CHECK(body && strstr(body, "W65-STDIN-ALIAS") != NULL,
		      "stdin 别名内容真实写入（回读非空）");
		CHECK(out && strstr(out, "命令执行成功") != NULL,
		      "成功结果文本正常");
		free(body);
		free(out);

		snprintf(args, sizeof(args),
			 "{\"command\":\"tee\",\"args\":[\"%s\"],"
			 "\"stdin_data\":\"W65-STDIN-DATA\\n\"}", tee2);
		out = NULL;
		ok = 0;
		CHECK(run(t, args, &out, &ok) == AI_OK && ok,
		      "stdin_data 别名被接受并执行成功");
		body = read_file(tee2);
		CHECK(body && strstr(body, "W65-STDIN-DATA") != NULL,
		      "stdin_data 别名内容真实写入");
		free(body);
		free(out);
	}
	unlink(tee1);
	unlink(tee2);

	/* ---- 3. 未知键绝不执行（副作用为 0） ---- */
	snprintf(noexec, sizeof(noexec), "/tmp/w65-noexec-%ld", (long)getpid());
	unlink(noexec);
	{
		char args[512];
		char *out = NULL;
		int ok = 1;
		struct stat st;

		snprintf(args, sizeof(args),
			 "{\"command\":\"touch\",\"args\":[\"%s\"],"
			 "\"bogus\":true}", noexec);
		CHECK(run(t, args, &out, &ok) == AI_OK && !ok,
		      "未知键 + touch → 拒绝");
		CHECK(stat(noexec, &st) != 0,
		      "拒绝发生在执行前（目标文件不存在）");
		free(out);
	}

	/* ---- 4. gcc/cc 仅 /tmp ---- */
	check_param_error(t, "{\"command\":\"gcc\",\"args\":"
			  "[\"/root/x.c\",\"-o\",\"/tmp/x\"]}",
			  "GCC_ARGS", "/tmp",
			  "gcc 源路径 /root → 结构化拒绝");
	check_param_error(t, "{\"command\":\"cc\",\"args\":"
			  "[\"/tmp/x.c\",\"-o\",\"/root/x\"]}",
			  "GCC_ARGS", "/tmp",
			  "cc 输出路径 /root → 结构化拒绝");
	check_param_error(t, "{\"command\":\"gcc\",\"args\":"
			  "[\"-wrapper\",\"/bin/sh\",\"/tmp/x.c\"]}",
			  "GCC_ARGS", "/tmp",
			  "gcc -wrapper（可执行外部程序）→ 结构化拒绝");
	check_param_error(t, "{\"command\":\"gcc\",\"args\":"
			  "[\"-I/root\",\"/tmp/x.c\"]}",
			  "GCC_ARGS", "/tmp",
			  "gcc -I/root（组合形式越界）→ 结构化拒绝");
	check_param_error(t, "{\"command\":\"gcc\",\"args\":"
			  "[\"/tmp/x.c\",\"-o/root/x\"]}",
			  "GCC_ARGS", "/tmp",
			  "gcc -o/root/x（贴合输出路径越界）→ 结构化拒绝");
	check_param_error(t, "{\"command\":\"gcc\",\"args\":"
			  "[\"relative.c\"]}",
			  "GCC_ARGS", "/tmp",
			  "gcc 相对源码路径 → 结构化拒绝（仅 /tmp 绝对路径）");

	/* gcc 正向闭环：tee 写源码（stdin 别名）→ gcc 编译 → 产物非空 */
	{
		char src[128], bin[128], args[512];
		char *out = NULL;
		int ok = 0;
		struct stat st;

		snprintf(src, sizeof(src), "/tmp/w65-gcc-%ld.c", (long)getpid());
		snprintf(bin, sizeof(bin), "/tmp/w65-gcc-%ld", (long)getpid());
		unlink(src);
		unlink(bin);
		snprintf(args, sizeof(args),
			 "{\"command\":\"tee\",\"args\":[\"%s\"],"
			 "\"stdin\":\"int main(void){return 0;}\\n\"}", src);
		CHECK(run(t, args, &out, &ok) == AI_OK && ok,
		      "gcc 前置：tee 写 /tmp 源码");
		free(out);
		out = NULL;
		snprintf(args, sizeof(args),
			 "{\"command\":\"gcc\",\"args\":[\"%s\",\"-o\",\"%s\"]}",
			 src, bin);
		CHECK(run(t, args, &out, &ok) == AI_OK && ok,
		      "gcc 编译 /tmp 源码成功（W1 + path_roots=/tmp）");
		CHECK(stat(bin, &st) == 0 && st.st_size > 0,
		      "gcc 产物非空（写入回读校验通过）");
		free(out);
		unlink(src);
		unlink(bin);
	}

	/* 选项值不是写目标：touch -d / mkdir -m 回读校验不得误判 */
	{
		char touchp[128], mkd[128], args[512];
		char *out = NULL;
		int ok = 0;
		struct stat st;

		snprintf(touchp, sizeof(touchp), "/tmp/w65-touch-%ld",
			 (long)getpid());
		snprintf(mkd, sizeof(mkd), "/tmp/w65-mkdir-%ld", (long)getpid());
		unlink(touchp);
		rmdir(mkd);
		snprintf(args, sizeof(args),
			 "{\"command\":\"touch\",\"args\":[\"-d\","
			 "\"2026-01-01 00:00:00\",\"%s\"]}", touchp);
		CHECK(run(t, args, &out, &ok) == AI_OK && ok,
		      "touch -d TIME target 成功（选项值不参与回读）");
		CHECK(stat(touchp, &st) == 0, "touch 目标存在");
		free(out);
		out = NULL;
		snprintf(args, sizeof(args),
			 "{\"command\":\"mkdir\",\"args\":[\"-m\",\"755\","
			 "\"%s\"]}", mkd);
		CHECK(run(t, args, &out, &ok) == AI_OK && ok,
		      "mkdir -m MODE target 成功（选项值不参与回读）");
		CHECK(stat(mkd, &st) == 0 && S_ISDIR(st.st_mode),
		      "mkdir 目标目录存在");
		free(out);
		unlink(touchp);
		rmdir(mkd);
	}

	/* ---- 5. 白名单新增命令 ---- */
	for (i = 0; i < t->exec_cmd_count; i++) {
		const struct tool_exec_cmd *c = &t->exec_cmds[i];

		if (strcmp(c->command, "getent") == 0 && c->risk &&
		    strcmp(c->risk, "R") == 0)
			found_getent = 1;
		if (strcmp(c->command, "systemd-analyze") == 0 && c->risk &&
		    strcmp(c->risk, "R") == 0)
			found_sa = 1;
		if (strcmp(c->command, "gcc") == 0 && c->risk &&
		    strcmp(c->risk, "W1") == 0 && c->path_check &&
		    c->path_root_count == 1 &&
		    strcmp(c->path_roots[0], "/tmp") == 0)
			found_gcc = 1;
		if (strcmp(c->command, "cc") == 0 && c->risk &&
		    strcmp(c->risk, "W1") == 0 && c->path_check &&
		    c->path_root_count == 1 &&
		    strcmp(c->path_roots[0], "/tmp") == 0)
			found_cc = 1;
	}
	CHECK(found_getent, "getent 入白名单（R）");
	CHECK(found_sa, "systemd-analyze 入白名单（R）");
	CHECK(found_gcc, "gcc 入白名单（W1 + path_roots=/tmp）");
	CHECK(found_cc, "cc 入白名单（W1 + path_roots=/tmp）");
	{
		char *out = NULL;
		int ok = 0;

		CHECK(run(t, "{\"command\":\"getent\",\"args\":"
			  "[\"passwd\",\"root\"]}", &out, &ok) == AI_OK &&
		      ok, "getent 实际执行成功");
		free(out);
	}

	/* ---- 6b. W69 P1-1/P1-4：sed/tar/符号链接/sys_shell ---- */
	{
		char link[160];
		char args[1024];
		char *out = NULL;
		int ok = 1;

		/* sed e：子进程强制 --sandbox，脚本命令必须失败 */
		CHECK(run(t, "{\"command\":\"sed\",\"args\":[\"-n\","
			  "\"e id\",\"/etc/hostname\"]}", &out, &ok) == AI_OK &&
		      !ok, "sed e（任意命令执行）被 --sandbox 拒绝");
		CHECK(out && (strstr(out, "sandbox") ||
			      strstr(out, "沙盒") ||
			      strstr(out, "e/r/w")),
		      "sed 错误含 sandbox/沙盒标记");
		free(out);
		out = NULL;
		ok = 1;

		/* sed w：--sandbox 禁写，目标文件不得出现 */
		snprintf(link, sizeof(link), "/tmp/w69-sedw-%ld",
			 (long)getpid());
		unlink(link);
		snprintf(args, sizeof(args),
			 "{\"command\":\"sed\",\"args\":[\"-n\",\"w %s\","
			 "\"/etc/hostname\"]}", link);
		CHECK(run(t, args, &out, &ok) == AI_OK && !ok,
		      "sed w（任意写）被 --sandbox 拒绝");
		{
			struct stat st;

			CHECK(stat(link, &st) != 0,
			      "sed w 目标文件未创建");
		}
		free(out);
		out = NULL;
		ok = 1;

		/* tar 执行面/绝对路径选项 */
		check_param_error(t,
			"{\"command\":\"tar\",\"args\":[\"--checkpoint=1\","
			"\"--checkpoint-action=exec=id\",\"-cf\","
			"\"/tmp/w69.tar\",\"/etc/hostname\"]}",
			"TAR_ARGS", "checkpoint-action",
			"tar --checkpoint-action → 拒绝");
		check_param_error(t,
			"{\"command\":\"tar\",\"args\":[\"--to-command=id\","
			"\"-xf\",\"/tmp/w69.tar\"]}",
			"TAR_ARGS", "to-command",
			"tar --to-command → 拒绝");
		check_param_error(t,
			"{\"command\":\"tar\",\"args\":[\"-I/bin/sh\","
			"\"-cf\",\"/tmp/w69.tar\",\"/etc/hostname\"]}",
			"TAR_ARGS", "-I",
			"tar -I（外部压缩程序）→ 拒绝");
		check_param_error(t,
			"{\"command\":\"tar\",\"args\":[\"-P\",\"-cf\","
			"\"/tmp/w69.tar\",\"/etc/hostname\"]}",
			"TAR_ARGS", "-P",
			"tar -P（绝对路径成员）→ 拒绝");

		/* ln -s /etc/passwd /tmp/x → 允许建链接；tee 写 x → 拒绝 */
		snprintf(link, sizeof(link), "/tmp/w69-link-%ld",
			 (long)getpid());
		unlink(link);
		CHECK(symlink("/etc/passwd", link) == 0,
		      "准备：/tmp 链接指向 /etc/passwd");
		snprintf(args, sizeof(args),
			 "{\"command\":\"tee\",\"args\":[\"%s\"],"
			 "\"input\":\"W69\\n\"}", link);
		CHECK(run(t, args, &out, &ok) == AI_OK && !ok,
		      "tee 写符号链接（→/etc/passwd）→ 拒绝");
		CHECK(out && strstr(out, "路径校验失败") != NULL,
		      "符号链接拒绝原因是路径校验");
		free(out);
		out = NULL;
		ok = 1;
		unlink(link);

		snprintf(args, sizeof(args),
			 "{\"command\":\"ln\",\"args\":[\"-s\",\"/etc/passwd\","
			 "\"%s\"]}", link);
		CHECK(run(t, args, &out, &ok) == AI_OK && ok,
		      "ln -s 建链接本身允许（写目标是链接路径）");
		free(out);
		out = NULL;
		ok = 1;
		snprintf(args, sizeof(args),
			 "{\"command\":\"tee\",\"args\":[\"%s\"],"
			 "\"input\":\"W69\\n\"}", link);
		CHECK(run(t, args, &out, &ok) == AI_OK && !ok,
		      "完整链路 ln -s + tee 被拒绝");
		free(out);
		out = NULL;
		ok = 1;
		unlink(link);

		/* 硬链接源 / mv 源 / cp -t 目标目录 */
		check_param_error(t,
			"{\"command\":\"ln\",\"args\":[\"/etc/passwd\","
			"\"/tmp/w69-hard\"]}", "PATH", "/etc/passwd",
			"硬链接系统文件 → 拒绝");
		check_param_error(t,
			"{\"command\":\"mv\",\"args\":[\"/etc/passwd\","
			"\"/tmp/w69-mv\"]}", "PATH", "/etc/passwd",
			"mv 系统文件作源 → 拒绝");
		check_param_error(t,
			"{\"command\":\"cp\",\"args\":[\"-t\",\"/etc\","
			"\"/tmp/w69-src\"]}", "PATH", "/etc",
			"cp -t /etc（目标目录）→ 拒绝");
		check_param_error(t,
			"{\"command\":\"tar\",\"args\":[\"-C/etc\","
			"\"-cf\",\"/tmp/w69-c.tar\",\"-T\",\"/dev/null\"]}",
			"PATH", "/etc",
			"tar -C/etc（贴合形式）→ 拒绝");
		/* W74：/etc/shadow 属 D4（身份文件），会在路径校验前进入
		 * D4 确认；这里用非身份系统文件验证 --reference 不跳过
		 * 目标路径校验（产品 D4 语义不放宽）。 */
		check_param_error(t,
			"{\"command\":\"chmod\",\"args\":["
			"\"--reference=/tmp/w69-ref\",\"/etc/hostname\"]}",
			"PATH", "/etc/hostname",
			"chmod --reference 仍校验目标路径");

		/* gcc -o 指向符号链接 */
		snprintf(link, sizeof(link), "/tmp/w69-gccout-%ld",
			 (long)getpid());
		unlink(link);
		CHECK(symlink("/etc/passwd", link) == 0,
		      "准备：gcc 输出链接指向 /etc/passwd");
		snprintf(args, sizeof(args),
			 "{\"command\":\"gcc\",\"args\":[\"/tmp/w69-x.c\","
			 "\"-o\",\"%s\"]}", link);
		CHECK(run(t, args, &out, &ok) == AI_OK && !ok &&
		      out && strstr(out, "E_PARAM_GCC_ARGS") != NULL,
		      "gcc -o 符号链接 → 结构化拒绝");
		free(out);
		out = NULL;
		ok = 1;
		unlink(link);

		/* sys_shell W2 + 非 TTY 拒绝 */
		{
			const struct ai_tool *ts =
				tool_registry_find(&reg, "sys_shell");

			CHECK(ts && ts->risk && strcmp(ts->risk, "W2") == 0,
			      "sys_shell 风险级 = W2");
			CHECK(ts && strcmp(tool_exec_effective_risk(ts, "{}"),
					   "W2") == 0,
			      "sys_shell effective risk = W2");
			if (freopen("/dev/null", "r", stdin) != NULL) {
				CHECK(run(ts, "{}", &out, &ok) == AI_OK &&
				      !ok, "sys_shell 非 TTY → 拒绝");
				CHECK(out && strstr(out,
				      TOOL_ERR_DENIED_PREFIX) != NULL &&
				      strstr(out, "非交互终端") != NULL,
				      "sys_shell 拒绝带策略前缀");
				free(out);
				out = NULL;
			} else {
				CHECK(0, "无法重定向 stdin 测试 sys_shell");
			}
		}

		/* sandbox 子进程拒绝 W2（tar 有效风险） */
		setenv("AIKERNEL_SANDBOX", "w69zone", 1);
		ok = 1;
		CHECK(run(t, "{\"command\":\"tar\",\"args\":[\"-cf\","
			  "\"/tmp/w69-sb.tar\",\"/tmp\"]}", &out, &ok) ==
		      AI_ERR_API && !ok && out &&
		      strstr(out, TOOL_ERR_DENIED_PREFIX) != NULL,
		      "sandbox 子进程拒绝 W2 命令（tar）");
		free(out);
		out = NULL;
		unsetenv("AIKERNEL_SANDBOX");

		/* P1-4 口径：只有策略前缀算 denied */
		CHECK(tool_exec_result_is_denied(
			      "ERROR: DENIED: plan 模式：只读") == 1,
		      "denied 判定识别策略拒绝");
		CHECK(tool_exec_result_is_denied(
			      "ERROR: 命令 'x' 的注册表可执行文件 /nope "
			      "不可用: No such file（tools.json 单源校验失败，"
			      "拒绝执行）") == 0,
		      "二进制缺失不算 denied（记 fail）");
		CHECK(tool_exec_result_is_denied(
			      "ERROR[E_PARAM_PATH]: 路径校验失败") == 1,
		      "写路径白名单拒绝算 denied（策略拒绝）");

		/* trace 用 effective risk：R/W2 不降格 */
		CHECK(strcmp(tool_exec_effective_risk(t,
			      "{\"command\":\"ls\",\"args\":[]}"), "R") == 0,
		      "exec ls effective risk = R");
		CHECK(strcmp(tool_exec_effective_risk(t,
			      "{\"command\":\"tar\",\"args\":[]}"), "W2") == 0,
		      "exec tar effective risk = W2");
	}

	/* ---- 6. 能力探测 probe ---- */
	{
		char probe_json[512];
		char tools_path[128];
		struct tool_registry preg;
		char *cat, *tj, *sum;

		snprintf(tools_path, sizeof(tools_path), "/tmp/w65-probe-%ld.json",
			 (long)getpid());
		snprintf(probe_json, sizeof(probe_json),
			 "{\"version\":2,\"tools\":[{\"name\":"
			 "\"procfs_read_pressure_cpu\",\"channel\":"
			 "\"procfs-read\",\"risk\":\"R\",\"description\":"
			 "\"读取 /proc/pressure/cpu（只读）：test\","
			 "\"path\":\"/nonexistent/pressure/cpu\","
			 "\"probe\":\"/nonexistent/pressure\","
			 "\"parameters\":{\"type\":\"object\","
			 "\"properties\":{}}}]}");
		CHECK(write_tmp_json(tools_path, probe_json) == 0,
		      "写临时 tools.json（probe 缺失）");
		setenv("AIKERNEL_TOOLS_JSON", tools_path, 1);
		memset(&preg, 0, sizeof(preg));
		CHECK(tool_registry_load(&preg, &err) == AI_OK,
		      "probe 缺失的注册表可加载");
		CHECK(tool_registry_find(&preg, "procfs_read_pressure_cpu") &&
		      tool_registry_find(&preg,
			  "procfs_read_pressure_cpu")->available == 0,
		      "probe 缺失 → available=0");
		cat = tool_registry_build_catalog(&preg);
		tj = tool_registry_build_tools_json(&preg);
		sum = tool_registry_summarize(&preg);
		CHECK(cat && strstr(cat, "procfs_read_pressure_cpu") == NULL,
		      "目录页排除不可用工具");
		CHECK(tj && strstr(tj, "procfs_read_pressure_cpu") == NULL,
		      "请求 tools 数组排除不可用工具");
		CHECK(sum && strstr(sum, "procfs_read_pressure_cpu") == NULL,
		      "文本清单排除不可用工具");
		free(cat);
		free(tj);
		free(sum);
		tool_registry_free(&preg);
		unlink(tools_path);

		snprintf(probe_json, sizeof(probe_json),
			 "{\"version\":2,\"tools\":[{\"name\":"
			 "\"procfs_read_pressure_cpu\",\"channel\":"
			 "\"procfs-read\",\"risk\":\"R\",\"description\":"
			 "\"读取 /proc/uptime（只读）：test\","
			 "\"path\":\"/proc/uptime\","
			 "\"probe\":\"/proc/uptime\","
			 "\"parameters\":{\"type\":\"object\","
			 "\"properties\":{}}}]}");
		CHECK(write_tmp_json(tools_path, probe_json) == 0,
		      "写临时 tools.json（probe 存在）");
		setenv("AIKERNEL_TOOLS_JSON", tools_path, 1);
		memset(&preg, 0, sizeof(preg));
		CHECK(tool_registry_load(&preg, &err) == AI_OK,
		      "probe 存在的注册表可加载");
		CHECK(tool_registry_find(&preg, "procfs_read_pressure_cpu") &&
		      tool_registry_find(&preg,
			  "procfs_read_pressure_cpu")->available == 1,
		      "probe 存在 → available=1");
		cat = tool_registry_build_catalog(&preg);
		CHECK(cat && strstr(cat, "procfs_read_pressure_cpu") != NULL,
		      "目录页保留可用工具");
		free(cat);
		tool_registry_free(&preg);
		unlink(tools_path);
	}

	/* 真实 tools.json：L1 有 /proc/pressure，三件 PSI 可用 */
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	{
		struct tool_registry r2;
		const struct ai_tool *ps;

		memset(&r2, 0, sizeof(r2));
		CHECK(tool_registry_load(&r2, &err) == AI_OK,
		      "恢复主注册表");
		ps = tool_registry_find(&r2, "procfs_read_pressure_cpu");
		CHECK(ps && ps->probe &&
		      strcmp(ps->probe, "/proc/pressure") == 0,
		      "PSI 工具带 probe=/proc/pressure");
		tool_registry_free(&r2);
	}

	tool_registry_free(&reg);
	unsetenv("AIKERNEL_TOOLS_JSON");
	if (g_fail) {
		printf("test_exec_contract: FAIL (%d)\n", g_fail);
		return 1;
	}
	printf("test_exec_contract: ALL PASS\n");
	return 0;
}
