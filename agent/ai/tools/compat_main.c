// SPDX-License-Identifier: GPL-2.0
/*
 * compat_main.c - aik-compat：compat 工具族的生产 CLI 面（C1 probe + C2 四子命令）
 *
 * C1（COMPAT-C1-DESIGN §2.2）：probe 此前只有模型 tool-call 一条触达面
 * （executor 的 TOOL_CH_COMPAT 分发）。本入口直调 ai_compat_probe_json
 * 纯函数——同一判定器、两条面（tool-call / CLI），probe JSON 输出零分叉。
 *
 * C2（COMPAT-C2-DESIGN §1 棒2）：generate/apply/verify/rollback 四子命令
 * 经 exec_compat_channel（compat_tools.c 通道入口）合成 struct ai_tool
 * {name="compat_generate"|...} 直调——与 executor 的 TOOL_CH_COMPAT 分发
 * 同一条路径，只按 tool->name 路由，不复制判定/落地逻辑。
 * rollback = compat_apply 的 rollback:true 形态（幂等：删 stage/shim，
 * 销毁本次 apply 新建的 workspace）。
 *
 * 用法：
 *   aik-compat probe    <宿主绝对路径>
 *     stdout：一行 probe JSON 原文 + 末行
 *       AIK_COMPAT rc=<0|1|-1> runnable=<0|1>
 *     （rc 语义 = ai_compat_probe_json 返回值：1=可执行 / 0=有 fatal 原因 /
 *     -1=参数非法）。退出码：0=可执行，1=有 fatal，2=使用错误。
 *   aik-compat generate <name> <宿主绝对路径> [选项]
 *     生成适配器 adapters/<name>.json（compat_generate，W1）。选项：
 *       --workspace W           L2 workspace 名（缺省 cmp-<name>）
 *       --interpreter-map K=V   解释器映射（可多次）
 *       --lib-source S=PATH     库来源（可多次）
 *       --env K=V               注入环境变量（可多次）
 *       --expect-exit N         契约期望退出码（缺省 0）
 *       --expect-stdout S       契约 stdout 须含（可多次）
 *       --expect-stderr-not S   契约 stderr 须不含（可多次）
 *       --expect-max-ms N       契约耗时上限毫秒
 *       --arg A                 传给目标的参数（可多次，不含 argv[0]）
 *       --timeout-s N           试跑超时秒 1-600（缺省 10）
 *       --dry-run               write=false 只回显不落盘
 *   aik-compat apply    <name> [--workspace W]
 *     workspace 内落地 + 试跑（compat_apply，W2；试跑失败自动回滚）。
 *   aik-compat verify   <name> [--no-trace]
 *     跑行为契约 + 三类负向自检（compat_verify，W1；须先 apply）。
 *   aik-compat rollback <name> [--workspace W]
 *     回滚（幂等；compat_apply 的 rollback:true 形态）。
 *
 * generate/apply/verify/rollback 的 stdout：一行工具结果 JSON（或
 * "ERROR: 人话"）+ 末行
 *   AIK_COMPAT sub=<子命令> rc=<n>
 * （rc = exec_compat_channel 返回值：0=AI_OK；负值=AI_ERR_*）。
 * 退出码（沿 probe 先例口径）：0=成功，1=执行失败（含契约不过/不可修），
 * 2=使用错误（AI_ERR_INVALID_ARG）。
 * 无参 / --help → 用法文本，退出 2。
 *
 * 注意（W2 旁路风险）：本 CLI 直调通道入口，不经 executor 的
 * uid→档位闸门——apply 等调用等同当前用户直接执行；需要 root 的动作
 * （宿主写点）由调用方自行保证权限。
 *
 * 链接（见 agent/ai/Makefile 的 aik-compat 目标）：本文件 +
 * compat_tools.c + workspace_tools.c + runtime/ai_json_util.c，
 * -ffunction-sections -fdata-sections + -Wl,--gc-sections 只保留实际
 * 调用图（注册表/模型面不进产物）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ai_types.h"
#include "ai_json_util.h"
#include "tools/tool_registry.h"
#include "tools/compat_tools.h"
#include "tools/workspace_tools.h"

static void usage(FILE *f)
{
	fprintf(f,
		"用法: aik-compat probe <宿主绝对路径>\n"
		"  stdout: 一行 probe JSON + 末行 AIK_COMPAT rc=<0|1|-1> runnable=<0|1>\n"
		"  退出码: 0=可执行 1=有 fatal 原因 2=使用错误\n"
		"用法: aik-compat generate <name> <宿主绝对路径> [选项]\n"
		"  生成适配器（W1）。选项:\n"
		"    --workspace W          L2 workspace 名（缺省 cmp-<name>）\n"
		"    --interpreter-map K=V  解释器映射（可多次）\n"
		"    --lib-source S=PATH    库来源（可多次）\n"
		"    --env K=V              注入环境变量（可多次）\n"
		"    --expect-exit N        契约期望退出码（缺省 0）\n"
		"    --expect-stdout S      契约 stdout 须含（可多次）\n"
		"    --expect-stderr-not S  契约 stderr 须不含（可多次）\n"
		"    --expect-max-ms N      契约耗时上限毫秒\n"
		"    --arg A                传给目标的参数（可多次）\n"
		"    --timeout-s N          试跑超时秒 1-600（缺省 10）\n"
		"    --dry-run              write=false 只回显不落盘\n"
		"用法: aik-compat apply <name> [--workspace W]\n"
		"  workspace 内落地+试跑（W2；试跑失败自动回滚）\n"
		"用法: aik-compat verify <name> [--no-trace]\n"
		"  跑行为契约+三类负向自检（须先 apply）\n"
		"用法: aik-compat rollback <name> [--workspace W]\n"
		"  回滚（幂等）\n"
		"  generate/apply/verify/rollback: stdout 一行结果 JSON + 末行\n"
		"  AIK_COMPAT sub=<名> rc=<n>；退出码 0=成功 1=失败 2=使用错误\n");
}

/* ================================================================== probe ==
 * C1 原路径，逐字节保持：argc==3 && argv[1]=="probe" 时行为与 C1 一致。
 * ====================================================================== */
static int run_probe(const char *target)
{
	char *json = NULL;
	int runnable = 0, rc;

	rc = ai_compat_probe_json(target, NULL, &json, &runnable);
	if (json) {
		printf("%s\n", json);
		free(json);
	}
	printf("AIK_COMPAT rc=%d runnable=%d\n", rc, runnable ? 1 : 0);
	return rc == 1 ? 0 : (rc < 0 ? 2 : 1);
}

/* ======================================================== C2 通道直调面 ===
 * 经 exec_compat_channel 合成 struct ai_tool{name} 直调（与 executor 的
 * TOOL_CH_COMPAT 分发同一条路径，只按 tool->name 路由）。
 * ====================================================================== */

/* CLI 收集上限：工具面自有 env≤16/map≤8/lib≤24/argv≤8 的安检（含 C2
 * 棒1 的超限诚实报错）；CLI 面只做参数形态校验，不重复业务上限。 */
#define CLI_MAX_KV   32
#define CLI_MAX_STR  32
#define CLI_STR_MAX  4096

struct cli_kv {
	char k[256];
	char v[CLI_STR_MAX];
};

struct cli_kvs {
	struct cli_kv e[CLI_MAX_KV];
	int n;
};

struct cli_strs {
	char e[CLI_STR_MAX][CLI_MAX_STR];
	int n;
};

static int kv_add(struct cli_kvs *a, const char *kv, const char *what)
{
	const char *eq = strchr(kv, '=');
	size_t klen;

	if (a->n >= CLI_MAX_KV) {
		fprintf(stderr, "aik-compat: %s 数量超上限 %d\n", what,
			CLI_MAX_KV);
		return -1;
	}
	if (!eq || eq == kv || !eq[1]) {
		fprintf(stderr, "aik-compat: %s 形态须为 K=V（两段均非空）：%s\n",
			what, kv);
		return -1;
	}
	klen = (size_t)(eq - kv);
	if (klen >= sizeof(a->e[0].k) || strlen(eq + 1) >= sizeof(a->e[0].v)) {
		fprintf(stderr, "aik-compat: %s 键或值过长（键≤%zu 值≤%zu）\n",
			what, sizeof(a->e[0].k) - 1,
			sizeof(a->e[0].v) - 1);
		return -1;
	}
	memcpy(a->e[a->n].k, kv, klen);
	a->e[a->n].k[klen] = '\0';
	snprintf(a->e[a->n].v, sizeof(a->e[0].v), "%s", eq + 1);
	a->n++;
	return 0;
}

static int strs_add(struct cli_strs *a, const char *v, const char *what)
{
	if (a->n >= CLI_MAX_STR) {
		fprintf(stderr, "aik-compat: %s 数量超上限 %d\n", what,
			CLI_MAX_STR);
		return -1;
	}
	if (!v || !*v || strlen(v) >= CLI_STR_MAX) {
		fprintf(stderr, "aik-compat: %s 值为空或过长（≤%d 字节）\n",
			what, CLI_STR_MAX - 1);
		return -1;
	}
	snprintf(a->e[a->n], CLI_STR_MAX, "%s", v);
	a->n++;
	return 0;
}

static int parse_ll(const char *s, long long *out)
{
	char *end;
	long long v;

	if (!s || !*s)
		return -1;
	v = strtoll(s, &end, 10);
	if (end == s || *end)
		return -1;
	*out = v;
	return 0;
}

/* memstream JSON object 成员输出辅助：first 语义=尚未输出过任何成员 */

static void emit_str(FILE *f, int *first, const char *key, const char *val)
{
	char *ev = ai_json_escape(val ? val : "");

	fputs(*first ? "\"" : ",\"", f);
	fputs(key, f);
	fputs("\":", f);
	fputc('"', f);
	if (ev) {
		fputs(ev, f);
		free(ev);
	}
	fputc('"', f);
	*first = 0;
}

static void emit_ll(FILE *f, int *first, const char *key, long long val)
{
	fputs(*first ? "\"" : ",\"", f);
	fputs(key, f);
	fprintf(f, "\":%lld", val);
	*first = 0;
}

/* "key":{"K":"V",...}（空集不输出） */
static void emit_kvs(FILE *f, const struct cli_kvs *a, const char *key,
		     int *first)
{
	int i;

	if (!a->n)
		return;
	fputs(*first ? "\"" : ",\"", f);
	fputs(key, f);
	fputs("\":{", f);
	for (i = 0; i < a->n; i++) {
		char *ek = ai_json_escape(a->e[i].k);
		char *ev = ai_json_escape(a->e[i].v);

		if (i)
			fputc(',', f);
		if (ek && ev)
			fprintf(f, "\"%s\":\"%s\"", ek, ev);
		free(ek);
		free(ev);
	}
	fputc('}', f);
	*first = 0;
}

/* "key":["v1","v2"]（空集不输出） */
static void emit_strs(FILE *f, const struct cli_strs *a, const char *key,
		      int *first)
{
	int i;

	if (!a->n)
		return;
	fputs(*first ? "\"" : ",\"", f);
	fputs(key, f);
	fputs("\":[", f);
	for (i = 0; i < a->n; i++) {
		char *ev = ai_json_escape(a->e[i]);

		if (i)
			fputc(',', f);
		fputc('"', f);
		if (ev) {
			fputs(ev, f);
			free(ev);
		}
		fputc('"', f);
	}
	fputc(']', f);
	*first = 0;
}

/* 通道直调：打印工具输出 + 末行汇总，返回进程退出码 */
static int run_via_channel(const char *sub, const char *tool_name,
			   char *args_json)
{
	struct ai_tool t;
	char *out = NULL;
	int rc;

	memset(&t, 0, sizeof(t));
	t.name = (char *)tool_name;
	rc = exec_compat_channel(&t, args_json, &out);
	if (out) {
		printf("%s\n", out);
		free(out);
	}
	printf("AIK_COMPAT sub=%s rc=%d\n", sub, rc);
	free(args_json);
	if (rc == AI_OK)
		return 0;
	if (rc == AI_ERR_INVALID_ARG)
		return 2;
	return 1;
}

/* generate 子命令 argv → args_json（tools.json compat_generate schema：
 * name/target 必填；workspace/interpreter_map/lib_sources/env/expect/
 * argv/timeout_s/write 可选——透传，棒1 面负责校验/新字段）。 */
static char *build_generate_json(const char *name, const char *target,
				 int argc, char **argv)
{
	struct cli_kvs imap = {0}, libs = {0}, envs = {0};
	struct cli_strs esout = {0}, eserr = {0}, extra = {0};
	long long expect_exit = -1, max_ms = -1, timeout_s = -1;
	int dry = 0, i, first = 1;
	char *ws = NULL;
	char *buf = NULL;
	size_t blen = 0;
	FILE *f;

	for (i = 0; i < argc; i++) {
		const char *a = argv[i];
		long long v;

		if (!strcmp(a, "--workspace") && i + 1 < argc) {
			ws = argv[++i];
		} else if (!strcmp(a, "--interpreter-map") && i + 1 < argc) {
			if (kv_add(&imap, argv[++i], "--interpreter-map"))
				return NULL;
		} else if (!strcmp(a, "--lib-source") && i + 1 < argc) {
			if (kv_add(&libs, argv[++i], "--lib-source"))
				return NULL;
		} else if (!strcmp(a, "--env") && i + 1 < argc) {
			if (kv_add(&envs, argv[++i], "--env"))
				return NULL;
		} else if (!strcmp(a, "--expect-exit") && i + 1 < argc) {
			if (parse_ll(argv[++i], &v)) {
				fprintf(stderr, "aik-compat: --expect-exit "
					"须为整数\n");
				return NULL;
			}
			expect_exit = v;
		} else if (!strcmp(a, "--expect-stdout") && i + 1 < argc) {
			if (strs_add(&esout, argv[++i], "--expect-stdout"))
				return NULL;
		} else if (!strcmp(a, "--expect-stderr-not") && i + 1 < argc) {
			if (strs_add(&eserr, argv[++i], "--expect-stderr-not"))
				return NULL;
		} else if (!strcmp(a, "--expect-max-ms") && i + 1 < argc) {
			if (parse_ll(argv[++i], &v)) {
				fprintf(stderr, "aik-compat: --expect-max-ms "
					"须为整数\n");
				return NULL;
			}
			max_ms = v;
		} else if (!strcmp(a, "--arg") && i + 1 < argc) {
			if (strs_add(&extra, argv[++i], "--arg"))
				return NULL;
		} else if (!strcmp(a, "--timeout-s") && i + 1 < argc) {
			if (parse_ll(argv[++i], &v)) {
				fprintf(stderr, "aik-compat: --timeout-s "
					"须为整数\n");
				return NULL;
			}
			timeout_s = v;
		} else if (!strcmp(a, "--dry-run")) {
			dry = 1;
		} else {
			fprintf(stderr, "aik-compat: 未知或残缺选项: %s\n",
				a);
			return NULL;
		}
	}

	f = open_memstream(&buf, &blen);
	if (!f) {
		fprintf(stderr, "aik-compat: 内存不足\n");
		return NULL;
	}
	fputc('{', f);
	emit_str(f, &first, "name", name);
	emit_str(f, &first, "target", target);
	if (ws && ws[0])
		emit_str(f, &first, "workspace", ws);
	emit_kvs(f, &imap, "interpreter_map", &first);
	emit_kvs(f, &libs, "lib_sources", &first);
	emit_kvs(f, &envs, "env", &first);
	/* expect 对象：任一契约字段给了才输出（缺席=用工具面缺省契约） */
	if (expect_exit >= 0 || max_ms >= 0 || esout.n || eserr.n) {
		int efirst = 1;

		fputs(first ? "\"expect\":" : ",\"expect\":", f);
		first = 0;
		fputc('{', f);
		if (expect_exit >= 0)
			emit_ll(f, &efirst, "exit_code", expect_exit);
		if (max_ms >= 0)
			emit_ll(f, &efirst, "max_ms", max_ms);
		emit_strs(f, &esout, "stdout_contains", &efirst);
		emit_strs(f, &eserr, "stderr_not_contains", &efirst);
		fputc('}', f);
	}
	emit_strs(f, &extra, "argv", &first);
	if (timeout_s >= 0)
		emit_ll(f, &first, "timeout_s", timeout_s);
	if (dry)
		fputs(",\"write\":false", f);
	fputc('}', f);
	fclose(f);
	return buf;
}

static int cmd_generate(int argc, char **argv, const char *name,
			const char *target)
{
	char *args_json;

	if (!ai_compat_valid_name(name)) {
		fprintf(stderr, "aik-compat: 非法 name（[A-Za-z0-9_.-]{1,32}，"
			"首字符非 . / -）：%s\n", name);
		return 2;
	}
	args_json = build_generate_json(name, target, argc, argv);
	if (!args_json) {
		usage(stderr);
		return 2;
	}
	return run_via_channel("generate", "compat_generate", args_json);
}

static int cmd_apply(const char *name, int argc, char **argv, int rollback)
{
	char *buf = NULL;
	size_t blen = 0;
	char *ws = NULL;
	FILE *f;
	int i, rc;
	const char *sub = rollback ? "rollback" : "apply";

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--workspace") && i + 1 < argc)
			ws = argv[++i];
		else {
			fprintf(stderr, "aik-compat: 未知或残缺选项: %s\n",
				argv[i]);
			usage(stderr);
			return 2;
		}
	}
	if (!ai_compat_valid_name(name)) {
		fprintf(stderr, "aik-compat: 非法 name：%s\n", name);
		return 2;
	}
	if (ws && ws[0] && !ai_ws_valid_name(ws)) {
		fprintf(stderr, "aik-compat: 非法 workspace 名：%s\n", ws);
		return 2;
	}
	f = open_memstream(&buf, &blen);
	if (!f) {
		fprintf(stderr, "aik-compat: 内存不足\n");
		return 2;
	}
	fprintf(f, "{\"name\":\"%s\"", name);
	if (ws && ws[0])
		fprintf(f, ",\"workspace\":\"%s\"", ws);
	fprintf(f, ",\"rollback\":%s}", rollback ? "true" : "false");
	fclose(f);
	rc = run_via_channel(sub, "compat_apply", buf);
	return rc;
}

static int cmd_verify(const char *name, int argc, char **argv)
{
	char *buf = NULL;
	size_t blen = 0;
	FILE *f;
	int no_trace = 0, i;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--no-trace"))
			no_trace = 1;
		else {
			fprintf(stderr, "aik-compat: 未知选项: %s\n", argv[i]);
			usage(stderr);
			return 2;
		}
	}
	if (!ai_compat_valid_name(name)) {
		fprintf(stderr, "aik-compat: 非法 name：%s\n", name);
		return 2;
	}
	f = open_memstream(&buf, &blen);
	if (!f) {
		fprintf(stderr, "aik-compat: 内存不足\n");
		return 2;
	}
	fprintf(f, "{\"name\":\"%s\",\"trace\":%s}", name,
		no_trace ? "false" : "true");
	fclose(f);
	return run_via_channel("verify", "compat_verify", buf);
}

int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "--help") == 0) {
		usage(stdout);
		return 2;
	}
	/* probe：C1 行为逐字节保持（argc!=3 → 用法错误退 2） */
	if (argc >= 2 && strcmp(argv[1], "probe") == 0) {
		if (argc != 3) {
			usage(stderr);
			return 2;
		}
		return run_probe(argv[2]);
	}
	if (argc >= 4 && strcmp(argv[1], "generate") == 0)
		return cmd_generate(argc - 4, argv + 4, argv[2], argv[3]);
	if (argc >= 3 && strcmp(argv[1], "apply") == 0)
		return cmd_apply(argv[2], argc - 3, argv + 3, 0);
	if (argc >= 3 && strcmp(argv[1], "verify") == 0)
		return cmd_verify(argv[2], argc - 3, argv + 3);
	if (argc >= 3 && strcmp(argv[1], "rollback") == 0)
		return cmd_apply(argv[2], argc - 3, argv + 3, 1);
	usage(stderr);
	return 2;
}
