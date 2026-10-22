// SPDX-License-Identifier: GPL-2.0
/*
 * test_exec_risk_matrix.c - W69 round 2：全部 97 条 exec 命令风险矩阵
 *
 * 数据文件 exec_risk_cases.tsv（每行 cmd \t args-json-array \t want \t note）
 * 覆盖：
 *   1. 52 条 R 命令的安全只读形态（want=R）；
 *   2. R 命令的危险选项/子命令：want=W2（升确认）、DENY（直接拒绝）、
 *      PATH（W2 但写目标 realpath 拒绝）、GCC（编译器输出路径拒绝）；
 *   3. W1 命令的执行面：ping flood、cp -l 硬链接源、gcc dump/profile。
 *
 * 对 want=R/W1/W2 只调用 tool_exec_effective_risk（不执行命令）；
 * 对 DENY/PATH/GCC 调用执行器，但拒绝发生在 fork 之前（无副作用）。
 * 另做少量正向只读调用与 sort/uniq 写 /tmp 的正向闭环。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "ai_types.h"
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

static char *read_all(const char *path)
{
	FILE *fp = fopen(path, "rb");
	long n;
	char *b;

	if (!fp)
		return NULL;
	if (fseek(fp, 0, SEEK_END) != 0) {
		fclose(fp);
		return NULL;
	}
	n = ftell(fp);
	rewind(fp);
	if (n < 0) {
		fclose(fp);
		return NULL;
	}
	b = malloc((size_t)n + 1);
	if (!b) {
		fclose(fp);
		return NULL;
	}
	if (fread(b, 1, (size_t)n, fp) != (size_t)n) {
		free(b);
		fclose(fp);
		return NULL;
	}
	b[n] = 0;
	fclose(fp);
	return b;
}

static int run(const struct ai_tool *t, const char *args, char **out, int *ok)
{
	*out = NULL;
	*ok = 0;
	return tool_executor_run(t, args, out, ok);
}

static int name_in(char names[][64], int n, const char *name)
{
	int i;

	for (i = 0; i < n; i++)
		if (strcmp(names[i], name) == 0)
			return 1;
	return 0;
}

int main(int argc, char **argv)
{
	struct tool_registry reg;
	char *err = NULL;
	const struct ai_tool *t;
	const char *cases_path = argc > 1 ? argv[1] : "exec_risk_cases.tsv";
	FILE *fp;
	char line[4096];
	char rseen[200][64];
	char dseen[200][64];
	int n_rseen = 0, n_dseen = 0, ncases = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	{
		char lerr[AI_LEASE_ERR_MAX] = "";

		ai_lease_ctx_init(NULL, 1, getuid(), lerr, sizeof(lerr));
	}
	setenv("AIKERNEL_POLICY", "/dev/null", 1);
	setenv("AIKERNEL_TOOLS_JSON", "../tools/tools.json", 1);
	unsetenv("AIKERNEL_SANDBOX");
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
	fp = fopen(cases_path, "r");
	if (!fp) {
		printf("FATAL: cannot open %s\n", cases_path);
		return 2;
	}

	while (fgets(line, sizeof(line), fp)) {
		char *cmd, *args, *want, *note, *tab1, *tab2, *tab3;
		char args_json[2048];
		char label[512];
		char *out = NULL;
		int ok = 0;

		line[strcspn(line, "\r\n")] = 0;
		if (!line[0] || line[0] == '#')
			continue;
		tab1 = strchr(line, '\t');
		if (!tab1)
			continue;
		*tab1++ = 0;
		tab2 = strchr(tab1, '\t');
		if (!tab2)
			continue;
		*tab2++ = 0;
		tab3 = strchr(tab2, '\t');
		if (tab3)
			*tab3++ = 0;
		cmd = line;
		args = tab1;
		want = tab2;
		note = tab3 ? tab3 : "";
		snprintf(args_json, sizeof(args_json),
			 "{\"command\":\"%.100s\",\"args\":%.1800s}", cmd, args);
		snprintf(label, sizeof(label), "%.60s %.300s (%.100s)", cmd, args, note);
		ncases++;

		if (strcmp(want, "R") == 0 || strcmp(want, "W1") == 0 ||
		    strcmp(want, "W2") == 0) {
			const char *risk = tool_exec_effective_risk(t, args_json);

			CHECK(risk && strcmp(risk, want) == 0, label);
			if (strcmp(want, "R") == 0 && n_rseen < 200)
				snprintf(rseen[n_rseen++], 64, "%.63s", cmd);
			if (strcmp(want, "R") != 0 && n_dseen < 200)
				snprintf(dseen[n_dseen++], 64, "%.63s", cmd);
		} else if (strcmp(want, "DENY") == 0) {
			CHECK(run(t, args_json, &out, &ok) == AI_ERR_API &&
			      !ok && out && tool_exec_result_is_denied(out),
			      label);
			if (n_dseen < 200)
				snprintf(dseen[n_dseen++], 64, "%.63s", cmd);
		} else if (strcmp(want, "PATH") == 0) {
			CHECK(run(t, args_json, &out, &ok) == AI_OK && !ok &&
			      out && strstr(out, "E_PARAM_PATH") != NULL,
			      label);
			if (n_dseen < 200)
				snprintf(dseen[n_dseen++], 64, "%.63s", cmd);
		} else if (strcmp(want, "GCC") == 0) {
			CHECK(run(t, args_json, &out, &ok) == AI_OK && !ok &&
			      out && strstr(out, "E_PARAM_GCC_ARGS") != NULL,
			      label);
			if (n_dseen < 200)
				snprintf(dseen[n_dseen++], 64, "%.63s", cmd);
		} else {
			CHECK(0, "unknown want in tsv");
		}
		free(out);
	}
	fclose(fp);

	/* 覆盖：每条 R 命令必须有至少一条安全形态；统计有危险形态的 R 命令 */
	{
		int r_total = 0;
		int r_danger = 0;
		int missing = 0;
		int j;

		for (j = 0; j < t->exec_cmd_count; j++) {
			const struct tool_exec_cmd *c = &t->exec_cmds[j];

			if (!c->risk || strcmp(c->risk, "R") != 0)
				continue;
			r_total++;
			if (!name_in(rseen, n_rseen, c->command)) {
				printf("FAIL: R 命令缺安全用例: %s\n",
				       c->command);
				missing++;
			}
			if (name_in(dseen, n_dseen, c->command))
				r_danger++;
		}
		CHECK(missing == 0, "52 条 R 命令全部有安全只读用例");
		printf("STATS: R_total=%d R_with_danger=%d cases=%d "
		       "R_safe_seen=%d danger_seen=%d\n",
		       r_total, r_danger, ncases, n_rseen, n_dseen);
		CHECK(r_total == 52, "R 命令总数 52");
		CHECK(r_danger >= 20, "至少 20 条 R 命令有危险形态用例");
	}

	/* 正向只读调用 */
	{
		char *out = NULL;
		int ok = 0;

		CHECK(run(t, "{\"command\":\"ls\",\"args\":[\"/tmp\"]}",
			  &out, &ok) == AI_OK && ok, "正向 ls /tmp 成功");
		free(out);
		out = NULL;
		CHECK(run(t, "{\"command\":\"uname\",\"args\":[\"-a\"]}",
			  &out, &ok) == AI_OK && ok, "正向 uname -a 成功");
		free(out);
		out = NULL;
		CHECK(run(t, "{\"command\":\"id\",\"args\":[]}",
			  &out, &ok) == AI_OK && ok, "正向 id 成功");
		free(out);
		out = NULL;
		/* W72：curl -o /dev/null 是 R，且真实执行不被动态写面误拒 */
		CHECK(run(t, "{\"command\":\"curl\",\"args\":[\"-sS\","
			  "\"-o\",\"/dev/null\",\"file:///etc/hostname\"]}",
			  &out, &ok) == AI_OK && ok &&
		      out && strstr(out, "E_PARAM_PATH") == NULL,
		      "正向 curl -o /dev/null 成功（R，只读 sink）");
		free(out);
		out = NULL;
	}

	/* 正向动态写：W2 确认后仍保留能力（落点 /tmp，realpath 通过） */
	{
		char *out = NULL;
		int ok = 0;
		char *body;

		unlink("/tmp/w69-risk-sort");
		CHECK(run(t, "{\"command\":\"sort\",\"args\":[\"-o\","
			  "\"/tmp/w69-risk-sort\"],\"input\":\"b\\na\\n\"}",
			  &out, &ok) == AI_OK && ok,
		      "正向 sort -o /tmp 成功（W2 能力保留）");
		body = read_all("/tmp/w69-risk-sort");
		CHECK(body && strcmp(body, "a\nb\n") == 0,
		      "sort -o 输出内容正确");
		free(body);
		free(out);
		out = NULL;
		unlink("/tmp/w69-risk-uniq-in");
		unlink("/tmp/w69-risk-uniq-out");
		CHECK(run(t, "{\"command\":\"tee\",\"args\":[\"/tmp/"
			  "w69-risk-uniq-in\"],\"input\":\"a\\na\\nb\\n\"}",
			  &out, &ok) == AI_OK && ok, "uniq 前置输入写入");
		free(out);
		out = NULL;
		CHECK(run(t, "{\"command\":\"uniq\",\"args\":[\"/tmp/"
			  "w69-risk-uniq-in\",\"/tmp/w69-risk-uniq-out\"]}",
			  &out, &ok) == AI_OK && ok,
		      "正向 uniq 输入 输出 成功（W2 能力保留）");
		body = read_all("/tmp/w69-risk-uniq-out");
		CHECK(body && strcmp(body, "a\nb\n") == 0,
		      "uniq 输出内容正确");
		free(body);
		free(out);
		unlink("/tmp/w69-risk-sort");
		unlink("/tmp/w69-risk-uniq-in");
		unlink("/tmp/w69-risk-uniq-out");
	}

	tool_registry_free(&reg);
	printf("\n%s\n", g_fail ? "test_exec_risk_matrix: FAIL" :
			  "test_exec_risk_matrix: ALL PASS");
	return g_fail ? 1 : 0;
}
