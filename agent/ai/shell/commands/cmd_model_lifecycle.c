// SPDX-License-Identifier: GPL-2.0
/*
 * cmd_model_lifecycle.c - aik model 生命周期子命令（W77d 契约 C）
 *
 *   model catalog                 列出目录全量条目
 *   model recommend               硬件盘点 → top-3 推荐
 *   model install <name> [--bench] D2：多 GB 下载确认 → pull+验证+注册
 *   model remove <name>           D2：卸载（活动模型二次确认）
 *   model switch cloud|local|<name>  切 [default]，记录 model-state.json
 *   model rollback                恢复上一状态
 *   model benchmark [name]        N=3 固定提示 → p50/p95/tok-s
 *
 * 交互确认只在本层（人类入口）；能力总线工具（executor model 通道）
 * 走 ai_lease_gate D2，非 TTY 且未预授权时本层拒绝 --yes 之外的执行。
 * 核心逻辑全部在 model_lifecycle.c（单源）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_runtime.h"
#include "ai_config.h"
#include "model_lifecycle.h"

/* 读一行 y/N（非 TTY 时返回 -1 要求 --yes） */
static int mlc_confirm(const char *prompt)
{
	char buf[32];

	if (!isatty(STDIN_FILENO))
		return -1;
	printf("%s [y/N]: ", prompt);
	fflush(stdout);
	if (!fgets(buf, sizeof(buf), stdin))
		return 0;
	return buf[0] == 'y' || buf[0] == 'Y';
}

static int sub_catalog(struct ai_shell *shell, int argc, char **argv)
{
	struct aik_ml_entry cat[AIK_ML_CATALOG_MAX];
	char *err = NULL;
	int n, i, j;

	(void)shell;
	(void)argc;
	(void)argv;
	n = aik_ml_catalog_load(NULL, cat, AIK_ML_CATALOG_MAX, &err);
	if (n <= 0) {
		printf("model catalog: %s\n", err ? err : "no entries");
		free(err);
		return AI_ERR_CONFIG;
	}
	printf("catalog: %s (%d entries)\n\n", aik_ml_catalog_path(), n);
	printf("  %-18s %-28s %6s %10s %7s %6s  %s\n",
	       "NAME", "OLLAMA_REF", "PARAMS", "CTX", "DISK", "RAM", "TAGS");
	printf("  %-18s %-28s %6s %10s %7s %6s  %s\n",
	       "----", "-----------", "------", "---", "----", "---", "----");
	for (i = 0; i < n; i++) {
		const struct aik_ml_entry *e = &cat[i];

		printf("  %-18s %-28s %5gB %8lldK %5gGB %4dGB  ",
		       e->name, e->ollama_ref, e->params_b, e->ctx_tokens / 1000,
		       e->disk_gb, e->ram_min_gb);
		for (j = 0; j < e->ntags; j++)
			printf("%s%s", j ? "," : "", e->tags[j]);
		printf("\n");
	}
	printf("\nwhy:\n");
	for (i = 0; i < n; i++)
		printf("  %-18s %s\n", cat[i].name, cat[i].why);
	printf("\nnotes:\n");
	for (i = 0; i < n; i++)
		if (cat[i].notes[0])
			printf("  %-18s %s\n", cat[i].name, cat[i].notes);
	return AI_OK;
}

static int sub_recommend(struct ai_shell *shell, int argc, char **argv)
{
	struct aik_ml_entry cat[AIK_ML_CATALOG_MAX];
	struct aik_ml_hw hw;
	struct aik_ml_scored top[AIK_ML_TOP_N];
	char *err = NULL;
	int n, cnt, i;

	(void)shell;
	(void)argc;
	(void)argv;
	n = aik_ml_catalog_load(NULL, cat, AIK_ML_CATALOG_MAX, &err);
	if (n <= 0) {
		printf("model recommend: %s\n", err ? err : "no entries");
		free(err);
		return AI_ERR_CONFIG;
	}
	aik_ml_hw_probe(&hw);
	printf("hardware: %lldMB RAM total / %lldMB avail, %lldMB disk free, %d cpus%s\n\n",
	       hw.mem_total_kb / 1024, hw.mem_avail_kb / 1024,
	       hw.disk_free_mb, hw.cpus,
	       hw.gpu ? ", dGPU" : "");
	cnt = aik_ml_recommend(cat, n, &hw, top, AIK_ML_TOP_N);
	if (cnt == 0) {
		printf("no catalog model fits this host (RAM/disk gates).\n");
		printf("See 'model catalog' for the full list.\n");
		return AI_OK;
	}
	printf("top-%d recommendations for this host:\n", cnt);
	for (i = 0; i < cnt; i++) {
		printf("\n  %d. %s  (%s)\n", i + 1, top[i].e->name,
		       top[i].e->ollama_ref);
		printf("     why : %s\n", top[i].e->why);
		printf("     fit : %s\n", top[i].reason);
		if (top[i].e->notes[0])
			printf("     note: %s\n", top[i].e->notes);
	}
	printf("\ninstall: aik model install <name>   (multi-GB download, asks confirmation)\n");
	return AI_OK;
}

static int sub_install(struct ai_shell *shell, int argc, char **argv)
{
	char *err = NULL;
	int rc, bench = 0;
	const char *name = NULL;
	int i;

	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--bench") == 0)
			bench = 1;
		else if (argv[i][0] != '-')
			name = argv[i];
	}
	if (!name) {
		printf("Usage: model install <name> [--bench]\n");
		return AI_ERR_INVALID_ARG;
	}

	if (isatty(STDIN_FILENO)) {
		char prompt[256];

		snprintf(prompt, sizeof(prompt),
			 "Download and install local model '%s' (multi-GB)",
			 name);
		if (mlc_confirm(prompt) != 1) {
			printf("install cancelled.\n");
			return AI_OK;
		}
	}

	rc = aik_ml_install(shell->config, name, 1, &err);
	if (rc != 0) {
		printf("install FAILED: %s\n", err ? err : "unknown");
		free(err);
		return AI_ERR_GENERIC;
	}
	free(err);
	printf("install OK. switch to it: aik model switch local\n");
	if (bench) {
		char bj[512];

		if (aik_ml_benchmark(shell->config, NULL, 0, bj,
				     sizeof(bj), &err) == 0)
			printf("bench: %s\n", bj);
		else
			printf("bench failed: %s\n", err ? err : "?");
	}
	return AI_OK;
}

static int sub_remove(struct ai_shell *shell, int argc, char **argv)
{
	char *err = NULL;
	int rc;

	if (argc < 3) {
		printf("Usage: model remove <name>\n");
		return AI_ERR_INVALID_ARG;
	}
	rc = aik_ml_remove(shell->config, argv[2], 0, &err);
	if (rc == AIK_ML_E_CONFIRM) {
		char prompt[256];

		free(err);
		snprintf(prompt, sizeof(prompt),
			 "'%s' is the ACTIVE local model; remove it", argv[2]);
		if (mlc_confirm(prompt) != 1) {
			printf("remove cancelled.\n");
			return AI_OK;
		}
		rc = aik_ml_remove(shell->config, argv[2], 1, &err);
	}
	if (rc != 0) {
		printf("remove FAILED: %s\n", err ? err : "unknown");
		free(err);
		return AI_ERR_GENERIC;
	}
	free(err);
	printf("removed '%s'; local provider disabled (cloud-first).\n",
	       argv[2]);
	return AI_OK;
}

static int sub_switch(struct ai_shell *shell, int argc, char **argv)
{
	char *err = NULL;

	if (argc < 3) {
		printf("Usage: model switch cloud|local|<name>\n");
		return AI_ERR_INVALID_ARG;
	}
	if (aik_ml_switch(shell->config, argv[2], &err) != 0) {
		printf("switch FAILED: %s\n", err ? err : "unknown");
		free(err);
		return AI_ERR_GENERIC;
	}
	free(err);
	/* 应用到运行时（与 model use 同路径） */
	if (ai_runtime_set_model(&shell->runtime,
				 shell->config->default_model) != AI_OK)
		printf("warning: switched config but runtime re-init failed\n");
	printf("switched default -> %s (previous saved; 'model rollback' to undo)\n",
	       shell->config->default_model);
	return AI_OK;
}

static int sub_rollback(struct ai_shell *shell, int argc, char **argv)
{
	char *err = NULL;

	(void)argc;
	(void)argv;
	if (aik_ml_rollback(shell->config, &err) != 0) {
		printf("rollback FAILED: %s\n", err ? err : "unknown");
		free(err);
		return AI_ERR_GENERIC;
	}
	free(err);
	if (ai_runtime_set_model(&shell->runtime,
				 shell->config->default_model) != AI_OK)
		printf("warning: rolled back config but runtime re-init failed\n");
	printf("rolled back default -> %s\n", shell->config->default_model);
	return AI_OK;
}

static int sub_benchmark(struct ai_shell *shell, int argc, char **argv)
{
	char *err = NULL;
	char bj[512];

	if (aik_ml_benchmark(shell->config, argc > 2 ? argv[2] : NULL, 0,
			     bj, sizeof(bj), &err) != 0) {
		printf("benchmark FAILED: %s\n", err ? err : "unknown");
		free(err);
		return AI_ERR_GENERIC;
	}
	free(err);
	printf("%s\n", bj);
	return AI_OK;
}

/*
 * cmd_model_lifecycle - 生命周期子命令分发
 * 返回: AI_OK 已处理；AI_ERR_NOT_FOUND 非本组子命令（交回 cmd_model）
 */
int cmd_model_lifecycle(void *shell_ptr, int argc, char **argv)
{
	struct ai_shell *shell = (struct ai_shell *)shell_ptr;

	if (argc < 2)
		return AI_ERR_NOT_FOUND;
	if (strcmp(argv[1], "catalog") == 0)
		return sub_catalog(shell, argc, argv);
	if (strcmp(argv[1], "recommend") == 0)
		return sub_recommend(shell, argc, argv);
	if (strcmp(argv[1], "install") == 0)
		return sub_install(shell, argc, argv);
	if (strcmp(argv[1], "remove") == 0)
		return sub_remove(shell, argc, argv);
	if (strcmp(argv[1], "switch") == 0)
		return sub_switch(shell, argc, argv);
	if (strcmp(argv[1], "rollback") == 0)
		return sub_rollback(shell, argc, argv);
	if (strcmp(argv[1], "benchmark") == 0)
		return sub_benchmark(shell, argc, argv);
	return AI_ERR_NOT_FOUND;
}
