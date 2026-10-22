/*
 * cmd_lang.c - lang REPL 命令：显示/切换界面语言（zh|en）
 *
 * 用法：
 *   lang        显示当前语言
 *   lang zh     切换中文（写回 model.toml [ui] lang，持久化）
 *   lang en     切换英文（写回 model.toml [ui] lang，持久化）
 *
 * 切换即时生效（tr() 下一次查询即新语言）；持久化经 ai_config_save
 * 原子写回 model.toml。切换完成提示固定双语输出——保证用户在任何
 * 语言状态下都能看懂如何切回。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ai_shell.h"
#include "ai_commands.h"
#include "ai_lang.h"

int cmd_lang(void *shell_ptr, int argc, char **argv)
{
	struct ai_shell *shell = (struct ai_shell *)shell_ptr;

	if (argc < 2) {
		printf(tr(TR_LANG_CURRENT), lang_get());
		return AI_OK;
	}

	if (strcmp(argv[1], AI_LANG_ZH) != 0 &&
	    strcmp(argv[1], AI_LANG_EN) != 0) {
		printf(tr(TR_LANG_INVALID), argv[1]);
		return AI_ERR_INVALID_ARG;
	}

	/* 切换运行时语言 */
	lang_set(argv[1]);

	/* 持久化写回 model.toml [ui] lang */
	if (shell && shell->config) {
		char *dup = strdup(argv[1]);

		if (dup) {
			free(shell->config->ui.lang);
			shell->config->ui.lang = dup;
		}
		if (ai_config_save(shell->config) != AI_OK)
			printf("%s", tr(TR_LANG_SAVE_FAIL));
	}

	/* 双语固定输出（切换去向语言优先展示） */
	printf("%s", tr(TR_LANG_SWITCHED));
	return AI_OK;
}
