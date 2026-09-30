/*
 * cmd_config.c - config 命令实现
 *
 * 查看和修改运行时配置参数。
 * 既有命令保留：config get <key>（config_dir/model_count）。
 * UI Phase 扩展：
 *   config set ctx_len <N>       上下文 token 预算（热调，持久化 [ui]）
 *   config set max_tokens <N>    单次生成上限（热调，持久化 [ui]）
 *   config set stream on|off     流式开关
 *   config set local_api native|v1
 *                                本地通道协议（原生 /api/chat 或 /v1）
 *   config set color on|off / verbose on|off / session <name>
 *   config show                  UI 参数 + usage 真值 + ctx 预算百分比
 *
 * 修改即写回 model.toml [ui] 段（ai_config_save），重启后保持。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "ai_shell.h"
#include "ai_ui.h"
#include "ai_config.h"
#include "local/ollama_native.h"

/* config set 的布尔键表 */
struct bool_key {
	const char *key;
	int *slot;              /* 指向 ui 配置内的开关 */
};

/* 打印一段 "标签: 值"（颜色关闭时零转义） */
static void show_line(const struct ai_shell *shell, const char *label,
		      const char *fmt, ...)
{
	va_list ap;

	printf("  %s%s%s", ui_c(shell->config->ui.color, UI_C_DIM), label,
	       ui_c(shell->config->ui.color, UI_C_RESET));
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

/* config show - UI 参数 + usage 统计 + ctx 预算 */
static void do_show(struct ai_shell *shell)
{
	const struct ai_config *cfg = shell->config;
	const struct ai_runtime *rt = &shell->runtime;
	int color = cfg->ui.color;
	char buf_in[24], buf_out[24], buf_total[24], buf_ctx[24];
	long session_total;
	int pct;

	printf("%sconfig / UI%s\n", ui_c(color, UI_C_CYAN),
	       ui_c(color, UI_C_RESET));
	show_line(shell, "模型        ", "%s（默认 %s）",
		  rt->current_model ? rt->current_model : "(未加载)",
		  cfg->default_model ? cfg->default_model : "(未设置)");
	show_line(shell, "ctx_len     ", "%d", cfg->ui.ctx_len);
	show_line(shell, "max_tokens  ", "%d", cfg->ui.max_tokens);
	show_line(shell, "stream      ", "%s", cfg->ui.stream ? "on" : "off");
	show_line(shell, "local_api   ", "%s",
		  cfg->ui.local_native ? "native (/api/chat)" : "v1 (/v1)");
	show_line(shell, "color       ", "%s", cfg->ui.color ? "on" : "off");
	show_line(shell, "verbose     ", "%s", cfg->ui.verbose ? "on" : "off");
	show_line(shell, "session     ", "%s", cfg->ui.session);

	/* usage：优先服务端真值，估算兜底（标记标注来源） */
	ui_fmt_tokens(buf_in, sizeof(buf_in), rt->token_last_in);
	ui_fmt_tokens(buf_out, sizeof(buf_out), rt->token_last_out);
	ui_fmt_tokens(buf_total, sizeof(buf_total),
		      (long)rt->token_session_in + rt->token_session_out);
	ui_fmt_tokens(buf_ctx, sizeof(buf_ctx), cfg->ui.ctx_len);
	session_total = (long)rt->token_session_in + rt->token_session_out;
	pct = ui_ctx_percent(session_total, cfg->ui.ctx_len);

	printf("  %susage%s\n", ui_c(color, UI_C_CYAN), ui_c(color, UI_C_RESET));
	printf("  上次: %s in / %s out %s| 会话累计: %s tok"
	       " | ctx 预算 %s%d%%%s（%s / %s）\n",
	       buf_in, buf_out,
	       rt->usage_is_real ? "" : "(估算) ",
	       buf_total,
	       pct > 80 ? ui_c(color, UI_C_YELLOW) : "",
	       pct, pct > 80 ? ui_c(color, UI_C_RESET) : "",
	       buf_total, buf_ctx);
}

int cmd_config(void *shell_ptr, int argc, char **argv)
{
	struct ai_shell *shell = (struct ai_shell *)shell_ptr;
	struct ai_ui_config *ui = &shell->config->ui;

	if (argc < 2) {
		printf("Usage: config <get|set|show> [key] [value]\n");
		return AI_ERR_INVALID_ARG;
	}

	if (strcmp(argv[1], "get") == 0) {
		if (argc < 3) {
			printf("Usage: config get <key>\n");
			printf("Available keys:\n");
			printf("  config_dir  - Configuration directory\n");
			printf("  model_count - Number of configured models\n");
			return AI_ERR_INVALID_ARG;
		}

		if (strcmp(argv[2], "config_dir") == 0) {
			printf("%s\n", shell->config->config_dir);
		} else if (strcmp(argv[2], "model_count") == 0) {
			printf("%d\n", shell->config->model_count);
		} else {
			printf("Unknown key: %s\n", argv[2]);
			return AI_ERR_NOT_FOUND;
		}
		return AI_OK;

	} else if (strcmp(argv[1], "show") == 0) {
		do_show(shell);
		return AI_OK;

	} else if (strcmp(argv[1], "set") == 0) {
		int dirty = 0;
		int ret = AI_OK;

		if (argc < 4) {
			printf("Usage: config set <key> <value>\n");
			printf("Keys: ctx_len max_tokens stream local_api "
			       "color verbose session\n");
			return AI_ERR_INVALID_ARG;
		}

		if (strcmp(argv[2], "ctx_len") == 0) {
			int v = atoi(argv[3]);

			if (v <= 0) {
				printf("config: ctx_len 需为正整数\n");
				return AI_ERR_INVALID_ARG;
			}
			/* 本地原生通道：按模型实际上限钳制（/api/show，
			 * 探测失败或云端模型不钳制） */
			if (shell->runtime.model_provider_type &&
			    shell->runtime.model_name &&
			    strcmp(shell->runtime.model_provider_type,
				   "local") == 0 &&
			    ui->local_native) {
				int cap = ollama_native_clamp_ctx(
					shell->runtime.model_base_url,
					shell->runtime.model_name, v);

				if (cap < v) {
					printf("config: 模型 %s 窗口上限 %d，"
					       "ctx_len %d 被钳制为 %d\n",
					       shell->runtime.model_name,
					       cap, v, cap);
					v = cap;
				}
			}
			ui->ctx_len = v;
			printf("ctx_len = %d\n", v);
			dirty = 1;
		} else if (strcmp(argv[2], "max_tokens") == 0) {
			int v = atoi(argv[3]);

			if (v <= 0 || v > 131072) {
				printf("config: max_tokens 需在 1-131072 之间\n");
				return AI_ERR_INVALID_ARG;
			}
			ui->max_tokens = v;
			printf("max_tokens = %d\n", v);
			dirty = 1;
		} else if (strcmp(argv[2], "stream") == 0) {
			int on = (strcmp(argv[3], "on") == 0 ||
				  strcmp(argv[3], "true") == 0 ||
				  strcmp(argv[3], "1") == 0);
			int off = (strcmp(argv[3], "off") == 0 ||
				   strcmp(argv[3], "false") == 0 ||
				   strcmp(argv[3], "0") == 0);

			if (!on && !off) {
				printf("config: stream 取值 on|off\n");
				return AI_ERR_INVALID_ARG;
			}
#ifndef CONFIG_AI_STREAM_MODE
			/* 编译开关未编入流式：如实拒绝，不静默假开 */
			if (on) {
				printf("config: stream 未编译进本二进制"
				       "（CONFIG_AIKERNEL_STREAM_MODE=n），"
				       "保持 off\n");
				return AI_ERR_INVALID_ARG;
			}
#endif
			ui->stream = on;
			printf("stream = %s\n", on ? "on" : "off");
			dirty = 1;
		} else if (strcmp(argv[2], "local_api") == 0) {
			if (strcmp(argv[3], "native") == 0) {
				ui->local_native = 1;
			} else if (strcmp(argv[3], "v1") == 0) {
				ui->local_native = 0;
			} else {
				printf("config: local_api 取值 native|v1\n");
				return AI_ERR_INVALID_ARG;
			}
			printf("local_api = %s\n",
			       ui->local_native ? "native" : "v1");
			dirty = 1;
		} else if (strcmp(argv[2], "color") == 0 ||
			   strcmp(argv[2], "verbose") == 0) {
			int on = (strcmp(argv[3], "on") == 0 ||
				  strcmp(argv[3], "true") == 0 ||
				  strcmp(argv[3], "1") == 0);
			int off = (strcmp(argv[3], "off") == 0 ||
				   strcmp(argv[3], "false") == 0 ||
				   strcmp(argv[3], "0") == 0);

			if (!on && !off) {
				printf("config: %s 取值 on|off\n", argv[2]);
				return AI_ERR_INVALID_ARG;
			}
			if (argv[2][0] == 'c')
				ui->color = on;
			else
				ui->verbose = on;
			printf("%s = %s\n", argv[2], on ? "on" : "off");
			dirty = 1;
		} else if (strcmp(argv[2], "session") == 0) {
			if (!ui_session_valid_name(argv[3])) {
				printf("config: 非法会话名 '%s'\n", argv[3]);
				return AI_ERR_INVALID_ARG;
			}
			{
				char *dup = strdup(argv[3]);

				if (!dup)
					return AI_ERR_MEMORY;
				free(ui->session);
				ui->session = dup;
			}
			printf("session = %s（%d 条历史消息）\n", argv[3],
			       ui_session_count(argv[3]));
			dirty = 1;
		} else {
			printf("Unknown key: %s\n", argv[2]);
			ret = AI_ERR_NOT_FOUND;
		}

		if (dirty)
			ai_config_save(shell->config);
		return ret;

	} else {
		printf("Usage: config <get|set|show> [key] [value]\n");
		return AI_ERR_INVALID_ARG;
	}
}
