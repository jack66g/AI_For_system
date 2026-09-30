/*
 * cmd_status.c - status 命令实现
 *
 * 显示当前 Runtime 状态、模型配置、Provider 信息。
 * 同时读取 /proc/aikernel 获取内核 AI 接口状态。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ai_shell.h"

int cmd_status(void *shell_ptr, int argc, char **argv)
{
	struct ai_shell *shell = (struct ai_shell *)shell_ptr;
	const char *default_model;
	char **model_names = NULL;
	int model_count = 0;
	int i;

	(void)argc;
	(void)argv;

	printf("\n=== AIKernel Status ===\n\n");

	/* Kernel AI Interface 状态 */
	printf("Kernel:\n");
	if (access("/proc/aikernel", F_OK) == 0) {
		FILE *fp = fopen("/proc/aikernel", "r");
		if (fp) {
			char buf[256];
			while (fgets(buf, sizeof(buf), fp)) {
				/* 去除尾部换行 */
				size_t len = strlen(buf);
				if (len > 0 && buf[len - 1] == '\n')
					buf[len - 1] = '\0';
				if (buf[0])
					printf("  %s\n", buf);
			}
			fclose(fp);
		}
	} else {
		printf("  Kernel AI Interface: Not Available\n");
	}
	printf("\n");

	/* Runtime 状态 */
	printf("Runtime:\n");
	switch (shell->runtime.state) {
	case AI_SESSION_IDLE:
		printf("  State: IDLE\n");
		break;
	case AI_SESSION_CHATTING:
		printf("  State: CHATTING\n");
		break;
	case AI_SESSION_ERROR:
		printf("  State: ERROR\n");
		break;
	}

	if (shell->runtime.current_model)
		printf("  Current Model: %s\n", shell->runtime.current_model);
	else
		printf("  Current Model: (none)\n");

	printf("  Token Used: %d\n", shell->runtime.token_used);

	/* 配置信息 */
	printf("\nConfiguration:\n");
	ai_config_get_models(shell->config, &model_names, &model_count);
	printf("  Models Configured: %d\n", model_count);

	default_model = ai_config_get_default_model(shell->config);
	if (default_model)
		printf("  Default Model: %s\n", default_model);
	else
		printf("  Default Model: (none)\n");

	/* 模型列表 */
	if (model_count > 0) {
		printf("\n  %-20s %s\n", "Model Name", "Default");
		printf("  %-20s %s\n", "----------", "-------");
		for (i = 0; i < model_count; i++) {
			int is_default = default_model &&
				strcmp(model_names[i], default_model) == 0;
			printf("  %-20s %s\n", model_names[i],
			       is_default ? "[*]" : "");
		}
	}

	/* Provider 信息 */
	printf("\nProviders:\n");
	struct ai_provider *p;
	for (p = shell->registry.head; p; p = p->next) {
		const char *state_str = "unknown";
		switch (p->state) {
		case AI_PROVIDER_UNINITIALIZED: state_str = "uninitialized"; break;
		case AI_PROVIDER_READY:         state_str = "ready"; break;
		case AI_PROVIDER_ERROR:         state_str = "error"; break;
		case AI_PROVIDER_DISCONNECTED:  state_str = "disconnected"; break;
		}
		printf("  %-25s [%s] %s\n", p->display_name, state_str,
		       p->type == AI_PROVIDER_CLOUD ? "(cloud)" : "(local)");
	}

	/* 通道编译实态（按 Kconfig 开关如实显示，不虚标） */
	printf("\nChannels (compiled in):\n");
#ifdef CONFIG_AI_CLOUD_PROVIDER
	printf("  cloud       : built-in (OpenAI compatible");
#ifdef CONFIG_AI_STREAM_MODE
	printf(" + SSE streaming)\n");
#else
	printf(")\n");
#endif
#else
	printf("  cloud       : not compiled (CONFIG_AIKERNEL_CLOUD_PROVIDER=n)\n");
#endif
#ifdef CONFIG_AI_LOCAL_PROVIDER
	printf("  local       : built-in (Ollama / OpenAI-compatible)\n");
#else
	printf("  local       : not compiled (CONFIG_AIKERNEL_LOCAL_PROVIDER=n)\n");
#endif
#ifdef CONFIG_AI_STREAM_MODE
	printf("  streaming   : built-in (delta 逐段实时交付; config stream=%s)\n",
	       shell->config->ui.stream ? "on" : "off");
#else
	printf("  streaming   : not compiled (CONFIG_AIKERNEL_STREAM_MODE=n)\n");
#endif
	printf("  memory(SME) : external service 127.0.0.1:8760 (启用与否见工具描述)\n");
	printf("  kernel link : %s\n",
	       access("/proc/aikernel", F_OK) == 0 ?
	       "/proc/aikernel present" : "host kernel without AIKernel (reserved)");

	printf("\n");

	/* 释放 */
	for (i = 0; i < model_count; i++)
		free(model_names[i]);
	free(model_names);

	return AI_OK;
}
