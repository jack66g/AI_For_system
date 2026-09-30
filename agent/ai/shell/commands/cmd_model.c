/*
 * cmd_model.c - model 命令实现
 *
 * 管理 AI 模型：
 *   model add <name>    - 交互式添加新模型
 *   model list          - 列出所有模型
 *   model use <name>    - 切换当前模型（local/cloud 为关键字，
 *                         分别切换到本地/云端 Provider）
 *   model remove <name> - 删除模型
 *   model test [name]   - 模型连通性测试（test local 探测本地服务）
 *
 * 本地/云端切换说明：
 *   `model use local` 把 model.toml [local] 段（本地 Provider 配置）
 *   同步为 [models.local] 镜像条目并设为默认模型，随后调用
 *   local_provider_configure() 应用参数（立即生效）；
 *   `model use cloud` 切回第一个 provider_type 为 openai_compatible
 *   的模型。聊天数据路径统一走 Communication Layer（runtime 侧），
 *   本地后端为 runtime/communication/backend/local_backend.c。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_shell.h"
#include "ai_runtime.h"
#include "ai_config.h"
#include "communication/communication.h"
#include "local/local_chat.h"

/* 前向声明本地 Provider 的配置入口（名称约定，非 ops 虚接口） */
void local_provider_configure(struct ai_provider *provider,
			      const char *model_name,
			      const char *base_url,
			      const char *api_key,
			      int timeout_ms);

/* ---- model add ---- */

static int model_add(struct ai_shell *shell, const char *name)
{
	char provider_type[AI_MAX_PROVIDER_NAME];
	char model_name[AI_MAX_MODEL_NAME];
	char base_url[AI_MAX_URL_LEN];
	char api_key[AI_MAX_KEY_LEN];
	char default_choice[16];
	int is_local;

	if (!name || !name[0]) {
		printf("Usage: model add <name>\n");
		printf("Example: model add deepseek\n");
		return AI_ERR_INVALID_ARG;
	}

	/* 检查是否已存在 */
	char **names;
	int count;
	ai_config_get_models(shell->config, &names, &count);
	for (int i = 0; i < count; i++) {
		if (strcmp(names[i], name) == 0) {
			printf("Model '%s' already exists.\n", name);
			for (int j = 0; j < count; j++)
				free(names[j]);
			free(names);
			return AI_ERR_GENERIC;
		}
		free(names[i]);
	}
	free(names);

	printf("\n=== Adding Model: %s ===\n\n", name);

	/* 询问 Provider 类型 */
	printf("Provider type (openai_compatible/local) [openai_compatible]: ");
	fflush(stdout);
	if (!fgets(provider_type, sizeof(provider_type), stdin))
		return AI_OK;
	provider_type[strcspn(provider_type, "\n")] = '\0';
	if (provider_type[0] == '\0')
		strcpy(provider_type, "openai_compatible");
	is_local = (strcmp(provider_type, "local") == 0);

	/* 询问模型名 */
	if (is_local)
		printf("Model name (e.g., llama3): ");
	else
		printf("Model name (e.g., deepseek-chat): ");
	fflush(stdout);
	if (!fgets(model_name, sizeof(model_name), stdin))
		return AI_OK;
	model_name[strcspn(model_name, "\n")] = '\0';
	if (model_name[0] == '\0') {
		printf("Model name is required.\n");
		return AI_ERR_INVALID_ARG;
	}

	/* 询问 Base URL */
	if (is_local)
		printf("Base URL (e.g., http://127.0.0.1:11434/v1): ");
	else
		printf("Base URL (e.g., https://api.deepseek.com/v1): ");
	fflush(stdout);
	if (!fgets(base_url, sizeof(base_url), stdin))
		return AI_OK;
	base_url[strcspn(base_url, "\n")] = '\0';
	if (base_url[0] == '\0') {
		printf("Base URL is required.\n");
		return AI_ERR_INVALID_ARG;
	}

	/* 询问 API Key（本地 Provider 通常无需认证） */
	if (is_local)
		printf("API Key (optional for local provider): ");
	else
		printf("API Key: ");
	fflush(stdout);
	if (!fgets(api_key, sizeof(api_key), stdin))
		return AI_OK;
	api_key[strcspn(api_key, "\n")] = '\0';
	if (api_key[0] == '\0' && !is_local) {
		printf("API Key is required.\n");
		return AI_ERR_INVALID_ARG;
	}

	/* 询问是否设为默认 */
	printf("Set as default? (y/n) [y]: ");
	fflush(stdout);
	if (!fgets(default_choice, sizeof(default_choice), stdin))
		return AI_OK;
	default_choice[strcspn(default_choice, "\n")] = '\0';

	/* 添加模型配置 */
	int ret = ai_config_add_model(shell->config, name,
				      provider_type, model_name,
				      base_url, api_key);
	if (ret != AI_OK) {
		printf("Failed to add model: %s\n", ai_error_string(ret));
		return ret;
	}

	/* 设置默认 */
	if (default_choice[0] == '\0' || default_choice[0] == 'y' ||
	    default_choice[0] == 'Y') {
		ai_config_set_default_model(shell->config, name);
		/* 更新 Runtime */
		ai_runtime_set_model(&shell->runtime, name);
		shell->first_run = 0;
	}

	/* 保存配置 */
	ai_config_save(shell->config);

	printf("\nModel '%s' added successfully.\n", name);
	return AI_OK;
}

/* ---- model list ---- */

static int model_list(struct ai_shell *shell)
{
	char **names;
	int count;
	int ret;
	int i;

	ret = ai_config_get_models(shell->config, &names, &count);
	if (ret != AI_OK) {
		printf("Failed to get models: %s\n", ai_error_string(ret));
		return ret;
	}

	if (count == 0) {
		printf("No models configured.\n");
		printf("Use 'model add <name>' to add a model.\n");
		return AI_OK;
	}

	const char *default_model = ai_config_get_default_model(shell->config);

	printf("\n");
	printf("  %-20s %-25s %-15s %s\n",
	       "Name", "Model", "Provider", "Default");
	printf("  %-20s %-25s %-15s %s\n",
	       "----", "-----", "--------", "-------");

	for (i = 0; i < count; i++) {
		char *provider_type = NULL;
		char *model_name = NULL;

		ai_config_get_model(shell->config, names[i],
				    &provider_type, &model_name,
				    NULL, NULL);

		int is_default = default_model &&
			strcmp(names[i], default_model) == 0;

		printf("  %-20s %-25s %-15s %s\n",
		       names[i],
		       model_name ? model_name : "-",
		       provider_type ? provider_type : "-",
		       is_default ? "[*]" : "");

		free(provider_type);
		free(model_name);
	}

	printf("\n");

	for (i = 0; i < count; i++)
		free(names[i]);
	free(names);

	return AI_OK;
}

/* ---- model use local ---- */

static int model_use_local(struct ai_shell *shell)
{
	int enabled, timeout_ms;
	char *base_url = NULL;
	char *model = NULL;
	char *api_key = NULL;
	struct ai_provider *provider;
	int ret;

	ret = ai_config_get_local(shell->config, &enabled, &base_url,
				  &model, &timeout_ms, &api_key);
	if (ret != AI_OK) {
		printf("Failed to read [local] config: %s\n",
		       ai_error_string(ret));
		return ret;
	}

	if (!enabled) {
		printf("Local provider is disabled.\n");
		printf("Set 'enabled = true' in the [local] section of "
		       "model.toml first.\n");
		ret = AI_ERR_CONFIG;
		goto out;
	}

	if (!base_url[0] || !model[0]) {
		printf("Local provider is not configured.\n");
		printf("Set base_url/model in the [local] section of "
		       "model.toml.\n");
		ret = AI_ERR_CONFIG;
		goto out;
	}

	/*
	 * 同步 [models.local] 镜像条目：
	 * Runtime（ai_runtime_set_model）只认 model.toml 的模型条目，
	 * 因此把 [local] 段的当前值镜像为名为 "local" 的条目。
	 */
	{
		char *ptype = NULL;

		ai_config_get_model(shell->config, "local",
				    &ptype, NULL, NULL, NULL);
		if (ptype && strcmp(ptype, "local") != 0) {
			printf("Model 'local' already exists with provider "
			       "type '%s'.\n", ptype);
			printf("Rename or remove it before switching to "
			       "local provider.\n");
			free(ptype);
			ret = AI_ERR_CONFIG;
			goto out;
		}
		free(ptype);

		/* 不存在时 remove 返回 AI_ERR_NOT_FOUND，属预期，忽略 */
		ai_config_remove_model(shell->config, "local");

		ret = ai_config_add_model(shell->config, "local", "local",
					  model, base_url,
					  api_key ? api_key : "");
		if (ret != AI_OK) {
			printf("Failed to sync local model entry: %s\n",
			       ai_error_string(ret));
			goto out;
		}
	}

	ai_config_set_default_model(shell->config, "local");
	shell->first_run = 0;

	/* 应用 [local] 参数到 Provider 实例（立即生效，含超时）；
	 * 本地 provider 未编入时注册表里没有 "local"，跳过即可 */
	provider = ai_provider_find(&shell->registry, "local");
#ifdef CONFIG_AI_LOCAL_PROVIDER
	if (provider)
		local_provider_configure(provider, model, base_url,
					 api_key, timeout_ms);
#else
	(void)provider;
	(void)model;
	(void)base_url;
	(void)api_key;
	(void)timeout_ms;
#endif

	/* 更新 Runtime 并建立 Provider 连接（配置校验级） */
	ret = ai_runtime_set_model(&shell->runtime, "local");
	if (ret != AI_OK) {
		printf("Warning: switched but failed to initialize: %s\n",
		       ai_error_string(ret));
	}

	/* 保存配置（持久化 [models.local] 与 [local] 段） */
	ai_config_save(shell->config);

	printf("Switched to local provider.\n");
	printf("  Base URL: %s\n", base_url);
	printf("  Model   : %s\n", model);
	printf("Tip: run 'model test local' to verify the local service.\n");
	ret = AI_OK;

out:
	free(base_url);
	free(model);
	free(api_key);
	return ret;
}

/* ---- model use cloud ---- */

static int model_use_cloud(struct ai_shell *shell)
{
	char **names;
	int count;
	const char *cloud_model = NULL;
	int ret;
	int i;

	ret = ai_config_get_models(shell->config, &names, &count);
	if (ret != AI_OK) {
		printf("Failed to get models: %s\n", ai_error_string(ret));
		return ret;
	}

	/* 找第一个云端（openai_compatible）模型 */
	for (i = 0; i < count && !cloud_model; i++) {
		char *ptype = NULL;

		ai_config_get_model(shell->config, names[i],
				    &ptype, NULL, NULL, NULL);
		if (ptype && strcmp(ptype, "openai_compatible") == 0)
			cloud_model = names[i];     /* 指向 names[i]，勿释放 */
		free(ptype);
	}

	if (!cloud_model) {
		printf("No cloud model configured.\n");
		printf("Use 'model add <name>' with provider type "
		       "openai_compatible first.\n");
		for (i = 0; i < count; i++)
			free(names[i]);
		free(names);
		return AI_ERR_NO_MODEL;
	}

	ai_config_set_default_model(shell->config, cloud_model);
	shell->first_run = 0;

	ret = ai_runtime_set_model(&shell->runtime, cloud_model);
	if (ret != AI_OK) {
		printf("Warning: switched but failed to initialize: %s\n",
		       ai_error_string(ret));
	}

	ai_config_save(shell->config);
	printf("Switched to cloud model '%s'.\n", cloud_model);

	/* names 数组整体释放（cloud_model 指向其中元素，最后统一 free） */
	for (i = 0; i < count; i++)
		free(names[i]);
	free(names);

	return AI_OK;
}

/* ---- model use ---- */

static int model_use(struct ai_shell *shell, const char *name)
{
	int ret;

	if (!name || !name[0]) {
		printf("Usage: model use <name>\n");
		printf("       model use local|cloud   (switch provider)\n");
		return AI_ERR_INVALID_ARG;
	}

	/* 本地/云端切换关键字 */
	if (strcmp(name, "local") == 0)
		return model_use_local(shell);
	if (strcmp(name, "cloud") == 0)
		return model_use_cloud(shell);

	/* 验证模型存在 */
	char **names;
	int count;
	int found = 0;

	ai_config_get_models(shell->config, &names, &count);
	for (int i = 0; i < count; i++) {
		if (strcmp(names[i], name) == 0) {
			found = 1;
		}
		free(names[i]);
	}
	free(names);

	if (!found) {
		printf("Model '%s' not found.\n", name);
		printf("Hint: use 'model use local' or 'model use cloud' to "
		       "switch provider.\n");
		return AI_ERR_NOT_FOUND;
	}

	/* 设置默认模型 */
	ret = ai_config_set_default_model(shell->config, name);
	if (ret != AI_OK) {
		printf("Failed to set default model: %s\n",
		       ai_error_string(ret));
		return ret;
	}

	/* 更新 Runtime */
	ret = ai_runtime_set_model(&shell->runtime, name);
	if (ret != AI_OK) {
		printf("Warning: Model set but failed to initialize: %s\n",
		       ai_error_string(ret));
	}

	/* 保存配置 */
	ai_config_save(shell->config);

	printf("Switched to model '%s'.\n", name);
	return AI_OK;
}

/* ---- model remove ---- */

static int model_remove(struct ai_shell *shell, const char *name)
{
	int ret;

	if (!name || !name[0]) {
		printf("Usage: model remove <name>\n");
		return AI_ERR_INVALID_ARG;
	}

	ret = ai_config_remove_model(shell->config, name);
	if (ret != AI_OK) {
		printf("Failed to remove model: %s\n", ai_error_string(ret));
		return ret;
	}

	/* 如果删除的是当前使用的模型，清除 Runtime */
	if (shell->runtime.current_model &&
	    strcmp(shell->runtime.current_model, name) == 0) {
		shell->runtime.provider = NULL;
		free(shell->runtime.current_model);
		shell->runtime.current_model = NULL;

		/* 尝试切换到新默认模型 */
		const char *new_default =
			ai_config_get_default_model(shell->config);
		if (new_default)
			ai_runtime_set_model(&shell->runtime, new_default);
	}

	/* 保存配置 */
	ai_config_save(shell->config);

	printf("Model '%s' removed.\n", name);
	return AI_OK;
}

/* ---- model test ---- */

/*
 * extract_host - 从 URL 提取主机名（去掉 scheme/路径/端口）
 * 返回: 0 成功，-1 格式错误
 */
static int extract_host(const char *url, char *host, size_t hostlen)
{
	const char *p = strstr(url, "://");
	const char *slash;
	size_t n;
	char *colon;

	p = p ? p + 3 : url;
	slash = strchr(p, '/');
	n = slash ? (size_t)(slash - p) : strlen(p);
	if (n == 0 || n >= hostlen)
		return -1;

	memcpy(host, p, n);
	host[n] = '\0';

	colon = strchr(host, ':');
	if (colon)
		*colon = '\0';

	return 0;
}

static int model_test(struct ai_shell *shell, const char *name)
{
	int ret;

	if (!name || !name[0]) {
		/* 缺省测试当前模型 */
		name = shell->runtime.current_model;
		if (!name)
			name = ai_config_get_default_model(shell->config);
		if (!name) {
			printf("No model selected.\n");
			printf("Usage: model test <name>|local\n");
			return AI_ERR_NO_MODEL;
		}
	}

	if (strcmp(name, "local") == 0) {
		/* 探测 [local] 段配置的本地服务 */
		char *base_url = NULL;

#ifndef CONFIG_AI_LOCAL_PROVIDER
		(void)base_url;
		printf("Local provider is not compiled in "
		       "(CONFIG_AIKERNEL_LOCAL_PROVIDER=n).\n");
		return AI_ERR_NO_PROVIDER;
#else
		ai_config_get_local(shell->config, NULL, &base_url,
				    NULL, NULL, NULL);
		if (!base_url || !base_url[0]) {
			printf("Local provider is not configured.\n");
			free(base_url);
			return AI_ERR_CONFIG;
		}

		printf("Testing local service at %s... ", base_url);
		fflush(stdout);

		char *err = NULL;
		ret = local_chat_probe_endpoint(base_url, &err);
		if (ret == AI_OK) {
			printf("OK\n");
		} else {
			printf("FAILED\n");
			if (err) {
				printf("  %s\n", err);
				free(err);
			}
		}
		free(base_url);
		return ret;
#endif
	}

	/* 按模型条目测试 */
	{
		char *ptype = NULL;
		char *purl = NULL;

		ret = ai_config_get_model(shell->config, name, &ptype,
					  NULL, &purl, NULL);
		if (ret != AI_OK) {
			printf("Model '%s' not found.\n", name);
			return AI_ERR_NOT_FOUND;
		}

		if (ptype && strcmp(ptype, "local") == 0 && purl) {
#ifndef CONFIG_AI_LOCAL_PROVIDER
			(void)purl;
			printf("Local provider is not compiled in "
			       "(CONFIG_AIKERNEL_LOCAL_PROVIDER=n).\n");
			ret = AI_ERR_NO_PROVIDER;
#else
			printf("Testing local service at %s... ", purl);
			fflush(stdout);

			char *err = NULL;
			ret = local_chat_probe_endpoint(purl, &err);
			if (ret == AI_OK) {
				printf("OK\n");
			} else {
				printf("FAILED\n");
				if (err) {
					printf("  %s\n", err);
					free(err);
				}
			}
#endif
		} else if (ptype &&
			   strcmp(ptype, "openai_compatible") == 0 && purl) {
			char host[AI_MAX_URL_LEN];

			if (extract_host(purl, host, sizeof(host)) != 0) {
				printf("Invalid base_url: %s\n", purl);
				ret = AI_ERR_CONFIG;
			} else {
				printf("Testing cloud API host '%s'... ",
				       host);
				fflush(stdout);

				/* 通信层测试：DNS + TLS 握手 + HTTPS GET */
				ret = communication_test(host);
				if (ret == AI_OK)
					printf("OK\n");
				else
					printf("FAILED (%s)\n",
					       ai_error_string(ret));
			}
		} else {
			printf("Provider type '%s' does not support "
			       "connectivity test.\n",
			       ptype ? ptype : "(unknown)");
			ret = AI_ERR_INVALID_ARG;
		}

		free(ptype);
		free(purl);
		return ret;
	}
}

/* ---- model 命令入口 ---- */

int cmd_model(void *shell_ptr, int argc, char **argv)
{
	struct ai_shell *shell = (struct ai_shell *)shell_ptr;

	if (argc < 2) {
		printf("Usage: model <add|list|use|remove|test> [args]\n");
		printf("       model use local|cloud to switch provider\n");
		printf("       model test [name|local] to check connectivity\n");
		return AI_ERR_INVALID_ARG;
	}

	if (strcmp(argv[1], "add") == 0) {
		return model_add(shell, argc > 2 ? argv[2] : NULL);

	} else if (strcmp(argv[1], "list") == 0) {
		return model_list(shell);

	} else if (strcmp(argv[1], "use") == 0) {
		return model_use(shell, argc > 2 ? argv[2] : NULL);

	} else if (strcmp(argv[1], "remove") == 0) {
		return model_remove(shell, argc > 2 ? argv[2] : NULL);

	} else if (strcmp(argv[1], "test") == 0) {
		return model_test(shell, argc > 2 ? argv[2] : NULL);

	} else {
		printf("Unknown model subcommand: %s\n", argv[1]);
		printf("Available: add, list, use, remove, test\n");
		return AI_ERR_NOT_FOUND;
	}
}
