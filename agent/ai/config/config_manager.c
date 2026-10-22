/*
 * config_manager.c - 配置管理器实现
 *
 * 管理 model.toml 和 provider.toml 的读写。
 * 采用简化的 TOML 解析器，仅支持所需格式。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "ai_config.h"

/* TOML 解析最大行长度 */
#define TOML_MAX_LINE  4096

/* ---- [local] 段默认值（本地 Provider） ---- */

#define LOCAL_DEFAULT_ENABLED     1
#define LOCAL_DEFAULT_BASE_URL    "http://127.0.0.1:11434/v1"
#define LOCAL_DEFAULT_MODEL       "llama3"
#define LOCAL_DEFAULT_TIMEOUT_MS  60000

/* ---- [ui] 段：布尔值解析（on/off/true/false/1/0），失败保持原值 ---- */

static int ui_parse_bool(const char *value, int cur)
{
	if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0 ||
	    strcasecmp(value, "yes") == 0 || strcasecmp(value, "on") == 0)
		return 1;
	if (strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0 ||
	    strcasecmp(value, "no") == 0 || strcasecmp(value, "off") == 0)
		return 0;
	return cur;
}

/* ---- 内部辅助函数 ---- */

/*
 * 获取用户配置目录路径
 * 返回: 静态缓冲区（不可 free）
 */
static const char *get_config_dir(void)
{
	static char dir[AI_PATH_MAX];
	const char *home;

	home = getenv("HOME");
	if (!home)
		home = "/tmp";

	snprintf(dir, sizeof(dir), "%s/.aikernel", home);
	return dir;
}

/*
 * 获取配置文件路径
 * （显式长度校验，避免 snprintf 截断告警）
 */
static void get_config_path(const char *filename, char *buf, size_t len)
{
	size_t dl = strlen(get_config_dir());
	size_t fl = strlen(filename);

	if (dl + 1 + fl + 1 > len)
		return;
	memcpy(buf, get_config_dir(), dl);
	buf[dl] = '/';
	memcpy(buf + dl + 1, filename, fl);
	buf[dl + 1 + fl] = '\0';
}

/*
 * 去除字符串首尾空白和引号
 */
static char *trim(char *str)
{
	char *end;

	if (!str || !*str)
		return str;

	/* 去除尾部空白 */
	end = str + strlen(str) - 1;
	while (end >= str && (*end == ' ' || *end == '\t' ||
	       *end == '\n' || *end == '\r'))
		*end-- = '\0';

	/* 去除首部空白 */
	while (*str == ' ' || *str == '\t')
		str++;

	/* 去除首尾引号 */
	end = str + strlen(str) - 1;
	if (*str == '"' && *end == '"' && end > str) {
		*end = '\0';
		str++;
	}

	return str;
}

/*
 * local_set_defaults - 填充 [local] 段默认值
 * 返回: AI_OK 成功，AI_ERR_MEMORY 分配失败（已回收已分配部分）
 */
static int local_set_defaults(struct ai_local_config *local)
{
	local->enabled = LOCAL_DEFAULT_ENABLED;
	local->timeout_ms = LOCAL_DEFAULT_TIMEOUT_MS;
	local->max_tokens = 0;          /* W20 修1：0=未显式配置（生效值走兜底链） */
	local->base_url = NULL;
	local->model = NULL;
	local->api_key = NULL;

	local->base_url = strdup(LOCAL_DEFAULT_BASE_URL);
	local->model = strdup(LOCAL_DEFAULT_MODEL);
	local->api_key = strdup("");

	if (!local->base_url || !local->model || !local->api_key) {
		free(local->base_url);
		free(local->model);
		free(local->api_key);
		local->base_url = NULL;
		local->model = NULL;
		local->api_key = NULL;
		return AI_ERR_MEMORY;
	}

	return AI_OK;
}

/*
 * route_set_defaults - 填充 [route] 段默认值（W77 模型路由）
 */
static void route_set_defaults(struct ai_route_config *r)
{
	memset(r, 0, sizeof(*r));
	r->mode = AI_MODEL_ROUTE_AUTO;
	r->privacy = 0;
	r->prefer_local = 1;
	r->failover = 1;
	r->offline_intents = 1;
	r->local_ctx = AI_LOCAL_CTX_MAX;
	r->local_p95_ms = 8000;
	r->switch_budget_ms = 2000;
	r->probe_timeout_ms = 400;
	r->cloud_down_ttl_ms = 60000;
}

/*
 * ai_ui_set_defaults - 填充 [ui] 段默认值
 * 来源优先级最低层；TOML/环境变量/命令行依次覆盖。
 */
void ai_ui_set_defaults(struct ai_ui_config *ui)
{
	memset(ui, 0, sizeof(*ui));
	ui->ctx_len = UI_DEFAULT_CTX_LEN;
	ui->max_tokens = UI_DEFAULT_MAX_TOKENS;
	ui->stream = 1;
	ui->local_native = 1;
	ui->color = 1;
	ui->verbose = 0;
	ui->session = strdup(UI_DEFAULT_SESSION);
	ui->lang = strdup(UI_DEFAULT_LANG);
}

/*
 * ui_apply_env - 环境变量覆盖（优先级高于 TOML，低于命令行）
 * AIKERNEL_CTX / AIKERNEL_MAX_TOKENS：正整数生效，非法值忽略。
 */
static void ui_apply_env(struct ai_ui_config *ui)
{
	const char *v;

	v = getenv("AIKERNEL_CTX");
	if (v && v[0]) {
		long n = strtol(v, NULL, 10);

		if (n > 0)
			ui->ctx_len = (int)n;
	}
	v = getenv("AIKERNEL_MAX_TOKENS");
	if (v && v[0]) {
		long n = strtol(v, NULL, 10);

		if (n > 0)
			ui->max_tokens = (int)n;
	}
}

/* ---- 配置管理 API ---- */

struct ai_config *ai_config_init(void)
{
	struct ai_config *cfg;
	const char *dir;
	char path[AI_PATH_MAX];

	cfg = calloc(1, sizeof(*cfg));
	if (!cfg)
		return NULL;

	dir = get_config_dir();
	cfg->config_dir = strdup(dir);
	if (!cfg->config_dir) {
		free(cfg);
		return NULL;
	}

	/* 填充 [local] 段默认值 */
	if (local_set_defaults(&cfg->local) != AI_OK) {
		free(cfg->config_dir);
		free(cfg);
		return NULL;
	}

	/* 填充 [ui] 段默认值（终端 UI 参数） */
	ai_ui_set_defaults(&cfg->ui);

	/* 填充 [route] 段默认值（W77 模型路由） */
	route_set_defaults(&cfg->route);
	if (!cfg->ui.session || !cfg->ui.lang) {
		free(cfg->ui.session);
		free(cfg->ui.lang);
		free(cfg->config_dir);
		free(cfg->local.base_url);
		free(cfg->local.model);
		free(cfg->local.api_key);
		free(cfg);
		return NULL;
	}

	/* 创建配置目录（如不存在） */
	if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
		fprintf(stderr, "Warning: Cannot create config dir %s: %s\n",
			dir, strerror(errno));
	}

	/* 创建默认 provider.toml（如不存在） */
	get_config_path("provider.toml", path, sizeof(path));
	if (access(path, F_OK) != 0) {
		FILE *fp = fopen(path, "w");
		if (fp) {
			fprintf(fp,
				"# AIKernel Provider Configuration\n"
				"# Available provider types\n\n"
				"[providers]\n"
				"available = [\"openai_compatible\", \"local\"]\n\n"
				"[providers.openai_compatible]\n"
				"type = \"cloud\"\n"
				"description = \"OpenAI-compatible API provider\"\n"
				"supports = [\"chat\", \"stream\"]\n\n"
				"[providers.local]\n"
				"type = \"local\"\n"
				"description = \"Local model inference\"\n"
				"supports = [\"chat\", \"stream\"]\n");
			fclose(fp);
		}
	}

	return cfg;
}

static int parse_model_toml(struct ai_config *cfg)
{
	char path[AI_PATH_MAX];
	FILE *fp;
	char line[TOML_MAX_LINE];
	char current_section[256];
	char default_model_buf[256];
	int in_default = 0;
	int in_local = 0;
	int in_ui = 0;
	int in_routing = 0;
	int in_route = 0;
	int in_models = 0;
	struct ai_model_config *model = NULL;

	get_config_path("model.toml", path, sizeof(path));
	fp = fopen(path, "r");
	if (!fp)
		return AI_ERR_NO_CONFIG;

	memset(current_section, 0, sizeof(current_section));
	memset(default_model_buf, 0, sizeof(default_model_buf));

	while (fgets(line, sizeof(line), fp)) {
		char *trimmed = trim(line);

		/* 跳过空行和注释 */
		if (!trimmed[0] || trimmed[0] == '#')
			continue;

		/* 检查是否是 section 头 */
		if (trimmed[0] == '[') {
			char *end = strchr(trimmed, ']');
			if (end) {
				*end = '\0';
				strncpy(current_section, trimmed + 1,
					sizeof(current_section) - 1);

				in_route = 0;
				if (strcmp(current_section, "default") == 0) {
					in_default = 1;
					in_local = 0;
					in_ui = 0;
					in_routing = 0;
					in_models = 0;
				} else if (strcmp(current_section, "local") == 0) {
					in_default = 0;
					in_local = 1;
					in_ui = 0;
					in_routing = 0;
					in_models = 0;
				} else if (strcmp(current_section, "ui") == 0) {
					in_default = 0;
					in_local = 0;
					in_ui = 1;
					in_routing = 0;
					in_models = 0;
				} else if (strcmp(current_section, "routing") == 0) {
					/* [routing] 段：SME 路由模式 */
					in_default = 0;
					in_local = 0;
					in_ui = 0;
					in_routing = 1;
					in_models = 0;
				} else if (strcmp(current_section, "route") == 0) {
					/* [route] 段：W77 本地/云端模型路由 */
					in_default = 0;
					in_local = 0;
					in_ui = 0;
					in_routing = 0;
					in_route = 1;
					in_models = 0;
				} else if (strncmp(current_section, "models.", 7) == 0) {
					in_default = 0;
					in_local = 0;
					in_ui = 0;
					in_routing = 0;
					in_models = 1;
					/* 创建新模型配置 */
					model = calloc(1, sizeof(*model));
					if (!model)
						goto oom;
					model->name = strdup(current_section + 7);
					if (!model->name) {
						free(model);
						goto oom;
					}
					/* 加入链表 */
					model->next = cfg->models_head;
					cfg->models_head = model;
					cfg->model_count++;
				}
			}
			continue;
		}

		/* 解析 key = value */
		char *eq = strchr(trimmed, '=');
		if (!eq)
			continue;

		*eq = '\0';
		char *key = trim(trimmed);
		char *value = trim(eq + 1);

		if (in_default && strcmp(key, "model") == 0) {
			strncpy(default_model_buf, value,
				sizeof(default_model_buf) - 1);
		} else if (in_routing) {
			/* [routing] 段：SME 路由（AI_ROUTE_* 见 ai_config.h）。
			 * 注意写在 in_models 之前：值可能带引号（TOML 字符串），
			 * 与 [ui] 的裸值解析同款宽松处理 */
			if (strcmp(key, "mode") == 0) {
				char *v = value;
				size_t vl = strlen(v);

				if (vl >= 2 && v[0] == '"' &&
				    v[vl - 1] == '"') {
					v[vl - 1] = '\0';
					v++;
				}
				if (strcasecmp(v, "autonomous") == 0)
					cfg->routing.mode =
						AI_ROUTE_AUTONOMOUS;
				else if (strcasecmp(v, "pre_retrieve") == 0)
					cfg->routing.mode =
						AI_ROUTE_PRE_RETRIEVE;
				else
					cfg->routing.mode = AI_ROUTE_AUTO;
			} else if (strcmp(key, "local_catalog") == 0) {
				cfg->routing.local_catalog =
					ui_parse_bool(value,
						      cfg->routing.local_catalog);
			}
			} else if (in_route) {
				/* [route] 段：W77 模型路由（auto|local|cloud） */
				if (strcmp(key, "mode") == 0) {
					char *v = value;
					size_t vl = strlen(v);

					if (vl >= 2 && v[0] == '"' &&
					    v[vl - 1] == '"') {
						v[vl - 1] = '\0';
						v++;
					}
					if (strcasecmp(v, "local") == 0)
						cfg->route.mode =
							AI_MODEL_ROUTE_LOCAL;
					else if (strcasecmp(v, "cloud") == 0)
						cfg->route.mode =
							AI_MODEL_ROUTE_CLOUD;
					else
						cfg->route.mode =
							AI_MODEL_ROUTE_AUTO;
				} else if (strcmp(key, "privacy") == 0) {
					cfg->route.privacy =
						ui_parse_bool(value,
							      cfg->route.privacy);
				} else if (strcmp(key, "prefer_local") == 0) {
					cfg->route.prefer_local =
						ui_parse_bool(value,
							      cfg->route.prefer_local);
				} else if (strcmp(key, "failover") == 0) {
					cfg->route.failover =
						ui_parse_bool(value,
							      cfg->route.failover);
				} else if (strcmp(key, "offline_intents") == 0) {
					cfg->route.offline_intents =
						ui_parse_bool(value,
							      cfg->route.offline_intents);
				} else if (strcmp(key, "local_ctx") == 0) {
					int v = atoi(value);

					if (v > 0)
						cfg->route.local_ctx =
							v > AI_LOCAL_CTX_MAX ?
							AI_LOCAL_CTX_MAX : v;
				} else if (strcmp(key, "local_p95_ms") == 0) {
					int v = atoi(value);

					if (v > 0)
						cfg->route.local_p95_ms = v;
				} else if (strcmp(key, "switch_budget_ms") == 0) {
					int v = atoi(value);

					if (v > 0)
						cfg->route.switch_budget_ms = v;
				} else if (strcmp(key, "probe_timeout_ms") == 0) {
					int v = atoi(value);

					if (v > 0)
						cfg->route.probe_timeout_ms = v;
				} else if (strcmp(key, "cloud_down_ttl_ms") == 0) {
					int v = atoi(value);

					if (v > 0)
						cfg->route.cloud_down_ttl_ms = v;
				}
			} else if (in_models && model) {
				if (strcmp(key, "provider_type") == 0) {
				model->provider_type = strdup(value);
			} else if (strcmp(key, "model_name") == 0) {
				model->model_name = strdup(value);
			} else if (strcmp(key, "base_url") == 0) {
				model->base_url = strdup(value);
			} else if (strcmp(key, "api_key") == 0) {
				model->api_key = strdup(value);
			} else if (strcmp(key, "max_tokens") == 0) {
				/* W20 修1：模型档生成上限（云端 reasoning
				 * 模型需大于 thinking+正文总预算） */
				int v = atoi(value);

				if (v > 0)
					model->max_tokens = v;
			}
		} else if (in_ui) {
			/* [ui] 段：终端 UI 运行参数 */
			if (strcmp(key, "ctx_len") == 0) {
				int v = atoi(value);

				if (v > 0)
					cfg->ui.ctx_len = v;
			} else if (strcmp(key, "max_tokens") == 0) {
				int v = atoi(value);

				if (v > 0)
					cfg->ui.max_tokens = v;
			} else if (strcmp(key, "stream") == 0) {
				cfg->ui.stream = ui_parse_bool(value,
							       cfg->ui.stream);
			} else if (strcmp(key, "color") == 0) {
				cfg->ui.color = ui_parse_bool(value,
							      cfg->ui.color);
			} else if (strcmp(key, "verbose") == 0) {
				cfg->ui.verbose = ui_parse_bool(value,
								cfg->ui.verbose);
			} else if (strcmp(key, "local_api") == 0) {
				/* native = Ollama 原生 /api/chat（可带
				 * options.num_ctx）；v1 = OpenAI 兼容端点 */
				cfg->ui.local_native =
					(strcasecmp(value, "v1") != 0);
			} else if (strcmp(key, "session") == 0) {
				char *dup = strdup(value);

				if (!dup)
					goto oom;
				free(cfg->ui.session);
				cfg->ui.session = dup;
			} else if (strcmp(key, "lang") == 0) {
				/* [ui] lang = "zh"|"en"（i18n，ai_lang.h）。
				 * 值可能带引号，与 routing mode 同款宽松处理 */
				char *v = value;
				size_t vl = strlen(v);

				if (vl >= 2 && v[0] == '"' &&
				    v[vl - 1] == '"') {
					v[vl - 1] = '\0';
					v++;
				}
				if (strcmp(v, "zh") == 0 ||
				    strcmp(v, "en") == 0) {
					char *dup = strdup(v);

					if (!dup)
						goto oom;
					free(cfg->ui.lang);
					cfg->ui.lang = dup;
				}
			}
		} else if (in_local) {
			/* [local] 段：本地 Provider 配置 */
			if (strcmp(key, "enabled") == 0) {
				cfg->local.enabled =
					(strcasecmp(value, "true") == 0 ||
					 strcmp(value, "1") == 0 ||
					 strcasecmp(value, "yes") == 0 ||
					 strcasecmp(value, "on") == 0);
			} else if (strcmp(key, "base_url") == 0 ||
				   strcmp(key, "model") == 0 ||
				   strcmp(key, "api_key") == 0) {
				char *dup = strdup(value);
				char **slot =
					(strcmp(key, "base_url") == 0) ?
						&cfg->local.base_url :
					(strcmp(key, "model") == 0) ?
						&cfg->local.model :
						&cfg->local.api_key;

				if (!dup)
					goto oom;
				free(*slot);
				*slot = dup;
			} else if (strcmp(key, "timeout_ms") == 0) {
				int v = atoi(value);

				if (v > 0)
					cfg->local.timeout_ms = v;
			} else if (strcmp(key, "max_tokens") == 0) {
				/* W20 修1：本地档生成上限（覆盖 [ui] 兜底） */
				int v = atoi(value);

				if (v > 0)
					cfg->local.max_tokens = v;
			}
		}
	}

	fclose(fp);

	/* 设置默认模型 */
	if (default_model_buf[0]) {
		cfg->default_model = strdup(default_model_buf);
	}

	return AI_OK;

oom:
	fclose(fp);
	return AI_ERR_MEMORY;
}

int ai_config_load(struct ai_config *cfg)
{
	if (!cfg)
		return AI_ERR_INVALID_ARG;

	/* TOML 先行，环境变量覆盖（命令行参数由入口 getopt 最后覆盖） */
	{
		int ret = parse_model_toml(cfg);
		const char *route_env = getenv("AIKERNEL_ROUTE");

		ui_apply_env(&cfg->ui);
		if (route_env && route_env[0]) {
			if (strcasecmp(route_env, "local") == 0)
				cfg->route.mode = AI_MODEL_ROUTE_LOCAL;
			else if (strcasecmp(route_env, "cloud") == 0)
				cfg->route.mode = AI_MODEL_ROUTE_CLOUD;
			else if (strcasecmp(route_env, "auto") == 0)
				cfg->route.mode = AI_MODEL_ROUTE_AUTO;
		}
		return ret;
	}
}

static void write_model_toml(struct ai_config *cfg)
{
	char path[AI_PATH_MAX];
	char tmp_path[AI_PATH_MAX];
	FILE *fp;
	struct ai_model_config *m;

	get_config_path("model.toml", path, sizeof(path));
	snprintf(tmp_path, sizeof(tmp_path), "%s", path);
	if (strlen(path) + 4 < sizeof(tmp_path))
		strcat(tmp_path, ".tmp");

	fp = fopen(tmp_path, "w");
	if (!fp)
		return;

	fprintf(fp, "# AIKernel Model Configuration\n");
	fprintf(fp, "# Auto-generated, do not edit while AI Shell is running\n\n");

	/* 写入默认模型 */
	if (cfg->default_model) {
		fprintf(fp, "[default]\n");
		fprintf(fp, "model = \"%s\"\n\n", cfg->default_model);
	}

	/* 写入 [local] 段（本地 Provider 配置） */
	fprintf(fp, "[local]\n");
	fprintf(fp, "enabled = %s\n",
		cfg->local.enabled ? "true" : "false");
	fprintf(fp, "base_url = \"%s\"\n",
		cfg->local.base_url ? cfg->local.base_url : "");
	fprintf(fp, "model = \"%s\"\n",
		cfg->local.model ? cfg->local.model : "");
	fprintf(fp, "timeout_ms = %d\n",
		cfg->local.timeout_ms > 0 ? cfg->local.timeout_ms
					  : LOCAL_DEFAULT_TIMEOUT_MS);
	/* W20 修1：本地档生成上限（显式配置过才写出，保持文件精简） */
	if (cfg->local.max_tokens > 0)
		fprintf(fp, "max_tokens = %d\n", cfg->local.max_tokens);
	fprintf(fp, "api_key = \"%s\"\n\n",
		cfg->local.api_key ? cfg->local.api_key : "");

	/* 写入 [ui] 段（终端 UI 运行参数） */
	fprintf(fp, "[ui]\n");
	fprintf(fp, "ctx_len = %d\n",
		cfg->ui.ctx_len > 0 ? cfg->ui.ctx_len : UI_DEFAULT_CTX_LEN);
	fprintf(fp, "max_tokens = %d\n",
		cfg->ui.max_tokens > 0 ? cfg->ui.max_tokens
				       : UI_DEFAULT_MAX_TOKENS);
	fprintf(fp, "stream = %s\n", cfg->ui.stream ? "true" : "false");
	fprintf(fp, "local_api = \"%s\"\n",
		cfg->ui.local_native ? "native" : "v1");
	fprintf(fp, "color = %s\n", cfg->ui.color ? "true" : "false");
	fprintf(fp, "verbose = %s\n", cfg->ui.verbose ? "true" : "false");
	fprintf(fp, "session = \"%s\"\n",
		cfg->ui.session ? cfg->ui.session : UI_DEFAULT_SESSION);
	fprintf(fp, "lang = \"%s\"\n\n",
		cfg->ui.lang ? cfg->ui.lang : UI_DEFAULT_LANG);

	/* 写入 [routing] 段（SME 路由；放最后：旧版解析器遇到未知段
	 * 保持 in_* 原值，本段 key 名（mode/local_catalog）在旧解析
	 * 分支中无匹配被忽略，向后兼容） */
	fprintf(fp, "[routing]\n");
	fprintf(fp, "mode = \"%s\"\n",
		cfg->routing.mode == AI_ROUTE_AUTONOMOUS ? "autonomous" :
		cfg->routing.mode == AI_ROUTE_PRE_RETRIEVE ?
		"pre_retrieve" : "auto");
	fprintf(fp, "local_catalog = %s\n\n",
		cfg->routing.local_catalog ? "true" : "false");

	/* 写入 [route] 段（W77 模型路由） */
	fprintf(fp, "[route]\n");
	fprintf(fp, "mode = \"%s\"\n",
		cfg->route.mode == AI_MODEL_ROUTE_LOCAL ? "local" :
		cfg->route.mode == AI_MODEL_ROUTE_CLOUD ? "cloud" : "auto");
	fprintf(fp, "privacy = %s\n", cfg->route.privacy ? "true" : "false");
	fprintf(fp, "prefer_local = %s\n",
		cfg->route.prefer_local ? "true" : "false");
	fprintf(fp, "failover = %s\n", cfg->route.failover ? "true" : "false");
	fprintf(fp, "offline_intents = %s\n",
		cfg->route.offline_intents ? "true" : "false");
	fprintf(fp, "local_ctx = %d\n",
		cfg->route.local_ctx > 0 ? cfg->route.local_ctx :
					  AI_LOCAL_CTX_MAX);
	fprintf(fp, "local_p95_ms = %d\n", cfg->route.local_p95_ms);
	fprintf(fp, "switch_budget_ms = %d\n", cfg->route.switch_budget_ms);
	fprintf(fp, "probe_timeout_ms = %d\n", cfg->route.probe_timeout_ms);
	fprintf(fp, "cloud_down_ttl_ms = %d\n\n",
		cfg->route.cloud_down_ttl_ms);

	/* 写入模型列表 */
	for (m = cfg->models_head; m; m = m->next) {
		fprintf(fp, "[models.%s]\n", m->name);
		fprintf(fp, "provider_type = \"%s\"\n",
			m->provider_type ? m->provider_type : "");
		fprintf(fp, "model_name = \"%s\"\n",
			m->model_name ? m->model_name : "");
		fprintf(fp, "base_url = \"%s\"\n",
			m->base_url ? m->base_url : "");
		fprintf(fp, "api_key = \"%s\"\n",
			m->api_key ? m->api_key : "");
		/* W20 修1：模型档生成上限（显式配置过才写出） */
		if (m->max_tokens > 0)
			fprintf(fp, "max_tokens = %d\n", m->max_tokens);
		fprintf(fp, "\n");
	}

	fclose(fp);

	/* 原子替换：rename tmp -> target */
	rename(tmp_path, path);
}

int ai_config_save(struct ai_config *cfg)
{
	if (!cfg)
		return AI_ERR_INVALID_ARG;

	write_model_toml(cfg);
	return AI_OK;
}

int ai_config_get_models(struct ai_config *cfg, char ***names, int *count)
{
	struct ai_model_config *m;
	char **n;
	int i;

	if (!cfg || !names || !count)
		return AI_ERR_INVALID_ARG;

	if (cfg->model_count == 0) {
		*names = NULL;
		*count = 0;
		return AI_OK;
	}

	n = calloc(cfg->model_count, sizeof(char *));
	if (!n)
		return AI_ERR_MEMORY;

	i = 0;
	for (m = cfg->models_head; m; m = m->next) {
		n[i] = strdup(m->name);
		if (!n[i]) {
			while (--i >= 0)
				free(n[i]);
			free(n);
			return AI_ERR_MEMORY;
		}
		i++;
	}

	*names = n;
	*count = cfg->model_count;
	return AI_OK;
}

int ai_config_get_model(struct ai_config *cfg, const char *name,
			char **provider_type, char **model_name,
			char **base_url, char **api_key)
{
	struct ai_model_config *m;

	if (!cfg || !name)
		return AI_ERR_INVALID_ARG;

	for (m = cfg->models_head; m; m = m->next) {
		if (strcmp(m->name, name) == 0) {
			if (provider_type && m->provider_type)
				*provider_type = strdup(m->provider_type);
			if (model_name && m->model_name)
				*model_name = strdup(m->model_name);
			if (base_url && m->base_url)
				*base_url = strdup(m->base_url);
			if (api_key && m->api_key)
				*api_key = strdup(m->api_key);
			return AI_OK;
		}
	}

	return AI_ERR_NOT_FOUND;
}

int ai_config_add_model(struct ai_config *cfg, const char *name,
			const char *provider_type, const char *model_name,
			const char *base_url, const char *api_key)
{
	struct ai_model_config *m;

	if (!cfg || !name)
		return AI_ERR_INVALID_ARG;

	/* 检查是否已存在 */
	for (m = cfg->models_head; m; m = m->next) {
		if (strcmp(m->name, name) == 0)
			return AI_ERR_GENERIC; /* 已存在 */
	}

	m = calloc(1, sizeof(*m));
	if (!m)
		return AI_ERR_MEMORY;

	m->name = strdup(name);
	m->provider_type = provider_type ? strdup(provider_type) : NULL;
	m->model_name = model_name ? strdup(model_name) : NULL;
	m->base_url = base_url ? strdup(base_url) : NULL;
	m->api_key = api_key ? strdup(api_key) : NULL;

	m->next = cfg->models_head;
	cfg->models_head = m;
	cfg->model_count++;

	return AI_OK;
}

int ai_config_remove_model(struct ai_config *cfg, const char *name)
{
	struct ai_model_config *m, *prev;

	if (!cfg || !name)
		return AI_ERR_INVALID_ARG;

	prev = NULL;
	for (m = cfg->models_head; m; m = m->next) {
		if (strcmp(m->name, name) == 0) {
			if (prev)
				prev->next = m->next;
			else
				cfg->models_head = m->next;

			/* 如果删除的是默认模型，清除默认 */
			if (cfg->default_model &&
			    strcmp(cfg->default_model, name) == 0) {
				free(cfg->default_model);
				cfg->default_model = NULL;
			}

			free(m->name);
			free(m->provider_type);
			free(m->model_name);
			free(m->base_url);
			free(m->api_key);
			free(m);
			cfg->model_count--;
			return AI_OK;
		}
		prev = m;
	}

	return AI_ERR_NOT_FOUND;
}

int ai_config_set_default_model(struct ai_config *cfg, const char *name)
{
	struct ai_model_config *m;

	if (!cfg || !name)
		return AI_ERR_INVALID_ARG;

	/* 验证模型是否存在 */
	for (m = cfg->models_head; m; m = m->next) {
		if (strcmp(m->name, name) == 0) {
			free(cfg->default_model);
			cfg->default_model = strdup(name);
			return AI_OK;
		}
	}

	return AI_ERR_NOT_FOUND;
}

const char *ai_config_get_default_model(struct ai_config *cfg)
{
	if (!cfg)
		return NULL;
	return cfg->default_model;
}

int ai_config_get_local(struct ai_config *cfg, int *enabled, char **base_url,
			char **model, int *timeout_ms, char **api_key)
{
	if (!cfg)
		return AI_ERR_INVALID_ARG;

	if (enabled)
		*enabled = cfg->local.enabled;
	if (timeout_ms)
		*timeout_ms = cfg->local.timeout_ms;

	if (base_url) {
		*base_url = strdup(cfg->local.base_url ? cfg->local.base_url
						       : "");
		if (!*base_url)
			return AI_ERR_MEMORY;
	}
	if (model) {
		*model = strdup(cfg->local.model ? cfg->local.model : "");
		if (!*model)
			return AI_ERR_MEMORY;
	}
	if (api_key) {
		*api_key = strdup(cfg->local.api_key ? cfg->local.api_key
						     : "");
		if (!*api_key)
			return AI_ERR_MEMORY;
	}

	return AI_OK;
}

int ai_config_effective_max_tokens(const struct ai_config *cfg,
				   const char *provider_type)
{
	int is_cloud = provider_type &&
		       strcmp(provider_type, "openai_compatible") == 0;

	if (is_cloud) {
		/* 云端档：生效模型（default_model 对应 [models.X]）显式
		 * 配置优先，缺省 8192（T3 P0-1：thinking token 计入输出
		 * 预算，1024 会让正文见底；W20 复测 E1 实测 4096
		 * 在深度思考型任务仍可被 thinking 吃满，提到 8192） */
		if (cfg && cfg->default_model) {
			const struct ai_model_config *m;

			for (m = cfg->models_head; m; m = m->next) {
				if (m->name && m->max_tokens > 0 &&
				    strcmp(m->name, cfg->default_model) == 0)
					return m->max_tokens;
			}
		}
		return AI_CFG_CLOUD_MAX_TOKENS_DEFAULT;
	}

	/* 本地档：[local].max_tokens > [ui].max_tokens（旧配置兼容
	 * 兜底，含 AIKERNEL_MAX_TOKENS 覆盖链）> 1024 */
	if (cfg && cfg->local.max_tokens > 0)
		return cfg->local.max_tokens;
	if (cfg && cfg->ui.max_tokens > 0)
		return cfg->ui.max_tokens;
	return AI_CFG_LOCAL_MAX_TOKENS_DEFAULT;
}

int ai_config_exists(void)
{
	char path[AI_PATH_MAX];

	get_config_path("model.toml", path, sizeof(path));
	return access(path, F_OK) == 0 ? 1 : 0;
}

void ai_config_destroy(struct ai_config *cfg)
{
	struct ai_model_config *m, *next;

	if (!cfg)
		return;

	for (m = cfg->models_head; m; m = next) {
		next = m->next;
		free(m->name);
		free(m->provider_type);
		free(m->model_name);
		free(m->base_url);
		free(m->api_key);
		free(m);
	}

	free(cfg->config_dir);
	free(cfg->default_model);
	free(cfg->local.base_url);
	free(cfg->local.model);
	free(cfg->local.api_key);
	memset(&cfg->local, 0, sizeof(cfg->local));
	free(cfg->ui.session);
	free(cfg->ui.lang);
	memset(&cfg->ui, 0, sizeof(cfg->ui));
	free(cfg);
}
