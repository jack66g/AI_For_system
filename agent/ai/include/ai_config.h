/*
 * ai_config.h - 配置管理接口
 *
 * 管理 AI 子系统的 TOML 配置文件读写。
 * 配置文件存储在 ~/.aikernel/ 目录下。
 */
#ifndef _AI_CONFIG_H
#define _AI_CONFIG_H

#include "ai_types.h"

/* 单个模型配置信息 */
struct ai_model_config {
	char *name;             /* 配置名（用户自定义） */
	char *provider_type;    /* Provider 类型 */
	char *model_name;       /* 模型名（如 deepseek-chat） */
	char *base_url;         /* API Base URL */
	char *api_key;          /* API Key */
	int max_tokens;         /* W20 修1：本模型档生成上限（<=0=未配置，
				 *   生效值见 ai_config_effective_max_tokens） */
	struct ai_model_config *next;  /* 链表指针 */
};

/*
 * ai_local_config - 本地 Provider（model.toml 的 [local] 段）配置
 *
 * 对应 OpenAI 兼容本地推理端点（base_url 已含 /v1），
 * 兼容 Ollama(11434)/llama.cpp server(8080)/LM Studio(1234)。
 * 由 config_manager.c 解析与持久化，`model use local` 切换时应用。
 */
struct ai_local_config {
	int enabled;            /* 是否允许切换到本地模式（默认 1） */
	char *base_url;         /* 本地服务 Base URL
				 * （默认 http://127.0.0.1:11434/v1） */
	char *model;            /* 本地模型名（默认 llama3） */
	int timeout_ms;         /* 请求超时毫秒数（默认 60000） */
	char *api_key;          /* 可选 API Key（空则不发 Authorization） */
	int max_tokens;         /* W20 修1：本地档生成上限（<=0=未配置，
				 *   兜底链见 ai_config_effective_max_tokens） */
};

/*
 * ai_ui_config - 终端 UI 运行参数（model.toml 的 [ui] 段）
 *
 * 三层来源（优先级从高到低，低层为初值、高层覆盖）：
 *   1. 命令行参数：ai --ctx N --max-tokens N --no-stream --session <name>
 *      --no-color（aikernel_main.c getopt 解析后直接覆盖内存值）；
 *   2. 环境变量：AIKERNEL_CTX / AIKERNEL_MAX_TOKENS（ai_config_load 应用）；
 *   3. TOML：model.toml 的 [ui] 段（config_manager.c 解析与持久化）。
 *
 * ctx_len 语义：客户端上下文 token 预算。
 *   - 本地通道：作为 Ollama 原生 /api/chat 的 options.num_ctx 下发
 *     （按模型实际上限钳制，见 local/ollama_native.c）；
 *   - 云端通道：作为客户端历史裁剪预算（按 usage.prompt_tokens 管理）。
 *
 * 修复 6（T2 P1-5）缺省值校准：出厂 num_ctx=8192 / num_predict=1024
 * （原 num_predict=4096 把 8192 窗口的提示预算腰斩到 4098 tokens，
 * ollama 实测系统提示只剩 4 个 token：keep=4）。两者均可被
 * model.toml [ui] 与环境变量覆盖。
 */
struct ai_ui_config {
	int ctx_len;            /* 上下文 token 预算（默认 8192） */
	int max_tokens;         /* 单次生成 token 上限（默认 1024） */
	int stream;             /* 1=流式输出（默认），0=一次性返回 */
	int local_native;       /* 1=Ollama 原生 /api/chat（默认，支持
				 *   options.num_ctx），0=OpenAI 兼容 /v1 */
	int color;              /* 1=ANSI 颜色（默认），0=关闭；
				 *   NO_COLOR 环境变量非空时强制关闭 */
	int verbose;            /* 1=工具过程全展开，0=折叠单行卡片（默认） */
	char *session;          /* 当前会话名（默认 "default"） */
	char *lang;             /* 界面语言 "zh"（默认）|"en"；优先级：
				 * AIKERNEL_LANG 环境变量 > 本值 > zh
				 * （i18n 见 ai_lang.h；lang 命令写回） */
};

/* [ui] 段默认值（config_manager.c 与 CLI 校验共用） */
#define UI_DEFAULT_CTX_LEN      8192
#define UI_DEFAULT_MAX_TOKENS   1024
#define UI_DEFAULT_SESSION      "default"
#define UI_DEFAULT_LANG         "zh"

/*
 * W20 修1：per-provider max_tokens（T3 P0-1 空回答根因）
 *
 * max_tokens=1024（原 [ui] 全局单一档）对云端 reasoning 模型矫枉过正：
 * thinking token 计入输出预算，思考完 1024 见底、正文为空（T3 8/25
 * 场景受害）。改为按当前生效 provider 取对应档：
 *   - 云端（openai_compatible）：生效 [models.<name>].max_tokens，
 *     缺省 AI_CFG_CLOUD_MAX_TOKENS（8192）；
 *   - 本地（local）：[local].max_tokens > [ui].max_tokens（旧配置
 *     兼容兜底）> AI_CFG_LOCAL_MAX_TOKENS（1024）。
 * 生效值统一由 ai_config_effective_max_tokens() 计算（runtime 构建
 * 请求与 config show 共用），AIKERNEL_MAX_TOKENS 环境变量沿用 [ui]
 * 覆盖链（本地档兜底语义不变）。
 */
#define AI_CFG_CLOUD_MAX_TOKENS_DEFAULT  8192
#define AI_CFG_LOCAL_MAX_TOKENS_DEFAULT  1024

/*
 * ai_routing_config - SME 路由配置（model.toml 的 [routing] 段）
 *
 * 同一套 agent，SME 检索成为接口路由核心，两种驱动：
 *   autonomous    云端：模型自主检索——system 常驻"目录页"（75 工具
 *                 名字+一句话）+ 检索指引；请求 tools 数组 = 已激活
 *                 集合，memory_search 命中的工具由框架自动扩入。
 *   pre_retrieve  本地：框架预检索——ask 进来框架先 SME 检索 top-K，
 *                 命中工具扩入请求 tools，模型无感知。
 * mode=AUTO 时按 provider 缺省：cloud=autonomous，local=pre_retrieve。
 */
#define AI_ROUTE_AUTO           0
#define AI_ROUTE_AUTONOMOUS     1
#define AI_ROUTE_PRE_RETRIEVE   2

struct ai_routing_config {
	int mode;               /* AI_ROUTE_*（默认 AUTO） */
	int local_catalog;      /* 预检索模式 system 是否带目录页：
				 * 0=不带（缺省，预算紧；检索不中→模型
				 * 诚实告知），1=带 */
};

/*
 * ai_route_config - W77 模型路由配置（model.toml 的 [route] 段）
 *
 * 与 [routing]（SME 工具路由）不同：本段决定“用本地还是云端模型”。
 * 环境变量 AIKERNEL_ROUTE=auto|local|cloud 覆盖 mode；
 * AIKERNEL_PRIVACY=1 覆盖 privacy；AIKERNEL_OFFLINE_INTENTS=0/1/force
 * 覆盖 offline_intents。
 */
enum ai_model_route_mode {
	AI_MODEL_ROUTE_AUTO = 0,   /* 按任务/延迟/隐私/成本自动 */
	AI_MODEL_ROUTE_LOCAL = 1,  /* 强制本地；本地失败明确降级 */
	AI_MODEL_ROUTE_CLOUD = 2,  /* 强制云；失败仍可按 failover 切本地 */
};

/* 本地模型上下文硬上限（目录条目保守值 32768；更长窗口由
 * ollama_native 按模型实际上限钳制，W77d 起本地模型按需安装） */
#define AI_LOCAL_CTX_MAX  32768

struct ai_route_config {
	int mode;                 /* AI_MODEL_ROUTE_*（默认 AUTO） */
	int privacy;              /* 1=隐私任务强制本地，绝不出网 */
	int prefer_local;         /* 1=运维/短任务优先本地（默认 1） */
	int failover;             /* 1=云失败自动切本地（默认 1） */
	int offline_intents;      /* 1=启用离线意图层（默认 1） */
	int local_ctx;            /* 本地上下文上限（默认/最大 32768） */
	int local_p95_ms;         /* 本地延迟预算（默认 8000） */
	int switch_budget_ms;     /* 切换预算（默认 2000） */
	int probe_timeout_ms;     /* 可达性探测超时（默认 400） */
	int cloud_down_ttl_ms;    /* 云失败记忆 TTL（默认 60000） */
};

/*
 * ai_clarify_config - W77e 澄清行为（model.toml 的 [clarify] 段；
 * [ui] 段同名键兼容）。仅控制非 TTY pending 过期后的自动默认降级，
 * 不改变 clarify 的 lease/confirm 边界（clarify 永不授权）。
 */
struct ai_clarify_config {
	int auto_default;   /* 1=过期 pending 按推荐项自动继续（默认）；
			     *   kind=authorization 永不自动 */
};

/*
 * ai_config - 配置管理器
 */
struct ai_config {
	char *config_dir;                       /* 配置目录路径 */
	char *default_model;                    /* 默认模型名 */
	struct ai_model_config *models_head;    /* 模型链表头 */
	int model_count;                        /* 模型数量 */
	struct ai_local_config local;           /* [local] 段配置 */
	struct ai_ui_config ui;                 /* [ui] 段配置（终端 UI） */
	struct ai_routing_config routing;       /* [routing] 段配置（SME 路由） */
	struct ai_route_config route;           /* [route] 段配置（模型路由） */
	struct ai_clarify_config clarify;       /* [clarify] 段配置（W77e） */
};

/*
 * ai_config_init - 创建配置管理器
 * 自动创建 ~/.aikernel/ 目录（如不存在）。
 * 返回: 配置对象指针，失败返回 NULL
 */
struct ai_config *ai_config_init(void);

/*
 * ai_config_load - 加载所有配置文件
 * @cfg: 已初始化的配置管理器
 * 返回: AI_OK 成功，AI_ERR_NO_CONFIG 配置文件不存在
 *
 * 注意：如果 model.toml 不存在，返回 AI_ERR_NO_CONFIG 但
 *       不会报错 —— 调用者应检查并提示用户配置模型。
 */
int ai_config_load(struct ai_config *cfg);

/*
 * ai_config_save - 保存配置到文件
 * @cfg: 配置管理器
 * 返回: AI_OK 成功
 */
int ai_config_save(struct ai_config *cfg);

/*
 * ai_config_get_models - 获取所有模型名列表
 * @cfg:   配置管理器
 * @names: 输出参数，模型名数组（调用者需 free 每个元素和数组本身）
 * @count: 输出参数，模型数量
 * 返回: AI_OK 成功
 */
int ai_config_get_models(struct ai_config *cfg, char ***names, int *count);

/*
 * ai_config_get_model - 获取指定模型的完整配置
 * @cfg:           配置管理器
 * @name:          模型配置名
 * @provider_type: 输出，Provider 类型
 * @model_name:    输出，模型名
 * @base_url:      输出，Base URL
 * @api_key:       输出，API Key
 * 返回: AI_OK 成功，AI_ERR_NOT_FOUND 未找到
 *
 * 所有输出参数可为 NULL 表示不需要该字段。
 * 输出字符串由调用者 free。
 */
int ai_config_get_model(struct ai_config *cfg, const char *name,
			char **provider_type, char **model_name,
			char **base_url, char **api_key);

/*
 * ai_config_add_model - 添加新模型
 * @cfg:           配置管理器
 * @name:          模型配置名
 * @provider_type: Provider 类型
 * @model_name:    模型名
 * @base_url:      Base URL
 * @api_key:       API Key
 * 返回: AI_OK 成功
 */
int ai_config_add_model(struct ai_config *cfg, const char *name,
			const char *provider_type, const char *model_name,
			const char *base_url, const char *api_key);

/*
 * ai_config_remove_model - 删除模型
 * @cfg:  配置管理器
 * @name: 模型配置名
 * 返回: AI_OK 成功，AI_ERR_NOT_FOUND 未找到
 */
int ai_config_remove_model(struct ai_config *cfg, const char *name);

/*
 * ai_config_set_default_model - 设置默认模型
 * @cfg:  配置管理器
 * @name: 模型配置名
 * 返回: AI_OK 成功，AI_ERR_NOT_FOUND 未找到
 */
int ai_config_set_default_model(struct ai_config *cfg, const char *name);

/*
 * ai_config_get_default_model - 获取默认模型名
 * @cfg: 配置管理器
 * 返回: 默认模型名，无默认模型返回 NULL
 */
const char *ai_config_get_default_model(struct ai_config *cfg);

/*
 * ai_config_get_local - 获取 [local] 段（本地 Provider）配置
 * @cfg:        配置管理器
 * @enabled:    输出，是否允许本地模式（可为 NULL）
 * @base_url:   输出，Base URL（调用者需 free，可为 NULL 表示不需要）
 * @model:      输出，模型名（调用者需 free，可为 NULL）
 * @timeout_ms: 输出，请求超时毫秒数（可为 NULL）
 * @api_key:    输出，API Key（调用者需 free，可为 NULL）
 * 返回: AI_OK 成功，AI_ERR_INVALID_ARG 参数错误，AI_ERR_MEMORY 拷贝失败
 *
 * base_url/model/api_key 未配置时返回空串（而非 NULL），
 * 调用者以空串判断"未配置"。
 */
int ai_config_get_local(struct ai_config *cfg, int *enabled, char **base_url,
			char **model, int *timeout_ms, char **api_key);

/*
 * ai_config_effective_max_tokens - W20 修1：按 provider 取生效生成上限
 * @cfg:           配置管理器（可为 NULL，取纯缺省值）
 * @provider_type: 当前生效 Provider 类型（rt->model_provider_type；
 *                 "openai_compatible"=云端，其他一律按本地档）
 * 返回: 生效 max_tokens（恒 >0）
 *
 * 云端档：生效模型（default_model 对应 [models.X]）显式配置优先，
 * 缺省 4096；本地档：[local].max_tokens > [ui].max_tokens > 1024。
 */
int ai_config_effective_max_tokens(const struct ai_config *cfg,
				   const char *provider_type);

/*
 * ai_ui_set_defaults - 填充 [ui] 段默认值（ai_config_init 内部调用，
 * 也供单测/重置使用）
 * @ui: 未初始化的 UI 配置
 */
void ai_ui_set_defaults(struct ai_ui_config *ui);

/*
 * ai_config_exists - 检查 model.toml 配置文件是否存在
 * 返回: 1 存在，0 不存在
 */
int ai_config_exists(void);

/*
 * ai_config_destroy - 销毁配置管理器
 * @cfg: 配置管理器
 */
void ai_config_destroy(struct ai_config *cfg);

#endif /* _AI_CONFIG_H */
