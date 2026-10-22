/*
 * ai_runtime.h - AI Runtime 接口
 *
 * Runtime 负责 Session 管理、上下文维护、Token 跟踪、
 * Provider 调度和聊天流程控制。
 * Runtime 不直接依赖任何具体 Provider 实现。
 */
#ifndef _AI_RUNTIME_H
#define _AI_RUNTIME_H

#include "ai_types.h"
#include "ai_provider.h"
#include "ai_chat.h"
#include "ai_stream.h"

/* 会话状态 */
enum ai_session_state {
	AI_SESSION_IDLE,        /* 空闲，等待命令 */
	AI_SESSION_CHATTING,    /* 正在聊天模式 */
	AI_SESSION_ERROR,       /* 错误状态 */
};

/* 前向声明 */
struct ai_config;

/*
 * ai_runtime - AI Runtime 主体
 *
 * Phase 4: 集成 Communication Layer。
 * chat 请求通过 communication_send() 发送，不再直接调用 Provider。
 * Provider 引用保留用于状态查询和兼容性。
 */
struct ai_runtime {
	enum ai_session_state state;            /* 当前会话状态 */
	struct ai_config *config;               /* 配置管理器 */
	struct ai_provider_registry *registry;  /* Provider 注册中心 */
	struct ai_provider *provider;           /* 当前使用的 Provider */
	char *current_model;                    /* 当前使用的模型名（配置名） */
	/* Phase 4: 缓存模型配置，供 Communication Layer 使用 */
	char *model_provider_type;              /* Provider 类型 */
	char *model_name;                       /* API 模型名 */
	char *model_base_url;                   /* API Base URL */
	char *model_api_key;                    /* API Key */
	int token_used;                         /* 本次会话已用 Token（估算兜底） */
	int token_limit;                        /* Token 上限（0=无限制） */
	/* ---- usage 真值统计（响应 usage 字段回填，粗估兜底） ---- */
	int token_last_in;                      /* 上次请求 prompt_tokens */
	int token_last_out;                     /* 上次请求 completion_tokens */
	int token_session_in;                   /* 会话累计 prompt_tokens */
	int token_session_out;                  /* 会话累计 completion_tokens */
	int usage_is_real;                      /* 1=上次为服务端 usage 真值 */
	/* ---- W77 路由/失败语义（ask 据此决定云→本切换/降级） ---- */
	int last_error;                         /* 上次请求 AI_ERR_* */
	int last_status_code;                   /* 上次 HTTP 状态码（0=未知） */
	int last_was_local;                     /* 1=上次请求走本地 */
};

/*
 * ai_runtime_init - 初始化 Runtime
 * @rt:  未初始化的 Runtime 结构体
 * @cfg: 配置管理器
 * @reg: Provider 注册中心
 * 返回: AI_OK 成功
 */
int ai_runtime_init(struct ai_runtime *rt, struct ai_config *cfg,
		    struct ai_provider_registry *reg);

/*
 * ai_runtime_set_model - 设置当前使用的模型
 * @rt:         Runtime
 * @model_name: 模型名（对应 model.toml 中的 key）
 * 返回: AI_OK 成功，AI_ERR_NOT_FOUND 模型未找到
 */
int ai_runtime_set_model(struct ai_runtime *rt, const char *model_name);

/*
 * ai_runtime_get_state - 获取 Runtime 当前状态
 */
enum ai_session_state ai_runtime_get_state(struct ai_runtime *rt);

/*
 * ai_runtime_chat - 发送消息并同步等待响应
 * @rt:       Runtime
 * @message:  用户消息
 * @response: 输出参数，AI 响应（调用者需 free）
 * 返回: AI_OK 成功，AI_ERR_* 失败
 */
int ai_runtime_chat(struct ai_runtime *rt, const char *message,
		    char **response);

/*
 * ai_runtime_chat_ex - messages 数组模式请求（Ask 工具调用闭环）
 * 与 ai_runtime_chat 同一配置/Provider 数据路径，但请求体携带完整
 * 消息数组（system/user/assistant/tool）与可选 OpenAI tools 数组，
 * 响应解析出 content + tool_calls。
 * @rt:         Runtime
 * @msgs:       消息数组
 * @nmsgs:      消息条数
 * @tools_json: OpenAI tools 数组 JSON（可 NULL）
 * @on_delta:   流式增量回调（可 NULL；非 NULL 且 [ui].stream 开时
 *              请求流式，delta.content 逐段交付）
 * @on_delta_ud: 回调上下文
 * @result:     输出参数，解析结果（调用者 ai_chat_result_free）
 * 返回: AI_OK 成功，AI_ERR_* 失败
 */
int ai_runtime_chat_ex(struct ai_runtime *rt,
		       const struct ai_chat_msg *msgs, int nmsgs,
		       const char *tools_json,
		       ai_stream_delta_cb on_delta, void *on_delta_ud,
		       struct ai_chat_result **result);

/*
 * ai_runtime_get_token_usage - 获取 Token 使用统计
 * @rt:    Runtime
 * @used:  输出参数，已用 Token 数
 * @limit: 输出参数，Token 上限（0=无限制）
 */
int ai_runtime_get_token_usage(struct ai_runtime *rt, int *used, int *limit);

/*
 * ai_runtime_destroy - 清理 Runtime 资源
 * @rt: Runtime
 */
void ai_runtime_destroy(struct ai_runtime *rt);

/* ====================================================================
 * W77 模型路由（runtime/ai_route.c）
 *
 * 与 SME 工具路由（AI_ROUTE_*）区分：这里决定“本地 or 云端模型”。
 * 路由决策只读配置/探测结果，不改变 D 级/租约语义。
 * ==================================================================== */

/* 路由目标 */
enum ai_model_route_target {
	AI_ROUTE_TARGET_LOCAL = 1,   /* 本地模型 */
	AI_ROUTE_TARGET_CLOUD = 2,   /* 云端模型 */
	AI_ROUTE_TARGET_OFFLINE = 3, /* 两者均不可用：明确降级到离线意图 */
};

/* 任务分类 */
enum ai_route_task_class {
	AI_ROUTE_TASK_OPERATIONAL = 0, /* 状态/诊断/文件/服务/沙箱/记忆 */
	AI_ROUTE_TASK_CHAT = 1,        /* 普通对话 */
	AI_ROUTE_TASK_REASONING = 2,   /* 代码/方案/分析等重推理 */
};

/* 决策事实（纯函数输入，供单测） */
struct ai_route_facts {
	int mode;            /* AI_MODEL_ROUTE_* */
	int task;            /* ai_route_task_class */
	int privacy;         /* 1=隐私任务 */
	int prefer_local;    /* 1=运维/短任务优先本地 */
	int failover;        /* 1=云失败可切本地 */
	int cloud_down;      /* 1=云不可用（探测/失败记忆） */
	int local_up;        /* 1=本地可用 */
	int local_slow;      /* 1=本地近期延迟超预算 */
	int tokens;          /* 估算 prompt token */
};

/* 决策输出 */
struct ai_route_choice {
	int target;              /* AI_ROUTE_TARGET_* */
	int mode;                /* 生效模式 */
	int task_class;
	int privacy;
	const char *reason;      /* 静态原因串（可写 trace） */
	long long decide_ms;     /* 决策耗时 */
	int cloud_known_down;
	int local_available;
	int local_probe_ms;
	int tokens_est;
};

/* 模式名字/解析（非法返回 -1）；生效模式 = env > [route].mode */
const char *ai_route_mode_name(int mode);
int ai_route_mode_parse(const char *s);
int ai_route_effective_mode(const struct ai_config *cfg);
int ai_route_offline_intents_enabled(const struct ai_config *cfg);

/* 任务分类/纯决策（无 IO，便于单测） */
int ai_route_classify_task(const char *question);
void ai_route_decide_facts(const struct ai_route_facts *f,
			   struct ai_route_choice *out);

/* 完整决策（含本地/云端 TCP 探测与失败记忆） */
int ai_route_decide(const struct ai_config *cfg, const char *question,
		    struct ai_route_choice *out);

/* 应用目标/云→本切换（返回 AI_OK；elapsed 输出切换耗时毫秒） */
int ai_route_current_target(const struct ai_runtime *rt);
int ai_route_apply(struct ai_runtime *rt, int target, long long *elapsed_ms);
int ai_route_failover(struct ai_runtime *rt, int from, int to,
		      const char *reason, long long *switch_ms);

/* 失败归类/健康记忆 */
int ai_route_should_failover(const struct ai_config *cfg, int from_target,
			     int ret, int status_code, int already_failed);
void ai_route_note_cloud(int ok, int status_code, int ret);
void ai_route_note_local(int ok, int status_code, int ret,
			 long long latency_ms);
long long ai_route_last_switch_ms(void);

/* 探测/状态 */
int ai_route_probe_url(const char *url, int timeout_ms);
int ai_route_local_available(const struct ai_config *cfg);
int ai_route_ensure_local_model(struct ai_config *cfg);
int ai_route_status_text(const struct ai_config *cfg,
			 const struct ai_runtime *rt,
			 char *buf, size_t n);

/* 路由 trace（route.jsonl；不含 base_url/api_key） */
int ai_route_trace_decision(const struct ai_config *cfg,
			    const struct ai_runtime *rt,
			    const struct ai_route_choice *choice,
			    long long apply_ms);
int ai_route_trace_switch(const struct ai_runtime *rt, int from, int to,
			  const char *reason, long long switch_ms);
int ai_route_trace_offline(const char *intent, const char *source,
			   long long cache_age_ms, long long latency_ms);

/* 测试/诊断：清零进程内健康缓存 */
void ai_route_reset_state(void);

#endif /* _AI_RUNTIME_H */
