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

#endif /* _AI_RUNTIME_H */
