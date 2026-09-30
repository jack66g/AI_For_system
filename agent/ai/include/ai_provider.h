/*
 * ai_provider.h - AI Provider 抽象接口
 *
 * 定义所有 AI Provider 必须实现的统一接口。
 * Provider 可插拔、可扩展，Runtime 不感知具体实现。
 */
#ifndef _AI_PROVIDER_H
#define _AI_PROVIDER_H

#include "ai_types.h"

/* Provider 类型 */
enum ai_provider_type {
	AI_PROVIDER_CLOUD,  /* Cloud AI Provider */
	AI_PROVIDER_LOCAL,  /* Local AI Provider */
};

/* Provider 能力标志 */
#define AI_PROVIDER_CAP_CHAT      (1 << 0)  /* 支持聊天 */
#define AI_PROVIDER_CAP_STREAM    (1 << 1)  /* 支持流式输出 */

/* Provider 状态 */
enum ai_provider_state {
	AI_PROVIDER_UNINITIALIZED,  /* 未初始化 */
	AI_PROVIDER_READY,          /* 就绪 */
	AI_PROVIDER_ERROR,          /* 错误 */
	AI_PROVIDER_DISCONNECTED,   /* 已断开 */
};

/* 前向声明 */
struct ai_config;

/*
 * ai_provider_ops - Provider 操作接口（虚函数表）
 *
 * 每个 Provider 必须实现此接口的全部方法。
 * instance 参数指向 Provider 自身的实例数据。
 */
struct ai_provider_ops {
	/*
	 * init - 初始化 Provider
	 * @instance: Provider 实例数据
	 * @cfg:      配置管理器（用于读取模型配置参数）
	 * 返回: AI_OK 成功，AI_ERR_* 失败
	 */
	int (*init)(void *instance, struct ai_config *cfg);

	/*
	 * connect - 建立与服务端的连接
	 * @instance: Provider 实例数据
	 * 返回: AI_OK 成功，AI_ERR_NETWORK/AI_ERR_AUTH 失败
	 */
	int (*connect)(void *instance);

	/*
	 * chat - 发送同步聊天请求
	 * @instance: Provider 实例数据
	 * @prompt:   用户输入消息
	 * @response: 输出参数，AI 响应（调用者需 free）
	 * 返回: AI_OK 成功，AI_ERR_* 失败
	 */
	int (*chat)(void *instance, const char *prompt, char **response);

	/*
	 * stream - 发送流式聊天请求
	 * @instance:  Provider 实例数据
	 * @prompt:    用户输入消息
	 * @on_token:  每收到一个 token 时回调
	 * @user_data: 传递给回调的用户数据
	 * 返回: AI_OK 成功，AI_ERR_* 失败
	 */
	int (*stream)(void *instance, const char *prompt,
		      void (*on_token)(const char *token, void *user_data),
		      void *user_data);

	/*
	 * status - 获取 Provider 当前状态
	 * @instance: Provider 实例数据
	 * 返回: 当前 Provider 状态枚举值
	 */
	int (*status)(void *instance);

	/*
	 * close - 关闭连接并释放资源
	 * @instance: Provider 实例数据
	 */
	void (*close)(void *instance);
};

/*
 * ai_provider - Provider 注册信息
 *
 * 每个 Provider 在启动时注册一个此结构体到注册中心。
 */
struct ai_provider {
	const char *name;                   /* Provider 名称 */
	const char *display_name;           /* 显示名称 */
	enum ai_provider_type type;         /* 类型 */
	unsigned int capabilities;          /* 能力标志位 */
	struct ai_provider_ops ops;         /* 操作接口 */
	void *instance;                     /* Provider 实例数据 */
	enum ai_provider_state state;       /* 当前状态 */
	struct ai_provider *next;           /* 链表指针 */
};

/*
 * ai_provider_registry - Provider 注册中心
 */
struct ai_provider_registry {
	struct ai_provider *head;           /* Provider 链表头 */
	int count;                          /* 已注册 Provider 数量 */
};

/* ---- Provider 注册中心 API ---- */

void ai_provider_registry_init(struct ai_provider_registry *reg);

int ai_provider_register(struct ai_provider_registry *reg,
			 struct ai_provider *provider);

struct ai_provider *ai_provider_find(struct ai_provider_registry *reg,
				     const char *name);

struct ai_provider *ai_provider_find_by_type(struct ai_provider_registry *reg,
					     enum ai_provider_type type);

int ai_provider_unregister(struct ai_provider_registry *reg,
			   const char *name);

void ai_provider_registry_destroy(struct ai_provider_registry *reg);

#endif /* _AI_PROVIDER_H */
