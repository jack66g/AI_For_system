/*
 * backend.h - Backend 抽象接口
 *
 * 每个 Backend（cloud、local、lan、enterprise）实现此接口。
 * Communication Layer 根据 provider_type 路由到对应 Backend。
 */

#ifndef _AI_BACKEND_H
#define _AI_BACKEND_H

#include "ai_types.h"

/* 前向声明 */
struct comm_request;
struct comm_response;

/*
 * backend_send - Backend 统一发送接口
 * @req:  请求参数
 * @resp: 输出响应
 * 返回: AI_OK 成功
 */
typedef int (*backend_send_fn)(const struct comm_request *req,
                               struct comm_response *resp);

/*
 * backend_test - Backend 连通性测试
 * @host: 目标主机
 * 返回: AI_OK 成功
 */
typedef int (*backend_test_fn)(const char *host);

/*
 * backend_init - Backend 初始化
 * 返回: AI_OK 成功
 */
typedef int (*backend_init_fn)(void);

/*
 * backend_cleanup - Backend 清理
 */
typedef void (*backend_cleanup_fn)(void);

/*
 * backend_ops - Backend 操作接口
 */
struct backend_ops {
    backend_init_fn    init;
    backend_send_fn    send;
    backend_test_fn    test;
    backend_cleanup_fn cleanup;
    const char        *name;   /* Backend 名称 */
};

/*
 * backend_find - 根据 provider_type 查找 Backend
 * @provider_type: 如 "openai_compatible", "local"
 * 返回: backend_ops 指针，未找到返回 NULL
 */
const struct backend_ops *backend_find(const char *provider_type);

/*
 * backend_register_all - 注册所有内置 Backend
 * 启动时调用一次。
 */
void backend_register_all(void);

#endif /* _AI_BACKEND_H */
