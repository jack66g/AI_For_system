/*
 * backend.c - Backend 注册与查找
 *
 * 维护一个全局的 Backend 注册表。
 * 启动时由 backend_register_all() 注册所有内置 Backend。
 */

#include <string.h>
#include "backend.h"

/* 最大注册 Backend 数量 */
#define MAX_BACKENDS 8

static const struct backend_ops *g_backends[MAX_BACKENDS];
static int g_backend_count = 0;

void backend_register_all(void)
{
    /* 由各 Backend 的注册函数填充 */
    /* cloud_backend 和 local_backend 通过各自的 register 函数注册 */

    /* 声明外部注册函数（按 Kconfig 开关条件接线，见 agent/ai/Makefile） */
    extern void cloud_backend_register(void);
    extern void local_backend_register(void);

#ifdef CONFIG_AI_CLOUD_PROVIDER
    cloud_backend_register();
#endif
#ifdef CONFIG_AI_LOCAL_PROVIDER
    local_backend_register();
#endif
}

void backend_register(const struct backend_ops *ops)
{
    if (!ops || g_backend_count >= MAX_BACKENDS)
        return;

    g_backends[g_backend_count++] = ops;

    /* 初始化 Backend */
    if (ops->init)
        ops->init();
}

const struct backend_ops *backend_find(const char *provider_type)
{
    int i;

    if (!provider_type)
        return NULL;

    /*
     * provider_type 到 Backend 名称的映射：
     * "openai_compatible" → "cloud"
     * "local"             → "local"
     * 未来： "lan" → "lan", "enterprise" → "enterprise"
     */
    const char *backend_name;
    if (strcmp(provider_type, "openai_compatible") == 0)
        backend_name = "cloud";
    else if (strcmp(provider_type, "local") == 0)
        backend_name = "local";
    else
        backend_name = provider_type;  /* 按原名查找 */

    for (i = 0; i < g_backend_count; i++) {
        if (g_backends[i]->name &&
            strcmp(g_backends[i]->name, backend_name) == 0)
            return g_backends[i];
    }

    return NULL;
}
