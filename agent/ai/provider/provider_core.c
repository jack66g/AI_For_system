/*
 * provider_core.c - Provider 注册中心实现
 *
 * 管理所有 AI Provider 的注册、查找和注销。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ai_provider.h"

void ai_provider_registry_init(struct ai_provider_registry *reg)
{
	if (!reg)
		return;
	reg->head = NULL;
	reg->count = 0;
}

int ai_provider_register(struct ai_provider_registry *reg,
			 struct ai_provider *provider)
{
	if (!reg || !provider || !provider->name)
		return AI_ERR_INVALID_ARG;

	/* 检查是否已存在同名 Provider */
	if (ai_provider_find(reg, provider->name))
		return AI_ERR_GENERIC;

	/* 插入链表头部 */
	provider->next = reg->head;
	reg->head = provider;
	reg->count++;

	return AI_OK;
}

struct ai_provider *ai_provider_find(struct ai_provider_registry *reg,
				     const char *name)
{
	struct ai_provider *p;

	if (!reg || !name)
		return NULL;

	for (p = reg->head; p; p = p->next) {
		if (strcmp(p->name, name) == 0)
			return p;
	}

	return NULL;
}

struct ai_provider *ai_provider_find_by_type(struct ai_provider_registry *reg,
					     enum ai_provider_type type)
{
	struct ai_provider *p;

	if (!reg)
		return NULL;

	for (p = reg->head; p; p = p->next) {
		if (p->type == type)
			return p;
	}

	return NULL;
}

int ai_provider_unregister(struct ai_provider_registry *reg,
			   const char *name)
{
	struct ai_provider *p, *prev;

	if (!reg || !name)
		return AI_ERR_INVALID_ARG;

	prev = NULL;
	for (p = reg->head; p; p = p->next) {
		if (strcmp(p->name, name) == 0) {
			if (prev)
				prev->next = p->next;
			else
				reg->head = p->next;
			reg->count--;
			return AI_OK;
		}
		prev = p;
	}

	return AI_ERR_NOT_FOUND;
}

void ai_provider_registry_destroy(struct ai_provider_registry *reg)
{
	struct ai_provider *p, *next;

	if (!reg)
		return;

	for (p = reg->head; p; p = next) {
		next = p->next;
		if (p->ops.close && p->instance)
			p->ops.close(p->instance);
		free(p->instance);
		/* 注意：不 free provider 本身，因为它可能是静态分配的 */
	}

	reg->head = NULL;
	reg->count = 0;
}
