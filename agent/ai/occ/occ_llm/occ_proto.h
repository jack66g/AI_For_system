/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_proto.h - occ_llm 内部：协议事件解析器分派（occ_sse.c 使用）
 * 单个 data 块 JSON → occ_event 序列（协议状态机各持私有状态）。
 */
#ifndef _OCC_PROTO_H
#define _OCC_PROTO_H

#include "occ_llm.h"

/* openai.c */
void *occ_openai_state_new(void);
void occ_openai_state_free(void *st);
/* 返回 1 表示该事件触发了流终结（DONE 由解析器发出） */
int occ_openai_event(void *st, const char *json, size_t len,
		     occ_event_cb cb, void *ud);

/* anthropic.c */
void *occ_anthropic_state_new(void);
void occ_anthropic_state_free(void *st);
int occ_anthropic_event(void *st, const char *json, size_t len,
			occ_event_cb cb, void *ud);

#endif /* _OCC_PROTO_H */
