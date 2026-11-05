/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_ring.h - SME 不可达时的有界降级环形缓冲
 *
 * 语义（规格）：有界（默认 4096 条）；满时**丢旧不丢新**（最旧一条被
 * 挤出并计数 buffer_dropped + journal 限频告警）；SME 恢复后按序补写。
 *
 * 槽内容 = 一条待写记忆的三元组（text / metadata JSON / tags JSON 均
 * strdup 私有副本），补写时经 sme_add_ex 重组请求体（与首发同一路径）。
 */
#ifndef _AS_RING_H
#define _AS_RING_H

#include <stddef.h>

struct as_ring_slot {
	char *text;
	char *meta;		/* JSON object 字符串 */
	char *tags;		/* JSON array 字符串 */
	int stream_idx;		/* 计数归属（buffer_dropped/written） */
};

struct as_ring {
	struct as_ring_slot *slots;
	int cap;
	int head;		/* 最旧（弹出端） */
	int len;
	long long dropped;	/* 累计丢旧条数 */
	long long pushed;
	long long popped;
};

int as_ring_init(struct as_ring *r, long long cap);

void as_ring_free(struct as_ring *r);

/* 已用条数 */
int as_ring_count(const struct as_ring *r);

/*
 * as_ring_push - 入队。容量满时丢最旧（dropped++，*dropped_out 收到被丢
 * 槽内容，调用方负责 free——用于计数与告警上下文）。返回 0。
 */
int as_ring_push(struct as_ring *r, const char *text, const char *meta,
		 const char *tags, int stream_idx,
		 struct as_ring_slot *dropped_out);

/*
 * as_ring_peek / as_ring_pop - 查看队首 / 弹出（slot 指针移交调用方，
 * 字符串由调用方 free）。
 */
const struct as_ring_slot *as_ring_peek(const struct as_ring *r);

void as_ring_pop(struct as_ring *r, struct as_ring_slot *out);

#endif /* _AS_RING_H */
