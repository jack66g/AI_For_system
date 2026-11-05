/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_sme.h - SME 写入通道（POST /memories，复用 memory/sme_client.c）
 *
 * 请求体契约（AddMemoryRequest，agent/ai/smehttp/routes.c）：
 *   {"text": <一行文本>,
 *    "metadata": {"src":"kernel_evt","ts":<epoch_ms>,"stream":..,
 *                 "category":..,"severity":..,"digest":..,
 *                 [,"count":N][,"decision_id":D]},
 *    "tags": ["kernel_evt","stream:<名>","cat:<分类>"],
 *    "importance": <conf，默认 0.3>,
 *    "source": "kernel_evt"}
 *
 * 失败语义：SME 不可达/非 2xx → 事件三元组入有界环形缓冲（丢旧不丢新），
 * 周期重试按序补写。绝不静默吞（计数 + journal 限频告警）。
 */
#ifndef _AS_SME_H
#define _AS_SME_H

#include "as_conf.h"
#include "as_event.h"
#include "as_ring.h"
#include "as_stats.h"

#define AS_TEXT_MAX (AS_LINE_MAX + 32)
#define AS_META_MAX 640
#define AS_TAGS_MAX 128

struct as_sme {
	struct as_conf *conf;
	struct as_stats *stats;
	struct as_ring ring;
};

int as_sme_init(struct as_sme *s, struct as_conf *c, struct as_stats *st);

void as_sme_free(struct as_sme *s);

/*
 * as_sme_build - 由事件构造记忆三元组（text / metadata JSON / tags JSON）。
 * 纯函数——单测对 mock server 的请求体逐字节断言用同一路径。
 */
void as_sme_build(const struct as_event *ev, const struct as_conf *c,
		  char *text, size_t textcap, char *meta, size_t metacap,
		  char *tags, size_t tagscap);

/* 内部：单次 POST（成功 0；失败 -1，并记 stats->sme_ok） */
int as_sme_post(struct as_sme *s, const char *text, const char *meta,
		const char *tags);

/*
 * as_sme_deliver - 直写；失败入环形缓冲（满则丢旧+计数+限频告警）。
 */
void as_sme_deliver(struct as_sme *s, const struct as_event *ev);

/*
 * as_sme_flush - 按序补写环形缓冲；首个失败即停（重试定时器再进）。
 * 返回本轮补写成功条数。
 */
int as_sme_flush(struct as_sme *s);

#endif /* _AS_SME_H */
