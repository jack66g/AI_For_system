/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_sme.c - SME 写入通道（POST /memories via sme_add_ex；不可达入环）
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ai_types.h"
#include "memory/sme_client.h"

#include "as_sme.h"
#include "as_util.h"

/* JSON 字符串转义（语义对齐 memory/sme_client.c 的 ai_json_escape：
 * 引号/反斜杠/控制字符 → \u00XX，UTF-8 多字节透传） */
static int jesc(const char *in, char *out, size_t cap)
{
	size_t o = 0;

	if (!in || !out || cap < 2)
		return -1;
	for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
		char tmp[8];

		if (*p == '"' || *p == '\\') {
			tmp[0] = '\\';
			tmp[1] = (char)*p;
			tmp[2] = '\0';
		} else if (*p < 0x20) {
			snprintf(tmp, sizeof(tmp), "\\u%04x", *p);
		} else {
			tmp[0] = (char)*p;
			tmp[1] = '\0';
		}
		{
			size_t l = strlen(tmp);

			if (o + l + 1 >= cap)
				return -1;
			memcpy(out + o, tmp, l);
			o += l;
		}
	}
	out[o] = '\0';
	return 0;
}

int as_sme_init(struct as_sme *s, struct as_conf *c, struct as_stats *st)
{
	memset(s, 0, sizeof(*s));
	s->conf = c;
	s->stats = st;
	if (as_ring_init(&s->ring, c->ring_size) != 0)
		return -1;
	/* sme_base_url() 读环境变量 SME_URL；conf 值在此统一注入 */
	setenv("SME_URL", c->sme_url, 1);
	return 0;
}

void as_sme_free(struct as_sme *s)
{
	as_ring_free(&s->ring);
}

void as_sme_build(const struct as_event *ev, const struct as_conf *c,
		  char *text, size_t textcap, char *meta, size_t metacap,
		  char *tags, size_t tagscap)
{
	char cat[48];

	/* text：一行文本（聚合记录已带 repeats=N 后缀） */
	snprintf(text, textcap, "%s", ev->line);

	/* category 用于 metadata/tags（uevent 的 action 来自内核报文，
	 * 统一过 JSON 转义防注入） */
	jesc(ev->category, cat, sizeof(cat));

	/* metadata：固定字段序（冻结；检索/审计依赖） */
	{
		int n = snprintf(meta, metacap,
				 "{\"src\":\"kernel_evt\",\"ts\":%lld,"
				 "\"stream\":\"%s\",\"category\":\"%s\","
				 "\"severity\":\"%s\",\"digest\":\"%s\"",
				 ev->ts_real_ms, ev->stream, cat,
				 ev->severity, ev->digest_hex);

		if (n < 0 || (size_t)n >= metacap) {
			snprintf(meta, metacap, "{\"src\":\"kernel_evt\","
				 "\"ts\":0,\"stream\":\"%s\",\"category\":"
				 "\"overflow\",\"severity\":\"info\","
				 "\"digest\":\"%s\"", ev->stream,
				 ev->digest_hex);
			n = (int)strlen(meta);
		}
		if (ev->merged_count > 1)
			n += snprintf(meta + n, metacap - (size_t)n,
				      ",\"count\":%d", ev->merged_count);
		if (ev->has_decision_id)
			n += snprintf(meta + n, metacap - (size_t)n,
				      ",\"decision_id\":%llu",
				      ev->decision_id);
		snprintf(meta + n, metacap - (size_t)n, "}");
	}

	/* tags：["kernel_evt","stream:<名>","cat:<分类>"] */
	snprintf(tags, tagscap, "[\"kernel_evt\",\"stream:%s\",\"cat:%s\"]",
		 ev->stream, cat);
	(void)c;
}

int as_sme_post(struct as_sme *s, const char *text, const char *meta,
		const char *tags)
{
	struct sme_add_opts o;
	char out[SME_OUT_BUF_MIN];
	int rc;

	memset(&o, 0, sizeof(o));
	o.text = text;
	o.metadata_json = meta;
	o.tags_json = tags;
	o.has_importance = 1;
	o.importance = s->conf->importance;
	o.source = "kernel_evt";
	rc = sme_add_ex(&o, out, sizeof(out));
	s->stats->sme_ok = (rc == AI_OK) ? 1 : 0;
	if (rc != AI_OK)
		as_log_debug("sme POST failed rc=%d out=%.120s", rc, out);
	return rc == AI_OK ? 0 : -1;
}

void as_sme_deliver(struct as_sme *s, const struct as_event *ev)
{
	char text[AS_TEXT_MAX], meta[AS_META_MAX], tags[AS_TAGS_MAX];

	as_sme_build(ev, s->conf, text, sizeof(text), meta, sizeof(meta),
		     tags, sizeof(tags));
	if (as_sme_post(s, text, meta, tags) == 0) {
		as_stats_written(s->stats, ev->stream_idx);
		return;
	}
	/* 不可达 → 有界环形缓冲（丢旧不丢新） */
	s->stats->sme_fail++;
	{
		struct as_ring_slot dropped;

		if (as_ring_push(&s->ring, text, meta, tags, ev->stream_idx,
				 &dropped) == 0 && dropped.text) {
			s->stats->per[dropped.stream_idx].buffer_dropped++;
			as_warn_ratelimit("ring-drop", 60000,
					  "SME down: ring full, dropped oldest"
					  " (stream=%s, total_dropped=%lld)",
					  as_stream_name(dropped.stream_idx),
					  s->ring.dropped);
			free(dropped.text);
			free(dropped.meta);
			free(dropped.tags);
		}
	}
	as_warn_ratelimit("sme-down", 60000,
			  "SME unreachable (%s), buffering (ring=%d/%d)",
			  s->conf->sme_url, as_ring_count(&s->ring),
			  s->ring.cap);
}

int as_sme_flush(struct as_sme *s)
{
	int flushed = 0;

	while (as_ring_count(&s->ring) > 0) {
		const struct as_ring_slot *slot = as_ring_peek(&s->ring);
		struct as_ring_slot popped;
		int idx;

		if (!slot)
			break;
		if (as_sme_post(s, slot->text, slot->meta, slot->tags) != 0)
			break;	/* 首个失败即停，保序 */
		idx = slot->stream_idx;
		as_ring_pop(&s->ring, &popped);
		free(popped.text);
		free(popped.meta);
		free(popped.tags);
		as_stats_written(s->stats, idx);
		s->stats->sme_flushed++;
		flushed++;
	}
	if (flushed > 0)
		as_log("SME recovered: flushed %d buffered events", flushed);
	return flushed;
}
