/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_ring.c - 有界环形缓冲（丢旧不丢新）
 */
#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include "as_ring.h"

static char *xstrdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = malloc(n);

	if (p)
		memcpy(p, s, n);
	return p;
}

static void slot_clear(struct as_ring_slot *s)
{
	free(s->text);
	free(s->meta);
	free(s->tags);
	s->text = NULL;
	s->meta = NULL;
	s->tags = NULL;
}

int as_ring_init(struct as_ring *r, long long cap)
{
	memset(r, 0, sizeof(*r));
	if (cap < 1 || cap > 1024 * 1024)
		return -1;
	r->slots = calloc((size_t)cap, sizeof(struct as_ring_slot));
	if (!r->slots)
		return -1;
	r->cap = (int)cap;
	r->head = 0;
	r->len = 0;
	r->dropped = 0;
	return 0;
}

void as_ring_free(struct as_ring *r)
{
	if (!r->slots)
		return;
	for (int i = 0; i < r->len; i++)
		slot_clear(&r->slots[(r->head + i) % r->cap]);
	free(r->slots);
	memset(r, 0, sizeof(*r));
}

int as_ring_count(const struct as_ring *r)
{
	return r->len;
}

int as_ring_push(struct as_ring *r, const char *text, const char *meta,
		 const char *tags, int stream_idx,
		 struct as_ring_slot *dropped_out)
{
	struct as_ring_slot *s;

	if (dropped_out)
		memset(dropped_out, 0, sizeof(*dropped_out));
	/* 满：丢最旧（丢旧不丢新） */
	if (r->len == r->cap) {
		struct as_ring_slot *old = &r->slots[r->head];

		if (dropped_out)
			*dropped_out = *old;	/* 移交所有权 */
		else
			slot_clear(old);
		r->head = (r->head + 1) % r->cap;
		r->len--;
		r->dropped++;
	}
	s = &r->slots[(r->head + r->len) % r->cap];
	s->text = xstrdup(text);
	s->meta = xstrdup(meta ? meta : "");
	s->tags = xstrdup(tags ? tags : "");
	s->stream_idx = stream_idx;
	if (!s->text || !s->meta || !s->tags) {
		slot_clear(s);
		return -1;
	}
	r->len++;
	r->pushed++;
	return 0;
}

const struct as_ring_slot *as_ring_peek(const struct as_ring *r)
{
	if (r->len == 0)
		return NULL;
	return &r->slots[r->head];
}

void as_ring_pop(struct as_ring *r, struct as_ring_slot *out)
{
	if (r->len == 0) {
		memset(out, 0, sizeof(*out));
		return;
	}
	*out = r->slots[r->head];
	r->slots[r->head].text = NULL;
	r->slots[r->head].meta = NULL;
	r->slots[r->head].tags = NULL;
	r->head = (r->head + 1) % r->cap;
	r->len--;
	r->popped++;
}
