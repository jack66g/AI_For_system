/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_ring.c - 环形缓冲单测（丢旧不丢新、边界容量、顺序、统计）
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "as_ring.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

int main(void)
{
	struct as_ring r;
	struct as_ring_slot d;

	/* ---- 1) 容量 3：边界填满不丢 ---- */
	CHECK(as_ring_init(&r, 3) == 0, "init");
	for (int i = 0; i < 3; i++) {
		char txt[32];

		snprintf(txt, sizeof(txt), "e%d", i);
		CHECK(as_ring_push(&r, txt, "{}", "[]", i % 6, &d) == 0 &&
		      d.text == NULL, "push no drop");
	}
	CHECK(as_ring_count(&r) == 3, "full at cap");
	CHECK(r.dropped == 0, "no drops at cap");

	/* ---- 2) 第 4 条：丢最旧（e0），保新 ---- */
	CHECK(as_ring_push(&r, "e3", "{}", "[]", 3, &d) == 0, "push 4th");
	CHECK(d.text && strcmp(d.text, "e0") == 0, "oldest dropped");
	CHECK(d.stream_idx == 0, "dropped stream_idx");
	free(d.text);
	free(d.meta);
	free(d.tags);
	CHECK(as_ring_count(&r) == 3, "still cap after drop");
	CHECK(r.dropped == 1, "dropped=1");

	/* ---- 3) FIFO 顺序弹出 ---- */
	const struct as_ring_slot *s = as_ring_peek(&r);
	CHECK(s && strcmp(s->text, "e1") == 0, "head is e1");
	struct as_ring_slot popped;
	as_ring_pop(&r, &popped);
	CHECK(strcmp(popped.text, "e1") == 0 && popped.stream_idx == 1,
	      "pop e1");
	free(popped.text);
	free(popped.meta);
	free(popped.tags);
	as_ring_pop(&r, &popped);
	CHECK(strcmp(popped.text, "e2") == 0, "pop e2");
	free(popped.text);
	free(popped.meta);
	free(popped.tags);
	as_ring_pop(&r, &popped);
	CHECK(strcmp(popped.text, "e3") == 0, "pop e3 (newest kept)");
	free(popped.text);
	free(popped.meta);
	free(popped.tags);
	CHECK(as_ring_count(&r) == 0, "empty");
	CHECK(as_ring_peek(&r) == NULL, "peek empty NULL");

	/* ---- 4) 容量 1 边界：每条都挤掉前一条 ---- */
	as_ring_free(&r);
	CHECK(as_ring_init(&r, 1) == 0, "init cap1");
	CHECK(as_ring_push(&r, "a", "m", "t", 0, &d) == 0 && !d.text,
	      "cap1 first");
	CHECK(as_ring_push(&r, "b", "m", "t", 5, &d) == 0 && d.text &&
	      strcmp(d.text, "a") == 0, "cap1 drop a");
	free(d.text);
	free(d.meta);
	free(d.tags);
	CHECK(as_ring_count(&r) == 1 && r.dropped == 1, "cap1 state");
	s = as_ring_peek(&r);
	CHECK(s && strcmp(s->text, "b") == 0 && s->stream_idx == 5,
	      "cap1 keeps newest");

	/* ---- 5) 环绕容量 + 大批量（容量 8 推 100 条，最后 8 条在环） ---- */
	as_ring_free(&r);
	CHECK(as_ring_init(&r, 8) == 0, "init 8");
	for (int i = 0; i < 100; i++) {
		char txt[32];

		snprintf(txt, sizeof(txt), "x%d", i);
		if (as_ring_push(&r, txt, "m", "t", 2, &d) == 0 && d.text) {
			free(d.text);
			free(d.meta);
			free(d.tags);
		}
	}
	CHECK(r.dropped == 92, "dropped 92");
	CHECK(as_ring_count(&r) == 8, "8 remain");
	as_ring_pop(&r, &popped);
	CHECK(strcmp(popped.text, "x92") == 0, "head is x92 (oldest kept)");
	free(popped.text);
	free(popped.meta);
	free(popped.tags);
	as_ring_free(&r);

	/* ---- 6) 非法容量拒绝 ---- */
	CHECK(as_ring_init(&r, 0) == -1, "cap 0 rejected");
	CHECK(as_ring_init(&r, -5) == -1, "cap -5 rejected");

	if (fails) {
		printf("test_ring: %d failures\n", fails);
		return 1;
	}
	printf("test_ring: OK\n");
	return 0;
}
