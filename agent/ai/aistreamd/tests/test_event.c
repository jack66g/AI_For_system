/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_event.c - 事件规范化单测（冻结 fixture 逐字节）+ 去重窗口语义
 *
 * 行格式见 as_event.h 注释（冻结）。ts/digest 动态，断言只对文本行与
 * 结构字段；digest 稳定性单独断言（同输入同 digest，异输入异 digest）。
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "as_event.h"
#include "as_util.h"

static int fails;

/* 聚合收集器 */
struct agg_collector {
	struct as_event ev[8];
	int n;
};

static void collect_agg(struct as_event *agg, void *u)
{
	struct agg_collector *c = u;

	if (c->n < 8)
		c->ev[c->n++] = *agg;
}

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

#define CHECK_LINE(ev, expect) do { \
	if (strcmp((ev)->line, expect) != 0) { \
		printf("FAIL: line mismatch\n  got:  [%s]\n  want: [%s]\n", \
		       (ev)->line, expect); \
		fails++; \
	} \
} while (0)

int main(void)
{
	struct as_event ev;

	/* ---- 冻结 fixture：一行文本逐字节 ---- */
	as_event_proc_fork(&ev, 1, 42);
	CHECK_LINE(&ev, "[kern] proc fork parent=1 child=42");
	CHECK(ev.stream_idx == as_stream_idx("proc"), "fork stream");
	CHECK(strcmp(ev.category, "fork") == 0, "fork category");

	as_event_proc_exec(&ev, 4242);
	CHECK_LINE(&ev, "[kern] proc exec pid=4242");

	as_event_proc_exit(&ev, 4242, 0);
	CHECK_LINE(&ev, "[kern] proc exit pid=4242 code=0");

	as_event_proc_comm(&ev, 777, "sshd");
	CHECK_LINE(&ev, "[kern] proc comm pid=777 comm=sshd");

	as_event_proc_id(&ev, "uid", 9, 1000, 0);
	CHECK_LINE(&ev, "[kern] proc uid pid=9 ruid=1000 euid=0");

	/* 决策事件：decision_id 原样透传（审计链关键） */
	as_event_ai_policy(&ev, 4711, 2, NULL, "mm.swappiness");
	CHECK_LINE(&ev,
		   "[kern] event policy decision_id=4711 executed=2 "
		   "param=mm.swappiness");
	CHECK(ev.has_decision_id == 1 && ev.decision_id == 4711,
	      "decision_id verbatim");
	CHECK(strcmp(ev.severity, "info") == 0, "default sev info");

	as_event_ai_policy(&ev, 999999999999ULL, 0, "warn", "net.qdisc");
	CHECK_LINE(&ev,
		   "[kern] event policy decision_id=999999999999 executed=0"
		   " param=net.qdisc sev=warn");
	CHECK(strcmp(ev.severity, "warn") == 0, "sev warn");

	as_event_ai_model(&ev, 5, 1, "vmp-logic-v3");
	CHECK_LINE(&ev, "[kern] event model id=5 op=load name=vmp-logic-v3");

	as_event_net_link(&ev, 1, 2, "lo", 0x10049);
	CHECK_LINE(&ev, "[kern] net newlink if=2 name=lo flags=0x10049");

	as_event_net_link(&ev, 0, 9, "k3cnet7", 0x0);
	CHECK_LINE(&ev, "[kern] net dellink if=9 name=k3cnet7 flags=0x0");

	as_event_net_addr(&ev, 1, "inet", "10.0.2.15", 24, 2);
	CHECK_LINE(&ev, "[kern] net newaddr if=2 family=inet addr=10.0.2.15/24");

	as_event_net_route(&ev, 1, "inet", "10.0.2.0", 24, 2, "10.0.2.2");
	CHECK_LINE(&ev, "[kern] net newroute family=inet dst=10.0.2.0/24 "
		   "oif=2 gw=10.0.2.2");

	as_event_net_route(&ev, 0, "inet6", "fd00::", 64, 3, NULL);
	CHECK_LINE(&ev, "[kern] net delroute family=inet6 dst=fd00::/64 oif=3");

	as_event_uevent(&ev, "add", "/devices/virtual/block/loop9", "block");
	CHECK_LINE(&ev, "[kern] uevent add dev=/devices/virtual/block/loop9 "
		   "subsystem=block");

	as_event_nflog(&ev, 2, 0, "k3c-deny", 1, 0);
	CHECK_LINE(&ev, "[kern] nflog packet hook=2 mark=0 prefix=k3c-deny uid=0");

	as_event_nflog(&ev, 3, 7, NULL, 0, 0);
	CHECK_LINE(&ev, "[kern] nflog packet hook=3 mark=7");

	as_event_taskstats(&ev, 187, 1234.5, 88.25, 3);
	CHECK_LINE(&ev, "[kern] taskstats sample pids=187 cpu_delay_ms=1234.5 "
		   "blkio_delay_ms=88.2 swapin=3");

	/* ---- digest 稳定性 ---- */
	struct as_event a, b;

	as_event_proc_exec(&a, 100);
	as_event_proc_exec(&b, 100);
	CHECK(a.digest == b.digest, "same input same digest");
	as_event_proc_exec(&b, 101);
	CHECK(a.digest != b.digest, "different input different digest");
	as_digest_hex(a.digest, a.digest_hex);
	CHECK(strlen(a.digest_hex) == 16, "digest hex 16 chars");

	/* ---- 去重窗口语义 ---- */
	struct as_dedup d;
	long long t = as_now_real_ms();

	as_dedup_init(&d, 10000);
	as_event_proc_exec(&a, 555);
	CHECK(as_dedup_filter(&d, &a, t) == AS_DEDUP_PASS, "first passes");
	CHECK(as_dedup_filter(&d, &a, t + 1000) == AS_DEDUP_SUPPRESS,
	      "dup in window suppressed");
	CHECK(as_dedup_filter(&d, &a, t + 2000) == AS_DEDUP_SUPPRESS,
	      "dup suppressed again");
	as_event_proc_exec(&b, 556);
	CHECK(as_dedup_filter(&d, &b, t + 3000) == AS_DEDUP_PASS,
	      "different digest passes");
	/* 窗口内 flush：不产出 */
	{
		struct agg_collector col = { .n = 0 };

		as_dedup_flush(&d, t + 5000, collect_agg, &col);
		CHECK(col.n == 0, "no flush before window end");
	}
	/* 窗口结束 flush：1 条聚合（suppressed=2 → repeats=2，
	 * merged_count=3：首条 + 2 条被抑制） */
	{
		struct agg_collector col = { .n = 0 };

		as_dedup_flush(&d, t + 11000, collect_agg, &col);
		CHECK(col.n == 1, "one aggregate flushed");
		if (col.n == 1) {
			CHECK(strcmp(col.ev[0].line,
				     "[kern] proc exec pid=555 repeats=2")
			      == 0, "aggregate line with repeats=2");
			CHECK(col.ev[0].merged_count == 3, "merged_count=3");
		}
	}
	/* 窗口过期后同 digest 再现＝新窗口首见 */
	CHECK(as_dedup_filter(&d, &a, t + 12000) == AS_DEDUP_PASS,
	      "after window expiry first again");

	if (fails) {
		printf("test_event: %d failures\n", fails);
		return 1;
	}
	printf("test_event: OK\n");
	return 0;
}
