/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_cmp.c - 对照 mismatch 滚动窗（双流冻结合同）+ 行解析（mock/proc）
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "aip_shadow.h"

static int fails, checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

int main(void)
{
	struct aip_cmp m;
	unsigned long long id;
	uint32_t action;

	/* ---- 1) mock 对照行解析 ---- */
	CHECK(aip_cmp_parse_mock_line("{\"decision_id\":3,\"action\":1}",
				      &id, &action) == 0 && id == 3 &&
	      action == 1, "mock line parses");
	CHECK(aip_cmp_parse_mock_line("{\"action\":2,\"decision_id\":9}",
				      &id, &action) == 0 && id == 9 &&
	      action == 2, "mock line order agnostic");
	CHECK(aip_cmp_parse_mock_line("{\"decision_id\":3}", &id,
				       &action) != 0,
	      "mock line missing action rejected");
	CHECK(aip_cmp_parse_mock_line("garbage", &id, &action) != 0,
	      "mock garbage rejected");

	/* ---- 2) proc 决策行解析（as_decisions 同源 23 字段） ---- */
	CHECK(aip_cmp_parse_proc_line("id=5 trig_ts=100 trig_evid=0x0042 "
		"dec_ts=200 type=3 data=1:2:3:4:5:6:7:8 exec_ts=300 "
		"outcome_ts=400 outcome=0 delta=0 ver=1 conf=80 domain=2 "
		"src=1 executed=0 safety_clamped=0", &id, &action) == 0 &&
	      id == 5 && action == 3, "proc line parses (id/type)");
	CHECK(aip_cmp_parse_proc_line("id=5 truncated", &id, &action) != 0,
	      "proc bad line rejected");

	/* ---- 3) 无影子=不匹配（诚实：影子未跑，对照全 mismatch） ---- */
	CHECK(aip_cmp_init(&m, 8) == 0, "cmp init");
	CHECK(aip_cmp_pct(&m) == 0.0, "pct 0 on empty");
	aip_cmp_observe(&m, 1, 1);
	CHECK(aip_cmp_pct(&m) == 100.0, "no shadow => 100% mismatch");

	/* ---- 4) 匹配/不匹配（动作面） ---- */
	aip_cmp_shadow(&m, 1);			/* 影子最新 action=1 */
	aip_cmp_observe(&m, 2, 1);		/* 同 action=match */
	CHECK(aip_cmp_pct(&m) == 50.0, "1/2 mismatch after match");
	aip_cmp_observe(&m, 3, 1);
	CHECK(aip_cmp_pct(&m) - 33.33 < 0.01 && aip_cmp_pct(&m) - 33.33 >
	      -0.01, "1/3 mismatch pct");
	CHECK(m.mismatch == 1 && m.matched == 2, "counters");

	/* ---- 5) 窗滚动：满 8 挤出最老，pct 只计窗内 ---- */
	aip_cmp_shadow(&m, 2);			/* 影子换 action=2 */
	for (unsigned long long i = 4; i <= 11; i++)
		aip_cmp_observe(&m, i, (i & 1) ? 1u : 2u);
	/* 窗=ids 4..11（1,2,3 被挤出）：4(2)m 5(1)x 6(2)m 7(1)x 8(2)m
	 * 9(1)x 10(2)m 11(1)x → 4m/4x = 50.00 */
	CHECK(aip_cmp_pct(&m) == 50.0, "rolling window pct 50.0");
	CHECK(m.count == 8, "window full at cap");

	/* ---- 6) 游标推进（摄取去重合同） ---- */
	CHECK(m.have_cursor && m.cursor == 11, "cursor at max id");

	aip_cmp_free(&m);
	aip_cmp_free(&m);			/* 幂等 */

	if (fails) {
		printf("test_cmp: %d failures (%d checks)\n", fails, checks);
		return 1;
	}
	printf("test_cmp: OK (%d checks)\n", checks);
	return 0;
}
