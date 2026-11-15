/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_model.c - aip_decide 纯函数边界（每规则命中/不命中/阈值边界/
 * 多命中首出+hits 计数/valid_bits 可信门/非法参数）
 */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "aip_feat.h"
#include "aip_model.h"
#include "aip_table.h"

static int fails, checks;

#define CHECK(cond, msg) do { \
	checks++; \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

/* 可信全位基向量（全低值=无命中） */
static struct aip_fvec base_vec(void)
{
	struct aip_fvec v;

	memset(&v, 0, sizeof(v));
	v.valid_bits = AIP_VALID_LAT | AIP_VALID_IOWAIT | AIP_VALID_PSI;
	v.seq = 7;
	v.ts = 123456789;
	v.lat_ewma_ns = 100000;		/* 0.1ms */
	v.iowait_pct = 3;
	v.psi_mem_some = 50;		/* ~2.4% */
	return v;
}

int main(void)
{
	struct aip_fvec v;
	struct aip_decision d;
	uint64_t hits[AIP_RULES_MAX];

	/* 表自校验前置（本测依赖内置表阈值：409/1e7/20） */
	{
		char err[128];

		if (aip_table_check(err, sizeof(err)) != 0) {
			printf("FAIL: table self-check: %s\n", err);
			return 1;
		}
	}

	/* ---- 1) 内置表：无命中 ---- */
	v = base_vec();
	memset(hits, 0, sizeof(hits));
	CHECK(aip_decide(&v, aip_rules, aip_nrules, hits, &d) == 0,
	      "decide ok");
	CHECK(d.rule_idx == -1 && d.action == AIP_ACT_NONE &&
	      !(d.flags & AIP_DF_HIT), "low vector no hit");
	CHECK(d.reason[0] == '\0', "no-hit reason empty");

	/* ---- 2) 规则 1（psi_mem_some>409） ---- */
	v = base_vec();
	v.psi_mem_some = 410;
	memset(hits, 0, sizeof(hits));
	CHECK(aip_decide(&v, aip_rules, aip_nrules, hits, &d) == 0 &&
	      d.rule_idx == 0 && d.action == AIP_ACT_RECLAIM_AGGRESSIVE &&
	      d.feat_val == 410 && (d.flags & AIP_DF_HIT) &&
	      hits[0] == 1 && d.reason[0] != '\0', "psi hit @410");
	v.psi_mem_some = 409;
	memset(hits, 0, sizeof(hits));
	CHECK(aip_decide(&v, aip_rules, aip_nrules, hits, &d) == 0 &&
	      d.rule_idx == -1 && hits[0] == 0,
	      "psi boundary 409 no hit (strict >)");

	/* ---- 3) 规则 2（lat_ewma_ns>10000000） ---- */
	v = base_vec();
	v.lat_ewma_ns = 10000001;
	memset(hits, 0, sizeof(hits));
	CHECK(aip_decide(&v, aip_rules, aip_nrules, hits, &d) == 0 &&
	      d.rule_idx == 1 && d.action == AIP_ACT_SCHED_COMPENSATE,
	      "lat hit @10000001");
	v.lat_ewma_ns = 10000000;
	CHECK(aip_decide(&v, aip_rules, aip_nrules, NULL, &d) == 0 &&
	      d.rule_idx == -1, "lat boundary 10000000 no hit");

	/* ---- 4) 规则 3（iowait_pct>20） ---- */
	v = base_vec();
	v.iowait_pct = 21;
	CHECK(aip_decide(&v, aip_rules, aip_nrules, NULL, &d) == 0 &&
	      d.rule_idx == 2 && d.action == AIP_ACT_READAHEAD_BOOST,
	      "iowait hit @21");
	v.iowait_pct = 20;
	CHECK(aip_decide(&v, aip_rules, aip_nrules, NULL, &d) == 0 &&
	      d.rule_idx == -1, "iowait boundary 20 no hit");

	/* ---- 5) 多命中：首命中单出+hits 全计 ---- */
	v = base_vec();
	v.psi_mem_some = 1000;
	v.lat_ewma_ns = 20000000;
	v.iowait_pct = 50;
	memset(hits, 0, sizeof(hits));
	CHECK(aip_decide(&v, aip_rules, aip_nrules, hits, &d) == 0 &&
	      d.rule_idx == 0 && d.action == AIP_ACT_RECLAIM_AGGRESSIVE,
	      "multi-hit first wins (contract)");
	CHECK(hits[0] == 1 && hits[1] == 1 && hits[2] == 1,
	      "all hits counted");

	/* ---- 6) valid_bits 可信门：缺位=跳过（值再高也不触发） ---- */
	v = base_vec();
	v.psi_mem_some = 1000;
	v.valid_bits = AIP_VALID_LAT | AIP_VALID_IOWAIT;	/* 无 PSI 位 */
	CHECK(aip_decide(&v, aip_rules, aip_nrules, NULL, &d) == 0 &&
	      d.rule_idx == -1, "psi rule skipped without VALID_PSI bit");
	v = base_vec();
	v.psi_mem_some = 1000;
	v.lat_ewma_ns = 20000000;
	v.iowait_pct = 50;
	v.valid_bits = 0;			/* 全不可信 */
	CHECK(aip_decide(&v, aip_rules, aip_nrules, NULL, &d) == 0 &&
	      d.rule_idx == -1, "all gated rules skipped @valid_bits=0");

	/* ---- 7) 非法参数 ---- */
	v = base_vec();
	CHECK(aip_decide(&v, aip_rules, 0, NULL, &d) == -1, "n=0 rejected");
	CHECK(aip_decide(NULL, aip_rules, aip_nrules, NULL, &d) == -1,
	      "NULL vec rejected");
	CHECK(aip_decide(&v, NULL, aip_nrules, NULL, &d) == -1,
	      "NULL rules rejected");
	CHECK(aip_decide(&v, aip_rules, aip_nrules, NULL, NULL) == -1,
	      "NULL out rejected");

	/* ---- 8) 自定义规则（生成器语义面：IN_RANGE/GT/SEQ 恒可信） ---- */
	{
		struct ai_rule r[2];

		memset(r, 0, sizeof(r));
		r[0].feat = AIP_F_IOWAIT_PCT;
		r[0].op = AIP_OP_IN_RANGE;
		r[0].lo = 10;
		r[0].hi = 20;
		r[0].action = AIP_ACT_READAHEAD_BOOST;
		r[1].feat = AIP_F_SEQ;
		r[1].op = AIP_OP_GT;
		r[1].lo = 5;
		r[1].action = AIP_ACT_SCHED_COMPENSATE;
		v = base_vec();
		v.iowait_pct = 10;		/* IN_RANGE 闭区间下沿 */
		CHECK(aip_decide(&v, r, 2, NULL, &d) == 0 &&
		      d.rule_idx == 0, "IN_RANGE lo inclusive");
		v.iowait_pct = 20;		/* 上沿 */
		CHECK(aip_decide(&v, r, 2, NULL, &d) == 0 && d.rule_idx == 0,
		      "IN_RANGE hi inclusive");
		v.iowait_pct = 21;
		v.seq = 7;			/* SEQ 恒可信：规则 1 命中 */
		CHECK(aip_decide(&v, r, 2, NULL, &d) == 0 &&
		      d.rule_idx == 1 && d.feat_val == 7,
		      "fallthrough to SEQ rule (always trusted)");
		v.iowait_pct = 21;
		v.seq = 5;
		CHECK(aip_decide(&v, r, 2, NULL, &d) == 0 &&
		      d.rule_idx == -1, "SEQ GT boundary no hit");
	}

	if (fails) {
		printf("test_model: %d failures (%d checks)\n", fails,
		       checks);
		return 1;
	}
	printf("test_model: OK (%d checks)\n", checks);
	return 0;
}
