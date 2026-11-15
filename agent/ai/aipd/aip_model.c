/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_model.c - 纯函数决策入口 + bench 测点（schema 冻结见 aip_model.h）
 *
 * 决策合同（头文件详注）：按序首命中单出 + hits 计数 + valid_bits
 * 可信门。无 IO/时钟/全局态——p99<1ms 验收（设计 §1.3）的本体。
 *
 * M1 影子语义：本文件与全模块**无任何 ACT 下发代码路径**（executed
 * 恒 0；不碰 NETLINK_AI ACT）。
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aip_feat.h"
#include "aip_model.h"
#include "aip_table.h"

int aip_feat_value(const struct aip_fvec *v, uint32_t feat, int64_t *out)
{
	if (!v || !out || feat >= AIP_FEAT_MAX)
		return -1;
	switch ((enum aip_feat)feat) {
	case AIP_F_SEQ:		*out = (int64_t)v->seq; break;
	case AIP_F_TS:		*out = (int64_t)v->ts; break;
	case AIP_F_LAT_EWMA_NS:	*out = (int64_t)v->lat_ewma_ns; break;
	case AIP_F_IOWAIT_PCT:	*out = (int64_t)v->iowait_pct; break;
	case AIP_F_PSI_MEM_SOME: *out = (int64_t)v->psi_mem_some; break;
	case AIP_F_CACHE_MISSES: *out = (int64_t)v->cache_misses; break;
	case AIP_F_VALID_BITS:	*out = (int64_t)v->valid_bits; break;
	default:		return -1;
	}
	return 0;
}

int aip_feat_trusted(const struct aip_fvec *v, uint32_t feat)
{
	if (!v || feat >= AIP_FEAT_MAX)
		return 0;
	switch ((enum aip_feat)feat) {
	case AIP_F_LAT_EWMA_NS:
		return (v->valid_bits & AIP_VALID_LAT) != 0;
	case AIP_F_IOWAIT_PCT:
		return (v->valid_bits & AIP_VALID_IOWAIT) != 0;
	case AIP_F_PSI_MEM_SOME:
		return (v->valid_bits & AIP_VALID_PSI) != 0;
	case AIP_F_CACHE_MISSES:
		return (v->valid_bits & AIP_VALID_CACHE) != 0;
	default:
		return 1;		/* SEQ/TS/VALID_BITS 恒可信 */
	}
}

int aip_decide(const struct aip_fvec *v, const struct ai_rule *rules,
	       size_t n, uint64_t *hits, struct aip_decision *out)
{
	int found = 0;

	if (!v || !rules || !out || n == 0 || n > AIP_RULES_MAX)
		return -1;
	memset(out, 0, sizeof(*out));
	out->rule_idx = -1;
	out->action = AIP_ACT_NONE;
	for (size_t i = 0; i < n; i++) {
		const struct ai_rule *r = &rules[i];
		int64_t x;
		int hit;

		if (!aip_feat_trusted(v, r->feat))
			continue;	/* 值不可信：跳过（诚实降级） */
		if (aip_feat_value(v, r->feat, &x) != 0)
			continue;
		if (r->op == AIP_OP_GT)
			hit = x > r->lo;
		else			/* AIP_OP_IN_RANGE：闭区间 */
			hit = x >= r->lo && x <= r->hi;
		if (!hit)
			continue;
		if (hits)
			hits[i]++;
		if (!found) {		/* 首命中单出（冻结合同） */
			found = 1;
			out->rule_idx = (int64_t)i;
			out->action = r->action;
			out->param = r->param;
			out->feat_val = x;
			out->flags |= AIP_DF_HIT;
			snprintf(out->reason, sizeof(out->reason), "%s",
				 r->reason);
		}
	}
	return 0;
}

/* ---- bench 子命令（aipd bench；Lane-B m1_bench.py 解析 AIPD_BENCH 行） ---- */

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y ? 1 : 0;
}

static uint64_t mono_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int aip_bench_run(long n)
{
	static const size_t NVAR = 8;
	/* 合成向量循环：覆盖 无命中×2 / 三规则各自命中与阈值边界
	 * （=lo 不命中、=lo+1 命中）/ 多规则同命中（首命中合同路径） */
	struct aip_fvec vars[8];
	uint64_t *lat;
	uint64_t hits[AIP_RULES_MAX];
	struct aip_decision d;

	if (n < 1 || n > 10000000) {
		fprintf(stderr, "aipd: bench --n range is 1..10000000\n");
		return -1;
	}
	memset(vars, 0, sizeof(vars));
	/* 0/1：全零（无 valid_bits→全跳过=无命中路径） */
	vars[0].valid_bits = 0;
	/* 1：可信但全部低值=无命中 */
	vars[1].valid_bits = AIP_VALID_LAT | AIP_VALID_IOWAIT | AIP_VALID_PSI;
	vars[1].seq = 1; vars[1].ts = 1;
	vars[1].lat_ewma_ns = 1000; vars[1].iowait_pct = 1;
	vars[1].psi_mem_some = 10;
	/* 2：psi 命中（>409） */
	vars[2] = vars[1];
	vars[2].psi_mem_some = 410;
	/* 3：psi 边界=409（不命中——严格大于） */
	vars[3] = vars[1];
	vars[3].psi_mem_some = 409;
	/* 4：lat 命中（>1e7） */
	vars[4] = vars[1];
	vars[4].lat_ewma_ns = 10000001;
	/* 5：iowait 命中（>20） */
	vars[5] = vars[1];
	vars[5].iowait_pct = 21;
	/* 6：三规则同命中（首命中=psi 规则；合同路径） */
	vars[6] = vars[1];
	vars[6].psi_mem_some = 1000;
	vars[6].lat_ewma_ns = 20000000;
	vars[6].iowait_pct = 50;
	/* 7：seq/ts 大值（泛型覆盖） */
	vars[7] = vars[1];
	vars[7].seq = 0x7fffffffffffULL;
	vars[7].ts = 0x7fffffffffffULL;

	lat = malloc((size_t)n * sizeof(*lat));
	if (!lat) {
		fprintf(stderr, "aipd: bench alloc %ld failed\n", n);
		return -1;
	}
	memset(hits, 0, sizeof(hits));
	for (long i = 0; i < n; i++) {
		uint64_t t0 = mono_ns();

		if (aip_decide(&vars[i % NVAR], aip_rules, aip_nrules,
			       hits, &d) != 0) {
			fprintf(stderr, "aipd: bench decide failed\n");
			free(lat);
			return -1;
		}
		lat[i] = mono_ns() - t0;
	}
	(void)hits;				/* 多命中计数面（bench 不打印） */
	qsort(lat, (size_t)n, sizeof(*lat), cmp_u64);
	{
		size_t i50 = (size_t)((double)(n - 1) * 0.50 + 0.5);
		size_t i99 = (size_t)((double)(n - 1) * 0.99 + 0.5);

		if (i50 >= (size_t)n)
			i50 = (size_t)n - 1;
		if (i99 >= (size_t)n)
			i99 = (size_t)n - 1;
		printf("AIPD_BENCH n=%ld p50_ns=%llu p99_ns=%llu max_ns=%llu\n",
		       n, (unsigned long long)lat[i50],
		       (unsigned long long)lat[i99],
		       (unsigned long long)lat[n - 1]);
	}
	free(lat);
	return 0;
}
