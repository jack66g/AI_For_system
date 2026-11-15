/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_feat.h - AIPD-M1 特征输入面：ai_feature_vec 冻结镜像 + 源抽象
 *
 * 契约锚：~/linux-k2/AIKernel/senses/ai_features.h:42-51（48B 冻结，
 * per-CPU+seqlock，1Hz 采样发布）。本文件为用户态只读镜像（k7feat.c
 * 手法：协议常量自搓，不引内核头）；偏移由 _Static_assert 锁死。
 *
 * 源抽象（conf FEAT_SOURCE）：
 *   map35 = 裸 bpf() syscall（BPF_MAP_TYPE_AI_FEATURES=35；attr 按偏移
 *           镜像打包，不引 libbpf——k7feat.c 先例）；每 CPU LOOKUP
 *           取 seq 最新槽；
 *   mock  = jsonl 逐行（字段镜像 ai_feature_vec；坏行计数跳过）——
 *           测试/无 map 宿主（FEAT_MOCK_FILE）。
 *
 * 新鲜度（冻结合同）：ts 距今 > 3×采样期 → stale（采样期=内核发布周期
 * 1s 与 aipd 轮询周期 1/POLL_HZ 取较大者；POLL_HZ=10 时阈值=3s）。
 * stale 时决策照出但打 AIP_DF_STALE 位（诚实报告，不静默）。
 *
 * map35 不可用（EPERM/ENOSYS/EINVAL=非 AI 内核）时：按 conf
 * FEAT_DEGRADE_MOCK 诚实失败（默认，exit 1）或降级 mock+计数。
 */
#ifndef _AIP_FEAT_H
#define _AIP_FEAT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "aip_conf.h"

/* ---- ai_feature_vec 冻结镜像（48B；偏移锁死） ---- */
struct aip_fvec {
	uint64_t seq;		/* @0  per-CPU 单调采样序号（seqlock 奇偶相） */
	uint64_t ts;		/* @8  ktime_get_ns()（CLOCK_MONOTONIC 域） */
	uint64_t lat_ewma_ns;	/* @16 sched latency EWMA（ns） */
	uint32_t iowait_pct;	/* @24 0..100 */
	uint32_t psi_mem_some;	/* @28 PSI mem some avg10 定点 0..2048 */
	uint64_t cache_misses;	/* @32 v1 恒 0 */
	uint32_t valid_bits;	/* @40 AIP_VALID_* 掩码 */
	uint32_t rsv;		/* @44 保留恒 0 */
};

#define AIP_FVEC_SZ		48
/* 内核采样发布周期（设计册头注：1Hz） */
#define AIP_FEAT_KERNEL_PERIOD_NS	1000000000ULL

struct aip_feat_src {
	int type;			/* AIP_FEAT_MAP35 / AIP_FEAT_MOCK */
	int map_fd;			/* map35：BPF map fd（-1=非 map35） */
	FILE *mockf;			/* mock：jsonl 文件（NULL=未开） */
	unsigned ncpu;			/* map35：轮询 CPU 覆盖面 */
	unsigned cpu_cursor;		/* map35：逐 CPU 轮转游标 */
	long long stale_thresh_ns;	/* 新鲜度阈值（开算一次） */
	char mock_path[256];		/* mock：jsonl 路径（journal 审计） */
	int mock_degraded;		/* 1=map35 失败降级来的 mock（诚实标） */
	int have_line;			/* mock：已成功读入至少一行 */
	struct aip_fvec last;		/* mock：EOF 复用的最后向量 */

	/* 计数（stats 面） */
	unsigned long long polls;	/* aip_feat_poll 调用数 */
	unsigned long long ok;		/* 成功取得向量数 */
	unsigned long long errors;	/* 源读失败（map error/文件读失败） */
	unsigned long long bad_lines;	/* mock 坏行跳过 */
	unsigned long long stale_polls;	/* stale 判定数 */
	unsigned long long empty_polls;	/* 无可用槽（全 CPU ENOENT/EOF 未初始化） */
};

enum {
	AIP_FEAT_MAP35 = 0,
	AIP_FEAT_MOCK = 1,
};

/*
 * aip_feat_open - 按配置开源。
 *   map35：BPF_MAP_CREATE(type=35, key_size=4)；失败按
 *   conf->feat_degrade_mock 降级（mock 文件须可用）或返回 -1（err 收
 *   原因；守护启动 exit 1=诚实失败）。
 *   mock：打开 conf->feat_mock_file（FEAT_SOURCE=mock 时必须非空）。
 * 返回 0；-1 失败（err 人读原因）。
 */
int aip_feat_open(struct aip_feat_src *f, const struct aip_conf *c,
		  char *err, size_t errcap);

/*
 * aip_feat_poll - 取最新特征向量。
 *   map35：逐 CPU LOOKUP（游标轮转，一轮覆盖 ncpu），取 seq 最大槽；
 *   mock：读下一行 jsonl（EOF=复用最后向量）。
 *   *stale 置 1 当 ts 距今 > stale_thresh_ns（ts 与 CLOCK_MONOTONIC
 *   同域比较）。
 * 返回 0 成功（out/stale 已写）；-1 本轮失败（errors++，out 零值，
 * 调用方跳过本轮决策——单路失败降级不退出）。
 */
int aip_feat_poll(struct aip_feat_src *f, struct aip_fvec *out, int *stale);

/* 释放（关 fd/FILE*；幂等） */
void aip_feat_close(struct aip_feat_src *f);

/* ---- 纯函数（单测冻结口径） ---- */

/*
 * aip_mock_parse_line - 解析一行 mock jsonl → 向量。
 * 字段（全 8 个必填，缺任一=坏行）：seq/ts/lat_ewma_ns/iowait_pct/
 * psi_mem_some/cache_misses/valid_bits（rsv 不出现，恒 0）。
 * 0=成功；-1=坏行（调用方 bad_lines++ 跳过）。
 */
int aip_mock_parse_line(const char *line, struct aip_fvec *out);

/* ts 距今（CLOCK_MONOTONIC ns）> thresh → 1；ts==0（从未发布）→ 1 */
int aip_feat_is_stale(uint64_t ts, long long thresh_ns);

/*
 * aip_feat_pack_create - BPF_MAP_CREATE attr 打包（k7feat selftest 同
 * 口径单测锚：map_type=35 LE@0、key_size=4 LE@4）。attr 容量 128。
 */
#define AIP_BPF_ATTR_SZ		128
int aip_feat_pack_create(unsigned char attr[AIP_BPF_ATTR_SZ]);

#endif /* _AIP_FEAT_H */
