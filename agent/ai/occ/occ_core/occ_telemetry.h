/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_telemetry.h - occ 会话遥测 → T8 parquet 沉淀（T9d/§9.6）
 *
 * 接入面侦察结论（T9d 报告 §E）：
 *   - aistreamd（aikernel-streams.service）是 **netlink 事件驱动**，进程内
 *     没有任何 HTTP ingest 路由——「8080 现有管线」是事件**出口**（SSE/
 *     统计），不是可写的入水口；因此 occ 侧走「同一条 T8 writer 链」：
 *     直接复用 `aistreamd/as_parquet.c`（writer-only、零第三方库，只依赖
 *     as_snappy.c + libc），写同一套 telemetry 9 列 schema 与同一套目录
 *     布局（`<root>/telemetry/YYYY-MM-DD/ai_NNNN.parquet` + index.parquet）。
 *   - category 固定 18（CAT_NAMES 里的 `ai`），event_type=0（aistreamd
 *     归一化行语义），data = 一行 UTF-8 JSON（零脱敏 all-ai 原则）。
 *   - 默认 root `$HOME/.occ/telemetry`（occ 以用户身份跑，不与 aistreamd
 *     抢同目录的序号扫描——跨进程 next_seq 竞态）；要与内核遥测合流时用
 *     `OCC_PARQUET_ROOT` 指到 aistreamd 的 root（同布局同 schema，只是
 *     目录共享方自行保证写入互斥）。
 *   - 落盘节流：行缓冲 128 条 / 换窗事件即刻 flush / 进程退出 atexit
 *     flush——避免每回合重建 index（index 重建要读当日全部 footer）。
 *
 * 环境开关：OCC_PARQUET=off 禁用；OCC_PARQUET_ROOT 覆盖 root。
 * 启用条件与 SME/ac 绑定同一总闸（occ_bind_active）：注入传输=回放/单测
 * 路径，不产生外部副作用。
 *
 * 读回边界（如实）：T8 的读面**有意收窄**到 footer FileMetaData 统计
 * （as_pq_file_stats：行数 / ts min-max / category max）+ index 重建；
 * 数据页读取不在 T8 读面内——本棒的「读回」即按该读面验收。
 */
#ifndef _OCC_TELEMETRY_H
#define _OCC_TELEMETRY_H

#include <stddef.h>

/* category 18 = CAT_NAMES 里的 "ai"（as_parquet.c names[]） */
#define OCC_TELEMETRY_CATEGORY 18

/* 行缓冲上限（到顶即 flush） */
#define OCC_TELEMETRY_BUF_MAX 128

int occ_telemetry_enabled(void);	/* env OCC_PARQUET=off → 0 */
const char *occ_telemetry_root(void);	/* env OCC_PARQUET_ROOT > $HOME/.occ/telemetry */

/*
 * occ_telemetry_turn - 记一条回合遥测（进缓冲，未必立刻落盘）。
 * @compacted:      1=本回合发生了换窗（同时会立刻 flush）
 * @digest_chars:   换窗时的摘要字符数（非换窗传 0）
 * 返回 0=已入缓冲/-1=禁用或参数错（绝不阻塞对话）。
 */
int occ_telemetry_turn(const char *session_id, long long tokens_total,
		       int rounds, const char *finish, int compacted,
		       long long digest_chars);

/* 立刻把缓冲写进 parquet（返回写出条数；禁用/空缓冲=0，失败=-1） */
int occ_telemetry_flush(void);

/* 缓冲内未落盘条数（单测断言节流语义） */
long occ_telemetry_pending(void);

/* 单测：root 直设（NULL=回缺省）；返回旧值（静态缓冲） */
const char *occ_telemetry_test_set_root(const char *root);

#endif /* _OCC_TELEMETRY_H */
