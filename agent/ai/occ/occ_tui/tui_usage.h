/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_usage.h - occ TUI token 水位纯函数（T9c3：OPENCODE-PLAN §3 / OCD §5.2）
 *
 * 单一口径（元数据行与侧栏底部同源——occ.c 只维护一份五项缓存）：
 *   percent = round(tokens / limit.context × 100)   （OCD 实测公式）
 *   分子 tokens = 上下文占用五项和（in+out+cache_read+cache_write+rea，
 *   OCD §5.2 最后一条带 usage 的 assistant 消息口径）；
 *   分母 limit  = models.dev 快照 context_limit；加载失败/未命中兜底
 *   200k（OCD 未知窗口默认，显示侧标 `*` 注明）。
 *   水位色：10% 绿（缺省色）/ 70% 黄 / 90% 红（tier 只给 70/90 两档）。
 *
 * reasoning：occ_usage 归一化无独立 reasoning 位（两协议 reasoning 计入
 * output）——rea 传 <0 显示 `–`（如实 n/a，不谎报 0）。
 */
#ifndef OCC_TUI_USAGE_H
#define OCC_TUI_USAGE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * percent = round(tokens/limit×100)（半数进位；整数运算防浮点边界抖动）。
 * limit<=0（未知窗口）或 tokens<0 → -1（显示侧不加百分比后缀）。
 */
int tui_usage_pct(long long tokens, long long limit);

/* 水位档：0=正常 1=≥70 黄 2=≥90 红；pct<0 → 0 */
int tui_usage_tier(int pct);

/* k/M 档（与 c2 fmt_tok 同口径）：999→"999"、12300→"12.3k"、
 * 200000→"200k"、1500000→"1.5M" */
void tui_usage_fmt(long long v, char *buf, size_t cap);

/* 上下文占用五项和（rea<0 按 0 计；负值防御按 0） */
long long tui_usage_ctx(long long in, long long out, long long cr,
			long long cw, long long rea);

/*
 * 五项行：`i8.1k o4.2k c9.0k r–`（cache=cr+cw 由调用方先合并或传和；
 * rea<0 → `–`；est=1 → 整行前缀 `~` 明示估算）。
 */
void tui_usage_items(char *buf, size_t cap, long long in, long long out,
		     long long cache, long long rea, int est);

/*
 * UXAB：上下文占用进度条（▓/░，5 格满）。按 pct 分档：
 *   0-9 `░` · 10-19 `▓░` · 20-39 `▓▓░` · 40-59 `▓▓▓░` · 60-79 `▓▓▓▓░`
 *   · ≥80 `▓▓▓▓▓`（全满无尾 ░）。pct<0（未知）→ `░`。
 * 每档 = floor((pct+20)/20) 个 ▓ + 1 个尾 ░（80+ 无尾）。
 */
void tui_usage_bar(int pct, char *buf, size_t cap);

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_USAGE_H */
