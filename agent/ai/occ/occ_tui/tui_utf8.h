/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tui_utf8.h - occ_tui UTF-8 解码 + wcwidth 双宽（T9c1）
 *
 * 零第三方依赖：完整 UTF-8 解码（非法序列→U+FFFD 不崩）、简化 East
 * Asian 宽表（诚实范围见 tui_utf8.c 表注）、组合字符（零宽跟前）策略。
 */
#ifndef OCC_TUI_UTF8_H
#define OCC_TUI_UTF8_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TUI_REPLACEMENT 0xFFFDu	/* 非法序列替换符 */

/* 解码状态 */
typedef enum {
	TUI_U8_OK = 0,		/* cp/adv 有效 */
	TUI_U8_NEEDMORE = 1,	/* 序列被缓冲区截断（等更多字节） */
	TUI_U8_INVALID = 2	/* 非法字节（adv>=1，调用方应吐替换符） */
} tui_u8stat;

/*
 * 解码 p[0..n) 的第一个码点。
 * OK:      *cp=码点, *adv=消耗字节数(1..4)
 * NEEDMORE:*adv=已见前缀字节数（调用方保留等下批）
 * INVALID: *adv=1（跳过 1 个坏字节，调用方吐 U+FFFD）
 * n==0:    NEEDMORE, *adv=0
 */
tui_u8stat tui_utf8_decode(const uint8_t *p, size_t n, uint32_t *cp, size_t *adv);

/* 码点 → UTF-8 写入 out（容量 >=4），返回字节数；非法码点返回 0 */
size_t tui_utf8_encode(uint32_t cp, uint8_t *out);

/*
 * 显示宽度（格数）：
 *   0 = 控制符 / 组合符（零宽跟前）
 *   1 = 普通
 *   2 = 双宽（中日韩/全角/emoji 主区块——简化表，范围注释在 .c）
 * 简化表不承诺与 glibc wcwidth 逐点一致，见 tui_utf8.c 头注。
 */
int tui_wcwidth(uint32_t cp);

/* 是否组合符（零宽）——wcwidth==0 且非控制符 */
int tui_is_combining(uint32_t cp);

/* 前导字节 → 期望总长度（非法前导返回 0） */
int tui_utf8_seqlen(uint8_t lead);

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_UTF8_H */
