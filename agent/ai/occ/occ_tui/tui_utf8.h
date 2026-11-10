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

/* 字符串显示列数（grapheme 宽度求和；非法字节按 1 列；NULL=0） */
size_t tui_utf8_cols(const char *s);

/* 是否组合符（零宽）——wcwidth==0 且非控制符 */
int tui_is_combining(uint32_t cp);

/* 前导字节 → 期望总长度（非法前导返回 0） */
int tui_utf8_seqlen(uint8_t lead);

/*
 * LT-BUG-005：按**显示列**安全截断（纯绘制层公共原语）。
 *
 * 复制 src 的前缀到 dst，最多占 maxcols 显示列；超宽时末列写 `…`
 * （即正文最多 maxcols-1 列），绝不切开多字节序列（CJK 双宽按 2 列
 * 计，放不下即停）。dst 恒以 NUL 结尾（即使 dstcap==0 也不写）。
 * 返回写入字节数（不含 NUL）。maxcols==0 / src==NULL → 空串。
 *
 * 口径与 tui_view 顶栏/侧栏旧私有实现逐字节相同（原 tv_clip_cols /
 * clip_cols 已统一到本函数）。
 */
size_t tui_utf8_clip_cols(const char *src, size_t maxcols, char *dst,
			  size_t dstcap);

/* ---- B7：简化 grapheme 续接判定（「宁可宽一格」的 emoji 落点） ----
 *
 * 现状（实测）：ZWJ 序列（👨‍👩‍👧）逐码点计宽=2+0+2+0+2=6 列，现代终端
 * 按扩展字素簇渲染为 1 个 2 列 emoji——模型宽 > 实际宽 → 行尾错位撕行；
 * 肤色修饰（👋🏽=2+1）、旗帜对（🇨🇳=2+2）同向；反向：VS16（✌️）文本
 * 呈现计 1 列、emoji 呈现 2 列——模型宽 < 实际宽 → 覆盖重叠。
 *
 * 落点：码点流喂入本状态机，动作分三类（调用方在 cell/gitem 装配处
 * 执行，tui_core.c tui_screen_put 与 tui_chat.c gi_push 两处）：
 *   START  新 grapheme 起点，按 tui_wcwidth 占列
 *   EXTEND 并入前一 grapheme（宽 0；ZWJ 后的下一基字符 / 肤色修饰 /
 *          旗帜第二枚 RI / 常规组合符）
 *   BUMP   并入且前 grapheme 宽 1→2（VS16 文本呈现→emoji 呈现；
 *          调用方放不下（行末/前格宽 2）时按 EXTEND 处理）
 * 诚实边界：非 UAX#29 全量（无 Extend_Pictographic 全表、无区域外
 * ZWJ 校验、>TUI_CELL_MAX 字节超长序列截断——截断丢字节但列宽不变，
 * 对齐保住）；数据面 = 码点特征判定（200D/1F3FB-FF/1F1E6-FF/FE0F），
 * 无新数据表。
 */
typedef struct tui_gph_st {
	uint32_t prev;		/* 前一码点（0=无） */
	uint8_t join;		/* ZWJ 后：下一码点并入当前 grapheme */
	uint8_t ri;		/* 连续 RI 计数（奇=等第二枚闭合旗帜对） */
} tui_gph_st;

enum {
	TUI_GPH_START = 0,
	TUI_GPH_EXTEND,
	TUI_GPH_BUMP
};

/*
 * 喂一个码点（wc=该码点 tui_wcwidth），返回动作并更新 st。
 * st 应按一次文本装配初始化 {0,0}（序列跨 markdown span 边界不保证）。
 */
int tui_graph_feed(tui_gph_st *st, uint32_t cp, int wc);

#ifdef __cplusplus
}
#endif
#endif /* OCC_TUI_UTF8_H */
