/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_usage.c - token 水位纯函数（T9c3：OPENCODE-PLAN §3 / OCD §5.2）
 *
 * 边界：round 半数进位（69.5→70 黄、89.5→90 红）、limit<=0 → -1、
 * k/M 档、五项行（rea<0 → `–`、est → `~` 前缀）、ctx 五项和。
 */
#include <stdio.h>
#include <string.h>

#include "tui_usage.h"

static int n_ok, n_fail;

#define OK(cond, name) do { \
	if (cond) { n_ok++; } \
	else { n_fail++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while (0)

int main(void)
{
	char buf[96];

	/* ---- pct 公式：round(tokens/limit×100)，整数半数进位 ---- */
	OK(tui_usage_pct(0, 200000) == 0, "pct-zero");
	OK(tui_usage_pct(1000, 200000) == 1, "pct-0.5-rounds-up");
	OK(tui_usage_pct(695, 1000) == 70, "pct-69.5-rounds-70");
	OK(tui_usage_pct(694, 1000) == 69, "pct-69.4-stays-69");
	OK(tui_usage_pct(895, 1000) == 90, "pct-89.5-rounds-90");
	OK(tui_usage_pct(894, 1000) == 89, "pct-89.4-stays-89");
	OK(tui_usage_pct(1000, 1000) == 100, "pct-full");
	OK(tui_usage_pct(12345, 200000) == 6, "pct-ocd-example-6");
	OK(tui_usage_pct(400000, 200000) == 200, "pct-over-100");
	OK(tui_usage_pct(100, 0) == -1, "pct-limit-zero-unknown");
	OK(tui_usage_pct(100, -5) == -1, "pct-limit-negative");
	OK(tui_usage_pct(-1, 200000) == -1, "pct-tokens-negative");

	/* ---- 水位档：70 黄 / 90 红 ---- */
	OK(tui_usage_tier(0) == 0, "tier-0");
	OK(tui_usage_tier(69) == 0, "tier-69-normal");
	OK(tui_usage_tier(70) == 1, "tier-70-warn");
	OK(tui_usage_tier(89) == 1, "tier-89-warn");
	OK(tui_usage_tier(90) == 2, "tier-90-err");
	OK(tui_usage_tier(100) == 2, "tier-100-err");
	OK(tui_usage_tier(-1) == 0, "tier-unknown-normal");

	/* ---- k/M 档（c2 fmt_tok 同口径） ---- */
	tui_usage_fmt(999, buf, sizeof(buf));
	OK(strcmp(buf, "999") == 0, "fmt-999");
	tui_usage_fmt(1000, buf, sizeof(buf));
	OK(strcmp(buf, "1k") == 0, "fmt-1000");
	tui_usage_fmt(12300, buf, sizeof(buf));
	OK(strcmp(buf, "12.3k") == 0, "fmt-12.3k");
	tui_usage_fmt(12000, buf, sizeof(buf));
	OK(strcmp(buf, "12k") == 0, "fmt-12k");
	tui_usage_fmt(200000, buf, sizeof(buf));
	OK(strcmp(buf, "200k") == 0, "fmt-200k");
	tui_usage_fmt(1500000, buf, sizeof(buf));
	OK(strcmp(buf, "1.5M") == 0, "fmt-1.5M");
	tui_usage_fmt(0, buf, sizeof(buf));
	OK(strcmp(buf, "0") == 0, "fmt-0");

	/* ---- ctx 五项和（rea<0/负值按 0） ---- */
	OK(tui_usage_ctx(10, 20, 30, 40, -1) == 100, "ctx-sum");
	OK(tui_usage_ctx(-5, -1, -2, -3, -1) == 0, "ctx-neg-clamp");
	OK(tui_usage_ctx(1, 2, 3, 4, 5) == 15, "ctx-rea-counted");

	/* ---- 五项行 ---- */
	tui_usage_items(buf, sizeof(buf), 8100, 4200, 9000, -1, 0);
	OK(strcmp(buf, "i8.1k o4.2k c9k r–") == 0, "items-basic");
	tui_usage_items(buf, sizeof(buf), 1000, 500, 250, -1, 1);
	OK(strcmp(buf, "~i1k o500 c250 r–") == 0, "items-est-tilde");
	tui_usage_items(buf, sizeof(buf), 10, 20, 30, 42, 0);
	OK(strcmp(buf, "i10 o20 c30 r42") == 0, "items-rea-present");
	tui_usage_items(buf, sizeof(buf), 0, 0, 0, -1, 0);
	OK(strcmp(buf, "i0 o0 c0 r–") == 0, "items-zero");

	/* ---- UXAB：进度条分档（▓=E2 96 93、░=E2 96 91） ---- */
	tui_usage_bar(-1, buf, sizeof(buf));
	OK(strcmp(buf, "\xe2\x96\x91") == 0, "bar-unknown");
	tui_usage_bar(0, buf, sizeof(buf));
	OK(strcmp(buf, "\xe2\x96\x91") == 0, "bar-0");
	tui_usage_bar(9, buf, sizeof(buf));
	OK(strcmp(buf, "\xe2\x96\x91") == 0, "bar-9");
	tui_usage_bar(10, buf, sizeof(buf));
	OK(strcmp(buf, "\xe2\x96\x93\xe2\x96\x91") == 0, "bar-10");
	tui_usage_bar(19, buf, sizeof(buf));
	OK(strcmp(buf, "\xe2\x96\x93\xe2\x96\x91") == 0, "bar-19");
	tui_usage_bar(20, buf, sizeof(buf));
	OK(strcmp(buf, "\xe2\x96\x93\xe2\x96\x93\xe2\x96\x91") == 0,
	   "bar-20");
	tui_usage_bar(39, buf, sizeof(buf));
	OK(strcmp(buf, "\xe2\x96\x93\xe2\x96\x93\xe2\x96\x91") == 0,
	   "bar-39");
	tui_usage_bar(59, buf, sizeof(buf));
	OK(strcmp(buf,
		  "\xe2\x96\x93\xe2\x96\x93\xe2\x96\x93\xe2\x96\x91") == 0,
	   "bar-59");
	tui_usage_bar(79, buf, sizeof(buf));
	OK(strcmp(buf,
		  "\xe2\x96\x93\xe2\x96\x93\xe2\x96\x93\xe2\x96\x93"
		  "\xe2\x96\x91") == 0, "bar-79");
	tui_usage_bar(80, buf, sizeof(buf));
	OK(strcmp(buf,
		  "\xe2\x96\x93\xe2\x96\x93\xe2\x96\x93\xe2\x96\x93"
		  "\xe2\x96\x93") == 0, "bar-80-full");
	tui_usage_bar(100, buf, sizeof(buf));
	OK(strcmp(buf,
		  "\xe2\x96\x93\xe2\x96\x93\xe2\x96\x93\xe2\x96\x93"
		  "\xe2\x96\x93") == 0, "bar-100-full");
	tui_usage_bar(250, buf, sizeof(buf));
	OK(strcmp(buf,
		  "\xe2\x96\x93\xe2\x96\x93\xe2\x96\x93\xe2\x96\x93"
		  "\xe2\x96\x93") == 0, "bar-over-clamped");

	printf("test_usage: %d ok, %d fail\n", n_ok, n_fail);
	return n_fail ? 1 : 0;
}
