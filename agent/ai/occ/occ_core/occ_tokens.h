/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_tokens.h - occ token 账本（T9a3；OPENCODE-PLAN §3 的 a3 子集）
 *
 * 五项账本：input / output / cache_read / cache_write / total
 * （±cache 与 reasoning 的 usage 口径见 occ_llm.h occ_usage 注释；
 * total=input+output，cache 项不计入 total——对齐 opencode cost 语义：
 * 计费口径 cache 命中另行计价，不与全价 input 双算）。
 *
 * 估算兜底：usage 未回传（occ_usage.present==0）时
 * len/4（UTF-8 字节数/4）估算并置 est=1（显示带 ~）。
 */
#ifndef _OCC_TOKENS_H
#define _OCC_TOKENS_H

#include "occ_llm/occ_llm.h"

typedef struct occ_tokens {
	long long input;
	long long output;
	long long cache_read;
	long long cache_write;
	long long total;		/* input+output */
	int est;			/* 1=含估算成分（~） */
} occ_tokens;

/* 重置归零 */
void occ_tokens_reset(occ_tokens *t);

/* 真实 usage 入账（多次调用覆盖式：SSE usage 事件为流末最终值） */
void occ_tokens_set_usage(occ_tokens *t, const occ_usage *u);

/*
 * 估算兜底：无 usage 回传时按文本长度近似。out/output 走 len/4；
 * 其余项保持。est 置 1。返回估算的 output 值。
 */
long long occ_tokens_estimate_output(const char *utf8_text);

/* len/4 估算原语（字节长度含 NUL 前；NULL=0） */
long long occ_tokens_estimate_len(const char *utf8);

/* 便捷格式化：est ? "~1234" : "1234"（buf 调用者给） */
const char *occ_tokens_fmt(const occ_tokens *t, char *buf, size_t buflen);

#endif /* _OCC_TOKENS_H */
