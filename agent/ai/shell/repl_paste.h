/* SPDX-License-Identifier: GPL-2.0 */
/*
 * repl_paste.h - NoTTY/TERM=dumb 下的 bracketed paste 合并（W65 P3-03）
 *
 * linenoise 只在 TTY raw 模式解析 ESC[200~ / ESC[201~；TERM=dumb 或
 * stdin 非 TTY 时走 linenoiseNoTTY（逐行 fgets），一次 8KB 多行粘贴会
 * 退化成 N 次 ask 请求（首行含字面 ESC[200~、末行含 ESC[201~）。
 * 本辅助函数在 REPL 拿到一行后：
 *   1) 剥离两种 bracketed-paste 标记；
 *   2) 若见到起始标记但未见结束标记，继续从 in 读行，用 '\n' 合并，
 *      直到结束标记/EOF/超过 max_bytes。
 * 返回 malloc 字符串（接管 first 所有权并释放）；失败时返回 first。
 */
#ifndef _AI_REPL_PASTE_H
#define _AI_REPL_PASTE_H

#include <stdio.h>
#include <stddef.h>

char *repl_paste_merge_line(char *first, FILE *in, size_t max_bytes);

#endif /* _AI_REPL_PASTE_H */
