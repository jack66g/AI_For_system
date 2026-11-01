/* SPDX-License-Identifier: GPL-2.0 */
/*
 * text.h - 轻量 tokenize（T3a）
 *
 * 复刻 REF-PY sme/utils.py::tokenize：
 *   lowered = str.lower(text)；
 *   按码点匹配 [a-z0-9\u4e00-\u9fff]+ 得到 run；
 *   run 长度 > 1 且含 CJK（仅基本区 U+4E00-U+9FFF）时，逐字符追加，
 *   cjk_bigram 时再追加所有相邻二元组，不追加原 run；
 *   其余 run 整段追加；空输入返回 0 个 token。
 */
#ifndef _AIK_TEXT_H
#define _AIK_TEXT_H

#include <stddef.h>

typedef struct {
	char **items;
	size_t count;
} aik_token_list;

/*
 * aik_tokenize - 切词
 *
 * 成功返回 0 并按序填充 out->items/out->count（每项 malloc）；
 * 非法 UTF-8 或内存不足返回 -1 并写 err。失败时 out 为空表。
 * 调用者用 aik_token_list_free() 释放。
 */
int aik_tokenize(const char *utf8, int cjk_bigram, aik_token_list *out,
		 char *err, size_t errlen);

/* 释放 token 列表（NULL 安全）；结构体被清零 */
void aik_token_list_free(aik_token_list *t);

#endif /* _AIK_TEXT_H */
