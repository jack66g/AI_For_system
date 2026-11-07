/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tokens.c - occ token 账本（T9a3）
 *
 * per-message 五项（input/output±cache/total）+ 估算兜底 len/4（标 ~）。
 * 会话级累计由 occ_session.tokens_total/tokens_est 承载（session.c
 * add_assistant 同事务维护），本模块只做纯计算与格式化。
 */
#include "occ_tokens.h"

#include <stdio.h>
#include <string.h>

void occ_tokens_reset(occ_tokens *t)
{
	if (!t)
		return;
	memset(t, 0, sizeof(*t));
}

void occ_tokens_set_usage(occ_tokens *t, const occ_usage *u)
{
	if (!t || !u || !u->present)
		return;
	t->input = u->input;
	t->output = u->output;
	t->cache_read = u->cache_read;
	t->cache_write = u->cache_write;
	t->total = u->input + u->output;
	t->est = 0;			/* 真实回传覆盖估算标记 */
}

long long occ_tokens_estimate_len(const char *utf8)
{
	if (!utf8)
		return 0;
	return (long long)(strlen(utf8) / 4);	/* 任务书口径：len/4 */
}

long long occ_tokens_estimate_output(const char *utf8_text)
{
	return occ_tokens_estimate_len(utf8_text);
}

const char *occ_tokens_fmt(const occ_tokens *t, char *buf, size_t buflen)
{
	if (!t || !buf || !buflen)
		return "";
	snprintf(buf, buflen, "%s%lld", t->est ? "~" : "", t->total);
	return buf;
}
