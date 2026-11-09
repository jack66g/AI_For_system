/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_norm.h - occ_event 流 → 规范化输出（差分台架/单测共用）
 *
 * 规范化形状（键序固定；与 parity/vectors/occ/diff_run.py 的 Python
 * 参考规范化器逐字节同构）：
 * {"text":...,"reasoning":...,"tool_calls":[{"idx":N,"id":..,"name":..,
 *  "arguments":..}],"usage":{"present":N,"input":N,"output":N,
 *  "cache_read":N,"cache_write":N},"finish":"..","done":N,
 *  "done_src":"..","errors":[".."]}
 */
#ifndef _OCC_NORM_H
#define _OCC_NORM_H

#include "occ_llm/occ_llm.h"

typedef struct occ_norm occ_norm;

occ_norm *occ_norm_new(void);
void occ_norm_free(occ_norm *n);
/* 直接可作 occ_event_cb */
void occ_norm_event(const occ_event *ev, void *ud);
/* malloc 输出（NUL 结尾；*outlen 可 NULL）；失败 NULL */
char *occ_norm_dump(const occ_norm *n, size_t *outlen);
int occ_norm_error_count(const occ_norm *n);

#endif /* _OCC_NORM_H */
