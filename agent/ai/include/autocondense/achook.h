/* SPDX-License-Identifier: GPL-2.0 */
/*
 * achook.h - T5e autocondense 宿主钩子适配器
 *
 * 对齐 REF-PY 42466f1 `autocondense/hooks/ac_hook.py`：
 *   autocondense-hook <EventName>  < stdin(JSON) > stdout
 *   - 转发 POST {AUTOCONDENSE_BASE_URL}/events/hook（默认 8761，3s 超时）；
 *   - SessionStart：additional_context → {"additionalContext": "..."}（9000 字截断）；
 *   - Stop：should != NO 且带 instruction → {"decision": "block", "reason": ...}，
 *     15 分钟闩锁（data/hook-latch/<safe>.json）；
 *   - 其余事件无输出；任何异常静默 exit 0，stderr 日志一行。
 */
#ifndef _AIK_AUTOCONDENSE_ACHOOK_H
#define _AIK_AUTOCONDENSE_ACHOOK_H

/* event 为 argv[1]（NULL/空 = 未指定）。总是返回 0。 */
int achook_run(const char *event);

#endif /* _AIK_AUTOCONDENSE_ACHOOK_H */
