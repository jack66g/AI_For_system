/* SPDX-License-Identifier: GPL-2.0 */
/*
 * occ_sysprompt.h - occ 系统提示（T9a3 最小中文版）
 *
 * OPENCODE-PLAN §6：上下文组装 = system prompt 固定串 + 历史窗口全量
 * （窗口裁剪 b 棒；SME 注入段 §8 是 d 棒）。b 棒起按 opencode 语义扩展。
 */
#ifndef _OCC_SYSPROMPT_H
#define _OCC_SYSPROMPT_H

/* 唯一实例（loop.c 定义）——extern 而非 static 数组：否则每个编译
 * 单元各持一份副本，测试的指针等同断言失效 */
extern const char OCC_SYSTEM_PROMPT[];

/* O-20 A 部：当前档系统提示（en=另写版/zh=OCC_SYSTEM_PROMPT 原文
 * 恒等）；AC 基线估算等消费方用此取活档 */
const char *occ_sysprompt_active(void);

#endif /* _OCC_SYSPROMPT_H */
