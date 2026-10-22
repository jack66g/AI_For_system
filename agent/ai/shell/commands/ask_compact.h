/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ask_compact.h - W59 自动压缩确定性替换计划（纯函数）
 *
 * 背景：W56 的 ask 入口自动压缩直接调用 cmd_compact，输出未做预算约束，
 * 摘要本身可能仍高于 80% 阈值；且每个 ask 独立压缩、无连续次数上限，
 * 多行输入逐行触发压缩 -> 模型请求翻倍、REPL 永不静默（p5-03 实测）。
 *
 * 本模块只做"压缩后历史长什么样"的纯计算，不碰文件/LLM，便于专项测试：
 *   - 压缩输出 = 一条 [历史摘要] + 最近的整轮原文（按 token 预算）；
 *   - 压缩输入 = 旧历史快照（调用方只读），压缩请求本身绝不入历史；
 *   - 目标预算 = 历史预算的 55%（W72：原 70% 与 80% 触发线只差 10%，
 *     一轮大工具结果就会再次越线，W70 实测 T08→T09/T16→T17 连续压缩）；
 *   - 最近原文窗口：优先保留 2-4 个完整用户轮（工具调用+结果不拆散）；
 *     预算装不下时至少保留最后 1 个完整轮，绝不 kept=0（W70 T11）；
 *   - 压缩失败/超限降级 = 丢弃最旧消息（保留已有摘要，若它装得下）。
 */
#ifndef _AI_ASK_COMPACT_H
#define _AI_ASK_COMPACT_H

#include <stddef.h>

#include "ai_chat.h"

/*
 * 压缩目标占历史预算比例（<80% 触发线）。
 * W72：70%→55%。W70 预算 21,576 时 70% 目标 15,103，与 80% 触发线
 * 17,260 只差 2,157 tok；T08 压缩后自身工具结果立即越线，T09 被迫再压。
 * 55% 目标 ≈ 11,867，与触发线留 5,393 tok（约 16% ctx）headroom。
 */
#define ASK_COMPACT_TARGET_PCT     55
/* 第二次（最后一次）压缩的收紧目标 */
#define ASK_COMPACT_RETRY_PCT      40
/* 摘要正文最多占目标预算比例，其余留给最近原文 */
#define ASK_COMPACT_SUMMARY_PCT    60
/* 摘要正文硬上限（字节；防模型无视"简洁"指令） */
#define ASK_COMPACT_SUMMARY_MAX    16384
/* 压缩后保留的最近原文条数上限（防大预算下窗口过长） */
#define ASK_COMPACT_KEEP_MAX_MSGS  64
/* 最近原文窗口：优先保留的用户轮数范围（W72，按整轮不拆工具配对） */
#define ASK_COMPACT_KEEP_TURNS_MIN 2
#define ASK_COMPACT_KEEP_TURNS_MAX 4
/* 跨语言协议标记：ask/cmd_compact 以该字节前缀识别摘要消息 */
#define ASK_COMPACT_SUMMARY_PREFIX "[历史摘要] "
#define ASK_COMPACT_SUMMARY_PREFIX_LEN 15

/*
 * struct ask_compact_plan - 历史替换计划
 * @keep_first:  1=保留旧历史第 0 条（已有摘要，降级裁剪时钉住）
 * @keep_from:   保留 [keep_from, nhist) 的原文；nhist=不保留原文
 * @before_tokens: 旧历史估算 token
 * @after_tokens:  压缩/裁剪后估算 token（含摘要消息）
 */
struct ask_compact_plan {
	int keep_first;
	int keep_from;
	long before_tokens;
	long after_tokens;
};

long ask_compact_msg_tokens(const struct ai_chat_msg *m);
long ask_compact_hist_tokens(const struct ai_chat_msg *hist, int nhist);
int ask_compact_is_user(const struct ai_chat_msg *m);
int ask_compact_is_summary(const struct ai_chat_msg *m);

/*
 * ask_compact_summary_cap - 摘要正文可用的最大字节数（不含前缀）
 * @target_tokens: 压缩后历史 token 目标（>0）
 *
 * 返回值已按 ASK_COMPACT_SUMMARY_MAX 钳位；调用方仍需按 UTF-8 边界截断。
 */
size_t ask_compact_summary_cap(long target_tokens);

/*
 * ask_compact_plan_summary - 计划"新摘要 + 最近整轮原文"
 * @hist/@nhist:     旧历史快照（只读）
 * @summary_bytes:   摘要正文长度（不含 ASK_COMPACT_SUMMARY_PREFIX）
 * @target_tokens:   压缩后历史 token 上限
 * @max_msgs:        保留原文条数上限（<=0 用默认）
 * @plan:            输出
 *
 * 返回: 0 成功；-1 参数非法/摘要本身已超目标（调用方应先调用
 *       summary_cap 截断）。保留窗口从 user 锚点开始，assistant(tool_calls)
 *       +tool 配对不被拆散；窗口优先保留 2-4 个完整用户轮，预算装不下
 *       时至少保留最后 1 个完整轮（after_tokens 可能略超 target，属
 *       有意的软目标：宁可多带最近原文，也不 kept=0）。
 */
int ask_compact_plan_summary(const struct ai_chat_msg *hist, int nhist,
			     size_t summary_bytes, long target_tokens,
			     int max_msgs, struct ask_compact_plan *plan);

/*
 * ask_compact_plan_truncate - 计划本地降级裁剪（不调用 LLM）
 * @hist/@nhist:   旧历史快照（只读）
 * @target_tokens: 裁剪后 token 上限
 * @max_msgs:      保留条数上限（<=0 用默认）
 * @plan:          输出（keep_first=1 表示钉住 hist[0] 摘要）
 *
 * 从最新往最旧保留整轮；已有摘要仅在其自身 token 能装下时钉住。
 * 返回 0（正常情况下 after_tokens 尽量 <= target；最近整轮保底时
 * 允许略超）。W72：与 summary 路径共用整轮窗口策略。
 */
int ask_compact_plan_truncate(const struct ai_chat_msg *hist, int nhist,
			      long target_tokens, int max_msgs,
			      struct ask_compact_plan *plan);

#endif /* _AI_ASK_COMPACT_H */
