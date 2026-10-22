/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_ask_stubs.h - ask 集成测试的进程内 mock（W55 P1）
 *
 * 不启真 LLM/HTTP：ai_runtime_chat_ex 由测试回调接管，逐轮检查请求
 * tools 数组、返回预设 tool_calls；tool_executor_run 记录分发并返回
 * 可激活工具名。等价于"mock server"，但走 cmd_ask 的真实主循环。
 */
#ifndef TEST_ASK_STUBS_H
#define TEST_ASK_STUBS_H

#include "ai_chat.h"

struct ai_tool;

typedef int (*ask_mock_chat_fn)(int call_no,
				const struct ai_chat_msg *msgs, int nmsgs,
				const char *tools_json,
				struct ai_chat_result **result);

extern ask_mock_chat_fn g_ask_mock_chat;
extern int g_ask_mock_calls;
extern char g_ask_dispatched[16][128];
extern int g_ask_dispatch_count;

/* W65：可选的工具执行 hook（默认 NULL = 原 MOCK_OK 行为）。
 * 用于参数契约自动重试测试（第一次返回 E_PARAM，第二次成功）。 */
typedef int (*ask_mock_tool_fn)(const struct ai_tool *tool,
				const char *args_json,
				char **out, int *ok);
extern ask_mock_tool_fn g_ask_mock_tool;

/* W56：policy 状态桩（默认 0，行为与 W55 一致） */
extern int g_ask_policy_assume_yes;
extern int g_ask_policy_plan_mode;

/* W56 T5：会话历史桩（NULL/0 = 空会话，行为与 W55 一致） */
extern struct ai_chat_msg *g_ask_session_msgs;
extern int g_ask_session_n;

/* W56 T5：compact 桩（NULL = 返回 AI_ERR_INVALID_ARG，行为不变） */
typedef int (*ask_mock_compact_fn)(void *shell);
extern ask_mock_compact_fn g_ask_mock_compact;
extern int g_ask_compact_calls;

/* W59：cmd_compact_apply 桩记录的参数（目标 token / 第几次尝试） */
extern long g_ask_compact_target;
extern int g_ask_compact_attempt;
/* W72：压缩后保留的最近原文条数 / after token（默认 1，避免误触重试） */
extern int g_ask_compact_kept;
extern long g_ask_compact_after;

/*
 * W59：会话桩存储重置。ui_session_replace stub 会把替换结果写入进程内
 * 存储（g_ask_session_msgs 指向它）；用例之间调用本函数清空，避免串味。
 */
void test_ask_session_reset(void);

/*
 * W59：stub 是否收到过含压缩指令的会话记录（应为 0——压缩请求绝不
 * 写入历史）。返回匹配条数。
 */
int test_ask_session_contains(const char *needle);

#endif /* TEST_ASK_STUBS_H */
