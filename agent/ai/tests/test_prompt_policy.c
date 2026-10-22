/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_prompt_policy.c - W56 T1/T4：system prompt 运行时策略段
 *
 * 实机缺陷（VM，W55 部署版）：
 *   - 查询"建个隔离区 demo11..."带 -y（AIKERNEL_ASSUME_YES），第 4 轮
 *     模型停下来说"sandbox_spawn 属于 W2，需要红色确认，请确认是否
 *     执行"——模型不知道 -y 已预授权，一句话任务没有闭环；
 *   - 中文提问，模型多次用英文回答（提示词按界面语言写死英文）。
 *
 * 本测试直接验证 cmd_ask 注入 system prompt 的策略段纯函数（W74 口径）：
 *   1. assume_yes=1 且非 plan：只预授权 D2 短租约；明确 D3/D4 仍需确认；
 *      CONFIRM_REQUIRED 时如实转告、不重试、不假设已授权；
 *   2. assume_yes=0：不含预授权指令（闸门行为不变）；
 *   3. assume_yes=1 且 plan：plan 优先，不含预授权段；
 *   4. 语言默认指令始终存在（中英两套文案）。
 * plan 闸门本身的拒绝行为由 test_plan_mode 覆盖。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ai_lang.h"
#include "ask_context.h"

static int g_fail;

#define CHECK(cond, msg)						\
	do {								\
		if (cond) {						\
			printf("  [PASS] %s\n", msg);			\
		} else {						\
			printf("  [FAIL] %s (%s:%d)\n", msg,		\
			       __FILE__, __LINE__);			\
			g_fail++;					\
		}							\
	} while (0)

static int has(const char *hay, const char *needle)
{
	return hay && needle && strstr(hay, needle) != NULL;
}

static void test_zh_assume_yes(void)
{
	char buf[1024];
	int n;

	printf("---- zh: assume_yes, no plan ----\n");
	lang_set("zh");
	n = ask_prompt_policy_notes_build(1, 0, buf, sizeof(buf));
	CHECK(n > 0, "策略段生成成功");
	CHECK(has(buf, "预授权"), "含「预授权」");
	CHECK(has(buf, "D2"), "说明只预授权 D2");
	CHECK(has(buf, "短租约"), "说明是本次 ask 的短租约");
	CHECK(has(buf, "D3"), "明确 D3 仍需人工确认");
	CHECK(has(buf, "D4"), "明确 D4 仍需人工确认");
	CHECK(has(buf, "CONFIRM_REQUIRED"), "说明 CONFIRM_REQUIRED 处置");
	CHECK(has(buf, "ephemeral lease"), "审计来源为 ephemeral lease");
	CHECK(has(buf, "不要重试同一调用"), "禁止重试同一调用");
	CHECK(!has(buf, "可直接调用"), "不再承诺「可直接调用」");
	CHECK(!has(buf, "无需再次询问"), "不再承诺「无需再次询问」");
	CHECK(!has(buf, "CONFIRM=yes(auto)"), "不再写旧审计口径");
	CHECK(!has(buf, "红色确认"), "不再声称红色确认被覆盖");
	CHECK(has(buf, "默认使用用户提问的语言"),
	      "语言默认：跟随用户提问语言");
	CHECK(has(buf, "必须使用中文"), "中文提问必须中文回答");
	printf("%s", buf);
}

static void test_zh_without_assume(void)
{
	char buf[1024];

	printf("---- zh: no assume_yes（W2 闸门行为不变） ----\n");
	lang_set("zh");
	CHECK(ask_prompt_policy_notes_build(0, 0, buf, sizeof(buf)) > 0,
	      "策略段生成成功");
	CHECK(!has(buf, "预授权"), "无预授权指令");
	CHECK(!has(buf, "可直接调用"), "无「可直接调用」");
	CHECK(has(buf, "默认使用用户提问的语言"), "语言默认仍在");
}

static void test_zh_plan_priority(void)
{
	char buf[1024];

	printf("---- zh: assume_yes + plan（plan 优先） ----\n");
	lang_set("zh");
	CHECK(ask_prompt_policy_notes_build(1, 1, buf, sizeof(buf)) > 0,
	      "策略段生成成功");
	CHECK(!has(buf, "预授权"), "plan 态不输出预授权段");
	CHECK(!has(buf, "可直接调用"), "plan 态不含「可直接调用」");
	CHECK(has(buf, "默认使用用户提问的语言"), "语言默认仍在");
}

static void test_en(void)
{
	char buf[1024];

	printf("---- en: assume_yes + language ----\n");
	lang_set("en");
	CHECK(ask_prompt_policy_notes_build(1, 0, buf, sizeof(buf)) > 0,
	      "策略段生成成功（en）");
	CHECK(has(buf, "Pre-authorization"), "en 含 Pre-authorization");
	CHECK(has(buf, "D2"), "en 说明只预授权 D2");
	CHECK(has(buf, "short lease"), "en 说明 short lease");
	CHECK(has(buf, "D3") && has(buf, "D4"),
	      "en 明确 D3/D4 仍需确认");
	CHECK(has(buf, "CONFIRM_REQUIRED"), "en 说明 CONFIRM_REQUIRED");
	CHECK(!has(buf, "may be called directly"),
	      "en 不再承诺 may be called directly");
	CHECK(!has(buf, "no need to ask again"),
	      "en 不再承诺 no need to ask again");
	CHECK(has(buf, "language of the user's question"),
	      "en 语言默认指令");
	CHECK(has(buf, "must answer in Chinese"), "en 中文提问必须中文回答");
	CHECK(ask_prompt_policy_notes_build(1, 1, buf, sizeof(buf)) > 0,
	      "策略段生成成功（en+plan）");
	CHECK(!has(buf, "Pre-authorization"), "en plan 态不输出预授权段");
	lang_set("zh");
}

static void test_rules_diag_tools(void)
{
	const char *r;

	printf("---- system rules: log diagnosis + sysfs scope ----\n");
	lang_set("zh");
	r = tr(TR_ASK_SYS_RULES_SHORT);
	CHECK(has(r, "exec_run") && has(r, "dmesg") &&
	      has(r, "journalctl") && has(r, "systemctl --failed"),
	      "zh short rules 要求日志排查用 exec_run");
	CHECK(has(r, "sysfs_get 只读"), "zh short rules 明确 sysfs_get 只读范围");
	lang_set("en");
	r = tr(TR_ASK_SYS_RULES_SHORT);
	CHECK(has(r, "exec_run") && has(r, "dmesg") &&
	      has(r, "journalctl") && has(r, "systemctl --failed"),
	      "en short rules 要求日志排查用 exec_run");
	CHECK(has(r, "sysfs_get only reads"), "en short rules 明确 sysfs_get 只读范围");
	lang_set("zh");
}

static void test_invalid(void)
{
	char buf[8];

	printf("---- invalid args ----\n");
	CHECK(ask_prompt_policy_notes_build(1, 0, NULL, 16) == -1,
	      "out=NULL → -1");
	CHECK(ask_prompt_policy_notes_build(1, 0, buf, 1) == -1,
	      "out_sz<2 → -1");
}

int main(void)
{
	printf("==== test_prompt_policy: W56 T1/T4 ====\n");
	test_zh_assume_yes();
	test_zh_without_assume();
	test_zh_plan_priority();
	test_en();
	test_rules_diag_tools();
	test_invalid();
	if (g_fail == 0) {
		printf("RESULT: PASS\n");
		return 0;
	}
	printf("RESULT: FAIL (%d)\n", g_fail);
	return 1;
}
