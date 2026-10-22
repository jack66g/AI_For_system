/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_ask_status_budget.c - W55 P2 + W56 T3/T5：status 摘要与预算口径
 *
 * 实机证据：
 *   - /proc/ai/status = 29880 字节 / 841 行（64 CPU x 12 条 sample_rate）；
 *   - 七域测试多次出现 session context budget 111%/243%/423%/778%，
 *     auto-compact 后仍超——根因是百分比按"会话累计 token"计算，
 *     而每轮 prompt 都包含历史，多轮累加必然假超限；
 *   - W56 实机 fs 会话在 compact 后仍报 110%：W55 口径把 completion
 *     也加进窗口，输出 token 与下一轮 prompt 重复计数。
 *
 * 本测试构造 30KB status，断言：
 *   1. 紧凑摘要 ≤2KB，含关键字段/模型名/dropped top3，且 dropped 标注
 *      "自启动累计；非本次新增"、sampled_skip 标注"主动降采样；非丢失"，
 *      连续两次摘要给出 dropped 增量；
 *   2. 摘要注入请求体后整包受控（≤8KB），不含 sample_rate 明细；
 *   3. 预算百分比按最近一次请求的 prompt（输入窗口）计算，
 *      completion 不计入（7221/8192 → 88%）；
 *   4. auto-compact 阈值 80%，历史达阈值触发、compact 后小历史不触发。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ai_chat.h"
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

static void build_status(char *buf, size_t cap, size_t *out_len)
{
	size_t off = 0;
	int cpu;

	off += (size_t)snprintf(buf + off, cap - off,
		"runtime_state: 2\n"
		"enabled: 1\n"
		"log_level: 1\n"
		"model_path: /etc/ai/\n"
		"telemetry_ring: 64 CPU x 256KB\n"
		"telemetry_format: human\n"
		"telemetry_drain: period_ms=250 active=1\n"
		"models:\n"
		"  [1] name=decide version=1 source=0 state=1\n");
	for (cpu = 0; cpu < 64; cpu++) {
		unsigned long long dropped = 0, skip = 1000000ULL + cpu;
		int ev;

		if (cpu == 1)
			dropped = 100;
		else if (cpu == 2)
			dropped = 3000;
		else if (cpu == 3)
			dropped = 22000;
		else if (cpu == 4)
			dropped = 50;
		off += (size_t)snprintf(buf + off, cap - off,
			"cpu%d: emitted=%d dropped=%llu sampled_skip=%llu"
			" head=%d tail=%d consumed=%d adapt_shift=0"
			" adapt_skipped=%d\n",
			cpu, 400000 + cpu, dropped, skip,
			30000000 + cpu * 1000, 29000000 + cpu * 1000,
			28000000 + cpu * 1000, 90000 + cpu);
		for (ev = 0; ev < 12; ev++)
			off += (size_t)snprintf(buf + off, cap - off,
				"  sample_rate[cat=%d ev=%d]=%d\n",
				1 + ev / 4, 2 + ev, 16 << (ev % 3));
	}
	buf[off] = '\0';
	*out_len = off;
}

static int count_substr(const char *hay, const char *needle)
{
	int n = 0;
	const char *p = hay;
	size_t nl = strlen(needle);

	if (!hay || !nl)
		return 0;
	while ((p = strstr(p, needle)) != NULL) {
		n++;
		p += nl;
	}
	return n;
}

static void test_status_summary(void)
{
	char status[65536];
	char summary[ASK_STATUS_SUMMARY_MAX];
	size_t status_len = 0;
	int n;

	printf("==== P2a: 30KB status -> compact summary ====\n");
	build_status(status, sizeof(status), &status_len);
	printf("  synthetic status: %zu bytes\n", status_len);
	CHECK(status_len >= 30000, "构造 status 达到 30KB 量级");

	n = ask_status_summary_build(status, summary, sizeof(summary));
	CHECK(n > 0, "摘要生成成功");
	CHECK(n < ASK_STATUS_SUMMARY_MAX, "摘要 < 2KB（硬上限内）");
	CHECK(strstr(summary, "runtime_state: 2") != NULL,
	      "含 runtime_state");
	CHECK(strstr(summary, "enabled: 1") != NULL, "含 enabled");
	CHECK(strstr(summary, "log_level: 1") != NULL, "含 log_level");
	CHECK(strstr(summary, "telemetry_ring: 64 CPU x 256KB") != NULL,
	      "含 telemetry_ring 环参数");
	CHECK(strstr(summary, "telemetry_drain: period_ms=250 active=1")
	      != NULL, "含 drain 状态");
	CHECK(strstr(summary, "models=1 (decide)") != NULL,
	      "含模型行数+模型名");
	CHECK(strstr(summary, "dropped_total=25150") != NULL,
	      "含 dropped 总量");
	CHECK(strstr(summary, "dropped_top3=cpu3:22000, cpu2:3000, "
	      "cpu1:100") != NULL, "含 per-CPU dropped top3");
	CHECK(strstr(summary, "sampled_skip_total=64002016") != NULL,
	      "含 sampled_skip 总量");
	CHECK(strstr(summary, "自启动累计") != NULL &&
	      strstr(summary, "非本次新增") != NULL,
	      "dropped 标注：自启动累计/非本次新增");
	CHECK(strstr(summary, "主动降采样") != NULL &&
	      strstr(summary, "非丢失") != NULL,
	      "sampled_skip 标注：主动降采样/非丢失");
	CHECK(strstr(summary, "sample_rate") == NULL,
	      "不含 64x12 条 sample_rate 明细");
	/* 连续第二次摘要：给出与上一采样的 dropped 增量 */
	n = ask_status_summary_build(status, summary, sizeof(summary));
	CHECK(n > 0 && strstr(summary, "较上次") != NULL,
	      "第二次摘要含 dropped 增量口径");
	CHECK(strstr(summary, "较上次 +0") != NULL,
	      "同一 status 第二次摘要增量 +0");
	printf("  summary (%d bytes):\n%s", n, summary);
}

static void test_request_budget(void)
{
	char status[65536];
	char summary[ASK_STATUS_SUMMARY_MAX];
	struct ai_chat_msg msgs[2];
	size_t status_len = 0;
	char *inject = NULL;
	char *body = NULL;
	int n;

	printf("==== P2b: injected request body size ====\n");
	build_status(status, sizeof(status), &status_len);
	n = ask_status_summary_build(status, summary, sizeof(summary));
	CHECK(n > 0, "摘要生成成功（预算用例）");

	{
		char *body = NULL;

		if (asprintf(&body, tr(TR_ASK_STATUS_FMT), summary) >= 0) {
			if (asprintf(&inject, "%s%s", body,
				     tr(TR_ASK_STATUS_NOTE)) < 0)
				inject = NULL;
			free(body);
		}
	}
	CHECK(inject != NULL, "注入文案组装成功（格式+sampled_skip 说明）");
	if (!inject)
		return;
	CHECK(strlen(inject) <= ASK_STATUS_SUMMARY_MAX,
	      "注入块（含框架文案+降采样说明）≤2KB");
	CHECK(strstr(inject, "sampled_skip") != NULL &&
	      strstr(inject, "主动降采样") != NULL,
	      "i18n 说明 sampled_skip 是主动降采样（正常）");
	CHECK(strstr(inject, "dropped") != NULL &&
	      strstr(inject, "真实丢失") != NULL,
	      "i18n 说明 dropped 才是真实丢失");

	memset(msgs, 0, sizeof(msgs));
	msgs[0].role = "system";
	msgs[0].content = "sys";
	msgs[1].role = "user";
	msgs[1].content = inject;
	body = ai_chat_build_request_json_ex("mock-model", msgs, 2, NULL,
					     0.0, 1024, 0);
	CHECK(body != NULL, "请求体构造成功");
	if (body) {
		printf("  request body: %zu bytes\n", strlen(body));
		CHECK(strlen(body) <= 8192,
		      "请求体 ≤8KB（ctx=8192 预算阈值）");
		CHECK(strstr(body, "sample_rate") == NULL,
		      "请求体不含 sample_rate 明细");
		CHECK(count_substr(body, "cpu63: emitted=") == 0,
		      "请求体不含第 64 个 CPU 的完整行");
		CHECK(strstr(body, "dropped_top3=cpu3:22000") != NULL,
		      "请求体保留 dropped top3");
		{
			long est_tok = (long)strlen(body) / 3;
			int pct = ask_ctx_budget_percent((int)est_tok, 0,
							 8192);

			printf("  est_tokens=%ld pct=%d%%\n", est_tok, pct);
			CHECK(pct < 100, "30KB 注入后预算百分比 <100%");
		}
		free(body);
	}
	free(inject);
}

static void test_budget_percent(void)
{
	printf("==== W56 T5a: per-request budget percent ====\n");
	/* W54 实测第 2 轮：prompt 7221 / completion 744。窗口=输入 prompt，
	 * completion 不计入（否则 compact 后出现 110% 假警告）。 */
	CHECK(ask_ctx_budget_percent(7221, 744, 8192) == 88,
	      "7221/8192 → 88%（不再加 completion）");
	CHECK(ask_ctx_budget_percent(7221, 744, 8192) ==
	      ask_ctx_budget_percent(7221, 0, 8192),
	      "completion 不改变窗口百分比");
	CHECK(ask_ctx_budget_percent(6000, 700, 8192) == 73,
	      "6000/8192 → 73%");
	CHECK(ask_ctx_budget_percent(1200, 744, 8192) <= 100,
	      "compact 后（prompt 1200）→ ≤100%");
	CHECK(ask_ctx_budget_percent(0, 0, 8192) == 0,
	      "空请求 → 0%");
	CHECK(ask_ctx_budget_percent(90000, 90000, 8192) == 100,
	      "W72 极端值钳到 100（不再 999）");
	CHECK(ask_ctx_budget_percent(1000, 0, 0) == 0,
	      "ctx_len<=0 → 0");

	/* W72：提示符实时百分比 = 最近一次请求 prompt / ctx_len。 */
	printf("==== W72: live prompt percent ====\n");
	CHECK(ask_ctx_prompt_percent(1200, 8192) == 14,
	      "1200/8192 → 14%");
	CHECK(ask_ctx_prompt_percent(8192, 8192) == 100,
	      "8192/8192 → 100%");
	CHECK(ask_ctx_prompt_percent(90000, 8192) == 100,
	      ">ctx 钳到 100%");
	CHECK(ask_ctx_prompt_percent(0, 8192) == -1,
	      "无 usage → -1（提示符 ?）");
	CHECK(ask_ctx_prompt_percent(1200, 0) == -1,
	      "ctx_len<=0 → -1");
}

static void test_autocompact_threshold(void)
{
	/* ctx=8192, max_tokens=1024, reserve=3000 → 历史预算 4168 */
	long budget = 8192 - 1024 - 3000;

	printf("==== W56 T5b: auto-compact threshold ====\n");
	printf("  history budget=%ld, threshold=%d%%\n",
	       budget, ASK_AUTOCOMPACT_PCT);
	CHECK(ASK_AUTOCOMPACT_PCT == 80, "阈值提前到 80%");
	CHECK(ask_ctx_should_autocompact(3400, budget) == 1,
	      "历史 3400/4168（81.6%）→ 触发 compact");
	CHECK(ask_ctx_should_autocompact(3334, budget) == 0,
	      "历史 3334/4168（79.98%）→ 不触发");
	CHECK(ask_ctx_should_autocompact(1200, budget) == 0,
	      "compact 后小历史（1200）→ 不触发");
	CHECK(ask_ctx_should_autocompact(0, budget) == 0,
	      "空历史 → 不触发");
	CHECK(ask_ctx_should_autocompact(1000, 0) == 0,
	      "非法预算 → 不触发");
}

int main(void)
{
	printf("==== test_ask_status_budget: W55 P2 + W56 T3/T5 ====\n");
	lang_set("zh");
	test_status_summary();
	test_request_budget();
	test_budget_percent();
	test_autocompact_threshold();
	if (g_fail == 0) {
		printf("RESULT: PASS\n");
		return 0;
	}
	printf("RESULT: FAIL (%d)\n", g_fail);
	return 1;
}
