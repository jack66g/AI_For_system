/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_streams - W78 六条事件流工具单测
 *
 * 覆盖：
 *   1. 参数钳制 ai_streams_clamp_ll（边界/默认值）
 *   2. JSON 转义 ai_streams_json_escape（引号/反斜杠/控制字符/容量不足）
 *   3. 非 AIKernel 内核上 event_listen 的诚实报错（L1 跑）
 *   4. taskstats 非法 pid 的诚实报错
 *   5. （root 时）net_monitor/udev_monitor 短窗口真实订阅冒烟：
 *      断言输出首行是 JSON 且含 "events" 字段；无 root 打 SKIP
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "netlink/ai_streams.h"

static int fails = 0;

#define CHECK(cond, name) do { \
	if (cond) { printf("ok %s\n", name); } \
	else { printf("FAIL %s\n", name); fails++; } \
} while (0)

static void test_clamp(void)
{
	CHECK(ai_streams_clamp_ll(500, 100, 10000, 1000) == 500, "clamp-in-range");
	CHECK(ai_streams_clamp_ll(50, 100, 10000, 1000) == 1000, "clamp-below");
	CHECK(ai_streams_clamp_ll(99999, 100, 10000, 1000) == 1000, "clamp-above");
	CHECK(ai_streams_clamp_ll(-1, 100, 10000, 1000) == 1000, "clamp-neg");
}

static void test_escape(void)
{
	char out[128];
	int rc;

	rc = ai_streams_json_escape("plain", out, sizeof(out));
	CHECK(rc == 0 && strcmp(out, "plain") == 0, "escape-plain");

	rc = ai_streams_json_escape("a\"b\\c\nd", out, sizeof(out));
	CHECK(rc == 0 && strcmp(out, "a\\\"b\\\\c\\u000ad") == 0, "escape-ctrl");

	rc = ai_streams_json_escape(NULL, out, sizeof(out));
	CHECK(rc == -1, "escape-null");

	memset(out, 'A', sizeof(out));
	rc = ai_streams_json_escape("", out, 1);
	CHECK(rc == -1, "escape-cap");
}

static void test_event_listen_honest(void)
{
	char *out = NULL;
	int rc = ai_streams_event_listen(200, 4, &out);

	if (rc == 0) {
		/* AIKernel 内核上：订阅本身成功（0 事件合法） */
		CHECK(out && strncmp(out, "{\"stream\":\"event\"", 18) == 0,
		      "event-ok-header");
	} else {
		/* L1 等非 AIKernel 内核：必须明确报错而不是假数据 */
		CHECK(out && strstr(out, "ERROR") != NULL,
		      "event-honest-error");
	}
	free(out);
}

static void test_taskstats_bad_pid(void)
{
	char *out = NULL;
	int rc = ai_streams_taskstats(99999999, &out);

	if (rc == 0) {
		/* 极小概率 pid 存在：只断言 JSON 形态 */
		CHECK(out && strstr(out, "\"stream\":\"taskstats\""),
		      "taskstats-unexpected-ok");
	} else {
		CHECK(out && strstr(out, "ERROR") != NULL,
		      "taskstats-honest-error");
	}
	free(out);
}

static void test_live_smoke(void)
{
	char *out = NULL;

	if (geteuid() != 0) {
		printf("SKIP live smoke (not root)\n");
		return;
	}
	if (ai_streams_net_monitor(300, 8, &out) == 0) {
		CHECK(out && strncmp(out, "{\"stream\":\"net\"", 16) == 0 &&
		      strstr(out, "\"events\"") != NULL, "live-net-monitor");
	}
	free(out);
	out = NULL;
	if (ai_streams_udev_monitor(300, 8, &out) == 0) {
		CHECK(out && strncmp(out, "{\"stream\":\"uevent\"", 19) == 0 &&
		      strstr(out, "\"events\"") != NULL, "live-uevent");
	}
	free(out);
}

int main(void)
{
	test_clamp();
	test_escape();
	test_event_listen_honest();
	test_taskstats_bad_pid();
	test_live_smoke();

	if (fails) {
		printf("test_streams: %d FAIL\n", fails);
		return 1;
	}
	printf("test_streams: all pass\n");
	return 0;
}
