// SPDX-License-Identifier: GPL-2.0
/*
 * test_telemetry_rate.c - I-2 采样率写口工具面单测
 *
 * 纯函数面（parse/status_find/run）+ 临时文件写读回（不碰真
 * /proc/ai——L1 无内核面，诚实 mock 层；真内核轮随 ISO 棒）。
 */
#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ai_types.h"
#include "telemetry_rate.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

static char tmpdir[96];

static void wfile(const char *rel, const char *content)
{
	char p[192];
	FILE *f;

	snprintf(p, sizeof(p), "%s/%s", tmpdir, rel);
	f = fopen(p, "w");
	if (!f) {
		printf("FATAL: open %s\n", p);
		exit(2);
	}
	fputs(content, f);
	fclose(f);
}

static int rc_of(const char *value)
{
	char wpath[192], spath[192], *out = NULL;
	int rc;

	snprintf(wpath, sizeof(wpath), "%s/tel", tmpdir);
	snprintf(spath, sizeof(spath), "%s/status", tmpdir);
	wfile("tel", "");	/* procfs 语义：节点在，值由写覆盖 */
	rc = tel_rate_run(value, wpath, spath, &out);
	if (out) {
		free(out);
		out = NULL;
	}
	return rc;
}

int main(void)
{
	char p[192], buf[512];
	unsigned cat, ev, n, rate;
	char err[320];
	char *out = NULL;
	int rc;
	FILE *f;
	size_t got;

	snprintf(tmpdir, sizeof(tmpdir), "/tmp/telrate-%d", (int)getpid());
	{
		char cmd[288];

		snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s",
			 tmpdir, tmpdir);
		if (system(cmd) != 0)
			return 2;
	}

	/* ---- 1) 枚举表/默认率表冻结 ---- */
	CHECK(tel_rate_cats_n == 18, "18 大类在表");
	CHECK(tel_rate_cats[0].cat == 1 && tel_rate_cats[0].ev_max == 8,
	      "cat1 sched ev 1..8");
	CHECK(tel_rate_cats[1].ev_max == 10, "cat2 mm ev 1..10");
	CHECK(tel_rate_cats[15].cat == 16 && tel_rate_cats[15].ev_max == 5,
	      "cat16 hw ev 1..5");
	CHECK(tel_rate_cats[16].ev_max == 3, "cat17 kconfig ev 1..3");
	CHECK(tel_rate_cats[17].cat == 18 && tel_rate_cats[17].ev_max == 2,
	      "cat18 ai ev 1..2");
	CHECK(tel_rate_defaults_n == 3, "默认率表 3 条");
	CHECK(tel_rate_defaults[0].cat == 16 && tel_rate_defaults[0].ev == 1 &&
	      tel_rate_defaults[0].rate == 16, "HW.DEVICE=1/16");
	CHECK(tel_rate_defaults[1].cat == 16 && tel_rate_defaults[1].ev == 4 &&
	      tel_rate_defaults[1].rate == 64, "HW.DMA=1/64");
	CHECK(tel_rate_defaults[2].cat == 17 && tel_rate_defaults[2].ev == 2 &&
	      tel_rate_defaults[2].rate == 16, "KCONFIG.SYSCTL=1/16");

	/* ---- 2) parse 好值 ---- */
	CHECK(tel_rate_parse("16:1:64", &cat, &ev, &n, err, sizeof(err)) == 0 &&
	      cat == 16 && ev == 1 && n == 64, "parse 16:1:64");
	CHECK(tel_rate_parse("rate=17:2:16", &cat, &ev, &n, err,
			     sizeof(err)) == 0 && cat == 17 && ev == 2 &&
	      n == 16, "parse rate= 前缀");
	CHECK(tel_rate_parse(" 1:1:1 ", &cat, &ev, &n, err, sizeof(err)) == 0 &&
	      cat == 1 && ev == 1 && n == 1, "parse 首尾空白容忍");
	CHECK(tel_rate_parse("18:2:0", &cat, &ev, &n, err, sizeof(err)) == 0 &&
	      n == 0, "parse N=0 合法（丢弃）");

	/* ---- 3) parse 坏值（人话报错） ---- */
	CHECK(tel_rate_parse("19:1:1", &cat, &ev, &n, err, sizeof(err)) != 0 &&
	      strstr(err, "1..18"), "cat 越界报有效域");
	CHECK(tel_rate_parse("0:1:1", &cat, &ev, &n, err, sizeof(err)) != 0,
	      "cat=0 拒绝");
	CHECK(tel_rate_parse("1:9:1", &cat, &ev, &n, err, sizeof(err)) != 0 &&
	      strstr(err, "sched") && strstr(err, "1..8"),
	      "cat1 ev 越界带类名与上界");
	CHECK(tel_rate_parse("18:3:1", &cat, &ev, &n, err, sizeof(err)) != 0 &&
	      strstr(err, "ai"), "cat18 ev=3 拒绝（只到 2）");
	CHECK(tel_rate_parse("16:1:65536", &cat, &ev, &n, err, sizeof(err)) !=
	      0 && strstr(err, "65535"), "N 越界提钳制上限");
	CHECK(tel_rate_parse("16:1", &cat, &ev, &n, err, sizeof(err)) != 0,
	      "两段拒绝");
	CHECK(tel_rate_parse("16:1:64:9", &cat, &ev, &n, err, sizeof(err)) !=
	      0 && strstr(err, "多余"), "四段拒绝");
	CHECK(tel_rate_parse("abc", &cat, &ev, &n, err, sizeof(err)) != 0,
	      "非数字拒绝");
	CHECK(tel_rate_parse("16: 1:64", &cat, &ev, &n, err, sizeof(err)) !=
	      0, "段内空白拒绝");
	CHECK(tel_rate_parse("", &cat, &ev, &n, err, sizeof(err)) != 0,
	      "空值拒绝");
	CHECK(tel_rate_parse(NULL, &cat, &ev, &n, err, sizeof(err)) != 0,
	      "NULL 拒绝");

	/* ---- 4) status_find ---- */
	wfile("status",
	      "models: 0\n"
	      "cpu0: emitted=10 dropped=0 sampled_skip=5\n"
	      "  sample_rate[cat=16 ev=1]=64\n"
	      "  sample_rate[cat=17 ev=2]=16\n"
	      "cpu1: emitted=9 dropped=0 sampled_skip=3\n"
	      "  sample_rate[cat=16 ev=1]=64\n"
	      "  sample_rate: all full (1)\n");
	snprintf(p, sizeof(p), "%s/status", tmpdir);
	CHECK(tel_rate_status_find(p, 16, 1, &rate) == 1 && rate == 64,
	      "status_find 命中");
	CHECK(tel_rate_status_find(p, 1, 1, &rate) == 0,
	      "status_find 全量条目不在表（=1）");
	CHECK(tel_rate_status_find(p, 18, 1, &rate) == 0,
	      "cat18 永不在 status（内核循环 1..17）");
	CHECK(tel_rate_status_find("/tmp/telrate-none-status", 1, 1,
				   &rate) == -1, "status 缺文件 -1");

	/* ---- 5) run：OK + 写文件 + 读回一致 ---- */
	snprintf(p, sizeof(p), "%s/tel", tmpdir);
	wfile("tel", "");
	out = NULL;
	rc = tel_rate_run("16:1:64", p, "/tmp/telrate-none-status", &out);
	CHECK(rc == AI_OK, "run OK rc");
	CHECK(out && strstr(out, "OK: 已写"), "run OK 消息");
	CHECK(out && strstr(out, "hw") && strstr(out, "16.01"),
	      "run 消息带类名与 cat.ev");
	f = fopen(p, "r");
	CHECK(f != NULL, "写文件存在");
	if (f) {
		memset(buf, 0, sizeof(buf));
		got = fread(buf, 1, sizeof(buf) - 1, f);
		buf[got] = '\0';
		fclose(f);
		CHECK(strcmp(buf, "rate=16:1:64\n") == 0,
		      "文件内容 rate=16:1:64（内核口同款）");
	}
	free(out); out = NULL;

	/* ---- 6) run：读回校验三分支 ---- */
	/* a) status 命中一致 */
	snprintf(p, sizeof(p), "%s/tel", tmpdir);
	rc = tel_rate_run("16:1:64", p, "/tmp/telrate-none-status", &out);
	/* 上面故意用缺文件 status：走"读回校验跳过"分支 */
	CHECK(rc == AI_OK && out && strstr(out, "读回校验跳过"),
	      "status 缺文件→跳过注记");
	free(out); out = NULL;
	rc = tel_rate_run("17:2:16", p, "/tmp/telrate-none-status", &out);
	CHECK(rc == AI_OK, "run 17:2:16 OK");
	free(out); out = NULL;
	/* b) 真 status 命中 */
	{
		char sp[192];

		snprintf(sp, sizeof(sp), "%s/status", tmpdir);
		rc = tel_rate_run("16:1:64", p, sp, &out);
		CHECK(rc == AI_OK && out && strstr(out, "读回校验一致") &&
		      strstr(out, "sample_rate[cat=16 ev=1]=64"),
		      "读回一致分支");
		free(out); out = NULL;
		/* c) 不一致 */
		rc = tel_rate_run("16:1:32", p, sp, &out);
		CHECK(rc == AI_OK && out && strstr(out, "读回不一致"),
		      "读回不一致如实报");
		free(out); out = NULL;
		/* d) N=1 无行=一致 */
		wfile("status", "cpu0: emitted=1\n  sample_rate: all full (1)\n");
		rc = tel_rate_run("1:1:1", p, sp, &out);
		CHECK(rc == AI_OK && out && strstr(out, "无非默认行"),
		      "N=1 无行=回全量一致");
		free(out); out = NULL;
		/* e) N!=1 但无行（可能并发改回） */
		rc = tel_rate_run("2:3:8", p, sp, &out);
		CHECK(rc == AI_OK && out && strstr(out, "不一致"),
		      "N!=1 无行→复核提示");
		free(out); out = NULL;
	}

	/* ---- 7) run：cat18 注记 + 出厂默认提示 ---- */
	wfile("status", "cpu0: emitted=1\n  sample_rate: all full (1)\n");
	{
		char sp[192];

		snprintf(sp, sizeof(sp), "%s/status", tmpdir);
		rc = tel_rate_run("18:1:8", p, sp, &out);
		CHECK(rc == AI_OK && out && strstr(out, "18 类(ai)不在") &&
		      strstr(out, "ai_procfs.c:112"), "cat18 读回边界注记");
		free(out); out = NULL;
		rc = tel_rate_run("16:1:32", p, sp, &out);
		CHECK(rc == AI_OK && out && strstr(out, "出厂默认 16") &&
		      strstr(out, "16:1:16"), "默认率恢复提示");
		free(out); out = NULL;
		rc = tel_rate_run("1:6:4", p, sp, &out);
		CHECK(rc == AI_OK && out && strstr(out, "出厂默认全量 1"),
		      "全量默认恢复提示");
		free(out); out = NULL;
	}

	/* ---- 8) run：越界人话 + 无内核面 ---- */
	CHECK(rc_of("19:1:1") == AI_ERR_INVALID_ARG, "cat 越界 rc");
	CHECK(rc_of("1:9:1") == AI_ERR_INVALID_ARG, "ev 越界 rc");
	CHECK(rc_of("16:1:99999") == AI_ERR_INVALID_ARG, "N 越界 rc");
	out = NULL;
	rc = tel_rate_run("16:1:64", "/tmp/telrate-none-ai/telemetry",
			  "/tmp/telrate-none-status", &out);
	CHECK(rc == AI_ERR_NOT_FOUND && out &&
	      strstr(out, "非 AIKernel 内核"), "无内核面人话+NOT_FOUND");
	free(out); out = NULL;

	/* ---- 清理 ---- */
	{
		char cmd[288];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
		if (system(cmd) != 0)
			return 2;
	}

	if (fails == 0)
		printf("test_telemetry_rate: all passed\n");
	else
		printf("test_telemetry_rate: %d FAILURES\n", fails);
	return fails ? 1 : 0;
}
