/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_hotplug.c - K3d-2 热插拔建议流水线单测（I-9 MVP）
 *
 * 覆盖（规格 §测试 1）：
 *   1) 事件分类器：uevent/netlink 两来源的进/不进判定（冻结 fixture）
 *   2) advisory JSONL 逐字节冻结（含 executed:false / decision_id:null）
 *   3) infer 超时路径（注入慢 mock：test_sleep_ms + 缩短阈值）
 *   4) advisory 配额（HOTPLUG_DAILY_MAX 打满拒绝）
 *   5) conf 新键：默认值 / 合法覆盖 / 坏值拒绝（行号级原因）
 *   6) executed 恒 false 断言（红线 C7）
 *   7) 集成：真实 tap → 文件 0600 + 父目录创建；enabled=0 零副作用
 *
 * 冻结 digest 由独立 FNV-1a64 参考实现（Python）预计算——本测试同时
 * 交叉验证 C 实现与参考实现一致。
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "as_conf.h"
#include "as_event.h"
#include "as_hotplug.h"
#include "as_stats.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

/* ---- fixture 事件（构造后钉 ts，digest 由构造器算出并与预计算值对拍） ---- */

static void mk_uevent(struct as_event *ev, const char *action,
		      const char *dev, const char *sub, long long ts)
{
	as_event_uevent(ev, action, dev, sub);
	ev->ts_real_ms = ts;
}

static void mk_ai_device(struct as_event *ev, int removed, const char *dev,
			 long long ts)
{
	as_event_ai_device(ev, removed, dev);
	ev->ts_real_ms = ts;
}

static void mk_ai_cpu(struct as_event *ev, int online, int cpu, long long ts)
{
	as_event_ai_cpu(ev, online, cpu);
	ev->ts_real_ms = ts;
}

static void mk_ai_mce(struct as_event *ev, int cpu, int bank, long long ts)
{
	as_event_ai_mce(ev, cpu, bank, "error");
	ev->ts_real_ms = ts;
}

/* ---- 1) 分类器 ---- */

static void test_classify(void)
{
	struct as_event ev;
	struct as_hp_event h;

	/* 进：uevent add/remove/online/offline */
	mk_uevent(&ev, "add", "/devices/virtual/net/k3d2frozen0", "net",
		  1767300000123LL);
	CHECK(as_hp_classify(&ev, &h) == 0, "cls: uevent add in");
	CHECK(h.type == AS_HP_DEV_ADD && strcmp(h.source, "uevent") == 0 &&
	      strcmp(h.dev, "/devices/virtual/net/k3d2frozen0") == 0 &&
	      strcmp(h.subsystem, "net") == 0 && h.ts_real_ms == 1767300000123LL,
	      "cls: uevent add fields");
	CHECK(strcmp(h.payload_digest, "4b71b5e6ab01c481") == 0,
	      "cls: digest cross-check vs reference impl (add)");

	mk_uevent(&ev, "remove", "/devices/virtual/block/loop9", "block", 1);
	CHECK(as_hp_classify(&ev, &h) == 0 && h.type == AS_HP_DEV_REMOVE,
	      "cls: uevent remove in");
	CHECK(strcmp(h.payload_digest, "527d96ba5b55fb08") == 0,
	      "cls: digest cross-check (remove)");
	mk_uevent(&ev, "online", "/devices/system/memory/memory42", "memory",
		  1);
	CHECK(as_hp_classify(&ev, &h) == 0 && h.type == AS_HP_DEV_ONLINE,
	      "cls: uevent online in");
	mk_uevent(&ev, "offline", "/devices/system/memory/memory42", "memory",
		  1);
	CHECK(as_hp_classify(&ev, &h) == 0 && h.type == AS_HP_DEV_OFFLINE,
	      "cls: uevent offline in");

	/* 不进：uevent 状态类动作（change/bind/unbind/move/other） */
	mk_uevent(&ev, "change", "/devices/virtual/block/loop0", "block", 1);
	CHECK(as_hp_classify(&ev, &h) != 0, "cls: uevent change OUT");
	mk_uevent(&ev, "bind", "/devices/x", "block", 1);
	CHECK(as_hp_classify(&ev, &h) != 0, "cls: uevent bind OUT");
	mk_uevent(&ev, "unbind", "/devices/x", "block", 1);
	CHECK(as_hp_classify(&ev, &h) != 0, "cls: uevent unbind OUT");
	mk_uevent(&ev, "move", "/devices/x", "block", 1);
	CHECK(as_hp_classify(&ev, &h) != 0, "cls: uevent move OUT");
	mk_uevent(&ev, "?", "/devices/x", "?", 1);
	CHECK(as_hp_classify(&ev, &h) != 0, "cls: uevent unknown OUT");

	/* 进：NETLINK_AI category 3/4/5（K3d-2 追加契约） */
	mk_ai_device(&ev, 0, "loop9", 1767300000999LL);
	CHECK(as_hp_classify(&ev, &h) == 0 && h.type == AS_HP_DEV_PROBE &&
	      strcmp(h.source, "ai-netlink") == 0 &&
	      strcmp(h.dev, "loop9") == 0,
	      "cls: ai device probe in");
	CHECK(strcmp(ev.line,
		     "[kern] event device action=probe dev=loop9") == 0,
	      "frozen line: ai device probe");
	CHECK(strcmp(h.payload_digest, "e9e721cb975a98d1") == 0,
	      "cls: digest cross-check (probe)");
	mk_ai_device(&ev, 1, "loop9", 1);
	CHECK(as_hp_classify(&ev, &h) == 0 && h.type == AS_HP_DEV_UNPROBE,
	      "cls: ai device remove in");
	CHECK(strcmp(h.payload_digest, "ca5eefdf8c0a6523") == 0,
	      "cls: digest cross-check (unprobe)");
	mk_ai_cpu(&ev, 0, 3, 1767300001001LL);
	CHECK(as_hp_classify(&ev, &h) == 0 && h.type == AS_HP_CPU_OFFLINE &&
	      h.cpu == 3, "cls: ai cpu offline in");
	CHECK(strcmp(h.payload_digest, "4b27f2c334718bf3") == 0,
	      "cls: digest cross-check (cpu offline)");
	mk_ai_cpu(&ev, 1, 5, 1);
	CHECK(as_hp_classify(&ev, &h) == 0 && h.type == AS_HP_CPU_ONLINE &&
	      h.cpu == 5, "cls: ai cpu online in");
	mk_ai_mce(&ev, 2, 4, 1767300002000LL);
	CHECK(as_hp_classify(&ev, &h) == 0 && h.type == AS_HP_MCE &&
	      h.cpu == 2 && h.bank == 4, "cls: ai mce in");

	/* 不进：event 流的 K3c 既有 category（policy/model/other）与其余四路 */
	as_event_ai_policy(&ev, 4711, 2, NULL, "mm.swappiness");
	CHECK(as_hp_classify(&ev, &h) != 0, "cls: event policy OUT");
	as_event_ai_model(&ev, 5, 1, "vmp-logic-v3");
	CHECK(as_hp_classify(&ev, &h) != 0, "cls: event model OUT");
	as_event_mk(&ev, as_stream_idx(AS_STREAM_EVENT), "other", NULL,
		    "event_id=1 category=9");
	CHECK(as_hp_classify(&ev, &h) != 0, "cls: event other OUT");
	as_event_proc_fork(&ev, 1, 42);
	CHECK(as_hp_classify(&ev, &h) != 0, "cls: proc fork OUT");
	as_event_net_link(&ev, 1, 2, "lo", 0x10049);
	CHECK(as_hp_classify(&ev, &h) != 0, "cls: net newlink OUT");
	as_event_nflog(&ev, 0, 0, "p", 0, 0);
	CHECK(as_hp_classify(&ev, &h) != 0, "cls: nflog OUT");
	as_event_taskstats(&ev, 8, 1.5, 0.0, 3);
	CHECK(as_hp_classify(&ev, &h) != 0, "cls: taskstats OUT");

	printf("  classify: OK\n");
}

/* ---- 2) advisory JSONL 逐字节冻结 ---- */

static void test_record_frozen(void)
{
	struct as_event ev;
	struct as_hp_event h;
	struct as_hp_infer skip, ok, mock;
	char buf[AS_HP_LINE_MAX];

	memset(&skip, 0, sizeof(skip));
	skip.status = "skipped_unconfigured";
	memset(&ok, 0, sizeof(ok));
	ok.ok = 1;
	ok.status = "ok";
	snprintf(ok.out_digest, sizeof(ok.out_digest), "0123456789abcdef");
	ok.latency_ns = 123456789;
	memset(&mock, 0, sizeof(mock));
	mock.ok = 1;
	mock.status = "mock";
	snprintf(mock.out_digest, sizeof(mock.out_digest), "0011223344556677");
	mock.latency_ns = 555;

	/* G1: uevent device.add + skipped_unconfigured（e2e 主路径） */
	mk_uevent(&ev, "add", "/devices/virtual/net/k3d2frozen0", "net",
		  1767300000123LL);
	CHECK(as_hp_classify(&ev, &h) == 0, "G1 classify");
	CHECK(as_hp_record_build(&h, &skip, "", 0, buf, sizeof(buf)) > 0,
	      "G1 build");
	CHECK(strcmp(buf,
		"{\"ts\":1767300000123,\"event\":{\"type\":\"device.add\","
		"\"source\":\"uevent\",\"dev\":\"/devices/virtual/net/"
		"k3d2frozen0\",\"subsystem\":\"net\",\"payload_digest\":"
		"\"4b71b5e6ab01c481\"},\"infer\":{\"model\":\"\","
		"\"status\":\"skipped_unconfigured\",\"out_digest\":\"\","
		"\"latency_ns\":0},\"suggestion\":{\"action_knob\":\"none\","
		"\"rationale\":\"device registered - observe and baseline its "
		"IO/latency; advisory mode (I-9 MVP), no automation\"},"
		"\"executed\":false,\"decision_id\":null}\n") == 0,
	      "G1 frozen bytes (device.add + skipped_unconfigured)");

	/* G2: uevent device.remove + C7 红线 rationale */
	mk_uevent(&ev, "remove", "/devices/virtual/block/loop9", "block",
		  1767300000123LL);
	CHECK(as_hp_classify(&ev, &h) == 0, "G2 classify");
	CHECK(as_hp_record_build(&h, &skip, "", 0, buf, sizeof(buf)) > 0,
	      "G2 build");
	CHECK(strcmp(buf,
		"{\"ts\":1767300000123,\"event\":{\"type\":\"device.remove\","
		"\"source\":\"uevent\",\"dev\":\"/devices/virtual/block/loop9\","
		"\"subsystem\":\"block\",\"payload_digest\":"
		"\"527d96ba5b55fb08\"},\"infer\":{\"model\":\"\","
		"\"status\":\"skipped_unconfigured\",\"out_digest\":\"\","
		"\"latency_ns\":0},\"suggestion\":{\"action_knob\":\"none\","
		"\"rationale\":\"C7 RED LINE: device removal/offline actions "
		"are NEVER auto-executed; human review required (advisory "
		"only)\"},\"executed\":false,\"decision_id\":null}\n") == 0,
	      "G2 frozen bytes (device.remove + C7 rationale)");

	/* G3: ai device.probe + infer ok（qemu 真 sysfs 前向形态） */
	mk_ai_device(&ev, 0, "loop9", 1767300000999LL);
	CHECK(as_hp_classify(&ev, &h) == 0, "G3 classify");
	CHECK(as_hp_record_build(&h, &ok, "hp-adv-v1", 0, buf,
				 sizeof(buf)) > 0, "G3 build");
	CHECK(strcmp(buf,
		"{\"ts\":1767300000999,\"event\":{\"type\":\"device.probe\","
		"\"source\":\"ai-netlink\",\"dev\":\"loop9\","
		"\"payload_digest\":\"e9e721cb975a98d1\"},\"infer\":{\"model\":"
		"\"hp-adv-v1\",\"status\":\"ok\",\"out_digest\":"
		"\"0123456789abcdef\",\"latency_ns\":123456789},"
		"\"suggestion\":{\"action_knob\":\"none\",\"rationale\":"
		"\"driver probe completed - observe; advisory mode, no "
		"automation\"},\"executed\":false,\"decision_id\":null}\n") == 0,
	      "G3 frozen bytes (device.probe + infer ok)");

	/* G4: ai cpu.online + infer ok（action_knob 引用既有 ACT 旋钮） */
	mk_ai_cpu(&ev, 1, 5, 1767300001000LL);
	CHECK(as_hp_classify(&ev, &h) == 0, "G4 classify");
	CHECK(as_hp_record_build(&h, &ok, "hp-adv-v1", 0, buf,
				 sizeof(buf)) > 0, "G4 build");
	CHECK(strcmp(buf,
		"{\"ts\":1767300001000,\"event\":{\"type\":\"cpu.online\","
		"\"source\":\"ai-netlink\",\"cpu\":5,\"payload_digest\":"
		"\"7a4b2129778f58ba\"},\"infer\":{\"model\":\"hp-adv-v1\","
		"\"status\":\"ok\",\"out_digest\":\"0123456789abcdef\","
		"\"latency_ns\":123456789},\"suggestion\":{\"action_knob\":"
		"\"sched.affinity\",\"rationale\":\"cpu online: consider "
		"rebalancing task affinity across the new topology - "
		"suggestion only, never executed\"},\"executed\":false,"
		"\"decision_id\":null}\n") == 0,
	      "G4 frozen bytes (cpu.online + sched.affinity)");

	/* G5: ai cpu.offline + infer ok */
	mk_ai_cpu(&ev, 0, 3, 1767300001001LL);
	CHECK(as_hp_classify(&ev, &h) == 0, "G5 classify");
	CHECK(as_hp_record_build(&h, &ok, "hp-adv-v1", 0, buf,
				 sizeof(buf)) > 0, "G5 build");
	CHECK(strcmp(buf,
		"{\"ts\":1767300001001,\"event\":{\"type\":\"cpu.offline\","
		"\"source\":\"ai-netlink\",\"cpu\":3,\"payload_digest\":"
		"\"4b27f2c334718bf3\"},\"infer\":{\"model\":\"hp-adv-v1\","
		"\"status\":\"ok\",\"out_digest\":\"0123456789abcdef\","
		"\"latency_ns\":123456789},\"suggestion\":{\"action_knob\":"
		"\"sched.affinity\",\"rationale\":\"cpu offline: verify no "
		"task affinity is pinned to the offline cpu - suggestion only, "
		"never executed (offline is C7 red line, never "
		"automated)\"},\"executed\":false,\"decision_id\":null}\n") == 0,
	      "G5 frozen bytes (cpu.offline + C7)");

	/* G6: ai mce + infer mock（L1 无内核面明示形态） */
	mk_ai_mce(&ev, 2, 4, 1767300002000LL);
	CHECK(as_hp_classify(&ev, &h) == 0, "G6 classify");
	CHECK(as_hp_record_build(&h, &mock, "hp-adv-v1", 0, buf,
				 sizeof(buf)) > 0, "G6 build");
	CHECK(strcmp(buf,
		"{\"ts\":1767300002000,\"event\":{\"type\":\"mce\","
		"\"source\":\"ai-netlink\",\"cpu\":2,\"bank\":4,"
		"\"payload_digest\":\"337465742987e441\"},\"infer\":{\"model\":"
		"\"hp-adv-v1\",\"status\":\"mock\",\"out_digest\":"
		"\"0011223344556677\",\"latency_ns\":555},\"suggestion\":"
		"{\"action_knob\":\"none\",\"rationale\":\"hardware memory "
		"error: consider offline checks on the affected page/cpu - "
		"advisory only, never executed\"},\"executed\":false,"
		"\"decision_id\":null}\n") == 0,
	      "G6 frozen bytes (mce + mock)");

	printf("  record-frozen: OK\n");
}

/* ---- 3) executed 恒 false（C7 红线断言；think 接口位恒 null） ---- */

static void test_executed_false(void)
{
	struct as_event ev;
	struct as_hp_event h;
	struct as_hp_infer ir;
	struct as_hotplug hp;
	struct as_conf c;
	char buf[AS_HP_LINE_MAX];

	memset(&ir, 0, sizeof(ir));
	ir.status = "ok";
	as_conf_defaults(&c);
	c.hotplug_enabled = 1;
	snprintf(c.hotplug_log, sizeof(c.hotplug_log), "/tmp/as-hp-exec.jsonl");
	{
		struct as_stats st;

		memset(&st, 0, sizeof(st));
		CHECK(as_hotplug_init(&hp, &c, &st) == 0, "exec: init");
		hp.sysfs_present = 0;	/* 单测环境无关化 */

		/* 全类型枚举逐一构造：executed 必须恒 false、decision_id 恒
		 * null（as_hp_think MVP 恒 0） */
		for (int t = AS_HP_DEV_ADD; t <= AS_HP_MCE; t++) {
			switch (t) {
			case AS_HP_DEV_ADD:
				mk_uevent(&ev, "add", "/d/a", "net", 1);
				break;
			case AS_HP_DEV_REMOVE:
				mk_uevent(&ev, "remove", "/d/r", "block", 1);
				break;
			case AS_HP_DEV_ONLINE:
				mk_uevent(&ev, "online", "/d/o", "memory", 1);
				break;
			case AS_HP_DEV_OFFLINE:
				mk_uevent(&ev, "offline", "/d/f", "memory", 1);
				break;
			case AS_HP_DEV_PROBE:
				mk_ai_device(&ev, 0, "d0", 1);
				break;
			case AS_HP_DEV_UNPROBE:
				mk_ai_device(&ev, 1, "d1", 1);
				break;
			case AS_HP_CPU_ONLINE:
				mk_ai_cpu(&ev, 1, 1, 1);
				break;
			case AS_HP_CPU_OFFLINE:
				mk_ai_cpu(&ev, 0, 2, 1);
				break;
			case AS_HP_MCE:
				mk_ai_mce(&ev, 1, 2, 1);
				break;
			default:
				continue;
			}
			CHECK(as_hp_classify(&ev, &h) == 0, "exec: classify");
			CHECK((int)h.type == t, "exec: type order");
			CHECK(as_hp_think(&hp, &h, &ir) == 0,
			      "exec: think stub returns 0 (MVP)");
			CHECK(as_hp_record_build(&h, &ir, "m", 0, buf,
						 sizeof(buf)) > 0,
			      "exec: build");
			CHECK(strstr(buf, "\"executed\":false") != NULL,
			      "exec: executed literal false");
			CHECK(strstr(buf, "\"executed\":true") == NULL,
			      "exec: executed never true");
			CHECK(strstr(buf, "\"decision_id\":null") != NULL,
			      "exec: decision_id null");
		}
		as_hotplug_close(&hp);
	}
	unlink("/tmp/as-hp-exec.jsonl");
	printf("  executed-false: OK\n");
}

/* ---- 4) infer 超时路径（注入慢 mock） ---- */

static void test_infer_timeout(void)
{
	struct as_conf c;
	struct as_stats st;
	struct as_hotplug hp;
	struct as_event ev;

	as_conf_defaults(&c);
	c.hotplug_enabled = 1;
	snprintf(c.hotplug_model, sizeof(c.hotplug_model), "slow-model");
	c.hotplug_infer_mock = 1;
	c.hotplug_daily_max = 100;
	snprintf(c.hotplug_log, sizeof(c.hotplug_log),
		 "/tmp/as-hp-timeout.jsonl");
	unlink("/tmp/as-hp-timeout.jsonl");
	memset(&st, 0, sizeof(st));
	CHECK(as_hotplug_init(&hp, &c, &st) == 0, "timeout: init");
	CHECK(hp.infer_timeout_ms == AS_HP_INFER_TIMEOUT_MS,
	      "timeout: spec default is 2000ms");
	hp.sysfs_present = 0;		/* 环境无关化：强制 mock 路 */
	hp.infer_timeout_ms = 150;	/* 测试缩短阈值（规格 2s 语义不变） */
	hp.test_sleep_ms = 400;		/* TEST ONLY：慢 mock 注入 */

	mk_uevent(&ev, "add", "/devices/virtual/net/k3d2slow", "net",
		  1767300009999LL);
	as_hotplug_tap(&hp, &ev);

	CHECK(st.hp.seen == 1, "timeout: seen=1");
	CHECK(st.hp.infer_timeout == 1, "timeout: infer_timeout=1");
	CHECK(st.hp.advisory_written == 0,
	      "timeout: event abandoned, no advisory");
	CHECK(st.hp.infer_ok == 0 && st.hp.infer_skipped == 0,
	      "timeout: no ok/skip counts");

	/* 快速 mock 不超时：advisory 正常落盘、status=mock */
	hp.test_sleep_ms = 0;
	as_hotplug_tap(&hp, &ev);
	CHECK(st.hp.seen == 2 && st.hp.infer_ok == 1 &&
	      st.hp.advisory_written == 1,
	      "timeout: fast mock writes advisory");
	{
		FILE *f = fopen("/tmp/as-hp-timeout.jsonl", "r");
		char line[AS_HP_LINE_MAX];
		int n = 0;

		CHECK(f != NULL, "timeout: file exists");
		if (f) {
			while (fgets(line, sizeof(line), f))
				n++;
			fclose(f);
		}
		CHECK(n == 1, "timeout: exactly 1 line (timeout dropped)");
	}
	as_hotplug_close(&hp);
	unlink("/tmp/as-hp-timeout.jsonl");
	printf("  infer-timeout: OK\n");
}

/* ---- 5) advisory 配额（HOTPLUG_DAILY_MAX 打满） ---- */

static void test_quota(void)
{
	struct as_conf c;
	struct as_stats st;
	struct as_hotplug hp;
	struct as_event ev;

	as_conf_defaults(&c);
	c.hotplug_enabled = 1;
	c.rate_per_min = 100000;	/* 只测日限 */
	c.hotplug_daily_max = 2;
	snprintf(c.hotplug_log, sizeof(c.hotplug_log), "/tmp/as-hp-quota.jsonl");
	unlink("/tmp/as-hp-quota.jsonl");
	memset(&st, 0, sizeof(st));
	CHECK(as_hotplug_init(&hp, &c, &st) == 0, "quota: init");
	hp.sysfs_present = 0;

	for (int i = 0; i < 3; i++) {
		char dev[64];

		snprintf(dev, sizeof(dev), "/devices/virtual/net/q%d", i);
		mk_uevent(&ev, "add", dev, "net", 1767300010000LL + i);
		as_hotplug_tap(&hp, &ev);
	}
	CHECK(st.hp.seen == 3, "quota: seen=3");
	CHECK(st.hp.advisory_written == 2, "quota: daily_max=2 written");
	CHECK(st.hp.dropped_noquota == 1, "quota: 3rd dropped_noquota");
	CHECK(st.hp.infer_skipped == 2,
	      "quota: only admitted events reach infer");
	as_hotplug_close(&hp);
	unlink("/tmp/as-hp-quota.jsonl");
	printf("  quota: OK\n");
}

/* ---- 6) conf 新键：默认 / 覆盖 / 坏值 ---- */

static int write_conf(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");

	if (!f)
		return -1;
	fputs(content, f);
	fclose(f);
	return 0;
}

static void test_conf(void)
{
	struct as_conf c;
	char err[256];

	as_conf_defaults(&c);
	CHECK(c.hotplug_enabled == 0, "conf: default enabled=0");
	CHECK(c.hotplug_model[0] == '\0', "conf: default model empty");
	CHECK(c.hotplug_daily_max == 200, "conf: default daily=200");
	CHECK(c.hotplug_infer_dim == 8, "conf: default dim=8");
	CHECK(c.hotplug_infer_mock == 0, "conf: default mock=0");
	CHECK(strcmp(c.hotplug_log,
		     "/var/log/aikernel/hotplug-advisories.jsonl") == 0,
	      "conf: default log path");

	CHECK(write_conf("/tmp/as-hp-good.conf",
			 "HOTPLUG_ENABLED=1\n"
			 "HOTPLUG_MODEL=hp-advisor-v1.2\n"
			 "HOTPLUG_DAILY_MAX=50\n"
			 "HOTPLUG_INFER_DIM=16\n"
			 "HOTPLUG_INFER_MOCK=1\n"
			 "HOTPLUG_LOG=/var/log/aikernel/x.jsonl\n") == 0,
	      "conf: write good");
	as_conf_defaults(&c);
	CHECK(as_conf_load(&c, "/tmp/as-hp-good.conf", err, sizeof(err)) == 0,
	      "conf: good file accepted");
	CHECK(c.hotplug_enabled == 1 && c.hotplug_daily_max == 50 &&
	      c.hotplug_infer_dim == 16 && c.hotplug_infer_mock == 1 &&
	      strcmp(c.hotplug_model, "hp-advisor-v1.2") == 0,
	      "conf: overrides applied");

	/* 坏值矩阵（每条独立文件，期望拒绝且 err 带行号） */
	{
		static const struct {
			const char *name, *content;
		} bad[] = {
			{ "enabled=2", "HOTPLUG_ENABLED=2\n" },
			{ "daily=0", "HOTPLUG_DAILY_MAX=0\n" },
			{ "dim=0", "HOTPLUG_INFER_DIM=0\n" },
			{ "dim=65", "HOTPLUG_INFER_DIM=65\n" },
			{ "model-space", "HOTPLUG_MODEL=bad name\n" },
			{ "model-slash", "HOTPLUG_MODEL=bad/name\n" },
			{ "mock=2", "HOTPLUG_INFER_MOCK=2\n" },
			{ "log-relative", "HOTPLUG_LOG=rel/path.jsonl\n" },
			{ "log-dotdot", "HOTPLUG_LOG=/var/../etc/x\n" },
			{ "unknown-key", "HOTPLUG_FOO=1\n" },
			{ "dup-key", "HOTPLUG_ENABLED=1\nHOTPLUG_ENABLED=0\n" },
		};

		for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
			char path[64];

			snprintf(path, sizeof(path), "/tmp/as-hp-bad-%zu.conf",
				 i);
			CHECK(write_conf(path, bad[i].content) == 0,
			      "conf: write bad");
			as_conf_defaults(&c);
			CHECK(as_conf_load(&c, path, err, sizeof(err)) != 0,
			      "conf: rejected");
			CHECK(strncmp(err, "line ", 5) == 0,
			      "conf: err has line number");
			printf("    rejected %-14s → %s", bad[i].name, err);
		}
	}
	unlink("/tmp/as-hp-good.conf");
	printf("  conf: OK\n");
}

/* ---- 7) 集成：真 tap → 文件 0600/父目录创建；enabled=0 零副作用 ---- */

static void test_integration(void)
{
	struct as_conf c;
	struct as_stats st;
	struct as_hotplug hp;
	struct as_event ev;
	struct stat sb;
	const char *dir = "/tmp/as-hp-int-dir-42";
	const char *log = "/tmp/as-hp-int-dir-42/adv.jsonl";

	unlink(log);
	rmdir(dir);

	/* enabled=0：同事件注入 → 计数零变化、文件不出现 */
	as_conf_defaults(&c);
	c.hotplug_enabled = 0;
	snprintf(c.hotplug_log, sizeof(c.hotplug_log), "%s", log);
	memset(&st, 0, sizeof(st));
	CHECK(as_hotplug_init(&hp, &c, &st) == 0, "int: init off");
	mk_uevent(&ev, "add", "/devices/virtual/net/k3d2off", "net",
		  1767300000001LL);
	as_hotplug_tap(&hp, &ev);
	mk_ai_cpu(&ev, 1, 7, 1767300000002LL);
	as_hotplug_tap(&hp, &ev);
	CHECK(st.hp.seen == 0 && st.hp.advisory_written == 0 &&
	      st.hp.dropped_noquota == 0 && st.hp.infer_skipped == 0,
	      "int: enabled=0 zero effect");
	CHECK(stat(log, &sb) != 0, "int: enabled=0 no file");
	as_hotplug_close(&hp);

	/* enabled=1：父目录自动创建（0700）、文件 0600、两源事件各一条 */
	as_conf_defaults(&c);
	c.hotplug_enabled = 1;
	snprintf(c.hotplug_log, sizeof(c.hotplug_log), "%s", log);
	memset(&st, 0, sizeof(st));
	CHECK(as_hotplug_init(&hp, &c, &st) == 0, "int: init on");
	hp.sysfs_present = 0;
	mk_uevent(&ev, "add", "/devices/virtual/net/k3d2on", "net",
		  1767300000003LL);
	as_hotplug_tap(&hp, &ev);
	mk_ai_cpu(&ev, 0, 9, 1767300000004LL);
	as_hotplug_tap(&hp, &ev);
	mk_uevent(&ev, "change", "/devices/virtual/block/loop0", "block",
		  1767300000005LL);
	as_hotplug_tap(&hp, &ev);	/* change：不进 */
	CHECK(st.hp.seen == 2, "int: seen=2 (change excluded)");
	CHECK(st.hp.infer_skipped == 2,
	      "int: model empty → skipped_unconfigured ×2");
	CHECK(st.hp.advisory_written == 2, "int: written=2");
	CHECK(stat(dir, &sb) == 0 && (sb.st_mode & 0777) == 0700,
	      "int: dir created 0700");
	CHECK(stat(log, &sb) == 0 && (sb.st_mode & 0777) == 0600,
	      "int: file mode 0600");
	{
		FILE *f = fopen(log, "r");
		char line[AS_HP_LINE_MAX];
		int n = 0;

		CHECK(f != NULL, "int: log readable");
		if (f) {
			while (fgets(line, sizeof(line), f)) {
				n++;
				CHECK(strstr(line, "\"executed\":false") != NULL,
				      "int: executed false on disk");
			}
			fclose(f);
		}
		CHECK(n == 2, "int: 2 lines on disk");
	}
	as_hotplug_close(&hp);
	unlink(log);
	rmdir(dir);
	printf("  integration: OK\n");
}

int main(void)
{
	test_classify();
	test_record_frozen();
	test_executed_false();
	test_infer_timeout();
	test_quota();
	test_conf();
	test_integration();
	if (fails) {
		printf("test_hotplug: %d failures\n", fails);
		return 1;
	}
	printf("test_hotplug: OK\n");
	return 0;
}
