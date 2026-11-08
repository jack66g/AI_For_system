/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_acpsi.c - K3d-1 PSI 触发源单测（acpsi.c + acconfig psi 段 + acstore psi 持久化）
 *
 * 已知向量风格沿 T5（期望值内联冻结；本模块无 Python 参考版，向量由
 * 规格语义直接推导）：
 *   - parse：/proc/pressure 文件文本（正常/缺 full/坏行/越界/空）；
 *   - read：fixture 目录三文件（缺文件/坏文件）；
 *   - 状态机：冻结时间序列（升阈抑制、回落解除、滞回带、到期续开/解除、
 *     边界值）；
 *   - 降级：读失败 streak→WARN 限频→DEGRADE（抑制一并解除、无自动恢复）；
 *   - gate：抑制期触发延迟文案逐字、到期/常态放行；
 *   - conf：默认关（to_dict 无 psi 键）、坏值/坏类型/交叉拒绝、sanitize、
 *     load/save 往返；
 *   - 持久化：sessions-state.json psi 段写入/清除/向后兼容加载。
 *
 * 运行：./tests/test_acpsi
 */
#define _DEFAULT_SOURCE 1

#include "autocondense/acpsi.h"
#include "autocondense/acstate.h"

#include "ac_vec.h"

#include <sys/stat.h>
#include <unistd.h>

/* 冻结时钟（ac_iso_epoch/状态文件 saved_at 一致性；机器测试直接注入 now）*/
#define FROZEN_EPOCH 1775000000.0

static aik_json *parse_text(const char *text)
{
	char err[128];
	aik_json *v = aik_json_parse(text, strlen(text), err, sizeof(err));

	if (!v) {
		fprintf(stderr, "FATAL: parse %s: %s\n", text, err);
		exit(2);
	}
	return v;
}

static void write_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "wb");

	if (!f) {
		fprintf(stderr, "FATAL: cannot write %s\n", path);
		exit(2);
	}
	fwrite(text, 1, strlen(text), f);
	fclose(f);
}

static ac_psi_values mkvals(double cpu, double mem, double io, double at)
{
	ac_psi_values v;

	memset(&v, 0, sizeof(v));
	v.cpu.some = cpu;
	v.cpu.full = -1.0;
	v.cpu.has_full = 0;
	v.mem.some = mem;
	v.mem.full = mem > 0 ? mem / 2 : 0.0;
	v.mem.has_full = 1;
	v.io.some = io;
	v.io.full = 0.0;
	v.io.has_full = 1;
	v.at = at;
	return v;
}

/* ---- 1. parse ------------------------------------------------------ */

static void test_parse(void)
{
	static const struct {
		const char *name;
		const char *text;
		int ok;
		double some;
		double full;
		int has_full;
	} CASES[] = {
		{ "memory-normal",
		  "some avg10=1.23 avg60=2.34 avg300=3.45 total=123456\n"
		  "full avg10=0.12 avg60=0.23 avg300=0.34 total=234567\n",
		  1, 1.23, 0.12, 1 },
		{ "cpu-some-only",
		  "some avg10=4.56 avg60=5.67 avg300=6.78 total=3456789\n",
		  1, 4.56, -1.0, 0 },
		{ "crlf",
		  "some avg10=7.89 avg60=0.00 avg300=0.00 total=9\r\n"
		  "full avg10=0.00 avg60=0.00 avg300=0.00 total=9\r\n",
		  1, 7.89, 0.0, 1 },
		{ "zero-boundary",
		  "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n", 1, 0.0, -1.0, 0 },
		{ "hundred-boundary",
		  "some avg10=100.00 avg60=0.00 avg300=0.00 total=0\n", 1, 100.0, -1.0, 0 },
		{ "extra-lines-ignored",
		  "# comment\nsome avg10=8.01 avg60=0.00 avg300=0.00 total=1\njunk\n",
		  1, 8.01, -1.0, 0 },
		{ "bad-value", "some avg10=xx avg60=0 total=0\n", 0, 0, 0, 0 },
		{ "bad-missing-avg10", "some avg60=1.0 avg300=2.0 total=3\n", 0, 0, 0, 0 },
		{ "bad-no-some-line",
		  "full avg10=1.00 avg60=0 total=0\n", 0, 0, 0, 0 },
		{ "bad-empty", "", 0, 0, 0, 0 },
		{ "bad-some-only-word", "some\n", 0, 0, 0, 0 },
		{ "bad-full-line",
		  "some avg10=1.00 avg60=0 total=0\nfull avg10=zz total=0\n",
		  0, 0, 0, 0 },
		{ "bad-out-of-range", "some avg10=150.00 avg60=0 total=0\n", 0, 0, 0, 0 },
		{ "bad-negative", "some avg10=-1.00 avg60=0 total=0\n", 0, 0, 0, 0 },
		{ "bad-prefix-somex", "somex avg10=1.00 avg60=0 total=0\n", 0, 0, 0, 0 },
	};
	size_t n = sizeof(CASES) / sizeof(CASES[0]);

	for (size_t i = 0; i < n; i++) {
		ac_psi_res r;
		int rc = ac_psi_parse(CASES[i].text, &r);

		g_ac_checks++;
		if (rc == 0 && !CASES[i].ok)
			ac_fail("parse[%zu] (%s) 应失败却成功", i, CASES[i].name);
		if (rc != 0 && CASES[i].ok)
			ac_fail("parse[%zu] (%s) 应成功却失败", i, CASES[i].name);
		if (rc != 0)
			continue;
		g_ac_checks++;
		if (r.some != CASES[i].some)
			ac_fail("parse[%zu] (%s) some=%.4f want=%.4f", i,
				CASES[i].name, r.some, CASES[i].some);
		g_ac_checks++;
		if (r.has_full != CASES[i].has_full ||
		    (CASES[i].has_full && r.full != CASES[i].full))
			ac_fail("parse[%zu] (%s) full=%.4f has=%d want=%.4f has=%d",
				i, CASES[i].name, r.full, r.has_full,
				CASES[i].full, CASES[i].has_full);
	}
	g_ac_checks++;
	if (ac_psi_parse(NULL, NULL) == 0)
		ac_fail("parse NULL 应失败");
}

/* ---- 2. read（fixture 目录）---------------------------------------- */

static void test_read(const char *tmp)
{
	char dir[512];
	char path[600];
	ac_psi_values v;

	snprintf(dir, sizeof(dir), "%s/psi-ok", tmp);
	mkdir(dir, 0755);
	snprintf(path, sizeof(path), "%s/cpu", dir);
	write_file(path,
		   "some avg10=2.50 avg60=0.00 avg300=0.00 total=100\n");
	snprintf(path, sizeof(path), "%s/memory", dir);
	write_file(path,
		   "some avg10=66.66 avg60=10.00 avg300=1.00 total=200\n"
		   "full avg10=33.33 avg60=5.00 avg300=0.50 total=150\n");
	snprintf(path, sizeof(path), "%s/io", dir);
	write_file(path,
		   "some avg10=0.10 avg60=0.00 avg300=0.00 total=300\n"
		   "full avg10=0.00 avg60=0.00 avg300=0.00 total=290\n");

	g_ac_checks++;
	if (ac_psi_read(dir, &v, 1775000100.0) != 0) {
		ac_fail("read 正常目录应成功");
	} else {
		g_ac_checks++;
		if (v.cpu.some != 2.50 || v.cpu.has_full)
			ac_fail("read cpu some=%.2f has_full=%d", v.cpu.some,
				v.cpu.has_full);
		g_ac_checks++;
		if (v.mem.some != 66.66 || !v.mem.has_full || v.mem.full != 33.33)
			ac_fail("read memory some=%.2f full=%.2f", v.mem.some,
				v.mem.full);
		g_ac_checks++;
		if (v.io.some != 0.10 || !v.io.has_full || v.io.full != 0.00)
			ac_fail("read io some=%.2f full=%.2f", v.io.some, v.io.full);
		g_ac_checks++;
		if (v.at != 1775000100.0)
			ac_fail("read at=%.1f 应原样回带", v.at);
	}

	/* 缺 io 文件 */
	snprintf(dir, sizeof(dir), "%s/psi-noio", tmp);
	mkdir(dir, 0755);
	snprintf(path, sizeof(path), "%s/cpu", dir);
	write_file(path, "some avg10=1.00 avg60=0.00 avg300=0.00 total=1\n");
	snprintf(path, sizeof(path), "%s/memory", dir);
	write_file(path, "some avg10=1.00 avg60=0.00 avg300=0.00 total=1\n");
	g_ac_checks++;
	if (ac_psi_read(dir, &v, 0.0) == 0)
		ac_fail("read 缺 io 应失败");

	/* memory 坏文件 */
	snprintf(dir, sizeof(dir), "%s/psi-bad", tmp);
	mkdir(dir, 0755);
	snprintf(path, sizeof(path), "%s/cpu", dir);
	write_file(path, "some avg10=1.00 avg60=0.00 avg300=0.00 total=1\n");
	snprintf(path, sizeof(path), "%s/memory", dir);
	write_file(path, "garbage\n");
	snprintf(path, sizeof(path), "%s/io", dir);
	write_file(path, "some avg10=1.00 avg60=0.00 avg300=0.00 total=1\n");
	g_ac_checks++;
	if (ac_psi_read(dir, &v, 0.0) == 0)
		ac_fail("read memory 坏文件应失败");

	g_ac_checks++;
	if (ac_psi_read("/nonexistent-psi-dir", &v, 0.0) == 0)
		ac_fail("read 不存在目录应失败");
}

/* ---- 3. 状态机冻结序列 --------------------------------------------- */

static void test_machine(void)
{
	ac_config cfg;
	ac_psi_machine m;
	ac_psi_event ev;
	ac_psi_values tv;

	ac_config_default(&cfg);
	/* high=50 low=20 window=120（默认）*/
	ac_psi_machine_init(&m, &cfg.psi);
	g_ac_checks++;
	if (m.state != AC_PSI_STATE_NORMAL || m.high_threshold != 50.0 ||
	    m.low_threshold != 20.0 || m.window_s != 120.0 ||
	    m.period_s != 5.0)
		ac_fail("machine init 快照错误");

	/* t=0：低压 → 无事 */
	tv = mkvals(1, 0, 0, 0);
	g_ac_checks++;
	if (ac_psi_step(&m, &tv, 0, &ev) != AC_PSI_EV_NONE ||
	    m.state != AC_PSI_STATE_NORMAL)
		ac_fail("t=0 低压应无事件");

	/* t=5：mem=60 ≥ 50 → 开窗 #1 */
	tv = mkvals(1, 60, 0, 5);
	g_ac_checks++;
	if (ac_psi_step(&m, &tv, 5, &ev) != AC_PSI_EV_SUPPRESS_START ||
	    m.state != AC_PSI_STATE_SUPPRESSED ||
	    m.suppressed_count != 1 || m.window_open_at != 5 ||
	    ev.counter != 1 || ev.v.mem.some != 60.0)
		ac_fail("t=5 升阈应开窗 #1（count=%lld open=%.0f）",
			m.suppressed_count, m.window_open_at);

	/* t=10：mem=35 滞回带 → 维持抑制 */
	tv = mkvals(1, 35, 0, 10);
	g_ac_checks++;
	if (ac_psi_step(&m, &tv, 10, &ev) != AC_PSI_EV_NONE ||
	    m.state != AC_PSI_STATE_SUPPRESSED || !ac_psi_suppressed(&m, 10))
		ac_fail("t=10 滞回带应维持抑制");

	/* t=15：mem=10 < 20 → 解除 */
	tv = mkvals(1, 10, 0, 15);
	g_ac_checks++;
	if (ac_psi_step(&m, &tv, 15, &ev) != AC_PSI_EV_END_CLEAR ||
	    m.state != AC_PSI_STATE_NORMAL || m.suppressed_count != 1)
		ac_fail("t=15 回落应解除");

	/* t=20：mem=50.00 恰等高阈（≥ 语义）→ 开窗 #2 */
	tv = mkvals(1, 50.0, 0, 20);
	g_ac_checks++;
	if (ac_psi_step(&m, &tv, 20, &ev) != AC_PSI_EV_SUPPRESS_START ||
	    m.suppressed_count != 2 || m.window_open_at != 20)
		ac_fail("t=20 恰等高阈应开窗");

	/* t=25..135：mem=25（带内）无事件；t=125 窗口内最后一刻 */
	tv = mkvals(1, 25, 0, 125);
	g_ac_checks++;
	if (ac_psi_step(&m, &tv, 125, &ev) != AC_PSI_EV_NONE ||
	    !ac_psi_suppressed(&m, 125))
		ac_fail("t=125 应仍在窗口 [20,140) 内");
	g_ac_checks++;
	if (ac_psi_suppressed(&m, 140.0))
		ac_fail("t=140 到期瞬间 suppressed 应为 0（照常评估）");

	/* t=140：带内到期 → END_EXPIRE */
	tv = mkvals(1, 25, 0, 140);
	g_ac_checks++;
	if (ac_psi_step(&m, &tv, 140, &ev) != AC_PSI_EV_END_EXPIRE ||
	    m.state != AC_PSI_STATE_NORMAL)
		ac_fail("t=140 带内到期应 END_EXPIRE");

	/* t=200：mem=80 → 开窗 #3 [200,320) */
	tv = mkvals(1, 80, 0, 200);
	ac_psi_step(&m, &tv, 200, &ev);
	g_ac_checks++;
	if (m.state != AC_PSI_STATE_SUPPRESSED || m.suppressed_count != 3)
		ac_fail("t=200 应开窗 #3");

	/* t=325：窗口 [200,320) 已到期且 mem=90 仍高 → 续开 #4 */
	tv = mkvals(1, 90, 0, 325);
	g_ac_checks++;
	if (ac_psi_step(&m, &tv, 325, &ev) != AC_PSI_EV_REARM ||
	    m.state != AC_PSI_STATE_SUPPRESSED ||
	    m.suppressed_count != 4 || m.window_open_at != 325 ||
	    !ac_psi_suppressed(&m, 326))
		ac_fail("t=325 到期仍高应续开 #4（count=%lld open=%.0f）",
			m.suppressed_count, m.window_open_at);
	g_ac_checks++;
	if (ac_psi_suppressed(&m, 445.0))
		ac_fail("续开窗 [325,445) 到期后 suppressed 应为 0");

	/* 恰等低阈不算回落（< 语义严格）*/
	tv = mkvals(1, 20.0, 0, 330);
	ac_psi_step(&m, &tv, 330, &ev);
	g_ac_checks++;
	if (m.state != AC_PSI_STATE_SUPPRESSED)
		ac_fail("mem=20.00 恰等低阈应维持抑制（< 才解除）");

	/* 计数与采样统计 */
	g_ac_checks++;
	if (m.samples < 8 || m.has_last != 1 || m.last.mem.some != 20.0)
		ac_fail("samples=%lld has_last=%d last=%.2f", m.samples,
			m.has_last, m.last.mem.some);

	/* off：计数保留、窗口清零、不再推进 */
	long long keep = m.suppressed_count;

	ac_psi_machine_off(&m);
	g_ac_checks++;
	if (m.state != AC_PSI_STATE_OFF || m.window_open_at != 0.0 ||
	    m.suppressed_count != keep)
		ac_fail("off 应清窗口留计数");
	tv = mkvals(1, 99, 0, 400);
	g_ac_checks++;
	if (ac_psi_step(&m, &tv, 400, &ev) != AC_PSI_EV_NONE ||
	    ac_psi_suppressed(&m, 400))
		ac_fail("off 后不应推进");

	/* 钳制：越界 conf 回落默认 */
	{
		ac_psi_config bad;

		ac_psi_config_default(&bad);
		bad.period_s = 0;
		bad.window_s = -5;
		bad.high_threshold = 200.0;
		bad.low_threshold = 300.0;
		ac_psi_machine_init(&m, &bad);
		g_ac_checks++;
		if (m.period_s != 5.0 || m.window_s != 120.0 ||
		    m.high_threshold != 50.0 || m.low_threshold != 20.0)
			ac_fail("钳制后应回落默认（p=%.0f w=%.0f h=%.2f l=%.2f）",
				m.period_s, m.window_s, m.high_threshold,
				m.low_threshold);
	}
	ac_config_cleanup(&cfg);
}

/* ---- 4. gate（触发延迟文案）---------------------------------------- */

static void test_gate(void)
{
	ac_config cfg;
	ac_psi_machine m;
	ac_psi_event ev;
	ac_psi_values tv;
	char reason[256];

	ac_config_default(&cfg);
	ac_psi_machine_init(&m, &cfg.psi);
	tv = mkvals(1.5, 87.5, 0.25, 1000);
	ac_psi_step(&m, &tv, 1000, &ev);

	memset(reason, 'x', sizeof(reason));
	g_ac_checks++;
	if (!ac_psi_gate(&m, 1010, reason, sizeof(reason)))
		ac_fail("抑制期 gate 应返回 1");
	g_ac_checks++;
	if (strcmp(reason,
		   "PSI 内存压力抑制窗口内（memory some avg10=87.50%，"
		   "高阈 50.00%），压缩触发延迟（不丢弃），"
		   "窗口结束或压力回落后恢复评估") != 0)
		ac_fail("gate 文案不符：\n  got:  %s", reason);

	/* 延迟计数 */
	long long before = m.deferred_count;

	ac_psi_note_deferred(&m);
	ac_psi_note_deferred(&m);
	g_ac_checks++;
	if (m.deferred_count != before + 2)
		ac_fail("deferred 计数 %lld", m.deferred_count);

	/* 到期（未续开采样）→ 放行 */
	memset(reason, 'x', sizeof(reason));
	g_ac_checks++;
	if (ac_psi_gate(&m, 1000 + 120 + 1, reason, sizeof(reason)) ||
	    reason[0] != 'x')
		ac_fail("窗口到期后 gate 应放行且不写文案");

	/* 常态放行 */
	ac_psi_machine_init(&m, &cfg.psi);
	g_ac_checks++;
	if (ac_psi_gate(&m, 50, reason, sizeof(reason)))
		ac_fail("常态 gate 应放行");

	/* 事件文案抽查 */
	char buf[512];

	tv = mkvals(1.5, 87.5, 0.25, 1000);
	ac_psi_step(&m, &tv, 1000, &ev);
	ac_psi_format_event(&ev, buf, sizeof(buf));
	g_ac_checks++;
	if (strcmp(buf,
		   "抑制窗口开启 #1：memory some avg10=87.50% ≥ 高阈 50.00%"
		   "（cpu some=1.50%，io some=0.25%），窗口 120s") != 0)
		ac_fail("START 文案不符：\n  got: %s", buf);
	tv = mkvals(1.5, 10.0, 0.25, 1010);
	ac_psi_step(&m, &tv, 1010, &ev);
	ac_psi_format_event(&ev, buf, sizeof(buf));
	g_ac_checks++;
	if (strcmp(buf,
		   "抑制解除（压力回落）：memory some avg10=10.00% < 低阈 20.00%"
		   "，延迟的压缩评估恢复") != 0)
		ac_fail("END_CLEAR 文案不符：\n  got: %s", buf);
	g_ac_checks++;
	if (strcmp(ac_psi_state_name(AC_PSI_STATE_OFF), "off") != 0 ||
	    strcmp(ac_psi_state_name(AC_PSI_STATE_SUPPRESSED),
		   "suppressed") != 0 ||
	    strcmp(ac_psi_state_name(AC_PSI_STATE_DEGRADED),
		   "degraded") != 0 ||
	    strcmp(ac_psi_state_name(AC_PSI_STATE_NORMAL), "normal") != 0)
		ac_fail("state 名错误");
	ac_config_cleanup(&cfg);
}

/* ---- 5. 降级 ------------------------------------------------------- */

static void test_degrade(void)
{
	ac_config cfg;
	ac_psi_machine m;
	ac_psi_event ev;
	ac_psi_values tv;

	ac_config_default(&cfg);

	/* 常态读失败：WARN（首个即时）→ 限频静默 → 第 3 次 DEGRADE */
	ac_psi_machine_init(&m, &cfg.psi);
	g_ac_checks++;
	if (ac_psi_step(&m, NULL, 100, &ev) != AC_PSI_EV_WARN ||
	    m.fail_streak != 1 || m.state != AC_PSI_STATE_NORMAL)
		ac_fail("首失败应 WARN");
	g_ac_checks++;
	if (ac_psi_step(&m, NULL, 105, &ev) != AC_PSI_EV_NONE)
		ac_fail("限频期内应静默");
	g_ac_checks++;
	if (ac_psi_step(&m, NULL, 110, &ev) != AC_PSI_EV_DEGRADE ||
	    m.state != AC_PSI_STATE_DEGRADED || m.degrade_count != 1 ||
	    ev.was_suppressed)
		ac_fail("第 3 次失败应 DEGRADE（count=%lld）", m.degrade_count);
	/* 无自动恢复 */
	tv = mkvals(0, 0, 0, 120);
	g_ac_checks++;
	if (ac_psi_step(&m, &tv, 120, &ev) != AC_PSI_EV_NONE ||
	    m.state != AC_PSI_STATE_DEGRADED)
		ac_fail("DEGRADED 后不应自动恢复");

	/* WARN 限频窗口过后再告警 */
	ac_psi_machine_init(&m, &cfg.psi);
	ac_psi_step(&m, NULL, 100, &ev);
	g_ac_checks++;
	if (ac_psi_step(&m, NULL, 161, &ev) != AC_PSI_EV_WARN)
		ac_fail("61s 后应再 WARN");

	/* 抑制期读失败：降级时抑制一并解除（was_suppressed=1）*/
	ac_psi_machine_init(&m, &cfg.psi);
	tv = mkvals(0, 80, 0, 200);
	ac_psi_step(&m, &tv, 200, &ev);
	g_ac_checks++;
	if (m.state != AC_PSI_STATE_SUPPRESSED)
		ac_fail("前置：应已抑制");
	ac_psi_step(&m, NULL, 205, &ev);
	ac_psi_step(&m, NULL, 210, &ev);
	g_ac_checks++;
	if (ac_psi_step(&m, NULL, 215, &ev) != AC_PSI_EV_DEGRADE ||
	    !ev.was_suppressed || m.state != AC_PSI_STATE_DEGRADED ||
	    ac_psi_suppressed(&m, 216))
		ac_fail("抑制期降级应解除抑制");

	/* 启动探测失败的显式降级 */
	ac_psi_machine_init(&m, &cfg.psi);
	ac_psi_degrade(&m, 300);
	g_ac_checks++;
	if (m.state != AC_PSI_STATE_DEGRADED || m.degrade_count != 1)
		ac_fail("显式降级失败");
	ac_config_cleanup(&cfg);
}

/* ---- 6. conf 校验/默认/序列化 --------------------------------------- */

static void expect_errors(const char *name, const char *json, int nerr,
			  const char *want0, const char *want1)
{
	aik_json *d = parse_text(json);
	aik_json *errs = ac_validate_config_dict(d);
	char *got = ac_dump(errs);
	char want[512];

	want[0] = '\0';
	if (want0)
		snprintf(want, sizeof(want), "%s", want0);
	g_ac_checks++;
	if (!errs || aik_json_count(errs) != (size_t)nerr ||
	    (nerr > 0 && strcmp(aik_json_str(aik_json_at(errs, 0)), want) != 0))
		ac_fail("validate(%s) got=%s want0=%s", name, got ? got : "?",
			want);
	if (nerr > 1 && want1) {
		g_ac_checks++;
		if (strcmp(aik_json_str(aik_json_at(errs, 1)), want1) != 0)
			ac_fail("validate(%s)[1] got=%s want=%s", name,
				aik_json_str(aik_json_at(errs, 1)), want1);
	}
	free(got);
	aik_json_free(errs);
	aik_json_free(d);
}

static void test_config(void)
{
	/* 默认关：to_dict 无 psi 键 */
	{
		ac_config cfg;
		ac_config_default(&cfg);
		aik_json *d = ac_config_to_dict(&cfg);

		g_ac_checks++;
		if (!d || aik_json_get(d, "psi") != NULL || cfg.psi_present ||
		    cfg.psi.enabled || cfg.psi.period_s != 5 ||
		    cfg.psi.high_threshold != 50.0 ||
		    cfg.psi.low_threshold != 20.0 || cfg.psi.window_s != 120)
			ac_fail("默认应无 psi 键且 psi.enabled=0");
		aik_json_free(d);
		ac_config_cleanup(&cfg);
	}

	/* 合法全量 */
	expect_errors("psi-ok",
		      "{\"psi\":{\"enabled\":true,\"period_s\":5,"
		      "\"high_threshold\":50.0,\"low_threshold\":20.0,"
		      "\"window_s\":120}}", 0, NULL, NULL);
	/* 部分（交叉字段缺一不算错）*/
	expect_errors("psi-partial",
		      "{\"psi\":{\"enabled\":true}}", 0, NULL, NULL);
	expect_errors("psi-partial-high",
		      "{\"psi\":{\"high_threshold\":50.0}}", 0, NULL, NULL);
	/* 坏类型 */
	expect_errors("psi-not-obj", "{\"psi\":1}", 1, "psi 应为对象", NULL);
	expect_errors("psi-unknown",
		      "{\"psi\":{\"foo\":1}}", 1,
		      "未知配置项：psi.foo", NULL);
	expect_errors("psi-enabled-int",
		      "{\"psi\":{\"enabled\":1}}", 1,
		      "psi.enabled 应为布尔值", NULL);
	expect_errors("psi-period-float",
		      "{\"psi\":{\"period_s\":2.5}}", 1,
		      "psi.period_s 应为整数", NULL);
	expect_errors("psi-high-str",
		      "{\"psi\":{\"high_threshold\":\"50\"}}", 1,
		      "psi.high_threshold 应为数字", NULL);
	/* 坏值 */
	expect_errors("psi-period-0",
		      "{\"psi\":{\"period_s\":0}}", 1,
		      "psi.period_s 应为不小于 1 的整数", NULL);
	expect_errors("psi-window-0",
		      "{\"psi\":{\"window_s\":0}}", 1,
		      "psi.window_s 应为不小于 1 的整数", NULL);
	expect_errors("psi-high-0",
		      "{\"psi\":{\"high_threshold\":0}}", 1,
		      "psi.high_threshold 应在 0 到 100 之间", NULL);
	expect_errors("psi-high-100.5",
		      "{\"psi\":{\"high_threshold\":100.5}}", 1,
		      "psi.high_threshold 应在 0 到 100 之间", NULL);
	expect_errors("psi-low-neg",
		      "{\"psi\":{\"low_threshold\":-1}}", 1,
		      "psi.low_threshold 应在 0 到 100 之间", NULL);
	expect_errors("psi-low-100",
		      "{\"psi\":{\"low_threshold\":100}}", 1,
		      "psi.low_threshold 应在 0 到 100 之间", NULL);
	/* 交叉 */
	expect_errors("psi-cross-eq",
		      "{\"psi\":{\"high_threshold\":30.0,"
		      "\"low_threshold\":30.0}}", 1,
		      "psi.low_threshold 应小于 psi.high_threshold", NULL);
	expect_errors("psi-cross-inv",
		      "{\"psi\":{\"high_threshold\":10.0,"
		      "\"low_threshold\":20.0}}", 1,
		      "psi.low_threshold 应小于 psi.high_threshold", NULL);
	/* 边界合法：low=0、high=100 */
	expect_errors("psi-edge",
		      "{\"psi\":{\"high_threshold\":100.0,"
		      "\"low_threshold\":0.0}}", 0, NULL, NULL);

	/* apply：psi_present 置位 + 字段 + to_dict 输出 */
	{
		ac_config cfg;
		aik_json *d = parse_text(
			"{\"psi\":{\"enabled\":true,\"period_s\":10,"
			"\"high_threshold\":40.0,\"low_threshold\":5.0,"
			"\"window_s\":60}}");

		ac_config_default(&cfg);
		g_ac_checks++;
		if (ac_config_apply_dict(&cfg, d) != 0 || !cfg.psi_present ||
		    !cfg.psi.enabled || cfg.psi.period_s != 10 ||
		    cfg.psi.high_threshold != 40.0 ||
		    cfg.psi.low_threshold != 5.0 || cfg.psi.window_s != 60)
			ac_fail("apply psi 应置 psi_present 并生效");
		aik_json *out = ac_config_to_dict(&cfg);
		const aik_json *psi = aik_json_get(out, "psi");

		g_ac_checks++;
		if (!psi || !aik_json_bool(aik_json_get(psi, "enabled")) ||
		    aik_json_int(aik_json_get(psi, "period_s")) != 10 ||
		    aik_json_num(aik_json_get(psi, "high_threshold")) != 40.0 ||
		    aik_json_num(aik_json_get(psi, "low_threshold")) != 5.0 ||
		    aik_json_int(aik_json_get(psi, "window_s")) != 60)
			ac_fail("to_dict psi 段字段错误");
		g_ac_checks++;
		if (aik_json_count(psi) != 5)
			ac_fail("to_dict psi 应恰 5 键");
		aik_json_free(out);
		aik_json_free(d);
		ac_config_cleanup(&cfg);
	}

	/* sanitize：类型不符/越界/交叉丢键，合法保留 */
	{
		aik_json *d = parse_text(
			"{\"psi\":{\"enabled\":true,\"bogus\":1,"
			"\"period_s\":0,\"high_threshold\":200.0,"
			"\"low_threshold\":20.0,\"window_s\":30}}");
		aik_json *san = ac_sanitize_config_dict(d);
		const aik_json *psi = aik_json_get(san, "psi");

		/* high=200 越界丢弃；low=20 合法且 20<200 交叉通过 → 保留 */
		g_ac_checks++;
		if (!psi || aik_json_count(psi) != 3 ||
		    !aik_json_get(psi, "enabled") ||
		    !aik_json_get(psi, "window_s") ||
		    !aik_json_get(psi, "low_threshold") ||
		    aik_json_get(psi, "bogus") ||
		    aik_json_get(psi, "period_s") ||
		    aik_json_get(psi, "high_threshold"))
			ac_fail("sanitize 应留 enabled+window_s+low_threshold");
		aik_json_free(san);
		aik_json_free(d);
	}
	{
		aik_json *d = parse_text(
			"{\"psi\":{\"high_threshold\":30.0,"
			"\"low_threshold\":30.0,\"enabled\":true}}");
		aik_json *san = ac_sanitize_config_dict(d);
		const aik_json *psi = aik_json_get(san, "psi");

		g_ac_checks++;
		if (!psi || aik_json_get(psi, "high_threshold") ||
		    aik_json_get(psi, "low_threshold") ||
		    !aik_json_get(psi, "enabled"))
			ac_fail("sanitize 交叉不符应丢双阈");
		aik_json_free(san);
		aik_json_free(d);
	}

	/* 无 psi 的配置 sanitize 后仍无 psi（默认关字节不变的一环）*/
	{
		aik_json *d = parse_text("{\"port\":9000,\"enabled\":true}");
		aik_json *san = ac_sanitize_config_dict(d);

		g_ac_checks++;
		if (aik_json_get(san, "psi") != NULL)
			ac_fail("无 psi 输入 sanitize 后不应凭空出现 psi");
		aik_json_free(san);
		aik_json_free(d);
	}
}

/* ---- 7. 持久化（config.json 往返 + sessions-state.json psi 段）----- */

static void test_persist(const char *tmp)
{
	char dir[512];
	ac_config cfg;

	/* config.json 往返：写 psi → load 回来 psi_present/enabled；无 psi → 0 */
	snprintf(dir, sizeof(dir), "%s/cfg-with-psi", tmp);
	mkdir(dir, 0755);
	ac_config_default(&cfg);
	{
		aik_json *d = parse_text(
			"{\"psi\":{\"enabled\":true,\"period_s\":7,"
			"\"high_threshold\":45.0,\"low_threshold\":15.0,"
			"\"window_s\":90}}");

		ac_config_apply_dict(&cfg, d);
		aik_json_free(d);
	}
	g_ac_checks++;
	if (ac_save_config(dir, &cfg) != 0)
		ac_fail("save_config(psi) 应成功");
	ac_config_cleanup(&cfg);
	g_ac_checks++;
	if (ac_load_config(dir, &cfg) != 0 || !cfg.psi_present ||
	    !cfg.psi.enabled || cfg.psi.period_s != 7 ||
	    cfg.psi.high_threshold != 45.0 || cfg.psi.window_s != 90)
		ac_fail("load_config(psi) 往返错误");
	ac_config_cleanup(&cfg);

	snprintf(dir, sizeof(dir), "%s/cfg-no-psi", tmp);
	mkdir(dir, 0755);
	ac_config_default(&cfg);
	ac_save_config(dir, &cfg);
	ac_config_cleanup(&cfg);
	g_ac_checks++;
	if (ac_load_config(dir, &cfg) != 0 || cfg.psi_present)
		ac_fail("无 psi 的 config.json 应保持 psi_present=0");
	ac_config_cleanup(&cfg);

	/* 手写坏值 psi 的 config.json：load 容忍（sanitize 丢键→默认值）*/
	snprintf(dir, sizeof(dir), "%s/cfg-bad-psi", tmp);
	mkdir(dir, 0755);
	{
		char path[600];

		snprintf(path, sizeof(path), "%s/config.json", dir);
		write_file(path,
			   "{\"port\":8762,\"psi\":{\"enabled\":true,"
			   "\"high_threshold\":500.0,\"low_threshold\":10.0,"
			   "\"period_s\":3}}");
	}
	g_ac_checks++;
	if (ac_load_config(dir, &cfg) != 0 || !cfg.psi_present ||
	    !cfg.psi.enabled || cfg.psi.high_threshold != 50.0 ||
	    cfg.psi.low_threshold != 10.0 || cfg.psi.period_s != 3)
		ac_fail("坏值 psi 应 sanitize（high 回落 50，其余保留）");
	ac_config_cleanup(&cfg);

	/* sessions-state.json：psi 段写入/清除/兼容加载 */
	snprintf(dir, sizeof(dir), "%s/store", tmp);
	mkdir(dir, 0755);
	{
		ac_store *st = ac_store_open(dir, NULL);
		aik_json *psi = parse_text(
			"{\"enabled\":true,\"state\":\"suppressed\","
			"\"suppressed_count\":2,\"deferred_count\":1,"
			"\"degrade_count\":0}");
		char path[600];
		size_t len = 0;
		char *text;

		g_ac_checks++;
		if (!st || ac_store_set_psi_state(st, psi) != 0)
			ac_fail("set_psi_state 应成功");
		snprintf(path, sizeof(path), "%s/sessions-state.json", dir);
		text = ac_read_file(path, &len);
		g_ac_checks++;
		if (!text || !strstr(text, "\"psi\"") ||
		    !strstr(text, "\"suppressed_count\": 2"))
			ac_fail("sessions-state.json 应含 psi 段");
		free(text);

		/* 清除 → 文件回到无 psi 形态 */
		g_ac_checks++;
		if (ac_store_set_psi_state(st, NULL) != 0)
			ac_fail("清除 psi 段应成功");
		text = ac_read_file(path, &len);
		g_ac_checks++;
		if (!text || strstr(text, "\"psi\""))
			ac_fail("清除后文件不应再含 psi 段");
		free(text);

		/* 带会话写入 psi，重开 store：会话仍在（兼容加载）*/
		(void)ac_store_upsert(st, "s1", "/tmp/p", NULL, 0, 0, 0, 0);
		(void)ac_store_set_psi_state(st, psi);
		ac_store_close(st);
		st = ac_store_open(dir, NULL);
		g_ac_checks++;
		if (!st || ac_store_get_session(st, "s1") == NULL)
			ac_fail("带 psi 段的状态文件应能正常加载会话");
		ac_store_close(st);
		aik_json_free(psi);
	}
}

int main(void)
{
	ac_time_set_now(FROZEN_EPOCH);
	unsetenv("AUTOCONDENSE_PORT");

	char *tmp = ac_mkdtemp("/tmp/ac-psi-");

	if (!tmp)
		return 2;

	test_parse();
	test_read(tmp);
	test_machine();
	test_gate();
	test_degrade();
	test_config();
	test_persist(tmp);

	/* 清理 fixture */
	char cmd[512];

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmp);
	if (system(cmd) != 0)
		fprintf(stderr, "WARN: cannot clean %s\n", tmp);
	free(tmp);
	ac_summary("test_acpsi");
	return g_ac_failed ? 1 : 0;
}
