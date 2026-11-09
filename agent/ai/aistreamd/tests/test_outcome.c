/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_outcome.c - I-10 outcome 回填器单测（mock 标准文件 + mock sysfs 树）
 *
 * 验收门（设计 §5 原文，在单测/模拟层验证逻辑正确性；真内核 qemu 轮
 * 移交 K3C §9-1 同源依赖）：
 *   1) 回填率 ≥90%（§5.1：executed>0 且 param 非空的应处理集中，
 *      写口成功占比——mock 层以写口文件行数计）
 *   2) Tier-A 方向一致性 ≥5 旋钮 × 每旋钮 ≥8 次已知方向注入、独立重算
 *      （测试自读原始指标源重推方向，不经回填器代码）一致率 ≥90%
 *   3) 无操作对照 PARTIAL ≥80%（§5.3 反假阳性）
 *   4) delta 一致性 ≥10 条（§5.4：独立重算差值一致，含单位约定）
 *   5) hitrate 对账（§5.5：armed+skip_*+notfound == 注入事件总数）
 *   6) 健壮性（§5.6：洪泛丢旧/写不存在 id ENOENT/指标源失败 PARTIAL）
 *   7) 兼容性：T8 decision 23 列 schema 的 outcome/outcome_ts 列直接可写
 *
 * mock 树 = <root>/{proc,sys}/…（格式逐字段对齐内核 ai_proc_dec_record /
 * ai_stats_ai_actions_show_fn / ai_proc_control_show 等实读源）。
 */
#define _GNU_SOURCE

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "as_conf.h"
#include "as_event.h"
#include "as_outcome.h"
#include "as_parquet.h"
#include "as_stats.h"
#include "as_util.h"

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

#define TREE "/tmp/as-oc-tree"
#define TREE2 "/tmp/as-oc-tree2"

/* ====================================================================
 * mock 树构造
 * ==================================================================== */

static void wfile(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");

	if (!f) {
		printf("FATAL: cannot write %s\n", path);
		exit(2);
	}
	fputs(content, f);
	fclose(f);
}

static void mkdirs_for(const char *path)
{
	char dir[600];
	size_t pos = 1;

	snprintf(dir, sizeof(dir), "%s", path);
	while (dir[pos]) {
		if (dir[pos] == '/') {
			dir[pos] = '\0';
			mkdir(dir, 0755);
			dir[pos] = '/';
		}
		pos++;
	}
}

static void wfile_mkdir(const char *path, const char *content)
{
	char dir[600];
	char *slash;

	snprintf(dir, sizeof(dir), "%s", path);
	slash = strrchr(dir, '/');
	if (slash && slash != dir) {
		*slash = '\0';
		mkdirs_for(dir);
		mkdir(dir, 0755);
	}
	wfile(path, content);
}

/* decisions 记录（ai_proc_dec_record 逐字段对齐；最新在前由调用方保证） */
static void dec_line(char *buf, size_t cap, unsigned long long id,
		     unsigned domain, unsigned long long d0,
		     unsigned long long d1, unsigned long long d2,
		     unsigned long long outcome_ts)
{
	snprintf(buf, cap,
		 "id=%llu trig_ts=1000 trig_evid=0x%04x dec_ts=1100 "
		 "type=1 data=%llu:%llu:%llu:0:0:0:0:0 exec_ts=1200 "
		 "outcome_ts=%llu outcome=%u delta=0 ver=1 conf=80 "
		 "domain=%u src=1 executed=1 safety_clamped=0\n",
		 id, (unsigned)(id & 0xffff), d0, d1, d2, outcome_ts,
		 outcome_ts ? 1u : 0u, domain);
}

/* 基线 decisions：每旋钮一条（id 段规划见各测试） */
static void write_decisions(const char *root, unsigned long long ots)
{
	char all[32768];	/* 77 行×~210B——8K 会静默截断（strncat 有界） */

	all[0] = '\0';
	/* id 规划（task 旋钮 data=pid:value[:res]，全局 data=value） */
	{
		char l[512];
		static const struct {
			unsigned long long id;
			unsigned dom;
			unsigned long long d0, d1, d2;
		} rows[] = {
			{ 1001, 1, 4242, 10, 0 },	/* sched.nice */
			{ 1002, 1, 4242, 2, 0 },	/* sched.affinity */
			{ 1003, 1, 4242, 500, 0 },	/* sched.oom_score */
			{ 1004, 1, 12, 0, 0 },		/* sched.timeslice */
			{ 1005, 2, 2, 0, 0 },		/* mm.thp */
			{ 1006, 2, 10, 0, 0 },		/* mm.swappiness */
			{ 1007, 2, 256, 0, 0 },		/* mm.readahead */
			{ 1008, 2, 50, 0, 0 },		/* mm.reclaim_prio */
			{ 1009, 3, 4242, 1, 0 },	/* io.priority */
			{ 1010, 3, 50, 0, 0 },		/* io.bandwidth */
			{ 1011, 4, 500, 0, 0 },		/* net.cwnd */
			{ 1012, 4, 400, 0, 0 },		/* net.rto */
			{ 1013, 4, 3, 0, 0 },		/* net.qdisc */
			{ 1014, 4, 1, 0, 0 },		/* net.nftables */
			{ 1015, 5, 1, 0, 0 },		/* sec.lsm_override */
			{ 1016, 5, 4242, 7, 0 },	/* sec.ws_label */
			{ 1017, 5, 0, 0, 0 },		/* sec.audit */
			{ 1018, 1, 1, 0, 0 },		/* ai.decision_inject */
			{ 1019, 6, 5000, 0, 0 },	/* power.freq */
			{ 1020, 6, 0, 0, 0 },		/* power.cstate */
			{ 1021, 6, 1, 0, 0 },		/* power.wakeup */
			{ 1022, 12, 4242, 1, 0 },	/* proc.signal(19) */
			{ 1023, 12, 4242, 1, 0 },	/* proc.freeze */
			{ 1024, 12, 4242, 100, 6 },	/* proc.rlimit */
			/* 方向一致性轮次（各旋钮 8 轮：id 基 + r） */
			{ 2001, 12, 4242, 1, 0 },	/* freeze r1 */
			{ 2011, 1, 4242, 10, 0 },	/* nice r1 */
			{ 2021, 2, 2, 0, 0 },		/* thp r1 */
			{ 2031, 4, 1, 0, 0 },		/* nftables r1 */
			{ 2041, 6, 1, 0, 0 },		/* wakeup r1 */
			{ 2051, 12, 4242, 19, 0 },	/* signal r1 */
			/* 对照组 */
			{ 3001, 1, 4242, 0, 0 },
			{ 3002, 2, 60, 0, 0 },
			{ 3003, 6, 0, 0, 0 },
			{ 3004, 5, 1, 0, 0 },
			{ 3005, 4, 0, 0, 0 },
			{ 3006, 2, 1, 0, 0 },
			{ 3007, 12, 4242, 1, 0 },
			{ 3008, 12, 4242, 19, 0 },
			{ 3009, 1, 4242, 2, 0 },
			{ 3010, 3, 4242, 4, 0 },
			/* 降级 */
			{ 4001, 12, 4242, 1, 0 },	/* ENOENT 路 */
			{ 4002, 12, 99999, 1, 0 },	/* pid 消亡 meas_fail */
			{ 4003, 2, 2, 0, 0 },		/* verify_fail 路 */
		};

		for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
			dec_line(l, sizeof(l), rows[i].id, rows[i].dom,
				 rows[i].d0, rows[i].d1, rows[i].d2, ots);
			strncat(all, l, sizeof(all) - strlen(all) - 1);
		}
		/* 方向一致性轮次 r2..r8（r1 已在上方 rows[]）：
		 * freeze(2001+)/signal(2051+)=task 4242:1 / 4242:19；
		 * nice(2011+)=task 4242:10；thp(2021+)=全局 2；
		 * nftables(2031+)/wakeup(2041+)=全局 1 */
		for (int r = 2; r <= 8; r++) {
			static const unsigned long long base_id[6] = { 2001, 2011,
				2021, 2031, 2041, 2051 };
			static const unsigned doms[6] = { 12, 1, 2, 4, 6, 12 };
			static const unsigned long long d0v[6] = { 4242, 4242, 2, 1,
				1, 4242 };
			static const unsigned long long d1v[6] = { 1, 10, 0, 0, 0, 19 };
			char l[512];

			for (int k = 0; k < 6; k++) {
				dec_line(l, sizeof(l), base_id[k] + r - 1, doms[k],
					 d0v[k], d1v[k], 0, ots);
				strncat(all, l, sizeof(all) - strlen(all) - 1);
			}
		}
	}
	{
		char p[512];

		snprintf(p, sizeof(p), "%s/proc/ai/decisions", root);
		wfile_mkdir(p, all);
	}
}

static void write_control(const char *root)
{
	char p[512];

	snprintf(p, sizeof(p), "%s/proc/ai/control", root);
	wfile_mkdir(p,
		"sched.nice domain=1 [real] min=-20 max=19 current=0 default=0\n"
		"sched.affinity domain=1 [real] min=0 max=255 current=0 default=0\n"
		"sched.oom_score domain=1 [real] min=-1000 max=1000 current=0 default=0\n"
		"sched.timeslice domain=1 [real] min=1 max=1000 current=6 default=6\n"
		"ai.decision_sched domain=1 [real] min=0 max=1 current=0 default=0\n"
		"mm.swappiness domain=2 [real] min=0 max=100 current=60 default=60\n"
		"mm.readahead domain=2 [real] min=0 max=4096 current=128 default=128\n"
		"mm.thp domain=2 [real] min=0 max=2 current=1 default=1\n"
		"mm.reclaim_prio domain=2 [real] min=0 max=100 current=100 default=100\n"
		"ai.decision_oom domain=2 [real] min=0 max=1 current=0 default=0\n"
		"ai.decision_mm domain=2 [real] min=0 max=1 current=0 default=0\n"
		"io.priority domain=3 [real] min=0 max=7 current=4 default=4\n"
		"io.bandwidth domain=3 [real] min=0 max=100 current=100 default=100\n"
		"net.cwnd domain=4 [real] min=1 max=4096 current=100 default=100\n"
		"net.rto domain=4 [real] min=1 max=10000 current=200 default=200\n"
		"net.qdisc domain=4 [real] min=0 max=3 current=1 default=1\n"
		"net.nftables domain=4 [real] min=0 max=1 current=0 default=0\n"
		"sec.lsm_override domain=5 [real] min=0 max=1 current=0 default=0\n"
		"sec.seccomp domain=5 [reserved] min=0 max=1 current=0 default=0\n"
		"sec.audit domain=5 [real] min=0 max=1 current=1 default=1\n"
		"sec.ws_label domain=5 [real] min=0 max=255 current=0 default=0\n"
		"ai.decision_inject domain=5 [real] min=0 max=1 current=0 default=0\n"
		"power.freq domain=6 [real] min=0 max=10000 current=10000 default=10000\n"
		"power.cstate domain=6 [real] min=0 max=10 current=2 default=2\n"
		"power.wakeup domain=6 [real] min=0 max=1 current=0 default=0\n"
		"proc.signal domain=12 [real] min=0 max=64 current=0 default=0\n"
		"proc.freeze domain=12 [real] min=0 max=1 current=0 default=0\n"
		"proc.rlimit domain=12 [real] min=0 max=1000000 current=1000000 default=1000000\n");
}

static void write_metric_sources(const char *root)
{
	char p[512];

	/* PSI */
	snprintf(p, sizeof(p), "%s/proc/pressure/cpu", root);
	wfile_mkdir(p, "some avg10=0.25 avg60=0.25 avg300=0.25 total=100000\n"
		      "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n");
	snprintf(p, sizeof(p), "%s/proc/pressure/memory", root);
	wfile_mkdir(p, "some avg10=0.10 avg60=0.10 avg300=0.10 total=50000\n");
	snprintf(p, sizeof(p), "%s/proc/pressure/io", root);
	wfile_mkdir(p, "some avg10=0.05 avg60=0.05 avg300=0.05 total=20000\n");
	/* vmstat / netstat */
	snprintf(p, sizeof(p), "%s/proc/vmstat", root);
	wfile_mkdir(p, "nr_free_pages 123456\nthp_fault_alloc 1000\n"
		      "thp_cow_fault 500\npswpin 10\npswpout 20\n"
		      "pgmajfault 5\nnr_dirty 100\n");
	snprintf(p, sizeof(p), "%s/proc/net/netstat", root);
	wfile_mkdir(p, "IpExt: InNoRoutes InTruncatedPkts\n"
		      "IpExt: 0 0\n"
		      "TcpExt: TcpRetransSegs TCPTimeouts\n"
		      "TcpExt: 1000 5\n");
	/* AIKernel stats */
	snprintf(p, sizeof(p), "%s/sys/kernel/ai/stats/ai_actions", root);
	wfile_mkdir(p,
		"cwnd_clamp_hits: 0\n"
		"aiguard_freq_requests: 5\n"
		"aiguard_freq_clamped: 1\n"
		"aiguard_freq_cap_pct: 10000\n"
		"wakeup_capture: 0\n"
		"wakeup_events: 500\n"
		"netfilter_hook: 0\n"
		"netfilter_pkts: 100000\n"
		"netfilter_bytes: 1000000\n"
		"audit_capture: 1\n"
		"audit_gate_drops: 3\n"
		"lsm_enforce: 0\n"
		"lsm_rules: 2\n"
		"sched_base_slice_ns: 600000\n"
		"vfs_cache_pressure: 100\n");
	snprintf(p, sizeof(p), "%s/sys/kernel/ai/stats/decisions_total", root);
	wfile_mkdir(p, "42\n");
	/* ws_labels（基线空文件） */
	snprintf(p, sizeof(p), "%s/proc/ai/ws_labels", root);
	wfile_mkdir(p, "");
	/* bdi / net / cpufreq / cpuidle */
	snprintf(p, sizeof(p), "%s/sys/class/bdi/8:0/ra_pages", root);
	wfile_mkdir(p, "128\n");
	snprintf(p, sizeof(p), "%s/sys/class/bdi/8:0/max_ratio", root);
	wfile_mkdir(p, "100\n");
	snprintf(p, sizeof(p), "%s/sys/class/net/eth0/qdisc", root);
	wfile_mkdir(p, "pfifo_fast\n");
	for (int cpu = 0; cpu < 2; cpu++) {
		snprintf(p, sizeof(p),
			 "%s/sys/devices/system/cpu/cpu%d/cpufreq/"
			 "scaling_cur_freq", root, cpu);
		wfile_mkdir(p, "2500000\n");
		snprintf(p, sizeof(p),
			 "%s/sys/devices/system/cpu/cpu%d/cpuidle/state0/time",
			 root, cpu);
		wfile_mkdir(p, "1000000\n");
		snprintf(p, sizeof(p),
			 "%s/sys/devices/system/cpu/cpu%d/cpuidle/state1/time",
			 root, cpu);
		wfile_mkdir(p, "500000\n");
	}
	/* pid 4242（基线：R 态、utime 50 stime 20、schedstat col2=100ms） */
	snprintf(p, sizeof(p), "%s/proc/4242/stat", root);
	wfile_mkdir(p, "4242 (burn) R 1 1 0 0 -1 4194560 100 0 0 3 50 20 "
		       "0 0 20 0 1 0 100 200 1 0 0 0 0 0 0 0 0 0 0 0 0 0 "
		       "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n");
	snprintf(p, sizeof(p), "%s/proc/4242/status", root);
	wfile_mkdir(p, "Name:\tburn\nState:\tR (running)\n"
		       "Cpus_allowed_list:\t0-3\n");
	snprintf(p, sizeof(p), "%s/proc/4242/schedstat", root);
	wfile_mkdir(p, "123456789 100000000 42\n");
	snprintf(p, sizeof(p), "%s/proc/4242/oom_score_adj", root);
	wfile_mkdir(p, "0\n");
	{
		/* limits：header + 16 行；行 6（0 基）= Max processes */
		char lim[2048];

		snprintf(lim, sizeof(lim),
			 "Limit                     Soft LimitHard Limit Units \n"
			 "Max cpu time              unlimitedunlimited seconds\n"
			 "Max file size             unlimitedunlimited bytes\n"
			 "Max data size             unlimitedunlimited bytes\n"
			 "Max stack size            8388608  unlimited KB\n"
			 "Max core file size        0        unlimited bytes\n"
			 "Max processes             12345    12345    processes\n"
			 "Max open files            1024     1048576  files\n"
			 "Max locked memory         65536    65536    KB\n"
			 "Max address space         unlimitedunlimited KB\n"
			 "Max file locks            unlimitedunlimited locks\n"
			 "Max pending signals       2341     2341     signals\n"
			 "Max msgqueue size         819200   819200   bytes\n"
			 "Max nice priority         0        0        \n"
			 "Max realtime priority     0        0        \n"
			 "Max realtime timeout      unlimitedunlimited us\n");
		snprintf(p, sizeof(p), "%s/proc/4242/limits", root);
		wfile_mkdir(p, lim);
	}
	/* 写口（mock：普通可写文件代表 0200 sysfs 节点） */
	snprintf(p, sizeof(p), "%s/sys/kernel/ai/policy/outcome", root);
	wfile_mkdir(p, "");
}

static void build_tree(const char *root, unsigned long long ots)
{

	write_decisions(root, ots);
	write_control(root);
	write_metric_sources(root);
}

/* pid 4242 stat 重写（state/utime/stime 由参数定） */
static void set_pid_stat(const char *root, char state, long long ut,
			 long long st)
{
	char p[512], buf[512];

	snprintf(p, sizeof(p), "%s/proc/4242/stat", root);
	snprintf(buf, sizeof(buf),
		 "4242 (burn) %c 1 1 0 0 -1 4194560 100 0 0 3 %lld %lld "
		 "0 0 20 0 1 0 100 200 1 0 0 0 0 0 0 0 0 0 0 0 0 0 "
		 "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", state, ut, st);
	wfile(p, buf);
}

/* ====================================================================
 * 驱动小工具
 * ==================================================================== */

static void conf_oc(struct as_conf *c, int pending)
{
	as_conf_defaults(c);
	c->outcome_enabled = 1;
	c->outcome_window_short_sec = 30;
	c->outcome_window_long_sec = 300;
	c->outcome_max_pending = pending;
	c->outcome_decisions_scan_max = 128;	/* mock decisions 77 行：覆盖全表 */
}

static void arm(struct as_outcome *oc, unsigned long long id, int executed,
		const char *param)
{
	struct as_event ev;

	as_event_ai_policy(&ev, id, executed, NULL, param);
	ev.ts_real_ms = 1767300000000LL + (long long)(id % 1000);
	as_outcome_tap(oc, &ev);
}

/* 写口文件解析：id → (outcome, delta)；返回找到行数 */
static int read_written(const char *root,
			unsigned long long id, int *oc_, long long *delta)
{
	char p[512], line[256];
	FILE *f;

	snprintf(p, sizeof(p), "%s/sys/kernel/ai/policy/outcome", root);
	f = fopen(p, "r");
	if (!f)
		return 0;
	{
		int n = 0;

		while (fgets(line, sizeof(line), f)) {
			unsigned long long rid;
			int o;
			long long d;

			if (sscanf(line, "%llu,%d,%lld", &rid, &o, &d) != 3)
				continue;
			n++;
			if (rid == id) {
				*oc_ = o;
				*delta = d;
			}
		}
		fclose(f);
		return n;
	}
}

/* ====================================================================
 * 1) metric 表 + conf 键
 * ==================================================================== */

static int write_conf(const char *path, const char *content)
{
	FILE *f = fopen(path, "w");

	if (!f)
		return -1;
	fputs(content, f);
	fclose(f);
	return 0;
}

static void test_table_conf(void)
{
	struct as_conf c;
	char err[256];

	CHECK(as_oc_rows_n == 28, "table: 28 rows (§2 全量)");
	for (size_t i = 0; i < as_oc_rows_n; i++)
		for (size_t j = i + 1; j < as_oc_rows_n; j++)
			if (strcmp(as_oc_rows[i].param, as_oc_rows[j].param) == 0) {
				CHECK(0, "table: dup param");
				break;
			}
	CHECK(as_oc_row_lookup("proc.freeze") >= 0, "table: freeze found");
	CHECK(as_oc_row_lookup("warp.drive") < 0, "table: unknown -1");
	CHECK(as_oc_rows[as_oc_row_lookup("sec.seccomp")].kind ==
	      OC_K_RESERVED, "table: seccomp reserved");

	as_conf_defaults(&c);
	CHECK(c.outcome_enabled == 0, "conf: default off (C3)");
	CHECK(c.outcome_window_short_sec == 30, "conf: short 30");
	CHECK(c.outcome_window_long_sec == 300, "conf: long 300");
	CHECK(c.outcome_grace_sec == 10, "conf: grace 10");
	CHECK(c.outcome_max_pending == 256, "conf: pending 256");
	CHECK(c.outcome_decisions_scan_max == 64, "conf: scan 64");
	CHECK(c.outcome_write_sme == 1, "conf: write_sme 1");
	CHECK(c.outcome_auto_rollback == 0, "conf: rollback 0 (C4)");

	CHECK(write_conf("/tmp/as-oc-good.conf",
			 "OUTCOME_ENABLED=1\nOUTCOME_WINDOW_SHORT_SEC=5\n"
			 "OUTCOME_WINDOW_LONG_SEC=600\nOUTCOME_GRACE_SEC=0\n"
			 "OUTCOME_MAX_PENDING=8\n"
			 "OUTCOME_DECISIONS_SCAN_MAX=16\n"
			 "OUTCOME_WRITE_SME=0\nOUTCOME_AUTO_ROLLBACK=1\n") == 0,
	      "conf: write good");
	as_conf_defaults(&c);
	CHECK(as_conf_load(&c, "/tmp/as-oc-good.conf", err, sizeof(err)) == 0,
	      "conf: good accepted");
	CHECK(c.outcome_enabled == 1 && c.outcome_window_short_sec == 5 &&
	      c.outcome_window_long_sec == 600 && c.outcome_grace_sec == 0 &&
	      c.outcome_max_pending == 8 &&
	      c.outcome_decisions_scan_max == 16 &&
	      c.outcome_write_sme == 0 && c.outcome_auto_rollback == 1,
	      "conf: overrides applied");

	{
		static const struct { const char *name, *content; } bad[] = {
			{ "enabled=2", "OUTCOME_ENABLED=2\n" },
			{ "short=4", "OUTCOME_WINDOW_SHORT_SEC=4\n" },
			{ "long=29", "OUTCOME_WINDOW_LONG_SEC=29\n" },
			{ "grace=601", "OUTCOME_GRACE_SEC=601\n" },
			{ "pending=7", "OUTCOME_MAX_PENDING=7\n" },
			{ "pending=4097", "OUTCOME_MAX_PENDING=4097\n" },
			{ "scan=4", "OUTCOME_DECISIONS_SCAN_MAX=4\n" },
			{ "sme=2", "OUTCOME_WRITE_SME=2\n" },
			{ "rollback=3", "OUTCOME_AUTO_ROLLBACK=3\n" },
			{ "mockroot-rel", "OUTCOME_MOCK_ROOT=tmp/x\n" },
			{ "mockroot-dotdot", "OUTCOME_MOCK_ROOT=/tmp/../x\n" },
			{ "dup", "OUTCOME_ENABLED=1\nOUTCOME_ENABLED=0\n" },
		};

		for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
			char path[64];

			snprintf(path, sizeof(path), "/tmp/as-oc-bad-%zu.conf",
				 i);
			CHECK(write_conf(path, bad[i].content) == 0,
			      "conf: write bad");
			as_conf_defaults(&c);
			CHECK(as_conf_load(&c, path, err, sizeof(err)) != 0,
			      "conf: rejected");
			CHECK(strncmp(err, "line ", 5) == 0,
			      "conf: err line number");
		}
	}
	printf("  table+conf: OK\n");
}

/* ====================================================================
 * 2) decisions 反查解析
 * ==================================================================== */

static void test_decisions_scan(void)
{
	char p[512];
	struct as_oc_decision d;

	mkdir("/tmp/as-oc-scan", 0755);
	snprintf(p, sizeof(p), "/tmp/as-oc-scan/decisions");
	wfile(p,
	      "id=30 trig_ts=1 trig_evid=0x001e dec_ts=2 type=1 "
	      "data=4242:10:0:0:0:0:0:0 exec_ts=3 outcome_ts=0 outcome=0 "
	      "delta=0 ver=1 conf=80 domain=1 src=1 executed=1 "
	      "safety_clamped=0\n"
	      "id=20 trig_ts=1 trig_evid=0x0014 dec_ts=2 type=1 "
	      "data=60:0:0:0:0:0:0:0 exec_ts=3 outcome_ts=999 outcome=1 "
	      "delta=-5 ver=1 conf=80 domain=2 src=1 executed=2 "
	      "safety_clamped=1\n"
	      "id=10 trig_ts=1 trig_evid=0x000a dec_ts=2 type=1 "
	      "data=1:0:0:0:0:0:0:0 exec_ts=3 outcome_ts=0 outcome=0 "
	      "delta=0 ver=1 conf=80 domain=4 src=1 executed=1 "
	      "safety_clamped=0\n");
	CHECK(as_oc_scan_decisions(p, 30, 64, &d) == 0 && d.id == 30 &&
	      d.data[0] == 4242 && d.data[1] == 10 && d.domain == 1 &&
	      d.executed == 1 && d.outcome_ts == 0,
	      "scan: newest record parsed");
	CHECK(as_oc_scan_decisions(p, 20, 64, &d) == 0 && d.domain == 2 &&
	      d.outcome_ts == 999 && d.executed == 2,
	      "scan: mid record parsed");
	CHECK(as_oc_scan_decisions(p, 10, 2, &d) == 1,
	      "scan: scan_max truncation misses");
	CHECK(as_oc_scan_decisions(p, 10, 64, &d) == 0,
	      "scan: full scan finds");
	CHECK(as_oc_scan_decisions("/tmp/as-oc-scan/nope", 10, 64, &d) == -1,
	      "scan: missing file -1");
	CHECK(as_oc_scan_decisions(p, 777, 64, &d) == 1,
	      "scan: absent id miss");
	printf("  decisions-scan: OK\n");
}

/* ====================================================================
 * 3) tap 路径（skip 桶 + arm + 洪泛）
 * ==================================================================== */

static void test_tap_paths(void)
{
	struct as_conf c;
	struct as_stats st;
	struct as_outcome oc;

	build_tree(TREE, 999999);	/* ots>0：verify 用 */
	conf_oc(&c, 256);
	memset(&st, 0, sizeof(st));
	CHECK(as_outcome_init(&oc, &c, &st) == 0, "tap: init");
	as_outcome_set_root(&oc, TREE);

	/* 非 policy 事件零副作用 */
	{
		struct as_event ev;

		as_event_ai_model(&ev, 5, 1, "m");
		as_outcome_tap(&oc, &ev);
		as_event_proc_fork(&ev, 1, 42);
		as_outcome_tap(&oc, &ev);
		CHECK(st.oc.armed == 0 && st.oc.skip_broadcast == 0,
		      "tap: non-policy zero effect");
	}
	arm(&oc, 1005, 2, "");			/* 广播 */
	arm(&oc, 1005, 0, "mm.thp");		/* 未执行 */
	arm(&oc, 1005, 2, "warp.drive");	/* 未收录 */
	arm(&oc, 1005, 2, "sec.seccomp");	/* reserved */
	arm(&oc, 999999, 2, "mm.thp");		/* decisions 无此 id */
	CHECK(st.oc.skip_broadcast == 1, "tap: skip_broadcast");
	CHECK(st.oc.skip_noexec == 1, "tap: skip_noexec");
	CHECK(st.oc.skip_unknown == 1, "tap: skip_unknown");
	CHECK(st.oc.skip_reserved == 1, "tap: skip_reserved");
	CHECK(st.oc.notfound == 1, "tap: reverse-lookup notfound");
	CHECK(st.oc.armed == 0, "tap: nothing armed yet");
	arm(&oc, 1005, 2, "mm.thp");
	CHECK(st.oc.armed == 1, "tap: valid armed");
	/* 去重口径外：同 id 再来一条也 arm（EVENT 每条独立审计） */
	arm(&oc, 1023, 2, "proc.freeze");
	CHECK(st.oc.armed == 2, "tap: second armed");
	/* 未到期 tick：无处理 */
	as_outcome_tick(&oc, as_now_mono_ms() + 1000);
	CHECK(st.oc.filled == 0, "tap: not-due tick noop");

	/* 洪泛：pending=8 打满（§5.6） */
	{
		struct as_conf c2;
		struct as_stats st2;
		struct as_outcome oc2;

		build_tree(TREE2, 999999);
		conf_oc(&c2, 8);
		memset(&st2, 0, sizeof(st2));
		CHECK(as_outcome_init(&oc2, &c2, &st2) == 0, "flood: init");
		as_outcome_set_root(&oc2, TREE2);
		for (int i = 0; i < 20; i++)
			arm(&oc2, 2001 + (unsigned)(i % 8), 2,
			     "proc.freeze");
		CHECK(st2.oc.armed == 20, "flood: 20 armed");
		CHECK(st2.oc.dropped == 12, "flood: 12 dropped (cap=8)");
		as_outcome_tick(&oc2, as_now_mono_ms() + 400000);
		CHECK(st2.oc.filled == 8, "flood: only 8 filled");
		CHECK(st2.oc.success + st2.oc.partial + st2.oc.worse == 8,
		      "flood: 8 written, no crash, no storm");
		as_outcome_close(&oc2);
	}
	as_outcome_close(&oc);
	printf("  tap-paths: OK\n");
}

/* ====================================================================
 * 4) 验收门主战场：方向一致性（6 旋钮×8）+ 回填率 + delta 一致性
 *    独立重算：测试自读原始指标源，测试本地规则推期望（不经模块代码）
 * ==================================================================== */

struct knob_result {
	int samples;		/* 已知方向样本数 */
	int consistent;		/* 与独立重算一致数 */
	int delta_checked;	/* delta 精确一致数 */
};

/* 测试本地期望计算（独立于 as_oc_classify_*）：
 * intent=注入-前值；期望=带内 PARTIAL；反向出带 WORSE；同向出带 SUCCESS */
static int expect_num(long long before_ctrl, long long injected,
		      long long metric_before, long long metric_after,
		      int dir, int thr, int is_rate, int window_sec,
		      long long *delta_out)
{
	long long delta = metric_after - metric_before;
	long long intent = injected > before_ctrl ? 1 :
			   injected < before_ctrl ? -1 : 0;
	long long ad;

	if (is_rate) {
		long long w = window_sec > 0 ? window_sec : 1;
		long long a = delta >= 0 ? delta : -delta;

		delta = (a + w / 2) / w;
		if (metric_after < metric_before)
			delta = -delta;
	}
	*delta_out = delta;
	ad = delta < 0 ? -delta : delta;
	if (intent == 0)
		return AS_OC_PARTIAL;		/* 无操作对照（§5.3） */
	if (ad <= thr)
		return AS_OC_PARTIAL;		/* 带内=无效果证据 */
	if (dir == 0)
		return AS_OC_SUCCESS;		/* INTENT：出带即生效 */
	if ((delta > 0 ? 1 : delta < 0 ? -1 : 0) == dir * intent)
		return AS_OC_SUCCESS;
	return AS_OC_WORSE;
}

static void test_fill_gates(void)
{
	struct as_conf c;
	struct as_stats st;
	struct as_outcome oc;
	struct knob_result kr[6];

	build_tree(TREE, 999999);	/* ots>0：自校验过 */
	conf_oc(&c, 256);
	memset(&st, 0, sizeof(st));
	CHECK(as_outcome_init(&oc, &c, &st) == 0, "gates: init");
	as_outcome_set_root(&oc, TREE);
	memset(kr, 0, sizeof(kr));

	/* ---- 旋钮 1：proc.freeze（match；R→T 已知方向） ---- */
	for (int r = 0; r < 8; r++) {
		unsigned long long id = 2001 + r;
		int got = 0;
		long long dl = 0, exp_dl;
		int exp_oc;

		set_pid_stat(TREE, 'R', 50, 20);	/* before */
		arm(&oc, id, 2, "proc.freeze");
		if (r < 7)
			set_pid_stat(TREE, 'T', 100, 40);	/* after */
		/* r=7：保持 R（未达成） */
		as_outcome_tick(&oc, as_now_mono_ms() + 400000);
		CHECK(read_written(TREE, id, &got, &dl) > 0, "freeze: written");
		/* 独立重算：state 迁移 R→T=SUCCESS；未迁移=PARTIAL；
		 * delta=(ut+st 差)*1000/100 */
		exp_oc = r < 7 ? AS_OC_SUCCESS : AS_OC_PARTIAL;
		exp_dl = r < 7 ? (140 - 70) * 10 : 0;
		kr[0].samples++;
		if (got == exp_oc)
			kr[0].consistent++;
		if (dl == exp_dl) {
			kr[0].delta_checked++;
		} else {
			printf("    freeze r%d delta=%lld exp=%lld\n", r, dl,
			       exp_dl);
		}
	}

	/* ---- 旋钮 2：sched.nice（schedstat 延迟 ms；dir +） ---- */
	for (int r = 0; r < 8; r++) {
		unsigned long long id = 2011 + r;
		char p[512], buf[128];
		int got = 0, exp_oc;
		long long dl = 0, exp_dl;
		long long after_ns = r == 6 ? 10000000LL :
				     r == 7 ? 300000000LL : 500000000LL;

		/* r=0..5：+400ms（SUCCESS）；r=6：-90ms（WORSE）；
		 * r=7：+200ms（SUCCESS） */
		snprintf(p, sizeof(p), "%s/proc/4242/schedstat", TREE);
		strcpy(buf, "123456789 100000000 42\n");
		wfile(p, buf);			/* before=100ms */
		arm(&oc, id, 2, "sched.nice");
		snprintf(buf, sizeof(buf), "123456789 %lld 42\n", after_ns);
		wfile(p, buf);			/* after */
		as_outcome_tick(&oc, as_now_mono_ms() + 400000);
		CHECK(read_written(TREE, id, &got, &dl) > 0, "nice: written");
		exp_oc = expect_num(0, 10, 100, after_ns / 1000000, 1, 1, 0,
				    30, &exp_dl);
		kr[1].samples++;
		if (got == exp_oc)
			kr[1].consistent++;
		if (dl == exp_dl) {
			kr[1].delta_checked++;
		} else {
			printf("    nice r%d delta=%lld exp=%lld\n", r, dl,
			       exp_dl);
		}
	}

	/* ---- 旋钮 3：mm.thp（vmstat 双键速率；dir +；L 窗） ---- */
	for (int r = 0; r < 8; r++) {
		unsigned long long id = 2021 + r;
		char p[512], buf[256];
		int got = 0, exp_oc;
		long long dl = 0, exp_dl;
		long long sum_before = 1500;
		long long sum_after = r == 6 ? 1350 : r == 7 ? 1650 :
				      sum_before + 6000;

		snprintf(p, sizeof(p), "%s/proc/vmstat", TREE);
		snprintf(buf, sizeof(buf),
			 "nr_free_pages 1\nthp_fault_alloc %lld\n"
			 "thp_cow_fault 0\n", sum_before);
		wfile(p, buf);
		arm(&oc, id, 2, "mm.thp");
		snprintf(buf, sizeof(buf),
			 "nr_free_pages 1\nthp_fault_alloc %lld\n"
			 "thp_cow_fault 0\n", sum_after);
		wfile(p, buf);
		as_outcome_tick(&oc, as_now_mono_ms() + 400000);
		CHECK(read_written(TREE, id, &got, &dl) > 0, "thp: written");
		exp_oc = expect_num(1, 2, sum_before, sum_after, 1, 1, 1, 300,
				    &exp_dl);
		kr[2].samples++;
		if (got == exp_oc)
			kr[2].consistent++;
		if (dl == exp_dl) {
			kr[2].delta_checked++;
		} else {
			printf("    thp r%d delta=%lld exp=%lld\n", r, dl,
			       exp_dl);
		}
	}

	/* ---- 旋钮 4/5：net.nftables + power.wakeup（ai_actions 速率；dir +）
	 *    每轮：基线文件 → arm → after 文件 → tick；期望独立重算 ---- */
	for (int r = 0; r < 8; r++) {
		static const char *knobs[2] = { "net.nftables",
					       "power.wakeup" };
		static const unsigned long long base_id[2] = { 2031, 2041 };
		static const long long base_v[2] = { 100000, 500 };
		static const long long ctrl_v[2] = { 0, 0 };
		static const long long inj_v[2] = { 1, 1 };
		char p[512];

		snprintf(p, sizeof(p), "%s/sys/kernel/ai/stats/ai_actions", TREE);
		for (int k = 0; k < 2; k++) {
			unsigned long long id = base_id[k] + r;
			long long after = r == 6 ? base_v[k] - 3000 :
					  r == 7 ? base_v[k] + 15 :
					  base_v[k] + 3000;
			char b[1024];
			int got = 0, exp_oc;
			long long dl = 0, exp_dl;

			/* 基线（两键都回基线值，互不污染） */
			snprintf(b, sizeof(b),
				 "cwnd_clamp_hits: 0\nwakeup_capture: 0\n"
				 "wakeup_events: %lld\nnetfilter_hook: 0\n"
				 "netfilter_pkts: %lld\nnetfilter_bytes: 1\n"
				 "audit_capture: 1\naudit_gate_drops: 3\n"
				 "lsm_enforce: 0\nlsm_rules: 2\n"
				 "sched_base_slice_ns: 1\nvfs_cache_pressure: 100\n",
				 base_v[1], base_v[0]);
			wfile(p, b);
			arm(&oc, id, 2, knobs[k]);
			/* after：本键动、他键保持基线 */
			snprintf(b, sizeof(b),
				 "cwnd_clamp_hits: 0\nwakeup_capture: 0\n"
				 "wakeup_events: %lld\nnetfilter_hook: 0\n"
				 "netfilter_pkts: %lld\nnetfilter_bytes: 1\n"
				 "audit_capture: 1\naudit_gate_drops: 3\n"
				 "lsm_enforce: 0\nlsm_rules: 2\n"
				 "sched_base_slice_ns: 1\nvfs_cache_pressure: 100\n",
				 k == 1 ? after : base_v[1],
				 k == 0 ? after : base_v[0]);
			wfile(p, b);
			as_outcome_tick(&oc, as_now_mono_ms() + 400000);
			CHECK(read_written(TREE, id, &got, &dl) > 0,
			      "actrate: written");
			exp_oc = expect_num(ctrl_v[k], inj_v[k], base_v[k], after,
					     1, 1, 1, 30, &exp_dl);
			kr[3 + k].samples++;
			if (got == exp_oc)
				kr[3 + k].consistent++;
			if (dl == exp_dl) {
				kr[3 + k].delta_checked++;
			} else {
				printf("    %s r%d delta=%lld exp=%lld\n",
					knobs[k], r, dl, exp_dl);
			}
		}
	}

	/* ---- 旋钮 6：proc.signal（match；S→T 已知方向） ---- */
	for (int r = 0; r < 8; r++) {
		unsigned long long id = 2051 + r;
		int got = 0;
		long long dl = 0;

		set_pid_stat(TREE, 'S', 50, 20);
		arm(&oc, id, 2, "proc.signal");
		if (r < 7)
			set_pid_stat(TREE, 'T', 50, 20);
		/* r=7：保持 S（未达成） */
		as_outcome_tick(&oc, as_now_mono_ms() + 400000);
		CHECK(read_written(TREE, id, &got, &dl) > 0, "signal: written");
		/* 独立重算：期望态 T；S→T=SUCCESS（+1）；仍 S=PARTIAL */
		kr[5].samples++;
		if (got == (r < 7 ? AS_OC_SUCCESS : AS_OC_PARTIAL))
			kr[5].consistent++;
		if (dl == (r < 7 ? 1 : 0))
			kr[5].delta_checked++;
	}

	/* ---- 验收门输出 ---- */
	{
		static const char *names[6] = { "proc.freeze", "sched.nice",
						"mm.thp", "net.nftables",
						"power.wakeup",
						"proc.signal" };
		int dir_knobs = 0;

		for (int k = 0; k < 6; k++) {
			double ratio = kr[k].samples ?
				(double)kr[k].consistent / kr[k].samples : 0;

			printf("    TierA %-14s samples=%d consistent=%d "
			       "(%.0f%%) delta_ok=%d\n", names[k],
			       kr[k].samples, kr[k].consistent, ratio * 100,
			       kr[k].delta_checked);
			if (kr[k].samples >= 8 && ratio >= 0.9)
				dir_knobs++;
			else
				CHECK(0, "gate2: knob below threshold");
		}
		CHECK(dir_knobs >= 5,
		      "gate2: >=5 Tier-A knobs direction-consistent >=90% (§5.2)");
		{
			int total_delta = 0;

			for (int k = 0; k < 6; k++)
				total_delta += kr[k].delta_checked;
			CHECK(total_delta >= 10,
			      "gate4: >=10 delta exact-match (§5.4)");
			printf("    delta exact-checked=%d\n", total_delta);
		}
	}
	as_outcome_close(&oc);
	printf("  fill-gates: OK\n");
}

/* ====================================================================
 * 5) 全表行覆盖（其余每行 1 job：期望 outcome + 精确 delta）
 * ==================================================================== */

struct row_case {
	unsigned long long id;
	const char *knob;
	int expect_oc;
	long long expect_delta;
};

static void test_misc_rows(void)
{
	struct as_conf c;
	struct as_stats st;
	struct as_outcome oc;

	build_tree(TREE, 999999);
	conf_oc(&c, 256);
	memset(&st, 0, sizeof(st));
	CHECK(as_outcome_init(&oc, &c, &st) == 0, "rows: init");
	as_outcome_set_root(&oc, TREE);

	/* sched.timeslice：PSI cpu 0.25→3.00（centi 25→300，INTENT 出带） */
	arm(&oc, 1004, 2, "sched.timeslice");
	{
		char p[512];

		snprintf(p, sizeof(p), "%s/proc/pressure/cpu", TREE);
		wfile(p, "some avg10=3.00 avg60=3.00 avg300=3.00 total=1\n"
			 "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n");
	}
	/* mm.swappiness：psi mem 0.10→2.50（+240；intent -（60→10）→WORSE） */
	arm(&oc, 1006, 2, "mm.swappiness");
	{
		char p[512];

		snprintf(p, sizeof(p), "%s/proc/pressure/memory", TREE);
		wfile(p, "some avg10=2.50 avg60=2.50 avg300=2.50 total=1\n");
	}
	/* mm.readahead：bdi ra 128→256（+128 SUCCESS） */
	arm(&oc, 1007, 2, "mm.readahead");
	{
		char p[512];

		snprintf(p, sizeof(p), "%s/sys/class/bdi/8:0/ra_pages", TREE);
		wfile(p, "256\n");
	}
	/* mm.reclaim_prio：ai_actions vfs_cache_pressure 100→50（-50，
	 * intent -（100→50），dir + → 符号匹配 SUCCESS） */
	arm(&oc, 1008, 2, "mm.reclaim_prio");
	/* io.priority：control 读回 4→1（TASK：data=4242:1；intent -） */
	arm(&oc, 1009, 2, "io.priority");
	/* io.bandwidth：bdi max_ratio 100→50 */
	arm(&oc, 1010, 2, "io.bandwidth");
	{
		char p[512];

		snprintf(p, sizeof(p), "%s/sys/class/bdi/8:0/max_ratio", TREE);
		wfile(p, "50\n");
	}
	/* net.cwnd：TcpExt retrans 1000→4000（rate=100/s，INTENT SUCCESS） */
	arm(&oc, 1011, 2, "net.cwnd");
	/* net.rto：TCPTimeouts 5→6005（rate=200/s，INTENT SUCCESS） */
	arm(&oc, 1012, 2, "net.rto");
	{
		char p[512];

		snprintf(p, sizeof(p), "%s/proc/net/netstat", TREE);
		wfile(p, "TcpExt: TcpRetransSegs TCPTimeouts\n"
			 "TcpExt: 4000 6005\n");
	}
	/* net.qdisc：pfifo_fast→fq_codel（match +1 SUCCESS；注入 3） */
	arm(&oc, 1013, 2, "net.qdisc");
	{
		char p[512];

		snprintf(p, sizeof(p), "%s/sys/class/net/eth0/qdisc", TREE);
		wfile(p, "fq_codel\n");
	}
	/* sec.lsm_override：lsm_enforce 0→1（flip，thr 0 → SUCCESS） */
	arm(&oc, 1015, 2, "sec.lsm_override");
	/* sec.audit：audit_capture 1→0（flip，intent - → SUCCESS） */
	arm(&oc, 1017, 2, "sec.audit");
	/* sec.ws_label：ws_labels 空 → 出现 "4242 7 burn"（match SUCCESS） */
	arm(&oc, 1016, 2, "sec.ws_label");
	/* ai.decision_inject：decisions_total 42→442（+400 SUCCESS） */
	arm(&oc, 1018, 2, "ai.decision_inject");
	/* power.freq：cpufreq 2.5G→1.5G 均值（-1000000，intent -） */
	arm(&oc, 1019, 2, "power.freq");
	/* power.cstate：cpuidle deep 1000000→0（-1000000，intent -） */
	arm(&oc, 1020, 2, "power.cstate");
	/* sched.oom_score：oom_adj 0→500（SCENARIO 帽 → PARTIAL，delta 报） */
	arm(&oc, 1003, 2, "sched.oom_score");
	/* sched.affinity：allowed 0-3→"2"（match SUCCESS） */
	arm(&oc, 1002, 2, "sched.affinity");
	/* proc.rlimit：limits soft(行6) 12345→100（-12245，intent -） */
	arm(&oc, 1024, 2, "proc.rlimit");

	/* 统一 mutate（arm 之后一次到位） */
	{
		char p[512];

		snprintf(p, sizeof(p), "%s/sys/kernel/ai/stats/ai_actions",
			 TREE);
		wfile(p,
		 "cwnd_clamp_hits: 0\naiguard_freq_requests: 5\n"
		 "aiguard_freq_clamped: 1\naiguard_freq_cap_pct: 10000\n"
		 "wakeup_capture: 0\nwakeup_events: 500\n"
		 "netfilter_hook: 0\nnetfilter_pkts: 100000\n"
		 "netfilter_bytes: 1000000\naudit_capture: 0\n"
		 "audit_gate_drops: 3\nlsm_enforce: 1\nlsm_rules: 2\n"
		 "sched_base_slice_ns: 600000\nvfs_cache_pressure: 50\n");
		snprintf(p, sizeof(p),
			 "%s/sys/kernel/ai/stats/decisions_total", TREE);
		wfile(p, "442\n");
		snprintf(p, sizeof(p), "%s/proc/ai/ws_labels", TREE);
		wfile(p, "4242 7 burn\n");
		for (int cpu = 0; cpu < 2; cpu++) {
			snprintf(p, sizeof(p),
				 "%s/sys/devices/system/cpu/cpu%d/cpufreq/"
				 "scaling_cur_freq", TREE, cpu);
			wfile(p, "1500000\n");
			snprintf(p, sizeof(p),
				 "%s/sys/devices/system/cpu/cpu%d/cpuidle/"
				 "state1/time", TREE, cpu);
			wfile(p, "0\n");
		}
		snprintf(p, sizeof(p), "%s/proc/4242/oom_score_adj", TREE);
		wfile(p, "500\n");
		snprintf(p, sizeof(p), "%s/proc/4242/status", TREE);
		wfile(p, "Name:\tburn\nState:\tS (sleeping)\n"
			 "Cpus_allowed_list:\t2\n");
		{
			char lim[2048];

			snprintf(lim, sizeof(lim),
				 "Limit                     Soft LimitHard Limit Units \n"
				 "Max cpu time              unlimitedunlimited seconds\n"
				 "Max file size             unlimitedunlimited bytes\n"
				 "Max data size             unlimitedunlimited bytes\n"
				 "Max stack size            8388608  unlimited KB\n"
				 "Max core file size        0        unlimited bytes\n"
				 "Max processes             100      12345    processes\n"
				 "Max open files            1024     1048576  files\n"
				 "Max locked memory         65536    65536    KB\n"
				 "Max address space         unlimitedunlimited KB\n"
				 "Max file locks            unlimitedunlimited locks\n"
				 "Max pending signals       2341     2341     signals\n"
				 "Max msgqueue size         819200   819200   bytes\n"
				 "Max nice priority         0        0        \n"
				 "Max realtime priority     0        0        \n"
				 "Max realtime timeout      unlimitedunlimited us\n");
			snprintf(p, sizeof(p), "%s/proc/4242/limits", TREE);
			wfile(p, lim);
		}
	}
	/* io.priority 的 control 读回 4→1：改 control 文件该行 */
	{
		char p[512];

		snprintf(p, sizeof(p), "%s/proc/ai/control", TREE);
		wfile(p,
			"sched.nice domain=1 [real] min=-20 max=19 current=0 default=0\n"
			"sched.affinity domain=1 [real] min=0 max=255 current=0 default=0\n"
			"sched.oom_score domain=1 [real] min=-1000 max=1000 current=0 default=0\n"
			"sched.timeslice domain=1 [real] min=1 max=1000 current=6 default=6\n"
			"ai.decision_sched domain=1 [real] min=0 max=1 current=0 default=0\n"
			"mm.swappiness domain=2 [real] min=0 max=100 current=60 default=60\n"
			"mm.readahead domain=2 [real] min=0 max=4096 current=128 default=128\n"
			"mm.thp domain=2 [real] min=0 max=2 current=1 default=1\n"
			"mm.reclaim_prio domain=2 [real] min=0 max=100 current=100 default=100\n"
			"ai.decision_oom domain=2 [real] min=0 max=1 current=0 default=0\n"
			"ai.decision_mm domain=2 [real] min=0 max=1 current=0 default=0\n"
			"io.priority domain=3 [real] min=0 max=7 current=1 default=4\n"
			"io.bandwidth domain=3 [real] min=0 max=100 current=100 default=100\n"
			"net.cwnd domain=4 [real] min=1 max=4096 current=100 default=100\n"
			"net.rto domain=4 [real] min=1 max=10000 current=200 default=200\n"
			"net.qdisc domain=4 [real] min=0 max=3 current=1 default=1\n"
			"net.nftables domain=4 [real] min=0 max=1 current=0 default=0\n"
			"sec.lsm_override domain=5 [real] min=0 max=1 current=0 default=0\n"
			"sec.seccomp domain=5 [reserved] min=0 max=1 current=0 default=0\n"
			"sec.audit domain=5 [real] min=0 max=1 current=1 default=1\n"
			"sec.ws_label domain=5 [real] min=0 max=255 current=0 default=0\n"
			"ai.decision_inject domain=5 [real] min=0 max=1 current=0 default=0\n"
			"power.freq domain=6 [real] min=0 max=10000 current=10000 default=10000\n"
			"power.cstate domain=6 [real] min=0 max=10 current=2 default=2\n"
			"power.wakeup domain=6 [real] min=0 max=1 current=0 default=0\n"
			"proc.signal domain=12 [real] min=0 max=64 current=0 default=0\n"
			"proc.freeze domain=12 [real] min=0 max=1 current=0 default=0\n"
			"proc.rlimit domain=12 [real] min=0 max=1000000 current=1000000 default=1000000\n");
	}

	as_outcome_tick(&oc, as_now_mono_ms() + 400000);

	{
		static const struct row_case cases[] = {
			{ 1004, "sched.timeslice", AS_OC_SUCCESS, 275 },
			{ 1006, "mm.swappiness", AS_OC_WORSE, 240 },
			{ 1007, "mm.readahead", AS_OC_SUCCESS, 128 },
			{ 1008, "mm.reclaim_prio", AS_OC_SUCCESS, -50 },
			{ 1009, "io.priority", AS_OC_SUCCESS, -3 },
			{ 1010, "io.bandwidth", AS_OC_SUCCESS, -50 },
			{ 1011, "net.cwnd", AS_OC_SUCCESS, 100 },
			{ 1012, "net.rto", AS_OC_SUCCESS, 200 },
			{ 1013, "net.qdisc", AS_OC_SUCCESS, 1 },
			{ 1015, "sec.lsm_override", AS_OC_SUCCESS, 1 },
			{ 1017, "sec.audit", AS_OC_SUCCESS, -1 },
			{ 1016, "sec.ws_label", AS_OC_SUCCESS, 1 },
			{ 1018, "ai.decision_inject", AS_OC_SUCCESS, 400 },
			{ 1019, "power.freq", AS_OC_SUCCESS, -1000000 },
			{ 1020, "power.cstate", AS_OC_SUCCESS, -1000000 },
			{ 1003, "sched.oom_score", AS_OC_PARTIAL, 500 },
			{ 1002, "sched.affinity", AS_OC_SUCCESS, 1 },
			{ 1024, "proc.rlimit", AS_OC_SUCCESS, -12245 },
		};
		size_t pass = 0;

		for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
			int got = 0;
			long long dl = 0;

			CHECK(read_written(TREE, cases[i].id, &got, &dl) > 0,
			      "rows: written");
			if (got == cases[i].expect_oc &&
			    dl == cases[i].expect_delta) {
				pass++;
			} else {
				printf("    %-18s got=%d/%lld exp=%d/%lld\n",
				       cases[i].knob, got, dl,
				       cases[i].expect_oc,
				       cases[i].expect_delta);
				CHECK(0, "rows: case mismatch");
			}
		}
		printf("    misc rows exact-pass=%zu/%zu\n", pass,
		       sizeof(cases) / sizeof(cases[0]));
	}
	as_outcome_close(&oc);
	printf("  misc-rows: OK\n");
}

/* ====================================================================
 * 6) 无操作对照（§5.3：PARTIAL ≥80%）
 * ==================================================================== */

static void test_control_group(void)
{
	struct as_conf c;
	struct as_stats st;
	struct as_outcome oc;
	int partial = 0, total = 0;
	static const unsigned long long ids[10] = { 3001, 3002, 3003, 3004,
						    3005, 3006, 3007, 3008,
						    3009, 3010 };
	static const char *knobs[10] = { "sched.nice", "mm.swappiness",
					 "power.wakeup", "sec.audit",
					 "net.nftables", "mm.thp",
					 "proc.freeze", "proc.signal",
					 "sched.affinity",
					 "io.priority" };

	build_tree(TREE, 999999);
	conf_oc(&c, 256);
	memset(&st, 0, sizeof(st));
	CHECK(as_outcome_init(&oc, &c, &st) == 0, "ctrl: init");
	as_outcome_set_root(&oc, TREE);
	/* 对照基线：freeze/signal 预置已成立态（T），affinity 预置 "2" */
	set_pid_stat(TREE, 'T', 50, 20);
	{
		char p[512];

		snprintf(p, sizeof(p), "%s/proc/4242/status", TREE);
		wfile(p, "Name:\tburn\nState:\tT (stopped)\n"
			 "Cpus_allowed_list:\t2\n");
	}
	for (int i = 0; i < 10; i++)
		arm(&oc, ids[i], 2, knobs[i]);
	/* 不做任何 mutate（无操作） */
	as_outcome_tick(&oc, as_now_mono_ms() + 400000);
	for (int i = 0; i < 10; i++) {
		int got = 0;
		long long dl = 0;

		CHECK(read_written(TREE, ids[i], &got, &dl) > 0,
		      "ctrl: written");
		total++;
		if (got == AS_OC_PARTIAL)
			partial++;
		else
			printf("    control %s -> %d (expect PARTIAL)\n",
			       knobs[i], got);
	}
	printf("    control PARTIAL=%d/%d (%.0f%%)\n", partial, total,
	       100.0 * partial / total);
	CHECK(total == 10 && partial >= 8,
	      "gate3: no-op control PARTIAL >=80% (§5.3)");
	as_outcome_close(&oc);
	printf("  control-group: OK\n");
}

/* ====================================================================
 * 7) 降级与健壮性（§5.6）+ due + stats 渲染 + SME 独立性
 * ==================================================================== */

static int g_sink_count;

static void sink_count(struct as_event *ev, void *u)
{
	(void)ev;
	(void)u;
	g_sink_count++;
}

static void test_degrade(void)
{
	struct as_conf c;
	struct as_stats st;
	struct as_outcome oc;
	char p[512];

	/* 7a. 写口 ENOENT（dangling symlink）：notfound 计数一次即止 */
	build_tree(TREE, 999999);
	snprintf(p, sizeof(p), "%s/sys/kernel/ai/policy/outcome", TREE);
	unlink(p);
	CHECK(symlink("./nonexistent-target", p) == 0, "deg: symlink");
	conf_oc(&c, 8);
	memset(&st, 0, sizeof(st));
	CHECK(as_outcome_init(&oc, &c, &st) == 0, "deg: init");
	as_outcome_set_root(&oc, TREE);
	arm(&oc, 4001, 2, "proc.freeze");
	as_outcome_tick(&oc, as_now_mono_ms() + 400000);
	CHECK(st.oc.filled == 1, "deg: enoent filled");
	CHECK(st.oc.notfound == 1, "deg: enoent notfound=1 (no retry)");
	CHECK(st.oc.success + st.oc.partial + st.oc.worse == 0,
	      "deg: enoent no outcome counted");
	as_outcome_close(&oc);

	/* 7b. pid 消亡：meas_fail + PARTIAL + delta=0（仍写口——如实注记） */
	build_tree(TREE, 999999);
	memset(&st, 0, sizeof(st));
	CHECK(as_outcome_init(&oc, &c, &st) == 0, "deg: init2");
	as_outcome_set_root(&oc, TREE);
	arm(&oc, 4002, 2, "proc.freeze");	/* pid 99999 无文件 */
	as_outcome_tick(&oc, as_now_mono_ms() + 400000);
	{
		int got = -1;
		long long dl = 99;

		CHECK(st.oc.meas_fail == 1, "deg: meas_fail=1");
		CHECK(read_written(TREE, 4002, &got, &dl) > 0,
		      "deg: meas_fail still written");
		CHECK(got == AS_OC_PARTIAL && dl == 0,
		      "deg: meas_fail PARTIAL delta=0");
	}
	as_outcome_close(&oc);

	/* 7c. verify_fail：decisions outcome_ts=0（写口成功但内核未映） */
	build_tree(TREE, 0);			/* ots=0 全部 */
	memset(&st, 0, sizeof(st));
	CHECK(as_outcome_init(&oc, &c, &st) == 0, "deg: init3");
	as_outcome_set_root(&oc, TREE);
	arm(&oc, 4003, 2, "mm.thp");
	/* vmstat 动一下出带（SUCCESS） */
	{
		snprintf(p, sizeof(p), "%s/proc/vmstat", TREE);
		wfile(p, "thp_fault_alloc 7000\nthp_cow_fault 500\n");
	}
	as_outcome_tick(&oc, as_now_mono_ms() + 400000);
	CHECK(st.oc.success == 1, "deg: verify write ok");
	CHECK(st.oc.verify_fail == 1, "deg: verify_fail=1");
	as_outcome_close(&oc);

	/* 7d. due_ms + SME 独立性 + stats 渲染 */
	build_tree(TREE, 999999);
	memset(&st, 0, sizeof(st));
	g_sink_count = 0;
	CHECK(as_outcome_init(&oc, &c, &st) == 0, "deg: init4");
	as_outcome_set_root(&oc, TREE);
	as_outcome_set_sink(&oc, sink_count, NULL);
	{
		long long t0 = as_now_mono_ms();

		arm(&oc, 1005, 2, "mm.thp");
		CHECK(as_outcome_due_ms(&oc, t0 + 1000) > 0,
		      "deg: due>0 before window");
		as_outcome_tick(&oc, t0 + 400000);
		CHECK(as_outcome_due_ms(&oc, t0 + 400000) == -1,
		      "deg: due=-1 after drain");
	}
	CHECK(g_sink_count == 1, "deg: sink fired (write_sme=1)");
	CHECK(st.oc.verify_fail == 0, "deg: verify ok (ots>0)");
	as_outcome_close(&oc);

	/* write_sme=0：outcome 仍写（SME 不可达不阻塞，§4.4） */
	build_tree(TREE, 999999);
	memset(&st, 0, sizeof(st));
	g_sink_count = 0;
	conf_oc(&c, 8);
	c.outcome_write_sme = 0;
	CHECK(as_outcome_init(&oc, &c, &st) == 0, "deg: init5");
	as_outcome_set_root(&oc, TREE);
	as_outcome_set_sink(&oc, sink_count, NULL);
	arm(&oc, 1005, 2, "mm.thp");
	as_outcome_tick(&oc, as_now_mono_ms() + 400000);
	CHECK(g_sink_count == 0, "deg: write_sme=0 no sink");
	{
		int got = -1;
		long long dl = 0;

		CHECK(read_written(TREE, 1005, &got, &dl) > 0,
		      "deg: outcome written regardless of SME");
	}
	as_outcome_close(&oc);

	/* 7e. stats 渲染含 outcome.* 段 */
	{
		char *buf = NULL;
		size_t len = 0;
		FILE *m = open_memstream(&buf, &len);

		CHECK(m != NULL, "deg: memstream");
		if (m) {
			st.oc.armed = 5;
			as_stats_render(&st, 0, 0, m);
			fclose(m);
			CHECK(strstr(buf, "outcome.enabled=1") != NULL,
			      "deg: render outcome.enabled");
			CHECK(strstr(buf, "outcome.armed=5") != NULL,
			      "deg: render outcome.armed");
			CHECK(strstr(buf, "outcome.verify_fail=") != NULL,
			      "deg: render verify_fail");
			free(buf);
		}
	}
	printf("  degrade: OK\n");
}

/* ====================================================================
 * 8) T8 衔接：as_event_outcome 冻结行 + decision 23 列 outcome 列可写
 * ==================================================================== */

static void test_parquet_link(void)
{
	struct as_event ev;

	/* 冻结行（SME 记忆语料与 parquet data 列的内容契约） */
	as_event_outcome(&ev, 4711, AS_OC_SUCCESS, -42, "proc.freeze");
	CHECK(strcmp(ev.line,
		     "[kern] event outcome decision_id=4711 outcome=SUCCESS "
		     "delta=-42 knob=proc.freeze") == 0,
	      "pq: frozen outcome event line");
	CHECK(ev.has_decision_id == 1 && ev.decision_id == 4711,
	      "pq: decision_id passthrough");
	as_event_outcome(&ev, 8, AS_OC_WORSE, 7, "mm.thp");
	CHECK(strcmp(ev.line,
		     "[kern] event outcome decision_id=8 outcome=WORSE "
		     "delta=7 knob=mm.thp") == 0,
	      "pq: frozen outcome event line (WORSE)");

	/* decision 23 列 schema：outcome/outcome_ts/metric_delta 已预留
	 * （as_parquet.h pq_dec_row）——填充后写盘 + footer 统计可读
	 * = 落盘侧零改动即兼容（设计 §0.5） */
	{
		const char *root = "/tmp/as-oc-pq";
		struct pq_dec_row row;
		struct pq_write_stat ws;
		int64_t btime = as_pq_btime();
		char cmd[512];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", root);
		if (system(cmd) != 0)
			(void)0;	/* 清场尽力 */
		memset(&row, 0, sizeof(row));
		row.decision_id = 4711;
		row.trigger_ts = 1000000000LL;
		row.decision_ts = 1000000000LL;
		row.outcome_ts = 1000500000LL;
		row.outcome = 1;
		row.metric_delta = -42;
		row.executed = 1;
		CHECK(as_pq_ensure_root(root) == 0, "pq: ensure root");
		CHECK(as_pq_write_decisions(root, &row, 1, btime, &ws) == 1,
		      "pq: write 1 decision row");
		{
			char path[512];
			struct pq_file_stats fs;
			DIR *d;
			struct dirent *e;
			int found = 0;

			snprintf(path, sizeof(path), "%s/decisions", root);
			d = opendir(path);
			CHECK(d != NULL, "pq: decisions dir");
			if (d) {
				while ((e = readdir(d)) != NULL) {
					char day[1024];

					if (e->d_name[0] == '.')
						continue;
					snprintf(day, sizeof(day),
						 "%s/%.200s/decisions.parquet",
						 path, e->d_name);
					if (access(day, R_OK) == 0 &&
					    as_pq_file_stats(day, &fs) == 0 &&
					    fs.num_rows == 1) {
						found = 1;
						break;
					}
				}
				closedir(d);
			}
			CHECK(found, "pq: outcome/outcome_ts row round-trip "
				     "(footer num_rows=1)");
		}
	}
	printf("  parquet-link: OK\n");
}

/* ==================================================================== */

int main(void)
{
	if (system("rm -rf /tmp/as-oc-tree /tmp/as-oc-tree2 /tmp/as-oc-scan /tmp/as-oc-pq") != 0)
		(void)0;	/* 清场尽力 */

	test_table_conf();
	test_decisions_scan();
	test_tap_paths();
	test_fill_gates();
	test_misc_rows();
	test_control_group();
	test_degrade();
	test_parquet_link();
	if (fails) {
		printf("test_outcome: %d failures\n", fails);
		return 1;
	}
	printf("test_outcome: OK\n");
	return 0;
}
