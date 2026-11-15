// SPDX-License-Identifier: GPL-2.0
/*
 * aipd.c - AIPD-M1 毫秒级快路径守护（影子期；aistreamd 骨架克隆）
 *
 * 管道：POLL_HZ 特征轮询（aip_feat：map35 裸 bpf()|mock）→ 静态阈值表
 *   决策（aip_decide：按序首命中，p99<1ms 纯函数）→ 影子记录
 *   （aip_shadow：33 列 parquet + 对照 mismatch 滚动窗）。
 *
 * ██████ M1 影子红线（设计 §0）：SHADOW 恒 1——**本守护无任何 ACT
 * 下发代码路径**（不调 NETLINK_AI ACT/ACT2；影子行 executed 恒 0）。
 * 全部输出=本地影子记录+stats。金丝雀/下发=M2 拍板。██████████
 *
 * lease：flock /run/aipd.lock + pid 文件，第二实例启动即退（非 0）。
 * 审计：stdout/stderr → journald 前缀 "aipd: "；stats 落
 *   /run/aipd.stats（原子写：周期 + SIGUSR1 + 退出前；heartbeat_ts_ms
 *   =失联判据面）。
 * 信号：SIGTERM/SIGINT=优雅退出（影子批 flush+终笔 stats）；
 *   SIGUSR1=立即写 stats；SIGHUP=重载标量（STATS_INTERVAL_SEC/
 *   LOG_DEBUG——路径/源/频率类改配置走 restart，journal 已含初值）。
 * 降级诚实：单轮特征读失败=计数跳过该轮（进程不退）；map35 不可用
 *   =按 conf 诚实 exit 1 或降级 mock（计数+journal 明示）。
 * 单轮模式：AIPD_ONCE=1（测试/冒烟——跑一轮 tick 即优雅退出，
 *   aistreamd AS_ONCE 先例）。
 *
 * 子命令：aipd bench [--n N]（决策延迟测点，输出 AIPD_BENCH 行——
 *   Lane-B m1_bench.py 台架解析此格式）。
 */
#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#include "aip_conf.h"
#include "aip_feat.h"
#include "aip_model.h"
#include "aip_shadow.h"
#include "aip_table.h"
#include "aip_util.h"

#define AIPD_VERSION \
	"aipd 1.0 (AIPD-M1 shadow: map35|mock feat + static table + parquet shadow; no ACT path)"

/* ---- 全局上下文（单线程，信号只置标志） ---- */

static volatile sig_atomic_t g_stop;
static volatile sig_atomic_t g_dump;
static volatile sig_atomic_t g_reload;

struct g_ctx {
	struct aip_conf conf;
	struct aip_stats stats;
	struct aip_feat_src feat;
	struct aip_shadow shadow;
	struct aip_cmp cmp;
	int cmp_on;			/* conf compare_enabled */
	int lock_fd;
	/* 决策计数（stats 面） */
	long long decisions, decision_hits, decisions_stale;
};

static struct g_ctx G;

static void on_signal(int sig)
{
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		g_stop = 1;
		break;
	case SIGUSR1:
		g_dump = 1;
		break;
	case SIGHUP:
		g_reload = 1;
		break;
	default:
		break;
	}
}

/* ---- stats ---- */

static void sync_stats(struct g_ctx *g)
{
	struct aip_stats *st = &g->stats;

	st->polls = (long long)g->feat.polls;
	st->feat_ok = (long long)g->feat.ok;
	st->feat_errors = (long long)g->feat.errors;
	st->feat_stale = (long long)g->feat.stale_polls;
	st->feat_bad_lines = (long long)g->feat.bad_lines;
	st->feat_empty = (long long)g->feat.empty_polls;
	st->decisions = g->decisions;
	st->decision_hits = g->decision_hits;
	st->decisions_stale = g->decisions_stale;
	st->cmp_total = g->cmp.matched + g->cmp.mismatch;
	st->cmp_mismatch = g->cmp.mismatch;
	st->mismatch_pct = aip_cmp_pct(&g->cmp);
	st->shadow_rows = g->shadow.rows_written;
	st->shadow_files = g->shadow.files;
	st->shadow_errors = g->shadow.errors;
	st->shadow_flushes = g->shadow.flushes;
}

static void write_stats(struct g_ctx *g, const char *why)
{
	g->stats.heartbeat_ts_ms = aip_now_real_ms();
	if (aip_stats_write_file(&g->stats, g->conf.stats_file) != 0)
		aip_warn_ratelimit("stats-write", 60000,
				   "stats write %s failed: %s",
				   g->conf.stats_file, strerror(errno));
	else
		aip_log_debug("stats written (%s)", why);
}

/* ---- SIGHUP：重载标量（路径/源/频率类不可动态改） ---- */

static void reload_scalars(struct g_ctx *g, const char *conf_path)
{
	struct aip_conf nc;
	char err[256];

	aip_conf_defaults(&nc);
	if (aip_conf_load(&nc, conf_path, err, sizeof(err)) != 0) {
		aip_warn_ratelimit("conf-reload", 10000,
				   "SIGHUP: conf reload rejected: %s", err);
		return;
	}
	g->conf.stats_interval_sec = nc.stats_interval_sec;
	g->conf.log_debug = nc.log_debug;
	aip_set_debug(g->conf.log_debug);
	aip_log("SIGHUP: scalars reloaded (stats_interval=%llds "
		"log_debug=%d; source/hz/path changes need restart)",
		g->conf.stats_interval_sec, g->conf.log_debug);
}

/* ---- 对照流 tick（只读对照；游标手法=as_decisions 摄取同源） ---- */

#define AIP_CMP_SCAN_MAX	4096	/* 内核 ring 全量口径 */

struct cmp_row {
	unsigned long long id;
	uint32_t action;
};

static int cmp_row_cmp(const void *a, const void *b)
{
	unsigned long long x = ((const struct cmp_row *)a)->id;
	unsigned long long y = ((const struct cmp_row *)b)->id;

	return x < y ? -1 : x > y ? 1 : 0;
}

static void compare_tick(struct g_ctx *g)
{
	const char *path;
	FILE *f;
	char line[1024];
	struct cmp_row rows[AIP_CMP_SCAN_MAX];
	size_t n = 0;

	if (!g->cmp_on)
		return;
	path = g->conf.compare_mock ? g->conf.compare_mock_file :
				      "/proc/ai/decisions";
	f = fopen(path, "r");
	if (!f) {
		if (errno == ENOENT) {
			/* 无内核面：诚实计数（feat.noiface 同口径） */
			g->stats.feat_empty++;	/* 复用 empty 计数面：
						   对照源缺失观测 */
		} else {
			aip_warn_ratelimit("cmp-open", 60000,
					   "compare open %s: %s", path,
					   strerror(errno));
		}
		return;
	}
	while (n < AIP_CMP_SCAN_MAX && fgets(line, sizeof(line), f)) {
		unsigned long long id;
		uint32_t action;

		if (g->conf.compare_mock) {
			if (aip_cmp_parse_mock_line(line, &id, &action) != 0)
				continue;	/* 坏行跳过（诚实） */
		} else {
			if (aip_cmp_parse_proc_line(line, &id, &action) != 0)
				continue;
		}
		/* 游标去重：仅摄取 id>游标（ring 最新在前→乱序收集后升序） */
		if (g->cmp.have_cursor && id <= g->cmp.cursor)
			continue;
		rows[n].id = id;
		rows[n].action = action;
		n++;
	}
	fclose(f);
	qsort(rows, n, sizeof(*rows), cmp_row_cmp);
	for (size_t i = 0; i < n; i++)
		aip_cmp_observe(&g->cmp, rows[i].id, rows[i].action);
}

/* ---- usage / 主 ---- */

static void usage(FILE *out)
{
	fprintf(out,
		"usage: aipd [--conf PATH] [--check-conf] [--version]\n"
		"       aipd bench [--n N]   in-proc decide latency probe\n"
		"  --conf PATH     config file (default %s)\n"
		"  --check-conf    validate config and exit 0/1\n"
		"  --version       print version\n",
		AIP_CONF_PATH_DEFAULT);
}

static int run_bench(int argc, char **argv)
{
	long n = 10000;

	for (int i = 2; i < argc; i++) {
		if (strcmp(argv[i], "--n") == 0 && i + 1 < argc) {
			char *end = NULL;

			n = strtol(argv[++i], &end, 10);
			if (!end || *end || n < 1) {
				fprintf(stderr, "aipd: bench --n invalid\n");
				return 2;
			}
		} else {
			usage(stderr);
			return 2;
		}
	}
	return aip_bench_run(n) == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
	const char *conf_path = AIP_CONF_PATH_DEFAULT;
	int check_only = 0;
	char err[256];
	long long period_ms;
	long long next_poll, next_stats, next_flush, next_cmp;
	int once;

	if (argc >= 2 && strcmp(argv[1], "bench") == 0)
		return run_bench(argc, argv);
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--conf") == 0 && i + 1 < argc) {
			conf_path = argv[++i];
		} else if (strcmp(argv[i], "--check-conf") == 0) {
			check_only = 1;
		} else if (strcmp(argv[i], "--version") == 0) {
			printf("%s\n", AIPD_VERSION);
			return 0;
		} else if (strcmp(argv[i], "--help") == 0) {
			usage(stdout);
			return 0;
		} else {
			usage(stderr);
			return 2;
		}
	}

	memset(&G, 0, sizeof(G));
	G.lock_fd = -1;
	aip_conf_defaults(&G.conf);
	if (aip_conf_load(&G.conf, conf_path, err, sizeof(err)) != 0) {
		aip_log("FATAL: conf: %s", err);
		return 1;
	}
	if (check_only) {
		printf("conf OK: %s\n", conf_path);
		printf("feat_source=%s mock=%s poll_hz=%lld "
		       "degrade_mock=%d\n",
		       G.conf.feat_source == 1 ? "mock" : "map35",
		       G.conf.feat_mock_file[0] ? G.conf.feat_mock_file : "-",
		       G.conf.poll_hz, G.conf.feat_degrade_mock);
		printf("shadow=%d (M1 frozen; no ACT path) parquet_dir=%s "
		       "flush=%llds/%lldrows\n",
		       G.conf.shadow, G.conf.parquet_dir,
		       G.conf.shadow_flush_sec, G.conf.shadow_flush_rows);
		printf("compare enabled=%d source=%s interval=%llds "
		       "window=%lld\n",
		       G.conf.compare_enabled,
		       G.conf.compare_mock ? "mock" : "proc",
		       G.conf.compare_interval_sec, G.conf.cmp_window);
		printf("stats_interval=%llds stats=%s\n",
		       G.conf.stats_interval_sec, G.conf.stats_file);
		return 0;
	}

	/* 表自校验（sha256 漂移/篡改=拒载启动——Lane-B --check 同口径） */
	if (aip_table_check(err, sizeof(err)) != 0) {
		aip_log("FATAL: table check: %s", err);
		return 1;
	}

	aip_set_debug(G.conf.log_debug);
	if (aip_acquire_lease(&G.conf, &G.lock_fd) != 0)
		return 1;
	aip_log("%s starting (conf=%s)", AIPD_VERSION, conf_path);
	aip_log("pid=%d lock=%s stats=%s — SHADOW ONLY (M1: no ACT path)",
		(int)getpid(), G.conf.lock_file, G.conf.stats_file);

	aip_stats_init(&G.stats, &G.conf, conf_path);
	G.stats.table_ver = (long long)aip_table_ver;
	G.stats.table_rules = (long long)aip_nrules;

	if (aip_feat_open(&G.feat, &G.conf, err, sizeof(err)) != 0) {
		aip_log("FATAL: feat open: %s", err);
		aip_release_lease(&G.conf, G.lock_fd);
		return 1;
	}
	if (G.feat.mock_degraded)
		snprintf(G.stats.feat_source, sizeof(G.stats.feat_source),
			 "mock(degraded)");
	if (aip_shadow_init(&G.shadow, &G.conf) != 0) {
		aip_log("FATAL: shadow init: %s", strerror(errno));
		aip_feat_close(&G.feat);
		aip_release_lease(&G.conf, G.lock_fd);
		return 1;
	}
	G.cmp_on = G.conf.compare_enabled;
	if (G.cmp_on) {
		if (aip_cmp_init(&G.cmp,
				 (unsigned)G.conf.cmp_window) != 0) {
			aip_log("FATAL: cmp init: %s", strerror(errno));
			aip_shadow_close(&G.shadow);
			aip_feat_close(&G.feat);
			aip_release_lease(&G.conf, G.lock_fd);
			return 1;
		}
		aip_log("compare on: source=%s window=%lld (read-only)",
			G.conf.compare_mock ? "mock" : "proc",
			G.conf.cmp_window);
	}
	aip_log("table: ver=%u rules=%zu sha256=%s (self-check OK)",
		aip_table_ver, aip_nrules, aip_table_sha256);

	/* 信号：不带 SA_RESTART（aistreamd 先例） */
	signal(SIGPIPE, SIG_IGN);
	{
		struct sigaction sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = on_signal;
		sigemptyset(&sa.sa_mask);
		sigaction(SIGTERM, &sa, NULL);
		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGUSR1, &sa, NULL);
		sigaction(SIGHUP, &sa, NULL);
	}

	once = (getenv("AIPD_ONCE") && getenv("AIPD_ONCE")[0] == '1');
	period_ms = 1000 / (G.conf.poll_hz > 0 ? G.conf.poll_hz : 1);
	if (period_ms < 1)
		period_ms = 1;
	write_stats(&G, "startup");

	next_poll = aip_now_mono_ms();
	next_stats = aip_now_mono_ms() + G.conf.stats_interval_sec * 1000;
	next_flush = aip_now_mono_ms() + G.conf.shadow_flush_sec * 1000;
	next_cmp = aip_now_mono_ms() + G.conf.compare_interval_sec * 1000;

	while (!g_stop) {
		long long now = aip_now_mono_ms();
		long long timeout = 1000;	/* 兜底 1s 醒一次 */

		if (once)
			g_stop = 1;
		if (g_dump) {
			g_dump = 0;
			sync_stats(&G);
			write_stats(&G, "sigusr1");
		}
		if (g_reload) {
			g_reload = 0;
			reload_scalars(&G, conf_path);
		}
		if (now >= next_poll) {
			struct aip_fvec v;
			struct aip_decision d;
			int stale = 0;

			if (aip_feat_poll(&G.feat, &v, &stale) == 0) {
				uint64_t decision_ts = (uint64_t)
					aip_now_mono_ns();

				if (aip_decide(&v, aip_rules, aip_nrules,
					       NULL, &d) == 0) {
					if (stale)
						d.flags |= AIP_DF_STALE;
					G.decisions++;
					if (d.flags & AIP_DF_HIT)
						G.decision_hits++;
					if (stale)
						G.decisions_stale++;
					aip_shadow_feed(&G.shadow, &v, stale,
							&d,
							(long long)
							decision_ts);
					aip_cmp_shadow(&G.cmp, d.action);
				}
			} else {
				aip_log_debug("feat poll failed (skipped)");
			}
			next_poll += period_ms;
			if (next_poll <= now)	/* 落后过多：重贴（不追帧） */
				next_poll = now + period_ms;
		}
		if (now >= next_stats) {
			sync_stats(&G);
			write_stats(&G, "periodic");
			next_stats = now + G.conf.stats_interval_sec * 1000;
		}
		if (G.shadow.n > 0 && (now >= next_flush ||
				       (long long)G.shadow.n >=
				       G.conf.shadow_flush_rows)) {
			aip_shadow_flush(&G.shadow);
			next_flush = now + G.conf.shadow_flush_sec * 1000;
		}
		if (G.cmp_on && now >= next_cmp) {
			compare_tick(&G);
			next_cmp = now + G.conf.compare_interval_sec * 1000;
		}
		{
			long long dues[4] = {
				next_poll - now,
				next_stats - now,
				G.shadow.n ? next_flush - now : -1,
				G.cmp_on ? next_cmp - now : -1,
			};

			for (int i = 0; i < 4; i++)
				if (dues[i] > 0 && dues[i] < timeout)
					timeout = dues[i];
		}
		if (timeout < 1)
			timeout = 1;
		{
			struct pollfd dummy;

			dummy.fd = -1;
			dummy.events = 0;
			if (poll(&dummy, 1, (int)timeout) < 0 &&
			    errno != EINTR)
				aip_warn_ratelimit("poll", 60000, "poll: %s",
						   strerror(errno));
		}
	}

	/* 优雅退出：影子批 flush → 终笔 stats → 释放 */
	aip_log("SIGTERM/INT: graceful shutdown");
	aip_shadow_close(&G.shadow);
	sync_stats(&G);
	write_stats(&G, "final");
	if (G.cmp_on)
		aip_cmp_free(&G.cmp);
	aip_feat_close(&G.feat);
	aip_release_lease(&G.conf, G.lock_fd);
	aip_log("bye (decisions=%lld hits=%lld stale=%lld "
		"shadow_rows=%lld files=%lld mismatch_pct=%.2f)",
		G.decisions, G.decision_hits, G.decisions_stale,
		G.shadow.rows_written, G.shadow.files,
		aip_cmp_pct(&G.cmp));
	return 0;
}
