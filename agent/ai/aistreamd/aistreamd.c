// SPDX-License-Identifier: GPL-2.0
/*
 * aistreamd.c - K3c 常驻内核事件流 → SME 记忆守护（主程序）
 *
 * 管道：六路 socket（poll 单进程）→ 解析 → 事件规范化（as_event）
 *   → [K3d-2] 热插拔建议流水线 tap（as_hotplug：sense→infer→decide
 *     →advisory JSONL 落盘；**act 级不存在，executed 恒 false——C7 红线：
 *     设备移除/下线类动作永不自动执行**）
 *   → 10s 去重窗口（首条立即写，聚合补写）
 *   → 配额（速率/日限/每路日限，as_quota）
 *   → POST /memories（as_sme；不可达入有界环形缓冲，恢复按序补写）
 *
 * lease：flock /run/aistreamd.lock + pid 文件，第二实例启动即退（非 0）。
 * 审计：stdout/stderr → journald（desktopd 风格 "aistreamd: " 前缀）；
 *   每路计数落 /run/aistreamd.stats（原子写：周期 + SIGUSR1 + 退出前）。
 * 回滚：systemctl stop/disable aikernel-streams 即回现状；记忆侧按
 *   tag kernel_evt 检索批量 DELETE（见 K3C-REPORT.md 回滚节）。
 * 信号：SIGTERM/SIGINT=优雅退出（关 socket、环形缓冲尽力补写、终笔
 *   stats）；SIGUSR1=立即写 stats；SIGHUP=重载标量配额项。
 *
 * 降级诚实：单路 socket 打开失败＝journal 告警 + state=stopped，进程不退；
 *   SME 不可达＝环形缓冲丢旧不丢新 + 计数 + 限频告警。
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "as_conf.h"
#include "as_event.h"
#include "as_hotplug.h"
#include "as_quota.h"
#include "as_ring.h"
#include "as_sme.h"
#include "as_stats.h"
#include "as_streams.h"
#include "as_util.h"

#define AISTREAMD_VERSION \
	"aistreamd 1.1 (K3c I-5+I-4+I-6 + K3d-2 I-9 hotplug advisory)"

/* ---- 全局上下文（单线程，信号只置标志） ---- */

static volatile sig_atomic_t g_stop;
static volatile sig_atomic_t g_dump;
static volatile sig_atomic_t g_reload;

struct g_ctx {
	struct as_conf conf;
	struct as_stats stats;
	struct as_quota quota;
	struct as_dedup dedup;
	struct as_sme sme;
	struct as_streams streams;
	struct as_hotplug hotplug;	/* K3d-2：advisory-only（C7 红线） */
	int lock_fd;
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

/* ---- 管道（解析回调 → 去重 → 配额 → SME） ---- */

static void quota_then_deliver(struct g_ctx *g, const struct as_event *ev)
{
	enum as_quota_verdict v =
		as_quota_check(&g->quota, ev->stream_idx, ev->ts_real_ms);

	if (v != AS_Q_ALLOW) {
		as_stats_quota(&g->stats, ev->stream_idx);
		as_warn_ratelimit("quota", 60000,
				  "quota drop stream=%s: %s (filtered=%lld)",
				  ev->stream, as_quota_reason(v),
				  g->stats.per[ev->stream_idx].filtered_quota);
		return;
	}
	as_quota_commit(&g->quota, ev->stream_idx, ev->ts_real_ms);
	as_sme_deliver(&g->sme, ev);
}

/* 去重聚合记录回调（不走去重，直接配额→写） */
static void agg_emit(struct as_event *agg, void *u)
{
	struct g_ctx *g = u;

	quota_then_deliver(g, agg);
}

static void on_event(struct as_event *ev, void *u)
{
	struct g_ctx *g = u;

	/* received 已在解析器计数 */
	/* K3d-2：热插拔建议流水线（advisory-only）——先于去重 tap（重复
	 * uevent 由 hotplug 自身日限配额约束）；K3c 记忆路零改动。
	 * C7 红线：该流水线只产建议（executed 恒 false），不执行任何动作。 */
	as_hotplug_tap(&g->hotplug, ev);
	if (as_dedup_filter(&g->dedup, ev, ev->ts_real_ms) ==
	    AS_DEDUP_SUPPRESS) {
		as_stats_dedup(&g->stats, ev->stream_idx);
		return;
	}
	quota_then_deliver(g, ev);
}

/* ---- 单实例 lease ---- */

static int acquire_lock(struct g_ctx *g)
{
	int fd = open(g->conf.lock_file, O_RDWR | O_CREAT | O_CLOEXEC, 0644);

	if (fd < 0) {
		as_log("FATAL: open %s: %s", g->conf.lock_file,
		       strerror(errno));
		return -1;
	}
	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		if (errno == EWOULDBLOCK) {
			char buf[32] = "";
			ssize_t r = pread(fd, buf, sizeof(buf) - 1, 0);

			if (r > 0)
				buf[r] = '\0';
			as_log("FATAL: another aistreamd holds %s (pid=%s) — "
			       "single instance (lease), exiting",
			       g->conf.lock_file, r > 0 ? buf : "?");
		} else {
			as_log("FATAL: flock %s: %s", g->conf.lock_file,
			       strerror(errno));
		}
		close(fd);
		return -1;
	}
	{
		char pidbuf[32];
		int n = snprintf(pidbuf, sizeof(pidbuf), "%d\n",
				 (int)getpid());

		if (ftruncate(fd, 0) != 0 || lseek(fd, 0, SEEK_SET) != 0 ||
		    write(fd, pidbuf, (size_t)n) != n) {
			as_log("FATAL: write lock file: %s", strerror(errno));
			close(fd);
			return -1;
		}
	}
	g->lock_fd = fd;
	/* pid 文件（lease 的可观测面；退出时 unlink） */
	{
		FILE *pf = fopen(g->conf.pid_file, "w");

		if (pf) {
			fprintf(pf, "%d\n", (int)getpid());
			fclose(pf);
		} else {
			as_warn_ratelimit("pidfile", 60000,
					  "pid file %s: %s (continuing)",
					  g->conf.pid_file, strerror(errno));
		}
	}
	return 0;
}

/* ---- stats ---- */

static void write_stats(struct g_ctx *g, const char *why)
{
	if (as_stats_write_file(&g->stats, g->conf.stats_file,
				as_ring_count(&g->sme.ring),
				g->sme.ring.dropped) != 0)
		as_warn_ratelimit("stats-write", 60000,
				  "stats write %s failed: %s",
				  g->conf.stats_file, strerror(errno));
	else
		as_log_debug("stats written (%s)", why);
}

/* ---- SIGHUP：重载标量配额（socket 开关/路径/mock 通道不可动态改） ---- */

static void reload_scalars(struct g_ctx *g, const char *conf_path)
{
	struct as_conf nc;
	char err[256];

	as_conf_defaults(&nc);
	if (as_conf_load(&nc, conf_path, err, sizeof(err)) != 0) {
		as_warn_ratelimit("conf-reload", 10000,
				  "SIGHUP: conf reload rejected: %s", err);
		return;
	}
	g->conf.importance = nc.importance;
	g->conf.rate_per_min = nc.rate_per_min;
	g->conf.daily_max = nc.daily_max;
	g->conf.stream_daily_max = nc.stream_daily_max;
	g->conf.dedup_window_ms = nc.dedup_window_ms;
	g->conf.sme_retry_sec = nc.sme_retry_sec;
	g->conf.stats_interval_sec = nc.stats_interval_sec;
	g->conf.taskstats_interval_sec = nc.taskstats_interval_sec;
	g->conf.taskstats_max_pids = nc.taskstats_max_pids;
	g->conf.log_debug = nc.log_debug;
	as_set_debug(g->conf.log_debug);
	g->conf.hotplug_daily_max = nc.hotplug_daily_max;
	/* K3d-2：advisory 日限热更（专用配额实例直改；rate 窗容量初始化固定） */
	g->hotplug.quota.daily_max = g->conf.hotplug_daily_max;
	g->hotplug.quota.stream_daily_max = g->conf.hotplug_daily_max;
	g->dedup.window_ms = g->conf.dedup_window_ms;
	as_log("SIGHUP: scalar quota knobs reloaded (rate/min=%lld "
	       "daily=%lld stream_daily=%lld window=%lldms hotplug_daily=%lld)",
	       g->conf.rate_per_min, g->conf.daily_max,
	       g->conf.stream_daily_max, g->conf.dedup_window_ms,
	       g->conf.hotplug_daily_max);
}

/* ---- usage / 主 ---- */

static void usage(FILE *out)
{
	fprintf(out,
		"usage: aistreamd [--conf PATH] [--check-conf] [--version]\n"
		"  --conf PATH     config file (default %s)\n"
		"  --check-conf    validate config and exit 0/1\n"
		"  --version       print version\n",
		AS_CONF_PATH_DEFAULT);
}

int main(int argc, char **argv)
{
	const char *conf_path = AS_CONF_PATH_DEFAULT;
	int check_only = 0;
	char err[256];
	struct pollfd pfds[AS_NSTREAMS];
	int idx_map[AS_NSTREAMS];

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--conf") == 0 && i + 1 < argc) {
			conf_path = argv[++i];
		} else if (strcmp(argv[i], "--check-conf") == 0) {
			check_only = 1;
		} else if (strcmp(argv[i], "--version") == 0) {
			printf("%s\n", AISTREAMD_VERSION);
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
	as_conf_defaults(&G.conf);
	if (as_conf_load(&G.conf, conf_path, err, sizeof(err)) != 0) {
		as_log("FATAL: conf: %s", err);
		return check_only ? 1 : 1;
	}
	if (check_only) {
		printf("conf OK: %s\n", conf_path);
		printf("sme_url=%s rate_per_min=%lld daily_max=%lld "
		       "stream_daily_max=%lld dedup_window_ms=%lld "
		       "ring_size=%lld importance=%.2f\n",
		       G.conf.sme_url, G.conf.rate_per_min, G.conf.daily_max,
		       G.conf.stream_daily_max, G.conf.dedup_window_ms,
		       G.conf.ring_size, G.conf.importance);
		printf("hotplug enabled=%d model=%s daily_max=%lld dim=%lld "
		       "mock=%d log=%s (executed always false — C7)\n",
		       G.conf.hotplug_enabled,
		       G.conf.hotplug_model[0] ? G.conf.hotplug_model : "-",
		       G.conf.hotplug_daily_max, G.conf.hotplug_infer_dim,
		       G.conf.hotplug_infer_mock, G.conf.hotplug_log);
		return 0;
	}

	as_set_debug(G.conf.log_debug);
	if (acquire_lock(&G) != 0)
		return 1;
	as_log("%s starting (conf=%s)", AISTREAMD_VERSION, conf_path);
	as_log("pid=%d lock=%s stats=%s", (int)getpid(), G.conf.lock_file,
	       G.conf.stats_file);

	as_stats_init(&G.stats, &G.conf);
	as_stats_set_conf_path(&G.stats, conf_path);
	if (as_quota_init(&G.quota, G.conf.rate_per_min, G.conf.daily_max,
			  G.conf.stream_daily_max) != 0) {
		as_log("FATAL: quota init: %s", strerror(errno));
		return 1;
	}
	as_dedup_init(&G.dedup, G.conf.dedup_window_ms);
	if (as_sme_init(&G.sme, &G.conf, &G.stats) != 0) {
		as_log("FATAL: ring init: %s", strerror(errno));
		return 1;
	}
	if (as_hotplug_init(&G.hotplug, &G.conf, &G.stats) != 0) {
		/* 仅配额内存失败致命；日志路径问题已在内部降级（journal 可见） */
		as_log("FATAL: hotplug quota init: %s", strerror(errno));
		return 1;
	}
	if (as_streams_setup(&G.streams, &G.conf, &G.stats, on_event,
			     &G) != 0) {
		as_log("FATAL: streams setup");
		return 1;
	}

	/* 信号：不带 SA_RESTART，让 poll 以 EINTR 及时醒来 */
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

	write_stats(&G, "startup");
	as_log("running (streams: see %s)", G.conf.stats_file);

	long long next_stats = as_now_mono_ms() +
			       G.conf.stats_interval_sec * 1000;
	long long next_sme_retry = 0;

	while (!g_stop) {
		long long now = as_now_mono_ms();
		long long timeout = 1000;	/* 兜底 1s 醒一次跑定时器 */
		long long due;
		int n;

		if (g_dump) {
			g_dump = 0;
			write_stats(&G, "sigusr1");
		}
		if (g_reload) {
			g_reload = 0;
			reload_scalars(&G, conf_path);
		}
		/* 定时器到期检查 */
		if (now >= next_stats) {
			write_stats(&G, "periodic");
			next_stats = now + G.conf.stats_interval_sec * 1000;
		}
		if (as_ring_count(&G.sme.ring) > 0 && now >= next_sme_retry) {
			as_sme_flush(&G.sme);
			next_sme_retry = now + G.conf.sme_retry_sec * 1000;
		}
		as_dedup_flush(&G.dedup, as_now_real_ms(), agg_emit, &G);
		due = as_streams_taskstats_due_ms(&G.streams);
		if (due <= 0) {
			as_streams_taskstats_tick(&G.streams);
			due = as_streams_taskstats_due_ms(&G.streams);
		}
		if (due > 0 && due < timeout)
			timeout = due;
		if (next_stats - now > 0 && next_stats - now < timeout)
			timeout = next_stats - now;

		{
			int cnt = as_streams_fill_poll(&G.streams, pfds,
						       idx_map, AS_NSTREAMS);

			n = poll(pfds, (nfds_t)cnt, (int)timeout);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				as_warn_ratelimit("poll", 60000, "poll: %s",
						  strerror(errno));
				continue;
			}
			for (int i = 0; i < cnt && n > 0; i++) {
				if (pfds[i].revents == 0)
					continue;
				n--;
				if (pfds[i].revents &
				    (POLLIN | POLLERR | POLLHUP))
					as_streams_dispatch(&G.streams,
							    idx_map[i]);
			}
		}
	}

	/* 优雅退出：关 socket → 环形缓冲尽力补写一轮 → advisory 落盘 flush
	 * → 终笔 stats */
	as_log("SIGTERM/INT: graceful shutdown");
	as_streams_close_all(&G.streams);
	as_sme_flush(&G.sme);
	as_hotplug_close(&G.hotplug);	/* K3d-2：flush+close advisory JSONL */
	write_stats(&G, "final");
	as_sme_free(&G.sme);
	as_quota_free(&G.quota);
	unlink(G.conf.pid_file);
	flock(G.lock_fd, LOCK_UN);
	close(G.lock_fd);
	as_log("bye");
	return 0;
}
