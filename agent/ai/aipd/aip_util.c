/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_util.c - aipd 公共小工具实现（时间/日志/原子写/lease/stats）
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "aip_util.h"

long long aip_now_mono_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

long long aip_now_mono_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

long long aip_now_real_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return 0;
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ---- 日志（journald 前缀 "aipd: "） ---- */

static int g_debug;

void aip_set_debug(int on)
{
	g_debug = on;
}

void aip_log(const char *fmt, ...)
{
	va_list ap;

	fputs("aipd: ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

void aip_log_debug(const char *fmt, ...)
{
	va_list ap;

	if (!g_debug)
		return;
	fputs("aipd: ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

/* 限频表（静态有界；key 指针为字面量——不拷贝） */
#define RL_MAX		32
#define RL_COOLDOWN_MS	60000

struct rl_ent {
	const char *key;
	long long last_mono_ms;
};

static struct rl_ent rl_tab[RL_MAX];

int aip_warn_ratelimit(const char *key, long long cooldown_ms,
		       const char *fmt, ...)
{
	long long now = aip_now_mono_ms();
	struct rl_ent *slot = NULL;
	va_list ap;

	for (int i = 0; i < RL_MAX; i++) {
		if (rl_tab[i].key == key) {
			slot = &rl_tab[i];
			break;
		}
		if (!slot && rl_tab[i].key == NULL)
			slot = &rl_tab[i];
	}
	if (slot && slot->key == key &&
	    now - slot->last_mono_ms < cooldown_ms)
		return 0;
	if (slot) {
		slot->key = key;
		slot->last_mono_ms = now;
	}
	fputs("aipd: ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	return 1;
}

/* ---- 原子写（tmp+rename） ---- */

int aip_write_file_atomic(const char *path, const char *data, size_t len)
{
	char tmp[600];
	int fd;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return -1;
	if (len && write(fd, data, len) != (ssize_t)len) {
		close(fd);
		unlink(tmp);
		return -1;
	}
	if (fsync(fd) != 0) {
		close(fd);
		unlink(tmp);
		return -1;
	}
	close(fd);
	if (rename(tmp, path) != 0) {
		unlink(tmp);
		return -1;
	}
	return 0;
}

/* ---- 单实例 lease ---- */

int aip_acquire_lease(const struct aip_conf *c, int *lock_fd)
{
	int fd = open(c->lock_file, O_RDWR | O_CREAT | O_CLOEXEC, 0644);

	if (fd < 0) {
		aip_log("FATAL: open %s: %s", c->lock_file, strerror(errno));
		return -1;
	}
	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		if (errno == EWOULDBLOCK) {
			char buf[32] = "";
			ssize_t r = pread(fd, buf, sizeof(buf) - 1, 0);

			if (r > 0)
				buf[r] = '\0';
			aip_log("FATAL: another aipd holds %s (pid=%s) — "
				"single instance (lease), exiting",
				c->lock_file, r > 0 ? buf : "?");
		} else {
			aip_log("FATAL: flock %s: %s", c->lock_file,
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
			aip_log("FATAL: write lock file: %s",
				strerror(errno));
			close(fd);
			return -1;
		}
	}
	*lock_fd = fd;
	{
		FILE *pf = fopen(c->pid_file, "w");

		if (pf) {
			fprintf(pf, "%d\n", (int)getpid());
			fclose(pf);
		} else {
			aip_warn_ratelimit("pidfile", RL_COOLDOWN_MS,
					   "pid file %s: %s (continuing)",
					   c->pid_file, strerror(errno));
		}
	}
	return 0;
}

void aip_release_lease(const struct aip_conf *c, int lock_fd)
{
	unlink(c->pid_file);
	if (lock_fd >= 0) {
		flock(lock_fd, LOCK_UN);
		close(lock_fd);
	}
}

/* ---- stats ---- */

void aip_stats_init(struct aip_stats *st, const struct aip_conf *c,
		    const char *conf_path)
{
	memset(st, 0, sizeof(*st));
	st->started_mono_ms = aip_now_mono_ms();
	st->started_real_ms = aip_now_real_ms();
	st->pid = (int)getpid();
	snprintf(st->conf_path, sizeof(st->conf_path), "%s", conf_path);
	snprintf(st->feat_source, sizeof(st->feat_source), "%s",
		 c->feat_source == 1 ? "mock" : "map35");
	st->table_sha_ok = 1;
	snprintf(st->canary_table, sizeof(st->canary_table), "builtin");
}

void aip_stats_render(const struct aip_stats *st, FILE *out)
{
	fprintf(out, "pid=%d\n", st->pid);
	fprintf(out, "uptime_ms=%lld\n",
		aip_now_mono_ms() - st->started_mono_ms);
	fprintf(out, "conf_path=%s\n", st->conf_path);
	fprintf(out, "feat_source=%s\n", st->feat_source);
	fprintf(out, "heartbeat_ts_ms=%lld\n", st->heartbeat_ts_ms);
	fprintf(out, "polls=%lld\n", st->polls);
	fprintf(out, "feat_ok=%lld\n", st->feat_ok);
	fprintf(out, "feat_errors=%lld\n", st->feat_errors);
	fprintf(out, "feat_stale=%lld\n", st->feat_stale);
	fprintf(out, "feat_bad_lines=%lld\n", st->feat_bad_lines);
	fprintf(out, "feat_empty=%lld\n", st->feat_empty);
	fprintf(out, "decisions=%lld\n", st->decisions);
	fprintf(out, "decision_hits=%lld\n", st->decision_hits);
	fprintf(out, "decisions_stale=%lld\n", st->decisions_stale);
	fprintf(out, "cmp_total=%lld\n", st->cmp_total);
	fprintf(out, "cmp_mismatch=%lld\n", st->cmp_mismatch);
	fprintf(out, "mismatch_pct=%.2f\n", st->mismatch_pct);
	fprintf(out, "shadow_rows=%lld\n", st->shadow_rows);
	fprintf(out, "shadow_files=%lld\n", st->shadow_files);
	fprintf(out, "shadow_errors=%lld\n", st->shadow_errors);
	fprintf(out, "shadow_flushes=%lld\n", st->shadow_flushes);
	fprintf(out, "table_sha_ok=%d\n", st->table_sha_ok);
	fprintf(out, "table_ver=%lld\n", st->table_ver);
	fprintf(out, "table_rules=%lld\n", st->table_rules);
	/* M2 §6 固定行序尾部（canary_* 11 字段） */
	fprintf(out, "canary_reg_ok=%lld\n", st->canary_reg_ok);
	fprintf(out, "canary_dispatched=%lld\n", st->canary_dispatched);
	fprintf(out, "canary_confirmed=%lld\n", st->canary_confirmed);
	fprintf(out, "canary_rolled_back=%lld\n", st->canary_rolled_back);
	fprintf(out, "canary_errors=%lld\n", st->canary_errors);
	fprintf(out, "canary_skip_stale=%lld\n", st->canary_skip_stale);
	fprintf(out, "canary_skip_busy=%lld\n", st->canary_skip_busy);
	fprintf(out, "canary_skip_interval=%lld\n", st->canary_skip_interval);
	fprintf(out, "canary_ab_total=%lld\n", st->canary_ab_total);
	fprintf(out, "canary_ab_mismatch=%lld\n", st->canary_ab_mismatch);
	fprintf(out, "canary_table=%s\n", st->canary_table);
}

int aip_stats_write_file(const struct aip_stats *st, const char *path)
{
	char *buf = NULL;
	size_t sz = 0;
	FILE *ms = open_memstream(&buf, &sz);
	int rc;

	if (!ms)
		return -1;
	aip_stats_render(st, ms);
	fclose(ms);			/* flush + NUL 终结 */
	if (!buf)
		return -1;
	rc = aip_write_file_atomic(path, buf, sz);
	free(buf);
	return rc;
}
