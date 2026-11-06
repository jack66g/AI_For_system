/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_pq_sink.c - aistreamd 事件 → Parquet telemetry 落盘（T8）
 *
 * 映射/节流/保留策略规格见 as_pq_sink.h。实现要点：
 *   - 流→category 映射表（静态，六路全映射到既有 CAT_NAMES 条目，
 *     不发明新类别号）：event→18(ai) proc→6(process) net→4(net)
 *     uevent→16(hw) nflog→8(security) taskstats→1(sched)
 *   - flush 失败：该批行丢弃（计数 parquet.errors + journal 限频告警）
 *     ——不重试不堆积（缓冲上界=FLUSH_ROWS 行，有界）
 *   - 保留策略每 flush 后跑一次；只删布局文件，删前 journal 列名台账
 */
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "as_parquet.h"
#include "as_pq_sink.h"
#include "as_stats.h"
#include "as_util.h"

/* 流下标 → ai_category（顺序=as_event.c stream_names：
 * 0 event 1 proc 2 net 3 uevent 4 nflog 5 taskstats） */
static const int8_t stream_cat[AS_NSTREAMS] = {
	18,	/* event     → ai */
	6,	/* proc      → process */
	4,	/* net       → net */
	16,	/* uevent    → hw */
	8,	/* nflog     → security */
	1,	/* taskstats → sched */
};

static int sev_num(const char *s)
{
	if (s && strcmp(s, "error") == 0)
		return 2;
	if (s && strcmp(s, "warn") == 0)
		return 1;
	return 0;
}

int as_pq_sink_init(struct as_pq_sink *s, const struct as_conf *c,
		    struct as_stats *st)
{
	memset(s, 0, sizeof(*s));
	s->btime = as_pq_btime();
	if (st) {
		st->pq.enabled = c->parquet_enabled;
		st->pq.btime = s->btime;
	}
	if (!c->parquet_enabled)
		return 0;		/* 默认关=零影响：不建目录不分配 */
	snprintf(s->root, sizeof(s->root), "%s", c->parquet_dir);
	s->flush_sec = c->parquet_flush_sec;
	s->flush_rows = c->parquet_flush_rows;
	s->max_gb = c->parquet_max_gb;
	s->stats = st;
	s->enabled = 1;
	if (as_pq_ensure_root(s->root) != 0) {
		as_log("FATAL: parquet ensure_root %s: %s", s->root,
		       strerror(errno));
		return -1;
	}
	as_log("parquet sink on: dir=%s flush=%llds/%lldrows max=%lldGB "
	       "btime=%lld (event_type=0 标记 aistreamd 归一化行)",
	       s->root, s->flush_sec, s->flush_rows, s->max_gb,
	       (long long)s->btime);
	return 0;
}

void as_pq_sink_feed(struct as_pq_sink *s, const struct as_event *ev)
{
	struct as_pq_brow *row;
	size_t len;

	if (!s->enabled || !ev)
		return;
	if (ev->stream_idx < 0 || ev->stream_idx >= AS_NSTREAMS)
		return;
	if (s->n == s->cap) {
		size_t cap = s->cap ? s->cap * 2 : 64;
		struct as_pq_brow *nb = realloc(s->buf,
						cap * sizeof(*nb));

		if (!nb) {
			/* 缓冲分配失败：丢本行并计数（诚实降级） */
			as_warn_ratelimit("pq-feed", 60000,
					  "parquet buffer alloc failed, "
					  "row dropped");
			return;
		}
		s->buf = nb;
		s->cap = cap;
	}
	row = &s->buf[s->n++];
	memset(row, 0, sizeof(*row));
	/* 墙钟 ms → 单调 ns（REF 遥测语义；btime 缺失时存墙钟 ns，日界
	 * 退"今天"——见 as_pq_day_from_ts） */
	if (s->btime > 0)
		row->ts_ns = (ev->ts_real_ms - s->btime * 1000) * 1000000LL;
	else
		row->ts_ns = ev->ts_real_ms * 1000000LL;
	row->pid = ev->pid;
	row->category = stream_cat[ev->stream_idx];
	row->severity = (int8_t)sev_num(ev->severity);
	len = strlen(ev->line);
	if (len >= sizeof(row->data))
		len = sizeof(row->data) - 1;
	memcpy(row->data, ev->line, len);
	row->data[len] = '\0';
	row->dlen = (uint16_t)len;
	if (s->stats) {
		s->stats->pq.fed++;
		s->stats->pq.buffered = (long long)s->n;
	}
}

/* ---- 保留策略（PARQUET_MAX_GB；只删布局文件；journal 列名台账） ---- */

/* telemetry 天目录内布局文件：<前缀>_<纯数字>.parquet
 * （数字区 = 最后一个 '_' 到 .parquet 前，全数字且至少 1 位） */
static int is_rotated(const char *nm)
{
	size_t n = strlen(nm);
	const char *lastu = NULL, *q, *digend;

	if (n < 12 || strcmp(nm + n - 8, ".parquet") != 0)
		return 0;
	for (q = nm; *q; q++)
		if (*q == '_')
			lastu = q;
	if (!lastu)
		return 0;
	digend = nm + n - 8;
	for (q = lastu + 1; q < digend; q++)
		if (*q < '0' || *q > '9')
			return 0;
	return q > lastu + 1;
}

/* decisions 天目录内布局文件：decisions.parquet / chains_*.parquet */
static int is_dec_file(const char *nm)
{
	size_t n = strlen(nm);

	if (strcmp(nm, "decisions.parquet") == 0)
		return 1;
	if (strncmp(nm, "chains_", 7) == 0 && n > 15 &&
	    strcmp(nm + n - 8, ".parquet") == 0)
		return 1;
	return 0;
}

/* 目录内是否全部为布局文件（决定该天目录可否整目录删）；
 * 目录不存在视作"空=可删" */
static int dir_all_layout(const char *dir, int decisions)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	int ok = 1;

	if (!d)
		return 1;		/* 不存在：无内容 */
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.')
			continue;
		{
			struct stat sb;
			char full[1400];

			snprintf(full, sizeof(full), "%s/%s", dir,
				 e->d_name);
			if (stat(full, &sb) != 0 || !S_ISREG(sb.st_mode)) {
				ok = 0;		/* 子目录/不可 stat：异物 */
				break;
			}
		}
		if (decisions ? is_dec_file(e->d_name) : is_rotated(e->d_name))
			continue;
		ok = 0;
		break;
	}
	closedir(d);
	return ok;
}

static long long dir_layout_bytes(const char *dir, int decisions)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	long long sum = 0;

	if (!d)
		return 0;
	while ((e = readdir(d)) != NULL) {
		struct stat sb;
		char full[1400];

		if (e->d_name[0] == '.')
			continue;
		if (decisions ? !is_dec_file(e->d_name)
			      : !is_rotated(e->d_name))
			continue;
		snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
		if (stat(full, &sb) == 0)
			sum += (long long)sb.st_size;
	}
	closedir(d);
	return sum;
}

/* 删除目录内布局文件（journal 逐文件列名台账）；返回删除字节数 */
static long long purge_layout_files(const char *dir, int decisions,
				    struct as_stats *st)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	long long sum = 0;

	if (!d)
		return 0;
	while ((e = readdir(d)) != NULL) {
		struct stat sb;
		char full[1400];

		if (e->d_name[0] == '.')
			continue;
		if (decisions ? !is_dec_file(e->d_name)
			      : !is_rotated(e->d_name))
			continue;
		snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
		if (stat(full, &sb) == 0 && S_ISREG(sb.st_mode) &&
		    unlink(full) == 0) {
			as_log("parquet retain: deleted %s (%lld bytes)",
			       full, (long long)sb.st_size);
			sum += (long long)sb.st_size;
			if (st) {
				st->pq.retained_files++;
				st->pq.retained_bytes +=
					(long long)sb.st_size;
			}
		}
	}
	closedir(d);
	return sum;
}

static void rmdir_if_empty(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	int empty = 1;

	if (!d)
		return;
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.')
			continue;
		empty = 0;
		break;
	}
	closedir(d);
	if (empty)
		rmdir(dir);
}

/* 收集 root/telemetry + root/decisions 下 distinct 10 字符天目录名，
 * 升序（最老在前）；返回个数 */
static int collect_days(const char *root, char days[][16], int max)
{
	static const char *subs[2] = { "telemetry", "decisions" };
	int n = 0;

	for (int s = 0; s < 2; s++) {
		char sub[512];
		DIR *d;
		struct dirent *e;

		snprintf(sub, sizeof(sub), "%s/%s", root, subs[s]);
		d = opendir(sub);
		if (!d)
			continue;
		while ((e = readdir(d)) != NULL && n < max) {
			int dup = 0;

			if (e->d_name[0] == '.' || strlen(e->d_name) != 10)
				continue;
			for (int i = 0; i < n; i++)
				if (strcmp(days[i], e->d_name) == 0)
					dup = 1;
			if (!dup)
				snprintf(days[n++], 16, "%s", e->d_name);
		}
		closedir(d);
	}
	for (int i = 1; i < n; i++) {	/* 插入排序=稳定升序 */
		char cur[16];
		int j = i;

		snprintf(cur, sizeof(cur), "%s", days[i]);
		while (j > 0 && strcmp(days[j - 1], cur) > 0) {
			snprintf(days[j], 16, "%s", days[j - 1]);
			j--;
		}
		snprintf(days[j], 16, "%s", cur);
	}
	return n;
}

/* 保留策略（flush 后调用；单测可直调：手工造 sink 状态） */
void as_pq_retain(struct as_pq_sink *s)
{
	const char *root = s->root;
	char today[11];
	char (*days)[16];
	int ndays;
	long long budget = s->max_gb * 1024LL * 1024LL * 1024LL;
	long long total = 0;
	int guard = 0;

	/* 总量 = telemetry/decisions 天目录内布局文件 + index.parquet */
	{
		static const char *subs[2] = { "telemetry", "decisions" };

		for (int i = 0; i < 2; i++) {
			char sub[512];
			DIR *d;
			struct dirent *e;

			snprintf(sub, sizeof(sub), "%s/%s", root, subs[i]);
			d = opendir(sub);
			if (!d)
				continue;
			while ((e = readdir(d)) != NULL) {
				char dd[1024];

				if (e->d_name[0] == '.' ||
				    strlen(e->d_name) != 10)
					continue;
				snprintf(dd, sizeof(dd), "%s/%s", sub,
					 e->d_name);
				total += dir_layout_bytes(dd, i == 1);
			}
			closedir(d);
		}
		{
			struct stat sb;
			char ip[1024];

			snprintf(ip, sizeof(ip), "%s/telemetry/index.parquet",
				 root);
			if (stat(ip, &sb) == 0)
				total += (long long)sb.st_size;
		}
	}
	if (total <= budget)
		return;

	/* 当天（UTC）目录永不删（ts=0 → btime 口径的今天=运行日） */
	as_pq_day_from_ts(0, s->btime, today);
	days = malloc(512 * 16);
	if (!days)
		return;
	ndays = collect_days(root, days, 512);

	while (total > budget && guard++ < 512) {
		int picked = -1;

		for (int i = 0; i < ndays; i++) {
			char td[1024], dd[1024];

			if (days[i][0] == '\0' || strcmp(days[i], today) == 0)
				continue;
			snprintf(td, sizeof(td), "%s/telemetry/%s", root,
				 days[i]);
			snprintf(dd, sizeof(dd), "%s/decisions/%s", root,
				 days[i]);
			if (dir_all_layout(td, 0) && dir_all_layout(dd, 1)) {
				picked = i;
				break;
			}
			as_log("parquet retain: skip day %s "
			       "(non-layout file present, kept)", days[i]);
		}
		if (picked < 0) {
			as_warn_ratelimit("pq-retain", 600000,
					  "parquet over budget (%lld>%lld "
					  "bytes) but no fully-deletable "
					  "day dir", total, budget);
			break;
		}
		{
			char td[1024], dd[1024];
			long long freed = 0;

			as_log("parquet retain: purging day %s (over "
			       "%lldGB budget)", days[picked], s->max_gb);
			snprintf(td, sizeof(td), "%s/telemetry/%s", root,
				 days[picked]);
			snprintf(dd, sizeof(dd), "%s/decisions/%s", root,
				 days[picked]);
			freed += purge_layout_files(td, 0, s->stats);
			freed += purge_layout_files(dd, 1, s->stats);
			rmdir_if_empty(td);
			rmdir_if_empty(dd);
			days[picked][0] = '\0';	/* 出候选（防空转重选） */
			if (freed == 0)
				break;
			total -= freed;
		}
	}
	free(days);
	/* 删了天目录后即时重建 index（下轮 flush 亦会重建） */
	{
		long sk = 0;

		as_pq_update_index(root, &sk);
	}
}

void as_pq_sink_flush(struct as_pq_sink *s)
{
	if (!s->enabled)
		return;
	if (s->n == 0)
		return;
	{
		struct pq_tel_row *rows = malloc(s->n * sizeof(*rows));

		if (!rows) {
			as_warn_ratelimit("pq-flush", 60000,
					  "parquet flush alloc failed, "
					  "%zu rows dropped", s->n);
			if (s->stats)
				s->stats->pq.errors += (long long)s->n;
			s->n = 0;
			return;
		}
		for (size_t i = 0; i < s->n; i++) {
			struct pq_tel_row *r = &rows[i];
			struct as_pq_brow *b = &s->buf[i];

			r->ts_ns = b->ts_ns;
			r->pid = b->pid;
			r->tgid = 0;
			r->cpu = 0;
			r->category = b->category;
			r->event_type = 0;
			r->severity = b->severity;
			r->data_len = (int16_t)b->dlen;
			r->data = (const uint8_t *)b->data;
		}
		{
			struct pq_write_stat wst = { 0, 0 };
			int r = as_pq_write_telemetry(s->root, rows, s->n,
						      s->btime, 65536, &wst);

			if (r >= 0) {
				if (s->stats) {
					s->stats->pq.rows_written += r;
					s->stats->pq.files += wst.files;
					s->stats->pq.bytes += wst.bytes;
					s->stats->pq.flushes++;
				}
			} else {
				as_warn_ratelimit("pq-flush", 60000,
						  "parquet write failed, "
						  "%zu rows dropped: %s",
						  s->n, strerror(errno));
				if (s->stats)
					s->stats->pq.errors += (long long)s->n;
			}
		}
		free(rows);
	}
	s->n = 0;
	if (s->stats)
		s->stats->pq.buffered = 0;
	as_pq_retain(s);
}

void as_pq_sink_close(struct as_pq_sink *s)
{
	if (!s->enabled)
		return;
	as_pq_sink_flush(s);
	free(s->buf);
	s->buf = NULL;
	s->cap = 0;
	s->n = 0;
	s->enabled = 0;	/* 幂等 + 防 close 后误用（feed/flush 零操作） */
}
