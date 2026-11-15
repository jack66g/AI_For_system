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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "aistreamd/as_parquet.h"
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
	s->retention_days = c->parquet_retention_days;
	s->cur_retention_days = c->curated_retention_days;
	s->cur_max_gb = c->curated_max_gb;
	for (int i = 0; i < c->n_cat_retention && i < AS_CAT_RET_MAX; i++) {
		/* 匿名结构体三处定义互异 → 逐字段拷贝 */
		snprintf(s->cat_ret[i].cat, sizeof(s->cat_ret[0].cat),
			 "%s", c->cat_retention[i].cat);
		s->cat_ret[i].days = c->cat_retention[i].days;
	}
	s->n_cat_ret = c->n_cat_retention;
	s->stats = st;
	s->enabled = 1;
	if (as_pq_ensure_root(s->root) != 0) {
		as_log("FATAL: parquet ensure_root %s: %s", s->root,
		       strerror(errno));
		return -1;
	}
	as_log("parquet sink on: dir=%s flush=%llds/%lldrows max=%lldGB "
	       "ttl=%lldd cur=%lldd/%lldGB cat_ov=%d "
	       "btime=%lld (event_type=0 标记 aistreamd 归一化行)",
	       s->root, s->flush_sec, s->flush_rows, s->max_gb,
	       s->retention_days, s->cur_retention_days, s->cur_max_gb,
	       s->n_cat_ret, (long long)s->btime);
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
	row->trace_hi = (int64_t)ev->trace_hi;
	row->trace_lo = (int64_t)ev->trace_lo;
	/* L1 v3：评分结果透传（挂点已回填 ev；未评=0） */
	row->value = ev->value;
	row->vflags = ev->vflags;
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

/* L1 棒②：curated 天目录内布局文件 = telemetry 形态 <cat>_<seq>.parquet
 * ∪ decisions 形态 decisions.parquet（棒① 镜像两种都写，as_parquet.c
 * write_tel_table/write_dec_table mid="" 路） */
static int is_curated_file(const char *nm)
{
	return is_rotated(nm) || is_dec_file(nm);
}

static int wl_dec(const char *nm)
{
	return is_dec_file(nm);
}

static int wl_tel(const char *nm)
{
	return is_rotated(nm);
}

static int wl_curated(const char *nm)
{
	return is_curated_file(nm);
}

/* 目录内是否全部为布局文件（决定该天目录可否整目录删）；
 * 目录不存在视作"空=可删"。L1 棒②：判定函数参数化（curated 层
 * 复用同一机制，白名单=is_curated_file）。 */
static int dir_all_layout_ok(const char *dir, int (*ok)(const char *))
{
	DIR *d = opendir(dir);
	struct dirent *e;
	int all = 1;

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
				all = 0;	/* 子目录/不可 stat：异物 */
				break;
			}
		}
		if (ok(e->d_name))
			continue;
		all = 0;
		break;
	}
	closedir(d);
	return all;
}

static int dir_all_layout(const char *dir, int decisions)
{
	return dir_all_layout_ok(dir, decisions ? wl_dec : wl_tel);
}

static long long dir_layout_bytes_ok(const char *dir,
				     int (*ok)(const char *))
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
		if (!ok(e->d_name))
			continue;
		snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
		if (stat(full, &sb) == 0)
			sum += (long long)sb.st_size;
	}
	closedir(d);
	return sum;
}

static long long dir_layout_bytes(const char *dir, int decisions)
{
	return dir_layout_bytes_ok(dir, decisions ? wl_dec : wl_tel);
}

/* 删除目录内布局文件（journal 逐文件列名台账）；返回删除字节数 */
static long long purge_layout_files_ok(const char *dir,
				       int (*ok)(const char *),
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
		if (!ok(e->d_name))
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

static long long purge_layout_files(const char *dir, int decisions,
				    struct as_stats *st)
{
	return purge_layout_files_ok(dir, decisions ? wl_dec : wl_tel, st);
}

/* L1 棒②："YYYY-MM-DD" → 相对儒略日（Howard Hinnant days_from_civil；
 * 负值=公元前）；非法名返回 LLONG_MIN 哨兵（调用方 age 计算自然不
 * 命中任何删除条件——保守保留）。 */
static long long day_epoch(const char *s)
{
	int y, m, d;

	if (strlen(s) != 10 || s[4] != '-' || s[7] != '-' ||
	    sscanf(s, "%d-%d-%d", &y, &m, &d) != 3)
		return (long long)LLONG_MIN;
	{
		long long yy = y - (m <= 2);
		long long era = (yy >= 0 ? yy : yy - 399) / 400;
		unsigned yoe = (unsigned)(yy - era * 400);
		unsigned doy = (153u * (m + (m > 2 ? -3 : 9)) + 2u) / 5u
			       + (unsigned)d - 1u;
		unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;

		return era * 146097LL + (long long)doe - 719468LL;
	}
}

/* L1 棒②：telemetry 天目录内被覆盖 cat（RETENTION_DAYS_<CAT>）命中时
 * 的最长覆盖天数（目录级粒度——设计 DATA-L1-DESIGN §2 裁定：取更长
 * 保留，宁留勿删；同日 decisions 子目录随整体原子保留）。 */
static long long dir_cat_override(const char *dir,
				  const struct as_pq_retain_cfg *cfg)
{
	long long best = 0;

	for (int i = 0; i < cfg->n_cat_ret && i < AS_CAT_RET_MAX; i++) {
		DIR *d = opendir(dir);
		struct dirent *e;

		if (!d)
			continue;
		while ((e = readdir(d)) != NULL) {
			const char *u = strrchr(e->d_name, '_');
			size_t cl;
			char cat[40];

			if (!u || !is_rotated(e->d_name))
				continue;
			cl = (size_t)(u - e->d_name);
			if (cl == 0 || cl >= sizeof(cat))
				continue;
			memcpy(cat, e->d_name, cl);
			cat[cl] = '\0';
			if (strcmp(cat, cfg->cat_ret[i].cat) == 0 &&
			    cfg->cat_ret[i].days > best)
				best = cfg->cat_ret[i].days;
		}
		closedir(d);
	}
	return best;
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

/* L1 棒②：单子目录版（curated 层用：<croot>/ 下直接天目录） */
static int collect_days_one(const char *dir, char days[][16], int max)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	int n = 0;

	if (!d)
		return 0;
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

/* 保留策略（flush 后调用；单测可直调：手工造 sink 状态）。
 * L1 棒② 三层核心（DATA-L1-DESIGN §2）：
 *   raw ① TTL 先（time：age>ttl 删最老优先；per-cat 目录级覆盖取
 *        更长——宁留勿删；含异物目录整跳；当天永不删）
 *   raw ② 体量预算后（size：历史语义原样——超 PARQUET_MAX_GB 删最老
 *        可整删天目录）
 *   curated 独立层（TTL+预算均独立；白名单=is_curated_file；当天
 *        永不删；cur_max_gb<0=整层跳过）
 * 删除即 journal 列名台账（含原因 ttl/size）；动过才重建对应 index。
 * 计数记 pq.retained_*（链级统一账目）。 */
void as_pq_retain_root_cfg(const char *root,
			   const struct as_pq_retain_cfg *cfg,
			   int64_t btime, struct as_stats *st)
{
	char today[11];
	long long today_e;
	int raw_touched = 0;

	as_pq_day_from_ts(0, btime, today);
	today_e = day_epoch(today);

	/* ---- raw ① TTL（time 先） ---- */
	if (cfg->ttl_days > 0) {
		char (*days)[16] = malloc(512 * 16);

		if (days) {
			int ndays = collect_days(root, days, 512);

			for (int i = 0; i < ndays; i++) {
				char td[1024], dd[1024];
				long long age, eff, ov;

				if (strcmp(days[i], today) == 0)
					continue;	/* 当天永不删 */
				age = today_e - day_epoch(days[i]);
				if (age <= cfg->ttl_days)
					continue;
				snprintf(td, sizeof(td),
					 "%s/telemetry/%s", root, days[i]);
				ov = dir_cat_override(td, cfg);
				eff = cfg->ttl_days > ov ? cfg->ttl_days : ov;
				if (age <= eff) {
					if (ov > cfg->ttl_days)
						as_log("parquet retain: "
						       "keep day %s "
						       "(cat_override "
						       "%lldd)", days[i], ov);
					continue;
				}
				snprintf(dd, sizeof(dd),
					 "%s/decisions/%s", root, days[i]);
				if (!(dir_all_layout(td, 0) &&
				      dir_all_layout(dd, 1))) {
					as_log("parquet retain: skip day "
					       "%s (non-layout file present"
					       ", ttl)", days[i]);
					continue;
				}
				as_log("parquet retain: purging day %s "
				       "(ttl age %lldd > %lldd)",
				       days[i], age, eff);
				purge_layout_files(td, 0, st);
				purge_layout_files(dd, 1, st);
				rmdir_if_empty(td);
				rmdir_if_empty(dd);
				raw_touched = 1;
			}
			free(days);
		}
	}

	/* ---- raw ② 体量预算（size 后；历史语义原样） ---- */
	{
		long long budget = cfg->max_gb * 1024LL * 1024LL * 1024LL;
		long long total = 0;
		int guard = 0;

		/* 总量 = telemetry/decisions 天目录内布局文件 + index */
		{
			static const char *subs[2] = { "telemetry",
						       "decisions" };

			for (int i = 0; i < 2; i++) {
				char sub[512];
				DIR *d;
				struct dirent *e;

				snprintf(sub, sizeof(sub), "%s/%s", root,
					 subs[i]);
				d = opendir(sub);
				if (!d)
					continue;
				while ((e = readdir(d)) != NULL) {
					char dd[1024];

					if (e->d_name[0] == '.' ||
					    strlen(e->d_name) != 10)
						continue;
					snprintf(dd, sizeof(dd), "%s/%s",
						 sub, e->d_name);
					total += dir_layout_bytes(dd, i == 1);
				}
				closedir(d);
			}
			{
				struct stat sb;
				char ip[1024];

				snprintf(ip, sizeof(ip),
					 "%s/telemetry/index.parquet", root);
				if (stat(ip, &sb) == 0)
					total += (long long)sb.st_size;
			}
		}
		if (total > budget) {
			char (*days)[16] = malloc(512 * 16);

			if (days) {
				int ndays = collect_days(root, days, 512);

				while (total > budget && guard++ < 512) {
					int picked = -1;

					for (int i = 0; i < ndays; i++) {
						char td[1024], dd[1024];

						if (days[i][0] == '\0' ||
						    strcmp(days[i], today) == 0)
							continue;
						snprintf(td, sizeof(td),
							 "%s/telemetry/%s",
							 root, days[i]);
						snprintf(dd, sizeof(dd),
							 "%s/decisions/%s",
							 root, days[i]);
						if (dir_all_layout(td, 0) &&
						    dir_all_layout(dd, 1)) {
							picked = i;
							break;
						}
						as_log("parquet retain: skip "
						       "day %s (non-layout "
						       "file present, kept)",
						       days[i]);
					}
					if (picked < 0) {
						as_warn_ratelimit(
							"pq-retain", 600000,
							"parquet over budget "
							"(%lld>%lld bytes) "
							"but no fully-"
							"deletable day dir",
							total, budget);
						break;
					}
					{
						char td[1024], dd[1024];
						long long freed = 0;

						as_log("parquet retain: "
						       "purging day %s "
						       "(over %lldGB "
						       "budget)",
						       days[picked],
						       cfg->max_gb);
						snprintf(td, sizeof(td),
							 "%s/telemetry/%s",
							 root, days[picked]);
						snprintf(dd, sizeof(dd),
							 "%s/decisions/%s",
							 root, days[picked]);
						freed += purge_layout_files(
							td, 0, st);
						freed += purge_layout_files(
							dd, 1, st);
						rmdir_if_empty(td);
						rmdir_if_empty(dd);
						/* 出候选（防空转重选） */
						days[picked][0] = '\0';
						if (freed == 0)
							break;
						total -= freed;
						raw_touched = 1;
					}
				}
				free(days);
			}
		}
	}

	/* raw 层动过 → 即时重建 index（下轮 flush 亦会重建） */
	if (raw_touched) {
		long sk = 0;

		as_pq_update_index(root, &sk);
	}

	/* ---- curated 独立层（TTL+预算独立；cur_max_gb<0=跳过） ---- */
	if (cfg->cur_max_gb >= 0) {
		char croot[512];
		struct stat sb;

		snprintf(croot, sizeof(croot), "%s/curated", root);
		if (stat(croot, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			int cur_touched = 0;

			/* ① TTL */
			if (cfg->cur_ttl_days > 0) {
				char (*days)[16] = malloc(512 * 16);

				if (days) {
					int ndays = collect_days_one(croot,
								     days,
								     512);

					for (int i = 0; i < ndays; i++) {
						char sd[1024];
						long long age;

						if (strcmp(days[i], today)
						    == 0)
							continue;
						age = today_e
						      - day_epoch(days[i]);
						if (age <= cfg->cur_ttl_days)
							continue;
						snprintf(sd, sizeof(sd),
							 "%s/%s", croot,
							 days[i]);
						if (!dir_all_layout_ok(
							    sd, wl_curated)) {
							as_log("parquet "
							       "retain: skip "
							       "curated day %s "
							       "(non-layout "
							       "file present)",
							       days[i]);
							continue;
						}
						as_log("parquet retain: "
						       "purging curated day "
						       "%s (ttl age %lldd > "
						       "%lldd)",
						       days[i], age,
						       cfg->cur_ttl_days);
						purge_layout_files_ok(
							sd, wl_curated, st);
						rmdir_if_empty(sd);
						cur_touched = 1;
					}
					free(days);
				}
			}
			/* ② 体量预算（curated/index.parquet 计入） */
			{
				long long budget = cfg->cur_max_gb *
					1024LL * 1024LL * 1024LL;
				long long total = 0;
				int guard = 0;

				{
					DIR *d = opendir(croot);
					struct dirent *e;

					if (d) {
						while ((e = readdir(d))
						       != NULL) {
							char sd[1024];

							if (e->d_name[0]
							    == '.' ||
							    strlen(e->d_name)
							    != 10)
								continue;
							snprintf(sd,
								 sizeof(sd),
								 "%s/%s",
								 croot,
								 e->d_name);
							total += dir_layout_bytes_ok(
								sd, wl_curated);
						}
						closedir(d);
					}
				}
				{
					char ip[1024];

					snprintf(ip, sizeof(ip),
						 "%s/index.parquet", croot);
					if (stat(ip, &sb) == 0)
						total += (long long)
							sb.st_size;
				}
				if (total > budget) {
					char (*days)[16] = malloc(512 * 16);

					if (days) {
						int ndays = collect_days_one(
							croot, days, 512);

						while (total > budget &&
						       guard++ < 512) {
							int picked = -1;

							for (int i = 0;
							     i < ndays;
							     i++) {
								char sd[1024];

								if (days[i][0]
								    == '\0' ||
								    strcmp(days[i],
									   today)
								    == 0)
									continue;
								snprintf(sd,
									 sizeof(sd),
									 "%s/%s",
									 croot,
									 days[i]);
								if (dir_all_layout_ok(
									sd,
									wl_curated)) {
									picked = i;
									break;
								}
								as_log("parquet "
								       "retain: "
								       "skip "
								       "curated "
								       "day %s "
								       "(non-"
								       "layout, "
								       "kept)",
								       days[i]);
							}
							if (picked < 0) {
								as_warn_ratelimit(
									"pq-retain",
									600000,
									"curated over budget "
									"(%lld>%lld) but no "
									"fully-deletable "
									"day dir",
									total,
									budget);
								break;
							}
							{
								char sd[1024];
								long long freed;

								snprintf(sd,
									 sizeof(sd),
									 "%s/%s",
									 croot,
									 days[picked]);
								as_log("parquet "
								       "retain: "
								       "purging "
								       "curated "
								       "day %s "
								       "(over "
								       "%lldGB "
								       "budget)",
								       days[picked],
								       cfg->cur_max_gb);
								freed = purge_layout_files_ok(
									sd,
									wl_curated,
									st);
								rmdir_if_empty(sd);
								days[picked][0] = '\0';
								if (freed == 0)
									break;
								total -= freed;
								cur_touched = 1;
							}
						}
						free(days);
					}
				}
			}
			if (cur_touched) {
				long sk = 0;

				as_pq_update_index_curated(croot, &sk);
			}
		}
	}
}

/* 旧签名包裹（T8 遗留接线：as_decisions 落盘后共用）——只做 raw
 * 预算，行为与历史一致（TTL 关、curated 层跳过——curated 保留由
 * sink 主路径负责）。 */
void as_pq_retain_root(const char *root, long long max_gb, int64_t btime,
		       struct as_stats *st)
{
	struct as_pq_retain_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.max_gb = max_gb;
	cfg.cur_max_gb = -1;
	as_pq_retain_root_cfg(root, &cfg, btime, st);
}

void as_pq_retain(struct as_pq_sink *s)
{
	struct as_pq_retain_cfg cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.max_gb = s->max_gb;
	cfg.ttl_days = s->retention_days;
	cfg.cur_ttl_days = s->cur_retention_days;
	cfg.cur_max_gb = s->cur_max_gb;
	for (int i = 0; i < s->n_cat_ret && i < AS_CAT_RET_MAX; i++) {
		snprintf(cfg.cat_ret[i].cat, sizeof(cfg.cat_ret[0].cat),
			 "%s", s->cat_ret[i].cat);
		cfg.cat_ret[i].days = s->cat_ret[i].days;
	}
	cfg.n_cat_ret = s->n_cat_ret;
	as_pq_retain_root_cfg(s->root, &cfg, s->btime, s->stats);
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
			r->trace_hi = b->trace_hi;
			r->trace_lo = b->trace_lo;
			r->value = b->value;		/* L1 v3 尾 2 列 */
			r->flags = b->vflags;
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
