/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_conf.c - 配置解析（KEY=VALUE，严格校验，坏值拒绝）
 */
#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "as_conf.h"

void as_conf_defaults(struct as_conf *c)
{
	memset(c, 0, sizeof(*c));
	snprintf(c->sme_url, sizeof(c->sme_url), "http://127.0.0.1:8000");
	c->importance = 0.3;
	c->sme_retry_sec = 5;
	c->rate_per_min = 60;
	c->daily_max = 5000;
	c->stream_daily_max = 1000;
	c->dedup_window_ms = 10000;
	c->ring_size = 4096;
	c->enable_event = 1;
	c->enable_proc = 1;
	c->enable_net = 1;
	c->enable_uevent = 1;
	c->enable_nflog = 1;
	c->enable_taskstats = 1;
	c->taskstats_interval_sec = 30;
	c->taskstats_max_pids = 256;
	c->ai_mock_proto = 0;
	c->hotplug_enabled = 0;
	c->hotplug_model[0] = '\0';
	c->hotplug_daily_max = 200;
	c->hotplug_infer_dim = 8;
	c->hotplug_infer_mock = 0;
	snprintf(c->hotplug_log, sizeof(c->hotplug_log),
		 "/var/log/aikernel/hotplug-advisories.jsonl");
	/* T8：Parquet 落盘（默认关——本轮保守） */
	c->parquet_enabled = 0;
	snprintf(c->parquet_dir, sizeof(c->parquet_dir), "/var/lib/aikernel");
	c->parquet_max_gb = 2;
	c->parquet_flush_sec = 30;
	c->parquet_flush_rows = 128;
	/* I-10：outcome 回填器（C3 默认关——设计 §4.5 出厂默认值） */
	c->outcome_enabled = 0;
	c->outcome_window_short_sec = 30;
	c->outcome_window_long_sec = 300;
	c->outcome_grace_sec = 10;
	c->outcome_max_pending = 256;
	c->outcome_decisions_scan_max = 64;
	c->outcome_write_sme = 1;
	c->outcome_auto_rollback = 0;
	/* TEST ONLY（L1 mock 冒烟；生产恒 "/"） */
	snprintf(c->outcome_mock_root, sizeof(c->outcome_mock_root), "/");
	/* T8 遗留接线：decisions 消费（默认关——出厂默认关，ISO 拍板翻） */
	c->decisions_enabled = 0;
	c->decisions_interval_sec = 5;
	c->decisions_scan_max = 4096;
	c->decisions_batch_max = 8192;
	c->decisions_write_sme = 1;
	snprintf(c->decisions_mock_root, sizeof(c->decisions_mock_root), "/");
	/* SENSE 脱敏（多用户前提；默认 off=单用户现状零字节变化——
	 * 设计 SENSE-REDACT-DESIGN §5 出厂默认建议） */
	c->sense_redact_level = 0;	/* 0=off 1=soft 2=strict */
	c->sense_redact_salt[0] = '\0';
	c->stats_interval_sec = 10;
	c->log_debug = 0;
	snprintf(c->stats_file, sizeof(c->stats_file), "/run/aistreamd.stats");
	snprintf(c->pid_file, sizeof(c->pid_file), "/run/aistreamd.pid");
	snprintf(c->lock_file, sizeof(c->lock_file), "/run/aistreamd.lock");
}

static int bad(char *err, size_t cap, int lineno, const char *fmt,
	       const char *a, const char *b)
{
	if (err && cap)
		snprintf(err, cap, "line %d: %s%s%s", lineno, fmt,
			 a ? a : "", b ? b : "");
	return -1;
}

/* str 对 int：整行必须是十进制整数（允许前后空白） */
static int parse_ll(const char *v, long long *out)
{
	char *end;
	long long r;

	while (*v == ' ' || *v == '\t')
		v++;
	errno = 0;
	r = strtoll(v, &end, 10);
	if (errno != 0 || end == v)
		return -1;
	while (*end == ' ' || *end == '\t')
		end++;
	if (*end != '\0')
		return -1;
	*out = r;
	return 0;
}

static int parse_double(const char *v, double *out)
{
	char *end;
	double r;

	while (*v == ' ' || *v == '\t')
		v++;
	errno = 0;
	r = strtod(v, &end);
	if (end == v)
		return -1;
	while (*end == ' ' || *end == '\t')
		end++;
	if (*end != '\0')
		return -1;
	*out = r;
	return 0;
}

/* 键集合（重复键拒绝） */
enum key_id {
	K_SME_URL, K_IMPORTANCE, K_SME_RETRY_SEC,
	K_RATE_PER_MIN, K_DAILY_MAX, K_STREAM_DAILY_MAX, K_DEDUP_WINDOW_MS,
	K_RING_SIZE,
	K_ENABLE_EVENT, K_ENABLE_PROC, K_ENABLE_NET, K_ENABLE_UEVENT,
	K_ENABLE_NFLOG, K_ENABLE_TASKSTATS,
	K_TASKSTATS_INTERVAL_SEC, K_TASKSTATS_MAX_PIDS,
	K_AI_MOCK_PROTO, K_STATS_INTERVAL_SEC, K_LOG_DEBUG,
	K_STATS_FILE, K_PID_FILE, K_LOCK_FILE,
	K_HOTPLUG_ENABLED, K_HOTPLUG_MODEL, K_HOTPLUG_DAILY_MAX,
	K_HOTPLUG_INFER_DIM, K_HOTPLUG_INFER_MOCK, K_HOTPLUG_LOG,
	K_PARQUET_ENABLED, K_PARQUET_DIR, K_PARQUET_MAX_GB,
	K_PARQUET_FLUSH_SEC, K_PARQUET_FLUSH_ROWS,
	K_OUTCOME_ENABLED, K_OUTCOME_WINDOW_SHORT_SEC,
	K_OUTCOME_WINDOW_LONG_SEC, K_OUTCOME_GRACE_SEC,
	K_OUTCOME_MAX_PENDING, K_OUTCOME_DECISIONS_SCAN_MAX,
	K_OUTCOME_WRITE_SME, K_OUTCOME_AUTO_ROLLBACK,
	K_OUTCOME_MOCK_ROOT,
	K_DECISIONS_ENABLED, K_DECISIONS_INTERVAL_SEC,
	K_DECISIONS_SCAN_MAX, K_DECISIONS_BATCH_MAX,
	K_DECISIONS_WRITE_SME, K_DECISIONS_MOCK_ROOT,
	K_SENSE_REDACT, K_SENSE_REDACT_SALT,
	K_MAX
};

static const char *const key_names[K_MAX] = {
	"SME_URL", "IMPORTANCE", "SME_RETRY_SEC",
	"RATE_PER_MIN", "DAILY_MAX", "STREAM_DAILY_MAX", "DEDUP_WINDOW_MS",
	"RING_SIZE",
	"ENABLE_EVENT", "ENABLE_PROC", "ENABLE_NET", "ENABLE_UEVENT",
	"ENABLE_NFLOG", "ENABLE_TASKSTATS",
	"TASKSTATS_INTERVAL_SEC", "TASKSTATS_MAX_PIDS",
	"AI_MOCK_PROTO", "STATS_INTERVAL_SEC", "LOG_DEBUG",
	"STATS_FILE", "PID_FILE", "LOCK_FILE",
	"HOTPLUG_ENABLED", "HOTPLUG_MODEL", "HOTPLUG_DAILY_MAX",
	"HOTPLUG_INFER_DIM", "HOTPLUG_INFER_MOCK", "HOTPLUG_LOG",
	"PARQUET_ENABLED", "PARQUET_DIR", "PARQUET_MAX_GB",
	"PARQUET_FLUSH_SEC", "PARQUET_FLUSH_ROWS",
	"OUTCOME_ENABLED", "OUTCOME_WINDOW_SHORT_SEC",
	"OUTCOME_WINDOW_LONG_SEC", "OUTCOME_GRACE_SEC",
	"OUTCOME_MAX_PENDING", "OUTCOME_DECISIONS_SCAN_MAX",
	"OUTCOME_WRITE_SME", "OUTCOME_AUTO_ROLLBACK",
	"OUTCOME_MOCK_ROOT",
	"DECISIONS_ENABLED", "DECISIONS_INTERVAL_SEC",
	"DECISIONS_SCAN_MAX", "DECISIONS_BATCH_MAX",
	"DECISIONS_WRITE_SME", "DECISIONS_MOCK_ROOT",
	"SENSE_REDACT", "SENSE_REDACT_SALT",
};

static int key_lookup(const char *k)
{
	for (int i = 0; i < K_MAX; i++)
		if (strcmp(k, key_names[i]) == 0)
			return i;
	return -1;
}

int as_conf_load(struct as_conf *c, const char *path, char *err, size_t errcap)
{
	FILE *f;
	char line[1024];
	int lineno = 0;
	int seen[K_MAX];
	char strbuf[3][300];
	int stridx = 0;

	memset(seen, 0, sizeof(seen));
	f = fopen(path, "r");
	if (!f) {
		if (err && errcap)
			snprintf(err, errcap, "open %s: %s", path,
				 strerror(errno));
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		char *eq, *k, *v;
		int id;
		long long n;
		double d;

		lineno++;
		/* 去尾部换行 */
		{
			size_t l = strlen(line);

			while (l > 0 && (line[l - 1] == '\n' ||
					 line[l - 1] == '\r'))
				line[--l] = '\0';
		}
		k = line;
		while (*k == ' ' || *k == '\t')
			k++;
		if (*k == '\0' || *k == '#')
			continue;
		eq = strchr(k, '=');
		if (!eq) {
			fclose(f);
			return bad(err, errcap, lineno,
				   "missing '='", NULL, NULL);
		}
		*eq = '\0';
		{
			char *ke = eq - 1;

			while (ke >= k && (*ke == ' ' || *ke == '\t'))
				*ke-- = '\0';
		}
		v = eq + 1;
		id = key_lookup(k);
		if (id < 0) {
			fclose(f);
			return bad(err, errcap, lineno,
				   "unknown key: ", k, NULL);
		}
		if (seen[id]) {
			fclose(f);
			return bad(err, errcap, lineno,
				   "duplicate key: ", k, NULL);
		}
		seen[id] = 1;

#define NEED_LL(key, lo, hi, dst) do { \
	if (parse_ll(v, &n) != 0 || n < (lo) || n > (hi)) { \
		fclose(f); \
		return bad(err, errcap, lineno, \
			   "bad value for " key " (need int " #lo ".." #hi "): ", v, NULL); \
	} \
	(dst) = n; \
} while (0)

		switch (id) {
		case K_SME_URL:
		case K_STATS_FILE:
		case K_PID_FILE:
		case K_LOCK_FILE:
		case K_HOTPLUG_MODEL:
		case K_HOTPLUG_LOG:
		case K_OUTCOME_MOCK_ROOT:
		case K_DECISIONS_MOCK_ROOT:
		case K_PARQUET_DIR: {
			/* 三个字符串槽循环使用（校验即时完成，不持有引用） */
			char *dst;
			size_t dstcap;

			if (stridx >= 3)
				stridx = 0;
			if (snprintf(strbuf[stridx], sizeof(strbuf[0]), "%s",
				     v) >= (int)sizeof(strbuf[0])) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "value too long: ", k, NULL);
			}
			/* K3d-2 键专用校验（在其字符串槽上就地做） */
			if (id == K_HOTPLUG_MODEL) {
				/* [A-Za-z0-9._-]{0,63}（空=未配置，合法）；
				 * 空白拒绝（内核 model_infer 按空白切词） */
				for (const char *p = v; *p; p++) {
					char ch = *p;

					if (!((ch >= 'a' && ch <= 'z') ||
					      (ch >= 'A' && ch <= 'Z') ||
					      (ch >= '0' && ch <= '9') ||
					      ch == '.' || ch == '_' ||
					      ch == '-')) {
						fclose(f);
						return bad(err, errcap, lineno,
							   "bad HOTPLUG_MODEL "
							   "charset: ", v, NULL);
					}
				}
			}
			if (id == K_HOTPLUG_LOG &&
			    (v[0] != '/' || strstr(v, "..") ||
			     strpbrk(v, " \t"))) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "bad HOTPLUG_LOG (need absolute "
					   "path, no ..): ", v, NULL);
			}
			if (id == K_OUTCOME_MOCK_ROOT &&
			    (v[0] != '/' || strstr(v, "..") ||
			    strpbrk(v, " 	"))) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "bad OUTCOME_MOCK_ROOT (need absolute "
					   "path, no ..): ", v, NULL);
			}
			if (id == K_DECISIONS_MOCK_ROOT &&
			    (v[0] != '/' || strstr(v, "..") ||
			    strpbrk(v, " 	"))) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "bad DECISIONS_MOCK_ROOT (need absolute "
					   "path, no ..): ", v, NULL);
			}
			if (id == K_PARQUET_DIR &&
			    (v[0] != '/' || strstr(v, "..") ||
			     strpbrk(v, " \t"))) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "bad PARQUET_DIR (need absolute "
					   "path, no ..): ", v, NULL);
			}
			if (id == K_SME_URL) {
				dst = c->sme_url;
				dstcap = sizeof(c->sme_url);
			} else if (id == K_STATS_FILE) {
				dst = c->stats_file;
				dstcap = sizeof(c->stats_file);
			} else if (id == K_PID_FILE) {
				dst = c->pid_file;
				dstcap = sizeof(c->pid_file);
			} else if (id == K_HOTPLUG_MODEL) {
				dst = c->hotplug_model;
				dstcap = sizeof(c->hotplug_model);
			} else if (id == K_HOTPLUG_LOG) {
				dst = c->hotplug_log;
				dstcap = sizeof(c->hotplug_log);
			} else if (id == K_OUTCOME_MOCK_ROOT) {
				dst = c->outcome_mock_root;
				dstcap = sizeof(c->outcome_mock_root);
			} else if (id == K_DECISIONS_MOCK_ROOT) {
				dst = c->decisions_mock_root;
				dstcap = sizeof(c->decisions_mock_root);
			} else if (id == K_PARQUET_DIR) {
				dst = c->parquet_dir;
				dstcap = sizeof(c->parquet_dir);
			} else {
				dst = c->lock_file;
				dstcap = sizeof(c->lock_file);
			}
			if (strlen(v) + 1 > dstcap) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "value too long for ", k, NULL);
			}
			snprintf(dst, dstcap, "%s", v);
			stridx++;
			break;
		}
		case K_IMPORTANCE:
			if (parse_double(v, &d) != 0 || d <= 0.0 || d > 1.0) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "bad IMPORTANCE (need 0<x<=1): ",
					   v, NULL);
			}
			c->importance = d;
			break;
		case K_SME_RETRY_SEC:
			NEED_LL("SME_RETRY_SEC", 1, 3600, c->sme_retry_sec);
			break;
		case K_RATE_PER_MIN:
			NEED_LL("RATE_PER_MIN", 1, 1000000, c->rate_per_min);
			break;
		case K_DAILY_MAX:
			NEED_LL("DAILY_MAX", 1, 10000000, c->daily_max);
			break;
		case K_STREAM_DAILY_MAX:
			NEED_LL("STREAM_DAILY_MAX", 1, 10000000,
				c->stream_daily_max);
			break;
		case K_DEDUP_WINDOW_MS:
			NEED_LL("DEDUP_WINDOW_MS", 100, 3600000,
				c->dedup_window_ms);
			break;
		case K_RING_SIZE:
			NEED_LL("RING_SIZE", 1, 1048576, c->ring_size);
			break;
		case K_ENABLE_EVENT:
			NEED_LL("ENABLE_EVENT", 0, 1, c->enable_event);
			break;
		case K_ENABLE_PROC:
			NEED_LL("ENABLE_PROC", 0, 1, c->enable_proc);
			break;
		case K_ENABLE_NET:
			NEED_LL("ENABLE_NET", 0, 1, c->enable_net);
			break;
		case K_ENABLE_UEVENT:
			NEED_LL("ENABLE_UEVENT", 0, 1, c->enable_uevent);
			break;
		case K_ENABLE_NFLOG:
			NEED_LL("ENABLE_NFLOG", 0, 1, c->enable_nflog);
			break;
		case K_ENABLE_TASKSTATS:
			NEED_LL("ENABLE_TASKSTATS", 0, 1, c->enable_taskstats);
			break;
		case K_TASKSTATS_INTERVAL_SEC:
			NEED_LL("TASKSTATS_INTERVAL_SEC", 5, 86400,
				c->taskstats_interval_sec);
			break;
		case K_TASKSTATS_MAX_PIDS:
			NEED_LL("TASKSTATS_MAX_PIDS", 1, 4096,
				c->taskstats_max_pids);
			break;
		case K_AI_MOCK_PROTO:
			/* 只允许 0（真协议）或 2（NETLINK_USERSOCK 测试通道） */
			NEED_LL("AI_MOCK_PROTO", 0, 2, c->ai_mock_proto);
			if (c->ai_mock_proto == 1) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "AI_MOCK_PROTO=1 reserved, use 0 or 2: ",
					   v, NULL);
			}
			break;
		case K_STATS_INTERVAL_SEC:
			NEED_LL("STATS_INTERVAL_SEC", 1, 3600,
				c->stats_interval_sec);
			break;
		case K_LOG_DEBUG:
			NEED_LL("LOG_DEBUG", 0, 1, c->log_debug);
			break;
		case K_HOTPLUG_ENABLED:
			NEED_LL("HOTPLUG_ENABLED", 0, 1, c->hotplug_enabled);
			break;
		case K_HOTPLUG_DAILY_MAX:
			NEED_LL("HOTPLUG_DAILY_MAX", 1, 1000000,
				c->hotplug_daily_max);
			break;
		case K_HOTPLUG_INFER_DIM:
			NEED_LL("HOTPLUG_INFER_DIM", 1, 64,
				c->hotplug_infer_dim);
			break;
		case K_HOTPLUG_INFER_MOCK:
			NEED_LL("HOTPLUG_INFER_MOCK", 0, 1,
				c->hotplug_infer_mock);
			break;
		case K_PARQUET_ENABLED:
			NEED_LL("PARQUET_ENABLED", 0, 1, c->parquet_enabled);
			break;
		case K_PARQUET_MAX_GB:
			NEED_LL("PARQUET_MAX_GB", 1, 1024, c->parquet_max_gb);
			break;
		case K_PARQUET_FLUSH_SEC:
			NEED_LL("PARQUET_FLUSH_SEC", 1, 86400,
				c->parquet_flush_sec);
			break;
		case K_PARQUET_FLUSH_ROWS:
			NEED_LL("PARQUET_FLUSH_ROWS", 1, 65536,
				c->parquet_flush_rows);
			break;
		case K_OUTCOME_ENABLED:
			NEED_LL("OUTCOME_ENABLED", 0, 1, c->outcome_enabled);
			break;
		case K_OUTCOME_WINDOW_SHORT_SEC:
			NEED_LL("OUTCOME_WINDOW_SHORT_SEC", 5, 3600,
				c->outcome_window_short_sec);
			break;
		case K_OUTCOME_WINDOW_LONG_SEC:
			NEED_LL("OUTCOME_WINDOW_LONG_SEC", 30, 86400,
				c->outcome_window_long_sec);
			break;
		case K_OUTCOME_GRACE_SEC:
			NEED_LL("OUTCOME_GRACE_SEC", 0, 600,
				c->outcome_grace_sec);
			break;
		case K_OUTCOME_MAX_PENDING:
			NEED_LL("OUTCOME_MAX_PENDING", 8, 4096,
				c->outcome_max_pending);
			break;
		case K_OUTCOME_DECISIONS_SCAN_MAX:
			NEED_LL("OUTCOME_DECISIONS_SCAN_MAX", 8, 4096,
				c->outcome_decisions_scan_max);
			break;
		case K_OUTCOME_WRITE_SME:
			NEED_LL("OUTCOME_WRITE_SME", 0, 1,
				c->outcome_write_sme);
			break;
		case K_OUTCOME_AUTO_ROLLBACK:
			NEED_LL("OUTCOME_AUTO_ROLLBACK", 0, 1,
				c->outcome_auto_rollback);
			break;
		case K_DECISIONS_ENABLED:
			NEED_LL("DECISIONS_ENABLED", 0, 1,
				c->decisions_enabled);
			break;
		case K_DECISIONS_INTERVAL_SEC:
			NEED_LL("DECISIONS_INTERVAL_SEC", 1, 86400,
				c->decisions_interval_sec);
			break;
		case K_DECISIONS_SCAN_MAX:
			NEED_LL("DECISIONS_SCAN_MAX", 16, 4096,
				c->decisions_scan_max);
			break;
		case K_DECISIONS_BATCH_MAX:
			NEED_LL("DECISIONS_BATCH_MAX", 1024, 262144,
				c->decisions_batch_max);
			break;
		case K_DECISIONS_WRITE_SME:
			NEED_LL("DECISIONS_WRITE_SME", 0, 1,
				c->decisions_write_sme);
			break;
		case K_SENSE_REDACT:
			if (strcmp(v, "off") == 0) {
				c->sense_redact_level = 0;
			} else if (strcmp(v, "soft") == 0) {
				c->sense_redact_level = 1;
			} else if (strcmp(v, "strict") == 0) {
				c->sense_redact_level = 2;
			} else {
				fclose(f);
				return bad(err, errcap, lineno,
					   "bad SENSE_REDACT (need off|soft|strict): ",
					   v, NULL);
			}
			break;
		case K_SENSE_REDACT_SALT:
			/* 盐：≤64 字节可打印非空白（参与 FNV，不落遥测） */
			if (strlen(v) > 64 || strpbrk(v, " \t")) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "bad SENSE_REDACT_SALT (<=64 chars, "
					   "no whitespace): ", v, NULL);
			}
			snprintf(c->sense_redact_salt,
				 sizeof(c->sense_redact_salt), "%s", v);
			break;
		default:
			fclose(f);
			return bad(err, errcap, lineno,
				   "internal: unhandled key", NULL, NULL);
		}
#undef NEED_LL
	}
	fclose(f);
	return 0;
}
