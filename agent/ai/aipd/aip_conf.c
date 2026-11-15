/* SPDX-License-Identifier: GPL-2.0 */
/*
 * aip_conf.c - aipd 配置解析（KEY=VALUE 严格校验，坏值拒绝——as_conf
 * 风格克隆；M1 键集见 aipd.conf 样例与设计册 §1.1/§1.6）
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aip_conf.h"

void aip_conf_defaults(struct aip_conf *c)
{
	memset(c, 0, sizeof(*c));
	c->feat_source = 0;			/* map35 */
	c->feat_mock_file[0] = '\0';
	c->feat_degrade_mock = 0;
	c->poll_hz = 10;
	c->shadow = 1;				/* M1 恒 1 */
	snprintf(c->parquet_dir, sizeof(c->parquet_dir),
		 "/var/lib/aikernel");
	c->shadow_flush_sec = 10;
	c->shadow_flush_rows = 128;
	c->compare_enabled = 0;
	c->compare_mock = 0;
	c->compare_mock_file[0] = '\0';
	c->compare_interval_sec = 5;
	c->cmp_window = 256;
	c->stats_interval_sec = 10;
	c->log_debug = 0;
	snprintf(c->stats_file, sizeof(c->stats_file), "/run/aipd.stats");
	snprintf(c->pid_file, sizeof(c->pid_file), "/run/aipd.pid");
	snprintf(c->lock_file, sizeof(c->lock_file), "/run/aipd.lock");
}

static int bad(char *err, size_t cap, int lineno, const char *msg)
{
	if (err && cap)
		snprintf(err, cap, "line %d: %s", lineno, msg);
	return -1;
}

/* 整行必须是十进制整数（允许前后空白；as_conf parse_ll 同语义） */
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

enum key_id {
	K_FEAT_SOURCE, K_FEAT_MOCK_FILE, K_FEAT_DEGRADE_MOCK, K_POLL_HZ,
	K_MODEL_TABLE, K_SHADOW, K_PARQUET_DIR,
	K_SHADOW_FLUSH_SEC, K_SHADOW_FLUSH_ROWS,
	K_COMPARE_ENABLED, K_COMPARE_SOURCE, K_COMPARE_MOCK_FILE,
	K_COMPARE_INTERVAL_SEC, K_CMP_WINDOW,
	K_STATS_INTERVAL_SEC, K_LOG_DEBUG,
	K_STATS_FILE, K_PID_FILE, K_LOCK_FILE,
	K_MAX
};

static const char *const key_names[K_MAX] = {
	"FEAT_SOURCE", "FEAT_MOCK_FILE", "FEAT_DEGRADE_MOCK", "POLL_HZ",
	"MODEL_TABLE", "SHADOW", "PARQUET_DIR",
	"SHADOW_FLUSH_SEC", "SHADOW_FLUSH_ROWS",
	"COMPARE_ENABLED", "COMPARE_SOURCE", "COMPARE_MOCK_FILE",
	"COMPARE_INTERVAL_SEC", "CMP_WINDOW",
	"STATS_INTERVAL_SEC", "LOG_DEBUG",
	"STATS_FILE", "PID_FILE", "LOCK_FILE",
};

static int key_lookup(const char *k)
{
	for (int i = 0; i < K_MAX; i++)
		if (strcmp(k, key_names[i]) == 0)
			return i;
	return -1;
}

/* 非空且无内部换行/空白控制符的路径 */
static int sane_path(const char *v)
{
	if (!v[0] || v[0] != '/')
		return 0;
	for (const char *p = v; *p; p++)
		if ((unsigned char)*p < 0x20)
			return 0;
	return 1;
}

int aip_conf_load(struct aip_conf *c, const char *path, char *err,
		  size_t errcap)
{
	FILE *f;
	char line[1024];
	int lineno = 0;
	int seen[K_MAX];

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

		lineno++;
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
			return bad(err, errcap, lineno, "missing '='");
		}
		*eq = '\0';
		{
			char *ke = eq - 1;

			while (ke >= k && (*ke == ' ' || *ke == '\t'))
				*ke-- = '\0';
		}
		v = eq + 1;
		while (*v == ' ' || *v == '\t')
			v++;
		id = key_lookup(k);
		if (id < 0) {
			fclose(f);
			if (err && errcap)
				snprintf(err, errcap,
					 "line %d: unknown key '%s'", lineno,
					 k);
			return -1;
		}
		if (seen[id]) {
			fclose(f);
			if (err && errcap)
				snprintf(err, errcap,
					 "line %d: duplicate key '%s'",
					 lineno, k);
			return -1;
		}
		seen[id] = 1;
		switch (id) {
		case K_FEAT_SOURCE:
			if (strcmp(v, AIP_SRC_MAP35) == 0) {
				c->feat_source = 0;
			} else if (strcmp(v, AIP_SRC_MOCK) == 0) {
				c->feat_source = 1;
			} else {
				fclose(f);
				return bad(err, errcap, lineno,
					   "FEAT_SOURCE must be map35|mock");
			}
			break;
		case K_FEAT_MOCK_FILE:
			if (!sane_path(v)) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "FEAT_MOCK_FILE must be absolute "
					   "path");
			}
			snprintf(c->feat_mock_file,
				 sizeof(c->feat_mock_file), "%s", v);
			break;
		case K_FEAT_DEGRADE_MOCK:
			if (parse_ll(v, &n) != 0 || n < 0 || n > 1) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "FEAT_DEGRADE_MOCK must be 0|1");
			}
			c->feat_degrade_mock = (int)n;
			break;
		case K_POLL_HZ:
			if (parse_ll(v, &n) != 0 || n < 1 || n > 1000) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "POLL_HZ must be 1..1000");
			}
			c->poll_hz = n;
			break;
		case K_MODEL_TABLE:
			if (strcmp(v, "builtin") != 0) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "MODEL_TABLE must be builtin "
					   "(M1: 内置表)");
			}
			break;
		case K_SHADOW:
			if (parse_ll(v, &n) != 0 || n != 1) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "SHADOW must be 1 (M1 冻结：影子"
					   "期无 ACT 下发路径)");
			}
			c->shadow = 1;
			break;
		case K_PARQUET_DIR:
			if (!sane_path(v)) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "PARQUET_DIR must be absolute path");
			}
			snprintf(c->parquet_dir, sizeof(c->parquet_dir),
				 "%s", v);
			break;
		case K_SHADOW_FLUSH_SEC:
			if (parse_ll(v, &n) != 0 || n < 1 || n > 3600) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "SHADOW_FLUSH_SEC must be 1..3600");
			}
			c->shadow_flush_sec = n;
			break;
		case K_SHADOW_FLUSH_ROWS:
			if (parse_ll(v, &n) != 0 || n < 1 || n > 65536) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "SHADOW_FLUSH_ROWS must be 1..65536");
			}
			c->shadow_flush_rows = n;
			break;
		case K_COMPARE_ENABLED:
			if (parse_ll(v, &n) != 0 || n < 0 || n > 1) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "COMPARE_ENABLED must be 0|1");
			}
			c->compare_enabled = (int)n;
			break;
		case K_COMPARE_SOURCE:
			if (strcmp(v, "proc") == 0) {
				c->compare_mock = 0;
			} else if (strcmp(v, "mock") == 0) {
				c->compare_mock = 1;
			} else {
				fclose(f);
				return bad(err, errcap, lineno,
					   "COMPARE_SOURCE must be proc|mock");
			}
			break;
		case K_COMPARE_MOCK_FILE:
			if (!sane_path(v)) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "COMPARE_MOCK_FILE must be absolute "
					   "path");
			}
			snprintf(c->compare_mock_file,
				 sizeof(c->compare_mock_file), "%s", v);
			break;
		case K_COMPARE_INTERVAL_SEC:
			if (parse_ll(v, &n) != 0 || n < 1 || n > 3600) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "COMPARE_INTERVAL_SEC must be "
					   "1..3600");
			}
			c->compare_interval_sec = n;
			break;
		case K_CMP_WINDOW:
			if (parse_ll(v, &n) != 0 || n < 8 || n > 65536) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "CMP_WINDOW must be 8..65536");
			}
			c->cmp_window = n;
			break;
		case K_STATS_INTERVAL_SEC:
			if (parse_ll(v, &n) != 0 || n < 1 || n > 3600) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "STATS_INTERVAL_SEC must be 1..3600");
			}
			c->stats_interval_sec = n;
			break;
		case K_LOG_DEBUG:
			if (parse_ll(v, &n) != 0 || n < 0 || n > 1) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "LOG_DEBUG must be 0|1");
			}
			c->log_debug = (int)n;
			break;
		case K_STATS_FILE:
		case K_PID_FILE:
		case K_LOCK_FILE:
			if (!sane_path(v)) {
				fclose(f);
				return bad(err, errcap, lineno,
					   "path key must be absolute path");
			}
			if (id == K_STATS_FILE)
				snprintf(c->stats_file,
					 sizeof(c->stats_file), "%s", v);
			else if (id == K_PID_FILE)
				snprintf(c->pid_file,
					 sizeof(c->pid_file), "%s", v);
			else
				snprintf(c->lock_file,
					 sizeof(c->lock_file), "%s", v);
			break;
		default:
			fclose(f);
			return bad(err, errcap, lineno, "internal: bad id");
		}
	}
	fclose(f);
	/* 跨键校验：mock 源必须给文件；降级 mock 亦须文件可用 */
	if (c->feat_source == 1 && !c->feat_mock_file[0])
		return bad(err, errcap, 0,
			   "FEAT_SOURCE=mock requires FEAT_MOCK_FILE");
	if (c->feat_degrade_mock && !c->feat_mock_file[0])
		return bad(err, errcap, 0,
			   "FEAT_DEGRADE_MOCK=1 requires FEAT_MOCK_FILE");
	if (c->compare_enabled && c->compare_mock &&
	    !c->compare_mock_file[0])
		return bad(err, errcap, 0,
			   "COMPARE_SOURCE=mock requires "
			   "COMPARE_MOCK_FILE");
	return 0;
}
