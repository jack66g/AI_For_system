// SPDX-License-Identifier: GPL-2.0
/*
 * acconfig.c - autocondense 配置模型 / 校验 / 深合并 / 加载保存 / 时钟
 *
 * 逐语义对齐 ref-autocondense/config.py（详见 acconfig.h）。
 * 零第三方依赖；JSON DOM 走 store/store_json。
 */
#define _DEFAULT_SOURCE 1

#include "autocondense/acconfig.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define AC_PORT_ENV "AUTOCONDENSE_PORT"

/* ================================================================== */
/* 注入时钟                                                            */
/* ================================================================== */

static int g_frozen;
static double g_frozen_epoch;

void ac_time_set_now(double epoch_seconds)
{
	g_frozen = 1;
	g_frozen_epoch = epoch_seconds;
}

void ac_time_unset_now(void)
{
	g_frozen = 0;
}

time_t ac_now(void)
{
	if (g_frozen)
		return (time_t)g_frozen_epoch;
	return time(NULL);
}

void ac_now_exact(long long *sec, int *msec)
{
	if (g_frozen) {
		double whole = floor(g_frozen_epoch);
		double frac = g_frozen_epoch - whole;

		if (sec)
			*sec = (long long)whole;
		if (msec)
			*msec = (int)(frac * 1000.0 + 0.5);
		return;
	}
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
		if (sec)
			*sec = (long long)time(NULL);
		if (msec)
			*msec = 0;
		return;
	}
	if (sec)
		*sec = (long long)ts.tv_sec;
	if (msec)
		*msec = (int)(ts.tv_nsec / 1000000);
}

static int fmt_local(time_t t, const char *fmt, char *buf, size_t buflen)
{
	struct tm tm;

	if (!localtime_r(&t, &tm))
		return -1;
	size_t n = strftime(buf, buflen, fmt, &tm);

	return n > 0 ? 0 : -1;
}

int ac_iso_now(char *buf, size_t buflen)
{
	return fmt_local(ac_now(), "%Y-%m-%dT%H:%M:%S", buf, buflen);
}

int ac_iso_ms_now(char *buf, size_t buflen)
{
	long long sec;
	int msec;
	char head[32];

	ac_now_exact(&sec, &msec);
	if (fmt_local((time_t)sec, "%Y-%m-%dT%H:%M:%S", head, sizeof(head)) != 0)
		return -1;
	return snprintf(buf, buflen, "%s.%03d", head, msec) < (int)buflen ? 0 : -1;
}

int ac_stamp_now(char *buf, size_t buflen)
{
	return fmt_local(ac_now(), "%Y%m%d-%H%M%S", buf, buflen);
}

int ac_iso_epoch(time_t t, char *buf, size_t buflen)
{
	return fmt_local(t, "%Y-%m-%dT%H:%M:%S", buf, buflen);
}

/* 解析 "YYYY-MM-DD[T| ]HH:MM:SS[.f+]"（datetime.fromisoformat 子集）*/
int ac_parse_iso(const char *s, time_t *out)
{
	if (!s || !out)
		return -1;
	long long vals[6];
	int nf = 0;
	char sep = 0;
	const char *p = s;

	for (int i = 0; i < 6; i++) {
		char *end = NULL;
		long v = strtol(p, &end, 10);

		if (end == p || v < -9999 || v > 99999)
			return -1;
		vals[nf++] = v;
		p = end;
		if (i == 0 || i == 1) {
			if (*p != '-')
				return -1;
			p++;
		} else if (i == 2) {
			if (*p != 'T' && *p != ' ')
				return -1;
			sep = *p;
			p++;
		} else if (i == 3 || i == 4) {
			if (*p != ':')
				return -1;
			p++;
		}
	}
	if (!sep)
		return -1;
	if (*p == '.') {
		p++;
		if (!(*p >= '0' && *p <= '9'))
			return -1;
		while (*p >= '0' && *p <= '9')
			p++;
	}
	if (*p != '\0')
		return -1;
	int y = (int)vals[0], mo = (int)vals[1], d = (int)vals[2];
	int h = (int)vals[3], mi = (int)vals[4], sec = (int)vals[5];

	if (mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 ||
	    mi < 0 || mi > 59 || sec < 0 || sec > 60)
		return -1;
	/* 墙钟按本地时区折算 epoch：datetime.fromisoformat 得 naive 时间，
	 * 与 ac_now()（epoch → 本地墙钟）同口径比较 */
	struct tm tmv;

	memset(&tmv, 0, sizeof(tmv));
	tmv.tm_year = y - 1900;
	tmv.tm_mon = mo - 1;
	tmv.tm_mday = d;
	tmv.tm_hour = h;
	tmv.tm_min = mi;
	tmv.tm_sec = sec;
	time_t as_utc = timegm(&tmv);

	if (as_utc == (time_t)-1)
		return -1;
	time_t now = ac_now();
	struct tm lnow;

	if (!localtime_r(&now, &lnow))
		return -1;
	time_t now_as_utc = timegm(&lnow);

	*out = as_utc - (now_as_utc - now);
	return 0;
}

/* ================================================================== */
/* 小工具                                                              */
/* ================================================================== */

static char *xstrdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = malloc(n);

	if (p)
		memcpy(p, s, n);
	return p;
}

static aik_json *deep_copy(const aik_json *v)
{
	/* parse(dump(v))：与手工递归拷贝等价，转义路径单一 */
	if (!v)
		return NULL;
	char *text = NULL;
	size_t n = 0;

	if (aik_json_dump(v, &text, &n) != 0)
		return NULL;
	char err[128];
	aik_json *out = aik_json_parse(text, n, err, sizeof(err));

	free(text);
	return out;
}

/* ================================================================== */
/* JSON 序列化形态（json.dumps 等价）                                  */
/* ================================================================== */

struct sbuf {
	char *p;
	size_t n, cap;
	int bad;
};

static int sb_grow(struct sbuf *b, size_t need)
{
	if (b->bad)
		return -1;
	if (b->n + need + 1 > b->cap) {
		size_t cap = b->cap ? b->cap : 256;
		char *q;

		while (cap < b->n + need + 1)
			cap *= 2;
		q = realloc(b->p, cap);
		if (!q) {
			b->bad = 1;
			return -1;
		}
		b->p = q;
		b->cap = cap;
	}
	return 0;
}

static void sb_putc(struct sbuf *b, char c)
{
	if (sb_grow(b, 1) == 0)
		b->p[b->n++] = c;
}

static void sb_puts(struct sbuf *b, const char *s, size_t n)
{
	if (sb_grow(b, n) == 0) {
		memcpy(b->p + b->n, s, n);
		b->n += n;
	}
}

static void sb_pad(struct sbuf *b, int indent, int depth)
{
	for (int i = 0; i < indent * depth; i++)
		sb_putc(b, ' ');
}

static const char HEXD[] = "0123456789abcdef";

/* ensure_ascii=False 等价转义（与 store_json.c dump_str 同规则）*/
static void sb_put_str(struct sbuf *b, const char *s, size_t n)
{
	sb_putc(b, '"');
	for (size_t i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];

		switch (c) {
		case '"':
			sb_puts(b, "\\\"", 2);
			break;
		case '\\':
			sb_puts(b, "\\\\", 2);
			break;
		case '\b':
			sb_puts(b, "\\b", 2);
			break;
		case '\f':
			sb_puts(b, "\\f", 2);
			break;
		case '\n':
			sb_puts(b, "\\n", 2);
			break;
		case '\r':
			sb_puts(b, "\\r", 2);
			break;
		case '\t':
			sb_puts(b, "\\t", 2);
			break;
		default:
			if (c < 0x20) {
				char esc[6];

				esc[0] = '\\';
				esc[1] = 'u';
				esc[2] = '0';
				esc[3] = '0';
				esc[4] = HEXD[c >> 4];
				esc[5] = HEXD[c & 0x0F];
				sb_puts(b, esc, 6);
			} else {
				sb_putc(b, (char)c);
			}
			break;
		}
	}
	sb_putc(b, '"');
}

static void sb_put_num(struct sbuf *b, const aik_json *v)
{
	char tmp[40];

	switch (aik_json_typeof(v)) {
	case AIK_JSON_INT:
		snprintf(tmp, sizeof(tmp), "%lld", aik_json_int(v));
		sb_puts(b, tmp, strlen(tmp));
		break;
	case AIK_JSON_NUM: {
		int n = aik_json_dtoa(aik_json_num(v), tmp, sizeof(tmp));

		if (n < 0) {
			b->bad = 1;
			break;
		}
		sb_puts(b, tmp, (size_t)n);
		break;
	}
	default:
		b->bad = 1;
		break;
	}
}

/*
 * dump_value - 两种形态：
 *   indent=0  → json.dumps(v, ensure_ascii=False)（分隔 ", " / ": "）
 *   indent>0  → json.dumps(v, ensure_ascii=False, indent=N)
 *     （分隔 "," / ": "，逐项换行缩进；空容器 "{}" / "[]"）
 */
static void dump_value(struct sbuf *b, const aik_json *v, int indent, int depth)
{
	switch (aik_json_typeof(v)) {
	case AIK_JSON_NULL:
		sb_puts(b, "null", 4);
		break;
	case AIK_JSON_BOOL:
		if (aik_json_bool(v))
			sb_puts(b, "true", 4);
		else
			sb_puts(b, "false", 5);
		break;
	case AIK_JSON_INT:
	case AIK_JSON_NUM:
		sb_put_num(b, v);
		break;
	case AIK_JSON_STR:
		sb_put_str(b, aik_json_str(v), aik_json_strlen(v));
		break;
	case AIK_JSON_ARR: {
		size_t n = aik_json_count(v);

		if (n == 0) {
			sb_puts(b, "[]", 2);
			break;
		}
		sb_putc(b, '[');
		for (size_t i = 0; i < n; i++) {
			if (i) {
				sb_putc(b, ',');
				if (indent == 0)
					sb_putc(b, ' ');
			}
			if (indent > 0) {
				sb_putc(b, '\n');
				sb_pad(b, indent, depth + 1);
			}
			dump_value(b, aik_json_at(v, i), indent, depth + 1);
		}
		if (indent > 0) {
			sb_putc(b, '\n');
			sb_pad(b, indent, depth);
		}
		sb_putc(b, ']');
		break;
	}
	case AIK_JSON_OBJ: {
		size_t n = aik_json_count(v);

		if (n == 0) {
			sb_puts(b, "{}", 2);
			break;
		}
		sb_putc(b, '{');
		for (size_t i = 0; i < n; i++) {
			if (i) {
				sb_putc(b, ',');
				if (indent == 0)
					sb_putc(b, ' ');
			}
			if (indent > 0) {
				sb_putc(b, '\n');
				sb_pad(b, indent, depth + 1);
			}
			const char *k = aik_json_key_at(v, i);

			sb_put_str(b, k, strlen(k));
			sb_puts(b, ": ", 2);
			dump_value(b, aik_json_val_at(v, i), indent, depth + 1);
		}
		if (indent > 0) {
			sb_putc(b, '\n');
			sb_pad(b, indent, depth);
		}
		sb_putc(b, '}');
		break;
	}
	}
}

static char *dump_finish(struct sbuf *b)
{
	if (b->bad || sb_grow(b, 1) != 0) {
		free(b->p);
		return NULL;
	}
	b->p[b->n] = '\0';
	return b->p;
}

char *ac_json_dump_indent(const aik_json *v, int indent)
{
	struct sbuf b = { 0 };

	if (indent < 1 || indent > 8)
		indent = 2;
	dump_value(&b, v, indent, 0);
	return dump_finish(&b);
}

char *ac_json_dump_default(const aik_json *v)
{
	struct sbuf b = { 0 };

	dump_value(&b, v, 0, 0);
	return dump_finish(&b);
}

/* ================================================================== */
/* 文件工具                                                            */
/* ================================================================== */

int ac_mkdir_p(const char *path)
{
	if (!path || !*path)
		return -1;
	size_t n = strlen(path);
	char *tmp = malloc(n + 1);

	if (!tmp)
		return -1;
	memcpy(tmp, path, n + 1);
	int rc = 0;

	for (size_t i = 1; i < n && rc == 0; i++) {
		if (tmp[i] == '/') {
			tmp[i] = '\0';
			struct stat st;

			if (mkdir(tmp, 0777) != 0 && errno != EEXIST)
				rc = -1;
			else if (stat(tmp, &st) == 0 && !S_ISDIR(st.st_mode))
				rc = -1;
			tmp[i] = '/';
		}
	}
	if (rc == 0) {
		struct stat st;

		if (mkdir(tmp, 0777) != 0 && errno != EEXIST)
			rc = -1;
		else if (stat(tmp, &st) == 0 && !S_ISDIR(st.st_mode))
			rc = -1;
	}
	free(tmp);
	return rc;
}

static char *parent_dir(const char *path)
{
	const char *slash = strrchr(path, '/');

	if (!slash || slash == path)
		return xstrdup("/");
	size_t n = (size_t)(slash - path);
	char *out = malloc(n + 1);

	if (out) {
		memcpy(out, path, n);
		out[n] = '\0';
	}
	return out;
}

int ac_atomic_write_text(const char *path, const char *buf, size_t len)
{
	if (!path || !buf)
		return -1;
	char *parent = parent_dir(path);

	if (!parent)
		return -1;
	int rc = ac_mkdir_p(parent);

	free(parent);
	if (rc != 0)
		return -1;
	char tmp[4096];

	if (snprintf(tmp, sizeof(tmp), "%s.tmp-%ld", path, (long)getpid()) >=
	    (int)sizeof(tmp))
		return -1;
	FILE *f = fopen(tmp, "wb");

	if (!f)
		return -1;
	size_t wrote = fwrite(buf, 1, len, f);

	if (wrote != len || fclose(f) != 0)
		goto fail;
	if (rename(tmp, path) != 0)
		goto fail;
	return 0;
fail:
	unlink(tmp);
	return -1;
}

char *ac_quarantine_corrupt(const char *path)
{
	if (!path)
		return NULL;
	struct stat st;

	if (stat(path, &st) != 0)
		return NULL;
	char stamp[32];

	if (ac_stamp_now(stamp, sizeof(stamp)) != 0)
		return NULL;
	size_t n = strlen(path) + strlen(".corrupt-") + strlen(stamp) + 1;
	char *target = malloc(n);

	if (!target)
		return NULL;
	snprintf(target, n, "%s.corrupt-%s", path, stamp);
	if (rename(path, target) != 0) {
		free(target);
		return NULL;
	}
	return target;
}

char *ac_read_file(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return NULL;
	}
	long sz = ftell(f);

	if (sz < 0 || fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return NULL;
	}
	char *buf = malloc((size_t)sz + 1);

	if (!buf) {
		fclose(f);
		return NULL;
	}
	if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	buf[sz] = '\0';
	if (len)
		*len = (size_t)sz;
	return buf;
}

/* ================================================================== */
/* 默认值 / to_dict / apply                                            */
/* ================================================================== */

static const char *SME_DEFAULT_TAGS[] = { "project", "todo", "session_digest" };

static char **dup_str_array(const char *const *src, size_t n)
{
	char **out = calloc(n ? n : 1, sizeof(char *));

	if (!out)
		return NULL;
	for (size_t i = 0; i < n; i++) {
		out[i] = xstrdup(src[i]);
		if (!out[i]) {
			for (size_t j = 0; j < i; j++)
				free(out[j]);
			free(out);
			return NULL;
		}
	}
	return out;
}

static void free_str_array(char **arr, size_t n)
{
	if (!arr)
		return;
	for (size_t i = 0; i < n; i++)
		free(arr[i]);
	free(arr);
}

static aik_json *jstr(const char *s)
{
	return aik_json_new_str(s ? s : "");
}

static int obj_own(aik_json *obj, const char *key, aik_json *v)
{
	if (!v || aik_json_obj_put(obj, key, v) != 0) {
		aik_json_free(v);
		return -1;
	}
	return 0;
}

/* float 字段：被赋整数值时保留 INT 形态（json.dumps(1) → "1"）*/
static aik_json *jnum_flag(double d, int is_int, long long i)
{
	return is_int ? aik_json_new_int(i) : aik_json_new_num(d);
}

void ac_sme_config_default(ac_sme_config *c)
{
	memset(c, 0, sizeof(*c));
	c->enabled = 1;
	c->base_url = xstrdup("http://127.0.0.1:8000");
	c->timeout_s = 2.0;
	c->tags = dup_str_array(SME_DEFAULT_TAGS, 3);
	c->n_tags = 3;
	c->importance = 0.7;
	c->split_segments = 1;
	c->max_segments = 15;
	c->dedup = 1;
	c->dedup_threshold = 0.92;
}

void ac_config_default(ac_config *c)
{
	memset(c, 0, sizeof(*c));
	c->port = 8761;
	c->host = xstrdup("127.0.0.1");
	c->enabled = 1;
	c->cooldown_minutes = 30;
	c->turns_threshold = 25;
	c->water_threshold = 0.7;
	c->usable_context_tokens = 160000;
	c->task_min_rounds = 5;
	c->judge_defer_turns = 5;
	c->judge_defer_max_turns = 20;
	c->restore_max_chars = 8000;
	c->restore_top_n = 3;
	c->restore_reread_files = 5;
	c->delta_mode = 1;
	c->delta_merge_every = 5;
	c->idle_signal_rounds = 3;
	ac_sme_config_default(&c->sme);
}

void ac_config_default_env(ac_config *c)
{
	ac_config_default(c);
	const char *raw = getenv(AC_PORT_ENV);

	if (raw && *raw) {
		char *end = NULL;
		long v = strtol(raw, &end, 10);

		if (end != raw && *end == '\0' && v > 0 && v <= 65535)
			c->port = (int)v;
	}
}

void ac_sme_config_cleanup(ac_sme_config *c)
{
	free(c->base_url);
	free_str_array(c->tags, c->n_tags);
	memset(c, 0, sizeof(*c));
}

void ac_config_cleanup(ac_config *c)
{
	free(c->host);
	ac_sme_config_cleanup(&c->sme);
	memset(c, 0, sizeof(*c));
}

aik_json *ac_sme_config_to_dict(const ac_sme_config *c)
{
	aik_json *o = aik_json_new_obj();

	if (!o)
		return NULL;
	aik_json *tags = aik_json_new_arr();

	if (!tags)
		goto fail;
	for (size_t i = 0; i < c->n_tags; i++) {
		aik_json *t = jstr(c->tags[i]);

		if (!t || aik_json_arr_push(tags, t) != 0) {
			aik_json_free(t);
			aik_json_free(tags);
			goto fail;
		}
	}
	if (obj_own(o, "enabled", aik_json_new_bool(c->enabled)) != 0 ||
	    obj_own(o, "base_url", jstr(c->base_url)) != 0 ||
	    obj_own(o, "timeout_s",
		    jnum_flag(c->timeout_s, c->timeout_s_is_int, c->timeout_s_int)) != 0 ||
	    aik_json_obj_put(o, "tags", tags) != 0) {
		aik_json_free(tags);
		goto fail;
	}
	if (obj_own(o, "importance",
		    jnum_flag(c->importance, c->importance_is_int, c->importance_int)) != 0 ||
	    obj_own(o, "split_segments", aik_json_new_bool(c->split_segments)) != 0 ||
	    obj_own(o, "max_segments", aik_json_new_int(c->max_segments)) != 0 ||
	    obj_own(o, "dedup", aik_json_new_bool(c->dedup)) != 0 ||
	    obj_own(o, "dedup_threshold",
		    jnum_flag(c->dedup_threshold, c->dedup_threshold_is_int,
			      c->dedup_threshold_int)) != 0)
		goto fail;
	return o;
fail:
	aik_json_free(o);
	return NULL;
}

aik_json *ac_config_to_dict(const ac_config *c)
{
	aik_json *o = aik_json_new_obj();

	if (!o)
		return NULL;
	if (obj_own(o, "port", aik_json_new_int(c->port)) != 0 ||
	    obj_own(o, "host", jstr(c->host)) != 0 ||
	    obj_own(o, "enabled", aik_json_new_bool(c->enabled)) != 0 ||
	    obj_own(o, "cooldown_minutes", aik_json_new_int(c->cooldown_minutes)) != 0 ||
	    obj_own(o, "turns_threshold", aik_json_new_int(c->turns_threshold)) != 0 ||
	    obj_own(o, "water_threshold",
		    jnum_flag(c->water_threshold, c->water_threshold_is_int,
			      c->water_threshold_int)) != 0 ||
	    obj_own(o, "usable_context_tokens",
		    aik_json_new_int(c->usable_context_tokens)) != 0 ||
	    obj_own(o, "task_min_rounds", aik_json_new_int(c->task_min_rounds)) != 0 ||
	    obj_own(o, "judge_defer_turns", aik_json_new_int(c->judge_defer_turns)) != 0 ||
	    obj_own(o, "judge_defer_max_turns",
		    aik_json_new_int(c->judge_defer_max_turns)) != 0 ||
	    obj_own(o, "restore_max_chars", aik_json_new_int(c->restore_max_chars)) != 0 ||
	    obj_own(o, "restore_top_n", aik_json_new_int(c->restore_top_n)) != 0 ||
	    obj_own(o, "restore_reread_files",
		    aik_json_new_int(c->restore_reread_files)) != 0 ||
	    obj_own(o, "delta_mode", aik_json_new_bool(c->delta_mode)) != 0 ||
	    obj_own(o, "delta_merge_every",
		    aik_json_new_int(c->delta_merge_every)) != 0 ||
	    obj_own(o, "idle_signal_rounds",
		    aik_json_new_int(c->idle_signal_rounds)) != 0)
		goto fail;
	aik_json *sme = ac_sme_config_to_dict(&c->sme);

	if (!sme || aik_json_obj_put(o, "sme", sme) != 0) {
		aik_json_free(sme);
		goto fail;
	}
	return o;
fail:
	aik_json_free(o);
	return NULL;
}

int ac_sme_config_apply_dict(ac_sme_config *c, const aik_json *d)
{
	if (!c || aik_json_typeof(d) != AIK_JSON_OBJ)
		return -1;
	for (size_t i = 0; i < aik_json_count(d); i++) {
		const char *k = aik_json_key_at(d, i);
		const aik_json *v = aik_json_val_at(d, i);

		if (strcmp(k, "enabled") == 0) {
			c->enabled = aik_json_bool(v);
		} else if (strcmp(k, "base_url") == 0) {
			const char *s = aik_json_str(v);
			char *dup = xstrdup(s ? s : "");

			if (!dup)
				return -1;
			free(c->base_url);
			c->base_url = dup;
		} else if (strcmp(k, "timeout_s") == 0) {
			if (aik_json_typeof(v) == AIK_JSON_INT) {
				c->timeout_s_is_int = 1;
				c->timeout_s_int = aik_json_int(v);
				c->timeout_s = (double)aik_json_int(v);
			} else {
				c->timeout_s_is_int = 0;
				c->timeout_s = aik_json_num(v);
			}
		} else if (strcmp(k, "tags") == 0) {
			size_t n = aik_json_count(v);
			char **arr = calloc(n ? n : 1, sizeof(char *));

			if (!arr)
				return -1;
			size_t j = 0;

			for (; j < n; j++) {
				const char *s = aik_json_str(aik_json_at(v, j));

				arr[j] = xstrdup(s ? s : "");
				if (!arr[j])
					break;
			}
			if (j < n) {
				free_str_array(arr, j);
				return -1;
			}
			free_str_array(c->tags, c->n_tags);
			c->tags = arr;
			c->n_tags = n;
		} else if (strcmp(k, "importance") == 0) {
			if (aik_json_typeof(v) == AIK_JSON_INT) {
				c->importance_is_int = 1;
				c->importance_int = aik_json_int(v);
				c->importance = (double)aik_json_int(v);
			} else {
				c->importance_is_int = 0;
				c->importance = aik_json_num(v);
			}
		} else if (strcmp(k, "split_segments") == 0) {
			c->split_segments = aik_json_bool(v);
		} else if (strcmp(k, "max_segments") == 0) {
			c->max_segments = aik_json_int(v);
		} else if (strcmp(k, "dedup") == 0) {
			c->dedup = aik_json_bool(v);
		} else if (strcmp(k, "dedup_threshold") == 0) {
			if (aik_json_typeof(v) == AIK_JSON_INT) {
				c->dedup_threshold_is_int = 1;
				c->dedup_threshold_int = aik_json_int(v);
				c->dedup_threshold = (double)aik_json_int(v);
			} else {
				c->dedup_threshold_is_int = 0;
				c->dedup_threshold = aik_json_num(v);
			}
		}
		/* 未知键忽略（调用方应先 validate/sanitize）*/
	}
	return 0;
}

int ac_config_apply_dict(ac_config *c, const aik_json *d)
{
	if (!c || aik_json_typeof(d) != AIK_JSON_OBJ)
		return -1;
	for (size_t i = 0; i < aik_json_count(d); i++) {
		const char *k = aik_json_key_at(d, i);
		const aik_json *v = aik_json_val_at(d, i);

		if (strcmp(k, "sme") == 0) {
			if (aik_json_typeof(v) == AIK_JSON_OBJ)
				ac_sme_config_apply_dict(&c->sme, v);
			continue;
		}
		if (strcmp(k, "port") == 0) {
			c->port = (int)aik_json_int(v);
		} else if (strcmp(k, "host") == 0) {
			const char *s = aik_json_str(v);
			char *dup = xstrdup(s ? s : "");

			if (!dup)
				return -1;
			free(c->host);
			c->host = dup;
		} else if (strcmp(k, "enabled") == 0) {
			c->enabled = aik_json_bool(v);
		} else if (strcmp(k, "cooldown_minutes") == 0) {
			c->cooldown_minutes = (int)aik_json_int(v);
		} else if (strcmp(k, "turns_threshold") == 0) {
			c->turns_threshold = (int)aik_json_int(v);
		} else if (strcmp(k, "water_threshold") == 0) {
			if (aik_json_typeof(v) == AIK_JSON_INT) {
				c->water_threshold_is_int = 1;
				c->water_threshold_int = aik_json_int(v);
				c->water_threshold = (double)aik_json_int(v);
			} else {
				c->water_threshold_is_int = 0;
				c->water_threshold = aik_json_num(v);
			}
		} else if (strcmp(k, "usable_context_tokens") == 0) {
			c->usable_context_tokens = aik_json_int(v);
		} else if (strcmp(k, "task_min_rounds") == 0) {
			c->task_min_rounds = aik_json_int(v);
		} else if (strcmp(k, "judge_defer_turns") == 0) {
			c->judge_defer_turns = aik_json_int(v);
		} else if (strcmp(k, "judge_defer_max_turns") == 0) {
			c->judge_defer_max_turns = aik_json_int(v);
		} else if (strcmp(k, "restore_max_chars") == 0) {
			c->restore_max_chars = aik_json_int(v);
		} else if (strcmp(k, "restore_top_n") == 0) {
			c->restore_top_n = aik_json_int(v);
		} else if (strcmp(k, "restore_reread_files") == 0) {
			c->restore_reread_files = aik_json_int(v);
		} else if (strcmp(k, "delta_mode") == 0) {
			c->delta_mode = aik_json_bool(v);
		} else if (strcmp(k, "delta_merge_every") == 0) {
			c->delta_merge_every = aik_json_int(v);
		} else if (strcmp(k, "idle_signal_rounds") == 0) {
			c->idle_signal_rounds = aik_json_int(v);
		}
	}
	return 0;
}

/* ================================================================== */
/* 校验                                                                */
/* ================================================================== */

enum rule_type {
	RT_INT, RT_BOOL, RT_FLOAT, RT_STR, RT_LIST
};

struct rule {
	const char *key;
	enum rule_type type;
};

static const struct rule TOP_RULES[] = {
	{ "port", RT_INT },
	{ "host", RT_STR },
	{ "enabled", RT_BOOL },
	{ "cooldown_minutes", RT_INT },
	{ "turns_threshold", RT_INT },
	{ "water_threshold", RT_FLOAT },
	{ "usable_context_tokens", RT_INT },
	{ "task_min_rounds", RT_INT },
	{ "judge_defer_turns", RT_INT },
	{ "judge_defer_max_turns", RT_INT },
	{ "restore_max_chars", RT_INT },
	{ "restore_top_n", RT_INT },
	{ "restore_reread_files", RT_INT },
	{ "delta_mode", RT_BOOL },
	{ "delta_merge_every", RT_INT },
	{ "idle_signal_rounds", RT_INT },
};

static const struct rule SME_RULES[] = {
	{ "enabled", RT_BOOL },
	{ "base_url", RT_STR },
	{ "timeout_s", RT_FLOAT },
	{ "tags", RT_LIST },
	{ "importance", RT_FLOAT },
	{ "split_segments", RT_BOOL },
	{ "max_segments", RT_INT },
	{ "dedup", RT_BOOL },
	{ "dedup_threshold", RT_FLOAT },
};

static const struct rule *find_rule(const struct rule *rules, size_t n,
				    const char *key)
{
	for (size_t i = 0; i < n; i++)
		if (strcmp(rules[i].key, key) == 0)
			return &rules[i];
	return NULL;
}

/* _type_error 等价：返回错误后缀文案（NULL = 通过）*/
static const char *type_error(const aik_json *v, enum rule_type t)
{
	aik_json_type jt = aik_json_typeof(v);

	switch (t) {
	case RT_BOOL:
		return jt == AIK_JSON_BOOL ? NULL : "应为布尔值";
	case RT_INT:
		return jt == AIK_JSON_INT ? NULL : "应为整数";
	case RT_FLOAT:
		return (jt == AIK_JSON_INT || jt == AIK_JSON_NUM) ? NULL : "应为数字";
	case RT_STR:
		return jt == AIK_JSON_STR ? NULL : "应为字符串";
	case RT_LIST:
		return jt == AIK_JSON_ARR ? NULL : "应为数组";
	}
	return NULL;
}

static char *concat_msg(const char *a, const char *b, const char *c)
{
	size_t n = strlen(a) + strlen(b) + strlen(c) + 1;
	char *out = malloc(n);

	if (out)
		snprintf(out, n, "%s%s%s", a, b, c);
	return out;
}

/* "<key> <文案>"（_type_error 的 f"{key} 应为xx" 形态）*/
static char *key_type_msg(const char *key, const char *msg)
{
	size_t n = strlen(key) + 1 + strlen(msg) + 1;
	char *out = malloc(n);

	if (out)
		snprintf(out, n, "%s %s", key, msg);
	return out;
}

/* 追加一条错误（msg 所有权转移）；失败或 msg=NULL 返回 -1 */
static int push_err(aik_json *arr, char *msg)
{
	if (!msg)
		return -1;
	aik_json *s = aik_json_new_str(msg);

	free(msg);
	if (!s)
		return -1;
	if (aik_json_arr_push(arr, s) != 0) {
		aik_json_free(s);
		return -1;
	}
	return 0;
}

aik_json *ac_validate_config_dict(const aik_json *data)
{
	aik_json *errors = aik_json_new_arr();

	if (!errors)
		return NULL;
	if (aik_json_typeof(data) != AIK_JSON_OBJ) {
		if (push_err(errors, xstrdup("配置必须是 JSON 对象")) != 0)
			goto fail;
		return errors;
	}
	for (size_t i = 0; i < aik_json_count(data); i++) {
		const char *k = aik_json_key_at(data, i);
		const aik_json *v = aik_json_val_at(data, i);

		if (strcmp(k, "sme") == 0) {
			if (aik_json_typeof(v) != AIK_JSON_OBJ) {
				if (push_err(errors, xstrdup("sme 应为对象")) != 0)
					goto fail;
				continue;
			}
			for (size_t j = 0; j < aik_json_count(v); j++) {
				const char *sk = aik_json_key_at(v, j);
				const aik_json *sv = aik_json_val_at(v, j);
				const struct rule *r = find_rule(
					SME_RULES,
					sizeof(SME_RULES) / sizeof(SME_RULES[0]), sk);

				if (!r) {
					if (push_err(errors,
						     concat_msg("未知配置项：sme.", sk, "")) != 0)
						goto fail;
				} else {
					const char *te = type_error(sv, r->type);

					if (te) {
						char *key = concat_msg("sme.", sk, "");
						char *msg = key ? key_type_msg(key, te) : NULL;

						free(key);
						if (!msg || push_err(errors, msg) != 0)
							goto fail;
					}
				}
			}
		} else {
			const struct rule *r = find_rule(
				TOP_RULES, sizeof(TOP_RULES) / sizeof(TOP_RULES[0]), k);

			if (!r) {
				if (push_err(errors, concat_msg("未知配置项：", k, "")) != 0)
					goto fail;
			} else {
				const char *te = type_error(v, r->type);

				if (te && push_err(errors, concat_msg(k, " ", te)) != 0)
					goto fail;
			}
		}
	}
	return errors;
fail:
	aik_json_free(errors);
	return NULL;
}

/* ================================================================== */
/* 深合并 / 净化 / 加载保存                                            */
/* ================================================================== */

aik_json *ac_deep_merge(const aik_json *base, const aik_json *override)
{
	aik_json *out = deep_copy(base);

	if (!out)
		return NULL;
	if (aik_json_typeof(override) != AIK_JSON_OBJ)
		return out;	/* (override or {}) 无键可并 */
	for (size_t i = 0; i < aik_json_count(override); i++) {
		const char *k = aik_json_key_at(override, i);
		const aik_json *ov = aik_json_val_at(override, i);
		const aik_json *cur = aik_json_get(out, k);

		if (cur && aik_json_typeof(cur) == AIK_JSON_OBJ &&
		    aik_json_typeof(ov) == AIK_JSON_OBJ) {
			aik_json *merged = ac_deep_merge(cur, ov);

			if (!merged || aik_json_obj_set(out, k, merged) != 0) {
				aik_json_free(merged);
				aik_json_free(out);
				return NULL;
			}
		} else {
			aik_json *cp = deep_copy(ov);

			if (!cp || aik_json_obj_set(out, k, cp) != 0) {
				aik_json_free(cp);
				aik_json_free(out);
				return NULL;
			}
		}
	}
	return out;
}

aik_json *ac_sanitize_config_dict(const aik_json *d)
{
	if (aik_json_typeof(d) != AIK_JSON_OBJ)
		return aik_json_new_obj();
	aik_json *out = aik_json_new_obj();

	if (!out)
		return NULL;
	for (size_t i = 0; i < aik_json_count(d); i++) {
		const char *k = aik_json_key_at(d, i);
		const aik_json *v = aik_json_val_at(d, i);

		if (strcmp(k, "sme") == 0 && aik_json_typeof(v) == AIK_JSON_OBJ) {
			aik_json *sme = aik_json_new_obj();

			if (!sme)
				goto fail;
			for (size_t j = 0; j < aik_json_count(v); j++) {
				const char *sk = aik_json_key_at(v, j);
				const aik_json *sv = aik_json_val_at(v, j);
				const struct rule *r = find_rule(
					SME_RULES,
					sizeof(SME_RULES) / sizeof(SME_RULES[0]), sk);

				if (r && !type_error(sv, r->type)) {
					aik_json *cp = deep_copy(sv);

					if (!cp || aik_json_obj_put(sme, sk, cp) != 0) {
						aik_json_free(cp);
						aik_json_free(sme);
						goto fail;
					}
				}
			}
			if (aik_json_obj_put(out, "sme", sme) != 0) {
				aik_json_free(sme);
				goto fail;
			}
		} else {
			const struct rule *r = find_rule(
				TOP_RULES, sizeof(TOP_RULES) / sizeof(TOP_RULES[0]), k);

			if (r && !type_error(v, r->type)) {
				aik_json *cp = deep_copy(v);

				if (!cp || aik_json_obj_put(out, k, cp) != 0) {
					aik_json_free(cp);
					goto fail;
				}
			}
			/* 未知/类型不符 → 告警丢弃（加载期容忍，不阻断）*/
		}
	}
	return out;
fail:
	aik_json_free(out);
	return NULL;
}

int ac_load_config(const char *data_dir, ac_config *out)
{
	if (!data_dir || !out)
		return -1;
	size_t plen = strlen(data_dir) + sizeof("/config.json");
	char *path = malloc(plen);

	if (!path)
		return -1;
	snprintf(path, plen, "%s/config.json", data_dir);

	aik_json *stored = NULL;
	char *text = ac_read_file(path, NULL);

	if (text) {
		char err[128];
		size_t n = strlen(text);
		aik_json *loaded = aik_json_parse(text, n, err, sizeof(err));

		free(text);
		if (!loaded || aik_json_typeof(loaded) != AIK_JSON_OBJ) {
			aik_json_free(loaded);
			char *q = ac_quarantine_corrupt(path);

			free(q);	/* 现场保留为 .corrupt-<ts> */
		} else {
			stored = loaded;
		}
	}
	free(path);

	ac_config defaults;

	ac_config_default_env(&defaults);
	aik_json *base = ac_config_to_dict(&defaults);

	ac_config_cleanup(&defaults);
	if (!base) {
		aik_json_free(stored);
		return -1;
	}
	aik_json *merged = ac_deep_merge(base, stored);

	aik_json_free(base);
	aik_json_free(stored);
	if (!merged)
		return -1;
	aik_json *sanitized = ac_sanitize_config_dict(merged);

	aik_json_free(merged);
	if (!sanitized)
		return -1;

	ac_config_default(out);
	int rc = ac_config_apply_dict(out, sanitized);

	aik_json_free(sanitized);
	return rc;
}

int ac_save_config(const char *data_dir, const ac_config *cfg)
{
	if (!data_dir || !cfg)
		return -1;
	aik_json *d = ac_config_to_dict(cfg);

	if (!d)
		return -1;
	char *body = ac_json_dump_indent(d, 2);

	aik_json_free(d);
	if (!body)
		return -1;

	size_t plen = strlen(data_dir) + sizeof("/config.json");
	char *path = malloc(plen);

	if (!path) {
		free(body);
		return -1;
	}
	snprintf(path, plen, "%s/config.json", data_dir);
	size_t blen = strlen(body);
	char *full = malloc(blen + 2);

	if (!full) {
		free(body);
		free(path);
		return -1;
	}
	memcpy(full, body, blen);
	full[blen] = '\n';
	full[blen + 1] = '\0';
	int rc = ac_atomic_write_text(path, full, blen + 1);

	free(full);
	free(body);
	free(path);
	return rc;
}
