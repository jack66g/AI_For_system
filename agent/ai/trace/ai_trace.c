// SPDX-License-Identifier: GPL-2.0
/*
 * ai_trace.c - AI 全轨迹日志（JSONL）实现
 *
 * 设计要点（详见 include/ai_trace.h 与 docs/trace-schema.md）：
 *   1. 单例 + 单写：每行在内存完整拼装后一次 write()（O_APPEND|O_CLOEXEC），
 *      进程内 pthread 互斥，行内绝不交错；
 *   2. 永不阻断：任何打开/写入错误只向 stderr 警告一次，随后静默丢弃；
 *   3. 统一脱敏：所有字符串字段先过 trace_redact() 再 JSON 转义；
 *   4. 轮转：按 max_file_mb 切分 <base>.jsonl → <base>.1.jsonl …，
 *      保留 max_files 个文件；
 *   5. 头字段：ts（ISO8601+毫秒+时区）、mono_ms（CLOCK_MONOTONIC）、
 *      session_id、session、turn、event_seq、event。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ai_trace.h"
#include "ai_types.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* ---- 全局单例状态 ---- */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ai_trace_config g_cfg = {
	.enabled = 1,
	.dir = NULL,
	.max_file_mb = 64,
	.max_files = 20,
	.include_model_text = 1,
	.max_payload_kb = 64,
};
static int g_inited;
static int g_enabled;
static int g_failed;
static int g_warned;
static int g_fd = -1;
static int g_session_started;
static int g_instance;
static char g_session_id[96];
static char g_session_name[128];
static char g_base_path[PATH_MAX + 64];
static unsigned long long g_seq;
static unsigned long long g_req_seq;
static unsigned long long g_events;
static unsigned long long g_turns;
static unsigned long long g_tool_calls;
static unsigned long long g_model_requests;
static unsigned long long g_degraded;
static unsigned long long g_errors;
static int g_turn;
static long long g_start_mono;
static long long g_turn_start_mono;
static unsigned long long g_cur_size;

/* ---- 动态字符串缓冲 ---- */
struct sbuf {
	char *p;
	size_t len;
	size_t cap;
};

static int sb_reserve(struct sbuf *b, size_t add)
{
	size_t need = b->len + add + 1;
	char *np;

	if (need <= b->cap)
		return 0;
	if (need < b->cap * 2)
		need = b->cap * 2;
	if (need < 256)
		need = 256;
	np = realloc(b->p, need);
	if (!np)
		return -1;
	b->p = np;
	b->cap = need;
	return 0;
}

static void sb_put(struct sbuf *b, const char *s, size_t n)
{
	if (!n || sb_reserve(b, n) != 0)
		return;
	memcpy(b->p + b->len, s, n);
	b->len += n;
	b->p[b->len] = '\0';
}

static void sb_puts(struct sbuf *b, const char *s)
{
	if (s)
		sb_put(b, s, strlen(s));
}

static void sb_putc(struct sbuf *b, char c)
{
	sb_put(b, &c, 1);
}

static void sb_printf(struct sbuf *b, const char *fmt, ...)
{
	va_list ap;
	va_list ap2;
	int n;

	va_start(ap, fmt);
	va_copy(ap2, ap);
	n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (n < 0) {
		va_end(ap2);
		return;
	}
	if (sb_reserve(b, (size_t)n) == 0) {
		vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap2);
		b->len += (size_t)n;
	}
	va_end(ap2);
}

static void sb_free(struct sbuf *b)
{
	free(b->p);
	memset(b, 0, sizeof(*b));
}

/* key 前自动加逗号（当前对象/数组刚打开时首字段不加） */
static void sb_key(struct sbuf *b, const char *key)
{
	if (b->len && b->p[b->len - 1] != '{' && b->p[b->len - 1] != '[')
		sb_putc(b, ',');
	sb_putc(b, '"');
	sb_puts(b, key);
	sb_puts(b, "\":");
}

/* ---- UTF-8 校验 / JSON 转义 ---- */

/* 返回合法 UTF-8 序列长度（1..4），非法返回 0 */
static size_t utf8_seq_len(const unsigned char *s, size_t n)
{
	unsigned char c = s[0];

	if (c < 0x80)
		return 1;
	if (c >= 0xC2 && c <= 0xDF) {
		if (n >= 2 && (s[1] & 0xC0) == 0x80)
			return 2;
		return 0;
	}
	if (c == 0xE0) {
		if (n >= 3 && s[1] >= 0xA0 && s[1] <= 0xBF &&
		    (s[2] & 0xC0) == 0x80)
			return 3;
		return 0;
	}
	if (c >= 0xE1 && c <= 0xEC) {
		if (n >= 3 && (s[1] & 0xC0) == 0x80 &&
		    (s[2] & 0xC0) == 0x80)
			return 3;
		return 0;
	}
	if (c == 0xED) {
		if (n >= 3 && s[1] >= 0x80 && s[1] <= 0x9F &&
		    (s[2] & 0xC0) == 0x80)
			return 3;
		return 0;
	}
	if (c >= 0xEE && c <= 0xEF) {
		if (n >= 3 && (s[1] & 0xC0) == 0x80 &&
		    (s[2] & 0xC0) == 0x80)
			return 3;
		return 0;
	}
	if (c == 0xF0) {
		if (n >= 4 && s[1] >= 0x90 && s[1] <= 0xBF &&
		    (s[2] & 0xC0) == 0x80 && (s[3] & 0xC0) == 0x80)
			return 4;
		return 0;
	}
	if (c >= 0xF1 && c <= 0xF3) {
		if (n >= 4 && (s[1] & 0xC0) == 0x80 &&
		    (s[2] & 0xC0) == 0x80 && (s[3] & 0xC0) == 0x80)
			return 4;
		return 0;
	}
	if (c == 0xF4) {
		if (n >= 4 && s[1] >= 0x80 && s[1] <= 0x8F &&
		    (s[2] & 0xC0) == 0x80 && (s[3] & 0xC0) == 0x80)
			return 4;
		return 0;
	}
	return 0;
}

/* 把截断点向下对齐到 UTF-8 字符边界（非法字节按 1 字节处理） */
static size_t utf8_floor(const char *s, size_t len)
{
	size_t i = 0;

	while (i < len) {
		size_t n = utf8_seq_len((const unsigned char *)s + i,
					len - i);

		if (n == 0)
			n = 1;
		if (i + n > len)
			break;
		i += n;
	}
	return i;
}

/* JSON 字符串转义；非法 UTF-8 字节替换为 U+FFFD，保证行是合法 UTF-8 */
static void sb_json_escape(struct sbuf *b, const char *s, size_t n)
{
	size_t i = 0;

	while (i < n) {
		unsigned char c = (unsigned char)s[i];
		char tmp[8];

		if (c < 0x80) {
			switch (c) {
			case '"':
				sb_puts(b, "\\\"");
				break;
			case '\\':
				sb_puts(b, "\\\\");
				break;
			case '\b':
				sb_puts(b, "\\b");
				break;
			case '\f':
				sb_puts(b, "\\f");
				break;
			case '\n':
				sb_puts(b, "\\n");
				break;
			case '\r':
				sb_puts(b, "\\r");
				break;
			case '\t':
				sb_puts(b, "\\t");
				break;
			default:
				if (c < 0x20) {
					snprintf(tmp, sizeof(tmp), "\\u%04x", c);
					sb_puts(b, tmp);
				} else {
					sb_putc(b, (char)c);
				}
			}
			i++;
			continue;
		}

		{
			size_t sl = utf8_seq_len((const unsigned char *)s + i,
						 n - i);

			if (sl == 0) {
				/* U+FFFD */
				sb_put(b, "\xEF\xBF\xBD", 3);
				i++;
			} else {
				sb_put(b, s + i, sl);
				i += sl;
			}
		}
	}
}

/* ---- 脱敏 ---- */

static int contains_sep(const char *s, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (s[i] == ':' || s[i] == '=' || s[i] == '"' ||
		    s[i] == '\'')
			return 1;
	return 0;
}

static int key_matches(const char *s, size_t len, size_t i, const char *key,
		       size_t *kl_out)
{
	size_t kl = strlen(key);
	unsigned char prev;
	unsigned char next;

	if (i + kl > len)
		return 0;
	if (strncasecmp(s + i, key, kl) != 0)
		return 0;
	prev = i ? (unsigned char)s[i - 1] : 0;
	if (isalnum(prev))
		return 0;
	next = i + kl < len ? (unsigned char)s[i + kl] : 0;
	if (!(next == ' ' || next == '\t' || next == '"' || next == '\'' ||
	      next == ':' || next == '='))
		return 0;
	*kl_out = kl;
	return 1;
}

/*
 * trace_redact - 统一脱敏
 * 覆盖（大小写不敏感，除非注明）：
 *   - sk-[A-Za-z0-9_-]{16,}
 *   - Bearer <token>
 *   - api_key/api-key/apikey、access_token/refresh_token/auth_token、
 *     token、password/passwd、secret、authorization 后跟 : / = / 引号的值
 * 返回 malloc 字符串（调用者 free）。
 */
static char *trace_redact(const char *s, size_t len)
{
	static const char *const keys[] = {
		"refresh_token", "access_token", "auth_token", "authorization",
		"api_key", "api-key", "apikey", "password", "passwd",
		"secret", "token",
	};
	struct sbuf out = { 0 };
	size_t i = 0;

	if (!s)
		return NULL;
	while (i < len) {
		/* Bearer token */
		if (i + 7 <= len && strncmp(s + i, "Bearer ", 7) == 0) {
			size_t j = i + 7;
			size_t v0 = j;

			while (j < len &&
			       (isalnum((unsigned char)s[j]) || s[j] == '.' ||
				s[j] == '_' || s[j] == '-' || s[j] == '+' ||
				s[j] == '/' || s[j] == '=' || s[j] == '~'))
				j++;
			if (j > v0 && !(j - v0 == 3 &&
					memcmp(s + v0, "***", 3) == 0)) {
				sb_puts(&out, "Bearer ***");
				i = j;
				continue;
			}
		}

		/* sk- 密钥 */
		if (i + 3 <= len && s[i] == 's' && s[i + 1] == 'k' &&
		    s[i + 2] == '-' &&
		    (i == 0 || (!isalnum((unsigned char)s[i - 1]) &&
				s[i - 1] != '_'))) {
			size_t j = i + 3;

			while (j < len &&
			       (isalnum((unsigned char)s[j]) ||
				s[j] == '_' || s[j] == '-'))
				j++;
			if (j - (i + 3) >= 16) {
				sb_puts(&out, "***");
				i = j;
				continue;
			}
		}

		/* key/value 形态 */
		{
			size_t k;
			int matched = 0;

			for (k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
				size_t kl = 0;
				size_t j;
				size_t sep_start;
				size_t v0;
				char quote = 0;
				size_t v_end;

				if (!key_matches(s, len, i, keys[k], &kl))
					continue;
				j = i + kl;
				sep_start = j;
				while (j < len &&
				       (s[j] == ' ' || s[j] == '\t' ||
					s[j] == '"' || s[j] == '\'' ||
					s[j] == ':' || s[j] == '=')) {
					if ((s[j] == '"' || s[j] == '\'') &&
					    quote == 0)
						quote = s[j];
					j++;
				}
				if (!contains_sep(s + sep_start, j - sep_start) ||
				    j >= len) {
					continue;
				}
				v0 = j;
				if (quote) {
					v_end = v0;
					while (v_end < len) {
						if (s[v_end] == '\\') {
							v_end += 2;
							continue;
						}
						if (s[v_end] == quote)
							break;
						v_end++;
					}
					if (v_end >= len)
						continue;
					if (v_end > v0 &&
					    !(v_end - v0 == 3 &&
					      memcmp(s + v0, "***", 3) == 0)) {
						sb_put(&out, s + i, v0 - i);
						sb_puts(&out, "***");
						sb_putc(&out, quote);
						i = v_end + 1;
						matched = 1;
					}
				} else {
					v_end = v0;
					while (v_end < len &&
					       !isspace((unsigned char)s[v_end]) &&
					       s[v_end] != ',' && s[v_end] != ';' &&
					       s[v_end] != '}' && s[v_end] != ']' &&
					       s[v_end] != '&')
						v_end++;
					if (v_end > v0 &&
					    !(v_end - v0 == 3 &&
					      memcmp(s + v0, "***", 3) == 0)) {
						sb_put(&out, s + i, v0 - i);
						sb_puts(&out, "***");
						i = v_end;
						matched = 1;
					}
				}
				if (matched)
					break;
			}
			if (matched)
				continue;
		}

		sb_putc(&out, s[i]);
		i++;
	}
	if (!out.p)
		return strdup("");
	out.p[out.len] = '\0';
	return out.p;
}

/* 添加 JSON 字符串字段（自动脱敏 + 截断 + 转义） */
static void sb_add_str(struct sbuf *b, const char *key, const char *val,
		       size_t max_bytes, int *truncated)
{
	char *red;
	size_t len;

	if (truncated)
		*truncated = 0;
	sb_key(b, key);
	if (!val) {
		sb_puts(b, "null");
		return;
	}
	red = trace_redact(val, strlen(val));
	if (!red) {
		sb_puts(b, "null");
		return;
	}
	len = strlen(red);
	if (max_bytes && len > max_bytes) {
		size_t cut = utf8_floor(red, max_bytes);

		if (truncated)
			*truncated = 1;
		sb_putc(b, '"');
		sb_json_escape(b, red, cut);
		sb_printf(b, "\\n[trace truncated: %zu bytes total]", len);
		sb_putc(b, '"');
		free(red);
		return;
	}
	sb_putc(b, '"');
	sb_json_escape(b, red, len);
	sb_putc(b, '"');
	free(red);
}

static void sb_add_int(struct sbuf *b, const char *key, long long v)
{
	sb_key(b, key);
	sb_printf(b, "%lld", v);
}

static void sb_add_bool(struct sbuf *b, const char *key, int v)
{
	sb_key(b, key);
	sb_puts(b, v ? "true" : "false");
}

/* ---- 配置解析 ---- */

static char *trim(char *s)
{
	char *e;

	while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
		s++;
	e = s + strlen(s);
	while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' ||
			 e[-1] == '\n'))
		e--;
	*e = '\0';
	return s;
}

static int parse_bool(const char *v, int def)
{
	if (!v)
		return def;
	if (!strcasecmp(v, "1") || !strcasecmp(v, "true") ||
	    !strcasecmp(v, "yes") || !strcasecmp(v, "on"))
		return 1;
	if (!strcasecmp(v, "0") || !strcasecmp(v, "false") ||
	    !strcasecmp(v, "no") || !strcasecmp(v, "off"))
		return 0;
	return def;
}

static int parse_int(const char *v, int def)
{
	char *end = NULL;
	long n;

	if (!v || !v[0])
		return def;
	n = strtol(v, &end, 10);
	if (!end || *end)
		return def;
	if (n < 1)
		return 1;
	if (n > 1000000)
		return 1000000;
	return (int)n;
}

static char *expand_home(const char *p)
{
	const char *home = getenv("HOME");
	char *out;

	if (!p)
		return NULL;
	if (p[0] == '~' && (p[1] == '/' || p[1] == '\0')) {
		if (!home || !home[0])
			home = "/tmp";
		if (asprintf(&out, "%s%s", home, p + 1) < 0)
			return NULL;
		return out;
	}
	return strdup(p);
}

static void config_defaults(struct ai_trace_config *cfg)
{
	const char *home = getenv("HOME");
	char *defdir;

	memset(cfg, 0, sizeof(*cfg));
	cfg->enabled = 1;
	cfg->max_file_mb = 64;
	cfg->max_files = 20;
	cfg->include_model_text = 1;
	cfg->max_payload_kb = 64;
	if (geteuid() == 0) {
		defdir = strdup("/var/log/aikernel/trace");
	} else if (home && home[0]) {
		if (asprintf(&defdir, "%s/.aikernel/trace", home) < 0)
			defdir = NULL;
	} else {
		defdir = strdup("/tmp/aikernel-trace");
	}
	cfg->dir = defdir ? defdir : strdup("/tmp/aikernel-trace");
}

void ai_trace_config_free(struct ai_trace_config *cfg)
{
	if (!cfg)
		return;
	free(cfg->dir);
	memset(cfg, 0, sizeof(*cfg));
}

static void parse_config_file(const char *path, struct ai_trace_config *cfg)
{
	FILE *fp;
	char line[1024];
	int in_trace = 1;   /* 无 section 时也接受键（容错） */

	fp = fopen(path, "r");
	if (!fp)
		return;
	while (fgets(line, sizeof(line), fp)) {
		char *s = trim(line);
		char *eq;
		char *k;
		char *v;

		if (!s[0] || s[0] == '#' || s[0] == ';')
			continue;
		if (s[0] == '[') {
			char *end = strchr(s, ']');

			if (end) {
				*end = '\0';
				in_trace = (strcmp(trim(s + 1), "trace") == 0);
			}
			continue;
		}
		if (!in_trace)
			continue;
		eq = strchr(s, '=');
		if (!eq)
			continue;
		*eq = '\0';
		k = trim(s);
		v = trim(eq + 1);
		if (v[0] == '"' || v[0] == '\'') {
			char q = v[0];
			size_t vl = strlen(v);

			if (vl >= 2 && v[vl - 1] == q) {
				v[vl - 1] = '\0';
				v++;
			}
		}
		if (!strcmp(k, "enabled"))
			cfg->enabled = parse_bool(v, cfg->enabled);
		else if (!strcmp(k, "dir")) {
			char *d = expand_home(v);

			if (d) {
				free(cfg->dir);
				cfg->dir = d;
			}
		} else if (!strcmp(k, "max_file_mb"))
			cfg->max_file_mb = parse_int(v, cfg->max_file_mb);
		else if (!strcmp(k, "max_files"))
			cfg->max_files = parse_int(v, cfg->max_files);
		else if (!strcmp(k, "include_model_text"))
			cfg->include_model_text =
				parse_bool(v, cfg->include_model_text);
		else if (!strcmp(k, "max_payload_kb"))
			cfg->max_payload_kb =
				parse_int(v, cfg->max_payload_kb);
	}
	fclose(fp);
}

int ai_trace_load_config(const char *config_path, struct ai_trace_config *cfg)
{
	const char *home;
	const char *env;
	char path[PATH_MAX];

	if (!cfg)
		return AI_ERR_INVALID_ARG;
	config_defaults(cfg);

	if (config_path && config_path[0]) {
		parse_config_file(config_path, cfg);
	} else {
		env = getenv("AIKERNEL_TRACE_CONFIG");
		if (env && env[0]) {
			parse_config_file(env, cfg);
		} else {
			home = getenv("HOME");
			if (home && home[0]) {
				snprintf(path, sizeof(path), "%s/.aikernel/trace.toml",
					 home);
				parse_config_file(path, cfg);
			}
			parse_config_file("/etc/aikernel/trace.toml", cfg);
		}
	}

	/* 环境变量覆盖（最高优先级） */
	env = getenv("AIKERNEL_TRACE_ENABLED");
	if (env)
		cfg->enabled = parse_bool(env, cfg->enabled);
	env = getenv("AIKERNEL_TRACE_DIR");
	if (env && env[0]) {
		char *d = expand_home(env);

		if (d) {
			free(cfg->dir);
			cfg->dir = d;
		}
	}
	env = getenv("AIKERNEL_TRACE_MAX_FILE_MB");
	if (env)
		cfg->max_file_mb = parse_int(env, cfg->max_file_mb);
	env = getenv("AIKERNEL_TRACE_MAX_FILES");
	if (env)
		cfg->max_files = parse_int(env, cfg->max_files);
	env = getenv("AIKERNEL_TRACE_INCLUDE_TEXT");
	if (env)
		cfg->include_model_text =
			parse_bool(env, cfg->include_model_text);
	env = getenv("AIKERNEL_TRACE_MAX_PAYLOAD_KB");
	if (env)
		cfg->max_payload_kb = parse_int(env, cfg->max_payload_kb);

	if (cfg->max_file_mb < 1)
		cfg->max_file_mb = 1;
	if (cfg->max_files < 1)
		cfg->max_files = 1;
	if (cfg->max_payload_kb < 1)
		cfg->max_payload_kb = 1;
	return AI_OK;
}

/* ---- 时间 / 哈希 ---- */

long long ai_trace_now_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

long long ai_trace_wall_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return 0;
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void ai_trace_format_ts(long long wall_ms, char *buf, size_t n)
{
	time_t sec = (time_t)(wall_ms / 1000);
	int ms = (int)(wall_ms % 1000);
	struct tm tm;
	char base[32];
	char zone[16];

	if (!buf || !n)
		return;
	if (!localtime_r(&sec, &tm)) {
		snprintf(buf, n, "1970-01-01T00:00:00.000+0000");
		return;
	}
	strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm);
	strftime(zone, sizeof(zone), "%z", &tm);
	snprintf(buf, n, "%s.%03d%s", base, ms, zone);
}

int ai_trace_hash_file(const char *path, char *out, size_t n)
{
	unsigned char buf[8192];
	uint64_t h = 1469598103934665603ULL;
	FILE *fp;
	size_t r;

	if (!out || !n)
		return AI_ERR_INVALID_ARG;
	if (!path || !(fp = fopen(path, "rb"))) {
		snprintf(out, n, "unavailable");
		return AI_ERR_NOT_FOUND;
	}
	while ((r = fread(buf, 1, sizeof(buf), fp)) > 0) {
		size_t i;

		for (i = 0; i < r; i++) {
			h ^= buf[i];
			h *= 1099511628211ULL;
		}
	}
	fclose(fp);
	snprintf(out, n, "%016llx", (unsigned long long)h);
	return AI_OK;
}

/* ---- 目录 / 文件 / 轮转 ---- */

static int mkdir_p(const char *path, mode_t mode)
{
	char tmp[PATH_MAX];
	size_t i;
	size_t len;

	if (!path || !path[0])
		return -1;
	len = strlen(path);
	if (len >= sizeof(tmp))
		return -1;
	memcpy(tmp, path, len + 1);
	for (i = 1; i < len; i++) {
		if (tmp[i] != '/')
			continue;
		tmp[i] = '\0';
		if (mkdir(tmp, mode) != 0 && errno != EEXIST)
			return -1;
		tmp[i] = '/';
	}
	if (mkdir(tmp, mode) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

static void warn_once(const char *what)
{
	if (g_warned)
		return;
	g_warned = 1;
	fprintf(stderr, "ai-trace: %s: %s (tracing disabled)\n",
		what, strerror(errno));
}

static int build_base_path(void)
{
	time_t now = time(NULL);
	struct tm tm;
	char stamp[32];
	int n;

	if (!localtime_r(&now, &tm))
		memset(&tm, 0, sizeof(tm));
	strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &tm);
	n = snprintf(g_base_path, sizeof(g_base_path),
		     "%s/trace-%s-%d-%d.jsonl", g_cfg.dir, stamp,
		     (int)getpid(), g_instance);
	if (n < 0 || (size_t)n >= sizeof(g_base_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	return 0;
}

static void rot_name(const char *base, int idx, char *out, size_t n)
{
	size_t len = strlen(base);
	size_t suffix = 6;   /* ".jsonl" */

	snprintf(out, n, "%.*s.%d.jsonl", (int)(len - suffix), base, idx);
}

/* 初始化时按 max_files 保留最新文件（跳过最近 5 秒内仍活跃的文件） */
struct prune_entry {
	char name[256];
	time_t mtime;
};

static int prune_cmp(const void *a, const void *b)
{
	const struct prune_entry *ea = a;
	const struct prune_entry *eb = b;

	if (ea->mtime != eb->mtime)
		return ea->mtime < eb->mtime ? -1 : 1;
	return strcmp(ea->name, eb->name);
}

/* 初始化时按 mtime 保留最新 max_files 个文件（跳过最近 5 秒活跃文件） */
static void prune_old_files(void)
{
	DIR *d;
	struct dirent *de;
	struct prune_entry *ents = NULL;
	int n = 0;
	int cap = 0;
	int i;
	time_t now = time(NULL);

	d = opendir(g_cfg.dir);
	if (!d)
		return;
	while ((de = readdir(d)) != NULL) {
		size_t nl = strlen(de->d_name);
		char full[PATH_MAX];
		struct stat st;

		if (strncmp(de->d_name, "trace-", 6) != 0)
			continue;
		if (nl < 6 || strcmp(de->d_name + nl - 6, ".jsonl") != 0)
			continue;
		snprintf(full, sizeof(full), "%s/%s", g_cfg.dir, de->d_name);
		if (stat(full, &st) != 0)
			continue;
		if (now - st.st_mtime < 5)
			continue;
		if (n == cap) {
			int nc = cap ? cap * 2 : 32;
			struct prune_entry *ne = realloc(ents,
						sizeof(*ne) * (size_t)nc);

			if (!ne)
				break;
			ents = ne;
			cap = nc;
		}
		snprintf(ents[n].name, sizeof(ents[n].name), "%s", de->d_name);
		ents[n].mtime = st.st_mtime;
		n++;
	}
	closedir(d);
	if (n <= g_cfg.max_files)
		goto out;
	qsort(ents, (size_t)n, sizeof(ents[0]), prune_cmp);
	for (i = 0; i < n - g_cfg.max_files; i++) {
		char full[PATH_MAX];

		snprintf(full, sizeof(full), "%s/%s", g_cfg.dir, ents[i].name);
		unlink(full);
	}
out:
	free(ents);
}

static int open_base_file(void)
{
	int fd;

	fd = open(g_base_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
		  0600);
	if (fd < 0) {
		warn_once("cannot open trace file");
		return -1;
	}
	g_fd = fd;
	g_cur_size = 0;
	{
		struct stat st;

		if (fstat(fd, &st) == 0 && st.st_size > 0)
			g_cur_size = (unsigned long long)st.st_size;
	}
	return 0;
}

static int rotate_locked(void)
{
	int i;

	if (g_fd >= 0) {
		close(g_fd);
		g_fd = -1;
	}
	for (i = g_cfg.max_files - 1; i >= 1; i--) {
		char oldp[PATH_MAX + 80];
		char newp[PATH_MAX + 80];

		rot_name(g_base_path, i, oldp, sizeof(oldp));
		if (i == g_cfg.max_files - 1) {
			unlink(oldp);
			continue;
		}
		rot_name(g_base_path, i + 1, newp, sizeof(newp));
		if (rename(oldp, newp) != 0 && errno != ENOENT) {
			/* 轮转失败不阻断：继续尝试打开新文件 */
		}
	}
	{
		char p1[PATH_MAX + 80];

		rot_name(g_base_path, 1, p1, sizeof(p1));
		if (rename(g_base_path, p1) != 0 && errno != ENOENT) {
			/* 保留原文件继续追加，避免丢日志 */
			return open_base_file();
		}
	}
	return open_base_file();
}

/* ---- 核心写入 ---- */

static int trace_write_event(const char *event, const struct sbuf *body)
{
	struct sbuf line = { 0 };
	char ts[64];
	long long wall;
	long long mono;
	int rc = 0;

	if (!g_inited || !g_enabled || g_failed)
		return -1;

	pthread_mutex_lock(&g_lock);
	if (!g_enabled || g_failed || g_fd < 0) {
		pthread_mutex_unlock(&g_lock);
		return -1;
	}
	g_seq++;
	wall = ai_trace_wall_ms();
	mono = ai_trace_now_ms();
	ai_trace_format_ts(wall, ts, sizeof(ts));

	sb_puts(&line, "{\"ts\":\"");
	sb_puts(&line, ts);
	sb_puts(&line, "\",\"mono_ms\":");
	sb_printf(&line, "%lld", mono);
	sb_puts(&line, ",\"session_id\":\"");
	sb_json_escape(&line, g_session_id, strlen(g_session_id));
	sb_puts(&line, "\",\"session\":\"");
	sb_json_escape(&line, g_session_name, strlen(g_session_name));
	sb_puts(&line, "\",\"turn\":");
	sb_printf(&line, "%d", g_turn);
	sb_puts(&line, ",\"event_seq\":");
	sb_printf(&line, "%llu", g_seq);
	sb_puts(&line, ",\"event\":\"");
	sb_json_escape(&line, event, strlen(event));
	sb_puts(&line, "\"");
	if (body && body->len) {
		sb_putc(&line, ',');
		sb_put(&line, body->p, body->len);
	}
	sb_puts(&line, "}\n");

	if (g_cur_size + line.len >
	    (unsigned long long)g_cfg.max_file_mb * 1024ULL * 1024ULL) {
		if (rotate_locked() != 0) {
			g_failed = 1;
			goto out;
		}
	}
	{
		ssize_t w = write(g_fd, line.p, line.len);

		if (w != (ssize_t)line.len) {
			warn_once("write failed");
			g_failed = 1;
			close(g_fd);
			g_fd = -1;
			rc = -1;
			goto out;
		}
		g_cur_size += (unsigned long long)w;
	}
	g_events++;
out:
	pthread_mutex_unlock(&g_lock);
	sb_free(&line);
	return rc;
}

/* ---- 初始化 / 关闭 ---- */

int ai_trace_init(const char *config_path, unsigned int flags)
{
	if (g_inited)
		ai_trace_shutdown();

	pthread_mutex_lock(&g_lock);
	memset(g_session_id, 0, sizeof(g_session_id));
	memset(g_session_name, 0, sizeof(g_session_name));
	g_seq = 0;
	g_req_seq = 0;
	g_events = 0;
	g_turns = 0;
	g_tool_calls = 0;
	g_model_requests = 0;
	g_degraded = 0;
	g_errors = 0;
	g_turn = 0;
	g_turn_start_mono = 0;
	g_failed = 0;
	g_warned = 0;
	g_session_started = 0;
	g_inited = 1;
	g_fd = -1;
	g_cur_size = 0;
	g_instance++;

	ai_trace_config_free(&g_cfg);
	ai_trace_load_config(config_path, &g_cfg);
	if (flags & AI_TRACE_FLAG_DISABLE)
		g_cfg.enabled = 0;
	if (!g_cfg.enabled) {
		g_enabled = 0;
		pthread_mutex_unlock(&g_lock);
		return AI_OK;
	}
	if (!g_cfg.dir || !g_cfg.dir[0]) {
		g_enabled = 0;
		pthread_mutex_unlock(&g_lock);
		return AI_ERR_STORAGE;
	}
	if (mkdir_p(g_cfg.dir, 0700) != 0) {
		warn_once("cannot create trace directory");
		g_enabled = 0;
		pthread_mutex_unlock(&g_lock);
		return AI_ERR_STORAGE;
	}
	{
		time_t now = time(NULL);
		struct tm tm;
		char stamp[24];

		if (!localtime_r(&now, &tm))
			memset(&tm, 0, sizeof(tm));
		strftime(stamp, sizeof(stamp), "%Y%m%dT%H%M%S", &tm);
		snprintf(g_session_id, sizeof(g_session_id), "s-%s-%d-%d",
			 stamp, (int)getpid(), g_instance);
	}
	if (build_base_path() != 0 || open_base_file() != 0) {
		g_enabled = 0;
		pthread_mutex_unlock(&g_lock);
		return AI_ERR_STORAGE;
	}
	prune_old_files();
	g_start_mono = ai_trace_now_ms();
	g_enabled = 1;
	pthread_mutex_unlock(&g_lock);
	return AI_OK;
}

void ai_trace_shutdown(void)
{
	pthread_mutex_lock(&g_lock);
	if (g_fd >= 0) {
		close(g_fd);
		g_fd = -1;
		/* 只初始化未写事件（如 trace stats 只读命令）→ 删除空文件 */
		if (g_events == 0 && g_base_path[0])
			unlink(g_base_path);
	}
	g_enabled = 0;
	g_inited = 0;
	g_session_started = 0;
	pthread_mutex_unlock(&g_lock);
	ai_trace_config_free(&g_cfg);
}

int ai_trace_is_enabled(void)
{
	return g_enabled;
}

const struct ai_trace_config *ai_trace_get_config(void)
{
	return &g_cfg;
}

unsigned long long ai_trace_event_count(void)
{
	return __atomic_load_n(&g_events, __ATOMIC_RELAXED);
}

/* ---- 事件发射 ---- */

int ai_trace_session_start(const char *session, const char *model,
			   const char *provider, int ctx_len, int max_tokens,
			   int stream, const char *routing,
			   const char *tools_hash)
{
	struct sbuf b = { 0 };

	if (!g_enabled)
		return -1;
	pthread_mutex_lock(&g_lock);
	if (g_session_started) {
		pthread_mutex_unlock(&g_lock);
		return 0;
	}
	snprintf(g_session_name, sizeof(g_session_name), "%s",
		 session && session[0] ? session : "default");
	g_session_started = 1;
	pthread_mutex_unlock(&g_lock);

	sb_add_str(&b, "model", model, 0, NULL);
	sb_add_str(&b, "provider", provider, 0, NULL);
	sb_add_int(&b, "pid", (long long)getpid());
	sb_add_int(&b, "uid", (long long)geteuid());
	sb_add_str(&b, "version", AI_TRACE_VERSION, 0, NULL);
	sb_key(&b, "config");
	sb_putc(&b, '{');
	sb_add_int(&b, "ctx_len", ctx_len);
	sb_add_int(&b, "max_tokens", max_tokens);
	sb_add_bool(&b, "stream", stream);
	sb_add_str(&b, "routing", routing ? routing : "-", 0, NULL);
	sb_putc(&b, '}');
	sb_add_str(&b, "tools_hash", tools_hash ? tools_hash : "unavailable",
		   0, NULL);
	sb_add_int(&b, "schema_version", 1);
	trace_write_event("session_start", &b);
	sb_free(&b);
	return 1;
}

int ai_trace_session_end(const char *reason)
{
	struct sbuf b = { 0 };
	long long dur;

	if (!g_enabled || !g_session_started)
		return -1;
	dur = ai_trace_now_ms() - g_start_mono;
	sb_add_str(&b, "reason", reason ? reason : "exit", 0, NULL);
	sb_add_int(&b, "duration_ms", dur);
	sb_add_int(&b, "turns",
		   (long long)__atomic_load_n(&g_turns, __ATOMIC_RELAXED));
	sb_add_int(&b, "model_requests",
		   (long long)__atomic_load_n(&g_model_requests,
					      __ATOMIC_RELAXED));
	sb_add_int(&b, "tool_calls",
		   (long long)__atomic_load_n(&g_tool_calls, __ATOMIC_RELAXED));
	sb_add_int(&b, "degraded",
		   (long long)__atomic_load_n(&g_degraded, __ATOMIC_RELAXED));
	sb_add_int(&b, "errors",
		   (long long)__atomic_load_n(&g_errors, __ATOMIC_RELAXED));
	sb_add_int(&b, "events",
		   (long long)__atomic_load_n(&g_events, __ATOMIC_RELAXED));
	trace_write_event("session_end", &b);
	sb_free(&b);
	g_session_started = 0;
	return 0;
}

int ai_trace_turn_start(const char *question)
{
	struct sbuf b = { 0 };
	int turn;

	if (!g_enabled)
		return 0;
	pthread_mutex_lock(&g_lock);
	g_turn++;
	turn = g_turn;
	g_turn_start_mono = ai_trace_now_ms();
	pthread_mutex_unlock(&g_lock);

	sb_add_int(&b, "turn", turn);
	sb_add_str(&b, "question", question ? question : "", 0, NULL);
	trace_write_event("turn_start", &b);
	sb_free(&b);
	__atomic_add_fetch(&g_turns, 1, __ATOMIC_RELAXED);
	return turn;
}

int ai_trace_turn_end(const char *reason, int rounds)
{
	struct sbuf b = { 0 };
	long long dur = 0;

	if (!g_enabled)
		return -1;
	if (g_turn_start_mono > 0)
		dur = ai_trace_now_ms() - g_turn_start_mono;
	sb_add_int(&b, "turn", g_turn);
	sb_add_int(&b, "duration_ms", dur);
	sb_add_int(&b, "rounds", rounds);
	sb_add_str(&b, "end_reason", reason ? reason : "completed", 0, NULL);
	trace_write_event("turn_end", &b);
	sb_free(&b);
	return 0;
}

int ai_trace_current_turn(void)
{
	return g_turn;
}

const char *ai_trace_session_id(void)
{
	return g_session_id;
}

/* 从 tools_json 提取 function.name 列表（非全文） */
static void add_tool_names(struct sbuf *b, const char *tools_json)
{
	const char *p = tools_json;
	int count = 0;

	sb_key(b, "tools");
	sb_puts(b, "[");
	if (p) {
		while ((p = strstr(p, "\"name\"")) != NULL) {
			const char *q = p + 6;
			const char *e;

			while (*q == ' ' || *q == '\t')
				q++;
			if (*q != ':') {
				p += 6;
				continue;
			}
			q++;
			while (*q == ' ' || *q == '\t')
				q++;
			if (*q != '"') {
				p += 6;
				continue;
			}
			q++;
			e = q;
			while (*e && *e != '"' && *e != '\\')
				e++;
			if (e > q) {
				if (count)
					sb_putc(b, ',');
				sb_putc(b, '"');
				sb_json_escape(b, q, (size_t)(e - q));
				sb_putc(b, '"');
				count++;
			}
			p = e;
		}
	}
	sb_puts(b, "],\"tool_count\":");
	sb_printf(b, "%d", count);
}

static long est_tokens_msgs(const struct ai_chat_msg *msgs, int nmsgs,
			    const char *tools_json)
{
	long bytes = 0;
	int i;

	for (i = 0; i < nmsgs; i++) {
		if (msgs[i].content)
			bytes += (long)strlen(msgs[i].content);
		if (msgs[i].tool_calls_json)
			bytes += (long)strlen(msgs[i].tool_calls_json);
	}
	if (tools_json)
		bytes += (long)strlen(tools_json) / 4;
	return bytes / 3 + 1;
}

char *ai_trace_model_request(const char *provider, const char *model,
			     const struct ai_chat_msg *msgs, int nmsgs,
			     const char *tools_json, int stream)
{
	struct sbuf b = { 0 };
	char id[160];
	unsigned long long n;
	size_t max_payload;
	int i;

	if (!g_enabled)
		return NULL;
	n = __atomic_add_fetch(&g_req_seq, 1, __ATOMIC_RELAXED);
	snprintf(id, sizeof(id), "req-%s-%llu", g_session_id, n);

	sb_add_str(&b, "provider", provider, 0, NULL);
	sb_add_str(&b, "model", model, 0, NULL);
	sb_add_str(&b, "request_id", id, 0, NULL);
	sb_add_bool(&b, "stream", stream);
	sb_add_int(&b, "message_count", nmsgs);
	{
		long est = est_tokens_msgs(msgs, nmsgs, tools_json);

		sb_add_int(&b, "est_tokens", est);
	}
	add_tool_names(&b, tools_json);

	max_payload = (size_t)g_cfg.max_payload_kb * 1024;
	sb_key(&b, "messages");
	sb_putc(&b, '[');
	for (i = 0; i < nmsgs; i++) {
		int trunc = 0;

		if (i)
			sb_putc(&b, ',');
		sb_putc(&b, '{');
		sb_add_str(&b, "role", msgs[i].role ? msgs[i].role : "-", 0,
			   NULL);
		if (g_cfg.include_model_text) {
			sb_add_str(&b, "content", msgs[i].content, max_payload,
				   &trunc);
		} else {
			sb_add_int(&b, "content_bytes",
				   msgs[i].content ?
				   (long long)strlen(msgs[i].content) : 0);
			sb_add_bool(&b, "content_omitted", 1);
		}
		if (msgs[i].tool_call_id)
			sb_add_str(&b, "tool_call_id", msgs[i].tool_call_id, 0,
				   NULL);
		if (msgs[i].tool_name)
			sb_add_str(&b, "tool_name", msgs[i].tool_name, 0, NULL);
		if (msgs[i].tool_calls_json) {
			int t2 = 0;

			sb_add_str(&b, "tool_calls", msgs[i].tool_calls_json,
				   max_payload, &t2);
			if (t2)
				sb_add_bool(&b, "tool_calls_truncated", 1);
		}
		sb_putc(&b, '}');
	}
	sb_putc(&b, ']');
	trace_write_event("model_request", &b);
	sb_free(&b);
	__atomic_add_fetch(&g_model_requests, 1, __ATOMIC_RELAXED);
	return strdup(id);
}

int ai_trace_model_response(const char *request_id,
			    const struct ai_chat_result *result,
			    long elapsed_ms)
{
	struct sbuf b = { 0 };
	size_t max_payload = (size_t)g_cfg.max_payload_kb * 1024;
	int i;

	if (!g_enabled || !result)
		return -1;
	sb_add_str(&b, "request_id", request_id, 0, NULL);
	if (g_cfg.include_model_text) {
		int trunc = 0;

		sb_add_str(&b, "content", result->content, max_payload,
			   &trunc);
		if (trunc)
			sb_add_bool(&b, "content_truncated", 1);
	} else {
		sb_add_int(&b, "content_bytes",
			   result->content ?
			   (long long)strlen(result->content) : 0);
		sb_add_bool(&b, "content_omitted", 1);
	}
	sb_key(&b, "tool_calls");
	sb_putc(&b, '[');
	for (i = 0; i < result->tool_call_count; i++) {
		const struct ai_tool_call *tc = &result->tool_calls[i];
		int trunc = 0;

		if (i)
			sb_putc(&b, ',');
		sb_putc(&b, '{');
		sb_add_str(&b, "id", tc->id, 0, NULL);
		sb_add_str(&b, "name", tc->name, 0, NULL);
		sb_add_str(&b, "arguments", tc->arguments, max_payload,
			   &trunc);
		if (trunc)
			sb_add_bool(&b, "arguments_truncated", 1);
		sb_putc(&b, '}');
	}
	sb_putc(&b, ']');
	sb_add_int(&b, "tool_call_count", result->tool_call_count);
	sb_add_bool(&b, "has_tool_calls", result->tool_call_count > 0);
	sb_add_str(&b, "finish_reason", result->finish_reason, 0, NULL);
	sb_add_int(&b, "elapsed_ms", elapsed_ms);
	sb_add_int(&b, "prompt_tokens", result->prompt_tokens);
	sb_add_int(&b, "completion_tokens", result->completion_tokens);
	sb_add_int(&b, "total_tokens",
		   (long long)result->prompt_tokens + result->completion_tokens);
	sb_add_int(&b, "http_status", result->http_status);
	trace_write_event("model_response", &b);
	sb_free(&b);
	return 0;
}

int ai_trace_route_activate(const char *trigger_token,
			    const char *const *tools, int ntools,
			    int active_before, int active_after)
{
	struct sbuf b = { 0 };
	int i;

	if (!g_enabled)
		return -1;
	sb_add_str(&b, "trigger_token", trigger_token, 0, NULL);
	sb_key(&b, "tools_hit");
	sb_putc(&b, '[');
	for (i = 0; i < ntools; i++) {
		if (i)
			sb_putc(&b, ',');
		if (tools && tools[i]) {
			sb_putc(&b, '"');
			sb_json_escape(&b, tools[i], strlen(tools[i]));
			sb_putc(&b, '"');
		} else {
			sb_puts(&b, "null");
		}
	}
	sb_putc(&b, ']');
	sb_add_int(&b, "tool_count_hit", ntools);
	sb_add_int(&b, "active_before", active_before);
	sb_add_int(&b, "active_after", active_after);
	trace_write_event("route_activate", &b);
	sb_free(&b);
	return 0;
}

/* W77c：字符串数组字段（NULL 元素写 null） */
static void sb_add_str_array(struct sbuf *b, const char *key,
			     const char *const *vals, int n)
{
	int i;

	sb_key(b, key);
	sb_putc(b, '[');
	for (i = 0; i < n; i++) {
		if (i)
			sb_putc(b, ',');
		if (vals && vals[i]) {
			sb_putc(b, '"');
			sb_json_escape(b, vals[i], strlen(vals[i]));
			sb_putc(b, '"');
		} else {
			sb_puts(b, "null");
		}
	}
	sb_putc(b, ']');
}

int ai_trace_clarify_request(const char *nonce, const char *kind,
			     const char *question,
			     const char *const *option_ids, int n_options,
			     const char *recommended, int multi_select,
			     int tty)
{
	struct sbuf b = { 0 };

	if (!g_enabled)
		return -1;
	sb_add_str(&b, "nonce", nonce, 0, NULL);
	sb_add_str(&b, "kind", kind, 0, NULL);
	sb_add_str(&b, "question", question, 0, NULL);
	sb_add_str_array(&b, "option_ids", option_ids, n_options);
	if (recommended && recommended[0])
		sb_add_str(&b, "recommended", recommended, 0, NULL);
	sb_add_bool(&b, "multi_select", multi_select);
	sb_add_bool(&b, "tty", tty);
	trace_write_event("clarify_request", &b);
	sb_free(&b);
	return 0;
}

int ai_trace_clarify_answer(const char *nonce, const char *kind,
			    const char *const *option_ids, int n_options,
			    const char *recommended,
			    const char *const *selected_ids, int n_selected,
			    const char *selected_text, const char *status,
			    int attempts, long elapsed_ms)
{
	struct sbuf b = { 0 };

	if (!g_enabled)
		return -1;
	sb_add_str(&b, "nonce", nonce, 0, NULL);
	sb_add_str(&b, "kind", kind, 0, NULL);
	sb_add_str_array(&b, "option_ids", option_ids, n_options);
	if (recommended && recommended[0])
		sb_add_str(&b, "recommended", recommended, 0, NULL);
	sb_add_str_array(&b, "selected_ids", selected_ids, n_selected);
	sb_add_str(&b, "selected_text", selected_text, 0, NULL);
	sb_add_str(&b, "status", status, 0, NULL);
	sb_add_int(&b, "attempts", attempts);
	sb_add_int(&b, "elapsed_ms", elapsed_ms);
	trace_write_event("clarify_answer", &b);
	sb_free(&b);
	return 0;
}

int ai_trace_tool_call(const char *tool, const char *channel,
		       const char *risk, const char *args_json,
		       long long start_wall_ms, long duration_ms,
		       int ok, int exit_code,
		       const char *result, size_t result_len)
{
	return ai_trace_tool_call_status(tool, channel, risk, args_json,
					 start_wall_ms, duration_ms,
					 ok ? AI_TRACE_STATUS_OK :
					 AI_TRACE_STATUS_FAIL,
					 exit_code, result, result_len);
}

int ai_trace_tool_call_status(const char *tool, const char *channel,
			      const char *risk, const char *args_json,
			      long long start_wall_ms, long duration_ms,
			      const char *status, int exit_code,
			      const char *result, size_t result_len)
{
	return ai_trace_tool_call_ex(tool, channel, risk, args_json,
				     start_wall_ms, duration_ms, status,
				     exit_code, result, result_len,
				     NULL, NULL);
}

int ai_trace_tool_call_ex(const char *tool, const char *channel,
			  const char *risk, const char *args_json,
			  long long start_wall_ms, long duration_ms,
			  const char *status, int exit_code,
			  const char *result, size_t result_len,
			  const char *danger, const char *lease_id)
{
	struct sbuf b = { 0 };
	size_t max_payload = (size_t)g_cfg.max_payload_kb * 1024;
	char start_ts[64];
	size_t total = result_len;
	int trunc = 0;

	if (!g_enabled)
		return -1;
	if (!total && result)
		total = strlen(result);
	if (start_wall_ms > 0)
		ai_trace_format_ts(start_wall_ms, start_ts, sizeof(start_ts));
	else
		start_ts[0] = '\0';

	sb_add_str(&b, "tool", tool, 0, NULL);
	sb_add_str(&b, "channel", channel, 0, NULL);
	sb_add_str(&b, "risk", risk, 0, NULL);
	sb_add_str(&b, "args", args_json && args_json[0] ? args_json : "{}",
		   0, NULL);
	if (start_ts[0])
		sb_add_str(&b, "start_ts", start_ts, 0, NULL);
	sb_add_int(&b, "duration_ms", duration_ms);
	sb_add_str(&b, "status", status ? status : AI_TRACE_STATUS_FAIL, 0,
		   NULL);
	sb_add_bool(&b, "ok", status && strcmp(status, AI_TRACE_STATUS_OK) == 0);
	sb_add_int(&b, "exit_code", exit_code);
	sb_add_int(&b, "result_bytes", (long long)total);
	sb_add_str(&b, "result", result, max_payload, &trunc);
	if (trunc)
		sb_add_bool(&b, "result_truncated", 1);
	if (danger && danger[0])
		sb_add_str(&b, "danger", danger, 0, NULL);
	if (lease_id && lease_id[0])
		sb_add_str(&b, "lease_id", lease_id, 0, NULL);
	trace_write_event("tool_call", &b);
	sb_free(&b);
	__atomic_add_fetch(&g_tool_calls, 1, __ATOMIC_RELAXED);
	return 0;
}

int ai_trace_policy_decision(const char *gate, const char *decision,
			     const char *reason, const char *tool,
			     const char *confirm_source,
			     const char *args_json)
{
	return ai_trace_policy_decision_ex(gate, decision, reason, tool,
					   confirm_source, args_json,
					   NULL, NULL, NULL, NULL, NULL);
}

int ai_trace_policy_decision_ex(const char *gate, const char *decision,
				const char *reason, const char *tool,
				const char *confirm_source,
				const char *args_json,
				const char *lease_id, const char *danger,
				const char *confirmation,
				const char *pending_nonce,
				const char *lease_source)
{
	struct sbuf b = { 0 };

	if (!g_enabled)
		return -1;
	sb_add_str(&b, "gate", gate, 0, NULL);
	sb_add_str(&b, "decision", decision, 0, NULL);
	sb_add_str(&b, "reason", reason, 0, NULL);
	sb_add_str(&b, "tool", tool, 0, NULL);
	sb_add_str(&b, "confirm_source", confirm_source, 0, NULL);
	sb_add_str(&b, "args", args_json && args_json[0] ? args_json : "{}",
		   0, NULL);
	if (lease_id && lease_id[0])
		sb_add_str(&b, "lease_id", lease_id, 0, NULL);
	if (danger && danger[0])
		sb_add_str(&b, "danger", danger, 0, NULL);
	if (confirmation && confirmation[0])
		sb_add_str(&b, "confirmation", confirmation, 0, NULL);
	if (pending_nonce && pending_nonce[0])
		sb_add_str(&b, "pending_nonce", pending_nonce, 0, NULL);
	if (lease_source && lease_source[0])
		sb_add_str(&b, "lease_source", lease_source, 0, NULL);
	sb_add_int(&b, "uid", (long long)getuid());
	trace_write_event("policy_decision", &b);
	sb_free(&b);
	return 0;
}

int ai_trace_degraded(const char *component, const char *reason_code,
		      const char *detail)
{
	struct sbuf b = { 0 };

	if (!g_enabled)
		return -1;
	sb_add_str(&b, "component", component, 0, NULL);
	sb_add_str(&b, "reason_code", reason_code, 0, NULL);
	sb_add_str(&b, "detail", detail, 0, NULL);
	trace_write_event("degraded", &b);
	sb_free(&b);
	__atomic_add_fetch(&g_degraded, 1, __ATOMIC_RELAXED);
	return 0;
}

int ai_trace_error(const char *phase, const char *code, const char *message)
{
	struct sbuf b = { 0 };

	if (!g_enabled)
		return -1;
	sb_add_str(&b, "phase", phase, 0, NULL);
	sb_add_str(&b, "code", code, 0, NULL);
	sb_add_str(&b, "message", message, 0, NULL);
	trace_write_event("error", &b);
	sb_free(&b);
	__atomic_add_fetch(&g_errors, 1, __ATOMIC_RELAXED);
	return 0;
}
