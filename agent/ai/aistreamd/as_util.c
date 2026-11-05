/* SPDX-License-Identifier: GPL-2.0 */
/*
 * as_util.c - 时间/FNV 哈希/限频日志/原子写文件
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "as_util.h"

long long as_now_mono_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

long long as_now_real_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

long long as_now_mono_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

uint64_t as_fnv1a64(const char *s, size_t n)
{
	/* FNV-1a 64bit 标准参数（offset/prime） */
	uint64_t h = 0xcbf29ce484222325ULL;

	for (size_t i = 0; i < n; i++) {
		h ^= (unsigned char)s[i];
		h *= 0x100000001b3ULL;
	}
	return h;
}

void as_digest_hex(uint64_t d, char out[17])
{
	snprintf(out, 17, "%016llx", (unsigned long long)d);
}

/* ---- 限频日志：同 key 冷却窗口内只输出一条 ---- */

struct rl_entry {
	const char *key;		/* 静态字面量，只比较指针 */
	long long last_ms;
};

#define RL_MAX 64

static struct rl_entry rl_tab[RL_MAX];
static int rl_cnt;
static int log_debug_on;

void as_set_debug(int on)
{
	log_debug_on = on;
}

int as_warn_ratelimit(const char *key, long long cooldown_ms,
		      const char *fmt, ...)
{
	long long now = as_now_mono_ms();
	va_list ap;

	for (int i = 0; i < rl_cnt; i++) {
		if (rl_tab[i].key == key) {
			if (now - rl_tab[i].last_ms < cooldown_ms)
				return 0;
			rl_tab[i].last_ms = now;
			goto emit;
		}
	}
	if (rl_cnt < RL_MAX) {
		rl_tab[rl_cnt].key = key;
		rl_tab[rl_cnt].last_ms = now;
		rl_cnt++;
	}
emit:
	fputs("aistreamd: ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	return 1;
}

void as_log(const char *fmt, ...)
{
	va_list ap;

	fputs("aistreamd: ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

void as_log_debug(const char *fmt, ...)
{
	va_list ap;

	if (!log_debug_on)
		return;
	fputs("aistreamd: [debug] ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

int as_write_file_atomic(const char *path, const char *data, size_t len)
{
	char tmp[512];
	FILE *f;
	int fd;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	f = fopen(tmp, "w");
	if (!f)
		return -1;
	fd = fileno(f);
	if (write(fd, data, len) != (ssize_t)len) {
		int e = errno;

		fclose(f);
		unlink(tmp);
		errno = e;
		return -1;
	}
	if (fclose(f) != 0) {
		unlink(tmp);
		return -1;
	}
	if (rename(tmp, path) != 0) {
		unlink(tmp);
		return -1;
	}
	return 0;
}
