/* SPDX-License-Identifier: GPL-2.0 */
/*
 * trace.c - occ 工具执行审计 trace JSONL（T9b1）
 *
 * ~/.occ/trace/<session>.jsonl，每次工具执行一行：
 *   {"ts":"2026-11-07T12:34:56.789+0800","mono_ms":123,"session":
 *    "ses_…","msg":"msg_…","seq":N,"event":"tool_exec","tool":"read",
 *    "args":"…(≤256B 摘要)","rc":0,"dur_ms":12,"out_bytes":1234}
 *
 * 形态对齐系统 ai_trace.c（trace/ai_trace.c）：
 *   - 头字段 ts（ISO8601+毫秒+时区）+ mono_ms（CLOCK_MONOTONIC）+ 递增 seq；
 *   - 单例单写：整行内存拼装后一次 write（O_APPEND|O_CLOEXEC），行内
 *     绝不交错；
 *   - 永不阻断：打开/写失败仅 stderr 警告一次，随后静默丢弃（审计不
 *     拖垮对话主流程）。
 */
#define _GNU_SOURCE
#include "occ_tools.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static unsigned long long g_seq;
static int g_warned;

/* ---- JSON 字符串转义（args 摘要用；控制字符 \u 化） ---- */

static size_t json_escape(const char *s, size_t len, char *out,
			  size_t outlen)
{
	size_t i, j = 0;

	for (i = 0; i < len && j + 8 < outlen; i++) {
		unsigned char c = (unsigned char)s[i];

		switch (c) {
		case '"':
			out[j++] = '\\';
			out[j++] = '"';
			break;
		case '\\':
			out[j++] = '\\';
			out[j++] = '\\';
			break;
		case '\n':
			out[j++] = '\\';
			out[j++] = 'n';
			break;
		case '\r':
			out[j++] = '\\';
			out[j++] = 'r';
			break;
		case '\t':
			out[j++] = '\\';
			out[j++] = 't';
			break;
		default:
			if (c < 0x20) {
				j += (size_t)snprintf(out + j, outlen - j,
						      "\\u%04x", c);
			} else {
				out[j++] = (char)c;
			}
			break;
		}
	}
	out[j] = '\0';
	return j;
}

/* ISO8601 + 毫秒 + 时区（ai_trace 同风格） */
static void fmt_ts(char *buf, size_t buflen)
{
	struct timespec ts;
	struct tm tm;
	char tz[8];
	long long ms;

	clock_gettime(CLOCK_REALTIME, &ts);
	localtime_r(&ts.tv_sec, &tm);
	strftime(buf, buflen, "%Y-%m-%dT%H:%M:%S", &tm);
	ms = ts.tv_nsec / 1000000;
	strftime(tz, sizeof(tz), "%z", &tm);
	snprintf(buf + strlen(buf), buflen - strlen(buf),
		 ".%03lld%s", ms, tz);
}

static void trace_warn_once(const char *path, const char *why)
{
	if (!g_warned) {
		fprintf(stderr, "occ-trace: %s: %s（trace 丢弃，不阻断）\n",
			path, why);
		g_warned = 1;
	}
}

int occ_trace_tool(const char *trace_dir, const char *session_id,
		   const char *msg_id, const char *tool,
		   const char *args_json, int rc, long long dur_ms,
		   size_t out_bytes)
{
	char path[4300];
	char line[4096];
	char ts[48];
	char args_esc[600];
	char dir[4096];
	const char *dirp = trace_dir && trace_dir[0] ? trace_dir : NULL;
	static char defdir[512];
	int fd;
	ssize_t wl;

	if (!session_id || !session_id[0])
		return -1;
	if (!dirp) {
		const char *env = getenv("OCC_TRACE_DIR");
		const char *home;

		if (env && env[0]) {
			snprintf(defdir, sizeof(defdir), "%s", env);
		} else if ((home = getenv("HOME")) != NULL) {
			snprintf(defdir, sizeof(defdir), "%s/.occ/trace",
				 home);
		} else {
			return -1;
		}
		dirp = defdir;
	}
	snprintf(dir, sizeof(dir), "%s", dirp);
	/* 递归建目录（一次 mkdir -p；失败即警告丢弃） */
	for (char *p = dir + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(dir, 0755) && errno != EEXIST) {
				trace_warn_once(dir, strerror(errno));
				return -1;
			}
			*p = '/';
		}
	}
	if (mkdir(dir, 0755) && errno != EEXIST) {
		trace_warn_once(dir, strerror(errno));
		return -1;
	}
	snprintf(path, sizeof(path), "%s/%s.jsonl", dir, session_id);

	/* args 摘要：UTF-8 边界安全截 256 字节后转义 */
	{
		char raw[512];
		size_t alen = args_json ? strlen(args_json) : 0;
		size_t keep = alen > 256 ? 256 : alen;

		if (keep < alen) {
			size_t cut = keep;

			while (cut > 0 &&
			       ((unsigned char)args_json[cut] & 0xC0) ==
			       0x80)
				cut--;
			if (cut == 0)
				cut = keep;
			keep = cut;
		}
		if (alen) {
			memcpy(raw, args_json, keep);
			raw[keep] = '\0';
			if (keep < alen)
				strcat(raw + keep, "…");
		} else {
			strcpy(raw, "{}");
		}
		json_escape(raw, strlen(raw), args_esc, sizeof(args_esc));
	}
	fmt_ts(ts, sizeof(ts));
	g_seq++;
	snprintf(line, sizeof(line),
		 "{\"ts\":\"%s\",\"mono_ms\":%lld,\"session\":\"%s\","
		 "\"msg\":\"%s\",\"seq\":%llu,\"event\":\"tool_exec\","
		 "\"tool\":\"%s\",\"args\":\"%s\",\"rc\":%d,"
		 "\"dur_ms\":%lld,\"out_bytes\":%zu}\n",
		 ts, occ_monotonic_ms(), session_id,
		 msg_id ? msg_id : "", g_seq, tool ? tool : "",
		 args_esc, rc, dur_ms, out_bytes);
	fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
	if (fd < 0) {
		trace_warn_once(path, strerror(errno));
		return -1;
	}
	wl = write(fd, line, strlen(line));
	if (wl < 0)
		trace_warn_once(path, strerror(errno));
	close(fd);
	return 0;
}
