/* SPDX-License-Identifier: GPL-2.0 */
/*
 * main.c - T4b `smehttp` 二进制（T4B-DESIGN.md §4）
 *
 *   smehttp --config PATH [--host 127.0.0.1] [--port 8000]
 *           [--frozen-now SECONDS]
 *
 * 读配置（--config 省略时用内置默认）→ 建 engine（真实 /dev/urandom id；
 * --frozen-now 时注入冻结时钟，供差分回放）→ storage.path 指向的文件存在
 * 则 aik_engine_load（失败退出非 0）→ 绑定 → stdout 打印
 * `LISTENING <actual_port>\n` 并 flush → 循环 serve_one → SIGINT/SIGTERM
 * 干净退出（0）。
 *
 * 默认监听取配置的 api.host/api.port（缺省 127.0.0.1:8000），--host/--port
 * 覆盖；--port 0 由内核选端口（测试用）。
 */
#define _POSIX_C_SOURCE 200809L

#include "smehttp/http.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

/* ------------------------------------------------------------------ */
/* 时钟                                                               */
/* ------------------------------------------------------------------ */
static int g_frozen;
static double g_frozen_now;

static double now_seconds(void *ud)
{
	(void)ud;
	if (g_frozen)
		return g_frozen_now;
	return (double)time(NULL);
}

/* ------------------------------------------------------------------ */
/* id 生成：<prefix>_ + 12 位小写十六进制（id_fn 契约 out[16]）        */
/* ------------------------------------------------------------------ */
static int g_urandom = -1;
static unsigned long long g_seq;

static int random_id(void *ud, const char *prefix, char out[16])
{
	char p = (prefix && prefix[0]) ? prefix[0] : 'x';
	unsigned long long v;
	unsigned char buf[6];

	(void)ud;
	if (g_urandom >= 0) {
		ssize_t n = read(g_urandom, buf, sizeof(buf));

		if (n == (ssize_t)sizeof(buf)) {
			size_t i;

			v = 0;
			for (i = 0; i < sizeof(buf); i++)
				v = (v << 8) | (unsigned long long)buf[i];
			snprintf(out, 16, "%c_%012llx", p,
				 v & 0xffffffffffffULL);
			return 0;
		}
	}
	/* 回退：单调计数器（种子掺入启动时间/pid，避免跨进程重复） */
	g_seq = (g_seq + 1) & 0xffffffffffffULL;
	snprintf(out, 16, "%c_%012llx", p, g_seq);
	return 0;
}

static void id_init(void)
{
	g_urandom = open("/dev/urandom", O_RDONLY);
	if (g_urandom < 0)
		g_urandom = -1;
	g_seq = (((unsigned long long)time(NULL) << 20) ^
		 ((unsigned long long)getpid() & 0xfffffULL)) &
		0xffffffffffffULL;
}

/* ------------------------------------------------------------------ */
/* 参数                                                               */
/* ------------------------------------------------------------------ */
static void usage(FILE *out)
{
	fprintf(out,
		"usage: smehttp --config PATH [--host HOST] [--port PORT]\n"
		"               [--frozen-now SECONDS]\n");
}

static int parse_port(const char *s, int *out)
{
	char *end = NULL;
	long v;

	if (!s || !*s)
		return -1;
	v = strtol(s, &end, 10);
	if (end == s || *end != '\0' || v < 0 || v > 65535)
		return -1;
	*out = (int)v;
	return 0;
}

int main(int argc, char **argv)
{
	const char *config_path = NULL;
	const char *host_arg = NULL;
	const char *frozen_arg = NULL;
	const char *cfg_host;
	const char *storage_path;
	int port_arg = -1;
	int have_port = 0;
	int i;
	char err[512];
	aik_config *cfg;
	aik_engine *engine;
	aik_http_server *server;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--config") == 0) {
			if (++i >= argc) {
				usage(stderr);
				return 2;
			}
			config_path = argv[i];
		} else if (strcmp(argv[i], "--host") == 0) {
			if (++i >= argc) {
				usage(stderr);
				return 2;
			}
			host_arg = argv[i];
		} else if (strcmp(argv[i], "--port") == 0) {
			if (++i >= argc || parse_port(argv[i], &port_arg) != 0) {
				fprintf(stderr, "smehttp: invalid --port\n");
				return 2;
			}
			have_port = 1;
		} else if (strcmp(argv[i], "--frozen-now") == 0) {
			if (++i >= argc) {
				usage(stderr);
				return 2;
			}
			frozen_arg = argv[i];
		} else if (strcmp(argv[i], "--help") == 0 ||
			   strcmp(argv[i], "-h") == 0) {
			usage(stdout);
			return 0;
		} else {
			fprintf(stderr, "smehttp: unknown argument '%s'\n",
				argv[i]);
			usage(stderr);
			return 2;
		}
	}
	if (frozen_arg) {
		char *end = NULL;
		double v = strtod(frozen_arg, &end);

		if (!end || end == frozen_arg || *end != '\0') {
			fprintf(stderr, "smehttp: invalid --frozen-now\n");
			return 2;
		}
		g_frozen_now = v;
		g_frozen = 1;
	}

	cfg = config_path ? aik_config_load(config_path, err, sizeof(err))
			  : aik_config_defaults(err, sizeof(err));
	if (!cfg) {
		fprintf(stderr, "smehttp: config: %s\n", err);
		return 1;
	}
	id_init();
	engine = aik_engine_new(cfg, 0, now_seconds, NULL, random_id, NULL, err,
				sizeof(err));
	if (!engine) {
		fprintf(stderr, "smehttp: engine: %s\n", err);
		aik_config_free(cfg);
		return 1;
	}
	storage_path = aik_config_get_str(cfg, "storage.path");
	if (storage_path && *storage_path &&
	    access(storage_path, F_OK) == 0) {
		if (aik_engine_load(engine, storage_path, err, sizeof(err)) != 0) {
			fprintf(stderr, "smehttp: load %s: %s\n", storage_path,
				err);
			aik_engine_free(engine);
			aik_config_free(cfg);
			return 1;
		}
	}
	cfg_host = aik_config_get_str(cfg, "api.host");
	if (!have_port) {
		long long p = 8000;

		(void)aik_config_get_i64(cfg, "api.port", &p);
		port_arg = 0;
		have_port = 1;
		if (p >= 0 && p <= 65535)
			port_arg = (int)p;
	}
	server = aik_http_server_new(engine, cfg,
				     host_arg ? host_arg : cfg_host, port_arg,
				     err, sizeof(err));
	if (!server) {
		fprintf(stderr, "smehttp: %s\n", err);
		aik_engine_free(engine);
		aik_config_free(cfg);
		return 1;
	}

	{
		struct sigaction sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = on_signal;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;	/* 不设 SA_RESTART：让 accept 被中断 */
		(void)sigaction(SIGINT, &sa, NULL);
		(void)sigaction(SIGTERM, &sa, NULL);
	}

	printf("LISTENING %d\n", aik_http_server_port(server));
	fflush(stdout);

	while (!g_stop) {
		int rc = aik_http_server_serve_one(server, -1);

		if (rc == 0)
			continue;
		if (rc == 1)
			continue;	/* 被信号中断，回到循环顶部看标志 */
		fprintf(stderr, "smehttp: accept: %s\n", strerror(errno));
		aik_http_server_free(server);
		aik_engine_free(engine);
		aik_config_free(cfg);
		if (g_urandom >= 0)
			close(g_urandom);
		return 1;
	}

	aik_http_server_free(server);
	aik_engine_free(engine);
	aik_config_free(cfg);
	if (g_urandom >= 0)
		close(g_urandom);
	return 0;
}
