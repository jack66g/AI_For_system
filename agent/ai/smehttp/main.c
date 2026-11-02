/* SPDX-License-Identifier: GPL-2.0 */
/*
 * main.c - T4b `smehttp` 二进制（T4B-DESIGN.md §4，T4e 配置来源）
 *
 *   smehttp [--config PATH] [--host 127.0.0.1] [--port 8000]
 *           [--static-dir DIR] [--frozen-now SECONDS]
 *
 * 配置来源优先级（对齐 sme/api/server.py::resolve_engine）：
 *   --config > SME_CONFIG_PATH > data/sme.config.json（存在才用）> 内置默认。
 * 快照恢复后重放配置文件显式键（`_apply_file_overrides`）与环境变量
 * （SME_LLM_* / SME_EMBEDDING_* / SME_API_AUTH_TOKEN）；source 随之取
 * "file" / "env" / "defaults"。
 *
 * 建 engine（真实 /dev/urandom id；--frozen-now 注入冻结时钟）→
 * storage.path 指向的文件存在则 aik_engine_load（失败退出非 0）→ 绑定 →
 * stdout 打印 `LISTENING <actual_port>\n` 并 flush → 循环 serve_one →
 * SIGINT/SIGTERM 干净退出（0）。默认监听取配置的 api.host/api.port
 * （缺省 127.0.0.1:8000），--host/--port 覆盖；--port 0 由内核选端口。
 *
 * 所有权：engine 接管 config（take_ownership=1），退出时只 free 当前
 * engine；热重建后 server 指向新引擎，旧引擎由配置路由释放。
 */
#define _POSIX_C_SOURCE 200809L

#include "smehttp/http.h"

#include "smeconfig/config_items.h"

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
		"usage: smehttp [--config PATH] [--host HOST] [--port PORT]\n"
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

/* ------------------------------------------------------------------ */
/* 配置来源：文件显式键重放 + 环境变量覆盖                            */
/* ------------------------------------------------------------------ */
static int env_set_str(aik_config *cfg, const char *path, const char *value)
{
	aik_json *v;
	int rc;

	if (!value)
		return 0;
	v = aik_json_new_str(value);
	if (!v)
		return -1;
	rc = aik_config_set_dotted(cfg, path, v);
	aik_json_free(v);
	return rc;
}

static int env_set_int(aik_config *cfg, const char *path, long long value)
{
	aik_json *v = aik_json_new_int(value);
	int rc;

	if (!v)
		return -1;
	rc = aik_config_set_dotted(cfg, path, v);
	aik_json_free(v);
	return rc;
}

/*
 * apply_env_overrides - SME_LLM_* / SME_EMBEDDING_* / SME_API_AUTH_TOKEN
 *
 * 与 server.py::_apply_env_overrides 同序同语义；*from_env 置 1 表示至少
 * 命中一个环境变量。SME_EMBEDDING_DIM 非法时返回 -1（Python int() 抛错）。
 */
static int apply_env_overrides(aik_config *cfg, int *from_env)
{
	const char *base_url = getenv("SME_LLM_BASE_URL");
	const char *token = getenv("SME_API_AUTH_TOKEN");
	const char *provider = getenv("SME_EMBEDDING_PROVIDER");

	*from_env = 0;
	if (base_url && *base_url) {
		const char *key = getenv("SME_LLM_API_KEY");
		const char *model = getenv("SME_LLM_MODEL");

		if (env_set_str(cfg, "llm.base_url", base_url) != 0 ||
		    env_set_str(cfg, "llm.api_key", key ? key : "") != 0 ||
		    env_set_str(cfg, "llm.model",
				model ? model : "gpt-4o-mini") != 0)
			return -1;
		*from_env = 1;
	}
	if (token && *token) {
		if (env_set_str(cfg, "api.auth_token", token) != 0)
			return -1;
		*from_env = 1;
	}
	if (provider && *provider) {
		const char *model = getenv("SME_EMBEDDING_MODEL");
		const char *dim_s = getenv("SME_EMBEDDING_DIM");
		const char *emb_url = getenv("SME_EMBEDDING_BASE_URL");
		const char *emb_key = getenv("SME_EMBEDDING_API_KEY");
		long long dim = 64;

		if (dim_s && *dim_s) {
			char *end = NULL;

			dim = strtoll(dim_s, &end, 10);
			if (end == dim_s || *end != '\0')
				return -1;
		}
		if (env_set_str(cfg, "embedding.provider", provider) != 0 ||
		    env_set_str(cfg, "embedding.model",
				model ? model : "text-embedding-3-small") != 0 ||
		    env_set_int(cfg, "embedding.dim", dim) != 0 ||
		    env_set_str(cfg, "embedding.base_url",
				emb_url ? emb_url : "") != 0 ||
		    env_set_str(cfg, "embedding.api_key",
				emb_key ? emb_key : "") != 0)
			return -1;
		*from_env = 1;
	}
	return 0;
}

/*
 * apply_file_overrides - 快照恢复后重放配置文件的显式键
 *
 * 对齐 server.py::_apply_file_overrides：只重放与 ITEM 注册表默认值不同
 * 的项；非空库跳过 embedding.provider/model/dim（向量维度是数据事实）。
 * 单项失败不阻断其余项。
 */
static void apply_file_overrides(aik_engine *engine, const char *path)
{
	aik_config *cfg = aik_engine_config(engine);
	aik_json *filecfg;
	int has_mem;
	size_t i;

	if (!cfg || !path || !*path || access(path, F_OK) != 0)
		return;
	filecfg = aik_config_load_file(path, NULL, 0);
	if (!filecfg)
		return;
	has_mem = aik_engine_memory_count(engine) > 0;
	for (i = 0; i < aik_config_item_count; i++) {
		const aik_config_item *it = &aik_config_items[i];
		const aik_json *fv = aik_config_item_get(filecfg, it);
		aik_json *dval;
		int skip = 0;

		if (!fv)
			continue;
		if (has_mem && strncmp(it->path, "embedding.", 10) == 0) {
			const char *suffix = strrchr(it->path, '.');

			if (suffix &&
			    (strcmp(suffix, ".provider") == 0 ||
			     strcmp(suffix, ".model") == 0 ||
			     strcmp(suffix, ".dim") == 0))
				skip = 1;
		}
		if (skip)
			continue;
		dval = aik_config_item_default(it);
		if (dval && aik_config_value_equal(fv, dval)) {
			aik_json_free(dval);
			continue;
		}
		aik_json_free(dval);
		(void)aik_config_set_dotted(cfg, it->path, fv);
	}
	aik_json_free(filecfg);
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
	const char *config_arg = NULL;
	const char *host_arg = NULL;
	const char *static_arg = NULL;
	const char *frozen_arg = NULL;
	const char *env_path;
	const char *default_file = "data/sme.config.json";
	const char *load_path = NULL;
	const char *config_file;
	const char *cfg_host;
	const char *storage_path;
	int port_arg = -1;
	int have_port = 0;
	int source;
	int file_source;
	int env_source = 0;
	int i;
	char static_buf[1024];
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
			config_arg = argv[i];
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
		} else if (strcmp(argv[i], "--static-dir") == 0) {
			if (++i >= argc) {
				usage(stderr);
				return 2;
			}
			static_arg = argv[i];
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

	env_path = getenv("SME_CONFIG_PATH");
	config_file = config_arg && *config_arg ? config_arg
		    : (env_path && *env_path ? env_path : default_file);
	load_path = config_file;
	file_source = access(load_path, F_OK) == 0;

	cfg = file_source ? aik_config_load(load_path, err, sizeof(err))
			  : aik_config_defaults(err, sizeof(err));
	if (!cfg) {
		fprintf(stderr, "smehttp: config: %s\n", err);
		return 1;
	}
	id_init();
	engine = aik_engine_new(cfg, 1, now_seconds, NULL, random_id, NULL, err,
				sizeof(err));
	if (!engine) {
		/* take_ownership=1：失败时 cfg 已由 aik_engine_new 释放 */
		fprintf(stderr, "smehttp: engine: %s\n", err);
		return 1;
	}
	storage_path = aik_config_get_str(aik_engine_config(engine),
					  "storage.path");
	if (storage_path && *storage_path &&
	    access(storage_path, F_OK) == 0) {
		if (aik_engine_load(engine, storage_path, err, sizeof(err)) != 0) {
			fprintf(stderr, "smehttp: load %s: %s\n", storage_path,
				err);
			aik_engine_free(engine);
			return 1;
		}
	}
	/* 快照内嵌配置会整体覆盖；随后重放文件显式键与 env（env 最高） */
	if (file_source)
		apply_file_overrides(engine, load_path);
	if (apply_env_overrides(aik_engine_config(engine), &env_source) != 0) {
		fprintf(stderr, "smehttp: invalid environment override\n");
		aik_engine_free(engine);
		return 1;
	}
	source = file_source ? AIK_HTTP_SOURCE_FILE
			     : (env_source ? AIK_HTTP_SOURCE_ENV
					   : AIK_HTTP_SOURCE_DEFAULTS);

	cfg_host = aik_config_get_str(aik_engine_config(engine), "api.host");
	if (!have_port) {
		long long p = 8000;

		(void)aik_config_get_i64(aik_engine_config(engine), "api.port",
					 &p);
		port_arg = 0;
		have_port = 1;
		if (p >= 0 && p <= 65535)
			port_arg = (int)p;
	}
	server = aik_http_server_new(engine, aik_engine_config(engine),
				     host_arg ? host_arg : cfg_host, port_arg,
				     err, sizeof(err));
	if (!server) {
		fprintf(stderr, "smehttp: %s\n", err);
		aik_engine_free(engine);
		return 1;
	}
	if (!static_arg) {
		const char *env_static = getenv("SME_STATIC_DIR");

		if (env_static && *env_static) {
			static_arg = env_static;
		} else {
			const char *slash = strrchr(argv[0], '/');
			size_t n = slash ? (size_t)(slash - argv[0] + 1) : 0;

			snprintf(static_buf, sizeof(static_buf), "%.*sstatic",
				 (int)n, argv[0]);
			static_arg = static_buf;
		}
	}
	if (aik_http_server_set_static_dir(server, static_arg) != 0) {
		fprintf(stderr, "smehttp: out of memory (static dir)\n");
		aik_http_server_free(server);
		aik_engine_free(engine);
		return 1;
	}
	if (aik_http_server_set_config_file(server, config_file) != 0) {
		fprintf(stderr, "smehttp: out of memory (config file)\n");
		aik_http_server_free(server);
		aik_engine_free(engine);
		return 1;
	}
	aik_http_server_set_source(server, source);

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
		{
			aik_engine *cur = aik_http_server_engine(server);

			aik_http_server_free(server);
			aik_engine_free(cur);
		}
		if (g_urandom >= 0)
			close(g_urandom);
		return 1;
	}

	{
		/* 配置热重建可能已换引擎：退出时释放 server 当前指向的那个 */
		aik_engine *cur = aik_http_server_engine(server);

		aik_http_server_free(server);
		aik_engine_free(cur);
	}
	if (g_urandom >= 0)
		close(g_urandom);
	return 0;
}
