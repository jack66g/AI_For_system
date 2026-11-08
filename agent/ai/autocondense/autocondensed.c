/* SPDX-License-Identifier: GPL-2.0 */
/*
 * autocondensed.c - autocondense 常驻服务 main（service.py main() 等价）
 *
 * 用法：
 *   autocondensed [--data-dir DIR] [--host H] [--port N]
 *                 [--frozen-now EPOCH]
 *
 *   --data-dir DIR   数据目录（缺省：环境变量 AC_DATA_DIR，再缺省
 *                    ~/.autocondense）
 *   --host H         监听地址（缺省取配置，初始 127.0.0.1）
 *   --port N         监听端口（0 = 内核分配；缺省取配置，初始 8762——T9d
 *                    改号，8761 让给 aikernel-api）
 *   --frozen-now E   冻结时钟（差分重放：所有 ISO/文件名走该 epoch）
 *
 * 行为对齐 service.py main()：
 *   - config.json 缺失时写默认配置；
 *   - 启动写 service.pid（{"pid","version","port","started"} + "\n"，
 *     紧凑 + Python 默认分隔符 ", "/": "；port 记实际监听端口）；
 *   - stdout 打 "LISTENING <port>"（供重放器取内核分配端口）；
 *   - SIGTERM/SIGINT 干净退出并清 pid 文件（pid 不符则不动）。
 */
#define _POSIX_C_SOURCE 200809L

#include "autocondense/acserv.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void on_term(int sig)
{
	(void)sig;
	ac_http_server_request_stop();
}

static char *path_join(const char *a, const char *b)
{
	size_t n = strlen(a) + 1 + strlen(b) + 1;
	char *out = malloc(n);

	if (out)
		snprintf(out, n, "%s/%s", a, b);
	return out;
}

/* write_pid_file：json.dumps(payload) + "\n"（默认分隔符 ", "/": "）*/
static int write_pid_file(const char *data_dir, int port)
{
	aik_json *o = aik_json_new_obj();
	char iso[32];
	char *dump = NULL;
	char *path = NULL;
	int rc = -1;

	if (!o || ac_iso_now(iso, sizeof(iso)) != 0)
		goto out;
	{
		aik_json *v = aik_json_new_int((long long)getpid());

		if (!v || aik_json_obj_put(o, "pid", v) != 0)
			goto out;
		v = aik_json_new_str(AC_SERV_VERSION);
		if (!v || aik_json_obj_put(o, "version", v) != 0)
			goto out;
		v = aik_json_new_int(port);
		if (!v || aik_json_obj_put(o, "port", v) != 0)
			goto out;
		v = aik_json_new_str(iso);
		if (!v || aik_json_obj_put(o, "started", v) != 0)
			goto out;
	}
	dump = ac_json_dump_default(o);
	if (!dump)
		goto out;
	path = path_join(data_dir, AC_PID_FILE_NAME);
	if (!path)
		goto out;
	{
		size_t n = strlen(dump);
		char *with_nl = malloc(n + 2);

		if (!with_nl)
			goto out;
		memcpy(with_nl, dump, n);
		with_nl[n] = '\n';
		with_nl[n + 1] = '\0';
		rc = ac_atomic_write_text(path, with_nl, n + 1);
		free(with_nl);
	}
out:
	free(dump);
	free(path);
	aik_json_free(o);
	return rc;
}

/* clear_pid_file：记录 pid 与本进程不一致（已被接管）时不动 */
static void clear_pid_file(const char *data_dir)
{
	char *path = path_join(data_dir, AC_PID_FILE_NAME);
	size_t len = 0;
	char *text;
	aik_json *d;

	if (!path)
		return;
	text = ac_read_file(path, &len);
	if (!text)
		goto out;
	d = aik_json_parse(text, len, NULL, 0);
	free(text);
	if (!d || aik_json_typeof(d) != AIK_JSON_OBJ)
		goto out_d;
	{
		const aik_json *pid = aik_json_get(d, "pid");

		if (pid && aik_json_typeof(pid) == AIK_JSON_INT &&
		    aik_json_int(pid) == (long long)getpid())
			(void)unlink(path);
	}
out_d:
	aik_json_free(d);
out:
	free(path);
}

static void usage(FILE *out)
{
	fprintf(out,
		"usage: autocondensed [--data-dir DIR] [--host H] [--port N] "
		"[--frozen-now EPOCH]\n");
}

int main(int argc, char **argv)
{
	const char *data_dir_arg = NULL;
	const char *host_arg = NULL;
	int port_arg = -1;
	double frozen = 0.0;
	int i;
	ac_http_server *srv;
	char errbuf[256];
	char *data_dir = NULL;
	ac_config cfg;
	char host_buf[256];

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--data-dir") == 0 && i + 1 < argc) {
			data_dir_arg = argv[++i];
		} else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
			host_arg = argv[++i];
		} else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
			port_arg = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--frozen-now") == 0 &&
			   i + 1 < argc) {
			frozen = atof(argv[++i]);
		} else if (strcmp(argv[i], "--help") == 0 ||
			   strcmp(argv[i], "-h") == 0) {
			usage(stdout);
			return 0;
		} else {
			usage(stderr);
			return 2;
		}
	}

	if (frozen > 0.0)
		ac_time_set_now(frozen);

	if (data_dir_arg) {
		data_dir = strdup(data_dir_arg);
	} else {
		const char *env = getenv("AC_DATA_DIR");

		if (env && *env) {
			data_dir = strdup(env);
		} else {
			const char *home = getenv("HOME");

			if (!home || !*home) {
				fprintf(stderr,
					"autocondensed: cannot resolve home directory\n");
				return 2;
			}
			data_dir = path_join(home, ".autocondense");
		}
	}
	if (!data_dir) {
		fprintf(stderr, "autocondensed: out of memory\n");
		return 2;
	}
	if (ac_mkdir_p(data_dir) != 0) {
		fprintf(stderr, "autocondensed: cannot create data dir %s\n",
			data_dir);
		free(data_dir);
		return 2;
	}

	/* config.json 缺失 → 写默认（service.py main 同步语义）*/
	if (ac_load_config(data_dir, &cfg) != 0) {
		fprintf(stderr, "autocondensed: cannot load config from %s\n",
			data_dir);
		free(data_dir);
		return 2;
	}
	{
		char *cfg_path = path_join(data_dir, "config.json");
		struct stat st;

		if (!cfg_path) {
			ac_config_cleanup(&cfg);
			free(data_dir);
			return 2;
		}
		if (stat(cfg_path, &st) != 0)
			(void)ac_save_config(data_dir, &cfg);
		free(cfg_path);
	}
	ac_config_cleanup(&cfg);

	if (port_arg < 0 || host_arg) {
		/* 端口/地址缺省取配置（初始 8762/127.0.0.1——T9d 改号）*/
		ac_config cfg2;

		if (ac_load_config(data_dir, &cfg2) == 0) {
			if (port_arg < 0)
				port_arg = (int)cfg2.port;
			if (!host_arg && cfg2.host && *cfg2.host) {
				/*
				 * 先拷进栈缓冲再 cleanup：ac_config_cleanup
				 * 会 free(cfg2.host)，原实现直接借指针是 UAF
				 * （T9d 实测缺省启动即 "cannot resolve host
				 * <垃圾字节>"，服务起不来）。
				 */
				snprintf(host_buf, sizeof(host_buf), "%s",
					 cfg2.host);
				host_arg = host_buf;
			}
			ac_config_cleanup(&cfg2);
		}
	}

	srv = ac_http_server_new(data_dir, host_arg, port_arg < 0 ? 8762
								  : port_arg,
				 errbuf, sizeof(errbuf));
	if (!srv) {
		fprintf(stderr, "autocondensed: %s\n",
			errbuf[0] ? errbuf : "cannot start server");
		free(data_dir);
		return 1;
	}

	if (signal(SIGTERM, on_term) == SIG_ERR ||
	    signal(SIGINT, on_term) == SIG_ERR) {
		fprintf(stderr, "autocondensed: cannot install signal handlers\n");
		ac_http_server_free(srv);
		free(data_dir);
		return 1;
	}

	(void)write_pid_file(data_dir, ac_http_server_port(srv));
	printf("LISTENING %d\n", ac_http_server_port(srv));
	fflush(stdout);

	if (ac_http_server_serve(srv) != 0)
		fprintf(stderr, "autocondensed: accept loop failed\n");

	clear_pid_file(data_dir);
	ac_http_server_free(srv);
	free(data_dir);
	return 0;
}
