/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_shutdown.c - 优雅退出 + 单实例 lease + 不可达缓冲补写（真二进制）
 *
 * 阶段：
 *  0) 单实例：daemon A 起后同 conf 再起 B → B 必须非 0 退出（lease）；
 *  1) SME 可达：注入 2 条 mock 决策事件 → stats event.written=2；
 *  2) SME 不可达（mock server 关监听）：注入 2 条 → ring_used=2；
 *  3) mock server 重开监听：补写定时器（SME_RETRY_SEC=1）按序补齐；
 *  4) SIGTERM：daemon 退出码 0；stderr 含 graceful shutdown；终笔 stats
 *     落盘（ring_used=0、written=4）。
 * 全程 enable_event=1（mock 通道）其余流关闭——单测无 root（CN_PROC 需
 * CAP_NET_ADMIN）。
 */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/netlink.h>

static int fails;

#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		printf("FAIL: %s\n", msg); \
		fails++; \
	} \
} while (0)

#define MOCK_RESP \
	"HTTP/1.1 200 OK\r\n" \
	"Content-Type: application/json\r\n" \
	"Content-Length: 13\r\n" \
	"Connection: close\r\n" \
	"\r\n" \
	"{\"id\":\"m1\"}"

static int serve_one(int cli, FILE *cap)
{
	char req[8192];
	size_t off = 0;

	while (off < sizeof(req) - 1) {
		ssize_t n = recv(cli, req + off, sizeof(req) - 1 - off, 0);

		if (n <= 0)
			return -1;
		off += (size_t)n;
		req[off] = '\0';
		if (strstr(req, "\r\n\r\n"))
			break;
	}
	{
		char *cl = strstr(req, "Content-Length:");
		long clen = cl ? strtol(cl + 15, NULL, 10) : 0;
		char *body = strstr(req, "\r\n\r\n");

		if (!body)
			return -1;
		body += 4;
		while ((long)strlen(body) < clen &&
		       off < sizeof(req) - 1) {
			ssize_t n = recv(cli, req + off,
					 sizeof(req) - 1 - off, 0);

			if (n <= 0)
				break;
			off += (size_t)n;
			req[off] = '\0';
			body = strstr(req, "\r\n\r\n") + 4;
		}
	}
	fwrite(req, 1, off, cap);
	fputc('\n', cap);
	fflush(cap);
	{
		const char *r = MOCK_RESP;

		if (send(cli, r, strlen(r), 0) < 0)
			return -1;
	}
	return 0;
}

/* mock SME：阶段 1 服务 2 请求 → 关监听（不可达窗）→ 3s 后重开服务
 * 直到 cap 收满 4 请求 */
static pid_t start_mock_server(const char *portfile, const char *capfile)
{
	pid_t p = fork();

	if (p != 0)
		return p;
	{
		int s = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in a;
		socklen_t al = sizeof(a);
		FILE *cap, *pf;
		int served = 0, total = 0;

		if (s < 0)
			_exit(3);
		int one = 1;

		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		a.sin_port = 0;
		if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0 ||
		    listen(s, 16) < 0 ||
		    getsockname(s, (struct sockaddr *)&a, &al) < 0)
			_exit(3);
		pf = fopen(portfile, "w");
		if (!pf)
			_exit(3);
		fprintf(pf, "%d\n", (int)ntohs(a.sin_port));
		fclose(pf);
		cap = fopen(capfile, "w");
		if (!cap)
			_exit(3);

		/* 阶段 1：2 请求 */
		while (served < 2) {
			int cli = accept(s, NULL, NULL);
			struct timeval tv = { .tv_sec = 10 };

			if (cli < 0)
				continue;
			setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tv,
				   sizeof(tv));
			if (serve_one(cli, cap) == 0) {
				served++;
				total++;
			}
			close(cli);
		}
		/* 不可达窗：关监听 */
		close(s);
		sleep(3);
		/* 阶段 3：重开同端口，服务至共 4 请求（容错多余连接） */
		s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0)
			_exit(3);
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0 ||
		    listen(s, 16) < 0)
			_exit(3);
		while (total < 4) {
			int cli = accept(s, NULL, NULL);
			struct timeval tv = { .tv_sec = 10 };

			if (cli < 0) {
				if (total >= 4)
					break;
				continue;
			}
			setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tv,
				   sizeof(tv));
			if (serve_one(cli, cap) == 0)
				total++;
			close(cli);
		}
		fclose(cap);
		close(s);
		_exit(0);
	}
}

static long long stat_of(const char *path, const char *key)
{
	FILE *f = fopen(path, "r");
	char line[256];
	size_t kl;

	if (!f)
		return -1;
	kl = strlen(key);
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, key, kl) == 0 && line[kl] == '=') {
			long long v = strtoll(line + kl + 1, NULL, 10);

			fclose(f);
			return v;
		}
	}
	fclose(f);
	return -1;
}

static int wait_stat(const char *path, const char *key, long long want,
		     long long timeout_ms, int ge)
{
	long long deadline = (long long)time(NULL) * 1000 + timeout_ms;

	while ((long long)time(NULL) * 1000 < deadline) {
		long long v = stat_of(path, key);

		if (v >= 0 && (ge ? v >= want : v == want))
			return 0;
		usleep(200000);
	}
	return -1;
}

int main(void)
{
	char dir[128], portfile[160], capfile[160], conffile[160];
	char statsfile[160], dlog[160], pidfile[160], lockfile[160];
	pid_t srv, dmn;
	int port = 0;
	char cwd[512];

	if (!getcwd(cwd, sizeof(cwd)))
		return 2;
	snprintf(dir, sizeof(dir), "/tmp/as-sd-%d", (int)getpid());
	{
		char cmd[512];

		snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s", dir,
			 dir);
		if (system(cmd) != 0)
			return 2;
	}
	snprintf(portfile, sizeof(portfile), "%s/port", dir);
	snprintf(capfile, sizeof(capfile), "%s/cap.txt", dir);
	snprintf(conffile, sizeof(conffile), "%s/a.conf", dir);
	snprintf(statsfile, sizeof(statsfile), "%s/stats", dir);
	snprintf(dlog, sizeof(dlog), "%s/daemon.log", dir);
	snprintf(pidfile, sizeof(pidfile), "%s/pid", dir);
	snprintf(lockfile, sizeof(lockfile), "%s/lock", dir);

	srv = start_mock_server(portfile, capfile);
	for (int i = 0; i < 100 && port == 0; i++) {
		FILE *f = fopen(portfile, "r");

		if (f) {
			if (fscanf(f, "%d", &port) != 1)
				port = 0;
			fclose(f);
		}
		usleep(50000);
	}
	CHECK(port > 0, "mock server up");
	if (port <= 0)
		return 1;

	{
		FILE *f = fopen(conffile, "w");

		CHECK(f != NULL, "write conf");
		fprintf(f,
			"SME_URL=http://127.0.0.1:%d\n"
			"SME_RETRY_SEC=1\n"
			"RATE_PER_MIN=1000\n"
			"STATS_INTERVAL_SEC=1\n"
			"ENABLE_EVENT=1\n"
			"ENABLE_PROC=0\n"
			"ENABLE_NET=0\n"
			"ENABLE_UEVENT=0\n"
			"ENABLE_NFLOG=0\n"
			"ENABLE_TASKSTATS=0\n"
			"AI_MOCK_PROTO=2\n"
			"STATS_FILE=%s\n"
			"PID_FILE=%s\n"
			"LOCK_FILE=%s\n",
			port, statsfile, pidfile, lockfile);
		fclose(f);
	}

	/* ---- 起 daemon A（stderr → dlog） ---- */
	dmn = fork();
	if (dmn == 0) {
		int devnull = open("/dev/null", O_RDONLY);
		int lf = open(dlog, O_WRONLY | O_CREAT | O_TRUNC, 0644);

		if (devnull >= 0)
			dup2(devnull, 0);
		if (lf >= 0) {
			dup2(lf, 1);
			dup2(lf, 2);
		}
		execl("./aistreamd", "aistreamd", "--conf", conffile,
		      (char *)NULL);
		_exit(127);
	}
	CHECK(wait_stat(statsfile, "nl_ai_portid", 1, 10000, 1) == 0,
	      "daemon A up (stats+portid)");

	/* ---- 阶段 0：单实例 lease ---- */
	{
		pid_t b = fork();
		int status;

		if (b == 0) {
			int devnull = open("/dev/null", O_WRONLY);

			if (devnull >= 0) {
				dup2(devnull, 1);
				dup2(devnull, 2);
			}
			execl("./aistreamd", "aistreamd", "--conf",
			      conffile, (char *)NULL);
			_exit(127);
		}
		CHECK(waitpid(b, &status, 0) == b, "second instance exits");
		CHECK(!(WIFEXITED(status) && WEXITSTATUS(status) == 0),
		      "second instance nonzero (lease enforced)");
	}

	/* ---- 阶段 1：SME 可达，注入 2 → written=2 ---- */
	{
		char cmd[512];
		int rc;

		snprintf(cmd, sizeof(cmd),
			 "./tests/ai_inject %s 2 9000 k3csd1", statsfile);
		rc = system(cmd);
		CHECK(rc == 0, "inject 2 (phase1)");
	}
	CHECK(wait_stat(statsfile, "event.received", 2, 10000, 1) == 0,
	      "received=2");
	CHECK(wait_stat(statsfile, "event.written", 2, 10000, 1) == 0,
	      "written=2 (SME up)");
	CHECK(stat_of(statsfile, "event.buffer_dropped") == 0,
	      "no buffer drops phase1");

	/* ---- 阶段 2：不可达窗（server 关监听 3s），注入 2 → 入环 ---- */
	{
		char cmd[512];
		int rc;

		snprintf(cmd, sizeof(cmd),
			 "sleep 1 && ./tests/ai_inject %s 2 9100 k3csd2",
			 statsfile);
		rc = system(cmd);
		CHECK(rc == 0, "inject 2 (phase2)");
	}
	CHECK(wait_stat(statsfile, "event.received", 4, 10000, 1) == 0,
	      "received=4");
	CHECK(wait_stat(statsfile, "ring_used", 2, 10000, 1) == 0,
	      "ring_used=2 while SME down");

	/* ---- 阶段 3：server 重开 → 补写 ---- */
	CHECK(wait_stat(statsfile, "ring_used", 0, 20000, 0) == 0,
	      "ring drained after recovery");
	CHECK(wait_stat(statsfile, "event.written", 4, 10000, 1) == 0,
	      "written=4 after flush");

	/* ---- 阶段 4：SIGTERM 优雅退出 ---- */
	CHECK(kill(dmn, SIGTERM) == 0, "SIGTERM sent");
	{
		int status;
		time_t deadline = time(NULL) + 15;

		while (time(NULL) < deadline) {
			pid_t r = waitpid(dmn, &status, WNOHANG);

			if (r == dmn)
				goto reaped;
			usleep(100000);
		}
		CHECK(0, "daemon exited within 15s");
		kill(dmn, SIGKILL);
		return 1;
reaped:
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		      "daemon exit 0");
	}
	{
		FILE *f = fopen(dlog, "r");
		char all[8192];
		size_t n;

		CHECK(f != NULL, "daemon log exists");
		if (f) {
			n = fread(all, 1, sizeof(all) - 1, f);
			all[n] = '\0';
			fclose(f);
			CHECK(strstr(all, "graceful shutdown") != NULL,
			      "log has graceful shutdown");
			CHECK(strstr(all, "MOCK channel") != NULL,
			      "log declares MOCK channel");
		}
	}
	CHECK(stat_of(statsfile, "event.written") >= 4, "final stats kept");
	CHECK(access(pidfile, F_OK) != 0, "pid file unlinked at exit");

	{
		int status;

		kill(srv, SIGKILL);
		waitpid(srv, &status, 0);
	}
	{
		char cmd[256];

		snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
		(void)!system(cmd);
	}
	if (fails) {
		printf("test_shutdown: %d failures\n", fails);
		return 1;
	}
	printf("test_shutdown: OK\n");
	return 0;
}
