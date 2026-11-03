// SPDX-License-Identifier: GPL-2.0
/*
 * dtvm.c - VM 真系统桥 C 化(T6c)。AIK_DESKTOP_VM=1 时:
 *   - 凭据 ~/.aikernel/vm138.conf(k=v 逐行,缺省 host=192.168.245.138/
 *     user=root/password="");password 只经 SSHPASS 环境变量给
 *     `sshpass -e`,不进 argv、不落日志;
 *   - ai/aiops/sandbox 快照 = 每次独立 `sshpass -e ssh ... '<命令串>'`
 *     (命令串逐字 = server.py:1024-1027/1074-1076/642-645;输出按
 *     `---` 分段 + 正则表解析,语义见 dt_vm_parse_*);
 *   - status/tools = 懒启动隧道子进程 `ssh -N -L 18761:127.0.0.1:8761`
 *     (代替 paramiko direct-tcpip;本地端口就绪轮询近似 connect() 完成
 *     语义),vm_api 走明文 http://127.0.0.1:18761 + Bearer token(经
 *     独立 SSH `cat /etc/aikernel/api-token` 现取,不缓存);空闲 120s
 *     由 housekeeping SIGTERM 关闭;
 *   - 错误映射:"HTTP <code>"(上游非 2xx)/ python 异常类名等价物
 *     (AuthenticationException/socket.timeout/gaierror/OSError/
 *     SSHException 近似映射,如实声明于 T6C 报告)。
 * L1 无真 SSH 靶:本模块经"编译零告警 + 纯解析单测 + 命令串断言"验收,
 * 真 SSH 差分留 T7 qemu;不做任何短路假绿。
 */
#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "desktop/dtchat.h"
#include "desktop/dtcore.h"
#include "desktop/dtjson.h"
#include "desktop/dtstate.h"
#include "desktop/dtvm.h"

#define VM_LOCAL_PORT 18761 /* L1 本地端口 -> VM 127.0.0.1:8761 */
#define VM_IDLE_CLOSE 120   /* 空闲关闭秒数 */
#define SSH_PATH "/usr/bin/sshpass"

/* ---------------- 命令串(与 server.py 逐字一致) ---------------- */

const char *dt_vm_cmd_ai(void)
{
	return "cat /proc/ai/status 2>&1; echo ---; cat /proc/loadavg; "
	       "echo ---; free -m | sed -n 2p";
}

const char *dt_vm_cmd_aiops(void)
{
	return "wc -c /proc/ai/decisions 2>&1; echo ---; "
	       "cat /proc/ai/decisions 2>&1 | head -c 4096; echo ---; "
	       "tail -c 4096 /proc/ai/telemetry 2>&1";
}

const char *dt_vm_cmd_sandbox(void)
{
	return "ls -la /sandbox/ 2>&1; echo ---MOUNTS---; "
	       "mount | grep -i sandbox 2>&1; echo ---PROCS---; "
	       "ps -eo pid,comm | grep -iw sandbox 2>&1";
}

const char *dt_vm_cmd_token(void)
{
	return "cat /etc/aikernel/api-token";
}

/* ---------------- 凭据 ---------------- */

/* usleep 在 POSIX 2008 下已废除:nanosleep 等效 */
static void sleep_ms(int ms)
{
	struct timespec ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (long)(ms % 1000) * 1000000L;
	nanosleep(&ts, NULL);
}

static int line_is_ws(char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
	       c == '\f' || c == '\v';
}

/* _vm_conf():k=v 逐行(line.strip().split("=",1));password 不落日志 */
static void vm_conf_load(char *host, size_t hsz, char *user, size_t usz,
			 char *pass, size_t psz)
{
	size_t n = 0;
	char *txt;

	snprintf(host, hsz, "192.168.245.138");
	snprintf(user, usz, "root");
	snprintf(pass, psz, "%s", "");
	txt = dt_read_file(g_cfg.vm_conf, &n);
	if (!txt)
		return;
	{
		char *p = txt;

		while (p && *p) {
			char *nl = strchr(p, '\n');
			size_t ln = nl ? (size_t)(nl - p) : strlen(p);
			size_t b = 0, e = ln;

			while (b < e && line_is_ws(p[b]))
				b++;
			while (e > b && line_is_ws(p[e - 1]))
				e--;
			if (e > b) {
				char *line = strndup(p + b, e - b);

				if (line) {
					char *eq = strchr(line, '=');

					if (eq && eq != line) {
						*eq = '\0';
						if (strcmp(line, "host") == 0)
							snprintf(host, hsz,
								 "%s", eq + 1);
						else if (strcmp(line, "user") ==
							 0)
							snprintf(user, usz,
								 "%s", eq + 1);
						else if (strcmp(line,
								"password") == 0)
							snprintf(pass, psz,
								 "%s", eq + 1);
					}
					free(line);
				}
			}
			p = nl ? nl + 1 : NULL;
		}
	}
	free(txt);
}

/* ---------------- SSH exec ---------------- */

/* stderr 首行 → python 异常类名等价物(paramiko/socket 近似映射) */
static void classify_ssh_err(const char *first_line, int exit_code, char *out,
			     size_t outsz)
{
	const char *type = "SSHException";
	char msg[112];
	const char *l = first_line;

	if (!l || !*l)
		l = "ssh failed";
	if (strstr(l, "Permission denied") || strstr(l, "Authentication"))
		type = "AuthenticationException";
	else if (strstr(l, "timed out"))
		type = "socket.timeout";
	else if (strstr(l, "Could not resolve") ||
		 strstr(l, "Name or service not known"))
		type = "gaierror";
	else if (strstr(l, "Connection refused") ||
		 strstr(l, "No route to host") ||
		 strstr(l, "Network is unreachable"))
		type = "OSError";
	{
		size_t n = strlen(l);

		if (n > 100)
			n = 100;
		memcpy(msg, l, n);
		msg[n] = '\0';
		for (size_t i = 0; i < n; i++)
			if (msg[i] == '\r' || msg[i] == '\n')
				msg[i] = ' ';
	}
	if (exit_code > 0 && strcmp(type, "SSHException") == 0)
		snprintf(out, outsz, "%s: ssh exit %d: %s", type, exit_code,
			 msg);
	else
		snprintf(out, outsz, "%s: %s", type, msg);
}

/* envp = environ - 旧 SSHPASS + 新 SSHPASS(密码绝不进 argv/日志) */
static char **build_envp(const char *sslenv)
{
	extern char **environ;
	size_t ne = 0;
	char **envp;

	for (char **e = environ; *e; e++)
		if (strncmp(*e, "SSHPASS=", 8) != 0)
			ne++;
	envp = malloc((ne + 2) * sizeof(char *));
	if (!envp)
		return NULL;
	{
		size_t k = 0;

		for (char **e = environ; *e; e++)
			if (strncmp(*e, "SSHPASS=", 8) != 0)
				envp[k++] = *e;
		envp[k++] = (char *)sslenv;
		envp[k] = NULL;
	}
	return envp;
}

/* 独立 SSH exec:sshpass -e ssh -o… <user>@<host> '<cmd>'
 * 成功 → *out = stdout(malloc,可能为空串);失败 → errbuf "ExcType: msg"。
 * deadline 16s(connect 8 + exec 8 上界;paramiko timeout=8 语义近似)。 */
static int vm_ssh_exec(const char *cmd, char **out, char *errbuf,
		       size_t errsz)
{
	char host[256], user[128], pass[256];
	char userhost[384];
	char sslenv[320];
	int outp[2], errp[2];
	pid_t pid;

	*out = NULL;
	errbuf[0] = '\0';
	vm_conf_load(host, sizeof(host), user, sizeof(user), pass,
		     sizeof(pass));
	snprintf(userhost, sizeof(userhost), "%s@%s", user, host);
	snprintf(sslenv, sizeof(sslenv), "SSHPASS=%s", pass);

	if (pipe(outp) != 0) {
		snprintf(errbuf, errsz, "OSError: pipe failed");
		return -1;
	}
	if (pipe(errp) != 0) {
		close(outp[0]);
		close(outp[1]);
		snprintf(errbuf, errsz, "OSError: pipe failed");
		return -1;
	}
	pid = fork();
	if (pid < 0) {
		close(outp[0]);
		close(outp[1]);
		close(errp[0]);
		close(errp[1]);
		snprintf(errbuf, errsz, "OSError: fork failed");
		return -1;
	}
	if (pid == 0) {
		char *argv[11];
		char o1[40], o2[40], o3[44], o4[28];
		char **envp;

		close(outp[0]);
		close(errp[0]);
		if (dup2(outp[1], STDOUT_FILENO) < 0)
			_exit(127);
		if (dup2(errp[1], STDERR_FILENO) < 0)
			_exit(127);
		if (dup2(errp[1], STDIN_FILENO) < 0)
			_exit(127);
		close(outp[1]);
		close(errp[1]);
		for (int fd = 3; fd < 1024; fd++)
			close(fd);
		snprintf(o1, sizeof(o1), "-oConnectTimeout=8");
		snprintf(o2, sizeof(o2), "-oStrictHostKeyChecking=no");
		snprintf(o3, sizeof(o3), "-oUserKnownHostsFile=/dev/null");
		snprintf(o4, sizeof(o4), "-oLogLevel=ERROR");
		argv[0] = (char *)"sshpass";
		argv[1] = (char *)"-e";
		argv[2] = (char *)"ssh";
		argv[3] = o1;
		argv[4] = o2;
		argv[5] = o3;
		argv[6] = o4;
		argv[7] = userhost;
		argv[8] = (char *)cmd;
		argv[9] = NULL;
		envp = build_envp(sslenv);
		if (!envp)
			_exit(127);
		execve(SSH_PATH, argv, envp);
		_exit(127);
	}
	{
		close(outp[1]);
		close(errp[1]);
		{
			struct dt_sbuf ob, eb;
			int out_open = 1, err_open = 1, timedout = 0;
			int status = 0;
			long long deadline = dt_time() + 16;

			dt_sb_init(&ob);
			dt_sb_init(&eb);
			fcntl(outp[0], F_SETFL, O_NONBLOCK);
			fcntl(errp[0], F_SETFL, O_NONBLOCK);
			while (out_open || err_open) {
				struct pollfd pfd[2];
				long long now = dt_time();
				int pr;

				if (now >= deadline) {
					timedout = 1;
					break;
				}
				pfd[0].fd = out_open ? outp[0] : -1;
				pfd[0].events = POLLIN;
				pfd[0].revents = 0;
				pfd[1].fd = err_open ? errp[0] : -1;
				pfd[1].events = POLLIN;
				pfd[1].revents = 0;
				pr = poll(pfd, 2,
					  (int)(deadline - now) * 1000);
				if (pr < 0) {
					if (errno == EINTR)
						continue;
					break;
				}
				for (int s = 0; s < 2; s++) {
					char buf[4096];
					ssize_t nrd;

					if (pfd[s].fd < 0 ||
					    !(pfd[s].revents & (POLLIN |
								POLLHUP)))
						continue;
					nrd = read(pfd[s].fd, buf,
						   sizeof(buf));
					if (nrd <= 0) {
						if (s == 0)
							out_open = 0;
						else
							err_open = 0;
						continue;
					}
					if (s == 0)
						dt_sb_puts(&ob, buf,
							   (size_t)nrd);
					else
						dt_sb_puts(&eb, buf,
							   (size_t)nrd);
				}
			}
			close(outp[0]);
			close(errp[0]);
			if (timedout) {
				kill(pid, SIGKILL);
				waitpid(pid, &status, 0);
				free(ob.p);
				free(eb.p);
				snprintf(errbuf, errsz,
					 "socket.timeout: ssh exec timeout");
				return -1;
			}
			waitpid(pid, &status, 0);
			{
				char *errtext = dt_sb_finish(&eb);
				int code = WIFEXITED(status)
					   ? WEXITSTATUS(status)
					   : 128 + WTERMSIG(status);

				if (code == 0) {
					*out = dt_sb_finish(&ob);
					free(errtext);
					if (!*out) {
						*out = strdup("");
						if (!*out)
							return -1;
					}
					return 0;
				}
				if (errtext) {
					char *nl = strchr(errtext, '\n');

					if (nl)
						*nl = '\0';
					classify_ssh_err(errtext, code, errbuf,
							 errsz);
					free(errtext);
				} else {
					classify_ssh_err("", code, errbuf,
							 errsz);
				}
				free(ob.p);
				return -1;
			}
		}
	}
}

/* ---------------- 隧道 ---------------- */

static pid_t g_tpid;
static long long g_tts;
static char g_tlast_err[256];

static int tunnel_alive(void)
{
	if (g_tpid <= 0)
		return 0;
	if (kill(g_tpid, 0) == 0)
		return 1;
	return errno == EPERM;
}

static void vm_close_locked(void)
{
	if (g_tpid > 0) {
		int status;

		kill(g_tpid, SIGTERM);
		for (int i = 0; i < 30; i++) {
			if (waitpid(g_tpid, &status, WNOHANG) > 0)
				goto done;
			sleep_ms(10); /* 最多等 300ms */
		}
		kill(g_tpid, SIGKILL);
		waitpid(g_tpid, &status, 0);
done:
		g_tpid = 0;
		dt_log("VM 隧道已关闭");
	}
	g_tpid = 0;
}

void dt_vm_close(void)
{
	pthread_mutex_lock(&g_lock_vm);
	vm_close_locked();
	pthread_mutex_unlock(&g_lock_vm);
}

static int local_port_ready(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa;

	if (fd < 0)
		return 0;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(VM_LOCAL_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	{
		int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));

		close(fd);
		return rc == 0;
	}
}

/* vm_tunnel():懒启动 + 本地端口就绪轮询(paramiko connect 完成语义近似) */
static int tunnel_ensure(char *errbuf, size_t errsz)
{
	char host[256], user[128], pass[256];
	char userhost[384];
	char sslenv[320];
	pid_t pid;

	if (tunnel_alive() && dt_time() - g_tts < VM_IDLE_CLOSE) {
		g_tts = dt_time();
		return 0;
	}
	vm_close_locked();

	vm_conf_load(host, sizeof(host), user, sizeof(user), pass,
		     sizeof(pass));
	snprintf(userhost, sizeof(userhost), "%s@%s", user, host);
	snprintf(sslenv, sizeof(sslenv), "SSHPASS=%s", pass);
	pid = fork();
	if (pid < 0) {
		snprintf(errbuf, errsz, "OSError: fork failed");
		goto fail;
	}
	if (pid == 0) {
		char *argv[13];
		char o1[40], o2[40], o3[44], o4[40], o5[40], fwd[40];
		char **envp;
		int devnull;

		for (int fd = 3; fd < 1024; fd++)
			close(fd);
		devnull = open("/dev/null", O_RDWR);
		if (devnull >= 0) {
			if (dup2(devnull, STDIN_FILENO) < 0)
				_exit(127);
			if (dup2(devnull, STDOUT_FILENO) < 0)
				_exit(127);
			if (dup2(devnull, STDERR_FILENO) < 0)
				_exit(127);
			if (devnull > 2)
				close(devnull);
		}
		snprintf(o1, sizeof(o1), "-oConnectTimeout=8");
		snprintf(o2, sizeof(o2), "-oStrictHostKeyChecking=no");
		snprintf(o3, sizeof(o3), "-oUserKnownHostsFile=/dev/null");
		snprintf(o4, sizeof(o4), "-oExitOnForwardFailure=yes");
		snprintf(o5, sizeof(o5), "-oServerAliveInterval=30");
		snprintf(fwd, sizeof(fwd), "-L%d:127.0.0.1:8761",
			 VM_LOCAL_PORT);
		argv[0] = (char *)"sshpass";
		argv[1] = (char *)"-e";
		argv[2] = (char *)"ssh";
		argv[3] = (char *)"-N";
		argv[4] = fwd;
		argv[5] = o1;
		argv[6] = o2;
		argv[7] = o3;
		argv[8] = o4;
		argv[9] = o5;
		argv[10] = (char *)"-oLogLevel=ERROR";
		argv[11] = userhost;
		argv[12] = NULL;
		envp = build_envp(sslenv);
		if (!envp)
			_exit(127);
		execve(SSH_PATH, argv, envp);
		_exit(127);
	}
	g_tpid = pid;
	/* ssh 建链后 -L 监听才可用:就绪轮询 ≤8s */
	for (int i = 0; i < 80; i++) {
		int status;

		if (waitpid(pid, &status, WNOHANG) > 0) {
			g_tpid = 0;
			snprintf(errbuf, errsz,
				 "SSHException: tunnel ssh exited");
			goto fail;
		}
		if (local_port_ready()) {
			g_tts = dt_time();
			g_tlast_err[0] = '\0';
			dt_log("VM 隧道已建立 127.0.0.1:%d -> 138:8761",
			       VM_LOCAL_PORT);
			return 0;
		}
		sleep_ms(100);
	}
	{
		int status;

		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
	}
	g_tpid = 0;
	snprintf(errbuf, errsz, "SSHException: tunnel setup timeout");
fail:
	snprintf(g_tlast_err, sizeof(g_tlast_err), "%s", errbuf);
	dt_log("VM 隧道失败: %s", g_tlast_err);
	return -1;
}

void dt_vm_housekeeping_tick(void)
{
	if (!g_cfg.vm_enabled)
		return;
	pthread_mutex_lock(&g_lock_vm);
	if (g_tpid > 0 && dt_time() - g_tts > VM_IDLE_CLOSE)
		vm_close_locked();
	pthread_mutex_unlock(&g_lock_vm);
}

/* ---------------- token ---------------- */

static char *vm_token(void)
{
	char *out = NULL;
	char err[256];

	if (!g_cfg.vm_enabled)
		return NULL;
	if (vm_ssh_exec(dt_vm_cmd_token(), &out, err, sizeof(err)) != 0) {
		char first[64];
		const char *sp = strchr(err, ':');

		/* 日志只记异常类名(server.py 口径),不带细节 */
		{
			size_t n = sp ? (size_t)(sp - err) : strlen(err);

			if (n >= sizeof(first))
				n = sizeof(first) - 1;
			memcpy(first, err, n);
			first[n] = '\0';
		}
		dt_log("VM token 读取失败: %s", first);
		free(out);
		return NULL;
	}
	{
		char *stripped = out ? dt_strip(out) : NULL;

		free(out);
		if (!stripped || !*stripped) {
			free(stripped);
			return NULL;
		}
		return stripped;
	}
}

/* ---------------- 本地 vm_api(明文 GET + Bearer) ---------------- */

static int local_http_get(const char *path, const char *tok, char **body_out,
			  int *status_out, char *errtype, size_t etz)
{
	int fd;
	struct sockaddr_in sa;
	struct timeval tv = { 8, 0 };
	char head[640];
	struct dt_sbuf resp;
	ssize_t off = 0;

	*body_out = NULL;
	*status_out = 0;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		snprintf(errtype, etz, "URLError");
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(VM_LOCAL_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		close(fd);
		snprintf(errtype, etz, "URLError");
		return -1;
	}
	snprintf(head, sizeof(head),
		 "GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n"
		 "Content-Type: application/json\r\n"
		 "Authorization: Bearer %s\r\nConnection: close\r\n\r\n",
		 path, VM_LOCAL_PORT, tok);
	while (off < (ssize_t)strlen(head)) {
		ssize_t n = write(fd, head + off, strlen(head) - (size_t)off);

		if (n <= 0)
			break;
		off += n;
	}
	dt_sb_init(&resp);
	for (;;) {
		char buf[8192];
		ssize_t n = read(fd, buf, sizeof(buf));

		if (n <= 0)
			break;
		dt_sb_puts(&resp, buf, (size_t)n);
	}
	close(fd);
	if (!resp.p) {
		snprintf(errtype, etz, "URLError");
		return -1;
	}
	{
		char *sep = strstr(resp.p, "\r\n\r\n");
		char *body;
		char *sp;

		if (!sep) {
			free(resp.p);
			snprintf(errtype, etz, "URLError");
			return -1;
		}
		body = strdup(sep + 4);
		*sep = '\0';
		sp = strchr(resp.p, ' ');
		*status_out = sp ? atoi(sp + 1) : 0;
		free(resp.p);
		if (*status_out < 100 || !body) {
			free(body);
			snprintf(errtype, etz, "URLError");
			return -1;
		}
		*body_out = body;
		return 0;
	}
}

int dt_vm_api_get(const char *path, aik_json **data, char *err, size_t errsz)
{
	char *body = NULL;
	int status = 0;
	char etype[64];
	char *tok;

	*data = NULL;
	err[0] = '\0';
	if (!g_cfg.vm_enabled) {
		snprintf(err, errsz, "%s", DT_VM_DISABLED_REASON);
		return 0;
	}
	pthread_mutex_lock(&g_lock_vm);
	if (tunnel_ensure(etype, sizeof(etype)) != 0) {
		pthread_mutex_unlock(&g_lock_vm);
		snprintf(err, errsz, "tunnel failed: %s", etype);
		return 0;
	}
	pthread_mutex_unlock(&g_lock_vm);
	tok = vm_token();
	if (!tok) {
		dt_vm_close();
		snprintf(err, errsz, "no token");
		return 0;
	}
	if (local_http_get(path, tok, &body, &status, etype, sizeof(etype)) !=
	    0) {
		free(tok);
		free(body);
		snprintf(err, errsz, "%s", etype);
		return 0;
	}
	free(tok);
	if (status < 200 || status >= 300) {
		free(body);
		snprintf(err, errsz, "HTTP %d", status);
		return 0;
	}
	{
		aik_json *obj = dt_parse(body, strlen(body));

		free(body);
		if (!obj) {
			snprintf(err, errsz, "JSONDecodeError");
			return 0;
		}
		*data = obj;
		return 1;
	}
}

/* ---------------- 纯解析:ai / aiops / sandbox ---------------- */

/* raw.split("---") 的第 idx 段;*count = 分段数(Python 非重叠左扫) */
static void split_dashes(const char *raw, int idx, const char **seg,
			 size_t *seglen, int *count)
{
	const char *p = raw;
	int seen = 0;

	*seg = NULL;
	*seglen = 0;
	*count = 0;
	for (const char *q = raw; (q = strstr(q, "---")) != NULL; q += 3)
		(*count)++;
	while (1) {
		const char *next = p ? strstr(p, "---") : NULL;

		if (seen == idx) {
			*seg = p;
			*seglen = next ? (size_t)(next - p)
				       : (p ? strlen(p) : 0);
			return;
		}
		if (!next)
			return;
		seen++;
		p = next + 3;
	}
}

/* search r"键:\s*(\d+)" → 整数;未命中 *found=0 */
static long long search_key_int(const char *raw, const char *key, int *found)
{
	size_t klen = strlen(key);
	const char *p = raw;

	*found = 0;
	while ((p = strstr(p, key)) != NULL) {
		const char *q = p + klen;

		if (*q == ':') {
			q++;
			while (*q == ' ' || *q == '\t' || *q == '\n' ||
			       *q == '\r' || *q == '\f' || *q == '\v')
				q++;
			if (*q >= '0' && *q <= '9') {
				*found = 1;
				return strtoll(q, NULL, 10);
			}
		}
		p += klen;
	}
	return 0;
}

/* findall r"cpu\d+: emitted=(\d+)" 求和 */
static long long sum_cpu_emitted(const char *raw)
{
	long long sum = 0;
	const char *p = raw;

	while ((p = strstr(p, "cpu")) != NULL) {
		const char *d = p + 3;

		if (*d >= '0' && *d <= '9') {
			d += strspn(d, "0123456789");
			if (strncmp(d, ": emitted=", 10) == 0 &&
			    d[10] >= '0' && d[10] <= '9') {
				sum += strtoll(d + 10, NULL, 10);
				d += 10;
				d += strspn(d, "0123456789");
			}
		}
		p = d;
	}
	return sum;
}

/* findall r"dropped=(\d+)" 求和 */
static long long sum_dropped(const char *raw)
{
	long long sum = 0;
	const char *p = raw;

	while ((p = strstr(p, "dropped=")) != NULL) {
		const char *d = p + 8;

		if (*d >= '0' && *d <= '9') {
			sum += strtoll(d, NULL, 10);
			d += strspn(d, "0123456789");
		}
		p = d;
	}
	return sum;
}

/* search r"name=(\S+)\s+version=(\S+)\s+source=\d+\s+state=(\d+)" */
static int search_model_line(const char *raw, char **name, size_t *name_len,
			     long long *state)
{
	const char *p = raw;

	*name = NULL;
	*name_len = 0;
	*state = 0;
	while ((p = strstr(p, "name=")) != NULL) {
		const char *ns = p + 5;
		const char *ne = ns;

		while (*ne && !line_is_ws(*ne))
			ne++;
		if (ns == ne) {
			p += 5;
			continue;
		}
		{
			const char *v = ne;

			while (*v && line_is_ws(*v))
				v++;
			if (strncmp(v, "version=", 8) != 0) {
				p = ne;
				continue;
			}
			{
				const char *ve = v + 8;

				while (*ve && !line_is_ws(*ve))
					ve++;
				if (ve == v + 8) {
					p = ve;
					continue;
				}
				{
					const char *s = ve;

					while (*s && line_is_ws(*s))
						s++;
					if (strncmp(s, "source=", 7) != 0 ||
					    !(s[7] >= '0' && s[7] <= '9')) {
						p = ve;
						continue;
					}
					{
						const char *d =
							s + 7 +
							strspn(s + 7,
							       "0123456789");
						const char *st = d;

						while (*st && line_is_ws(*st))
							st++;
						if (strncmp(st, "state=", 6) !=
							    0 ||
						    !(st[6] >= '0' &&
						      st[6] <= '9')) {
							p = d;
							continue;
						}
						*name = strndup(
							ns, (size_t)(ne - ns));
						*name_len = (size_t)(ne - ns);
						*state = strtoll(st + 6, NULL,
								 10);
						return 1;
					}
				}
			}
		}
	}
	return 0;
}

int dt_vm_parse_ai(const char *raw, aik_json *o)
{
	const char *seg;
	size_t seglen;
	int count;

	if (!strstr(raw, "runtime_state"))
		return -1; /* "/proc/ai 不可读"(调用方 vm_close) */
	{
		aik_json *ai = dt_new_obj();
		int f1, f2, mf;
		long long v;
		char *mname;
		size_t mname_len;
		long long mstate;

		v = search_key_int(raw, "enabled", &f1);
		if (f1)
			dt_put_int(ai, "enabled", v);
		else
			dt_put_null(ai, "enabled");
		v = search_key_int(raw, "runtime_state", &f2);
		if (f2)
			dt_put_int(ai, "runtime_state", v);
		else
			dt_put_null(ai, "runtime_state");
		mf = search_model_line(raw, &mname, &mname_len, &mstate);
		if (mf && mname)
			dt_put_str(ai, "model", mname);
		else
			dt_put_null(ai, "model");
		if (mf)
			dt_put_int(ai, "model_state", mstate);
		else
			dt_put_null(ai, "model_state");
		dt_put_int(ai, "telemetry_emitted", sum_cpu_emitted(raw));
		dt_put_int(ai, "telemetry_dropped", sum_dropped(raw));
		free(mname);
		dt_put_bool(o, "reachable", 1);
		aik_json_obj_put(o, "ai", ai);
	}
	/* load_line = split("---")[1].strip().split()[0](无段则 "0") */
	split_dashes(raw, 1, &seg, &seglen, &count);
	{
		char loadbuf[64];

		if (!seg || !seglen) {
			snprintf(loadbuf, sizeof(loadbuf), "0");
		} else {
			size_t b = 0, e = seglen, i;

			while (b < e && line_is_ws(seg[b]))
				b++;
			while (e > b && line_is_ws(seg[e - 1]))
				e--;
			i = b;
			while (i < e && !line_is_ws(seg[i]))
				i++;
			if (i > b) {
				size_t L = i - b;

				if (L >= sizeof(loadbuf))
					L = sizeof(loadbuf) - 1;
				memcpy(loadbuf, seg + b, L);
				loadbuf[L] = '\0';
			} else {
				snprintf(loadbuf, sizeof(loadbuf), "0");
			}
		}
		{
			char *endp = NULL;
			double v = strtod(loadbuf, &endp);

			if (endp == loadbuf) {
				/* float() ValueError → 外层异常形 */
				return -2;
			}
			dt_put_num(o, "load1", v);
		}
	}
	/* mem = split("---")[2]:round(100.0*parts[2]/parts[1],1) 或 "n/a" */
	split_dashes(raw, 2, &seg, &seglen, &count);
	if (!seg) {
		dt_put_str(o, "mem_pct", "n/a");
	} else {
		char *dupseg = strndup(seg, seglen);
		int done = 0;

		if (dupseg) {
			char *save = NULL;
			char *toks[8];
			int nt = 0;

			for (char *tk = strtok_r(dupseg, " \t\r\n\f\v", &save);
			     tk && nt < 8;
			     tk = strtok_r(NULL, " \t\r\n\f\v", &save))
				toks[nt++] = tk;
			if (nt >= 3) {
				char *e1 = NULL, *e2 = NULL;
				long long used = strtoll(toks[2], &e1, 10);
				long long tot = strtoll(toks[1], &e2, 10);

				if (e1 && *e1 == '\0' && e2 && *e2 == '\0') {
					if (tot != 0) {
						dt_put_num(
							o, "mem_pct",
							dt_py_round1(
								100.0 *
									(double)
										used /
									(double)tot));
						done = 1;
					}
					/* tot==0 → ZeroDivision → n/a */
				}
			}
			free(dupseg);
		}
		if (!done)
			dt_put_str(o, "mem_pct", "n/a");
	}
	return 0;
}

/* 遥测行 re.match r"ts=(\d+)\s+pid=(\d+)\s+tgid=\d+\s+cpu=(\d+)\s+
 * cat=(\d+)\s+ev=(\d+)\s+sev=(\d+)\s+len=(\d+)"(前缀匹配,尾随不限) */
static int match_tele_line(const char *line, long long v[7], long long *lenv)
{
	static const char *keys[7] = { "ts=", "pid=", "tgid=", "cpu=",
				       "cat=",  "ev=",  "sev=" };
	const char *p = line;

	for (int i = 0; i < 7; i++) {
		size_t klen = strlen(keys[i]);

		if (strncmp(p, keys[i], klen) != 0)
			return 0;
		p += klen;
		if (!(*p >= '0' && *p <= '9'))
			return 0;
		v[i] = strtoll(p, NULL, 10);
		p += strspn(p, "0123456789");
		{
			size_t ws = strspn(p, " \t\r\f\v");

			if (ws == 0)
				return 0; /* \s+ */
			if (i == 6) {
				p += ws;
				goto sev_done;
			}
			p += ws;
		}
	}
sev_done:
	if (strncmp(p, "len=", 4) != 0)
		return 0;
	p += 4;
	if (!(*p >= '0' && *p <= '9'))
		return 0;
	*lenv = strtoll(p, NULL, 10);
	return 1;
}

int dt_vm_parse_aiops(const char *raw, aik_json *o)
{
	const char *seg;
	size_t seglen;
	int count;
	long long dec_size = 0;

	/* dec_size = int(parts[0].split()[0]) except 0 */
	split_dashes(raw, 0, &seg, &seglen, &count);
	if (seg && seglen) {
		char *dupseg = strndup(seg, seglen);

		if (dupseg) {
			char *save = NULL;
			char *tk = strtok_r(dupseg, " \t\r\n\f\v", &save);

			if (tk) {
				char *e = NULL;
				long long v = strtoll(tk, &e, 10);

				if (e && *e == '\0')
					dec_size = v;
			}
			free(dupseg);
		}
	}
	dt_put_bool(o, "reachable", 1);
	dt_put_int(o, "decisions_size", dec_size);
	/* decisions_raw = parts[1].strip()[:2000 码点] */
	split_dashes(raw, 1, &seg, &seglen, &count);
	if (seg && seglen) {
		char *dupseg = strndup(seg, seglen);
		char *d = dupseg ? dt_strip(dupseg) : NULL;
		char *head = d ? dt_utf8_head(d, 2000) : NULL;

		dt_put_str(o, "decisions_raw", head ? head : "");
		free(head);
		free(d);
		free(dupseg);
	} else {
		dt_put_str(o, "decisions_raw", "");
	}
	dt_put_bool(o, "decisions_empty", dec_size == 0);
	{
		/* events = 遥测行解析(末 20) */
		aik_json *events = dt_new_arr();
		long long total = 0;

		split_dashes(raw, 2, &seg, &seglen, &count);
		if (seg && seglen) {
			char *dupseg = strndup(seg, seglen);

			if (dupseg) {
				char *save = NULL;

				for (char *line = strtok_r(dupseg, "\n", &save);
				     line; line = strtok_r(NULL, "\n", &save)) {
					size_t ln = strlen(line);

					if (ln && line[ln - 1] == '\r')
						line[ln - 1] = '\0';
					{
						long long v[7];
						long long lenv;

						if (match_tele_line(line, v,
								    &lenv)) {
							aik_json *e =
								dt_new_obj();

							total++;
							dt_put_int(e, "ts",
								   v[0]);
							dt_put_int(e, "pid",
								   v[1]);
							dt_put_int(e, "cpu",
								   v[3]);
							dt_put_int(e, "cat",
								   v[4]);
							dt_put_int(e, "ev",
								   v[5]);
							dt_put_int(e, "sev",
								   v[6]);
							dt_put_int(e, "len",
								   lenv);
							aik_json_arr_push(
								events, e);
						}
					}
				}
				free(dupseg);
			}
		}
		{
			size_t n = aik_json_count(events);

			if (n > 20) {
				aik_json *kept = dt_new_arr();

				for (size_t i = n - 20; i < n; i++)
					dt_arr_push_copy(kept,
							 aik_json_at(events,
								     i));
				aik_json_free(events);
				events = kept;
			}
		}
		aik_json_obj_put(o, "events", events);
		dt_put_int(o, "event_total_recent", total);
	}
	return 0;
}

long long dt_vm_sandbox_is_empty(const char *raw)
{
	long long nl = 0;

	if (!raw)
		return 0;
	if (!strstr(raw, "total 8"))
		return 0;
	if (!strstr(raw, "---MOUNTS---"))
		return 0;
	for (const char *p = raw; *p; p++)
		if (*p == '\n')
			nl++;
	return nl < 8;
}

/* ---------------- 快照入口 ---------------- */

aik_json *dt_vm_ai_snapshot(void)
{
	char *raw = NULL;
	char err[256];
	aik_json *o;

	if (vm_ssh_exec(dt_vm_cmd_ai(), &raw, err, sizeof(err)) != 0) {
		dt_vm_close();
		o = dt_new_obj();
		dt_put_bool(o, "reachable", 0);
		dt_put_str(o, "error", err);
		return o;
	}
	o = dt_new_obj();
	{
		int rc = dt_vm_parse_ai(raw, o);

		if (rc != 0) {
			aik_json_free(o);
			dt_vm_close();
			o = dt_new_obj();
			dt_put_bool(o, "reachable", 0);
			dt_put_str(o, "error",
				   rc == -1 ? "/proc/ai 不可读"
					    : "ValueError: could not convert "
					      "string to float");
		}
	}
	free(raw);
	return o;
}

aik_json *dt_vm_aiops_snapshot(void)
{
	char *raw = NULL;
	char err[256];
	aik_json *o;

	if (vm_ssh_exec(dt_vm_cmd_aiops(), &raw, err, sizeof(err)) != 0) {
		dt_vm_close();
		o = dt_new_obj();
		dt_put_bool(o, "reachable", 0);
		dt_put_str(o, "error", err);
		return o;
	}
	o = dt_new_obj();
	dt_vm_parse_aiops(raw, o);
	free(raw);
	return o;
}

aik_json *dt_vm_status_snapshot(void)
{
	if (!g_cfg.vm_enabled) {
		aik_json *obj;
		aik_json *o = dt_new_obj();
		const aik_json *wins;
		size_t nw = 0;

		pthread_mutex_lock(&g_lock_desktop);
		obj = dt_load_desktop();
		wins = dt_get(obj, "windows");
		if (wins && aik_json_typeof(wins) == AIK_JSON_ARR)
			nw = aik_json_count(wins);
		dt_put_bool(o, "reachable", 0);
		dt_put_bool(o, "available", 0);
		dt_put_str(o, "mode", "local");
		dt_put_str(o, "error", DT_VM_DISABLED_REASON);
		{
			aik_json *desk = dt_new_obj();

			dt_put_str(desk, "backend",
				   "web-demo-virtual-window");
			dt_put_int(desk, "windows", (long long)nw);
			aik_json_obj_put(o, "desktop", desk);
		}
		dt_put_str(o, "note",
			   "factory/VM 只提供本地桌面状态;L1 VM 隧道已禁用");
		aik_json_free(obj);
		pthread_mutex_unlock(&g_lock_desktop);
		return o;
	}
	{
		aik_json *st = NULL, *se = NULL;
		char e1[256] = { 0 }, e2[256] = { 0 };
		int ok1 = dt_vm_api_get("/health", &st, e1, sizeof(e1));
		int ok2 = dt_vm_api_get("/sense?what=status", &se, e2,
					sizeof(e2));
		aik_json *o = dt_new_obj();

		if (!ok1 && !ok2) {
			dt_vm_close();
			dt_put_bool(o, "reachable", 0);
			dt_put_str(o, "error", *e1 ? e1 : e2);
			return o;
		}
		dt_put_bool(o, "reachable", 1);
		if (ok1)
			aik_json_obj_put(o, "status", st);
		else
			dt_put_null(o, "status");
		if (ok2)
			aik_json_obj_put(o, "sense", se);
		else
			dt_put_null(o, "sense");
		return o;
	}
}

aik_json *dt_vm_sandbox_snapshot(void)
{
	if (!g_cfg.vm_enabled) {
		aik_json *o = dt_new_obj();

		dt_put_bool(o, "reachable", 0);
		dt_put_bool(o, "available", 0);
		dt_put_str(o, "raw", "");
		dt_put_bool(o, "empty", 1);
		dt_put_str(o, "error", DT_VM_DISABLED_REASON);
		return o;
	}
	{
		char *raw = NULL;
		char err[256];

		if (vm_ssh_exec(dt_vm_cmd_sandbox(), &raw, err,
				sizeof(err)) != 0) {
			aik_json *o = dt_new_obj();

			dt_vm_close();
			dt_put_bool(o, "reachable", 0);
			dt_put_str(o, "error", err);
			return o;
		}
		{
			aik_json *o = dt_new_obj();
			char *head = raw ? dt_utf8_head(raw, 2000) : strdup("");

			dt_put_bool(o, "reachable", 1);
			dt_put_str(o, "raw", head ? head : "");
			dt_put_bool(o, "empty",
				    (long long)dt_vm_sandbox_is_empty(
					    head ? head : ""));
			free(head);
			free(raw);
			return o;
		}
	}
}
