/* SPDX-License-Identifier: GPL-2.0 */
/*
 * tlsgw.c - T7c aik-tls-gateway(C+mbedTLS):TLS 服务端 + 监听/线程/main
 *
 * 参考 aik_tls_gateway.py 主流程(规格 T7C-PROGRESS.md §A1):
 *   缺证书即退(rc=1,文案逐字);LISTEN rsplit/int 失败即退;bind 失败即退;
 *   TLS:min TLS1.2 + CERT_REQUIRED + ca.crt;
 *   LISTENING <host>:<port> -> <BACKEND> (<VERSION>);SIGTERM/SIGINT → EXIT rc=0。
 *
 * 与参考的结构差异(客户端不可观测,报告声明):
 *   - TLS 握手在连接线程内(参考在 accept 循环串行完成);
 *   - 每连接独立 ctr_drbg(getrandom 种子;vendored mbedtls 无 THREADING_C,
 *     共享 DRBG 非线程安全);
 *   - 未捕获异常等价 = 单行 stderr 日志(参考打印 Python traceback)。
 */
#define _POSIX_C_SOURCE 200809L

#include "tlsgw/tlsgw.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "mbedtls/build_info.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

/* ---------------- 全局 ---------------- */

static volatile sig_atomic_t g_stop = 0;
static int g_listen_fd = -1;

struct gw_tls_ctx {
	mbedtls_ssl_config conf;	/* 只读共享 */
	mbedtls_x509_crt server_crt;
	mbedtls_x509_crt ca_crt;
	mbedtls_pk_context server_key;
};

struct gw_conn_arg {
	int fd;
	struct gw_tls_ctx *tls;
	struct gw_cfg cfg;
	char backend_host[320];
	int backend_port;
	char peer_ip[64];
};

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
	if (g_listen_fd >= 0)
		shutdown(g_listen_fd, SHUT_RDWR);
}

/* 无状态 RNG 回调(getrandom;vendored mbedtls 无 THREADING_C,
 * 共享 DRBG 非线程安全 → 每调用直读内核熵,天然线程安全) */
static int gw_getrandom_rng(void *ctx, unsigned char *buf, size_t len)
{
	(void)ctx;
	while (len > 0) {
		ssize_t n = getrandom(buf, len, 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
		}
		buf += n;
		len -= (size_t)n;
	}
	return 0;
}

static const char *getenv_wrapper(void *ctx, const char *name)
{
	(void)ctx;
	return getenv(name);
}

/* gw_stream.read 语义:>=0 字节;0=EOF;-2=错误 */
static int stream_tls_read(void *ctx, unsigned char *buf, size_t n)
{
	mbedtls_ssl_context *ssl = ctx;

	for (;;) {
		int rc = mbedtls_ssl_read(ssl, buf, n);

		if (rc > 0)
			return rc;
		if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ||
		    rc == MBEDTLS_ERR_SSL_CONN_EOF ||
		    rc == MBEDTLS_ERR_NET_CONN_RESET)
			return 0;	/* py SSLError/EOF → 关连接 */
		if (rc == MBEDTLS_ERR_SSL_WANT_READ ||
		    rc == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;	/* 阻塞 fd:罕见 */
		return -2;
	}
}

static int stream_tls_write(void *ctx, const unsigned char *buf, size_t n)
{
	mbedtls_ssl_context *ssl = ctx;

	for (;;) {
		int rc = mbedtls_ssl_write(ssl, buf, n);

		if (rc >= 0 && (size_t)rc == n)
			return 0;
		if (rc >= 0)
			continue;
		if (rc == MBEDTLS_ERR_SSL_WANT_READ ||
		    rc == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;
		return -1;
	}
}

/* mbedtls BIO(裸 fd) */
static int bio_send(void *ctx, const unsigned char *buf, size_t len)
{
	int fd = *(int *)ctx;
	ssize_t n;

	for (;;) {
		n = send(fd, buf, len, MSG_NOSIGNAL);
		if (n >= 0)
			return (int)n;
		if (errno == EINTR)
			continue;
		return MBEDTLS_ERR_NET_SEND_FAILED;
	}
}

static int bio_recv(void *ctx, unsigned char *buf, size_t len)
{
	int fd = *(int *)ctx;
	ssize_t n;

	for (;;) {
		n = recv(fd, buf, len, 0);
		if (n >= 0)
			return (int)n;
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return MBEDTLS_ERR_SSL_WANT_READ;
		return MBEDTLS_ERR_NET_RECV_FAILED;
	}
}

/* 对端证书 Subject 最后一个 CN(py getpeercert 循环后者覆盖) */
static void peer_cn(const mbedtls_x509_crt *crt, char *out, size_t cap)
{
	char buf[512];
	int n;
	const char *p;

	out[0] = '\0';
	if (!crt)
		return;
	n = mbedtls_x509_dn_gets(buf, sizeof(buf), &crt->subject);
	if (n < 0)
		return;
	buf[n < (int)sizeof(buf) ? n : (int)sizeof(buf) - 1] = '\0';
	p = buf;
	for (;;) {
		const char *hit = strstr(p, "CN=");
		const char *val;
		size_t i = 0;

		if (!hit)
			return;
		val = hit + 3;
		while (val[i] && val[i] != ',')
			i++;
		if (i >= cap)
			i = cap - 1;
		memcpy(out, val, i);
		out[i] = '\0';
		p = val + i;		/* 继续找下一个(最后一个生效) */
	}
}

/* ---------------- 连接线程 ---------------- */

static void *conn_main(void *arg)
{
	struct gw_conn_arg *ca = arg;
	struct gw_tls_ctx *tc = ca->tls;
	mbedtls_ssl_context ssl;
	struct gw_serve sv;
	struct gw_stream io;
	int rc;

	mbedtls_ssl_init(&ssl);
	if (mbedtls_ssl_setup(&ssl, &tc->conf) != 0)
		goto out;
	mbedtls_ssl_set_bio(&ssl, &ca->fd, bio_send, bio_recv, NULL);

	rc = mbedtls_ssl_handshake(&ssl);
	if (rc != 0)
		goto out;	/* py:accept 内 SSLError 被吞,客户端收 alert */
	if (mbedtls_ssl_get_verify_result(&ssl) != 0 ||
	    mbedtls_ssl_get_peer_cert(&ssl) == NULL) {
		/* py CERT_REQUIRED 语义:无客户端证书/验证不过一律断
		 * (mbedtls TLS1.3 下 handshake 可能先返 0,此处兜底) */
		goto out;
	}

	{
		char cn[128];
		const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&ssl);

		peer_cn(peer, cn, sizeof(cn));
		memset(&sv, 0, sizeof(sv));
		io.ctx = &ssl;
		io.read = stream_tls_read;
		io.write = stream_tls_write;
		sv.io = &io;
		sv.cfg = &ca->cfg;
		snprintf(sv.backend_host, sizeof(sv.backend_host), "%s",
			 ca->backend_host);
		sv.backend_port = ca->backend_port;
		sv.peer_ip = ca->peer_ip;
		sv.cn = cn;
		sv.log = stderr;
		for (;;) {
			int r = gw_serve_conn(&sv);

			if (r <= 0)
				break;
		}
	}
out:
	mbedtls_ssl_free(&ssl);
	close(ca->fd);
	free(ca);
	return NULL;
}

/* ---------------- 证书加载 ---------------- */

static int load_certs(struct gw_tls_ctx *tc, const struct gw_cfg *cfg,
		      char *detail, size_t cap)
{
	int rc;

	mbedtls_x509_crt_init(&tc->server_crt);
	mbedtls_x509_crt_init(&tc->ca_crt);
	mbedtls_pk_init(&tc->server_key);

	rc = mbedtls_x509_crt_parse_file(&tc->server_crt, cfg->server_crt);
	if (rc != 0) {
		mbedtls_strerror(rc, detail, cap);
		return -1;
	}
	rc = mbedtls_pk_parse_keyfile(&tc->server_key, cfg->server_key,
				       NULL, gw_getrandom_rng, NULL);
	if (rc != 0) {
		mbedtls_strerror(rc, detail, cap);
		return -1;
	}
	rc = mbedtls_x509_crt_parse_file(&tc->ca_crt, cfg->ca_crt);
	if (rc != 0) {
		mbedtls_strerror(rc, detail, cap);
		return -1;
	}
	return 0;
}

/* ---------------- main ---------------- */

static void die(const char *msg)
{
	gw_die_msg(stderr, msg);
	exit(1);
}

int main(void)
{
	struct gw_cfg cfg;
	struct gw_tls_ctx tc;
	char host[256];
	char detail[512];
	char msg[4600];
	int port = 0;
	struct addrinfo hints, *res = NULL, *ai;
	char portstr[16];
	struct gw_conn_arg *ca;
	pthread_t tid;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	gw_cfg_from_env(&cfg, (gw_getenv_fn)getenv_wrapper, NULL);

	/* 证书缺失检查(顺序同参考;文案逐字) */
	{
		char missing[4352];
		int miss = gw_first_missing_cert(&cfg, missing,
						 sizeof(missing));

		if (miss) {
			gw_missing_cert_msg(missing, msg, sizeof(msg));
			die(msg);
		}
	}
	/* 证书加载失败(前缀逐字;detail=mbedtls 文案,白名单) */
	if (load_certs(&tc, &cfg, detail, sizeof(detail)) != 0) {
		snprintf(msg, sizeof(msg), "证书加载失败: %s", detail);
		die(msg);
	}
	/* LISTEN 解析 */
	if (gw_parse_listen(cfg.listen, host, sizeof(host), &port) != 0) {
		gw_listen_bad_msg(cfg.listen, msg, sizeof(msg));
		die(msg);
	}
	/* 监听(AF_INET;参考 GatewayServer.address_family 固定 IPv4) */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(portstr, sizeof(portstr), "%d", port);
	if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
		snprintf(msg, sizeof(msg),
			 "监听 %s 失败: [Errno -2] Name or service not known",
			 cfg.listen);
		die(msg);
	}
	{
		int fd = -1;
		int bind_errno = 0;

		for (ai = res; ai; ai = ai->ai_next) {
			int one = 1;

			fd = socket(ai->ai_family, ai->ai_socktype,
				    ai->ai_protocol);
			if (fd < 0)
				continue;
			(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one,
					 sizeof(one)); /* allow_reuse_address */
			if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 &&
			    listen(fd, 128) == 0)
				break;
			bind_errno = errno;
			close(fd);
			fd = -1;
		}
		freeaddrinfo(res);
		if (fd < 0) {
			gw_listen_fail_msg(cfg.listen,
					   bind_errno ? bind_errno : EACCES,
					   msg, sizeof(msg));
			die(msg);
		}
		g_listen_fd = fd;
	}
	/* SSL 配置:min TLS1.2 + CERT_REQUIRED + CA 链 + 自证 */
	{
		int rc = mbedtls_ssl_config_defaults(&tc.conf,
						     MBEDTLS_SSL_IS_SERVER,
						     MBEDTLS_SSL_TRANSPORT_STREAM,
						     MBEDTLS_SSL_PRESET_DEFAULT);

		if (rc != 0) {
			mbedtls_strerror(rc, detail, sizeof(detail));
			snprintf(msg, sizeof(msg), "TLS 初始化失败: %s",
				 detail);
			die(msg);
		}
		mbedtls_ssl_conf_min_tls_version(&tc.conf,
						 MBEDTLS_SSL_VERSION_TLS1_2);
		mbedtls_ssl_conf_rng(&tc.conf, gw_getrandom_rng, NULL);
		mbedtls_ssl_conf_authmode(&tc.conf,
					  MBEDTLS_SSL_VERIFY_REQUIRED);
		mbedtls_ssl_conf_ca_chain(&tc.conf, &tc.ca_crt, NULL);
		rc = mbedtls_ssl_conf_own_cert(&tc.conf, &tc.server_crt,
					       &tc.server_key);
		if (rc != 0) {
			mbedtls_strerror(rc, detail, sizeof(detail));
			snprintf(msg, sizeof(msg), "TLS 初始化失败: %s",
				 detail);
			die(msg);
		}
	}
	{
		struct sockaddr_in sin;
		socklen_t sl = sizeof(sin);
		char ip[INET_ADDRSTRLEN];
		int lport = port;

		memset(&sin, 0, sizeof(sin));
		if (getsockname(g_listen_fd, (struct sockaddr *)&sin, &sl) == 0) {
			inet_ntop(AF_INET, &sin.sin_addr, ip, sizeof(ip));
			lport = ntohs(sin.sin_port);
		} else if (strlen(host) < sizeof(ip)) {
			snprintf(ip, sizeof(ip), "%s", host);
		} else {
			ip[0] = '\0';
		}
		printf("LISTENING %s:%d -> %s (%s)\n", ip, lport, cfg.backend,
		       GW_VERSION);
		fflush(stdout);
	}

	/* accept 循环(每连接一线程;握手在线程内) */
	while (!g_stop) {
		struct pollfd pfd;
		int cfd;
		struct sockaddr_in peer;
		socklen_t pl = sizeof(peer);

		pfd.fd = g_listen_fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, 200) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
			break;
		if (!(pfd.revents & POLLIN))
			continue;
		cfd = accept(g_listen_fd, (struct sockaddr *)&peer, &pl);
		if (cfd < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			break;
		}
		ca = calloc(1, sizeof(*ca));
		if (!ca) {
			close(cfd);
			continue;
		}
		ca->fd = cfd;
		ca->tls = &tc;
		ca->cfg = cfg;
		if (gw_parse_listen(cfg.backend, ca->backend_host,
				    sizeof(ca->backend_host),
				    &ca->backend_port) != 0) {
			/* BACKEND 无冒号:py proxy() ValueError 未捕获 →
			 * 连接级崩溃;此处等价 = 收到请求即关 */
			ca->backend_port = 0;
		}
		inet_ntop(AF_INET, &peer.sin_addr, ca->peer_ip,
			  sizeof(ca->peer_ip));
		if (pthread_create(&tid, NULL, conn_main, ca) == 0) {
			pthread_detach(tid);
			continue;
		}
		close(cfd);
		free(ca);
	}
	close(g_listen_fd);
	g_listen_fd = -1;
	printf("EXIT\n");
	fflush(stdout);
	return 0;
}
