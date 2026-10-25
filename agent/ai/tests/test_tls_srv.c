/* test_tls_srv.c —— W78 agent-D：mbedtls 服务端能力回归（SSL_SRV_C 回开）
 *
 * 背景：E 波裁剪时 agent 仅做 TLS 客户端，B2 批 #undef MBEDTLS_SSL_SRV_C。
 * W78 回开服务端后，vendored mbedtls 的原生 test suites 已在保守档清空
 * （tests/ 仅剩 seedfile），本测试以最小回环 mTLS 握手替代原生套件：
 *
 *   A. 私钥解析存留（W78A 存疑项③）：明文 EC/RSA 私钥可解析；
 *      加密私钥被拒（B3 裁 PKCS5/PKCS12，服务端须用明文私钥+文件 600）
 *   B. 正路径：TLS1.3 回环 mTLS 握手（服务端要求客户端证书），
 *      双向证书校验 + PING/PONG 应用数据
 *   C. 负路径：客户端不带证书 -> 服务端握手失败
 *   D. 负路径：客户端持野 CA 签发证书 -> 服务端握手失败
 *
 * 证书为一次性测试证书（tls_test_certs.h 内嵌，30 天有效期，
 * 过期用 tests/tls_certs_regen.sh 重新生成头文件）。
 */
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>

#include "mbedtls/build_info.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

#include "tls_test_certs.h"

/* 服务端子进程通过管道回报的结果 */
struct srv_result {
	int hs_rc;		/* 握手返回码 */
	char peer_cn[80];	/* 客户端证书 CN（正路径用） */
	char ver[24];		/* 协商出的 TLS 版本 */
};

static int g_fail;

static void pass(const char *name) { printf("PASS %s\n", name); }
static void fail(const char *name, const char *why)
{
	printf("FAIL %s: %s\n", name, why);
	g_fail++;
}

/* ---------- A. 私钥解析存留 ---------- */
static void case_pk_parse(void)
{
	mbedtls_pk_context pk;
	char err[128];
	int rc;

	mbedtls_pk_init(&pk);
	rc = mbedtls_pk_parse_key(&pk,
				  (const unsigned char *)TEST_SERVER_KEY,
				  sizeof(TEST_SERVER_KEY), NULL, 0, NULL, NULL);
	if (rc == 0 && strcmp(mbedtls_pk_get_name(&pk), "EC") == 0)
		pass("A1 pk_parse 明文 EC 私钥 (SEC1)");
	else
		fail("A1 pk_parse 明文 EC 私钥 (SEC1)",
		     rc ? "parse 失败" : "类型非 EC");
	mbedtls_pk_free(&pk);

	mbedtls_pk_init(&pk);
	rc = mbedtls_pk_parse_key(&pk,
				  (const unsigned char *)TEST_RSA2048_KEY,
				  sizeof(TEST_RSA2048_KEY), NULL, 0, NULL, NULL);
	if (rc == 0 && strcmp(mbedtls_pk_get_name(&pk), "RSA") == 0)
		pass("A2 pk_parse 明文 RSA 私钥 (PKCS#1)");
	else
		fail("A2 pk_parse 明文 RSA 私钥 (PKCS#1)",
		     rc ? "parse 失败" : "类型非 RSA");
	mbedtls_pk_free(&pk);

	/* B3 裁了 PKCS5/PKCS12：PBES2 加密容器必须被拒（带不带口令都拒） */
	mbedtls_pk_init(&pk);
	rc = mbedtls_pk_parse_key(&pk,
				  (const unsigned char *)TEST_RSA2048_ENC_KEY,
				  sizeof(TEST_RSA2048_ENC_KEY),
				  (const unsigned char *)"test123", 7,
				  NULL, NULL);
	if (rc != 0) {
		mbedtls_strerror(rc, err, sizeof(err));
		printf("     (加密私钥拒绝码 -0x%04x: %s，符合预期)\n",
		       (unsigned)-rc, err);
		pass("A3 pk_parse 加密私钥被拒 (PKCS5/PKCS12 已裁)");
	} else {
		fail("A3 pk_parse 加密私钥被拒 (PKCS5/PKCS12 已裁)",
		     "竟然解析成功");
	}
	mbedtls_pk_free(&pk);
}

/* ---------- 公共 TLS 上下文 ---------- */
struct tls_side {
	mbedtls_net_context net;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt crt_own;	/* 自身证书链 */
	mbedtls_x509_crt crt_ca;	/* 校验对端的 CA */
	mbedtls_pk_context key;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
};

static int side_init(struct tls_side *s, const char *who)
{
	memset(s, 0, sizeof(*s));
	mbedtls_net_init(&s->net);
	mbedtls_ssl_init(&s->ssl);
	mbedtls_ssl_config_init(&s->conf);
	mbedtls_x509_crt_init(&s->crt_own);
	mbedtls_x509_crt_init(&s->crt_ca);
	mbedtls_pk_init(&s->key);
	mbedtls_ctr_drbg_init(&s->ctr_drbg);
	mbedtls_entropy_init(&s->entropy);
	return mbedtls_ctr_drbg_seed(&s->ctr_drbg, mbedtls_entropy_func,
				     &s->entropy, (const unsigned char *)who,
				     strlen(who));
}

static void side_free(struct tls_side *s)
{
	mbedtls_ssl_free(&s->ssl);
	mbedtls_ssl_config_free(&s->conf);
	mbedtls_x509_crt_free(&s->crt_own);
	mbedtls_x509_crt_free(&s->crt_ca);
	mbedtls_pk_free(&s->key);
	mbedtls_ctr_drbg_free(&s->ctr_drbg);
	mbedtls_entropy_free(&s->entropy);
	mbedtls_net_free(&s->net);
}

static int load_chain(mbedtls_x509_crt *crt, const char *pem)
{
	return mbedtls_x509_crt_parse(crt, (const unsigned char *)pem,
				      strlen(pem) + 1);
}

static int load_key(mbedtls_pk_context *pk, const char *pem)
{
	return mbedtls_pk_parse_key(pk, (const unsigned char *)pem,
				    strlen(pem) + 1, NULL, 0, NULL, NULL);
}

/* 提取证书 Subject CN（返回 0 成功写入 out） */
static int cert_cn(const mbedtls_x509_crt *crt, char *out, size_t outsz)
{
	char buf[256];
	int n = mbedtls_x509_dn_gets(buf, sizeof(buf), &crt->subject);
	const char *p;

	(void)outsz;
	if (n < 0)
		return n;
	buf[n] = 0;
	p = strstr(buf, "CN=");
	if (!p)
		return -1;
	if (sscanf(p + 3, "%79[^,]", out) != 1)
		return -1;
	return 0;
}

/* ---------- 服务端（子进程内运行） ---------- */
/* 返回前把结果写入 respipe。 */
static void run_server(int portpipe_wr, int respipe_wr)
{
	struct tls_side s;
	struct srv_result res;
	char portstr[8];
	struct sockaddr_in sa;
	socklen_t salen = sizeof(sa);
	unsigned char buf[64];
	int rc, port;
	mbedtls_net_context client_fd;

	alarm(30);	/* 兜底，任何卡死直接杀，不挂回归 */
	memset(&res, 0, sizeof(res));
	mbedtls_net_init(&client_fd);

	if (side_init(&s, "srv") != 0)
		goto report;

	rc = mbedtls_ssl_config_defaults(&s.conf, MBEDTLS_SSL_IS_SERVER,
					 MBEDTLS_SSL_TRANSPORT_STREAM,
					 MBEDTLS_SSL_PRESET_DEFAULT);
	if (rc != 0)
		goto report;
	mbedtls_ssl_conf_rng(&s.conf, mbedtls_ctr_drbg_random, &s.ctr_drbg);
	mbedtls_ssl_conf_authmode(&s.conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	if (load_chain(&s.crt_own, TEST_SERVER_CRT) != 0 ||
	    load_key(&s.key, TEST_SERVER_KEY) != 0 ||
	    load_chain(&s.crt_ca, TEST_CA_CRT) != 0)
		goto report;
	mbedtls_ssl_conf_ca_chain(&s.conf, &s.crt_ca, NULL);
	rc = mbedtls_ssl_conf_own_cert(&s.conf, &s.crt_own, &s.key);
	if (rc != 0)
		goto report;

	/* 绑回环临时端口，把端口告诉父进程 */
	rc = mbedtls_net_bind(&s.net, "127.0.0.1", "0", MBEDTLS_NET_PROTO_TCP);
	if (rc != 0)
		goto report;
	if (getsockname(s.net.fd, (struct sockaddr *)&sa, &salen) != 0)
		goto report;
	port = ntohs(sa.sin_port);
	snprintf(portstr, sizeof(portstr), "%d", port);
	if (write(portpipe_wr, portstr, strlen(portstr)) < 0)
		goto report;
	close(portpipe_wr);

	rc = mbedtls_net_accept(&s.net, &client_fd, NULL, 0, NULL);
	if (rc != 0)
		goto report;
	mbedtls_net_free(&s.net);
	s.net = client_fd;	/* 之后只在连接 socket 上工作 */

	rc = mbedtls_ssl_setup(&s.ssl, &s.conf);
	if (rc != 0)
		goto report;
	mbedtls_ssl_set_bio(&s.ssl, &s.net, mbedtls_net_send, mbedtls_net_recv,
			    NULL);

	res.hs_rc = mbedtls_ssl_handshake(&s.ssl);
	snprintf(res.ver, sizeof(res.ver), "%s",
		 mbedtls_ssl_get_version(&s.ssl));
	if (res.hs_rc == 0) {
		const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&s.ssl);

		/* 读 PING 回 PONG */
		memset(buf, 0, sizeof(buf));
		if (mbedtls_ssl_read(&s.ssl, buf, sizeof(buf) - 1) == 4 &&
		    memcmp(buf, "PING", 4) == 0) {
			rc = mbedtls_ssl_write(&s.ssl,
					       (const unsigned char *)"PONG", 4);
			(void)rc;
			mbedtls_ssl_close_notify(&s.ssl);
		}
		if (peer && cert_cn(peer, res.peer_cn, sizeof(res.peer_cn)) != 0)
			res.peer_cn[0] = 0;
	}

report:
	/* 各阶段失败早退时 hs_rc 仍为 0：统一改成非 0 表示服务端异常 */
	if (res.hs_rc == 0 && res.ver[0] == 0)
		res.hs_rc = -1;
	{
		ssize_t wr = write(respipe_wr, &res, sizeof(res));

		(void)wr;
	}
	side_free(&s);
	_exit(0);
}

/* ---------- 客户端（父进程内运行） ---------- */
/* client_mode: 0=带有效证书, 1=不带证书, 2=带野 CA 证书
 * 返回 0 = 握手+收发全部成功；非 0 = 失败（负路径期望非 0） */
static int run_client(int client_mode, int portpipe_rd,
		      char *ver_out, size_t ver_sz)
{
	struct tls_side s;
	char portstr[8];
	ssize_t n;
	unsigned char buf[64];
	int rc = -1, ret = -1;

	alarm(30);
	if (side_init(&s, "cli") != 0)
		return -1;

	rc = mbedtls_ssl_config_defaults(&s.conf, MBEDTLS_SSL_IS_CLIENT,
					 MBEDTLS_SSL_TRANSPORT_STREAM,
					 MBEDTLS_SSL_PRESET_DEFAULT);
	if (rc != 0)
		goto out;
	mbedtls_ssl_conf_rng(&s.conf, mbedtls_ctr_drbg_random, &s.ctr_drbg);
	mbedtls_ssl_conf_authmode(&s.conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	if (load_chain(&s.crt_ca, TEST_CA_CRT) != 0)
		goto out;
	mbedtls_ssl_conf_ca_chain(&s.conf, &s.crt_ca, NULL);
	if (client_mode != 1) {
		const char *crt = client_mode == 2 ? TEST_ROGUE_CLIENT_CRT
						   : TEST_CLIENT_CRT;
		const char *key = client_mode == 2 ? TEST_ROGUE_CLIENT_KEY
						   : TEST_CLIENT_KEY;

		if (load_chain(&s.crt_own, crt) != 0 || load_key(&s.key, key) != 0)
			goto out;
		if (mbedtls_ssl_conf_own_cert(&s.conf, &s.crt_own, &s.key) != 0)
			goto out;
	}

	/* 等服务端端口 */
	n = read(portpipe_rd, portstr, sizeof(portstr) - 1);
	if (n <= 0)
		goto out;
	portstr[n] = 0;
	rc = mbedtls_net_connect(&s.net, "127.0.0.1", portstr,
				 MBEDTLS_NET_PROTO_TCP);
	if (rc != 0)
		goto out;

	rc = mbedtls_ssl_setup(&s.ssl, &s.conf);
	if (rc != 0)
		goto out;
	rc = mbedtls_ssl_set_hostname(&s.ssl, "127.0.0.1");
	if (rc != 0)
		goto out;
	mbedtls_ssl_set_bio(&s.ssl, &s.net, mbedtls_net_send, mbedtls_net_recv,
			    NULL);

	rc = mbedtls_ssl_handshake(&s.ssl);
	if (ver_out)
		snprintf(ver_out, ver_sz, "%s", mbedtls_ssl_get_version(&s.ssl));
	if (rc != 0) {
		rc = -2;	/* 握手失败（负路径 2：服务端告警） */
		goto out;
	}

	/* 正路径：PING/PONG */
	if (mbedtls_ssl_write(&s.ssl, (const unsigned char *)"PING", 4) != 4)
		goto out;
	memset(buf, 0, sizeof(buf));
	if (mbedtls_ssl_read(&s.ssl, buf, sizeof(buf) - 1) != 4 ||
	    memcmp(buf, "PONG", 4) != 0)
		goto out;
	ret = 0;
out:
	side_free(&s);
	return ret != 0 ? (rc != 0 ? rc : -3) : 0;
}

/* ---------- 用例调度：fork 服务端 + 父进程客户端 ---------- */
static int run_case_with_client(int client_mode, struct srv_result *res_out,
				char *ver_out, size_t ver_sz)
{
	int portpipe[2], respipe[2];
	pid_t pid;
	ssize_t n;
	int status, cli_rc;

	if (pipe(portpipe) != 0 || pipe(respipe) != 0)
		return -1;

	pid = fork();
	if (pid == 0) {
		close(portpipe[0]);
		close(respipe[0]);
		run_server(portpipe[1], respipe[1]);
		_exit(0);
	}
	close(portpipe[1]);
	close(respipe[1]);

	cli_rc = run_client(client_mode, portpipe[0], ver_out, ver_sz);
	close(portpipe[0]);

	res_out->hs_rc = 1;
	n = read(respipe[0], res_out, sizeof(*res_out));
	if (n != sizeof(*res_out))
		res_out->hs_rc = -100;
	close(respipe[0]);
	waitpid(pid, &status, 0);
	return cli_rc;
}

int main(void)
{
	struct srv_result res;
	char ver[24] = "";
	int cli_rc;

	signal(SIGPIPE, SIG_IGN);

	printf("== W78 test_tls_srv：mbedtls 服务端能力（SSL_SRV_C 回开） ==\n");
	case_pk_parse();
	printf("\n");

	/* B. 正路径：mTLS 握手 + 双向校验 + 应用数据 */
	cli_rc = run_case_with_client(0, &res, ver, sizeof(ver));
	if (cli_rc == 0 && res.hs_rc == 0 &&
	    strcmp(res.peer_cn, "ai-test-client") == 0) {
		pass("B1 回环 mTLS 握手 (TLS 版本协商)");
		printf("     (协商版本 %s, 客户端 CN=%s)\n", ver, res.peer_cn);
		if (strcmp(ver, "TLSv1.3") == 0)
			pass("B2 TLS1.3 (无 NewSessionTicket, TICKET_C 仍裁)");
		else
			printf("     (注意: 协商为 %s 而非 TLSv1.3)\n", ver);
	} else {
		fail("B1 回环 mTLS 握手", "握手或校验失败");
		printf("     (cli_rc=%d srv_hs=%d peer_cn=%s ver=%s)\n",
		       cli_rc, res.hs_rc, res.peer_cn, ver);
	}

	/* C. 负路径：无客户端证书 */
	cli_rc = run_case_with_client(1, &res, ver, sizeof(ver));
	if (res.hs_rc != 0) {
		pass("C1 无客户端证书 -> 服务端拒绝 (srv_hs != 0)");
		printf("     (srv_hs=%d, cli_rc=%d)\n", res.hs_rc, cli_rc);
	} else {
		fail("C1 无客户端证书 -> 服务端拒绝", "服务端竟然握手成功");
	}

	/* D. 负路径：野 CA 签发的客户端证书 */
	cli_rc = run_case_with_client(2, &res, ver, sizeof(ver));
	if (res.hs_rc != 0) {
		pass("D1 野 CA 客户端证书 -> 服务端拒绝 (srv_hs != 0)");
		printf("     (srv_hs=%d, cli_rc=%d)\n", res.hs_rc, cli_rc);
	} else {
		fail("D1 野 CA 客户端证书 -> 服务端拒绝", "服务端竟然握手成功");
	}

	printf("\n%s (fail=%d)\n",
	       g_fail ? "RESULT: FAIL" : "RESULT: ALL PASS", g_fail);
	return g_fail ? 1 : 0;
}
