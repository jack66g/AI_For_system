/*
 * tls_manager.c - TLS Manager 实现
 *
 * 基于 mbedTLS 的 TLS 会话管理。
 * 封装 mbedTLS 初始化和会话生命周期。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tls_manager.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

/* ---- mbedTLS 全局上下文 ---- */

static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;
static int g_initialized = 0;

int tls_manager_init(void)
{
    int ret;

    if (g_initialized)
        return 0;

    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func,
                                &g_entropy,
                                (const unsigned char *)"AIKernel-TLS-Manager",
                                22);
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&g_ctr_drbg);
        mbedtls_entropy_free(&g_entropy);
        return ret;
    }

    g_initialized = 1;
    return 0;
}

int tls_manager_create_session(struct mbedtls_ssl_context **ssl_out,
                               struct mbedtls_ssl_config **conf_out,
                               const char *hostname, int fd)
{
    mbedtls_ssl_context *ssl;
    mbedtls_ssl_config *conf;
    int ret;

    if (!g_initialized)
        return -1;

    ssl = calloc(1, sizeof(*ssl));
    conf = calloc(1, sizeof(*conf));
    if (!ssl || !conf) {
        free(ssl);
        free(conf);
        return -1;
    }

    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(conf);

    ret = mbedtls_ssl_config_defaults(conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
        goto fail;

    /* 默认 VERIFY_OPTIONAL，如果证书管理器可用则用 VERIFY_REQUIRED */
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, &g_ctr_drbg);

    ret = mbedtls_ssl_setup(ssl, conf);
    if (ret != 0)
        goto fail;

    if (hostname)
        mbedtls_ssl_set_hostname(ssl, hostname);

    mbedtls_ssl_set_bio(ssl, &fd, mbedtls_net_send,
                        mbedtls_net_recv, NULL);

    *ssl_out = ssl;
    *conf_out = conf;
    return 0;

fail:
    mbedtls_ssl_free(ssl);
    mbedtls_ssl_config_free(conf);
    free(ssl);
    free(conf);
    return ret;
}

int tls_manager_handshake(struct mbedtls_ssl_context *ssl)
{
    int ret;

    if (!ssl)
        return -1;

    while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            return ret;
    }

    return 0;
}

int tls_manager_write(struct mbedtls_ssl_context *ssl,
                      const unsigned char *buf, size_t len)
{
    int ret;

    if (!ssl || !buf)
        return -1;

    while ((ret = mbedtls_ssl_write(ssl, buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_WRITE &&
            ret != MBEDTLS_ERR_SSL_WANT_READ)
            return ret;
    }

    return ret;
}

int tls_manager_read(struct mbedtls_ssl_context *ssl,
                     unsigned char *buf, size_t len)
{
    int ret;

    if (!ssl || !buf)
        return -1;

    ret = mbedtls_ssl_read(ssl, buf, len);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
        ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        return 0;

    return ret;
}

void tls_manager_close_session(struct mbedtls_ssl_context *ssl,
                               struct mbedtls_ssl_config *conf)
{
    if (ssl) {
        mbedtls_ssl_free(ssl);
        free(ssl);
    }
    if (conf) {
        mbedtls_ssl_config_free(conf);
        free(conf);
    }
}

void tls_manager_cleanup(void)
{
    if (!g_initialized)
        return;

    mbedtls_ctr_drbg_free(&g_ctr_drbg);
    mbedtls_entropy_free(&g_entropy);
    g_initialized = 0;
}
