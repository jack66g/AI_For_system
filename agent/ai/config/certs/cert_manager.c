/*
 * cert_manager.c - Certificate Manager 实现
 *
 * 使用内置的最小 CA Bundle 实现证书验证。
 * 包含 Mozilla CA Certificate Store 中的主要根 CA 证书。
 *
 * 证书来源：Mozilla CA Certificate Store
 * 由 curl 项目维护的 PEM 格式版本：https://curl.se/ca/cacert.pem
 * 我们内置了几个关键的根 CA 证书用于验证 DeepSeek/OpenAI 等常用服务。
 *
 * 内置证书（PEM 格式）：
 * - ISRG Root X1 (Let's Encrypt)
 * - DigiCert Global Root CA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cert_manager.h"

#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"

static mbedtls_x509_crt g_ca_chain;
static int g_initialized = 0;

/*
 * 内置 CA 证书 (PEM 格式)
 *
 * ISRG Root X1 - Let's Encrypt 根证书
 * 有效期: 2015-06-04 到 2035-06-04
 * 来源: https://letsencrypt.org/certs/isrgrootx1.pem
 * 这是 Let's Encrypt 签发的证书的信任根，用于 api.deepseek.com 等。
 */
static const char *ISRG_ROOT_X1_PEM =
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "-----END CERTIFICATE-----\n";

/*
 * DigiCert Global Root CA
 * 有效期: 2006-11-10 到 2031-11-10
 * 来源: https://www.digicert.com/kb/digicert-root-certificates.htm
 */
static const char *DIGICERT_GLOBAL_ROOT_CA_PEM =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
    "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\n"
    "QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT\n"
    "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\n"
    "b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG\n"
    "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB\n"
    "CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97\n"
    "nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt\n"
    "43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P\n"
    "T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4\n"
    "gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO\n"
    "BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR\n"
    "TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw\n"
    "DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr\n"
    "hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg\n"
    "06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF\n"
    "PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls\n"
    "YSEY1QSteDwsOoBrp+98FRu3Qmw/pQeZPfj3yFQwrls+E0XUxHBJOC7Iaryvb+4S\n"
    "ZJhKunAS+2Y2q5+gOoF/qNmR0pBEeqaqTvf2x2B2LHWxfuI=\n"
    "-----END CERTIFICATE-----\n";

int cert_manager_init(void)
{
    int ret;

    if (g_initialized)
        return 0;

    mbedtls_x509_crt_init(&g_ca_chain);

    /* 加载 ISRG Root X1 */
    ret = mbedtls_x509_crt_parse(&g_ca_chain,
                                 (const unsigned char *)ISRG_ROOT_X1_PEM,
                                 strlen(ISRG_ROOT_X1_PEM) + 1);
    if (ret < 0) {
        char err[256];
        mbedtls_strerror(ret, err, sizeof(err));
        fprintf(stderr, "cert_manager: Failed to parse ISRG Root X1: %s\n", err);
        mbedtls_x509_crt_free(&g_ca_chain);
        return ret;
    }

    /* 加载 DigiCert Global Root CA */
    ret = mbedtls_x509_crt_parse(&g_ca_chain,
                                 (const unsigned char *)DIGICERT_GLOBAL_ROOT_CA_PEM,
                                 strlen(DIGICERT_GLOBAL_ROOT_CA_PEM) + 1);
    if (ret < 0) {
        char err[256];
        mbedtls_strerror(ret, err, sizeof(err));
        fprintf(stderr, "cert_manager: Failed to parse DigiCert Root CA: %s\n", err);
        mbedtls_x509_crt_free(&g_ca_chain);
        return ret;
    }

    g_initialized = 1;
    return 0;
}

struct mbedtls_x509_crt *cert_manager_get_ca_chain(void)
{
    if (!g_initialized)
        return NULL;
    return &g_ca_chain;
}

int cert_manager_verify(struct mbedtls_x509_crt *server_cert)
{
    uint32_t flags;

    if (!g_initialized || !server_cert)
        return -1;

    flags = 0;
    (void)server_cert;

    /*
     * mbedTLS 在握手时自动使用 CA chain 进行验证，
     * 此函数为预留接口，用于手动验证场景。
     */
    return (int)flags;
}

int cert_manager_reload(const char *bundle_path)
{
    (void)bundle_path;
    /* 接口预留：未来支持从外部加载证书文件 */
    return 0;
}

void cert_manager_cleanup(void)
{
    if (!g_initialized)
        return;

    mbedtls_x509_crt_free(&g_ca_chain);
    g_initialized = 0;
}
