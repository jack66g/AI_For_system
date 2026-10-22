/* AIKernel mbedTLS 裁剪配置头（进阶档）
 * 注入机制：agent 源码、mbedtls library/3rdparty、tests 云通道测试统一用
 * -DMBEDTLS_CONFIG_FILE=\"config/mbedtls-trim.h\"（配 -I 指向 agent/ai），
 * 保证所有编译单元看到同一份配置，结构体 ABI 一致。
 * 方法：先原样引入默认配置，再逐批 #undef；每批过 TLS 四件套+六套 tests，
 * 红了回退该批。禁止一次性全关。
 */
#ifndef AIKERNEL_MBEDTLS_TRIM_H
#define AIKERNEL_MBEDTLS_TRIM_H

#include "mbedtls/mbedtls_config.h"

/* ==== 裁剪批次 ==== */
/* B1 保守批次：legacy 密码/哈希 + 旧 DHE 密钥交换 + LMS + NIST KW + CMAC + ECJPAKE
 * 依据: agent 仅做客户端 TLS1.2/1.3, 套件为 ECDHE_ECDSA/RSA + AES-GCM/CHACHAPOLY,
 *       证书链验证只需 SHA-256/384; 以下宏在默认配置为开且无任何引用方。 */
#undef MBEDTLS_DES_C
#undef MBEDTLS_CAMELLIA_C
#undef MBEDTLS_ARIA_C
#undef MBEDTLS_RIPEMD160_C
#undef MBEDTLS_NIST_KW_C
#undef MBEDTLS_CMAC_C
#undef MBEDTLS_ECJPAKE_C
#undef MBEDTLS_DHM_C
#undef MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
#undef MBEDTLS_LMS_C
/* B2 TLS 特性面批次：DTLS 全家(纯 TCP 客户端)、会话恢复/服务端件、PSK 全家。
 * 依据: http_client 仅 net_sockets+ssl_cli+entropy+ctr_drbg+x509_crt,
 *       无 alpn/dtls/ticket/cache/get_peer_cert/export_keys 引用(已 grep 证实);
 *       每次请求新建连接, 不依赖会话恢复; SNI/EMS/ETM/TLS1.3 兼容模式必保留。 */
#undef MBEDTLS_SSL_PROTO_DTLS
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID
#undef MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT
#undef MBEDTLS_SSL_DTLS_ANTI_REPLAY
#undef MBEDTLS_SSL_DTLS_HELLO_VERIFY
#undef MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE
#undef MBEDTLS_SSL_COOKIE_C
#undef MBEDTLS_SSL_RENEGOTIATION
#undef MBEDTLS_SSL_SESSION_TICKETS
#undef MBEDTLS_SSL_TICKET_C
#undef MBEDTLS_SSL_CACHE_C
#undef MBEDTLS_SSL_ALPN
#undef MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
#undef MBEDTLS_SSL_CONTEXT_SERIALIZATION
#undef MBEDTLS_SSL_SRV_C
#undef MBEDTLS_SSL_ALL_ALERT_MESSAGES
/* MBEDTLS_SSL_KEEP_PEER_CERTIFICATE 不可关: TLS1.3 硬依赖(check_config.h:833), B2 首跑实证 */
#undef MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED
#undef MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED
/* B3 X.509 写侧/密钥容器批次: agent 仅做证书链解析+验证(x509_crt_parse_file),
 * 不解析私钥/不签发/不查 CRL; PKCS5/12 仅为加密私钥解析服务。 */
#undef MBEDTLS_PKCS12_C
#undef MBEDTLS_PKCS5_C
#undef MBEDTLS_PK_WRITE_C
#undef MBEDTLS_X509_CREATE_C
#undef MBEDTLS_X509_CSR_PARSE_C
#undef MBEDTLS_X509_CRL_PARSE_C
#undef MBEDTLS_X509_WRITE_C
#undef MBEDTLS_X509_CRT_WRITE_C
#undef MBEDTLS_X509_CSR_WRITE_C
#undef MBEDTLS_PKCS7_C
/* B4 ECP 曲线批次: TLS1.2/1.3 实际组为 x25519 + NIST P-256/384/521,
 * github/deepseek 证书链公钥均在 NIST 曲线; 192/224/K1/BP 全裁。 */
#undef MBEDTLS_ECP_DP_SECP192R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP224R1_ENABLED
#undef MBEDTLS_ECP_DP_SECP192K1_ENABLED
#undef MBEDTLS_ECP_DP_SECP224K1_ENABLED
#undef MBEDTLS_ECP_DP_SECP256K1_ENABLED
#undef MBEDTLS_ECP_DP_BP256R1_ENABLED
#undef MBEDTLS_ECP_DP_BP384R1_ENABLED
#undef MBEDTLS_ECP_DP_BP512R1_ENABLED
/* B5 静态密钥交换+MD5 批次: agent 只出 ECDHE(前向保密)客户端套件;
 * 静态 RSA/ECDH_kx 无 PFS 且 deepseek/github 不选; MD5 仅旧 PRF/md5 签名链用。 */
#undef MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED
#undef MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
#undef MBEDTLS_MD5_C
/* B6 收尾试验批: PEM 写侧(agent 只读 PEM)、timing(仅 DTLS 用, 已裁 DTLS)、
 * SHA3(经典 TLS 不用)、SHA1(现代链为 SHA-256/384 签名)。红即回退。 */
#undef MBEDTLS_PEM_WRITE_C
#undef MBEDTLS_TIMING_C
#undef MBEDTLS_SHA3_C
#undef MBEDTLS_SHA1_C
/* B7 分组模式批次: agent 套件只有 AES-GCM/CHACHAPOLY; CCM(TLS1.3 CCM 套件)与
 * CBC/CFB/OFB/XTS 旧模式全裁; CTR 保留(GCM 内部依赖 + CTR_DRBG)。 */
#undef MBEDTLS_CCM_C
#undef MBEDTLS_CIPHER_MODE_CBC
#undef MBEDTLS_CIPHER_MODE_CFB
#undef MBEDTLS_CIPHER_MODE_OFB
#undef MBEDTLS_CIPHER_MODE_XTS

#endif /* AIKERNEL_MBEDTLS_TRIM_H */
