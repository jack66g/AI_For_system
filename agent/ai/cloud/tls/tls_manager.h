/*
 * tls_manager.h - TLS Manager 接口
 *
 * 负责 TLS 初始化、握手、证书验证、连接关闭。
 * 基于 mbedTLS，提供统一的 TLS 管理能力。
 */

#ifndef _AI_TLS_MANAGER_H
#define _AI_TLS_MANAGER_H

#include <stddef.h>

/* 前向声明 mbedTLS 类型 */
struct mbedtls_ssl_context;
struct mbedtls_ssl_config;

/*
 * tls_manager_init - 全局 TLS 初始化
 * 初始化 mbedTLS entropy、CTR_DRBG 等。
 * 程序启动时调用一次。
 * 返回: 0 成功，负值失败
 */
int tls_manager_init(void);

/*
 * tls_manager_create_session - 创建 TLS 会话
 * @ssl:       输出，SSL 上下文指针
 * @conf:      输出，SSL 配置指针
 * @hostname:  目标主机名（用于 SNI）
 * @fd:        TCP socket 文件描述符
 * 返回: 0 成功，负值失败
 *
 * 调用者负责在连接关闭后调用 tls_manager_close_session()。
 */
int tls_manager_create_session(struct mbedtls_ssl_context **ssl,
                               struct mbedtls_ssl_config **conf,
                               const char *hostname, int fd);

/*
 * tls_manager_handshake - 执行 TLS 握手
 * @ssl: TLS 会话
 * 返回: 0 成功，负值失败
 */
int tls_manager_handshake(struct mbedtls_ssl_context *ssl);

/*
 * tls_manager_write - TLS 发送数据
 * @ssl:  TLS 会话
 * @buf:  数据缓冲区
 * @len:  数据长度
 * 返回: 写入的字节数，负值失败
 */
int tls_manager_write(struct mbedtls_ssl_context *ssl,
                      const unsigned char *buf, size_t len);

/*
 * tls_manager_read - TLS 接收数据
 * @ssl:  TLS 会话
 * @buf:  数据缓冲区
 * @len:  缓冲区大小
 * 返回: 读取的字节数，负值失败或连接关闭
 */
int tls_manager_read(struct mbedtls_ssl_context *ssl,
                     unsigned char *buf, size_t len);

/*
 * tls_manager_close_session - 关闭 TLS 会话
 * @ssl:  TLS 会话（会被释放）
 * @conf: TLS 配置（会被释放）
 */
void tls_manager_close_session(struct mbedtls_ssl_context *ssl,
                               struct mbedtls_ssl_config *conf);

/*
 * tls_manager_cleanup - 全局 TLS 清理
 * 程序退出时调用一次。
 */
void tls_manager_cleanup(void);

#endif /* _AI_TLS_MANAGER_H */
