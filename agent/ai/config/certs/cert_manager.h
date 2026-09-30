/*
 * cert_manager.h - Certificate Manager 接口
 *
 * 负责 CA 证书的加载、验证、切换和更新（接口预留）。
 * 默认使用 Mozilla CA Bundle (来自 curl 官方维护的公开 CA 集合)。
 *
 * 证书来源：Mozilla CA Certificate Store
 * 下载地址：https://curl.se/docs/caextract.html
 * 实际文件：https://curl.se/ca/cacert.pem
 *
 * 版本：截至 2026 年 8 月的公开版本
 * 更新方式：定期从上述地址重新下载（接口预留）
 */

#ifndef _AI_CERT_MANAGER_H
#define _AI_CERT_MANAGER_H

/* 前向声明 */
struct mbedtls_x509_crt;

/*
 * cert_manager_init - 初始化证书管理器
 * 加载默认 CA Bundle。
 * 返回: 0 成功，负值失败
 */
int cert_manager_init(void);

/*
 * cert_manager_get_ca_chain - 获取 CA 证书链
 * 返回: mbedTLS X.509 证书链指针（内部数据，不可释放）
 *       未初始化返回 NULL
 */
struct mbedtls_x509_crt *cert_manager_get_ca_chain(void);

/*
 * cert_manager_verify - 验证服务器证书
 * @server_cert: 服务器证书
 * 返回: 0 验证通过，非零失败
 */
int cert_manager_verify(struct mbedtls_x509_crt *server_cert);

/*
 * cert_manager_reload - 重新加载证书（接口预留）
 * 返回: 0 成功，负值失败
 */
int cert_manager_reload(const char *bundle_path);

/*
 * cert_manager_cleanup - 清理证书管理器
 */
void cert_manager_cleanup(void);

#endif /* _AI_CERT_MANAGER_H */
