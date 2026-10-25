/* W78 agent-D 任务1：核私钥解析存留（W78A 存疑项③）
 *
 * 背景：B3 批砍了 X.509 写侧与 PKCS5/PKCS12（加密私钥容器），但
 * MBEDTLS_PK_PARSE_C / MBEDTLS_PEM_PARSE_C 未在 trim.h 中 #undef。
 * 本程序链接当前 libmbedcrypto.a（trim 配置），验证：
 *   1. 明文 EC 私钥（SEC1 "EC PRIVATE KEY"）可解析
 *   2. 明文 RSA 私钥（PKCS#1 "RSA PRIVATE KEY"）可解析
 *   3. 加密 RSA 私钥（"ENCRYPTED PRIVATE KEY", PBES2）解析失败
 *      ——PKCS5/PKCS12 已裁，属预期行为（服务端须用明文私钥 + 文件权限 600）
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/build_info.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"

#define STR(x) #x

#define REPORT_ON(name)  printf("  %-42s ON\n", name)
#define REPORT_OFF(name) printf("  %-42s OFF (undefined)\n", name)

static int g_fail;

static void check(const char *path, const char *pwd, int expect_ok,
		  const char *expect_name)
{
	FILE *f = fopen(path, "rb");
	mbedtls_pk_context pk;
	unsigned char *buf;
	long n;
	char err[128];
	int rc;

	if (!f) {
		printf("FAIL open %s: %s\n", path, strerror(errno));
		g_fail++;
		return;
	}
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc((size_t)n + 1);
	if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) {
		printf("FAIL read %s\n", path);
		fclose(f);
		free(buf);
		g_fail++;
		return;
	}
	fclose(f);
	buf[n] = 0;

	mbedtls_pk_init(&pk);
	rc = mbedtls_pk_parse_key(&pk, buf, (size_t)n + 1,
				  (const unsigned char *)pwd,
				  pwd ? strlen(pwd) : 0, NULL, NULL);
	if (rc == 0) {
		const char *name = mbedtls_pk_get_name(&pk);
		if (!expect_ok) {
			printf("FAIL %s: parsed OK but expected REJECT\n", path);
			g_fail++;
		} else if (expect_name && strcmp(name, expect_name) != 0) {
			printf("FAIL %s: type %s != expected %s\n", path,
			       name, expect_name);
			g_fail++;
		} else {
			printf("PASS %s: parsed, type=%s\n", path, name);
		}
	} else {
		mbedtls_strerror(rc, err, sizeof(err));
		if (expect_ok) {
			printf("FAIL %s: parse rc=-0x%04x (%s)\n", path,
			       (unsigned)-rc, err);
			g_fail++;
		} else {
			printf("PASS %s: rejected as expected rc=-0x%04x (%s)\n",
			       path, (unsigned)-rc, err);
		}
	}
	mbedtls_pk_free(&pk);
	free(buf);
}

int main(int argc, char **argv)
{
	const char *dir = argc > 1 ? argv[1] : ".";
	char path[512];

	printf("== W78 私钥解析存留核验（当前 trim 配置） ==\n");
	printf("有效配置宏（-DMBEDTLS_CONFIG_FILE=config/mbedtls-trim.h）：\n");
#ifdef MBEDTLS_PK_PARSE_C
	REPORT_ON("MBEDTLS_PK_PARSE_C");
#else
	REPORT_OFF("MBEDTLS_PK_PARSE_C");
#endif
#ifdef MBEDTLS_PEM_PARSE_C
	REPORT_ON("MBEDTLS_PEM_PARSE_C");
#else
	REPORT_OFF("MBEDTLS_PEM_PARSE_C");
#endif
#ifdef MBEDTLS_RSA_C
	REPORT_ON("MBEDTLS_RSA_C");
#else
	REPORT_OFF("MBEDTLS_RSA_C");
#endif
#ifdef MBEDTLS_ECP_C
	REPORT_ON("MBEDTLS_ECP_C");
#else
	REPORT_OFF("MBEDTLS_ECP_C");
#endif
#ifdef MBEDTLS_PKCS5_C
	REPORT_ON("MBEDTLS_PKCS5_C");
#else
	REPORT_OFF("MBEDTLS_PKCS5_C");
#endif
#ifdef MBEDTLS_PKCS12_C
	REPORT_ON("MBEDTLS_PKCS12_C");
#else
	REPORT_OFF("MBEDTLS_PKCS12_C");
#endif
#ifdef MBEDTLS_PK_WRITE_C
	REPORT_ON("MBEDTLS_PK_WRITE_C");
#else
	REPORT_OFF("MBEDTLS_PK_WRITE_C");
#endif
	printf("\n");

	snprintf(path, sizeof(path), "%s/server.key", dir);
	check(path, NULL, 1, "EC");
	snprintf(path, sizeof(path), "%s/client.key", dir);
	check(path, NULL, 1, "EC");
	snprintf(path, sizeof(path), "%s/rsa2048.key", dir);
	check(path, NULL, 1, "RSA");
	snprintf(path, sizeof(path), "%s/rsa2048-enc.key", dir);
	check(path, "test123", 0, NULL);
	check(path, NULL, 0, NULL);

	printf("\n%s（g_fail=%d）\n", g_fail ? "RESULT: FAIL" : "RESULT: ALL PASS",
	       g_fail);
	return g_fail ? 1 : 0;
}
