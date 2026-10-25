#!/bin/sh
# tls_certs_regen.sh —— W78 agent-D：test_tls_srv.c 内嵌证书过期后再生
# 用法: 在 agent/ai/tests/ 下执行  sh tls_certs_regen.sh
# 产物: 重新生成 tls_test_certs.h（30 天有效期的一次性测试证书）
# 注意: 同步把新证书归档到 ~/aikernel-longterm/evidence/w78/agent-d/certs/
#       （私钥 600），保持证据与源码一致。
set -e
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n' > san.ext
printf 'extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n' > cli.ext

openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 30 -subj "/CN=AIKernel Test CA" -out ca.crt 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -key server.key -subj "/CN=ai-test-server" -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -sha256 -extfile san.ext -out server.crt 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out client.key
openssl req -new -key client.key -subj "/CN=ai-test-client" -out client.csr 2>/dev/null
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -sha256 -extfile cli.ext -out client.crt 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out rogue-ca.key
openssl req -x509 -new -key rogue-ca.key -sha256 -days 30 -subj "/CN=Rogue CA" -out rogue-ca.crt 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out rogue-client.key
openssl req -new -key rogue-client.key -subj "/CN=rogue-client" -out rogue-client.csr 2>/dev/null
openssl x509 -req -in rogue-client.csr -CA rogue-ca.crt -CAkey rogue-ca.key -CAcreateserial -days 30 -sha256 -extfile cli.ext -out rogue-client.crt 2>/dev/null
openssl genrsa -out rsa2048.key 2048 2>/dev/null
openssl genrsa -aes-256-cbc -passout pass:test123 -out rsa2048-enc.key 2048 2>/dev/null

emit() {
	printf 'static const char %s[] =\n' "$1"
	awk '{ printf "\t\"%s\\n\"\n", $0 }' "$2"
	printf '\t;\n\n'
}

{
	echo '/* W78 agent-D：一次性测试证书（内嵌供 test_tls_srv.c 自包含运行）'
	echo ' * 由 tls_certs_regen.sh 生成（30 天有效期）。仅回环测试用。 */'
	echo '#ifndef AIK_TLS_TEST_CERTS_H'
	echo '#define AIK_TLS_TEST_CERTS_H'
	emit TEST_CA_CRT ca.crt
	emit TEST_SERVER_CRT server.crt
	emit TEST_SERVER_KEY server.key
	emit TEST_CLIENT_CRT client.crt
	emit TEST_CLIENT_KEY client.key
	emit TEST_ROGUE_CA_CRT rogue-ca.crt
	emit TEST_ROGUE_CLIENT_CRT rogue-client.crt
	emit TEST_ROGUE_CLIENT_KEY rogue-client.key
	emit TEST_RSA2048_KEY rsa2048.key
	emit TEST_RSA2048_ENC_KEY rsa2048-enc.key
	echo '#endif /* AIK_TLS_TEST_CERTS_H */'
} > "$here/tls_test_certs.h"

echo "OK -> $here/tls_test_certs.h （请同步归档到证据目录并重跑 test_tls_srv）"
