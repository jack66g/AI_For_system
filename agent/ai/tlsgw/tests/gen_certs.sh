#!/bin/sh
# gen_certs.sh - T7c 一次性测试证书(沙箱;私钥绝不入仓库)
# 与参考单测 tests/test_tls_gateway.py 的证书形状一致:
#   ca/server/client + rogue(野 CA)/rogue-client;EC prime256v1;30 天
# 用法: gen_certs.sh <目标目录>
set -e
DIR="${1:?usage: gen_certs.sh <dir>}"
mkdir -p "$DIR"
cd "$DIR"

[ -f ca.crt ] && exit 0  # 幂等

cat > san.ext <<'EOF'
subjectAltName=IP:127.0.0.1,DNS:localhost
extendedKeyUsage=serverAuth
keyUsage=digitalSignature
EOF
cat > cli.ext <<'EOF'
extendedKeyUsage=clientAuth
keyUsage=digitalSignature
EOF

eckey() { openssl ecparam -name prime256v1 -genkey -noout -out "$1"; }
sign() { # csr crt ca cakey ext
	openssl x509 -req -in "$1" -CA "$3" -CAkey "$4" -CAcreateserial \
		-days 30 -sha256 -extfile "$5" -out "$2" 2>/dev/null
}

eckey ca.key
openssl req -x509 -new -key ca.key -sha256 -days 30 \
	-subj "/CN=AIKernel GW Test CA" -out ca.crt 2>/dev/null

eckey server.key
openssl req -new -key server.key -subj "/CN=aik-tls-gw-test" -out s.csr 2>/dev/null
sign s.csr server.crt ca.crt ca.key san.ext

eckey client.key
openssl req -new -key client.key -subj "/CN=gw-test-client" -out c.csr 2>/dev/null
sign c.csr client.crt ca.crt ca.key cli.ext

eckey rogue-ca.key
openssl req -x509 -new -key rogue-ca.key -sha256 -days 30 \
	-subj "/CN=Rogue CA" -out rogue-ca.crt 2>/dev/null
eckey rogue-client.key
openssl req -new -key rogue-client.key -subj "/CN=rogue-client" -out r.csr 2>/dev/null
sign r.csr rogue-client.crt rogue-ca.crt rogue-ca.key cli.ext

for k in *.key; do chmod 600 "$k"; done
echo "certs ready: $DIR"
