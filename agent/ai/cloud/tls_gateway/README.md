# cloud/tls_gateway/ —— mTLS 入站网关源码（W78 agent-D）

`aik_tls_gateway.py`：mTLS TLS 终结 + HTTP 反向转发（→ aikernel-api
127.0.0.1:8761，Bearer 透传）。部署副本在工厂 rootfs
`/usr/local/sbin/aik-tls-gateway`（systemd unit `aik-tls-gateway.service`，
默认 disabled，运维文档
`w7i-rootfs/usr/local/share/doc/aik-tls-gateway/README.md`）。

实现语言决策（W78）：python3 标准库 ssl，而非 C + mbedtls ——

1. rootfs 出厂即有 python3.10，aikernel-api/aikernel-memory/sme-seed 全是
   python3 systemd 服务，运维栈一致、无二进制同步成本；
2. 网关是 TLS 终结 + HTTP 转发胶水，标准库 ssl/http.client 原生支持
   mTLS（CERT_REQUIRED）与流式转发（SSE/chunked 自动透传）；
   C 实现同等健壮性工期数倍且引入自有 HTTP 解析风险；
3. mbedtls 服务端能力（SSL_SRV_C 回开）由 tests/test_tls_srv.c 在树内
   真握手回归，与网关实现解耦——库能力不依赖本服务选型；
4. 独立进程、不注册为 AI 工具（本轮只做服务），契合微内核
   “系统只是辅助 AI”原则。

配置环境变量：`AIK_TLS_GATEWAY_LISTEN` / `AIK_TLS_GATEWAY_BACKEND` /
`AIK_TLS_DIR`（见脚本 docstring）。缺证书启动即退出，不自动生成。

测试：`python3 tests/test_tls_gateway.py`（已注册进 tests/run_all.sh；
运行时 openssl 生成一次性证书于临时目录，不落库）。
