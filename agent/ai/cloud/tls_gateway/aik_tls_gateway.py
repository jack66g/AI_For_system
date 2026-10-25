#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""aik-tls-gateway —— AIKernel mTLS 入站网关（W78 agent-D）

监听 TLS（默认 127.0.0.1:8443），强制校验客户端证书（mTLS），
TLS 终结后将 HTTP 明文转发给后端 API（默认 127.0.0.1:8761
aikernel-api），Authorization（Bearer）原样透传，并注入
X-Client-Cert-CN / X-Forwarded-* 头供后端审计。

实现语言决策（W78）：python3 标准库 ssl 而非 C+mbedtls ——
  1. 出厂 rootfs 已有 python3.10，aikernel-api / aikernel-memory /
     sme-seed 均为 python3 systemd 服务，运维栈一致，无二进制同步负担；
  2. 网关本质是 TLS 终结 + HTTP 反向转发胶水，标准库 ssl/http.client
     原生支持 mTLS 与流式转发（SSE/chunked）；C 实现同等健壮性工期数倍；
  3. mbedtls 服务端能力（SSL_SRV_C 回开）由 agent 树内 C 测试
     tests/test_tls_srv.c 真握手回归覆盖，与本服务实现解耦；
  4. 独立进程 + 不注册为 AI 工具，契合微内核"系统只是辅助 AI"原则。

证书约定（目录 $AIK_TLS_DIR，默认 /etc/aikernel/tls/）：
    server.crt / server.key —— 网关 TLS 服务端证书与私钥（明文，600）
    ca.crt                —— 签发客户端证书的 CA（客户端证书白名单根）
启动时缺任一文件立即报错退出——不自动生成，工厂镜像不携带任何私钥。

配置（环境变量，systemd Environment= / EnvironmentFile 均可）：
    AIK_TLS_GATEWAY_LISTEN=127.0.0.1:8443   # 端口 0 = 随机（测试用）
    AIK_TLS_GATEWAY_BACKEND=127.0.0.1:8761
    AIK_TLS_DIR=/etc/aikernel/tls
"""
import http.client
import json
import os
import signal
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "aik-tls-gateway 1.0 (W78)"

LISTEN = os.environ.get("AIK_TLS_GATEWAY_LISTEN", "127.0.0.1:8443")
BACKEND = os.environ.get("AIK_TLS_GATEWAY_BACKEND", "127.0.0.1:8761")
TLS_DIR = os.environ.get("AIK_TLS_DIR", "/etc/aikernel/tls")

SERVER_CRT = os.path.join(TLS_DIR, "server.crt")
SERVER_KEY = os.path.join(TLS_DIR, "server.key")
CA_CRT = os.path.join(TLS_DIR, "ca.crt")

BACKEND_TIMEOUT = 60  # 秒，后端连接/读超时
MAX_BODY = 64 * 1024 * 1024  # 客户端请求体上限，防滥用

# RFC 7230 逐跳头，转发时两侧都要剥掉
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "trailers", "transfer-encoding",
    "upgrade",
}


def die(msg):
    sys.stderr.write("aik-tls-gateway: %s\n" % msg)
    sys.exit(1)


def build_ssl_context():
    for path in (SERVER_CRT, SERVER_KEY, CA_CRT):
        if not os.path.isfile(path):
            die("缺少证书文件 %s（不自动生成；生成方法见 "
                "/usr/local/share/doc/aik-tls-gateway/README.md）" % path)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(SERVER_CRT, SERVER_KEY)
        ctx.load_verify_locations(CA_CRT)
        ctx.verify_mode = ssl.CERT_REQUIRED  # mTLS：无客户端证书即拒绝
        return ctx
    except ssl.SSLError as exc:
        die("证书加载失败: %s" % exc)
    except OSError as exc:
        die("证书读取失败: %s" % exc)


class GatewayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "aik-tls-gw/1.0"

    # ---- 工具 ----
    def log_message(self, fmt, *args):
        peer = self.connection.getpeercert() or {}
        cn = ""
        for rdn in peer.get("subject", ()):
            for key, val in rdn:
                if key == "commonName":
                    cn = val
        sys.stderr.write("[aik-tls-gateway] %s cn=%s %s\n"
                         % (self.address_string(), cn, fmt % args))

    def client_cn(self):
        try:
            peer = self.connection.getpeercert() or {}
            for rdn in peer.get("subject", ()):
                for key, val in rdn:
                    if key == "commonName":
                        return val
        except (AttributeError, ValueError):
            pass
        return "unknown"

    def send_json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---- 请求体 ----
    def read_body(self):
        """支持 Content-Length 与 chunked 两种请求体。"""
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            chunks = []
            total = 0
            while True:
                line = self.rfile.readline(64)
                size = int(line.split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()  # 尾部 CRLF
                    break
                total += size
                if total > MAX_BODY:
                    raise OverflowError("请求体超限")
                chunks.append(self.rfile.read(size))
                self.rfile.readline()  # 块尾 CRLF
            return b"".join(chunks)
        length = int(self.headers.get("Content-Length") or 0)
        if length < 0 or length > MAX_BODY:
            raise OverflowError("请求体超限")
        return self.rfile.read(length) if length else b""

    # ---- 主流程 ----
    def proxy(self):
        if self.path == "/healthz":  # 网关自身健康检查，不触后端
            self.send_json(200, {"status": "ok", "gateway": VERSION})
            return

        host, port = BACKEND.rsplit(":", 1)
        body = None
        try:
            body = self.read_body()
        except (ValueError, OverflowError) as exc:
            self.send_json(400, {"error": "bad_request", "detail": str(exc)})
            return

        headers = {}
        for name, value in self.headers.items():
            if name.lower() in HOP_BY_HOP or name.lower() == "host":
                continue
            headers[name] = value  # Authorization（Bearer）在此透传
        headers["Host"] = BACKEND
        headers["X-Forwarded-For"] = self.client_address[0]
        headers["X-Forwarded-Proto"] = "tls"
        headers["X-Client-Cert-CN"] = self.client_cn()

        try:
            conn = http.client.HTTPConnection(host, int(port),
                                              timeout=BACKEND_TIMEOUT)
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            self.send_json(502, {"error": "bad_gateway",
                                 "detail": "%s: %s" % (BACKEND, exc)})
            return

        try:
            self.relay_response(resp)
        finally:
            conn.close()

    def relay_response(self, resp):
        self.send_response_only(resp.status, resp.reason)
        out_cl = None
        for name, value in resp.getheaders():
            low = name.lower()
            if low in HOP_BY_HOP:
                continue
            if low == "content-length":
                out_cl = int(value)
            self.send_header(name, value)
        if out_cl is not None:
            self.end_headers()
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
        else:
            # 无 Content-Length（SSE/流式）：1.1 chunked 分块转发
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
            self.wfile.write(b"0\r\n\r\n")

    def handle_one_request(self):
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        except ssl.SSLError:
            self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = proxy
    do_OPTIONS = proxy


class GatewayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    ctx = build_ssl_context()

    try:
        host, port = LISTEN.rsplit(":", 1)
        port = int(port)
    except ValueError:
        die("AIK_TLS_GATEWAY_LISTEN 格式应为 host:port，当前 %r" % LISTEN)

    GatewayServer.address_family = socket.AF_INET
    try:
        httpd = GatewayServer((host, port), GatewayHandler)
    except OSError as exc:
        die("监听 %s 失败: %s" % (LISTEN, exc))
    try:
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    except ssl.SSLError as exc:
        die("TLS 初始化失败: %s" % exc)

    print("LISTENING %s:%d -> %s (%s)"
          % (httpd.server_address[0], httpd.server_address[1], BACKEND,
             VERSION), flush=True)

    def _shutdown(signum, frame):
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    httpd.serve_forever(poll_interval=0.5)
    print("EXIT", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
