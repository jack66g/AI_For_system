#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_tls_gateway.py —— W78 agent-D：aik-tls-gateway 端到端单测

覆盖（任务铁律三条 + 加固）：
  T1 无证书目录启动 -> 立即报错退出（不自动生成，工厂镜像不带私钥）
  T2 有效证书启动后：无客户端证书的请求 -> TLS 层拒绝
  T3 有效客户端证书 -> 请求透传到假后端，Bearer/路径/体/注入头全对
  T4 野 CA 签发的客户端证书 -> 拒绝
  T5 POST 请求体透传
  T6 /healthz 网关本地健康检查

测试证书运行时用 openssl 一次性生成于临时目录（不落库）；
网关脚本取 agent/ai/cloud/tls_gateway/aik_tls_gateway.py。
"""
import http.client
import http.server
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GATEWAY = os.path.join(HERE, "..", "cloud", "tls_gateway",
                       "aik_tls_gateway.py")

FAILURES = []


def check(name, ok, detail=""):
    print("%s %s%s" % ("PASS" if ok else "FAIL", name,
                       ("  [%s]" % detail) if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


# ---------------------------------------------------------------- 证书
def gen_certs(tlsdir):
    def run(*args):
        r = subprocess.run(["openssl"] + list(args), capture_output=True,
                           text=True)
        if r.returncode != 0:
            raise RuntimeError("openssl %s: %s" % (args, r.stderr))
        return r

    with open(os.path.join(tlsdir, "san.ext"), "w") as f:
        f.write("subjectAltName=IP:127.0.0.1,DNS:localhost\n"
                "extendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n")
    with open(os.path.join(tlsdir, "cli.ext"), "w") as f:
        f.write("extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n")

    def eckey(path):
        run("ecparam", "-name", "prime256v1", "-genkey", "-noout",
            "-out", path)

    def sign(csr, crt, ca, cakey, ext):
        run("x509", "-req", "-in", os.path.join(tlsdir, csr),
            "-CA", os.path.join(tlsdir, ca), "-CAkey",
            os.path.join(tlsdir, cakey),
            "-CAcreateserial", "-days", "30", "-sha256",
            "-extfile", os.path.join(tlsdir, ext),
            "-out", os.path.join(tlsdir, crt))

    eckey(os.path.join(tlsdir, "ca.key"))
    run("req", "-x509", "-new", "-key", os.path.join(tlsdir, "ca.key"),
        "-sha256", "-days", "30", "-subj", "/CN=AIKernel GW Test CA",
        "-out", os.path.join(tlsdir, "ca.crt"))
    # server（网关自身）
    eckey(os.path.join(tlsdir, "server.key"))
    run("req", "-new", "-key", os.path.join(tlsdir, "server.key"),
        "-subj", "/CN=aik-tls-gw-test", "-out", os.path.join(tlsdir, "s.csr"))
    sign("s.csr", "server.crt", "ca.crt", "ca.key", "san.ext")
    # client（合法）
    eckey(os.path.join(tlsdir, "client.key"))
    run("req", "-new", "-key", os.path.join(tlsdir, "client.key"),
        "-subj", "/CN=gw-test-client", "-out", os.path.join(tlsdir, "c.csr"))
    sign("c.csr", "client.crt", "ca.crt", "ca.key", "cli.ext")
    # rogue CA + rogue client
    eckey(os.path.join(tlsdir, "rogue-ca.key"))
    run("req", "-x509", "-new", "-key", os.path.join(tlsdir, "rogue-ca.key"),
        "-sha256", "-days", "30", "-subj", "/CN=Rogue CA",
        "-out", os.path.join(tlsdir, "rogue-ca.crt"))
    eckey(os.path.join(tlsdir, "rogue-client.key"))
    run("req", "-new", "-key", os.path.join(tlsdir, "rogue-client.key"),
        "-subj", "/CN=rogue-client",
        "-out", os.path.join(tlsdir, "r.csr"))
    sign("r.csr", "rogue-client.crt", "rogue-ca.crt", "rogue-ca.key",
         "cli.ext")
    for key in os.listdir(tlsdir):
        if key.endswith(".key"):
            os.chmod(os.path.join(tlsdir, key), 0o600)


# ---------------------------------------------------------------- 假后端
class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _serve(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        payload = json.dumps({
            "backend": True,
            "method": self.command,
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "xcn": self.headers.get("X-Client-Cert-CN"),
            "xff": self.headers.get("X-Forwarded-For"),
            "body": body.decode("utf-8", "replace"),
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        pass

    do_GET = do_POST = _serve


def start_backend():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---------------------------------------------------------------- 网关
def start_gateway(tlsdir, backend_port):
    env = dict(os.environ)
    env.update({
        "AIK_TLS_GATEWAY_LISTEN": "127.0.0.1:0",
        "AIK_TLS_GATEWAY_BACKEND": "127.0.0.1:%d" % backend_port,
        "AIK_TLS_DIR": tlsdir,
    })
    proc = subprocess.Popen([sys.executable, GATEWAY], env=env,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    port = None

    def reader():
        nonlocal port
        line = proc.stdout.readline()
        if line.startswith("LISTENING"):
            try:
                port = int(line.split()[1].rsplit(":", 1)[1])
            except (IndexError, ValueError):
                port = None

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    t.join(20)
    return proc, port


def tls_client_ctx(tlsdir, with_cert):
    ctx = ssl.create_default_context(
        cafile=os.path.join(tlsdir, "ca.crt"))
    if with_cert == "valid":
        ctx.load_cert_chain(os.path.join(tlsdir, "client.crt"),
                            os.path.join(tlsdir, "client.key"))
    elif with_cert == "rogue":
        ctx.load_cert_chain(os.path.join(tlsdir, "rogue-client.crt"),
                            os.path.join(tlsdir, "rogue-client.key"))
    return ctx


def request(port, tlsdir, with_cert, method, path, headers=None, body=None):
    conn = http.client.HTTPSConnection("127.0.0.1", port,
                                       context=tls_client_ctx(tlsdir,
                                                              with_cert),
                                       timeout=15)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


def expect_tls_reject(name, port, tlsdir, with_cert):
    try:
        request(port, tlsdir, with_cert, "GET", "/v1/tools")
        check(name, False, "请求竟然成功")
    except (ssl.SSLError, ConnectionResetError, ConnectionAbortedError,
            OSError) as exc:
        check(name, True, str(exc))


def main():
    tmp = tempfile.mkdtemp(prefix="aik-tlsgw-")
    try:
        # T1 无证书目录启动即拒
        empty = os.path.join(tmp, "empty")
        os.makedirs(empty)
        env = dict(os.environ)
        env.update({"AIK_TLS_DIR": empty,
                    "AIK_TLS_GATEWAY_LISTEN": "127.0.0.1:0"})
        r = subprocess.run([sys.executable, GATEWAY], env=env,
                           capture_output=True, text=True, timeout=30)
        check("T1 无证书启动拒绝",
              r.returncode != 0 and "缺少证书文件" in r.stderr,
              "rc=%d stderr=%s" % (r.returncode, r.stderr.strip()[:120]))

        # 生成证书 + 假后端 + 网关
        tlsdir = os.path.join(tmp, "tls")
        os.makedirs(tlsdir)
        gen_certs(tlsdir)
        backend = start_backend()
        proc, port = start_gateway(tlsdir, backend.server_address[1])
        try:
            check("T0 网关启动(临时端口)", port is not None,
                  "stdout 未返回 LISTENING")
            if port is None:
                err = proc.stderr.read() if proc.poll() is not None else ""
                print("  网关输出: %s" % err[:300])
                raise SystemExit(1)

            # T2 无客户端证书 -> TLS 层拒绝
            expect_tls_reject("T2 无客户端证书拒绝", port, tlsdir, None)
            # T4 野 CA 客户端证书 -> 拒绝
            expect_tls_reject("T4 野CA客户端证书拒绝", port, tlsdir, "rogue")

            # T3 有效证书 -> 透传后端
            status, data = request(
                port, tlsdir, "valid", "GET", "/v1/tools?x=1",
                headers={"Authorization": "Bearer test-token-123"})
            ok = status == 200
            detail = ""
            if ok:
                j = json.loads(data)
                ok = (j.get("backend") is True
                      and j.get("path") == "/v1/tools?x=1"
                      and j.get("auth") == "Bearer test-token-123"
                      and j.get("xcn") == "gw-test-client"
                      and j.get("xff") == "127.0.0.1")
                detail = json.dumps(j, ensure_ascii=False)
            check("T3 有效证书透传(Bearer/路径/CN注入)", ok,
                  "status=%d %s" % (status, detail))

            # T5 POST 体透传
            status, data = request(
                port, tlsdir, "valid", "POST", "/v1/ask",
                headers={"Authorization": "Bearer tok2",
                         "Content-Type": "application/json"},
                body='{"q":"你好"}'.encode("utf-8"))
            j = json.loads(data) if status == 200 else {}
            check("T5 POST 体透传",
                  status == 200 and j.get("method") == "POST"
                  and j.get("body") == '{"q":"你好"}',
                  "status=%d body=%r" % (status, j.get("body")))

            # T6 healthz
            status, data = request(port, tlsdir, "valid", "GET", "/healthz")
            j = json.loads(data) if status == 200 else {}
            check("T6 /healthz", status == 200 and j.get("status") == "ok",
                  "status=%d" % status)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            backend.shutdown()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    if FAILURES:
        print("RESULT: FAIL (%s)" % ", ".join(FAILURES))
        return 1
    print("RESULT: ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
