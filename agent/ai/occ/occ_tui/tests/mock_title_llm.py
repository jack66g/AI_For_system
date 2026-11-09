#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""mock_title_llm.py - B8 /rename AI 标题生成 mock（仅测试，明标）

用法: python3 mock_title_llm.py <port> <req_dir>

POST /v1/chat/completions，按请求体分路（occ 侧两种请求）：
  - 标题生成请求（system prompt 含标记串「会话标题」）→ 按控制文件
    <req_dir>/ctl 逐请求回放（KEY=VALUE 行；进程启动后可改——env 在
    mock fork 时已固化，控制文件才是场景旋钮）：
      TEXT  生成标题文本（缺省「内核调度器排障」）；分两块 SSE 回放
            （考验 TEXT_DELTA 增量累积）
      FAIL  =1 → 全部 500（失败降级路径）
      HANG  =1 → sleep 30（Esc 取消路径——SIGINT 打断）
  - 普通对话请求（建会话的首条消息 turn）→ 固定回复「收到，第一条消息已记录。」

请求体原样落 <req_dir>/req_<n>.json（断言输入=首条 user 消息截断用）。
仅测试夹具：绝无真实网络/密钥（127.0.0.1 + mock-key）。
"""
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CHAT_REPLY = "收到，第一条消息已记录。"
NREQ = [0]
REQ_DIR = "."


def ctl(key, default=None):
    """逐请求读 <req_dir>/ctl（KEY=VALUE）——env 已在 mock 启动时固化"""
    try:
        with open(os.path.join(REQ_DIR, "ctl"), encoding="utf-8") as f:
            for line in f:
                if line.startswith("#") or "=" not in line:
                    continue
                k, v = line.rstrip("\n").split("=", 1)
                if k.strip() == key:
                    return v.strip()
    except OSError:
        pass
    return default


def sse_text_deltas(text):
    """文本分两段 data 块（增量累积考验）+ finish + [DONE]"""
    mid = max(1, len(text) // 2)
    parts = [text[:mid], text[mid:]]
    out = []
    for p in parts:
        out.append('data: {"choices":[{"delta":{"content":'
                   + json.dumps(p, ensure_ascii=False) + '}}]}\n\n')
    out.append('data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n')
    out.append("data: [DONE]\n\n")
    return "".join(out).encode("utf-8")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        req = self.rfile.read(length) if length else b""
        NREQ[0] += 1
        with open(os.path.join(REQ_DIR, "req_%d.json" % NREQ[0]), "w",
                  encoding="utf-8") as f:
            f.write(req.decode("utf-8", "replace"))
        is_title = "会话标题".encode("utf-8") in req
        if is_title and ctl("FAIL"):
            self.send_response(500)
            self.send_header("Content-Length", "9")
            self.end_headers()
            self.wfile.write(b"mock fail")
            return
        if is_title and ctl("HANG"):
            time.sleep(30)
            self.send_response(500)
            self.send_header("Content-Length", "9")
            self.end_headers()
            self.wfile.write(b"mock hang")
            return
        if is_title:
            text = ctl("TEXT", "内核调度器排障")
        else:
            text = CHAT_REPLY
        payload = sse_text_deltas(text)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main():
    global REQ_DIR
    port = int(sys.argv[1])
    REQ_DIR = sys.argv[2]
    os.makedirs(REQ_DIR, exist_ok=True)
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.serve_forever()


if __name__ == "__main__":
    main()
