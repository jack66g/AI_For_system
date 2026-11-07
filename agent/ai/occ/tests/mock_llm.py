#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""mock_llm.py - occ -p 冒烟用本地 mock LLM（仅测试，明标）

用法: python3 mock_llm.py <port> <req_dir>

POST /v1/chat/completions：
  - 请求体原样落 <req_dir>/req_<n>.json（冒烟脚本断言 system prompt/
    历史组装用；失败请求也落盘——重试演练按文件数计尝试次数）
  - 回放固定 SSE（Content-Length 一次回；occ_sse 按字节切分消费，
    与 chunked 语义等价——mock 仅测试，如实标注）

回复固定文本「你好，我是 occ 冒烟 mock 助手。」+ usage + finish=stop
+ [DONE]。

T9b2 演练扩展（环境变量，缺省全关=旧行为不变）：
  OCC_MOCK_SLOW        每 data 块后 flush+sleep 秒数（kill 留窗口）
  OCC_MOCK_TOOL        =1 → 第 1 个请求回两枚 bash tool_call（sleep 2
                       写 a.txt/b.txt），其后请求回普通回复
                       （recover/interrupt 演练的工具执行阶段）
  OCC_MOCK_FAIL_N      前 N 个请求注入失败（重试演练「第 N 次成功」）
  OCC_MOCK_ALWAYS_FAIL =1 → 全部失败（「永不成功封顶」）
  OCC_MOCK_FAIL_STATUS 失败状态码（缺省 503；408=超时类/401=不重试）
  OCC_MOCK_BIND        监听地址（缺省 127.0.0.1；重试演练用 127.0.0.2
                       ——非 loopback 字面量，避开 occ 的 forwarder→direct
                       兜底，绝不触真网）
"""
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPLY = "你好，我是 occ 冒烟 mock 助手。"

SSE = (
    'data: {"choices":[{"delta":{"role":"assistant","content":"'
    + REPLY[:4]
    + '"}}]}\n\n'
    'data: {"choices":[{"delta":{"content":"'
    + REPLY[4:]
    + '"}}]}\n\n'
    'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n'
    'data: {"choices":[],"usage":{"prompt_tokens":42,'
    '"completion_tokens":8,"prompt_tokens_details":{"cached_tokens":3}}}\n\n'
    'data: [DONE]\n\n'
)

# 工具阶段（T9b2）：一次回两枚 bash 调用（各 sleep 2 后各写一个文件）——
# kill/SIGINT 有稳定窗口；两跑产物可对拍。
TOOL_SSE = (
    'data: {"choices":[{"delta":{"role":"assistant","tool_calls":['
    '{"index":0,"id":"call_t1","type":"function","function":'
    '{"name":"bash","arguments":""}},'
    '{"index":1,"id":"call_t2","type":"function","function":'
    '{"name":"bash","arguments":""}}]}}]}\n\n'
    'data: {"choices":[{"delta":{"tool_calls":['
    '{"index":0,"function":{"arguments":'
    '"{\\"command\\":\\"sleep 2 && echo KILL-A > a.txt\\"}"}},'
    '{"index":1,"function":{"arguments":'
    '"{\\"command\\":\\"sleep 2 && echo KILL-B > b.txt\\"}"}}'
    ']}}]}\n\n'
    'data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}\n\n'
    'data: {"choices":[],"usage":{"prompt_tokens":50,'
    '"completion_tokens":30}}\n\n'
    'data: [DONE]\n\n'
)

# 慢流模式（durable 演练用）：每 data 块写后 flush + sleep，给 kill -9
# 留流式中途的时间窗。OCC_MOCK_SLOW=秒（缺省 0=一次写）。
SLOW = float(os.environ.get("OCC_MOCK_SLOW", "0"))
TOOL_MODE = os.environ.get("OCC_MOCK_TOOL", "") == "1"
FAIL_N = int(os.environ.get("OCC_MOCK_FAIL_N", "0") or "0")
ALWAYS_FAIL = os.environ.get("OCC_MOCK_ALWAYS_FAIL", "") == "1"
FAIL_STATUS = int(os.environ.get("OCC_MOCK_FAIL_STATUS", "503") or "503")
BIND = os.environ.get("OCC_MOCK_BIND", "127.0.0.1")

state = {"n": 0}
lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass  # 静默（冒烟输出干净）

    def _send_bytes(self, status, ctype, payload):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if not self.path.endswith("/chat/completions"):
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        with lock:
            state["n"] += 1
            n = state["n"]
            with open(f"{REQ_DIR}/req_{n}.json", "wb") as f:
                f.write(body)

        # ---- 注入失败（重试演练；请求仍计数/落盘） ----
        if ALWAYS_FAIL or n <= FAIL_N:
            err = json.dumps(
                {"error": {"message": "mock injected failure"}},
                ensure_ascii=False,
            ).encode("utf-8")
            self._send_bytes(FAIL_STATUS, "application/json; charset=utf-8",
                             err)
            return

        if TOOL_MODE and n == 1:
            payload_s = TOOL_SSE
        else:
            payload_s = SSE
        payload = payload_s.encode("utf-8")

        if SLOW > 0:
            # 分块发送：先回 200 头，再逐块 flush+sleep（kill 窗口）
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                for chunk in payload_s.split("\n\n"):
                    if chunk:
                        self.wfile.write((chunk + "\n\n").encode("utf-8"))
                        self.wfile.flush()
                        time.sleep(SLOW)
            except (BrokenPipeError, ConnectionResetError):
                pass  # 客户端 kill -9 断连（durable 演练预期路径）
        else:
            self._send_bytes(200, "text/event-stream", payload)


if __name__ == "__main__":
    port = int(sys.argv[1])
    REQ_DIR = sys.argv[2]
    ThreadingHTTPServer((BIND, port), Handler).serve_forever()
