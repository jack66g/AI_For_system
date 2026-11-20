#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""mock_w2_llm.py - P-52 W2 确认面板 PTY 测试 mock（仅测试，明标）

用法: python3 mock_w2_llm.py <port> <req_dir>

POST /v1/chat/completions，按请求体分路（occ 侧两种请求）：
  - 普通对话请求（不含 tool_call_id）→ 按控制文件 <req_dir>/ctl 回放
    一个 toolCall（KEY=VALUE 行；进程启动后可改——ctl 才是场景旋钮）：
      TOOL  工具名（缺省 bash）
      ARGS  toolCall arguments 的 JSON 对象文本（原样嵌入字符串字段）
    SSE：tool_calls 增量（单块全量 arguments）→ finish_reason=
    tool_calls → [DONE]
  - 工具结果回投请求（含 tool_call_id）→ 固定文本回复收口（turn 结束）

请求体原样落 <req_dir>/req_<n>.json。仅测试夹具：绝无真实网络/密钥
（127.0.0.1 + mock-key）。
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPLY_AFTER_TOOL = "收到工具结果。"
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


def sse_tool_call(tool, args):
    """toolCall 增量（单块全量 arguments）+ finish + [DONE]——参数结构
    照 mock_title_llm.py / test_view_pty 既有 SSE 形态，不自造"""
    ev = {"choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [
        {"index": 0, "id": "call_w52_1", "type": "function",
         "function": {"name": tool, "arguments": args}}]}}]}
    fin = {"choices": [{"index": 0, "delta": {},
                        "finish_reason": "tool_calls"}]}
    out = ("data: " + json.dumps(ev, ensure_ascii=False) + "\n\n"
           + "data: " + json.dumps(fin) + "\n\n"
           + "data: [DONE]\n\n")
    return out.encode("utf-8")


def sse_text(text):
    out = ('data: {"choices":[{"delta":{"content":'
           + json.dumps(text, ensure_ascii=False) + '}}]}\n\n'
           + 'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n'
           + "data: [DONE]\n\n")
    return out.encode("utf-8")


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
        # O-18（W3 S8 两 turn）：分路看**最后一条消息 role**——旧判据
        # 「请求体含 tool_call_id」在第二轮起必中（历史携带该字段），
        # 对话请求被误判回投直接收口、第二 toolCall 永不回放
        last_role = ""
        try:
            last_role = json.loads(
                req.decode("utf-8", "replace"))["messages"][-1].get(
                    "role", "")
        except Exception:
            last_role = ""
        if last_role == "tool":
            payload = sse_text(REPLY_AFTER_TOOL)
        elif "会话标题".encode("utf-8") in req:
            # B8 同款分路：标题请求（/rename AI）绝不该拿 toolCall
            payload = sse_text("p52 测试标题")
        else:
            payload = sse_tool_call(ctl("TOOL", "bash"),
                                    ctl("ARGS", "{}"))
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
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()


if __name__ == "__main__":
    main()
