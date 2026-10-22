#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""W77 mock LLM server (OpenAI /v1 + Ollama native /api/chat).

Used by tests/test_w77_e2e.py to exercise routing without real qwen:
  --mode ok|500|429|slow|drop|toolcall|badjson
  --latency-ms N        delay before responding
  --fail-first N        first N requests return HTTP 500 (then ok)
  --port 0              bind ephemeral port; prints PORT=<n>
  --log path            append one JSON line per request

Endpoints:
  POST /chat/completions, /v1/chat/completions   (OpenAI, SSE if stream)
  POST /api/chat                                  (Ollama NDJSON if stream)
  POST /api/show                                  (context_length=32768)
  GET  /api/tags, /v1/models
  GET  /__stats                                   (request counters)
  GET  /__health                                  (ok)
"""
import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATS = {"requests": 0, "by_path": {}, "failures": 0, "streams": 0}
LOCK = threading.Lock()
ARGS = None


def log_request(path, body, status):
    if not ARGS.log:
        return
    try:
        with open(ARGS.log, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": time.time(),
                "path": path,
                "status": status,
                "stream": bool(body.get("stream")),
                "model": body.get("model"),
                "tools": len(body.get("tools") or []),
                "num_ctx": (body.get("options") or {}).get("num_ctx"),
                "messages": len(body.get("messages") or []),
            }, ensure_ascii=False) + "\n")
    except OSError:
        pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _toolcall_now(self):
        if ARGS.mode == "toolcall":
            return True
        return bool(ARGS.toolcall_once and STATS["requests"] == 1)

    def log_message(self, fmt, *args):
        pass

    def _read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return {}

    def _send_json(self, obj, status=200):
        # 紧凑 JSON：与真实 OpenAI 错误体一致，云 backend 的
        # "message":" 文本扫描才能取到错误信息/状态码。
        data = json.dumps(obj, ensure_ascii=False,
                          separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def _should_fail(self):
        with LOCK:
            STATS["requests"] += 1
            path = self.path.split("?")[0]
            STATS["by_path"][path] = STATS["by_path"].get(path, 0) + 1
            req_no = STATS["requests"]
        mode = ARGS.mode
        if ARGS.fail_first and req_no <= ARGS.fail_first:
            mode = "500"
        if mode in ("500", "429"):
            with LOCK:
                STATS["failures"] += 1
            return int(mode)
        return 0

    def _delay(self):
        if ARGS.latency_ms > 0:
            time.sleep(ARGS.latency_ms / 1000.0)

    def _content(self, body):
        if ARGS.mode == "toolcall":
            return None
        text = ARGS.reply
        # Echo a hint so e2e can assert which server answered.
        return text

    def _openai_toolcall_message(self):
        return {
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "call_w77_1",
                "type": "function",
                "function": {
                    "name": "exec_run",
                    "arguments": json.dumps({"command": "uname -s"}),
                },
            }],
        }

    def _handle_openai(self, body):
        status = self._should_fail()
        if status:
            log_request(self.path, body, status)
            self._send_json({"error": {"message": "mock failure %d" % status}},
                            status)
            return
        self._delay()
        stream = bool(body.get("stream"))
        msg = (self._openai_toolcall_message()
               if self._toolcall_now() else
               {"role": "assistant", "content": self._content(body)})
        if not stream:
            log_request(self.path, body, 200)
            self._send_json({
                "id": "chatcmpl-w77",
                "object": "chat.completion",
                "model": body.get("model") or "mock",
                "choices": [{"index": 0, "message": msg,
                             "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 3},
            })
            return
        with LOCK:
            STATS["streams"] += 1
        log_request(self.path, body, 200)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        if ARGS.mode == "toolcall":
            chunk = {"choices": [{"index": 0, "delta": {
                "role": "assistant",
                "tool_calls": msg["tool_calls"],
            }, "finish_reason": "tool_calls"}]}
            self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
        else:
            text = self._content(body) or ""
            mid = max(1, len(text) // 2)
            for piece in (text[:mid], text[mid:]):
                if not piece:
                    continue
                chunk = {"choices": [{"index": 0, "delta": {
                    "content": piece}, "finish_reason": None}]}
                self.wfile.write(b"data: " + json.dumps(chunk).encode() +
                                 b"\n\n")
            self.wfile.write(b"data: " + json.dumps({
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 3},
            }).encode() + b"\n\n")
        self.wfile.write(b"data: [DONE]\n\n")
        self.close_connection = True

    def _handle_ollama(self, body):
        status = self._should_fail()
        if status:
            log_request(self.path, body, status)
            self._send_json({"error": "mock failure %d" % status}, status)
            return
        self._delay()
        stream = bool(body.get("stream"))
        text = self._content(body)
        if not stream:
            log_request(self.path, body, 200)
            msg = {"role": "assistant", "content": text}
            if self._toolcall_now():
                msg = {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "function": {
                            "name": "exec_run",
                            "arguments": {"command": "uname -s"},
                        }
                    }],
                }
            self._send_json({
                "model": body.get("model") or "mock",
                "message": msg,
                "done": True,
                "prompt_eval_count": 12,
                "eval_count": 3,
            })
            return
        with LOCK:
            STATS["streams"] += 1
        log_request(self.path, body, 200)
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Connection", "close")
        self.end_headers()
        text = text or ""
        mid = max(1, len(text) // 2)
        for piece in (text[:mid], text[mid:]):
            if not piece:
                continue
            self.wfile.write(json.dumps({
                "model": body.get("model") or "mock",
                "message": {"role": "assistant", "content": piece},
                "done": False,
            }).encode() + b"\n")
        self.wfile.write(json.dumps({
            "model": body.get("model") or "mock",
            "message": {"role": "assistant", "content": ""},
            "done": True,
            "prompt_eval_count": 12,
            "eval_count": 3,
        }).encode() + b"\n")
        self.close_connection = True

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/__health", "/health"):
            self._send_json({"status": "ok"})
        elif path == "/__stats":
            with LOCK:
                self._send_json(dict(STATS))
        elif path == "/api/tags":
            self._send_json({"models": [{
                "name": "qwen2.5:1.5b",
                "model": "qwen2.5:1.5b",
                "size": 986000000,
                "details": {"parameter_size": "1.5B"},
            }]})
        elif path == "/v1/models":
            self._send_json({"object": "list", "data": [{
                "id": "mock", "object": "model"}]})
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = self.path.split("?")[0]
        body = self._read_body()
        if ARGS.mode == "drop":
            with LOCK:
                STATS["requests"] += 1
                STATS["failures"] += 1
            log_request(path, body, 0)
            self.close_connection = True
            return
        if path.endswith("/chat/completions"):
            self._handle_openai(body)
        elif path == "/api/chat":
            self._handle_ollama(body)
        elif path == "/api/show":
            self._send_json({
                "model_info": {"qwen2.context_length": 32768},
                "details": {"parameter_size": "1.5B"},
            })
        else:
            self._send_json({"error": "not found"}, 404)


def main():
    global ARGS
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--mode", default="ok",
                    choices=["ok", "500", "429", "slow", "drop", "toolcall",
                             "badjson"])
    ap.add_argument("--latency-ms", type=int, default=0)
    ap.add_argument("--fail-first", type=int, default=0)
    ap.add_argument("--reply", default="mock-ok")
    ap.add_argument("--log", default="")
    ap.add_argument("--toolcall-once", action="store_true",
                    help="first request returns an exec_run tool_call")
    ARGS = ap.parse_args()
    if ARGS.mode == "slow" and ARGS.latency_ms == 0:
        ARGS.latency_ms = 3000
    srv = ThreadingHTTPServer(("127.0.0.1", ARGS.port), Handler)
    print("PORT=%d" % srv.server_address[1], flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
