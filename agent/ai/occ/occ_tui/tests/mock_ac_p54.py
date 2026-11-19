#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""mock_ac_p54.py - P-54 AC 服务 mock（仅测试，明标）

用法: python3 mock_ac_p54.py <port> <log_path>
协议形状=tests/test_ac.c 内嵌 mock 的 python 移植（P-54 台架正典源）：
  POST /session/start → {"session_id":"ses_x"}
  GET  /check         → {"should":"JUDGE",...}（恒判可审）
  POST /judge         → {"decision":"COMPRESS_NOW",...}（恒判压缩）
  POST /begin         → {"mode":"full","template":五节模板,...}
  POST /commit        → 落盘 digest 快照并回 snapshot_path（E5 原子闸成功路）
请求序列写 <log_path>（分号分隔），供台架断言顺序。
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_PATH = ""
SEQ = []

def log_seq(tag):
    SEQ.append(tag)
    with open(LOG_PATH, "w", encoding="utf-8") as f:
        f.write(";".join(SEQ) + "\n")

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n).decode("utf-8", "replace") if n else ""

    def _send(self, status, obj):
        b = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path.startswith("/check"):
            log_seq("check")
            self._send(200, {"should": "JUDGE", "trigger": "turns",
                             "urgency": "normal", "reason": "轮次到阈值",
                             "signals": {"turns": 26},
                             "action_hint": "condense_judge"})
        else:
            self._send(404, {"errors": [{"msg": "nope"}]})

    def do_POST(self):
        body = self._body()
        if self.path.startswith("/session/start"):
            log_seq("session/start")
            self._send(200, {"session_id": "ses_x"})
        elif self.path.startswith("/judge"):
            log_seq("judge")
            self._send(200, {"decision": "COMPRESS_NOW",
                             "urgency": "normal", "reason": "判定通过"})
        elif self.path.startswith("/begin"):
            log_seq("begin")
            self._send(200, {"mode": "full",
                             "template": "## 目标\n\n## 已完成\n\n## 未完成\n\n"
                                         "## 文件变更清单\n\n## 恢复指针\n",
                             "guidance": "逐节填写",
                             "required_sections": ["## 目标", "## 已完成",
                                                   "## 未完成", "## 文件变更清单",
                                                   "## 恢复指针"]})
        elif self.path.startswith("/commit"):
            log_seq("commit")
            snap = "/tmp/p54_ac_snap_%d.md" % os.getpid()
            try:
                md = json.loads(body).get("digest_md", "")
                open(snap, "w", encoding="utf-8").write(md)
                self._send(200, {"ok": True, "snapshot_path": snap,
                                 "segments_written": 0,
                                 "sme": {"stored": False}})
            except Exception:
                self._send(200, {"ok": True, "segments_written": 0,
                                 "sme": {"stored": False}})
        else:
            self._send(404, {"errors": [{"msg": "nope"}]})

if __name__ == "__main__":
    LOG_PATH = sys.argv[2]
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
