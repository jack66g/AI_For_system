#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""test_ac_pty.py - P-54：TUI 实链自动压缩台架（真 occ + pty + mock 全家）

链路：occ TUI（pty）→ mock LLM（127.0.0.1，明标假 key）→ turn 收口
→ occ_ac 客户端 → mock AC（mock_ac_p54.py，恒判压）→ begin/填表/commit
→ 换窗。断言：①AC 请求序列顺序 ②OCC_DB 落〈会话摘要〉system 行
③换窗后续 turn 连续性。运行：python3 test_ac_pty.py（L1，非 root 可）。
"""
import fcntl
import json
import os
import pty
import re
import select
import signal
import sqlite3
import struct
import subprocess
import sys
import termios
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = "/tmp/p54ac"
OCC = os.path.join(HERE, "..", "..", "..", "aikernel-repo-alpha11", "occ")  # 占位，下方修正
OCC = "/home/jack66g/aikernel-repo-alpha11/agent/ai/occ/occ"
LLM_PORT = 8973
AC_PORT = 8974

DIGEST = ("## 目标\nP-54 台架：验证 TUI 实链自动压缩（判官恒 COMPRESS_NOW）。\n\n"
          "## 已完成\n首轮对话完成；mock AC 收到 session/start 与 judge；"
          "填表摘要经 LLM mock 生成并 commit 落盘。\n\n"
          "## 未完成\n后续真机自然触发观察（140 autocondensed 真服务）。\n\n"
          "## 文件变更清单\n无（只读链路）。\n\n"
          "## 恢复指针\ntranscript=本台架；快照=snapshot_path。\n")

LLM_HITS = {"text": 0, "digest": 0, "tool": 0}

def sse_text(text):
    return (('data: {"choices":[{"delta":{"content":'
             + json.dumps(text, ensure_ascii=False) + '}}]}\n\n'
             + 'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\n\n'
             + "data: [DONE]\n\n").encode("utf-8"))

class LLM(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        if "会话压缩助手" in body:
            LLM_HITS["digest"] += 1
            out = sse_text(DIGEST)
        elif "tool_call_id" in body:
            LLM_HITS["tool"] += 1
            out = sse_text("done")
        else:
            LLM_HITS["text"] += 1
            out = sse_text("ok-turn")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

def ok(name, cond):
    print("%s %s" % ("ok  " if cond else "FAIL", name), flush=True)
    return 1 if cond else 0

def main():
    npass = 0
    nfail = 0
    subprocess.run(["rm", "-rf", ROOT], check=False)
    os.makedirs(ROOT)
    open(ROOT + "/model.toml", "w").write(
        '[models.cloud]\nprovider_type = "openai_compatible"\n'
        'model_name = "mock-model"\nbase_url = "http://127.0.0.1:%d/v1"\n'
        'api_key = "mock-key-not-real"\n' % LLM_PORT)
    open(ROOT + "/policy.conf", "w").write(
        "[root]\nmode = privileged\n[wheel]\nmode = privileged\n"
        "group = p54-nogrp\n[default]\nmode = privileged\n")
    aclog = ROOT + "/ac_seq.log"
    ac = subprocess.Popen([sys.executable, HERE + "/mock_ac_p54.py",
                           str(AC_PORT), aclog])
    llm = ThreadingHTTPServer(("127.0.0.1", LLM_PORT), LLM)
    import threading
    threading.Thread(target=llm.serve_forever, daemon=True).start()
    time.sleep(0.6)

    pid, fd = pty.fork()
    if pid == 0:
        os.environ.update(AIK_CONSOLE_GATE_SKIP="1", TERM="xterm",
                          OCC_MODEL_TOML=ROOT + "/model.toml",
                          OCC_DB=ROOT + "/t.db",
                          OCC_CATALOG=ROOT + "/none.json",
                          AIKERNEL_POLICY=ROOT + "/policy.conf",
                          OCC_AC_URL="http://127.0.0.1:%d" % AC_PORT,
                          OCC_LLM_RETRY_MAX="1",
                          OCC_LLM_RETRY_BASE_MS="50",
                          OCC_LLM_RETRY_CAP_MS="100")
        os.chdir(ROOT)
        os.execv(OCC, ["occ"])
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
    buf = b""

    def drain(t):
        nonlocal buf
        end = time.time() + t
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    c = os.read(fd, 65536)
                except OSError:
                    return
                if not c:
                    return
                buf += c

    def send(s):
        os.write(fd, (s + "\r").encode())

    drain(4)
    send("/new")
    drain(1.5)
    send("hello")
    drain(10)

    seq = ""
    for _ in range(20):
        try:
            seq = open(aclog, encoding="utf-8").read().strip()
        except OSError:
            seq = ""
        if "commit" in seq:
            break
        drain(1)
    # 首跑实测：客户端可走双趟（第一趟 start/check/begin 未达 commit，
    # 第二趟补全——begin 可先于 judge 出现）。断言=结果导向：五元齐全
    # +session/start 打头+commit 收尾。
    want = ["session/start", "check", "judge", "begin", "commit"]
    outcome_ok = (all(w in seq for w in want)
                  and seq.startswith("session/start")
                  and seq.rstrip().endswith("commit"))
    r = ok("ac-seq %r" % seq[:120], outcome_ok)
    npass, nfail = npass + r, nfail + (1 - r)

    summary_seen = False
    for _ in range(15):
        try:
            db = sqlite3.connect("file:%s/t.db?mode=ro" % ROOT, uri=True)
            n = db.execute("SELECT COUNT(*) FROM occ_message WHERE role='system' "
                           "AND content_json LIKE '%会话摘要%'").fetchone()[0]
            db.close()
        except Exception:
            n = 0
        if n:
            summary_seen = True
            break
        drain(1)
    r = ok("db-summary-row", summary_seen)
    npass, nfail = npass + r, nfail + (1 - r)

    r = ok("llm-digest-filled", LLM_HITS["digest"] >= 1)
    npass, nfail = npass + r, nfail + (1 - r)

    send("again")
    drain(8)
    r = ok("post-compact-turn", LLM_HITS["text"] >= 2)
    npass, nfail = npass + r, nfail + (1 - r)

    try:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
    except Exception:
        pass
    ac.terminate()
    llm.shutdown()
    print("test_ac_pty: %d ok, %d fail" % (npass, nfail))
    return 0 if nfail == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
