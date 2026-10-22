#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""W77c E2E: real ai binary + mock OpenAI server, non-TTY and PTY clarify."""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    import pexpect
except ImportError:
    pexpect = None

STATE = {"requests": 0, "bodies": [], "final": "澄清已回答，任务继续。"}
LOCK = threading.Lock()

CLARIFY_ARGS = {
    "kind": "scope",
    "header": "选择要重启的服务",
    "question": "要重启哪个服务？",
    "options": [
        {"id": "1", "label": "nginx.service",
         "why": "当前活跃且是 Web 入口",
         "impact": "Web 短暂中断",
         "rollback": "systemctl start nginx"},
        {"id": "2", "label": "sshd.service",
         "why": "当前活跃",
         "impact": "会断开 SSH",
         "rollback": "systemctl start sshd"},
    ],
    "recommended": "1",
    "multi_select": False,
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, obj):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            body = json.loads(raw.decode() or "{}")
        except Exception:
            body = {}
        with LOCK:
            STATE["requests"] += 1
            idx = STATE["requests"]
            STATE["bodies"].append(body)
        msgs = body.get("messages") or []
        has_answer = any(m.get("role") == "tool" and
                         "CLARIFY_ANSWER" in str(m.get("content") or "")
                         for m in msgs)
        if idx == 1 and not has_answer:
            tool_calls = [{
                "id": "call_clarify_1", "type": "function",
                "function": {"name": "clarify",
                             "arguments": json.dumps(CLARIFY_ARGS,
                                                     ensure_ascii=False)},
            }]
            self._send({"id": "c1", "object": "chat.completion",
                        "model": "mock", "choices": [{
                            "index": 0, "message": {
                                "role": "assistant", "content": "",
                                "tool_calls": tool_calls},
                            "finish_reason": "tool_calls"}],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1}})
            return
        self._send({"id": "c2", "object": "chat.completion",
                    "model": "mock", "choices": [{
                        "index": 0, "message": {
                            "role": "assistant", "content": STATE["final"]},
                        "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1}})


def start_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return srv, srv.server_address[1]


def write_config(home, port):
    d = home / ".aikernel"
    d.mkdir(parents=True, exist_ok=True)
    (d / "model.toml").write_text(f"""[default]
model = "cloud"

[local]
enabled = false
base_url = "http://127.0.0.1:{port}/v1"
model = "mock"
timeout_ms = 30000
api_key = ""

[ui]
ctx_len = 32768
max_tokens = 512
stream = false
local_api = "native"
color = false
verbose = false
session = "default"

[route]
mode = "auto"
privacy = false
prefer_local = false
failover = false
offline_intents = false

[models.cloud]
provider_type = "openai_compatible"
model_name = "mock"
base_url = "http://127.0.0.1:{port}/v1"
api_key = ""

[models.local]
provider_type = "local"
model_name = "mock"
base_url = "http://127.0.0.1:{port}/v1"
api_key = ""
""", encoding="utf-8")


def env_for(home, agent):
    env = dict(os.environ)
    env.update({
        "HOME": str(home),
        "AIKERNEL_TOOLS_JSON": str(agent / "tools" / "tools.json"),
        "AIKERNEL_TRACE_DIR": str(home / "trace"),
        "NO_COLOR": "1",
    })
    for k in ("AIKERNEL_ASSUME_YES", "AIKERNEL_LEASE",
              "AIKERNEL_CONFIRM_NONCE", "AIKERNEL_OFFLINE_INTENTS",
              "AIKERNEL_CLARIFY_DETECT"):
        env.pop(k, None)
    return env


def run_ai(agent, home, args):
    env = env_for(home, agent)
    p = subprocess.run([str(agent / "ai")] + list(args), env=env,
                       stdin=subprocess.DEVNULL, capture_output=True,
                       text=True, timeout=60)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def run_non_tty(agent, home, q):
    return run_ai(agent, home, ["-p", q])


def find_nonce(out):
    m = re.search(r'"nonce":"(cq-[A-Za-z0-9._-]+)"', out)
    return m.group(1) if m else ""


def _txt(x):
    return x if isinstance(x, str) else ""


def run_pty(agent, home, q, answer="2"):
    if pexpect is None:
        return None, "pexpect missing"
    env = env_for(home, agent)
    child = pexpect.spawn(str(agent / "ai"), ["-p", q], env=env,
                          encoding="utf-8", timeout=30)
    out = []
    try:
        child.expect(r"\[clarify\]", timeout=20)
        out.append((child.before or "") + _txt(child.after))
        child.expect(r"选择（序号或 id）", timeout=10)
        out.append((child.before or "") + _txt(child.after))
        child.sendline(answer)
        child.expect(r"澄清已回答", timeout=20)
        out.append((child.before or "") + _txt(child.after))
        child.expect(pexpect.EOF, timeout=10)
        out.append((child.before or "") + _txt(child.after))
        try:
            child.close()
        except Exception:
            pass
        return child.exitstatus, "".join(out)
    except Exception as e:
        out.append(str(e))
        try:
            child.close(force=True)
        except Exception:
            pass
        return None, "".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-dir", default=".")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    agent = Path(args.agent_dir).resolve()
    if not (agent / "ai").exists():
        print("missing ai binary", file=sys.stderr)
        return 2
    srv, port = start_server()
    results = []
    try:
        home = Path(tempfile.mkdtemp(prefix="w77c-e2e-nt-"))
        write_config(home, port)
        rc, out = run_non_tty(agent, home, "重启服务")
        reqs = STATE["requests"]
        results.append(("non_tty_rc", rc == 0, "rc=%s" % rc))
        results.append(("non_tty_json", "CLARIFY_REQUIRED" in out and
                        '"nonce":"cq-' in out and '"options"' in out,
                        out[-1200:]))
        results.append(("non_tty_header", "选择要重启的服务" in out, ""))
        results.append(("non_tty_why", '"why"' in out, ""))
        results.append(("non_tty_stops", reqs == 1, "requests=%d" % reqs))
        nonce = find_nonce(out)
        results.append(("non_tty_nonce", nonce.startswith("cq-"),
                        "nonce=%s" % nonce))

        # W77c-2a：第二次调用恢复 pending（同一 HOME/session/mock）
        rc_r, out_r = run_ai(agent, home, [
            "--clarify-answer", nonce, "--clarify-select", "2",
            "--session", "default"])
        results.append(("resume_rc", rc_r == 0,
                        "rc=%s out=%s" % (rc_r, out_r[-1200:])))
        results.append(("resume_final", STATE["final"] in out_r,
                        out_r[-1200:]))
        last = STATE["bodies"][-1] if STATE["bodies"] else {}
        joined = "\n".join(str(m.get("content") or "")
                           for m in (last.get("messages") or []))
        results.append(("resume_question",
                        "[clarification answer]" in joined and
                        "sshd.service" in joined, joined[-1200:]))
        results.append(("resume_history", "CLARIFY_REQUIRED" in joined, ""))
        results.append(("resume_requests", STATE["requests"] == 2,
                        "requests=%d" % STATE["requests"]))

        rc_p, out_p = run_ai(agent, home, [
            "--clarify-answer", nonce, "--clarify-select", "2",
            "--session", "default"])
        results.append(("replay_rc", rc_p != 0, "rc=%s" % rc_p))
        results.append(("replay_rejected", "消费" in out_p or "重放" in out_p,
                        out_p[-800:]))
        results.append(("replay_no_model", STATE["requests"] == 2,
                        "requests=%d" % STATE["requests"]))

        # 未知选项：必须在模型调用前失败，且不消费 pending
        STATE.update({"requests": 0, "bodies": []})
        home3 = Path(tempfile.mkdtemp(prefix="w77c-e2e-badid-"))
        write_config(home3, port)
        rc_b, out_b = run_non_tty(agent, home3, "重启服务")
        nonce3 = find_nonce(out_b)
        pending3 = (home3 / ".aikernel" / "clarify" / "pending" /
                    ("%s.json" % nonce3))
        rc_na, out_na = run_ai(agent, home3, [
            "--clarify-answer", nonce3, "--session", "default"])
        results.append(("no_answer_rc", rc_na != 0, "rc=%s" % rc_na))
        results.append(("no_answer_no_model", STATE["requests"] == 1,
                        "requests=%d" % STATE["requests"]))
        results.append(("no_answer_not_consumed", pending3.exists(), ""))
        rc_ws, out_ws = run_ai(agent, home3, [
            "--clarify-answer", nonce3, "--clarify-select", "2",
            "--session", "other-session"])
        results.append(("wrong_session_rc", rc_ws != 0, "rc=%s" % rc_ws))
        results.append(("wrong_session_rejected", "session" in out_ws.lower(),
                        out_ws[-800:]))
        results.append(("wrong_session_no_model", STATE["requests"] == 1,
                        "requests=%d" % STATE["requests"]))
        results.append(("wrong_session_not_consumed", pending3.exists(), ""))
        rc_bad, out_bad = run_ai(agent, home3, [
            "--clarify-answer", nonce3, "--clarify-select", "9",
            "--session", "default"])
        results.append(("wrong_id_rc", rc_bad != 0, "rc=%s" % rc_bad))
        results.append(("wrong_id_rejected", "未知" in out_bad or
                        "非法选项" in out_bad, out_bad[-800:]))
        results.append(("wrong_id_no_model", STATE["requests"] == 1,
                        "requests=%d" % STATE["requests"]))
        results.append(("wrong_id_not_consumed", pending3.exists(),
                        str(pending3)))
        rc_ok, out_ok = run_ai(agent, home3, [
            "--clarify-answer", nonce3, "--clarify-select", "2"])
        results.append(("wrong_id_retry", rc_ok == 0 and
                        STATE["final"] in out_ok and
                        STATE["requests"] == 2,
                        "rc=%s requests=%d out=%s" %
                        (rc_ok, STATE["requests"], out_ok[-800:])))

        if pexpect is not None:
            STATE.update({"requests": 0, "bodies": []})
            home2 = Path(tempfile.mkdtemp(prefix="w77c-e2e-pty-"))
            write_config(home2, port)
            rc2, out2 = run_pty(agent, home2, "重启服务", "2")
            results.append(("pty_rc", rc2 == 0,
                            "rc=%s out=%s" % (rc2, out2[-1500:])))
            results.append(("pty_menu", "（推荐）" in out2 and
                            "nginx.service" in out2 and
                            "sshd.service" in out2, out2[-1200:]))
            results.append(("pty_continue", "澄清已回答" in out2,
                            out2[-2000:]))
            answered = any("CLARIFY_ANSWER" in json.dumps(b, ensure_ascii=False)
                           for b in STATE["bodies"][1:])
            results.append(("pty_answer_sent", answered, ""))
    finally:
        srv.shutdown()
    ok = all(r[1] for r in results)
    for name, good, detail in results:
        print(("PASS: " if good else "FAIL: ") + name +
              (("  [%s]" % detail) if not good and detail else ""))
    print("RESULT: %s (%d/%d)" % ("PASS" if ok else "FAIL",
                                  sum(1 for r in results if r[1]),
                                  len(results)))
    if args.out:
        Path(args.out).write_text(json.dumps(
            {"ok": ok, "checks": [{"name": n, "ok": g, "detail": d}
                                  for n, g, d in results]},
            ensure_ascii=False, indent=1), encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
