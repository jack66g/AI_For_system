#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""W77c clarify gate: real ai + mock model + API, 5 controlled scenarios.

Scenarios:
  1 restart-service (ambiguous)  -> must clarify; accept recommended; success
  2 restart-nginx   (unique)     -> must NOT clarify
  3 delete          (no target)  -> must clarify; accept recommended; success
  4 memory          (normal)     -> must NOT clarify
  5 same-round clarify+exec_run  -> clarify; exec_run suppressed; success

Metrics: missed questions 0, unnecessary questions 0, recommendation
acceptance 3/3, post-clarify success 3/3, average questions per task <= 2.
Also: clarify creates no lease; same-round exec_run has no side effect.
"""
import argparse
import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOKEN = "test-token"
SIDE_EFFECT = "/tmp/clarify-gate-side-effect"
STATE = {"requests": 0, "bodies": []}
LOCK = threading.Lock()
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("PASS: " if cond else "FAIL: ") + name +
          (("  [" + str(detail) + "]") if not cond and detail else ""))


CLARIFY_SERVICE = {
    "kind": "scope", "header": "选择要重启的服务",
    "question": "要重启哪个服务？",
    "options": [
        {"id": "nginx", "label": "nginx.service", "why": "Web 入口",
         "impact": "Web 短暂中断", "rollback": "systemctl start nginx"},
        {"id": "sshd", "label": "sshd.service", "why": "远程入口",
         "impact": "会断开 SSH", "rollback": "systemctl start sshd"},
    ],
    "recommended": "nginx", "multi_select": False,
}
CLARIFY_DELETE = {
    "kind": "scope", "header": "选择要删除的路径",
    "question": "要删除哪个路径？",
    "options": [
        {"id": "a", "label": "/tmp/a", "why": "候选路径",
         "impact": "删除该路径", "rollback": "无法回滚"},
        {"id": "b", "label": "/tmp/b", "why": "候选路径",
         "impact": "删除该路径", "rollback": "无法回滚"},
    ],
    "recommended": "a", "multi_select": False,
}


def tool_call(cid, name, args):
    return {"id": cid, "type": "function",
            "function": {"name": name,
                         "arguments": json.dumps(args, ensure_ascii=False)}}


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
            STATE["bodies"].append(body)
        msgs = body.get("messages") or []
        joined = "\n".join(str(m.get("content") or "") for m in msgs)
        user_text = "\n".join(str(m.get("content") or "") for m in msgs
                              if m.get("role") == "user")
        has_answer = ("[clarification answer]" in user_text or
                      any(m.get("role") == "tool" and
                          "CLARIFY_ANSWER" in str(m.get("content") or "")
                          for m in msgs))
        suppressed = "not executed (clarify pending)" in joined

        if has_answer:
            if "同轮" in user_text:
                content = "suppressed-ok" if suppressed else "suppressed-MISSING"
            else:
                content = "clarified-ok"
            return self._final(content)

        need = None
        if "同轮" in user_text and "重启服务" not in user_text:
            need = CLARIFY_SERVICE
        elif "重启服务" in user_text:
            need = CLARIFY_SERVICE
        elif "删除" in user_text and "/tmp/" not in user_text:
            need = CLARIFY_DELETE
        if need is None:
            return self._final("no-clarify-ok")

        calls = [tool_call("call_clarify_gate", "clarify", need)]
        if "同轮" in user_text:
            calls.append(tool_call(
                "call_exec_gate", "exec_run",
                {"command": "touch", "args": [SIDE_EFFECT]}))
        self._send({"id": "gate", "object": "chat.completion",
                    "model": "mock", "choices": [{
                        "index": 0, "message": {
                            "role": "assistant", "content": "",
                            "tool_calls": calls},
                        "finish_reason": "tool_calls"}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

    def _final(self, text):
        self._send({"id": "gate-final", "object": "chat.completion",
                    "model": "mock", "choices": [{
                        "index": 0, "message": {"role": "assistant",
                                                "content": text},
                        "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1}})


def load_api(path):
    loader = importlib.machinery.SourceFileLoader("aikernel_api_gate", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def http(port, path, body=None, token=TOKEN, timeout=120):
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    data = json.dumps(body, ensure_ascii=False).encode() if body is not None \
        else None
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path),
                                 data=data, headers=headers,
                                 method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except ValueError:
            return e.code, {}


def write_config(home, port):
    d = Path(home) / ".aikernel"
    d.mkdir(parents=True, exist_ok=True)
    (d / "model.toml").write_text("""[default]
model = "cloud"

[local]
enabled = false
base_url = "http://127.0.0.1:%d/v1"
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
base_url = "http://127.0.0.1:%d/v1"
api_key = ""

[models.local]
provider_type = "local"
model_name = "mock"
base_url = "http://127.0.0.1:%d/v1"
api_key = ""

[api]
token = "%s"
""" % (port, port, port, TOKEN), encoding="utf-8")
    os.chmod(str(d / "model.toml"), 0o600)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-dir", default=".")
    args = ap.parse_args()
    agent = Path(args.agent_dir).resolve()
    api_path = agent / "api" / "aikernel-api"
    if not (agent / "ai").exists() or not api_path.exists():
        print("missing ai binary or api/aikernel-api", file=sys.stderr)
        return 2

    if os.path.exists(SIDE_EFFECT):
        os.unlink(SIDE_EFFECT)
    home = Path(tempfile.mkdtemp(prefix="w77c-gate-"))
    leases = home / "leases"
    leases.mkdir()

    srv_model = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    th_model = threading.Thread(target=srv_model.serve_forever, daemon=True)
    th_model.start()
    port_model = srv_model.server_address[1]
    write_config(home, port_model)

    os.environ["HOME"] = str(home)
    os.environ["AIKERNEL_AI_BIN"] = str(agent / "ai")
    os.environ["AIKERNEL_TOOLS_JSON"] = str(agent / "tools" / "tools.json")
    os.environ["AIKERNEL_API_ASK_TIMEOUT"] = "60"
    os.environ["AIKERNEL_LEASE_DIR"] = str(leases)
    os.environ["AIKERNEL_CLARIFY_DETECT"] = "0"

    api = load_api(api_path)
    api.AUDIT_LOG = str(home / "audit.log")
    api.TOKEN_FILE = str(home / "api-token")
    api.TOML_FILE = str(home / ".aikernel" / "model.toml")
    srv = api.Server(("127.0.0.1", 0), api.Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    port = srv.server_address[1]

    scenarios = [
        ("ambiguous_service", "重启服务", True),
        ("unique_service", "重启 nginx.service", False),
        ("destructive_no_target", "删除", True),
        ("normal", "查看内存使用", False),
        ("same_round_suppress", "同轮 clarify 和 exec_run 一起", True),
    ]
    asked = 0
    unnecessary = 0
    missed = 0
    rec_total = 0
    rec_ok = 0
    post_total = 0
    post_ok = 0
    side_effect_seen = False

    try:
        for name, q, expect_clarify in scenarios:
            code, body = http(port, "/ask", {"question": q})
            check(name + ".ask_http", code == 200, body)
            status = body.get("status")
            if expect_clarify:
                if status != "clarify_required":
                    missed += 1
                    check(name + ".asked", False, body)
                    continue
                asked += 1
                check(name + ".asked", True)
                clar = body.get("clarify") or {}
                rec = clar.get("recommended")
                session = body.get("session")
                code2, body2 = http(port, "/clarify", {
                    "nonce": clar.get("nonce"),
                    "session": session,
                    "selection": [rec] if rec else [1],
                })
                check(name + ".clarify_http", code2 == 200 and
                      body2.get("status") == "ok", body2)
                rec_total += 1
                rec_ok += int(bool(rec))
                post_total += 1
                post_ok += int(body2.get("status") == "ok")
                if name == "same_round_suppress":
                    check(name + ".suppressed",
                          "suppressed-ok" in body2.get("answer", ""), body2)
                    side_effect_seen = os.path.exists(SIDE_EFFECT)
            else:
                if status == "clarify_required":
                    unnecessary += 1
                check(name + ".no_clarify", status == "ok", body)
                check(name + ".answer", "no-clarify-ok" in
                      body.get("answer", ""), body)

        check("metrics_missed_zero", missed == 0, missed)
        check("metrics_unnecessary_zero", unnecessary == 0, unnecessary)
        check("metrics_recommendation", rec_total == 3 and rec_ok == 3,
              (rec_ok, rec_total))
        check("metrics_post_clarify", post_total == 3 and post_ok == 3,
              (post_ok, post_total))
        avg = asked / len(scenarios)
        check("metrics_avg_questions_le_2", avg <= 2.0, avg)
        check("same_round_no_side_effect", not side_effect_seen, SIDE_EFFECT)
        lease_files = [p for p in leases.rglob("*") if p.is_file()]
        check("no_lease_created", not lease_files, lease_files[:3])
        print("METRICS: asked=%d/%d unnecessary=%d missed=%d "
              "recommendation=%d/%d post_clarify=%d/%d avg_questions=%.2f" %
              (asked, len(scenarios), unnecessary, missed,
               rec_ok, rec_total, post_ok, post_total, avg))
    finally:
        srv.shutdown()
        th.join(2)
        srv_model.shutdown()
        th_model.join(2)

    ok = all(r[1] for r in RESULTS)
    print("RESULT: %s (%d/%d)" %
          ("PASS" if ok else "FAIL", sum(1 for r in RESULTS if r[1]),
           len(RESULTS)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
