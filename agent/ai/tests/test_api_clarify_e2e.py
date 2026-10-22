#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""W77c-2b live E2E: real ai binary + mock OpenAI + in-process API server.

Proves the whole chain:
  API /ask (question via AIKERNEL_PROMPT, not argv)
    -> shell `-p -`
    -> clarify tool (mock model)
    -> non-TTY tagged stderr event
    -> API clarify_required envelope
    -> POST /clarify (selection via env, not argv)
    -> shell consumes pending and resumes same session
    -> final answer; replay rejected; session bound.
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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_clarify_e2e as mockllm  # noqa: E402

TOKEN = "test-token"
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond), detail))
    print(("PASS: " if cond else "FAIL: ") + name +
          (("  [" + str(detail) + "]") if not cond and detail else ""))


def load_api(path):
    loader = importlib.machinery.SourceFileLoader("aikernel_api_live",
                                                  str(path))
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent-dir", default=".")
    args = ap.parse_args()
    agent = Path(args.agent_dir).resolve()
    if not (agent / "ai").exists() or not (agent / "api" / "aikernel-api").exists():
        print("missing ai binary or api/aikernel-api", file=sys.stderr)
        return 2

    srv_model, port_model = mockllm.start_server()
    home = Path(tempfile.mkdtemp(prefix="w77c-api-e2e-"))
    mockllm.write_config(home, port_model)
    with open(home / ".aikernel" / "model.toml", "a", encoding="utf-8") as f:
        f.write('\n[api]\ntoken = "%s"\n' % TOKEN)

    os.environ["HOME"] = str(home)
    os.environ["AIKERNEL_AI_BIN"] = str(agent / "ai")
    os.environ["AIKERNEL_TOOLS_JSON"] = str(agent / "tools" / "tools.json")
    os.environ["AIKERNEL_API_ASK_TIMEOUT"] = "60"

    api = load_api(agent / "api" / "aikernel-api")
    api.AUDIT_LOG = str(home / "audit.log")
    api.TOKEN_FILE = str(home / "api-token")
    api.TOML_FILE = str(home / ".aikernel" / "model.toml")
    srv = api.Server(("127.0.0.1", 0), api.Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    port = srv.server_address[1]
    try:
        code, body = http(port, "/ask", {"question": "重启服务"})
        check("ask_http", code == 200, body)
        check("ask_status", body.get("status") == "clarify_required", body)
        clar = body.get("clarify") or {}
        nonce = clar.get("nonce", "")
        session = body.get("session", "")
        check("ask_nonce", nonce.startswith("cq-"), nonce)
        check("ask_session", session.startswith("api-"), session)
        check("ask_clarify_session_field", clar.get("session") == session,
              clar)
        check("ask_options", len(clar.get("options") or []) == 2, clar)
        check("ask_human_answer",
              "选择要重启的服务" in body.get("answer", "") and
              '"status":"CLARIFY_REQUIRED"' not in body.get("answer", ""),
              body.get("answer", "")[:400])
        pending = (home / ".aikernel" / "clarify" / "pending" /
                   (nonce + ".json"))
        check("pending_exists", pending.exists(), str(pending))
        if pending.exists():
            doc = json.loads(pending.read_text(encoding="utf-8"))
            check("pending_session", doc.get("session") == session, doc)
            check("pending_mode",
                  (pending.stat().st_mode & 0o777) == 0o600,
                  oct(pending.stat().st_mode & 0o777))
        model_requests_after_ask = mockllm.STATE["requests"]
        check("model_called_once", model_requests_after_ask == 1,
              model_requests_after_ask)

        code, body = http(port, "/clarify", {
            "nonce": nonce, "session": "api-wrongsession", "selection": ["1"]})
        check("clarify_wrong_session", code == 409, body)
        check("wrong_session_not_consumed", pending.exists(), "")
        check("wrong_session_no_model",
              mockllm.STATE["requests"] == model_requests_after_ask,
              mockllm.STATE["requests"])

        code, body = http(port, "/clarify", {
            "nonce": nonce, "session": session, "selection": ["2"]})
        check("clarify_ok", code == 200 and body.get("status") == "ok", body)
        check("clarify_final", mockllm.STATE["final"] in
              body.get("answer", ""), body)
        check("clarify_consumed", not pending.exists(), "")

        last = mockllm.STATE["bodies"][-1] if mockllm.STATE["bodies"] else {}
        joined = "\n".join(str(m.get("content") or "")
                           for m in (last.get("messages") or []))
        check("clarify_resume_question",
              "[clarification answer]" in joined and "sshd.service" in joined,
              joined[-1200:])
        check("clarify_history_kept", "CLARIFY_REQUIRED" in joined, "")

        requests_before = mockllm.STATE["requests"]
        code, body = http(port, "/clarify", {
            "nonce": nonce, "session": session, "selection": ["2"]})
        check("clarify_replay", code == 409, body)
        check("replay_no_model", mockllm.STATE["requests"] == requests_before,
              mockllm.STATE["requests"])
    finally:
        srv.shutdown()
        th.join(2)
        srv_model.shutdown()

    ok = all(r[1] for r in RESULTS)
    print("RESULT: %s (%d/%d)" %
          ("PASS" if ok else "FAIL", sum(1 for r in RESULTS if r[1]),
           len(RESULTS)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
