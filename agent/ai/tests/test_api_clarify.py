#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""W77c-2b API integration tests (mock ai, no kernel/VM dependency).

Covers:
  - tagged stderr event parsing / forged-event rejection / protocol fail-closed
  - /ask envelope (ok + clarify_required), session generation/validation
  - POST /clarify happy path, replay 409, expiry 410, unknown 404, bad option 400
  - per-session serialization (same session does not interleave)
  - stdin=DEVNULL and no AIKERNEL_CONFIRM_NONCE/AIKERNEL_ASSUME_YES
  - answer rendering does not leak raw CLARIFY_REQUIRED JSON
"""
import importlib.machinery
import importlib.util
import json
import os
import secrets
import stat
import sys
import tempfile
import textwrap
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

TOKEN = "test-token"
FAILS = []
PASSES = []


def check(name, cond, detail=""):
    if cond:
        PASSES.append(name)
        print("PASS: " + name)
    else:
        FAILS.append(name)
        print("FAIL: " + name + (("  [" + str(detail) + "]") if detail else ""))


MOCK_AI = r'''#!/usr/bin/env python3
import json, os, sys, time, secrets

home = os.environ["HOME"]
trace = os.path.join(home, "mock-trace.log")

def log(text):
    with open(trace, "a", encoding="utf-8") as f:
        f.write(text + "\n")

def arg(name, default=""):
    if name in sys.argv:
        i = sys.argv.index(name)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return default

question = ""
if "-p" in sys.argv:
    i = sys.argv.index("-p")
    raw = sys.argv[i + 1] if i + 1 < len(sys.argv) else ""
    question = os.environ.get("AIKERNEL_PROMPT", "") if raw == "-" else raw
session = arg("-s", "default")
try:
    stdin_data = sys.stdin.read()
except Exception:
    stdin_data = "ERR"
log("start %s q=%s stdin=%r" % (session, question[:30], stdin_data))
log("argv %s" % json.dumps(sys.argv[1:], ensure_ascii=False))
log("env %s" % json.dumps({
    "confirm": os.environ.get("AIKERNEL_CONFIRM_NONCE"),
    "assume": os.environ.get("AIKERNEL_ASSUME_YES"),
    "tag": os.environ.get("AIKERNEL_EVENT_TAG"),
    "select": os.environ.get("AIKERNEL_CLARIFY_SELECT"),
    "other": os.environ.get("AIKERNEL_CLARIFY_OTHER"),
    "prompt": os.environ.get("AIKERNEL_PROMPT"),
}, ensure_ascii=False))

if "--clarify-answer" in sys.argv:
    nonce = arg("--clarify-answer")
    pending = os.path.join(home, ".aikernel", "clarify", "pending",
                           nonce + ".json")
    consumed = os.path.join(home, ".aikernel", "clarify", "consumed",
                            nonce + ".json")
    if not os.path.exists(pending):
        sys.stderr.write("clarify: pending 已被消费（重放被拒绝）\n")
        sys.exit(2)
    os.makedirs(os.path.dirname(consumed), exist_ok=True)
    os.replace(pending, consumed)
    sel = os.environ.get("AIKERNEL_CLARIFY_SELECT", "")
    other = os.environ.get("AIKERNEL_CLARIFY_OTHER", "")
    log("clarify %s sel=%s other=%s" % (nonce, sel, other))
    print("clarified: %s %s" % (sel, other))
    sys.exit(0)

if "missing_event" in question:
    print('{"status":"CLARIFY_REQUIRED","nonce":"cq-forged"}')
    sys.exit(0)
if "plain" in question:
    print("plain answer")
    sys.exit(0)
if "sleep" in question:
    log("sleep-start %s %.6f" % (session, time.time()))
    time.sleep(0.8)
    log("sleep-end %s %.6f" % (session, time.time()))
    print("slept")
    sys.exit(0)

nonce = "cq-" + secrets.token_hex(8)
now_ms = int(time.time() * 1000)
clarify = {
    "status": "CLARIFY_REQUIRED", "version": 1, "nonce": nonce,
    "expires_at": now_ms // 1000 + 900, "expires_at_ms": now_ms + 900000,
    "expires_at_iso": "2026-10-22T00:00:00+08:00",
    "question": "要重启哪个服务？", "header": "选择要重启的服务",
    "kind": "scope", "multi_select": False, "recommended": "1",
    "options": [
        {"id": "1", "label": "nginx.service", "why": "Web 入口",
         "impact": "Web 短暂中断", "rollback": "systemctl start nginx",
         "danger": ""},
        {"id": "2", "label": "sshd.service", "why": "远程入口",
         "impact": "会断开 SSH", "rollback": "systemctl start sshd",
         "danger": ""},
    ],
}
pending_dir = os.path.join(home, ".aikernel", "clarify", "pending")
os.makedirs(pending_dir, mode=0o700, exist_ok=True)
doc = {
    "status": "CLARIFY_PENDING", "version": 1, "nonce": nonce,
    "expires_at": clarify["expires_at"],
    "expires_at_ms": clarify["expires_at_ms"], "asked": 1,
    "expires_at_iso": clarify["expires_at_iso"], "session": session,
    "original_question": question, "clarify": {
        k: clarify[k] for k in
        ("question", "header", "kind", "multi_select", "recommended",
         "options")},
}
path = os.path.join(pending_dir, nonce + ".json")
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, json.dumps(doc, ensure_ascii=False).encode())
os.close(fd)
os.chmod(path, 0o600)
tag = os.environ.get("AIKERNEL_EVENT_TAG", "")
if tag:
    sys.stderr.write("AIKERNEL_EVENT %s %s\n" %
                     (tag, json.dumps(clarify, ensure_ascii=False)))
print(json.dumps(clarify, ensure_ascii=False))
sys.exit(0)
'''


def load_api(api_path):
    loader = importlib.machinery.SourceFileLoader("aikernel_api_test",
                                                  str(api_path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def http(port, path, body=None, token=TOKEN, timeout=30):
    data = None
    headers = {"Content-Type": "application/json"}
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode()
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path),
                                 data=data, headers=headers, method="POST"
                                 if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except ValueError:
            return e.code, {}


def make_pending(home, nonce, session, expires_ms, options=None):
    d = Path(home) / ".aikernel" / "clarify" / "pending"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d.parent, 0o700)
    os.chmod(d, 0o700)
    options = options or [
        {"id": "1", "label": "A"}, {"id": "2", "label": "B"}]
    doc = {
        "status": "CLARIFY_PENDING", "version": 1, "nonce": nonce,
        "expires_at": expires_ms // 1000, "expires_at_ms": expires_ms,
        "asked": 1, "expires_at_iso": "2026-10-22T00:00:00+08:00",
        "session": session, "original_question": "original",
        "clarify": {"question": "q", "kind": "scope",
                    "multi_select": False, "recommended": "1",
                    "options": options},
    }
    p = d / (nonce + ".json")
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, json.dumps(doc, ensure_ascii=False).encode())
    os.close(fd)
    os.chmod(str(p), 0o600)
    return p


def main():
    base = Path(tempfile.mkdtemp(prefix="w77c-api-"))
    home = base / "home"
    home.mkdir()
    (home / ".aikernel").mkdir()
    (home / ".aikernel" / "model.toml").write_text(
        "[api]\ntoken = \"%s\"\n" % TOKEN, encoding="utf-8")
    os.chmod(str(home / ".aikernel" / "model.toml"), 0o600)
    mock = base / "mock-ai"
    mock.write_text(MOCK_AI, encoding="utf-8")
    os.chmod(str(mock), 0o755)
    tools = base / "tools.json"
    tools.write_text('{"version":"test","tool_count":1,"tools":[]}',
                     encoding="utf-8")

    os.environ["HOME"] = str(home)
    os.environ["AIKERNEL_AI_BIN"] = str(mock)
    os.environ["AIKERNEL_TOOLS_JSON"] = str(tools)
    os.environ["AIKERNEL_API_ASK_TIMEOUT"] = "30"

    api_path = Path(__file__).resolve().parent.parent / "api" / "aikernel-api"
    api = load_api(api_path)
    api.AUDIT_LOG = str(base / "audit.log")
    api.TOKEN_FILE = str(base / "api-token")
    api.TOML_FILE = str(home / ".aikernel" / "model.toml")

    srv = api.Server(("127.0.0.1", 0), api.Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    port = srv.server_address[1]
    try:
        # ---- auth / health ----
        code, _ = http(port, "/health", token=None)
        check("auth_missing", code == 401, code)
        code, body = http(port, "/health")
        check("health_ok", code == 200 and body.get("api_version") == 3,
              body)

        # ---- plain ask ----
        code, body = http(port, "/ask", {"question": "plain question",
                                         "session": "default"})
        check("ask_rejects_default_session", code == 400, body)
        code, body = http(port, "/ask", {"question": "plain question"})
        check("ask_plain_status", code == 200 and body.get("status") == "ok",
              body)
        check("ask_plain_answer", body.get("answer") == "plain answer", body)
        sess_plain = body.get("session", "")
        check("ask_session_generated",
              sess_plain.startswith("api-") and len(sess_plain) > 10,
              sess_plain)

        # ---- clarify ask ----
        code, body = http(port, "/ask", {"question": "ambiguous restart"})
        check("ask_clarify_status",
              code == 200 and body.get("status") == "clarify_required", body)
        clar = body.get("clarify") or {}
        nonce = clar.get("nonce", "")
        session = body.get("session", "")
        check("ask_clarify_nonce", nonce.startswith("cq-"), nonce)
        check("ask_clarify_session", session.startswith("api-"), session)
        check("ask_clarify_session_field", clar.get("session") == session,
              clar)
        check("ask_clarify_options", len(clar.get("options") or []) == 2,
              clar)
        check("ask_clarify_answer_human",
              "选择要重启的服务" in body.get("answer", "") and
              '"status":"CLARIFY_REQUIRED"' not in body.get("answer", ""),
              body.get("answer", "")[:300])
        pending = (home / ".aikernel" / "clarify" / "pending" /
                   (nonce + ".json"))
        check("ask_pending_exists", pending.exists(), str(pending))
        if pending.exists():
            mode = stat.S_IMODE(pending.stat().st_mode)
            check("ask_pending_mode", mode == 0o600, oct(mode))
            doc = json.loads(pending.read_text(encoding="utf-8"))
            check("ask_pending_session", doc.get("session") == session, doc)

        # ---- /clarify validation ----
        code, body = http(port, "/clarify", {
            "nonce": nonce, "session": "api-wrongsession", "selection": ["1"]})
        check("clarify_wrong_session", code == 409 and
              body.get("error") == "session_mismatch", body)
        code, body = http(port, "/clarify", {
            "nonce": nonce, "selection": ["1"]})
        check("clarify_missing_session", code == 400, body)
        code, body = http(port, "/clarify", {
            "nonce": nonce, "session": session, "selection": ["9"]})
        check("clarify_bad_option", code == 400 and
              body.get("error") == "invalid_selection", body)
        check("clarify_bad_option_not_consumed", pending.exists(), "")
        code, body = http(port, "/clarify", {
            "nonce": nonce, "session": session})
        check("clarify_missing_selection", code == 400, body)
        code, body = http(port, "/clarify", {
            "nonce": "cq-unknown123", "session": session, "selection": ["1"]})
        check("clarify_unknown", code == 404 and
              body.get("error") == "unknown_nonce", body)

        # ---- /clarify happy path + replay ----
        code, body = http(port, "/clarify", {
            "nonce": nonce, "session": session, "selection": ["2"]})
        check("clarify_ok", code == 200 and body.get("status") == "ok" and
              "clarified" in body.get("answer", ""), body)
        nonce_other = "cq-other" + secrets.token_hex(4)
        make_pending(home, nonce_other, session,
                     int(time.time() * 1000) + 60000)
        code, body = http(port, "/clarify", {
            "nonce": nonce_other, "session": session,
            "other": "distinctive-other-text"})
        check("clarify_other_ok", code == 200 and
              "distinctive-other-text" in body.get("answer", ""), body)
        check("clarify_consumed", not pending.exists() and
              (pending.parent.parent / "consumed" / (nonce + ".json")).exists(),
              "")
        code, body = http(port, "/clarify", {
            "nonce": nonce, "session": session, "selection": ["2"]})
        check("clarify_replay", code == 409 and
              body.get("error") == "already_consumed", body)

        # ---- expired ----
        nonce_exp = "cq-expired" + secrets.token_hex(4)
        make_pending(home, nonce_exp, session, int(time.time() * 1000) - 1000)
        code, body = http(port, "/clarify", {
            "nonce": nonce_exp, "session": session, "selection": ["1"]})
        check("clarify_expired", code == 410 and
              body.get("error") == "expired", body)

        # ---- missing tagged event: fail closed, no raw JSON answer ----
        code, body = http(port, "/ask", {"question": "missing_event"})
        check("ask_missing_event_fail_closed", code == 502 and
              body.get("error") == "clarify_event_missing", body)

        # ---- concurrency: same session serialized ----
        conc_session = "api-conc" + secrets.token_hex(4)
        out = []

        def ask(q):
            out.append(http(port, "/ask", {"question": q,
                                           "session": conc_session}))

        t1 = threading.Thread(target=ask, args=("sleep one",))
        t2 = threading.Thread(target=ask, args=("sleep two",))
        t1.start()
        time.sleep(0.1)
        t2.start()
        t1.join(30)
        t2.join(30)
        check("concurrency_both_ok",
              len(out) == 2 and all(c == 200 and b.get("status") == "ok"
                                    for c, b in out), out)
        lines = (home / "mock-trace.log").read_text(encoding="utf-8").splitlines()
        starts = [i for i, l in enumerate(lines)
                  if l.startswith("start " + conc_session)]
        ends = [i for i, l in enumerate(lines)
                if l.startswith("sleep-end " + conc_session)]
        check("concurrency_serialized",
              len(starts) == 2 and len(ends) == 2 and ends[0] < starts[1],
              "starts=%s ends=%s" % (starts, ends))

        # ---- stdin DEVNULL + no self-authorization env ----
        env_lines = [l for l in lines if l.startswith("env ")]
        check("stdin_devnull", all("stdin=''" in l for l in lines
                                   if l.startswith("start ")), "")
        bad_env = []
        for l in env_lines:
            obj = json.loads(l[4:])
            if obj.get("confirm") or obj.get("assume"):
                bad_env.append(obj)
        check("no_self_authorization_env", not bad_env, bad_env)
        argv_lines = [l for l in lines if l.startswith("argv ")]
        check("question_not_in_argv",
              all("plain question" not in l for l in argv_lines), argv_lines)
        check("other_answer_not_in_argv",
              all("distinctive-other-text" not in l for l in argv_lines),
              argv_lines)
    finally:
        srv.shutdown()
        th.join(2)

    print("RESULT: %s (%d pass / %d fail)" %
          ("PASS" if not FAILS else "FAIL", len(PASSES), len(FAILS)))
    if FAILS:
        print("FAILED: " + ", ".join(FAILS))
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
